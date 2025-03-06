```diff
diff --git a/Apex.cpp b/Apex.cpp
index 20705e2..e8e2439 100644
--- a/Apex.cpp
+++ b/Apex.cpp
@@ -69,11 +69,8 @@ static status_t GetVintfDirs(FileSystem* fileSystem, PropertyFetcher* propertyFe
     for (const auto& apexInfo : apexInfoList->getApexInfo()) {
         // Skip non-active apexes
         if (!apexInfo.getIsActive()) continue;
-        // Skip if no preinstalled paths. This shouldn't happen but XML schema says it's optional.
-        if (!apexInfo.hasPreinstalledModulePath()) continue;
 
-        const std::string& path = apexInfo.getPreinstalledModulePath();
-        if (filter(path)) {
+        if (filter(apexInfo.getPartition())) {
             dirs->push_back(fmt::format("{}/{}/" VINTF_SUB_DIR, apexDir, apexInfo.getModuleName()));
         }
     }
@@ -102,19 +99,16 @@ std::optional<timespec> GetModifiedTime(FileSystem* fileSystem, PropertyFetcher*
 
 status_t GetDeviceVintfDirs(FileSystem* fileSystem, PropertyFetcher* propertyFetcher,
                             std::vector<std::string>* dirs, std::string* error) {
-    return GetVintfDirs(fileSystem, propertyFetcher, dirs, error, [](const std::string& path) {
-        return StartsWith(path, "/vendor/apex/") || StartsWith(path, "/system/vendor/apex/") ||
-               StartsWith(path, "/odm/apex/") || StartsWith(path, "/vendor/odm/apex/") ||
-               StartsWith(path, "/system/vendor/odm/apex/");
+    return GetVintfDirs(fileSystem, propertyFetcher, dirs, error, [](const std::string& partition) {
+        return partition.compare("VENDOR") == 0 || partition.compare("ODM") == 0;
     });
 }
 
 status_t GetFrameworkVintfDirs(FileSystem* fileSystem, PropertyFetcher* propertyFetcher,
                                std::vector<std::string>* dirs, std::string* error) {
-    return GetVintfDirs(fileSystem, propertyFetcher, dirs, error, [](const std::string& path) {
-        return StartsWith(path, "/system/apex/") || StartsWith(path, "/system_ext/apex/") ||
-               StartsWith(path, "/system/system_ext/apex/") || StartsWith(path, "/product/apex/") ||
-               StartsWith(path, "/system/product/apex/");
+    return GetVintfDirs(fileSystem, propertyFetcher, dirs, error, [](const std::string& partition) {
+        return partition.compare("SYSTEM") == 0 || partition.compare("SYSTEM_EXT") == 0 ||
+               partition.compare("PRODUCT") == 0;
     });
 }
 
diff --git a/CompatibilityMatrix.cpp b/CompatibilityMatrix.cpp
index b6c8e45..4707221 100644
--- a/CompatibilityMatrix.cpp
+++ b/CompatibilityMatrix.cpp
@@ -435,12 +435,13 @@ bool CompatibilityMatrix::addAllAsOptional(CompatibilityMatrix* inputMatrix, std
 }
 
 bool CompatibilityMatrix::forEachInstanceOfVersion(
-    HalFormat format, const std::string& package, const Version& expectVersion,
-    const std::function<bool(const MatrixInstance&)>& func) const {
+    HalFormat format, ExclusiveTo exclusiveTo, const std::string& package,
+    const Version& expectVersion, const std::function<bool(const MatrixInstance&)>& func) const {
     for (const MatrixHal* hal : getHals(package)) {
         bool cont = hal->forEachInstance([&](const MatrixInstance& matrixInstance) {
             if (matrixInstance.format() == format &&
-                matrixInstance.versionRange().contains(expectVersion)) {
+                matrixInstance.versionRange().contains(expectVersion) &&
+                matrixInstance.exclusiveTo() == exclusiveTo) {
                 return func(matrixInstance);
             }
             return true;
@@ -450,11 +451,12 @@ bool CompatibilityMatrix::forEachInstanceOfVersion(
     return true;
 }
 
-bool CompatibilityMatrix::matchInstance(HalFormat format, const std::string& halName,
-                                        const Version& version, const std::string& interfaceName,
+bool CompatibilityMatrix::matchInstance(HalFormat format, ExclusiveTo exclusiveTo,
+                                        const std::string& halName, const Version& version,
+                                        const std::string& interfaceName,
                                         const std::string& instance) const {
     bool found = false;
-    (void)forEachInstanceOfInterface(format, halName, version, interfaceName,
+    (void)forEachInstanceOfInterface(format, exclusiveTo, halName, version, interfaceName,
                                      [&found, &instance](const auto& e) {
                                          found |= (e.matchInstance(instance));
                                          return !found;  // if not found, continue
diff --git a/FileSystem.cpp b/FileSystem.cpp
index 382dc86..a282720 100644
--- a/FileSystem.cpp
+++ b/FileSystem.cpp
@@ -17,11 +17,13 @@
 
 #include <vintf/FileSystem.h>
 
-#include <dirent.h>
-
 #include <android-base/file.h>
 #include <android-base/strings.h>
 
+#include <ranges>
+
+#include <dirent.h>
+
 namespace android {
 namespace vintf {
 namespace details {
@@ -117,21 +119,21 @@ const std::string& FileSystemUnderPath::getRootDir() const {
     return mRootDir;
 }
 
-PathReplacingFileSystem::PathReplacingFileSystem(std::string path_to_replace,
-                                                 std::string path_replacement,
-                                                 std::unique_ptr<FileSystem> impl)
-    : path_to_replace_{std::move(path_to_replace)},
-      path_replacement_{std::move(path_replacement)},
-      impl_{std::move(impl)} {
+static std::string enforceTrailingSlash(const std::string& path) {
+    if (android::base::EndsWith(path, '/')) {
+        return path;
+    }
+    return path + "/";
+}
+
+PathReplacingFileSystem::PathReplacingFileSystem(
+    std::unique_ptr<FileSystem> impl, const std::map<std::string, std::string>& path_replacements)
+    : impl_{std::move(impl)} {
     // Enforce a trailing slash on the path-to-be-replaced, prevents
     // the problem (for example) of /foo matching and changing /fooxyz
-    if (!android::base::EndsWith(path_to_replace_, '/')) {
-        path_to_replace_ += "/";
-    }
-    // Enforce a trailing slash on the replacement path.  This ensures
-    // we are replacing a directory with a directory.
-    if (!android::base::EndsWith(path_replacement_, '/')) {
-        path_replacement_ += "/";
+    for (const auto& [to_replace, replacement] : path_replacements) {
+        path_replacements_.emplace(enforceTrailingSlash(to_replace),
+                                   enforceTrailingSlash(replacement));
     }
 }
 
@@ -151,12 +153,11 @@ status_t PathReplacingFileSystem::modifiedTime(const std::string& path, timespec
 }
 
 std::string PathReplacingFileSystem::path_replace(std::string_view path) const {
-    std::string retstr;
-    if (android::base::ConsumePrefix(&path, path_to_replace_)) {
-        retstr.reserve(path_replacement_.size() + path.size());
-        retstr.append(path_replacement_);
-        retstr.append(path);
-        return retstr;
+    // reverse for "longer match wins".
+    for (const auto& [to_replace, replacement] : path_replacements_ | std::views::reverse) {
+        if (android::base::ConsumePrefix(&path, to_replace)) {
+            return replacement + std::string{path};
+        }
     }
     return std::string{path};
 }
diff --git a/HalManifest.cpp b/HalManifest.cpp
index 8224bab..5f371d4 100644
--- a/HalManifest.cpp
+++ b/HalManifest.cpp
@@ -275,16 +275,7 @@ std::set<std::string> HalManifest::getHalNames() const {
 std::set<std::string> HalManifest::getHalNamesAndVersions() const {
     std::set<std::string> names{};
     forEachInstance([&names](const ManifestInstance& e) {
-        switch (e.format()) {
-            case HalFormat::HIDL:
-                [[fallthrough]];
-            case HalFormat::NATIVE:
-                names.insert(toFQNameString(e.package(), e.version()));
-                break;
-            case HalFormat::AIDL:
-                names.insert(e.package() + "@" + aidlVersionToString(e.version()));
-                break;
-        }
+        names.insert(e.nameWithVersion());
         return true;
     });
     return names;
@@ -294,12 +285,13 @@ Transport HalManifest::getHidlTransport(const std::string& package, const Versio
                                         const std::string& interfaceName,
                                         const std::string& instanceName) const {
     Transport transport{Transport::EMPTY};
-    forEachInstanceOfInterface(HalFormat::HIDL, package, v, interfaceName, [&](const auto& e) {
-        if (e.instance() == instanceName) {
-            transport = e.transport();
-        }
-        return transport == Transport::EMPTY;  // if not found, continue
-    });
+    forEachInstanceOfInterface(HalFormat::HIDL, ExclusiveTo::EMPTY, package, v, interfaceName,
+                               [&](const auto& e) {
+                                   if (e.instance() == instanceName) {
+                                       transport = e.transport();
+                                   }
+                                   return transport == Transport::EMPTY;  // if not found, continue
+                               });
     if (transport == Transport::EMPTY) {
         LOG(DEBUG) << "HalManifest::getHidlTransport(" << mType << "): Cannot find "
                    << toFQNameString(package, v, interfaceName, instanceName);
@@ -308,12 +300,13 @@ Transport HalManifest::getHidlTransport(const std::string& package, const Versio
 }
 
 bool HalManifest::forEachInstanceOfVersion(
-    HalFormat format, const std::string& package, const Version& expectVersion,
-    const std::function<bool(const ManifestInstance&)>& func) const {
+    HalFormat format, ExclusiveTo exclusiveTo, const std::string& package,
+    const Version& expectVersion, const std::function<bool(const ManifestInstance&)>& func) const {
     for (const ManifestHal* hal : getHals(package)) {
         bool cont = hal->forEachInstance([&](const ManifestInstance& manifestInstance) {
             if (manifestInstance.format() == format &&
-                manifestInstance.version().minorAtLeast(expectVersion)) {
+                manifestInstance.version().minorAtLeast(expectVersion) &&
+                manifestInstance.exclusiveTo() == exclusiveTo) {
                 return func(manifestInstance);
             }
             return true;
@@ -401,9 +394,9 @@ std::set<std::string> HalManifest::checkUnusedHals(
     std::set<std::string> ret;
 
     forEachInstance([&ret, &mat, &childrenMap](const auto& manifestInstance) {
-        if (mat.matchInstance(manifestInstance.format(), manifestInstance.package(),
-                              manifestInstance.version(), manifestInstance.interface(),
-                              manifestInstance.instance())) {
+        if (mat.matchInstance(manifestInstance.format(), manifestInstance.exclusiveTo(),
+                              manifestInstance.package(), manifestInstance.version(),
+                              manifestInstance.interface(), manifestInstance.instance())) {
             // manifestInstance exactly matches an instance in |mat|.
             return true;
         }
@@ -417,8 +410,8 @@ std::set<std::string> HalManifest::checkUnusedHals(
             for (auto it = range.first; it != range.second; ++it) {
                 details::FQName fqName;
                 CHECK(fqName.setTo(it->second));
-                if (mat.matchInstance(manifestInstance.format(), fqName.package(),
-                                      fqName.getVersion(), fqName.name(),
+                if (mat.matchInstance(manifestInstance.format(), manifestInstance.exclusiveTo(),
+                                      fqName.package(), fqName.getVersion(), fqName.name(),
                                       manifestInstance.instance())) {
                     return true;
                 }
@@ -657,11 +650,11 @@ bool operator==(const HalManifest &lft, const HalManifest &rgt) {
 }
 
 // Alternative to forEachInstance if you just need a set of instance names instead.
-std::set<std::string> HalManifest::getInstances(HalFormat format, const std::string& package,
-                                                const Version& version,
+std::set<std::string> HalManifest::getInstances(HalFormat format, ExclusiveTo exclusiveTo,
+                                                const std::string& package, const Version& version,
                                                 const std::string& interfaceName) const {
     std::set<std::string> ret;
-    (void)forEachInstanceOfInterface(format, package, version, interfaceName,
+    (void)forEachInstanceOfInterface(format, exclusiveTo, package, version, interfaceName,
                                      [&ret](const auto& e) {
                                          ret.insert(e.instance());
                                          return true;
@@ -670,10 +663,11 @@ std::set<std::string> HalManifest::getInstances(HalFormat format, const std::str
 }
 
 // Return whether instance is in getInstances(...).
-bool HalManifest::hasInstance(HalFormat format, const std::string& package, const Version& version,
-                              const std::string& interfaceName, const std::string& instance) const {
+bool HalManifest::hasInstance(HalFormat format, ExclusiveTo exclusiveTo, const std::string& package,
+                              const Version& version, const std::string& interfaceName,
+                              const std::string& instance) const {
     bool found = false;
-    (void)forEachInstanceOfInterface(format, package, version, interfaceName,
+    (void)forEachInstanceOfInterface(format, exclusiveTo, package, version, interfaceName,
                                      [&found, &instance](const auto& e) {
                                          found |= (instance == e.instance());
                                          return !found;  // if not found, continue
@@ -683,18 +677,20 @@ bool HalManifest::hasInstance(HalFormat format, const std::string& package, cons
 std::set<std::string> HalManifest::getHidlInstances(const std::string& package,
                                                     const Version& version,
                                                     const std::string& interfaceName) const {
-    return getInstances(HalFormat::HIDL, package, version, interfaceName);
+    return getInstances(HalFormat::HIDL, ExclusiveTo::EMPTY, package, version, interfaceName);
 }
 
 std::set<std::string> HalManifest::getAidlInstances(const std::string& package,
                                                     const std::string& interfaceName) const {
+    // Only get the instances available on the host device with ExclusiveTo::EMPTY
     return getAidlInstances(package, 0, interfaceName);
 }
 
 std::set<std::string> HalManifest::getAidlInstances(const std::string& package, size_t version,
                                                     const std::string& interfaceName) const {
-    return getInstances(HalFormat::AIDL, package, {details::kFakeAidlMajorVersion, version},
-                        interfaceName);
+    // Only get the instances available on the host device with ExclusiveTo::EMPTY
+    return getInstances(HalFormat::AIDL, ExclusiveTo::EMPTY, package,
+                        {details::kFakeAidlMajorVersion, version}, interfaceName);
 }
 
 std::set<std::string> HalManifest::getNativeInstances(const std::string& package) const {
@@ -709,7 +705,8 @@ std::set<std::string> HalManifest::getNativeInstances(const std::string& package
 bool HalManifest::hasHidlInstance(const std::string& package, const Version& version,
                                   const std::string& interfaceName,
                                   const std::string& instance) const {
-    return hasInstance(HalFormat::HIDL, package, version, interfaceName, instance);
+    return hasInstance(HalFormat::HIDL, ExclusiveTo::EMPTY, package, version, interfaceName,
+                       instance);
 }
 
 bool HalManifest::hasAidlInstance(const std::string& package, const std::string& interface,
@@ -719,8 +716,8 @@ bool HalManifest::hasAidlInstance(const std::string& package, const std::string&
 
 bool HalManifest::hasAidlInstance(const std::string& package, size_t version,
                                   const std::string& interface, const std::string& instance) const {
-    return hasInstance(HalFormat::AIDL, package, {details::kFakeAidlMajorVersion, version},
-                       interface, instance);
+    return hasInstance(HalFormat::AIDL, ExclusiveTo::EMPTY, package,
+                       {details::kFakeAidlMajorVersion, version}, interface, instance);
 }
 
 bool HalManifest::hasNativeInstance(const std::string& package, const std::string& instance) const {
diff --git a/ManifestHal.cpp b/ManifestHal.cpp
index 252f455..175cce3 100644
--- a/ManifestHal.cpp
+++ b/ManifestHal.cpp
@@ -70,6 +70,7 @@ bool ManifestHal::operator==(const ManifestHal &other) const {
     if (updatableViaApex() != other.updatableViaApex()) return false;
     if (updatableViaSystem() != other.updatableViaSystem()) return false;
     if (mManifestInstances != other.mManifestInstances) return false;
+    if (getExclusiveTo() != other.getExclusiveTo()) return false;
     return accessor() == other.accessor();
 }
 
@@ -184,7 +185,7 @@ bool ManifestHal::insertInstance(const FqInstance& e, bool allowDupMajorVersion,
     }
 
     mManifestInstances.emplace(std::move(toAdd), this->transportArch, this->format,
-                               this->updatableViaApex(), this->accessor(),
+                               this->updatableViaApex(), this->getExclusiveTo(), this->accessor(),
                                this->updatableViaSystem());
     return true;
 }
diff --git a/ManifestInstance.cpp b/ManifestInstance.cpp
index bd12d9f..afd8dde 100644
--- a/ManifestInstance.cpp
+++ b/ManifestInstance.cpp
@@ -42,23 +42,27 @@ ManifestInstance& ManifestInstance::operator=(ManifestInstance&&) noexcept = def
 
 ManifestInstance::ManifestInstance(FqInstance&& fqInstance, TransportArch&& ta, HalFormat fmt,
                                    std::optional<std::string>&& updatableViaApex,
-                                   std::optional<std::string>&& accessor, bool updatableViaSystem)
+                                   ExclusiveTo exclusiveTo, std::optional<std::string>&& accessor,
+                                   bool updatableViaSystem)
     : mFqInstance(std::move(fqInstance)),
       mTransportArch(std::move(ta)),
       mHalFormat(fmt),
       mUpdatableViaApex(std::move(updatableViaApex)),
+      mExclusiveTo(std::move(exclusiveTo)),
       mAccessor(std::move(accessor)),
       mUpdatableViaSystem(std::move(updatableViaSystem)) {}
 
 ManifestInstance::ManifestInstance(const FqInstance& fqInstance, const TransportArch& ta,
                                    HalFormat fmt,
                                    const std::optional<std::string>& updatableViaApex,
+                                   ExclusiveTo exclusiveTo,
                                    const std::optional<std::string>& accessor,
                                    bool updatableViaSystem)
     : mFqInstance(fqInstance),
       mTransportArch(ta),
       mHalFormat(fmt),
       mUpdatableViaApex(updatableViaApex),
+      mExclusiveTo(exclusiveTo),
       mAccessor(accessor),
       mUpdatableViaSystem(updatableViaSystem) {}
 
@@ -102,6 +106,10 @@ const std::optional<std::string>& ManifestInstance::updatableViaApex() const {
     return mUpdatableViaApex;
 }
 
+ExclusiveTo ManifestInstance::exclusiveTo() const {
+    return mExclusiveTo;
+}
+
 const std::optional<std::string>& ManifestInstance::accessor() const {
     return mAccessor;
 }
@@ -181,12 +189,25 @@ std::string ManifestInstance::descriptionWithoutPackage() const {
     }
 }
 
+std::string ManifestInstance::nameWithVersion() const {
+    switch (format()) {
+        case HalFormat::HIDL:
+            [[fallthrough]];
+        case HalFormat::NATIVE:
+            return toFQNameString(package(), version());
+            break;
+        case HalFormat::AIDL:
+            return package() + "@" + aidlVersionToString(version());
+            break;
+    }
+}
+
 ManifestInstance ManifestInstance::withVersion(const Version& v) const {
     FqInstance fqInstance;
     CHECK(fqInstance.setTo(getFqInstance().getPackage(), v.majorVer, v.minorVer,
                            getFqInstance().getInterface(), getFqInstance().getInstance()));
     return ManifestInstance(std::move(fqInstance), mTransportArch, format(), mUpdatableViaApex,
-                            mAccessor, mUpdatableViaSystem);
+                            mExclusiveTo, mAccessor, mUpdatableViaSystem);
 }
 
 }  // namespace vintf
diff --git a/MatrixHal.cpp b/MatrixHal.cpp
index 5b5a5af..d18c42c 100644
--- a/MatrixHal.cpp
+++ b/MatrixHal.cpp
@@ -89,8 +89,8 @@ bool MatrixHal::forEachInstance(const VersionRange& vr,
                 // TODO(b/73556059): Store MatrixInstance as well to avoid creating temps
                 FqInstance fqInstance;
                 if (fqInstance.setTo(getName(), vr.majorVer, vr.minMinor, interface, instance)) {
-                    if (!func(MatrixInstance(format, std::move(fqInstance), VersionRange(vr),
-                                             optional, isRegex))) {
+                    if (!func(MatrixInstance(format, exclusiveTo, std::move(fqInstance),
+                                             VersionRange(vr), optional, isRegex))) {
                         return false;
                     }
                 }
diff --git a/MatrixInstance.cpp b/MatrixInstance.cpp
index 0c6354d..2ba1612 100644
--- a/MatrixInstance.cpp
+++ b/MatrixInstance.cpp
@@ -34,17 +34,20 @@ MatrixInstance& MatrixInstance::operator=(const MatrixInstance&) = default;
 
 MatrixInstance& MatrixInstance::operator=(MatrixInstance&&) noexcept = default;
 
-MatrixInstance::MatrixInstance(HalFormat format, FqInstance&& fqInstance, VersionRange&& range,
-                               bool optional, bool isRegex)
+MatrixInstance::MatrixInstance(HalFormat format, ExclusiveTo exclusiveTo, FqInstance&& fqInstance,
+                               VersionRange&& range, bool optional, bool isRegex)
     : mFormat(format),
+      mExclusiveTo(exclusiveTo),
       mFqInstance(std::move(fqInstance)),
       mRange(std::move(range)),
       mOptional(optional),
       mIsRegex(isRegex) {}
 
-MatrixInstance::MatrixInstance(HalFormat format, const FqInstance fqInstance,
-                               const VersionRange& range, bool optional, bool isRegex)
+MatrixInstance::MatrixInstance(HalFormat format, ExclusiveTo exclusiveTo,
+                               const FqInstance fqInstance, const VersionRange& range,
+                               bool optional, bool isRegex)
     : mFormat(format),
+      mExclusiveTo(exclusiveTo),
       mFqInstance(fqInstance),
       mRange(range),
       mOptional(optional),
@@ -66,6 +69,10 @@ HalFormat MatrixInstance::format() const {
     return mFormat;
 }
 
+ExclusiveTo MatrixInstance::exclusiveTo() const {
+    return mExclusiveTo;
+}
+
 bool MatrixInstance::optional() const {
     return mOptional;
 }
diff --git a/VintfObject.cpp b/VintfObject.cpp
index cb123b3..f391679 100644
--- a/VintfObject.cpp
+++ b/VintfObject.cpp
@@ -809,9 +809,9 @@ bool VintfObject::IsInstanceDeprecated(const MatrixInstance& oldMatrixInstance,
             return true;  // continue
         }
 
-        auto inheritance =
-            GetListedInstanceInheritance(oldMatrixInstance.format(), package, servedVersion,
-                                         interface, servedInstance, deviceManifest, childrenMap);
+        auto inheritance = GetListedInstanceInheritance(
+            oldMatrixInstance.format(), oldMatrixInstance.exclusiveTo(), package, servedVersion,
+            interface, servedInstance, deviceManifest, childrenMap);
         if (!inheritance.has_value()) {
             accumulatedErrors.push_back(inheritance.error().message());
             return true;  // continue
@@ -819,8 +819,9 @@ bool VintfObject::IsInstanceDeprecated(const MatrixInstance& oldMatrixInstance,
 
         std::vector<std::string> errors;
         for (const auto& fqInstance : *inheritance) {
-            auto result = IsFqInstanceDeprecated(targetMatrix, oldMatrixInstance.format(),
-                                                 fqInstance, deviceManifest);
+            auto result =
+                IsFqInstanceDeprecated(targetMatrix, oldMatrixInstance.format(),
+                                       oldMatrixInstance.exclusiveTo(), fqInstance, deviceManifest);
             if (result.ok()) {
                 errors.clear();
                 break;
@@ -846,8 +847,9 @@ bool VintfObject::IsInstanceDeprecated(const MatrixInstance& oldMatrixInstance,
         accumulatedErrors.insert(accumulatedErrors.end(), errors.begin(), errors.end());
         return true;  // continue to next instance
     };
-    (void)deviceManifest->forEachInstanceOfInterface(oldMatrixInstance.format(), package, version,
-                                                     interface, addErrorForInstance);
+    (void)deviceManifest->forEachInstanceOfInterface(oldMatrixInstance.format(),
+                                                     oldMatrixInstance.exclusiveTo(), package,
+                                                     version, interface, addErrorForInstance);
 
     if (accumulatedErrors.empty()) {
         return false;
@@ -858,11 +860,12 @@ bool VintfObject::IsInstanceDeprecated(const MatrixInstance& oldMatrixInstance,
 
 // Check if fqInstance is listed in |deviceManifest|.
 bool VintfObject::IsInstanceListed(const std::shared_ptr<const HalManifest>& deviceManifest,
-                                   HalFormat format, const FqInstance& fqInstance) {
+                                   HalFormat format, ExclusiveTo exclusiveTo,
+                                   const FqInstance& fqInstance) {
     bool found = false;
     (void)deviceManifest->forEachInstanceOfInterface(
-        format, fqInstance.getPackage(), fqInstance.getVersion(), fqInstance.getInterface(),
-        [&](const ManifestInstance& manifestInstance) {
+        format, exclusiveTo, fqInstance.getPackage(), fqInstance.getVersion(),
+        fqInstance.getInterface(), [&](const ManifestInstance& manifestInstance) {
             if (manifestInstance.instance() == fqInstance.getInstance()) {
                 found = true;
             }
@@ -875,7 +878,7 @@ bool VintfObject::IsInstanceListed(const std::shared_ptr<const HalManifest>& dev
 // - is listed in |deviceManifest|; AND
 // - is, or inherits from, package@version::interface/instance (as specified by |childrenMap|)
 android::base::Result<std::vector<FqInstance>> VintfObject::GetListedInstanceInheritance(
-    HalFormat format, const std::string& package, const Version& version,
+    HalFormat format, ExclusiveTo exclusiveTo, const std::string& package, const Version& version,
     const std::string& interface, const std::string& instance,
     const std::shared_ptr<const HalManifest>& deviceManifest, const ChildrenMap& childrenMap) {
     FqInstance fqInstance;
@@ -884,7 +887,7 @@ android::base::Result<std::vector<FqInstance>> VintfObject::GetListedInstanceInh
                                       << " is not a valid FqInstance";
     }
 
-    if (!IsInstanceListed(deviceManifest, format, fqInstance)) {
+    if (!IsInstanceListed(deviceManifest, format, exclusiveTo, fqInstance)) {
         return {};
     }
 
@@ -908,7 +911,7 @@ android::base::Result<std::vector<FqInstance>> VintfObject::GetListedInstanceInh
                                           << fqInstance.getInstance() << " as FqInstance";
             continue;
         }
-        if (!IsInstanceListed(deviceManifest, format, childFqInstance)) {
+        if (!IsInstanceListed(deviceManifest, format, exclusiveTo, childFqInstance)) {
             continue;
         }
         ret.push_back(childFqInstance);
@@ -922,13 +925,13 @@ android::base::Result<std::vector<FqInstance>> VintfObject::GetListedInstanceInh
 // 2. package@x.z::interface/servedInstance is in targetMatrix but
 //    servedInstance is not in deviceManifest(package@x.z::interface)
 android::base::Result<void> VintfObject::IsFqInstanceDeprecated(
-    const CompatibilityMatrix& targetMatrix, HalFormat format, const FqInstance& fqInstance,
-    const std::shared_ptr<const HalManifest>& deviceManifest) {
+    const CompatibilityMatrix& targetMatrix, HalFormat format, ExclusiveTo exclusiveTo,
+    const FqInstance& fqInstance, const std::shared_ptr<const HalManifest>& deviceManifest) {
     // Find minimum package@x.? in target matrix, and check if instance is in target matrix.
     bool foundInstance = false;
     Version targetMatrixMinVer{SIZE_MAX, SIZE_MAX};
     targetMatrix.forEachInstanceOfPackage(
-        format, fqInstance.getPackage(), [&](const auto& targetMatrixInstance) {
+        format, exclusiveTo, fqInstance.getPackage(), [&](const auto& targetMatrixInstance) {
             if (targetMatrixInstance.versionRange().majorVer == fqInstance.getMajorVersion() &&
                 targetMatrixInstance.interface() == fqInstance.getInterface() &&
                 targetMatrixInstance.matchInstance(fqInstance.getInstance())) {
@@ -948,7 +951,7 @@ android::base::Result<void> VintfObject::IsFqInstanceDeprecated(
     bool targetVersionServed = false;
 
     (void)deviceManifest->forEachInstanceOfInterface(
-        format, fqInstance.getPackage(), targetMatrixMinVer, fqInstance.getInterface(),
+        format, exclusiveTo, fqInstance.getPackage(), targetMatrixMinVer, fqInstance.getInterface(),
         [&](const ManifestInstance& manifestInstance) {
             if (manifestInstance.instance() == fqInstance.getInstance()) {
                 targetVersionServed = true;
diff --git a/include/vintf/CompatibilityMatrix.h b/include/vintf/CompatibilityMatrix.h
index bb776ec..4fa3fd7 100644
--- a/include/vintf/CompatibilityMatrix.h
+++ b/include/vintf/CompatibilityMatrix.h
@@ -76,7 +76,8 @@ struct CompatibilityMatrix : public HalGroup<MatrixHal>,
 
    protected:
     bool forEachInstanceOfVersion(
-        HalFormat format, const std::string& package, const Version& expectVersion,
+        HalFormat format, ExclusiveTo exclusiveTo, const std::string& package,
+        const Version& expectVersion,
         const std::function<bool(const MatrixInstance&)>& func) const override;
 
    private:
@@ -145,8 +146,9 @@ struct CompatibilityMatrix : public HalGroup<MatrixHal>,
 
     // Return whether instance is in "this"; that is, instance is in any <instance> tag or
     // matches any <regex-instance> tag.
-    bool matchInstance(HalFormat format, const std::string& halName, const Version& version,
-                       const std::string& interfaceName, const std::string& instance) const;
+    bool matchInstance(HalFormat format, ExclusiveTo exclusiveTo, const std::string& halName,
+                       const Version& version, const std::string& interfaceName,
+                       const std::string& instance) const;
 
     // Return the minlts of the latest <kernel>, or empty value if any error (e.g. this is not an
     // FCM, or there are no <kernel> tags).
diff --git a/include/vintf/ExclusiveTo.h b/include/vintf/ExclusiveTo.h
new file mode 100644
index 0000000..79f0c34
--- /dev/null
+++ b/include/vintf/ExclusiveTo.h
@@ -0,0 +1,43 @@
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
+#pragma once
+
+#include <stdint.h>
+#include <array>
+#include <string>
+
+namespace android {
+namespace vintf {
+
+enum class ExclusiveTo : size_t {
+    // Not exclusive to any particular execution environment and
+    // is available to host processes on the device (given they have
+    // the correct access permissions like sepolicy).
+    EMPTY = 0,
+    // Exclusive to processes inside virtual machines on devices (given
+    // they have the correct access permissions).
+    // Host processes do not have access to these services.
+    VM,
+};
+
+static constexpr std::array<const char*, 2> gExclusiveToStrings = {{
+    "",
+    "virtual-machine",
+}};
+
+}  // namespace vintf
+}  // namespace android
diff --git a/include/vintf/FileSystem.h b/include/vintf/FileSystem.h
index de16d50..fc1d8ae 100644
--- a/include/vintf/FileSystem.h
+++ b/include/vintf/FileSystem.h
@@ -17,6 +17,7 @@
 #ifndef ANDROID_VINTF_FILE_SYSTEM_H
 #define ANDROID_VINTF_FILE_SYSTEM_H
 
+#include <map>
 #include <memory>
 #include <mutex>
 #include <string>
@@ -104,8 +105,8 @@ class FileSystemUnderPath : public FileSystem {
 class PathReplacingFileSystem : public FileSystem {
    public:
     // Use |impl| for any actual reads. Owns impl.
-    PathReplacingFileSystem(std::string path_to_override, std::string path_replacement,
-                            std::unique_ptr<FileSystem> impl);
+    PathReplacingFileSystem(std::unique_ptr<FileSystem> impl,
+                            const std::map<std::string, std::string>& path_replacements);
 
     status_t fetch(const std::string& path, std::string* fetched,
                    std::string* error) const override;
@@ -116,9 +117,9 @@ class PathReplacingFileSystem : public FileSystem {
 
    private:
     std::string path_replace(std::string_view path) const;
-    std::string path_to_replace_;
-    std::string path_replacement_;
+
     std::unique_ptr<FileSystem> impl_;
+    std::map<std::string, std::string> path_replacements_;
 };
 }  // namespace details
 }  // namespace vintf
diff --git a/include/vintf/HalGroup.h b/include/vintf/HalGroup.h
index 4971181..cdc1cec 100644
--- a/include/vintf/HalGroup.h
+++ b/include/vintf/HalGroup.h
@@ -20,6 +20,7 @@
 #include <map>
 #include <set>
 
+#include "ExclusiveTo.h"
 #include "HalFormat.h"
 #include "MapValueIterator.h"
 #include "Version.h"
@@ -85,12 +86,16 @@ struct HalGroup {
         });
     }
 
-    bool forEachInstanceOfPackage(HalFormat format, const std::string& package,
+    bool forEachInstanceOfPackage(HalFormat format, ExclusiveTo exclusiveTo,
+                                  const std::string& package,
                                   const std::function<bool(const InstanceType&)>& func) const {
         for (const auto* hal : getHals(package)) {
             if (hal->format != format) {
                 continue;
             }
+            if (hal->exclusiveTo != exclusiveTo) {
+                continue;
+            }
             if (!hal->forEachInstance(func)) {
                 return false;
             }
@@ -108,17 +113,19 @@ struct HalGroup {
     // is called with a.h.foo@1.0, then a.h.foo@1.1::IFoo/default is returned.
     // If format is AIDL, expectVersion should be the fake AIDL version.
     virtual bool forEachInstanceOfVersion(
-        HalFormat format, const std::string& package, const Version& expectVersion,
+        HalFormat format, ExclusiveTo exclusiveTo, const std::string& package,
+        const Version& expectVersion,
         const std::function<bool(const InstanceType&)>& func) const = 0;
 
     // Apply func to instances of package@expectVersion::interface/*.
     // For example, if a.h.foo@1.1::IFoo/default is in "this" and getHidlFqInstances
     // is called with a.h.foo@1.0::IFoo, then a.h.foo@1.1::IFoo/default is returned.
     // If format is AIDL, expectVersion should be the fake AIDL version.
-    bool forEachInstanceOfInterface(HalFormat format, const std::string& package,
-                                    const Version& expectVersion, const std::string& interface,
+    bool forEachInstanceOfInterface(HalFormat format, ExclusiveTo exclusiveTo,
+                                    const std::string& package, const Version& expectVersion,
+                                    const std::string& interface,
                                     const std::function<bool(const InstanceType&)>& func) const {
-        return forEachInstanceOfVersion(format, package, expectVersion,
+        return forEachInstanceOfVersion(format, exclusiveTo, package, expectVersion,
                                         [&func, &interface](const InstanceType& e) {
                                             if (e.interface() == interface) {
                                                 return func(e);
@@ -134,7 +141,8 @@ struct HalGroup {
     virtual bool forEachHidlInstanceOfVersion(
         const std::string& package, const Version& expectVersion,
         const std::function<bool(const InstanceType&)>& func) const {
-        return forEachInstanceOfVersion(HalFormat::HIDL, package, expectVersion, func);
+        return forEachInstanceOfVersion(HalFormat::HIDL, ExclusiveTo::EMPTY, package, expectVersion,
+                                        func);
     }
 
     // Apply func to instances of package@expectVersion::interface/*.
@@ -143,7 +151,8 @@ struct HalGroup {
     bool forEachHidlInstanceOfInterface(
         const std::string& package, const Version& expectVersion, const std::string& interface,
         const std::function<bool(const InstanceType&)>& func) const {
-        return forEachInstanceOfInterface(HalFormat::HIDL, package, expectVersion, interface, func);
+        return forEachInstanceOfInterface(HalFormat::HIDL, ExclusiveTo::EMPTY, package,
+                                          expectVersion, interface, func);
     }
 
     // Alternative to forEachHidlInstanceOfInterface if you need a vector instead.
diff --git a/include/vintf/HalManifest.h b/include/vintf/HalManifest.h
index 3413359..34dec69 100644
--- a/include/vintf/HalManifest.h
+++ b/include/vintf/HalManifest.h
@@ -99,7 +99,6 @@ struct HalManifest : public HalGroup<ManifestHal>,
     // Returns all component names and versions, e.g.
     // "android.hardware.camera.device@1.0", "android.hardware.camera.device@3.2",
     // "android.hardware.nfc@1.0"]
-    // For AIDL HALs, versions are stripped away.
     std::set<std::string> getHalNamesAndVersions() const;
 
     // Type of the manifest. FRAMEWORK or DEVICE.
@@ -163,7 +162,8 @@ struct HalManifest : public HalGroup<ManifestHal>,
     bool shouldAddXmlFile(const ManifestXmlFile& toAdd) const override;
 
     bool forEachInstanceOfVersion(
-        HalFormat format, const std::string& package, const Version& expectVersion,
+        HalFormat format, ExclusiveTo exclusiveTo, const std::string& package,
+        const Version& expectVersion,
         const std::function<bool(const ManifestInstance&)>& func) const override;
 
     bool forEachNativeInstance(const std::string& package,
@@ -207,13 +207,14 @@ struct HalManifest : public HalGroup<ManifestHal>,
     bool empty() const;
 
     // Alternative to forEachInstance if you just need a set of instance names instead.
-    std::set<std::string> getInstances(HalFormat format, const std::string& package,
-                                       const Version& version,
+    std::set<std::string> getInstances(HalFormat format, ExclusiveTo exclusiveTo,
+                                       const std::string& package, const Version& version,
                                        const std::string& interfaceName) const;
 
     // Return whether instance is in getInstances(...).
-    bool hasInstance(HalFormat format, const std::string& package, const Version& version,
-                     const std::string& interfaceName, const std::string& instance) const;
+    bool hasInstance(HalFormat format, ExclusiveTo exclusiveTo, const std::string& package,
+                     const Version& version, const std::string& interfaceName,
+                     const std::string& instance) const;
 
     // Get the <kernel> tag. Assumes type() == DEVICE.
     // - On host, <kernel> tag only exists for the fully assembled HAL manifest.
diff --git a/include/vintf/ManifestHal.h b/include/vintf/ManifestHal.h
index 6bac534..3d9a484 100644
--- a/include/vintf/ManifestHal.h
+++ b/include/vintf/ManifestHal.h
@@ -24,6 +24,7 @@
 #include <string>
 #include <vector>
 
+#include <vintf/ExclusiveTo.h>
 #include <vintf/FqInstance.h>
 #include <vintf/HalFormat.h>
 #include <vintf/HalInterface.h>
@@ -48,6 +49,10 @@ struct ManifestHal : public WithFileName {
     std::string name;
     std::vector<Version> versions;
     TransportArch transportArch;
+    // If this is set to something other than EMPTY, the service is only
+    // accessible by specific means like through a Trusty VM, and not
+    // available on the host device.
+    ExclusiveTo exclusiveTo = ExclusiveTo::EMPTY;
 
     inline Transport transport() const {
         return transportArch.transport;
@@ -57,6 +62,7 @@ struct ManifestHal : public WithFileName {
     inline std::optional<std::string> ip() const { return transportArch.ip; }
     inline std::optional<uint64_t> port() const { return transportArch.port; }
 
+    ExclusiveTo getExclusiveTo() const { return exclusiveTo; }
     inline const std::string& getName() const { return name; }
     inline bool updatableViaSystem() const { return mUpdatableViaSystem; }
 
diff --git a/include/vintf/ManifestInstance.h b/include/vintf/ManifestInstance.h
index 09940ff..16c2be5 100644
--- a/include/vintf/ManifestInstance.h
+++ b/include/vintf/ManifestInstance.h
@@ -20,6 +20,7 @@
 #include <optional>
 #include <string>
 
+#include <vintf/ExclusiveTo.h>
 #include <vintf/FqInstance.h>
 #include <vintf/HalFormat.h>
 #include <vintf/TransportArch.h>
@@ -38,10 +39,10 @@ class ManifestInstance {
 
     using VersionType = Version;
     ManifestInstance(FqInstance&& fqInstance, TransportArch&& ta, HalFormat fmt,
-                     std::optional<std::string>&& updatableViaApex,
+                     std::optional<std::string>&& updatableViaApex, ExclusiveTo exclusiveTo,
                      std::optional<std::string>&& accessor, bool updatableViaSystem);
     ManifestInstance(const FqInstance& fqInstance, const TransportArch& ta, HalFormat fmt,
-                     const std::optional<std::string>& updatableViaApex,
+                     const std::optional<std::string>& updatableViaApex, ExclusiveTo exclusiveTo,
                      const std::optional<std::string>& accessor, bool updatableViaSystem);
     const std::string& package() const;
     Version version() const;
@@ -50,6 +51,7 @@ class ManifestInstance {
     Transport transport() const;
     Arch arch() const;
     HalFormat format() const;
+    ExclusiveTo exclusiveTo() const;
     const std::optional<std::string>& accessor() const;
     const std::optional<std::string>& updatableViaApex() const;
     const std::optional<std::string> ip() const;
@@ -77,6 +79,9 @@ class ManifestInstance {
     // For others, return "@version::interface/instance".
     std::string descriptionWithoutPackage() const;
 
+    // Returns name with version. e.g. "android.hardware.camera.device@1"
+    std::string nameWithVersion() const;
+
     // Return a new ManifestInstance that's the same as this, but with the given version.
     ManifestInstance withVersion(const Version& v) const;
 
@@ -85,6 +90,7 @@ class ManifestInstance {
     TransportArch mTransportArch;
     HalFormat mHalFormat;
     std::optional<std::string> mUpdatableViaApex;
+    ExclusiveTo mExclusiveTo;
     std::optional<std::string> mAccessor;
     bool mUpdatableViaSystem;
 };
diff --git a/include/vintf/MatrixHal.h b/include/vintf/MatrixHal.h
index 25ff113..af964cf 100644
--- a/include/vintf/MatrixHal.h
+++ b/include/vintf/MatrixHal.h
@@ -22,6 +22,7 @@
 #include <string>
 #include <vector>
 
+#include "ExclusiveTo.h"
 #include "HalFormat.h"
 #include "HalInterface.h"
 #include "MatrixInstance.h"
@@ -42,6 +43,7 @@ struct MatrixHal {
     std::string name;
     std::vector<VersionRange> versionRanges;
     bool optional = false;
+    ExclusiveTo exclusiveTo = ExclusiveTo::EMPTY;
     bool updatableViaApex = false;
     std::map<std::string, HalInterface> interfaces;
 
diff --git a/include/vintf/MatrixInstance.h b/include/vintf/MatrixInstance.h
index f7489d3..73b9a92 100644
--- a/include/vintf/MatrixInstance.h
+++ b/include/vintf/MatrixInstance.h
@@ -19,6 +19,7 @@
 
 #include <string>
 
+#include <vintf/ExclusiveTo.h>
 #include <vintf/FqInstance.h>
 #include <vintf/HalFormat.h>
 #include <vintf/VersionRange.h>
@@ -36,15 +37,16 @@ class MatrixInstance {
 
     using VersionType = VersionRange;
     // fqInstance.version is ignored. Version range is provided separately.
-    MatrixInstance(HalFormat format, FqInstance&& fqInstance, VersionRange&& range, bool optional,
-                   bool isRegex);
-    MatrixInstance(HalFormat format, const FqInstance fqInstance, const VersionRange& range,
-                   bool optional, bool isRegex);
+    MatrixInstance(HalFormat format, ExclusiveTo exclusiveTo, FqInstance&& fqInstance,
+                   VersionRange&& range, bool optional, bool isRegex);
+    MatrixInstance(HalFormat format, ExclusiveTo exclusiveTo, const FqInstance fqInstance,
+                   const VersionRange& range, bool optional, bool isRegex);
     const std::string& package() const;
     const VersionRange& versionRange() const;
     std::string interface() const;
     bool optional() const;
     HalFormat format() const;
+    ExclusiveTo exclusiveTo() const;
 
     bool isSatisfiedBy(const FqInstance& provided) const;
 
@@ -75,6 +77,7 @@ class MatrixInstance {
 
    private:
     HalFormat mFormat = HalFormat::HIDL;
+    ExclusiveTo mExclusiveTo = ExclusiveTo::EMPTY;
     FqInstance mFqInstance;
     VersionRange mRange;
     bool mOptional = false;
diff --git a/include/vintf/VintfObject.h b/include/vintf/VintfObject.h
index 67cfdcb..a7ba2ba 100644
--- a/include/vintf/VintfObject.h
+++ b/include/vintf/VintfObject.h
@@ -338,14 +338,15 @@ class VintfObject {
                                      const ChildrenMap& childrenMap, std::string* appendedError);
 
     static android::base::Result<std::vector<FqInstance>> GetListedInstanceInheritance(
-        HalFormat format, const std::string& package, const Version& version,
-        const std::string& interface, const std::string& instance,
+        HalFormat format, ExclusiveTo exclusiveTo, const std::string& package,
+        const Version& version, const std::string& interface, const std::string& instance,
         const std::shared_ptr<const HalManifest>& halManifest, const ChildrenMap& childrenMap);
     static bool IsInstanceListed(const std::shared_ptr<const HalManifest>& halManifest,
-                                 HalFormat format, const FqInstance& fqInstance);
+                                 HalFormat format, ExclusiveTo exclusiveTo,
+                                 const FqInstance& fqInstance);
     static android::base::Result<void> IsFqInstanceDeprecated(
-        const CompatibilityMatrix& targetMatrix, HalFormat format, const FqInstance& fqInstance,
-        const std::shared_ptr<const HalManifest>& halManifest);
+        const CompatibilityMatrix& targetMatrix, HalFormat format, ExclusiveTo exclusiveTo,
+        const FqInstance& fqInstance, const std::shared_ptr<const HalManifest>& halManifest);
 
    public:
     class Builder;
diff --git a/include/vintf/constants.h b/include/vintf/constants.h
index 423cea0..1e57179 100644
--- a/include/vintf/constants.h
+++ b/include/vintf/constants.h
@@ -23,7 +23,7 @@ namespace android {
 namespace vintf {
 
 /* libvintf meta-version */
-constexpr Version kMetaVersion{8, 0};
+constexpr Version kMetaVersion{9, 0};
 
 // Some legacy metaversion constants
 // The metaversion where inet transport is added to AIDL HALs
@@ -33,6 +33,10 @@ constexpr Version kMetaVersionAidlInet{5, 0};
 // as an error tag.
 constexpr Version kMetaVersionNoHalInterfaceInstance{6, 0};
 
+// The metaversion that throws errors when an attribute value is something
+// other than what is expected. Like `hal format="not_expected"'
+constexpr Version kMetaVersionStrictAttributeValues{9, 0};
+
 // Default version for an AIDL HAL if no version is specified.
 constexpr size_t kDefaultAidlMinorVersion = 1;
 
diff --git a/include/vintf/parse_string.h b/include/vintf/parse_string.h
index 52defff..4a8eada 100644
--- a/include/vintf/parse_string.h
+++ b/include/vintf/parse_string.h
@@ -29,68 +29,70 @@
 namespace android {
 namespace vintf {
 
-std::ostream &operator<<(std::ostream &os, HalFormat hf);
-std::ostream &operator<<(std::ostream &os, Transport tr);
-std::ostream &operator<<(std::ostream &os, Arch ar);
-std::ostream &operator<<(std::ostream &os, KernelConfigType il);
-std::ostream &operator<<(std::ostream &os, Tristate tr);
-std::ostream &operator<<(std::ostream &os, SchemaType ksv);
+std::ostream& operator<<(std::ostream& os, HalFormat hf);
+std::ostream& operator<<(std::ostream& os, Transport tr);
+std::ostream& operator<<(std::ostream& os, Arch ar);
+std::ostream& operator<<(std::ostream& os, KernelConfigType il);
+std::ostream& operator<<(std::ostream& os, Tristate tr);
+std::ostream& operator<<(std::ostream& os, SchemaType ksv);
 std::ostream& operator<<(std::ostream& os, XmlSchemaFormat f);
 std::ostream& operator<<(std::ostream& os, Level l);
 std::ostream& operator<<(std::ostream& os, KernelSepolicyVersion v);
-std::ostream &operator<<(std::ostream &os, const Version &ver);
-std::ostream &operator<<(std::ostream &os, const VersionRange &vr);
+std::ostream& operator<<(std::ostream& os, ExclusiveTo e);
+std::ostream& operator<<(std::ostream& os, const Version& ver);
+std::ostream& operator<<(std::ostream& os, const VersionRange& vr);
 std::ostream& operator<<(std::ostream& os, const SepolicyVersion& ver);
 std::ostream& operator<<(std::ostream& os, const SepolicyVersionRange& vr);
 
 #pragma clang diagnostic push
 #pragma clang diagnostic ignored "-Wdeprecated-declarations"
-std::ostream &operator<<(std::ostream &os, const VndkVersionRange &vr);
+std::ostream& operator<<(std::ostream& os, const VndkVersionRange& vr);
 #pragma clang diagnostic pop
 
-std::ostream &operator<<(std::ostream &os, const KernelVersion &ver);
-std::ostream &operator<<(std::ostream &os, const TransportArch &ta);
-std::ostream &operator<<(std::ostream &os, const ManifestHal &hal);
-std::ostream &operator<<(std::ostream &os, const KernelConfigTypedValue &kcv);
+std::ostream& operator<<(std::ostream& os, const KernelVersion& ver);
+std::ostream& operator<<(std::ostream& os, const TransportArch& ta);
+std::ostream& operator<<(std::ostream& os, const ManifestHal& hal);
+std::ostream& operator<<(std::ostream& os, const KernelConfigTypedValue& kcv);
 std::ostream& operator<<(std::ostream& os, const FqInstance& fqInstance);
 
 template <typename T>
-std::string to_string(const T &obj) {
+std::string to_string(const T& obj) {
     std::ostringstream oss;
     oss << obj;
     return oss.str();
 }
 
-bool parse(const std::string &s, HalFormat *hf);
-bool parse(const std::string &s, Transport *tr);
-bool parse(const std::string &s, Arch *ar);
-bool parse(const std::string &s, KernelConfigType *il);
-bool parse(const std::string &s, KernelConfigKey *key);
-bool parse(const std::string &s, Tristate *tr);
-bool parse(const std::string &s, SchemaType *ver);
+bool parse(const std::string& s, HalFormat* hf);
+bool parse(const std::string& s, Transport* tr);
+bool parse(const std::string& s, Arch* ar);
+bool parse(const std::string& s, KernelConfigType* il);
+bool parse(const std::string& s, KernelConfigKey* key);
+bool parse(const std::string& s, Tristate* tr);
+bool parse(const std::string& s, SchemaType* ver);
 bool parse(const std::string& s, XmlSchemaFormat* ver);
 bool parse(const std::string& s, Level* l);
-bool parse(const std::string &s, KernelSepolicyVersion *ksv);
-bool parse(const std::string &s, Version *ver);
-bool parse(const std::string &s, VersionRange *vr);
+bool parse(const std::string& s, KernelSepolicyVersion* ksv);
+bool parse(const std::string& s, ExclusiveTo* e);
+bool parse(const std::string& s, Version* ver);
+bool parse(const std::string& s, VersionRange* vr);
 bool parse(const std::string& s, SepolicyVersion* ver);
 bool parse(const std::string& s, SepolicyVersionRange* ver);
 
 #pragma clang diagnostic push
 #pragma clang diagnostic ignored "-Wdeprecated-declarations"
-bool parse(const std::string &s, VndkVersionRange *vr);
+bool parse(const std::string& s, VndkVersionRange* vr);
 #pragma clang diagnostic pop
 
-bool parse(const std::string &s, KernelVersion *ver);
+bool parse(const std::string& s, KernelVersion* ver);
 bool parse(const std::string& s, FqInstance* fqInstance);
 
-bool parseKernelConfigInt(const std::string &s, int64_t *i);
-bool parseKernelConfigInt(const std::string &s, uint64_t *i);
-bool parseRange(const std::string &s, KernelConfigRangeValue *range);
+bool parseKernelConfigInt(const std::string& s, int64_t* i);
+bool parseKernelConfigInt(const std::string& s, uint64_t* i);
+bool parseRange(const std::string& s, KernelConfigRangeValue* range);
 
 // Parse the KernelConfigValue in s, assuming type kctv->type, and store it in
 // kctv->value.
-bool parseKernelConfigValue(const std::string &s, KernelConfigTypedValue *kctv);
+bool parseKernelConfigValue(const std::string& s, KernelConfigTypedValue* kctv);
 
 // Parse the KernelConfigTypedValue in s (type is guessed) and store it in kctv.
 // Do not expect quotes in strings.
@@ -108,7 +110,7 @@ bool parseAidlVersionRange(const std::string& s, VersionRange* vr);
 // A string that describes the whole object, with versions of all
 // its components. For debugging and testing purposes only. This is not
 // the XML string.
-std::string dump(const HalManifest &vm);
+std::string dump(const HalManifest& vm);
 
 std::string dump(const RuntimeInfo& ki, bool verbose = true);
 
diff --git a/parse_string.cpp b/parse_string.cpp
index 6fdd9f5..c95fe10 100644
--- a/parse_string.cpp
+++ b/parse_string.cpp
@@ -98,6 +98,7 @@ DEFINE_PARSE_STREAMIN_FOR_ENUM(KernelConfigType)
 DEFINE_PARSE_STREAMIN_FOR_ENUM(Tristate)
 DEFINE_PARSE_STREAMIN_FOR_ENUM(SchemaType)
 DEFINE_PARSE_STREAMIN_FOR_ENUM(XmlSchemaFormat)
+DEFINE_PARSE_STREAMIN_FOR_ENUM(ExclusiveTo)
 
 std::ostream &operator<<(std::ostream &os, const KernelConfigTypedValue &kctv) {
     switch (kctv.mType) {
diff --git a/parse_xml.cpp b/parse_xml.cpp
index 57b9d9d..37483f5 100644
--- a/parse_xml.cpp
+++ b/parse_xml.cpp
@@ -205,6 +205,8 @@ struct XmlNodeConverter {
     // Deserialize XML element |root| into |object|.
     inline bool operator()(Object* object, NodeType* root, const BuildObjectParam& param) const {
         if (nameOf(root) != this->elementName()) {
+            *param.error = "The root name(" + nameOf(root) + ") does not match the element name (" +
+                           this->elementName() + ")";
             return false;
         }
         return this->buildObject(object, root, param);
@@ -292,14 +294,24 @@ struct XmlNodeConverter {
     // set to error message.
     template <typename T>
     inline bool parseOptionalAttr(NodeType* root, const std::string& attrName, T&& defaultValue,
-                                  T* attr, std::string* /* error */) const {
+                                  T* attr, const BuildObjectParam& param) const {
         std::string attrText;
-        bool success = getAttr(root, attrName, &attrText) &&
-                       ::android::vintf::parse(attrText, attr);
-        if (!success) {
+        bool success = getAttr(root, attrName, &attrText);
+        bool parseSuccess = true;
+        if (success) {
+            parseSuccess = ::android::vintf::parse(attrText, attr);
+        } else {
             *attr = std::move(defaultValue);
         }
-        return true;
+        if (param.metaVersion >= kMetaVersionStrictAttributeValues) {
+            if (!parseSuccess && param.error) {
+                *param.error += "Unknown value (\"" + attrText + "\") for attribute '" + attrName +
+                                "' is considered a failure.";
+            }
+            return parseSuccess;
+        } else {
+            return true;
+        }
     }
 
     template <typename T>
@@ -539,9 +551,9 @@ struct TransportArchConverter : public XmlNodeConverter<TransportArch> {
     }
     bool buildObject(TransportArch* object, NodeType* root,
                      const BuildObjectParam& param) const override {
-        if (!parseOptionalAttr(root, "arch", Arch::ARCH_EMPTY, &object->arch, param.error) ||
-            !parseOptionalAttr(root, "ip", {}, &object->ip, param.error) ||
-            !parseOptionalAttr(root, "port", {}, &object->port, param.error) ||
+        if (!parseOptionalAttr(root, "arch", Arch::ARCH_EMPTY, &object->arch, param) ||
+            !parseOptionalAttr(root, "ip", {}, &object->ip, param) ||
+            !parseOptionalAttr(root, "port", {}, &object->port, param) ||
             !parseText(root, &object->transport, param.error)) {
             return false;
         }
@@ -633,6 +645,10 @@ struct MatrixHalConverter : public XmlNodeConverter<MatrixHal> {
                     const MutateNodeParam& param) const override {
         appendAttr(root, "format", object.format);
         appendAttr(root, "optional", object.optional);
+        // Only include if it is not the default empty value
+        if (object.exclusiveTo != ExclusiveTo::EMPTY) {
+            appendAttr(root, "exclusive-to", object.exclusiveTo);
+        }
         // Only include update-via-apex if enabled
         if (object.updatableViaApex) {
             appendAttr(root, "updatable-via-apex", object.updatableViaApex);
@@ -654,11 +670,13 @@ struct MatrixHalConverter : public XmlNodeConverter<MatrixHal> {
     bool buildObject(MatrixHal* object, NodeType* root,
                      const BuildObjectParam& param) const override {
         std::vector<HalInterface> interfaces;
-        if (!parseOptionalAttr(root, "format", HalFormat::HIDL, &object->format, param.error) ||
+        if (!parseOptionalAttr(root, "format", HalFormat::HIDL, &object->format, param) ||
             !parseOptionalAttr(root, "optional", true /* defaultValue */, &object->optional,
-                               param.error) ||
+                               param) ||
+            !parseOptionalAttr(root, "exclusive-to", ExclusiveTo::EMPTY, &object->exclusiveTo,
+                               param) ||
             !parseOptionalAttr(root, "updatable-via-apex", false /* defaultValue */,
-                               &object->updatableViaApex, param.error) ||
+                               &object->updatableViaApex, param) ||
             !parseTextElement(root, "name", &object->name, param.error) ||
             !parseChildren(root, HalInterfaceConverter{}, &interfaces, param)) {
             return false;
@@ -769,8 +787,7 @@ struct MatrixKernelConverter : public XmlNodeConverter<MatrixKernel> {
                      const BuildObjectParam& param) const override {
         Level sourceMatrixLevel = Level::UNSPECIFIED;
         if (!parseAttr(root, "version", &object->mMinLts, param.error) ||
-            !parseOptionalAttr(root, "level", Level::UNSPECIFIED, &sourceMatrixLevel,
-                               param.error) ||
+            !parseOptionalAttr(root, "level", Level::UNSPECIFIED, &sourceMatrixLevel, param) ||
             !parseOptionalChild(root, MatrixKernelConditionsConverter{}, {}, &object->mConditions,
                                 param) ||
             !parseChildren(root, MatrixKernelConfigConverter{}, &object->mConfigs, param)) {
@@ -792,6 +809,10 @@ struct ManifestHalConverter : public XmlNodeConverter<ManifestHal> {
     void mutateNode(const ManifestHal& object, NodeType* root,
                     const MutateNodeParam& param) const override {
         appendAttr(root, "format", object.format);
+        // Only include if it is not the default empty value
+        if (object.exclusiveTo != ExclusiveTo::EMPTY) {
+            appendAttr(root, "exclusive-to", object.exclusiveTo);
+        }
         appendTextElement(root, "name", object.name, param.d);
         if (!object.transportArch.empty()) {
             appendChild(root, TransportArchConverter{}(object.transportArch, param));
@@ -838,20 +859,19 @@ struct ManifestHalConverter : public XmlNodeConverter<ManifestHal> {
     bool buildObject(ManifestHal* object, NodeType* root,
                      const BuildObjectParam& param) const override {
         std::vector<HalInterface> interfaces;
-        if (!parseOptionalAttr(root, "format", HalFormat::HIDL, &object->format, param.error) ||
-            !parseOptionalAttr(root, "override", false, &object->mIsOverride, param.error) ||
-            !parseOptionalAttr(root, "updatable-via-apex", {}, &object->mUpdatableViaApex,
-                               param.error) ||
+        if (!parseOptionalAttr(root, "format", HalFormat::HIDL, &object->format, param) ||
+            !parseOptionalAttr(root, "override", false, &object->mIsOverride, param) ||
+            !parseOptionalAttr(root, "exclusive-to", ExclusiveTo::EMPTY, &object->exclusiveTo,
+                               param) ||
+            !parseOptionalAttr(root, "updatable-via-apex", {}, &object->mUpdatableViaApex, param) ||
             !parseOptionalAttr(root, "updatable-via-system", false /* defaultValue */,
-                               &object->mUpdatableViaSystem, param.error) ||
+                               &object->mUpdatableViaSystem, param) ||
             !parseOptionalTextElement(root, "accessor", {}, &object->mAccessor, param.error) ||
             !parseTextElement(root, "name", &object->name, param.error) ||
             !parseOptionalChild(root, TransportArchConverter{}, {}, &object->transportArch,
                                 param) ||
-            !parseOptionalAttr(root, "max-level", Level::UNSPECIFIED, &object->mMaxLevel,
-                               param.error) ||
-            !parseOptionalAttr(root, "min-level", Level::UNSPECIFIED, &object->mMinLevel,
-                               param.error)) {
+            !parseOptionalAttr(root, "max-level", Level::UNSPECIFIED, &object->mMaxLevel, param) ||
+            !parseOptionalAttr(root, "min-level", Level::UNSPECIFIED, &object->mMinLevel, param)) {
             return false;
         }
         if (getChildren(root, "accessor").size() > 1) {
@@ -1242,9 +1262,9 @@ struct KernelInfoConverter : public XmlNodeConverter<KernelInfo> {
     }
     bool buildObject(KernelInfo* object, NodeType* root,
                      const BuildObjectParam& param) const override {
-        return parseOptionalAttr(root, "version", {}, &object->mVersion, param.error) &&
+        return parseOptionalAttr(root, "version", {}, &object->mVersion, param) &&
                parseOptionalAttr(root, "target-level", Level::UNSPECIFIED, &object->mLevel,
-                                 param.error) &&
+                                 param) &&
                parseChildren(root, StringKernelConfigConverter{}, &object->mConfigs, param);
     }
 };
@@ -1334,7 +1354,7 @@ struct HalManifestConverter : public XmlNodeConverter<HalManifest> {
             }
 
             if (!parseOptionalAttr(root, "target-level", Level::UNSPECIFIED, &object->mLevel,
-                                   param.error)) {
+                                   param)) {
                 return false;
             }
 
@@ -1431,7 +1451,7 @@ struct MatrixXmlFileConverter : public XmlNodeConverter<MatrixXmlFile> {
                      const BuildObjectParam& param) const override {
         if (!parseTextElement(root, "name", &object->mName, param.error) ||
             !parseAttr(root, "format", &object->mFormat, param.error) ||
-            !parseOptionalAttr(root, "optional", false, &object->mOptional, param.error) ||
+            !parseOptionalAttr(root, "optional", false, &object->mOptional, param) ||
             !parseChild(root, VersionRangeConverter{}, &object->mVersionRange, param) ||
             !parseOptionalTextElement(root, "path", {}, &object->mOverriddenPath, param.error)) {
             return false;
@@ -1538,8 +1558,7 @@ struct CompatibilityMatrixConverter : public XmlNodeConverter<CompatibilityMatri
                 seenKernelVersions.insert(minLts);
             }
 
-            if (!parseOptionalAttr(root, "level", Level::UNSPECIFIED, &object->mLevel,
-                                   param.error)) {
+            if (!parseOptionalAttr(root, "level", Level::UNSPECIFIED, &object->mLevel, param)) {
                 return false;
             }
 
diff --git a/test/LibVintfTest.cpp b/test/LibVintfTest.cpp
index dccf6b5..2bc3c0a 100644
--- a/test/LibVintfTest.cpp
+++ b/test/LibVintfTest.cpp
@@ -145,11 +145,21 @@ public:
     }
 
     ManifestHal createManifestHal(HalFormat format, std::string name, TransportArch ta,
+                                  ExclusiveTo exclusiveTo,
                                   const std::set<FqInstance>& fqInstances) {
         ManifestHal ret;
         ret.format = format;
         ret.name = std::move(name);
+        // AIDL versions are stored in the versions field instead of only in the
+        // FqInstance
+        if (format == HalFormat::AIDL) {
+            for (const auto& fq : fqInstances) {
+                auto [major, minor] = fq.getVersion();
+                ret.versions.push_back({major, minor});
+            }
+        }
         ret.transportArch = ta;
+        ret.exclusiveTo = exclusiveTo;
         std::string error;
         EXPECT_TRUE(ret.insertInstances(fqInstances, false, &error)) << error;
         return ret;
@@ -160,14 +170,14 @@ public:
         vm.mType = SchemaType::DEVICE;
         vm.device.mSepolicyVersion = sepolicyVersion;
         vm.add(createManifestHal(HalFormat::HIDL, "android.hardware.camera",
-                                 {Transport::HWBINDER, Arch::ARCH_EMPTY},
+                                 {Transport::HWBINDER, Arch::ARCH_EMPTY}, ExclusiveTo::EMPTY,
                                  {
                                      *FqInstance::from(2, 0, "ICamera", "legacy/0"),
                                      *FqInstance::from(2, 0, "ICamera", "default"),
                                      *FqInstance::from(2, 0, "IBetterCamera", "camera"),
                                  }));
         vm.add(createManifestHal(HalFormat::HIDL, "android.hardware.nfc",
-                                 {Transport::PASSTHROUGH, Arch::ARCH_32_64},
+                                 {Transport::PASSTHROUGH, Arch::ARCH_32_64}, ExclusiveTo::EMPTY,
                                  std::set({*FqInstance::from(1, 0, "INfc", "default")})));
 
         return vm;
@@ -186,7 +196,7 @@ public:
         vm.mType = SchemaType::FRAMEWORK;
         vm.add(createManifestHal(
             HalFormat::HIDL, "android.hidl.manager", {Transport::HWBINDER, Arch::ARCH_EMPTY},
-            std::set({*FqInstance::from(1, 0, "IServiceManager", "default")})));
+            ExclusiveTo::EMPTY, std::set({*FqInstance::from(1, 0, "IServiceManager", "default")})));
         Vndk vndk2505;
         vndk2505.mVersionRange = {25, 0, 5};
         vndk2505.mLibraries = {"libjpeg.so", "libbase.so"};
@@ -276,6 +286,7 @@ TEST_F(LibVintfTest, FutureManifestCompatible) {
     expectedManifest.add(createManifestHal(HalFormat::HIDL,
                                      "android.hardware.foo",
                                      {Transport::HWBINDER, Arch::ARCH_EMPTY},
+                                     ExclusiveTo::EMPTY,
                                      {*FqInstance::from(1, 0, "IFoo", "default")}));
     std::string manifestXml =
         "<manifest " + kMetaVersionStr + " type=\"device\" might_add=\"true\">\n"
@@ -292,7 +303,8 @@ TEST_F(LibVintfTest, FutureManifestCompatible) {
         "</manifest>\n";
     HalManifest manifest;
     EXPECT_TRUE(fromXml(&manifest, manifestXml));
-    EXPECT_EQ(expectedManifest, manifest);
+    EXPECT_EQ(expectedManifest, manifest) << dump(expectedManifest)
+                                          << " is expected but got " << dump(manifest);
 }
 
 TEST_F(LibVintfTest, HalManifestConverter) {
@@ -724,7 +736,7 @@ static bool insert(std::map<std::string, HalInterface>* map, HalInterface&& intf
 TEST_F(LibVintfTest, MatrixHalConverter) {
     MatrixHal mh{HalFormat::NATIVE, "android.hardware.camera",
             {{VersionRange(1,2,3), VersionRange(4,5,6)}},
-            false /* optional */, false /* updatableViaApex */, {}};
+            false /* optional */, ExclusiveTo::EMPTY, false /* updatableViaApex */, {}};
     EXPECT_TRUE(insert(&mh.interfaces, {"IBetterCamera", {"default", "great"}}));
     EXPECT_TRUE(insert(&mh.interfaces, {"ICamera", {"default"}}));
     std::string xml = toXml(mh);
@@ -836,14 +848,18 @@ TEST_F(LibVintfTest, CompatibilityMatrixConverter) {
     CompatibilityMatrix cm;
     EXPECT_TRUE(add(cm, MatrixHal{HalFormat::NATIVE, "android.hardware.camera",
             {{VersionRange(1,2,3), VersionRange(4,5,6)}},
-            false /* optional */,  false /* updatableViaApex */, testHalInterfaces()}));
+            false /* optional */, ExclusiveTo::EMPTY,  false /* updatableViaApex */,
+            testHalInterfaces()}));
     EXPECT_TRUE(add(cm, MatrixHal{HalFormat::NATIVE, "android.hardware.nfc",
             {{VersionRange(4,5,6), VersionRange(10,11,12)}},
-            true /* optional */,  false /* updatableViaApex */, testHalInterfaces()}));
+            true /* optional */, ExclusiveTo::EMPTY, false /* updatableViaApex */,
+            testHalInterfaces()}));
     EXPECT_TRUE(add(cm, MatrixKernel{KernelVersion(3, 18, 22),
-            {KernelConfig{"CONFIG_FOO", Tristate::YES}, KernelConfig{"CONFIG_BAR", "stringvalue"}}}));
+            {KernelConfig{"CONFIG_FOO", Tristate::YES},
+             KernelConfig{"CONFIG_BAR", "stringvalue"}}}));
     EXPECT_TRUE(add(cm, MatrixKernel{KernelVersion(4, 4, 1),
-            {KernelConfig{"CONFIG_BAZ", 20}, KernelConfig{"CONFIG_BAR", KernelConfigRangeValue{3, 5} }}}));
+            {KernelConfig{"CONFIG_BAZ", 20},
+             KernelConfig{"CONFIG_BAR", KernelConfigRangeValue{3, 5} }}}));
     set(cm, Sepolicy(30, {{25, 0}, {26, 0, 3}, {202404, std::nullopt}}));
     setAvb(cm, Version{2, 1});
     std::string xml = toXml(cm);
@@ -906,7 +922,8 @@ TEST_F(LibVintfTest, DeviceCompatibilityMatrixCoverter) {
     CompatibilityMatrix cm;
     EXPECT_TRUE(add(cm, MatrixHal{HalFormat::NATIVE, "android.hidl.manager",
             {{VersionRange(1,0)}},
-            false /* optional */,  false /* updatableViaApex */, testHalInterfaces()}));
+            false /* optional */, ExclusiveTo::EMPTY, false /* updatableViaApex */,
+            testHalInterfaces()}));
     set(cm, SchemaType::DEVICE);
     set(cm, VndkVersionRange{25,0,1,5}, {"libjpeg.so", "libbase.so"});
     std::string xml = toXml(cm);
@@ -954,8 +971,9 @@ TEST_F(LibVintfTest, CompatibilityMatrixDefaultOptionalTrue) {
 TEST_F(LibVintfTest, IsValid) {
     EXPECT_TRUE(isValid(ManifestHal()));
 
-    auto invalidHal = createManifestHal(HalFormat::HIDL, "android.hardware.camera",
-                                        {Transport::PASSTHROUGH, Arch::ARCH_32_64}, {});
+    auto invalidHal =
+        createManifestHal(HalFormat::HIDL, "android.hardware.camera",
+                          {Transport::PASSTHROUGH, Arch::ARCH_32_64}, ExclusiveTo::EMPTY, {});
     invalidHal.versions = {{Version(2, 0), Version(2, 1)}};
 
     EXPECT_FALSE(isValid(invalidHal));
@@ -986,42 +1004,48 @@ TEST_F(LibVintfTest, HalManifestGetAllHals) {
 TEST_F(LibVintfTest, HalManifestGetHals) {
     HalManifest vm;
 
-    EXPECT_TRUE(add(vm, createManifestHal(HalFormat::HIDL, "android.hardware.camera",
-                                          {Transport::HWBINDER, Arch::ARCH_EMPTY},
-                                          {
-                                              *FqInstance::from(1, 2, "ICamera", "legacy/0"),
-                                              *FqInstance::from(1, 2, "ICamera", "default"),
-                                              *FqInstance::from(1, 2, "IBetterCamera", "camera"),
-                                          })));
-    EXPECT_TRUE(add(vm, createManifestHal(HalFormat::HIDL, "android.hardware.camera",
-                                          {Transport::HWBINDER, Arch::ARCH_EMPTY},
-                                          {
-                                              *FqInstance::from(2, 0, "ICamera", "legacy/0"),
-                                              *FqInstance::from(2, 0, "ICamera", "default"),
-                                              *FqInstance::from(2, 0, "IBetterCamera", "camera"),
-                                          })));
-
-    EXPECT_TRUE(add(vm, createManifestHal(HalFormat::HIDL, "android.hardware.nfc",
-                                          {Transport::PASSTHROUGH, Arch::ARCH_32_64},
-                                          {*FqInstance::from(1, 0, "INfc", "default"),
-                                           *FqInstance::from(2, 1, "INfc", "default")})));
-
-    ManifestHal expectedCameraHalV1_2 = createManifestHal(
-        HalFormat::HIDL, "android.hardware.camera", {Transport::HWBINDER, Arch::ARCH_EMPTY},
-        {
-            *FqInstance::from(1, 2, "ICamera", "legacy/0"),
-            *FqInstance::from(1, 2, "ICamera", "default"),
-            *FqInstance::from(1, 2, "IBetterCamera", "camera"),
-        });
-    ManifestHal expectedCameraHalV2_0 = createManifestHal(
-        HalFormat::HIDL, "android.hardware.camera", {Transport::HWBINDER, Arch::ARCH_EMPTY},
-        {
-            *FqInstance::from(2, 0, "ICamera", "legacy/0"),
-            *FqInstance::from(2, 0, "ICamera", "default"),
-            *FqInstance::from(2, 0, "IBetterCamera", "camera"),
-        });
+    EXPECT_TRUE(
+        add(vm, createManifestHal(HalFormat::HIDL, "android.hardware.camera",
+                                  {Transport::HWBINDER, Arch::ARCH_EMPTY}, ExclusiveTo::EMPTY,
+                                  {
+                                      *FqInstance::from(1, 2, "ICamera", "legacy/0"),
+                                      *FqInstance::from(1, 2, "ICamera", "default"),
+                                      *FqInstance::from(1, 2, "IBetterCamera", "camera"),
+                                  })));
+    EXPECT_TRUE(
+        add(vm, createManifestHal(HalFormat::HIDL, "android.hardware.camera",
+                                  {Transport::HWBINDER, Arch::ARCH_EMPTY}, ExclusiveTo::EMPTY,
+                                  {
+                                      *FqInstance::from(2, 0, "ICamera", "legacy/0"),
+                                      *FqInstance::from(2, 0, "ICamera", "default"),
+                                      *FqInstance::from(2, 0, "IBetterCamera", "camera"),
+                                  })));
+
+    EXPECT_TRUE(
+        add(vm, createManifestHal(HalFormat::HIDL, "android.hardware.nfc",
+                                  {Transport::PASSTHROUGH, Arch::ARCH_32_64}, ExclusiveTo::EMPTY,
+                                  {*FqInstance::from(1, 0, "INfc", "default"),
+                                   *FqInstance::from(2, 1, "INfc", "default")})));
+
+    ManifestHal expectedCameraHalV1_2 =
+        createManifestHal(HalFormat::HIDL, "android.hardware.camera",
+                          {Transport::HWBINDER, Arch::ARCH_EMPTY}, ExclusiveTo::EMPTY,
+                          {
+                              *FqInstance::from(1, 2, "ICamera", "legacy/0"),
+                              *FqInstance::from(1, 2, "ICamera", "default"),
+                              *FqInstance::from(1, 2, "IBetterCamera", "camera"),
+                          });
+    ManifestHal expectedCameraHalV2_0 =
+        createManifestHal(HalFormat::HIDL, "android.hardware.camera",
+                          {Transport::HWBINDER, Arch::ARCH_EMPTY}, ExclusiveTo::EMPTY,
+                          {
+                              *FqInstance::from(2, 0, "ICamera", "legacy/0"),
+                              *FqInstance::from(2, 0, "ICamera", "default"),
+                              *FqInstance::from(2, 0, "IBetterCamera", "camera"),
+                          });
     ManifestHal expectedNfcHal = createManifestHal(
         HalFormat::HIDL, "android.hardware.nfc", {Transport::PASSTHROUGH, Arch::ARCH_32_64},
+        ExclusiveTo::EMPTY,
         {*FqInstance::from(1, 0, "INfc", "default"), *FqInstance::from(2, 1, "INfc", "default")});
 
     auto cameraHals = getHals(vm, "android.hardware.camera");
@@ -1040,12 +1064,14 @@ TEST_F(LibVintfTest, CompatibilityMatrixGetHals) {
                                   "android.hardware.camera",
                                   {{VersionRange(1, 2, 3), VersionRange(4, 5, 6)}},
                                   false /* optional */,
+                                  ExclusiveTo::EMPTY,
                                   false /* updatableViaApex */,
                                   testHalInterfaces()}));
     EXPECT_TRUE(add(cm, MatrixHal{HalFormat::NATIVE,
                                   "android.hardware.nfc",
                                   {{VersionRange(4, 5, 6), VersionRange(10, 11, 12)}},
                                   true /* optional */,
+                                  ExclusiveTo::EMPTY,
                                   false /* updatableViaApex */,
                                   testHalInterfaces()}));
 
@@ -1054,6 +1080,7 @@ TEST_F(LibVintfTest, CompatibilityMatrixGetHals) {
         "android.hardware.camera",
         {{VersionRange(1, 2, 3), VersionRange(4, 5, 6)}},
         false /* optional */,
+        ExclusiveTo::EMPTY,
         false /* updatableViaApex */,
         testHalInterfaces(),
     };
@@ -1061,6 +1088,7 @@ TEST_F(LibVintfTest, CompatibilityMatrixGetHals) {
                                          "android.hardware.nfc",
                                          {{VersionRange(4, 5, 6), VersionRange(10, 11, 12)}},
                                          true /* optional */,
+                                         ExclusiveTo::EMPTY,
                                          false /* updatableViaApex */,
                                          testHalInterfaces()};
     auto cameraHals = getHals(cm, "android.hardware.camera");
@@ -5621,6 +5649,258 @@ TEST_F(LibVintfTest, RuntimeInfoGkiReleaseV) {
     EXPECT_EQ(Level::V, level);
 }
 
+TEST_F(LibVintfTest, AccessEntryInManifest) {
+    HalManifest expectedManifest;
+    expectedManifest.add(createManifestHal(HalFormat::AIDL, "android.hardware.foo",
+                                           {Transport::EMPTY, Arch::ARCH_EMPTY}, ExclusiveTo::VM,
+                                           {*FqInstance::from(SIZE_MAX, 1, "IFoo", "default")}));
+    std::string manifestXml = "<manifest " + kMetaVersionStr +
+                              " type=\"device\">\n"
+                              "    <hal format=\"aidl\" exclusive-to=\"virtual-machine\">\n"
+                              "        <name>android.hardware.foo</name>\n"
+                              "        <version>1</version>\n"
+                              "        <interface>\n"
+                              "            <name>IFoo</name>\n"
+                              "            <instance>default</instance>\n"
+                              "        </interface>\n"
+                              "    </hal>\n"
+                              "</manifest>\n";
+    HalManifest manifest;
+    EXPECT_TRUE(fromXml(&manifest, manifestXml));
+    EXPECT_EQ(expectedManifest, manifest)
+        << dump(expectedManifest) << " is expected but got " << dump(manifest);
+}
+
+TEST_F(LibVintfTest, NoAccessEntryInManifestIsEmpty) {
+    HalManifest expectedManifest;
+    expectedManifest.add(createManifestHal(HalFormat::AIDL, "android.hardware.foo",
+                                           {Transport::EMPTY, Arch::ARCH_EMPTY}, ExclusiveTo::EMPTY,
+                                           {*FqInstance::from(SIZE_MAX, 1, "IFoo", "default")}));
+    std::string manifestXml = "<manifest " + kMetaVersionStr +
+                              " type=\"device\">\n"
+                              "    <hal format=\"aidl\">\n"
+                              "        <name>android.hardware.foo</name>\n"
+                              "        <version>1</version>\n"
+                              "        <interface>\n"
+                              "            <name>IFoo</name>\n"
+                              "            <instance>default</instance>\n"
+                              "        </interface>\n"
+                              "    </hal>\n"
+                              "</manifest>\n";
+    HalManifest manifest;
+    EXPECT_TRUE(fromXml(&manifest, manifestXml));
+    EXPECT_EQ(expectedManifest, manifest)
+        << dump(expectedManifest) << " is expected but got " << dump(manifest);
+}
+
+TEST_F(LibVintfTest, UnknownAccessEntryInManifestIsEmpty) {
+    HalManifest expectedManifest;
+    expectedManifest.add(createManifestHal(HalFormat::AIDL, "android.hardware.foo",
+                                           {Transport::EMPTY, Arch::ARCH_EMPTY}, ExclusiveTo::EMPTY,
+                                           {*FqInstance::from(SIZE_MAX, 1, "IFoo", "default")}));
+    std::string manifestXml = "<manifest " + kMetaVersionStr +
+                              " type=\"device\">\n"
+                              "    <hal format=\"aidl\" exclusive-to=\"blooper\">\n"
+                              "        <name>android.hardware.foo</name>\n"
+                              "        <version>1</version>\n"
+                              "        <interface>\n"
+                              "            <name>IFoo</name>\n"
+                              "            <instance>default</instance>\n"
+                              "        </interface>\n"
+                              "    </hal>\n"
+                              "</manifest>\n";
+    HalManifest manifest;
+    std::string error;
+    EXPECT_FALSE(fromXml(&manifest, manifestXml, &error));
+    EXPECT_EQ(error,
+              "Could not parse element with name <hal> in element <manifest>: Unknown value "
+              "(\"blooper\") for attribute 'exclusive-to' is considered a failure.");
+}
+
+TEST_F(LibVintfTest, AccessEntryInMatrix) {
+    MatrixHal mh{HalFormat::AIDL,
+                 "android.hardware.foo",
+                 {{SIZE_MAX, 1}},
+                 false /* optional */,
+                 ExclusiveTo::VM,
+                 false /* updatableViaApex */,
+                 {}};
+    EXPECT_TRUE(insert(&mh.interfaces, {"IFoo", {"default"}}));
+    std::string xml = toXml(mh);
+    EXPECT_EQ(xml,
+              "<hal format=\"aidl\" optional=\"false\" exclusive-to=\"virtual-machine\">\n"
+              "    <name>android.hardware.foo</name>\n"
+              "    <interface>\n"
+              "        <name>IFoo</name>\n"
+              "        <instance>default</instance>\n"
+              "    </interface>\n"
+              "</hal>\n");
+    MatrixHal mh2;
+    EXPECT_TRUE(fromXml(&mh2, xml));
+    EXPECT_EQ(mh, mh2);
+}
+
+TEST_F(LibVintfTest, NoAccessEntryInMatrix) {
+    MatrixHal mh{HalFormat::AIDL,
+                 "android.hardware.foo",
+                 {{SIZE_MAX, 1}},
+                 false /* optional */,
+                 ExclusiveTo::EMPTY,
+                 false /* updatableViaApex */,
+                 {}};
+    EXPECT_TRUE(insert(&mh.interfaces, {"IFoo", {"default"}}));
+    std::string xml = toXml(mh);
+    EXPECT_EQ(xml,
+              "<hal format=\"aidl\" optional=\"false\">\n"
+              "    <name>android.hardware.foo</name>\n"
+              "    <interface>\n"
+              "        <name>IFoo</name>\n"
+              "        <instance>default</instance>\n"
+              "    </interface>\n"
+              "</hal>\n");
+    MatrixHal mh2;
+    EXPECT_TRUE(fromXml(&mh2, xml));
+    EXPECT_EQ(mh, mh2);
+}
+
+// Specific access desired and declared
+TEST_F(LibVintfTest, AccessCompatibleSimple) {
+    CompatibilityMatrix cm;
+    HalManifest manifest;
+    std::string xml;
+    std::string error;
+
+    xml = "<compatibility-matrix " + kMetaVersionStr +
+          " type=\"framework\">\n"
+          "    <hal format=\"aidl\" exclusive-to=\"virtual-machine\">\n"
+          "        <name>android.hardware.foo</name>\n"
+          "        <interface>\n"
+          "            <name>IFoo</name>\n"
+          "            <instance>default</instance>\n"
+          "        </interface>\n"
+          "    </hal>\n"
+          "    <sepolicy>\n"
+          "        <kernel-sepolicy-version>30</kernel-sepolicy-version>\n"
+          "        <sepolicy-version>25.5</sepolicy-version>\n"
+          "    </sepolicy>\n"
+          "</compatibility-matrix>\n";
+    EXPECT_TRUE(fromXml(&cm, xml, &error)) << error;
+
+    xml = "<manifest " + kMetaVersionStr +
+          " type=\"device\">\n"
+          "    <hal format=\"aidl\" exclusive-to=\"virtual-machine\">\n"
+          "        <name>android.hardware.foo</name>\n"
+          "        <version>1</version>\n"
+          "        <interface>\n"
+          "            <name>IFoo</name>\n"
+          "            <instance>default</instance>\n"
+          "        </interface>\n"
+          "    </hal>\n"
+          "    <sepolicy>\n"
+          "        <version>25.5</version>\n"
+          "    </sepolicy>\n"
+          "</manifest>\n";
+    EXPECT_TRUE(fromXml(&manifest, xml, &error)) << error;
+
+    EXPECT_TRUE(manifest.checkCompatibility(cm, &error)) << error;
+}
+
+// FCM expects specific access, but device provides normal access to host
+TEST_F(LibVintfTest, AccessIncompatibleNoAccess) {
+    CompatibilityMatrix cm;
+    HalManifest manifest;
+    std::string xml;
+    std::string error;
+
+    xml = "<compatibility-matrix " + kMetaVersionStr +
+          " type=\"framework\">\n"
+          "    <hal format=\"aidl\" optional=\"false\" exclusive-to=\"virtual-machine\">\n"
+          "        <name>android.hardware.foo</name>\n"
+          "        <interface>\n"
+          "            <name>IFoo</name>\n"
+          "            <instance>default</instance>\n"
+          "        </interface>\n"
+          "    </hal>\n"
+          "    <sepolicy>\n"
+          "        <kernel-sepolicy-version>30</kernel-sepolicy-version>\n"
+          "        <sepolicy-version>25.5</sepolicy-version>\n"
+          "    </sepolicy>\n"
+          "</compatibility-matrix>\n";
+    EXPECT_TRUE(fromXml(&cm, xml, &error)) << error;
+
+    xml = "<manifest " + kMetaVersionStr +
+          " type=\"device\">\n"
+          "    <hal format=\"aidl\">\n"
+          "        <name>android.hardware.foo</name>\n"
+          "        <version>1</version>\n"
+          "        <interface>\n"
+          "            <name>IFoo</name>\n"
+          "            <instance>default</instance>\n"
+          "        </interface>\n"
+          "    </hal>\n"
+          "    <sepolicy>\n"
+          "        <version>25.5</version>\n"
+          "    </sepolicy>\n"
+          "</manifest>\n";
+    EXPECT_TRUE(fromXml(&manifest, xml, &error)) << error;
+
+    EXPECT_TRUE(manifest.checkCompatibility(cm, &error)) << error;
+
+    // Error comes from unused HALs because the manifest provided a service
+    // with access that the matrix doesn't expect
+    auto unused = checkUnusedHals(manifest, cm);
+    EXPECT_FALSE(unused.empty())
+        << "Should conatin 'android.hardware.foo' HAL with ExclusiveTo::EMPTY but doesn't";
+}
+
+// FCM expects normal, non-exclusive, access for service but device
+// only provides exclusive access to virtual-machine clients
+TEST_F(LibVintfTest, AccessIncompatibleWrongAccess) {
+    CompatibilityMatrix cm;
+    HalManifest manifest;
+    std::string xml;
+    std::string error;
+
+    xml = "<compatibility-matrix " + kMetaVersionStr +
+          " type=\"framework\">\n"
+          "    <hal format=\"aidl\">\n"
+          "        <name>android.hardware.foo</name>\n"
+          "        <interface>\n"
+          "            <name>IFoo</name>\n"
+          "            <instance>default</instance>\n"
+          "        </interface>\n"
+          "    </hal>\n"
+          "    <sepolicy>\n"
+          "        <kernel-sepolicy-version>30</kernel-sepolicy-version>\n"
+          "        <sepolicy-version>25.5</sepolicy-version>\n"
+          "    </sepolicy>\n"
+          "</compatibility-matrix>\n";
+    EXPECT_TRUE(fromXml(&cm, xml, &error)) << error;
+
+    xml = "<manifest " + kMetaVersionStr +
+          " type=\"device\">\n"
+          "    <hal format=\"aidl\" exclusive-to=\"virtual-machine\">\n"
+          "        <name>android.hardware.foo</name>\n"
+          "        <version>1</version>\n"
+          "        <interface>\n"
+          "            <name>IFoo</name>\n"
+          "            <instance>default</instance>\n"
+          "        </interface>\n"
+          "    </hal>\n"
+          "    <sepolicy>\n"
+          "        <version>25.5</version>\n"
+          "    </sepolicy>\n"
+          "</manifest>\n";
+    EXPECT_TRUE(fromXml(&manifest, xml, &error)) << error;
+
+    EXPECT_TRUE(manifest.checkCompatibility(cm, &error)) << error;
+    // Error comes from unused HALs because the manifest provided a service
+    // with access that the matrix doesn't expect
+    auto unused = checkUnusedHals(manifest, cm);
+    EXPECT_FALSE(unused.empty())
+        << "Should contain 'android.hardware.foo' HAL with ExclusiveTo::VM but doesn't";
+}
+
 class ManifestMissingITest : public LibVintfTest,
                              public ::testing::WithParamInterface<std::string> {
    public:
@@ -6658,6 +6938,47 @@ TEST_F(DeviceCompatibilityMatrixCombineTest, AidlAndHidlNames) {
 
 // clang-format on
 
+TEST(FileSystem, PathReplacingFileSystem) {
+    std::map<std::string, std::string> files = {
+        {"a/a", "a/a"}, {"aa/aa", "aa/aa"}, {"b/b", "b/b"}, {"bb/bb", "bb/bb"}, {"x/y/z", "x/y/z"},
+    };
+    std::map<std::string, std::string> replacements = {
+        {"a", "b"},
+        {"aa", "bb"},
+        {"x", "a"},
+        {"x/y", "b"},
+    };
+    details::PathReplacingFileSystem fs(std::make_unique<InMemoryFileSystem>(files), replacements);
+
+    std::string fetched;
+    std::vector<std::string> list;
+
+    // no replace
+    ASSERT_EQ(OK, fs.fetch("b/b", &fetched, nullptr));
+    ASSERT_EQ("b/b", fetched);
+
+    // replace
+    ASSERT_EQ(OK, fs.fetch("a/b", &fetched, nullptr));
+    ASSERT_EQ("b/b", fetched);
+    ASSERT_EQ(OK, fs.fetch("aa/bb", &fetched, nullptr));
+    ASSERT_EQ("bb/bb", fetched);
+
+    // "a" doesn't match with "aa"
+    ASSERT_EQ(OK, fs.listFiles("aa/", &list, nullptr));
+    ASSERT_EQ(std::vector{"bb"s}, list);
+
+    // do not replace recursively
+    ASSERT_EQ(OK, fs.fetch("x/a", &fetched, nullptr));
+    ASSERT_EQ("a/a", fetched);
+
+    // longer match wins.
+    ASSERT_EQ(OK, fs.fetch("x/y/b", &fetched, nullptr));
+    ASSERT_EQ("b/b", fetched);
+
+    ASSERT_EQ(OK, fs.fetch("x/a", &fetched, nullptr));
+    ASSERT_EQ("a/a", fetched);
+}
+
 } // namespace vintf
 } // namespace android
 
diff --git a/test/vintf_object_tests.cpp b/test/vintf_object_tests.cpp
index 52376c1..9baeb59 100644
--- a/test/vintf_object_tests.cpp
+++ b/test/vintf_object_tests.cpp
@@ -238,6 +238,14 @@ const std::string systemMatrixLevel1 =
     "            <instance>default</instance>\n"
     "        </interface>\n"
     "    </hal>\n"
+    "    <hal format=\"aidl\" exclusive-to=\"virtual-machine\">\n"
+    "        <name>android.hardware.vm.removed</name>\n"
+    "        <version>2</version>\n"
+    "        <interface>\n"
+    "            <name>IRemoved</name>\n"
+    "            <instance>default</instance>\n"
+    "        </interface>\n"
+    "    </hal>\n"
     "</compatibility-matrix>\n";
 
 const std::string systemMatrixLevel2 =
@@ -266,6 +274,14 @@ const std::string systemMatrixLevel2 =
     "            <instance>default</instance>\n"
     "        </interface>\n"
     "    </hal>\n"
+    "    <hal format=\"aidl\" exclusive-to=\"virtual-machine\">\n"
+    "        <name>android.hardware.vm.removed</name>\n"
+    "        <version>3</version>\n"
+    "        <interface>\n"
+    "            <name>IRemoved</name>\n"
+    "            <instance>default</instance>\n"
+    "        </interface>\n"
+    "    </hal>\n"
     "</compatibility-matrix>\n";
 
 //
@@ -547,7 +563,8 @@ class VintfObjectTestBase : public ::testing::Test {
 
     // clang-format on
     void expectVendorManifest(Level level, const std::vector<std::string>& fqInstances,
-                              const std::vector<FqInstance>& aidlInstances = {}) {
+                              const std::vector<FqInstance>& aidlInstances = {},
+                              ExclusiveTo exclusiveTo = ExclusiveTo::EMPTY) {
         std::string xml =
             android::base::StringPrintf(R"(<manifest %s type="device" target-level="%s">)",
                                         kMetaVersionStr.c_str(), to_string(level).c_str());
@@ -570,12 +587,13 @@ class VintfObjectTestBase : public ::testing::Test {
         for (const auto& fqInstance : aidlInstances) {
             xml += android::base::StringPrintf(
                 R"(
-                    <hal format="aidl">
+                    <hal format="aidl" exclusive-to="%s">
                         <name>%s</name>
                         <version>%zu</version>
                         <fqname>%s</fqname>
                     </hal>
                 )",
+                gExclusiveToStrings.at(static_cast<size_t>(exclusiveTo)),
                 fqInstance.getPackage().c_str(), fqInstance.getMinorVersion(),
                 toFQNameString(fqInstance.getInterface(), fqInstance.getInstance()).c_str());
         }
@@ -879,9 +897,9 @@ class DeviceManifestTest : public VintfObjectTestBase {
     void expectApex(const std::string& halManifest = apexHalManifest) {
         expectFetchRepeatedly(kApexInfoFile, R"(<apex-info-list>
             <apex-info moduleName="com.test"
-                preinstalledModulePath="/vendor/apex/com.test.apex" isActive="true"/>
+                partition="VENDOR" isActive="true"/>
             <apex-info moduleName="com.novintf"
-                preinstalledModulePath="/vendor/apex/com.novintf.apex" isActive="true"/>
+                partition="VENDOR" isActive="true"/>
         </apex-info-list>)");
         EXPECT_CALL(fetcher(), modifiedTime(kApexInfoFile, _, _))
             .WillOnce(Invoke([](auto, timespec* out, auto){
@@ -1068,7 +1086,7 @@ TEST_F(VendorApexTest, ReadBootstrapApexBeforeApexReady) {
             out = R"(<?xml version="1.0" encoding="utf-8"?>
                 <apex-info-list>
                     <apex-info moduleName="com.vendor.foo"
-                            preinstalledModulePath="/vendor/apex/foo.apex"
+                            partition="VENDOR"
                             isActive="true" />
                 </apex-info-list>)";
             return ::android::OK;
@@ -1244,7 +1262,7 @@ TEST_F(ManifestOverrideTest, NoOverrideForVendorApex) {
         R"(<apex-info-list>
           <apex-info
             moduleName="com.android.foo"
-            preinstalledModulePath="/vendor/apex/com.android.foo.apex"
+            partition="VENDOR"
             isActive="true"/>
         </apex-info-list>)");
     expect("/apex/com.android.foo/etc/vintf/foo.xml",
@@ -1267,7 +1285,7 @@ TEST_F(ManifestOverrideTest, OdmOverridesVendorApex) {
         R"(<apex-info-list>
             <apex-info
                 moduleName="com.android.foo"
-                preinstalledModulePath="/vendor/apex/com.android.foo.apex"
+                partition="VENDOR"
                 isActive="true"/>
             </apex-info-list>)");
     expect("/apex/com.android.foo/etc/vintf/foo.xml",
@@ -1364,6 +1382,33 @@ TEST_F(DeprecateTest, CheckRemovedSystem) {
         << "removed@1.0 should be deprecated. " << error;
 }
 
+TEST_F(DeprecateTest, CheckRemovedVersionAccess) {
+    expectVendorManifest(Level{2}, {}, {aidlFqInstance("android.hardware.vm.removed", 2, "IRemoved",
+                                                       "default")}, ExclusiveTo::VM);
+    std::string error;
+    EXPECT_EQ(DEPRECATED, vintfObject->checkDeprecation({}, &error))
+        << "removed@2 should be deprecated. " << error;
+    EXPECT_IN("android.hardware.vm.removed", error);
+    EXPECT_IN("is deprecated; requires at least", error);
+}
+
+TEST_F(DeprecateTest, CheckOkVersionSystemAccess) {
+    expectVendorManifest(Level{2}, {}, {aidlFqInstance("android.hardware.vm.removed", 3, "IRemoved",
+                                                       "default")}, ExclusiveTo::VM);
+    std::string error;
+    EXPECT_EQ(NO_DEPRECATED_HALS, vintfObject->checkDeprecation({}, &error))
+        << "V3 should be allowed at level 2" << error;
+}
+
+TEST_F(DeprecateTest, CheckRemovedSystemAccessWrong) {
+    expectVendorManifest(Level{2}, {}, {aidlFqInstance("android.hardware.vm.removed", 2, "IRemoved",
+                                                       "default")}, ExclusiveTo::EMPTY);
+    std::string error;
+    EXPECT_EQ(NO_DEPRECATED_HALS, vintfObject->checkDeprecation({}, &error))
+        << "There is no entry for this HAL with ExclusiveTo::EMPTY so it "
+        << "should not show as deprecated." << error;
+}
+
 TEST_F(DeprecateTest, CheckRemovedSystemAidl) {
     expectVendorManifest(Level{2}, {}, {
         aidlFqInstance("android.hardware.removed", 101, "IRemoved", "default"),
@@ -2204,7 +2249,7 @@ class FrameworkManifestTest : public VintfObjectTestBase,
             <apex-info-list>
                 <apex-info
                     moduleName="com.system"
-                    preinstalledModulePath="/system/apex/com.system.apex"
+                    partition="SYSTEM"
                     isActive="true"/>
             </apex-info-list>)");
         EXPECT_CALL(fetcher(), modifiedTime(kApexInfoFile, _, _))
diff --git a/xsd/compatibilityMatrix/Android.bp b/xsd/compatibilityMatrix/Android.bp
index 41b18fa..31b5a66 100644
--- a/xsd/compatibilityMatrix/Android.bp
+++ b/xsd/compatibilityMatrix/Android.bp
@@ -31,4 +31,5 @@ xsd_config {
     name: "compatibility_matrix",
     srcs: [":compatibility_matrix_schema"],
     package_name: "compatibility.matrix",
+    api_dir: "schema",
 }
diff --git a/xsd/compatibilityMatrix/compatibility_matrix.xsd b/xsd/compatibilityMatrix/compatibility_matrix.xsd
index 7cd0e2e..4a5c4c9 100644
--- a/xsd/compatibilityMatrix/compatibility_matrix.xsd
+++ b/xsd/compatibilityMatrix/compatibility_matrix.xsd
@@ -45,6 +45,7 @@
         <xs:attribute name="format" type="xs:string"/>
         <xs:attribute name="optional" type="xs:string"/>
         <xs:attribute name="updatable-via-apex" type="xs:boolean"/>
+        <xs:attribute name="exclusive-to" type="xs:string"/>
     </xs:complexType>
     <xs:complexType name="interface">
         <xs:sequence>
diff --git a/xsd/compatibilityMatrix/api/current.txt b/xsd/compatibilityMatrix/schema/current.txt
similarity index 98%
rename from xsd/compatibilityMatrix/api/current.txt
rename to xsd/compatibilityMatrix/schema/current.txt
index b7de07b..16d0fae 100644
--- a/xsd/compatibilityMatrix/api/current.txt
+++ b/xsd/compatibilityMatrix/schema/current.txt
@@ -48,6 +48,7 @@ package compatibility.matrix {
 
   public class Hal {
     ctor public Hal();
+    method public String getExclusiveTo();
     method public String getFormat();
     method public java.util.List<java.lang.String> getFqname();
     method public String getName();
@@ -55,6 +56,7 @@ package compatibility.matrix {
     method public boolean getUpdatableViaApex();
     method public java.util.List<java.lang.String> getVersion();
     method public java.util.List<compatibility.matrix.Interface> get_interface();
+    method public void setExclusiveTo(String);
     method public void setFormat(String);
     method public void setName(String);
     method public void setOptional(String);
diff --git a/xsd/compatibilityMatrix/api/last_current.txt b/xsd/compatibilityMatrix/schema/last_current.txt
similarity index 100%
rename from xsd/compatibilityMatrix/api/last_current.txt
rename to xsd/compatibilityMatrix/schema/last_current.txt
diff --git a/xsd/compatibilityMatrix/api/last_removed.txt b/xsd/compatibilityMatrix/schema/last_removed.txt
similarity index 100%
rename from xsd/compatibilityMatrix/api/last_removed.txt
rename to xsd/compatibilityMatrix/schema/last_removed.txt
diff --git a/xsd/compatibilityMatrix/api/removed.txt b/xsd/compatibilityMatrix/schema/removed.txt
similarity index 100%
rename from xsd/compatibilityMatrix/api/removed.txt
rename to xsd/compatibilityMatrix/schema/removed.txt
diff --git a/xsd/compatibilityMatrix/vts/Android.bp b/xsd/compatibilityMatrix/vts/Android.bp
index d310fa0..eaafd10 100644
--- a/xsd/compatibilityMatrix/vts/Android.bp
+++ b/xsd/compatibilityMatrix/vts/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     // http://go/android-license-faq
     // A large-scale-change added 'default_applicable_licenses' to import
     // the below license kinds from "system_libvintf_license":
diff --git a/xsd/halManifest/hal_manifest.xsd b/xsd/halManifest/hal_manifest.xsd
index 1118c65..a23f563 100644
--- a/xsd/halManifest/hal_manifest.xsd
+++ b/xsd/halManifest/hal_manifest.xsd
@@ -50,8 +50,10 @@
             <xs:element name="version" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
             <xs:element name="interface" type="interface" minOccurs="0" maxOccurs="unbounded"/>
             <xs:element name="fqname" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
+            <xs:element name="accessor" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
         </xs:sequence>
         <xs:attribute name="format" type="xs:string"/>
+        <xs:attribute name="exclusive-to" type="xs:string"/>
         <xs:attribute name="override" type="xs:string"/>
         <xs:attribute name="updatable-via-apex" type="xs:string"/>
         <xs:attribute name="updatable-via-system" type="xs:string"/>
diff --git a/xsd/halManifest/schema/current.txt b/xsd/halManifest/schema/current.txt
index 765e6bc..7af4b03 100644
--- a/xsd/halManifest/schema/current.txt
+++ b/xsd/halManifest/schema/current.txt
@@ -3,6 +3,8 @@ package hal.manifest {
 
   public class Hal {
     ctor public Hal();
+    method public java.util.List<java.lang.String> getAccessor();
+    method public String getExclusiveTo();
     method public String getFormat();
     method public java.util.List<java.lang.String> getFqname();
     method public String getMaxLevel();
@@ -14,6 +16,7 @@ package hal.manifest {
     method public String getUpdatableViaSystem();
     method public java.util.List<java.lang.String> getVersion();
     method public java.util.List<hal.manifest.Interface> get_interface();
+    method public void setExclusiveTo(String);
     method public void setFormat(String);
     method public void setMaxLevel(String);
     method public void setMinLevel(String);
diff --git a/xsd/halManifest/vts/Android.bp b/xsd/halManifest/vts/Android.bp
index 972d512..475b411 100644
--- a/xsd/halManifest/vts/Android.bp
+++ b/xsd/halManifest/vts/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     // http://go/android-license-faq
     // A large-scale-change added 'default_applicable_licenses' to import
     // the below license kinds from "system_libvintf_license":
```

