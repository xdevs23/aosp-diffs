```diff
diff --git a/Android.bp b/Android.bp
index def212e..a13e290 100644
--- a/Android.bp
+++ b/Android.bp
@@ -178,6 +178,9 @@ cc_binary_host {
         "HostFileSystem.cpp",
     ],
     local_include_dirs: ["include-host"],
+    dist: {
+        targets: ["dist_files"],
+    },
 }
 
 cc_library_static {
diff --git a/Android.mk b/Android.mk
deleted file mode 100644
index 2c23f30..0000000
--- a/Android.mk
+++ /dev/null
@@ -1,18 +0,0 @@
-# Copyright (C) 2018 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-LOCAL_PATH := $(call my-dir)
-
-$(call dist-for-goals,dist_files,$(HOST_OUT_EXECUTABLES)/checkvintf)
-
-include $(call first-makefiles-under,$(LOCAL_PATH))
diff --git a/Apex.cpp b/Apex.cpp
index 96fb155..20705e2 100644
--- a/Apex.cpp
+++ b/Apex.cpp
@@ -103,7 +103,9 @@ std::optional<timespec> GetModifiedTime(FileSystem* fileSystem, PropertyFetcher*
 status_t GetDeviceVintfDirs(FileSystem* fileSystem, PropertyFetcher* propertyFetcher,
                             std::vector<std::string>* dirs, std::string* error) {
     return GetVintfDirs(fileSystem, propertyFetcher, dirs, error, [](const std::string& path) {
-        return StartsWith(path, "/vendor/apex/") || StartsWith(path, "/system/vendor/apex/");
+        return StartsWith(path, "/vendor/apex/") || StartsWith(path, "/system/vendor/apex/") ||
+               StartsWith(path, "/odm/apex/") || StartsWith(path, "/vendor/odm/apex/") ||
+               StartsWith(path, "/system/vendor/odm/apex/");
     });
 }
 
diff --git a/HalManifest.cpp b/HalManifest.cpp
index 61d2c32..8224bab 100644
--- a/HalManifest.cpp
+++ b/HalManifest.cpp
@@ -111,48 +111,78 @@ bool HalManifest::addingConflictingFqInstance(const ManifestHal& halToAdd,
     // Key: FqInstance with minor version 0
     // Value: original HAL and FqInstance
     std::map<FqInstance, std::tuple<const ManifestHal*, ManifestInstance>> existing;
+    std::map<std::string, std::tuple<const ManifestHal*, ManifestInstance>> existingAccessors;
     for (auto it = existingHals.first; it != existingHals.second; ++it) {
         const ManifestHal& existingHal = it->second;
-        bool success =
-            existingHal.forEachInstance([&existingHal, &existing](const auto& manifestInstance) {
+        bool success = existingHal.forEachInstance(
+            [&existingHal, &existing, &existingAccessors](const auto& manifestInstance) {
                 auto versionZero = manifestInstance.version().withMinor(0);
                 auto key = manifestInstance.withVersion(versionZero).getFqInstance();
                 // Assume integrity on existingHals, so no check on emplace().second
                 existing.emplace(key, std::make_tuple(&existingHal, manifestInstance));
+                if (auto accessor = manifestInstance.accessor(); accessor.has_value()) {
+                    existingAccessors.emplace(accessor.value(),
+                                              std::make_tuple(&existingHal, manifestInstance));
+                }
                 return true;  // continue
             });
         if (!success) {
             return false;
         }
     }
-    return halToAdd.forEachInstance(
-        [&halToAdd, &existing, error](const auto& manifestInstanceToAdd) {
-            auto versionZero = manifestInstanceToAdd.version().withMinor(0);
-            auto key = manifestInstanceToAdd.withVersion(versionZero).getFqInstance();
-
-            auto&& [existingIt, inserted] =
-                existing.emplace(key, std::make_tuple(&halToAdd, manifestInstanceToAdd));
-            if (inserted) {
-                return true;  // continue
+    return halToAdd.forEachInstance([&halToAdd, &existing, &existingAccessors,
+                                     &error](const auto& manifestInstanceToAdd) {
+        auto constructErrorMessage = [&halToAdd, &manifestInstanceToAdd](
+                                         const auto& existingManifestInstance,
+                                         const auto& existingHal) {
+            std::string errorMsg = existingManifestInstance.descriptionWithoutPackage();
+            if (!existingHal->fileName().empty()) {
+                errorMsg += " (from " + existingHal->fileName() + ")";
+            }
+            errorMsg += " vs. " + manifestInstanceToAdd.descriptionWithoutPackage();
+            if (!halToAdd.fileName().empty()) {
+                errorMsg += " (from " + halToAdd.fileName() + ")";
             }
+            return errorMsg;
+        };
 
+        auto versionZero = manifestInstanceToAdd.version().withMinor(0);
+        auto key = manifestInstanceToAdd.withVersion(versionZero).getFqInstance();
+
+        // Check duplicate FqInstance.
+        auto&& [existingIt, inserted] =
+            existing.emplace(key, std::make_tuple(&halToAdd, manifestInstanceToAdd));
+        if (!inserted) {
             if (error) {
                 auto&& [existingHal, existingManifestInstance] = existingIt->second;
                 *error = "Conflicting FqInstance: ";
-                *error += existingManifestInstance.descriptionWithoutPackage();
-                if (!existingHal->fileName().empty()) {
-                    *error += " (from " + existingHal->fileName() + ")";
-                }
-                *error += " vs. " + manifestInstanceToAdd.descriptionWithoutPackage();
-                if (!halToAdd.fileName().empty()) {
-                    *error += " (from " + halToAdd.fileName() + ")";
-                }
+                *error += constructErrorMessage(existingManifestInstance, existingHal);
                 *error +=
                     ". Check whether or not multiple modules providing the same HAL are installed.";
             }
-
             return false;  // break and let addingConflictingFqInstance return false
-        });
+        }
+
+        // Check duplicate accessor.
+        auto accessor = manifestInstanceToAdd.accessor();
+        if (!accessor.has_value()) {
+            return true;
+        }
+        auto&& [existingAccessorIt, insertedAccessor] = existingAccessors.emplace(
+            accessor.value(), std::make_tuple(&halToAdd, manifestInstanceToAdd));
+        if (insertedAccessor) {
+            return true;
+        }
+        if (error) {
+            auto&& [existingHal, existingManifestInstance] = existingAccessorIt->second;
+            *error = "Conflicting Accessor: ";
+            *error += constructErrorMessage(existingManifestInstance, existingHal);
+            *error +=
+                ". Check whether or not multiple modules providing the same accessor are "
+                "installed.";
+        }
+        return false;  // break and let addingConflictingFqInstance return false
+    });
 }
 
 // Remove elements from "list" if p(element) returns true.
diff --git a/ManifestHal.cpp b/ManifestHal.cpp
index 0952e4f..252f455 100644
--- a/ManifestHal.cpp
+++ b/ManifestHal.cpp
@@ -50,6 +50,10 @@ bool ManifestHal::isValid(std::string* error) const {
         success = false;
         if (error) *error += transportArchError + "\n";
     }
+    if (accessor().has_value() && accessor().value().empty()) {
+        success = false;
+        if (error) *error += "Accessor requires a non-empty value.\n";
+    }
     return success;
 }
 
@@ -64,8 +68,9 @@ bool ManifestHal::operator==(const ManifestHal &other) const {
     if (!(transportArch == other.transportArch)) return false;
     if (isOverride() != other.isOverride()) return false;
     if (updatableViaApex() != other.updatableViaApex()) return false;
+    if (updatableViaSystem() != other.updatableViaSystem()) return false;
     if (mManifestInstances != other.mManifestInstances) return false;
-    return true;
+    return accessor() == other.accessor();
 }
 
 bool ManifestHal::forEachInstance(const std::function<bool(const ManifestInstance&)>& func) const {
@@ -179,7 +184,8 @@ bool ManifestHal::insertInstance(const FqInstance& e, bool allowDupMajorVersion,
     }
 
     mManifestInstances.emplace(std::move(toAdd), this->transportArch, this->format,
-                               this->updatableViaApex());
+                               this->updatableViaApex(), this->accessor(),
+                               this->updatableViaSystem());
     return true;
 }
 
diff --git a/ManifestInstance.cpp b/ManifestInstance.cpp
index 60bd146..bd12d9f 100644
--- a/ManifestInstance.cpp
+++ b/ManifestInstance.cpp
@@ -41,19 +41,26 @@ ManifestInstance& ManifestInstance::operator=(const ManifestInstance&) = default
 ManifestInstance& ManifestInstance::operator=(ManifestInstance&&) noexcept = default;
 
 ManifestInstance::ManifestInstance(FqInstance&& fqInstance, TransportArch&& ta, HalFormat fmt,
-                                   std::optional<std::string>&& updatableViaApex)
+                                   std::optional<std::string>&& updatableViaApex,
+                                   std::optional<std::string>&& accessor, bool updatableViaSystem)
     : mFqInstance(std::move(fqInstance)),
       mTransportArch(std::move(ta)),
       mHalFormat(fmt),
-      mUpdatableViaApex(std::move(updatableViaApex)) {}
+      mUpdatableViaApex(std::move(updatableViaApex)),
+      mAccessor(std::move(accessor)),
+      mUpdatableViaSystem(std::move(updatableViaSystem)) {}
 
 ManifestInstance::ManifestInstance(const FqInstance& fqInstance, const TransportArch& ta,
                                    HalFormat fmt,
-                                   const std::optional<std::string>& updatableViaApex)
+                                   const std::optional<std::string>& updatableViaApex,
+                                   const std::optional<std::string>& accessor,
+                                   bool updatableViaSystem)
     : mFqInstance(fqInstance),
       mTransportArch(ta),
       mHalFormat(fmt),
-      mUpdatableViaApex(updatableViaApex) {}
+      mUpdatableViaApex(updatableViaApex),
+      mAccessor(accessor),
+      mUpdatableViaSystem(updatableViaSystem) {}
 
 const std::string& ManifestInstance::package() const {
     return mFqInstance.getPackage();
@@ -95,13 +102,22 @@ const std::optional<std::string>& ManifestInstance::updatableViaApex() const {
     return mUpdatableViaApex;
 }
 
+const std::optional<std::string>& ManifestInstance::accessor() const {
+    return mAccessor;
+}
+
 const FqInstance& ManifestInstance::getFqInstance() const {
     return mFqInstance;
 }
 
+bool ManifestInstance::updatableViaSystem() const {
+    return mUpdatableViaSystem;
+}
+
 bool ManifestInstance::operator==(const ManifestInstance& other) const {
     return mFqInstance == other.mFqInstance && mTransportArch == other.mTransportArch &&
-           mHalFormat == other.mHalFormat && mUpdatableViaApex == other.mUpdatableViaApex;
+           mHalFormat == other.mHalFormat && mUpdatableViaApex == other.mUpdatableViaApex &&
+           mUpdatableViaSystem == other.mUpdatableViaSystem && mAccessor == other.mAccessor;
 }
 bool ManifestInstance::operator<(const ManifestInstance& other) const {
     if (mFqInstance < other.mFqInstance) return true;
@@ -110,7 +126,11 @@ bool ManifestInstance::operator<(const ManifestInstance& other) const {
     if (other.mTransportArch < mTransportArch) return false;
     if (mHalFormat < other.mHalFormat) return true;
     if (other.mHalFormat < mHalFormat) return false;
-    return mUpdatableViaApex < other.mUpdatableViaApex;
+    if (mUpdatableViaApex < other.mUpdatableViaApex) return true;
+    if (other.mUpdatableViaApex < mUpdatableViaApex) return false;
+    if (mUpdatableViaSystem < other.mUpdatableViaSystem) return true;
+    if (other.mUpdatableViaSystem < mUpdatableViaSystem) return false;
+    return mAccessor < other.mAccessor;
 }
 
 std::string ManifestInstance::getSimpleFqInstance() const {
@@ -165,7 +185,8 @@ ManifestInstance ManifestInstance::withVersion(const Version& v) const {
     FqInstance fqInstance;
     CHECK(fqInstance.setTo(getFqInstance().getPackage(), v.majorVer, v.minorVer,
                            getFqInstance().getInterface(), getFqInstance().getInstance()));
-    return ManifestInstance(std::move(fqInstance), mTransportArch, format(), mUpdatableViaApex);
+    return ManifestInstance(std::move(fqInstance), mTransportArch, format(), mUpdatableViaApex,
+                            mAccessor, mUpdatableViaSystem);
 }
 
 }  // namespace vintf
diff --git a/OWNERS b/OWNERS
index bbeb9b8..3518238 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,5 @@
 # Bug component: 192869
+devinmoore@google.com
 smoreland@google.com
 elsk@google.com
 malchev@google.com
diff --git a/RuntimeInfo.cpp b/RuntimeInfo.cpp
index 9496ccf..9dc4ad5 100644
--- a/RuntimeInfo.cpp
+++ b/RuntimeInfo.cpp
@@ -199,6 +199,9 @@ Level RuntimeInfo::gkiAndroidReleaseToLevel(uint64_t androidRelease) {
             case 15: {
                 ret = Level::V;
             } break;
+            case 16: {
+                ret = Level::W;
+            } break;
             // Add more levels above this line.
             default: {
                 LOG(FATAL) << "Convert Android " << androidRelease << " to level '" << ret
diff --git a/TEST_MAPPING b/TEST_MAPPING
index d6acf00..2e5faa0 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -8,6 +8,9 @@
     },
     {
       "name": "lshal_test"
+    },
+    {
+      "name": "vts_halManifest_validate_test"
     }
   ],
   "hwasan-presubmit": [
diff --git a/analyze_matrix/analyze_matrix.cpp b/analyze_matrix/analyze_matrix.cpp
index 3c2b2c3..c5eee23 100644
--- a/analyze_matrix/analyze_matrix.cpp
+++ b/analyze_matrix/analyze_matrix.cpp
@@ -90,6 +90,9 @@ std::string GetDescription(Level level) {
             return "Android 14 (U)";
         case Level::V:
             return "Android 15 (V)";
+        case Level::W:
+            // TODO(b/346861728) verify name/number once decided
+            return "Android 16 (W)";
         case Level::UNSPECIFIED:
             return "Level unspecified";
         default:
diff --git a/include/vintf/Level.h b/include/vintf/Level.h
index d638394..37dbbe7 100644
--- a/include/vintf/Level.h
+++ b/include/vintf/Level.h
@@ -43,6 +43,7 @@ enum class Level : size_t {
     T = 7,
     U = 8,
     V = 202404,
+    W = 202504,  // TODO(346861728) placeholder letter/number.
     // To add new values:
     // (1) add above this line.
     // (2) edit array below
@@ -68,6 +69,7 @@ inline bool IsValid(Level level) {
         Level::T,
         Level::U,
         Level::V,
+        Level::W,
         Level::UNSPECIFIED,
         // clang-format on
     };
diff --git a/include/vintf/ManifestHal.h b/include/vintf/ManifestHal.h
index 0b309d8..6bac534 100644
--- a/include/vintf/ManifestHal.h
+++ b/include/vintf/ManifestHal.h
@@ -58,6 +58,7 @@ struct ManifestHal : public WithFileName {
     inline std::optional<uint64_t> port() const { return transportArch.port; }
 
     inline const std::string& getName() const { return name; }
+    inline bool updatableViaSystem() const { return mUpdatableViaSystem; }
 
     // Assume isValid().
     bool forEachInstance(const std::function<bool(const ManifestInstance&)>& func) const;
@@ -65,6 +66,10 @@ struct ManifestHal : public WithFileName {
     bool isOverride() const { return mIsOverride; }
     const std::optional<std::string>& updatableViaApex() const { return mUpdatableViaApex; }
 
+    // Returns the name of the accessor interface for this HAL.
+    // If not set, no accessor will be used.
+    const std::optional<std::string>& accessor() const { return mAccessor; }
+
     // When true, the existence of this <hal> tag means the component does NOT
     // exist on the device. This is useful for ODM manifests to specify that
     // a HAL is disabled on certain products.
@@ -99,7 +104,9 @@ struct ManifestHal : public WithFileName {
     bool verifyInstance(const FqInstance& fqInstance, std::string* error = nullptr) const;
 
     bool mIsOverride = false;
+    std::optional<std::string> mAccessor;
     std::optional<std::string> mUpdatableViaApex;
+    bool mUpdatableViaSystem = false;
     // All instances specified with <fqname> and <version> x <interface> x <instance>
     std::set<ManifestInstance> mManifestInstances;
 
diff --git a/include/vintf/ManifestInstance.h b/include/vintf/ManifestInstance.h
index 4ae66e1..09940ff 100644
--- a/include/vintf/ManifestInstance.h
+++ b/include/vintf/ManifestInstance.h
@@ -38,9 +38,11 @@ class ManifestInstance {
 
     using VersionType = Version;
     ManifestInstance(FqInstance&& fqInstance, TransportArch&& ta, HalFormat fmt,
-                     std::optional<std::string>&& updatableViaApex);
+                     std::optional<std::string>&& updatableViaApex,
+                     std::optional<std::string>&& accessor, bool updatableViaSystem);
     ManifestInstance(const FqInstance& fqInstance, const TransportArch& ta, HalFormat fmt,
-                     const std::optional<std::string>& updatableViaApex);
+                     const std::optional<std::string>& updatableViaApex,
+                     const std::optional<std::string>& accessor, bool updatableViaSystem);
     const std::string& package() const;
     Version version() const;
     std::string interface() const;
@@ -48,9 +50,11 @@ class ManifestInstance {
     Transport transport() const;
     Arch arch() const;
     HalFormat format() const;
+    const std::optional<std::string>& accessor() const;
     const std::optional<std::string>& updatableViaApex() const;
     const std::optional<std::string> ip() const;
     const std::optional<uint64_t> port() const;
+    bool updatableViaSystem() const;
 
     bool operator==(const ManifestInstance& other) const;
     bool operator<(const ManifestInstance& other) const;
@@ -81,6 +85,8 @@ class ManifestInstance {
     TransportArch mTransportArch;
     HalFormat mHalFormat;
     std::optional<std::string> mUpdatableViaApex;
+    std::optional<std::string> mAccessor;
+    bool mUpdatableViaSystem;
 };
 
 }  // namespace vintf
diff --git a/include/vintf/MapValueIterator.h b/include/vintf/MapValueIterator.h
index b44c661..d999043 100644
--- a/include/vintf/MapValueIterator.h
+++ b/include/vintf/MapValueIterator.h
@@ -31,18 +31,13 @@ struct MapIterTypes {
 
     // Iterator over all values of a Map
     template<bool is_const>
-    struct IteratorImpl : public std::iterator <
-            std::bidirectional_iterator_tag, /* Category */
-            V,
-            ptrdiff_t, /* Distance */
-            typename std::conditional<is_const, const V *, V *>::type /* Pointer */,
-            typename std::conditional<is_const, const V &, V &>::type /* Reference */
-        >
+    struct IteratorImpl
     {
-        using traits = std::iterator_traits<IteratorImpl>;
-        using ptr_type = typename traits::pointer;
-        using ref_type = typename traits::reference;
-        using diff_type = typename traits::difference_type;
+        using iterator_category = std::bidirectional_iterator_tag;
+        using value_type = V;
+        using difference_type = ptrdiff_t;
+        using pointer = typename std::conditional<is_const, const V *, V *>::type;
+        using reference = typename std::conditional<is_const, const V &, V &>::type;
 
         using map_iter = typename std::conditional<is_const,
                 typename Map::const_iterator, typename Map::iterator>::type;
@@ -67,8 +62,8 @@ struct MapIterTypes {
             mIter--;
             return i;
         }
-        inline ref_type operator*() const  { return mIter->second; }
-        inline ptr_type operator->() const { return &(mIter->second); }
+        inline reference operator*() const  { return mIter->second; }
+        inline pointer operator->() const { return &(mIter->second); }
         inline bool operator==(const IteratorImpl &rhs) const { return mIter == rhs.mIter; }
         inline bool operator!=(const IteratorImpl &rhs) const { return mIter != rhs.mIter; }
 
diff --git a/parse_string.cpp b/parse_string.cpp
index caf58d9..6fdd9f5 100644
--- a/parse_string.cpp
+++ b/parse_string.cpp
@@ -28,10 +28,6 @@ using base::ParseUint;
 
 namespace vintf {
 
-static const std::string kRequired("required");
-static const std::string kOptional("optional");
-static const std::string kConfigPrefix("CONFIG_");
-
 std::vector<std::string> SplitString(const std::string &s, char c) {
     std::vector<std::string> components;
 
diff --git a/parse_xml.cpp b/parse_xml.cpp
index f5410e7..57b9d9d 100644
--- a/parse_xml.cpp
+++ b/parse_xml.cpp
@@ -336,9 +336,9 @@ struct XmlNodeConverter {
         return true;
     }
 
+    template <typename T>
     inline bool parseOptionalTextElement(NodeType* root, const std::string& elementName,
-                                         std::string&& defaultValue, std::string* s,
-                                         std::string* /* error */) const {
+                                         T&& defaultValue, T* s, std::string* /* error */) const {
         NodeType* child = getChild(root, elementName);
         *s = child == nullptr ? std::move(defaultValue) : getText(child);
         return true;
@@ -812,6 +812,13 @@ struct ManifestHalConverter : public XmlNodeConverter<ManifestHal> {
         if (const auto& apex = object.updatableViaApex(); apex.has_value()) {
             appendAttr(root, "updatable-via-apex", apex.value());
         }
+        // Only include update-via-system if enabled
+        if (object.updatableViaSystem()) {
+            appendAttr(root, "updatable-via-system", object.updatableViaSystem());
+        }
+        if (const auto& accessor = object.accessor(); accessor.has_value()) {
+            appendTextElement(root, "accessor", accessor.value(), param.d);
+        }
         if (param.flags.isFqnameEnabled()) {
             std::set<std::string> simpleFqInstances;
             object.forEachInstance([&simpleFqInstances](const auto& manifestInstance) {
@@ -835,6 +842,9 @@ struct ManifestHalConverter : public XmlNodeConverter<ManifestHal> {
             !parseOptionalAttr(root, "override", false, &object->mIsOverride, param.error) ||
             !parseOptionalAttr(root, "updatable-via-apex", {}, &object->mUpdatableViaApex,
                                param.error) ||
+            !parseOptionalAttr(root, "updatable-via-system", false /* defaultValue */,
+                               &object->mUpdatableViaSystem, param.error) ||
+            !parseOptionalTextElement(root, "accessor", {}, &object->mAccessor, param.error) ||
             !parseTextElement(root, "name", &object->name, param.error) ||
             !parseOptionalChild(root, TransportArchConverter{}, {}, &object->transportArch,
                                 param) ||
@@ -844,6 +854,10 @@ struct ManifestHalConverter : public XmlNodeConverter<ManifestHal> {
                                param.error)) {
             return false;
         }
+        if (getChildren(root, "accessor").size() > 1) {
+            *param.error = "No more than one <accessor> is allowed in <hal>";
+            return false;
+        }
 
         std::string_view apexName = parseApexName(param.fileName);
         if (!apexName.empty()) {
diff --git a/test/Android.bp b/test/Android.bp
index 48c74ea..19eeb3e 100644
--- a/test/Android.bp
+++ b/test/Android.bp
@@ -55,6 +55,7 @@ cc_test {
         "-O0",
         "-g",
         "-Wno-deprecated-declarations",
+        "-Wno-reorder-init-list",
     ],
     target: {
         android: {
@@ -102,6 +103,7 @@ cc_test {
     cflags: [
         "-O0",
         "-g",
+        "-Wno-reorder-init-list",
     ],
     target: {
         android: {
diff --git a/test/LibVintfTest.cpp b/test/LibVintfTest.cpp
index 3584800..dccf6b5 100644
--- a/test/LibVintfTest.cpp
+++ b/test/LibVintfTest.cpp
@@ -3652,6 +3652,115 @@ TEST_F(LibVintfTest, ParsingUpdatableHalsWithInterface) {
     EXPECT_THAT(foo.front()->updatableViaApex(), Optional(Eq("com.android.foo")));
 }
 
+TEST_F(LibVintfTest, ParsingUpdatableViaSystemHals) {
+    std::string error;
+
+    HalManifest manifest;
+    std::string manifestXml =
+        "<manifest " + kMetaVersionStr + " type=\"device\">\n"
+        "    <hal format=\"aidl\" updatable-via-system=\"true\">\n"
+        "        <name>android.hardware.foo</name>\n"
+        "        <fqname>IFoo/default</fqname>\n"
+        "    </hal>\n"
+        "</manifest>\n";
+    EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
+    EXPECT_EQ(manifestXml, toXml(manifest, SerializeFlags::HALS_ONLY));
+
+    auto foo = getHals(manifest, "android.hardware.foo");
+    ASSERT_EQ(1u, foo.size());
+    EXPECT_THAT(foo.front()->updatableViaSystem(), true);
+}
+
+TEST_F(LibVintfTest, ParsingUpdatableViaSystemHals_defaultIsNonUpdatableHal) {
+    std::string error;
+
+    HalManifest manifest;
+    std::string manifestXml =
+        "<manifest " + kMetaVersionStr + " type=\"device\">\n"
+        "    <hal format=\"aidl\">\n"
+        "        <name>android.hardware.foo</name>\n"
+        "        <fqname>IFoo/default</fqname>\n"
+        "    </hal>\n"
+        "</manifest>\n";
+    EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
+    EXPECT_EQ(manifestXml, toXml(manifest, SerializeFlags::HALS_ONLY));
+
+    auto foo = getHals(manifest, "android.hardware.foo");
+    ASSERT_EQ(1u, foo.size());
+    EXPECT_THAT(foo.front()->updatableViaSystem(), false);
+}
+
+TEST_F(LibVintfTest, ParsingHalsAccessor) {
+    std::string error;
+
+    HalManifest manifest;
+    std::string manifestXml =
+        "<manifest " + kMetaVersionStr + " type=\"device\">\n"
+        "    <hal format=\"aidl\">\n"
+        "        <name>android.hardware.foo</name>\n"
+        "        <fqname>IFoo/default</fqname>\n"
+        "    </hal>\n"
+        "</manifest>\n";
+    EXPECT_TRUE(fromXml(&manifest, manifestXml, &error)) << error;
+    EXPECT_EQ(manifestXml, toXml(manifest, SerializeFlags::HALS_ONLY));
+
+    auto foo = getHals(manifest, "android.hardware.foo");
+    ASSERT_EQ(1u, foo.size());
+    ASSERT_FALSE(foo.front()->accessor().has_value());
+
+    HalManifest newManifest;
+    std::string accessorName = "android.os.IAccessor/android.hardware.foo.IFoo/default";
+    manifestXml =
+        "<manifest " + kMetaVersionStr + " type=\"device\">\n"
+        "    <hal format=\"aidl\">\n"
+        "        <name>android.hardware.foo</name>\n"
+        "        <accessor>" + accessorName + "</accessor>\n"
+        "        <fqname>IFoo/default</fqname>\n"
+        "    </hal>\n"
+        "</manifest>\n";
+    EXPECT_TRUE(fromXml(&newManifest, manifestXml, &error)) << error;
+    EXPECT_EQ(manifestXml, toXml(newManifest, SerializeFlags::HALS_ONLY));
+
+    foo = getHals(newManifest, "android.hardware.foo");
+    ASSERT_EQ(1u, foo.size());
+    ASSERT_EQ(accessorName, foo.front()->accessor());
+}
+
+TEST_F(LibVintfTest, RejectHalsAccessorNoValue) {
+    std::string error;
+
+    HalManifest manifest;
+    std::string manifestXml =
+        "<manifest " + kMetaVersionStr + " type=\"device\">\n"
+        "    <hal format=\"aidl\">\n"
+        "        <name>android.hardware.foo</name>\n"
+        "        <accessor></accessor>\n"
+        "        <fqname>IFoo/default</fqname>\n"
+        "    </hal>\n"
+        "</manifest>\n";
+    EXPECT_FALSE(fromXml(&manifest, manifestXml, &error));
+    EXPECT_IN("Accessor requires a non-empty value", error);
+}
+
+TEST_F(LibVintfTest, RejectHalsAccessorMoreThanOneValue) {
+    std::string error;
+
+    HalManifest manifest;
+    std::string accessorName1 = "android.os.IAccessor/android.hardware.foo.IFoo/default";
+    std::string accessorName2 = "android.os.IAccessor/android.hardware.foo.IFoo/vm";
+    std::string manifestXml =
+        "<manifest " + kMetaVersionStr + " type=\"device\">\n"
+        "    <hal format=\"aidl\">\n"
+        "        <name>android.hardware.foo</name>\n"
+        "        <accessor>" + accessorName1 + "</accessor>\n"
+        "        <accessor>" + accessorName2 + "</accessor>\n"
+        "        <fqname>IFoo/default</fqname>\n"
+        "    </hal>\n"
+        "</manifest>\n";
+    EXPECT_FALSE(fromXml(&manifest, manifestXml, &error));
+    EXPECT_IN("No more than one <accessor> is allowed in <hal>", error);
+}
+
 TEST_F(LibVintfTest, ParsingHalsInetTransport) {
     std::string error;
 
@@ -5978,6 +6087,21 @@ class AllowDupMajorVersionTest
                 </hal>
             </manifest>
             )"});
+        ret.push_back({"AidlAccessorInDifferentHals", "Conflicting Accessor", R"(
+                <hal format="aidl">
+                    <name>android.hardware.nfc</name>
+                    <version>2</version>
+                    <accessor>android.os.accessor.IAccessor/android.hardware.nfc.INfc/a</accessor>
+                    <fqname>INfc/default</fqname>
+                </hal>
+                <hal format="aidl">
+                    <name>android.hardware.nfc</name>
+                    <version>2</version>
+                    <accessor>android.os.accessor.IAccessor/android.hardware.nfc.INfc/a</accessor>
+                    <fqname>INfc/foo</fqname>
+                </hal>
+            </manifest>
+            )"});
         return ret;
     }
     static std::string getTestSuffix(const TestParamInfo<ParamType>& info) {
diff --git a/xsd/halManifest/Android.bp b/xsd/halManifest/Android.bp
index bbae30e..8e27c81 100644
--- a/xsd/halManifest/Android.bp
+++ b/xsd/halManifest/Android.bp
@@ -26,4 +26,5 @@ xsd_config {
     name: "hal_manifest",
     srcs: ["hal_manifest.xsd"],
     package_name: "hal.manifest",
+    api_dir: "schema",
 }
diff --git a/xsd/halManifest/hal_manifest.xsd b/xsd/halManifest/hal_manifest.xsd
index 9aa8795..1118c65 100644
--- a/xsd/halManifest/hal_manifest.xsd
+++ b/xsd/halManifest/hal_manifest.xsd
@@ -54,6 +54,9 @@
         <xs:attribute name="format" type="xs:string"/>
         <xs:attribute name="override" type="xs:string"/>
         <xs:attribute name="updatable-via-apex" type="xs:string"/>
+        <xs:attribute name="updatable-via-system" type="xs:string"/>
+        <xs:attribute name="max-level" type="xs:string" />
+        <xs:attribute name="min-level" type="xs:string" />
     </xs:complexType>
     <xs:complexType name="interface">
         <xs:sequence>
diff --git a/xsd/halManifest/api/current.txt b/xsd/halManifest/schema/current.txt
similarity index 93%
rename from xsd/halManifest/api/current.txt
rename to xsd/halManifest/schema/current.txt
index 2e4db0e..765e6bc 100644
--- a/xsd/halManifest/api/current.txt
+++ b/xsd/halManifest/schema/current.txt
@@ -5,17 +5,23 @@ package hal.manifest {
     ctor public Hal();
     method public String getFormat();
     method public java.util.List<java.lang.String> getFqname();
+    method public String getMaxLevel();
+    method public String getMinLevel();
     method public String getName();
     method public String getOverride();
     method public hal.manifest.Hal.Transport getTransport();
     method public String getUpdatableViaApex();
+    method public String getUpdatableViaSystem();
     method public java.util.List<java.lang.String> getVersion();
     method public java.util.List<hal.manifest.Interface> get_interface();
     method public void setFormat(String);
+    method public void setMaxLevel(String);
+    method public void setMinLevel(String);
     method public void setName(String);
     method public void setOverride(String);
     method public void setTransport(hal.manifest.Hal.Transport);
     method public void setUpdatableViaApex(String);
+    method public void setUpdatableViaSystem(String);
   }
 
   public static class Hal.Transport {
diff --git a/xsd/halManifest/api/last_current.txt b/xsd/halManifest/schema/last_current.txt
similarity index 100%
rename from xsd/halManifest/api/last_current.txt
rename to xsd/halManifest/schema/last_current.txt
diff --git a/xsd/halManifest/api/last_removed.txt b/xsd/halManifest/schema/last_removed.txt
similarity index 100%
rename from xsd/halManifest/api/last_removed.txt
rename to xsd/halManifest/schema/last_removed.txt
diff --git a/xsd/halManifest/api/removed.txt b/xsd/halManifest/schema/removed.txt
similarity index 100%
rename from xsd/halManifest/api/removed.txt
rename to xsd/halManifest/schema/removed.txt
diff --git a/xsd/halManifest/vts/ValidateHalManifest.cpp b/xsd/halManifest/vts/ValidateHalManifest.cpp
index 6254b44..fb29a2d 100644
--- a/xsd/halManifest/vts/ValidateHalManifest.cpp
+++ b/xsd/halManifest/vts/ValidateHalManifest.cpp
@@ -15,9 +15,11 @@
  */
 
 #include <dirent.h>
+#include <glob.h>
 #include <string>
 
 #include <android-base/properties.h>
+#include <android-base/scopeguard.h>
 #include <android-base/strings.h>
 #include "utility/ValidateXml.h"
 
@@ -41,6 +43,20 @@ static void get_files_in_dirs(const char* dir_path, std::vector<std::string>& fi
     closedir(d);
 }
 
+static std::vector<std::string> glob(const std::string& pattern) {
+    glob_t glob_result;
+    auto ret = glob(pattern.c_str(), GLOB_MARK, nullptr, &glob_result);
+    auto guard = android::base::make_scope_guard([&glob_result] { globfree(&glob_result); });
+
+    std::vector<std::string> files;
+    if (ret == 0) {
+        for (size_t i = 0; i < glob_result.gl_pathc; i++) {
+            files.emplace_back(glob_result.gl_pathv[i]);
+        }
+    }
+    return files;
+}
+
 TEST(CheckConfig, halManifestValidation) {
     if (android::base::GetIntProperty("ro.product.first_api_level", INT64_MAX) <= 28) {
         GTEST_SKIP();
@@ -76,4 +92,13 @@ TEST(CheckConfig, halManifestValidation) {
             EXPECT_VALID_XML((dir_path + "/"s + file_name).c_str(), xsd);
         }
     }
+
+    // APEXes contain fragments as well.
+    auto fragments = glob("/apex/*/etc/vintf/*.xml");
+    for (const auto& fragment : fragments) {
+        // Skip /apex/name@version paths to avoid double processing
+        auto parts = android::base::Split(fragment, "/");
+        if (parts.size() < 3 || parts[2].find('@') != std::string::npos) continue;
+        EXPECT_VALID_XML(fragment.c_str(), xsd);
+    }
 }
```

