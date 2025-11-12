```diff
diff --git a/incfs/Android.bp b/incfs/Android.bp
index a475528..5152207 100644
--- a/incfs/Android.bp
+++ b/incfs/Android.bp
@@ -44,7 +44,6 @@ license {
 
 cc_defaults {
     name: "libincfs_defaults_common",
-    cpp_std: "c++2a",
     cflags: [
         "-Werror",
         "-Wall",
diff --git a/incfs/MountRegistry.cpp b/incfs/MountRegistry.cpp
index 376eaf2..2530fd1 100644
--- a/incfs/MountRegistry.cpp
+++ b/incfs/MountRegistry.cpp
@@ -438,4 +438,27 @@ auto MountRegistry::Mounts::load(base::borrowed_fd mountInfo, std::string_view f
     return res;
 }
 
+MountRegistry::Mounts::Mounts(const Mounts& other) {
+    copyFrom(other);
+}
+
+MountRegistry::Mounts& MountRegistry::Mounts::operator=(const Mounts& other) {
+    if (this != &other) {
+        copyFrom(other);
+    }
+    return *this;
+}
+
+void MountRegistry::Mounts::copyFrom(const Mounts& other) {
+    roots = other.roots;
+    rootByBindPoint = other.rootByBindPoint;
+    // Now find the iterators of the new roots in our map and update them so
+    // they don't point to the `other`'s map.
+    for (auto& root : roots) {
+        for (auto& it : root.binds) {
+            it = rootByBindPoint.find(it->first);
+        }
+    }
+}
+
 } // namespace android::incfs
diff --git a/incfs/incfs.cpp b/incfs/incfs.cpp
index 8953b77..5fdc008 100644
--- a/incfs/incfs.cpp
+++ b/incfs/incfs.cpp
@@ -44,6 +44,7 @@
 #include <sys/xattr.h>
 #include <unistd.h>
 
+#include <algorithm>
 #include <charconv>
 #include <chrono>
 #include <iterator>
diff --git a/incfs/include/MountRegistry.h b/incfs/include/MountRegistry.h
index 1ff320f..12ba6bc 100644
--- a/incfs/include/MountRegistry.h
+++ b/incfs/include/MountRegistry.h
@@ -68,9 +68,20 @@ public:
         };
 
         struct iterator final : public std::vector<Root>::const_iterator {
+            struct MountPtr {
+                Mount m;
+
+                Mount* operator->() { return &m; }
+                Mount& operator*() { return m; }
+            };
+
             using base = std::vector<Root>::const_iterator;
             using value_type = Mount;
+            using reference = Mount;
+            using pointer = MountPtr;
+
             value_type operator*() const { return Mount(*this); }
+            pointer operator->() const { return MountPtr{Mount(*this)}; }
 
             explicit iterator(base b) : base(b) {}
         };
@@ -78,6 +89,14 @@ public:
         static Mounts load(base::borrowed_fd fd, std::string_view filesystem);
         bool loadFrom(base::borrowed_fd fd, std::string_view filesystem);
 
+        Mounts() = default;
+        Mounts(Mounts&&) = default;
+        Mounts& operator=(Mounts&&) = default;
+
+        // These require some fixups as we have self references in the member containers.
+        Mounts(const Mounts& other);
+        Mounts& operator=(const Mounts& other);
+
         iterator begin() const { return iterator(roots.begin()); }
         iterator end() const { return iterator(roots.end()); }
         size_t size() const { return roots.size(); }
@@ -96,6 +115,7 @@ public:
 
     private:
         std::pair<int, BindMap::const_iterator> rootIndex(std::string_view path) const;
+        void copyFrom(const Mounts& other);
 
         std::vector<Root> roots;
         BindMap rootByBindPoint;
diff --git a/incfs/include/path.h b/incfs/include/path.h
index 62f8b54..2d77aa4 100644
--- a/incfs/include/path.h
+++ b/incfs/include/path.h
@@ -17,6 +17,7 @@
 #pragma once
 
 #include <iterator>
+#include <memory>
 #include <optional>
 #include <string>
 #include <string_view>
diff --git a/incfs/tests/MountRegistry_test.cpp b/incfs/tests/MountRegistry_test.cpp
index bb3ba49..b3a1cc8 100644
--- a/incfs/tests/MountRegistry_test.cpp
+++ b/incfs/tests/MountRegistry_test.cpp
@@ -102,7 +102,7 @@ static MountRegistry::Mounts makeFrom(std::string_view str) {
 
     MountRegistry::Mounts m;
     EXPECT_TRUE(m.loadFrom(f.fd, INCFS_NAME));
-    return std::move(m);
+    return m;
 }
 
 TEST_F(MountRegistryTest, MultiRootLoad) {
@@ -169,3 +169,49 @@ TEST_F(MountRegistryTest, LoadInvalid) {
     // only two of the mounts in this file are valid
     EXPECT_EQ(size_t(2), m.size());
 }
+
+TEST_F(MountRegistryTest, CopyThreadSafety) {
+    r().addRoot("/root/123456789", "/backing/123456789");
+    r().addBind("/root/123456789", "/bind/123456789");
+    auto mounts = MountRegistry::Mounts(r());
+    ASSERT_NE(&mounts, &r());
+
+    ASSERT_EQ(size_t(1), mounts.size());
+    ASSERT_STREQ("/root/123456789", mounts.begin()->root().data());
+    ASSERT_EQ(size_t(2), mounts.begin()->binds().size());
+    ASSERT_STREQ("", mounts.begin()->binds().front().first.data());
+    ASSERT_STREQ("/root/123456789", mounts.begin()->binds().front().second.data());
+    ASSERT_STREQ("", mounts.begin()->binds()[1].first.data());
+    ASSERT_STREQ("/bind/123456789", mounts.begin()->binds()[1].second.data());
+
+    // Now make sure the copy stays valid after clearing the original.
+    r().clear();
+
+    // Populate the original with some other info, ensuring the old pointers are wrong
+    r().addRoot("/not_root1", "/not_backing1");
+    r().addBind("/not_root1", "/not_bind1");
+
+    ASSERT_EQ(size_t(1), mounts.size());
+    ASSERT_STREQ("/root/123456789", mounts.begin()->root().data());
+    ASSERT_EQ(size_t(2), mounts.begin()->binds().size());
+    ASSERT_STREQ("", mounts.begin()->binds().front().first.data());
+    ASSERT_STREQ("/root/123456789", mounts.begin()->binds().front().second.data());
+    ASSERT_STREQ("", mounts.begin()->binds()[1].first.data());
+    ASSERT_STREQ("/bind/123456789", mounts.begin()->binds()[1].second.data());
+
+    // Now the same but with assignment.
+    MountRegistry::Mounts mounts2;
+    mounts2 = mounts;
+
+    mounts.clear();
+    mounts.addRoot("/really_not_root1", "/really_not_backing1");
+    mounts.addBind("/really_not_root1", "/really_not_bind1");
+
+    ASSERT_EQ(size_t(1), mounts2.size());
+    ASSERT_STREQ("/root/123456789", mounts2.begin()->root().data());
+    ASSERT_EQ(size_t(2), mounts2.begin()->binds().size());
+    ASSERT_STREQ("", mounts2.begin()->binds().front().first.data());
+    ASSERT_STREQ("/root/123456789", mounts2.begin()->binds().front().second.data());
+    ASSERT_STREQ("", mounts2.begin()->binds()[1].first.data());
+    ASSERT_STREQ("/bind/123456789", mounts2.begin()->binds()[1].second.data());
+}
diff --git a/libdataloader/Android.bp b/libdataloader/Android.bp
index 3bc3642..64e05bf 100644
--- a/libdataloader/Android.bp
+++ b/libdataloader/Android.bp
@@ -33,7 +33,6 @@ license {
 
 cc_defaults {
     name: "libdataloader_defaults",
-    cpp_std: "c++2a",
     cflags: ["-Werror", "-Wall", "-Wextra", "-Wno-unused-parameter", "-D_FILE_OFFSET_BITS=64"],
     defaults: ["linux_bionic_supported"],
     export_include_dirs: ["include/"],
diff --git a/libdataloader/DataLoaderConnector.cpp b/libdataloader/DataLoaderConnector.cpp
index 0206cf1..88dcaeb 100644
--- a/libdataloader/DataLoaderConnector.cpp
+++ b/libdataloader/DataLoaderConnector.cpp
@@ -23,6 +23,7 @@
 #include <sys/stat.h>
 #include <utils/Looper.h>
 
+#include <mutex>
 #include <thread>
 #include <unordered_map>
 
```

