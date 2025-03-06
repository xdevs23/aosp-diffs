```diff
diff --git a/contents/configuration/baseconfig.cc b/contents/configuration/baseconfig.cc
index d29eaee..b3b103e 100644
--- a/contents/configuration/baseconfig.cc
+++ b/contents/configuration/baseconfig.cc
@@ -85,9 +85,10 @@ android::linkerconfig::modules::Configuration CreateBaseConfiguration(
       {"/data/local/tmp", "unrestricted"},
 
       {"/postinstall", "postinstall"},
-      // Fallback entry to provide APEX namespace lookups for binaries anywhere
-      // else. This must be last.
+      // Fallback entries to provide APEX namespace lookups for binaries
+      // anywhere else. These must be last.
       {"/data", "system"},
+      {"/tmp", "system"},
       // TODO(b/168556887): Remove this when we have a dedicated section for
       // binaries in APKs
       {Var("PRODUCT") + "/app/", "system"},
diff --git a/contents/tests/configuration/apexconfig_test.cc b/contents/tests/configuration/apexconfig_test.cc
index 21f38df..121015d 100644
--- a/contents/tests/configuration/apexconfig_test.cc
+++ b/contents/tests/configuration/apexconfig_test.cc
@@ -92,7 +92,7 @@ TEST_F(ApexConfigTest, vndk_in_system_vendor_apex) {
 
   auto vendor_apex =
       PrepareApex("vendor_apex", {}, {":vndk", "libvendorprovide.so"});
-  vendor_apex.original_path = "/vendor/apex/com.android.vendor";
+  vendor_apex.partition = "VENDOR";
   ctx.SetApexModules({vendor_apex, CreateTestVndkApex()});
   auto config = android::linkerconfig::contents::CreateApexConfiguration(
       ctx, vendor_apex);
@@ -113,7 +113,7 @@ TEST_F(ApexConfigTest, vndk_in_system_product_apex) {
 
   auto product_apex =
       PrepareApex("product_apex", {}, {":vndksp", "libproductprovide.so"});
-  product_apex.original_path = "/product/apex/com.android.product";
+  product_apex.partition = "PRODUCT";
   ctx.SetApexModules({product_apex, CreateTestVndkApex()});
   auto config = android::linkerconfig::contents::CreateApexConfiguration(
       ctx, product_apex);
@@ -135,7 +135,7 @@ TEST_F(ApexConfigTest, vendor_apex_without_use_vndk_as_stable) {
   // Vendor apex requires :vndk
   auto vendor_apex = PrepareApex(
       "com.android.vendor", {"libapexprovide.so"}, {"libvendorprovide.so"});
-  vendor_apex.original_path = "/vendor/apex/com.android.vendor";
+  vendor_apex.partition = "VENDOR";
   ctx.SetApexModules({vendor_apex, CreateTestVndkApex()});
 
   auto config = CreateApexConfiguration(ctx, vendor_apex);
diff --git a/contents/tests/configuration/baseconfig_test.cc b/contents/tests/configuration/baseconfig_test.cc
index cb9e306..118e706 100644
--- a/contents/tests/configuration/baseconfig_test.cc
+++ b/contents/tests/configuration/baseconfig_test.cc
@@ -105,7 +105,7 @@ TEST(linkerconfig_configuration_fulltest,
                               true,
                               true,
                               false);
-  vendor_apex.original_path = "/vendor/apex/com.android.vendor";
+  vendor_apex.partition = "VENDOR";
   ctx.SetApexModules({vendor_apex,
                       // To generate vendor section
                       ApexInfo("com.android.vndk.v",
diff --git a/devicetest/Android.bp b/devicetest/Android.bp
index 233b5cb..8082b0b 100644
--- a/devicetest/Android.bp
+++ b/devicetest/Android.bp
@@ -18,6 +18,7 @@ package {
     default_applicable_licenses: [
         "Android-Apache-2.0",
     ],
+    default_team: "trendy_team_treble",
 }
 
 java_test_host {
@@ -34,6 +35,5 @@ java_test_host {
     test_suites: [
         "gts",
         "general-tests",
-        "mts-mainline-infra",
     ],
 }
diff --git a/modules/apex.cc b/modules/apex.cc
index 0bd3753..5e2a2d1 100644
--- a/modules/apex.cc
+++ b/modules/apex.cc
@@ -219,26 +219,7 @@ Result<std::map<std::string, ApexInfo>> ScanActiveApexes(const std::string& root
         if (info.getProvideSharedApexLibs()) {
           continue;
         }
-        // Get the pre-installed path of the apex. Normally (i.e. in Android),
-        // failing to find the pre-installed path is an assertion failure
-        // because apexd demands that every apex to have a pre-installed one.
-        // However, when this runs in a VM where apexes are seen as virtio block
-        // devices, the situation is different. If the APEX in the host side is
-        // an updated (or staged) one, the block device representing the APEX on
-        // the VM side doesn't have the pre-installed path because the factory
-        // version of the APEX wasn't exported to the VM. Therefore, we use the
-        // module path as original_path when we are running in a VM which can be
-        // guessed by checking if the path is /dev/block/vdN.
-        std::string path;
-        if (info.hasPreinstalledModulePath()) {
-          path = info.getPreinstalledModulePath();
-        } else if (StartsWith(info.getModulePath(), "/dev/block/vd")) {
-          path = info.getModulePath();
-        } else {
-          return Error() << "Failed to determine original path for apex "
-                         << info.getModuleName() << " at " << info_list_file;
-        }
-        apexes[info.getModuleName()].original_path = std::move(path);
+        apexes[info.getModuleName()].partition = std::move(info.getPartition());
       }
     } else {
       return ErrnoError() << "Can't read " << info_list_file;
@@ -267,23 +248,15 @@ Result<std::map<std::string, ApexInfo>> ScanActiveApexes(const std::string& root
 
 bool ApexInfo::InSystem() const {
   // /system partition
-  if (StartsWith(original_path, "/system/apex/")) {
+  if (partition.compare("SYSTEM") == 0) {
     return true;
   }
   // /system_ext partition
-  if (StartsWith(original_path, "/system_ext/apex/") ||
-      StartsWith(original_path, "/system/system_ext/apex/")) {
+  if (partition.compare("SYSTEM_EXT") == 0) {
     return true;
   }
   // /product partition if it's not separated from "system"
-  if (!IsTreblelizedDevice()) {
-    if (StartsWith(original_path, "/product/apex/") ||
-        StartsWith(original_path, "/system/product/apex/")) {
-      return true;
-    }
-  }
-  // Guest mode Android may have system APEXes from host via block APEXes
-  if (StartsWith(original_path, "/dev/block/vd")) {
+  if (!IsTreblelizedDevice() && partition.compare("PRODUCT") == 0) {
     return true;
   }
   return false;
@@ -292,8 +265,7 @@ bool ApexInfo::InSystem() const {
 bool ApexInfo::InProduct() const {
   // /product partition if it's separated from "system"
   if (IsTreblelizedDevice()) {
-    if (StartsWith(original_path, "/product/apex/") ||
-        StartsWith(original_path, "/system/product/apex/")) {
+    if (partition.compare("PRODUCT") == 0) {
       return true;
     }
   }
@@ -302,11 +274,7 @@ bool ApexInfo::InProduct() const {
 
 bool ApexInfo::InVendor() const {
   // /vendor and /odm partition
-  if (StartsWith(original_path, "/vendor/apex/") ||
-      StartsWith(original_path, "/system/vendor/apex/") ||
-      StartsWith(original_path, "/odm/apex/") ||
-      StartsWith(original_path, "/vendor/odm/apex/") ||
-      StartsWith(original_path, "/system/vendor/odm/apex/")) {
+  if (partition.compare("VENDOR") == 0 || partition.compare("ODM") == 0) {
     return true;
   }
   return false;
diff --git a/modules/include/linkerconfig/apex.h b/modules/include/linkerconfig/apex.h
index a857dba..c5ee1a9 100644
--- a/modules/include/linkerconfig/apex.h
+++ b/modules/include/linkerconfig/apex.h
@@ -29,7 +29,7 @@ struct ApexInfo {
   std::string name;
   std::string namespace_name;
   std::string path;
-  std::string original_path;
+  std::string partition;
   std::vector<std::string> provide_libs;
   std::vector<std::string> require_libs;
   std::vector<std::string> jni_libs;
@@ -71,4 +71,4 @@ android::base::Result<std::map<std::string, ApexInfo>> ScanActiveApexes(
     const std::string& root);
 }  // namespace modules
 }  // namespace linkerconfig
-}  // namespace android
\ No newline at end of file
+}  // namespace android
diff --git a/modules/tests/apex_test.cc b/modules/tests/apex_test.cc
index 79358af..9879dc4 100644
--- a/modules/tests/apex_test.cc
+++ b/modules/tests/apex_test.cc
@@ -251,11 +251,11 @@ TEST_F(ApexTest, skip_sharedlibs_apex) {
   PrepareApex("foo", {}, {}, {});
   WriteFile("/apex/apex-info-list.xml", R"(<apex-info-list>
     <apex-info moduleName="foo"
-      preinstalledModulePath="/system/apex/foo.apex"
+      partition="SYSTEM"
       modulePath="/data/apex/active/foo.apex"
       isActive="true" />
     <apex-info moduleName="sharedlibs"
-      preinstalledModulePath="/system/apex/sharedlibs.apex"
+      partition="SYSTEM"
       modulePath="/data/apex/active/sharedlibs.apex"
       provideSharedApexLibs="true"
       isActive="true" />
@@ -278,7 +278,7 @@ TEST_F(ApexTest, public_libs_with_public_libraries_txt) {
   PrepareApex("foo", /*provide_libs=*/{"libfoo.so"}, {}, {});
   WriteFile("/apex/apex-info-list.xml", R"(<apex-info-list>
     <apex-info moduleName="foo"
-      preinstalledModulePath="/system/apex/foo.apex"
+      partition="SYSTEM"
       modulePath="/data/apex/active/foo.apex"
       isActive="true" />
   </apex-info-list>)");
@@ -293,7 +293,7 @@ TEST_F(ApexTest, public_libs_should_be_system_apex) {
   PrepareApex("foo", /*provide_libs=*/{"libfoo.so"}, {}, {});
   WriteFile("/apex/apex-info-list.xml", R"(<apex-info-list>
     <apex-info moduleName="foo"
-      preinstalledModulePath="/vendor/apex/foo.apex"
+      partition="VENDOR"
       modulePath="/data/apex/active/foo.apex"
       isActive="true" />
   </apex-info-list>)");
@@ -307,7 +307,7 @@ TEST_F(ApexTest, system_ext_can_be_linked_to_system_system_ext) {
   PrepareApex("foo", /*provide_libs=*/{"libfoo.so"}, {}, {});
   WriteFile("/apex/apex-info-list.xml", R"(<apex-info-list>
     <apex-info moduleName="foo"
-      preinstalledModulePath="/system/system_ext/apex/foo.apex"
+      partition="SYSTEM_EXT"
       modulePath="/data/apex/active/foo.apex"
       isActive="true" />
   </apex-info-list>)");
diff --git a/testdata/golden_output/guest/ld.config.txt b/testdata/golden_output/guest/ld.config.txt
index 281abc5..3d13010 100644
--- a/testdata/golden_output/guest/ld.config.txt
+++ b/testdata/golden_output/guest/ld.config.txt
@@ -22,6 +22,7 @@ dir.vendor = /data/local/tests/vendor
 dir.unrestricted = /data/local/tmp
 dir.postinstall = /postinstall
 dir.system = /data
+dir.system = /tmp
 dir.system = /product/app/
 [system]
 additional.namespaces = com_android_adbd,com_android_art,com_android_conscrypt,com_android_i18n,com_android_media,com_android_neuralnetworks,com_android_os_statsd,com_android_resolv,com_android_runtime,com_android_systemext1,com_product_service1,com_vendor_service3,product,rs,sphal,vndk,vndk_product
diff --git a/testdata/golden_output/stage1/ld.config.txt b/testdata/golden_output/stage1/ld.config.txt
index 98732ca..42a0c8f 100644
--- a/testdata/golden_output/stage1/ld.config.txt
+++ b/testdata/golden_output/stage1/ld.config.txt
@@ -22,6 +22,7 @@ dir.vendor = /data/local/tests/vendor
 dir.unrestricted = /data/local/tmp
 dir.postinstall = /postinstall
 dir.system = /data
+dir.system = /tmp
 dir.system = /product/app/
 [system]
 additional.namespaces = com_android_art,com_android_i18n,com_android_runtime,product,rs,sphal
diff --git a/testdata/golden_output/stage2/ld.config.txt b/testdata/golden_output/stage2/ld.config.txt
index 8843f87..08f25dd 100644
--- a/testdata/golden_output/stage2/ld.config.txt
+++ b/testdata/golden_output/stage2/ld.config.txt
@@ -22,6 +22,7 @@ dir.vendor = /data/local/tests/vendor
 dir.unrestricted = /data/local/tmp
 dir.postinstall = /postinstall
 dir.system = /data
+dir.system = /tmp
 dir.system = /product/app/
 [system]
 additional.namespaces = com_android_adbd,com_android_art,com_android_conscrypt,com_android_i18n,com_android_media,com_android_neuralnetworks,com_android_os_statsd,com_android_resolv,com_android_runtime,com_android_systemext1,com_product_service1,com_vendor_service3,product,rs,sphal
diff --git a/testdata/golden_output/vendor_with_vndk/ld.config.txt b/testdata/golden_output/vendor_with_vndk/ld.config.txt
index 06c02bb..6f844d3 100644
--- a/testdata/golden_output/vendor_with_vndk/ld.config.txt
+++ b/testdata/golden_output/vendor_with_vndk/ld.config.txt
@@ -22,6 +22,7 @@ dir.vendor = /data/local/tests/vendor
 dir.unrestricted = /data/local/tmp
 dir.postinstall = /postinstall
 dir.system = /data
+dir.system = /tmp
 dir.system = /product/app/
 [system]
 additional.namespaces = com_android_adbd,com_android_art,com_android_conscrypt,com_android_i18n,com_android_media,com_android_neuralnetworks,com_android_os_statsd,com_android_resolv,com_android_runtime,com_android_systemext1,com_product_service1,com_vendor_service3,product,rs,sphal,vndk
diff --git a/testdata/prepare_root.sh b/testdata/prepare_root.sh
index 75f3012..301f442 100755
--- a/testdata/prepare_root.sh
+++ b/testdata/prepare_root.sh
@@ -121,7 +121,7 @@ for partition in system product system_ext vendor odm; do
       if [ $(get_level $name) -le $activate_level ]; then
         # simulate "activation" by copying "apex dir" into /apex
         cp -r $src $dst
-        echo " <apex-info moduleName=\"$name\" modulePath=\"$module_path\" preinstalledModulePath=\"$module_path\" isFactory=\"true\" isActive=\"true\" />" >> $apexInfo
+        echo " <apex-info moduleName=\"$name\" modulePath=\"$module_path\" partition=\"${partition^^}\" isFactory=\"true\" isActive=\"true\" />" >> $apexInfo
       fi
     done
   fi
```

