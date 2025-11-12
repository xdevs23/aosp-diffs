```diff
diff --git a/contents/configuration/baseconfig.cc b/contents/configuration/baseconfig.cc
index b3b103e..6204921 100644
--- a/contents/configuration/baseconfig.cc
+++ b/contents/configuration/baseconfig.cc
@@ -22,17 +22,6 @@
 using android::linkerconfig::modules::DirToSection;
 using android::linkerconfig::modules::Section;
 
-namespace {
-void RemoveSection(std::vector<DirToSection>& dir_to_section,
-                   const std::string& to_be_removed) {
-  dir_to_section.erase(
-      std::remove_if(dir_to_section.begin(),
-                     dir_to_section.end(),
-                     [&](auto pair) { return (pair.second == to_be_removed); }),
-      dir_to_section.end());
-}
-}  // namespace
-
 namespace android {
 namespace linkerconfig {
 namespace contents {
@@ -95,13 +84,8 @@ android::linkerconfig::modules::Configuration CreateBaseConfiguration(
   };
 
   sections.emplace_back(BuildSystemSection(ctx));
-  if (android::linkerconfig::modules::IsTreblelizedDevice()) {
-    sections.emplace_back(BuildVendorSection(ctx));
-    sections.emplace_back(BuildProductSection(ctx));
-  } else {
-    RemoveSection(dirToSection, "product");
-    RemoveSection(dirToSection, "vendor");
-  }
+  sections.emplace_back(BuildVendorSection(ctx));
+  sections.emplace_back(BuildProductSection(ctx));
 
   sections.emplace_back(BuildUnrestrictedSection(ctx));
   sections.emplace_back(BuildPostInstallSection(ctx));
diff --git a/contents/configuration/legacy.cc b/contents/configuration/legacy.cc
deleted file mode 100644
index b857a3d..0000000
--- a/contents/configuration/legacy.cc
+++ /dev/null
@@ -1,54 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-#include "linkerconfig/legacy.h"
-#include "linkerconfig/sectionbuilder.h"
-
-using android::linkerconfig::contents::LinkerConfigType;
-using android::linkerconfig::modules::DirToSection;
-using android::linkerconfig::modules::Section;
-
-namespace android {
-namespace linkerconfig {
-namespace contents {
-android::linkerconfig::modules::Configuration CreateLegacyConfiguration(
-    Context& ctx) {
-  std::vector<Section> sections;
-  ctx.SetCurrentLinkerConfigType(LinkerConfigType::Legacy);
-
-  sections.emplace_back(BuildLegacySection(ctx));
-  sections.emplace_back(BuildPostInstallSection(ctx));
-
-  const std::vector<DirToSection> kDirToSection = {
-      // All binaries gets the same configuration 'legacy'
-      {"/system", "legacy"},
-      {Var("SYSTEM_EXT"), "legacy"},
-      {Var("PRODUCT"), "legacy"},
-      {"/vendor", "legacy"},
-      {"/odm", "legacy"},
-      {"/sbin", "legacy"},
-      // Except for /postinstall, where only /system and /product are searched
-      {"/postinstall", "postinstall"},
-      // Fallback entry to provide APEX namespace lookups for binaries anywhere
-      // else. This must be last.
-      {"/data", "legacy"},
-  };
-  return android::linkerconfig::modules::Configuration(std::move(sections),
-                                                       kDirToSection);
-}
-}  // namespace contents
-}  // namespace linkerconfig
-}  // namespace android
\ No newline at end of file
diff --git a/contents/configuration/recovery.cc b/contents/configuration/recovery.cc
index c984057..f0fcb1e 100644
--- a/contents/configuration/recovery.cc
+++ b/contents/configuration/recovery.cc
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#include "linkerconfig/legacy.h"
+#include "linkerconfig/configuration.h"
 #include "linkerconfig/sectionbuilder.h"
 
 using android::linkerconfig::contents::LinkerConfigType;
diff --git a/contents/include/linkerconfig/legacy.h b/contents/include/linkerconfig/legacy.h
deleted file mode 100644
index e142374..0000000
--- a/contents/include/linkerconfig/legacy.h
+++ /dev/null
@@ -1,27 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-#pragma once
-
-#include "linkerconfig/configuration.h"
-#include "linkerconfig/context.h"
-
-namespace android {
-namespace linkerconfig {
-namespace contents {
-modules::Configuration CreateLegacyConfiguration(Context& ctx);
-}  // namespace contents
-}  // namespace linkerconfig
-}  // namespace android
\ No newline at end of file
diff --git a/contents/namespace/apexplatform.cc b/contents/namespace/apexplatform.cc
index ae20708..0d9e499 100644
--- a/contents/namespace/apexplatform.cc
+++ b/contents/namespace/apexplatform.cc
@@ -34,9 +34,6 @@ Namespace BuildApexPlatformNamespace([[maybe_unused]] const Context& ctx) {
 
   ns.AddSearchPath("/system/${LIB}");
   ns.AddSearchPath(Var("SYSTEM_EXT") + "/${LIB}");
-  if (!android::linkerconfig::modules::IsTreblelizedDevice()) {
-    ns.AddSearchPath(Var("PRODUCT") + "/${LIB}");
-  }
 
   SetupSystemPermittedPaths(&ns);
 
diff --git a/contents/namespace/sphal.cc b/contents/namespace/sphal.cc
index 22a0003..c91eefa 100644
--- a/contents/namespace/sphal.cc
+++ b/contents/namespace/sphal.cc
@@ -57,14 +57,6 @@ Namespace BuildSphalNamespace([[maybe_unused]] const Context& ctx) {
     ns.GetLink(ctx.GetSystemNamespaceName()).AddSharedLib("libft2.so");
   }
 
-  if (ctx.IsApexBinaryConfig() &&
-      !android::linkerconfig::modules::IsTreblelizedDevice()) {
-    // If device is legacy, let Sphal libraries access to system lib path for
-    // VNDK-SP libraries
-    ns.AddSearchPath("/system/${LIB}");
-    ns.AddPermittedPath("/system/${LIB}");
-  }
-
   AddLlndkLibraries(ctx, &ns, VndkUserPartition::Vendor);
 
   if (ctx.IsApexBinaryConfig()) {
diff --git a/contents/namespace/system.cc b/contents/namespace/system.cc
index 0175300..951f982 100644
--- a/contents/namespace/system.cc
+++ b/contents/namespace/system.cc
@@ -30,9 +30,6 @@ Namespace BuildSystemNamespace([[maybe_unused]] const Context& ctx) {
   Namespace ns("system", /*is_isolated=*/false, /*is_visible=*/false);
   ns.AddSearchPath("/system/${LIB}");
   ns.AddSearchPath(Var("SYSTEM_EXT") + "/${LIB}");
-  if (!android::linkerconfig::modules::IsTreblelizedDevice()) {
-    ns.AddSearchPath(Var("PRODUCT") + "/${LIB}");
-  }
 
   SetupSystemPermittedPaths(&ns);
 
diff --git a/contents/namespace/systemdefault.cc b/contents/namespace/systemdefault.cc
index 88af8eb..2ae0ad6 100644
--- a/contents/namespace/systemdefault.cc
+++ b/contents/namespace/systemdefault.cc
@@ -76,37 +76,22 @@ void SetupSystemPermittedPaths(Namespace* ns) {
   for (const std::string& path : permitted_paths) {
     ns->AddPermittedPath(path);
   }
-  if (!android::linkerconfig::modules::IsTreblelizedDevice()) {
-    // System processes can use product libs only if device is not treblelized.
-    ns->AddPermittedPath(product + "/${LIB}");
-  }
 }
 
 Namespace BuildSystemDefaultNamespace([[maybe_unused]] const Context& ctx) {
-  bool is_fully_treblelized =
-      android::linkerconfig::modules::IsTreblelizedDevice();
   std::string product = Var("PRODUCT");
   std::string system_ext = Var("SYSTEM_EXT");
 
   // Visible to allow links to be created at runtime, e.g. through
   // android_link_namespaces in libnativeloader.
   Namespace ns("default",
-               /*is_isolated=*/is_fully_treblelized,
+               /*is_isolated=*/true,
                /*is_visible=*/true);
 
   ns.AddSearchPath("/system/${LIB}");
   ns.AddSearchPath(system_ext + "/${LIB}");
-  if (!is_fully_treblelized) {
-    // System processes can search product libs only if product VNDK is not
-    // enforced.
-    ns.AddSearchPath(product + "/${LIB}");
-    ns.AddSearchPath("/vendor/${LIB}");
-    ns.AddSearchPath("/odm/${LIB}");
-  }
 
-  if (is_fully_treblelized) {
-    SetupSystemPermittedPaths(&ns);
-  }
+  SetupSystemPermittedPaths(&ns);
 
   ns.AddRequires(ctx.GetSystemRequireLibs());
   ns.AddProvides(ctx.GetSystemProvideLibs());
diff --git a/contents/section/apexdefault.cc b/contents/section/apexdefault.cc
index 5c9c8c0..ea9753b 100644
--- a/contents/section/apexdefault.cc
+++ b/contents/section/apexdefault.cc
@@ -80,31 +80,29 @@ Section BuildApexDefaultSection(Context& ctx, const ApexInfo& apex_info) {
 
   // Vendor APEXes can use libs provided by "vendor"
   // and Product APEXes can use libs provided by "product"
-  if (android::linkerconfig::modules::IsTreblelizedDevice()) {
-    if (apex_info.InVendor()) {
-      namespaces.emplace_back(BuildRsNamespace(ctx));
-      auto vendor = BuildVendorNamespace(ctx, "vendor");
-      if (!vendor.GetProvides().empty()) {
-        namespaces.emplace_back(std::move(vendor));
-      }
-      if (android::linkerconfig::modules::IsVendorVndkVersionDefined()) {
-        namespaces.emplace_back(
-            BuildVndkNamespace(ctx, VndkUserPartition::Vendor));
-        if (android::linkerconfig::modules::IsVndkInSystemNamespace()) {
-          namespaces.emplace_back(BuildVndkInSystemNamespace(ctx));
-        }
-      }
-    } else if (apex_info.InProduct()) {
-      auto product = BuildProductNamespace(ctx, "product");
-      if (!product.GetProvides().empty()) {
-        namespaces.emplace_back(std::move(product));
+  if (apex_info.InVendor()) {
+    namespaces.emplace_back(BuildRsNamespace(ctx));
+    auto vendor = BuildVendorNamespace(ctx, "vendor");
+    if (!vendor.GetProvides().empty()) {
+      namespaces.emplace_back(std::move(vendor));
+    }
+    if (android::linkerconfig::modules::IsVendorVndkVersionDefined()) {
+      namespaces.emplace_back(
+          BuildVndkNamespace(ctx, VndkUserPartition::Vendor));
+      if (android::linkerconfig::modules::IsVndkInSystemNamespace()) {
+        namespaces.emplace_back(BuildVndkInSystemNamespace(ctx));
       }
-      if (android::linkerconfig::modules::IsProductVndkVersionDefined()) {
-        namespaces.emplace_back(
-            BuildVndkNamespace(ctx, VndkUserPartition::Product));
-        if (android::linkerconfig::modules::IsVndkInSystemNamespace()) {
-          namespaces.emplace_back(BuildVndkInSystemNamespace(ctx));
-        }
+    }
+  } else if (apex_info.InProduct()) {
+    auto product = BuildProductNamespace(ctx, "product");
+    if (!product.GetProvides().empty()) {
+      namespaces.emplace_back(std::move(product));
+    }
+    if (android::linkerconfig::modules::IsProductVndkVersionDefined()) {
+      namespaces.emplace_back(
+          BuildVndkNamespace(ctx, VndkUserPartition::Product));
+      if (android::linkerconfig::modules::IsVndkInSystemNamespace()) {
+        namespaces.emplace_back(BuildVndkInSystemNamespace(ctx));
       }
     }
   }
diff --git a/contents/section/system.cc b/contents/section/system.cc
index b8ce7b6..bf0d480 100644
--- a/contents/section/system.cc
+++ b/contents/section/system.cc
@@ -34,19 +34,17 @@ Section BuildSystemSection(Context& ctx) {
   std::vector<Namespace> namespaces;
 
   namespaces.emplace_back(BuildSystemDefaultNamespace(ctx));
-  if (android::linkerconfig::modules::IsTreblelizedDevice()) {
-    namespaces.emplace_back(BuildSphalNamespace(ctx));
-    namespaces.emplace_back(BuildRsNamespace(ctx));
-    namespaces.emplace_back(BuildProductNamespace(ctx, "product"));
-    if (ctx.IsVndkAvailable()) {
-      if (android::linkerconfig::modules::IsVendorVndkVersionDefined()) {
-        namespaces.emplace_back(
-            BuildVndkNamespace(ctx, VndkUserPartition::Vendor));
-      }
-      if (android::linkerconfig::modules::IsProductVndkVersionDefined()) {
-        namespaces.emplace_back(
-            BuildVndkNamespace(ctx, VndkUserPartition::Product));
-      }
+  namespaces.emplace_back(BuildSphalNamespace(ctx));
+  namespaces.emplace_back(BuildRsNamespace(ctx));
+  namespaces.emplace_back(BuildProductNamespace(ctx, "product"));
+  if (ctx.IsVndkAvailable()) {
+    if (android::linkerconfig::modules::IsVendorVndkVersionDefined()) {
+      namespaces.emplace_back(
+          BuildVndkNamespace(ctx, VndkUserPartition::Vendor));
+    }
+    if (android::linkerconfig::modules::IsProductVndkVersionDefined()) {
+      namespaces.emplace_back(
+          BuildVndkNamespace(ctx, VndkUserPartition::Product));
     }
   }
 
diff --git a/contents/section/unrestricted.cc b/contents/section/unrestricted.cc
index f73c264..3ce0e57 100644
--- a/contents/section/unrestricted.cc
+++ b/contents/section/unrestricted.cc
@@ -38,13 +38,11 @@ Section BuildUnrestrictedSection(Context& ctx) {
   std::vector<Namespace> namespaces;
 
   namespaces.emplace_back(BuildUnrestrictedDefaultNamespace(ctx));
-  if (android::linkerconfig::modules::IsTreblelizedDevice()) {
-    namespaces.emplace_back(BuildSphalNamespace(ctx));
-    if (android::linkerconfig::modules::IsVendorVndkVersionDefined()) {
-      namespaces.emplace_back(BuildVndkNamespace(ctx, VndkUserPartition::Vendor));
-    }
-    namespaces.emplace_back(BuildRsNamespace(ctx));
+  namespaces.emplace_back(BuildSphalNamespace(ctx));
+  if (android::linkerconfig::modules::IsVendorVndkVersionDefined()) {
+    namespaces.emplace_back(BuildVndkNamespace(ctx, VndkUserPartition::Vendor));
   }
+  namespaces.emplace_back(BuildRsNamespace(ctx));
 
   std::set<std::string> visible_apexes;
 
diff --git a/contents/tests/backward_compatibility/legacy_test.cc b/contents/tests/backward_compatibility/legacy_test.cc
deleted file mode 100644
index 8308d0e..0000000
--- a/contents/tests/backward_compatibility/legacy_test.cc
+++ /dev/null
@@ -1,38 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-#include <gtest/gtest.h>
-
-#include "linkerconfig/legacy.h"
-#include "linkerconfig/variables.h"
-#include "testbase.h"
-
-TEST(linkerconfig_legacy_backward_compatibility, default_namespace) {
-  MockVariables("");
-  android::linkerconfig::modules::Variables::AddValue("ro.treble.enabled",
-                                                      "false");
-  android::linkerconfig::contents::Context ctx;
-  auto config = android::linkerconfig::contents::CreateLegacyConfiguration(ctx);
-
-  auto legacy_section = config.GetSection("legacy");
-  ASSERT_TRUE(legacy_section);
-
-  auto default_namespace = legacy_section->GetNamespace("default");
-  ASSERT_TRUE(default_namespace);
-
-  ASSERT_TRUE(ContainsSearchPath(default_namespace, "/vendor/${LIB}"));
-  ASSERT_TRUE(ContainsSearchPath(default_namespace, "/odm/${LIB}"));
-}
\ No newline at end of file
diff --git a/contents/tests/configuration/legacy_test.cc b/contents/tests/configuration/legacy_test.cc
deleted file mode 100644
index 8e979a1..0000000
--- a/contents/tests/configuration/legacy_test.cc
+++ /dev/null
@@ -1,35 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-#include "linkerconfig/legacy.h"
-#include "configurationtest.h"
-#include "linkerconfig/configwriter.h"
-#include "mockenv.h"
-
-using android::linkerconfig::contents::Context;
-using android::linkerconfig::contents::CreateLegacyConfiguration;
-using android::linkerconfig::modules::ConfigWriter;
-
-TEST(linkerconfig_configuration_fulltest, legacy_test) {
-  MockGenericVariables();
-  Context ctx;
-  auto legacy_config = CreateLegacyConfiguration(ctx);
-  ConfigWriter config_writer;
-
-  legacy_config.WriteConfig(config_writer);
-
-  VerifyConfiguration(config_writer.ToString());
-}
\ No newline at end of file
diff --git a/main.cc b/main.cc
index 3ef3e8b..bc4e05b 100644
--- a/main.cc
+++ b/main.cc
@@ -36,7 +36,6 @@
 #include "linkerconfig/configparser.h"
 #include "linkerconfig/context.h"
 #include "linkerconfig/environment.h"
-#include "linkerconfig/legacy.h"
 #include "linkerconfig/log.h"
 #include "linkerconfig/namespacebuilder.h"
 #include "linkerconfig/recovery.h"
@@ -280,10 +279,6 @@ Configuration GetConfiguration(Context& ctx) {
     return android::linkerconfig::contents::CreateRecoveryConfiguration(ctx);
   }
 
-  if (!android::linkerconfig::modules::IsTreblelizedDevice()) {
-    return android::linkerconfig::contents::CreateLegacyConfiguration(ctx);
-  }
-
   // Use base configuration in default
   return android::linkerconfig::contents::CreateBaseConfiguration(ctx);
 }
@@ -417,8 +412,7 @@ int main(int argc, char* argv[]) {
     PrintUsage(EXIT_FAILURE);
   }
 
-  if (android::linkerconfig::modules::IsTreblelizedDevice() &&
-      android::linkerconfig::modules::IsVndkLiteDevice()) {
+  if (android::linkerconfig::modules::IsVndkLiteDevice()) {
     LOG(ERROR) << "Linkerconfig no longer supports VNDK-Lite configuration";
     exit(EXIT_FAILURE);
   }
diff --git a/modules/apex.cc b/modules/apex.cc
index 5e2a2d1..62abaa3 100644
--- a/modules/apex.cc
+++ b/modules/apex.cc
@@ -255,21 +255,12 @@ bool ApexInfo::InSystem() const {
   if (partition.compare("SYSTEM_EXT") == 0) {
     return true;
   }
-  // /product partition if it's not separated from "system"
-  if (!IsTreblelizedDevice() && partition.compare("PRODUCT") == 0) {
-    return true;
-  }
   return false;
 }
 
 bool ApexInfo::InProduct() const {
   // /product partition if it's separated from "system"
-  if (IsTreblelizedDevice()) {
-    if (partition.compare("PRODUCT") == 0) {
-      return true;
-    }
-  }
-  return false;
+  return (partition.compare("PRODUCT") == 0);
 }
 
 bool ApexInfo::InVendor() const {
diff --git a/modules/environment.cc b/modules/environment.cc
index 01e520e..559a5ec 100644
--- a/modules/environment.cc
+++ b/modules/environment.cc
@@ -23,9 +23,6 @@
 namespace android {
 namespace linkerconfig {
 namespace modules {
-bool IsTreblelizedDevice() {
-  return Variables::GetValue("ro.treble.enabled").value_or("false") == "true";
-}
 
 bool IsVndkLiteDevice() {
   return Variables::GetValue("ro.vndk.lite").value_or("") == "true";
diff --git a/modules/include/linkerconfig/environment.h b/modules/include/linkerconfig/environment.h
index 8de806e..c5af872 100644
--- a/modules/include/linkerconfig/environment.h
+++ b/modules/include/linkerconfig/environment.h
@@ -19,7 +19,6 @@
 namespace android {
 namespace linkerconfig {
 namespace modules {
-bool IsTreblelizedDevice();
 bool IsVndkLiteDevice();
 bool IsVndkInSystemNamespace();
 std::string GetVendorVndkVersion();
```

