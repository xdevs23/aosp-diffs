```diff
diff --git a/Android.bp b/Android.bp
index 496de06b2..5d9e42330 100644
--- a/Android.bp
+++ b/Android.bp
@@ -88,16 +88,7 @@ se_build_files {
     srcs: ["technical_debt.cil"],
 }
 
-soong_config_module_type {
-    name: "se_phony",
-    module_type: "phony",
-    config_namespace: "ANDROID",
-    bool_variables: ["PRODUCT_PRECOMPILED_SEPOLICY"],
-    list_variables: ["PLATFORM_SEPOLICY_COMPAT_VERSIONS"],
-    properties: ["required"],
-}
-
-se_phony {
+phony {
     // Currently used only for aosp_cf_system_x86_64
     // TODO(b/329208946): migrate selinux_policy_system to Soong
     name: "selinux_policy_system_soong",
@@ -113,18 +104,28 @@ se_phony {
         "plat_sepolicy.cil",
         "plat_service_contexts",
         "secilc",
-    ],
-    soong_config_variables: {
-        PLATFORM_SEPOLICY_COMPAT_VERSIONS: {
-            required: [
-                "plat_%s.cil",
-                "%s.compat.cil",
-            ],
-        },
-        PRODUCT_PRECOMPILED_SEPOLICY: {
-            required: ["plat_sepolicy_and_mapping.sha256"],
-        },
-    },
+        "plat_29.0.cil",
+        "29.0.compat.cil",
+        "plat_30.0.cil",
+        "30.0.compat.cil",
+        "plat_31.0.cil",
+        "31.0.compat.cil",
+        "plat_32.0.cil",
+        "32.0.compat.cil",
+        "plat_33.0.cil",
+        "33.0.compat.cil",
+        "plat_34.0.cil",
+        "34.0.compat.cil",
+    ] + select(soong_config_variable("ANDROID", "PLATFORM_SEPOLICY_VERSION"), {
+        "202404": [],
+        default: [
+            "plat_202404.cil",
+            "202404.compat.cil",
+        ],
+    }) + select(soong_config_variable("ANDROID", "PRODUCT_PRECOMPILED_SEPOLICY"), {
+        true: ["plat_sepolicy_and_mapping.sha256"],
+        default: [],
+    }),
 }
 
 reqd_mask_policy = [":se_build_files{.reqd_mask}"]
@@ -145,7 +146,7 @@ product_private_policy = [":se_build_files{.product_private}"]
 // policy and subsequent removal of CIL policy that should not be exported.
 se_policy_conf {
     name: "reqd_policy_mask.conf",
-    defaults: ["se_policy_conf_public_flags_defaults"],
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: reqd_mask_policy,
     installable: false,
 }
@@ -181,7 +182,7 @@ se_policy_cil {
 //
 se_policy_conf {
     name: "pub_policy.conf",
-    defaults: ["se_policy_conf_public_flags_defaults"],
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: plat_public_policy +
         system_ext_public_policy +
         product_public_policy +
@@ -201,7 +202,7 @@ se_policy_cil {
 
 se_policy_conf {
     name: "system_ext_pub_policy.conf",
-    defaults: ["se_policy_conf_public_flags_defaults"],
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: plat_public_policy +
         system_ext_public_policy +
         reqd_mask_policy,
@@ -220,7 +221,7 @@ se_policy_cil {
 
 se_policy_conf {
     name: "plat_pub_policy.conf",
-    defaults: ["se_policy_conf_public_flags_defaults"],
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: plat_public_policy +
         reqd_mask_policy,
     installable: false,
@@ -409,7 +410,7 @@ se_versioned_policy {
 // policy and the platform public policy files in order to use checkpolicy.
 se_policy_conf {
     name: "vendor_sepolicy.conf",
-    defaults: ["se_policy_conf_public_flags_defaults"],
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: plat_public_policy +
         system_ext_public_policy +
         product_public_policy +
@@ -451,7 +452,7 @@ se_versioned_policy {
 // policy and the platform public policy files in order to use checkpolicy.
 se_policy_conf {
     name: "odm_sepolicy.conf",
-    defaults: ["se_policy_conf_public_flags_defaults"],
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: plat_public_policy +
         system_ext_public_policy +
         product_public_policy +
@@ -792,7 +793,7 @@ se_policy_binary {
 
 se_policy_conf {
     name: "base_plat_pub_policy.conf",
-    defaults: ["se_policy_conf_public_flags_defaults"],
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: plat_public_policy +
         reqd_mask_policy,
     build_variant: "user",
@@ -812,7 +813,7 @@ se_policy_cil {
 
 se_policy_conf {
     name: "base_product_pub_policy.conf",
-    defaults: ["se_policy_conf_public_flags_defaults"],
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: plat_public_policy +
         system_ext_public_policy +
         product_public_policy +
@@ -952,3 +953,55 @@ dev_type_test_genrule {
         },
     },
 }
+
+phony {
+    name: "selinux_policy_system_ext",
+    required: [
+        //"ifdef HAS_SYSTEM_EXT_PUBLIC_SEPOLICY" check included in system_ext_pub_policy.cil
+        "system_ext_mapping_file",
+        //"ifdef HAS_SYSTEM_EXT_SEPOLICY" check included in .cil
+        "system_ext_sepolicy.cil",
+    ] + [
+        //"ifdef HAS_SYSTEM_EXT_SEPOLICY" check included in .cil
+        "system_ext_29.0.cil",
+        "system_ext_30.0.cil",
+        "system_ext_31.0.cil",
+        "system_ext_32.0.cil",
+        "system_ext_33.0.cil",
+        "system_ext_34.0.cil",
+    ] + select(soong_config_variable("ANDROID", "PLATFORM_SEPOLICY_VERSION"), {
+        "202404": [],
+        default: [
+            "system_ext_202404.cil",
+        ],
+    }) +
+    select(soong_config_variable("ANDROID", "PRODUCT_PRECOMPILED_SEPOLICY"), {
+        true: ["system_ext_sepolicy_and_mapping.sha256"],
+        default: [],
+    }) + [
+        "system_ext_file_contexts",
+        "system_ext_file_contexts_test",
+        "system_ext_keystore2_key_contexts",
+        "system_ext_hwservice_contexts",
+        "system_ext_hwservice_contexts_test",
+        "system_ext_property_contexts",
+        "system_ext_property_contexts_test",
+        "system_ext_seapp_contexts",
+        "system_ext_service_contexts",
+        "system_ext_service_contexts_test",
+        "system_ext_mac_permissions.xml",
+        "system_ext_bug_map",
+        // $(addprefix system_ext_,$(addsuffix .compat.cil,$(PLATFORM_SEPOLICY_COMPAT_VERSIONS))) \
+        "system_ext_29.0.compat.cil",
+        "system_ext_30.0.compat.cil",
+        "system_ext_31.0.compat.cil",
+        "system_ext_32.0.compat.cil",
+        "system_ext_33.0.compat.cil",
+        "system_ext_34.0.compat.cil",
+    ] + select(soong_config_variable("ANDROID", "PLATFORM_SEPOLICY_VERSION"), {
+        "202404": [],
+        default: [
+            "system_ext_202404.compat.cil",
+        ],
+    }),
+}
diff --git a/Android.mk b/Android.mk
index dc628334f..efbae89af 100644
--- a/Android.mk
+++ b/Android.mk
@@ -189,6 +189,11 @@ LOCAL_REQUIRED_MODULES += \
     selinux_policy_nonsystem \
     selinux_policy_system \
 
+# Runs checkfc against merged service_contexts files
+LOCAL_REQUIRED_MODULES += \
+    merged_service_contexts_test \
+    merged_hwservice_contexts_test
+
 include $(BUILD_PHONY_PACKAGE)
 
 # selinux_policy is a main goal and triggers lots of tests.
@@ -259,55 +264,6 @@ include $(BUILD_PHONY_PACKAGE)
 
 include $(CLEAR_VARS)
 
-LOCAL_MODULE := selinux_policy_system_ext
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 legacy_unencumbered
-LOCAL_LICENSE_CONDITIONS := notice unencumbered
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-# Include precompiled policy, unless told otherwise.
-ifneq ($(PRODUCT_PRECOMPILED_SEPOLICY),false)
-ifdef HAS_SYSTEM_EXT_SEPOLICY
-LOCAL_REQUIRED_MODULES += system_ext_sepolicy_and_mapping.sha256
-endif
-endif
-
-ifdef HAS_SYSTEM_EXT_SEPOLICY
-LOCAL_REQUIRED_MODULES += system_ext_sepolicy.cil
-endif
-
-ifdef HAS_SYSTEM_EXT_PUBLIC_SEPOLICY
-LOCAL_REQUIRED_MODULES += \
-    system_ext_mapping_file
-
-system_ext_compat_files := $(call build_policy, $(sepolicy_compat_files), $(SYSTEM_EXT_PRIVATE_POLICY))
-
-LOCAL_REQUIRED_MODULES += $(addprefix system_ext_, $(notdir $(system_ext_compat_files)))
-
-endif
-
-ifdef HAS_SYSTEM_EXT_SEPOLICY_DIR
-LOCAL_REQUIRED_MODULES += \
-    system_ext_file_contexts \
-    system_ext_file_contexts_test \
-    system_ext_keystore2_key_contexts \
-    system_ext_hwservice_contexts \
-    system_ext_hwservice_contexts_test \
-    system_ext_property_contexts \
-    system_ext_property_contexts_test \
-    system_ext_seapp_contexts \
-    system_ext_service_contexts \
-    system_ext_service_contexts_test \
-    system_ext_mac_permissions.xml \
-    system_ext_bug_map \
-    $(addprefix system_ext_,$(addsuffix .compat.cil,$(PLATFORM_SEPOLICY_COMPAT_VERSIONS))) \
-
-endif
-
-include $(BUILD_PHONY_PACKAGE)
-
-#################################
-
-include $(CLEAR_VARS)
-
 LOCAL_MODULE := selinux_policy_product
 LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 legacy_unencumbered
 LOCAL_LICENSE_CONDITIONS := notice unencumbered
diff --git a/OWNERS b/OWNERS
index 1f2ac9b8b..6a2b611e1 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,4 @@
 adamshih@google.com
-alanstokes@google.com
 bowgotsai@google.com
 inseob@google.com
 jbires@google.com
@@ -7,3 +6,5 @@ jeffv@google.com
 jiyong@google.com
 smoreland@google.com
 tweek@google.com
+
+per-file service_fuzzer_bindings.go = waghpawan@google.com
diff --git a/apex/Android.bp b/apex/Android.bp
index c9c06e3e1..a6d08536f 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -286,3 +286,31 @@ filegroup {
         "com.android.telephonymodules-file_contexts",
     ],
 }
+
+filegroup {
+    name: "com.android.configinfrastructure-file_contexts",
+    srcs: [
+        "com.android.configinfrastructure-file_contexts",
+    ],
+}
+
+filegroup {
+    name: "com.android.biometrics.virtual.fingerprint-file_contexts",
+    srcs: [
+        "com.android.biometrics.virtual.fingerprint-file_contexts",
+    ],
+}
+
+filegroup {
+    name: "com.android.uprobestats-file_contexts",
+    srcs: [
+        "com.android.uprobestats-file_contexts",
+    ],
+}
+
+filegroup {
+    name: "com.android.biometrics.virtual.face-file_contexts",
+    srcs: [
+        "com.android.biometrics.virtual.face-file_contexts",
+    ],
+}
diff --git a/apex/com.android.art-file_contexts b/apex/com.android.art-file_contexts
index 14b68adb3..ed12f10b9 100644
--- a/apex/com.android.art-file_contexts
+++ b/apex/com.android.art-file_contexts
@@ -10,5 +10,4 @@
 /bin/dexoptanalyzer            u:object_r:dexoptanalyzer_exec:s0
 /bin/odrefresh                 u:object_r:odrefresh_exec:s0
 /bin/profman                   u:object_r:profman_exec:s0
-/bin/oatdump                   u:object_r:oatdump_exec:s0
 /lib(64)?(/.*)?                u:object_r:system_lib_file:s0
diff --git a/apex/com.android.biometrics.virtual.face-file_contexts b/apex/com.android.biometrics.virtual.face-file_contexts
new file mode 100644
index 000000000..07fc0a8f7
--- /dev/null
+++ b/apex/com.android.biometrics.virtual.face-file_contexts
@@ -0,0 +1,3 @@
+(/.*)?                                          u:object_r:vendor_file:s0
+/etc(/.*)?                                      u:object_r:vendor_configs_file:s0
+/bin/hw/android\.hardware\.biometrics\.face-service\.example u:object_r:virtual_face_exec:s0
diff --git a/apex/com.android.biometrics.virtual.fingerprint-file_contexts b/apex/com.android.biometrics.virtual.fingerprint-file_contexts
new file mode 100644
index 000000000..940934bd9
--- /dev/null
+++ b/apex/com.android.biometrics.virtual.fingerprint-file_contexts
@@ -0,0 +1,2 @@
+(/.*)?                  u:object_r:system_file:s0
+/bin/hw/android\.hardware\.biometrics\.fingerprint-service\.example u:object_r:virtual_fingerprint_exec:s0
diff --git a/apex/com.android.configinfrastructure-file_contexts b/apex/com.android.configinfrastructure-file_contexts
new file mode 100644
index 000000000..23e7b890e
--- /dev/null
+++ b/apex/com.android.configinfrastructure-file_contexts
@@ -0,0 +1 @@
+(/.*)?                   u:object_r:system_file:s0
\ No newline at end of file
diff --git a/apex/com.android.uprobestats-file_contexts b/apex/com.android.uprobestats-file_contexts
new file mode 100644
index 000000000..01de3e2a5
--- /dev/null
+++ b/apex/com.android.uprobestats-file_contexts
@@ -0,0 +1,3 @@
+(/.*)?                         u:object_r:system_file:s0
+/bin/uprobestats               u:object_r:uprobestats_exec:s0
+
diff --git a/apex/com.android.virt-file_contexts b/apex/com.android.virt-file_contexts
index d8fc8df7d..75f9c10f2 100644
--- a/apex/com.android.virt-file_contexts
+++ b/apex/com.android.virt-file_contexts
@@ -9,3 +9,6 @@ is_flag_enabled(RELEASE_AVF_ENABLE_DEVICE_ASSIGNMENT, `
 is_flag_enabled(RELEASE_AVF_ENABLE_NETWORK, `
     /bin/vmnic u:object_r:vmnic_exec:s0
 ')
+is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `
+    /bin/early_virtmgr u:object_r:early_virtmgr_exec:s0
+')
diff --git a/build/soong/compat_cil.go b/build/soong/compat_cil.go
index 3b9d5e222..fef2e6910 100644
--- a/build/soong/compat_cil.go
+++ b/build/soong/compat_cil.go
@@ -136,46 +136,6 @@ type compatTestModule struct {
 	compatTestTimestamp android.ModuleOutPath
 }
 
-func (f *compatTestModule) createPlatPubVersionedModule(ctx android.LoadHookContext, ver string) {
-	confName := fmt.Sprintf("pub_policy_%s.conf", ver)
-	cilName := fmt.Sprintf("pub_policy_%s.cil", ver)
-	platPubVersionedName := fmt.Sprintf("plat_pub_versioned_%s.cil", ver)
-
-	ctx.CreateModule(policyConfFactory, &nameProperties{
-		Name: proptools.StringPtr(confName),
-	}, &policyConfProperties{
-		Srcs: []string{
-			fmt.Sprintf(":se_build_files{.plat_public_%s}", ver),
-			fmt.Sprintf(":se_build_files{.system_ext_public_%s}", ver),
-			fmt.Sprintf(":se_build_files{.product_public_%s}", ver),
-			":se_build_files{.reqd_mask}",
-		},
-		Installable: proptools.BoolPtr(false),
-	}, &struct {
-		Defaults []string
-	}{
-		Defaults: f.properties.Defaults,
-	})
-
-	ctx.CreateModule(policyCilFactory, &nameProperties{
-		Name: proptools.StringPtr(cilName),
-	}, &policyCilProperties{
-		Src:          proptools.StringPtr(":" + confName),
-		Filter_out:   []string{":reqd_policy_mask.cil"},
-		Secilc_check: proptools.BoolPtr(false),
-		Installable:  proptools.BoolPtr(false),
-	})
-
-	ctx.CreateModule(versionedPolicyFactory, &nameProperties{
-		Name: proptools.StringPtr(platPubVersionedName),
-	}, &versionedPolicyProperties{
-		Base:          proptools.StringPtr(":" + cilName),
-		Target_policy: proptools.StringPtr(":" + cilName),
-		Version:       proptools.StringPtr(ver),
-		Installable:   proptools.BoolPtr(false),
-	})
-}
-
 func (f *compatTestModule) createCompatTestModule(ctx android.LoadHookContext, ver string) {
 	srcs := []string{
 		":plat_sepolicy.cil",
@@ -195,7 +155,7 @@ func (f *compatTestModule) createCompatTestModule(ctx android.LoadHookContext, v
 			":odm_sepolicy.cil",
 		)
 	} else {
-		srcs = append(srcs, fmt.Sprintf(":plat_pub_versioned_%s.cil", ver))
+		srcs = append(srcs, fmt.Sprintf(":%s_plat_pub_versioned.cil", ver))
 	}
 
 	compatTestName := fmt.Sprintf("%s_compat_test", ver)
@@ -210,7 +170,6 @@ func (f *compatTestModule) createCompatTestModule(ctx android.LoadHookContext, v
 
 func (f *compatTestModule) loadHook(ctx android.LoadHookContext) {
 	for _, ver := range ctx.DeviceConfig().PlatformSepolicyCompatVersions() {
-		f.createPlatPubVersionedModule(ctx, ver)
 		f.createCompatTestModule(ctx, ver)
 	}
 }
diff --git a/build/soong/policy.go b/build/soong/policy.go
index 7b2122c36..8bdf01bd3 100644
--- a/build/soong/policy.go
+++ b/build/soong/policy.go
@@ -33,6 +33,7 @@ const (
 
 // This order should be kept. checkpolicy syntax requires it.
 var policyConfOrder = []string{
+	"flagging_macros",
 	"security_classes",
 	"initial_sids",
 	"access_vectors",
@@ -90,8 +91,9 @@ type policyConfProperties struct {
 	// Desired number of MLS categories. Defaults to 1024
 	Mls_cats *int64
 
-	// Whether to turn on board_api_level guard or not. Defaults to false
-	Board_api_level_guard *bool
+	// Board api level of policy files. Set "current" for RELEASE_BOARD_API_LEVEL, or a direct
+	// version string (e.g. "202404"). Defaults to "current"
+	Board_api_level *string
 }
 
 type policyConf struct {
@@ -222,14 +224,6 @@ func (c *policyConf) mlsCats() int {
 	return proptools.IntDefault(c.properties.Mls_cats, MlsCats)
 }
 
-func (c *policyConf) boardApiLevel(ctx android.ModuleContext) string {
-	if proptools.Bool(c.properties.Board_api_level_guard) {
-		return ctx.Config().VendorApiLevel()
-	}
-	// aribtrary value greater than any other vendor API levels
-	return "1000000"
-}
-
 func findPolicyConfOrder(name string) int {
 	for idx, pattern := range policyConfOrder {
 		// We could use regexp but it seems like an overkill
@@ -271,7 +265,7 @@ func (c *policyConf) transformPolicyToConf(ctx android.ModuleContext) android.Ou
 		FlagWithArg("-D target_requires_insecure_execmem_for_swiftshader=", strconv.FormatBool(ctx.DeviceConfig().RequiresInsecureExecmemForSwiftshader())).
 		FlagWithArg("-D target_enforce_debugfs_restriction=", c.enforceDebugfsRestrictions(ctx)).
 		FlagWithArg("-D target_recovery=", strconv.FormatBool(c.isTargetRecovery())).
-		FlagWithArg("-D target_board_api_level=", c.boardApiLevel(ctx)).
+		Flag(boardApiLevelToM4Macro(ctx, c.properties.Board_api_level)).
 		Flags(flagsToM4Macros(flags)).
 		Flag("-s").
 		Inputs(srcs).
diff --git a/build/soong/selinux.go b/build/soong/selinux.go
index f8112313e..51ff73279 100644
--- a/build/soong/selinux.go
+++ b/build/soong/selinux.go
@@ -16,6 +16,7 @@ package selinux
 
 import (
 	"github.com/google/blueprint"
+	"github.com/google/blueprint/proptools"
 
 	"android/soong/android"
 )
@@ -50,3 +51,12 @@ func flagsToM4Macros(flags map[string]string) []string {
 	}
 	return flagMacros
 }
+
+// boardApiLevel returns the M4 argument containing the target board API level.
+func boardApiLevelToM4Macro(ctx android.ModuleContext, apiLevel *string) string {
+	level := proptools.StringDefault(apiLevel, "current")
+	if level == "current" {
+		level = ctx.Config().VendorApiLevel()
+	}
+	return "-D target_board_api_level=" + level
+}
diff --git a/build/soong/selinux_contexts.go b/build/soong/selinux_contexts.go
index a65de356f..fd1cd3422 100644
--- a/build/soong/selinux_contexts.go
+++ b/build/soong/selinux_contexts.go
@@ -46,6 +46,10 @@ type selinuxContextsProperties struct {
 
 	// Make this module available when building for recovery
 	Recovery_available *bool
+
+	// Board api level of policy files. Set "current" for RELEASE_BOARD_API_LEVEL, or a direct
+	// version string (e.g. "202404"). Defaults to "current"
+	Board_api_level *string
 }
 
 type seappProperties struct {
@@ -231,6 +235,14 @@ func (m *selinuxContextsModule) ImageMutatorBegin(ctx android.BaseModuleContext)
 	}
 }
 
+func (m *selinuxContextsModule) VendorVariantNeeded(ctx android.BaseModuleContext) bool {
+	return false
+}
+
+func (m *selinuxContextsModule) ProductVariantNeeded(ctx android.BaseModuleContext) bool {
+	return false
+}
+
 func (m *selinuxContextsModule) CoreVariantNeeded(ctx android.BaseModuleContext) bool {
 	return !m.ModuleBase.InstallInRecovery()
 }
@@ -280,6 +292,7 @@ func (m *selinuxContextsModule) buildGeneralContexts(ctx android.ModuleContext,
 		Tool(ctx.Config().PrebuiltBuildTool(ctx, "m4")).
 		Text("--fatal-warnings -s").
 		FlagForEachArg("-D", ctx.DeviceConfig().SepolicyM4Defs()).
+		Flag(boardApiLevelToM4Macro(ctx, m.properties.Board_api_level)).
 		Flags(flagsToM4Macros(flags)).
 		Inputs(inputsWithNewline).
 		FlagWithOutput("> ", builtContext)
@@ -706,6 +719,14 @@ func (m *contextsTestModule) AndroidMkEntries() []android.AndroidMkEntries {
 func (m *contextsTestModule) ImageMutatorBegin(ctx android.BaseModuleContext) {
 }
 
+func (m *contextsTestModule) VendorVariantNeeded(ctx android.BaseModuleContext) bool {
+	return false
+}
+
+func (m *contextsTestModule) ProductVariantNeeded(ctx android.BaseModuleContext) bool {
+	return false
+}
+
 func (m *contextsTestModule) CoreVariantNeeded(ctx android.BaseModuleContext) bool {
 	return true
 }
diff --git a/build/soong/service_fuzzer_bindings.go b/build/soong/service_fuzzer_bindings.go
index 6ea767907..28bafa45a 100644
--- a/build/soong/service_fuzzer_bindings.go
+++ b/build/soong/service_fuzzer_bindings.go
@@ -45,8 +45,10 @@ var (
 		"android.hardware.automotive.audiocontrol.IAudioControl/default":          EXCEPTION_NO_FUZZER,
 		"android.hardware.biometrics.face.IFace/default":                          EXCEPTION_NO_FUZZER,
 		"android.hardware.biometrics.face.IFace/virtual":                          EXCEPTION_NO_FUZZER,
+		"android.hardware.biometrics.face.virtualhal.IVirtualHal/virtual":         EXCEPTION_NO_FUZZER,
 		"android.hardware.biometrics.fingerprint.IFingerprint/default":            EXCEPTION_NO_FUZZER,
 		"android.hardware.biometrics.fingerprint.IFingerprint/virtual":            EXCEPTION_NO_FUZZER,
+		"android.hardware.biometrics.fingerprint.virtualhal.IVirtualHal/virtual":  EXCEPTION_NO_FUZZER,
 		"android.hardware.bluetooth.audio.IBluetoothAudioProviderFactory/default": EXCEPTION_NO_FUZZER,
 		"android.hardware.broadcastradio.IBroadcastRadio/amfm":                    []string{"android.hardware.broadcastradio-service.default_fuzzer"},
 		"android.hardware.broadcastradio.IBroadcastRadio/dab":                     []string{"android.hardware.broadcastradio-service.default_fuzzer"},
@@ -80,7 +82,7 @@ var (
 		"android.hardware.media.c2.IComponentStore/software":                      []string{"libcodec2-aidl-fuzzer"},
 		"android.hardware.memtrack.IMemtrack/default":                             EXCEPTION_NO_FUZZER,
 		"android.hardware.net.nlinterceptor.IInterceptor/default":                 EXCEPTION_NO_FUZZER,
-		"android.hardware.nfc.INfc/default":                                       EXCEPTION_NO_FUZZER,
+		"android.hardware.nfc.INfc/default":                                       []string{"nfc_service_fuzzer"},
 		"android.hardware.oemlock.IOemLock/default":                               EXCEPTION_NO_FUZZER,
 		"android.hardware.power.IPower/default":                                   EXCEPTION_NO_FUZZER,
 		"android.hardware.power.stats.IPowerStats/default":                        EXCEPTION_NO_FUZZER,
@@ -184,14 +186,17 @@ var (
 		"android.security.metrics":                                       EXCEPTION_NO_FUZZER,
 		"android.service.gatekeeper.IGateKeeperService":                  []string{"gatekeeperd_service_fuzzer"},
 		"android.system.composd":                                         EXCEPTION_NO_FUZZER,
+		"android.system.microfuchsiad":                                   EXCEPTION_NO_FUZZER,
 		// TODO(b/294158658): add fuzzer
 		"android.hardware.security.keymint.IRemotelyProvisionedComponent/avf": EXCEPTION_NO_FUZZER,
 		"android.system.virtualizationservice":                                []string{"virtualizationmanager_fuzzer"},
 		"android.system.virtualizationservice_internal.IVfioHandler":          EXCEPTION_NO_FUZZER,
 		"android.system.virtualizationservice_internal.IVmnic":                EXCEPTION_NO_FUZZER,
 		"android.system.virtualizationmaintenance":                            EXCEPTION_NO_FUZZER,
+		"android.system.vmtethering.IVmTethering":                             EXCEPTION_NO_FUZZER,
 		"ambient_context":               EXCEPTION_NO_FUZZER,
 		"app_binding":                   EXCEPTION_NO_FUZZER,
+		"app_function":                  EXCEPTION_NO_FUZZER,
 		"app_hibernation":               EXCEPTION_NO_FUZZER,
 		"app_integrity":                 EXCEPTION_NO_FUZZER,
 		"app_prediction":                EXCEPTION_NO_FUZZER,
@@ -389,9 +394,11 @@ var (
 		"procstats":                              EXCEPTION_NO_FUZZER,
 		"profcollectd":                           EXCEPTION_NO_FUZZER,
 		"profiling_service":                      EXCEPTION_NO_FUZZER,
+		"protolog_configuration":                 EXCEPTION_NO_FUZZER,
 		"radio.phonesubinfo":                     EXCEPTION_NO_FUZZER,
 		"radio.phone":                            EXCEPTION_NO_FUZZER,
 		"radio.sms":                              EXCEPTION_NO_FUZZER,
+		"ranging":                                EXCEPTION_NO_FUZZER,
 		"rcs":                                    EXCEPTION_NO_FUZZER,
 		"reboot_readiness":                       EXCEPTION_NO_FUZZER,
 		"recovery":                               EXCEPTION_NO_FUZZER,
@@ -445,6 +452,7 @@ var (
 		"SurfaceFlingerAIDL":                     EXCEPTION_NO_FUZZER,
 		"suspend_control":                        []string{"suspend_service_fuzzer"},
 		"suspend_control_internal":               []string{"suspend_service_internal_fuzzer"},
+		"supervision":                            EXCEPTION_NO_FUZZER,
 		"system_config":                          EXCEPTION_NO_FUZZER,
 		"system_server_dumper":                   EXCEPTION_NO_FUZZER,
 		"system_update":                          EXCEPTION_NO_FUZZER,
diff --git a/contexts/Android.bp b/contexts/Android.bp
index ca3cf5727..850601f59 100644
--- a/contexts/Android.bp
+++ b/contexts/Android.bp
@@ -206,6 +206,18 @@ hwservice_contexts {
     device_specific: true,
 }
 
+hwservice_contexts {
+    name: "merged_hwservice_contexts",
+    defaults: ["contexts_flags_defaults"],
+    srcs: [
+        ":plat_hwservice_contexts",
+        ":system_ext_hwservice_contexts",
+        ":product_hwservice_contexts",
+        ":vendor_hwservice_contexts",
+        ":odm_hwservice_contexts",
+    ],
+}
+
 property_contexts {
     name: "plat_property_contexts",
     defaults: ["contexts_flags_defaults"],
@@ -308,6 +320,18 @@ service_contexts {
     recovery_available: true,
 }
 
+service_contexts {
+    name: "merged_service_contexts",
+    defaults: ["contexts_flags_defaults"],
+    srcs: [
+        ":plat_service_contexts",
+        ":system_ext_service_contexts",
+        ":product_service_contexts",
+        ":vendor_service_contexts",
+        ":odm_service_contexts",
+    ],
+}
+
 keystore2_key_contexts {
     name: "plat_keystore2_key_contexts",
     defaults: ["contexts_flags_defaults"],
@@ -490,6 +514,12 @@ hwservice_contexts_test {
     sepolicy: ":precompiled_sepolicy",
 }
 
+hwservice_contexts_test {
+    name: "merged_hwservice_contexts_test",
+    srcs: [":merged_hwservice_contexts"],
+    sepolicy: ":precompiled_sepolicy",
+}
+
 property_contexts_test {
     name: "plat_property_contexts_test",
     srcs: [":plat_property_contexts"],
@@ -568,6 +598,12 @@ service_contexts_test {
     sepolicy: ":precompiled_sepolicy",
 }
 
+service_contexts_test {
+    name: "merged_service_contexts_test",
+    srcs: [":merged_service_contexts"],
+    sepolicy: ":precompiled_sepolicy",
+}
+
 vndservice_contexts_test {
     name: "vndservice_contexts_test",
     srcs: [":vndservice_contexts"],
diff --git a/contexts/plat_file_contexts_test b/contexts/plat_file_contexts_test
index 0bd8e07ff..72b17ca99 100644
--- a/contexts/plat_file_contexts_test
+++ b/contexts/plat_file_contexts_test
@@ -3,7 +3,7 @@
 # It can be passed to checkfc to confirm that the regular expressions in
 # file_contexts are matching the intended paths.
 /                                                                 rootfs
-/adb_keys                                                         adb_keys_file
+/adb_keys                                                         system_file
 /build.prop                                                       rootfs
 /default.prop                                                     rootfs
 /fstab.persist                                                    rootfs
@@ -37,6 +37,7 @@
 /sys                                                              sysfs
 /apex                                                             apex_mnt_dir
 /bootstrap-apex                                                   apex_mnt_dir
+/mnt/vm                                                           vm_data_file
 
 /postinstall                                                      postinstall_mnt_dir
 /postinstall/apex                                                 postinstall_apex_mnt_dir
@@ -416,7 +417,6 @@
 /system/bin/cppreopts.sh                                          cppreopts_exec
 /system/bin/preloads_copy.sh                                      preloads_copy_exec
 /system/bin/preopt2cachename                                      preopt2cachename_exec
-/system/bin/viewcompiler                                          viewcompiler_exec
 /system/bin/sgdisk                                                sgdisk_exec
 /system/bin/blkid                                                 blkid_exec
 /system/bin/flags_health_check                                    flags_health_check_exec
@@ -723,6 +723,9 @@
 /system/product/lib64                                             system_lib_file
 /system/product/lib64/does_not_exist                              system_lib_file
 
+/product/etc/security/adb_keys                                    adb_keys_file
+/system/product/etc/security/adb_keys                             adb_keys_file
+
 /system_ext                                                       system_file
 /system_ext/does_not_exist                                        system_file
 /system/system_ext                                                system_file
@@ -774,6 +777,9 @@
 /system/system_ext/bin/canhalconfigurator                         canhalconfigurator_exec
 /system/system_ext/bin/canhalconfigurator-aidl                    canhalconfigurator_exec
 
+/system_ext/bin/custom_vm_setup                                   custom_vm_setup_exec
+/system/system_ext/bin/custom_vm_setup                            custom_vm_setup_exec
+
 /system_ext/lib                                                   system_lib_file
 /system_ext/lib/does_not_exist                                    system_lib_file
 /system_ext/lib64                                                 system_lib_file
@@ -1266,8 +1272,6 @@
 /metadata/bootstat/test                                           metadata_bootstat_file
 /metadata/staged-install                                          staged_install_file
 /metadata/staged-install/test                                     staged_install_file
-/metadata/userspacereboot                                         userspace_reboot_metadata_file
-/metadata/userspacereboot/test                                    userspace_reboot_metadata_file
 /metadata/watchdog                                                watchdog_metadata_file
 /metadata/watchdog/test                                           watchdog_metadata_file
 /metadata/repair-mode                                             repair_mode_metadata_file
@@ -1299,6 +1303,11 @@
 /mnt/product                                                      mnt_product_file
 /mnt/product/test                                                 mnt_product_file
 
+
+/mnt/scratch_ota_metadata_super                                   ota_metadata_file
+/mnt/scratch_ota_metadata_super/ota                               ota_metadata_file
+/mnt/scratch_ota_metadata_super/ota/snapshots                     ota_metadata_file
+
 /system/bin/check_dynamic_partitions                              postinstall_exec
 /product/bin/check_dynamic_partitions                             postinstall_exec
 /system/bin/otapreopt_script                                      postinstall_exec
diff --git a/flagging/Android.bp b/flagging/Android.bp
index 2d0bb6841..bd97a162a 100644
--- a/flagging/Android.bp
+++ b/flagging/Android.bp
@@ -18,9 +18,14 @@ se_flags {
     name: "aosp_selinux_flags",
     flags: [
         "RELEASE_AVF_SUPPORT_CUSTOM_VM_WITH_PARAVIRTUALIZED_DEVICES",
+        "RELEASE_AVF_ENABLE_EARLY_VM",
         "RELEASE_AVF_ENABLE_DEVICE_ASSIGNMENT",
         "RELEASE_AVF_ENABLE_LLPVM_CHANGES",
         "RELEASE_AVF_ENABLE_NETWORK",
+        "RELEASE_AVF_ENABLE_MICROFUCHSIA",
+        "RELEASE_RANGING_STACK",
+        "RELEASE_READ_FROM_NEW_STORAGE",
+        "RELEASE_SUPERVISION_SERVICE",
         "RELEASE_HARDWARE_BLUETOOTH_RANGING_SERVICE",
         "RELEASE_UNLOCKED_STORAGE_API",
     ],
@@ -38,13 +43,6 @@ se_policy_conf_defaults {
     build_flags: ["all_selinux_flags"],
 }
 
-se_policy_conf_defaults {
-    name: "se_policy_conf_public_flags_defaults",
-    srcs: [":sepolicy_flagging_macros"],
-    build_flags: ["all_selinux_flags"],
-    board_api_level_guard: true,
-}
-
 contexts_defaults {
     name: "contexts_flags_defaults",
     srcs: [":sepolicy_flagging_macros"],
@@ -54,5 +52,5 @@ contexts_defaults {
 
 filegroup {
     name: "sepolicy_flagging_macros",
-    srcs: ["te_macros"],
+    srcs: ["flagging_macros"],
 }
diff --git a/flagging/flagging_macros b/flagging/flagging_macros
new file mode 100644
index 000000000..44cd33a5b
--- /dev/null
+++ b/flagging/flagging_macros
@@ -0,0 +1,23 @@
+####################################
+# is_flag_enabled(flag, rules)
+# SELinux rules which apply only if given feature is turned on
+define(`is_flag_enabled', `ifelse(target_flag_$1, `true', `$2')')
+
+####################################
+# is_flag_disabled(flag, rules)
+# SELinux rules which apply only if given feature is turned off
+define(`is_flag_disabled', `ifelse(target_flag_$1, `true', , `$2')')
+
+####################################
+# starting_at_board_api(api_level, rules_if_api_level)
+#
+# This macro conditionally exposes SELinux rules ensuring they are available
+# only when the board API level is at or above the specified 'api_level'.
+define(`starting_at_board_api', `ifelse(eval(target_board_api_level >= $1), 1, `$2')')
+
+####################################
+# until_board_api(api_level, rules_if_lower_api_level)
+#
+# This macro conditionally exposes SELinux rules ensuring they are available
+# only when the board API level is below the specified 'api_level'.
+define(`until_board_api', `ifelse(eval(target_board_api_level < $1), 1, `$2')')
diff --git a/flagging/te_macros b/flagging/te_macros
deleted file mode 100644
index baf26c35d..000000000
--- a/flagging/te_macros
+++ /dev/null
@@ -1,24 +0,0 @@
-####################################
-# is_flag_enabled(flag, rules)
-# SELinux rules which apply only if given feature is turned on
-define(`is_flag_enabled', `ifelse(target_flag_$1, `true', `$2')')
-
-####################################
-# is_flag_disabled(flag, rules)
-# SELinux rules which apply only if given feature is turned off
-define(`is_flag_disabled', `ifelse(target_flag_$1, `true', , `$2')')
-
-####################################
-# starting_at_board_api(api_level, rules)
-#
-# This macro conditionally exposes SELinux rules within system/sepolicy/public,
-# ensuring they are available to vendors only when the board API level is at or
-# above the specified 'api_level'.
-#
-# * Platform sepolicy: Rules are always enabled, regardless of API level.
-# * Vendor sepolicy: Rules are enabled only when the board API level meets or
-#                    exceeds the value provided in 'api_level'.
-#
-# Apply this macro to public types and attributes (in system/sepolicy/public) to
-# restrict vendor access based on board API level.
-define(`starting_at_board_api', `ifelse(eval(target_board_api_level >= $1), 1, `$2')')
diff --git a/microdroid/Android.bp b/microdroid/Android.bp
index dce489849..e9b4b1e24 100644
--- a/microdroid/Android.bp
+++ b/microdroid/Android.bp
@@ -107,6 +107,7 @@ vendor_policy_files = [
 
 se_policy_conf {
     name: "microdroid_reqd_policy_mask.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: reqd_mask_files,
     installable: false,
     mls_cats: 1,
@@ -121,6 +122,7 @@ se_policy_cil {
 
 se_policy_conf {
     name: "microdroid_plat_sepolicy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: system_policy_files,
     installable: false,
     mls_cats: 1,
@@ -135,6 +137,7 @@ se_policy_cil {
 
 se_policy_conf {
     name: "microdroid_plat_pub_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: system_public_policy_files,
     installable: false,
     mls_cats: 1,
@@ -172,6 +175,7 @@ se_versioned_policy {
 
 se_policy_conf {
     name: "microdroid_vendor_sepolicy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: vendor_policy_files,
     installable: false,
     mls_cats: 1,
diff --git a/prebuilts/api/202404/202404_general_sepolicy.conf b/prebuilts/api/202404/202404_general_sepolicy.conf
index e418549b6..5ce168ccb 100644
--- a/prebuilts/api/202404/202404_general_sepolicy.conf
+++ b/prebuilts/api/202404/202404_general_sepolicy.conf
@@ -20767,6 +20767,7 @@ neverallow {
   # TODO(b/196225233): Remove hal_uwb_vendor_server
   -hal_uwb_vendor_server
   -hal_nlinterceptor_server
+  -hal_tv_tuner_server
 } self:{ capability cap_userns } { net_admin net_raw };
 
 # Unless a HAL's job is to communicate over the network, or control network
@@ -20789,6 +20790,7 @@ neverallow {
   -hal_uwb_vendor_server
   -hal_nlinterceptor_server
   -hal_bluetooth_server
+  -hal_tv_tuner_server
 } domain:{ udp_socket rawip_socket } *;
 
 neverallow {
@@ -20802,6 +20804,7 @@ neverallow {
   -hal_telephony_server
   -hal_nlinterceptor_server
   -hal_bluetooth_server
+  -hal_tv_tuner_server
 } {
   domain
   
@@ -46100,24 +46103,12 @@ neverallow { domain -bpfloader } bpffs_type:lnk_file ~read;
 neverallow { domain -bpfdomain } bpffs_type:lnk_file read;
 
 neverallow { domain -bpfloader } *:bpf { map_create prog_load };
+neverallow { domain -bpfdomain } *:bpf { map_read map_write prog_run };
 
 # 'fs_bpf_loader' is for internal use of the BpfLoader oneshot boot time process.
 neverallow { domain -bpfloader } fs_bpf_loader:bpf *;
 neverallow { domain -bpfloader } fs_bpf_loader:file *;
 
-neverallow {
-  domain
-  -bpfloader
-  -gpuservice
-  -hal_health_server
-  -mediaprovider_app
-  -netd
-  -netutils_wrapper
-  -network_stack
-  -system_server
-  -uprobestats
-} *:bpf prog_run;
-neverallow { domain -bpfloader -gpuservice -lmkd -mediaprovider_app -netd -network_stack -system_server -uprobestats } *:bpf { map_read map_write };
 neverallow { domain -bpfloader -init } bpfloader_exec:file { execute execute_no_trans };
 
 neverallow { coredomain -bpfloader -netd -netutils_wrapper } fs_bpf_vendor:file *;
diff --git a/prebuilts/api/202404/Android.bp b/prebuilts/api/202404/Android.bp
index c0fb5a2ba..bca377e5d 100644
--- a/prebuilts/api/202404/Android.bp
+++ b/prebuilts/api/202404/Android.bp
@@ -1,4 +1,33 @@
-// Automatically generated file, do not edit!
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+se_policy_conf {
+    name: "202404_reqd_policy_mask.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
+    srcs: reqd_mask_policy,
+    installable: false,
+    build_variant: "user",
+    board_api_level: "202404",
+}
+
+se_policy_cil {
+    name: "202404_reqd_policy_mask.cil",
+    src: ":202404_reqd_policy_mask.conf",
+    secilc_check: false,
+    installable: false,
+}
+
 se_policy_conf {
     name: "202404_plat_pub_policy.conf",
     defaults: ["se_policy_conf_flags_defaults"],
@@ -8,12 +37,13 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "202404",
 }
 
 se_policy_cil {
     name: "202404_plat_pub_policy.cil",
     src: ":202404_plat_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":202404_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
@@ -29,16 +59,25 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "202404",
 }
 
 se_policy_cil {
     name: "202404_product_pub_policy.cil",
     src: ":202404_product_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":202404_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
+se_versioned_policy {
+    name: "202404_plat_pub_versioned.cil",
+    base: ":202404_product_pub_policy.cil",
+    target_policy: ":202404_product_pub_policy.cil",
+    version: "202404",
+    installable: false,
+}
+
 se_policy_conf {
     name: "202404_plat_policy.conf",
     defaults: ["se_policy_conf_flags_defaults"],
@@ -52,6 +91,7 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "202404",
 }
 
 se_policy_cil {
diff --git a/prebuilts/api/29.0/Android.bp b/prebuilts/api/29.0/Android.bp
index 8acca2964..e83528851 100644
--- a/prebuilts/api/29.0/Android.bp
+++ b/prebuilts/api/29.0/Android.bp
@@ -12,26 +12,45 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+se_policy_conf {
+    name: "29.0_reqd_policy_mask.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
+    srcs: reqd_mask_policy,
+    installable: false,
+    build_variant: "user",
+    board_api_level: "29",
+}
+
+se_policy_cil {
+    name: "29.0_reqd_policy_mask.cil",
+    src: ":29.0_reqd_policy_mask.conf",
+    secilc_check: false,
+    installable: false,
+}
+
 se_policy_conf {
     name: "29.0_plat_pub_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_29.0}",
         ":se_build_files{.reqd_mask}",
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "29",
 }
 
 se_policy_cil {
     name: "29.0_plat_pub_policy.cil",
     src: ":29.0_plat_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":29.0_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
 se_policy_conf {
     name: "29.0_product_pub_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_29.0}",
         ":se_build_files{.system_ext_public_29.0}",
@@ -40,18 +59,28 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "29",
 }
 
 se_policy_cil {
     name: "29.0_product_pub_policy.cil",
     src: ":29.0_product_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":29.0_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
+se_versioned_policy {
+    name: "29.0_plat_pub_versioned.cil",
+    base: ":29.0_product_pub_policy.cil",
+    target_policy: ":29.0_product_pub_policy.cil",
+    version: "29.0",
+    installable: false,
+}
+
 se_policy_conf {
     name: "29.0_plat_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_29.0}",
         ":se_build_files{.plat_private_29.0}",
@@ -62,6 +91,7 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "29",
 }
 
 se_policy_cil {
diff --git a/prebuilts/api/30.0/Android.bp b/prebuilts/api/30.0/Android.bp
index 6f3254d74..df137567d 100644
--- a/prebuilts/api/30.0/Android.bp
+++ b/prebuilts/api/30.0/Android.bp
@@ -12,26 +12,45 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+se_policy_conf {
+    name: "30.0_reqd_policy_mask.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
+    srcs: reqd_mask_policy,
+    installable: false,
+    build_variant: "user",
+    board_api_level: "30",
+}
+
+se_policy_cil {
+    name: "30.0_reqd_policy_mask.cil",
+    src: ":30.0_reqd_policy_mask.conf",
+    secilc_check: false,
+    installable: false,
+}
+
 se_policy_conf {
     name: "30.0_plat_pub_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_30.0}",
         ":se_build_files{.reqd_mask}",
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "30",
 }
 
 se_policy_cil {
     name: "30.0_plat_pub_policy.cil",
     src: ":30.0_plat_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":30.0_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
 se_policy_conf {
     name: "30.0_product_pub_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_30.0}",
         ":se_build_files{.system_ext_public_30.0}",
@@ -40,18 +59,28 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "30",
 }
 
 se_policy_cil {
     name: "30.0_product_pub_policy.cil",
     src: ":30.0_product_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":30.0_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
+se_versioned_policy {
+    name: "30.0_plat_pub_versioned.cil",
+    base: ":30.0_product_pub_policy.cil",
+    target_policy: ":30.0_product_pub_policy.cil",
+    version: "30.0",
+    installable: false,
+}
+
 se_policy_conf {
     name: "30.0_plat_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_30.0}",
         ":se_build_files{.plat_private_30.0}",
@@ -62,6 +91,7 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "30",
 }
 
 se_policy_cil {
diff --git a/prebuilts/api/31.0/Android.bp b/prebuilts/api/31.0/Android.bp
index caf1c10f6..ba8d67c40 100644
--- a/prebuilts/api/31.0/Android.bp
+++ b/prebuilts/api/31.0/Android.bp
@@ -12,26 +12,45 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+se_policy_conf {
+    name: "31.0_reqd_policy_mask.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
+    srcs: reqd_mask_policy,
+    installable: false,
+    build_variant: "user",
+    board_api_level: "31",
+}
+
+se_policy_cil {
+    name: "31.0_reqd_policy_mask.cil",
+    src: ":31.0_reqd_policy_mask.conf",
+    secilc_check: false,
+    installable: false,
+}
+
 se_policy_conf {
     name: "31.0_plat_pub_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_31.0}",
         ":se_build_files{.reqd_mask}",
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "31",
 }
 
 se_policy_cil {
     name: "31.0_plat_pub_policy.cil",
     src: ":31.0_plat_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":31.0_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
 se_policy_conf {
     name: "31.0_product_pub_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_31.0}",
         ":se_build_files{.system_ext_public_31.0}",
@@ -40,18 +59,28 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "31",
 }
 
 se_policy_cil {
     name: "31.0_product_pub_policy.cil",
     src: ":31.0_product_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":31.0_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
+se_versioned_policy {
+    name: "31.0_plat_pub_versioned.cil",
+    base: ":31.0_product_pub_policy.cil",
+    target_policy: ":31.0_product_pub_policy.cil",
+    version: "31.0",
+    installable: false,
+}
+
 se_policy_conf {
     name: "31.0_plat_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_31.0}",
         ":se_build_files{.plat_private_31.0}",
@@ -62,6 +91,7 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "31",
 }
 
 se_policy_cil {
diff --git a/prebuilts/api/32.0/Android.bp b/prebuilts/api/32.0/Android.bp
index 9a2b4e2ac..053e094bb 100644
--- a/prebuilts/api/32.0/Android.bp
+++ b/prebuilts/api/32.0/Android.bp
@@ -12,26 +12,45 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+se_policy_conf {
+    name: "32.0_reqd_policy_mask.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
+    srcs: reqd_mask_policy,
+    installable: false,
+    build_variant: "user",
+    board_api_level: "32",
+}
+
+se_policy_cil {
+    name: "32.0_reqd_policy_mask.cil",
+    src: ":32.0_reqd_policy_mask.conf",
+    secilc_check: false,
+    installable: false,
+}
+
 se_policy_conf {
     name: "32.0_plat_pub_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_32.0}",
         ":se_build_files{.reqd_mask}",
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "32",
 }
 
 se_policy_cil {
     name: "32.0_plat_pub_policy.cil",
     src: ":32.0_plat_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":32.0_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
 se_policy_conf {
     name: "32.0_product_pub_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_32.0}",
         ":se_build_files{.system_ext_public_32.0}",
@@ -40,18 +59,28 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "32",
 }
 
 se_policy_cil {
     name: "32.0_product_pub_policy.cil",
     src: ":32.0_product_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":32.0_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
+se_versioned_policy {
+    name: "32.0_plat_pub_versioned.cil",
+    base: ":32.0_product_pub_policy.cil",
+    target_policy: ":32.0_product_pub_policy.cil",
+    version: "32.0",
+    installable: false,
+}
+
 se_policy_conf {
     name: "32.0_plat_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_32.0}",
         ":se_build_files{.plat_private_32.0}",
@@ -62,6 +91,7 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "32",
 }
 
 se_policy_cil {
diff --git a/prebuilts/api/33.0/Android.bp b/prebuilts/api/33.0/Android.bp
index 0a01a44ad..0824e9c2d 100644
--- a/prebuilts/api/33.0/Android.bp
+++ b/prebuilts/api/33.0/Android.bp
@@ -12,26 +12,45 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+se_policy_conf {
+    name: "33.0_reqd_policy_mask.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
+    srcs: reqd_mask_policy,
+    installable: false,
+    build_variant: "user",
+    board_api_level: "33",
+}
+
+se_policy_cil {
+    name: "33.0_reqd_policy_mask.cil",
+    src: ":33.0_reqd_policy_mask.conf",
+    secilc_check: false,
+    installable: false,
+}
+
 se_policy_conf {
     name: "33.0_plat_pub_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_33.0}",
         ":se_build_files{.reqd_mask}",
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "33",
 }
 
 se_policy_cil {
     name: "33.0_plat_pub_policy.cil",
     src: ":33.0_plat_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":33.0_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
 se_policy_conf {
     name: "33.0_product_pub_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_33.0}",
         ":se_build_files{.system_ext_public_33.0}",
@@ -40,18 +59,28 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "33",
 }
 
 se_policy_cil {
     name: "33.0_product_pub_policy.cil",
     src: ":33.0_product_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":33.0_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
+se_versioned_policy {
+    name: "33.0_plat_pub_versioned.cil",
+    base: ":33.0_product_pub_policy.cil",
+    target_policy: ":33.0_product_pub_policy.cil",
+    version: "33.0",
+    installable: false,
+}
+
 se_policy_conf {
     name: "33.0_plat_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_33.0}",
         ":se_build_files{.plat_private_33.0}",
@@ -62,6 +91,7 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "33",
 }
 
 se_policy_cil {
diff --git a/prebuilts/api/34.0/Android.bp b/prebuilts/api/34.0/Android.bp
index b3be5bbdf..efd3c2539 100644
--- a/prebuilts/api/34.0/Android.bp
+++ b/prebuilts/api/34.0/Android.bp
@@ -12,26 +12,45 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+se_policy_conf {
+    name: "34.0_reqd_policy_mask.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
+    srcs: reqd_mask_policy,
+    installable: false,
+    build_variant: "user",
+    board_api_level: "34",
+}
+
+se_policy_cil {
+    name: "34.0_reqd_policy_mask.cil",
+    src: ":34.0_reqd_policy_mask.conf",
+    secilc_check: false,
+    installable: false,
+}
+
 se_policy_conf {
     name: "34.0_plat_pub_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_34.0}",
         ":se_build_files{.reqd_mask}",
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "34",
 }
 
 se_policy_cil {
     name: "34.0_plat_pub_policy.cil",
     src: ":34.0_plat_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":34.0_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
 se_policy_conf {
     name: "34.0_product_pub_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_34.0}",
         ":se_build_files{.system_ext_public_34.0}",
@@ -40,18 +59,28 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "34",
 }
 
 se_policy_cil {
     name: "34.0_product_pub_policy.cil",
     src: ":34.0_product_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":34.0_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
+se_versioned_policy {
+    name: "34.0_plat_pub_versioned.cil",
+    base: ":34.0_product_pub_policy.cil",
+    target_policy: ":34.0_product_pub_policy.cil",
+    version: "34.0",
+    installable: false,
+}
+
 se_policy_conf {
     name: "34.0_plat_policy.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
     srcs: [
         ":se_build_files{.plat_public_34.0}",
         ":se_build_files{.plat_private_34.0}",
@@ -62,6 +91,7 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "34",
 }
 
 se_policy_cil {
diff --git a/private/access_vectors b/private/access_vectors
index 7a280c518..9d82ac8ef 100644
--- a/private/access_vectors
+++ b/private/access_vectors
@@ -139,8 +139,8 @@ common cap2
 	block_suspend
 	audit_read
 	perfmon
-	checkpoint_restore
-	bpf
+	starting_at_board_api(202504, `checkpoint_restore')
+	starting_at_board_api(202504, `bpf')
 }
 
 #
diff --git a/private/adbd.te b/private/adbd.te
index c85203806..154a04cb5 100644
--- a/private/adbd.te
+++ b/private/adbd.te
@@ -216,8 +216,7 @@ allow adbd shell:unix_stream_socket { read write shutdown };
 allow adbd shell:fd use;
 
 # Allow pull /vendor/apex files for CTS tests
-allow adbd vendor_apex_file:dir search;
-allow adbd vendor_apex_file:file r_file_perms;
+r_dir_file(adbd, vendor_apex_file)
 
 # Allow adb pull of updated apex files in /data/apex/active.
 allow adbd apex_data_file:dir search;
diff --git a/private/app.te b/private/app.te
index 30931e464..6362c7d66 100644
--- a/private/app.te
+++ b/private/app.te
@@ -167,6 +167,8 @@ use_keystore({ appdomain -isolated_app_all -ephemeral_app -sdk_sandbox_all })
 
 use_credstore({ appdomain -isolated_app_all -ephemeral_app -sdk_sandbox_all })
 
+allow { appdomain -isolated_app_all -ephemeral_app -sdk_sandbox_all } persistent_data_block_service:service_manager find;
+
 # For app fuse.
 pdx_client({ appdomain -isolated_app_all -ephemeral_app -sdk_sandbox_all }, display_client)
 pdx_client({ appdomain -isolated_app_all -ephemeral_app -sdk_sandbox_all }, display_manager)
@@ -488,6 +490,8 @@ allow appdomain app_fuse_file:file { getattr read append write map };
 allow appdomain runas_exec:file getattr;
 # Others are either allowed elsewhere or not desired.
 
+get_prop(appdomain, high_barometer_quality_prop)
+
 # Connect to adbd and use a socket transferred from it.
 # This is used for e.g. adb backup/restore.
 allow appdomain adbd:unix_stream_socket connectto;
@@ -639,12 +643,6 @@ neverallow { appdomain -platform_app }
     apk_tmp_file:dir_file_class_set
     { create write setattr relabelfrom relabelto append unlink link rename };
 
-neverallow { appdomain -untrusted_app_all -platform_app -priv_app -isolated_app_all }
-    { apk_tmp_file apk_private_tmp_file }:dir_file_class_set *;
-
-neverallow { untrusted_app_all isolated_app_all } { apk_tmp_file apk_private_tmp_file }:{ devfile_class_set dir fifo_file lnk_file sock_file } *;
-neverallow { untrusted_app_all isolated_app_all } { apk_tmp_file apk_private_tmp_file }:file ~{ getattr read };
-
 # Access to factory files.
 neverallow appdomain efs_file:dir_file_class_set write;
 neverallow { appdomain -shell } efs_file:dir_file_class_set read;
diff --git a/private/app_neverallows.te b/private/app_neverallows.te
index bf723c5be..0e2b01ce9 100644
--- a/private/app_neverallows.te
+++ b/private/app_neverallows.te
@@ -45,6 +45,10 @@ neverallow { all_untrusted_apps -mediaprovider } property_socket:sock_file write
 neverallow { all_untrusted_apps -mediaprovider } init:unix_stream_socket connectto;
 neverallow { all_untrusted_apps -mediaprovider } property_type:property_service set;
 
+# Do not allow untrusted apps to modify temporarily staged APKs.
+neverallow all_untrusted_apps { apk_tmp_file apk_private_tmp_file }:{ devfile_class_set dir fifo_file lnk_file sock_file } *;
+neverallow all_untrusted_apps { apk_tmp_file apk_private_tmp_file }:file ~{ getattr read map };
+
 # net.dns properties are not a public API. Disallow untrusted apps from reading this property.
 neverallow { all_untrusted_apps } net_dns_prop:file read;
 
diff --git a/private/artd.te b/private/artd.te
index e6a6aaa6b..15d7969dc 100644
--- a/private/artd.te
+++ b/private/artd.te
@@ -4,6 +4,9 @@ typeattribute artd mlstrustedsubject;
 type artd_exec, system_file_type, exec_type, file_type;
 type artd_tmpfs, file_type;
 
+# All types of artd subprocesses, which artd can kill.
+attribute artd_subprocess_type;
+
 # Allow artd to publish a binder service and make binder calls.
 binder_use(artd)
 add_service(artd, artd_service)
@@ -37,6 +40,8 @@ userfaultfd_use(artd)
 allow artd mnt_expand_file:dir { getattr search };
 allow artd apk_data_file:dir { rw_dir_perms create setattr relabelfrom };
 allow artd apk_data_file:file r_file_perms;
+allow artd apk_tmp_file:dir { rw_dir_perms create setattr relabelfrom };
+allow artd apk_tmp_file:file r_file_perms;
 
 # Read access to vendor APKs ({/vendor,/odm}/{app,priv-app}/...).
 r_dir_file(artd, vendor_app_file)
@@ -131,7 +136,7 @@ domain_auto_trans(artd, profman_exec, profman)
 domain_auto_trans(artd, dex2oat_exec, dex2oat)
 
 # Allow sending sigkill to subprocesses.
-allow artd { profman dex2oat }:process sigkill;
+allow artd artd_subprocess_type:process sigkill;
 
 # Allow reading process info (/proc/<pid>/...).
 # This is needed for getting CPU time and wall time spent on subprocesses.
@@ -159,9 +164,6 @@ allow artd self:global_capability_class_set sys_admin;
 domain_auto_trans(artd, derive_classpath_exec, derive_classpath)
 domain_auto_trans(artd, odrefresh_exec, odrefresh)
 
-# Allow sending sigkill to subprocesses.
-allow artd { derive_classpath odrefresh }:process sigkill;
-
 # Allow accessing Pre-reboot Dexopt files.
 allow artd pre_reboot_dexopt_file:dir { getattr search };
 
@@ -185,3 +187,15 @@ allow artd { apex_art_data_file odrefresh_data_file pre_reboot_dexopt_artd_file
 # Never allow running other binaries without a domain transition.
 # The exception for art_exec_exec is explained above.
 neverallow artd ~{art_exec_exec}:file execute_no_trans;
+
+# Make sure artd_subprocess_type is complete, in a sense that it includes all
+# types of artd subprocesses.
+neverallow artd ~{artd_subprocess_type crash_dump}:process transition;
+
+# artd uses process groups to manage subprocesses and kill them. To ensure
+# successful kill, we need to prevent subprocesses from changing their
+# process groups or transitioning to other domains.
+# Transitioning crash_dump is allowed because it is transient and is only used
+# upon crashes.
+neverallow artd_subprocess_type self:process setpgid;
+neverallow artd_subprocess_type ~{artd_subprocess_type crash_dump}:process transition;
diff --git a/private/cameraserver.te b/private/cameraserver.te
index b143f587c..16c1f3d38 100644
--- a/private/cameraserver.te
+++ b/private/cameraserver.te
@@ -14,7 +14,7 @@ binder_call(cameraserver, appdomain)
 binder_service(cameraserver)
 
 hal_client_domain(cameraserver, hal_camera)
-
+allow cameraserver hal_camera_server:process signal;
 hal_client_domain(cameraserver, hal_graphics_allocator)
 
 allow cameraserver ion_device:chr_file rw_file_perms;
diff --git a/private/compat/202404/202404.cil b/private/compat/202404/202404.cil
index 869deb668..5ba9b3f07 100644
--- a/private/compat/202404/202404.cil
+++ b/private/compat/202404/202404.cil
@@ -1,5 +1,7 @@
 ;; This type may or may not already exist in vendor policy. Re-define it here (duplicate
 ;; definitions in CIL will be ignored) - so we can reference it in 202404.cil.
+(type virtual_fingerprint_hal_prop)
+(type otapreopt_chroot)
 (type vendor_hidraw_device)
 (typeattributeset dev_type (vendor_hidraw_device))
 
@@ -2723,7 +2725,7 @@
 (typeattributeset virtual_device_native_service_202404 (virtual_device_native_service))
 (typeattributeset virtual_device_service_202404 (virtual_device_service))
 (typeattributeset virtual_face_hal_prop_202404 (virtual_face_hal_prop))
-(typeattributeset virtual_fingerprint_hal_prop_202404 (virtual_fingerprint_hal_prop))
+(typeattributeset virtual_fingerprint_hal_prop_202404 (virtual_fingerprint_hal_prop virtual_fingerprint_prop))
 (typeattributeset virtual_touchpad_202404 (virtual_touchpad))
 (typeattributeset virtual_touchpad_exec_202404 (virtual_touchpad_exec))
 (typeattributeset virtual_touchpad_service_202404 (virtual_touchpad_service))
diff --git a/private/compat/202404/202404.ignore.cil b/private/compat/202404/202404.ignore.cil
index efeeff7cf..17e28424a 100644
--- a/private/compat/202404/202404.ignore.cil
+++ b/private/compat/202404/202404.ignore.cil
@@ -5,12 +5,19 @@
 (typeattribute new_objects)
 (typeattributeset new_objects
   ( new_objects
+    bluetooth_finder_prop
     profcollectd_etr_prop
-    fs_bpf_lmkd_memevents_rb
-    fs_bpf_lmkd_memevents_prog
     fstype_prop
     binderfs_logs_transactions
     binderfs_logs_transaction_history
     proc_compaction_proactiveness
     proc_cgroups
+    ranging_service
+    supervision_service
+    sysfs_udc
+    app_function_service
+    virtual_fingerprint
+    virtual_fingerprint_exec
+    virtual_face
+    virtual_face_exec
   ))
diff --git a/private/compat/33.0/33.0.compat.cil b/private/compat/33.0/33.0.compat.cil
index 53ee8ff9c..f102b0256 100644
--- a/private/compat/33.0/33.0.compat.cil
+++ b/private/compat/33.0/33.0.compat.cil
@@ -1,3 +1,12 @@
 ;; complement CIL file for compatibility between ToT policy and 33.0 vendors.
 ;; will be compiled along with other normal policy files, on 33.0 vendors.
 ;;
+
+;; This type may or may not already exist in vendor policy. The 202404 sepolicy
+;; (well, the 24Q1 release) added hidraw_device, but existing vendor policy
+;; may still label the relevant devices with the old label.
+(type vendor_hidraw_device)
+(typeattributeset dev_type (vendor_hidraw_device))
+
+(allow system_server vendor_hidraw_device (dir (open getattr read search ioctl lock watch watch_reads)))
+(allow system_server vendor_hidraw_device (chr_file (getattr open read ioctl lock map watch watch_reads append write)))
\ No newline at end of file
diff --git a/private/compat/33.0/33.0.ignore.cil b/private/compat/33.0/33.0.ignore.cil
index 352aecfcf..a43f0fd46 100644
--- a/private/compat/33.0/33.0.ignore.cil
+++ b/private/compat/33.0/33.0.ignore.cil
@@ -81,6 +81,7 @@
     usb_uvc_enabled_prop
     virtual_face_hal_prop
     virtual_fingerprint_hal_prop
+    virtual_fingerprint_prop
     hal_gatekeeper_service
     hal_broadcastradio_service
     hal_confirmationui_service
diff --git a/private/compat/34.0/34.0.ignore.cil b/private/compat/34.0/34.0.ignore.cil
index 455cbff28..6c52dba76 100644
--- a/private/compat/34.0/34.0.ignore.cil
+++ b/private/compat/34.0/34.0.ignore.cil
@@ -32,6 +32,7 @@
     security_state_service
     sensitive_content_protection_service
     setupwizard_mode_prop
+    supervision_service
     sysfs_sync_on_suspend
     tv_ad_service
     threadnetwork_service
diff --git a/private/coredomain.te b/private/coredomain.te
index d89e9ca82..93cbff53b 100644
--- a/private/coredomain.te
+++ b/private/coredomain.te
@@ -55,7 +55,6 @@ full_treble_only(`
         -appdomain
         -artd
         -dex2oat
-        -dexoptanalyzer
         -idmap
         -init
         -installd
@@ -73,7 +72,6 @@ full_treble_only(`
         -appdomain
         -artd
         -dex2oat
-        -dexoptanalyzer
         -idmap
         -init
         -installd
@@ -96,7 +94,6 @@ full_treble_only(`
         -appdomain
         -artd
         -dex2oat
-        -dexoptanalyzer
         -idmap
         -init
         -installd
@@ -117,7 +114,6 @@ full_treble_only(`
         -appdomain
         -artd
         -dex2oat
-        -dexoptanalyzer
         -idmap
         -init
         -installd
diff --git a/private/crash_dump.te b/private/crash_dump.te
index 45d57222d..b2d3bd5a0 100644
--- a/private/crash_dump.te
+++ b/private/crash_dump.te
@@ -106,8 +106,15 @@ dontaudit crash_dump {
   core_data_file_type
   vendor_file_type
 }:dir search;
-dontaudit crash_dump system_data_file:{ lnk_file file } read;
-dontaudit crash_dump property_type:file read;
+# Crash dump might try to read files that are mapped into the crashed process's
+# memory space to extract useful binary information such as the ELF header. See
+# system/core/debuggerd/libdebuggerd/tombstone_proto.cpp:dump_mappings.
+# Ignore these accesses.
+dontaudit crash_dump {
+  app_data_file_type
+  property_type
+  system_data_file
+}:{ lnk_file file } { read open };
 
 get_prop(crash_dump, misctrl_prop)
 
diff --git a/private/crosvm.te b/private/crosvm.te
index cddab367c..ccfffa01e 100644
--- a/private/crosvm.te
+++ b/private/crosvm.te
@@ -20,10 +20,16 @@ neverallow { coredomain appdomain -crosvm -ueventd } vm_manager_device_type:chr_
 tmpfs_domain(crosvm)
 
 # Let crosvm receive file descriptors from VirtualizationService.
-allow crosvm virtualizationmanager:fd use;
+allow crosvm {
+  virtualizationmanager
+  is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `early_virtmgr')
+}:fd use;
 
 # Allow sending VirtualizationService the failure reason and console/log from the VM via pipe.
-allow crosvm virtualizationmanager:fifo_file write;
+allow crosvm {
+  virtualizationmanager
+  is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `early_virtmgr')
+}:fifo_file write;
 
 # Let crosvm read the composite disk images (virtualizationservice_data_file), APEXes
 # (staging_data_file), APKs (apk_data_file and shell_data_file where the latter is for test apks in
@@ -40,10 +46,14 @@ allow crosvm {
   apex_virt_data_file
   shell_data_file
   vendor_microdroid_file
+  is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `vm_data_file')
 }:file { getattr read ioctl lock };
 
 # Allow searching the directory where the composite disk images are.
-allow crosvm virtualizationservice_data_file:dir search;
+allow crosvm {
+    virtualizationservice_data_file
+    is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `vm_data_file')
+}:dir search;
 
 # When running a VM as root we get spurious capability denials.
 # Suppress them.
@@ -58,7 +68,10 @@ allow crosvm self:global_capability_class_set sys_nice;
 #   read, write, getattr: listener socket polling
 #   accept: listener socket accepting new connection
 # Note that the open permission is not given as the socket is passed by FD.
-allow crosvm virtualizationmanager:unix_stream_socket { accept read write getattr getopt };
+allow crosvm {
+  virtualizationmanager
+  is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `early_virtmgr')
+}:unix_stream_socket { accept read write getattr getopt };
 
 # Let crosvm open test artifacts under /data/local/tmp with file path. (e.g. custom pvmfw.img)
 userdebug_or_eng(`
@@ -74,6 +87,7 @@ allow crosvm {
   privapp_data_file
   apex_compos_data_file
   apex_virt_data_file
+  is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `vm_data_file')
 }:file write;
 
 # Allow crosvm to pipe console log to shell or app which could be the owner of a VM.
@@ -116,7 +130,10 @@ allow crosvm shell_data_file:file write;
 # crosvm tries to read serial device, including the write-only pipe from virtualizationmanager (to
 # forward console/log to the host logcat).
 # crosvm only needs write permission, so dontaudit read
-dontaudit crosvm virtualizationmanager:fifo_file { read getattr };
+dontaudit crosvm {
+  virtualizationmanager
+  is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `early_virtmgr')
+}:fifo_file { read getattr };
 
 # Required for crosvm to start gdb-server to enable debugging of guest kernel.
 allow crosvm self:tcp_socket { bind create read setopt write accept listen };
@@ -129,18 +146,20 @@ allow crosvm vfio_device:chr_file rw_file_perms;
 allow crosvm vfio_device:dir r_dir_perms;
 
 # Allow crosvm to access VM DTBO via a file created by virtualizationmanager.
-allow crosvm virtualizationmanager:fd use;
 allow crosvm virtualizationservice_data_file:file read;
 
 is_flag_enabled(RELEASE_AVF_ENABLE_NETWORK, `
     # Allow crosvm to deal with file descriptors of TAP interfaces.
     allow crosvm tun_device:chr_file rw_file_perms;
-    allowxperm crosvm tun_device:chr_file ioctl { TUNGETIFF TUNSETVNETHDRSZ };
+    allowxperm crosvm tun_device:chr_file ioctl { TUNGETIFF TUNSETOFFLOAD TUNSETVNETHDRSZ };
     allow crosvm self:udp_socket create_socket_perms;
     allowxperm crosvm self:udp_socket ioctl SIOCGIFMTU;
     allow crosvm vmnic:fd use;
 ')
 
+# Early VMs may print messages to kmsg_debug_device.
+allow crosvm kmsg_debug_device:chr_file w_file_perms;
+
 # Don't allow crosvm to open files that it doesn't own.
 # This is important because a malicious application could try to start a VM with a composite disk
 # image referring by name to files which it doesn't have permission to open, trying to get crosvm to
@@ -153,6 +172,7 @@ neverallow crosvm {
   app_data_file
   privapp_data_file
   is_flag_enabled(RELEASE_UNLOCKED_STORAGE_API, `storage_area_content_file')
+  is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `vm_data_file')
   userdebug_or_eng(`-shell_data_file')
 }:file open;
 
@@ -188,4 +208,6 @@ neverallow {
   domain
   -crosvm
   -virtualizationmanager
+
+  is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `-early_virtmgr')
 } crosvm_exec:file no_x_file_perms;
diff --git a/private/custom_vm_setup.te b/private/custom_vm_setup.te
new file mode 100644
index 000000000..c14f5e0e0
--- /dev/null
+++ b/private/custom_vm_setup.te
@@ -0,0 +1,6 @@
+type custom_vm_setup, domain, coredomain;
+type custom_vm_setup_exec, system_file_type, exec_type, file_type;
+
+is_flag_enabled(RELEASE_AVF_SUPPORT_CUSTOM_VM_WITH_PARAVIRTUALIZED_DEVICES, `
+  init_daemon_domain(custom_vm_setup)
+')
diff --git a/private/derive_classpath.te b/private/derive_classpath.te
index 8dd65720a..d7c29c28b 100644
--- a/private/derive_classpath.te
+++ b/private/derive_classpath.te
@@ -1,6 +1,6 @@
 
 # Domain for derive_classpath
-type derive_classpath, domain, coredomain;
+type derive_classpath, domain, coredomain, artd_subprocess_type;
 type derive_classpath_exec, system_file_type, exec_type, file_type;
 init_daemon_domain(derive_classpath)
 
diff --git a/private/dex2oat.te b/private/dex2oat.te
index 18600d8b9..3a841ced7 100644
--- a/private/dex2oat.te
+++ b/private/dex2oat.te
@@ -1,5 +1,5 @@
 # dex2oat
-type dex2oat, domain, coredomain;
+type dex2oat, domain, coredomain, artd_subprocess_type;
 type dex2oat_exec, system_file_type, exec_type, file_type;
 
 userfaultfd_use(dex2oat)
diff --git a/private/dexopt_chroot_setup.te b/private/dexopt_chroot_setup.te
index 4267d09d3..9e98baebd 100644
--- a/private/dexopt_chroot_setup.te
+++ b/private/dexopt_chroot_setup.te
@@ -52,6 +52,7 @@ allow dexopt_chroot_setup {
   apex_mnt_dir
   apk_data_file
   binderfs
+  binfmt_miscfs
   cgroup
   cgroup_v2
   userdebug_or_eng(debugfs)
@@ -73,6 +74,7 @@ allow dexopt_chroot_setup {
   system_data_file
   system_data_root_file
   system_file
+  system_lib_file
   tmpfs
   vendor_file
 }:dir mounton;
@@ -81,6 +83,7 @@ allow dexopt_chroot_setup { tmpfs labeledfs }:filesystem mount;
 
 allow dexopt_chroot_setup {
   binderfs
+  binfmt_miscfs
   cgroup
   cgroup_v2
   userdebug_or_eng(debugfs)
diff --git a/private/dexoptanalyzer.te b/private/dexoptanalyzer.te
index ca715c192..4c87f99ab 100644
--- a/private/dexoptanalyzer.te
+++ b/private/dexoptanalyzer.te
@@ -1,60 +1,3 @@
-# dexoptanalyzer
-type dexoptanalyzer, domain, coredomain, mlstrustedsubject;
+# Deprecated file type for the legacy dexoptanalyzer binary, used by Android T-. We need to keep it
+# for compatibility because the file type is burnt into the apex image.
 type dexoptanalyzer_exec, system_file_type, exec_type, file_type;
-type dexoptanalyzer_tmpfs, file_type;
-
-r_dir_file(dexoptanalyzer, apk_data_file)
-# Access to /vendor/app
-r_dir_file(dexoptanalyzer, vendor_app_file)
-
-# Reading an APK opens a ZipArchive, which unpack to tmpfs.
-# Use tmpfs_domain() which will give tmpfs files created by dexoptanalyzer their
-# own label, which differs from other labels created by other processes.
-# This allows to distinguish in policy files created by dexoptanalyzer vs other
-# processes.
-tmpfs_domain(dexoptanalyzer)
-
-userfaultfd_use(dexoptanalyzer)
-
-# Allow dexoptanalyzer to read files in the dalvik cache.
-allow dexoptanalyzer dalvikcache_data_file:dir { getattr search };
-allow dexoptanalyzer dalvikcache_data_file:file r_file_perms;
-
-# Read symlinks in /data/dalvik-cache. This is required for PIC mode boot
-# app_data_file the oat file is symlinked to the original file in /system.
-allow dexoptanalyzer dalvikcache_data_file:lnk_file read;
-
-# Allow dexoptanalyzer to read files in the ART APEX data directory.
-allow dexoptanalyzer { apex_art_data_file apex_module_data_file }:dir { getattr search };
-allow dexoptanalyzer apex_art_data_file:file r_file_perms;
-
-# Allow dexoptanalyzer to use file descriptors from odrefresh.
-allow dexoptanalyzer odrefresh:fd use;
-
-# Use devpts and fd from odsign (which exec()'s odrefresh)
-allow dexoptanalyzer odsign:fd use;
-allow dexoptanalyzer odsign_devpts:chr_file { read write };
-
-allow dexoptanalyzer installd:fd use;
-allow dexoptanalyzer installd:fifo_file { getattr write };
-
-# Acquire advisory lock on /system/framework/arm/*
-allow dexoptanalyzer system_file:file lock;
-
-# Allow reading secondary dex files that were reported by the app to the
-# package manager.
-allow dexoptanalyzer { privapp_data_file app_data_file }:file { getattr read map };
-
-# dexoptanalyzer checks the DM files next to dex files. We don't need this check
-# for secondary dex files, but it's not harmful. Just deny it and ignore it.
-dontaudit dexoptanalyzer { privapp_data_file app_data_file }:dir search;
-
-# Allow testing /data/user/0 which symlinks to /data/data
-allow dexoptanalyzer system_data_file:lnk_file { getattr };
-
-# Allow query ART device config properties
-get_prop(dexoptanalyzer, device_config_runtime_native_prop)
-get_prop(dexoptanalyzer, device_config_runtime_native_boot_prop)
-
-# Allow dexoptanalyzer to read /apex/apex-info-list.xml
-allow dexoptanalyzer apex_info_file:file r_file_perms;
diff --git a/private/domain.te b/private/domain.te
index 61e2ea66f..e9cc7f565 100644
--- a/private/domain.te
+++ b/private/domain.te
@@ -15,12 +15,12 @@ allow domain self:process {
     setsched
     getsession
     getpgid
-    setpgid
     getcap
     setcap
     getattr
     setrlimit
 };
+allow { domain -artd_subprocess_type } self:process setpgid;
 allow domain self:fd use;
 allow domain proc:dir r_dir_perms;
 allow domain proc_net_type:dir search;
@@ -84,6 +84,10 @@ allow domain ashmem_libcutils_device:chr_file rw_file_perms;
 # /dev/binder can be accessed by ... everyone! :)
 allow { domain -hwservicemanager -vndservicemanager } binder_device:chr_file rw_file_perms;
 get_prop({domain -hwservicemanager -vndservicemanager }, servicemanager_prop)
+# Checking for the existance of the hwservicemanager binary is done in the client API
+# isHwServiceManagerInstalled
+dontaudit domain hwservicemanager_exec:file r_file_perms;
+
 
 # Restrict binder ioctls to an allowlist. Additional ioctl commands may be
 # added to individual domains, but this sets safe defaults for all processes.
@@ -342,6 +346,10 @@ allow domain apex_mnt_dir:lnk_file r_file_perms;
 allow domain sysfs_pgsize_migration:dir search;
 allow domain sysfs_pgsize_migration:file r_file_perms;
 
+# Linker is executed from the context of the process requesting the dynamic linking,
+# so this prop must be "world-readable".
+get_prop(domain, bionic_linker_16kb_app_compat_prop)
+
 # Allow everyone to read media server-configurable flags, so that libstagefright can be
 # configured using server-configurable flags
 get_prop(domain, device_config_media_native_prop)
@@ -493,7 +501,7 @@ get_prop(domain, socket_hook_prop)
 get_prop(domain, surfaceflinger_prop)
 get_prop(domain, telephony_status_prop)
 get_prop(domain, timezone_prop)
-get_prop({domain -untrusted_app_all -isolated_app_all -ephemeral_app },  userdebug_or_eng_prop)
+get_prop({domain -untrusted_app_all -isolated_app_all -ephemeral_app -app_zygote },  userdebug_or_eng_prop)
 get_prop(domain, vendor_socket_hook_prop)
 get_prop(domain, vndk_prop)
 get_prop(domain, vold_status_prop)
@@ -570,13 +578,15 @@ allow {
   -hal_omx_server
 } {shell_exec toolbox_exec}:file rx_file_perms;
 
-# Allow all to read from flag value boot snapshot storage files and general pb files
-# The boot snapshot of storage files serves flag read traffic for all processes, thus
-# needs to be readable by everybody.
-r_dir_file(domain, aconfig_storage_metadata_file);
+# Allow all processes to read aconfig flag storage files. The format is hidden behind
+# code-generated APIs, but since the libraries are executed in the context of the caller,
+# all processes need access to the underlying files.
+is_flag_enabled(RELEASE_READ_FROM_NEW_STORAGE, `
+  r_dir_file(domain, aconfig_storage_metadata_file);
+  r_dir_file(domain, aconfig_test_mission_files);
+')
 
 r_dir_file({ coredomain appdomain }, system_aconfig_storage_file);
-r_dir_file({ coredomain appdomain }, aconfig_test_mission_files);
 
 # processes needs to access storage file stored at /metadata/aconfig/boot, require search
 # permission on /metadata dir
@@ -1631,7 +1641,6 @@ neverallow {
   -appdomain
   -app_zygote
   -artd # compile secondary dex files
-  -dexoptanalyzer
   -installd
   -profman
   -rs # spawned by appdomain, so carryover the exception above
@@ -2235,3 +2244,6 @@ neverallow { domain -dexopt_chroot_setup -init -zygote } proc_type:{ file dir }
 # Only init/vendor are allowed to write sysfs_pgsize_migration;
 # ueventd needs write access to all sysfs files.
 neverallow { domain -init -vendor_init -ueventd } sysfs_pgsize_migration:file no_w_file_perms;
+
+# We need to be able to rely on vsock labels, so disallow changing them.
+neverallow domain *:vsock_socket { relabelfrom relabelto };
diff --git a/private/dumpstate.te b/private/dumpstate.te
index 6d5f0b360..13b7b9f90 100644
--- a/private/dumpstate.te
+++ b/private/dumpstate.te
@@ -33,6 +33,9 @@ userdebug_or_eng(`
   allow dumpstate dropbox_data_file:file r_file_perms;
 ')
 
+r_dir_file(dumpstate, aconfig_storage_metadata_file);
+r_dir_file(dumpstate, aconfig_test_mission_files);
+
 # Allow dumpstate to make binder calls to incidentd
 binder_call(dumpstate, incidentd)
 
@@ -258,6 +261,12 @@ allow dumpstate {
   system_suspend_server
 }:process signal;
 
+# On userdebug, dumpstate may fork and execute a command as su. Make sure the
+# timeout logic is allowed to terminate the child process if necessary.
+userdebug_or_eng(`
+  allow dumpstate su:process { signal sigkill };
+')
+
 # Connect to tombstoned to intercept dumps.
 unix_socket_connect(dumpstate, tombstoned_intercept, tombstoned)
 
@@ -528,6 +537,7 @@ dontaudit dumpstate {
   linkerconfig_file
   mirror_data_file
   mnt_user_file
+  vm_data_file
 }:dir getattr;
 
 # Allow dumpstate to talk to bufferhubd over binder
diff --git a/private/early_virtmgr.te b/private/early_virtmgr.te
new file mode 100644
index 000000000..e244be2b0
--- /dev/null
+++ b/private/early_virtmgr.te
@@ -0,0 +1,75 @@
+is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `
+    # Domain for a child process that manages early VMs available before /data mount, on behalf of
+    # its parent.
+    type early_virtmgr, domain, coredomain;
+    type early_virtmgr_exec, system_file_type, exec_type, file_type;
+
+    use_bootstrap_libs(early_virtmgr)
+
+    # Let early_virtmgr create files and directories inside /mnt/vm/early.
+    allow early_virtmgr vm_data_file:dir create_dir_perms;
+    allow early_virtmgr vm_data_file:file create_file_perms;
+    allow early_virtmgr vm_data_file:sock_file create_file_perms;
+
+    # Allow early_virtmgr to communicate use, read and write over the adb connection.
+    allow early_virtmgr adbd:fd use;
+    allow early_virtmgr adbd:unix_stream_socket { getattr read write };
+
+    # Allow writing VM logs to the shell console
+    allow early_virtmgr devpts:chr_file { read write getattr ioctl };
+
+    # Let the early_virtmgr domain use Binder.
+    binder_use(early_virtmgr)
+
+    # When early_virtmgr execs a file with the crosvm_exec label, run it in the crosvm domain.
+    domain_auto_trans(early_virtmgr, crosvm_exec, crosvm)
+
+    # Let early_virtmgr kill crosvm.
+    allow early_virtmgr crosvm:process sigkill;
+
+    # Allow early_virtmgr to read apex-info-list.xml and access the APEX files listed there.
+    allow early_virtmgr apex_info_file:file r_file_perms;
+    allow early_virtmgr apex_data_file:dir search;
+
+    # Ignore harmless denials on /proc/self/fd
+    dontaudit early_virtmgr self:dir write;
+
+    # Let early_virtmgr to accept vsock connection from the guest VMs
+    allow early_virtmgr self:vsock_socket { create_socket_perms_no_ioctl listen accept };
+
+    # Allow early_virtmgr to inspect all hypervisor capabilities.
+    get_prop(early_virtmgr, hypervisor_prop)
+    get_prop(early_virtmgr, hypervisor_pvmfw_prop)
+    get_prop(early_virtmgr, hypervisor_restricted_prop)
+    get_prop(early_virtmgr, hypervisor_virtualizationmanager_prop)
+
+    # Allow early_virtmgr to read file system DT for VM reference DT and AVF debug policy
+    r_dir_file(early_virtmgr, proc_dt_avf)
+    r_dir_file(early_virtmgr, sysfs_dt_avf)
+
+    # early_virtmgr to be client of secretkeeper HAL. It ferries SecretManagement messages from pVM
+    # to HAL.
+    hal_client_domain(early_virtmgr, hal_secretkeeper);
+
+    # Allow reading files under /proc/[crosvm pid]/, for collecting CPU & memory usage inside VM.
+    r_dir_file(early_virtmgr, crosvm);
+
+    # Allow early_virtmgr to:
+    # 1) bind to a vsock port less than 1024, because early VMs use static CIDs less than 1024
+    # 2) call RLIMIT_MEMLOCK for itself
+    allow early_virtmgr self:global_capability_class_set { net_bind_service ipc_lock sys_resource };
+
+    # early_virtmgr may print messages to kmsg_debug_device.
+    allow early_virtmgr kmsg_debug_device:chr_file w_file_perms;
+
+    ###
+    ### Neverallow rules
+    ###
+
+    # Only crosvm and early_virtmgr can access vm_data_file
+    neverallow { domain -crosvm -early_virtmgr -init } vm_data_file:dir no_w_dir_perms;
+    neverallow { domain -crosvm -early_virtmgr } vm_data_file:file no_rw_file_perms;
+
+    # No other domains can accept vsock connection from the guest VMs
+    neverallow { domain -early_virtmgr } early_virtmgr:vsock_socket { accept bind create connect listen };
+')
diff --git a/private/ferrochrome_app.te b/private/ferrochrome_app.te
new file mode 100644
index 000000000..e12c84c62
--- /dev/null
+++ b/private/ferrochrome_app.te
@@ -0,0 +1,11 @@
+type ferrochrome_app, domain;
+typeattribute ferrochrome_app coredomain;
+
+app_domain(ferrochrome_app)
+
+allow ferrochrome_app app_api_service:service_manager find;
+allow ferrochrome_app system_api_service:service_manager find;
+
+# TODO(b/348113995): after remove sysprop usage, we can use just (priv_)app.te
+set_prop(ferrochrome_app, debug_prop);
+get_prop(ferrochrome_app, debug_prop);
diff --git a/private/file.te b/private/file.te
index f8a48cd13..70b8523bc 100644
--- a/private/file.te
+++ b/private/file.te
@@ -9,6 +9,7 @@ type fs_bpf_netd_readonly, fs_type, bpffs_type;
 type fs_bpf_netd_shared, fs_type, bpffs_type;
 type fs_bpf_loader, fs_type, bpffs_type;
 type fs_bpf_uprobestats, fs_type, bpffs_type;
+type fs_bpf_memevents, fs_type, bpffs_type;
 
 # /data/misc/storaged
 type storaged_data_file, file_type, data_file_type, core_data_file_type;
@@ -38,6 +39,7 @@ type system_perfetto_config_file, file_type, system_file_type;
 type uprobestats_configs_data_file, file_type, data_file_type, core_data_file_type;
 
 # /apex/com.android.art/bin/oatdump
+# TODO (b/350628688): Remove this once it's safe to do so.
 type oatdump_exec, system_file_type, exec_type, file_type;
 
 # /data/misc_{ce/de}/<user>/sdksandbox root data directory for sdk sandbox processes
@@ -116,6 +118,9 @@ type odsign_metrics_file, file_type, data_file_type, core_data_file_type;
 # virtualizationmanager, which runs at a more constrained MLS level.
 type virtualizationservice_data_file, file_type, data_file_type, core_data_file_type, mlstrustedobject;
 
+# /mnt/vm
+type vm_data_file, file_type, core_data_file_type;
+
 # /data/system/environ
 type environ_system_data_file, file_type, data_file_type, core_data_file_type;
 
@@ -209,3 +214,30 @@ type storage_area_content_file, file_type, data_file_type, core_data_file_type,
 
 # /data/misc_ce/userId/storage_area_keys
 type storage_area_key_file, file_type, data_file_type, core_data_file_type;
+
+
+# Types added in 202504 in public/file.te
+until_board_api(202504, `
+    type binderfs_logs_transactions, fs_type;
+    type binderfs_logs_transaction_history, fs_type;
+')
+
+until_board_api(202504, `
+    type proc_cgroups, fs_type, proc_type;
+')
+
+until_board_api(202504, `
+    type sysfs_udc, fs_type, sysfs_type;
+')
+
+until_board_api(202504, `
+    type fs_bpf_lmkd_memevents_rb, fs_type, bpffs_type;
+    type fs_bpf_lmkd_memevents_prog, fs_type, bpffs_type;
+')
+
+until_board_api(202504, `
+    # boot otas for 16KB developer option
+    type vendor_boot_ota_file, vendor_file_type, file_type;
+')
+## END Types added in 202504 in public/file.te
+
diff --git a/private/file_contexts b/private/file_contexts
index f0832f3b0..fa2fe3a22 100644
--- a/private/file_contexts
+++ b/private/file_contexts
@@ -24,7 +24,7 @@
 /                   u:object_r:rootfs:s0
 
 # Data files
-/adb_keys           u:object_r:adb_keys_file:s0
+/adb_keys           u:object_r:system_file:s0
 /build\.prop        u:object_r:rootfs:s0
 /default\.prop      u:object_r:rootfs:s0
 /fstab\..*          u:object_r:rootfs:s0
@@ -362,7 +362,7 @@
 /system/bin/virtual_camera          u:object_r:virtual_camera_exec:s0
 /system/bin/hw/android\.frameworks\.bufferhub@1\.0-service    u:object_r:fwk_bufferhub_exec:s0
 /system/bin/hw/android\.system\.suspend-service               u:object_r:system_suspend_exec:s0
-/(system|system_ext|product)/etc/aconfig(/.*)?                u:object_r:system_aconfig_storage_file:s0
+/system/etc/aconfig(/.*)?                u:object_r:system_aconfig_storage_file:s0
 /system/etc/cgroups\.json               u:object_r:cgroup_desc_file:s0
 /system/etc/task_profiles/cgroups_[0-9]+\.json               u:object_r:cgroup_desc_api_file:s0
 /system/etc/event-log-tags              u:object_r:system_event_log_tags_file:s0
@@ -432,7 +432,6 @@
 /(vendor|system/vendor)/overlay(/.*)?          u:object_r:vendor_overlay_file:s0
 /(vendor|system/vendor)/framework(/.*)?        u:object_r:vendor_framework_file:s0
 
-/(vendor|system/vendor)/apex(/[^/]+){0,2}                      u:object_r:vendor_apex_file:s0
 /(vendor|system/vendor)/bin/misc_writer                        u:object_r:vendor_misc_writer_exec:s0
 /(vendor|system/vendor)/bin/boringssl_self_test(32|64)         u:object_r:vendor_boringssl_self_test_exec:s0
 
@@ -462,6 +461,8 @@
 # secure-element service: vendor uuid mapping config file
 /(odm|vendor/odm|vendor|system/vendor)/etc/hal_uuid_map_(.*)?\.xml    u:object_r:vendor_uuid_mapping_config_file:s0
 
+# APEX packages
+/(odm|vendor/odm|vendor|system/vendor)/apex(/[^/]+){0,2}              u:object_r:vendor_apex_file:s0
 
 # Input configuration
 /(odm|vendor/odm|vendor|system/vendor)/usr/keylayout(/.*)?\.kl        u:object_r:vendor_keylayout_file:s0
@@ -506,6 +507,9 @@
 
 /(product|system/product)/lib(64)?(/.*)?                         u:object_r:system_lib_file:s0
 
+/(product|system/product)/etc/security/adb_keys                 u:object_r:adb_keys_file:s0
+/(product|system/product)/etc/aconfig(/.*)?                     u:object_r:system_aconfig_storage_file:s0
+
 #############################
 # SystemExt files
 #
@@ -530,11 +534,14 @@
 /(system_ext|system/system_ext)/bin/hwservicemanager         u:object_r:hwservicemanager_exec:s0
 /(system_ext|system/system_ext)/bin/hw/android\.hidl\.allocator@1\.0-service u:object_r:hal_allocator_default_exec:s0
 
+/(system_ext|system/system_ext)/bin/custom_vm_setup       u:object_r:custom_vm_setup_exec:s0
 
 /(system_ext|system/system_ext)/bin/canhalconfigurator(-aidl)? u:object_r:canhalconfigurator_exec:s0
 
 /(system_ext|system/system_ext)/lib(64)?(/.*)?      u:object_r:system_lib_file:s0
 
+/(system_ext|system/system_ext)/etc/aconfig(/.*)?                u:object_r:system_aconfig_storage_file:s0
+
 #############################
 # VendorDlkm files
 # This includes VENDOR Dynamically Loadable Kernel Modules and other misc files.
@@ -875,13 +882,18 @@
 /metadata/ota(/.*)?       u:object_r:ota_metadata_file:s0
 /metadata/bootstat(/.*)?  u:object_r:metadata_bootstat_file:s0
 /metadata/staged-install(/.*)?    u:object_r:staged_install_file:s0
-/metadata/userspacereboot(/.*)?    u:object_r:userspace_reboot_metadata_file:s0
 /metadata/watchdog(/.*)?    u:object_r:watchdog_metadata_file:s0
 /metadata/repair-mode(/.*)?    u:object_r:repair_mode_metadata_file:s0
 /metadata/aconfig(/.*)?    u:object_r:aconfig_storage_metadata_file:s0
 /metadata/aconfig/flags(/.*)?    u:object_r:aconfig_storage_flags_metadata_file:s0
 /metadata/aconfig_test_missions(/.*)?    u:object_r:aconfig_test_mission_files:s0
 
+############################
+# mount point for ota metadata
+/mnt/scratch_ota_metadata_super(/.*)?                 u:object_r:ota_metadata_file:s0
+/mnt/scratch_ota_metadata_super/ota(/.*)?             u:object_r:ota_metadata_file:s0
+/mnt/scratch_ota_metadata_super/ota/snapshots(/.*)?   u:object_r:ota_metadata_file:s0
+
 #############################
 # asec containers
 /mnt/asec(/.*)?             u:object_r:asec_apk_file:s0
@@ -920,3 +932,7 @@
 # dexopt_chroot_setup inside chroot, in addition to the files and directories
 # matching the pattern below.
 /mnt/pre_reboot_dexopt(/.*)?  u:object_r:pre_reboot_dexopt_file:s0
+
+#############################
+# For early boot VM
+/mnt/vm u:object_r:vm_data_file:s0
diff --git a/private/fsck.te b/private/fsck.te
index 5eeb39f8a..90f7e5120 100644
--- a/private/fsck.te
+++ b/private/fsck.te
@@ -2,6 +2,9 @@ typeattribute fsck coredomain;
 
 init_daemon_domain(fsck)
 
+# fsck can run before apex is ready.
+use_bootstrap_libs(fsck)
+
 allow fsck metadata_block_device:blk_file rw_file_perms;
 
 # /dev/__null__ created by init prior to policy load,
diff --git a/private/fsck_untrusted.te b/private/fsck_untrusted.te
index 682831ff2..4b55a57e5 100644
--- a/private/fsck_untrusted.te
+++ b/private/fsck_untrusted.te
@@ -1,5 +1,7 @@
 typeattribute fsck_untrusted coredomain;
 
+use_bootstrap_libs(fsck)
+
 # Inherit and use pty created by android_fork_execvp_ext().
 allow fsck_untrusted devpts:chr_file { read write ioctl getattr };
 
diff --git a/private/genfs_contexts b/private/genfs_contexts
index ac59c9afc..b8b724739 100644
--- a/private/genfs_contexts
+++ b/private/genfs_contexts
@@ -94,7 +94,6 @@ genfscon proc /sys/vm/min_free_order_shift u:object_r:proc_min_free_order_shift:
 genfscon proc /sys/vm/watermark_boost_factor u:object_r:proc_watermark_boost_factor:s0
 genfscon proc /sys/vm/watermark_scale_factor u:object_r:proc_watermark_scale_factor:s0
 genfscon proc /sys/vm/percpu_pagelist_high_fraction u:object_r:proc_percpu_pagelist_high_fraction:s0
-genfscon proc /sys/vm/compaction_proactiveness u:object_r:proc_compaction_proactiveness:s0
 genfscon proc /timer_list u:object_r:proc_timer:s0
 genfscon proc /timer_stats u:object_r:proc_timer:s0
 genfscon proc /tty/drivers u:object_r:proc_tty_drivers:s0
@@ -136,6 +135,7 @@ genfscon sysfs /class/rfkill/rfkill3/state        u:object_r:sysfs_bluetooth_wri
 genfscon sysfs /class/rtc                         u:object_r:sysfs_rtc:s0
 genfscon sysfs /class/switch                      u:object_r:sysfs_switch:s0
 genfscon sysfs /class/wakeup                      u:object_r:sysfs_wakeup:s0
+genfscon sysfs /class/udc                         u:object_r:sysfs_udc:s0
 genfscon sysfs /devices/platform/nfc-power/nfc_power u:object_r:sysfs_nfc_power_writable:s0
 genfscon sysfs /devices/virtual/android_usb     u:object_r:sysfs_android_usb:s0
 genfscon sysfs /devices/virtual/block/            u:object_r:sysfs_devices_block:s0
@@ -330,13 +330,11 @@ genfscon binfmt_misc / u:object_r:binfmt_miscfs:s0
 
 genfscon bpf / u:object_r:fs_bpf:s0
 genfscon bpf /loader u:object_r:fs_bpf_loader:s0
-genfscon bpf /map_bpfMemEvents_lmkd_rb u:object_r:fs_bpf_lmkd_memevents_rb:s0
+genfscon bpf /memevents u:object_r:fs_bpf_memevents:s0
 genfscon bpf /net_private u:object_r:fs_bpf_net_private:s0
 genfscon bpf /net_shared u:object_r:fs_bpf_net_shared:s0
 genfscon bpf /netd_readonly u:object_r:fs_bpf_netd_readonly:s0
 genfscon bpf /netd_shared u:object_r:fs_bpf_netd_shared:s0
-genfscon bpf /prog_bpfMemEvents_tracepoint_vmscan_mm_vmscan_direct_reclaim_begin_lmkd u:object_r:fs_bpf_lmkd_memevents_prog:s0
-genfscon bpf /prog_bpfMemEvents_tracepoint_vmscan_mm_vmscan_direct_reclaim_end_lmkd u:object_r:fs_bpf_lmkd_memevents_prog:s0
 genfscon bpf /tethering u:object_r:fs_bpf_tethering:s0
 genfscon bpf /vendor u:object_r:fs_bpf_vendor:s0
 genfscon bpf /uprobestats u:object_r:fs_bpf_uprobestats:s0
diff --git a/private/gmscore_app.te b/private/gmscore_app.te
index f938ad508..fa3420acc 100644
--- a/private/gmscore_app.te
+++ b/private/gmscore_app.te
@@ -112,11 +112,6 @@ allow gmscore_app radio_service:service_manager find;
 allow gmscore_app recovery_service:service_manager find;
 allow gmscore_app stats_service:service_manager find;
 
-# Used by Finsky / Android "Verify Apps" functionality when
-# running "adb install foo.apk".
-allow gmscore_app shell_data_file:file r_file_perms;
-allow gmscore_app shell_data_file:dir r_dir_perms;
-
 # Write to /cache.
 allow gmscore_app { cache_file cache_recovery_file }:dir create_dir_perms;
 allow gmscore_app { cache_file cache_recovery_file }:file create_file_perms;
@@ -161,6 +156,9 @@ get_prop(gmscore_app, remote_prov_prop)
 get_prop(gmscore_app, quick_start_prop)
 neverallow { domain -init -dumpstate -vendor_init -gmscore_app } quick_start_prop:file no_rw_file_perms;
 
+# Allow GmsCore to read Bluetotoh Power Off Finder property
+get_prop(gmscore_app, bluetooth_finder_prop)
+
 # Do not allow getting permission-protected network information from sysfs.
 neverallow gmscore_app sysfs_net:file *;
 
diff --git a/private/hal_bluetooth.te b/private/hal_bluetooth.te
index 53bbef246..2e03ea28a 100644
--- a/private/hal_bluetooth.te
+++ b/private/hal_bluetooth.te
@@ -24,6 +24,7 @@ allow hal_bluetooth self:global_capability2_class_set wake_alarm;
 # Allow write access to bluetooth-specific properties
 set_prop(hal_bluetooth, bluetooth_a2dp_offload_prop)
 set_prop(hal_bluetooth, bluetooth_audio_hal_prop)
+set_prop(hal_bluetooth, bluetooth_finder_prop)
 set_prop(hal_bluetooth, bluetooth_prop)
 set_prop(hal_bluetooth, exported_bluetooth_prop)
 
diff --git a/private/hal_face.te b/private/hal_face.te
index e14666a84..5e4395354 100644
--- a/private/hal_face.te
+++ b/private/hal_face.te
@@ -11,5 +11,5 @@ binder_use(hal_face_server)
 allow hal_face ion_device:chr_file r_file_perms;
 
 # Allow read/write access to the face template directory.
-allow hal_face face_vendor_data_file:file create_file_perms;
-allow hal_face face_vendor_data_file:dir rw_dir_perms;
+allow {hal_face -coredomain} face_vendor_data_file:file create_file_perms;
+allow {hal_face -coredomain} face_vendor_data_file:dir rw_dir_perms;
diff --git a/private/hal_fingerprint.te b/private/hal_fingerprint.te
index 29abe4f50..3295cc7fb 100644
--- a/private/hal_fingerprint.te
+++ b/private/hal_fingerprint.te
@@ -10,11 +10,11 @@ binder_use(hal_fingerprint_server)
 # For memory allocation
 allow hal_fingerprint ion_device:chr_file r_file_perms;
 
-allow hal_fingerprint fingerprint_vendor_data_file:file { create_file_perms };
-allow hal_fingerprint fingerprint_vendor_data_file:dir rw_dir_perms;
+allow { hal_fingerprint -coredomain } fingerprint_vendor_data_file:file { create_file_perms };
+allow { hal_fingerprint -coredomain } fingerprint_vendor_data_file:dir rw_dir_perms;
 
 r_dir_file(hal_fingerprint, cgroup)
 r_dir_file(hal_fingerprint, cgroup_v2)
-r_dir_file(hal_fingerprint, sysfs)
+r_dir_file({hal_fingerprint -coredomain}, sysfs)
 
 
diff --git a/private/hal_keymint.te b/private/hal_keymint.te
index ba2995628..6c7b57727 100644
--- a/private/hal_keymint.te
+++ b/private/hal_keymint.te
@@ -4,5 +4,5 @@ hal_attribute_service(hal_keymint, hal_keymint_service)
 hal_attribute_service(hal_keymint, hal_remotelyprovisionedcomponent_service)
 binder_call(hal_keymint_server, servicemanager)
 
-allow hal_keymint_server tee_device:chr_file rw_file_perms;
-allow hal_keymint_server ion_device:chr_file r_file_perms;
+allow { hal_keymint_server -coredomain } tee_device:chr_file rw_file_perms;
+allow { hal_keymint_server -coredomain } ion_device:chr_file r_file_perms;
diff --git a/private/hal_keymint_system.te b/private/hal_keymint_system.te
new file mode 100644
index 000000000..0a20870ac
--- /dev/null
+++ b/private/hal_keymint_system.te
@@ -0,0 +1,7 @@
+type hal_keymint_system, domain, coredomain;
+hal_server_domain(hal_keymint_system, hal_keymint)
+
+type hal_keymint_system_exec, exec_type, system_file_type, file_type;
+init_daemon_domain(hal_keymint_system)
+
+allow hal_keymint_system self:vsock_socket { create_socket_perms_no_ioctl };
diff --git a/private/hal_neverallows.te b/private/hal_neverallows.te
index 6730c322d..356288851 100644
--- a/private/hal_neverallows.te
+++ b/private/hal_neverallows.te
@@ -12,6 +12,7 @@ neverallow {
   # TODO(b/196225233): Remove hal_uwb_vendor_server
   -hal_uwb_vendor_server
   -hal_nlinterceptor_server
+  -hal_tv_tuner_server
 } self:global_capability_class_set { net_admin net_raw };
 
 # Unless a HAL's job is to communicate over the network, or control network
@@ -34,6 +35,7 @@ neverallow {
   -hal_uwb_vendor_server
   -hal_nlinterceptor_server
   -hal_bluetooth_server
+  -hal_tv_tuner_server
 } domain:{ udp_socket rawip_socket } *;
 
 neverallow {
@@ -47,6 +49,7 @@ neverallow {
   -hal_telephony_server
   -hal_nlinterceptor_server
   -hal_bluetooth_server
+  -hal_tv_tuner_server
 } {
   domain
   userdebug_or_eng(`-su')
diff --git a/private/init.te b/private/init.te
index e4bafd83d..73ab049cd 100644
--- a/private/init.te
+++ b/private/init.te
@@ -82,6 +82,9 @@ allow init vd_device:blk_file relabelto;
 set_prop(init, init_perf_lsm_hooks_prop)
 set_prop(init, vts_status_prop)
 
+# Allow init to set 16kb app compatibility props
+set_prop(init, bionic_linker_16kb_app_compat_prop)
+
 # Allow accessing /sys/kernel/tracing/instances/bootreceiver to set up tracing.
 allow init debugfs_bootreceiver_tracing:file w_file_perms;
 
@@ -115,6 +118,8 @@ allow init kmsg_device:chr_file { getattr write relabelto };
 userdebug_or_eng(`
   allow init kmsg_debug_device:chr_file { open write relabelto };
 ')
+# /mnt/vm, also permissions to mkdir / mount / chmod / chown
+allow init vm_data_file:dir { add_name create search write getattr setattr relabelto mounton };
 
 # allow init to mount and unmount debugfs in debug builds
 userdebug_or_eng(`
@@ -305,6 +310,7 @@ allow init {
     -storage_area_app_dir
     -storage_area_content_file
   ')
+  -vm_data_file
   -bpffs_type
   -exec_type
   -misc_logd_file
@@ -324,6 +330,7 @@ allow init {
     -storage_area_app_dir
     -storage_area_content_file
   ')
+  -vm_data_file
   -bpffs_type
   -credstore_data_file
   -exec_type
@@ -351,6 +358,7 @@ allow init {
     -storage_area_app_dir
     -storage_area_content_file
   ')
+  -vm_data_file
   -bpffs_type
   -exec_type
   -gsi_data_file
@@ -383,6 +391,7 @@ allow init {
     -storage_area_app_dir
     -storage_area_content_file
   ')
+  -vm_data_file
   -bpffs_type
   -exec_type
   -gsi_data_file
@@ -408,6 +417,7 @@ allow init {
     -storage_area_app_dir
     -storage_area_content_file
   ')
+  -vm_data_file
   -bpffs_type
   -exec_type
   -gsi_data_file
@@ -439,6 +449,7 @@ allow init {
     -storage_area_app_dir
     -storage_area_content_file
   ')
+  -vm_data_file
   -privapp_data_file
 }:dir_file_class_set relabelto;
 
diff --git a/private/installd.te b/private/installd.te
index 742c89733..55e962a4d 100644
--- a/private/installd.te
+++ b/private/installd.te
@@ -9,9 +9,6 @@ allow installd shell_exec:file rx_file_perms;
 # Run dex2oat in its own sandbox.
 domain_auto_trans(installd, dex2oat_exec, dex2oat)
 
-# Run dexoptanalyzer in its own sandbox.
-domain_auto_trans(installd, dexoptanalyzer_exec, dexoptanalyzer)
-
 # Run profman in its own sandbox.
 domain_auto_trans(installd, profman_exec, profman)
 
@@ -44,11 +41,6 @@ get_prop(installd, odsign_prop)
 allow installd staging_data_file:file unlink;
 allow installd staging_data_file:dir { open read add_name remove_name rename rmdir search write getattr };
 
-allow installd { dex2oat dexoptanalyzer }:process signal;
-
-# installd kills subprocesses if they time out.
-allow installd { dex2oat dexoptanalyzer profman }:process sigkill;
-
 # Allow installd manage dirs in /data/misc_ce/0/sdksandbox
 allow installd sdk_sandbox_system_data_file:dir { create_dir_perms relabelfrom };
 
diff --git a/private/isolated_app_all.te b/private/isolated_app_all.te
index 8c1fdcbf7..43f1ac656 100644
--- a/private/isolated_app_all.te
+++ b/private/isolated_app_all.te
@@ -32,8 +32,8 @@ allow isolated_app_all app_zygote:unix_dgram_socket write;
 # suppress denials to /data/local/tmp
 dontaudit isolated_app_all shell_data_file:dir search;
 
-# Allow to read (but not open) staged apks.
-allow isolated_app_all { apk_tmp_file apk_private_tmp_file }:file { read getattr };
+# Allow to read, map (but not open) staged apks.
+allow isolated_app_all { apk_tmp_file apk_private_tmp_file }:file { read getattr map };
 
 #####
 ##### Neverallow
@@ -70,7 +70,7 @@ neverallow { isolated_app_all -isolated_compute_app } {
 }:service_manager find;
 
 # Isolated apps shouldn't be able to access the driver directly.
-neverallow isolated_app_all gpu_device:chr_file { rw_file_perms execute };
+neverallow { isolated_app_all -isolated_compute_app } gpu_device:chr_file { rw_file_perms execute };
 
 # Do not allow isolated_apps access to /cache
 neverallow isolated_app_all cache_file:dir ~{ r_dir_perms };
diff --git a/private/isolated_compute_app.te b/private/isolated_compute_app.te
index 5d4070d6c..f34850e45 100644
--- a/private/isolated_compute_app.te
+++ b/private/isolated_compute_app.te
@@ -32,6 +32,12 @@ allow isolated_compute_app { ephemeral_app priv_app untrusted_app_all }:{ tcp_so
 # Allow access to the toybox: b/275024392
 allow isolated_compute_app toolbox_exec:file rx_file_perms;
 
+# Grant GPU access to isolated_compute_app as it is required for acceleration.
+allow isolated_compute_app gpu_device:chr_file rw_file_perms;
+allow isolated_compute_app gpu_device:dir r_dir_perms;
+allow isolated_compute_app sysfs_gpu:file r_file_perms;
+
+
 #####
 ##### Neverallow
 #####
diff --git a/private/lmkd.te b/private/lmkd.te
index 5369c7990..97dc398b8 100644
--- a/private/lmkd.te
+++ b/private/lmkd.te
@@ -19,9 +19,9 @@ allow lmkd self:perf_event { cpu kernel open write };
 allow lmkd fs_bpf:file read;
 allow lmkd bpfloader:bpf { map_read map_write prog_run };
 
-# Needed for polling directly from the bpf ring buffer's fd
-allow lmkd fs_bpf_lmkd_memevents_rb:file { read write };
-allow lmkd fs_bpf_lmkd_memevents_prog:file read;
+# Needed to interact with memevents-eBPF and receive notifications for memory events
+allow lmkd fs_bpf_memevents:file { read write };
+allow lmkd fs_bpf_memevents:dir search;
 
 allow lmkd self:global_capability_class_set { dac_override dac_read_search sys_resource kill };
 
@@ -86,9 +86,6 @@ allow lmkd lmkd_socket:sock_file write;
 # Allow lmkd to write to statsd.
 unix_socket_send(lmkd, statsdw, statsd)
 
-# Allow lmkd to create io_uring
-allow lmkd self:anon_inode { create map read write };
-
 ### neverallow rules
 
 # never honor LD_PRELOAD
diff --git a/private/microfuchsiad.te b/private/microfuchsiad.te
new file mode 100644
index 000000000..f02acaf30
--- /dev/null
+++ b/private/microfuchsiad.te
@@ -0,0 +1,18 @@
+is_flag_enabled(RELEASE_AVF_ENABLE_MICROFUCHSIA, `
+    type microfuchsiad, domain, coredomain;
+    type microfuchsiad_exec, system_file_type, exec_type, file_type;
+
+    # Host dynamic AIDL services
+    init_daemon_domain(microfuchsiad)
+    binder_use(microfuchsiad)
+    add_service(microfuchsiad, microfuchsia_service)
+
+    # Call back into system server
+    binder_call(microfuchsiad, system_server)
+
+    # Start a VM
+    virtualizationservice_use(microfuchsiad)
+
+    # Create pty devices
+    allow microfuchsiad devpts:chr_file { read write open getattr ioctl };
+')
diff --git a/private/netd.te b/private/netd.te
index 37581a699..8b6ea4c77 100644
--- a/private/netd.te
+++ b/private/netd.te
@@ -79,13 +79,6 @@ allow netd devpts:chr_file rw_file_perms;
 allow netd system_file:file lock;
 dontaudit netd system_file:dir write;
 
-# Allow netd to write to qtaguid ctrl file.
-# TODO: Add proper rules to prevent other process to access qtaguid_proc file
-# after migration complete
-allow netd proc_qtaguid_ctrl:file rw_file_perms;
-# Allow netd to read /dev/qtaguid. This is the same privilege level that normal apps have.
-allow netd qtaguid_device:chr_file r_file_perms;
-
 r_dir_file(netd, proc_net_type)
 # For /proc/sys/net/ipv[46]/route/flush.
 allow netd proc_net_type:file rw_file_perms;
diff --git a/private/odrefresh.te b/private/odrefresh.te
index 899b0d9e1..97205c25f 100644
--- a/private/odrefresh.te
+++ b/private/odrefresh.te
@@ -1,5 +1,5 @@
 # odrefresh
-type odrefresh, domain, coredomain;
+type odrefresh, domain, coredomain, artd_subprocess_type;
 type odrefresh_exec, system_file_type, exec_type, file_type;
 
 # Allow odrefresh to create files and directories for on device signing.
@@ -24,12 +24,6 @@ domain_auto_trans(odrefresh, dex2oat_exec, dex2oat)
 # Allow odrefresh to kill dex2oat if compilation times out.
 allow odrefresh dex2oat:process sigkill;
 
-# Run dexoptanalyzer in its own sandbox.
-domain_auto_trans(odrefresh, dexoptanalyzer_exec, dexoptanalyzer)
-
-# Allow odrefresh to kill dexoptanalyzer if analysis times out.
-allow odrefresh dexoptanalyzer:process sigkill;
-
 # Use devpts and fd from odsign (which exec()'s odrefresh)
 allow odrefresh odsign_devpts:chr_file { read write };
 allow odrefresh odsign:fd use;
diff --git a/private/otapreopt_chroot.te b/private/otapreopt_chroot.te
index 73e170b30..2aeab0bcb 100644
--- a/private/otapreopt_chroot.te
+++ b/private/otapreopt_chroot.te
@@ -1,4 +1,5 @@
 # otapreopt_chroot executable
+starting_at_board_api(202504, `type otapreopt_chroot, domain;')
 typeattribute otapreopt_chroot coredomain;
 type otapreopt_chroot_exec, exec_type, file_type, system_file_type;
 
diff --git a/private/platform_app.te b/private/platform_app.te
index eb1a7c75e..320624cdb 100644
--- a/private/platform_app.te
+++ b/private/platform_app.te
@@ -51,6 +51,7 @@ userdebug_or_eng(`
 userdebug_or_eng(`
   set_prop(platform_app, persist_sysui_ranking_update_prop)
 ')
+set_prop(platform_app, debug_tracing_desktop_mode_visible_tasks_prop)
 
 # com.android.captiveportallogin reads /proc/vmstat
 allow platform_app {
diff --git a/private/profman.te b/private/profman.te
index af5364628..d1ce92652 100644
--- a/private/profman.te
+++ b/private/profman.te
@@ -1,10 +1,12 @@
 typeattribute profman coredomain;
+typeattribute profman artd_subprocess_type;
 
 # Allow profman to read APKs and profile files next to them by FDs passed from
 # other programs. In addition, allow profman to acquire flocks on those files.
 allow profman {
   system_file
   apk_data_file
+  apk_tmp_file
   vendor_app_file
 }:file { getattr read map lock };
 
@@ -22,6 +24,7 @@ allow profman user_profile_data_file:file { getattr read write lock map };
 allow profman asec_apk_file:file { read map };
 allow profman apk_data_file:file { getattr read map };
 allow profman apk_data_file:dir { getattr read search };
+allow profman apk_tmp_file:dir { getattr read search };
 
 allow profman oemfs:file { read map };
 # Reading an APK opens a ZipArchive, which unpack to tmpfs.
diff --git a/private/property.te b/private/property.te
index 19513d93f..8cc91e423 100644
--- a/private/property.te
+++ b/private/property.te
@@ -3,6 +3,7 @@ system_internal_prop(adbd_prop)
 system_internal_prop(apexd_payload_metadata_prop)
 system_internal_prop(ctl_snapuserd_prop)
 system_internal_prop(crashrecovery_prop)
+system_internal_prop(debug_tracing_desktop_mode_visible_tasks_prop)
 system_internal_prop(device_config_core_experiments_team_internal_prop)
 system_internal_prop(device_config_lmkd_native_prop)
 system_internal_prop(device_config_mglru_native_prop)
@@ -66,16 +67,34 @@ system_internal_prop(hypervisor_virtualizationmanager_prop)
 system_internal_prop(game_manager_config_prop)
 system_internal_prop(hidl_memory_prop)
 system_internal_prop(suspend_debug_prop)
+system_internal_prop(system_service_enable_prop)
+system_internal_prop(ctl_artd_pre_reboot_prop)
+
 
 # Properties which can't be written outside system
+system_restricted_prop(bionic_linker_16kb_app_compat_prop)
 system_restricted_prop(device_config_virtualization_framework_native_prop)
 system_restricted_prop(fstype_prop)
 system_restricted_prop(log_file_logger_prop)
 system_restricted_prop(persist_sysui_builder_extras_prop)
 system_restricted_prop(persist_sysui_ranking_update_prop)
+system_restricted_prop(page_size_prop)
+
+# Properties with no restrictions
+until_board_api(202504, `
+    system_public_prop(bluetooth_finder_prop)
+    system_public_prop(virtual_fingerprint_prop)
+')
+
+# These types will be public starting at board api 202504
+until_board_api(202504, `
+    system_restricted_prop(enable_16k_pages_prop)
+    system_restricted_prop(profcollectd_etr_prop)
+')
 
 # Properties which should only be written by vendor_init
 system_vendor_config_prop(avf_virtualizationservice_prop)
+system_vendor_config_prop(high_barometer_quality_prop)
 
 typeattribute log_prop log_property_type;
 typeattribute log_tag_prop log_property_type;
@@ -423,6 +442,14 @@ compatible_property_only(`
     suspend_debug_prop
   }:property_service set;
 
+  neverallow {
+    domain
+    -init
+    -vendor_init
+  } {
+    high_barometer_quality_prop
+    }:property_service set;
+
   neverallow {
     domain
     -init
@@ -749,7 +776,9 @@ neverallow domain system_and_vendor_property_type:{file property_service} *;
 neverallow {
   domain
   -init
+  -keystore
   -shell
+  -system_server
   -rkpdapp
 } remote_prov_prop:property_service set;
 
@@ -819,3 +848,9 @@ neverallow {
   -init
   -vendor_init
 } pm_archiving_enabled_prop:property_service set;
+
+neverallow {
+  domain
+  -init
+  userdebug_or_eng(`-su')
+} bionic_linker_16kb_app_compat_prop:property_service set;
diff --git a/private/property_contexts b/private/property_contexts
index 9b48082e2..13dff313d 100644
--- a/private/property_contexts
+++ b/private/property_contexts
@@ -33,6 +33,7 @@ bluetooth.              u:object_r:bluetooth_prop:s0
 
 debug.                  u:object_r:debug_prop:s0
 debug.db.               u:object_r:debuggerd_prop:s0
+debug.tracing.desktop_mode_visible_tasks u:object_r:debug_tracing_desktop_mode_visible_tasks_prop:s0 exact uint
 dumpstate.              u:object_r:dumpstate_prop:s0
 dumpstate.options       u:object_r:dumpstate_options_prop:s0
 init.svc_debug_pid.     u:object_r:init_svc_debug_prop:s0
@@ -201,6 +202,11 @@ ctl.start$snapuserd     u:object_r:ctl_snapuserd_prop:s0
 ctl.stop$snapuserd      u:object_r:ctl_snapuserd_prop:s0
 ctl.restart$snapuserd   u:object_r:ctl_snapuserd_prop:s0
 
+# Restrict access to starting/stopping artd_pre_reboot.
+ctl.start$artd_pre_reboot          u:object_r:ctl_artd_pre_reboot_prop:s0
+ctl.stop$artd_pre_reboot           u:object_r:ctl_artd_pre_reboot_prop:s0
+ctl.restart$artd_pre_reboot        u:object_r:ctl_artd_pre_reboot_prop:s0
+
 # NFC properties
 nfc.                    u:object_r:nfc_prop:s0
 
@@ -313,6 +319,7 @@ apexd.config.dm_delete.timeout           u:object_r:apexd_config_prop:s0 exact u
 apexd.config.dm_create.timeout           u:object_r:apexd_config_prop:s0 exact uint
 apexd.config.loop_wait.attempts          u:object_r:apexd_config_prop:s0 exact uint
 apexd.config.boot_activation.threads     u:object_r:apexd_config_prop:s0 exact uint
+apexd.config.loopback.readahead          u:object_r:apexd_config_prop:s0 exact uint
 persist.apexd.          u:object_r:apexd_prop:s0
 persist.vendor.apex.    u:object_r:apexd_select_prop:s0
 ro.boot.vendor.apex.    u:object_r:apexd_select_prop:s0
@@ -361,7 +368,7 @@ ro.virtual_ab.num_worker_threads u:object_r:virtual_ab_prop:s0 exact int
 ro.virtual_ab.num_merge_threads u:object_r:virtual_ab_prop:s0 exact int
 ro.virtual_ab.num_verify_threads u:object_r:virtual_ab_prop:s0 exact int
 ro.virtual_ab.cow_op_merge_size u:object_r:virtual_ab_prop:s0 exact int
-ro.virtual_ab.verify_threshold_block_size u:object_r:virtual_ab_prop:s0 exact int
+ro.virtual_ab.verify_threshold_size u:object_r:virtual_ab_prop:s0 exact int
 ro.virtual_ab.verify_block_size u:object_r:virtual_ab_prop:s0 exact int
 
 # OEMs can set this prop at build time to configure how many seconds to delay
@@ -408,6 +415,11 @@ audio.deep_buffer.media         u:object_r:audio_config_prop:s0 exact bool
 audio.offload.video             u:object_r:audio_config_prop:s0 exact bool
 audio.offload.min.duration.secs u:object_r:audio_config_prop:s0 exact int
 
+# Timecheck configuration
+audio.timecheck.disabled                  u:object_r:audio_config_prop:s0 exact bool
+audio.timecheck.timeout_duration_ms       u:object_r:audio_config_prop:s0 exact int
+audio.timecheck.second_chance_duration_ms u:object_r:audio_config_prop:s0 exact int
+
 # spatializer tuning
 audio.spatializer.priority               u:object_r:audio_config_prop:s0 exact int
 audio.spatializer.effect.affinity        u:object_r:audio_config_prop:s0 exact int
@@ -415,6 +427,9 @@ audio.spatializer.effect.util_clamp_min  u:object_r:audio_config_prop:s0 exact i
 audio.spatializer.pose_predictor_type    u:object_r:audio_config_prop:s0 exact enum 0 1 2 3
 audio.spatializer.prediction_duration_ms u:object_r:audio_config_prop:s0 exact int
 
+# Timestamp correction for MSD
+audio.timestamp.corrected_output_device  u:object_r:audio_config_prop:s0 exact int
+
 ro.audio.ignore_effects   u:object_r:audio_config_prop:s0 exact bool
 ro.audio.monitorRotation  u:object_r:audio_config_prop:s0 exact bool
 ro.audio.offload_wakelock u:object_r:audio_config_prop:s0 exact bool
@@ -573,6 +588,7 @@ persist.bluetooth.bluetooth_audio_hal.disabled              u:object_r:bluetooth
 persist.bluetooth.btsnoopenable                             u:object_r:exported_bluetooth_prop:s0 exact bool
 persist.bluetooth.btsnoopdefaultmode                        u:object_r:bluetooth_prop:s0 exact enum empty disabled filtered full
 persist.bluetooth.btsnooplogmode                            u:object_r:bluetooth_prop:s0 exact enum empty disabled filtered full
+persist.bluetooth.finder.supported                          u:object_r:bluetooth_finder_prop:s0 exact bool
 persist.bluetooth.snooplogfilter.headers.enabled            u:object_r:bluetooth_prop:s0 exact bool
 persist.bluetooth.snooplogfilter.profiles.a2dp.enabled      u:object_r:bluetooth_prop:s0 exact bool
 persist.bluetooth.snooplogfilter.profiles.map               u:object_r:bluetooth_prop:s0 exact enum empty disabled fullfilter header magic
@@ -657,6 +673,7 @@ bluetooth.core.le.inquiry_scan_interval              u:object_r:bluetooth_config
 bluetooth.core.le.inquiry_scan_window                u:object_r:bluetooth_config_prop:s0 exact uint
 
 bluetooth.core.le.vendor_capabilities.enabled        u:object_r:bluetooth_config_prop:s0 exact bool
+bluetooth.hfp.software_datapath.enabled              u:object_r:bluetooth_config_prop:s0 exact bool
 bluetooth.sco.disable_enhanced_connection            u:object_r:bluetooth_config_prop:s0 exact bool
 bluetooth.sco.managed_by_audio                       u:object_r:bluetooth_config_prop:s0 exact bool
 bluetooth.core.le.dsa_transport_preference           u:object_r:bluetooth_config_prop:s0 exact string
@@ -1022,6 +1039,9 @@ ro.actionable_compatible_property.enabled u:object_r:build_prop:s0 exact bool
 # Property for enabling 16k pages developer option.
 ro.product.build.16k_page.enabled u:object_r:enable_16k_pages_prop:s0 exact bool
 
+# Property that indicates which page size the device boots by default.
+ro.product.page_size u:object_r:page_size_prop:s0 exact int
+
 ro.debuggable       u:object_r:userdebug_or_eng_prop:s0 exact bool
 ro.force.debuggable u:object_r:build_prop:s0 exact bool
 
@@ -1255,6 +1275,8 @@ ro.bionic.2nd_cpu_variant u:object_r:cpu_variant_prop:s0 exact string
 ro.bionic.arch            u:object_r:cpu_variant_prop:s0 exact string
 ro.bionic.cpu_variant     u:object_r:cpu_variant_prop:s0 exact string
 
+bionic.linker.16kb.app_compat.enabled u:object_r:bionic_linker_16kb_app_compat_prop:s0 exact bool
+
 ro.board.platform u:object_r:exported_default_prop:s0 exact string
 
 ro.boot.fake_battery         u:object_r:exported_default_prop:s0 exact int
@@ -1590,6 +1612,7 @@ persist.rollback.is_test u:object_r:rollback_test_prop:s0 exact bool
 
 # bootanimation properties
 ro.bootanim.quiescent.enabled u:object_r:bootanim_config_prop:s0 exact bool
+ro.product.bootanim.file u:object_r:bootanim_config_prop:s0 exact string
 
 # dck properties
 ro.gms.dck.eligible_wcc u:object_r:dck_prop:s0 exact int
@@ -1627,32 +1650,32 @@ vendor.face.virtual.operation_enroll_latency u:object_r:virtual_face_hal_prop:s0
 vendor.face.virtual.operation_authenticate_duration u:object_r:virtual_face_hal_prop:s0 exact int
 
 # properties for the virtual Fingerprint HAL
-persist.vendor.fingerprint.virtual.type u:object_r:virtual_fingerprint_hal_prop:s0 exact string
-persist.vendor.fingerprint.virtual.enrollments u:object_r:virtual_fingerprint_hal_prop:s0 exact string
-persist.vendor.fingerprint.virtual.lockout u:object_r:virtual_fingerprint_hal_prop:s0 exact bool
-persist.vendor.fingerprint.virtual.authenticator_id u:object_r:virtual_fingerprint_hal_prop:s0 exact int
-persist.vendor.fingerprint.virtual.sensor_location u:object_r:virtual_fingerprint_hal_prop:s0 exact string
-persist.vendor.fingerprint.virtual.sensor_id u:object_r:virtual_fingerprint_hal_prop:s0 exact int
-persist.vendor.fingerprint.virtual.sensor_strength u:object_r:virtual_fingerprint_hal_prop:s0 exact int
-persist.vendor.fingerprint.virtual.max_enrollments u:object_r:virtual_fingerprint_hal_prop:s0 exact int
-persist.vendor.fingerprint.virtual.navigation_guesture u:object_r:virtual_fingerprint_hal_prop:s0 exact bool
-persist.vendor.fingerprint.virtual.detect_interaction u:object_r:virtual_fingerprint_hal_prop:s0 exact bool
-persist.vendor.fingerprint.virtual.udfps.display_touch u:object_r:virtual_fingerprint_hal_prop:s0 exact bool
-persist.vendor.fingerprint.virtual.udfps.control_illumination u:object_r:virtual_fingerprint_hal_prop:s0 exact bool
-persist.vendor.fingerprint.virtual.lockout_enable u:object_r:virtual_fingerprint_hal_prop:s0 exact bool
-persist.vendor.fingerprint.virtual.lockout_timed_threshold u:object_r:virtual_fingerprint_hal_prop:s0 exact int
-persist.vendor.fingerprint.virtual.lockout_timed_duration u:object_r:virtual_fingerprint_hal_prop:s0 exact int
-persist.vendor.fingerprint.virtual.lockout_permanent_threshold u:object_r:virtual_fingerprint_hal_prop:s0 exact int
-vendor.fingerprint.virtual.enrollment_hit u:object_r:virtual_fingerprint_hal_prop:s0 exact int
-vendor.fingerprint.virtual.next_enrollment u:object_r:virtual_fingerprint_hal_prop:s0 exact string
-vendor.fingerprint.virtual.challenge u:object_r:virtual_fingerprint_hal_prop:s0 exact int
-vendor.fingerprint.virtual.operation_authenticate_fails u:object_r:virtual_fingerprint_hal_prop:s0 exact bool
-vendor.fingerprint.virtual.operation_detect_interaction_fails u:object_r:virtual_fingerprint_hal_prop:s0 exact bool
-vendor.fingerprint.virtual.operation_enroll_fails u:object_r:virtual_fingerprint_hal_prop:s0 exact bool
-vendor.fingerprint.virtual.operation_authenticate_latency u:object_r:virtual_fingerprint_hal_prop:s0 exact string
-vendor.fingerprint.virtual.operation_detect_interaction_latency u:object_r:virtual_fingerprint_hal_prop:s0 exact string
-vendor.fingerprint.virtual.operation_enroll_latency u:object_r:virtual_fingerprint_hal_prop:s0 exact string
-vendor.fingerprint.virtual.operation_authenticate_duration u:object_r:virtual_fingerprint_hal_prop:s0 exact int
+persist.vendor.fingerprint.virtual.type u:object_r:virtual_fingerprint_prop:s0 exact string
+persist.vendor.fingerprint.virtual.enrollments u:object_r:virtual_fingerprint_prop:s0 exact string
+persist.vendor.fingerprint.virtual.lockout u:object_r:virtual_fingerprint_prop:s0 exact bool
+persist.vendor.fingerprint.virtual.authenticator_id u:object_r:virtual_fingerprint_prop:s0 exact int
+persist.vendor.fingerprint.virtual.sensor_location u:object_r:virtual_fingerprint_prop:s0 exact string
+persist.vendor.fingerprint.virtual.sensor_id u:object_r:virtual_fingerprint_prop:s0 exact int
+persist.vendor.fingerprint.virtual.sensor_strength u:object_r:virtual_fingerprint_prop:s0 exact int
+persist.vendor.fingerprint.virtual.max_enrollments u:object_r:virtual_fingerprint_prop:s0 exact int
+persist.vendor.fingerprint.virtual.navigation_guesture u:object_r:virtual_fingerprint_prop:s0 exact bool
+persist.vendor.fingerprint.virtual.detect_interaction u:object_r:virtual_fingerprint_prop:s0 exact bool
+persist.vendor.fingerprint.virtual.udfps.display_touch u:object_r:virtual_fingerprint_prop:s0 exact bool
+persist.vendor.fingerprint.virtual.udfps.control_illumination u:object_r:virtual_fingerprint_prop:s0 exact bool
+persist.vendor.fingerprint.virtual.lockout_enable u:object_r:virtual_fingerprint_prop:s0 exact bool
+persist.vendor.fingerprint.virtual.lockout_timed_threshold u:object_r:virtual_fingerprint_prop:s0 exact int
+persist.vendor.fingerprint.virtual.lockout_timed_duration u:object_r:virtual_fingerprint_prop:s0 exact int
+persist.vendor.fingerprint.virtual.lockout_permanent_threshold u:object_r:virtual_fingerprint_prop:s0 exact int
+vendor.fingerprint.virtual.enrollment_hit u:object_r:virtual_fingerprint_prop:s0 exact int
+vendor.fingerprint.virtual.next_enrollment u:object_r:virtual_fingerprint_prop:s0 exact string
+vendor.fingerprint.virtual.challenge u:object_r:virtual_fingerprint_prop:s0 exact int
+vendor.fingerprint.virtual.operation_authenticate_fails u:object_r:virtual_fingerprint_prop:s0 exact bool
+vendor.fingerprint.virtual.operation_detect_interaction_fails u:object_r:virtual_fingerprint_prop:s0 exact bool
+vendor.fingerprint.virtual.operation_enroll_fails u:object_r:virtual_fingerprint_prop:s0 exact bool
+vendor.fingerprint.virtual.operation_authenticate_latency u:object_r:virtual_fingerprint_prop:s0 exact string
+vendor.fingerprint.virtual.operation_detect_interaction_latency u:object_r:virtual_fingerprint_prop:s0 exact string
+vendor.fingerprint.virtual.operation_enroll_latency u:object_r:virtual_fingerprint_prop:s0 exact string
+vendor.fingerprint.virtual.operation_authenticate_duration u:object_r:virtual_fingerprint_prop:s0 exact int
 
 # properties for tuner
 ro.tuner.lazyhal    u:object_r:tuner_config_prop:s0 exact bool
@@ -1675,6 +1698,10 @@ ro.quick_start.device_id u:object_r:quick_start_prop:s0 exact string
 # Properties for sensor service
 sensors.aosp_low_power_sensor_fusion.maximum_rate u:object_r:sensors_config_prop:s0 exact uint
 
+# Whether the device has a high quality barometer as defined on the CDD.
+# Set by OEMs, read for xTS verifier tests
+sensor.barometer.high_quality.implemented  u:object_r:high_barometer_quality_prop:s0 exact bool
+
 # Properties for game manager service
 persist.graphics.game_default_frame_rate.enabled  u:object_r:game_manager_config_prop:s0 exact bool
 
@@ -1695,3 +1722,7 @@ persist.crashrecovery.last_factory_reset u:object_r:crashrecovery_prop:s0 exact
 # Properties for controlling snapshotctl.
 sys.snapshotctl.map u:object_r:snapshotctl_prop:s0 exact string
 sys.snapshotctl.unmap u:object_r:snapshotctl_prop:s0 exact string
+
+# Properties for enabling/disabling system services
+ro.system_settings.service.odp_enabled   u:object_r:system_service_enable_prop:s0 exact bool
+ro.system_settings.service.backgound_install_control_enabled   u:object_r:system_service_enable_prop:s0 exact bool
diff --git a/private/seapp_contexts b/private/seapp_contexts
index a07d27219..0b857dede 100644
--- a/private/seapp_contexts
+++ b/private/seapp_contexts
@@ -121,9 +121,6 @@
 # levelFrom=app or levelFrom=all is only supported for _app UIDs.
 # level may be used to specify a fixed level for any UID.
 #
-# For backwards compatibility levelFromUid=true is equivalent to levelFrom=app
-# and levelFromUid=false is equivalent to levelFrom=none.
-#
 #
 # Neverallow Assertions
 # Additional compile time assertion checks for the rules in this file can be
@@ -226,3 +223,7 @@ user=_app minTargetSdkVersion=28 fromRunAs=true domain=runas_app levelFrom=all
 user=_app fromRunAs=true domain=runas_app levelFrom=user
 user=_app isPrivApp=true name=com.android.virtualization.vmlauncher domain=vmlauncher_app type=privapp_data_file levelFrom=all
 user=_app isPrivApp=true name=com.google.android.virtualization.vmlauncher domain=vmlauncher_app type=privapp_data_file levelFrom=all
+user=_app isPrivApp=true name=com.android.virtualization.terminal domain=vmlauncher_app type=privapp_data_file levelFrom=all
+user=_app isPrivApp=true name=com.google.android.virtualization.terminal domain=vmlauncher_app type=privapp_data_file levelFrom=all
+user=_app isPrivApp=true name=com.android.virtualization.linuxinstaller domain=ferrochrome_app type=privapp_data_file levelFrom=all
+user=_app isPrivApp=true name=com.android.virtualization.ferrochrome domain=ferrochrome_app type=privapp_data_file levelFrom=all
diff --git a/private/service.te b/private/service.te
index 1fb4d1d03..a4d00f36e 100644
--- a/private/service.te
+++ b/private/service.te
@@ -1,26 +1,36 @@
-type adaptive_auth_service,         system_server_service, service_manager_type;
-type ambient_context_service,       app_api_service, system_server_service, service_manager_type;
-type attention_service,             system_server_service, service_manager_type;
-type bg_install_control_service,    system_api_service, system_server_service, service_manager_type;
-type compos_service,                service_manager_type;
-type communal_service,              app_api_service, system_server_service, service_manager_type;
-type dynamic_system_service,        system_api_service, system_server_service, service_manager_type;
-type feature_flags_service,         app_api_service, system_server_service, service_manager_type;
-type gsi_service,                   service_manager_type;
-type incidentcompanion_service,     app_api_service, system_api_service, system_server_service, service_manager_type;
-type logcat_service,                system_server_service, service_manager_type;
-type logd_service,                  service_manager_type;
-type mediatuner_service,            app_api_service, service_manager_type;
+type adaptive_auth_service,          system_server_service, service_manager_type;
+type ambient_context_service,        app_api_service, system_server_service, service_manager_type;
+
+# These types will be public starting at board api 202504
+until_board_api(202504, `
+    type app_function_service, app_api_service, system_server_service, service_manager_type;
+')
+type attention_service,              system_server_service, service_manager_type;
+type bg_install_control_service,     system_api_service, system_server_service, service_manager_type;
+type compos_service,                 service_manager_type;
+type communal_service,               app_api_service, system_server_service, service_manager_type;
+type dynamic_system_service,         system_api_service, system_server_service, service_manager_type;
+type feature_flags_service,          app_api_service, system_server_service, service_manager_type;
+type gsi_service,                    service_manager_type;
+type incidentcompanion_service,      app_api_service, system_api_service, system_server_service, service_manager_type;
+type logcat_service,                 system_server_service, service_manager_type;
+type logd_service,                   service_manager_type;
+type mediatuner_service,             app_api_service, service_manager_type;
 type on_device_intelligence_service, app_api_service, system_server_service, service_manager_type, isolated_compute_allowed_service;
-type profcollectd_service,          service_manager_type;
-type resolver_service,              system_server_service, service_manager_type;
-type rkpd_registrar_service,        service_manager_type;
-type rkpd_refresh_service,          service_manager_type;
-type safety_center_service,         app_api_service, system_api_service, system_server_service, service_manager_type;
-type stats_service,                 service_manager_type;
-type statsbootstrap_service,        system_server_service, service_manager_type;
-type statscompanion_service,        system_server_service, service_manager_type;
-type statsmanager_service,          system_api_service, system_server_service, service_manager_type;
+type profcollectd_service,           service_manager_type;
+type protolog_configuration_service, app_api_service, system_api_service, system_server_service, service_manager_type;
+type resolver_service,               system_server_service, service_manager_type;
+type rkpd_registrar_service,         service_manager_type;
+type rkpd_refresh_service,           service_manager_type;
+type safety_center_service,          app_api_service, system_api_service, system_server_service, service_manager_type;
+type stats_service,                  service_manager_type;
+type statsbootstrap_service,         system_server_service, service_manager_type;
+type statscompanion_service,         system_server_service, service_manager_type;
+type statsmanager_service,           system_api_service, system_server_service, service_manager_type;
+
+is_flag_enabled(RELEASE_SUPERVISION_SERVICE, `
+    type supervision_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
+')
 type tracingproxy_service,          system_server_service, service_manager_type;
 type transparency_service,          system_server_service, service_manager_type;
 
@@ -31,7 +41,11 @@ is_flag_enabled(RELEASE_AVF_ENABLE_LLPVM_CHANGES, `
     type virtualization_maintenance_service, service_manager_type;
 ')
 is_flag_enabled(RELEASE_AVF_ENABLE_NETWORK, `
-    type vmnic_service, service_manager_type;
+    type vm_tethering_service, system_server_service, service_manager_type;
+    type vmnic_service,        service_manager_type;
+')
+is_flag_enabled(RELEASE_AVF_ENABLE_MICROFUCHSIA, `
+    type microfuchsia_service,          service_manager_type;
 ')
 
 type uce_service,                   service_manager_type;
diff --git a/private/service_contexts b/private/service_contexts
index c7917f121..aec4213df 100644
--- a/private/service_contexts
+++ b/private/service_contexts
@@ -26,8 +26,10 @@ android.hardware.automotive.remoteaccess.IRemoteAccess/default       u:object_r:
 android.hardware.automotive.vehicle.IVehicle/default                 u:object_r:hal_vehicle_service:s0
 android.hardware.biometrics.face.IFace/default                       u:object_r:hal_face_service:s0
 android.hardware.biometrics.face.IFace/virtual                       u:object_r:hal_face_service:s0
+android.hardware.biometrics.face.virtualhal.IVirtualHal/virtual      u:object_r:hal_face_service:s0
 android.hardware.biometrics.fingerprint.IFingerprint/default         u:object_r:hal_fingerprint_service:s0
 android.hardware.biometrics.fingerprint.IFingerprint/virtual         u:object_r:hal_fingerprint_service:s0
+android.hardware.biometrics.fingerprint.virtualhal.IVirtualHal/virtual u:object_r:hal_fingerprint_service:s0
 android.hardware.bluetooth.IBluetoothHci/default                     u:object_r:hal_bluetooth_service:s0
 android.hardware.bluetooth.finder.IBluetoothFinder/default           u:object_r:hal_bluetooth_service:s0
 is_flag_enabled(RELEASE_HARDWARE_BLUETOOTH_RANGING_SERVICE, `
@@ -172,9 +174,14 @@ is_flag_enabled(RELEASE_AVF_ENABLE_LLPVM_CHANGES, `
 ')
 is_flag_enabled(RELEASE_AVF_ENABLE_NETWORK, `
     android.system.virtualizationservice_internal.IVmnic u:object_r:vmnic_service:s0
+    android.system.vmtethering.IVmTethering              u:object_r:vm_tethering_service:s0
+')
+is_flag_enabled(RELEASE_AVF_ENABLE_MICROFUCHSIA, `
+    android.system.microfuchsiad              u:object_r:microfuchsia_service:s0
 ')
 ambient_context                           u:object_r:ambient_context_service:s0
 app_binding                               u:object_r:app_binding_service:s0
+app_function                              u:object_r:app_function_service:s0
 app_hibernation                           u:object_r:app_hibernation_service:s0
 app_integrity                             u:object_r:app_integrity_service:s0
 app_prediction                            u:object_r:app_prediction_service:s0
@@ -368,6 +375,7 @@ pinner                                    u:object_r:pinner_service:s0
 powerstats                                u:object_r:powerstats_service:s0
 power                                     u:object_r:power_service:s0
 profiling_service                         u:object_r:profiling_service:s0
+protolog_configuration                    u:object_r:protolog_configuration_service:s0
 print                                     u:object_r:print_service:s0
 processinfo                               u:object_r:processinfo_service:s0
 procstats                                 u:object_r:procstats_service:s0
@@ -375,6 +383,9 @@ profcollectd                              u:object_r:profcollectd_service:s0
 radio.phonesubinfo                        u:object_r:radio_service:s0
 radio.phone                               u:object_r:radio_service:s0
 radio.sms                                 u:object_r:radio_service:s0
+is_flag_enabled(RELEASE_RANGING_STACK, `
+    ranging                               u:object_r:ranging_service:s0
+')
 rcs                                       u:object_r:radio_service:s0
 reboot_readiness                          u:object_r:reboot_readiness_service:s0
 recovery                                  u:object_r:recovery_service:s0
@@ -425,6 +436,10 @@ storaged_pri                              u:object_r:storaged_service:s0
 storagestats                              u:object_r:storagestats_service:s0
 # sdk_sandbox here refers to the service name, not the domain name.
 sdk_sandbox                               u:object_r:sdk_sandbox_service:s0
+
+is_flag_enabled(RELEASE_SUPERVISION_SERVICE, `
+    supervision                               u:object_r:supervision_service:s0
+')
 SurfaceFlinger                            u:object_r:surfaceflinger_service:s0
 SurfaceFlingerAIDL                        u:object_r:surfaceflinger_service:s0
 suspend_control                           u:object_r:system_suspend_control_service:s0
diff --git a/private/servicemanager.te b/private/servicemanager.te
index 7a5bf5174..6764b451f 100644
--- a/private/servicemanager.te
+++ b/private/servicemanager.te
@@ -44,6 +44,8 @@ selinux_check_access(servicemanager)
 
 allow servicemanager kmsg_device:chr_file rw_file_perms;
 
+perfetto_producer(servicemanager)
+
 recovery_only(`
   # Read VINTF files.
   r_dir_file(servicemanager, rootfs)
diff --git a/private/shell.te b/private/shell.te
index e421ec6c0..18e346226 100644
--- a/private/shell.te
+++ b/private/shell.te
@@ -198,6 +198,14 @@ get_prop(shell, system_boot_reason_prop)
 
 # Allow shell to execute the remote key provisioning factory tool
 binder_call(shell, hal_keymint)
+# Allow shell to run the AVF RKP HAL during the execution of the remote key
+# provisioning factory tool.
+# TODO(b/351113293): Remove this once the AVF RKP HAL registration is moved to
+# a separate process.
+binder_call(shell, virtualizationservice)
+# Allow the shell to inspect whether AVF remote attestation is supported
+# through the system property.
+get_prop(shell, avf_virtualizationservice_prop)
 
 # Allow reading the outcome of perf_event_open LSM support test for CTS.
 get_prop(shell, init_perf_lsm_hooks_prop)
@@ -262,6 +270,7 @@ userdebug_or_eng(`set_prop(shell, persist_sysui_ranking_update_prop)')
 get_prop(shell, build_attestation_prop)
 
 # Allow shell to execute oatdump.
+# TODO (b/350628688): Remove this once it's safe to do so.
 allow shell oatdump_exec:file rx_file_perms;
 
 # Allow shell access to socket for test
@@ -359,6 +368,7 @@ allow shell {
   -virtual_touchpad_service
   -vold_service
   -default_android_service
+  -virtualization_service
 }:service_manager find;
 allow shell dumpstate:binder call;
 
@@ -468,6 +478,10 @@ allow shell sepolicy_file:file r_file_perms;
 # Allow shell to start up vendor shell
 allow shell vendor_shell_exec:file rx_file_perms;
 
+is_flag_enabled(RELEASE_AVF_SUPPORT_CUSTOM_VM_WITH_PARAVIRTUALIZED_DEVICES, `
+  allow shell custom_vm_setup_exec:file { entrypoint r_file_perms };
+')
+
 # Everything is labeled as rootfs in recovery mode. Allow shell to
 # execute them.
 recovery_only(`
@@ -484,6 +498,7 @@ neverallow shell {
   hal_keymint_service
   hal_secureclock_service
   hal_sharedsecret_service
+  virtualization_service
 }:service_manager find;
 
 # Do not allow shell to hard link to any files.
diff --git a/private/surfaceflinger.te b/private/surfaceflinger.te
index 91e9aba05..f6f1d9b97 100644
--- a/private/surfaceflinger.te
+++ b/private/surfaceflinger.te
@@ -85,6 +85,10 @@ perfetto_producer(surfaceflinger)
 # Use socket supplied by adbd, for cmd gpu vkjson etc.
 allow surfaceflinger adbd:unix_stream_socket { read write getattr };
 
+# Allow reading and writing to sockets used for BLAST buffer releases
+allow surfaceflinger { appdomain -isolated_app_all -ephemeral_app -sdk_sandbox_all }:unix_stream_socket { read write };
+allow surfaceflinger bootanim:unix_stream_socket { read write };
+
 # Allow a dumpstate triggered screenshot
 binder_call(surfaceflinger, dumpstate)
 binder_call(surfaceflinger, shell)
diff --git a/private/system_app.te b/private/system_app.te
index e0ed8c3e8..0b6ffe264 100644
--- a/private/system_app.te
+++ b/private/system_app.te
@@ -151,7 +151,7 @@ allow system_app {
   proc_version
 }:file r_file_perms;
 
-# Settings app writes to /dev/stune/foreground/tasks.
+# Allow system apps to modify cgroup attributes and migrate processes
 allow system_app cgroup:file w_file_perms;
 allow system_app cgroup_v2:file w_file_perms;
 allow system_app cgroup_v2:dir w_dir_perms;
diff --git a/private/system_server.te b/private/system_server.te
index e7ae9fc9a..fc4faefa5 100644
--- a/private/system_server.te
+++ b/private/system_server.te
@@ -774,6 +774,7 @@ userdebug_or_eng(`set_prop(system_server, system_user_mode_emulation_prop)')
 set_prop(system_server, ctl_default_prop)
 set_prop(system_server, ctl_bugreport_prop)
 set_prop(system_server, ctl_gsid_prop)
+set_prop(system_server, ctl_artd_pre_reboot_prop)
 
 # cppreopt property
 set_prop(system_server, cppreopt_prop)
@@ -900,6 +901,9 @@ get_prop(system_server, traced_oome_heap_session_count_prop)
 # configuration properties
 get_prop(system_server, sensors_config_prop)
 
+# Allow system server to determine if system services are enabled
+get_prop(system_server, system_service_enable_prop)
+
 # Create a socket for connections from debuggerd.
 allow system_server system_ndebug_socket:sock_file create_file_perms;
 
@@ -1233,6 +1237,10 @@ allow system_server self:key_socket create;
 # calls if (fd.isSocket$()) if (isLingerSocket(fd)) ...
 dontaudit system_server self:key_socket getopt;
 
+# Needed to interact with memevents-eBPF and receive notifications for memory events
+allow system_server fs_bpf_memevents:dir search;
+allow system_server fs_bpf_memevents:file { read write };
+
 # Allow system_server to start clatd in its own domain and kill it.
 domain_auto_trans(system_server, clatd_exec, clatd)
 allow system_server clatd:process { sigkill signal };
@@ -1261,6 +1269,9 @@ get_prop(system_server,system_jvmti_agent_prop)
 # UsbDeviceManager uses /dev/usb-ffs
 allow system_server functionfs:dir search;
 allow system_server functionfs:file rw_file_perms;
+# To resolve arbitrary sysfs paths from /sys/class/udc/* symlinks.
+allow system_server sysfs_type:dir search;
+r_dir_file(system_server, sysfs_udc)
 
 # system_server contains time / time zone detection logic so reads the associated properties.
 get_prop(system_server, time_prop)
@@ -1539,10 +1550,6 @@ allow system_server proc_pressure_mem:file rw_file_perms;
 # Read /proc/pressure/cpu and /proc/pressure/io
 allow system_server { proc_pressure_cpu proc_pressure_io }:file r_file_perms;
 
-# dexoptanalyzer is currently used only for secondary dex files which
-# system_server should never access.
-neverallow system_server dexoptanalyzer_exec:file no_x_file_perms;
-
 # No ptracing others
 neverallow system_server { domain -system_server }:process ptrace;
 
@@ -1559,10 +1566,6 @@ neverallow {
 } password_slot_metadata_file:notdevfile_class_set ~{ relabelto getattr };
 neverallow { domain -init -system_server } password_slot_metadata_file:notdevfile_class_set *;
 
-# Only system_server/init should access /metadata/userspacereboot.
-neverallow { domain -init -system_server } userspace_reboot_metadata_file:dir *;
-neverallow { domain -init -system_server } userspace_reboot_metadata_file:file no_rw_file_perms;
-
 # Only system server should access /metadata/aconfig
 neverallow { domain -init -system_server -aconfigd } aconfig_storage_flags_metadata_file:dir *;
 neverallow { domain -init -system_server -aconfigd } aconfig_storage_flags_metadata_file:file no_rw_file_perms;
diff --git a/private/traced_probes.te b/private/traced_probes.te
index 003e992c2..654042085 100644
--- a/private/traced_probes.te
+++ b/private/traced_probes.te
@@ -111,6 +111,10 @@ unix_socket_send(traced_probes, statsdw, statsd)
 binder_call(traced_probes, statsd)
 allow traced_probes stats_service:service_manager find;
 
+# Allow reading the system property representing number of desktop windows to
+# set the initial value for the counter in traces.
+get_prop(traced_probes, debug_tracing_desktop_mode_visible_tasks_prop)
+
 ###
 ### Neverallow rules
 ###
diff --git a/private/update_engine_common.te b/private/update_engine_common.te
index 5bba84a80..6de02929c 100644
--- a/private/update_engine_common.te
+++ b/private/update_engine_common.te
@@ -107,5 +107,5 @@ get_prop(update_engine_common, build_bootimage_prop)
 
 # Allow to read/write/create OTA metadata files for snapshot status and COW file status.
 allow update_engine_common metadata_file:dir search;
-allow update_engine_common ota_metadata_file:dir rw_dir_perms;
+allow update_engine_common ota_metadata_file:dir { rw_dir_perms rmdir };
 allow update_engine_common ota_metadata_file:file create_file_perms;
diff --git a/private/uprobestats.te b/private/uprobestats.te
index f6dd9069d..2c5711f11 100644
--- a/private/uprobestats.te
+++ b/private/uprobestats.te
@@ -16,7 +16,7 @@ allow uprobestats sysfs_uprobe:file { open read };
 allow uprobestats sysfs_uprobe:dir { search };
 
 # Allow uprobestats to popen oatdump.
-allow uprobestats oatdump_exec:file rx_file_perms;
+allow uprobestats system_file:file rx_file_perms;
 
 # Allow uprobestats to write atoms to statsd
 unix_socket_send(uprobestats, statsdw, statsd)
diff --git a/private/vendor_init.te b/private/vendor_init.te
index 72157ad7c..84ec60ebc 100644
--- a/private/vendor_init.te
+++ b/private/vendor_init.te
@@ -221,9 +221,6 @@ allow vendor_init self:global_capability_class_set net_admin;
 # Write to /proc/sys/vm/page-cluster
 allow vendor_init proc_page_cluster:file w_file_perms;
 
-# Write to /proc/sys/vm/compaction_proactiveness
-allow vendor_init proc_compaction_proactiveness:file w_file_perms;
-
 # Write to sysfs nodes.
 allow vendor_init sysfs_type:dir r_dir_perms;
 allow vendor_init sysfs_type:lnk_file read;
diff --git a/private/virtual_camera.te b/private/virtual_camera.te
index 6b3be0c8f..fa8db4365 100644
--- a/private/virtual_camera.te
+++ b/private/virtual_camera.te
@@ -30,6 +30,7 @@ allow virtual_camera { appdomain -isolated_app }:fd use;
 
 # Allow virtual_camera to use fd from surface flinger
 allow virtual_camera surfaceflinger:fd use;
+allow virtual_camera surfaceflinger:binder call;
 
 # Only allow virtual_camera to add a virtual_camera_service and no one else.
 add_service(virtual_camera, virtual_camera_service);
@@ -40,7 +41,7 @@ hal_client_domain(virtual_camera, hal_graphics_allocator)
 # Allow virtual_camera to use GPU
 allow virtual_camera gpu_device:chr_file rw_file_perms;
 allow virtual_camera gpu_device:dir r_dir_perms;
-allow virtual_camera sysfs_gpu:file r_file_perms;
+r_dir_file(virtual_camera, sysfs_gpu)
 
 # Allow virtual camera to use graphics composer fd-s (fences).
 allow virtual_camera hal_graphics_composer:fd use;
diff --git a/private/virtual_face.te b/private/virtual_face.te
new file mode 100644
index 000000000..0e33d6b26
--- /dev/null
+++ b/private/virtual_face.te
@@ -0,0 +1,6 @@
+# biometric virtual face sensor
+type virtual_face, domain;
+type virtual_face_exec, system_file_type, exec_type, file_type;
+hal_server_domain(virtual_face, hal_face)
+typeattribute virtual_face coredomain;
+init_daemon_domain(virtual_face)
diff --git a/private/virtual_fingerprint.te b/private/virtual_fingerprint.te
new file mode 100644
index 000000000..be20e241a
--- /dev/null
+++ b/private/virtual_fingerprint.te
@@ -0,0 +1,7 @@
+# biometric virtual fingerprint sensor
+type virtual_fingerprint, domain;
+type virtual_fingerprint_exec, system_file_type, exec_type, file_type;
+hal_server_domain(virtual_fingerprint, hal_fingerprint)
+typeattribute virtual_fingerprint coredomain;
+init_daemon_domain(virtual_fingerprint)
+set_prop(virtual_fingerprint, virtual_fingerprint_prop)
diff --git a/private/virtualizationmanager.te b/private/virtualizationmanager.te
index 9b3cfcff8..023e3e908 100644
--- a/private/virtualizationmanager.te
+++ b/private/virtualizationmanager.te
@@ -70,12 +70,24 @@ get_prop(virtualizationmanager, hypervisor_restricted_prop)
 # Allow virtualizationmanager to be read custom pvmfw.img configuration
 userdebug_or_eng(`get_prop(virtualizationmanager, hypervisor_pvmfw_prop)')
 dontaudit virtualizationmanager hypervisor_pvmfw_prop:file read;
-neverallow { domain -init -dumpstate userdebug_or_eng(`-virtualizationmanager') } hypervisor_pvmfw_prop:file no_rw_file_perms;
+neverallow {
+  domain
+  -init
+  -dumpstate
+  userdebug_or_eng(`-virtualizationmanager')
+  is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, -early_virtmgr)
+} hypervisor_pvmfw_prop:file no_rw_file_perms;
 
 # Allow virtualizationmanager to be read custom virtualizationmanager configuration
 userdebug_or_eng(`get_prop(virtualizationmanager, hypervisor_virtualizationmanager_prop)')
 dontaudit virtualizationmanager hypervisor_virtualizationmanager_prop:file read;
-neverallow { domain -init -dumpstate userdebug_or_eng(`-virtualizationmanager') } hypervisor_virtualizationmanager_prop:file no_rw_file_perms;
+neverallow {
+  domain
+  -init
+  -dumpstate
+  userdebug_or_eng(`-virtualizationmanager')
+  is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, -early_virtmgr)
+} hypervisor_virtualizationmanager_prop:file no_rw_file_perms;
 
 # Allow virtualizationmanager service to talk to tombstoned to push guest ramdumps
 unix_socket_connect(virtualizationmanager, tombstoned_crash, tombstoned)
diff --git a/private/virtualizationservice.te b/private/virtualizationservice.te
index 3d0aac0ff..bc29e39e1 100644
--- a/private/virtualizationservice.te
+++ b/private/virtualizationservice.te
@@ -28,6 +28,7 @@ is_flag_enabled(RELEASE_AVF_ENABLE_NETWORK, `
     # Let virtualizationservice find and communicate with vmnic.
     allow virtualizationservice vmnic_service:service_manager find;
     binder_call(virtualizationservice, vmnic)
+    allow virtualizationservice vm_tethering_service:service_manager find;
 ')
 
 # Allow the virtualizationservice domain to serve a remotely provisioned component for
@@ -84,10 +85,10 @@ allow virtualizationservice apex_module_data_file:dir { search getattr };
 allow virtualizationservice apex_virt_data_file:dir create_dir_perms;
 allow virtualizationservice apex_virt_data_file:file create_file_perms;
 
-# Let virtualizationservice to accept vsock connection from the guest VMs to singleton services
+# Accept vsock connection from the guest VMs to singleton services
 # such as the guest tombstone server.
-allow virtualizationservice self:vsock_socket { create_socket_perms_no_ioctl listen accept };
-neverallow { domain -virtualizationservice } virtualizationservice:vsock_socket { accept bind create connect listen };
+allow virtualizationservice self:vsock_socket { create read getattr write setattr lock append bind getopt setopt shutdown map listen accept };
+neverallow { domain -virtualizationservice -dumpstate } virtualizationservice:vsock_socket *;
 
 # Allow virtualizationservice to read/write its own sysprop. Only the process can do so.
 set_prop(virtualizationservice, virtualizationservice_prop)
diff --git a/private/vmlauncher_app.te b/private/vmlauncher_app.te
index f0f372b48..c76c1175a 100644
--- a/private/vmlauncher_app.te
+++ b/private/vmlauncher_app.te
@@ -2,6 +2,7 @@ type vmlauncher_app, domain;
 typeattribute vmlauncher_app coredomain;
 
 app_domain(vmlauncher_app)
+net_domain(vmlauncher_app)
 
 allow vmlauncher_app app_api_service:service_manager find;
 allow vmlauncher_app system_api_service:service_manager find;
diff --git a/private/vmnic.te b/private/vmnic.te
index 1b7e0d8b6..4a706dff5 100644
--- a/private/vmnic.te
+++ b/private/vmnic.te
@@ -17,7 +17,7 @@ is_flag_enabled(RELEASE_AVF_ENABLE_NETWORK, `
     allow vmnic self:global_capability_class_set net_admin;
     allow vmnic self:tun_socket create_socket_perms_no_ioctl;
     allow vmnic tun_device:chr_file rw_file_perms;
-    allowxperm vmnic tun_device:chr_file ioctl { TUNGETIFF TUNSETIFF TUNSETPERSIST };
+    allowxperm vmnic tun_device:chr_file ioctl { TUNGETIFF TUNSETIFF };
     allow vmnic self:udp_socket create_socket_perms;
     allowxperm vmnic self:udp_socket ioctl SIOCSIFFLAGS;
 
diff --git a/private/vold.te b/private/vold.te
index 2c1fb8f91..339877de0 100644
--- a/private/vold.te
+++ b/private/vold.te
@@ -235,7 +235,7 @@ allow vold vold_device:blk_file { create setattr unlink rw_file_perms };
 allowxperm vold vold_device:blk_file ioctl { BLKDISCARD BLKGETSIZE };
 allow vold dm_device:chr_file rw_file_perms;
 allow vold dm_device:blk_file rw_file_perms;
-allowxperm vold dm_device:blk_file ioctl { BLKDISCARD BLKSECDISCARD BLKREPORTZONE BLKRESETZONE };
+allowxperm vold dm_device:blk_file ioctl { BLKDISCARD BLKSECDISCARD BLKREPORTZONE BLKRESETZONE BLKROSET BLKROGET };
 # For vold Process::killProcessesWithOpenFiles function.
 allow vold domain:dir r_dir_perms;
 allow vold domain:{ file lnk_file } r_file_perms;
diff --git a/public/device.te b/public/device.te
index beafdf299..835b532a2 100644
--- a/public/device.te
+++ b/public/device.te
@@ -25,7 +25,7 @@ type vold_device, dev_type;
 type console_device, dev_type;
 type fscklogs, dev_type;
 # GPU (used by most UI apps)
-type gpu_device, dev_type, mlstrustedobject;
+type gpu_device, dev_type, mlstrustedobject, isolated_compute_allowed_device;
 type graphics_device, dev_type;
 type hw_random_device, dev_type;
 type input_device, dev_type;
diff --git a/public/file.te b/public/file.te
index 9f75f05d1..4f187ec50 100644
--- a/public/file.te
+++ b/public/file.te
@@ -23,11 +23,6 @@ type proc_min_free_order_shift, fs_type, proc_type;
 type proc_kpageflags, fs_type, proc_type;
 type proc_watermark_boost_factor, fs_type, proc_type;
 type proc_percpu_pagelist_high_fraction, fs_type, proc_type;
-
-starting_at_board_api(202504, `
-    type proc_compaction_proactiveness, fs_type, proc_type;
-')
-
 # proc, sysfs, or other nodes that permit configuration of kernel usermodehelpers.
 type usermodehelper, fs_type, proc_type;
 type sysfs_usermodehelper, fs_type, sysfs_type;
@@ -105,6 +100,9 @@ type cgroup, fs_type, mlstrustedobject;
 type cgroup_v2, fs_type;
 type sysfs, fs_type, sysfs_type, mlstrustedobject;
 type sysfs_android_usb, fs_type, sysfs_type;
+starting_at_board_api(202504, `
+    type sysfs_udc, fs_type, sysfs_type;
+')
 type sysfs_uio, sysfs_type, fs_type;
 type sysfs_batteryinfo, fs_type, sysfs_type;
 type sysfs_bluetooth_writable, fs_type, sysfs_type, mlstrustedobject;
@@ -152,12 +150,6 @@ type fs_bpf, fs_type, bpffs_type;
 type fs_bpf_tethering, fs_type, bpffs_type;
 type fs_bpf_vendor, fs_type, bpffs_type;
 
-starting_at_board_api(202504, `
-    type fs_bpf_lmkd_memevents_rb, fs_type, bpffs_type;
-    type fs_bpf_lmkd_memevents_prog, fs_type, bpffs_type;
-')
-
-
 type configfs, fs_type;
 # /sys/devices/cs_etm
 type sysfs_devices_cs_etm, fs_type, sysfs_type;
diff --git a/public/otapreopt_chroot.te b/public/otapreopt_chroot.te
index 8a625f554..eb340c840 100644
--- a/public/otapreopt_chroot.te
+++ b/public/otapreopt_chroot.te
@@ -1,7 +1,7 @@
 # otapreopt_chroot seclabel
 
 # TODO: Only present to allow mediatek/wembley-sepolicy to see it for validation reasons.
-type otapreopt_chroot, domain;
+until_board_api(202504, `type otapreopt_chroot, domain;')
 
 # system/sepolicy/public is for vendor-facing type and attribute definitions.
 # DO NOT ADD allow, neverallow, or dontaudit statements here.
diff --git a/public/property.te b/public/property.te
index 47a1bde20..fa89cbb14 100644
--- a/public/property.te
+++ b/public/property.te
@@ -212,6 +212,9 @@ system_public_prop(adbd_config_prop)
 system_public_prop(audio_prop)
 system_public_prop(bluetooth_a2dp_offload_prop)
 system_public_prop(bluetooth_audio_hal_prop)
+starting_at_board_api(202504, `
+    system_public_prop(bluetooth_finder_prop)
+')
 system_public_prop(bluetooth_prop)
 system_public_prop(bpf_progs_loaded_prop)
 system_public_prop(charger_status_prop)
@@ -273,10 +276,13 @@ system_internal_prop(default_prop)
 vendor_internal_prop(rebootescrow_hal_prop)
 
 # Properties used in the default Face HAL implementations
-vendor_internal_prop(virtual_face_hal_prop)
+system_public_prop(virtual_face_hal_prop)
 
 # Properties used in the default Fingerprint HAL implementations
 vendor_internal_prop(virtual_fingerprint_hal_prop)
+starting_at_board_api(202504, `
+    system_public_prop(virtual_fingerprint_prop)
+')
 
 vendor_public_prop(persist_vendor_debug_wifi_prop)
 
diff --git a/public/service.te b/public/service.te
index 6ba1dcc78..663ca1411 100644
--- a/public/service.te
+++ b/public/service.te
@@ -68,6 +68,9 @@ type adb_service, system_api_service, system_server_service, service_manager_typ
 type adservices_manager_service, system_api_service, system_server_service, service_manager_type;
 type alarm_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type app_binding_service, system_server_service, service_manager_type;
+starting_at_board_api(202504, `
+    type app_function_service, app_api_service, system_server_service, service_manager_type;
+')
 type app_hibernation_service, app_api_service, system_api_service, system_server_service, service_manager_type;
 type app_integrity_service, system_api_service, system_server_service, service_manager_type;
 type app_prediction_service, app_api_service, system_server_service, service_manager_type;
@@ -195,13 +198,16 @@ type people_service, app_api_service, system_server_service, service_manager_typ
 type permission_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type permissionmgr_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type permission_checker_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
-type persistent_data_block_service, system_api_service, system_server_service, service_manager_type;
+type persistent_data_block_service, app_api_service, system_api_service, system_server_service, service_manager_type;
 type pinner_service, system_server_service, service_manager_type;
 type powerstats_service, app_api_service, system_server_service, service_manager_type;
 type power_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type print_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type processinfo_service, system_server_service, service_manager_type;
 type procstats_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
+is_flag_enabled(RELEASE_RANGING_STACK, `
+    type ranging_service, app_api_service, system_server_service, service_manager_type;
+')
 type reboot_readiness_service, app_api_service, system_server_service, service_manager_type;
 type recovery_service, system_server_service, service_manager_type;
 type registry_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
diff --git a/public/te_macros b/public/te_macros
index 6d7533afa..e446f56ee 100644
--- a/public/te_macros
+++ b/public/te_macros
@@ -203,6 +203,34 @@ get_prop($1, hypervisor_prop)
 allow $1 virtualizationservice_data_file:file { getattr read };
 ')
 
+####################################
+# early_virtmgr_use(domain)
+# Allow domain to create and communicate with an early virtual machine using
+# early_virtmgr.
+define(`early_virtmgr_use', `
+# Transition to early_virtmgr when the client executes it.
+domain_auto_trans($1, early_virtmgr_exec, early_virtmgr)
+# Allow early_virtmgr to communicate over UDS with the client.
+allow { early_virtmgr crosvm } $1:unix_stream_socket { ioctl getattr read write };
+# Let the client pass file descriptors to early_virtmgr and on to crosvm.
+allow { early_virtmgr crosvm } $1:fd use;
+allow { early_virtmgr crosvm } $1_tmpfs:file rw_file_perms;
+# Let the client use file descriptors created by early_virtmgr.
+allow $1 early_virtmgr:fd use;
+# Allow piping console log to the client
+allow { early_virtmgr crosvm } $1:fifo_file { ioctl getattr read write };
+# Allow client to read/write vsock created by early_virtmgr to communicate with the VM
+# that it created. Notice that we do not grant permission to create a vsock;
+# the client can only connect to VMs that it owns.
+allow $1 early_virtmgr:vsock_socket { getattr getopt read write };
+# Allow client to inspect hypervisor capabilities
+get_prop($1, hypervisor_prop)
+# Allow early_virtmgr to read the path of the client using /proc/{PID}/exe
+allow early_virtmgr $1:dir search;
+allow early_virtmgr $1:file read;
+allow early_virtmgr $1:lnk_file read;
+')
+
 #####################################
 # app_domain(domain)
 # Allow a base set of permissions required for all apps.
diff --git a/tests/sepolicy_tests.py b/tests/sepolicy_tests.py
index af4793826..2791c5303 100644
--- a/tests/sepolicy_tests.py
+++ b/tests/sepolicy_tests.py
@@ -44,6 +44,10 @@ def TestSystemTypeViolations(pol):
         "/system/product/vendor_overlay/",
         "/system/system_ext/overlay/",
         "/system_ext/overlay/",
+
+        # adb_keys_file hasn't been a system_file_type
+        "/product/etc/security/adb_keys",
+        "/system/product/etc/security/adb_keys",
     ]
 
     return pol.AssertPathTypesHaveAttr(partitions, exceptions, "system_file_type")
@@ -182,6 +186,7 @@ def TestIsolatedAttributeConsistency(test_policy):
         # access given from technical_debt.cil
         "codec2_config_prop" : ["file"],
         "device_config_nnapi_native_prop":["file"],
+        "gpu_device": ["dir"],
         "hal_allocator_default":["binder", "fd"],
         "hal_codec2": ["binder", "fd"],
         "hal_codec2_hwservice":["hwservice_manager"],
@@ -206,6 +211,7 @@ def TestIsolatedAttributeConsistency(test_policy):
         "media_variant_prop":["file"],
         "nnapi_ext_deny_product_prop":["file"],
         "servicemanager":["fd"],
+        "sysfs_gpu": ["file"],
         "toolbox_exec": ["file"],
         # extra types being granted to isolated_compute_app
         "isolated_compute_allowed":["service_manager", "chr_file"],
diff --git a/tools/check_seapp.c b/tools/check_seapp.c
index 02882af31..f19b0f1cc 100644
--- a/tools/check_seapp.c
+++ b/tools/check_seapp.c
@@ -233,7 +233,6 @@ key_map rules[] = {
                 /*Outputs*/
                 { .name = "domain",         .dir = dir_out, .fn_validate = validate_domain  },
                 { .name = "type",           .dir = dir_out, .fn_validate = validate_type  },
-                { .name = "levelFromUid",   .dir = dir_out, .fn_validate = validate_bool          },
                 { .name = "levelFrom",      .dir = dir_out, .fn_validate = validate_levelFrom     },
                 { .name = "level",          .dir = dir_out, .fn_validate = validate_selinux_level },
 };
diff --git a/tools/checkfc.c b/tools/checkfc.c
index 051e24ba1..904f02f9b 100644
--- a/tools/checkfc.c
+++ b/tools/checkfc.c
@@ -304,6 +304,7 @@ static void do_test_data_and_die_on_error(struct selinux_opt opts[], unsigned in
     }
 
     char line[1024];
+    bool non_matching_entries = false;
     while (fgets(line, sizeof(line), test_data)) {
         char *path;
         char *expected_type;
@@ -331,6 +332,7 @@ static void do_test_data_and_die_on_error(struct selinux_opt opts[], unsigned in
         if (strcmp(found_type, expected_type)) {
             fprintf(stderr, "Incorrect type for %s: resolved to %s, expected %s\n",
                     path, found_type, expected_type);
+            non_matching_entries = true;
         }
 
         free(found_context);
@@ -340,6 +342,10 @@ static void do_test_data_and_die_on_error(struct selinux_opt opts[], unsigned in
     }
     fclose(test_data);
 
+    if (non_matching_entries) {
+        exit(1);
+    }
+
     // Prints the coverage of file_contexts on the test data. It includes
     // warnings for rules that have not been hit by any test example.
     union selinux_callback cb;
diff --git a/tools/finalize-vintf-resources.sh b/tools/finalize-vintf-resources.sh
index cdf82f162..3f3def6b2 100755
--- a/tools/finalize-vintf-resources.sh
+++ b/tools/finalize-vintf-resources.sh
@@ -29,6 +29,22 @@ cp -r "$top/system/sepolicy/private/" "$prebuilt_dir"
 
 cat > "$prebuilt_dir/Android.bp" <<EOF
 // Automatically generated file, do not edit!
+se_policy_conf {
+    name: "${ver}_reqd_policy_mask.conf",
+    defaults: ["se_policy_conf_flags_defaults"],
+    srcs: reqd_mask_policy,
+    installable: false,
+    build_variant: "user",
+    board_api_level: "${ver}",
+}
+
+se_policy_cil {
+    name: "${ver}_reqd_policy_mask.cil",
+    src: ":${ver}_reqd_policy_mask.conf",
+    secilc_check: false,
+    installable: false,
+}
+
 se_policy_conf {
     name: "${ver}_plat_pub_policy.conf",
     defaults: ["se_policy_conf_flags_defaults"],
@@ -38,12 +54,13 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "${ver}",
 }
 
 se_policy_cil {
     name: "${ver}_plat_pub_policy.cil",
     src: ":${ver}_plat_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":${ver}_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
@@ -59,16 +76,25 @@ se_policy_conf {
     ],
     installable: false,
     build_variant: "user",
+    board_api_level: "${ver}",
 }
 
 se_policy_cil {
     name: "${ver}_product_pub_policy.cil",
     src: ":${ver}_product_pub_policy.conf",
-    filter_out: [":reqd_policy_mask.cil"],
+    filter_out: [":${ver}_reqd_policy_mask.cil"],
     secilc_check: false,
     installable: false,
 }
 
+se_versioned_policy {
+    name: "${ver}_plat_pub_versioned.cil",
+    base: ":${ver}_product_pub_policy.cil",
+    target_policy: ":${ver}_product_pub_policy.cil",
+    version: "${ver}",
+    installable: false,
+}
+
 se_policy_conf {
     name: "${ver}_plat_policy.conf",
     defaults: ["se_policy_conf_flags_defaults"],
diff --git a/tools/fuzzer_bindings_check.py b/tools/fuzzer_bindings_check.py
index 55859ac8c..65b54de7d 100644
--- a/tools/fuzzer_bindings_check.py
+++ b/tools/fuzzer_bindings_check.py
@@ -50,8 +50,8 @@ def check_fuzzer_exists(context_file, bindings):
        if service_name not in bindings:
          sys.exit("\nerror: Service '{0}' is being added, but we have no fuzzer on file for it. "
                   "Fuzzers are listed at $ANDROID_BUILD_TOP/system/sepolicy/build/soong/service_fuzzer_bindings.go \n\n"
-                  "NOTE: automatic service fuzzers are currently not supported in Java (b/232439254) "
-                  "and Rust (b/164122727). In this case, please ignore this for now and add an entry for your"
+                  "NOTE: automatic service fuzzers are currently not supported in Java (b/287102710.)"
+                  "In this case, please ignore this for now and add an entry for your"
                   "new service in service_fuzzer_bindings.go \n\n"
                   "If you are writing a new service, it may be subject to attack from other "
                   "potentially malicious processes. A fuzzer can be written automatically "
diff --git a/tools/sepolicy-analyze/neverallow.c b/tools/sepolicy-analyze/neverallow.c
index 745ab1333..4b88206e9 100644
--- a/tools/sepolicy-analyze/neverallow.c
+++ b/tools/sepolicy-analyze/neverallow.c
@@ -382,7 +382,6 @@ static int check_neverallows(policydb_t *policydb, char *text, char *end)
     char *p, *start;
     int result;
 
-    int non_comment_len = 0, cur_non_comment_len = 0;
     char *cur_non_comment_text = calloc(1, (end - text) + 1);
     char *non_comment_text = cur_non_comment_text;
     if (!cur_non_comment_text)
diff --git a/vendor/file_contexts b/vendor/file_contexts
index edd1c7133..d0c698dd4 100644
--- a/vendor/file_contexts
+++ b/vendor/file_contexts
@@ -24,9 +24,10 @@
 /(vendor|system/vendor)/bin/hw/android\.hardware\.bluetooth\.lmp_event-service\.default    u:object_r:hal_bluetooth_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.biometrics\.face@1\.[0-9]+-service\.example u:object_r:hal_face_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.biometrics\.face-service\.example u:object_r:hal_face_default_exec:s0
+/(vendor|system/vendor)/bin/hw/android\.hardware\.biometrics\.face-service\.default u:object_r:hal_face_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.biometrics\.fingerprint@2\.1-service u:object_r:hal_fingerprint_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.biometrics\.fingerprint@2\.2-service\.example u:object_r:hal_fingerprint_default_exec:s0
-/(vendor|system/vendor)/bin/hw/android\.hardware\.biometrics\.fingerprint-service\.example u:object_r:hal_fingerprint_default_exec:s0
+/(vendor|system/vendor)/bin/hw/android\.hardware\.biometrics\.fingerprint-service\.default u:object_r:hal_fingerprint_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.boot@1\.[0-9]+-service      u:object_r:hal_bootctl_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.boot-service.default      u:object_r:hal_bootctl_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.broadcastradio@\d+\.\d+-service u:object_r:hal_broadcastradio_default_exec:s0
diff --git a/vendor/hal_fingerprint_default.te b/vendor/hal_fingerprint_default.te
index e380ebd2d..3ad14bf2c 100644
--- a/vendor/hal_fingerprint_default.te
+++ b/vendor/hal_fingerprint_default.te
@@ -7,8 +7,6 @@ init_daemon_domain(hal_fingerprint_default)
 # android.frameworks.sensorservice through libsensorndkbridge
 allow hal_fingerprint_default fwk_sensor_service:service_manager find;
 
-set_prop(hal_fingerprint_default, virtual_fingerprint_hal_prop)
-
 userdebug_or_eng(`
   # Allow fingerprint hal to read app-created pipes (to respond shell commands from test apps)
   allow hal_fingerprint_default appdomain:fifo_file read;
diff --git a/vendor/hal_tv_tuner_default.te b/vendor/hal_tv_tuner_default.te
index e11d4dd62..5e149a674 100644
--- a/vendor/hal_tv_tuner_default.te
+++ b/vendor/hal_tv_tuner_default.te
@@ -11,3 +11,6 @@ allow hal_tv_tuner_default dmabuf_system_heap_device:chr_file r_file_perms;
 
 # Allow servicemanager to notify hal_tv_tuner_default clients status
 binder_use(hal_tv_tuner_default)
+
+# Allow network communication
+net_domain(hal_tv_tuner_default)
\ No newline at end of file
```

