```diff
diff --git a/Android.bp b/Android.bp
index 5d9e42330..558810cb8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -102,6 +102,7 @@ phony {
         "plat_property_contexts",
         "plat_seapp_contexts",
         "plat_sepolicy.cil",
+        "plat_sepolicy_genfs_202504.cil",
         "plat_service_contexts",
         "secilc",
         "plat_29.0.cil",
@@ -125,6 +126,9 @@ phony {
     }) + select(soong_config_variable("ANDROID", "PRODUCT_PRECOMPILED_SEPOLICY"), {
         true: ["plat_sepolicy_and_mapping.sha256"],
         default: [],
+    }) + select(release_flag("RELEASE_AVF_ENABLE_VM_TO_TEE_SERVICES_ALLOWLIST"), {
+        true: ["plat_tee_service_contexts"],
+        default: [],
     }),
 }
 
@@ -509,7 +513,7 @@ se_versioned_policy {
 //   precompiled_sepolicy.product_sepolicy_and_mapping.sha256
 // See system/core/init/selinux.cpp for details.
 //////////////////////////////////
-genrule {
+java_genrule {
     name: "plat_sepolicy_and_mapping.sha256_gen",
     srcs: [
         ":plat_sepolicy.cil",
@@ -526,7 +530,7 @@ prebuilt_etc {
     relative_install_path: "selinux",
 }
 
-genrule {
+java_genrule {
     name: "system_ext_sepolicy_and_mapping.sha256_gen",
     srcs: [
         ":system_ext_sepolicy.cil",
@@ -544,7 +548,7 @@ prebuilt_etc {
     system_ext_specific: true,
 }
 
-genrule {
+java_genrule {
     name: "product_sepolicy_and_mapping.sha256_gen",
     srcs: [
         ":product_sepolicy.cil",
@@ -568,6 +572,22 @@ sepolicy_vers {
     vendor: true,
 }
 
+genrule {
+    name: "genfs_labels_version.txt.gen",
+    out: ["genfs_labels_version.txt"],
+    cmd: select(soong_config_variable("ANDROID", "BOARD_GENFS_LABELS_VERSION"), {
+        any @ value: "echo " + value + " > $(out)",
+        default: "echo > $(out)",
+    }),
+}
+
+prebuilt_etc {
+    name: "genfs_labels_version.txt",
+    src: ":genfs_labels_version.txt.gen",
+    relative_install_path: "selinux",
+    vendor: true,
+}
+
 soong_config_module_type {
     name: "precompiled_sepolicy_prebuilts_defaults",
     module_type: "prebuilt_defaults",
@@ -640,7 +660,7 @@ soong_config_module_type {
 
 filegroup {
     name: "precompiled_sepolicy_srcs",
-    srcs: [
+    device_common_srcs: [
         ":plat_sepolicy.cil",
         ":plat_pub_versioned.cil",
         ":system_ext_sepolicy.cil",
@@ -651,6 +671,10 @@ filegroup {
         ":system_ext_mapping_file",
         ":product_mapping_file",
     ],
+    device_first_srcs: select(soong_config_variable("ANDROID", "BOARD_GENFS_LABELS_VERSION"), {
+        "202504": [":plat_sepolicy_genfs_202504.cil"],
+        default: [],
+    }),
     // Make precompiled_sepolicy_srcs as public so that OEMs have access to them.
     // Useful when some partitions need to be bind mounted across VM boundaries.
     visibility: ["//visibility:public"],
@@ -890,7 +914,7 @@ se_freeze_test {
 // sepolicy_test checks various types of violations, which can't be easily done
 // by CIL itself. Refer tests/sepolicy_tests.py for more detail.
 //////////////////////////////////
-genrule {
+java_genrule {
     name: "sepolicy_test",
     srcs: [
         ":plat_file_contexts",
@@ -918,7 +942,7 @@ genrule {
 
 soong_config_module_type {
     name: "dev_type_test_genrule",
-    module_type: "genrule",
+    module_type: "java_genrule",
     config_namespace: "ANDROID",
     bool_variables: ["CHECK_DEV_TYPE_VIOLATIONS"],
     properties: ["cmd"],
@@ -1003,5 +1027,333 @@ phony {
         default: [
             "system_ext_202404.compat.cil",
         ],
+    }) + select(release_flag("RELEASE_AVF_ENABLE_VM_TO_TEE_SERVICES_ALLOWLIST"), {
+        true: ["system_ext_tee_service_contexts"],
+        default: [],
+    }),
+    system_ext_specific: true,
+}
+
+phony {
+    name: "selinux_policy_product",
+    required: [
+        "product_mapping_file",
+        "product_sepolicy.cil",
+        // "ifdef HAS_PRODUCT_PUBLIC_SEPOLICY" check included in .cil
+        "product_29.0.cil",
+        "product_30.0.cil",
+        "product_31.0.cil",
+        "product_32.0.cil",
+        "product_33.0.cil",
+        "product_34.0.cil",
+        "product_file_contexts",
+        // "ifdef HAS_PRODUCT_SEPOLICY_DIR" in Android.mk can be ignored.
+        "product_file_contexts_test",
+        "product_keystore2_key_contexts",
+        "product_hwservice_contexts",
+        "product_hwservice_contexts_test",
+        "product_property_contexts",
+        "product_property_contexts_test",
+        "product_seapp_contexts",
+        "product_service_contexts",
+        "product_service_contexts_test",
+        "product_mac_permissions.xml",
+    ] + select(soong_config_variable("ANDROID", "PRODUCT_PRECOMPILED_SEPOLICY"), {
+        true: ["product_sepolicy_and_mapping.sha256"],
+        default: [],
+    }) + select(soong_config_variable("ANDROID", "PLATFORM_SEPOLICY_VERSION"), {
+        "202404": [],
+        default: [
+            "product_202404.cil",
+        ],
+    }) + select(release_flag("RELEASE_AVF_ENABLE_VM_TO_TEE_SERVICES_ALLOWLIST"), {
+        true: ["product_tee_service_contexts"],
+        default: [],
+    }),
+    product_specific: true,
+}
+
+phony {
+    name: "selinux_policy_nonsystem",
+    required: [
+        "selinux_policy_system_ext",
+        "selinux_policy_product",
+        "selinux_policy_vendor",
+        "selinux_policy_odm",
+        // Builds an additional userdebug sepolicy into the debug ramdisk.
+        "userdebug_plat_sepolicy.cil",
+    ],
+}
+
+phony {
+    name: "selinux_policy_vendor",
+    required: [
+        "genfs_labels_version.txt",
+        "plat_pub_versioned.cil",
+        "vendor_sepolicy.cil",
+        "plat_sepolicy_vers.txt",
+        "vendor_file_contexts",
+        "vendor_file_contexts_test",
+        "vendor_keystore2_key_contexts",
+        "vendor_mac_permissions.xml",
+        "vendor_property_contexts",
+        "vendor_property_contexts_test",
+        "vendor_seapp_contexts",
+        "vendor_service_contexts",
+        "vendor_service_contexts_test",
+        "vendor_hwservice_contexts",
+        "vendor_hwservice_contexts_test",
+        "vendor_bug_map",
+        "vndservice_contexts",
+        "vndservice_contexts_test",
+    ] + select(release_flag("RELEASE_AVF_ENABLE_VM_TO_TEE_SERVICES_ALLOWLIST"), {
+        true: ["vendor_tee_service_contexts"],
+        default: [],
+    }),
+    vendor: true,
+}
+
+phony {
+    name: "selinux_policy_odm",
+    required: [
+        "odm_sepolicy.cil",
+        "odm_file_contexts",
+        "odm_file_contexts_test",
+        "odm_seapp_contexts",
+        "odm_property_contexts",
+        "odm_property_contexts_test",
+        "odm_service_contexts",
+        "odm_service_contexts_test",
+        "odm_hwservice_contexts",
+        "odm_hwservice_contexts_test",
+        "odm_mac_permissions.xml",
+    ] + select(soong_config_variable("ANDROID", "PRODUCT_PRECOMPILED_SEPOLICY"), {
+        true: [
+            "precompiled_sepolicy",
+            "precompiled_sepolicy.plat_sepolicy_and_mapping.sha256",
+            "precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256",
+            "precompiled_sepolicy.product_sepolicy_and_mapping.sha256",
+        ],
+        default: [],
+    }),
+    device_specific: true,
+}
+
+phony {
+    name: "selinux_policy_system",
+    required: [
+        "29.0.compat.cil",
+        "30.0.compat.cil",
+        "31.0.compat.cil",
+        "32.0.compat.cil",
+        "33.0.compat.cil",
+        "34.0.compat.cil",
+        "build_sepolicy",
+        "fuzzer_bindings_test",
+        "plat_29.0.cil",
+        "plat_30.0.cil",
+        "plat_31.0.cil",
+        "plat_32.0.cil",
+        "plat_33.0.cil",
+        "plat_34.0.cil",
+        "plat_bug_map",
+        "plat_file_contexts",
+        "plat_file_contexts_data_test",
+        "plat_file_contexts_test",
+        "plat_hwservice_contexts",
+        "plat_hwservice_contexts_test",
+        "plat_keystore2_key_contexts",
+        "plat_mac_permissions.xml",
+        "plat_mapping_file",
+        "plat_property_contexts",
+        "plat_property_contexts_test",
+        "plat_seapp_contexts",
+        "plat_sepolicy.cil",
+        "plat_sepolicy_genfs_202504.cil",
+        "plat_service_contexts",
+        "plat_service_contexts_test",
+        "searchpolicy",
+        "secilc",
+    ] + select(soong_config_variable("ANDROID", "PLATFORM_SEPOLICY_VERSION"), {
+        "202404": [],
+        default: [
+            "202404.compat.cil",
+            "plat_202404.cil",
+        ],
+    }) + select(soong_config_variable("ANDROID", "PRODUCT_PRECOMPILED_SEPOLICY"), {
+        true: ["plat_sepolicy_and_mapping.sha256"],
+        default: [],
+    }) + select((
+        soong_config_variable("ANDROID", "ASAN_ENABLED"),
+        product_variable("selinux_ignore_neverallows"),
+    ), {
+        (true, true): [
+        ],
+        (default, default): [
+            "sepolicy_compat_test",
+            "sepolicy_test",
+            "sepolicy_dev_type_test",
+            "treble_sepolicy_tests_29.0",
+            "treble_sepolicy_tests_30.0",
+            "treble_sepolicy_tests_31.0",
+            "treble_sepolicy_tests_32.0",
+            "treble_sepolicy_tests_33.0",
+            "treble_sepolicy_tests_34.0",
+        ],
+    }) + select((
+        soong_config_variable("ANDROID", "PLATFORM_SEPOLICY_VERSION"),
+        soong_config_variable("ANDROID", "ASAN_ENABLED"),
+        product_variable("selinux_ignore_neverallows"),
+    ), {
+        ("202404", true, true): [],
+        (default, true, true): [],
+        (default, default, default): [
+            "treble_sepolicy_tests_202404",
+        ],
+    }) + select(soong_config_variable("ANDROID", "RELEASE_BOARD_API_LEVEL_FROZEN"), {
+        true: ["se_freeze_test"],
+        default: [],
+    }) + select(release_flag("RELEASE_AVF_ENABLE_VM_TO_TEE_SERVICES_ALLOWLIST"), {
+        true: ["plat_tee_service_contexts"],
+        default: [],
     }),
 }
+
+phony {
+    name: "selinux_policy",
+    required: [
+        // Runs checkfc against merged service_contexts files
+        "merged_hwservice_contexts_test",
+        "merged_service_contexts_test",
+        "selinux_policy_nonsystem",
+        "selinux_policy_system",
+    ],
+}
+
+// selinux_policy is a main goal and triggers lots of tests.
+// Most tests are FAKE modules, so aren'triggered on normal builds. (e.g. 'm')
+// By setting as droidcore's dependency, tests will run on normal builds.
+phony_rule {
+    name: "droidcore",
+    phony_deps: ["selinux_policy"],
+}
+
+//-----------------------------------------------------------------------------
+// TODO - remove this.   Keep around until we get the filesystem creation stuff
+// taken care of.
+//
+// The file_contexts.bin is built in the following way:
+// 1. Collect all file_contexts files in THIS repository and process them with
+//    m4 into a tmp file called file_contexts.local.tmp.
+// 2. Collect all device specific file_contexts files and process them with m4
+//    into a tmp file called file_contexts.device.tmp.
+// 3. Run checkfc -e (allow no device fc entries ie empty) and fc_sort on
+//    file_contexts.device.tmp and output to file_contexts.device.sorted.tmp.
+// 4. Concatenate file_contexts.local.tmp and  file_contexts.device.sorted.tmp
+//    into file_contexts.concat.tmp.
+// 5. Run checkfc and sefcontext_compile on file_contexts.concat.tmp to produce
+//    file_contexts.bin.
+//
+//  Note: That a newline file is placed between each file_context file found to
+//        ensure a proper build when an fc file is missing an ending newline.
+//---
+// 1. Collect all file_contexts files in THIS repository and process them with
+//    m4 into a tmp file called file_contexts.local.tmp.
+java_genrule {
+    name: "file_contexts.local.tmp",
+    srcs: [
+        ":plat_file_contexts",
+        ":system_ext_file_contexts",
+        ":product_file_contexts",
+    ],
+    tools: [
+        "m4",
+    ],
+    out: ["file_contexts.local.tmp"],
+    cmd: "$(location m4) --fatal-warnings " +
+        "-s $(in) > $(out)",
+}
+
+// 2. Collect all device specific file_contexts files and process them with m4
+//    into a tmp file called file_contexts.device.tmp.
+PRIVATE_ADDITIONAL_M4DEFS = select(soong_config_variable("ANDROID", "ADDITIONAL_M4DEFS"), {
+    any @ m4defs: m4defs,
+    default: "",
+})
+java_genrule {
+    name: "file_contexts.device.tmp",
+    srcs: [
+        ":vendor_file_contexts",
+        ":odm_file_contexts",
+    ],
+    tools: [
+        "m4",
+    ],
+    out: ["file_contexts.device.tmp"],
+    cmd: "$(location m4) --fatal-warnings " +
+        "-s " + PRIVATE_ADDITIONAL_M4DEFS +
+        " $(in) > $(out)",
+}
+
+// 3. Run checkfc -e (allow no device fc entries ie empty) and fc_sort on
+//    file_contexts.device.tmp and output to file_contexts.device.sorted.tmp.
+java_genrule {
+    name: "file_contexts.device.sorted.tmp",
+    srcs: [
+        ":file_contexts.device.tmp",
+        ":precompiled_sepolicy",
+    ],
+    tools: [
+        "checkfc",
+        "fc_sort",
+    ],
+    out: ["file_contexts.device.sorted.tmp"],
+    cmd: "$(location checkfc) " +
+        "-e $(location :precompiled_sepolicy) " +
+        "$(location :file_contexts.device.tmp) && " +
+        "$(location fc_sort) " +
+        "-i $(location :file_contexts.device.tmp) " +
+        "-o $(out)",
+}
+
+// 4. Concatenate file_contexts.local.tmp and  file_contexts.device.sorted.tmp
+//    into file_contexts.concat.tmp.
+java_genrule {
+    name: "file_contexts.concat.tmp",
+    srcs: [
+        ":file_contexts.local.tmp",
+        ":file_contexts.device.sorted.tmp",
+    ],
+    tools: [
+        "m4",
+    ],
+    out: ["file_contexts.concat.tmp"],
+    cmd: "$(location m4) --fatal-warnings " +
+        "-s $(location :file_contexts.local.tmp) " +
+        "$(location :file_contexts.device.sorted.tmp) > $(out)",
+}
+
+// 5. Run checkfc and sefcontext_compile on file_contexts.concat.tmp to produce
+//    file_contexts.bin.
+java_genrule {
+    name: "file_contexts_bin_gen",
+    srcs: [
+        ":file_contexts.concat.tmp",
+        ":precompiled_sepolicy",
+    ],
+    tools: [
+        "checkfc",
+        "sefcontext_compile",
+    ],
+    out: ["file_contexts.bin"],
+    cmd: "$(location checkfc) " +
+        "$(location :precompiled_sepolicy) " +
+        "$(location :file_contexts.concat.tmp) && " +
+        "$(location sefcontext_compile) " +
+        "-o $(out) $(location :file_contexts.concat.tmp)",
+}
+
+prebuilt_etc {
+    name: "file_contexts.bin",
+    src: ":file_contexts_bin_gen",
+}
diff --git a/Android.mk b/Android.mk
deleted file mode 100644
index efbae89af..000000000
--- a/Android.mk
+++ /dev/null
@@ -1,516 +0,0 @@
-LOCAL_PATH:= $(call my-dir)
-
-include $(CLEAR_VARS)
-
-ifdef BOARD_SEPOLICY_UNION
-$(warning BOARD_SEPOLICY_UNION is no longer required - all files found in BOARD_SEPOLICY_DIRS are implicitly unioned; please remove from your BoardConfig.mk or other .mk file.)
-endif
-
-ifdef BOARD_SEPOLICY_M4DEFS
-LOCAL_ADDITIONAL_M4DEFS := $(addprefix -D, $(BOARD_SEPOLICY_M4DEFS))
-else
-LOCAL_ADDITIONAL_M4DEFS :=
-endif
-
-# sepolicy is now divided into multiple portions:
-# public - policy exported on which non-platform policy developers may write
-#   additional policy.  types and attributes are versioned and included in
-#   delivered non-platform policy, which is to be combined with platform policy.
-# private - platform-only policy required for platform functionality but which
-#  is not exported to vendor policy developers and as such may not be assumed
-#  to exist.
-# vendor - vendor-only policy required for vendor functionality. This policy can
-#  reference the public policy but cannot reference the private policy. This
-#  policy is for components which are produced from the core/non-vendor tree and
-#  placed into a vendor partition.
-# mapping - This contains policy statements which map the attributes
-#  exposed in the public policy of previous versions to the concrete types used
-#  in this policy to ensure that policy targeting attributes from public
-#  policy from an older platform version continues to work.
-
-# build process for device:
-# 1) convert policies to CIL:
-#    - private + public platform policy to CIL
-#    - mapping file to CIL (should already be in CIL form)
-#    - non-platform public policy to CIL
-#    - non-platform public + private policy to CIL
-# 2) attributize policy
-#    - run script which takes non-platform public and non-platform combined
-#      private + public policy and produces attributized and versioned
-#      non-platform policy
-# 3) combine policy files
-#    - combine mapping, platform and non-platform policy.
-#    - compile output binary policy file
-
-PLAT_PUBLIC_POLICY := $(LOCAL_PATH)/public
-PLAT_PRIVATE_POLICY := $(LOCAL_PATH)/private
-PLAT_VENDOR_POLICY := $(LOCAL_PATH)/vendor
-REQD_MASK_POLICY := $(LOCAL_PATH)/reqd_mask
-
-SYSTEM_EXT_PUBLIC_POLICY := $(SYSTEM_EXT_PUBLIC_SEPOLICY_DIRS)
-SYSTEM_EXT_PRIVATE_POLICY := $(SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS)
-
-PRODUCT_PUBLIC_POLICY := $(PRODUCT_PUBLIC_SEPOLICY_DIRS)
-PRODUCT_PRIVATE_POLICY := $(PRODUCT_PRIVATE_SEPOLICY_DIRS)
-
-ifneq (,$(SYSTEM_EXT_PUBLIC_POLICY)$(SYSTEM_EXT_PRIVATE_POLICY))
-HAS_SYSTEM_EXT_SEPOLICY_DIR := true
-endif
-
-# TODO(b/119305624): Currently if the device doesn't have a product partition,
-# we install product sepolicy into /system/product. We do that because bits of
-# product sepolicy that's still in /system might depend on bits that have moved
-# to /product. Once we finish migrating product sepolicy out of system, change
-# it so that if no product partition is present, product sepolicy artifacts are
-# not built and installed at all.
-ifneq (,$(PRODUCT_PUBLIC_POLICY)$(PRODUCT_PRIVATE_POLICY))
-HAS_PRODUCT_SEPOLICY_DIR := true
-endif
-
-ifeq ($(SELINUX_IGNORE_NEVERALLOWS),true)
-ifeq ($(TARGET_BUILD_VARIANT),user)
-$(error SELINUX_IGNORE_NEVERALLOWS := true cannot be used in user builds)
-endif
-$(warning Be careful when using the SELINUX_IGNORE_NEVERALLOWS flag. \
-          It does not work in user builds and using it will \
-          not stop you from failing CTS.)
-endif
-
-# BOARD_SEPOLICY_DIRS was used for vendor/odm sepolicy customization before.
-# It has been replaced by BOARD_VENDOR_SEPOLICY_DIRS (mandatory) and
-# BOARD_ODM_SEPOLICY_DIRS (optional). BOARD_SEPOLICY_DIRS is still allowed for
-# backward compatibility, which will be merged into BOARD_VENDOR_SEPOLICY_DIRS.
-ifdef BOARD_SEPOLICY_DIRS
-BOARD_VENDOR_SEPOLICY_DIRS += $(BOARD_SEPOLICY_DIRS)
-endif
-
-###########################################################
-# Compute policy files to be used in policy build.
-# $(1): files to include
-# $(2): directories in which to find files
-###########################################################
-
-define build_policy
-$(strip $(foreach type, $(1), $(foreach file, $(addsuffix /$(type), $(2)), $(sort $(wildcard $(file))))))
-endef
-
-sepolicy_build_files := security_classes \
-                        initial_sids \
-                        access_vectors \
-                        global_macros \
-                        neverallow_macros \
-                        mls_macros \
-                        mls_decl \
-                        mls \
-                        policy_capabilities \
-                        te_macros \
-                        attributes \
-                        ioctl_defines \
-                        ioctl_macros \
-                        *.te \
-                        roles_decl \
-                        roles \
-                        users \
-                        initial_sid_contexts \
-                        fs_use \
-                        genfs_contexts \
-                        port_contexts
-
-sepolicy_compat_files := $(foreach ver, $(PLATFORM_SEPOLICY_COMPAT_VERSIONS), \
-                           $(addprefix compat/$(ver)/, $(addsuffix .cil, $(ver))))
-
-# Security classes and permissions defined outside of system/sepolicy.
-security_class_extension_files := $(call build_policy, security_classes access_vectors, \
-  $(SYSTEM_EXT_PUBLIC_POLICY) $(SYSTEM_EXT_PRIVATE_POLICY) \
-  $(PRODUCT_PUBLIC_POLICY) $(PRODUCT_PRIVATE_POLICY) \
-  $(BOARD_VENDOR_SEPOLICY_DIRS) $(BOARD_ODM_SEPOLICY_DIRS))
-
-ifneq (,$(strip $(security_class_extension_files)))
-  $(error Only platform SELinux policy may define classes and permissions: $(strip $(security_class_extension_files)))
-endif
-
-ifdef HAS_SYSTEM_EXT_SEPOLICY_DIR
-  # Checks if there are public system_ext policy files.
-  policy_files := $(call build_policy, $(sepolicy_build_files), $(SYSTEM_EXT_PUBLIC_POLICY))
-  ifneq (,$(strip $(policy_files)))
-    HAS_SYSTEM_EXT_PUBLIC_SEPOLICY := true
-  endif
-  # Checks if there are public/private system_ext policy files.
-  policy_files := $(call build_policy, $(sepolicy_build_files), $(SYSTEM_EXT_PUBLIC_POLICY) $(SYSTEM_EXT_PRIVATE_POLICY))
-  ifneq (,$(strip $(policy_files)))
-    HAS_SYSTEM_EXT_SEPOLICY := true
-  endif
-endif # ifdef HAS_SYSTEM_EXT_SEPOLICY_DIR
-
-ifdef HAS_PRODUCT_SEPOLICY_DIR
-  # Checks if there are public product policy files.
-  policy_files := $(call build_policy, $(sepolicy_build_files), $(PRODUCT_PUBLIC_POLICY))
-  ifneq (,$(strip $(policy_files)))
-    HAS_PRODUCT_PUBLIC_SEPOLICY := true
-  endif
-  # Checks if there are public/private product policy files.
-  policy_files := $(call build_policy, $(sepolicy_build_files), $(PRODUCT_PUBLIC_POLICY) $(PRODUCT_PRIVATE_POLICY))
-  ifneq (,$(strip $(policy_files)))
-    HAS_PRODUCT_SEPOLICY := true
-  endif
-endif # ifdef HAS_PRODUCT_SEPOLICY_DIR
-
-with_asan := false
-ifneq (,$(filter address,$(SANITIZE_TARGET)))
-  with_asan := true
-endif
-
-ifeq ($(PRODUCT_SHIPPING_API_LEVEL),)
-  #$(warning no product shipping level defined)
-else ifneq ($(call math_lt,29,$(PRODUCT_SHIPPING_API_LEVEL)),)
-  ifneq ($(BUILD_BROKEN_TREBLE_SYSPROP_NEVERALLOW),)
-    $(error BUILD_BROKEN_TREBLE_SYSPROP_NEVERALLOW cannot be set on a device shipping with R or later, and this is tested by CTS.)
-  endif
-endif
-
-ifeq ($(PRODUCT_SHIPPING_API_LEVEL),)
-  #$(warning no product shipping level defined)
-else ifneq ($(call math_lt,30,$(PRODUCT_SHIPPING_API_LEVEL)),)
-  ifneq ($(BUILD_BROKEN_ENFORCE_SYSPROP_OWNER),)
-    $(error BUILD_BROKEN_ENFORCE_SYSPROP_OWNER cannot be set on a device shipping with S or later, and this is tested by CTS.)
-  endif
-endif
-
-#################################
-
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := selinux_policy
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 legacy_unencumbered
-LOCAL_LICENSE_CONDITIONS := notice unencumbered
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-LOCAL_MODULE_TAGS := optional
-LOCAL_REQUIRED_MODULES += \
-    selinux_policy_nonsystem \
-    selinux_policy_system \
-
-# Runs checkfc against merged service_contexts files
-LOCAL_REQUIRED_MODULES += \
-    merged_service_contexts_test \
-    merged_hwservice_contexts_test
-
-include $(BUILD_PHONY_PACKAGE)
-
-# selinux_policy is a main goal and triggers lots of tests.
-# Most tests are FAKE modules, so aren'triggered on normal builds. (e.g. 'm')
-# By setting as droidcore's dependency, tests will run on normal builds.
-droidcore: selinux_policy
-
-include $(CLEAR_VARS)
-LOCAL_MODULE := selinux_policy_system
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 legacy_unencumbered
-LOCAL_LICENSE_CONDITIONS := notice unencumbered
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-# These build targets are not used on non-Treble devices. However, we build these to avoid
-# divergence between Treble and non-Treble devices.
-LOCAL_REQUIRED_MODULES += \
-    plat_mapping_file \
-    $(addprefix plat_,$(addsuffix .cil,$(PLATFORM_SEPOLICY_COMPAT_VERSIONS))) \
-    $(addsuffix .compat.cil,$(PLATFORM_SEPOLICY_COMPAT_VERSIONS)) \
-    plat_sepolicy.cil \
-    secilc \
-
-ifneq ($(PRODUCT_PRECOMPILED_SEPOLICY),false)
-LOCAL_REQUIRED_MODULES += plat_sepolicy_and_mapping.sha256
-endif
-
-LOCAL_REQUIRED_MODULES += \
-    build_sepolicy \
-    plat_file_contexts \
-    plat_file_contexts_test \
-    plat_keystore2_key_contexts \
-    plat_mac_permissions.xml \
-    plat_property_contexts \
-    plat_property_contexts_test \
-    plat_seapp_contexts \
-    plat_service_contexts \
-    plat_service_contexts_test \
-    plat_hwservice_contexts \
-    plat_hwservice_contexts_test \
-    fuzzer_bindings_test \
-    plat_bug_map \
-    searchpolicy \
-
-ifneq ($(with_asan),true)
-ifneq ($(SELINUX_IGNORE_NEVERALLOWS),true)
-LOCAL_REQUIRED_MODULES += \
-    sepolicy_compat_test \
-
-# HACK: sepolicy_test is implemented as genrule
-# genrule modules aren't installable, so LOCAL_REQUIRED_MODULES doesn't work.
-# Instead, use LOCAL_ADDITIONAL_DEPENDENCIES with intermediate output
-LOCAL_ADDITIONAL_DEPENDENCIES += $(call intermediates-dir-for,ETC,sepolicy_test)/sepolicy_test
-LOCAL_ADDITIONAL_DEPENDENCIES += $(call intermediates-dir-for,ETC,sepolicy_dev_type_test)/sepolicy_dev_type_test
-
-LOCAL_REQUIRED_MODULES += \
-    $(addprefix treble_sepolicy_tests_,$(PLATFORM_SEPOLICY_COMPAT_VERSIONS)) \
-
-endif  # SELINUX_IGNORE_NEVERALLOWS
-endif  # with_asan
-
-ifeq ($(RELEASE_BOARD_API_LEVEL_FROZEN),true)
-LOCAL_REQUIRED_MODULES += \
-    se_freeze_test
-endif
-
-include $(BUILD_PHONY_PACKAGE)
-
-#################################
-
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := selinux_policy_product
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 legacy_unencumbered
-LOCAL_LICENSE_CONDITIONS := notice unencumbered
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-# Include precompiled policy, unless told otherwise.
-ifneq ($(PRODUCT_PRECOMPILED_SEPOLICY),false)
-ifdef HAS_PRODUCT_SEPOLICY
-LOCAL_REQUIRED_MODULES += product_sepolicy_and_mapping.sha256
-endif
-endif
-
-ifdef HAS_PRODUCT_SEPOLICY
-LOCAL_REQUIRED_MODULES += product_sepolicy.cil
-endif
-
-ifdef HAS_PRODUCT_PUBLIC_SEPOLICY
-LOCAL_REQUIRED_MODULES += \
-    product_mapping_file
-
-product_compat_files := $(call build_policy, $(sepolicy_compat_files), $(PRODUCT_PRIVATE_POLICY))
-
-LOCAL_REQUIRED_MODULES += $(addprefix product_, $(notdir $(product_compat_files)))
-
-endif
-
-ifdef HAS_PRODUCT_SEPOLICY_DIR
-LOCAL_REQUIRED_MODULES += \
-    product_file_contexts \
-    product_file_contexts_test \
-    product_keystore2_key_contexts \
-    product_hwservice_contexts \
-    product_hwservice_contexts_test \
-    product_property_contexts \
-    product_property_contexts_test \
-    product_seapp_contexts \
-    product_service_contexts \
-    product_service_contexts_test \
-    product_mac_permissions.xml \
-
-endif
-
-include $(BUILD_PHONY_PACKAGE)
-
-#################################
-
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := selinux_policy_nonsystem
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 legacy_unencumbered
-LOCAL_LICENSE_CONDITIONS := notice unencumbered
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-# Include precompiled policy, unless told otherwise.
-ifneq ($(PRODUCT_PRECOMPILED_SEPOLICY),false)
-LOCAL_REQUIRED_MODULES += \
-    precompiled_sepolicy \
-    precompiled_sepolicy.plat_sepolicy_and_mapping.sha256
-
-ifdef HAS_SYSTEM_EXT_SEPOLICY
-LOCAL_REQUIRED_MODULES += precompiled_sepolicy.system_ext_sepolicy_and_mapping.sha256
-endif
-
-ifdef HAS_PRODUCT_SEPOLICY
-LOCAL_REQUIRED_MODULES += precompiled_sepolicy.product_sepolicy_and_mapping.sha256
-endif
-
-endif # ($(PRODUCT_PRECOMPILED_SEPOLICY),false)
-
-
-# These build targets are not used on non-Treble devices. However, we build these to avoid
-# divergence between Treble and non-Treble devices.
-LOCAL_REQUIRED_MODULES += \
-    plat_pub_versioned.cil \
-    vendor_sepolicy.cil \
-    plat_sepolicy_vers.txt \
-
-LOCAL_REQUIRED_MODULES += \
-    vendor_file_contexts \
-    vendor_file_contexts_test \
-    vendor_keystore2_key_contexts \
-    vendor_mac_permissions.xml \
-    vendor_property_contexts \
-    vendor_property_contexts_test \
-    vendor_seapp_contexts \
-    vendor_service_contexts \
-    vendor_service_contexts_test \
-    vendor_hwservice_contexts \
-    vendor_hwservice_contexts_test \
-    vendor_bug_map \
-    vndservice_contexts \
-    vndservice_contexts_test \
-
-ifdef BOARD_ODM_SEPOLICY_DIRS
-LOCAL_REQUIRED_MODULES += \
-    odm_sepolicy.cil \
-    odm_file_contexts \
-    odm_file_contexts_test \
-    odm_seapp_contexts \
-    odm_property_contexts \
-    odm_property_contexts_test \
-    odm_service_contexts \
-    odm_service_contexts_test \
-    odm_hwservice_contexts \
-    odm_hwservice_contexts_test \
-    odm_mac_permissions.xml
-endif
-
-LOCAL_REQUIRED_MODULES += selinux_policy_system_ext
-LOCAL_REQUIRED_MODULES += selinux_policy_product
-
-# Builds an addtional userdebug sepolicy into the debug ramdisk.
-LOCAL_REQUIRED_MODULES += \
-    userdebug_plat_sepolicy.cil \
-
-include $(BUILD_PHONY_PACKAGE)
-
-##################################
-# Policy files are now built with Android.bp. Grab them from intermediate.
-# See Android.bp for details of policy files.
-#
-built_sepolicy := $(call intermediates-dir-for,ETC,precompiled_sepolicy)/precompiled_sepolicy
-
-##################################
-# TODO - remove this.   Keep around until we get the filesystem creation stuff taken care of.
-#
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := file_contexts.bin
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 legacy_unencumbered
-LOCAL_LICENSE_CONDITIONS := notice unencumbered
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-LOCAL_MODULE_CLASS := ETC
-LOCAL_MODULE_TAGS := optional
-LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)
-
-include $(BUILD_SYSTEM)/base_rules.mk
-
-# The file_contexts.bin is built in the following way:
-# 1. Collect all file_contexts files in THIS repository and process them with
-#    m4 into a tmp file called file_contexts.local.tmp.
-# 2. Collect all device specific file_contexts files and process them with m4
-#    into a tmp file called file_contexts.device.tmp.
-# 3. Run checkfc -e (allow no device fc entries ie empty) and fc_sort on
-#    file_contexts.device.tmp and output to file_contexts.device.sorted.tmp.
-# 4. Concatenate file_contexts.local.tmp and  file_contexts.device.sorted.tmp
-#    into file_contexts.concat.tmp.
-# 5. Run checkfc and sefcontext_compile on file_contexts.concat.tmp to produce
-#    file_contexts.bin.
-#
-#  Note: That a newline file is placed between each file_context file found to
-#        ensure a proper build when an fc file is missing an ending newline.
-
-local_fc_files := $(call intermediates-dir-for,ETC,plat_file_contexts)/plat_file_contexts
-
-ifdef HAS_SYSTEM_EXT_SEPOLICY_DIR
-local_fc_files += $(call intermediates-dir-for,ETC,system_ext_file_contexts)/system_ext_file_contexts
-endif
-
-ifdef HAS_PRODUCT_SEPOLICY_DIR
-local_fc_files += $(call intermediates-dir-for,ETC,product_file_contexts)/product_file_contexts
-endif
-
-###########################################################
-## Collect file_contexts files into a single tmp file with m4
-##
-## $(1): list of file_contexts files
-## $(2): filename into which file_contexts files are merged
-###########################################################
-
-define _merge-fc-files
-$(2): $(1) $(M4)
-	$(hide) mkdir -p $$(dir $$@)
-	$(hide) $(M4) --fatal-warnings -s $(1) > $$@
-endef
-
-define merge-fc-files
-$(eval $(call _merge-fc-files,$(1),$(2)))
-endef
-
-file_contexts.local.tmp := $(intermediates)/file_contexts.local.tmp
-$(call merge-fc-files,$(local_fc_files),$(file_contexts.local.tmp))
-
-device_fc_files += $(call intermediates-dir-for,ETC,vendor_file_contexts)/vendor_file_contexts
-
-ifdef BOARD_ODM_SEPOLICY_DIRS
-device_fc_files += $(call intermediates-dir-for,ETC,odm_file_contexts)/odm_file_contexts
-endif
-
-file_contexts.device.tmp := $(intermediates)/file_contexts.device.tmp
-$(file_contexts.device.tmp): PRIVATE_ADDITIONAL_M4DEFS := $(LOCAL_ADDITIONAL_M4DEFS)
-$(file_contexts.device.tmp): PRIVATE_DEVICE_FC_FILES := $(device_fc_files)
-$(file_contexts.device.tmp): $(device_fc_files) $(M4)
-	@mkdir -p $(dir $@)
-	$(hide) $(M4) --fatal-warnings -s $(PRIVATE_ADDITIONAL_M4DEFS) $(PRIVATE_DEVICE_FC_FILES) > $@
-
-file_contexts.device.sorted.tmp := $(intermediates)/file_contexts.device.sorted.tmp
-$(file_contexts.device.sorted.tmp): PRIVATE_SEPOLICY := $(built_sepolicy)
-$(file_contexts.device.sorted.tmp): $(file_contexts.device.tmp) $(built_sepolicy) \
-  $(HOST_OUT_EXECUTABLES)/fc_sort $(HOST_OUT_EXECUTABLES)/checkfc
-	@mkdir -p $(dir $@)
-	$(hide) $(HOST_OUT_EXECUTABLES)/checkfc -e $(PRIVATE_SEPOLICY) $<
-	$(hide) $(HOST_OUT_EXECUTABLES)/fc_sort -i $< -o $@
-
-file_contexts.concat.tmp := $(intermediates)/file_contexts.concat.tmp
-$(call merge-fc-files,\
-  $(file_contexts.local.tmp) $(file_contexts.device.sorted.tmp),$(file_contexts.concat.tmp))
-
-$(LOCAL_BUILT_MODULE): PRIVATE_SEPOLICY := $(built_sepolicy)
-$(LOCAL_BUILT_MODULE): $(file_contexts.concat.tmp) $(built_sepolicy) $(HOST_OUT_EXECUTABLES)/sefcontext_compile $(HOST_OUT_EXECUTABLES)/checkfc
-	@mkdir -p $(dir $@)
-	$(hide) $(HOST_OUT_EXECUTABLES)/checkfc $(PRIVATE_SEPOLICY) $<
-	$(hide) $(HOST_OUT_EXECUTABLES)/sefcontext_compile -o $@ $<
-
-local_fc_files :=
-device_fc_files :=
-file_contexts.concat.tmp :=
-file_contexts.device.sorted.tmp :=
-file_contexts.device.tmp :=
-file_contexts.local.tmp :=
-
-##################################
-# Tests for Treble compatibility of current platform policy and vendor policy of
-# given release version.
-
-ver := $(PLATFORM_SEPOLICY_VERSION)
-ifneq ($(wildcard $(LOCAL_PATH)/prebuilts/api/$(PLATFORM_SEPOLICY_VERSION)),)
-# If PLATFORM_SEPOLICY_VERSION is already frozen, use prebuilts for compat test
-base_plat_pub_policy.cil    := $(call intermediates-dir-for,ETC,$(ver)_plat_pub_policy.cil)/$(ver)_plat_pub_policy.cil
-base_product_pub_policy.cil := $(call intermediates-dir-for,ETC,$(ver)_product_pub_policy.cil)/$(ver)_product_pub_policy.cil
-else
-# If not, use ToT for compat test
-base_plat_pub_policy.cil    := $(call intermediates-dir-for,ETC,base_plat_pub_policy.cil)/base_plat_pub_policy.cil
-base_product_pub_policy.cil := $(call intermediates-dir-for,ETC,base_product_pub_policy.cil)/base_product_pub_policy.cil
-endif
-ver :=
-
-$(foreach v,$(PLATFORM_SEPOLICY_COMPAT_VERSIONS), \
-  $(eval version_under_treble_tests := $(v)) \
-  $(eval include $(LOCAL_PATH)/treble_sepolicy_tests_for_release.mk) \
-)
-
-base_plat_pub_policy.cil :=
-base_product_pub_policy.cil :=
-
-#################################
-
-
-build_policy :=
-built_sepolicy :=
-sepolicy_build_files :=
-with_asan :=
diff --git a/apex/Android.bp b/apex/Android.bp
index a6d08536f..37400ddb3 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -155,6 +155,13 @@ filegroup {
     ],
 }
 
+filegroup {
+    name: "com.android.nfcservices-file_contexts",
+    srcs: [
+        "com.android.nfcservices-file_contexts",
+    ],
+}
+
 filegroup {
     name: "com.android.os.statsd-file_contexts",
     srcs: [
@@ -314,3 +321,17 @@ filegroup {
         "com.android.biometrics.virtual.face-file_contexts",
     ],
 }
+
+filegroup {
+    name: "com.android.documentsuibundle-file_contexts",
+    srcs: [
+        "com.android.documentsuibundle-file_contexts",
+    ],
+}
+
+filegroup {
+    name: "com.android.profiling-file_contexts",
+    srcs: [
+        "com.android.profiling-file_contexts",
+    ],
+}
diff --git a/apex/com.android.configinfrastructure-file_contexts b/apex/com.android.configinfrastructure-file_contexts
index 23e7b890e..de745474f 100644
--- a/apex/com.android.configinfrastructure-file_contexts
+++ b/apex/com.android.configinfrastructure-file_contexts
@@ -1 +1,2 @@
-(/.*)?                   u:object_r:system_file:s0
\ No newline at end of file
+(/.*)?                   u:object_r:system_file:s0
+/bin/aconfigd-mainline   u:object_r:aconfigd_mainline_exec:s0
diff --git a/apex/com.android.documentsuibundle-file_contexts b/apex/com.android.documentsuibundle-file_contexts
new file mode 100644
index 000000000..f6b21daaa
--- /dev/null
+++ b/apex/com.android.documentsuibundle-file_contexts
@@ -0,0 +1,2 @@
+(/.*)?                u:object_r:system_file:s0
+/lib(64)?(/.*)        u:object_r:system_lib_file:s0
diff --git a/apex/com.android.profiling-file_contexts b/apex/com.android.profiling-file_contexts
new file mode 100644
index 000000000..796becaf6
--- /dev/null
+++ b/apex/com.android.profiling-file_contexts
@@ -0,0 +1,2 @@
+(/.*)?               u:object_r:system_file:s0
+/bin/trace_redactor  u:object_r:trace_redactor_exec:s0
diff --git a/apex/com.android.uprobestats-file_contexts b/apex/com.android.uprobestats-file_contexts
index 01de3e2a5..994951b15 100644
--- a/apex/com.android.uprobestats-file_contexts
+++ b/apex/com.android.uprobestats-file_contexts
@@ -1,3 +1,3 @@
 (/.*)?                         u:object_r:system_file:s0
 /bin/uprobestats               u:object_r:uprobestats_exec:s0
-
+/bin/uprobestatsbpfload        u:object_r:bpfloader_exec:s0
diff --git a/apex/com.android.wifi-file_contexts b/apex/com.android.wifi-file_contexts
index f3a65d43a..2355fcaff 100644
--- a/apex/com.android.wifi-file_contexts
+++ b/apex/com.android.wifi-file_contexts
@@ -1 +1,2 @@
 (/.*)?                u:object_r:system_file:s0
+/bin/wpa_supplicant_mainline       u:object_r:wifi_mainline_supplicant_exec:s0
diff --git a/build/soong/compat_cil.go b/build/soong/compat_cil.go
index fef2e6910..33c6d3b61 100644
--- a/build/soong/compat_cil.go
+++ b/build/soong/compat_cil.go
@@ -29,7 +29,7 @@ var (
 func init() {
 	ctx := android.InitRegistrationContext
 	ctx.RegisterModuleType("se_compat_cil", compatCilFactory)
-	ctx.RegisterParallelSingletonModuleType("se_compat_test", compatTestFactory)
+	ctx.RegisterModuleType("se_compat_test", compatTestFactory)
 }
 
 // se_compat_cil collects and installs backwards compatibility cil files.
@@ -116,10 +116,10 @@ func (c *compatCil) AndroidMkEntries() []android.AndroidMkEntries {
 
 // se_compat_test checks if compat files ({ver}.cil, {ver}.compat.cil) files are compatible with
 // current policy.
-func compatTestFactory() android.SingletonModule {
+func compatTestFactory() android.Module {
 	f := &compatTestModule{}
 	f.AddProperties(&f.properties)
-	android.InitAndroidModule(f)
+	android.InitAndroidArchModule(f, android.DeviceSupported, android.MultilibCommon)
 	android.AddLoadHook(f, func(ctx android.LoadHookContext) {
 		f.loadHook(ctx)
 	})
@@ -127,7 +127,7 @@ func compatTestFactory() android.SingletonModule {
 }
 
 type compatTestModule struct {
-	android.SingletonModuleBase
+	android.ModuleBase
 	properties struct {
 		// Default modules for conf
 		Defaults []string
@@ -180,11 +180,11 @@ func (f *compatTestModule) DepsMutator(ctx android.BottomUpMutatorContext) {
 	}
 }
 
-func (f *compatTestModule) GenerateSingletonBuildActions(ctx android.SingletonContext) {
-	// does nothing; se_compat_test is a singeton because two compat test modules don't make sense.
-}
-
 func (f *compatTestModule) GenerateAndroidBuildActions(ctx android.ModuleContext) {
+	if ctx.ModuleName() != "sepolicy_compat_test" || ctx.ModuleDir() != "system/sepolicy/compat" {
+		// two compat test modules don't make sense.
+		ctx.ModuleErrorf("There can only be 1 se_compat_test module named sepolicy_compat_test in system/sepolicy/compat")
+	}
 	var inputs android.Paths
 	ctx.VisitDirectDepsWithTag(compatTestDepTag, func(child android.Module) {
 		outputs := android.OutputFilesForModule(ctx, child, "")
diff --git a/build/soong/selinux_contexts.go b/build/soong/selinux_contexts.go
index fd1cd3422..c96dda58b 100644
--- a/build/soong/selinux_contexts.go
+++ b/build/soong/selinux_contexts.go
@@ -91,6 +91,7 @@ func init() {
 	android.RegisterModuleType("keystore2_key_contexts", keystoreKeyFactory)
 	android.RegisterModuleType("seapp_contexts", seappFactory)
 	android.RegisterModuleType("vndservice_contexts", vndServiceFactory)
+	android.RegisterModuleType("tee_service_contexts", teeServiceFactory)
 
 	android.RegisterModuleType("file_contexts_test", fileContextsTestFactory)
 	android.RegisterModuleType("property_contexts_test", propertyContextsTestFactory)
@@ -228,46 +229,46 @@ func (m *selinuxContextsModule) AndroidMk() android.AndroidMkData {
 	}
 }
 
-func (m *selinuxContextsModule) ImageMutatorBegin(ctx android.BaseModuleContext) {
+func (m *selinuxContextsModule) ImageMutatorBegin(ctx android.ImageInterfaceContext) {
 	if proptools.Bool(m.properties.Recovery_available) && m.ModuleBase.InstallInRecovery() {
 		ctx.PropertyErrorf("recovery_available",
 			"doesn't make sense at the same time as `recovery: true`")
 	}
 }
 
-func (m *selinuxContextsModule) VendorVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *selinuxContextsModule) VendorVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return false
 }
 
-func (m *selinuxContextsModule) ProductVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *selinuxContextsModule) ProductVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return false
 }
 
-func (m *selinuxContextsModule) CoreVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *selinuxContextsModule) CoreVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return !m.ModuleBase.InstallInRecovery()
 }
 
-func (m *selinuxContextsModule) RamdiskVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *selinuxContextsModule) RamdiskVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return false
 }
 
-func (m *selinuxContextsModule) VendorRamdiskVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *selinuxContextsModule) VendorRamdiskVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return false
 }
 
-func (m *selinuxContextsModule) DebugRamdiskVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *selinuxContextsModule) DebugRamdiskVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return false
 }
 
-func (m *selinuxContextsModule) RecoveryVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *selinuxContextsModule) RecoveryVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return m.ModuleBase.InstallInRecovery() || proptools.Bool(m.properties.Recovery_available)
 }
 
-func (m *selinuxContextsModule) ExtraImageVariations(ctx android.BaseModuleContext) []string {
+func (m *selinuxContextsModule) ExtraImageVariations(ctx android.ImageInterfaceContext) []string {
 	return nil
 }
 
-func (m *selinuxContextsModule) SetImageVariation(ctx android.BaseModuleContext, variation string) {
+func (m *selinuxContextsModule) SetImageVariation(ctx android.ImageInterfaceContext, variation string) {
 }
 
 var _ android.ImageInterface = (*selinuxContextsModule)(nil)
@@ -538,6 +539,12 @@ func keystoreKeyFactory() android.Module {
 	return m
 }
 
+func teeServiceFactory() android.Module {
+	m := newModule()
+	m.build = m.buildGeneralContexts
+	return m
+}
+
 func seappFactory() android.Module {
 	m := newModule()
 	m.build = m.buildSeappContexts
@@ -716,42 +723,42 @@ func (m *contextsTestModule) AndroidMkEntries() []android.AndroidMkEntries {
 
 // contextsTestModule implements ImageInterface to be able to include recovery_available contexts
 // modules as its sources.
-func (m *contextsTestModule) ImageMutatorBegin(ctx android.BaseModuleContext) {
+func (m *contextsTestModule) ImageMutatorBegin(ctx android.ImageInterfaceContext) {
 }
 
-func (m *contextsTestModule) VendorVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *contextsTestModule) VendorVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return false
 }
 
-func (m *contextsTestModule) ProductVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *contextsTestModule) ProductVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return false
 }
 
-func (m *contextsTestModule) CoreVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *contextsTestModule) CoreVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return true
 }
 
-func (m *contextsTestModule) RamdiskVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *contextsTestModule) RamdiskVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return false
 }
 
-func (m *contextsTestModule) VendorRamdiskVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *contextsTestModule) VendorRamdiskVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return false
 }
 
-func (m *contextsTestModule) DebugRamdiskVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *contextsTestModule) DebugRamdiskVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return false
 }
 
-func (m *contextsTestModule) RecoveryVariantNeeded(ctx android.BaseModuleContext) bool {
+func (m *contextsTestModule) RecoveryVariantNeeded(ctx android.ImageInterfaceContext) bool {
 	return false
 }
 
-func (m *contextsTestModule) ExtraImageVariations(ctx android.BaseModuleContext) []string {
+func (m *contextsTestModule) ExtraImageVariations(ctx android.ImageInterfaceContext) []string {
 	return nil
 }
 
-func (m *contextsTestModule) SetImageVariation(ctx android.BaseModuleContext, variation string) {
+func (m *contextsTestModule) SetImageVariation(ctx android.ImageInterfaceContext, variation string) {
 }
 
 var _ android.ImageInterface = (*contextsTestModule)(nil)
diff --git a/build/soong/sepolicy_freeze.go b/build/soong/sepolicy_freeze.go
index d6f4f3c98..41d460d27 100644
--- a/build/soong/sepolicy_freeze.go
+++ b/build/soong/sepolicy_freeze.go
@@ -25,15 +25,15 @@ var prebuiltCilTag = dependencyTag{name: "prebuilt_cil"}
 
 func init() {
 	ctx := android.InitRegistrationContext
-	ctx.RegisterParallelSingletonModuleType("se_freeze_test", freezeTestFactory)
+	ctx.RegisterModuleType("se_freeze_test", freezeTestFactory)
 }
 
 // se_freeze_test compares the plat sepolicy with the prebuilt sepolicy.  Additional directories can
 // be specified via Makefile variables: SEPOLICY_FREEZE_TEST_EXTRA_DIRS and
 // SEPOLICY_FREEZE_TEST_EXTRA_PREBUILT_DIRS.
-func freezeTestFactory() android.SingletonModule {
+func freezeTestFactory() android.Module {
 	f := &freezeTestModule{}
-	android.InitAndroidModule(f)
+	android.InitAndroidArchModule(f, android.DeviceSupported, android.MultilibCommon)
 	android.AddLoadHook(f, func(ctx android.LoadHookContext) {
 		f.loadHook(ctx)
 	})
@@ -41,7 +41,7 @@ func freezeTestFactory() android.SingletonModule {
 }
 
 type freezeTestModule struct {
-	android.SingletonModuleBase
+	android.ModuleBase
 	freezeTestTimestamp android.ModuleOutPath
 }
 
@@ -82,10 +82,6 @@ func (f *freezeTestModule) DepsMutator(ctx android.BottomUpMutatorContext) {
 	ctx.AddDependency(f, prebuiltCilTag, f.prebuiltCilModuleName(ctx))
 }
 
-func (f *freezeTestModule) GenerateSingletonBuildActions(ctx android.SingletonContext) {
-	// does nothing; se_freeze_test is a singeton because two freeze test modules don't make sense.
-}
-
 func (f *freezeTestModule) outputFileOfDep(ctx android.ModuleContext, depTag dependencyTag) android.Path {
 	deps := ctx.GetDirectDepsWithTag(depTag)
 	if len(deps) != 1 {
@@ -104,6 +100,11 @@ func (f *freezeTestModule) outputFileOfDep(ctx android.ModuleContext, depTag dep
 }
 
 func (f *freezeTestModule) GenerateAndroidBuildActions(ctx android.ModuleContext) {
+	if ctx.ModuleName() != "se_freeze_test" || ctx.ModuleDir() != "system/sepolicy" {
+		// two freeze test modules don't make sense.
+		ctx.ModuleErrorf("There can only be 1 se_freeze_test module named se_freeze_test in system/sepolicy")
+	}
+
 	f.freezeTestTimestamp = android.PathForModuleOut(ctx, "freeze_test")
 
 	if !f.shouldRunTest(ctx) {
diff --git a/build/soong/sepolicy_neverallow.go b/build/soong/sepolicy_neverallow.go
index 78cbc8421..c2a21dd3d 100644
--- a/build/soong/sepolicy_neverallow.go
+++ b/build/soong/sepolicy_neverallow.go
@@ -57,7 +57,7 @@ var sepolicyAnalyzeTag = dependencyTag{name: "sepolicy_analyze"}
 func neverallowTestFactory() android.Module {
 	n := &neverallowTestModule{}
 	n.AddProperties(&n.properties)
-	android.InitAndroidModule(n)
+	android.InitAndroidArchModule(n, android.DeviceSupported, android.MultilibCommon)
 	android.AddLoadHook(n, func(ctx android.LoadHookContext) {
 		n.loadHook(ctx)
 	})
diff --git a/build/soong/service_fuzzer_bindings.go b/build/soong/service_fuzzer_bindings.go
index 28bafa45a..39f414c10 100644
--- a/build/soong/service_fuzzer_bindings.go
+++ b/build/soong/service_fuzzer_bindings.go
@@ -56,6 +56,7 @@ var (
 		"android.hardware.bluetooth.finder.IBluetoothFinder/default":              EXCEPTION_NO_FUZZER,
 		"android.hardware.bluetooth.ranging.IBluetoothChannelSounding/default":    EXCEPTION_NO_FUZZER,
 		"android.hardware.bluetooth.lmp_event.IBluetoothLmpEvent/default":         EXCEPTION_NO_FUZZER,
+		"android.hardware.bluetooth.socket.IBluetoothSocket/default":              []string{"android.hardware.bluetooth.socket-service_fuzzer"},
 		"android.hardware.camera.provider.ICameraProvider/internal/0":             EXCEPTION_NO_FUZZER,
 		"android.hardware.camera.provider.ICameraProvider/virtual/0":              EXCEPTION_NO_FUZZER,
 		"android.hardware.cas.IMediaCasService/default":                           EXCEPTION_NO_FUZZER,
@@ -139,6 +140,7 @@ var (
 		"android.hardware.tv.hdmi.connection.IHdmiConnection/default":             EXCEPTION_NO_FUZZER,
 		"android.hardware.tv.hdmi.earc.IEArc/default":                             EXCEPTION_NO_FUZZER,
 		"android.hardware.tv.input.ITvInput/default":                              EXCEPTION_NO_FUZZER,
+		"android.hardware.tv.mediaquality.IMediaQuality/default":                  EXCEPTION_NO_FUZZER,
 		"android.hardware.tv.tuner.ITuner/default":                                EXCEPTION_NO_FUZZER,
 		"android.hardware.usb.IUsb/default":                                       EXCEPTION_NO_FUZZER,
 		"android.hardware.usb.gadget.IUsbGadget/default":                          EXCEPTION_NO_FUZZER,
@@ -150,6 +152,7 @@ var (
 		"android.hardware.wifi.hostapd.IHostapd/default":                          EXCEPTION_NO_FUZZER,
 		"android.hardware.wifi.supplicant.ISupplicant/default":                    EXCEPTION_NO_FUZZER,
 		"android.frameworks.cameraservice.service.ICameraService/default":         EXCEPTION_NO_FUZZER,
+		"android.frameworks.devicestate.IDeviceStateService/default":              EXCEPTION_NO_FUZZER,
 		"android.frameworks.location.altitude.IAltitudeService/default":           EXCEPTION_NO_FUZZER,
 		"android.frameworks.sensorservice.ISensorManager/default":                 []string{"libsensorserviceaidl_fuzzer"},
 		"android.frameworks.stats.IStats/default":                                 EXCEPTION_NO_FUZZER,
@@ -162,9 +165,9 @@ var (
 		"account":             EXCEPTION_NO_FUZZER,
 		"activity":            EXCEPTION_NO_FUZZER,
 		"activity_task":       EXCEPTION_NO_FUZZER,
-		"adaptive_auth":       EXCEPTION_NO_FUZZER,
 		"adb":                 EXCEPTION_NO_FUZZER,
 		"adservices_manager":  EXCEPTION_NO_FUZZER,
+		"advanced_protection": EXCEPTION_NO_FUZZER,
 		"aidl_lazy_test_1":    EXCEPTION_NO_FUZZER,
 		"aidl_lazy_test_2":    EXCEPTION_NO_FUZZER,
 		"aidl_lazy_test_quit": EXCEPTION_NO_FUZZER,
@@ -204,6 +207,7 @@ var (
 		"apexservice":                   EXCEPTION_NO_FUZZER,
 		"archive":                       EXCEPTION_NO_FUZZER,
 		"attestation_verification":      EXCEPTION_NO_FUZZER,
+		"authentication_policy":         EXCEPTION_NO_FUZZER,
 		"blob_store":                    EXCEPTION_NO_FUZZER,
 		"gsiservice":                    EXCEPTION_NO_FUZZER,
 		"appops":                        EXCEPTION_NO_FUZZER,
@@ -275,6 +279,7 @@ var (
 		"dropbox":                       EXCEPTION_NO_FUZZER,
 		"dumpstate":                     EXCEPTION_NO_FUZZER,
 		"dynamic_system":                EXCEPTION_NO_FUZZER,
+		"dynamic_instrumentation":       EXCEPTION_NO_FUZZER,
 		"econtroller":                   EXCEPTION_NO_FUZZER,
 		"ecm_enhanced_confirmation":     EXCEPTION_NO_FUZZER,
 		"emergency_affordance":          EXCEPTION_NO_FUZZER,
@@ -286,6 +291,7 @@ var (
 		"fingerprint":                   EXCEPTION_NO_FUZZER,
 		"feature_flags":                 EXCEPTION_NO_FUZZER,
 		"font":                          EXCEPTION_NO_FUZZER,
+		"forensic":                      EXCEPTION_NO_FUZZER,
 		"android.hardware.fingerprint.IFingerprintDaemon": EXCEPTION_NO_FUZZER,
 		"game":                                   EXCEPTION_NO_FUZZER,
 		"gfxinfo":                                EXCEPTION_NO_FUZZER,
@@ -304,6 +310,7 @@ var (
 		"inputflinger":                           EXCEPTION_NO_FUZZER,
 		"input_method":                           EXCEPTION_NO_FUZZER,
 		"input":                                  EXCEPTION_NO_FUZZER,
+		"intrusion_detection":                    EXCEPTION_NO_FUZZER,
 		"installd":                               []string{"installd_service_fuzzer"},
 		"iphonesubinfo_msim":                     EXCEPTION_NO_FUZZER,
 		"iphonesubinfo2":                         EXCEPTION_NO_FUZZER,
@@ -349,12 +356,14 @@ var (
 		"media_communication":                    EXCEPTION_NO_FUZZER,
 		"media_metrics":                          EXCEPTION_NO_FUZZER,
 		"media_projection":                       EXCEPTION_NO_FUZZER,
+		"media_quality":                          EXCEPTION_NO_FUZZER,
 		"media_resource_monitor":                 EXCEPTION_NO_FUZZER,
 		"media_router":                           EXCEPTION_NO_FUZZER,
 		"media_session":                          EXCEPTION_NO_FUZZER,
 		"meminfo":                                EXCEPTION_NO_FUZZER,
 		"memtrack.proxy":                         EXCEPTION_NO_FUZZER,
 		"midi":                                   EXCEPTION_NO_FUZZER,
+		"mmd":                                    EXCEPTION_NO_FUZZER,
 		"mount":                                  EXCEPTION_NO_FUZZER,
 		"music_recognition":                      EXCEPTION_NO_FUZZER,
 		"nearby":                                 EXCEPTION_NO_FUZZER,
@@ -409,6 +418,7 @@ var (
 		"restrictions":                           EXCEPTION_NO_FUZZER,
 		"rkpd.registrar":                         EXCEPTION_NO_FUZZER,
 		"rkpd.refresh":                           EXCEPTION_NO_FUZZER,
+		"rkp_cert_processor.service":             EXCEPTION_NO_FUZZER,
 		"role":                                   EXCEPTION_NO_FUZZER,
 		"rollback":                               EXCEPTION_NO_FUZZER,
 		"rttmanager":                             EXCEPTION_NO_FUZZER,
@@ -471,6 +481,7 @@ var (
 		"time_zone_detector":                     EXCEPTION_NO_FUZZER,
 		"thermalservice":                         EXCEPTION_NO_FUZZER,
 		"tracing.proxy":                          EXCEPTION_NO_FUZZER,
+		"tradeinmode":                            EXCEPTION_NO_FUZZER,
 		"translation":                            EXCEPTION_NO_FUZZER,
 		"transparency":                           EXCEPTION_NO_FUZZER,
 		"trust":                                  EXCEPTION_NO_FUZZER,
@@ -506,7 +517,9 @@ var (
 		"wifi":                                   EXCEPTION_NO_FUZZER,
 		"wifinl80211":                            []string{"wificond_service_fuzzer"},
 		"wifiaware":                              EXCEPTION_NO_FUZZER,
+		"wifi_usd":                               EXCEPTION_NO_FUZZER,
 		"wifirtt":                                EXCEPTION_NO_FUZZER,
+		"wifi_mainline_supplicant":               []string{"mainline_supplicant_service_fuzzer"},
 		"window":                                 EXCEPTION_NO_FUZZER,
 		"*":                                      EXCEPTION_NO_FUZZER,
 	}
diff --git a/compat/Android.bp b/compat/Android.bp
index f09fb2137..28936dd53 100644
--- a/compat/Android.bp
+++ b/compat/Android.bp
@@ -585,3 +585,9 @@ se_compat_cil {
     system_ext_specific: true,
     version: "202404",
 }
+
+prebuilt_etc {
+    name: "plat_sepolicy_genfs_202504.cil",
+    src: "plat_sepolicy_genfs_202504.cil",
+    relative_install_path: "selinux",
+}
diff --git a/compat/libgenfslabelsversion/Android.bp b/compat/libgenfslabelsversion/Android.bp
new file mode 100644
index 000000000..7f512a7be
--- /dev/null
+++ b/compat/libgenfslabelsversion/Android.bp
@@ -0,0 +1,35 @@
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
+package {
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "system_sepolicy_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-Apache-2.0
+    default_applicable_licenses: ["system_sepolicy_license"],
+}
+
+rust_defaults {
+    name: "libgenfslabelsversion.default",
+    crate_name: "genfslabelsversion",
+    srcs: ["src/lib.rs"],
+    apex_available: ["//apex_available:platform"],
+}
+
+rust_ffi_static {
+    name: "libgenfslabelsversion.ffi",
+    defaults: ["libgenfslabelsversion.default"],
+    export_include_dirs: ["include"],
+}
diff --git a/compat/libgenfslabelsversion/include/genfslabelsversion.h b/compat/libgenfslabelsversion/include/genfslabelsversion.h
new file mode 100644
index 000000000..4c029c83b
--- /dev/null
+++ b/compat/libgenfslabelsversion/include/genfslabelsversion.h
@@ -0,0 +1,27 @@
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
+#pragma once
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+int get_genfs_labels_version();
+
+#ifdef __cplusplus
+}
+#endif
diff --git a/compat/libgenfslabelsversion/src/lib.rs b/compat/libgenfslabelsversion/src/lib.rs
new file mode 100644
index 000000000..21619e8c4
--- /dev/null
+++ b/compat/libgenfslabelsversion/src/lib.rs
@@ -0,0 +1,40 @@
+// Copyright 2024 The Android Open Source Project
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
+//! Client library to read genfs labels version of the vendor.
+
+use std::fs;
+
+const GENFS_LABELS_VERSION_TXT_PATH: &str = "/vendor/etc/selinux/genfs_labels_version.txt";
+const DEFAULT_GENFS_LABELS_VERSION: i32 = 202404;
+
+/// Get genfs labels version from the vendor partition.
+///
+/// This function reads the genfs labels version from the file
+/// `/vendor/etc/selinux/genfs_labels_version.txt`. If the file does not exist or
+/// cannot be parsed, it returns a default version of 202404.
+///
+/// # Returns
+///
+/// The genfs labels version as an integer.
+#[no_mangle]
+pub extern "C" fn get_genfs_labels_version() -> i32 {
+    match fs::read_to_string(GENFS_LABELS_VERSION_TXT_PATH) {
+        Ok(contents) => match contents.trim().parse::<i32>() {
+            Ok(version) => version,
+            Err(_) => DEFAULT_GENFS_LABELS_VERSION,
+        },
+        Err(_) => DEFAULT_GENFS_LABELS_VERSION,
+    }
+}
diff --git a/compat/plat_sepolicy_genfs_202504.cil b/compat/plat_sepolicy_genfs_202504.cil
new file mode 100644
index 000000000..79cc73247
--- /dev/null
+++ b/compat/plat_sepolicy_genfs_202504.cil
@@ -0,0 +1 @@
+(genfscon sysfs "/class/udc" (u object_r sysfs_udc ((s0) (s0))))
diff --git a/contexts/Android.bp b/contexts/Android.bp
index 850601f59..08a4f6483 100644
--- a/contexts/Android.bp
+++ b/contexts/Android.bp
@@ -68,6 +68,11 @@ se_build_files {
     srcs: ["vndservice_contexts"],
 }
 
+se_build_files {
+    name: "tee_service_contexts_files",
+    srcs: ["tee_service_contexts"],
+}
+
 file_contexts {
     name: "plat_file_contexts",
     defaults: ["contexts_flags_defaults"],
@@ -614,3 +619,34 @@ fuzzer_bindings_test {
     name: "fuzzer_bindings_test",
     srcs: [":plat_service_contexts"],
 }
+
+tee_service_contexts {
+    name: "plat_tee_service_contexts",
+    defaults: ["contexts_flags_defaults"],
+    srcs: [":tee_service_contexts_files{.plat_private}"],
+}
+
+tee_service_contexts {
+    name: "system_ext_tee_service_contexts",
+    defaults: ["contexts_flags_defaults"],
+    srcs: [":tee_service_contexts_files{.system_ext_private}"],
+    system_ext_specific: true,
+}
+
+tee_service_contexts {
+    name: "product_tee_service_contexts",
+    defaults: ["contexts_flags_defaults"],
+    srcs: [":tee_service_contexts_files{.product_private}"],
+    product_specific: true,
+}
+
+tee_service_contexts {
+    name: "vendor_tee_service_contexts",
+    defaults: ["contexts_flags_defaults"],
+    srcs: [
+        ":tee_service_contexts_files{.plat_vendor}",
+        ":tee_service_contexts_files{.vendor}",
+        ":tee_service_contexts_files{.reqd_mask}",
+    ],
+    soc_specific: true,
+}
diff --git a/contexts/plat_file_contexts_test b/contexts/plat_file_contexts_test
index 72b17ca99..fc2d7b81c 100644
--- a/contexts/plat_file_contexts_test
+++ b/contexts/plat_file_contexts_test
@@ -65,6 +65,7 @@
 /vendor_seapp_contexts                                            seapp_contexts_file
 /plat_seapp_contexts                                              seapp_contexts_file
 /sepolicy                                                         sepolicy_file
+/plat_tee_service_contexts                                        tee_service_contexts_file
 /plat_service_contexts                                            service_contexts_file
 /plat_hwservice_contexts                                          hwservice_contexts_file
 /plat_keystore2_key_contexts                                      keystore2_key_contexts_file
@@ -189,7 +190,8 @@
 /dev/socket                                                       socket_device
 /dev/socket/does_not_exist                                        socket_device
 /dev/socket/adbd                                                  adbd_socket
-/dev/socket/aconfigd                                              aconfigd_socket
+/dev/socket/aconfigd_mainline                                     aconfigd_mainline_socket
+/dev/socket/aconfigd_system                                       aconfigd_socket
 /dev/socket/dnsproxyd                                             dnsproxyd_socket
 /dev/socket/dumpstate                                             dumpstate_socket
 /dev/socket/fwmarkd                                               fwmarkd_socket
@@ -323,6 +325,7 @@
 /system/bin/sload_f2fs                                            e2fs_exec
 /system/bin/make_f2fs                                             e2fs_exec
 /system/bin/fsck_msdos                                            fsck_exec
+/system/bin/prefetch                                              prefetch_exec
 /system/bin/tcpdump                                               tcpdump_exec
 /system/bin/tune2fs                                               fsck_exec
 /system/bin/resize2fs                                             fsck_exec
@@ -396,6 +399,7 @@
 /system/bin/bootstrap/linkerconfig                                linkerconfig_exec
 /system/bin/llkd                                                  llkd_exec
 /system/bin/lmkd                                                  lmkd_exec
+/system/bin/mmd                                                   mmd_exec
 /system/bin/usbd                                                  usbd_exec
 /system/bin/inputflinger                                          inputflinger_exec
 /system/bin/logd                                                  logd_exec
@@ -409,6 +413,7 @@
 /system/bin/traced_perf                                           traced_perf_exec
 /system/bin/traced_probes                                         traced_probes_exec
 /system/bin/traced_relay                                          traced_exec
+/system/bin/tradeinmode                                           tradeinmode_exec
 /system/bin/heapprofd                                             heapprofd_exec
 /system/bin/uncrypt                                               uncrypt_exec
 /system/bin/update_verifier                                       update_verifier_exec
@@ -433,8 +438,8 @@
 /system/bin/hw/android.system.suspend-service                     system_suspend_exec
 /system/etc/aconfig                                               system_aconfig_storage_file
 /system/etc/cgroups.json                                          cgroup_desc_file
-/system/etc/task_profiles/cgroups_0.json                          cgroup_desc_api_file
-/system/etc/task_profiles/cgroups_999.json                        cgroup_desc_api_file
+/system/etc/task_profiles/cgroups_0.json                          cgroup_desc_file
+/system/etc/task_profiles/cgroups_999.json                        cgroup_desc_file
 /system/etc/event-log-tags                                        system_event_log_tags_file
 /system/etc/font_fallback.xml                                     system_font_fallback_file
 /system/etc/group                                                 system_group_file
@@ -450,6 +455,7 @@
 #/system/etc/selinux/mapping/30.compat.0.cil                      sepolicy_file
 /system/etc/selinux/plat_mac_permissions.xml                      mac_perms_file
 /system/etc/selinux/plat_property_contexts                        property_contexts_file
+/system/etc/selinux/plat_tee_service_contexts                     tee_service_contexts_file
 /system/etc/selinux/plat_service_contexts                         service_contexts_file
 /system/etc/selinux/plat_hwservice_contexts                       hwservice_contexts_file
 /system/etc/selinux/plat_keystore2_key_contexts                   keystore2_key_contexts_file
@@ -458,12 +464,12 @@
 /system/etc/selinux/plat_sepolicy.cil                             sepolicy_file
 /system/etc/selinux/plat_and_mapping_sepolicy.cil.sha256          sepolicy_file
 /system/etc/task_profiles.json                                    task_profiles_file
-/system/etc/task_profiles/task_profiles_0.json                    task_profiles_api_file
-/system/etc/task_profiles/task_profiles_99.json                   task_profiles_api_file
+/system/etc/task_profiles/task_profiles_0.json                    task_profiles_file
+/system/etc/task_profiles/task_profiles_99.json                   task_profiles_file
 /system/usr/share/zoneinfo                                        system_zoneinfo_file
 /system/usr/share/zoneinfo/0                                      system_zoneinfo_file
 /system/bin/adbd                                                  adbd_exec
-/system/bin/aconfigd                                              aconfigd_exec
+/system/bin/aconfigd-system                                       aconfigd_exec
 /system/bin/vold_prepare_subdirs                                  vold_prepare_subdirs_exec
 /system/bin/stats                                                 stats_exec
 /system/bin/statsd                                                statsd_exec
@@ -485,6 +491,7 @@
 /system/bin/android.automotive.evs.manager@1.99                   evsmanagerd_exec
 /system/bin/uprobestats                                           uprobestats_exec
 /system/bin/trace_redactor                                        trace_redactor_exec
+/system/bin/bert_collector                                        bert_collector_exec
 
 /vendor                                                           vendor_file
 /vendor/does_not_exist                                            vendor_file
@@ -637,6 +644,7 @@
 /odm/usr/keylayout/test.kl                                        vendor_keylayout_file
 /vendor/odm/usr/keylayout.kl                                      vendor_keylayout_file
 /vendor/odm/usr/keylayout/test.kl                                 vendor_keylayout_file
+/vendor/usr/keylayout                                             vendor_keylayout_file
 /vendor/usr/keylayout.kl                                          vendor_keylayout_file
 /vendor/usr/keylayout/test.kl                                     vendor_keylayout_file
 /system/vendor/usr/keylayout.kl                                   vendor_keylayout_file
@@ -645,6 +653,7 @@
 /odm/usr/keychars/test.kcm                                        vendor_keychars_file
 /vendor/odm/usr/keychars.kcm                                      vendor_keychars_file
 /vendor/odm/usr/keychars/test.kcm                                 vendor_keychars_file
+/vendor/usr/keychars                                              vendor_keychars_file
 /vendor/usr/keychars.kcm                                          vendor_keychars_file
 /vendor/usr/keychars/test.kcm                                     vendor_keychars_file
 /system/vendor/usr/keychars.kcm                                   vendor_keychars_file
@@ -653,6 +662,7 @@
 /odm/usr/idc/test.idc                                             vendor_idc_file
 /vendor/odm/usr/idc.idc                                           vendor_idc_file
 /vendor/odm/usr/idc/test.idc                                      vendor_idc_file
+/vendor/usr/idc                                                   vendor_idc_file
 /vendor/usr/idc.idc                                               vendor_idc_file
 /vendor/usr/idc/test.idc                                          vendor_idc_file
 /system/vendor/usr/idc.idc                                        vendor_idc_file
@@ -685,6 +695,8 @@
 /vendor/odm/etc/selinux/odm_keystore2_key_contexts                keystore2_key_contexts_file
 /odm/etc/selinux/odm_mac_permissions.xml                          mac_perms_file
 /vendor/odm/etc/selinux/odm_mac_permissions.xml                   mac_perms_file
+/odm/etc/selinux/odm_tee_service_contexts                         tee_service_contexts_file
+/vendor/odm/etc/selinux/odm_tee_service_contexts                  tee_service_contexts_file
 
 /product                                                          system_file
 /product/does_not_exist                                           system_file
@@ -713,6 +725,8 @@
 /system/product/etc/selinux/product_service_contexts              service_contexts_file
 /product/etc/selinux/product_mac_permissions.xml                  mac_perms_file
 /system/product/etc/selinux/product_mac_permissions.xml           mac_perms_file
+/product/etc/selinux/product_tee_service_contexts                 tee_service_contexts_file
+/system/product/etc/selinux/product_tee_service_contexts          tee_service_contexts_file
 
 /product/lib                                                      system_lib_file
 /product/lib/does_not_exist                                       system_lib_file
@@ -757,6 +771,8 @@
 /system/system_ext/etc/selinux/system_ext_mac_permissions.xml     mac_perms_file
 /system_ext/etc/selinux/userdebug_plat_sepolicy.cil               sepolicy_file
 /system/system_ext/etc/selinux/userdebug_plat_sepolicy.cil        sepolicy_file
+/system_ext/etc/selinux/system_ext_tee_service_contexts           tee_service_contexts_file
+/system/system_ext/etc/selinux/system_ext_tee_service_contexts    tee_service_contexts_file
 
 /system_ext/bin/aidl_lazy_test_server                             aidl_lazy_test_server_exec
 /system/system_ext/bin/aidl_lazy_test_server                      aidl_lazy_test_server_exec
@@ -771,14 +787,16 @@
 /system_ext/bin/hw/android.hidl.allocator@1.0-service             hal_allocator_default_exec
 /system/system_ext/bin/hw/android.hidl.allocator@1.0-service      hal_allocator_default_exec
 
+/system_ext/bin/rkp_cert_processor                                rkp_cert_processor_exec
+/system/system_ext/bin/rkp_cert_processor                         rkp_cert_processor_exec
+
 
 /system_ext/bin/canhalconfigurator                                canhalconfigurator_exec
 /system_ext/bin/canhalconfigurator-aidl                           canhalconfigurator_exec
 /system/system_ext/bin/canhalconfigurator                         canhalconfigurator_exec
 /system/system_ext/bin/canhalconfigurator-aidl                    canhalconfigurator_exec
 
-/system_ext/bin/custom_vm_setup                                   custom_vm_setup_exec
-/system/system_ext/bin/custom_vm_setup                            custom_vm_setup_exec
+/system/bin/linux_vm_setup                                        linux_vm_setup_exec
 
 /system_ext/lib                                                   system_lib_file
 /system_ext/lib/does_not_exist                                    system_lib_file
@@ -1063,6 +1081,8 @@
 /data/misc/wifi/test                                              wifi_data_file
 /data/misc_ce/0/wifi                                              wifi_data_file
 /data/misc_ce/99/wifi/test                                        wifi_data_file
+/data/misc/wifi/mainline_supplicant                               mainline_supplicant_data_file
+/data/misc/wifi/mainline_supplicant/sockets                       mainline_supplicant_data_file
 /data/misc/wifi/sockets                                           wpa_socket
 /data/misc/wifi/sockets/test                                      wpa_socket
 /data/misc/wifi/sockets/wpa_ctrl_test                             system_wpa_socket
@@ -1250,8 +1270,6 @@
 /metadata/aconfig/maps/test                                       aconfig_storage_metadata_file
 /metadata/aconfig/boot                                            aconfig_storage_metadata_file
 /metadata/aconfig/boot/test                                       aconfig_storage_metadata_file
-/metadata/aconfig_test_missions                                   aconfig_test_mission_files
-/metadata/aconfig_test_missions/test                              aconfig_test_mission_files
 /metadata/apex                                                    apex_metadata_file
 /metadata/apex/test                                               apex_metadata_file
 /metadata/vold                                                    vold_metadata_file
@@ -1276,6 +1294,10 @@
 /metadata/watchdog/test                                           watchdog_metadata_file
 /metadata/repair-mode                                             repair_mode_metadata_file
 /metadata/repair-mode/test                                        repair_mode_metadata_file
+/metadata/tradeinmode                                             tradeinmode_metadata_file
+/metadata/tradeinmode/test                                        tradeinmode_metadata_file
+/metadata/prefetch                                                prefetch_metadata_file
+/metadata/prefetch/test                                           prefetch_metadata_file
 
 /mnt/asec                                                         asec_apk_file
 /mnt/asec/test                                                    asec_apk_file
diff --git a/flagging/Android.bp b/flagging/Android.bp
index bd97a162a..c92991fa8 100644
--- a/flagging/Android.bp
+++ b/flagging/Android.bp
@@ -23,11 +23,14 @@ se_flags {
         "RELEASE_AVF_ENABLE_LLPVM_CHANGES",
         "RELEASE_AVF_ENABLE_NETWORK",
         "RELEASE_AVF_ENABLE_MICROFUCHSIA",
+        "RELEASE_AVF_ENABLE_VM_TO_TEE_SERVICES_ALLOWLIST",
+        "RELEASE_AVF_ENABLE_WIDEVINE_PVM",
         "RELEASE_RANGING_STACK",
         "RELEASE_READ_FROM_NEW_STORAGE",
         "RELEASE_SUPERVISION_SERVICE",
         "RELEASE_HARDWARE_BLUETOOTH_RANGING_SERVICE",
         "RELEASE_UNLOCKED_STORAGE_API",
+        "RELEASE_BLUETOOTH_SOCKET_SERVICE",
     ],
     export_to: ["all_selinux_flags"],
 }
diff --git a/microdroid/Android.bp b/microdroid/Android.bp
index e9b4b1e24..a20ce9362 100644
--- a/microdroid/Android.bp
+++ b/microdroid/Android.bp
@@ -212,7 +212,7 @@ sepolicy_vers {
 }
 
 // sepolicy sha256 for vendor
-genrule {
+java_genrule {
     name: "microdroid_plat_sepolicy_and_mapping.sha256_gen",
     srcs: [
         ":microdroid_plat_sepolicy.cil",
diff --git a/microdroid/system/private/domain.te b/microdroid/system/private/domain.te
index 7361462de..40cfe5bfc 100644
--- a/microdroid/system/private/domain.te
+++ b/microdroid/system/private/domain.te
@@ -230,7 +230,6 @@ allow { domain } cgroup_v2:dir w_dir_perms;
 allow { domain } cgroup_v2:file w_file_perms;
 
 allow domain task_profiles_file:file r_file_perms;
-allow domain task_profiles_api_file:file r_file_perms;
 
 # Allow all processes to connect to PRNG seeder daemon.
 unix_socket_connect(domain, prng_seeder, prng_seeder)
diff --git a/microdroid/system/private/file_contexts b/microdroid/system/private/file_contexts
index 6414f76ba..841608765 100644
--- a/microdroid/system/private/file_contexts
+++ b/microdroid/system/private/file_contexts
@@ -113,7 +113,7 @@
 /system/bin/traced               u:object_r:traced_exec:s0
 /system/bin/traced_probes        u:object_r:traced_probes_exec:s0
 /system/etc/cgroups\.json               u:object_r:cgroup_desc_file:s0
-/system/etc/task_profiles/cgroups_[0-9]+\.json               u:object_r:cgroup_desc_api_file:s0
+/system/etc/task_profiles/cgroups_[0-9]+\.json               u:object_r:cgroup_desc_file:s0
 /system/etc/event-log-tags              u:object_r:system_event_log_tags_file:s0
 /system/etc/group                       u:object_r:system_group_file:s0
 /system/etc/ld\.config.*                u:object_r:system_linker_config_file:s0
@@ -127,7 +127,7 @@
 /system/etc/selinux/plat_sepolicy\.cil       u:object_r:sepolicy_file:s0
 /system/etc/selinux/plat_and_mapping_sepolicy\.cil\.sha256 u:object_r:sepolicy_file:s0
 /system/etc/task_profiles\.json  u:object_r:task_profiles_file:s0
-/system/etc/task_profiles/task_profiles_[0-9]+\.json  u:object_r:task_profiles_api_file:s0
+/system/etc/task_profiles/task_profiles_[0-9]+\.json  u:object_r:task_profiles_file:s0
 
 #############################
 # Vendor files
diff --git a/microdroid/system/private/init.te b/microdroid/system/private/init.te
index 67af209e5..9a0345f05 100644
--- a/microdroid/system/private/init.te
+++ b/microdroid/system/private/init.te
@@ -114,7 +114,6 @@ allow init tmpfs:dir mounton;
 allow init cgroup:dir create_dir_perms;
 allow init cgroup:file rw_file_perms;
 allow init cgroup_desc_file:file r_file_perms;
-allow init cgroup_desc_api_file:file r_file_perms;
 allow init cgroup_v2:dir { mounton create_dir_perms};
 allow init cgroup_v2:file rw_file_perms;
 
diff --git a/microdroid/system/private/microdroid_app.te b/microdroid/system/private/microdroid_app.te
index d26154a44..77667ff60 100644
--- a/microdroid/system/private/microdroid_app.te
+++ b/microdroid/system/private/microdroid_app.te
@@ -8,3 +8,7 @@
 
 type microdroid_app, domain, coredomain, microdroid_payload;
 type microdroid_app_exec, exec_type, file_type, system_file_type;
+
+# Let microdroid_manager kernel-log.
+allow microdroid_app kmsg_device:chr_file w_file_perms;
+allow microdroid_app kmsg_debug_device:chr_file w_file_perms;
diff --git a/microdroid/system/private/microdroid_manager.te b/microdroid/system/private/microdroid_manager.te
index 75c89bebc..96a05f774 100644
--- a/microdroid/system/private/microdroid_manager.te
+++ b/microdroid/system/private/microdroid_manager.te
@@ -129,7 +129,8 @@ allow microdroid_manager sysfs_zram:file rw_file_perms;
 allow microdroid_manager ram_device:blk_file rw_file_perms;
 
 # Allow microdroid_manager to read/write failure serial device
-allow microdroid_manager serial_device:chr_file w_file_perms;
+# tcdrain requires ioctl.
+allow microdroid_manager serial_device:chr_file { w_file_perms ioctl };
 
 # Allow microdroid_manager to handle extra_apks
 allow microdroid_manager extra_apk_file:dir create_dir_perms;
diff --git a/microdroid/system/private/shell.te b/microdroid/system/private/shell.te
index 0ea67a74d..ba8877050 100644
--- a/microdroid/system/private/shell.te
+++ b/microdroid/system/private/shell.te
@@ -43,7 +43,6 @@ allow shell sysfs_net:dir r_dir_perms;
 
 r_dir_file(shell, cgroup)
 allow shell cgroup_desc_file:file r_file_perms;
-allow shell cgroup_desc_api_file:file r_file_perms;
 r_dir_file(shell, cgroup_v2)
 allow shell domain:dir { search open read getattr };
 allow shell domain:{ file lnk_file } { open read getattr };
diff --git a/microdroid/system/public/file.te b/microdroid/system/public/file.te
index 8d3f76a0a..8551bb6c3 100644
--- a/microdroid/system/public/file.te
+++ b/microdroid/system/public/file.te
@@ -6,7 +6,9 @@ type apex_info_file, file_type;
 type apex_mnt_dir, file_type;
 type authfs_data_file, file_type, data_file_type, core_data_file_type;
 type authfs_service_socket, file_type, coredomain_socket;
-type cgroup_desc_api_file, file_type, system_file_type;
+until_board_api(202504, `
+    type cgroup_desc_api_file, file_type, system_file_type;
+')
 type cgroup_desc_file, file_type, system_file_type;
 type extra_apk_file, file_type;
 type file_contexts_file, file_type, system_file_type;
@@ -30,7 +32,9 @@ type system_linker_config_file, file_type, system_file_type;
 type system_passwd_file, file_type, system_file_type;
 type system_seccomp_policy_file, file_type, system_file_type;
 type system_security_cacerts_file, file_type, system_file_type;
-type task_profiles_api_file, file_type, system_file_type;
+until_board_api(202504, `
+    type task_profiles_api_file, file_type, system_file_type;
+')
 type task_profiles_file, file_type, system_file_type;
 type trace_data_file, file_type, data_file_type, core_data_file_type;
 type unlabeled, file_type;
diff --git a/prebuilts/api/202404/202404_general_sepolicy.conf b/prebuilts/api/202404/202404_general_sepolicy.conf
index 5ce168ccb..2c418a8f4 100644
--- a/prebuilts/api/202404/202404_general_sepolicy.conf
+++ b/prebuilts/api/202404/202404_general_sepolicy.conf
@@ -56456,7 +56456,7 @@ neverallow { isolated_app_all -isolated_compute_app } {
 }:service_manager find;
 
 # Isolated apps shouldn't be able to access the driver directly.
-neverallow isolated_app_all gpu_device:chr_file { { { getattr open read ioctl lock map watch watch_reads } { open append write lock map } } execute };
+neverallow { isolated_app_all -isolated_compute_app } gpu_device:chr_file { { { getattr open read ioctl lock map watch watch_reads } { open append write lock map } } execute };
 
 # Do not allow isolated_apps access to /cache
 neverallow isolated_app_all cache_file:dir ~{ { open getattr read search ioctl lock watch watch_reads } };
diff --git a/private/access_vectors b/private/access_vectors
index 9d82ac8ef..f91c1a409 100644
--- a/private/access_vectors
+++ b/private/access_vectors
@@ -807,3 +807,8 @@ class user_namespace
 {
 	create
 }
+
+class tee_service
+{
+	use
+}
diff --git a/private/aconfigd.te b/private/aconfigd.te
index 97e7493a3..211405bcf 100644
--- a/private/aconfigd.te
+++ b/private/aconfigd.te
@@ -1,15 +1,9 @@
 # aconfigd -- manager for aconfig flags
-type aconfigd, domain;
+type aconfigd, domain, coredomain, mlstrustedsubject;
 type aconfigd_exec, exec_type, file_type, system_file_type;
 
-typeattribute aconfigd coredomain;
-
 init_daemon_domain(aconfigd)
 
-# only init is allowed to enter the aconfigd domain
-neverallow { domain -init } aconfigd:process transition;
-neverallow * aconfigd:process dyntransition;
-
 allow aconfigd metadata_file:dir search;
 
 allow aconfigd {
@@ -22,17 +16,9 @@ allow aconfigd {
     aconfig_storage_flags_metadata_file
 }:file create_file_perms;
 
-allow aconfigd aconfigd_socket:unix_stream_socket { accept listen getattr read write };
-allow aconfigd aconfigd_socket:sock_file rw_file_perms;
-
-# allow aconfigd to access shell_data_file for atest
-userdebug_or_eng(`
-    allow aconfigd shell_data_file:dir search;
-    allow aconfigd shell_data_file:file { getattr read open map };
-')
-
-# allow aconfigd to log to the kernel.
-allow aconfigd kmsg_device:chr_file w_file_perms;
+# allow aconfigd to log to the kernel dmesg via a file descriptor
+# passed from init to aconfigd
+allow aconfigd kmsg_device:chr_file write;
 
 # allow aconfigd to read vendor partition storage files
 allow aconfigd vendor_aconfig_storage_file:file r_file_perms;
@@ -41,3 +27,44 @@ allow aconfigd vendor_aconfig_storage_file:dir r_dir_perms;
 # allow aconfigd to read /apex dir
 allow aconfigd apex_mnt_dir:dir r_dir_perms;
 allow aconfigd apex_mnt_dir:file r_file_perms;
+dontaudit aconfigd apex_info_file:file r_file_perms;
+
+###
+### Neverallow assertions
+###
+
+# only init is allowed to enter the aconfigd domain
+neverallow { domain -init } aconfigd:process transition;
+neverallow * aconfigd:process dyntransition;
+
+# Do not allow write access to boot/map storage files except, aconfigd and aconfigd_mainline.
+# These files are meant to serve flag reads for all processes. They are created by aconfigd (for
+# platform storage files) and aconfigd_mainline (mainline storage files) processes.
+neverallow {
+  domain
+  -init
+  -aconfigd
+  -aconfigd_mainline
+} aconfig_storage_metadata_file:dir no_w_dir_perms;
+neverallow {
+  domain
+  -init
+  -aconfigd
+  -aconfigd_mainline
+} aconfig_storage_metadata_file:file no_w_file_perms;
+
+# Only aconfigd and aconfigd_mainline can access persist storage files
+# These files are meant to serve as persist flag value storage, only aconfigd and
+# aconfigd_mainline process should manage them. Other processes should have zero access.
+neverallow {
+  domain
+  -init
+  -aconfigd
+  -aconfigd_mainline
+} aconfig_storage_flags_metadata_file:dir *;
+neverallow {
+  domain
+  -init
+  -aconfigd
+  -aconfigd_mainline
+} aconfig_storage_flags_metadata_file:file no_rw_file_perms;
diff --git a/private/aconfigd_mainline.te b/private/aconfigd_mainline.te
new file mode 100644
index 000000000..cd98d4bee
--- /dev/null
+++ b/private/aconfigd_mainline.te
@@ -0,0 +1,38 @@
+# aconfigd_mainline -- manager for mainline aconfig flags
+type aconfigd_mainline, domain, coredomain, mlstrustedsubject;
+type aconfigd_mainline_exec, exec_type, file_type, system_file_type;
+
+init_daemon_domain(aconfigd_mainline)
+
+# allow aconfigd_mainline to search /metadata dir as it needs to access files under
+# /metadata/aconfig dir
+allow aconfigd_mainline metadata_file:dir search;
+
+# aconfigd_mainline should be able to create storage files under /metadata/aconfig dir
+allow aconfigd_mainline {
+    aconfig_storage_metadata_file
+    aconfig_storage_flags_metadata_file
+}:dir create_dir_perms;
+
+allow aconfigd_mainline {
+    aconfig_storage_metadata_file
+    aconfig_storage_flags_metadata_file
+}:file create_file_perms;
+
+# allow aconfigd_mainline to log to the kernel.
+allow aconfigd_mainline kmsg_device:chr_file write;
+
+# allow aconfigd_mainline to read /apex dir, aconfigd_mainline need to loop thru all
+# dirs under /apex to find all currently mounted mainline modules and get their
+# storage files
+allow aconfigd_mainline apex_mnt_dir:dir r_dir_perms;
+allow aconfigd_mainline apex_mnt_dir:file r_file_perms;
+dontaudit aconfigd_mainline apex_info_file:file r_file_perms;
+
+###
+### Neverallow assertions
+###
+
+# only init is allowed to enter the aconfigd_mainline domain
+neverallow { domain -init } aconfigd_mainline:process transition;
+neverallow * aconfigd_mainline:process dyntransition;
diff --git a/private/adbd.te b/private/adbd.te
index 154a04cb5..b87b31916 100644
--- a/private/adbd.te
+++ b/private/adbd.te
@@ -2,13 +2,17 @@
 
 typeattribute adbd coredomain;
 typeattribute adbd mlstrustedsubject;
+typeattribute adbd adbd_common;
 
 init_daemon_domain(adbd)
 
 domain_auto_trans(adbd, shell_exec, shell)
 
+# Allow adb to setcon() to tradeinmode.
+allow adbd self:process setcurrent;
+allow adbd adbd_tradeinmode:process dyntransition;
+
 userdebug_or_eng(`
-  allow adbd self:process setcurrent;
   allow adbd su:process dyntransition;
 ')
 
@@ -40,18 +44,8 @@ allow adbd self:global_capability_class_set setpcap;
 # ignore spurious denials for adbd when disk space is low.
 dontaudit adbd self:global_capability_class_set sys_resource;
 
-# adbd probes for vsock support. Do not generate denials when
-# this occurs. (b/123569840)
-dontaudit adbd self:{ socket vsock_socket } create;
-
-# Allow adbd inside vm to forward vm's vsock.
-allow adbd self:vsock_socket { create_socket_perms_no_ioctl listen accept };
-
 # Create and use network sockets.
 net_domain(adbd)
-# Connect to mdnsd via mdnsd socket.
-unix_socket_connect(adbd, mdnsd, mdnsd)
-
 # Access /dev/usb-ffs/adb/ep0
 allow adbd functionfs:dir search;
 allow adbd functionfs:file rw_file_perms;
@@ -60,13 +54,6 @@ allowxperm adbd functionfs:file ioctl {
   FUNCTIONFS_CLEAR_HALT
 };
 
-# Use a pseudo tty.
-allow adbd devpts:chr_file rw_file_perms;
-
-# adb push/pull /data/local/tmp.
-allow adbd shell_data_file:dir create_dir_perms;
-allow adbd shell_data_file:file create_file_perms;
-
 # adb pull /data/local/traces/*
 allow adbd trace_data_file:dir r_dir_perms;
 allow adbd trace_data_file:file r_file_perms;
@@ -95,26 +82,11 @@ set_prop(adbd, shell_prop)
 set_prop(adbd, powerctl_prop)
 get_prop(adbd, ffs_config_prop)
 set_prop(adbd, ffs_control_prop)
-
-# Set service.adb.tcp.port, service.adb.tls.port, persist.adb.wifi.* properties
-set_prop(adbd, adbd_prop)
-set_prop(adbd, adbd_config_prop)
+set_prop(adbd, adbd_tradeinmode_prop)
 
 # Allow adbd start/stop mdnsd via ctl.start
 set_prop(adbd, ctl_mdnsd_prop)
 
-# Access device logging gating property
-get_prop(adbd, device_logging_prop)
-
-# Read device's serial number from system properties
-get_prop(adbd, serialno_prop)
-
-# Read whether or not Test Harness Mode is enabled
-get_prop(adbd, test_harness_prop)
-
-# Read persist.adb.tls_server.enable property
-get_prop(adbd, system_adbd_prop)
-
 # Read device's overlayfs related properties and files
 userdebug_or_eng(`
   get_prop(adbd, persistent_properties_ready_prop)
@@ -215,6 +187,10 @@ allow adbd perfetto_configs_data_file:file create_file_perms;
 allow adbd shell:unix_stream_socket { read write shutdown };
 allow adbd shell:fd use;
 
+# adb push/pull /data/local/tmp.
+allow adbd shell_data_file:dir create_dir_perms;
+allow adbd shell_data_file:file create_file_perms;
+
 # Allow pull /vendor/apex files for CTS tests
 r_dir_file(adbd, vendor_apex_file)
 
@@ -239,10 +215,15 @@ allow adbd shell_test_data_file:lnk_file create_file_perms;
 ###
 
 # No transitions from adbd to non-shell, non-crash_dump domains. adbd only ever
-# transitions to the shell domain (except when it crashes). In particular, we
-# never want to see a transition from adbd to su (aka "adb root")
-neverallow adbd { domain -crash_dump -shell }:process transition;
-neverallow adbd { domain userdebug_or_eng(`-su') recovery_only(`-shell') }:process dyntransition;
+# transitions to the shell or tradeinmode domain (except when it crashes). In
+# particular, we never want to see a transition from adbd to su (aka "adb root")
+neverallow adbd { domain -crash_dump -shell -adbd_tradeinmode }:process transition;
+neverallow adbd {
+    domain
+    userdebug_or_eng(`-su')
+    recovery_only(`-shell')
+    -adbd_tradeinmode
+}:process dyntransition;
 
 # Only init is allowed to enter the adbd domain via exec()
 neverallow { domain -init } adbd:process transition;
diff --git a/private/adbd_common.te b/private/adbd_common.te
new file mode 100644
index 000000000..c24b02927
--- /dev/null
+++ b/private/adbd_common.te
@@ -0,0 +1,31 @@
+### ADB daemon common rules.
+### Put things here that are needed for both adbd proper and adbd in trade-in mode.
+
+# Connect to mdnsd via mdnsd socket.
+unix_socket_connect(adbd_common, mdnsd, mdnsd)
+
+# adbd probes for vsock support. Do not generate denials when
+# this occurs. (b/123569840)
+dontaudit adbd_common self:{ socket vsock_socket } create;
+
+# Allow adbd inside vm to forward vm's vsock.
+allow adbd_common self:vsock_socket { create_socket_perms_no_ioctl listen accept };
+
+# Access device logging gating property
+get_prop(adbd_common, device_logging_prop)
+
+# Use a pseudo tty.
+allow adbd_common devpts:chr_file rw_file_perms;
+
+# Read persist.adb.tls_server.enable property
+get_prop(adbd_common, system_adbd_prop)
+
+# Read whether or not Test Harness Mode is enabled
+get_prop(adbd_common, test_harness_prop)
+
+# Set service.adb.tcp.port, service.adb.tls.port, persist.adb.wifi.* properties
+set_prop(adbd_common, adbd_prop)
+set_prop(adbd_common, adbd_config_prop)
+
+# Read device's serial number from system properties
+get_prop(adbd_common, serialno_prop)
diff --git a/private/adbd_tradeinmode.te b/private/adbd_tradeinmode.te
new file mode 100644
index 000000000..42fdec463
--- /dev/null
+++ b/private/adbd_tradeinmode.te
@@ -0,0 +1,26 @@
+### ADB in trade-in mode
+type adbd_tradeinmode, domain, coredomain, adbd_common;
+
+# Create and use network sockets.
+net_domain(adbd_tradeinmode)
+
+# Run /system/bin/tradeinmode
+domain_auto_trans(adbd_tradeinmode, tradeinmode_exec, tradeinmode)
+
+# Baseline rules to make adbd work after setcon().
+allow adbd_tradeinmode adbd:unix_stream_socket {
+    rw_socket_perms_no_ioctl
+    listen
+    accept
+};
+allow adbd_tradeinmode adbd:fd use;
+allow adbd_tradeinmode adbd:unix_dgram_socket { connect write };
+allow adbd_tradeinmode functionfs:dir r_dir_perms;
+allow adbd_tradeinmode functionfs:file rw_file_perms;
+allow adbd_tradeinmode proc_uptime:file r_file_perms;
+allow adbd_tradeinmode rootfs:dir r_dir_perms;
+
+set_prop(adbd_tradeinmode, ffs_control_prop)
+
+# Allow changing persist.adb.tradeinmode when testing.
+userdebug_or_eng(`set_prop(adbd_tradeinmode, shell_prop)')
diff --git a/private/apexd.te b/private/apexd.te
index e7ad3b9db..58a365869 100644
--- a/private/apexd.te
+++ b/private/apexd.te
@@ -95,6 +95,8 @@ allow apexd staging_data_file:dir r_dir_perms;
 allow apexd staging_data_file:file { r_file_perms link };
 # # Allow relabeling file created in /data/apex/decompressed
 allow apexd staging_data_file:file relabelto;
+# Allow renaming files in /data/apex/decompressed (from .ota.apex to .decompressed.apex)
+allow apexd staging_data_file:file rename;
 
 # allow apexd to read files from /vendor/apex
 r_dir_file(apexd, vendor_apex_file)
@@ -189,6 +191,9 @@ set_prop(apexd, apex_ready_prop)
 
 # Allow apexd to write to statsd.
 unix_socket_send(apexd, statsdw, statsd)
+# Allow apexd to call
+allow apexd statsbootstrap_service:service_manager find;
+binder_call(apexd, system_server) # system_server serves statsbootstrap_service
 
 ###
 ### Neverallow rules
@@ -221,7 +226,11 @@ neverallow { domain -apexd } apex_info_file:file no_w_file_perms;
 neverallow { domain -apexd -init -otapreopt_chroot } apex_mnt_dir:filesystem { mount unmount };
 neverallow { domain -apexd -dexopt_chroot_setup -init -otapreopt_chroot } apex_mnt_dir:dir mounton;
 
-neverallow { domain -init -apexd -system_server -update_engine } apex_service:service_manager find;
-neverallow { domain -init -apexd -system_server -servicemanager -update_engine } apexd:binder call;
+# The update_provider performs APEX updates. To do this, it needs to be able to find apex_service
+# and make binder calls to apexd.
+# WARNING: USING THE update_provider ATTRIBUTE WILL CAUSE CTS TO FAIL!
+neverallow { domain -init -apexd -system_server -update_engine -update_provider } apex_service:service_manager find;
+# WARNING: USING THE update_provider ATTRIBUTE WILL CAUSE CTS TO FAIL!
+neverallow { domain -init -apexd -system_server -servicemanager -update_engine -update_provider } apexd:binder call;
 
 neverallow { domain userdebug_or_eng(`-crash_dump') } apexd:process ptrace;
diff --git a/private/app.te b/private/app.te
index 6362c7d66..b9a6d85e8 100644
--- a/private/app.te
+++ b/private/app.te
@@ -159,7 +159,7 @@ allow { appdomain -isolated_app_all -ephemeral_app -sdk_sandbox_all } usbaccesso
 control_logd({ appdomain -ephemeral_app -sdk_sandbox_all })
 
 # application inherit logd write socket (urge is to deprecate this long term)
-allow { appdomain -isolated_app_all -ephemeral_app -sdk_sandbox_all } keystore:keystore2_key { delete use get_info rebind update };
+allow { appdomain -isolated_app_all -ephemeral_app -sdk_sandbox_all } keystore:keystore2_key { delete use get_info grant rebind update };
 
 allow { appdomain -isolated_app_all -ephemeral_app -sdk_sandbox_all } keystore_maintenance_service:service_manager find;
 
diff --git a/private/attributes b/private/attributes
index fe50b0dfb..13479c967 100644
--- a/private/attributes
+++ b/private/attributes
@@ -11,7 +11,23 @@ attribute mlsvendorcompat;
 attribute system_and_vendor_property_type;
 expandattribute system_and_vendor_property_type false;
 
+# HALs
+until_board_api(202504, `
+    hal_attribute(mediaquality);
+')
+
 # All SDK sandbox domains
 attribute sdk_sandbox_all;
 # The SDK sandbox domains for the current SDK level.
 attribute sdk_sandbox_current;
+# Common to adbd and adbd_tradeinmode.
+attribute adbd_common;
+
+# Provides access to platform update services.
+# WARNING: USING THE update_provider ATTRIBUTE WILL CAUSE CTS TO FAIL!
+attribute update_provider;
+expandattribute update_provider false;
+
+until_board_api(202504, `
+    attribute tee_service_type;
+')
diff --git a/private/bert_collector.te b/private/bert_collector.te
new file mode 100644
index 000000000..b11bd76f6
--- /dev/null
+++ b/private/bert_collector.te
@@ -0,0 +1,12 @@
+type bert_collector, domain, coredomain;
+type bert_collector_exec, system_file_type, exec_type, file_type;
+
+init_daemon_domain(bert_collector)
+
+r_dir_file(bert_collector, sysfs_firmware_acpi_tables)
+
+binder_use(bert_collector)
+binder_call(bert_collector, system_server)
+
+allow bert_collector dropbox_service:service_manager find;
+allow bert_collector proc_version:file r_file_perms;
diff --git a/private/bootanim.te b/private/bootanim.te
index d9be72f95..fd3a09b5c 100644
--- a/private/bootanim.te
+++ b/private/bootanim.te
@@ -64,3 +64,6 @@ allow bootanim proc_meminfo:file r_file_perms;
 
 # System file accesses.
 allow bootanim system_file:dir r_dir_perms;
+
+# Allow bootanim to send information to statsd socket.
+unix_socket_send(bootanim, statsdw, statsd)
\ No newline at end of file
diff --git a/private/bpfloader.te b/private/bpfloader.te
index 33d37835b..4fe38432d 100644
--- a/private/bpfloader.te
+++ b/private/bpfloader.te
@@ -6,7 +6,7 @@ typeattribute bpfloader bpfdomain;
 allow bpfloader kmsg_device:chr_file w_file_perms;
 
 # These permissions are required to pin ebpf maps & programs.
-allow bpfloader bpffs_type:dir { add_name create remove_name search setattr write };
+allow bpfloader bpffs_type:dir { add_name create open read remove_name search setattr write };
 allow bpfloader bpffs_type:file { create getattr read rename setattr };
 allow bpfloader bpffs_type:lnk_file { create getattr read };
 allow { bpffs_type -fs_bpf } fs_bpf:filesystem associate;
@@ -29,8 +29,8 @@ allow bpfloader bpfloader_exec:file execute_no_trans;
 ###
 
 # Note: we don't care about getattr/mounton/search
-neverallow { domain            } bpffs_type:dir ~{ add_name create getattr mounton remove_name search setattr write };
-neverallow { domain -bpfloader } bpffs_type:dir { add_name create remove_name setattr write };
+neverallow { domain            } bpffs_type:dir ~{ add_name create getattr mounton open read remove_name search setattr write };
+neverallow { domain -bpfloader } bpffs_type:dir { add_name create open read remove_name setattr write };
 
 neverallow { domain            } bpffs_type:file ~{ create getattr map open read rename setattr write };
 neverallow { domain -bpfloader } bpffs_type:file { create map open rename setattr };
diff --git a/private/bug_map b/private/bug_map
index 97d971390..a4873a7cc 100644
--- a/private/bug_map
+++ b/private/bug_map
@@ -1,3 +1,4 @@
+crash_dump keystore process b/376065666
 dnsmasq netd fifo_file b/77868789
 dnsmasq netd unix_stream_socket b/77868789
 gmscore_app system_data_file dir b/146166941
diff --git a/private/compat/202404/202404.ignore.cil b/private/compat/202404/202404.ignore.cil
index 17e28424a..1c108cf65 100644
--- a/private/compat/202404/202404.ignore.cil
+++ b/private/compat/202404/202404.ignore.cil
@@ -14,10 +14,16 @@
     proc_cgroups
     ranging_service
     supervision_service
-    sysfs_udc
     app_function_service
     virtual_fingerprint
     virtual_fingerprint_exec
     virtual_face
     virtual_face_exec
+    hal_mediaquality_service
+    media_quality_service
+    advanced_protection_service
+    sysfs_firmware_acpi_tables
+    dynamic_instrumentation_service
+    intrusion_detection_service
+    wifi_mainline_supplicant_service
   ))
diff --git a/private/compat/34.0/34.0.ignore.cil b/private/compat/34.0/34.0.ignore.cil
index 6c52dba76..3f5cb6878 100644
--- a/private/compat/34.0/34.0.ignore.cil
+++ b/private/compat/34.0/34.0.ignore.cil
@@ -19,6 +19,7 @@
     hal_secretkeeper_service
     hal_codec2_service
     hal_macsec_service
+    hal_mediaquality_service
     hal_remotelyprovisionedcomponent_avf_service
     hal_threadnetwork_service
     hidl_memory_prop
@@ -52,4 +53,5 @@
     aconfigd_socket
     enable_16k_pages_prop
     proc_cgroups
+    media_quality_service
   ))
diff --git a/private/coredomain.te b/private/coredomain.te
index 93cbff53b..23ad43a03 100644
--- a/private/coredomain.te
+++ b/private/coredomain.te
@@ -183,6 +183,7 @@ full_treble_only(`
     -shell
     -system_server
     -traceur_app
+    -prefetch
     userdebug_or_eng(`-profcollectd')
     userdebug_or_eng(`-simpleperf_boot')
   } debugfs_tracing:file no_rw_file_perms;
@@ -220,6 +221,7 @@ full_treble_only(`
   neverallow {
     coredomain
     -adbd
+    -adbd_tradeinmode
     -init
     -mediaprovider
     -system_server
diff --git a/private/crash_dump.te b/private/crash_dump.te
index b2d3bd5a0..a9a802ce3 100644
--- a/private/crash_dump.te
+++ b/private/crash_dump.te
@@ -19,13 +19,7 @@ allow crash_dump {
 }:process { ptrace signal sigchld sigstop sigkill };
 
 userdebug_or_eng(`
-  allow crash_dump {
-    apexd
-    keystore
-    llkd
-    logd
-    vold
-  }:process { ptrace signal sigchld sigstop sigkill };
+  allow crash_dump { apexd llkd logd vold }:process { ptrace signal sigchld sigstop sigkill };
 ')
 
 # Read ART APEX data directory
@@ -135,7 +129,6 @@ neverallow crash_dump {
   init
   kernel
   keystore
-  userdebug_or_eng(`-keystore')
   llkd
   userdebug_or_eng(`-llkd')
   logd
diff --git a/private/crosvm.te b/private/crosvm.te
index ccfffa01e..750df24dc 100644
--- a/private/crosvm.te
+++ b/private/crosvm.te
@@ -115,6 +115,15 @@ is_flag_enabled(RELEASE_AVF_SUPPORT_CUSTOM_VM_WITH_PARAVIRTUALIZED_DEVICES, `
   # Allow crosvm to play sound.
   binder_call(crosvm, audioserver)
   allow crosvm audioserver_service:service_manager find;
+
+  # Allow crosvm to mount fuse path in guest VM through virtiofs
+  allow crosvm fuse:file create_file_perms;
+  allow crosvm fuse:dir create_dir_perms;
+  allow crosvm mnt_user_file:dir search;
+
+  # Allow crosvm to create unix socket for vhost-user-fs
+  allow crosvm virtualizationservice_data_file:dir { add_name write remove_name };
+  allow crosvm virtualizationservice_data_file:sock_file { create write unlink };
 ')
 
 # crosvm tries to use netlink sockets as part its APCI implementation, but we don't need it for AVF (b/228077254)
@@ -184,11 +193,12 @@ full_treble_only(`
     -vendor_vm_data_file
     # These types are not required for crosvm, but the access is granted to globally in domain.te
     # thus should be exempted here.
+    -vendor_cgroup_desc_file
     -vendor_configs_file
     -vendor_microdroid_file
     -vndk_sp_file
     -vendor_task_profiles_file
-    is_flag_enabled(RELEASE_AVF_SUPPORT_CUSTOM_VM_WITH_PARAVIRTUALIZED_DEVICES, `-same_process_hal_file')
+    -same_process_hal_file
   }:file *;
 ')
 
@@ -204,10 +214,12 @@ neverallow crosvm {
 }:file read;
 
 # Only virtualizationmanager can run crosvm
+# Allow vmlauncher app to launch crosvm for virtiofs
 neverallow {
   domain
   -crosvm
   -virtualizationmanager
+  -vmlauncher_app
 
   is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `-early_virtmgr')
 } crosvm_exec:file no_x_file_perms;
diff --git a/private/custom_vm_setup.te b/private/custom_vm_setup.te
deleted file mode 100644
index c14f5e0e0..000000000
--- a/private/custom_vm_setup.te
+++ /dev/null
@@ -1,6 +0,0 @@
-type custom_vm_setup, domain, coredomain;
-type custom_vm_setup_exec, system_file_type, exec_type, file_type;
-
-is_flag_enabled(RELEASE_AVF_SUPPORT_CUSTOM_VM_WITH_PARAVIRTUALIZED_DEVICES, `
-  init_daemon_domain(custom_vm_setup)
-')
diff --git a/private/domain.te b/private/domain.te
index e9cc7f565..456389567 100644
--- a/private/domain.te
+++ b/private/domain.te
@@ -424,10 +424,11 @@ allow domain cgroup_v2:dir search;
 allow { domain -appdomain -rs } cgroup_v2:dir w_dir_perms;
 allow { domain -appdomain -rs } cgroup_v2:file w_file_perms;
 
+allow domain cgroup_desc_file:file r_file_perms;
 allow domain cgroup_rc_file:dir search;
 allow domain cgroup_rc_file:file r_file_perms;
 allow domain task_profiles_file:file r_file_perms;
-allow domain task_profiles_api_file:file r_file_perms;
+allow domain vendor_cgroup_desc_file:file r_file_perms;
 allow domain vendor_task_profiles_file:file r_file_perms;
 
 # Allow all domains to read sys.use_memfd to determine
@@ -583,7 +584,6 @@ allow {
 # all processes need access to the underlying files.
 is_flag_enabled(RELEASE_READ_FROM_NEW_STORAGE, `
   r_dir_file(domain, aconfig_storage_metadata_file);
-  r_dir_file(domain, aconfig_test_mission_files);
 ')
 
 r_dir_file({ coredomain appdomain }, system_aconfig_storage_file);
@@ -816,6 +816,7 @@ neverallow { domain -init } userdebug_or_eng_prop:property_service set;
 neverallow {
   domain
   -adbd
+  -adbd_tradeinmode
   -dumpstate
   -fastbootd
   -hal_camera_server
@@ -861,6 +862,7 @@ neverallow {
   userdebug_or_eng(`-fsck')
   userdebug_or_eng(`-init')
   -recovery
+  userdebug_or_eng(`-remount')
   -update_engine
 } system_block_device:blk_file { write append };
 
@@ -1160,6 +1162,7 @@ full_treble_only(`
     } {
         system_file_type
         -system_lib_file
+        -system_bootstrap_lib_file
         -system_linker_exec
         -crash_dump_exec
         -netutils_wrapper_exec
@@ -1230,6 +1233,7 @@ full_treble_only(`
     -vendor_init
   } {
     system_file_type
+    -cgroup_desc_file
     -crash_dump_exec
     -file_contexts_file
     -netutils_wrapper_exec
@@ -1237,6 +1241,7 @@ full_treble_only(`
     -system_event_log_tags_file
     -system_group_file
     -system_lib_file
+    -system_bootstrap_lib_file
     with_asan(`-system_asan_options_file')
     -system_linker_exec
     -system_linker_config_file
@@ -1244,7 +1249,6 @@ full_treble_only(`
     -system_seccomp_policy_file
     -system_security_cacerts_file
     -system_zoneinfo_file
-    -task_profiles_api_file
     -task_profiles_file
     userdebug_or_eng(`-tcpdump_exec')
     # Vendor components still can invoke shell commands via /system/bin/sh
@@ -1363,10 +1367,17 @@ neverallow {
 } shell:process { transition dyntransition };
 
 # Only domains spawned from zygote, runas and simpleperf_app_runner may have
-# the appdomain attribute. simpleperf is excluded as a domain transitioned to
-# when running an app-scoped profiling session.
+# the appdomain attribute.
+#
+# simpleperf is excluded as a domain transitioned to when running an app-scoped
+# profiling session.
+#
+# tradeinmode is excluded; it is only run when adbd is in trade-in mode,
+# transitioned from the limited adbd_tradeinmode context. It is a wrapper
+# around "am" to avoid exposing the shell context when adbd is in trade-in
+# mode.
 neverallow { domain -simpleperf_app_runner -runas -app_zygote -webview_zygote -zygote } {
-  appdomain -shell -simpleperf userdebug_or_eng(`-su')
+  appdomain -shell -simpleperf userdebug_or_eng(`-su') -tradeinmode
 }:process { transition dyntransition };
 
 # Minimize read access to shell- or app-writable symlinks.
@@ -1752,6 +1763,7 @@ is_flag_enabled(RELEASE_UNLOCKED_STORAGE_API, `
 # that these files cannot be accessed by other domains to ensure that the files
 # do not change between system_server staging the files and apexd processing
 # the files.
+# The update_provider can also stage files before apexd processes them.
 neverallow {
   domain
   -init
@@ -1760,6 +1772,7 @@ neverallow {
   -installd
   -priv_app
   -virtualizationmanager
+  -update_provider # WARNING: USING THIS ATTRIBUTE WILL CAUSE CTS TO FAIL!
 } staging_data_file:dir *;
 neverallow {
   domain
@@ -1774,12 +1787,19 @@ neverallow {
   -shell
   -virtualizationmanager
   -crosvm
+  -update_provider # WARNING: USING THIS ATTRIBUTE WILL CAUSE CTS TO FAIL!
 } staging_data_file:file *;
-neverallow { domain -init -system_server -installd} staging_data_file:dir no_w_dir_perms;
-# apexd needs the link and unlink permissions, so list every `no_w_file_perms`
-# except for `link` and `unlink`.
-neverallow { domain -init -system_server } staging_data_file:file
-  { append create relabelfrom rename setattr write no_x_file_perms };
+# WARNING: USING THE update_provider ATTRIBUTE WILL CAUSE CTS TO FAIL!
+neverallow { domain -init -system_server -installd -update_provider } staging_data_file:dir no_w_dir_perms;
+# apexd needs the link/unlink/rename permissions
+# WARNING: USING THE update_provider ATTRIBUTE WILL CAUSE CTS TO FAIL!
+neverallow { domain -init -system_server -installd -apexd -update_provider } staging_data_file:file {
+  no_w_file_perms no_x_file_perms
+};
+neverallow apexd staging_data_file:file {
+  append create relabelfrom setattr write # no_w_file_perms -link -unlink -rename
+  no_x_file_perms
+};
 
 neverallow {
     domain
@@ -1811,6 +1831,7 @@ neverallow {
     file_type
     -system_file_type
     -system_lib_file
+    -system_bootstrap_lib_file
     -system_linker_exec
     -vendor_file_type
     -exec_type
@@ -2060,6 +2081,7 @@ full_treble_only(`
     -vendor_apex_file
     -vendor_apex_metadata_file
     -vendor_boot_ota_file
+    -vendor_cgroup_desc_file
     -vendor_configs_file
     -vendor_microdroid_file
     -vendor_service_contexts_file
@@ -2155,7 +2177,6 @@ neverallow {
   -artd
   -dumpstate
   -installd
-  userdebug_or_eng(`-aconfigd')
   userdebug_or_eng(`-uncrypt')
   userdebug_or_eng(`-virtualizationmanager')
   userdebug_or_eng(`-virtualizationservice')
@@ -2203,7 +2224,6 @@ neverallow {
   -installd
   -simpleperf_app_runner
   -system_server # why?
-  userdebug_or_eng(`-aconfigd')
   userdebug_or_eng(`-uncrypt')
   userdebug_or_eng(`-virtualizationmanager')
   userdebug_or_eng(`-crosvm')
@@ -2234,10 +2254,6 @@ neverallow { domain -init } kcmdlinectrl:process { dyntransition transition };
 # For now, don't allow processes other than gmscore to access /data/misc_ce/<userid>/checkin
 neverallow { domain -gmscore_app -init -vold_prepare_subdirs } checkin_data_file:{dir file} *;
 
-# Do not allow write access to aconfig flag value files except init and aconfigd
-neverallow { domain -init -aconfigd -system_server } aconfig_storage_metadata_file:dir no_w_dir_perms;
-neverallow { domain -init -aconfigd -system_server } aconfig_storage_metadata_file:file no_w_file_perms;
-
 neverallow { domain -dexopt_chroot_setup -init } proc:{ file dir } mounton;
 neverallow { domain -dexopt_chroot_setup -init -zygote } proc_type:{ file dir } mounton;
 
diff --git a/private/dumpstate.te b/private/dumpstate.te
index 13b7b9f90..5e3bce5ca 100644
--- a/private/dumpstate.te
+++ b/private/dumpstate.te
@@ -34,7 +34,6 @@ userdebug_or_eng(`
 ')
 
 r_dir_file(dumpstate, aconfig_storage_metadata_file);
-r_dir_file(dumpstate, aconfig_test_mission_files);
 
 # Allow dumpstate to make binder calls to incidentd
 binder_call(dumpstate, incidentd)
diff --git a/private/fastbootd.te b/private/fastbootd.te
index 66dd2b1e7..a62cc47af 100644
--- a/private/fastbootd.te
+++ b/private/fastbootd.te
@@ -159,6 +159,9 @@ recovery_only(`
   allow fastbootd gsi_metadata_file_type:dir search;
   allow fastbootd ota_metadata_file:dir rw_dir_perms;
   allow fastbootd ota_metadata_file:file create_file_perms;
+
+  # Fastbootd uses liblogwrap to write mke2fs logs to kmsg, liblogwrap requires devpts.
+  allow fastbootd devpts:chr_file rw_file_perms;
 ')
 
 # This capability allows fastbootd to circumvent memlock rlimits while using
diff --git a/private/ferrochrome_app.te b/private/ferrochrome_app.te
deleted file mode 100644
index e12c84c62..000000000
--- a/private/ferrochrome_app.te
+++ /dev/null
@@ -1,11 +0,0 @@
-type ferrochrome_app, domain;
-typeattribute ferrochrome_app coredomain;
-
-app_domain(ferrochrome_app)
-
-allow ferrochrome_app app_api_service:service_manager find;
-allow ferrochrome_app system_api_service:service_manager find;
-
-# TODO(b/348113995): after remove sysprop usage, we can use just (priv_)app.te
-set_prop(ferrochrome_app, debug_prop);
-get_prop(ferrochrome_app, debug_prop);
diff --git a/private/file.te b/private/file.te
index 70b8523bc..189fb4789 100644
--- a/private/file.te
+++ b/private/file.te
@@ -156,7 +156,10 @@ type system_font_fallback_file, system_file_type, file_type;
 type sysfs_uprobe, fs_type, sysfs_type;
 
 # Type for aconfig daemon socket
-type aconfigd_socket, file_type, coredomain_socket;
+type aconfigd_socket, file_type, coredomain_socket, mlstrustedobject;
+
+# Type for aconfig mainline daemon socket
+type aconfigd_mainline_socket, file_type, coredomain_socket,  mlstrustedobject;
 
 # Type for /(system|system_ext|product)/etc/aconfig
 type system_aconfig_storage_file, system_file_type, file_type;
@@ -164,11 +167,12 @@ type system_aconfig_storage_file, system_file_type, file_type;
 # Type for /vendor/etc/aconfig
 type vendor_aconfig_storage_file, vendor_file_type, file_type;
 
-type aconfig_test_mission_files, file_type;
-
 # /data/misc/connectivityblobdb
 type connectivityblob_data_file, file_type, data_file_type, core_data_file_type;
 
+# /data/misc/wifi/mainline_supplicant
+type mainline_supplicant_data_file, file_type, data_file_type, core_data_file_type;
+
 # Type for /mnt/pre_reboot_dexopt
 type pre_reboot_dexopt_file, file_type;
 
@@ -182,6 +186,9 @@ type apk_metadata_file, file_type, data_file_type, core_data_file_type;
 # Type for /sys/kernel/mm/pgsize_migration/enabled
 type sysfs_pgsize_migration, fs_type, sysfs_type;
 
+# /sys/firmware/acpi/tables
+type sysfs_firmware_acpi_tables, fs_type, sysfs_type;
+
 # Allow files to be created in their appropriate filesystems.
 allow fs_type self:filesystem associate;
 allow cgroup tmpfs:filesystem associate;
@@ -215,6 +222,11 @@ type storage_area_content_file, file_type, data_file_type, core_data_file_type,
 # /data/misc_ce/userId/storage_area_keys
 type storage_area_key_file, file_type, data_file_type, core_data_file_type;
 
+# /metadata/tradeinmode files
+type tradeinmode_metadata_file, file_type;
+
+# /metadata/prefetch files
+type prefetch_metadata_file, file_type;
 
 # Types added in 202504 in public/file.te
 until_board_api(202504, `
@@ -239,5 +251,10 @@ until_board_api(202504, `
     # boot otas for 16KB developer option
     type vendor_boot_ota_file, vendor_file_type, file_type;
 ')
+
+until_board_api(202504, `
+    type tee_service_contexts_file, system_file_type, file_type;
+')
+
 ## END Types added in 202504 in public/file.te
 
diff --git a/private/file_contexts b/private/file_contexts
index fa2fe3a22..d6f7113f3 100644
--- a/private/file_contexts
+++ b/private/file_contexts
@@ -83,6 +83,7 @@
 /vendor_seapp_contexts      u:object_r:seapp_contexts_file:s0
 /plat_seapp_contexts     u:object_r:seapp_contexts_file:s0
 /sepolicy           u:object_r:sepolicy_file:s0
+/plat_tee_service_contexts   u:object_r:tee_service_contexts_file:s0
 /plat_service_contexts   u:object_r:service_contexts_file:s0
 /plat_hwservice_contexts   u:object_r:hwservice_contexts_file:s0
 /plat_keystore2_key_contexts u:object_r:keystore2_key_contexts_file:s0
@@ -155,7 +156,8 @@
 /dev/snd(/.*)?		u:object_r:audio_device:s0
 /dev/socket(/.*)?	u:object_r:socket_device:s0
 /dev/socket/adbd	u:object_r:adbd_socket:s0
-/dev/socket/aconfigd	u:object_r:aconfigd_socket:s0
+/dev/socket/aconfigd_mainline	u:object_r:aconfigd_mainline_socket:s0
+/dev/socket/aconfigd_system	u:object_r:aconfigd_socket:s0
 /dev/socket/dnsproxyd	u:object_r:dnsproxyd_socket:s0
 /dev/socket/dumpstate	u:object_r:dumpstate_socket:s0
 /dev/socket/fwmarkd	u:object_r:fwmarkd_socket:s0
@@ -327,6 +329,7 @@
 /system/bin/bootstrap/linkerconfig u:object_r:linkerconfig_exec:s0
 /system/bin/llkd        u:object_r:llkd_exec:s0
 /system/bin/lmkd        u:object_r:lmkd_exec:s0
+/system/bin/mmd         u:object_r:mmd_exec:s0
 /system/bin/usbd   u:object_r:usbd_exec:s0
 /system/bin/inputflinger u:object_r:inputflinger_exec:s0
 /system/bin/logd        u:object_r:logd_exec:s0
@@ -362,9 +365,9 @@
 /system/bin/virtual_camera          u:object_r:virtual_camera_exec:s0
 /system/bin/hw/android\.frameworks\.bufferhub@1\.0-service    u:object_r:fwk_bufferhub_exec:s0
 /system/bin/hw/android\.system\.suspend-service               u:object_r:system_suspend_exec:s0
-/system/etc/aconfig(/.*)?                u:object_r:system_aconfig_storage_file:s0
+/system/etc/aconfig(/.*)?               u:object_r:system_aconfig_storage_file:s0
 /system/etc/cgroups\.json               u:object_r:cgroup_desc_file:s0
-/system/etc/task_profiles/cgroups_[0-9]+\.json               u:object_r:cgroup_desc_api_file:s0
+/system/etc/task_profiles/cgroups_[0-9]+\.json               u:object_r:cgroup_desc_file:s0
 /system/etc/event-log-tags              u:object_r:system_event_log_tags_file:s0
 /system/etc/font_fallback.xml           u:object_r:system_font_fallback_file:s0
 /system/etc/group                       u:object_r:system_group_file:s0
@@ -376,6 +379,7 @@
 /system/etc/selinux/mapping/[0-9]+\.[0-9]+(\.compat)?\.cil       u:object_r:sepolicy_file:s0
 /system/etc/selinux/plat_mac_permissions\.xml u:object_r:mac_perms_file:s0
 /system/etc/selinux/plat_property_contexts  u:object_r:property_contexts_file:s0
+/system/etc/selinux/plat_tee_service_contexts  u:object_r:tee_service_contexts_file:s0
 /system/etc/selinux/plat_service_contexts  u:object_r:service_contexts_file:s0
 /system/etc/selinux/plat_hwservice_contexts  u:object_r:hwservice_contexts_file:s0
 /system/etc/selinux/plat_keystore2_key_contexts  u:object_r:keystore2_key_contexts_file:s0
@@ -384,7 +388,7 @@
 /system/etc/selinux/plat_sepolicy\.cil       u:object_r:sepolicy_file:s0
 /system/etc/selinux/plat_and_mapping_sepolicy\.cil\.sha256 u:object_r:sepolicy_file:s0
 /system/etc/task_profiles\.json  u:object_r:task_profiles_file:s0
-/system/etc/task_profiles/task_profiles_[0-9]+\.json  u:object_r:task_profiles_api_file:s0
+/system/etc/task_profiles/task_profiles_[0-9]+\.json  u:object_r:task_profiles_file:s0
 /system/usr/share/zoneinfo(/.*)? u:object_r:system_zoneinfo_file:s0
 /system/bin/adbd                 u:object_r:adbd_exec:s0
 /system/bin/vold_prepare_subdirs u:object_r:vold_prepare_subdirs_exec:s0
@@ -393,7 +397,7 @@
 /system/bin/bpfloader            u:object_r:bpfloader_exec:s0
 /system/bin/netbpfload           u:object_r:bpfloader_exec:s0
 /system/bin/watchdogd            u:object_r:watchdogd_exec:s0
-/system/bin/aconfigd             u:object_r:aconfigd_exec:s0
+/system/bin/aconfigd-system      u:object_r:aconfigd_exec:s0
 /system/bin/apexd                u:object_r:apexd_exec:s0
 /system/bin/gsid                 u:object_r:gsid_exec:s0
 /system/bin/simpleperf           u:object_r:simpleperf_exec:s0
@@ -407,6 +411,10 @@
 /system/bin/evsmanagerd          u:object_r:evsmanagerd_exec:s0
 /system/bin/android\.automotive\.evs\.manager@1\.[0-9]+ u:object_r:evsmanagerd_exec:s0
 /system/bin/uprobestats           u:object_r:uprobestats_exec:s0
+/system/bin/bert_collector        u:object_r:bert_collector_exec:s0
+/system/bin/linux_vm_setup        u:object_r:linux_vm_setup_exec:s0
+/system/bin/tradeinmode           u:object_r:tradeinmode_exec:s0
+/system/bin/prefetch              u:object_r:prefetch_exec:s0
 
 #############################
 # Vendor files
@@ -465,8 +473,11 @@
 /(odm|vendor/odm|vendor|system/vendor)/apex(/[^/]+){0,2}              u:object_r:vendor_apex_file:s0
 
 # Input configuration
+/(odm|vendor/odm|vendor|system/vendor)/usr/keylayout(/.*)?            u:object_r:vendor_keylayout_file:s0
 /(odm|vendor/odm|vendor|system/vendor)/usr/keylayout(/.*)?\.kl        u:object_r:vendor_keylayout_file:s0
+/(odm|vendor/odm|vendor|system/vendor)/usr/keychars(/.*)?             u:object_r:vendor_keychars_file:s0
 /(odm|vendor/odm|vendor|system/vendor)/usr/keychars(/.*)?\.kcm        u:object_r:vendor_keychars_file:s0
+/(odm|vendor/odm|vendor|system/vendor)/usr/idc(/.*)?                  u:object_r:vendor_idc_file:s0
 /(odm|vendor/odm|vendor|system/vendor)/usr/idc(/.*)?\.idc             u:object_r:vendor_idc_file:s0
 
 /oem(/.*)?              u:object_r:oemfs:s0
@@ -488,6 +499,7 @@
 /(odm|vendor/odm)/etc/selinux/odm_hwservice_contexts            u:object_r:hwservice_contexts_file:s0
 /(odm|vendor/odm)/etc/selinux/odm_keystore2_key_contexts        u:object_r:keystore2_key_contexts_file:s0
 /(odm|vendor/odm)/etc/selinux/odm_mac_permissions\.xml          u:object_r:mac_perms_file:s0
+/(odm|vendor/odm)/etc/selinux/odm_tee_service_contexts          u:object_r:tee_service_contexts_file:s0
 
 #############################
 # Product files
@@ -504,6 +516,7 @@
 /(product|system/product)/etc/selinux/product_seapp_contexts     u:object_r:seapp_contexts_file:s0
 /(product|system/product)/etc/selinux/product_service_contexts   u:object_r:service_contexts_file:s0
 /(product|system/product)/etc/selinux/product_mac_permissions\.xml u:object_r:mac_perms_file:s0
+/(product|system/product)/etc/selinux/product_tee_service_contexts  u:object_r:tee_service_contexts_file:s0
 
 /(product|system/product)/lib(64)?(/.*)?                         u:object_r:system_lib_file:s0
 
@@ -533,14 +546,14 @@
 /(system_ext|system/system_ext)/bin/hidl_lazy_cb_test_server u:object_r:hidl_lazy_test_server_exec:s0
 /(system_ext|system/system_ext)/bin/hwservicemanager         u:object_r:hwservicemanager_exec:s0
 /(system_ext|system/system_ext)/bin/hw/android\.hidl\.allocator@1\.0-service u:object_r:hal_allocator_default_exec:s0
-
-/(system_ext|system/system_ext)/bin/custom_vm_setup       u:object_r:custom_vm_setup_exec:s0
+/(system_ext|system/system_ext)/bin/rkp_cert_processor       u:object_r:rkp_cert_processor_exec:s0
 
 /(system_ext|system/system_ext)/bin/canhalconfigurator(-aidl)? u:object_r:canhalconfigurator_exec:s0
 
 /(system_ext|system/system_ext)/lib(64)?(/.*)?      u:object_r:system_lib_file:s0
 
 /(system_ext|system/system_ext)/etc/aconfig(/.*)?                u:object_r:system_aconfig_storage_file:s0
+/(system_ext|system/system_ext)/etc/selinux/system_ext_tee_service_contexts  u:object_r:tee_service_contexts_file:s0
 
 #############################
 # VendorDlkm files
@@ -707,6 +720,7 @@
 /data/misc/vpn(/.*)?            u:object_r:vpn_data_file:s0
 /data/misc/wifi(/.*)?           u:object_r:wifi_data_file:s0
 /data/misc_ce/[0-9]+/wifi(/.*)? u:object_r:wifi_data_file:s0
+/data/misc/wifi/mainline_supplicant(/.*)?  u:object_r:mainline_supplicant_data_file:s0
 /data/misc/wifi/sockets(/.*)?   u:object_r:wpa_socket:s0
 /data/misc/wifi/sockets/wpa_ctrl.*   u:object_r:system_wpa_socket:s0
 /data/misc/vold(/.*)?           u:object_r:vold_data_file:s0
@@ -886,7 +900,8 @@
 /metadata/repair-mode(/.*)?    u:object_r:repair_mode_metadata_file:s0
 /metadata/aconfig(/.*)?    u:object_r:aconfig_storage_metadata_file:s0
 /metadata/aconfig/flags(/.*)?    u:object_r:aconfig_storage_flags_metadata_file:s0
-/metadata/aconfig_test_missions(/.*)?    u:object_r:aconfig_test_mission_files:s0
+/metadata/tradeinmode(/.*)?    u:object_r:tradeinmode_metadata_file:s0
+/metadata/prefetch(/.*)?    u:object_r:prefetch_metadata_file:s0
 
 ############################
 # mount point for ota metadata
diff --git a/private/flags_health_check.te b/private/flags_health_check.te
index c6785dd12..db7f08f58 100644
--- a/private/flags_health_check.te
+++ b/private/flags_health_check.te
@@ -34,6 +34,7 @@ set_prop(flags_health_check, device_config_memory_safety_native_prop)
 set_prop(flags_health_check, device_config_remote_key_provisioning_native_prop)
 set_prop(flags_health_check, device_config_camera_native_prop)
 set_prop(flags_health_check, device_config_tethering_u_or_later_native_prop)
+set_prop(flags_health_check, device_config_mmd_native_prop)
 set_prop(flags_health_check, next_boot_prop)
 
 allow flags_health_check server_configurable_flags_data_file:dir rw_dir_perms;
diff --git a/private/genfs_contexts b/private/genfs_contexts
index b8b724739..3ff1012b7 100644
--- a/private/genfs_contexts
+++ b/private/genfs_contexts
@@ -135,7 +135,6 @@ genfscon sysfs /class/rfkill/rfkill3/state        u:object_r:sysfs_bluetooth_wri
 genfscon sysfs /class/rtc                         u:object_r:sysfs_rtc:s0
 genfscon sysfs /class/switch                      u:object_r:sysfs_switch:s0
 genfscon sysfs /class/wakeup                      u:object_r:sysfs_wakeup:s0
-genfscon sysfs /class/udc                         u:object_r:sysfs_udc:s0
 genfscon sysfs /devices/platform/nfc-power/nfc_power u:object_r:sysfs_nfc_power_writable:s0
 genfscon sysfs /devices/virtual/android_usb     u:object_r:sysfs_android_usb:s0
 genfscon sysfs /devices/virtual/block/            u:object_r:sysfs_devices_block:s0
@@ -149,6 +148,7 @@ genfscon sysfs /devices/virtual/misc/hw_random    u:object_r:sysfs_hwrandom:s0
 genfscon sysfs /devices/virtual/net             u:object_r:sysfs_net:s0
 genfscon sysfs /devices/virtual/switch          u:object_r:sysfs_switch:s0
 genfscon sysfs /devices/virtual/wakeup          u:object_r:sysfs_wakeup:s0
+genfscon sysfs /firmware/acpi/tables              u:object_r:sysfs_firmware_acpi_tables:s0
 genfscon sysfs /firmware/devicetree/base/avf u:object_r:sysfs_dt_avf:s0
 genfscon sysfs /firmware/devicetree/base/firmware/android u:object_r:sysfs_dt_firmware_android:s0
 genfscon sysfs /fs/ext4/features                  u:object_r:sysfs_fs_ext4_features:s0
@@ -175,6 +175,7 @@ genfscon sysfs /kernel/notes u:object_r:sysfs_kernel_notes:s0
 genfscon sysfs /kernel/uevent_helper u:object_r:sysfs_usermodehelper:s0
 genfscon sysfs /kernel/wakeup_reasons u:object_r:sysfs_wakeup_reasons:s0
 genfscon sysfs /kernel/dmabuf/buffers u:object_r:sysfs_dmabuf_stats:s0
+genfscon sysfs /module/dm_bufio/parameters/max_age_seconds u:object_r:sysfs_dm_verity:s0
 genfscon sysfs /module/dm_verity/parameters/prefetch_cluster u:object_r:sysfs_dm_verity:s0
 genfscon sysfs /module/lowmemorykiller u:object_r:sysfs_lowmemorykiller:s0
 genfscon sysfs /module/tcp_cubic/parameters u:object_r:sysfs_net:s0
diff --git a/private/gmscore_app.te b/private/gmscore_app.te
index fa3420acc..148cb7e68 100644
--- a/private/gmscore_app.te
+++ b/private/gmscore_app.te
@@ -132,8 +132,10 @@ allow gmscore_app shell_data_file:file r_file_perms;
 allow gmscore_app shell_data_file:dir r_dir_perms;
 
 # allow gms core app write to aconfigd socket
-allow gmscore_app aconfigd_socket:sock_file {read write};
-allow gmscore_app aconfigd:unix_stream_socket connectto;
+unix_socket_connect(gmscore_app, aconfigd, aconfigd);
+
+# allow gms core app write to aconfigd_mainline socket
+unix_socket_connect(gmscore_app, aconfigd_mainline, aconfigd_mainline);
 
 # b/18504118: Allow reads from /data/anr/traces.txt
 allow gmscore_app anr_data_file:file r_file_perms;
diff --git a/private/hal_mediaquality.te b/private/hal_mediaquality.te
new file mode 100644
index 000000000..5bcdbbc32
--- /dev/null
+++ b/private/hal_mediaquality.te
@@ -0,0 +1,9 @@
+starting_at_board_api(202504, `
+    binder_call(hal_mediaquality_client, hal_mediaquality_server)
+    binder_call(hal_mediaquality_server, hal_mediaquality_client)
+
+    hal_attribute_service(hal_mediaquality, hal_mediaquality_service)
+
+    binder_call(hal_mediaquality_server, servicemanager)
+    binder_call(hal_mediaquality_client, servicemanager)
+')
diff --git a/private/init.te b/private/init.te
index 73ab049cd..012ef0bde 100644
--- a/private/init.te
+++ b/private/init.te
@@ -84,6 +84,11 @@ set_prop(init, vts_status_prop)
 
 # Allow init to set 16kb app compatibility props
 set_prop(init, bionic_linker_16kb_app_compat_prop)
+set_prop(init, pm_16kb_app_compat_prop)
+
+
+# Allow init to set/get prefetch boot prop to initiate record/replay
+set_prop(init, ctl_prefetch_prop);
 
 # Allow accessing /sys/kernel/tracing/instances/bootreceiver to set up tracing.
 allow init debugfs_bootreceiver_tracing:file w_file_perms;
@@ -237,7 +242,6 @@ allow init cgroup:dir create_dir_perms;
 allow init cgroup:file rw_file_perms;
 allow init cgroup_rc_file:file rw_file_perms;
 allow init cgroup_desc_file:file r_file_perms;
-allow init cgroup_desc_api_file:file r_file_perms;
 allow init vendor_cgroup_desc_file:file r_file_perms;
 allow init cgroup_v2:dir { mounton create_dir_perms};
 allow init cgroup_v2:file rw_file_perms;
@@ -465,6 +469,7 @@ allow init debugfs_tracing:file w_file_perms;
 allow init debugfs_tracing_instances:dir create_dir_perms;
 allow init debugfs_tracing_instances:file w_file_perms;
 allow init debugfs_wifi_tracing:file w_file_perms;
+allow init debugfs_wifi_tracing:dir create_dir_perms;
 
 # chown/chmod on pseudo files.
 allow init {
@@ -616,6 +621,7 @@ allow init sysfs_vibrator:file w_file_perms;
 allow init {
   sysfs_android_usb
   sysfs_devices_system_cpu
+  sysfs_firmware_acpi_tables
   sysfs_ipv4
   sysfs_leds
   sysfs_lowmemorykiller
@@ -717,6 +723,8 @@ allow init kernel:process { getsched setsched };
 # swapon() needs write access to swap device
 # system/core/fs_mgr/fs_mgr.c - fs_mgr_swapon_all
 allow init swap_block_device:blk_file rw_file_perms;
+# Allow to change group owner and permissions for new swap setup in mmd
+allow init swap_block_device:blk_file setattr;
 
 # Create and access /dev files without a specific type,
 # e.g. /dev/.coldboot_done, /dev/.booting
diff --git a/private/keystore.te b/private/keystore.te
index 53e5dd3e2..50542b009 100644
--- a/private/keystore.te
+++ b/private/keystore.te
@@ -20,6 +20,9 @@ get_prop(keystore, device_logging_prop)
 # Allow keystore to check if the system is rkp only.
 get_prop(keystore, remote_prov_prop)
 
+# Allow keystore to check whether to post-process RKP certificates
+get_prop(keystore, remote_prov_cert_prop)
+
 # Allow keystore to check rkpd feature flags
 get_prop(keystore, device_config_remote_key_provisioning_native_prop)
 
@@ -45,6 +48,7 @@ typeattribute keystore mlstrustedsubject;
 binder_use(keystore)
 binder_service(keystore)
 binder_call(keystore, remote_provisioning_service_server)
+binder_call(keystore, rkp_cert_processor)
 binder_call(keystore, system_server)
 binder_call(keystore, wificond)
 
@@ -54,8 +58,9 @@ allow keystore keystore_exec:file { getattr };
 
 add_service(keystore, keystore_service)
 allow keystore sec_key_att_app_id_provider_service:service_manager find;
-allow keystore dropbox_service:service_manager find;
 allow keystore remote_provisioning_service:service_manager find;
+allow keystore rkp_cert_processor_service:service_manager find;
+
 add_service(keystore, apc_service)
 add_service(keystore, keystore_compat_hal_service)
 add_service(keystore, authorization_service)
@@ -88,8 +93,7 @@ neverallow { domain -keystore } keystore_data_file:notdevfile_class_set ~{ relab
 neverallow { domain -keystore -init } keystore_data_file:dir *;
 neverallow { domain -keystore -init } keystore_data_file:notdevfile_class_set *;
 
-# TODO(b/186868271): Remove the crash dump exception soon-ish (maybe by May 14, 2021?)
-neverallow { domain userdebug_or_eng(`-crash_dump') } keystore:process ptrace;
+neverallow * keystore:process ptrace;
 
 # Only keystore can set keystore.crash_count system property. Since init is allowed to set any
 # system property, an exception is added for init as well.
diff --git a/private/linux_vm_setup.te b/private/linux_vm_setup.te
new file mode 100644
index 000000000..ba483e8c9
--- /dev/null
+++ b/private/linux_vm_setup.te
@@ -0,0 +1,6 @@
+type linux_vm_setup, domain, coredomain;
+type linux_vm_setup_exec, system_file_type, exec_type, file_type;
+
+is_flag_enabled(RELEASE_AVF_SUPPORT_CUSTOM_VM_WITH_PARAVIRTUALIZED_DEVICES, `
+  init_daemon_domain(linux_vm_setup)
+')
diff --git a/private/mmd.te b/private/mmd.te
new file mode 100644
index 000000000..90510f1d5
--- /dev/null
+++ b/private/mmd.te
@@ -0,0 +1,31 @@
+# mmd memory management daemon
+type mmd, domain;
+typeattribute mmd coredomain;
+type mmd_exec, system_file_type, exec_type, file_type;
+
+init_daemon_domain(mmd)
+
+# Set mmd.enabled_aconfig properties.
+set_prop(mmd, mmd_prop)
+get_prop(mmd, device_config_mmd_native_prop)
+
+# mmd binder setup
+add_service(mmd, mmd_service)
+binder_use(mmd)
+
+# Read /proc/swaps
+allow mmd proc_swaps:file r_file_perms;
+
+# zram sysfs access
+allow mmd sysfs_zram:dir search;
+allow mmd sysfs_zram:file rw_file_perms;
+
+# procfs
+allow mmd proc_meminfo:file r_file_perms;
+
+# mkswap /dev/block/zram command
+allow mmd block_device:dir search;
+allow mmd swap_block_device:blk_file rw_file_perms;
+
+# swapon syscall
+allow mmd self:capability sys_admin;
diff --git a/private/nfc.te b/private/nfc.te
index f1a08f7a4..7050d5a7b 100644
--- a/private/nfc.te
+++ b/private/nfc.te
@@ -33,3 +33,6 @@ set_prop(nfc, nfc_prop);
 # the nfc process, from a file in
 # /data/data/com.android.shell/files/bugreports/bugreport-*.
 allow nfc shell_data_file:file read;
+
+# Allow to check whether security logging is enabled.
+get_prop(nfc, device_logging_prop)
diff --git a/private/ot_daemon.te b/private/ot_daemon.te
index 2fc74b50c..04cb70ffa 100644
--- a/private/ot_daemon.te
+++ b/private/ot_daemon.te
@@ -26,6 +26,9 @@ allow ot_daemon tun_device:chr_file {read write};
 # Allow OT daemon to read/write on the socket created by System Server
 allow ot_daemon system_server:rawip_socket rw_socket_perms_no_ioctl;
 
+# Allow OT daemon to read/write on the UDP sockets created by system server
+allow ot_daemon system_server:udp_socket rw_socket_perms;
+
 hal_client_domain(ot_daemon, hal_threadnetwork)
 
 # Only ot_daemon can publish the binder service
diff --git a/private/platform_app.te b/private/platform_app.te
index 320624cdb..e60dcdde2 100644
--- a/private/platform_app.te
+++ b/private/platform_app.te
@@ -99,6 +99,7 @@ allow platform_app app_api_service:service_manager find;
 allow platform_app system_api_service:service_manager find;
 allow platform_app vr_manager_service:service_manager find;
 allow platform_app stats_service:service_manager find;
+allow platform_app tradeinmode_service:service_manager find;
 
 # Allow platform apps to log via statsd.
 binder_call(platform_app, statsd)
diff --git a/private/prefetch.te b/private/prefetch.te
new file mode 100644
index 000000000..21287f3bf
--- /dev/null
+++ b/private/prefetch.te
@@ -0,0 +1,24 @@
+type prefetch, coredomain, domain;
+type prefetch_exec, exec_type, file_type, system_file_type;
+
+init_daemon_domain(prefetch)
+
+# Allow prefetch to start recording by enabling tracing event under
+# /sys/kernel/tracing/events/filemap/mm_filemap_add_to_page_cache
+allow prefetch debugfs_tracing_instances:dir create_dir_perms;
+allow prefetch debugfs_tracing_instances:file rw_file_perms;
+
+# Allow to read/write/create/delete to storage prefetch record files
+allow prefetch metadata_file:dir search;
+allow prefetch prefetch_metadata_file:dir rw_dir_perms;
+allow prefetch prefetch_metadata_file:file create_file_perms;
+
+get_prop(prefetch, prefetch_boot_prop);
+set_prop(prefetch, prefetch_service_prop);
+
+# Disallow other domains controlling prefetch service.
+neverallow {
+  domain
+  -init
+  -shell
+} ctl_prefetch_prop:property_service set;
diff --git a/private/priv_app.te b/private/priv_app.te
index bb5da7c1e..1ef5be156 100644
--- a/private/priv_app.te
+++ b/private/priv_app.te
@@ -136,6 +136,9 @@ allow priv_app incidentd:fifo_file { read write };
 # Allow priv_apps to check whether Dynamic System Update is enabled
 get_prop(priv_app, dynamic_system_prop)
 
+# Allow privileged apps to read trade in mode property
+get_prop(priv_app, adbd_tradeinmode_prop)
+
 # suppress denials for non-API accesses.
 dontaudit priv_app exec_type:file getattr;
 dontaudit priv_app device:dir read;
diff --git a/private/property.te b/private/property.te
index 64ddc3538..525754fe3 100644
--- a/private/property.te
+++ b/private/property.te
@@ -1,12 +1,16 @@
 # Properties used only in /system
 system_internal_prop(adbd_prop)
+system_internal_prop(adbd_tradeinmode_prop)
 system_internal_prop(apexd_payload_metadata_prop)
 system_internal_prop(ctl_snapuserd_prop)
+system_internal_prop(ctl_prefetch_prop)
+system_internal_prop(ctl_uprobestats_prop)
 system_internal_prop(crashrecovery_prop)
 system_internal_prop(debug_tracing_desktop_mode_visible_tasks_prop)
 system_internal_prop(device_config_core_experiments_team_internal_prop)
 system_internal_prop(device_config_lmkd_native_prop)
 system_internal_prop(device_config_mglru_native_prop)
+system_internal_prop(device_config_mmd_native_prop)
 system_internal_prop(device_config_profcollect_native_boot_prop)
 system_internal_prop(device_config_remote_key_provisioning_native_prop)
 system_internal_prop(device_config_statsd_native_prop)
@@ -32,6 +36,7 @@ system_internal_prop(last_boot_reason_prop)
 system_internal_prop(localization_prop)
 system_internal_prop(logd_auditrate_prop)
 system_internal_prop(lower_kptr_restrict_prop)
+system_internal_prop(mmd_prop)
 system_internal_prop(net_464xlat_fromvendor_prop)
 system_internal_prop(net_connectivity_prop)
 system_internal_prop(netd_stable_secret_prop)
@@ -40,9 +45,11 @@ system_internal_prop(odsign_prop)
 system_internal_prop(misctrl_prop)
 system_internal_prop(perf_drop_caches_prop)
 system_internal_prop(pm_prop)
+system_internal_prop(prefetch_service_prop)
 system_internal_prop(profcollectd_node_id_prop)
 system_internal_prop(radio_cdma_ecm_prop)
 system_internal_prop(remote_prov_prop)
+system_internal_prop(remote_prov_cert_prop)
 system_internal_prop(rollback_test_prop)
 system_internal_prop(setupwizard_prop)
 system_internal_prop(snapshotctl_prop)
@@ -69,6 +76,7 @@ system_internal_prop(hidl_memory_prop)
 system_internal_prop(suspend_debug_prop)
 system_internal_prop(system_service_enable_prop)
 system_internal_prop(ctl_artd_pre_reboot_prop)
+system_internal_prop(trusty_security_vm_sys_prop)
 
 
 # Properties which can't be written outside system
@@ -79,6 +87,8 @@ system_restricted_prop(log_file_logger_prop)
 system_restricted_prop(persist_sysui_builder_extras_prop)
 system_restricted_prop(persist_sysui_ranking_update_prop)
 system_restricted_prop(page_size_prop)
+system_restricted_prop(pm_16kb_app_compat_prop)
+
 
 # Properties with no restrictions
 until_board_api(202504, `
@@ -93,9 +103,15 @@ until_board_api(202504, `
     system_restricted_prop(profcollectd_etr_prop)
 ')
 
+# These types will be public starting at board api 202504
+until_board_api(202504, `
+    system_vendor_config_prop(trusty_security_vm_sys_vendor_prop)
+')
+
 # Properties which should only be written by vendor_init
 system_vendor_config_prop(avf_virtualizationservice_prop)
 system_vendor_config_prop(high_barometer_quality_prop)
+system_vendor_config_prop(prefetch_boot_prop)
 
 typeattribute log_prop log_property_type;
 typeattribute log_tag_prop log_property_type;
@@ -508,6 +524,7 @@ neverallow {
   -init
   -vendor_init
   -adbd
+  -adbd_tradeinmode
   -system_server
 } {
   adbd_config_prop
@@ -518,6 +535,7 @@ neverallow {
   domain
   -init
   -adbd
+  -adbd_tradeinmode
 } {
   adbd_prop
 }:property_service set;
@@ -783,6 +801,11 @@ neverallow {
   -rkpdapp
 } remote_prov_prop:property_service set;
 
+neverallow {
+  domain
+  -init
+} remote_prov_cert_prop:property_service set;
+
 neverallow {
   # Only allow init and shell to set rollback_test_prop
   domain
@@ -853,5 +876,13 @@ neverallow {
 neverallow {
   domain
   -init
+  -shell
   userdebug_or_eng(`-su')
 } bionic_linker_16kb_app_compat_prop:property_service set;
+
+neverallow {
+  domain
+  -init
+  -shell
+  userdebug_or_eng(`-su')
+} pm_16kb_app_compat_prop:property_service set;
diff --git a/private/property_contexts b/private/property_contexts
index 4f1d02d2c..b67fbffbd 100644
--- a/private/property_contexts
+++ b/private/property_contexts
@@ -51,6 +51,7 @@ persist.simpleperf.profile_app_expiration_time  u:object_r:shell_prop:s0
 security.lower_kptr_restrict u:object_r:lower_kptr_restrict_prop:s0
 service.adb.root        u:object_r:shell_prop:s0
 service.adb.tls.port    u:object_r:adbd_prop:s0
+persist.adb.tradeinmode u:object_r:adbd_tradeinmode_prop:s0
 persist.adb.wifi.       u:object_r:adbd_prop:s0
 persist.adb.tls_server.enable  u:object_r:system_adbd_prop:s0
 
@@ -202,6 +203,16 @@ ctl.start$snapuserd     u:object_r:ctl_snapuserd_prop:s0
 ctl.stop$snapuserd      u:object_r:ctl_snapuserd_prop:s0
 ctl.restart$snapuserd   u:object_r:ctl_snapuserd_prop:s0
 
+# Restrict access to control prefetch
+ctl.start$prefetch     u:object_r:ctl_prefetch_prop:s0
+ctl.stop$prefetch      u:object_r:ctl_prefetch_prop:s0
+ctl.restart$prefetch   u:object_r:ctl_prefetch_prop:s0
+
+# Restrict access to control uprobestats
+ctl.start$uprobestats     u:object_r:ctl_uprobestats_prop:s0
+ctl.stop$uprobestats      u:object_r:ctl_uprobestats_prop:s0
+ctl.restart$uprobestats   u:object_r:ctl_uprobestats_prop:s0
+
 # Restrict access to starting/stopping artd_pre_reboot.
 ctl.start$artd_pre_reboot          u:object_r:ctl_artd_pre_reboot_prop:s0
 ctl.stop$artd_pre_reboot           u:object_r:ctl_artd_pre_reboot_prop:s0
@@ -294,6 +305,7 @@ persist.device_config.window_manager_native_boot.   u:object_r:device_config_win
 persist.device_config.memory_safety_native_boot.    u:object_r:device_config_memory_safety_native_boot_prop:s0
 persist.device_config.memory_safety_native.         u:object_r:device_config_memory_safety_native_prop:s0
 persist.device_config.tethering_u_or_later_native.  u:object_r:device_config_tethering_u_or_later_native_prop:s0
+persist.device_config.mmd_native.                   u:object_r:device_config_mmd_native_prop:s0
 
 # Prop indicates the apex that bundles input configuration files (*.idc,*.kl,*.kcm)
 input_device.config_file.apex    u:object_r:input_device_config_prop:s0 exact string
@@ -349,6 +361,17 @@ sys.boot_from_charger_mode  u:object_r:charger_status_prop:s0 exact int
 ro.enable_boot_charger_mode u:object_r:charger_config_prop:s0 exact bool
 ro.product.charger.unplugged_shutdown_time  u:object_r:charger_config_prop:s0 exact int
 
+# Prefetch boot properties which are tunables
+ro.prefetch_boot.enabled u:object_r:prefetch_boot_prop:s0 exact bool
+ro.prefetch_boot.trace_buffer_size_kib u:object_r:prefetch_boot_prop:s0 exact int
+ro.prefetch_boot.duration_s u:object_r:prefetch_boot_prop:s0 exact int
+ro.prefetch_boot.io_depth u:object_r:prefetch_boot_prop:s0 exact int
+ro.prefetch_boot.max_fds u:object_r:prefetch_boot_prop:s0 exact int
+ro.prefetch_boot.record_stop u:object_r:prefetch_boot_prop:s0 exact bool
+# Prefetch property to start and stop the record/replay
+prefetch_boot.record u:object_r:prefetch_service_prop:s0 exact bool
+prefetch_boot.replay u:object_r:prefetch_service_prop:s0 exact bool
+
 # Virtual A/B and snapuserd properties
 ro.virtual_ab.enabled   u:object_r:virtual_ab_prop:s0 exact bool
 ro.virtual_ab.retrofit  u:object_r:virtual_ab_prop:s0 exact bool
@@ -447,6 +470,10 @@ ro.audio.headtracking_enabled u:object_r:audio_config_prop:s0 exact bool
 # to enable spatialization for stereo channel mask
 ro.audio.stereo_spatialization_enabled u:object_r:audio_config_prop:s0 exact bool
 
+# Boolean property used in AudioPolicyInterfaceImpl to configure whether
+# to disable usecase validator for game mode
+ro.audio.usecase_validator_enabled u:object_r:audio_config_prop:s0 exact bool
+
 # Boolean property used in UsbAlsaManager to decide if only one or multiple
 # USB devices can be connected to audio system at a certain time
 ro.audio.multi_usb_mode u:object_r:audio_config_prop:s0 exact bool
@@ -568,6 +595,7 @@ keyguard.no_require_sim u:object_r:keyguard_config_prop:s0 exact bool
 
 media.c2.dmabuf.padding                      u:object_r:codec2_config_prop:s0 exact int
 media.c2.hal.selection                       u:object_r:codec2_config_prop:s0 exact enum aidl hidl
+media.c2.remove_rendering_depth              u:object_r:codec2_config_prop:s0 exact bool
 
 media.recorder.show_manufacturer_and_model   u:object_r:media_config_prop:s0 exact bool
 media.resolution.limit.32bit                 u:object_r:media_config_prop:s0 exact int
@@ -597,12 +625,19 @@ persist.bluetooth.snooplogfilter.profiles.rfcomm.enabled    u:object_r:bluetooth
 persist.bluetooth.factoryreset                              u:object_r:bluetooth_prop:s0 exact bool
 persist.bluetooth.leaudio.allow_list                        u:object_r:bluetooth_prop:s0 exact string
 
+bluetooth.a2dp.source.sbc_priority.config            u:object_r:bluetooth_config_prop:s0 exact int
+bluetooth.a2dp.source.aac_priority.config            u:object_r:bluetooth_config_prop:s0 exact int
+bluetooth.a2dp.source.aptx_priority.config           u:object_r:bluetooth_config_prop:s0 exact int
+bluetooth.a2dp.source.aptx_hd_priority.config        u:object_r:bluetooth_config_prop:s0 exact int
+bluetooth.a2dp.source.ldac_priority.config           u:object_r:bluetooth_config_prop:s0 exact int
+
 bluetooth.hardware.power.operating_voltage_mv        u:object_r:bluetooth_config_prop:s0 exact int
 bluetooth.hardware.power.idle_cur_ma                 u:object_r:bluetooth_config_prop:s0 exact int
 bluetooth.hardware.power.tx_cur_ma                   u:object_r:bluetooth_config_prop:s0 exact int
 bluetooth.hardware.power.rx_cur_ma                   u:object_r:bluetooth_config_prop:s0 exact int
 bluetooth.hardware.radio.le_tx_path_loss_comp_db     u:object_r:bluetooth_config_prop:s0 exact int
 bluetooth.hardware.radio.le_rx_path_loss_comp_db     u:object_r:bluetooth_config_prop:s0 exact int
+bluetooth.hardware.wakeup_supported                  u:object_r:bluetooth_config_prop:s0 exact bool
 
 bluetooth.framework.support_persisted_state          u:object_r:bluetooth_config_prop:s0 exact bool
 bluetooth.framework.adapter_address_validation       u:object_r:bluetooth_config_prop:s0 exact bool
@@ -727,6 +762,8 @@ pm.dexopt.downgrade_after_inactive_days                 u:object_r:exported_pm_p
 
 pm.dexopt.                                              u:object_r:future_pm_prop:s0 prefix
 
+pm.16kb.app_compat.disabled                             u:object_r:pm_16kb_app_compat_prop:s0 exact bool
+
 ro.apk_verity.mode u:object_r:apk_verity_prop:s0 exact int
 
 ro.bluetooth.a2dp_offload.supported u:object_r:bluetooth_a2dp_offload_prop:s0 exact bool
@@ -775,6 +812,7 @@ avf.remote_attestation.enabled u:object_r:avf_virtualizationservice_prop:s0 exac
 
 hypervisor.pvmfw.path                              u:object_r:hypervisor_pvmfw_prop:s0 exact string
 hypervisor.virtualizationmanager.debug_policy.path u:object_r:hypervisor_virtualizationmanager_prop:s0 exact string
+hypervisor.virtualizationmanager.dump_device_tree u:object_r:hypervisor_virtualizationmanager_prop:s0 exact bool
 
 # hypervisor.*: configured by the vendor to advertise capabilities of their
 # hypervisor to virtualizationservice.
@@ -987,6 +1025,7 @@ ro.boot.qemu               u:object_r:bootloader_prop:s0 exact bool
 ro.boot.revision           u:object_r:bootloader_prop:s0 exact string
 ro.boot.serialconsole      u:object_r:bootloader_prop:s0 exact bool
 ro.boot.vbmeta.avb_version u:object_r:bootloader_prop:s0 exact string
+ro.boot.vbmeta.public_key_digest  u:object_r:bootloader_prop:s0 exact string
 ro.boot.verifiedbootstate  u:object_r:bootloader_prop:s0 exact string
 ro.boot.veritymode         u:object_r:bootloader_prop:s0 exact string
 # Properties specific to virtualized deployments of Android
@@ -1008,6 +1047,7 @@ ro.boottime.init.mount.data u:object_r:boottime_public_prop:s0 exact string
 ro.boottime.init.fsck.data  u:object_r:boottime_public_prop:s0 exact string
 ro.fstype.data  u:object_r:fstype_prop:s0 exact string
 
+ro.build.backported_fixes.alias_bitset.long_list u:object_r:build_prop:s0 exact string
 ro.build.characteristics                  u:object_r:build_prop:s0 exact string
 ro.build.date                             u:object_r:build_prop:s0 exact string
 ro.build.date.utc                         u:object_r:build_prop:s0 exact int
@@ -1286,6 +1326,13 @@ ro.boot.product.hardware.sku u:object_r:exported_default_prop:s0 exact string
 ro.boot.product.vendor.sku   u:object_r:exported_default_prop:s0 exact string
 ro.boot.slot_suffix          u:object_r:exported_default_prop:s0 exact string
 
+# Vendor configurable property to be used specifically to assign industrial
+# design ID or vendor hardware identifier that encodes on device components.
+# This property should not be assigned a generic device name or identifier and
+# should not be redundant to properties like ro.boot.hardware. ro.product.name
+# etc.
+ro.boot.product.hardware.id  u:object_r:exported_default_prop:s0 exact string
+
 ro.boringcrypto.hwrand u:object_r:exported_default_prop:s0 exact bool
 
 # Update related props
@@ -1539,6 +1586,9 @@ remote_provisioning.tee.rkp_only u:object_r:remote_prov_prop:s0 exact bool
 # Hostname for the remote provisioning server a device should communicate with
 remote_provisioning.hostname u:object_r:remote_prov_prop:s0 exact string
 
+# Support for post-processing RKP certificates
+remote_provisioning.use_cert_processor u:object_r:remote_prov_cert_prop:s0 exact bool
+
 # Connection Timeout for remote provisioning step
 remote_provisioning.connect_timeout_millis u:object_r:remote_prov_prop:s0 exact int
 
@@ -1726,3 +1776,15 @@ sys.snapshotctl.unmap u:object_r:snapshotctl_prop:s0 exact string
 # Properties for enabling/disabling system services
 ro.system_settings.service.odp_enabled   u:object_r:system_service_enable_prop:s0 exact bool
 ro.system_settings.service.backgound_install_control_enabled   u:object_r:system_service_enable_prop:s0 exact bool
+
+# Properties related to Trusty VMs
+trusty.security_vm.nonsecure_vm_ready u:object_r:trusty_security_vm_sys_prop:s0 exact bool
+trusty.security_vm.vm_cid u:object_r:trusty_security_vm_sys_prop:s0 exact int
+
+# Properties that allows vendors to enable Trusty security VM features
+trusty.security_vm.enabled u:object_r:trusty_security_vm_sys_vendor_prop:s0 exact bool
+trusty.security_vm.keymint.enabled u:object_r:trusty_security_vm_sys_vendor_prop:s0 exact bool
+
+# Properties for mmd
+mmd. u:object_r:mmd_prop:s0
+mmd.enabled_aconfig u:object_r:mmd_prop:s0 exact bool
diff --git a/private/rkp_cert_processor.te b/private/rkp_cert_processor.te
new file mode 100644
index 000000000..e5c9d0748
--- /dev/null
+++ b/private/rkp_cert_processor.te
@@ -0,0 +1,15 @@
+# Cert processor service
+type rkp_cert_processor, domain, coredomain;
+type rkp_cert_processor_exec, system_file_type, exec_type, file_type;
+
+init_daemon_domain(rkp_cert_processor)
+net_domain(rkp_cert_processor)
+
+binder_use(rkp_cert_processor)
+binder_call(rkp_cert_processor, system_server)
+
+add_service(rkp_cert_processor, rkp_cert_processor_service)
+
+use_bootstrap_libs(rkp_cert_processor)
+
+allow rkp_cert_processor package_native_service:service_manager find;
diff --git a/private/sdk_sandbox_all.te b/private/sdk_sandbox_all.te
index b4c655b8f..41b2799fb 100644
--- a/private/sdk_sandbox_all.te
+++ b/private/sdk_sandbox_all.te
@@ -124,3 +124,25 @@ neverallow sdk_sandbox_all sdk_sandbox_system_data_file:dir ~{ getattr search };
 # Only dirs should be created at sdk_sandbox_all_system_data_file level
 neverallow { domain -init } sdk_sandbox_system_data_file:file *;
 
+# Restrict unix stream sockets for IPC.
+neverallow sdk_sandbox_all {
+    domain
+    -sdk_sandbox_all
+    -netd
+    -logd
+    -adbd
+    userdebug_or_eng(`-su')
+    # needed for profiling
+    -traced
+    -traced_perf
+    -heapprofd
+    # fallback crash handling for processes that can't exec crash_dump.
+    -tombstoned
+    # needed to connect to PRNG seeder daemon.
+    -prng_seeder
+}:unix_stream_socket connectto;
+neverallow {
+    domain
+    -adbd
+    -sdk_sandbox_all
+} sdk_sandbox_all:unix_stream_socket connectto;
diff --git a/private/seapp_contexts b/private/seapp_contexts
index 0b857dede..25ed1ba2a 100644
--- a/private/seapp_contexts
+++ b/private/seapp_contexts
@@ -224,6 +224,3 @@ user=_app fromRunAs=true domain=runas_app levelFrom=user
 user=_app isPrivApp=true name=com.android.virtualization.vmlauncher domain=vmlauncher_app type=privapp_data_file levelFrom=all
 user=_app isPrivApp=true name=com.google.android.virtualization.vmlauncher domain=vmlauncher_app type=privapp_data_file levelFrom=all
 user=_app isPrivApp=true name=com.android.virtualization.terminal domain=vmlauncher_app type=privapp_data_file levelFrom=all
-user=_app isPrivApp=true name=com.google.android.virtualization.terminal domain=vmlauncher_app type=privapp_data_file levelFrom=all
-user=_app isPrivApp=true name=com.android.virtualization.linuxinstaller domain=ferrochrome_app type=privapp_data_file levelFrom=all
-user=_app isPrivApp=true name=com.android.virtualization.ferrochrome domain=ferrochrome_app type=privapp_data_file levelFrom=all
diff --git a/private/security_classes b/private/security_classes
index 1d13d9fa0..053721449 100644
--- a/private/security_classes
+++ b/private/security_classes
@@ -172,3 +172,6 @@ class diced                     # userspace
 
 class drmservice                # userspace
 # FLASK
+
+# Permissions for VMs to access SMC services
+class tee_service            		# userspace
diff --git a/private/service.te b/private/service.te
index a4d00f36e..7e893009c 100644
--- a/private/service.te
+++ b/private/service.te
@@ -1,5 +1,5 @@
-type adaptive_auth_service,          system_server_service, service_manager_type;
 type ambient_context_service,        app_api_service, system_server_service, service_manager_type;
+type authentication_policy_service,  system_api_service, system_server_service, service_manager_type;
 
 # These types will be public starting at board api 202504
 until_board_api(202504, `
@@ -11,27 +11,38 @@ type compos_service,                 service_manager_type;
 type communal_service,               app_api_service, system_server_service, service_manager_type;
 type dynamic_system_service,         system_api_service, system_server_service, service_manager_type;
 type feature_flags_service,          app_api_service, system_server_service, service_manager_type;
+type fwk_devicestate_service, system_server_service, service_manager_type;
 type gsi_service,                    service_manager_type;
 type incidentcompanion_service,      app_api_service, system_api_service, system_server_service, service_manager_type;
 type logcat_service,                 system_server_service, service_manager_type;
 type logd_service,                   service_manager_type;
 type mediatuner_service,             app_api_service, service_manager_type;
+type mmd_service,                    service_manager_type;
 type on_device_intelligence_service, app_api_service, system_server_service, service_manager_type, isolated_compute_allowed_service;
 type profcollectd_service,           service_manager_type;
 type protolog_configuration_service, app_api_service, system_api_service, system_server_service, service_manager_type;
 type resolver_service,               system_server_service, service_manager_type;
 type rkpd_registrar_service,         service_manager_type;
 type rkpd_refresh_service,           service_manager_type;
+type rkp_cert_processor_service,     service_manager_type;
 type safety_center_service,          app_api_service, system_api_service, system_server_service, service_manager_type;
 type stats_service,                  service_manager_type;
 type statsbootstrap_service,         system_server_service, service_manager_type;
 type statscompanion_service,         system_server_service, service_manager_type;
 type statsmanager_service,           system_api_service, system_server_service, service_manager_type;
+until_board_api(202504, `
+    type media_quality_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
+')
+
+until_board_api(202504, `
+    type hal_mediaquality_service, protected_service, hal_service_type, service_manager_type;
+')
 
 is_flag_enabled(RELEASE_SUPERVISION_SERVICE, `
     type supervision_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 ')
 type tracingproxy_service,          system_server_service, service_manager_type;
+type tradeinmode_service,           system_server_service, service_manager_type;
 type transparency_service,          system_server_service, service_manager_type;
 
 is_flag_enabled(RELEASE_AVF_ENABLE_DEVICE_ASSIGNMENT, `
@@ -48,8 +59,9 @@ is_flag_enabled(RELEASE_AVF_ENABLE_MICROFUCHSIA, `
     type microfuchsia_service,          service_manager_type;
 ')
 
-type uce_service,                   service_manager_type;
-type wearable_sensing_service,      app_api_service, system_server_service, service_manager_type;
+type uce_service,                      service_manager_type;
+type wearable_sensing_service,         app_api_service, system_server_service, service_manager_type;
+type wifi_mainline_supplicant_service, service_manager_type;
 
 ###
 ### Neverallow rules
diff --git a/private/service_contexts b/private/service_contexts
index aec4213df..1478e93ad 100644
--- a/private/service_contexts
+++ b/private/service_contexts
@@ -3,6 +3,7 @@ android.frameworks.location.altitude.IAltitudeService/default        u:object_r:
 android.frameworks.stats.IStats/default                              u:object_r:fwk_stats_service:s0
 android.frameworks.sensorservice.ISensorManager/default              u:object_r:fwk_sensor_service:s0
 android.frameworks.vibrator.IVibratorControlService/default          u:object_r:fwk_vibrator_control_service:s0
+android.frameworks.devicestate.IDeviceStateService/default           u:object_r:fwk_devicestate_service:s0
 android.hardware.audio.core.IConfig/default                          u:object_r:hal_audio_service:s0
 # 'default' IModule is equivalent to 'primary' in HIDL
 android.hardware.audio.core.IModule/default                          u:object_r:hal_audio_service:s0
@@ -37,6 +38,7 @@ is_flag_enabled(RELEASE_HARDWARE_BLUETOOTH_RANGING_SERVICE, `
 ')
 android.hardware.bluetooth.lmp_event.IBluetoothLmpEvent/default      u:object_r:hal_bluetooth_service:s0
 android.hardware.bluetooth.audio.IBluetoothAudioProviderFactory/default u:object_r:hal_audio_service:s0
+android.hardware.bluetooth.socket.IBluetoothSocket/default           u:object_r:hal_bluetooth_service:s0
 android.hardware.broadcastradio.IBroadcastRadio/amfm                 u:object_r:hal_broadcastradio_service:s0
 android.hardware.broadcastradio.IBroadcastRadio/dab                  u:object_r:hal_broadcastradio_service:s0
 # The instance here is internal/0 following naming convention for ICameraProvider.
@@ -115,6 +117,7 @@ android.hardware.threadnetwork.IThreadChip/chip0                     u:object_r:
 android.hardware.tv.hdmi.cec.IHdmiCec/default                        u:object_r:hal_tv_hdmi_cec_service:s0
 android.hardware.tv.hdmi.connection.IHdmiConnection/default          u:object_r:hal_tv_hdmi_connection_service:s0
 android.hardware.tv.hdmi.earc.IEArc/default                          u:object_r:hal_tv_hdmi_earc_service:s0
+android.hardware.tv.mediaquality.IMediaQuality/default               u:object_r:hal_mediaquality_service:s0
 android.hardware.tv.tuner.ITuner/default                             u:object_r:hal_tv_tuner_service:s0
 android.hardware.tv.input.ITvInput/default                           u:object_r:hal_tv_input_service:s0
 android.hardware.usb.IUsb/default                                    u:object_r:hal_usb_service:s0
@@ -143,9 +146,11 @@ accessibility                             u:object_r:accessibility_service:s0
 account                                   u:object_r:account_service:s0
 activity                                  u:object_r:activity_service:s0
 activity_task                             u:object_r:activity_task_service:s0
-adaptive_auth                             u:object_r:adaptive_auth_service:s0
 adb                                       u:object_r:adb_service:s0
 adservices_manager                        u:object_r:adservices_manager_service:s0
+starting_at_board_api(202504, `
+    advanced_protection                       u:object_r:advanced_protection_service:s0
+')
 aidl_lazy_test_1                          u:object_r:aidl_lazy_test_service:s0
 aidl_lazy_test_2                          u:object_r:aidl_lazy_test_service:s0
 aidl_lazy_test_quit                       u:object_r:aidl_lazy_test_service:s0
@@ -183,6 +188,9 @@ ambient_context                           u:object_r:ambient_context_service:s0
 app_binding                               u:object_r:app_binding_service:s0
 app_function                              u:object_r:app_function_service:s0
 app_hibernation                           u:object_r:app_hibernation_service:s0
+starting_at_board_api(202504, `
+    dynamic_instrumentation               u:object_r:dynamic_instrumentation_service:s0
+')
 app_integrity                             u:object_r:app_integrity_service:s0
 app_prediction                            u:object_r:app_prediction_service:s0
 app_search                                u:object_r:app_search_service:s0
@@ -199,6 +207,7 @@ assetatlas                                u:object_r:assetatlas_service:s0
 attention                                 u:object_r:attention_service:s0
 audio                                     u:object_r:audio_service:s0
 auth                                      u:object_r:auth_service:s0
+authentication_policy                     u:object_r:authentication_policy_service:s0
 autofill                                  u:object_r:autofill_service:s0
 background_install_control                u:object_r:bg_install_control_service:s0
 backup                                    u:object_r:backup_service:s0
@@ -271,6 +280,9 @@ feature_flags                             u:object_r:feature_flags_service:s0
 file_integrity                            u:object_r:file_integrity_service:s0
 fingerprint                               u:object_r:fingerprint_service:s0
 font                                      u:object_r:font_service:s0
+starting_at_board_api(202504, `
+    forensic                                  u:object_r:forensic_service:s0
+')
 android.hardware.fingerprint.IFingerprintDaemon u:object_r:fingerprintd_service:s0
 game                                      u:object_r:game_service:s0
 gfxinfo                                   u:object_r:gfxinfo_service:s0
@@ -290,6 +302,9 @@ inputflinger                              u:object_r:inputflinger_service:s0
 input_method                              u:object_r:input_method_service:s0
 input                                     u:object_r:input_service:s0
 installd                                  u:object_r:installd_service:s0
+starting_at_board_api(202504, `
+    intrusion_detection                   u:object_r:intrusion_detection_service:s0
+')
 iphonesubinfo_msim                        u:object_r:radio_service:s0
 iphonesubinfo2                            u:object_r:radio_service:s0
 iphonesubinfo                             u:object_r:radio_service:s0
@@ -334,12 +349,14 @@ media.tuner                               u:object_r:mediatuner_service:s0
 media_communication                       u:object_r:media_communication_service:s0
 media_metrics                             u:object_r:media_metrics_service:s0
 media_projection                          u:object_r:media_projection_service:s0
+media_quality                             u:object_r:media_quality_service:s0
 media_resource_monitor                    u:object_r:media_session_service:s0
 media_router                              u:object_r:media_router_service:s0
 media_session                             u:object_r:media_session_service:s0
 meminfo                                   u:object_r:meminfo_service:s0
 memtrack.proxy                            u:object_r:memtrackproxy_service:s0
 midi                                      u:object_r:midi_service:s0
+mmd                                       u:object_r:mmd_service:s0
 mount                                     u:object_r:mount_service:s0
 music_recognition                         u:object_r:music_recognition_service:s0
 nearby                                    u:object_r:nearby_service:s0
@@ -396,6 +413,7 @@ resources                                 u:object_r:resources_manager_service:s
 restrictions                              u:object_r:restrictions_service:s0
 rkpd.registrar                            u:object_r:rkpd_registrar_service:s0
 rkpd.refresh                              u:object_r:rkpd_refresh_service:s0
+rkp_cert_processor.service                u:object_r:rkp_cert_processor_service:s0
 role                                      u:object_r:role_service:s0
 rollback                                  u:object_r:rollback_service:s0
 rttmanager                                u:object_r:rttmanager_service:s0
@@ -462,6 +480,7 @@ time_zone_detector                        u:object_r:timezonedetector_service:s0
 thermalservice                            u:object_r:thermal_service:s0
 thread_network                            u:object_r:threadnetwork_service:s0
 tracing.proxy                             u:object_r:tracingproxy_service:s0
+tradeinmode                               u:object_r:tradeinmode_service:s0
 translation                               u:object_r:translation_service:s0
 transparency                              u:object_r:transparency_service:s0
 trust                                     u:object_r:trust_service:s0
@@ -498,5 +517,9 @@ wifi                                      u:object_r:wifi_service:s0
 wifinl80211                               u:object_r:wifinl80211_service:s0
 wifiaware                                 u:object_r:wifiaware_service:s0
 wifirtt                                   u:object_r:rttmanager_service:s0
+starting_at_board_api(202504, `
+   wifi_usd                                  u:object_r:wifi_usd_service:s0
+')
+wifi_mainline_supplicant                  u:object_r:wifi_mainline_supplicant_service:s0
 window                                    u:object_r:window_service:s0
 *                                         u:object_r:default_android_service:s0
diff --git a/private/shell.te b/private/shell.te
index 18e346226..890d6f4bb 100644
--- a/private/shell.te
+++ b/private/shell.te
@@ -42,6 +42,9 @@ perfetto_producer(shell)
 
 domain_auto_trans(shell, vendor_shell_exec, vendor_shell)
 
+# Allow shell to execute tradeinmode for testing.
+domain_auto_trans(shell, tradeinmode_exec, tradeinmode)
+
 # Allow shell binaries to exec the perfetto cmdline util and have that
 # transition into its own domain, so that it behaves consistently to
 # when exec()-d by statsd.
@@ -108,6 +111,12 @@ set_prop(shell, rollback_test_prop)
 # Allow shell to set RKP properties for testing purposes
 set_prop(shell, remote_prov_prop)
 
+# Allow shell to enable 16 KB backcompat globally.
+set_prop(shell, bionic_linker_16kb_app_compat_prop)
+
+# Allow shell to disable compat in package manager
+set_prop(shell, pm_16kb_app_compat_prop)
+
 # Allow shell to get encryption policy of /data/local/tmp/, for CTS
 allowxperm shell shell_data_file:dir ioctl {
   FS_IOC_GET_ENCRYPTION_POLICY
@@ -177,6 +186,8 @@ set_prop(shell, traced_perf_enabled_prop)
 # Allow shell to start/stop gsid via ctl.start|stop|restart gsid.
 set_prop(shell, ctl_gsid_prop)
 set_prop(shell, ctl_snapuserd_prop)
+# Allow shell to start/stop prefetch
+set_prop(shell, ctl_prefetch_prop)
 # Allow shell to enable Dynamic System Update
 set_prop(shell, dynamic_system_prop)
 # Allow shell to mock an OTA using persist.pm.mock-upgrade
@@ -273,12 +284,6 @@ get_prop(shell, build_attestation_prop)
 # TODO (b/350628688): Remove this once it's safe to do so.
 allow shell oatdump_exec:file rx_file_perms;
 
-# Allow shell access to socket for test
-userdebug_or_eng(`
-    allow shell aconfigd_socket:sock_file write;
-    allow shell aconfigd:unix_stream_socket connectto;
-')
-
 # Create and use network sockets.
 net_domain(shell)
 
@@ -403,7 +408,6 @@ allow shell sysfs_net:dir r_dir_perms;
 
 r_dir_file(shell, cgroup)
 allow shell cgroup_desc_file:file r_file_perms;
-allow shell cgroup_desc_api_file:file r_file_perms;
 allow shell vendor_cgroup_desc_file:file r_file_perms;
 r_dir_file(shell, cgroup_v2)
 allow shell domain:dir { search open read getattr };
@@ -479,9 +483,12 @@ allow shell sepolicy_file:file r_file_perms;
 allow shell vendor_shell_exec:file rx_file_perms;
 
 is_flag_enabled(RELEASE_AVF_SUPPORT_CUSTOM_VM_WITH_PARAVIRTUALIZED_DEVICES, `
-  allow shell custom_vm_setup_exec:file { entrypoint r_file_perms };
+  allow shell linux_vm_setup_exec:file { entrypoint r_file_perms };
 ')
 
+allow shell tee_service_contexts_file:file r_file_perms;
+allow shell test_pkvm_tee_service:tee_service use;
+
 # Everything is labeled as rootfs in recovery mode. Allow shell to
 # execute them.
 recovery_only(`
diff --git a/private/statsd.te b/private/statsd.te
index b932bc61d..3db5c6061 100644
--- a/private/statsd.te
+++ b/private/statsd.te
@@ -41,6 +41,12 @@ allow statsd uprobestats_configs_data_file:file create_file_perms;
 
 # Allow statsd to trigger uprobestats via property.
 set_prop(statsd, uprobestats_start_with_config_prop);
+
+# Allow statsd to use io_uring
+io_uring_use(statsd)
+
+# Allow statsd to start the uprobestats service.
+set_prop(statsd, ctl_uprobestats_prop)
 binder_use(statsd)
 
 # Allow statsd to scan through /proc/pid for all processes.
diff --git a/private/su.te b/private/su.te
index 2d4b0c64c..1e2adef0d 100644
--- a/private/su.te
+++ b/private/su.te
@@ -106,6 +106,7 @@ userdebug_or_eng(`
   typeattribute su hal_ir_client;
   typeattribute su hal_keymaster_client;
   typeattribute su hal_light_client;
+  typeattribute su hal_mediaquality_client;
   typeattribute su hal_memtrack_client;
   typeattribute su hal_neuralnetworks_client;
   typeattribute su hal_nfc_client;
diff --git a/private/surfaceflinger.te b/private/surfaceflinger.te
index f6f1d9b97..1e0e1ef9c 100644
--- a/private/surfaceflinger.te
+++ b/private/surfaceflinger.te
@@ -85,9 +85,14 @@ perfetto_producer(surfaceflinger)
 # Use socket supplied by adbd, for cmd gpu vkjson etc.
 allow surfaceflinger adbd:unix_stream_socket { read write getattr };
 
-# Allow reading and writing to sockets used for BLAST buffer releases
+# Allow reading and writing to sockets used for BLAST buffer releases.
+# SurfaceFlinger never reads from these sockets but needs read permissions in order to receive
+# the file descriptors over binder. There's no mechanism to mark a socket as write-only.
+# shutdown is used to close the read-end of the sockets that are sent to SurfaceFlinger. See
+# b/353597444
 allow surfaceflinger { appdomain -isolated_app_all -ephemeral_app -sdk_sandbox_all }:unix_stream_socket { read write };
 allow surfaceflinger bootanim:unix_stream_socket { read write };
+allow surfaceflinger automotive_display_service:unix_stream_socket { read write };
 
 # Allow a dumpstate triggered screenshot
 binder_call(surfaceflinger, dumpstate)
@@ -135,6 +140,8 @@ allow surfaceflinger stats_service:service_manager find;
 allow surfaceflinger statsmanager_service:service_manager find;
 # TODO(146461633): remove this once native pullers talk to StatsManagerService
 binder_call(surfaceflinger, statsd);
+# Allow pushing atoms to the stats bootstrap atom service
+allow surfaceflinger statsbootstrap_service:service_manager find;
 
 # Allow to use files supplied by hal_evs
 allow surfaceflinger hal_evs:fd use;
@@ -142,10 +149,6 @@ allow surfaceflinger hal_evs:fd use;
 # Allow to use release fence fds supplied by hal_camera
 allow surfaceflinger hal_camera:fd use;
 
-# Allow pushing jank event atoms to statsd
-userdebug_or_eng(`
-    unix_socket_send(surfaceflinger, statsdw, statsd)
-')
 
 # Surfaceflinger should not be reading default vendor-defined properties.
 dontaudit surfaceflinger vendor_default_prop:file read;
diff --git a/private/system_app.te b/private/system_app.te
index 0b6ffe264..93be46f0a 100644
--- a/private/system_app.te
+++ b/private/system_app.te
@@ -199,3 +199,7 @@ neverallow { domain -init -system_app } drm_forcel3_prop:property_service set;
 
 allow system_app vendor_boot_ota_file:dir { r_dir_perms };
 allow system_app vendor_boot_ota_file:file { r_file_perms };
+
+# allow system_app to read system_dlkm_file for /system_dlkm/etc/NOTICE.xml.gz
+allow system_app system_dlkm_file:dir search;
+allow system_app system_dlkm_file:file { getattr open read };
diff --git a/private/system_server.te b/private/system_server.te
index fc4faefa5..01097f2b1 100644
--- a/private/system_server.te
+++ b/private/system_server.te
@@ -198,6 +198,8 @@ allow system_server cameraserver:process { getsched setsched };
 allow system_server hal_camera:process { getsched setsched };
 allow system_server mediaserver:process { getsched setsched };
 allow system_server bootanim:process { getsched setsched };
+# Set scheduling info for VMs (b/375058190)
+allow system_server { virtualizationmanager crosvm }:process { getsched setsched };
 
 # Set scheduling info for psi monitor thread.
 # TODO: delete this line b/131761776
@@ -291,6 +293,7 @@ binder_call(system_server, gpuservice)
 binder_call(system_server, idmap)
 binder_call(system_server, installd)
 binder_call(system_server, incidentd)
+binder_call(system_server, mmd)
 binder_call(system_server, netd)
 binder_call(system_server, ot_daemon)
 userdebug_or_eng(`binder_call(system_server, profcollectd)')
@@ -302,6 +305,7 @@ binder_call(system_server, vold)
 binder_call(system_server, logd)
 binder_call(system_server, wificond)
 binder_call(system_server, uprobestats)
+binder_call(system_server, wifi_mainline_supplicant)
 binder_service(system_server)
 
 # Use HALs
@@ -324,6 +328,7 @@ hal_client_domain(system_server, hal_input_processor)
 hal_client_domain(system_server, hal_ir)
 hal_client_domain(system_server, hal_keymint)
 hal_client_domain(system_server, hal_light)
+hal_client_domain(system_server, hal_mediaquality)
 hal_client_domain(system_server, hal_memtrack)
 hal_client_domain(system_server, hal_neuralnetworks)
 hal_client_domain(system_server, hal_oemlock)
@@ -389,6 +394,7 @@ allow system_server {
   mediaswcodec
   mediatranscoding
   mediatuner
+  mmd
   netd
   sdcardd
   servicemanager
@@ -810,12 +816,16 @@ set_prop(system_server, device_config_memory_safety_native_boot_prop)
 set_prop(system_server, device_config_memory_safety_native_prop)
 set_prop(system_server, device_config_remote_key_provisioning_native_prop)
 set_prop(system_server, device_config_tethering_u_or_later_native_prop)
+set_prop(system_server, device_config_mmd_native_prop)
 set_prop(system_server, smart_idle_maint_enabled_prop)
 set_prop(system_server, arm64_memtag_prop)
 
 # staged flag properties
 set_prop(system_server, next_boot_prop)
 
+# Allow system server to read pm.16kb.app_compat.disabled
+get_prop(system_server, pm_16kb_app_compat_prop)
+
 # Allow query ART device config properties
 get_prop(system_server, device_config_runtime_native_boot_prop)
 get_prop(system_server, device_config_runtime_native_prop)
@@ -1002,6 +1012,7 @@ allow system_server mediametrics_service:service_manager find;
 allow system_server mediaextractor_service:service_manager find;
 allow system_server mediadrmserver_service:service_manager find;
 allow system_server mediatuner_service:service_manager find;
+allow system_server mmd_service:service_manager find;
 allow system_server netd_service:service_manager find;
 allow system_server nfc_service:service_manager find;
 allow system_server ot_daemon_service:service_manager find;
@@ -1020,6 +1031,7 @@ allow system_server logd_service:service_manager find;
 userdebug_or_eng(`
   allow system_server profcollectd_service:service_manager find;
 ')
+allow system_server wifi_mainline_supplicant_service:service_manager find;
 
 add_service(system_server, batteryproperties_service)
 
@@ -1134,9 +1146,9 @@ allow system_server configfs:file { getattr open create unlink write };
 
 # Connect to adbd and use a socket transferred from it.
 # Used for e.g. jdwp.
-allow system_server adbd:unix_stream_socket connectto;
-allow system_server adbd:fd use;
-allow system_server adbd:unix_stream_socket { getattr getopt ioctl read write shutdown };
+allow system_server adbd_common:unix_stream_socket connectto;
+allow system_server adbd_common:fd use;
+allow system_server adbd_common:unix_stream_socket { getattr getopt ioctl read write shutdown };
 
 # Read service.adb.tls.port, persist.adb.wifi. properties
 get_prop(system_server, adbd_prop)
@@ -1144,6 +1156,9 @@ get_prop(system_server, adbd_prop)
 # Set persist.adb.tls_server.enable property
 set_prop(system_server, system_adbd_prop)
 
+# Set service.adbd.tradeinmode from ITradeInService.
+set_prop(system_server, adbd_tradeinmode_prop)
+
 # Allow invoking tools like "timeout"
 allow system_server toolbox_exec:file rx_file_perms;
 
@@ -1270,8 +1285,10 @@ get_prop(system_server,system_jvmti_agent_prop)
 allow system_server functionfs:dir search;
 allow system_server functionfs:file rw_file_perms;
 # To resolve arbitrary sysfs paths from /sys/class/udc/* symlinks.
+starting_at_board_api(202504, `
 allow system_server sysfs_type:dir search;
 r_dir_file(system_server, sysfs_udc)
+')
 
 # system_server contains time / time zone detection logic so reads the associated properties.
 get_prop(system_server, time_prop)
@@ -1389,6 +1406,7 @@ neverallow {
   device_config_aconfig_flags_prop
   device_config_window_manager_native_boot_prop
   device_config_tethering_u_or_later_native_prop
+  device_config_mmd_native_prop
   next_boot_prop
 }:property_service set;
 
@@ -1447,6 +1465,9 @@ allow system_server apex_mnt_dir:dir r_dir_perms;
 # Allow system server to read /apex/apex-info-list.xml
 allow system_server apex_info_file:file r_file_perms;
 
+# Allow system_server to communicate with tradeinmode.
+binder_call(system_server, tradeinmode)
+
 # Allow system server to communicate to system-suspend's control interface
 allow system_server system_suspend_control_internal_service:service_manager find;
 allow system_server system_suspend_control_service:service_manager find;
@@ -1498,6 +1519,10 @@ allow system_server metadata_file:dir search;
 allow system_server password_slot_metadata_file:dir rw_dir_perms;
 allow system_server password_slot_metadata_file:file create_file_perms;
 
+# Allow TradeInMode service rw access to /metadata/tradeinmode.
+allow system_server tradeinmode_metadata_file:dir rw_dir_perms;
+allow system_server tradeinmode_metadata_file:file create_file_perms;
+
 allow system_server userspace_reboot_metadata_file:dir create_dir_perms;
 allow system_server userspace_reboot_metadata_file:file create_file_perms;
 
@@ -1508,15 +1533,11 @@ allow system_server staged_install_file:file create_file_perms;
 allow system_server watchdog_metadata_file:dir rw_dir_perms;
 allow system_server watchdog_metadata_file:file create_file_perms;
 
-allow system_server aconfig_storage_flags_metadata_file:dir rw_dir_perms;
-allow system_server aconfig_storage_flags_metadata_file:file create_file_perms;
-allow system_server aconfig_storage_metadata_file:dir search;
-
-allow system_server aconfigd_socket:sock_file {read write};
-allow system_server aconfigd:unix_stream_socket connectto;
+# allow system_server write to aconfigd socket
+unix_socket_connect(system_server, aconfigd, aconfigd);
 
-allow system_server aconfig_test_mission_files:dir create_dir_perms;
-allow system_server aconfig_test_mission_files:file create_file_perms;
+# allow system_server write to aconfigd_mainline socket
+unix_socket_connect(system_server, aconfigd_mainline, aconfigd_mainline);
 
 allow system_server repair_mode_metadata_file:dir rw_dir_perms;
 allow system_server repair_mode_metadata_file:file create_file_perms;
@@ -1566,10 +1587,6 @@ neverallow {
 } password_slot_metadata_file:notdevfile_class_set ~{ relabelto getattr };
 neverallow { domain -init -system_server } password_slot_metadata_file:notdevfile_class_set *;
 
-# Only system server should access /metadata/aconfig
-neverallow { domain -init -system_server -aconfigd } aconfig_storage_flags_metadata_file:dir *;
-neverallow { domain -init -system_server -aconfigd } aconfig_storage_flags_metadata_file:file no_rw_file_perms;
-
 # Allow systemserver to read/write the invalidation property
 set_prop(system_server, binder_cache_system_server_prop)
 neverallow { domain -system_server -init }
@@ -1673,6 +1690,9 @@ allow system_server {
 neverallow { domain -init -system_server } crashrecovery_prop:property_service set;
 neverallow { domain -init -dumpstate -system_server } crashrecovery_prop:file no_rw_file_perms;
 
+# Do not allow anything other than system_server and init to touch /metadata/tradeinmode.
+neverallow { domain -init -system_server } tradeinmode_metadata_file:file no_rw_file_perms;
+
 neverallow {
   domain
   -init
diff --git a/private/tee_service_contexts b/private/tee_service_contexts
new file mode 100644
index 000000000..89eceae26
--- /dev/null
+++ b/private/tee_service_contexts
@@ -0,0 +1,13 @@
+# Tee services contexts.
+#
+# This file defines all tee services available to VMs.
+# This file is read by virtmngr.
+#
+# Format:
+# <tee_service_name> <label>
+#
+# <tee_service_name> must be a string
+
+# Example tee service that can be used for end-to-end integration of
+# custom smcs filtering on devices with pkvm hypervisor.
+test_pkvm_tee_service u:object_r:test_pkvm_tee_service:s0
diff --git a/private/tee_services.te b/private/tee_services.te
new file mode 100644
index 000000000..320f8b78c
--- /dev/null
+++ b/private/tee_services.te
@@ -0,0 +1,6 @@
+# Specify tee_services in this file.
+# Please keep the names in the alphabetical order and comment each new entry.
+
+# An example tee_service that can be used to test end-to-end integration of custom
+# smcs filtering feature on a device with pkvm hypervisor.
+type test_pkvm_tee_service, tee_service_type;
diff --git a/private/traced.te b/private/traced.te
index 796095fd7..8a2954115 100644
--- a/private/traced.te
+++ b/private/traced.te
@@ -53,6 +53,9 @@ allow traced  {
   userdebug_or_eng(`system_server_tmpfs')
 }:file { getattr map read write };
 
+# Allow traced to detect if a process is frozen (b/381089063).
+allow traced cgroup_v2:file r_file_perms;
+
 # Allow setting debug properties which guard initialization of the Perfetto SDK
 # in SurfaceFlinger and HWUI's copy of Skia.
 # Required for the android.sdk_sysprop_guard data source.
diff --git a/private/tradeinmode.te b/private/tradeinmode.te
new file mode 100644
index 000000000..dca1bc109
--- /dev/null
+++ b/private/tradeinmode.te
@@ -0,0 +1,31 @@
+### trade-in mode
+
+type tradeinmode, domain, coredomain;
+type tradeinmode_exec, exec_type, file_type, system_file_type;
+
+allow tradeinmode adbd_tradeinmode:fd use;
+allow tradeinmode adbd_tradeinmode:unix_stream_socket { read write ioctl };
+
+# Allow running from normal shell.
+allow tradeinmode { adbd shell }:fd use;
+allow tradeinmode adbd:unix_stream_socket { read write ioctl };
+
+allow tradeinmode devpts:chr_file rw_file_perms;
+
+# Allow executing am/content without a domain transition.
+allow tradeinmode system_file:file rx_file_perms;
+allow tradeinmode zygote_exec:file rx_file_perms;
+allow tradeinmode apex_info_file:file r_file_perms;
+
+allow tradeinmode activity_service:service_manager find;
+
+get_prop(tradeinmode, odsign_prop)
+get_prop(tradeinmode, build_attestation_prop)
+get_prop(tradeinmode, adbd_tradeinmode_prop)
+
+# Needed to start activities through "am".
+binder_call(tradeinmode, system_server)
+binder_call(tradeinmode, servicemanager)
+
+# Needed to run "content".
+binder_call(tradeinmode, platform_app)
diff --git a/private/uprobestats.te b/private/uprobestats.te
index 2c5711f11..c55f23d61 100644
--- a/private/uprobestats.te
+++ b/private/uprobestats.te
@@ -24,6 +24,9 @@ unix_socket_send(uprobestats, statsdw, statsd)
 # For registration with system server as a process observer.
 binder_use(uprobestats)
 allow uprobestats activity_service:service_manager find;
+starting_at_board_api(202504, `
+    allow uprobestats dynamic_instrumentation_service:service_manager find;
+')
 binder_call(uprobestats, system_server);
 
 # Allow uprobestats to talk to native package manager
diff --git a/private/vendor_init.te b/private/vendor_init.te
index 84ec60ebc..a50bc27e6 100644
--- a/private/vendor_init.te
+++ b/private/vendor_init.te
@@ -115,6 +115,7 @@ allow vendor_init {
   -userspace_reboot_metadata_file
   -aconfig_storage_metadata_file
   -aconfig_storage_flags_metadata_file
+  -tradeinmode_metadata_file
   enforce_debugfs_restriction(`-debugfs_type')
 }:file { create getattr open read write setattr relabelfrom unlink map };
 
@@ -291,6 +292,7 @@ set_prop(vendor_init, logd_prop)
 set_prop(vendor_init, log_tag_prop)
 set_prop(vendor_init, log_prop)
 set_prop(vendor_init, graphics_config_writable_prop)
+set_prop(vendor_init, prefetch_boot_prop);
 set_prop(vendor_init, qemu_hw_prop)
 set_prop(vendor_init, radio_control_prop)
 set_prop(vendor_init, rebootescrow_hal_prop)
diff --git a/private/virtual_camera.te b/private/virtual_camera.te
index fa8db4365..c4fa6a1a3 100644
--- a/private/virtual_camera.te
+++ b/private/virtual_camera.te
@@ -28,9 +28,7 @@ binder_call(virtual_camera, appdomain)
 # Allow virtual_camera to use fd from apps
 allow virtual_camera { appdomain -isolated_app }:fd use;
 
-# Allow virtual_camera to use fd from surface flinger
-allow virtual_camera surfaceflinger:fd use;
-allow virtual_camera surfaceflinger:binder call;
+binder_call(virtual_camera, surfaceflinger);
 
 # Only allow virtual_camera to add a virtual_camera_service and no one else.
 add_service(virtual_camera, virtual_camera_service);
diff --git a/private/virtualizationmanager.te b/private/virtualizationmanager.te
index 023e3e908..ca7227953 100644
--- a/private/virtualizationmanager.te
+++ b/private/virtualizationmanager.te
@@ -135,3 +135,10 @@ is_flag_enabled(RELEASE_AVF_ENABLE_NETWORK, `
     allow virtualizationmanager tun_device:chr_file rw_file_perms;
     allow virtualizationmanager vmnic:fd use;
 ')
+
+# virtualizationmanager reads tee_service_contexts_file to determine if VM is allowed
+# to access requested tee services
+allow virtualizationmanager tee_service_contexts_file:file r_file_perms;
+# virtualizationmanager uses libselinux to check if VM is allowed to access requested
+# tee services.
+selinux_check_access(virtualizationmanager)
diff --git a/private/virtualizationservice.te b/private/virtualizationservice.te
index bc29e39e1..1acf73456 100644
--- a/private/virtualizationservice.te
+++ b/private/virtualizationservice.te
@@ -131,7 +131,7 @@ neverallow virtualizationservice {
   -virtualizationmanager
   -virtualizationservice
   # TODO(b/332677707): remove them when display service uses binder RPC.
-  is_flag_enabled(RELEASE_AVF_SUPPORT_CUSTOM_VM_WITH_PARAVIRTUALIZED_DEVICES, `-crosvm')
+  -crosvm
 }:process setrlimit;
 
 is_flag_enabled(RELEASE_AVF_ENABLE_NETWORK, `
diff --git a/private/vmlauncher_app.te b/private/vmlauncher_app.te
index c76c1175a..ef34c31c8 100644
--- a/private/vmlauncher_app.te
+++ b/private/vmlauncher_app.te
@@ -11,6 +11,13 @@ allow vmlauncher_app shell_data_file:dir search;
 allow vmlauncher_app shell_data_file:file { read open write };
 virtualizationservice_use(vmlauncher_app)
 
+allow vmlauncher_app fsck_exec:file { r_file_perms execute execute_no_trans };
+allow vmlauncher_app crosvm:fd use;
+allow vmlauncher_app crosvm_tmpfs:file { map read write };
+allow vmlauncher_app crosvm_exec:file rx_file_perms;
+
+allow vmlauncher_app privapp_data_file:sock_file { create unlink write getattr };
+
 is_flag_enabled(RELEASE_AVF_SUPPORT_CUSTOM_VM_WITH_PARAVIRTUALIZED_DEVICES, `
   # TODO(b/332677707): remove them when display service uses binder RPC.
   allow vmlauncher_app virtualization_service:service_manager find;
@@ -18,9 +25,16 @@ is_flag_enabled(RELEASE_AVF_SUPPORT_CUSTOM_VM_WITH_PARAVIRTUALIZED_DEVICES, `
   allow vmlauncher_app crosvm:binder { call transfer };
 ')
 
+is_flag_enabled(RELEASE_AVF_ENABLE_NETWORK, `
+  allow vmlauncher_app self:vsock_socket { create_socket_perms_no_ioctl listen accept };
+')
+
 userdebug_or_eng(`
   # Create pty/pts and connect it to the guest terminal.
   create_pty(vmlauncher_app)
   # Allow other processes to access the pts.
   allow vmlauncher_app vmlauncher_app_devpts:chr_file setattr;
 ')
+
+# TODO(b/372664601): Remove this when we don't need linux_vm_setup
+set_prop(vmlauncher_app, debug_prop);
diff --git a/private/vold.te b/private/vold.te
index 339877de0..c24204021 100644
--- a/private/vold.te
+++ b/private/vold.te
@@ -364,6 +364,8 @@ allow vold mnt_vendor_file:dir search;
 
 dontaudit vold self:global_capability_class_set sys_resource;
 
+dontaudit vold self:capability sys_rawio;
+
 # Allow ReadDefaultFstab().
 read_fstab(vold)
 
diff --git a/private/wifi_mainline_supplicant.te b/private/wifi_mainline_supplicant.te
new file mode 100644
index 000000000..d6c7998b9
--- /dev/null
+++ b/private/wifi_mainline_supplicant.te
@@ -0,0 +1,31 @@
+type wifi_mainline_supplicant, domain, coredomain;
+type wifi_mainline_supplicant_exec, system_file_type, exec_type, file_type;
+
+binder_use(wifi_mainline_supplicant)
+init_daemon_domain(wifi_mainline_supplicant)
+add_service(wifi_mainline_supplicant, wifi_mainline_supplicant_service)
+
+allow wifi_mainline_supplicant self:global_capability_class_set { setuid setgid net_admin net_raw };
+allow wifi_mainline_supplicant proc_net:file rw_file_perms;
+allow wifi_mainline_supplicant sysfs_net:dir search;
+
+# Allow limited access to the parent directory /data/misc/wifi/
+allow wifi_mainline_supplicant wifi_data_file:dir { getattr search };
+
+# Create temporary socket files in /data/misc/wifi/mainline_supplicant/sockets
+allow wifi_mainline_supplicant mainline_supplicant_data_file:dir create_dir_perms;
+allow wifi_mainline_supplicant mainline_supplicant_data_file:file create_file_perms;
+allow wifi_mainline_supplicant mainline_supplicant_data_file:sock_file { create write setattr unlink };
+
+# UDP sockets
+allow wifi_mainline_supplicant self:udp_socket create_socket_perms;
+allowxperm wifi_mainline_supplicant self:udp_socket ioctl { priv_sock_ioctls SIOCSIFFLAGS SIOCSIFHWADDR };
+
+# Packet sockets
+allow wifi_mainline_supplicant self:packet_socket create_socket_perms;
+allowxperm wifi_mainline_supplicant self:packet_socket ioctl { unpriv_sock_ioctls priv_sock_ioctls unpriv_tty_ioctls };
+
+# Netlink sockets
+allow wifi_mainline_supplicant self:netlink_route_socket { bind create read write nlmsg_readpriv nlmsg_write };
+allow wifi_mainline_supplicant self:netlink_socket create_socket_perms_no_ioctl;
+allow wifi_mainline_supplicant self:netlink_generic_socket create_socket_perms_no_ioctl;
diff --git a/public/attributes b/public/attributes
index 759b773a2..6e11b8605 100644
--- a/public/attributes
+++ b/public/attributes
@@ -366,6 +366,9 @@ hal_attribute(keymint);
 hal_attribute(light);
 hal_attribute(lowpan);
 hal_attribute(macsec);
+starting_at_board_api(202504, `
+    hal_attribute(mediaquality);
+')
 hal_attribute(memtrack);
 hal_attribute(neuralnetworks);
 hal_attribute(nfc);
@@ -449,3 +452,8 @@ attribute charger_type;
 
 # All types of ART properties.
 attribute dalvik_config_prop_type;
+
+# All tee services that can be accessed by VMs
+starting_at_board_api(202504, `
+    attribute tee_service_type;
+')
diff --git a/public/file.te b/public/file.te
index 4f187ec50..94483a3bf 100644
--- a/public/file.te
+++ b/public/file.te
@@ -100,9 +100,6 @@ type cgroup, fs_type, mlstrustedobject;
 type cgroup_v2, fs_type;
 type sysfs, fs_type, sysfs_type, mlstrustedobject;
 type sysfs_android_usb, fs_type, sysfs_type;
-starting_at_board_api(202504, `
-    type sysfs_udc, fs_type, sysfs_type;
-')
 type sysfs_uio, sysfs_type, fs_type;
 type sysfs_batteryinfo, fs_type, sysfs_type;
 type sysfs_bluetooth_writable, fs_type, sysfs_type, mlstrustedobject;
@@ -224,16 +221,22 @@ type system_security_cacerts_file, system_file_type, file_type;
 type tcpdump_exec, system_file_type, exec_type, file_type;
 # Default type for zoneinfo files in /system/usr/share/zoneinfo/*.
 type system_zoneinfo_file, system_file_type, file_type;
-# Cgroups description file under /system/etc/cgroups.json
+# Cgroups description file under /system/etc/cgroups.json or
+# API file under /system/etc/task_profiles/cgroups_*.json
 type cgroup_desc_file, system_file_type, file_type;
-# Cgroups description file under /system/etc/task_profiles/cgroups_*.json
-type cgroup_desc_api_file, system_file_type, file_type;
+until_board_api(202504, `
+    # Cgroups description file under /system/etc/task_profiles/cgroups_*.json
+    type cgroup_desc_api_file, system_file_type, file_type;
+')
 # Vendor cgroups description file under /vendor/etc/cgroups.json
 type vendor_cgroup_desc_file, vendor_file_type, file_type;
-# Task profiles file under /system/etc/task_profiles.json
+# Task profiles file under /system/etc/task_profiles.json or
+# API file under /system/etc/task_profiles/task_profiles_*.json
 type task_profiles_file, system_file_type, file_type;
-# Task profiles file under /system/etc/task_profiles/task_profiles_*.json
-type task_profiles_api_file, system_file_type, file_type;
+until_board_api(202504, `
+    # Task profiles file under /system/etc/task_profiles/task_profiles_*.json
+    type task_profiles_api_file, system_file_type, file_type;
+')
 # Vendor task profiles file under /vendor/etc/task_profiles.json
 type vendor_task_profiles_file, vendor_file_type, file_type;
 # Type for /system/apex/com.android.art
@@ -644,6 +647,11 @@ with_asan(`type asanwrapper_exec, exec_type, file_type;')
 # Deprecated in SDK version 28
 type audiohal_data_file, file_type, data_file_type, core_data_file_type;
 
+starting_at_board_api(202504, `
+    type sysfs_udc, fs_type, sysfs_type;
+    type tee_service_contexts_file, system_file_type, file_type;
+')
+
 # system/sepolicy/public is for vendor-facing type and attribute definitions.
 # DO NOT ADD allow, neverallow, or dontaudit statements here.
 # Instead, add such policy rules to system/sepolicy/private/*.te.
diff --git a/public/property.te b/public/property.te
index a186f0425..cb1874179 100644
--- a/public/property.te
+++ b/public/property.te
@@ -206,6 +206,9 @@ system_vendor_config_prop(tuner_config_prop)
 system_vendor_config_prop(usb_uvc_enabled_prop)
 system_vendor_config_prop(setupwizard_mode_prop)
 system_vendor_config_prop(pm_archiving_enabled_prop)
+starting_at_board_api(202504, `
+    system_vendor_config_prop(trusty_security_vm_sys_vendor_prop)
+')
 
 # Properties with no restrictions
 system_public_prop(adbd_config_prop)
diff --git a/public/service.te b/public/service.te
index 663ca1411..854ceef11 100644
--- a/public/service.te
+++ b/public/service.te
@@ -66,12 +66,18 @@ type activity_service, app_api_service, ephemeral_app_api_service, system_server
 type activity_task_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type adb_service, system_api_service, system_server_service, service_manager_type;
 type adservices_manager_service, system_api_service, system_server_service, service_manager_type;
+starting_at_board_api(202504, `
+    type advanced_protection_service, app_api_service, system_server_service, service_manager_type;
+')
 type alarm_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type app_binding_service, system_server_service, service_manager_type;
 starting_at_board_api(202504, `
     type app_function_service, app_api_service, system_server_service, service_manager_type;
 ')
 type app_hibernation_service, app_api_service, system_api_service, system_server_service, service_manager_type;
+starting_at_board_api(202504, `
+    type dynamic_instrumentation_service, app_api_service, system_server_service, service_manager_type;
+')
 type app_integrity_service, system_api_service, system_server_service, service_manager_type;
 type app_prediction_service, app_api_service, system_server_service, service_manager_type;
 type app_search_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
@@ -141,6 +147,9 @@ type bugreport_service, app_api_service, system_server_service, service_manager_
 type platform_compat_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type face_service, app_api_service, system_server_service, service_manager_type;
 type fingerprint_service, app_api_service, system_server_service, service_manager_type;
+starting_at_board_api(202504, `
+    type forensic_service, app_api_service, system_api_service, system_server_service, service_manager_type;
+')
 type fwk_altitude_service, system_server_service, service_manager_type;
 type fwk_stats_service, app_api_service, system_server_service, service_manager_type;
 type fwk_sensor_service, system_server_service, service_manager_type;
@@ -159,6 +168,9 @@ type imms_service, app_api_service, ephemeral_app_api_service, system_server_ser
 type incremental_service, system_server_service, service_manager_type;
 type input_method_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type input_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
+starting_at_board_api(202504, `
+    type intrusion_detection_service, app_api_service, system_api_service, system_server_service, service_manager_type;
+')
 type ipsec_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type iris_service, app_api_service, system_server_service, service_manager_type;
 type jobscheduler_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
@@ -173,6 +185,9 @@ type looper_stats_service, system_server_service, service_manager_type;
 type media_communication_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type media_metrics_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type media_projection_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
+starting_at_board_api(202504, `
+    type media_quality_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
+')
 type media_router_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type media_session_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
 type meminfo_service, system_api_service, system_server_service, service_manager_type;
@@ -283,6 +298,9 @@ type wifiscanner_service, app_api_service, system_server_service, service_manage
 type wifi_service, app_api_service, system_server_service, service_manager_type;
 type wifinl80211_service, service_manager_type;
 type wifiaware_service, app_api_service, system_server_service, service_manager_type;
+starting_at_board_api(202504, `
+   type wifi_usd_service, app_api_service, system_server_service, service_manager_type;
+')
 type window_service, system_api_service, system_server_service, service_manager_type;
 type inputflinger_service, system_api_service, system_server_service, service_manager_type;
 type tethering_service, app_api_service, ephemeral_app_api_service, system_server_service, service_manager_type;
@@ -324,6 +342,9 @@ type hal_ivn_service, protected_service, hal_service_type, service_manager_type;
 type hal_keymint_service, protected_service, hal_service_type, service_manager_type;
 type hal_light_service, protected_service, hal_service_type, service_manager_type;
 type hal_macsec_service, protected_service, hal_service_type, service_manager_type;
+starting_at_board_api(202504, `
+    type hal_mediaquality_service, protected_service, hal_service_type, service_manager_type;
+')
 type hal_memtrack_service, protected_service, hal_service_type, service_manager_type;
 type hal_neuralnetworks_service, hal_service_type, service_manager_type;
 type hal_nfc_service, protected_service, hal_service_type, service_manager_type;
diff --git a/tests/Android.bp b/tests/Android.bp
index 3dda11a1b..81e7927c5 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -83,6 +83,8 @@ python_binary_host {
     libs: ["pysepolwrap"],
     data: [
         ":libsepolwrap",
+    ],
+    device_common_data: [
         ":precompiled_sepolicy",
     ],
 }
@@ -96,6 +98,8 @@ python_test_host {
     libs: ["pysepolwrap"],
     data: [
         ":libsepolwrap",
+    ],
+    device_common_data: [
         ":precompiled_sepolicy",
     ],
     test_options: {
diff --git a/treble_sepolicy_tests_for_release.mk b/treble_sepolicy_tests_for_release.mk
deleted file mode 100644
index 2e9d68f6b..000000000
--- a/treble_sepolicy_tests_for_release.mk
+++ /dev/null
@@ -1,81 +0,0 @@
-version := $(version_under_treble_tests)
-
-include $(CLEAR_VARS)
-# For Treble builds run tests verifying that processes are properly labeled and
-# permissions granted do not violate the treble model.  Also ensure that treble
-# compatibility guarantees are upheld between SELinux version bumps.
-LOCAL_MODULE := treble_sepolicy_tests_$(version)
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0 legacy_unencumbered
-LOCAL_LICENSE_CONDITIONS := notice unencumbered
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/NOTICE
-LOCAL_MODULE_CLASS := FAKE
-LOCAL_MODULE_TAGS := optional
-
-IS_TREBLE_TEST_ENABLED_PARTNER := false
-ifeq ($(filter 26.0 27.0 28.0 29.0,$(version)),)
-ifneq (,$(BOARD_SYSTEM_EXT_PREBUILT_DIR)$(BOARD_PRODUCT_PREBUILT_DIR))
-IS_TREBLE_TEST_ENABLED_PARTNER := true
-endif # (,$(BOARD_SYSTEM_EXT_PREBUILT_DIR)$(BOARD_PRODUCT_PREBUILT_DIR))
-endif # ($(filter 26.0 27.0 28.0 29.0,$(version)),)
-
-include $(BUILD_SYSTEM)/base_rules.mk
-
-# $(version)_plat - the platform policy shipped as part of the $(version) release.  This is
-# built to enable us to determine the diff between the current policy and the
-# $(version) policy, which will be used in tests to make sure that compatibility has
-# been maintained by our mapping files.
-built_$(version)_plat_sepolicy_cil := $(call intermediates-dir-for,ETC,$(version)_plat_policy.cil)/$(version)_plat_policy.cil
-
-$(version)_mapping.cil := $(call intermediates-dir-for,ETC,plat_$(version).cil)/plat_$(version).cil
-$(version)_mapping.ignore.cil := \
-    $(call intermediates-dir-for,ETC,$(version).ignore.cil)/$(version).ignore.cil
-ifeq ($(IS_TREBLE_TEST_ENABLED_PARTNER),true)
-ifneq (,$(BOARD_SYSTEM_EXT_PREBUILT_DIR))
-$(version)_mapping.cil += \
-    $(call intermediates-dir-for,ETC,system_ext_$(version).cil)/system_ext_$(version).cil
-$(version)_mapping.ignore.cil += \
-    $(call intermediates-dir-for,ETC,system_ext_$(version).ignore.cil)/system_ext_$(version).ignore.cil
-endif # (,$(BOARD_SYSTEM_EXT_PREBUILT_DIR))
-ifneq (,$(BOARD_PRODUCT_PREBUILT_DIR))
-$(version)_mapping.cil += \
-    $(call intermediates-dir-for,ETC,product_$(version).cil)/product_$(version).cil
-$(version)_mapping.ignore.cil += \
-    $(call intermediates-dir-for,ETC,product_$(version).ignore.cil)/product_$(version).ignore.cil
-endif # (,$(BOARD_PRODUCT_PREBUILT_DIR))
-endif #($(IS_TREBLE_TEST_ENABLED_PARTNER),true)
-
-# $(version)_mapping.combined.cil - a combination of the mapping file used when
-# combining the current platform policy with nonplatform policy based on the
-# $(version) policy release and also a special ignored file that exists purely for
-# these tests.
-intermediates := $(TARGET_OUT_INTERMEDIATES)/ETC/$(LOCAL_MODULE)_intermediates
-$(version)_mapping.combined.cil := $(intermediates)/$(version)_mapping.combined.cil
-$($(version)_mapping.combined.cil): $($(version)_mapping.cil) $($(version)_mapping.ignore.cil)
-	mkdir -p $(dir $@)
-	cat $^ > $@
-
-ifeq ($(IS_TREBLE_TEST_ENABLED_PARTNER),true)
-public_cil_files := $(base_product_pub_policy.cil)
-else
-public_cil_files := $(base_plat_pub_policy.cil)
-endif # ($(IS_TREBLE_TEST_ENABLED_PARTNER),true)
-$(LOCAL_BUILT_MODULE): PRIVATE_SEPOLICY_OLD := $(built_$(version)_plat_sepolicy_cil)
-$(LOCAL_BUILT_MODULE): PRIVATE_COMBINED_MAPPING := $($(version)_mapping.combined.cil)
-$(LOCAL_BUILT_MODULE): PRIVATE_PLAT_PUB_SEPOLICY := $(public_cil_files)
-$(LOCAL_BUILT_MODULE): $(HOST_OUT_EXECUTABLES)/treble_sepolicy_tests \
-  $(public_cil_files) \
-  $(built_$(version)_plat_sepolicy_cil) $($(version)_mapping.combined.cil)
-	@mkdir -p $(dir $@)
-	$(hide) $(HOST_OUT_EXECUTABLES)/treble_sepolicy_tests \
-                -b $(PRIVATE_PLAT_PUB_SEPOLICY) -m $(PRIVATE_COMBINED_MAPPING) \
-                -o $(PRIVATE_SEPOLICY_OLD)
-	$(hide) touch $@
-
-built_sepolicy_files :=
-public_cil_files :=
-$(version)_mapping.cil :=
-$(version)_mapping.combined.cil :=
-$(version)_mapping.ignore.cil :=
-built_$(version)_plat_sepolicy :=
-version :=
-version_under_treble_tests :=
diff --git a/treble_sepolicy_tests_for_release/Android.bp b/treble_sepolicy_tests_for_release/Android.bp
new file mode 100644
index 000000000..7756cbb82
--- /dev/null
+++ b/treble_sepolicy_tests_for_release/Android.bp
@@ -0,0 +1,448 @@
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
+package {
+    default_applicable_licenses: [
+        "Android-Apache-2.0",
+        "system_sepolicy_license",
+    ],
+}
+
+//////////////////////////////////
+// Tests for Treble compatibility of current platform policy and vendor policy of
+// given release version.
+//////////////////////////////////
+java_genrule {
+    name: "29.0_mapping.combined.cil",
+    srcs: [
+        ":plat_29.0.cil",
+        ":29.0.ignore.cil",
+    ],
+    out: ["29.0_mapping.combined.cil"],
+    cmd: "cat $(location :plat_29.0.cil) $(location :29.0.ignore.cil) > $(out)",
+}
+
+java_genrule {
+    name: "treble_sepolicy_tests_29.0",
+    srcs: [
+        ":29.0_plat_policy.cil",
+        ":29.0_mapping.combined.cil",
+        ":29.0_plat_pub_policy.cil",
+    ],
+    tools: ["treble_sepolicy_tests"],
+    out: ["treble_sepolicy_tests_29.0"],
+    cmd: "$(location treble_sepolicy_tests) " +
+        "-b $(location :29.0_plat_pub_policy.cil) " +
+        "-m $(location :29.0_mapping.combined.cil) " +
+        "-o $(location :29.0_plat_policy.cil) && " +
+        "touch $(out)",
+}
+
+java_genrule {
+    name: "30.0_mapping.combined.cil",
+    srcs: [
+        ":plat_30.0.cil",
+        ":30.0.ignore.cil",
+    ] + select(soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"), {
+        true: [
+            ":system_ext_30.0.cil",
+            ":system_ext_30.0.ignore.cil",
+        ],
+        default: [],
+    }) + select(soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"), {
+        true: [
+            ":product_30.0.cil",
+            ":product_30.0.ignore.cil",
+        ],
+        default: [],
+    }),
+    out: ["30.0_mapping.combined.cil"],
+    cmd: "cat $(location :plat_30.0.cil) " +
+        "$(location :30.0.ignore.cil) " +
+        select(soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"), {
+            true: "$(location :system_ext_30.0.cil) " +
+                "$(location :system_ext_30.0.ignore.cil) ",
+            default: "",
+        }) +
+        select(soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"), {
+            true: "$(location :product_30.0.cil) " +
+                "$(location :product_30.0.ignore.cil) ",
+            default: "",
+        }) +
+        "> $(out)",
+}
+
+java_genrule {
+    name: "treble_sepolicy_tests_30.0",
+    srcs: [
+        ":30.0_plat_policy.cil",
+        ":30.0_mapping.combined.cil",
+    ] + select((
+        soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"),
+        soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"),
+    ), {
+        (false, false): [":30.0_plat_pub_policy.cil"],
+        (default, default): [":30.0_product_pub_policy.cil"],
+    }),
+    tools: ["treble_sepolicy_tests"],
+    out: ["treble_sepolicy_tests_30.0"],
+    cmd: select((
+        soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"),
+        soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"),
+    ), {
+        (false, false): "$(location treble_sepolicy_tests) " +
+            "-b $(location :30.0_plat_pub_policy.cil) " +
+            "-m $(location :30.0_mapping.combined.cil) " +
+            "-o $(location :30.0_plat_policy.cil) && " +
+            "touch $(out)",
+        (default, default): "$(location treble_sepolicy_tests) " +
+            "-b $(location :30.0_product_pub_policy.cil) " +
+            "-m $(location :30.0_mapping.combined.cil) " +
+            "-o $(location :30.0_plat_policy.cil) && " +
+            "touch $(out)",
+    }),
+}
+
+java_genrule {
+    name: "31.0_mapping.combined.cil",
+    srcs: [
+        ":plat_31.0.cil",
+        ":31.0.ignore.cil",
+    ] + select(soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"), {
+        true: [
+            ":system_ext_31.0.cil",
+            ":system_ext_31.0.ignore.cil",
+        ],
+        default: [],
+    }) + select(soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"), {
+        true: [
+            ":product_31.0.cil",
+            ":product_31.0.ignore.cil",
+        ],
+        default: [],
+    }),
+    out: ["31.0_mapping.combined.cil"],
+    cmd: "cat $(location :plat_31.0.cil) " +
+        "$(location :31.0.ignore.cil) " +
+        select(soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"), {
+            true: "$(location :system_ext_31.0.cil) " +
+                "$(location :system_ext_31.0.ignore.cil) ",
+            default: "",
+        }) +
+        select(soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"), {
+            true: "$(location :product_31.0.cil) " +
+                "$(location :product_31.0.ignore.cil) ",
+            default: "",
+        }) +
+        "> $(out)",
+}
+
+java_genrule {
+    name: "treble_sepolicy_tests_31.0",
+    srcs: [
+        ":31.0_plat_policy.cil",
+        ":31.0_mapping.combined.cil",
+    ] + select((
+        soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"),
+        soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"),
+    ), {
+        (false, false): [":31.0_plat_pub_policy.cil"],
+        (default, default): [":31.0_product_pub_policy.cil"],
+    }),
+    tools: ["treble_sepolicy_tests"],
+    out: ["treble_sepolicy_tests_31.0"],
+    cmd: select((
+        soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"),
+        soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"),
+    ), {
+        (false, false): "$(location treble_sepolicy_tests) " +
+            "-b $(location :31.0_plat_pub_policy.cil) " +
+            "-m $(location :31.0_mapping.combined.cil) " +
+            "-o $(location :31.0_plat_policy.cil) && " +
+            "touch $(out)",
+        (default, default): "$(location treble_sepolicy_tests) " +
+            "-b $(location :31.0_product_pub_policy.cil) " +
+            "-m $(location :31.0_mapping.combined.cil) " +
+            "-o $(location :31.0_plat_policy.cil) && " +
+            "touch $(out)",
+    }),
+}
+
+java_genrule {
+    name: "32.0_mapping.combined.cil",
+    srcs: [
+        ":plat_32.0.cil",
+        ":32.0.ignore.cil",
+    ] + select(soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"), {
+        true: [
+            ":system_ext_32.0.cil",
+            ":system_ext_32.0.ignore.cil",
+        ],
+        default: [],
+    }) + select(soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"), {
+        true: [
+            ":product_32.0.cil",
+            ":product_32.0.ignore.cil",
+        ],
+        default: [],
+    }),
+    out: ["32.0_mapping.combined.cil"],
+    cmd: "cat $(location :plat_32.0.cil) " +
+        "$(location :32.0.ignore.cil) " +
+        select(soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"), {
+            true: "$(location :system_ext_32.0.cil) " +
+                "$(location :system_ext_32.0.ignore.cil) ",
+            default: "",
+        }) +
+        select(soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"), {
+            true: "$(location :product_32.0.cil) " +
+                "$(location :product_32.0.ignore.cil) ",
+            default: "",
+        }) +
+        "> $(out)",
+}
+
+java_genrule {
+    name: "treble_sepolicy_tests_32.0",
+    srcs: [
+        ":32.0_plat_policy.cil",
+        ":32.0_mapping.combined.cil",
+    ] + select((
+        soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"),
+        soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"),
+    ), {
+        (false, false): [":32.0_plat_pub_policy.cil"],
+        (default, default): [":32.0_product_pub_policy.cil"],
+    }),
+    tools: ["treble_sepolicy_tests"],
+    out: ["treble_sepolicy_tests_32.0"],
+    cmd: select((
+        soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"),
+        soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"),
+    ), {
+        (false, false): "$(location treble_sepolicy_tests) " +
+            "-b $(location :32.0_plat_pub_policy.cil) " +
+            "-m $(location :32.0_mapping.combined.cil) " +
+            "-o $(location :32.0_plat_policy.cil) && " +
+            "touch $(out)",
+        (default, default): "$(location treble_sepolicy_tests) " +
+            "-b $(location :32.0_product_pub_policy.cil) " +
+            "-m $(location :32.0_mapping.combined.cil) " +
+            "-o $(location :32.0_plat_policy.cil) && " +
+            "touch $(out)",
+    }),
+}
+
+java_genrule {
+    name: "33.0_mapping.combined.cil",
+    srcs: [
+        ":plat_33.0.cil",
+        ":33.0.ignore.cil",
+    ] + select(soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"), {
+        true: [
+            ":system_ext_33.0.cil",
+            ":system_ext_33.0.ignore.cil",
+        ],
+        default: [],
+    }) + select(soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"), {
+        true: [
+            ":product_33.0.cil",
+            ":product_33.0.ignore.cil",
+        ],
+        default: [],
+    }),
+    out: ["33.0_mapping.combined.cil"],
+    cmd: "cat $(location :plat_33.0.cil) " +
+        "$(location :33.0.ignore.cil) " +
+        select(soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"), {
+            true: "$(location :system_ext_33.0.cil) " +
+                "$(location :system_ext_33.0.ignore.cil) ",
+            default: "",
+        }) +
+        select(soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"), {
+            true: "$(location :product_33.0.cil) " +
+                "$(location :product_33.0.ignore.cil) ",
+            default: "",
+        }) +
+        "> $(out)",
+}
+
+java_genrule {
+    name: "treble_sepolicy_tests_33.0",
+    srcs: [
+        ":33.0_plat_policy.cil",
+        ":33.0_mapping.combined.cil",
+    ] + select((
+        soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"),
+        soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"),
+    ), {
+        (false, false): [":33.0_plat_pub_policy.cil"],
+        (default, default): [":33.0_product_pub_policy.cil"],
+    }),
+    tools: ["treble_sepolicy_tests"],
+    out: ["treble_sepolicy_tests_33.0"],
+    cmd: select((
+        soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"),
+        soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"),
+    ), {
+        (false, false): "$(location treble_sepolicy_tests) " +
+            "-b $(location :33.0_plat_pub_policy.cil) " +
+            "-m $(location :33.0_mapping.combined.cil) " +
+            "-o $(location :33.0_plat_policy.cil) && " +
+            "touch $(out)",
+        (default, default): "$(location treble_sepolicy_tests) " +
+            "-b $(location :33.0_product_pub_policy.cil) " +
+            "-m $(location :33.0_mapping.combined.cil) " +
+            "-o $(location :33.0_plat_policy.cil) && " +
+            "touch $(out)",
+    }),
+}
+
+java_genrule {
+    name: "34.0_mapping.combined.cil",
+    srcs: [
+        ":plat_34.0.cil",
+        ":34.0.ignore.cil",
+    ] + select(soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"), {
+        true: [
+            ":system_ext_34.0.cil",
+            ":system_ext_34.0.ignore.cil",
+        ],
+        default: [],
+    }) + select(soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"), {
+        true: [
+            ":product_34.0.cil",
+            ":product_34.0.ignore.cil",
+        ],
+        default: [],
+    }),
+    out: ["34.0_mapping.combined.cil"],
+    cmd: "cat $(location :plat_34.0.cil) " +
+        "$(location :34.0.ignore.cil) " +
+        select(soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"), {
+            true: "$(location :system_ext_34.0.cil) " +
+                "$(location :system_ext_34.0.ignore.cil) ",
+            default: "",
+        }) +
+        select(soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"), {
+            true: "$(location :product_34.0.cil) " +
+                "$(location :product_34.0.ignore.cil) ",
+            default: "",
+        }) +
+        "> $(out)",
+}
+
+java_genrule {
+    name: "treble_sepolicy_tests_34.0",
+    srcs: [
+        ":34.0_plat_policy.cil",
+        ":34.0_mapping.combined.cil",
+    ] + select((
+        soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"),
+        soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"),
+    ), {
+        (false, false): [":34.0_plat_pub_policy.cil"],
+        (default, default): [":34.0_product_pub_policy.cil"],
+    }),
+    tools: ["treble_sepolicy_tests"],
+    out: ["treble_sepolicy_tests_34.0"],
+    cmd: select((
+        soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"),
+        soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"),
+    ), {
+        (false, false): "$(location treble_sepolicy_tests) " +
+            "-b $(location :34.0_plat_pub_policy.cil) " +
+            "-m $(location :34.0_mapping.combined.cil) " +
+            "-o $(location :34.0_plat_policy.cil) && " +
+            "touch $(out)",
+        (default, default): "$(location treble_sepolicy_tests) " +
+            "-b $(location :34.0_product_pub_policy.cil) " +
+            "-m $(location :34.0_mapping.combined.cil) " +
+            "-o $(location :34.0_plat_policy.cil) && " +
+            "touch $(out)",
+    }),
+}
+
+java_genrule {
+    name: "202404_mapping.combined.cil",
+    srcs: select(soong_config_variable("ANDROID", "PLATFORM_SEPOLICY_VERSION"), {
+        "202404": [
+        ],
+        default: [
+            ":plat_202404.cil",
+            ":202404.ignore.cil",
+        ],
+    }) + select((
+        soong_config_variable("ANDROID", "PLATFORM_SEPOLICY_VERSION"),
+        soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"),
+    ), {
+        ("202404", true): [],
+        ("202404", default): [],
+        (default, true): [
+            ":system_ext_202404.cil",
+            ":system_ext_202404.ignore.cil",
+        ],
+        (default, default): [],
+    }) + select((
+        soong_config_variable("ANDROID", "PLATFORM_SEPOLICY_VERSION"),
+        soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"),
+    ), {
+        ("202404", true): [],
+        ("202404", default): [],
+        (default, true): [
+            ":product_202404.cil",
+            ":product_202404.ignore.cil",
+        ],
+        (default, default): [],
+    }),
+    out: ["202404_mapping.combined.cil"],
+    cmd: select(soong_config_variable("ANDROID", "PLATFORM_SEPOLICY_VERSION"), {
+        "202404": "touch $(out)",
+        default: "cat $(in) > $(out)",
+    }),
+}
+
+java_genrule {
+    name: "treble_sepolicy_tests_202404",
+    srcs: [
+        ":202404_plat_policy.cil",
+        ":202404_mapping.combined.cil",
+    ] + select((
+        soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"),
+        soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"),
+    ), {
+        (false, false): [":202404_plat_pub_policy.cil"],
+        (default, default): [":202404_product_pub_policy.cil"],
+    }),
+    tools: ["treble_sepolicy_tests"],
+    out: ["treble_sepolicy_tests_202404"],
+    cmd: select((
+        soong_config_variable("ANDROID", "PLATFORM_SEPOLICY_VERSION"),
+        soong_config_variable("ANDROID", "HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR"),
+        soong_config_variable("ANDROID", "HAS_BOARD_PRODUCT_PREBUILT_DIR"),
+    ), {
+        ("202404", false, false): "touch $(out)",
+        ("202404", default, default): "touch $(out)",
+        (default, false, false): "$(location treble_sepolicy_tests) " +
+            "-b $(location :202404_plat_pub_policy.cil) " +
+            "-m $(location :202404_mapping.combined.cil) " +
+            "-o $(location :202404_plat_policy.cil) && " +
+            "touch $(out)",
+        (default, default, default): "$(location treble_sepolicy_tests) " +
+            "-b $(location :202404_product_pub_policy.cil) " +
+            "-m $(location :202404_mapping.combined.cil) " +
+            "-o $(location :202404_plat_policy.cil) && " +
+            "touch $(out)",
+    }),
+}
diff --git a/vendor/file_contexts b/vendor/file_contexts
index d0c698dd4..66ac4ec44 100644
--- a/vendor/file_contexts
+++ b/vendor/file_contexts
@@ -22,6 +22,7 @@
 /(vendor|system/vendor)/bin/hw/android\.hardware\.bluetooth\.finder-service\.default      u:object_r:hal_bluetooth_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.bluetooth\.ranging-service\.default      u:object_r:hal_bluetooth_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.bluetooth\.lmp_event-service\.default    u:object_r:hal_bluetooth_default_exec:s0
+/(vendor|system/vendor)/bin/hw/android\.hardware\.bluetooth\.socket-service\.default       u:object_r:hal_bluetooth_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.biometrics\.face@1\.[0-9]+-service\.example u:object_r:hal_face_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.biometrics\.face-service\.example u:object_r:hal_face_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.biometrics\.face-service\.default u:object_r:hal_face_default_exec:s0
@@ -82,6 +83,9 @@
 /(vendor|system/vendor)/bin/hw/android\.hardware\.lowpan@1\.0-service         u:object_r:hal_lowpan_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.macsec-service              u:object_r:hal_macsec_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.media\.c2-default-service   u:object_r:mediacodec_exec:s0
+starting_at_board_api(202504, `
+    /(vendor|system/vendor)/bin/hw/android\.hardware\.tv\.mediaquality-service\.example  u:object_r:hal_mediaquality_default_exec:s0
+')
 /(vendor|system/vendor)/bin/hw/android\.hardware\.memtrack@1\.0-service       u:object_r:hal_memtrack_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.memtrack-service.example    u:object_r:hal_memtrack_default_exec:s0
 /(vendor|system/vendor)/bin/hw/android\.hardware\.nfc@1\.0-service            u:object_r:hal_nfc_default_exec:s0
@@ -165,7 +169,7 @@
 /(vendor|system/vendor)/lib(64)?/android\.hardware\.common-V2-ndk\.so u:object_r:same_process_hal_file:s0
 /(vendor|system/vendor)/lib(64)?/android\.hardware\.common\.fmq-V1-ndk\.so u:object_r:same_process_hal_file:s0
 /(vendor|system/vendor)/lib(64)?/android\.hardware\.graphics\.allocator-V2-ndk\.so u:object_r:same_process_hal_file:s0
-/(vendor|system/vendor)/lib(64)?/android\.hardware\.graphics\.common-V5-ndk\.so u:object_r:same_process_hal_file:s0
+/(vendor|system/vendor)/lib(64)?/android\.hardware\.graphics\.common-V[0-9]+-ndk\.so u:object_r:same_process_hal_file:s0
 /(vendor|system/vendor)/lib(64)?/android\.hardware\.graphics\.common@1\.0\.so u:object_r:same_process_hal_file:s0
 /(vendor|system/vendor)/lib(64)?/android\.hardware\.graphics\.common@1\.1\.so u:object_r:same_process_hal_file:s0
 /(vendor|system/vendor)/lib(64)?/android\.hardware\.graphics\.common@1\.2\.so u:object_r:same_process_hal_file:s0
diff --git a/vendor/hal_fingerprint_default.te b/vendor/hal_fingerprint_default.te
index 3ad14bf2c..0bcc26d4e 100644
--- a/vendor/hal_fingerprint_default.te
+++ b/vendor/hal_fingerprint_default.te
@@ -7,6 +7,10 @@ init_daemon_domain(hal_fingerprint_default)
 # android.frameworks.sensorservice through libsensorndkbridge
 allow hal_fingerprint_default fwk_sensor_service:service_manager find;
 
+starting_at_board_api(202504, `
+  set_prop(hal_fingerprint_default, virtual_fingerprint_prop)
+')
+
 userdebug_or_eng(`
   # Allow fingerprint hal to read app-created pipes (to respond shell commands from test apps)
   allow hal_fingerprint_default appdomain:fifo_file read;
diff --git a/vendor/hal_mediaquality_default.te b/vendor/hal_mediaquality_default.te
new file mode 100644
index 000000000..8f604c4cf
--- /dev/null
+++ b/vendor/hal_mediaquality_default.te
@@ -0,0 +1,7 @@
+starting_at_board_api(202504, `
+    type hal_mediaquality_default, domain;
+    hal_server_domain(hal_mediaquality_default, hal_mediaquality)
+
+    type hal_mediaquality_default_exec, exec_type, vendor_file_type, file_type;
+    init_daemon_domain(hal_mediaquality_default)
+')
\ No newline at end of file
```

