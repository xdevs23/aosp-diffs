```diff
diff --git a/Changes.md b/Changes.md
index eddec04a6c..4b7aea9654 100644
--- a/Changes.md
+++ b/Changes.md
@@ -3,11 +3,9 @@
 ## Soong genrules are now sandboxed
 
 Previously, soong genrules could access any files in the source tree, without specifying them as
-inputs. This makes them incorrect in incremental builds, and incompatible with RBE and Bazel.
+inputs. This makes them incorrect in incremental builds, and incompatible with RBE.
 
-Now, genrules are sandboxed so they can only access their listed srcs. Modules denylisted in
-genrule/allowlists.go are exempt from this. You can also set `BUILD_BROKEN_GENRULE_SANDBOXING`
-in board config to disable this behavior.
+Now, genrules are sandboxed so they can only access their listed srcs.
 
 ## Partitions are no longer affected by previous builds
 
diff --git a/CleanSpec.mk b/CleanSpec.mk
index 8c30883864..9a6db21fc2 100644
--- a/CleanSpec.mk
+++ b/CleanSpec.mk
@@ -794,6 +794,9 @@ $(call add-clean-step, rm -f $(PRODUCT_OUT)/dexpreopt_config/dexpreopt_soong.con
 # Clear out Soong .intermediates directory regarding removal of hashed subdir
 $(call add-clean-step, rm -rf $(OUT_DIR)/soong/.intermediates)
 
+# Prefer the version of build-flag in build/soong/bin
+$(call add-clean-step, rm -f $(HOST_OUT)/bin/build-flag)
+
 # ************************************************
 # NEWER CLEAN STEPS MUST BE AT THE END OF THE LIST
 # ************************************************
diff --git a/OWNERS b/OWNERS
index bd049e9558..4cac0f5a23 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,7 +1 @@
 include platform/build/soong:/OWNERS
-
-# Since this file affects all Android developers, lock it down. There is still
-# round the world timzeone coverage.
-per-file envsetup.sh = joeo@google.com, jingwen@google.com
-per-file shell_utils.sh = joeo@google.com, jingwen@google.com
-
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 97ecd33212..76c9a2c76e 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -3,3 +3,4 @@ do_not_use_DO_NOT_MERGE = ${REPO_ROOT}/build/soong/scripts/check_do_not_merge.sh
 
 [Builtin Hooks]
 ktfmt = true
+bpfmt = true
diff --git a/ci/optimized_targets.py b/ci/optimized_targets.py
index 548e34273d..75ffcb90c6 100644
--- a/ci/optimized_targets.py
+++ b/ci/optimized_targets.py
@@ -54,8 +54,14 @@ class OptimizedBuildTarget(ABC):
   def get_build_targets(self) -> set[str]:
     features = self.build_context.enabled_build_features
     if self.get_enabled_flag() in features:
-      self.modules_to_build = self.get_build_targets_impl()
-      return self.modules_to_build
+      try:
+        self.modules_to_build = self.get_build_targets_impl()
+        return self.modules_to_build
+      except Exception as e:
+        logging.error(f'error while getting build targets: {e}')
+        metrics_agent_instance = metrics_agent.MetricsAgent.instance()
+        metrics_agent_instance.report_unoptimized_target(self.target, f'Error in optimized target for {self.target}: {repr(e)}')
+        return {self.target}
 
     if self.target == 'general-tests':
       self._report_info_metrics_silently('general-tests.zip')
diff --git a/ci/optimized_targets_test.py b/ci/optimized_targets_test.py
index 2935c83cc5..fe6e80aaa5 100644
--- a/ci/optimized_targets_test.py
+++ b/ci/optimized_targets_test.py
@@ -198,26 +198,32 @@ class GeneralTestsOptimizerTest(fake_filesystem_unittest.TestCase):
     self._verify_soong_zip_commands(package_commands, ['module_1'])
 
   @mock.patch('subprocess.run')
-  def test_get_soong_dumpvars_fails_raises(self, subprocess_run):
+  def test_get_soong_dumpvars_fails_fallback(self, subprocess_run):
     subprocess_run.return_value = self._get_soong_vars_output(return_code=-1)
     optimizer = self._create_general_tests_optimizer()
     self._set_up_build_outputs(['test_mapping_module'])
 
-    with self.assertRaisesRegex(RuntimeError, 'Soong dumpvars failed!'):
-      targets = optimizer.get_build_targets()
+    targets = optimizer.get_build_targets()
+
+    expected_build_targets = set()
+    expected_build_targets.add('general-tests')
+    # When a failure happens, we return the target itself
+    self.assertSetEqual(targets, expected_build_targets)
 
   @mock.patch('subprocess.run')
-  def test_get_soong_dumpvars_bad_output_raises(self, subprocess_run):
+  def test_get_soong_dumpvars_bad_output_fallback(self, subprocess_run):
     subprocess_run.return_value = self._get_soong_vars_output(
         stdout='This output is bad'
     )
     optimizer = self._create_general_tests_optimizer()
     self._set_up_build_outputs(['test_mapping_module'])
 
-    with self.assertRaisesRegex(
-        RuntimeError, 'Error parsing soong dumpvars output'
-    ):
-      targets = optimizer.get_build_targets()
+    targets = optimizer.get_build_targets()
+
+    expected_build_targets = set()
+    expected_build_targets.add('general-tests')
+    # When a failure happens, we return the target itself
+    self.assertSetEqual(targets, expected_build_targets)
 
   def _create_general_tests_optimizer(self, build_context: BuildContext = None):
     if not build_context:
diff --git a/ci/test_discovery_agent.py b/ci/test_discovery_agent.py
index 3c1caf45d9..4099fbe030 100644
--- a/ci/test_discovery_agent.py
+++ b/ci/test_discovery_agent.py
@@ -72,7 +72,8 @@ class TestDiscoveryAgent:
       env.update({"DISCOVERY_OUTPUT_FILE": test_discovery_output_file.name})
       logging.info(f"Calling test discovery with args: {java_args}")
       try:
-        result = subprocess.run(args=java_args, env=env, text=True, check=True)
+        result = subprocess.run(args=java_args, env=env, text=True, check=True, stdout=subprocess.PIPE,
+    stderr=subprocess.PIPE)
         logging.info(f"Test zip discovery output: {result.stdout}")
       except subprocess.CalledProcessError as e:
         raise TestDiscoveryError(
diff --git a/core/Makefile b/core/Makefile
index 1448572d46..a18d6bd8fc 100644
--- a/core/Makefile
+++ b/core/Makefile
@@ -1,5 +1,7 @@
 # Put some miscellaneous rules here
 
+$(info [$(include_makefiles_total)/$(include_makefiles_total)] finishing Make packaging rules)
+
 # HACK: clear LOCAL_PATH from including last build target before calling
 # intermedites-dir-for
 LOCAL_PATH := $(BUILD_SYSTEM)
@@ -767,6 +769,21 @@ $(hide) cat $1 >> $2
 
 endef
 
+define _apkcerts_build_for_packages
+$(1): $(sort $(foreach p,$(2),$(PACKAGES.$(p).APKCERTS_FILE)))
+	rm -f $$@
+	$$(foreach p,$(sort $(2)),\
+    $$(if $$(filter UNUSED-%,$$(PACKAGES.$$(p).STEM)),,\
+      $$(if $$(PACKAGES.$$(p).APKCERTS_FILE),\
+        $$(call _apkcerts_merge,$$(PACKAGES.$$(p).APKCERTS_FILE), $$@),\
+        $$(if $$(PACKAGES.$$(p).EXTERNAL_KEY),\
+          $$(call _apkcerts_write_line,$$(PACKAGES.$$(p).STEM),EXTERNAL,,$$(PACKAGES.$$(p).COMPRESSED),$$(PACKAGES.$$(p).PARTITION),$$@),\
+          $$(call _apkcerts_write_line,$$(PACKAGES.$$(p).STEM),$$(PACKAGES.$$(p).CERTIFICATE),$$(PACKAGES.$$(p).PRIVATE_KEY),$$(PACKAGES.$$(p).COMPRESSED),$$(PACKAGES.$$(p).PARTITION),$$@)))))
+	touch $$@
+	sort -u -o $$@ $$@
+
+endef
+
 name := $(TARGET_PRODUCT)
 ifeq ($(TARGET_BUILD_TYPE),debug)
   name := $(name)_debug
@@ -775,26 +792,35 @@ name := $(name)-apkcerts
 intermediates := \
 	$(call intermediates-dir-for,PACKAGING,apkcerts)
 APKCERTS_FILE := $(intermediates)/$(name).txt
-ifeq ($(RELEASE_APKCERTS_INSTALL_ONLY), true)
-  all_apkcerts_packages := $(filter $(call product-installed-modules,$(INTERNAL_PRODUCT)),$(PACKAGES))
-else
-  all_apkcerts_packages := $(PACKAGES)
-endif
-all_apkcerts_files := $(sort $(foreach p,$(all_apkcerts_packages),$(PACKAGES.$(p).APKCERTS_FILE)))
 
-$(APKCERTS_FILE): $(all_apkcerts_files)
-# We don't need to really build all the modules.
-# TODO: rebuild APKCERTS_FILE if any app change its cert.
-$(APKCERTS_FILE):
+# remove duplicates
+PACKAGES := $(sort $(PACKAGES))
+
+make_apkcerts_packages := $(foreach p,$(PACKAGES),$(if $(ALL_MODULES.$(p).IS_SOONG_MODULE),,$(p)))
+make_apkcerts_file := $(intermediates)/$(name)-make.txt
+$(eval $(call _apkcerts_build_for_packages,$(make_apkcerts_file),$(make_apkcerts_packages)))
+
+soong_apkcerts_packages := $(foreach p,$(PACKAGES),$(if $(ALL_MODULES.$(p).IS_SOONG_MODULE),$(p)))
+soong_doublecheck_apkcerts_file := $(intermediates)/$(name)-soong-doublecheck.txt
+$(eval $(call _apkcerts_build_for_packages,$(soong_doublecheck_apkcerts_file),$(soong_apkcerts_packages)))
+
+soong_apkcerts_file_with_soong_and_make_modules_removed := $(intermediates)/$(name)-soong_apkcerts_file_with_soong_and_make_modules_removed.txt
+$(soong_apkcerts_file_with_soong_and_make_modules_removed): $(SOONG_APKCERTS_FILE)
+	rm -f $@ $@.tmp $@.tmp2
+	cp $(SOONG_APKCERTS_FILE) $@.tmp
+	$(foreach p,$(PACKAGES),$(if $(ALL_MODULES.$(p).IS_MAKE_AND_SOONG_MODULE),\
+		grep -v "^name=\"$(PACKAGES.$(p).STEM).apk\"" $@.tmp > $@.tmp2 && mv $@.tmp2 $@.tmp$(newline)))
+	mv $@.tmp $@
+
+soong_apkcerts_doublecheck_stamp := $(intermediates)/$(name)-soong-doublecheck-stamp.txt
+$(soong_apkcerts_doublecheck_stamp): $(soong_doublecheck_apkcerts_file) $(soong_apkcerts_file_with_soong_and_make_modules_removed)
+	rm -f $@ && diff -q $^ && touch $@
+
+$(APKCERTS_FILE): $(make_apkcerts_file) $(soong_apkcerts_file_with_soong_and_make_modules_removed) $(soong_apkcerts_doublecheck_stamp)
 	@echo APK certs list: $@
 	@mkdir -p $(dir $@)
 	@rm -f $@
-	$(foreach p,$(sort $(all_apkcerts_packages)),\
-	  $(if $(PACKAGES.$(p).APKCERTS_FILE),\
-	    $(call _apkcerts_merge,$(PACKAGES.$(p).APKCERTS_FILE), $@),\
-	    $(if $(PACKAGES.$(p).EXTERNAL_KEY),\
-	      $(call _apkcerts_write_line,$(PACKAGES.$(p).STEM),EXTERNAL,,$(PACKAGES.$(p).COMPRESSED),$(PACKAGES.$(p).PARTITION),$@),\
-	      $(call _apkcerts_write_line,$(PACKAGES.$(p).STEM),$(PACKAGES.$(p).CERTIFICATE),$(PACKAGES.$(p).PRIVATE_KEY),$(PACKAGES.$(p).COMPRESSED),$(PACKAGES.$(p).PARTITION),$@))))
+	cat $(make_apkcerts_file) $(soong_apkcerts_file_with_soong_and_make_modules_removed) > $@
 	$(if $(filter true,$(PRODUCT_FSVERITY_GENERATE_METADATA)),\
 	  $(call _apkcerts_write_line,BuildManifest,$(FSVERITY_APK_KEY_PATH).x509.pem,$(FSVERITY_APK_KEY_PATH).pk8,,system,$@) \
 	  $(if $(filter true,$(BUILDING_SYSTEM_EXT_IMAGE)),\
@@ -807,6 +833,9 @@ $(call declare-0p-target,$(APKCERTS_FILE))
 .PHONY: apkcerts-list
 apkcerts-list: $(APKCERTS_FILE)
 
+# In unbundled builds, apexkeys.txt is built by soong
+ifeq (,$(TARGET_BUILD_APPS))
+
 intermediates := $(call intermediates-dir-for,PACKAGING,apexkeys)
 APEX_KEYS_FILE := $(intermediates)/apexkeys.txt
 
@@ -823,10 +852,7 @@ $(call declare-0p-target,$(APEX_KEYS_FILE))
 .PHONY: apexkeys.txt
 apexkeys.txt: $(APEX_KEYS_FILE)
 
-ifneq (,$(TARGET_BUILD_APPS))
-  $(call dist-for-goals, apps_only, $(APKCERTS_FILE):apkcerts.txt)
-  $(call dist-for-goals, apps_only, $(APEX_KEYS_FILE):apexkeys.txt)
-endif
+endif # ifeq (,$(TARGET_BUILD_APPS))
 
 
 # -----------------------------------------------------------------
@@ -1231,6 +1257,12 @@ endif
 
 INTERNAL_PREBUILT_BOOTIMAGE :=
 
+# Split lunches (especially the system side lunch) can have init_boot enabled without the kernel,
+# handle that case and continue to pass the OS-version/patch-level values into the init_boot.img.
+INTERNAL_MKBOOTIMG_VERSION_ARGS := \
+  --os_version $(PLATFORM_VERSION_LAST_STABLE) \
+  --os_patch_level $(PLATFORM_SECURITY_PATCH)
+
 my_installed_prebuilt_gki_apex := $(strip $(foreach package,$(PRODUCT_PACKAGES),$(if $(ALL_MODULES.$(package).EXTRACTED_BOOT_IMAGE),$(package))))
 ifdef my_installed_prebuilt_gki_apex
   ifneq (1,$(words $(my_installed_prebuilt_gki_apex))) # len(my_installed_prebuilt_gki_apex) > 1
@@ -1328,10 +1360,6 @@ else ifndef BUILDING_VENDOR_BOOT_IMAGE # && BOARD_USES_GENERIC_KERNEL_IMAGE != t
   endif
 endif # BUILDING_VENDOR_BOOT_IMAGE == "" && BOARD_USES_GENERIC_KERNEL_IMAGE != true
 
-INTERNAL_MKBOOTIMG_VERSION_ARGS := \
-  --os_version $(PLATFORM_VERSION_LAST_STABLE) \
-  --os_patch_level $(PLATFORM_SECURITY_PATCH)
-
 # Define these only if we are building boot
 ifdef BUILDING_BOOT_IMAGE
 INSTALLED_BOOTIMAGE_TARGET := $(BUILT_BOOTIMAGE_TARGET)
@@ -1541,8 +1569,14 @@ $(INSTALLED_INIT_BOOT_IMAGE_TARGET): $(MKBOOTIMG) $(INSTALLED_RAMDISK_TARGET)
 
 INTERNAL_INIT_BOOT_IMAGE_ARGS := --ramdisk $(INSTALLED_RAMDISK_TARGET)
 
-ifdef BOARD_KERNEL_PAGESIZE
-  INTERNAL_INIT_BOOT_IMAGE_ARGS += --pagesize $(BOARD_KERNEL_PAGESIZE)
+ifdef BOARD_INIT_BOOT_IMAGE_PAGESIZE
+	INTERNAL_INIT_BOOT_IMAGE_PAGESIZE := $(BOARD_INIT_BOOT_IMAGE_PAGESIZE)
+else ifdef BOARD_KERNEL_PAGESIZE
+	INTERNAL_INIT_BOOT_IMAGE_PAGESIZE := $(BOARD_KERNEL_PAGESIZE)
+endif
+
+ifdef INTERNAL_INIT_BOOT_IMAGE_PAGESIZE
+  INTERNAL_INIT_BOOT_IMAGE_ARGS += --pagesize $(INTERNAL_INIT_BOOT_IMAGE_PAGESIZE)
 endif
 
 ifeq ($(BOARD_AVB_ENABLE),true)
@@ -1918,36 +1952,49 @@ kernel_notice_file := $(TARGET_OUT_NOTICE_FILES)/src/kernel.txt
 exclude_target_dirs := apex
 
 # target_notice_file_xml := $(TARGET_OUT_INTERMEDIATES)/NOTICE.xml
-target_notice_file_xml_gz := $(TARGET_OUT_INTERMEDIATES)/NOTICE.xml.gz
-installed_notice_html_or_xml_gz := $(TARGET_OUT)/etc/NOTICE.xml.gz
 
 target_vendor_notice_file_txt := $(TARGET_OUT_INTERMEDIATES)/NOTICE_VENDOR.txt
 target_vendor_notice_file_xml_gz := $(TARGET_OUT_INTERMEDIATES)/NOTICE_VENDOR.xml.gz
-installed_vendor_notice_xml_gz := $(TARGET_OUT_VENDOR)/etc/NOTICE.xml.gz
 
 target_product_notice_file_txt := $(TARGET_OUT_INTERMEDIATES)/NOTICE_PRODUCT.txt
 target_product_notice_file_xml_gz := $(TARGET_OUT_INTERMEDIATES)/NOTICE_PRODUCT.xml.gz
-installed_product_notice_xml_gz := $(TARGET_OUT_PRODUCT)/etc/NOTICE.xml.gz
 
 target_system_ext_notice_file_txt := $(TARGET_OUT_INTERMEDIATES)/NOTICE_SYSTEM_EXT.txt
 target_system_ext_notice_file_xml_gz := $(TARGET_OUT_INTERMEDIATES)/NOTICE_SYSTEM_EXT.xml.gz
-installed_system_ext_notice_xml_gz := $(TARGET_OUT_SYSTEM_EXT)/etc/NOTICE.xml.gz
 
 target_odm_notice_file_txt := $(TARGET_OUT_INTERMEDIATES)/NOTICE_ODM.txt
 target_odm_notice_file_xml_gz := $(TARGET_OUT_INTERMEDIATES)/NOTICE_ODM.xml.gz
-installed_odm_notice_xml_gz := $(TARGET_OUT_ODM)/etc/NOTICE.xml.gz
 
 target_vendor_dlkm_notice_file_txt := $(TARGET_OUT_INTERMEDIATES)/NOTICE_VENDOR_DLKM.txt
 target_vendor_dlkm_notice_file_xml_gz := $(TARGET_OUT_INTERMEDIATES)/NOTICE_VENDOR_DLKM.xml.gz
-installed_vendor_dlkm_notice_xml_gz := $(TARGET_OUT_VENDOR_DLKM)/etc/NOTICE.xml.gz
 
 target_odm_dlkm_notice_file_txt := $(TARGET_OUT_INTERMEDIATES)/NOTICE_ODM_DLKM.txt
 target_odm_dlkm_notice_file_xml_gz := $(TARGET_OUT_INTERMEDIATES)/NOTICE_ODM_DLKM.xml.gz
-installed_odm_dlkm_notice_xml_gz := $(TARGET_OUT_ODM_DLKM)/etc/NOTICE.xml.gz
 
 target_system_dlkm_notice_file_txt := $(TARGET_OUT_INTERMEDIATES)/NOTICE_SYSTEM_DLKM.txt
 target_system_dlkm_notice_file_xml_gz := $(TARGET_OUT_INTERMEDIATES)/NOTICE_SYSTEM_DLKM.xml.gz
-installed_system_dlkm_notice_xml_gz := $(TARGET_OUT_SYSTEM_DLKM)/etc/NOTICE.xml.gz
+
+ifeq (,$(DISABLE_NOTICE_XML_GENERATION))
+  target_notice_file_xml_gz := $(TARGET_OUT_INTERMEDIATES)/NOTICE.xml.gz
+  installed_notice_html_or_xml_gz := $(TARGET_OUT)/etc/NOTICE.xml.gz
+  installed_vendor_notice_xml_gz := $(TARGET_OUT_VENDOR)/etc/NOTICE.xml.gz
+  installed_product_notice_xml_gz := $(TARGET_OUT_PRODUCT)/etc/NOTICE.xml.gz
+  installed_system_ext_notice_xml_gz := $(TARGET_OUT_SYSTEM_EXT)/etc/NOTICE.xml.gz
+  installed_odm_notice_xml_gz := $(TARGET_OUT_ODM)/etc/NOTICE.xml.gz
+  installed_vendor_dlkm_notice_xml_gz := $(TARGET_OUT_VENDOR_DLKM)/etc/NOTICE.xml.gz
+  installed_odm_dlkm_notice_xml_gz := $(TARGET_OUT_ODM_DLKM)/etc/NOTICE.xml.gz
+  installed_system_dlkm_notice_xml_gz := $(TARGET_OUT_SYSTEM_DLKM)/etc/NOTICE.xml.gz
+else
+  target_notice_file_xml_gz :=
+  installed_notice_html_or_xml_gz :=
+  installed_vendor_notice_xml_gz :=
+  installed_product_notice_xml_gz :=
+  installed_system_ext_notice_xml_gz :=
+  installed_odm_notice_xml_gz :=
+  installed_vendor_dlkm_notice_xml_gz :=
+  installed_odm_dlkm_notice_xml_gz :=
+  installed_system_dlkm_notice_xml_gz :=
+endif
 
 ALL_INSTALLED_NOTICE_FILES := \
   $(installed_notice_html_or_xml_gz) \
@@ -2305,9 +2352,10 @@ $(if $(BOARD_AVB_ENABLE), \
   $(if $(filter $(2),system_other), \
     $(hide) echo "avb_system_other_hashtree_enable=$(BOARD_AVB_ENABLE)" >> $(1)$(newline) \
     $(hide) echo "avb_system_other_add_hashtree_footer_args=$(BOARD_AVB_SYSTEM_OTHER_ADD_HASHTREE_FOOTER_ARGS)" >> $(1)$(newline) \
-    $(if $(BOARD_AVB_SYSTEM_OTHER_KEY_PATH),\
-      $(hide) echo "avb_system_other_key_path=$(BOARD_AVB_SYSTEM_OTHER_KEY_PATH)" >> $(1)$(newline) \
-      $(hide) echo "avb_system_other_algorithm=$(BOARD_AVB_SYSTEM_OTHER_ALGORITHM)" >> $(1)$(newline))) \
+    $(if $(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE_AVB_KEY_PATH)$(BOARD_AVB_SYSTEM_KEY_PATH),\
+      $(hide) echo "avb_system_other_key_path=$(firstword $(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE_AVB_KEY_PATH) $(BOARD_AVB_SYSTEM_KEY_PATH))" >> $(1)$(newline)) \
+    $(if $(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE_AVB_ALGORITHM)$(BOARD_AVB_SYSTEM_ALGORITHM),\
+      $(hide) echo "avb_system_other_algorithm=$(firstword $(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE_AVB_ALGORITHM) $(BOARD_AVB_SYSTEM_ALGORITHM))" >> $(1)$(newline))) \
   $(if $(filter $(2),vendor), \
     $(hide) echo "avb_vendor_hashtree_enable=$(BOARD_AVB_ENABLE)" >> $(1)$(newline) \
     $(hide) echo "avb_vendor_add_hashtree_footer_args=$(BOARD_AVB_VENDOR_ADD_HASHTREE_FOOTER_ARGS)" >> $(1)$(newline) \
@@ -3400,6 +3448,118 @@ endif
 endif  # PRODUCT_FSVERITY_GENERATE_METADATA
 
 
+# Treble Labeling Test
+platform-preinstalled-apps-patterns := \
+  $(TARGET_OUT)/priv-app/%.apk \
+  $(TARGET_OUT)/app/%.apk \
+
+ifdef BUILDING_SYSTEM_EXT_IMAGE
+platform-preinstalled-apps-patterns += \
+  $(TARGET_OUT_SYSTEM_EXT)/priv-app/%.apk \
+  $(TARGET_OUT_SYSTEM_EXT)/app/%.apk \
+
+endif
+
+ifdef BUILDING_PRODUCT_IMAGE
+platform-preinstalled-apps-patterns += \
+  $(TARGET_OUT_PRODUCT)/priv-app/%.apk \
+  $(TARGET_OUT_PRODUCT)/app/%.apk \
+
+endif
+
+platform-preinstalled-apps := $(sort $(filter \
+  $(platform-preinstalled-apps-patterns), \
+  $(ALL_DEFAULT_INSTALLED_MODULES)))
+
+
+vendor-preinstalled-apps-patterns := \
+  $(TARGET_OUT_VENDOR)/priv-app/%.apk \
+  $(TARGET_OUT_VENDOR)/app/%.apk \
+
+ifdef BUILDING_ODM_IMAGE
+vendor-preinstalled-apps-patterns += \
+  $(TARGET_OUT_ODM)/priv-app/%.apk \
+  $(TARGET_OUT_ODM)/app/%.apk \
+
+endif
+
+vendor-preinstalled-apps := $(sort $(filter \
+  $(vendor-preinstalled-apps-patterns), \
+  $(ALL_DEFAULT_INSTALLED_MODULES)))
+
+sepolicy-binary-without-vendor := $(call intermediates-dir-for,ETC,precompiled_sepolicy_without_vendor)/precompiled_sepolicy_without_vendor
+sepolicy-binary := $(call intermediates-dir-for,ETC,precompiled_sepolicy)/precompiled_sepolicy
+
+platform-seapp-contexts := $(call intermediates-dir-for,ETC,plat_seapp_contexts)/plat_seapp_contexts
+
+ifdef BUILDING_SYSTEM_EXT_IMAGE
+platform-seapp-contexts += $(call intermediates-dir-for,ETC,system_ext_seapp_contexts)/system_ext_seapp_contexts
+endif
+
+ifdef BUILDING_PRODUCT_IMAGE
+platform-seapp-contexts += $(call intermediates-dir-for,ETC,product_seapp_contexts)/product_seapp_contexts
+endif
+
+vendor-seapp-contexts := $(call intermediates-dir-for,ETC,vendor_seapp_contexts)/vendor_seapp_contexts
+
+ifdef BUILDING_ODM_IMAGE
+vendor-seapp-contexts += $(call intermediates-dir-for,ETC,odm_seapp_contexts)/odm_seapp_contexts
+endif
+
+vendor-file-contexts := $(call intermediates-dir-for,ETC,vendor_file_contexts)/vendor_file_contexts
+
+ifdef BUILDING_ODM_IMAGE
+vendor-file-contexts += $(call intermediates-dir-for,ETC,odm_file_contexts)/odm_file_contexts
+endif
+
+check-selinux-treble-labeling.timestamp := $(call intermediates-dir-for,PACKAGING,check-selinux-treble-labeling)/check-selinux-treble-labeling.timestamp
+
+$(check-selinux-treble-labeling.timestamp): PRIVATE_PLATFORM_APPS := $(platform-preinstalled-apps)
+$(check-selinux-treble-labeling.timestamp): PRIVATE_VENDOR_APPS := $(vendor-preinstalled-apps)
+$(check-selinux-treble-labeling.timestamp): PRIVATE_SEPOLICY_WITHOUT_VENDOR := $(sepolicy-binary-without-vendor)
+$(check-selinux-treble-labeling.timestamp): PRIVATE_SEPOLICY := $(sepolicy-binary)
+$(check-selinux-treble-labeling.timestamp): PRIVATE_PLATFORM_SEAPP_CONTEXTS := $(platform-seapp-contexts)
+$(check-selinux-treble-labeling.timestamp): PRIVATE_VENDOR_SEAPP_CONTEXTS := $(vendor-seapp-contexts)
+$(check-selinux-treble-labeling.timestamp): PRIVATE_VENDOR_FILE_CONTEXTS := $(vendor-file-contexts)
+$(check-selinux-treble-labeling.timestamp): PRIVATE_TRACKING_LIST_FILE := $(PRODUCT_SELINUX_TREBLE_LABELING_TRACKING_LIST_FILE)
+$(check-selinux-treble-labeling.timestamp): PRIVATE_TREAT_AS_WARNINGS := $(if $(filter true,$(PRODUCT_ENFORCE_SELINUX_TREBLE_LABELING)),,--treat_as_warnings)
+$(check-selinux-treble-labeling.timestamp): PRIVATE_DEBUGGABLE := $(if $(filter user,$(TARGET_BUILD_VARIANT)),,--debuggable)
+$(check-selinux-treble-labeling.timestamp): $(HOST_OUT_EXECUTABLES)/treble_labeling_tests \
+    $(platform-preinstalled-apps) $(vendor-preinstalled-apps) \
+    $(platform-sepolicy-binary) $(sepolicy-binary) $(sepolicy-binary-without-vendor) \
+    $(platform-seapp-contexts) $(vendor-seapp-contexts) $(vendor-file-contexts) \
+    $(PRODUCT_SELINUX_TREBLE_LABELING_TRACKING_LIST_FILE) $(AAPT2)
+	@rm -rf $@
+	@echo $(PRIVATE_PLATFORM_APPS) > $@.platform_apps.txt
+	@echo $(PRIVATE_VENDOR_APPS) > $@.vendor_apps.txt
+	$(hide) $< --platform_apks $@.platform_apps.txt --vendor_apks $@.vendor_apps.txt \
+    --precompiled_sepolicy_without_vendor $(PRIVATE_SEPOLICY_WITHOUT_VENDOR) \
+    --precompiled_sepolicy $(PRIVATE_SEPOLICY) \
+    --platform_seapp_contexts $(PRIVATE_PLATFORM_SEAPP_CONTEXTS) \
+    --vendor_seapp_contexts $(PRIVATE_VENDOR_SEAPP_CONTEXTS) \
+    --vendor_file_contexts $(PRIVATE_VENDOR_FILE_CONTEXTS) \
+    $(if $(PRIVATE_TRACKING_LIST_FILE),--tracking_list_file $(PRIVATE_TRACKING_LIST_FILE)) \
+    $(PRIVATE_TREAT_AS_WARNINGS) $(PRIVATE_DEBUGGABLE) \
+    --aapt2_path $(AAPT2) > $@
+
+.PHONY: check-selinux-treble-labeling
+check-selinux-treble-labeling: $(check-selinux-treble-labeling.timestamp)
+
+# Treble Labeling tests only for 202604 or later
+ifeq ($(call math_gt_or_eq,$(PLATFORM_SEPOLICY_VERSION),202604),true)
+droidcore: check-selinux-treble-labeling
+endif
+
+platform-preinstalled-apps-patterns :=
+platform-preinstalled-apps :=
+vendor-preinstalled-apps-patterns :=
+vendor-preinstalled-apps :=
+check-selinux-treble-labeling.timestamp :=
+platform-sepolicy-binary :=
+sepolicy-binary :=
+platform-seapp-contexts :=
+vendor-seapp-contexts :=
+
 # -----------------------------------------------------------------
 # system image
 
@@ -3529,6 +3689,10 @@ $(eval $(call write-partition-file-list,$(systemimage_intermediates)/file_list.t
 ifneq ($(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE),)
 file_list_diff := $(HOST_OUT_EXECUTABLES)/file_list_diff$(HOST_EXECUTABLE_SUFFIX)
 system_file_diff_timestamp := $(systemimage_intermediates)/file_diff.timestamp
+# Override system's avb_key with the avb_key of the soong defined system image.
+# This will be used as the avb_key to sign system_other.img
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE_AVB_KEY_PATH := $(ALL_MODULES.$(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE).FILESYSTEM_AVB_KEY_PATH)
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE_AVB_ALGORITHM := $(ALL_MODULES.$(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE).FILESYSTEM_AVB_ALGORITHM)
 
 # The build configuration to build the REL version may have more files to allow.
 # Use allowlist_next in addition to the allowlist in this case.
@@ -3793,13 +3957,6 @@ $(INSTALLED_FILES_FILE_SYSTEMOTHER) : $(INTERNAL_SYSTEMOTHERIMAGE_FILES) $(FILES
 $(eval $(call declare-0p-target,$(INSTALLED_FILES_FILE_SYSTEMOTHER)))
 $(eval $(call declare-0p-target,$(INSTALLED_FILES_JSON_SYSTEMOTHER)))
 
-# Determines partition size for system_other.img.
-ifeq ($(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS),true)
-ifneq ($(filter system,$(BOARD_SUPER_PARTITION_BLOCK_DEVICES)),)
-INTERNAL_SYSTEM_OTHER_PARTITION_SIZE := $(BOARD_SUPER_PARTITION_SYSTEM_DEVICE_SIZE)
-endif
-endif
-
 ifndef INTERNAL_SYSTEM_OTHER_PARTITION_SIZE
 INTERNAL_SYSTEM_OTHER_PARTITION_SIZE:= $(BOARD_SYSTEMIMAGE_PARTITION_SIZE)
 endif
@@ -5346,7 +5503,7 @@ $(BUILT_KERNEL_VERSION_FILE): $(EXTRACT_KERNEL) $(firstword $(INSTALLED_KERNEL_T
 	  --output-release` ;\
   if [ "$$KERNEL_RELEASE" != '$(BOARD_KERNEL_VERSION)' ]; then \
     echo "Specified kernel version '$(BOARD_KERNEL_VERSION)' does not match actual kernel version '$$KERNEL_RELEASE' " ; exit 1; fi;
-	echo '$(BOARD_KERNEL_VERSION)' > $@
+	echo -n '$(BOARD_KERNEL_VERSION)' > $@
 
 $(call declare-license-metadata,$(BUILT_KERNEL_VERSION_FILE),SPDX-license-identifier-GPL-2.0-only,restricted,$(BUILD_SYSTEM)/LINUX_KERNEL_COPYING,"Kernel",kernel)
 
@@ -5743,64 +5900,6 @@ INTERNAL_OTATOOLS_FILES := \
 .PHONY: otatools
 otatools: $(INTERNAL_OTATOOLS_FILES)
 
-# For each module, recursively resolve its host shared library dependencies. Then we have a full
-# list of modules whose installed files need to be packed.
-INTERNAL_OTATOOLS_MODULES_WITH_DEPS := \
-  $(sort $(INTERNAL_OTATOOLS_MODULES) \
-      $(foreach m,$(INTERNAL_OTATOOLS_MODULES),$(call get-all-shared-libs-deps,$(m))))
-
-INTERNAL_OTATOOLS_PACKAGE_FILES := \
-  $(filter $(HOST_OUT)/%,$(call module-installed-files,$(INTERNAL_OTATOOLS_MODULES_WITH_DEPS)))
-
-INTERNAL_OTATOOLS_PACKAGE_FILES += \
-  $(sort $(shell find build/make/target/product/security -type f -name "*.x509.pem" -o \
-      -name "*.pk8"))
-
-ifneq (,$(wildcard packages/modules))
-INTERNAL_OTATOOLS_PACKAGE_FILES += \
-  $(sort $(shell find packages/modules -type f -name "*.x509.pem" -o -name "*.pk8" -o -name \
-      "key.pem"))
-endif
-
-ifneq (,$(wildcard device))
-INTERNAL_OTATOOLS_PACKAGE_FILES += \
-  $(sort $(shell find device $(wildcard vendor) -type f -name "*.pk8" -o -name "verifiedboot*" -o \
-      -name "*.pem" -o -name "oem*.prop" -o -name "*.avbpubkey"))
-endif
-ifneq (,$(wildcard external/avb))
-INTERNAL_OTATOOLS_PACKAGE_FILES += \
-  $(sort $(shell find external/avb/test/data -type f -name "testkey_*.pem" -o \
-      -name "atx_metadata.bin"))
-endif
-
-INTERNAL_OTATOOLS_RELEASETOOLS := \
-  $(shell find build/make/tools/releasetools -name "*.pyc" -prune -o \
-      \( -type f -o -type l \) -print | sort)
-
-BUILT_OTATOOLS_PACKAGE := $(PRODUCT_OUT)/otatools.zip
-$(BUILT_OTATOOLS_PACKAGE): PRIVATE_ZIP_ROOT := $(call intermediates-dir-for,PACKAGING,otatools)/otatools
-$(BUILT_OTATOOLS_PACKAGE): PRIVATE_OTATOOLS_PACKAGE_FILES := $(INTERNAL_OTATOOLS_PACKAGE_FILES)
-$(BUILT_OTATOOLS_PACKAGE): PRIVATE_OTATOOLS_RELEASETOOLS := $(INTERNAL_OTATOOLS_RELEASETOOLS)
-$(BUILT_OTATOOLS_PACKAGE): $(INTERNAL_OTATOOLS_PACKAGE_FILES) $(INTERNAL_OTATOOLS_RELEASETOOLS)
-$(BUILT_OTATOOLS_PACKAGE): $(SOONG_ZIP) $(ZIP2ZIP)
-	@echo "Package OTA tools: $@"
-	rm -rf $@ $(PRIVATE_ZIP_ROOT)
-	mkdir -p $(dir $@)
-	$(call copy-files-with-structure,$(PRIVATE_OTATOOLS_PACKAGE_FILES),$(HOST_OUT)/,$(PRIVATE_ZIP_ROOT))
-	$(call copy-files-with-structure,$(PRIVATE_OTATOOLS_RELEASETOOLS),build/make/tools/,$(PRIVATE_ZIP_ROOT))
-	cp $(SOONG_ZIP) $(ZIP2ZIP) $(MERGE_ZIPS) $(PRIVATE_ZIP_ROOT)/bin/
-	$(SOONG_ZIP) -o $@ -C $(PRIVATE_ZIP_ROOT) -D $(PRIVATE_ZIP_ROOT)
-
-$(call declare-1p-container,$(BUILT_OTATOOLS_PACKAGE),build)
-$(call declare-container-license-deps,$(INTERNAL_OTATOOLS_PACKAGE_FILES) $(INTERNAL_OTATOOLS_RELEASETOOLS),$(BUILT_OTATOOLS_PACKAGE):)
-
-.PHONY: otatools-package
-otatools-package: $(BUILT_OTATOOLS_PACKAGE)
-
-$(call dist-for-goals, otatools-package, \
-  $(BUILT_OTATOOLS_PACKAGE) \
-)
-
 endif # build_otatools_package
 
 # -----------------------------------------------------------------
@@ -6262,15 +6361,11 @@ endef
 define dump-dynamic-partitions-info
   $(if $(filter true,$(PRODUCT_USE_DYNAMIC_PARTITIONS)), \
     echo "use_dynamic_partitions=true" >> $(1))
-  $(if $(filter true,$(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS)), \
-    echo "dynamic_partition_retrofit=true" >> $(1))
   echo "lpmake=$(notdir $(LPMAKE))" >> $(1)
   $(if $(filter true,$(PRODUCT_BUILD_SUPER_PARTITION)), $(if $(BOARD_SUPER_PARTITION_SIZE), \
     echo "build_super_partition=true" >> $(1)))
   $(if $(BUILDING_SUPER_EMPTY_IMAGE), \
     echo "build_super_empty_partition=true" >> $(1))
-  $(if $(filter true,$(BOARD_BUILD_RETROFIT_DYNAMIC_PARTITIONS_OTA_PACKAGE)), \
-    echo "build_retrofit_dynamic_partitions_ota_package=true" >> $(1))
   echo "super_metadata_device=$(BOARD_SUPER_PARTITION_METADATA_DEVICE)" >> $(1)
   $(if $(BOARD_SUPER_PARTITION_BLOCK_DEVICES), \
     echo "super_block_devices=$(BOARD_SUPER_PARTITION_BLOCK_DEVICES)" >> $(1))
@@ -6307,8 +6402,6 @@ define dump-dynamic-partitions-info
 # e.g. "none", "gz", "brotli"
   $(if $(PRODUCT_VIRTUAL_AB_COMPRESSION_METHOD), \
     echo "virtual_ab_compression_method=$(PRODUCT_VIRTUAL_AB_COMPRESSION_METHOD)" >> $(1))
-  $(if $(filter true,$(PRODUCT_VIRTUAL_AB_OTA_RETROFIT)), \
-    echo "virtual_ab_retrofit=true" >> $(1))
   $(if $(PRODUCT_VIRTUAL_AB_COW_VERSION), \
     echo "virtual_ab_cow_version=$(PRODUCT_VIRTUAL_AB_COW_VERSION)" >> $(1))
   $(if $(PRODUCT_VIRTUAL_AB_COMPRESSION_FACTOR), \
@@ -6371,6 +6464,8 @@ ifdef BUILDING_VENDOR_BOOT_IMAGE
   ifeq (true,$(BOARD_MOVE_RECOVERY_RESOURCES_TO_VENDOR_BOOT))
     $(BUILT_TARGET_FILES_DIR): $(INTERNAL_RECOVERY_RAMDISK_FILES_TIMESTAMP)
   endif
+else ifdef BOARD_PREBUILT_VENDOR_BOOTIMAGE
+  $(BUILT_TARGET_FILES_DIR): $(INSTALLED_VENDOR_BOOTIMAGE_TARGET)
 endif
 
 ifdef BUILDING_VENDOR_KERNEL_BOOT_IMAGE
@@ -6466,7 +6561,7 @@ else ifdef BOARD_PREBUILT_SYSTEM_DLKMIMAGE
 endif
 
 ifeq ($(BUILD_QEMU_IMAGES),true)
-  MK_VBMETA_BOOT_KERNEL_CMDLINE_SH := device/generic/goldfish/tools/mk_vbmeta_boot_params.sh
+  MK_VBMETA_BOOT_KERNEL_CMDLINE_SH := device/generic/goldfish/build/tools/mk_vbmeta_boot_params.sh
   $(BUILT_TARGET_FILES_DIR): $(MK_VBMETA_BOOT_KERNEL_CMDLINE_SH)
 endif
 
@@ -6793,10 +6888,6 @@ ifdef OSRELEASED_DIRECTORY
 	$(hide) cp $(TARGET_OUT_ETC)/$(OSRELEASED_DIRECTORY)/system_version $(zip_root)/META/system_version.txt
 endif
 endif
-ifeq ($(BREAKPAD_GENERATE_SYMBOLS),true)
-	@# If breakpad symbols have been generated, add them to the zip.
-	$(hide) cp -R $(TARGET_OUT_BREAKPAD) $(zip_root)/BREAKPAD
-endif
 ifdef BOARD_PREBUILT_VENDOR_BOOTIMAGE
 	$(hide) mkdir -p $(zip_root)/IMAGES
 	$(hide) cp $(INSTALLED_VENDOR_BOOTIMAGE_TARGET) $(zip_root)/IMAGES/
@@ -7093,27 +7184,6 @@ $(call declare-container-license-deps,$(INTERNAL_OTA_PACKAGE_TARGET),$(BUILT_TAR
 .PHONY: otapackage
 otapackage: $(INTERNAL_OTA_PACKAGE_TARGET)
 
-ifeq ($(BOARD_BUILD_RETROFIT_DYNAMIC_PARTITIONS_OTA_PACKAGE),true)
-name := $(product_name)-ota-retrofit
-
-INTERNAL_OTA_RETROFIT_DYNAMIC_PARTITIONS_PACKAGE_TARGET := $(PRODUCT_OUT)/$(name).zip
-$(INTERNAL_OTA_RETROFIT_DYNAMIC_PARTITIONS_PACKAGE_TARGET): KEY_CERT_PAIR := $(DEFAULT_KEY_CERT_PAIR)
-$(INTERNAL_OTA_RETROFIT_DYNAMIC_PARTITIONS_PACKAGE_TARGET): \
-    $(BUILT_TARGET_FILES_PACKAGE) \
-    $(OTA_FROM_TARGET_FILES) \
-    $(INTERNAL_OTATOOLS_FILES)
-	@echo "Package OTA (retrofit dynamic partitions): $@"
-	$(call build-ota-package-target,$@,-k $(KEY_CERT_PAIR) --retrofit_dynamic_partitions)
-
-$(call declare-1p-container,$(INTERNAL_OTA_RETROFIT_DYNAMIC_PARTITIONS_PACKAGE_TARGET),)
-$(call declare-container-license-deps,$(INTERNAL_OTA_RETROFIT_DYNAMIC_PARTITIONS_PACKAGE_TARGET),$(BUILT_TARGET_FILES_PACKAGE) $(OTA_FROM_TARGET_FILES) $(INTERNAL_OTATOOLS_FILES),$(PRODUCT_OUT)/:/)
-
-.PHONY: otardppackage
-
-otapackage otardppackage: $(INTERNAL_OTA_RETROFIT_DYNAMIC_PARTITIONS_PACKAGE_TARGET)
-
-endif # BOARD_BUILD_RETROFIT_DYNAMIC_PARTITIONS_OTA_PACKAGE
-
 ifneq ($(BOARD_PARTIAL_OTA_UPDATE_PARTITIONS_LIST),)
 name := $(product_name)-partial-ota
 
@@ -7200,6 +7270,9 @@ $(foreach suite,$(ALL_COMPATIBILITY_SUITES),$(eval $(call create-suite-symbols-m
 # a stack trace frame.
 #
 
+# The symbols.zip for unbundled builds is built with soong
+ifeq (,$(TARGET_BUILD_UNBUNDLED))
+
 name := $(TARGET_PRODUCT)
 ifeq ($(TARGET_BUILD_TYPE),debug)
   name := $(name)_debug
@@ -7211,16 +7284,19 @@ SYMBOLS_ZIP := $(PRODUCT_OUT)/$(name)-symbols.zip
 SYMBOLS_MAPPING := $(PRODUCT_OUT)/$(name)-symbols-mapping.textproto
 .KATI_READONLY := SYMBOLS_ZIP SYMBOLS_MAPPING
 
-ifeq (,$(TARGET_BUILD_UNBUNDLED))
-  _symbols_zip_modules := $(call product-installed-modules,$(INTERNAL_PRODUCT))
-  $(SYMBOLS_ZIP): $(updater_dep)
-else
-  _symbols_zip_modules := $(unbundled_build_modules)
-endif
+_symbols_zip_modules := $(call product-installed-modules,$(INTERNAL_PRODUCT))
 
 _symbols_zip_modules_symbols_files := $(foreach m,$(_symbols_zip_modules),$(ALL_MODULES.$(m).SYMBOLIC_OUTPUT_PATH))
 _symbols_zip_modules_mapping_files := $(foreach m,$(_symbols_zip_modules),$(ALL_MODULES.$(m).ELF_SYMBOL_MAPPING_PATH))
 
+.PHONY: symbols-files
+symbols-files: $(_symbols_zip_modules_symbols_files)
+droidcore-unbundled: symbols-files
+
+.PHONY: symbols-mappings
+symbols-mappings: $(_symbols_zip_modules_mapping_files)
+droidcore-unbundled: symbols-mappings
+
 $(SYMBOLS_ZIP): PRIVATE_SYMBOLS_MODULES_FILES := $(_symbols_zip_modules_symbols_files)
 $(SYMBOLS_ZIP): PRIVATE_SYMBOLS_MODULES_MAPPING_FILES := $(_symbols_zip_modules_mapping_files)
 $(SYMBOLS_ZIP): $(SOONG_ZIP) $(SYMBOLS_MAP) $(_symbols_zip_modules_symbols_files) $(_symbols_zip_modules_mapping_files)
@@ -7235,86 +7311,44 @@ $(SYMBOLS_ZIP): $(SOONG_ZIP) $(SYMBOLS_MAP) $(_symbols_zip_modules_symbols_files
 $(SYMBOLS_ZIP): .KATI_IMPLICIT_OUTPUTS := $(SYMBOLS_MAPPING)
 
 $(call declare-1p-container,$(SYMBOLS_ZIP),)
-ifeq (,$(TARGET_BUILD_UNBUNDLED))
-$(call declare-container-license-deps,$(SYMBOLS_ZIP),$(PRIVATE_SYMBOLS_MODULES_FILES) $(updater_dep),$(PRODUCT_OUT)/:/)
-endif
+$(call declare-container-license-deps,$(SYMBOLS_ZIP),$(PRIVATE_SYMBOLS_MODULES_FILES),$(PRODUCT_OUT)/:/)
 
 _symbols_zip_modules_symbols_files :=
 _symbols_zip_modules_mapping_files :=
-# -----------------------------------------------------------------
-# A zip of the coverage directory.
-#
-name := gcov-report-files-all
-ifeq ($(TARGET_BUILD_TYPE),debug)
-name := $(name)_debug
-endif
-COVERAGE_ZIP := $(PRODUCT_OUT)/$(name).zip
-ifeq (,$(TARGET_BUILD_UNBUNDLED))
-$(COVERAGE_ZIP): $(INTERNAL_ALLIMAGES_FILES)
-endif
-$(COVERAGE_ZIP): PRIVATE_LIST_FILE := $(call intermediates-dir-for,PACKAGING,coverage)/filelist
-$(COVERAGE_ZIP): $(SOONG_ZIP)
-	@echo "Package coverage: $@"
-	$(hide) rm -rf $@ $(PRIVATE_LIST_FILE)
-	$(hide) mkdir -p $(dir $@) $(TARGET_OUT_COVERAGE) $(dir $(PRIVATE_LIST_FILE))
-	$(hide) find $(TARGET_OUT_COVERAGE) | sort >$(PRIVATE_LIST_FILE)
-	$(hide) $(SOONG_ZIP) -d -o $@ -C $(TARGET_OUT_COVERAGE) -l $(PRIVATE_LIST_FILE)
-
-$(call declare-1p-container,$(COVERAGE_ZIP),)
-ifeq (,$(TARGET_BUILD_UNBUNDLED))
-$(call declare-container-license-deps,$(COVERAGE_ZIP),$(INTERNAL_ALLIMAGE_FILES),$(PRODUCT_OUT)/:/)
-endif
 
-SYSTEM_NOTICE_DEPS += $(COVERAGE_ZIP)
+endif # ifeq (,$(TARGET_BUILD_UNBUNDLED))
 
-#------------------------------------------------------------------
-# Export the LLVM profile data tool and dependencies for Clang coverage processing
-#
-ifeq (true,$(CLANG_COVERAGE))
-  LLVM_PROFDATA := $(LLVM_PREBUILTS_BASE)/linux-x86/$(LLVM_PREBUILTS_VERSION)/bin/llvm-profdata
-  LLVM_COV := $(LLVM_PREBUILTS_BASE)/linux-x86/$(LLVM_PREBUILTS_VERSION)/bin/llvm-cov
-  LIBCXX := $(LLVM_PREBUILTS_BASE)/linux-x86/$(LLVM_PREBUILTS_VERSION)/lib/x86_64-unknown-linux-gnu/libc++.so
-  # Use llvm-profdata.zip for backwards compatibility with tradefed code.
-  LLVM_COVERAGE_TOOLS_ZIP := $(PRODUCT_OUT)/llvm-profdata.zip
-
-  $(LLVM_COVERAGE_TOOLS_ZIP): $(SOONG_ZIP)
-	$(hide) $(SOONG_ZIP) -d -o $@ -C $(LLVM_PREBUILTS_BASE)/linux-x86/$(LLVM_PREBUILTS_VERSION) -f $(LLVM_PROFDATA) -f $(LIBCXX) -f $(LLVM_COV)
-
-  $(call dist-for-goals,droidcore-unbundled apps_only,$(LLVM_COVERAGE_TOOLS_ZIP))
-endif
-
-ifeq (true,$(EMMA_INSTRUMENT))
 #------------------------------------------------------------------
 # An archive of classes for use in generating code-coverage reports
 # These are the uninstrumented versions of any classes that were
 # to be instrumented.
 # Any dependencies are set up later in build/make/core/main.mk.
 
-JACOCO_REPORT_CLASSES_ALL := $(PRODUCT_OUT)/jacoco-report-classes-all.jar
-$(JACOCO_REPORT_CLASSES_ALL): PRIVATE_TARGET_JACOCO_DIR := $(call intermediates-dir-for,PACKAGING,jacoco)
-$(JACOCO_REPORT_CLASSES_ALL): PRIVATE_HOST_JACOCO_DIR := $(call intermediates-dir-for,PACKAGING,jacoco,HOST)
-$(JACOCO_REPORT_CLASSES_ALL): PRIVATE_TARGET_PROGUARD_USAGE_DIR := $(call intermediates-dir-for,PACKAGING,proguard_usage)
-$(JACOCO_REPORT_CLASSES_ALL): PRIVATE_HOST_PROGUARD_USAGE_DIR := $(call intermediates-dir-for,PACKAGING,proguard_usage,HOST)
-$(JACOCO_REPORT_CLASSES_ALL) :
-	@echo "Collecting uninstrumented classes"
-	mkdir -p $(PRIVATE_TARGET_JACOCO_DIR) $(PRIVATE_HOST_JACOCO_DIR) $(PRIVATE_TARGET_PROGUARD_USAGE_DIR) $(PRIVATE_HOST_PROGUARD_USAGE_DIR)
-	$(SOONG_ZIP) -o $@ -L 0 \
-	  -C $(PRIVATE_TARGET_JACOCO_DIR) -P out/target/common/obj -D $(PRIVATE_TARGET_JACOCO_DIR) \
-	  -C $(PRIVATE_HOST_JACOCO_DIR) -P out/target/common/obj -D $(PRIVATE_HOST_JACOCO_DIR) \
-	  -C $(PRIVATE_TARGET_PROGUARD_USAGE_DIR) -P out/target/common/obj -D $(PRIVATE_TARGET_PROGUARD_USAGE_DIR) \
-	  -C $(PRIVATE_HOST_PROGUARD_USAGE_DIR) -P out/target/common/obj -D $(PRIVATE_HOST_PROGUARD_USAGE_DIR)
-
+ifeq (true,$(EMMA_INSTRUMENT))
+# The unbundled build is handled by soong in unbundled.go
 ifeq (,$(TARGET_BUILD_UNBUNDLED))
-  $(JACOCO_REPORT_CLASSES_ALL): $(INTERNAL_ALLIMAGES_FILES)
-endif
+_jacoco_modules := $(call product-installed-modules,$(INTERNAL_PRODUCT))
 
 # This is not ideal, but it is difficult to correctly figure out the actual jacoco report
 # jars we need to add here as dependencies, so we add the device-tests as a dependency when
 # the env variable is set and this should guarantee thaat all the jacoco report jars are ready
 # when we package the final report jar here.
 ifeq ($(JACOCO_PACKAGING_INCLUDE_DEVICE_TESTS),true)
-  $(JACOCO_REPORT_CLASSES_ALL): $(COMPATIBILITY.device-tests.FILES)
+  _jacoco_modules += $(COMPATIBILITY.device-tests.MODULES)
 endif
+
+JACOCO_REPORT_CLASSES_ALL := $(PRODUCT_OUT)/jacoco-report-classes-all.jar
+$(JACOCO_REPORT_CLASSES_ALL): PRIVATE_SOONG_ZIP_ARGUMENTS := $(foreach m,$(_jacoco_modules),$(ALL_MODULES.$(m).JACOCO_REPORT_SOONG_ZIP_ARGUMENTS))
+$(JACOCO_REPORT_CLASSES_ALL): $(SOONG_ZIP) $(foreach m,$(_jacoco_modules),$(ALL_MODULES.$(m).JACOCO_REPORT_FILES))
+	@echo "Collecting uninstrumented classes"
+	rm -f $@.tmparglist && touch $@.tmparglist
+	$(foreach arg,$(PRIVATE_SOONG_ZIP_ARGUMENTS),printf "%s\n" "$(arg)" >> $@.tmparglist$(newline))
+	$(SOONG_ZIP) -o $@ -L 0 @$@.tmparglist
+	rm -f $@.tmparglist
+
+_jacoco_modules :=
+
+endif # ifeq (,$(TARGET_BUILD_UNBUNDLED))
 endif # EMMA_INSTRUMENT=true
 
 
@@ -7326,14 +7360,12 @@ endif # EMMA_INSTRUMENT=true
 # finding the appropriate dictionary to deobfuscate a stack trace frame.
 #
 
+# The proguard zips for unbundled builds are built with soong
 ifeq (,$(TARGET_BUILD_UNBUNDLED))
-  _proguard_dict_zip_modules := $(call product-installed-modules,$(INTERNAL_PRODUCT))
-else
-  _proguard_dict_zip_modules := $(unbundled_build_modules)
-endif
+
+_proguard_dict_zip_modules := $(call product-installed-modules,$(INTERNAL_PRODUCT))
 
 # Filter out list to avoid uncessary proguard related file generation
-ifeq (,$(TARGET_BUILD_UNBUNDLED))
 filter_out_proguard_dict_zip_modules :=
 # product.img
 ifndef BUILDING_PRODUCT_IMAGE
@@ -7396,7 +7428,6 @@ endef
 
 # Filter out proguard dict zip modules those are not installed at the built image
 _proguard_dict_zip_modules := $(foreach m,$(_proguard_dict_zip_modules),$(strip $(call filter-out-proguard-modules,$(m))))
-endif
 
 # The path to the zip file containing proguard dictionaries.
 PROGUARD_DICT_ZIP :=$= $(PRODUCT_OUT)/$(TARGET_PRODUCT)-proguard-dict.zip
@@ -7460,6 +7491,8 @@ $(call declare-container-license-deps,$(PROGUARD_USAGE_ZIP),$(INSTALLED_SYSTEMIM
     $(updater_dep),$(PROGUARD_USAGE_ZIP):/)
 endif
 
+endif # ifeq (,$(TARGET_BUILD_UNBUNDLED))
+
 ifeq (true,$(PRODUCT_USE_DYNAMIC_PARTITIONS))
 
 # Dump variables used by build_super_image.py (for building super.img and super_empty.img).
@@ -7480,8 +7513,6 @@ ifeq (true,$(PRODUCT_BUILD_SUPER_PARTITION))
 # BOARD_SUPER_PARTITION_SIZE must be defined to build super image.
 ifneq ($(BOARD_SUPER_PARTITION_SIZE),)
 
-ifneq (true,$(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS))
-
 # For real devices and for dist builds, build super image from target files to an intermediate directory.
 INTERNAL_SUPERIMAGE_DIST_TARGET := $(call intermediates-dir-for,PACKAGING,super.img)/super.img
 $(INTERNAL_SUPERIMAGE_DIST_TARGET): extracted_input_target_files := $(patsubst %.zip,%,$(BUILT_TARGET_FILES_PACKAGE))
@@ -7498,7 +7529,6 @@ endif
 .PHONY: superimage_dist
 superimage_dist: $(INTERNAL_SUPERIMAGE_DIST_TARGET)
 
-endif # PRODUCT_RETROFIT_DYNAMIC_PARTITIONS != "true"
 endif # BOARD_SUPER_PARTITION_SIZE != ""
 endif # PRODUCT_BUILD_SUPER_PARTITION == "true"
 
@@ -7507,7 +7537,6 @@ endif # PRODUCT_BUILD_SUPER_PARTITION == "true"
 
 ifeq (true,$(PRODUCT_BUILD_SUPER_PARTITION))
 ifneq ($(BOARD_SUPER_PARTITION_SIZE),)
-ifneq (true,$(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS))
 
 # Build super.img by using $(INSTALLED_*IMAGE_TARGET) to $(1)
 # $(1): built image path
@@ -7529,6 +7558,8 @@ INSTALLED_SUPERIMAGE_TARGET := $(PRODUCT_OUT)/super.img
 INSTALLED_SUPERIMAGE_DEPENDENCIES := $(LPMAKE) $(BUILD_SUPER_IMAGE) \
     $(foreach p, $(BOARD_SUPER_PARTITION_PARTITION_LIST), $(INSTALLED_$(call to-upper,$(p))IMAGE_TARGET))
 
+INSTALLED_ESPIMAGE_TARGET := $(PRODUCT_OUT)/esp.img
+
 ifdef BUILDING_SYSTEM_OTHER_IMAGE
 ifneq ($(filter system,$(BOARD_SUPER_PARTITION_PARTITION_LIST)),)
 INSTALLED_SUPERIMAGE_DEPENDENCIES += $(INSTALLED_SYSTEMOTHERIMAGE_TARGET)
@@ -7562,7 +7593,6 @@ superimage-nodeps supernod: | $(INSTALLED_SUPERIMAGE_DEPENDENCIES)
 	$(call build-superimage-target,$(INSTALLED_SUPERIMAGE_TARGET),\
 	  $(call intermediates-dir-for,PACKAGING,superimage-nodeps)/misc_info.txt)
 
-endif # PRODUCT_RETROFIT_DYNAMIC_PARTITIONS != "true"
 endif # BOARD_SUPER_PARTITION_SIZE != ""
 endif # PRODUCT_BUILD_SUPER_PARTITION == "true"
 
@@ -7626,9 +7656,8 @@ $(call dist-for-goals-with-filenametag,updatepackage,$(INTERNAL_UPDATE_PACKAGE_T
 dalvikfiles: $(INTERNAL_DALVIK_MODULES)
 
 ifeq ($(BUILD_QEMU_IMAGES),true)
-MK_QEMU_IMAGE_SH := device/generic/goldfish/tools/mk_qemu_image.sh
+MK_QEMU_IMAGE_SH := device/generic/goldfish/build/tools/mk_qemu_image.sh
 MK_COMBINE_QEMU_IMAGE := $(HOST_OUT_EXECUTABLES)/mk_combined_img
-SGDISK_HOST := $(HOST_OUT_EXECUTABLES)/sgdisk
 
 ifdef INSTALLED_SYSTEMIMAGE_TARGET
 INSTALLED_QEMU_SYSTEMIMAGE := $(PRODUCT_OUT)/system-qemu.img
@@ -7636,10 +7665,10 @@ INSTALLED_SYSTEM_QEMU_CONFIG := $(PRODUCT_OUT)/system-qemu-config.txt
 $(INSTALLED_SYSTEM_QEMU_CONFIG): $(INSTALLED_SUPERIMAGE_TARGET) $(INSTALLED_VBMETAIMAGE_TARGET)
 	@echo "$(PRODUCT_OUT)/vbmeta.img vbmeta 1" > $@
 	@echo "$(INSTALLED_SUPERIMAGE_TARGET) super 2" >> $@
-$(INSTALLED_QEMU_SYSTEMIMAGE): $(INSTALLED_VBMETAIMAGE_TARGET) $(MK_COMBINE_QEMU_IMAGE) $(SGDISK_HOST) $(SIMG2IMG) \
+$(INSTALLED_QEMU_SYSTEMIMAGE): $(INSTALLED_VBMETAIMAGE_TARGET) $(MK_COMBINE_QEMU_IMAGE) $(SGDISK) $(SIMG2IMG) \
     $(INSTALLED_SUPERIMAGE_TARGET) $(INSTALLED_SYSTEM_QEMU_CONFIG)
 	@echo Create system-qemu.img now
-	(export SGDISK=$(SGDISK_HOST) SIMG2IMG=$(SIMG2IMG); \
+	(export SGDISK=$(SGDISK) SIMG2IMG=$(SIMG2IMG); \
      $(MK_COMBINE_QEMU_IMAGE) -i $(INSTALLED_SYSTEM_QEMU_CONFIG) -o $@)
 
 systemimage: $(INSTALLED_QEMU_SYSTEMIMAGE)
@@ -7647,9 +7676,9 @@ droidcore-unbundled: $(INSTALLED_QEMU_SYSTEMIMAGE)
 endif
 ifdef INSTALLED_VENDORIMAGE_TARGET
 INSTALLED_QEMU_VENDORIMAGE := $(PRODUCT_OUT)/vendor-qemu.img
-$(INSTALLED_QEMU_VENDORIMAGE): $(INSTALLED_VENDORIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK_HOST) $(SIMG2IMG)
+$(INSTALLED_QEMU_VENDORIMAGE): $(INSTALLED_VENDORIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK) $(SIMG2IMG)
 	@echo Create vendor-qemu.img
-	(export SGDISK=$(SGDISK_HOST) SIMG2IMG=$(SIMG2IMG); $(MK_QEMU_IMAGE_SH) $(INSTALLED_VENDORIMAGE_TARGET))
+	(export SGDISK=$(SGDISK) SIMG2IMG=$(SIMG2IMG); $(MK_QEMU_IMAGE_SH) $(INSTALLED_VENDORIMAGE_TARGET))
 
 vendorimage: $(INSTALLED_QEMU_VENDORIMAGE)
 droidcore-unbundled: $(INSTALLED_QEMU_VENDORIMAGE)
@@ -7670,27 +7699,27 @@ endif
 
 ifdef INSTALLED_PRODUCTIMAGE_TARGET
 INSTALLED_QEMU_PRODUCTIMAGE := $(PRODUCT_OUT)/product-qemu.img
-$(INSTALLED_QEMU_PRODUCTIMAGE): $(INSTALLED_PRODUCTIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK_HOST) $(SIMG2IMG)
+$(INSTALLED_QEMU_PRODUCTIMAGE): $(INSTALLED_PRODUCTIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK) $(SIMG2IMG)
 	@echo Create product-qemu.img
-	(export SGDISK=$(SGDISK_HOST) SIMG2IMG=$(SIMG2IMG); $(MK_QEMU_IMAGE_SH) $(INSTALLED_PRODUCTIMAGE_TARGET))
+	(export SGDISK=$(SGDISK) SIMG2IMG=$(SIMG2IMG); $(MK_QEMU_IMAGE_SH) $(INSTALLED_PRODUCTIMAGE_TARGET))
 
 productimage: $(INSTALLED_QEMU_PRODUCTIMAGE)
 droidcore-unbundled: $(INSTALLED_QEMU_PRODUCTIMAGE)
 endif
 ifdef INSTALLED_SYSTEM_EXTIMAGE_TARGET
 INSTALLED_QEMU_SYSTEM_EXTIMAGE := $(PRODUCT_OUT)/system_ext-qemu.img
-$(INSTALLED_QEMU_SYSTEM_EXTIMAGE): $(INSTALLED_SYSTEM_EXTIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK_HOST) $(SIMG2IMG)
+$(INSTALLED_QEMU_SYSTEM_EXTIMAGE): $(INSTALLED_SYSTEM_EXTIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK) $(SIMG2IMG)
 	@echo Create system_ext-qemu.img
-	(export SGDISK=$(SGDISK_HOST) SIMG2IMG=$(SIMG2IMG); $(MK_QEMU_IMAGE_SH) $(INSTALLED_SYSTEM_EXTIMAGE_TARGET))
+	(export SGDISK=$(SGDISK) SIMG2IMG=$(SIMG2IMG); $(MK_QEMU_IMAGE_SH) $(INSTALLED_SYSTEM_EXTIMAGE_TARGET))
 
 systemextimage: $(INSTALLED_QEMU_SYSTEM_EXTIMAGE)
 droidcore-unbundled: $(INSTALLED_QEMU_SYSTEM_EXTIMAGE)
 endif
 ifdef INSTALLED_ODMIMAGE_TARGET
 INSTALLED_QEMU_ODMIMAGE := $(PRODUCT_OUT)/odm-qemu.img
-$(INSTALLED_QEMU_ODMIMAGE): $(INSTALLED_ODMIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK_HOST)
+$(INSTALLED_QEMU_ODMIMAGE): $(INSTALLED_ODMIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK)
 	@echo Create odm-qemu.img
-	(export SGDISK=$(SGDISK_HOST); $(MK_QEMU_IMAGE_SH) $(INSTALLED_ODMIMAGE_TARGET))
+	(export SGDISK=$(SGDISK); $(MK_QEMU_IMAGE_SH) $(INSTALLED_ODMIMAGE_TARGET))
 
 odmimage: $(INSTALLED_QEMU_ODMIMAGE)
 droidcore-unbundled: $(INSTALLED_QEMU_ODMIMAGE)
@@ -7698,9 +7727,9 @@ endif
 
 ifdef INSTALLED_VENDOR_DLKMIMAGE_TARGET
 INSTALLED_QEMU_VENDOR_DLKMIMAGE := $(PRODUCT_OUT)/vendor_dlkm-qemu.img
-$(INSTALLED_QEMU_VENDOR_DLKMIMAGE): $(INSTALLED_VENDOR_DLKMIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK_HOST)
+$(INSTALLED_QEMU_VENDOR_DLKMIMAGE): $(INSTALLED_VENDOR_DLKMIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK)
 	@echo Create vendor_dlkm-qemu.img
-	(export SGDISK=$(SGDISK_HOST); $(MK_QEMU_IMAGE_SH) $(INSTALLED_VENDOR_DLKMIMAGE_TARGET))
+	(export SGDISK=$(SGDISK); $(MK_QEMU_IMAGE_SH) $(INSTALLED_VENDOR_DLKMIMAGE_TARGET))
 
 vendor_dlkmimage: $(INSTALLED_QEMU_VENDOR_DLKMIMAGE)
 droidcore-unbundled: $(INSTALLED_QEMU_VENDOR_DLKMIMAGE)
@@ -7708,9 +7737,9 @@ endif
 
 ifdef INSTALLED_ODM_DLKMIMAGE_TARGET
 INSTALLED_QEMU_ODM_DLKMIMAGE := $(PRODUCT_OUT)/odm_dlkm-qemu.img
-$(INSTALLED_QEMU_ODM_DLKMIMAGE): $(INSTALLED_ODM_DLKMIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK_HOST)
+$(INSTALLED_QEMU_ODM_DLKMIMAGE): $(INSTALLED_ODM_DLKMIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK)
 	@echo Create odm_dlkm-qemu.img
-	(export SGDISK=$(SGDISK_HOST); $(MK_QEMU_IMAGE_SH) $(INSTALLED_ODM_DLKMIMAGE_TARGET))
+	(export SGDISK=$(SGDISK); $(MK_QEMU_IMAGE_SH) $(INSTALLED_ODM_DLKMIMAGE_TARGET))
 
 odm_dlkmimage: $(INSTALLED_QEMU_ODM_DLKMIMAGE)
 droidcore-unbundled: $(INSTALLED_QEMU_ODM_DLKMIMAGE)
@@ -7718,9 +7747,9 @@ endif
 
 ifdef INSTALLED_SYSTEM_DLKMIMAGE_TARGET
 INSTALLED_QEMU_SYSTEM_DLKMIMAGE := $(PRODUCT_OUT)/system_dlkm-qemu.img
-$(INSTALLED_QEMU_SYSTEM_DLKMIMAGE): $(INSTALLED_SYSTEM_DLKMIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK_HOST)
+$(INSTALLED_QEMU_SYSTEM_DLKMIMAGE): $(INSTALLED_SYSTEM_DLKMIMAGE_TARGET) $(MK_QEMU_IMAGE_SH) $(SGDISK)
 	@echo Create system_dlkm-qemu.img
-	(export SGDISK=$(SGDISK_HOST); $(MK_QEMU_IMAGE_SH) $(INSTALLED_SYSTEM_DLKMIMAGE_TARGET))
+	(export SGDISK=$(SGDISK); $(MK_QEMU_IMAGE_SH) $(INSTALLED_SYSTEM_DLKMIMAGE_TARGET))
 
 system_dlkmimage: $(INSTALLED_QEMU_SYSTEM_DLKMIMAGE)
 droidcore-unbundled: $(INSTALLED_QEMU_SYSTEM_DLKMIMAGE)
@@ -7837,8 +7866,7 @@ deps := \
   $(INSTALLED_SDK_BUILD_PROP_TARGET) \
 	$(ATREE_FILES) \
 	$(sdk_atree_files) \
-	$(HOST_OUT_EXECUTABLES)/atree \
-	$(HOST_OUT_EXECUTABLES)/line_endings
+	$(HOST_OUT_EXECUTABLES)/atree
 
 # The name of the subdir within the platforms dir of the sdk. One of:
 # - android-<SDK_INT> (stable base dessert SDKs)
@@ -7847,8 +7875,8 @@ deps := \
 sdk_platform_dir_name := $(strip \
   $(if $(filter REL,$(PLATFORM_VERSION_CODENAME)), \
     $(if $(filter $(PLATFORM_SDK_EXTENSION_VERSION),$(PLATFORM_BASE_SDK_EXTENSION_VERSION)), \
-      android-$(PLATFORM_SDK_VERSION), \
-      android-$(PLATFORM_SDK_VERSION)-ext$(PLATFORM_SDK_EXTENSION_VERSION) \
+      android-$(PLATFORM_SDK_VERSION_FULL), \
+      android-$(PLATFORM_SDK_VERSION_FULL)-ext$(PLATFORM_SDK_EXTENSION_VERSION) \
     ), \
     android-$(PLATFORM_VERSION_CODENAME) \
   ) \
@@ -7922,18 +7950,24 @@ $(INTERNAL_FINDBUGS_HTML_TARGET): $(INTERNAL_FINDBUGS_XML_TARGET)
 # -----------------------------------------------------------------
 # These are some additional build tasks that need to be run.
 ifneq ($(dont_bother),true)
-include $(sort $(wildcard $(BUILD_SYSTEM)/tasks/*.mk))
--include $(sort $(wildcard vendor/*/build/tasks/*.mk))
--include $(sort $(wildcard device/*/build/tasks/*.mk))
--include $(sort $(wildcard product/*/build/tasks/*.mk))
-# Also the project-specific tasks
--include $(sort $(wildcard vendor/*/*/build/tasks/*.mk))
--include $(sort $(wildcard device/*/*/build/tasks/*.mk))
--include $(sort $(wildcard product/*/*/build/tasks/*.mk))
-# Also add test specifc tasks
-include $(sort $(wildcard platform_testing/build/tasks/*.mk))
-include $(sort $(wildcard test/vts/tools/build/tasks/*.mk))
+task_makefiles := \
+	$(sort $(wildcard $(BUILD_SYSTEM)/tasks/*.mk)) \
+	$(sort $(wildcard vendor/*/build/tasks/*.mk)) \
+	$(sort $(wildcard device/*/build/tasks/*.mk)) \
+	$(sort $(wildcard product/*/build/tasks/*.mk)) \
+	$(sort $(wildcard vendor/*/*/build/tasks/*.mk)) \
+	$(sort $(wildcard device/*/*/build/tasks/*.mk)) \
+	$(sort $(wildcard product/*/*/build/tasks/*.mk)) \
+	$(sort $(wildcard platform_testing/build/tasks/*.mk)) \
+	$(sort $(wildcard test/vts/tools/build/tasks/*.mk))
+
+include_makefiles_total := $(words int $(task_makefiles))
+include_makefiles_inc:=
+
+$(foreach mk,$(task_makefiles),$(info [$(call inc_and_print,include_makefiles_inc)/$(include_makefiles_total)] including $(mk) ...)$(eval include $(mk)))
+
 endif
+$(info [$(include_makefiles_total)/$(include_makefiles_total)] finishing Make packaging rules)
 
 include $(BUILD_SYSTEM)/product-graph.mk
 
@@ -7944,44 +7978,6 @@ ifneq ($(sdk_repo_goal),)
 include $(TOPDIR)development/build/tools/sdk_repo.mk
 endif
 
-# -----------------------------------------------------------------
-# Soong generates the list of all shared libraries that are depended on by fuzz
-# targets. It saves this list as a source:destination pair to
-# FUZZ_TARGET_SHARED_DEPS_INSTALL_PAIRS, where the source is the path to the
-# build of the unstripped shared library, and the destination is the
-# /data/fuzz/$ARCH/lib (for device) or /fuzz/$ARCH/lib (for host) directory
-# where fuzz target shared libraries are to be "reinstalled". The
-# copy-many-files below generates the rules to copy the unstripped shared
-# libraries to the device or host "reinstallation" directory. These rules are
-# depended on by each module in soong_cc_prebuilt.mk, where the module will have
-# a dependency on each shared library that it needs to be "reinstalled".
-FUZZ_SHARED_DEPS := $(call copy-many-files,$(strip $(FUZZ_TARGET_SHARED_DEPS_INSTALL_PAIRS)))
-
-# -----------------------------------------------------------------
-# The rule to build all fuzz targets for C++ and Rust, and package them.
-# Note: The packages are created in Soong, and in a perfect world,
-# we'd be able to create the phony rule there. But, if we want to
-# have dist goals for the fuzz target, we need to have the PHONY
-# target defined in make. MakeVarsContext.DistForGoal doesn't take
-# into account that a PHONY rule create by Soong won't be available
-# during make, and such will fail with `writing to readonly
-# directory`, because kati will see 'haiku' as being a file, not a
-# phony target.
-.PHONY: haiku
-haiku: $(SOONG_FUZZ_PACKAGING_ARCH_MODULES) $(ALL_FUZZ_TARGETS)
-$(call dist-for-goals,haiku,$(SOONG_FUZZ_PACKAGING_ARCH_MODULES))
-$(call dist-for-goals,haiku,$(PRODUCT_OUT)/module-info.json)
-.PHONY: haiku-java
-haiku-java: $(SOONG_JAVA_FUZZ_PACKAGING_ARCH_MODULES) $(ALL_JAVA_FUZZ_TARGETS)
-$(call dist-for-goals,haiku-java,$(SOONG_JAVA_FUZZ_PACKAGING_ARCH_MODULES))
-.PHONY: haiku-rust
-haiku-rust: $(SOONG_RUST_FUZZ_PACKAGING_ARCH_MODULES) $(ALL_RUST_FUZZ_TARGETS)
-$(call dist-for-goals,haiku-rust,$(SOONG_RUST_FUZZ_PACKAGING_ARCH_MODULES))
-$(call dist-for-goals,haiku-rust,$(PRODUCT_OUT)/module-info.json)
-.PHONY: haiku-presubmit
-haiku-presubmit: $(SOONG_PRESUBMIT_FUZZ_PACKAGING_ARCH_MODULES) $(ALL_PRESUBMIT_FUZZ_TARGETS)
-$(call dist-for-goals,haiku-presubmit,$(SOONG_PRESUBMIT_FUZZ_PACKAGING_ARCH_MODULES))
-
 # -----------------------------------------------------------------
 # Extract additional data files used in Layoutlib
 include $(BUILD_SYSTEM)/layoutlib_data.mk
@@ -7989,23 +7985,30 @@ include $(BUILD_SYSTEM)/layoutlib_data.mk
 # -----------------------------------------------------------------
 # Desktop pack common variables.
 PACK_IMAGE_SCRIPT := $(HOST_OUT_EXECUTABLES)/pack_image
-IMAGES := $(INSTALLED_BOOTIMAGE_TARGET) \
+PACK_IMAGE_DEPS := $(PACK_IMAGE_SCRIPT) \
+	$(SGDISK) \
+	$(INSTALLED_BOOTIMAGE_TARGET) \
 	$(INSTALLED_SUPERIMAGE_TARGET) \
 	$(INSTALLED_INIT_BOOT_IMAGE_TARGET) \
 	$(INSTALLED_VENDOR_BOOTIMAGE_TARGET) \
 	$(INSTALLED_VBMETAIMAGE_TARGET) \
 	$(INSTALLED_USERDATAIMAGE_TARGET)
+UPDATE_PARTITION_SCRIPT := $(HOST_OUT_EXECUTABLES)/update-partition
+
+ifneq (,$(strip $(PACK_DESKTOP_ESP_IMAGE)))
+  PACK_IMAGE_DEPS += $(INSTALLED_ESPIMAGE_TARGET)
+endif # PACK_DESKTOP_ESP_IMAGE
 
 # -----------------------------------------------------------------
 # Desktop generated firmware filesystem.
-TARGET_PRODUCT_FW_IMAGE_PACKAGE := prebuilt-$(TARGET_PRODUCT)-firmware-image
-GENERATED_FW_IMAGE := $(PRODUCT_OUT)/product/etc/$(TARGET_PRODUCT)-firmware.img
-
-generated_fw_image_found := $(strip $(foreach pp,$(PRODUCT_PACKAGES),\
-	$(if $(findstring $(TARGET_PRODUCT_FW_IMAGE_PACKAGE),$(pp)),$(pp))))
+# This artifact is used in two places:
+# 1. Packed into the recovery image.
+# 2. Added into DIST_DIR so that lab provisioning can download the firmware.
+TARGET_PRODUCT_FW_IMAGE_PACKAGE := gen-$(TARGET_PRODUCT)-firmware-image
+GENERATED_FW_IMAGE := $(call module-built-files,$(TARGET_PRODUCT_FW_IMAGE_PACKAGE))
 
-ifneq (,$(generated_fw_image_found))
-$(call dist-for-goals,dist_files,$(GENERATED_FW_IMAGE))
+ifneq (,$(GENERATED_FW_IMAGE))
+$(call dist-for-goals,dist_files,$(GENERATED_FW_IMAGE):${TARGET_PRODUCT}-firmware.img)
 endif
 
 # -----------------------------------------------------------------
@@ -8013,7 +8016,7 @@ endif
 ifneq (,$(strip $(PACK_DESKTOP_FILESYSTEM_IMAGES)))
 PACK_IMAGE_TARGET := $(PRODUCT_OUT)/android-desktop_image.bin
 
-$(PACK_IMAGE_TARGET): $(IMAGES) $(PACK_IMAGE_SCRIPT)
+$(PACK_IMAGE_TARGET): $(PACK_IMAGE_DEPS)
 	$(PACK_IMAGE_SCRIPT) --out_dir $(PRODUCT_OUT) --noarchive
 
 PACKED_IMAGE_ARCHIVE_TARGET := $(PACK_IMAGE_TARGET).gz
@@ -8032,44 +8035,69 @@ endif # PACK_DESKTOP_FILESYSTEM_IMAGES
 # Desktop pack recovery image hook.
 ifeq ($(BOARD_USES_DESKTOP_RECOVERY_IMAGE),true)
 PACK_RECOVERY_IMAGE_TARGET := $(PRODUCT_OUT)/android-desktop_recovery_image.bin
-PACK_RECOVERY_IMAGE_ARGS := --noarchive --recovery
+PACK_RECOVERY_IMAGE_ARGS := --noarchive --recovery --firmware $(GENERATED_FW_IMAGE)
 
 ifneq (,$(strip $(PACK_RECOVERY_IMAGE_EXPERIMENTAL)))
 PACK_RECOVERY_IMAGE_ARGS += --experimental
 endif # PACK_RECOVERY_IMAGE_EXPERIMENTAL
 
-$(PACK_RECOVERY_IMAGE_TARGET): $(IMAGES) $(PACK_IMAGE_SCRIPT)
+$(PACK_RECOVERY_IMAGE_TARGET): $(PACK_IMAGE_DEPS) $(PRODUCT_OUT)/recovery-kernel $(GENERATED_FW_IMAGE)
 	$(PACK_IMAGE_SCRIPT) --out_dir $(PRODUCT_OUT) $(PACK_RECOVERY_IMAGE_ARGS)
 
-PACKED_RECOVERY_IMAGE_ARCHIVE_TARGET := $(PACK_RECOVERY_IMAGE_TARGET).gz
+PACKED_RECOVERY_IMAGE_ARCHIVE_TARGET := $(PACK_RECOVERY_IMAGE_TARGET).zst
 
-$(PACKED_RECOVERY_IMAGE_ARCHIVE_TARGET): $(PACK_RECOVERY_IMAGE_TARGET) | $(GZIP)
-	$(GZIP) -fk $(PACK_RECOVERY_IMAGE_TARGET)
+$(PACKED_RECOVERY_IMAGE_ARCHIVE_TARGET): $(PACK_RECOVERY_IMAGE_TARGET) | $(ZSTD)
+	$(ZSTD) -T0 -19 -fk $(PACK_RECOVERY_IMAGE_TARGET)
 
 $(call dist-for-goals,dist_files,$(PACKED_RECOVERY_IMAGE_ARCHIVE_TARGET))
 
 .PHONY: pack-recovery-image
 pack-recovery-image: $(PACK_RECOVERY_IMAGE_TARGET)
 
+RECOVERY_SWAP_KERNEL_TARGET := $(PRODUCT_OUT)/recovery-kernel-swap
+
+# Has swap kernel for insecure recovery image.
+ifeq ($(BOARD_USES_DESKTOP_RECOVERY_SWAP_KERNEL),true)
+
+$(call dist-for-goals,dist_files,$(RECOVERY_SWAP_KERNEL_TARGET))
+
+PACK_INSECURE_RECOVERY_IMAGE_TARGET := $(PRODUCT_OUT)/android-desktop_insecure_recovery_image.bin
+
+$(PACK_INSECURE_RECOVERY_IMAGE_TARGET): $(PACK_RECOVERY_IMAGE_TARGET) $(UPDATE_PARTITION_SCRIPT) $(RECOVERY_SWAP_KERNEL_TARGET) $(SGDISK)
+	@cp -f $< $@
+	(export SGDISK=$(SGDISK); $(UPDATE_PARTITION_SCRIPT) KERN-A $@ $(RECOVERY_SWAP_KERNEL_TARGET))
+
+PACKED_INSECURE_RECOVERY_IMAGE_ARCHIVE_TARGET := $(PACK_INSECURE_RECOVERY_IMAGE_TARGET).zst
+
+$(PACKED_INSECURE_RECOVERY_IMAGE_ARCHIVE_TARGET): $(PACK_INSECURE_RECOVERY_IMAGE_TARGET) | $(ZSTD)
+	$(ZSTD) -T0 -19 -fk $(PACK_INSECURE_RECOVERY_IMAGE_TARGET)
+
+$(call dist-for-goals,dist_files,$(PACKED_INSECURE_RECOVERY_IMAGE_ARCHIVE_TARGET))
+
+.PHONY: pack-insecure-recovery-image
+pack-insecure-recovery-image: $(PACK_INSECURE_RECOVERY_IMAGE_TARGET)
+
+endif # BOARD_USES_DESKTOP_RECOVERY_SWAP_KERNEL
+
 endif # BOARD_USES_DESKTOP_RECOVERY_IMAGE
 
 # -----------------------------------------------------------------
 # Desktop pack update image hook.
 ifeq ($(BOARD_USES_DESKTOP_UPDATE_IMAGE),true)
 PACK_UPDATE_IMAGE_TARGET := $(PRODUCT_OUT)/android-desktop_update_image.bin
-PACK_UPDATE_IMAGE_ARGS := --noarchive --update
+PACK_UPDATE_IMAGE_ARGS := --noarchive --update --firmware $(GENERATED_FW_IMAGE)
 
 ifneq (,$(strip $(PACK_UPDATE_IMAGE_EXPERIMENTAL)))
 PACK_UPDATE_IMAGE_ARGS += --experimental
 endif # PACK_UPDATE_IMAGE_EXPERIMENTAL
 
-$(PACK_UPDATE_IMAGE_TARGET): $(IMAGES) $(PACK_IMAGE_SCRIPT)
+$(PACK_UPDATE_IMAGE_TARGET): $(PACK_IMAGE_DEPS) $(PRODUCT_OUT)/update-kernel $(GENERATED_FW_IMAGE)
 	$(PACK_IMAGE_SCRIPT) --out_dir $(PRODUCT_OUT) $(PACK_UPDATE_IMAGE_ARGS)
 
-PACKED_UPDATE_IMAGE_ARCHIVE_TARGET := $(PACK_UPDATE_IMAGE_TARGET).gz
+PACKED_UPDATE_IMAGE_ARCHIVE_TARGET := $(PACK_UPDATE_IMAGE_TARGET).zst
 
-$(PACKED_UPDATE_IMAGE_ARCHIVE_TARGET): $(PACK_UPDATE_IMAGE_TARGET) | $(GZIP)
-	$(GZIP) -fk $(PACK_UPDATE_IMAGE_TARGET)
+$(PACKED_UPDATE_IMAGE_ARCHIVE_TARGET): $(PACK_UPDATE_IMAGE_TARGET) | $(ZSTD)
+	$(ZSTD) -T0 -19 -fk $(PACK_UPDATE_IMAGE_TARGET)
 
 $(call dist-for-goals,dist_files,$(PACKED_UPDATE_IMAGE_ARCHIVE_TARGET))
 
@@ -8085,13 +8113,13 @@ PACK_MIGRATION_IMAGE_SCRIPT := $(HOST_OUT_EXECUTABLES)/pack_migration_image
 ifeq ($(ANDROID_DESKTOP_MIGRATION_IMAGE),true)
 PACK_MIGRATION_IMAGE_TARGET := $(PRODUCT_OUT)/android-desktop_migration_image.bin
 
-$(PACK_MIGRATION_IMAGE_TARGET): $(IMAGES) $(PACK_MIGRATION_IMAGE_SCRIPT)
+$(PACK_MIGRATION_IMAGE_TARGET): $(PACK_IMAGE_DEPS) $(PACK_MIGRATION_IMAGE_SCRIPT)
 	$(PACK_MIGRATION_IMAGE_SCRIPT) --out_dir $(PRODUCT_OUT) --noarchive
 
-PACKED_MIGRATION_IMAGE_ARCHIVE_TARGET := $(PACK_MIGRATION_IMAGE_TARGET).gz
+PACKED_MIGRATION_IMAGE_ARCHIVE_TARGET := $(PACK_MIGRATION_IMAGE_TARGET).zst
 
-$(PACKED_MIGRATION_IMAGE_ARCHIVE_TARGET): $(PACK_MIGRATION_IMAGE_TARGET) | $(GZIP)
-	$(GZIP) -fk $(PACK_MIGRATION_IMAGE_TARGET)
+$(PACKED_MIGRATION_IMAGE_ARCHIVE_TARGET): $(PACK_MIGRATION_IMAGE_TARGET) | $(ZSTD)
+	$(ZSTD) -T0 -19 -fk $(PACK_MIGRATION_IMAGE_TARGET)
 
 $(call dist-for-goals,dist_files,$(PACKED_MIGRATION_IMAGE_ARCHIVE_TARGET))
 
diff --git a/core/OWNERS b/core/OWNERS
index d8aa2372c1..b9c6079bfe 100644
--- a/core/OWNERS
+++ b/core/OWNERS
@@ -11,3 +11,5 @@ per-file version_defaults.mk = amhk@google.com,gurpreetgs@google.com,mkhokhlova@
 # For Ravenwood test configs
 per-file ravenwood_test_config_template.xml =omakoto@google.com
 
+# For ART configuration.
+per-file art_config.mk = file:platform/art:main:/OWNERS
diff --git a/core/android_soong_config_vars.mk b/core/android_soong_config_vars.mk
index 59b6467b47..1595787ea0 100644
--- a/core/android_soong_config_vars.mk
+++ b/core/android_soong_config_vars.mk
@@ -30,8 +30,8 @@ $(call add_soong_config_var,ANDROID,BOARD_USES_ODMIMAGE)
 $(call soong_config_set_bool,ANDROID,BOARD_USES_RECOVERY_AS_BOOT,$(BOARD_USES_RECOVERY_AS_BOOT))
 $(call soong_config_set_bool,ANDROID,BOARD_MOVE_GSI_AVB_KEYS_TO_VENDOR_BOOT,$(BOARD_MOVE_GSI_AVB_KEYS_TO_VENDOR_BOOT))
 $(call add_soong_config_var,ANDROID,CHECK_DEV_TYPE_VIOLATIONS)
-$(call soong_config_set_bool,ANDROID,HAS_BOARD_SYSTEM_EXT_PREBUILT_DIR,$(if $(BOARD_SYSTEM_EXT_PREBUILT_DIR),true,false))
-$(call soong_config_set_bool,ANDROID,HAS_BOARD_PRODUCT_PREBUILT_DIR,$(if $(BOARD_PRODUCT_PREBUILT_DIR),true,false))
+$(call soong_config_set_bool,ANDROID,HAS_BOARD_SYSTEM_EXT_SEPOLICY_PREBUILT_DIRS,$(if $(BOARD_SYSTEM_EXT_SEPOLICY_PREBUILT_DIRS),true,false))
+$(call soong_config_set_bool,ANDROID,HAS_BOARD_PRODUCT_SEPOLICY_PREBUILT_DIRS,$(if $(BOARD_PRODUCT_SEPOLICY_PREBUILT_DIRS),true,false))
 $(call add_soong_config_var,ANDROID,PLATFORM_SEPOLICY_VERSION)
 $(call add_soong_config_var,ANDROID,PLATFORM_SEPOLICY_COMPAT_VERSIONS)
 $(call add_soong_config_var,ANDROID,PRODUCT_INSTALL_DEBUG_POLICY_TO_SYSTEM_EXT)
@@ -263,6 +263,10 @@ $(call soong_config_set,bootclasspath,release_package_profiling_module,$(RELEASE
 # Move VCN from platform to the Tethering module; used by both platform and module
 $(call soong_config_set,ANDROID,is_vcn_in_mainline,$(RELEASE_MOVE_VCN_TO_MAINLINE))
 
+# Add telephony build flag to soong
+$(call soong_config_set,ANDROID,release_telephony_module,$(RELEASE_TELEPHONY_MODULE))
+$(call soong_config_set,bootclasspath,release_telephony_module,$(RELEASE_TELEPHONY_MODULE))
+
 # Add perf-setup build flag to soong
 # Note: BOARD_PERFSETUP_SCRIPT location must be under platform_testing/scripts/perf-setup/.
 ifdef BOARD_PERFSETUP_SCRIPT
@@ -376,3 +380,84 @@ endif
 ifneq ($(wildcard bootable/deprecated-ota/applypatch),)
   $(call soong_config_set_bool,otatools,use_bootable_deprecated_ota_applypatch,true)
 endif
+
+# Flags used in building continuous_native_tests
+ifeq ($(BOARD_IS_AUTOMOTIVE), true)
+  $(call soong_config_set_bool,ANDROID,board_is_automotive,true)
+endif
+ifneq ($(filter vendor/google/darwinn,$(PRODUCT_SOONG_NAMESPACES)),)
+  $(call soong_config_set_bool,ci_tests,uses_darwinn_tests,true)
+endif
+
+# Flags used in building continuous_instrumentation_tests
+ifneq ($(filter StorageManager, $(PRODUCT_PACKAGES)),)
+  $(call soong_config_set_bool,ci_tests,uses_storage_manager_tests,true)
+endif
+
+ifneq ($(BUILD_OS),darwin)
+  ifneq ($(TARGET_SKIP_OTATOOLS_PACKAGE),true)
+    $(call soong_config_set_bool,otatools,use_otatools_package,true)
+  endif
+endif
+
+# Variables for qcom bluetooth modules.
+$(call soong_config_set,qcom_bluetooth,TARGET_BLUETOOTH_UART_DEVICE,$(TARGET_BLUETOOTH_UART_DEVICE))
+$(call soong_config_set_bool,qcom_bluetooth,BOARD_HAVE_QCOM_FM,$(if $(filter true,$(BOARD_HAVE_QCOM_FM)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,BOARD_HAVE_QTI_BT_LAZY_SERVICE,$(if $(filter true,$(BOARD_HAVE_QTI_BT_LAZY_SERVICE)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,QCOM_BLUETOOTH_USING_DIAG,$(if $(filter true,$(QCOM_BLUETOOTH_USING_DIAG)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,TARGET_BLUETOOTH_HCI_V1_1,$(if $(filter true,$(TARGET_BLUETOOTH_HCI_V1_1)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,TARGET_BLUETOOTH_SUPPORT_QMI_ADDRESS,$(if $(filter true,$(TARGET_BLUETOOTH_SUPPORT_QMI_ADDRESS)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,TARGET_DROP_BYTES_BEFORE_SSR_DUMP,$(if $(filter true,$(TARGET_DROP_BYTES_BEFORE_SSR_DUMP)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,TARGET_USE_QTI_BT_CHANNEL_AVOIDANCE,$(if $(filter true,$(TARGET_USE_QTI_BT_CHANNEL_AVOIDANCE)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,TARGET_USE_QTI_BT_CONFIGSTORE,$(if $(filter true,$(TARGET_USE_QTI_BT_CONFIGSTORE)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,TARGET_USE_QTI_BT_IBS,$(if $(filter true,$(TARGET_USE_QTI_BT_IBS)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,TARGET_USE_QTI_BT_OBS,$(if $(filter true,$(TARGET_USE_QTI_BT_OBS)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,TARGET_USE_QTI_BT_SAR,$(if $(filter true,$(TARGET_USE_QTI_BT_SAR)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,TARGET_USE_QTI_BT_SAR_V1_1,$(if $(filter true,$(TARGET_USE_QTI_BT_SAR_V1_1)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,TARGET_USE_QTI_VND_FWK_DETECT,$(if $(filter true,$(TARGET_USE_QTI_VND_FWK_DETECT)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,UART_BAUDRATE_3_0_MBPS,$(if $(filter true,$(UART_BAUDRATE_3_0_MBPS)),true,false))
+$(call soong_config_set_bool,qcom_bluetooth,UART_USE_TERMIOS_AFC,$(if $(filter true,$(UART_USE_TERMIOS_AFC)),true,false))
+
+# Flags for Fingerprint HAL
+$(call soong_config_set,fp_hal_feature,FPC_CONFIG_KEYMASTER_APP_PATH,$(FPC_CONFIG_KEYMASTER_APP_PATH))
+$(call soong_config_set,fp_hal_feature,FPC_CONFIG_KEYMASTER_NAME,$(FPC_CONFIG_KEYMASTER_NAME))
+$(call soong_config_set,fp_hal_feature,FPC_CONFIG_SENSE_TOUCH_CALIBRATION_PATH,$(FPC_CONFIG_SENSE_TOUCH_CALIBRATION_PATH))
+$(call soong_config_set,fp_hal_feature,FPC_MODULE_TYPE,$(FPC_MODULE_TYPE))
+$(call soong_config_set,fp_hal_feature,FPC_PLATFORM_TARGET,$(FPC_PLATFORM_TARGET))
+$(call soong_config_set,fp_hal_feature,FPC_TEE_RUNTIME,$(FPC_TEE_RUNTIME))
+ifneq ($(FPC_CONFIG_RETRY_MATCH_TIMEOUT),)
+  $(call soong_config_set,fp_hal_feature,FPC_CONFIG_RETRY_MATCH_TIMEOUT,$(FPC_CONFIG_RETRY_MATCH_TIMEOUT))
+endif
+ifneq ($(GOOGLE_CONFIG_DP_COUNT),)
+  $(call soong_config_set,fp_hal_feature,GOOGLE_CONFIG_DP_COUNT,$(GOOGLE_CONFIG_DP_COUNT))
+endif
+ifneq ($(GOOGLE_CONFIG_POWER_NODE),)
+  $(call soong_config_set,fp_hal_feature,GOOGLE_CONFIG_POWER_NODE,$(GOOGLE_CONFIG_POWER_NODE))
+endif
+
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_DEBUG,$(if $(filter 1,$(FPC_CONFIG_DEBUG)),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_ENGINEERING,$(if $(FPC_CONFIG_ENGINEERING),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_ENROL_TIMEOUT,$(if $(filter 1,$(FPC_CONFIG_ENROL_TIMEOUT)),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_FIDO_AUTH,$(if $(FPC_CONFIG_FIDO_AUTH),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_FIDO_AUTH_VER_GMRZ,$(if $(filter 1,$(FPC_CONFIG_FIDO_AUTH_VER_GMRZ)),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_HW_AUTH,$(if $(filter 1,$(FPC_CONFIG_HW_AUTH)),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_GOOGLE_CUSTOMIZE,$(if $(filter 1,$(FPC_CONFIG_GOOGLE_CUSTOMIZE)),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_GOOGLE_RELEASE,$(if $(filter 1,$(FPC_CONFIG_GOOGLE_RELEASE)),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_NAVIGATION,$(if $(FPC_CONFIG_NAVIGATION),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_NO_ALGO,$(if $(FPC_CONFIG_NO_ALGO),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_NO_SENSOR,$(if $(FPC_CONFIG_NO_SENSOR),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_NORMAL_SENSOR_RESET,$(if $(FPC_CONFIG_NORMAL_SENSOR_RESET),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_NORMAL_SPI_RESET,$(if $(FPC_CONFIG_NORMAL_SPI_RESET),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_SENSORTEST,$(if $(FPC_CONFIG_SENSORTEST),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_SWIPE_ENROL,$(if $(filter 1,$(FPC_CONFIG_SWIPE_ENROL)),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_TA_FS,$(if $(FPC_CONFIG_TA_FS),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_TRUSTY_CLEAN_TA,$(if $(filter 1,$(FPC_CONFIG_TRUSTY_CLEAN_TA)),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_TRUSTY_EMULATOR,$(if $(filter 1,$(FPC_CONFIG_TRUSTY_EMULATOR)),true,false))
+$(call soong_config_set_bool,fp_hal_feature,FPC_CONFIG_TRUSTY_SC,$(if $(filter 1,$(FPC_CONFIG_TRUSTY_SC)),true,false))
+$(call soong_config_set_bool,fp_hal_feature,GOOGLE_CONFIG_PERFORMANCE,$(if $(filter 1,$(GOOGLE_CONFIG_PERFORMANCE)),true,false))
+$(call soong_config_set_bool,fp_hal_feature,GOOGLE_CONFIG_TOUCH_TO_UNLOCK_ANYTIME,$(if $(filter 1,$(GOOGLE_CONFIG_TOUCH_TO_UNLOCK_ANYTIME)),true,false))
+
+# Flags for CLOCKWORK
+$(call soong_config_set_bool,CLOCKWORK,CLOCKWORK_EMULATOR_PRODUCT,$(if $(filter true,$(CLOCKWORK_EMULATOR_PRODUCT)),true,false))
+$(call soong_config_set_bool,CLOCKWORK,CLOCKWORK_ENABLE_HEALTH_SERVICES_HAL,$(if $(filter true,$(CLOCKWORK_ENABLE_HEALTH_SERVICES_HAL)),true,false))
+$(call soong_config_set_bool,CLOCKWORK,CLOCKWORK_G3_BUILD,$(if $(filter true,$(CLOCKWORK_G3_BUILD)),true,false))
diff --git a/core/base_rules.mk b/core/base_rules.mk
index 604fe06667..c71670f6be 100644
--- a/core/base_rules.mk
+++ b/core/base_rules.mk
@@ -40,6 +40,8 @@ $(call verify-module-name)
 my_test_data :=
 my_test_config :=
 
+LOCAL_IS_SOONG_MODULE := $(if $(filter $(LOCAL_MODULE_MAKEFILE),$(SOONG_ANDROID_MK)),true)
+
 LOCAL_IS_HOST_MODULE := $(strip $(LOCAL_IS_HOST_MODULE))
 ifdef LOCAL_IS_HOST_MODULE
   ifneq ($(LOCAL_IS_HOST_MODULE),true)
@@ -128,7 +130,7 @@ include $(BUILD_SYSTEM)/local_current_sdk.mk
 
 # Check if the use of System SDK is correct. Note that, for Soong modules, the system sdk version
 # check is done in Soong. No need to do it twice.
-ifneq ($(LOCAL_MODULE_MAKEFILE),$(SOONG_ANDROID_MK))
+ifeq (,$(LOCAL_IS_SOONG_MODULE))
 include $(BUILD_SYSTEM)/local_systemsdk.mk
 endif
 
@@ -176,6 +178,7 @@ my_module_path := $(strip $(LOCAL_MODULE_PATH))
 endif
 my_module_path := $(patsubst %/,%,$(my_module_path))
 my_module_relative_path := $(strip $(LOCAL_MODULE_RELATIVE_PATH))
+my_module_relative_path := $(patsubst %/,%,$(my_module_relative_path))
 
 ifdef LOCAL_IS_HOST_MODULE
   partition_tag :=
@@ -220,7 +223,7 @@ endif
 # modulo "null-sute", "mts", and "mcts". mts/mcts are automatically added if there's a different
 # suite starting with "m(c)ts-". null-suite seems useless and is sometimes automatically added
 # if no other suites are added.
-ifneq (,$(filter $(LOCAL_MODULE_MAKEFILE),$(SOONG_ANDROID_MK)))
+ifneq (,$(LOCAL_IS_SOONG_MODULE))
   a := $(filter-out null-suite mts mcts,$(sort $(LOCAL_COMPATIBILITY_SUITE)))
   b := $(filter-out null-suite mts mcts,$(sort $(LOCAL_SOONG_PROVIDER_TEST_SUITES)))
   ifneq ($(a),$(b))
@@ -355,7 +358,7 @@ include $(BUILD_SYSTEM)/configure_module_stem.mk
 LOCAL_BUILT_MODULE := $(intermediates)/$(my_built_module_stem)
 
 ifneq (,$(LOCAL_SOONG_INSTALLED_MODULE))
-  ifneq ($(LOCAL_MODULE_MAKEFILE),$(SOONG_ANDROID_MK))
+  ifeq (,$(LOCAL_IS_SOONG_MODULE))
     $(call pretty-error, LOCAL_MODULE_MAKEFILE can only be used from $(SOONG_ANDROID_MK))
   endif
   # Use the install path requested by Soong.
@@ -389,7 +392,7 @@ LOCAL_INTERMEDIATE_TARGETS += $(LOCAL_BUILT_MODULE)
 # Don't create .toc files for Soong shared libraries, that is handled in
 # Soong and soong_cc_prebuilt.mk
 ###########################################################
-ifneq ($(LOCAL_MODULE_MAKEFILE),$(SOONG_ANDROID_MK))
+ifeq (,$(LOCAL_IS_SOONG_MODULE))
 ifeq ($(LOCAL_MODULE_CLASS),SHARED_LIBRARIES)
 LOCAL_INTERMEDIATE_TARGETS += $(LOCAL_BUILT_MODULE).toc
 $(LOCAL_BUILT_MODULE).toc: $(LOCAL_BUILT_MODULE)
@@ -502,16 +505,12 @@ my_path_comp :=
 
 my_installed_symlinks :=
 
-ifneq (,$(LOCAL_SOONG_INSTALLED_MODULE))
-  # Soong already generated the copy rule, but make the installed location depend on the Make
-  # copy of the intermediates for now, as some rules that collect intermediates may expect
-  # them to exist.
-  $(LOCAL_INSTALLED_MODULE): $(LOCAL_BUILT_MODULE)
-else ifneq (true,$(LOCAL_UNINSTALLABLE_MODULE))
+ifeq (,$(LOCAL_SOONG_INSTALLED_MODULE))
+ifneq (true,$(LOCAL_UNINSTALLABLE_MODULE))
   $(LOCAL_INSTALLED_MODULE): PRIVATE_POST_INSTALL_CMD := $(LOCAL_POST_INSTALL_CMD)
   $(LOCAL_INSTALLED_MODULE): $(LOCAL_BUILT_MODULE)
 	@echo "Install: $@"
-  ifeq ($(LOCAL_MODULE_MAKEFILE),$(SOONG_ANDROID_MK))
+  ifneq (,$(LOCAL_IS_SOONG_MODULE))
 	$(copy-file-or-link-to-new-target)
   else
 	$(copy-file-to-new-target)
@@ -527,6 +526,7 @@ else ifneq (true,$(LOCAL_UNINSTALLABLE_MODULE))
   $(my_all_targets) : | $(my_installed_symlinks)
 
 endif # !LOCAL_UNINSTALLABLE_MODULE
+endif # !LOCAL_SOONG_INSTALLED_MODULE
 
 # Add dependencies on LOCAL_SOONG_INSTALL_SYMLINKS if we're installing any kind of module, not just
 # ones that set LOCAL_SOONG_INSTALLED_MODULE. This is so we can have a soong module that only
@@ -982,6 +982,15 @@ ALL_MODULES.$(my_register_name).SOONG_MODULE_TYPE := \
     $(ALL_MODULES.$(my_register_name).SOONG_MODULE_TYPE) $(LOCAL_SOONG_MODULE_TYPE)
 ALL_MODULES.$(my_register_name).IS_SOONG_MODULE := \
     $(if $(filter $(LOCAL_MODULE_MAKEFILE),$(SOONG_ANDROID_MK)),true)
+# .IS_SOONG_MODULE above will get reset to an empty string if it encounters a make module with the
+# same name as a soong module. The following 3 variables allow for more nuanced detection when it's
+# both a make and soong module.
+ALL_MODULES.$(my_register_name).IS_SOONG_MODULE_AND_POTENTIALLY_ALSO_MAKE_MODULE := \
+    $(or $(ALL_MODULES.$(my_register_name).IS_SOONG_MODULE_AND_POTENTIALLY_ALSO_MAKE_MODULE),$(if $(filter $(LOCAL_MODULE_MAKEFILE),$(SOONG_ANDROID_MK)),true))
+ALL_MODULES.$(my_register_name).IS_MAKE_MODULE_AND_POTENTIALLY_ALSO_SOONG_MODULE := \
+    $(or $(ALL_MODULES.$(my_register_name).IS_MAKE_MODULE_AND_POTENTIALLY_ALSO_SOONG_MODULE),$(if $(filter $(LOCAL_MODULE_MAKEFILE),$(SOONG_ANDROID_MK)),,true))
+ALL_MODULES.$(my_register_name).IS_MAKE_AND_SOONG_MODULE := \
+    $(and $(ALL_MODULES.$(my_register_name).IS_SOONG_MODULE_AND_POTENTIALLY_ALSO_MAKE_MODULE),$(ALL_MODULES.$(my_register_name).IS_MAKE_MODULE_AND_POTENTIALLY_ALSO_SOONG_MODULE))
 ifndef LOCAL_IS_HOST_MODULE
 ALL_MODULES.$(my_register_name).TARGET_BUILT := \
     $(ALL_MODULES.$(my_register_name).TARGET_BUILT) $(LOCAL_BUILT_MODULE)
@@ -1077,6 +1086,16 @@ ifdef LOCAL_FILESYSTEM_FILELIST
       $(ALL_MODULES.$(my_register_name).FILESYSTEM_FILELIST) $(LOCAL_FILESYSTEM_FILELIST)
 endif
 
+ifdef LOCAL_FILESYSTEM_AVB_KEY_PATH
+  ALL_MODULES.$(my_register_name).FILESYSTEM_AVB_KEY_PATH := \
+      $(ALL_MODULES.$(my_register_name).FILESYSTEM_AVB_KEY_PATH) $(LOCAL_FILESYSTEM_AVB_KEY_PATH)
+endif
+
+ifdef LOCAL_FILESYSTEM_AVB_ALGORITHM
+  ALL_MODULES.$(my_register_name).FILESYSTEM_AVB_ALGORITHM := \
+      $(ALL_MODULES.$(my_register_name).FILESYSTEM_AVB_ALGORITHM) $(LOCAL_FILESYSTEM_AVB_ALGORITHM)
+endif
+
 ifndef LOCAL_SOONG_MODULE_INFO_JSON
   ALL_MAKE_MODULE_INFO_JSON_MODULES += $(my_register_name)
   ALL_MODULES.$(my_register_name).SHARED_LIBS := \
diff --git a/core/binary.mk b/core/binary.mk
index ea862be6b4..825d58f55d 100644
--- a/core/binary.mk
+++ b/core/binary.mk
@@ -7,7 +7,6 @@
 
 #######################################
 include $(BUILD_SYSTEM)/base_rules.mk
-include $(BUILD_SYSTEM)/use_lld_setup.mk
 #######################################
 
 ##################################################
@@ -134,12 +133,12 @@ endif
 my_tidy_checks := $(subst $(space),,$(my_tidy_checks))
 
 # Configure the pool to use for clang rules.
-# If LOCAL_CC or LOCAL_CXX is set don't use goma or RBE.
+# If LOCAL_CC or LOCAL_CXX is set don't RBE.
 # If clang-tidy is being used, don't use the RBE pool (as clang-tidy runs in
 # the same action, and is not remoted)
 my_pool :=
 ifeq (,$(strip $(my_cc))$(strip $(my_cxx))$(strip $(my_tidy_checks)))
-  my_pool := $(GOMA_OR_RBE_POOL)
+  my_pool := $(RBE_POOL)
 endif
 
 ifneq (,$(strip $(foreach dir,$(NATIVE_COVERAGE_PATHS),$(filter $(dir)%,$(LOCAL_PATH)))))
@@ -1629,17 +1628,13 @@ ifndef LOCAL_IS_HOST_MODULE
 my_target_global_cflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_CFLAGS)
 my_target_global_conlyflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_CONLYFLAGS) $(my_c_std_conlyflags)
 my_target_global_cppflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_CPPFLAGS) $(my_cpp_std_cppflags)
-ifeq ($(my_use_clang_lld),true)
-  my_target_global_ldflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_LLDFLAGS)
-  include $(BUILD_SYSTEM)/pack_dyn_relocs_setup.mk
-  ifeq ($(my_pack_module_relocations),true)
-    my_target_global_ldflags += -Wl,--pack-dyn-relocs=android+relr -Wl,--use-android-relr-tags
-  else
-    my_target_global_ldflags += -Wl,--pack-dyn-relocs=none
-  endif
+my_target_global_ldflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_LDFLAGS)
+include $(BUILD_SYSTEM)/pack_dyn_relocs_setup.mk
+ifeq ($(my_pack_module_relocations),true)
+  my_target_global_ldflags += -Wl,--pack-dyn-relocs=android+relr -Wl,--use-android-relr-tags
 else
-  my_target_global_ldflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_LDFLAGS)
-endif # my_use_clang_lld
+  my_target_global_ldflags += -Wl,--pack-dyn-relocs=none
+endif
 
 ifeq ($(call module-in-vendor-or-product),true)
   my_target_global_c_includes :=
@@ -1684,11 +1679,7 @@ my_host_global_c_system_includes := $(SRC_SYSTEM_HEADERS) \
 my_host_global_cflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_CFLAGS)
 my_host_global_conlyflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_CONLYFLAGS) $(my_c_std_conlyflags)
 my_host_global_cppflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_CPPFLAGS) $(my_cpp_std_cppflags)
-ifeq ($(my_use_clang_lld),true)
-  my_host_global_ldflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_LLDFLAGS)
-else
-  my_host_global_ldflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_LDFLAGS)
-endif # my_use_clang_lld
+my_host_global_ldflags := $($(LOCAL_2ND_ARCH_VAR_PREFIX)CLANG_$(my_prefix)GLOBAL_LDFLAGS)
 
 $(LOCAL_INTERMEDIATE_TARGETS): PRIVATE_GLOBAL_C_INCLUDES := $(my_host_global_c_includes)
 $(LOCAL_INTERMEDIATE_TARGETS): PRIVATE_GLOBAL_C_SYSTEM_INCLUDES := $(my_host_global_c_system_includes)
diff --git a/core/board_config.mk b/core/board_config.mk
index cf01c8416c..9db7eddde2 100644
--- a/core/board_config.mk
+++ b/core/board_config.mk
@@ -67,6 +67,7 @@ _board_strip_readonly_list += TARGET_ARCH_SUITE
 _board_strip_readonly_list += BOARD_FLASH_BLOCK_SIZE
 _board_strip_readonly_list += BOARD_BOOTIMAGE_PARTITION_SIZE
 _board_strip_readonly_list += BOARD_INIT_BOOT_IMAGE_PARTITION_SIZE
+_board_strip_readonly_list += BOARD_INIT_BOOT_IMAGE_PAGESIZE
 _board_strip_readonly_list += BOARD_RECOVERYIMAGE_PARTITION_SIZE
 _board_strip_readonly_list += BOARD_SYSTEMIMAGE_PARTITION_SIZE
 _board_strip_readonly_list += BOARD_SYSTEMIMAGE_FILE_SYSTEM_TYPE
@@ -186,7 +187,6 @@ _build_broken_var_list := \
   BUILD_BROKEN_VENDOR_PROPERTY_NAMESPACE \
   BUILD_BROKEN_VINTF_PRODUCT_COPY_FILES \
   BUILD_BROKEN_INCORRECT_PARTITION_IMAGES \
-  BUILD_BROKEN_GENRULE_SANDBOXING \
   BUILD_BROKEN_DONT_CHECK_SYSTEMSDK \
 
 _build_broken_var_list += \
@@ -221,14 +221,14 @@ ifdef TARGET_DEVICE_DIR
   board_config_mk := $(TARGET_DEVICE_DIR)/BoardConfig.mk
 else
   board_config_mk := \
-    $(strip $(sort $(wildcard \
+    $(sort $(wildcard \
       $(SRC_TARGET_DIR)/board/$(TARGET_DEVICE)/BoardConfig.mk \
       device/generic/goldfish/board/$(TARGET_DEVICE)/BoardConfig.mk \
       device/google/cuttlefish/board/$(TARGET_DEVICE)/BoardConfig.mk \
       vendor/google/products/cuttlefish/pixel_watch/board/$(TARGET_DEVICE)/BoardConfig.mk \
       $(shell test -d device && find -L device -maxdepth 4 -path '*/$(TARGET_DEVICE)/BoardConfig.mk') \
       $(shell test -d vendor && find -L vendor -maxdepth 4 -path '*/$(TARGET_DEVICE)/BoardConfig.mk') \
-    )))
+    ))
   ifeq ($(board_config_mk),)
     $(error No config file found for TARGET_DEVICE $(TARGET_DEVICE))
   endif
@@ -294,7 +294,6 @@ include $(BUILD_SYSTEM)/board_config_wifi.mk
 
 # Set up soong config for "soong_config_value_variable".
 -include hardware/interfaces/configstore/1.1/default/surfaceflinger.mk
--include vendor/google/build/soong/soong_config_namespace/camera.mk
 
 # Default *_CPU_VARIANT_RUNTIME to CPU_VARIANT if unspecified.
 TARGET_CPU_VARIANT_RUNTIME := $(or $(TARGET_CPU_VARIANT_RUNTIME),$(TARGET_CPU_VARIANT))
@@ -933,6 +932,12 @@ ifeq ($(PRODUCT_BUILD_DESKTOP_RECOVERY_IMAGE),true)
 endif
 .KATI_READONLY := BOARD_USES_DESKTOP_RECOVERY_IMAGE
 
+BOARD_USES_DESKTOP_RECOVERY_SWAP_KERNEL :=
+ifeq ($(PRODUCT_USES_DESKTOP_RECOVERY_SWAP_KERNEL),true)
+  BOARD_USES_DESKTOP_RECOVERY_SWAP_KERNEL := true
+endif
+.KATI_READONLY := BOARD_USES_DESKTOP_RECOVERY_SWAP_KERNEL
+
 BOARD_USES_DESKTOP_UPDATE_IMAGE :=
 ifeq ($(PRODUCT_BUILD_DESKTOP_UPDATE_IMAGE),true)
   BOARD_USES_DESKTOP_UPDATE_IMAGE := true
diff --git a/core/build_id.mk b/core/build_id.mk
index 98ccf47c8d..2a000b47d1 100644
--- a/core/build_id.mk
+++ b/core/build_id.mk
@@ -18,4 +18,4 @@
 # (like "CRB01").  It must be a single word, and is
 # capitalized by convention.
 
-BUILD_ID=BP2A.250605.031.A3
+BUILD_ID=BP3A.250905.014
diff --git a/core/cc_prebuilt_internal.mk b/core/cc_prebuilt_internal.mk
index e34e110953..10d8dae95d 100644
--- a/core/cc_prebuilt_internal.mk
+++ b/core/cc_prebuilt_internal.mk
@@ -183,16 +183,6 @@ include $(BUILD_SYSTEM)/check_elf_file.mk
 ifeq ($(NATIVE_COVERAGE),true)
 ifneq (,$(strip $(LOCAL_PREBUILT_COVERAGE_ARCHIVE)))
   $(eval $(call copy-one-file,$(LOCAL_PREBUILT_COVERAGE_ARCHIVE),$(intermediates)/$(LOCAL_MODULE).gcnodir))
-  ifneq ($(LOCAL_UNINSTALLABLE_MODULE),true)
-    ifdef LOCAL_IS_HOST_MODULE
-      my_coverage_path := $($(my_prefix)OUT_COVERAGE)/$(patsubst $($(my_prefix)OUT)/%,%,$(my_module_path))
-    else
-      my_coverage_path := $(TARGET_OUT_COVERAGE)/$(patsubst $(PRODUCT_OUT)/%,%,$(my_module_path))
-    endif
-    my_coverage_path := $(my_coverage_path)/$(patsubst %.so,%,$(my_installed_module_stem)).gcnodir
-    $(eval $(call copy-one-file,$(LOCAL_PREBUILT_COVERAGE_ARCHIVE),$(my_coverage_path)))
-    $(LOCAL_BUILT_MODULE): $(my_coverage_path)
-  endif
 else
 # Coverage information is needed when static lib is a dependency of another
 # coverage-enabled module.
diff --git a/core/clear_vars.mk b/core/clear_vars.mk
index 8a98c13b1d..11e7adedc9 100644
--- a/core/clear_vars.mk
+++ b/core/clear_vars.mk
@@ -88,6 +88,7 @@ LOCAL_EXTRA_FULL_TEST_CONFIGS:=
 LOCAL_EXTRACT_APK:=
 LOCAL_EXTRACT_DPI_APK:=
 LOCAL_FILESYSTEM_FILELIST:=
+LOCAL_FILESYSTEM_AVB_KEY_PATH:=
 LOCAL_FINDBUGS_FLAGS:=
 LOCAL_FORCE_STATIC_EXECUTABLE:=
 LOCAL_FULL_CLASSES_JACOCO_JAR:=
@@ -98,7 +99,6 @@ LOCAL_FULL_MANIFEST_FILE:=
 LOCAL_FULL_TEST_CONFIG:=
 LOCAL_FULL_VINTF_FRAGMENTS:=
 LOCAL_FUZZ_ENGINE:=
-LOCAL_FUZZ_INSTALLED_SHARED_DEPS:=
 LOCAL_GCNO_FILES:=
 LOCAL_GENERATED_SOURCES:=
 # Group static libraries with "-Wl,--start-group" and "-Wl,--end-group" when linking.
@@ -265,7 +265,6 @@ LOCAL_SOONG_INSTALLED_MODULE :=
 LOCAL_SOONG_JACOCO_REPORT_CLASSES_JAR :=
 LOCAL_SOONG_LICENSE_METADATA :=
 LOCAL_SOONG_LINK_TYPE :=
-LOCAL_SOONG_LINT_REPORTS :=
 LOCAL_SOONG_LOGTAGS_FILES :=
 LOCAL_SOONG_MODULE_INFO_JSON :=
 LOCAL_SOONG_MODULE_TYPE :=
@@ -308,7 +307,6 @@ LOCAL_UNCOMPRESS_DEX:=
 LOCAL_UNINSTALLABLE_MODULE:=
 LOCAL_UNSTRIPPED_PATH:=
 LOCAL_USE_AAPT2:=
-LOCAL_USE_CLANG_LLD:=
 LOCAL_USE_VNDK:=
 LOCAL_IN_VENDOR:=
 LOCAL_IN_PRODUCT:=
diff --git a/core/combo/TARGET_linux-arm.mk b/core/combo/TARGET_linux-arm.mk
index 11c19444be..35a62faf29 100644
--- a/core/combo/TARGET_linux-arm.mk
+++ b/core/combo/TARGET_linux-arm.mk
@@ -58,12 +58,10 @@ ifeq ($(strip $(TARGET_$(combo_2nd_arch_prefix)ARCH_VARIANT)),)
   $(error TARGET_$(combo_2nd_arch_prefix)ARCH_VARIANT must be set)
 endif
 
-TARGET_ARCH_SPECIFIC_MAKEFILE := $(BUILD_COMBOS)/arch/$(TARGET_$(combo_2nd_arch_prefix)ARCH)/$(TARGET_$(combo_2nd_arch_prefix)ARCH_VARIANT).mk
-ifeq ($(strip $(wildcard $(TARGET_ARCH_SPECIFIC_MAKEFILE))),)
-  $(error Unknown ARM architecture version: $(TARGET_$(combo_2nd_arch_prefix)ARCH_VARIANT))
-endif
-
-include $(TARGET_ARCH_SPECIFIC_MAKEFILE)
+# NEON is mandatory, see: https://developer.android.com/ndk/guides/abis#v7a
+ARCH_ARM_HAVE_VFP               := true
+ARCH_ARM_HAVE_VFP_D32           := true
+ARCH_ARM_HAVE_NEON              := true
 
 define $(combo_var_prefix)transform-shared-lib-to-toc
 $(call _gen_toc_command_for_elf,$(1),$(2))
diff --git a/core/combo/TARGET_linux-arm64.mk b/core/combo/TARGET_linux-arm64.mk
index 5d481cb8fe..992dce8d99 100644
--- a/core/combo/TARGET_linux-arm64.mk
+++ b/core/combo/TARGET_linux-arm64.mk
@@ -33,13 +33,6 @@ ifeq ($(strip $(TARGET_ARCH_VARIANT)),)
 TARGET_ARCH_VARIANT := armv8
 endif
 
-TARGET_ARCH_SPECIFIC_MAKEFILE := $(BUILD_COMBOS)/arch/$(TARGET_ARCH)/$(TARGET_ARCH_VARIANT).mk
-ifeq ($(strip $(wildcard $(TARGET_ARCH_SPECIFIC_MAKEFILE))),)
-$(error Unknown ARM architecture version: $(TARGET_ARCH_VARIANT))
-endif
-
-include $(TARGET_ARCH_SPECIFIC_MAKEFILE)
-
 define $(combo_var_prefix)transform-shared-lib-to-toc
 $(call _gen_toc_command_for_elf,$(1),$(2))
 endef
diff --git a/core/combo/TARGET_linux-riscv64.mk b/core/combo/TARGET_linux-riscv64.mk
index 8f8fd3c5ba..0a6cfa4b59 100644
--- a/core/combo/TARGET_linux-riscv64.mk
+++ b/core/combo/TARGET_linux-riscv64.mk
@@ -22,17 +22,6 @@ ifeq ($(strip $(TARGET_ARCH_VARIANT)),)
 TARGET_ARCH_VARIANT := riscv64
 endif
 
-# Include the arch-variant-specific configuration file.
-# Its role is to define various ARCH_X86_HAVE_XXX feature macros,
-# plus initial values for TARGET_GLOBAL_CFLAGS
-#
-TARGET_ARCH_SPECIFIC_MAKEFILE := $(BUILD_COMBOS)/arch/$(TARGET_ARCH)/$(TARGET_ARCH_VARIANT).mk
-ifeq ($(strip $(wildcard $(TARGET_ARCH_SPECIFIC_MAKEFILE))),)
-$(error Unknown $(TARGET_ARCH) architecture version: $(TARGET_ARCH_VARIANT))
-endif
-
-include $(TARGET_ARCH_SPECIFIC_MAKEFILE)
-
 define $(combo_var_prefix)transform-shared-lib-to-toc
 $(call _gen_toc_command_for_elf,$(1),$(2))
 endef
diff --git a/core/combo/TARGET_linux-x86.mk b/core/combo/TARGET_linux-x86.mk
index acbae519fe..9ab6880b7e 100644
--- a/core/combo/TARGET_linux-x86.mk
+++ b/core/combo/TARGET_linux-x86.mk
@@ -22,17 +22,6 @@ ifeq ($(strip $(TARGET_$(combo_2nd_arch_prefix)ARCH_VARIANT)),)
 TARGET_$(combo_2nd_arch_prefix)ARCH_VARIANT := x86
 endif
 
-# Include the arch-variant-specific configuration file.
-# Its role is to define various ARCH_X86_HAVE_XXX feature macros,
-# plus initial values for TARGET_GLOBAL_CFLAGS
-#
-TARGET_ARCH_SPECIFIC_MAKEFILE := $(BUILD_COMBOS)/arch/$(TARGET_$(combo_2nd_arch_prefix)ARCH)/$(TARGET_$(combo_2nd_arch_prefix)ARCH_VARIANT).mk
-ifeq ($(strip $(wildcard $(TARGET_ARCH_SPECIFIC_MAKEFILE))),)
-$(error Unknown $(TARGET_$(combo_2nd_arch_prefix)ARCH) architecture version: $(TARGET_$(combo_2nd_arch_prefix)ARCH_VARIANT))
-endif
-
-include $(TARGET_ARCH_SPECIFIC_MAKEFILE)
-
 define $(combo_var_prefix)transform-shared-lib-to-toc
 $(call _gen_toc_command_for_elf,$(1),$(2))
 endef
diff --git a/core/combo/TARGET_linux-x86_64.mk b/core/combo/TARGET_linux-x86_64.mk
index 9e7e3630d1..6dd7b03428 100644
--- a/core/combo/TARGET_linux-x86_64.mk
+++ b/core/combo/TARGET_linux-x86_64.mk
@@ -22,17 +22,6 @@ ifeq ($(strip $(TARGET_ARCH_VARIANT)),)
 TARGET_ARCH_VARIANT := x86_64
 endif
 
-# Include the arch-variant-specific configuration file.
-# Its role is to define various ARCH_X86_HAVE_XXX feature macros,
-# plus initial values for TARGET_GLOBAL_CFLAGS
-#
-TARGET_ARCH_SPECIFIC_MAKEFILE := $(BUILD_COMBOS)/arch/$(TARGET_ARCH)/$(TARGET_ARCH_VARIANT).mk
-ifeq ($(strip $(wildcard $(TARGET_ARCH_SPECIFIC_MAKEFILE))),)
-$(error Unknown $(TARGET_ARCH) architecture version: $(TARGET_ARCH_VARIANT))
-endif
-
-include $(TARGET_ARCH_SPECIFIC_MAKEFILE)
-
 define $(combo_var_prefix)transform-shared-lib-to-toc
 $(call _gen_toc_command_for_elf,$(1),$(2))
 endef
diff --git a/core/combo/arch/arm/armv7-a-neon.mk b/core/combo/arch/arm/armv7-a-neon.mk
deleted file mode 100644
index 0c01ac3efd..0000000000
--- a/core/combo/arch/arm/armv7-a-neon.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on ARM.
-# Generating binaries for the ARMv7-a architecture and higher with NEON
-#
-ARCH_ARM_HAVE_VFP               := true
-ARCH_ARM_HAVE_VFP_D32           := true
-ARCH_ARM_HAVE_NEON              := true
diff --git a/core/combo/arch/arm/armv8-2a.mk b/core/combo/arch/arm/armv8-2a.mk
deleted file mode 100644
index 7e2ca18aa8..0000000000
--- a/core/combo/arch/arm/armv8-2a.mk
+++ /dev/null
@@ -1,8 +0,0 @@
-# Configuration for Linux on ARM.
-# Generating binaries for the ARMv8-2a architecture
-#
-# Many libraries are not aware of armv8-2a, and AArch32 is (almost) a superset
-# of armv7-a-neon. So just let them think we are just like v7.
-ARCH_ARM_HAVE_VFP               := true
-ARCH_ARM_HAVE_VFP_D32           := true
-ARCH_ARM_HAVE_NEON              := true
diff --git a/core/combo/arch/arm/armv8-a.mk b/core/combo/arch/arm/armv8-a.mk
deleted file mode 100644
index 19bc014382..0000000000
--- a/core/combo/arch/arm/armv8-a.mk
+++ /dev/null
@@ -1,8 +0,0 @@
-# Configuration for Linux on ARM.
-# Generating binaries for the ARMv8-a architecture
-#
-# Many libraries are not aware of armv8-a, and AArch32 is (almost) a superset
-# of armv7-a-neon. So just let them think we are just like v7.
-ARCH_ARM_HAVE_VFP               := true
-ARCH_ARM_HAVE_VFP_D32           := true
-ARCH_ARM_HAVE_NEON              := true
diff --git a/core/combo/arch/arm64/armv8-2a-dotprod.mk b/core/combo/arch/arm64/armv8-2a-dotprod.mk
deleted file mode 100644
index c775cf7bec..0000000000
--- a/core/combo/arch/arm64/armv8-2a-dotprod.mk
+++ /dev/null
@@ -1,19 +0,0 @@
-#
-# Copyright (C) 2020 The Android Open Source Project
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
-#
-
-# .mk file required to support build for the new armv8-2a-dotprod Arm64 arch
-# variant. The file just needs to be present but does not require to contain
-# anything
diff --git a/core/combo/arch/arm64/armv8-2a.mk b/core/combo/arch/arm64/armv8-2a.mk
deleted file mode 100644
index e69de29bb2..0000000000
diff --git a/core/combo/arch/arm64/armv8-a-branchprot.mk b/core/combo/arch/arm64/armv8-a-branchprot.mk
deleted file mode 100644
index 77f353515f..0000000000
--- a/core/combo/arch/arm64/armv8-a-branchprot.mk
+++ /dev/null
@@ -1,19 +0,0 @@
-#
-# Copyright (C) 2021 The Android Open Source Project
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
-#
-
-# .mk file required to support build for the new armv8-a-branchprot Arm64 arch
-# variant. The file just needs to be present but does not require to contain
-# anything
diff --git a/core/combo/arch/arm64/armv8-a.mk b/core/combo/arch/arm64/armv8-a.mk
deleted file mode 100644
index e69de29bb2..0000000000
diff --git a/core/combo/arch/arm64/armv9-2a.mk b/core/combo/arch/arm64/armv9-2a.mk
deleted file mode 100644
index 69ffde014b..0000000000
--- a/core/combo/arch/arm64/armv9-2a.mk
+++ /dev/null
@@ -1,18 +0,0 @@
-#
-# Copyright (C) 2023 The Android Open Source Project
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
-#
-
-# .mk file required to support build for the ARMv9.2-A arch variant.
-# The file just needs to be present, it does not need to contain anything.
diff --git a/core/combo/arch/arm64/armv9-3a.mk b/core/combo/arch/arm64/armv9-3a.mk
deleted file mode 100644
index 0f2c620eeb..0000000000
--- a/core/combo/arch/arm64/armv9-3a.mk
+++ /dev/null
@@ -1,18 +0,0 @@
-#
-# Copyright (C) 2025 The Android Open Source Project
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
-#
-
-# .mk file required to support build for the ARMv9.3-A arch variant.
-# The file just needs to be present, it does not need to contain anything.
diff --git a/core/combo/arch/arm64/armv9-4a.mk b/core/combo/arch/arm64/armv9-4a.mk
deleted file mode 100644
index 6ab3bed875..0000000000
--- a/core/combo/arch/arm64/armv9-4a.mk
+++ /dev/null
@@ -1,18 +0,0 @@
-#
-# Copyright (C) 2025 The Android Open Source Project
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
-#
-
-# .mk file required to support build for the ARMv9.4-A arch variant.
-# The file just needs to be present, it does not need to contain anything.
diff --git a/core/combo/arch/arm64/armv9-a.mk b/core/combo/arch/arm64/armv9-a.mk
deleted file mode 100644
index de0760ae23..0000000000
--- a/core/combo/arch/arm64/armv9-a.mk
+++ /dev/null
@@ -1,19 +0,0 @@
-#
-# Copyright (C) 2023 The Android Open Source Project
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
-#
-
-# .mk file required to support build for the new armv9-a Arm64 arch
-# variant. The file just needs to be present but does not require to contain
-# anything
diff --git a/core/combo/arch/riscv64/riscv64.mk b/core/combo/arch/riscv64/riscv64.mk
deleted file mode 100644
index 0505541749..0000000000
--- a/core/combo/arch/riscv64/riscv64.mk
+++ /dev/null
@@ -1,2 +0,0 @@
-# This file contains feature macro definitions specific to the
-# base 'riscv64' platform ABI.
diff --git a/core/combo/arch/x86/alderlake.mk b/core/combo/arch/x86/alderlake.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86/alderlake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/amberlake.mk b/core/combo/arch/x86/amberlake.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86/amberlake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/atom.mk b/core/combo/arch/x86/atom.mk
deleted file mode 100644
index bae7946722..0000000000
--- a/core/combo/arch/x86/atom.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# This file contains feature macro definitions specific to the
-# 'x86-atom' arch variant. This is an extension of the 'x86' base variant
-# that adds Atom-specific features.
-#
-# See build/make/core/combo/arch/x86/x86.mk for differences.
-#
diff --git a/core/combo/arch/x86/broadwell.mk b/core/combo/arch/x86/broadwell.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86/broadwell.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/goldmont-plus.mk b/core/combo/arch/x86/goldmont-plus.mk
deleted file mode 100644
index 4ce205344c..0000000000
--- a/core/combo/arch/x86/goldmont-plus.mk
+++ /dev/null
@@ -1,7 +0,0 @@
-# This file contains feature macro definitions specific to the
-# goldmont-plus arch variant.
-#
-# See build/make/core/combo/arch/x86/x86-atom.mk for differences.
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/goldmont-without-sha-xsaves.mk b/core/combo/arch/x86/goldmont-without-sha-xsaves.mk
deleted file mode 100644
index 1b93c17c69..0000000000
--- a/core/combo/arch/x86/goldmont-without-sha-xsaves.mk
+++ /dev/null
@@ -1,7 +0,0 @@
-# This file contains feature macro definitions specific to the
-# goldmont-without-xsaves arch variant.
-#
-# See build/make/core/combo/arch/x86/x86-atom.mk for differences.
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/goldmont.mk b/core/combo/arch/x86/goldmont.mk
deleted file mode 100644
index b5a6ff242b..0000000000
--- a/core/combo/arch/x86/goldmont.mk
+++ /dev/null
@@ -1,7 +0,0 @@
-# This file contains feature macro definitions specific to the
-# goldmont arch variant.
-#
-# See build/make/core/combo/arch/x86/x86-atom.mk for differences.
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/haswell.mk b/core/combo/arch/x86/haswell.mk
deleted file mode 100644
index ffa3bac8cf..0000000000
--- a/core/combo/arch/x86/haswell.mk
+++ /dev/null
@@ -1,4 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for Haswell processors.
-#
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/icelake.mk b/core/combo/arch/x86/icelake.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86/icelake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/ivybridge.mk b/core/combo/arch/x86/ivybridge.mk
deleted file mode 100644
index a1358e63fd..0000000000
--- a/core/combo/arch/x86/ivybridge.mk
+++ /dev/null
@@ -1,4 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for Ivy Bridge processors.
-#
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/kabylake.mk b/core/combo/arch/x86/kabylake.mk
deleted file mode 100644
index 9906259215..0000000000
--- a/core/combo/arch/x86/kabylake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors.
-# that support AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/sandybridge.mk b/core/combo/arch/x86/sandybridge.mk
deleted file mode 100644
index d6552ab2fb..0000000000
--- a/core/combo/arch/x86/sandybridge.mk
+++ /dev/null
@@ -1,4 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for SandyBridge processors.
-#
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/silvermont.mk b/core/combo/arch/x86/silvermont.mk
deleted file mode 100644
index 8ac2b98ef6..0000000000
--- a/core/combo/arch/x86/silvermont.mk
+++ /dev/null
@@ -1,7 +0,0 @@
-# This file contains feature macro definitions specific to the
-# silvermont arch variant.
-#
-# See build/make/core/combo/arch/x86/x86-atom.mk for differences.
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/skylake.mk b/core/combo/arch/x86/skylake.mk
deleted file mode 100644
index 9906259215..0000000000
--- a/core/combo/arch/x86/skylake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors.
-# that support AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/stoneyridge.mk b/core/combo/arch/x86/stoneyridge.mk
deleted file mode 100644
index 05ff77aa69..0000000000
--- a/core/combo/arch/x86/stoneyridge.mk
+++ /dev/null
@@ -1,4 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for Stoney Ridge processors.
-#
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/tigerlake.mk b/core/combo/arch/x86/tigerlake.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86/tigerlake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/tremont.mk b/core/combo/arch/x86/tremont.mk
deleted file mode 100644
index b80d228f0e..0000000000
--- a/core/combo/arch/x86/tremont.mk
+++ /dev/null
@@ -1,7 +0,0 @@
-# This file contains feature macro definitions specific to the
-# tremont arch variant.
-#
-# See build/make/core/combo/arch/x86/x86-atom.mk for differences.
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/whiskeylake.mk b/core/combo/arch/x86/whiskeylake.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86/whiskeylake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86/x86.mk b/core/combo/arch/x86/x86.mk
deleted file mode 100644
index 066f66ab6b..0000000000
--- a/core/combo/arch/x86/x86.mk
+++ /dev/null
@@ -1,10 +0,0 @@
-# This file contains feature macro definitions specific to the
-# base 'x86' platform ABI.
-#
-# It is also used to build full_x86-eng / sdk_x86-eng platform images that
-# are run in the emulator under KVM emulation (i.e. running directly on
-# the host development machine's CPU).
-
-# These features are optional and shall not be included in the base platform
-# Otherwise, sdk_x86-eng system images might fail to run on some
-# developer machines.
diff --git a/core/combo/arch/x86/x86_64.mk b/core/combo/arch/x86/x86_64.mk
deleted file mode 100644
index eff406b47d..0000000000
--- a/core/combo/arch/x86/x86_64.mk
+++ /dev/null
@@ -1,7 +0,0 @@
-# This file is used as the second (32-bit) architecture when building a generic
-# x86_64 64-bit platform image. (full_x86_64-eng / sdk_x86_64-eng)
-#
-# The generic 'x86' variant cannot be used, since it resets some flags used
-# by the 'x86_64' variant.
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/alderlake.mk b/core/combo/arch/x86_64/alderlake.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86_64/alderlake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/amberlake.mk b/core/combo/arch/x86_64/amberlake.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86_64/amberlake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/broadwell.mk b/core/combo/arch/x86_64/broadwell.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86_64/broadwell.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/goldmont-plus.mk b/core/combo/arch/x86_64/goldmont-plus.mk
deleted file mode 100644
index 4ce205344c..0000000000
--- a/core/combo/arch/x86_64/goldmont-plus.mk
+++ /dev/null
@@ -1,7 +0,0 @@
-# This file contains feature macro definitions specific to the
-# goldmont-plus arch variant.
-#
-# See build/make/core/combo/arch/x86/x86-atom.mk for differences.
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/goldmont-without-sha-xsaves.mk b/core/combo/arch/x86_64/goldmont-without-sha-xsaves.mk
deleted file mode 100644
index 1b93c17c69..0000000000
--- a/core/combo/arch/x86_64/goldmont-without-sha-xsaves.mk
+++ /dev/null
@@ -1,7 +0,0 @@
-# This file contains feature macro definitions specific to the
-# goldmont-without-xsaves arch variant.
-#
-# See build/make/core/combo/arch/x86/x86-atom.mk for differences.
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/goldmont.mk b/core/combo/arch/x86_64/goldmont.mk
deleted file mode 100644
index b5a6ff242b..0000000000
--- a/core/combo/arch/x86_64/goldmont.mk
+++ /dev/null
@@ -1,7 +0,0 @@
-# This file contains feature macro definitions specific to the
-# goldmont arch variant.
-#
-# See build/make/core/combo/arch/x86/x86-atom.mk for differences.
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/haswell.mk b/core/combo/arch/x86_64/haswell.mk
deleted file mode 100644
index faf12fa9af..0000000000
--- a/core/combo/arch/x86_64/haswell.mk
+++ /dev/null
@@ -1,4 +0,0 @@
-# Configuration for Linux on x86_64.
-# Generating binaries for Haswell processors.
-#
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/icelake.mk b/core/combo/arch/x86_64/icelake.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86_64/icelake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/ivybridge.mk b/core/combo/arch/x86_64/ivybridge.mk
deleted file mode 100644
index 464fa98854..0000000000
--- a/core/combo/arch/x86_64/ivybridge.mk
+++ /dev/null
@@ -1,4 +0,0 @@
-# Configuration for Linux on x86_64.
-# Generating binaries for Ivy Bridge processors.
-#
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/kabylake.mk b/core/combo/arch/x86_64/kabylake.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86_64/kabylake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/sandybridge.mk b/core/combo/arch/x86_64/sandybridge.mk
deleted file mode 100644
index a09db2a87d..0000000000
--- a/core/combo/arch/x86_64/sandybridge.mk
+++ /dev/null
@@ -1,4 +0,0 @@
-# Configuration for Linux on x86_64.
-# Generating binaries for SandyBridge processors.
-#
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/silvermont.mk b/core/combo/arch/x86_64/silvermont.mk
deleted file mode 100644
index 8ac2b98ef6..0000000000
--- a/core/combo/arch/x86_64/silvermont.mk
+++ /dev/null
@@ -1,7 +0,0 @@
-# This file contains feature macro definitions specific to the
-# silvermont arch variant.
-#
-# See build/make/core/combo/arch/x86/x86-atom.mk for differences.
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/skylake.mk b/core/combo/arch/x86_64/skylake.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86_64/skylake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/stoneyridge.mk b/core/combo/arch/x86_64/stoneyridge.mk
deleted file mode 100644
index 5950d9abde..0000000000
--- a/core/combo/arch/x86_64/stoneyridge.mk
+++ /dev/null
@@ -1,4 +0,0 @@
-# Configuration for Linux on x86_64.
-# Generating binaries for Stoney Ridge processors.
-#
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/tigerlake.mk b/core/combo/arch/x86_64/tigerlake.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86_64/tigerlake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/tremont.mk b/core/combo/arch/x86_64/tremont.mk
deleted file mode 100644
index b80d228f0e..0000000000
--- a/core/combo/arch/x86_64/tremont.mk
+++ /dev/null
@@ -1,7 +0,0 @@
-# This file contains feature macro definitions specific to the
-# tremont arch variant.
-#
-# See build/make/core/combo/arch/x86/x86-atom.mk for differences.
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/whiskeylake.mk b/core/combo/arch/x86_64/whiskeylake.mk
deleted file mode 100644
index a7ae6ed679..0000000000
--- a/core/combo/arch/x86_64/whiskeylake.mk
+++ /dev/null
@@ -1,6 +0,0 @@
-# Configuration for Linux on x86.
-# Generating binaries for processors
-# that have AVX2 feature flag
-#
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/combo/arch/x86_64/x86_64.mk b/core/combo/arch/x86_64/x86_64.mk
deleted file mode 100755
index 17413c7537..0000000000
--- a/core/combo/arch/x86_64/x86_64.mk
+++ /dev/null
@@ -1,8 +0,0 @@
-# This file contains feature macro definitions specific to the
-# base 'x86_64' platform ABI.
-#
-# It is also used to build full_x86_64-eng / sdk_x86_64-eng  platform images
-# that are run in the emulator under KVM emulation (i.e. running directly on
-# the host development machine's CPU).
-
-ARCH_X86_HAVE_SSE4_1 := true
diff --git a/core/config.mk b/core/config.mk
index 38f3f5b802..58d3b944db 100644
--- a/core/config.mk
+++ b/core/config.mk
@@ -108,6 +108,7 @@ $(KATI_obsolete_var TARGET_ROOT_OUT_SBIN_UNSTRIPPED,/sbin has been removed, use
 $(KATI_obsolete_var BUILD_BROKEN_PHONY_TARGETS)
 $(KATI_obsolete_var BUILD_BROKEN_DUP_COPY_HEADERS)
 $(KATI_obsolete_var BUILD_BROKEN_ENG_DEBUG_TAGS)
+$(KATI_obsolete_var BUILD_BROKEN_GENRULE_SANDBOXING)
 $(KATI_obsolete_export It is a global setting. See $(CHANGES_URL)#export_keyword)
 $(KATI_obsolete_var BUILD_BROKEN_ANDROIDMK_EXPORTS)
 $(KATI_obsolete_var PRODUCT_NOTICE_SPLIT_OVERRIDE,Stop using this, keep calm, and carry on.)
@@ -174,6 +175,8 @@ $(KATI_obsolete_var BUILDING_PVMFW_IMAGE,BUILDING_PVMFW_IMAGE is no longer used)
 $(KATI_obsolete_var BOARD_BUILD_SYSTEM_ROOT_IMAGE)
 $(KATI_obsolete_var FS_GET_STATS)
 $(KATI_obsolete_var BUILD_BROKEN_USES_SOONG_PYTHON2_MODULES)
+$(KATI_obsolete_var BOARD_SYSTEM_EXT_PREBUILT_DIR,Use BOARD_SYSTEM_EXT_SEPOLICY_PREBUILT_DIRS instead)
+$(KATI_obsolete_var BOARD_PRODUCT_PREBUILT_DIR,Use BOARD_PRODUCT_SEPOLICY_PREBUILT_DIRS instead)
 
 # Used to force goals to build.  Only use for conditionally defined goals.
 .PHONY: FORCE
@@ -685,12 +688,6 @@ BISON_DATA :=$=
 YASM := prebuilts/misc/$(BUILD_OS)-$(HOST_PREBUILT_ARCH)/yasm/yasm
 
 DOXYGEN:= doxygen
-ifeq ($(HOST_OS),linux)
-BREAKPAD_DUMP_SYMS := $(HOST_OUT_EXECUTABLES)/dump_syms
-else
-# For non-supported hosts, do not generate breakpad symbols.
-BREAKPAD_GENERATE_SYMBOLS := false
-endif
 GZIP := prebuilts/build-tools/path/$(BUILD_OS)-$(HOST_PREBUILT_ARCH)/gzip
 PROTOC := $(HOST_OUT_EXECUTABLES)/aprotoc$(HOST_EXECUTABLE_SUFFIX)
 NANOPB_SRCS := $(HOST_OUT_EXECUTABLES)/protoc-gen-nanopb
@@ -716,6 +713,7 @@ MKF2FSUSERIMG := $(HOST_OUT_EXECUTABLES)/mkf2fsuserimg
 SIMG2IMG := $(HOST_OUT_EXECUTABLES)/simg2img$(HOST_EXECUTABLE_SUFFIX)
 E2FSCK := $(HOST_OUT_EXECUTABLES)/e2fsck$(HOST_EXECUTABLE_SUFFIX)
 TUNE2FS := $(HOST_OUT_EXECUTABLES)/tune2fs$(HOST_EXECUTABLE_SUFFIX)
+SGDISK := $(HOST_OUT_EXECUTABLES)/sgdisk
 JARJAR := $(HOST_OUT_JAVA_LIBRARIES)/jarjar.jar
 DATA_BINDING_COMPILER := $(HOST_OUT_JAVA_LIBRARIES)/databinding-compiler.jar
 FAT16COPY := build/make/tools/fat16copy.py
@@ -736,6 +734,7 @@ OTA_FROM_RAW_IMG := $(HOST_OUT_EXECUTABLES)/ota_from_raw_img$(HOST_EXECUTABLE_SU
 SPARSE_IMG := $(HOST_OUT_EXECUTABLES)/sparse_img$(HOST_EXECUTABLE_SUFFIX)
 CHECK_PARTITION_SIZES := $(HOST_OUT_EXECUTABLES)/check_partition_sizes$(HOST_EXECUTABLE_SUFFIX)
 SYMBOLS_MAP := $(HOST_OUT_EXECUTABLES)/symbols_map
+ZSTD := $(HOST_OUT_EXECUTABLES)/zstd
 
 PROGUARD_HOME := external/proguard
 PROGUARD := $(PROGUARD_HOME)/bin/proguard.sh
@@ -895,19 +894,6 @@ ifeq ($(call math_gt,$(BOARD_API_LEVEL),$(BOARD_GENFS_LABELS_VERSION)),true)
   $(error BOARD_GENFS_LABELS_VERSION ($(BOARD_GENFS_LABELS_VERSION)) must be greater than or equal to BOARD_API_LEVEL ($(BOARD_API_LEVEL)))
 endif
 
-ifeq ($(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS),true)
-  ifneq ($(PRODUCT_USE_DYNAMIC_PARTITIONS),true)
-    $(error PRODUCT_USE_DYNAMIC_PARTITIONS must be true when PRODUCT_RETROFIT_DYNAMIC_PARTITIONS \
-        is set)
-  endif
-  ifdef PRODUCT_SHIPPING_API_LEVEL
-    ifeq (true,$(call math_gt_or_eq,$(PRODUCT_SHIPPING_API_LEVEL),29))
-      $(error Devices with shipping API level $(PRODUCT_SHIPPING_API_LEVEL) must not set \
-          PRODUCT_RETROFIT_DYNAMIC_PARTITIONS)
-    endif
-  endif
-endif
-
 ifeq ($(PRODUCT_USE_DYNAMIC_PARTITIONS),true)
     ifneq ($(PRODUCT_USE_DYNAMIC_PARTITION_SIZE),true)
         $(error PRODUCT_USE_DYNAMIC_PARTITION_SIZE must be true for devices with dynamic partitions)
@@ -1009,41 +995,6 @@ BOARD_SUPER_PARTITION_PARTITION_LIST := \
 .KATI_READONLY := BOARD_SUPER_PARTITION_PARTITION_LIST
 
 ifneq ($(BOARD_SUPER_PARTITION_SIZE),)
-ifeq ($(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS),true)
-
-# The metadata device must be specified manually for retrofitting.
-ifeq ($(BOARD_SUPER_PARTITION_METADATA_DEVICE),)
-$(error Must specify BOARD_SUPER_PARTITION_METADATA_DEVICE if PRODUCT_RETROFIT_DYNAMIC_PARTITIONS=true.)
-endif
-
-# The super partition block device list must be specified manually for retrofitting.
-ifeq ($(BOARD_SUPER_PARTITION_BLOCK_DEVICES),)
-$(error Must specify BOARD_SUPER_PARTITION_BLOCK_DEVICES if PRODUCT_RETROFIT_DYNAMIC_PARTITIONS=true.)
-endif
-
-# The metadata device must be included in the super partition block device list.
-ifeq (,$(filter $(BOARD_SUPER_PARTITION_METADATA_DEVICE),$(BOARD_SUPER_PARTITION_BLOCK_DEVICES)))
-$(error BOARD_SUPER_PARTITION_METADATA_DEVICE is not listed in BOARD_SUPER_PARTITION_BLOCK_DEVICES.)
-endif
-
-# The metadata device must be supplied to init via the kernel command-line.
-INTERNAL_KERNEL_CMDLINE += androidboot.super_partition=$(BOARD_SUPER_PARTITION_METADATA_DEVICE)
-
-BOARD_BUILD_RETROFIT_DYNAMIC_PARTITIONS_OTA_PACKAGE := true
-
-# If "vendor" is listed as one of the dynamic partitions but without its image available (e.g. an
-# AOSP target built without vendor image), don't build the retrofit full OTA package. Because we
-# won't be able to build meaningful super_* images for retrofitting purpose.
-ifneq (,$(filter vendor,$(BOARD_SUPER_PARTITION_PARTITION_LIST)))
-ifndef BUILDING_VENDOR_IMAGE
-ifndef BOARD_PREBUILT_VENDORIMAGE
-BOARD_BUILD_RETROFIT_DYNAMIC_PARTITIONS_OTA_PACKAGE :=
-endif # BOARD_PREBUILT_VENDORIMAGE
-endif # BUILDING_VENDOR_IMAGE
-endif # BOARD_SUPER_PARTITION_PARTITION_LIST
-
-else # PRODUCT_RETROFIT_DYNAMIC_PARTITIONS
-
 # For normal devices, we populate BOARD_SUPER_PARTITION_BLOCK_DEVICES so the
 # build can handle both cases consistently.
 ifeq ($(BOARD_SUPER_PARTITION_METADATA_DEVICE),)
@@ -1063,16 +1014,12 @@ endif
 ifneq ($(BOARD_SUPER_PARTITION_METADATA_DEVICE),super)
 INTERNAL_KERNEL_CMDLINE += androidboot.super_partition=$(BOARD_SUPER_PARTITION_METADATA_DEVICE)
 endif
-BOARD_BUILD_RETROFIT_DYNAMIC_PARTITIONS_OTA_PACKAGE :=
 
-endif # PRODUCT_RETROFIT_DYNAMIC_PARTITIONS
 endif # BOARD_SUPER_PARTITION_SIZE
 BOARD_SUPER_PARTITION_BLOCK_DEVICES ?=
 .KATI_READONLY := BOARD_SUPER_PARTITION_BLOCK_DEVICES
 BOARD_SUPER_PARTITION_METADATA_DEVICE ?=
 .KATI_READONLY := BOARD_SUPER_PARTITION_METADATA_DEVICE
-BOARD_BUILD_RETROFIT_DYNAMIC_PARTITIONS_OTA_PACKAGE ?=
-.KATI_READONLY := BOARD_BUILD_RETROFIT_DYNAMIC_PARTITIONS_OTA_PACKAGE
 
 $(foreach device,$(call to-upper,$(BOARD_SUPER_PARTITION_BLOCK_DEVICES)), \
     $(eval BOARD_SUPER_PARTITION_$(device)_DEVICE_SIZE := $(strip $(BOARD_SUPER_PARTITION_$(device)_DEVICE_SIZE))) \
@@ -1217,20 +1164,14 @@ define find_warning_allowed_projects
     $(filter $(ANDROID_WARNING_ALLOWED_PROJECTS),$(1)/)
 endef
 
-GOMA_POOL :=
 RBE_POOL :=
-GOMA_OR_RBE_POOL :=
-# When goma or RBE are enabled, kati will be passed --default_pool=local_pool to put
+# When RBE is enabled, kati will be passed --default_pool=local_pool to put
 # most rules into the local pool.  Explicitly set the pool to "none" for rules that
 # should be run outside the local pool, i.e. with -j500.
-ifneq (,$(filter-out false,$(USE_GOMA)))
-  GOMA_POOL := none
-  GOMA_OR_RBE_POOL := none
-else ifneq (,$(filter-out false,$(USE_RBE)))
+ifneq (,$(filter-out false,$(USE_RBE)))
   RBE_POOL := none
-  GOMA_OR_RBE_POOL := none
 endif
-.KATI_READONLY := GOMA_POOL RBE_POOL GOMA_OR_RBE_POOL
+.KATI_READONLY := RBE_POOL
 
 JAVAC_NINJA_POOL :=
 R8_NINJA_POOL :=
@@ -1250,9 +1191,6 @@ endif
 
 .KATI_READONLY := JAVAC_NINJA_POOL R8_NINJA_POOL D8_NINJA_POOL
 
-# Soong modules that are known to have broken optional_uses_libs dependencies.
-BUILD_WARNING_BAD_OPTIONAL_USES_LIBS_ALLOWLIST := LegacyCamera Gallery2
-
 # These goals don't need to collect and include Android.mks/CleanSpec.mks
 # in the source tree.
 dont_bother_goals := out product-graph
@@ -1366,7 +1304,7 @@ BUILD_THUMBPRINT_FILE := $(PRODUCT_OUT)/build_thumbprint.txt
 ifeq ($(strip $(HAS_BUILD_NUMBER)),true)
 $(BUILD_THUMBPRINT_FILE): $(BUILD_NUMBER_FILE)
 endif
-ifneq (,$(shell mkdir -p $(PRODUCT_OUT) && echo $(BUILD_THUMBPRINT) >$(BUILD_THUMBPRINT_FILE) && grep " " $(BUILD_THUMBPRINT_FILE)))
+ifneq (,$(shell mkdir -p $(PRODUCT_OUT) && echo $(BUILD_THUMBPRINT) >$(BUILD_THUMBPRINT_FILE).tmp && (if ! cmp -s $(BUILD_THUMBPRINT_FILE).tmp $(BUILD_THUMBPRINT_FILE); then mv $(BUILD_THUMBPRINT_FILE).tmp $(BUILD_THUMBPRINT_FILE); else rm $(BUILD_THUMBPRINT_FILE).tmp; fi) && grep " " $(BUILD_THUMBPRINT_FILE)))
   $(error BUILD_THUMBPRINT cannot contain spaces: "$(file <$(BUILD_THUMBPRINT_FILE))")
 endif
 # unset it for safety.
diff --git a/core/definitions.mk b/core/definitions.mk
index ea151fac37..5d6abe8bab 100644
--- a/core/definitions.mk
+++ b/core/definitions.mk
@@ -1433,7 +1433,7 @@ $(hide) $(PRIVATE_CXX_LINK) -fuse-ld=lld -target $(CLANG_TARGET_TRIPLE) -shared
   -Wl,-rpath,\$$ORIGIN/../lib \
   $(dir $@)/$(notdir $(<:.bc=.o)) \
   $(RS_PREBUILT_COMPILER_RT) \
-  -o $@ $(CLANG_TARGET_GLOBAL_LLDFLAGS) -Wl,--hash-style=sysv \
+  -o $@ $(CLANG_TARGET_GLOBAL_LDFLAGS) -Wl,--hash-style=sysv \
   -L $(SOONG_OUT_DIR)/ndk/platforms/android-$(PRIVATE_SDK_VERSION)/arch-$(TARGET_ARCH)/usr/lib64 \
   -L $(SOONG_OUT_DIR)/ndk/platforms/android-$(PRIVATE_SDK_VERSION)/arch-$(TARGET_ARCH)/usr/lib \
   $(call intermediates-dir-for,SHARED_LIBRARIES,libRSSupport)/libRSSupport.so \
@@ -3680,21 +3680,24 @@ $(foreach suite, $(LOCAL_COMPATIBILITY_SUITE), \
   $(eval COMPATIBILITY.$(suite).ARCH_DIRS.$(my_register_name) := $(my_compat_module_arch_dir_$(suite).$(my_register_name))) \
   $(eval COMPATIBILITY.$(suite).API_MAP_FILES += $$(my_compat_api_map_$(suite))) \
   $(eval COMPATIBILITY.$(suite).SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES += $(LOCAL_SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES)) \
-  $(eval ALL_COMPATIBILITY_DIST_FILES += $$(my_compat_dist_$(suite))) \
+  $(if $(LOCAL_IS_SOONG_MODULE),, \
+    $(eval ALL_COMPATIBILITY_DIST_FILES += $$(my_compat_dist_$(suite)))) \
   $(eval COMPATIBILITY.$(suite).MODULES += $$(my_register_name))) \
 $(eval $(my_all_targets) : \
   $(sort $(foreach suite,$(LOCAL_COMPATIBILITY_SUITE), \
     $(foreach f,$(my_compat_dist_$(suite)), $(call word-colon,2,$(f))))) \
-  $(call copy-many-xml-files-checked, \
-    $(sort $(foreach suite,$(LOCAL_COMPATIBILITY_SUITE),$(my_compat_dist_config_$(suite))))))
+  $(if $(LOCAL_IS_SOONG_MODULE), \
+    $(sort $(foreach p,$(foreach suite,$(LOCAL_COMPATIBILITY_SUITE),$(my_compat_dist_config_$(suite))),$(call word-colon,2,$(p)))), \
+    $(call copy-many-xml-files-checked, \
+      $(sort $(foreach suite,$(LOCAL_COMPATIBILITY_SUITE),$(my_compat_dist_config_$(suite)))))))
 endef
 
 # Define symbols.zip and symbols-mapping.textproto build rule per test suite
 #
 # $(1): Name of the test suite to create the zip and mapping build rules
 define create-suite-symbols-map
-_suite_symbols_zip := $$(subst -tests-,-tests_-,$$(PRODUCT_OUT)/$(1)-symbols.zip)
-_suite_symbols_mapping := $$(subst -tests-,-tests_-,$$(PRODUCT_OUT)/$(1)-symbols-mapping.textproto)
+_suite_symbols_zip := $$(PRODUCT_OUT)/$(1)-symbols.zip
+_suite_symbols_mapping := $$(PRODUCT_OUT)/$(1)-symbols-mapping.textproto
 _suite_modules_symbols_files := $$(foreach m,$$(COMPATIBILITY.$(1).MODULES),$$(ALL_MODULES.$$(m).SYMBOLIC_OUTPUT_PATH))
 _suite_modules_mapping_files := $$(foreach m,$$(COMPATIBILITY.$(1).MODULES),$$(ALL_MODULES.$$(m).ELF_SYMBOL_MAPPING_PATH))
 
diff --git a/core/dex_preopt_config.mk b/core/dex_preopt_config.mk
index f1e9fb59b7..fdec0dca08 100644
--- a/core/dex_preopt_config.mk
+++ b/core/dex_preopt_config.mk
@@ -123,6 +123,7 @@ ifeq ($(WRITE_SOONG_VARIABLES),true)
   $(call add_json_str,  Dex2oatXms,                              $(DEX2OAT_XMS))
   $(call add_json_str,  EmptyDirectory,                          $(OUT_DIR)/empty)
   $(call add_json_str,  EnableUffdGc,                            $(ENABLE_UFFD_GC))
+  $(call add_json_str,  PlatformSdkVersion,                      $(PLATFORM_SDK_VERSION))
 
 ifdef TARGET_ARCH
   $(call add_json_map,  CpuVariant)
diff --git a/core/dex_preopt_odex_install.mk b/core/dex_preopt_odex_install.mk
index 6fe9d38a36..b87be1ca79 100644
--- a/core/dex_preopt_odex_install.mk
+++ b/core/dex_preopt_odex_install.mk
@@ -138,9 +138,17 @@ else
   my_dexpreopt_libs_compat :=
 endif
 
-my_dexpreopt_libs := \
-  $(LOCAL_USES_LIBRARIES) \
-  $(my_filtered_optional_uses_libraries)
+# Bootclasspath jars are accessible by all apps, so they don't have to and
+# should not be in the CLC.
+# For framework.jar, the name in `PRODUCT_BOOT_JARS` is `framework-minus-apex`,
+# so we need to use `FRAMEWORK_LIBRARIES`, which contains `framework`, to be
+# used for filtering.
+my_all_boot_jars := \
+  $(foreach jar,$(PRODUCT_BOOT_JARS) $(PRODUCT_APEX_BOOT_JARS),$(call word-colon,2,$(jar))) \
+  $(FRAMEWORK_LIBRARIES)
+
+my_dexpreopt_libs := $(filter-out $(my_all_boot_jars), \
+  $(LOCAL_USES_LIBRARIES) $(my_filtered_optional_uses_libraries))
 
 # The order needs to be deterministic.
 my_dexpreopt_libs_all := $(sort $(my_dexpreopt_libs) $(my_dexpreopt_libs_compat))
@@ -152,7 +160,7 @@ my_dexpreopt_libs_all := $(sort $(my_dexpreopt_libs) $(my_dexpreopt_libs_compat)
 # this dexpreopt.config is generated. So it's necessary to add file-level
 # dependencies between dexpreopt.config files.
 my_dexpreopt_dep_configs := $(foreach lib, \
-  $(filter-out $(my_dexpreopt_libs_compat) $(FRAMEWORK_LIBRARIES),$(LOCAL_USES_LIBRARIES) $(my_filtered_optional_uses_libraries)), \
+  $(filter-out $(my_dexpreopt_libs_compat),$(my_dexpreopt_libs)), \
   $(call intermediates-dir-for,JAVA_LIBRARIES,$(lib),,)/dexpreopt.config)
 
 # 1: SDK version
@@ -234,18 +242,21 @@ endif
 my_enforced_uses_libraries :=
 ifeq (true,$(LOCAL_ENFORCE_USES_LIBRARIES))
   my_verify_script := build/soong/scripts/manifest_check.py
-  my_uses_libs_args := $(patsubst %,--uses-library %,$(LOCAL_USES_LIBRARIES))
+  my_uses_libs_args := $(patsubst %,--uses-library %, \
+    $(filter-out $(my_all_boot_jars),$(LOCAL_USES_LIBRARIES)))
   my_optional_uses_libs_args := $(patsubst %,--optional-uses-library %, \
-    $(LOCAL_OPTIONAL_USES_LIBRARIES))
+    $(filter-out $(my_all_boot_jars),$(LOCAL_OPTIONAL_USES_LIBRARIES)))
   my_relax_check_arg := $(if $(filter true,$(RELAX_USES_LIBRARY_CHECK)), \
     --enforce-uses-libraries-relax,)
   my_dexpreopt_config_args := $(patsubst %,--dexpreopt-config %,$(my_dexpreopt_dep_configs))
+  my_bootclasspath_libs_args := $(patsubst %,--bootclasspath-libs %,$(my_all_boot_jars))
 
   my_enforced_uses_libraries := $(intermediates)/enforce_uses_libraries.status
   $(my_enforced_uses_libraries): PRIVATE_USES_LIBRARIES := $(my_uses_libs_args)
   $(my_enforced_uses_libraries): PRIVATE_OPTIONAL_USES_LIBRARIES := $(my_optional_uses_libs_args)
   $(my_enforced_uses_libraries): PRIVATE_DEXPREOPT_CONFIGS := $(my_dexpreopt_config_args)
   $(my_enforced_uses_libraries): PRIVATE_RELAX_CHECK := $(my_relax_check_arg)
+  $(my_enforced_uses_libraries): PRIVATE_BOOT_CLASSPATH_LIBS := $(my_bootclasspath_libs_args)
   $(my_enforced_uses_libraries): $(AAPT2)
   $(my_enforced_uses_libraries): $(my_verify_script)
   $(my_enforced_uses_libraries): $(my_dexpreopt_dep_configs)
@@ -260,6 +271,7 @@ ifeq (true,$(LOCAL_ENFORCE_USES_LIBRARIES))
 	  $(PRIVATE_OPTIONAL_USES_LIBRARIES) \
 	  $(PRIVATE_DEXPREOPT_CONFIGS) \
 	  $(PRIVATE_RELAX_CHECK) \
+	  $(PRIVATE_BOOT_CLASSPATH_LIBS) \
 	  $<
   $(LOCAL_BUILT_MODULE) : $(my_enforced_uses_libraries)
 endif
@@ -503,7 +515,7 @@ ifdef LOCAL_DEX_PREOPT
   _dexname := $(basename $(notdir $(_dexlocation)))
   _system_other := $(strip $(if $(strip $(BOARD_USES_SYSTEM_OTHER_ODEX)), \
     $(if $(strip $(SANITIZE_LITE)),, \
-      $(if $(filter $(_dexname),$(PRODUCT_DEXPREOPT_SPEED_APPS))$(filter $(_dexname),$(PRODUCT_SYSTEM_SERVER_APPS)),, \
+      $(if $(filter $(_dexname),$(PRODUCT_SYSTEM_SERVER_APPS)),, \
         $(if $(strip $(foreach myfilter,$(SYSTEM_OTHER_ODEX_FILTER),$(filter system/$(myfilter),$(_dexlocation))$(filter $(myfilter),$(_dexlocation)))), \
             system_other/)))))
   # _dexdir has a trailing /
diff --git a/core/dynamic_binary.mk b/core/dynamic_binary.mk
index 878989d635..4de8bea9dc 100644
--- a/core/dynamic_binary.mk
+++ b/core/dynamic_binary.mk
@@ -30,7 +30,6 @@ linked_module := $(intermediates)/LINKED/$(notdir $(my_installed_module_stem))
 LOCAL_INTERMEDIATE_TARGETS := $(linked_module)
 
 ###################################
-include $(BUILD_SYSTEM)/use_lld_setup.mk
 include $(BUILD_SYSTEM)/binary.mk
 ###################################
 
@@ -45,54 +44,12 @@ else
 inject_module := $(linked_module)
 endif
 
-###########################################################
-## Store a copy with symbols for symbolic debugging
-###########################################################
-ifeq ($(LOCAL_UNSTRIPPED_PATH),)
-my_unstripped_path := $(TARGET_OUT_UNSTRIPPED)/$(patsubst $(PRODUCT_OUT)/%,%,$(my_module_path))
-else
-my_unstripped_path := $(LOCAL_UNSTRIPPED_PATH)
-endif
-symbolic_input := $(inject_module)
-symbolic_output := $(my_unstripped_path)/$(my_installed_module_stem)
-elf_mapping_path := $(patsubst $(TARGET_OUT_UNSTRIPPED)/%,$(call intermediates-dir-for,PACKAGING,elf_symbol_mapping)/%,$(symbolic_output).textproto)
-
-ALL_MODULES.$(my_register_name).SYMBOLIC_OUTPUT_PATH := $(symbolic_output)
-ALL_MODULES.$(my_register_name).ELF_SYMBOL_MAPPING_PATH := $(elf_mapping_path)
-
-$(eval $(call copy-unstripped-elf-file-with-mapping,$(symbolic_input),$(symbolic_output),$(elf_mapping_path)))
-
-###########################################################
-## Store breakpad symbols
-###########################################################
-
-ifeq ($(BREAKPAD_GENERATE_SYMBOLS),true)
-my_breakpad_path := $(TARGET_OUT_BREAKPAD)/$(patsubst $(PRODUCT_OUT)/%,%,$(my_module_path))
-breakpad_input := $(inject_module)
-breakpad_output := $(my_breakpad_path)/$(my_installed_module_stem).sym
-$(breakpad_output) : $(breakpad_input) | $(BREAKPAD_DUMP_SYMS) $(PRIVATE_READELF)
-	@echo "target breakpad: $(PRIVATE_MODULE) ($@)"
-	@mkdir -p $(dir $@)
-	$(hide) if $(PRIVATE_READELF) -S $< > /dev/null 2>&1 ; then \
-	  $(BREAKPAD_DUMP_SYMS) -c $< > $@ ; \
-	else \
-	  echo "skipped for non-elf file."; \
-	  touch $@; \
-	fi
-$(LOCAL_BUILT_MODULE) : $(breakpad_output)
-endif
-
 ###########################################################
 ## Strip
 ###########################################################
 strip_input := $(inject_module)
 strip_output := $(LOCAL_BUILT_MODULE)
 
-# Use an order-only dependency to ensure the unstripped file in the symbols
-# directory is copied when the module is built, but does not force the
-# module to be rebuilt when the symbols directory is cleaned by installclean.
-$(strip_output): | $(symbolic_output)
-
 my_strip_module := $(firstword \
   $(LOCAL_STRIP_MODULE_$($(my_prefix)$(LOCAL_2ND_ARCH_VAR_PREFIX)ARCH)) \
   $(LOCAL_STRIP_MODULE))
@@ -152,6 +109,5 @@ endif # my_strip_module
 $(cleantarget): PRIVATE_CLEAN_FILES += \
     $(linked_module) \
     $(inject_module) \
-    $(breakpad_output) \
     $(symbolic_output) \
     $(strip_output)
diff --git a/core/envsetup.mk b/core/envsetup.mk
index f82e861abf..7a264859dd 100644
--- a/core/envsetup.mk
+++ b/core/envsetup.mk
@@ -336,9 +336,9 @@ $(eval _dump_variables_rbc_excluded := \
   TOPDIR \
   TRACE_BEGIN_SOONG \
   USER)
-$(file >$(OUT_DIR)/dump-variables-rbc-temp.txt,$(subst $(space),$(newline),$(sort $(filter-out $(_dump_variables_rbc_excluded),$(.VARIABLES)))))
+$(file >$(OUT_DIR)/dump-variables-rbc-temp-$(TARGET_PRODUCT).txt,$(subst $(space),$(newline),$(sort $(filter-out $(_dump_variables_rbc_excluded),$(.VARIABLES)))))
 $(file >$(1),\
-$(foreach v, $(shell grep -he "^[A-Z][A-Z0-9_]*$$" $(OUT_DIR)/dump-variables-rbc-temp.txt),\
+$(foreach v, $(shell grep -he "^[A-Z][A-Z0-9_]*$$" $(OUT_DIR)/dump-variables-rbc-temp-$(TARGET_PRODUCT).txt),\
 $(v) := $(strip $($(v)))$(newline))\
 $(foreach ns,$(sort $(SOONG_CONFIG_NAMESPACES)),\
 $(foreach v,$(sort $(SOONG_CONFIG_$(ns))),\
@@ -415,7 +415,6 @@ HOST_OUT_RENDERSCRIPT_BITCODE := $(HOST_OUT_SHARED_LIBRARIES)
 HOST_OUT_JAVA_LIBRARIES := $(HOST_OUT)/framework
 HOST_OUT_SDK_ADDON := $(HOST_OUT)/sdk_addon
 HOST_OUT_NATIVE_TESTS := $(HOST_OUT)/nativetest64
-HOST_OUT_COVERAGE := $(HOST_OUT)/coverage
 HOST_OUT_TESTCASES := $(HOST_OUT)/testcases
 HOST_OUT_ETC := $(HOST_OUT)/etc
 .KATI_READONLY := \
@@ -425,20 +424,17 @@ HOST_OUT_ETC := $(HOST_OUT)/etc
   HOST_OUT_JAVA_LIBRARIES \
   HOST_OUT_SDK_ADDON \
   HOST_OUT_NATIVE_TESTS \
-  HOST_OUT_COVERAGE \
   HOST_OUT_TESTCASES \
   HOST_OUT_ETC
 
 HOST_CROSS_OUT_EXECUTABLES := $(HOST_CROSS_OUT)/bin
 HOST_CROSS_OUT_SHARED_LIBRARIES := $(HOST_CROSS_OUT)/lib
 HOST_CROSS_OUT_NATIVE_TESTS := $(HOST_CROSS_OUT)/nativetest
-HOST_CROSS_OUT_COVERAGE := $(HOST_CROSS_OUT)/coverage
 HOST_CROSS_OUT_TESTCASES := $(HOST_CROSS_OUT)/testcases
 .KATI_READONLY := \
   HOST_CROSS_OUT_EXECUTABLES \
   HOST_CROSS_OUT_SHARED_LIBRARIES \
   HOST_CROSS_OUT_NATIVE_TESTS \
-  HOST_CROSS_OUT_COVERAGE \
   HOST_CROSS_OUT_TESTCASES
 
 HOST_OUT_INTERMEDIATES := $(HOST_OUT)/obj
@@ -987,24 +983,19 @@ $(TARGET_2ND_ARCH_VAR_PREFIX)TARGET_OUT_SYSTEM_EXT_APPS_PRIVILEGED := $(TARGET_O
   $(TARGET_2ND_ARCH_VAR_PREFIX)TARGET_OUT_SYSTEM_EXT_APPS \
   $(TARGET_2ND_ARCH_VAR_PREFIX)TARGET_OUT_SYSTEM_EXT_APPS_PRIVILEGED
 
-TARGET_OUT_BREAKPAD := $(PRODUCT_OUT)/breakpad
-.KATI_READONLY := TARGET_OUT_BREAKPAD
-
 TARGET_OUT_UNSTRIPPED := $(PRODUCT_OUT)/symbols
 TARGET_OUT_EXECUTABLES_UNSTRIPPED := $(TARGET_OUT_UNSTRIPPED)/system/bin
 TARGET_OUT_SHARED_LIBRARIES_UNSTRIPPED := $(TARGET_OUT_UNSTRIPPED)/system/lib
 TARGET_OUT_VENDOR_SHARED_LIBRARIES_UNSTRIPPED := $(TARGET_OUT_UNSTRIPPED)/$(TARGET_COPY_OUT_VENDOR)/lib
 TARGET_ROOT_OUT_UNSTRIPPED := $(TARGET_OUT_UNSTRIPPED)
 TARGET_ROOT_OUT_BIN_UNSTRIPPED := $(TARGET_OUT_UNSTRIPPED)/bin
-TARGET_OUT_COVERAGE := $(PRODUCT_OUT)/coverage
 .KATI_READONLY := \
   TARGET_OUT_UNSTRIPPED \
   TARGET_OUT_EXECUTABLES_UNSTRIPPED \
   TARGET_OUT_SHARED_LIBRARIES_UNSTRIPPED \
   TARGET_OUT_VENDOR_SHARED_LIBRARIES_UNSTRIPPED \
   TARGET_ROOT_OUT_UNSTRIPPED \
-  TARGET_ROOT_OUT_BIN_UNSTRIPPED \
-  TARGET_OUT_COVERAGE
+  TARGET_ROOT_OUT_BIN_UNSTRIPPED
 
 TARGET_RAMDISK_OUT := $(PRODUCT_OUT)/$(TARGET_COPY_OUT_RAMDISK)
 TARGET_RAMDISK_OUT_UNSTRIPPED := $(TARGET_OUT_UNSTRIPPED)
@@ -1059,3 +1050,30 @@ PER_ARCH_MODULE_CLASSES := SHARED_LIBRARIES STATIC_LIBRARIES EXECUTABLES GYP REN
 ifeq ($(CALLED_FROM_SETUP),true)
 PRINT_BUILD_CONFIG ?= true
 endif
+
+# CTS-specific config.
+-include cts/build/config.mk
+# device-tests-specific-config.
+-include tools/tradefederation/build/suites/device-tests/config.mk
+# general-tests-specific-config.
+-include tools/tradefederation/build/suites/general-tests/config.mk
+# STS-specific config.
+-include test/sts/tools/sts-tradefed/build/config.mk
+# CTS-Instant-specific config
+-include test/suite_harness/tools/cts-instant-tradefed/build/config.mk
+# MTS-specific config.
+-include test/mts/tools/build/config.mk
+# VTS-Core-specific config.
+-include test/vts/tools/vts-core-tradefed/build/config.mk
+# CSUITE-specific config.
+-include test/app_compat/csuite/tools/build/config.mk
+# CATBox-specific config.
+-include test/catbox/tools/build/config.mk
+# CTS-Root-specific config.
+-include test/cts-root/tools/build/config.mk
+# WVTS-specific config.
+-include test/wvts/tools/build/config.mk
+# DTS-specific config.
+-include test/dts/tools/build/config.mk
+# Include the google-specific config
+-include vendor/google/build/config.mk
diff --git a/core/executable_internal.mk b/core/executable_internal.mk
index 2a76c9d419..ee1f464b6d 100644
--- a/core/executable_internal.mk
+++ b/core/executable_internal.mk
@@ -90,12 +90,6 @@ built_static_gcno_libraries := \
         STATIC_LIBRARIES,$(lib),$(my_kind),,$(LOCAL_2ND_ARCH_VAR_PREFIX), \
         $(my_host_cross))/$(lib)$(gcno_suffix))
 
-ifdef LOCAL_IS_HOST_MODULE
-my_coverage_path := $($(my_prefix)OUT_COVERAGE)/$(patsubst $($(my_prefix)OUT)/%,%,$(my_module_path))
-else
-my_coverage_path := $(TARGET_OUT_COVERAGE)/$(patsubst $(PRODUCT_OUT)/%,%,$(my_module_path))
-endif
-
 GCNO_ARCHIVE := $(my_installed_module_stem)$(gcno_suffix)
 
 $(intermediates)/$(GCNO_ARCHIVE) : $(SOONG_ZIP) $(MERGE_ZIPS)
@@ -103,11 +97,6 @@ $(intermediates)/$(GCNO_ARCHIVE) : PRIVATE_ALL_OBJECTS := $(strip $(LOCAL_GCNO_F
 $(intermediates)/$(GCNO_ARCHIVE) : PRIVATE_ALL_WHOLE_STATIC_LIBRARIES := $(strip $(built_whole_gcno_libraries)) $(strip $(built_static_gcno_libraries))
 $(intermediates)/$(GCNO_ARCHIVE) : $(LOCAL_GCNO_FILES) $(built_whole_gcno_libraries) $(built_static_gcno_libraries)
 	$(package-coverage-files)
-
-$(my_coverage_path)/$(GCNO_ARCHIVE) : $(intermediates)/$(GCNO_ARCHIVE)
-	$(copy-file-to-target)
-
-$(LOCAL_BUILT_MODULE): $(my_coverage_path)/$(GCNO_ARCHIVE)
 endif
 
 $(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=EXECUTABLE))
diff --git a/core/host_java_library.mk b/core/host_java_library.mk
index 652eb0ef79..88f98a9d9f 100644
--- a/core/host_java_library.mk
+++ b/core/host_java_library.mk
@@ -66,8 +66,6 @@ java_sources_deps := \
 $(java_source_list_file): $(java_sources_deps)
 	$(write-java-source-list)
 
-# TODO(b/143658984): goma can't handle the --system argument to javac.
-#$(full_classes_compiled_jar): .KATI_NINJA_POOL := $(GOMA_POOL)
 $(full_classes_compiled_jar): PRIVATE_JAVACFLAGS := $(LOCAL_JAVACFLAGS) $(annotation_processor_flags)
 $(full_classes_compiled_jar): PRIVATE_JAR_EXCLUDE_FILES :=
 $(full_classes_compiled_jar): PRIVATE_JAR_PACKAGES :=
@@ -125,4 +123,4 @@ ifeq ($(TURBINE_ENABLED),false)
 $(eval $(call copy-one-file,$(LOCAL_FULL_CLASSES_JACOCO_JAR),$(full_classes_header_jar)))
 endif
 
-$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=HOST_JAVA_LIBRARY))
\ No newline at end of file
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=HOST_JAVA_LIBRARY))
diff --git a/core/jacoco.mk b/core/jacoco.mk
index 7099526455..4b635ca5ef 100644
--- a/core/jacoco.mk
+++ b/core/jacoco.mk
@@ -72,11 +72,10 @@ $(my_classes_to_report_on_path): $(my_unzipped_timestamp_path)
 	zip -q $@ \
 	  -r $(PRIVATE_UNZIPPED_PATH)
 
-# Make a rule to copy the jacoco-report-classes.jar to a packaging directory.
-$(eval $(call copy-one-file,$(my_classes_to_report_on_path),\
-  $(call local-packaging-dir,jacoco)/jacoco-report-classes.jar))
-$(call add-dependency,$(LOCAL_BUILT_MODULE),\
-  $(call local-packaging-dir,jacoco)/jacoco-report-classes.jar)
+ALL_MODULES.$(my_register_name).JACOCO_REPORT_FILES := $(my_classes_to_report_on_path)
+ALL_MODULES.$(my_register_name).JACOCO_REPORT_SOONG_ZIP_ARGUMENTS := \
+  -e out/target/common/obj/$(LOCAL_MODULE_CLASS)/$(LOCAL_MODULE)_intermediates/jacoco-report-classes.jar \
+  -f $(my_classes_to_report_on_path)
 
   # make a task that invokes instrumentation
   my_instrumented_path := $(my_files)/work/instrumented/classes
diff --git a/core/java.mk b/core/java.mk
index 41a1b1ba84..292facaf32 100644
--- a/core/java.mk
+++ b/core/java.mk
@@ -257,8 +257,6 @@ $(eval $(call copy-one-file,$(full_classes_header_jarjar),$(full_classes_header_
 
 endif # TURBINE_ENABLED != false
 
-# TODO(b/143658984): goma can't handle the --system argument to javac.
-#$(full_classes_compiled_jar): .KATI_NINJA_POOL := $(GOMA_POOL)
 $(full_classes_compiled_jar): .KATI_NINJA_POOL := $(JAVAC_NINJA_POOL)
 $(full_classes_compiled_jar): PRIVATE_JAVACFLAGS := $(LOCAL_JAVACFLAGS) $(annotation_processor_flags)
 $(full_classes_compiled_jar): PRIVATE_JAR_EXCLUDE_FILES := $(LOCAL_JAR_EXCLUDE_FILES)
diff --git a/core/layoutlib_data.mk b/core/layoutlib_data.mk
index 5dde50f7a8..792a17ab7e 100644
--- a/core/layoutlib_data.mk
+++ b/core/layoutlib_data.mk
@@ -134,8 +134,8 @@ $(LAYOUTLIB_SBOM)/sbom-metadata.csv:
 
 	$(foreach f,$(_layoutlib_fonts_files), \
 	  $(eval _module_name := $(ALL_INSTALLED_FILES.$f)) \
-	  $(eval _module_path := $(strip $(sort $(ALL_MODULES.$(_module_name).PATH)))) \
-	  $(eval _soong_module_type := $(strip $(sort $(ALL_MODULES.$(_module_name).SOONG_MODULE_TYPE)))) \
+	  $(eval _module_path := $(sort $(ALL_MODULES.$(_module_name).PATH))) \
+	  $(eval _soong_module_type := $(sort $(ALL_MODULES.$(_module_name).SOONG_MODULE_TYPE))) \
 	  echo data/fonts/$(notdir $f),$(_module_path),$(_soong_module_type),,,,,$f,,, >> $@; \
 	)
 
@@ -145,8 +145,8 @@ $(LAYOUTLIB_SBOM)/sbom-metadata.csv:
 
 	$(foreach f,$(_layoutlib_hyphen_files), \
 	  $(eval _module_name := $(ALL_INSTALLED_FILES.$f)) \
-	  $(eval _module_path := $(strip $(sort $(ALL_MODULES.$(_module_name).PATH)))) \
-	  $(eval _soong_module_type := $(strip $(sort $(ALL_MODULES.$(_module_name).SOONG_MODULE_TYPE)))) \
+	  $(eval _module_path := $(sort $(ALL_MODULES.$(_module_name).PATH))) \
+	  $(eval _soong_module_type := $(sort $(ALL_MODULES.$(_module_name).SOONG_MODULE_TYPE))) \
 	  echo data/hyphen-data/$(notdir $f),$(_module_path),$(_soong_module_type),,,,,$f,,, >> $@; \
 	)
 
@@ -156,8 +156,8 @@ $(LAYOUTLIB_SBOM)/sbom-metadata.csv:
 	  $(eval _dist_file := $(patsubst data/windows/%,data/win/lib64/%,$(patsubst layoutlib_native/%,data/%,$(_dist_file)))) \
 	  $(eval _dist_file := $(subst layoutlib.jar,data/layoutlib.jar,$(_dist_file))) \
 	  $(eval _module_name := $(strip $(foreach m,$(ALL_MODULES),$(if $(filter $(_prebuilt_module_file),$(ALL_MODULES.$m.CHECKED)),$m)))) \
-	  $(eval _module_path := $(strip $(sort $(ALL_MODULES.$(_module_name).PATH)))) \
-	  $(eval _soong_module_type := $(strip $(sort $(ALL_MODULES.$(_module_name).SOONG_MODULE_TYPE)))) \
+	  $(eval _module_path := $(sort $(ALL_MODULES.$(_module_name).PATH))) \
+	  $(eval _soong_module_type := $(sort $(ALL_MODULES.$(_module_name).SOONG_MODULE_TYPE))) \
 	  echo $(patsubst layoutlib_native/%,%,$(_dist_file)),$(_module_path),$(_soong_module_type),,,,,$(_prebuilt_module_file),,, >> $@; \
 	)
 
diff --git a/core/main.mk b/core/main.mk
index aed3fa2fd9..a0135613df 100644
--- a/core/main.mk
+++ b/core/main.mk
@@ -4,7 +4,7 @@ $(warning Either use 'envsetup.sh; m' or 'build/soong/soong_ui.bash --make-mode'
 $(error done)
 endif
 
-$(info [1/1] initializing legacy Make module parser ...)
+$(info [1/1] initializing Make module parser ...)
 
 # Absolute path of the present working direcotry.
 # This overrides the shell variable $PWD, which does not necessarily points to
@@ -56,31 +56,6 @@ DATE_FROM_FILE := date -d @$(BUILD_DATETIME_FROM_FILE)
 EMPTY_DIRECTORY := $(OUT_DIR)/empty
 $(shell mkdir -p $(EMPTY_DIRECTORY) && rm -rf $(EMPTY_DIRECTORY)/*)
 
-# CTS-specific config.
--include cts/build/config.mk
-# device-tests-specific-config.
--include tools/tradefederation/build/suites/device-tests/config.mk
-# general-tests-specific-config.
--include tools/tradefederation/build/suites/general-tests/config.mk
-# STS-specific config.
--include test/sts/tools/sts-tradefed/build/config.mk
-# CTS-Instant-specific config
--include test/suite_harness/tools/cts-instant-tradefed/build/config.mk
-# MTS-specific config.
--include test/mts/tools/build/config.mk
-# VTS-Core-specific config.
--include test/vts/tools/vts-core-tradefed/build/config.mk
-# CSUITE-specific config.
--include test/app_compat/csuite/tools/build/config.mk
-# CATBox-specific config.
--include test/catbox/tools/build/config.mk
-# CTS-Root-specific config.
--include test/cts-root/tools/build/config.mk
-# WVTS-specific config.
--include test/wvts/tools/build/config.mk
-# DTS-specific config.
--include test/dts/tools/build/config.mk
-
 
 # Clean rules
 .PHONY: clean-dex-files
@@ -90,9 +65,6 @@ clean-dex-files:
 				grep -q "\.dex$$" && rm -f $$i) || continue ) ; done
 	@echo "All dex files and archives containing dex files have been removed."
 
-# Include the google-specific config
--include vendor/google/build/config.mk
-
 # These are the modifier targets that don't do anything themselves, but
 # change the behavior of the build.
 # (must be defined before including definitions.make)
@@ -263,7 +235,7 @@ $(shell $(call echo-error,$(LOCAL_MODULE_MAKEFILE),$(LOCAL_MODULE): $(1)))
 $(error done)
 endef
 
-subdir_makefiles_inc := .
+include_makefiles_inc := .
 FULL_BUILD :=
 
 ifneq ($(dont_bother),true)
@@ -294,12 +266,12 @@ endif
 
 subdir_makefiles += $(SOONG_OUT_DIR)/late-$(TARGET_PRODUCT)$(COVERAGE_SUFFIX).mk
 
-subdir_makefiles_total := $(words int $(subdir_makefiles) post finish)
-.KATI_READONLY := subdir_makefiles_total
+include_makefiles_total := $(words int $(subdir_makefiles))
 
-$(foreach mk,$(subdir_makefiles),$(info [$(call inc_and_print,subdir_makefiles_inc)/$(subdir_makefiles_total)] including $(mk) ...)$(eval include $(mk)))
+$(foreach mk,$(subdir_makefiles),$(info [$(call inc_and_print,include_makefiles_inc)/$(include_makefiles_total)] including $(mk) ...)$(eval include $(mk)))
 
--include device/generic/goldfish/tasks/emu_img_zip.mk
+# Unfortunately build/tasks is included at a wrong time and the order is important (b/417070498)
+-include device/generic/goldfish/build/tasks.workaround/emu_img_zip.mk
 
 # Build bootloader.img/radio.img, and unpack the partitions.
 -include vendor/google_devices/$(TARGET_SOC)/prebuilts/misc_bins/update_bootloader_radio_image.mk
@@ -317,11 +289,11 @@ include system/core/rootdir/create_root_structure.mk
 
 endif # dont_bother
 
-ifndef subdir_makefiles_total
-subdir_makefiles_total := $(words init post finish)
+ifndef include_makefiles_total
+include_makefiles_total := $(words init post finish)
 endif
 
-$(info [$(call inc_and_print,subdir_makefiles_inc)/$(subdir_makefiles_total)] finishing legacy Make module parsing ...)
+$(info [$(include_makefiles_total)/$(include_makefiles_total)] finishing Make module rules ...)
 
 # -------------------------------------------------------------------
 # All module makefiles have been included at this point.
@@ -543,6 +515,8 @@ define add-required-host-so-deps
 $(1): $(2)
 endef
 
+$(info [$(include_makefiles_total)/$(include_makefiles_total)] finishing Make module rules: Adding module dependencies)
+
 # Sets up dependencies such that whenever a host module is installed,
 # any other host modules listed in $(ALL_MODULES.$(m).REQUIRED_FROM_HOST) will also be installed
 define add-all-host-to-host-required-modules-deps
@@ -700,6 +674,8 @@ endef
 # flatten the shared library dependencies.
 define update-host-shared-libs-deps-for-suites
 $(foreach suite,general-tests device-tests vts tvts art-host-tests host-unit-tests camera-hal-tests,\
+  $(eval COMPATIBILITY.$(suite).SYMLINKS :=)\
+  $(eval COMPATIBILITY.$(suite).HOST_SHARED_LIBRARY.FILES :=)\
   $(foreach m,$(COMPATIBILITY.$(suite).MODULES),\
     $(eval my_deps := $(call get-all-shared-libs-deps,$(m)))\
     $(foreach dep,$(my_deps),\
@@ -712,15 +688,13 @@ $(foreach suite,general-tests device-tests vts tvts art-host-tests host-unit-tes
         $(if $(strip $(patsubst %x86,,$(COMPATIBILITY.$(suite).ARCH_DIRS.$(m)))), \
           $(if $(strip $(patsubst %x86_64,,$(COMPATIBILITY.$(suite).ARCH_DIRS.$(m)))),$(eval prefix := ../..),),) \
         $(eval link_target := $(prefix)/$(lastword $(subst /, ,$(dir $(f))))/$(notdir $(f)))\
-        $(eval symlink := $(COMPATIBILITY.$(suite).ARCH_DIRS.$(m))/shared_libs/$(notdir $(f)))\
-        $(eval COMPATIBILITY.$(suite).SYMLINKS := \
-          $$(COMPATIBILITY.$(suite).SYMLINKS) $(f):$(link_target):$(symlink))\
+        $(foreach arch_dir,$(COMPATIBILITY.$(suite).ARCH_DIRS.$(m)),\
+          $(eval symlink := $(arch_dir)/shared_libs/$(notdir $(f)))\
+          $(eval COMPATIBILITY.$(suite).SYMLINKS += $(f):$(link_target):$(symlink)))\
         $(if $(strip $(ALL_TARGETS.$(target).META_LIC)),,$(call declare-copy-target-license-metadata,$(target),$(f)))\
-        $(eval COMPATIBILITY.$(suite).HOST_SHARED_LIBRARY.FILES := \
-          $$(COMPATIBILITY.$(suite).HOST_SHARED_LIBRARY.FILES) $(f):$(target))\
-        $(eval COMPATIBILITY.$(suite).HOST_SHARED_LIBRARY.FILES := \
-          $(sort $(COMPATIBILITY.$(suite).HOST_SHARED_LIBRARY.FILES))))))\
-  $(eval COMPATIBILITY.$(suite).SYMLINKS := $(sort $(COMPATIBILITY.$(suite).SYMLINKS))))
+        $(eval COMPATIBILITY.$(suite).HOST_SHARED_LIBRARY.FILES += $(f):$(target)))))\
+  $(eval COMPATIBILITY.$(suite).SYMLINKS := $(sort $(COMPATIBILITY.$(suite).SYMLINKS)))\
+  $(eval COMPATIBILITY.$(suite).HOST_SHARED_LIBRARY.FILES := $(sort $(COMPATIBILITY.$(suite).HOST_SHARED_LIBRARY.FILES))))
 endef
 
 $(call resolve-shared-libs-depes,TARGET_)
@@ -1217,6 +1191,8 @@ endif
 modules_to_install := $(sort $(ALL_DEFAULT_INSTALLED_MODULES))
 ALL_DEFAULT_INSTALLED_MODULES :=
 
+$(info [$(include_makefiles_total)/$(include_makefiles_total)] finishing Make packaging rules: Adding phony targets)
+
 ifdef FULL_BUILD
 #
 # Used by the cleanup logic in soong_ui to remove files that should no longer
@@ -1240,6 +1216,7 @@ $(file >$(HOST_OUT)/.installable_test_files,$(sort \
 test_files :=
 endif
 
+
 # Some notice deps refer to module names without prefix or arch suffix where
 # only the variants with them get built.
 # fix-notice-deps replaces those unadorned module names with every built variant.
@@ -1470,8 +1447,6 @@ droidcore: droidcore-unbundled
 # dist_files only for putting your library into the dist directory with a full build.
 .PHONY: dist_files
 
-$(call dist-for-goals, dist_files, $(PRODUCT_OUT)/module-info.json)
-
 .PHONY: apps_only
 ifeq ($(HOST_OS),darwin)
   # Mac only supports building host modules
@@ -1479,66 +1454,15 @@ ifeq ($(HOST_OS),darwin)
 
 else ifneq ($(TARGET_BUILD_APPS),)
   # If this build is just for apps, only build apps and not the full system by default.
-
-  # Dist the installed files if they exist, except the installed symlinks. dist-for-goals emits
-  # `cp src dest` commands, which will fail to copy dangling symlinks.
-  apps_only_installed_files := $(foreach m,$(unbundled_build_modules),\
-    $(filter-out $(ALL_MODULES.$(m).INSTALLED_SYMLINKS),$(ALL_MODULES.$(m).INSTALLED)))
-  $(call dist-for-goals,apps_only, $(apps_only_installed_files))
-
-  # Dist the bundle files if they exist.
-  apps_only_bundle_files := $(foreach m,$(unbundled_build_modules),\
-    $(if $(ALL_MODULES.$(m).BUNDLE),$(ALL_MODULES.$(m).BUNDLE):$(m)-base.zip))
-  $(call dist-for-goals,apps_only, $(apps_only_bundle_files))
-
-  # Dist the lint reports if they exist.
-  apps_only_lint_report_files := $(foreach m,$(unbundled_build_modules),\
-    $(foreach report,$(ALL_MODULES.$(m).LINT_REPORTS),\
-      $(report):$(m)-$(notdir $(report))))
-  .PHONY: lint-check
-  lint-check: $(foreach f, $(apps_only_lint_report_files), $(call word-colon,1,$(f)))
-  $(call dist-for-goals,lint-check, $(apps_only_lint_report_files))
-
-  # For uninstallable modules such as static Java library, we have to dist the built file,
-  # as <module_name>.<suffix>
-  apps_only_dist_built_files := $(foreach m,$(unbundled_build_modules),$(if $(ALL_MODULES.$(m).INSTALLED),,\
-      $(if $(ALL_MODULES.$(m).BUILT),$(ALL_MODULES.$(m).BUILT):$(m)$(suffix $(ALL_MODULES.$(m).BUILT)))\
-      $(if $(ALL_MODULES.$(m).AAR),$(ALL_MODULES.$(m).AAR):$(m).aar)\
-      ))
-  $(call dist-for-goals,apps_only, $(apps_only_dist_built_files))
-
-  ifeq ($(EMMA_INSTRUMENT),true)
-    $(JACOCO_REPORT_CLASSES_ALL) : $(apps_only_installed_files)
-    $(call dist-for-goals,apps_only, $(JACOCO_REPORT_CLASSES_ALL))
-  endif
-
-  $(PROGUARD_DICT_ZIP) : $(apps_only_installed_files)
-  $(call dist-for-goals-with-filenametag,apps_only, $(PROGUARD_DICT_ZIP) $(PROGUARD_DICT_ZIP) $(PROGUARD_DICT_MAPPING))
-  $(call declare-container-license-deps,$(PROGUARD_DICT_ZIP),$(apps_only_installed_files),$(PRODUCT_OUT)/:/)
-
-  $(PROGUARD_USAGE_ZIP) : $(apps_only_installed_files)
-  $(call dist-for-goals-with-filenametag,apps_only, $(PROGUARD_USAGE_ZIP))
-  $(call declare-container-license-deps,$(PROGUARD_USAGE_ZIP),$(apps_only_installed_files),$(PRODUCT_OUT)/:/)
-
-  $(SYMBOLS_ZIP) : $(apps_only_installed_files)
-  $(call dist-for-goals-with-filenametag,apps_only, $(SYMBOLS_ZIP) $(SYMBOLS_MAPPING))
-  $(call declare-container-license-deps,$(SYMBOLS_ZIP),$(apps_only_installed_files),$(PRODUCT_OUT)/:/)
-
-  $(COVERAGE_ZIP) : $(apps_only_installed_files)
-  $(call dist-for-goals,apps_only, $(COVERAGE_ZIP))
-  $(call declare-container-license-deps,$(COVERAGE_ZIP),$(apps_only_installed_files),$(PRODUCT_OUT)/:/)
+  # The majority of this block has been converted to soong's unbundled_builder module.
 
 apps_only: $(unbundled_build_modules)
 
 droid_targets: apps_only
 
-# NOTICE files for a apps_only build
-$(eval $(call html-notice-rule,$(target_notice_file_html_or_xml),"Apps","Notices for files for apps:",$(unbundled_build_modules),$(PRODUCT_OUT)/ $(HOST_OUT)/))
-
 $(eval $(call text-notice-rule,$(target_notice_file_txt),"Apps","Notices for files for apps:",$(unbundled_build_modules),$(PRODUCT_OUT)/ $(HOST_OUT)/))
 
 $(call declare-0p-target,$(target_notice_file_txt))
-$(call declare-0p-target,$(target_notice_html_or_xml))
 
 
 else ifeq ($(TARGET_BUILD_UNBUNDLED),$(TARGET_BUILD_UNBUNDLED_IMAGE))
@@ -1556,7 +1480,6 @@ else ifeq ($(TARGET_BUILD_UNBUNDLED),$(TARGET_BUILD_UNBUNDLED_IMAGE))
   # sources in a droidcore full build.
 
   $(call dist-for-goals, droidcore, \
-    $(BUILT_OTATOOLS_PACKAGE) \
     $(APPCOMPAT_ZIP) \
   )
 
@@ -1572,7 +1495,6 @@ else ifeq ($(TARGET_BUILD_UNBUNDLED),$(TARGET_BUILD_UNBUNDLED_IMAGE))
     $(INTERNAL_OTA_PARTIAL_PACKAGE_TARGET) \
     $(BUILT_RAMDISK_16K_TARGET) \
     $(BUILT_KERNEL_16K_TARGET) \
-    $(INTERNAL_OTA_RETROFIT_DYNAMIC_PARTITIONS_PACKAGE_TARGET) \
     $(SYMBOLS_ZIP) \
     $(SYMBOLS_MAPPING) \
     $(PROGUARD_DICT_ZIP) \
@@ -1583,7 +1505,6 @@ else ifeq ($(TARGET_BUILD_UNBUNDLED),$(TARGET_BUILD_UNBUNDLED_IMAGE))
 
   $(call dist-for-goals, droidcore-unbundled, \
     $(INTERNAL_OTA_METADATA) \
-    $(COVERAGE_ZIP) \
     $(INSTALLED_FILES_FILE) \
     $(INSTALLED_FILES_JSON) \
     $(INSTALLED_FILES_FILE_VENDOR) \
@@ -1743,6 +1664,8 @@ ifneq ($(UNSAFE_DISABLE_APEX_ALLOWED_DEPS_CHECK),true)
   droidcore: ${APEX_ALLOWED_DEPS_CHECK}
 endif
 
+$(info [$(include_makefiles_total)/$(include_makefiles_total)] finishing Make packaging rules: Checking licensing and SBOM)
+
 # Create a license metadata rule per module. Could happen in base_rules.mk or
 # notice_files.mk; except, it has to happen after fix-notice-deps to avoid
 # missing dependency errors.
@@ -1757,7 +1680,8 @@ filter_out_files := \
   $(PRODUCT_OUT)/apex/% \
   $(PRODUCT_OUT)/fake_packages/% \
   $(PRODUCT_OUT)/testcases/% \
-  $(dest_files_without_source)
+  $(dest_files_without_source) \
+  $(PRODUCT_OUT)/required_images
 # Check if each partition image is built, if not filter out all its installed files
 # Also check if a partition uses prebuilt image file, save the info if prebuilt image is used.
 PREBUILT_PARTITION_COPY_FILES :=
@@ -1869,6 +1793,45 @@ make-compliance-metadata: \
     $(SOONG_OUT_DIR)/compliance-metadata/$(TARGET_PRODUCT)/make-metadata.csv \
     $(SOONG_OUT_DIR)/compliance-metadata/$(TARGET_PRODUCT)/make-modules.csv
 
+
+# Precompute these as an optimization to not do $(findstring).
+# Normally we would unset these to save memory, but we're almost at the end of the make
+# run, so don't bother.
+$(foreach f,$(INSTALLED_PRODUCT_SYSTEM_OTHER_AVBKEY_TARGET),\
+	$(eval _is_product_system_other_avbkey.$(f):=Y) \
+)
+$(foreach f,$(event_log_tags_file),\
+	$(eval _is_event_log_tags_file.$(f):=Y) \
+)
+$(foreach f,$(INSTALLED_SYSTEM_OTHER_ODEX_MARKER),\
+	$(eval _is_system_other_odex_marker.$(f):=Y) \
+)
+$(foreach f,$(ALL_KERNEL_MODULES_BLOCKLIST),\
+	$(eval _is_kernel_modules_blocklist.$(f):=Y) \
+)
+$(foreach f,$(ALL_FSVERITY_BUILD_MANIFEST_APK),\
+	$(eval _is_fsverity_build_manifest_apk.$(f):=Y) \
+)
+$(foreach f,$(SYSTEM_LINKER_CONFIG),\
+	$(eval _is_linker_config.$(f):=Y) \
+)
+$(foreach f,$(vendor_linker_config_file),\
+	$(eval _is_linker_config.$(f):=Y) \
+)
+$(foreach f,$(product_linker_config_file),\
+	$(eval _is_linker_config.$(f):=Y) \
+)
+$(foreach f,$(PARTITION_COMPAT_SYMLINKS),\
+	$(eval _is_partition_compat_symlink.$(f):=Y) \
+)
+$(foreach f,$(ALL_FLAGS_FILES),\
+	$(eval _is_flags_file.$(f):=Y) \
+)
+$(foreach f,$(ALL_ROOTDIR_SYMLINKS),\
+	$(eval _is_rootdir_symlink.$(f):=Y) \
+)
+$(foreach m,$(ALL_NON_MODULES),$(eval _is_non_module.$(m):=Y))
+
 $(SOONG_OUT_DIR)/compliance-metadata/$(TARGET_PRODUCT)/make-metadata.csv:
 	rm -f $@
 	echo 'installed_file,module_path,is_soong_module,is_prebuilt_make_module,product_copy_files,kernel_module_copy_files,is_platform_generated,static_libs,whole_static_libs,license_text' >> $@
@@ -1876,26 +1839,26 @@ $(SOONG_OUT_DIR)/compliance-metadata/$(TARGET_PRODUCT)/make-metadata.csv:
 	  $(eval _module_name := $(ALL_INSTALLED_FILES.$f)) \
 	  $(eval _path_on_device := $(patsubst $(PRODUCT_OUT)/%,%,$f)) \
 	  $(eval _build_output_path := $(PRODUCT_OUT)/$(_path_on_device)) \
-	  $(eval _module_path := $(strip $(sort $(ALL_MODULES.$(_module_name).PATH)))) \
+	  $(eval _module_path := $(sort $(ALL_MODULES.$(_module_name).PATH))) \
 	  $(eval _is_soong_module := $(ALL_MODULES.$(_module_name).IS_SOONG_MODULE)) \
 	  $(eval _is_prebuilt_make_module := $(ALL_MODULES.$(_module_name).IS_PREBUILT_MAKE_MODULE)) \
 	  $(eval _product_copy_files := $(sort $(filter %:$(_path_on_device),$(product_copy_files_without_owner)))) \
 	  $(eval _kernel_module_copy_files := $(sort $(filter %$(_path_on_device),$(KERNEL_MODULE_COPY_FILES)))) \
 	  $(eval _is_build_prop := $(call is-build-prop,$f)) \
 	  $(eval _is_notice_file := $(call is-notice-file,$f)) \
-	  $(eval _is_product_system_other_avbkey := $(if $(findstring $f,$(INSTALLED_PRODUCT_SYSTEM_OTHER_AVBKEY_TARGET)),Y)) \
-	  $(eval _is_event_log_tags_file := $(if $(findstring $f,$(event_log_tags_file)),Y)) \
-	  $(eval _is_system_other_odex_marker := $(if $(findstring $f,$(INSTALLED_SYSTEM_OTHER_ODEX_MARKER)),Y)) \
-	  $(eval _is_kernel_modules_blocklist := $(if $(findstring $f,$(ALL_KERNEL_MODULES_BLOCKLIST)),Y)) \
-	  $(eval _is_fsverity_build_manifest_apk := $(if $(findstring $f,$(ALL_FSVERITY_BUILD_MANIFEST_APK)),Y)) \
-	  $(eval _is_linker_config := $(if $(findstring $f,$(SYSTEM_LINKER_CONFIG) $(vendor_linker_config_file) $(product_linker_config_file)),Y)) \
-	  $(eval _is_partition_compat_symlink := $(if $(findstring $f,$(PARTITION_COMPAT_SYMLINKS)),Y)) \
-	  $(eval _is_flags_file := $(if $(findstring $f, $(ALL_FLAGS_FILES)),Y)) \
-	  $(eval _is_rootdir_symlink := $(if $(findstring $f, $(ALL_ROOTDIR_SYMLINKS)),Y)) \
+	  $(eval _is_product_system_other_avbkey := $(_is_product_system_other_avbkey.$(f))) \
+	  $(eval _is_event_log_tags_file := $(_is_event_log_tags_file.$(f))) \
+	  $(eval _is_system_other_odex_marker := $(_is_system_other_odex_marker.$(f))) \
+	  $(eval _is_kernel_modules_blocklist := $(_is_kernel_modules_blocklist.$(f))) \
+	  $(eval _is_fsverity_build_manifest_apk := $(_is_fsverity_build_manifest_apk.$(f))) \
+	  $(eval _is_linker_config := $(_is_linker_config.$(f))) \
+	  $(eval _is_partition_compat_symlink := $(_is_partition_compat_symlink.$(f))) \
+	  $(eval _is_flags_file := $(_is_flags_file.$(f))) \
+	  $(eval _is_rootdir_symlink := $(_is_rootdir_symlink.$(f))) \
 	  $(eval _is_platform_generated := $(if $(_is_soong_module),,$(_is_build_prop)$(_is_notice_file)$(_is_product_system_other_avbkey)$(_is_event_log_tags_file)$(_is_system_other_odex_marker)$(_is_kernel_modules_blocklist)$(_is_fsverity_build_manifest_apk)$(_is_linker_config)$(_is_partition_compat_symlink)$(_is_flags_file)$(_is_rootdir_symlink))) \
 	  $(eval _static_libs := $(if $(_is_soong_module),,$(ALL_INSTALLED_FILES.$f.STATIC_LIBRARIES))) \
 	  $(eval _whole_static_libs := $(if $(_is_soong_module),,$(ALL_INSTALLED_FILES.$f.WHOLE_STATIC_LIBRARIES))) \
-	  $(eval _license_text := $(if $(filter $(_build_output_path),$(ALL_NON_MODULES)),$(ALL_NON_MODULES.$(_build_output_path).NOTICES),\
+	  $(eval _license_text := $(if $(_is_non_module.$(_build_output_path)),$(ALL_NON_MODULES.$(_build_output_path).NOTICES),\
 	                          $(if $(_is_partition_compat_symlink),build/soong/licenses/LICENSE))) \
 	  echo '$(_build_output_path),$(_module_path),$(_is_soong_module),$(_is_prebuilt_make_module),$(_product_copy_files),$(_kernel_module_copy_files),$(_is_platform_generated),$(_static_libs),$(_whole_static_libs),$(_license_text)' >> $@; \
 	)
@@ -1905,13 +1868,13 @@ $(SOONG_OUT_DIR)/compliance-metadata/$(TARGET_PRODUCT)/make-modules.csv:
 	echo 'name,module_path,module_class,module_type,static_libs,whole_static_libs,built_files,installed_files' >> $@
 	$(foreach m,$(ALL_MODULES), \
 	  $(eval _module_name := $m) \
-	  $(eval _module_path := $(strip $(sort $(ALL_MODULES.$(_module_name).PATH)))) \
+	  $(eval _module_path := $(sort $(ALL_MODULES.$(_module_name).PATH))) \
 	  $(eval _make_module_class := $(ALL_MODULES.$(_module_name).CLASS)) \
 	  $(eval _make_module_type := $(ALL_MODULES.$(_module_name).MAKE_MODULE_TYPE)) \
-	  $(eval _static_libs := $(strip $(sort $(ALL_MODULES.$(_module_name).STATIC_LIBS)))) \
-	  $(eval _whole_static_libs := $(strip $(sort $(ALL_MODULES.$(_module_name).WHOLE_STATIC_LIBS)))) \
-	  $(eval _built_files := $(strip $(sort $(ALL_MODULES.$(_module_name).BUILT)))) \
-	  $(eval _installed_files := $(strip $(sort $(ALL_MODULES.$(_module_name).INSTALLED)))) \
+	  $(eval _static_libs := $(sort $(ALL_MODULES.$(_module_name).STATIC_LIBS))) \
+	  $(eval _whole_static_libs := $(sort $(ALL_MODULES.$(_module_name).WHOLE_STATIC_LIBS))) \
+	  $(eval _built_files := $(sort $(ALL_MODULES.$(_module_name).BUILT))) \
+	  $(eval _installed_files := $(sort $(ALL_MODULES.$(_module_name).INSTALLED))) \
 	  $(eval _is_soong_module := $(ALL_MODULES.$(_module_name).IS_SOONG_MODULE)) \
 	  $(if $(_is_soong_module),, \
 		echo '$(_module_name),$(_module_path),$(_make_module_class),$(_make_module_type),$(_static_libs),$(_whole_static_libs),$(_built_files),$(_installed_files)' >> $@; \
@@ -1975,4 +1938,4 @@ endif
 
 $(call dist-write-file,$(KATI_PACKAGE_MK_DIR)/dist.mk)
 
-$(info [$(call inc_and_print,subdir_makefiles_inc)/$(subdir_makefiles_total)] writing legacy Make module rules ...)
+$(info [$(include_makefiles_total)/$(include_makefiles_total)] writing make module actions ...)
diff --git a/core/packaging/flags.mk b/core/packaging/flags.mk
index 19068f4a0a..a9538b872b 100644
--- a/core/packaging/flags.mk
+++ b/core/packaging/flags.mk
@@ -119,10 +119,9 @@ define generate-partition-aconfig-storage-file
 $(eval $(strip $(1)): PRIVATE_OUT := $(strip $(1)))
 $(eval $(strip $(1)): PRIVATE_IN := $(strip $(9)))
 
-ifneq (,$(RELEASE_FINGERPRINT_ACONFIG_PACKAGES))
-STORAGE_FILE_VERSION := 2
-else
-STORAGE_FILE_VERSION := 1
+STORAGE_FILE_VERSION := $(RELEASE_ACONFIG_STORAGE_VERSION)
+ifeq (,$(STORAGE_FILE_VERSION))
+STORAGE_FILE_VERSION := "2"
 endif
 
 $(strip $(1)): $(ACONFIG) $(strip $(9))
diff --git a/core/prebuilt_internal.mk b/core/prebuilt_internal.mk
index 5dfc6c1951..12709c0587 100644
--- a/core/prebuilt_internal.mk
+++ b/core/prebuilt_internal.mk
@@ -6,8 +6,6 @@
 ##
 ###########################################################
 
-include $(BUILD_SYSTEM)/use_lld_setup.mk
-
 ifneq ($(LOCAL_PREBUILT_LIBS),)
 $(call pretty-error,dont use LOCAL_PREBUILT_LIBS anymore)
 endif
@@ -69,4 +67,4 @@ $(built_module) : $(LOCAL_ADDITIONAL_DEPENDENCIES)
 
 my_prebuilt_src_file :=
 
-$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=PREBUILT))
\ No newline at end of file
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=PREBUILT))
diff --git a/core/product.mk b/core/product.mk
index 1fbc3eef51..886bfa12ac 100644
--- a/core/product.mk
+++ b/core/product.mk
@@ -230,9 +230,6 @@ _product_single_value_vars += PRODUCT_SYSTEM_DLKM_BASE_FS_PATH
 # The first API level this product shipped with
 _product_single_value_vars += PRODUCT_SHIPPING_API_LEVEL
 
-# The first vendor API level this product shipped with
-_product_single_value_vars += PRODUCT_SHIPPING_VENDOR_API_LEVEL
-
 _product_list_vars += VENDOR_PRODUCT_RESTRICT_VENDOR_FILES
 _product_list_vars += VENDOR_EXCEPTION_MODULES
 _product_list_vars += VENDOR_EXCEPTION_PATHS
@@ -301,12 +298,6 @@ _product_list_vars += PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST
 # installed on /system directory by default.
 _product_list_vars += PRODUCT_FORCE_PRODUCT_MODULES_TO_SYSTEM_PARTITION
 
-# When this is true, dynamic partitions is retrofitted on a device that has
-# already been launched without dynamic partitions. Otherwise, the device
-# is launched with dynamic partitions.
-# This flag implies PRODUCT_USE_DYNAMIC_PARTITIONS.
-_product_single_value_vars += PRODUCT_RETROFIT_DYNAMIC_PARTITIONS
-
 # List of directories that will be used to gate blueprint modules from the build graph
 _product_list_vars += PRODUCT_SOURCE_ROOT_DIRS
 
@@ -382,9 +373,6 @@ _product_single_value_vars += PRODUCT_VIRTUAL_AB_OTA
 # If set, device uses virtual A/B Compression.
 _product_single_value_vars += PRODUCT_VIRTUAL_AB_COMPRESSION
 
-# If set, device retrofits virtual A/B.
-_product_single_value_vars += PRODUCT_VIRTUAL_AB_OTA_RETROFIT
-
 # If set, forcefully generate a non-A/B update package.
 # Note: A device configuration should inherit from virtual_ab_ota_plus_non_ab.mk
 # instead of setting this variable directly.
@@ -427,6 +415,12 @@ _product_single_value_vars += PRODUCT_MEMCG_V2_FORCE_ENABLED
 # If true, the cgroup v2 hierarchy will be split into apps/system subtrees
 _product_single_value_vars += PRODUCT_CGROUP_V2_SYS_APP_ISOLATION_ENABLED
 
+# If set, check treble labeling
+_product_single_value_vars += PRODUCT_ENFORCE_SELINUX_TREBLE_LABELING
+
+# Path to a tracking list file for treble labeling
+_product_single_value_vars += PRODUCT_SELINUX_TREBLE_LABELING_TRACKING_LIST_FILE
+
 # List of .json files to be merged/compiled into vendor/etc/linker.config.pb and product/etc/linker.config.pb
 _product_list_vars += PRODUCT_VENDOR_LINKER_CONFIG_FRAGMENTS
 _product_list_vars += PRODUCT_PRODUCT_LINKER_CONFIG_FRAGMENTS
diff --git a/core/product_config.mk b/core/product_config.mk
index 13907f095e..f1ef447058 100644
--- a/core/product_config.mk
+++ b/core/product_config.mk
@@ -276,6 +276,19 @@ ifneq ($(ALLOW_RULES_IN_PRODUCT_CONFIG),)
 _product_config_saved_KATI_ALLOW_RULES :=
 endif
 
+# Sort/dedup all PRODUCT_PACKAGES variables. This is every PRODUCT_PACKAGES_* variable that appears
+# in product-installed-modules.
+PRODUCT_PACKAGES := $(sort $(PRODUCT_PACKAGES))
+PRODUCT_PACKAGES_DEBUG := $(sort $(PRODUCT_PACKAGES_DEBUG))
+PRODUCT_PACKAGES_ENG := $(sort $(PRODUCT_PACKAGES_ENG))
+PRODUCT_PACKAGES_TESTS := $(sort $(PRODUCT_PACKAGES_TESTS))
+PRODUCT_PACKAGES_DEBUG_ASAN := $(sort $(PRODUCT_PACKAGES_DEBUG_ASAN))
+PRODUCT_PACKAGES_DEBUG_JAVA_COVERAGE := $(sort $(PRODUCT_PACKAGES_DEBUG_JAVA_COVERAGE))
+PRODUCT_PACKAGES_ARM64 := $(sort $(PRODUCT_PACKAGES_ARM64))
+PRODUCT_PACKAGES_SHIPPING_API_LEVEL_29 := $(sort $(PRODUCT_PACKAGES_SHIPPING_API_LEVEL_29))
+PRODUCT_PACKAGES_SHIPPING_API_LEVEL_33 := $(sort $(PRODUCT_PACKAGES_SHIPPING_API_LEVEL_33))
+PRODUCT_PACKAGES_SHIPPING_API_LEVEL_34 := $(sort $(PRODUCT_PACKAGES_SHIPPING_API_LEVEL_34))
+
 ############################################################################
 
 current_product_makefile :=
@@ -287,7 +300,7 @@ current_product_makefile :=
 # TODO(b/308187268): Remove this denylist mechanism
 # Use PRODUCT_PACKAGES to determine if this is an aosp product. aosp products do not use google signed apexes.
 ignore_apex_contributions :=
-ifeq (,$(findstring com.google.android.conscrypt,$(PRODUCT_PACKAGES))$(findstring com.google.android.go.conscrypt,$(PRODUCT_PACKAGES)))
+ifeq (,$(filter com.google.android.conscrypt com.google.android.go.conscrypt com.google.android.extservices com.google.android.go.extservices,$(PRODUCT_PACKAGES)))
   ignore_apex_contributions := true
 endif
 ifeq (true,$(PRODUCT_MODULE_BUILD_FROM_SOURCE))
@@ -495,10 +508,6 @@ ifdef PRODUCT_INSTALL_DEBUG_POLICY_TO_SYSTEM_EXT
   endif
 endif
 
-ifndef PRODUCT_USE_DYNAMIC_PARTITIONS
-  PRODUCT_USE_DYNAMIC_PARTITIONS := $(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS)
-endif
-
 # All requirements of PRODUCT_USE_DYNAMIC_PARTITIONS falls back to
 # PRODUCT_USE_DYNAMIC_PARTITIONS if not defined.
 ifndef PRODUCT_USE_DYNAMIC_PARTITION_SIZE
@@ -532,21 +541,50 @@ ifdef OVERRIDE_PRODUCT_EXTRA_VNDK_VERSIONS
 endif
 
 ###########################################
-# APEXes are by default not compressed
+# PRODUCT_COMPRESSED_APEX: Use compressed apexes in pre-installed partitions.
+#
+# Note: this doesn't mean that all pre-installed apexes will be compressed.
+#  Whether an apex is compressed or not is controlled at apex Soong module
+#  via compresible property.
 #
 # APEX compression can be forcibly enabled (resp. disabled) by
 # setting OVERRIDE_PRODUCT_COMPRESSED_APEX to true (resp. false), e.g. by
 # setting the OVERRIDE_PRODUCT_COMPRESSED_APEX environment variable.
+
+_default_compressed_apex := true
+# To mount APEXes before /data partition is mounted, there should be no compressed
+# apexes.
+ifeq (true,$(RELEASE_APEX_MOUNT_BEFORE_DATA))
+  _default_compressed_apex := false
+endif
+
 ifdef OVERRIDE_PRODUCT_COMPRESSED_APEX
   PRODUCT_COMPRESSED_APEX := $(OVERRIDE_PRODUCT_COMPRESSED_APEX)
+else ifeq (,$(PRODUCT_COMPRESSED_APEX))
+  PRODUCT_COMPRESSED_APEX := $(_default_compressed_apex)
 endif
+ifeq (,$(filter true false,$(PRODUCT_COMPRESSED_APEX)))
+  $(error PRODUCT_COMPRESSED_APEX should be either true or false)
+endif
+PRODUCT_SYSTEM_PROPERTIES += apexd.config.compressed_apex=$(PRODUCT_COMPRESSED_APEX)
 
+###########################################
+# Set the default payload type for APEXes
+#
+_default_payload_fs_type := ext4
+ifeq (true,$(RELEASE_APEX_USE_EROFS_PREINSTALLED))
+  _default_payload_fs_type := erofs
+endif
+
+# Default APEX payload type can be forcibly set with
+# OVERRIDE_PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE.
 ifdef OVERRIDE_PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE
   PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE := $(OVERRIDE_PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE)
 else ifeq ($(PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE),)
-  # Use ext4 as a default payload fs type
-  PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE := ext4
+  PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE := $(_default_payload_fs_type)
 endif
+_default_payload_fs_type :=
+
 ifeq ($(filter ext4 erofs,$(PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE)),)
   $(error PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE should be either erofs or ext4,\
     not $(PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE).)
@@ -609,26 +647,23 @@ ifneq ($(call sdk-to-vendor-api-level,10000),10000000)
 $(error sdk-to-vendor-api-level is broken for current $(call sdk-to-vendor-api-level,10000))
 endif
 
-ifdef PRODUCT_SHIPPING_VENDOR_API_LEVEL
-# Follow the version that is set manually.
-  VSR_VENDOR_API_LEVEL := $(PRODUCT_SHIPPING_VENDOR_API_LEVEL)
-else
-  # VSR API level is the vendor api level of the product shipping API level.
-  VSR_VENDOR_API_LEVEL := $(call sdk-to-vendor-api-level,$(PLATFORM_SDK_VERSION))
-  ifdef PRODUCT_SHIPPING_API_LEVEL
-    VSR_VENDOR_API_LEVEL := $(call sdk-to-vendor-api-level,$(PRODUCT_SHIPPING_API_LEVEL))
-  endif
-  ifdef BOARD_SHIPPING_API_LEVEL
-    # Vendors with GRF must define BOARD_SHIPPING_API_LEVEL for the vendor API level.
-    # In this case, the VSR API level is the minimum of the PRODUCT_SHIPPING_API_LEVEL
-    # and RELEASE_BOARD_API_LEVEL
-    board_api_level := $(RELEASE_BOARD_API_LEVEL)
-    ifdef BOARD_API_LEVEL_PROP_OVERRIDE
-      board_api_level := $(BOARD_API_LEVEL_PROP_OVERRIDE)
-    endif
-    VSR_VENDOR_API_LEVEL := $(call math_min,$(VSR_VENDOR_API_LEVEL),$(board_api_level))
-    board_api_level :=
+# VSR API level is the vendor api level of the product shipping API level.
+VSR_VENDOR_API_LEVEL := $(call sdk-to-vendor-api-level,$(PLATFORM_SDK_VERSION))
+ifdef PRODUCT_SHIPPING_API_LEVEL
+  VSR_VENDOR_API_LEVEL := $(call sdk-to-vendor-api-level,$(PRODUCT_SHIPPING_API_LEVEL))
+endif
+ifdef BOARD_SHIPPING_API_LEVEL
+  # Vendors with GRF must define BOARD_SHIPPING_API_LEVEL for the vendor API level.
+  # In this case, the VSR API level is the minimum of the PRODUCT_SHIPPING_API_LEVEL
+  # and RELEASE_BOARD_API_LEVEL
+  board_api_level := $(RELEASE_BOARD_API_LEVEL)
+  ifdef BOARD_API_LEVEL_PROP_OVERRIDE
+    # This must be used only for testing purpose. Product must not be released
+    # with the modified api level value.
+    board_api_level := $(BOARD_API_LEVEL_PROP_OVERRIDE)
   endif
+  VSR_VENDOR_API_LEVEL := $(call math_min,$(VSR_VENDOR_API_LEVEL),$(board_api_level))
+  board_api_level :=
 endif
 .KATI_READONLY := VSR_VENDOR_API_LEVEL
 
diff --git a/core/product_validation_checks.mk b/core/product_validation_checks.mk
index e0d976f156..0cf5a69c09 100644
--- a/core/product_validation_checks.mk
+++ b/core/product_validation_checks.mk
@@ -54,7 +54,7 @@ _c+=$(newline))
 _c+=$(newline))
 _c+=$(foreach f,$(PRODUCT_VALIDATION_CHECKS),$(newline)validate_product_variables_$(call filename_to_starlark,$(f))(_ctx))
 _c+=$(newline)variables_to_export_to_make = {}
-$(KATI_file_no_rerun >$(OUT_DIR)/product_validation_checks_entrypoint.scl,$(_c))
+$(KATI_file_no_rerun >$(OUT_DIR)/product_validation_checks_entrypoint.$(TARGET_PRODUCT).scl,$(_c))
 filename_to_starlark:=
 escape_starlark_string:=
 product_variable_starlark_value:=
@@ -67,6 +67,6 @@ known_board_list_variables :=
 #
 # We also need to pass --allow_external_entrypoint to rbcrun in case the OUT_DIR is set to something
 # outside of the source tree.
-$(call run-starlark,$(OUT_DIR)/product_validation_checks_entrypoint.scl,$(OUT_DIR)/product_validation_checks_entrypoint.scl,--allow_external_entrypoint)
+$(call run-starlark,$(OUT_DIR)/product_validation_checks_entrypoint.$(TARGET_PRODUCT).scl,$(OUT_DIR)/product_validation_checks_entrypoint.$(TARGET_PRODUCT).scl,--allow_external_entrypoint)
 
 endif # ifdef PRODUCT_VALIDATION_CHECKS
diff --git a/core/proguard/checknotnull.flags b/core/proguard/checknotnull.flags
index 1e1e5ce46c..928835ea33 100644
--- a/core/proguard/checknotnull.flags
+++ b/core/proguard/checknotnull.flags
@@ -1,15 +1,13 @@
 # Tell R8 that the following methods are check not null methods, and to
 # replace invocations to them with a more concise nullness check that produces
-# (slightly) less informative error messages
+# (slightly) less informative error messages.
+# Note that we omit such optimizations for `Objects.requireNonNull`, as such
+# messages are explicit and surfaced in the framework across API boundaries.
 
 -convertchecknotnull class com.google.common.base.Preconditions {
   ** checkNotNull(...);
 }
 
--convertchecknotnull class java.util.Objects {
-  ** requireNonNull(...);
-}
-
 -convertchecknotnull class kotlin.jvm.internal.Intrinsics {
   void checkNotNull(...);
   void checkExpressionValueIsNotNull(...);
diff --git a/core/ravenwood_test_config_template.xml b/core/ravenwood_test_config_template.xml
index 9e9dd762ff..b9d7e724ea 100644
--- a/core/ravenwood_test_config_template.xml
+++ b/core/ravenwood_test_config_template.xml
@@ -24,21 +24,27 @@
     <option name="null-device" value="true" />
     <option name="do-not-swallow-runner-errors" value="true" />
 
+    <option name="java-flags" value="-Dandroid.ravenwood.version=1"/>
+
+    <option name="java-flags" value="--add-modules=jdk.compiler"/>
+    <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED"/>
+    <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.code=ALL-UNNAMED"/>
+    <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.comp=ALL-UNNAMED"/>
+    <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED"/>
+    <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.main=ALL-UNNAMED"/>
+    <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.parser=ALL-UNNAMED"/>
+    <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED"/>
+    <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED"/>
+
+    <!-- Needed for supporting ParcelFileDescriptor internals -->
+    <option name="java-flags" value="--add-exports=java.base/jdk.internal.access=ALL-UNNAMED"/>
+
     {EXTRA_CONFIGS}
 
     <test class="com.android.tradefed.testtype.IsolatedHostTest" >
+
+        {EXTRA_TEST_RUNNER_CONFIGS}
+
         <option name="jar" value="{MODULE}.jar" />
-        <option name="java-flags" value="--add-modules=jdk.compiler"/>
-        <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED"/>
-        <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.code=ALL-UNNAMED"/>
-        <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.comp=ALL-UNNAMED"/>
-        <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED"/>
-        <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.main=ALL-UNNAMED"/>
-        <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.parser=ALL-UNNAMED"/>
-        <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED"/>
-        <option name="java-flags" value="--add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED"/>
-
-        <!-- Needed for supporting ParcelFileDescriptor internals -->
-        <option name="java-flags" value="--add-exports=java.base/jdk.internal.access=ALL-UNNAMED"/>
     </test>
 </configuration>
diff --git a/core/release_config.mk b/core/release_config.mk
index c6986c704e..2815f5ea52 100644
--- a/core/release_config.mk
+++ b/core/release_config.mk
@@ -49,19 +49,7 @@ endif
 
 # If this is a google source tree, restrict it to only the one file
 # which has OWNERS control.  If it isn't let others define their own.
-config_map_files := $(wildcard build/release/release_config_map.mk) \
-    $(wildcard vendor/google_shared/build/release/release_config_map.mk) \
-    $(if $(wildcard vendor/google/release/release_config_map.mk), \
-        vendor/google/release/release_config_map.mk, \
-        $(sort \
-            $(wildcard device/*/release/release_config_map.mk) \
-            $(wildcard device/*/*/release/release_config_map.mk) \
-            $(wildcard vendor/*/release/release_config_map.mk) \
-            $(wildcard vendor/*/*/release/release_config_map.mk) \
-        ) \
-    )
-
-protobuf_map_files := build/release/release_config_map.textproto \
+_protobuf_map_files := build/release/release_config_map.textproto \
     $(wildcard vendor/google_shared/build/release/release_config_map.textproto) \
     $(if $(wildcard vendor/google/release/release_config_map.textproto), \
         vendor/google/release/release_config_map.textproto, \
@@ -73,184 +61,47 @@ protobuf_map_files := build/release/release_config_map.textproto \
         ) \
     )
 
-# Remove support for the legacy approach.
-_must_protobuf := true
-
 # PRODUCT_RELEASE_CONFIG_MAPS is set by Soong using an initial run of product
 # config to capture only the list of config maps needed by the build.
 # Keep them in the order provided, but remove duplicates.
-# Treat .mk and .textproto as equal for duplicate elimination, but force
-# protobuf if any PRODUCT_RELEASE_CONFIG_MAPS specify .textproto.
+# Treat any .mk file as an error, since those have not worked since ap3a.
 $(foreach map,$(PRODUCT_RELEASE_CONFIG_MAPS), \
-    $(if $(filter $(basename $(map)),$(basename $(config_map_files))),, \
-        $(eval config_map_files += $(map))) \
-    $(if $(filter $(basename $(map)).textproto,$(map)),$(eval _must_protobuf := true)) \
-)
-
-
-# If we are missing the textproto version of any of $(config_map_files), we cannot use protobuf.
-_can_protobuf := true
-$(foreach map,$(config_map_files), \
-    $(if $(wildcard $(basename $(map)).textproto),,$(eval _can_protobuf :=)) \
+    $(if $(filter $(basename $(map)).mk,$(map)),\
+        $(error $(map): use of release_config_map.mk files is not supported))\
+    $(if $(filter $(basename $(map)),$(basename $(_protobuf_map_files))),, \
+        $(eval _protobuf_map_files += $(map))) \
 )
-# If we are missing the mk version of any of $(protobuf_map_files), we must use protobuf.
-$(foreach map,$(protobuf_map_files), \
-    $(if $(wildcard $(basename $(map)).mk),,$(eval _must_protobuf := true)) \
-)
-
-ifneq (,$(_must_protobuf))
-    ifeq (,$(_can_protobuf))
-        # We must use protobuf, but we cannot use protobuf.
-        $(error release config is a mixture of .scl and .textproto)
-    endif
-endif
 
-_use_protobuf :=
-ifneq (,$(_must_protobuf))
-    _use_protobuf := true
-else
-    ifneq ($(_can_protobuf),)
-        # Determine the default
-        $(foreach map,$(config_map_files), \
-            $(if $(wildcard $(dir $(map))/build_config/DEFAULT=proto),$(eval _use_protobuf := true)) \
-            $(if $(wildcard $(dir $(map))/build_config/DEFAULT=make),$(eval _use_protobuf := )) \
-        )
-        # Update for this specific release config only (no inheritance).
-        $(foreach map,$(config_map_files), \
-            $(if $(wildcard $(dir $(map))/build_config/$(TARGET_RELEASE)=proto),$(eval _use_protobuf := true)) \
-            $(if $(wildcard $(dir $(map))/build_config/$(TARGET_RELEASE)=make),$(eval _use_protobuf := )) \
-        )
-    endif
+# The .textproto files are the canonical source of truth.
+_args := --guard=false $(foreach map,$(_protobuf_map_files), --map $(map) )
+_args += --allow-missing=true
+ifneq (,$(TARGET_PRODUCT))
+    _args += --product $(TARGET_PRODUCT)
 endif
-
-ifneq (,$(_use_protobuf))
-    # The .textproto files are the canonical source of truth.
-    _args := $(foreach map,$(config_map_files), --map $(map) )
-    ifneq (,$(_must_protobuf))
-        # Disable the build flag in release-config.
-        _args += --guard=false
-    endif
-    _args += --allow-missing=true
-    ifneq (,$(TARGET_PRODUCT))
-        _args += --product $(TARGET_PRODUCT)
-    endif
-    _flags_dir:=$(OUT_DIR)/soong/release-config
-    _flags_file:=$(_flags_dir)/release_config-$(TARGET_PRODUCT)-$(TARGET_RELEASE).vars
-    # release-config generates $(_flags_varmk)
-    _flags_varmk:=$(_flags_file:.vars=.varmk)
-    $(shell $(OUT_DIR)/release-config $(_args) >$(OUT_DIR)/release-config.out && touch -t 200001010000 $(_flags_varmk))
-    $(if $(filter-out 0,$(.SHELLSTATUS)),$(error release-config failed to run))
-    ifneq (,$(_final_product_config_pass))
-        # Save the final version of the config.
-        $(shell if ! cmp --quiet $(_flags_varmk) $(_flags_file); then cp $(_flags_varmk) $(_flags_file); fi)
-        # This will also set ALL_RELEASE_CONFIGS_FOR_PRODUCT and _used_files for us.
-        $(eval include $(_flags_file))
-        $(KATI_extra_file_deps $(OUT_DIR)/release-config $(protobuf_map_files) $(_flags_file))
-        ifneq (,$(_disallow_lunch_use))
-            $(error Release config ${TARGET_RELEASE} is disallowed for build.  Please use one of: $(ALL_RELEASE_CONFIGS_FOR_PRODUCT))
-        endif
-    else
-        # This is the first pass of product config.
-        $(eval include $(_flags_varmk))
-    endif
-    _used_files :=
-    ifeq (,$(_must_protobuf)$(RELEASE_BUILD_FLAGS_IN_PROTOBUF))
-        _use_protobuf :=
+_flags_dir:=$(OUT_DIR)/soong/release-config
+_flags_file:=$(_flags_dir)/release_config-$(TARGET_PRODUCT)-$(TARGET_RELEASE).vars
+# release-config generates $(_flags_varmk)
+_flags_varmk:=$(_flags_file:.vars=.varmk)
+$(shell $(OUT_DIR)/release-config $(_args) >$(OUT_DIR)/release-config.${TARGET_PRODUCT}.out && touch -t 200001010000 $(_flags_varmk))
+$(if $(filter-out 0,$(.SHELLSTATUS)),$(error release-config failed to run))
+ifneq (,$(_final_product_config_pass))
+    # Save the final version of the config.
+    $(shell if ! cmp --quiet $(_flags_varmk) $(_flags_file); then cp $(_flags_varmk) $(_flags_file); fi)
+    # This will also set ALL_RELEASE_CONFIGS_FOR_PRODUCT and _used_files for us.
+    $(eval include $(_flags_file))
+    $(KATI_extra_file_deps $(OUT_DIR)/release-config $(_protobuf_map_files) $(_flags_file))
+    ifneq (,$(_disallow_lunch_use))
+        $(error Release config ${TARGET_RELEASE} is disallowed for build.  Please use one of: $(ALL_RELEASE_CONFIGS_FOR_PRODUCT))
     endif
-    _flags_dir:=
-    _flags_file:=
-    _flags_varmk:=
-endif
-ifeq (,$(_use_protobuf))
-    # The .mk files are the canonical source of truth.
-
-
-# Declare an alias release-config
-#
-# This should be used to declare a release as an alias of another, meaning no
-# release config files should be present.
-#
-# $1 config name
-# $2 release config for which it is an alias
-define alias-release-config
-    $(call _declare-release-config,$(1),,$(2),true)
-endef
-
-# Declare or extend a release-config.
-#
-# The order of processing is:
-# 1. Recursively apply any overridden release configs.  Only apply each config
-#    the first time we reach it.
-# 2. Apply any files for this release config, in the order they were added to
-#    the declaration.
-#
-# Example:
-#   With these declarations:
-#     $(declare-release-config foo, foo.scl)
-#     $(declare-release-config bar, bar.scl, foo)
-#     $(declare-release-config baz, baz.scl, bar)
-#     $(declare-release-config bif, bif.scl, foo baz)
-#     $(declare-release-config bop, bop.scl, bar baz)
-#
-#   TARGET_RELEASE:
-#     - bar will use: foo.scl bar.scl
-#     - baz will use: foo.scl bar.scl baz.scl
-#     - bif will use: foo.scl bar.scl baz.scl bif.scl
-#     - bop will use: foo.scl bar.scl baz.scl bop.scl
-#
-# $1 config name
-# $2 release config files
-# $3 overridden release config
-define declare-release-config
-    $(call _declare-release-config,$(1),$(2),$(3),)
-endef
-
-define _declare-release-config
-    $(if $(strip $(2)$(3)),,  \
-        $(error declare-release-config: config $(strip $(1)) must have release config files, override another release config, or both) \
-    )
-    $(if $(strip $(4)),$(eval _all_release_configs.$(strip $(1)).ALIAS := true))
-    $(eval ALL_RELEASE_CONFIGS_FOR_PRODUCT := $(sort $(ALL_RELEASE_CONFIGS_FOR_PRODUCT) $(strip $(1))))
-    $(if $(strip $(3)), \
-      $(if $(filter $(ALL_RELEASE_CONFIGS_FOR_PRODUCT), $(strip $(3))),
-        $(if $(filter $(_all_release_configs.$(strip $(1)).OVERRIDES),$(strip $(3))),,
-          $(eval _all_release_configs.$(strip $(1)).OVERRIDES := $(_all_release_configs.$(strip $(1)).OVERRIDES) $(strip $(3)))), \
-        $(error No release config $(strip $(3))) \
-      ) \
-    )
-    $(eval _all_release_configs.$(strip $(1)).DECLARED_IN := $(_included) $(_all_release_configs.$(strip $(1)).DECLARED_IN))
-    $(eval _all_release_configs.$(strip $(1)).FILES := $(_all_release_configs.$(strip $(1)).FILES) $(strip $(2)))
-endef
-
-# Include the config map files and populate _flag_declaration_files.
-# If the file is found more than once, only include it the first time.
-_flag_declaration_files :=
-_included_config_map_files :=
-$(foreach f, $(config_map_files), \
-    $(eval FLAG_DECLARATION_FILES:= ) \
-    $(if $(filter $(_included_config_map_files),$(f)),,\
-        $(eval _included := $(f)) \
-        $(eval include $(f)) \
-        $(eval _flag_declaration_files += $(FLAG_DECLARATION_FILES)) \
-        $(eval _included_config_map_files += $(f)) \
-    ) \
-)
-FLAG_DECLARATION_FILES :=
-
-# Verify that all inherited/overridden release configs are declared.
-$(foreach config,$(ALL_RELEASE_CONFIGS_FOR_PRODUCT),\
-  $(foreach r,$(all_release_configs.$(r).OVERRIDES),\
-    $(if $(strip $(_all_release_configs.$(r).FILES)$(_all_release_configs.$(r).OVERRIDES)),,\
-    $(error Release config $(config) [declared in: $(_all_release_configs.$(r).DECLARED_IN)] inherits from non-existent $(r).)\
-)))
-# Verify that alias configs do not have config files.
-$(foreach r,$(ALL_RELEASE_CONFIGS_FOR_PRODUCT),\
-  $(if $(_all_release_configs.$(r).ALIAS),$(if $(_all_release_configs.$(r).FILES),\
-    $(error Alias release config "$(r)" may not specify release config files $(_all_release_configs.$(r).FILES))\
-)))
-
-# Use makefiles
+else
+    # This is the first pass of product config.
+    $(eval include $(_flags_varmk))
 endif
+_args:=
+_used_files:=
+_flags_dir:=
+_flags_file:=
+_flags_varmk:=
 
 ifeq ($(TARGET_RELEASE),)
     # We allow some internal paths to explicitly set TARGET_RELEASE to the
@@ -275,39 +126,6 @@ ifneq (,$(_final_product_config_pass))
     endif
 endif
 
-ifeq (,$(_use_protobuf))
-# Choose flag files
-# Don't sort this, use it in the order they gave us.
-# Do allow duplicate entries, retaining only the first usage.
-flag_value_files :=
-
-# Apply overrides recursively
-#
-# $1 release config that we override
-applied_releases :=
-define _apply-release-config-overrides
-$(foreach r,$(1), \
-  $(if $(filter $(r),$(applied_releases)),, \
-    $(foreach o,$(_all_release_configs.$(r).OVERRIDES),$(call _apply-release-config-overrides,$(o)))\
-    $(eval applied_releases += $(r))\
-    $(foreach f,$(_all_release_configs.$(r).FILES), \
-      $(if $(filter $(f),$(flag_value_files)),,$(eval flag_value_files += $(f)))\
-    )\
-  )\
-)
-endef
-$(call _apply-release-config-overrides,$(TARGET_RELEASE))
-# Unset variables so they can't use them
-define declare-release-config
-$(error declare-release-config can only be called from inside release_config_map.mk files)
-endef
-define _apply-release-config-overrides
-$(error invalid use of apply-release-config-overrides)
-endef
-
-# use makefiles
-endif
-
 # TODO: Remove this check after enough people have sourced lunch that we don't
 # need to worry about it trying to do get_build_vars TARGET_RELEASE. Maybe after ~9/2023
 ifneq ($(CALLED_FROM_SETUP),true)
@@ -319,58 +137,4 @@ TARGET_RELEASE:=
 endif
 .KATI_READONLY := TARGET_RELEASE
 
-ifeq (,$(_use_protobuf))
-$(foreach config, $(ALL_RELEASE_CONFIGS_FOR_PRODUCT), \
-    $(eval _all_release_configs.$(config).DECLARED_IN:= ) \
-    $(eval _all_release_configs.$(config).FILES:= ) \
-)
-applied_releases:=
-# use makefiles
-endif
-config_map_files:=
-protobuf_map_files:=
-
-
-ifeq (,$(_use_protobuf))
-# -----------------------------------------------------------------
-# Flag declarations and values
-# -----------------------------------------------------------------
-# This part is in starlark.  We generate a root starlark file that loads
-# all of the flags declaration files that we found, and the flag_value_files
-# that we chose from the config map above.  Then we run that, and load the
-# results of that into the make environment.
-
-# _flag_declaration_files is the combined list of FLAG_DECLARATION_FILES set by
-# release_config_map.mk files above.
-
-# Because starlark can't find files with $(wildcard), write an entrypoint starlark script that
-# contains the result of the above wildcards for the starlark code to use.
-filename_to_starlark=$(subst /,_,$(subst .,_,$(1)))
-_c:=load("//build/make/core/release_config.scl", "release_config")
-_c+=$(newline)def add(d, k, v):
-_c+=$(newline)$(space)d = dict(d)
-_c+=$(newline)$(space)d[k] = v
-_c+=$(newline)$(space)return d
-_c+=$(foreach f,$(_flag_declaration_files),$(newline)load("$(f)", flags_$(call filename_to_starlark,$(f)) = "flags"))
-_c+=$(newline)all_flags = [] $(foreach f,$(_flag_declaration_files),+ [add(x, "declared_in", "$(f)") for x in flags_$(call filename_to_starlark,$(f))])
-_c+=$(foreach f,$(flag_value_files),$(newline)load("//$(f)", values_$(call filename_to_starlark,$(f)) = "values"))
-_c+=$(newline)all_values = [] $(foreach f,$(flag_value_files),+ [add(x, "set_in", "$(f)") for x in values_$(call filename_to_starlark,$(f))])
-_c+=$(newline)variables_to_export_to_make = release_config(all_flags, all_values)
-$(file >$(OUT_DIR)/release_config_entrypoint.scl,$(_c))
-_c:=
-filename_to_starlark:=
-
-# Exclude the entrypoint file as a dependency (by passing it as the 2nd argument) so that we don't
-# rerun kati every build. Kati will replay the $(file) command that generates it every build,
-# updating its timestamp.
-#
-# We also need to pass --allow_external_entrypoint to rbcrun in case the OUT_DIR is set to something
-# outside of the source tree.
-$(call run-starlark,$(OUT_DIR)/release_config_entrypoint.scl,$(OUT_DIR)/release_config_entrypoint.scl,--allow_external_entrypoint)
-
-# use makefiles
-endif
-_can_protobuf :=
-_must_protobuf :=
-_use_protobuf :=
-
+_protobuf_map_files:=
diff --git a/core/release_config.scl b/core/release_config.scl
deleted file mode 100644
index c5815dfe30..0000000000
--- a/core/release_config.scl
+++ /dev/null
@@ -1,243 +0,0 @@
-# Copyright (C) 2023 The Android Open Source Project
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
-"""
-Export build flags (with values) to make.
-"""
-
-load("//build/bazel/utils:schema_validation.scl", "validate")
-
-# Partitions that get build system flag summaries
-_flag_partitions = [
-    "product",
-    "system",
-    "system_ext",
-    "vendor",
-]
-
-ALL = ["all"]
-PRODUCT = ["product"]
-SYSTEM = ["system"]
-SYSTEM_EXT = ["system_ext"]
-VENDOR = ["vendor"]
-
-_valid_types = ["NoneType", "bool", "list", "string", "int"]
-
-_all_flags_schema = {
-    "type": "list",
-    "of": {
-        "type": "dict",
-        "required_keys": {
-            "name": {"type": "string"},
-            "partitions": {
-                "type": "list",
-                "of": {
-                    "type": "string",
-                    "choices": _flag_partitions + ["all"],
-                },
-                "unique": True,
-            },
-            "default": {
-                "or": [
-                    {"type": t}
-                    for t in _valid_types
-                ],
-            },
-            "origin": {"type": "string"},
-            "declared_in": {"type": "string"},
-        },
-        "optional_keys": {
-            "appends": {
-                "type": "bool",
-            },
-        },
-    },
-}
-
-_all_values_schema = {
-    "type": "list",
-    "of": {
-        "type": "dict",
-        "required_keys": {
-            "name": {"type": "string"},
-            "value": {
-                "or": [
-                    {"type": t}
-                    for t in _valid_types
-                ],
-            },
-            "set_in": {"type": "string"},
-        },
-    },
-}
-
-def flag(name, partitions, default, *, origin = "Unknown", appends = False):
-    """Declare a flag.
-
-    Args:
-      name: name of the flag
-      partitions: the partitions where this should be recorded.
-      default: the default value of the flag.
-      origin: The origin of this flag.
-      appends: Whether new values should be append (not replace) the old.
-
-    Returns:
-      A dictionary containing the flag declaration.
-    """
-    if not partitions:
-        fail("At least 1 partition is required")
-    if not name.startswith("RELEASE_"):
-        fail("Release flag names must start with RELEASE_")
-    if " " in name or "\t" in name or "\n" in name:
-        fail("Flag names must not contain whitespace: \"" + name + "\"")
-    for partition in partitions:
-        if partition == "all":
-            if len(partitions) > 1:
-                fail("\"all\" can't be combined with other partitions: " + str(partitions))
-        elif partition not in _flag_partitions:
-            fail("Invalid partition: " + partition + ", allowed partitions: " +
-                 str(_flag_partitions))
-    if type(default) not in _valid_types:
-        fail("Invalid type of default for flag \"" + name + "\" (" + type(default) + ")")
-    return {
-        "name": name,
-        "partitions": partitions,
-        "default": default,
-        "appends": appends,
-        "origin": origin,
-    }
-
-def value(name, value):
-    """Define the flag value for a particular configuration.
-
-    Args:
-      name: The name of the flag.
-      value: The value for the flag.
-
-    Returns:
-      A dictionary containing the name and value to be used.
-    """
-    return {
-        "name": name,
-        "value": value,
-    }
-
-def _format_value(val):
-    """Format the starlark type correctly for make.
-
-    Args:
-      val: The value to format
-
-    Returns:
-      The value, formatted correctly for make.
-    """
-    if type(val) == "NoneType":
-        return ""
-    elif type(val) == "bool":
-        return "true" if val else ""
-    else:
-        return val
-
-def equal_flag_declaration(flag, other):
-    """Return true if the flag declarations are equal.
-
-    Args:
-      flag: This flag declaration.
-      other: Another flag declaration.
-
-    Returns:
-      Whether the declarations are the same.
-    """
-    for key in "name", "partitions", "default", "appends":
-        if flag[key] != other[key]:
-            return False
-    # For now, allow Unknown to match any other origin.
-    if flag["origin"] == "Unknown" or other["origin"] == "Unknown":
-        return True
-    return flag["origin"] == other["origin"]
-
-def release_config(all_flags, all_values):
-    """Return the make variables that should be set for this release config.
-
-    Args:
-      all_flags: A list of flag objects (from flag() calls).
-      all_values: A list of value objects (from value() calls).
-
-    Returns:
-      A dictionary of {name: value} variables for make.
-    """
-    validate(all_flags, _all_flags_schema)
-    validate(all_values, _all_values_schema)
-
-    # Final values.
-    values = {}
-    # Validate flags
-    flag_names = []
-    flags_dict = {}
-    for flag in all_flags:
-        name = flag["name"]
-        if name in flag_names:
-            if equal_flag_declaration(flag, flags_dict[name]):
-                continue
-            else:
-                fail(flag["declared_in"] + ": Duplicate declaration of flag " + name +
-                     " (declared first in " + flags_dict[name]["declared_in"] + ")")
-        flag_names.append(name)
-        flags_dict[name] = flag
-        # Set the flag value to the default value.
-        values[name] = {"name": name, "value": _format_value(flag["default"]), "set_in": flag["declared_in"]}
-
-    # Record which flags go on which partition
-    partitions = {}
-    for flag in all_flags:
-        for partition in flag["partitions"]:
-            if partition == "all":
-                if len(flag["partitions"]) > 1:
-                    fail("\"all\" can't be combined with other partitions: " + str(flag["partitions"]))
-                for partition in _flag_partitions:
-                    partitions.setdefault(partition, []).append(flag["name"])
-            else:
-                partitions.setdefault(partition, []).append(flag["name"])
-
-    # Generate final values.
-    # Only declared flags may have a value.
-    for value in all_values:
-        name = value["name"]
-        if name not in flag_names:
-            fail(value["set_in"] + ": Value set for undeclared build flag: " + name)
-        if flags_dict[name]["appends"]:
-            if name in values:
-                values[name]["value"] += " " + value["value"]
-                values[name]["set_in"] += " " + value["set_in"]
-            else:
-                values[name] = value
-        else:
-            values[name] = value
-
-    # Collect values
-    result = {
-        "_ALL_RELEASE_FLAGS": sorted(flag_names),
-    }
-    for partition, names in partitions.items():
-        result["_ALL_RELEASE_FLAGS.PARTITIONS." + partition] = names
-    for flag in all_flags:
-        val = _format_value(values[flag["name"]]["value"])
-        result[flag["name"]] = val
-        result["_ALL_RELEASE_FLAGS." + flag["name"] + ".PARTITIONS"] = flag["partitions"]
-        result["_ALL_RELEASE_FLAGS." + flag["name"] + ".DEFAULT"] = _format_value(flag["default"])
-        result["_ALL_RELEASE_FLAGS." + flag["name"] + ".VALUE"] = val
-        result["_ALL_RELEASE_FLAGS." + flag["name"] + ".DECLARED_IN"] = flag["declared_in"]
-        result["_ALL_RELEASE_FLAGS." + flag["name"] + ".SET_IN"] = values[flag["name"]]["set_in"]
-        result["_ALL_RELEASE_FLAGS." + flag["name"] + ".ORIGIN"] = flag["origin"]
-
-    return result
diff --git a/core/sbom.mk b/core/sbom.mk
index 39c251ae0c..44c40aee94 100644
--- a/core/sbom.mk
+++ b/core/sbom.mk
@@ -8,13 +8,13 @@ ifdef my_register_name
   ifneq (, $(strip $(ALL_MODULES.$(my_register_name).INSTALLED)))
     $(foreach installed_file,$(ALL_MODULES.$(my_register_name).INSTALLED),\
       $(eval ALL_INSTALLED_FILES.$(installed_file) := $(my_register_name))\
-      $(eval ALL_INSTALLED_FILES.$(installed_file).STATIC_LIBRARIES := $(foreach l,$(strip $(sort $(LOCAL_STATIC_LIBRARIES))),$l$(if $(LOCAL_2ND_ARCH_VAR_PREFIX),$($(my_prefix)2ND_ARCH_MODULE_SUFFIX))))\
-      $(eval ALL_INSTALLED_FILES.$(installed_file).WHOLE_STATIC_LIBRARIES := $(foreach l,$(strip $(sort $(LOCAL_WHOLE_STATIC_LIBRARIES))),$l$(if $(LOCAL_2ND_ARCH_VAR_PREFIX),$($(my_prefix)2ND_ARCH_MODULE_SUFFIX))))\
+      $(eval ALL_INSTALLED_FILES.$(installed_file).STATIC_LIBRARIES := $(foreach l,$(sort $(LOCAL_STATIC_LIBRARIES)),$l$(if $(LOCAL_2ND_ARCH_VAR_PREFIX),$($(my_prefix)2ND_ARCH_MODULE_SUFFIX))))\
+      $(eval ALL_INSTALLED_FILES.$(installed_file).WHOLE_STATIC_LIBRARIES := $(foreach l,$(sort $(LOCAL_WHOLE_STATIC_LIBRARIES)),$l$(if $(LOCAL_2ND_ARCH_VAR_PREFIX),$($(my_prefix)2ND_ARCH_MODULE_SUFFIX))))\
     )
   endif
   ifeq (STATIC_LIBRARIES,$(LOCAL_MODULE_CLASS))
-  ALL_STATIC_LIBRARIES.$(my_register_name).STATIC_LIBRARIES := $(foreach l,$(strip $(sort $(LOCAL_STATIC_LIBRARIES))),$l$($(my_prefix)2ND_ARCH_MODULE_SUFFIX))
-  ALL_STATIC_LIBRARIES.$(my_register_name).WHOLE_STATIC_LIBRARIES := $(foreach l,$(strip $(sort $(LOCAL_WHOLE_STATIC_LIBRARIES))),$l$($(my_prefix)2ND_ARCH_MODULE_SUFFIX))
+  ALL_STATIC_LIBRARIES.$(my_register_name).STATIC_LIBRARIES := $(foreach l,$(sort $(LOCAL_STATIC_LIBRARIES)),$l$($(my_prefix)2ND_ARCH_MODULE_SUFFIX))
+  ALL_STATIC_LIBRARIES.$(my_register_name).WHOLE_STATIC_LIBRARIES := $(foreach l,$(sort $(LOCAL_WHOLE_STATIC_LIBRARIES)),$l$($(my_prefix)2ND_ARCH_MODULE_SUFFIX))
   ifdef LOCAL_SOONG_MODULE_TYPE
     ALL_STATIC_LIBRARIES.$(my_register_name).BUILT_FILE := $(LOCAL_PREBUILT_MODULE_FILE)
   endif
diff --git a/core/shared_library_internal.mk b/core/shared_library_internal.mk
index ae34cb887d..77acd9934a 100644
--- a/core/shared_library_internal.mk
+++ b/core/shared_library_internal.mk
@@ -81,12 +81,6 @@ built_static_gcno_libraries := \
         STATIC_LIBRARIES,$(lib),$(my_kind),,$(LOCAL_2ND_ARCH_VAR_PREFIX), \
         $(my_host_cross))/$(lib)$(gcno_suffix))
 
-ifdef LOCAL_IS_HOST_MODULE
-my_coverage_path := $($(my_prefix)OUT_COVERAGE)/$(patsubst $($(my_prefix)OUT)/%,%,$(my_module_path))
-else
-my_coverage_path := $(TARGET_OUT_COVERAGE)/$(patsubst $(PRODUCT_OUT)/%,%,$(my_module_path))
-endif
-
 GCNO_ARCHIVE := $(basename $(my_installed_module_stem))$(gcno_suffix)
 
 $(intermediates)/$(GCNO_ARCHIVE) : $(SOONG_ZIP) $(MERGE_ZIPS)
@@ -94,11 +88,6 @@ $(intermediates)/$(GCNO_ARCHIVE) : PRIVATE_ALL_OBJECTS := $(strip $(LOCAL_GCNO_F
 $(intermediates)/$(GCNO_ARCHIVE) : PRIVATE_ALL_WHOLE_STATIC_LIBRARIES := $(strip $(built_whole_gcno_libraries)) $(strip $(built_static_gcno_libraries))
 $(intermediates)/$(GCNO_ARCHIVE) : $(LOCAL_GCNO_FILES) $(built_whole_gcno_libraries) $(built_static_gcno_libraries)
 	$(package-coverage-files)
-
-$(my_coverage_path)/$(GCNO_ARCHIVE) : $(intermediates)/$(GCNO_ARCHIVE)
-	$(copy-file-to-target)
-
-$(LOCAL_BUILT_MODULE): $(my_coverage_path)/$(GCNO_ARCHIVE)
 endif
 
 $(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=SHARED_LIBRARY))
diff --git a/core/soong_app_prebuilt.mk b/core/soong_app_prebuilt.mk
index 62b5d5bab1..c766667acb 100644
--- a/core/soong_app_prebuilt.mk
+++ b/core/soong_app_prebuilt.mk
@@ -85,10 +85,10 @@ else
 endif
 
 ifdef LOCAL_SOONG_JACOCO_REPORT_CLASSES_JAR
-  $(eval $(call copy-one-file,$(LOCAL_SOONG_JACOCO_REPORT_CLASSES_JAR),\
-    $(call local-packaging-dir,jacoco)/jacoco-report-classes.jar))
-  $(call add-dependency,$(LOCAL_BUILT_MODULE),\
-    $(call local-packaging-dir,jacoco)/jacoco-report-classes.jar)
+  ALL_MODULES.$(my_register_name).JACOCO_REPORT_FILES := $(LOCAL_SOONG_JACOCO_REPORT_CLASSES_JAR)
+  ALL_MODULES.$(my_register_name).JACOCO_REPORT_SOONG_ZIP_ARGUMENTS := \
+    -e out/target/common/obj/$(LOCAL_MODULE_CLASS)/$(LOCAL_MODULE)_intermediates/jacoco-report-classes.jar \
+    -f $(LOCAL_SOONG_JACOCO_REPORT_CLASSES_JAR)
 endif
 
 ifdef LOCAL_SOONG_PROGUARD_DICT
@@ -143,14 +143,6 @@ endif
 my_jni_lib_symbols_copy_files := $(foreach f,$(LOCAL_SOONG_JNI_LIBS_SYMBOLS),\
   $(call word-colon,1,$(f)):$(patsubst $(PRODUCT_OUT)/%,$(TARGET_OUT_UNSTRIPPED)/%,$(call word-colon,2,$(f))))
 
-$(foreach f, $(my_jni_lib_symbols_copy_files), \
-  $(eval $(call copy-unstripped-elf-file-with-mapping, \
-    $(call word-colon,1,$(f)), \
-    $(call word-colon,2,$(f)), \
-    $(patsubst $(TARGET_OUT_UNSTRIPPED)/%,$(call intermediates-dir-for,PACKAGING,elf_symbol_mapping)/%,$(call word-colon,2,$(f)).textproto)\
-  ))\
-)
-
 symbolic_outputs := $(foreach f,$(my_jni_lib_symbols_copy_files),$(call word-colon,2,$(f)))
 symbolic_mappings := $(foreach f,$(symbolic_outputs),$(patsubst $(TARGET_OUT_UNSTRIPPED)/%,$(call intermediates-dir-for,PACKAGING,elf_symbol_mapping)/%,$(f).textproto))
 ALL_MODULES.$(my_register_name).SYMBOLIC_OUTPUT_PATH := $(symbolic_outputs)
@@ -215,10 +207,6 @@ ifdef LOCAL_SOONG_BUNDLE
   ALL_MODULES.$(my_register_name).BUNDLE := $(LOCAL_SOONG_BUNDLE)
 endif
 
-ifdef LOCAL_SOONG_LINT_REPORTS
-  ALL_MODULES.$(my_register_name).LINT_REPORTS := $(LOCAL_SOONG_LINT_REPORTS)
-endif
-
 ifndef LOCAL_IS_HOST_MODULE
 ifeq ($(LOCAL_SDK_VERSION),system_current)
 my_link_type := java:system
@@ -238,13 +226,6 @@ my_common := COMMON
 include $(BUILD_SYSTEM)/link_type.mk
 endif # !LOCAL_IS_HOST_MODULE
 
-ifdef LOCAL_PREBUILT_COVERAGE_ARCHIVE
-  my_coverage_dir := $(TARGET_OUT_COVERAGE)/$(patsubst $(PRODUCT_OUT)/%,%,$(my_module_path))
-  my_coverage_copy_pairs := $(foreach f,$(LOCAL_PREBUILT_COVERAGE_ARCHIVE),$(f):$(my_coverage_dir)/$(notdir  $(f)))
-  my_coverage_files := $(call copy-many-files,$(my_coverage_copy_pairs))
-  $(LOCAL_INSTALLED_MODULE): $(my_coverage_files)
-endif
-
 SOONG_ALREADY_CONV += $(LOCAL_MODULE)
 
 ###########################################################
diff --git a/core/soong_cc_rust_prebuilt.mk b/core/soong_cc_rust_prebuilt.mk
index 9ea24f7e46..55fb4edf1d 100644
--- a/core/soong_cc_rust_prebuilt.mk
+++ b/core/soong_cc_rust_prebuilt.mk
@@ -195,23 +195,7 @@ ifndef LOCAL_IS_HOST_MODULE
       ALL_MODULES.$(my_register_name).SYMBOLIC_OUTPUT_PATH := $(symbolic_output)
       ALL_MODULES.$(my_register_name).ELF_SYMBOL_MAPPING_PATH := $(elf_symbol_mapping_path)
 
-      $(eval $(call copy-unstripped-elf-file-with-mapping,$(LOCAL_SOONG_UNSTRIPPED_BINARY),$(symbolic_output),$(elf_symbol_mapping_path)))
       $(LOCAL_BUILT_MODULE): | $(symbolic_output)
-
-      ifeq ($(BREAKPAD_GENERATE_SYMBOLS),true)
-        my_breakpad_path := $(TARGET_OUT_BREAKPAD)/$(patsubst $(PRODUCT_OUT)/%,%,$(my_symbol_path))
-        breakpad_output := $(my_breakpad_path)/$(my_installed_module_stem).sym
-        $(breakpad_output) : $(LOCAL_SOONG_UNSTRIPPED_BINARY) | $(BREAKPAD_DUMP_SYMS) $(PRIVATE_READELF)
-	@echo "target breakpad: $(PRIVATE_MODULE) ($@)"
-	@mkdir -p $(dir $@)
-	$(hide) if $(PRIVATE_READELF) -S $< > /dev/null 2>&1 ; then \
-	  $(BREAKPAD_DUMP_SYMS) -c $< > $@ ; \
-	else \
-	  echo "skipped for non-elf file."; \
-	  touch $@; \
-	fi
-        $(call add-dependency,$(LOCAL_BUILT_MODULE),$(breakpad_output))
-      endif
     endif
   endif
 endif
@@ -219,16 +203,6 @@ endif
 ifeq ($(NATIVE_COVERAGE),true)
   ifneq (,$(strip $(LOCAL_PREBUILT_COVERAGE_ARCHIVE)))
     $(eval $(call copy-one-file,$(LOCAL_PREBUILT_COVERAGE_ARCHIVE),$(intermediates)/$(LOCAL_MODULE).zip))
-    ifneq ($(LOCAL_UNINSTALLABLE_MODULE),true)
-      ifdef LOCAL_IS_HOST_MODULE
-        my_coverage_path := $($(my_prefix)OUT_COVERAGE)/$(patsubst $($(my_prefix)OUT)/%,%,$(my_module_path))
-      else
-        my_coverage_path := $(TARGET_OUT_COVERAGE)/$(patsubst $(PRODUCT_OUT)/%,%,$(my_module_path))
-      endif
-      my_coverage_path := $(my_coverage_path)/$(patsubst %.so,%,$(my_installed_module_stem)).zip
-      $(eval $(call copy-one-file,$(LOCAL_PREBUILT_COVERAGE_ARCHIVE),$(my_coverage_path)))
-      $(LOCAL_BUILT_MODULE): $(my_coverage_path)
-    endif
   else
     # Coverage information is needed when static lib is a dependency of another
     # coverage-enabled module.
@@ -253,9 +227,3 @@ $(LOCAL_INSTALLED_MODULE): PRIVATE_POST_INSTALL_CMD := \
 endif
 
 $(LOCAL_BUILT_MODULE): $(LOCAL_ADDITIONAL_DEPENDENCIES)
-
-# Reinstall shared library dependencies of fuzz targets to /data/fuzz/ (for
-# target) or /data/ (for host).
-ifdef LOCAL_IS_FUZZ_TARGET
-$(LOCAL_INSTALLED_MODULE): $(LOCAL_FUZZ_INSTALLED_SHARED_DEPS)
-endif
diff --git a/core/soong_config.mk b/core/soong_config.mk
index dcfe9ff6b3..75336a92aa 100644
--- a/core/soong_config.mk
+++ b/core/soong_config.mk
@@ -15,10 +15,6 @@ endif
 # PRODUCT_AFDO_PROFILES takes precedence over product-agnostic profiles in AFDO_PROFILES
 ALL_AFDO_PROFILES := $(PRODUCT_AFDO_PROFILES) $(AFDO_PROFILES)
 
-ifneq (,$(filter-out environment undefined,$(origin GENRULE_SANDBOXING)))
-  $(error GENRULE_SANDBOXING can only be provided via an environment variable, use BUILD_BROKEN_GENRULE_SANDBOXING to disable genrule sandboxing in board config)
-endif
-
 ifeq ($(WRITE_SOONG_VARIABLES),true)
 
 # Create soong.variables with copies of makefile settings.  Runs every build,
@@ -200,7 +196,6 @@ $(call add_json_bool, BuildingRecoveryImage,             $(BUILDING_RECOVERY_IMA
 $(call add_json_str,  UserdataPath,                      $(TARGET_COPY_OUT_DATA))
 $(call add_json_bool, BuildingUserdataImage,             $(BUILDING_USERDATA_IMAGE))
 
-$(call add_json_bool, UseGoma,                           $(filter-out false,$(USE_GOMA)))
 $(call add_json_bool, UseRBE,                            $(filter-out false,$(USE_RBE)))
 $(call add_json_bool, UseRBEJAVAC,                       $(filter-out false,$(RBE_JAVAC)))
 $(call add_json_bool, UseRBER8,                          $(filter-out false,$(RBE_R8)))
@@ -217,8 +212,8 @@ $(call add_json_list, SystemExtPublicSepolicyDirs,       $(SYSTEM_EXT_PUBLIC_SEP
 $(call add_json_list, SystemExtPrivateSepolicyDirs,      $(SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS))
 $(call add_json_list, BoardSepolicyM4Defs,               $(BOARD_SEPOLICY_M4DEFS))
 $(call add_json_str,  BoardSepolicyVers,                 $(BOARD_SEPOLICY_VERS))
-$(call add_json_str,  SystemExtSepolicyPrebuiltApiDir,   $(BOARD_SYSTEM_EXT_PREBUILT_DIR))
-$(call add_json_str,  ProductSepolicyPrebuiltApiDir,     $(BOARD_PRODUCT_PREBUILT_DIR))
+$(call add_json_list, SystemExtSepolicyPrebuiltApiDirs,  $(BOARD_SYSTEM_EXT_SEPOLICY_PREBUILT_DIRS))
+$(call add_json_list, ProductSepolicyPrebuiltApiDirs,    $(BOARD_PRODUCT_SEPOLICY_PREBUILT_DIRS))
 $(call add_json_str,  BoardPlatform,                     $(TARGET_BOARD_PLATFORM))
 
 $(call add_json_str,  PlatformSepolicyVersion,           $(PLATFORM_SEPOLICY_VERSION))
@@ -297,8 +292,6 @@ $(call add_json_list, BuildBrokenPluginValidation,         $(BUILD_BROKEN_PLUGIN
 $(call add_json_bool, BuildBrokenClangProperty,            $(filter true,$(BUILD_BROKEN_CLANG_PROPERTY)))
 $(call add_json_bool, BuildBrokenClangAsFlags,             $(filter true,$(BUILD_BROKEN_CLANG_ASFLAGS)))
 $(call add_json_bool, BuildBrokenClangCFlags,              $(filter true,$(BUILD_BROKEN_CLANG_CFLAGS)))
-# Use the value of GENRULE_SANDBOXING if set, otherwise use the inverse of BUILD_BROKEN_GENRULE_SANDBOXING
-$(call add_json_bool, GenruleSandboxing,                   $(if $(GENRULE_SANDBOXING),$(filter true,$(GENRULE_SANDBOXING)),$(if $(filter true,$(BUILD_BROKEN_GENRULE_SANDBOXING)),,true)))
 $(call add_json_bool, BuildBrokenEnforceSyspropOwner,      $(filter true,$(BUILD_BROKEN_ENFORCE_SYSPROP_OWNER)))
 $(call add_json_bool, BuildBrokenTrebleSyspropNeverallow,  $(filter true,$(BUILD_BROKEN_TREBLE_SYSPROP_NEVERALLOW)))
 $(call add_json_bool, BuildBrokenVendorPropertyNamespace,  $(filter true,$(BUILD_BROKEN_VENDOR_PROPERTY_NAMESPACE)))
@@ -307,8 +300,6 @@ $(call add_json_list, BuildBrokenInputDirModules,          $(BUILD_BROKEN_INPUT_
 $(call add_json_bool, BuildBrokenDontCheckSystemSdk,       $(filter true,$(BUILD_BROKEN_DONT_CHECK_SYSTEMSDK)))
 $(call add_json_bool, BuildBrokenDupSysprop,               $(filter true,$(BUILD_BROKEN_DUP_SYSPROP)))
 
-$(call add_json_list, BuildWarningBadOptionalUsesLibsAllowlist,    $(BUILD_WARNING_BAD_OPTIONAL_USES_LIBS_ALLOWLIST))
-
 $(call add_json_bool, BuildDebugfsRestrictionsEnabled, $(filter true,$(PRODUCT_SET_DEBUGFS_RESTRICTIONS)))
 
 $(call add_json_bool, RequiresInsecureExecmemForSwiftshader, $(filter true,$(PRODUCT_REQUIRES_INSECURE_EXECMEM_FOR_SWIFTSHADER)))
@@ -366,7 +357,7 @@ $(call add_json_list, VendorPropFiles, $(TARGET_VENDOR_PROP))
 # Do not set ArtTargetIncludeDebugBuild into any value if PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD is not set,
 # to have the same behavior from runtime_libart.mk.
 ifneq ($(PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD),)
-$(call add_json_bool, ArtTargetIncludeDebugBuild, $(PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD))
+$(call add_json_bool, ArtTargetIncludeDebugBuild, $(filter true,$(PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD)))
 endif
 
 _config_enable_uffd_gc := \
@@ -448,6 +439,7 @@ $(call add_json_map, PartitionVarsForSoongMigrationOnlyDoNotUse)
   $(call add_json_str, BoardVendorBootimagePartitionSize, $(BOARD_VENDOR_BOOTIMAGE_PARTITION_SIZE))
   $(call add_json_str, BoardInitBootimagePartitionSize, $(BOARD_INIT_BOOT_IMAGE_PARTITION_SIZE))
   $(call add_json_str, BoardBootHeaderVersion, $(BOARD_BOOT_HEADER_VERSION))
+  $(call add_json_str, BoardInitBootHeaderVersion, $(BOARD_INIT_BOOT_HEADER_VERSION))
   $(call add_json_str, TargetKernelPath, $(TARGET_KERNEL_PATH))
   $(call add_json_bool, BoardUsesGenericKernelImage, $(BOARD_USES_GENERIC_KERNEL_IMAGE))
   $(call add_json_str, BootSecurityPatch, $(BOOT_SECURITY_PATCH))
@@ -466,7 +458,6 @@ $(call add_json_map, PartitionVarsForSoongMigrationOnlyDoNotUse)
 
   # super image stuff
   $(call add_json_bool, ProductUseDynamicPartitions, $(filter true,$(PRODUCT_USE_DYNAMIC_PARTITIONS)))
-  $(call add_json_bool, ProductRetrofitDynamicPartitions, $(filter true,$(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS)))
   $(call add_json_bool, ProductBuildSuperPartition, $(filter true,$(PRODUCT_BUILD_SUPER_PARTITION)))
   $(call add_json_bool, BuildingSuperEmptyImage, $(filter true,$(BUILDING_SUPER_EMPTY_IMAGE)))
   $(call add_json_str, BoardSuperPartitionSize, $(BOARD_SUPER_PARTITION_SIZE))
@@ -481,7 +472,6 @@ $(call add_json_map, PartitionVarsForSoongMigrationOnlyDoNotUse)
       $(call end_json_map))
     $(call end_json_map)
   $(call add_json_bool, ProductVirtualAbOta, $(filter true,$(PRODUCT_VIRTUAL_AB_OTA)))
-  $(call add_json_bool, ProductVirtualAbOtaRetrofit, $(filter true,$(PRODUCT_VIRTUAL_AB_OTA_RETROFIT)))
   $(call add_json_bool, ProductVirtualAbCompression, $(filter true,$(PRODUCT_VIRTUAL_AB_COMPRESSION)))
   $(call add_json_str, ProductVirtualAbCompressionMethod, $(PRODUCT_VIRTUAL_AB_COMPRESSION_METHOD))
   $(call add_json_str, ProductVirtualAbCompressionFactor, $(PRODUCT_VIRTUAL_AB_COMPRESSION_FACTOR))
@@ -513,6 +503,13 @@ $(call add_json_map, PartitionVarsForSoongMigrationOnlyDoNotUse)
 
   $(call add_json_list, ProductPackages, $(PRODUCT_PACKAGES))
   $(call add_json_list, ProductPackagesDebug, $(PRODUCT_PACKAGES_DEBUG))
+  $(call add_json_list, ProductPackagesEng, $(PRODUCT_PACKAGES_ENG))
+  $(call add_json_list, ProductPackagesDebugAsan, $(PRODUCT_PACKAGES_DEBUG_ASAN))
+  $(call add_json_list, ProductPackagesDebugJavaCoverage, $(PRODUCT_PACKAGES_DEBUG_JAVA_COVERAGE))
+  $(call add_json_list, ProductPackagesArm64, $(PRODUCT_PACKAGES_ARM64))
+  $(call add_json_list, ProductPackagesShippingApiLevel29, $(PRODUCT_PACKAGES_SHIPPING_API_LEVEL_29))
+  $(call add_json_list, ProductPackagesShippingApiLevel33, $(PRODUCT_PACKAGES_SHIPPING_API_LEVEL_33))
+  $(call add_json_list, ProductPackagesShippingApiLevel34, $(PRODUCT_PACKAGES_SHIPPING_API_LEVEL_34))
 
   # Used to generate /vendor/linker.config.pb
   $(call add_json_list, VendorLinkerConfigSrcs, $(PRODUCT_VENDOR_LINKER_CONFIG_FRAGMENTS))
@@ -526,6 +523,7 @@ $(call add_json_map, PartitionVarsForSoongMigrationOnlyDoNotUse)
   $(call add_json_bool, BuildingVendorDlkmImage,               $(BUILDING_VENDOR_DLKM_IMAGE))
   $(call add_json_list, VendorKernelModules, $(BOARD_VENDOR_KERNEL_MODULES))
   $(call add_json_str, VendorKernelBlocklistFile, $(BOARD_VENDOR_KERNEL_MODULES_BLOCKLIST_FILE))
+  $(call add_json_list, VendorKernelModules2ndStage16kbMode, $(foreach k,$(BOARD_VENDOR_KERNEL_MODULES_2ND_STAGE_16KB_MODE),$(TARGET_KERNEL_DIR_16K)/$(k)))
   $(call add_json_bool, BuildingOdmDlkmImage,               $(BUILDING_ODM_DLKM_IMAGE))
   $(call add_json_list, OdmKernelModules, $(BOARD_ODM_KERNEL_MODULES))
   $(call add_json_str, OdmKernelBlocklistFile, $(BOARD_ODM_KERNEL_MODULES_BLOCKLIST_FILE))
@@ -533,6 +531,8 @@ $(call add_json_map, PartitionVarsForSoongMigrationOnlyDoNotUse)
   $(call add_json_str, VendorRamdiskKernelBlocklistFile, $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES_BLOCKLIST_FILE))
   $(call add_json_list, VendorRamdiskKernelLoadModules, $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES_LOAD))
   $(call add_json_str, VendorRamdiskKernelOptionsFile, $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES_OPTIONS_FILE))
+  $(call add_json_bool, DoNotStripVendorRamdiskModules, $(BOARD_DO_NOT_STRIP_VENDOR_RAMDISK_MODULES))
+  $(call add_json_bool, DoNotStripVendorModules, $(BOARD_DO_NOT_STRIP_VENDOR_MODULES))
 
   # Used to generate /vendor/build.prop
   $(call add_json_list, BoardInfoFiles, $(if $(TARGET_BOARD_INFO_FILES),$(TARGET_BOARD_INFO_FILES),$(firstword $(TARGET_BOARD_INFO_FILE) $(wildcard $(TARGET_DEVICE_DIR)/board-info.txt))))
@@ -575,6 +575,8 @@ $(call add_json_map, PartitionVarsForSoongMigrationOnlyDoNotUse)
   $(call add_json_str, BoardFlashBlockSize, $(BOARD_FLASH_BLOCK_SIZE))
   $(call add_json_bool, BootloaderInUpdatePackage, $(BOARD_BOOTLOADER_IN_UPDATE_PACKAGE))
 
+  $(call add_json_str, TargetRecoveryWipe, $(TARGET_RECOVERY_WIPE))
+
   # Fastboot
   $(call add_json_str, BoardFastbootInfoFile, $(TARGET_BOARD_FASTBOOT_INFO_FILE))
 
@@ -600,7 +602,23 @@ else
 endif
 $(call add_json_list, SystemExtManifestFiles, $(SYSTEM_EXT_MANIFEST_FILES) $(SYSTEM_EXT_HWSERVICE_FILES))
 $(call add_json_list, DeviceManifestFiles, $(DEVICE_MANIFEST_FILE))
+$(call add_json_list, DeviceManifestSkus, $(DEVICE_MANIFEST_SKUS))
 $(call add_json_list, OdmManifestFiles, $(ODM_MANIFEST_FILES))
+$(call add_json_list, OdmManifestSkus, $(ODM_MANIFEST_SKUS))
+
+$(call add_json_map,CompatibilityTestcases)
+$(foreach suite,$(sort $(patsubst COMPATIBILITY_TESTCASES_OUT_%,%,$(filter-out COMPATIBILITY_TESTCASES_OUT_INCLUDE_MODULE_FOLDER_%,$(filter COMPATIBILITY_TESTCASES_OUT_%,$(.VARIABLES))))),\
+  $(call add_json_map, $(suite)) \
+  $(call add_json_str, OutDir, $(COMPATIBILITY_TESTCASES_OUT_$(suite))) \
+  $(call add_json_bool, IncludeModuleFolder, $(COMPATIBILITY_TESTCASES_OUT_INCLUDE_MODULE_FOLDER_$(suite))) \
+  $(call end_json_map))
+$(call end_json_map)
+
+$(call add_json_list, ProductHostPackages, $(PRODUCT_HOST_PACKAGES))
+
+$(call add_json_bool, EnforceSELinuxTrebleLabeling, $(filter true,$(PRODUCT_ENFORCE_SELINUX_TREBLE_LABELING)))
+
+$(call add_json_str, SELinuxTrebleLabelingTrackingListFile, $(filter true,$(PRODUCT_SELINUX_TREBLE_LABELING_TRACKING_LIST_FILE)))
 
 $(call json_end)
 
diff --git a/core/soong_extra_config.mk b/core/soong_extra_config.mk
index 8eee50ae00..b1fb37c448 100644
--- a/core/soong_extra_config.mk
+++ b/core/soong_extra_config.mk
@@ -14,7 +14,6 @@ $(call add_json_str, SecondaryDex2oatInstructionSetFeatures, $($(TARGET_2ND_ARCH
 $(call add_json_str, BoardPlatform,          $(TARGET_BOARD_PLATFORM))
 $(call add_json_str, BoardShippingApiLevel,  $(BOARD_SHIPPING_API_LEVEL))
 $(call add_json_str, ShippingApiLevel,       $(PRODUCT_SHIPPING_API_LEVEL))
-$(call add_json_str, ShippingVendorApiLevel, $(PRODUCT_SHIPPING_VENDOR_API_LEVEL))
 
 $(call add_json_str, ProductModel,                      $(PRODUCT_MODEL))
 $(call add_json_str, ProductModelForAttestation,        $(PRODUCT_MODEL_FOR_ATTESTATION))
@@ -66,10 +65,6 @@ ifdef PRODUCT_USE_DYNAMIC_PARTITIONS
 $(call add_json_bool, UseDynamicPartitions, $(filter true,$(PRODUCT_USE_DYNAMIC_PARTITIONS)))
 endif
 
-ifdef PRODUCT_RETROFIT_DYNAMIC_PARTITIONS
-$(call add_json_bool, RetrofitDynamicPartitions, $(filter true,$(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS)))
-endif
-
 $(call add_json_bool, DontUseVabcOta, $(filter true,$(BOARD_DONT_USE_VABC_OTA)))
 
 $(call add_json_bool, FullTreble, $(filter true,$(PRODUCT_FULL_TREBLE)))
diff --git a/core/soong_java_prebuilt.mk b/core/soong_java_prebuilt.mk
index 8c3882f364..ac942c5ffd 100644
--- a/core/soong_java_prebuilt.mk
+++ b/core/soong_java_prebuilt.mk
@@ -28,7 +28,6 @@ include $(BUILD_SYSTEM)/base_rules.mk
 ifdef LOCAL_SOONG_CLASSES_JAR
   $(eval $(call copy-one-file,$(LOCAL_SOONG_CLASSES_JAR),$(full_classes_jar)))
   $(eval $(call copy-one-file,$(LOCAL_SOONG_CLASSES_JAR),$(full_classes_pre_proguard_jar)))
-  $(eval $(call add-dependency,$(LOCAL_BUILT_MODULE),$(full_classes_jar)))
 
   ifneq ($(TURBINE_ENABLED),false)
     ifdef LOCAL_SOONG_HEADER_JAR
@@ -42,10 +41,10 @@ endif
 $(eval $(call copy-one-file,$(LOCAL_PREBUILT_MODULE_FILE),$(LOCAL_BUILT_MODULE)))
 
 ifdef LOCAL_SOONG_JACOCO_REPORT_CLASSES_JAR
-  $(eval $(call copy-one-file,$(LOCAL_SOONG_JACOCO_REPORT_CLASSES_JAR),\
-    $(call local-packaging-dir,jacoco)/jacoco-report-classes.jar))
-  $(call add-dependency,$(common_javalib.jar),\
-    $(call local-packaging-dir,jacoco)/jacoco-report-classes.jar)
+  ALL_MODULES.$(my_register_name).JACOCO_REPORT_FILES := $(LOCAL_SOONG_JACOCO_REPORT_CLASSES_JAR)
+  ALL_MODULES.$(my_register_name).JACOCO_REPORT_SOONG_ZIP_ARGUMENTS := \
+    -e out/target/common/obj/$(LOCAL_MODULE_CLASS)/$(LOCAL_MODULE)_intermediates/jacoco-report-classes.jar \
+    -f $(LOCAL_SOONG_JACOCO_REPORT_CLASSES_JAR)
 endif
 
 ifdef LOCAL_SOONG_PROGUARD_DICT
@@ -116,9 +115,7 @@ ifdef LOCAL_SOONG_DEX_JAR
     endif # is_boot_jar
 
     $(eval $(call copy-one-file,$(LOCAL_SOONG_DEX_JAR),$(common_javalib.jar)))
-    $(eval $(call add-dependency,$(LOCAL_BUILT_MODULE),$(common_javalib.jar)))
     ifdef LOCAL_SOONG_CLASSES_JAR
-      $(eval $(call add-dependency,$(common_javalib.jar),$(full_classes_jar)))
       ifneq ($(TURBINE_ENABLED),false)
         $(eval $(call add-dependency,$(common_javalib.jar),$(full_classes_header_jar)))
       endif
diff --git a/core/sysprop_config.mk b/core/sysprop_config.mk
index 199150347c..0ccd53da28 100644
--- a/core/sysprop_config.mk
+++ b/core/sysprop_config.mk
@@ -58,19 +58,17 @@ ADDITIONAL_VENDOR_PROPERTIES += \
     ro.boot.dynamic_partitions=$(PRODUCT_USE_DYNAMIC_PARTITIONS)
 endif
 
-ifdef PRODUCT_RETROFIT_DYNAMIC_PARTITIONS
-ADDITIONAL_VENDOR_PROPERTIES += \
-    ro.boot.dynamic_partitions_retrofit=$(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS)
-endif
-
 ifdef PRODUCT_SHIPPING_API_LEVEL
 ADDITIONAL_VENDOR_PROPERTIES += \
     ro.product.first_api_level=$(PRODUCT_SHIPPING_API_LEVEL)
 endif
 
 ifdef PRODUCT_SHIPPING_VENDOR_API_LEVEL
-ADDITIONAL_VENDOR_PROPERTIES += \
-    ro.vendor.api_level=$(PRODUCT_SHIPPING_VENDOR_API_LEVEL)
+# PRODUCT_SHIPPING_VENDOR_API_LEVEL was used to set ro.vendor.api_level
+# manually for testing. To prevent using this variable for product release,
+# remove this variable and show an error message.
+$(error PRODUCT_SHIPPING_VENDOR_API_LEVEL is not available. ro.vendor.api_level\
+  property must not be set manually)
 endif
 
 ifneq ($(TARGET_BUILD_VARIANT),user)
@@ -94,6 +92,9 @@ ifdef BOARD_API_LEVEL
   ADDITIONAL_VENDOR_PROPERTIES += \
     ro.board.api_level?=$(BOARD_API_LEVEL)
   ifdef BOARD_API_LEVEL_PROP_OVERRIDE
+    # This must be used only for testing purpose. Product must not be released
+    # with the modified api level value.
+    $(warning BOARD_API_LEVEL_PROP_OVERRIDE can be defined only for testing purpose)
     ADDITIONAL_VENDOR_PROPERTIES += \
       ro.board.api_level=$(BOARD_API_LEVEL_PROP_OVERRIDE)
   endif
diff --git a/core/tasks/automotive-general-tests.mk b/core/tasks/automotive-general-tests.mk
index 44b62bef78..5497178f2a 100644
--- a/core/tasks/automotive-general-tests.mk
+++ b/core/tasks/automotive-general-tests.mk
@@ -24,17 +24,6 @@ automotive_general_tests_zip := $(PRODUCT_OUT)/automotive-general-tests.zip
 # Create an artifact to include a list of test config files in automotive-general-tests.
 automotive_general_tests_list_zip := $(PRODUCT_OUT)/automotive-general-tests_list.zip
 
-# Filter shared entries between automotive-general-tests and automotive-tests's HOST_SHARED_LIBRARY.FILES,
-# to avoid warning about overriding commands.
-my_host_shared_lib_for_automotive_general_tests := \
-  $(foreach m,$(filter $(COMPATIBILITY.automotive-tests.HOST_SHARED_LIBRARY.FILES),\
-	   $(COMPATIBILITY.automotive-general-tests.HOST_SHARED_LIBRARY.FILES)),$(call word-colon,2,$(m)))
-my_automotive_general_tests_shared_lib_files := \
-  $(filter-out $(COMPATIBILITY.automotive-tests.HOST_SHARED_LIBRARY.FILES),\
-	 $(COMPATIBILITY.automotive-general-tests.HOST_SHARED_LIBRARY.FILES))
-
-my_host_shared_lib_for_automotive_general_tests += $(call copy-many-files,$(my_automotive_general_tests_shared_lib_files))
-
 # Create an artifact to include all test config files in automotive-general-tests.
 automotive_general_tests_configs_zip := $(PRODUCT_OUT)/automotive-general-tests_configs.zip
 # Create an artifact to include all shared librariy files in automotive-general-tests.
@@ -44,7 +33,6 @@ $(automotive_general_tests_zip) : PRIVATE_automotive_general_tests_list_zip := $
 $(automotive_general_tests_zip) : .KATI_IMPLICIT_OUTPUTS := $(automotive_general_tests_list_zip) $(automotive_general_tests_configs_zip) $(automotive_general_tests_host_shared_libs_zip)
 $(automotive_general_tests_zip) : PRIVATE_TOOLS := $(automotive_general_tests_tools)
 $(automotive_general_tests_zip) : PRIVATE_INTERMEDIATES_DIR := $(intermediates_dir)
-$(automotive_general_tests_zip) : PRIVATE_HOST_SHARED_LIBS := $(my_host_shared_lib_for_automotive_general_tests)
 $(automotive_general_tests_zip) : PRIVATE_automotive_general_tests_configs_zip := $(automotive_general_tests_configs_zip)
 $(automotive_general_tests_zip) : PRIVATE_general_host_shared_libs_zip := $(automotive_general_tests_host_shared_libs_zip)
 $(automotive_general_tests_zip) : $(COMPATIBILITY.automotive-general-tests.FILES) $(automotive_general_tests_tools) $(my_host_shared_lib_for_automotive_general_tests) $(SOONG_ZIP)
@@ -56,11 +44,6 @@ $(automotive_general_tests_zip) : $(COMPATIBILITY.automotive-general-tests.FILES
 	grep $(TARGET_OUT_TESTCASES) $(PRIVATE_INTERMEDIATES_DIR)/list > $(PRIVATE_INTERMEDIATES_DIR)/target.list || true
 	grep -e .*\\.config$$ $(PRIVATE_INTERMEDIATES_DIR)/host.list > $(PRIVATE_INTERMEDIATES_DIR)/host-test-configs.list || true
 	grep -e .*\\.config$$ $(PRIVATE_INTERMEDIATES_DIR)/target.list > $(PRIVATE_INTERMEDIATES_DIR)/target-test-configs.list || true
-	$(hide) for shared_lib in $(PRIVATE_HOST_SHARED_LIBS); do \
-	  echo $$shared_lib >> $(PRIVATE_INTERMEDIATES_DIR)/host.list; \
-	  echo $$shared_lib >> $(PRIVATE_INTERMEDIATES_DIR)/shared-libs.list; \
-	done
-	grep $(HOST_OUT_TESTCASES) $(PRIVATE_INTERMEDIATES_DIR)/shared-libs.list > $(PRIVATE_INTERMEDIATES_DIR)/host-shared-libs.list || true
 	cp -fp $(PRIVATE_TOOLS) $(PRIVATE_INTERMEDIATES_DIR)/tools/
 	$(SOONG_ZIP) -d -o $@ \
 	  -P host -C $(PRIVATE_INTERMEDIATES_DIR) -D $(PRIVATE_INTERMEDIATES_DIR)/tools \
@@ -69,8 +52,7 @@ $(automotive_general_tests_zip) : $(COMPATIBILITY.automotive-general-tests.FILES
 	$(SOONG_ZIP) -d -o $(PRIVATE_automotive_general_tests_configs_zip) \
 	  -P host -C $(HOST_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/host-test-configs.list \
 	  -P target -C $(PRODUCT_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/target-test-configs.list
-	$(SOONG_ZIP) -d -o $(PRIVATE_general_host_shared_libs_zip) \
-	  -P host -C $(HOST_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/host-shared-libs.list
+	$(SOONG_ZIP) -o $(PRIVATE_general_host_shared_libs_zip) # empty file
 	grep -e .*\\.config$$ $(PRIVATE_INTERMEDIATES_DIR)/host.list | sed s%$(HOST_OUT)%host%g > $(PRIVATE_INTERMEDIATES_DIR)/automotive-general-tests_list
 	grep -e .*\\.config$$ $(PRIVATE_INTERMEDIATES_DIR)/target.list | sed s%$(PRODUCT_OUT)%target%g >> $(PRIVATE_INTERMEDIATES_DIR)/automotive-general-tests_list
 	$(SOONG_ZIP) -d -o $(PRIVATE_automotive_general_tests_list_zip) -C $(PRIVATE_INTERMEDIATES_DIR) -f $(PRIVATE_INTERMEDIATES_DIR)/automotive-general-tests_list
diff --git a/core/tasks/automotive-sdv-tests.mk b/core/tasks/automotive-sdv-tests.mk
index 12706ce33d..c13e8ceaf7 100644
--- a/core/tasks/automotive-sdv-tests.mk
+++ b/core/tasks/automotive-sdv-tests.mk
@@ -20,37 +20,28 @@ automotive-sdv-tests-zip := $(PRODUCT_OUT)/automotive-sdv-tests.zip
 automotive-sdv-tests-list-zip := $(PRODUCT_OUT)/automotive-sdv-tests_list.zip
 # Create an artifact to include all test config files in automotive-sdv-tests.
 automotive-sdv-tests-configs-zip := $(PRODUCT_OUT)/automotive-sdv-tests_configs.zip
-my_host_shared_lib_for_automotive_sdv_tests := $(call copy-many-files,$(COMPATIBILITY.automotive-sdv-tests.HOST_SHARED_LIBRARY.FILES))
 automotive_sdv_tests_host_shared_libs_zip := $(PRODUCT_OUT)/automotive-sdv-tests_host-shared-libs.zip
 
 $(automotive-sdv-tests-zip) : .KATI_IMPLICIT_OUTPUTS := $(automotive-sdv-tests-list-zip) $(automotive-sdv-tests-configs-zip) $(automotive_sdv_tests_host_shared_libs_zip)
 $(automotive-sdv-tests-zip) : PRIVATE_automotive_sdv_tests_list := $(PRODUCT_OUT)/automotive-sdv-tests_list
-$(automotive-sdv-tests-zip) : PRIVATE_HOST_SHARED_LIBS := $(my_host_shared_lib_for_automotive_sdv_tests)
 $(automotive-sdv-tests-zip) : PRIVATE_automotive_host_shared_libs_zip := $(automotive_sdv_tests_host_shared_libs_zip)
 $(automotive-sdv-tests-zip) : $(COMPATIBILITY.automotive-sdv-tests.FILES) $(my_host_shared_lib_for_automotive_sdv_tests) $(SOONG_ZIP)
-	rm -f $@-shared-libs.list
 	echo $(sort $(COMPATIBILITY.automotive-sdv-tests.FILES)) | tr " " "\n" > $@.list
 	grep $(HOST_OUT_TESTCASES) $@.list > $@-host.list || true
 	grep -e .*\\.config$$ $@-host.list > $@-host-test-configs.list || true
-	$(hide) for shared_lib in $(PRIVATE_HOST_SHARED_LIBS); do \
-	  echo $$shared_lib >> $@-host.list; \
-	  echo $$shared_lib >> $@-shared-libs.list; \
-	done
-	grep $(HOST_OUT_TESTCASES) $@-shared-libs.list > $@-host-shared-libs.list || true
 	grep $(TARGET_OUT_TESTCASES) $@.list > $@-target.list || true
 	grep -e .*\\.config$$ $@-target.list > $@-target-test-configs.list || true
 	$(hide) $(SOONG_ZIP) -d -o $@ -P host -C $(HOST_OUT) -l $@-host.list -P target -C $(PRODUCT_OUT) -l $@-target.list
 	$(hide) $(SOONG_ZIP) -d -o $(automotive-sdv-tests-configs-zip) \
 	  -P host -C $(HOST_OUT) -l $@-host-test-configs.list \
 	  -P target -C $(PRODUCT_OUT) -l $@-target-test-configs.list
-	$(SOONG_ZIP) -d -o $(PRIVATE_automotive_host_shared_libs_zip) \
-	  -P host -C $(HOST_OUT) -l $@-host-shared-libs.list
+	$(SOONG_ZIP) -o $(PRIVATE_automotive_host_shared_libs_zip) # empty file
 	rm -f $(PRIVATE_automotive_sdv_tests_list)
 	$(hide) grep -e .*\\.config$$ $@-host.list | sed s%$(HOST_OUT)%host%g > $(PRIVATE_automotive_sdv_tests_list)
 	$(hide) grep -e .*\\.config$$ $@-target.list | sed s%$(PRODUCT_OUT)%target%g >> $(PRIVATE_automotive_sdv_tests_list)
 	$(hide) $(SOONG_ZIP) -d -o $(automotive-sdv-tests-list-zip) -C $(dir $@) -f $(PRIVATE_automotive_sdv_tests_list)
 	rm -f $@.list $@-host.list $@-target.list $@-host-test-configs.list $@-target-test-configs.list \
-	  $@-shared-libs.list $@-host-shared-libs.list $(PRIVATE_automotive_sdv_tests_list)
+	  $(PRIVATE_automotive_sdv_tests_list)
 
 automotive-sdv-tests: $(automotive-sdv-tests-zip)
 $(call dist-for-goals, automotive-sdv-tests, $(automotive-sdv-tests-zip) $(automotive-sdv-tests-list-zip) $(automotive-sdv-tests-configs-zip) $(automotive_sdv_tests_host_shared_libs_zip))
diff --git a/core/tasks/automotive-tests.mk b/core/tasks/automotive-tests.mk
index da6af6bb3c..c163b5d8cb 100644
--- a/core/tasks/automotive-tests.mk
+++ b/core/tasks/automotive-tests.mk
@@ -20,37 +20,28 @@ automotive-tests-zip := $(PRODUCT_OUT)/automotive-tests.zip
 automotive-tests-list-zip := $(PRODUCT_OUT)/automotive-tests_list.zip
 # Create an artifact to include all test config files in automotive-tests.
 automotive-tests-configs-zip := $(PRODUCT_OUT)/automotive-tests_configs.zip
-my_host_shared_lib_for_automotive_tests := $(call copy-many-files,$(COMPATIBILITY.automotive-tests.HOST_SHARED_LIBRARY.FILES))
 automotive_tests_host_shared_libs_zip := $(PRODUCT_OUT)/automotive-tests_host-shared-libs.zip
 
 $(automotive-tests-zip) : .KATI_IMPLICIT_OUTPUTS := $(automotive-tests-list-zip) $(automotive-tests-configs-zip) $(automotive_tests_host_shared_libs_zip)
 $(automotive-tests-zip) : PRIVATE_automotive_tests_list := $(PRODUCT_OUT)/automotive-tests_list
-$(automotive-tests-zip) : PRIVATE_HOST_SHARED_LIBS := $(my_host_shared_lib_for_automotive_tests)
 $(automotive-tests-zip) : PRIVATE_automotive_host_shared_libs_zip := $(automotive_tests_host_shared_libs_zip)
 $(automotive-tests-zip) : $(COMPATIBILITY.automotive-tests.FILES) $(my_host_shared_lib_for_automotive_tests) $(SOONG_ZIP)
-	rm -f $@-shared-libs.list
 	echo $(sort $(COMPATIBILITY.automotive-tests.FILES)) | tr " " "\n" > $@.list
 	grep $(HOST_OUT_TESTCASES) $@.list > $@-host.list || true
 	grep -e .*\\.config$$ $@-host.list > $@-host-test-configs.list || true
-	$(hide) for shared_lib in $(PRIVATE_HOST_SHARED_LIBS); do \
-	  echo $$shared_lib >> $@-host.list; \
-	  echo $$shared_lib >> $@-shared-libs.list; \
-	done
-	grep $(HOST_OUT_TESTCASES) $@-shared-libs.list > $@-host-shared-libs.list || true
 	grep $(TARGET_OUT_TESTCASES) $@.list > $@-target.list || true
 	grep -e .*\\.config$$ $@-target.list > $@-target-test-configs.list || true
 	$(hide) $(SOONG_ZIP) -d -o $@ -P host -C $(HOST_OUT) -l $@-host.list -P target -C $(PRODUCT_OUT) -l $@-target.list
 	$(hide) $(SOONG_ZIP) -d -o $(automotive-tests-configs-zip) \
 	  -P host -C $(HOST_OUT) -l $@-host-test-configs.list \
 	  -P target -C $(PRODUCT_OUT) -l $@-target-test-configs.list
-	$(SOONG_ZIP) -d -o $(PRIVATE_automotive_host_shared_libs_zip) \
-	  -P host -C $(HOST_OUT) -l $@-host-shared-libs.list
+	$(SOONG_ZIP) -o $(PRIVATE_automotive_host_shared_libs_zip) # empty file
 	rm -f $(PRIVATE_automotive_tests_list)
 	$(hide) grep -e .*\\.config$$ $@-host.list | sed s%$(HOST_OUT)%host%g > $(PRIVATE_automotive_tests_list)
 	$(hide) grep -e .*\\.config$$ $@-target.list | sed s%$(PRODUCT_OUT)%target%g >> $(PRIVATE_automotive_tests_list)
 	$(hide) $(SOONG_ZIP) -d -o $(automotive-tests-list-zip) -C $(dir $@) -f $(PRIVATE_automotive_tests_list)
 	rm -f $@.list $@-host.list $@-target.list $@-host-test-configs.list $@-target-test-configs.list \
-	  $@-shared-libs.list $@-host-shared-libs.list $(PRIVATE_automotive_tests_list)
+	  $(PRIVATE_automotive_tests_list)
 
 automotive-tests: $(automotive-tests-zip)
 $(call dist-for-goals, automotive-tests, $(automotive-tests-zip) $(automotive-tests-list-zip) $(automotive-tests-configs-zip) $(automotive_tests_host_shared_libs_zip))
diff --git a/core/tasks/check-abi-dump-list.mk b/core/tasks/check-abi-dump-list.mk
index 81d549e46f..80a3a128cf 100644
--- a/core/tasks/check-abi-dump-list.mk
+++ b/core/tasks/check-abi-dump-list.mk
@@ -104,17 +104,17 @@ PLATFORM_ABI_DUMPS := $(call find-abi-dump-paths,$(PLATFORM_ABI_DUMP_DIR))
 $(check-abi-dump-list-timestamp): PRIVATE_LSDUMP_PATHS := $(LSDUMP_PATHS)
 $(check-abi-dump-list-timestamp): PRIVATE_STUB_LIBRARIES := $(STUB_LIBRARIES)
 $(check-abi-dump-list-timestamp):
-	$(eval added_vndk_abi_dumps := $(strip $(sort $(filter-out \
+	$(eval added_vndk_abi_dumps := $(sort $(filter-out \
 	  $(call filter-abi-dump-names,LLNDK,$(PRIVATE_LSDUMP_PATHS)) libRS.so.lsdump, \
-	  $(notdir $(VNDK_ABI_DUMPS))))))
+	  $(notdir $(VNDK_ABI_DUMPS)))))
 	$(if $(added_vndk_abi_dumps), \
 	  echo -e "Found unexpected ABI reference dump files under $(VNDK_ABI_DUMP_DIR). It is caused by mismatch between Android.bp and the dump files. Run \`find \$${ANDROID_BUILD_TOP}/$(VNDK_ABI_DUMP_DIR) '(' -name $(subst $(space), -or -name ,$(added_vndk_abi_dumps)) ')' -delete\` to delete the dump files.")
 
 	# TODO(b/314010764): Remove LLNDK tag after PLATFORM_SDK_VERSION is upgraded to 35.
-	$(eval added_platform_abi_dumps := $(strip $(sort $(filter-out \
+	$(eval added_platform_abi_dumps := $(sort $(filter-out \
 	  $(call filter-abi-dump-names,APEX LLNDK PLATFORM,$(PRIVATE_LSDUMP_PATHS)) \
 	  $(addsuffix .lsdump,$(PRIVATE_STUB_LIBRARIES)) libRS.so.lsdump, \
-	  $(notdir $(PLATFORM_ABI_DUMPS))))))
+	  $(notdir $(PLATFORM_ABI_DUMPS)))))
 	$(if $(added_platform_abi_dumps), \
 	  echo -e "Found unexpected ABI reference dump files under $(PLATFORM_ABI_DUMP_DIR). It is caused by mismatch between Android.bp and the dump files. Run \`find \$${ANDROID_BUILD_TOP}/$(PLATFORM_ABI_DUMP_DIR) '(' -name $(subst $(space), -or -name ,$(added_platform_abi_dumps)) ')' -delete\` to delete the dump files.")
 
diff --git a/core/tasks/cts.mk b/core/tasks/cts.mk
index c7b5cad5eb..7c237a310e 100644
--- a/core/tasks/cts.mk
+++ b/core/tasks/cts.mk
@@ -101,6 +101,20 @@ $(verifier-zip): $(SOONG_ANDROID_CTS_VERIFIER_ZIP) $(cts-v-host-zip) $(SOONG_ZIP
 endif
 $(call dist-for-goals, cts, $(verifier-zip))
 
+cts_files_metadata := $(HOST_OUT)/cts/cts_files_metadata.textproto
+file_metadata_generation_tool := $(HOST_OUT_EXECUTABLES)/file_metadata_generation$(HOST_EXECUTABLE_SUFFIX)
+aapt2_tool := $(HOST_OUT_EXECUTABLES)/aapt2$(HOST_EXECUTABLE_SUFFIX)
+$(cts_files_metadata): PRIVATE_TESTCASES_DIR := $(HOST_OUT)/cts/android-cts/testcases
+$(cts_files_metadata): PRIVATE_AAPT2_TOOL := $(aapt2_tool)
+$(cts_files_metadata): PRIVATE_METADATA_TOOL := $(file_metadata_generation_tool)
+$(cts_files_metadata): PRIVATE_SDK_VERSION := $(PLATFORM_SDK_VERSION)
+$(cts_files_metadata): $(file_metadata_generation_tool) $(aapt2_tool) $(compatibility_zip)
+	$(PRIVATE_METADATA_TOOL) --testcases_dir $(PRIVATE_TESTCASES_DIR)\
+	--aapt2 $(PRIVATE_AAPT2_TOOL) --sdk_version $(PRIVATE_SDK_VERSION) --output $@
+
+ALL_TARGETS.$(cts_files_metadata).META_LIC:=$(module_license_metadata)
+$(call dist-for-goals, cts-api-coverage, $(cts_files_metadata))
+
 # For producing CTS coverage reports.
 # Run "make cts-test-coverage" in the $ANDROID_BUILD_TOP directory.
 
@@ -296,12 +310,6 @@ cts-combined-api-map-xml : $(cts-combined-api-map-xml-report)
 .PHONY: cts-combined-api-inherit-xml
 cts-combined-api-inherit-xml : $(cts-combined-api-inherit-xml-report)
 
-.PHONY: cts-api-map-all
-
-# Put the test coverage report in the dist dir if "cts-api-coverage" is among the build goals.
-$(call dist-for-goals, cts-api-coverage, $(cts-system-api-xml-coverage-report):cts-system-api-coverage-report.xml)
-$(call dist-for-goals, cts-api-coverage, $(cts-combined-xml-coverage-report):cts-combined-coverage-report.xml)
-
 ALL_TARGETS.$(cts-test-coverage-report).META_LIC:=$(module_license_metadata)
 ALL_TARGETS.$(cts-system-api-coverage-report).META_LIC:=$(module_license_metadata)
 ALL_TARGETS.$(cts-system-api-xml-coverage-report).META_LIC:=$(module_license_metadata)
@@ -309,9 +317,9 @@ ALL_TARGETS.$(cts-verifier-coverage-report).META_LIC:=$(module_license_metadata)
 ALL_TARGETS.$(cts-combined-coverage-report).META_LIC:=$(module_license_metadata)
 ALL_TARGETS.$(cts-combined-xml-coverage-report).META_LIC:=$(module_license_metadata)
 
-# Put the test api map report in the dist dir if "cts-api-map-all" is among the build goals.
-$(call dist-for-goals, cts-api-map-all, $(cts-combined-api-map-xml-report):cts-api-map-report.xml)
-$(call dist-for-goals, cts-api-map-all, $(cts-combined-api-inherit-xml-report):cts-api-inherit-report.xml)
+# Put the test api map report in the dist dir if "cts-api-coverage" is among the build goals.
+$(call dist-for-goals, cts-api-coverage, $(cts-combined-api-map-xml-report):cts-api-map-report.xml)
+$(call dist-for-goals, cts-api-coverage, $(cts-combined-api-inherit-xml-report):cts-api-inherit-report.xml)
 
 ALL_TARGETS.$(cts-api-map-xml-report).META_LIC:=$(module_license_metadata)
 ALL_TARGETS.$(cts-v-host-api-map-xml-report).META_LIC:=$(module_license_metadata)
@@ -387,3 +395,6 @@ verifier-dir :=
 verifier-zip-name :=
 verifier-zip :=
 cts-v-host-zip :=
+cts_files_metadata :=
+file_metadata_generation_tool :=
+aapt2_tool :=
diff --git a/core/tasks/device-platinum-tests.mk b/core/tasks/device-platinum-tests.mk
deleted file mode 100644
index 75f4c4c29b..0000000000
--- a/core/tasks/device-platinum-tests.mk
+++ /dev/null
@@ -1,71 +0,0 @@
-# Copyright (C) 2024 The Android Open Source Project
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
-
-
-.PHONY: device-platinum-tests
-
-device_platinum_tests_zip := $(PRODUCT_OUT)/device-platinum-tests.zip
-# Create an artifact to include a list of test config files in device-platinum-tests.
-device_platinum_tests_list_zip := $(PRODUCT_OUT)/device-platinum-tests_list.zip
-# Create an artifact to include all test config files in device-platinum-tests.
-device_platinum_tests_configs_zip := $(PRODUCT_OUT)/device-platinum-tests_configs.zip
-my_host_shared_lib_for_device_platinum_tests := $(call copy-many-files,$(COMPATIBILITY.device-platinum-tests.HOST_SHARED_LIBRARY.FILES))
-device_platinum_tests_host_shared_libs_zip := $(PRODUCT_OUT)/device-platinum-tests_host-shared-libs.zip
-
-$(device_platinum_tests_zip) : .KATI_IMPLICIT_OUTPUTS := $(device_platinum_tests_list_zip) $(device_platinum_tests_configs_zip) $(device_platinum_tests_host_shared_libs_zip)
-$(device_platinum_tests_zip) : PRIVATE_device_platinum_tests_list_zip := $(device_platinum_tests_list_zip)
-$(device_platinum_tests_zip) : PRIVATE_device_platinum_tests_configs_zip := $(device_platinum_tests_configs_zip)
-$(device_platinum_tests_zip) : PRIVATE_device_platinum_tests_list := $(PRODUCT_OUT)/device-platinum-tests_list
-$(device_platinum_tests_zip) : PRIVATE_HOST_SHARED_LIBS := $(my_host_shared_lib_for_device_platinum_tests)
-$(device_platinum_tests_zip) : PRIVATE_device_host_shared_libs_zip := $(device_platinum_tests_host_shared_libs_zip)
-$(device_platinum_tests_zip) : $(COMPATIBILITY.device-platinum-tests.FILES) $(my_host_shared_lib_for_device_platinum_tests) $(SOONG_ZIP)
-	rm -f $@-shared-libs.list
-	rm -f $(PRIVATE_device_platinum_tests_list_zip)
-	echo $(sort $(COMPATIBILITY.device-platinum-tests.FILES)) | tr " " "\n" > $@.list
-	grep $(HOST_OUT_TESTCASES) $@.list > $@-host.list || true
-	grep -e .*\\.config$$ $@-host.list > $@-host-test-configs.list || true
-	$(hide) for shared_lib in $(PRIVATE_HOST_SHARED_LIBS); do \
-	  echo $$shared_lib >> $@-host.list; \
-	  echo $$shared_lib >> $@-shared-libs.list; \
-	done
-	grep $(HOST_OUT_TESTCASES) $@-shared-libs.list > $@-host-shared-libs.list || true
-	grep $(TARGET_OUT_TESTCASES) $@.list > $@-target.list || true
-	grep -e .*\\.config$$ $@-target.list > $@-target-test-configs.list || true
-	$(hide) $(SOONG_ZIP) -d -o $@ -P host -C $(HOST_OUT) -l $@-host.list -P target -C $(PRODUCT_OUT) -l $@-target.list -sha256
-	$(hide) $(SOONG_ZIP) -d -o $(PRIVATE_device_platinum_tests_configs_zip) \
-	  -P host -C $(HOST_OUT) -l $@-host-test-configs.list \
-	  -P target -C $(PRODUCT_OUT) -l $@-target-test-configs.list
-	$(SOONG_ZIP) -d -o $(PRIVATE_device_host_shared_libs_zip) \
-	  -P host -C $(HOST_OUT) -l $@-host-shared-libs.list
-	rm -f $(PRIVATE_device_platinum_tests_list)
-	$(hide) grep -e .*\\.config$$ $@-host.list | sed s%$(HOST_OUT)%host%g > $(PRIVATE_device_platinum_tests_list)
-	$(hide) grep -e .*\\.config$$ $@-target.list | sed s%$(PRODUCT_OUT)%target%g >> $(PRIVATE_device_platinum_tests_list)
-	$(hide) $(SOONG_ZIP) -d -o $(PRIVATE_device_platinum_tests_list_zip) -C $(dir $@) -f $(PRIVATE_device_platinum_tests_list)
-	rm -f $@.list $@-host.list $@-target.list $@-host-test-configs.list $@-target-test-configs.list \
-	  $@-shared-libs.list $@-host-shared-libs.list $(PRIVATE_device_platinum_tests_list)
-
-device-platinum-tests: $(device_platinum_tests_zip)
-$(call dist-for-goals, device-platinum-tests, $(device_platinum_tests_zip) $(device_platinum_tests_list_zip) $(device_platinum_tests_configs_zip) $(device_platinum_tests_host_shared_libs_zip))
-
-$(call declare-1p-container,$(device_platinum_tests_zip),)
-$(call declare-container-license-deps,$(device_platinum_tests_zip),$(COMPATIBILITY.device-platinum-tests.FILES) $(my_host_shared_lib_for_device_platinum_tests),$(PRODUCT_OUT)/:/)
-
-tests: device-platinum-tests
-
-# Reset temp vars
-device_platinum_tests_zip :=
-device_platinum_tests_list_zip :=
-device_platinum_tests_configs_zip :=
-my_host_shared_lib_for_device_platinum_tests :=
-device_platinum_tests_host_shared_libs_zip :=
diff --git a/core/tasks/device-tests.mk b/core/tasks/device-tests.mk
deleted file mode 100644
index 209bd3e28a..0000000000
--- a/core/tasks/device-tests.mk
+++ /dev/null
@@ -1,64 +0,0 @@
-# Copyright (C) 2017 The Android Open Source Project
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
-
-
-.PHONY: device-tests
-.PHONY: device-tests-files-list
-
-device-tests-zip := $(PRODUCT_OUT)/device-tests.zip
-# Create an artifact to include a list of test config files in device-tests.
-device-tests-list-zip := $(PRODUCT_OUT)/device-tests_list.zip
-# Create an artifact to include all test config files in device-tests.
-device-tests-configs-zip := $(PRODUCT_OUT)/device-tests_configs.zip
-my_host_shared_lib_for_device_tests := $(call copy-many-files,$(COMPATIBILITY.device-tests.HOST_SHARED_LIBRARY.FILES))
-device_tests_files_list := $(PRODUCT_OUT)/device-tests_files
-
-$(device-tests-zip) : .KATI_IMPLICIT_OUTPUTS := $(device-tests-list-zip) $(device-tests-configs-zip)
-$(device-tests-zip) : PRIVATE_device_tests_list := $(PRODUCT_OUT)/device-tests_list
-$(device-tests-zip) : PRIVATE_HOST_SHARED_LIBS := $(my_host_shared_lib_for_device_tests)
-$(device-tests-zip) : $(COMPATIBILITY.device-tests.FILES) $(COMPATIBILITY.device-tests.SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES) $(my_host_shared_lib_for_device_tests) $(SOONG_ZIP)
-	echo $(sort $(COMPATIBILITY.device-tests.FILES) $(COMPATIBILITY.device-tests.SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES)) | tr " " "\n" > $@.list
-	grep $(HOST_OUT_TESTCASES) $@.list > $@-host.list || true
-	grep -e .*\\.config$$ $@-host.list > $@-host-test-configs.list || true
-	$(hide) for shared_lib in $(PRIVATE_HOST_SHARED_LIBS); do \
-	  echo $$shared_lib >> $@-host.list; \
-	done
-	grep $(TARGET_OUT_TESTCASES) $@.list > $@-target.list || true
-	grep -e .*\\.config$$ $@-target.list > $@-target-test-configs.list || true
-	$(hide) $(SOONG_ZIP) -d -o $@ -P host -C $(HOST_OUT) -l $@-host.list -P target -C $(PRODUCT_OUT) -l $@-target.list -sha256
-	$(hide) $(SOONG_ZIP) -d -o $(device-tests-configs-zip) \
-	  -P host -C $(HOST_OUT) -l $@-host-test-configs.list \
-	  -P target -C $(PRODUCT_OUT) -l $@-target-test-configs.list
-	rm -f $(PRIVATE_device_tests_list)
-	$(hide) grep -e .*\\.config$$ $@-host.list | sed s%$(HOST_OUT)%host%g > $(PRIVATE_device_tests_list)
-	$(hide) grep -e .*\\.config$$ $@-target.list | sed s%$(PRODUCT_OUT)%target%g >> $(PRIVATE_device_tests_list)
-	$(hide) $(SOONG_ZIP) -d -o $(device-tests-list-zip) -C $(dir $@) -f $(PRIVATE_device_tests_list)
-	rm -f $@.list $@-host.list $@-target.list $@-host-test-configs.list $@-target-test-configs.list \
-		$(PRIVATE_device_tests_list)
-
-$(device_tests_files_list) : PRIVATE_HOST_SHARED_LIBS := $(my_host_shared_lib_for_device_tests)
-$(device_tests_files_list) :
-	echo $(sort $(COMPATIBILITY.device-tests.FILES) $(COMPATIBILITY.device-tests.SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES)) | tr " " "\n" > $@.full_list
-	grep $(HOST_OUT_TESTCASES) $@.full_list > $@ || true
-	grep $(TARGET_OUT_TESTCASES) $@.full_list >> $@ || true
-
-device-tests: $(device-tests-zip)
-device-tests-files-list: $(device_tests_files_list)
-
-$(call dist-for-goals, device-tests, $(device-tests-zip) $(device-tests-list-zip) $(device-tests-configs-zip))
-
-$(call declare-1p-container,$(device-tests-zip),)
-$(call declare-container-license-deps,$(device-tests-zip),$(COMPATIBILITY.device-tests.FILES) $(my_host_shared_lib_for_device_tests),$(PRODUCT_OUT)/:/)
-
-tests: device-tests
diff --git a/core/tasks/general-tests.mk b/core/tasks/general-tests.mk
index 44476cb178..489afa6f62 100644
--- a/core/tasks/general-tests.mk
+++ b/core/tasks/general-tests.mk
@@ -37,7 +37,7 @@ my_general_tests_shared_lib_files := \
   $(filter-out $(COMPATIBILITY.device-tests.HOST_SHARED_LIBRARY.FILES),\
 	 $(COMPATIBILITY.general-tests.HOST_SHARED_LIBRARY.FILES))
 
-my_host_shared_lib_for_general_tests += $(call copy-many-files,$(my_general_tests_shared_lib_files))
+my_host_shared_lib_for_general_tests += $(foreach p,$(my_general_tests_shared_lib_files),$(call word-colon,2,$(p)))
 
 my_host_shared_lib_symlinks := \
     $(filter $(COMPATIBILITY.host-unit-tests.SYMLINKS),\
diff --git a/core/tasks/module-info.mk b/core/tasks/module-info.mk
index dd01f9667c..5a202e6912 100644
--- a/core/tasks/module-info.mk
+++ b/core/tasks/module-info.mk
@@ -61,8 +61,7 @@ module-info: $(MODULE_INFO_JSON)
 
 droidcore-unbundled: $(MODULE_INFO_JSON)
 
-$(call dist-for-goals, general-tests, $(MODULE_INFO_JSON))
-$(call dist-for-goals, droidcore-unbundled, $(MODULE_INFO_JSON))
+$(call dist-for-goals, general-tests droidcore-unbundled dist_files module-info, $(MODULE_INFO_JSON))
 
 # On every build, generate an all_modules.txt file to be used for autocompleting
 # the m command. After timing this using $(shell date +"%s.%3N"), it only adds
diff --git a/core/tasks/multitree.mk b/core/tasks/multitree.mk
deleted file mode 100644
index 225477e394..0000000000
--- a/core/tasks/multitree.mk
+++ /dev/null
@@ -1,16 +0,0 @@
-# Copyright (C) 2022 The Android Open Source Project
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
-
-.PHONY: update-meta
-update-meta: $(SOONG_MULTITREE_METADATA)
diff --git a/core/tasks/performance-tests.mk b/core/tasks/performance-tests.mk
deleted file mode 100644
index 8702756f31..0000000000
--- a/core/tasks/performance-tests.mk
+++ /dev/null
@@ -1,56 +0,0 @@
-# Copyright (C) 2024 The Android Open Source Project
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
-
-
-.PHONY: performance-tests
-
-performance_tests_zip := $(PRODUCT_OUT)/performance-tests.zip
-# Create an artifact to include a list of test config files in performance-tests.
-performance_tests_list_zip := $(PRODUCT_OUT)/performance-tests_list.zip
-# Create an artifact to include all test config files in performance-tests.
-performance_tests_configs_zip := $(PRODUCT_OUT)/performance-tests_configs.zip
-
-$(performance_tests_zip) : .KATI_IMPLICIT_OUTPUTS := $(performance_tests_list_zip) $(performance_tests_configs_zip)
-$(performance_tests_zip) : PRIVATE_performance_tests_list_zip := $(performance_tests_list_zip)
-$(performance_tests_zip) : PRIVATE_performance_tests_configs_zip := $(performance_tests_configs_zip)
-$(performance_tests_zip) : PRIVATE_performance_tests_list := $(PRODUCT_OUT)/performance-tests_list
-$(performance_tests_zip) : $(COMPATIBILITY.performance-tests.FILES) $(SOONG_ZIP)
-	echo $(sort $(COMPATIBILITY.performance-tests.FILES)) | tr " " "\n" > $@.list
-	grep $(HOST_OUT_TESTCASES) $@.list > $@-host.list || true
-	grep -e .*\\.config$$ $@-host.list > $@-host-test-configs.list || true
-	grep $(TARGET_OUT_TESTCASES) $@.list > $@-target.list || true
-	grep -e .*\\.config$$ $@-target.list > $@-target-test-configs.list || true
-	$(hide) $(SOONG_ZIP) -d -o $@ -P host -C $(HOST_OUT) -l $@-host.list -P target -C $(PRODUCT_OUT) -l $@-target.list -sha256
-	$(hide) $(SOONG_ZIP) -d -o $(PRIVATE_performance_tests_configs_zip) \
-	  -P host -C $(HOST_OUT) -l $@-host-test-configs.list \
-	  -P target -C $(PRODUCT_OUT) -l $@-target-test-configs.list
-	rm -f $(PRIVATE_performance_tests_list)
-	$(hide) grep -e .*\\.config$$ $@-host.list | sed s%$(HOST_OUT)%host%g > $(PRIVATE_performance_tests_list)
-	$(hide) grep -e .*\\.config$$ $@-target.list | sed s%$(PRODUCT_OUT)%target%g >> $(PRIVATE_performance_tests_list)
-	$(hide) $(SOONG_ZIP) -d -o $(PRIVATE_performance_tests_list_zip) -C $(dir $@) -f $(PRIVATE_performance_tests_list)
-	rm -f $@.list $@-host.list $@-target.list $@-host-test-configs.list $@-target-test-configs.list \
-	  $(PRIVATE_performance_tests_list)
-
-performance-tests: $(performance_tests_zip)
-$(call dist-for-goals, performance-tests, $(performance_tests_zip) $(performance_tests_list_zip) $(performance_tests_configs_zip))
-
-$(call declare-1p-container,$(performance_tests_zip),)
-$(call declare-container-license-deps,$(performance_tests_zip),$(COMPATIBILITY.performance-tests.FILES),$(PRODUCT_OUT)/:/)
-
-tests: performance-tests
-
-# Reset temp vars
-performance_tests_zip :=
-performance_tests_list_zip :=
-performance_tests_configs_zip :=
diff --git a/core/tasks/tools/compatibility.mk b/core/tasks/tools/compatibility.mk
index f205cea156..110f988025 100644
--- a/core/tasks/tools/compatibility.mk
+++ b/core/tasks/tools/compatibility.mk
@@ -83,7 +83,7 @@ test_copied_tools := $(foreach t,$(test_tools) $(test_suite_prebuilt_tools), $(o
 
 
 # Include host shared libraries
-host_shared_libs := $(call copy-many-files, $(COMPATIBILITY.$(test_suite_name).HOST_SHARED_LIBRARY.FILES))
+host_shared_libs := $(foreach p,$(COMPATIBILITY.$(test_suite_name).HOST_SHARED_LIBRARY.FILES),$(call word-colon,2,$(p)))
 
 $(if $(strip $(host_shared_libs)),\
   $(foreach p,$(COMPATIBILITY.$(test_suite_name).HOST_SHARED_LIBRARY.FILES),\
@@ -140,13 +140,13 @@ $(compatibility_zip): $(compatibility_zip_deps) | $(ADB) $(ACP)
 	cp $(PRIVATE_TOOLS) $(PRIVATE_OUT_DIR)/tools
 	$(if $(PRIVATE_DYNAMIC_CONFIG),$(hide) cp $(PRIVATE_DYNAMIC_CONFIG) $(PRIVATE_OUT_DIR)/testcases/$(PRIVATE_SUITE_NAME).dynamic)
 	find $(PRIVATE_RESOURCES) | sort >$@.list
-	$(SOONG_ZIP) -d -o $@.tmp -C $(dir $@) -l $@.list -sha256
-	$(MERGE_ZIPS) $@ $@.tmp $(PRIVATE_JDK)
+	$(SOONG_ZIP) -o $@.tmp -C $(dir $@) -l $@.list -sha256
+	$(MERGE_ZIPS) -s $@ $@.tmp $(PRIVATE_JDK)
 	rm -f $@.tmp
 # Build a list of tests
 	rm -f $(PRIVATE_tests_list)
 	$(hide) grep -e .*\\.config$$ $@.list | sed s%$(PRIVATE_OUT_DIR)/testcases/%%g > $(PRIVATE_tests_list)
-	$(SOONG_ZIP) -d -o $(PRIVATE_tests_list_zip) -j -f $(PRIVATE_tests_list)
+	$(SOONG_ZIP) -o $(PRIVATE_tests_list_zip) -j -f $(PRIVATE_tests_list)
 	rm -f $(PRIVATE_tests_list)
 
 $(call declare-0p-target,$(compatibility_tests_list_zip),)
diff --git a/core/use_lld_setup.mk b/core/use_lld_setup.mk
deleted file mode 100644
index 8f47d68c3f..0000000000
--- a/core/use_lld_setup.mk
+++ /dev/null
@@ -1,20 +0,0 @@
-#############################################################
-## Set up flags based on LOCAL_USE_CLANG_LLD.
-## Input variables: LOCAL_USE_CLANG_LLD
-## Output variables: my_use_clang_lld
-#############################################################
-
-# Use LLD by default.
-# Do not use LLD if LOCAL_USE_CLANG_LLD is false or 0
-my_use_clang_lld := true
-ifneq (,$(LOCAL_USE_CLANG_LLD))
-  ifneq (,$(filter 0 false,$(LOCAL_USE_CLANG_LLD)))
-    my_use_clang_lld := false
-  endif
-endif
-
-# Do not use LLD for Darwin host executables or shared libraries.  See
-# https://lld.llvm.org/AtomLLD.html for status of lld for Mach-O.
-ifeq ($($(my_prefix)OS),darwin)
-my_use_clang_lld := false
-endif
diff --git a/core/version_util.mk b/core/version_util.mk
index cc94063bbe..8ab36b773b 100644
--- a/core/version_util.mk
+++ b/core/version_util.mk
@@ -195,7 +195,7 @@ ifeq (REL,$(PLATFORM_VERSION_CODENAME))
 else
   PLATFORM_SYSTEMSDK_VERSIONS += $(subst $(comma),$(space),$(PLATFORM_VERSION_ALL_CODENAMES))
 endif
-PLATFORM_SYSTEMSDK_VERSIONS := $(strip $(sort $(PLATFORM_SYSTEMSDK_VERSIONS)))
+PLATFORM_SYSTEMSDK_VERSIONS := $(sort $(PLATFORM_SYSTEMSDK_VERSIONS))
 .KATI_READONLY := PLATFORM_SYSTEMSDK_VERSIONS
 
 .KATI_READONLY := PLATFORM_SECURITY_PATCH
diff --git a/envsetup.sh b/envsetup.sh
index c04031186e..43c1618787 100644
--- a/envsetup.sh
+++ b/envsetup.sh
@@ -184,8 +184,13 @@ function set_lunch_paths()
     fi
 
     # And in with the new...
-    ANDROID_LUNCH_BUILD_PATHS=$(_get_abs_build_var_cached SOONG_HOST_OUT_EXECUTABLES)
-    ANDROID_LUNCH_BUILD_PATHS+=:$(_get_abs_build_var_cached HOST_OUT_EXECUTABLES)
+    local SOONG_HOST_OUT_EXECUTABLES=$(_get_abs_build_var_cached SOONG_HOST_OUT_EXECUTABLES)
+    local HOST_OUT_EXECUTABLES=$(_get_abs_build_var_cached HOST_OUT_EXECUTABLES)
+    # Binaries in build/soong/bin should always be preferred over any build path.
+    ANDROID_LUNCH_BUILD_PATHS=$T/build/soong/bin:${SOONG_HOST_OUT_EXECUTABLES}
+    if [ "${HOST_OUT_EXECUTABLES}" != "${SOONG_HOST_OUT_EXECUTABLES}" ]; then
+        ANDROID_LUNCH_BUILD_PATHS+=:${HOST_OUT_EXECUTABLES}
+    fi
 
     # Append llvm binutils prebuilts path to ANDROID_LUNCH_BUILD_PATHS.
     local ANDROID_LLVM_BINUTILS=$(_get_abs_build_var_cached ANDROID_CLANG_PREBUILTS)/llvm-binutils-stable
@@ -273,7 +278,7 @@ function set_global_paths()
 
     # Out with the old...
     if [ -n "$ANDROID_GLOBAL_BUILD_PATHS" ] ; then
-        export PATH=${PATH/$ANDROID_GLOBAL_BUILD_PATHS/}
+        export PATH=${PATH/$ANDROID_GLOBAL_BUILD_PATHS:/}
     fi
 
     # And in with the new...
@@ -447,6 +452,7 @@ function _lunch_meat()
     TARGET_PRODUCT=$product \
     TARGET_RELEASE=$release \
     TARGET_BUILD_VARIANT=$variant \
+    TARGET_BUILD_APPS= \
     build_build_var_cache
     if [ $? -ne 0 ]
     then
@@ -461,6 +467,8 @@ function _lunch_meat()
     export TARGET_RELEASE=$release
     # Note this is the string "release", not the value of the variable.
     export TARGET_BUILD_TYPE=release
+    # Undo any previous tapas or banchan setup
+    export TARGET_BUILD_APPS=
 
     [[ -n "${ANDROID_QUIET_BUILD:-}" ]] || echo
 
@@ -520,12 +528,24 @@ function _lunch_usage()
         echo "Note that the previous interactive menu and list of hard-coded"
         echo "list of curated targets has been removed. If you would like the"
         echo "list of products, release configs for a particular product, or"
-        echo "variants, run list_products list_releases or list_variants"
+        echo "variants, run the following as individual commands:"
+        echo "list_products, list_releases, or list_variants"
         echo "respectively."
         echo
     ) 1>&2
 }
 
+function _lunch_store_leftovers()
+{
+    local product=$1
+    local release=$2
+    local variant=$3
+
+    local dot_leftovers="$(getoutdir)/.leftovers"
+    rm -f $dot_leftovers
+    echo "$product $release $variant" > $dot_leftovers
+}
+
 function lunch()
 {
     if [[ $# -eq 1 && $1 = "--help" ]]; then
@@ -570,6 +590,54 @@ function lunch()
 
     # Validate the selection and set all the environment stuff
     _lunch_meat $product $release $variant
+
+    _lunch_store_leftovers $product $release $variant
+}
+
+function leftovers()
+{
+    if [ -t 1 ] && [ $(tput colors) -ge 8 ]; then
+        local style_reset="$(tput sgr0)"
+        local style_red="$(tput setaf 1)"
+        local style_green="$(tput setaf 2)"
+        local style_bold="$(tput bold)"
+    fi
+    local FAIL="${style_bold}${style_red}ERROR${style_reset}"
+    local INFO="${style_bold}${style_green}INFO${style_reset}"
+
+    if [[ $# -eq 1 && ($1 = "--help" || $1 == "-h" || $1 == "help") ]]; then
+        (
+            echo "The leftovers command restores your previous lunch choices, if found."
+            echo
+            echo "Set ${style_bold}USE_LEFTOVERS=1${style_reset} in your environment to automatically run this"
+            echo "from ${style_bold}build/envsetup.sh${style_reset}."
+        ) 1>&2
+        return
+    fi
+
+    local dot_leftovers="$(getoutdir)/.leftovers"
+
+    # seamlessly migrate old .leftovers location
+    local old_leftovers="$(gettop)/.leftovers"
+    if [[ -e $old_leftovers ]]
+    then
+        if [[ -e $dot_leftovers ]]; then
+            rm $old_leftovers
+        else
+            mv $old_leftovers $dot_leftovers
+        fi
+    fi
+
+    if [ ! -f $dot_leftovers ]; then
+        echo -e "$FAIL: .leftovers not found. Run ${style_bold}lunch${style_reset} first."
+        return 1
+    fi
+
+    local product release variant
+    IFS=" " read -r product release variant < "$dot_leftovers"
+
+    echo "$INFO: Loading previous lunch: ${style_bold}$product $release $variant${style_reset}"
+    lunch $product $release $variant
 }
 
 unset ANDROID_LUNCH_COMPLETION_PRODUCT_CACHE
@@ -1113,4 +1181,6 @@ set_global_paths
 source_vendorsetup
 addcompletions
 
-
+if [[ "$USE_LEFTOVERS" -eq 1 ]]; then
+  leftovers
+fi
diff --git a/rbesetup.sh b/rbesetup.sh
index 0da7a57647..9f2343fa0d 100644
--- a/rbesetup.sh
+++ b/rbesetup.sh
@@ -61,7 +61,6 @@ function _export_metrics_uploader() {
 # This function sets RBE specific environment variables needed for the build to
 # executed by RBE. This file should be sourced once per checkout of Android code.
 function _set_rbe_vars() {
-  unset USE_GOMA
   export USE_RBE="true"
   export RBE_CXX_EXEC_STRATEGY="racing"
   export RBE_JAVAC_EXEC_STRATEGY="racing"
diff --git a/target/board/generic_arm64/BoardConfig.mk b/target/board/generic_arm64/BoardConfig.mk
index 1a05549193..e6eac7f064 100644
--- a/target/board/generic_arm64/BoardConfig.mk
+++ b/target/board/generic_arm64/BoardConfig.mk
@@ -62,13 +62,6 @@ include build/make/target/board/BoardConfigGsiCommon.mk
 # Some vendors still haven't cleaned up all device specific directories under
 # root!
 
-# TODO(b/111434759, b/111287060) SoC specific hacks
-BOARD_ROOT_EXTRA_SYMLINKS += /vendor/lib/dsp:/dsp
-BOARD_ROOT_EXTRA_SYMLINKS += /mnt/vendor/persist:/persist
-BOARD_ROOT_EXTRA_SYMLINKS += /vendor/firmware_mnt:/firmware
-# for Android.bp
-TARGET_ADD_ROOT_EXTRA_VENDOR_SYMLINKS := true
-
 # TODO(b/36764215): remove this setting when the generic system image
 # no longer has QCOM-specific directories under /.
 BOARD_SEPOLICY_DIRS += build/make/target/board/generic_arm64/sepolicy
diff --git a/target/product/OWNERS b/target/product/OWNERS
index 276c885280..ab00980515 100644
--- a/target/product/OWNERS
+++ b/target/product/OWNERS
@@ -1,4 +1,5 @@
-per-file runtime_libart.mk = mast@google.com, ngeoffray@google.com, rpl@google.com, vmarko@google.com
+per-file runtime_libart.mk = file:platform/art:main:/OWNERS
+per-file default_art_config.mk = file:platform/art:main:/OWNERS
 
 # GSI
 per-file gsi_release.mk = file:/target/product/gsi/OWNERS
diff --git a/target/product/base_system.mk b/target/product/base_system.mk
index 5c4ef33284..84ab0446e0 100644
--- a/target/product/base_system.mk
+++ b/target/product/base_system.mk
@@ -28,6 +28,7 @@ PRODUCT_PACKAGES += \
     android.test.mock \
     android.test.runner \
     apexd \
+    apexd.mainline_patch_level_2 \
     appops \
     app_process \
     appwidget \
@@ -103,7 +104,6 @@ PRODUCT_PACKAGES += \
     framework-sysconfig.xml \
     fsck.erofs \
     fsck_msdos \
-    fsverity-release-cert-der \
     fs_config_files_system \
     fs_config_dirs_system \
     gpu_counter_producer \
@@ -284,7 +284,6 @@ PRODUCT_PACKAGES += \
     system-build.prop \
     task_profiles.json \
     tc \
-    telecom \
     telephony-common \
     tombstoned \
     traced \
@@ -304,6 +303,17 @@ PRODUCT_PACKAGES += \
     wifi.rc \
     wm \
 
+# Once Telecom is APEX, we will consolidate all deps
+ifeq ($(RELEASE_TELECOM_MAINLINE_MODULE),true)
+  PRODUCT_PACKAGES += \
+      com.android.telecom \
+
+else
+  PRODUCT_PACKAGES += \
+      telecom \
+
+endif
+
 # When we release crashrecovery module
 ifeq ($(RELEASE_CRASHRECOVERY_MODULE),true)
   PRODUCT_PACKAGES += \
@@ -377,6 +387,11 @@ ifneq ($(RELEASE_MOVE_VCN_TO_MAINLINE),true)
         framework-connectivity-b
 endif
 
+ifeq ($(RELEASE_TELEPHONY_MODULE),true)
+    PRODUCT_PACKAGES += \
+       com.android.telephony2
+endif
+
 ifneq (,$(RELEASE_RANGING_STACK))
     PRODUCT_PACKAGES += \
         com.android.ranging
@@ -577,8 +592,3 @@ $(call inherit-product,$(SRC_TARGET_DIR)/product/updatable_apex.mk)
 
 $(call soong_config_set, bionic, large_system_property_node, $(RELEASE_LARGE_SYSTEM_PROPERTY_NODE))
 $(call soong_config_set, Aconfig, read_from_new_storage, $(RELEASE_READ_FROM_NEW_STORAGE))
-$(call soong_config_set, SettingsLib, legacy_avatar_picker_app_enabled, $(if $(RELEASE_AVATAR_PICKER_APP),,true))
-$(call soong_config_set, appsearch, enable_isolated_storage, $(RELEASE_APPSEARCH_ENABLE_ISOLATED_STORAGE))
-
-# Enable AppSearch Isolated Storage per BUILD flag
-PRODUCT_PRODUCT_PROPERTIES += ro.appsearch.feature.enable_isolated_storage=$(RELEASE_APPSEARCH_ENABLE_ISOLATED_STORAGE)
diff --git a/target/product/default_art_config.mk b/target/product/default_art_config.mk
index f91cb07849..1b6aaabe6e 100644
--- a/target/product/default_art_config.mk
+++ b/target/product/default_art_config.mk
@@ -147,6 +147,12 @@ else
 
 endif
 
+ifeq ($(RELEASE_TELEPHONY_MODULE),true)
+    PRODUCT_APEX_BOOT_JARS += \
+        com.android.telephony2:framework-telephony \
+
+endif
+
 # List of system_server classpath jars delivered via apex.
 # Keep the list sorted by module names and then library names.
 # Note: For modules available in Q, DO NOT add new entries here.
@@ -193,6 +199,7 @@ PRODUCT_STANDALONE_SYSTEM_SERVER_JARS := \
 # List of jars delivered via apex that system_server loads dynamically using separate classloaders.
 # Keep the list sorted by module names and then library names.
 # Note: For modules available in Q, DO NOT add new entries here.
+# The Soong modules for these jars should inherit standalone-system-server-module-optimize-defaults.
 PRODUCT_APEX_STANDALONE_SYSTEM_SERVER_JARS := \
     com.android.bt:service-bluetooth \
     com.android.devicelock:service-devicelock \
diff --git a/target/product/generic/Android.bp b/target/product/generic/Android.bp
index 0a32a55b6b..7ad49f15de 100644
--- a/target/product/generic/Android.bp
+++ b/target/product/generic/Android.bp
@@ -464,7 +464,10 @@ soong_config_module_type {
     module_type: "android_filesystem_defaults",
     config_namespace: "ANDROID",
     bool_variables: ["TARGET_ADD_ROOT_EXTRA_VENDOR_SYMLINKS"],
-    properties: ["symlinks"],
+    properties: [
+        "symlinks",
+        "file_contexts",
+    ],
 }
 
 genrule {
@@ -487,12 +490,13 @@ system_image_defaults {
     soong_config_variables: {
         TARGET_ADD_ROOT_EXTRA_VENDOR_SYMLINKS: {
             symlinks: generic_symlinks + extra_vendor_symlinks,
+            file_contexts: ":plat_and_vendor_file_contexts",
             conditions_default: {
                 symlinks: generic_symlinks,
+                file_contexts: ":plat_file_contexts",
             },
         },
     },
-    file_contexts: ":plat_and_vendor_file_contexts",
     linker_config: {
         gen_linker_config: true,
         linker_config_srcs: [":system_linker_config_json_file"],
@@ -517,6 +521,7 @@ system_image_defaults {
     },
     build_logtags: true,
     gen_aconfig_flags_pb: true,
+    check_vintf: true,
 
     compile_multilib: "both",
 
@@ -536,6 +541,7 @@ system_image_defaults {
         "android.software.window_magnification.prebuilt.xml", // handheld_system
         "android.system.suspend-service",
         "apexd",
+        "apexd.mainline_patch_level_2",
         "appops",
         "approved-ogki-builds.xml", // base_system
         "appwidget",
@@ -578,7 +584,6 @@ system_image_defaults {
         "fsck.erofs",
         "fsck.f2fs", // for media_system
         "fsck_msdos",
-        "fsverity-release-cert-der",
         "gatekeeperd",
         "gpu_counter_producer",
         "gpuservice",
@@ -691,7 +696,6 @@ system_image_defaults {
         "uinput", // base_system
         "uncrypt", // base_system
         "update_engine", // generic_system
-        "update_engine_sideload", // recovery
         "update_verifier", // generic_system
         "usbd", // base_system
         "vdc", // base_system
@@ -815,6 +819,7 @@ system_image_defaults {
                 "PartnerBookmarksProvider", // generic_system
                 "PrintRecommendationService", // handheld_system
                 "PrintSpooler", // handheld_system
+                "PrivateSpace", // handheld_system
                 "ProxyHandler", // handheld_system
                 "SecureElement", // handheld_system
                 "SettingsProvider", // base_system
@@ -902,6 +907,11 @@ system_image_defaults {
                     "com.android.uprobestats", // base_system (RELEASE_UPROBESTATS_MODULE)
                 ],
                 default: [],
+            }) + select(release_flag("RELEASE_TELEPHONY_MODULE"), {
+                true: [
+                    "com.android.telephony2", // base_system (RELEASE_TELEPHONY_MODULE)
+                ],
+                default: [],
             }),
         },
         prefer32: {
diff --git a/target/product/gsi/Android.bp b/target/product/gsi/Android.bp
index 8c200a1dcb..1381119239 100644
--- a/target/product/gsi/Android.bp
+++ b/target/product/gsi/Android.bp
@@ -102,6 +102,9 @@ android_filesystem_defaults {
         "StorageManager",
         "SystemUI",
 
+        // Allowlist for handheld packages
+        "preinstalled_packages_handheld_system_ext.xml",
+
         // telephony packages
         "CarrierConfig",
 
@@ -131,6 +134,7 @@ android_filesystem_defaults {
         "Camera2",
         "Dialer",
         "LatinIME",
+        "messaging",
         "apns-full-conf.xml",
         "frameworks-base-overlays",
     ],
@@ -165,7 +169,10 @@ android_system_image {
         // init-second-stage to load debug policy from system_ext.
         // This option is only meant to be set by compliance GSI targets.
         "system_ext_userdebug_plat_sepolicy.cil",
-    ],
+    ] + select(soong_config_variable("gsi", "import_usb_debugging_test_app"), {
+        true: ["UsbDisableDebugger"],
+        default: [],
+    }),
 }
 
 // system.img for aosp_{arch} targets
@@ -181,6 +188,7 @@ android_system_image {
         "EmergencyInfo",
 
         // handheld_product
+        "AvatarPicker",
         "Calendar",
         "Contacts",
         "DeskClock",
@@ -197,7 +205,6 @@ android_system_image {
 
         // more AOSP packages
         "initial-package-stopped-states-aosp.xml",
-        "messaging",
         "PhotoTable",
         "preinstalled-packages-platform-aosp-product.xml",
         "ThemePicker",
@@ -209,14 +216,4 @@ android_system_image {
         true: true,
         default: false,
     }),
-    multilib: {
-        common: {
-            deps: select(release_flag("RELEASE_AVATAR_PICKER_APP"), {
-                true: [
-                    "AvatarPicker", // handheld_system_ext (RELEASE_AVATAR_PICKER_APP)
-                ],
-                default: [],
-            }),
-        },
-    },
 }
diff --git a/target/product/handheld_system.mk b/target/product/handheld_system.mk
index 2b055c7ed0..37ed8e28df 100644
--- a/target/product/handheld_system.mk
+++ b/target/product/handheld_system.mk
@@ -63,12 +63,12 @@ PRODUCT_PACKAGES += \
     preinstalled-packages-platform-handheld-system.xml \
     PrintRecommendationService \
     PrintSpooler \
+    PrivateSpace \
     ProxyHandler \
     screenrecord \
     SecureElement \
     SharedStorageBackup \
     SimAppDialog \
-    Telecom \
     TeleService \
     Traceur \
     UserDictionaryProvider \
@@ -92,7 +92,15 @@ PRODUCT_SYSTEM_SERVER_APPS += \
     FusedLocation \
     InputDevices \
     KeyChain \
-    Telecom \
+
+ifneq ($(RELEASE_TELECOM_MAINLINE_MODULE),true)
+  PRODUCT_PACKAGES += \
+      Telecom \
+
+  PRODUCT_SYSTEM_SERVER_APPS += \
+      Telecom \
+
+endif
 
 PRODUCT_PACKAGES += framework-audio_effects.xml
 
diff --git a/target/product/handheld_system_ext.mk b/target/product/handheld_system_ext.mk
index 6d686c554f..01bccd6e6c 100644
--- a/target/product/handheld_system_ext.mk
+++ b/target/product/handheld_system_ext.mk
@@ -23,10 +23,13 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/media_system_ext.mk)
 # /system_ext packages
 PRODUCT_PACKAGES += \
     AccessibilityMenu \
-    $(if $(RELEASE_AVATAR_PICKER_APP), AvatarPicker,) \
+    AvatarPicker \
     Launcher3QuickStep \
     Provision \
     Settings \
     StorageManager \
     SystemUI \
     WallpaperCropper \
+
+# Allowlist for system packages included in handheld_system_ext.mk
+PRODUCT_PACKAGES += preinstalled_packages_handheld_system_ext.xml
diff --git a/target/product/hsum_common.mk b/target/product/hsum_common.mk
index b19bc65c90..87e4fdb3b1 100644
--- a/target/product/hsum_common.mk
+++ b/target/product/hsum_common.mk
@@ -22,6 +22,12 @@
 PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
     ro.fw.mu.headless_system_user=true
 
+# Experimental configuration sets a RAM limit for HSUM, primarily for testing its behavior
+# on simulated low RAM devices.
+ifneq ($(CONFIG_HSUM_EXPERIMENTAL_RAM_LIMIT),)
+BOARD_KERNEL_CMDLINE += mem=$(CONFIG_HSUM_EXPERIMENTAL_RAM_LIMIT)
+endif
+
 # Variable for elsewhere choosing the appropriate products based on HSUM status.
 PRODUCT_USE_HSUM := true
 
diff --git a/target/product/module_common.mk b/target/product/module_common.mk
index da4ea23ad9..65c49e78c9 100644
--- a/target/product/module_common.mk
+++ b/target/product/module_common.mk
@@ -35,3 +35,6 @@ ifneq (,$(strip $(wildcard frameworks/base/Android.bp)))
 endif
 
 PRODUCT_BRAND := Android
+
+# Only run soong (and not make), for faster builds
+PRODUCT_SOONG_ONLY := $(RELEASE_SOONG_ONLY_MAINLINE)
diff --git a/target/product/security/Android.bp b/target/product/security/Android.bp
index 214c009ec8..140a52e058 100644
--- a/target/product/security/Android.bp
+++ b/target/product/security/Android.bp
@@ -17,15 +17,6 @@ android_app_certificate {
     certificate: "cts_uicc_2021",
 }
 
-// Google-owned certificate for CTS testing, since we can't trust arbitrary keys
-// on release devices.
-prebuilt_etc {
-    name: "fsverity-release-cert-der",
-    src: "fsverity-release.x509.der",
-    sub_dir: "security/fsverity",
-    filename_from_src: true,
-}
-
 // otacerts: A keystore with the authorized keys in it, which is used to verify
 // the authenticity of downloaded OTA packages.
 // This module zips files defined in PRODUCT_DEFAULT_DEV_CERTIFICATE and
diff --git a/target/product/security/fsverity-release.x509.der b/target/product/security/fsverity-release.x509.der
deleted file mode 100644
index cd8cd795cf..0000000000
Binary files a/target/product/security/fsverity-release.x509.der and /dev/null differ
diff --git a/target/product/sysconfig/Android.bp b/target/product/sysconfig/Android.bp
index 95042a707e..d4166632e2 100644
--- a/target/product/sysconfig/Android.bp
+++ b/target/product/sysconfig/Android.bp
@@ -55,6 +55,13 @@ prebuilt_etc {
     src: "preinstalled-packages-platform-telephony-product.xml",
 }
 
+prebuilt_etc {
+    name: "preinstalled_packages_handheld_system_ext.xml",
+    sub_dir: "sysconfig",
+    system_ext_specific: true,
+    src: "preinstalled_packages_handheld_system_ext.xml",
+}
+
 prebuilt_etc {
     name: "initial-package-stopped-states-aosp.xml",
     product_specific: true,
diff --git a/target/product/sysconfig/preinstalled_packages_handheld_system_ext.xml b/target/product/sysconfig/preinstalled_packages_handheld_system_ext.xml
new file mode 100644
index 0000000000..34ebd71475
--- /dev/null
+++ b/target/product/sysconfig/preinstalled_packages_handheld_system_ext.xml
@@ -0,0 +1,31 @@
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
+<!-- Allowlist for system packages included in handheld_system_ext.mk -->
+<config>
+    <!--  Settings (Settings app) -->
+    <!--  Do not install the Settings app for non-FULL SYSTEM user -->
+    <!--  @TODO To revisit it again and see if this package still needs to
+        be installed on all the PROFILE user types listed,
+        b/408457689 - Only changing broader PROFILE to granual PROFILE types.
+    -->
+    <install-in-user-type package="com.android.settings">
+        <install-in user-type="FULL" />
+        <install-in user-type="android.os.usertype.profile.CLONE" />
+        <install-in user-type="android.os.usertype.profile.MANAGED" />
+        <install-in user-type="android.os.usertype.profile.PRIVATE" />
+        <install-in user-type="android.os.usertype.profile.SUPERVISING" />
+    </install-in-user-type>
+</config>
diff --git a/target/product/updatable_apex.mk b/target/product/updatable_apex.mk
index 8357fdf7fd..8b3bc9a7e5 100644
--- a/target/product/updatable_apex.mk
+++ b/target/product/updatable_apex.mk
@@ -17,10 +17,4 @@
 # com.android.apex.cts.shim.v1_prebuilt overrides CtsShimPrebuilt
 # and CtsShimPrivPrebuilt since they are packaged inside the APEX.
 PRODUCT_PACKAGES += com.android.apex.cts.shim.v1_prebuilt
-PRODUCT_SYSTEM_PROPERTIES := ro.apex.updatable=true
-
-# Use compressed apexes in pre-installed partitions.
-# Note: this doesn't mean that all pre-installed apexes will be compressed.
-#  Whether an apex is compressed or not is controlled at apex Soong module
-#  via compresible property.
-PRODUCT_COMPRESSED_APEX := true
+PRODUCT_SYSTEM_PROPERTIES += ro.apex.updatable=true
diff --git a/target/product/virtual_ab_ota/README.md b/target/product/virtual_ab_ota/README.md
index 2d40c030be..a042b8696c 100644
--- a/target/product/virtual_ab_ota/README.md
+++ b/target/product/virtual_ab_ota/README.md
@@ -6,7 +6,6 @@ Devices that uses Virtual A/B must inherit from one of the makefiles in this dir
 
 ```
 launch.mk
-  |- retrofit.mk
   |- plus_non_ab.mk
 
 launch_with_vendor_ramdisk.mk
diff --git a/target/product/virtual_ab_ota/compression_retrofit.mk b/target/product/virtual_ab_ota/compression_retrofit.mk
index 6c29cba6e1..33ea0d1dcb 100644
--- a/target/product/virtual_ab_ota/compression_retrofit.mk
+++ b/target/product/virtual_ab_ota/compression_retrofit.mk
@@ -20,7 +20,7 @@ PRODUCT_VIRTUAL_AB_COMPRESSION := true
 # For devices that are not GKI-capable (eg do not have vendor_boot),
 # snapuserd.ramdisk is included rather than snapuserd.vendor_ramdisk.
 # When using virtual_ab_ota_compression_retrofit.mk, either
-# virtual_ab_ota.mk or virtual_ab_ota_retrofit.mk must be inherited
+# virtual_ab_ota.mk must be inherited
 # as well.
 PRODUCT_PACKAGES += \
     snapuserd.ramdisk \
diff --git a/target/product/virtual_ab_ota/retrofit.mk b/target/product/virtual_ab_ota/retrofit.mk
deleted file mode 100644
index 93b42b7acb..0000000000
--- a/target/product/virtual_ab_ota/retrofit.mk
+++ /dev/null
@@ -1,21 +0,0 @@
-#
-# Copyright (C) 2019 The Android Open-Source Project
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
-#
-
-$(call inherit-product, $(SRC_TARGET_DIR)/product/virtual_ab_ota/launch.mk)
-
-PRODUCT_VIRTUAL_AB_OTA_RETROFIT := true
-
-PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.retrofit=true
diff --git a/target/product/virtual_ab_ota/vabc_features.mk b/target/product/virtual_ab_ota/vabc_features.mk
index 0339ebddb8..82a09467ca 100644
--- a/target/product/virtual_ab_ota/vabc_features.mk
+++ b/target/product/virtual_ab_ota/vabc_features.mk
@@ -53,6 +53,9 @@ PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.compression.xor.enabled?=true
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.verify_threshold_size=1073741824
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.verify_block_size=1048576
 
+# Enabling this property will assign CPUSET_SP_BACKGROUND to readahead threads
+# and merge threads.
+# PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.set_task_profiles=true
 
 # Enabling this property will skip verification post OTA reboot.
 # Verification allows the device to safely roll back if any boot failures
@@ -61,7 +64,7 @@ PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.compression.xor.enabled?=true
 # /metadata/ota/. This will increase the boot time and may also impact
 # memory usage as all the blocks in dynamic partitions are read into page-cache.
 # If care_map.pb isn't present, update-verifier will skip the verification.
-# PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.skip_verification =true
+# PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.skip_verification=true
 
 # Enabling this property, will improve OTA install time
 # but will use an additional CPU core
diff --git a/target/product/virtual_ab_ota_retrofit.mk b/target/product/virtual_ab_ota_retrofit.mk
deleted file mode 120000
index 1e16ca8b62..0000000000
--- a/target/product/virtual_ab_ota_retrofit.mk
+++ /dev/null
@@ -1 +0,0 @@
-virtual_ab_ota/retrofit.mk
\ No newline at end of file
diff --git a/teams/Android.bp b/teams/Android.bp
index 7946a3d21a..d368dba88a 100644
--- a/teams/Android.bp
+++ b/teams/Android.bp
@@ -3108,7 +3108,7 @@ team {
 }
 
 team {
-    name: "trendy_team_wear_wearflow",
+    name: "trendy_team_wear_remote_compose",
 
     // go/trendy/manage/engineers/5947250429558784
     trendy_team_id: "5947250429558784",
@@ -4416,5 +4416,12 @@ team {
     trendy_team_id: "6463689697099776",
 }
 
+team {
+    name: "trendy_team_desktop_experiences",
+
+    // go/trendy/manage/engineers/5342568499216384
+    trendy_team_id: "5342568499216384",
+}
+
 // DON'T ADD NEW RULES HERE. For more details refer to
 // go/new-android-ownership-model
diff --git a/tools/aconfig/OWNERS b/tools/aconfig/OWNERS
index 0c31938d63..be81975206 100644
--- a/tools/aconfig/OWNERS
+++ b/tools/aconfig/OWNERS
@@ -1,7 +1,7 @@
 dzshen@google.com
+marybethfair@google.com
 opg@google.com
 zhidou@google.com
 
 amhk@google.com  #{LAST_RESORT_SUGGESTION}
 jham@google.com  #{LAST_RESORT_SUGGESTION}
-joeo@google.com  #{LAST_RESORT_SUGGESTION}
diff --git a/tools/aconfig/TEST_MAPPING b/tools/aconfig/TEST_MAPPING
index b1cc6025e2..75a530c0dc 100644
--- a/tools/aconfig/TEST_MAPPING
+++ b/tools/aconfig/TEST_MAPPING
@@ -79,10 +79,6 @@
       // aconfig_storage write api rust integration tests
       "name": "aconfig_storage_write_api.test.rust"
     },
-    {
-      // aconfig_storage write api cpp integration tests
-      "name": "aconfig_storage_write_api.test.cpp"
-    },
     {
       // aconfig_storage read api rust integration tests
       "name": "aconfig_storage_read_api.test.rust"
diff --git a/tools/aconfig/aconfig/Android.bp b/tools/aconfig/aconfig/Android.bp
index 7bdec58004..846fa0afe0 100644
--- a/tools/aconfig/aconfig/Android.bp
+++ b/tools/aconfig/aconfig/Android.bp
@@ -7,36 +7,56 @@ rust_defaults {
     edition: "2021",
     clippy_lints: "android",
     lints: "android",
+    crate_root: "src/main.rs",
     srcs: [
-        "src/main.rs",
         ":finalized_flags_record.json",
+        "templates/*.template",
     ],
     rustlibs: [
         "libaconfig_protos",
-        "libaconfig_storage_file",
         "libanyhow",
         "libclap",
         "libitertools",
+        "liblazy_static",
         "libprotobuf",
         "libserde",
         "libserde_json",
         "libtinytemplate",
         "libconvert_finalized_flags",
     ],
+    cfgs: select(release_flag("RELEASE_ACONFIG_FINGERPRINT_RUST"), {
+        true: ["enable_fingerprint_rust"],
+        default: [],
+    }) +
+        select(release_flag("RELEASE_ACONFIG_FINGERPRINT_CPP"), {
+            true: ["enable_fingerprint_cpp"],
+            default: [],
+        }) +
+        select(release_flag("RELEASE_JARJAR_FLAGS_IN_FRAMEWORK"), {
+            true: ["enable_jarjar_flags_in_framwork"],
+            default: [],
+        }),
 }
 
 rust_binary_host {
     name: "aconfig",
     defaults: ["aconfig.defaults"],
+    rustlibs: [
+        "libaconfig_storage_file",
+    ],
 }
 
 rust_test_host {
     name: "aconfig.test",
     defaults: ["aconfig.defaults"],
     rustlibs: [
+        "libaconfig_storage_file_with_test_utils",
         "libitertools",
     ],
     test_suites: ["general-tests"],
+    data: [
+        "tests/mainline_beta_namespaces.json",
+    ],
 }
 
 // integration tests: general
@@ -63,31 +83,33 @@ aconfig_declarations {
     srcs: ["tests/test_force_read_only.aconfig"],
 }
 
-aconfig_values {
-    name: "aconfig.test.flag.values",
-    package: "com.android.aconfig.test",
-    srcs: [
-        "tests/first.values",
-        "tests/second.values",
-    ],
+aconfig_declarations {
+    name: "mainline_beta_mockup_flags",
+    package: "com.android.aconfig.test.mainline_beta",
+    container: "com.android.mainline_beta_mockup",
+    srcs: ["tests/mainline_beta_mockup.aconfig"],
 }
 
-aconfig_values {
-    name: "aconfig.test.flag.second_values",
-    package: "com.android.aconfig.test",
-    srcs: [
-        "tests/third.values",
-    ],
+aconfig_declarations {
+    name: "mainline_beta_exported_mockup_flags",
+    package: "com.android.aconfig.test.exported.mainline_beta",
+    container: "com.android.mainline_beta_mockup",
+    srcs: ["tests/mainline_beta_exported_mockup.aconfig"],
+    exportable: true,
 }
 
-aconfig_value_set {
-    name: "aconfig.test.flag.value_set",
-    values: [
-        "aconfig.test.flag.values",
-    ],
+// integration tests: java
+
+java_aconfig_library {
+    name: "aconfig_test_mainline_beta_java_library",
+    aconfig_declarations: "mainline_beta_mockup_flags",
 }
 
-// integration tests: java
+java_aconfig_library {
+    name: "aconfig_test_mainline_beta_java_library_exported",
+    aconfig_declarations: "mainline_beta_exported_mockup_flags",
+    mode: "exported",
+}
 
 java_aconfig_library {
     name: "aconfig_test_java_library",
@@ -117,6 +139,8 @@ android_test {
         "aconfig_test_java_library",
         "aconfig_test_java_library_exported",
         "aconfig_test_java_library_forcereadonly",
+        "aconfig_test_mainline_beta_java_library",
+        "aconfig_test_mainline_beta_java_library_exported",
         "androidx.test.rules",
         "testng",
     ],
diff --git a/tools/aconfig/aconfig/Cargo.toml b/tools/aconfig/aconfig/Cargo.toml
index 7e4bdf2f7d..2f5994febf 100644
--- a/tools/aconfig/aconfig/Cargo.toml
+++ b/tools/aconfig/aconfig/Cargo.toml
@@ -15,8 +15,9 @@ protobuf = "3.2.0"
 serde = { version = "1.0.152", features = ["derive"] }
 serde_json = "1.0.93"
 tinytemplate = "1.2.1"
+lazy_static = "1.5.0"
 aconfig_protos = { path = "../aconfig_protos" }
-aconfig_storage_file = { path = "../aconfig_storage_file" }
+aconfig_storage_file = { path = "../aconfig_storage_file", features = ["test_utils"] }
 convert_finalized_flags = { path = "../convert_finalized_flags" }
 
 [build-dependencies]
@@ -25,3 +26,11 @@ itertools = "0.10.5"
 serde = { version = "1.0.152", features = ["derive"] }
 serde_json = "1.0.93"
 convert_finalized_flags = { path = "../convert_finalized_flags" }
+
+[lints.rust.unexpected_cfgs]
+level = "warn"
+check-cfg = [
+    "cfg(enable_fingerprint_rust)",
+    "cfg(enable_fingerprint_cpp)",
+    "cfg(enable_jarjar_flags_in_framwork)",
+]
diff --git a/tools/aconfig/aconfig/config/mainline_beta_namespaces_apr_25.json b/tools/aconfig/aconfig/config/mainline_beta_namespaces_apr_25.json
new file mode 100644
index 0000000000..c30733f7d6
--- /dev/null
+++ b/tools/aconfig/aconfig/config/mainline_beta_namespaces_apr_25.json
@@ -0,0 +1,28 @@
+{
+    "namespaces": {
+        "com_android_mainline_beta_mockup": {
+            "container": "com.android.mainline_beta_mockup",
+            "allow_exported": true
+        },
+        "com_android_tethering": {
+            "container": "com.android.tethering",
+            "allow_exported": true
+        },
+        "com_android_networkstack": {
+            "container": "com.android.networkstack",
+            "allow_exported": false
+        },
+        "com_android_captiveportallogin": {
+            "container": "com.android.captiveportallogin",
+            "allow_exported": false
+        },
+        "com_android_healthfitness": {
+            "container": "com.android.healthfitness",
+            "allow_exported": true
+        },
+        "com_android_mediaprovider": {
+            "container": "com.android.mediaprovider",
+            "allow_exported": true
+        }
+    }
+}
diff --git a/tools/aconfig/aconfig/src/cli_parser.rs b/tools/aconfig/aconfig/src/cli_parser.rs
new file mode 100644
index 0000000000..09fbd8645e
--- /dev/null
+++ b/tools/aconfig/aconfig/src/cli_parser.rs
@@ -0,0 +1,782 @@
+use crate::codegen::CodegenMode;
+use crate::dump::DumpFormat;
+use aconfig_storage_file::{StorageFileType, DEFAULT_FILE_VERSION, MAX_SUPPORTED_FILE_VERSION};
+
+use anyhow::{anyhow, bail, ensure, Context, Result};
+use clap::{builder::ArgAction, builder::EnumValueParser, Arg, ArgMatches, Command};
+use core::any::Any;
+use std::ffi::OsString;
+use std::io::BufRead;
+use std::path::PathBuf;
+
+const HELP_DUMP_CACHE: &str = r#"
+An aconfig cache file, created via `aconfig create-cache`.
+"#;
+
+const HELP_DUMP_FORMAT: &str = r#"
+Change the output format for each flag.
+
+The argument to --format is a format string. Each flag will be a copy of this string, with certain
+placeholders replaced by attributes of the flag. The placeholders are
+
+  {package}
+  {name}
+  {namespace}
+  {description}
+  {bug}
+  {state}
+  {state:bool}
+  {permission}
+  {trace}
+  {trace:paths}
+  {is_fixed_read_only}
+  {is_exported}
+  {container}
+  {metadata}
+  {fully_qualified_name}
+
+Note: the format strings "textproto" and "protobuf" are handled in a special way: they output all
+flag attributes in text or binary protobuf format.
+
+Examples:
+
+  # See which files were read to determine the value of a flag; the files were read in the order
+  # listed.
+  --format='{fully_qualified_name} {trace}'
+
+  # Trace the files read for a specific flag. Useful during debugging.
+  --filter=fully_qualified_name:com.foo.flag_name --format='{trace}'
+
+  # Print a somewhat human readable description of each flag.
+  --format='The flag {name} in package {package} is {state} and has permission {permission}.'
+"#;
+
+const HELP_DUMP_FILTER: &str = r#"
+Limit which flags to output. If --filter is omitted, all flags will be printed. If multiple
+--filter options are provided, the output will be limited to flags that match any of the filters.
+
+The argument to --filter is a search query. Multiple queries can be AND-ed together by
+concatenating them with a plus sign.
+
+Valid queries are:
+
+  package:<string>
+  name:<string>
+  namespace:<string>
+  bug:<string>
+  state:ENABLED|DISABLED
+  permission:READ_ONLY|READ_WRITE
+  is_fixed_read_only:true|false
+  is_exported:true|false
+  container:<string>
+  fully_qualified_name:<string>
+
+Note: there is currently no support for filtering based on these flag attributes: description,
+trace, metadata.
+
+Examples:
+
+  # Print a single flag:
+  --filter=fully_qualified_name:com.foo.flag_name
+
+  # Print all known information about a single flag:
+  --filter=fully_qualified_name:com.foo.flag_name --format=textproto
+
+  # Print all flags in the com.foo package, and all enabled flags in the com.bar package:
+  --filter=package:com.foo --filter=package.com.bar+state:ENABLED
+"#;
+
+const HELP_DUMP_DEDUP: &str = r#"
+Allow the same flag to be present in multiple cache files; if duplicates are found, collapse into
+a single instance.
+"#;
+
+const MAINLINE_BETA_NAMESPACE_CONFIG: &str = r#"
+A json file to configure mainline beta namespaces. This option is internal to Google. The json
+configuration should assume the following format:
+
+{
+    "namespaces": {
+        "com_android_tethering": {
+            "container": "com.android.tethering",
+            "allow_exported": true
+        },
+        "com_android_mediaprovider": {
+            "container": "com.android.mediaprovider",
+            "allow_exported": true
+        }
+    }
+}
+"#;
+
+/// Conventional prefix to mark response file
+pub const RESPONSE_FILE_PREFIX: char = '@';
+
+// Trait for Reading Response Files
+// Defines the capability to read lines from a response file path.
+// Allows mocking file access during testing.
+pub trait ResponseFileReader {
+    fn read_to_bufread(&self, path_str: &str) -> Result<Box<dyn BufRead>>;
+}
+
+#[derive(Debug)]
+pub enum ParsedCommand {
+    CreateCache {
+        package: String,
+        container: String,
+        declarations: Vec<String>,
+        values: Vec<String>,
+        default_permission: aconfig_protos::ProtoFlagPermission,
+        allow_read_write: bool,
+        cache_out_path: String,
+        mainline_beta_namespace_config: Option<PathBuf>,
+        force_read_only: bool,
+    },
+    CreateJavaLib {
+        cache_path: String,
+        out_dir: PathBuf,
+        mode: CodegenMode,
+        single_exported_file: bool,
+    },
+    CreateCppLib {
+        cache_path: String,
+        out_dir: PathBuf,
+        mode: CodegenMode,
+    },
+    CreateRustLib {
+        cache_path: String,
+        out_dir: PathBuf,
+        mode: CodegenMode,
+    },
+    DumpCache {
+        cache_paths: Vec<String>,
+        format: DumpFormat,
+        filters: Vec<String>,
+        dedup: bool,
+        out_path: String,
+    },
+    CreateStorage {
+        container: String,
+        file_type: StorageFileType,
+        cache_paths: Vec<String>,
+        out_path: String,
+        version: u32,
+    },
+}
+
+fn build_cli() -> Command {
+    Command::new("aconfig")
+        .subcommand_required(true)
+        .about(format!("A tool trunk flags. Supports {}responsefile syntax.", RESPONSE_FILE_PREFIX))
+        .subcommand(
+            Command::new("create-cache")
+                .arg(Arg::new("package").long("package").required(true))
+                .arg(Arg::new("container").long("container").required(true))
+                .arg(Arg::new("declarations").long("declarations").action(ArgAction::Append))
+                .arg(Arg::new("values").long("values").action(ArgAction::Append))
+                .arg(
+                    Arg::new("default-permission")
+                        .long("default-permission")
+                        .value_parser(aconfig_protos::flag_permission::parse_from_str)
+                        .default_value(aconfig_protos::flag_permission::to_string(
+                            &crate::commands::DEFAULT_FLAG_PERMISSION,
+                        )),
+                )
+                .arg(
+                    Arg::new("allow-read-write")
+                        .long("allow-read-write")
+                        .value_parser(clap::value_parser!(bool))
+                        .default_value("true"),
+                )
+                .arg(Arg::new("cache").long("cache").required(true).help("Output cache file path."))
+                .arg(
+                    Arg::new("mainline-beta-namespace-config")
+                        .long("mainline-beta-namespace-config")
+                        .long_help(MAINLINE_BETA_NAMESPACE_CONFIG.trim()),
+                )
+                .arg(
+                    Arg::new("force-read-only")
+                        .long("force-read-only")
+                        .value_parser(clap::value_parser!(bool))
+                        .default_value("false"),
+                ),
+        )
+        .subcommand(
+            Command::new("create-java-lib")
+                .arg(Arg::new("cache").long("cache").required(true))
+                .arg(Arg::new("out").long("out").required(true))
+                .arg(
+                    Arg::new("mode")
+                        .long("mode")
+                        .value_parser(EnumValueParser::<CodegenMode>::new())
+                        .default_value("production"),
+                )
+                .arg(
+                    Arg::new("single-exported-file")
+                        .long("single-exported-file")
+                        .value_parser(clap::value_parser!(bool))
+                        .default_value("false"),
+                ),
+        )
+        .subcommand(
+            Command::new("create-cpp-lib")
+                .arg(Arg::new("cache").long("cache").required(true))
+                .arg(Arg::new("out").long("out").required(true))
+                .arg(
+                    Arg::new("mode")
+                        .long("mode")
+                        .value_parser(EnumValueParser::<CodegenMode>::new())
+                        .default_value("production"),
+                ),
+        )
+        .subcommand(
+            Command::new("create-rust-lib")
+                .arg(Arg::new("cache").long("cache").required(true))
+                .arg(Arg::new("out").long("out").required(true))
+                .arg(
+                    Arg::new("mode")
+                        .long("mode")
+                        .value_parser(EnumValueParser::<CodegenMode>::new())
+                        .default_value("production"),
+                ),
+        )
+        .subcommand(
+            Command::new("dump-cache")
+                .alias("dump")
+                .arg(
+                    Arg::new("cache")
+                        .long("cache")
+                        .action(ArgAction::Append)
+                        .long_help(HELP_DUMP_CACHE.trim()),
+                )
+                .arg(
+                    Arg::new("format")
+                        .long("format")
+                        .value_parser(|s: &str| DumpFormat::try_from(s))
+                        .default_value(
+                            "{fully_qualified_name} [{container}]: {permission} + {state}",
+                        )
+                        .long_help(HELP_DUMP_FORMAT.trim()),
+                )
+                .arg(
+                    Arg::new("filter")
+                        .long("filter")
+                        .action(ArgAction::Append)
+                        .long_help(HELP_DUMP_FILTER.trim()),
+                )
+                .arg(
+                    Arg::new("dedup")
+                        .long("dedup")
+                        .num_args(0)
+                        .action(ArgAction::SetTrue)
+                        .long_help(HELP_DUMP_DEDUP.trim()),
+                )
+                .arg(Arg::new("out").long("out").default_value("-")),
+        )
+        .subcommand(
+            Command::new("create-storage")
+                .arg(
+                    Arg::new("container")
+                        .long("container")
+                        .required(true)
+                        .help("The target container for the generated storage file."),
+                )
+                .arg(
+                    Arg::new("file")
+                        .long("file")
+                        .required(true)
+                        .value_parser(|s: &str| StorageFileType::try_from(s))
+                        .help("Type of storage file to create (pb, flatbuffer, test-mapping)."),
+                )
+                .arg(Arg::new("cache").long("cache").action(ArgAction::Append).required(true))
+                .arg(Arg::new("out").long("out").required(true))
+                .arg(
+                    Arg::new("version")
+                        .long("version")
+                        .value_parser(|s: &str| s.parse::<u32>())
+                        .help("Storage file format version."),
+                ),
+        )
+}
+
+fn get_required_arg<'a, T>(matches: &'a ArgMatches, arg_name: &str) -> Result<&'a T>
+where
+    T: Any + Clone + Send + Sync + 'static,
+{
+    matches
+        .get_one::<T>(arg_name)
+        .ok_or(anyhow!("internal error: required argument '{}' not found", arg_name))
+}
+
+fn get_zero_or_more_string_paths_from_arg(matches: &ArgMatches, arg_name: &str) -> Vec<String> {
+    matches.get_many::<String>(arg_name).unwrap_or_default().cloned().collect()
+}
+
+// Process the raw arguments
+// It will extract the arguments in response file if there is
+pub fn process_raw_args<R: ResponseFileReader>(
+    raw_args_iter: impl IntoIterator<Item = OsString>,
+    reader: &R,
+) -> Result<Vec<OsString>> {
+    let mut processed_args: Vec<OsString> = Vec::new();
+    let mut args_iter = raw_args_iter.into_iter();
+
+    if let Some(app_arg) = args_iter.next() {
+        processed_args.push(app_arg);
+    }
+
+    for arg in args_iter {
+        let arg_str = arg.to_str().ok_or(anyhow!("Invalid argument: not a valid string"))?;
+
+        if let Some(response_file_path) = arg_str.strip_prefix(RESPONSE_FILE_PREFIX) {
+            ensure!(
+                !response_file_path.is_empty(),
+                "missing response file after {}",
+                RESPONSE_FILE_PREFIX
+            );
+            let reader = reader
+                .read_to_bufread(response_file_path)
+                .with_context(|| format!("Failed to open response file: {}", response_file_path))?;
+            for line_result in reader.lines() {
+                let line = line_result.with_context(|| {
+                    format!("Failed to read line from response file reader: {}", response_file_path)
+                })?;
+                let trimmed_line = line.trim();
+                if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
+                    continue;
+                }
+                for token in trimmed_line.split_whitespace() {
+                    processed_args.push(OsString::from(token));
+                }
+            }
+        } else {
+            processed_args.push(arg);
+        }
+    }
+    Ok(processed_args)
+}
+
+// Parses command line arguments, handling response files (@file).
+// Returns a structured representation of the command or an error.
+pub fn parse_args(
+    processed_args: impl IntoIterator<Item = std::ffi::OsString>,
+) -> Result<ParsedCommand> {
+    let cli_app = build_cli();
+    let matches = cli_app.get_matches_from(processed_args);
+
+    match matches.subcommand() {
+        Some(("create-cache", sub_matches)) => {
+            let declarations = get_zero_or_more_string_paths_from_arg(sub_matches, "declarations");
+            let values = get_zero_or_more_string_paths_from_arg(sub_matches, "values");
+            let mainline_beta_namespace_config =
+                match sub_matches.get_one::<String>("mainline-beta-namespace-config") {
+                    Some(config) => {
+                        if config.is_empty() {
+                            None
+                        } else {
+                            Some(PathBuf::from(config))
+                        }
+                    }
+                    None => None,
+                };
+            Ok(ParsedCommand::CreateCache {
+                package: get_required_arg::<String>(sub_matches, "package")?.clone(),
+                container: get_required_arg::<String>(sub_matches, "container")?.clone(),
+                declarations,
+                values,
+                default_permission: *get_required_arg::<aconfig_protos::ProtoFlagPermission>(
+                    sub_matches,
+                    "default-permission",
+                )?,
+                allow_read_write: *get_required_arg::<bool>(sub_matches, "allow-read-write")?,
+                cache_out_path: get_required_arg::<String>(sub_matches, "cache")?.clone(),
+                mainline_beta_namespace_config,
+                force_read_only: *get_required_arg::<bool>(sub_matches, "force-read-only")?,
+            })
+        }
+        Some(("create-java-lib", sub_matches)) => Ok(ParsedCommand::CreateJavaLib {
+            cache_path: get_required_arg::<String>(sub_matches, "cache")?.clone(),
+            out_dir: PathBuf::from(get_required_arg::<String>(sub_matches, "out")?),
+            mode: *get_required_arg::<CodegenMode>(sub_matches, "mode")?,
+            single_exported_file: *get_required_arg::<bool>(sub_matches, "single-exported-file")?,
+        }),
+        Some(("create-cpp-lib", sub_matches)) => Ok(ParsedCommand::CreateCppLib {
+            cache_path: get_required_arg::<String>(sub_matches, "cache")?.clone(),
+            out_dir: PathBuf::from(get_required_arg::<String>(sub_matches, "out")?),
+            mode: *get_required_arg::<CodegenMode>(sub_matches, "mode")?,
+        }),
+        Some(("create-rust-lib", sub_matches)) => Ok(ParsedCommand::CreateRustLib {
+            cache_path: get_required_arg::<String>(sub_matches, "cache")?.clone(),
+            out_dir: PathBuf::from(get_required_arg::<String>(sub_matches, "out")?),
+            mode: *get_required_arg::<CodegenMode>(sub_matches, "mode")?,
+        }),
+        Some(("dump-cache", sub_matches)) => {
+            let filters = sub_matches
+                .get_many::<String>("filter")
+                .unwrap_or_default()
+                .cloned()
+                .collect::<Vec<_>>();
+            Ok(ParsedCommand::DumpCache {
+                cache_paths: get_zero_or_more_string_paths_from_arg(sub_matches, "cache"),
+                format: get_required_arg::<DumpFormat>(sub_matches, "format")?.clone(),
+                filters,
+                dedup: *get_required_arg::<bool>(sub_matches, "dedup")?,
+                out_path: get_required_arg::<String>(sub_matches, "out")?.clone(),
+            })
+        }
+        Some(("create-storage", sub_matches)) => {
+            let version =
+                sub_matches.get_one::<u32>("version").copied().unwrap_or(DEFAULT_FILE_VERSION);
+
+            if version > MAX_SUPPORTED_FILE_VERSION {
+                bail!(
+                    "Invalid version selected ({}) for create-storage. Max supported: {}",
+                    version,
+                    MAX_SUPPORTED_FILE_VERSION
+                );
+            }
+
+            Ok(ParsedCommand::CreateStorage {
+                container: get_required_arg::<String>(sub_matches, "container")?.clone(),
+                file_type: get_required_arg::<StorageFileType>(sub_matches, "file")?.clone(),
+                cache_paths: get_zero_or_more_string_paths_from_arg(sub_matches, "cache"),
+                out_path: get_required_arg::<String>(sub_matches, "out")?.clone(),
+                version,
+            })
+        }
+        _ => unreachable!(),
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    use std::collections::HashMap;
+    use std::io::{BufRead, BufReader, Cursor};
+    use std::path::PathBuf;
+
+    #[derive(Default)]
+    struct MockFileReader {
+        files: HashMap<String, String>,
+    }
+
+    impl MockFileReader {
+        fn add_file(&mut self, path: &str, content: &str) {
+            self.files.insert(path.to_string(), content.to_string());
+        }
+    }
+
+    impl ResponseFileReader for MockFileReader {
+        fn read_to_bufread(&self, path_str: &str) -> Result<Box<dyn BufRead>> {
+            match self.files.get(path_str) {
+                Some(content) => {
+                    let data = content.clone().into_bytes();
+                    let cursor = Cursor::new(data);
+                    let buf_reader = BufReader::new(cursor);
+                    Ok(Box::new(buf_reader))
+                }
+                None => Err(anyhow!("Mock file not found: {}", path_str)),
+            }
+        }
+    }
+
+    fn create_os_command(command: &str) -> Vec<OsString> {
+        command.split_whitespace().map(OsString::from).collect()
+    }
+
+    #[test]
+    fn test_parse_create_cache() -> Result<()> {
+        let command_string = "aconfig create-cache \
+             --package com.test.cache \
+             --container vendor \
+             --declarations test.aconfig \
+             --values flag.val \
+             --cache /output/cache.pb \
+             --default-permission READ_WRITE \
+             --allow-read-write true \
+             --mainline-beta-namespace-config /path/to/some/file.json \
+             --force-read-only false";
+        let input_args = create_os_command(command_string);
+        let parsed = parse_args(input_args)?;
+
+        assert!(matches!(parsed, ParsedCommand::CreateCache { .. }));
+        if let ParsedCommand::CreateCache {
+            package,
+            container,
+            declarations,
+            values,
+            default_permission,
+            allow_read_write,
+            cache_out_path,
+            mainline_beta_namespace_config,
+            force_read_only,
+        } = parsed
+        {
+            assert_eq!(package, "com.test.cache");
+            assert_eq!(container, "vendor".to_string());
+            assert_eq!(declarations.len(), 1);
+            assert_eq!(values.len(), 1);
+            assert_eq!(declarations[0], "test.aconfig");
+            assert_eq!(values[0], "flag.val");
+            assert_eq!(default_permission, aconfig_protos::ProtoFlagPermission::READ_WRITE);
+            assert!(allow_read_write);
+            assert_eq!(cache_out_path, "/output/cache.pb");
+            assert_eq!(
+                mainline_beta_namespace_config,
+                Some(PathBuf::from("/path/to/some/file.json"))
+            );
+            assert!(!force_read_only);
+        }
+        Ok(())
+    }
+
+    #[test]
+    fn test_parse_create_java_lib() -> Result<()> {
+        let command_string = "aconfig create-java-lib \
+             --cache cache.pb \
+             --out /java/output \
+             --mode test \
+             --single-exported-file true";
+        let input_args = create_os_command(command_string);
+        let parsed = parse_args(input_args)?;
+
+        assert!(matches!(parsed, ParsedCommand::CreateJavaLib { .. }));
+        if let ParsedCommand::CreateJavaLib { cache_path, out_dir, mode, single_exported_file } =
+            parsed
+        {
+            assert_eq!(cache_path, "cache.pb");
+            assert_eq!(out_dir, PathBuf::from("/java/output"));
+            assert_eq!(mode, CodegenMode::Test);
+            assert!(single_exported_file);
+        }
+        Ok(())
+    }
+
+    #[test]
+    fn test_parse_create_cpp_lib() -> Result<()> {
+        let command_string = "aconfig create-cpp-lib \
+             --cache cache.pb \
+             --out /cpp/output \
+             --mode test";
+        let input_args = create_os_command(command_string);
+        let parsed = parse_args(input_args)?;
+
+        assert!(matches!(parsed, ParsedCommand::CreateCppLib { .. }));
+        if let ParsedCommand::CreateCppLib { cache_path, out_dir, mode } = parsed {
+            assert_eq!(cache_path, "cache.pb");
+            assert_eq!(out_dir, PathBuf::from("/cpp/output"));
+            assert_eq!(mode, CodegenMode::Test);
+        }
+        Ok(())
+    }
+
+    #[test]
+    fn test_parse_dump_cache() -> Result<()> {
+        let command_string = "aconfig dump-cache \
+             --cache cache1.pb \
+             --cache cache2.pb \
+             --format textproto \
+             --filter package:com.foo \
+             --filter state:ENABLED+name:bar \
+             --dedup \
+             --out /tmp/dump.txt";
+
+        let input_args = create_os_command(command_string);
+        let parsed = parse_args(input_args)?;
+
+        assert!(matches!(parsed, ParsedCommand::DumpCache { .. }));
+        if let ParsedCommand::DumpCache { cache_paths, format, filters, dedup, out_path } = parsed {
+            assert_eq!(cache_paths.len(), 2);
+            assert!(cache_paths.iter().any(|c| c == "cache1.pb"));
+            assert!(cache_paths.iter().any(|c| c == "cache2.pb"));
+            assert_eq!(format, DumpFormat::Textproto);
+            assert_eq!(filters.len(), 2);
+            assert_eq!(filters[0], "package:com.foo");
+            assert_eq!(filters[1], "state:ENABLED+name:bar");
+            assert!(dedup);
+            assert_eq!(out_path, "/tmp/dump.txt");
+        }
+        Ok(())
+    }
+
+    #[test]
+    fn test_parse_create_storage() -> Result<()> {
+        let version = DEFAULT_FILE_VERSION + 1;
+
+        let command_string = format!(
+            "aconfig create-storage \
+             --container system \
+             --file package_map \
+             --cache cache1.pb \
+             --cache cache2.pb \
+             --out /storage/system.package.map \
+             --version {}",
+            version
+        );
+        let input_args = create_os_command(&command_string);
+        let parsed = parse_args(input_args)?;
+
+        assert!(matches!(parsed, ParsedCommand::CreateStorage { .. }));
+        if let ParsedCommand::CreateStorage {
+            container,
+            file_type,
+            cache_paths,
+            out_path,
+            version: parsed_version,
+        } = parsed
+        {
+            assert_eq!(container, "system");
+            assert_eq!(file_type, StorageFileType::PackageMap);
+            assert_eq!(cache_paths.len(), 2);
+            assert!(cache_paths.iter().any(|c| c == "cache1.pb"));
+            assert!(cache_paths.iter().any(|c| c == "cache2.pb"));
+            assert_eq!(out_path, "/storage/system.package.map");
+            assert_eq!(parsed_version, version);
+        }
+        Ok(())
+    }
+
+    #[test]
+    fn test_parse_create_rust_lib() -> Result<()> {
+        let command_string = "aconfig create-rust-lib \
+             --cache cache.pb \
+             --out /rust/output \
+             --mode test"
+            .to_string();
+        let input_args = create_os_command(&command_string);
+        let parsed = parse_args(input_args)?;
+
+        assert!(matches!(parsed, ParsedCommand::CreateRustLib { .. }));
+        if let ParsedCommand::CreateRustLib { cache_path, out_dir, mode } = parsed {
+            assert_eq!(cache_path, "cache.pb");
+            assert_eq!(out_dir, PathBuf::from("/rust/output"));
+            assert_eq!(mode, CodegenMode::Test);
+        }
+        Ok(())
+    }
+
+    #[test]
+    fn test_process_args_with_response_file() -> Result<()> {
+        let mut reader = MockFileReader::default();
+        reader.add_file("args.txt", "--option1 value1\n#comment\n--flag value2");
+
+        let raw_args = create_os_command("aconfig dump @args.txt --other value3");
+        let expected_args: Vec<OsString> = vec![
+            "aconfig".into(),
+            "dump".into(),
+            "--option1".into(),
+            "value1".into(),
+            "--flag".into(),
+            "value2".into(),
+            "--other".into(),
+            "value3".into(),
+        ];
+
+        let processed = process_raw_args(raw_args, &reader)?;
+
+        assert_eq!(processed, expected_args);
+        Ok(())
+    }
+
+    #[test]
+    fn test_response_file_expansion() -> Result<()> {
+        let file_content = r#"
+        --package
+        com.via.respfile
+        # This is a comment
+
+        --container
+        vendor
+        --cache
+        cache.pb
+        "#;
+        let extra_command = "--declarations test.aconfig \
+             --values flag.val";
+        let mut reader = MockFileReader::default();
+        reader.add_file("response", file_content);
+
+        let mut input_args: Vec<OsString> =
+            vec!["aconfig".into(), "create-cache".into(), "@response".into()];
+        input_args.append(&mut create_os_command(extra_command));
+
+        let processed = process_raw_args(input_args, &reader)?;
+        let parsed = parse_args(processed)?;
+
+        assert!(matches!(parsed, ParsedCommand::CreateCache { .. }));
+        if let ParsedCommand::CreateCache {
+            package,
+            container,
+            declarations,
+            values,
+            cache_out_path,
+            default_permission,
+            allow_read_write,
+            mainline_beta_namespace_config,
+            force_read_only,
+        } = parsed
+        {
+            assert_eq!(package, "com.via.respfile");
+            assert_eq!(container, "vendor");
+            assert_eq!(declarations.len(), 1);
+            assert_eq!(values.len(), 1);
+            assert_eq!(declarations[0], "test.aconfig");
+            assert_eq!(values[0], "flag.val");
+            assert_eq!(default_permission, aconfig_protos::ProtoFlagPermission::READ_WRITE);
+            assert!(allow_read_write);
+            assert_eq!(cache_out_path, "cache.pb");
+            assert_eq!(mainline_beta_namespace_config, None);
+            assert!(!force_read_only);
+        }
+
+        Ok(())
+    }
+
+    #[test]
+    fn test_response_file_expansion_empty_file() -> Result<()> {
+        let file_content = r#""#;
+        let extra_command = "--package \
+            com.via.respfile \
+            --container \
+            vendor \
+            --cache \
+            cache.pb \
+            --declarations  test.aconfig \
+            --values flag.val";
+        let mut reader = MockFileReader::default();
+        reader.add_file("response", file_content);
+        let mut input_args: Vec<OsString> =
+            vec!["aconfig".into(), "create-cache".into(), "@response".into()];
+        input_args.append(&mut create_os_command(extra_command));
+        let processed = process_raw_args(input_args, &reader)?;
+        let parsed = parse_args(processed)?;
+
+        assert!(matches!(parsed, ParsedCommand::CreateCache { .. }));
+        if let ParsedCommand::CreateCache {
+            package,
+            container,
+            declarations,
+            values,
+            cache_out_path,
+            default_permission,
+            allow_read_write,
+            mainline_beta_namespace_config,
+            force_read_only,
+        } = parsed
+        {
+            assert_eq!(package, "com.via.respfile");
+            assert_eq!(container, "vendor");
+            assert_eq!(declarations.len(), 1);
+            assert_eq!(values.len(), 1);
+            assert_eq!(declarations[0], "test.aconfig");
+            assert_eq!(values[0], "flag.val");
+            assert_eq!(default_permission, aconfig_protos::ProtoFlagPermission::READ_WRITE);
+            assert!(allow_read_write);
+            assert_eq!(cache_out_path, "cache.pb");
+            assert_eq!(mainline_beta_namespace_config, None);
+            assert!(!force_read_only);
+        }
+
+        Ok(())
+    }
+}
diff --git a/tools/aconfig/aconfig/src/codegen/cpp.rs b/tools/aconfig/aconfig/src/codegen/cpp.rs
index b855d78602..aceebcd160 100644
--- a/tools/aconfig/aconfig/src/codegen/cpp.rs
+++ b/tools/aconfig/aconfig/src/codegen/cpp.rs
@@ -20,25 +20,27 @@ use std::collections::HashMap;
 use std::path::PathBuf;
 use tinytemplate::TinyTemplate;
 
-use aconfig_protos::{ProtoFlagPermission, ProtoFlagState, ProtoParsedFlag};
+use aconfig_protos::{
+    ParsedFlagExt, ProtoFlagPermission, ProtoFlagState, ProtoFlagStorageBackend, ProtoParsedFlag,
+};
 
-use crate::codegen;
-use crate::codegen::CodegenMode;
-use crate::commands::{should_include_flag, OutputFile};
+use crate::codegen::{self, get_flag_offset_in_storage_file, CodegenMode};
+use crate::commands::OutputFile;
 
 pub fn generate_cpp_code<I>(
     package: &str,
     parsed_flags_iter: I,
     codegen_mode: CodegenMode,
     flag_ids: HashMap<String, u16>,
+    package_fingerprint: Option<u64>,
 ) -> Result<Vec<OutputFile>>
 where
     I: Iterator<Item = ProtoParsedFlag>,
 {
     let mut readwrite_count = 0;
-    let class_elements: Vec<ClassElement> = parsed_flags_iter
+    let class_elements = parsed_flags_iter
         .map(|pf| create_class_element(package, &pf, flag_ids.clone(), &mut readwrite_count))
-        .collect();
+        .collect::<Result<Vec<ClassElement>>>()?;
     let readwrite = readwrite_count > 0;
     let has_fixed_read_only = class_elements.iter().any(|item| item.is_fixed_read_only);
     let header = package.replace('.', "_");
@@ -47,6 +49,7 @@ where
     ensure!(class_elements.len() > 0);
     let container = class_elements[0].container.clone();
     ensure!(codegen::is_valid_name_ident(&header));
+    let use_package_fingerprint = package_fingerprint.is_some();
     let context = Context {
         header: &header,
         package_macro: &package_macro,
@@ -58,6 +61,8 @@ where
         is_test_mode: codegen_mode == CodegenMode::Test,
         class_elements,
         container,
+        use_package_fingerprint,
+        package_fingerprint: package_fingerprint.unwrap_or_default(),
     };
 
     let files = [
@@ -102,6 +107,8 @@ pub struct Context<'a> {
     pub is_test_mode: bool,
     pub class_elements: Vec<ClassElement>,
     pub container: String,
+    pub use_package_fingerprint: bool,
+    pub package_fingerprint: u64,
 }
 
 #[derive(Serialize)]
@@ -123,25 +130,13 @@ fn create_class_element(
     pf: &ProtoParsedFlag,
     flag_ids: HashMap<String, u16>,
     rw_count: &mut i32,
-) -> ClassElement {
-    let no_assigned_offset = !should_include_flag(pf);
-
-    let flag_offset = match flag_ids.get(pf.name()) {
-        Some(offset) => offset,
-        None => {
-            // System/vendor/product RO+disabled flags have no offset in storage files.
-            // Assign placeholder value.
-            if no_assigned_offset {
-                &0
-            }
-            // All other flags _must_ have an offset.
-            else {
-                panic!("{}", format!("missing flag offset for {}", pf.name()));
-            }
-        }
-    };
-
-    ClassElement {
+) -> Result<ClassElement> {
+    ensure!(
+        pf.metadata.storage() != ProtoFlagStorageBackend::DEVICE_CONFIG,
+        "device config storage backend cannot be used in native codegen for flag {}",
+        pf.fully_qualified_name()
+    );
+    Ok(ClassElement {
         readwrite_idx: if pf.permission() == ProtoFlagPermission::READ_WRITE {
             let index = *rw_count;
             *rw_count += 1;
@@ -158,12 +153,12 @@ fn create_class_element(
         },
         flag_name: pf.name().to_string(),
         flag_macro: pf.name().to_uppercase(),
-        flag_offset: *flag_offset,
+        flag_offset: get_flag_offset_in_storage_file(&flag_ids, pf)?,
         device_config_namespace: pf.namespace().to_string(),
         device_config_flag: codegen::create_device_config_ident(package, pf.name())
             .expect("values checked at flag parse time"),
         container: pf.container().to_string(),
-    }
+    })
 }
 
 #[cfg(test)]
@@ -175,6 +170,19 @@ mod tests {
     const EXPORTED_PROD_HEADER_EXPECTED: &str = r#"
 #pragma once
 
+// Avoid destruction for thread safety.
+// Only enable this with clang.
+#if defined(__clang__)
+#ifndef ACONFIG_NO_DESTROY
+#define ACONFIG_NO_DESTROY [[clang::no_destroy]]
+#endif
+#else
+#warning "not built with clang disable no_destroy"
+#ifndef ACONFIG_NO_DESTROY
+#define ACONFIG_NO_DESTROY
+#endif
+#endif
+
 #ifndef COM_ANDROID_ACONFIG_TEST
 #define COM_ANDROID_ACONFIG_TEST(FLAG) COM_ANDROID_ACONFIG_TEST_##FLAG
 #endif
@@ -216,7 +224,7 @@ public:
     virtual bool enabled_rw() = 0;
 };
 
-extern std::unique_ptr<flag_provider_interface> provider_;
+ACONFIG_NO_DESTROY extern std::unique_ptr<flag_provider_interface> provider_;
 
 inline bool disabled_ro() {
     return false;
@@ -538,7 +546,7 @@ bool com_android_aconfig_test_enabled_rw();
 #include <android/log.h>
 #define LOG_TAG "aconfig_cpp_codegen"
 #define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
-
+#include <atomic>
 #include <vector>
 
 namespace com::android::aconfig::test {
@@ -547,16 +555,252 @@ namespace com::android::aconfig::test {
         public:
 
             flag_provider()
-                : cache_(4, -1)
+                : cache_(4)
                 , boolean_start_index_()
                 , flag_value_file_(nullptr)
                 , package_exists_in_storage_(true) {
+                for (size_t i = 0 ; i < 4; i++) {
+                    cache_[i] = -1;
+                }
+
+                auto package_map_file = aconfig_storage::get_mapped_file(
+                    "system",
+                    aconfig_storage::StorageFileType::package_map);
+                if (!package_map_file.ok()) {
+// Host doesn't have the package map file.
+#ifdef __ANDROID__
+                    ALOGE("error: failed to get package map file: %s", package_map_file.error().c_str());
+#endif
+                    package_exists_in_storage_ = false;
+                    return;
+                }
+
+                auto context = aconfig_storage::get_package_read_context(
+                    **package_map_file, "com.android.aconfig.test");
+                if (!context.ok()) {
+                    ALOGE("error: failed to get package read context: %s", context.error().c_str());
+                    package_exists_in_storage_ = false;
+                    return;
+                }
+
+                if (!(context->package_exists)) {
+                    package_exists_in_storage_ = false;
+                    return;
+                }
+
+                // cache package boolean flag start index
+                boolean_start_index_ = context->boolean_start_index;
+
+                // unmap package map file and free memory
+                delete *package_map_file;
+
+                auto flag_value_file = aconfig_storage::get_mapped_file(
+                    "system",
+                    aconfig_storage::StorageFileType::flag_val);
+                if (!flag_value_file.ok()) {
+                    ALOGE("error: failed to get flag value file: %s", flag_value_file.error().c_str());
+                    package_exists_in_storage_ = false;
+                    return;
+                }
+
+                // cache flag value file
+                flag_value_file_ = std::unique_ptr<aconfig_storage::MappedStorageFile>(
+                    *flag_value_file);
+
+            }
+
+
+            virtual bool disabled_ro() override {
+                return false;
+            }
+
+            virtual bool disabled_rw() override {
+                if (cache_[0].load(std::memory_order_relaxed) == -1) {
+                    if (!package_exists_in_storage_) {
+                        ALOGE("error: package does not exist, returning flag default value.");
+                        return false;
+                    }
+
+                    auto value = aconfig_storage::get_boolean_flag_value(
+                        *flag_value_file_,
+                        boolean_start_index_ + 0);
+
+                    if (!value.ok()) {
+                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                        return false;
+                    }
+
+                    cache_[0].store(*value, std::memory_order_relaxed);
+                }
+                return cache_[0].load(std::memory_order_relaxed);
+            }
+
+            virtual bool disabled_rw_exported() override {
+                if (cache_[1].load(std::memory_order_relaxed) == -1) {
+                    if (!package_exists_in_storage_) {
+                        ALOGE("error: package does not exist, returning flag default value.");
+                        return false;
+                    }
+
+                    auto value = aconfig_storage::get_boolean_flag_value(
+                        *flag_value_file_,
+                        boolean_start_index_ + 1);
+
+                    if (!value.ok()) {
+                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                        return false;
+                    }
+
+                    cache_[1].store(*value, std::memory_order_relaxed);
+                }
+                return cache_[1].load(std::memory_order_relaxed);
+            }
+
+            virtual bool disabled_rw_in_other_namespace() override {
+                if (cache_[2].load(std::memory_order_relaxed) == -1) {
+                    if (!package_exists_in_storage_) {
+                        ALOGE("error: package does not exist, returning flag default value.");
+                        return false;
+                    }
+
+                    auto value = aconfig_storage::get_boolean_flag_value(
+                        *flag_value_file_,
+                        boolean_start_index_ + 2);
+
+                    if (!value.ok()) {
+                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                        return false;
+                    }
+
+                    cache_[2].store(*value, std::memory_order_relaxed);
+                }
+                return cache_[2].load(std::memory_order_relaxed);
+            }
+
+            virtual bool enabled_fixed_ro() override {
+                return COM_ANDROID_ACONFIG_TEST_ENABLED_FIXED_RO;
+            }
+
+            virtual bool enabled_fixed_ro_exported() override {
+                return COM_ANDROID_ACONFIG_TEST_ENABLED_FIXED_RO_EXPORTED;
+            }
+
+            virtual bool enabled_ro() override {
+                return true;
+            }
+
+            virtual bool enabled_ro_exported() override {
+                return true;
+            }
+
+            virtual bool enabled_rw() override {
+                if (cache_[3].load(std::memory_order_relaxed) == -1) {
+                    if (!package_exists_in_storage_) {
+                        ALOGE("error: package does not exist, returning flag default value.");
+                        return true;
+                    }
+
+                    auto value = aconfig_storage::get_boolean_flag_value(
+                        *flag_value_file_,
+                        boolean_start_index_ + 7);
+
+                    if (!value.ok()) {
+                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                        return true;
+                    }
+
+                    cache_[3].store(*value, std::memory_order_relaxed);
+                }
+                return cache_[3].load(std::memory_order_relaxed);
+            }
+
+    private:
+        std::vector<std::atomic_int8_t> cache_;
+
+        uint32_t boolean_start_index_;
+
+        std::unique_ptr<aconfig_storage::MappedStorageFile> flag_value_file_;
+
+        bool package_exists_in_storage_;
+
+    };
+
+    std::unique_ptr<flag_provider_interface> provider_ =
+        std::make_unique<flag_provider>();
+}
+
+bool com_android_aconfig_test_disabled_ro() {
+    return false;
+}
+
+bool com_android_aconfig_test_disabled_rw() {
+    return com::android::aconfig::test::disabled_rw();
+}
+
+bool com_android_aconfig_test_disabled_rw_exported() {
+    return com::android::aconfig::test::disabled_rw_exported();
+}
+
+bool com_android_aconfig_test_disabled_rw_in_other_namespace() {
+    return com::android::aconfig::test::disabled_rw_in_other_namespace();
+}
+
+bool com_android_aconfig_test_enabled_fixed_ro() {
+    return COM_ANDROID_ACONFIG_TEST_ENABLED_FIXED_RO;
+}
+
+bool com_android_aconfig_test_enabled_fixed_ro_exported() {
+    return COM_ANDROID_ACONFIG_TEST_ENABLED_FIXED_RO_EXPORTED;
+}
+
+bool com_android_aconfig_test_enabled_ro() {
+    return true;
+}
+
+bool com_android_aconfig_test_enabled_ro_exported() {
+    return true;
+}
+
+bool com_android_aconfig_test_enabled_rw() {
+    return com::android::aconfig::test::enabled_rw();
+}
+
+"#;
+
+    const PROD_SOURCE_FILE_EXPECTED_WITH_FINGERPRINT: &str = r#"
+#include "com_android_aconfig_test.h"
+
+#include <unistd.h>
+#include "aconfig_storage/aconfig_storage_read_api.hpp"
+#include <android/log.h>
+#define LOG_TAG "aconfig_cpp_codegen"
+#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
+#include <atomic>
+#include <vector>
+
+namespace com::android::aconfig::test {
+
+    class flag_provider : public flag_provider_interface {
+        public:
+
+            flag_provider()
+                : cache_(4)
+                , boolean_start_index_()
+                , flag_value_file_(nullptr)
+                , package_exists_in_storage_(true)
+                , fingerprint_matches_(true) {
+                for (size_t i = 0 ; i < 4; i++) {
+                    cache_[i] = -1;
+                }
 
                 auto package_map_file = aconfig_storage::get_mapped_file(
                     "system",
                     aconfig_storage::StorageFileType::package_map);
                 if (!package_map_file.ok()) {
+// Host doesn't have the package map file.
+#ifdef __ANDROID__
                     ALOGE("error: failed to get package map file: %s", package_map_file.error().c_str());
+#endif
                     package_exists_in_storage_ = false;
                     return;
                 }
@@ -574,6 +818,12 @@ namespace com::android::aconfig::test {
                     return;
                 }
 
+                if (context->fingerprint != 5801144784618221668ULL) {
+                    ALOGE("Fingerprint mismatch for package com.android.aconfig.test.");
+                    fingerprint_matches_ = false;
+                    return;
+                }
+
                 // cache package boolean flag start index
                 boolean_start_index_ = context->boolean_start_index;
 
@@ -601,8 +851,14 @@ namespace com::android::aconfig::test {
             }
 
             virtual bool disabled_rw() override {
-                if (cache_[0] == -1) {
+                if (cache_[0].load(std::memory_order_relaxed) == -1) {
                     if (!package_exists_in_storage_) {
+                        ALOGE("error: package does not exist, returning flag default value.");
+                        return false;
+                    }
+
+                    if (!fingerprint_matches_) {
+                        ALOGE("error: package fingerprint mismtach, returning flag default value.");
                         return false;
                     }
 
@@ -615,17 +871,24 @@ namespace com::android::aconfig::test {
                         return false;
                     }
 
-                    cache_[0] = *value;
+                    cache_[0].store(*value, std::memory_order_relaxed);
                 }
-                return cache_[0];
+                return cache_[0].load(std::memory_order_relaxed);
             }
 
             virtual bool disabled_rw_exported() override {
-                if (cache_[1] == -1) {
+                if (cache_[1].load(std::memory_order_relaxed) == -1) {
                     if (!package_exists_in_storage_) {
+                        ALOGE("error: package does not exist, returning flag default value.");
                         return false;
                     }
 
+
+                    if (!fingerprint_matches_) {
+                      ALOGE("error: package fingerprint mismtach, returning flag default value.");
+                      return false;
+                    }
+
                     auto value = aconfig_storage::get_boolean_flag_value(
                         *flag_value_file_,
                         boolean_start_index_ + 1);
@@ -635,17 +898,24 @@ namespace com::android::aconfig::test {
                         return false;
                     }
 
-                    cache_[1] = *value;
+                    cache_[1].store(*value, std::memory_order_relaxed);
                 }
-                return cache_[1];
+                return cache_[1].load(std::memory_order_relaxed);
             }
 
             virtual bool disabled_rw_in_other_namespace() override {
-                if (cache_[2] == -1) {
+                if (cache_[2].load(std::memory_order_relaxed) == -1) {
                     if (!package_exists_in_storage_) {
+                        ALOGE("error: package does not exist, returning flag default value.");
                         return false;
                     }
 
+
+                    if (!fingerprint_matches_) {
+                      ALOGE("error: package fingerprint mismtach, returning flag default value.");
+                      return false;
+                    }
+
                     auto value = aconfig_storage::get_boolean_flag_value(
                         *flag_value_file_,
                         boolean_start_index_ + 2);
@@ -655,9 +925,9 @@ namespace com::android::aconfig::test {
                         return false;
                     }
 
-                    cache_[2] = *value;
+                    cache_[2].store(*value, std::memory_order_relaxed);
                 }
-                return cache_[2];
+                return cache_[2].load(std::memory_order_relaxed);
             }
 
             virtual bool enabled_fixed_ro() override {
@@ -677,11 +947,18 @@ namespace com::android::aconfig::test {
             }
 
             virtual bool enabled_rw() override {
-                if (cache_[3] == -1) {
+                if (cache_[3].load(std::memory_order_relaxed) == -1) {
                     if (!package_exists_in_storage_) {
+                        ALOGE("error: package does not exist, returning flag default value.");
                         return true;
                     }
 
+
+                    if (!fingerprint_matches_) {
+                      ALOGE("error: package fingerprint mismtach, returning flag default value.");
+                      return true;
+                    }
+
                     auto value = aconfig_storage::get_boolean_flag_value(
                         *flag_value_file_,
                         boolean_start_index_ + 7);
@@ -691,19 +968,21 @@ namespace com::android::aconfig::test {
                         return true;
                     }
 
-                    cache_[3] = *value;
+                    cache_[3].store(*value, std::memory_order_relaxed);
                 }
-                return cache_[3];
+                return cache_[3].load(std::memory_order_relaxed);
             }
 
     private:
-        std::vector<int8_t> cache_ = std::vector<int8_t>(4, -1);
+        std::vector<std::atomic_int8_t> cache_;
 
         uint32_t boolean_start_index_;
 
         std::unique_ptr<aconfig_storage::MappedStorageFile> flag_value_file_;
 
         bool package_exists_in_storage_;
+
+        bool fingerprint_matches_;
     };
 
     std::unique_ptr<flag_provider_interface> provider_ =
@@ -784,7 +1063,10 @@ namespace com::android::aconfig::test {
                     aconfig_storage::StorageFileType::package_map);
 
                 if (!package_map_file.ok()) {
+// Host doesn't have the package map file.
+#ifdef __ANDROID__
                     ALOGE("error: failed to get package map file: %s", package_map_file.error().c_str());
+#endif
                     package_exists_in_storage_ = false;
                     return;
                 }
@@ -843,6 +1125,7 @@ namespace com::android::aconfig::test {
                       return it->second;
                 } else {
                     if (!package_exists_in_storage_) {
+                        ALOGE("error: package does not exist, returning flag default value.");
                         return false;
                     }
 
@@ -869,6 +1152,7 @@ namespace com::android::aconfig::test {
                       return it->second;
                 } else {
                     if (!package_exists_in_storage_) {
+                        ALOGE("error: package does not exist, returning flag default value.");
                         return false;
                     }
 
@@ -895,6 +1179,7 @@ namespace com::android::aconfig::test {
                       return it->second;
                 } else {
                     if (!package_exists_in_storage_) {
+                        ALOGE("error: package does not exist, returning flag default value.");
                         return false;
                     }
 
@@ -973,6 +1258,7 @@ namespace com::android::aconfig::test {
                       return it->second;
                 } else {
                     if (!package_exists_in_storage_) {
+                        ALOGE("error: package does not exist, returning flag default value.");
                         return true;
                     }
 
@@ -1274,16 +1560,19 @@ bool com_android_aconfig_test_enabled_ro() {
         mode: CodegenMode,
         expected_header: &str,
         expected_src: &str,
+        with_fingerprint: bool,
     ) {
         let modified_parsed_flags =
             crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
         let flag_ids =
             assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let package_fingerprint = if with_fingerprint { Some(5801144784618221668) } else { None };
         let generated = generate_cpp_code(
             crate::test::TEST_PACKAGE,
             modified_parsed_flags.into_iter(),
             mode,
             flag_ids,
+            package_fingerprint,
         )
         .unwrap();
         let mut generated_files_map = HashMap::new();
@@ -1306,12 +1595,9 @@ bool com_android_aconfig_test_enabled_ro() {
 
         target_file_path = String::from("com_android_aconfig_test.cc");
         assert!(generated_files_map.contains_key(&target_file_path));
-        assert_eq!(
-            None,
-            crate::test::first_significant_code_diff(
-                expected_src,
-                generated_files_map.get(&target_file_path).unwrap()
-            )
+        crate::test::assert_no_significant_code_diff(
+            expected_src,
+            generated_files_map.get(&target_file_path).unwrap(),
         );
     }
 
@@ -1323,6 +1609,19 @@ bool com_android_aconfig_test_enabled_ro() {
             CodegenMode::Production,
             EXPORTED_PROD_HEADER_EXPECTED,
             PROD_SOURCE_FILE_EXPECTED,
+            false,
+        );
+    }
+
+    #[test]
+    fn test_generate_cpp_code_for_prod_with_fingerprint() {
+        let parsed_flags = crate::test::parse_test_flags();
+        test_generate_cpp_code(
+            parsed_flags,
+            CodegenMode::Production,
+            EXPORTED_PROD_HEADER_EXPECTED,
+            PROD_SOURCE_FILE_EXPECTED_WITH_FINGERPRINT,
+            true,
         );
     }
 
@@ -1334,6 +1633,7 @@ bool com_android_aconfig_test_enabled_ro() {
             CodegenMode::Test,
             EXPORTED_TEST_HEADER_EXPECTED,
             TEST_SOURCE_FILE_EXPECTED,
+            false,
         );
     }
 
@@ -1345,6 +1645,7 @@ bool com_android_aconfig_test_enabled_ro() {
             CodegenMode::ForceReadOnly,
             EXPORTED_FORCE_READ_ONLY_HEADER_EXPECTED,
             FORCE_READ_ONLY_SOURCE_FILE_EXPECTED,
+            false,
         );
     }
 
@@ -1356,6 +1657,7 @@ bool com_android_aconfig_test_enabled_ro() {
             CodegenMode::Production,
             READ_ONLY_EXPORTED_PROD_HEADER_EXPECTED,
             READ_ONLY_PROD_SOURCE_FILE_EXPECTED,
+            false,
         );
     }
 }
diff --git a/tools/aconfig/aconfig/src/codegen/java.rs b/tools/aconfig/aconfig/src/codegen/java.rs
index e9c95fd766..0645f66ab8 100644
--- a/tools/aconfig/aconfig/src/codegen/java.rs
+++ b/tools/aconfig/aconfig/src/codegen/java.rs
@@ -14,28 +14,29 @@
 * limitations under the License.
 */
 
-use anyhow::Result;
+use anyhow::{ensure, Result};
 use serde::Serialize;
 use std::collections::{BTreeMap, BTreeSet};
 use std::path::PathBuf;
 use tinytemplate::TinyTemplate;
 
-use crate::codegen;
-use crate::codegen::CodegenMode;
-use crate::commands::{should_include_flag, OutputFile};
-use aconfig_protos::{ProtoFlagPermission, ProtoFlagState, ProtoParsedFlag};
-use convert_finalized_flags::{FinalizedFlag, FinalizedFlagMap};
+use crate::codegen::{self, get_flag_offset_in_storage_file, CodegenMode};
+use crate::commands::OutputFile;
+use aconfig_protos::{
+    ProtoFlagPermission, ProtoFlagState, ProtoFlagStorageBackend, ProtoParsedFlag,
+};
+use convert_finalized_flags::{ApiLevel, FinalizedFlag, FinalizedFlagMap};
 use std::collections::HashMap;
 
 // Arguments to configure codegen for generate_java_code.
 pub struct JavaCodegenConfig {
     pub codegen_mode: CodegenMode,
     pub flag_ids: HashMap<String, u16>,
-    pub allow_instrumentation: bool,
     pub package_fingerprint: u64,
-    pub new_exported: bool,
     pub single_exported_file: bool,
     pub finalized_flags: FinalizedFlagMap,
+    // Whether to add the "@UnsupportedAppUsage" (UAU) annotation in the generated code.
+    pub support_uau_annotation: bool,
 }
 
 pub fn generate_java_code<I>(
@@ -46,11 +47,21 @@ pub fn generate_java_code<I>(
 where
     I: Iterator<Item = ProtoParsedFlag>,
 {
+    let mut use_device_config = false;
+    let mut use_aconfigd = false;
     let flag_elements: Vec<FlagElement> = parsed_flags_iter
         .map(|pf| {
+            use_device_config |= pf.metadata.storage() == ProtoFlagStorageBackend::DEVICE_CONFIG;
+            use_aconfigd |= pf.metadata.storage() == ProtoFlagStorageBackend::ACONFIGD;
+            ensure!(
+                !(use_device_config && use_aconfigd),
+                "Package {} cannot contain both device_config and new storage stored flags",
+                package
+            );
+
             create_flag_element(package, &pf, config.flag_ids.clone(), &config.finalized_flags)
         })
-        .collect();
+        .collect::<Result<Vec<FlagElement>>>()?;
     let namespace_flags = gen_flags_by_namespace(&flag_elements);
     let properties_set: BTreeSet<String> =
         flag_elements.iter().map(|fe| format_property_name(&fe.device_config_namespace)).collect();
@@ -69,12 +80,12 @@ where
         properties_set,
         package_name: package.to_string(),
         library_exported,
-        allow_instrumentation: config.allow_instrumentation,
         container,
         is_platform_container,
         package_fingerprint: format!("0x{:X}L", config.package_fingerprint),
-        new_exported: config.new_exported,
         single_exported_file: config.single_exported_file,
+        use_device_config,
+        support_uau_annotation: config.support_uau_annotation,
     };
     let mut template = TinyTemplate::new();
     if library_exported && config.single_exported_file {
@@ -82,6 +93,15 @@ where
             "ExportedFlags.java",
             include_str!("../../templates/ExportedFlags.java.template"),
         )?;
+    } else {
+        template.add_template(
+            "CustomFeatureFlags.java",
+            include_str!("../../templates/CustomFeatureFlags.java.template"),
+        )?;
+        template.add_template(
+            "FakeFeatureFlagsImpl.java",
+            include_str!("../../templates/FakeFeatureFlagsImpl.java.template"),
+        )?;
     }
     template.add_template("Flags.java", include_str!("../../templates/Flags.java.template"))?;
     add_feature_flags_impl_template(&context, &mut template)?;
@@ -89,25 +109,14 @@ where
         "FeatureFlags.java",
         include_str!("../../templates/FeatureFlags.java.template"),
     )?;
-    template.add_template(
-        "CustomFeatureFlags.java",
-        include_str!("../../templates/CustomFeatureFlags.java.template"),
-    )?;
-    template.add_template(
-        "FakeFeatureFlagsImpl.java",
-        include_str!("../../templates/FakeFeatureFlagsImpl.java.template"),
-    )?;
 
     let path: PathBuf = package.split('.').collect();
-    let mut files = vec![
-        "Flags.java",
-        "FeatureFlags.java",
-        "FeatureFlagsImpl.java",
-        "CustomFeatureFlags.java",
-        "FakeFeatureFlagsImpl.java",
-    ];
+    let mut files = vec!["Flags.java", "FeatureFlags.java", "FeatureFlagsImpl.java"];
     if library_exported && config.single_exported_file {
         files.push("ExportedFlags.java");
+    } else {
+        files.push("CustomFeatureFlags.java");
+        files.push("FakeFeatureFlagsImpl.java");
     }
     files
         .iter()
@@ -150,12 +159,12 @@ struct Context {
     pub properties_set: BTreeSet<String>,
     pub package_name: String,
     pub library_exported: bool,
-    pub allow_instrumentation: bool,
     pub container: String,
     pub is_platform_container: bool,
     pub package_fingerprint: String,
-    pub new_exported: bool,
     pub single_exported_file: bool,
+    pub use_device_config: bool,
+    pub support_uau_annotation: bool,
 }
 
 #[derive(Serialize, Debug)]
@@ -177,61 +186,44 @@ struct FlagElement {
     pub method_name: String,
     pub properties: String,
     pub finalized_sdk_present: bool,
-    pub finalized_sdk_value: i32,
+    pub finalized_sdk_check: String,
 }
 
 fn create_flag_element(
     package: &str,
     pf: &ProtoParsedFlag,
-    flag_offsets: HashMap<String, u16>,
+    flag_ids: HashMap<String, u16>,
     finalized_flags: &FinalizedFlagMap,
-) -> FlagElement {
+) -> Result<FlagElement> {
     let device_config_flag = codegen::create_device_config_ident(package, pf.name())
         .expect("values checked at flag parse time");
 
-    let no_assigned_offset = !should_include_flag(pf);
-
-    let flag_offset = match flag_offsets.get(pf.name()) {
-        Some(offset) => offset,
-        None => {
-            // System/vendor/product RO+disabled flags have no offset in storage files.
-            // Assign placeholder value.
-            if no_assigned_offset {
-                &0
-            }
-            // All other flags _must_ have an offset.
-            else {
-                panic!("{}", format!("missing flag offset for {}", pf.name()));
-            }
-        }
-    };
-
     // An empty map is provided if check_api_level is disabled.
-    let mut finalized_sdk_present: bool = false;
-    let mut finalized_sdk_value: i32 = 0;
-    if !finalized_flags.is_empty() {
+    let (finalized_sdk_present, finalized_sdk_value) = if !finalized_flags.is_empty() {
         let finalized_sdk = finalized_flags.get_finalized_level(&FinalizedFlag {
             flag_name: pf.name().to_string(),
             package_name: package.to_string(),
         });
-        finalized_sdk_present = finalized_sdk.is_some();
-        finalized_sdk_value = finalized_sdk.map(|f| f.0).unwrap_or_default();
-    }
+        (finalized_sdk.is_some(), finalized_sdk.unwrap_or(ApiLevel(0)))
+    } else {
+        (false, ApiLevel(0))
+    };
+    let finalized_sdk_check = finalized_sdk_value.conditional();
 
-    FlagElement {
+    Ok(FlagElement {
         container: pf.container().to_string(),
         default_value: pf.state() == ProtoFlagState::ENABLED,
         device_config_namespace: pf.namespace().to_string(),
         device_config_flag,
         flag_name: pf.name().to_string(),
         flag_name_constant_suffix: pf.name().to_ascii_uppercase(),
-        flag_offset: *flag_offset,
+        flag_offset: get_flag_offset_in_storage_file(&flag_ids, pf)?,
         is_read_write: pf.permission() == ProtoFlagPermission::READ_WRITE,
         method_name: format_java_method_name(pf.name()),
         properties: format_property_name(pf.namespace()),
         finalized_sdk_present,
-        finalized_sdk_value,
-    }
+        finalized_sdk_check,
+    })
 }
 
 fn format_java_method_name(flag_name: &str) -> String {
@@ -260,10 +252,7 @@ fn format_property_name(property_name: &str) -> String {
     format!("mProperties{}{}", &name[0..1].to_ascii_uppercase(), &name[1..])
 }
 
-fn add_feature_flags_impl_template(
-    context: &Context,
-    template: &mut TinyTemplate,
-) -> Result<(), tinytemplate::error::Error> {
+fn add_feature_flags_impl_template(context: &Context, template: &mut TinyTemplate) -> Result<()> {
     if context.is_test_mode {
         // Test mode has its own template, so use regardless of any other settings.
         template.add_template(
@@ -273,41 +262,35 @@ fn add_feature_flags_impl_template(
         return Ok(());
     }
 
-    match (context.library_exported, context.new_exported, context.allow_instrumentation) {
+    match context.library_exported {
         // Exported library with new_exported enabled, use new storage exported template.
-        (true, true, _) => {
+        true => {
+            ensure!(
+                !context.use_device_config,
+                "All exported mode codegen should rely on new storage for safety"
+            );
             template.add_template(
                 "FeatureFlagsImpl.java",
                 include_str!("../../templates/FeatureFlagsImpl.exported.java.template"),
             )?;
         }
-
-        // Exported library with new_exported NOT enabled, use legacy (device
-        // config) template, because regardless of allow_instrumentation, we use
-        // device config for exported libs if new_exported isn't enabled.
-        // Remove once new_exported is fully rolled out.
-        (true, false, _) => {
-            template.add_template(
-                "FeatureFlagsImpl.java",
-                include_str!("../../templates/FeatureFlagsImpl.deviceConfig.java.template"),
-            )?;
-        }
-
         // New storage internal mode.
-        (false, _, true) => {
-            template.add_template(
-                "FeatureFlagsImpl.java",
-                include_str!("../../templates/FeatureFlagsImpl.new_storage.java.template"),
-            )?;
-        }
-
-        // Device config internal mode. Use legacy (device config) template.
-        (false, _, false) => {
-            template.add_template(
-                "FeatureFlagsImpl.java",
-                include_str!("../../templates/FeatureFlagsImpl.deviceConfig.java.template"),
-            )?;
-        }
+        false => match context.use_device_config {
+            true => {
+                template.add_template(
+                    "FeatureFlagsImpl.java",
+                    include_str!(
+                        "../../templates/FeatureFlagsImpl.legacy_flag.internal.java.template"
+                    ),
+                )?;
+            }
+            false => {
+                template.add_template(
+                    "FeatureFlagsImpl.java",
+                    include_str!("../../templates/FeatureFlagsImpl.new_storage.java.template"),
+                )?;
+            }
+        },
     };
     Ok(())
 }
@@ -322,49 +305,36 @@ mod tests {
 
     const EXPECTED_FEATUREFLAGS_COMMON_CONTENT: &str = r#"
     package com.android.aconfig.test;
-    // TODO(b/303773055): Remove the annotation after access issue is resolved.
-    import android.compat.annotation.UnsupportedAppUsage;
     /** @hide */
     public interface FeatureFlags {
         @com.android.aconfig.annotations.AssumeFalseForR8
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         boolean disabledRo();
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         boolean disabledRw();
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         boolean disabledRwExported();
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         boolean disabledRwInOtherNamespace();
         @com.android.aconfig.annotations.AssumeTrueForR8
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         boolean enabledFixedRo();
         @com.android.aconfig.annotations.AssumeTrueForR8
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         boolean enabledFixedRoExported();
         @com.android.aconfig.annotations.AssumeTrueForR8
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         boolean enabledRo();
         @com.android.aconfig.annotations.AssumeTrueForR8
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         boolean enabledRoExported();
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         boolean enabledRw();
     }
     "#;
 
     const EXPECTED_FLAG_COMMON_CONTENT: &str = r#"
     package com.android.aconfig.test;
-    // TODO(b/303773055): Remove the annotation after access issue is resolved.
-    import android.compat.annotation.UnsupportedAppUsage;
     /** @hide */
     public final class Flags {
         /** @hide */
@@ -388,51 +358,42 @@ mod tests {
 
         @com.android.aconfig.annotations.AssumeFalseForR8
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         public static boolean disabledRo() {
             return FEATURE_FLAGS.disabledRo();
         }
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         public static boolean disabledRw() {
             return FEATURE_FLAGS.disabledRw();
         }
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         public static boolean disabledRwExported() {
             return FEATURE_FLAGS.disabledRwExported();
         }
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         public static boolean disabledRwInOtherNamespace() {
             return FEATURE_FLAGS.disabledRwInOtherNamespace();
         }
         @com.android.aconfig.annotations.AssumeTrueForR8
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         public static boolean enabledFixedRo() {
             return FEATURE_FLAGS.enabledFixedRo();
         }
         @com.android.aconfig.annotations.AssumeTrueForR8
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         public static boolean enabledFixedRoExported() {
             return FEATURE_FLAGS.enabledFixedRoExported();
         }
         @com.android.aconfig.annotations.AssumeTrueForR8
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         public static boolean enabledRo() {
             return FEATURE_FLAGS.enabledRo();
         }
         @com.android.aconfig.annotations.AssumeTrueForR8
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         public static boolean enabledRoExported() {
             return FEATURE_FLAGS.enabledRoExported();
         }
         @com.android.aconfig.annotations.AconfigFlagAccessor
-        @UnsupportedAppUsage
         public static boolean enabledRw() {
             return FEATURE_FLAGS.enabledRw();
         }
@@ -440,9 +401,6 @@ mod tests {
 
     const EXPECTED_CUSTOMFEATUREFLAGS_CONTENT: &str = r#"
     package com.android.aconfig.test;
-
-    // TODO(b/303773055): Remove the annotation after access issue is resolved.
-    import android.compat.annotation.UnsupportedAppUsage;
     import java.util.Arrays;
     import java.util.HashSet;
     import java.util.List;
@@ -460,55 +418,46 @@ mod tests {
         }
 
         @Override
-        @UnsupportedAppUsage
         public boolean disabledRo() {
             return getValue(Flags.FLAG_DISABLED_RO,
                     FeatureFlags::disabledRo);
         }
         @Override
-        @UnsupportedAppUsage
         public boolean disabledRw() {
             return getValue(Flags.FLAG_DISABLED_RW,
                 FeatureFlags::disabledRw);
         }
         @Override
-        @UnsupportedAppUsage
         public boolean disabledRwExported() {
             return getValue(Flags.FLAG_DISABLED_RW_EXPORTED,
                 FeatureFlags::disabledRwExported);
         }
         @Override
-        @UnsupportedAppUsage
         public boolean disabledRwInOtherNamespace() {
             return getValue(Flags.FLAG_DISABLED_RW_IN_OTHER_NAMESPACE,
                 FeatureFlags::disabledRwInOtherNamespace);
         }
         @Override
-        @UnsupportedAppUsage
         public boolean enabledFixedRo() {
             return getValue(Flags.FLAG_ENABLED_FIXED_RO,
                 FeatureFlags::enabledFixedRo);
         }
         @Override
-        @UnsupportedAppUsage
         public boolean enabledFixedRoExported() {
             return getValue(Flags.FLAG_ENABLED_FIXED_RO_EXPORTED,
                 FeatureFlags::enabledFixedRoExported);
         }
         @Override
-        @UnsupportedAppUsage
         public boolean enabledRo() {
             return getValue(Flags.FLAG_ENABLED_RO,
                 FeatureFlags::enabledRo);
         }
         @Override
-        @UnsupportedAppUsage
         public boolean enabledRoExported() {
             return getValue(Flags.FLAG_ENABLED_RO_EXPORTED,
                 FeatureFlags::enabledRoExported);
         }
         @Override
-        @UnsupportedAppUsage
         public boolean enabledRw() {
             return getValue(Flags.FLAG_ENABLED_RW,
                 FeatureFlags::enabledRw);
@@ -610,38 +559,8 @@ mod tests {
     }
     "#;
 
-    #[test]
-    fn test_generate_java_code_production() {
-        let parsed_flags = crate::test::parse_test_flags();
-        let mode = CodegenMode::Production;
-        let modified_parsed_flags =
-            crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
-        let flag_ids =
-            assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
-        let config = JavaCodegenConfig {
-            codegen_mode: mode,
-            flag_ids,
-            allow_instrumentation: true,
-            package_fingerprint: 5801144784618221668,
-            new_exported: false,
-            single_exported_file: false,
-            finalized_flags: FinalizedFlagMap::new(),
-        };
-        let generated_files = generate_java_code(
-            crate::test::TEST_PACKAGE,
-            modified_parsed_flags.into_iter(),
-            config,
-        )
-        .unwrap();
-        let expect_flags_content = EXPECTED_FLAG_COMMON_CONTENT.to_string()
-            + r#"
-            private static FeatureFlags FEATURE_FLAGS = new FeatureFlagsImpl();
-        }"#;
-
-        let expected_featureflagsmpl_content = r#"
+    const EXPECTED_NEW_STORAGE_FEATUREFLAGSIMPL_CONTENT: &str = r#"
         package com.android.aconfig.test;
-        // TODO(b/303773055): Remove the annotation after access issue is resolved.
-        import android.compat.annotation.UnsupportedAppUsage;
         import android.os.flagging.PlatformAconfigPackageInternal;
         import android.util.Log;
         /** @hide */
@@ -671,14 +590,12 @@ mod tests {
 
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public boolean disabledRo() {
+                public boolean disabledRo() {
                 return false;
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public boolean disabledRw() {
+                public boolean disabledRw() {
                 if (!isCached) {
                     init();
                 }
@@ -686,8 +603,7 @@ mod tests {
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public boolean disabledRwExported() {
+                public boolean disabledRwExported() {
                 if (!isCached) {
                     init();
                 }
@@ -695,8 +611,7 @@ mod tests {
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public boolean disabledRwInOtherNamespace() {
+                public boolean disabledRwInOtherNamespace() {
                 if (!isCached) {
                     init();
                 }
@@ -704,43 +619,177 @@ mod tests {
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
+                public boolean enabledFixedRo() {
+                return true;
+            }
+            @Override
+            @com.android.aconfig.annotations.AconfigFlagAccessor
+                public boolean enabledFixedRoExported() {
+                return true;
+            }
+            @Override
+            @com.android.aconfig.annotations.AconfigFlagAccessor
+                public boolean enabledRo() {
+                return true;
+            }
+            @Override
+            @com.android.aconfig.annotations.AconfigFlagAccessor
+                public boolean enabledRoExported() {
+                return true;
+            }
+            @Override
+            @com.android.aconfig.annotations.AconfigFlagAccessor
+                public boolean enabledRw() {
+                if (!isCached) {
+                    init();
+                }
+                return enabledRw;
+            }
+        }
+    "#;
+
+    const EXPECTED_MAINLINE_BETA_FEATUREFLAGSIMPL_CONTENT: &str = r#"
+        package com.android.aconfig.test;
+        import android.provider.DeviceConfig;
+        /** @hide */
+        public final class FeatureFlagsImpl implements FeatureFlags {
+            @Override
+            @com.android.aconfig.annotations.AconfigFlagAccessor
+            public boolean disabledRo() {
+                return false;
+            }
+            @Override
+            @com.android.aconfig.annotations.AconfigFlagAccessor
+            public boolean disabledRw() {
+                try {
+                    return DeviceConfig.getBoolean(
+                    "aconfig_test",
+                    Flags.FLAG_DISABLED_RW,
+                    false);
+                } catch (NullPointerException e) {
+                    throw new RuntimeException(
+                        "Cannot read value from namespace aconfig_test "
+                        + "from DeviceConfig. It could be that the code using flag "
+                        + "executed before SettingsProvider initialization. Please use "
+                        + "fixed read-only flag by adding is_fixed_read_only: true in "
+                        + "flag declaration.",
+                        e
+                    );
+                }
+            }
+            @Override
+            @com.android.aconfig.annotations.AconfigFlagAccessor
+            public boolean disabledRwExported() {
+                try {
+                    return DeviceConfig.getBoolean(
+                    "aconfig_test",
+                    Flags.FLAG_DISABLED_RW_EXPORTED,
+                    false);
+                } catch (NullPointerException e) {
+                    throw new RuntimeException(
+                        "Cannot read value from namespace aconfig_test "
+                        + "from DeviceConfig. It could be that the code using flag "
+                        + "executed before SettingsProvider initialization. Please use "
+                        + "fixed read-only flag by adding is_fixed_read_only: true in "
+                        + "flag declaration.",
+                        e
+                    );
+                }
+            }
+            @Override
+            @com.android.aconfig.annotations.AconfigFlagAccessor
+            public boolean disabledRwInOtherNamespace() {
+                try {
+                    return DeviceConfig.getBoolean(
+                    "other_namespace",
+                    Flags.FLAG_DISABLED_RW_IN_OTHER_NAMESPACE,
+                    false);
+                } catch (NullPointerException e) {
+                    throw new RuntimeException(
+                        "Cannot read value from namespace other_namespace "
+                        + "from DeviceConfig. It could be that the code using flag "
+                        + "executed before SettingsProvider initialization. Please use "
+                        + "fixed read-only flag by adding is_fixed_read_only: true in "
+                        + "flag declaration.",
+                        e
+                    );
+                }
+            }
+            @Override
+            @com.android.aconfig.annotations.AconfigFlagAccessor
             public boolean enabledFixedRo() {
                 return true;
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
             public boolean enabledFixedRoExported() {
                 return true;
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
             public boolean enabledRo() {
                 return true;
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
             public boolean enabledRoExported() {
                 return true;
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
             public boolean enabledRw() {
-                if (!isCached) {
-                    init();
+                try {
+                    return DeviceConfig.getBoolean(
+                    "aconfig_test",
+                    Flags.FLAG_ENABLED_RW,
+                    true);
+                } catch (NullPointerException e) {
+                    throw new RuntimeException(
+                        "Cannot read value from namespace aconfig_test "
+                        + "from DeviceConfig. It could be that the code using flag "
+                        + "executed before SettingsProvider initialization. Please use "
+                        + "fixed read-only flag by adding is_fixed_read_only: true in "
+                        + "flag declaration.",
+                        e
+                    );
                 }
-                return enabledRw;
             }
         }
-        "#;
+    "#;
+
+    #[test]
+    fn test_generate_java_code_production() {
+        let parsed_flags = crate::test::parse_test_flags();
+        let mode = CodegenMode::Production;
+        let modified_parsed_flags =
+            crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
+        let flag_ids =
+            assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let config = JavaCodegenConfig {
+            codegen_mode: mode,
+            flag_ids,
+            package_fingerprint: 5801144784618221668,
+            single_exported_file: false,
+            finalized_flags: FinalizedFlagMap::new(),
+            support_uau_annotation: false,
+        };
+        let generated_files = generate_java_code(
+            crate::test::TEST_PACKAGE,
+            modified_parsed_flags.into_iter(),
+            config,
+        )
+        .unwrap();
+        let expect_flags_content = EXPECTED_FLAG_COMMON_CONTENT.to_string()
+            + r#"
+            private static FeatureFlags FEATURE_FLAGS = new FeatureFlagsImpl();
+        }"#;
 
         let mut file_set = HashMap::from([
             ("com/android/aconfig/test/Flags.java", expect_flags_content.as_str()),
-            ("com/android/aconfig/test/FeatureFlagsImpl.java", expected_featureflagsmpl_content),
+            (
+                "com/android/aconfig/test/FeatureFlagsImpl.java",
+                EXPECTED_NEW_STORAGE_FEATUREFLAGSIMPL_CONTENT,
+            ),
             ("com/android/aconfig/test/FeatureFlags.java", EXPECTED_FEATUREFLAGS_COMMON_CONTENT),
             (
                 "com/android/aconfig/test/CustomFeatureFlags.java",
@@ -771,21 +820,30 @@ mod tests {
     }
 
     #[test]
-    fn test_generate_java_code_exported() {
+    fn test_generate_java_code_mainline_beta_production() {
         let parsed_flags = crate::test::parse_test_flags();
-        let mode = CodegenMode::Exported;
-        let modified_parsed_flags =
-            crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
+        let mode = CodegenMode::Production;
+        let modified_parsed_flags: Vec<_> =
+            crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode)
+                .unwrap()
+                .into_iter()
+                .map(|mut pf| {
+                    if pf.metadata.storage() == ProtoFlagStorageBackend::ACONFIGD {
+                        let m = pf.metadata.as_mut().unwrap();
+                        m.set_storage(ProtoFlagStorageBackend::DEVICE_CONFIG);
+                    }
+                    pf
+                })
+                .collect();
         let flag_ids =
             assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
         let config = JavaCodegenConfig {
             codegen_mode: mode,
             flag_ids,
-            allow_instrumentation: true,
             package_fingerprint: 5801144784618221668,
-            new_exported: false,
             single_exported_file: false,
             finalized_flags: FinalizedFlagMap::new(),
+            support_uau_annotation: false,
         };
         let generated_files = generate_java_code(
             crate::test::TEST_PACKAGE,
@@ -793,181 +851,21 @@ mod tests {
             config,
         )
         .unwrap();
-
-        let expect_flags_content = r#"
-        package com.android.aconfig.test;
-        import android.os.Build;
-        /** @hide */
-        public final class Flags {
-            /** @hide */
-            public static final String FLAG_DISABLED_RW_EXPORTED = "com.android.aconfig.test.disabled_rw_exported";
-            /** @hide */
-            public static final String FLAG_ENABLED_FIXED_RO_EXPORTED = "com.android.aconfig.test.enabled_fixed_ro_exported";
-            /** @hide */
-            public static final String FLAG_ENABLED_RO_EXPORTED = "com.android.aconfig.test.enabled_ro_exported";
-            public static boolean disabledRwExported() {
-                return FEATURE_FLAGS.disabledRwExported();
-            }
-            public static boolean enabledFixedRoExported() {
-                return FEATURE_FLAGS.enabledFixedRoExported();
-            }
-            public static boolean enabledRoExported() {
-                return FEATURE_FLAGS.enabledRoExported();
-            }
+        let expect_flags_content = EXPECTED_FLAG_COMMON_CONTENT.to_string()
+            + r#"
             private static FeatureFlags FEATURE_FLAGS = new FeatureFlagsImpl();
-        }
-        "#;
-
-        let expect_feature_flags_content = r#"
-        package com.android.aconfig.test;
-        /** @hide */
-        public interface FeatureFlags {
-            boolean disabledRwExported();
-            boolean enabledFixedRoExported();
-            boolean enabledRoExported();
-        }
-        "#;
-
-        let expect_feature_flags_impl_content = r#"
-        package com.android.aconfig.test;
-        import android.os.Binder;
-        import android.provider.DeviceConfig;
-        import android.provider.DeviceConfig.Properties;
-        /** @hide */
-        public final class FeatureFlagsImpl implements FeatureFlags {
-            private static volatile boolean aconfig_test_is_cached = false;
-            private static boolean disabledRwExported = false;
-            private static boolean enabledFixedRoExported = false;
-            private static boolean enabledRoExported = false;
-
-            private void load_overrides_aconfig_test() {
-                final long ident = Binder.clearCallingIdentity();
-                try {
-                    Properties properties = DeviceConfig.getProperties("aconfig_test");
-                    disabledRwExported =
-                        properties.getBoolean(Flags.FLAG_DISABLED_RW_EXPORTED, false);
-                    enabledFixedRoExported =
-                        properties.getBoolean(Flags.FLAG_ENABLED_FIXED_RO_EXPORTED, false);
-                    enabledRoExported =
-                        properties.getBoolean(Flags.FLAG_ENABLED_RO_EXPORTED, false);
-                } catch (NullPointerException e) {
-                    throw new RuntimeException(
-                        "Cannot read value from namespace aconfig_test "
-                        + "from DeviceConfig. It could be that the code using flag "
-                        + "executed before SettingsProvider initialization. Please use "
-                        + "fixed read-only flag by adding is_fixed_read_only: true in "
-                        + "flag declaration.",
-                        e
-                    );
-                } catch (SecurityException e) {
-                    // for isolated process case, skip loading flag value from the storage, use the default
-                } finally {
-                    Binder.restoreCallingIdentity(ident);
-                }
-                aconfig_test_is_cached = true;
-            }
-            @Override
-            public boolean disabledRwExported() {
-                if (!aconfig_test_is_cached) {
-                        load_overrides_aconfig_test();
-                }
-                return disabledRwExported;
-            }
-            @Override
-            public boolean enabledFixedRoExported() {
-                if (!aconfig_test_is_cached) {
-                        load_overrides_aconfig_test();
-                }
-                return enabledFixedRoExported;
-            }
-            @Override
-            public boolean enabledRoExported() {
-                if (!aconfig_test_is_cached) {
-                        load_overrides_aconfig_test();
-                }
-                return enabledRoExported;
-            }
         }"#;
 
-        let expect_custom_feature_flags_content = r#"
-        package com.android.aconfig.test;
-
-        import java.util.Arrays;
-        import java.util.HashMap;
-        import java.util.Map;
-        import java.util.HashSet;
-        import java.util.List;
-        import java.util.Set;
-        import java.util.function.BiPredicate;
-        import java.util.function.Predicate;
-
-        import android.os.Build;
-
-        /** @hide */
-        public class CustomFeatureFlags implements FeatureFlags {
-
-            private BiPredicate<String, Predicate<FeatureFlags>> mGetValueImpl;
-
-            public CustomFeatureFlags(BiPredicate<String, Predicate<FeatureFlags>> getValueImpl) {
-                mGetValueImpl = getValueImpl;
-            }
-
-            @Override
-            public boolean disabledRwExported() {
-                return getValue(Flags.FLAG_DISABLED_RW_EXPORTED,
-                    FeatureFlags::disabledRwExported);
-            }
-            @Override
-            public boolean enabledFixedRoExported() {
-                return getValue(Flags.FLAG_ENABLED_FIXED_RO_EXPORTED,
-                    FeatureFlags::enabledFixedRoExported);
-            }
-            @Override
-            public boolean enabledRoExported() {
-                return getValue(Flags.FLAG_ENABLED_RO_EXPORTED,
-                    FeatureFlags::enabledRoExported);
-            }
-
-            protected boolean getValue(String flagName, Predicate<FeatureFlags> getter) {
-                return mGetValueImpl.test(flagName, getter);
-            }
-
-            public List<String> getFlagNames() {
-                return Arrays.asList(
-                    Flags.FLAG_DISABLED_RW_EXPORTED,
-                    Flags.FLAG_ENABLED_FIXED_RO_EXPORTED,
-                    Flags.FLAG_ENABLED_RO_EXPORTED
-                );
-            }
-
-            private Set<String> mReadOnlyFlagsSet = new HashSet<>(
-                Arrays.asList(
-                    ""
-                )
-            );
-
-            private Map<String, Integer> mFinalizedFlags = new HashMap<>(
-                Map.ofEntries(
-                    Map.entry("", Integer.MAX_VALUE)
-                )
-            );
-
-            public boolean isFlagFinalized(String flagName) {
-                if (!mFinalizedFlags.containsKey(flagName)) {
-                    return false;
-                }
-                return Build.VERSION.SDK_INT >= mFinalizedFlags.get(flagName);
-            }
-        }
-    "#;
-
         let mut file_set = HashMap::from([
-            ("com/android/aconfig/test/Flags.java", expect_flags_content),
-            ("com/android/aconfig/test/FeatureFlags.java", expect_feature_flags_content),
-            ("com/android/aconfig/test/FeatureFlagsImpl.java", expect_feature_flags_impl_content),
+            ("com/android/aconfig/test/Flags.java", expect_flags_content.as_str()),
+            (
+                "com/android/aconfig/test/FeatureFlagsImpl.java",
+                EXPECTED_MAINLINE_BETA_FEATUREFLAGSIMPL_CONTENT,
+            ),
+            ("com/android/aconfig/test/FeatureFlags.java", EXPECTED_FEATUREFLAGS_COMMON_CONTENT),
             (
                 "com/android/aconfig/test/CustomFeatureFlags.java",
-                expect_custom_feature_flags_content,
+                EXPECTED_CUSTOMFEATUREFLAGS_CONTENT,
             ),
             (
                 "com/android/aconfig/test/FakeFeatureFlagsImpl.java",
@@ -978,14 +876,9 @@ mod tests {
         for file in generated_files {
             let file_path = file.path.to_str().unwrap();
             assert!(file_set.contains_key(file_path), "Cannot find {}", file_path);
-            assert_eq!(
-                None,
-                crate::test::first_significant_code_diff(
-                    file_set.get(file_path).unwrap(),
-                    &String::from_utf8(file.contents).unwrap()
-                ),
-                "File {} content is not correct",
-                file_path
+            crate::test::assert_no_significant_code_diff(
+                file_set.get(file_path).unwrap(),
+                &String::from_utf8(file.contents).unwrap(),
             );
             file_set.remove(file_path);
         }
@@ -1004,11 +897,10 @@ mod tests {
         let config = JavaCodegenConfig {
             codegen_mode: mode,
             flag_ids,
-            allow_instrumentation: true,
             package_fingerprint: 5801144784618221668,
-            new_exported: true,
             single_exported_file: false,
             finalized_flags: FinalizedFlagMap::new(),
+            support_uau_annotation: false,
         };
         let generated_files = generate_java_code(
             crate::test::TEST_PACKAGE,
@@ -1158,9 +1050,9 @@ mod tests {
                 )
             );
 
-            private Map<String, Integer> mFinalizedFlags = new HashMap<>(
+            private Map<String, Boolean> mFinalizedFlags = new HashMap<>(
                 Map.ofEntries(
-                    Map.entry("", Integer.MAX_VALUE)
+                    Map.entry("", false)
                 )
             );
 
@@ -1168,7 +1060,7 @@ mod tests {
                 if (!mFinalizedFlags.containsKey(flagName)) {
                     return false;
                 }
-                return Build.VERSION.SDK_INT >= mFinalizedFlags.get(flagName);
+                return mFinalizedFlags.get(flagName);
             }
         }
     "#;
@@ -1215,7 +1107,7 @@ mod tests {
             assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
         let mut finalized_flags = FinalizedFlagMap::new();
         finalized_flags.insert_if_new(
-            ApiLevel(36),
+            ApiLevel::from_sdk_int(36),
             FinalizedFlag {
                 flag_name: "disabled_rw_exported".to_string(),
                 package_name: "com.android.aconfig.test".to_string(),
@@ -1224,11 +1116,10 @@ mod tests {
         let config = JavaCodegenConfig {
             codegen_mode: mode,
             flag_ids,
-            allow_instrumentation: true,
             package_fingerprint: 5801144784618221668,
-            new_exported: true,
             single_exported_file: false,
             finalized_flags,
+            support_uau_annotation: false,
         };
         let generated_files = generate_java_code(
             crate::test::TEST_PACKAGE,
@@ -1381,10 +1272,10 @@ mod tests {
                 )
             );
 
-            private Map<String, Integer> mFinalizedFlags = new HashMap<>(
+            private Map<String, Boolean> mFinalizedFlags = new HashMap<>(
                 Map.ofEntries(
-                    Map.entry(Flags.FLAG_DISABLED_RW_EXPORTED, 36),
-                    Map.entry("", Integer.MAX_VALUE)
+                    Map.entry(Flags.FLAG_DISABLED_RW_EXPORTED, Build.VERSION.SDK_INT >= 36 ? true : false),
+                    Map.entry("", false)
                 )
             );
 
@@ -1392,7 +1283,7 @@ mod tests {
                 if (!mFinalizedFlags.containsKey(flagName)) {
                     return false;
                 }
-                return Build.VERSION.SDK_INT >= mFinalizedFlags.get(flagName);
+                return mFinalizedFlags.get(flagName);
             }
         }
     "#;
@@ -1441,7 +1332,7 @@ mod tests {
             assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
         let mut finalized_flags = FinalizedFlagMap::new();
         finalized_flags.insert_if_new(
-            ApiLevel(36),
+            ApiLevel::from_sdk_int(36),
             FinalizedFlag {
                 flag_name: "disabled_rw".to_string(),
                 package_name: "com.android.aconfig.test".to_string(),
@@ -1450,11 +1341,10 @@ mod tests {
         let config = JavaCodegenConfig {
             codegen_mode: mode,
             flag_ids,
-            allow_instrumentation: true,
             package_fingerprint: 5801144784618221668,
-            new_exported: true,
             single_exported_file: false,
             finalized_flags,
+            support_uau_annotation: false,
         };
         let generated_files = generate_java_code(
             crate::test::TEST_PACKAGE,
@@ -1490,11 +1380,10 @@ mod tests {
         let config = JavaCodegenConfig {
             codegen_mode: mode,
             flag_ids,
-            allow_instrumentation: true,
             package_fingerprint: 5801144784618221668,
-            new_exported: false,
             single_exported_file: false,
             finalized_flags: FinalizedFlagMap::new(),
+            support_uau_annotation: false,
         };
         let generated_files = generate_java_code(
             crate::test::TEST_PACKAGE,
@@ -1618,11 +1507,10 @@ mod tests {
         let config = JavaCodegenConfig {
             codegen_mode: mode,
             flag_ids,
-            allow_instrumentation: true,
             package_fingerprint: 5801144784618221668,
-            new_exported: false,
             single_exported_file: false,
             finalized_flags: FinalizedFlagMap::new(),
+            support_uau_annotation: false,
         };
         let generated_files = generate_java_code(
             crate::test::TEST_PACKAGE,
@@ -1632,76 +1520,60 @@ mod tests {
         .unwrap();
         let expect_featureflags_content = r#"
         package com.android.aconfig.test;
-        // TODO(b/303773055): Remove the annotation after access issue is resolved.
-        import android.compat.annotation.UnsupportedAppUsage;
         /** @hide */
         public interface FeatureFlags {
             @com.android.aconfig.annotations.AssumeFalseForR8
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            boolean disabledRo();
+                boolean disabledRo();
             @com.android.aconfig.annotations.AssumeFalseForR8
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            boolean disabledRw();
+                boolean disabledRw();
             @com.android.aconfig.annotations.AssumeFalseForR8
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            boolean disabledRwInOtherNamespace();
+                boolean disabledRwInOtherNamespace();
             @com.android.aconfig.annotations.AssumeTrueForR8
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            boolean enabledFixedRo();
+                boolean enabledFixedRo();
             @com.android.aconfig.annotations.AssumeTrueForR8
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            boolean enabledRo();
+                boolean enabledRo();
             @com.android.aconfig.annotations.AssumeTrueForR8
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            boolean enabledRw();
+                boolean enabledRw();
         }"#;
 
         let expect_featureflagsimpl_content = r#"
         package com.android.aconfig.test;
-        // TODO(b/303773055): Remove the annotation after access issue is resolved.
-        import android.compat.annotation.UnsupportedAppUsage;
         /** @hide */
         public final class FeatureFlagsImpl implements FeatureFlags {
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public boolean disabledRo() {
+                public boolean disabledRo() {
                 return false;
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public boolean disabledRw() {
+                public boolean disabledRw() {
                 return false;
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public boolean disabledRwInOtherNamespace() {
+                public boolean disabledRwInOtherNamespace() {
                 return false;
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public boolean enabledFixedRo() {
+                public boolean enabledFixedRo() {
                 return true;
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public boolean enabledRo() {
+                public boolean enabledRo() {
                 return true;
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public boolean enabledRw() {
+                public boolean enabledRw() {
                 return true;
             }
         }
@@ -1709,8 +1581,6 @@ mod tests {
 
         let expect_flags_content = r#"
         package com.android.aconfig.test;
-        // TODO(b/303773055): Remove the annotation after access issue is resolved.
-        import android.compat.annotation.UnsupportedAppUsage;
         /** @hide */
         public final class Flags {
             /** @hide */
@@ -1727,38 +1597,32 @@ mod tests {
             public static final String FLAG_ENABLED_RW = "com.android.aconfig.test.enabled_rw";
             @com.android.aconfig.annotations.AssumeFalseForR8
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public static boolean disabledRo() {
+                public static boolean disabledRo() {
                 return FEATURE_FLAGS.disabledRo();
             }
             @com.android.aconfig.annotations.AssumeFalseForR8
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public static boolean disabledRw() {
+                public static boolean disabledRw() {
                 return FEATURE_FLAGS.disabledRw();
             }
             @com.android.aconfig.annotations.AssumeFalseForR8
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public static boolean disabledRwInOtherNamespace() {
+                public static boolean disabledRwInOtherNamespace() {
                 return FEATURE_FLAGS.disabledRwInOtherNamespace();
             }
             @com.android.aconfig.annotations.AssumeTrueForR8
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public static boolean enabledFixedRo() {
+                public static boolean enabledFixedRo() {
                 return FEATURE_FLAGS.enabledFixedRo();
             }
             @com.android.aconfig.annotations.AssumeTrueForR8
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public static boolean enabledRo() {
+                public static boolean enabledRo() {
                 return FEATURE_FLAGS.enabledRo();
             }
             @com.android.aconfig.annotations.AssumeTrueForR8
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
-            public static boolean enabledRw() {
+                public static boolean enabledRw() {
                 return FEATURE_FLAGS.enabledRw();
             }
             private static FeatureFlags FEATURE_FLAGS = new FeatureFlagsImpl();
@@ -1767,8 +1631,6 @@ mod tests {
         let expect_customfeatureflags_content = r#"
         package com.android.aconfig.test;
 
-        // TODO(b/303773055): Remove the annotation after access issue is resolved.
-        import android.compat.annotation.UnsupportedAppUsage;
         import java.util.Arrays;
         import java.util.HashSet;
         import java.util.List;
@@ -1786,38 +1648,32 @@ mod tests {
             }
 
             @Override
-            @UnsupportedAppUsage
-            public boolean disabledRo() {
+                public boolean disabledRo() {
                 return getValue(Flags.FLAG_DISABLED_RO,
                         FeatureFlags::disabledRo);
             }
             @Override
-            @UnsupportedAppUsage
-            public boolean disabledRw() {
+                public boolean disabledRw() {
                 return getValue(Flags.FLAG_DISABLED_RW,
                     FeatureFlags::disabledRw);
             }
             @Override
-            @UnsupportedAppUsage
-            public boolean disabledRwInOtherNamespace() {
+                public boolean disabledRwInOtherNamespace() {
                 return getValue(Flags.FLAG_DISABLED_RW_IN_OTHER_NAMESPACE,
                     FeatureFlags::disabledRwInOtherNamespace);
             }
             @Override
-            @UnsupportedAppUsage
-            public boolean enabledFixedRo() {
+                public boolean enabledFixedRo() {
                 return getValue(Flags.FLAG_ENABLED_FIXED_RO,
                     FeatureFlags::enabledFixedRo);
             }
             @Override
-            @UnsupportedAppUsage
-            public boolean enabledRo() {
+                public boolean enabledRo() {
                 return getValue(Flags.FLAG_ENABLED_RO,
                     FeatureFlags::enabledRo);
             }
             @Override
-            @UnsupportedAppUsage
-            public boolean enabledRw() {
+                public boolean enabledRw() {
                 return getValue(Flags.FLAG_ENABLED_RW,
                     FeatureFlags::enabledRw);
             }
@@ -1903,7 +1759,7 @@ mod tests {
             assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
         let mut finalized_flags = FinalizedFlagMap::new();
         finalized_flags.insert_if_new(
-            ApiLevel(36),
+            ApiLevel::from_sdk_int(36),
             FinalizedFlag {
                 flag_name: "disabled_rw_exported".to_string(),
                 package_name: "com.android.aconfig.test".to_string(),
@@ -1912,11 +1768,10 @@ mod tests {
         let config = JavaCodegenConfig {
             codegen_mode: mode,
             flag_ids,
-            allow_instrumentation: true,
             package_fingerprint: 5801144784618221668,
-            new_exported: true,
             single_exported_file: true,
             finalized_flags,
+            support_uau_annotation: false,
         };
         let generated_files = generate_java_code(
             crate::test::TEST_PACKAGE,
@@ -1986,6 +1841,7 @@ mod tests {
         }"#;
 
         let file = generated_files.iter().find(|f| f.path.ends_with("ExportedFlags.java")).unwrap();
+        assert_eq!(4, generated_files.len());
         assert_eq!(
             None,
             crate::test::first_significant_code_diff(
@@ -1996,6 +1852,39 @@ mod tests {
         );
     }
 
+    #[test]
+    fn test_mix_device_config_and_new_storage_flags() {
+        let mut parsed_flags = crate::test::parse_test_flags();
+        parsed_flags.parsed_flag[0].set_permission(ProtoFlagPermission::READ_WRITE);
+        let m = parsed_flags.parsed_flag[0].metadata.as_mut().unwrap();
+        m.set_storage(ProtoFlagStorageBackend::DEVICE_CONFIG);
+        parsed_flags.parsed_flag[1].set_permission(ProtoFlagPermission::READ_WRITE);
+        let m = parsed_flags.parsed_flag[1].metadata.as_mut().unwrap();
+        m.set_storage(ProtoFlagStorageBackend::ACONFIGD);
+
+        let flag_ids =
+            assign_flag_ids(crate::test::TEST_PACKAGE, parsed_flags.parsed_flag.iter()).unwrap();
+
+        let config = JavaCodegenConfig {
+            codegen_mode: CodegenMode::Production,
+            flag_ids,
+            package_fingerprint: 5801144784618221668,
+            single_exported_file: false,
+            finalized_flags: FinalizedFlagMap::new(),
+            support_uau_annotation: false,
+        };
+        let error = generate_java_code(
+            crate::test::TEST_PACKAGE,
+            parsed_flags.parsed_flag.into_iter(),
+            config,
+        )
+        .unwrap_err();
+        assert_eq!(
+            format!("{:?}", error),
+            "Package com.android.aconfig.test cannot contain both device_config and new storage stored flags",
+        );
+    }
+
     #[test]
     fn test_format_java_method_name() {
         let expected = "someSnakeName";
diff --git a/tools/aconfig/aconfig/src/codegen/mod.rs b/tools/aconfig/aconfig/src/codegen/mod.rs
index 9ed66dbd03..df38d9194e 100644
--- a/tools/aconfig/aconfig/src/codegen/mod.rs
+++ b/tools/aconfig/aconfig/src/codegen/mod.rs
@@ -18,9 +18,12 @@ pub mod cpp;
 pub mod java;
 pub mod rust;
 
+use crate::commands::should_include_flag;
 use aconfig_protos::{is_valid_name_ident, is_valid_package_ident};
+use aconfig_protos::{ParsedFlagExt, ProtoParsedFlag};
 use anyhow::{ensure, Result};
 use clap::ValueEnum;
+use std::collections::HashMap;
 
 pub fn create_device_config_ident(package: &str, flag_name: &str) -> Result<String> {
     ensure!(is_valid_package_ident(package), "bad package");
@@ -28,6 +31,30 @@ pub fn create_device_config_ident(package: &str, flag_name: &str) -> Result<Stri
     Ok(format!("{}.{}", package, flag_name))
 }
 
+pub(crate) fn get_flag_offset_in_storage_file(
+    flag_ids: &HashMap<String, u16>,
+    pf: &ProtoParsedFlag,
+) -> Result<u16> {
+    match flag_ids.get(pf.name()) {
+        Some(offset) => {
+            ensure!(
+                should_include_flag(pf),
+                "flag {} should not have an assigned flag id in new storage file",
+                pf.fully_qualified_name()
+            );
+            Ok(*offset)
+        }
+        None => {
+            ensure!(
+                !should_include_flag(pf),
+                "flag {} should have an assigned flag id in new storage file",
+                pf.fully_qualified_name()
+            );
+            Ok(u16::MAX)
+        }
+    }
+}
+
 #[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
 pub enum CodegenMode {
     Exported,
@@ -50,6 +77,8 @@ impl std::fmt::Display for CodegenMode {
 #[cfg(test)]
 mod tests {
     use super::*;
+    use aconfig_protos::ProtoFlagPermission;
+
     #[test]
     fn test_create_device_config_ident() {
         assert_eq!(
@@ -57,4 +86,30 @@ mod tests {
             create_device_config_ident("com.foo.bar", "some_flag").unwrap()
         );
     }
+
+    #[test]
+    fn test_get_flag_offset_in_storage_file() {
+        let mut parsed_flags = crate::test::parse_test_flags();
+        let pf = parsed_flags.parsed_flag.iter_mut().find(|pf| pf.name() == "disabled_rw").unwrap();
+        let flag_ids = HashMap::from([(String::from("disabled_rw"), 0_u16)]);
+
+        assert_eq!(0_u16, get_flag_offset_in_storage_file(&flag_ids, pf).unwrap());
+
+        pf.set_permission(ProtoFlagPermission::READ_ONLY);
+        let error = get_flag_offset_in_storage_file(&flag_ids, pf).unwrap_err();
+        assert_eq!(
+            format!("{:?}", error),
+            "flag com.android.aconfig.test.disabled_rw should not have an assigned flag id in new storage file"
+        );
+
+        pf.set_name(String::from("enabled_rw"));
+        assert_eq!(u16::MAX, get_flag_offset_in_storage_file(&flag_ids, pf).unwrap());
+
+        pf.set_permission(ProtoFlagPermission::READ_WRITE);
+        let error = get_flag_offset_in_storage_file(&flag_ids, pf).unwrap_err();
+        assert_eq!(
+            format!("{:?}", error),
+            "flag com.android.aconfig.test.enabled_rw should have an assigned flag id in new storage file"
+        );
+    }
 }
diff --git a/tools/aconfig/aconfig/src/codegen/rust.rs b/tools/aconfig/aconfig/src/codegen/rust.rs
index 2ee5f36822..dcabdd42a5 100644
--- a/tools/aconfig/aconfig/src/codegen/rust.rs
+++ b/tools/aconfig/aconfig/src/codegen/rust.rs
@@ -14,38 +14,43 @@
  * limitations under the License.
  */
 
-use anyhow::Result;
+use anyhow::{ensure, Result};
 use serde::Serialize;
 use tinytemplate::TinyTemplate;
 
-use aconfig_protos::{ProtoFlagPermission, ProtoFlagState, ProtoParsedFlag};
+use aconfig_protos::{
+    ParsedFlagExt, ProtoFlagPermission, ProtoFlagState, ProtoFlagStorageBackend, ProtoParsedFlag,
+};
 
 use std::collections::HashMap;
 
-use crate::codegen;
-use crate::codegen::CodegenMode;
-use crate::commands::{should_include_flag, OutputFile};
+use crate::codegen::{self, get_flag_offset_in_storage_file, CodegenMode};
+use crate::commands::OutputFile;
 
 pub fn generate_rust_code<I>(
     package: &str,
     flag_ids: HashMap<String, u16>,
     parsed_flags_iter: I,
     codegen_mode: CodegenMode,
+    package_fingerprint: Option<u64>,
 ) -> Result<OutputFile>
 where
     I: Iterator<Item = ProtoParsedFlag>,
 {
-    let template_flags: Vec<TemplateParsedFlag> = parsed_flags_iter
+    let template_flags = parsed_flags_iter
         .map(|pf| TemplateParsedFlag::new(package, flag_ids.clone(), &pf))
-        .collect();
+        .collect::<Result<Vec<TemplateParsedFlag>>>()?;
     let has_readwrite = template_flags.iter().any(|item| item.readwrite);
     let container = (template_flags.first().expect("zero template flags").container).to_string();
+    let use_package_fingerprint = package_fingerprint.is_some();
     let context = TemplateContext {
         package: package.to_string(),
         template_flags,
         modules: package.split('.').map(|s| s.to_string()).collect::<Vec<_>>(),
         has_readwrite,
         container,
+        use_package_fingerprint,
+        package_fingerprint: package_fingerprint.unwrap_or_default(),
     };
     let mut template = TinyTemplate::new();
     template.add_template(
@@ -69,6 +74,8 @@ struct TemplateContext {
     pub modules: Vec<String>,
     pub has_readwrite: bool,
     pub container: String,
+    pub use_package_fingerprint: bool,
+    pub package_fingerprint: u64,
 }
 
 #[derive(Serialize)]
@@ -84,23 +91,13 @@ struct TemplateParsedFlag {
 
 impl TemplateParsedFlag {
     #[allow(clippy::nonminimal_bool)]
-    fn new(package: &str, flag_offsets: HashMap<String, u16>, pf: &ProtoParsedFlag) -> Self {
-        let flag_offset = match flag_offsets.get(pf.name()) {
-            Some(offset) => offset,
-            None => {
-                // System/vendor/product RO+disabled flags have no offset in storage files.
-                // Assign placeholder value.
-                if !should_include_flag(pf) {
-                    &0
-                }
-                // All other flags _must_ have an offset.
-                else {
-                    panic!("{}", format!("missing flag offset for {}", pf.name()));
-                }
-            }
-        };
-
-        Self {
+    fn new(package: &str, flag_ids: HashMap<String, u16>, pf: &ProtoParsedFlag) -> Result<Self> {
+        ensure!(
+            pf.metadata.storage() != ProtoFlagStorageBackend::DEVICE_CONFIG,
+            "device config storage backend cannot be used in native codegen for flag {}",
+            pf.fully_qualified_name()
+        );
+        Ok(Self {
             readwrite: pf.permission() == ProtoFlagPermission::READ_WRITE,
             default_value: match pf.state() {
                 ProtoFlagState::ENABLED => "true".to_string(),
@@ -108,11 +105,11 @@ impl TemplateParsedFlag {
             },
             name: pf.name().to_string(),
             container: pf.container().to_string(),
-            flag_offset: *flag_offset,
+            flag_offset: get_flag_offset_in_storage_file(&flag_ids, pf)?,
             device_config_namespace: pf.namespace().to_string(),
             device_config_flag: codegen::create_device_config_ident(package, pf.name())
                 .expect("values checked at flag parse time"),
-        }
+        })
     }
 }
 
@@ -131,10 +128,9 @@ use log::{log, LevelFilter, Level};
 /// flag provider
 pub struct FlagProvider;
 
-static PACKAGE_OFFSET: LazyLock<Result<Option<u32>, AconfigStorageError>> = LazyLock::new(|| unsafe {
+static PACKAGE_CONTEXT: LazyLock<Result<Option<PackageReadContext>, AconfigStorageError>> = LazyLock::new(|| unsafe {
     get_mapped_storage_file("system", StorageFileType::PackageMap)
     .and_then(|package_map| get_package_read_context(&package_map, "com.android.aconfig.test"))
-    .map(|context| context.map(|c| c.boolean_start_index))
 });
 
 static FLAG_VAL_MAP: LazyLock<Result<Mmap, AconfigStorageError>> = LazyLock::new(|| unsafe {
@@ -153,13 +149,13 @@ static CACHED_disabled_rw: LazyLock<bool> = LazyLock::new(|| {
         .as_ref()
         .map_err(|err| format!("failed to get flag val map: {err}"))
         .and_then(|flag_val_map| {
-            PACKAGE_OFFSET
-               .as_ref()
-               .map_err(|err| format!("failed to get package read offset: {err}"))
-               .and_then(|package_offset| {
-                   match package_offset {
-                       Some(offset) => {
-                           get_boolean_flag_value(&flag_val_map, offset + 0)
+            PACKAGE_CONTEXT
+              .as_ref()
+               .map_err(|err| format!("failed to get package read context: {err}"))
+               .and_then(|package_context| {
+                   match package_context {
+                       Some(context) => {
+                           get_boolean_flag_value(&flag_val_map, context.boolean_start_index + 0)
                                .map_err(|err| format!("failed to get flag: {err}"))
                        },
                        None => {
@@ -193,13 +189,13 @@ static CACHED_disabled_rw_exported: LazyLock<bool> = LazyLock::new(|| {
             .as_ref()
             .map_err(|err| format!("failed to get flag val map: {err}"))
             .and_then(|flag_val_map| {
-                PACKAGE_OFFSET
+                PACKAGE_CONTEXT
                     .as_ref()
-                    .map_err(|err| format!("failed to get package read offset: {err}"))
-                    .and_then(|package_offset| {
-                        match package_offset {
-                            Some(offset) => {
-                                get_boolean_flag_value(&flag_val_map, offset + 1)
+                .map_err(|err| format!("failed to get package read context: {err}"))
+                .and_then(|package_context| {
+                    match package_context {
+                        Some(context) => {
+                           get_boolean_flag_value(&flag_val_map, context.boolean_start_index + 1)
                                     .map_err(|err| format!("failed to get flag: {err}"))
                             },
                             None => {
@@ -233,13 +229,13 @@ static CACHED_disabled_rw_in_other_namespace: LazyLock<bool> = LazyLock::new(||
             .as_ref()
             .map_err(|err| format!("failed to get flag val map: {err}"))
             .and_then(|flag_val_map| {
-                PACKAGE_OFFSET
+                PACKAGE_CONTEXT
                     .as_ref()
-                    .map_err(|err| format!("failed to get package read offset: {err}"))
-                    .and_then(|package_offset| {
-                        match package_offset {
-                            Some(offset) => {
-                                get_boolean_flag_value(&flag_val_map, offset + 2)
+                .map_err(|err| format!("failed to get package read context: {err}"))
+                .and_then(|package_context| {
+                    match package_context {
+                        Some(context) => {
+                           get_boolean_flag_value(&flag_val_map, context.boolean_start_index + 2)
                                     .map_err(|err| format!("failed to get flag: {err}"))
                             },
                             None => {
@@ -274,14 +270,14 @@ static CACHED_enabled_rw: LazyLock<bool> = LazyLock::new(|| {
             .as_ref()
             .map_err(|err| format!("failed to get flag val map: {err}"))
             .and_then(|flag_val_map| {
-                PACKAGE_OFFSET
+                PACKAGE_CONTEXT
                     .as_ref()
-                    .map_err(|err| format!("failed to get package read offset: {err}"))
-                    .and_then(|package_offset| {
-                        match package_offset {
-                            Some(offset) => {
-                                get_boolean_flag_value(&flag_val_map, offset + 7)
-                                    .map_err(|err| format!("failed to get flag: {err}"))
+                    .map_err(|err| format!("failed to get package read context: {err}"))
+                    .and_then(|package_context| {
+                      match package_context {
+                            Some(context) => {
+                              get_boolean_flag_value(&flag_val_map, context.boolean_start_index + 7)
+                                      .map_err(|err| format!("failed to get flag: {err}"))
                             },
                             None => {
                                 log!(Level::Error, "no context found for package com.android.aconfig.test");
@@ -426,10 +422,9 @@ pub struct FlagProvider {
     overrides: BTreeMap<&'static str, bool>,
 }
 
-static PACKAGE_OFFSET: LazyLock<Result<Option<u32>, AconfigStorageError>> = LazyLock::new(|| unsafe {
+static PACKAGE_CONTEXT: LazyLock<Result<Option<PackageReadContext>, AconfigStorageError>> = LazyLock::new(|| unsafe {
     get_mapped_storage_file("system", StorageFileType::PackageMap)
     .and_then(|package_map| get_package_read_context(&package_map, "com.android.aconfig.test"))
-    .map(|context| context.map(|c| c.boolean_start_index))
 });
 
 static FLAG_VAL_MAP: LazyLock<Result<Mmap, AconfigStorageError>> = LazyLock::new(|| unsafe {
@@ -448,13 +443,13 @@ static CACHED_disabled_rw: LazyLock<bool> = LazyLock::new(|| {
         .as_ref()
         .map_err(|err| format!("failed to get flag val map: {err}"))
         .and_then(|flag_val_map| {
-            PACKAGE_OFFSET
+            PACKAGE_CONTEXT
                .as_ref()
-               .map_err(|err| format!("failed to get package read offset: {err}"))
-               .and_then(|package_offset| {
-                   match package_offset {
-                       Some(offset) => {
-                           get_boolean_flag_value(&flag_val_map, offset + 0)
+                    .map_err(|err| format!("failed to get package read context: {err}"))
+                    .and_then(|package_context| {
+                      match package_context {
+                            Some(context) => {
+                              get_boolean_flag_value(&flag_val_map, context.boolean_start_index + 0)
                                .map_err(|err| format!("failed to get flag: {err}"))
                        },
                        None => {
@@ -488,13 +483,13 @@ static CACHED_disabled_rw_exported: LazyLock<bool> = LazyLock::new(|| {
             .as_ref()
             .map_err(|err| format!("failed to get flag val map: {err}"))
             .and_then(|flag_val_map| {
-                PACKAGE_OFFSET
+                PACKAGE_CONTEXT
                     .as_ref()
-                    .map_err(|err| format!("failed to get package read offset: {err}"))
-                    .and_then(|package_offset| {
-                        match package_offset {
-                            Some(offset) => {
-                                get_boolean_flag_value(&flag_val_map, offset + 1)
+                    .map_err(|err| format!("failed to get package read context: {err}"))
+                    .and_then(|package_context| {
+                      match package_context {
+                            Some(context) => {
+                              get_boolean_flag_value(&flag_val_map, context.boolean_start_index + 1)
                                     .map_err(|err| format!("failed to get flag: {err}"))
                             },
                             None => {
@@ -528,13 +523,13 @@ static CACHED_disabled_rw_in_other_namespace: LazyLock<bool> = LazyLock::new(||
             .as_ref()
             .map_err(|err| format!("failed to get flag val map: {err}"))
             .and_then(|flag_val_map| {
-                PACKAGE_OFFSET
+                PACKAGE_CONTEXT
                     .as_ref()
-                    .map_err(|err| format!("failed to get package read offset: {err}"))
-                    .and_then(|package_offset| {
-                        match package_offset {
-                            Some(offset) => {
-                                get_boolean_flag_value(&flag_val_map, offset + 2)
+                    .map_err(|err| format!("failed to get package read context: {err}"))
+                    .and_then(|package_context| {
+                      match package_context {
+                            Some(context) => {
+                              get_boolean_flag_value(&flag_val_map, context.boolean_start_index + 2)
                                     .map_err(|err| format!("failed to get flag: {err}"))
                             },
                             None => {
@@ -569,13 +564,13 @@ static CACHED_enabled_rw: LazyLock<bool> = LazyLock::new(|| {
             .as_ref()
             .map_err(|err| format!("failed to get flag val map: {err}"))
             .and_then(|flag_val_map| {
-                PACKAGE_OFFSET
+                PACKAGE_CONTEXT
                     .as_ref()
-                    .map_err(|err| format!("failed to get package read offset: {err}"))
-                    .and_then(|package_offset| {
-                        match package_offset {
-                            Some(offset) => {
-                                get_boolean_flag_value(&flag_val_map, offset + 7)
+                    .map_err(|err| format!("failed to get package read context: {err}"))
+                    .and_then(|package_context| {
+                      match package_context {
+                            Some(context) => {
+                              get_boolean_flag_value(&flag_val_map, context.boolean_start_index + 7)
                                     .map_err(|err| format!("failed to get flag: {err}"))
                             },
                             None => {
@@ -926,15 +921,13 @@ pub fn enabled_rw() -> bool {
             flag_ids,
             modified_parsed_flags.into_iter(),
             mode,
+            None,
         )
         .unwrap();
         assert_eq!("src/lib.rs", format!("{}", generated.path.display()));
-        assert_eq!(
-            None,
-            crate::test::first_significant_code_diff(
-                expected,
-                &String::from_utf8(generated.contents).unwrap()
-            )
+        crate::test::assert_no_significant_code_diff(
+            expected,
+            &String::from_utf8(generated.contents).unwrap(),
         );
     }
 
diff --git a/tools/aconfig/aconfig/src/commands.rs b/tools/aconfig/aconfig/src/commands.rs
index 14a98f0ba2..4b8195b1b0 100644
--- a/tools/aconfig/aconfig/src/commands.rs
+++ b/tools/aconfig/aconfig/src/commands.rs
@@ -14,11 +14,14 @@
  * limitations under the License.
  */
 
-use anyhow::{bail, ensure, Context, Result};
+use anyhow::{anyhow, bail, ensure, Context, Result};
 use convert_finalized_flags::FinalizedFlagMap;
 use itertools::Itertools;
 use protobuf::Message;
+use serde::Deserialize;
+use serde::Serialize;
 use std::collections::HashMap;
+use std::fmt;
 use std::hash::Hasher;
 use std::io::Read;
 use std::path::PathBuf;
@@ -30,8 +33,8 @@ use crate::codegen::CodegenMode;
 use crate::dump::{DumpFormat, DumpPredicate};
 use crate::storage::generate_storage_file;
 use aconfig_protos::{
-    ParsedFlagExt, ProtoFlagMetadata, ProtoFlagPermission, ProtoFlagState, ProtoParsedFlag,
-    ProtoParsedFlags, ProtoTracepoint,
+    ParsedFlagExt, ProtoFlagMetadata, ProtoFlagPermission, ProtoFlagState, ProtoFlagStorageBackend,
+    ProtoParsedFlag, ProtoParsedFlags, ProtoTracepoint,
 };
 use aconfig_storage_file::sip_hasher13::SipHasher13;
 use aconfig_storage_file::StorageFileType;
@@ -56,6 +59,13 @@ impl Input {
     }
 }
 
+impl fmt::Debug for Input {
+    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
+        write!(formatter, "{}", self.source)
+    }
+}
+
+#[derive(Debug)]
 pub struct OutputFile {
     pub path: PathBuf, // relative to some root directory only main knows about
     pub contents: Vec<u8>,
@@ -64,16 +74,131 @@ pub struct OutputFile {
 pub const DEFAULT_FLAG_STATE: ProtoFlagState = ProtoFlagState::DISABLED;
 pub const DEFAULT_FLAG_PERMISSION: ProtoFlagPermission = ProtoFlagPermission::READ_WRITE;
 
+pub const PLATFORM_CONTAINERS: [&str; 4] = ["system", "system_ext", "product", "vendor"];
+
+#[derive(Serialize, Deserialize, Debug)]
+pub struct NamespaceSetting {
+    pub container: String,
+    pub allow_exported: bool,
+}
+
+#[derive(Serialize, Deserialize, Debug)]
+pub struct MainlineBetaNamespaces {
+    pub namespaces: HashMap<String, NamespaceSetting>,
+}
+
+#[allow(dead_code)]
+impl MainlineBetaNamespaces {
+    fn has_flag(&self, pf: &ProtoParsedFlag) -> bool {
+        self.namespaces.contains_key(pf.namespace())
+    }
+
+    fn is_mainline_beta_flag(&self, pf: &ProtoParsedFlag) -> bool {
+        match self.namespaces.get(pf.namespace()) {
+            Some(setting) => setting.container == pf.container(),
+            None => false,
+        }
+    }
+
+    // for each mainline beta namespace, only platform and the corresponding
+    // module containers are allowed
+    fn supports_container(&self, pf: &ProtoParsedFlag) -> bool {
+        match self.namespaces.get(pf.namespace()) {
+            Some(setting) => {
+                setting.container == pf.container()
+                    || PLATFORM_CONTAINERS.iter().any(|&c| c == pf.container())
+            }
+            None => panic!(
+                "Should not check container support for flags in non mainline beta namespaces"
+            ),
+        }
+    }
+
+    fn supports_exported_mode(&self, pf: &ProtoParsedFlag) -> bool {
+        match self.namespaces.get(pf.namespace()) {
+            Some(setting) => {
+                if setting.container == pf.container() {
+                    setting.allow_exported
+                } else {
+                    panic!("Should not check exported mode support on none mainline beta flag")
+                }
+            }
+            None => panic!("Should not check exported mode support on none mainline beta flag"),
+        }
+    }
+}
+
+fn assign_storage_backend(
+    pf: &mut ProtoParsedFlag,
+    beta_namespaces: &Option<MainlineBetaNamespaces>,
+) -> Result<()> {
+    let is_mainline_beta = match beta_namespaces {
+        Some(namespaces) => namespaces.is_mainline_beta_flag(pf),
+        None => false,
+    };
+    let is_read_only = pf.permission() == ProtoFlagPermission::READ_ONLY;
+    let storage = if is_read_only {
+        ProtoFlagStorageBackend::NONE
+    } else if is_mainline_beta {
+        ProtoFlagStorageBackend::DEVICE_CONFIG
+    } else {
+        ProtoFlagStorageBackend::ACONFIGD
+    };
+    let m = pf.metadata.as_mut().ok_or(anyhow!("missing metadata"))?;
+    m.set_storage(storage);
+    Ok(())
+}
+
+fn verify_mainline_beta_namespace_flag(
+    pf: &mut ProtoParsedFlag,
+    beta_namespaces: &Option<MainlineBetaNamespaces>,
+) -> Result<()> {
+    if let Some(namespaces) = beta_namespaces {
+        if !namespaces.has_flag(pf) {
+            return Ok(());
+        }
+        ensure!(
+            namespaces.supports_container(pf),
+            "Creating {} container flag in namespace {} is not allowed",
+            pf.container(),
+            pf.namespace()
+        );
+        if pf.is_exported() {
+            ensure!(
+                namespaces.supports_exported_mode(pf),
+                "Creating exported flag {} in namespace {} is not allowed",
+                pf.fully_qualified_name(),
+                pf.namespace()
+            );
+        }
+    }
+    Ok(())
+}
+
+pub struct ExtendedPermissionsOptions {
+    pub default_permission: ProtoFlagPermission,
+    pub allow_read_write: bool,
+    pub force_read_only: bool,
+}
+
 pub fn parse_flags(
     package: &str,
-    container: Option<&str>,
+    container: &str,
     declarations: Vec<Input>,
     values: Vec<Input>,
-    default_permission: ProtoFlagPermission,
-    allow_read_write: bool,
+    mainline_beta_namespace_config: Option<PathBuf>,
+    extended_permissions_options: ExtendedPermissionsOptions,
 ) -> Result<Vec<u8>> {
     let mut parsed_flags = ProtoParsedFlags::new();
 
+    let beta_namespaces: Option<MainlineBetaNamespaces> = match mainline_beta_namespace_config {
+        Some(file) => {
+            let contents = std::fs::read_to_string(file)?;
+            Some(serde_json::from_str(&contents)?)
+        }
+        None => None,
+    };
+
     for mut input in declarations {
         let mut contents = String::new();
         input
@@ -90,34 +215,34 @@ pub fn parse_flags(
             package,
             flag_declarations.package()
         );
-        if let Some(c) = container {
-            ensure!(
-                c == flag_declarations.container(),
-                "failed to parse {}: expected container {}, got {}",
-                input.source,
-                c,
-                flag_declarations.container()
-            );
-        }
+        ensure!(
+            container == flag_declarations.container(),
+            "failed to parse {}: expected container {}, got {}",
+            input.source,
+            container,
+            flag_declarations.container()
+        );
+
         for mut flag_declaration in flag_declarations.flag.into_iter() {
             aconfig_protos::flag_declaration::verify_fields(&flag_declaration)
                 .with_context(|| input.error_context())?;
 
             // create ParsedFlag using FlagDeclaration and default values
             let mut parsed_flag = ProtoParsedFlag::new();
-            if let Some(c) = container {
-                parsed_flag.set_container(c.to_string());
-            }
+            parsed_flag.set_container(container.to_string());
             parsed_flag.set_package(package.to_string());
             parsed_flag.set_name(flag_declaration.take_name());
             parsed_flag.set_namespace(flag_declaration.take_namespace());
             parsed_flag.set_description(flag_declaration.take_description());
             parsed_flag.bug.append(&mut flag_declaration.bug);
             parsed_flag.set_state(DEFAULT_FLAG_STATE);
-            let flag_permission = if flag_declaration.is_fixed_read_only() {
+            // for fixed read only or forced read only flags, set to read only.
+            let flag_permission = if flag_declaration.is_fixed_read_only()
+                || extended_permissions_options.force_read_only
+            {
                 ProtoFlagPermission::READ_ONLY
             } else {
-                default_permission
+                extended_permissions_options.default_permission
             };
             parsed_flag.set_permission(flag_permission);
             parsed_flag.set_is_fixed_read_only(flag_declaration.is_fixed_read_only());
@@ -132,6 +257,8 @@ pub fn parse_flags(
             let purpose = flag_declaration.metadata.purpose();
             metadata.set_purpose(purpose);
             parsed_flag.metadata = Some(metadata).into();
+            assign_storage_backend(&mut parsed_flag, &beta_namespaces)?;
+            verify_mainline_beta_namespace_flag(&mut parsed_flag, &beta_namespaces)?;
 
             // verify ParsedFlag looks reasonable
             aconfig_protos::parsed_flag::verify_fields(&parsed_flag)?;
@@ -157,7 +284,7 @@ pub fn parse_flags(
             .with_context(|| format!("failed to read {}", input.source))?;
         let flag_values = aconfig_protos::flag_values::try_from_text_proto(&contents)
             .with_context(|| input.error_context())?;
-        for flag_value in flag_values.flag_value.into_iter() {
+        for mut flag_value in flag_values.flag_value.into_iter() {
             aconfig_protos::flag_value::verify_fields(&flag_value)
                 .with_context(|| input.error_context())?;
 
@@ -176,9 +303,15 @@ pub fn parse_flags(
                 "failed to set permission of flag {}, since this flag is fixed read only flag",
                 flag_value.name()
             );
+            if extended_permissions_options.force_read_only {
+                flag_value.set_permission(ProtoFlagPermission::READ_ONLY);
+            }
 
             parsed_flag.set_state(flag_value.state());
-            parsed_flag.set_permission(flag_value.permission());
+            if parsed_flag.permission() != flag_value.permission() {
+                parsed_flag.set_permission(flag_value.permission());
+                assign_storage_backend(parsed_flag, &beta_namespaces)?;
+            }
             let mut tracepoint = ProtoTracepoint::new();
             tracepoint.set_source(input.source.clone());
             tracepoint.set_state(flag_value.state());
@@ -187,7 +320,7 @@ pub fn parse_flags(
         }
     }
 
-    if !allow_read_write {
+    if !extended_permissions_options.allow_read_write {
         if let Some(pf) = parsed_flags
             .parsed_flag
             .iter()
@@ -208,8 +341,6 @@ pub fn parse_flags(
 pub fn create_java_lib(
     mut input: Input,
     codegen_mode: CodegenMode,
-    allow_instrumentation: bool,
-    new_exported: bool,
     single_exported_file: bool,
     finalized_flags: FinalizedFlagMap,
 ) -> Result<Vec<OutputFile>> {
@@ -226,11 +357,10 @@ pub fn create_java_lib(
     let config = JavaCodegenConfig {
         codegen_mode,
         flag_ids,
-        allow_instrumentation,
         package_fingerprint,
-        new_exported,
         single_exported_file,
         finalized_flags,
+        support_uau_annotation: !cfg!(enable_jarjar_flags_in_framwork),
     };
     generate_java_code(&package, modified_parsed_flags.into_iter(), config)
 }
@@ -242,13 +372,26 @@ pub fn create_cpp_lib(mut input: Input, codegen_mode: CodegenMode) -> Result<Vec
         "Exported mode for generated c/c++ flag library is disabled"
     );
     let parsed_flags = input.try_parse_flags()?;
-    let modified_parsed_flags = modify_parsed_flags_based_on_mode(parsed_flags, codegen_mode)?;
+    let modified_parsed_flags =
+        modify_parsed_flags_based_on_mode(parsed_flags.clone(), codegen_mode)?;
     let Some(package) = find_unique_package(&modified_parsed_flags) else {
         bail!("no parsed flags, or the parsed flags use different packages");
     };
     let package = package.to_string();
     let flag_ids = assign_flag_ids(&package, modified_parsed_flags.iter())?;
-    generate_cpp_code(&package, modified_parsed_flags.into_iter(), codegen_mode, flag_ids)
+    let package_fingerprint: Option<u64> = if cfg!(enable_fingerprint_cpp) {
+        let mut flag_names = extract_flag_names(parsed_flags)?;
+        Some(compute_flags_fingerprint(&mut flag_names))
+    } else {
+        None
+    };
+    generate_cpp_code(
+        &package,
+        modified_parsed_flags.into_iter(),
+        codegen_mode,
+        flag_ids,
+        package_fingerprint,
+    )
 }
 
 pub fn create_rust_lib(mut input: Input, codegen_mode: CodegenMode) -> Result<OutputFile> {
@@ -258,13 +401,28 @@ pub fn create_rust_lib(mut input: Input, codegen_mode: CodegenMode) -> Result<Ou
         "Exported mode for generated rust flag library is disabled"
     );
     let parsed_flags = input.try_parse_flags()?;
-    let modified_parsed_flags = modify_parsed_flags_based_on_mode(parsed_flags, codegen_mode)?;
+    let modified_parsed_flags =
+        modify_parsed_flags_based_on_mode(parsed_flags.clone(), codegen_mode)?;
     let Some(package) = find_unique_package(&modified_parsed_flags) else {
         bail!("no parsed flags, or the parsed flags use different packages");
     };
     let package = package.to_string();
+
+    let package_fingerprint: Option<u64> = if cfg!(enable_fingerprint_rust) {
+        let mut flag_names = extract_flag_names(parsed_flags)?;
+        Some(compute_flags_fingerprint(&mut flag_names))
+    } else {
+        None
+    };
+
     let flag_ids = assign_flag_ids(&package, modified_parsed_flags.iter())?;
-    generate_rust_code(&package, flag_ids, modified_parsed_flags.into_iter(), codegen_mode)
+    generate_rust_code(
+        &package,
+        flag_ids,
+        modified_parsed_flags.into_iter(),
+        codegen_mode,
+        package_fingerprint,
+    )
 }
 
 pub fn create_storage(
@@ -278,53 +436,10 @@ pub fn create_storage(
     generate_storage_file(container, parsed_flags_vec.iter(), file, version)
 }
 
-pub fn create_device_config_defaults(mut input: Input) -> Result<Vec<u8>> {
-    let parsed_flags = input.try_parse_flags()?;
-    let mut output = Vec::new();
-    for parsed_flag in parsed_flags
-        .parsed_flag
-        .into_iter()
-        .filter(|pf| pf.permission() == ProtoFlagPermission::READ_WRITE)
-    {
-        let line = format!(
-            "{}:{}={}\n",
-            parsed_flag.namespace(),
-            parsed_flag.fully_qualified_name(),
-            match parsed_flag.state() {
-                ProtoFlagState::ENABLED => "enabled",
-                ProtoFlagState::DISABLED => "disabled",
-            }
-        );
-        output.extend_from_slice(line.as_bytes());
-    }
-    Ok(output)
-}
-
-pub fn create_device_config_sysprops(mut input: Input) -> Result<Vec<u8>> {
-    let parsed_flags = input.try_parse_flags()?;
-    let mut output = Vec::new();
-    for parsed_flag in parsed_flags
-        .parsed_flag
-        .into_iter()
-        .filter(|pf| pf.permission() == ProtoFlagPermission::READ_WRITE)
-    {
-        let line = format!(
-            "persist.device_config.{}={}\n",
-            parsed_flag.fully_qualified_name(),
-            match parsed_flag.state() {
-                ProtoFlagState::ENABLED => "true",
-                ProtoFlagState::DISABLED => "false",
-            }
-        );
-        output.extend_from_slice(line.as_bytes());
-    }
-    Ok(output)
-}
-
 pub fn dump_parsed_flags(
     mut input: Vec<Input>,
     format: DumpFormat,
-    filters: &[&str],
+    filters: &[String],
     dedup: bool,
 ) -> Result<Vec<u8>> {
     let individually_parsed_flags: Result<Vec<ProtoParsedFlags>> =
@@ -357,16 +472,22 @@ pub fn modify_parsed_flags_based_on_mode(
     parsed_flags: ProtoParsedFlags,
     codegen_mode: CodegenMode,
 ) -> Result<Vec<ProtoParsedFlag>> {
-    fn exported_mode_flag_modifier(mut parsed_flag: ProtoParsedFlag) -> ProtoParsedFlag {
+    fn exported_mode_flag_modifier(mut parsed_flag: ProtoParsedFlag) -> Result<ProtoParsedFlag> {
         parsed_flag.set_state(ProtoFlagState::DISABLED);
         parsed_flag.set_permission(ProtoFlagPermission::READ_WRITE);
         parsed_flag.set_is_fixed_read_only(false);
-        parsed_flag
+        let m = parsed_flag.metadata.as_mut().ok_or(anyhow!("missing metadata"))?;
+        m.set_storage(ProtoFlagStorageBackend::ACONFIGD);
+        Ok(parsed_flag)
     }
 
-    fn force_read_only_mode_flag_modifier(mut parsed_flag: ProtoParsedFlag) -> ProtoParsedFlag {
+    fn force_read_only_mode_flag_modifier(
+        mut parsed_flag: ProtoParsedFlag,
+    ) -> Result<ProtoParsedFlag> {
         parsed_flag.set_permission(ProtoFlagPermission::READ_ONLY);
-        parsed_flag
+        let m = parsed_flag.metadata.as_mut().ok_or(anyhow!("missing metadata"))?;
+        m.set_storage(ProtoFlagStorageBackend::NONE);
+        Ok(parsed_flag)
     }
 
     let modified_parsed_flags: Vec<_> = match codegen_mode {
@@ -375,13 +496,13 @@ pub fn modify_parsed_flags_based_on_mode(
             .into_iter()
             .filter(|pf| pf.is_exported())
             .map(exported_mode_flag_modifier)
-            .collect(),
+            .collect::<Result<Vec<_>>>()?,
         CodegenMode::ForceReadOnly => parsed_flags
             .parsed_flag
             .into_iter()
             .filter(|pf| !pf.is_exported())
             .map(force_read_only_mode_flag_modifier)
-            .collect(),
+            .collect::<Result<Vec<_>>>()?,
         CodegenMode::Production | CodegenMode::Test => {
             parsed_flags.parsed_flag.into_iter().collect()
         }
@@ -405,9 +526,9 @@ where
             return Err(anyhow::anyhow!("encountered a flag not in current package"));
         }
 
-        // put a cap on how many flags a package can contain to 65535
-        if flag_idx > u16::MAX as u32 {
-            return Err(anyhow::anyhow!("the number of flags in a package cannot exceed 65535"));
+        // put a cap on how many flags a package can contain to 65534
+        if flag_idx >= u16::MAX as u32 {
+            return Err(anyhow::anyhow!("the number of flags in a package cannot exceed 65534"));
         }
 
         if should_include_flag(pf) {
@@ -448,17 +569,13 @@ fn extract_flag_names(flags: ProtoParsedFlags) -> Result<Vec<String>> {
         .collect::<Vec<_>>())
 }
 
-// Exclude system/vendor/product flags that are RO+disabled.
+// Check if a flag should be managed by aconfigd
 pub fn should_include_flag(pf: &ProtoParsedFlag) -> bool {
-    let should_filter_container = pf.container == Some("vendor".to_string())
-        || pf.container == Some("system".to_string())
-        || pf.container == Some("system_ext".to_string())
-        || pf.container == Some("product".to_string());
-
-    let disabled_ro = pf.state == Some(ProtoFlagState::DISABLED.into())
+    let is_platform_container = PLATFORM_CONTAINERS.iter().any(|&c| c == pf.container());
+    let is_disabled_ro = pf.state == Some(ProtoFlagState::DISABLED.into())
         && pf.permission == Some(ProtoFlagPermission::READ_ONLY.into());
 
-    !should_filter_container || !disabled_ro
+    !(is_platform_container && is_disabled_ro)
 }
 
 #[cfg(test)]
@@ -568,6 +685,7 @@ mod tests {
     fn test_parse_flags_setting_default() {
         let first_flag = r#"
         package: "com.first"
+        container: "test"
         flag {
             name: "first"
             namespace: "first_ns"
@@ -578,14 +696,19 @@ mod tests {
         let declaration =
             vec![Input { source: "momery".to_string(), reader: Box::new(first_flag.as_bytes()) }];
         let value: Vec<Input> = vec![];
+        let extended_permissions_options = ExtendedPermissionsOptions {
+            default_permission: ProtoFlagPermission::READ_ONLY,
+            allow_read_write: true,
+            force_read_only: false,
+        };
 
         let flags_bytes = crate::commands::parse_flags(
             "com.first",
-            None,
+            "test",
             declaration,
             value,
-            ProtoFlagPermission::READ_ONLY,
-            true,
+            None,
+            extended_permissions_options,
         )
         .unwrap();
         let parsed_flags =
@@ -612,14 +735,19 @@ mod tests {
             vec![Input { source: "memory".to_string(), reader: Box::new(first_flag.as_bytes()) }];
 
         let value: Vec<Input> = vec![];
+        let extended_permissions_options = ExtendedPermissionsOptions {
+            default_permission: ProtoFlagPermission::READ_WRITE,
+            allow_read_write: true,
+            force_read_only: false,
+        };
 
         let error = crate::commands::parse_flags(
             "com.argument.package",
-            Some("first.container"),
+            "first.container",
             declaration,
             value,
-            ProtoFlagPermission::READ_WRITE,
-            true,
+            None,
+            extended_permissions_options,
         )
         .unwrap_err();
         assert_eq!(
@@ -644,14 +772,19 @@ mod tests {
             vec![Input { source: "memory".to_string(), reader: Box::new(first_flag.as_bytes()) }];
 
         let value: Vec<Input> = vec![];
+        let extended_permissions_options = ExtendedPermissionsOptions {
+            default_permission: ProtoFlagPermission::READ_WRITE,
+            allow_read_write: true,
+            force_read_only: false,
+        };
 
         let error = crate::commands::parse_flags(
             "com.first",
-            Some("argument.container"),
+            "argument.container",
             declaration,
             value,
-            ProtoFlagPermission::READ_WRITE,
-            true,
+            None,
+            extended_permissions_options,
         )
         .unwrap_err();
         assert_eq!(
@@ -673,14 +806,19 @@ mod tests {
         "#;
         let declaration =
             vec![Input { source: "memory".to_string(), reader: Box::new(first_flag.as_bytes()) }];
+        let extended_permissions_options = ExtendedPermissionsOptions {
+            default_permission: ProtoFlagPermission::READ_WRITE,
+            allow_read_write: false,
+            force_read_only: false,
+        };
 
         let error = crate::commands::parse_flags(
             "com.first",
-            Some("com.first.container"),
+            "com.first.container",
             declaration,
             vec![],
-            ProtoFlagPermission::READ_WRITE,
-            false,
+            None,
+            extended_permissions_options,
         )
         .unwrap_err();
         assert_eq!(
@@ -716,13 +854,18 @@ mod tests {
             source: "memory".to_string(),
             reader: Box::new(first_flag_value.as_bytes()),
         }];
+        let extended_permissions_options = ExtendedPermissionsOptions {
+            default_permission: ProtoFlagPermission::READ_ONLY,
+            allow_read_write: false,
+            force_read_only: false,
+        };
         let error = crate::commands::parse_flags(
             "com.first",
-            Some("com.first.container"),
+            "com.first.container",
             declaration,
             value,
-            ProtoFlagPermission::READ_ONLY,
-            false,
+            None,
+            extended_permissions_options,
         )
         .unwrap_err();
         assert_eq!(
@@ -758,13 +901,116 @@ mod tests {
             source: "memory".to_string(),
             reader: Box::new(first_flag_value.as_bytes()),
         }];
+        let extended_permissions_options = ExtendedPermissionsOptions {
+            default_permission: ProtoFlagPermission::READ_ONLY,
+            allow_read_write: false,
+            force_read_only: false,
+        };
         let flags_bytes = crate::commands::parse_flags(
             "com.first",
-            Some("com.first.container"),
+            "com.first.container",
             declaration,
             value,
-            ProtoFlagPermission::READ_ONLY,
-            false,
+            None,
+            extended_permissions_options,
+        )
+        .unwrap();
+        let parsed_flags =
+            aconfig_protos::parsed_flags::try_from_binary_proto(&flags_bytes).unwrap();
+        assert_eq!(1, parsed_flags.parsed_flag.len());
+        let parsed_flag = parsed_flags.parsed_flag.first().unwrap();
+        assert_eq!(ProtoFlagState::DISABLED, parsed_flag.state());
+        assert_eq!(ProtoFlagPermission::READ_ONLY, parsed_flag.permission());
+    }
+
+    #[test]
+    fn test_parse_flags_force_read_only_convert_read_write_to_read_only_success() {
+        let first_flag = r#"
+        package: "com.first"
+        container: "com.first.container"
+        flag {
+            name: "first"
+            namespace: "first_ns"
+            description: "This is the description of the first flag."
+            bug: "123"
+        }
+        "#;
+        let declaration =
+            vec![Input { source: "memory".to_string(), reader: Box::new(first_flag.as_bytes()) }];
+
+        let first_flag_value = r#"
+        flag_value {
+            package: "com.first"
+            name: "first"
+            state: DISABLED
+            permission: READ_WRITE
+        }
+        "#;
+        let value = vec![Input {
+            source: "memory".to_string(),
+            reader: Box::new(first_flag_value.as_bytes()),
+        }];
+        let extended_permissions_options = ExtendedPermissionsOptions {
+            default_permission: ProtoFlagPermission::READ_ONLY,
+            allow_read_write: true,
+            force_read_only: true,
+        };
+        let flags_bytes = crate::commands::parse_flags(
+            "com.first",
+            "com.first.container",
+            declaration,
+            value,
+            None,
+            extended_permissions_options,
+        )
+        .unwrap();
+        let parsed_flags =
+            aconfig_protos::parsed_flags::try_from_binary_proto(&flags_bytes).unwrap();
+        assert_eq!(1, parsed_flags.parsed_flag.len());
+        let parsed_flag = parsed_flags.parsed_flag.first().unwrap();
+        assert_eq!(ProtoFlagState::DISABLED, parsed_flag.state());
+        assert_eq!(ProtoFlagPermission::READ_ONLY, parsed_flag.permission());
+    }
+
+    #[test]
+    fn test_parse_flags_force_read_only_no_allow_read_write_does_not_fail() {
+        let first_flag = r#"
+        package: "com.first"
+        container: "com.first.container"
+        flag {
+            name: "first"
+            namespace: "first_ns"
+            description: "This is the description of the first flag."
+            bug: "123"
+        }
+        "#;
+        let declaration =
+            vec![Input { source: "memory".to_string(), reader: Box::new(first_flag.as_bytes()) }];
+
+        let first_flag_value = r#"
+        flag_value {
+            package: "com.first"
+            name: "first"
+            state: DISABLED
+            permission: READ_WRITE
+        }
+        "#;
+        let value = vec![Input {
+            source: "memory".to_string(),
+            reader: Box::new(first_flag_value.as_bytes()),
+        }];
+        let extended_permissions_options = ExtendedPermissionsOptions {
+            default_permission: ProtoFlagPermission::READ_ONLY,
+            allow_read_write: false,
+            force_read_only: true,
+        };
+        let flags_bytes = crate::commands::parse_flags(
+            "com.first",
+            "com.first.container",
+            declaration,
+            value,
+            None,
+            extended_permissions_options,
         )
         .unwrap();
         let parsed_flags =
@@ -803,13 +1049,18 @@ mod tests {
             source: "memory".to_string(),
             reader: Box::new(first_flag_value.as_bytes()),
         }];
+        let extended_permissions_options = ExtendedPermissionsOptions {
+            default_permission: ProtoFlagPermission::READ_WRITE,
+            allow_read_write: true,
+            force_read_only: false,
+        };
         let error = crate::commands::parse_flags(
             "com.first",
-            Some("com.first.container"),
+            "com.first.container",
             declaration,
             value,
-            ProtoFlagPermission::READ_WRITE,
-            true,
+            None,
+            extended_permissions_options,
         )
         .unwrap_err();
         assert_eq!(
@@ -819,9 +1070,10 @@ mod tests {
     }
 
     #[test]
-    fn test_parse_flags_metadata() {
+    fn test_parse_flags_metadata_purpose() {
         let metadata_flag = r#"
         package: "com.first"
+        container: "test"
         flag {
             name: "first"
             namespace: "first_ns"
@@ -837,14 +1089,18 @@ mod tests {
             reader: Box::new(metadata_flag.as_bytes()),
         }];
         let value: Vec<Input> = vec![];
-
+        let extended_permissions_options = ExtendedPermissionsOptions {
+            default_permission: ProtoFlagPermission::READ_ONLY,
+            allow_read_write: true,
+            force_read_only: false,
+        };
         let flags_bytes = crate::commands::parse_flags(
             "com.first",
-            None,
+            "test",
             declaration,
             value,
-            ProtoFlagPermission::READ_ONLY,
-            true,
+            None,
+            extended_permissions_options,
         )
         .unwrap();
         let parsed_flags =
@@ -854,20 +1110,226 @@ mod tests {
         assert_eq!(ProtoFlagPurpose::PURPOSE_FEATURE, parsed_flag.metadata.purpose());
     }
 
-    #[test]
-    fn test_create_device_config_defaults() {
-        let input = parse_test_flags_as_input();
-        let bytes = create_device_config_defaults(input).unwrap();
-        let text = std::str::from_utf8(&bytes).unwrap();
-        assert_eq!("aconfig_test:com.android.aconfig.test.disabled_rw=disabled\naconfig_test:com.android.aconfig.test.disabled_rw_exported=disabled\nother_namespace:com.android.aconfig.test.disabled_rw_in_other_namespace=disabled\naconfig_test:com.android.aconfig.test.enabled_rw=enabled\n", text);
+    fn get_parsed_flag_proto(
+        container: &'static str,
+        package: &'static str,
+        decl: &'static str,
+        val: Option<&'static str>,
+        config: Option<PathBuf>,
+    ) -> Result<ProtoParsedFlag> {
+        let declaration =
+            vec![Input { source: "memory".to_string(), reader: Box::new(decl.as_bytes()) }];
+
+        let value: Vec<Input> = match val {
+            Some(val_str) => {
+                vec![Input { source: "memory".to_string(), reader: Box::new(val_str.as_bytes()) }]
+            }
+            None => {
+                vec![]
+            }
+        };
+        let extended_permissions_options = ExtendedPermissionsOptions {
+            default_permission: ProtoFlagPermission::READ_WRITE,
+            allow_read_write: true,
+            force_read_only: false,
+        };
+
+        let flags_bytes = crate::commands::parse_flags(
+            package,
+            container,
+            declaration,
+            value,
+            config,
+            extended_permissions_options,
+        )?;
+
+        let parsed_flags = aconfig_protos::parsed_flags::try_from_binary_proto(&flags_bytes)?;
+
+        assert_eq!(1, parsed_flags.parsed_flag.len());
+        Ok(parsed_flags.parsed_flag.first().unwrap().clone())
     }
 
     #[test]
-    fn test_create_device_config_sysprops() {
-        let input = parse_test_flags_as_input();
-        let bytes = create_device_config_sysprops(input).unwrap();
-        let text = std::str::from_utf8(&bytes).unwrap();
-        assert_eq!("persist.device_config.com.android.aconfig.test.disabled_rw=false\npersist.device_config.com.android.aconfig.test.disabled_rw_exported=false\npersist.device_config.com.android.aconfig.test.disabled_rw_in_other_namespace=false\npersist.device_config.com.android.aconfig.test.enabled_rw=true\n", text);
+    fn test_parse_flags_mainline_beta_namespace_config() {
+        let metadata_flag = r#"
+        package: "com.first"
+        container: "test"
+        flag {
+            name: "first"
+            namespace: "first_ns"
+            description: "This is the description of this feature flag."
+            bug: "123"
+        }
+        "#;
+
+        let config = Some(PathBuf::from("tests/mainline_beta_namespaces.json"));
+
+        // Case 1, regular RW flag without value file override
+        let parsed_flag =
+            get_parsed_flag_proto("test", "com.first", metadata_flag, None, config.clone())
+                .unwrap();
+        assert_eq!(ProtoFlagStorageBackend::ACONFIGD, parsed_flag.metadata.storage());
+
+        // Case 2, regular RW flag with value file override to RO
+        let first_flag_value = r#"
+        flag_value {
+            package: "com.first"
+            name: "first"
+            state: DISABLED
+            permission: READ_ONLY
+        }
+        "#;
+        let parsed_flag = get_parsed_flag_proto(
+            "test",
+            "com.first",
+            metadata_flag,
+            Some(first_flag_value),
+            config.clone(),
+        )
+        .unwrap();
+        assert_eq!(ProtoFlagStorageBackend::NONE, parsed_flag.metadata.storage());
+
+        // Case 3, fixed read only flag
+        let metadata_flag = r#"
+        package: "com.first"
+        container: "test"
+        flag {
+            name: "first"
+            namespace: "first_ns"
+            description: "This is the description of this feature flag."
+            bug: "123"
+            is_fixed_read_only: true
+        }
+        "#;
+
+        let parsed_flag =
+            get_parsed_flag_proto("test", "com.first", metadata_flag, None, config.clone())
+                .unwrap();
+        assert_eq!(ProtoFlagStorageBackend::NONE, parsed_flag.metadata.storage());
+
+        // Case 4, mainline beta namespace fixed read only flag
+        let metadata_flag = r#"
+        package: "com.first"
+        container: "com.android.tethering"
+        flag {
+            name: "first"
+            namespace: "com_android_tethering"
+            description: "This is the description of this feature flag."
+            bug: "123"
+            is_fixed_read_only: true
+        }
+        "#;
+        let parsed_flag = get_parsed_flag_proto(
+            "com.android.tethering",
+            "com.first",
+            metadata_flag,
+            None,
+            config.clone(),
+        )
+        .unwrap();
+        assert_eq!(ProtoFlagStorageBackend::NONE, parsed_flag.metadata.storage());
+
+        // Case 5, mainline beta namespace platform flag
+        let metadata_flag = r#"
+        package: "com.first"
+        container: "system"
+        flag {
+            name: "first"
+            namespace: "com_android_tethering"
+            description: "This is the description of this feature flag."
+            bug: "123"
+        }
+        "#;
+        let parsed_flag =
+            get_parsed_flag_proto("system", "com.first", metadata_flag, None, config.clone())
+                .unwrap();
+        assert_eq!(ProtoFlagStorageBackend::ACONFIGD, parsed_flag.metadata.storage());
+
+        // Case 6, mainline beta namespace mainline flag
+        let metadata_flag = r#"
+        package: "com.first"
+        container: "com.android.tethering"
+        flag {
+            name: "first"
+            namespace: "com_android_tethering"
+            description: "This is the description of this feature flag."
+            bug: "123"
+        }
+        "#;
+        let parsed_flag = get_parsed_flag_proto(
+            "com.android.tethering",
+            "com.first",
+            metadata_flag,
+            None,
+            config.clone(),
+        )
+        .unwrap();
+        assert_eq!(ProtoFlagStorageBackend::DEVICE_CONFIG, parsed_flag.metadata.storage());
+
+        // Case 7, mainline beta namespace mainline flag but without config
+        let metadata_flag = r#"
+        package: "com.first"
+        container: "com.android.tethering"
+        flag {
+            name: "first"
+            namespace: "com_android_tethering"
+            description: "This is the description of this feature flag."
+            bug: "123"
+        }
+        "#;
+        let parsed_flag =
+            get_parsed_flag_proto("com.android.tethering", "com.first", metadata_flag, None, None)
+                .unwrap();
+        assert_eq!(ProtoFlagStorageBackend::ACONFIGD, parsed_flag.metadata.storage());
+
+        // Case 8, mainline beta namespace invalid container
+        let metadata_flag = r#"
+        package: "com.first"
+        container: "com.android.tethering"
+        flag {
+            name: "first"
+            namespace: "com_android_networkstack"
+            description: "This is the description of this feature flag."
+            bug: "123"
+        }
+        "#;
+        let error = get_parsed_flag_proto(
+            "com.android.tethering",
+            "com.first",
+            metadata_flag,
+            None,
+            config.clone(),
+        )
+        .unwrap_err();
+        assert_eq!(
+            format!("{:?}", error),
+            "Creating com.android.tethering container flag in namespace com_android_networkstack is not allowed"
+        );
+
+        // Case 9, mainline beta namespace unsupported exported mode
+        let metadata_flag = r#"
+        package: "com.first"
+        container: "com.android.networkstack"
+        flag {
+            name: "first"
+            namespace: "com_android_networkstack"
+            description: "This is the description of this feature flag."
+            bug: "123"
+            is_exported: true
+        }
+        "#;
+        let error = get_parsed_flag_proto(
+            "com.android.networkstack",
+            "com.first",
+            metadata_flag,
+            None,
+            config.clone(),
+        )
+        .unwrap_err();
+        assert_eq!(
+            format!("{:?}", error),
+            "Creating exported flag com.first.first in namespace com_android_networkstack is not allowed"
+        );
     }
 
     #[test]
@@ -890,7 +1352,10 @@ mod tests {
         let bytes = dump_parsed_flags(
             vec![input],
             DumpFormat::Custom("{fully_qualified_name}".to_string()),
-            &["container:system+state:ENABLED", "container:system+permission:READ_WRITE"],
+            &[
+                "container:system+state:ENABLED".to_string(),
+                "container:system+permission:READ_WRITE".to_string(),
+            ],
             false,
         )
         .unwrap();
@@ -946,13 +1411,19 @@ mod tests {
 
     #[test]
     fn test_modify_parsed_flags_based_on_mode_exported() {
-        let parsed_flags = crate::test::parse_test_flags();
+        let mut parsed_flags = crate::test::parse_test_flags();
+
+        let pf = parsed_flags.parsed_flag.iter_mut().find(|pf| pf.is_exported()).unwrap();
+        let m = pf.metadata.as_mut().unwrap();
+        m.set_storage(ProtoFlagStorageBackend::DEVICE_CONFIG);
+
         let p_parsed_flags =
             modify_parsed_flags_based_on_mode(parsed_flags, CodegenMode::Exported).unwrap();
         assert_eq!(3, p_parsed_flags.len());
         for flag in p_parsed_flags.iter() {
             assert_eq!(ProtoFlagState::DISABLED, flag.state());
             assert_eq!(ProtoFlagPermission::READ_WRITE, flag.permission());
+            assert_eq!(ProtoFlagStorageBackend::ACONFIGD, flag.metadata.storage());
             assert!(!flag.is_fixed_read_only());
             assert!(flag.is_exported());
         }
@@ -964,9 +1435,27 @@ mod tests {
         assert_eq!("exported library contains no exported flags", format!("{:?}", error));
     }
 
+    #[test]
+    fn test_modify_parsed_flags_based_on_mode_forcereadonly() {
+        let mut parsed_flags = crate::test::parse_test_flags();
+
+        let pf = parsed_flags.parsed_flag.iter_mut().find(|pf| !pf.is_exported()).unwrap();
+        let m = pf.metadata.as_mut().unwrap();
+        m.set_storage(ProtoFlagStorageBackend::DEVICE_CONFIG);
+
+        let p_parsed_flags =
+            modify_parsed_flags_based_on_mode(parsed_flags, CodegenMode::ForceReadOnly).unwrap();
+        assert_eq!(6, p_parsed_flags.len());
+        for flag in p_parsed_flags.iter() {
+            assert_eq!(ProtoFlagPermission::READ_ONLY, flag.permission());
+            assert_eq!(ProtoFlagStorageBackend::NONE, flag.metadata.storage());
+            assert!(!flag.is_exported());
+        }
+    }
+
     #[test]
     fn test_assign_flag_ids() {
-        let parsed_flags = crate::test::parse_test_flags();
+        let mut parsed_flags = crate::test::parse_test_flags();
         let package = find_unique_package(&parsed_flags.parsed_flag).unwrap().to_string();
         let flag_ids = assign_flag_ids(&package, parsed_flags.parsed_flag.iter()).unwrap();
         let expected_flag_ids = HashMap::from([
@@ -980,6 +1469,16 @@ mod tests {
             (String::from("enabled_rw"), 7_u16),
         ]);
         assert_eq!(flag_ids, expected_flag_ids);
+
+        let pf = parsed_flags
+            .parsed_flag
+            .iter_mut()
+            .find(|pf| pf.name() == "disabled_rw_in_other_namespace")
+            .unwrap();
+        let m = pf.metadata.as_mut().unwrap();
+        m.set_storage(ProtoFlagStorageBackend::DEVICE_CONFIG);
+        let flag_ids = assign_flag_ids(&package, parsed_flags.parsed_flag.iter()).unwrap();
+        assert_eq!(flag_ids, expected_flag_ids);
     }
 
     #[test]
diff --git a/tools/aconfig/aconfig/src/main.rs b/tools/aconfig/aconfig/src/main.rs
index 6b294239e9..43357a30c2 100644
--- a/tools/aconfig/aconfig/src/main.rs
+++ b/tools/aconfig/aconfig/src/main.rs
@@ -16,324 +16,62 @@
 
 //! `aconfig` is a build time tool to manage build time configurations, such as feature flags.
 
-use aconfig_storage_file::DEFAULT_FILE_VERSION;
-use aconfig_storage_file::MAX_SUPPORTED_FILE_VERSION;
-use anyhow::{anyhow, bail, Context, Result};
-use clap::{builder::ArgAction, builder::EnumValueParser, Arg, ArgMatches, Command};
-use core::any::Any;
-use std::fs;
-use std::io;
-use std::io::Write;
-use std::path::{Path, PathBuf};
-
+mod cli_parser;
 mod codegen;
 mod commands;
 mod dump;
 mod storage;
 
-use aconfig_storage_file::StorageFileType;
-use codegen::CodegenMode;
+use commands::Input;
 use convert_finalized_flags::FinalizedFlagMap;
-use dump::DumpFormat;
+
+use anyhow::{anyhow, Context, Result};
+use std::env;
+use std::fs;
+use std::fs::File;
+use std::io;
+use std::io::{BufRead, BufReader, Write};
+use std::path::Path;
 
 #[cfg(test)]
 mod test;
 
-use commands::{Input, OutputFile};
-
-const HELP_DUMP_CACHE: &str = r#"
-An aconfig cache file, created via `aconfig create-cache`.
-"#;
-
-const HELP_DUMP_FORMAT: &str = r#"
-Change the output format for each flag.
-
-The argument to --format is a format string. Each flag will be a copy of this string, with certain
-placeholders replaced by attributes of the flag. The placeholders are
-
-  {package}
-  {name}
-  {namespace}
-  {description}
-  {bug}
-  {state}
-  {state:bool}
-  {permission}
-  {trace}
-  {trace:paths}
-  {is_fixed_read_only}
-  {is_exported}
-  {container}
-  {metadata}
-  {fully_qualified_name}
-
-Note: the format strings "textproto" and "protobuf" are handled in a special way: they output all
-flag attributes in text or binary protobuf format.
-
-Examples:
-
-  # See which files were read to determine the value of a flag; the files were read in the order
-  # listed.
-  --format='{fully_qualified_name} {trace}'
-
-  # Trace the files read for a specific flag. Useful during debugging.
-  --filter=fully_qualified_name:com.foo.flag_name --format='{trace}'
-
-  # Print a somewhat human readable description of each flag.
-  --format='The flag {name} in package {package} is {state} and has permission {permission}.'
-"#;
-
-const HELP_DUMP_FILTER: &str = r#"
-Limit which flags to output. If --filter is omitted, all flags will be printed. If multiple
---filter options are provided, the output will be limited to flags that match any of the filters.
-
-The argument to --filter is a search query. Multiple queries can be AND-ed together by
-concatenating them with a plus sign.
-
-Valid queries are:
-
-  package:<string>
-  name:<string>
-  namespace:<string>
-  bug:<string>
-  state:ENABLED|DISABLED
-  permission:READ_ONLY|READ_WRITE
-  is_fixed_read_only:true|false
-  is_exported:true|false
-  container:<string>
-  fully_qualified_name:<string>
-
-Note: there is currently no support for filtering based on these flag attributes: description,
-trace, metadata.
-
-Examples:
-
-  # Print a single flag:
-  --filter=fully_qualified_name:com.foo.flag_name
-
-  # Print all known information about a single flag:
-  --filter=fully_qualified_name:com.foo.flag_name --format=textproto
-
-  # Print all flags in the com.foo package, and all enabled flags in the com.bar package:
-  --filter=package:com.foo --filter=package.com.bar+state:ENABLED
-"#;
-
-const HELP_DUMP_DEDUP: &str = r#"
-Allow the same flag to be present in multiple cache files; if duplicates are found, collapse into
-a single instance.
-"#;
-
-fn cli() -> Command {
-    Command::new("aconfig")
-        .subcommand_required(true)
-        .subcommand(
-            Command::new("create-cache")
-                .arg(Arg::new("package").long("package").required(true))
-                .arg(Arg::new("container").long("container").required(true))
-                .arg(Arg::new("declarations").long("declarations").action(ArgAction::Append))
-                .arg(Arg::new("values").long("values").action(ArgAction::Append))
-                .arg(
-                    Arg::new("default-permission")
-                        .long("default-permission")
-                        .value_parser(aconfig_protos::flag_permission::parse_from_str)
-                        .default_value(aconfig_protos::flag_permission::to_string(
-                            &commands::DEFAULT_FLAG_PERMISSION,
-                        )),
-                )
-                .arg(
-                    Arg::new("allow-read-write")
-                        .long("allow-read-write")
-                        .value_parser(clap::value_parser!(bool))
-                        .default_value("true"),
-                )
-                .arg(Arg::new("cache").long("cache").required(true)),
-        )
-        .subcommand(
-            Command::new("create-java-lib")
-                .arg(Arg::new("cache").long("cache").required(true))
-                .arg(Arg::new("out").long("out").required(true))
-                .arg(
-                    Arg::new("mode")
-                        .long("mode")
-                        .value_parser(EnumValueParser::<CodegenMode>::new())
-                        .default_value("production"),
-                )
-                .arg(
-                    Arg::new("single-exported-file")
-                        .long("single-exported-file")
-                        .value_parser(clap::value_parser!(bool))
-                        .default_value("false"),
-                )
-                // TODO: b/395899938 - clean up flags for switching to new storage
-                .arg(
-                    Arg::new("allow-instrumentation")
-                        .long("allow-instrumentation")
-                        .value_parser(clap::value_parser!(bool))
-                        .default_value("false"),
-                )
-                // TODO: b/395899938 - clean up flags for switching to new storage
-                .arg(
-                    Arg::new("new-exported")
-                        .long("new-exported")
-                        .value_parser(clap::value_parser!(bool))
-                        .default_value("false"),
-                )
-                // Allows build flag toggling of checking API level in exported
-                // flag lib for finalized API flags.
-                // TODO: b/378936061 - Remove once build flag for API level
-                // check is fully enabled.
-                .arg(
-                    Arg::new("check-api-level")
-                        .long("check-api-level")
-                        .value_parser(clap::value_parser!(bool))
-                        .default_value("false"),
-                ),
-        )
-        .subcommand(
-            Command::new("create-cpp-lib")
-                .arg(Arg::new("cache").long("cache").required(true))
-                .arg(Arg::new("out").long("out").required(true))
-                .arg(
-                    Arg::new("mode")
-                        .long("mode")
-                        .value_parser(EnumValueParser::<CodegenMode>::new())
-                        .default_value("production"),
-                )
-                .arg(
-                    Arg::new("allow-instrumentation")
-                        .long("allow-instrumentation")
-                        .value_parser(clap::value_parser!(bool))
-                        .default_value("false"),
-                ),
-        )
-        .subcommand(
-            Command::new("create-rust-lib")
-                .arg(Arg::new("cache").long("cache").required(true))
-                .arg(Arg::new("out").long("out").required(true))
-                .arg(
-                    Arg::new("allow-instrumentation")
-                        .long("allow-instrumentation")
-                        .value_parser(clap::value_parser!(bool))
-                        .default_value("false"),
-                )
-                .arg(
-                    Arg::new("mode")
-                        .long("mode")
-                        .value_parser(EnumValueParser::<CodegenMode>::new())
-                        .default_value("production"),
-                ),
-        )
-        .subcommand(
-            Command::new("create-device-config-defaults")
-                .arg(Arg::new("cache").long("cache").action(ArgAction::Append).required(true))
-                .arg(Arg::new("out").long("out").default_value("-")),
-        )
-        .subcommand(
-            Command::new("create-device-config-sysprops")
-                .arg(Arg::new("cache").long("cache").action(ArgAction::Append).required(true))
-                .arg(Arg::new("out").long("out").default_value("-")),
-        )
-        .subcommand(
-            Command::new("dump-cache")
-                .alias("dump")
-                .arg(
-                    Arg::new("cache")
-                        .long("cache")
-                        .action(ArgAction::Append)
-                        .long_help(HELP_DUMP_CACHE.trim()),
-                )
-                .arg(
-                    Arg::new("format")
-                        .long("format")
-                        .value_parser(|s: &str| DumpFormat::try_from(s))
-                        .default_value(
-                            "{fully_qualified_name} [{container}]: {permission} + {state}",
-                        )
-                        .long_help(HELP_DUMP_FORMAT.trim()),
-                )
-                .arg(
-                    Arg::new("filter")
-                        .long("filter")
-                        .action(ArgAction::Append)
-                        .long_help(HELP_DUMP_FILTER.trim()),
-                )
-                .arg(
-                    Arg::new("dedup")
-                        .long("dedup")
-                        .num_args(0)
-                        .action(ArgAction::SetTrue)
-                        .long_help(HELP_DUMP_DEDUP.trim()),
-                )
-                .arg(Arg::new("out").long("out").default_value("-")),
-        )
-        .subcommand(
-            Command::new("create-storage")
-                .arg(
-                    Arg::new("container")
-                        .long("container")
-                        .required(true)
-                        .help("The target container for the generated storage file."),
-                )
-                .arg(
-                    Arg::new("file")
-                        .long("file")
-                        .value_parser(|s: &str| StorageFileType::try_from(s)),
-                )
-                .arg(Arg::new("cache").long("cache").action(ArgAction::Append).required(true))
-                .arg(Arg::new("out").long("out").required(true))
-                .arg(
-                    Arg::new("version")
-                        .long("version")
-                        .required(false)
-                        .value_parser(|s: &str| s.parse::<u32>()),
-                ),
-        )
-}
-
-fn get_required_arg<'a, T>(matches: &'a ArgMatches, arg_name: &str) -> Result<&'a T>
-where
-    T: Any + Clone + Send + Sync + 'static,
-{
-    matches
-        .get_one::<T>(arg_name)
-        .ok_or(anyhow!("internal error: required argument '{}' not found", arg_name))
-}
-
-fn get_optional_arg<'a, T>(matches: &'a ArgMatches, arg_name: &str) -> Option<&'a T>
-where
-    T: Any + Clone + Send + Sync + 'static,
-{
-    matches.get_one::<T>(arg_name)
+fn load_finalized_flags() -> Result<FinalizedFlagMap> {
+    let json_str = include_str!(concat!(env!("OUT_DIR"), "/finalized_flags_record.json"));
+    let map = serde_json::from_str(json_str)?;
+    Ok(map)
 }
 
-fn open_zero_or_more_files(matches: &ArgMatches, arg_name: &str) -> Result<Vec<Input>> {
+fn open_zero_or_more_files(file_paths: &Vec<String>) -> Result<Vec<Input>> {
     let mut opened_files = vec![];
-    for path in matches.get_many::<String>(arg_name).unwrap_or_default() {
-        let file = Box::new(fs::File::open(path)?);
+    for path in file_paths {
+        let file = Box::new(File::open(path).with_context(|| format!("Couldn't open {path}"))?);
         opened_files.push(Input { source: path.to_string(), reader: file });
     }
     Ok(opened_files)
 }
 
-fn open_single_file(matches: &ArgMatches, arg_name: &str) -> Result<Input> {
-    let Some(path) = matches.get_one::<String>(arg_name) else {
-        bail!("missing argument {}", arg_name);
-    };
-    let file = Box::new(fs::File::open(path)?);
+fn open_single_file(path: &str) -> Result<Input> {
+    let file = Box::new(File::open(path).with_context(|| format!("Couldn't open {path}"))?);
     Ok(Input { source: path.to_string(), reader: file })
 }
 
-fn write_output_file_realtive_to_dir(root: &Path, output_file: &OutputFile) -> Result<()> {
-    let path = root.join(&output_file.path);
-    let parent = path
-        .parent()
-        .ok_or(anyhow!("unable to locate parent of output file {}", path.display()))?;
-    fs::create_dir_all(parent)
-        .with_context(|| format!("failed to create directory {}", parent.display()))?;
-    let mut file =
-        fs::File::create(&path).with_context(|| format!("failed to open {}", path.display()))?;
-    file.write_all(&output_file.contents)
-        .with_context(|| format!("failed to write to {}", path.display()))?;
+fn write_output_files_relative_to_dir(
+    root: &Path,
+    output_files: &[commands::OutputFile],
+) -> Result<()> {
+    for output_file in output_files {
+        let path = root.join(&output_file.path);
+        let parent = path
+            .parent()
+            .ok_or_else(|| anyhow!("unable to locate parent of output file {}", path.display()))?;
+        fs::create_dir_all(parent)
+            .with_context(|| format!("failed to create directory {}", parent.display()))?;
+        let mut file = fs::File::create(&path)
+            .with_context(|| format!("failed to open {}", path.display()))?;
+        file.write_all(&output_file.contents)
+            .with_context(|| format!("failed to write to {}", path.display()))?;
+    }
     Ok(())
 }
 
@@ -349,129 +87,109 @@ fn write_output_to_file_or_stdout(path: &str, data: &[u8]) -> Result<()> {
     Ok(())
 }
 
-fn load_finalized_flags() -> Result<FinalizedFlagMap> {
-    let json_str = include_str!(concat!(env!("OUT_DIR"), "/finalized_flags_record.json"));
-    let map = serde_json::from_str(json_str)?;
-    Ok(map)
+struct RealResponseFileReader;
+
+impl cli_parser::ResponseFileReader for RealResponseFileReader {
+    fn read_to_bufread(&self, path_str: &str) -> Result<Box<dyn BufRead>> {
+        let path = Path::new(path_str);
+        let file = File::open(path)
+            .with_context(|| format!("Failed to open response file: {}", path.display()))?;
+        let reader = BufReader::new(file);
+        Ok(Box::new(reader))
+    }
 }
 
 fn main() -> Result<()> {
-    let matches = cli().get_matches();
-    match matches.subcommand() {
-        Some(("create-cache", sub_matches)) => {
-            let package = get_required_arg::<String>(sub_matches, "package")?;
-            let container =
-                get_optional_arg::<String>(sub_matches, "container").map(|c| c.as_str());
-            let declarations = open_zero_or_more_files(sub_matches, "declarations")?;
-            let values = open_zero_or_more_files(sub_matches, "values")?;
-            let default_permission = get_required_arg::<aconfig_protos::ProtoFlagPermission>(
-                sub_matches,
-                "default-permission",
-            )?;
-            let allow_read_write = get_optional_arg::<bool>(sub_matches, "allow-read-write")
-                .expect("failed to parse allow-read-write");
+    let reader = RealResponseFileReader;
+    let processed_args = cli_parser::process_raw_args(env::args_os(), &reader)?;
+    let parsed_command = cli_parser::parse_args(processed_args)?;
+
+    match parsed_command {
+        cli_parser::ParsedCommand::CreateCache {
+            package,
+            container,
+            declarations,
+            values,
+            default_permission,
+            allow_read_write,
+            cache_out_path,
+            mainline_beta_namespace_config,
+            force_read_only,
+        } => {
+            let extended_permissions_options = commands::ExtendedPermissionsOptions {
+                default_permission,
+                allow_read_write,
+                force_read_only,
+            };
             let output = commands::parse_flags(
-                package,
-                container,
-                declarations,
-                values,
-                *default_permission,
-                *allow_read_write,
+                &package,
+                &container,
+                open_zero_or_more_files(&declarations)?, // declarations
+                open_zero_or_more_files(&values)?,       // values
+                mainline_beta_namespace_config,
+                extended_permissions_options,
             )
             .context("failed to create cache")?;
-            let path = get_required_arg::<String>(sub_matches, "cache")?;
-            write_output_to_file_or_stdout(path, &output)?;
+            write_output_to_file_or_stdout(&cache_out_path, &output)?;
         }
-        Some(("create-java-lib", sub_matches)) => {
-            let cache = open_single_file(sub_matches, "cache")?;
-            let mode = get_required_arg::<CodegenMode>(sub_matches, "mode")?;
-            let allow_instrumentation =
-                get_required_arg::<bool>(sub_matches, "allow-instrumentation")?;
-            let new_exported = get_required_arg::<bool>(sub_matches, "new-exported")?;
-            let single_exported_file =
-                get_required_arg::<bool>(sub_matches, "single-exported-file")?;
-
-            let check_api_level = get_required_arg::<bool>(sub_matches, "check-api-level")?;
-            let finalized_flags: FinalizedFlagMap =
-                if *check_api_level { load_finalized_flags()? } else { FinalizedFlagMap::new() };
-
+        cli_parser::ParsedCommand::CreateJavaLib {
+            cache_path,
+            out_dir,
+            mode,
+            single_exported_file,
+        } => {
+            let finalized_flags = load_finalized_flags()?;
             let generated_files = commands::create_java_lib(
-                cache,
-                *mode,
-                *allow_instrumentation,
-                *new_exported,
-                *single_exported_file,
+                open_single_file(&cache_path)?, // cache
+                mode,
+                single_exported_file,
                 finalized_flags,
             )
             .context("failed to create java lib")?;
-            let dir = PathBuf::from(get_required_arg::<String>(sub_matches, "out")?);
-            generated_files
-                .iter()
-                .try_for_each(|file| write_output_file_realtive_to_dir(&dir, file))?;
-        }
-        Some(("create-cpp-lib", sub_matches)) => {
-            let cache = open_single_file(sub_matches, "cache")?;
-            let mode = get_required_arg::<CodegenMode>(sub_matches, "mode")?;
-            let generated_files =
-                commands::create_cpp_lib(cache, *mode).context("failed to create cpp lib")?;
-            let dir = PathBuf::from(get_required_arg::<String>(sub_matches, "out")?);
-            generated_files
-                .iter()
-                .try_for_each(|file| write_output_file_realtive_to_dir(&dir, file))?;
-        }
-        Some(("create-rust-lib", sub_matches)) => {
-            let cache = open_single_file(sub_matches, "cache")?;
-            let mode = get_required_arg::<CodegenMode>(sub_matches, "mode")?;
-            let generated_file =
-                commands::create_rust_lib(cache, *mode).context("failed to create rust lib")?;
-            let dir = PathBuf::from(get_required_arg::<String>(sub_matches, "out")?);
-            write_output_file_realtive_to_dir(&dir, &generated_file)?;
+            write_output_files_relative_to_dir(&out_dir, &generated_files)?;
         }
-        Some(("create-device-config-defaults", sub_matches)) => {
-            let cache = open_single_file(sub_matches, "cache")?;
-            let output = commands::create_device_config_defaults(cache)
-                .context("failed to create device config defaults")?;
-            let path = get_required_arg::<String>(sub_matches, "out")?;
-            write_output_to_file_or_stdout(path, &output)?;
+        cli_parser::ParsedCommand::CreateCppLib { cache_path, out_dir, mode } => {
+            let generated_files = commands::create_cpp_lib(
+                open_single_file(&cache_path)?, // cache,
+                mode,
+            )
+            .context("failed to create cpp lib")?;
+            write_output_files_relative_to_dir(&out_dir, &generated_files)?;
         }
-        Some(("create-device-config-sysprops", sub_matches)) => {
-            let cache = open_single_file(sub_matches, "cache")?;
-            let output = commands::create_device_config_sysprops(cache)
-                .context("failed to create device config sysprops")?;
-            let path = get_required_arg::<String>(sub_matches, "out")?;
-            write_output_to_file_or_stdout(path, &output)?;
+        cli_parser::ParsedCommand::CreateRustLib { cache_path, out_dir, mode } => {
+            let generated_file = commands::create_rust_lib(
+                open_single_file(&cache_path)?, // cach
+                mode,
+            )
+            .context("failed to create rust lib")?;
+            write_output_files_relative_to_dir(&out_dir, &[generated_file])?;
         }
-        Some(("dump-cache", sub_matches)) => {
-            let input = open_zero_or_more_files(sub_matches, "cache")?;
-            let format = get_required_arg::<DumpFormat>(sub_matches, "format")
-                .context("failed to dump previously parsed flags")?;
-            let filters = sub_matches
-                .get_many::<String>("filter")
-                .unwrap_or_default()
-                .map(String::as_ref)
-                .collect::<Vec<_>>();
-            let dedup = get_required_arg::<bool>(sub_matches, "dedup")?;
-            let output = commands::dump_parsed_flags(input, format.clone(), &filters, *dedup)?;
-            let path = get_required_arg::<String>(sub_matches, "out")?;
-            write_output_to_file_or_stdout(path, &output)?;
+        cli_parser::ParsedCommand::DumpCache { cache_paths, format, filters, dedup, out_path } => {
+            let output = commands::dump_parsed_flags(
+                open_zero_or_more_files(&cache_paths)?,
+                format,
+                &filters,
+                dedup,
+            )?;
+            write_output_to_file_or_stdout(&out_path, &output)?;
         }
-        Some(("create-storage", sub_matches)) => {
-            let version =
-                get_optional_arg::<u32>(sub_matches, "version").unwrap_or(&DEFAULT_FILE_VERSION);
-            if *version > MAX_SUPPORTED_FILE_VERSION {
-                bail!("Invalid version selected ({})", version);
-            }
-            let file = get_required_arg::<StorageFileType>(sub_matches, "file")
-                .context("Invalid storage file selection")?;
-            let cache = open_zero_or_more_files(sub_matches, "cache")?;
-            let container = get_required_arg::<String>(sub_matches, "container")?;
-            let path = get_required_arg::<String>(sub_matches, "out")?;
-
-            let output = commands::create_storage(cache, container, file, *version)
-                .context("failed to create storage files")?;
-            write_output_to_file_or_stdout(path, &output)?;
+        cli_parser::ParsedCommand::CreateStorage {
+            container,
+            file_type,
+            cache_paths,
+            out_path,
+            version,
+        } => {
+            let output = commands::create_storage(
+                open_zero_or_more_files(&cache_paths)?,
+                &container,
+                &file_type,
+                version,
+            )
+            .context("failed to create storage files")?;
+            write_output_to_file_or_stdout(&out_path, &output)?;
         }
-        _ => unreachable!(),
     }
+
     Ok(())
 }
diff --git a/tools/aconfig/aconfig/src/storage/flag_info.rs b/tools/aconfig/aconfig/src/storage/flag_info.rs
index 0943daa86c..68cee240a3 100644
--- a/tools/aconfig/aconfig/src/storage/flag_info.rs
+++ b/tools/aconfig/aconfig/src/storage/flag_info.rs
@@ -14,9 +14,9 @@
  * limitations under the License.
  */
 
-use crate::commands::assign_flag_ids;
+use crate::commands::{assign_flag_ids, should_include_flag};
 use crate::storage::FlagPackage;
-use aconfig_protos::{ProtoFlagPermission, ProtoFlagState};
+use aconfig_protos::ProtoFlagPermission;
 use aconfig_storage_file::{FlagInfoHeader, FlagInfoList, FlagInfoNode, StorageFileType};
 use anyhow::{anyhow, Result};
 
@@ -38,13 +38,8 @@ pub fn create_flag_info(
 ) -> Result<FlagInfoList> {
     // Exclude system/vendor/product flags that are RO+disabled.
     let mut filtered_packages = packages.to_vec();
-    if container == "system" || container == "vendor" || container == "product" {
-        for package in filtered_packages.iter_mut() {
-            package.boolean_flags.retain(|b| {
-                !(b.state == Some(ProtoFlagState::DISABLED.into())
-                    && b.permission == Some(ProtoFlagPermission::READ_ONLY.into()))
-            });
-        }
+    for package in filtered_packages.iter_mut() {
+        package.boolean_flags.retain(|b| should_include_flag(b));
     }
 
     let num_flags = filtered_packages.iter().map(|pkg| pkg.boolean_flags.len() as u32).sum();
diff --git a/tools/aconfig/aconfig/src/storage/flag_value.rs b/tools/aconfig/aconfig/src/storage/flag_value.rs
index 3cfa447098..ad0e75ba87 100644
--- a/tools/aconfig/aconfig/src/storage/flag_value.rs
+++ b/tools/aconfig/aconfig/src/storage/flag_value.rs
@@ -14,9 +14,9 @@
  * limitations under the License.
  */
 
-use crate::commands::assign_flag_ids;
+use crate::commands::{assign_flag_ids, should_include_flag};
 use crate::storage::FlagPackage;
-use aconfig_protos::{ProtoFlagPermission, ProtoFlagState};
+use aconfig_protos::ProtoFlagState;
 use aconfig_storage_file::{FlagValueHeader, FlagValueList, StorageFileType};
 use anyhow::{anyhow, Result};
 
@@ -38,13 +38,8 @@ pub fn create_flag_value(
 ) -> Result<FlagValueList> {
     // Exclude system/vendor/product flags that are RO+disabled.
     let mut filtered_packages = packages.to_vec();
-    if container == "system" || container == "vendor" || container == "product" {
-        for package in filtered_packages.iter_mut() {
-            package.boolean_flags.retain(|b| {
-                !(b.state == Some(ProtoFlagState::DISABLED.into())
-                    && b.permission == Some(ProtoFlagPermission::READ_ONLY.into()))
-            });
-        }
+    for package in filtered_packages.iter_mut() {
+        package.boolean_flags.retain(|b| should_include_flag(b));
     }
     let num_flags = filtered_packages.iter().map(|pkg| pkg.boolean_flags.len() as u32).sum();
     let mut list = FlagValueList {
diff --git a/tools/aconfig/aconfig/src/storage/mod.rs b/tools/aconfig/aconfig/src/storage/mod.rs
index 61e65d1dfc..22c8190a03 100644
--- a/tools/aconfig/aconfig/src/storage/mod.rs
+++ b/tools/aconfig/aconfig/src/storage/mod.rs
@@ -22,12 +22,12 @@ pub mod package_table;
 use anyhow::Result;
 use std::collections::{HashMap, HashSet};
 
-use crate::commands::compute_flags_fingerprint;
+use crate::commands::{compute_flags_fingerprint, should_include_flag};
 use crate::storage::{
     flag_info::create_flag_info, flag_table::create_flag_table, flag_value::create_flag_value,
     package_table::create_package_table,
 };
-use aconfig_protos::{ProtoFlagPermission, ProtoFlagState, ProtoParsedFlag, ProtoParsedFlags};
+use aconfig_protos::{ProtoParsedFlag, ProtoParsedFlags};
 use aconfig_storage_file::StorageFileType;
 
 #[derive(Clone)]
@@ -35,6 +35,7 @@ pub struct FlagPackage<'a> {
     pub package_name: &'a str,
     pub package_id: u32,
     pub fingerprint: u64,
+    pub redact_exported_reads: bool,
     pub flag_names: HashSet<&'a str>,
     pub boolean_flags: Vec<&'a ProtoParsedFlag>,
     // The index of the first boolean flag in this aconfig package among all boolean
@@ -48,6 +49,7 @@ impl<'a> FlagPackage<'a> {
             package_name,
             package_id,
             fingerprint: 0,
+            redact_exported_reads: false,
             flag_names: HashSet::new(),
             boolean_flags: vec![],
             boolean_start_index: 0,
@@ -70,21 +72,15 @@ where
     let mut package_index: HashMap<&str, usize> = HashMap::new();
     for parsed_flags in parsed_flags_vec_iter {
         for parsed_flag in parsed_flags.parsed_flag.iter() {
+            // exclude both platform ro disabled flags as well as flags using device config
+            if !should_include_flag(parsed_flag) {
+                continue;
+            }
+
             let index = *(package_index.entry(parsed_flag.package()).or_insert(packages.len()));
             if index == packages.len() {
                 packages.push(FlagPackage::new(parsed_flag.package(), index as u32));
             }
-
-            // Exclude system/vendor/product flags that are RO+disabled.
-            if (parsed_flag.container == Some("system".to_string())
-                || parsed_flag.container == Some("vendor".to_string())
-                || parsed_flag.container == Some("product".to_string()))
-                && parsed_flag.permission == Some(ProtoFlagPermission::READ_ONLY.into())
-                && parsed_flag.state == Some(ProtoFlagState::DISABLED.into())
-            {
-                continue;
-            }
-
             packages[index].insert(parsed_flag);
         }
     }
@@ -101,6 +97,8 @@ where
             let fingerprint = compute_flags_fingerprint(&mut flag_names_vec);
             p.fingerprint = fingerprint;
         }
+
+        // TODO - b/377311211: Set redact_exported_reads if the build flag is enabled.
     }
 
     packages
@@ -139,10 +137,9 @@ where
 
 #[cfg(test)]
 mod tests {
-    use aconfig_storage_file::DEFAULT_FILE_VERSION;
 
     use super::*;
-    use crate::Input;
+    use crate::commands::Input;
 
     pub fn parse_all_test_flags() -> Vec<ProtoParsedFlags> {
         let aconfig_files = [
@@ -171,9 +168,14 @@ mod tests {
         aconfig_files
             .into_iter()
             .map(|(pkg, aconfig_file, aconfig_content, value_file, value_content)| {
+                let extended_permissions_options = crate::commands::ExtendedPermissionsOptions {
+                    default_permission: crate::commands::DEFAULT_FLAG_PERMISSION,
+                    allow_read_write: true,
+                    force_read_only: false,
+                };
                 let bytes = crate::commands::parse_flags(
                     pkg,
-                    Some("system"),
+                    "system",
                     vec![Input {
                         source: format!("tests/{}", aconfig_file).to_string(),
                         reader: Box::new(aconfig_content),
@@ -182,8 +184,8 @@ mod tests {
                         source: format!("tests/{}", value_file).to_string(),
                         reader: Box::new(value_content),
                     }],
-                    crate::commands::DEFAULT_FLAG_PERMISSION,
-                    true,
+                    None,
+                    extended_permissions_options,
                 )
                 .unwrap();
                 aconfig_protos::parsed_flags::try_from_binary_proto(&bytes).unwrap()
@@ -191,10 +193,11 @@ mod tests {
             .collect()
     }
 
+    // Storage file v1.
     #[test]
     fn test_flag_package() {
         let caches = parse_all_test_flags();
-        let packages = group_flags_by_package(caches.iter(), DEFAULT_FILE_VERSION);
+        let packages = group_flags_by_package(caches.iter(), 1);
 
         for pkg in packages.iter() {
             let pkg_name = pkg.package_name;
@@ -234,6 +237,7 @@ mod tests {
         assert_eq!(packages[2].fingerprint, 0);
     }
 
+    // Storage file v2.
     #[test]
     fn test_flag_package_with_fingerprint() {
         let caches = parse_all_test_flags();
diff --git a/tools/aconfig/aconfig/src/storage/package_table.rs b/tools/aconfig/aconfig/src/storage/package_table.rs
index 53daa7ff2a..09c860ca17 100644
--- a/tools/aconfig/aconfig/src/storage/package_table.rs
+++ b/tools/aconfig/aconfig/src/storage/package_table.rs
@@ -48,6 +48,7 @@ impl PackageTableNodeWrapper {
             package_name: String::from(package.package_name),
             package_id: package.package_id,
             fingerprint: package.fingerprint,
+            redact_exported_reads: package.redact_exported_reads,
             boolean_start_index: package.boolean_start_index,
             next_offset: None,
         };
diff --git a/tools/aconfig/aconfig/src/test.rs b/tools/aconfig/aconfig/src/test.rs
index 10da252ceb..dd4d012f1a 100644
--- a/tools/aconfig/aconfig/src/test.rs
+++ b/tools/aconfig/aconfig/src/test.rs
@@ -49,6 +49,7 @@ parsed_flag {
   container: "system"
   metadata {
     purpose: PURPOSE_UNSPECIFIED
+    storage: NONE
   }
 }
 parsed_flag {
@@ -69,6 +70,7 @@ parsed_flag {
   container: "system"
   metadata {
     purpose: PURPOSE_UNSPECIFIED
+    storage: ACONFIGD
   }
 }
 parsed_flag {
@@ -94,6 +96,7 @@ parsed_flag {
   container: "system"
   metadata {
     purpose: PURPOSE_UNSPECIFIED
+    storage: ACONFIGD
   }
 }
 parsed_flag {
@@ -119,6 +122,7 @@ parsed_flag {
   container: "system"
   metadata {
     purpose: PURPOSE_UNSPECIFIED
+    storage: ACONFIGD
   }
 }
 parsed_flag {
@@ -144,6 +148,7 @@ parsed_flag {
   container: "system"
   metadata {
     purpose: PURPOSE_UNSPECIFIED
+    storage: NONE
   }
 }
 parsed_flag {
@@ -169,6 +174,7 @@ parsed_flag {
   container: "system"
   metadata {
     purpose: PURPOSE_UNSPECIFIED
+    storage: NONE
   }
 }
 parsed_flag {
@@ -199,6 +205,7 @@ parsed_flag {
   container: "system"
   metadata {
     purpose: PURPOSE_BUGFIX
+    storage: NONE
   }
 }
 parsed_flag {
@@ -224,6 +231,7 @@ parsed_flag {
   container: "system"
   metadata {
     purpose: PURPOSE_UNSPECIFIED
+    storage: NONE
   }
 }
 parsed_flag {
@@ -249,14 +257,20 @@ parsed_flag {
   container: "system"
   metadata {
     purpose: PURPOSE_UNSPECIFIED
+    storage: ACONFIGD
   }
 }
 "#;
 
     pub fn parse_read_only_test_flags() -> ProtoParsedFlags {
+        let extended_permissions_options = crate::commands::ExtendedPermissionsOptions {
+            default_permission: crate::commands::DEFAULT_FLAG_PERMISSION,
+            allow_read_write: true,
+            force_read_only: false,
+        };
         let bytes = crate::commands::parse_flags(
             "com.android.aconfig.test",
-            Some("system"),
+            "system",
             vec![Input {
                 source: "tests/read_only_test.aconfig".to_string(),
                 reader: Box::new(include_bytes!("../tests/read_only_test.aconfig").as_slice()),
@@ -265,17 +279,22 @@ parsed_flag {
                 source: "tests/read_only_test.values".to_string(),
                 reader: Box::new(include_bytes!("../tests/read_only_test.values").as_slice()),
             }],
-            crate::commands::DEFAULT_FLAG_PERMISSION,
-            true,
+            None,
+            extended_permissions_options,
         )
         .unwrap();
         aconfig_protos::parsed_flags::try_from_binary_proto(&bytes).unwrap()
     }
 
     pub fn parse_test_flags() -> ProtoParsedFlags {
+        let extended_permissions_options = crate::commands::ExtendedPermissionsOptions {
+            default_permission: crate::commands::DEFAULT_FLAG_PERMISSION,
+            allow_read_write: true,
+            force_read_only: false,
+        };
         let bytes = crate::commands::parse_flags(
             "com.android.aconfig.test",
-            Some("system"),
+            "system",
             vec![Input {
                 source: "tests/test.aconfig".to_string(),
                 reader: Box::new(include_bytes!("../tests/test.aconfig").as_slice()),
@@ -290,17 +309,22 @@ parsed_flag {
                     reader: Box::new(include_bytes!("../tests/second.values").as_slice()),
                 },
             ],
-            crate::commands::DEFAULT_FLAG_PERMISSION,
-            true,
+            None,
+            extended_permissions_options,
         )
         .unwrap();
         aconfig_protos::parsed_flags::try_from_binary_proto(&bytes).unwrap()
     }
 
     pub fn parse_second_package_flags() -> ProtoParsedFlags {
+        let extended_permissions_options = crate::commands::ExtendedPermissionsOptions {
+            default_permission: crate::commands::DEFAULT_FLAG_PERMISSION,
+            allow_read_write: true,
+            force_read_only: false,
+        };
         let bytes = crate::commands::parse_flags(
             "com.android.aconfig.second_test",
-            Some("system"),
+            "system",
             vec![Input {
                 source: "tests/test_second_package.aconfig".to_string(),
                 reader: Box::new(include_bytes!("../tests/test_second_package.aconfig").as_slice()),
@@ -309,8 +333,8 @@ parsed_flag {
                 source: "tests/third.values".to_string(),
                 reader: Box::new(include_bytes!("../tests/third.values").as_slice()),
             }],
-            crate::commands::DEFAULT_FLAG_PERMISSION,
-            true,
+            None,
+            extended_permissions_options,
         )
         .unwrap();
         aconfig_protos::parsed_flags::try_from_binary_proto(&bytes).unwrap()
@@ -333,6 +357,30 @@ parsed_flag {
         }
     }
 
+    /// Asserts that the two strings are equivalent. For use in tests. Fails
+    /// with formatted error message for easier debugging.
+    pub fn assert_no_significant_code_diff(expected: &str, actual: &str) {
+        let expected =
+            expected.lines().map(|line| line.trim_start()).filter(|line| !line.is_empty());
+        let actual = actual.lines().map(|line| line.trim_start()).filter(|line| !line.is_empty());
+        let fail_message: Option<String> =
+            match itertools::diff_with(expected, actual, |left, right| left == right) {
+                Some(itertools::Diff::FirstMismatch(_, mut left, mut right)) => Some(format!(
+                    "DOES NOT MATCH: 1) expected, 2) actual:\n{}\n{}",
+                    left.next().unwrap(),
+                    right.next().unwrap()
+                )),
+                Some(itertools::Diff::Shorter(_, mut left)) => {
+                    Some(format!("LHS trailing data: '{}'", left.next().unwrap()))
+                }
+                Some(itertools::Diff::Longer(_, mut right)) => {
+                    Some(format!("RHS trailing data: '{}'", right.next().unwrap()))
+                }
+                None => None,
+            };
+        assert!(fail_message.is_none(), "{}", fail_message.unwrap());
+    }
+
     #[test]
     fn test_first_significant_code_diff() {
         assert!(first_significant_code_diff("", "").is_none());
diff --git a/tools/aconfig/aconfig/templates/CustomFeatureFlags.java.template b/tools/aconfig/aconfig/templates/CustomFeatureFlags.java.template
index c702c9b1e5..2055b2dc4e 100644
--- a/tools/aconfig/aconfig/templates/CustomFeatureFlags.java.template
+++ b/tools/aconfig/aconfig/templates/CustomFeatureFlags.java.template
@@ -1,9 +1,11 @@
 package {package_name};
 
 {{ if not library_exported- }}
+{{ if support_uau_annotation- }}
 // TODO(b/303773055): Remove the annotation after access issue is resolved.
 import android.compat.annotation.UnsupportedAppUsage;
 {{ -endif }}
+{{ -endif }}
 import java.util.Arrays;
 {{ -if library_exported }}
 import java.util.HashMap;
@@ -35,7 +37,11 @@ public class CustomFeatureFlags implements FeatureFlags \{
 
 {{ -for item in flag_elements}}
     @Override
-{{ if not library_exported }}    @UnsupportedAppUsage{{ -endif }}
+{{ if not library_exported- }}
+{{ if support_uau_annotation- }}
+    @UnsupportedAppUsage
+{{ -endif }}
+{{ -endif }}
     public boolean {item.method_name}() \{
         return getValue(Flags.FLAG_{item.flag_name_constant_suffix},
             FeatureFlags::{item.method_name});
@@ -82,14 +88,14 @@ public class CustomFeatureFlags implements FeatureFlags \{
     );
 
 {{ -if library_exported }}
-    private Map<String, Integer> mFinalizedFlags = new HashMap<>(
+    private Map<String, Boolean> mFinalizedFlags = new HashMap<>(
         Map.ofEntries(
             {{ -for item in flag_elements }}
             {{ -if item.finalized_sdk_present }}
-            Map.entry(Flags.FLAG_{item.flag_name_constant_suffix}, {item.finalized_sdk_value}),
+            Map.entry(Flags.FLAG_{item.flag_name_constant_suffix}, {item.finalized_sdk_check|unescaped} ? true : false),
             {{ -endif }}
             {{ -endfor }}
-            Map.entry("", Integer.MAX_VALUE){# The empty entry to avoid empty entries #}
+            Map.entry("", false){# The empty entry to avoid empty entries #}
         )
     );
 
@@ -97,7 +103,7 @@ public class CustomFeatureFlags implements FeatureFlags \{
         if (!mFinalizedFlags.containsKey(flagName)) \{
             return false;
         }
-        return Build.VERSION.SDK_INT >= mFinalizedFlags.get(flagName);
+        return mFinalizedFlags.get(flagName);
     }
 {{ -endif }}
 }
diff --git a/tools/aconfig/aconfig/templates/ExportedFlags.java.template b/tools/aconfig/aconfig/templates/ExportedFlags.java.template
index 176da18186..d46777677d 100644
--- a/tools/aconfig/aconfig/templates/ExportedFlags.java.template
+++ b/tools/aconfig/aconfig/templates/ExportedFlags.java.template
@@ -37,7 +37,7 @@ public final class ExportedFlags \{
 {{ -for flag in flag_elements }}
     public static boolean {flag.method_name}() \{
         {{ -if flag.finalized_sdk_present }}
-        if (Build.VERSION.SDK_INT >= {flag.finalized_sdk_value}) \{
+        if ({flag.finalized_sdk_check|unescaped}) \{
           return true;
         }
         {{ -endif}}  {#- end finalized_sdk_present#}
diff --git a/tools/aconfig/aconfig/templates/FeatureFlags.java.template b/tools/aconfig/aconfig/templates/FeatureFlags.java.template
index c8b9b7f263..0d485b71d2 100644
--- a/tools/aconfig/aconfig/templates/FeatureFlags.java.template
+++ b/tools/aconfig/aconfig/templates/FeatureFlags.java.template
@@ -1,8 +1,10 @@
 package {package_name};
 {{ if not library_exported- }}
+{{ if support_uau_annotation- }}
 // TODO(b/303773055): Remove the annotation after access issue is resolved.
 import android.compat.annotation.UnsupportedAppUsage;
 {{ -endif }}
+{{ -endif }}
 {{ -if single_exported_file }}
 {{ -if library_exported }}
 /**
@@ -24,7 +26,9 @@ public interface FeatureFlags \{
 {{ -endif }}
 {{ -if not library_exported }}
     @com.android.aconfig.annotations.AconfigFlagAccessor
+{{ if support_uau_annotation- }}
     @UnsupportedAppUsage
+{{ -endif }}
 {{ -endif }}
     boolean {item.method_name}();
 {{ -endfor }}
diff --git a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.deviceConfig.java.template b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.deviceConfig.java.template
index 44d5cc019b..4589bf4c46 100644
--- a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.deviceConfig.java.template
+++ b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.deviceConfig.java.template
@@ -1,7 +1,9 @@
 package {package_name};
 {{ if not library_exported- }}
+{{ if support_uau_annotation- }}
 // TODO(b/303773055): Remove the annotation after access issue is resolved.
 import android.compat.annotation.UnsupportedAppUsage;
+{{ -endif }}
 {{ -endif }} {#- end of not library_exported#}
 {{ -if runtime_lookup_required }}
 import android.os.Binder;
@@ -52,7 +54,9 @@ public final class FeatureFlagsImpl implements FeatureFlags \{
     @Override
 {{ -if not library_exported }}
     @com.android.aconfig.annotations.AconfigFlagAccessor
+{{ if support_uau_annotation- }}
     @UnsupportedAppUsage
+{{ -endif }}
 {{ -endif }}{#- end of not library_exported #}
     public boolean {flag.method_name}() \{
 {{ -if flag.is_read_write }}
diff --git a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.exported.java.template b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.exported.java.template
index b843ec2441..8ff9dbe1ab 100644
--- a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.exported.java.template
+++ b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.exported.java.template
@@ -25,7 +25,7 @@ public final class FeatureFlagsImpl implements FeatureFlags \{
             {{ -for namespace_with_flags in namespace_flags }}
             {{ -for flag in namespace_with_flags.flags }}
             {{ -if flag.finalized_sdk_present }}
-            {flag.method_name} = Build.VERSION.SDK_INT >= {flag.finalized_sdk_value} ? true : reader.getBooleanFlagValue("{flag.flag_name}", {flag.default_value});
+            {flag.method_name} = {flag.finalized_sdk_check|unescaped} ? true : reader.getBooleanFlagValue("{flag.flag_name}", {flag.default_value});
             {{ - else }} {#- else finalized_sdk_present #}
             {flag.method_name} = reader.getBooleanFlagValue("{flag.flag_name}", {flag.default_value});
             {{ -endif}}  {#- end finalized_sdk_present#}
diff --git a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.legacy_flag.internal.java.template b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.legacy_flag.internal.java.template
new file mode 100644
index 0000000000..77dd2b2441
--- /dev/null
+++ b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.legacy_flag.internal.java.template
@@ -0,0 +1,34 @@
+package {package_name};
+{{ -if runtime_lookup_required }}
+import android.provider.DeviceConfig;
+{{ -endif }}  {#- end of runtime_lookup_required#}
+/** @hide */
+public final class FeatureFlagsImpl implements FeatureFlags \{
+{{ -for flag in flag_elements }}
+    @Override
+{{ -if not library_exported }}
+    @com.android.aconfig.annotations.AconfigFlagAccessor
+{{ -endif }}{#- end of not library_exported #}
+    public boolean {flag.method_name}() \{
+{{ -if flag.is_read_write }}
+        try \{
+            return DeviceConfig.getBoolean(
+                "{flag.device_config_namespace}",
+                Flags.FLAG_{flag.flag_name_constant_suffix},
+                {flag.default_value});
+        } catch (NullPointerException e) \{
+            throw new RuntimeException(
+                "Cannot read value from namespace {flag.device_config_namespace} "
+                + "from DeviceConfig. It could be that the code using flag "
+                + "executed before SettingsProvider initialization. Please use "
+                + "fixed read-only flag by adding is_fixed_read_only: true in "
+                + "flag declaration.",
+                e
+            );
+        }
+{{ -else }} {#- else is_read_write #}
+        return {flag.default_value};
+{{ -endif }}{#- end of is_read_write #}
+    }
+{{ endfor }}
+}
diff --git a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.new_storage.java.template b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.new_storage.java.template
index 8dc7581193..0a9d6e41e8 100644
--- a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.new_storage.java.template
+++ b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.new_storage.java.template
@@ -1,6 +1,8 @@
 package {package_name}; {#- CODEGEN FOR INTERNAL MODE FOR NEW STORAGE #}
+{{ if support_uau_annotation- }}
 // TODO(b/303773055): Remove the annotation after access issue is resolved.
 import android.compat.annotation.UnsupportedAppUsage;
+{{ -endif }}
 {{ -if runtime_lookup_required }}
 {{ if is_platform_container }}
 import android.os.flagging.PlatformAconfigPackageInternal;
@@ -47,7 +49,9 @@ public final class FeatureFlagsImpl implements FeatureFlags \{
 {{ -for flag in flag_elements }}
     @Override
     @com.android.aconfig.annotations.AconfigFlagAccessor
+{{ if support_uau_annotation- }}
     @UnsupportedAppUsage
+{{ -endif }}
     public boolean {flag.method_name}() \{
 {{ -if flag.is_read_write }}
         if (!isCached) \{
diff --git a/tools/aconfig/aconfig/templates/Flags.java.template b/tools/aconfig/aconfig/templates/Flags.java.template
index 0cdc2692ca..b631d00c64 100644
--- a/tools/aconfig/aconfig/templates/Flags.java.template
+++ b/tools/aconfig/aconfig/templates/Flags.java.template
@@ -1,7 +1,9 @@
 package {package_name};
 {{ if not library_exported- }}
+{{ if support_uau_annotation- }}
 // TODO(b/303773055): Remove the annotation after access issue is resolved.
 import android.compat.annotation.UnsupportedAppUsage;
+{{ -endif }}
 {{ else }}
 import android.os.Build;
 {{ -endif }} {#- end not library_exported#}
@@ -30,12 +32,14 @@ public final class Flags \{
 {{ -endif }}
 {{ -if not library_exported }}
     @com.android.aconfig.annotations.AconfigFlagAccessor
+{{ -if support_uau_annotation- }}
     @UnsupportedAppUsage
+{{ -endif }}
 {{ -endif }}
     public static boolean {item.method_name}() \{
         {{ if library_exported- }}
         {{ -if item.finalized_sdk_present }}
-        if (Build.VERSION.SDK_INT >= {item.finalized_sdk_value}) \{
+        if ({item.finalized_sdk_check|unescaped}) \{
           return true;
         }
         {{ -endif}}  {#- end finalized_sdk_present#}
diff --git a/tools/aconfig/aconfig/templates/cpp_exported_header.template b/tools/aconfig/aconfig/templates/cpp_exported_header.template
index f6f576a29e..a752cc98e2 100644
--- a/tools/aconfig/aconfig/templates/cpp_exported_header.template
+++ b/tools/aconfig/aconfig/templates/cpp_exported_header.template
@@ -1,5 +1,22 @@
 #pragma once
 
+{{ if not is_test_mode }}
+{{ if readwrite- }}
+// Avoid destruction for thread safety.
+// Only enable this with clang.
+#if defined(__clang__)
+#ifndef ACONFIG_NO_DESTROY
+#define ACONFIG_NO_DESTROY [[clang::no_destroy]]
+#endif
+#else
+#warning "not built with clang disable no_destroy"
+#ifndef ACONFIG_NO_DESTROY
+#define ACONFIG_NO_DESTROY
+#endif
+#endif
+{{ -endif }}
+{{ -endif }}
+
 {{ if not is_test_mode- }}
 {{ if has_fixed_read_only- }}
 #ifndef {package_macro}
@@ -38,7 +55,7 @@ public:
     {{ -endif }}
 };
 
-extern std::unique_ptr<flag_provider_interface> provider_;
+{{ if not is_test_mode }}{{ if readwrite }}ACONFIG_NO_DESTROY{{ endif }}{{ endif }} extern std::unique_ptr<flag_provider_interface> provider_;
 
 {{ for item in class_elements}}
 {{ if not is_test_mode }}{{ if item.is_fixed_read_only }}constexpr {{ endif }}{{ endif -}}
diff --git a/tools/aconfig/aconfig/templates/cpp_source_file.template b/tools/aconfig/aconfig/templates/cpp_source_file.template
index 36ab774f54..a235679642 100644
--- a/tools/aconfig/aconfig/templates/cpp_source_file.template
+++ b/tools/aconfig/aconfig/templates/cpp_source_file.template
@@ -13,6 +13,7 @@
 #include <string>
 {{ -else- }}
 {{ if readwrite- }}
+#include <atomic>
 #include <vector>
 {{ -endif }}
 {{ -endif }}
@@ -30,6 +31,10 @@ namespace {cpp_namespace} \{
         std::unique_ptr<aconfig_storage::MappedStorageFile> flag_value_file_;
 
         bool package_exists_in_storage_;
+
+        {{ if use_package_fingerprint- }}
+        bool fingerprint_matches_;
+        {{ -endif }}{#- end of use_package_fingerprint #}
     {{ -endif }}
 
     public:
@@ -38,14 +43,22 @@ namespace {cpp_namespace} \{
             : overrides_()
             , boolean_start_index_()
             , flag_value_file_(nullptr)
+            {{ if use_package_fingerprint- }}
+            , package_exists_in_storage_(true)
+            , fingerprint_matches_(true) \{
+            {{ -else }}
             , package_exists_in_storage_(true) \{
+            {{ -endif }}{#- end of use_package_fingerprint #}
 
             auto package_map_file = aconfig_storage::get_mapped_file(
                  "{container}",
                  aconfig_storage::StorageFileType::package_map);
 
             if (!package_map_file.ok()) \{
+// Host doesn't have the package map file.
+#ifdef __ANDROID__
                 ALOGE("error: failed to get package map file: %s", package_map_file.error().c_str());
+#endif
                 package_exists_in_storage_ = false;
                 return;
             }
@@ -63,6 +76,14 @@ namespace {cpp_namespace} \{
                 package_exists_in_storage_ = false;
                 return;
             }
+            {{ if use_package_fingerprint- }}
+
+                if (context->fingerprint != { package_fingerprint }ULL) \{
+                    ALOGE("Fingerprint mismatch for package {package}.");
+                    fingerprint_matches_ = false;
+                    return;
+                }
+            {{ -endif }}{#- end of use_package_fingerprint #}
 
             // cache package boolean flag start index
             boolean_start_index_ = context->boolean_start_index;
@@ -98,8 +119,16 @@ namespace {cpp_namespace} \{
             } else \{
                 {{ if item.readwrite- }}
                 if (!package_exists_in_storage_) \{
+                    ALOGE("error: package does not exist, returning flag default value.");
                     return {item.default_value};
                 }
+                {{ if use_package_fingerprint- }}
+
+                if (!fingerprint_matches_) \{
+                    ALOGE("error: package fingerprint mismtach, returning flag default value.");
+                    return {item.default_value};
+                }
+                {{ -endif }}{#- end of use_package_fingerprint #}
 
                 auto value = aconfig_storage::get_boolean_flag_value(
                     *flag_value_file_,
@@ -134,16 +163,27 @@ namespace {cpp_namespace} \{
 
         {{ if readwrite- }}
         flag_provider()
-            : cache_({readwrite_count}, -1)
+            : cache_({readwrite_count})
             , boolean_start_index_()
             , flag_value_file_(nullptr)
+            {{ if use_package_fingerprint- }}
+            , package_exists_in_storage_(true)
+            , fingerprint_matches_(true) \{
+            {{ -else }}
             , package_exists_in_storage_(true) \{
+            {{ -endif }}{#- end of use_package_fingerprint #}
+            for (size_t i = 0 ; i < {readwrite_count}; i++) \{
+                cache_[i] = -1;
+            }
 
             auto package_map_file = aconfig_storage::get_mapped_file(
                  "{container}",
                  aconfig_storage::StorageFileType::package_map);
             if (!package_map_file.ok()) \{
+// Host doesn't have the package map file.
+#ifdef __ANDROID__
                 ALOGE("error: failed to get package map file: %s", package_map_file.error().c_str());
+#endif
                 package_exists_in_storage_ = false;
                 return;
             }
@@ -160,6 +200,14 @@ namespace {cpp_namespace} \{
                 package_exists_in_storage_ = false;
                 return;
             }
+            {{ if use_package_fingerprint- }}
+
+                if (context->fingerprint != { package_fingerprint }ULL) \{
+                    ALOGE("Fingerprint mismatch for package {package}.");
+                    fingerprint_matches_ = false;
+                    return;
+                }
+            {{ -endif }}{#- end of use_package_fingerprint #}
 
             // cache package boolean flag start index
             boolean_start_index_ = context->boolean_start_index;
@@ -186,10 +234,18 @@ namespace {cpp_namespace} \{
         {{ -for item in class_elements }}
         virtual bool {item.flag_name}() override \{
             {{ -if item.readwrite }}
-            if (cache_[{item.readwrite_idx}] == -1) \{
+            if (cache_[{item.readwrite_idx}].load(std::memory_order_relaxed) == -1) \{
                 if (!package_exists_in_storage_) \{
+                    ALOGE("error: package does not exist, returning flag default value.");
                     return {item.default_value};
                 }
+                {{ if use_package_fingerprint- }}
+
+                if (!fingerprint_matches_) \{
+                    ALOGE("error: package fingerprint mismtach, returning flag default value.");
+                    return {item.default_value};
+                }
+                {{ -endif }}{#- end of use_package_fingerprint #}
 
                 auto value = aconfig_storage::get_boolean_flag_value(
                     *flag_value_file_,
@@ -200,9 +256,9 @@ namespace {cpp_namespace} \{
                     return {item.default_value};
                 }
 
-                cache_[{item.readwrite_idx}] = *value;
+                cache_[{item.readwrite_idx}].store(*value, std::memory_order_relaxed);
             }
-            return cache_[{item.readwrite_idx}];
+            return cache_[{item.readwrite_idx}].load(std::memory_order_relaxed);
             {{ -else }}
             {{ -if item.is_fixed_read_only }}
             return {package_macro}_{item.flag_macro};
@@ -215,13 +271,17 @@ namespace {cpp_namespace} \{
 
     {{ if readwrite- }}
     private:
-        std::vector<int8_t> cache_ = std::vector<int8_t>({readwrite_count}, -1);
+        std::vector<std::atomic_int8_t> cache_;
 
         uint32_t boolean_start_index_;
 
         std::unique_ptr<aconfig_storage::MappedStorageFile> flag_value_file_;
 
         bool package_exists_in_storage_;
+        {{ if use_package_fingerprint- }}
+
+        bool fingerprint_matches_;
+        {{ -endif }}{#- end of use_package_fingerprint #}
     {{ -endif }}
 
     };
diff --git a/tools/aconfig/aconfig/templates/rust.template b/tools/aconfig/aconfig/templates/rust.template
index 56323e25ca..292beae87e 100644
--- a/tools/aconfig/aconfig/templates/rust.template
+++ b/tools/aconfig/aconfig/templates/rust.template
@@ -9,10 +9,9 @@ use log::\{log, LevelFilter, Level};
 pub struct FlagProvider;
 
 {{ if has_readwrite- }}
-static PACKAGE_OFFSET: LazyLock<Result<Option<u32>, AconfigStorageError>> = LazyLock::new(|| unsafe \{
+static PACKAGE_CONTEXT: LazyLock<Result<Option<PackageReadContext>, AconfigStorageError>> = LazyLock::new(|| unsafe \{
     get_mapped_storage_file("{container}", StorageFileType::PackageMap)
     .and_then(|package_map| get_package_read_context(&package_map, "{package}"))
-    .map(|context| context.map(|c| c.boolean_start_index))
 });
 
 static FLAG_VAL_MAP: LazyLock<Result<Mmap, AconfigStorageError>> = LazyLock::new(|| unsafe \{
@@ -30,17 +29,38 @@ static CACHED_{flag.name}: LazyLock<bool> = LazyLock::new(|| \{
             .with_tag_on_device("aconfig_rust_codegen")
             .with_max_level(LevelFilter::Info));
 
+    {{ -if use_package_fingerprint }}
+    let fingerprint_check_failed: bool = PACKAGE_CONTEXT
+        .as_ref()
+        .is_ok_and(|package_context| \{
+              match package_context \{
+                Some(context) => \{
+                        return context.fingerprint != {package_fingerprint}
+                    },
+                    None => \{
+                        log!(Level::Info, "aconfig_rust_codegen: missing fingerprint; performing lookup.");
+                        false
+                    }
+                  }
+                });
+
+    if fingerprint_check_failed \{
+      log!(Level::Error, "Fingerprint mismatch for package {package}; returning flag default ({flag.default_value}) for {flag.name}.");
+      return {flag.default_value};
+    }
+    {{ -endif }}
+
     let flag_value_result = FLAG_VAL_MAP
         .as_ref()
         .map_err(|err| format!("failed to get flag val map: \{err}"))
         .and_then(|flag_val_map| \{
-            PACKAGE_OFFSET
+            PACKAGE_CONTEXT
                 .as_ref()
-                .map_err(|err| format!("failed to get package read offset: \{err}"))
-                .and_then(|package_offset| \{
-                    match package_offset \{
-                        Some(offset) => \{
-                            get_boolean_flag_value(&flag_val_map, offset + {flag.flag_offset})
+                .map_err(|err| format!("failed to get package read context: \{err}"))
+                .and_then(|package_context| \{
+                    match package_context \{
+                        Some(context) => \{
+                            get_boolean_flag_value(&flag_val_map, context.boolean_start_index + {flag.flag_offset})
                                 .map_err(|err| format!("failed to get flag: \{err}"))
                         },
                         None => \{
diff --git a/tools/aconfig/aconfig/templates/rust_test.template b/tools/aconfig/aconfig/templates/rust_test.template
index 139a5ec62a..66f7817f2b 100644
--- a/tools/aconfig/aconfig/templates/rust_test.template
+++ b/tools/aconfig/aconfig/templates/rust_test.template
@@ -12,10 +12,9 @@ pub struct FlagProvider \{
 }
 
 {{ if has_readwrite- }}
-static PACKAGE_OFFSET: LazyLock<Result<Option<u32>, AconfigStorageError>> = LazyLock::new(|| unsafe \{
+static PACKAGE_CONTEXT: LazyLock<Result<Option<PackageReadContext>, AconfigStorageError>> = LazyLock::new(|| unsafe \{
     get_mapped_storage_file("{container}", StorageFileType::PackageMap)
     .and_then(|package_map| get_package_read_context(&package_map, "{package}"))
-    .map(|context| context.map(|c| c.boolean_start_index))
 });
 
 static FLAG_VAL_MAP: LazyLock<Result<Mmap, AconfigStorageError>> = LazyLock::new(|| unsafe \{
@@ -33,17 +32,38 @@ static CACHED_{flag.name}: LazyLock<bool> = LazyLock::new(|| \{
             .with_tag_on_device("aconfig_rust_codegen")
             .with_max_level(LevelFilter::Info));
 
+    {{ -if use_package_fingerprint }}
+    let fingerprint_check_failed: bool = PACKAGE_CONTEXT
+        .as_ref()
+        .is_ok_and(|package_context| \{
+              match package_context \{
+                Some(context) => \{
+                        return context.fingerprint != {package_fingerprint}
+                    },
+                    None => \{
+                        log!(Level::Info, "aconfig_rust_codegen: missing fingerprint; performing lookup.");
+                        false
+                    }
+                  }
+                });
+
+    if fingerprint_check_failed \{
+      log!(Level::Error, "Fingerprint mismatch for package {package}; returning flag default ({flag.default_value}) for {flag.name}.");
+      return {flag.default_value};
+    }
+    {{ -endif }}
+
     let flag_value_result = FLAG_VAL_MAP
         .as_ref()
         .map_err(|err| format!("failed to get flag val map: \{err}"))
         .and_then(|flag_val_map| \{
-            PACKAGE_OFFSET
+            PACKAGE_CONTEXT
                 .as_ref()
-                .map_err(|err| format!("failed to get package read offset: \{err}"))
-                .and_then(|package_offset| \{
-                    match package_offset \{
-                        Some(offset) => \{
-                            get_boolean_flag_value(&flag_val_map, offset + {flag.flag_offset})
+                .map_err(|err| format!("failed to get package read context: \{err}"))
+                .and_then(|package_context| \{
+                    match package_context \{
+                        Some(context) => \{
+                            get_boolean_flag_value(&flag_val_map, context.boolean_start_index + {flag.flag_offset})
                                 .map_err(|err| format!("failed to get flag: \{err}"))
                         },
                         None => \{
diff --git a/tools/aconfig/aconfig/tests/AconfigTest.java b/tools/aconfig/aconfig/tests/AconfigTest.java
index 7e76efba3c..8037feaf3d 100644
--- a/tools/aconfig/aconfig/tests/AconfigTest.java
+++ b/tools/aconfig/aconfig/tests/AconfigTest.java
@@ -11,6 +11,10 @@ import static com.android.aconfig.test.Flags.enabledRw;
 import static com.android.aconfig.test.exported.Flags.exportedFlag;
 import static com.android.aconfig.test.exported.Flags.FLAG_EXPORTED_FLAG;
 import static com.android.aconfig.test.forcereadonly.Flags.froRw;
+import static com.android.aconfig.test.mainline_beta.Flags.betaDisabledRw;
+import static com.android.aconfig.test.mainline_beta.Flags.betaEnabledRw;
+import static com.android.aconfig.test.mainline_beta.Flags.betaDisabledFixedRo;
+import static com.android.aconfig.test.exported.mainline_beta.Flags.exportedBetaDisabledRw;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertThrows;
@@ -72,4 +76,24 @@ public final class AconfigTest {
     public void testForceReadOnly() {
         assertFalse(froRw());
     }
+
+	@Test
+    public void testBetaDisabledRw() {
+        assertFalse(betaDisabledRw());
+    }
+
+	@Test
+    public void testBetaEnabledRw() {
+        assertTrue(betaEnabledRw());
+    }
+
+	@Test
+    public void testBetaDisabledFixedRo() {
+        assertFalse(betaDisabledFixedRo());
+    }
+
+	@Test
+    public void testExportedBetaDisabledRw() {
+        assertFalse(exportedBetaDisabledRw());
+    }
 }
diff --git a/tools/aconfig/aconfig/tests/mainline_beta_exported_mockup.aconfig b/tools/aconfig/aconfig/tests/mainline_beta_exported_mockup.aconfig
new file mode 100644
index 0000000000..1c72399785
--- /dev/null
+++ b/tools/aconfig/aconfig/tests/mainline_beta_exported_mockup.aconfig
@@ -0,0 +1,25 @@
+package: "com.android.aconfig.test.exported.mainline_beta"
+container: "com.android.mainline_beta_mockup"
+
+flag {
+    name: "exported_beta_disabled_rw"
+    namespace: "com_android_mainline_beta_mockup"
+    description: "exported disabled rw mainline beta flag."
+    bug: "123456789"
+    is_exported: true
+}
+
+flag {
+    name: "exported_beta_enabled_rw"
+    namespace: "com_android_mainline_beta_mockup"
+    description: "exported enabled rw mainline beta flag."
+    bug: "123456789"
+    is_exported: true
+}
+
+flag {
+    name: "beta_enabled_rw"
+    namespace: "com_android_mainline_beta_mockup"
+    description: "enabled rw mainline beta flag."
+    bug: "123456789"
+}
diff --git a/tools/aconfig/aconfig/tests/mainline_beta_mockup.aconfig b/tools/aconfig/aconfig/tests/mainline_beta_mockup.aconfig
new file mode 100644
index 0000000000..8a4526da28
--- /dev/null
+++ b/tools/aconfig/aconfig/tests/mainline_beta_mockup.aconfig
@@ -0,0 +1,24 @@
+package: "com.android.aconfig.test.mainline_beta"
+container: "com.android.mainline_beta_mockup"
+
+flag {
+    name: "beta_disabled_rw"
+    namespace: "com_android_mainline_beta_mockup"
+    description: "disabled rw mainline beta flag."
+    bug: "123456789"
+}
+
+flag {
+    name: "beta_enabled_rw"
+    namespace: "com_android_mainline_beta_mockup"
+    description: "enabled rw mainline beta flag."
+    bug: "123456789"
+}
+
+flag {
+    name: "beta_disabled_fixed_ro"
+    namespace: "com_android_mainline_beta_mockup"
+    description: "fixed read only mainline beta flag."
+    is_fixed_read_only: true
+    bug: "123456789"
+}
diff --git a/tools/aconfig/aconfig/tests/mainline_beta_mockup.values b/tools/aconfig/aconfig/tests/mainline_beta_mockup.values
new file mode 100644
index 0000000000..7ad0263156
--- /dev/null
+++ b/tools/aconfig/aconfig/tests/mainline_beta_mockup.values
@@ -0,0 +1,18 @@
+flag_value {
+    package: "com.android.aconfig.test.mainline_beta"
+    name: "beta_disabled_rw"
+    state: DISABLED
+    permission: READ_WRITE
+}
+flag_value {
+    package: "com.android.aconfig.test.mainline_beta"
+    name: "beta_enabled_rw"
+    state: ENABLED
+    permission: READ_WRITE
+}
+flag_value {
+    package: "com.android.aconfig.test.mainline_beta"
+    name: "beta_disabled_fixed_ro"
+    state: DISABLED
+    permission: READ_ONLY
+}
diff --git a/tools/aconfig/aconfig/tests/mainline_beta_namespaces.json b/tools/aconfig/aconfig/tests/mainline_beta_namespaces.json
new file mode 100644
index 0000000000..e320f5122b
--- /dev/null
+++ b/tools/aconfig/aconfig/tests/mainline_beta_namespaces.json
@@ -0,0 +1,24 @@
+{
+    "namespaces": {
+        "com_android_tethering": {
+            "container": "com.android.tethering",
+            "allow_exported": true
+        },
+        "com_android_networkstack": {
+            "container": "com.android.networkstack",
+            "allow_exported": false
+        },
+        "com_android_captiveportallogin": {
+            "container": "com.android.captiveportallogin",
+            "allow_exported": false
+        },
+        "com_android_healthfitness": {
+            "container": "com.android.healthfitness",
+            "allow_exported": true
+        },
+        "com_android_mediaprovider": {
+            "container": "com.android.mediaprovider",
+            "allow_exported": true
+        }
+    }
+}
diff --git a/tools/aconfig/aconfig_device_paths/src/DeviceProtosTemplate.java b/tools/aconfig/aconfig_device_paths/src/DeviceProtosTemplate.java
index 4d4119947f..bad5fcc1f0 100644
--- a/tools/aconfig/aconfig_device_paths/src/DeviceProtosTemplate.java
+++ b/tools/aconfig/aconfig_device_paths/src/DeviceProtosTemplate.java
@@ -27,6 +27,8 @@ import java.util.List;
 
 /**
  * @hide
+ *
+ * Note this class does _not_ work on Ravenwood (yet). Contact g/ravenwood if you need it.
  */
 public class DeviceProtos {
 	public static final String[] PATHS = {
diff --git a/tools/aconfig/aconfig_device_paths/src/DeviceProtosTestUtilTemplate.java b/tools/aconfig/aconfig_device_paths/src/DeviceProtosTestUtilTemplate.java
index 45d67663ef..e34593568a 100644
--- a/tools/aconfig/aconfig_device_paths/src/DeviceProtosTestUtilTemplate.java
+++ b/tools/aconfig/aconfig_device_paths/src/DeviceProtosTestUtilTemplate.java
@@ -25,12 +25,44 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 
-/** @hide */
+/**
+ * Utility class to load protobuf storage files.
+ *
+ * This class _does_ support Ravenwood.
+ *
+ * In order to avoid adding extra dependencies, this class doesn't use Ravenwood annotations
+ * or RavenwoodHelper.java. Instead, we just hardcode relevant logic.
+ *
+ * @hide
+ */
 public class DeviceProtosTestUtil {
-    public static final String[] PATHS = {
+    private static final String[] PATHS_DEVICE = {
         TEMPLATE
     };
 
+    /** Path to ravenwood runtime, or null on non-ravenwood environment. */
+    private static final String RAVENWOOD_RUNTIME_PATH
+            = System.getProperty("android.ravenwood.runtime_path");
+
+    /** True if on ravenwood */
+    private static final boolean ON_RAVENWOOD = RAVENWOOD_RUNTIME_PATH != null;
+
+    private static String[] getPaths() {
+        if (!ON_RAVENWOOD) {
+            return PATHS_DEVICE;
+        }
+        return new String[] {
+            RAVENWOOD_RUNTIME_PATH + "/aconfig/metadata/aconfig/etc/all_aconfig_declarations.pb"
+        };
+    }
+
+    /**
+     * Protobuf storage files. On the device side, this array contains multiple files, one
+     * from each partition. On Ravenwood, this contains a single protobuf file containing all the
+     * flags.
+     */
+    public static final String[] PATHS = getPaths();
+
     private static final String APEX_DIR = "/apex/";
     private static final String APEX_ACONFIG_PATH_SUFFIX = "/etc/aconfig_flags.pb";
     private static final String SYSTEM_APEX_DIR = "/system/apex";
@@ -67,6 +99,10 @@ public class DeviceProtosTestUtil {
     public static List<String> parsedFlagsProtoPaths() {
         ArrayList<String> paths = new ArrayList(Arrays.asList(PATHS));
 
+        if (ON_RAVENWOOD) {
+            return paths; // No apexes on Ravenwood.
+        }
+
         File apexDirectory = new File(SYSTEM_APEX_DIR);
         if (!apexDirectory.isDirectory()) {
             return paths;
diff --git a/tools/aconfig/aconfig_flags/src/lib.rs b/tools/aconfig/aconfig_flags/src/lib.rs
index dc507aef6f..78d78c4094 100644
--- a/tools/aconfig/aconfig_flags/src/lib.rs
+++ b/tools/aconfig/aconfig_flags/src/lib.rs
@@ -30,11 +30,6 @@
 /// Module used when building with the Android tool-chain
 #[cfg(not(feature = "cargo"))]
 pub mod auto_generated {
-    /// Returns the value for the enable_only_new_storage flag.
-    pub fn enable_only_new_storage() -> bool {
-        aconfig_flags_rust::enable_only_new_storage()
-    }
-
     /// Returns the value for the enable_aconfigd_from_mainline flag.
     pub fn enable_aconfigd_from_mainline() -> bool {
         aconfig_flags_rust::enable_only_new_storage()
@@ -49,12 +44,6 @@ pub mod auto_generated {
 /// Module used when building with cargo
 #[cfg(feature = "cargo")]
 pub mod auto_generated {
-    /// Returns a placeholder value for the enable_only_new_storage flag.
-    pub fn enable_only_new_storage() -> bool {
-        // Used only to enable typechecking and testing with cargo
-        true
-    }
-
     /// Returns a placeholder value for the enable_aconfigd_from_mainline flag.
     pub fn enable_aconfigd_from_mainline() -> bool {
         // Used only to enable typechecking and testing with cargo
diff --git a/tools/aconfig/aconfig_protos/protos/aconfig.proto b/tools/aconfig/aconfig_protos/protos/aconfig.proto
index 9d1b8cbfbf..99017bc55e 100644
--- a/tools/aconfig/aconfig_protos/protos/aconfig.proto
+++ b/tools/aconfig/aconfig_protos/protos/aconfig.proto
@@ -106,8 +106,18 @@ message flag_metadata {
     PURPOSE_BUGFIX = 2;
   }
 
+  // storage backend for flag
+  enum flag_storage_backend {
+    UNSPECIFIED = 0;    // unspecified, let aconfig choose one
+    ACONFIGD = 1;       // aconfigd based new storage
+    DEVICE_CONFIG = 2;  // device config based legacy storage
+    NONE = 3;           // no need for flag storage
+  }
+
   optional flag_purpose purpose = 1;
 
+  optional flag_storage_backend storage = 2;
+
   // TODO(b/315025930): Add field to designate intended target device form factor(s), such as phone, watch or other.
 }
 
diff --git a/tools/aconfig/aconfig_protos/src/lib.rs b/tools/aconfig/aconfig_protos/src/lib.rs
index 64b82d6796..e2803a03ec 100644
--- a/tools/aconfig/aconfig_protos/src/lib.rs
+++ b/tools/aconfig/aconfig_protos/src/lib.rs
@@ -31,6 +31,7 @@
 #[cfg(not(feature = "cargo"))]
 mod auto_generated {
     pub use aconfig_rust_proto::aconfig::flag_metadata::Flag_purpose as ProtoFlagPurpose;
+    pub use aconfig_rust_proto::aconfig::flag_metadata::Flag_storage_backend as ProtoFlagStorageBackend;
     pub use aconfig_rust_proto::aconfig::Flag_declaration as ProtoFlagDeclaration;
     pub use aconfig_rust_proto::aconfig::Flag_declarations as ProtoFlagDeclarations;
     pub use aconfig_rust_proto::aconfig::Flag_metadata as ProtoFlagMetadata;
@@ -51,6 +52,7 @@ mod auto_generated {
     // Android tool-chain, we allow it
     include!(concat!(env!("OUT_DIR"), "/aconfig_proto/mod.rs"));
     pub use aconfig::flag_metadata::Flag_purpose as ProtoFlagPurpose;
+    pub use aconfig::flag_metadata::Flag_storage_backend as ProtoFlagStorageBackend;
     pub use aconfig::Flag_declaration as ProtoFlagDeclaration;
     pub use aconfig::Flag_declarations as ProtoFlagDeclarations;
     pub use aconfig::Flag_metadata as ProtoFlagMetadata;
@@ -142,6 +144,11 @@ pub mod flag_declaration {
         ensure!(!pdf.description().is_empty(), "bad flag declaration: empty description");
         ensure!(pdf.bug.len() == 1, "bad flag declaration: exactly one bug required");
 
+        ensure!(
+            !pdf.metadata.has_storage(),
+            "bad flag declaration: storage in metadata should not be explicitly selected"
+        );
+
         Ok(())
     }
 }
@@ -321,10 +328,31 @@ pub mod parsed_flag {
                 );
             }
         }
+        match pf.permission() {
+            ProtoFlagPermission::READ_ONLY => {
+                ensure!(
+                    pf.metadata.storage() == ProtoFlagStorageBackend::NONE,
+                    "bad parsed flag: storage backend is not NONE for a read only flag"
+                )
+            }
+            ProtoFlagPermission::READ_WRITE => {
+                ensure!(
+                    pf.metadata.storage() != ProtoFlagStorageBackend::UNSPECIFIED,
+                    "bad parsed flag: storage backend cannot be UNSPECIFIED"
+                )
+            }
+        }
 
         Ok(())
     }
 
+    /// Construct a proto instance from a textproto string content
+    pub fn try_from_text_proto(s: &str) -> Result<ProtoParsedFlag> {
+        let pf: ProtoParsedFlag = super::try_from_text_proto(s)?;
+        verify_fields(&pf)?;
+        Ok(pf)
+    }
+
     /// Get the file path of the corresponding flag declaration
     pub fn path_to_declaration(pf: &ProtoParsedFlag) -> &str {
         debug_assert!(!pf.trace.is_empty());
@@ -338,6 +366,13 @@ pub mod parsed_flags {
     use anyhow::bail;
     use std::cmp::Ordering;
 
+    /// Construct a proto instance from a textproto string content
+    pub fn try_from_text_proto(s: &str) -> Result<ProtoParsedFlags> {
+        let pfs: ProtoParsedFlags = super::try_from_text_proto(s)?;
+        verify_fields(&pfs)?;
+        Ok(pfs)
+    }
+
     /// Construct a proto instance from a binary proto bytes
     pub fn try_from_binary_proto(bytes: &[u8]) -> Result<ProtoParsedFlags> {
         let message: ProtoParsedFlags = protobuf::Message::parse_from_bytes(bytes)?;
@@ -600,6 +635,28 @@ flag {
         .unwrap_err();
         assert!(format!("{:?}", error).contains("bad flag declarations: bad container"));
 
+        // bad input: storage backend should not be explicitly set
+        let error = flag_declarations::try_from_text_proto(
+            r#"
+package: "com.foo.bar"
+container: "system"
+flag {
+    name: "first"
+    namespace: "first_ns"
+    description: "This is the description of the first flag."
+    bug: "123"
+    is_fixed_read_only: true
+    metadata {
+        storage: ACONFIGD
+    }
+}
+"#,
+        )
+        .unwrap_err();
+        assert!(format!("{:?}", error).contains(
+            "bad flag declaration: storage in metadata should not be explicitly selected"
+        ));
+
         // TODO(b/312769710): Verify error when container is missing.
     }
 
@@ -716,6 +773,9 @@ parsed_flag {
         permission: READ_ONLY
     }
     container: "system"
+    metadata {
+        storage: NONE
+    }
 }
 parsed_flag {
     package: "com.second"
@@ -737,6 +797,9 @@ parsed_flag {
     }
     is_fixed_read_only: true
     container: "system"
+    metadata {
+        storage: NONE
+    }
 }
 "#;
         let parsed_flags = try_from_binary_proto_from_text_proto(text_proto).unwrap();
@@ -812,6 +875,9 @@ parsed_flag {
         permission: READ_ONLY
     }
     container: "system"
+    metadata {
+        storage: NONE
+    }
 }
 parsed_flag {
     package: "aaa.aaa"
@@ -827,6 +893,9 @@ parsed_flag {
         permission: READ_ONLY
     }
     container: "system"
+    metadata {
+        storage: ACONFIGD
+    }
 }
 "#;
         let error = try_from_binary_proto_from_text_proto(text_proto).unwrap_err();
@@ -851,6 +920,9 @@ parsed_flag {
         permission: READ_ONLY
     }
     container: "system"
+    metadata {
+        storage: NONE
+    }
 }
 parsed_flag {
     package: "com.foo"
@@ -866,6 +938,9 @@ parsed_flag {
         permission: READ_ONLY
     }
     container: "system"
+    metadata {
+        storage: ACONFIGD
+    }
 }
 "#;
         let error = try_from_binary_proto_from_text_proto(text_proto).unwrap_err();
@@ -890,6 +965,9 @@ parsed_flag {
         permission: READ_ONLY
     }
     container: "system"
+    metadata {
+        storage: NONE
+    }
 }
 parsed_flag {
     package: "com.foo"
@@ -905,10 +983,67 @@ parsed_flag {
         permission: READ_ONLY
     }
     container: "system"
+    metadata {
+        storage: ACONFIGD
+    }
 }
 "#;
         let error = try_from_binary_proto_from_text_proto(text_proto).unwrap_err();
         assert_eq!(format!("{:?}", error), "bad parsed flags: duplicate flag com.foo.bar (defined in flags.declarations and flags.declarations)");
+
+        // bad input: wrong storage backend: not NONE
+        let text_proto = r#"
+parsed_flag {
+    package: "com.foo"
+    name: "bar"
+    namespace: "first_ns"
+    description: "This is the description of the first flag."
+    bug: ""
+    state: DISABLED
+    permission: READ_ONLY
+    trace {
+        source: "flags.declarations"
+        state: DISABLED
+        permission: READ_ONLY
+    }
+    container: "system"
+    metadata {
+        storage: ACONFIGD
+    }
+}
+"#;
+        let error = try_from_binary_proto_from_text_proto(text_proto).unwrap_err();
+        assert_eq!(
+            format!("{:?}", error),
+            "bad parsed flag: storage backend is not NONE for a read only flag"
+        );
+
+        // bad input: wrong storage backend UNSPECIFIED
+        let text_proto = r#"
+parsed_flag {
+    package: "com.foo"
+    name: "bar"
+    namespace: "second_ns"
+    description: "This is the description of the second flag."
+    bug: ""
+    state: ENABLED
+    permission: READ_WRITE
+    trace {
+        source: "flags.declarations"
+        state: DISABLED
+        permission: READ_ONLY
+    }
+    container: "system"
+    metadata {
+        storage: UNSPECIFIED
+    }
+}
+"#;
+        let error = try_from_binary_proto_from_text_proto(text_proto).unwrap_err();
+        assert_eq!(
+            format!("{:?}", error),
+            "bad parsed flag: storage backend cannot be UNSPECIFIED"
+        );
     }
 
     #[test]
@@ -933,6 +1068,9 @@ parsed_flag {
         permission: READ_ONLY
     }
     container: "system"
+    metadata {
+        storage: NONE
+    }
 }
 "#;
         let parsed_flags = try_from_binary_proto_from_text_proto(text_proto).unwrap();
@@ -957,6 +1095,9 @@ parsed_flag {
         permission: READ_ONLY
     }
     container: "system"
+    metadata {
+        storage: NONE
+    }
 }
 parsed_flag {
     package: "com.second"
@@ -972,6 +1113,9 @@ parsed_flag {
         permission: READ_ONLY
     }
     container: "system"
+    metadata {
+        storage: ACONFIGD
+    }
 }
 "#;
         let expected = try_from_binary_proto_from_text_proto(text_proto).unwrap();
@@ -991,6 +1135,9 @@ parsed_flag {
         permission: READ_ONLY
     }
     container: "system"
+    metadata {
+        storage: NONE
+    }
 }
 "#;
         let first = try_from_binary_proto_from_text_proto(text_proto).unwrap();
@@ -1010,6 +1157,9 @@ parsed_flag {
         permission: READ_ONLY
     }
     container: "system"
+    metadata {
+        storage: ACONFIGD
+    }
 }
 "#;
         let second = try_from_binary_proto_from_text_proto(text_proto).unwrap();
@@ -1028,6 +1178,9 @@ parsed_flag {
         state: DISABLED
         permission: READ_ONLY
     }
+    metadata {
+        storage: ACONFIGD
+    }
 }
 "#;
         let second_duplicate = try_from_binary_proto_from_text_proto(text_proto).unwrap();
diff --git a/tools/aconfig/aconfig_storage_file/Android.bp b/tools/aconfig/aconfig_storage_file/Android.bp
index e875c7be6a..2fc0b96737 100644
--- a/tools/aconfig/aconfig_storage_file/Android.bp
+++ b/tools/aconfig/aconfig_storage_file/Android.bp
@@ -9,7 +9,6 @@ rust_defaults {
     rustlibs: [
         "libanyhow",
         "libthiserror",
-        "libtempfile",
         "libprotobuf",
         "libclap",
         "libcxx",
@@ -33,6 +32,20 @@ rust_library {
     product_available: true,
 }
 
+rust_library {
+    name: "libaconfig_storage_file_with_test_utils",
+    crate_name: "aconfig_storage_file",
+    features: [
+        "test_utils",
+    ],
+    host_supported: true,
+    defaults: ["aconfig_storage_file.defaults"],
+    srcs: ["src/lib.rs"],
+    rustlibs: [
+        "libtempfile",
+    ],
+}
+
 rust_binary_host {
     name: "aconfig-storage",
     defaults: ["aconfig_storage_file.defaults"],
@@ -48,6 +61,9 @@ rust_test_host {
     test_suites: ["general-tests"],
     defaults: ["aconfig_storage_file.defaults"],
     srcs: ["src/lib.rs"],
+    rustlibs: [
+        "libtempfile",
+    ],
 }
 
 rust_protobuf {
@@ -148,6 +164,9 @@ java_library {
     srcs: [
         "srcs/**/*.java",
     ],
+    libs: [
+        "ravenwood-annotations-lib",
+    ],
     sdk_version: "core_current",
     min_sdk_version: "29",
     host_supported: true,
@@ -163,6 +182,9 @@ java_library {
     srcs: [
         "srcs/**/*.java",
     ],
+    libs: [
+        "ravenwood-annotations-lib",
+    ],
     sdk_version: "none",
     system_modules: "core-all-system-modules",
     host_supported: true,
diff --git a/tools/aconfig/aconfig_storage_file/Cargo.toml b/tools/aconfig/aconfig_storage_file/Cargo.toml
index a40557803f..3f287a70c3 100644
--- a/tools/aconfig/aconfig_storage_file/Cargo.toml
+++ b/tools/aconfig/aconfig_storage_file/Cargo.toml
@@ -6,6 +6,7 @@ edition = "2021"
 [features]
 default = ["cargo"]
 cargo = []
+test_utils = []
 
 [dependencies]
 anyhow = "1.0.69"
diff --git a/tools/aconfig/aconfig_storage_file/src/lib.rs b/tools/aconfig/aconfig_storage_file/src/lib.rs
index e99132092d..fcded9e278 100644
--- a/tools/aconfig/aconfig_storage_file/src/lib.rs
+++ b/tools/aconfig/aconfig_storage_file/src/lib.rs
@@ -38,6 +38,7 @@ pub mod flag_value;
 pub mod package_table;
 pub mod protos;
 pub mod sip_hasher13;
+#[cfg(any(test, feature = "test_utils"))]
 pub mod test_utils;
 
 use anyhow::anyhow;
@@ -59,11 +60,11 @@ use crate::AconfigStorageError::{
 
 /// The max storage file version from which we can safely read/write. May be
 /// experimental.
-pub const MAX_SUPPORTED_FILE_VERSION: u32 = 2;
+pub const MAX_SUPPORTED_FILE_VERSION: u32 = 3;
 
 /// The newest fully-released version. Unless otherwise specified, this is the
 /// version we will write.
-pub const DEFAULT_FILE_VERSION: u32 = 1;
+pub const DEFAULT_FILE_VERSION: u32 = 2;
 
 /// Good hash table prime number
 pub(crate) const HASH_PRIMES: [u32; 29] = [
diff --git a/tools/aconfig/aconfig_storage_file/src/package_table.rs b/tools/aconfig/aconfig_storage_file/src/package_table.rs
index 4d6bd91675..9e0db2489f 100644
--- a/tools/aconfig/aconfig_storage_file/src/package_table.rs
+++ b/tools/aconfig/aconfig_storage_file/src/package_table.rs
@@ -101,6 +101,7 @@ pub struct PackageTableNode {
     pub package_name: String,
     pub package_id: u32,
     pub fingerprint: u64,
+    pub redact_exported_reads: bool,
     // The index of the first boolean flag in this aconfig package among all boolean
     // flags in this container.
     pub boolean_start_index: u32,
@@ -112,10 +113,11 @@ impl fmt::Debug for PackageTableNode {
     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
         writeln!(
             f,
-            "Package: {}, Id: {}, Fingerprint: {}, Boolean flag start index: {}, Next: {:?}",
+            "Package: {}, Id: {}, Fingerprint: {}, Redact Exported Reads: {}, Boolean flag start index: {}, Next: {:?}",
             self.package_name,
             self.package_id,
             self.fingerprint,
+            self.redact_exported_reads,
             self.boolean_start_index,
             self.next_offset
         )?;
@@ -129,6 +131,7 @@ impl PackageTableNode {
         match version {
             1 => Self::into_bytes_v1(self),
             2 => Self::into_bytes_v2(self),
+            3 => Self::into_bytes_v3(self),
             // TODO(b/316357686): into_bytes should return a Result.
             _ => Self::into_bytes_v2(&self),
         }
@@ -157,11 +160,25 @@ impl PackageTableNode {
         result
     }
 
+    fn into_bytes_v3(&self) -> Vec<u8> {
+        let mut result = Vec::new();
+        let name_bytes = self.package_name.as_bytes();
+        result.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
+        result.extend_from_slice(name_bytes);
+        result.extend_from_slice(&self.package_id.to_le_bytes());
+        result.extend_from_slice(&self.fingerprint.to_le_bytes());
+        result.extend_from_slice(&u8::from(self.redact_exported_reads).to_le_bytes());
+        result.extend_from_slice(&self.boolean_start_index.to_le_bytes());
+        result.extend_from_slice(&self.next_offset.unwrap_or(0).to_le_bytes());
+        result
+    }
+
     /// Deserialize from bytes based on file version.
     pub fn from_bytes(bytes: &[u8], version: u32) -> Result<Self, AconfigStorageError> {
         match version {
             1 => Self::from_bytes_v1(bytes),
             2 => Self::from_bytes_v2(bytes),
+            3 => Self::from_bytes_v3(bytes),
             _ => {
                 return Err(AconfigStorageError::BytesParseFail(anyhow!(
                     "Binary file is an unsupported version: {}",
@@ -183,7 +200,14 @@ impl PackageTableNode {
             val => Some(val),
         };
 
-        let node = Self { package_name, package_id, fingerprint, boolean_start_index, next_offset };
+        let node = Self {
+            package_name,
+            package_id,
+            fingerprint,
+            redact_exported_reads: false,
+            boolean_start_index,
+            next_offset,
+        };
         Ok(node)
     }
 
@@ -198,7 +222,38 @@ impl PackageTableNode {
             val => Some(val),
         };
 
-        let node = Self { package_name, package_id, fingerprint, boolean_start_index, next_offset };
+        let node = Self {
+            package_name,
+            package_id,
+            fingerprint,
+            redact_exported_reads: false,
+            boolean_start_index,
+            next_offset,
+        };
+        Ok(node)
+    }
+
+    fn from_bytes_v3(bytes: &[u8]) -> Result<Self, AconfigStorageError> {
+        let mut head = 0;
+        let package_name = read_str_from_bytes(bytes, &mut head)?;
+        let package_id = read_u32_from_bytes(bytes, &mut head)?;
+        let fingerprint = read_u64_from_bytes(bytes, &mut head)?;
+        let redact_exported_reads_bytes = read_u8_from_bytes(bytes, &mut head)?;
+        let redact_exported_reads = redact_exported_reads_bytes == 1;
+        let boolean_start_index = read_u32_from_bytes(bytes, &mut head)?;
+        let next_offset = match read_u32_from_bytes(bytes, &mut head)? {
+            0 => None,
+            val => Some(val),
+        };
+
+        let node = Self {
+            package_name,
+            package_id,
+            fingerprint,
+            redact_exported_reads,
+            boolean_start_index,
+            next_offset,
+        };
         Ok(node)
     }
 
diff --git a/tools/aconfig/aconfig_storage_file/src/protos.rs b/tools/aconfig/aconfig_storage_file/src/protos.rs
index 8b862057e7..21520e5eab 100644
--- a/tools/aconfig/aconfig_storage_file/src/protos.rs
+++ b/tools/aconfig/aconfig_storage_file/src/protos.rs
@@ -50,8 +50,6 @@ pub use auto_generated::*;
 
 use anyhow::Result;
 use protobuf::Message;
-use std::io::Write;
-use tempfile::NamedTempFile;
 
 pub mod storage_record_pb {
     use super::*;
@@ -90,13 +88,6 @@ pub mod storage_record_pb {
         storage_files.write_to_vec(&mut binary_proto)?;
         Ok(binary_proto)
     }
-
-    pub fn write_proto_to_temp_file(text_proto: &str) -> Result<NamedTempFile> {
-        let bytes = get_binary_proto_from_text_proto(text_proto).unwrap();
-        let mut file = NamedTempFile::new()?;
-        let _ = file.write_all(&bytes);
-        Ok(file)
-    }
 }
 
 #[cfg(test)]
diff --git a/tools/aconfig/aconfig_storage_file/src/test_utils.rs b/tools/aconfig/aconfig_storage_file/src/test_utils.rs
index 7c603df40e..2c7d5f7418 100644
--- a/tools/aconfig/aconfig_storage_file/src/test_utils.rs
+++ b/tools/aconfig/aconfig_storage_file/src/test_utils.rs
@@ -32,6 +32,7 @@ pub fn create_test_package_table(version: u32) -> PackageTable {
         file_size: match version {
             1 => 209,
             2 => 233,
+            3 => 236,
             _ => panic!("Unsupported version."),
         },
         num_packages: 3,
@@ -41,6 +42,7 @@ pub fn create_test_package_table(version: u32) -> PackageTable {
     let buckets: Vec<Option<u32>> = match version {
         1 => vec![Some(59), None, None, Some(109), None, None, None],
         2 => vec![Some(59), None, None, Some(117), None, None, None],
+        3 => vec![Some(59), None, None, Some(118), None, None, None],
         _ => panic!("Unsupported version."),
     };
     let first_node = PackageTableNode {
@@ -48,9 +50,14 @@ pub fn create_test_package_table(version: u32) -> PackageTable {
         package_id: 1,
         fingerprint: match version {
             1 => 0,
-            2 => 4431940502274857964u64,
+            2..=3 => 4431940502274857964u64,
             _ => panic!("Unsupported version."),
         },
+        redact_exported_reads: match version {
+            1..=2 => false,
+            3 => true,
+            _ => panic!("unsupported version."),
+        },
         boolean_start_index: 3,
         next_offset: None,
     };
@@ -59,13 +66,19 @@ pub fn create_test_package_table(version: u32) -> PackageTable {
         package_id: 0,
         fingerprint: match version {
             1 => 0,
-            2 => 15248948510590158086u64,
+            2..=3 => 15248948510590158086u64,
             _ => panic!("Unsupported version."),
         },
+        redact_exported_reads: match version {
+            1..=2 => false,
+            3 => true,
+            _ => panic!("unsupported version."),
+        },
         boolean_start_index: 0,
         next_offset: match version {
             1 => Some(159),
             2 => Some(175),
+            3 => Some(177),
             _ => panic!("Unsupported version."),
         },
     };
@@ -74,9 +87,14 @@ pub fn create_test_package_table(version: u32) -> PackageTable {
         package_id: 2,
         fingerprint: match version {
             1 => 0,
-            2 => 16233229917711622375u64,
+            2..=3 => 16233229917711622375u64,
             _ => panic!("Unsupported version."),
         },
+        redact_exported_reads: match version {
+            1..=2 => false,
+            3 => true,
+            _ => panic!("unsupported version."),
+        },
         boolean_start_index: 6,
         next_offset: None,
     };
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/AconfigStorageException.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/AconfigStorageException.java
index 324c55d57d..dbb491310c 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/AconfigStorageException.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/AconfigStorageException.java
@@ -22,6 +22,7 @@ package android.aconfig.storage;
  * <p>This exception indicates a general problem with Aconfig Storage, such as an inability to read
  * or write data.
  */
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public class AconfigStorageException extends RuntimeException {
 
     /** Generic error code indicating an unspecified Aconfig Storage error. */
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java
index 14fc468f11..51892eb189 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java
@@ -21,6 +21,7 @@ import java.nio.ByteOrder;
 import java.nio.charset.StandardCharsets;
 import java.util.Objects;
 
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public class ByteBufferReader {
 
     private ByteBuffer mByteBuffer;
@@ -31,6 +32,10 @@ public class ByteBufferReader {
         this.mByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
     }
 
+    public boolean readBoolean() {
+        return readByte() == 1;
+    }
+
     public int readByte() {
         return Byte.toUnsignedInt(mByteBuffer.get(nextGetIndex(1)));
     }
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FileType.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FileType.java
index c35487358d..dee41349f0 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FileType.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FileType.java
@@ -16,6 +16,7 @@
 
 package android.aconfig.storage;
 
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public enum FileType {
     PACKAGE_MAP(0),
     FLAG_MAP(1),
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java
index ee60b18dcb..a6227f2fdf 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java
@@ -21,6 +21,7 @@ import static java.nio.charset.StandardCharsets.UTF_8;
 import java.nio.ByteBuffer;
 import java.util.Objects;
 
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public class FlagTable {
 
     private Header mHeader;
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagType.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagType.java
index 385e2d9db9..20587c9b82 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagType.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagType.java
@@ -16,6 +16,7 @@
 
 package android.aconfig.storage;
 
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public enum FlagType {
     ReadWriteBoolean (0),
     ReadOnlyBoolean(1),
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagValueList.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagValueList.java
index 493436d2a2..e2c31364ee 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagValueList.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagValueList.java
@@ -18,6 +18,7 @@ package android.aconfig.storage;
 
 import java.nio.ByteBuffer;
 
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public class FlagValueList {
 
     private Header mHeader;
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java
index 215616e781..38e5b9679d 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java
@@ -23,6 +23,7 @@ import java.util.ArrayList;
 import java.util.List;
 import java.util.Objects;
 
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public class PackageTable {
 
     private static final int FINGERPRINT_BYTES = 8;
@@ -72,7 +73,8 @@ public class PackageTable {
         ByteBufferReader reader = new ByteBufferReader(mBuffer);
         reader.position(mHeader.mNodeOffset);
         int fingerprintBytes = mHeader.mVersion == 1 ? 0 : FINGERPRINT_BYTES;
-        int skipBytes = fingerprintBytes + NODE_SKIP_BYTES;
+        int redactionBytes = mHeader.mVersion >= 3 ? 1 : 0;
+        int skipBytes = fingerprintBytes + redactionBytes + NODE_SKIP_BYTES;
         for (int i = 0; i < mHeader.mNumPackages; i++) {
             list.add(reader.readString());
             reader.position(reader.position() + skipBytes);
@@ -145,9 +147,11 @@ public class PackageTable {
         private String mPackageName;
         private int mPackageId;
         private long mPackageFingerprint;
+        private boolean mRedactExportedReads;
         private int mBooleanStartIndex;
         private int mNextOffset;
         private boolean mHasPackageFingerprint;
+        private boolean mHasRedactExportedReads;
 
         private static Node fromBytes(ByteBufferReader reader, int version) {
             switch (version) {
@@ -155,6 +159,8 @@ public class PackageTable {
                     return fromBytesV1(reader);
                 case 2:
                     return fromBytesV2(reader);
+                case 3:
+                    return fromBytesV3(reader);
                 default:
                     // Do we want to throw here?
                     return new Node();
@@ -183,6 +189,20 @@ public class PackageTable {
             return node;
         }
 
+        private static Node fromBytesV3(ByteBufferReader reader) {
+            Node node = new Node();
+            node.mPackageName = reader.readString();
+            node.mPackageId = reader.readInt();
+            node.mPackageFingerprint = reader.readLong();
+            node.mRedactExportedReads = reader.readBoolean();
+            node.mHasRedactExportedReads = true;
+            node.mBooleanStartIndex = reader.readInt();
+            node.mNextOffset = reader.readInt();
+            node.mNextOffset = node.mNextOffset == 0 ? -1 : node.mNextOffset;
+            node.mHasPackageFingerprint = true;
+            return node;
+        }
+
         @Override
         public int hashCode() {
             return Objects.hash(mPackageName, mPackageId, mBooleanStartIndex, mNextOffset);
@@ -217,6 +237,10 @@ public class PackageTable {
             return mPackageFingerprint;
         }
 
+        public boolean getRedactExportedReads() {
+            return mRedactExportedReads;
+        }
+
         public int getBooleanStartIndex() {
             return mBooleanStartIndex;
         }
@@ -228,5 +252,9 @@ public class PackageTable {
         public boolean hasPackageFingerprint() {
             return mHasPackageFingerprint;
         }
+
+        public boolean hasRedactExportedReads() {
+            return mHasRedactExportedReads;
+        }
     }
 }
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/SipHasher13.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/SipHasher13.java
index 64714ee5f8..97a60b3bad 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/SipHasher13.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/SipHasher13.java
@@ -16,6 +16,7 @@
 
 package android.aconfig.storage;
 
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public class SipHasher13 {
     static class State {
         private long v0;
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/StorageFileProvider.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/StorageFileProvider.java
index f75ac36f7d..6fa5238885 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/StorageFileProvider.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/StorageFileProvider.java
@@ -32,16 +32,33 @@ import java.util.List;
 import java.util.Set;
 
 /** @hide */
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public class StorageFileProvider {
+    /**
+     * Method to allow using a different "top" directly on Ravenwood.
+     */
+    @android.ravenwood.annotation.RavenwoodReplace
+    private static String getStorageRoot() {
+        return ""; // No extra path is needed, unless on Ravenwood.
+    }
+
+    private static String getStorageRoot$ravenwood() {
+        // RavenwoodHelper has a utility method for this, but we just hardcode it here to avoid
+        // the extra dependency.
+        return System.getProperty("android.ravenwood.runtime_path") + "/aconfig";
+    }
 
-    private static final String DEFAULT_MAP_PATH = "/metadata/aconfig/maps/";
-    private static final String DEFAULT_BOOT_PATH = "/metadata/aconfig/boot/";
+    private static final String DEFAULT_MAP_PATH = getStorageRoot() + "/metadata/aconfig/maps/";
+    private static final String DEFAULT_BOOT_PATH = getStorageRoot() + "/metadata/aconfig/boot/";
     private static final String PMAP_FILE_EXT = ".package.map";
     private static final String FMAP_FILE_EXT = ".flag.map";
     private static final String VAL_FILE_EXT = ".val";
     private static final StorageFileProvider DEFAULT_INSTANCE =
             new StorageFileProvider(DEFAULT_MAP_PATH, DEFAULT_BOOT_PATH);
 
+    /** On Ravenwood, we only have one container file with this filename. */
+    private static final String RAVENWOOD_STORAGE_FILE = "all_aconfig_declarations";
+
     private final String mMapPath;
     private final String mBootPath;
 
@@ -82,23 +99,36 @@ public class StorageFileProvider {
         return result;
     }
 
+    /**
+     * On Ravenwood, we only have one kind of container file. We use this method to absorb
+     * the difference.
+     */
+    @android.ravenwood.annotation.RavenwoodReplace
+    private static Path buildPath(String path, String container, String extension) {
+        return Paths.get(path, container + extension);
+    }
+
+    private static Path buildPath$ravenwood(String path, String container, String extension) {
+        return Paths.get(path, RAVENWOOD_STORAGE_FILE + extension);
+    }
+
     /** @hide */
     public PackageTable getPackageTable(String container) {
         return PackageTable.fromBytes(
                 mapStorageFile(
-                        Paths.get(mMapPath, container + PMAP_FILE_EXT), FileType.PACKAGE_MAP));
+                        buildPath(mMapPath, container, PMAP_FILE_EXT), FileType.PACKAGE_MAP));
     }
 
     /** @hide */
     public FlagTable getFlagTable(String container) {
         return FlagTable.fromBytes(
-                mapStorageFile(Paths.get(mMapPath, container + FMAP_FILE_EXT), FileType.FLAG_MAP));
+                mapStorageFile(buildPath(mMapPath, container, FMAP_FILE_EXT), FileType.FLAG_MAP));
     }
 
     /** @hide */
     public FlagValueList getFlagValueList(String container) {
         return FlagValueList.fromBytes(
-                mapStorageFile(Paths.get(mBootPath, container + VAL_FILE_EXT), FileType.FLAG_VAL));
+                mapStorageFile(buildPath(mBootPath, container, VAL_FILE_EXT), FileType.FLAG_VAL));
     }
 
     // Map a storage file given file path
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/TableUtils.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/TableUtils.java
index d4269dac3f..d41912dcd8 100644
--- a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/TableUtils.java
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/TableUtils.java
@@ -16,6 +16,7 @@
 
 package android.aconfig.storage;
 
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public class TableUtils {
 
     private static final int[] HASH_PRIMES =
diff --git a/tools/aconfig/aconfig_storage_file/tests/Android.bp b/tools/aconfig/aconfig_storage_file/tests/Android.bp
index bd46d5f0ab..8141d6ea7f 100644
--- a/tools/aconfig/aconfig_storage_file/tests/Android.bp
+++ b/tools/aconfig/aconfig_storage_file/tests/Android.bp
@@ -18,6 +18,10 @@ cc_test {
         "data/v2/flag_v2.map",
         "data/v2/flag_v2.val",
         "data/v2/flag_v2.info",
+        "data/v3/package_v3.map",
+        "data/v3/flag_v3.map",
+        "data/v3/flag_v3.val",
+        "data/v3/flag_v3.info",
     ],
     test_suites: [
         "device-tests",
@@ -47,6 +51,10 @@ android_test {
         "data/v2/flag_v2.map",
         "data/v2/flag_v2.val",
         "data/v2/flag_v2.info",
+        "data/v3/package_v3.map",
+        "data/v3/flag_v3.map",
+        "data/v3/flag_v3.val",
+        "data/v3/flag_v3.info",
     ],
     test_suites: [
         "general-tests",
diff --git a/tools/aconfig/aconfig_storage_file/tests/AndroidStorageJaveTest.xml b/tools/aconfig/aconfig_storage_file/tests/AndroidStorageJaveTest.xml
index bfc238e320..43dc226d3b 100644
--- a/tools/aconfig/aconfig_storage_file/tests/AndroidStorageJaveTest.xml
+++ b/tools/aconfig/aconfig_storage_file/tests/AndroidStorageJaveTest.xml
@@ -29,6 +29,10 @@
         <option name="push" value="flag_v2.map->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v2.flag.map" />
         <option name="push" value="flag_v2.val->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v2.val" />
         <option name="push" value="flag_v2.info->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v2.info" />
+        <option name="push" value="package_v3.map->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v3.package.map" />
+        <option name="push" value="flag_v3.map->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v3.flag.map" />
+        <option name="push" value="flag_v3.val->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v3.val" />
+        <option name="push" value="flag_v3.info->/data/local/tmp/aconfig_storage_file_test_java/testdata/mock.v3.info" />
         <option name="post-push" value="chmod +r /data/local/tmp/aconfig_storage_file_test_java/testdata/" />
     </target_preparer>
     <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
diff --git a/tools/aconfig/aconfig_storage_file/tests/data/v3/flag_v3.info b/tools/aconfig/aconfig_storage_file/tests/data/v3/flag_v3.info
new file mode 100644
index 0000000000..fd75712c42
Binary files /dev/null and b/tools/aconfig/aconfig_storage_file/tests/data/v3/flag_v3.info differ
diff --git a/tools/aconfig/aconfig_storage_file/tests/data/v3/flag_v3.map b/tools/aconfig/aconfig_storage_file/tests/data/v3/flag_v3.map
new file mode 100644
index 0000000000..1b1ef61a6c
Binary files /dev/null and b/tools/aconfig/aconfig_storage_file/tests/data/v3/flag_v3.map differ
diff --git a/tools/aconfig/aconfig_storage_file/tests/data/v3/flag_v3.val b/tools/aconfig/aconfig_storage_file/tests/data/v3/flag_v3.val
new file mode 100644
index 0000000000..a966eb2314
Binary files /dev/null and b/tools/aconfig/aconfig_storage_file/tests/data/v3/flag_v3.val differ
diff --git a/tools/aconfig/aconfig_storage_file/tests/data/v3/package_v3.map b/tools/aconfig/aconfig_storage_file/tests/data/v3/package_v3.map
new file mode 100644
index 0000000000..497ef4f507
Binary files /dev/null and b/tools/aconfig/aconfig_storage_file/tests/data/v3/package_v3.map differ
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java b/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java
index 4b68e5bb92..7650694465 100644
--- a/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java
@@ -91,6 +91,14 @@ public class PackageTableTest {
         assertFalse(node1.hasPackageFingerprint());
         assertFalse(node2.hasPackageFingerprint());
         assertFalse(node4.hasPackageFingerprint());
+
+        assertFalse(node1.hasRedactExportedReads());
+        assertFalse(node2.hasRedactExportedReads());
+        assertFalse(node4.hasRedactExportedReads());
+
+        assertFalse(node1.getRedactExportedReads());
+        assertFalse(node2.getRedactExportedReads());
+        assertFalse(node4.getRedactExportedReads());
     }
 
     @Test
@@ -125,6 +133,56 @@ public class PackageTableTest {
         assertEquals(-3197795563119393530L, node1.getPackageFingerprint());
         assertEquals(4431940502274857964L, node2.getPackageFingerprint());
         assertEquals(-2213514155997929241L, node4.getPackageFingerprint());
+
+        assertFalse(node1.hasRedactExportedReads());
+        assertFalse(node2.hasRedactExportedReads());
+        assertFalse(node4.hasRedactExportedReads());
+
+        assertFalse(node1.getRedactExportedReads());
+        assertFalse(node2.getRedactExportedReads());
+        assertFalse(node4.getRedactExportedReads());
+    }
+
+    @Test
+    public void testPackageTable_rightNode_v3() throws Exception {
+        PackageTable packageTable =
+                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer(3));
+
+        PackageTable.Node node1 = packageTable.get("com.android.aconfig.storage.test_1");
+        PackageTable.Node node2 = packageTable.get("com.android.aconfig.storage.test_2");
+        PackageTable.Node node4 = packageTable.get("com.android.aconfig.storage.test_4");
+
+        assertEquals("com.android.aconfig.storage.test_1", node1.getPackageName());
+        assertEquals("com.android.aconfig.storage.test_2", node2.getPackageName());
+        assertEquals("com.android.aconfig.storage.test_4", node4.getPackageName());
+
+        assertEquals(0, node1.getPackageId());
+        assertEquals(1, node2.getPackageId());
+        assertEquals(2, node4.getPackageId());
+
+        assertEquals(0, node1.getBooleanStartIndex());
+        assertEquals(3, node2.getBooleanStartIndex());
+        assertEquals(6, node4.getBooleanStartIndex());
+
+        assertEquals(177, node1.getNextOffset());
+        assertEquals(-1, node2.getNextOffset());
+        assertEquals(-1, node4.getNextOffset());
+
+        assertTrue(node1.hasPackageFingerprint());
+        assertTrue(node2.hasPackageFingerprint());
+        assertTrue(node4.hasPackageFingerprint());
+
+        assertEquals(-3197795563119393530L, node1.getPackageFingerprint());
+        assertEquals(4431940502274857964L, node2.getPackageFingerprint());
+        assertEquals(-2213514155997929241L, node4.getPackageFingerprint());
+
+        assertTrue(node1.hasRedactExportedReads());
+        assertTrue(node2.hasRedactExportedReads());
+        assertTrue(node4.hasRedactExportedReads());
+
+        assertTrue(node1.getRedactExportedReads());
+        assertFalse(node2.getRedactExportedReads());
+        assertTrue(node4.getRedactExportedReads());
     }
 
     @Test
@@ -143,6 +201,13 @@ public class PackageTableTest {
         assertTrue(packages.contains("com.android.aconfig.storage.test_1"));
         assertTrue(packages.contains("com.android.aconfig.storage.test_2"));
         assertTrue(packages.contains("com.android.aconfig.storage.test_4"));
+
+        packageTable = PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer(3));
+        packages = new HashSet<>(packageTable.getPackageList());
+        assertEquals(3, packages.size());
+        assertTrue(packages.contains("com.android.aconfig.storage.test_1"));
+        assertTrue(packages.contains("com.android.aconfig.storage.test_2"));
+        assertTrue(packages.contains("com.android.aconfig.storage.test_4"));
     }
 
     @Test
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/StorageFileProviderTest.java b/tools/aconfig/aconfig_storage_file/tests/srcs/StorageFileProviderTest.java
index c2720f9544..c95f9264f6 100644
--- a/tools/aconfig/aconfig_storage_file/tests/srcs/StorageFileProviderTest.java
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/StorageFileProviderTest.java
@@ -29,7 +29,6 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
-import java.nio.file.Paths;
 import java.util.List;
 
 @RunWith(JUnit4.class)
@@ -41,11 +40,14 @@ public class StorageFileProviderTest {
                 new StorageFileProvider(TestDataUtils.TESTDATA_PATH, TestDataUtils.TESTDATA_PATH);
         String[] excludes = {};
         List<String> containers = p.listContainers(excludes);
-        assertEquals(2, containers.size());
+
+        // Each directory ("mock.v#") is considered its own container.
+        assertEquals(3, containers.size());
+        int originalSize = containers.size();
 
         excludes = new String[] {"mock.v1"};
         containers = p.listContainers(excludes);
-        assertEquals(1, containers.size());
+        assertEquals(originalSize - 1, containers.size());
 
         p = new StorageFileProvider("fake/path/", "fake/path/");
         containers = p.listContainers(excludes);
diff --git a/tools/aconfig/aconfig_storage_file/tests/storage_file_test.cpp b/tools/aconfig/aconfig_storage_file/tests/storage_file_test.cpp
index 5c008afbf1..a25ab6dbc3 100644
--- a/tools/aconfig/aconfig_storage_file/tests/storage_file_test.cpp
+++ b/tools/aconfig/aconfig_storage_file/tests/storage_file_test.cpp
@@ -119,6 +119,31 @@ TEST(AconfigStorageFileTest, test_list_flag_v2) {
                "true", "ReadWriteBoolean");
 }
 
+// TODO: b/376256472 - Use parameterized tests.
+TEST(AconfigStorageFileTest, test_list_flag_v3) {
+  auto flag_list_result = get_flag_list_result("3");
+  ASSERT_TRUE(flag_list_result.ok());
+
+  auto const& flag_list = *flag_list_result;
+  ASSERT_EQ(flag_list.size(), 8);
+  verify_value(flag_list[0], "com.android.aconfig.storage.test_1",
+               "disabled_rw", "false", "ReadWriteBoolean");
+  verify_value(flag_list[1], "com.android.aconfig.storage.test_1", "enabled_ro",
+               "true", "ReadOnlyBoolean");
+  verify_value(flag_list[2], "com.android.aconfig.storage.test_1", "enabled_rw",
+               "true", "ReadWriteBoolean");
+  verify_value(flag_list[3], "com.android.aconfig.storage.test_2",
+               "disabled_rw", "false", "ReadWriteBoolean");
+  verify_value(flag_list[4], "com.android.aconfig.storage.test_2",
+               "enabled_fixed_ro", "true", "FixedReadOnlyBoolean");
+  verify_value(flag_list[5], "com.android.aconfig.storage.test_2", "enabled_ro",
+               "true", "ReadOnlyBoolean");
+  verify_value(flag_list[6], "com.android.aconfig.storage.test_4",
+               "enabled_fixed_ro", "true", "FixedReadOnlyBoolean");
+  verify_value(flag_list[7], "com.android.aconfig.storage.test_4", "enabled_rw",
+               "true", "ReadWriteBoolean");
+}
+
 TEST(AconfigStorageFileTest, test_list_flag_with_info) {
   auto flag_list_result = get_flag_list_result_with_info("1");
   ASSERT_TRUE(flag_list_result.ok());
@@ -182,3 +207,35 @@ TEST(AconfigStorageFileTest, test_list_flag_with_info_v2) {
                     "enabled_rw", "true", "ReadWriteBoolean", true, false,
                     false);
 }
+
+TEST(AconfigStorageFileTest, test_list_flag_with_info_v3) {
+  auto flag_list_result = get_flag_list_result_with_info("3");
+  ASSERT_TRUE(flag_list_result.ok());
+
+  auto const& flag_list = *flag_list_result;
+  ASSERT_EQ(flag_list.size(), 8);
+  verify_value_info(flag_list[0], "com.android.aconfig.storage.test_1",
+                    "disabled_rw", "false", "ReadWriteBoolean", true, false,
+                    false);
+  verify_value_info(flag_list[1], "com.android.aconfig.storage.test_1",
+                    "enabled_ro", "true", "ReadOnlyBoolean", false, false,
+                    false);
+  verify_value_info(flag_list[2], "com.android.aconfig.storage.test_1",
+                    "enabled_rw", "true", "ReadWriteBoolean", true, false,
+                    false);
+  verify_value_info(flag_list[3], "com.android.aconfig.storage.test_2",
+                    "disabled_rw", "false", "ReadWriteBoolean", true, false,
+                    false);
+  verify_value_info(flag_list[4], "com.android.aconfig.storage.test_2",
+                    "enabled_fixed_ro", "true", "FixedReadOnlyBoolean", false,
+                    false, false);
+  verify_value_info(flag_list[5], "com.android.aconfig.storage.test_2",
+                    "enabled_ro", "true", "ReadOnlyBoolean", false, false,
+                    false);
+  verify_value_info(flag_list[6], "com.android.aconfig.storage.test_4",
+                    "enabled_fixed_ro", "true", "FixedReadOnlyBoolean", false,
+                    false, false);
+  verify_value_info(flag_list[7], "com.android.aconfig.storage.test_4",
+                    "enabled_rw", "true", "ReadWriteBoolean", true, false,
+                    false);
+}
diff --git a/tools/aconfig/aconfig_storage_read_api/Android.bp b/tools/aconfig/aconfig_storage_read_api/Android.bp
index 16341b9273..320770827a 100644
--- a/tools/aconfig/aconfig_storage_read_api/Android.bp
+++ b/tools/aconfig/aconfig_storage_read_api/Android.bp
@@ -12,7 +12,6 @@ rust_defaults {
         "libmemmap2",
         "libcxx",
         "libthiserror",
-        "libaconfig_storage_file",
     ],
 }
 
@@ -20,7 +19,26 @@ rust_library {
     name: "libaconfig_storage_read_api",
     crate_name: "aconfig_storage_read_api",
     host_supported: true,
+    vendor_available: true,
     defaults: ["aconfig_storage_read_api.defaults"],
+    rustlibs: [
+        "libaconfig_storage_file",
+    ],
+    apex_available: [
+        "//apex_available:platform",
+        "//apex_available:anyapex",
+    ],
+    min_sdk_version: "29",
+}
+
+rust_library {
+    name: "libaconfig_storage_read_api_with_test_utils",
+    crate_name: "aconfig_storage_read_api",
+    host_supported: true,
+    defaults: ["aconfig_storage_read_api.defaults"],
+    rustlibs: [
+        "libaconfig_storage_file_with_test_utils",
+    ],
     apex_available: [
         "//apex_available:platform",
         "//apex_available:anyapex",
@@ -33,7 +51,8 @@ rust_test_host {
     test_suites: ["general-tests"],
     defaults: ["aconfig_storage_read_api.defaults"],
     rustlibs: [
-        "librand",
+        "librand-0.8",
+        "libaconfig_storage_file_with_test_utils",
     ],
     data: [
         "tests/data/v1/package_v1.map",
@@ -69,6 +88,9 @@ rust_ffi_static {
     vendor_available: true,
     product_available: true,
     defaults: ["aconfig_storage_read_api.defaults"],
+    rustlibs: [
+        "libaconfig_storage_file",
+    ],
     apex_available: [
         "//apex_available:platform",
         "//apex_available:anyapex",
@@ -109,10 +131,20 @@ cc_library {
 
 cc_defaults {
     name: "aconfig_lib_cc_shared_link.defaults",
-    shared_libs: select(release_flag("RELEASE_READ_FROM_NEW_STORAGE"), {
-        true: ["libaconfig_storage_read_api_cc"],
-        default: [],
-    }),
+    target: {
+        android: {
+            shared_libs: select(release_flag("RELEASE_READ_FROM_NEW_STORAGE"), {
+                true: ["libaconfig_storage_read_api_cc"],
+                default: [],
+            }),
+        },
+        host: {
+            static_libs: select(release_flag("RELEASE_READ_FROM_NEW_STORAGE"), {
+                true: ["libaconfig_storage_read_api_cc"],
+                default: [],
+            }),
+        },
+    },
 }
 
 cc_defaults {
diff --git a/tools/aconfig/aconfig_storage_read_api/aconfig_storage_read_api.cpp b/tools/aconfig/aconfig_storage_read_api/aconfig_storage_read_api.cpp
index 8e0c4e1a12..862b7c1e84 100644
--- a/tools/aconfig/aconfig_storage_read_api/aconfig_storage_read_api.cpp
+++ b/tools/aconfig/aconfig_storage_read_api/aconfig_storage_read_api.cpp
@@ -138,6 +138,7 @@ Result<PackageReadContext> get_package_read_context(
     context.package_exists = context_cxx.package_exists;
     context.package_id = context_cxx.package_id;
     context.boolean_start_index = context_cxx.boolean_start_index;
+    context.fingerprint = context_cxx.fingerprint;
     return context;
   } else {
     auto result = Result<PackageReadContext>();
diff --git a/tools/aconfig/aconfig_storage_read_api/include/aconfig_storage/aconfig_storage_read_api.hpp b/tools/aconfig/aconfig_storage_read_api/include/aconfig_storage/aconfig_storage_read_api.hpp
index b50935bf69..5246cbcbb2 100644
--- a/tools/aconfig/aconfig_storage_read_api/include/aconfig_storage/aconfig_storage_read_api.hpp
+++ b/tools/aconfig/aconfig_storage_read_api/include/aconfig_storage/aconfig_storage_read_api.hpp
@@ -49,6 +49,7 @@ struct PackageReadContext {
   bool package_exists;
   uint32_t package_id;
   uint32_t boolean_start_index;
+  uint64_t fingerprint;
 };
 
 /// Flag read context query result
diff --git a/tools/aconfig/aconfig_storage_read_api/src/lib.rs b/tools/aconfig/aconfig_storage_read_api/src/lib.rs
index d3cc9d427d..1b6e1fcdaf 100644
--- a/tools/aconfig/aconfig_storage_read_api/src/lib.rs
+++ b/tools/aconfig/aconfig_storage_read_api/src/lib.rs
@@ -185,6 +185,7 @@ mod ffi {
         pub package_exists: bool,
         pub package_id: u32,
         pub boolean_start_index: u32,
+        pub fingerprint: u64,
     }
 
     // Flag table query return for cc interlop
@@ -248,6 +249,7 @@ impl ffi::PackageReadContextQueryCXX {
                     package_exists: true,
                     package_id: offset.package_id,
                     boolean_start_index: offset.boolean_start_index,
+                    fingerprint: offset.fingerprint,
                 },
                 None => Self {
                     query_success: true,
@@ -255,6 +257,7 @@ impl ffi::PackageReadContextQueryCXX {
                     package_exists: false,
                     package_id: 0,
                     boolean_start_index: 0,
+                    fingerprint: 0,
                 },
             },
             Err(errmsg) => Self {
@@ -263,6 +266,7 @@ impl ffi::PackageReadContextQueryCXX {
                 package_exists: false,
                 package_id: 0,
                 boolean_start_index: 0,
+                fingerprint: 0,
             },
         }
     }
diff --git a/tools/aconfig/aconfig_storage_read_api/src/package_table_query.rs b/tools/aconfig/aconfig_storage_read_api/src/package_table_query.rs
index b20668f9c2..5c8f347272 100644
--- a/tools/aconfig/aconfig_storage_read_api/src/package_table_query.rs
+++ b/tools/aconfig/aconfig_storage_read_api/src/package_table_query.rs
@@ -79,9 +79,9 @@ mod tests {
     use aconfig_storage_file::{test_utils::create_test_package_table, DEFAULT_FILE_VERSION};
 
     #[test]
-    // this test point locks down table query
+    // this test point locks down table query - v1 files.
     fn test_package_query() {
-        let package_table = create_test_package_table(DEFAULT_FILE_VERSION).into_bytes();
+        let package_table = create_test_package_table(1).into_bytes();
         let package_context =
             find_package_read_context(&package_table[..], "com.android.aconfig.storage.test_1")
                 .unwrap()
@@ -106,7 +106,7 @@ mod tests {
     }
 
     #[test]
-    // this test point locks down table query
+    // this test point locks down table query - v2 files.
     fn test_package_query_v2() {
         let package_table = create_test_package_table(2).into_bytes();
         let package_context =
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/Android.bp b/tools/aconfig/aconfig_storage_read_api/tests/Android.bp
index c071f7cd88..26e825cfb7 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/Android.bp
+++ b/tools/aconfig/aconfig_storage_read_api/tests/Android.bp
@@ -21,7 +21,7 @@ rust_test {
         "libanyhow",
         "libaconfig_storage_file",
         "libaconfig_storage_read_api",
-        "librand",
+        "librand-0.8",
     ],
     data: [
         ":read_api_test_storage_files",
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/storage_read_api_test.cpp b/tools/aconfig/aconfig_storage_read_api/tests/storage_read_api_test.cpp
index 5289faa6de..bb2be37442 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/storage_read_api_test.cpp
+++ b/tools/aconfig/aconfig_storage_read_api/tests/storage_read_api_test.cpp
@@ -44,9 +44,9 @@ class AconfigStorageTest : public ::testing::Test {
     return {};
   }
 
-  void SetUp() override {
+  void setup_files_for_version(std::string version) {
     auto const test_base_dir = android::base::GetExecutableDirectory();
-    auto const test_dir = test_base_dir + "/data/v1";
+    auto const test_dir = test_base_dir + "/data/v" + version;
     storage_dir = std::string(root_dir.path);
     auto maps_dir = storage_dir + "/maps";
     auto boot_dir = storage_dir + "/boot";
@@ -56,10 +56,10 @@ class AconfigStorageTest : public ::testing::Test {
     flag_map = std::string(maps_dir) + "/mockup.flag.map";
     flag_val = std::string(boot_dir) + "/mockup.val";
     flag_info = std::string(boot_dir) + "/mockup.info";
-    copy_file(test_dir + "/package_v1.map", package_map);
-    copy_file(test_dir + "/flag_v1.map", flag_map);
-    copy_file(test_dir + "/flag_v1.val", flag_val);
-    copy_file(test_dir + "/flag_v1.info", flag_info);
+    copy_file(test_dir + "/package_v" + version + ".map", package_map);
+    copy_file(test_dir + "/flag_v" + version + ".map", flag_map);
+    copy_file(test_dir + "/flag_v" + version + ".val", flag_val);
+    copy_file(test_dir + "/flag_v" + version + ".info", flag_info);
   }
 
   void TearDown() override {
@@ -79,6 +79,7 @@ class AconfigStorageTest : public ::testing::Test {
 
 /// Test to lock down storage file version query api
 TEST_F(AconfigStorageTest, test_storage_version_query) {
+  setup_files_for_version("1");
   auto version = api::get_storage_file_version(package_map);
   ASSERT_TRUE(version.ok());
   ASSERT_EQ(*version, 1);
@@ -95,6 +96,7 @@ TEST_F(AconfigStorageTest, test_storage_version_query) {
 
 /// Negative test to lock down the error when mapping none exist storage files
 TEST_F(AconfigStorageTest, test_none_exist_storage_file_mapping) {
+  setup_files_for_version("1");
   auto mapped_file_result = private_api::get_mapped_file_impl(
       storage_dir, "vendor", api::StorageFileType::package_map);
   ASSERT_FALSE(mapped_file_result.ok());
@@ -104,7 +106,8 @@ TEST_F(AconfigStorageTest, test_none_exist_storage_file_mapping) {
 }
 
 /// Test to lock down storage package context query api
-TEST_F(AconfigStorageTest, test_package_context_query) {
+TEST_F(AconfigStorageTest, test_package_context_query_v1) {
+  setup_files_for_version("1");
   auto mapped_file_result = private_api::get_mapped_file_impl(
       storage_dir, "mockup", api::StorageFileType::package_map);
   ASSERT_TRUE(mapped_file_result.ok());
@@ -116,6 +119,7 @@ TEST_F(AconfigStorageTest, test_package_context_query) {
   ASSERT_TRUE(context->package_exists);
   ASSERT_EQ(context->package_id, 0);
   ASSERT_EQ(context->boolean_start_index, 0);
+  ASSERT_EQ(context->fingerprint, 0);
 
   context = api::get_package_read_context(
       *mapped_file, "com.android.aconfig.storage.test_2");
@@ -123,6 +127,7 @@ TEST_F(AconfigStorageTest, test_package_context_query) {
   ASSERT_TRUE(context->package_exists);
   ASSERT_EQ(context->package_id, 1);
   ASSERT_EQ(context->boolean_start_index, 3);
+  ASSERT_EQ(context->fingerprint, 0);
 
   context = api::get_package_read_context(
       *mapped_file, "com.android.aconfig.storage.test_4");
@@ -130,10 +135,45 @@ TEST_F(AconfigStorageTest, test_package_context_query) {
   ASSERT_TRUE(context->package_exists);
   ASSERT_EQ(context->package_id, 2);
   ASSERT_EQ(context->boolean_start_index, 6);
+  ASSERT_EQ(context->fingerprint, 0);
+}
+
+/// Test to lock down storage package context query api
+TEST_F(AconfigStorageTest, test_package_context_query_v2) {
+  setup_files_for_version("2");
+  auto mapped_file_result = private_api::get_mapped_file_impl(
+      storage_dir, "mockup", api::StorageFileType::package_map);
+  ASSERT_TRUE(mapped_file_result.ok());
+  auto mapped_file = std::unique_ptr<api::MappedStorageFile>(*mapped_file_result);
+
+  auto context = api::get_package_read_context(
+      *mapped_file, "com.android.aconfig.storage.test_1");
+  ASSERT_TRUE(context.ok());
+  ASSERT_TRUE(context->package_exists);
+  ASSERT_EQ(context->package_id, 0);
+  ASSERT_EQ(context->boolean_start_index, 0);
+  ASSERT_EQ(context->fingerprint, 15248948510590158086ULL);
+
+  context = api::get_package_read_context(
+      *mapped_file, "com.android.aconfig.storage.test_2");
+  ASSERT_TRUE(context.ok());
+  ASSERT_TRUE(context->package_exists);
+  ASSERT_EQ(context->package_id, 1);
+  ASSERT_EQ(context->boolean_start_index, 3);
+  ASSERT_EQ(context->fingerprint, 4431940502274857964ULL);
+
+  context = api::get_package_read_context(
+      *mapped_file, "com.android.aconfig.storage.test_4");
+  ASSERT_TRUE(context.ok());
+  ASSERT_TRUE(context->package_exists);
+  ASSERT_EQ(context->package_id, 2);
+  ASSERT_EQ(context->boolean_start_index, 6);
+  ASSERT_EQ(context->fingerprint, 16233229917711622375ULL);
 }
 
 /// Test to lock down when querying none exist package
 TEST_F(AconfigStorageTest, test_none_existent_package_context_query) {
+  setup_files_for_version("1");
   auto mapped_file_result = private_api::get_mapped_file_impl(
       storage_dir, "mockup", api::StorageFileType::package_map);
   ASSERT_TRUE(mapped_file_result.ok());
@@ -147,6 +187,7 @@ TEST_F(AconfigStorageTest, test_none_existent_package_context_query) {
 
 /// Test to lock down storage flag context query api
 TEST_F(AconfigStorageTest, test_flag_context_query) {
+  setup_files_for_version("1");
   auto mapped_file_result = private_api::get_mapped_file_impl(
       storage_dir, "mockup", api::StorageFileType::flag_map);
   ASSERT_TRUE(mapped_file_result.ok());
@@ -173,6 +214,7 @@ TEST_F(AconfigStorageTest, test_flag_context_query) {
 
 /// Test to lock down when querying none exist flag
 TEST_F(AconfigStorageTest, test_none_existent_flag_context_query) {
+  setup_files_for_version("1");
   auto mapped_file_result = private_api::get_mapped_file_impl(
       storage_dir, "mockup", api::StorageFileType::flag_map);
   ASSERT_TRUE(mapped_file_result.ok());
@@ -189,6 +231,7 @@ TEST_F(AconfigStorageTest, test_none_existent_flag_context_query) {
 
 /// Test to lock down storage flag value query api
 TEST_F(AconfigStorageTest, test_boolean_flag_value_query) {
+  setup_files_for_version("1");
   auto mapped_file_result = private_api::get_mapped_file_impl(
       storage_dir, "mockup", api::StorageFileType::flag_val);
   ASSERT_TRUE(mapped_file_result.ok());
@@ -205,6 +248,7 @@ TEST_F(AconfigStorageTest, test_boolean_flag_value_query) {
 
 /// Negative test to lock down the error when querying flag value out of range
 TEST_F(AconfigStorageTest, test_invalid_boolean_flag_value_query) {
+  setup_files_for_version("1");
   auto mapped_file_result = private_api::get_mapped_file_impl(
       storage_dir, "mockup", api::StorageFileType::flag_val);
   ASSERT_TRUE(mapped_file_result.ok());
@@ -218,6 +262,7 @@ TEST_F(AconfigStorageTest, test_invalid_boolean_flag_value_query) {
 
 /// Test to lock down storage flag info query api
 TEST_F(AconfigStorageTest, test_boolean_flag_info_query) {
+  setup_files_for_version("1");
   auto mapped_file_result = private_api::get_mapped_file_impl(
       storage_dir, "mockup", api::StorageFileType::flag_info);
   ASSERT_TRUE(mapped_file_result.ok());
@@ -237,6 +282,7 @@ TEST_F(AconfigStorageTest, test_boolean_flag_info_query) {
 
 /// Negative test to lock down the error when querying flag info out of range
 TEST_F(AconfigStorageTest, test_invalid_boolean_flag_info_query) {
+  setup_files_for_version("1");
   auto mapped_file_result = private_api::get_mapped_file_impl(
       storage_dir, "mockup", api::StorageFileType::flag_info);
   ASSERT_TRUE(mapped_file_result.ok());
diff --git a/tools/aconfig/aconfig_storage_write_api/Android.bp b/tools/aconfig/aconfig_storage_write_api/Android.bp
index 4c882b4b9a..4c3940b046 100644
--- a/tools/aconfig/aconfig_storage_write_api/Android.bp
+++ b/tools/aconfig/aconfig_storage_write_api/Android.bp
@@ -9,12 +9,8 @@ rust_defaults {
     srcs: ["src/lib.rs"],
     rustlibs: [
         "libanyhow",
-        "libtempfile",
         "libmemmap2",
-        "libcxx",
         "libthiserror",
-        "libaconfig_storage_file",
-        "libaconfig_storage_read_api",
     ],
     min_sdk_version: "34",
     apex_available: [
@@ -28,6 +24,10 @@ rust_library {
     crate_name: "aconfig_storage_write_api",
     host_supported: true,
     defaults: ["aconfig_storage_write_api.defaults"],
+    rustlibs: [
+        "libaconfig_storage_file",
+        "libaconfig_storage_read_api",
+    ],
 }
 
 rust_test_host {
@@ -39,50 +39,8 @@ rust_test_host {
         "tests/flag.info",
     ],
     rustlibs: [
-        "libaconfig_storage_read_api",
-    ],
-}
-
-// cxx source codegen from rust api
-genrule {
-    name: "libcxx_aconfig_storage_write_api_bridge_code",
-    tools: ["cxxbridge"],
-    cmd: "$(location cxxbridge) $(in) > $(out)",
-    srcs: ["src/lib.rs"],
-    out: ["aconfig_storage/lib.rs.cc"],
-}
-
-// cxx header codegen from rust api
-genrule {
-    name: "libcxx_aconfig_storage_write_api_bridge_header",
-    tools: ["cxxbridge"],
-    cmd: "$(location cxxbridge) $(in) --header > $(out)",
-    srcs: ["src/lib.rs"],
-    out: ["aconfig_storage/lib.rs.h"],
-}
-
-// a static cc lib based on generated code
-rust_ffi_static {
-    name: "libaconfig_storage_write_api_cxx_bridge",
-    crate_name: "aconfig_storage_write_api_cxx_bridge",
-    host_supported: true,
-    defaults: ["aconfig_storage_write_api.defaults"],
-}
-
-// flag write api cc interface
-cc_library_static {
-    name: "libaconfig_storage_write_api_cc",
-    srcs: ["aconfig_storage_write_api.cpp"],
-    generated_headers: [
-        "cxx-bridge-header",
-        "libcxx_aconfig_storage_write_api_bridge_header",
-    ],
-    generated_sources: ["libcxx_aconfig_storage_write_api_bridge_code"],
-    whole_static_libs: ["libaconfig_storage_write_api_cxx_bridge"],
-    export_include_dirs: ["include"],
-    static_libs: [
-        "libaconfig_storage_read_api_cc",
-        "libprotobuf-cpp-lite",
-        "libbase",
+        "libaconfig_storage_read_api_with_test_utils",
+        "libaconfig_storage_file_with_test_utils",
+        "libtempfile",
     ],
 }
diff --git a/tools/aconfig/aconfig_storage_write_api/Cargo.toml b/tools/aconfig/aconfig_storage_write_api/Cargo.toml
index 2ce6edfe96..96aa78c66b 100644
--- a/tools/aconfig/aconfig_storage_write_api/Cargo.toml
+++ b/tools/aconfig/aconfig_storage_write_api/Cargo.toml
@@ -9,12 +9,8 @@ cargo = []
 
 [dependencies]
 anyhow = "1.0.69"
-cxx = "1.0"
 memmap2 = "0.8.0"
 tempfile = "3.9.0"
 thiserror = "1.0.56"
 aconfig_storage_file = { path = "../aconfig_storage_file" }
 aconfig_storage_read_api = { path = "../aconfig_storage_read_api" }
-
-[build-dependencies]
-cxx-build = "1.0"
diff --git a/tools/aconfig/aconfig_storage_write_api/aconfig_storage_write_api.cpp b/tools/aconfig/aconfig_storage_write_api/aconfig_storage_write_api.cpp
deleted file mode 100644
index 03a8fa284a..0000000000
--- a/tools/aconfig/aconfig_storage_write_api/aconfig_storage_write_api.cpp
+++ /dev/null
@@ -1,103 +0,0 @@
-
-#include <android-base/file.h>
-#include <android-base/logging.h>
-#include <android-base/unique_fd.h>
-
-#include <sys/mman.h>
-#include <sys/stat.h>
-#include <fcntl.h>
-
-#include "rust/cxx.h"
-#include "aconfig_storage/lib.rs.h"
-#include "aconfig_storage/aconfig_storage_write_api.hpp"
-
-namespace aconfig_storage {
-
-/// Map a storage file
-android::base::Result<MutableMappedStorageFile *> map_mutable_storage_file(
-    std::string const &file) {
-  struct stat file_stat;
-  if (stat(file.c_str(), &file_stat) < 0) {
-    return android::base::ErrnoError() << "stat failed";
-  }
-
-  if ((file_stat.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0) {
-    return android::base::Error() << "cannot map nonwriteable file";
-  }
-
-  size_t file_size = file_stat.st_size;
-
-  android::base::unique_fd ufd(open(file.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC));
-  if (ufd.get() == -1) {
-    return android::base::ErrnoError() << "failed to open " << file;
-  };
-
-  void *const map_result =
-      mmap(nullptr, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, ufd.get(), 0);
-  if (map_result == MAP_FAILED) {
-    return android::base::ErrnoError() << "mmap failed";
-  }
-
-  auto mapped_file = new MutableMappedStorageFile();
-  mapped_file->file_ptr = map_result;
-  mapped_file->file_size = file_size;
-
-  return mapped_file;
-}
-
-/// Set boolean flag value
-android::base::Result<void> set_boolean_flag_value(
-    const MutableMappedStorageFile &file,
-    uint32_t offset,
-    bool value) {
-  auto content = rust::Slice<uint8_t>(
-      static_cast<uint8_t *>(file.file_ptr), file.file_size);
-  auto update_cxx = update_boolean_flag_value_cxx(content, offset, value);
-  if (!update_cxx.update_success) {
-    return android::base::Error() << update_cxx.error_message.c_str();
-  }
-  if (!msync(static_cast<uint8_t *>(file.file_ptr) + update_cxx.offset, 1, MS_SYNC)) {
-    return android::base::ErrnoError() << "msync failed";
-  }
-  return {};
-}
-
-/// Set if flag has server override
-android::base::Result<void> set_flag_has_server_override(
-    const MutableMappedStorageFile &file,
-    FlagValueType value_type,
-    uint32_t offset,
-    bool value) {
-  auto content = rust::Slice<uint8_t>(
-      static_cast<uint8_t *>(file.file_ptr), file.file_size);
-  auto update_cxx = update_flag_has_server_override_cxx(
-      content, static_cast<uint16_t>(value_type), offset, value);
-  if (!update_cxx.update_success) {
-    return android::base::Error() << update_cxx.error_message.c_str();
-  }
-  if (!msync(static_cast<uint8_t *>(file.file_ptr) + update_cxx.offset, 1, MS_SYNC)) {
-    return android::base::ErrnoError() << "msync failed";
-  }
-  return {};
-}
-
-/// Set if flag has local override
-android::base::Result<void> set_flag_has_local_override(
-    const MutableMappedStorageFile &file,
-    FlagValueType value_type,
-    uint32_t offset,
-    bool value) {
-  auto content = rust::Slice<uint8_t>(
-      static_cast<uint8_t *>(file.file_ptr), file.file_size);
-  auto update_cxx = update_flag_has_local_override_cxx(
-      content, static_cast<uint16_t>(value_type), offset, value);
-  if (!update_cxx.update_success) {
-    return android::base::Error() << update_cxx.error_message.c_str();
-  }
-  if (!msync(static_cast<uint8_t *>(file.file_ptr) + update_cxx.offset, 1, MS_SYNC)) {
-    return android::base::ErrnoError() << "msync failed";
-  }
-  return {};
-}
-
-} // namespace aconfig_storage
diff --git a/tools/aconfig/aconfig_storage_write_api/build.rs b/tools/aconfig/aconfig_storage_write_api/build.rs
deleted file mode 100644
index 7b1aa53b5f..0000000000
--- a/tools/aconfig/aconfig_storage_write_api/build.rs
+++ /dev/null
@@ -1,4 +0,0 @@
-fn main() {
-    let _ = cxx_build::bridge("src/lib.rs");
-    println!("cargo:rerun-if-changed=src/lib.rs");
-}
diff --git a/tools/aconfig/aconfig_storage_write_api/include/aconfig_storage/aconfig_storage_write_api.hpp b/tools/aconfig/aconfig_storage_write_api/include/aconfig_storage/aconfig_storage_write_api.hpp
deleted file mode 100644
index 50a51889b1..0000000000
--- a/tools/aconfig/aconfig_storage_write_api/include/aconfig_storage/aconfig_storage_write_api.hpp
+++ /dev/null
@@ -1,39 +0,0 @@
-#pragma once
-
-#include <stdint.h>
-#include <string>
-
-#include <android-base/result.h>
-#include <aconfig_storage/aconfig_storage_read_api.hpp>
-
-
-namespace aconfig_storage {
-
-/// Mapped flag value file
-struct MutableMappedStorageFile : MappedStorageFile {};
-
-/// Map a storage file
-android::base::Result<MutableMappedStorageFile*> map_mutable_storage_file(
-    std::string const& file);
-
-/// Set boolean flag value
-android::base::Result<void> set_boolean_flag_value(
-    const MutableMappedStorageFile& file,
-    uint32_t offset,
-    bool value);
-
-/// Set if flag has server override
-android::base::Result<void> set_flag_has_server_override(
-    const MutableMappedStorageFile& file,
-    FlagValueType value_type,
-    uint32_t offset,
-    bool value);
-
-/// Set if flag has local override
-android::base::Result<void> set_flag_has_local_override(
-    const MutableMappedStorageFile& file,
-    FlagValueType value_type,
-    uint32_t offset,
-    bool value);
-
-} // namespace aconfig_storage
diff --git a/tools/aconfig/aconfig_storage_write_api/src/lib.rs b/tools/aconfig/aconfig_storage_write_api/src/lib.rs
index 09bb41f54f..22eaa0424d 100644
--- a/tools/aconfig/aconfig_storage_write_api/src/lib.rs
+++ b/tools/aconfig/aconfig_storage_write_api/src/lib.rs
@@ -99,139 +99,6 @@ pub fn set_flag_has_local_override(
     })
 }
 
-// *************************************** //
-// CC INTERLOP
-// *************************************** //
-
-// Exported rust data structure and methods, c++ code will be generated
-#[cxx::bridge]
-mod ffi {
-    // Flag value update return for cc interlop
-    pub struct BooleanFlagValueUpdateCXX {
-        pub update_success: bool,
-        pub offset: usize,
-        pub error_message: String,
-    }
-
-    // Flag has server override update return for cc interlop
-    pub struct FlagHasServerOverrideUpdateCXX {
-        pub update_success: bool,
-        pub offset: usize,
-        pub error_message: String,
-    }
-
-    // Flag has local override update return for cc interlop
-    pub struct FlagHasLocalOverrideUpdateCXX {
-        pub update_success: bool,
-        pub offset: usize,
-        pub error_message: String,
-    }
-
-    // Rust export to c++
-    extern "Rust" {
-        pub fn update_boolean_flag_value_cxx(
-            file: &mut [u8],
-            offset: u32,
-            value: bool,
-        ) -> BooleanFlagValueUpdateCXX;
-
-        pub fn update_flag_has_server_override_cxx(
-            file: &mut [u8],
-            flag_type: u16,
-            offset: u32,
-            value: bool,
-        ) -> FlagHasServerOverrideUpdateCXX;
-
-        pub fn update_flag_has_local_override_cxx(
-            file: &mut [u8],
-            flag_type: u16,
-            offset: u32,
-            value: bool,
-        ) -> FlagHasLocalOverrideUpdateCXX;
-    }
-}
-
-pub(crate) fn update_boolean_flag_value_cxx(
-    file: &mut [u8],
-    offset: u32,
-    value: bool,
-) -> ffi::BooleanFlagValueUpdateCXX {
-    match crate::flag_value_update::update_boolean_flag_value(file, offset, value) {
-        Ok(head) => ffi::BooleanFlagValueUpdateCXX {
-            update_success: true,
-            offset: head,
-            error_message: String::from(""),
-        },
-        Err(errmsg) => ffi::BooleanFlagValueUpdateCXX {
-            update_success: false,
-            offset: usize::MAX,
-            error_message: format!("{:?}", errmsg),
-        },
-    }
-}
-
-pub(crate) fn update_flag_has_server_override_cxx(
-    file: &mut [u8],
-    flag_type: u16,
-    offset: u32,
-    value: bool,
-) -> ffi::FlagHasServerOverrideUpdateCXX {
-    match FlagValueType::try_from(flag_type) {
-        Ok(value_type) => {
-            match crate::flag_info_update::update_flag_has_server_override(
-                file, value_type, offset, value,
-            ) {
-                Ok(head) => ffi::FlagHasServerOverrideUpdateCXX {
-                    update_success: true,
-                    offset: head,
-                    error_message: String::from(""),
-                },
-                Err(errmsg) => ffi::FlagHasServerOverrideUpdateCXX {
-                    update_success: false,
-                    offset: usize::MAX,
-                    error_message: format!("{:?}", errmsg),
-                },
-            }
-        }
-        Err(errmsg) => ffi::FlagHasServerOverrideUpdateCXX {
-            update_success: false,
-            offset: usize::MAX,
-            error_message: format!("{:?}", errmsg),
-        },
-    }
-}
-
-pub(crate) fn update_flag_has_local_override_cxx(
-    file: &mut [u8],
-    flag_type: u16,
-    offset: u32,
-    value: bool,
-) -> ffi::FlagHasLocalOverrideUpdateCXX {
-    match FlagValueType::try_from(flag_type) {
-        Ok(value_type) => {
-            match crate::flag_info_update::update_flag_has_local_override(
-                file, value_type, offset, value,
-            ) {
-                Ok(head) => ffi::FlagHasLocalOverrideUpdateCXX {
-                    update_success: true,
-                    offset: head,
-                    error_message: String::from(""),
-                },
-                Err(errmsg) => ffi::FlagHasLocalOverrideUpdateCXX {
-                    update_success: false,
-                    offset: usize::MAX,
-                    error_message: format!("{:?}", errmsg),
-                },
-            }
-        }
-        Err(errmsg) => ffi::FlagHasLocalOverrideUpdateCXX {
-            update_success: false,
-            offset: usize::MAX,
-            error_message: format!("{:?}", errmsg),
-        },
-    }
-}
-
 #[cfg(test)]
 mod tests {
     use super::*;
diff --git a/tools/aconfig/aconfig_storage_write_api/tests/Android.bp b/tools/aconfig/aconfig_storage_write_api/tests/Android.bp
index 5508dacbea..960da11f72 100644
--- a/tools/aconfig/aconfig_storage_write_api/tests/Android.bp
+++ b/tools/aconfig/aconfig_storage_write_api/tests/Android.bp
@@ -17,31 +17,3 @@ rust_test {
     ],
     test_suites: ["general-tests"],
 }
-
-cc_test {
-    name: "aconfig_storage_write_api.test.cpp",
-    srcs: [
-        "storage_write_api_test.cpp",
-    ],
-    static_libs: [
-        "libgmock",
-        "libaconfig_storage_read_api_cc",
-        "libaconfig_storage_write_api_cc",
-        "libbase",
-        "liblog",
-    ],
-    data: [
-        "flag.val",
-        "flag.info",
-    ],
-    test_suites: [
-        "device-tests",
-        "general-tests",
-    ],
-    generated_headers: [
-        "cxx-bridge-header",
-        "libcxx_aconfig_storage_read_api_bridge_header",
-    ],
-    generated_sources: ["libcxx_aconfig_storage_read_api_bridge_code"],
-    whole_static_libs: ["libaconfig_storage_read_api_cxx_bridge"],
-}
diff --git a/tools/aconfig/aconfig_storage_write_api/tests/storage_write_api_test.cpp b/tools/aconfig/aconfig_storage_write_api/tests/storage_write_api_test.cpp
deleted file mode 100644
index 133f5a0592..0000000000
--- a/tools/aconfig/aconfig_storage_write_api/tests/storage_write_api_test.cpp
+++ /dev/null
@@ -1,225 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-#include <string>
-#include <vector>
-#include <cstdio>
-
-#include <sys/stat.h>
-#include "aconfig_storage/aconfig_storage_read_api.hpp"
-#include "aconfig_storage/aconfig_storage_write_api.hpp"
-#include <gtest/gtest.h>
-#include <android-base/file.h>
-#include <android-base/result.h>
-
-#include "rust/cxx.h"
-#include "aconfig_storage/lib.rs.h"
-
-using namespace android::base;
-
-namespace api = aconfig_storage;
-namespace private_api = aconfig_storage::private_internal_api;
-
-class AconfigStorageTest : public ::testing::Test {
- protected:
-  Result<std::string> copy_to_rw_temp_file(std::string const& source_file) {
-    auto temp_file = std::string(std::tmpnam(nullptr));
-    auto content = std::string();
-    if (!ReadFileToString(source_file, &content)) {
-      return Error() << "failed to read file: " << source_file;
-    }
-    if (!WriteStringToFile(content, temp_file)) {
-      return Error() << "failed to copy file: " << source_file;
-    }
-    if (chmod(temp_file.c_str(),
-              S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IWOTH) == -1) {
-      return Error() << "failed to chmod";
-    }
-    return temp_file;
-  }
-
-  void SetUp() override {
-    auto const test_dir = android::base::GetExecutableDirectory();
-    flag_val = *copy_to_rw_temp_file(test_dir + "/flag.val");
-    flag_info = *copy_to_rw_temp_file(test_dir + "/flag.info");
-  }
-
-  void TearDown() override {
-    std::remove(flag_val.c_str());
-    std::remove(flag_info.c_str());
-  }
-
-  std::string flag_val;
-  std::string flag_info;
-};
-
-/// Negative test to lock down the error when mapping a non writeable storage file
-TEST_F(AconfigStorageTest, test_non_writable_storage_file_mapping) {
-  ASSERT_TRUE(chmod(flag_val.c_str(), S_IRUSR | S_IRGRP | S_IROTH) != -1);
-  auto mapped_file_result = api::map_mutable_storage_file(flag_val);
-  ASSERT_FALSE(mapped_file_result.ok());
-  auto it = mapped_file_result.error().message().find("cannot map nonwriteable file");
-  ASSERT_TRUE(it != std::string::npos) << mapped_file_result.error().message();
-}
-
-/// Test to lock down storage flag value update api
-TEST_F(AconfigStorageTest, test_boolean_flag_value_update) {
-  auto mapped_file_result = api::map_mutable_storage_file(flag_val);
-  ASSERT_TRUE(mapped_file_result.ok());
-  auto mapped_file = std::unique_ptr<api::MutableMappedStorageFile>(*mapped_file_result);
-
-  for (int offset = 0; offset < 8; ++offset) {
-    auto update_result = api::set_boolean_flag_value(*mapped_file, offset, true);
-    ASSERT_TRUE(update_result.ok());
-    auto value = api::get_boolean_flag_value(*mapped_file, offset);
-    ASSERT_TRUE(value.ok());
-    ASSERT_TRUE(*value);
-  }
-
-  // load the file on disk and check has been updated
-  std::ifstream file(flag_val, std::ios::binary | std::ios::ate);
-  std::streamsize size = file.tellg();
-  file.seekg(0, std::ios::beg);
-
-  std::vector<uint8_t> buffer(size);
-  file.read(reinterpret_cast<char *>(buffer.data()), size);
-
-  auto content = rust::Slice<const uint8_t>(
-      buffer.data(), mapped_file->file_size);
-
-  for (int offset = 0; offset < 8; ++offset) {
-    auto value_cxx = get_boolean_flag_value_cxx(content, offset);
-    ASSERT_TRUE(value_cxx.query_success);
-    ASSERT_TRUE(value_cxx.flag_value);
-  }
-}
-
-/// Negative test to lock down the error when querying flag value out of range
-TEST_F(AconfigStorageTest, test_invalid_boolean_flag_value_update) {
-  auto mapped_file_result = api::map_mutable_storage_file(flag_val);
-  ASSERT_TRUE(mapped_file_result.ok());
-  auto mapped_file = std::unique_ptr<api::MutableMappedStorageFile>(*mapped_file_result);
-  auto update_result = api::set_boolean_flag_value(*mapped_file, 8, true);
-  ASSERT_FALSE(update_result.ok());
-  ASSERT_EQ(update_result.error().message(),
-            std::string("InvalidStorageFileOffset(Flag value offset goes beyond the end of the file.)"));
-}
-
-/// Test to lock down storage flag has server override update api
-TEST_F(AconfigStorageTest, test_flag_has_server_override_update) {
-  auto mapped_file_result = api::map_mutable_storage_file(flag_info);
-  ASSERT_TRUE(mapped_file_result.ok());
-  auto mapped_file = std::unique_ptr<api::MutableMappedStorageFile>(*mapped_file_result);
-
-  for (int offset = 0; offset < 8; ++offset) {
-    auto update_result = api::set_flag_has_server_override(
-        *mapped_file, api::FlagValueType::Boolean, offset, true);
-    ASSERT_TRUE(update_result.ok()) << update_result.error();
-    auto attribute = api::get_flag_attribute(
-        *mapped_file, api::FlagValueType::Boolean, offset);
-    ASSERT_TRUE(attribute.ok());
-    ASSERT_TRUE(*attribute & api::FlagInfoBit::HasServerOverride);
-  }
-
-  // load the file on disk and check has been updated
-  std::ifstream file(flag_info, std::ios::binary | std::ios::ate);
-  std::streamsize size = file.tellg();
-  file.seekg(0, std::ios::beg);
-
-  std::vector<uint8_t> buffer(size);
-  file.read(reinterpret_cast<char *>(buffer.data()), size);
-
-  auto content = rust::Slice<const uint8_t>(
-      buffer.data(), mapped_file->file_size);
-
-  for (int offset = 0; offset < 8; ++offset) {
-    auto attribute = get_flag_attribute_cxx(content, api::FlagValueType::Boolean, offset);
-    ASSERT_TRUE(attribute.query_success);
-    ASSERT_TRUE(attribute.flag_attribute & api::FlagInfoBit::HasServerOverride);
-  }
-
-  for (int offset = 0; offset < 8; ++offset) {
-    auto update_result = api::set_flag_has_server_override(
-        *mapped_file, api::FlagValueType::Boolean, offset, false);
-    ASSERT_TRUE(update_result.ok());
-    auto attribute = api::get_flag_attribute(
-        *mapped_file, api::FlagValueType::Boolean, offset);
-    ASSERT_TRUE(attribute.ok());
-    ASSERT_FALSE(*attribute & api::FlagInfoBit::HasServerOverride);
-  }
-
-  std::ifstream file2(flag_info, std::ios::binary);
-  buffer.clear();
-  file2.read(reinterpret_cast<char *>(buffer.data()), size);
-  for (int offset = 0; offset < 8; ++offset) {
-    auto attribute = get_flag_attribute_cxx(content, api::FlagValueType::Boolean, offset);
-    ASSERT_TRUE(attribute.query_success);
-    ASSERT_FALSE(attribute.flag_attribute & api::FlagInfoBit::HasServerOverride);
-  }
-}
-
-/// Test to lock down storage flag has local override update api
-TEST_F(AconfigStorageTest, test_flag_has_local_override_update) {
-  auto mapped_file_result = api::map_mutable_storage_file(flag_info);
-  ASSERT_TRUE(mapped_file_result.ok());
-  auto mapped_file = std::unique_ptr<api::MutableMappedStorageFile>(*mapped_file_result);
-
-  for (int offset = 0; offset < 8; ++offset) {
-    auto update_result = api::set_flag_has_local_override(
-        *mapped_file, api::FlagValueType::Boolean, offset, true);
-    ASSERT_TRUE(update_result.ok());
-    auto attribute = api::get_flag_attribute(
-        *mapped_file, api::FlagValueType::Boolean, offset);
-    ASSERT_TRUE(attribute.ok());
-    ASSERT_TRUE(*attribute & api::FlagInfoBit::HasLocalOverride);
-  }
-
-  // load the file on disk and check has been updated
-  std::ifstream file(flag_info, std::ios::binary | std::ios::ate);
-  std::streamsize size = file.tellg();
-  file.seekg(0, std::ios::beg);
-
-  std::vector<uint8_t> buffer(size);
-  file.read(reinterpret_cast<char *>(buffer.data()), size);
-
-  auto content = rust::Slice<const uint8_t>(
-      buffer.data(), mapped_file->file_size);
-
-  for (int offset = 0; offset < 8; ++offset) {
-    auto attribute = get_flag_attribute_cxx(content, api::FlagValueType::Boolean, offset);
-    ASSERT_TRUE(attribute.query_success);
-    ASSERT_TRUE(attribute.flag_attribute & api::FlagInfoBit::HasLocalOverride);
-  }
-
-  for (int offset = 0; offset < 8; ++offset) {
-    auto update_result = api::set_flag_has_local_override(
-        *mapped_file, api::FlagValueType::Boolean, offset, false);
-    ASSERT_TRUE(update_result.ok());
-    auto attribute = api::get_flag_attribute(
-        *mapped_file, api::FlagValueType::Boolean, offset);
-    ASSERT_TRUE(attribute.ok());
-    ASSERT_FALSE(*attribute & api::FlagInfoBit::HasLocalOverride);
-  }
-
-  std::ifstream file2(flag_info, std::ios::binary);
-  buffer.clear();
-  file2.read(reinterpret_cast<char *>(buffer.data()), size);
-  for (int offset = 0; offset < 8; ++offset) {
-    auto attribute = get_flag_attribute_cxx(content, api::FlagValueType::Boolean, offset);
-    ASSERT_TRUE(attribute.query_success);
-    ASSERT_FALSE(attribute.flag_attribute & api::FlagInfoBit::HasLocalOverride);
-  }
-}
diff --git a/tools/aconfig/aflags/src/main.rs b/tools/aconfig/aflags/src/main.rs
index 568ad999e0..dd1a48bf9f 100644
--- a/tools/aconfig/aflags/src/main.rs
+++ b/tools/aconfig/aflags/src/main.rs
@@ -132,11 +132,6 @@ trait FlagSource {
     fn override_flag(namespace: &str, qualified_name: &str, value: &str) -> Result<()>;
 }
 
-enum FlagSourceType {
-    DeviceConfig,
-    AconfigStorage,
-}
-
 const ABOUT_TEXT: &str = "Tool for reading and writing flags.
 
 Rows in the table from the `list` command follow this format:
@@ -184,9 +179,6 @@ enum Command {
         /// <package>.<flag_name>
         qualified_name: String,
     },
-
-    /// Display which flag storage backs aconfig flags.
-    WhichBacking,
 }
 
 struct PaddingInfo {
@@ -251,11 +243,8 @@ fn set_flag(qualified_name: &str, value: &str) -> Result<()> {
     Ok(())
 }
 
-fn list(source_type: FlagSourceType, container: Option<String>) -> Result<String> {
-    let flags_unfiltered = match source_type {
-        FlagSourceType::DeviceConfig => DeviceConfigSource::list_flags()?,
-        FlagSourceType::AconfigStorage => AconfigStorageSource::list_flags()?,
-    };
+fn list(container: Option<String>) -> Result<String> {
+    let flags_unfiltered = AconfigStorageSource::list_flags()?;
 
     if let Some(ref c) = container {
         ensure!(
@@ -293,19 +282,12 @@ fn list(source_type: FlagSourceType, container: Option<String>) -> Result<String
     Ok(result)
 }
 
-fn display_which_backing() -> String {
-    if aconfig_flags::auto_generated::enable_only_new_storage() {
-        "aconfig_storage".to_string()
-    } else {
-        "device_config".to_string()
-    }
-}
-
 fn invoke_updatable_aflags() {
     let updatable_command = "/apex/com.android.configinfrastructure/bin/aflags_updatable";
 
     let args: Vec<String> = env::args().collect();
-    let command_args = if args.len() >= 2 { &args[1..] } else { &["--help".to_string()] };
+    let default_command_args = ["--help".to_string()];
+    let command_args = if args.len() >= 2 { &args[1..] } else { &default_command_args };
 
     let mut child = OsCommand::new(updatable_command);
     for arg in command_args {
@@ -337,17 +319,10 @@ fn main() -> Result<()> {
     let cli = Cli::parse();
     let output = match cli.command {
         Command::List { container } => {
-            if aconfig_flags::auto_generated::enable_only_new_storage() {
-                list(FlagSourceType::AconfigStorage, container)
-                    .map_err(|err| anyhow!("could not list flags: {err}"))
-                    .map(Some)
-            } else {
-                list(FlagSourceType::DeviceConfig, container).map(Some)
-            }
+            list(container).map_err(|err| anyhow!("could not list flags: {err}")).map(Some)
         }
         Command::Enable { qualified_name } => set_flag(&qualified_name, "true").map(|_| None),
         Command::Disable { qualified_name } => set_flag(&qualified_name, "false").map(|_| None),
-        Command::WhichBacking => Ok(Some(display_which_backing())),
     };
     match output {
         Ok(Some(text)) => println!("{text}"),
diff --git a/tools/aconfig/convert_finalized_flags/Android.bp b/tools/aconfig/convert_finalized_flags/Android.bp
index 9ace80597a..0acc15bede 100644
--- a/tools/aconfig/convert_finalized_flags/Android.bp
+++ b/tools/aconfig/convert_finalized_flags/Android.bp
@@ -14,9 +14,12 @@ rust_defaults {
         "libprotobuf",
         "libserde",
         "libserde_json",
-        "libtempfile",
         "libtinytemplate",
     ],
+    features: select(release_flag("RELEASE_ACONFIG_SUPPORT_MINOR_SDK"), {
+        true: ["support_minor_sdk"],
+        default: [],
+    }),
 }
 
 rust_library_host {
@@ -43,6 +46,9 @@ rust_test_host {
     defaults: ["convert_finalized_flags.defaults"],
     test_suites: ["general-tests"],
     srcs: ["src/lib.rs"],
+    rustlibs: [
+        "libtempfile",
+    ],
 }
 
 genrule {
@@ -50,11 +56,16 @@ genrule {
     srcs: [
         "//prebuilts/sdk:finalized-api-flags",
     ],
-    tool_files: ["extended_flags_list_35.txt"],
+    tool_files: [
+        "sdk/35/extended_flags_list.txt",
+        "sdk/36/extended_flags_list.txt",
+    ],
     out: ["finalized_flags_record.json"],
     tools: ["convert_finalized_flags"],
     cmd: "args=\"\" && " +
         "for f in $(locations //prebuilts/sdk:finalized-api-flags); " +
         " do args=\"$$args --flag_file_path $$f\"; done && " +
-        "$(location convert_finalized_flags) $$args  --extended-flag-file-path $(location extended_flags_list_35.txt) > $(out)",
+        "$(location convert_finalized_flags) $$args " +
+        "  --flag_file_path $(location sdk/35/extended_flags_list.txt) " +
+        "  --flag_file_path $(location sdk/36/extended_flags_list.txt) > $(out)",
 }
diff --git a/tools/aconfig/convert_finalized_flags/Cargo.toml b/tools/aconfig/convert_finalized_flags/Cargo.toml
index e34e030841..4bf8da8486 100644
--- a/tools/aconfig/convert_finalized_flags/Cargo.toml
+++ b/tools/aconfig/convert_finalized_flags/Cargo.toml
@@ -6,6 +6,7 @@ edition = "2021"
 [features]
 default = ["cargo"]
 cargo = []
+support_minor_sdk = []
 
 [dependencies]
 anyhow = "1.0.69"
diff --git a/tools/aconfig/convert_finalized_flags/extended_flags_list_35.txt b/tools/aconfig/convert_finalized_flags/sdk/35/extended_flags_list.txt
similarity index 100%
rename from tools/aconfig/convert_finalized_flags/extended_flags_list_35.txt
rename to tools/aconfig/convert_finalized_flags/sdk/35/extended_flags_list.txt
diff --git a/tools/aconfig/convert_finalized_flags/sdk/36/extended_flags_list.txt b/tools/aconfig/convert_finalized_flags/sdk/36/extended_flags_list.txt
new file mode 100644
index 0000000000..d1c0f41344
--- /dev/null
+++ b/tools/aconfig/convert_finalized_flags/sdk/36/extended_flags_list.txt
@@ -0,0 +1,242 @@
+android.adpf.adpf_viewrootimpl_action_down_boost
+android.app.pic_uses_shared_memory
+android.app.supervision.flags.supervision_api
+android.app.supervision.flags.supervision_api_on_wear
+android.appwidget.flags.use_smaller_app_widget_system_radius
+android.car.feature.android_b_vehicle_properties
+android.car.feature.audio_vendor_freeze_improvements
+android.car.feature.visible_background_user_restrictions
+android.companion.virtualdevice.flags.notifications_for_device_streaming
+android.content.pm.uid_based_provider_lookup
+android.content.res.self_targeting_android_resource_frro
+android.content.res.system_context_handle_app_info_changed
+android.content.res.use_new_aconfig_storage
+android.credentials.flags.propagate_user_context_for_intent_creation
+android.database.sqlite.concurrent_open_helper
+android.hardware.biometrics.screen_off_unlock_udfps
+android.hardware.devicestate.feature.flags.device_state_configuration_flag
+android.hardware.devicestate.feature.flags.device_state_property_migration
+android.hardware.devicestate.feature.flags.device_state_rdm_v2
+android.hardware.usb.flags.enable_interface_name_device_filter
+android.location.flags.geoid_heights_via_altitude_hal
+android.location.flags.gnss_api_measurement_request_work_source
+android.location.flags.gnss_api_navic_l1
+android.location.flags.new_geocoder
+android.media.audio.muted_by_port_volume_api
+android.media.swcodec.flags.apv_software_codec
+android.media.swcodec.flags.mpeg2_keep_threads_active
+android.media.tv.flags.hdmi_control_enhanced_behavior
+android.media.tv.flags.tif_extension_standardization
+android.media.tv.flags.tif_unbind_inactive_tis
+android.net.http.preload_httpengine_in_zygote
+android.net.vcn.mainline_vcn_module_api
+android.nfc.enable_card_emulation_euicc
+android.nfc.nfc_check_tag_intent_preference
+android.nfc.nfc_event_listener
+android.nfc.nfc_oem_extension
+android.nfc.nfc_override_recover_routing_table
+android.nfc.nfc_persist_log
+android.nfc.nfc_set_default_disc_tech
+android.nfc.nfc_set_service_enabled_for_category_other
+android.nfc.nfc_state_change
+android.nfc.nfc_watchdog
+android.os.network_time_uses_shared_memory
+android.os.profiling.persist_queue
+android.os.profiling.system_triggered_profiling_new
+android.permission.flags.allow_host_permission_dialogs_on_virtual_devices
+android.permission.flags.enable_otp_in_text_classifiers
+android.permission.flags.enhanced_confirmation_in_call_apis_enabled
+android.permission.flags.location_bypass_privacy_dashboard_enabled
+android.permission.flags.note_op_batching_enabled
+android.permission.flags.supervision_role_permission_update_enabled
+android.permission.flags.unknown_call_package_install_blocking_enabled
+android.permission.flags.unknown_call_setting_blocked_logging_enabled
+android.permission.flags.updatable_text_classifier_for_otp_detection_enabled
+android.permission.flags.use_profile_labels_for_default_app_section_titles
+android.permission.flags.wallet_role_cross_user_enabled
+android.provider.allow_config_maximum_call_log_entries_per_sim
+android.provider.flags.device_config_writable_namespaces_api
+android.provider.flags.new_storage_public_api
+android.view.contentcapture.flags.flush_after_each_frame
+android.view.inputmethod.concurrent_input_methods
+android.view.inputmethod.ime_switcher_revamp
+android.widget.flags.use_wear_material3_ui
+com.android.adservices.flags.ad_id_cache_enabled
+com.android.adservices.flags.adext_data_service_apis_enabled
+com.android.adservices.flags.adservices_enable_per_module_overrides_api
+com.android.adservices.flags.adservices_enablement_check_enabled
+com.android.adservices.flags.adservices_outcomereceiver_r_api_deprecated
+com.android.adservices.flags.adservices_outcomereceiver_r_api_enabled
+com.android.adservices.flags.enable_adservices_api_enabled
+com.android.adservices.flags.fledge_ad_selection_filtering_enabled
+com.android.adservices.flags.fledge_auction_server_get_ad_selection_data_id_enabled
+com.android.adservices.flags.fledge_custom_audience_auction_server_request_flags_enabled
+com.android.adservices.flags.fledge_enable_custom_audience_component_ads
+com.android.adservices.flags.fledge_enable_schedule_custom_audience_default_partial_custom_audiences_constructor
+com.android.adservices.flags.fledge_get_ad_selection_data_seller_configuration_enabled
+com.android.adservices.flags.fledge_schedule_custom_audience_update_enabled
+com.android.adservices.flags.fledge_server_auction_multi_cloud_enabled
+com.android.adservices.flags.protected_signals_enabled
+com.android.adservices.flags.sdksandbox_invalidate_effective_target_sdk_version_cache
+com.android.adservices.flags.sdksandbox_use_effective_target_sdk_version_for_restrictions
+com.android.adservices.flags.topics_encryption_enabled
+com.android.adservices.ondevicepersonalization.flags.data_class_missing_ctors_and_getters_enabled
+com.android.adservices.ondevicepersonalization.flags.execute_in_isolated_service_api_enabled
+com.android.adservices.ondevicepersonalization.flags.fcp_model_version_enabled
+com.android.appsearch.flags.app_open_event_indexer_enabled
+com.android.appsearch.flags.apps_indexer_enabled
+com.android.appsearch.flags.enable_additional_builder_copy_constructors
+com.android.appsearch.flags.enable_apps_indexer_incremental_put
+com.android.appsearch.flags.enable_blob_store
+com.android.appsearch.flags.enable_check_contacts_indexer_delta_timestamps
+com.android.appsearch.flags.enable_contacts_index_first_middle_and_last_names
+com.android.appsearch.flags.enable_document_limiter_replace_tracking
+com.android.appsearch.flags.enable_enterprise_empty_batch_result_fix
+com.android.appsearch.flags.enable_generic_document_over_ipc
+com.android.appsearch.flags.enable_informational_ranking_expressions
+com.android.appsearch.flags.enable_list_filter_match_score_expression_function
+com.android.appsearch.flags.enable_result_already_exists
+com.android.appsearch.flags.enable_result_denied_and_result_rate_limited
+com.android.appsearch.flags.enable_schema_embedding_property_config
+com.android.appsearch.flags.enable_schema_embedding_quantization
+com.android.appsearch.flags.enable_scorable_property
+com.android.appsearch.flags.enable_search_result_parent_types
+com.android.appsearch.flags.enable_search_spec_filter_document_ids
+com.android.appsearch.flags.enable_search_spec_search_string_parameters
+com.android.art.flags.art_service_v3
+com.android.bluetooth.flags.aics_api
+com.android.bluetooth.flags.channel_sounding_25q2_apis
+com.android.bluetooth.flags.directed_advertising_api
+com.android.bluetooth.flags.encryption_change_broadcast
+com.android.bluetooth.flags.hci_vendor_specific_extension
+com.android.bluetooth.flags.identity_address_type_api
+com.android.bluetooth.flags.key_missing_public
+com.android.bluetooth.flags.leaudio_add_opus_codec_type
+com.android.bluetooth.flags.leaudio_broadcast_api_get_local_metadata
+com.android.bluetooth.flags.leaudio_broadcast_api_manage_primary_group
+com.android.bluetooth.flags.leaudio_mono_location_errata_api
+com.android.bluetooth.flags.metadata_api_microphone_for_call_enabled
+com.android.bluetooth.flags.socket_settings_api
+com.android.bluetooth.flags.support_bluetooth_quality_report_v6
+com.android.bluetooth.flags.support_metadata_device_types_apis
+com.android.graphics.hwui.flags.animated_image_drawable_filter_bitmap
+com.android.hardware.input.manage_key_gestures
+com.android.healthconnect.flags.background_read
+com.android.healthconnect.flags.history_read
+com.android.healthfitness.flags.activity_intensity
+com.android.healthfitness.flags.activity_intensity_db
+com.android.healthfitness.flags.add_missing_access_logs
+com.android.healthfitness.flags.export_import
+com.android.healthfitness.flags.export_import_fast_follow
+com.android.healthfitness.flags.health_connect_mappings
+com.android.healthfitness.flags.mindfulness
+com.android.healthfitness.flags.new_information_architecture
+com.android.healthfitness.flags.personal_health_record
+com.android.healthfitness.flags.personal_health_record_database
+com.android.healthfitness.flags.personal_health_record_disable_export_import
+com.android.healthfitness.flags.personal_health_record_enable_d2d_and_export_import
+com.android.healthfitness.flags.personal_health_record_enable_export_import
+com.android.healthfitness.flags.personal_health_record_lock_screen_banner
+com.android.healthfitness.flags.personal_health_record_telemetry
+com.android.healthfitness.flags.personal_health_record_telemetry_private_ww
+com.android.healthfitness.flags.personal_health_record_ui_telemetry
+com.android.healthfitness.flags.phr_fhir_basic_complex_type_validation
+com.android.healthfitness.flags.phr_fhir_primitive_type_validation
+com.android.healthfitness.flags.phr_fhir_structural_validation
+com.android.healthfitness.flags.phr_read_medical_resources_fix_query_limit
+com.android.healthfitness.flags.phr_upsert_fix_parcel_size_calculation
+com.android.healthfitness.flags.phr_upsert_fix_use_shared_memory
+com.android.icu.icu_25q2_api
+com.android.icu.telephony_lookup_mcc_extension
+com.android.internal.telephony.flags.async_init_carrier_privileges_tracker
+com.android.internal.telephony.flags.pass_copied_call_state_list
+com.android.internal.telephony.flags.remap_disconnect_cause_sip_request_cancelled
+com.android.internal.telephony.flags.starlink_data_bugfix
+com.android.libcore.native_metrics
+com.android.libcore.openjdk21_stringconcat
+com.android.libcore.openjdk_21_v1_apis
+com.android.libcore.post_cleanup_apis
+com.android.libcore.read_only_dynamic_code_load
+com.android.media.audio.hardening_impl
+com.android.media.extractor.flags.extractor_mp4_enable_apv
+com.android.media.extractor.flags.extractor_sniff_midi_optimizations
+com.android.media.projection.flags.media_projection_connected_display
+com.android.media.projection.flags.media_projection_connected_display_no_virtual_device
+com.android.media.projection.flags.show_stop_dialog_post_call_end
+com.android.net.ct.flags.certificate_transparency_job
+com.android.net.ct.flags.certificate_transparency_service
+com.android.net.flags.ipv6_over_ble
+com.android.net.flags.net_capability_not_bandwidth_constrained
+com.android.net.flags.netstats_add_entries
+com.android.net.flags.tethering_with_soft_ap_config
+com.android.net.thread.flags.channel_max_powers_enabled
+com.android.net.thread.flags.configuration_enabled
+com.android.net.thread.flags.epskc_enabled
+com.android.net.thread.flags.set_nat64_configuration_enabled
+com.android.nfc.module.flags.nfc_hce_latency_events
+com.android.org.conscrypt.flags.certificate_transparency_checkservertrusted_api
+com.android.org.conscrypt.flags.spake2plus_api
+com.android.permission.flags.add_banners_to_privacy_sensitive_apps_for_aaos
+com.android.permission.flags.app_permission_fragment_uses_preferences
+com.android.permission.flags.archiving_read_only
+com.android.permission.flags.cross_user_role_enabled
+com.android.permission.flags.cross_user_role_ux_bugfix_enabled
+com.android.permission.flags.default_apps_recommendation_enabled
+com.android.permission.flags.odad_notifications_supported
+com.android.permission.flags.permission_timeline_attribution_label_fix
+com.android.permission.flags.safety_center_enabled_no_device_config
+com.android.permission.flags.safety_center_issue_only_affects_group_status
+com.android.providers.media.flags.audio_sample_columns
+com.android.providers.media.flags.cloud_media_provider_search
+com.android.providers.media.flags.enable_cloud_media_provider_capabilities
+com.android.providers.media.flags.enable_embedded_photopicker
+com.android.providers.media.flags.enable_mark_is_favorite_status_api
+com.android.providers.media.flags.enable_oem_metadata
+com.android.providers.media.flags.enable_photopicker_search
+com.android.providers.media.flags.enable_photopicker_transcoding
+com.android.providers.media.flags.enable_stable_uris_for_external_primary_volume
+com.android.providers.media.flags.enable_unicode_check
+com.android.providers.media.flags.inferred_media_date
+com.android.providers.media.flags.media_cognition_service
+com.android.providers.media.flags.media_store_open_file
+com.android.providers.media.flags.motion_photo_intent
+com.android.providers.media.flags.picker_pre_selection_extra
+com.android.providers.media.flags.revoke_access_owned_photos
+com.android.providers.media.flags.version_lockdown
+com.android.ranging.flags.ranging_rtt_enabled
+com.android.sdksandbox.flags.sandbox_activity_sdk_based_context
+com.android.sdksandbox.flags.sandbox_client_importance_listener
+com.android.sdksandbox.flags.selinux_input_selector
+com.android.sdksandbox.flags.selinux_sdk_sandbox_audit
+com.android.server.telecom.flags.allow_system_apps_resolve_voip_calls
+com.android.server.telecom.flags.telecom_main_user_in_block_check
+com.android.server.telecom.flags.telecom_main_user_in_get_respond_message_app
+com.android.system.virtualmachine.flags.promote_set_should_use_hugepages_to_system_api
+com.android.tradeinmode.flags.enable_trade_in_mode
+com.android.wifi.flags.ap_isolate
+com.android.wifi.flags.autojoin_restriction_security_types_api
+com.android.wifi.flags.aware_pairing
+com.android.wifi.flags.bssid_blocklist_for_suggestion
+com.android.wifi.flags.get_bssid_blocklist_api
+com.android.wifi.flags.get_channel_width_api
+com.android.wifi.flags.local_only_connection_optimization
+com.android.wifi.flags.mlo_sap
+com.android.wifi.flags.public_bands_for_lohs
+com.android.wifi.flags.secure_ranging
+com.android.wifi.flags.softap_disconnect_reason
+com.android.wifi.flags.wep_disabled_in_apm
+com.android.wifi.flags.wifi_direct_r2
+com.android.wifi.flags.wifi_state_changed_listener
+com.android.window.flags.fix_hide_overlay_api
+com.google.wear.sdk.enable_can_app_be_muted
+com.google.wear.sdk.require_manage_tiles_permission
+com.google.wear.sdk.rotary_scroll_haptic_constants
+com.google.wear.sdk.wear_api_version
+com.google.wear.sdk.wrist_detection_auto_locking_api
+com.google.wear.services.infra.flags.enable_get_active_tiles_api
+com.google.wear.services.infra.flags.enable_get_packages_to_reinstall_from_pending_state_api
+com.google.wear.services.infra.flags.enable_tether_config_client_feature_extensions_v2
+com.google.wear.services.infra.flags.enable_tiles_api_for_wearsky
+com.google.wear.services.infra.flags.enable_transfer_editing_session
+vendor.google.wireless_charger.service.flags.enable_service
+vendor.vibrator.hal.flags.remove_capo
diff --git a/tools/aconfig/convert_finalized_flags/src/lib.rs b/tools/aconfig/convert_finalized_flags/src/lib.rs
index 335a31b046..d531a41fc6 100644
--- a/tools/aconfig/convert_finalized_flags/src/lib.rs
+++ b/tools/aconfig/convert_finalized_flags/src/lib.rs
@@ -25,9 +25,16 @@ use serde::{Deserialize, Serialize};
 use std::collections::{HashMap, HashSet};
 use std::fs;
 use std::io::{self, BufRead};
+use std::str::FromStr;
 
+/// Mirrors the Java API in android.os.Build.
 const SDK_INT_MULTIPLIER: u32 = 100_000;
 
+/// SDK_INT_FULL was introduced in Baklava, so checking SDK_INT_FULL on a lower
+/// version would throw an exception. Therefore, we shouldn't allow the creation
+/// of a lower version.
+const MIN_SDK_INT_FULL: u32 = SDK_INT_MULTIPLIER * 36;
+
 /// Just the fully qualified flag name (package_name.flag_name).
 #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
 pub struct FinalizedFlag {
@@ -37,12 +44,64 @@ pub struct FinalizedFlag {
     pub package_name: String,
 }
 
-/// API level in which the flag was finalized.
-#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
-pub struct ApiLevel(pub i32);
+/// API level check for the flag.
+#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
+pub struct ApiLevel(pub u32);
+
+impl ApiLevel {
+    /// Creates an api level check against Build.VERSION.SDK_INT.
+    pub fn from_sdk_int(level: u32) -> Self {
+        if level > SDK_INT_MULTIPLIER {
+            panic!("SDK_INT value too large.");
+        }
+        ApiLevel(level)
+    }
+
+    /// Creates an api level check against Build.VERSION.SDK_INT_FULL.
+    /// Since SDK_INT_FULL was introduced in Baklava, only works for levels above
+    /// 3_600_000 (panics otherwise).
+    pub fn from_sdk_int_full(level: u32) -> Self {
+        if level < MIN_SDK_INT_FULL {
+            panic!("Cannot use SDK_INT_FULL below Baklava (36).");
+        }
 
-/// API level of the extended flags file of version 35
-pub const EXTENDED_FLAGS_35_APILEVEL: ApiLevel = ApiLevel(35);
+        ApiLevel(level)
+    }
+
+    /// Returns the string condition to check if the flag is finalized on device
+    /// in Java.
+    pub fn conditional(&self) -> String {
+        if self.0 < SDK_INT_MULTIPLIER {
+            format!("Build.VERSION.SDK_INT >= {}", self.0)
+        } else if self.0 < MIN_SDK_INT_FULL {
+            panic!("Invalid SDK level ({}) - greater than the multiplier but less than the supported level.", self.0);
+        } else {
+            format!("Build.VERSION.SDK_INT >= 36 && Build.VERSION.SDK_INT_FULL >= {}", self.0)
+        }
+    }
+}
+
+impl FromStr for ApiLevel {
+    type Err = anyhow::Error;
+
+    /// Converts a string to the appropriate ApiLevel.
+    fn from_str(s: &str) -> Result<Self, Self::Err> {
+        let float_value = s.parse::<f64>()?;
+
+        if float_value.fract() == 0.0 {
+            return Ok(ApiLevel::from_sdk_int(float_value as u32));
+        }
+
+        if cfg!(feature = "support_minor_sdk") {
+            match parse_full_version(s.to_string()) {
+                Ok(full_sdk_int) => Ok(ApiLevel::from_sdk_int_full(full_sdk_int)),
+                Err(e) => Err(e),
+            }
+        } else {
+            Err(anyhow!("Numeric string is float, can't parse to int."))
+        }
+    }
+}
 
 /// Contains all flags finalized for a given API level.
 #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
@@ -63,7 +122,7 @@ impl FinalizedFlagMap {
     pub fn get_finalized_level(&self, flag: &FinalizedFlag) -> Option<ApiLevel> {
         for (api_level, flags_for_level) in &self.0 {
             if flags_for_level.contains(flag) {
-                return Some(*api_level);
+                return Some(api_level.clone());
             }
         }
         None
@@ -83,7 +142,6 @@ impl FinalizedFlagMap {
     }
 }
 
-#[allow(dead_code)] // TODO: b/378936061: Use with SDK_INT_FULL check.
 fn parse_full_version(version: String) -> Result<u32> {
     let (major, minor) = if let Some(decimal_index) = version.find('.') {
         (version[..decimal_index].parse::<u32>()?, version[decimal_index + 1..].parse::<u32>()?)
@@ -101,20 +159,6 @@ fn parse_full_version(version: String) -> Result<u32> {
     Ok(major * SDK_INT_MULTIPLIER + minor)
 }
 
-const EXTENDED_FLAGS_LIST_35: &str = "extended_flags_list_35.txt";
-
-/// Converts a string to an int. Will parse to int even if the string is "X.0".
-/// Returns error for "X.1".
-fn str_to_api_level(numeric_string: &str) -> Result<ApiLevel> {
-    let float_value = numeric_string.parse::<f64>()?;
-
-    if float_value.fract() == 0.0 {
-        Ok(ApiLevel(float_value as i32))
-    } else {
-        Err(anyhow!("Numeric string is float, can't parse to int."))
-    }
-}
-
 /// For each file, extracts the qualified flag names into a FinalizedFlag, then
 /// enters them in a map at the API level corresponding to their directory.
 /// Ex: /prebuilts/sdk/35/finalized-flags.txt -> {36, [flag1, flag2]}.
@@ -126,19 +170,18 @@ pub fn read_files_to_map_using_path(flag_files: Vec<String>) -> Result<Finalized
         let flag_file_split: Vec<String> =
             flag_file.clone().rsplitn(3, '/').map(|s| s.to_string()).collect();
 
-        if &flag_file_split[0] != "finalized-flags.txt" {
-            return Err(anyhow!("Provided incorrect file, must be finalized-flags.txt"));
+        if &flag_file_split[0] != "finalized-flags.txt"
+            && &flag_file_split[0] != "extended_flags_list.txt"
+        {
+            return Err(anyhow!(
+                "Provided incorrect file, must be finalized-flags.txt or extended_flags_list.txt"
+            ));
         }
 
         let api_level_string = &flag_file_split[1];
 
-        // For now, skip any directory with full API level, e.g. "36.1". The
-        // finalized flag files each contain all flags finalized *up to* that
-        // level (including prior levels), so skipping intermediate levels means
-        // the flags will be included at the next full number.
-        // TODO: b/378936061 - Support full SDK version.
         // In the future, we should error if provided a non-numeric directory.
-        let Ok(api_level) = str_to_api_level(api_level_string) else {
+        let Ok(api_level) = ApiLevel::from_str(api_level_string) else {
             continue;
         };
 
@@ -149,32 +192,13 @@ pub fn read_files_to_map_using_path(flag_files: Vec<String>) -> Result<Finalized
                 flag.unwrap_or_else(|_| panic!("Failed to read line from file {}", flag_file));
             let finalized_flag = build_finalized_flag(&flag)
                 .unwrap_or_else(|_| panic!("cannot build finalized flag {}", flag));
-            data_map.insert_if_new(api_level, finalized_flag);
+            data_map.insert_if_new(api_level.clone(), finalized_flag);
         });
     }
 
     Ok(data_map)
 }
 
-/// Read the qualified flag names into a FinalizedFlag set
-pub fn read_extend_file_to_map_using_path(extened_file: String) -> Result<HashSet<FinalizedFlag>> {
-    let (_, file_name) =
-        extened_file.rsplit_once('/').ok_or(anyhow!("Invalid file: '{}'", extened_file))?;
-    if file_name != EXTENDED_FLAGS_LIST_35 {
-        return Err(anyhow!("Provided incorrect file, must be {}", EXTENDED_FLAGS_LIST_35));
-    }
-    let file = fs::File::open(extened_file)?;
-    let extended_flags = io::BufReader::new(file)
-        .lines()
-        .map(|flag| {
-            let flag = flag.expect("Failed to read line from extended file");
-            build_finalized_flag(&flag)
-                .unwrap_or_else(|_| panic!("cannot build finalized flag {}", flag))
-        })
-        .collect::<HashSet<FinalizedFlag>>();
-    Ok(extended_flags)
-}
-
 fn build_finalized_flag(qualified_flag_name: &String) -> Result<FinalizedFlag> {
     // Split the qualified flag name into package and flag name:
     // com.my.package.name.my_flag_name -> ('com.my.package.name', 'my_flag_name')
@@ -230,8 +254,8 @@ mod tests {
         let map = read_files_to_map_using_path(vec![flag_file_path]).unwrap();
 
         assert_eq!(map.0.len(), 1);
-        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[0]));
-        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[1]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(35)).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(35)).unwrap().contains(&flags[1]));
     }
 
     #[test]
@@ -263,12 +287,12 @@ mod tests {
 
         // Assert there are two API levels, 35 and 36.
         assert_eq!(map.0.len(), 2);
-        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(35)).unwrap().contains(&flags[0]));
 
         // 36 should not have the first flag in the set, as it was finalized in
         // an earlier API level.
-        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[1]));
-        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[2]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(36)).unwrap().contains(&flags[1]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(36)).unwrap().contains(&flags[2]));
     }
 
     #[test]
@@ -299,11 +323,12 @@ mod tests {
         let map = read_files_to_map_using_path(vec![flag_file_path1, flag_file_path2]).unwrap();
 
         assert_eq!(map.0.len(), 2);
-        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[0]));
-        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[1]));
-        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[2]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(35)).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(36)).unwrap().contains(&flags[1]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(36)).unwrap().contains(&flags[2]));
     }
 
+    #[cfg(not(feature = "support_minor_sdk"))]
     #[test]
     fn test_read_flags_fractions_round_up() {
         let flags = create_test_flags();
@@ -311,13 +336,13 @@ mod tests {
         // Create the file <temp_dir>/35/finalized-flags.txt and for 36.
         let temp_dir = tempdir().unwrap();
         let mut file_path1 = temp_dir.path().to_path_buf();
-        file_path1.push("35.1");
+        file_path1.push("36.1");
         fs::create_dir_all(&file_path1).unwrap();
         file_path1.push(FLAG_FILE_NAME);
         let mut file1 = File::create(&file_path1).unwrap();
 
         let mut file_path2 = temp_dir.path().to_path_buf();
-        file_path2.push("36.0");
+        file_path2.push("37.0");
         fs::create_dir_all(&file_path2).unwrap();
         file_path2.push(FLAG_FILE_NAME);
         let mut file2 = File::create(&file_path2).unwrap();
@@ -333,10 +358,46 @@ mod tests {
 
         // No flags were added in 35. All 35.1 flags were rolled up to 36.
         assert_eq!(map.0.len(), 1);
-        assert!(!map.0.contains_key(&ApiLevel(35)));
-        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[0]));
-        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[1]));
-        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[2]));
+        assert!(!map.0.contains_key(&ApiLevel::from_sdk_int(36)));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(37)).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(37)).unwrap().contains(&flags[1]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(37)).unwrap().contains(&flags[2]));
+    }
+
+    #[cfg(feature = "support_minor_sdk")]
+    #[test]
+    fn test_read_flags_fractions_creates_full_sdk() {
+        let flags = create_test_flags();
+
+        // Create the file <temp_dir>/35/finalized-flags.txt and for 36.
+        let temp_dir = tempdir().unwrap();
+        let mut file_path1 = temp_dir.path().to_path_buf();
+        file_path1.push("36.1");
+        fs::create_dir_all(&file_path1).unwrap();
+        file_path1.push(FLAG_FILE_NAME);
+        let mut file1 = File::create(&file_path1).unwrap();
+
+        let mut file_path2 = temp_dir.path().to_path_buf();
+        file_path2.push("37.0");
+        fs::create_dir_all(&file_path2).unwrap();
+        file_path2.push(FLAG_FILE_NAME);
+        let mut file2 = File::create(&file_path2).unwrap();
+
+        // Write all flags to the files.
+        add_flags_to_file(&mut file1, &[flags[0].clone()]);
+        add_flags_to_file(&mut file2, &[flags[0].clone(), flags[1].clone(), flags[2].clone()]);
+        let flag_file_path1 = file_path1.to_string_lossy().to_string();
+        let flag_file_path2 = file_path2.to_string_lossy().to_string();
+
+        // Convert to map.
+        let map = read_files_to_map_using_path(vec![flag_file_path1, flag_file_path2]).unwrap();
+
+        // Support 35.1 and 36.0.
+        assert_eq!(map.0.len(), 2);
+        assert!(!map.0.contains_key(&ApiLevel::from_sdk_int(36)));
+        assert!(map.0.get(&ApiLevel::from_sdk_int_full(3_600_001)).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(37)).unwrap().contains(&flags[1]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(37)).unwrap().contains(&flags[2]));
     }
 
     #[test]
@@ -370,8 +431,8 @@ mod tests {
 
         // No set should be created for sdk-annotations.
         assert_eq!(map.0.len(), 1);
-        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[0]));
-        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[1]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(35)).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&ApiLevel::from_sdk_int(35)).unwrap().contains(&flags[1]));
     }
 
     #[test]
@@ -409,76 +470,135 @@ mod tests {
     fn test_flags_map_insert_if_new() {
         let flags = create_test_flags();
         let mut map = FinalizedFlagMap::new();
-        let l35 = ApiLevel(35);
-        let l36 = ApiLevel(36);
+        let l35 = ApiLevel::from_sdk_int(35);
+        let l36 = ApiLevel::from_sdk_int(36);
 
-        map.insert_if_new(l35, flags[0].clone());
-        map.insert_if_new(l35, flags[1].clone());
-        map.insert_if_new(l35, flags[2].clone());
-        map.insert_if_new(l36, flags[0].clone());
+        map.insert_if_new(l35.clone(), flags[0].clone());
+        map.insert_if_new(l35.clone(), flags[1].clone());
+        map.insert_if_new(l35.clone(), flags[2].clone());
+        map.insert_if_new(l36.clone(), flags[0].clone());
 
-        assert!(map.0.get(&l35).unwrap().contains(&flags[0]));
-        assert!(map.0.get(&l35).unwrap().contains(&flags[1]));
-        assert!(map.0.get(&l35).unwrap().contains(&flags[2]));
-        assert!(!map.0.contains_key(&l36));
+        assert!(map.0.get(&l35.clone()).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&l35.clone()).unwrap().contains(&flags[1]));
+        assert!(map.0.get(&l35.clone()).unwrap().contains(&flags[2]));
+        assert!(!map.0.contains_key(&l36.clone()));
     }
 
     #[test]
     fn test_flags_map_get_level() {
         let flags = create_test_flags();
         let mut map = FinalizedFlagMap::new();
-        let l35 = ApiLevel(35);
-        let l36 = ApiLevel(36);
+        let l35 = ApiLevel::from_sdk_int(35);
+        let l36 = ApiLevel::from_sdk_int(36);
 
         map.insert_if_new(l35, flags[0].clone());
         map.insert_if_new(l36, flags[1].clone());
 
-        assert_eq!(map.get_finalized_level(&flags[0]).unwrap(), l35);
-        assert_eq!(map.get_finalized_level(&flags[1]).unwrap(), l36);
+        assert_eq!(
+            map.get_finalized_level(&flags[0]).unwrap(),
+            //ApiLevel("Build.VERSION.SDK_INT >= 35".to_string())
+            ApiLevel(35)
+        );
+        assert_eq!(
+            map.get_finalized_level(&flags[1]).unwrap(),
+            //ApiLevel("Build.VERSION.SDK_INT >= 36".to_string())
+            ApiLevel(36)
+        );
     }
 
     #[test]
     fn test_read_flag_from_extended_file() {
         let flags = create_test_flags();
 
-        // Create the file <temp_dir>/35/extended_flags_list_35.txt
+        // Create the file <temp_dir>/35/extended_flags_list.txt
         let temp_dir = tempdir().unwrap();
         let mut file_path = temp_dir.path().to_path_buf();
         file_path.push("35");
         fs::create_dir_all(&file_path).unwrap();
-        file_path.push(EXTENDED_FLAGS_LIST_35);
+        file_path.push("extended_flags_list.txt");
         let mut file = File::create(&file_path).unwrap();
 
         // Write all flags to the file.
         add_flags_to_file(&mut file, &[flags[0].clone(), flags[1].clone()]);
 
-        let flags_set =
-            read_extend_file_to_map_using_path(file_path.to_string_lossy().to_string()).unwrap();
-        assert_eq!(flags_set.len(), 2);
-        assert!(flags_set.contains(&flags[0]));
-        assert!(flags_set.contains(&flags[1]));
+        let map =
+            read_files_to_map_using_path(vec![file_path.to_string_lossy().to_string()]).unwrap();
+        assert_eq!(map.0.len(), 1);
+        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[1]));
+    }
+
+    #[test]
+    fn test_read_flags_sdk_file_and_extended_file() {
+        let flags = create_test_flags();
+
+        // Create the file <temp_dir>/35/finalized-flags.txt
+        let temp_dir = tempdir().unwrap();
+        let mut file_path1 = temp_dir.path().to_path_buf();
+        file_path1.push("35");
+        fs::create_dir_all(&file_path1).unwrap();
+        file_path1.push(FLAG_FILE_NAME);
+        let mut file1 = File::create(&file_path1).unwrap();
+
+        // Create the file <temp_dir>/36/finalized-flags.txt
+        let temp_dir = tempdir().unwrap();
+        let mut file_path2 = temp_dir.path().to_path_buf();
+        file_path2.push("36");
+        fs::create_dir_all(&file_path2).unwrap();
+        file_path2.push(FLAG_FILE_NAME);
+        let mut file2 = File::create(&file_path2).unwrap();
+
+        // Create the file <temp_dir>/36/extended_flags_list.txt
+        let mut file_path3 = temp_dir.path().to_path_buf();
+        file_path3.push("36");
+        fs::create_dir_all(&file_path3).unwrap();
+        file_path3.push("extended_flags_list.txt");
+        let mut file3 = File::create(&file_path3).unwrap();
+
+        // Write all flags to the files.
+        add_flags_to_file(&mut file1, &[flags[0].clone()]);
+        add_flags_to_file(&mut file2, &[flags[0].clone(), flags[1].clone()]);
+        add_flags_to_file(&mut file3, &[flags[0].clone(), flags[1].clone(), flags[2].clone()]);
+        let flag_file_path1 = file_path1.to_string_lossy().to_string();
+        let flag_file_path2 = file_path2.to_string_lossy().to_string();
+        let flag_file_path3 = file_path3.to_string_lossy().to_string();
+
+        // Convert to map.
+        let map =
+            read_files_to_map_using_path(vec![flag_file_path1, flag_file_path2, flag_file_path3])
+                .unwrap();
+
+        // Assert there are two API levels, 35 and 36.
+        assert_eq!(map.0.len(), 2);
+        assert!(map.0.get(&ApiLevel(35)).unwrap().contains(&flags[0]));
+
+        // 36 should not have the first flag in the set, as it was finalized in
+        // an earlier API level.
+        assert!(!map.0.get(&ApiLevel(36)).unwrap().contains(&flags[0]));
+        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[1]));
+        assert!(map.0.get(&ApiLevel(36)).unwrap().contains(&flags[2]));
     }
 
     #[test]
     fn test_read_flag_from_wrong_extended_file_err() {
         let flags = create_test_flags();
 
-        // Create the file <temp_dir>/35/extended_flags_list.txt
+        // Create the file <temp_dir>/35/bar.txt
         let temp_dir = tempdir().unwrap();
         let mut file_path = temp_dir.path().to_path_buf();
         file_path.push("35");
         fs::create_dir_all(&file_path).unwrap();
-        file_path.push("extended_flags_list.txt");
+        file_path.push("bar.txt");
         let mut file = File::create(&file_path).unwrap();
 
         // Write all flags to the file.
         add_flags_to_file(&mut file, &[flags[0].clone(), flags[1].clone()]);
 
-        let err = read_extend_file_to_map_using_path(file_path.to_string_lossy().to_string())
+        let err = read_files_to_map_using_path(vec![file_path.to_string_lossy().to_string()])
             .unwrap_err();
         assert_eq!(
             format!("{:?}", err),
-            "Provided incorrect file, must be extended_flags_list_35.txt"
+            "Provided incorrect file, must be finalized-flags.txt or extended_flags_list.txt"
         );
     }
 
diff --git a/tools/aconfig/convert_finalized_flags/src/main.rs b/tools/aconfig/convert_finalized_flags/src/main.rs
index 605e964d7e..38300f6776 100644
--- a/tools/aconfig/convert_finalized_flags/src/main.rs
+++ b/tools/aconfig/convert_finalized_flags/src/main.rs
@@ -23,9 +23,7 @@
 use anyhow::Result;
 use clap::Parser;
 
-use convert_finalized_flags::{
-    read_extend_file_to_map_using_path, read_files_to_map_using_path, EXTENDED_FLAGS_35_APILEVEL,
-};
+use convert_finalized_flags::read_files_to_map_using_path;
 
 const ABOUT_TEXT: &str = "Tool for processing finalized-flags.txt files.
 
@@ -47,18 +45,11 @@ struct Cli {
     /// Flags files.
     #[arg(long = "flag_file_path")]
     flag_file_path: Vec<String>,
-
-    #[arg(long)]
-    extended_flag_file_path: String,
 }
 
 fn main() -> Result<()> {
     let cli = Cli::parse();
-    let mut finalized_flags_map = read_files_to_map_using_path(cli.flag_file_path)?;
-    let extended_flag_set = read_extend_file_to_map_using_path(cli.extended_flag_file_path)?;
-    for flag in extended_flag_set {
-        finalized_flags_map.insert_if_new(EXTENDED_FLAGS_35_APILEVEL, flag);
-    }
+    let finalized_flags_map = read_files_to_map_using_path(cli.flag_file_path)?;
 
     let json_str = serde_json::to_string(&finalized_flags_map)?;
     println!("{}", json_str);
diff --git a/tools/aconfig/exported_flag_check/Android.bp b/tools/aconfig/exported_flag_check/Android.bp
index 184149adac..48facb9e07 100644
--- a/tools/aconfig/exported_flag_check/Android.bp
+++ b/tools/aconfig/exported_flag_check/Android.bp
@@ -12,17 +12,18 @@ rust_defaults {
         "libaconfig_protos",
         "libanyhow",
         "libclap",
+        "libprotobuf",
         "libregex",
     ],
 }
 
 rust_binary_host {
     name: "exported-flag-check",
-    defaults: ["record-finalized-flags-defaults"],
+    defaults: ["exported-flag-check-defaults"],
 }
 
 rust_test_host {
     name: "exported-flag-check-test",
-    defaults: ["record-finalized-flags-defaults"],
+    defaults: ["exported-flag-check-defaults"],
     test_suites: ["general-tests"],
 }
diff --git a/tools/aconfig/exported_flag_check/Cargo.toml b/tools/aconfig/exported_flag_check/Cargo.toml
index 6bc07c5410..f664ec4420 100644
--- a/tools/aconfig/exported_flag_check/Cargo.toml
+++ b/tools/aconfig/exported_flag_check/Cargo.toml
@@ -11,4 +11,5 @@ cargo = []
 aconfig_protos = { path = "../aconfig_protos" }
 anyhow = "1.0.69"
 clap = { version = "4.1.8", features = ["derive"] }
+protobuf = "3.2.0"
 regex = "1.11.1"
diff --git a/tools/aconfig/exported_flag_check/allow_flag_list.txt b/tools/aconfig/exported_flag_check/non_api_flags_list.txt
similarity index 93%
rename from tools/aconfig/exported_flag_check/allow_flag_list.txt
rename to tools/aconfig/exported_flag_check/non_api_flags_list.txt
index 9c314c27d5..64de604d9c 100644
--- a/tools/aconfig/exported_flag_check/allow_flag_list.txt
+++ b/tools/aconfig/exported_flag_check/non_api_flags_list.txt
@@ -10,11 +10,13 @@ android.app.admin.flags.set_keyguard_disabled_features_coexistence
 android.app.admin.flags.set_permission_grant_state_coexistence
 android.app.app_restrictions_api
 android.app.enforce_pic_testmode_protocol
-android.app.job.backup_jobs_exemption
-android.app.pic_uses_shared_memory
 android.app.pinner_service_client_api
 android.app.supervision.flags.deprecate_dpm_supervision_apis
+android.app.supervision.flags.enable_app_approval
+android.app.supervision.flags.enable_supervision_pin_recovery_screen
+android.app.supervision.flags.enable_supervision_settings_screen
 android.app.supervision.flags.enable_sync_with_dpm
+android.app.supervision.flags.enable_web_content_filters_screen
 android.app.supervision.flags.supervision_api
 android.app.supervision.flags.supervision_api_on_wear
 android.app.ui_rich_ongoing
@@ -42,6 +44,7 @@ android.car.feature.car_property_supported_value
 android.car.feature.car_property_value_property_status
 android.car.feature.cluster_health_monitoring
 android.car.feature.display_compatibility
+android.car.feature.display_compatibility_caption_bar
 android.car.feature.handle_property_events_in_binder_thread
 android.car.feature.persist_ap_settings
 android.car.feature.projection_query_bt_profile_inhibit
@@ -55,17 +58,24 @@ android.companion.new_association_builder
 android.companion.ongoing_perm_sync
 android.companion.virtualdevice.flags.camera_multiple_input_streams
 android.companion.virtualdevice.flags.notifications_for_device_streaming
+android.content.pm.always_load_past_certs_v4
 android.content.pm.get_package_storage_stats
+android.content.res.always_false
 android.content.res.layout_readwrite_flags
 android.content.res.resources_minor_version_support
 android.content.res.rro_control_for_android_no_overlayable
 android.content.res.self_targeting_android_resource_frro
 android.content.res.system_context_handle_app_info_changed
+android.content.res.use_new_aconfig_storage
+android.credentials.flags.propagate_user_context_for_intent_creation
 android.credentials.flags.settings_activity_enabled
+android.database.sqlite.concurrent_open_helper
 android.hardware.biometrics.screen_off_unlock_udfps
+android.hardware.devicestate.feature.flags.device_state_configuration_flag
 android.hardware.devicestate.feature.flags.device_state_property_migration
 android.hardware.devicestate.feature.flags.device_state_rdm_v2
 android.hardware.devicestate.feature.flags.device_state_requester_cancel_state
+android.hardware.serial.flags.enable_serial_api
 android.hardware.usb.flags.enable_interface_name_device_filter
 android.hardware.usb.flags.enable_is_mode_change_supported_api
 android.media.audio.focus_exclusive_with_recording
@@ -73,23 +83,30 @@ android.media.audio.focus_freeze_test_api
 android.media.audio.foreground_audio_control
 android.media.audio.hardening_permission_api
 android.media.audio.hardening_permission_spa
+android.media.audio.ringtone_user_uri_check
 android.media.audio.ro_foreground_audio_control
 android.media.audiopolicy.audio_mix_test_api
 android.media.codec.aidl_hal_input_surface
+android.media.soundtrigger.detection_service_paused_resumed_api
 android.media.swcodec.flags.apv_software_codec
 android.media.swcodec.flags.mpeg2_keep_threads_active
 android.media.tv.flags.enable_le_audio_broadcast_ui
 android.media.tv.flags.enable_le_audio_unicast_ui
 android.media.tv.flags.hdmi_control_collect_physical_address
 android.media.tv.flags.hdmi_control_enhanced_behavior
+android.media.tv.flags.tif_extension_standardization
 android.media.tv.flags.tif_unbind_inactive_tis
 android.multiuser.enable_biometrics_to_unlock_private_space
+// TODO(b/411372618): remove after sdk version ramp up for 25Q4
+android.net.platform.flags.connectivity_service_destroy_socket
 android.net.platform.flags.mdns_improvement_for_25q2
 android.nfc.nfc_persist_log
 android.nfc.nfc_watchdog
 android.os.adpf_graphics_pipeline
+android.os.allow_thermal_hal_skin_forecast
 android.os.android_os_build_vanilla_ice_cream
 android.os.battery_saver_supported_check_api
+android.os.force_concurrent_message_queue
 android.os.network_time_uses_shared_memory
 android.os.profiling.persist_queue
 android.os.profiling.redaction_enabled
@@ -97,46 +114,75 @@ android.permission.flags.allow_host_permission_dialogs_on_virtual_devices
 android.permission.flags.device_aware_permissions_enabled
 android.permission.flags.device_policy_management_role_split_create_managed_profile_enabled
 android.permission.flags.enable_aiai_proxied_text_classifiers
+android.permission.flags.enable_all_sqlite_appops_accesses
 android.permission.flags.enable_otp_in_text_classifiers
 android.permission.flags.enable_sqlite_appops_accesses
+android.permission.flags.grant_read_blocked_numbers_to_system_ui_intelligence
 android.permission.flags.location_bypass_privacy_dashboard_enabled
 android.permission.flags.note_op_batching_enabled
 android.permission.flags.permission_request_short_circuit_enabled
 android.permission.flags.rate_limit_batched_note_op_async_callbacks_enabled
+android.permission.flags.record_all_runtime_appops_sqlite
 android.permission.flags.sensitive_notification_app_protection
 android.permission.flags.supervision_role_permission_update_enabled
 android.permission.flags.unknown_call_package_install_blocking_enabled
+android.permission.flags.unknown_call_setting_blocked_logging_enabled
 android.permission.flags.updatable_text_classifier_for_otp_detection_enabled
 android.permission.flags.use_profile_labels_for_default_app_section_titles
 android.permission.flags.wallet_role_cross_user_enabled
 android.provider.allow_config_maximum_call_log_entries_per_sim
-android.provider.backup_tasks_settings_screen
 android.provider.flags.new_storage_writer_system_api
+android.server.wear_gesture_api
 android.service.autofill.fill_dialog_improvements_impl
 android.service.chooser.fix_resolver_memory_leak
 android.service.notification.redact_sensitive_notifications_big_text_style
 android.service.notification.redact_sensitive_notifications_from_untrusted_listeners
+android.view.accessibility.a11y_is_visited_api
 android.view.accessibility.motion_event_observing
+android.view.accessibility.request_rectangle_with_source
+android.view.contentcapture.flags.flush_after_each_frame
 android.view.flags.expected_presentation_time_api
 android.view.flags.toolkit_frame_rate_touch_boost_25q1
 android.view.inputmethod.concurrent_input_methods
 android.view.inputmethod.ime_switcher_revamp
-android.view.inputmethod.imm_userhandle_hostsidetests
 android.webkit.mainline_apis
 android.widget.flags.use_wear_material3_ui
 com.android.aconfig.test.disabled_rw_exported
 com.android.aconfig.test.enabled_fixed_ro_exported
 com.android.aconfig.test.enabled_ro_exported
 com.android.aconfig.test.exported.exported_flag
+com.android.aconfig.test.exported.mainline_beta.exported_beta_disabled_rw
+com.android.aconfig.test.exported.mainline_beta.exported_beta_enabled_rw
 com.android.aconfig.test.forcereadonly.fro_exported
+com.android.adservices.flags.ad_id_cache_enabled
+com.android.adservices.flags.adservices_enablement_check_enabled
+com.android.adservices.flags.adservices_outcomereceiver_r_api_enabled
+com.android.adservices.flags.enable_adservices_api_enabled
+com.android.adservices.flags.sdksandbox_invalidate_effective_target_sdk_version_cache
+com.android.adservices.flags.sdksandbox_use_effective_target_sdk_version_for_restrictions
 com.android.adservices.ondevicepersonalization.flags.on_device_personalization_apis_enabled
 com.android.appsearch.flags.app_open_event_indexer_enabled
 com.android.appsearch.flags.apps_indexer_enabled
+com.android.appsearch.flags.enable_all_package_indexing_on_indexer_update
 com.android.appsearch.flags.enable_app_functions_schema_parser
+com.android.appsearch.flags.enable_app_open_events_indexer_check_prior_attempt
+com.android.appsearch.flags.enable_app_search_manage_blob_files
+com.android.appsearch.flags.enable_apps_indexer_check_prior_attempt
 com.android.appsearch.flags.enable_apps_indexer_incremental_put
+com.android.appsearch.flags.enable_batch_put
+com.android.appsearch.flags.enable_calculate_time_since_last_attempted_optimize
+com.android.appsearch.flags.enable_check_contacts_indexer_delta_timestamps
+com.android.appsearch.flags.enable_check_contacts_indexer_update_job_params
 com.android.appsearch.flags.enable_contacts_index_first_middle_and_last_names
 com.android.appsearch.flags.enable_document_limiter_replace_tracking
 com.android.appsearch.flags.enable_enterprise_empty_batch_result_fix
+com.android.appsearch.flags.enable_four_hour_min_time_optimize_threshold
+com.android.appsearch.flags.enable_isolated_storage
+com.android.appsearch.flags.enable_marker_file_for_optimize
+com.android.appsearch.flags.enable_qualified_id_join_index_v3
+com.android.appsearch.flags.enable_recovery_proof_persistence
+com.android.appsearch.flags.enable_release_backup_schema_file_if_overlay_present
+com.android.appsearch.flags.enable_soft_index_restoration
 com.android.bluetooth.flags.allow_switching_hid_and_hogp
 com.android.bluetooth.flags.bt_offload_socket_api
 com.android.bluetooth.flags.channel_sounding
@@ -148,16 +194,20 @@ com.android.bluetooth.flags.leaudio_multiple_vocs_instances_api
 com.android.bluetooth.flags.metadata_api_inactive_audio_device_upon_connection
 com.android.bluetooth.flags.settings_can_control_hap_preset
 com.android.bluetooth.flags.unix_file_socket_creation_failure
+com.android.clockwork.flags.support_paired_device_none
+com.android.gms.flags.enable_deleted_gms
+com.android.gms.flags.enable_new_gms
+com.android.gms.flags.enable_optional_gms
 com.android.graphics.flags.icon_load_drawable_return_null_when_uri_decode_fails
 com.android.graphics.hwui.flags.animated_image_drawable_filter_bitmap
+com.android.graphics.surfaceflinger.flags.disable_synthetic_vsync_for_performance
+com.android.hardware.input.key_event_activity_detection
 com.android.hardware.input.manage_key_gestures
 com.android.healthfitness.flags.activity_intensity_db
 com.android.healthfitness.flags.add_missing_access_logs
 com.android.healthfitness.flags.architecture_improvement
-com.android.healthfitness.flags.cloud_backup_and_restore
+com.android.healthfitness.flags.cloud_backup_and_restore_db
 com.android.healthfitness.flags.cycle_phases
-com.android.healthfitness.flags.d2d_file_deletion_bug_fix
-com.android.healthfitness.flags.dependency_injection
 com.android.healthfitness.flags.development_database
 com.android.healthfitness.flags.ecosystem_metrics
 com.android.healthfitness.flags.ecosystem_metrics_db_changes
@@ -165,47 +215,62 @@ com.android.healthfitness.flags.export_import
 com.android.healthfitness.flags.export_import_fast_follow
 com.android.healthfitness.flags.export_import_nice_to_have
 com.android.healthfitness.flags.expressive_theming_enabled
+com.android.healthfitness.flags.extend_export_import_telemetry
 com.android.healthfitness.flags.health_connect_mappings
 com.android.healthfitness.flags.immediate_export
 com.android.healthfitness.flags.logcat_censor_iae
 com.android.healthfitness.flags.new_information_architecture
 com.android.healthfitness.flags.onboarding
-com.android.healthfitness.flags.permission_metrics
-com.android.healthfitness.flags.permission_tracker_fix_mapping_init
-com.android.healthfitness.flags.personal_health_record_database
-com.android.healthfitness.flags.personal_health_record_disable_d2d
 com.android.healthfitness.flags.personal_health_record_disable_export_import
 com.android.healthfitness.flags.personal_health_record_enable_d2d_and_export_import
+com.android.healthfitness.flags.personal_health_record_enable_export_import
 com.android.healthfitness.flags.personal_health_record_entries_screen
 com.android.healthfitness.flags.personal_health_record_lock_screen_banner
 com.android.healthfitness.flags.personal_health_record_telemetry
 com.android.healthfitness.flags.personal_health_record_telemetry_private_ww
 com.android.healthfitness.flags.personal_health_record_ui_telemetry
+com.android.healthfitness.flags.phr_change_logs
+com.android.healthfitness.flags.phr_change_logs_db
 com.android.healthfitness.flags.phr_fhir_basic_complex_type_validation
 com.android.healthfitness.flags.phr_fhir_complex_type_validation
+com.android.healthfitness.flags.phr_fhir_extension_validation
 com.android.healthfitness.flags.phr_fhir_oneof_validation
 com.android.healthfitness.flags.phr_fhir_primitive_type_validation
-com.android.healthfitness.flags.phr_fhir_structural_validation
+com.android.healthfitness.flags.phr_fhir_resource_validator_use_weak_reference
+com.android.healthfitness.flags.phr_fhir_validation_disallow_empty_objects_arrays
 com.android.healthfitness.flags.phr_read_medical_resources_fix_query_limit
-com.android.healthfitness.flags.phr_upsert_fix_parcel_size_calculation
 com.android.healthfitness.flags.phr_upsert_fix_use_shared_memory
+com.android.healthfitness.flags.refactor_aggregations
+com.android.healthfitness.flags.single_user_permission_intent_tracker
+com.android.healthfitness.flags.smoking_db
+com.android.healthfitness.flags.step_tracking_enabled
+com.android.healthfitness.flags.symptoms
+com.android.healthfitness.flags.symptoms_db
 com.android.icu.icu_v_api
+com.android.icu.telephony_lookup_mcc_extension
 com.android.internal.telephony.flags.async_init_carrier_privileges_tracker
 com.android.internal.telephony.flags.cleanup_carrier_app_update_enabled_state_logic
 com.android.internal.telephony.flags.oem_enabled_satellite_phase_2
+com.android.internal.telephony.flags.pass_copied_call_state_list
 com.android.internal.telephony.flags.remap_disconnect_cause_sip_request_cancelled
+com.android.internal.telephony.flags.robust_number_verification
+com.android.internal.telephony.flags.satellite_exit_p2p_session_outside_geofence
+com.android.internal.telephony.flags.starlink_data_bugfix
 com.android.libcore.hpke_v_apis
 com.android.libcore.read_only_dynamic_code_load
 com.android.libcore.v_apis
 com.android.media.audio.hardening_impl
+com.android.media.audio.hardening_partial
 com.android.media.audio.hardening_strict
 com.android.media.extractor.flags.extractor_mp4_enable_apv
 com.android.media.extractor.flags.extractor_sniff_midi_optimizations
 com.android.media.flags.enable_cross_user_routing_in_media_router2
 com.android.media.flags.enable_notifying_activity_manager_with_media_session_status_change
+com.android.media.flags.enable_use_of_singleton_audio_manager_route_controller
 com.android.media.metrics.flags.mediametrics_to_module
 com.android.media.projection.flags.media_projection_connected_display
 com.android.media.projection.flags.media_projection_connected_display_no_virtual_device
+com.android.media.projection.flags.show_stop_dialog_post_call_end
 com.android.net.ct.flags.certificate_transparency_job
 com.android.net.ct.flags.certificate_transparency_service
 com.android.net.flags.restrict_local_network
@@ -213,14 +278,18 @@ com.android.net.flags.tethering_active_sessions_metrics
 com.android.net.thread.flags.thread_mobile_enabled
 com.android.nfc.module.flags.nfc_hce_latency_events
 com.android.org.conscrypt.flags.certificate_transparency_checkservertrusted_api
+com.android.org.conscrypt.net.flags.certificate_transparency_default_enabled
+com.android.org.conscrypt.net.flags.network_security_config
 com.android.permission.flags.add_banners_to_privacy_sensitive_apps_for_aaos
 com.android.permission.flags.app_permission_fragment_uses_preferences
 com.android.permission.flags.archiving_read_only
+com.android.permission.flags.cross_user_role_ux_bugfix_enabled
 com.android.permission.flags.decluttered_permission_manager_enabled
+com.android.permission.flags.default_apps_recommendation_enabled
 com.android.permission.flags.enable_coarse_fine_location_prompt_for_aaos
 com.android.permission.flags.enhanced_confirmation_backport_enabled
 com.android.permission.flags.expressive_design_enabled
-com.android.permission.flags.livedata_refactor_permission_timeline_enabled
+com.android.permission.flags.fix_safety_center_touch_target
 com.android.permission.flags.odad_notifications_supported
 com.android.permission.flags.permission_timeline_attribution_label_fix
 com.android.permission.flags.private_profile_supported
@@ -230,130 +299,43 @@ com.android.permission.flags.wear_compose_material3
 com.android.permission.flags.wear_privacy_dashboard_enabled_read_only
 com.android.providers.contactkeys.flags.contactkeys_strip_fix
 com.android.providers.media.flags.enable_backup_and_restore
+com.android.providers.media.flags.enable_exclusion_list_for_default_folders
+com.android.providers.media.flags.enable_local_media_provider_capabilities
 com.android.providers.media.flags.enable_malicious_app_detector
 com.android.providers.media.flags.enable_mark_media_as_favorite_api
+com.android.providers.media.flags.enable_mime_type_fix_for_android_15
 com.android.providers.media.flags.enable_modern_photopicker
+com.android.providers.media.flags.enable_photopicker_datescrubber
 com.android.providers.media.flags.enable_photopicker_search
 com.android.providers.media.flags.enable_photopicker_transcoding
 com.android.providers.media.flags.enable_stable_uris_for_external_primary_volume
 com.android.providers.media.flags.enable_stable_uris_for_public_volume
 com.android.providers.media.flags.enable_unicode_check
+com.android.providers.media.flags.exclude_unreliable_volumes
 com.android.providers.media.flags.index_media_latitude_longitude
+com.android.providers.media.flags.revoke_access_owned_photos
 com.android.providers.media.flags.version_lockdown
 com.android.ranging.flags.ranging_stack_updates_25q4
+com.android.sdksandbox.flags.sandbox_activity_sdk_based_context
+com.android.sdksandbox.flags.selinux_input_selector
+com.android.sdksandbox.flags.selinux_sdk_sandbox_audit
 com.android.server.backup.enable_read_all_external_storage_files
 com.android.server.telecom.flags.allow_system_apps_resolve_voip_calls
 com.android.server.telecom.flags.telecom_app_label_proxy_hsum_aware
 com.android.server.telecom.flags.telecom_main_user_in_block_check
 com.android.server.telecom.flags.telecom_main_user_in_get_respond_message_app
-com.android.server.updates.certificate_transparency_installer
+com.android.settings.flags.enable_remove_association_bt_unpair
+com.android.settingslib.widget.theme.flags.is_expressive_design_enabled
 com.android.system.virtualmachine.flags.terminal_gui_support
+com.android.system.virtualmachine.flags.terminal_storage_balloon
 com.android.tradeinmode.flags.enable_trade_in_mode
-com.android.update_engine.minor_changes_2025q4
-com.android.uwb.flags.uwb_fira_3_0_25q4
+com.android.tradeinmode.flags.trade_in_mode_2025q4
 com.android.wifi.flags.network_provider_battery_charging_status
 com.android.wifi.flags.p2p_dialog2
 com.android.wifi.flags.shared_connectivity_broadcast_receiver_test_api
 com.android.wifi.flags.wep_disabled_in_apm
-com.android.window.flags.untrusted_embedding_state_sharing
-vendor.vibrator.hal.flags.enable_pwle_v2
-vendor.vibrator.hal.flags.remove_capo
-
-android.app.supervision.flags.enable_app_approval
-android.app.supervision.flags.enable_supervision_app_service
-android.app.supervision.flags.enable_supervision_pin_recovery_screen
-android.app.supervision.flags.enable_supervision_settings_screen
-android.app.supervision.flags.enable_web_content_filters_screen
-android.car.feature.display_compatibility_caption_bar
-android.companion.virtualdevice.flags.viewconfiguration_apis
-android.content.pm.always_load_past_certs_v4
-android.content.res.always_false
-android.content.res.use_new_aconfig_storage
-android.credentials.flags.propagate_user_context_for_intent_creation
-android.database.sqlite.concurrent_open_helper
-android.hardware.devicestate.feature.flags.device_state_configuration_flag
-android.media.audio.ringtone_user_uri_check
-android.media.soundtrigger.detection_service_paused_resumed_api
-android.media.tv.flags.tif_extension_standardization
-android.os.allow_thermal_hal_skin_forecast
-android.os.force_concurrent_message_queue
-android.permission.flags.enable_all_sqlite_appops_accesses
-android.permission.flags.grant_read_blocked_numbers_to_system_ui_intelligence
-android.permission.flags.record_all_runtime_appops_sqlite
-android.permission.flags.unknown_call_setting_blocked_logging_enabled
-android.server.wear_gesture_api
-android.view.accessibility.a11y_is_visited_api
-android.view.accessibility.request_rectangle_with_source
-android.view.contentcapture.flags.flush_after_each_frame
-com.android.adservices.flags.ad_id_cache_enabled
-com.android.adservices.flags.adservices_enablement_check_enabled
-com.android.adservices.flags.adservices_outcomereceiver_r_api_enabled
-com.android.adservices.flags.enable_adservices_api_enabled
-com.android.adservices.flags.sdksandbox_invalidate_effective_target_sdk_version_cache
-com.android.adservices.flags.sdksandbox_use_effective_target_sdk_version_for_restrictions
-com.android.appsearch.flags.enable_all_package_indexing_on_indexer_update
-com.android.appsearch.flags.enable_app_functions
-com.android.appsearch.flags.enable_app_open_events_indexer_check_prior_attempt
-com.android.appsearch.flags.enable_app_search_manage_blob_files
-com.android.appsearch.flags.enable_apps_indexer_check_prior_attempt
-com.android.appsearch.flags.enable_batch_put
-com.android.appsearch.flags.enable_calculate_time_since_last_attempted_optimize
-com.android.appsearch.flags.enable_check_contacts_indexer_delta_timestamps
-com.android.appsearch.flags.enable_check_contacts_indexer_update_job_params
-com.android.appsearch.flags.enable_four_hour_min_time_optimize_threshold
-com.android.appsearch.flags.enable_isolated_storage
-com.android.appsearch.flags.enable_marker_file_for_optimize
-com.android.appsearch.flags.enable_qualified_id_join_index_v3
-com.android.appsearch.flags.enable_recovery_proof_persistence
-com.android.appsearch.flags.enable_release_backup_schema_file_if_overlay_present
-com.android.appsearch.flags.enable_soft_index_restoration
-com.android.clockwork.flags.support_paired_device_none
-com.android.gms.flags.enable_deleted_gms
-com.android.gms.flags.enable_new_gms
-com.android.gms.flags.enable_optional_gms
-com.android.hardware.input.key_event_activity_detection
-com.android.healthfitness.flags.cloud_backup_and_restore_db
-com.android.healthfitness.flags.exercise_segment_weight
-com.android.healthfitness.flags.exercise_segment_weight_db
-com.android.healthfitness.flags.extend_export_import_telemetry
-com.android.healthfitness.flags.launch_onboarding_activity
-com.android.healthfitness.flags.personal_health_record_enable_export_import
-com.android.healthfitness.flags.phr_change_logs
-com.android.healthfitness.flags.phr_change_logs_db
-com.android.healthfitness.flags.phr_fhir_extension_validation
-com.android.healthfitness.flags.phr_fhir_resource_validator_use_weak_reference
-com.android.healthfitness.flags.phr_fhir_validation_disallow_empty_objects_arrays
-com.android.healthfitness.flags.refactor_aggregations
-com.android.healthfitness.flags.single_user_permission_intent_tracker
-com.android.healthfitness.flags.smoking
-com.android.healthfitness.flags.smoking_db
-com.android.healthfitness.flags.step_tracking_enabled
-com.android.healthfitness.flags.symptoms
-com.android.healthfitness.flags.symptoms_db
-com.android.icu.telephony_lookup_mcc_extension
-com.android.internal.telephony.flags.pass_copied_call_state_list
-com.android.internal.telephony.flags.robust_number_verification
-com.android.internal.telephony.flags.satellite_exit_p2p_session_outside_geofence
-com.android.internal.telephony.flags.starlink_data_bugfix
-com.android.media.audio.hardening_partial
-com.android.media.flags.enable_suggested_device_api
-com.android.media.flags.enable_use_of_singleton_audio_manager_route_controller
-com.android.media.projection.flags.app_content_sharing
-com.android.media.projection.flags.show_stop_dialog_post_call_end
-com.android.permission.flags.cross_user_role_ux_bugfix_enabled
-com.android.permission.flags.default_apps_recommendation_enabled
-com.android.permission.flags.fix_safety_center_touch_target
-com.android.providers.media.flags.enable_exclusion_list_for_default_folders
-com.android.providers.media.flags.enable_mime_type_fix_for_android_15
-com.android.providers.media.flags.exclude_unreliable_volumes
-com.android.providers.media.flags.revoke_access_owned_photos
-com.android.sdksandbox.flags.sandbox_activity_sdk_based_context
-com.android.sdksandbox.flags.selinux_input_selector
-com.android.sdksandbox.flags.selinux_sdk_sandbox_audit
-com.android.settings.flags.enable_remove_association_bt_unpair
-com.android.settingslib.widget.theme.flags.is_expressive_design_enabled
 com.android.window.flags.fix_hide_overlay_api
-com.android.window.flags.update_host_input_transfer_token
+com.android.window.flags.untrusted_embedding_state_sharing
 com.fuchsia.bluetooth.flags.a2dp_lhdc_api
 com.fuchsia.bluetooth.flags.aics_api
 com.fuchsia.bluetooth.flags.allow_switching_hid_and_hogp
@@ -378,7 +360,6 @@ com.fuchsia.bluetooth.flags.metadata_api_microphone_for_call_enabled
 com.fuchsia.bluetooth.flags.settings_can_control_hap_preset
 com.fuchsia.bluetooth.flags.socket_settings_api
 com.fuchsia.bluetooth.flags.support_bluetooth_quality_report_v6
-com.fuchsia.bluetooth.flags.support_exclusive_manager
 com.fuchsia.bluetooth.flags.support_metadata_device_types_apis
 com.fuchsia.bluetooth.flags.support_remote_device_metadata
 com.fuchsia.bluetooth.flags.unix_file_socket_creation_failure
@@ -391,10 +372,5 @@ vendor.gc2.flags.mse_report
 vendor.google.plat_security.flags.enable_service
 vendor.google.plat_security.flags.enable_trusty_service
 vendor.google.wireless_charger.service.flags.enable_service
-
-android.hardware.biometrics.move_fm_api_to_bm
-android.hardware.serial.flags.enable_serial_api
-com.android.providers.media.flags.enable_local_media_provider_capabilities
-com.android.providers.media.flags.enable_photopicker_datescrubber
-com.android.system.virtualmachine.flags.terminal_storage_balloon
-com.android.tradeinmode.flags.trade_in_mode_2025q4
+vendor.vibrator.hal.flags.enable_pwle_v2
+vendor.vibrator.hal.flags.remove_capo
diff --git a/tools/aconfig/exported_flag_check/allow_package_list.txt b/tools/aconfig/exported_flag_check/non_api_flags_packages.txt
similarity index 100%
rename from tools/aconfig/exported_flag_check/allow_package_list.txt
rename to tools/aconfig/exported_flag_check/non_api_flags_packages.txt
diff --git a/tools/aconfig/exported_flag_check/skip_api_filter_list.txt b/tools/aconfig/exported_flag_check/skip_api_filter_list.txt
new file mode 100644
index 0000000000..36fd56aa6c
--- /dev/null
+++ b/tools/aconfig/exported_flag_check/skip_api_filter_list.txt
@@ -0,0 +1,10 @@
+// This flag is used in SettingsLibSettingsTheme. This flag is
+// exported, but it is not used for any API. It should be removed from
+// API flag libary. However because of the current setup, this flag should
+// still be in the library. This flag should be removed from the code base
+// after release of the new feature
+com.android.graphics.surfaceflinger.flags.disable_synthetic_vsync_for_performance
+com.android.settingslib.widget.theme.flags.is_expressive_design_enabled
+
+// This flag is used to guard wear devices API
+com.google.android.clockwork.pele.flags.koru_feature_cached_views
\ No newline at end of file
diff --git a/tools/aconfig/exported_flag_check/src/main.rs b/tools/aconfig/exported_flag_check/src/main.rs
index 866a700d02..d075233145 100644
--- a/tools/aconfig/exported_flag_check/src/main.rs
+++ b/tools/aconfig/exported_flag_check/src/main.rs
@@ -15,18 +15,19 @@
  */
 
 //! `exported-flag-check` is a tool to ensures that exported flags are used as intended
-use anyhow::{ensure, Result};
-use clap::Parser;
-use std::{collections::HashSet, fs::File, path::PathBuf};
+use anyhow::{anyhow, bail, ensure, Context, Result};
+use clap::{builder::ArgAction, Arg, ArgMatches, Command};
+use std::io::Write;
+use std::{collections::HashSet, fs, fs::File, io::Read, path::PathBuf};
 
 mod utils;
 
 use utils::{
-    check_all_exported_flags, extract_flagged_api_flags, get_exported_flags_from_binary_proto,
-    read_finalized_flags,
+    check_all_exported_flags, extract_flagged_api_flags, filter_api_flags,
+    get_exported_flags_from_binary_proto, read_flag_from_binary, FlagId,
 };
 
-const ABOUT: &str = "CCheck Exported Flags
+const HELP: &str = "Check Exported Flags
 
 This tool ensures that exported flags are used as intended. Exported flags, marked with
 `is_exported: true` in their declaration, are designed to control access to specific API
@@ -34,84 +35,192 @@ features. This tool identifies and reports any exported flags that are not curre
 associated with an API feature, preventing unnecessary flag proliferation and maintaining
 a clear API design.
 
-This tool works as follows:
+Commands:
 
-  - Read API signature files from source tree (*current.txt files) [--api-signature-file]
-  - Read the current aconfig flag values from source tree [--parsed-flags-file]
-  - Read the previous finalized-flags.txt files from prebuilts/sdk [--finalized-flags-file]
-  - Extract the flags slated for API by scanning through the API signature files
-  - Merge the found flags with the recorded flags from previous API finalizations
-  - Error if exported flags are not in the set
-";
+This tool offers two commands:
+
+1. validate-exported-flags :This command verifies that all exported flags within 
+   the current source tree are actively used to guard API features.
+
+Arguments:
+    --parsed-flags-file: Current aconfig flag values from source tree
+    --api-signature-file: API signature files from source tree (*current.txt files)
+    --finalized-flags-file: The previous finalized-flags.txt files from prebuilts/sdk
+
+Example:
+exported-flag-tool validate-exported-flags \
+    --parsed-flags-file out/soong/aconfig/parsed_flags.pb \
+    --api-signature-file frameworks/base/api/current.txt \
+    --api-signature-file external/library/api/current.txt \
+    --finalized-flags-file prebuilts/sdk/34/public/finalized-flags.txt
+
+2. filter-api-flags: This command processes an input list of flags and filters it, based on
+   the non-api lists to produce an output file containing only the exported flags that
+   are used for controlling API features.
+
+Arguments:
+    --cache: The path to the input aconfig flag proto file
+    --out: The output file
 
-#[derive(Parser, Debug)]
-#[clap(about=ABOUT)]
-struct Cli {
-    #[arg(long)]
-    parsed_flags_file: PathBuf,
+Example:
+exported-flag-tool filter-api-flags \
+    --cache build/intermediate/foo_flags.pb \
+    --cache build/intermediate/bar_flags.pb \
+    --out build/intermediate/api_relevant_exported_flags.pb
 
-    #[arg(long)]
-    api_signature_file: Vec<PathBuf>,
+";
+
+fn cli() -> Command {
+    Command::new("exported-flag-check")
+        .subcommand_required(true)
+        .subcommand(
+            Command::new("validate-exported-flags")
+                .arg(Arg::new("parsed-flags-file").long("parsed-flags-file").required(true))
+                .arg(
+                    Arg::new("api-signature-file")
+                        .long("api-signature-file")
+                        .required(true)
+                        .action(ArgAction::Append),
+                )
+                .arg(Arg::new("finalized-flags-file").long("finalized-flags-file").required(true)),
+        )
+        .subcommand(
+            Command::new("filter-api-flags")
+                .arg(Arg::new("cache").long("cache").required(true))
+                .arg(Arg::new("out").long("out").required(true)),
+        )
+        .after_help(HELP.trim())
+}
 
-    #[arg(long)]
-    finalized_flags_file: PathBuf,
+fn open_single_file(matches: &ArgMatches, arg_name: &str) -> Result<Box<dyn Read>> {
+    let Some(path) = matches.get_one::<String>(arg_name) else {
+        bail!("missing argument {}", arg_name);
+    };
+    Ok(Box::new(File::open(path)?))
 }
 
-fn main() -> Result<()> {
-    let args = Cli::parse();
+fn open_multiple_files(matches: &ArgMatches, arg_name: &str) -> Result<Vec<Box<dyn Read>>> {
+    let mut opened_files: Vec<Box<dyn Read>> = Vec::new();
+    for path in matches.get_many::<String>(arg_name).unwrap_or_default() {
+        opened_files.push(Box::new(File::open(path)?));
+    }
+    Ok(opened_files)
+}
 
+fn validate_exported_flags<R: Read>(
+    parsed_flags_file: R,
+    api_signature_files: Vec<R>,
+    finalized_flags_file: R,
+    non_api_flags: R,
+    allow_flag_package: R,
+) -> Result<Vec<FlagId>> {
     let mut flags_used_with_flaggedapi_annotation = HashSet::new();
-    for path in &args.api_signature_file {
-        let file = File::open(path)?;
+    for file in api_signature_files {
         let flags = extract_flagged_api_flags(file)?;
         flags_used_with_flaggedapi_annotation.extend(flags);
     }
-
-    let file = File::open(args.parsed_flags_file)?;
-    let all_flags = get_exported_flags_from_binary_proto(file)?;
-
-    let file = File::open(args.finalized_flags_file)?;
-    let already_finalized_flags = read_finalized_flags(file)?;
+    let all_flags = get_exported_flags_from_binary_proto(parsed_flags_file)?;
+    let already_finalized_flags = read_flag_from_binary(finalized_flags_file)?;
+    let allow_flag_set = read_flag_from_binary(non_api_flags)?;
+    let allow_package_set = read_flag_from_binary(allow_flag_package)?;
 
     let exported_flags = check_all_exported_flags(
         &flags_used_with_flaggedapi_annotation,
         &all_flags,
         &already_finalized_flags,
+        &allow_flag_set,
+        &allow_package_set,
     )?;
 
     println!("{}", exported_flags.join("\n"));
 
-    ensure!(
-        exported_flags.is_empty(),
-        "Flags {} are exported but not used to guard any API. \
-    Exported flag should be used to guard API",
-        exported_flags.join(",")
-    );
+    Ok(exported_flags)
+}
+
+fn main() -> Result<()> {
+    let matches = cli().get_matches();
+    match matches.subcommand() {
+        Some(("validate-exported-flags", sub_matches)) => {
+            let parsed_flags_file = open_single_file(sub_matches, "parsed-flags-file")?;
+            let api_signature_files = open_multiple_files(sub_matches, "api-signature-file")?;
+            let finalized_flags_file = open_single_file(sub_matches, "finalized-flags-file")?;
+            let non_api_flags = include_str!("../non_api_flags_list.txt");
+            let non_api_flags_packages = include_str!("../non_api_flags_packages.txt");
+
+            let exported_flags = validate_exported_flags(
+                parsed_flags_file,
+                api_signature_files,
+                finalized_flags_file,
+                Box::new(non_api_flags.as_bytes()),
+                Box::new(non_api_flags_packages.as_bytes()),
+            )?;
+
+            ensure!(
+                exported_flags.is_empty(),
+                "Flags {} are exported but not used to guard any API. \
+            Exported flag should be used to guard API",
+                exported_flags.join(",")
+            );
+        }
+        Some(("filter-api-flags", sub_matches)) => {
+            let cache = open_single_file(sub_matches, "cache")?;
+
+            let Some(out_file_arg) = sub_matches.get_one::<String>("out") else {
+                bail!("argument out is missing");
+            };
+            let out_file = PathBuf::from(out_file_arg);
+            let mut non_api_flags_set =
+                read_flag_from_binary(&include_bytes!("../non_api_flags_list.txt")[..])?;
+            let skip_flags_set =
+                read_flag_from_binary(&include_bytes!("../skip_api_filter_list.txt")[..])?;
+            skip_flags_set.iter().for_each(|flag| {
+                non_api_flags_set.remove(flag);
+            });
+            let filtered_cache = filter_api_flags(cache, &non_api_flags_set)?;
+            let parent = out_file
+                .parent()
+                .ok_or(anyhow!("unable to locate parent of output file {}", out_file.display()))?;
+            fs::create_dir_all(parent)
+                .with_context(|| format!("failed to create directory {}", parent.display()))?;
+            let mut file = fs::File::create(&out_file)
+                .with_context(|| format!("failed to open {}", out_file.display()))?;
+            file.write_all(&filtered_cache)
+                .with_context(|| format!("failed to write to {}", out_file.display()))?;
+        }
+        _ => unreachable!(),
+    }
+
     Ok(())
 }
 
 #[cfg(test)]
 mod tests {
     use super::*;
+    use aconfig_protos::parsed_flags;
+    use protobuf::Message;
 
     #[test]
     fn test() {
-        let input = include_bytes!("../tests/api-signature-file.txt");
-        let flags_used_with_flaggedapi_annotation = extract_flagged_api_flags(&input[..]).unwrap();
-
-        let input = include_bytes!("../tests/flags.protobuf");
-        let all_flags_to_be_finalized = get_exported_flags_from_binary_proto(&input[..]).unwrap();
-
-        let input = include_bytes!("../tests/finalized-flags.txt");
-        let already_finalized_flags = read_finalized_flags(&input[..]).unwrap();
-
-        let exported_flags = check_all_exported_flags(
-            &flags_used_with_flaggedapi_annotation,
-            &all_flags_to_be_finalized,
-            &already_finalized_flags,
+        let input = std::str::from_utf8(include_bytes!("../tests/flags.textproto")).unwrap();
+        let parsed_flags = parsed_flags::try_from_text_proto(input).unwrap();
+        let mut all_flags_to_be_finalized = Vec::new();
+        parsed_flags.write_to_vec(&mut all_flags_to_be_finalized).unwrap();
+        let flags_used_with_flaggedapi_annotation =
+            vec![&include_bytes!("../tests/api-signature-file.txt")[..]];
+        let already_finalized_flags = include_bytes!("../tests/finalized-flags.txt");
+        let non_api_flags = "record_finalized_flags.test.boo".as_bytes();
+        let allow_flag_package = "".as_bytes();
+
+        let exported_flags = validate_exported_flags(
+            &all_flags_to_be_finalized[..],
+            flags_used_with_flaggedapi_annotation,
+            &already_finalized_flags[..],
+            non_api_flags,
+            allow_flag_package,
         )
         .unwrap();
 
         assert_eq!(1, exported_flags.len());
+        assert_eq!("record_finalized_flags.test.not_enabled", exported_flags[0]);
     }
 }
diff --git a/tools/aconfig/exported_flag_check/src/utils.rs b/tools/aconfig/exported_flag_check/src/utils.rs
index 3686fec739..b514f3da82 100644
--- a/tools/aconfig/exported_flag_check/src/utils.rs
+++ b/tools/aconfig/exported_flag_check/src/utils.rs
@@ -14,8 +14,9 @@
  * limitations under the License.
  */
 
-use aconfig_protos::ParsedFlagExt;
-use anyhow::{anyhow, Context, Result};
+use aconfig_protos::{ParsedFlagExt, ProtoParsedFlags};
+use anyhow::{anyhow, Result};
+use protobuf::Message;
 use regex::Regex;
 use std::{
     collections::HashSet,
@@ -36,11 +37,14 @@ pub(crate) fn extract_flagged_api_flags<R: Read>(mut reader: R) -> Result<HashSe
 
 /// Read a list of flag names. The input is expected to be plain text, with each line containing
 /// the name of a single flag.
-pub(crate) fn read_finalized_flags<R: Read>(reader: R) -> Result<HashSet<FlagId>> {
-    BufReader::new(reader)
+pub(crate) fn read_flag_from_binary<R: Read>(reader: R) -> Result<HashSet<FlagId>> {
+    Ok(BufReader::new(reader)
         .lines()
-        .map(|line_result| line_result.context("Failed to read line from finalized flags file"))
-        .collect()
+        .map_while(Result::ok) // Ignore lines that fail to read
+        .map(|line| line.trim().to_string())
+        .filter(|line| !line.is_empty())
+        .filter(|line| !line.starts_with("/"))
+        .collect())
 }
 
 /// Parse a ProtoParsedFlags binary protobuf blob and return the fully qualified names of flags
@@ -60,28 +64,15 @@ pub(crate) fn get_exported_flags_from_binary_proto<R: Read>(
     Ok(HashSet::from_iter(iter))
 }
 
-fn get_allow_flag_list() -> Result<HashSet<FlagId>> {
-    let allow_list: HashSet<FlagId> =
-        include_str!("../allow_flag_list.txt").lines().map(|x| x.into()).collect();
-    Ok(allow_list)
-}
-
-fn get_allow_package_list() -> Result<HashSet<FlagId>> {
-    let allow_list: HashSet<FlagId> =
-        include_str!("../allow_package_list.txt").lines().map(|x| x.into()).collect();
-    Ok(allow_list)
-}
-
 /// Filter out the flags have is_exported as true but not used with @FlaggedApi annotations
 /// in the source tree, or in the previously finalized flags set.
 pub(crate) fn check_all_exported_flags(
     flags_used_with_flaggedapi_annotation: &HashSet<FlagId>,
     all_flags: &HashSet<FlagId>,
     already_finalized_flags: &HashSet<FlagId>,
+    allow_flag_set: &HashSet<FlagId>,
+    allow_package_set: &HashSet<FlagId>,
 ) -> Result<Vec<FlagId>> {
-    let allow_flag_list = get_allow_flag_list()?;
-    let allow_package_list = get_allow_package_list()?;
-
     let new_flags: Vec<FlagId> = all_flags
         .difference(flags_used_with_flaggedapi_annotation)
         .cloned()
@@ -89,11 +80,11 @@ pub(crate) fn check_all_exported_flags(
         .difference(already_finalized_flags)
         .cloned()
         .collect::<HashSet<_>>()
-        .difference(&allow_flag_list)
+        .difference(allow_flag_set)
         .filter(|flag| {
             if let Some(last_dot_index) = flag.rfind('.') {
                 let package_name = &flag[..last_dot_index];
-                !allow_package_list.contains(package_name)
+                !allow_package_set.contains(package_name)
             } else {
                 true
             }
@@ -104,14 +95,37 @@ pub(crate) fn check_all_exported_flags(
     Ok(new_flags)
 }
 
+pub(crate) fn filter_api_flags<R: Read>(
+    mut cache: R,
+    non_api_flag_set: &HashSet<FlagId>,
+) -> Result<Vec<u8>> {
+    let mut buffer = Vec::new();
+    cache.read_to_end(&mut buffer)?;
+    let parsed_flags = aconfig_protos::parsed_flags::try_from_binary_proto(&buffer)
+        .map_err(|_| anyhow!("failed to parse binary proto"))?;
+    let mut filtered_parsed_flags = ProtoParsedFlags::new();
+    parsed_flags
+        .parsed_flag
+        .into_iter()
+        .filter(|flag| {
+            flag.is_exported() && !non_api_flag_set.contains(&flag.fully_qualified_name())
+        })
+        .for_each(|flag| filtered_parsed_flags.parsed_flag.push(flag.clone()));
+    aconfig_protos::parsed_flags::sort_parsed_flags(&mut filtered_parsed_flags);
+    let mut output = Vec::new();
+    filtered_parsed_flags.write_to_vec(&mut output)?;
+    Ok(output)
+}
+
 #[cfg(test)]
 mod tests {
     use super::*;
+    use aconfig_protos::parsed_flags;
 
     #[test]
     fn test_extract_flagged_api_flags() {
-        let api_signature_file = include_bytes!("../tests/api-signature-file.txt");
-        let flags = extract_flagged_api_flags(&api_signature_file[..]).unwrap();
+        let api_signature_files = include_bytes!("../tests/api-signature-file.txt");
+        let flags = extract_flagged_api_flags(&api_signature_files[..]).unwrap();
         assert_eq!(
             flags,
             HashSet::from_iter(vec![
@@ -124,7 +138,7 @@ mod tests {
     #[test]
     fn test_read_finalized_flags() {
         let input = include_bytes!("../tests/finalized-flags.txt");
-        let flags = read_finalized_flags(&input[..]).unwrap();
+        let flags = read_flag_from_binary(&input[..]).unwrap();
         assert_eq!(
             flags,
             HashSet::from_iter(vec![
@@ -135,14 +149,91 @@ mod tests {
     }
 
     #[test]
-    fn test_disabled_or_read_write_flags_are_ignored() {
-        let bytes = include_bytes!("../tests/flags.protobuf");
+    fn test_get_exported_flags_from_binary_proto() {
+        let input = std::str::from_utf8(include_bytes!("../tests/flags.textproto")).unwrap();
+        let parsed_flags = parsed_flags::try_from_text_proto(input).unwrap();
+        let mut bytes = Vec::new();
+        parsed_flags.write_to_vec(&mut bytes).unwrap();
         let flags = get_exported_flags_from_binary_proto(&bytes[..]).unwrap();
         assert_eq!(
             flags,
             HashSet::from_iter(vec![
                 "record_finalized_flags.test.foo".to_string(),
-                "record_finalized_flags.test.not_enabled".to_string()
+                "record_finalized_flags.test.not_enabled".to_string(),
+                "record_finalized_flags.test.bar".to_string(),
+                "record_finalized_flags.test.boo".to_string(),
+            ])
+        );
+    }
+
+    #[test]
+    fn test_filter_api_flags() {
+        let input = std::str::from_utf8(include_bytes!("../tests/flags.textproto")).unwrap();
+        let parsed_flags = parsed_flags::try_from_text_proto(input).unwrap();
+        let mut bytes = Vec::new();
+        parsed_flags.write_to_vec(&mut bytes).unwrap();
+        let allow_flag_file = r#"
+        record_finalized_flags.test.boo
+        record_finalized_flags.test.not_enabled
+        "#
+        .as_bytes();
+
+        let allow_flag_set = read_flag_from_binary(allow_flag_file).unwrap();
+        let flags = filter_api_flags(&bytes[..], &allow_flag_set).unwrap();
+        let parsed_flags = aconfig_protos::parsed_flags::try_from_binary_proto(&flags).unwrap();
+        assert_eq!(2, parsed_flags.parsed_flag.len());
+
+        let ret = parsed_flags
+            .parsed_flag
+            .into_iter()
+            .filter(|flag| flag.is_exported())
+            .map(|flag| flag.fully_qualified_name())
+            .collect::<HashSet<FlagId>>();
+        assert_eq!(
+            ret,
+            HashSet::from_iter(vec![
+                "record_finalized_flags.test.foo".to_string(),
+                "record_finalized_flags.test.bar".to_string(),
+            ])
+        );
+
+        let allow_flag_file = r#"
+        record_finalized_flags.test.foo
+        record_finalized_flags.test.boo
+        record_finalized_flags.test.not_enabled
+        "#
+        .as_bytes();
+        let allow_flag_set = read_flag_from_binary(allow_flag_file).unwrap();
+        let flags = filter_api_flags(&bytes[..], &allow_flag_set).unwrap();
+        let parsed_flags = aconfig_protos::parsed_flags::try_from_binary_proto(&flags).unwrap();
+        assert_eq!(1, parsed_flags.parsed_flag.len());
+
+        let ret = parsed_flags
+            .parsed_flag
+            .into_iter()
+            .filter(|flag| flag.is_exported())
+            .map(|flag| flag.fully_qualified_name())
+            .collect::<HashSet<FlagId>>();
+        assert_eq!(ret, HashSet::from_iter(vec!["record_finalized_flags.test.bar".to_string(),]));
+    }
+
+    #[test]
+    fn test_read_flag_from_binary() {
+        let test_binary_file = r#"
+        // This is a comment
+        //record_finalized_flags.test.not_enabled
+        record_finalized_flags.test.bar
+
+        record_finalized_flags.test.baz
+        "#
+        .as_bytes();
+        let ret = read_flag_from_binary(test_binary_file).unwrap();
+        assert_eq!(2, ret.len());
+        assert_eq!(
+            ret,
+            HashSet::from_iter(vec![
+                "record_finalized_flags.test.bar".to_string(),
+                "record_finalized_flags.test.baz".to_string(),
             ])
         );
     }
diff --git a/tools/aconfig/exported_flag_check/tests/finalized-flags.txt b/tools/aconfig/exported_flag_check/tests/finalized-flags.txt
index 7fbcb3dc65..aa65d868d5 100644
--- a/tools/aconfig/exported_flag_check/tests/finalized-flags.txt
+++ b/tools/aconfig/exported_flag_check/tests/finalized-flags.txt
@@ -1,2 +1,3 @@
+//record_finalized_flags.test.not_enabled
 record_finalized_flags.test.bar
 record_finalized_flags.test.baz
diff --git a/tools/aconfig/exported_flag_check/tests/flags.declarations b/tools/aconfig/exported_flag_check/tests/flags.declarations
deleted file mode 100644
index f86dbfafbb..0000000000
--- a/tools/aconfig/exported_flag_check/tests/flags.declarations
+++ /dev/null
@@ -1,18 +0,0 @@
-package: "record_finalized_flags.test"
-container: "system"
-
-flag {
-    name: "foo"
-    namespace: "test"
-    description: "FIXME"
-    bug: ""
-    is_exported:true
-}
-
-flag {
-    name: "not_enabled"
-    namespace: "test"
-    description: "FIXME"
-    bug: ""
-    is_exported:true
-}
diff --git a/tools/aconfig/exported_flag_check/tests/flags.protobuf b/tools/aconfig/exported_flag_check/tests/flags.protobuf
deleted file mode 100644
index be64ef9927..0000000000
Binary files a/tools/aconfig/exported_flag_check/tests/flags.protobuf and /dev/null differ
diff --git a/tools/aconfig/exported_flag_check/tests/flags.textproto b/tools/aconfig/exported_flag_check/tests/flags.textproto
new file mode 100644
index 0000000000..6fa7743c6b
--- /dev/null
+++ b/tools/aconfig/exported_flag_check/tests/flags.textproto
@@ -0,0 +1,115 @@
+  parsed_flag {
+    package   : "record_finalized_flags.test"
+    name      : "bar"
+    namespace : "test"
+    description       : "This is a finalized flag for API"
+    bug       : ""
+    state     : DISABLED
+    permission: READ_WRITE
+    trace {
+      source    : "flags.declarations"
+      state     : DISABLED
+      permission: READ_WRITE
+    }
+    is_fixed_read_only: false
+    is_exported       : true
+    container : "system"
+    metadata {
+      purpose: PURPOSE_UNSPECIFIED
+      storage: ACONFIGD
+    }
+  }
+  parsed_flag {
+    package   : "record_finalized_flags.test"
+    name      : "boo"
+    namespace : "test"
+    description       : "This is a flag not for API, but allowed"
+    bug       : ""
+    state     : DISABLED
+    permission: READ_WRITE
+    trace {
+      source    : "flags.declarations"
+      state     : DISABLED
+      permission: READ_WRITE
+    }
+    is_fixed_read_only: false
+    is_exported       : true
+    container : "system"
+    metadata {
+      purpose: PURPOSE_UNSPECIFIED
+      storage: ACONFIGD
+    }
+  }
+  parsed_flag {
+    package   : "record_finalized_flags.test"
+    name      : "far"
+    namespace : "test"
+    description       : "This is a flag is not exported"
+    bug       : ""
+    state     : DISABLED
+    permission: READ_WRITE
+    trace {
+      source    : "flags.declarations"
+      state     : DISABLED
+      permission: READ_WRITE
+    }
+    is_fixed_read_only: false
+    is_exported       : false
+    container : "system"
+    metadata {
+      purpose: PURPOSE_UNSPECIFIED
+      storage: ACONFIGD
+    }
+  }
+  parsed_flag {
+    package   : "record_finalized_flags.test"
+    name      : "foo"
+    namespace : "test"
+    description       : "This is allow_list flag for API in the signature file"
+    bug       : ""
+    state     : ENABLED
+    permission: READ_ONLY
+    trace {
+      source    : "flags.declarations"
+      state     : DISABLED
+      permission: READ_WRITE
+    }
+    trace {
+      source    : "flags.values"
+      state     : ENABLED
+      permission: READ_ONLY
+    }
+    is_fixed_read_only: false
+    is_exported       : true
+    container : "system"
+    metadata {
+      purpose: PURPOSE_UNSPECIFIED
+      storage: NONE
+    }
+  }
+  parsed_flag {
+    package   : "record_finalized_flags.test"
+    name      : "not_enabled"
+    namespace : "test"
+    description       : "This is a flag exported, but not for API"
+    bug       : ""
+    state     : DISABLED
+    permission: READ_ONLY
+    trace {
+      source    : "flags.declarations"
+      state     : DISABLED
+      permission: READ_WRITE
+    }
+    trace {
+      source    : "flags.values"
+      state     : DISABLED
+      permission: READ_ONLY
+    }
+    is_fixed_read_only: false
+    is_exported       : true
+    container : "system"
+    metadata {
+      purpose: PURPOSE_UNSPECIFIED
+      storage: NONE
+    }
+  }
diff --git a/tools/aconfig/exported_flag_check/tests/flags.values b/tools/aconfig/exported_flag_check/tests/flags.values
deleted file mode 100644
index ff6225d822..0000000000
--- a/tools/aconfig/exported_flag_check/tests/flags.values
+++ /dev/null
@@ -1,13 +0,0 @@
-flag_value {
-    package: "record_finalized_flags.test"
-    name: "foo"
-    state: ENABLED
-    permission: READ_ONLY
-}
-
-flag_value {
-    package: "record_finalized_flags.test"
-    name: "not_enabled"
-    state: DISABLED
-    permission: READ_ONLY
-}
diff --git a/tools/aconfig/exported_flag_check/tests/generate-flags-protobuf.sh b/tools/aconfig/exported_flag_check/tests/generate-flags-protobuf.sh
deleted file mode 100755
index 701189cd5c..0000000000
--- a/tools/aconfig/exported_flag_check/tests/generate-flags-protobuf.sh
+++ /dev/null
@@ -1,7 +0,0 @@
-#!/bin/bash
-aconfig create-cache \
-    --package record_finalized_flags.test \
-    --container system \
-    --declarations flags.declarations \
-    --values flags.values \
-    --cache flags.protobuf
diff --git a/tools/aconfig/fake_device_config/Android.bp b/tools/aconfig/fake_device_config/Android.bp
index bf98058895..3b9cfe3b4a 100644
--- a/tools/aconfig/fake_device_config/Android.bp
+++ b/tools/aconfig/fake_device_config/Android.bp
@@ -27,6 +27,7 @@ java_library {
     name: "aconfig_storage_stub",
     srcs: [
         "src/android/os/flagging/**/*.java",
+        "src/android/provider/**/*.java",
     ],
     sdk_version: "core_current",
     host_supported: true,
diff --git a/tools/aconfig/fake_device_config/src/android/provider/DeviceConfig.java b/tools/aconfig/fake_device_config/src/android/provider/DeviceConfig.java
new file mode 100644
index 0000000000..dbb07ac983
--- /dev/null
+++ b/tools/aconfig/fake_device_config/src/android/provider/DeviceConfig.java
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package android.provider;
+
+/*
+ * This class allows generated aconfig code to compile independently of the framework.
+ */
+public class DeviceConfig {
+	private DeviceConfig() {
+	}
+
+	public static boolean getBoolean(String ns, String name, boolean def) {
+		return false;
+	}
+
+	public static Properties getProperties(String namespace, String... names) {
+		return new Properties();
+	}
+
+	public static class Properties {
+		public boolean getBoolean(String name, boolean def) {
+			return false;
+		}
+	}
+}
diff --git a/tools/check-flagged-apis/src/com/android/checkflaggedapis/Main.kt b/tools/check-flagged-apis/src/com/android/checkflaggedapis/Main.kt
index 25cba9ce4a..67b16fbfbc 100644
--- a/tools/check-flagged-apis/src/com/android/checkflaggedapis/Main.kt
+++ b/tools/check-flagged-apis/src/com/android/checkflaggedapis/Main.kt
@@ -24,6 +24,7 @@ import com.android.tools.metalava.model.ClassItem
 import com.android.tools.metalava.model.FieldItem
 import com.android.tools.metalava.model.Item
 import com.android.tools.metalava.model.text.ApiFile
+import com.android.tools.metalava.model.value.asString
 import com.github.ajalt.clikt.core.CliktCommand
 import com.github.ajalt.clikt.core.ProgramResult
 import com.github.ajalt.clikt.core.subcommands
@@ -292,8 +293,9 @@ internal fun parseApiSignature(path: String, input: InputStream): Set<Pair<Symbo
           return item.modifiers
               .findAnnotation("android.annotation.FlaggedApi")
               ?.findAttribute("value")
-              ?.legacyValue
-              ?.let { Flag(it.value() as String) }
+              ?.value
+              ?.asString()
+              ?.let { Flag(it) }
         }
       }
   val codebase = ApiFile.parseApi(path, input)
diff --git a/tools/compliance/cmd/htmlnotice/htmlnotice.go b/tools/compliance/cmd/htmlnotice/htmlnotice.go
index 78371ee599..6d07e66b30 100644
--- a/tools/compliance/cmd/htmlnotice/htmlnotice.go
+++ b/tools/compliance/cmd/htmlnotice/htmlnotice.go
@@ -241,6 +241,17 @@ func htmlNotice(ctx *context, files ...string) error {
 		fmt.Fprintf(ctx.stdout, "  <h1>%s</h1>\n", html.EscapeString(ctx.product))
 	}
 	ids := make(map[string]string)
+
+	// MD5 hash of File build/soong/licenses/opensourcerequest
+	opensourcerequestHash := "67459f64e6325b6ffaa3e53946688e6f"
+	opensourcerequestNotice := false
+	for h := range ni.Hashes() {
+		if h.String() == opensourcerequestHash {
+			opensourcerequestNotice = true
+			break
+		}
+	}
+
 	if ctx.includeTOC {
 		fmt.Fprintln(ctx.stdout, "  <ul class=\"toc\">")
 		i := 0
@@ -250,6 +261,9 @@ func htmlNotice(ctx *context, files ...string) error {
 			ids[installPath] = id
 			fmt.Fprintf(ctx.stdout, "    <li id=\"%s\"><strong>%s</strong>\n      <ul>\n", id, html.EscapeString(ctx.strip(installPath)))
 			for _, h := range ni.InstallHashes(installPath) {
+				if h.String() == opensourcerequestHash {
+					continue
+				}
 				libs := ni.InstallHashLibs(installPath, h)
 				fmt.Fprintf(ctx.stdout, "        <li><a href=\"#%s\">%s</a>\n", h.String(), html.EscapeString(strings.Join(libs, ", ")))
 			}
@@ -257,7 +271,15 @@ func htmlNotice(ctx *context, files ...string) error {
 		}
 		fmt.Fprintln(ctx.stdout, "  </ul><!-- toc -->")
 	}
+
+	if opensourcerequestNotice {
+		fmt.Fprintln(ctx.stdout, "  <hr>")
+		fmt.Fprintln(ctx.stdout, "  <strong>", html.EscapeString(string(ni.HashTextOfMd5(opensourcerequestHash))), "</strong>")
+	}
 	for h := range ni.Hashes() {
+		if h.String() == opensourcerequestHash {
+			continue
+		}
 		fmt.Fprintln(ctx.stdout, "  <hr>")
 		for _, libName := range ni.HashLibs(h) {
 			fmt.Fprintf(ctx.stdout, "  <strong>%s</strong> used by:\n    <ul class=\"file-list\">\n", html.EscapeString(libName))
diff --git a/tools/compliance/noticeindex.go b/tools/compliance/noticeindex.go
index c91a8dfa32..378dd23429 100644
--- a/tools/compliance/noticeindex.go
+++ b/tools/compliance/noticeindex.go
@@ -232,7 +232,7 @@ func (ni *NoticeIndex) Hashes() chan hash {
 // InputFiles returns the complete list of files read during indexing.
 func (ni *NoticeIndex) InputFiles() []string {
 	projectMeta := ni.pmix.AllMetadataFiles()
-	files := make([]string, 0, len(ni.files) + len(ni.lg.targets) + len(projectMeta))
+	files := make([]string, 0, len(ni.files)+len(ni.lg.targets)+len(projectMeta))
 	files = append(files, ni.files...)
 	for f := range ni.lg.targets {
 		files = append(files, f)
@@ -325,6 +325,11 @@ func (ni *NoticeIndex) HashText(h hash) []byte {
 	return ni.text[h]
 }
 
+func (ni *NoticeIndex) HashTextOfMd5(s string) []byte {
+	h := hash{key: s}
+	return ni.text[h]
+}
+
 // getLibName returns the name of the library associated with `noticeFor`.
 func (ni *NoticeIndex) getLibName(noticeFor *TargetNode, h hash) (string, error) {
 	for _, text := range noticeFor.LicenseTexts() {
diff --git a/tools/dependency_mapper/Android.bp b/tools/dependency_mapper/Android.bp
index 6763c0e106..dcf0e2f0d6 100644
--- a/tools/dependency_mapper/Android.bp
+++ b/tools/dependency_mapper/Android.bp
@@ -1,3 +1,17 @@
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
     default_team: "trendy_team_android_crumpet",
diff --git a/tools/dependency_mapper/README.md b/tools/dependency_mapper/README.md
index 475aef24fe..12d6fe0437 100644
--- a/tools/dependency_mapper/README.md
+++ b/tools/dependency_mapper/README.md
@@ -1,3 +1,16 @@
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
 # Dependency Mapper
 
 [dependency-mapper] command line tool. This tool finds the usage based dependencies between java
@@ -11,16 +24,13 @@ files by utilizing byte-code and java file analysis.
 
 ## Output
 * proto file, representing the list of dependencies for each java file present in input rsp file,
-represented by [proto/usage.proto]
+represented by [proto/dependency.proto]
 
 ## Usage
 ```
-dependency-mapper --src-path [src-list.rsp] --jar-path [classes.jar] --usage-map-path [usage-map.proto]"
+dependency-mapper --src-path [src-list.rsp] --jar-path [classes.jar] --usage-map-path [usage-map.proto]
 ```
 
 # Notes
 ## Dependencies enlisted are only within the java files present in input.
-## Ensure that [SourceFile] is present in the classes present in the jar.
-## To ensure dependencies are listed correctly
-* Classes jar should only contain class files generated from the source rsp files.
-* Classes jar should not exclude any class file that was generated from source rsp files.
\ No newline at end of file
+## To ensure dependencies are listed correctly classes jar should contain every class files generated from each source file.
\ No newline at end of file
diff --git a/tools/dependency_mapper/proto/Android.bp b/tools/dependency_mapper/proto/Android.bp
new file mode 100644
index 0000000000..810e4e5cc0
--- /dev/null
+++ b/tools/dependency_mapper/proto/Android.bp
@@ -0,0 +1,29 @@
+// Copyright 2025 Google Inc. All rights reserved.
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
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+bootstrap_go_package {
+    name: "golang-dependency-mapper-protoimpl",
+    pkgPath: "go.dependencymapper/protoimpl",
+    deps: [
+        "golang-protobuf-reflect-protoreflect",
+        "golang-protobuf-runtime-protoimpl",
+    ],
+    srcs: [
+        "dependency.pb.go",
+    ],
+}
diff --git a/tools/dependency_mapper/proto/dependency.pb.go b/tools/dependency_mapper/proto/dependency.pb.go
new file mode 100644
index 0000000000..334222e35e
--- /dev/null
+++ b/tools/dependency_mapper/proto/dependency.pb.go
@@ -0,0 +1,270 @@
+//
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+// Code generated by protoc-gen-go. DO NOT EDIT.
+// versions:
+// 	protoc-gen-go v1.30.0
+// 	protoc        v3.21.12
+// source: dependency.proto
+
+package protoimpl
+
+import (
+	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
+	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
+	reflect "reflect"
+	sync "sync"
+)
+
+const (
+	// Verify that this generated code is sufficiently up-to-date.
+	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
+	// Verify that runtime/protoimpl is sufficiently up-to-date.
+	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
+)
+
+type FileDependency struct {
+	state         protoimpl.MessageState
+	sizeCache     protoimpl.SizeCache
+	unknownFields protoimpl.UnknownFields
+
+	// java file path on disk
+	FilePath *string `protobuf:"bytes,1,opt,name=file_path,json=filePath" json:"file_path,omitempty"`
+	// if a change in this file warrants recompiling all files
+	IsDependencyToAll *bool `protobuf:"varint,2,opt,name=is_dependency_to_all,json=isDependencyToAll" json:"is_dependency_to_all,omitempty"`
+	// class files generated when this java file is compiled
+	GeneratedClasses []string `protobuf:"bytes,3,rep,name=generated_classes,json=generatedClasses" json:"generated_classes,omitempty"`
+	// dependencies of this file.
+	FileDependencies []string `protobuf:"bytes,4,rep,name=file_dependencies,json=fileDependencies" json:"file_dependencies,omitempty"`
+}
+
+func (x *FileDependency) Reset() {
+	*x = FileDependency{}
+	if protoimpl.UnsafeEnabled {
+		mi := &file_dependency_proto_msgTypes[0]
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		ms.StoreMessageInfo(mi)
+	}
+}
+
+func (x *FileDependency) String() string {
+	return protoimpl.X.MessageStringOf(x)
+}
+
+func (*FileDependency) ProtoMessage() {}
+
+func (x *FileDependency) ProtoReflect() protoreflect.Message {
+	mi := &file_dependency_proto_msgTypes[0]
+	if protoimpl.UnsafeEnabled && x != nil {
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		if ms.LoadMessageInfo() == nil {
+			ms.StoreMessageInfo(mi)
+		}
+		return ms
+	}
+	return mi.MessageOf(x)
+}
+
+// Deprecated: Use FileDependency.ProtoReflect.Descriptor instead.
+func (*FileDependency) Descriptor() ([]byte, []int) {
+	return file_dependency_proto_rawDescGZIP(), []int{0}
+}
+
+func (x *FileDependency) GetFilePath() string {
+	if x != nil && x.FilePath != nil {
+		return *x.FilePath
+	}
+	return ""
+}
+
+func (x *FileDependency) GetIsDependencyToAll() bool {
+	if x != nil && x.IsDependencyToAll != nil {
+		return *x.IsDependencyToAll
+	}
+	return false
+}
+
+func (x *FileDependency) GetGeneratedClasses() []string {
+	if x != nil {
+		return x.GeneratedClasses
+	}
+	return nil
+}
+
+func (x *FileDependency) GetFileDependencies() []string {
+	if x != nil {
+		return x.FileDependencies
+	}
+	return nil
+}
+
+// *
+// A com.android.dependencymapper.DependencyProto.FileDependencyList object.
+type FileDependencyList struct {
+	state         protoimpl.MessageState
+	sizeCache     protoimpl.SizeCache
+	unknownFields protoimpl.UnknownFields
+
+	// List of java file usages
+	FileDependency []*FileDependency `protobuf:"bytes,1,rep,name=fileDependency" json:"fileDependency,omitempty"`
+}
+
+func (x *FileDependencyList) Reset() {
+	*x = FileDependencyList{}
+	if protoimpl.UnsafeEnabled {
+		mi := &file_dependency_proto_msgTypes[1]
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		ms.StoreMessageInfo(mi)
+	}
+}
+
+func (x *FileDependencyList) String() string {
+	return protoimpl.X.MessageStringOf(x)
+}
+
+func (*FileDependencyList) ProtoMessage() {}
+
+func (x *FileDependencyList) ProtoReflect() protoreflect.Message {
+	mi := &file_dependency_proto_msgTypes[1]
+	if protoimpl.UnsafeEnabled && x != nil {
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		if ms.LoadMessageInfo() == nil {
+			ms.StoreMessageInfo(mi)
+		}
+		return ms
+	}
+	return mi.MessageOf(x)
+}
+
+// Deprecated: Use FileDependencyList.ProtoReflect.Descriptor instead.
+func (*FileDependencyList) Descriptor() ([]byte, []int) {
+	return file_dependency_proto_rawDescGZIP(), []int{1}
+}
+
+func (x *FileDependencyList) GetFileDependency() []*FileDependency {
+	if x != nil {
+		return x.FileDependency
+	}
+	return nil
+}
+
+var File_dependency_proto protoreflect.FileDescriptor
+
+var file_dependency_proto_rawDesc = []byte{
+	0x0a, 0x10, 0x64, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x79, 0x2e, 0x70, 0x72, 0x6f,
+	0x74, 0x6f, 0x12, 0x1c, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e,
+	0x64, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x79, 0x6d, 0x61, 0x70, 0x70, 0x65, 0x72,
+	0x22, 0xb8, 0x01, 0x0a, 0x0e, 0x46, 0x69, 0x6c, 0x65, 0x44, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65,
+	0x6e, 0x63, 0x79, 0x12, 0x1b, 0x0a, 0x09, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x70, 0x61, 0x74, 0x68,
+	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x66, 0x69, 0x6c, 0x65, 0x50, 0x61, 0x74, 0x68,
+	0x12, 0x2f, 0x0a, 0x14, 0x69, 0x73, 0x5f, 0x64, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63,
+	0x79, 0x5f, 0x74, 0x6f, 0x5f, 0x61, 0x6c, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x11,
+	0x69, 0x73, 0x44, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x79, 0x54, 0x6f, 0x41, 0x6c,
+	0x6c, 0x12, 0x2b, 0x0a, 0x11, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x63,
+	0x6c, 0x61, 0x73, 0x73, 0x65, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x10, 0x67, 0x65,
+	0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x65, 0x73, 0x12, 0x2b,
+	0x0a, 0x11, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x64, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63,
+	0x69, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x52, 0x10, 0x66, 0x69, 0x6c, 0x65, 0x44,
+	0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x69, 0x65, 0x73, 0x22, 0x6a, 0x0a, 0x12, 0x46,
+	0x69, 0x6c, 0x65, 0x44, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x79, 0x4c, 0x69, 0x73,
+	0x74, 0x12, 0x54, 0x0a, 0x0e, 0x66, 0x69, 0x6c, 0x65, 0x44, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65,
+	0x6e, 0x63, 0x79, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x63, 0x6f, 0x6d, 0x2e,
+	0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x64, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e,
+	0x63, 0x79, 0x6d, 0x61, 0x70, 0x70, 0x65, 0x72, 0x2e, 0x46, 0x69, 0x6c, 0x65, 0x44, 0x65, 0x70,
+	0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x79, 0x52, 0x0e, 0x66, 0x69, 0x6c, 0x65, 0x44, 0x65, 0x70,
+	0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x79, 0x42, 0x4e, 0x0a, 0x1c, 0x63, 0x6f, 0x6d, 0x2e, 0x61,
+	0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2e, 0x64, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63,
+	0x79, 0x6d, 0x61, 0x70, 0x70, 0x65, 0x72, 0x42, 0x0f, 0x44, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65,
+	0x6e, 0x63, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x5a, 0x1d, 0x67, 0x6f, 0x2e, 0x64, 0x65, 0x70,
+	0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x79, 0x6d, 0x61, 0x70, 0x70, 0x65, 0x72, 0x2f, 0x70, 0x72,
+	0x6f, 0x74, 0x6f, 0x69, 0x6d, 0x70, 0x6c,
+}
+
+var (
+	file_dependency_proto_rawDescOnce sync.Once
+	file_dependency_proto_rawDescData = file_dependency_proto_rawDesc
+)
+
+func file_dependency_proto_rawDescGZIP() []byte {
+	file_dependency_proto_rawDescOnce.Do(func() {
+		file_dependency_proto_rawDescData = protoimpl.X.CompressGZIP(file_dependency_proto_rawDescData)
+	})
+	return file_dependency_proto_rawDescData
+}
+
+var file_dependency_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
+var file_dependency_proto_goTypes = []interface{}{
+	(*FileDependency)(nil),     // 0: com.android.dependencymapper.FileDependency
+	(*FileDependencyList)(nil), // 1: com.android.dependencymapper.FileDependencyList
+}
+var file_dependency_proto_depIdxs = []int32{
+	0, // 0: com.android.dependencymapper.FileDependencyList.fileDependency:type_name -> com.android.dependencymapper.FileDependency
+	1, // [1:1] is the sub-list for method output_type
+	1, // [1:1] is the sub-list for method input_type
+	1, // [1:1] is the sub-list for extension type_name
+	1, // [1:1] is the sub-list for extension extendee
+	0, // [0:1] is the sub-list for field type_name
+}
+
+func init() { file_dependency_proto_init() }
+func file_dependency_proto_init() {
+	if File_dependency_proto != nil {
+		return
+	}
+	if !protoimpl.UnsafeEnabled {
+		file_dependency_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
+			switch v := v.(*FileDependency); i {
+			case 0:
+				return &v.state
+			case 1:
+				return &v.sizeCache
+			case 2:
+				return &v.unknownFields
+			default:
+				return nil
+			}
+		}
+		file_dependency_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
+			switch v := v.(*FileDependencyList); i {
+			case 0:
+				return &v.state
+			case 1:
+				return &v.sizeCache
+			case 2:
+				return &v.unknownFields
+			default:
+				return nil
+			}
+		}
+	}
+	type x struct{}
+	out := protoimpl.TypeBuilder{
+		File: protoimpl.DescBuilder{
+			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
+			RawDescriptor: file_dependency_proto_rawDesc,
+			NumEnums:      0,
+			NumMessages:   2,
+			NumExtensions: 0,
+			NumServices:   0,
+		},
+		GoTypes:           file_dependency_proto_goTypes,
+		DependencyIndexes: file_dependency_proto_depIdxs,
+		MessageInfos:      file_dependency_proto_msgTypes,
+	}.Build()
+	File_dependency_proto = out.File
+	file_dependency_proto_rawDesc = nil
+	file_dependency_proto_goTypes = nil
+	file_dependency_proto_depIdxs = nil
+}
diff --git a/tools/dependency_mapper/proto/dependency.proto b/tools/dependency_mapper/proto/dependency.proto
index 60a88f8f40..d96c38f634 100644
--- a/tools/dependency_mapper/proto/dependency.proto
+++ b/tools/dependency_mapper/proto/dependency.proto
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2019 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -19,6 +19,7 @@ syntax = "proto2";
 package com.android.dependencymapper;
 option java_package = "com.android.dependencymapper";
 option java_outer_classname = "DependencyProto";
+option go_package = "go.dependencymapper/protoimpl";
 
 /**
  * A com.android.dependencymapper.DependencyProto.FileDependency object.
diff --git a/tools/dependency_mapper/proto/go.mod b/tools/dependency_mapper/proto/go.mod
new file mode 100644
index 0000000000..e3ffa1b270
--- /dev/null
+++ b/tools/dependency_mapper/proto/go.mod
@@ -0,0 +1,3 @@
+module go.dependencymapper/protoimpl
+
+go 1.23
diff --git a/tools/dependency_mapper/proto/regen.sh b/tools/dependency_mapper/proto/regen.sh
new file mode 100755
index 0000000000..1649a4fcee
--- /dev/null
+++ b/tools/dependency_mapper/proto/regen.sh
@@ -0,0 +1,3 @@
+#!/bin/bash
+
+aprotoc --go_out=paths=source_relative:.  dependency.proto
\ No newline at end of file
diff --git a/tools/dependency_mapper/src/com/android/dependencymapper/DependencyMapper.java b/tools/dependency_mapper/src/com/android/dependencymapper/DependencyMapper.java
index ecf520c7d8..bf476c17a5 100644
--- a/tools/dependency_mapper/src/com/android/dependencymapper/DependencyMapper.java
+++ b/tools/dependency_mapper/src/com/android/dependencymapper/DependencyMapper.java
@@ -127,15 +127,17 @@ public class DependencyMapper {
         combinedClassDependencies.forEach((className, dependencies) -> {
             String sourceFile = mClassToSourceMap.get(className);
             if (sourceFile == null) {
-                throw new IllegalArgumentException("Class '" + className
+                System.err.println("Class '" + className
                         + "' does not have a corresponding source file.");
+                return;
             }
             mFileDependencies.computeIfAbsent(sourceFile, k -> new HashSet<>());
             dependencies.forEach(dependency -> {
                 String dependencySource = mClassToSourceMap.get(dependency);
                 if (dependencySource == null) {
-                    throw new IllegalArgumentException("Dependency '" + dependency
+                    System.err.println("Dependency '" + dependency
                             + "' does not have a corresponding source file.");
+                    return;
                 }
                 mFileDependencies.get(sourceFile).add(dependencySource);
             });
@@ -145,7 +147,7 @@ public class DependencyMapper {
     private void buildSourceToClassMap() {
         mClassToSourceMap.forEach((className, sourceFile) ->
                 mSourceToClasses.computeIfAbsent(sourceFile, k ->
-                        new HashSet<>()).add(className));
+                        new HashSet<>()).add(Utils.convertClassToFileBasedPath(className)));
     }
 
     private DependencyProto.FileDependencyList createFileDependencies() {
diff --git a/tools/dependency_mapper/src/com/android/dependencymapper/JavaSourceAnalyzer.java b/tools/dependency_mapper/src/com/android/dependencymapper/JavaSourceAnalyzer.java
index 3a4efadd77..4bb69a0790 100644
--- a/tools/dependency_mapper/src/com/android/dependencymapper/JavaSourceAnalyzer.java
+++ b/tools/dependency_mapper/src/com/android/dependencymapper/JavaSourceAnalyzer.java
@@ -19,7 +19,6 @@ import java.io.BufferedReader;
 import java.io.FileReader;
 import java.io.IOException;
 import java.nio.file.Path;
-import java.nio.file.Paths;
 import java.util.ArrayList;
 import java.util.List;
 import java.util.regex.Matcher;
@@ -33,19 +32,29 @@ public class JavaSourceAnalyzer {
 
     // Regex that matches against "package abc.xyz.lmn;" declarations in a java file.
     private static final String PACKAGE_REGEX = "^package\\s+([a-zA-Z_][a-zA-Z0-9_.]*);";
+    // Match either a single-quoted string, OR a sequence of non-whitespace characters.
+    private static final String FILE_PATH_REGEX = "'([^']*)'|(\\S+)";
 
     public static List<JavaSourceData> analyze(Path srcRspFile) {
         List<JavaSourceData> javaSourceDataList = new ArrayList<>();
         try (BufferedReader reader = new BufferedReader(new FileReader(srcRspFile.toFile()))) {
             String line;
             while ((line = reader.readLine()) != null) {
-                // Split the line by spaces, tabs, multiple java files can be on a single line.
-                String[] files = line.trim().split("\\s+");
+                List<String> files = new ArrayList<>();
+                Pattern pattern = Pattern.compile(FILE_PATH_REGEX);
+                Matcher matcher = pattern.matcher(line);
+                while (matcher.find()) {
+                    if (matcher.group(1) != null) {
+                        // Group 1: Single-quoted string (without the quotes)
+                        files.add(matcher.group(1));
+                    } else {
+                        // Group 2: Non-whitespace sequence
+                        files.add(matcher.group(2));
+                    }
+                }
                 for (String file : files) {
-                    Path p = Paths.get("", file);
-                    System.out.println(p.toAbsolutePath().toString());
-                    javaSourceDataList
-                            .add(new JavaSourceData(file, constructPackagePrependedFileName(file)));
+                    javaSourceDataList.add(new JavaSourceData(file,
+                            constructPackagePrependedFileName(file)));
                 }
             }
         } catch (IOException e) {
diff --git a/tools/dependency_mapper/src/com/android/dependencymapper/Utils.java b/tools/dependency_mapper/src/com/android/dependencymapper/Utils.java
index 5dd5f35bb9..931f45a9c2 100644
--- a/tools/dependency_mapper/src/com/android/dependencymapper/Utils.java
+++ b/tools/dependency_mapper/src/com/android/dependencymapper/Utils.java
@@ -40,6 +40,11 @@ public class Utils {
         return fileBasedPath.replaceAll("\\..*", "").replaceAll("/", ".");
     }
 
+    public static String convertClassToFileBasedPath(String packageBasedClass) {
+        // Remove ".class" from the fileBasedPath, then replace "/" with "."
+        return packageBasedClass.replaceAll("\\.", "/") + ".class";
+    }
+
     public static String buildPackagePrependedClassSource(String qualifiedClassPath,
             String classSource) {
         // Find the location of the start of classname in the qualifiedClassPath
@@ -52,8 +57,10 @@ public class Utils {
         Gson gson = new GsonBuilder().setPrettyPrinting().create();
         Map<String, Set<String>> jsonMap = new HashMap<>();
         for (DependencyProto.FileDependency fileDependency : contents.getFileDependencyList()) {
-            jsonMap.putIfAbsent(fileDependency.getFilePath(),
-                    Set.copyOf(fileDependency.getFileDependenciesList()));
+            jsonMap.putIfAbsent(fileDependency.getFilePath(), new HashSet<>(Set.copyOf(fileDependency.getFileDependenciesList())));
+            if (fileDependency.getIsDependencyToAll()) {
+                jsonMap.get(fileDependency.getFilePath()).add("isDepToAll");
+            }
         }
         String json = gson.toJson(jsonMap);
         try (FileWriter file = new FileWriter(jsonOut.toFile())) {
@@ -67,7 +74,7 @@ public class Utils {
     public static void writeContentsToProto(DependencyProto.FileDependencyList usages, Path protoOut) {
         try {
             OutputStream outputStream = Files.newOutputStream(protoOut);
-            usages.writeDelimitedTo(outputStream);
+            usages.writeTo(outputStream);
         } catch (IOException e) {
             System.err.println("Error writing proto output to: " + protoOut);
             throw new RuntimeException(e);
diff --git a/tools/edit_monitor/edit_monitor.py b/tools/edit_monitor/edit_monitor.py
index ab528e870f..3a3db332ad 100644
--- a/tools/edit_monitor/edit_monitor.py
+++ b/tools/edit_monitor/edit_monitor.py
@@ -46,7 +46,6 @@ class ClearcutEventHandler(PatternMatchingEventHandler):
       is_dry_run: bool = False,
       cclient: clearcut_client.Clearcut | None = None,
   ):
-
     super().__init__(patterns=["*"], ignore_directories=True)
     self.root_monitoring_path = path
     self.flush_interval_sec = flush_interval_sec
@@ -74,6 +73,10 @@ class ClearcutEventHandler(PatternMatchingEventHandler):
   def on_modified(self, event: FileSystemEvent):
     self._log_edit_event(event, edit_event_pb2.EditEvent.MODIFY)
 
+  def dispatch(self, event: FileSystemEvent) -> None:
+    if event.event_type in ("moved", "created", "deleted", "modified"):
+        super().dispatch(event)
+
   def flushall(self):
     logging.info("flushing all pending events.")
     if self._scheduled_log_thread:
@@ -110,7 +113,7 @@ class ClearcutEventHandler(PatternMatchingEventHandler):
       )
       event_proto.single_edit_event.CopyFrom(
           edit_event_pb2.EditEvent.SingleEditEvent(
-              file_path=event.src_path, edit_type=edit_type
+              edit_type=edit_type
           )
       )
       with self._pending_events_lock:
@@ -199,11 +202,26 @@ def start(
     conn: the sender of the pipe to communicate with the deamon manager.
   """
   event_handler = ClearcutEventHandler(
-      path, flush_interval_sec, single_events_size_threshold, is_dry_run, cclient)
+      path,
+      flush_interval_sec,
+      single_events_size_threshold,
+      is_dry_run,
+      cclient,
+  )
   observer = Observer()
 
-  logging.info("Starting observer on path %s.", path)
-  observer.schedule(event_handler, path, recursive=True)
+  out_dir = os.environ.get("OUT_DIR", "out")
+  sub_dirs = [
+      os.path.join(path, name)
+      for name in os.listdir(path)
+      if name != out_dir
+      and not name.startswith(".")
+      and os.path.isdir(os.path.join(path, name))
+  ]
+  for sub_dir_name in sub_dirs:
+      logging.info("Starting observer on path %s.", sub_dir_name)
+      observer.schedule(event_handler, sub_dir_name, recursive=True)
+
   observer.start()
   logging.info("Observer started.")
   if pipe_sender:
diff --git a/tools/edit_monitor/edit_monitor_integration_test.py b/tools/edit_monitor/edit_monitor_integration_test.py
index f39b93667d..000f0b705b 100644
--- a/tools/edit_monitor/edit_monitor_integration_test.py
+++ b/tools/edit_monitor/edit_monitor_integration_test.py
@@ -58,18 +58,20 @@ class EditMonitorIntegrationTest(unittest.TestCase):
     super().tearDown()
 
   def test_log_single_edit_event_success(self):
-    p = self._start_edit_monitor_process()
-
     # Create the .git file under the monitoring dir.
     self.root_monitoring_path.joinpath(".git").touch()
+    test_dir = self.root_monitoring_path.joinpath('test')
+    test_dir.mkdir()
+
+    p = self._start_edit_monitor_process()
 
     # Create and modify a file.
-    test_file = self.root_monitoring_path.joinpath("test.txt")
+    test_file = test_dir.joinpath("test.txt")
     with open(test_file, "w") as f:
       f.write("something")
 
     # Move the file.
-    test_file_moved = self.root_monitoring_path.joinpath("new_test.txt")
+    test_file_moved = test_dir.joinpath("new_test.txt")
     test_file.rename(test_file_moved)
 
     # Delete the file.
diff --git a/tools/edit_monitor/edit_monitor_test.py b/tools/edit_monitor/edit_monitor_test.py
index deb73e724b..ce77284fb2 100644
--- a/tools/edit_monitor/edit_monitor_test.py
+++ b/tools/edit_monitor/edit_monitor_test.py
@@ -56,17 +56,19 @@ class EditMonitorTest(unittest.TestCase):
   def test_log_single_edit_event_success(self):
     # Create the .git file under the monitoring dir.
     self.root_monitoring_path.joinpath('.git').touch()
+    test_dir = self.root_monitoring_path.joinpath('test')
+    test_dir.mkdir()
     fake_cclient = FakeClearcutClient(
         log_output_file=self.log_event_dir.joinpath('logs.output')
     )
     p = self._start_test_edit_monitor_process(fake_cclient)
 
     # Create and modify a file.
-    test_file = self.root_monitoring_path.joinpath('test.txt')
+    test_file = test_dir.joinpath('test.txt')
     with open(test_file, 'w') as f:
       f.write('something')
     # Move the file.
-    test_file_moved = self.root_monitoring_path.joinpath('new_test.txt')
+    test_file_moved = test_dir.joinpath('new_test.txt')
     test_file.rename(test_file_moved)
     # Delete the file.
     test_file_moved.unlink()
@@ -79,27 +81,15 @@ class EditMonitorTest(unittest.TestCase):
     logged_events = self._get_logged_events()
     self.assertEqual(len(logged_events), 4)
     expected_create_event = edit_event_pb2.EditEvent.SingleEditEvent(
-        file_path=str(
-            self.root_monitoring_path.joinpath('test.txt').resolve()
-        ),
         edit_type=edit_event_pb2.EditEvent.CREATE,
     )
     expected_modify_event = edit_event_pb2.EditEvent.SingleEditEvent(
-        file_path=str(
-            self.root_monitoring_path.joinpath('test.txt').resolve()
-        ),
         edit_type=edit_event_pb2.EditEvent.MODIFY,
     )
     expected_move_event = edit_event_pb2.EditEvent.SingleEditEvent(
-        file_path=str(
-            self.root_monitoring_path.joinpath('test.txt').resolve()
-        ),
         edit_type=edit_event_pb2.EditEvent.MOVE,
     )
     expected_delete_event = edit_event_pb2.EditEvent.SingleEditEvent(
-        file_path=str(
-            self.root_monitoring_path.joinpath('new_test.txt').resolve()
-        ),
         edit_type=edit_event_pb2.EditEvent.DELETE,
     )
     self.assertEqual(
@@ -127,10 +117,11 @@ class EditMonitorTest(unittest.TestCase):
         ).single_edit_event,
     )
 
-
   def test_log_aggregated_edit_event_success(self):
     # Create the .git file under the monitoring dir.
     self.root_monitoring_path.joinpath('.git').touch()
+    test_dir = self.root_monitoring_path.joinpath('test')
+    test_dir.mkdir()
     fake_cclient = FakeClearcutClient(
         log_output_file=self.log_event_dir.joinpath('logs.output')
     )
@@ -138,7 +129,7 @@ class EditMonitorTest(unittest.TestCase):
 
     # Create 6 test files
     for i in range(6):
-      test_file = self.root_monitoring_path.joinpath('test_' + str(i))
+      test_file = test_dir.joinpath('test_' + str(i))
       test_file.touch()
 
     # Give some time for the edit monitor to receive the edit event.
@@ -163,9 +154,34 @@ class EditMonitorTest(unittest.TestCase):
         ).aggregated_edit_event,
     )
 
+  def test_do_not_log_edit_event_under_out_dir(self):
+    # Create the .git file under the monitoring dir.
+    self.root_monitoring_path.joinpath('.git').touch()
+    fake_cclient = FakeClearcutClient(
+        log_output_file=self.log_event_dir.joinpath('logs.output')
+    )
+    p = self._start_test_edit_monitor_process(fake_cclient)
+
+    # Create out directory
+    self.root_monitoring_path.joinpath('out').mkdir()
+    # Create a file under out directory
+    test_file = self.root_monitoring_path.joinpath('out', 'test.txt')
+    with open(test_file, 'w') as f:
+      f.write('something')
+    # Give some time for the edit monitor to receive the edit event.
+    time.sleep(1)
+    # Stop the edit monitor and flush all events.
+    os.kill(p.pid, signal.SIGINT)
+    p.join()
+
+    logged_events = self._get_logged_events()
+    self.assertEqual(len(logged_events), 0)
+
   def test_do_not_log_edit_event_for_directory_change(self):
     # Create the .git file under the monitoring dir.
     self.root_monitoring_path.joinpath('.git').touch()
+    test_dir = self.root_monitoring_path.joinpath('test')
+    test_dir.mkdir()
     fake_cclient = FakeClearcutClient(
         log_output_file=self.log_event_dir.joinpath('logs.output')
     )
@@ -185,15 +201,17 @@ class EditMonitorTest(unittest.TestCase):
   def test_do_not_log_edit_event_for_hidden_file(self):
     # Create the .git file under the monitoring dir.
     self.root_monitoring_path.joinpath('.git').touch()
+    test_dir = self.root_monitoring_path.joinpath('test')
+    test_dir.mkdir()
     fake_cclient = FakeClearcutClient(
         log_output_file=self.log_event_dir.joinpath('logs.output')
     )
     p = self._start_test_edit_monitor_process(fake_cclient)
 
     # Create a hidden file.
-    self.root_monitoring_path.joinpath('.test.txt').touch()
+    test_dir.joinpath('.test.txt').touch()
     # Create a hidden dir.
-    hidden_dir = self.root_monitoring_path.joinpath('.test')
+    hidden_dir = test_dir.joinpath('.test')
     hidden_dir.mkdir()
     hidden_dir.joinpath('test.txt').touch()
     # Give some time for the edit monitor to receive the edit event.
@@ -206,15 +224,17 @@ class EditMonitorTest(unittest.TestCase):
     self.assertEqual(len(logged_events), 0)
 
   def test_do_not_log_edit_event_for_non_git_project_file(self):
+    test_dir = self.root_monitoring_path.joinpath('test')
+    test_dir.mkdir()
     fake_cclient = FakeClearcutClient(
         log_output_file=self.log_event_dir.joinpath('logs.output')
     )
     p = self._start_test_edit_monitor_process(fake_cclient)
 
     # Create a file.
-    self.root_monitoring_path.joinpath('test.txt').touch()
+    test_dir.joinpath('test.txt').touch()
     # Create a file under a sub dir.
-    sub_dir = self.root_monitoring_path.joinpath('.test')
+    sub_dir = test_dir.joinpath('.test')
     sub_dir.mkdir()
     sub_dir.joinpath('test.txt').touch()
     # Give some time for the edit monitor to receive the edit event.
@@ -229,6 +249,8 @@ class EditMonitorTest(unittest.TestCase):
   def test_log_edit_event_fail(self):
     # Create the .git file under the monitoring dir.
     self.root_monitoring_path.joinpath('.git').touch()
+    test_dir = self.root_monitoring_path.joinpath('test')
+    test_dir.mkdir()
     fake_cclient = FakeClearcutClient(
         log_output_file=self.log_event_dir.joinpath('logs.output'),
         raise_log_exception=True,
@@ -236,7 +258,7 @@ class EditMonitorTest(unittest.TestCase):
     p = self._start_test_edit_monitor_process(fake_cclient)
 
     # Create a file.
-    self.root_monitoring_path.joinpath('test.txt').touch()
+    test_dir.joinpath('test.txt').touch()
     # Give some time for the edit monitor to receive the edit event.
     time.sleep(1)
     # Stop the edit monitor and flush all events.
@@ -253,7 +275,14 @@ class EditMonitorTest(unittest.TestCase):
     # Start edit monitor in a subprocess.
     p = multiprocessing.Process(
         target=edit_monitor.start,
-        args=(str(self.root_monitoring_path.resolve()), False, 0.5, 5, cclient, sender),
+        args=(
+            str(self.root_monitoring_path.resolve()),
+            False,
+            0.5,
+            5,
+            cclient,
+            sender,
+        ),
     )
     p.daemon = True
     p.start()
diff --git a/tools/filelistdiff/README.md b/tools/filelistdiff/README.md
new file mode 100644
index 0000000000..0ed370dcb5
--- /dev/null
+++ b/tools/filelistdiff/README.md
@@ -0,0 +1,44 @@
+# Resolving System Image File List Differences
+
+The Android build system uses the `file_list_diff` tool to ensure consistency
+between the lists of installed files in system images defined by Kati and Soong.
+This check is crucial when transitioning to Soong-defined system images. If the
+tool detects any discrepancies, the build will fail.
+
+This document helps you understand and resolve the reported errors. There are
+two main types of errors: files present only in the Kati-defined image
+(`Kati only`) and files present only in the Soong-defined image (`Soong only`).
+
+## Understanding and Fixing Errors
+
+### Kati only installed files
+
+This error indicates that certain system modules are included via
+`PRODUCT_PACKAGES` in your device's Makefiles (`.mk` files) but are not
+explicitly defined within the `android_system_image` module or its default
+dependencies in `Android.bp`.
+
+**To resolve this:**
+
+* **Default System Modules:** If the module is defined in a common system
+Makefile (like `base_system.mk`, `generic_system.mk`, etc.), ensure it's listed
+in the `system_image_defaults` module within
+`build/make/target/product/generic/Android.bp`.
+* **Device-Specific Modules:** For modules specific to your device, add them to
+the relevant `android_system_image` module defined in
+`PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE` for your target.
+
+### Soong only installed files
+
+This error means that certain system modules are present in the Soong-defined
+system image (specified by `PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE`) but are not
+included in the `PRODUCT_PACKAGES` list for your target.
+
+**To resolve this:**
+
+* **Remove Incorrect Modules:** If these modules shouldn't be part of the system
+image, remove them from the `android_system_image` module definition.
+* **Add Missing Modules to Makefiles:** If these modules are indeed required,
+add them to the appropriate `.mk` files, following the guidance in the "Kati
+only installed files" section to ensure they are correctly included in both the
+Kati and Soong definitions.
\ No newline at end of file
diff --git a/tools/filelistdiff/file_list_diff.py b/tools/filelistdiff/file_list_diff.py
index a6408e87cc..e2b6fb7c71 100644
--- a/tools/filelistdiff/file_list_diff.py
+++ b/tools/filelistdiff/file_list_diff.py
@@ -42,17 +42,20 @@ def find_unique_items(kati_installed_files, soong_installed_files, system_module
 
     if unique_in_kati:
         print('')
-        print(f'{COLOR_ERROR}Missing required modules in {system_module_name} module.{COLOR_NORMAL}')
-        print(f'To resolve this issue, please add the modules to the Android.bp file for the {system_module_name} to install the following KATI only installed files.')
-        print(f'You can find the correct Android.bp file using the command "gomod {system_module_name}".')
+        print(f'{COLOR_ERROR}Missing required modules in the "{system_module_name}" module.{COLOR_NORMAL}')
+        print(f'To resolve this issue, please add the modules to the Android.bp file for the "{system_module_name}" to install the following KATI only installed files.')
+        print(f'You can find the Android.bp file using the command "gomod {system_module_name}".')
+        print('See build/make/tools/filelistdiff/README.md for more details.')
         print(f'{COLOR_WARNING}KATI only installed file(s):{COLOR_NORMAL}')
         for item in sorted(unique_in_kati):
             print('  '+item)
 
     if unique_in_soong:
         print('')
-        print(f'{COLOR_ERROR}Missing packages in base_system.mk.{COLOR_NORMAL}')
-        print('Please add packages into build/make/target/product/base_system.mk or build/make/tools/filelistdiff/allowlist to install or skip the following Soong only installed files.')
+        print(f'{COLOR_ERROR}Missing packages in PRODUCT_PACKAGES.{COLOR_NORMAL}')
+        print(f'Please add packages into .mk files or remove them from the "{system_module_name}" module in Android.bp file.')
+        print(f'You can find the Android.bp file using the command "gomod {system_module_name}".')
+        print('See build/make/tools/filelistdiff/README.md for more details.')
         print(f'{COLOR_WARNING}Soong only installed file(s):{COLOR_NORMAL}')
         for item in sorted(unique_in_soong):
             print('  '+item)
diff --git a/tools/finalization/build-step-0-and-m.sh b/tools/finalization/build-step-0-and-m.sh
index 484380045e..2b85682941 100755
--- a/tools/finalization/build-step-0-and-m.sh
+++ b/tools/finalization/build-step-0-and-m.sh
@@ -15,6 +15,6 @@ function finalize_main_step0_and_m() {
     source $top/build/make/tools/finalization/build-step-0.sh
     local m="$top/build/soong/soong_ui.bash --make-mode TARGET_PRODUCT=$1 TARGET_RELEASE=fina_0 TARGET_BUILD_VARIANT=userdebug"
     # This command tests the release state for AIDL.
-    AIDL_FROZEN_REL=true $m ${@:2}
+    $m ${@:2}
 }
 finalize_main_step0_and_m $@
diff --git a/tools/finalization/environment.sh b/tools/finalization/environment.sh
index c76980d90f..6c35cd6e4c 100755
--- a/tools/finalization/environment.sh
+++ b/tools/finalization/environment.sh
@@ -22,16 +22,16 @@ export FINAL_MAINLINE_EXTENSION='13'
 # 'vintf' - VINTF is finalized
 # 'sdk' - VINTF and SDK/API are finalized
 # 'rel' - branch is finalized, switched to REL
-export FINAL_STATE='rel'
+export FINAL_STATE='unfinalized'
 
 export BUILD_FROM_SOURCE_STUB=true
 
 # FINAL versions for VINTF
 # TODO(b/323985297): The version must match with that from the release configuration.
 # Instead of hardcoding the version here, read it from a release configuration.
-export FINAL_BOARD_API_LEVEL='202504'
-export FINAL_CORRESPONDING_VERSION_LETTER='B'
-export FINAL_CORRESPONDING_PLATFORM_VERSION='16'
-export FINAL_NEXT_BOARD_API_LEVEL='202604'
-export FINAL_NEXT_CORRESPONDING_VERSION_LETTER='C'
-export FINAL_NEXT_CORRESPONDING_SDK_VERSION='37'
+export FINAL_BOARD_API_LEVEL='202604'
+export FINAL_CORRESPONDING_VERSION_LETTER='C'
+export FINAL_CORRESPONDING_PLATFORM_VERSION='17'
+export FINAL_NEXT_BOARD_API_LEVEL='202704'
+export FINAL_NEXT_CORRESPONDING_VERSION_LETTER='D'
+export FINAL_NEXT_CORRESPONDING_SDK_VERSION='38'
diff --git a/tools/finalization/finalization-test/Android.bp b/tools/finalization/finalization-test/Android.bp
new file mode 100644
index 0000000000..03c9ff7634
--- /dev/null
+++ b/tools/finalization/finalization-test/Android.bp
@@ -0,0 +1,22 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_updatable_sdk_apis",
+}
+
+rust_test_host {
+    name: "finalization-test",
+    edition: "2021",
+    clippy_lints: "android",
+    lints: "android",
+    srcs: [
+        "test.rs",
+    ],
+    data: [
+        ":all_release_configs",
+    ],
+    rustlibs: [
+        "liball_release_configs_proto",
+        "libprotobuf",
+    ],
+    test_suites: ["general-tests"],
+}
diff --git a/tools/finalization/finalization-test/TEST_MAPPING b/tools/finalization/finalization-test/TEST_MAPPING
new file mode 100644
index 0000000000..1450fc2a8e
--- /dev/null
+++ b/tools/finalization/finalization-test/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "postsubmit": [
+    {
+      "name": "finalization-test"
+    }
+  ]
+}
diff --git a/tools/finalization/finalization-test/build_flags.rs b/tools/finalization/finalization-test/build_flags.rs
new file mode 100644
index 0000000000..816fd40879
--- /dev/null
+++ b/tools/finalization/finalization-test/build_flags.rs
@@ -0,0 +1,96 @@
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
+use all_release_configs_proto::build_flags_out::{ReleaseConfigArtifact, ReleaseConfigsArtifact};
+use protobuf::Message;
+use std::collections::HashMap;
+use std::fs;
+
+#[allow(dead_code)]
+pub const FLAGS_WE_CARE_ABOUT: [&str; 5] = [
+    "RELEASE_PLATFORM_SDK_VERSION",
+    "RELEASE_PLATFORM_SDK_VERSION_FULL",
+    "RELEASE_PLATFORM_VERSION",
+    "RELEASE_PLATFORM_VERSION_CODENAME",
+    "RELEASE_HIDDEN_API_EXPORTABLE_STUBS",
+];
+
+// A map of release-config -name -> map of flag-name -> flag-value
+//
+// Example access:
+//
+//   assert_eq!(BUILD_FLAGS["trunk"]["RELEASE_PLATFORM_SDK_VERSION"], 36)
+#[allow(dead_code)]
+pub type BuildFlagMap = HashMap<String, HashMap<String, String>>;
+
+#[allow(dead_code)]
+pub struct ReleaseConfigs {
+    pub flags: BuildFlagMap,
+    pub next: String,
+}
+
+impl ReleaseConfigs {
+    #[allow(dead_code)]
+    pub fn init() -> Self {
+        let protobuf =
+            fs::read("all_release_configs.pb").expect("Could not read all_release_configs.pb");
+        let all_release_configs = ReleaseConfigsArtifact::parse_from_bytes(&protobuf[..])
+            .expect("failed to parse protobuf as ReleaseConfigArtifact");
+
+        let mut flags = HashMap::new();
+        let mut next: Option<String> = None;
+
+        // parse currently active release config
+        parse_release_config(&mut flags, &all_release_configs.release_config);
+
+        // parse the other release configs
+        for release_config in all_release_configs.other_release_configs {
+            parse_release_config(&mut flags, &release_config);
+            if release_config.other_names.contains(&"next".to_string()) {
+                assert!(next.is_none(), "next: multiple aliases");
+                next = Some(release_config.name().to_string());
+            }
+        }
+
+        ReleaseConfigs { flags, next: next.expect("next: missing alias") }
+    }
+}
+
+fn parse_release_config(build_flag_map: &mut BuildFlagMap, release_config: &ReleaseConfigArtifact) {
+    let x: HashMap<String, String> = release_config
+        .flags
+        .iter()
+        .filter(|flag| FLAGS_WE_CARE_ABOUT.contains(&flag.flag_declaration.name()))
+        .map(|flag| {
+            // Flag values are expected to be strings or bools, or not set. In this tool, we
+            // represent all types as strings (for simplicity).
+            let value = if flag.value.val.is_none() {
+                // value not set -> ""
+                String::new()
+            } else if flag.value.has_string_value() {
+                // already a string, use as is
+                flag.value.string_value().to_string()
+            } else if flag.value.has_bool_value() {
+                // convert bool to "true" or "false"
+                format!("{}", flag.value.bool_value())
+            } else {
+                panic!("unexpected protobuf value type: {:?}", flag.value);
+            };
+            (flag.flag_declaration.name().to_string(), value)
+        })
+        .collect();
+    build_flag_map.insert(release_config.name().to_string(), x);
+}
diff --git a/tools/finalization/finalization-test/test.rs b/tools/finalization/finalization-test/test.rs
new file mode 100644
index 0000000000..60a677f597
--- /dev/null
+++ b/tools/finalization/finalization-test/test.rs
@@ -0,0 +1,130 @@
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
+mod build_flags;
+
+#[cfg(test)]
+mod tests {
+    use crate::build_flags::{ReleaseConfigs, FLAGS_WE_CARE_ABOUT};
+    use std::sync::LazyLock;
+
+    // the subset of build flags relevant for SDK finalization
+    static RELEASE_CONFIGS: LazyLock<ReleaseConfigs> = LazyLock::new(ReleaseConfigs::init);
+
+    fn sdk_version(release_config: &str) -> f32 {
+        // use SDK_INT_FULL if set, otherwise fall back to SDK_INT
+        let s = &RELEASE_CONFIGS.flags[release_config]["RELEASE_PLATFORM_SDK_VERSION_FULL"];
+        if !s.is_empty() {
+            s.parse::<f32>().unwrap_or_else(|_| {
+                panic!(
+                    "failed to parse RELEASE_PLATFORM_SDK_VERSION_FULL for {} ({}) as f32",
+                    release_config, s
+                )
+            })
+        } else {
+            let s = &RELEASE_CONFIGS.flags[release_config]["RELEASE_PLATFORM_SDK_VERSION"];
+            s.parse::<f32>().unwrap_or_else(|_| {
+                panic!(
+                    "failed to parse RELEASE_PLATFORM_SDK_VERSION for {} ({}) as f32",
+                    release_config, s
+                )
+            })
+        }
+    }
+
+    #[test]
+    fn test_build_flags_in_trunk_and_trunk_staging_are_equal() {
+        // invariant: the values of the flags (that this test cares about) in RELEASE_CONFIGS.flags are equal
+        // across trunk and trunk_staging release configs
+        //
+        // this means that the rest of the tests can focus on trunk and ignore trunk_staging
+        for flag in FLAGS_WE_CARE_ABOUT {
+            assert_eq!(
+                RELEASE_CONFIGS.flags["trunk"][flag], RELEASE_CONFIGS.flags["trunk_staging"][flag],
+                "flag {} differenct across trunk and trunk_staging",
+                flag,
+            );
+        }
+    }
+
+    #[test]
+    fn test_trunk_is_never_rel() {
+        // invariant: the codename in trunk is never REL: trunk is always bleeding edge and thus
+        // always something later than the latest finalized (REL) platform
+        assert_ne!(RELEASE_CONFIGS.flags["trunk"]["RELEASE_PLATFORM_VERSION_CODENAME"], "REL");
+    }
+
+    #[test]
+    fn test_version_parity_if_next_is_not_rel() {
+        // invariant: the version code of trunk and next are identical, unless next is REL: then
+        // the version in trunk can be one less than the version in next (during the intermediate
+        // state where next is REL but we haven't created prebuilts/sdk/<new-version> yet), or the
+        // version in trunk is identical to the one in next
+        let next = &RELEASE_CONFIGS.next;
+        if RELEASE_CONFIGS.flags[next]["RELEASE_PLATFORM_VERSION_CODENAME"] != "REL" {
+            // expect the versions to be identical
+            assert_eq!(
+                RELEASE_CONFIGS.flags[next]["RELEASE_PLATFORM_SDK_VERSION_FULL"],
+                RELEASE_CONFIGS.flags["trunk"]["RELEASE_PLATFORM_SDK_VERSION_FULL"]
+            );
+        } else {
+            // make sure the version in trunk is less or equal to that of next
+            //
+            // ideally this should check that trunk is at most one version behind next, but we
+            // can't tell what that means, so let's settle for the weaker guarantee of "less or
+            // equal"
+            assert!(sdk_version("trunk") <= sdk_version(next));
+        }
+    }
+
+    #[test]
+    fn test_version_and_version_full_parity() {
+        // invariant: for the release configs that set RELEASE_PLATFORM_SDK_VERSION_FULL:
+        //   - the value can be parsed as a float
+        //   - the value contains a decimal separator
+        //   - the value before the decimal separator is identical to RELEASE_PLATFORM_SDK_VERSION
+        //     (e.g. 36.0 and 36)
+        for release_config in RELEASE_CONFIGS.flags.keys() {
+            let version_full =
+                &RELEASE_CONFIGS.flags[release_config]["RELEASE_PLATFORM_SDK_VERSION_FULL"];
+            if version_full.is_empty() {
+                // skip this release config if it doesn't set RELEASE_PLATFORM_SDK_VERSION_FULL
+                continue;
+            }
+            assert!(
+                version_full.parse::<f32>().is_ok(),
+                "failed to convert value ({}) of RELEASE_PLATFORM_SDK_VERSION_FULL for {} to f32",
+                version_full,
+                release_config
+            );
+            let (integer_part, _) = version_full.split_once(".").unwrap_or_else(|| panic!("value of RELEASE_PLATFORM_SDK_VERSION_FULL ({}) for {} doesn't have expected format", version_full, release_config));
+            assert_eq!(
+                integer_part,
+                RELEASE_CONFIGS.flags[release_config]["RELEASE_PLATFORM_SDK_VERSION"]
+            );
+        }
+    }
+
+    #[test]
+    fn test_release_hidden_api_exportable_stubs_is_enabled_in_next() {
+        // invariant: RELEASE_HIDDEN_API_EXPORTABLE_STUBS is set to `true` in `next`, because we'll
+        // cut an Android release from this release config (the flag is too expensive in terms of
+        // build performance to enable everywhere)
+        let next = &RELEASE_CONFIGS.next;
+        let value = &RELEASE_CONFIGS.flags[next]["RELEASE_HIDDEN_API_EXPORTABLE_STUBS"];
+        assert_eq!(value, "true");
+    }
+}
diff --git a/tools/finalization/step-0.sh b/tools/finalization/step-0.sh
index 2087f6e670..b68bcadec3 100755
--- a/tools/finalization/step-0.sh
+++ b/tools/finalization/step-0.sh
@@ -33,7 +33,7 @@ function finalize_step_0_main() {
     commit_step_0_changes
 
     # build to confirm everything is OK
-    AIDL_FROZEN_REL=true $m
+    $m
 }
 
 finalize_step_0_main $@
diff --git a/tools/ide_query/ide_query.go b/tools/ide_query/ide_query.go
index 6caa29c1f3..075e136e61 100644
--- a/tools/ide_query/ide_query.go
+++ b/tools/ide_query/ide_query.go
@@ -20,6 +20,7 @@ package main
 
 import (
 	"bytes"
+	"cmp"
 	"container/list"
 	"context"
 	"encoding/json"
@@ -299,7 +300,18 @@ func findJavaModules(paths []string, modules map[string]*javaModule) map[string]
 	for name := range modules {
 		keys = append(keys, name)
 	}
-	slices.Sort(keys)
+	slices.SortFunc(keys, func(k1, k2 string) int {
+		// Some libraries use annotations by setting annotations_enabled: true.
+		// To enable IDE integration for such libraries, prefer the non package-private
+		// version of the annotations library.
+		if k1 == "stub-annotations" && k2 == "private-stub-annotations" {
+			return -1
+		} else if k1 == "private-stub-annotations" && k2 == "stub-annotations" {
+			return 1
+		} else {
+			return cmp.Compare(k1, k2)
+		}
+	})
 	for _, name := range keys {
 		if strings.HasSuffix(name, ".impl") {
 			continue
diff --git a/tools/otatools_package/Android.bp b/tools/otatools_package/Android.bp
index 80e1e7d964..38c77dfc68 100644
--- a/tools/otatools_package/Android.bp
+++ b/tools/otatools_package/Android.bp
@@ -17,8 +17,22 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+genrule_defaults {
+    name: "otatools_package_defaults",
+    enabled: select(soong_config_variable("otatools", "use_otatools_package"), {
+        true: true,
+        default: false,
+    }),
+    target: {
+        windows: {
+            enabled: false,
+        },
+    },
+}
+
 java_genrule_host {
     name: "otatools_package_dep_jars",
+    defaults: ["otatools_package_defaults"],
     tools: ["soong_zip"],
     compile_multilib: "first",
     cmd: "mkdir -p $(genDir)/framework && " +
@@ -35,6 +49,7 @@ java_genrule_host {
 
 cc_genrule {
     name: "otatools_package_dep_libs",
+    defaults: ["otatools_package_defaults"],
     host_supported: true,
     device_supported: false,
     compile_multilib: "first",
@@ -84,6 +99,7 @@ cc_genrule {
 
 cc_genrule {
     name: "otatools_package_dep_bins",
+    defaults: ["otatools_package_defaults"],
     host_supported: true,
     device_supported: false,
     compile_multilib: "first",
@@ -188,7 +204,8 @@ cc_genrule {
 }
 
 java_genrule_host {
-    name: "otatools_package",
+    name: "otatools-package",
+    defaults: ["otatools_package_defaults"],
     tools: ["merge_zips"],
     compile_multilib: "first",
     cmd: "$(location merge_zips) $(out) $(in)",
@@ -199,11 +216,11 @@ java_genrule_host {
         ":otatools_package_dep_libs",
         ":otatools_package_releasetools",
     ],
-    // TODO: Rename as "otatools.zip" when the rest files are ready.
-    out: ["otatools_temp.zip"],
+    out: ["otatools.zip"],
     dist: {
         targets: [
-            "otatools-package-temp",
+            "droidcore",
+            "otatools-package",
         ],
     },
 }
diff --git a/tools/perf/benchmarks b/tools/perf/benchmarks
index 38715ea8ea..267c315c63 100755
--- a/tools/perf/benchmarks
+++ b/tools/perf/benchmarks
@@ -381,17 +381,24 @@ class Runner():
         self._reports.append(report)
 
         # Preroll builds
-        for i in range(benchmark.preroll):
-            ns = self._run_build(lunch, benchmark_log_dir.joinpath(f"pre_{i}"), benchmark)
-            report.preroll_duration_ns.append(ns)
+        if not self._options.ApplyOnly():
+            for i in range(benchmark.preroll):
+                ns = self._run_build(lunch, benchmark_log_dir.joinpath(f"pre_{i}"), benchmark, {})
+                report.preroll_duration_ns.append(ns)
 
         sys.stderr.write(f"PERFORMING CHANGE: {benchmark.change.label}\n")
         if not self._options.DryRun():
             benchmark.change.change()
+            if self._options.ApplyOnly():
+                sys.stderr.write(f"NOT UNDOING CHANGE: {benchmark.change.label}\n")
+                return
         try:
 
+            extra_env = {
+                    "SOONG_HONOR_USE_PARTIAL_COMPILE": "true",
+            }
             # Measured build
-            ns = self._run_build(lunch, benchmark_log_dir.joinpath("measured"), benchmark)
+            ns = self._run_build(lunch, benchmark_log_dir.joinpath("measured"), benchmark, extra_env)
             report.duration_ns = ns
 
             dist_one = self._options.DistOne()
@@ -403,7 +410,7 @@ class Runner():
                 # Postroll builds
                 for i in range(benchmark.postroll):
                     ns = self._run_build(lunch, benchmark_log_dir.joinpath(f"post_{i}"),
-                                         benchmark)
+                                         benchmark, {})
                     report.postroll_duration_ns.append(ns)
 
         finally:
@@ -422,7 +429,7 @@ class Runner():
         path += ("/%0" + str(len(str(self._options.Iterations()))) + "d") % iteration
         return path
 
-    def _run_build(self, lunch, build_log_dir, benchmark):
+    def _run_build(self, lunch, build_log_dir, benchmark, extra_env):
         """Builds the modules.  Saves interesting log files to log_dir.  Raises FatalError
         if the build fails.
         """
@@ -437,6 +444,8 @@ class Runner():
             env["TARGET_PRODUCT"] = lunch.target_product
             env["TARGET_RELEASE"] = lunch.target_release
             env["TARGET_BUILD_VARIANT"] = lunch.target_build_variant
+            for k, v in extra_env.items():
+              env[k] = v
             returncode = subprocess.call(cmd, env=env)
             if returncode != 0:
                 report_error(f"Build failed: {' '.join(cmd)}")
@@ -564,6 +573,8 @@ benchmarks:
                             help="Benchmarks to run.  Default suite will be run if omitted.")
         parser.add_argument("--list", action="store_true",
                             help="list the available benchmarks.  No benchmark is run.")
+        parser.add_argument("--apply-only", action="store_true",
+                            help="apply the change only, and then exit. Intended only for debugging.")
         parser.add_argument("--dist-one", action="store_true",
                             help="Copy logs and metrics to the given dist dir. Requires that only"
                                 + " one benchmark be supplied. Postroll steps will be skipped.")
@@ -585,6 +596,12 @@ benchmarks:
         if self._args.dist_one and len(self.Benchmarks()) != 1:
             self._error("--dist-one requires exactly one --benchmark.")
 
+        # --apply-only forces --iterations=1
+        if self._args.apply_only:
+            self._args.iterations = 1
+            if self._args.dist_one:
+              self._error("--dist-one cannot be used with --apply-only.")
+
         if self._had_error:
             raise FatalError()
 
@@ -630,6 +647,9 @@ benchmarks:
     def Tag(self):
         return self._args.tag
 
+    def ApplyOnly(self):
+        return self._args.apply_only
+
     def DryRun(self):
         return self._args.dry_run
 
diff --git a/tools/perf/format_benchmarks b/tools/perf/format_benchmarks
index 807e546a17..8843078c4a 100755
--- a/tools/perf/format_benchmarks
+++ b/tools/perf/format_benchmarks
@@ -185,7 +185,7 @@ def main(argv):
         tagsort = lambda tag: tag
 
     # Sort the summaries
-    summaries.sort(key=lambda s: (s[1]["date"], s[1]["branch"], tagsort(s[1]["tag"])))
+    summaries.sort(key=lambda s: (s[1]["date"], s[1]["branch"], tagsort(s[1]["tag"] or "")))
 
     # group the benchmarks by column and iteration
     def bm_key(b):
diff --git a/tools/record-finalized-flags/Android.bp b/tools/record-finalized-flags/Android.bp
index 55a3a389e0..bad7560060 100644
--- a/tools/record-finalized-flags/Android.bp
+++ b/tools/record-finalized-flags/Android.bp
@@ -9,7 +9,6 @@ rust_defaults {
     lints: "android",
     srcs: ["src/main.rs"],
     rustlibs: [
-        "libaconfig_protos",
         "libanyhow",
         "libclap",
         "libregex",
diff --git a/tools/record-finalized-flags/Cargo.toml b/tools/record-finalized-flags/Cargo.toml
index 0fc795363f..598754f8bf 100644
--- a/tools/record-finalized-flags/Cargo.toml
+++ b/tools/record-finalized-flags/Cargo.toml
@@ -9,7 +9,6 @@ version = "0.1.0"
 edition = "2021"
 
 [dependencies]
-aconfig_protos = { path = "../aconfig/aconfig_protos" }
 anyhow = { path = "../../../../external/rust/android-crates-io/crates/anyhow" }
 clap = { path = "../../../../external/rust/android-crates-io/crates/clap", features = ["derive"] }
 regex = { path = "../../../../external/rust/android-crates-io/crates/regex" }
diff --git a/tools/record-finalized-flags/src/api_signature_files.rs b/tools/record-finalized-flags/src/api_signature_files.rs
deleted file mode 100644
index af8f4d1957..0000000000
--- a/tools/record-finalized-flags/src/api_signature_files.rs
+++ /dev/null
@@ -1,49 +0,0 @@
-/*
- * Copyright (C) 2025 The Android Open Source Project
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
-use anyhow::Result;
-use regex::Regex;
-use std::{collections::HashSet, io::Read};
-
-use crate::FlagId;
-
-/// Grep for all flags used with @FlaggedApi annotations in an API signature file (*current.txt
-/// file).
-pub(crate) fn extract_flagged_api_flags<R: Read>(mut reader: R) -> Result<HashSet<FlagId>> {
-    let mut haystack = String::new();
-    reader.read_to_string(&mut haystack)?;
-    let regex = Regex::new(r#"(?ms)@FlaggedApi\("(.*?)"\)"#).unwrap();
-    let iter = regex.captures_iter(&haystack).map(|cap| cap[1].to_owned());
-    Ok(HashSet::from_iter(iter))
-}
-
-#[cfg(test)]
-mod tests {
-    use super::*;
-
-    #[test]
-    fn test() {
-        let api_signature_file = include_bytes!("../tests/api-signature-file.txt");
-        let flags = extract_flagged_api_flags(&api_signature_file[..]).unwrap();
-        assert_eq!(
-            flags,
-            HashSet::from_iter(vec![
-                "record_finalized_flags.test.foo".to_string(),
-                "this.flag.is.not.used".to_string(),
-            ])
-        );
-    }
-}
diff --git a/tools/record-finalized-flags/src/flag_report.rs b/tools/record-finalized-flags/src/flag_report.rs
new file mode 100644
index 0000000000..ab2643231e
--- /dev/null
+++ b/tools/record-finalized-flags/src/flag_report.rs
@@ -0,0 +1,46 @@
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
+use anyhow::Result;
+use std::{collections::HashSet, io::Read};
+
+use crate::FlagId;
+
+/// Read a flag report generated by `metalava flag-report` representing all flags known by the
+/// build, and filter out the flags in the report that metalava has marked as finalized.
+pub(crate) fn read_and_filter_flag_report<R: Read>(mut reader: R) -> Result<HashSet<FlagId>> {
+    let mut contents = String::new();
+    reader.read_to_string(&mut contents)?;
+    let iter =
+        contents.lines().filter(|s| s.ends_with(",finalized") || s.ends_with(",kept")).map(|s| {
+            let (flag, _) =
+                s.split_once(",").expect("previous filter guarantees at least one comma");
+            flag.to_owned()
+        });
+    Ok(HashSet::from_iter(iter))
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test() {
+        let input = include_bytes!("../tests/flag-report.csv");
+        let flags = read_and_filter_flag_report(&input[..]).unwrap();
+        assert_eq!(flags, HashSet::from_iter(["com.foo".to_string(), "com.baz".to_string(),]));
+    }
+}
diff --git a/tools/record-finalized-flags/src/flag_values.rs b/tools/record-finalized-flags/src/flag_values.rs
deleted file mode 100644
index cc16d12f3c..0000000000
--- a/tools/record-finalized-flags/src/flag_values.rs
+++ /dev/null
@@ -1,53 +0,0 @@
-/*
- * Copyright (C) 2025 The Android Open Source Project
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
-use aconfig_protos::{ParsedFlagExt, ProtoFlagPermission, ProtoFlagState};
-use anyhow::{anyhow, Result};
-use std::{collections::HashSet, io::Read};
-
-use crate::FlagId;
-
-/// Parse a ProtoParsedFlags binary protobuf blob and return the fully qualified names of flags
-/// that are slated for API finalization (i.e. are both ENABLED and READ_ONLY).
-pub(crate) fn get_relevant_flags_from_binary_proto<R: Read>(
-    mut reader: R,
-) -> Result<HashSet<FlagId>> {
-    let mut buffer = Vec::new();
-    reader.read_to_end(&mut buffer)?;
-    let parsed_flags = aconfig_protos::parsed_flags::try_from_binary_proto(&buffer)
-        .map_err(|_| anyhow!("failed to parse binary proto"))?;
-    let iter = parsed_flags
-        .parsed_flag
-        .into_iter()
-        .filter(|flag| {
-            flag.state() == ProtoFlagState::ENABLED
-                && flag.permission() == ProtoFlagPermission::READ_ONLY
-        })
-        .map(|flag| flag.fully_qualified_name());
-    Ok(HashSet::from_iter(iter))
-}
-
-#[cfg(test)]
-mod tests {
-    use super::*;
-
-    #[test]
-    fn test_disabled_or_read_write_flags_are_ignored() {
-        let bytes = include_bytes!("../tests/flags.protobuf");
-        let flags = get_relevant_flags_from_binary_proto(&bytes[..]).unwrap();
-        assert_eq!(flags, HashSet::from_iter(vec!["record_finalized_flags.test.foo".to_string()]));
-    }
-}
diff --git a/tools/record-finalized-flags/src/main.rs b/tools/record-finalized-flags/src/main.rs
index efdbc9be8e..f9d667adfb 100644
--- a/tools/record-finalized-flags/src/main.rs
+++ b/tools/record-finalized-flags/src/main.rs
@@ -18,11 +18,10 @@
 //! prebuilts/sdk) of the flags used with @FlaggedApi APIs
 use anyhow::Result;
 use clap::Parser;
-use std::{collections::HashSet, fs::File, path::PathBuf};
+use std::{fs::File, path::PathBuf};
 
-mod api_signature_files;
 mod finalized_flags;
-mod flag_values;
+mod flag_report;
 
 pub(crate) type FlagId = String;
 
@@ -34,12 +33,10 @@ flags from being re-used for new, unfinalized, APIs, and by the aconfig code gen
 
 This tool works as follows:
 
-  - Read API signature files from source tree (*current.txt files) [--api-signature-file]
-  - Read the current aconfig flag values from source tree [--parsed-flags-file]
   - Read the previous finalized-flags.txt files from prebuilts/sdk [--finalized-flags-file]
-  - Extract the flags slated for API finalization by scanning through the API signature files for
-    flags that are ENABLED and READ_ONLY
-  - Merge the found flags with the recorded flags from previous API finalizations
+  - Read the state of the currently flags in the source as generated by `metalava flag-report`, and
+    filter out the flags marked as finalized [--flag-report]
+  - Merge and sort the two inputs
   - Print the set of flags to stdout
 ";
 
@@ -47,88 +44,26 @@ This tool works as follows:
 #[clap(about=ABOUT)]
 struct Cli {
     #[arg(long)]
-    parsed_flags_file: PathBuf,
+    finalized_flags: PathBuf,
 
     #[arg(long)]
-    api_signature_file: Vec<PathBuf>,
-
-    #[arg(long)]
-    finalized_flags_file: PathBuf,
-}
-
-/// Filter out the ENABLED and READ_ONLY flags used with @FlaggedApi annotations in the source
-/// tree, and add those flags to the set of previously finalized flags.
-fn calculate_new_finalized_flags(
-    flags_used_with_flaggedapi_annotation: &HashSet<FlagId>,
-    all_flags_to_be_finalized: &HashSet<FlagId>,
-    already_finalized_flags: &HashSet<FlagId>,
-) -> HashSet<FlagId> {
-    let new_flags: HashSet<_> = flags_used_with_flaggedapi_annotation
-        .intersection(all_flags_to_be_finalized)
-        .map(|s| s.to_owned())
-        .collect();
-    already_finalized_flags.union(&new_flags).map(|s| s.to_owned()).collect()
+    flag_report: PathBuf,
 }
 
 fn main() -> Result<()> {
     let args = Cli::parse();
 
-    let mut flags_used_with_flaggedapi_annotation = HashSet::new();
-    for path in args.api_signature_file {
-        let file = File::open(path)?;
-        for flag in api_signature_files::extract_flagged_api_flags(file)?.drain() {
-            flags_used_with_flaggedapi_annotation.insert(flag);
-        }
-    }
-
-    let file = File::open(args.parsed_flags_file)?;
-    let all_flags_to_be_finalized = flag_values::get_relevant_flags_from_binary_proto(file)?;
-
-    let file = File::open(args.finalized_flags_file)?;
+    let file = File::open(args.finalized_flags)?;
     let already_finalized_flags = finalized_flags::read_finalized_flags(file)?;
 
-    let mut new_finalized_flags = Vec::from_iter(calculate_new_finalized_flags(
-        &flags_used_with_flaggedapi_annotation,
-        &all_flags_to_be_finalized,
-        &already_finalized_flags,
-    ));
-    new_finalized_flags.sort();
-
-    println!("{}", new_finalized_flags.join("\n"));
+    let file = File::open(args.flag_report)?;
+    let newly_finalized_flags = flag_report::read_and_filter_flag_report(file)?;
 
-    Ok(())
-}
-
-#[cfg(test)]
-mod tests {
-    use super::*;
-
-    #[test]
-    fn test() {
-        let input = include_bytes!("../tests/api-signature-file.txt");
-        let flags_used_with_flaggedapi_annotation =
-            api_signature_files::extract_flagged_api_flags(&input[..]).unwrap();
+    let mut all_finalized_flags: Vec<_> =
+        already_finalized_flags.union(&newly_finalized_flags).map(|s| s.to_owned()).collect();
+    all_finalized_flags.sort();
 
-        let input = include_bytes!("../tests/flags.protobuf");
-        let all_flags_to_be_finalized =
-            flag_values::get_relevant_flags_from_binary_proto(&input[..]).unwrap();
+    println!("{}", all_finalized_flags.join("\n"));
 
-        let input = include_bytes!("../tests/finalized-flags.txt");
-        let already_finalized_flags = finalized_flags::read_finalized_flags(&input[..]).unwrap();
-
-        let new_finalized_flags = calculate_new_finalized_flags(
-            &flags_used_with_flaggedapi_annotation,
-            &all_flags_to_be_finalized,
-            &already_finalized_flags,
-        );
-
-        assert_eq!(
-            new_finalized_flags,
-            HashSet::from_iter(vec![
-                "record_finalized_flags.test.foo".to_string(),
-                "record_finalized_flags.test.bar".to_string(),
-                "record_finalized_flags.test.baz".to_string(),
-            ])
-        );
-    }
+    Ok(())
 }
diff --git a/tools/record-finalized-flags/tests/api-signature-file.txt b/tools/record-finalized-flags/tests/api-signature-file.txt
deleted file mode 100644
index 2ad559f0ad..0000000000
--- a/tools/record-finalized-flags/tests/api-signature-file.txt
+++ /dev/null
@@ -1,15 +0,0 @@
-// Signature format: 2.0
-package android {
-
-  public final class C {
-    ctor public C();
-  }
-
-  public static final class C.inner {
-    ctor public C.inner();
-    field @FlaggedApi("record_finalized_flags.test.foo") public static final String FOO = "foo";
-    field @FlaggedApi("this.flag.is.not.used") public static final String BAR = "bar";
-  }
-
-}
-
diff --git a/tools/record-finalized-flags/tests/flag-report.csv b/tools/record-finalized-flags/tests/flag-report.csv
new file mode 100644
index 0000000000..9fe750f3e0
--- /dev/null
+++ b/tools/record-finalized-flags/tests/flag-report.csv
@@ -0,0 +1,3 @@
+com.foo,known,finalized
+com.bar,unknown,reverted
+com.baz,known,kept
diff --git a/tools/record-finalized-flags/tests/flags.declarations b/tools/record-finalized-flags/tests/flags.declarations
deleted file mode 100644
index b45ef62523..0000000000
--- a/tools/record-finalized-flags/tests/flags.declarations
+++ /dev/null
@@ -1,16 +0,0 @@
-package: "record_finalized_flags.test"
-container: "system"
-
-flag {
-    name: "foo"
-    namespace: "test"
-    description: "FIXME"
-    bug: ""
-}
-
-flag {
-    name: "not_enabled"
-    namespace: "test"
-    description: "FIXME"
-    bug: ""
-}
diff --git a/tools/record-finalized-flags/tests/flags.protobuf b/tools/record-finalized-flags/tests/flags.protobuf
deleted file mode 100644
index 7c6e63eca8..0000000000
Binary files a/tools/record-finalized-flags/tests/flags.protobuf and /dev/null differ
diff --git a/tools/record-finalized-flags/tests/flags.values b/tools/record-finalized-flags/tests/flags.values
deleted file mode 100644
index ff6225d822..0000000000
--- a/tools/record-finalized-flags/tests/flags.values
+++ /dev/null
@@ -1,13 +0,0 @@
-flag_value {
-    package: "record_finalized_flags.test"
-    name: "foo"
-    state: ENABLED
-    permission: READ_ONLY
-}
-
-flag_value {
-    package: "record_finalized_flags.test"
-    name: "not_enabled"
-    state: DISABLED
-    permission: READ_ONLY
-}
diff --git a/tools/record-finalized-flags/tests/generate-flags-protobuf.sh b/tools/record-finalized-flags/tests/generate-flags-protobuf.sh
deleted file mode 100755
index 701189cd5c..0000000000
--- a/tools/record-finalized-flags/tests/generate-flags-protobuf.sh
+++ /dev/null
@@ -1,7 +0,0 @@
-#!/bin/bash
-aconfig create-cache \
-    --package record_finalized_flags.test \
-    --container system \
-    --declarations flags.declarations \
-    --values flags.values \
-    --cache flags.protobuf
diff --git a/tools/releasetools/Android.bp b/tools/releasetools/Android.bp
index 2232385c6c..d5325710f6 100644
--- a/tools/releasetools/Android.bp
+++ b/tools/releasetools/Android.bp
@@ -41,6 +41,7 @@ python_defaults {
     ],
     required: [
         "care_map_generator",
+        "mkbootimg",
     ],
 }
 
diff --git a/tools/releasetools/add_img_to_target_files.py b/tools/releasetools/add_img_to_target_files.py
index 180bf159a1..e8c6bbae1f 100644
--- a/tools/releasetools/add_img_to_target_files.py
+++ b/tools/releasetools/add_img_to_target_files.py
@@ -1146,12 +1146,6 @@ def AddImagesToTargetFiles(filename):
       banner("super_empty")
       AddSuperEmpty(output_zip)
 
-  if OPTIONS.info_dict.get("build_super_partition") == "true":
-    if OPTIONS.info_dict.get(
-            "build_retrofit_dynamic_partitions_ota_package") == "true":
-      banner("super split images")
-      AddSuperSplit(output_zip)
-
   banner("radio")
   ab_partitions_txt = os.path.join(OPTIONS.input_tmp, "META",
                                    "ab_partitions.txt")
diff --git a/tools/releasetools/apex_utils.py b/tools/releasetools/apex_utils.py
index 08f2b83388..58b949167e 100644
--- a/tools/releasetools/apex_utils.py
+++ b/tools/releasetools/apex_utils.py
@@ -425,15 +425,12 @@ def SignCompressedApex(avbtool, apex_file, payload_key, container_key,
   Returns:
     The path to the signed APEX file.
   """
-  debugfs_path = os.path.join(OPTIONS.search_path, 'bin', 'debugfs_static')
-
   # 1. Decompress original_apex inside compressed apex.
   original_apex_file = common.MakeTempFile(prefix='original-apex-',
                                            suffix='.apex')
   # Decompression target path should not exist
   os.remove(original_apex_file)
-  common.RunAndCheckOutput(['deapexer', '--debugfs_path', debugfs_path,
-                            'decompress', '--input', apex_file,
+  common.RunAndCheckOutput(['deapexer', 'decompress', '--input', apex_file,
                             '--output', original_apex_file])
 
   # 2. Sign original_apex
@@ -495,9 +492,7 @@ def SignApex(avbtool, apex_data, payload_key, container_key, container_pw,
   with open(apex_file, 'wb') as output_fp:
     output_fp.write(apex_data)
 
-  debugfs_path = os.path.join(OPTIONS.search_path, 'bin', 'debugfs_static')
-  cmd = ['deapexer', '--debugfs_path', debugfs_path,
-         'info', '--print-type', apex_file]
+  cmd = ['deapexer', 'info', '--print-type', apex_file]
 
   try:
     apex_type = common.RunAndCheckOutput(cmd).strip()
@@ -571,10 +566,6 @@ def GetApexInfoForPartition(input_file, partition):
 
   apex_infos = []
 
-  debugfs_path = "debugfs"
-  if OPTIONS.search_path:
-    debugfs_path = os.path.join(OPTIONS.search_path, "bin", "debugfs_static")
-
   deapexer = 'deapexer'
   if OPTIONS.search_path:
     deapexer_path = os.path.join(OPTIONS.search_path, "bin", "deapexer")
@@ -594,8 +585,7 @@ def GetApexInfoForPartition(input_file, partition):
     apex_info.version = manifest.version
     # Check if the file is compressed or not
     apex_type = RunAndCheckOutput([
-        deapexer, "--debugfs_path", debugfs_path,
-        'info', '--print-type', apex_filepath]).rstrip()
+        deapexer, 'info', '--print-type', apex_filepath]).rstrip()
     if apex_type == 'COMPRESSED':
       apex_info.is_compressed = True
     elif apex_type == 'UNCOMPRESSED':
diff --git a/tools/releasetools/build_super_image.py b/tools/releasetools/build_super_image.py
index ac61e609d3..fe3af3bcf9 100755
--- a/tools/releasetools/build_super_image.py
+++ b/tools/releasetools/build_super_image.py
@@ -30,11 +30,9 @@ input_file: one of the following:
       and super split images), a list of "*_image" should be paths of each
       source images.
 
-output_dir_or_file:
-    If a single super image is built (for super_empty.img, or super.img for
+output_file:
+    If a super image is built (for super_empty.img, or super.img for
     launch devices), this argument is the output file.
-    If a collection of split images are built (for retrofit devices), this
-    argument is the output directory.
 """
 
 from __future__ import print_function
@@ -77,32 +75,25 @@ def BuildSuperImageFromDict(info_dict, output):
 
   ab_update = info_dict.get("ab_update") == "true"
   virtual_ab = info_dict.get("virtual_ab") == "true"
-  virtual_ab_retrofit = info_dict.get("virtual_ab_retrofit") == "true"
-  retrofit = info_dict.get("dynamic_partition_retrofit") == "true"
   block_devices = shlex.split(info_dict.get("super_block_devices", "").strip())
   groups = shlex.split(info_dict.get("super_partition_groups", "").strip())
 
-  if ab_update and retrofit:
-    cmd += ["--metadata-slots", "2"]
-  elif ab_update:
+  if ab_update:
     cmd += ["--metadata-slots", "3"]
   else:
     cmd += ["--metadata-slots", "2"]
 
-  if ab_update and retrofit:
-    cmd.append("--auto-slot-suffixing")
-  if virtual_ab and not virtual_ab_retrofit:
+  if virtual_ab:
     cmd.append("--virtual-ab")
 
   for device in block_devices:
     size = info_dict["super_{}_device_size".format(device)]
     cmd += ["--device", "{}:{}".format(device, size)]
 
-  append_suffix = ab_update and not retrofit
   has_image = False
   for group in groups:
     group_size = info_dict["super_{}_group_size".format(group)]
-    if append_suffix:
+    if ab_update:
       cmd += ["--group", "{}_a:{}".format(group, group_size),
               "--group", "{}_b:{}".format(group, group_size)]
     else:
@@ -116,7 +107,7 @@ def BuildSuperImageFromDict(info_dict, output):
       if image:
         has_image = True
 
-      if not append_suffix:
+      if not ab_update:
         cmd += GetArgumentsForImage(partition, group, image)
         continue
 
@@ -140,11 +131,7 @@ def BuildSuperImageFromDict(info_dict, output):
 
   common.RunAndCheckOutput(cmd)
 
-  if retrofit and has_image:
-    logger.info("Done writing images to directory %s", output)
-  else:
-    logger.info("Done writing image %s", output)
-
+  logger.info("Done writing image %s", output)
   return True
 
 
diff --git a/tools/releasetools/check_partition_sizes.py b/tools/releasetools/check_partition_sizes.py
index b469d460b0..9a99f515f2 100644
--- a/tools/releasetools/check_partition_sizes.py
+++ b/tools/releasetools/check_partition_sizes.py
@@ -29,6 +29,7 @@ Exit code is 0 if successful and non-zero if any failures.
 from __future__ import print_function
 
 import logging
+import os
 import sys
 
 import common
@@ -94,15 +95,12 @@ class Expression(object):
 class DeviceType(object):
   NONE = 0
   AB = 1
-  RVAB = 2 # retrofit Virtual-A/B
-  VAB = 3
+  VAB = 2
 
   @staticmethod
   def Get(info_dict):
     if info_dict.get("ab_update") != "true":
       return DeviceType.NONE
-    if info_dict.get("virtual_ab_retrofit") == "true":
-      return DeviceType.RVAB
     if info_dict.get("virtual_ab") == "true":
       return DeviceType.VAB
     return DeviceType.AB
@@ -111,15 +109,12 @@ class DeviceType(object):
 # Dynamic partition feature flags
 class Dap(object):
   NONE = 0
-  RDAP = 1
-  DAP = 2
+  DAP = 1
 
   @staticmethod
   def Get(info_dict):
     if info_dict.get("use_dynamic_partitions") != "true":
       return Dap.NONE
-    if info_dict.get("dynamic_partition_retrofit") == "true":
-      return Dap.RDAP
     return Dap.DAP
 
 
@@ -182,13 +177,6 @@ class DynamicPartitionSizeChecker(object):
       raise RuntimeError("check_partition_sizes should only be executed on "
                          "builds with dynamic partitions enabled")
 
-    # Retrofit dynamic partitions: 1 slot per "super", 2 "super"s on the device
-    if dap == Dap.RDAP:
-      if slot != DeviceType.AB:
-        raise RuntimeError("Device with retrofit dynamic partitions must use "
-                           "regular (non-Virtual) A/B")
-      return 1
-
     # Launch DAP: 1 super on the device
     assert dap == Dap.DAP
 
@@ -196,10 +184,6 @@ class DynamicPartitionSizeChecker(object):
     if slot == DeviceType.AB:
       return 2
 
-    # DAP + retrofit Virtual A/B: same as A/B
-    if slot == DeviceType.RVAB:
-      return 2
-
     # DAP + Launch Virtual A/B: 1 *real* slot in super (2 virtual slots)
     if slot == DeviceType.VAB:
       return 1
@@ -260,10 +244,6 @@ class DynamicPartitionSizeChecker(object):
       max_size = Expression(
           "BOARD_SUPER_PARTITION_SIZE{}".format(size_limit_suffix),
           int(info_dict["super_partition_size"]) // num_slots)
-      # Retrofit DAP will build metadata as part of super image.
-      if Dap.Get(info_dict) == Dap.RDAP:
-        sum_size.CheckLe(max_size)
-        return
 
       sum_size.CheckLt(max_size)
       # Display a warning if group size + 1M >= super size
@@ -277,8 +257,6 @@ class DynamicPartitionSizeChecker(object):
 
   def Run(self):
     self._CheckAllPartitionSizes()
-    if self.info_dict.get("dynamic_partition_retrofit") == "true":
-      self._CheckSuperPartitionSize()
 
 
 def CheckPartitionSizes(inp):
diff --git a/tools/releasetools/common.py b/tools/releasetools/common.py
index 3fc08c668e..1ea01d7de8 100644
--- a/tools/releasetools/common.py
+++ b/tools/releasetools/common.py
@@ -1345,8 +1345,7 @@ def MergeDynamicPartitionInfoDicts(framework_dict, vendor_dict):
   else:
     merged_dict["vabc_cow_version"] = min(vendor_dict["vabc_cow_version"], framework_dict["vabc_cow_version"])
   # Various other flags should be copied from the vendor dict, if defined.
-  for key in ("virtual_ab", "virtual_ab_retrofit", "lpmake",
-              "super_metadata_device", "super_partition_error_limit",
+  for key in ("virtual_ab", "lpmake", "super_metadata_device", "super_partition_error_limit",
               "super_partition_size"):
     if key in vendor_dict.keys():
       merged_dict[key] = vendor_dict[key]
diff --git a/tools/releasetools/img_from_target_files.py b/tools/releasetools/img_from_target_files.py
index 186257786a..8b86c7f43d 100755
--- a/tools/releasetools/img_from_target_files.py
+++ b/tools/releasetools/img_from_target_files.py
@@ -66,7 +66,6 @@ OPTIONS.put_super = None
 OPTIONS.put_bootloader = None
 OPTIONS.dynamic_partition_list = None
 OPTIONS.super_device_list = None
-OPTIONS.retrofit_dap = None
 OPTIONS.build_super = None
 OPTIONS.sparse_userimages = None
 OPTIONS.use_fastboot_info = True
@@ -88,7 +87,6 @@ def LoadOptions(input_file):
                                             '').strip().split()
   OPTIONS.super_device_list = info.get('super_block_devices',
                                        '').strip().split()
-  OPTIONS.retrofit_dap = info.get('dynamic_partition_retrofit') == 'true'
   OPTIONS.build_super = info.get('build_super_partition') == 'true'
   OPTIONS.sparse_userimages = bool(info.get('extfs_sparse_flag'))
 
@@ -127,7 +125,7 @@ def EntriesForUserImages(input_file):
   dynamic_images = [p + '.img' for p in OPTIONS.dynamic_partition_list]
 
   # Filter out system_other for launch DAP devices because it is in super image.
-  if not OPTIONS.retrofit_dap and 'system' in OPTIONS.dynamic_partition_list:
+  if 'system' in OPTIONS.dynamic_partition_list:
     dynamic_images.append('system_other.img')
 
   entries = [
@@ -172,24 +170,6 @@ def EntriesForUserImages(input_file):
   return entries
 
 
-def EntriesForSplitSuperImages(input_file):
-  """Returns the entries for split super images.
-
-  This is only done for retrofit dynamic partition devices.
-
-  Args:
-    input_file: Path to the input target_files zip file.
-  """
-  with zipfile.ZipFile(input_file) as input_zip:
-    namelist = input_zip.namelist()
-  entries = []
-  for device in OPTIONS.super_device_list:
-    image = 'OTA/super_{}.img'.format(device)
-    assert image in namelist, 'Failed to find {}'.format(image)
-    entries.append('{}:{}'.format(image, os.path.basename(image)))
-  return entries
-
-
 def RebuildAndWriteSuperImages(input_file, output_file):
   """Builds and writes super images to the output file."""
   logger.info('Building super image...')
@@ -238,14 +218,9 @@ def ImgFromTargetFiles(input_file, output_file):
   # Entries to be copied into the output file.
   entries = EntriesForUserImages(input_file)
 
-  # Only for devices that retrofit dynamic partitions there're split super
-  # images available in the target_files.zip.
   rebuild_super = False
   if OPTIONS.build_super and OPTIONS.put_super:
-    if OPTIONS.retrofit_dap:
-      entries += EntriesForSplitSuperImages(input_file)
-    else:
-      rebuild_super = True
+    rebuild_super = True
 
   # Any additional entries provided by caller.
   entries += OPTIONS.additional_entries
diff --git a/tools/releasetools/merge/merge_compatibility_checks.py b/tools/releasetools/merge/merge_compatibility_checks.py
index 80b5caa156..69633bd43c 100644
--- a/tools/releasetools/merge/merge_compatibility_checks.py
+++ b/tools/releasetools/merge/merge_compatibility_checks.py
@@ -151,6 +151,15 @@ def CheckCombinedSepolicy(target_files_dir, partition_map, execute=True):
   with open(vendor_plat_version_file) as f:
     vendor_plat_version = f.read().strip()
 
+  vendor_genfs_version = ""
+  vendor_genfs_version_file = get_file('vendor',
+                                       'etc/selinux/genfs_labels_version.txt')
+  if vendor_genfs_version_file:
+    with open(vendor_genfs_version_file) as f:
+      vendor_genfs_version = f.read().strip()
+  else:
+    logger.debug('Missing vendor/etc/selinux/genfs_labels_version.txt')
+
   # Use the same flags and arguments as selinux.cpp OpenSplitPolicy().
   cmd = ['secilc', '-m', '-M', 'true', '-G', '-N']
   cmd.extend(['-c', kernel_sepolicy_version])
@@ -170,14 +179,20 @@ def CheckCombinedSepolicy(target_files_dir, partition_map, execute=True):
       return errors
     cmd.append(policy)
 
-  optional_policy_files = (
+  optional_policy_files = [
       ('system', 'etc/selinux/mapping/%s.compat.cil' % vendor_plat_version),
       ('system_ext', 'etc/selinux/system_ext_sepolicy.cil'),
       ('system_ext', 'etc/selinux/mapping/%s.cil' % vendor_plat_version),
       ('product', 'etc/selinux/product_sepolicy.cil'),
       ('product', 'etc/selinux/mapping/%s.cil' % vendor_plat_version),
       ('odm', 'etc/selinux/odm_sepolicy.cil'),
-  )
+  ]
+  if vendor_genfs_version != "":
+    optional_policy_files.append(
+        ('system',
+         f'etc/selinux/plat_sepolicy_genfs_{vendor_genfs_version}.cil',
+        )
+    )
   for policy in (map(lambda partition_and_path: get_file(*partition_and_path),
                      optional_policy_files)):
     if policy:
diff --git a/tools/releasetools/merge/merge_meta.py b/tools/releasetools/merge/merge_meta.py
index 76582c0946..0ee11d0506 100644
--- a/tools/releasetools/merge/merge_meta.py
+++ b/tools/releasetools/merge/merge_meta.py
@@ -50,8 +50,40 @@ PARTITION_TAG_PATTERN = re.compile(r'partition="(.*?)"')
 # The sorting algorithm for apexkeys.txt and apkcerts.txt does not include the
 # ".apex" or ".apk" suffix, so we use the following pattern to extract a key.
 
+def LoadKeyValueText(path):
+  keyvalue_store = {}
+  if os.path.exists(path):
+    with open(path) as fp:
+      for line in fp.readlines():
+        components = line.strip().split("=", 1)
+        if len(components) == 2:
+          keyvalue_store[components[0]] = components[1]
+  return keyvalue_store
+
+
 MODULE_KEY_PATTERN = re.compile(r'name="(.+)\.(apex|apk)"')
 
+def MergePostinstallConfig(framework_meta_dir, vendor_meta_dir,
+                            merged_meta_dir):
+  _CONFIG_NAME = 'postinstall_config.txt'
+  _SYSTEM_PARTITIONS = ["system", "system_ext", "product", "init_boot"]
+  _SYSTEM_PARTITIONS_PREFIXED = [ "_" + p for p in _SYSTEM_PARTITIONS ]
+  framework_config_path = os.path.join(framework_meta_dir, _CONFIG_NAME)
+  vendor_config_path = os.path.join(vendor_meta_dir, _CONFIG_NAME)
+  merged_config_path = os.path.join(merged_meta_dir, _CONFIG_NAME)
+  framework_config = LoadKeyValueText(framework_config_path)
+  vendor_config = LoadKeyValueText(vendor_config_path)
+  merged_config = {}
+  merged_config.update(framework_config)
+  key: str
+  for (key, val) in vendor_config.items():
+    # only allow vendor postinstall config to override non-system postinstall
+    # configs
+    if not key.endswith(tuple(_SYSTEM_PARTITIONS_PREFIXED)):
+      merged_config[key] = val
+
+  # TODO: might want to consider sorting according to suffix to group per partition
+  merge_utils.WriteSortedData(merged_config, merged_config_path)
 
 def MergeUpdateEngineConfig(framework_meta_dir, vendor_meta_dir,
                             merged_meta_dir):
@@ -134,6 +166,7 @@ def MergeMetaFiles(temp_dir, merged_dir, framework_partitions):
   if OPTIONS.merged_misc_info.get('ab_update') == 'true':
     MergeUpdateEngineConfig(
         framework_meta_dir, vendor_meta_dir, merged_meta_dir)
+    MergePostinstallConfig(framework_meta_dir, vendor_meta_dir, merged_meta_dir)
 
   # Write the now-finalized OPTIONS.merged_misc_info.
   merge_utils.WriteSortedData(
diff --git a/tools/releasetools/merge/test_merge_compatibility_checks.py b/tools/releasetools/merge/test_merge_compatibility_checks.py
index 0f319de970..0a32565a6b 100644
--- a/tools/releasetools/merge/test_merge_compatibility_checks.py
+++ b/tools/releasetools/merge/test_merge_compatibility_checks.py
@@ -56,11 +56,13 @@ class MergeCompatibilityChecksTest(test_utils.ReleaseToolsTestCase):
           <kernel-sepolicy-version>30</kernel-sepolicy-version>
         </sepolicy>
       </compatibility-matrix>""")
-    write_temp_file('vendor/etc/selinux/plat_sepolicy_vers.txt', '30.0')
+    write_temp_file('vendor/etc/selinux/plat_sepolicy_vers.txt', '202504')
+    write_temp_file('vendor/etc/selinux/genfs_labels_version.txt', '202504')
 
     write_temp_file('system/etc/selinux/plat_sepolicy.cil')
-    write_temp_file('system/etc/selinux/mapping/30.0.cil')
-    write_temp_file('product/etc/selinux/mapping/30.0.cil')
+    write_temp_file('system/etc/selinux/mapping/202504.cil')
+    write_temp_file('system/etc/selinux/plat_sepolicy_genfs_202504.cil')
+    write_temp_file('product/etc/selinux/mapping/202504.cil')
     write_temp_file('vendor/etc/selinux/vendor_sepolicy.cil')
     write_temp_file('vendor/etc/selinux/plat_pub_versioned.cil')
 
@@ -70,10 +72,11 @@ class MergeCompatibilityChecksTest(test_utils.ReleaseToolsTestCase):
                      ('secilc -m -M true -G -N -c 30 '
                       '-o {OTP}/META/combined_sepolicy -f /dev/null '
                       '{OTP}/system/etc/selinux/plat_sepolicy.cil '
-                      '{OTP}/system/etc/selinux/mapping/30.0.cil '
+                      '{OTP}/system/etc/selinux/mapping/202504.cil '
                       '{OTP}/vendor/etc/selinux/vendor_sepolicy.cil '
                       '{OTP}/vendor/etc/selinux/plat_pub_versioned.cil '
-                      '{OTP}/product/etc/selinux/mapping/30.0.cil').format(
+                      '{OTP}/product/etc/selinux/mapping/202504.cil',
+                      '{OTP}/system/etc/selinux/plat_sepolicy_genfs_202504.cil').format(
                           OTP=product_out_dir))
 
   def _copy_apex(self, source, output_dir, partition):
diff --git a/tools/releasetools/ota_from_raw_img.py b/tools/releasetools/ota_from_raw_img.py
index 3b9374ab13..ce44d98c13 100644
--- a/tools/releasetools/ota_from_raw_img.py
+++ b/tools/releasetools/ota_from_raw_img.py
@@ -21,21 +21,25 @@ Given a series of .img files, produces an OTA package that installs thoese image
 import sys
 import os
 import argparse
+import shutil
 import subprocess
 import tempfile
 import logging
 import zipfile
 
 import common
+import ota_metadata_pb2
 from payload_signer import PayloadSigner
-from ota_utils import PayloadGenerator
+from ota_utils import PayloadGenerator, FinalizeMetadata
 from ota_signing_utils import AddSigningArgumentParse
 
 
 logger = logging.getLogger(__name__)
 
 
-def ResolveBinaryPath(filename, search_path):
+def ResolveBinaryPath(filename, search_path, bin_path):
+  if bin_path is not None:
+    return bin_path
   if not search_path:
     return filename
   if not os.path.exists(search_path):
@@ -49,6 +53,28 @@ def ResolveBinaryPath(filename, search_path):
   return path
 
 
+def UpdateDynamicPartitionInfo(contents, in_file):
+    with open(in_file, 'r') as fp:
+        for line in fp.readlines():
+            parts = line.split('=', maxsplit=1)
+            if len(parts) != 2:
+                continue
+            contents[parts[0]] = parts[1]
+
+
+def WriteDynamicPartitionInfo(in_file, out_fp):
+    keyvalues = {
+        "virtual_ab": "true",
+        "super_partition_groups": "",
+    }
+    if in_file is not None:
+        UpdateDynamicPartitionInfo(keyvalues, in_file)
+    for key in keyvalues:
+        line = "{}={}\n".format(key, keyvalues[key])
+        out_fp.write(line.encode("utf-8"))
+    out_fp.flush()
+
+
 def main(argv):
   parser = argparse.ArgumentParser(
       prog=argv[0], description="Given a series of .img files, produces a full OTA package that installs thoese images")
@@ -60,6 +86,12 @@ def main(argv):
                       help='Paths to output merged ota', required=True)
   parser.add_argument('--max_timestamp', type=int,
                       help='Maximum build timestamp allowed to install this OTA')
+  parser.add_argument("--metadata_proto_file", type=str,
+                      help="Optional OTA metadata proto to use for signing")
+  parser.add_argument("--dynamic_partition_info_file", type=str,
+                      help="Optional dynamic partition info file")
+  parser.add_argument("--delta_generator_path", type=str,
+                      help="Path to delta_generator")
   parser.add_argument("-v", action="store_true",
                       help="Enable verbose logging", dest="verbose")
   AddSigningArgumentParse(parser)
@@ -79,10 +111,8 @@ def main(argv):
   else:
     args.partition_names = args.partition_names.split(",")
   with tempfile.NamedTemporaryFile() as unsigned_payload, tempfile.NamedTemporaryFile() as dynamic_partition_info_file:
-    dynamic_partition_info_file.writelines(
-        [b"virtual_ab=true\n", b"super_partition_groups=\n"])
-    dynamic_partition_info_file.flush()
-    cmd = [ResolveBinaryPath("delta_generator", args.search_path)]
+    WriteDynamicPartitionInfo(args.dynamic_partition_info_file, dynamic_partition_info_file)
+    cmd = [ResolveBinaryPath("delta_generator", args.search_path, args.delta_generator_path)]
     cmd.append("--partition_names=" + ":".join(args.partition_names))
     cmd.append("--dynamic_partition_info_file=" +
                dynamic_partition_info_file.name)
@@ -119,6 +149,13 @@ def main(argv):
     with zipfile.ZipFile(args.output, "w") as zfp:
       generator.WriteToZip(zfp)
 
+    if args.package_key and args.metadata_proto_file:
+      temp_zip = common.MakeTempFile(prefix="temp-", suffix=".zip")
+      metadata = ota_metadata_pb2.OtaMetadata()
+      with open(args.metadata_proto_file, "rb") as fp:
+          metadata.ParseFromString(fp.read())
+      shutil.copy(args.output, temp_zip)
+      FinalizeMetadata(metadata, temp_zip, args.output, package_key=args.package_key)
 
 if __name__ == "__main__":
   logging.basicConfig()
diff --git a/tools/releasetools/ota_from_target_files.py b/tools/releasetools/ota_from_target_files.py
index 76d168cb8e..9ee33295b9 100755
--- a/tools/releasetools/ota_from_target_files.py
+++ b/tools/releasetools/ota_from_target_files.py
@@ -64,13 +64,6 @@ Common options that apply to both of non-A/B and A/B OTAs
       Generate an OTA package that will wipe the user data partition when
       installed.
 
-  --retrofit_dynamic_partitions
-      Generates an OTA package that updates a device to support dynamic
-      partitions (default False). This flag is implied when generating
-      an incremental OTA where the base build does not support dynamic
-      partitions but the target build does. For A/B, when this flag is set,
-      --skip_postinstall is implied.
-
   --skip_compatibility_check
       Skip checking compatibility of the input target files package.
 
@@ -249,9 +242,9 @@ A/B OTA specific options
       older SPL.
 
   --vabc_compression_param
-      Compression algorithm to be used for VABC. Available options: gz, lz4, zstd, brotli, none. 
-      Compression level can be specified by appending ",$LEVEL" to option. 
-      e.g. --vabc_compression_param=gz,9 specifies level 9 compression with gz algorithm
+      Compression algorithm to be used for VABC. Available options: lz4, zstd, none.
+      Compression level can be specified by appending ",$LEVEL" to option.
+      e.g. --vabc_compression_param=zstd,9 specifies level 9 compression with zstd algorithm
 
   --security_patch_level
       Override the security patch level in target files
@@ -353,7 +346,6 @@ AB_PARTITIONS = 'META/ab_partitions.txt'
 TARGET_DIFFING_UNZIP_PATTERN = ['BOOT', 'RECOVERY', 'SYSTEM/*', 'VENDOR/*',
                                 'PRODUCT/*', 'SYSTEM_EXT/*', 'ODM/*',
                                 'VENDOR_DLKM/*', 'ODM_DLKM/*', 'SYSTEM_DLKM/*']
-RETROFIT_DAP_UNZIP_PATTERN = ['OTA/super_*.img', AB_PARTITIONS]
 
 # Images to be excluded from secondary payload. We essentially only keep
 # 'system_other' and bootloader partitions.
@@ -480,7 +472,7 @@ def GetTargetFilesZipForSecondaryImages(input_file, skip_postinstall=False):
       content = f.read()
     # Remove virtual_ab flag from secondary payload so that OTA client
     # don't use snapshots for secondary update
-    delete_keys = ['virtual_ab', "virtual_ab_retrofit"]
+    delete_keys = ['virtual_ab']
     return UpdatesInfoForSpecialUpdates(
         content, lambda p: p not in SECONDARY_PAYLOAD_SKIPPED_IMAGES,
         delete_keys)
@@ -693,77 +685,6 @@ def GetTargetFilesZipForPartialUpdates(input_file, ab_partitions):
   return input_file
 
 
-def GetTargetFilesZipForRetrofitDynamicPartitions(input_file,
-                                                  super_block_devices,
-                                                  dynamic_partition_list):
-  """Returns a target-files.zip for retrofitting dynamic partitions.
-
-  This allows brillo_update_payload to generate an OTA based on the exact
-  bits on the block devices. Postinstall is disabled.
-
-  Args:
-    input_file: The input target-files.zip filename.
-    super_block_devices: The list of super block devices
-    dynamic_partition_list: The list of dynamic partitions
-
-  Returns:
-    The filename of target-files.zip with *.img replaced with super_*.img for
-    each block device in super_block_devices.
-  """
-  assert super_block_devices, "No super_block_devices are specified."
-
-  replace = {'OTA/super_{}.img'.format(dev): 'IMAGES/{}.img'.format(dev)
-             for dev in super_block_devices}
-
-  # Remove partitions from META/ab_partitions.txt that is in
-  # dynamic_partition_list but not in super_block_devices so that
-  # brillo_update_payload won't generate update for those logical partitions.
-  ab_partitions_lines = common.ReadFromInputFile(
-      input_file, AB_PARTITIONS).split("\n")
-  ab_partitions = [line.strip() for line in ab_partitions_lines]
-  # Assert that all super_block_devices are in ab_partitions
-  super_device_not_updated = [partition for partition in super_block_devices
-                              if partition not in ab_partitions]
-  assert not super_device_not_updated, \
-      "{} is in super_block_devices but not in {}".format(
-          super_device_not_updated, AB_PARTITIONS)
-  # ab_partitions -= (dynamic_partition_list - super_block_devices)
-  to_delete = [AB_PARTITIONS]
-
-  # Always skip postinstall for a retrofit update.
-  to_delete += [POSTINSTALL_CONFIG]
-
-  # Delete dynamic_partitions_info.txt so that brillo_update_payload thinks this
-  # is a regular update on devices without dynamic partitions support.
-  to_delete += [DYNAMIC_PARTITION_INFO]
-
-  # Remove the existing partition images as well as the map files.
-  to_delete += list(replace.values())
-  to_delete += ['IMAGES/{}.map'.format(dev) for dev in super_block_devices]
-  for item in to_delete:
-    os.unlink(os.path.join(input_file, item))
-
-  # Write super_{foo}.img as {foo}.img.
-  for src, dst in replace.items():
-    assert DoesInputFileContain(input_file, src), \
-        'Missing {} in {}; {} cannot be written'.format(src, input_file, dst)
-    source_path = os.path.join(input_file, *src.split("/"))
-    target_path = os.path.join(input_file, *dst.split("/"))
-    os.rename(source_path, target_path)
-
-  # Write new ab_partitions.txt file
-  new_ab_partitions = os.path.join(input_file, AB_PARTITIONS)
-  with open(new_ab_partitions, 'w') as f:
-    for partition in ab_partitions:
-      if (partition in dynamic_partition_list and
-              partition not in super_block_devices):
-        logger.info("Dropping %s from ab_partitions.txt", partition)
-        continue
-      f.write(partition + "\n")
-
-  return input_file
-
-
 def GetTargetFilesZipForCustomImagesUpdates(input_file, custom_images: dict):
   """Returns a target-files.zip for custom partitions update.
 
@@ -817,45 +738,6 @@ def GeneratePartitionTimestampFlagsDowngrade(
   ]
 
 
-def SupportsMainlineGkiUpdates(target_file):
-  """Return True if the build supports MainlineGKIUpdates.
-
-  This function scans the product.img file in IMAGES/ directory for
-  pattern |*/apex/com.android.gki.*.apex|. If there are files
-  matching this pattern, conclude that build supports mainline
-  GKI and return True
-
-  Args:
-    target_file: Path to a target_file.zip, or an extracted directory
-  Return:
-    True if thisb uild supports Mainline GKI Updates.
-  """
-  if target_file is None:
-    return False
-  if os.path.isfile(target_file):
-    target_file = common.UnzipTemp(target_file, ["IMAGES/product.img"])
-  if not os.path.isdir(target_file):
-    assert os.path.isdir(target_file), \
-        "{} must be a path to zip archive or dir containing extracted"\
-        " target_files".format(target_file)
-  image_file = os.path.join(target_file, "IMAGES", "product.img")
-
-  if not os.path.isfile(image_file):
-    return False
-
-  if IsSparseImage(image_file):
-    # Unsparse the image
-    tmp_img = common.MakeTempFile(suffix=".img")
-    subprocess.check_output(["simg2img", image_file, tmp_img])
-    image_file = tmp_img
-
-  cmd = ["debugfs_static", "-R", "ls -p /apex", image_file]
-  output = subprocess.check_output(cmd).decode()
-
-  pattern = re.compile(r"com\.android\.gki\..*\.apex")
-  return pattern.search(output) is not None
-
-
 def ExtractOrCopyTargetFiles(target_file):
   if os.path.isdir(target_file):
     return CopyTargetFilesDir(target_file)
@@ -1045,11 +927,7 @@ def GenerateAbOtaPackage(target_file, output_file, source_file=None):
     target_file = GetTargetFilesZipForCustomImagesUpdates(
         target_file, OPTIONS.custom_images)
 
-  if OPTIONS.retrofit_dynamic_partitions:
-    target_file = GetTargetFilesZipForRetrofitDynamicPartitions(
-        target_file, target_info.get("super_block_devices").strip().split(),
-        target_info.get("dynamic_partition_list").strip().split())
-  elif OPTIONS.partial:
+  if OPTIONS.partial:
     target_file = GetTargetFilesZipForPartialUpdates(target_file,
                                                      OPTIONS.partial)
   if vabc_compression_param != target_info.vabc_compression_param:
@@ -1266,7 +1144,7 @@ def main(argv):
     elif o == "--skip_postinstall":
       OPTIONS.skip_postinstall = True
     elif o == "--retrofit_dynamic_partitions":
-      OPTIONS.retrofit_dynamic_partitions = True
+      raise ValueError("Retrofit dynamic partitions is no longer supported")
     elif o == "--skip_compatibility_check":
       OPTIONS.skip_compatibility_check = True
     elif o == "--output_metadata_path":
@@ -1372,7 +1250,6 @@ def main(argv):
                                  "log_diff=",
                                  "extracted_input_target_files=",
                                  "skip_postinstall",
-                                 "retrofit_dynamic_partitions",
                                  "skip_compatibility_check",
                                  "output_metadata_path=",
                                  "disable_fec_computation",
@@ -1429,7 +1306,7 @@ def main(argv):
   if OPTIONS.incremental_source is None and OPTIONS.downgrade:
     raise ValueError("Cannot generate downgradable full OTAs")
 
-  # TODO(xunchang) for retrofit and partial updates, maybe we should rebuild the
+  # TODO(xunchang) for partial updates, maybe we should rebuild the
   # target-file and reload the info_dict. So the info will be consistent with
   # the modified target-file.
 
@@ -1459,22 +1336,12 @@ def main(argv):
   # Load OEM dicts if provided.
   OPTIONS.oem_dicts = _LoadOemDicts(OPTIONS.oem_source)
 
-  # Assume retrofitting dynamic partitions when base build does not set
-  # use_dynamic_partitions but target build does.
   if (OPTIONS.source_info_dict and
       OPTIONS.source_info_dict.get("use_dynamic_partitions") != "true" and
           OPTIONS.target_info_dict.get("use_dynamic_partitions") == "true"):
-    if OPTIONS.target_info_dict.get("dynamic_partition_retrofit") != "true":
-      raise common.ExternalError(
-          "Expect to generate incremental OTA for retrofitting dynamic "
-          "partitions, but dynamic_partition_retrofit is not set in target "
-          "build.")
-    logger.info("Implicitly generating retrofit incremental OTA.")
-    OPTIONS.retrofit_dynamic_partitions = True
-
-  # Skip postinstall for retrofitting dynamic partitions.
-  if OPTIONS.retrofit_dynamic_partitions:
-    OPTIONS.skip_postinstall = True
+    logger.error("Retrofitting dynamic partitions is no longer supported.")
+    raise common.ExternalError(
+        "Both source and target builds must have dynamic partition support")
 
   ab_update = OPTIONS.info_dict.get("ab_update") == "true"
   allow_non_ab = OPTIONS.info_dict.get("allow_non_ab") == "true"
diff --git a/tools/releasetools/ota_metadata.proto b/tools/releasetools/ota_metadata.proto
index 689ce807b9..7c6d4a4a84 100644
--- a/tools/releasetools/ota_metadata.proto
+++ b/tools/releasetools/ota_metadata.proto
@@ -104,9 +104,10 @@ message OtaMetadata {
   // The expected device state after the update.
   DeviceState postcondition = 6;
 
-  // True if the ota that updates a device to support dynamic partitions, where
-  // the source build doesn't support it.
-  bool retrofit_dynamic_partitions = 7;
+  // This was previously a boolean flag called retrofit_dynamic_partitions, but
+  // is no longer used or supported.
+  reserved 7;
+
   // The required size of the cache partition, only valid for non-A/B update.
   int64 required_cache = 8;
 
diff --git a/tools/releasetools/ota_utils.py b/tools/releasetools/ota_utils.py
index 852d62bb0f..847a2a519a 100644
--- a/tools/releasetools/ota_utils.py
+++ b/tools/releasetools/ota_utils.py
@@ -39,7 +39,6 @@ OPTIONS.wipe_user_data = False
 OPTIONS.downgrade = False
 OPTIONS.key_passwords = {}
 OPTIONS.incremental_source = None
-OPTIONS.retrofit_dynamic_partitions = False
 OPTIONS.output_metadata_path = None
 OPTIONS.boot_variable_file = None
 
@@ -296,9 +295,6 @@ def GetPackageMetadata(target_info, source_info=None):
   if OPTIONS.wipe_user_data:
     metadata_proto.wipe = True
 
-  if OPTIONS.retrofit_dynamic_partitions:
-    metadata_proto.retrofit_dynamic_partitions = True
-
   is_incremental = source_info is not None
   if is_incremental:
     UpdateDeviceState(metadata_proto.precondition, source_info,
@@ -332,8 +328,6 @@ def BuildLegacyOtaMetadata(metadata_proto):
     metadata_dict['ota-type'] = 'BLOCK'
   if metadata_proto.wipe:
     metadata_dict['ota-wipe'] = 'yes'
-  if metadata_proto.retrofit_dynamic_partitions:
-    metadata_dict['ota-retrofit-dynamic-partitions'] = 'yes'
   if metadata_proto.downgrade:
     metadata_dict['ota-downgrade'] = 'yes'
 
diff --git a/tools/releasetools/test_check_partition_sizes.py b/tools/releasetools/test_check_partition_sizes.py
index 88cf60f6da..4e0add0a15 100644
--- a/tools/releasetools/test_check_partition_sizes.py
+++ b/tools/releasetools/test_check_partition_sizes.py
@@ -54,16 +54,6 @@ class CheckPartitionSizesTest(test_utils.ReleaseToolsTestCase):
     with self.assertRaises(RuntimeError):
       CheckPartitionSizes(self.info_dict)
 
-  def test_retrofit_dap(self):
-    self.info_dict.update(common.LoadDictionaryFromLines("""
-        dynamic_partition_retrofit=true
-        super_block_devices=system vendor
-        super_system_device_size=75
-        super_vendor_device_size=25
-        super_partition_size=100
-        """.split("\n")))
-    CheckPartitionSizes(self.info_dict)
-
   def test_ab_partition_too_big(self):
     self.info_dict.update(common.LoadDictionaryFromLines("""
         system_image_size=100
@@ -83,33 +73,6 @@ class CheckPartitionSizesTest(test_utils.ReleaseToolsTestCase):
     with self.assertRaises(KeyError):
       CheckPartitionSizes(self.info_dict)
 
-  def test_block_devices_not_match(self):
-    self.info_dict.update(common.LoadDictionaryFromLines("""
-        dynamic_partition_retrofit=true
-        super_block_devices=system vendor
-        super_system_device_size=80
-        super_vendor_device_size=25
-        super_partition_size=100
-        """.split("\n")))
-    with self.assertRaises(RuntimeError):
-      CheckPartitionSizes(self.info_dict)
-
-  def test_retrofit_vab(self):
-    self.info_dict.update(common.LoadDictionaryFromLines("""
-        virtual_ab=true
-        virtual_ab_retrofit=true
-        """.split("\n")))
-    CheckPartitionSizes(self.info_dict)
-
-  def test_retrofit_vab_too_big(self):
-    self.info_dict.update(common.LoadDictionaryFromLines("""
-        virtual_ab=true
-        virtual_ab_retrofit=true
-        system_image_size=100
-        """.split("\n")))
-    with self.assertRaises(RuntimeError):
-      CheckPartitionSizes(self.info_dict)
-
   def test_vab(self):
     self.info_dict.update(common.LoadDictionaryFromLines("""
         virtual_ab=true
diff --git a/tools/releasetools/test_ota_from_target_files.py b/tools/releasetools/test_ota_from_target_files.py
index b6fcb1841e..b1a575defa 100644
--- a/tools/releasetools/test_ota_from_target_files.py
+++ b/tools/releasetools/test_ota_from_target_files.py
@@ -184,7 +184,6 @@ class OtaFromTargetFilesTest(test_utils.ReleaseToolsTestCase):
     # Reset the global options as in ota_from_target_files.py.
     common.OPTIONS.incremental_source = None
     common.OPTIONS.downgrade = False
-    common.OPTIONS.retrofit_dynamic_partitions = False
     common.OPTIONS.timestamp = False
     common.OPTIONS.wipe_user_data = False
     common.OPTIONS.no_signing = False
@@ -340,24 +339,6 @@ class OtaFromTargetFilesTest(test_utils.ReleaseToolsTestCase):
     self.assertEqual(1000, info_list[0].version)
     self.assertEqual(1000, info_list[0].source_version)
 
-  def test_GetPackageMetadata_retrofitDynamicPartitions(self):
-    target_info = common.BuildInfo(self.TEST_TARGET_INFO_DICT, None)
-    common.OPTIONS.retrofit_dynamic_partitions = True
-    metadata = self.GetLegacyOtaMetadata(target_info)
-    self.assertDictEqual(
-        {
-            'ota-retrofit-dynamic-partitions': 'yes',
-            'ota-type': 'BLOCK',
-            'ota-required-cache': '0',
-            'post-build': 'build-fingerprint-target',
-            'post-build-incremental': 'build-version-incremental-target',
-            'post-sdk-level': '27',
-            'post-security-patch-level': '2017-12-01',
-            'post-timestamp': '1500000000',
-            'pre-device': 'product-device',
-        },
-        metadata)
-
   @staticmethod
   def _test_GetPackageMetadata_swapBuildTimestamps(target_info, source_info):
     (target_info['build.prop'].build_props['ro.build.date.utc'],
@@ -1665,9 +1646,6 @@ class RuntimeFingerprintTest(test_utils.ReleaseToolsTestCase):
                      metadata_dict.get('ota-wipe') == 'yes')
     self.assertEqual(metadata_proto.required_cache,
                      int(metadata_dict.get('ota-required-cache', 0)))
-    self.assertEqual(metadata_proto.retrofit_dynamic_partitions,
-                     metadata_dict.get(
-                         'ota-retrofit-dynamic-partitions') == 'yes')
 
   def test_GetPackageMetadata_incremental_package(self):
     vendor_build_prop = copy.deepcopy(self.VENDOR_BUILD_PROP)
diff --git a/tools/sbom/gen_sbom.py b/tools/sbom/gen_sbom.py
index e875ddb6a7..f9be0a540b 100644
--- a/tools/sbom/gen_sbom.py
+++ b/tools/sbom/gen_sbom.py
@@ -36,6 +36,7 @@ import queue
 import metadata_file_pb2
 import sbom_data
 import sbom_writers
+import sys
 
 # Package type
 PKG_SOURCE = 'SOURCE'
@@ -570,6 +571,25 @@ def get_all_transitive_static_dep_files_of_installed_files(installed_files_metad
 
   return sorted(all_static_dep_files.keys())
 
+def get_license_of_product_copy_file(file_path):
+  # Provides license info for known AOSP files used in PRODUCT_COPY_FILES.
+  paths = {
+      'device/sample/etc/',
+      'frameworks/av/media/libeffects/data/',
+      'frameworks/av/media/libstagefright/data/',
+      'frameworks/av/services/audiopolicy/config/',
+      'frameworks/base/config/',
+      'frameworks/base/data/keyboards/',
+      'frameworks/base/data/sounds/',
+      'frameworks/native/data/etc/',
+      'hardware/google/camera/devices/EmulatedCamera/hwl/configs/',
+      'system/core/rootdir/etc/',
+  }
+  for p in paths:
+    if file_path.startswith(p):
+      return 'build/soong/licenses/LICENSE'
+
+  return ''
 
 def main():
   global args
@@ -674,6 +694,8 @@ def main():
       doc.add_relationship(sbom_data.Relationship(id1=file_id,
                                                   relationship=sbom_data.RelationshipType.GENERATED_FROM,
                                                   id2=sbom_data.SPDXID_PLATFORM))
+      if not installed_file_metadata['license_text']:
+        installed_file_metadata['license_text'] = get_license_of_product_copy_file(src_path)
       if installed_file_metadata['license_text']:
         if installed_file_metadata['license_text'] == 'build/soong/licenses/LICENSE':
           f.concluded_license_ids = [sbom_data.SPDXID_LICENSE_APACHE]
```

