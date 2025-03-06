```diff
diff --git a/.ci/.gitlab-ci-checkcommit.sh b/.ci/.gitlab-ci-checkcommit.sh
index f854999..3f597c3 100755
--- a/.ci/.gitlab-ci-checkcommit.sh
+++ b/.ci/.gitlab-ci-checkcommit.sh
@@ -36,13 +36,13 @@ findtag() {
 }
 
 check_tool_installed bpfmt
-check_tool_installed clang-format-diff-15
+check_tool_installed clang-format-diff-19
 
 git fetch https://gitlab.freedesktop.org/drm-hwcomposer/drm-hwcomposer.git
 
 git log --pretty='%h' FETCH_HEAD..HEAD | while read h; do
 	subject=$(git show -s --pretty='%s' "$h")
-	if [[ $subject != drm_hwcomposer:* ]]; then
+	if [[ $subject != drm_hwcomposer:* ]] && [[ $subject != Revert* ]]; then
 		echoerr "Invalid subject prefix: $subject"
 		exit 1
 	fi
@@ -61,7 +61,7 @@ git log --pretty='%h' FETCH_HEAD..HEAD | while read h; do
 		exit 1
 	fi
 
-	git show "$h" -- | clang-format-diff-15 -p 1 -style=file > /tmp/format-fixup.patch
+	git show "$h" -- | clang-format-diff-19 -p 1 -style=file > /tmp/format-fixup.patch
 	if [ -s  /tmp/format-fixup.patch ]; then
 		cat /tmp/format-fixup.patch >&2
 		exit 1
diff --git a/.ci/Dockerfile b/.ci/Dockerfile
index c42c8b6..9dfe3d3 100644
--- a/.ci/Dockerfile
+++ b/.ci/Dockerfile
@@ -1,4 +1,4 @@
-FROM ubuntu:23.04
+FROM ubuntu:24.10
 
 ENV DEBIAN_FRONTEND=noninteractive
 
@@ -6,7 +6,7 @@ ENV PATH="/home/user/bin:${PATH}"
 
 # Taking into account layer structure, everything should be done within one layer.
 RUN apt-get update && apt-get upgrade -y && \
-    apt-get install -y clang-15 clang-tidy-15 clang-format-15 git libdrm-dev blueprint-tools libgtest-dev clang \
+    apt-get install -y clang-19 clang-tidy-19 clang-format-19 git libdrm-dev blueprint-tools libgtest-dev clang \
     llvm make python3 wget sudo rsync lld pkg-config ninja-build meson \
     python3-mako python3-jinja2 python3-ply python3-yaml
 
@@ -41,10 +41,10 @@ RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> \
 USER ${RUN_USER}
 
 # Install aospless package (produced by GloDroid/aospext)
-RUN wget -P ${USER_HOME} https://gitlab.freedesktop.org/-/project/5/uploads/d66764aa71f9f1235b92d44a652cd3c3/aospless_drm_hwcomposer_arm64.tar.xz && \
+RUN wget -P ${USER_HOME} https://gitlab.freedesktop.org/-/project/5/uploads/70643bd1c4d419015b9930b7aadc9cfd/aospless_drm_hwcomposer_arm64.tar.xz && \
     cd ${USER_HOME} && \
     sha256sum aospless_drm_hwcomposer_arm64.tar.xz && \
-    (echo 00ff288f184111dd35143c462e82fd5f8f31a1417d5eb9a11e8798695abcc141 aospless_drm_hwcomposer_arm64.tar.xz | sha256sum --check) && \
+    (echo 640e0d0e04761c804db69f880e0c0957699babdbe82c72c507177b860d878569 aospless_drm_hwcomposer_arm64.tar.xz | sha256sum --check) && \
     tar xf aospless_drm_hwcomposer_arm64.tar.xz && ln -s ../drm_hwcomposer/ ${USER_HOME}/aospless/src
 
 # Create project path
diff --git a/.ci/Makefile b/.ci/Makefile
index 325e0b5..051a437 100644
--- a/.ci/Makefile
+++ b/.ci/Makefile
@@ -1,18 +1,18 @@
 
-BASE_DIR ?=../aospless
+BASE_DIR:=../aospless
 
 SYSTEM_INCLUDE_DIRS := /usr/include/libdrm
 
-CLANG := clang++-15
-CLANG_TIDY := clang-tidy-15
+CLANG := clang++-19
+CLANG_TIDY := clang-tidy-19
 OUT_DIR := /tmp/drm_hwcomposer/build
 SRC_DIR := .
 
-CXXFLAGS := -Wall -Wextra -Werror
+CXXFLAGS := -Wall -Wextra -Werror -Wno-missing-designated-field-initializers
 CXXFLAGS += -D_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS
 CXXFLAGS += -fvisibility-inlines-hidden -std=gnu++17 -DHWC2_USE_CPP11 -DHWC2_INCLUDE_STRINGIFICATION -fno-rtti
 
-CXXARGS := $(shell cat $(BASE_DIR)/build_flags/sharedlib.cppflags)
+CXXARGS := $(shell cat $(BASE_DIR)/toolchain_wrapper/sharedlib.cppflags)
 CXXARGS := $(subst [BASE_DIR],$(BASE_DIR),$(CXXARGS))
 # clang-tidy doesn't like -mcpu=xxx flag
 CXXARGS := $(patsubst -mcpu=%,,$(CXXARGS))
@@ -45,6 +45,24 @@ TIDY_CHECKS_FINE := *                                   \
     -hicpp-signed-bitwise                               \
     -misc-const-correctness                             \
     -readability-identifier-length                      \
+    -misc-include-cleaner                               \
+    -performance-enum-size                              \
+    -misc-use-anonymous-namespace                       \
+    -boost-use-ranges                                   \
+    -cppcoreguidelines-avoid-do-while                   \
+    -modernize-min-max-use-initializer-list             \
+    -cppcoreguidelines-owning-memory                    \
+    -readability-redundant-member-init                  \
+    -cppcoreguidelines-avoid-const-or-ref-data-members  \
+    -cert-err33-c                                       \
+    -readability-math-missing-parentheses               \
+    -readability-avoid-unconditional-preprocessor-if    \
+    -modernize-type-traits                              \
+    -clang-analyzer-optin.core.EnumCastOutOfRange       \
+    -performance-inefficient-vector-operation           \
+    -readability-static-accessed-through-instance       \
+    -misc-use-internal-linkage                          \
+    -performance-avoid-endl                             \
 
 TIDY_CHECKS_NORMAL :=                                   \
     $(TIDY_CHECKS_FINE)                                 \
diff --git a/.clang-format b/.clang-format
index 984fa5e..caadedf 100644
--- a/.clang-format
+++ b/.clang-format
@@ -3,5 +3,6 @@ AllowAllParametersOfDeclarationOnNextLine: false
 AllowShortIfStatementsOnASingleLine: false
 AllowShortLoopsOnASingleLine: false
 AllowShortFunctionsOnASingleLine: None
+IncludeBlocks: Preserve
 PenaltyBreakAssignment: 10000000
 PenaltyBreakBeforeFirstCallParameter: 1000
diff --git a/.gitignore b/.gitignore
new file mode 100644
index 0000000..f58f7a3
--- /dev/null
+++ b/.gitignore
@@ -0,0 +1,3 @@
+.out/
+.vscode/
+.idea/
diff --git a/.gitlab-ci.yml b/.gitlab-ci.yml
index da052c3..b045da8 100644
--- a/.gitlab-ci.yml
+++ b/.gitlab-ci.yml
@@ -1,3 +1,5 @@
+image: ubuntu:24.10
+
 workflow:
   rules:
     - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
@@ -5,38 +7,31 @@ workflow:
 
 variables:
   DEBIAN_FRONTEND: noninteractive
-  DOCKER_IMAGE_TAG: $CI_REGISTRY_IMAGE:latest
+
+before_script:
+  - apt-get --quiet update --yes >/dev/null
+  - apt-get --quiet install --yes clang-19 clang-tidy-19 clang-format-19 git libdrm-dev blueprint-tools libgtest-dev make >/dev/null
+  - apt-get --quiet install --yes clang llvm make python3 wget sudo rsync lld pkg-config ninja-build meson >/dev/null
+  - apt-get --quiet install --yes python3-mako python3-jinja2 python3-ply python3-yaml >/dev/null
 
 stages:
-  - build-container
   - build
   - tidy
   - style
 
-build-container:
-  stage: build-container
-  image: docker:27.0.3
-  services:
-    - docker:27.0.3-dind
-  variables:
-    DOCKER_TLS_CERTDIR: ""
-  before_script:
-    - echo "$CI_JOB_TOKEN" | docker login $CI_REGISTRY -u $CI_REGISTRY_USER --password-stdin
-  script:
-    - docker build -t $DOCKER_IMAGE_TAG -f .ci/Dockerfile .
-    - docker push $DOCKER_IMAGE_TAG
-  after_script:
-    - docker logout
-
 build:
   stage: build
-  image: $DOCKER_IMAGE_TAG
   script:
     - mkdir -p install/arm64
-    - rm ${HOME}/aospless/src
-    - ln -s ${PWD} ${HOME}/aospless/src
-    - make -C ${HOME}/aospless all
-    - cp -r ${HOME}/aospless/install/* install/arm64
+    - cd ..
+    - rm -f aospless_drm_hwcomposer_arm64.tar.xz
+    - rm -rf aospless/*
+    - wget https://gitlab.freedesktop.org/-/project/5/uploads/70643bd1c4d419015b9930b7aadc9cfd/aospless_drm_hwcomposer_arm64.tar.xz
+    - tar xf aospless_drm_hwcomposer_arm64.tar.xz
+    - rm -rf aospless/src
+    - ln -s ../drm-hwcomposer/ aospless/src
+    - make -C ./aospless install
+    - cp -r aospless/install/* drm-hwcomposer/install/arm64
 
   artifacts:
     paths:
@@ -45,16 +40,17 @@ build:
 
 tidy:
   stage: tidy
-  image: $DOCKER_IMAGE_TAG
   script:
-    - rm ${HOME}/aospless/src
-    - ln -s ${PWD} ${HOME}/aospless/src
-    - BASE_DIR=${HOME}/aospless make -j$(nproc) -k -f .ci/Makefile
-  timeout: 2h
+    - cd ..
+    - rm -f aospless_drm_hwcomposer_arm64.tar.xz
+    - rm -rf aospless/*
+    - wget https://gitlab.freedesktop.org/-/project/5/uploads/70643bd1c4d419015b9930b7aadc9cfd/aospless_drm_hwcomposer_arm64.tar.xz
+    - tar xf aospless_drm_hwcomposer_arm64.tar.xz
+    - cd -
+    - make -j$(nproc) -k -f .ci/Makefile
 
 checkstyle:
   stage: style
-  image: $DOCKER_IMAGE_TAG
   script: "./.ci/.gitlab-ci-checkcommit.sh"
   artifacts:
     when: on_failure
diff --git a/Android.bp b/Android.bp
index 7d014dc..24d4d99 100644
--- a/Android.bp
+++ b/Android.bp
@@ -72,6 +72,8 @@ cc_defaults {
         "-DHWC2_USE_CPP11",
     ],
 
+    cpp_std: "gnu++17",
+
     relative_install_path: "hw",
     vendor: true,
 }
@@ -97,13 +99,13 @@ filegroup {
         "drm/DrmDisplayPipeline.cpp",
         "drm/DrmEncoder.cpp",
         "drm/DrmFbImporter.cpp",
+        "drm/DrmHwc.cpp",
         "drm/DrmMode.cpp",
         "drm/DrmPlane.cpp",
         "drm/DrmProperty.cpp",
         "drm/ResourceManager.cpp",
         "drm/UEventListener.cpp",
         "drm/VSyncWorker.cpp",
-        "drm/DrmHwc.cpp",
 
         "backend/Backend.cpp",
         "backend/BackendClient.cpp",
@@ -116,6 +118,7 @@ filegroup {
         "hwc2_device/hwc2_device.cpp",
 
         "utils/fd.cpp",
+        "utils/properties.cpp",
     ],
 }
 
@@ -181,9 +184,9 @@ cc_binary {
     name: "android.hardware.composer.hwc3-service.drm",
 
     srcs: [
+        ":drm_hwcomposer_common",
         ":drm_hwcomposer_hwc3",
         ":drm_hwcomposer_service",
-        ":drm_hwcomposer_common",
         "bufferinfo/legacy/BufferInfoLibdrm.cpp",
     ],
 
@@ -192,9 +195,8 @@ cc_binary {
     ],
 
     shared_libs: [
-        "android.hardware.graphics.composer3-V3-ndk",
+        "android.hardware.graphics.composer3-V4-ndk",
         "libbase",
-        "libbinder",
         "libbinder_ndk",
         "liblog",
         "libutils",
@@ -242,3 +244,60 @@ filegroup {
     name: "drm_hwcomposer_platformmediatek",
     srcs: ["bufferinfo/legacy/BufferInfoMaliMediatek.cpp"],
 }
+
+prebuilt_etc {
+    name: "drm_hwcomposer_hwc3_apex_vintf",
+    src: "hwc3/hwc3-drm.xml",
+    sub_dir: "vintf",
+    vendor: true,
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "drm_hwcomposer_hwc3_apex_init_rc",
+    filename_from_src: true,
+    vendor: true,
+    src: ":gen-drm_hwcomposer_hwc3_apex_init_rc",
+}
+
+genrule {
+    name: "gen-drm_hwcomposer_hwc3_apex_init_rc",
+    srcs: ["hwc3/hwc3-drm.rc"],
+    out: ["hwc3-drm.apex.rc"],
+    cmd: "sed " +
+        // Update the binary location to inside the Apex:
+        "-e 's%/vendor/bin/%/apex/com.android.hardware.graphics.composer/bin/%' " +
+        "$(in) > $(out)",
+}
+
+filegroup {
+    name: "drm_hwcomposer_hwc3_apex_file_contexts",
+    srcs: [
+        "hwc3/hwc3-apex-file-contexts",
+    ],
+}
+
+filegroup {
+    name: "drm_hwcomposer_hwc3_apex_manifest",
+    srcs: [
+        "hwc3/hwc3-apex-manifest.json",
+    ],
+}
+
+apex {
+    name: "com.android.hardware.graphics.composer.drm_hwcomposer",
+    key: "com.android.hardware.key",
+    certificate: ":com.android.hardware.certificate",
+    file_contexts: ":drm_hwcomposer_hwc3_apex_file_contexts",
+    manifest: ":drm_hwcomposer_hwc3_apex_manifest",
+    vendor: true,
+    updatable: false,
+    soc_specific: true,
+    binaries: [
+        "android.hardware.composer.hwc3-service.drm",
+    ],
+    prebuilts: [
+        "drm_hwcomposer_hwc3_apex_init_rc",
+        "drm_hwcomposer_hwc3_apex_vintf",
+    ],
+}
diff --git a/Makefile b/Makefile
index 8a88083..aa8062b 100644
--- a/Makefile
+++ b/Makefile
@@ -51,7 +51,7 @@ ci: ## Run presubmit within the docker container
 	@echo "Run native build:"
 	$(DOCKER_BIN) exec -it $(IMAGE_NAME) bash -c "make -f .ci/Makefile -j$(NPROCS)"
 	@echo "Run meson cross-build for Android:"
-	$(DOCKER_BIN) exec -it $(IMAGE_NAME) bash -c "make -C ~/aospless all"
+	$(DOCKER_BIN) exec -it $(IMAGE_NAME) bash -c "make -C ~/aospless install"
 	@echo "Run style check:"
 	$(if $(GIT_IS_SYMLINK), \
 		./.ci/.gitlab-ci-checkcommit.sh, \
@@ -59,7 +59,7 @@ ci: ## Run presubmit within the docker container
 	@echo "\n\e[32m --- SUCCESS ---\n"
 
 ci_cleanup: ## Cleanup after 'make ci'
-	$(DOCKER_BIN) exec -it $(IMAGE_NAME) bash -c "make -f .ci/Makefile clean	"
+	$(DOCKER_BIN) exec -it $(IMAGE_NAME) bash -c "make -f .ci/Makefile clean"
 	$(DOCKER_BIN) exec -it $(IMAGE_NAME) bash -c "rm -rf ~/aospless/build"
 	$(DOCKER_BIN) exec -it $(IMAGE_NAME) bash -c "rm -rf ~/aospless/install"
 	$(DOCKER_BIN) exec -it $(IMAGE_NAME) bash -c "rm -rf ~/aospless/out_src"
@@ -69,14 +69,11 @@ build_deploy: ## Build for Andoid and deploy onto the target device (require act
 	$(if $(filter $(shell adb shell getprop ro.bionic.arch),arm64),,$(error arm64 only is supported at the moment))
 	adb root && adb remount vendor
 	mkdir -p .out/arm64
-	$(DOCKER_BIN) exec -it $(IMAGE_NAME) bash -c "make -C ~/aospless all"
+	$(DOCKER_BIN) exec -it $(IMAGE_NAME) bash -c "make -C ~/aospless install"
 	$(DOCKER_BIN) exec -it $(IMAGE_NAME) bash -c "cp -r ~/aospless/install/* ~/drm_hwcomposer/.out/arm64"
-	adb push .out/arm64/vendor/lib64/hw/hwcomposer.drm.so /vendor/lib64/hw/hwcomposer.drm.so
+	adb push .out/arm64/vendor/bin/hw/android.hardware.composer.hwc3-service.drm /vendor/bin/hw/android.hardware.composer.hwc3-service.drm
 	adb shell stop
-	adb shell stop vendor.hwcomposer-2-1 && adb shell start vendor.hwcomposer-2-1 || true
-	adb shell stop vendor.hwcomposer-2-2 && adb shell start vendor.hwcomposer-2-2 || true
-	adb shell stop vendor.hwcomposer-2-3 && adb shell start vendor.hwcomposer-2-3 || true
-	adb shell stop vendor.hwcomposer-2-4 && adb shell start vendor.hwcomposer-2-4 || true
+	adb shell stop vendor.hwcomposer-3 && adb shell start vendor.hwcomposer-3 || true
 	bash -c '[[ "$$HWCLOG" -eq "1" ]] && adb logcat -c || true'
 	adb shell start
 	bash -c '[[ "$$HWCLOG" -eq "1" ]] && adb logcat | grep -i hwc || true'
diff --git a/OWNERS b/OWNERS
index 39f2084..a4f788d 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,4 @@
 adelva@google.com
+ddavenport@google.com
 jstultz@google.com
-marcheu@google.com
 seanpaul@google.com
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
new file mode 100644
index 0000000..1f413f7
--- /dev/null
+++ b/PREUPLOAD.cfg
@@ -0,0 +1,3 @@
+[Hook Scripts]
+
+check hooks installed = hooks/check-hooks-installed
\ No newline at end of file
diff --git a/README.md b/README.md
index 5724b36..76cfd6c 100644
--- a/README.md
+++ b/README.md
@@ -16,7 +16,7 @@ A short list of contribution guidelines:
   you with formatting of your patches:
 
     ```
-    git diff | clang-format-diff-15 -p 1 -style=file
+    git diff | clang-format-diff-19 -p 1 -style=file
     ```
 
 * Hardware specific changes should be tested on relevant platforms before
diff --git a/compositor/DisplayInfo.h b/compositor/DisplayInfo.h
new file mode 100644
index 0000000..6ddc66f
--- /dev/null
+++ b/compositor/DisplayInfo.h
@@ -0,0 +1,57 @@
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
+#include <cstdint>
+
+enum class Colorspace : int32_t {
+  kDefault,
+  kSmpte170MYcc,
+  kBt709Ycc,
+  kXvycc601,
+  kXvycc709,
+  kSycc601,
+  kOpycc601,
+  kOprgb,
+  kBt2020Cycc,
+  kBt2020Rgb,
+  kBt2020Ycc,
+  kDciP3RgbD65,
+  kDciP3RgbTheater,
+  kRgbWideFixed,
+  kRgbWideFloat,
+  kBt601Ycc,
+};
+
+/**
+ * Display panel orientation property values.
+ */
+enum PanelOrientation {
+  kModePanelOrientationNormal = 0,
+  kModePanelOrientationBottomUp,
+  kModePanelOrientationLeftUp,
+  kModePanelOrientationRightUp
+};
+
+struct QueuedConfigTiming {
+  // In order for the new config to be applied, the client must send a new frame
+  // at this time.
+  int64_t refresh_time_ns;
+
+  // The time when the display will start to refresh at the new vsync period.
+  int64_t new_vsync_time_ns;
+};
diff --git a/drm/DrmAtomicStateManager.cpp b/drm/DrmAtomicStateManager.cpp
index 537f819..9a8769a 100644
--- a/drm/DrmAtomicStateManager.cpp
+++ b/drm/DrmAtomicStateManager.cpp
@@ -101,7 +101,7 @@ auto DrmAtomicStateManager::CommitFrame(AtomicCommitArgs &args) -> int {
     }
   }
 
-  bool nonblock = true;
+  bool nonblock = !args.blocking;
 
   if (args.active) {
     nonblock = false;
@@ -139,6 +139,17 @@ auto DrmAtomicStateManager::CommitFrame(AtomicCommitArgs &args) -> int {
       return -EINVAL;
   }
 
+  if (args.colorspace && connector->GetColorspaceProperty()) {
+    if (!connector->GetColorspaceProperty()
+             .AtomicSet(*pset, connector->GetColorspacePropertyValue(*args.colorspace)))
+      return -EINVAL;
+  }
+
+  if (args.content_type && connector->GetContentTypeProperty()) {
+    if (!connector->GetContentTypeProperty().AtomicSet(*pset, *args.content_type))
+      return -EINVAL;
+  }
+
   auto unused_planes = new_frame_state.used_planes;
 
   if (args.composition) {
diff --git a/drm/DrmAtomicStateManager.h b/drm/DrmAtomicStateManager.h
index 923927d..8d22b99 100644
--- a/drm/DrmAtomicStateManager.h
+++ b/drm/DrmAtomicStateManager.h
@@ -21,6 +21,7 @@
 #include <memory>
 #include <optional>
 
+#include "compositor/DisplayInfo.h"
 #include "compositor/DrmKmsPlan.h"
 #include "compositor/LayerData.h"
 #include "drm/DrmPlane.h"
@@ -32,10 +33,13 @@ namespace android {
 struct AtomicCommitArgs {
   /* inputs. All fields are optional, but at least one has to be specified */
   bool test_only = false;
+  bool blocking = false;
   std::optional<DrmMode> display_mode;
   std::optional<bool> active;
   std::shared_ptr<DrmKmsPlan> composition;
   std::shared_ptr<drm_color_ctm> color_matrix;
+  std::optional<Colorspace> colorspace;
+  std::optional<int32_t> content_type;
 
   std::shared_ptr<DrmFbIdHandle> writeback_fb;
   SharedFd writeback_release_fence;
diff --git a/drm/DrmConnector.cpp b/drm/DrmConnector.cpp
index e459fe7..eeec3b1 100644
--- a/drm/DrmConnector.cpp
+++ b/drm/DrmConnector.cpp
@@ -14,6 +14,7 @@
  * limitations under the License.
  */
 
+#include <drm/drm_mode.h>
 #define LOG_TAG "drmhwc"
 
 #include "DrmConnector.h"
@@ -22,10 +23,12 @@
 
 #include <array>
 #include <cerrno>
+#include <cinttypes>
 #include <cstdint>
 #include <sstream>
 
 #include "DrmDevice.h"
+#include "compositor/DisplayInfo.h"
 #include "utils/log.h"
 
 #ifndef DRM_MODE_CONNECTOR_SPI
@@ -42,22 +45,21 @@ namespace android {
 
 constexpr size_t kTypesCount = 21;
 
-static bool GetOptionalConnectorProperty(const DrmDevice &dev,
-                                         const DrmConnector &connector,
-                                         const char *prop_name,
-                                         DrmProperty *property) {
-  return dev.GetProperty(connector.GetId(), DRM_MODE_OBJECT_CONNECTOR,
-                         prop_name, property) == 0;
-}
-
-static bool GetConnectorProperty(const DrmDevice &dev,
-                                 const DrmConnector &connector,
-                                 const char *prop_name, DrmProperty *property) {
-  if (!GetOptionalConnectorProperty(dev, connector, prop_name, property)) {
-    ALOGE("Could not get %s property\n", prop_name);
-    return false;
+auto DrmConnector::GetConnectorProperty(const char *prop_name,
+                                        DrmProperty *property,
+                                        bool is_optional) -> bool {
+  auto err = drm_->GetProperty(GetId(), DRM_MODE_OBJECT_CONNECTOR, prop_name,
+                               property);
+  if (err == 0)
+    return true;
+
+  if (is_optional) {
+    ALOGV("Could not get optional %s property from connector %d", prop_name,
+          GetId());
+  } else {
+    ALOGE("Could not get %s property from connector %d", prop_name, GetId());
   }
-  return true;
+  return false;
 }
 
 auto DrmConnector::CreateInstance(DrmDevice &dev, uint32_t connector_id,
@@ -72,28 +74,95 @@ auto DrmConnector::CreateInstance(DrmDevice &dev, uint32_t connector_id,
   auto c = std::unique_ptr<DrmConnector>(
       new DrmConnector(std::move(conn), &dev, index));
 
-  if (!GetConnectorProperty(dev, *c, "DPMS", &c->dpms_property_) ||
-      !GetConnectorProperty(dev, *c, "CRTC_ID", &c->crtc_id_property_)) {
+  if (!c->Init()) {
+    ALOGE("Failed to initialize connector %d", connector_id);
     return {};
   }
 
-  c->UpdateEdidProperty();
+  return c;
+}
 
-  if (c->IsWriteback() &&
-      (!GetConnectorProperty(dev, *c, "WRITEBACK_PIXEL_FORMATS",
-                             &c->writeback_pixel_formats_) ||
-       !GetConnectorProperty(dev, *c, "WRITEBACK_FB_ID",
-                             &c->writeback_fb_id_) ||
-       !GetConnectorProperty(dev, *c, "WRITEBACK_OUT_FENCE_PTR",
-                             &c->writeback_out_fence_))) {
-    return {};
+auto DrmConnector::Init()-> bool {
+  if (!GetConnectorProperty("DPMS", &dpms_property_) ||
+      !GetConnectorProperty("CRTC_ID", &crtc_id_property_)) {
+    return false;
   }
 
-  return c;
+  UpdateEdidProperty();
+
+  if (IsWriteback() &&
+      (!GetConnectorProperty("WRITEBACK_PIXEL_FORMATS",
+                             &writeback_pixel_formats_) ||
+       !GetConnectorProperty("WRITEBACK_FB_ID", &writeback_fb_id_) ||
+       !GetConnectorProperty("WRITEBACK_OUT_FENCE_PTR",
+                             &writeback_out_fence_))) {
+    return false;
+  }
+
+  if (GetConnectorProperty("Colorspace", &colorspace_property_,
+                           /*is_optional=*/true)) {
+    colorspace_property_.AddEnumToMap("Default", Colorspace::kDefault,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("SMPTE_170M_YCC", Colorspace::kSmpte170MYcc,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("BT709_YCC", Colorspace::kBt709Ycc,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("XVYCC_601", Colorspace::kXvycc601,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("XVYCC_709", Colorspace::kXvycc709,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("SYCC_601", Colorspace::kSycc601,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("opYCC_601", Colorspace::kOpycc601,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("opRGB", Colorspace::kOprgb,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("BT2020_CYCC", Colorspace::kBt2020Cycc,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("BT2020_RGB", Colorspace::kBt2020Rgb,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("BT2020_YCC", Colorspace::kBt2020Ycc,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("DCI-P3_RGB_D65", Colorspace::kDciP3RgbD65,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("DCI-P3_RGB_Theater", Colorspace::kDciP3RgbTheater,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("RGB_WIDE_FIXED", Colorspace::kRgbWideFixed,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("RGB_WIDE_FLOAT", Colorspace::kRgbWideFloat,
+                                      colorspace_enum_map_);
+    colorspace_property_.AddEnumToMap("BT601_YCC", Colorspace::kBt601Ycc,
+                                      colorspace_enum_map_);
+  }
+
+  GetConnectorProperty("content type", &content_type_property_,
+                       /*is_optional=*/true);
+
+  if (GetConnectorProperty("panel orientation", &panel_orientation_,
+                           /*is_optional=*/true)) {
+    panel_orientation_
+        .AddEnumToMapReverse("Normal",
+                             PanelOrientation::kModePanelOrientationNormal,
+                             panel_orientation_enum_map_);
+    panel_orientation_
+        .AddEnumToMapReverse("Upside Down",
+                             PanelOrientation::kModePanelOrientationBottomUp,
+                             panel_orientation_enum_map_);
+    panel_orientation_
+        .AddEnumToMapReverse("Left Side Up",
+                             PanelOrientation::kModePanelOrientationLeftUp,
+                             panel_orientation_enum_map_);
+    panel_orientation_
+        .AddEnumToMapReverse("Right Side Up",
+                             PanelOrientation::kModePanelOrientationRightUp,
+                             panel_orientation_enum_map_);
+  }
+
+  return true;
 }
 
 int DrmConnector::UpdateEdidProperty() {
-  return GetOptionalConnectorProperty(*drm_, *this, "EDID", &edid_property_)
+  return GetConnectorProperty("EDID", &edid_property_, /*is_optional=*/true)
              ? 0
              : -EINVAL;
 }
@@ -184,4 +253,36 @@ int DrmConnector::UpdateModes() {
   return 0;
 }
 
+bool DrmConnector::IsLinkStatusGood() {
+  if (GetConnectorProperty("link-status", &link_status_property_, false)) {
+    auto link_status_property_value = link_status_property_.GetValue();
+    if (link_status_property_value &&
+        (link_status_property_value == DRM_MODE_LINK_STATUS_BAD))
+      return false;
+  }
+
+  return true;
+}
+
+std::optional<PanelOrientation> DrmConnector::GetPanelOrientation() {
+  if (!panel_orientation_.GetValue().has_value()) {
+    ALOGW("No panel orientation property available.");
+    return {};
+  }
+
+  /* The value_or(0) satisfies the compiler warning. However,
+   * panel_orientation_.GetValue() is guaranteed to have a value since we check
+   * has_value() and return early otherwise.
+   */
+  uint64_t panel_orientation_value = panel_orientation_.GetValue().value_or(0);
+
+  if (panel_orientation_enum_map_.count(panel_orientation_value) == 1) {
+    return panel_orientation_enum_map_[panel_orientation_value];
+  }
+
+  ALOGE("Unknown panel orientation: panel_orientation = %" PRIu64,
+        panel_orientation_value);
+  return {};
+}
+
 }  // namespace android
diff --git a/drm/DrmConnector.h b/drm/DrmConnector.h
index 018c615..be84ae3 100644
--- a/drm/DrmConnector.h
+++ b/drm/DrmConnector.h
@@ -26,6 +26,7 @@
 #include "DrmMode.h"
 #include "DrmProperty.h"
 #include "DrmUnique.h"
+#include "compositor/DisplayInfo.h"
 
 namespace android {
 
@@ -78,6 +79,8 @@ class DrmConnector : public PipelineBindable<DrmConnector> {
 
   int UpdateModes();
 
+  bool IsLinkStatusGood();
+
   auto &GetModes() const {
     return modes_;
   }
@@ -94,6 +97,18 @@ class DrmConnector : public PipelineBindable<DrmConnector> {
     return edid_property_;
   }
 
+  auto &GetColorspaceProperty() const {
+    return colorspace_property_;
+  }
+
+  auto GetColorspacePropertyValue(Colorspace c) {
+    return colorspace_enum_map_[c];
+  }
+
+  auto &GetContentTypeProperty() const {
+    return content_type_property_;
+  }
+
   auto &GetWritebackFbIdProperty() const {
     return writeback_fb_id_;
   }
@@ -102,6 +117,10 @@ class DrmConnector : public PipelineBindable<DrmConnector> {
     return writeback_out_fence_;
   }
 
+  auto &GetPanelOrientationProperty() const {
+    return panel_orientation_;
+  }
+
   auto IsConnected() const {
     return connector_->connection == DRM_MODE_CONNECTED;
   }
@@ -114,15 +133,21 @@ class DrmConnector : public PipelineBindable<DrmConnector> {
     return connector_->mmHeight;
   };
 
+  auto GetPanelOrientation() -> std::optional<PanelOrientation>;
+
  private:
   DrmConnector(DrmModeConnectorUnique connector, DrmDevice *drm, uint32_t index)
       : connector_(std::move(connector)),
         drm_(drm),
-        index_in_res_array_(index){};
+        index_in_res_array_(index) {};
 
   DrmModeConnectorUnique connector_;
   DrmDevice *const drm_;
 
+  auto Init() -> bool;
+  auto GetConnectorProperty(const char *prop_name, DrmProperty *property,
+                            bool is_optional = false) -> bool;
+
   const uint32_t index_in_res_array_;
 
   std::vector<DrmMode> modes_;
@@ -130,8 +155,16 @@ class DrmConnector : public PipelineBindable<DrmConnector> {
   DrmProperty dpms_property_;
   DrmProperty crtc_id_property_;
   DrmProperty edid_property_;
+  DrmProperty colorspace_property_;
+  DrmProperty content_type_property_;
+
+  DrmProperty link_status_property_;
   DrmProperty writeback_pixel_formats_;
   DrmProperty writeback_fb_id_;
   DrmProperty writeback_out_fence_;
+  DrmProperty panel_orientation_;
+
+  std::map<Colorspace, uint64_t> colorspace_enum_map_;
+  std::map<uint64_t, PanelOrientation> panel_orientation_enum_map_;
 };
 }  // namespace android
diff --git a/drm/DrmHwc.cpp b/drm/DrmHwc.cpp
index df3eb56..aaba506 100644
--- a/drm/DrmHwc.cpp
+++ b/drm/DrmHwc.cpp
@@ -22,6 +22,7 @@
 
 #include "backend/Backend.h"
 #include "utils/log.h"
+#include "utils/properties.h"
 
 namespace android {
 
@@ -124,6 +125,16 @@ bool DrmHwc::UnbindDisplay(std::shared_ptr<DrmDisplayPipeline> pipeline) {
   return true;
 }
 
+void DrmHwc::NotifyDisplayLinkStatus(
+    std::shared_ptr<DrmDisplayPipeline> pipeline) {
+  if (display_handles_.count(pipeline) == 0) {
+    ALOGE("%s, can't find the display, pipeline: %p", __func__, pipeline.get());
+    return;
+  }
+  ScheduleHotplugEvent(display_handles_[pipeline],
+                       DisplayStatus::kLinkTrainingFailed);
+}
+
 HWC2::Error DrmHwc::CreateVirtualDisplay(
     uint32_t width, uint32_t height,
     int32_t *format,  // NOLINT(readability-non-const-parameter)
@@ -186,6 +197,13 @@ void DrmHwc::Dump(uint32_t *out_size, char *out_buffer) {
 }
 
 uint32_t DrmHwc::GetMaxVirtualDisplayCount() {
+  /* Virtual display is an experimental feature.
+   * Unless explicitly set to true, return 0 for no support.
+   */
+  if (0 == property_get_bool("vendor.hwc.drm.enable_virtual_display", 0)) {
+    return 0;
+  }
+
   auto writeback_count = resource_manager_.GetWritebackConnectorsCount();
   writeback_count = std::min(writeback_count, 1U);
   /* Currently, only 1 virtual display is supported. Other cases need testing */
diff --git a/drm/DrmHwc.h b/drm/DrmHwc.h
index 44dc276..ac97717 100644
--- a/drm/DrmHwc.h
+++ b/drm/DrmHwc.h
@@ -16,6 +16,7 @@
 
 #pragma once
 
+#include "drm/DrmDisplayPipeline.h"
 #include "drm/ResourceManager.h"
 #include "hwc2_device/HwcDisplay.h"
 
@@ -26,6 +27,13 @@ class DrmHwc : public PipelineToFrontendBindingInterface {
   DrmHwc();
   ~DrmHwc() override = default;
 
+  // Enum for Display status: Connected, Disconnected, Link Training Failed
+  enum DisplayStatus {
+    kDisconnected,
+    kConnected,
+    kLinkTrainingFailed,
+  };
+
   // Client Callback functions.:
   virtual void SendVsyncEventToClient(hwc2_display_t displayid,
                                       int64_t timestamp,
@@ -34,7 +42,7 @@ class DrmHwc : public PipelineToFrontendBindingInterface {
       hwc2_display_t displayid, int64_t timestamp) const = 0;
   virtual void SendRefreshEventToClient(uint64_t displayid) = 0;
   virtual void SendHotplugEventToClient(hwc2_display_t displayid,
-                                        bool connected) = 0;
+                                        enum DisplayStatus display_status) = 0;
 
   // Device functions
   HWC2::Error CreateVirtualDisplay(uint32_t width, uint32_t height,
@@ -53,8 +61,9 @@ class DrmHwc : public PipelineToFrontendBindingInterface {
     return resource_manager_;
   }
 
-  void ScheduleHotplugEvent(hwc2_display_t displayid, bool connected) {
-    deferred_hotplug_events_[displayid] = connected;
+  void ScheduleHotplugEvent(hwc2_display_t displayid,
+                            enum DisplayStatus display_status) {
+    deferred_hotplug_events_[displayid] = display_status;
   }
 
   void DeinitDisplays();
@@ -64,8 +73,14 @@ class DrmHwc : public PipelineToFrontendBindingInterface {
   bool UnbindDisplay(std::shared_ptr<DrmDisplayPipeline> pipeline) override;
   void FinalizeDisplayBinding() override;
 
+  // Notify Display Link Status
+  void NotifyDisplayLinkStatus(
+      std::shared_ptr<DrmDisplayPipeline> pipeline) override;
+
  protected:
-  auto& Displays() { return displays_; }
+  auto &Displays() {
+    return displays_;
+  }
 
  private:
   ResourceManager resource_manager_;
@@ -75,7 +90,7 @@ class DrmHwc : public PipelineToFrontendBindingInterface {
 
   std::string dump_string_;
 
-  std::map<hwc2_display_t, bool> deferred_hotplug_events_;
+  std::map<hwc2_display_t, enum DisplayStatus> deferred_hotplug_events_;
   std::vector<hwc2_display_t> displays_for_removal_list_;
 
   uint32_t last_display_handle_ = kPrimaryDisplay;
diff --git a/drm/DrmMode.h b/drm/DrmMode.h
index c5790a5..5450daf 100644
--- a/drm/DrmMode.h
+++ b/drm/DrmMode.h
@@ -48,6 +48,12 @@ class DrmMode {
            (float)(mode_.vtotal * mode_.htotal) * 1000.0F;
   }
 
+  auto GetVSyncPeriodNs() const {
+    static const int kNanosecondsPerSecond = 1E9;
+    return static_cast<int32_t>(kNanosecondsPerSecond *
+                                double(1 / GetVRefresh()));
+  }
+
   auto GetName() const {
     return std::string(mode_.name) + "@" + std::to_string(GetVRefresh());
   }
diff --git a/drm/DrmPlane.cpp b/drm/DrmPlane.cpp
index 310e67b..dbb5ad6 100644
--- a/drm/DrmPlane.cpp
+++ b/drm/DrmPlane.cpp
@@ -155,14 +155,11 @@ bool DrmPlane::IsCrtcSupported(const DrmCrtc &crtc) const {
   if (crtc_prop_val != 0 && crtc_prop_val != crtc.GetId() &&
       GetType() == DRM_PLANE_TYPE_PRIMARY) {
     // Some DRM driver such as omap_drm allows sharing primary plane between
-    // CRTCs, but the primay plane could not be shared if it has been used by
+    // CRTCs, but the primary plane could not be shared if it has been used by
     // any CRTC already, which is protected by the plane_switching_crtc function
     // in the kernel drivers/gpu/drm/drm_atomic.c file.
     // The current drm_hwc design is not ready to support such scenario yet,
     // so adding the CRTC status check here to workaorund for now.
-    ALOGW("%s: This Plane(id=%d) is activated for Crtc(id=%" PRIu64
-          "), could not be used for Crtc (id=%d)",
-          __FUNCTION__, GetId(), crtc_prop_val, crtc.GetId());
     return false;
   }
 
diff --git a/drm/DrmProperty.cpp b/drm/DrmProperty.cpp
index 031918a..dbd307e 100644
--- a/drm/DrmProperty.cpp
+++ b/drm/DrmProperty.cpp
@@ -22,6 +22,7 @@
 #include <xf86drmMode.h>
 
 #include <cerrno>
+#include <cinttypes>
 #include <cstdint>
 #include <string>
 
@@ -125,4 +126,22 @@ auto DrmProperty::AtomicSet(drmModeAtomicReq &pset, uint64_t value) const
   return true;
 }
 
+std::optional<std::string> DrmProperty::GetEnumNameFromValue(
+    uint64_t value) const {
+  if (enums_.empty()) {
+    ALOGE("No enum values for property: %s", name_.c_str());
+    return {};
+  }
+
+  for (const auto &it : enums_) {
+    if (it.value == value) {
+      return it.name;
+    }
+  }
+
+  ALOGE("Property '%s' has no matching enum for value: %" PRIu64, name_.c_str(),
+        value);
+  return {};
+}
+
 }  // namespace android
diff --git a/drm/DrmProperty.h b/drm/DrmProperty.h
index 516518b..2683ad8 100644
--- a/drm/DrmProperty.h
+++ b/drm/DrmProperty.h
@@ -64,10 +64,16 @@ class DrmProperty {
   auto AddEnumToMap(const std::string &name, E key, std::map<E, uint64_t> &map)
       -> bool;
 
+  template <class E>
+  auto AddEnumToMapReverse(const std::string &name, E value,
+                           std::map<uint64_t, E> &map) -> bool;
+
   explicit operator bool() const {
     return id_ != 0;
   }
 
+  auto GetEnumNameFromValue(uint64_t value) const -> std::optional<std::string>;
+
  private:
   class DrmPropertyEnum {
    public:
@@ -104,4 +110,18 @@ auto DrmProperty::AddEnumToMap(const std::string &name, E key,
   return false;
 }
 
+template <class E>
+auto DrmProperty::AddEnumToMapReverse(const std::string &name, E value,
+                                      std::map<uint64_t, E> &map) -> bool {
+  uint64_t enum_value = UINT64_MAX;
+  int err = 0;
+  std::tie(enum_value, err) = GetEnumValueWithName(name);
+  if (err == 0) {
+    map[enum_value] = value;
+    return true;
+  }
+
+  return false;
+}
+
 }  // namespace android
diff --git a/drm/ResourceManager.cpp b/drm/ResourceManager.cpp
index 5ac80c4..0c23734 100644
--- a/drm/ResourceManager.cpp
+++ b/drm/ResourceManager.cpp
@@ -154,6 +154,10 @@ void ResourceManager::UpdateFrontendDisplays() {
         attached_pipelines_.erase(conn);
       }
     }
+    if (connected) {
+      if (!conn->IsLinkStatusGood())
+        frontend_interface_->NotifyDisplayLinkStatus(attached_pipelines_[conn]);
+    }
   }
   frontend_interface_->FinalizeDisplayBinding();
 }
diff --git a/drm/ResourceManager.h b/drm/ResourceManager.h
index 9a2652c..3c4d7ae 100644
--- a/drm/ResourceManager.h
+++ b/drm/ResourceManager.h
@@ -22,6 +22,7 @@
 #include "DrmDevice.h"
 #include "DrmDisplayPipeline.h"
 #include "DrmFbImporter.h"
+#include "DrmProperty.h"
 #include "UEventListener.h"
 
 namespace android {
@@ -37,6 +38,8 @@ class PipelineToFrontendBindingInterface {
   virtual bool BindDisplay(std::shared_ptr<DrmDisplayPipeline>) = 0;
   virtual bool UnbindDisplay(std::shared_ptr<DrmDisplayPipeline>) = 0;
   virtual void FinalizeDisplayBinding() = 0;
+  virtual void NotifyDisplayLinkStatus(
+      std::shared_ptr<DrmDisplayPipeline> pipeline) = 0;
 };
 
 class ResourceManager {
diff --git a/hooks/check-hooks-installed b/hooks/check-hooks-installed
new file mode 100755
index 0000000..45e5c73
--- /dev/null
+++ b/hooks/check-hooks-installed
@@ -0,0 +1,10 @@
+#!/bin/bash
+
+# Gerrit hook that runs on repo upload. Checks to ensure that the pre-upload hook
+# has been installed.
+
+cmd=$(git config hookcmd.check-non-public-commits.command)
+if [ -z "$cmd" ]; then
+  echo "Please install hooks by running: hooks/install-hooks.sh"
+  exit 1
+fi
\ No newline at end of file
diff --git a/hooks/check-non-public-commits b/hooks/check-non-public-commits
new file mode 100755
index 0000000..fc20795
--- /dev/null
+++ b/hooks/check-non-public-commits
@@ -0,0 +1,44 @@
+#!/bin/bash
+
+# git pre-push hook to detect whether a developer is attempting to push
+# non-public commits to a public repository.
+
+remote="$1"
+url="$2"
+
+# Don't bother checking if this is being pushed to gerrit.
+if [[ "$url" = "sso://googleplex-android/platform/external/drm_hwcomposer" ]] ||
+   [[ "$url" = "sso://android.googlesource.com/platform/external/drm_hwcomposer" ]]
+then
+  exit 0
+fi
+
+while read local_ref local_sha remote_ref remote_sha
+do
+  # Gather a list of all commits that are to be pushed to the remote.
+  # remote_sha will be 000000 if there is no corresponding remote branch.
+  if [[ "$remote_sha" =~ "0000000000" ]]; then
+    commits=$(git rev-list $local_sha --not --remotes=$remote)
+  else
+    commits=$(git rev-list $remote_sha..$local_sha)
+  fi
+
+  # Check each commit message for the prohibited prefix.
+  for commit in $commits; do
+    # Get the commit message.
+    message=$(git log -1 --pretty=%B $commit)
+
+    # Check if the commit message starts with "ANDROID:"
+    if [[ "$message" == "ANDROID"* ]] ||
+       [[ "$message" == "INTERNAL"* ]] ||
+       [[ "$message" == "DO NOT MERGE"* ]]; then
+      echo "Error: Commit message starts with downstream tag:"
+      echo "$message"
+      echo "It looks like you're trying to push internal changes to an externally "
+      echo "visible repository: $url"
+      exit 1
+    fi
+  done
+done
+
+exit 0
diff --git a/hooks/install-hooks.sh b/hooks/install-hooks.sh
new file mode 100755
index 0000000..cc5d967
--- /dev/null
+++ b/hooks/install-hooks.sh
@@ -0,0 +1,5 @@
+#!/bin/bash
+
+# Install hooks.
+git config --add hookcmd.check-non-public-commits.command "[ ! -d hooks ] || hooks/check-non-public-commits"
+git config --add hook.pre-push.command check-non-public-commits
\ No newline at end of file
diff --git a/hwc2_device/DrmHwcTwo.cpp b/hwc2_device/DrmHwcTwo.cpp
index c120b63..b243199 100644
--- a/hwc2_device/DrmHwcTwo.cpp
+++ b/hwc2_device/DrmHwcTwo.cpp
@@ -69,15 +69,16 @@ HWC2::Error DrmHwcTwo::RegisterCallback(int32_t descriptor,
 }
 
 void DrmHwcTwo::SendHotplugEventToClient(hwc2_display_t displayid,
-                                         bool connected) {
+                                         DisplayStatus display_status) {
   auto hc = hotplug_callback_;
+
   if (hc.first != nullptr && hc.second != nullptr) {
     /* For some reason HWC Service will call HWC2 API in hotplug callback
      * handler. This is the reason we're using recursive mutex.
      */
     hc.first(hc.second, displayid,
-             connected ? HWC2_CONNECTION_CONNECTED
-                       : HWC2_CONNECTION_DISCONNECTED);
+             display_status ? HWC2_CONNECTION_CONNECTED
+                            : HWC2_CONNECTION_DISCONNECTED);
   }
 }
 
diff --git a/hwc2_device/DrmHwcTwo.h b/hwc2_device/DrmHwcTwo.h
index b3ca0f8..ac87153 100644
--- a/hwc2_device/DrmHwcTwo.h
+++ b/hwc2_device/DrmHwcTwo.h
@@ -37,7 +37,7 @@ class DrmHwcTwo : public DrmHwc {
       hwc2_display_t displayid, int64_t timestamp) const override;
   void SendRefreshEventToClient(uint64_t displayid) override;
   void SendHotplugEventToClient(hwc2_display_t displayid,
-                                bool connected) override;
+                                DisplayStatus display_status) override;
 
  private:
   std::pair<HWC2_PFN_HOTPLUG, hwc2_callback_data_t> hotplug_callback_{};
diff --git a/hwc2_device/HwcDisplay.cpp b/hwc2_device/HwcDisplay.cpp
index 36333d2..0503f39 100644
--- a/hwc2_device/HwcDisplay.cpp
+++ b/hwc2_device/HwcDisplay.cpp
@@ -19,15 +19,92 @@
 
 #include "HwcDisplay.h"
 
+#include <cinttypes>
+
+#include <hardware/gralloc.h>
+#include <ui/GraphicBufferAllocator.h>
+#include <ui/GraphicBufferMapper.h>
+#include <ui/PixelFormat.h>
+
 #include "backend/Backend.h"
 #include "backend/BackendManager.h"
 #include "bufferinfo/BufferInfoGetter.h"
+#include "compositor/DisplayInfo.h"
+#include "drm/DrmConnector.h"
+#include "drm/DrmDisplayPipeline.h"
 #include "drm/DrmHwc.h"
 #include "utils/log.h"
 #include "utils/properties.h"
 
+using ::android::DrmDisplayPipeline;
+
 namespace android {
 
+namespace {
+// Allocate a black buffer that can be used for an initial modeset when there.
+// is no appropriate client buffer available to be used.
+// Caller must free the returned buffer with GraphicBufferAllocator::free.
+auto GetModesetBuffer(uint32_t width, uint32_t height) -> buffer_handle_t {
+  constexpr PixelFormat format = PIXEL_FORMAT_RGBA_8888;
+  constexpr uint64_t usage = GRALLOC_USAGE_SW_READ_OFTEN |
+                             GRALLOC_USAGE_SW_WRITE_OFTEN |
+                             GRALLOC_USAGE_HW_COMPOSER | GRALLOC_USAGE_HW_FB;
+
+  constexpr uint32_t layer_count = 1;
+  const std::string name = "drm-hwcomposer";
+
+  buffer_handle_t handle = nullptr;
+  uint32_t stride = 0;
+  status_t status = GraphicBufferAllocator::get().allocate(width, height,
+                                                           format, layer_count,
+                                                           usage, &handle,
+                                                           &stride, name);
+  if (status != OK) {
+    ALOGE("Failed to allocate modeset buffer.");
+    return nullptr;
+  }
+
+  void *data = nullptr;
+  Rect bounds = {0, 0, static_cast<int32_t>(width),
+                 static_cast<int32_t>(height)};
+  status = GraphicBufferMapper::get().lock(handle, usage, bounds, &data);
+  if (status != OK) {
+    ALOGE("Failed to map modeset buffer.");
+    GraphicBufferAllocator::get().free(handle);
+    return nullptr;
+  }
+
+  // Cast one of the multiplicands to ensure that the multiplication happens
+  // in a wider type (size_t).
+  const size_t buffer_size = static_cast<size_t>(height) * stride *
+                             bytesPerPixel(format);
+  memset(data, 0, buffer_size);
+  status = GraphicBufferMapper::get().unlock(handle);
+  ALOGW_IF(status != OK, "Failed to unmap buffer.");
+  return handle;
+}
+
+auto GetModesetLayerProperties(buffer_handle_t buffer, uint32_t width,
+                               uint32_t height) -> HwcLayer::LayerProperties {
+  HwcLayer::LayerProperties properties;
+  properties.buffer = {.buffer_handle = buffer, .acquire_fence = {}};
+  properties.display_frame = {
+      .left = 0,
+      .top = 0,
+      .right = int(width),
+      .bottom = int(height),
+  };
+  properties.source_crop = (hwc_frect_t){
+      .left = 0.0F,
+      .top = 0.0F,
+      .right = static_cast<float>(width),
+      .bottom = static_cast<float>(height),
+  };
+  properties.blend_mode = BufferBlendMode::kNone;
+  return properties;
+}
+}  // namespace
+
 std::string HwcDisplay::DumpDelta(HwcDisplay::Stats delta) {
   if (delta.total_pixops_ == 0)
     return "No stats yet";
@@ -73,7 +150,7 @@ HwcDisplay::HwcDisplay(hwc2_display_t handle, HWC2::DisplayType type,
   }
 }
 
-void HwcDisplay::SetColorMarixToIdentity() {
+void HwcDisplay::SetColorMatrixToIdentity() {
   color_matrix_ = std::make_shared<drm_color_ctm>();
   for (int i = 0; i < kCtmCols; i++) {
     for (int j = 0; j < kCtmRows; j++) {
@@ -89,6 +166,110 @@ HwcDisplay::~HwcDisplay() {
   Deinit();
 };
 
+auto HwcDisplay::GetConfig(hwc2_config_t config_id) const
+    -> const HwcDisplayConfig * {
+  auto config_iter = configs_.hwc_configs.find(config_id);
+  if (config_iter == configs_.hwc_configs.end()) {
+    return nullptr;
+  }
+  return &config_iter->second;
+}
+
+auto HwcDisplay::GetCurrentConfig() const -> const HwcDisplayConfig * {
+  return GetConfig(configs_.active_config_id);
+}
+
+auto HwcDisplay::GetLastRequestedConfig() const -> const HwcDisplayConfig * {
+  return GetConfig(staged_mode_config_id_.value_or(configs_.active_config_id));
+}
+
+HwcDisplay::ConfigError HwcDisplay::SetConfig(hwc2_config_t config) {
+  const HwcDisplayConfig *new_config = GetConfig(config);
+  if (new_config == nullptr) {
+    ALOGE("Could not find active mode for %u", config);
+    return ConfigError::kBadConfig;
+  }
+
+  const HwcDisplayConfig *current_config = GetCurrentConfig();
+
+  const uint32_t width = new_config->mode.GetRawMode().hdisplay;
+  const uint32_t height = new_config->mode.GetRawMode().vdisplay;
+
+  std::optional<LayerData> modeset_layer_data;
+  // If a client layer has already been provided, and its size matches the
+  // new config, use it for the modeset.
+  if (client_layer_.IsLayerUsableAsDevice() && current_config &&
+      current_config->mode.GetRawMode().hdisplay == width &&
+      current_config->mode.GetRawMode().vdisplay == height) {
+    ALOGV("Use existing client_layer for blocking config.");
+    modeset_layer_data = client_layer_.GetLayerData();
+  } else {
+    ALOGV("Allocate modeset buffer.");
+    buffer_handle_t modeset_buffer = GetModesetBuffer(width, height);
+    if (modeset_buffer != nullptr) {
+      auto modeset_layer = std::make_unique<HwcLayer>(this);
+      modeset_layer->SetLayerProperties(
+          GetModesetLayerProperties(modeset_buffer, width, height));
+      modeset_layer->PopulateLayerData();
+      modeset_layer_data = modeset_layer->GetLayerData();
+      GraphicBufferAllocator::get().free(modeset_buffer);
+    }
+  }
+
+  ALOGV("Create modeset commit.");
+  // Create atomic commit args for a blocking modeset. There's no need to do a
+  // separate test commit, since the commit does a test anyways.
+  AtomicCommitArgs commit_args = CreateModesetCommit(new_config,
+                                                     modeset_layer_data);
+  commit_args.blocking = true;
+  int ret = GetPipe().atomic_state_manager->ExecuteAtomicCommit(commit_args);
+
+  if (ret) {
+    ALOGE("Blocking config failed: %d", ret);
+    return HwcDisplay::ConfigError::kBadConfig;
+  }
+
+  ALOGV("Blocking config succeeded.");
+  configs_.active_config_id = config;
+  staged_mode_config_id_.reset();
+  return ConfigError::kNone;
+}
+
+auto HwcDisplay::QueueConfig(hwc2_config_t config, int64_t desired_time,
+                             bool seamless, QueuedConfigTiming *out_timing)
+    -> ConfigError {
+  if (configs_.hwc_configs.count(config) == 0) {
+    ALOGE("Could not find active mode for %u", config);
+    return ConfigError::kBadConfig;
+  }
+
+  // TODO: Add support for seamless configuration changes.
+  if (seamless) {
+    return ConfigError::kSeamlessNotAllowed;
+  }
+
+  // Request a refresh from the client one vsync period before the desired
+  // time, or simply at the desired time if there is no active configuration.
+  const HwcDisplayConfig *current_config = GetCurrentConfig();
+  out_timing->refresh_time_ns = desired_time -
+                                (current_config
+                                     ? current_config->mode.GetVSyncPeriodNs()
+                                     : 0);
+  out_timing->new_vsync_time_ns = desired_time;
+
+  // Queue the config change timing to be consistent with the requested
+  // refresh time.
+  staged_mode_change_time_ = out_timing->refresh_time_ns;
+  staged_mode_config_id_ = config;
+
+  // Enable vsync events until the mode has been applied.
+  last_vsync_ts_ = 0;
+  vsync_tracking_en_ = true;
+  vsync_worker_->VSyncControl(true);
+
+  return ConfigError::kNone;
+}
+
 void HwcDisplay::SetPipeline(std::shared_ptr<DrmDisplayPipeline> pipeline) {
   Deinit();
 
@@ -96,9 +277,9 @@ void HwcDisplay::SetPipeline(std::shared_ptr<DrmDisplayPipeline> pipeline) {
 
   if (pipeline_ != nullptr || handle_ == kPrimaryDisplay) {
     Init();
-    hwc_->ScheduleHotplugEvent(handle_, /*connected = */ true);
+    hwc_->ScheduleHotplugEvent(handle_, DrmHwc::kConnected);
   } else {
-    hwc_->ScheduleHotplugEvent(handle_, /*connected = */ false);
+    hwc_->ScheduleHotplugEvent(handle_, DrmHwc::kDisconnected);
   }
 }
 
@@ -107,22 +288,9 @@ void HwcDisplay::Deinit() {
     AtomicCommitArgs a_args{};
     a_args.composition = std::make_shared<DrmKmsPlan>();
     GetPipe().atomic_state_manager->ExecuteAtomicCommit(a_args);
-/*
- *  TODO:
- *  Unfortunately the following causes regressions on db845c
- *  with VtsHalGraphicsComposerV2_3TargetTest due to the display
- *  never coming back. Patches to avoiding that issue on the
- *  the kernel side unfortunately causes further crashes in
- *  drm_hwcomposer, because the client detach takes longer then the
- *  1 second max VTS expects. So for now as a workaround, lets skip
- *  deactivating the display on deinit, which matches previous
- *  behavior prior to commit d0494d9b8097
- */
-#if 0
     a_args.composition = {};
     a_args.active = false;
     GetPipe().atomic_state_manager->ExecuteAtomicCommit(a_args);
-#endif
 
     current_plan_.reset();
     backend_.reset();
@@ -189,11 +357,28 @@ HWC2::Error HwcDisplay::Init() {
 
   client_layer_.SetLayerBlendMode(HWC2_BLEND_MODE_PREMULTIPLIED);
 
-  SetColorMarixToIdentity();
+  SetColorMatrixToIdentity();
 
   return HWC2::Error::None;
 }
 
+std::optional<PanelOrientation> HwcDisplay::getDisplayPhysicalOrientation() {
+  if (IsInHeadlessMode()) {
+    // The pipeline can be nullptr in headless mode, so return the default
+    // "normal" mode.
+    return PanelOrientation::kModePanelOrientationNormal;
+  }
+
+  DrmDisplayPipeline &pipeline = GetPipe();
+  if (pipeline.connector == nullptr || pipeline.connector->Get() == nullptr) {
+    ALOGW(
+        "No display pipeline present to query the panel orientation property.");
+    return {};
+  }
+
+  return pipeline.connector->Get()->GetPanelOrientation();
+}
+
 HWC2::Error HwcDisplay::ChosePreferredConfig() {
   HWC2::Error err{};
   if (type_ == HWC2::DisplayType::Virtual) {
@@ -233,10 +418,12 @@ HWC2::Error HwcDisplay::DestroyLayer(hwc2_layer_t layer) {
 }
 
 HWC2::Error HwcDisplay::GetActiveConfig(hwc2_config_t *config) const {
-  if (configs_.hwc_configs.count(staged_mode_config_id_) == 0)
+  // If a config has been queued, it is considered the "active" config.
+  const HwcDisplayConfig *hwc_config = GetLastRequestedConfig();
+  if (hwc_config == nullptr)
     return HWC2::Error::BadConfig;
 
-  *config = staged_mode_config_id_;
+  *config = hwc_config->id;
   return HWC2::Error::None;
 }
 
@@ -320,7 +507,7 @@ HWC2::Error HwcDisplay::GetDisplayAttribute(hwc2_config_t config,
       break;
     case HWC2::Attribute::VsyncPeriod:
       // in nanoseconds
-      *value = static_cast<int>(1E9 / hwc_config.mode.GetVRefresh());
+      *value = hwc_config.mode.GetVSyncPeriodNs();
       break;
     case HWC2::Attribute::DpiY:
       // ideally this should be vdisplay/mm_heigth, however mm_height
@@ -455,6 +642,34 @@ HWC2::Error HwcDisplay::GetReleaseFences(uint32_t *num_elements,
   return HWC2::Error::None;
 }
 
+AtomicCommitArgs HwcDisplay::CreateModesetCommit(
+    const HwcDisplayConfig *config,
+    const std::optional<LayerData> &modeset_layer) {
+  AtomicCommitArgs args{};
+
+  args.color_matrix = color_matrix_;
+  args.content_type = content_type_;
+  args.colorspace = colorspace_;
+
+  std::vector<LayerData> composition_layers;
+  if (modeset_layer) {
+    composition_layers.emplace_back(modeset_layer.value());
+  }
+
+  if (composition_layers.empty()) {
+    ALOGW("Attempting to create a modeset commit without a layer.");
+  }
+
+  args.display_mode = config->mode;
+  args.active = true;
+  args.composition = DrmKmsPlan::CreateDrmKmsPlan(GetPipe(),
+                                                  std::move(
+                                                      composition_layers));
+  ALOGW_IF(!args.composition, "No composition for blocking modeset");
+
+  return args;
+}
+
 HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
   if (IsInHeadlessMode()) {
     ALOGE("%s: Display is in headless mode, should never reach here", __func__);
@@ -462,22 +677,29 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
   }
 
   a_args.color_matrix = color_matrix_;
+  a_args.content_type = content_type_;
+  a_args.colorspace = colorspace_;
 
   uint32_t prev_vperiod_ns = 0;
   GetDisplayVsyncPeriod(&prev_vperiod_ns);
 
   auto mode_update_commited_ = false;
-  if (staged_mode_ &&
+  if (staged_mode_config_id_ &&
       staged_mode_change_time_ <= ResourceManager::GetTimeMonotonicNs()) {
+    const HwcDisplayConfig *staged_config = GetConfig(
+        staged_mode_config_id_.value());
+    if (staged_config == nullptr) {
+      return HWC2::Error::BadConfig;
+    }
     client_layer_.SetLayerDisplayFrame(
         (hwc_rect_t){.left = 0,
                      .top = 0,
-                     .right = int(staged_mode_->GetRawMode().hdisplay),
-                     .bottom = int(staged_mode_->GetRawMode().vdisplay)});
+                     .right = int(staged_config->mode.GetRawMode().hdisplay),
+                     .bottom = int(staged_config->mode.GetRawMode().vdisplay)});
 
-    configs_.active_config_id = staged_mode_config_id_;
+    configs_.active_config_id = staged_mode_config_id_.value();
 
-    a_args.display_mode = *staged_mode_;
+    a_args.display_mode = staged_config->mode;
     if (!a_args.test_only) {
       mode_update_commited_ = true;
     }
@@ -542,9 +764,7 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
   }
 
   if (!current_plan_) {
-    if (!a_args.test_only) {
-      ALOGE("Failed to create DrmKmsPlan");
-    }
+    ALOGE_IF(!a_args.test_only, "Failed to create DrmKmsPlan");
     return HWC2::Error::BadConfig;
   }
 
@@ -553,13 +773,12 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
   auto ret = GetPipe().atomic_state_manager->ExecuteAtomicCommit(a_args);
 
   if (ret) {
-    if (!a_args.test_only)
-      ALOGE("Failed to apply the frame composition ret=%d", ret);
+    ALOGE_IF(!a_args.test_only, "Failed to apply the frame composition ret=%d", ret);
     return HWC2::Error::BadParameter;
   }
 
   if (mode_update_commited_) {
-    staged_mode_.reset();
+    staged_mode_config_id_.reset();
     vsync_tracking_en_ = false;
     if (last_vsync_ts_ != 0) {
       hwc_->SendVsyncPeriodTimingChangedEventToClient(handle_,
@@ -604,6 +823,7 @@ HWC2::Error HwcDisplay::PresentDisplay(int32_t *out_present_fence) {
   color_matrix_ = {};
 
   ++frame_no_;
+
   return HWC2::Error::None;
 }
 
@@ -614,7 +834,6 @@ HWC2::Error HwcDisplay::SetActiveConfigInternal(uint32_t config,
     return HWC2::Error::BadConfig;
   }
 
-  staged_mode_ = configs_.hwc_configs[config].mode;
   staged_mode_change_time_ = change_time;
   staged_mode_config_id_ = config;
 
@@ -671,11 +890,35 @@ HWC2::Error HwcDisplay::SetClientTarget(buffer_handle_t target,
 }
 
 HWC2::Error HwcDisplay::SetColorMode(int32_t mode) {
-  if (mode < HAL_COLOR_MODE_NATIVE || mode > HAL_COLOR_MODE_BT2100_HLG)
+  /* Maps to the Colorspace DRM connector property:
+   * https://elixir.bootlin.com/linux/v6.11/source/include/drm/drm_connector.h#L538
+   */
+  if (mode < HAL_COLOR_MODE_NATIVE || mode > HAL_COLOR_MODE_DISPLAY_P3)
     return HWC2::Error::BadParameter;
 
-  if (mode != HAL_COLOR_MODE_NATIVE)
-    return HWC2::Error::Unsupported;
+  switch (mode) {
+    case HAL_COLOR_MODE_NATIVE:
+      colorspace_ = Colorspace::kDefault;
+      break;
+    case HAL_COLOR_MODE_STANDARD_BT601_625:
+    case HAL_COLOR_MODE_STANDARD_BT601_625_UNADJUSTED:
+    case HAL_COLOR_MODE_STANDARD_BT601_525:
+    case HAL_COLOR_MODE_STANDARD_BT601_525_UNADJUSTED:
+      // The DP spec does not say whether this is the 525 or the 625 line version.
+      colorspace_ = Colorspace::kBt601Ycc;
+      break;
+    case HAL_COLOR_MODE_STANDARD_BT709:
+    case HAL_COLOR_MODE_SRGB:
+      colorspace_ = Colorspace::kBt709Ycc;
+      break;
+    case HAL_COLOR_MODE_DCI_P3:
+    case HAL_COLOR_MODE_DISPLAY_P3:
+      colorspace_ = Colorspace::kDciP3RgbD65;
+      break;
+    case HAL_COLOR_MODE_ADOBE_RGB:
+    default:
+      return HWC2::Error::Unsupported;
+  }
 
   color_mode_ = mode;
   return HWC2::Error::None;
@@ -683,6 +926,15 @@ HWC2::Error HwcDisplay::SetColorMode(int32_t mode) {
 
 #include <xf86drmMode.h>
 
+static uint64_t To3132FixPt(float in) {
+  constexpr uint64_t kSignMask = (1ULL << 63);
+  constexpr uint64_t kValueMask = ~(1ULL << 63);
+  constexpr auto kValueScale = static_cast<float>(1ULL << 32);
+  if (in < 0)
+    return (static_cast<uint64_t>(-in * kValueScale) & kValueMask) | kSignMask;
+  return static_cast<uint64_t>(in * kValueScale) & kValueMask;
+}
+
 HWC2::Error HwcDisplay::SetColorTransform(const float *matrix, int32_t hint) {
   if (hint < HAL_COLOR_TRANSFORM_IDENTITY ||
       hint > HAL_COLOR_TRANSFORM_CORRECT_TRITANOPIA)
@@ -701,17 +953,40 @@ HWC2::Error HwcDisplay::SetColorTransform(const float *matrix, int32_t hint) {
 
   switch (color_transform_hint_) {
     case HAL_COLOR_TRANSFORM_IDENTITY:
-      SetColorMarixToIdentity();
+      SetColorMatrixToIdentity();
       break;
     case HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX:
+      // Without HW support, we cannot correctly process matrices with an offset.
+      for (int i = 12; i < 14; i++) {
+        if (matrix[i] != 0.F)
+          return HWC2::Error::Unsupported;
+      }
+
+      /* HAL provides a 4x4 float type matrix:
+       * | 0  1  2  3|
+       * | 4  5  6  7|
+       * | 8  9 10 11|
+       * |12 13 14 15|
+       *
+       * R_out = R*0 + G*4 + B*8 + 12
+       * G_out = R*1 + G*5 + B*9 + 13
+       * B_out = R*2 + G*6 + B*10 + 14
+       *
+       * DRM expects a 3x3 s31.32 fixed point matrix:
+       * out   matrix    in
+       * |R|   |0 1 2|   |R|
+       * |G| = |3 4 5| x |G|
+       * |B|   |6 7 8|   |B|
+       *
+       * R_out = R*0 + G*1 + B*2
+       * G_out = R*3 + G*4 + B*5
+       * B_out = R*6 + G*7 + B*8
+       */
       color_matrix_ = std::make_shared<drm_color_ctm>();
-      /* DRM expects a 3x3 matrix, but the HAL provides a 4x4 matrix. */
       for (int i = 0; i < kCtmCols; i++) {
         for (int j = 0; j < kCtmRows; j++) {
           constexpr int kInCtmRows = 4;
-          /* HAL matrix type is float, but DRM expects a s31.32 fix point */
-          auto value = uint64_t(matrix[i * kInCtmRows + j] * float(1ULL << 32));
-          color_matrix_->matrix[i * kCtmRows + j] = value;
+          color_matrix_->matrix[i * kCtmRows + j] = To3132FixPt(matrix[j * kInCtmRows + i]);
         }
       }
       break;
@@ -916,12 +1191,13 @@ HWC2::Error HwcDisplay::GetSupportedContentTypes(
 }
 
 HWC2::Error HwcDisplay::SetContentType(int32_t contentType) {
-  if (contentType != HWC2_CONTENT_TYPE_NONE)
-    return HWC2::Error::Unsupported;
-
-  /* TODO: Map to the DRM Connector property:
-   * https://elixir.bootlin.com/linux/v5.4-rc5/source/drivers/gpu/drm/drm_connector.c#L809
+  /* Maps exactly to the content_type DRM connector property:
+   * https://elixir.bootlin.com/linux/v6.11/source/include/uapi/drm/drm_mode.h#L107
    */
+  if (contentType < HWC2_CONTENT_TYPE_NONE || contentType > HWC2_CONTENT_TYPE_GAME)
+    return HWC2::Error::BadParameter;
+
+  content_type_ = contentType;
 
   return HWC2::Error::None;
 }
@@ -1016,16 +1292,12 @@ HWC2::Error HwcDisplay::SetColorModeWithIntent(int32_t mode, int32_t intent) {
       intent > HAL_RENDER_INTENT_TONE_MAP_ENHANCE)
     return HWC2::Error::BadParameter;
 
-  if (mode < HAL_COLOR_MODE_NATIVE || mode > HAL_COLOR_MODE_BT2100_HLG)
-    return HWC2::Error::BadParameter;
-
-  if (mode != HAL_COLOR_MODE_NATIVE)
-    return HWC2::Error::Unsupported;
-
   if (intent != HAL_RENDER_INTENT_COLORIMETRIC)
     return HWC2::Error::Unsupported;
 
-  color_mode_ = mode;
+  auto err = SetColorMode(mode);
+  if (err != HWC2::Error::None) return err;
+
   return HWC2::Error::None;
 }
 
diff --git a/hwc2_device/HwcDisplay.h b/hwc2_device/HwcDisplay.h
index 87d2da7..ecca514 100644
--- a/hwc2_device/HwcDisplay.h
+++ b/hwc2_device/HwcDisplay.h
@@ -23,6 +23,7 @@
 #include <sstream>
 
 #include "HwcDisplayConfigs.h"
+#include "compositor/DisplayInfo.h"
 #include "compositor/FlatteningController.h"
 #include "compositor/LayerData.h"
 #include "drm/DrmAtomicStateManager.h"
@@ -40,6 +41,13 @@ inline constexpr uint32_t kPrimaryDisplay = 0;
 // NOLINTNEXTLINE
 class HwcDisplay {
  public:
+  enum ConfigError {
+    kNone,
+    kBadConfig,
+    kSeamlessNotAllowed,
+    kSeamlessNotPossible
+  };
+
   HwcDisplay(hwc2_display_t handle, HWC2::DisplayType type, DrmHwc *hwc);
   HwcDisplay(const HwcDisplay &) = delete;
   ~HwcDisplay();
@@ -58,7 +66,27 @@ class HwcDisplay {
     return configs_;
   }
 
-  // HWC Hooks
+  // Get the config representing the mode that has been committed to KMS.
+  auto GetCurrentConfig() const -> const HwcDisplayConfig *;
+
+  // Get the config that was last requested through SetActiveConfig and similar
+  // functions. This may differ from the GetCurrentConfig if the config change
+  // is queued up to take effect in the future.
+  auto GetLastRequestedConfig() const -> const HwcDisplayConfig *;
+
+  // Set a config synchronously. If the requested config fails to be committed,
+  // this will return with an error. Otherwise, the config will have been
+  // committed to the kernel on successful return.
+  ConfigError SetConfig(hwc2_config_t config);
+
+  // Queue a configuration change to take effect in the future.
+  auto QueueConfig(hwc2_config_t config, int64_t desired_time, bool seamless,
+                   QueuedConfigTiming *out_timing) -> ConfigError;
+
+  // Get the HwcDisplayConfig, or nullptor if none.
+  auto GetConfig(hwc2_config_t config_id) const -> const HwcDisplayConfig *;
+
+  // HWC2 Hooks - these should not be used outside of the hwc2 device.
   HWC2::Error AcceptDisplayChanges();
   HWC2::Error CreateLayer(hwc2_layer_t *layer);
   HWC2::Error DestroyLayer(hwc2_layer_t layer);
@@ -197,16 +225,21 @@ class HwcDisplay {
     virtual_disp_height_ = height;
   }
 
+  auto getDisplayPhysicalOrientation() -> std::optional<PanelOrientation>;
+
  private:
+  AtomicCommitArgs CreateModesetCommit(
+      const HwcDisplayConfig *config,
+      const std::optional<LayerData> &modeset_layer);
+
   HwcDisplayConfigs configs_;
 
   DrmHwc *const hwc_;
 
   SharedFd present_fence_;
 
-  std::optional<DrmMode> staged_mode_;
   int64_t staged_mode_change_time_{};
-  uint32_t staged_mode_config_id_{};
+  std::optional<uint32_t> staged_mode_config_id_{};
 
   std::shared_ptr<DrmDisplayPipeline> pipeline_;
 
@@ -233,6 +266,8 @@ class HwcDisplay {
   static constexpr int kCtmCols = 3;
   std::shared_ptr<drm_color_ctm> color_matrix_;
   android_color_transform_t color_transform_hint_{};
+  int32_t content_type_{};
+  Colorspace colorspace_{};
 
   std::shared_ptr<DrmKmsPlan> current_plan_;
 
@@ -241,7 +276,7 @@ class HwcDisplay {
   Stats prev_stats_;
   std::string DumpDelta(HwcDisplay::Stats delta);
 
-  void SetColorMarixToIdentity();
+  void SetColorMatrixToIdentity();
 
   HWC2::Error Init();
 
diff --git a/hwc2_device/HwcDisplayConfigs.cpp b/hwc2_device/HwcDisplayConfigs.cpp
index 3645356..fa1d2a9 100644
--- a/hwc2_device/HwcDisplayConfigs.cpp
+++ b/hwc2_device/HwcDisplayConfigs.cpp
@@ -23,6 +23,7 @@
 
 #include "drm/DrmConnector.h"
 #include "utils/log.h"
+#include "utils/properties.h"
 
 constexpr uint32_t kHeadlessModeDisplayWidthMm = 163;
 constexpr uint32_t kHeadlessModeDisplayHeightMm = 122;
@@ -113,17 +114,20 @@ HWC2::Error HwcDisplayConfigs::Update(DrmConnector &connector) {
 
   auto first_config_id = last_config_id;
   uint32_t last_group_id = 1;
+  const bool use_config_groups = Properties::UseConfigGroups();
 
   /* Group modes */
   for (const auto &mode : connector.GetModes()) {
     /* Find group for the new mode or create new group */
     uint32_t group_found = 0;
-    for (auto &hwc_config : hwc_configs) {
-      if (mode.GetRawMode().hdisplay ==
-              hwc_config.second.mode.GetRawMode().hdisplay &&
-          mode.GetRawMode().vdisplay ==
-              hwc_config.second.mode.GetRawMode().vdisplay) {
-        group_found = hwc_config.second.group_id;
+    if (use_config_groups) {
+      for (auto &hwc_config : hwc_configs) {
+        if (mode.GetRawMode().hdisplay ==
+                hwc_config.second.mode.GetRawMode().hdisplay &&
+            mode.GetRawMode().vdisplay ==
+                hwc_config.second.mode.GetRawMode().vdisplay) {
+          group_found = hwc_config.second.group_id;
+        }
       }
     }
     if (group_found == 0) {
diff --git a/hwc2_device/HwcLayer.cpp b/hwc2_device/HwcLayer.cpp
index da4ce7c..cb18fdd 100644
--- a/hwc2_device/HwcLayer.cpp
+++ b/hwc2_device/HwcLayer.cpp
@@ -24,6 +24,42 @@
 
 namespace android {
 
+void HwcLayer::SetLayerProperties(const LayerProperties& layer_properties) {
+  if (layer_properties.buffer) {
+    layer_data_.acquire_fence = layer_properties.buffer->acquire_fence;
+    buffer_handle_ = layer_properties.buffer->buffer_handle;
+    buffer_handle_updated_ = true;
+  }
+  if (layer_properties.blend_mode) {
+    blend_mode_ = layer_properties.blend_mode.value();
+  }
+  if (layer_properties.color_space) {
+    color_space_ = layer_properties.color_space.value();
+  }
+  if (layer_properties.sample_range) {
+    sample_range_ = layer_properties.sample_range.value();
+  }
+  if (layer_properties.composition_type) {
+    sf_type_ = layer_properties.composition_type.value();
+  }
+  if (layer_properties.display_frame) {
+    layer_data_.pi.display_frame = layer_properties.display_frame.value();
+  }
+  if (layer_properties.alpha) {
+    layer_data_.pi.alpha = std::lround(layer_properties.alpha.value() *
+                                       UINT16_MAX);
+  }
+  if (layer_properties.source_crop) {
+    layer_data_.pi.source_crop = layer_properties.source_crop.value();
+  }
+  if (layer_properties.transform) {
+    layer_data_.pi.transform = layer_properties.transform.value();
+  }
+  if (layer_properties.z_order) {
+    z_order_ = layer_properties.z_order.value();
+  }
+}
+
 // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
 HWC2::Error HwcLayer::SetCursorPosition(int32_t /*x*/, int32_t /*y*/) {
   return HWC2::Error::None;
diff --git a/hwc2_device/HwcLayer.h b/hwc2_device/HwcLayer.h
index b69ce5b..e1d62b7 100644
--- a/hwc2_device/HwcLayer.h
+++ b/hwc2_device/HwcLayer.h
@@ -16,6 +16,7 @@
 
 #pragma once
 
+#include <aidl/android/hardware/graphics/common/Transform.h>
 #include <hardware/hwcomposer2.h>
 
 #include "bufferinfo/BufferInfoGetter.h"
@@ -27,6 +28,24 @@ class HwcDisplay;
 
 class HwcLayer {
  public:
+  struct Buffer {
+    buffer_handle_t buffer_handle;
+    SharedFd acquire_fence;
+  };
+  // A set of properties to be validated.
+  struct LayerProperties {
+    std::optional<Buffer> buffer;
+    std::optional<BufferBlendMode> blend_mode;
+    std::optional<BufferColorSpace> color_space;
+    std::optional<BufferSampleRange> sample_range;
+    std::optional<HWC2::Composition> composition_type;
+    std::optional<hwc_rect_t> display_frame;
+    std::optional<float> alpha;
+    std::optional<hwc_frect_t> source_crop;
+    std::optional<LayerTransform> transform;
+    std::optional<uint32_t> z_order;
+  };
+
   explicit HwcLayer(HwcDisplay *parent_display) : parent_(parent_display){};
 
   HWC2::Composition GetSfType() const {
@@ -61,7 +80,9 @@ class HwcLayer {
     return layer_data_;
   }
 
-  // Layer hooks
+  void SetLayerProperties(const LayerProperties &layer_properties);
+
+  // HWC2 Layer hooks
   HWC2::Error SetCursorPosition(int32_t /*x*/, int32_t /*y*/);
   HWC2::Error SetLayerBlendMode(int32_t mode);
   HWC2::Error SetLayerBuffer(buffer_handle_t buffer, int32_t acquire_fence);
diff --git a/hwc3/CommandResultWriter.h b/hwc3/CommandResultWriter.h
index fa96f33..aae6817 100644
--- a/hwc3/CommandResultWriter.h
+++ b/hwc3/CommandResultWriter.h
@@ -17,6 +17,8 @@
 #include <unordered_map>
 #include <vector>
 
+#include <android-base/unique_fd.h>
+
 #include "Utils.h"
 #include "aidl/android/hardware/graphics/composer3/CommandError.h"
 #include "aidl/android/hardware/graphics/composer3/CommandResultPayload.h"
diff --git a/hwc3/Composer.cpp b/hwc3/Composer.cpp
index 4977a14..124380d 100644
--- a/hwc3/Composer.cpp
+++ b/hwc3/Composer.cpp
@@ -25,6 +25,7 @@
 #include "hwc3/ComposerClient.h"
 #include "hwc3/Utils.h"
 #include "utils/log.h"
+#include "utils/properties.h"
 
 namespace aidl::android::hardware::graphics::composer3::impl {
 
@@ -71,6 +72,11 @@ ndk::ScopedAStatus Composer::getCapabilities(std::vector<Capability>* caps) {
   DEBUG_FUNC();
   /* No capabilities advertised */
   caps->clear();
+
+  if (Properties::IsPresentFenceNotReliable()) {
+    caps->emplace_back(Capability::PRESENT_FENCE_IS_NOT_RELIABLE);
+  }
+
   return ndk::ScopedAStatus::ok();
 }
 
diff --git a/hwc3/ComposerClient.cpp b/hwc3/ComposerClient.cpp
index f353abb..b8128f0 100644
--- a/hwc3/ComposerClient.cpp
+++ b/hwc3/ComposerClient.cpp
@@ -19,28 +19,31 @@
 
 #include "ComposerClient.h"
 
-#include <aidlcommonsupport/NativeHandle.h>
-#include <android-base/logging.h>
-#include <android/binder_ibinder_platform.h>
-#include <hardware/hwcomposer2.h>
-
 #include <cinttypes>
 #include <cmath>
 #include <memory>
 #include <unordered_map>
 #include <vector>
 
-#include "aidl/android/hardware/graphics/common/Transform.h"
-#include "aidl/android/hardware/graphics/composer3/ClientTarget.h"
-#include "aidl/android/hardware/graphics/composer3/Composition.h"
-#include "aidl/android/hardware/graphics/composer3/DisplayRequest.h"
-#include "aidl/android/hardware/graphics/composer3/IComposerClient.h"
-#include "aidl/android/hardware/graphics/composer3/PowerMode.h"
-#include "aidl/android/hardware/graphics/composer3/PresentOrValidate.h"
-#include "aidl/android/hardware/graphics/composer3/RenderIntent.h"
-#include "android/binder_auto_utils.h"
-#include "cutils/native_handle.h"
-#include "hardware/hwcomposer_defs.h"
+#include <aidl/android/hardware/graphics/common/Transform.h>
+#include <aidl/android/hardware/graphics/composer3/ClientTarget.h>
+#include <aidl/android/hardware/graphics/composer3/Composition.h>
+#include <aidl/android/hardware/graphics/composer3/DisplayRequest.h>
+#include <aidl/android/hardware/graphics/composer3/IComposerClient.h>
+#include <aidl/android/hardware/graphics/composer3/Luts.h>
+#include <aidl/android/hardware/graphics/composer3/PowerMode.h>
+#include <aidl/android/hardware/graphics/composer3/PresentOrValidate.h>
+#include <aidl/android/hardware/graphics/composer3/RenderIntent.h>
+#include <aidlcommonsupport/NativeHandle.h>
+#include <android-base/logging.h>
+#include <android/binder_auto_utils.h>
+#include <android/binder_ibinder_platform.h>
+#include <cutils/native_handle.h>
+#include <hardware/hwcomposer2.h>
+#include <hardware/hwcomposer_defs.h>
+
+#include "bufferinfo/BufferInfo.h"
+#include "compositor/DisplayInfo.h"
 #include "hwc2_device/HwcDisplay.h"
 #include "hwc2_device/HwcDisplayConfigs.h"
 #include "hwc2_device/HwcLayer.h"
@@ -48,7 +51,10 @@
 #include "hwc3/Utils.h"
 
 using ::android::HwcDisplay;
+using ::android::HwcDisplayConfig;
 using ::android::HwcDisplayConfigs;
+using ::android::HwcLayer;
+using ::android::LayerTransform;
 
 #include "utils/log.h"
 
@@ -64,6 +70,239 @@ constexpr std::array<float, 16> kIdentityMatrix = {
 };
 // clang-format on
 
+std::optional<BufferBlendMode> AidlToBlendMode(
+    const std::optional<ParcelableBlendMode>& aidl_blend_mode) {
+  if (!aidl_blend_mode) {
+    return std::nullopt;
+  }
+
+  switch (aidl_blend_mode->blendMode) {
+    case common::BlendMode::NONE:
+      return BufferBlendMode::kNone;
+    case common::BlendMode::PREMULTIPLIED:
+      return BufferBlendMode::kPreMult;
+    case common::BlendMode::COVERAGE:
+      return BufferBlendMode::kCoverage;
+    case common::BlendMode::INVALID:
+      ALOGE("Invalid BlendMode");
+      return std::nullopt;
+  }
+}
+
+std::optional<BufferColorSpace> AidlToColorSpace(
+    const std::optional<ParcelableDataspace>& dataspace) {
+  if (!dataspace) {
+    return std::nullopt;
+  }
+
+  int32_t standard = static_cast<int32_t>(dataspace->dataspace) &
+                     static_cast<int32_t>(common::Dataspace::STANDARD_MASK);
+  switch (standard) {
+    case static_cast<int32_t>(common::Dataspace::STANDARD_BT709):
+      return BufferColorSpace::kItuRec709;
+    case static_cast<int32_t>(common::Dataspace::STANDARD_BT601_625):
+    case static_cast<int32_t>(common::Dataspace::STANDARD_BT601_625_UNADJUSTED):
+    case static_cast<int32_t>(common::Dataspace::STANDARD_BT601_525):
+    case static_cast<int32_t>(common::Dataspace::STANDARD_BT601_525_UNADJUSTED):
+      return BufferColorSpace::kItuRec601;
+    case static_cast<int32_t>(common::Dataspace::STANDARD_BT2020):
+    case static_cast<int32_t>(
+        common::Dataspace::STANDARD_BT2020_CONSTANT_LUMINANCE):
+      return BufferColorSpace::kItuRec2020;
+    case static_cast<int32_t>(common::Dataspace::UNKNOWN):
+      return BufferColorSpace::kUndefined;
+    default:
+      ALOGE("Unsupported standard: %d", standard);
+      return std::nullopt;
+  }
+}
+
+std::optional<BufferSampleRange> AidlToSampleRange(
+    const std::optional<ParcelableDataspace>& dataspace) {
+  if (!dataspace) {
+    return std::nullopt;
+  }
+
+  int32_t sample_range = static_cast<int32_t>(dataspace->dataspace) &
+                         static_cast<int32_t>(common::Dataspace::RANGE_MASK);
+  switch (sample_range) {
+    case static_cast<int32_t>(common::Dataspace::RANGE_FULL):
+      return BufferSampleRange::kFullRange;
+    case static_cast<int32_t>(common::Dataspace::RANGE_LIMITED):
+      return BufferSampleRange::kLimitedRange;
+    case static_cast<int32_t>(common::Dataspace::UNKNOWN):
+      return BufferSampleRange::kUndefined;
+    default:
+      ALOGE("Unsupported sample range: %d", sample_range);
+      return std::nullopt;
+  }
+}
+
+bool IsSupportedCompositionType(
+    const std::optional<ParcelableComposition> composition) {
+  if (!composition) {
+    return true;
+  }
+  switch (composition->composition) {
+    case Composition::INVALID:
+    case Composition::CLIENT:
+    case Composition::DEVICE:
+    case Composition::SOLID_COLOR:
+    case Composition::CURSOR:
+      return true;
+
+    // Unsupported composition types. Set an error for the current
+    // DisplayCommand and return.
+    case Composition::DISPLAY_DECORATION:
+    case Composition::SIDEBAND:
+#if __ANDROID_API__ >= 34
+    case Composition::REFRESH_RATE_INDICATOR:
+#endif
+      return false;
+  }
+}
+
+bool ValidateLayerBrightness(const std::optional<LayerBrightness>& brightness) {
+  if (!brightness) {
+    return true;
+  }
+  return !(std::signbit(brightness->brightness) ||
+           std::isnan(brightness->brightness));
+}
+
+std::optional<HWC2::Composition> AidlToCompositionType(
+    const std::optional<ParcelableComposition> composition) {
+  if (!composition) {
+    return std::nullopt;
+  }
+
+  switch (composition->composition) {
+    case Composition::INVALID:
+      return HWC2::Composition::Invalid;
+    case Composition::CLIENT:
+      return HWC2::Composition::Client;
+    case Composition::DEVICE:
+      return HWC2::Composition::Device;
+    case Composition::SOLID_COLOR:
+      return HWC2::Composition::SolidColor;
+    case Composition::CURSOR:
+      return HWC2::Composition::Cursor;
+
+    // Unsupported composition types.
+    case Composition::DISPLAY_DECORATION:
+    case Composition::SIDEBAND:
+#if __ANDROID_API__ >= 34
+    case Composition::REFRESH_RATE_INDICATOR:
+#endif
+      ALOGE("Unsupported composition type: %s",
+            toString(composition->composition).c_str());
+      return std::nullopt;
+  }
+}
+
+#if __ANDROID_API__ < 35
+
+class DisplayConfiguration {
+ public:
+  class Dpi {
+   public:
+    float x = 0.000000F;
+    float y = 0.000000F;
+  };
+  // NOLINTNEXTLINE(readability-identifier-naming)
+  int32_t configId = 0;
+  int32_t width = 0;
+  int32_t height = 0;
+  std::optional<Dpi> dpi;
+  // NOLINTNEXTLINE(readability-identifier-naming)
+  int32_t configGroup = 0;
+  // NOLINTNEXTLINE(readability-identifier-naming)
+  int32_t vsyncPeriod = 0;
+};
+
+#endif
+
+DisplayConfiguration HwcDisplayConfigToAidlConfiguration(
+    const HwcDisplayConfigs& configs, const HwcDisplayConfig& config) {
+  DisplayConfiguration aidl_configuration =
+      {.configId = static_cast<int32_t>(config.id),
+       .width = config.mode.GetRawMode().hdisplay,
+       .height = config.mode.GetRawMode().vdisplay,
+       .configGroup = static_cast<int32_t>(config.group_id),
+       .vsyncPeriod = config.mode.GetVSyncPeriodNs()};
+
+  if (configs.mm_width != 0) {
+    // ideally this should be vdisplay/mm_heigth, however mm_height
+    // comes from edid parsing and is highly unreliable. Viewing the
+    // rarity of anisotropic displays, falling back to a single value
+    // for dpi yield more correct output.
+    static const float kMmPerInch = 25.4;
+    float dpi = float(config.mode.GetRawMode().hdisplay) * kMmPerInch /
+                float(configs.mm_width);
+    aidl_configuration.dpi = {.x = dpi, .y = dpi};
+  }
+  // TODO: Populate vrrConfig.
+  return aidl_configuration;
+}
+
+std::optional<hwc_rect> AidlToRect(const std::optional<common::Rect>& rect) {
+  if (!rect) {
+    return std::nullopt;
+  }
+  return hwc_rect{rect->left, rect->top, rect->right, rect->bottom};
+}
+
+std::optional<hwc_frect> AidlToFRect(const std::optional<common::FRect>& rect) {
+  if (!rect) {
+    return std::nullopt;
+  }
+  return hwc_frect{rect->left, rect->top, rect->right, rect->bottom};
+}
+
+std::optional<float> AidlToAlpha(const std::optional<PlaneAlpha>& alpha) {
+  if (!alpha) {
+    return std::nullopt;
+  }
+  return alpha->alpha;
+}
+
+std::optional<uint32_t> AidlToZOrder(const std::optional<ZOrder>& z_order) {
+  if (!z_order) {
+    return std::nullopt;
+  }
+  return z_order->z;
+}
+
+std::optional<LayerTransform> AidlToLayerTransform(
+    const std::optional<ParcelableTransform>& aidl_transform) {
+  if (!aidl_transform) {
+    return std::nullopt;
+  }
+
+  uint32_t transform = LayerTransform::kIdentity;
+  // 270* and 180* cannot be combined with flips. More specifically, they
+  // already contain both horizontal and vertical flips, so those fields are
+  // redundant in this case. 90* rotation can be combined with either horizontal
+  // flip or vertical flip, so treat it differently
+  if (aidl_transform->transform == common::Transform::ROT_270) {
+    transform = LayerTransform::kRotate270;
+  } else if (aidl_transform->transform == common::Transform::ROT_180) {
+    transform = LayerTransform::kRotate180;
+  } else {
+    auto aidl_transform_bits = static_cast<uint32_t>(aidl_transform->transform);
+    if ((aidl_transform_bits &
+         static_cast<uint32_t>(common::Transform::FLIP_H)) != 0)
+      transform |= LayerTransform::kFlipH;
+    if ((aidl_transform_bits &
+         static_cast<uint32_t>(common::Transform::FLIP_V)) != 0)
+      transform |= LayerTransform::kFlipV;
+    if ((aidl_transform_bits &
+         static_cast<uint32_t>(common::Transform::ROT_90)) != 0)
+      transform |= LayerTransform::kRotate90;
+  }
+  return static_cast<LayerTransform>(transform);
+}
+
 }  // namespace
 
 ComposerClient::ComposerClient() {
@@ -202,9 +441,15 @@ hwc3::Error ComposerClient::ValidateDisplayInternal(
     return Hwc2toHwc3Error(hwc2_error);
   }
 
+  hwc3::Error error = Hwc2toHwc3Error(
+      display.GetChangedCompositionTypes(&num_types, nullptr, nullptr));
+  if (error != hwc3::Error::kNone) {
+    return error;
+  }
+
   std::vector<hwc2_layer_t> hwc_changed_layers(num_types);
   std::vector<int32_t> hwc_composition_types(num_types);
-  hwc3::Error error = Hwc2toHwc3Error(
+  error = Hwc2toHwc3Error(
       display.GetChangedCompositionTypes(&num_types, hwc_changed_layers.data(),
                                          hwc_composition_types.data()));
   if (error != hwc3::Error::kNone) {
@@ -300,39 +545,46 @@ void ComposerClient::DispatchLayerCommand(int64_t display_id,
     return;
   }
 
-  HwcLayerWrapper layer_wrapper{command.layer, layer};
-  if (command.buffer) {
-    ExecuteSetLayerBuffer(display_id, layer_wrapper, *command.buffer);
-  }
-  if (command.blendMode) {
-    ExecuteSetLayerBlendMode(display_id, layer_wrapper, *command.blendMode);
-  }
-  if (command.composition) {
-    ExecuteSetLayerComposition(display_id, layer_wrapper, *command.composition);
-  }
-  if (command.dataspace) {
-    ExecuteSetLayerDataspace(display_id, layer_wrapper, *command.dataspace);
-  }
-  if (command.displayFrame) {
-    ExecuteSetLayerDisplayFrame(display_id, layer_wrapper,
-                                *command.displayFrame);
-  }
-  if (command.planeAlpha) {
-    ExecuteSetLayerPlaneAlpha(display_id, layer_wrapper, *command.planeAlpha);
-  }
-  if (command.sourceCrop) {
-    ExecuteSetLayerSourceCrop(display_id, layer_wrapper, *command.sourceCrop);
-  }
-  if (command.transform) {
-    ExecuteSetLayerTransform(display_id, layer_wrapper, *command.transform);
+  // If the requested composition type is not supported, the HWC should return
+  // an error and not process any further commands.
+  if (!IsSupportedCompositionType(command.composition)) {
+    cmd_result_writer_->AddError(hwc3::Error::kUnsupported);
+    return;
   }
-  if (command.z) {
-    ExecuteSetLayerZOrder(display_id, layer_wrapper, *command.z);
+
+  // For some invalid parameters, the HWC should return an error and not process
+  // any further commands.
+  if (!ValidateLayerBrightness(command.brightness)) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadParameter);
+    return;
   }
-  if (command.brightness) {
-    ExecuteSetLayerBrightness(display_id, layer_wrapper, *command.brightness);
+
+  HwcLayer::LayerProperties properties;
+  if (command.buffer) {
+    HwcLayer::Buffer buffer;
+    auto err = ImportLayerBuffer(display_id, command.layer, *command.buffer,
+                                 &buffer.buffer_handle);
+    if (err != hwc3::Error::kNone) {
+      cmd_result_writer_->AddError(err);
+      return;
+    }
+    buffer.acquire_fence = ::android::MakeSharedFd(
+        command.buffer->fence.dup().release());
+    properties.buffer.emplace(buffer);
   }
 
+  properties.blend_mode = AidlToBlendMode(command.blendMode);
+  properties.color_space = AidlToColorSpace(command.dataspace);
+  properties.sample_range = AidlToSampleRange(command.dataspace);
+  properties.composition_type = AidlToCompositionType(command.composition);
+  properties.display_frame = AidlToRect(command.displayFrame);
+  properties.alpha = AidlToAlpha(command.planeAlpha);
+  properties.source_crop = AidlToFRect(command.sourceCrop);
+  properties.transform = AidlToLayerTransform(command.transform);
+  properties.z_order = AidlToZOrder(command.z);
+
+  layer->SetLayerProperties(properties);
+
   // Some unsupported functionality returns kUnsupported, and others
   // are just a no-op.
   // TODO: Audit whether some of these should actually return kUnsupported
@@ -340,6 +592,9 @@ void ComposerClient::DispatchLayerCommand(int64_t display_id,
   if (command.sidebandStream) {
     cmd_result_writer_->AddError(hwc3::Error::kUnsupported);
   }
+  if (command.luts) {
+    cmd_result_writer_->AddError(hwc3::Error::kUnsupported);
+  }
   // TODO: Blocking region handling missing.
   // TODO: Layer surface damage.
   // TODO: Layer visible region.
@@ -356,13 +611,16 @@ void ComposerClient::ExecuteDisplayCommand(const DisplayCommand& command) {
     return;
   }
 
+  if (command.brightness) {
+    // TODO: Implement support for display brightness.
+    cmd_result_writer_->AddError(hwc3::Error::kUnsupported);
+    return;
+  }
+
   for (const auto& layer_cmd : command.layers) {
     DispatchLayerCommand(command.display, layer_cmd);
   }
 
-  if (command.brightness) {
-    ExecuteSetDisplayBrightness(command.display, *command.brightness);
-  }
   if (command.colorTransformMatrix) {
     ExecuteSetDisplayColorTransform(command.display,
                                     *command.colorTransformMatrix);
@@ -405,7 +663,7 @@ ndk::ScopedAStatus ComposerClient::executeCommands(
 }
 
 ndk::ScopedAStatus ComposerClient::getActiveConfig(int64_t display_id,
-                                                   int32_t* config) {
+                                                   int32_t* config_id) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
   HwcDisplay* display = GetDisplay(display_id);
@@ -413,13 +671,12 @@ ndk::ScopedAStatus ComposerClient::getActiveConfig(int64_t display_id,
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  uint32_t hwc2_config = 0;
-  const hwc3::Error error = Hwc2toHwc3Error(
-      display->GetActiveConfig(&hwc2_config));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
+  const HwcDisplayConfig* config = display->GetLastRequestedConfig();
+  if (config == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadConfig);
   }
-  *config = Hwc2ConfigIdToHwc3(hwc2_config);
+
+  *config_id = Hwc2ConfigIdToHwc3(config->id);
   return ndk::ScopedAStatus::ok();
 }
 
@@ -467,7 +724,7 @@ ndk::ScopedAStatus ComposerClient::getDataspaceSaturationMatrix(
 }
 
 ndk::ScopedAStatus ComposerClient::getDisplayAttribute(
-    int64_t display_id, int32_t config, DisplayAttribute attribute,
+    int64_t display_id, int32_t config_id, DisplayAttribute attribute,
     int32_t* value) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
@@ -476,11 +733,46 @@ ndk::ScopedAStatus ComposerClient::getDisplayAttribute(
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  const hwc3::Error error = Hwc2toHwc3Error(
-      display->GetDisplayAttribute(Hwc3ConfigIdToHwc2(config),
-                                   Hwc3DisplayAttributeToHwc2(attribute),
-                                   value));
-  return ToBinderStatus(error);
+  const HwcDisplayConfigs& configs = display->GetDisplayConfigs();
+  auto config = configs.hwc_configs.find(config_id);
+  if (config == configs.hwc_configs.end()) {
+    return ToBinderStatus(hwc3::Error::kBadConfig);
+  }
+
+  DisplayConfiguration
+      aidl_configuration = HwcDisplayConfigToAidlConfiguration(configs,
+                                                               config->second);
+  // Legacy API for querying DPI uses units of dots per 1000 inches.
+  static const int kLegacyDpiUnit = 1000;
+  switch (attribute) {
+    case DisplayAttribute::WIDTH:
+      *value = aidl_configuration.width;
+      break;
+    case DisplayAttribute::HEIGHT:
+      *value = aidl_configuration.height;
+      break;
+    case DisplayAttribute::VSYNC_PERIOD:
+      *value = aidl_configuration.vsyncPeriod;
+      break;
+    case DisplayAttribute::DPI_X:
+      *value = aidl_configuration.dpi
+                   ? static_cast<int>(aidl_configuration.dpi->x *
+                                      kLegacyDpiUnit)
+                   : -1;
+      break;
+    case DisplayAttribute::DPI_Y:
+      *value = aidl_configuration.dpi
+                   ? static_cast<int>(aidl_configuration.dpi->y *
+                                      kLegacyDpiUnit)
+                   : -1;
+      break;
+    case DisplayAttribute::CONFIG_GROUP:
+      *value = aidl_configuration.configGroup;
+      break;
+    case DisplayAttribute::INVALID:
+      return ToBinderStatus(hwc3::Error::kUnsupported);
+  }
+  return ndk::ScopedAStatus::ok();
 }
 
 ndk::ScopedAStatus ComposerClient::getDisplayCapabilities(
@@ -514,7 +806,7 @@ ndk::ScopedAStatus ComposerClient::getDisplayCapabilities(
 }
 
 ndk::ScopedAStatus ComposerClient::getDisplayConfigs(
-    int64_t display_id, std::vector<int32_t>* configs) {
+    int64_t display_id, std::vector<int32_t>* out_configs) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
   HwcDisplay* display = GetDisplay(display_id);
@@ -522,23 +814,9 @@ ndk::ScopedAStatus ComposerClient::getDisplayConfigs(
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  uint32_t num_configs = 0;
-  hwc3::Error error = Hwc2toHwc3Error(
-      display->LegacyGetDisplayConfigs(&num_configs, nullptr));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
-
-  std::vector<hwc2_config_t> out_configs(num_configs);
-  error = Hwc2toHwc3Error(
-      display->LegacyGetDisplayConfigs(&num_configs, out_configs.data()));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
-
-  configs->reserve(num_configs);
-  for (const auto config : out_configs) {
-    configs->emplace_back(Hwc2ConfigIdToHwc3(config));
+  const HwcDisplayConfigs& configs = display->GetDisplayConfigs();
+  for (const auto& [id, config] : configs.hwc_configs) {
+    out_configs->push_back(static_cast<int32_t>(id));
   }
   return ndk::ScopedAStatus::ok();
 }
@@ -621,14 +899,15 @@ ndk::ScopedAStatus ComposerClient::getDisplayVsyncPeriod(
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  uint32_t hwc2_vsync_period = 0;
-  auto error = Hwc2toHwc3Error(
-      display->GetDisplayVsyncPeriod(&hwc2_vsync_period));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
+  // getDisplayVsyncPeriod should return the vsync period of the config that
+  // is currently committed to the kernel. If a config change is pending due to
+  // setActiveConfigWithConstraints, return the pre-change vsync period.
+  const HwcDisplayConfig* config = display->GetCurrentConfig();
+  if (config == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadConfig);
   }
 
-  *vsync_period = static_cast<int32_t>(hwc2_vsync_period);
+  *vsync_period = config->mode.GetVSyncPeriodNs();
   return ndk::ScopedAStatus::ok();
 }
 
@@ -648,13 +927,40 @@ ndk::ScopedAStatus ComposerClient::getDisplayedContentSamplingAttributes(
 ndk::ScopedAStatus ComposerClient::getDisplayPhysicalOrientation(
     int64_t display_id, common::Transform* orientation) {
   DEBUG_FUNC();
+
+  if (orientation == nullptr) {
+    ALOGE("Invalid 'orientation' pointer.");
+    return ToBinderStatus(hwc3::Error::kBadParameter);
+  }
+
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
   HwcDisplay* display = GetDisplay(display_id);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  *orientation = common::Transform::NONE;
+  PanelOrientation
+      drm_orientation = display->getDisplayPhysicalOrientation().value_or(
+          PanelOrientation::kModePanelOrientationNormal);
+
+  switch (drm_orientation) {
+    case PanelOrientation::kModePanelOrientationNormal:
+      *orientation = common::Transform::NONE;
+      break;
+    case PanelOrientation::kModePanelOrientationBottomUp:
+      *orientation = common::Transform::ROT_180;
+      break;
+    case PanelOrientation::kModePanelOrientationLeftUp:
+      *orientation = common::Transform::ROT_270;
+      break;
+    case PanelOrientation::kModePanelOrientationRightUp:
+      *orientation = common::Transform::ROT_90;
+      break;
+    default:
+      ALOGE("Unknown panel orientation value: %d", drm_orientation);
+      return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
   return ndk::ScopedAStatus::ok();
 }
 
@@ -738,24 +1044,8 @@ ndk::ScopedAStatus ComposerClient::getSupportedContentTypes(
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  uint32_t out_num_supported_types = 0;
-  auto error = Hwc2toHwc3Error(
-      display->GetSupportedContentTypes(&out_num_supported_types, nullptr));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
-
-  std::vector<uint32_t> out_supported_types(out_num_supported_types);
-  error = Hwc2toHwc3Error(
-      display->GetSupportedContentTypes(&out_num_supported_types,
-                                        out_supported_types.data()));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
-
-  for (const auto type : out_supported_types) {
-    types->push_back(Hwc2ContentTypeToHwc3(type));
-  }
+  // Support for ContentType is not implemented.
+  types->clear();
   return ndk::ScopedAStatus::ok();
 }
 
@@ -778,13 +1068,14 @@ ndk::ScopedAStatus ComposerClient::registerCallback(
 ndk::ScopedAStatus ComposerClient::setActiveConfig(int64_t display_id,
                                                    int32_t config) {
   DEBUG_FUNC();
-  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
-  if (display == nullptr) {
-    return ToBinderStatus(hwc3::Error::kBadDisplay);
-  }
 
-  return ToBinderStatus(Hwc2toHwc3Error(display->SetActiveConfig(config)));
+  VsyncPeriodChangeTimeline timeline;
+  VsyncPeriodChangeConstraints constraints = {
+      .desiredTimeNanos = ::android::ResourceManager::GetTimeMonotonicNs(),
+      .seamlessRequired = false,
+  };
+  return setActiveConfigWithConstraints(display_id, config, constraints,
+                                        &timeline);
 }
 
 ndk::ScopedAStatus ComposerClient::setActiveConfigWithConstraints(
@@ -798,23 +1089,47 @@ ndk::ScopedAStatus ComposerClient::setActiveConfigWithConstraints(
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  hwc_vsync_period_change_constraints_t hwc2_constraints;
-  hwc2_constraints.desiredTimeNanos = constraints.desiredTimeNanos;
-  hwc2_constraints.seamlessRequired = static_cast<uint8_t>(
-      constraints.seamlessRequired);
-
-  hwc_vsync_period_change_timeline_t hwc2_timeline{};
-  auto error = Hwc2toHwc3Error(
-      display->SetActiveConfigWithConstraints(config, &hwc2_constraints,
-                                              &hwc2_timeline));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
+  if (constraints.seamlessRequired) {
+    return ToBinderStatus(hwc3::Error::kSeamlessNotAllowed);
+  }
+
+  const bool future_config = constraints.desiredTimeNanos >
+                             ::android::ResourceManager::GetTimeMonotonicNs();
+  const HwcDisplayConfig* current_config = display->GetCurrentConfig();
+  const HwcDisplayConfig* next_config = display->GetConfig(config);
+  const bool same_config_group = current_config != nullptr &&
+                                 next_config != nullptr &&
+                                 current_config->group_id ==
+                                     next_config->group_id;
+  // If the contraints dictate that this is to be applied in the future, it
+  // must be queued. If the new config is in the same config group as the
+  // current one, then queue it to reduce jank.
+  HwcDisplay::ConfigError result{};
+  if (future_config || same_config_group) {
+    QueuedConfigTiming timing = {};
+    result = display->QueueConfig(config, constraints.desiredTimeNanos,
+                                  constraints.seamlessRequired, &timing);
+    timeline->newVsyncAppliedTimeNanos = timing.new_vsync_time_ns;
+    timeline->refreshTimeNanos = timing.refresh_time_ns;
+    timeline->refreshRequired = true;
+  } else {
+    // Fall back to a blocking commit, which may modeset.
+    result = display->SetConfig(config);
+    timeline->newVsyncAppliedTimeNanos = ::android::ResourceManager::
+        GetTimeMonotonicNs();
+    timeline->refreshRequired = false;
+  }
+
+  switch (result) {
+    case HwcDisplay::ConfigError::kBadConfig:
+      return ToBinderStatus(hwc3::Error::kBadConfig);
+    case HwcDisplay::ConfigError::kSeamlessNotAllowed:
+      return ToBinderStatus(hwc3::Error::kSeamlessNotAllowed);
+    case HwcDisplay::ConfigError::kSeamlessNotPossible:
+      return ToBinderStatus(hwc3::Error::kSeamlessNotPossible);
+    case HwcDisplay::ConfigError::kNone:
+      return ndk::ScopedAStatus::ok();
   }
-
-  timeline->refreshTimeNanos = hwc2_timeline.refreshTimeNanos;
-  timeline->newVsyncAppliedTimeNanos = hwc2_timeline.newVsyncAppliedTimeNanos;
-  timeline->refreshRequired = static_cast<bool>(hwc2_timeline.refreshRequired);
-  return ndk::ScopedAStatus::ok();
 }
 
 ndk::ScopedAStatus ComposerClient::setBootDisplayConfig(int64_t /*display_id*/,
@@ -879,8 +1194,10 @@ ndk::ScopedAStatus ComposerClient::setContentType(int64_t display_id,
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  auto error = display->SetContentType(Hwc3ContentTypeToHwc2(type));
-  return ToBinderStatus(Hwc2toHwc3Error(error));
+  if (type == ContentType::NONE) {
+    return ndk::ScopedAStatus::ok();
+  }
+  return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
 ndk::ScopedAStatus ComposerClient::setDisplayedContentSamplingEnabled(
@@ -933,6 +1250,8 @@ ndk::ScopedAStatus ComposerClient::setIdleTimerEnabled(int64_t /*display_id*/,
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
+#if __ANDROID_API__ >= 34
+
 ndk::ScopedAStatus ComposerClient::getOverlaySupport(
     OverlayProperties* /*out_overlay_properties*/) {
   return ToBinderStatus(hwc3::Error::kUnsupported);
@@ -954,6 +1273,10 @@ ndk::ScopedAStatus ComposerClient::setRefreshRateChangedCallbackDebugEnabled(
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
+#endif
+
+#if __ANDROID_API__ >= 35
+
 ndk::ScopedAStatus ComposerClient::getDisplayConfigurations(
     int64_t display_id, int32_t /*max_frame_interval_ns*/,
     std::vector<DisplayConfiguration>* configurations) {
@@ -966,28 +1289,8 @@ ndk::ScopedAStatus ComposerClient::getDisplayConfigurations(
 
   const HwcDisplayConfigs& configs = display->GetDisplayConfigs();
   for (const auto& [id, config] : configs.hwc_configs) {
-    static const int kNanosecondsPerSecond = 1E9;
-    configurations->emplace_back(
-        DisplayConfiguration{.configId = static_cast<int32_t>(config.id),
-                             .width = config.mode.GetRawMode().hdisplay,
-                             .height = config.mode.GetRawMode().vdisplay,
-                             .configGroup = static_cast<int32_t>(
-                                 config.group_id),
-                             .vsyncPeriod = static_cast<int>(kNanosecondsPerSecond * double(
-                                 1 / config.mode.GetVRefresh()))});
-
-    if (configs.mm_width != 0) {
-      // ideally this should be vdisplay/mm_heigth, however mm_height
-      // comes from edid parsing and is highly unreliable. Viewing the
-      // rarity of anisotropic displays, falling back to a single value
-      // for dpi yield more correct output.
-      static const float kMmPerInch = 25.4;
-      float dpi = float(config.mode.GetRawMode().hdisplay) * kMmPerInch /
-                  float(configs.mm_width);
-      configurations->back().dpi = {.x = dpi, .y = dpi};
-    }
-
-    // TODO: Populate vrrConfig.
+    configurations->push_back(
+        HwcDisplayConfigToAidlConfiguration(configs, config));
   }
   return ndk::ScopedAStatus::ok();
 }
@@ -998,6 +1301,22 @@ ndk::ScopedAStatus ComposerClient::notifyExpectedPresent(
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
+ndk::ScopedAStatus ComposerClient::startHdcpNegotiation(
+    int64_t /*display*/, const AidlHdcpLevels& /*levels*/) {
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+#endif
+
+ndk::ScopedAStatus ComposerClient::getMaxLayerPictureProfiles(int64_t, int32_t*) {
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getLuts(int64_t, const std::vector<Buffer>&,
+    std::vector<Luts>*) {
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
 std::string ComposerClient::Dump() {
   uint32_t size = 0;
   hwc_->Dump(&size, nullptr);
@@ -1013,139 +1332,18 @@ std::string ComposerClient::Dump() {
   return binder;
 }
 
-void ComposerClient::ExecuteSetLayerBuffer(int64_t display_id,
-                                           HwcLayerWrapper& layer,
-                                           const Buffer& buffer) {
-  buffer_handle_t imported_buffer = nullptr;
+hwc3::Error ComposerClient::ImportLayerBuffer(
+    int64_t display_id, int64_t layer_id, const Buffer& buffer,
+    buffer_handle_t* out_imported_buffer) {
+  *out_imported_buffer = nullptr;
 
   auto releaser = composer_resources_->CreateResourceReleaser(true);
-  auto err = composer_resources_->GetLayerBuffer(display_id, layer.layer_id,
-                                                 buffer, &imported_buffer,
+  auto err = composer_resources_->GetLayerBuffer(display_id, layer_id, buffer,
+                                                 out_imported_buffer,
                                                  releaser.get());
-  if (err != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(err);
-    return;
-  }
-
-  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
-  auto fence_fd = const_cast<ndk::ScopedFileDescriptor&>(buffer.fence)
-                      .release();
-  err = Hwc2toHwc3Error(layer.layer->SetLayerBuffer(imported_buffer, fence_fd));
-  if (err != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(err);
-  }
-}
-
-void ComposerClient::ExecuteSetLayerBlendMode(
-    int64_t /*display_id*/, HwcLayerWrapper& layer,
-    const ParcelableBlendMode& blend_mode) {
-  auto err = Hwc2toHwc3Error(layer.layer->SetLayerBlendMode(
-      Hwc3BlendModeToHwc2(blend_mode.blendMode)));
-  if (err != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(err);
-  }
-}
-
-void ComposerClient::ExecuteSetLayerComposition(
-    int64_t /*display_id*/, HwcLayerWrapper& layer,
-    const ParcelableComposition& composition) {
-  hwc3::Error error = hwc3::Error::kNone;
-  switch (composition.composition) {
-      // Unsupported composition types should set an error for the current
-      // DisplayCommand.
-    case Composition::DISPLAY_DECORATION:
-    case Composition::SIDEBAND:
-      error = hwc3::Error::kUnsupported;
-      break;
-    default:
-      error = Hwc2toHwc3Error(layer.layer->SetLayerCompositionType(
-          Hwc3CompositionToHwc2(composition.composition)));
-  }
-  if (error != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(error);
-  }
-}
-
-void ComposerClient::ExecuteSetLayerDataspace(
-    int64_t /*display_id*/, HwcLayerWrapper& layer,
-    const ParcelableDataspace& dataspace) {
-  auto err = Hwc2toHwc3Error(
-      layer.layer->SetLayerDataspace(Hwc3DataspaceToHwc2(dataspace.dataspace)));
-  if (err != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(err);
-  }
-}
-
-void ComposerClient::ExecuteSetLayerDisplayFrame(int64_t /*display_id*/,
-                                                 HwcLayerWrapper& layer,
-                                                 const common::Rect& rect) {
-  const hwc_rect_t hwc2_rect{rect.left, rect.top, rect.right, rect.bottom};
-  auto err = Hwc2toHwc3Error(layer.layer->SetLayerDisplayFrame(hwc2_rect));
-  if (err != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(err);
-  }
-}
-void ComposerClient::ExecuteSetLayerPlaneAlpha(int64_t /*display_id*/,
-                                               HwcLayerWrapper& layer,
-                                               const PlaneAlpha& plane_alpha) {
-  auto err = Hwc2toHwc3Error(
-      layer.layer->SetLayerPlaneAlpha(plane_alpha.alpha));
-  if (err != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(err);
-  }
-}
-
-void ComposerClient::ExecuteSetLayerSourceCrop(
-    int64_t /*display_id*/, HwcLayerWrapper& layer,
-    const common::FRect& source_crop) {
-  const hwc_frect_t rect{source_crop.left, source_crop.top, source_crop.right,
-                         source_crop.bottom};
-  auto err = Hwc2toHwc3Error(layer.layer->SetLayerSourceCrop(rect));
-  if (err != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(err);
-  }
-}
-void ComposerClient::ExecuteSetLayerTransform(
-    int64_t /*display_id*/, HwcLayerWrapper& layer,
-    const ParcelableTransform& transform) {
-  auto err = Hwc2toHwc3Error(
-      layer.layer->SetLayerTransform(Hwc3TransformToHwc2(transform.transform)));
-  if (err != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(err);
-  }
-}
-void ComposerClient::ExecuteSetLayerZOrder(int64_t /*display_id*/,
-                                           HwcLayerWrapper& layer,
-                                           const ZOrder& z_order) {
-  auto err = Hwc2toHwc3Error(layer.layer->SetLayerZOrder(z_order.z));
-  if (err != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(err);
-  }
+  return err;
 }
 
-void ComposerClient::ExecuteSetLayerBrightness(
-    int64_t /*display_id*/, HwcLayerWrapper& /*layer*/,
-    const LayerBrightness& brightness) {
-  if (std::signbit(brightness.brightness) ||
-      std::isnan(brightness.brightness)) {
-    cmd_result_writer_->AddError(hwc3::Error::kBadParameter);
-  }
-}
-
-void ComposerClient::ExecuteSetDisplayBrightness(
-    uint64_t display_id, const DisplayBrightness& command) {
-  auto* display = GetDisplay(display_id);
-  if (display == nullptr) {
-    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
-    return;
-  }
-
-  auto error = Hwc2toHwc3Error(
-      display->SetDisplayBrightness(command.brightness));
-  if (error != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(error);
-  }
-}
 void ComposerClient::ExecuteSetDisplayColorTransform(
     uint64_t display_id, const std::vector<float>& matrix) {
   auto* display = GetDisplay(display_id);
diff --git a/hwc3/ComposerClient.h b/hwc3/ComposerClient.h
index f6362ad..2595203 100644
--- a/hwc3/ComposerClient.h
+++ b/hwc3/ComposerClient.h
@@ -25,6 +25,7 @@
 #include "hwc3/Utils.h"
 #include "utils/Mutex.h"
 
+using AidlHdcpLevels = aidl::android::hardware::drm::HdcpLevels;
 using AidlPixelFormat = aidl::android::hardware::graphics::common::PixelFormat;
 using AidlNativeHandle = aidl::android::hardware::common::NativeHandle;
 
@@ -39,11 +40,6 @@ namespace aidl::android::hardware::graphics::composer3::impl {
 
 class DrmHwcThree;
 
-struct HwcLayerWrapper {
-  int64_t layer_id;
-  ::android::HwcLayer* layer;
-};
-
 class ComposerClient : public BnComposerClient {
  public:
   ComposerClient();
@@ -136,6 +132,9 @@ class ComposerClient : public BnComposerClient {
   ndk::ScopedAStatus setVsyncEnabled(int64_t display, bool enabled) override;
   ndk::ScopedAStatus setIdleTimerEnabled(int64_t display,
                                          int32_t timeout) override;
+
+#if __ANDROID_API__ >= 34
+
   ndk::ScopedAStatus getOverlaySupport(
       OverlayProperties* out_overlay_properties) override;
   ndk::ScopedAStatus getHdrConversionCapabilities(
@@ -145,44 +144,40 @@ class ComposerClient : public BnComposerClient {
       common::Hdr* out_hdr) override;
   ndk::ScopedAStatus setRefreshRateChangedCallbackDebugEnabled(
       int64_t display, bool enabled) override;
+
+#endif
+
+#if __ANDROID_API__ >= 35
+
   ndk::ScopedAStatus getDisplayConfigurations(
       int64_t display, int32_t max_frame_interval_ns,
       std::vector<DisplayConfiguration>* configurations) override;
   ndk::ScopedAStatus notifyExpectedPresent(
       int64_t display, const ClockMonotonicTimestamp& expected_present_time,
       int32_t frame_interval_ns) override;
+  ndk::ScopedAStatus startHdcpNegotiation(int64_t display,
+      const AidlHdcpLevels& levels) override;
+
+#endif
+
+  ndk::ScopedAStatus getMaxLayerPictureProfiles(
+      int64_t display, int32_t* maxProfiles) override;
+  ndk::ScopedAStatus getLuts(int64_t, const std::vector<Buffer>&,
+                             std::vector<Luts>* out_luts) override;
 
  protected:
   ::ndk::SpAIBinder createBinder() override;
 
  private:
+  hwc3::Error ImportLayerBuffer(int64_t display_id, int64_t layer_id,
+                                const Buffer& buffer,
+                                buffer_handle_t* out_imported_buffer);
+
   // Layer commands
   void DispatchLayerCommand(int64_t display_id, const LayerCommand& command);
-  void ExecuteSetLayerBuffer(int64_t display_id, HwcLayerWrapper& layer_id,
-                             const Buffer& buffer);
-  void ExecuteSetLayerBlendMode(int64_t display_id, HwcLayerWrapper& layer,
-                                const ParcelableBlendMode& blend_mode);
-  void ExecuteSetLayerComposition(int64_t display_id, HwcLayerWrapper& layer,
-                                  const ParcelableComposition& composition);
-  void ExecuteSetLayerDataspace(int64_t display_id, HwcLayerWrapper& layer,
-                                const ParcelableDataspace& dataspace);
-  void ExecuteSetLayerDisplayFrame(int64_t display_id, HwcLayerWrapper& layer,
-                                   const common::Rect& rect);
-  void ExecuteSetLayerPlaneAlpha(int64_t display_id, HwcLayerWrapper& layer,
-                                 const PlaneAlpha& plane_alpha);
-  void ExecuteSetLayerSourceCrop(int64_t display_id, HwcLayerWrapper& layer,
-                                 const common::FRect& source_crop);
-  void ExecuteSetLayerTransform(int64_t display_id, HwcLayerWrapper& layer,
-                                const ParcelableTransform& transform);
-  void ExecuteSetLayerZOrder(int64_t display_id, HwcLayerWrapper& layer,
-                             const ZOrder& z_order);
-  void ExecuteSetLayerBrightness(int64_t display_id, HwcLayerWrapper& layer,
-                                 const LayerBrightness& brightness);
 
   // Display commands
   void ExecuteDisplayCommand(const DisplayCommand& command);
-  void ExecuteSetDisplayBrightness(uint64_t display_id,
-                                   const DisplayBrightness& command);
   void ExecuteSetDisplayColorTransform(uint64_t display_id,
                                        const std::vector<float>& matrix);
   void ExecuteSetDisplayClientTarget(uint64_t display_id,
diff --git a/hwc3/DrmHwcThree.cpp b/hwc3/DrmHwcThree.cpp
index d758865..fb14bc9 100644
--- a/hwc3/DrmHwcThree.cpp
+++ b/hwc3/DrmHwcThree.cpp
@@ -14,13 +14,17 @@
  * limitations under the License.
  */
 
+#define LOG_TAG "drmhwc"
+
 #include "DrmHwcThree.h"
 
 #include <cinttypes>
 
 #include "Utils.h"
 #include "aidl/android/hardware/graphics/common/Dataspace.h"
+#if __ANDROID_API__ >= 35
 #include "aidl/android/hardware/graphics/common/DisplayHotplugEvent.h"
+#endif
 
 namespace aidl::android::hardware::graphics::composer3::impl {
 
@@ -59,13 +63,38 @@ void DrmHwcThree::SendVsyncEventToClient(uint64_t display_id, int64_t timestamp,
                               static_cast<int32_t>(vsync_period));
 }
 
-void DrmHwcThree::SendHotplugEventToClient(hwc2_display_t display_id,
-                                           bool connected) {
-  HandleDisplayHotplugEvent(static_cast<uint64_t>(display_id), connected);
-  common::DisplayHotplugEvent event = connected ? common::DisplayHotplugEvent::CONNECTED : common::DisplayHotplugEvent::DISCONNECTED;
+#if __ANDROID_API__ >= 35
+
+void DrmHwcThree::SendHotplugEventToClient(
+    hwc2_display_t display_id, DrmHwc::DisplayStatus display_status) {
+  common::DisplayHotplugEvent event = common::DisplayHotplugEvent::DISCONNECTED;
+  switch (display_status) {
+    case DrmHwc::kDisconnected:
+      event = common::DisplayHotplugEvent::DISCONNECTED;
+      HandleDisplayHotplugEvent(static_cast<uint64_t>(display_id), false);
+      break;
+    case DrmHwc::kConnected:
+      event = common::DisplayHotplugEvent::CONNECTED;
+      HandleDisplayHotplugEvent(static_cast<uint64_t>(display_id), true);
+      break;
+    case DrmHwc::kLinkTrainingFailed:
+      event = common::DisplayHotplugEvent::ERROR_INCOMPATIBLE_CABLE;
+      break;
+  }
   composer_callback_->onHotplugEvent(static_cast<int64_t>(display_id), event);
 }
 
+#else
+
+void DrmHwcThree::SendHotplugEventToClient(
+    hwc2_display_t display_id, DrmHwc::DisplayStatus display_status) {
+  bool connected = display_status != DrmHwc::kDisconnected;
+  HandleDisplayHotplugEvent(static_cast<uint64_t>(display_id), connected);
+  composer_callback_->onHotplug(static_cast<int64_t>(display_id), connected);
+}
+
+#endif
+
 void DrmHwcThree::CleanDisplayResources(uint64_t display_id) {
   DEBUG_FUNC();
   HwcDisplay* display = GetDisplay(display_id);
diff --git a/hwc3/DrmHwcThree.h b/hwc3/DrmHwcThree.h
index 8ba96c6..f020634 100644
--- a/hwc3/DrmHwcThree.h
+++ b/hwc3/DrmHwcThree.h
@@ -39,7 +39,7 @@ class DrmHwcThree : public ::android::DrmHwc {
       hwc2_display_t display_id, int64_t timestamp) const override;
   void SendRefreshEventToClient(uint64_t display_id) override;
   void SendHotplugEventToClient(hwc2_display_t display_id,
-                                bool connected) override;
+                                DrmHwc::DisplayStatus display_status) override;
 
  private:
   void CleanDisplayResources(uint64_t display_id);
diff --git a/hwc3/Utils.h b/hwc3/Utils.h
index 23d6bdc..b322f5d 100644
--- a/hwc3/Utils.h
+++ b/hwc3/Utils.h
@@ -18,6 +18,7 @@
 
 #include <aidl/android/hardware/graphics/composer3/IComposerClient.h>
 #include <hardware/hwcomposer2.h>
+#include <log/log.h>
 
 #include <cstdint>
 
@@ -93,13 +94,6 @@ inline Composition Hwc2CompositionTypeToHwc3(int32_t composition_type) {
   return static_cast<Composition>(composition_type);
 }
 
-inline int32_t Hwc3CompositionToHwc2(Composition composition_type) {
-  if (composition_type > Composition::SIDEBAND) {
-    return HWC2_COMPOSITION_INVALID;
-  }
-  return static_cast<int32_t>(composition_type);
-}
-
 // Values for color modes match across HWC versions, so static cast is safe:
 // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/ColorMode.aidl
 // https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.0.h;drc=7d940ae4afa450696afa25e07982f3a95e17e9b2;l=118
@@ -152,27 +146,6 @@ inline int32_t Hwc3RenderIntentToHwc2(RenderIntent render_intent) {
   return static_cast<int32_t>(render_intent);
 }
 
-// Content type matches, so static_cast is safe.
-// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/ContentType.aidl
-// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;l=350;drc=1a0e4a1698c7b080d6763cef9e16592bce75967e
-inline ContentType Hwc2ContentTypeToHwc3(uint32_t content_type) {
-  if (content_type > HWC2_CONTENT_TYPE_GAME) {
-    ALOGE("Unknown HWC2 content type. Could not translate: %d", content_type);
-    return ContentType::NONE;
-  }
-  return static_cast<ContentType>(content_type);
-}
-inline int32_t Hwc3ContentTypeToHwc2(ContentType content_type) {
-  return static_cast<int32_t>(content_type);
-}
-
-// Values match, so it's safe to do static_cast.
-// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/DisplayAttribute.aidl
-// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;l=58;drc=d783cabd4d9bddb4b83f2dd38300b7598bb58b24
-inline int32_t Hwc3DisplayAttributeToHwc2(DisplayAttribute display_attribute) {
-  return static_cast<int32_t>(display_attribute);
-}
-
 // Values match up to DOZE_SUSPEND.
 // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/PowerMode.aidl
 // https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;l=348;drc=d783cabd4d9bddb4b83f2dd38300b7598bb58b24
@@ -184,13 +157,6 @@ inline int32_t Hwc3PowerModeToHwc2(PowerMode power_mode) {
   return static_cast<int32_t>(power_mode);
 }
 
-// Values match, so static_cast is okay.
-// https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/graphics/common/aidl/android/hardware/graphics/common/BlendMode.aidl;drc=bab1ba54ede32520a5042d616a3af46ad4f55d5f;l=25
-// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;l=72;drc=1a0e4a1698c7b080d6763cef9e16592bce75967e
-inline int32_t Hwc3BlendModeToHwc2(common::BlendMode blend_mode) {
-  return static_cast<int32_t>(blend_mode);
-}
-
 // Values appear to match.
 // https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/graphics/common/aidl/android/hardware/graphics/common/Dataspace.aidl
 // https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.0.h;l=43
@@ -199,11 +165,4 @@ inline int32_t Hwc3DataspaceToHwc2(common::Dataspace dataspace) {
   return static_cast<int32_t>(dataspace);
 }
 
-// Values match, so static_cast is okay.
-// https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/graphics/common/aidl/android/hardware/graphics/common/Transform.aidl
-// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.0.h;l=41
-inline int32_t Hwc3TransformToHwc2(common::Transform transform) {
-  return static_cast<int32_t>(transform);
-}
-
 };  // namespace aidl::android::hardware::graphics::composer3
\ No newline at end of file
diff --git a/hwc3/hwc3-apex-file-contexts b/hwc3/hwc3-apex-file-contexts
new file mode 100644
index 0000000..5c8de15
--- /dev/null
+++ b/hwc3/hwc3-apex-file-contexts
@@ -0,0 +1,3 @@
+(/.*)?                                                   u:object_r:vendor_file:s0
+/etc(/.*)?                                               u:object_r:vendor_configs_file:s0
+/bin/hw/android\.hardware\.composer\.hwc3-service\.drm   u:object_r:hal_graphics_composer_default_exec:s0
\ No newline at end of file
diff --git a/hwc3/hwc3-apex-manifest.json b/hwc3/hwc3-apex-manifest.json
new file mode 100644
index 0000000..fa9e626
--- /dev/null
+++ b/hwc3/hwc3-apex-manifest.json
@@ -0,0 +1,5 @@
+{
+    "name": "com.android.hardware.graphics.composer",
+    "version": 1,
+    "vendorBootstrap": true
+}
\ No newline at end of file
diff --git a/hwc3/hwc3-drm.xml b/hwc3/hwc3-drm.xml
index 911f7f8..7debcf9 100644
--- a/hwc3/hwc3-drm.xml
+++ b/hwc3/hwc3-drm.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.graphics.composer3</name>
-        <version>3</version>
+        <version>4</version>
         <interface>
             <name>IComposer</name>
             <instance>default</instance>
diff --git a/hwc3/meson.build b/hwc3/meson.build
index 2486212..291c71a 100644
--- a/hwc3/meson.build
+++ b/hwc3/meson.build
@@ -14,7 +14,7 @@ executable(
     cpp_args : common_cpp_flags + hwc2_cpp_flags,
     dependencies : deps,
     install : true,
-    link_with: [drmhwc_common, drmhwc_hwc2_common],
+    link_whole: [drmhwc_common, drmhwc_hwc2_common],
     install_dir : get_option('bindir') / 'hw',
     include_directories: inc_include,
 )
diff --git a/hwc3/service.cpp b/hwc3/service.cpp
index 920260a..b545a67 100644
--- a/hwc3/service.cpp
+++ b/hwc3/service.cpp
@@ -19,7 +19,6 @@
 
 #include <android/binder_manager.h>
 #include <android/binder_process.h>
-#include <binder/ProcessState.h>
 #include <sched.h>
 
 #include "Composer.h"
@@ -47,9 +46,14 @@ int main(int /*argc*/, char* argv[]) {
   const std::string instance = std::string() + Composer::descriptor +
                                "/default";
   ALOGI("HWC3 service name %s", instance.c_str());
+#if __ANDROID_API__ >= 34
   auto status = AServiceManager_addServiceWithFlags(
       composer->asBinder().get(), instance.c_str(),
       AServiceManager_AddServiceFlag::ADD_SERVICE_ALLOW_ISOLATED);
+#else
+  auto status = AServiceManager_addService(composer->asBinder().get(),
+                                           instance.c_str());
+#endif
   if (status != STATUS_OK) {
     ALOGE("Failed to register service. Error %d", (int)status);
     return -EINVAL;
diff --git a/meson.build b/meson.build
index e9a86ec..8cfbbc8 100644
--- a/meson.build
+++ b/meson.build
@@ -16,6 +16,7 @@ src_common = files(
     'backend/Backend.cpp',
     'backend/BackendClient.cpp',
     'utils/fd.cpp',
+    'utils/properties.cpp',
 )
 
 srcs_hwc2_device = [
diff --git a/utils/properties.cpp b/utils/properties.cpp
new file mode 100644
index 0000000..a855c94
--- /dev/null
+++ b/utils/properties.cpp
@@ -0,0 +1,31 @@
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
+#include "properties.h"
+
+/**
+ * @brief Determine if the "Present Not Reliable" property is enabled.
+ *
+ * @return boolean
+ */
+auto Properties::IsPresentFenceNotReliable() -> bool {
+  return (property_get_bool("ro.vendor.hwc.drm.present_fence_not_reliable",
+                            0) != 0);
+}
+
+auto Properties::UseConfigGroups() -> bool {
+  return (property_get_bool("ro.vendor.hwc.drm.use_config_groups", 1) != 0);
+}
diff --git a/utils/properties.h b/utils/properties.h
index e400236..15c2fb2 100644
--- a/utils/properties.h
+++ b/utils/properties.h
@@ -39,4 +39,43 @@ auto inline property_get(const char *name, char *value,
   return static_cast<int>(strlen(value));
 }
 
+/**
+ * Bluntly copied from system/core/libcutils/properties.cpp,
+ * which is part of the Android Project and licensed under Apache 2.
+ * Source:
+ * https://cs.android.com/android/platform/superproject/main/+/main:system/core/libcutils/properties.cpp;l=27
+ */
+auto inline property_get_bool(const char *key, int8_t default_value) -> int8_t {
+  if (!key)
+    return default_value;
+
+  int8_t result = default_value;
+  char buf[PROPERTY_VALUE_MAX] = {};
+
+  int len = property_get(key, buf, "");
+  if (len == 1) {
+    char ch = buf[0];
+    if (ch == '0' || ch == 'n') {
+      result = false;
+    } else if (ch == '1' || ch == 'y') {
+      result = true;
+    }
+  } else if (len > 1) {
+    if (!strcmp(buf, "no") || !strcmp(buf, "false") || !strcmp(buf, "off")) {
+      result = false;
+    } else if (!strcmp(buf, "yes") || !strcmp(buf, "true") ||
+               !strcmp(buf, "on")) {
+      result = true;
+    }
+  }
+
+  return result;
+}
+
 #endif
+
+class Properties {
+ public:
+  static auto IsPresentFenceNotReliable() -> bool;
+  static auto UseConfigGroups() -> bool;
+};
```

