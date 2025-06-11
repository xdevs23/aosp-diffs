```diff
diff --git a/.ci/.gitlab-ci-checkcommit.sh b/.ci/.gitlab-ci-checkcommit.sh
index 3f597c3..5649475 100755
--- a/.ci/.gitlab-ci-checkcommit.sh
+++ b/.ci/.gitlab-ci-checkcommit.sh
@@ -61,7 +61,7 @@ git log --pretty='%h' FETCH_HEAD..HEAD | while read h; do
 		exit 1
 	fi
 
-	git show "$h" -- | clang-format-diff-19 -p 1 -style=file > /tmp/format-fixup.patch
+	git diff -U0 "$h" -- | clang-format-diff-19 -p 1 -style=file > /tmp/format-fixup.patch
 	if [ -s  /tmp/format-fixup.patch ]; then
 		cat /tmp/format-fixup.patch >&2
 		exit 1
diff --git a/.ci/Dockerfile b/.ci/Dockerfile
index 9dfe3d3..8a3172e 100644
--- a/.ci/Dockerfile
+++ b/.ci/Dockerfile
@@ -41,10 +41,10 @@ RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> \
 USER ${RUN_USER}
 
 # Install aospless package (produced by GloDroid/aospext)
-RUN wget -P ${USER_HOME} https://gitlab.freedesktop.org/-/project/5/uploads/70643bd1c4d419015b9930b7aadc9cfd/aospless_drm_hwcomposer_arm64.tar.xz && \
+RUN wget -P ${USER_HOME} https://gitlab.freedesktop.org/-/project/5/uploads/cafa930dad28acf7ee44d50101d5e8f0/aospless_drm_hwcomposer_arm64.tar.xz && \
     cd ${USER_HOME} && \
     sha256sum aospless_drm_hwcomposer_arm64.tar.xz && \
-    (echo 640e0d0e04761c804db69f880e0c0957699babdbe82c72c507177b860d878569 aospless_drm_hwcomposer_arm64.tar.xz | sha256sum --check) && \
+    (echo f792b1140861112f80c8a3a22e1af8e3eccf4910fe4449705e62d2032b713bf9 aospless_drm_hwcomposer_arm64.tar.xz | sha256sum --check) && \
     tar xf aospless_drm_hwcomposer_arm64.tar.xz && ln -s ../drm_hwcomposer/ ${USER_HOME}/aospless/src
 
 # Create project path
diff --git a/.ci/Makefile b/.ci/Makefile
index 051a437..d57ea86 100644
--- a/.ci/Makefile
+++ b/.ci/Makefile
@@ -9,15 +9,13 @@ OUT_DIR := /tmp/drm_hwcomposer/build
 SRC_DIR := .
 
 CXXFLAGS := -Wall -Wextra -Werror -Wno-missing-designated-field-initializers
-CXXFLAGS += -D_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS
+CXXFLAGS += -D_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS -Wthread-safety
 CXXFLAGS += -fvisibility-inlines-hidden -std=gnu++17 -DHWC2_USE_CPP11 -DHWC2_INCLUDE_STRINGIFICATION -fno-rtti
 
 CXXARGS := $(shell cat $(BASE_DIR)/toolchain_wrapper/sharedlib.cppflags)
 CXXARGS := $(subst [BASE_DIR],$(BASE_DIR),$(CXXARGS))
 # clang-tidy doesn't like -mcpu=xxx flag
 CXXARGS := $(patsubst -mcpu=%,,$(CXXARGS))
-# TODO: build aospless with gtest enabled and remove line below
-CXXARGS := $(subst -nostdlibinc,,$(CXXARGS))
 CXXARGS += -I. -I./tests/test_include $(CXXFLAGS)
 
 TIDY_FILES_OVERRIDE := \
@@ -55,14 +53,6 @@ TIDY_CHECKS_FINE := *                                   \
     -readability-redundant-member-init                  \
     -cppcoreguidelines-avoid-const-or-ref-data-members  \
     -cert-err33-c                                       \
-    -readability-math-missing-parentheses               \
-    -readability-avoid-unconditional-preprocessor-if    \
-    -modernize-type-traits                              \
-    -clang-analyzer-optin.core.EnumCastOutOfRange       \
-    -performance-inefficient-vector-operation           \
-    -readability-static-accessed-through-instance       \
-    -misc-use-internal-linkage                          \
-    -performance-avoid-endl                             \
 
 TIDY_CHECKS_NORMAL :=                                   \
     $(TIDY_CHECKS_FINE)                                 \
diff --git a/.ci/container/.gitlab-ci.yml b/.ci/container/.gitlab-ci.yml
new file mode 100644
index 0000000..85024f8
--- /dev/null
+++ b/.ci/container/.gitlab-ci.yml
@@ -0,0 +1,37 @@
+
+.incorporate-templates-commit:
+  variables:
+    FDO_DISTRIBUTION_TAG: "${HWC_TAG}--${CI_TEMPLATES_COMMIT}"
+
+.container:
+  stage: container
+  extends:
+    - .incorporate-templates-commit
+  variables:
+    FDO_REPO_SUFFIX: $CI_JOB_NAME
+    # no need to pull the whole repo to build the container image
+    GIT_STRATEGY: none
+
+ubuntu/x86_64_hwc:
+  extends:
+    - .fdo.container-build@ubuntu
+    - .container
+  variables:
+    FDO_DISTRIBUTION_VERSION: "24.10"
+    FDO_DISTRIBUTION_EXEC: 'bash .ci/container/ubuntu/x86_64_aospless.sh'
+    HWC_TAG: $UBUNTU_HWC_TAG
+
+.set-image:
+  extends:
+    - .incorporate-templates-commit
+  image: "$CI_REGISTRY_IMAGE/${HWC_IMAGE}:${FDO_DISTRIBUTION_TAG}"
+
+.use-ubuntu/x86_64_hwc:
+  extends:
+    - .fdo.container-build@ubuntu
+    - .set-image
+  variables:
+    HWC_TAG: $UBUNTU_HWC_TAG
+    HWC_IMAGE: $UBUNTU_HWC_IMAGE
+  needs:
+    - ubuntu/x86_64_hwc
diff --git a/.ci/container/ubuntu/x86_64_aospless.sh b/.ci/container/ubuntu/x86_64_aospless.sh
new file mode 100644
index 0000000..9b6e49d
--- /dev/null
+++ b/.ci/container/ubuntu/x86_64_aospless.sh
@@ -0,0 +1,52 @@
+#!/usr/bin/env bash
+
+# For any changes to this file to take effect, the UBUNTU_HWC_TAG has
+# to be bumped to generate a new image.
+
+set -ex
+
+DEPS=(
+    clang
+    llvm
+    clang-19
+    clang-tidy-19
+    clang-format-19
+    ca-certificates
+    git
+    libdrm-dev
+    blueprint-tools
+    libgtest-dev
+    make
+    python3
+    wget
+    sudo
+    rsync
+    lld
+    pkg-config
+    ninja-build
+    meson
+    python3-mako
+    python3-jinja2
+    python3-ply
+    python3-yaml
+    wget
+    gnupg
+    xz-utils
+)
+
+export DEBIAN_FRONTEND=noninteractive
+
+apt-get update
+apt-get upgrade -y
+
+apt-get install -y --no-remove --no-install-recommends "${DEPS[@]}"
+
+wget https://gitlab.freedesktop.org/-/project/5/uploads/cafa930dad28acf7ee44d50101d5e8f0/aospless_drm_hwcomposer_arm64.tar.xz
+
+sha256sum aospless_drm_hwcomposer_arm64.tar.xz
+if echo f792b1140861112f80c8a3a22e1af8e3eccf4910fe4449705e62d2032b713bf9 aospless_drm_hwcomposer_arm64.tar.xz | sha256sum --check; then
+    tar --no-same-owner -xf aospless_drm_hwcomposer_arm64.tar.xz -C /
+else
+    echo "Tar file check failed"
+    exit 1
+fi
diff --git a/.gitlab-ci.yml b/.gitlab-ci.yml
index b045da8..3d39f17 100644
--- a/.gitlab-ci.yml
+++ b/.gitlab-ci.yml
@@ -1,5 +1,3 @@
-image: ubuntu:24.10
-
 workflow:
   rules:
     - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
@@ -7,51 +5,53 @@ workflow:
 
 variables:
   DEBIAN_FRONTEND: noninteractive
-
-before_script:
-  - apt-get --quiet update --yes >/dev/null
-  - apt-get --quiet install --yes clang-19 clang-tidy-19 clang-format-19 git libdrm-dev blueprint-tools libgtest-dev make >/dev/null
-  - apt-get --quiet install --yes clang llvm make python3 wget sudo rsync lld pkg-config ninja-build meson >/dev/null
-  - apt-get --quiet install --yes python3-mako python3-jinja2 python3-ply python3-yaml >/dev/null
+  CI_TEMPLATES_COMMIT: &ci-templates-commit e195d80f35b45cc73668be3767b923fd76c70ed5
+  FDO_UPSTREAM_REPO: "drm-hwcomposer/drm-hwcomposer"
+  UBUNTU_HWC_IMAGE: "ubuntu/x86_64_hwc"
+  UBUNTU_HWC_TAG: "20250218_hwc"
+
+include:
+  - project: 'freedesktop/ci-templates'
+    ref: *ci-templates-commit
+    file:
+      - '/templates/ubuntu.yml'
+  - local: '.ci/container/.gitlab-ci.yml'
 
 stages:
+  - container
   - build
   - tidy
   - style
 
 build:
   stage: build
+  extends:
+    .use-ubuntu/x86_64_hwc
   script:
-    - mkdir -p install/arm64
-    - cd ..
-    - rm -f aospless_drm_hwcomposer_arm64.tar.xz
-    - rm -rf aospless/*
-    - wget https://gitlab.freedesktop.org/-/project/5/uploads/70643bd1c4d419015b9930b7aadc9cfd/aospless_drm_hwcomposer_arm64.tar.xz
-    - tar xf aospless_drm_hwcomposer_arm64.tar.xz
-    - rm -rf aospless/src
-    - ln -s ../drm-hwcomposer/ aospless/src
-    - make -C ./aospless install
-    - cp -r aospless/install/* drm-hwcomposer/install/arm64
-
+    - ln -s "${CI_PROJECT_DIR}" "/aospless/src"
+    - make -C /aospless install
+    - mkdir -p "${CI_PROJECT_DIR}/install/arm64"
+    - cp -r /aospless/install/* "${CI_PROJECT_DIR}/install/arm64"
   artifacts:
     paths:
-      - install/
+      - "${CI_PROJECT_DIR}/install/arm64"
     expire_in: 1 week
 
 tidy:
   stage: tidy
+  extends:
+    .use-ubuntu/x86_64_hwc
   script:
-    - cd ..
-    - rm -f aospless_drm_hwcomposer_arm64.tar.xz
-    - rm -rf aospless/*
-    - wget https://gitlab.freedesktop.org/-/project/5/uploads/70643bd1c4d419015b9930b7aadc9cfd/aospless_drm_hwcomposer_arm64.tar.xz
-    - tar xf aospless_drm_hwcomposer_arm64.tar.xz
-    - cd -
-    - make -j$(nproc) -k -f .ci/Makefile
+    - cp -r /aospless ../
+    - make -j$(nproc) -k -f "${CI_PROJECT_DIR}/.ci/Makefile"
 
 checkstyle:
   stage: style
+  extends:
+    .use-ubuntu/x86_64_hwc
   script: "./.ci/.gitlab-ci-checkcommit.sh"
   artifacts:
     when: on_failure
     untracked: true
+  tags:
+    - placeholder-job
diff --git a/Android.bp b/Android.bp
index 24d4d99..47b2cd8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -42,8 +42,6 @@ cc_defaults {
     name: "hwcomposer.drm_defaults",
 
     shared_libs: [
-        "android.hardware.graphics.composer@2.1-resources",
-        "android.hardware.graphics.composer@2.2-resources",
         "libcutils",
         "libdrm",
         "libhardware",
@@ -56,6 +54,7 @@ cc_defaults {
 
     static_libs: [
         "libaidlcommonsupport",
+        "libdisplay_info",
     ],
 
     header_libs: [
@@ -68,6 +67,7 @@ cc_defaults {
     ],
 
     cppflags: [
+        "-DHAS_LIBDISPLAY_INFO",
         "-DHWC2_INCLUDE_STRINGIFICATION",
         "-DHWC2_USE_CPP11",
     ],
@@ -117,6 +117,7 @@ filegroup {
         "hwc2_device/HwcLayer.cpp",
         "hwc2_device/hwc2_device.cpp",
 
+        "utils/LibdisplayEdidWrapper.cpp",
         "utils/fd.cpp",
         "utils/properties.cpp",
     ],
@@ -127,7 +128,6 @@ filegroup {
     srcs: [
         "hwc3/Composer.cpp",
         "hwc3/ComposerClient.cpp",
-        "hwc3/ComposerResources.cpp",
         "hwc3/DrmHwcThree.cpp",
         "hwc3/Utils.cpp",
     ],
@@ -154,40 +154,13 @@ filegroup {
     ],
 }
 
-// Kept only for compatibility with older Android version. Please do not use!
-cc_library_static {
-    name: "drm_hwcomposer",
-    defaults: ["hwcomposer.drm_defaults"],
-    srcs: [":drm_hwcomposer_common"],
-}
-
-cc_library_shared {
-    name: "hwcomposer.drm",
-    defaults: ["hwcomposer.drm_defaults"],
-    srcs: [
-        ":drm_hwcomposer_common",
-        "bufferinfo/legacy/BufferInfoLibdrm.cpp",
-    ],
-    cflags: ["-DUSE_IMAPPER4_METADATA_API"],
-}
-
-cc_library_shared {
-    name: "hwcomposer.drm_minigbm",
-    defaults: ["hwcomposer.drm_defaults"],
-    srcs: [
-        ":drm_hwcomposer_common",
-        "bufferinfo/legacy/BufferInfoMinigbm.cpp",
-    ],
-}
-
-cc_binary {
-    name: "android.hardware.composer.hwc3-service.drm",
+cc_defaults {
+    name: "android.hardware.composer.hwc3-service.drm.defaults",
 
     srcs: [
         ":drm_hwcomposer_common",
         ":drm_hwcomposer_hwc3",
         ":drm_hwcomposer_service",
-        "bufferinfo/legacy/BufferInfoLibdrm.cpp",
     ],
 
     defaults: [
@@ -203,16 +176,25 @@ cc_binary {
     ],
 
     cflags: [
+        "-DUSE_IMAPPER4_METADATA_API",
         "-Wall",
         "-Werror",
-
-        "-DUSE_IMAPPER4_METADATA_API",
     ],
 
     cppflags: [
         "-DHWC2_INCLUDE_STRINGIFICATION",
         "-DHWC2_USE_CPP11",
     ],
+}
+
+cc_binary {
+    name: "android.hardware.composer.hwc3-service.drm",
+
+    defaults: [
+        "android.hardware.composer.hwc3-service.drm.defaults",
+    ],
+
+    srcs: ["bufferinfo/legacy/BufferInfoLibdrm.cpp"],
 
     relative_install_path: "hw",
     vendor: true,
diff --git a/METADATA b/METADATA
index d97975c..c577677 100644
--- a/METADATA
+++ b/METADATA
@@ -1,3 +1,19 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/drm_hwcomposer
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
+
+name: "drm_hwcomposer"
+description: "KMS-based HWComposer implementation."
 third_party {
   license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 3
+    day: 21
+  }
+  identifier {
+    type: "Git"
+    value: "https://gitlab.freedesktop.org/drm-hwcomposer/drm-hwcomposer"
+    version: "12d302c4abcef99ab28c94c3fef709754fac48e2"
+  }
 }
diff --git a/OWNERS b/OWNERS
index a4f788d..78b324f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,4 @@ adelva@google.com
 ddavenport@google.com
 jstultz@google.com
 seanpaul@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/TEST_MAPPING b/TEST_MAPPING
new file mode 100644
index 0000000..305410c
--- /dev/null
+++ b/TEST_MAPPING
@@ -0,0 +1,12 @@
+{
+  "presubmit": [
+    {
+      "name": "VtsHalGraphicsComposer3_TargetTest"
+    }
+  ],
+  "desktop-presubmit": [
+    {
+      "name": "VtsHalGraphicsComposer3_TargetTest"
+    }
+  ]
+}
diff --git a/backend/Backend.cpp b/backend/Backend.cpp
index 91cb84d..12a5fea 100644
--- a/backend/Backend.cpp
+++ b/backend/Backend.cpp
@@ -20,9 +20,20 @@
 
 #include "BackendManager.h"
 #include "bufferinfo/BufferInfoGetter.h"
+#include "hardware/hwcomposer2.h"
 
 namespace android {
 
+namespace {
+
+bool HasCursorLayer(const std::vector<HwcLayer *> &layers) {
+  return std::find_if(layers.begin(), layers.end(), [&](auto *layer) -> bool {
+           return layer->GetSfType() == HWC2::Composition::Cursor;
+         }) != layers.end();
+}
+
+}  // namespace
+
 HWC2::Error Backend::ValidateDisplay(HwcDisplay *display, uint32_t *num_types,
                                      uint32_t *num_requests) {
   *num_types = 0;
@@ -62,7 +73,27 @@ HWC2::Error Backend::ValidateDisplay(HwcDisplay *display, uint32_t *num_types,
     ++display->total_stats().failed_kms_validate_;
     client_start = 0;
     client_size = layers.size();
-    MarkValidated(layers, 0, client_size);
+
+    // Expand the client range to include all layers except the cursor layer (if
+    // there is one) and retry.
+    auto [_, cursor_plane] = display->GetPipe().GetUsablePlanes();
+    if (cursor_plane && HasCursorLayer(layers)) {
+      --client_size;
+      MarkValidated(layers, 0, client_size);
+
+      testing_needed = display->CreateComposition(a_args) != HWC2::Error::None;
+
+      // If testing is still needed, expand the client range to include the
+      // cursor layer for the next retry.
+      if (testing_needed) {
+        ++client_size;
+        ++display->total_stats().failed_kms_validate_;
+      }
+    }
+
+    if (testing_needed) {
+      MarkValidated(layers, 0, client_size);
+    }
   }
 
   *num_types = client_size;
@@ -108,7 +139,10 @@ uint32_t Backend::CalcPixOps(const std::vector<HwcLayer *> &layers,
   for (size_t z_order = 0; z_order < layers.size(); ++z_order) {
     if (z_order >= first_z && z_order < first_z + size) {
       auto &df = layers[z_order]->GetLayerData().pi.display_frame;
-      pixops += (df.right - df.left) * (df.bottom - df.top);
+      if (df.i_rect) {
+        pixops += (df.i_rect->right - df.i_rect->left) *
+                  (df.i_rect->bottom - df.i_rect->top);
+      }
     }
   }
   return pixops;
@@ -117,43 +151,54 @@ uint32_t Backend::CalcPixOps(const std::vector<HwcLayer *> &layers,
 void Backend::MarkValidated(std::vector<HwcLayer *> &layers,
                             size_t client_first_z, size_t client_size) {
   for (size_t z_order = 0; z_order < layers.size(); ++z_order) {
-    if (z_order >= client_first_z && z_order < client_first_z + client_size)
+    if (z_order >= client_first_z && z_order < client_first_z + client_size) {
       layers[z_order]->SetValidatedType(HWC2::Composition::Client);
-    else
+    } else if (layers[z_order]->GetSfType() == HWC2::Composition::Cursor) {
+      layers[z_order]->SetValidatedType(HWC2::Composition::Cursor);
+    } else {
       layers[z_order]->SetValidatedType(HWC2::Composition::Device);
+    }
   }
 }
 
 std::tuple<int, int> Backend::GetExtraClientRange(
     HwcDisplay *display, const std::vector<HwcLayer *> &layers,
     int client_start, size_t client_size) {
-  auto planes = display->GetPipe().GetUsablePlanes();
+  auto [planes, cursor_plane] = display->GetPipe().GetUsablePlanes();
   size_t avail_planes = planes.size();
+  size_t layers_size = layers.size();
+
+  // |cursor_plane| is not counted among |avail_planes|, so the cursor layer
+  // shouldn't be counted in |layers_size|.
+  if (cursor_plane && HasCursorLayer(layers)) {
+    --layers_size;
+  }
 
   /*
-   * If more layers then planes, save one plane
+   * If more layers than planes, save one plane
    * for client composited layers
    */
-  if (avail_planes < display->layers().size())
+  if (avail_planes < layers_size) {
     avail_planes--;
+  }
 
-  const int extra_client = int(layers.size() - client_size) - int(avail_planes);
+  const int extra_client = int(layers_size - client_size) - int(avail_planes);
 
   if (extra_client > 0) {
     int start = 0;
     size_t steps = 0;
     if (client_size != 0) {
       const int prepend = std::min(client_start, extra_client);
-      const int append = std::min(int(layers.size()) -
+      const int append = std::min(int(layers_size) -
                                       int(client_start + client_size),
                                   extra_client);
       start = client_start - (int)prepend;
       client_size += extra_client;
       steps = 1 + std::min(std::min(append, prepend),
-                           int(layers.size()) - int(start + client_size));
+                           int(layers_size) - int(start + client_size));
     } else {
       client_size = extra_client;
-      steps = 1 + layers.size() - extra_client;
+      steps = 1 + layers_size - extra_client;
     }
 
     uint32_t gpu_pixops = UINT32_MAX;
diff --git a/bufferinfo/BufferInfo.h b/bufferinfo/BufferInfo.h
index b2297f9..db4c53e 100644
--- a/bufferinfo/BufferInfo.h
+++ b/bufferinfo/BufferInfo.h
@@ -17,6 +17,7 @@
 #pragma once
 
 #include <cstdint>
+#include <memory>
 
 constexpr int kBufferMaxPlanes = 4;
 
@@ -40,6 +41,11 @@ enum class BufferBlendMode : int32_t {
   kCoverage,
 };
 
+class PrimeFdsSharedBase {
+ public:
+  virtual ~PrimeFdsSharedBase() = default;
+};
+
 struct BufferInfo {
   uint32_t width;
   uint32_t height;
@@ -54,4 +60,9 @@ struct BufferInfo {
   BufferColorSpace color_space;
   BufferSampleRange sample_range;
   BufferBlendMode blend_mode;
+
+  /* prime_fds field require valid file descriptors. While their lifecycle is
+   * managed elsewhere. The shared_ptr is used to ensure that the fds are not
+   * closed while the BufferInfo is still in use. */
+  std::shared_ptr<PrimeFdsSharedBase> fds_shared;
 };
diff --git a/bufferinfo/BufferInfoMapperMetadata.cpp b/bufferinfo/BufferInfoMapperMetadata.cpp
index dc1b906..125c5c8 100644
--- a/bufferinfo/BufferInfoMapperMetadata.cpp
+++ b/bufferinfo/BufferInfoMapperMetadata.cpp
@@ -31,6 +31,23 @@
 
 namespace android {
 
+namespace {
+
+std::optional<std::pair<uint32_t, uint32_t>> GetAlignedDimensions(
+    const ui::PlaneLayout &layout) {
+  if (layout.sampleIncrementInBits == 0 || layout.strideInBytes == 0) {
+    ALOGW("Invalid plane layout");
+    return std::nullopt;
+  }
+
+  constexpr uint32_t kBitsPerByte = 8;
+  return std::pair{layout.strideInBytes * kBitsPerByte /
+                       layout.sampleIncrementInBits,
+                   layout.totalSizeInBytes / layout.strideInBytes};
+}
+
+}  // namespace
+
 BufferInfoGetter *BufferInfoMapperMetadata::CreateInstance() {
   if (GraphicBufferMapper::getInstance().getMapperVersion() <
       GraphicBufferMapper::GRALLOC_4)
@@ -136,6 +153,25 @@ auto BufferInfoMapperMetadata::GetBoInfo(buffer_handle_t handle)
     bi.sizes[i] = layouts[i].totalSizeInBytes;
   }
 
+  uint64_t usage = 0;
+  err = mapper.getUsage(handle, &usage);
+  if (err != 0) {
+    ALOGE("Failed to get Usage err=%d", err);
+    return {};
+  }
+
+  if ((usage & GRALLOC_USAGE_CURSOR) != 0) {
+    if (layouts.size() > 1) {
+      ALOGW("Multiplanar format buffer alignment not supported");
+    } else {
+      auto aligned = GetAlignedDimensions(layouts[0]);
+      if (aligned.has_value()) {
+        bi.width = aligned->first;
+        bi.height = aligned->second;
+      }
+    }
+  }
+
   err = GetFds(handle, &bi);
   if (err != 0) {
     ALOGE("Failed to get fds (err=%d)", err);
diff --git a/compositor/DisplayInfo.h b/compositor/DisplayInfo.h
index 6ddc66f..f580d99 100644
--- a/compositor/DisplayInfo.h
+++ b/compositor/DisplayInfo.h
@@ -18,6 +18,31 @@
 
 #include <cstdint>
 
+/*
+ * Display colorimetry enums.
+ */
+// NOLINTBEGIN(readability-identifier-naming)
+enum class Colormode : int32_t {
+  kNative,
+  kBt601_625,
+  kBt601_625Unadjusted,
+  kBt601_525,
+  kBt601_525Unadjusted,
+  kBt709,
+  kDciP3,
+  kSrgb,
+  kAdobeRgb,
+  kDisplayP3,
+  kBt2020,
+  kBt2100Pq,
+  kBt2100Hlg,
+  kDisplayBt2020,
+};
+// NOLINTEND(readability-identifier-naming)
+
+/**
+ * Display panel colorspace property values.
+ */
 enum class Colorspace : int32_t {
   kDefault,
   kSmpte170MYcc,
diff --git a/compositor/DrmKmsPlan.cpp b/compositor/DrmKmsPlan.cpp
index 4f75e89..1155697 100644
--- a/compositor/DrmKmsPlan.cpp
+++ b/compositor/DrmKmsPlan.cpp
@@ -23,17 +23,30 @@
 #include "utils/log.h"
 
 namespace android {
-auto DrmKmsPlan::CreateDrmKmsPlan(DrmDisplayPipeline &pipe,
-                                  std::vector<LayerData> composition)
-    -> std::unique_ptr<DrmKmsPlan> {
+auto DrmKmsPlan::CreateDrmKmsPlan(
+    DrmDisplayPipeline &pipe, std::vector<LayerData> composition,
+    std::optional<LayerData> cursor_layer) -> std::unique_ptr<DrmKmsPlan> {
   auto plan = std::make_unique<DrmKmsPlan>();
 
-  auto avail_planes = pipe.GetUsablePlanes();
+  auto [avail_planes, cursor_plane] = pipe.GetUsablePlanes();
 
   int z_pos = 0;
+  if (cursor_layer.has_value()) {
+    if (cursor_plane &&
+        cursor_plane->Get()->IsValidForLayer(&cursor_layer.value())) {
+      plan->plan.emplace_back(
+          LayerToPlaneJoining{.layer = std::move(cursor_layer.value()),
+                              .plane = cursor_plane,
+                              .z_pos = z_pos++});
+    } else {
+      // Cursor layer can't use cursor plane, so let it match normally with
+      // others.
+      composition.push_back(std::move(cursor_layer.value()));
+    }
+  }
+
   for (auto &dhl : composition) {
     std::shared_ptr<BindingOwner<DrmPlane>> plane;
-
     /* Skip unsupported planes */
     do {
       if (avail_planes.empty()) {
diff --git a/compositor/DrmKmsPlan.h b/compositor/DrmKmsPlan.h
index 054cd93..d0b271a 100644
--- a/compositor/DrmKmsPlan.h
+++ b/compositor/DrmKmsPlan.h
@@ -35,8 +35,9 @@ struct DrmKmsPlan {
   std::vector<LayerToPlaneJoining> plan;
 
   static auto CreateDrmKmsPlan(DrmDisplayPipeline &pipe,
-                               std::vector<LayerData> composition)
-      -> std::unique_ptr<DrmKmsPlan>;
+                               std::vector<LayerData> composition,
+                               std::optional<LayerData> cursor_layer =
+                                   std::nullopt) -> std::unique_ptr<DrmKmsPlan>;
 };
 
 }  // namespace android
diff --git a/compositor/LayerData.h b/compositor/LayerData.h
index a808adc..90ae7be 100644
--- a/compositor/LayerData.h
+++ b/compositor/LayerData.h
@@ -16,9 +16,6 @@
 
 #pragma once
 
-#include <hardware/hardware.h>
-#include <hardware/hwcomposer.h>
-
 #include <cmath>
 #include <cstdbool>
 #include <cstdint>
@@ -33,32 +30,63 @@ namespace android {
 
 class DrmFbIdHandle;
 
+using ILayerId = int64_t;
+
 /* Rotation is defined in the clockwise direction */
-enum LayerTransform : uint32_t {
-  kIdentity = 0,
-  kFlipH = 1 << 0,
-  kFlipV = 1 << 1,
-  kRotate90 = 1 << 2,
-  kRotate180 = 1 << 3,
-  kRotate270 = 1 << 4,
+/* The flip is done before rotation */
+struct LayerTransform {
+  bool hflip;
+  bool vflip;
+  bool rotate90;
 };
 
+struct SrcRectInfo {
+  struct FRect {
+    float left;
+    float top;
+    float right;
+    float bottom;
+  };
+  /* nullopt means the whole buffer */
+  std::optional<FRect> f_rect;
+};
+
+struct DstRectInfo {
+  struct IRect {
+    int32_t left;
+    int32_t top;
+    int32_t right;
+    int32_t bottom;
+  };
+  /* nullopt means the whole display */
+  std::optional<IRect> i_rect;
+};
+
+constexpr float kAlphaOpaque = 1.0F;
+
 struct PresentInfo {
   LayerTransform transform{};
-  uint16_t alpha = UINT16_MAX;
-  hwc_frect_t source_crop{};
-  hwc_rect_t display_frame{};
+  float alpha = kAlphaOpaque;
+  SrcRectInfo source_crop{};
+  DstRectInfo display_frame{};
 
   bool RequireScalingOrPhasing() const {
-    const float src_width = source_crop.right - source_crop.left;
-    const float src_height = source_crop.bottom - source_crop.top;
+    if (!source_crop.f_rect || !display_frame.i_rect) {
+      return false;
+    }
+
+    const auto &src = *source_crop.f_rect;
+    const auto &dst = *display_frame.i_rect;
+
+    const float src_width = src.right - src.left;
+    const float src_height = src.bottom - src.top;
 
-    auto dest_width = float(display_frame.right - display_frame.left);
-    auto dest_height = float(display_frame.bottom - display_frame.top);
+    auto dest_width = float(dst.right - dst.left);
+    auto dest_height = float(dst.bottom - dst.top);
 
     auto scaling = src_width != dest_width || src_height != dest_height;
-    auto phasing = (source_crop.left - std::floor(source_crop.left) != 0) ||
-                   (source_crop.top - std::floor(source_crop.top) != 0);
+    auto phasing = (src.left - std::floor(src.left) != 0) ||
+                   (src.top - std::floor(src.top) != 0);
     return scaling || phasing;
   }
 };
diff --git a/drm/DrmAtomicStateManager.cpp b/drm/DrmAtomicStateManager.cpp
index 9a8769a..4e4be80 100644
--- a/drm/DrmAtomicStateManager.cpp
+++ b/drm/DrmAtomicStateManager.cpp
@@ -120,6 +120,9 @@ auto DrmAtomicStateManager::CommitFrame(AtomicCommitArgs &args) -> int {
       return -EINVAL;
     }
 
+    auto raw_mode = args.display_mode.value().GetRawMode();
+    whole_display_rect_.i_rect = {0, 0, raw_mode.hdisplay, raw_mode.vdisplay};
+
     if (!crtc->GetModeProperty().AtomicSet(*pset, *new_frame_state.mode_blob)) {
       return -EINVAL;
     }
@@ -141,12 +144,46 @@ auto DrmAtomicStateManager::CommitFrame(AtomicCommitArgs &args) -> int {
 
   if (args.colorspace && connector->GetColorspaceProperty()) {
     if (!connector->GetColorspaceProperty()
-             .AtomicSet(*pset, connector->GetColorspacePropertyValue(*args.colorspace)))
+             .AtomicSet(*pset, connector->GetColorspacePropertyValue(
+                                   *args.colorspace)))
       return -EINVAL;
   }
 
   if (args.content_type && connector->GetContentTypeProperty()) {
-    if (!connector->GetContentTypeProperty().AtomicSet(*pset, *args.content_type))
+    if (!connector->GetContentTypeProperty().AtomicSet(*pset,
+                                                       *args.content_type))
+      return -EINVAL;
+  }
+
+  if (args.hdr_metadata && connector->GetHdrOutputMetadataProperty()) {
+    auto blob = drm->RegisterUserPropertyBlob(args.hdr_metadata.get(),
+                                              sizeof(hdr_output_metadata));
+    new_frame_state.hdr_metadata_blob = std::move(blob);
+    if (!new_frame_state.hdr_metadata_blob) {
+      ALOGE("Failed to create %s blob",
+            connector->GetHdrOutputMetadataProperty().GetName().c_str());
+      return -EINVAL;
+    }
+
+    if (!connector->GetHdrOutputMetadataProperty()
+             .AtomicSet(*pset, *new_frame_state.hdr_metadata_blob))
+      return -EINVAL;
+  }
+
+  if (args.min_bpc && connector->GetMinBpcProperty()) {
+    int err;
+    uint64_t range_min, range_max = 0;
+    std::tie(err, range_min) = connector->GetMinBpcProperty().RangeMin();
+    if (err)
+      return err;
+    std::tie(err, range_max) = connector->GetMinBpcProperty().RangeMax();
+    if (err)
+      return err;
+
+    // Adjust requested min bpc to be within the property range
+    int32_t min_bpc_val = std::max(args.min_bpc.value(), static_cast<int32_t>(range_min));
+    min_bpc_val = std::min(min_bpc_val, static_cast<int32_t>(range_max));
+    if (!connector->GetMinBpcProperty().AtomicSet(*pset, min_bpc_val))
       return -EINVAL;
   }
 
@@ -166,8 +203,8 @@ auto DrmAtomicStateManager::CommitFrame(AtomicCommitArgs &args) -> int {
       auto &v = unused_planes;
       v.erase(std::remove(v.begin(), v.end(), joining.plane), v.end());
 
-      if (plane->AtomicSetState(*pset, layer, joining.z_pos, crtc->GetId()) !=
-          0) {
+      if (plane->AtomicSetState(*pset, layer, joining.z_pos, crtc->GetId(),
+                                whole_display_rect_) != 0) {
         return -EINVAL;
       }
     }
diff --git a/drm/DrmAtomicStateManager.h b/drm/DrmAtomicStateManager.h
index 8d22b99..e4fff56 100644
--- a/drm/DrmAtomicStateManager.h
+++ b/drm/DrmAtomicStateManager.h
@@ -40,6 +40,8 @@ struct AtomicCommitArgs {
   std::shared_ptr<drm_color_ctm> color_matrix;
   std::optional<Colorspace> colorspace;
   std::optional<int32_t> content_type;
+  std::shared_ptr<hdr_output_metadata> hdr_metadata;
+  std::optional<int32_t> min_bpc;
 
   std::shared_ptr<DrmFbIdHandle> writeback_fb;
   SharedFd writeback_release_fence;
@@ -84,6 +86,7 @@ class DrmAtomicStateManager {
 
     DrmModeUserPropertyBlobUnique mode_blob;
     DrmModeUserPropertyBlobUnique ctm_blob;
+    DrmModeUserPropertyBlobUnique hdr_metadata_blob;
 
     int release_fence_pt_index{};
 
@@ -108,6 +111,8 @@ class DrmAtomicStateManager {
   int frames_staged_{};
   int frames_tracked_{};
 
+  DstRectInfo whole_display_rect_{};
+
   void ThreadFn(const std::shared_ptr<DrmAtomicStateManager> &dasm);
   std::condition_variable cv_;
   std::mutex mutex_;
diff --git a/drm/DrmConnector.cpp b/drm/DrmConnector.cpp
index eeec3b1..82a109b 100644
--- a/drm/DrmConnector.cpp
+++ b/drm/DrmConnector.cpp
@@ -89,6 +89,12 @@ auto DrmConnector::Init()-> bool {
   }
 
   UpdateEdidProperty();
+#if HAS_LIBDISPLAY_INFO
+  auto edid = LibdisplayEdidWrapper::Create(GetEdidBlob());
+  edid_wrapper_ = edid ? std::move(edid) : std::make_unique<EdidWrapper>();
+#else
+  edid_wrapper_ = std::make_unique<EdidWrapper>();
+#endif
 
   if (IsWriteback() &&
       (!GetConnectorProperty("WRITEBACK_PIXEL_FORMATS",
@@ -99,8 +105,7 @@ auto DrmConnector::Init()-> bool {
     return false;
   }
 
-  if (GetConnectorProperty("Colorspace", &colorspace_property_,
-                           /*is_optional=*/true)) {
+  if (GetOptionalConnectorProperty("Colorspace", &colorspace_property_)) {
     colorspace_property_.AddEnumToMap("Default", Colorspace::kDefault,
                                       colorspace_enum_map_);
     colorspace_property_.AddEnumToMap("SMPTE_170M_YCC", Colorspace::kSmpte170MYcc,
@@ -129,17 +134,21 @@ auto DrmConnector::Init()-> bool {
                                       colorspace_enum_map_);
     colorspace_property_.AddEnumToMap("RGB_WIDE_FIXED", Colorspace::kRgbWideFixed,
                                       colorspace_enum_map_);
-    colorspace_property_.AddEnumToMap("RGB_WIDE_FLOAT", Colorspace::kRgbWideFloat,
+    colorspace_property_.AddEnumToMap("RGB_WIDE_FLOAT",
+                                      Colorspace::kRgbWideFloat,
                                       colorspace_enum_map_);
     colorspace_property_.AddEnumToMap("BT601_YCC", Colorspace::kBt601Ycc,
                                       colorspace_enum_map_);
   }
 
-  GetConnectorProperty("content type", &content_type_property_,
-                       /*is_optional=*/true);
+  GetOptionalConnectorProperty("content type", &content_type_property_);
+
+  GetOptionalConnectorProperty("HDR_OUTPUT_METADATA",
+                               &hdr_output_metadata_property_);
+
+  GetOptionalConnectorProperty("min bpc", &min_bpc_property_);
 
-  if (GetConnectorProperty("panel orientation", &panel_orientation_,
-                           /*is_optional=*/true)) {
+  if (GetOptionalConnectorProperty("panel orientation", &panel_orientation_)) {
     panel_orientation_
         .AddEnumToMapReverse("Normal",
                              PanelOrientation::kModePanelOrientationNormal,
@@ -162,9 +171,7 @@ auto DrmConnector::Init()-> bool {
 }
 
 int DrmConnector::UpdateEdidProperty() {
-  return GetConnectorProperty("EDID", &edid_property_, /*is_optional=*/true)
-             ? 0
-             : -EINVAL;
+  return GetOptionalConnectorProperty("EDID", &edid_property_) ? 0 : -EINVAL;
 }
 
 auto DrmConnector::GetEdidBlob() -> DrmModePropertyBlobUnique {
diff --git a/drm/DrmConnector.h b/drm/DrmConnector.h
index be84ae3..4d4f070 100644
--- a/drm/DrmConnector.h
+++ b/drm/DrmConnector.h
@@ -27,11 +27,14 @@
 #include "DrmProperty.h"
 #include "DrmUnique.h"
 #include "compositor/DisplayInfo.h"
+#include "utils/EdidWrapper.h"
 
 namespace android {
 
 class DrmDevice;
 
+using EdidWrapperUnique = std::unique_ptr<EdidWrapper>;
+
 class DrmConnector : public PipelineBindable<DrmConnector> {
  public:
   static auto CreateInstance(DrmDevice &dev, uint32_t connector_id,
@@ -42,6 +45,9 @@ class DrmConnector : public PipelineBindable<DrmConnector> {
 
   int UpdateEdidProperty();
   auto GetEdidBlob() -> DrmModePropertyBlobUnique;
+  auto GetParsedEdid() -> EdidWrapperUnique & {
+    return edid_wrapper_;
+  }
 
   auto GetDev() const -> DrmDevice & {
     return *drm_;
@@ -109,6 +115,14 @@ class DrmConnector : public PipelineBindable<DrmConnector> {
     return content_type_property_;
   }
 
+  auto &GetMinBpcProperty() const {
+    return min_bpc_property_;
+  }
+
+  auto &GetHdrOutputMetadataProperty() const {
+    return hdr_output_metadata_property_;
+  }
+
   auto &GetWritebackFbIdProperty() const {
     return writeback_fb_id_;
   }
@@ -147,6 +161,12 @@ class DrmConnector : public PipelineBindable<DrmConnector> {
   auto Init() -> bool;
   auto GetConnectorProperty(const char *prop_name, DrmProperty *property,
                             bool is_optional = false) -> bool;
+  auto GetOptionalConnectorProperty(const char *prop_name,
+                                    DrmProperty *property) -> bool {
+    return GetConnectorProperty(prop_name, property, /*is_optional=*/true);
+  }
+
+  EdidWrapperUnique edid_wrapper_;
 
   const uint32_t index_in_res_array_;
 
@@ -157,6 +177,8 @@ class DrmConnector : public PipelineBindable<DrmConnector> {
   DrmProperty edid_property_;
   DrmProperty colorspace_property_;
   DrmProperty content_type_property_;
+  DrmProperty min_bpc_property_;
+  DrmProperty hdr_output_metadata_property_;
 
   DrmProperty link_status_property_;
   DrmProperty writeback_pixel_formats_;
diff --git a/drm/DrmDevice.cpp b/drm/DrmDevice.cpp
index 4534104..f6141d4 100644
--- a/drm/DrmDevice.cpp
+++ b/drm/DrmDevice.cpp
@@ -18,6 +18,7 @@
 
 #include "DrmDevice.h"
 
+#include <sys/mman.h>
 #include <xf86drm.h>
 #include <xf86drmMode.h>
 
@@ -34,13 +35,13 @@
 namespace android {
 
 auto DrmDevice::CreateInstance(std::string const &path,
-                               ResourceManager *res_man)
+                               ResourceManager *res_man, uint32_t index)
     -> std::unique_ptr<DrmDevice> {
   if (!IsKMSDev(path.c_str())) {
     return {};
   }
 
-  auto device = std::unique_ptr<DrmDevice>(new DrmDevice(res_man));
+  auto device = std::unique_ptr<DrmDevice>(new DrmDevice(res_man, index));
 
   if (device->Init(path.c_str()) != 0) {
     return {};
@@ -49,7 +50,8 @@ auto DrmDevice::CreateInstance(std::string const &path,
   return device;
 }
 
-DrmDevice::DrmDevice(ResourceManager *res_man) : res_man_(res_man) {
+DrmDevice::DrmDevice(ResourceManager *res_man, uint32_t index)
+    : index_in_dev_array_(index), res_man_(res_man) {
   drm_fb_importer_ = std::make_unique<DrmFbImporter>(*this);
 }
 
@@ -88,6 +90,14 @@ auto DrmDevice::Init(const char *path) -> int {
   }
   HasAddFb2ModifiersSupport_ = cap_value != 0;
 
+  uint64_t cursor_width = 0;
+  uint64_t cursor_height = 0;
+  if (drmGetCap(*GetFd(), DRM_CAP_CURSOR_WIDTH, &cursor_width) == 0 &&
+      drmGetCap(*GetFd(), DRM_CAP_CURSOR_HEIGHT, &cursor_height) == 0) {
+    cap_cursor_size_ = std::pair<uint64_t, uint64_t>(cursor_width,
+                                                     cursor_height);
+  }
+
   drmSetMaster(*GetFd());
   if (drmIsMaster(*GetFd()) == 0) {
     ALOGE("DRM/KMS master access required");
@@ -198,7 +208,7 @@ int DrmDevice::GetProperty(uint32_t obj_id, uint32_t obj_type,
     drmModePropertyPtr p = drmModeGetProperty(*GetFd(), props->props[i]);
     if (strcmp(p->name, prop_name) == 0) {
       // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
-      property->Init(obj_id, p, props->prop_values[i]);
+      property->Init(GetFd(), obj_id, p, props->prop_values[i]);
       found = true;
     }
     drmModeFreeProperty(p);
@@ -260,4 +270,93 @@ auto DrmDevice::GetEncoders()
   return encoders_;
 }
 
+class DumbBufferFd : public PrimeFdsSharedBase {
+ public:
+  SharedFd fd;
+};
+
+// NOLINTBEGIN(cppcoreguidelines-avoid-goto)
+auto DrmDevice::CreateBufferForModeset(uint32_t width, uint32_t height)
+    -> std::optional<BufferInfo> {
+  constexpr uint32_t kDumbBufferFormat = DRM_FORMAT_XRGB8888;
+  constexpr uint32_t kDumbBufferBpp = 32;
+
+  std::optional<BufferInfo> result;
+  void *ptr = MAP_FAILED;
+  struct drm_mode_create_dumb create = {
+      .height = height,
+      .width = width,
+      .bpp = kDumbBufferBpp,
+      .flags = 0,
+  };
+
+  int ret = drmIoctl(*fd_, DRM_IOCTL_MODE_CREATE_DUMB, &create);
+  if (ret != 0) {
+    ALOGE("Failed to DRM_IOCTL_MODE_CREATE_DUMB %d", errno);
+    return {};
+  }
+
+  struct drm_mode_map_dumb map = {
+      .handle = create.handle,
+  };
+
+  auto dumb_buffer_fd = std::make_shared<DumbBufferFd>();
+
+  BufferInfo buffer_info = {
+      .width = width,
+      .height = height,
+
+      .format = kDumbBufferFormat,
+      .pitches = {create.pitch},
+      .prime_fds = {-1, -1, -1, -1},
+      .modifiers = {DRM_FORMAT_MOD_NONE},
+
+      .color_space = BufferColorSpace::kUndefined,
+      .sample_range = BufferSampleRange::kUndefined,
+      .blend_mode = BufferBlendMode::kNone,
+
+      .fds_shared = dumb_buffer_fd,
+  };
+
+  ret = drmIoctl(*fd_, DRM_IOCTL_MODE_MAP_DUMB, &map);
+  if (ret != 0) {
+    ALOGE("Failed to DRM_IOCTL_MODE_MAP_DUMB %d", errno);
+    goto done;
+  }
+
+  ptr = mmap(nullptr, create.size, PROT_READ | PROT_WRITE, MAP_SHARED, *fd_,
+             (off_t)map.offset);
+  if (ptr == MAP_FAILED) {
+    ALOGE("Failed to mmap dumb buffer %d", errno);
+    goto done;
+  }
+
+  memset(ptr, 0, create.size);
+
+  if (munmap(ptr, create.size) != 0) {
+    ALOGE("Failed to unmap dumb buffer: %d", errno);
+  }
+
+  ret = drmPrimeHandleToFD(*fd_, create.handle, 0, &buffer_info.prime_fds[0]);
+  if (ret != 0) {
+    ALOGE("Failed to export dumb buffer as FD: %d", errno);
+    goto done;
+  }
+
+  dumb_buffer_fd->fd = MakeSharedFd(buffer_info.prime_fds[0]);
+
+  result = buffer_info;
+
+done:
+  if (create.handle > 0) {
+    struct drm_mode_destroy_dumb destroy = {
+        .handle = create.handle,
+    };
+    drmIoctl(*fd_, DRM_IOCTL_MODE_DESTROY_DUMB, &destroy);
+  }
+
+  return result;
+}
+// NOLINTEND(cppcoreguidelines-avoid-goto)
+
 }  // namespace android
diff --git a/drm/DrmDevice.h b/drm/DrmDevice.h
index cbaa536..ac20855 100644
--- a/drm/DrmDevice.h
+++ b/drm/DrmDevice.h
@@ -18,11 +18,13 @@
 
 #include <cstdint>
 #include <map>
+#include <optional>
 #include <tuple>
 
 #include "DrmConnector.h"
 #include "DrmCrtc.h"
 #include "DrmEncoder.h"
+#include "bufferinfo/BufferInfo.h"
 #include "utils/fd.h"
 
 namespace android {
@@ -35,13 +37,17 @@ class DrmDevice {
  public:
   ~DrmDevice() = default;
 
-  static auto CreateInstance(std::string const &path, ResourceManager *res_man)
-      -> std::unique_ptr<DrmDevice>;
+  static auto CreateInstance(std::string const &path, ResourceManager *res_man,
+                             uint32_t index) -> std::unique_ptr<DrmDevice>;
 
   auto &GetFd() const {
     return fd_;
   }
 
+  auto GetIndexInDevArray() const {
+    return index_in_dev_array_;
+  }
+
   auto &GetResMan() {
     return *res_man_;
   }
@@ -70,6 +76,9 @@ class DrmDevice {
     return HasAddFb2ModifiersSupport_;
   }
 
+  auto CreateBufferForModeset(uint32_t width, uint32_t height)
+      -> std::optional<BufferInfo>;
+
   auto &GetDrmFbImporter() {
     return *drm_fb_importer_;
   }
@@ -97,13 +106,18 @@ class DrmDevice {
   int GetProperty(uint32_t obj_id, uint32_t obj_type, const char *prop_name,
                   DrmProperty *property) const;
 
+  const std::optional<std::pair<uint64_t, uint64_t>> &GetCapCursorSize() const {
+    return cap_cursor_size_;
+  }
+
  private:
-  explicit DrmDevice(ResourceManager *res_man);
+  explicit DrmDevice(ResourceManager *res_man, uint32_t index);
   auto Init(const char *path) -> int;
 
   static auto IsKMSDev(const char *path) -> bool;
 
   SharedFd fd_;
+  const uint32_t index_in_dev_array_;
 
   std::vector<std::unique_ptr<DrmConnector>> connectors_;
   std::vector<std::unique_ptr<DrmConnector>> writeback_connectors_;
@@ -113,6 +127,7 @@ class DrmDevice {
 
   std::pair<uint32_t, uint32_t> min_resolution_;
   std::pair<uint32_t, uint32_t> max_resolution_;
+  std::optional<std::pair<uint64_t, uint64_t>> cap_cursor_size_;
 
   bool HasAddFb2ModifiersSupport_{};
 
@@ -120,4 +135,5 @@ class DrmDevice {
 
   ResourceManager *const res_man_;
 };
+
 }  // namespace android
diff --git a/drm/DrmDisplayPipeline.cpp b/drm/DrmDisplayPipeline.cpp
index 2d81578..8062b2c 100644
--- a/drm/DrmDisplayPipeline.cpp
+++ b/drm/DrmDisplayPipeline.cpp
@@ -65,18 +65,21 @@ static auto TryCreatePipeline(DrmDevice &dev, DrmConnector &connector,
   }
 
   std::vector<DrmPlane *> primary_planes;
-  std::vector<DrmPlane *> overlay_planes;
 
   /* Attach necessary resources */
   auto display_planes = std::vector<DrmPlane *>();
   for (const auto &plane : dev.GetPlanes()) {
     if (plane->IsCrtcSupported(crtc)) {
-      if (plane->GetType() == DRM_PLANE_TYPE_PRIMARY) {
-        primary_planes.emplace_back(plane.get());
-      } else if (plane->GetType() == DRM_PLANE_TYPE_OVERLAY) {
-        overlay_planes.emplace_back(plane.get());
-      } else {
-        ALOGI("Ignoring cursor plane %d", plane->GetId());
+      switch (plane->GetType()) {
+        case DRM_PLANE_TYPE_PRIMARY:
+          primary_planes.emplace_back(plane.get());
+          break;
+        case DRM_PLANE_TYPE_OVERLAY:
+        case DRM_PLANE_TYPE_CURSOR:
+          break;
+        default:
+          ALOGE("Unknown type for plane %d", plane->GetId());
+          break;
       }
     }
   }
@@ -158,35 +161,34 @@ auto DrmDisplayPipeline::CreatePipeline(DrmConnector &connector)
   return {};
 }
 
-static bool ReadUseOverlayProperty() {
-  char use_overlay_planes_prop[PROPERTY_VALUE_MAX];
-  property_get("vendor.hwc.drm.use_overlay_planes", use_overlay_planes_prop,
-               "1");
-  constexpr int kStrtolBase = 10;
-  return strtol(use_overlay_planes_prop, nullptr, kStrtolBase) != 0;
-}
+auto DrmDisplayPipeline::GetUsablePlanes() -> UsablePlanes {
+  UsablePlanes pair;
+  auto &[planes, cursor] = pair;
 
-auto DrmDisplayPipeline::GetUsablePlanes()
-    -> std::vector<std::shared_ptr<BindingOwner<DrmPlane>>> {
-  std::vector<std::shared_ptr<BindingOwner<DrmPlane>>> planes;
   planes.emplace_back(primary_plane);
 
-  const static bool kUseOverlayPlanes = ReadUseOverlayProperty();
-
-  if (kUseOverlayPlanes) {
-    for (const auto &plane : device->GetPlanes()) {
-      if (plane->IsCrtcSupported(*crtc->Get())) {
-        if (plane->GetType() == DRM_PLANE_TYPE_OVERLAY) {
-          auto op = plane->BindPipeline(this, true);
-          if (op) {
-            planes.emplace_back(op);
-          }
+  for (const auto &plane : device->GetPlanes()) {
+    if (plane->IsCrtcSupported(*crtc->Get())) {
+      if (Properties::UseOverlayPlanes() &&
+          plane->GetType() == DRM_PLANE_TYPE_OVERLAY) {
+        auto op = plane->BindPipeline(this, true);
+        if (op) {
+          planes.emplace_back(op);
+        }
+      } else if (plane->GetType() == DRM_PLANE_TYPE_CURSOR) {
+        if (cursor) {
+          ALOGW(
+              "Encountered multiple cursor planes for CRTC %d. Ignoring "
+              "plane %d",
+              crtc->Get()->GetId(), plane->GetId());
+        } else {
+          cursor = plane->BindPipeline(this, true);
         }
       }
     }
   }
 
-  return planes;
+  return pair;
 }
 
 DrmDisplayPipeline::~DrmDisplayPipeline() {
diff --git a/drm/DrmDisplayPipeline.h b/drm/DrmDisplayPipeline.h
index cf64a36..0d05288 100644
--- a/drm/DrmDisplayPipeline.h
+++ b/drm/DrmDisplayPipeline.h
@@ -67,12 +67,15 @@ class BindingOwner {
   B *const bindable_;
 };
 
+using UsablePlanes = std::pair<
+    std::vector<std::shared_ptr<BindingOwner<DrmPlane>>>,
+    std::shared_ptr<BindingOwner<DrmPlane>>>;
+
 struct DrmDisplayPipeline {
   static auto CreatePipeline(DrmConnector &connector)
       -> std::unique_ptr<DrmDisplayPipeline>;
 
-  auto GetUsablePlanes()
-      -> std::vector<std::shared_ptr<BindingOwner<DrmPlane>>>;
+  auto GetUsablePlanes() -> UsablePlanes;
 
   ~DrmDisplayPipeline();
 
diff --git a/drm/DrmHwc.cpp b/drm/DrmHwc.cpp
index aaba506..3f30123 100644
--- a/drm/DrmHwc.cpp
+++ b/drm/DrmHwc.cpp
@@ -200,7 +200,7 @@ uint32_t DrmHwc::GetMaxVirtualDisplayCount() {
   /* Virtual display is an experimental feature.
    * Unless explicitly set to true, return 0 for no support.
    */
-  if (0 == property_get_bool("vendor.hwc.drm.enable_virtual_display", 0)) {
+  if (!Properties::EnableVirtualDisplay()) {
     return 0;
   }
 
diff --git a/drm/DrmMode.cpp b/drm/DrmMode.cpp
index 7cbea44..d9fdb37 100644
--- a/drm/DrmMode.cpp
+++ b/drm/DrmMode.cpp
@@ -28,6 +28,11 @@ bool DrmMode::operator==(const drmModeModeInfo &m) const {
   return memcmp(&m, &mode_, offsetof(drmModeModeInfo, name)) == 0;
 }
 
+bool DrmMode::SameSize(const DrmMode &mode) const {
+  return (mode_.vdisplay == mode.mode_.vdisplay) &&
+         (mode_.hdisplay == mode.mode_.hdisplay);
+}
+
 auto DrmMode::CreateModeBlob(const DrmDevice &drm)
     -> DrmModeUserPropertyBlobUnique {
   struct drm_mode_modeinfo drm_mode = {};
diff --git a/drm/DrmMode.h b/drm/DrmMode.h
index 5450daf..7520824 100644
--- a/drm/DrmMode.h
+++ b/drm/DrmMode.h
@@ -35,6 +35,8 @@ class DrmMode {
 
   bool operator==(const drmModeModeInfo &m) const;
 
+  bool SameSize(const DrmMode &mode) const;
+
   auto &GetRawMode() const {
     return mode_;
   }
diff --git a/drm/DrmPlane.cpp b/drm/DrmPlane.cpp
index dbb5ad6..2251a78 100644
--- a/drm/DrmPlane.cpp
+++ b/drm/DrmPlane.cpp
@@ -25,6 +25,7 @@
 
 #include "DrmDevice.h"
 #include "bufferinfo/BufferInfoGetter.h"
+#include "compositor/LayerData.h"
 #include "utils/log.h"
 
 namespace android {
@@ -88,22 +89,8 @@ int DrmPlane::Init() {
 
   GetPlaneProperty("zpos", zpos_property_, Presence::kOptional);
 
-  /* DRM/KMS uses counter-clockwise rotations, while HWC API uses
-   * clockwise. That's why 90 and 270 are swapped here.
-   */
   if (GetPlaneProperty("rotation", rotation_property_, Presence::kOptional)) {
-    rotation_property_.AddEnumToMap("rotate-0", LayerTransform::kIdentity,
-                                    transform_enum_map_);
-    rotation_property_.AddEnumToMap("rotate-90", LayerTransform::kRotate270,
-                                    transform_enum_map_);
-    rotation_property_.AddEnumToMap("rotate-180", LayerTransform::kRotate180,
-                                    transform_enum_map_);
-    rotation_property_.AddEnumToMap("rotate-270", LayerTransform::kRotate90,
-                                    transform_enum_map_);
-    rotation_property_.AddEnumToMap("reflect-x", LayerTransform::kFlipH,
-                                    transform_enum_map_);
-    rotation_property_.AddEnumToMap("reflect-y", LayerTransform::kFlipV,
-                                    transform_enum_map_);
+    rotation_property_.GetEnumMask(transform_enum_mask_);
   }
 
   GetPlaneProperty("alpha", alpha_property_, Presence::kOptional);
@@ -121,17 +108,17 @@ int DrmPlane::Init() {
   GetPlaneProperty("IN_FENCE_FD", in_fence_fd_property_, Presence::kOptional);
 
   if (HasNonRgbFormat()) {
-    if (GetPlaneProperty("COLOR_ENCODING", color_encoding_propery_,
+    if (GetPlaneProperty("COLOR_ENCODING", color_encoding_property_,
                          Presence::kOptional)) {
-      color_encoding_propery_.AddEnumToMap("ITU-R BT.709 YCbCr",
-                                           BufferColorSpace::kItuRec709,
-                                           color_encoding_enum_map_);
-      color_encoding_propery_.AddEnumToMap("ITU-R BT.601 YCbCr",
-                                           BufferColorSpace::kItuRec601,
-                                           color_encoding_enum_map_);
-      color_encoding_propery_.AddEnumToMap("ITU-R BT.2020 YCbCr",
-                                           BufferColorSpace::kItuRec2020,
-                                           color_encoding_enum_map_);
+      color_encoding_property_.AddEnumToMap("ITU-R BT.709 YCbCr",
+                                            BufferColorSpace::kItuRec709,
+                                            color_encoding_enum_map_);
+      color_encoding_property_.AddEnumToMap("ITU-R BT.601 YCbCr",
+                                            BufferColorSpace::kItuRec601,
+                                            color_encoding_enum_map_);
+      color_encoding_property_.AddEnumToMap("ITU-R BT.2020 YCbCr",
+                                            BufferColorSpace::kItuRec2020,
+                                            color_encoding_enum_map_);
     }
 
     if (GetPlaneProperty("COLOR_RANGE", color_range_property_,
@@ -145,6 +132,12 @@ int DrmPlane::Init() {
     }
   }
 
+  if (type_ == DRM_PLANE_TYPE_CURSOR &&
+      GetPlaneProperty("SIZE_HINTS", size_hints_property_,
+                       Presence::kOptional)) {
+    size_hints_property_.GetBlobData(size_hints_);
+  }
+
   return 0;
 }
 
@@ -159,32 +152,50 @@ bool DrmPlane::IsCrtcSupported(const DrmCrtc &crtc) const {
     // any CRTC already, which is protected by the plane_switching_crtc function
     // in the kernel drivers/gpu/drm/drm_atomic.c file.
     // The current drm_hwc design is not ready to support such scenario yet,
-    // so adding the CRTC status check here to workaorund for now.
+    // so adding the CRTC status check here to workaround for now.
     return false;
   }
 
   return ((1 << crtc.GetIndexInResArray()) & plane_->possible_crtcs) != 0;
 }
 
+static uint64_t ToDrmRotation(LayerTransform transform) {
+  /* DRM/KMS uses counter-clockwise rotations, while HWC API uses
+   * clockwise. That's why 90 and 270 are swapped here.
+   */
+  uint64_t rotation = DRM_MODE_ROTATE_0;
+
+  if (transform.rotate90) {
+    rotation |= DRM_MODE_ROTATE_270;
+  }
+
+  if (transform.hflip) {
+    rotation |= DRM_MODE_REFLECT_X;
+  }
+
+  if (transform.vflip) {
+    rotation |= DRM_MODE_REFLECT_Y;
+  }
+
+  // TODO(nobody): Respect transform_enum_mask_ to find alternative rotation
+  // values
+
+  return rotation;
+}
+
 bool DrmPlane::IsValidForLayer(LayerData *layer) {
   if (layer == nullptr || !layer->bi) {
     ALOGE("%s: Invalid parameters", __func__);
     return false;
   }
 
-  if (!rotation_property_) {
-    if (layer->pi.transform != LayerTransform::kIdentity) {
-      ALOGV("No rotation property on plane %d", GetId());
-      return false;
-    }
-  } else {
-    if (transform_enum_map_.count(layer->pi.transform) == 0) {
-      ALOGV("Transform is not supported on plane %d", GetId());
-      return false;
-    }
+  uint64_t drm_rotation = ToDrmRotation(layer->pi.transform);
+  if ((drm_rotation & transform_enum_mask_) != drm_rotation) {
+    ALOGV("Transform is not supported on plane %d", GetId());
+    return false;
   }
 
-  if (!alpha_property_ && layer->pi.alpha != UINT16_MAX) {
+  if (!alpha_property_ && layer->pi.alpha != kAlphaOpaque) {
     ALOGV("Alpha is not supported on plane %d", GetId());
     return false;
   }
@@ -203,6 +214,13 @@ bool DrmPlane::IsValidForLayer(LayerData *layer) {
     return false;
   }
 
+  if (type_ == DRM_PLANE_TYPE_CURSOR &&
+      !IsBufferValidForCursorPlane(layer->bi.value())) {
+    ALOGV("Buffer size %dx%d is not supported by cursor plane %d",
+          layer->bi->width, layer->bi->height, GetId());
+    return false;
+  }
+
   return true;
 }
 
@@ -218,27 +236,6 @@ bool DrmPlane::HasNonRgbFormat() const {
                           }) != std::end(formats_);
 }
 
-static uint64_t ToDrmRotation(LayerTransform transform) {
-  uint64_t rotation = 0;
-  /* DRM/KMS uses counter-clockwise rotations, while HWC API uses
-   * clockwise. That's why 90 and 270 are swapped here.
-   */
-  if ((transform & LayerTransform::kFlipH) != 0)
-    rotation |= DRM_MODE_REFLECT_X;
-  if ((transform & LayerTransform::kFlipV) != 0)
-    rotation |= DRM_MODE_REFLECT_Y;
-  if ((transform & LayerTransform::kRotate90) != 0)
-    rotation |= DRM_MODE_ROTATE_270;
-  else if ((transform & LayerTransform::kRotate180) != 0)
-    rotation |= DRM_MODE_ROTATE_180;
-  else if ((transform & LayerTransform::kRotate270) != 0)
-    rotation |= DRM_MODE_ROTATE_90;
-  else
-    rotation |= DRM_MODE_ROTATE_0;
-
-  return rotation;
-}
-
 /* Convert float to 16.16 fixed point */
 static int To1616FixPt(float in) {
   constexpr int kBitShift = 16;
@@ -246,7 +243,8 @@ static int To1616FixPt(float in) {
 }
 
 auto DrmPlane::AtomicSetState(drmModeAtomicReq &pset, LayerData &layer,
-                              uint32_t zpos, uint32_t crtc_id) -> int {
+                              uint32_t zpos, uint32_t crtc_id,
+                              DstRectInfo &whole_display_rect) -> int {
   if (!layer.fb || !layer.bi) {
     ALOGE("%s: Invalid arguments", __func__);
     return -EINVAL;
@@ -268,8 +266,31 @@ auto DrmPlane::AtomicSetState(drmModeAtomicReq &pset, LayerData &layer,
     return -EINVAL;
   }
 
-  auto &disp = layer.pi.display_frame;
-  auto &src = layer.pi.source_crop;
+  auto opt_disp = layer.pi.display_frame.i_rect;
+  if (!layer.pi.display_frame.i_rect) {
+    opt_disp = whole_display_rect.i_rect;
+  }
+
+  auto opt_src = layer.pi.source_crop.f_rect;
+  if (!layer.pi.source_crop.f_rect) {
+    opt_src = {0.0F, 0.0F, float(layer.bi->width), float(layer.bi->height)};
+  }
+
+  if (!opt_disp || !opt_src) {
+    ALOGE("%s: Invalid display frame or source crop", __func__);
+    return -EINVAL;
+  }
+
+  auto disp = opt_disp.value();
+  auto src = opt_src.value();
+
+  if (type_ == DRM_PLANE_TYPE_CURSOR) {
+    disp.right = disp.left + static_cast<int>(layer.bi->width);
+    disp.bottom = disp.top + static_cast<int>(layer.bi->height);
+    src = {0, 0, static_cast<float>(layer.bi->width),
+           static_cast<float>(layer.bi->height)};
+  }
+
   if (!crtc_property_.AtomicSet(pset, crtc_id) ||
       !fb_property_.AtomicSet(pset, layer.fb->GetFbId()) ||
       !crtc_x_property_.AtomicSet(pset, disp.left) ||
@@ -288,7 +309,9 @@ auto DrmPlane::AtomicSetState(drmModeAtomicReq &pset, LayerData &layer,
     return -EINVAL;
   }
 
-  if (alpha_property_ && !alpha_property_.AtomicSet(pset, layer.pi.alpha)) {
+  if (alpha_property_ &&
+      !alpha_property_.AtomicSet(pset,
+                                 std::lround(layer.pi.alpha * UINT16_MAX))) {
     return -EINVAL;
   }
 
@@ -299,7 +322,7 @@ auto DrmPlane::AtomicSetState(drmModeAtomicReq &pset, LayerData &layer,
   }
 
   if (color_encoding_enum_map_.count(layer.bi->color_space) != 0 &&
-      !color_encoding_propery_
+      !color_encoding_property_
            .AtomicSet(pset, color_encoding_enum_map_[layer.bi->color_space])) {
     return -EINVAL;
   }
@@ -339,4 +362,21 @@ auto DrmPlane::GetPlaneProperty(const char *prop_name, DrmProperty &property,
   return true;
 }
 
+bool DrmPlane::HasCursorSizeConstraints() const {
+  return drm_->GetCapCursorSize().has_value() || !size_hints_.empty();
+}
+
+bool DrmPlane::IsBufferValidForCursorPlane(const BufferInfo &bi) const {
+  if (std::find_if(size_hints_.begin(), size_hints_.end(),
+                   [&](const auto &hint) -> bool {
+                     return bi.width == hint.width && bi.height == hint.height;
+                   }) != size_hints_.end()) {
+    return true;
+  }
+
+  const auto &cap_size = drm_->GetCapCursorSize();
+  return cap_size.has_value() && bi.width == cap_size->first &&
+         bi.height == cap_size->second;
+}
+
 }  // namespace android
diff --git a/drm/DrmPlane.h b/drm/DrmPlane.h
index c26a3cc..2fa6388 100644
--- a/drm/DrmPlane.h
+++ b/drm/DrmPlane.h
@@ -30,6 +30,12 @@ namespace android {
 class DrmDevice;
 struct LayerData;
 
+// NOLINTNEXTLINE(readability-identifier-naming)
+struct drm_plane_size_hint_local {
+  __u16 width;
+  __u16 height;
+};
+
 class DrmPlane : public PipelineBindable<DrmPlane> {
  public:
   DrmPlane(const DrmPlane &) = delete;
@@ -49,7 +55,7 @@ class DrmPlane : public PipelineBindable<DrmPlane> {
   bool HasNonRgbFormat() const;
 
   auto AtomicSetState(drmModeAtomicReq &pset, LayerData &layer, uint32_t zpos,
-                      uint32_t crtc_id) -> int;
+                      uint32_t crtc_id, DstRectInfo &whole_display_rect) -> int;
   auto AtomicDisablePlane(drmModeAtomicReq &pset) -> int;
   auto &GetZPosProperty() const {
     return zpos_property_;
@@ -59,6 +65,8 @@ class DrmPlane : public PipelineBindable<DrmPlane> {
     return plane_->plane_id;
   }
 
+  bool HasCursorSizeConstraints() const;
+
  private:
   DrmPlane(DrmDevice &dev, DrmModePlaneUnique plane)
       : drm_(&dev), plane_(std::move(plane)){};
@@ -70,6 +78,7 @@ class DrmPlane : public PipelineBindable<DrmPlane> {
   auto Init() -> int;
   auto GetPlaneProperty(const char *prop_name, DrmProperty &property,
                         Presence presence = Presence::kMandatory) -> bool;
+  bool IsBufferValidForCursorPlane(const BufferInfo &bi) const;
 
   uint32_t type_{};
 
@@ -90,12 +99,14 @@ class DrmPlane : public PipelineBindable<DrmPlane> {
   DrmProperty alpha_property_;
   DrmProperty blend_property_;
   DrmProperty in_fence_fd_property_;
-  DrmProperty color_encoding_propery_;
+  DrmProperty color_encoding_property_;
   DrmProperty color_range_property_;
+  DrmProperty size_hints_property_;
 
   std::map<BufferBlendMode, uint64_t> blending_enum_map_;
   std::map<BufferColorSpace, uint64_t> color_encoding_enum_map_;
   std::map<BufferSampleRange, uint64_t> color_range_enum_map_;
-  std::map<LayerTransform, uint64_t> transform_enum_map_;
+  uint64_t transform_enum_mask_ = DRM_MODE_ROTATE_0;
+  std::vector<drm_plane_size_hint_local> size_hints_;
 };
 }  // namespace android
diff --git a/drm/DrmProperty.cpp b/drm/DrmProperty.cpp
index dbd307e..24a67bc 100644
--- a/drm/DrmProperty.cpp
+++ b/drm/DrmProperty.cpp
@@ -35,12 +35,14 @@ DrmProperty::DrmPropertyEnum::DrmPropertyEnum(drm_mode_property_enum *e)
     : value(e->value), name(e->name) {
 }
 
-DrmProperty::DrmProperty(uint32_t obj_id, drmModePropertyPtr p,
-                         uint64_t value) {
-  Init(obj_id, p, value);
+DrmProperty::DrmProperty(const SharedFd &fd, uint32_t obj_id,
+                         drmModePropertyPtr p, uint64_t value) {
+  Init(fd, obj_id, p, value);
 }
 
-void DrmProperty::Init(uint32_t obj_id, drmModePropertyPtr p, uint64_t value) {
+void DrmProperty::Init(const SharedFd &fd, uint32_t obj_id,
+                       drmModePropertyPtr p, uint64_t value) {
+  fd_ = fd;
   obj_id_ = obj_id;
   id_ = p->prop_id;
   flags_ = p->flags;
@@ -144,4 +146,24 @@ std::optional<std::string> DrmProperty::GetEnumNameFromValue(
   return {};
 }
 
+auto DrmProperty::GetEnumMask(uint64_t &mask) -> bool {
+  if (enums_.empty()) {
+    ALOGE("No enum values for property: %s", name_.c_str());
+    return false;
+  }
+
+  if (!IsBitmask()) {
+    ALOGE("Property %s is not a bitmask property.", name_.c_str());
+    return false;
+  }
+
+  mask = 0;
+
+  for (const auto &it : enums_) {
+    mask |= (1 << it.value);
+  }
+
+  return true;
+}
+
 }  // namespace android
diff --git a/drm/DrmProperty.h b/drm/DrmProperty.h
index 2683ad8..c0f6161 100644
--- a/drm/DrmProperty.h
+++ b/drm/DrmProperty.h
@@ -18,22 +18,29 @@
 
 #include <xf86drmMode.h>
 
+#include <cinttypes>
 #include <cstdint>
 #include <map>
 #include <optional>
 #include <string>
 #include <vector>
 
+#include "drm/DrmUnique.h"
+#include "utils/fd.h"
+#include "utils/log.h"
+
 namespace android {
 
 class DrmProperty {
  public:
   DrmProperty() = default;
-  DrmProperty(uint32_t obj_id, drmModePropertyPtr p, uint64_t value);
+  DrmProperty(const SharedFd &fd, uint32_t obj_id, drmModePropertyPtr p,
+              uint64_t value);
   DrmProperty(const DrmProperty &) = delete;
   DrmProperty &operator=(const DrmProperty &) = delete;
 
-  auto Init(uint32_t obj_id, drmModePropertyPtr p, uint64_t value) -> void;
+  auto Init(const SharedFd &fd, uint32_t obj_id, drmModePropertyPtr p,
+            uint64_t value) -> void;
   std::tuple<uint64_t, int> GetEnumValueWithName(const std::string &name) const;
 
   auto GetId() const {
@@ -54,6 +61,10 @@ class DrmProperty {
     return id_ != 0 && (flags_ & DRM_MODE_PROP_RANGE) != 0;
   }
 
+  bool IsBitmask() const {
+    return id_ != 0 && (flags_ & DRM_MODE_PROP_BITMASK) != 0;
+  }
+
   auto RangeMin() const -> std::tuple<int, uint64_t>;
   auto RangeMax() const -> std::tuple<int, uint64_t>;
 
@@ -68,12 +79,20 @@ class DrmProperty {
   auto AddEnumToMapReverse(const std::string &name, E value,
                            std::map<uint64_t, E> &map) -> bool;
 
+  auto GetEnumMask(uint64_t &mask) -> bool;
+
   explicit operator bool() const {
     return id_ != 0;
   }
 
   auto GetEnumNameFromValue(uint64_t value) const -> std::optional<std::string>;
 
+  bool IsBlob() const {
+    return id_ != 0 && (flags_ & DRM_MODE_PROP_BLOB) != 0;
+  }
+  template <typename T>
+  bool GetBlobData(std::vector<T> &data_out) const;
+
  private:
   class DrmPropertyEnum {
    public:
@@ -84,6 +103,7 @@ class DrmProperty {
     std::string name;
   };
 
+  SharedFd fd_ = nullptr;
   uint32_t obj_id_ = 0;
   uint32_t id_ = 0;
 
@@ -124,4 +144,43 @@ auto DrmProperty::AddEnumToMapReverse(const std::string &name, E value,
   return false;
 }
 
+template <typename T>
+bool DrmProperty::GetBlobData(std::vector<T> &data_out) const {
+  auto value = GetValue();
+  if (!fd_) {
+    ALOGE("Could not read blob data from property %s: No fd", name_.c_str());
+    return false;
+  }
+  if (!IsBlob()) {
+    ALOGE("Property %s is not blob type", name_.c_str());
+    return false;
+  }
+  if (!value.has_value()) {
+    ALOGE("Could not read blob data from property %s: No blob id",
+          name_.c_str());
+    return false;
+  }
+
+  auto blob = MakeDrmModePropertyBlobUnique(*fd_, value.value());
+  if (blob == nullptr) {
+    ALOGE("Failed to read blob with id=%" PRIu64 " from property %s",
+          value.value(), name_.c_str());
+    return false;
+  }
+
+  if (blob->length % sizeof(T) != 0) {
+    ALOGE(
+        "Property %s blob size of %u bytes is not divisible by type argument "
+        "size of %zu bytes",
+        name_.c_str(), blob->length, sizeof(T));
+    return false;
+  }
+
+  auto cast_data = static_cast<T *>(blob->data);
+  size_t cast_data_length = blob->length / sizeof(T);
+  data_out.assign(cast_data, cast_data + cast_data_length);
+
+  return true;
+}
+
 }  // namespace android
diff --git a/drm/ResourceManager.cpp b/drm/ResourceManager.cpp
index 0c23734..fee251e 100644
--- a/drm/ResourceManager.cpp
+++ b/drm/ResourceManager.cpp
@@ -55,7 +55,7 @@ void ResourceManager::Init() {
   auto path_len = property_get("vendor.hwc.drm.device", path_pattern,
                                "/dev/dri/card%");
   if (path_pattern[path_len - 1] != '%') {
-    auto dev = DrmDevice::CreateInstance(path_pattern, this);
+    auto dev = DrmDevice::CreateInstance(path_pattern, this, 0);
     if (dev) {
       drms_.emplace_back(std::move(dev));
     }
@@ -69,17 +69,16 @@ void ResourceManager::Init() {
       if (stat(path.str().c_str(), &buf) != 0)
         break;
 
-      auto dev = DrmDevice::CreateInstance(path.str(), this);
+      auto dev = DrmDevice::CreateInstance(path.str(), this, idx);
       if (dev) {
         drms_.emplace_back(std::move(dev));
       }
     }
   }
 
-  char proptext[PROPERTY_VALUE_MAX];
-  property_get("vendor.hwc.drm.scale_with_gpu", proptext, "0");
-  scale_with_gpu_ = bool(strncmp(proptext, "0", 1));
+  scale_with_gpu_ = Properties::ScaleWithGpu();
 
+  char proptext[PROPERTY_VALUE_MAX];
   constexpr char kDrmOrGpu[] = "DRM_OR_GPU";
   constexpr char kDrmOrIgnore[] = "DRM_OR_IGNORE";
   property_get("vendor.hwc.drm.ctm", proptext, kDrmOrGpu);
@@ -125,7 +124,7 @@ auto ResourceManager::GetTimeMonotonicNs() -> int64_t {
   struct timespec ts {};
   clock_gettime(CLOCK_MONOTONIC, &ts);
   constexpr int64_t kNsInSec = 1000000000LL;
-  return int64_t(ts.tv_sec) * kNsInSec + int64_t(ts.tv_nsec);
+  return (int64_t(ts.tv_sec) * kNsInSec) + int64_t(ts.tv_nsec);
 }
 
 void ResourceManager::UpdateFrontendDisplays() {
diff --git a/drm/VSyncWorker.cpp b/drm/VSyncWorker.cpp
index 963a37b..4b08515 100644
--- a/drm/VSyncWorker.cpp
+++ b/drm/VSyncWorker.cpp
@@ -30,12 +30,9 @@
 
 namespace android {
 
-auto VSyncWorker::CreateInstance(std::shared_ptr<DrmDisplayPipeline> &pipe,
-                                 VSyncWorkerCallbacks &callbacks)
-    -> std::shared_ptr<VSyncWorker> {
-  auto vsw = std::shared_ptr<VSyncWorker>(new VSyncWorker());
-
-  vsw->callbacks_ = callbacks;
+auto VSyncWorker::CreateInstance(std::shared_ptr<DrmDisplayPipeline> &pipe)
+    -> std::unique_ptr<VSyncWorker> {
+  auto vsw = std::unique_ptr<VSyncWorker>(new VSyncWorker());
 
   if (pipe) {
     vsw->high_crtc_ = pipe->crtc->Get()->GetIndexInResArray()
@@ -43,32 +40,78 @@ auto VSyncWorker::CreateInstance(std::shared_ptr<DrmDisplayPipeline> &pipe,
     vsw->drm_fd_ = pipe->device->GetFd();
   }
 
-  std::thread(&VSyncWorker::ThreadFn, vsw.get(), vsw).detach();
+  vsw->vswt_ = std::thread(&VSyncWorker::ThreadFn, vsw.get());
 
   return vsw;
 }
 
-void VSyncWorker::VSyncControl(bool enabled) {
+VSyncWorker::~VSyncWorker() {
+  StopThread();
+
+  vswt_.join();
+}
+
+void VSyncWorker::UpdateVSyncControl() {
   {
     const std::lock_guard<std::mutex> lock(mutex_);
-    enabled_ = enabled;
-    last_timestamp_ = -1;
+    enabled_ = ShouldEnable();
   }
 
   cv_.notify_all();
 }
 
+void VSyncWorker::SetVsyncPeriodNs(uint32_t vsync_period_ns) {
+  const std::lock_guard<std::mutex> lock(mutex_);
+  vsync_period_ns_ = vsync_period_ns;
+  last_timestamp_ = std::nullopt;
+}
+
+void VSyncWorker::SetVsyncTimestampTracking(bool enabled) {
+  {
+    const std::lock_guard<std::mutex> lock(mutex_);
+    enable_vsync_timestamps_ = enabled;
+    if (enabled) {
+      // Reset the freshness flag to ensure that only a fresh timestamp is
+      // returned from GetLastVsyncTimestamp.
+      last_timestamp_is_fresh_ = false;
+    }
+  }
+  UpdateVSyncControl();
+}
+
+uint32_t VSyncWorker::GetLastVsyncTimestamp() {
+  const std::lock_guard<std::mutex> lock(mutex_);
+  return last_timestamp_is_fresh_ ? last_timestamp_.value_or(0) : 0;
+}
+
+int64_t VSyncWorker::GetNextVsyncTimestamp(int64_t time) {
+  const std::lock_guard<std::mutex> lock(mutex_);
+  return GetPhasedVSync(vsync_period_ns_, time);
+}
+
+void VSyncWorker::SetTimestampCallback(
+    std::optional<VsyncTimestampCallback> &&callback) {
+  {
+    const std::lock_guard<std::mutex> lock(mutex_);
+    callback_ = std::move(callback);
+  }
+  UpdateVSyncControl();
+}
+
 void VSyncWorker::StopThread() {
   {
     const std::lock_guard<std::mutex> lock(mutex_);
     thread_exit_ = true;
     enabled_ = false;
-    callbacks_ = {};
   }
 
   cv_.notify_all();
 }
 
+bool VSyncWorker::ShouldEnable() const {
+  return enable_vsync_timestamps_ || callback_.has_value();
+};
+
 /*
  * Returns the timestamp of the next vsync in phase with last_timestamp_.
  * For example:
@@ -83,25 +126,23 @@ void VSyncWorker::StopThread() {
  *  timestamp.
  */
 int64_t VSyncWorker::GetPhasedVSync(int64_t frame_ns, int64_t current) const {
-  if (last_timestamp_ < 0)
+  if (!last_timestamp_.has_value())
     return current + frame_ns;
 
-  return frame_ns * ((current - last_timestamp_) / frame_ns + 1) +
-         last_timestamp_;
+  return (frame_ns * ((current - *last_timestamp_) / frame_ns + 1)) +
+         *last_timestamp_;
 }
 
 static const int64_t kOneSecondNs = 1LL * 1000 * 1000 * 1000;
 
 int VSyncWorker::SyntheticWaitVBlank(int64_t *timestamp) {
-  auto time_now = ResourceManager::GetTimeMonotonicNs();
-
-  // Default to 60Hz refresh rate
-  constexpr uint32_t kDefaultVSPeriodNs = 16666666;
-  auto period_ns = kDefaultVSPeriodNs;
-  if (callbacks_.get_vperiod_ns && callbacks_.get_vperiod_ns() != 0)
-    period_ns = callbacks_.get_vperiod_ns();
+  int64_t phased_timestamp = 0;
+  {
+    std::lock_guard<std::mutex> lock(mutex_);
+    int64_t time_now = ResourceManager::GetTimeMonotonicNs();
+    phased_timestamp = GetPhasedVSync(vsync_period_ns_, time_now);
+  }
 
-  auto phased_timestamp = GetPhasedVSync(period_ns, time_now);
   struct timespec vsync {};
   vsync.tv_sec = int(phased_timestamp / kOneSecondNs);
   vsync.tv_nsec = int(phased_timestamp - (vsync.tv_sec * kOneSecondNs));
@@ -117,20 +158,24 @@ int VSyncWorker::SyntheticWaitVBlank(int64_t *timestamp) {
   return 0;
 }
 
-void VSyncWorker::ThreadFn(const std::shared_ptr<VSyncWorker> &vsw) {
+void VSyncWorker::ThreadFn() {
   int ret = 0;
 
   for (;;) {
     {
-      std::unique_lock<std::mutex> lock(vsw->mutex_);
+      std::unique_lock<std::mutex> lock(mutex_);
+      // Thread safety analysis doesn't understand std::unique_lock.
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wthread-safety-analysis"
       if (thread_exit_)
         break;
 
       if (!enabled_)
-        vsw->cv_.wait(lock);
+        cv_.wait(lock);
 
       if (!enabled_)
         continue;
+#pragma clang diagnostic pop
     }
 
     ret = -EAGAIN;
@@ -158,19 +203,24 @@ void VSyncWorker::ThreadFn(const std::shared_ptr<VSyncWorker> &vsw) {
                   (int64_t)vblank.reply.tval_usec * kUsToNsMul;
     }
 
-    decltype(callbacks_.out_event) callback;
+    std::optional<VsyncTimestampCallback> vsync_callback;
+    int64_t vsync_period_ns = 0;
 
     {
       const std::lock_guard<std::mutex> lock(mutex_);
       if (!enabled_)
         continue;
-      callback = callbacks_.out_event;
+      if (enable_vsync_timestamps_) {
+        last_timestamp_is_fresh_ = true;
+      }
+      vsync_callback = callback_;
+      vsync_period_ns = vsync_period_ns_;
+      last_timestamp_ = timestamp;
     }
 
-    if (callback)
-      callback(timestamp);
-
-    last_timestamp_ = timestamp;
+    if (vsync_callback) {
+      vsync_callback.value()(timestamp, vsync_period_ns);
+    }
   }
 
   ALOGI("VSyncWorker thread exit");
diff --git a/drm/VSyncWorker.h b/drm/VSyncWorker.h
index 2a4c7c8..e8ed24b 100644
--- a/drm/VSyncWorker.h
+++ b/drm/VSyncWorker.h
@@ -23,41 +23,64 @@
 #include <thread>
 
 #include "DrmDevice.h"
+#include "utils/thread_annotations.h"
 
 namespace android {
 
-struct VSyncWorkerCallbacks {
-  std::function<void(uint64_t /*timestamp*/)> out_event;
-  std::function<uint32_t()> get_vperiod_ns;
-};
-
 class VSyncWorker {
  public:
-  ~VSyncWorker() = default;
+  using VsyncTimestampCallback = std::function<void(int64_t /*timestamp*/,
+                                                    uint32_t /*period*/)>;
+
+  ~VSyncWorker();
+
+  auto static CreateInstance(std::shared_ptr<DrmDisplayPipeline> &pipe)
+      -> std::unique_ptr<VSyncWorker>;
 
-  auto static CreateInstance(std::shared_ptr<DrmDisplayPipeline> &pipe,
-                             VSyncWorkerCallbacks &callbacks)
-      -> std::shared_ptr<VSyncWorker>;
+  // Set the expected vsync period. Resets internal timestamp tracking until the
+  // next vsync event is tracked.
+  void SetVsyncPeriodNs(uint32_t vsync_period_ns);
+
+  // Set or clear a callback to be fired on vsync.
+  void SetTimestampCallback(std::optional<VsyncTimestampCallback> &&callback);
+
+  // Enable vsync timestamp tracking. GetLastVsyncTimestamp will return 0 if
+  // vsync tracking is disabled, or if no vsync has happened since it was
+  // enabled.
+  void SetVsyncTimestampTracking(bool enabled);
+  uint32_t GetLastVsyncTimestamp();
+
+  // Get the next predicted vsync timestamp after |time|, based on the last
+  // recorded vsync timestamp and the current vsync period.
+  int64_t GetNextVsyncTimestamp(int64_t time);
 
-  void VSyncControl(bool enabled);
   void StopThread();
 
  private:
   VSyncWorker() = default;
 
-  void ThreadFn(const std::shared_ptr<VSyncWorker> &vsw);
+  void ThreadFn();
 
-  int64_t GetPhasedVSync(int64_t frame_ns, int64_t current) const;
+  int64_t GetPhasedVSync(int64_t frame_ns, int64_t current) const
+      REQUIRES(mutex_);
   int SyntheticWaitVBlank(int64_t *timestamp);
 
-  VSyncWorkerCallbacks callbacks_;
+  void UpdateVSyncControl();
+  bool ShouldEnable() const REQUIRES(mutex_);
 
   SharedFd drm_fd_;
   uint32_t high_crtc_ = 0;
 
-  bool enabled_ = false;
-  bool thread_exit_ = false;
-  int64_t last_timestamp_ = -1;
+  bool enabled_ GUARDED_BY(mutex_) = false;
+  bool thread_exit_ GUARDED_BY(mutex_) = false;
+  std::optional<int64_t> last_timestamp_ GUARDED_BY(mutex_);
+
+  // Default to 60Hz refresh rate
+  static constexpr uint32_t kDefaultVSPeriodNs = 16666666;
+  uint32_t vsync_period_ns_ GUARDED_BY(mutex_) = kDefaultVSPeriodNs;
+  bool enable_vsync_timestamps_ GUARDED_BY(mutex_) = false;
+  bool last_timestamp_is_fresh_ GUARDED_BY(mutex_) = false;
+  std::optional<VsyncTimestampCallback> callback_ GUARDED_BY(mutex_);
 
   std::condition_variable cv_;
   std::thread vswt_;
diff --git a/hooks/check-non-public-commits b/hooks/check-non-public-commits
index fc20795..1e8e997 100755
--- a/hooks/check-non-public-commits
+++ b/hooks/check-non-public-commits
@@ -8,7 +8,8 @@ url="$2"
 
 # Don't bother checking if this is being pushed to gerrit.
 if [[ "$url" = "sso://googleplex-android/platform/external/drm_hwcomposer" ]] ||
-   [[ "$url" = "sso://android.googlesource.com/platform/external/drm_hwcomposer" ]]
+   [[ "$url" = "sso://android.googlesource.com/platform/external/drm_hwcomposer" ]] ||
+   [[ "$url" = "sso://android/platform/external/drm_hwcomposer" ]]
 then
   exit 0
 fi
diff --git a/hwc2_device/HwcDisplay.cpp b/hwc2_device/HwcDisplay.cpp
index 0503f39..2a47a2a 100644
--- a/hwc2_device/HwcDisplay.cpp
+++ b/hwc2_device/HwcDisplay.cpp
@@ -21,10 +21,7 @@
 
 #include <cinttypes>
 
-#include <hardware/gralloc.h>
-#include <ui/GraphicBufferAllocator.h>
-#include <ui/GraphicBufferMapper.h>
-#include <ui/PixelFormat.h>
+#include <ui/ColorSpace.h>
 
 #include "backend/Backend.h"
 #include "backend/BackendManager.h"
@@ -37,78 +34,82 @@
 #include "utils/properties.h"
 
 using ::android::DrmDisplayPipeline;
+using ColorGamut = ::android::ColorSpace;
 
 namespace android {
 
 namespace {
-// Allocate a black buffer that can be used for an initial modeset when there.
-// is no appropriate client buffer available to be used.
-// Caller must free the returned buffer with GraphicBufferAllocator::free.
-auto GetModesetBuffer(uint32_t width, uint32_t height) -> buffer_handle_t {
-  constexpr PixelFormat format = PIXEL_FORMAT_RGBA_8888;
-  constexpr uint64_t usage = GRALLOC_USAGE_SW_READ_OFTEN |
-                             GRALLOC_USAGE_SW_WRITE_OFTEN |
-                             GRALLOC_USAGE_HW_COMPOSER | GRALLOC_USAGE_HW_FB;
-
-  constexpr uint32_t layer_count = 1;
-  const std::string name = "drm-hwcomposer";
-
-  buffer_handle_t handle = nullptr;
-  uint32_t stride = 0;
-  status_t status = GraphicBufferAllocator::get().allocate(width, height,
-                                                           format, layer_count,
-                                                           usage, &handle,
-                                                           &stride, name);
-  if (status != OK) {
-    ALOGE("Failed to allocate modeset buffer.");
-    return nullptr;
-  }
 
-  void *data = nullptr;
-  Rect bounds = {0, 0, static_cast<int32_t>(width),
-                 static_cast<int32_t>(height)};
-  status = GraphicBufferMapper::get().lock(handle, usage, bounds, &data);
-  if (status != OK) {
-    ALOGE("Failed to map modeset buffer.");
-    GraphicBufferAllocator::get().free(handle);
-    return nullptr;
-  }
+constexpr int kCtmRows = 3;
+constexpr int kCtmCols = 3;
+
+constexpr std::array<float, 16> kIdentityMatrix = {
+    1.0F, 0.0F, 0.0F, 0.0F, 0.0F, 1.0F, 0.0F, 0.0F,
+    0.0F, 0.0F, 1.0F, 0.0F, 0.0F, 0.0F, 0.0F, 1.0F,
+};
 
-  // Cast one of the multiplicands to ensure that the multiplication happens
-  // in a wider type (size_t).
-  const size_t buffer_size = static_cast<size_t>(height) * stride *
-                             bytesPerPixel(format);
-  memset(data, 0, buffer_size);
-  status = GraphicBufferMapper::get().unlock(handle);
-  ALOGW_IF(status != OK, "Failed to unmap buffer.");
-  return handle;
+bool float_equals(float a, float b) {
+  const float epsilon = 0.001F;
+  return std::abs(a - b) < epsilon;
 }
 
-auto GetModesetLayerProperties(buffer_handle_t buffer, uint32_t width,
-                               uint32_t height) -> HwcLayer::LayerProperties {
-  HwcLayer::LayerProperties properties;
-  properties.buffer = {.buffer_handle = buffer, .acquire_fence = {}};
-  properties.display_frame = {
-      .left = 0,
-      .top = 0,
-      .right = int(width),
-      .bottom = int(height),
-  };
-  properties.source_crop = (hwc_frect_t){
-      .left = 0.0F,
-      .top = 0.0F,
-      .right = static_cast<float>(width),
-      .bottom = static_cast<float>(height),
-  };
-  properties.blend_mode = BufferBlendMode::kNone;
-  return properties;
+uint64_t To3132FixPt(float in) {
+  constexpr uint64_t kSignMask = (1ULL << 63);
+  constexpr uint64_t kValueMask = ~(1ULL << 63);
+  constexpr auto kValueScale = static_cast<float>(1ULL << 32);
+  if (in < 0)
+    return (static_cast<uint64_t>(-in * kValueScale) & kValueMask) | kSignMask;
+  return static_cast<uint64_t>(in * kValueScale) & kValueMask;
+}
+
+bool TransformHasOffsetValue(const float *matrix) {
+  for (int i = 12; i < 14; i++) {
+    if (!float_equals(matrix[i], 0.F)) {
+      ALOGW("DRM API does not support CTM with offsets.");
+      return true;
+    }
+  }
+  return false;
+}
+
+auto ToColorTransform(const std::array<float, 16> &color_transform_matrix) {
+  /* HAL provides a 4x4 float type matrix:
+   * | 0  1  2  3|
+   * | 4  5  6  7|
+   * | 8  9 10 11|
+   * |12 13 14 15|
+   *
+   * R_out = R*0 + G*4 + B*8 + 12
+   * G_out = R*1 + G*5 + B*9 + 13
+   * B_out = R*2 + G*6 + B*10 + 14
+   *
+   * DRM expects a 3x3 s31.32 fixed point matrix:
+   * out   matrix    in
+   * |R|   |0 1 2|   |R|
+   * |G| = |3 4 5| x |G|
+   * |B|   |6 7 8|   |B|
+   *
+   * R_out = R*0 + G*1 + B*2
+   * G_out = R*3 + G*4 + B*5
+   * B_out = R*6 + G*7 + B*8
+   */
+  auto color_matrix = std::make_shared<drm_color_ctm>();
+  for (int i = 0; i < kCtmCols; i++) {
+    for (int j = 0; j < kCtmRows; j++) {
+      constexpr int kInCtmRows = 4;
+      color_matrix->matrix[(i * kCtmRows) + j] = To3132FixPt(
+          color_transform_matrix[(j * kInCtmRows) + i]);
+    }
+  }
+  return color_matrix;
 }
+
 }  // namespace
 
 std::string HwcDisplay::DumpDelta(HwcDisplay::Stats delta) {
   if (delta.total_pixops_ == 0)
     return "No stats yet";
-  auto ratio = 1.0 - double(delta.gpu_pixops_) / double(delta.total_pixops_);
+  auto ratio = 1.0 - (double(delta.gpu_pixops_) / double(delta.total_pixops_));
 
   std::stringstream ss;
   ss << " Total frames count: " << delta.total_frames_ << "\n"
@@ -148,17 +149,31 @@ HwcDisplay::HwcDisplay(hwc2_display_t handle, HWC2::DisplayType type,
   if (type_ == HWC2::DisplayType::Virtual) {
     writeback_layer_ = std::make_unique<HwcLayer>(this);
   }
+
+  identity_color_matrix_ = ToColorTransform(kIdentityMatrix);
 }
 
-void HwcDisplay::SetColorMatrixToIdentity() {
-  color_matrix_ = std::make_shared<drm_color_ctm>();
-  for (int i = 0; i < kCtmCols; i++) {
-    for (int j = 0; j < kCtmRows; j++) {
-      constexpr uint64_t kOne = (1ULL << 32); /* 1.0 in s31.32 format */
-      color_matrix_->matrix[i * kCtmRows + j] = (i == j) ? kOne : 0;
-    }
+void HwcDisplay::SetColorTransformMatrix(
+    const std::array<float, 16> &color_transform_matrix) {
+  const bool is_identity = std::equal(color_transform_matrix.begin(),
+                                      color_transform_matrix.end(),
+                                      kIdentityMatrix.begin(), float_equals);
+  color_transform_hint_ = is_identity ? HAL_COLOR_TRANSFORM_IDENTITY
+                                      : HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX;
+  ctm_has_offset_ = false;
+
+  if (color_transform_hint_ == is_identity) {
+    SetColorMatrixToIdentity();
+  } else {
+    if (TransformHasOffsetValue(color_transform_matrix.data()))
+      ctm_has_offset_ = true;
+
+    color_matrix_ = ToColorTransform(color_transform_matrix);
   }
+}
 
+void HwcDisplay::SetColorMatrixToIdentity() {
+  color_matrix_ = identity_color_matrix_;
   color_transform_hint_ = HAL_COLOR_TRANSFORM_IDENTITY;
 }
 
@@ -183,6 +198,43 @@ auto HwcDisplay::GetLastRequestedConfig() const -> const HwcDisplayConfig * {
   return GetConfig(staged_mode_config_id_.value_or(configs_.active_config_id));
 }
 
+HWC2::Error HwcDisplay::SetOutputType(uint32_t hdr_output_type) {
+  switch (hdr_output_type) {
+    case 3: { // HDR10
+      auto ret = SetHdrOutputMetadata(ui::Hdr::HDR10);
+      if (ret != HWC2::Error::None)
+        return ret;
+      min_bpc_ = 8;
+      colorspace_ = Colorspace::kBt2020Rgb;
+      break;
+    }
+    case 1: { // SYSTEM
+      std::vector<ui::Hdr> hdr_types;
+      GetEdid()->GetSupportedHdrTypes(hdr_types);
+      if (!hdr_types.empty()) {
+        auto ret = SetHdrOutputMetadata(hdr_types.front());
+        if (ret != HWC2::Error::None)
+          return ret;
+        min_bpc_ = 8;
+        colorspace_ = Colorspace::kBt2020Rgb;
+        break;
+      } else {
+        [[fallthrough]];
+      }
+    }
+    case 0:  // INVALID
+      [[fallthrough]];
+    case 2:  // SDR
+      [[fallthrough]];
+    default:
+      hdr_metadata_ = std::make_shared<hdr_output_metadata>();
+      min_bpc_ = 6;
+      colorspace_ = Colorspace::kDefault;
+  }
+
+  return HWC2::Error::None;
+}
+
 HwcDisplay::ConfigError HwcDisplay::SetConfig(hwc2_config_t config) {
   const HwcDisplayConfig *new_config = GetConfig(config);
   if (new_config == nullptr) {
@@ -205,18 +257,29 @@ HwcDisplay::ConfigError HwcDisplay::SetConfig(hwc2_config_t config) {
     modeset_layer_data = client_layer_.GetLayerData();
   } else {
     ALOGV("Allocate modeset buffer.");
-    buffer_handle_t modeset_buffer = GetModesetBuffer(width, height);
-    if (modeset_buffer != nullptr) {
+    auto modeset_buffer =  //
+        GetPipe().device->CreateBufferForModeset(width, height);
+    if (modeset_buffer) {
       auto modeset_layer = std::make_unique<HwcLayer>(this);
-      modeset_layer->SetLayerProperties(
-          GetModesetLayerProperties(modeset_buffer, width, height));
+      HwcLayer::LayerProperties properties;
+      properties.slot_buffer = {
+          .slot_id = 0,
+          .bi = modeset_buffer,
+      };
+      properties.active_slot = {
+          .slot_id = 0,
+          .fence = {},
+      };
+      properties.blend_mode = BufferBlendMode::kNone;
+      modeset_layer->SetLayerProperties(properties);
       modeset_layer->PopulateLayerData();
       modeset_layer_data = modeset_layer->GetLayerData();
-      GraphicBufferAllocator::get().free(modeset_buffer);
     }
   }
 
   ALOGV("Create modeset commit.");
+  SetOutputType(new_config->output_type);
+
   // Create atomic commit args for a blocking modeset. There's no need to do a
   // separate test commit, since the commit does a test anyways.
   AtomicCommitArgs commit_args = CreateModesetCommit(new_config,
@@ -226,12 +289,14 @@ HwcDisplay::ConfigError HwcDisplay::SetConfig(hwc2_config_t config) {
 
   if (ret) {
     ALOGE("Blocking config failed: %d", ret);
-    return HwcDisplay::ConfigError::kBadConfig;
+    return HwcDisplay::ConfigError::kConfigFailed;
   }
 
   ALOGV("Blocking config succeeded.");
   configs_.active_config_id = config;
   staged_mode_config_id_.reset();
+  vsync_worker_->SetVsyncPeriodNs(new_config->mode.GetVSyncPeriodNs());
+  // set new vsync period
   return ConfigError::kNone;
 }
 
@@ -263,13 +328,117 @@ auto HwcDisplay::QueueConfig(hwc2_config_t config, int64_t desired_time,
   staged_mode_config_id_ = config;
 
   // Enable vsync events until the mode has been applied.
-  last_vsync_ts_ = 0;
-  vsync_tracking_en_ = true;
-  vsync_worker_->VSyncControl(true);
+  vsync_worker_->SetVsyncTimestampTracking(true);
 
   return ConfigError::kNone;
 }
 
+auto HwcDisplay::ValidateStagedComposition() -> std::vector<ChangedLayer> {
+  if (IsInHeadlessMode()) {
+    return {};
+  }
+
+  /* In current drm_hwc design in case previous frame layer was not validated as
+   * a CLIENT, it is used by display controller (Front buffer). We have to store
+   * this state to provide the CLIENT with the release fences for such buffers.
+   */
+  for (auto &l : layers_) {
+    l.second.SetPriorBufferScanOutFlag(l.second.GetValidatedType() !=
+                                       HWC2::Composition::Client);
+  }
+
+  // ValidateDisplay returns the number of layers that may be changed.
+  uint32_t num_types = 0;
+  uint32_t num_requests = 0;
+  backend_->ValidateDisplay(this, &num_types, &num_requests);
+
+  if (num_types == 0) {
+    return {};
+  }
+
+  // Iterate through the layers to find which layers actually changed.
+  std::vector<ChangedLayer> changed_layers;
+  for (auto &l : layers_) {
+    if (l.second.IsTypeChanged()) {
+      changed_layers.emplace_back(l.first, l.second.GetValidatedType());
+    }
+  }
+  return changed_layers;
+}
+
+auto HwcDisplay::GetDisplayBoundsMm() -> std::pair<int32_t, int32_t> {
+
+  const auto bounds = GetEdid()->GetBoundsMm();
+  if (bounds.first > 0 || bounds.second > 0) {
+    return bounds;
+  }
+
+  ALOGE("Failed to get display bounds for d=%d\n", int(handle_));
+  // mm_width and mm_height are unreliable. so only provide mm_width to avoid
+  // wrong dpi computations or other use of the values.
+  return {configs_.mm_width, -1};
+}
+
+auto HwcDisplay::AcceptValidatedComposition() -> void {
+  for (auto &[_, layer] : layers_) {
+    layer.AcceptTypeChange();
+  }
+}
+
+auto HwcDisplay::PresentStagedComposition(
+    std::optional<int64_t> desired_present_time, SharedFd &out_present_fence,
+    std::vector<ReleaseFence> &out_release_fences) -> bool {
+  if (IsInHeadlessMode()) {
+    return true;
+  }
+  HWC2::Error ret{};
+
+  ++total_stats_.total_frames_;
+
+  uint32_t vperiod_ns = 0;
+  GetDisplayVsyncPeriod(&vperiod_ns);
+
+  if (desired_present_time && vperiod_ns != 0) {
+    // DRM atomic uAPI does not support specifying that a commit should be
+    // applied to some future vsync. Until such uAPI is available, sleep in
+    // userspace until the next expected vsync time is consistent with the
+    // desired present time.
+    WaitForPresentTime(desired_present_time.value(), vperiod_ns);
+  }
+
+  AtomicCommitArgs a_args{};
+  ret = CreateComposition(a_args);
+
+  if (ret != HWC2::Error::None)
+    ++total_stats_.failed_kms_present_;
+
+  if (ret == HWC2::Error::BadLayer) {
+    // Can we really have no client or device layers?
+    return true;
+  }
+  if (ret != HWC2::Error::None)
+    return false;
+
+  out_present_fence = a_args.out_fence;
+
+  // Reset the color matrix so we don't apply it over and over again.
+  color_matrix_ = {};
+
+  ++frame_no_;
+
+  if (!out_present_fence) {
+    return true;
+  }
+
+  for (auto &l : layers_) {
+    if (l.second.GetPriorBufferScanOutFlag()) {
+      out_release_fences.emplace_back(l.first, out_present_fence);
+    }
+  }
+
+  return true;
+}
+
 void HwcDisplay::SetPipeline(std::shared_ptr<DrmDisplayPipeline> pipeline) {
   Deinit();
 
@@ -301,43 +470,18 @@ void HwcDisplay::Deinit() {
   }
 
   if (vsync_worker_) {
-    // TODO: There should be a mechanism to wait for this worker to complete,
-    // otherwise there is a race condition while destructing the HwcDisplay.
     vsync_worker_->StopThread();
     vsync_worker_ = {};
   }
 
-  SetClientTarget(nullptr, -1, 0, {});
+  client_layer_.ClearSlots();
 }
 
 HWC2::Error HwcDisplay::Init() {
   ChosePreferredConfig();
 
-  auto vsw_callbacks = (VSyncWorkerCallbacks){
-      .out_event =
-          [this](int64_t timestamp) {
-            const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-            if (vsync_event_en_) {
-              uint32_t period_ns{};
-              GetDisplayVsyncPeriod(&period_ns);
-              hwc_->SendVsyncEventToClient(handle_, timestamp, period_ns);
-            }
-            if (vsync_tracking_en_) {
-              last_vsync_ts_ = timestamp;
-            }
-            if (!vsync_event_en_ && !vsync_tracking_en_) {
-              vsync_worker_->VSyncControl(false);
-            }
-          },
-      .get_vperiod_ns = [this]() -> uint32_t {
-        uint32_t outVsyncPeriod = 0;
-        GetDisplayVsyncPeriod(&outVsyncPeriod);
-        return outVsyncPeriod;
-      },
-  };
-
   if (type_ != HWC2::DisplayType::Virtual) {
-    vsync_worker_ = VSyncWorker::CreateInstance(pipeline_, vsw_callbacks);
+    vsync_worker_ = VSyncWorker::CreateInstance(pipeline_);
     if (!vsync_worker_) {
       ALOGE("Failed to create event worker for d=%d\n", int(handle_));
       return HWC2::Error::BadDisplay;
@@ -355,7 +499,9 @@ HWC2::Error HwcDisplay::Init() {
     flatcon_ = FlatteningController::CreateInstance(flatcbk);
   }
 
-  client_layer_.SetLayerBlendMode(HWC2_BLEND_MODE_PREMULTIPLIED);
+  HwcLayer::LayerProperties lp;
+  lp.blend_mode = BufferBlendMode::kPreMult;
+  client_layer_.SetLayerProperties(lp);
 
   SetColorMatrixToIdentity();
 
@@ -395,26 +541,18 @@ HWC2::Error HwcDisplay::ChosePreferredConfig() {
   return SetActiveConfig(configs_.preferred_config_id);
 }
 
-HWC2::Error HwcDisplay::AcceptDisplayChanges() {
-  for (std::pair<const hwc2_layer_t, HwcLayer> &l : layers_)
-    l.second.AcceptTypeChange();
-  return HWC2::Error::None;
-}
+auto HwcDisplay::CreateLayer(ILayerId new_layer_id) -> bool {
+  if (layers_.count(new_layer_id) > 0)
+    return false;
 
-HWC2::Error HwcDisplay::CreateLayer(hwc2_layer_t *layer) {
-  layers_.emplace(static_cast<hwc2_layer_t>(layer_idx_), HwcLayer(this));
-  *layer = static_cast<hwc2_layer_t>(layer_idx_);
-  ++layer_idx_;
-  return HWC2::Error::None;
-}
+  layers_.emplace(new_layer_id, HwcLayer(this));
 
-HWC2::Error HwcDisplay::DestroyLayer(hwc2_layer_t layer) {
-  if (!get_layer(layer)) {
-    return HWC2::Error::BadLayer;
-  }
+  return true;
+}
 
-  layers_.erase(layer);
-  return HWC2::Error::None;
+auto HwcDisplay::DestroyLayer(ILayerId layer_id) -> bool {
+  auto count = layers_.erase(layer_id);
+  return count != 0;
 }
 
 HWC2::Error HwcDisplay::GetActiveConfig(hwc2_config_t *config) const {
@@ -427,58 +565,31 @@ HWC2::Error HwcDisplay::GetActiveConfig(hwc2_config_t *config) const {
   return HWC2::Error::None;
 }
 
-HWC2::Error HwcDisplay::GetChangedCompositionTypes(uint32_t *num_elements,
-                                                   hwc2_layer_t *layers,
-                                                   int32_t *types) {
+HWC2::Error HwcDisplay::GetColorModes(uint32_t *num_modes, int32_t *modes) {
   if (IsInHeadlessMode()) {
-    *num_elements = 0;
+    *num_modes = 1;
+    if (modes)
+      modes[0] = HAL_COLOR_MODE_NATIVE;
     return HWC2::Error::None;
   }
 
-  uint32_t num_changes = 0;
-  for (auto &l : layers_) {
-    if (l.second.IsTypeChanged()) {
-      if (layers && num_changes < *num_elements)
-        layers[num_changes] = l.first;
-      if (types && num_changes < *num_elements)
-        types[num_changes] = static_cast<int32_t>(l.second.GetValidatedType());
-      ++num_changes;
-    }
+  if (!modes) {
+    std::vector<Colormode> temp_modes;
+    GetEdid()->GetColorModes(temp_modes);
+    *num_modes = temp_modes.size();
+    return HWC2::Error::None;
   }
-  if (!layers && !types)
-    *num_elements = num_changes;
-  return HWC2::Error::None;
-}
 
-HWC2::Error HwcDisplay::GetClientTargetSupport(uint32_t width, uint32_t height,
-                                               int32_t /*format*/,
-                                               int32_t dataspace) {
-  if (IsInHeadlessMode()) {
+  std::vector<Colormode> temp_modes;
+  std::vector<int32_t> out_modes(modes, modes + *num_modes);
+  GetEdid()->GetColorModes(temp_modes);
+  if (temp_modes.empty()) {
+    out_modes.emplace_back(HAL_COLOR_MODE_NATIVE);
     return HWC2::Error::None;
   }
 
-  auto min = pipeline_->device->GetMinResolution();
-  auto max = pipeline_->device->GetMaxResolution();
-
-  if (width < min.first || height < min.second)
-    return HWC2::Error::Unsupported;
-
-  if (width > max.first || height > max.second)
-    return HWC2::Error::Unsupported;
-
-  if (dataspace != HAL_DATASPACE_UNKNOWN)
-    return HWC2::Error::Unsupported;
-
-  // TODO(nobody): Validate format can be handled by either GL or planes
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::GetColorModes(uint32_t *num_modes, int32_t *modes) {
-  if (!modes)
-    *num_modes = 1;
-
-  if (modes)
-    *modes = HAL_COLOR_MODE_NATIVE;
+  for (auto &c : temp_modes)
+    out_modes.emplace_back(static_cast<int32_t>(c));
 
   return HWC2::Error::None;
 }
@@ -510,15 +621,25 @@ HWC2::Error HwcDisplay::GetDisplayAttribute(hwc2_config_t config,
       *value = hwc_config.mode.GetVSyncPeriodNs();
       break;
     case HWC2::Attribute::DpiY:
-      // ideally this should be vdisplay/mm_heigth, however mm_height
-      // comes from edid parsing and is highly unreliable. Viewing the
-      // rarity of anisotropic displays, falling back to a single value
-      // for dpi yield more correct output.
+      *value = GetEdid()->GetDpiY();
+      if (*value < 0) {
+        // default to raw mode DpiX for both x and y when no good value
+        // can be provided from edid.
+        *value = mm_width ? int(hwc_config.mode.GetRawMode().hdisplay *
+                                kUmPerInch / mm_width)
+                          : -1;
+      }
+      break;
     case HWC2::Attribute::DpiX:
       // Dots per 1000 inches
-      *value = mm_width ? int(hwc_config.mode.GetRawMode().hdisplay *
-                              kUmPerInch / mm_width)
-                        : -1;
+      *value = GetEdid()->GetDpiX();
+      if (*value < 0) {
+        // default to raw mode DpiX for both x and y when no good value
+        // can be provided from edid.
+        *value = mm_width ? int(hwc_config.mode.GetRawMode().hdisplay *
+                                kUmPerInch / mm_width)
+                          : -1;
+      }
       break;
 #if __ANDROID_API__ > 29
     case HWC2::Attribute::ConfigGroup:
@@ -574,71 +695,45 @@ HWC2::Error HwcDisplay::GetDisplayName(uint32_t *size, char *name) {
   return HWC2::Error::None;
 }
 
-HWC2::Error HwcDisplay::GetDisplayRequests(int32_t * /*display_requests*/,
-                                           uint32_t *num_elements,
-                                           hwc2_layer_t * /*layers*/,
-                                           int32_t * /*layer_requests*/) {
-  // TODO(nobody): I think virtual display should request
-  //      HWC2_DISPLAY_REQUEST_WRITE_CLIENT_TARGET_TO_OUTPUT here
-  *num_elements = 0;
-  return HWC2::Error::None;
-}
-
 HWC2::Error HwcDisplay::GetDisplayType(int32_t *type) {
   *type = static_cast<int32_t>(type_);
   return HWC2::Error::None;
 }
 
-HWC2::Error HwcDisplay::GetDozeSupport(int32_t *support) {
-  *support = 0;
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::GetHdrCapabilities(uint32_t *num_types,
-                                           int32_t * /*types*/,
-                                           float * /*max_luminance*/,
-                                           float * /*max_average_luminance*/,
-                                           float * /*min_luminance*/) {
-  *num_types = 0;
-  return HWC2::Error::None;
-}
-
-/* Find API details at:
- * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r3:hardware/libhardware/include/hardware/hwcomposer2.h;l=1767
- *
- * Called after PresentDisplay(), CLIENT is expecting release fence for the
- * prior buffer (not the one assigned to the layer at the moment).
- */
-HWC2::Error HwcDisplay::GetReleaseFences(uint32_t *num_elements,
-                                         hwc2_layer_t *layers,
-                                         int32_t *fences) {
+HWC2::Error HwcDisplay::GetHdrCapabilities(uint32_t *num_types, int32_t *types,
+                                           float *max_luminance,
+                                           float *max_average_luminance,
+                                           float *min_luminance) {
   if (IsInHeadlessMode()) {
-    *num_elements = 0;
+    *num_types = 0;
     return HWC2::Error::None;
   }
 
-  uint32_t num_layers = 0;
-
-  for (auto &l : layers_) {
-    if (!l.second.GetPriorBufferScanOutFlag() || !present_fence_) {
-      continue;
-    }
-
-    ++num_layers;
-
-    if (layers == nullptr || fences == nullptr)
-      continue;
+  if (!types) {
+    std::vector<ui::Hdr> temp_types;
+    float lums[3] = {0.F};
+    GetEdid()->GetHdrCapabilities(temp_types, &lums[0], &lums[1], &lums[2]);
+    *num_types = temp_types.size();
+    return HWC2::Error::None;
+  }
 
-    if (num_layers > *num_elements) {
-      ALOGW("Overflow num_elements %d/%d", num_layers, *num_elements);
-      return HWC2::Error::None;
+  std::vector<ui::Hdr> temp_types;
+  std::vector<int32_t> out_types(types, types + *num_types);
+  GetEdid()->GetHdrCapabilities(temp_types, max_luminance,
+                                max_average_luminance, min_luminance);
+  for (auto &t : temp_types) {
+    switch (t) {
+      case ui::Hdr::HDR10:
+        out_types.emplace_back(HAL_HDR_HDR10);
+        break;
+      case ui::Hdr::HLG:
+        out_types.emplace_back(HAL_HDR_HLG);
+        break;
+      default:
+        // Ignore any other HDR types
+        break;
     }
-
-    layers[num_layers - 1] = l.first;
-    fences[num_layers - 1] = DupFd(present_fence_);
   }
-  *num_elements = num_layers;
-
   return HWC2::Error::None;
 }
 
@@ -650,6 +745,8 @@ AtomicCommitArgs HwcDisplay::CreateModesetCommit(
   args.color_matrix = color_matrix_;
   args.content_type = content_type_;
   args.colorspace = colorspace_;
+  args.hdr_metadata = hdr_metadata_;
+  args.min_bpc = min_bpc_;
 
   std::vector<LayerData> composition_layers;
   if (modeset_layer) {
@@ -670,6 +767,40 @@ AtomicCommitArgs HwcDisplay::CreateModesetCommit(
   return args;
 }
 
+void HwcDisplay::WaitForPresentTime(int64_t present_time,
+                                    uint32_t vsync_period_ns) {
+  const int64_t current_time = ResourceManager::GetTimeMonotonicNs();
+  int64_t next_vsync_time = vsync_worker_->GetNextVsyncTimestamp(current_time);
+
+  int64_t vsync_after_present_time = vsync_worker_->GetNextVsyncTimestamp(
+      present_time);
+  int64_t vsync_before_present_time = vsync_after_present_time -
+                                      vsync_period_ns;
+
+  // Check if |present_time| is closer to the expected vsync before or after.
+  int64_t desired_vsync = (vsync_after_present_time - present_time) <
+                                  (present_time - vsync_before_present_time)
+                              ? vsync_after_present_time
+                              : vsync_before_present_time;
+
+  // Don't sleep if desired_vsync is before or nearly equal to vsync_period of
+  // the next expected vsync.
+  const int64_t quarter_vsync_period = vsync_period_ns / 4;
+  if ((desired_vsync - next_vsync_time) < quarter_vsync_period) {
+    return;
+  }
+
+  // Sleep until 75% vsync_period before the desired_vsync.
+  int64_t sleep_until = desired_vsync - (quarter_vsync_period * 3);
+  struct timespec sleep_until_ts{};
+  constexpr int64_t kOneSecondNs = 1LL * 1000 * 1000 * 1000;
+  sleep_until_ts.tv_sec = int(sleep_until / kOneSecondNs);
+  sleep_until_ts.tv_nsec = int(sleep_until -
+                               (sleep_until_ts.tv_sec * kOneSecondNs));
+  clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &sleep_until_ts, nullptr);
+}
+
+// NOLINTNEXTLINE(readability-function-cognitive-complexity)
 HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
   if (IsInHeadlessMode()) {
     ALOGE("%s: Display is in headless mode, should never reach here", __func__);
@@ -679,11 +810,13 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
   a_args.color_matrix = color_matrix_;
   a_args.content_type = content_type_;
   a_args.colorspace = colorspace_;
+  a_args.hdr_metadata = hdr_metadata_;
+  a_args.min_bpc = min_bpc_;
 
   uint32_t prev_vperiod_ns = 0;
   GetDisplayVsyncPeriod(&prev_vperiod_ns);
 
-  auto mode_update_commited_ = false;
+  std::optional<uint32_t> new_vsync_period_ns;
   if (staged_mode_config_id_ &&
       staged_mode_change_time_ <= ResourceManager::GetTimeMonotonicNs()) {
     const HwcDisplayConfig *staged_config = GetConfig(
@@ -691,41 +824,69 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
     if (staged_config == nullptr) {
       return HWC2::Error::BadConfig;
     }
-    client_layer_.SetLayerDisplayFrame(
-        (hwc_rect_t){.left = 0,
-                     .top = 0,
-                     .right = int(staged_config->mode.GetRawMode().hdisplay),
-                     .bottom = int(staged_config->mode.GetRawMode().vdisplay)});
 
     configs_.active_config_id = staged_mode_config_id_.value();
-
     a_args.display_mode = staged_config->mode;
     if (!a_args.test_only) {
-      mode_update_commited_ = true;
+      new_vsync_period_ns = staged_config->mode.GetVSyncPeriodNs();
     }
   }
 
   // order the layers by z-order
+  size_t client_layer_count = 0;
   bool use_client_layer = false;
   uint32_t client_z_order = UINT32_MAX;
   std::map<uint32_t, HwcLayer *> z_map;
-  for (std::pair<const hwc2_layer_t, HwcLayer> &l : layers_) {
-    switch (l.second.GetValidatedType()) {
+  std::optional<LayerData> cursor_layer = std::nullopt;
+  for (auto &[_, layer] : layers_) {
+    switch (layer.GetValidatedType()) {
       case HWC2::Composition::Device:
-        z_map.emplace(l.second.GetZOrder(), &l.second);
+        z_map.emplace(layer.GetZOrder(), &layer);
+        break;
+      case HWC2::Composition::Cursor:
+        if (!cursor_layer.has_value()) {
+          layer.PopulateLayerData();
+          cursor_layer = layer.GetLayerData();
+        } else {
+          ALOGW("Detected multiple cursor layers");
+          z_map.emplace(layer.GetZOrder(), &layer);
+        }
         break;
       case HWC2::Composition::Client:
         // Place it at the z_order of the lowest client layer
         use_client_layer = true;
-        client_z_order = std::min(client_z_order, l.second.GetZOrder());
+        client_layer_count++;
+        client_z_order = std::min(client_z_order, layer.GetZOrder());
         break;
       default:
         continue;
     }
   }
-  if (use_client_layer)
+
+  // CTM will be applied by the client, don't apply DRM CTM
+  if (client_layer_count == layers_.size())
+   a_args.color_matrix = identity_color_matrix_;
+  else
+    a_args.color_matrix = color_matrix_;
+
+  if (use_client_layer) {
     z_map.emplace(client_z_order, &client_layer_);
 
+    client_layer_.PopulateLayerData();
+    if (!client_layer_.IsLayerUsableAsDevice()) {
+      ALOGE_IF(!a_args.test_only,
+               "Client layer must be always usable by DRM/KMS");
+      /* This may be normally triggered on validation of the first frame
+       * containing CLIENT layer. At this moment client buffer is not yet
+       * provided by the CLIENT.
+       * This may be triggered once in HwcLayer lifecycle in case FB can't be
+       * imported. For example when non-contiguous buffer is imported into
+       * contiguous-only DRM/KMS driver.
+       */
+      return HWC2::Error::BadLayer;
+    }
+  }
+
   if (z_map.empty())
     return HWC2::Error::BadLayer;
 
@@ -739,13 +900,6 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
   // now that they're ordered by z, add them to the composition
   for (std::pair<const uint32_t, HwcLayer *> &l : z_map) {
     if (!l.second->IsLayerUsableAsDevice()) {
-      /* This will be normally triggered on validation of the first frame
-       * containing CLIENT layer. At this moment client buffer is not yet
-       * provided by the CLIENT.
-       * This may be triggered once in HwcLayer lifecycle in case FB can't be
-       * imported. For example when non-contiguous buffer is imported into
-       * contiguous-only DRM/KMS driver.
-       */
       return HWC2::Error::BadLayer;
     }
     composition_layers.emplace_back(l.second->GetLayerData());
@@ -755,9 +909,15 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
    * in between of ValidateDisplay() and PresentDisplay() calls
    */
   current_plan_ = DrmKmsPlan::CreateDrmKmsPlan(GetPipe(),
-                                               std::move(composition_layers));
+                                               std::move(composition_layers),
+                                               cursor_layer);
 
   if (type_ == HWC2::DisplayType::Virtual) {
+    writeback_layer_->PopulateLayerData();
+    if (!writeback_layer_->IsLayerUsableAsDevice()) {
+      ALOGE("Output layer must be always usable by DRM/KMS");
+      return HWC2::Error::BadLayer;
+    }
     a_args.writeback_fb = writeback_layer_->GetLayerData().fb;
     a_args.writeback_release_fence = writeback_layer_->GetLayerData()
                                          .acquire_fence;
@@ -777,56 +937,22 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
     return HWC2::Error::BadParameter;
   }
 
-  if (mode_update_commited_) {
+  if (new_vsync_period_ns) {
     staged_mode_config_id_.reset();
-    vsync_tracking_en_ = false;
-    if (last_vsync_ts_ != 0) {
+
+    vsync_worker_->SetVsyncTimestampTracking(false);
+    uint32_t last_vsync_ts = vsync_worker_->GetLastVsyncTimestamp();
+    if (last_vsync_ts != 0) {
       hwc_->SendVsyncPeriodTimingChangedEventToClient(handle_,
-                                                      last_vsync_ts_ +
+                                                      last_vsync_ts +
                                                           prev_vperiod_ns);
     }
+    vsync_worker_->SetVsyncPeriodNs(new_vsync_period_ns.value());
   }
 
   return HWC2::Error::None;
 }
 
-/* Find API details at:
- * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r3:hardware/libhardware/include/hardware/hwcomposer2.h;l=1805
- */
-HWC2::Error HwcDisplay::PresentDisplay(int32_t *out_present_fence) {
-  if (IsInHeadlessMode()) {
-    *out_present_fence = -1;
-    return HWC2::Error::None;
-  }
-  HWC2::Error ret{};
-
-  ++total_stats_.total_frames_;
-
-  AtomicCommitArgs a_args{};
-  ret = CreateComposition(a_args);
-
-  if (ret != HWC2::Error::None)
-    ++total_stats_.failed_kms_present_;
-
-  if (ret == HWC2::Error::BadLayer) {
-    // Can we really have no client or device layers?
-    *out_present_fence = -1;
-    return HWC2::Error::None;
-  }
-  if (ret != HWC2::Error::None)
-    return ret;
-
-  this->present_fence_ = a_args.out_fence;
-  *out_present_fence = DupFd(a_args.out_fence);
-
-  // Reset the color matrix so we don't apply it over and over again.
-  color_matrix_ = {};
-
-  ++frame_no_;
-
-  return HWC2::Error::None;
-}
-
 HWC2::Error HwcDisplay::SetActiveConfigInternal(uint32_t config,
                                                 int64_t change_time) {
   if (configs_.hwc_configs.count(config) == 0) {
@@ -836,6 +962,8 @@ HWC2::Error HwcDisplay::SetActiveConfigInternal(uint32_t config,
 
   staged_mode_change_time_ = change_time;
   staged_mode_config_id_ = config;
+  if (const HwcDisplayConfig *new_config = GetConfig(config))
+    SetOutputType(new_config->output_type);
 
   return HWC2::Error::None;
 }
@@ -844,56 +972,11 @@ HWC2::Error HwcDisplay::SetActiveConfig(hwc2_config_t config) {
   return SetActiveConfigInternal(config, ResourceManager::GetTimeMonotonicNs());
 }
 
-/* Find API details at:
- * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r3:hardware/libhardware/include/hardware/hwcomposer2.h;l=1861
- */
-HWC2::Error HwcDisplay::SetClientTarget(buffer_handle_t target,
-                                        int32_t acquire_fence,
-                                        int32_t dataspace,
-                                        hwc_region_t /*damage*/) {
-  client_layer_.SetLayerBuffer(target, acquire_fence);
-  client_layer_.SetLayerDataspace(dataspace);
-
-  /*
-   * target can be nullptr, this does mean the Composer Service is calling
-   * cleanDisplayResources() on after receiving HOTPLUG event. See more at:
-   * https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/graphics/composer/2.1/utils/hal/include/composer-hal/2.1/ComposerClient.h;l=350;drc=944b68180b008456ed2eb4d4d329e33b19bd5166
-   */
-  if (target == nullptr) {
-    client_layer_.SwChainClearCache();
-    return HWC2::Error::None;
-  }
-
-  if (IsInHeadlessMode()) {
-    return HWC2::Error::None;
-  }
-
-  client_layer_.PopulateLayerData();
-  if (!client_layer_.IsLayerUsableAsDevice()) {
-    ALOGE("Client layer must be always usable by DRM/KMS");
-    return HWC2::Error::BadLayer;
-  }
-
-  auto &bi = client_layer_.GetLayerData().bi;
-  if (!bi) {
-    ALOGE("%s: Invalid state", __func__);
-    return HWC2::Error::BadLayer;
-  }
-
-  auto source_crop = (hwc_frect_t){.left = 0.0F,
-                                   .top = 0.0F,
-                                   .right = static_cast<float>(bi->width),
-                                   .bottom = static_cast<float>(bi->height)};
-  client_layer_.SetLayerSourceCrop(source_crop);
-
-  return HWC2::Error::None;
-}
-
 HWC2::Error HwcDisplay::SetColorMode(int32_t mode) {
   /* Maps to the Colorspace DRM connector property:
    * https://elixir.bootlin.com/linux/v6.11/source/include/drm/drm_connector.h#L538
    */
-  if (mode < HAL_COLOR_MODE_NATIVE || mode > HAL_COLOR_MODE_DISPLAY_P3)
+  if (mode < HAL_COLOR_MODE_NATIVE || mode > HAL_COLOR_MODE_DISPLAY_BT2020)
     return HWC2::Error::BadParameter;
 
   switch (mode) {
@@ -915,7 +998,11 @@ HWC2::Error HwcDisplay::SetColorMode(int32_t mode) {
     case HAL_COLOR_MODE_DISPLAY_P3:
       colorspace_ = Colorspace::kDciP3RgbD65;
       break;
+    case HAL_COLOR_MODE_DISPLAY_BT2020:
     case HAL_COLOR_MODE_ADOBE_RGB:
+    case HAL_COLOR_MODE_BT2020:
+    case HAL_COLOR_MODE_BT2100_PQ:
+    case HAL_COLOR_MODE_BT2100_HLG:
     default:
       return HWC2::Error::Unsupported;
   }
@@ -924,17 +1011,6 @@ HWC2::Error HwcDisplay::SetColorMode(int32_t mode) {
   return HWC2::Error::None;
 }
 
-#include <xf86drmMode.h>
-
-static uint64_t To3132FixPt(float in) {
-  constexpr uint64_t kSignMask = (1ULL << 63);
-  constexpr uint64_t kValueMask = ~(1ULL << 63);
-  constexpr auto kValueScale = static_cast<float>(1ULL << 32);
-  if (in < 0)
-    return (static_cast<uint64_t>(-in * kValueScale) & kValueMask) | kSignMask;
-  return static_cast<uint64_t>(in * kValueScale) & kValueMask;
-}
-
 HWC2::Error HwcDisplay::SetColorTransform(const float *matrix, int32_t hint) {
   if (hint < HAL_COLOR_TRANSFORM_IDENTITY ||
       hint > HAL_COLOR_TRANSFORM_CORRECT_TRITANOPIA)
@@ -944,6 +1020,7 @@ HWC2::Error HwcDisplay::SetColorTransform(const float *matrix, int32_t hint) {
     return HWC2::Error::BadParameter;
 
   color_transform_hint_ = static_cast<android_color_transform_t>(hint);
+  ctm_has_offset_ = false;
 
   if (IsInHeadlessMode())
     return HWC2::Error::None;
@@ -957,37 +1034,13 @@ HWC2::Error HwcDisplay::SetColorTransform(const float *matrix, int32_t hint) {
       break;
     case HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX:
       // Without HW support, we cannot correctly process matrices with an offset.
-      for (int i = 12; i < 14; i++) {
-        if (matrix[i] != 0.F)
-          return HWC2::Error::Unsupported;
-      }
+      {
+        if (TransformHasOffsetValue(matrix))
+          ctm_has_offset_ = true;
 
-      /* HAL provides a 4x4 float type matrix:
-       * | 0  1  2  3|
-       * | 4  5  6  7|
-       * | 8  9 10 11|
-       * |12 13 14 15|
-       *
-       * R_out = R*0 + G*4 + B*8 + 12
-       * G_out = R*1 + G*5 + B*9 + 13
-       * B_out = R*2 + G*6 + B*10 + 14
-       *
-       * DRM expects a 3x3 s31.32 fixed point matrix:
-       * out   matrix    in
-       * |R|   |0 1 2|   |R|
-       * |G| = |3 4 5| x |G|
-       * |B|   |6 7 8|   |B|
-       *
-       * R_out = R*0 + G*1 + B*2
-       * G_out = R*3 + G*4 + B*5
-       * B_out = R*6 + G*7 + B*8
-       */
-      color_matrix_ = std::make_shared<drm_color_ctm>();
-      for (int i = 0; i < kCtmCols; i++) {
-        for (int j = 0; j < kCtmRows; j++) {
-          constexpr int kInCtmRows = 4;
-          color_matrix_->matrix[i * kCtmRows + j] = To3132FixPt(matrix[j * kInCtmRows + i]);
-        }
+        std::array<float, 16> aidl_matrix = kIdentityMatrix;
+        memcpy(aidl_matrix.data(), matrix, aidl_matrix.size() * sizeof(float));
+        color_matrix_ = ToColorTransform(aidl_matrix);
       }
       break;
     default:
@@ -1001,7 +1054,7 @@ bool HwcDisplay::CtmByGpu() {
   if (color_transform_hint_ == HAL_COLOR_TRANSFORM_IDENTITY)
     return false;
 
-  if (GetPipe().crtc->Get()->GetCtmProperty())
+  if (GetPipe().crtc->Get()->GetCtmProperty() && !ctm_has_offset_)
     return false;
 
   if (GetHwc()->GetResMan().GetCtmHandling() == CtmHandling::kDrmOrIgnore)
@@ -1010,18 +1063,6 @@ bool HwcDisplay::CtmByGpu() {
   return true;
 }
 
-HWC2::Error HwcDisplay::SetOutputBuffer(buffer_handle_t buffer,
-                                        int32_t release_fence) {
-  writeback_layer_->SetLayerBuffer(buffer, release_fence);
-  writeback_layer_->PopulateLayerData();
-  if (!writeback_layer_->IsLayerUsableAsDevice()) {
-    ALOGE("Output layer must be always usable by DRM/KMS");
-    return HWC2::Error::BadLayer;
-  }
-  /* TODO: Check if format is supported by writeback connector */
-  return HWC2::Error::None;
-}
-
 HWC2::Error HwcDisplay::SetPowerMode(int32_t mode_in) {
   auto mode = static_cast<HWC2::PowerMode>(mode_in);
 
@@ -1070,33 +1111,24 @@ HWC2::Error HwcDisplay::SetVsyncEnabled(int32_t enabled) {
   if (type_ == HWC2::DisplayType::Virtual) {
     return HWC2::Error::None;
   }
+  if (!vsync_worker_) {
+    return HWC2::Error::NoResources;
+  }
 
   vsync_event_en_ = HWC2_VSYNC_ENABLE == enabled;
+  std::optional<VSyncWorker::VsyncTimestampCallback> callback = std::nullopt;
   if (vsync_event_en_) {
-    vsync_worker_->VSyncControl(true);
-  }
+    DrmHwc *hwc = hwc_;
+    hwc2_display_t id = handle_;
+    // Callback will be called from the vsync thread.
+    callback = [hwc, id](int64_t timestamp, uint32_t period_ns) {
+      hwc->SendVsyncEventToClient(id, timestamp, period_ns);
+    };
+  }
+  vsync_worker_->SetTimestampCallback(std::move(callback));
   return HWC2::Error::None;
 }
 
-HWC2::Error HwcDisplay::ValidateDisplay(uint32_t *num_types,
-                                        uint32_t *num_requests) {
-  if (IsInHeadlessMode()) {
-    *num_types = *num_requests = 0;
-    return HWC2::Error::None;
-  }
-
-  /* In current drm_hwc design in case previous frame layer was not validated as
-   * a CLIENT, it is used by display controller (Front buffer). We have to store
-   * this state to provide the CLIENT with the release fences for such buffers.
-   */
-  for (auto &l : layers_) {
-    l.second.SetPriorBufferScanOutFlag(l.second.GetValidatedType() !=
-                                       HWC2::Composition::Client);
-  }
-
-  return backend_->ValidateDisplay(this, num_types, num_requests);
-}
-
 std::vector<HwcLayer *> HwcDisplay::GetOrderLayersByZPos() {
   std::vector<HwcLayer *> ordered_layers;
   ordered_layers.reserve(layers_.size());
@@ -1107,6 +1139,12 @@ std::vector<HwcLayer *> HwcDisplay::GetOrderLayersByZPos() {
 
   std::sort(std::begin(ordered_layers), std::end(ordered_layers),
             [](const HwcLayer *lhs, const HwcLayer *rhs) {
+              // Cursor layers should always have highest zpos.
+              if ((lhs->GetSfType() == HWC2::Composition::Cursor) !=
+                  (rhs->GetSfType() == HWC2::Composition::Cursor)) {
+                return rhs->GetSfType() == HWC2::Composition::Cursor;
+              }
+
               return lhs->GetZOrder() < rhs->GetZOrder();
             });
 
@@ -1120,6 +1158,61 @@ HWC2::Error HwcDisplay::GetDisplayVsyncPeriod(
                              (int32_t *)(outVsyncPeriod));
 }
 
+// Display primary values are coded as unsigned 16-bit values in units of
+// 0.00002, where 0x0000 represents zero and 0xC350 represents 1.0000.
+static uint64_t ToU16ColorValue(float in) {
+  constexpr float kPrimariesFixedPoint = 50000.F;
+  return static_cast<uint64_t>(kPrimariesFixedPoint * in);
+}
+
+HWC2::Error HwcDisplay::SetHdrOutputMetadata(ui::Hdr type) {
+  hdr_metadata_ = std::make_shared<hdr_output_metadata>();
+  hdr_metadata_->metadata_type = 0;
+  auto *m = &hdr_metadata_->hdmi_metadata_type1;
+  m->metadata_type = 0;
+
+  switch (type) {
+    case ui::Hdr::HDR10:
+      m->eotf = 2;  // PQ
+      break;
+    case ui::Hdr::HLG:
+      m->eotf = 3;  // HLG
+      break;
+    default:
+      return HWC2::Error::Unsupported;
+  }
+
+  // Most luminance values are coded as an unsigned 16-bit value in units of 1
+  // cd/m2, where 0x0001 represents 1 cd/m2 and 0xFFFF represents 65535 cd/m2.
+  std::vector<ui::Hdr> types;
+  float hdr_luminance[3]{0.F, 0.F, 0.F};
+  GetEdid()->GetHdrCapabilities(types, &hdr_luminance[0], &hdr_luminance[1],
+                                &hdr_luminance[2]);
+  m->max_display_mastering_luminance = m->max_cll = static_cast<uint64_t>(
+      hdr_luminance[0]);
+  m->max_fall = static_cast<uint64_t>(hdr_luminance[1]);
+  // The min luminance value is coded as an unsigned 16-bit value in units of
+  // 0.0001 cd/m2, where 0x0001 represents 0.0001 cd/m2 and 0xFFFF
+  // represents 6.5535 cd/m2.
+  m->min_display_mastering_luminance = static_cast<uint64_t>(hdr_luminance[2] *
+                                                             10000.F);
+
+  auto gamut = ColorGamut::BT2020();
+  auto primaries = gamut.getPrimaries();
+  m->display_primaries[0].x = ToU16ColorValue(primaries[0].x);
+  m->display_primaries[0].y = ToU16ColorValue(primaries[0].y);
+  m->display_primaries[1].x = ToU16ColorValue(primaries[1].x);
+  m->display_primaries[1].y = ToU16ColorValue(primaries[1].y);
+  m->display_primaries[2].x = ToU16ColorValue(primaries[2].x);
+  m->display_primaries[2].y = ToU16ColorValue(primaries[2].y);
+
+  auto whitePoint = gamut.getWhitePoint();
+  m->white_point.x = ToU16ColorValue(whitePoint.x);
+  m->white_point.y = ToU16ColorValue(whitePoint.y);
+
+  return HWC2::Error::None;
+}
+
 #if __ANDROID_API__ > 29
 HWC2::Error HwcDisplay::GetDisplayConnectionType(uint32_t *outType) {
   if (IsInHeadlessMode()) {
@@ -1170,22 +1263,7 @@ HWC2::Error HwcDisplay::SetActiveConfigWithConstraints(
   outTimeline->newVsyncAppliedTimeNanos = vsyncPeriodChangeConstraints
                                               ->desiredTimeNanos;
 
-  last_vsync_ts_ = 0;
-  vsync_tracking_en_ = true;
-  vsync_worker_->VSyncControl(true);
-
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::SetAutoLowLatencyMode(bool /*on*/) {
-  return HWC2::Error::Unsupported;
-}
-
-HWC2::Error HwcDisplay::GetSupportedContentTypes(
-    uint32_t *outNumSupportedContentTypes,
-    const uint32_t *outSupportedContentTypes) {
-  if (outSupportedContentTypes == nullptr)
-    *outNumSupportedContentTypes = 0;
+  vsync_worker_->SetVsyncTimestampTracking(true);
 
   return HWC2::Error::None;
 }
@@ -1211,12 +1289,21 @@ HWC2::Error HwcDisplay::GetDisplayIdentificationData(uint8_t *outPort,
     return HWC2::Error::Unsupported;
   }
 
-  auto blob = GetPipe().connector->Get()->GetEdidBlob();
+  auto *connector = GetPipe().connector->Get();
+  auto blob = connector->GetEdidBlob();
   if (!blob) {
     return HWC2::Error::Unsupported;
   }
 
-  *outPort = handle_; /* TDOD(nobody): What should be here? */
+  constexpr uint8_t kDrmDeviceBitShift = 5U;
+  constexpr uint8_t kDrmDeviceBitMask = 0xE0;
+  constexpr uint8_t kConnectorBitMask = 0x1F;
+  const auto kDrmIdx = static_cast<uint8_t>(
+      connector->GetDev().GetIndexInDevArray());
+  const auto kConnectorIdx = static_cast<uint8_t>(
+      connector->GetIndexInResArray());
+  *outPort = (((kDrmIdx << kDrmDeviceBitShift) & kDrmDeviceBitMask) |
+              (kConnectorIdx & kConnectorBitMask));
 
   if (outData) {
     *outDataSize = std::min(*outDataSize, blob->length);
@@ -1240,11 +1327,6 @@ HWC2::Error HwcDisplay::GetDisplayCapabilities(uint32_t *outNumCapabilities,
   if (GetHwc()->GetResMan().GetCtmHandling() == CtmHandling::kDrmOrIgnore)
     skip_ctm = true;
 
-  // Skip client CTM if DRM can handle it
-  if (!skip_ctm && !IsInHeadlessMode() &&
-      GetPipe().crtc->Get()->GetCtmProperty())
-    skip_ctm = true;
-
   if (!skip_ctm) {
     *outNumCapabilities = 0;
     return HWC2::Error::None;
@@ -1258,15 +1340,6 @@ HWC2::Error HwcDisplay::GetDisplayCapabilities(uint32_t *outNumCapabilities,
   return HWC2::Error::None;
 }
 
-HWC2::Error HwcDisplay::GetDisplayBrightnessSupport(bool *supported) {
-  *supported = false;
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::SetDisplayBrightness(float /* brightness */) {
-  return HWC2::Error::Unsupported;
-}
-
 #endif /* __ANDROID_API__ > 28 */
 
 #if __ANDROID_API__ > 27
@@ -1311,4 +1384,12 @@ void HwcDisplay::set_backend(std::unique_ptr<Backend> backend) {
   backend_ = std::move(backend);
 }
 
+bool HwcDisplay::NeedsClientLayerUpdate() const {
+  return std::any_of(layers_.begin(), layers_.end(), [](const auto &pair) {
+    const auto &layer = pair.second;
+    return layer.GetSfType() == HWC2::Composition::Client ||
+           layer.GetValidatedType() == HWC2::Composition::Client;
+  });
+}
+
 }  // namespace android
diff --git a/hwc2_device/HwcDisplay.h b/hwc2_device/HwcDisplay.h
index ecca514..d493597 100644
--- a/hwc2_device/HwcDisplay.h
+++ b/hwc2_device/HwcDisplay.h
@@ -22,6 +22,8 @@
 #include <optional>
 #include <sstream>
 
+#include <ui/GraphicTypes.h>
+
 #include "HwcDisplayConfigs.h"
 #include "compositor/DisplayInfo.h"
 #include "compositor/FlatteningController.h"
@@ -36,6 +38,11 @@ namespace android {
 class Backend;
 class DrmHwc;
 
+class FrontendDisplayBase {
+ public:
+  virtual ~FrontendDisplayBase() = default;
+};
+
 inline constexpr uint32_t kPrimaryDisplay = 0;
 
 // NOLINTNEXTLINE
@@ -45,13 +52,17 @@ class HwcDisplay {
     kNone,
     kBadConfig,
     kSeamlessNotAllowed,
-    kSeamlessNotPossible
+    kSeamlessNotPossible,
+    kConfigFailed,
   };
 
   HwcDisplay(hwc2_display_t handle, HWC2::DisplayType type, DrmHwc *hwc);
   HwcDisplay(const HwcDisplay &) = delete;
   ~HwcDisplay();
 
+  void SetColorTransformMatrix(
+      const std::array<float, 16> &color_transform_matrix);
+
   /* SetPipeline should be carefully used only by DrmHwcTwo hotplug handlers */
   void SetPipeline(std::shared_ptr<DrmDisplayPipeline> pipeline);
 
@@ -86,24 +97,47 @@ class HwcDisplay {
   // Get the HwcDisplayConfig, or nullptor if none.
   auto GetConfig(hwc2_config_t config_id) const -> const HwcDisplayConfig *;
 
+  auto GetDisplayBoundsMm() -> std::pair<int32_t, int32_t>;
+
+  // To be called after SetDisplayProperties. Returns an empty vector if the
+  // requested layers have been validated, otherwise the vector describes
+  // the requested composition type changes.
+  using ChangedLayer = std::pair<ILayerId, HWC2::Composition>;
+  auto ValidateStagedComposition() -> std::vector<ChangedLayer>;
+
+  // Mark previously validated properties as ready to present.
+  auto AcceptValidatedComposition() -> void;
+
+  using ReleaseFence = std::pair<ILayerId, SharedFd>;
+  // Present previously staged properties, and return fences to indicate when
+  // the new content has been presented, and when the previous buffers have
+  // been released. If |desired_present_time| is set, ensure that the
+  // composition is presented at the closest vsync to that requested time.
+  // Otherwise, present immediately.
+  auto PresentStagedComposition(std::optional<int64_t> desired_present_time,
+                                SharedFd &out_present_fence,
+                                std::vector<ReleaseFence> &out_release_fences)
+      -> bool;
+
+  auto GetFrontendPrivateData() -> std::shared_ptr<FrontendDisplayBase> {
+    return frontend_private_data_;
+  }
+
+  auto SetFrontendPrivateData(std::shared_ptr<FrontendDisplayBase> data) {
+    frontend_private_data_ = std::move(data);
+  }
+
+  auto CreateLayer(ILayerId new_layer_id) -> bool;
+  auto DestroyLayer(ILayerId layer_id) -> bool;
+
   // HWC2 Hooks - these should not be used outside of the hwc2 device.
-  HWC2::Error AcceptDisplayChanges();
-  HWC2::Error CreateLayer(hwc2_layer_t *layer);
-  HWC2::Error DestroyLayer(hwc2_layer_t layer);
   HWC2::Error GetActiveConfig(hwc2_config_t *config) const;
-  HWC2::Error GetChangedCompositionTypes(uint32_t *num_elements,
-                                         hwc2_layer_t *layers, int32_t *types);
-  HWC2::Error GetClientTargetSupport(uint32_t width, uint32_t height,
-                                     int32_t format, int32_t dataspace);
   HWC2::Error GetColorModes(uint32_t *num_modes, int32_t *modes);
   HWC2::Error GetDisplayAttribute(hwc2_config_t config, int32_t attribute,
                                   int32_t *value);
   HWC2::Error LegacyGetDisplayConfigs(uint32_t *num_configs,
                                       hwc2_config_t *configs);
   HWC2::Error GetDisplayName(uint32_t *size, char *name);
-  HWC2::Error GetDisplayRequests(int32_t *display_requests,
-                                 uint32_t *num_elements, hwc2_layer_t *layers,
-                                 int32_t *layer_requests);
   HWC2::Error GetDisplayType(int32_t *type);
 #if __ANDROID_API__ > 27
   HWC2::Error GetRenderIntents(int32_t mode, uint32_t *outNumIntents,
@@ -116,8 +150,6 @@ class HwcDisplay {
                                            uint8_t *outData);
   HWC2::Error GetDisplayCapabilities(uint32_t *outNumCapabilities,
                                      uint32_t *outCapabilities);
-  HWC2::Error GetDisplayBrightnessSupport(bool *supported);
-  HWC2::Error SetDisplayBrightness(float);
 #endif
 #if __ANDROID_API__ > 29
   HWC2::Error GetDisplayConnectionType(uint32_t *outType);
@@ -126,34 +158,22 @@ class HwcDisplay {
       hwc2_config_t config,
       hwc_vsync_period_change_constraints_t *vsyncPeriodChangeConstraints,
       hwc_vsync_period_change_timeline_t *outTimeline);
-  HWC2::Error SetAutoLowLatencyMode(bool on);
-  HWC2::Error GetSupportedContentTypes(
-      uint32_t *outNumSupportedContentTypes,
-      const uint32_t *outSupportedContentTypes);
 
   HWC2::Error SetContentType(int32_t contentType);
 #endif
   HWC2::Error GetDisplayVsyncPeriod(uint32_t *outVsyncPeriod);
 
-  HWC2::Error GetDozeSupport(int32_t *support);
   HWC2::Error GetHdrCapabilities(uint32_t *num_types, int32_t *types,
                                  float *max_luminance,
                                  float *max_average_luminance,
                                  float *min_luminance);
-  HWC2::Error GetReleaseFences(uint32_t *num_elements, hwc2_layer_t *layers,
-                               int32_t *fences);
-  HWC2::Error PresentDisplay(int32_t *out_present_fence);
   HWC2::Error SetActiveConfig(hwc2_config_t config);
   HWC2::Error ChosePreferredConfig();
-  HWC2::Error SetClientTarget(buffer_handle_t target, int32_t acquire_fence,
-                              int32_t dataspace, hwc_region_t damage);
   HWC2::Error SetColorMode(int32_t mode);
   HWC2::Error SetColorTransform(const float *matrix, int32_t hint);
-  HWC2::Error SetOutputBuffer(buffer_handle_t buffer, int32_t release_fence);
   HWC2::Error SetPowerMode(int32_t mode);
   HWC2::Error SetVsyncEnabled(int32_t enabled);
-  HWC2::Error ValidateDisplay(uint32_t *num_types, uint32_t *num_requests);
-  HwcLayer *get_layer(hwc2_layer_t layer) {
+  HwcLayer *get_layer(ILayerId layer) {
     auto it = layers_.find(layer);
     if (it == layers_.end())
       return nullptr;
@@ -186,7 +206,7 @@ class HwcDisplay {
     return hwc_;
   }
 
-  std::map<hwc2_layer_t, HwcLayer> &layers() {
+  auto layers() -> std::map<ILayerId, HwcLayer> & {
     return layers_;
   }
 
@@ -216,6 +236,10 @@ class HwcDisplay {
     return flatcon_;
   }
 
+  auto GetClientLayer() -> HwcLayer & {
+    return client_layer_;
+  }
+
   auto &GetWritebackLayer() {
     return writeback_layer_;
   }
@@ -227,17 +251,21 @@ class HwcDisplay {
 
   auto getDisplayPhysicalOrientation() -> std::optional<PanelOrientation>;
 
+  bool NeedsClientLayerUpdate() const;
+
  private:
   AtomicCommitArgs CreateModesetCommit(
       const HwcDisplayConfig *config,
       const std::optional<LayerData> &modeset_layer);
 
+  // Sleep the current thread until |present_time| is closest to the next
+  // expected vsync time.
+  void WaitForPresentTime(int64_t present_time, uint32_t vsync_period_ns);
+
   HwcDisplayConfigs configs_;
 
   DrmHwc *const hwc_;
 
-  SharedFd present_fence_;
-
   int64_t staged_mode_change_time_{};
   std::optional<uint32_t> staged_mode_config_id_{};
 
@@ -246,28 +274,26 @@ class HwcDisplay {
   std::unique_ptr<Backend> backend_;
   std::shared_ptr<FlatteningController> flatcon_;
 
-  std::shared_ptr<VSyncWorker> vsync_worker_;
+  std::unique_ptr<VSyncWorker> vsync_worker_;
   bool vsync_event_en_{};
-  bool vsync_tracking_en_{};
-  int64_t last_vsync_ts_{};
 
   const hwc2_display_t handle_;
   HWC2::DisplayType type_;
 
-  uint32_t layer_idx_{};
-
-  std::map<hwc2_layer_t, HwcLayer> layers_;
+  std::map<ILayerId, HwcLayer> layers_;
   HwcLayer client_layer_;
   std::unique_ptr<HwcLayer> writeback_layer_;
   uint16_t virtual_disp_width_{};
   uint16_t virtual_disp_height_{};
   int32_t color_mode_{};
-  static constexpr int kCtmRows = 3;
-  static constexpr int kCtmCols = 3;
   std::shared_ptr<drm_color_ctm> color_matrix_;
+  std::shared_ptr<drm_color_ctm> identity_color_matrix_;
   android_color_transform_t color_transform_hint_{};
+  bool ctm_has_offset_ = false;
   int32_t content_type_{};
   Colorspace colorspace_{};
+  int32_t min_bpc_{};
+  std::shared_ptr<hdr_output_metadata> hdr_metadata_;
 
   std::shared_ptr<DrmKmsPlan> current_plan_;
 
@@ -281,6 +307,14 @@ class HwcDisplay {
   HWC2::Error Init();
 
   HWC2::Error SetActiveConfigInternal(uint32_t config, int64_t change_time);
+  HWC2::Error SetHdrOutputMetadata(ui::Hdr hdrType);
+  HWC2::Error SetOutputType(uint32_t hdr_output_type);
+
+  auto GetEdid() -> EdidWrapperUnique & {
+    return GetPipe().connector->Get()->GetParsedEdid();
+  }
+
+  std::shared_ptr<FrontendDisplayBase> frontend_private_data_;
 };
 
 }  // namespace android
diff --git a/hwc2_device/HwcDisplayConfigs.cpp b/hwc2_device/HwcDisplayConfigs.cpp
index fa1d2a9..ca70c14 100644
--- a/hwc2_device/HwcDisplayConfigs.cpp
+++ b/hwc2_device/HwcDisplayConfigs.cpp
@@ -147,6 +147,7 @@ HWC2::Error HwcDisplayConfigs::Update(DrmConnector &connector) {
         .group_id = group_found,
         .mode = mode,
         .disabled = disabled,
+        .output_type = 1,  // OutputType::SYSTEM
     };
 
     /* Chwck if the mode is preferred */
diff --git a/hwc2_device/HwcDisplayConfigs.h b/hwc2_device/HwcDisplayConfigs.h
index 33dcb81..8fc89bf 100644
--- a/hwc2_device/HwcDisplayConfigs.h
+++ b/hwc2_device/HwcDisplayConfigs.h
@@ -31,6 +31,7 @@ struct HwcDisplayConfig {
   uint32_t group_id{};
   DrmMode mode{};
   bool disabled{};
+  uint32_t output_type{};
 
   bool IsInterlaced() const {
     return (mode.GetRawMode().flags & DRM_MODE_FLAG_INTERLACE) != 0;
diff --git a/hwc2_device/HwcLayer.cpp b/hwc2_device/HwcLayer.cpp
index cb18fdd..400ac9b 100644
--- a/hwc2_device/HwcLayer.cpp
+++ b/hwc2_device/HwcLayer.cpp
@@ -25,10 +25,21 @@
 namespace android {
 
 void HwcLayer::SetLayerProperties(const LayerProperties& layer_properties) {
-  if (layer_properties.buffer) {
-    layer_data_.acquire_fence = layer_properties.buffer->acquire_fence;
-    buffer_handle_ = layer_properties.buffer->buffer_handle;
-    buffer_handle_updated_ = true;
+  if (layer_properties.slot_buffer) {
+    auto slot_id = layer_properties.slot_buffer->slot_id;
+    if (!layer_properties.slot_buffer->bi) {
+      slots_.erase(slot_id);
+    } else {
+      slots_[slot_id] = {
+          .bi = layer_properties.slot_buffer->bi.value(),
+          .fb = {},
+      };
+    }
+  }
+  if (layer_properties.active_slot) {
+    active_slot_id_ = layer_properties.active_slot->slot_id;
+    layer_data_.acquire_fence = layer_properties.active_slot->fence;
+    buffer_updated_ = true;
   }
   if (layer_properties.blend_mode) {
     blend_mode_ = layer_properties.blend_mode.value();
@@ -46,8 +57,7 @@ void HwcLayer::SetLayerProperties(const LayerProperties& layer_properties) {
     layer_data_.pi.display_frame = layer_properties.display_frame.value();
   }
   if (layer_properties.alpha) {
-    layer_data_.pi.alpha = std::lround(layer_properties.alpha.value() *
-                                       UINT16_MAX);
+    layer_data_.pi.alpha = layer_properties.alpha.value();
   }
   if (layer_properties.source_crop) {
     layer_data_.pi.source_crop = layer_properties.source_crop.value();
@@ -60,192 +70,44 @@ void HwcLayer::SetLayerProperties(const LayerProperties& layer_properties) {
   }
 }
 
-// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
-HWC2::Error HwcLayer::SetCursorPosition(int32_t /*x*/, int32_t /*y*/) {
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcLayer::SetLayerBlendMode(int32_t mode) {
-  switch (static_cast<HWC2::BlendMode>(mode)) {
-    case HWC2::BlendMode::None:
-      blend_mode_ = BufferBlendMode::kNone;
-      break;
-    case HWC2::BlendMode::Premultiplied:
-      blend_mode_ = BufferBlendMode::kPreMult;
-      break;
-    case HWC2::BlendMode::Coverage:
-      blend_mode_ = BufferBlendMode::kCoverage;
-      break;
-    default:
-      ALOGE("Unknown blending mode b=%d", mode);
-      blend_mode_ = BufferBlendMode::kUndefined;
-      break;
-  }
-  return HWC2::Error::None;
-}
-
-/* Find API details at:
- * https://cs.android.com/android/platform/superproject/+/android-11.0.0_r3:hardware/libhardware/include/hardware/hwcomposer2.h;l=2314
- */
-HWC2::Error HwcLayer::SetLayerBuffer(buffer_handle_t buffer,
-                                     int32_t acquire_fence) {
-  layer_data_.acquire_fence = MakeSharedFd(acquire_fence);
-  buffer_handle_ = buffer;
-  buffer_handle_updated_ = true;
-
-  return HWC2::Error::None;
-}
-
-// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
-HWC2::Error HwcLayer::SetLayerColor(hwc_color_t /*color*/) {
-  // TODO(nobody): Put to client composition here?
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcLayer::SetLayerCompositionType(int32_t type) {
-  sf_type_ = static_cast<HWC2::Composition>(type);
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcLayer::SetLayerDataspace(int32_t dataspace) {
-  switch (dataspace & HAL_DATASPACE_STANDARD_MASK) {
-    case HAL_DATASPACE_STANDARD_BT709:
-      color_space_ = BufferColorSpace::kItuRec709;
-      break;
-    case HAL_DATASPACE_STANDARD_BT601_625:
-    case HAL_DATASPACE_STANDARD_BT601_625_UNADJUSTED:
-    case HAL_DATASPACE_STANDARD_BT601_525:
-    case HAL_DATASPACE_STANDARD_BT601_525_UNADJUSTED:
-      color_space_ = BufferColorSpace::kItuRec601;
-      break;
-    case HAL_DATASPACE_STANDARD_BT2020:
-    case HAL_DATASPACE_STANDARD_BT2020_CONSTANT_LUMINANCE:
-      color_space_ = BufferColorSpace::kItuRec2020;
-      break;
-    default:
-      color_space_ = BufferColorSpace::kUndefined;
-  }
-
-  switch (dataspace & HAL_DATASPACE_RANGE_MASK) {
-    case HAL_DATASPACE_RANGE_FULL:
-      sample_range_ = BufferSampleRange::kFullRange;
-      break;
-    case HAL_DATASPACE_RANGE_LIMITED:
-      sample_range_ = BufferSampleRange::kLimitedRange;
-      break;
-    default:
-      sample_range_ = BufferSampleRange::kUndefined;
-  }
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcLayer::SetLayerDisplayFrame(hwc_rect_t frame) {
-  layer_data_.pi.display_frame = frame;
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcLayer::SetLayerPlaneAlpha(float alpha) {
-  layer_data_.pi.alpha = std::lround(alpha * UINT16_MAX);
-  return HWC2::Error::None;
-}
-
-// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
-HWC2::Error HwcLayer::SetLayerSidebandStream(
-    const native_handle_t* /*stream*/) {
-  // TODO(nobody): We don't support sideband
-  return HWC2::Error::Unsupported;
-}
-
-HWC2::Error HwcLayer::SetLayerSourceCrop(hwc_frect_t crop) {
-  layer_data_.pi.source_crop = crop;
-  return HWC2::Error::None;
-}
-
-// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
-HWC2::Error HwcLayer::SetLayerSurfaceDamage(hwc_region_t /*damage*/) {
-  // TODO(nobody): We don't use surface damage, marking as unsupported
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcLayer::SetLayerTransform(int32_t transform) {
-  uint32_t l_transform = 0;
-
-  // 270* and 180* cannot be combined with flips. More specifically, they
-  // already contain both horizontal and vertical flips, so those fields are
-  // redundant in this case. 90* rotation can be combined with either horizontal
-  // flip or vertical flip, so treat it differently
-  if (transform == HWC_TRANSFORM_ROT_270) {
-    l_transform = LayerTransform::kRotate270;
-  } else if (transform == HWC_TRANSFORM_ROT_180) {
-    l_transform = LayerTransform::kRotate180;
-  } else {
-    if ((transform & HWC_TRANSFORM_FLIP_H) != 0)
-      l_transform |= LayerTransform::kFlipH;
-    if ((transform & HWC_TRANSFORM_FLIP_V) != 0)
-      l_transform |= LayerTransform::kFlipV;
-    if ((transform & HWC_TRANSFORM_ROT_90) != 0)
-      l_transform |= LayerTransform::kRotate90;
-  }
-
-  layer_data_.pi.transform = static_cast<LayerTransform>(l_transform);
-  return HWC2::Error::None;
-}
-
-// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
-HWC2::Error HwcLayer::SetLayerVisibleRegion(hwc_region_t /*visible*/) {
-  // TODO(nobody): We don't use this information, marking as unsupported
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcLayer::SetLayerZOrder(uint32_t order) {
-  z_order_ = order;
-  return HWC2::Error::None;
-}
-
 void HwcLayer::ImportFb() {
-  if (!IsLayerUsableAsDevice() || !buffer_handle_updated_) {
-    return;
-  }
-  buffer_handle_updated_ = false;
-
-  layer_data_.fb = {};
-
-  auto unique_id = BufferInfoGetter::GetInstance()->GetUniqueId(buffer_handle_);
-  if (unique_id && SwChainGetBufferFromCache(*unique_id)) {
+  if (!IsLayerUsableAsDevice() || !buffer_updated_ ||
+      !active_slot_id_.has_value()) {
     return;
   }
+  buffer_updated_ = false;
 
-  layer_data_.bi = BufferInfoGetter::GetInstance()->GetBoInfo(buffer_handle_);
-  if (!layer_data_.bi) {
-    ALOGW("Unable to get buffer information (0x%p)", buffer_handle_);
-    bi_get_failed_ = true;
+  if (slots_[*active_slot_id_].fb) {
     return;
   }
 
-  layer_data_
-      .fb = parent_->GetPipe().device->GetDrmFbImporter().GetOrCreateFbId(
-      &layer_data_.bi.value());
+  auto& fb_importer = parent_->GetPipe().device->GetDrmFbImporter();
+  auto fb = fb_importer.GetOrCreateFbId(&slots_[*active_slot_id_].bi);
 
-  if (!layer_data_.fb) {
-    ALOGV("Unable to create framebuffer object for buffer 0x%p",
-          buffer_handle_);
+  if (!fb) {
+    ALOGE("Unable to create framebuffer object for layer %p", this);
     fb_import_failed_ = true;
     return;
   }
 
-  if (unique_id) {
-    SwChainAddCurrentBuffer(*unique_id);
-  }
+  slots_[*active_slot_id_].fb = fb;
 }
 
 void HwcLayer::PopulateLayerData() {
   ImportFb();
 
-  if (!layer_data_.bi) {
-    ALOGE("%s: Invalid state", __func__);
+  if (!active_slot_id_.has_value()) {
+    ALOGE("Internal error: populate layer data called without active slot");
     return;
   }
 
+  if (slots_.count(*active_slot_id_) == 0) {
+    return;
+  }
+
+  layer_data_.bi = slots_[*active_slot_id_].bi;
+  layer_data_.fb = slots_[*active_slot_id_].fb;
+
   if (blend_mode_ != BufferBlendMode::kUndefined) {
     layer_data_.bi->blend_mode = blend_mode_;
   }
@@ -257,75 +119,9 @@ void HwcLayer::PopulateLayerData() {
   }
 }
 
-/* SwapChain Cache */
-
-bool HwcLayer::SwChainGetBufferFromCache(BufferUniqueId unique_id) {
-  if (swchain_lookup_table_.count(unique_id) == 0) {
-    return false;
-  }
-
-  auto seq = swchain_lookup_table_[unique_id];
-
-  if (swchain_cache_.count(seq) == 0) {
-    return false;
-  }
-
-  auto& el = swchain_cache_[seq];
-  if (!el.bi) {
-    return false;
-  }
-
-  layer_data_.bi = el.bi;
-  layer_data_.fb = el.fb;
-
-  return true;
-}
-
-void HwcLayer::SwChainReassemble(BufferUniqueId unique_id) {
-  if (swchain_lookup_table_.count(unique_id) != 0) {
-    if (swchain_lookup_table_[unique_id] ==
-        int(swchain_lookup_table_.size()) - 1) {
-      /* Skip same buffer */
-      return;
-    }
-    if (swchain_lookup_table_[unique_id] == 0) {
-      swchain_reassembled_ = true;
-      return;
-    }
-    /* Tracking error */
-    SwChainClearCache();
-    return;
-  }
-
-  swchain_lookup_table_[unique_id] = int(swchain_lookup_table_.size());
-}
-
-void HwcLayer::SwChainAddCurrentBuffer(BufferUniqueId unique_id) {
-  if (!swchain_reassembled_) {
-    SwChainReassemble(unique_id);
-  }
-
-  if (swchain_reassembled_) {
-    if (swchain_lookup_table_.count(unique_id) == 0) {
-      SwChainClearCache();
-      return;
-    }
-
-    auto seq = swchain_lookup_table_[unique_id];
-
-    if (swchain_cache_.count(seq) == 0) {
-      swchain_cache_[seq] = {};
-    }
-
-    swchain_cache_[seq].bi = layer_data_.bi;
-    swchain_cache_[seq].fb = layer_data_.fb;
-  }
-}
-
-void HwcLayer::SwChainClearCache() {
-  swchain_cache_.clear();
-  swchain_lookup_table_.clear();
-  swchain_reassembled_ = false;
+void HwcLayer::ClearSlots() {
+  slots_.clear();
+  active_slot_id_.reset();
 }
 
 }  // namespace android
\ No newline at end of file
diff --git a/hwc2_device/HwcLayer.h b/hwc2_device/HwcLayer.h
index e1d62b7..c335d88 100644
--- a/hwc2_device/HwcLayer.h
+++ b/hwc2_device/HwcLayer.h
@@ -18,30 +18,43 @@
 
 #include <aidl/android/hardware/graphics/common/Transform.h>
 #include <hardware/hwcomposer2.h>
+#include <memory>
 
+#include "bufferinfo/BufferInfo.h"
 #include "bufferinfo/BufferInfoGetter.h"
 #include "compositor/LayerData.h"
+#include "utils/fd.h"
 
 namespace android {
 
 class HwcDisplay;
 
+class FrontendLayerBase {
+ public:
+  virtual ~FrontendLayerBase() = default;
+};
+
 class HwcLayer {
  public:
   struct Buffer {
-    buffer_handle_t buffer_handle;
-    SharedFd acquire_fence;
+    int32_t slot_id;
+    std::optional<BufferInfo> bi;
+  };
+  struct Slot {
+    int32_t slot_id;
+    SharedFd fence;
   };
   // A set of properties to be validated.
   struct LayerProperties {
-    std::optional<Buffer> buffer;
+    std::optional<Buffer> slot_buffer;
+    std::optional<Slot> active_slot;
     std::optional<BufferBlendMode> blend_mode;
     std::optional<BufferColorSpace> color_space;
     std::optional<BufferSampleRange> sample_range;
     std::optional<HWC2::Composition> composition_type;
-    std::optional<hwc_rect_t> display_frame;
+    std::optional<DstRectInfo> display_frame;
     std::optional<float> alpha;
-    std::optional<hwc_frect_t> source_crop;
+    std::optional<SrcRectInfo> source_crop;
     std::optional<LayerTransform> transform;
     std::optional<uint32_t> z_order;
   };
@@ -82,21 +95,13 @@ class HwcLayer {
 
   void SetLayerProperties(const LayerProperties &layer_properties);
 
-  // HWC2 Layer hooks
-  HWC2::Error SetCursorPosition(int32_t /*x*/, int32_t /*y*/);
-  HWC2::Error SetLayerBlendMode(int32_t mode);
-  HWC2::Error SetLayerBuffer(buffer_handle_t buffer, int32_t acquire_fence);
-  HWC2::Error SetLayerColor(hwc_color_t /*color*/);
-  HWC2::Error SetLayerCompositionType(int32_t type);
-  HWC2::Error SetLayerDataspace(int32_t dataspace);
-  HWC2::Error SetLayerDisplayFrame(hwc_rect_t frame);
-  HWC2::Error SetLayerPlaneAlpha(float alpha);
-  HWC2::Error SetLayerSidebandStream(const native_handle_t *stream);
-  HWC2::Error SetLayerSourceCrop(hwc_frect_t crop);
-  HWC2::Error SetLayerSurfaceDamage(hwc_region_t damage);
-  HWC2::Error SetLayerTransform(int32_t transform);
-  HWC2::Error SetLayerVisibleRegion(hwc_region_t visible);
-  HWC2::Error SetLayerZOrder(uint32_t order);
+  auto GetFrontendPrivateData() -> std::shared_ptr<FrontendLayerBase> {
+    return frontend_private_data_;
+  }
+
+  auto SetFrontendPrivateData(std::shared_ptr<FrontendLayerBase> data) {
+    frontend_private_data_ = std::move(data);
+  }
 
  private:
   // sf_type_ stores the initial type given to us by surfaceflinger,
@@ -117,43 +122,32 @@ class HwcLayer {
   BufferColorSpace color_space_{};
   BufferSampleRange sample_range_{};
   BufferBlendMode blend_mode_{};
-  buffer_handle_t buffer_handle_{};
-  bool buffer_handle_updated_{};
+  bool buffer_updated_{};
 
   bool prior_buffer_scanout_flag_{};
 
   HwcDisplay *const parent_;
 
-  /* Layer state */
- public:
-  void PopulateLayerData();
+  std::shared_ptr<FrontendLayerBase> frontend_private_data_;
 
-  bool IsLayerUsableAsDevice() const {
-    return !bi_get_failed_ && !fb_import_failed_ && buffer_handle_ != nullptr;
-  }
+  std::optional<int32_t> active_slot_id_;
+  struct BufferSlot {
+    BufferInfo bi;
+    std::shared_ptr<DrmFbIdHandle> fb;
+  };
+  std::map<int32_t /*slot*/, BufferSlot> slots_;
 
- private:
   void ImportFb();
-  bool bi_get_failed_{};
   bool fb_import_failed_{};
 
-  /* SwapChain Cache */
  public:
-  void SwChainClearCache();
-
- private:
-  struct SwapChainElement {
-    std::optional<BufferInfo> bi;
-    std::shared_ptr<DrmFbIdHandle> fb;
-  };
-
-  bool SwChainGetBufferFromCache(BufferUniqueId unique_id);
-  void SwChainReassemble(BufferUniqueId unique_id);
-  void SwChainAddCurrentBuffer(BufferUniqueId unique_id);
+  void PopulateLayerData();
+  void ClearSlots();
 
-  std::map<int /*seq_no*/, SwapChainElement> swchain_cache_;
-  std::map<BufferUniqueId, int /*seq_no*/> swchain_lookup_table_;
-  bool swchain_reassembled_{};
+  bool IsLayerUsableAsDevice() const {
+    return !fb_import_failed_ && active_slot_id_.has_value() &&
+           slots_.count(*active_slot_id_) > 0;
+  }
 };
 
 }  // namespace android
diff --git a/hwc2_device/hwc2_device.cpp b/hwc2_device/hwc2_device.cpp
index 28b6963..7c9d806 100644
--- a/hwc2_device/hwc2_device.cpp
+++ b/hwc2_device/hwc2_device.cpp
@@ -19,10 +19,16 @@
 
 #define LOG_TAG "drmhwc"
 
+#include <cassert>
 #include <cinttypes>
+#include <memory>
+#include <optional>
+
+#include <cutils/native_handle.h>
 
 #include "DrmHwcTwo.h"
 #include "backend/Backend.h"
+#include "hwc2_device/HwcLayer.h"
 #include "utils/log.h"
 
 namespace android {
@@ -43,6 +49,128 @@ static std::string GetFuncName(const char *pretty_function) {
   return str.substr(p1, p2 - p1);
 }
 
+class Hwc2DeviceDisplay : public FrontendDisplayBase {
+ public:
+  std::vector<HwcDisplay::ReleaseFence> release_fences;
+  std::vector<HwcDisplay::ChangedLayer> changed_layers;
+
+  int64_t next_layer_id = 1;
+};
+
+static auto GetHwc2DeviceDisplay(HwcDisplay &display)
+    -> std::shared_ptr<Hwc2DeviceDisplay> {
+  auto frontend_private_data = display.GetFrontendPrivateData();
+  if (!frontend_private_data) {
+    frontend_private_data = std::make_shared<Hwc2DeviceDisplay>();
+    display.SetFrontendPrivateData(frontend_private_data);
+  }
+  return std::static_pointer_cast<Hwc2DeviceDisplay>(frontend_private_data);
+}
+
+class Hwc2DeviceLayer : public FrontendLayerBase {
+ public:
+  auto HandleNextBuffer(buffer_handle_t buffer_handle, int32_t fence_fd)
+      -> std::pair<std::optional<HwcLayer::LayerProperties>,
+                   bool /* not a swapchain */> {
+    auto slot = GetSlotNumber(buffer_handle);
+
+    if (invalid_) {
+      return std::make_pair(std::nullopt, true);
+    }
+
+    bool buffer_provided = false;
+    bool not_a_swapchain = true;
+    int32_t slot_id = 0;
+
+    if (slot.has_value()) {
+      buffer_provided = swchain_slots_[slot.value()];
+      slot_id = slot.value();
+      not_a_swapchain = true;
+    }
+
+    HwcLayer::LayerProperties lp;
+    if (!buffer_provided) {
+      auto bo_info = BufferInfoGetter::GetInstance()->GetBoInfo(buffer_handle);
+      if (!bo_info) {
+        invalid_ = true;
+        return std::make_pair(std::nullopt, true);
+      }
+
+      lp.slot_buffer = {
+          .slot_id = slot_id,
+          .bi = bo_info,
+      };
+    }
+    lp.active_slot = {
+        .slot_id = slot_id,
+        .fence = MakeSharedFd(fence_fd),
+    };
+
+    return std::make_pair(lp, not_a_swapchain);
+  }
+
+  void SwChainClearCache() {
+    swchain_lookup_table_.clear();
+    swchain_slots_.clear();
+    swchain_reassembled_ = false;
+  }
+
+ private:
+  auto GetSlotNumber(buffer_handle_t buffer_handle) -> std::optional<int32_t> {
+    auto unique_id = BufferInfoGetter::GetInstance()->GetUniqueId(
+        buffer_handle);
+    if (!unique_id) {
+      ALOGE("Failed to get unique id for buffer handle %p", buffer_handle);
+      return std::nullopt;
+    }
+
+    if (swchain_lookup_table_.count(*unique_id) == 0) {
+      SwChainReassemble(*unique_id);
+      return std::nullopt;
+    }
+
+    if (!swchain_reassembled_) {
+      return std::nullopt;
+    }
+
+    return swchain_lookup_table_[*unique_id];
+  }
+
+  void SwChainReassemble(BufferUniqueId unique_id) {
+    if (swchain_lookup_table_.count(unique_id) != 0) {
+      if (swchain_lookup_table_[unique_id] ==
+          int(swchain_lookup_table_.size()) - 1) {
+        /* Skip same buffer */
+        return;
+      }
+      if (swchain_lookup_table_[unique_id] == 0) {
+        swchain_reassembled_ = true;
+        return;
+      }
+      /* Tracking error */
+      SwChainClearCache();
+      return;
+    }
+
+    swchain_lookup_table_[unique_id] = int(swchain_lookup_table_.size());
+  }
+
+  bool invalid_{}; /* Layer is invalid and should be skipped */
+  std::map<BufferUniqueId, int /*slot*/> swchain_lookup_table_;
+  std::map<int /*slot*/, bool /*buffer_provided*/> swchain_slots_;
+  bool swchain_reassembled_{};
+};
+
+static auto GetHwc2DeviceLayer(HwcLayer &layer)
+    -> std::shared_ptr<Hwc2DeviceLayer> {
+  auto frontend_private_data = layer.GetFrontendPrivateData();
+  if (!frontend_private_data) {
+    frontend_private_data = std::make_shared<Hwc2DeviceLayer>();
+    layer.SetFrontendPrivateData(frontend_private_data);
+  }
+  return std::static_pointer_cast<Hwc2DeviceLayer>(frontend_private_data);
+}
+
 struct Drmhwc2Device : hwc2_device {
   DrmHwcTwo drmhwctwo;
 };
@@ -54,6 +182,7 @@ static DrmHwcTwo *ToDrmHwcTwo(hwc2_device_t *dev) {
 
 template <typename PFN, typename T>
 static hwc2_function_pointer_t ToHook(T function) {
+  // NOLINTNEXTLINE(modernize-type-traits): ToHook is going to be removed
   static_assert(std::is_same<PFN, T>::value, "Incompatible fn pointer");
   // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast):
   return reinterpret_cast<hwc2_function_pointer_t>(function);
@@ -81,24 +210,6 @@ static int32_t DisplayHook(hwc2_device_t *dev, hwc2_display_t display_handle,
   return static_cast<int32_t>((display->*func)(std::forward<Args>(args)...));
 }
 
-template <typename HookType, HookType func, typename... Args>
-static int32_t LayerHook(hwc2_device_t *dev, hwc2_display_t display_handle,
-                         hwc2_layer_t layer_handle, Args... args) {
-  ALOGV("Display #%" PRIu64 " Layer: #%" PRIu64 " hook: %s", display_handle,
-        layer_handle, GetFuncName(__PRETTY_FUNCTION__).c_str());
-  DrmHwcTwo *hwc = ToDrmHwcTwo(dev);
-  const std::unique_lock lock(hwc->GetResMan().GetMainLock());
-  auto *display = hwc->GetDisplay(display_handle);
-  if (display == nullptr)
-    return static_cast<int32_t>(HWC2::Error::BadDisplay);
-
-  HwcLayer *layer = display->get_layer(layer_handle);
-  if (!layer)
-    return static_cast<int32_t>(HWC2::Error::BadLayer);
-
-  return static_cast<int32_t>((layer->*func)(std::forward<Args>(args)...));
-}
-
 static int HookDevClose(hw_device_t *dev) {
   // NOLINTNEXTLINE (cppcoreguidelines-pro-type-reinterpret-cast): Safe
   auto *hwc2_dev = reinterpret_cast<hwc2_device_t *>(dev);
@@ -111,6 +222,548 @@ static void HookDevGetCapabilities(hwc2_device_t * /*dev*/, uint32_t *out_count,
   *out_count = 0;
 }
 
+// NOLINTBEGIN(cppcoreguidelines-macro-usage)
+
+#define LOCK_COMPOSER(dev)       \
+  auto *ihwc = ToDrmHwcTwo(dev); \
+  const std::unique_lock lock(ihwc->GetResMan().GetMainLock());
+
+#define GET_DISPLAY(display_id)                  \
+  auto *idisplay = ihwc->GetDisplay(display_id); \
+  if (!idisplay)                                 \
+    return static_cast<int32_t>(HWC2::Error::BadDisplay);
+
+#define GET_LAYER(layer_id)                     \
+  auto *ilayer = idisplay->get_layer(layer_id); \
+  if (!ilayer)                                  \
+    return static_cast<int32_t>(HWC2::Error::BadLayer);
+
+// NOLINTEND(cppcoreguidelines-macro-usage)
+
+static BufferColorSpace Hwc2ToColorSpace(int32_t dataspace) {
+  switch (dataspace & HAL_DATASPACE_STANDARD_MASK) {
+    case HAL_DATASPACE_STANDARD_BT709:
+      return BufferColorSpace::kItuRec709;
+    case HAL_DATASPACE_STANDARD_BT601_625:
+    case HAL_DATASPACE_STANDARD_BT601_625_UNADJUSTED:
+    case HAL_DATASPACE_STANDARD_BT601_525:
+    case HAL_DATASPACE_STANDARD_BT601_525_UNADJUSTED:
+      return BufferColorSpace::kItuRec601;
+    case HAL_DATASPACE_STANDARD_BT2020:
+    case HAL_DATASPACE_STANDARD_BT2020_CONSTANT_LUMINANCE:
+      return BufferColorSpace::kItuRec2020;
+    default:
+      return BufferColorSpace::kUndefined;
+  }
+}
+
+static BufferSampleRange Hwc2ToSampleRange(int32_t dataspace) {
+  switch (dataspace & HAL_DATASPACE_RANGE_MASK) {
+    case HAL_DATASPACE_RANGE_FULL:
+      return BufferSampleRange::kFullRange;
+    case HAL_DATASPACE_RANGE_LIMITED:
+      return BufferSampleRange::kLimitedRange;
+    default:
+      return BufferSampleRange::kUndefined;
+  }
+}
+
+/* Display functions */
+static int32_t CreateLayer(hwc2_device_t *device, hwc2_display_t display,
+                           hwc2_layer_t *out_layer) {
+  ALOGV("CreateLayer");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  auto hwc2display = GetHwc2DeviceDisplay(*idisplay);
+
+  if (!idisplay->CreateLayer(hwc2display->next_layer_id)) {
+    return static_cast<int32_t>(HWC2::Error::BadDisplay);
+  }
+
+  *out_layer = (hwc2_layer_t)hwc2display->next_layer_id;
+  hwc2display->next_layer_id++;
+
+  return 0;
+}
+
+static int32_t DestroyLayer(hwc2_device_t *device, hwc2_display_t display,
+                            hwc2_layer_t layer) {
+  ALOGV("DestroyLayer");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  if (!idisplay->DestroyLayer((ILayerId)layer)) {
+    return static_cast<int32_t>(HWC2::Error::BadLayer);
+  }
+
+  return 0;
+}
+
+static int32_t GetDisplayRequests(hwc2_device_t * /*device*/,
+                                  hwc2_display_t /*display*/,
+                                  int32_t * /* out_display_requests */,
+                                  uint32_t *out_num_elements,
+                                  hwc2_layer_t * /*out_layers*/,
+                                  int32_t * /*out_layer_requests*/) {
+  ALOGV("GetDisplayRequests");
+
+  *out_num_elements = 0;
+  return 0;
+}
+
+static int32_t GetDozeSupport(hwc2_device_t * /*device*/,
+                              hwc2_display_t /*display*/,
+                              int32_t *out_support) {
+  ALOGV("GetDozeSupport");
+  *out_support = 0;  // Doze support is not available
+  return 0;
+}
+
+static int32_t GetClientTargetSupport(hwc2_device_t * /*device*/,
+                                      hwc2_display_t /*display*/,
+                                      uint32_t /*width*/, uint32_t /*height*/,
+                                      int32_t /*format*/, int32_t dataspace) {
+  ALOGV("GetClientTargetSupport");
+
+  if (dataspace != HAL_DATASPACE_UNKNOWN)
+    return static_cast<int32_t>(HWC2::Error::Unsupported);
+
+  return 0;
+}
+
+static int32_t SetClientTarget(hwc2_device_t *device, hwc2_display_t display,
+                               buffer_handle_t target, int32_t acquire_fence,
+                               int32_t dataspace, hwc_region_t /*damage*/) {
+  ALOGV("SetClientTarget");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  auto &client_layer = idisplay->GetClientLayer();
+  auto h2l = GetHwc2DeviceLayer(client_layer);
+  if (!h2l) {
+    client_layer.SetFrontendPrivateData(std::make_shared<Hwc2DeviceLayer>());
+  }
+
+  if (target == nullptr) {
+    client_layer.ClearSlots();
+    h2l->SwChainClearCache();
+
+    return 0;
+  }
+
+  auto [lp, not_a_swapchain] = h2l->HandleNextBuffer(target, acquire_fence);
+  if (!lp) {
+    ALOGE("Failed to process client target");
+    return static_cast<int32_t>(HWC2::Error::BadLayer);
+  }
+
+  if (not_a_swapchain) {
+    client_layer.ClearSlots();
+  }
+
+  lp->color_space = Hwc2ToColorSpace(dataspace);
+  lp->sample_range = Hwc2ToSampleRange(dataspace);
+
+  idisplay->GetClientLayer().SetLayerProperties(lp.value());
+
+  return 0;
+}
+
+static int32_t SetOutputBuffer(hwc2_device_t *device, hwc2_display_t display,
+                               buffer_handle_t buffer, int32_t release_fence) {
+  ALOGV("SetOutputBuffer");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  auto &writeback_layer = idisplay->GetWritebackLayer();
+  if (!writeback_layer) {
+    ALOGE("Writeback layer is not available");
+    return static_cast<int32_t>(HWC2::Error::BadLayer);
+  }
+
+  auto h2l = GetHwc2DeviceLayer(*writeback_layer);
+  if (!h2l) {
+    writeback_layer->SetFrontendPrivateData(
+        std::make_shared<Hwc2DeviceLayer>());
+  }
+
+  auto [lp, not_a_swapchain] = h2l->HandleNextBuffer(buffer, release_fence);
+  if (!lp) {
+    ALOGE("Failed to process output buffer");
+    return static_cast<int32_t>(HWC2::Error::BadLayer);
+  }
+
+  if (not_a_swapchain) {
+    writeback_layer->ClearSlots();
+  }
+
+  writeback_layer->SetLayerProperties(lp.value());
+
+  return 0;
+}
+
+static int32_t AcceptDisplayChanges(hwc2_device_t *device,
+                                    hwc2_display_t display) {
+  ALOGV("AcceptDisplayChanges");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  idisplay->AcceptValidatedComposition();
+
+  return 0;
+}
+
+static int32_t GetReleaseFences(hwc2_device_t *device, hwc2_display_t display,
+                                uint32_t *out_num_elements,
+                                hwc2_layer_t *out_layers, int32_t *out_fences) {
+  ALOGV("GetReleaseFences");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  auto hwc2display = GetHwc2DeviceDisplay(*idisplay);
+
+  if (*out_num_elements < hwc2display->release_fences.size()) {
+    ALOGW("Overflow num_elements %d/%zu", *out_num_elements,
+          hwc2display->release_fences.size());
+    return static_cast<int32_t>(HWC2::Error::NoResources);
+  }
+
+  for (size_t i = 0; i < hwc2display->release_fences.size(); ++i) {
+    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic):
+    out_layers[i] = hwc2display->release_fences[i].first;
+    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic):
+    out_fences[i] = DupFd(hwc2display->release_fences[i].second);
+  }
+
+  *out_num_elements = hwc2display->release_fences.size();
+  hwc2display->release_fences.clear();
+
+  return static_cast<int32_t>(HWC2::Error::None);
+}
+
+static int32_t ValidateDisplay(hwc2_device_t *device, hwc2_display_t display,
+                               uint32_t *out_num_types,
+                               uint32_t *out_num_requests) {
+  ALOGV("ValidateDisplay");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  auto hwc2display = GetHwc2DeviceDisplay(*idisplay);
+
+  hwc2display->changed_layers = idisplay->ValidateStagedComposition();
+
+  *out_num_types = hwc2display->changed_layers.size();
+  *out_num_requests = 0;
+
+  return 0;
+}
+
+static int32_t GetChangedCompositionTypes(hwc2_device_t *device,
+                                          hwc2_display_t display,
+                                          uint32_t *out_num_elements,
+                                          hwc2_layer_t *out_layers,
+                                          int32_t *out_types) {
+  ALOGV("GetChangedCompositionTypes");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  auto hwc2display = GetHwc2DeviceDisplay(*idisplay);
+
+  if (*out_num_elements < hwc2display->changed_layers.size()) {
+    ALOGW("Overflow num_elements %d/%zu", *out_num_elements,
+          hwc2display->changed_layers.size());
+    return static_cast<int32_t>(HWC2::Error::NoResources);
+  }
+
+  for (size_t i = 0; i < hwc2display->changed_layers.size(); ++i) {
+    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic):
+    out_layers[i] = hwc2display->changed_layers[i].first;
+    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic):
+    out_types[i] = static_cast<int32_t>(hwc2display->changed_layers[i].second);
+  }
+
+  *out_num_elements = hwc2display->changed_layers.size();
+  hwc2display->changed_layers.clear();
+
+  return static_cast<int32_t>(HWC2::Error::None);
+}
+
+static int32_t PresentDisplay(hwc2_device_t *device, hwc2_display_t display,
+                              int32_t *out_release_fence) {
+  ALOGV("PresentDisplay");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  auto hwc2display = GetHwc2DeviceDisplay(*idisplay);
+
+  SharedFd out_fence;
+
+  hwc2display->release_fences.clear();
+
+  if (!idisplay->PresentStagedComposition(std::nullopt, out_fence,
+                                          hwc2display->release_fences)) {
+    ALOGE("Failed to present display");
+    return static_cast<int32_t>(HWC2::Error::BadDisplay);
+  }
+
+  *out_release_fence = DupFd(out_fence);
+
+  return 0;
+}
+
+#if __ANDROID_API__ >= 28
+
+static int32_t GetDisplayBrightnessSupport(hwc2_device_t * /*device*/,
+                                           hwc2_display_t /*display*/,
+                                           bool *out_support) {
+  ALOGV("GetDisplayBrightnessSupport");
+  *out_support = false;  // Brightness support is not available
+  return static_cast<int32_t>(HWC2::Error::None);
+}
+
+static int32_t SetDisplayBrightness(hwc2_device_t * /*device*/,
+                                    hwc2_display_t /*display*/,
+                                    float /*brightness*/) {
+  ALOGV("SetDisplayBrightness");
+  return static_cast<int32_t>(HWC2::Error::Unsupported);
+}
+
+#endif
+
+#if __ANDROID_API__ >= 29
+static int32_t SetAutoLowLatencyMode(hwc2_device_t * /*device*/,
+                                     hwc2_display_t /*display*/, bool /*on*/) {
+  ALOGV("SetAutoLowLatencyMode");
+  return static_cast<int32_t>(HWC2::Error::Unsupported);
+}
+
+static int32_t GetSupportedContentTypes(
+    hwc2_device_t * /*device*/, hwc2_display_t /*display*/,
+    uint32_t *out_num_supported_content_types,
+    uint32_t * /*out_supported_content_types*/) {
+  ALOGV("GetSupportedContentTypes");
+  *out_num_supported_content_types = 0;
+  return static_cast<int32_t>(HWC2::Error::None);
+}
+#endif
+
+/* Layer functions */
+
+static int32_t SetLayerBlendMode(hwc2_device_t *device, hwc2_display_t display,
+                                 hwc2_layer_t layer,
+                                 int32_t /*hwc2_blend_mode_t*/ mode) {
+  ALOGV("SetLayerBlendMode");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+  GET_LAYER(layer);
+
+  BufferBlendMode blend_mode{};
+  switch (static_cast<HWC2::BlendMode>(mode)) {
+    case HWC2::BlendMode::None:
+      blend_mode = BufferBlendMode::kNone;
+      break;
+    case HWC2::BlendMode::Premultiplied:
+      blend_mode = BufferBlendMode::kPreMult;
+      break;
+    case HWC2::BlendMode::Coverage:
+      blend_mode = BufferBlendMode::kCoverage;
+      break;
+    default:
+      ALOGE("Unknown blending mode b=%d", mode);
+      blend_mode = BufferBlendMode::kUndefined;
+      break;
+  }
+
+  HwcLayer::LayerProperties layer_properties;
+  layer_properties.blend_mode = blend_mode;
+
+  ilayer->SetLayerProperties(layer_properties);
+
+  return 0;
+}
+
+static int32_t SetLayerBuffer(hwc2_device_t *device, hwc2_display_t display,
+                              hwc2_layer_t layer, buffer_handle_t buffer,
+                              int32_t acquire_fence) {
+  ALOGV("SetLayerBuffer");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+  GET_LAYER(layer);
+
+  auto h2l = GetHwc2DeviceLayer(*ilayer);
+
+  auto [lp, not_a_swapchain] = h2l->HandleNextBuffer(buffer, acquire_fence);
+  if (!lp) {
+    ALOGV("Failed to process layer buffer");
+    return static_cast<int32_t>(HWC2::Error::BadLayer);
+  }
+
+  if (not_a_swapchain) {
+    ilayer->ClearSlots();
+  }
+
+  ilayer->SetLayerProperties(lp.value());
+
+  return 0;
+}
+
+static int32_t SetLayerDataspace(hwc2_device_t *device, hwc2_display_t display,
+                                 hwc2_layer_t layer,
+                                 int32_t /*android_dataspace_t*/ dataspace) {
+  ALOGV("SetLayerDataspace");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+  GET_LAYER(layer);
+
+  HwcLayer::LayerProperties layer_properties;
+  layer_properties.color_space = Hwc2ToColorSpace(dataspace);
+  layer_properties.sample_range = Hwc2ToSampleRange(dataspace);
+  ilayer->SetLayerProperties(layer_properties);
+  return 0;
+}
+
+static int32_t SetCursorPosition(hwc2_device_t * /*device*/,
+                                 hwc2_display_t /*display*/,
+                                 hwc2_layer_t /*layer*/, int32_t /*x*/,
+                                 int32_t /*y*/) {
+  ALOGV("SetCursorPosition");
+  return 0;
+}
+
+static int32_t SetLayerColor(hwc2_device_t * /*device*/,
+                             hwc2_display_t /*display*/, hwc2_layer_t /*layer*/,
+                             hwc_color_t /*color*/) {
+  ALOGV("SetLayerColor");
+  return 0;
+}
+
+static int32_t SetLayerCompositionType(hwc2_device_t *device,
+                                       hwc2_display_t display,
+                                       hwc2_layer_t layer,
+                                       int32_t /*hwc2_composition_t*/ type) {
+  ALOGV("SetLayerCompositionType");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+  GET_LAYER(layer);
+
+  HwcLayer::LayerProperties layer_properties;
+  layer_properties.composition_type = static_cast<HWC2::Composition>(type);
+  ilayer->SetLayerProperties(layer_properties);
+
+  return 0;
+}
+
+static int32_t SetLayerDisplayFrame(hwc2_device_t *device,
+                                    hwc2_display_t display, hwc2_layer_t layer,
+                                    hwc_rect_t frame) {
+  ALOGV("SetLayerDisplayFrame");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+  GET_LAYER(layer);
+
+  HwcLayer::LayerProperties layer_properties;
+  layer_properties.display_frame = {
+      .i_rect = DstRectInfo::IRect{.left = frame.left,
+                                   .top = frame.top,
+                                   .right = frame.right,
+                                   .bottom = frame.bottom}};
+  ilayer->SetLayerProperties(layer_properties);
+
+  return 0;
+}
+
+static int32_t SetLayerPlaneAlpha(hwc2_device_t *device, hwc2_display_t display,
+                                  hwc2_layer_t layer, float alpha) {
+  ALOGV("SetLayerPlaneAlpha");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+  GET_LAYER(layer);
+
+  HwcLayer::LayerProperties layer_properties;
+  layer_properties.alpha = alpha;
+  ilayer->SetLayerProperties(layer_properties);
+
+  return 0;
+}
+
+static int32_t SetLayerSidebandStream(hwc2_device_t * /*device*/,
+                                      hwc2_display_t /*display*/,
+                                      hwc2_layer_t /*layer*/,
+                                      const native_handle_t * /*stream*/) {
+  ALOGV("SetLayerSidebandStream");
+  return static_cast<int32_t>(HWC2::Error::Unsupported);
+}
+
+static int32_t SetLayerSourceCrop(hwc2_device_t *device, hwc2_display_t display,
+                                  hwc2_layer_t layer, hwc_frect_t crop) {
+  ALOGV("SetLayerSourceCrop");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+  GET_LAYER(layer);
+
+  HwcLayer::LayerProperties layer_properties;
+  layer_properties.source_crop = {
+      .f_rect = SrcRectInfo::FRect{.left = crop.left,
+                                   .top = crop.top,
+                                   .right = crop.right,
+                                   .bottom = crop.bottom}};
+  ilayer->SetLayerProperties(layer_properties);
+
+  return 0;
+}
+
+static int32_t SetLayerSurfaceDamage(hwc2_device_t * /*device*/,
+                                     hwc2_display_t /*display*/,
+                                     hwc2_layer_t /*layer*/,
+                                     hwc_region_t /*damage*/) {
+  ALOGV("SetLayerSurfaceDamage");
+  return 0;
+}
+
+static int32_t SetLayerTransform(hwc2_device_t *device, hwc2_display_t display,
+                                 hwc2_layer_t layer, int32_t transform) {
+  ALOGV("SetLayerTransform");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+  GET_LAYER(layer);
+
+  HwcLayer::LayerProperties layer_properties;
+  layer_properties.transform = {
+      .hflip = (transform & HAL_TRANSFORM_FLIP_H) != 0,
+      .vflip = (transform & HAL_TRANSFORM_FLIP_V) != 0,
+      .rotate90 = (transform & HAL_TRANSFORM_ROT_90) != 0,
+  };
+  ilayer->SetLayerProperties(layer_properties);
+
+  return 0;
+}
+
+static int32_t SetLayerVisibleRegion(hwc2_device_t * /*device*/,
+                                     hwc2_display_t /*display*/,
+                                     hwc2_layer_t /*layer*/,
+                                     hwc_region_t /*visible*/) {
+  ALOGV("SetLayerVisibleRegion");
+  return 0;
+}
+
+static int32_t SetLayerZOrder(hwc2_device_t *device, hwc2_display_t display,
+                              hwc2_layer_t layer, uint32_t z) {
+  ALOGV("SetLayerZOrder");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+  GET_LAYER(layer);
+
+  HwcLayer::LayerProperties layer_properties;
+  layer_properties.z_order = z;
+  ilayer->SetLayerProperties(layer_properties);
+
+  return 0;
+}
+
+/* Entry point for the HWC2 API */
+// NOLINTBEGIN(cppcoreguidelines-pro-type-cstyle-cast)
+
 static hwc2_function_pointer_t HookDevGetFunction(struct hwc2_device * /*dev*/,
                                                   int32_t descriptor) {
   auto func = static_cast<HWC2::FunctionDescriptor>(descriptor);
@@ -141,31 +794,19 @@ static hwc2_function_pointer_t HookDevGetFunction(struct hwc2_device * /*dev*/,
 
     // Display functions
     case HWC2::FunctionDescriptor::AcceptDisplayChanges:
-      return ToHook<HWC2_PFN_ACCEPT_DISPLAY_CHANGES>(
-          DisplayHook<decltype(&HwcDisplay::AcceptDisplayChanges),
-                      &HwcDisplay::AcceptDisplayChanges>);
+      return (hwc2_function_pointer_t)AcceptDisplayChanges;
     case HWC2::FunctionDescriptor::CreateLayer:
-      return ToHook<HWC2_PFN_CREATE_LAYER>(
-          DisplayHook<decltype(&HwcDisplay::CreateLayer),
-                      &HwcDisplay::CreateLayer, hwc2_layer_t *>);
+      return (hwc2_function_pointer_t)CreateLayer;
     case HWC2::FunctionDescriptor::DestroyLayer:
-      return ToHook<HWC2_PFN_DESTROY_LAYER>(
-          DisplayHook<decltype(&HwcDisplay::DestroyLayer),
-                      &HwcDisplay::DestroyLayer, hwc2_layer_t>);
+      return (hwc2_function_pointer_t)DestroyLayer;
     case HWC2::FunctionDescriptor::GetActiveConfig:
       return ToHook<HWC2_PFN_GET_ACTIVE_CONFIG>(
           DisplayHook<decltype(&HwcDisplay::GetActiveConfig),
                       &HwcDisplay::GetActiveConfig, hwc2_config_t *>);
     case HWC2::FunctionDescriptor::GetChangedCompositionTypes:
-      return ToHook<HWC2_PFN_GET_CHANGED_COMPOSITION_TYPES>(
-          DisplayHook<decltype(&HwcDisplay::GetChangedCompositionTypes),
-                      &HwcDisplay::GetChangedCompositionTypes, uint32_t *,
-                      hwc2_layer_t *, int32_t *>);
+      return (hwc2_function_pointer_t)GetChangedCompositionTypes;
     case HWC2::FunctionDescriptor::GetClientTargetSupport:
-      return ToHook<HWC2_PFN_GET_CLIENT_TARGET_SUPPORT>(
-          DisplayHook<decltype(&HwcDisplay::GetClientTargetSupport),
-                      &HwcDisplay::GetClientTargetSupport, uint32_t, uint32_t,
-                      int32_t, int32_t>);
+      return (hwc2_function_pointer_t)GetClientTargetSupport;
     case HWC2::FunctionDescriptor::GetColorModes:
       return ToHook<HWC2_PFN_GET_COLOR_MODES>(
           DisplayHook<decltype(&HwcDisplay::GetColorModes),
@@ -185,41 +826,28 @@ static hwc2_function_pointer_t HookDevGetFunction(struct hwc2_device * /*dev*/,
           DisplayHook<decltype(&HwcDisplay::GetDisplayName),
                       &HwcDisplay::GetDisplayName, uint32_t *, char *>);
     case HWC2::FunctionDescriptor::GetDisplayRequests:
-      return ToHook<HWC2_PFN_GET_DISPLAY_REQUESTS>(
-          DisplayHook<decltype(&HwcDisplay::GetDisplayRequests),
-                      &HwcDisplay::GetDisplayRequests, int32_t *, uint32_t *,
-                      hwc2_layer_t *, int32_t *>);
+      return (hwc2_function_pointer_t)GetDisplayRequests;
     case HWC2::FunctionDescriptor::GetDisplayType:
       return ToHook<HWC2_PFN_GET_DISPLAY_TYPE>(
           DisplayHook<decltype(&HwcDisplay::GetDisplayType),
                       &HwcDisplay::GetDisplayType, int32_t *>);
     case HWC2::FunctionDescriptor::GetDozeSupport:
-      return ToHook<HWC2_PFN_GET_DOZE_SUPPORT>(
-          DisplayHook<decltype(&HwcDisplay::GetDozeSupport),
-                      &HwcDisplay::GetDozeSupport, int32_t *>);
+      return (hwc2_function_pointer_t)GetDozeSupport;
     case HWC2::FunctionDescriptor::GetHdrCapabilities:
       return ToHook<HWC2_PFN_GET_HDR_CAPABILITIES>(
           DisplayHook<decltype(&HwcDisplay::GetHdrCapabilities),
                       &HwcDisplay::GetHdrCapabilities, uint32_t *, int32_t *,
                       float *, float *, float *>);
     case HWC2::FunctionDescriptor::GetReleaseFences:
-      return ToHook<HWC2_PFN_GET_RELEASE_FENCES>(
-          DisplayHook<decltype(&HwcDisplay::GetReleaseFences),
-                      &HwcDisplay::GetReleaseFences, uint32_t *, hwc2_layer_t *,
-                      int32_t *>);
+      return (hwc2_function_pointer_t)GetReleaseFences;
     case HWC2::FunctionDescriptor::PresentDisplay:
-      return ToHook<HWC2_PFN_PRESENT_DISPLAY>(
-          DisplayHook<decltype(&HwcDisplay::PresentDisplay),
-                      &HwcDisplay::PresentDisplay, int32_t *>);
+      return (hwc2_function_pointer_t)PresentDisplay;
     case HWC2::FunctionDescriptor::SetActiveConfig:
       return ToHook<HWC2_PFN_SET_ACTIVE_CONFIG>(
           DisplayHook<decltype(&HwcDisplay::SetActiveConfig),
                       &HwcDisplay::SetActiveConfig, hwc2_config_t>);
     case HWC2::FunctionDescriptor::SetClientTarget:
-      return ToHook<HWC2_PFN_SET_CLIENT_TARGET>(
-          DisplayHook<decltype(&HwcDisplay::SetClientTarget),
-                      &HwcDisplay::SetClientTarget, buffer_handle_t, int32_t,
-                      int32_t, hwc_region_t>);
+      return (hwc2_function_pointer_t)SetClientTarget;
     case HWC2::FunctionDescriptor::SetColorMode:
       return ToHook<HWC2_PFN_SET_COLOR_MODE>(
           DisplayHook<decltype(&HwcDisplay::SetColorMode),
@@ -229,9 +857,7 @@ static hwc2_function_pointer_t HookDevGetFunction(struct hwc2_device * /*dev*/,
           DisplayHook<decltype(&HwcDisplay::SetColorTransform),
                       &HwcDisplay::SetColorTransform, const float *, int32_t>);
     case HWC2::FunctionDescriptor::SetOutputBuffer:
-      return ToHook<HWC2_PFN_SET_OUTPUT_BUFFER>(
-          DisplayHook<decltype(&HwcDisplay::SetOutputBuffer),
-                      &HwcDisplay::SetOutputBuffer, buffer_handle_t, int32_t>);
+      return (hwc2_function_pointer_t)SetOutputBuffer;
     case HWC2::FunctionDescriptor::SetPowerMode:
       return ToHook<HWC2_PFN_SET_POWER_MODE>(
           DisplayHook<decltype(&HwcDisplay::SetPowerMode),
@@ -241,9 +867,7 @@ static hwc2_function_pointer_t HookDevGetFunction(struct hwc2_device * /*dev*/,
           DisplayHook<decltype(&HwcDisplay::SetVsyncEnabled),
                       &HwcDisplay::SetVsyncEnabled, int32_t>);
     case HWC2::FunctionDescriptor::ValidateDisplay:
-      return ToHook<HWC2_PFN_VALIDATE_DISPLAY>(
-          DisplayHook<decltype(&HwcDisplay::ValidateDisplay),
-                      &HwcDisplay::ValidateDisplay, uint32_t *, uint32_t *>);
+      return (hwc2_function_pointer_t)ValidateDisplay;
 #if __ANDROID_API__ > 27
     case HWC2::FunctionDescriptor::GetRenderIntents:
       return ToHook<HWC2_PFN_GET_RENDER_INTENTS>(
@@ -267,13 +891,9 @@ static hwc2_function_pointer_t HookDevGetFunction(struct hwc2_device * /*dev*/,
                       &HwcDisplay::GetDisplayCapabilities, uint32_t *,
                       uint32_t *>);
     case HWC2::FunctionDescriptor::GetDisplayBrightnessSupport:
-      return ToHook<HWC2_PFN_GET_DISPLAY_BRIGHTNESS_SUPPORT>(
-          DisplayHook<decltype(&HwcDisplay::GetDisplayBrightnessSupport),
-                      &HwcDisplay::GetDisplayBrightnessSupport, bool *>);
+      return (hwc2_function_pointer_t)GetDisplayBrightnessSupport;
     case HWC2::FunctionDescriptor::SetDisplayBrightness:
-      return ToHook<HWC2_PFN_SET_DISPLAY_BRIGHTNESS>(
-          DisplayHook<decltype(&HwcDisplay::SetDisplayBrightness),
-                      &HwcDisplay::SetDisplayBrightness, float>);
+      return (hwc2_function_pointer_t)SetDisplayBrightness;
 #endif /* __ANDROID_API__ > 28 */
 #if __ANDROID_API__ > 29
     case HWC2::FunctionDescriptor::GetDisplayConnectionType:
@@ -292,14 +912,9 @@ static hwc2_function_pointer_t HookDevGetFunction(struct hwc2_device * /*dev*/,
                       hwc2_config_t, hwc_vsync_period_change_constraints_t *,
                       hwc_vsync_period_change_timeline_t *>);
     case HWC2::FunctionDescriptor::SetAutoLowLatencyMode:
-      return ToHook<HWC2_PFN_SET_AUTO_LOW_LATENCY_MODE>(
-          DisplayHook<decltype(&HwcDisplay::SetAutoLowLatencyMode),
-                      &HwcDisplay::SetAutoLowLatencyMode, bool>);
+      return (hwc2_function_pointer_t)SetAutoLowLatencyMode;
     case HWC2::FunctionDescriptor::GetSupportedContentTypes:
-      return ToHook<HWC2_PFN_GET_SUPPORTED_CONTENT_TYPES>(
-          DisplayHook<decltype(&HwcDisplay::GetSupportedContentTypes),
-                      &HwcDisplay::GetSupportedContentTypes, uint32_t *,
-                      uint32_t *>);
+      return (hwc2_function_pointer_t)GetSupportedContentTypes;
     case HWC2::FunctionDescriptor::SetContentType:
       return ToHook<HWC2_PFN_SET_CONTENT_TYPE>(
           DisplayHook<decltype(&HwcDisplay::SetContentType),
@@ -307,68 +922,41 @@ static hwc2_function_pointer_t HookDevGetFunction(struct hwc2_device * /*dev*/,
 #endif
     // Layer functions
     case HWC2::FunctionDescriptor::SetCursorPosition:
-      return ToHook<HWC2_PFN_SET_CURSOR_POSITION>(
-          LayerHook<decltype(&HwcLayer::SetCursorPosition),
-                    &HwcLayer::SetCursorPosition, int32_t, int32_t>);
+      return (hwc2_function_pointer_t)SetCursorPosition;
     case HWC2::FunctionDescriptor::SetLayerBlendMode:
-      return ToHook<HWC2_PFN_SET_LAYER_BLEND_MODE>(
-          LayerHook<decltype(&HwcLayer::SetLayerBlendMode),
-                    &HwcLayer::SetLayerBlendMode, int32_t>);
+      return (hwc2_function_pointer_t)SetLayerBlendMode;
     case HWC2::FunctionDescriptor::SetLayerBuffer:
-      return ToHook<HWC2_PFN_SET_LAYER_BUFFER>(
-          LayerHook<decltype(&HwcLayer::SetLayerBuffer),
-                    &HwcLayer::SetLayerBuffer, buffer_handle_t, int32_t>);
+      return (hwc2_function_pointer_t)SetLayerBuffer;
     case HWC2::FunctionDescriptor::SetLayerColor:
-      return ToHook<HWC2_PFN_SET_LAYER_COLOR>(
-          LayerHook<decltype(&HwcLayer::SetLayerColor),
-                    &HwcLayer::SetLayerColor, hwc_color_t>);
+      return (hwc2_function_pointer_t)SetLayerColor;
     case HWC2::FunctionDescriptor::SetLayerCompositionType:
-      return ToHook<HWC2_PFN_SET_LAYER_COMPOSITION_TYPE>(
-          LayerHook<decltype(&HwcLayer::SetLayerCompositionType),
-                    &HwcLayer::SetLayerCompositionType, int32_t>);
+      return (hwc2_function_pointer_t)SetLayerCompositionType;
     case HWC2::FunctionDescriptor::SetLayerDataspace:
-      return ToHook<HWC2_PFN_SET_LAYER_DATASPACE>(
-          LayerHook<decltype(&HwcLayer::SetLayerDataspace),
-                    &HwcLayer::SetLayerDataspace, int32_t>);
+      return (hwc2_function_pointer_t)SetLayerDataspace;
     case HWC2::FunctionDescriptor::SetLayerDisplayFrame:
-      return ToHook<HWC2_PFN_SET_LAYER_DISPLAY_FRAME>(
-          LayerHook<decltype(&HwcLayer::SetLayerDisplayFrame),
-                    &HwcLayer::SetLayerDisplayFrame, hwc_rect_t>);
+      return (hwc2_function_pointer_t)SetLayerDisplayFrame;
     case HWC2::FunctionDescriptor::SetLayerPlaneAlpha:
-      return ToHook<HWC2_PFN_SET_LAYER_PLANE_ALPHA>(
-          LayerHook<decltype(&HwcLayer::SetLayerPlaneAlpha),
-                    &HwcLayer::SetLayerPlaneAlpha, float>);
+      return (hwc2_function_pointer_t)SetLayerPlaneAlpha;
     case HWC2::FunctionDescriptor::SetLayerSidebandStream:
-      return ToHook<HWC2_PFN_SET_LAYER_SIDEBAND_STREAM>(
-          LayerHook<decltype(&HwcLayer::SetLayerSidebandStream),
-                    &HwcLayer::SetLayerSidebandStream,
-                    const native_handle_t *>);
+      return (hwc2_function_pointer_t)SetLayerSidebandStream;
     case HWC2::FunctionDescriptor::SetLayerSourceCrop:
-      return ToHook<HWC2_PFN_SET_LAYER_SOURCE_CROP>(
-          LayerHook<decltype(&HwcLayer::SetLayerSourceCrop),
-                    &HwcLayer::SetLayerSourceCrop, hwc_frect_t>);
+      return (hwc2_function_pointer_t)SetLayerSourceCrop;
     case HWC2::FunctionDescriptor::SetLayerSurfaceDamage:
-      return ToHook<HWC2_PFN_SET_LAYER_SURFACE_DAMAGE>(
-          LayerHook<decltype(&HwcLayer::SetLayerSurfaceDamage),
-                    &HwcLayer::SetLayerSurfaceDamage, hwc_region_t>);
+      return (hwc2_function_pointer_t)SetLayerSurfaceDamage;
     case HWC2::FunctionDescriptor::SetLayerTransform:
-      return ToHook<HWC2_PFN_SET_LAYER_TRANSFORM>(
-          LayerHook<decltype(&HwcLayer::SetLayerTransform),
-                    &HwcLayer::SetLayerTransform, int32_t>);
+      return (hwc2_function_pointer_t)SetLayerTransform;
     case HWC2::FunctionDescriptor::SetLayerVisibleRegion:
-      return ToHook<HWC2_PFN_SET_LAYER_VISIBLE_REGION>(
-          LayerHook<decltype(&HwcLayer::SetLayerVisibleRegion),
-                    &HwcLayer::SetLayerVisibleRegion, hwc_region_t>);
+      return (hwc2_function_pointer_t)SetLayerVisibleRegion;
     case HWC2::FunctionDescriptor::SetLayerZOrder:
-      return ToHook<HWC2_PFN_SET_LAYER_Z_ORDER>(
-          LayerHook<decltype(&HwcLayer::SetLayerZOrder),
-                    &HwcLayer::SetLayerZOrder, uint32_t>);
+      return (hwc2_function_pointer_t)SetLayerZOrder;
     case HWC2::FunctionDescriptor::Invalid:
     default:
       return nullptr;
   }
 }
 
+// NOLINTEND(cppcoreguidelines-pro-type-cstyle-cast)
+
 static int HookDevOpen(const struct hw_module_t *module, const char *name,
                        struct hw_device_t **dev) {
   if (strcmp(name, HWC_HARDWARE_COMPOSER) != 0) {
diff --git a/hwc3/Composer.cpp b/hwc3/Composer.cpp
index 124380d..de875db 100644
--- a/hwc3/Composer.cpp
+++ b/hwc3/Composer.cpp
@@ -38,11 +38,13 @@ ndk::ScopedAStatus Composer::createClient(
   }
 
   auto client = ndk::SharedRefBase::make<ComposerClient>();
-  if (!client || !client->Init()) {
+  if (!client) {
     *out_client = nullptr;
     return ToBinderStatus(hwc3::Error::kNoResources);
   }
 
+  client->Init();
+
   *out_client = client;
   client_ = client;
 
@@ -77,6 +79,10 @@ ndk::ScopedAStatus Composer::getCapabilities(std::vector<Capability>* caps) {
     caps->emplace_back(Capability::PRESENT_FENCE_IS_NOT_RELIABLE);
   }
 
+#if __ANDROID_API__ >= 35
+  caps->emplace_back(Capability::LAYER_LIFECYCLE_BATCH_COMMAND);
+#endif
+
   return ndk::ScopedAStatus::ok();
 }
 
diff --git a/hwc3/ComposerClient.cpp b/hwc3/ComposerClient.cpp
index b8128f0..bc5932b 100644
--- a/hwc3/ComposerClient.cpp
+++ b/hwc3/ComposerClient.cpp
@@ -31,6 +31,7 @@
 #include <aidl/android/hardware/graphics/composer3/DisplayRequest.h>
 #include <aidl/android/hardware/graphics/composer3/IComposerClient.h>
 #include <aidl/android/hardware/graphics/composer3/Luts.h>
+#include <aidl/android/hardware/graphics/composer3/OutputType.h>
 #include <aidl/android/hardware/graphics/composer3/PowerMode.h>
 #include <aidl/android/hardware/graphics/composer3/PresentOrValidate.h>
 #include <aidl/android/hardware/graphics/composer3/RenderIntent.h>
@@ -41,6 +42,7 @@
 #include <cutils/native_handle.h>
 #include <hardware/hwcomposer2.h>
 #include <hardware/hwcomposer_defs.h>
+#include <ui/GraphicBufferMapper.h>
 
 #include "bufferinfo/BufferInfo.h"
 #include "compositor/DisplayInfo.h"
@@ -50,19 +52,25 @@
 #include "hwc3/DrmHwcThree.h"
 #include "hwc3/Utils.h"
 
+using ::android::DstRectInfo;
 using ::android::HwcDisplay;
 using ::android::HwcDisplayConfig;
 using ::android::HwcDisplayConfigs;
 using ::android::HwcLayer;
 using ::android::LayerTransform;
+using ::android::SrcRectInfo;
 
 #include "utils/log.h"
 
 namespace aidl::android::hardware::graphics::composer3::impl {
 namespace {
 
+constexpr int kCtmRows = 4;
+constexpr int kCtmColumns = 4;
+constexpr int kCtmSize = kCtmRows * kCtmColumns;
+
 // clang-format off
-constexpr std::array<float, 16> kIdentityMatrix = {
+constexpr std::array<float, kCtmSize> kIdentityMatrix = {
     1.0F, 0.0F, 0.0F, 0.0F,
     0.0F, 1.0F, 0.0F, 0.0F,
     0.0F, 0.0F, 1.0F, 0.0F,
@@ -90,12 +98,8 @@ std::optional<BufferBlendMode> AidlToBlendMode(
 }
 
 std::optional<BufferColorSpace> AidlToColorSpace(
-    const std::optional<ParcelableDataspace>& dataspace) {
-  if (!dataspace) {
-    return std::nullopt;
-  }
-
-  int32_t standard = static_cast<int32_t>(dataspace->dataspace) &
+    const common::Dataspace& dataspace) {
+  int32_t standard = static_cast<int32_t>(dataspace) &
                      static_cast<int32_t>(common::Dataspace::STANDARD_MASK);
   switch (standard) {
     case static_cast<int32_t>(common::Dataspace::STANDARD_BT709):
@@ -117,13 +121,17 @@ std::optional<BufferColorSpace> AidlToColorSpace(
   }
 }
 
-std::optional<BufferSampleRange> AidlToSampleRange(
+std::optional<BufferColorSpace> AidlToColorSpace(
     const std::optional<ParcelableDataspace>& dataspace) {
   if (!dataspace) {
     return std::nullopt;
   }
+  return AidlToColorSpace(dataspace->dataspace);
+}
 
-  int32_t sample_range = static_cast<int32_t>(dataspace->dataspace) &
+std::optional<BufferSampleRange> AidlToSampleRange(
+    const common::Dataspace& dataspace) {
+  int32_t sample_range = static_cast<int32_t>(dataspace) &
                          static_cast<int32_t>(common::Dataspace::RANGE_MASK);
   switch (sample_range) {
     case static_cast<int32_t>(common::Dataspace::RANGE_FULL):
@@ -138,6 +146,22 @@ std::optional<BufferSampleRange> AidlToSampleRange(
   }
 }
 
+std::optional<BufferSampleRange> AidlToSampleRange(
+    const std::optional<ParcelableDataspace>& dataspace) {
+  if (!dataspace) {
+    return std::nullopt;
+  }
+  return AidlToSampleRange(dataspace->dataspace);
+}
+
+std::optional<int64_t> AidlToPresentTimeNs(
+    const std::optional<ClockMonotonicTimestamp>& expected_present_time) {
+  if (!expected_present_time || expected_present_time->timestampNanos == 0) {
+    return std::nullopt;
+  }
+  return expected_present_time->timestampNanos;
+}
+
 bool IsSupportedCompositionType(
     const std::optional<ParcelableComposition> composition) {
   if (!composition) {
@@ -162,6 +186,21 @@ bool IsSupportedCompositionType(
   }
 }
 
+hwc3::Error ValidateColorTransformMatrix(
+    const std::optional<std::vector<float>>& color_transform_matrix) {
+  if (!color_transform_matrix) {
+    return hwc3::Error::kNone;
+  }
+
+  if (color_transform_matrix->size() != kCtmSize) {
+    ALOGE("Expected color transform matrix of size %d, got size %d.", kCtmSize,
+          (int)color_transform_matrix->size());
+    return hwc3::Error::kBadParameter;
+  }
+
+  return hwc3::Error::kNone;
+}
+
 bool ValidateLayerBrightness(const std::optional<LayerBrightness>& brightness) {
   if (!brightness) {
     return true;
@@ -170,6 +209,19 @@ bool ValidateLayerBrightness(const std::optional<LayerBrightness>& brightness) {
            std::isnan(brightness->brightness));
 }
 
+std::optional<std::array<float, kCtmSize>> AidlToColorTransformMatrix(
+    const std::optional<std::vector<float>>& aidl_color_transform_matrix) {
+  if (!aidl_color_transform_matrix ||
+      aidl_color_transform_matrix->size() < kCtmSize) {
+    return std::nullopt;
+  }
+
+  std::array<float, kCtmSize> color_transform_matrix = kIdentityMatrix;
+  std::copy(aidl_color_transform_matrix->begin(),
+            aidl_color_transform_matrix->end(), color_transform_matrix.begin());
+  return color_transform_matrix;
+}
+
 std::optional<HWC2::Composition> AidlToCompositionType(
     const std::optional<ParcelableComposition> composition) {
   if (!composition) {
@@ -223,40 +275,51 @@ class DisplayConfiguration {
 #endif
 
 DisplayConfiguration HwcDisplayConfigToAidlConfiguration(
-    const HwcDisplayConfigs& configs, const HwcDisplayConfig& config) {
+    int32_t width, int32_t height, const HwcDisplayConfig& config) {
   DisplayConfiguration aidl_configuration =
       {.configId = static_cast<int32_t>(config.id),
        .width = config.mode.GetRawMode().hdisplay,
        .height = config.mode.GetRawMode().vdisplay,
        .configGroup = static_cast<int32_t>(config.group_id),
-       .vsyncPeriod = config.mode.GetVSyncPeriodNs()};
+       .vsyncPeriod = config.mode.GetVSyncPeriodNs(),
+       .hdrOutputType = static_cast<OutputType>(config.output_type)};
 
-  if (configs.mm_width != 0) {
-    // ideally this should be vdisplay/mm_heigth, however mm_height
-    // comes from edid parsing and is highly unreliable. Viewing the
-    // rarity of anisotropic displays, falling back to a single value
-    // for dpi yield more correct output.
+  if (width > 0) {
     static const float kMmPerInch = 25.4;
-    float dpi = float(config.mode.GetRawMode().hdisplay) * kMmPerInch /
-                float(configs.mm_width);
-    aidl_configuration.dpi = {.x = dpi, .y = dpi};
+    float dpi_x = float(config.mode.GetRawMode().hdisplay) * kMmPerInch /
+                float(width);
+    float dpi_y = height <= 0 ? dpi_x :
+                  float(config.mode.GetRawMode().vdisplay) * kMmPerInch /
+                    float(height);
+    aidl_configuration.dpi = {.x = dpi_x, .y = dpi_y};
   }
   // TODO: Populate vrrConfig.
   return aidl_configuration;
 }
 
-std::optional<hwc_rect> AidlToRect(const std::optional<common::Rect>& rect) {
+std::optional<DstRectInfo> AidlToRect(const std::optional<common::Rect>& rect) {
   if (!rect) {
     return std::nullopt;
   }
-  return hwc_rect{rect->left, rect->top, rect->right, rect->bottom};
+  DstRectInfo dst_rec;
+  dst_rec.i_rect = {.left = rect->left,
+                    .top = rect->top,
+                    .right = rect->right,
+                    .bottom = rect->bottom};
+  return dst_rec;
 }
 
-std::optional<hwc_frect> AidlToFRect(const std::optional<common::FRect>& rect) {
+std::optional<SrcRectInfo> AidlToFRect(
+    const std::optional<common::FRect>& rect) {
   if (!rect) {
     return std::nullopt;
   }
-  return hwc_frect{rect->left, rect->top, rect->right, rect->bottom};
+  SrcRectInfo src_rect;
+  src_rect.f_rect = {.left = rect->left,
+                     .top = rect->top,
+                     .right = rect->right,
+                     .bottom = rect->bottom};
+  return src_rect;
 }
 
 std::optional<float> AidlToAlpha(const std::optional<PlaneAlpha>& alpha) {
@@ -279,66 +342,152 @@ std::optional<LayerTransform> AidlToLayerTransform(
     return std::nullopt;
   }
 
-  uint32_t transform = LayerTransform::kIdentity;
-  // 270* and 180* cannot be combined with flips. More specifically, they
-  // already contain both horizontal and vertical flips, so those fields are
-  // redundant in this case. 90* rotation can be combined with either horizontal
-  // flip or vertical flip, so treat it differently
-  if (aidl_transform->transform == common::Transform::ROT_270) {
-    transform = LayerTransform::kRotate270;
-  } else if (aidl_transform->transform == common::Transform::ROT_180) {
-    transform = LayerTransform::kRotate180;
-  } else {
-    auto aidl_transform_bits = static_cast<uint32_t>(aidl_transform->transform);
-    if ((aidl_transform_bits &
-         static_cast<uint32_t>(common::Transform::FLIP_H)) != 0)
-      transform |= LayerTransform::kFlipH;
-    if ((aidl_transform_bits &
-         static_cast<uint32_t>(common::Transform::FLIP_V)) != 0)
-      transform |= LayerTransform::kFlipV;
-    if ((aidl_transform_bits &
-         static_cast<uint32_t>(common::Transform::ROT_90)) != 0)
-      transform |= LayerTransform::kRotate90;
-  }
-  return static_cast<LayerTransform>(transform);
+  using aidl::android::hardware::graphics::common::Transform;
+
+  return (LayerTransform){
+      .hflip = (int32_t(aidl_transform->transform) &
+                int32_t(Transform::FLIP_H)) != 0,
+      .vflip = (int32_t(aidl_transform->transform) &
+                int32_t(Transform::FLIP_V)) != 0,
+      .rotate90 = (int32_t(aidl_transform->transform) &
+                   int32_t(Transform::ROT_90)) != 0,
+  };
 }
 
 }  // namespace
 
+class Hwc3BufferHandle : public PrimeFdsSharedBase {
+ public:
+  static auto Create(buffer_handle_t handle)
+      -> std::shared_ptr<Hwc3BufferHandle> {
+    auto hwc3 = std::shared_ptr<Hwc3BufferHandle>(new Hwc3BufferHandle());
+
+    auto result = ::android::GraphicBufferMapper::get()
+        .importBufferNoValidate(handle, &hwc3->imported_handle_);
+
+    if (result != ::android::NO_ERROR) {
+      ALOGE("Failed to import buffer handle: %d", result);
+      return nullptr;
+    }
+
+    return hwc3;
+  }
+
+  auto GetHandle() const -> buffer_handle_t {
+    return imported_handle_;
+  }
+
+  ~Hwc3BufferHandle() override {
+    ::android::GraphicBufferMapper::get().freeBuffer(imported_handle_);
+  }
+
+ private:
+  Hwc3BufferHandle() = default;
+  buffer_handle_t imported_handle_{};
+};
+
+class Hwc3Layer : public ::android::FrontendLayerBase {
+ public:
+  auto HandleNextBuffer(std::optional<buffer_handle_t> raw_handle,
+                        ::android::SharedFd fence_fd, int32_t slot_id)
+      -> std::optional<HwcLayer::LayerProperties> {
+    HwcLayer::LayerProperties lp;
+    if (!raw_handle && slots_.count(slot_id) != 0) {
+      lp.active_slot = {
+          .slot_id = slot_id,
+          .fence = std::move(fence_fd),
+      };
+
+      return lp;
+    }
+
+    if (!raw_handle) {
+      ALOGE("Buffer handle is nullopt but slot was not cached.");
+      return std::nullopt;
+    }
+
+    auto hwc3 = Hwc3BufferHandle::Create(*raw_handle);
+    if (!hwc3) {
+      return std::nullopt;
+    }
+
+    auto bi = ::android::BufferInfoGetter::GetInstance()->GetBoInfo(
+        hwc3->GetHandle());
+    if (bi) {
+      bi->fds_shared = hwc3;
+
+      lp.slot_buffer = {
+          .slot_id = slot_id,
+          .bi = bi,
+      };
+    }
+
+    lp.active_slot = {
+        .slot_id = slot_id,
+        .fence = std::move(fence_fd),
+    };
+
+    slots_[slot_id] = hwc3;
+
+    return lp;
+  }
+
+  [[maybe_unused]]
+  auto HandleClearSlot(int32_t slot_id)
+      -> std::optional<HwcLayer::LayerProperties> {
+    if (slots_.count(slot_id) == 0) {
+      return std::nullopt;
+    }
+
+    slots_.erase(slot_id);
+
+    auto lp = HwcLayer::LayerProperties{};
+    lp.slot_buffer = {
+        .slot_id = slot_id,
+        .bi = std::nullopt,
+    };
+
+    return lp;
+  }
+
+  void ClearSlots() {
+    slots_.clear();
+  }
+
+ private:
+  std::map<int32_t /*slot*/, std::shared_ptr<Hwc3BufferHandle>> slots_;
+};
+
+static auto GetHwc3Layer(HwcLayer& layer) -> std::shared_ptr<Hwc3Layer> {
+  auto frontend_private_data = layer.GetFrontendPrivateData();
+  if (!frontend_private_data) {
+    frontend_private_data = std::make_shared<Hwc3Layer>();
+    layer.SetFrontendPrivateData(frontend_private_data);
+  }
+  return std::static_pointer_cast<Hwc3Layer>(frontend_private_data);
+}
+
 ComposerClient::ComposerClient() {
   DEBUG_FUNC();
 }
 
-bool ComposerClient::Init() {
+void ComposerClient::Init() {
   DEBUG_FUNC();
-  composer_resources_ = ComposerResources::Create();
-  if (composer_resources_) {
-    hwc_ = std::make_unique<DrmHwcThree>(composer_resources_.get());
-  }
-  return composer_resources_ != nullptr;
+  hwc_ = std::make_unique<DrmHwcThree>();
 }
 
 ComposerClient::~ComposerClient() {
   DEBUG_FUNC();
-  {
-    // First Deinit the displays to start shutting down the Display's dependent
-    // threads such as VSyncWorker.
+  if (hwc_) {
     const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
     hwc_->DeinitDisplays();
-  }
-  // Sleep to wait for threads to complete and exit.
-  const int time_for_threads_to_exit_us = 200000;
-  usleep(time_for_threads_to_exit_us);
-  {
-    // Hold the lock while destructing the hwc_ and the objects that it owns.
-    const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
     hwc_.reset();
   }
   LOG(DEBUG) << "removed composer client";
 }
 
 ndk::ScopedAStatus ComposerClient::createLayer(int64_t display_id,
-                                               int32_t buffer_slot_count,
+                                               int32_t /*buffer_slot_count*/,
                                                int64_t* layer_id) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
@@ -348,27 +497,22 @@ ndk::ScopedAStatus ComposerClient::createLayer(int64_t display_id,
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  hwc2_layer_t hwc2_layer_id = 0;
-  auto err = Hwc2toHwc3Error(display->CreateLayer(&hwc2_layer_id));
-  if (err != hwc3::Error::kNone) {
-    return ToBinderStatus(err);
-  }
+  auto hwc3display = DrmHwcThree::GetHwc3Display(*display);
 
-  const int64_t created_layer_id = Hwc2LayerToHwc3(hwc2_layer_id);
-  err = composer_resources_->AddLayer(display_id, created_layer_id,
-                                      buffer_slot_count);
-  if (err != hwc3::Error::kNone) {
-    destroyLayer(display_id, created_layer_id);
-    return ToBinderStatus(err);
+  if (!display->CreateLayer(hwc3display->next_layer_id)) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  *layer_id = created_layer_id;
+  *layer_id = hwc3display->next_layer_id;
+
+  hwc3display->next_layer_id++;
+
   return ndk::ScopedAStatus::ok();
 }
 
 ndk::ScopedAStatus ComposerClient::createVirtualDisplay(
     int32_t width, int32_t height, AidlPixelFormat format_hint,
-    int32_t output_buffer_slot_count, VirtualDisplay* out_display) {
+    int32_t /*output_buffer_slot_count*/, VirtualDisplay* out_display) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
 
@@ -382,15 +526,7 @@ ndk::ScopedAStatus ComposerClient::createVirtualDisplay(
     return ToBinderStatus(err);
   }
 
-  const int64_t created_display_id = Hwc2DisplayToHwc3(hwc2_display_id);
-  err = composer_resources_->AddVirtualDisplay(hwc2_display_id,
-                                               output_buffer_slot_count);
-  if (err != hwc3::Error::kNone) {
-    hwc_->DestroyVirtualDisplay(hwc2_display_id);
-    return ToBinderStatus(err);
-  }
-
-  out_display->display = created_display_id;
+  out_display->display = Hwc2DisplayToHwc3(hwc2_display_id);
   out_display->format = format_hint;
   return ndk::ScopedAStatus::ok();
 }
@@ -404,13 +540,11 @@ ndk::ScopedAStatus ComposerClient::destroyLayer(int64_t display_id,
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  auto err = Hwc2toHwc3Error(display->DestroyLayer(Hwc3LayerToHwc2(layer_id)));
-  if (err != hwc3::Error::kNone) {
-    return ToBinderStatus(err);
+  if (!display->DestroyLayer(layer_id)) {
+    return ToBinderStatus(hwc3::Error::kBadLayer);
   }
 
-  err = composer_resources_->RemoveLayer(display_id, layer_id);
-  return ToBinderStatus(err);
+  return ToBinderStatus(hwc3::Error::kNone);
 }
 
 ndk::ScopedAStatus ComposerClient::destroyVirtualDisplay(int64_t display_id) {
@@ -420,113 +554,6 @@ ndk::ScopedAStatus ComposerClient::destroyVirtualDisplay(int64_t display_id) {
   return ToBinderStatus(err);
 }
 
-hwc3::Error ComposerClient::ValidateDisplayInternal(
-    HwcDisplay& display, std::vector<int64_t>* out_changed_layers,
-    std::vector<Composition>* out_composition_types,
-    int32_t* out_display_request_mask,
-    std::vector<int64_t>* out_requested_layers,
-    std::vector<int32_t>* out_request_masks,
-    ClientTargetProperty* /*out_client_target_property*/,
-    DimmingStage* /*out_dimming_stage*/) {
-  DEBUG_FUNC();
-
-  uint32_t num_types = 0;
-  uint32_t num_requests = 0;
-  const HWC2::Error hwc2_error = display.ValidateDisplay(&num_types,
-                                                         &num_requests);
-
-  /* Check if display has pending changes and no errors */
-  if (hwc2_error != HWC2::Error::None &&
-      hwc2_error != HWC2::Error::HasChanges) {
-    return Hwc2toHwc3Error(hwc2_error);
-  }
-
-  hwc3::Error error = Hwc2toHwc3Error(
-      display.GetChangedCompositionTypes(&num_types, nullptr, nullptr));
-  if (error != hwc3::Error::kNone) {
-    return error;
-  }
-
-  std::vector<hwc2_layer_t> hwc_changed_layers(num_types);
-  std::vector<int32_t> hwc_composition_types(num_types);
-  error = Hwc2toHwc3Error(
-      display.GetChangedCompositionTypes(&num_types, hwc_changed_layers.data(),
-                                         hwc_composition_types.data()));
-  if (error != hwc3::Error::kNone) {
-    return error;
-  }
-
-  int32_t display_reqs = 0;
-  out_request_masks->resize(num_requests);
-  std::vector<hwc2_layer_t> hwc_requested_layers(num_requests);
-  error = Hwc2toHwc3Error(
-      display.GetDisplayRequests(&display_reqs, &num_requests,
-                                 hwc_requested_layers.data(),
-                                 out_request_masks->data()));
-  if (error != hwc3::Error::kNone) {
-    return error;
-  }
-
-  for (const auto& layer : hwc_changed_layers) {
-    out_changed_layers->emplace_back(Hwc2LayerToHwc3(layer));
-  }
-  for (const auto& type : hwc_composition_types) {
-    out_composition_types->emplace_back(Hwc2CompositionTypeToHwc3(type));
-  }
-  for (const auto& layer : hwc_requested_layers) {
-    out_requested_layers->emplace_back(Hwc2LayerToHwc3(layer));
-  }
-  *out_display_request_mask = display_reqs;
-
-  /* Client target property/dimming stage unsupported */
-  return hwc3::Error::kNone;
-}
-
-hwc3::Error ComposerClient::PresentDisplayInternal(
-    uint64_t display_id, ::android::base::unique_fd& out_display_fence,
-    std::unordered_map<int64_t, ::android::base::unique_fd>&
-        out_release_fences) {
-  DEBUG_FUNC();
-  auto* display = GetDisplay(display_id);
-  if (display == nullptr) {
-    return hwc3::Error::kBadDisplay;
-  }
-
-  if (composer_resources_->MustValidateDisplay(display_id)) {
-    return hwc3::Error::kNotValidated;
-  }
-
-  int32_t present_fence = -1;
-  auto error = Hwc2toHwc3Error(display->PresentDisplay(&present_fence));
-  if (error != hwc3::Error::kNone) {
-    return error;
-  }
-  out_display_fence.reset(present_fence);
-
-  uint32_t release_fence_count = 0;
-  error = Hwc2toHwc3Error(
-      display->GetReleaseFences(&release_fence_count, nullptr, nullptr));
-  if (error != hwc3::Error::kNone) {
-    return error;
-  }
-
-  std::vector<hwc2_layer_t> hwc_layers(release_fence_count);
-  std::vector<int32_t> hwc_fences(release_fence_count);
-  error = Hwc2toHwc3Error(display->GetReleaseFences(&release_fence_count,
-                                                    hwc_layers.data(),
-                                                    hwc_fences.data()));
-  if (error != hwc3::Error::kNone) {
-    return error;
-  }
-
-  for (size_t i = 0; i < hwc_layers.size(); i++) {
-    auto layer = Hwc2LayerToHwc3(hwc_layers[i]);
-    out_release_fences[layer] = ::android::base::unique_fd{hwc_fences[i]};
-  }
-
-  return hwc3::Error::kNone;
-}
-
 ::android::HwcDisplay* ComposerClient::GetDisplay(uint64_t display_id) {
   return hwc_->GetDisplay(display_id);
 }
@@ -539,6 +566,24 @@ void ComposerClient::DispatchLayerCommand(int64_t display_id,
     return;
   }
 
+#if __ANDROID_API__ >= 35
+  auto batch_command = command.layerLifecycleBatchCommandType;
+  if (batch_command == LayerLifecycleBatchCommandType::CREATE) {
+    if (!display->CreateLayer(command.layer)) {
+      cmd_result_writer_->AddError(hwc3::Error::kBadLayer);
+      return;
+    }
+  }
+
+  if (batch_command == LayerLifecycleBatchCommandType::DESTROY) {
+    if (!display->DestroyLayer(command.layer)) {
+      cmd_result_writer_->AddError(hwc3::Error::kBadLayer);
+    }
+
+    return;
+  }
+#endif
+
   auto* layer = display->get_layer(command.layer);
   if (layer == nullptr) {
     cmd_result_writer_->AddError(hwc3::Error::kBadLayer);
@@ -559,18 +604,44 @@ void ComposerClient::DispatchLayerCommand(int64_t display_id,
     return;
   }
 
+#if __ANDROID_API__ >= 34
+  /* https://source.android.com/docs/core/graphics/reduce-consumption */
+  if (command.bufferSlotsToClear) {
+    auto hwc3_layer = GetHwc3Layer(*layer);
+    for (const auto& slot : *command.bufferSlotsToClear) {
+      auto lp = hwc3_layer->HandleClearSlot(slot);
+      if (!lp) {
+        cmd_result_writer_->AddError(hwc3::Error::kBadLayer);
+        return;
+      }
+
+      layer->SetLayerProperties(lp.value());
+    }
+  }
+#endif
+
   HwcLayer::LayerProperties properties;
   if (command.buffer) {
-    HwcLayer::Buffer buffer;
-    auto err = ImportLayerBuffer(display_id, command.layer, *command.buffer,
-                                 &buffer.buffer_handle);
-    if (err != hwc3::Error::kNone) {
-      cmd_result_writer_->AddError(err);
+    auto hwc3_layer = GetHwc3Layer(*layer);
+    std::optional<buffer_handle_t> buffer_handle = std::nullopt;
+    if (command.buffer->handle) {
+      buffer_handle = ::android::makeFromAidl(*command.buffer->handle);
+    }
+
+    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
+    auto fence = const_cast<::ndk::ScopedFileDescriptor&>(command.buffer->fence)
+                     .release();
+
+    auto lp = hwc3_layer->HandleNextBuffer(buffer_handle,
+                                           ::android::MakeSharedFd(fence),
+                                           command.buffer->slot);
+
+    if (!lp) {
+      cmd_result_writer_->AddError(hwc3::Error::kBadLayer);
       return;
     }
-    buffer.acquire_fence = ::android::MakeSharedFd(
-        command.buffer->fence.dup().release());
-    properties.buffer.emplace(buffer);
+
+    properties = lp.value();
   }
 
   properties.blend_mode = AidlToBlendMode(command.blendMode);
@@ -606,7 +677,8 @@ void ComposerClient::DispatchLayerCommand(int64_t display_id,
 
 void ComposerClient::ExecuteDisplayCommand(const DisplayCommand& command) {
   const int64_t display_id = command.display;
-  if (hwc_->GetDisplay(display_id) == nullptr) {
+  HwcDisplay* display = hwc_->GetDisplay(display_id);
+  if (display == nullptr) {
     cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
     return;
   }
@@ -617,14 +689,22 @@ void ComposerClient::ExecuteDisplayCommand(const DisplayCommand& command) {
     return;
   }
 
+  hwc3::Error error = ValidateColorTransformMatrix(
+      command.colorTransformMatrix);
+  if (error != hwc3::Error::kNone) {
+    ALOGE("Invalid color transform matrix.");
+    cmd_result_writer_->AddError(error);
+    return;
+  }
+
   for (const auto& layer_cmd : command.layers) {
     DispatchLayerCommand(command.display, layer_cmd);
   }
 
-  if (command.colorTransformMatrix) {
-    ExecuteSetDisplayColorTransform(command.display,
-                                    *command.colorTransformMatrix);
+  if (cmd_result_writer_->HasError()) {
+    return;
   }
+
   if (command.clientTarget) {
     ExecuteSetDisplayClientTarget(command.display, *command.clientTarget);
   }
@@ -632,18 +712,74 @@ void ComposerClient::ExecuteDisplayCommand(const DisplayCommand& command) {
     ExecuteSetDisplayOutputBuffer(command.display,
                                   *command.virtualDisplayOutputBuffer);
   }
-  if (command.validateDisplay) {
-    ExecuteValidateDisplay(command.display, command.expectedPresentTime);
-  }
-  if (command.acceptDisplayChanges) {
-    ExecuteAcceptDisplayChanges(command.display);
+
+  std::optional<std::array<float, kCtmSize>> ctm = AidlToColorTransformMatrix(
+      command.colorTransformMatrix);
+  if (ctm) {
+    display->SetColorTransformMatrix(ctm.value());
   }
-  if (command.presentDisplay) {
-    ExecutePresentDisplay(command.display);
+
+  bool shall_present_now = false;
+
+  DisplayChanges changes{};
+  if (command.validateDisplay || command.presentOrValidateDisplay) {
+    std::vector<HwcDisplay::ChangedLayer>
+        changed_layers = display->ValidateStagedComposition();
+    for (auto [layer_id, composition_type] : changed_layers) {
+      changes.AddLayerCompositionChange(command.display, layer_id,
+                                        static_cast<Composition>(
+                                            composition_type));
+    }
+    cmd_result_writer_->AddChanges(changes);
+    auto hwc3_display = DrmHwcThree::GetHwc3Display(*display);
+    hwc3_display->must_validate = false;
+    hwc3_display->desired_present_time = AidlToPresentTimeNs(
+        command.expectedPresentTime);
+
+    // TODO: DisplayRequests are not implemented.
   }
+
   if (command.presentOrValidateDisplay) {
-    ExecutePresentOrValidateDisplay(command.display,
-                                    command.expectedPresentTime);
+    auto result = PresentOrValidate::Result::Validated;
+    if (!display->NeedsClientLayerUpdate() && !changes.HasAnyChanges()) {
+      ALOGV("Skipping SF roundtrip for display %" PRId64, display_id);
+      result = PresentOrValidate::Result::Presented;
+      shall_present_now = true;
+    }
+    cmd_result_writer_->AddPresentOrValidateResult(display_id, result);
+  }
+
+  if (command.acceptDisplayChanges) {
+    display->AcceptValidatedComposition();
+  }
+
+  if (command.presentDisplay || shall_present_now) {
+    auto hwc3_display = DrmHwcThree::GetHwc3Display(*display);
+    if (hwc3_display->must_validate) {
+      cmd_result_writer_->AddError(hwc3::Error::kNotValidated);
+      return;
+    }
+
+    ::android::SharedFd present_fence;
+    std::vector<HwcDisplay::ReleaseFence> release_fences;
+    bool ret = display->PresentStagedComposition(hwc3_display
+                                                     ->desired_present_time,
+                                                 present_fence, release_fences);
+
+    if (!ret) {
+      cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
+      return;
+    }
+
+    using ::android::base::unique_fd;
+    cmd_result_writer_->AddPresentFence(  //
+        display_id, unique_fd(::android::DupFd(present_fence)));
+
+    std::unordered_map<int64_t, unique_fd> hal_release_fences;
+    for (const auto& [layer_id, release_fence] : release_fences) {
+      hal_release_fences[layer_id] = unique_fd(::android::DupFd(release_fence));
+    }
+    cmd_result_writer_->AddReleaseFence(display_id, hal_release_fences);
   }
 }
 
@@ -739,9 +875,11 @@ ndk::ScopedAStatus ComposerClient::getDisplayAttribute(
     return ToBinderStatus(hwc3::Error::kBadConfig);
   }
 
-  DisplayConfiguration
-      aidl_configuration = HwcDisplayConfigToAidlConfiguration(configs,
-                                                               config->second);
+  const auto bounds = display->GetDisplayBoundsMm();
+  DisplayConfiguration aidl_configuration =
+      HwcDisplayConfigToAidlConfiguration(/*width =*/ bounds.first,
+                                          /*height =*/bounds.second,
+                                          config->second);
   // Legacy API for querying DPI uses units of dots per 1000 inches.
   static const int kLegacyDpiUnit = 1000;
   switch (attribute) {
@@ -973,8 +1111,28 @@ ndk::ScopedAStatus ComposerClient::getHdrCapabilities(int64_t display_id,
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  /* No HDR capabilities */
-  caps->types.clear();
+  uint32_t num_types = 0;
+  hwc3::Error error = Hwc2toHwc3Error(
+      display->GetHdrCapabilities(&num_types, nullptr, nullptr, nullptr,
+                                  nullptr));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  std::vector<int32_t> out_types(num_types);
+  error = Hwc2toHwc3Error(
+      display->GetHdrCapabilities(&num_types, out_types.data(),
+                                  &caps->maxLuminance,
+                                  &caps->maxAverageLuminance,
+                                  &caps->minLuminance));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  caps->types.reserve(num_types);
+  for (const auto type : out_types)
+    caps->types.emplace_back(Hwc2HdrTypeToHwc3(type));
+
   return ndk::ScopedAStatus::ok();
 }
 
@@ -1101,6 +1259,20 @@ ndk::ScopedAStatus ComposerClient::setActiveConfigWithConstraints(
                                  next_config != nullptr &&
                                  current_config->group_id ==
                                      next_config->group_id;
+  const bool same_resolution = current_config != nullptr &&
+                               next_config != nullptr &&
+                               current_config->mode.SameSize(next_config->mode);
+
+  /* Client framebuffer management:
+   * https://source.android.com/docs/core/graphics/framebuffer-mgmt
+   */
+  if (!same_resolution && !future_config) {
+    auto& client_layer = display->GetClientLayer();
+    auto hwc3_layer = GetHwc3Layer(client_layer);
+    hwc3_layer->ClearSlots();
+    client_layer.ClearSlots();
+  }
+
   // If the contraints dictate that this is to be applied in the future, it
   // must be queued. If the new config is in the same config group as the
   // current one, then queue it to reduce jank.
@@ -1127,6 +1299,8 @@ ndk::ScopedAStatus ComposerClient::setActiveConfigWithConstraints(
       return ToBinderStatus(hwc3::Error::kSeamlessNotAllowed);
     case HwcDisplay::ConfigError::kSeamlessNotPossible:
       return ToBinderStatus(hwc3::Error::kSeamlessNotPossible);
+    case HwcDisplay::ConfigError::kConfigFailed:
+      return ToBinderStatus(hwc3::Error::kConfigFailed);
     case HwcDisplay::ConfigError::kNone:
       return ndk::ScopedAStatus::ok();
   }
@@ -1151,7 +1325,7 @@ ndk::ScopedAStatus ComposerClient::getPreferredBootDisplayConfig(
 }
 
 ndk::ScopedAStatus ComposerClient::setAutoLowLatencyMode(int64_t display_id,
-                                                         bool on) {
+                                                         bool /*on*/) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
   HwcDisplay* display = GetDisplay(display_id);
@@ -1159,15 +1333,13 @@ ndk::ScopedAStatus ComposerClient::setAutoLowLatencyMode(int64_t display_id,
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  auto error = Hwc2toHwc3Error(display->SetAutoLowLatencyMode(on));
-  return ToBinderStatus(error);
+  return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
-ndk::ScopedAStatus ComposerClient::setClientTargetSlotCount(int64_t display_id,
-                                                            int32_t count) {
+ndk::ScopedAStatus ComposerClient::setClientTargetSlotCount(
+    int64_t /*display_id*/, int32_t /*count*/) {
   DEBUG_FUNC();
-  return ToBinderStatus(
-      composer_resources_->SetDisplayClientTargetCacheSize(display_id, count));
+  return ToBinderStatus(hwc3::Error::kNone);
 }
 
 ndk::ScopedAStatus ComposerClient::setColorMode(int64_t display_id,
@@ -1288,15 +1460,19 @@ ndk::ScopedAStatus ComposerClient::getDisplayConfigurations(
   }
 
   const HwcDisplayConfigs& configs = display->GetDisplayConfigs();
+  const auto bounds = display->GetDisplayBoundsMm();
   for (const auto& [id, config] : configs.hwc_configs) {
     configurations->push_back(
-        HwcDisplayConfigToAidlConfiguration(configs, config));
+        HwcDisplayConfigToAidlConfiguration(/*width =*/ bounds.first, 
+                                            /*height =*/ bounds.second,
+                                            config));
   }
   return ndk::ScopedAStatus::ok();
 }
 
 ndk::ScopedAStatus ComposerClient::notifyExpectedPresent(
-    int64_t /*display*/, const ClockMonotonicTimestamp& /*expected_present_time*/,
+    int64_t /*display*/,
+    const ClockMonotonicTimestamp& /*expected_present_time*/,
     int32_t /*frame_interval_ns*/) {
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
@@ -1332,41 +1508,6 @@ std::string ComposerClient::Dump() {
   return binder;
 }
 
-hwc3::Error ComposerClient::ImportLayerBuffer(
-    int64_t display_id, int64_t layer_id, const Buffer& buffer,
-    buffer_handle_t* out_imported_buffer) {
-  *out_imported_buffer = nullptr;
-
-  auto releaser = composer_resources_->CreateResourceReleaser(true);
-  auto err = composer_resources_->GetLayerBuffer(display_id, layer_id, buffer,
-                                                 out_imported_buffer,
-                                                 releaser.get());
-  return err;
-}
-
-void ComposerClient::ExecuteSetDisplayColorTransform(
-    uint64_t display_id, const std::vector<float>& matrix) {
-  auto* display = GetDisplay(display_id);
-  if (display == nullptr) {
-    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
-    return;
-  }
-
-  auto almost_equal = [](auto a, auto b) {
-    const float epsilon = 0.001F;
-    return std::abs(a - b) < epsilon;
-  };
-  const bool is_identity = std::equal(matrix.begin(), matrix.end(),
-                                      kIdentityMatrix.begin(), almost_equal);
-
-  const int32_t hint = is_identity ? HAL_COLOR_TRANSFORM_IDENTITY
-                                   : HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX;
-
-  auto error = Hwc2toHwc3Error(display->SetColorTransform(matrix.data(), hint));
-  if (error != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(error);
-  }
-}
 void ComposerClient::ExecuteSetDisplayClientTarget(
     uint64_t display_id, const ClientTarget& command) {
   auto* display = GetDisplay(display_id);
@@ -1375,190 +1516,71 @@ void ComposerClient::ExecuteSetDisplayClientTarget(
     return;
   }
 
-  hwc_region_t damage_regions;
-  damage_regions.numRects = command.damage.size();
+  auto& client_layer = display->GetClientLayer();
+  auto hwc3layer = GetHwc3Layer(client_layer);
 
-  std::vector<hwc_rect_t> regions(command.damage.size());
-  for (const auto& region : command.damage) {
-    regions.push_back({region.left, region.top, region.right, region.bottom});
-  }
-  damage_regions.rects = regions.data();
-
-  buffer_handle_t imported_buffer = nullptr;
-  auto buf_releaser = composer_resources_->CreateResourceReleaser(true);
-
-  auto error = composer_resources_->GetDisplayClientTarget(display_id,
-                                                           command.buffer,
-                                                           &imported_buffer,
-                                                           buf_releaser.get());
-  if (error != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(error);
-    return;
+  std::optional<buffer_handle_t> raw_buffer = std::nullopt;
+  if (command.buffer.handle) {
+    raw_buffer = ::android::makeFromAidl(*command.buffer.handle);
   }
 
   // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
   auto fence = const_cast<::ndk::ScopedFileDescriptor&>(command.buffer.fence)
                    .release();
-  error = Hwc2toHwc3Error(
-      display->SetClientTarget(imported_buffer, fence,
-                               Hwc3DataspaceToHwc2(command.dataspace),
-                               damage_regions));
-  if (error != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(error);
-  }
-}
-
-void ComposerClient::ExecuteSetDisplayOutputBuffer(uint64_t display_id,
-                                                   const Buffer& buffer) {
-  auto* display = GetDisplay(display_id);
-  if (display == nullptr) {
-    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
-    return;
-  }
 
-  buffer_handle_t imported_buffer = nullptr;
-  auto buf_releaser = composer_resources_->CreateResourceReleaser(true);
+  auto properties = hwc3layer->HandleNextBuffer(raw_buffer,
+                                                ::android::MakeSharedFd(fence),
+                                                command.buffer.slot);
 
-  auto error = composer_resources_->GetDisplayOutputBuffer(display_id, buffer,
-                                                           &imported_buffer,
-                                                           buf_releaser.get());
-  if (error != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(error);
+  if (!properties) {
+    ALOGE("Failed to import client target buffer.");
+    /* Here, sending an error would be the natural way to do the thing.
+     * But VTS checks for no error. Is it the VTS issue?
+     * https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/graphics/composer/aidl/vts/VtsHalGraphicsComposer3_TargetTest.cpp;l=1892;drc=2647200f4c535ca6567b452695b7d13f2aaf3f2a
+     */
     return;
   }
 
-  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
-  auto fence = const_cast<::ndk::ScopedFileDescriptor&>(buffer.fence).release();
-  error = Hwc2toHwc3Error(display->SetOutputBuffer(imported_buffer, fence));
-  if (error != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(error);
-    return;
-  }
-}
-void ComposerClient::ExecuteValidateDisplay(
-    int64_t display_id,
-    std::optional<ClockMonotonicTimestamp> /*expected_present_time*/
-) {
-  auto* display = GetDisplay(display_id);
-  if (display == nullptr) {
-    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
-    return;
-  }
-
-  /* TODO: Handle expectedPresentTime */
-  /* This can be implemented in multiple ways. For example, the expected present
-   * time property can be implemented by the DRM driver directly as a CRTC
-   * property. See:
-   * https://cs.android.com/android/platform/superproject/main/+/b8b3b1646e64d0235f77b9e717a3e4082e26f2a8:hardware/google/graphics/common/libhwc2.1/libdrmresource/drm/drmcrtc.cpp;drc=468f6172546ab98983de18210222f231f16b21e1;l=88
-   * Unfortunately there doesn't seem to be a standardised way of delaying
-   * presentation with a timestamp in the DRM API. What we can do alternatively
-   * is to spawn a separate presentation thread that could handle the VBlank
-   * events by using DRM_MODE_PAGE_FLIP_EVENT and schedule them appropriately.
-   */
+  properties->color_space = AidlToColorSpace(command.dataspace);
+  properties->sample_range = AidlToSampleRange(command.dataspace);
 
-  std::vector<int64_t> changed_layers;
-  std::vector<Composition> composition_types;
-  int32_t display_request_mask = 0;
-  std::vector<int64_t> requested_layers;
-  std::vector<int32_t> request_masks;
-
-  const hwc3::Error error = ValidateDisplayInternal(*display, &changed_layers,
-                                                    &composition_types,
-                                                    &display_request_mask,
-                                                    &requested_layers,
-                                                    &request_masks, nullptr,
-                                                    nullptr);
-
-  if (error != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(error);
-  }
-
-  // If a CommandError has been been set for the current DisplayCommand, then
-  // no other results should be returned besides the error.
-  if (cmd_result_writer_->HasError()) {
-    return;
-  }
-
-  DisplayChanges changes{};
-  for (size_t i = 0; i < composition_types.size(); i++) {
-    changes.AddLayerCompositionChange(display_id, changed_layers[i],
-                                      composition_types[i]);
-  }
-
-  std::vector<DisplayRequest::LayerRequest> layer_requests;
-  for (size_t i = 0; i < requested_layers.size(); i++) {
-    layer_requests.push_back({requested_layers[i], request_masks[i]});
-  }
-
-  const DisplayRequest request_changes{display_id, display_request_mask,
-                                       layer_requests};
-  changes.display_request_changes = request_changes;
-
-  cmd_result_writer_->AddChanges(changes);
-  composer_resources_->SetDisplayMustValidateState(display_id, false);
+  client_layer.SetLayerProperties(properties.value());
 }
 
-void ComposerClient::ExecuteAcceptDisplayChanges(int64_t display_id) {
+void ComposerClient::ExecuteSetDisplayOutputBuffer(uint64_t display_id,
+                                                   const Buffer& buffer) {
   auto* display = GetDisplay(display_id);
   if (display == nullptr) {
     cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
     return;
   }
 
-  auto error = Hwc2toHwc3Error(display->AcceptDisplayChanges());
-  if (error != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(error);
+  auto& writeback_layer = display->GetWritebackLayer();
+  if (!writeback_layer) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadLayer);
     return;
   }
-}
 
-void ComposerClient::ExecutePresentDisplay(int64_t display_id) {
-  auto* display = GetDisplay(display_id);
-  if (display == nullptr) {
-    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
-    return;
-  }
+  auto hwc3layer = GetHwc3Layer(*writeback_layer);
 
-  ::android::base::unique_fd display_fence;
-  std::unordered_map<int64_t, ::android::base::unique_fd> release_fences;
-  auto error = PresentDisplayInternal(display_id, display_fence,
-                                      release_fences);
-  if (error != hwc3::Error::kNone) {
-    cmd_result_writer_->AddError(error);
-  }
-  if (cmd_result_writer_->HasError()) {
-    return;
+  std::optional<buffer_handle_t> raw_buffer = std::nullopt;
+  if (buffer.handle) {
+    raw_buffer = ::android::makeFromAidl(*buffer.handle);
   }
 
-  cmd_result_writer_->AddPresentFence(display_id, std::move(display_fence));
-  cmd_result_writer_->AddReleaseFence(display_id, release_fences);
-}
+  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
+  auto fence = const_cast<::ndk::ScopedFileDescriptor&>(buffer.fence).release();
 
-void ComposerClient::ExecutePresentOrValidateDisplay(
-    int64_t display_id,
-    std::optional<ClockMonotonicTimestamp> expected_present_time) {
-  auto* display = GetDisplay(display_id);
-  if (display == nullptr) {
-    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
+  auto properties = hwc3layer->HandleNextBuffer(raw_buffer,
+                                                ::android::MakeSharedFd(fence),
+                                                buffer.slot);
+
+  if (!properties) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadLayer);
     return;
   }
 
-  /* TODO: Handle expectedPresentTime */
-  /* This can be implemented in multiple ways. For example, the expected present
-   * time property can be implemented by the DRM driver directly as a CRTC
-   * property. See:
-   * https://cs.android.com/android/platform/superproject/main/+/b8b3b1646e64d0235f77b9e717a3e4082e26f2a8:hardware/google/graphics/common/libhwc2.1/libdrmresource/drm/drmcrtc.cpp;drc=468f6172546ab98983de18210222f231f16b21e1;l=88
-   * Unfortunately there doesn't seem to be a standardised way of delaying
-   * presentation with a timestamp in the DRM API. What we can do alternatively
-   * is to spawn a separate presentation thread that could handle the VBlank
-   * events by using DRM_MODE_PAGE_FLIP_EVENT and schedule them appropriately.
-   */
-
-  /* TODO: Add check if it's possible to skip display validation */
-  ExecuteValidateDisplay(display_id, expected_present_time);
-  cmd_result_writer_
-      ->AddPresentOrValidateResult(display_id,
-                                   PresentOrValidate::Result::Validated);
+  writeback_layer->SetLayerProperties(properties.value());
 }
 
 }  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hwc3/ComposerClient.h b/hwc3/ComposerClient.h
index 2595203..ed47cd6 100644
--- a/hwc3/ComposerClient.h
+++ b/hwc3/ComposerClient.h
@@ -20,8 +20,8 @@
 
 #include "aidl/android/hardware/graphics/composer3/BnComposerClient.h"
 #include "aidl/android/hardware/graphics/composer3/LayerCommand.h"
+#include "hwc2_device/HwcLayer.h"
 #include "hwc3/CommandResultWriter.h"
-#include "hwc3/ComposerResources.h"
 #include "hwc3/Utils.h"
 #include "utils/Mutex.h"
 
@@ -30,10 +30,7 @@ using AidlPixelFormat = aidl::android::hardware::graphics::common::PixelFormat;
 using AidlNativeHandle = aidl::android::hardware::common::NativeHandle;
 
 namespace android {
-
 class HwcDisplay;
-class HwcLayer;
-
 }  // namespace android
 
 namespace aidl::android::hardware::graphics::composer3::impl {
@@ -45,7 +42,7 @@ class ComposerClient : public BnComposerClient {
   ComposerClient();
   ~ComposerClient() override;
 
-  bool Init();
+  void Init();
   std::string Dump();
 
   // composer3 interface
@@ -171,48 +168,21 @@ class ComposerClient : public BnComposerClient {
  private:
   hwc3::Error ImportLayerBuffer(int64_t display_id, int64_t layer_id,
                                 const Buffer& buffer,
-                                buffer_handle_t* out_imported_buffer);
+                                ::android::HwcLayer::Buffer* out_buffer);
 
   // Layer commands
   void DispatchLayerCommand(int64_t display_id, const LayerCommand& command);
 
   // Display commands
   void ExecuteDisplayCommand(const DisplayCommand& command);
-  void ExecuteSetDisplayColorTransform(uint64_t display_id,
-                                       const std::vector<float>& matrix);
   void ExecuteSetDisplayClientTarget(uint64_t display_id,
                                      const ClientTarget& command);
   void ExecuteSetDisplayOutputBuffer(uint64_t display_id, const Buffer& buffer);
-  void ExecuteValidateDisplay(
-      int64_t display_id,
-      std::optional<ClockMonotonicTimestamp> expected_present_time);
-  void ExecuteAcceptDisplayChanges(int64_t display_id);
-  void ExecutePresentDisplay(int64_t display_id);
-  void ExecutePresentOrValidateDisplay(
-      int64_t display_id,
-      std::optional<ClockMonotonicTimestamp> expected_present_time);
-
-  static hwc3::Error ValidateDisplayInternal(
-      ::android::HwcDisplay& display, std::vector<int64_t>* out_changed_layers,
-      std::vector<Composition>* out_composition_types,
-      int32_t* out_display_request_mask,
-      std::vector<int64_t>* out_requested_layers,
-      std::vector<int32_t>* out_request_masks,
-      ClientTargetProperty* out_client_target_property,
-      DimmingStage* out_dimming_stage);
-
-  hwc3::Error PresentDisplayInternal(
-      uint64_t display_id, ::android::base::unique_fd& out_display_fence,
-      std::unordered_map<int64_t, ::android::base::unique_fd>&
-          out_release_fences);
 
   ::android::HwcDisplay* GetDisplay(uint64_t display_id);
 
   std::unique_ptr<CommandResultWriter> cmd_result_writer_;
 
-  // Manages importing and caching gralloc buffers for displays and layers.
-  std::unique_ptr<ComposerResources> composer_resources_;
-
   std::unique_ptr<DrmHwcThree> hwc_;
 };
 
diff --git a/hwc3/ComposerResources.cpp b/hwc3/ComposerResources.cpp
deleted file mode 100644
index ae0edf4..0000000
--- a/hwc3/ComposerResources.cpp
+++ /dev/null
@@ -1,202 +0,0 @@
-
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
-#define LOG_TAG "drmhwc"
-#define ATRACE_TAG (ATRACE_TAG_GRAPHICS | ATRACE_TAG_HAL)
-
-#include "ComposerResources.h"
-
-#include <aidlcommonsupport/NativeHandle.h>
-
-#include "hardware/hwcomposer2.h"
-#include "hwc3/Utils.h"
-
-namespace aidl::android::hardware::graphics::composer3::impl {
-
-::android::hardware::graphics::composer::V2_1::Display ToHwc2Display(
-    uint64_t display_id) {
-  return static_cast<::android::hardware::graphics::composer::V2_1::Display>(
-      display_id);
-}
-
-::android::hardware::graphics::composer::V2_1::Layer ToHwc2Layer(
-    int64_t layer_id) {
-  return static_cast<::android::hardware::graphics::composer::V2_1::Layer>(
-      layer_id);
-}
-
-std::unique_ptr<ComposerResourceReleaser>
-ComposerResources::CreateResourceReleaser(bool is_buffer) {
-  return std::make_unique<ComposerResourceReleaser>(is_buffer);
-}
-
-std::unique_ptr<ComposerResources> ComposerResources::Create() {
-  auto instance = std::unique_ptr<ComposerResources>(new ComposerResources);
-  if (instance->resources_ == nullptr) {
-    ALOGE("%s: Failed to initialise ComposerResources", __func__);
-    return nullptr;
-  }
-
-  return instance;
-}
-
-hwc3::Error ComposerResources::GetLayerBuffer(
-    uint64_t display_id, int64_t layer_id, const Buffer& buffer,
-    buffer_handle_t* out_buffer_handle,
-    ComposerResourceReleaser* buf_releaser) {
-  auto display = ToHwc2Display(display_id);
-  auto layer = ToHwc2Layer(layer_id);
-
-  const bool use_cache = !buffer.handle.has_value();
-  buffer_handle_t buffer_handle = nullptr;
-  if (buffer.handle.has_value()) {
-    buffer_handle = ::android::makeFromAidl(*buffer.handle);
-  }
-
-  auto err = resources_->getLayerBuffer(display, layer, buffer.slot, use_cache,
-                                        buffer_handle, out_buffer_handle,
-                                        buf_releaser->GetReplacedHandle());
-
-  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
-}
-
-hwc3::Error ComposerResources::GetLayerSidebandStream(
-    uint64_t display_id, int64_t layer_id,
-    const aidl::android::hardware::common::NativeHandle& handle,
-    buffer_handle_t* out_handle, ComposerResourceReleaser* releaser) {
-  auto display = ToHwc2Display(display_id);
-  auto layer = ToHwc2Layer(layer_id);
-
-  auto err = resources_->getLayerSidebandStream(display, layer,
-                                                ::android::makeFromAidl(handle),
-                                                out_handle,
-                                                releaser->GetReplacedHandle());
-
-  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
-}
-
-hwc3::Error ComposerResources::AddLayer(uint64_t display_id, int64_t layer_id,
-                                        uint32_t buffer_cache_size) {
-  auto display = ToHwc2Display(display_id);
-  auto layer = ToHwc2Layer(layer_id);
-
-  auto err = resources_->addLayer(display, layer, buffer_cache_size);
-  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
-}
-
-hwc3::Error ComposerResources::RemoveLayer(uint64_t display_id,
-                                           int64_t layer_id) {
-  auto display = ToHwc2Display(display_id);
-  auto layer = ToHwc2Layer(layer_id);
-
-  auto err = resources_->removeLayer(display, layer);
-  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
-}
-
-bool ComposerResources::HasDisplay(uint64_t display_id) {
-  auto display = ToHwc2Display(display_id);
-  return resources_->hasDisplay(display);
-}
-
-hwc3::Error ComposerResources::AddPhysicalDisplay(uint64_t display_id) {
-  auto display = ToHwc2Display(display_id);
-  auto err = resources_->addPhysicalDisplay(display);
-  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
-}
-
-hwc3::Error ComposerResources::AddVirtualDisplay(
-    uint64_t display, uint32_t output_buffer_cache_size) {
-  auto err = resources_->addVirtualDisplay(display, output_buffer_cache_size);
-  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
-}
-
-hwc3::Error ComposerResources::RemoveDisplay(uint64_t display_id) {
-  auto display = ToHwc2Display(display_id);
-  auto err = resources_->removeDisplay(display);
-  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
-}
-
-void ComposerResources::SetDisplayMustValidateState(uint64_t display_id,
-                                                    bool must_validate) {
-  auto display = ToHwc2Display(display_id);
-  resources_->setDisplayMustValidateState(display, must_validate);
-}
-
-bool ComposerResources::MustValidateDisplay(uint64_t display_id) {
-  auto display = ToHwc2Display(display_id);
-  return resources_->mustValidateDisplay(display);
-}
-
-hwc3::Error ComposerResources::GetDisplayClientTarget(
-    uint64_t display_id, const Buffer& buffer, buffer_handle_t* out_handle,
-    ComposerResourceReleaser* releaser) {
-  auto display = ToHwc2Display(display_id);
-
-  const bool use_cache = !buffer.handle.has_value();
-  buffer_handle_t buffer_handle = nullptr;
-  if (buffer.handle.has_value()) {
-    buffer_handle = ::android::makeFromAidl(*buffer.handle);
-  }
-
-  auto err = resources_->getDisplayClientTarget(display, buffer.slot, use_cache,
-                                                buffer_handle, out_handle,
-                                                releaser->GetReplacedHandle());
-  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
-}
-
-hwc3::Error ComposerResources::SetDisplayClientTargetCacheSize(
-    uint64_t display_id, uint32_t client_target_cache_size) {
-  auto display = ToHwc2Display(display_id);
-  auto err = resources_
-                 ->setDisplayClientTargetCacheSize(display,
-                                                   client_target_cache_size);
-  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
-}
-
-hwc3::Error ComposerResources::GetDisplayClientTargetCacheSize(
-    uint64_t display_id, size_t* out_cache_size) {
-  auto display = ToHwc2Display(display_id);
-  auto err = resources_->getDisplayClientTargetCacheSize(display,
-                                                         out_cache_size);
-  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
-}
-
-hwc3::Error ComposerResources::GetDisplayOutputBufferCacheSize(
-    uint64_t display_id, size_t* out_cache_size) {
-  auto display = ToHwc2Display(display_id);
-  auto err = resources_->getDisplayOutputBufferCacheSize(display,
-                                                         out_cache_size);
-  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
-}
-
-hwc3::Error ComposerResources::GetDisplayOutputBuffer(
-    uint64_t display_id, const Buffer& buffer, buffer_handle_t* out_handle,
-    ComposerResourceReleaser* releaser) {
-  auto display = ToHwc2Display(display_id);
-  const bool use_cache = !buffer.handle.has_value();
-
-  buffer_handle_t buffer_handle = nullptr;
-  if (buffer.handle.has_value()) {
-    buffer_handle = ::android::makeFromAidl(*buffer.handle);
-  }
-
-  auto err = resources_->getDisplayOutputBuffer(display, buffer.slot, use_cache,
-                                                buffer_handle, out_handle,
-                                                releaser->GetReplacedHandle());
-  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
-}
-}  // namespace aidl::android::hardware::graphics::composer3::impl
\ No newline at end of file
diff --git a/hwc3/ComposerResources.h b/hwc3/ComposerResources.h
deleted file mode 100644
index 6f4eee7..0000000
--- a/hwc3/ComposerResources.h
+++ /dev/null
@@ -1,99 +0,0 @@
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
-#pragma once
-
-#include <memory>
-
-#include "aidl/android/hardware/graphics/composer3/IComposerClient.h"
-#include "composer-resources/2.2/ComposerResources.h"
-#include "cutils/native_handle.h"
-#include "hwc3/Utils.h"
-
-namespace aidl::android::hardware::graphics::composer3::impl {
-
-class ComposerResourceReleaser {
- public:
-  explicit ComposerResourceReleaser(bool is_buffer)
-      : replaced_handle_(is_buffer) {
-  }
-  virtual ~ComposerResourceReleaser() = default;
-
-  ::android::hardware::graphics::composer::V2_2::hal::ComposerResources::
-      ReplacedHandle*
-      GetReplacedHandle() {
-    return &replaced_handle_;
-  }
-
- private:
-  ::android::hardware::graphics::composer::V2_2::hal::ComposerResources::
-      ReplacedHandle replaced_handle_;
-};
-
-class ComposerResources {
- public:
-  static std::unique_ptr<ComposerResources> Create();
-  ~ComposerResources() = default;
-
-  hwc3::Error GetLayerBuffer(uint64_t display_id, int64_t layer_id,
-                             const Buffer& buffer,
-                             buffer_handle_t* out_buffer_handle,
-                             ComposerResourceReleaser* releaser);
-  hwc3::Error GetLayerSidebandStream(
-      uint64_t display_id, int64_t layer_id,
-      const aidl::android::hardware::common::NativeHandle& handle,
-      buffer_handle_t* out_handle, ComposerResourceReleaser* releaser);
-
-  hwc3::Error AddLayer(uint64_t display, int64_t layer,
-                       uint32_t buffer_cache_size);
-  hwc3::Error RemoveLayer(uint64_t display, int64_t layer);
-
-  bool HasDisplay(uint64_t display);
-  hwc3::Error AddPhysicalDisplay(uint64_t display);
-  hwc3::Error AddVirtualDisplay(uint64_t display,
-                                uint32_t output_buffer_cache_size);
-  hwc3::Error RemoveDisplay(uint64_t display);
-
-  void SetDisplayMustValidateState(uint64_t display_id, bool must_validate);
-  bool MustValidateDisplay(uint64_t display_id);
-
-  hwc3::Error GetDisplayClientTarget(uint64_t display_id, const Buffer& buffer,
-                                     buffer_handle_t* out_handle,
-                                     ComposerResourceReleaser* releaser);
-
-  hwc3::Error SetDisplayClientTargetCacheSize(
-      uint64_t display_id, uint32_t client_target_cache_size);
-  hwc3::Error GetDisplayClientTargetCacheSize(uint64_t display_id,
-                                              size_t* out_cache_size);
-  hwc3::Error GetDisplayOutputBufferCacheSize(uint64_t display,
-                                              size_t* out_cache_size);
-  hwc3::Error GetDisplayOutputBuffer(uint64_t display_id, const Buffer& buffer,
-                                     buffer_handle_t* out_handle,
-                                     ComposerResourceReleaser* releaser);
-
-  static std::unique_ptr<ComposerResourceReleaser> CreateResourceReleaser(
-      bool is_buffer);
-
- private:
-  ComposerResources() = default;
-
-  std::unique_ptr<
-      ::android::hardware::graphics::composer::V2_2::hal::ComposerResources>
-      resources_ = ::android::hardware::graphics::composer::V2_2::hal::
-          ComposerResources::create();
-};
-
-}  // namespace aidl::android::hardware::graphics::composer3::impl
\ No newline at end of file
diff --git a/hwc3/DrmHwcThree.cpp b/hwc3/DrmHwcThree.cpp
index fb14bc9..6df3022 100644
--- a/hwc3/DrmHwcThree.cpp
+++ b/hwc3/DrmHwcThree.cpp
@@ -28,7 +28,15 @@
 
 namespace aidl::android::hardware::graphics::composer3::impl {
 
-using ::android::HwcDisplay;
+auto DrmHwcThree::GetHwc3Display(::android::HwcDisplay& display)
+    -> std::shared_ptr<Hwc3Display> {
+  auto frontend_private_data = display.GetFrontendPrivateData();
+  if (!frontend_private_data) {
+    frontend_private_data = std::make_shared<Hwc3Display>();
+    display.SetFrontendPrivateData(frontend_private_data);
+  }
+  return std::static_pointer_cast<Hwc3Display>(frontend_private_data);
+}
 
 DrmHwcThree::~DrmHwcThree() {
   /* Display deinit routine is handled by resource manager */
@@ -53,7 +61,16 @@ void DrmHwcThree::SendVsyncPeriodTimingChangedEventToClient(
 }
 
 void DrmHwcThree::SendRefreshEventToClient(uint64_t display_id) {
-  composer_resources_->SetDisplayMustValidateState(display_id, true);
+  {
+    const std::unique_lock lock(GetResMan().GetMainLock());
+    auto* idisplay = GetDisplay(display_id);
+    if (idisplay == nullptr) {
+      ALOGE("Failed to get display %" PRIu64, display_id);
+      return;
+    }
+    auto hwc3_display = GetHwc3Display(*idisplay);
+    hwc3_display->must_validate = true;
+  }
   composer_callback_->onRefresh(static_cast<int64_t>(display_id));
 }
 
@@ -71,11 +88,9 @@ void DrmHwcThree::SendHotplugEventToClient(
   switch (display_status) {
     case DrmHwc::kDisconnected:
       event = common::DisplayHotplugEvent::DISCONNECTED;
-      HandleDisplayHotplugEvent(static_cast<uint64_t>(display_id), false);
       break;
     case DrmHwc::kConnected:
       event = common::DisplayHotplugEvent::CONNECTED;
-      HandleDisplayHotplugEvent(static_cast<uint64_t>(display_id), true);
       break;
     case DrmHwc::kLinkTrainingFailed:
       event = common::DisplayHotplugEvent::ERROR_INCOMPATIBLE_CABLE;
@@ -89,73 +104,9 @@ void DrmHwcThree::SendHotplugEventToClient(
 void DrmHwcThree::SendHotplugEventToClient(
     hwc2_display_t display_id, DrmHwc::DisplayStatus display_status) {
   bool connected = display_status != DrmHwc::kDisconnected;
-  HandleDisplayHotplugEvent(static_cast<uint64_t>(display_id), connected);
   composer_callback_->onHotplug(static_cast<int64_t>(display_id), connected);
 }
 
 #endif
 
-void DrmHwcThree::CleanDisplayResources(uint64_t display_id) {
-  DEBUG_FUNC();
-  HwcDisplay* display = GetDisplay(display_id);
-  if (display == nullptr) {
-    return;
-  }
-
-  display->SetPowerMode(static_cast<int32_t>(PowerMode::OFF));
-
-  size_t cache_size = 0;
-  auto err = composer_resources_->GetDisplayClientTargetCacheSize(display_id,
-                                                                  &cache_size);
-  if (err != hwc3::Error::kNone) {
-    ALOGE("%s: Could not clear target buffer cache for display: %" PRIu64,
-          __func__, display_id);
-    return;
-  }
-
-  for (size_t slot = 0; slot < cache_size; slot++) {
-    buffer_handle_t buffer_handle = nullptr;
-    auto buf_releaser = ComposerResources::CreateResourceReleaser(true);
-
-    Buffer buf{};
-    buf.slot = static_cast<int32_t>(slot);
-    err = composer_resources_->GetDisplayClientTarget(display_id, buf,
-                                                      &buffer_handle,
-                                                      buf_releaser.get());
-    if (err != hwc3::Error::kNone) {
-      continue;
-    }
-
-    err = Hwc2toHwc3Error(
-        display->SetClientTarget(buffer_handle, -1,
-                                 static_cast<int32_t>(
-                                     common::Dataspace::UNKNOWN),
-                                 {}));
-    if (err != hwc3::Error::kNone) {
-      ALOGE(
-          "%s: Could not clear slot %zu of the target buffer cache for "
-          "display %" PRIu64,
-          __func__, slot, display_id);
-    }
-  }
-}
-
-void DrmHwcThree::HandleDisplayHotplugEvent(uint64_t display_id,
-                                            bool connected) {
-  DEBUG_FUNC();
-  if (!connected) {
-    composer_resources_->RemoveDisplay(display_id);
-    Displays().erase(display_id);
-    return;
-  }
-
-  if (composer_resources_->HasDisplay(display_id)) {
-    /* Cleanup existing display resources */
-    CleanDisplayResources(display_id);
-    composer_resources_->RemoveDisplay(display_id);
-    Displays().erase(display_id);
-  }
-  composer_resources_->AddPhysicalDisplay(display_id);
-}
-
 }  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hwc3/DrmHwcThree.h b/hwc3/DrmHwcThree.h
index f020634..89bcf46 100644
--- a/hwc3/DrmHwcThree.h
+++ b/hwc3/DrmHwcThree.h
@@ -19,15 +19,23 @@
 #include <aidl/android/hardware/graphics/composer3/IComposerCallback.h>
 
 #include "drm/DrmHwc.h"
-#include "hwc3/ComposerResources.h"
+#include "hwc2_device/HwcDisplay.h"
 
 namespace aidl::android::hardware::graphics::composer3::impl {
 
+class Hwc3Display : public ::android::FrontendDisplayBase {
+ public:
+  bool must_validate = false;
+  // Desired present time for a composition that has been validated but not
+  // yet presented. nullopt means it should be presented at the next vsync.
+  std::optional<int64_t> desired_present_time = std::nullopt;
+
+  int64_t next_layer_id = 1;
+};
+
 class DrmHwcThree : public ::android::DrmHwc {
  public:
-  explicit DrmHwcThree(ComposerResources* composer_resources)
-      : composer_resources_(composer_resources) {
-  }
+  explicit DrmHwcThree() = default;
   ~DrmHwcThree() override;
 
   void Init(std::shared_ptr<IComposerCallback> callback);
@@ -41,11 +49,10 @@ class DrmHwcThree : public ::android::DrmHwc {
   void SendHotplugEventToClient(hwc2_display_t display_id,
                                 DrmHwc::DisplayStatus display_status) override;
 
- private:
-  void CleanDisplayResources(uint64_t display_id);
-  void HandleDisplayHotplugEvent(uint64_t display_id, bool connected);
+  static auto GetHwc3Display(::android::HwcDisplay& display)
+      -> std::shared_ptr<Hwc3Display>;
 
+ private:
   std::shared_ptr<IComposerCallback> composer_callback_;
-  ComposerResources* composer_resources_;
 };
 }  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hwc3/Utils.h b/hwc3/Utils.h
index b322f5d..89767c8 100644
--- a/hwc3/Utils.h
+++ b/hwc3/Utils.h
@@ -16,6 +16,7 @@
 
 #pragma once
 
+#include <aidl/android/hardware/graphics/common/Hdr.h>
 #include <aidl/android/hardware/graphics/composer3/IComposerClient.h>
 #include <hardware/hwcomposer2.h>
 #include <log/log.h>
@@ -39,6 +40,7 @@ enum class Error : int32_t {
   kUnsupported = IComposerClient::EX_UNSUPPORTED,
   kSeamlessNotAllowed = IComposerClient::EX_SEAMLESS_NOT_ALLOWED,
   kSeamlessNotPossible = IComposerClient::EX_SEAMLESS_NOT_POSSIBLE,
+  kConfigFailed = IComposerClient::EX_CONFIG_FAILED,
 };
 }  // namespace hwc3
 
@@ -56,12 +58,6 @@ inline ndk::ScopedAStatus ToBinderStatus(HWC2::Error error) {
   return ToBinderStatus(Hwc2toHwc3Error(error));
 }
 
-// ID conversion. HWC2 uses typedef'd unsigned integer types while HWC3 uses
-// signed integer types. static_cast in between these.
-inline int64_t Hwc2LayerToHwc3(hwc2_layer_t layer) {
-  return static_cast<int64_t>(layer);
-}
-
 inline int64_t Hwc2DisplayToHwc3(hwc2_display_t display) {
   return static_cast<int64_t>(display);
 }
@@ -70,10 +66,6 @@ inline int32_t Hwc2ConfigIdToHwc3(hwc2_config_t config_id) {
   return static_cast<int32_t>(config_id);
 }
 
-inline hwc2_layer_t Hwc3LayerToHwc2(int64_t layer) {
-  return static_cast<hwc2_layer_t>(layer);
-}
-
 inline hwc2_display_t Hwc3DisplayToHwc2(int64_t display) {
   return static_cast<hwc2_display_t>(display);
 }
@@ -165,4 +157,12 @@ inline int32_t Hwc3DataspaceToHwc2(common::Dataspace dataspace) {
   return static_cast<int32_t>(dataspace);
 }
 
-};  // namespace aidl::android::hardware::graphics::composer3
\ No newline at end of file
+// Values appear to match.
+// https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/graphics/common/aidl/android/hardware/graphics/common/Hdr.aidl
+// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.0.h;l=130;drc=7d940ae4afa450696afa25e07982f3a95e17e9b2
+// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.2.h;l=12;drc=af7be7616859f8e9e57710b9c37c66cf880a6643
+inline common::Hdr Hwc2HdrTypeToHwc3(int32_t hdr_type) {
+  return static_cast<common::Hdr>(hdr_type);
+}
+
+};  // namespace aidl::android::hardware::graphics::composer3
diff --git a/hwc3/meson.build b/hwc3/meson.build
index 291c71a..c525308 100644
--- a/hwc3/meson.build
+++ b/hwc3/meson.build
@@ -4,7 +4,6 @@ src_hwc3 = files(
     'Composer.cpp',
     'DrmHwcThree.cpp',
     'service.cpp',
-    'ComposerResources.cpp',
     'Utils.cpp',
 )
 
diff --git a/meson.build b/meson.build
index 8cfbbc8..3d5c9f0 100644
--- a/meson.build
+++ b/meson.build
@@ -16,6 +16,7 @@ src_common = files(
     'backend/Backend.cpp',
     'backend/BackendClient.cpp',
     'utils/fd.cpp',
+    'utils/LibdisplayEdidWrapper.cpp',
     'utils/properties.cpp',
 )
 
@@ -45,6 +46,12 @@ common_cpp_flags = [
     '-DUSE_IMAPPER4_METADATA_API',
 ]
 
+dep_libdisplay_info = dependency('display_info', required : false)
+if dep_libdisplay_info.found()
+  common_cpp_flags += '-DHAS_LIBDISPLAY_INFO'
+  deps += dep_libdisplay_info
+endif
+
 hwc2_cpp_flags = [
     '-DHWC2_INCLUDE_STRINGIFICATION',
     '-DHWC2_USE_CPP11',
diff --git a/tests/uevent_print.cpp b/tests/uevent_print.cpp
index 6ffbbfb..cfe2191 100644
--- a/tests/uevent_print.cpp
+++ b/tests/uevent_print.cpp
@@ -7,7 +7,7 @@
 int main() {
   auto uevent = android::UEvent::CreateInstance();
   if (!uevent) {
-    std::cout << "Can't initialize UEvent class" << std::endl;
+    std::cout << "Can't initialize UEvent class\n";
     return -ENODEV;
   }
 
@@ -18,8 +18,8 @@ int main() {
       continue;
     }
 
-    std::cout << "New event #" << number++ << std::endl
-              << *msg << std::endl
-              << std::endl;
+    std::cout << "New event #" << number++ << '\n'
+              << *msg << '\n'
+              << std::flush;
   }
 }
diff --git a/utils/EdidWrapper.h b/utils/EdidWrapper.h
new file mode 100644
index 0000000..651c284
--- /dev/null
+++ b/utils/EdidWrapper.h
@@ -0,0 +1,99 @@
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
+#pragma once
+
+#if HAS_LIBDISPLAY_INFO
+extern "C" {
+#include <libdisplay-info/edid.h>
+#include <libdisplay-info/info.h>
+}
+#endif
+
+#include <ui/GraphicTypes.h>
+
+#include "compositor/DisplayInfo.h"
+#include "drm/DrmUnique.h"
+
+namespace android {
+
+// Stub wrapper class for edid parsing
+class EdidWrapper {
+ public:
+  EdidWrapper() = default;
+  EdidWrapper(const EdidWrapper &) = delete;
+  virtual ~EdidWrapper() = default;
+
+  virtual void GetSupportedHdrTypes(std::vector<ui::Hdr> &types) {
+    types.clear();
+  };
+  virtual void GetHdrCapabilities(std::vector<ui::Hdr> &types,
+                                  float * /*max_luminance*/,
+                                  float * /*max_average_luminance*/,
+                                  float * /*min_luminance*/) {
+    GetSupportedHdrTypes(types);
+  };
+  virtual void GetColorModes(std::vector<Colormode> &color_modes) {
+    color_modes.clear();
+  };
+  virtual int GetDpiX() {
+    return -1;
+  }
+  virtual int GetDpiY() {
+    return -1;
+  }
+
+  virtual auto GetBoundsMm() -> std::pair<int32_t, int32_t> {
+    return {-1, -1};
+  }
+};
+
+#if HAS_LIBDISPLAY_INFO
+// Wrapper class for that uses libdisplay-info to parse edids
+class LibdisplayEdidWrapper final : public EdidWrapper {
+ public:
+  LibdisplayEdidWrapper() = delete;
+  ~LibdisplayEdidWrapper() override {
+    di_info_destroy(info_);
+  }
+  static auto Create(DrmModePropertyBlobUnique blob)
+      -> std::unique_ptr<LibdisplayEdidWrapper>;
+
+  void GetSupportedHdrTypes(std::vector<ui::Hdr> &types) override;
+
+  void GetHdrCapabilities(std::vector<ui::Hdr> &types,
+                          float *max_luminance,
+                          float *max_average_luminance,
+                          float *min_luminance) override;
+
+  void GetColorModes(std::vector<Colormode> &color_modes) override;
+
+  auto GetDpiX() -> int override;
+  auto GetDpiY() -> int override;
+
+  auto GetBoundsMm() -> std::pair<int32_t, int32_t> override;
+
+ private:
+  LibdisplayEdidWrapper(di_info *info) : info_(std::move(info)) {
+  }
+
+  std::pair<int32_t, int32_t> GetDpi();
+
+  di_info *info_{};
+};
+#endif
+
+}  // namespace android
diff --git a/utils/LibdisplayEdidWrapper.cpp b/utils/LibdisplayEdidWrapper.cpp
new file mode 100644
index 0000000..ad737a2
--- /dev/null
+++ b/utils/LibdisplayEdidWrapper.cpp
@@ -0,0 +1,145 @@
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
+#define LOG_TAG "drmhwc"
+
+#if HAS_LIBDISPLAY_INFO
+
+#include "utils/EdidWrapper.h"
+#include "utils/log.h"
+
+namespace android {
+
+auto LibdisplayEdidWrapper::Create(DrmModePropertyBlobUnique blob)
+    -> std::unique_ptr<LibdisplayEdidWrapper> {
+  if (!blob)
+    return nullptr;
+
+  auto *info = di_info_parse_edid(blob->data, blob->length);
+  if (!info) {
+    ALOGW("Failed to parse edid blob.");
+    return nullptr;
+  }
+
+  return std::unique_ptr<LibdisplayEdidWrapper>(
+      new LibdisplayEdidWrapper(std::move(info)));
+}
+
+void LibdisplayEdidWrapper::GetSupportedHdrTypes(std::vector<ui::Hdr> &types) {
+  types.clear();
+
+  const auto *hdr_static_meta = di_info_get_hdr_static_metadata(info_);
+  const auto *colorimetries = di_info_get_supported_signal_colorimetry(info_);
+  if (colorimetries->bt2020_cycc || colorimetries->bt2020_ycc ||
+      colorimetries->bt2020_rgb) {
+    if (hdr_static_meta->pq)
+      types.emplace_back(ui::Hdr::HDR10);
+    if (hdr_static_meta->hlg)
+      types.emplace_back(ui::Hdr::HLG);
+  }
+}
+
+void LibdisplayEdidWrapper::GetHdrCapabilities(
+    std::vector<ui::Hdr> &types, float *max_luminance,
+    float *max_average_luminance, float *min_luminance) {
+  GetSupportedHdrTypes(types);
+
+  const auto *hdr_static_meta = di_info_get_hdr_static_metadata(info_);
+  *max_luminance = hdr_static_meta->desired_content_max_luminance;
+  *max_average_luminance = hdr_static_meta
+                               ->desired_content_max_frame_avg_luminance;
+  *min_luminance = hdr_static_meta->desired_content_min_luminance;
+}
+
+void LibdisplayEdidWrapper::GetColorModes(std::vector<Colormode> &color_modes) {
+  color_modes.clear();
+  color_modes.emplace_back(Colormode::kNative);
+
+  const auto *hdr_static_meta = di_info_get_hdr_static_metadata(info_);
+  const auto *colorimetries = di_info_get_supported_signal_colorimetry(info_);
+
+  /* Rec. ITU-R BT.2020 constant luminance YCbCr */
+  /* Rec. ITU-R BT.2020 non-constant luminance YCbCr */
+  if (colorimetries->bt2020_cycc || colorimetries->bt2020_ycc)
+    color_modes.emplace_back(Colormode::kBt2020);
+
+  /* Rec. ITU-R BT.2020 RGB */
+  if (colorimetries->bt2020_rgb)
+    color_modes.emplace_back(Colormode::kDisplayBt2020);
+
+  /* SMPTE ST 2113 RGB: P3D65 and P3DCI */
+  if (colorimetries->st2113_rgb) {
+    color_modes.emplace_back(Colormode::kDciP3);
+    color_modes.emplace_back(Colormode::kDisplayP3);
+  }
+
+  /* Rec. ITU-R BT.2100 ICtCp HDR (with PQ and/or HLG) */
+  if (colorimetries->ictcp) {
+    if (hdr_static_meta->pq)
+      color_modes.emplace_back(Colormode::kBt2100Pq);
+    if (hdr_static_meta->hlg)
+      color_modes.emplace_back(Colormode::kBt2100Hlg);
+  }
+}
+
+auto LibdisplayEdidWrapper::GetDpiX() -> int {
+  return GetDpi().first;
+}
+
+auto LibdisplayEdidWrapper::GetDpiY() -> int {
+  return GetDpi().second;
+}
+
+auto LibdisplayEdidWrapper::GetBoundsMm() -> std::pair<int32_t, int32_t> {
+  const auto edid = di_info_get_edid(info_);
+  const auto detailed_timing_defs = di_edid_get_detailed_timing_defs(edid);
+  const auto dtd = detailed_timing_defs[0];
+  if (dtd == nullptr || dtd->horiz_image_mm == 0 || dtd->vert_image_mm == 0) {
+    // try to fallback on display size if no dtd.
+    // However since edid screen size are vastly unreliable only provide a valid
+    // width to avoid invalid dpi computation.
+    const auto screen_size = di_edid_get_screen_size(edid);
+    return {screen_size->width_cm * 10, -1};
+  }
+
+  return {dtd->horiz_image_mm, dtd->vert_image_mm};
+}
+
+auto LibdisplayEdidWrapper::GetDpi() -> std::pair<int32_t, int32_t> {
+  static const int32_t kUmPerInch = 25400;
+  const auto edid = di_info_get_edid(info_);
+  const auto detailed_timing_defs = di_edid_get_detailed_timing_defs(edid);
+  const auto dtd = detailed_timing_defs[0];
+  if (dtd == nullptr || dtd->horiz_image_mm == 0 || dtd->vert_image_mm == 0) {
+    // try to fallback on display size if no dtd.
+    const auto screen_size = di_edid_get_screen_size(edid);
+    const auto standard_timings = di_edid_get_standard_timings(edid);
+    if (screen_size->width_cm <= 0 || standard_timings == nullptr) {
+      return {-1, -1};
+    }
+
+    // display size is more unreliable so use only horizontal dpi.
+    int32_t horiz_video = standard_timings[0]->horiz_video;
+    int32_t dpi = horiz_video * kUmPerInch / (screen_size->width_cm * 10);
+    return {dpi, dpi};
+  }
+
+  return {dtd->horiz_video * kUmPerInch / dtd->horiz_image_mm,
+          dtd->vert_video * kUmPerInch / dtd->vert_image_mm};
+}
+
+}  // namespace android
+#endif
diff --git a/utils/properties.cpp b/utils/properties.cpp
index a855c94..a975822 100644
--- a/utils/properties.cpp
+++ b/utils/properties.cpp
@@ -27,5 +27,17 @@ auto Properties::IsPresentFenceNotReliable() -> bool {
 }
 
 auto Properties::UseConfigGroups() -> bool {
-  return (property_get_bool("ro.vendor.hwc.drm.use_config_groups", 1) != 0);
+  return (property_get_bool("ro.vendor.hwc.drm.use_config_groups", 0) != 0);
+}
+
+auto Properties::UseOverlayPlanes() -> bool {
+  return (property_get_bool("ro.vendor.hwc.use_overlay_planes", 1) != 0);
+}
+
+auto Properties::ScaleWithGpu() -> bool {
+  return (property_get_bool("vendor.hwc.drm.scale_with_gpu", 0) != 0);
+}
+
+auto Properties::EnableVirtualDisplay() -> bool {
+  return (property_get_bool("vendor.hwc.drm.enable_virtual_display", 0) != 0);
 }
diff --git a/utils/properties.h b/utils/properties.h
index 15c2fb2..4df79eb 100644
--- a/utils/properties.h
+++ b/utils/properties.h
@@ -78,4 +78,7 @@ class Properties {
  public:
   static auto IsPresentFenceNotReliable() -> bool;
   static auto UseConfigGroups() -> bool;
+  static auto UseOverlayPlanes() -> bool;
+  static auto ScaleWithGpu() -> bool;
+  static auto EnableVirtualDisplay() -> bool;
 };
diff --git a/utils/thread_annotations.h b/utils/thread_annotations.h
new file mode 100644
index 0000000..f3bd2e0
--- /dev/null
+++ b/utils/thread_annotations.h
@@ -0,0 +1,77 @@
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
+#pragma once
+
+// Enable thread safety attributes only with clang.
+#if defined(__clang__)
+#define THREAD_ANNOTATION_ATTRIBUTE__(x) __attribute__((x))
+#else
+#define THREAD_ANNOTATION_ATTRIBUTE__(x)  // no-op
+#endif
+
+#define CAPABILITY(x) THREAD_ANNOTATION_ATTRIBUTE__(capability(x))
+
+#define SCOPED_CAPABILITY THREAD_ANNOTATION_ATTRIBUTE__(scoped_lockable)
+
+#define GUARDED_BY(x) THREAD_ANNOTATION_ATTRIBUTE__(guarded_by(x))
+
+#define PT_GUARDED_BY(x) THREAD_ANNOTATION_ATTRIBUTE__(pt_guarded_by(x))
+
+#define ACQUIRED_BEFORE(...) \
+  THREAD_ANNOTATION_ATTRIBUTE__(acquired_before(__VA_ARGS__))
+
+#define ACQUIRED_AFTER(...) \
+  THREAD_ANNOTATION_ATTRIBUTE__(acquired_after(__VA_ARGS__))
+
+#define REQUIRES(...) \
+  THREAD_ANNOTATION_ATTRIBUTE__(requires_capability(__VA_ARGS__))
+
+#define REQUIRES_SHARED(...) \
+  THREAD_ANNOTATION_ATTRIBUTE__(requires_shared_capability(__VA_ARGS__))
+
+#define ACQUIRE(...) \
+  THREAD_ANNOTATION_ATTRIBUTE__(acquire_capability(__VA_ARGS__))
+
+#define ACQUIRE_SHARED(...) \
+  THREAD_ANNOTATION_ATTRIBUTE__(acquire_shared_capability(__VA_ARGS__))
+
+#define RELEASE(...) \
+  THREAD_ANNOTATION_ATTRIBUTE__(release_capability(__VA_ARGS__))
+
+#define RELEASE_SHARED(...) \
+  THREAD_ANNOTATION_ATTRIBUTE__(release_shared_capability(__VA_ARGS__))
+
+#define RELEASE_GENERIC(...) \
+  THREAD_ANNOTATION_ATTRIBUTE__(release_generic_capability(__VA_ARGS__))
+
+#define TRY_ACQUIRE(...) \
+  THREAD_ANNOTATION_ATTRIBUTE__(try_acquire_capability(__VA_ARGS__))
+
+#define TRY_ACQUIRE_SHARED(...) \
+  THREAD_ANNOTATION_ATTRIBUTE__(try_acquire_shared_capability(__VA_ARGS__))
+
+#define EXCLUDES(...) THREAD_ANNOTATION_ATTRIBUTE__(locks_excluded(__VA_ARGS__))
+
+#define ASSERT_CAPABILITY(x) THREAD_ANNOTATION_ATTRIBUTE__(assert_capability(x))
+
+#define ASSERT_SHARED_CAPABILITY(x) \
+  THREAD_ANNOTATION_ATTRIBUTE__(assert_shared_capability(x))
+
+#define RETURN_CAPABILITY(x) THREAD_ANNOTATION_ATTRIBUTE__(lock_returned(x))
+
+#define NO_THREAD_SAFETY_ANALYSIS \
+  THREAD_ANNOTATION_ATTRIBUTE__(no_thread_safety_analysis)
\ No newline at end of file
```

