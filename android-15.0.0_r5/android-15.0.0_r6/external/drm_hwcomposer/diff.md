```diff
diff --git a/.ci/Dockerfile b/.ci/Dockerfile
index 2158d7a..c42c8b6 100644
--- a/.ci/Dockerfile
+++ b/.ci/Dockerfile
@@ -41,11 +41,11 @@ RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> \
 USER ${RUN_USER}
 
 # Install aospless package (produced by GloDroid/aospext)
-RUN wget -P ${USER_HOME} https://gitlab.freedesktop.org/drm-hwcomposer/drm-hwcomposer/uploads/28ef9379b1a0ec1ee19a17825b0f3f3f/aospless_drm_hwcomposer_arm64.tar.xz && \
+RUN wget -P ${USER_HOME} https://gitlab.freedesktop.org/-/project/5/uploads/d66764aa71f9f1235b92d44a652cd3c3/aospless_drm_hwcomposer_arm64.tar.xz && \
     cd ${USER_HOME} && \
-    (echo 96b2148d04c50cf36d4151ae022e665764b8ca3317712e9467a433b62c545a43 aospless_drm_hwcomposer_arm64.tar.xz | sha256sum --check) && \
-    tar xf aospless_drm_hwcomposer_arm64.tar.xz && \
-    rm -r ${USER_HOME}/aospless/src && ln -s ../drm_hwcomposer/ ${USER_HOME}/aospless/src
+    sha256sum aospless_drm_hwcomposer_arm64.tar.xz && \
+    (echo 00ff288f184111dd35143c462e82fd5f8f31a1417d5eb9a11e8798695abcc141 aospless_drm_hwcomposer_arm64.tar.xz | sha256sum --check) && \
+    tar xf aospless_drm_hwcomposer_arm64.tar.xz && ln -s ../drm_hwcomposer/ ${USER_HOME}/aospless/src
 
 # Create project path
 RUN mkdir -pv ${USER_HOME}/drm_hwcomposer
diff --git a/.ci/Makefile b/.ci/Makefile
index a30414c..325e0b5 100644
--- a/.ci/Makefile
+++ b/.ci/Makefile
@@ -1,5 +1,5 @@
 
-BASE_DIR:=../aospless
+BASE_DIR ?=../aospless
 
 SYSTEM_INCLUDE_DIRS := /usr/include/libdrm
 
@@ -40,8 +40,10 @@ TIDY_CHECKS_FINE := *                                   \
     -llvmlibc* -fuchsia-* -altera-*                     \
     -llvm-header-guard                                  \
     -cppcoreguidelines-pro-type-vararg                  \
+    -google-readability-todo                            \
     -hicpp-vararg                                       \
     -hicpp-signed-bitwise                               \
+    -misc-const-correctness                             \
     -readability-identifier-length                      \
 
 TIDY_CHECKS_NORMAL :=                                   \
diff --git a/.gitlab-ci.yml b/.gitlab-ci.yml
index bdbb8be..da052c3 100644
--- a/.gitlab-ci.yml
+++ b/.gitlab-ci.yml
@@ -1,5 +1,3 @@
-image: ubuntu:23.04
-
 workflow:
   rules:
     - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
@@ -7,31 +5,38 @@ workflow:
 
 variables:
   DEBIAN_FRONTEND: noninteractive
-
-before_script:
-  - apt-get --quiet update --yes >/dev/null
-  - apt-get --quiet install --yes clang-15 clang-tidy-15 clang-format-15 git libdrm-dev blueprint-tools libgtest-dev make >/dev/null
-  - apt-get --quiet install --yes clang llvm make python3 wget sudo rsync lld pkg-config ninja-build meson >/dev/null
-  - apt-get --quiet install --yes python3-mako python3-jinja2 python3-ply python3-yaml >/dev/null
+  DOCKER_IMAGE_TAG: $CI_REGISTRY_IMAGE:latest
 
 stages:
+  - build-container
   - build
   - tidy
   - style
 
+build-container:
+  stage: build-container
+  image: docker:27.0.3
+  services:
+    - docker:27.0.3-dind
+  variables:
+    DOCKER_TLS_CERTDIR: ""
+  before_script:
+    - echo "$CI_JOB_TOKEN" | docker login $CI_REGISTRY -u $CI_REGISTRY_USER --password-stdin
+  script:
+    - docker build -t $DOCKER_IMAGE_TAG -f .ci/Dockerfile .
+    - docker push $DOCKER_IMAGE_TAG
+  after_script:
+    - docker logout
+
 build:
   stage: build
+  image: $DOCKER_IMAGE_TAG
   script:
     - mkdir -p install/arm64
-    - cd ..
-    - rm -f aospless_drm_hwcomposer_arm64.tar.xz
-    - rm -rf aospless/*
-    - wget https://gitlab.freedesktop.org/drm-hwcomposer/drm-hwcomposer/uploads/28ef9379b1a0ec1ee19a17825b0f3f3f/aospless_drm_hwcomposer_arm64.tar.xz
-    - tar xf aospless_drm_hwcomposer_arm64.tar.xz
-    - rm -r aospless/src
-    - ln -s ../drm-hwcomposer/ aospless/src
-    - make -C ./aospless all
-    - cp -r aospless/install/* drm-hwcomposer/install/arm64
+    - rm ${HOME}/aospless/src
+    - ln -s ${PWD} ${HOME}/aospless/src
+    - make -C ${HOME}/aospless all
+    - cp -r ${HOME}/aospless/install/* install/arm64
 
   artifacts:
     paths:
@@ -40,17 +45,16 @@ build:
 
 tidy:
   stage: tidy
+  image: $DOCKER_IMAGE_TAG
   script:
-    - cd ..
-    - rm -f aospless_drm_hwcomposer_arm64.tar.xz
-    - rm -rf aospless/*
-    - wget https://gitlab.freedesktop.org/drm-hwcomposer/drm-hwcomposer/uploads/28ef9379b1a0ec1ee19a17825b0f3f3f/aospless_drm_hwcomposer_arm64.tar.xz
-    - tar xf aospless_drm_hwcomposer_arm64.tar.xz
-    - cd -
-    - make -f .ci/Makefile
+    - rm ${HOME}/aospless/src
+    - ln -s ${PWD} ${HOME}/aospless/src
+    - BASE_DIR=${HOME}/aospless make -j$(nproc) -k -f .ci/Makefile
+  timeout: 2h
 
 checkstyle:
   stage: style
+  image: $DOCKER_IMAGE_TAG
   script: "./.ci/.gitlab-ci-checkcommit.sh"
   artifacts:
     when: on_failure
diff --git a/Android.bp b/Android.bp
index 62c7e0c..7d014dc 100644
--- a/Android.bp
+++ b/Android.bp
@@ -42,6 +42,8 @@ cc_defaults {
     name: "hwcomposer.drm_defaults",
 
     shared_libs: [
+        "android.hardware.graphics.composer@2.1-resources",
+        "android.hardware.graphics.composer@2.2-resources",
         "libcutils",
         "libdrm",
         "libhardware",
@@ -52,7 +54,13 @@ cc_defaults {
         "libutils",
     ],
 
-    header_libs: ["drm_hwcomposer_headers"],
+    static_libs: [
+        "libaidlcommonsupport",
+    ],
+
+    header_libs: [
+        "drm_hwcomposer_headers",
+    ],
 
     cflags: [
         "-Wall",
@@ -62,7 +70,6 @@ cc_defaults {
     cppflags: [
         "-DHWC2_INCLUDE_STRINGIFICATION",
         "-DHWC2_USE_CPP11",
-        "-std=c++17",
     ],
 
     relative_install_path: "hw",
@@ -96,6 +103,7 @@ filegroup {
         "drm/ResourceManager.cpp",
         "drm/UEventListener.cpp",
         "drm/VSyncWorker.cpp",
+        "drm/DrmHwc.cpp",
 
         "backend/Backend.cpp",
         "backend/BackendClient.cpp",
@@ -111,6 +119,38 @@ filegroup {
     ],
 }
 
+filegroup {
+    name: "drm_hwcomposer_hwc3",
+    srcs: [
+        "hwc3/Composer.cpp",
+        "hwc3/ComposerClient.cpp",
+        "hwc3/ComposerResources.cpp",
+        "hwc3/DrmHwcThree.cpp",
+        "hwc3/Utils.cpp",
+    ],
+}
+
+filegroup {
+    name: "drm_hwcomposer_service",
+    srcs: [
+        "hwc3/service.cpp",
+    ],
+}
+
+filegroup {
+    name: "drm_hwcomposer_init_rc",
+    srcs: [
+        "hwc3/hwc3-drm.rc",
+    ],
+}
+
+filegroup {
+    name: "drm_hwcomposer_vintf_manifest",
+    srcs: [
+        "hwc3/hwc3-drm.xml",
+    ],
+}
+
 // Kept only for compatibility with older Android version. Please do not use!
 cc_library_static {
     name: "drm_hwcomposer",
@@ -137,6 +177,48 @@ cc_library_shared {
     ],
 }
 
+cc_binary {
+    name: "android.hardware.composer.hwc3-service.drm",
+
+    srcs: [
+        ":drm_hwcomposer_hwc3",
+        ":drm_hwcomposer_service",
+        ":drm_hwcomposer_common",
+        "bufferinfo/legacy/BufferInfoLibdrm.cpp",
+    ],
+
+    defaults: [
+        "hwcomposer.drm_defaults",
+    ],
+
+    shared_libs: [
+        "android.hardware.graphics.composer3-V3-ndk",
+        "libbase",
+        "libbinder",
+        "libbinder_ndk",
+        "liblog",
+        "libutils",
+    ],
+
+    cflags: [
+        "-Wall",
+        "-Werror",
+
+        "-DUSE_IMAPPER4_METADATA_API",
+    ],
+
+    cppflags: [
+        "-DHWC2_INCLUDE_STRINGIFICATION",
+        "-DHWC2_USE_CPP11",
+    ],
+
+    relative_install_path: "hw",
+    vendor: true,
+
+    vintf_fragments: [":drm_hwcomposer_vintf_manifest"],
+    init_rc: [":drm_hwcomposer_init_rc"],
+}
+
 // Used by hwcomposer.drm_imagination
 filegroup {
     name: "drm_hwcomposer_platformimagination",
diff --git a/backend/Backend.cpp b/backend/Backend.cpp
index 3ca6e92..91cb84d 100644
--- a/backend/Backend.cpp
+++ b/backend/Backend.cpp
@@ -94,7 +94,7 @@ bool Backend::IsClientLayer(HwcDisplay *display, HwcLayer *layer) {
   return !HardwareSupportsLayerType(layer->GetSfType()) ||
          !layer->IsLayerUsableAsDevice() || display->CtmByGpu() ||
          (layer->GetLayerData().pi.RequireScalingOrPhasing() &&
-          display->GetHwc2()->GetResMan().ForcedScalingWithGpu());
+          display->GetHwc()->GetResMan().ForcedScalingWithGpu());
 }
 
 bool Backend::HardwareSupportsLayerType(HWC2::Composition comp_type) {
diff --git a/backend/BackendManager.cpp b/backend/BackendManager.cpp
index 4e2532a..23fe270 100644
--- a/backend/BackendManager.cpp
+++ b/backend/BackendManager.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-backend"
+#define LOG_TAG "drmhwc"
 
 #include "BackendManager.h"
 
diff --git a/bufferinfo/BufferInfoGetter.cpp b/bufferinfo/BufferInfoGetter.cpp
index 726b4eb..f12db22 100644
--- a/bufferinfo/BufferInfoGetter.cpp
+++ b/bufferinfo/BufferInfoGetter.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-buffer-info-getter"
+#define LOG_TAG "drmhwc"
 
 #include "BufferInfoGetter.h"
 
diff --git a/bufferinfo/BufferInfoMapperMetadata.cpp b/bufferinfo/BufferInfoMapperMetadata.cpp
index 823d28a..dc1b906 100644
--- a/bufferinfo/BufferInfoMapperMetadata.cpp
+++ b/bufferinfo/BufferInfoMapperMetadata.cpp
@@ -16,7 +16,7 @@
 
 #if __ANDROID_API__ >= 30
 
-#define LOG_TAG "hwc-bufferinfo-mappermetadata"
+#define LOG_TAG "drmhwc"
 
 #include "BufferInfoMapperMetadata.h"
 
diff --git a/bufferinfo/legacy/BufferInfoImagination.cpp b/bufferinfo/legacy/BufferInfoImagination.cpp
index 6d917c2..0bb0aaa 100644
--- a/bufferinfo/legacy/BufferInfoImagination.cpp
+++ b/bufferinfo/legacy/BufferInfoImagination.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-bufferinfo-imagination"
+#define LOG_TAG "drmhwc"
 
 #include "BufferInfoImagination.h"
 
diff --git a/bufferinfo/legacy/BufferInfoLibdrm.cpp b/bufferinfo/legacy/BufferInfoLibdrm.cpp
index b314bdc..6978b08 100644
--- a/bufferinfo/legacy/BufferInfoLibdrm.cpp
+++ b/bufferinfo/legacy/BufferInfoLibdrm.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-bufferinfo-libdrm"
+#define LOG_TAG "drmhwc"
 
 #include "BufferInfoLibdrm.h"
 
diff --git a/bufferinfo/legacy/BufferInfoMaliHisi.cpp b/bufferinfo/legacy/BufferInfoMaliHisi.cpp
index 461e2eb..bfb2e7b 100644
--- a/bufferinfo/legacy/BufferInfoMaliHisi.cpp
+++ b/bufferinfo/legacy/BufferInfoMaliHisi.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-bufferinfo-mali-hisi"
+#define LOG_TAG "drmhwc"
 
 #include "BufferInfoMaliHisi.h"
 
diff --git a/bufferinfo/legacy/BufferInfoMaliMediatek.cpp b/bufferinfo/legacy/BufferInfoMaliMediatek.cpp
index 6dac973..4493c98 100644
--- a/bufferinfo/legacy/BufferInfoMaliMediatek.cpp
+++ b/bufferinfo/legacy/BufferInfoMaliMediatek.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-bufferinfo-mali-mediatek"
+#define LOG_TAG "drmhwc"
 
 #include "BufferInfoMaliMediatek.h"
 
diff --git a/bufferinfo/legacy/BufferInfoMaliMeson.cpp b/bufferinfo/legacy/BufferInfoMaliMeson.cpp
index 536e5a6..aa77529 100644
--- a/bufferinfo/legacy/BufferInfoMaliMeson.cpp
+++ b/bufferinfo/legacy/BufferInfoMaliMeson.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-bufferinfo-mali-meson"
+#define LOG_TAG "drmhwc"
 
 #include "BufferInfoMaliMeson.h"
 
diff --git a/bufferinfo/legacy/BufferInfoMinigbm.cpp b/bufferinfo/legacy/BufferInfoMinigbm.cpp
index c5a9e98..4bc4358 100644
--- a/bufferinfo/legacy/BufferInfoMinigbm.cpp
+++ b/bufferinfo/legacy/BufferInfoMinigbm.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-bufferinfo-minigbm"
+#define LOG_TAG "drmhwc"
 
 #include "BufferInfoMinigbm.h"
 
diff --git a/compositor/DrmKmsPlan.cpp b/compositor/DrmKmsPlan.cpp
index 6289b84..4f75e89 100644
--- a/compositor/DrmKmsPlan.cpp
+++ b/compositor/DrmKmsPlan.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-composition-drm-kms-plan"
+#define LOG_TAG "drmhwc"
 
 #include "DrmKmsPlan.h"
 
diff --git a/compositor/FlatteningController.cpp b/compositor/FlatteningController.cpp
index 257f8a0..efd7ad0 100644
--- a/compositor/FlatteningController.cpp
+++ b/compositor/FlatteningController.cpp
@@ -29,7 +29,7 @@
  * composed by the client into a single framebuffer using GPU.
  */
 
-#define LOG_TAG "hwc-flatcon"
+#define LOG_TAG "drmhwc"
 
 #include "FlatteningController.h"
 
@@ -41,6 +41,12 @@ auto FlatteningController::CreateInstance(FlatConCallbacks &cbks)
     -> std::shared_ptr<FlatteningController> {
   auto fc = std::shared_ptr<FlatteningController>(new FlatteningController());
 
+  /* Disable the controller by default as it can cause refresh event to be
+   * issued at creation time, even when it is not required. This can fail VTS
+   * tests at teardown that check for this behaviour. See:
+   * https://cs.android.com/android/platform/superproject/main/+/cedca652b903e4f4e584e457b5a7038e0825fb94:hardware/interfaces/graphics/composer/aidl/vts/VtsComposerClient.cpp;drc=a2a6deaf5036e081f48379b6573db4465538b5ac;l=604
+   */
+  fc->Disable();
   fc->cbks_ = cbks;
 
   std::thread(&FlatteningController::ThreadFn, fc).detach();
diff --git a/drm/DrmAtomicStateManager.cpp b/drm/DrmAtomicStateManager.cpp
index b1f8257..537f819 100644
--- a/drm/DrmAtomicStateManager.cpp
+++ b/drm/DrmAtomicStateManager.cpp
@@ -17,7 +17,7 @@
 #undef NDEBUG /* Required for assert to work */
 
 #define ATRACE_TAG ATRACE_TAG_GRAPHICS
-#define LOG_TAG "hwc-drm-atomic-state-manager"
+#define LOG_TAG "drmhwc"
 
 #include "DrmAtomicStateManager.h"
 
diff --git a/drm/DrmConnector.cpp b/drm/DrmConnector.cpp
index b396487..e459fe7 100644
--- a/drm/DrmConnector.cpp
+++ b/drm/DrmConnector.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-drm-connector"
+#define LOG_TAG "drmhwc"
 
 #include "DrmConnector.h"
 
diff --git a/drm/DrmCrtc.cpp b/drm/DrmCrtc.cpp
index 948a9ac..ecee9e2 100644
--- a/drm/DrmCrtc.cpp
+++ b/drm/DrmCrtc.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-drm-crtc"
+#define LOG_TAG "drmhwc"
 
 #include "DrmCrtc.h"
 
diff --git a/drm/DrmDevice.cpp b/drm/DrmDevice.cpp
index f6f0b01..4534104 100644
--- a/drm/DrmDevice.cpp
+++ b/drm/DrmDevice.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-drm-device"
+#define LOG_TAG "drmhwc"
 
 #include "DrmDevice.h"
 
diff --git a/drm/DrmDisplayPipeline.cpp b/drm/DrmDisplayPipeline.cpp
index 1a8ad5b..2d81578 100644
--- a/drm/DrmDisplayPipeline.cpp
+++ b/drm/DrmDisplayPipeline.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-drm-display-pipeline"
+#define LOG_TAG "drmhwc"
 
 #include "DrmDisplayPipeline.h"
 
diff --git a/drm/DrmEncoder.cpp b/drm/DrmEncoder.cpp
index 21ca693..7480ce6 100644
--- a/drm/DrmEncoder.cpp
+++ b/drm/DrmEncoder.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-drm-encoder"
+#define LOG_TAG "drmhwc"
 
 #include "DrmEncoder.h"
 
diff --git a/drm/DrmFbImporter.cpp b/drm/DrmFbImporter.cpp
index a91a52b..fe80891 100644
--- a/drm/DrmFbImporter.cpp
+++ b/drm/DrmFbImporter.cpp
@@ -17,7 +17,7 @@
 // NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
 #define ATRACE_TAG ATRACE_TAG_GRAPHICS
 // NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
-#define LOG_TAG "hwc-platform-drm-generic"
+#define LOG_TAG "drmhwc"
 
 #include "DrmFbImporter.h"
 
@@ -97,7 +97,7 @@ DrmFbIdHandle::~DrmFbIdHandle() {
   ATRACE_NAME("Close FB and dmabufs");
 
   /* Destroy framebuffer object */
-  if (drmModeRmFB(*drm_->GetFd(), fb_id_) != 0) {
+  if (drmModeRmFB(*drm_fd_, fb_id_) != 0) {
     ALOGE("Failed to rm fb");
   }
 
@@ -118,7 +118,7 @@ DrmFbIdHandle::~DrmFbIdHandle() {
       continue;
     }
     gem_close.handle = gem_handles_[i];
-    auto err = drmIoctl(*drm_->GetFd(), DRM_IOCTL_GEM_CLOSE, &gem_close);
+    auto err = drmIoctl(*drm_fd_, DRM_IOCTL_GEM_CLOSE, &gem_close);
     if (err != 0) {
       ALOGE("Failed to close gem handle %d, errno: %d", gem_handles_[i], errno);
     }
@@ -127,10 +127,21 @@ DrmFbIdHandle::~DrmFbIdHandle() {
 
 auto DrmFbImporter::GetOrCreateFbId(BufferInfo *bo)
     -> std::shared_ptr<DrmFbIdHandle> {
+  /* TODO: Clean up DrmDevices and DrmFbImporter inter-dependency.
+   *
+   * DrmFbImporter can outlive DrmDevice which will cause issues when resources
+   * are released. Addressing this would require a restructure on how
+   * ResourceManager stores DrmDevices and DrmFbImporter to make sure they
+   * depend on each other. For now, just acquire the DRM fd from the DrmDevice
+   * to make sure it is not closed.
+   */
+  if (drm_fd_ == nullptr) {
+    drm_fd_ = drm_->GetFd();
+  }
+
   /* Lookup DrmFbIdHandle in cache first. First handle serves as a cache key. */
   GemHandle first_handle = 0;
-  auto err = drmPrimeFDToHandle(*drm_->GetFd(), bo->prime_fds[0],
-                                &first_handle);
+  auto err = drmPrimeFDToHandle(*drm_fd_, bo->prime_fds[0], &first_handle);
 
   if (err != 0) {
     ALOGE("Failed to import prime fd %d ret=%d", bo->prime_fds[0], err);
diff --git a/drm/DrmFbImporter.h b/drm/DrmFbImporter.h
index 9a7c335..30f57ba 100644
--- a/drm/DrmFbImporter.h
+++ b/drm/DrmFbImporter.h
@@ -24,6 +24,7 @@
 
 #include "bufferinfo/BufferInfo.h"
 #include "drm/DrmDevice.h"
+#include "utils/fd.h"
 
 #ifndef DRM_FORMAT_INVALID
 #define DRM_FORMAT_INVALID 0
@@ -49,9 +50,9 @@ class DrmFbIdHandle {
   }
 
  private:
-  explicit DrmFbIdHandle(DrmDevice &drm) : drm_(&drm){};
+  explicit DrmFbIdHandle(DrmDevice &drm) : drm_fd_(drm.GetFd()) {};
 
-  DrmDevice *const drm_;
+  SharedFd drm_fd_;
 
   uint32_t fb_id_{};
   std::array<GemHandle, kBufferMaxPlanes> gem_handles_{};
@@ -81,6 +82,7 @@ class DrmFbImporter {
   }
 
   DrmDevice *const drm_;
+  SharedFd drm_fd_;
 
   std::map<GemHandle, std::weak_ptr<DrmFbIdHandle>> drm_fb_id_handle_cache_;
 };
diff --git a/drm/DrmHwc.cpp b/drm/DrmHwc.cpp
new file mode 100644
index 0000000..df3eb56
--- /dev/null
+++ b/drm/DrmHwc.cpp
@@ -0,0 +1,202 @@
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
+#include "DrmHwc.h"
+
+#include <cinttypes>
+
+#include "backend/Backend.h"
+#include "utils/log.h"
+
+namespace android {
+
+DrmHwc::DrmHwc() : resource_manager_(this) {};
+
+/* Must be called after every display attach/detach cycle */
+void DrmHwc::FinalizeDisplayBinding() {
+  if (displays_.count(kPrimaryDisplay) == 0) {
+    /* Primary display MUST always exist */
+    ALOGI("No pipelines available. Creating null-display for headless mode");
+    displays_[kPrimaryDisplay] = std::make_unique<
+        HwcDisplay>(kPrimaryDisplay, HWC2::DisplayType::Physical, this);
+    /* Initializes null-display */
+    displays_[kPrimaryDisplay]->SetPipeline({});
+  }
+
+  if (displays_[kPrimaryDisplay]->IsInHeadlessMode() &&
+      !display_handles_.empty()) {
+    /* Reattach first secondary display to take place of the primary */
+    auto pipe = display_handles_.begin()->first;
+    ALOGI("Primary display was disconnected, reattaching '%s' as new primary",
+          pipe->connector->Get()->GetName().c_str());
+    UnbindDisplay(pipe);
+    BindDisplay(pipe);
+  }
+
+  // Finally, send hotplug events to the client
+  for (auto &dhe : deferred_hotplug_events_) {
+    SendHotplugEventToClient(dhe.first, dhe.second);
+  }
+  deferred_hotplug_events_.clear();
+
+  /* Wait 0.2s before removing the displays to flush pending HWC2 transactions
+   */
+  auto &mutex = GetResMan().GetMainLock();
+  mutex.unlock();
+  const int time_for_sf_to_dispose_display_us = 200000;
+  usleep(time_for_sf_to_dispose_display_us);
+  mutex.lock();
+  for (auto handle : displays_for_removal_list_) {
+    displays_.erase(handle);
+  }
+}
+
+bool DrmHwc::BindDisplay(std::shared_ptr<DrmDisplayPipeline> pipeline) {
+  if (display_handles_.count(pipeline) != 0) {
+    ALOGE("%s, pipeline is already used by another display, FIXME!!!: %p",
+          __func__, pipeline.get());
+    return false;
+  }
+
+  uint32_t disp_handle = kPrimaryDisplay;
+
+  if (displays_.count(kPrimaryDisplay) != 0 &&
+      !displays_[kPrimaryDisplay]->IsInHeadlessMode()) {
+    disp_handle = ++last_display_handle_;
+  }
+
+  if (displays_.count(disp_handle) == 0) {
+    auto disp = std::make_unique<HwcDisplay>(disp_handle,
+                                             HWC2::DisplayType::Physical, this);
+    displays_[disp_handle] = std::move(disp);
+  }
+
+  ALOGI("Attaching pipeline '%s' to the display #%d%s",
+        pipeline->connector->Get()->GetName().c_str(), (int)disp_handle,
+        disp_handle == kPrimaryDisplay ? " (Primary)" : "");
+
+  displays_[disp_handle]->SetPipeline(pipeline);
+  display_handles_[pipeline] = disp_handle;
+
+  return true;
+}
+
+bool DrmHwc::UnbindDisplay(std::shared_ptr<DrmDisplayPipeline> pipeline) {
+  if (display_handles_.count(pipeline) == 0) {
+    ALOGE("%s, can't find the display, pipeline: %p", __func__, pipeline.get());
+    return false;
+  }
+  auto handle = display_handles_[pipeline];
+  display_handles_.erase(pipeline);
+
+  ALOGI("Detaching the pipeline '%s' from the display #%i%s",
+        pipeline->connector->Get()->GetName().c_str(), (int)handle,
+        handle == kPrimaryDisplay ? " (Primary)" : "");
+
+  if (displays_.count(handle) == 0) {
+    ALOGE("%s, can't find the display, handle: %" PRIu64, __func__, handle);
+    return false;
+  }
+  displays_[handle]->SetPipeline({});
+
+  /* We must defer display disposal and removal, since it may still have pending
+   * HWC_API calls scheduled and waiting until ueventlistener thread releases
+   * main lock, otherwise transaction may fail and SF may crash
+   */
+  if (handle != kPrimaryDisplay) {
+    displays_for_removal_list_.emplace_back(handle);
+  }
+  return true;
+}
+
+HWC2::Error DrmHwc::CreateVirtualDisplay(
+    uint32_t width, uint32_t height,
+    int32_t *format,  // NOLINT(readability-non-const-parameter)
+    hwc2_display_t *display) {
+  ALOGI("Creating virtual display %dx%d format %d", width, height, *format);
+
+  auto virtual_pipeline = resource_manager_.GetVirtualDisplayPipeline();
+  if (!virtual_pipeline)
+    return HWC2::Error::Unsupported;
+
+  *display = ++last_display_handle_;
+  auto disp = std::make_unique<HwcDisplay>(*display, HWC2::DisplayType::Virtual,
+                                           this);
+
+  disp->SetVirtualDisplayResolution(width, height);
+  disp->SetPipeline(virtual_pipeline);
+  displays_[*display] = std::move(disp);
+  return HWC2::Error::None;
+}
+
+HWC2::Error DrmHwc::DestroyVirtualDisplay(hwc2_display_t display) {
+  ALOGI("Destroying virtual display %" PRIu64, display);
+
+  if (displays_.count(display) == 0) {
+    ALOGE("Trying to destroy non-existent display %" PRIu64, display);
+    return HWC2::Error::BadDisplay;
+  }
+
+  displays_[display]->SetPipeline({});
+
+  /* Wait 0.2s before removing the displays to flush pending HWC2 transactions
+   */
+  auto &mutex = GetResMan().GetMainLock();
+  mutex.unlock();
+  const int time_for_sf_to_dispose_display_us = 200000;
+  usleep(time_for_sf_to_dispose_display_us);
+  mutex.lock();
+
+  displays_.erase(display);
+
+  return HWC2::Error::None;
+}
+
+void DrmHwc::Dump(uint32_t *out_size, char *out_buffer) {
+  if (out_buffer != nullptr) {
+    auto copied_bytes = dump_string_.copy(out_buffer, *out_size);
+    *out_size = static_cast<uint32_t>(copied_bytes);
+    return;
+  }
+
+  std::stringstream output;
+
+  output << "-- drm_hwcomposer --\n\n";
+
+  for (auto &disp : displays_)
+    output << disp.second->Dump();
+
+  dump_string_ = output.str();
+  *out_size = static_cast<uint32_t>(dump_string_.size());
+}
+
+uint32_t DrmHwc::GetMaxVirtualDisplayCount() {
+  auto writeback_count = resource_manager_.GetWritebackConnectorsCount();
+  writeback_count = std::min(writeback_count, 1U);
+  /* Currently, only 1 virtual display is supported. Other cases need testing */
+  ALOGI("Max virtual display count: %d", writeback_count);
+  return writeback_count;
+}
+
+void DrmHwc::DeinitDisplays() {
+  for (auto &pair : Displays()) {
+    pair.second->SetPipeline(nullptr);
+  }
+}
+
+}  // namespace android
\ No newline at end of file
diff --git a/drm/DrmHwc.h b/drm/DrmHwc.h
new file mode 100644
index 0000000..44dc276
--- /dev/null
+++ b/drm/DrmHwc.h
@@ -0,0 +1,83 @@
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
+#pragma once
+
+#include "drm/ResourceManager.h"
+#include "hwc2_device/HwcDisplay.h"
+
+namespace android {
+
+class DrmHwc : public PipelineToFrontendBindingInterface {
+ public:
+  DrmHwc();
+  ~DrmHwc() override = default;
+
+  // Client Callback functions.:
+  virtual void SendVsyncEventToClient(hwc2_display_t displayid,
+                                      int64_t timestamp,
+                                      uint32_t vsync_period) const = 0;
+  virtual void SendVsyncPeriodTimingChangedEventToClient(
+      hwc2_display_t displayid, int64_t timestamp) const = 0;
+  virtual void SendRefreshEventToClient(uint64_t displayid) = 0;
+  virtual void SendHotplugEventToClient(hwc2_display_t displayid,
+                                        bool connected) = 0;
+
+  // Device functions
+  HWC2::Error CreateVirtualDisplay(uint32_t width, uint32_t height,
+                                   int32_t *format, hwc2_display_t *display);
+  HWC2::Error DestroyVirtualDisplay(hwc2_display_t display);
+  void Dump(uint32_t *out_size, char *out_buffer);
+  uint32_t GetMaxVirtualDisplayCount();
+
+  auto GetDisplay(hwc2_display_t display_handle) {
+    return displays_.count(display_handle) != 0
+               ? displays_[display_handle].get()
+               : nullptr;
+  }
+
+  auto &GetResMan() {
+    return resource_manager_;
+  }
+
+  void ScheduleHotplugEvent(hwc2_display_t displayid, bool connected) {
+    deferred_hotplug_events_[displayid] = connected;
+  }
+
+  void DeinitDisplays();
+
+  // PipelineToFrontendBindingInterface
+  bool BindDisplay(std::shared_ptr<DrmDisplayPipeline> pipeline) override;
+  bool UnbindDisplay(std::shared_ptr<DrmDisplayPipeline> pipeline) override;
+  void FinalizeDisplayBinding() override;
+
+ protected:
+  auto& Displays() { return displays_; }
+
+ private:
+  ResourceManager resource_manager_;
+  std::map<hwc2_display_t, std::unique_ptr<HwcDisplay>> displays_;
+  std::map<std::shared_ptr<DrmDisplayPipeline>, hwc2_display_t>
+      display_handles_;
+
+  std::string dump_string_;
+
+  std::map<hwc2_display_t, bool> deferred_hotplug_events_;
+  std::vector<hwc2_display_t> displays_for_removal_list_;
+
+  uint32_t last_display_handle_ = kPrimaryDisplay;
+};
+}  // namespace android
\ No newline at end of file
diff --git a/drm/DrmPlane.cpp b/drm/DrmPlane.cpp
index 19b7609..310e67b 100644
--- a/drm/DrmPlane.cpp
+++ b/drm/DrmPlane.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-drm-plane"
+#define LOG_TAG "drmhwc"
 
 #include "DrmPlane.h"
 
diff --git a/drm/DrmProperty.cpp b/drm/DrmProperty.cpp
index 938b3ad..031918a 100644
--- a/drm/DrmProperty.cpp
+++ b/drm/DrmProperty.cpp
@@ -15,7 +15,7 @@
  */
 
 // NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
-#define LOG_TAG "hwc-drm-property"
+#define LOG_TAG "drmhwc"
 
 #include "DrmProperty.h"
 
diff --git a/drm/ResourceManager.cpp b/drm/ResourceManager.cpp
index a6e9fc2..5ac80c4 100644
--- a/drm/ResourceManager.cpp
+++ b/drm/ResourceManager.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-resource-manager"
+#define LOG_TAG "drmhwc"
 
 #include "ResourceManager.h"
 
@@ -39,6 +39,10 @@ ResourceManager::ResourceManager(
   uevent_listener_ = UEventListener::CreateInstance();
 }
 
+ResourceManager::~ResourceManager() {
+  uevent_listener_->StopThread();
+}
+
 void ResourceManager::Init() {
   if (initialized_) {
     ALOGE("Already initialized");
diff --git a/drm/ResourceManager.h b/drm/ResourceManager.h
index 20e84a9..9a2652c 100644
--- a/drm/ResourceManager.h
+++ b/drm/ResourceManager.h
@@ -34,9 +34,9 @@ enum class CtmHandling {
 class PipelineToFrontendBindingInterface {
  public:
   virtual ~PipelineToFrontendBindingInterface() = default;
-  virtual bool BindDisplay(std::shared_ptr<DrmDisplayPipeline>);
-  virtual bool UnbindDisplay(std::shared_ptr<DrmDisplayPipeline>);
-  virtual void FinalizeDisplayBinding();
+  virtual bool BindDisplay(std::shared_ptr<DrmDisplayPipeline>) = 0;
+  virtual bool UnbindDisplay(std::shared_ptr<DrmDisplayPipeline>) = 0;
+  virtual void FinalizeDisplayBinding() = 0;
 };
 
 class ResourceManager {
@@ -47,7 +47,7 @@ class ResourceManager {
   ResourceManager &operator=(const ResourceManager &) = delete;
   ResourceManager(const ResourceManager &&) = delete;
   ResourceManager &&operator=(const ResourceManager &&) = delete;
-  ~ResourceManager() = default;
+  ~ResourceManager();
 
   void Init();
 
diff --git a/drm/UEventListener.cpp b/drm/UEventListener.cpp
index a05ec65..f69481a 100644
--- a/drm/UEventListener.cpp
+++ b/drm/UEventListener.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-uevent-listener"
+#define LOG_TAG "drmhwc"
 
 #include "UEventListener.h"
 
@@ -24,6 +24,10 @@
 
 namespace android {
 
+void UEventListener::StopThread() {
+  uevent_->Stop();
+}
+
 auto UEventListener::CreateInstance() -> std::shared_ptr<UEventListener> {
   auto uel = std::shared_ptr<UEventListener>(new UEventListener());
 
@@ -61,4 +65,5 @@ void UEventListener::ThreadFn(const std::shared_ptr<UEventListener> &uel) {
 
   ALOGI("UEvent thread exit");
 }
+
 }  // namespace android
diff --git a/drm/UEventListener.h b/drm/UEventListener.h
index 4f2be7c..f26c465 100644
--- a/drm/UEventListener.h
+++ b/drm/UEventListener.h
@@ -32,6 +32,8 @@ class UEventListener {
     hotplug_handler_ = std::move(hotplug_handler);
   }
 
+  void StopThread();
+
  private:
   UEventListener() = default;
 
diff --git a/drm/VSyncWorker.cpp b/drm/VSyncWorker.cpp
index 10d48e3..963a37b 100644
--- a/drm/VSyncWorker.cpp
+++ b/drm/VSyncWorker.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-vsync-worker"
+#define LOG_TAG "drmhwc"
 
 #include "VSyncWorker.h"
 
diff --git a/drm/meson.build b/drm/meson.build
index 7bef11a..47a45cc 100644
--- a/drm/meson.build
+++ b/drm/meson.build
@@ -6,6 +6,7 @@ src_common += files(
     'DrmDisplayPipeline.cpp',
     'DrmEncoder.cpp',
     'DrmFbImporter.cpp',
+    'DrmHwc.cpp',
     'DrmMode.cpp',
     'DrmPlane.cpp',
     'DrmProperty.cpp',
diff --git a/hwc2_device/DrmHwcTwo.cpp b/hwc2_device/DrmHwcTwo.cpp
index b151155..c120b63 100644
--- a/hwc2_device/DrmHwcTwo.cpp
+++ b/hwc2_device/DrmHwcTwo.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-drm-two"
+#define LOG_TAG "drmhwc"
 
 #include "DrmHwcTwo.h"
 
@@ -25,174 +25,6 @@
 
 namespace android {
 
-DrmHwcTwo::DrmHwcTwo() : resource_manager_(this){};
-
-/* Must be called after every display attach/detach cycle */
-void DrmHwcTwo::FinalizeDisplayBinding() {
-  if (displays_.count(kPrimaryDisplay) == 0) {
-    /* Primary display MUST always exist */
-    ALOGI("No pipelines available. Creating null-display for headless mode");
-    displays_[kPrimaryDisplay] = std::make_unique<
-        HwcDisplay>(kPrimaryDisplay, HWC2::DisplayType::Physical, this);
-    /* Initializes null-display */
-    displays_[kPrimaryDisplay]->SetPipeline({});
-  }
-
-  if (displays_[kPrimaryDisplay]->IsInHeadlessMode() &&
-      !display_handles_.empty()) {
-    /* Reattach first secondary display to take place of the primary */
-    auto pipe = display_handles_.begin()->first;
-    ALOGI("Primary display was disconnected, reattaching '%s' as new primary",
-          pipe->connector->Get()->GetName().c_str());
-    UnbindDisplay(pipe);
-    BindDisplay(pipe);
-  }
-
-  // Finally, send hotplug events to the client
-  for (auto &dhe : deferred_hotplug_events_) {
-    SendHotplugEventToClient(dhe.first, dhe.second);
-  }
-  deferred_hotplug_events_.clear();
-
-  /* Wait 0.2s before removing the displays to flush pending HWC2 transactions
-   */
-  auto &mutex = GetResMan().GetMainLock();
-  mutex.unlock();
-  const int kTimeForSFToDisposeDisplayUs = 200000;
-  usleep(kTimeForSFToDisposeDisplayUs);
-  mutex.lock();
-  for (auto handle : displays_for_removal_list_) {
-    displays_.erase(handle);
-  }
-}
-
-bool DrmHwcTwo::BindDisplay(std::shared_ptr<DrmDisplayPipeline> pipeline) {
-  if (display_handles_.count(pipeline) != 0) {
-    ALOGE("%s, pipeline is already used by another display, FIXME!!!: %p",
-          __func__, pipeline.get());
-    return false;
-  }
-
-  uint32_t disp_handle = kPrimaryDisplay;
-
-  if (displays_.count(kPrimaryDisplay) != 0 &&
-      !displays_[kPrimaryDisplay]->IsInHeadlessMode()) {
-    disp_handle = ++last_display_handle_;
-  }
-
-  if (displays_.count(disp_handle) == 0) {
-    auto disp = std::make_unique<HwcDisplay>(disp_handle,
-                                             HWC2::DisplayType::Physical, this);
-    displays_[disp_handle] = std::move(disp);
-  }
-
-  ALOGI("Attaching pipeline '%s' to the display #%d%s",
-        pipeline->connector->Get()->GetName().c_str(), (int)disp_handle,
-        disp_handle == kPrimaryDisplay ? " (Primary)" : "");
-
-  displays_[disp_handle]->SetPipeline(pipeline);
-  display_handles_[pipeline] = disp_handle;
-
-  return true;
-}
-
-bool DrmHwcTwo::UnbindDisplay(std::shared_ptr<DrmDisplayPipeline> pipeline) {
-  if (display_handles_.count(pipeline) == 0) {
-    ALOGE("%s, can't find the display, pipeline: %p", __func__, pipeline.get());
-    return false;
-  }
-  auto handle = display_handles_[pipeline];
-  display_handles_.erase(pipeline);
-
-  ALOGI("Detaching the pipeline '%s' from the display #%i%s",
-        pipeline->connector->Get()->GetName().c_str(), (int)handle,
-        handle == kPrimaryDisplay ? " (Primary)" : "");
-
-  if (displays_.count(handle) == 0) {
-    ALOGE("%s, can't find the display, handle: %" PRIu64, __func__, handle);
-    return false;
-  }
-  displays_[handle]->SetPipeline({});
-
-  /* We must defer display disposal and removal, since it may still have pending
-   * HWC_API calls scheduled and waiting until ueventlistener thread releases
-   * main lock, otherwise transaction may fail and SF may crash
-   */
-  if (handle != kPrimaryDisplay) {
-    displays_for_removal_list_.emplace_back(handle);
-  }
-  return true;
-}
-
-HWC2::Error DrmHwcTwo::CreateVirtualDisplay(
-    uint32_t width, uint32_t height,
-    int32_t *format,  // NOLINT(readability-non-const-parameter)
-    hwc2_display_t *display) {
-  ALOGI("Creating virtual display %dx%d format %d", width, height, *format);
-
-  auto virtual_pipeline = resource_manager_.GetVirtualDisplayPipeline();
-  if (!virtual_pipeline)
-    return HWC2::Error::Unsupported;
-
-  *display = ++last_display_handle_;
-  auto disp = std::make_unique<HwcDisplay>(*display, HWC2::DisplayType::Virtual,
-                                           this);
-
-  disp->SetVirtualDisplayResolution(width, height);
-  disp->SetPipeline(virtual_pipeline);
-  displays_[*display] = std::move(disp);
-  return HWC2::Error::None;
-}
-
-HWC2::Error DrmHwcTwo::DestroyVirtualDisplay(hwc2_display_t display) {
-  ALOGI("Destroying virtual display %" PRIu64, display);
-
-  if (displays_.count(display) == 0) {
-    ALOGE("Trying to destroy non-existent display %" PRIu64, display);
-    return HWC2::Error::BadDisplay;
-  }
-
-  displays_[display]->SetPipeline({});
-
-  /* Wait 0.2s before removing the displays to flush pending HWC2 transactions
-   */
-  auto &mutex = GetResMan().GetMainLock();
-  mutex.unlock();
-  const int kTimeForSFToDisposeDisplayUs = 200000;
-  usleep(kTimeForSFToDisposeDisplayUs);
-  mutex.lock();
-
-  displays_.erase(display);
-
-  return HWC2::Error::None;
-}
-
-void DrmHwcTwo::Dump(uint32_t *outSize, char *outBuffer) {
-  if (outBuffer != nullptr) {
-    auto copied_bytes = mDumpString.copy(outBuffer, *outSize);
-    *outSize = static_cast<uint32_t>(copied_bytes);
-    return;
-  }
-
-  std::stringstream output;
-
-  output << "-- drm_hwcomposer --\n\n";
-
-  for (auto &disp : displays_)
-    output << disp.second->Dump();
-
-  mDumpString = output.str();
-  *outSize = static_cast<uint32_t>(mDumpString.size());
-}
-
-uint32_t DrmHwcTwo::GetMaxVirtualDisplayCount() {
-  auto writeback_count = resource_manager_.GetWritebackConnectorsCount();
-  writeback_count = std::min(writeback_count, 1U);
-  /* Currently, only 1 virtual display is supported. Other cases need testing */
-  ALOGI("Max virtual display count: %d", writeback_count);
-  return writeback_count;
-}
-
 HWC2::Error DrmHwcTwo::RegisterCallback(int32_t descriptor,
                                         hwc2_callback_data_t data,
                                         hwc2_function_pointer_t function) {
@@ -200,13 +32,13 @@ HWC2::Error DrmHwcTwo::RegisterCallback(int32_t descriptor,
     case HWC2::Callback::Hotplug: {
       hotplug_callback_ = std::make_pair(HWC2_PFN_HOTPLUG(function), data);
       if (function != nullptr) {
-        resource_manager_.Init();
+        GetResMan().Init();
       } else {
-        resource_manager_.DeInit();
+        GetResMan().DeInit();
         /* Headless display may still be here. Remove it! */
-        if (displays_.count(kPrimaryDisplay) != 0) {
-          displays_[kPrimaryDisplay]->Deinit();
-          displays_.erase(kPrimaryDisplay);
+        if (Displays().count(kPrimaryDisplay) != 0) {
+          Displays()[kPrimaryDisplay]->Deinit();
+          Displays().erase(kPrimaryDisplay);
         }
       }
       break;
@@ -237,15 +69,15 @@ HWC2::Error DrmHwcTwo::RegisterCallback(int32_t descriptor,
 }
 
 void DrmHwcTwo::SendHotplugEventToClient(hwc2_display_t displayid,
-                                         bool connected) const {
+                                         bool connected) {
   auto hc = hotplug_callback_;
   if (hc.first != nullptr && hc.second != nullptr) {
     /* For some reason HWC Service will call HWC2 API in hotplug callback
      * handler. This is the reason we're using recursive mutex.
      */
     hc.first(hc.second, displayid,
-             connected == DRM_MODE_CONNECTED ? HWC2_CONNECTION_CONNECTED
-                                             : HWC2_CONNECTION_DISCONNECTED);
+             connected ? HWC2_CONNECTION_CONNECTED
+                       : HWC2_CONNECTION_DISCONNECTED);
   }
 }
 
@@ -283,4 +115,11 @@ void DrmHwcTwo::SendVsyncPeriodTimingChangedEventToClient(
 #endif
 }
 
+void DrmHwcTwo::SendRefreshEventToClient(hwc2_display_t displayid) {
+  if (refresh_callback_.first != nullptr &&
+      refresh_callback_.second != nullptr) {
+    refresh_callback_.first(refresh_callback_.second, displayid);
+  }
+}
+
 }  // namespace android
diff --git a/hwc2_device/DrmHwcTwo.h b/hwc2_device/DrmHwcTwo.h
index 8701feb..b3ca0f8 100644
--- a/hwc2_device/DrmHwcTwo.h
+++ b/hwc2_device/DrmHwcTwo.h
@@ -18,16 +18,28 @@
 
 #include <hardware/hwcomposer2.h>
 
-#include "drm/ResourceManager.h"
-#include "hwc2_device/HwcDisplay.h"
+#include "drm/DrmHwc.h"
 
 namespace android {
 
-class DrmHwcTwo : public PipelineToFrontendBindingInterface {
+class DrmHwcTwo : public DrmHwc {
  public:
-  DrmHwcTwo();
+  DrmHwcTwo() = default;
   ~DrmHwcTwo() override = default;
 
+  HWC2::Error RegisterCallback(int32_t descriptor, hwc2_callback_data_t data,
+                               hwc2_function_pointer_t function);
+
+  // DrmHwc
+  void SendVsyncEventToClient(hwc2_display_t displayid, int64_t timestamp,
+                              uint32_t vsync_period) const override;
+  void SendVsyncPeriodTimingChangedEventToClient(
+      hwc2_display_t displayid, int64_t timestamp) const override;
+  void SendRefreshEventToClient(uint64_t displayid) override;
+  void SendHotplugEventToClient(hwc2_display_t displayid,
+                                bool connected) override;
+
+ private:
   std::pair<HWC2_PFN_HOTPLUG, hwc2_callback_data_t> hotplug_callback_{};
   std::pair<HWC2_PFN_VSYNC, hwc2_callback_data_t> vsync_callback_{};
 #if __ANDROID_API__ > 29
@@ -36,53 +48,5 @@ class DrmHwcTwo : public PipelineToFrontendBindingInterface {
       period_timing_changed_callback_{};
 #endif
   std::pair<HWC2_PFN_REFRESH, hwc2_callback_data_t> refresh_callback_{};
-
-  // Device functions
-  HWC2::Error CreateVirtualDisplay(uint32_t width, uint32_t height,
-                                   int32_t *format, hwc2_display_t *display);
-  HWC2::Error DestroyVirtualDisplay(hwc2_display_t display);
-  void Dump(uint32_t *outSize, char *outBuffer);
-  uint32_t GetMaxVirtualDisplayCount();
-  HWC2::Error RegisterCallback(int32_t descriptor, hwc2_callback_data_t data,
-                               hwc2_function_pointer_t function);
-
-  auto GetDisplay(hwc2_display_t display_handle) {
-    return displays_.count(display_handle) != 0
-               ? displays_[display_handle].get()
-               : nullptr;
-  }
-
-  auto &GetResMan() {
-    return resource_manager_;
-  }
-
-  void ScheduleHotplugEvent(hwc2_display_t displayid, bool connected) {
-    deferred_hotplug_events_[displayid] = connected;
-  }
-
-  // PipelineToFrontendBindingInterface
-  bool BindDisplay(std::shared_ptr<DrmDisplayPipeline> pipeline) override;
-  bool UnbindDisplay(std::shared_ptr<DrmDisplayPipeline> pipeline) override;
-  void FinalizeDisplayBinding() override;
-
-  void SendVsyncEventToClient(hwc2_display_t displayid, int64_t timestamp,
-                              uint32_t vsync_period) const;
-  void SendVsyncPeriodTimingChangedEventToClient(hwc2_display_t displayid,
-                                                 int64_t timestamp) const;
-
- private:
-  void SendHotplugEventToClient(hwc2_display_t displayid, bool connected) const;
-
-  ResourceManager resource_manager_;
-  std::map<hwc2_display_t, std::unique_ptr<HwcDisplay>> displays_;
-  std::map<std::shared_ptr<DrmDisplayPipeline>, hwc2_display_t>
-      display_handles_;
-
-  std::string mDumpString;
-
-  std::map<hwc2_display_t, bool> deferred_hotplug_events_;
-  std::vector<hwc2_display_t> displays_for_removal_list_;
-
-  uint32_t last_display_handle_ = kPrimaryDisplay;
 };
 }  // namespace android
diff --git a/hwc2_device/HwcDisplay.cpp b/hwc2_device/HwcDisplay.cpp
index 6f08c33..36333d2 100644
--- a/hwc2_device/HwcDisplay.cpp
+++ b/hwc2_device/HwcDisplay.cpp
@@ -14,15 +14,15 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-display"
+#define LOG_TAG "drmhwc"
 #define ATRACE_TAG ATRACE_TAG_GRAPHICS
 
 #include "HwcDisplay.h"
 
-#include "DrmHwcTwo.h"
 #include "backend/Backend.h"
 #include "backend/BackendManager.h"
 #include "bufferinfo/BufferInfoGetter.h"
+#include "drm/DrmHwc.h"
 #include "utils/log.h"
 #include "utils/properties.h"
 
@@ -66,8 +66,8 @@ std::string HwcDisplay::Dump() {
 }
 
 HwcDisplay::HwcDisplay(hwc2_display_t handle, HWC2::DisplayType type,
-                       DrmHwcTwo *hwc2)
-    : hwc2_(hwc2), handle_(handle), type_(type), client_layer_(this) {
+                       DrmHwc *hwc)
+    : hwc_(hwc), handle_(handle), type_(type), client_layer_(this) {
   if (type_ == HWC2::DisplayType::Virtual) {
     writeback_layer_ = std::make_unique<HwcLayer>(this);
   }
@@ -85,7 +85,9 @@ void HwcDisplay::SetColorMarixToIdentity() {
   color_transform_hint_ = HAL_COLOR_TRANSFORM_IDENTITY;
 }
 
-HwcDisplay::~HwcDisplay() = default;
+HwcDisplay::~HwcDisplay() {
+  Deinit();
+};
 
 void HwcDisplay::SetPipeline(std::shared_ptr<DrmDisplayPipeline> pipeline) {
   Deinit();
@@ -94,9 +96,9 @@ void HwcDisplay::SetPipeline(std::shared_ptr<DrmDisplayPipeline> pipeline) {
 
   if (pipeline_ != nullptr || handle_ == kPrimaryDisplay) {
     Init();
-    hwc2_->ScheduleHotplugEvent(handle_, /*connected = */ true);
+    hwc_->ScheduleHotplugEvent(handle_, /*connected = */ true);
   } else {
-    hwc2_->ScheduleHotplugEvent(handle_, /*connected = */ false);
+    hwc_->ScheduleHotplugEvent(handle_, /*connected = */ false);
   }
 }
 
@@ -131,6 +133,8 @@ void HwcDisplay::Deinit() {
   }
 
   if (vsync_worker_) {
+    // TODO: There should be a mechanism to wait for this worker to complete,
+    // otherwise there is a race condition while destructing the HwcDisplay.
     vsync_worker_->StopThread();
     vsync_worker_ = {};
   }
@@ -144,11 +148,11 @@ HWC2::Error HwcDisplay::Init() {
   auto vsw_callbacks = (VSyncWorkerCallbacks){
       .out_event =
           [this](int64_t timestamp) {
-            const std::unique_lock lock(hwc2_->GetResMan().GetMainLock());
+            const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
             if (vsync_event_en_) {
               uint32_t period_ns{};
               GetDisplayVsyncPeriod(&period_ns);
-              hwc2_->SendVsyncEventToClient(handle_, timestamp, period_ns);
+              hwc_->SendVsyncEventToClient(handle_, timestamp, period_ns);
             }
             if (vsync_tracking_en_) {
               last_vsync_ts_ = timestamp;
@@ -178,12 +182,8 @@ HWC2::Error HwcDisplay::Init() {
       ALOGE("Failed to set backend for d=%d %d\n", int(handle_), ret);
       return HWC2::Error::BadDisplay;
     }
-    auto flatcbk = (struct FlatConCallbacks){.trigger = [this]() {
-      if (hwc2_->refresh_callback_.first != nullptr &&
-          hwc2_->refresh_callback_.second != nullptr)
-        hwc2_->refresh_callback_.first(hwc2_->refresh_callback_.second,
-                                       handle_);
-    }};
+    auto flatcbk = (struct FlatConCallbacks){
+        .trigger = [this]() { hwc_->SendRefreshEventToClient(handle_); }};
     flatcon_ = FlatteningController::CreateInstance(flatcbk);
   }
 
@@ -310,7 +310,6 @@ HWC2::Error HwcDisplay::GetDisplayAttribute(hwc2_config_t config,
 
   static const int32_t kUmPerInch = 25400;
   auto mm_width = configs_.mm_width;
-  auto mm_height = configs_.mm_height;
   auto attribute = static_cast<HWC2::Attribute>(attribute_in);
   switch (attribute) {
     case HWC2::Attribute::Width:
@@ -323,18 +322,17 @@ HWC2::Error HwcDisplay::GetDisplayAttribute(hwc2_config_t config,
       // in nanoseconds
       *value = static_cast<int>(1E9 / hwc_config.mode.GetVRefresh());
       break;
+    case HWC2::Attribute::DpiY:
+      // ideally this should be vdisplay/mm_heigth, however mm_height
+      // comes from edid parsing and is highly unreliable. Viewing the
+      // rarity of anisotropic displays, falling back to a single value
+      // for dpi yield more correct output.
     case HWC2::Attribute::DpiX:
       // Dots per 1000 inches
       *value = mm_width ? int(hwc_config.mode.GetRawMode().hdisplay *
                               kUmPerInch / mm_width)
                         : -1;
       break;
-    case HWC2::Attribute::DpiY:
-      // Dots per 1000 inches
-      *value = mm_height ? int(hwc_config.mode.GetRawMode().vdisplay *
-                               kUmPerInch / mm_height)
-                         : -1;
-      break;
 #if __ANDROID_API__ > 29
     case HWC2::Attribute::ConfigGroup:
       /* Dispite ConfigGroup is a part of HWC2.4 API, framework
@@ -349,8 +347,8 @@ HWC2::Error HwcDisplay::GetDisplayAttribute(hwc2_config_t config,
   return HWC2::Error::None;
 }
 
-HWC2::Error HwcDisplay::GetDisplayConfigs(uint32_t *num_configs,
-                                          hwc2_config_t *configs) {
+HWC2::Error HwcDisplay::LegacyGetDisplayConfigs(uint32_t *num_configs,
+                                                hwc2_config_t *configs) {
   uint32_t idx = 0;
   for (auto &hwc_config : configs_.hwc_configs) {
     if (hwc_config.second.disabled) {
@@ -564,9 +562,9 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
     staged_mode_.reset();
     vsync_tracking_en_ = false;
     if (last_vsync_ts_ != 0) {
-      hwc2_->SendVsyncPeriodTimingChangedEventToClient(handle_,
-                                                       last_vsync_ts_ +
-                                                           prev_vperiod_ns);
+      hwc_->SendVsyncPeriodTimingChangedEventToClient(handle_,
+                                                      last_vsync_ts_ +
+                                                          prev_vperiod_ns);
     }
   }
 
@@ -731,7 +729,7 @@ bool HwcDisplay::CtmByGpu() {
   if (GetPipe().crtc->Get()->GetCtmProperty())
     return false;
 
-  if (GetHwc2()->GetResMan().GetCtmHandling() == CtmHandling::kDrmOrIgnore)
+  if (GetHwc()->GetResMan().GetCtmHandling() == CtmHandling::kDrmOrIgnore)
     return false;
 
   return true;
@@ -963,7 +961,7 @@ HWC2::Error HwcDisplay::GetDisplayCapabilities(uint32_t *outNumCapabilities,
   bool skip_ctm = false;
 
   // Skip client CTM if user requested DRM_OR_IGNORE
-  if (GetHwc2()->GetResMan().GetCtmHandling() == CtmHandling::kDrmOrIgnore)
+  if (GetHwc()->GetResMan().GetCtmHandling() == CtmHandling::kDrmOrIgnore)
     skip_ctm = true;
 
   // Skip client CTM if DRM can handle it
diff --git a/hwc2_device/HwcDisplay.h b/hwc2_device/HwcDisplay.h
index 13d4328..87d2da7 100644
--- a/hwc2_device/HwcDisplay.h
+++ b/hwc2_device/HwcDisplay.h
@@ -33,14 +33,14 @@
 namespace android {
 
 class Backend;
-class DrmHwcTwo;
+class DrmHwc;
 
 inline constexpr uint32_t kPrimaryDisplay = 0;
 
 // NOLINTNEXTLINE
 class HwcDisplay {
  public:
-  HwcDisplay(hwc2_display_t handle, HWC2::DisplayType type, DrmHwcTwo *hwc2);
+  HwcDisplay(hwc2_display_t handle, HWC2::DisplayType type, DrmHwc *hwc);
   HwcDisplay(const HwcDisplay &) = delete;
   ~HwcDisplay();
 
@@ -54,6 +54,10 @@ class HwcDisplay {
 
   std::string Dump();
 
+  const HwcDisplayConfigs &GetDisplayConfigs() const {
+    return configs_;
+  }
+
   // HWC Hooks
   HWC2::Error AcceptDisplayChanges();
   HWC2::Error CreateLayer(hwc2_layer_t *layer);
@@ -66,7 +70,8 @@ class HwcDisplay {
   HWC2::Error GetColorModes(uint32_t *num_modes, int32_t *modes);
   HWC2::Error GetDisplayAttribute(hwc2_config_t config, int32_t attribute,
                                   int32_t *value);
-  HWC2::Error GetDisplayConfigs(uint32_t *num_configs, hwc2_config_t *configs);
+  HWC2::Error LegacyGetDisplayConfigs(uint32_t *num_configs,
+                                      hwc2_config_t *configs);
   HWC2::Error GetDisplayName(uint32_t *size, char *name);
   HWC2::Error GetDisplayRequests(int32_t *display_requests,
                                  uint32_t *num_elements, hwc2_layer_t *layers,
@@ -149,8 +154,8 @@ class HwcDisplay {
   const Backend *backend() const;
   void set_backend(std::unique_ptr<Backend> backend);
 
-  auto GetHwc2() {
-    return hwc2_;
+  auto GetHwc() {
+    return hwc_;
   }
 
   std::map<hwc2_layer_t, HwcLayer> &layers() {
@@ -195,7 +200,7 @@ class HwcDisplay {
  private:
   HwcDisplayConfigs configs_;
 
-  DrmHwcTwo *const hwc2_;
+  DrmHwc *const hwc_;
 
   SharedFd present_fence_;
 
diff --git a/hwc2_device/HwcDisplayConfigs.cpp b/hwc2_device/HwcDisplayConfigs.cpp
index f6bf4a1..3645356 100644
--- a/hwc2_device/HwcDisplayConfigs.cpp
+++ b/hwc2_device/HwcDisplayConfigs.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-display-configs"
+#define LOG_TAG "drmhwc"
 
 #include "HwcDisplayConfigs.h"
 
diff --git a/hwc2_device/HwcLayer.cpp b/hwc2_device/HwcLayer.cpp
index 12da418..da4ce7c 100644
--- a/hwc2_device/HwcLayer.cpp
+++ b/hwc2_device/HwcLayer.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#define LOG_TAG "hwc-layer"
+#define LOG_TAG "drmhwc"
 
 #include "HwcLayer.h"
 
diff --git a/hwc2_device/hwc2_device.cpp b/hwc2_device/hwc2_device.cpp
index d4ee10d..28b6963 100644
--- a/hwc2_device/hwc2_device.cpp
+++ b/hwc2_device/hwc2_device.cpp
@@ -17,7 +17,7 @@
 // NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
 // #define LOG_NDEBUG 0 // Uncomment to see HWC2 API calls in logcat
 
-#define LOG_TAG "hwc2-device"
+#define LOG_TAG "drmhwc"
 
 #include <cinttypes>
 
@@ -177,8 +177,8 @@ static hwc2_function_pointer_t HookDevGetFunction(struct hwc2_device * /*dev*/,
                       int32_t *>);
     case HWC2::FunctionDescriptor::GetDisplayConfigs:
       return ToHook<HWC2_PFN_GET_DISPLAY_CONFIGS>(
-          DisplayHook<decltype(&HwcDisplay::GetDisplayConfigs),
-                      &HwcDisplay::GetDisplayConfigs, uint32_t *,
+          DisplayHook<decltype(&HwcDisplay::LegacyGetDisplayConfigs),
+                      &HwcDisplay::LegacyGetDisplayConfigs, uint32_t *,
                       hwc2_config_t *>);
     case HWC2::FunctionDescriptor::GetDisplayName:
       return ToHook<HWC2_PFN_GET_DISPLAY_NAME>(
diff --git a/hwc2_device/meson.build b/hwc2_device/meson.build
index 7e6b8f4..6a9a93a 100644
--- a/hwc2_device/meson.build
+++ b/hwc2_device/meson.build
@@ -6,14 +6,23 @@ src_hwc2_device = files(
     'HwcLayer.cpp',
 )
 
+drmhwc_hwc2_common = static_library(
+    'drm_hwc2',
+    src_hwc2_device,
+# TODO remove hwc2 flags from common code (backends needs rework)
+    cpp_args : common_cpp_flags + hwc2_cpp_flags,
+    dependencies : deps,
+    link_with: drmhwc_common,
+    include_directories: inc_include,
+)
+
 shared_library(
     'hwcomposer.drm',
-    src_hwc2_device,
     name_prefix : '',
     cpp_args : common_cpp_flags + hwc2_cpp_flags,
     dependencies : deps,
     install : true,
-    link_whole: drmhwc_common,
+    link_whole: [drmhwc_common, drmhwc_hwc2_common],
     install_dir : get_option('libdir') / 'hw',
     include_directories: inc_include,
-)
+)
\ No newline at end of file
diff --git a/hwc3/CommandResultWriter.h b/hwc3/CommandResultWriter.h
new file mode 100644
index 0000000..fa96f33
--- /dev/null
+++ b/hwc3/CommandResultWriter.h
@@ -0,0 +1,139 @@
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
+#include <unordered_map>
+#include <vector>
+
+#include "Utils.h"
+#include "aidl/android/hardware/graphics/composer3/CommandError.h"
+#include "aidl/android/hardware/graphics/composer3/CommandResultPayload.h"
+#include "aidl/android/hardware/graphics/composer3/PresentFence.h"
+#include "aidl/android/hardware/graphics/composer3/PresentOrValidate.h"
+#include "aidl/android/hardware/graphics/composer3/ReleaseFences.h"
+
+namespace aidl::android::hardware::graphics::composer3 {
+
+struct DisplayChanges {
+  std::optional<ChangedCompositionTypes> composition_changes;
+  std::optional<DisplayRequest> display_request_changes;
+
+  void AddLayerCompositionChange(int64_t display_id, int64_t layer_id,
+                                 Composition layer_composition) {
+    if (!composition_changes) {
+      composition_changes.emplace();
+      composition_changes->display = display_id;
+    }
+
+    ChangedCompositionLayer composition_change;
+    composition_change.layer = layer_id;
+    composition_change.composition = layer_composition;
+    composition_changes->layers.emplace_back(composition_change);
+  }
+
+  void ClearLayerCompositionChanges() {
+    composition_changes.reset();
+  }
+
+  bool HasAnyChanges() const {
+    return composition_changes.has_value() ||
+           display_request_changes.has_value();
+  }
+
+  void Reset() {
+    composition_changes.reset();
+    display_request_changes.reset();
+  }
+};
+
+class CommandResultWriter {
+ public:
+  explicit CommandResultWriter(std::vector<CommandResultPayload>* results)
+      : results_(results) {
+  }
+
+  bool HasError() const {
+    return has_error_;
+  }
+
+  void IncrementCommand() {
+    index_++;
+    has_error_ = false;
+  }
+
+  void AddError(hwc3::Error error) {
+    CommandError command_error;
+    command_error.errorCode = static_cast<int32_t>(error);
+    command_error.commandIndex = static_cast<int32_t>(index_);
+
+    results_->emplace_back(command_error);
+    has_error_ = true;
+  }
+
+  void AddPresentFence(int64_t display_id, ::android::base::unique_fd fence) {
+    if (!fence.ok()) {
+      return;
+    }
+
+    PresentFence present_fence;
+    present_fence.fence = ::ndk::ScopedFileDescriptor(fence.release());
+    present_fence.display = display_id;
+    results_->emplace_back(std::move(present_fence));
+  }
+
+  void AddReleaseFence(
+      int64_t display_id,
+      std::unordered_map<int64_t, ::android::base::unique_fd>& layer_fences) {
+    ReleaseFences release_fences;
+    release_fences.display = display_id;
+    for (auto& [layer, fence] : layer_fences) {
+      if (!fence.ok()) {
+        continue;
+      }
+
+      ReleaseFences::Layer layer_result;
+      layer_result.layer = layer;
+      layer_result.fence = ::ndk::ScopedFileDescriptor(fence.release());
+
+      release_fences.layers.emplace_back(std::move(layer_result));
+    }
+
+    results_->emplace_back(std::move(release_fences));
+  }
+
+  void AddChanges(const DisplayChanges& changes) {
+    if (changes.composition_changes) {
+      results_->emplace_back(*changes.composition_changes);
+    }
+    if (changes.display_request_changes) {
+      results_->emplace_back(*changes.display_request_changes);
+    }
+  }
+
+  void AddPresentOrValidateResult(int64_t display_id,
+                                  const PresentOrValidate::Result& pov_result) {
+    PresentOrValidate pov_command;
+    pov_command.display = display_id;
+    pov_command.result = pov_result;
+
+    results_->emplace_back(pov_command);
+  }
+
+ private:
+  size_t index_{0};
+  bool has_error_{false};
+  std::vector<CommandResultPayload>* results_{nullptr};
+};
+};  // namespace aidl::android::hardware::graphics::composer3
\ No newline at end of file
diff --git a/hwc3/Composer.cpp b/hwc3/Composer.cpp
new file mode 100644
index 0000000..4977a14
--- /dev/null
+++ b/hwc3/Composer.cpp
@@ -0,0 +1,83 @@
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
+#define ATRACE_TAG (ATRACE_TAG_GRAPHICS | ATRACE_TAG_HAL)
+
+#include "Composer.h"
+
+#include <android-base/logging.h>
+#include <android/binder_ibinder_platform.h>
+
+#include "hwc3/ComposerClient.h"
+#include "hwc3/Utils.h"
+#include "utils/log.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+ndk::ScopedAStatus Composer::createClient(
+    std::shared_ptr<IComposerClient>* out_client) {
+  DEBUG_FUNC();
+
+  if (!client_.expired()) {
+    return ToBinderStatus(hwc3::Error::kNoResources);
+  }
+
+  auto client = ndk::SharedRefBase::make<ComposerClient>();
+  if (!client || !client->Init()) {
+    *out_client = nullptr;
+    return ToBinderStatus(hwc3::Error::kNoResources);
+  }
+
+  *out_client = client;
+  client_ = client;
+
+  return ndk::ScopedAStatus::ok();
+}
+
+binder_status_t Composer::dump(int fd, const char** /*args*/,
+                               uint32_t /*numArgs*/) {
+  std::stringstream output;
+  output << "hwc3-drm\n\n";
+
+  auto client_instance = client_.lock();
+  if (!client_instance) {
+    return STATUS_OK;
+  }
+
+  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast)
+  auto* client = static_cast<ComposerClient*>(client_instance.get());
+  output << client->Dump();
+
+  auto output_str = output.str();
+  write(fd, output_str.c_str(), output_str.size());
+  return STATUS_OK;
+}
+
+ndk::ScopedAStatus Composer::getCapabilities(std::vector<Capability>* caps) {
+  DEBUG_FUNC();
+  /* No capabilities advertised */
+  caps->clear();
+  return ndk::ScopedAStatus::ok();
+}
+
+::ndk::SpAIBinder Composer::createBinder() {
+  auto binder = BnComposer::createBinder();
+  AIBinder_setInheritRt(binder.get(), true);
+  return binder;
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hwc3/Composer.h b/hwc3/Composer.h
new file mode 100644
index 0000000..f6c2536
--- /dev/null
+++ b/hwc3/Composer.h
@@ -0,0 +1,44 @@
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
+#include <aidl/android/hardware/graphics/composer3/BnComposer.h>
+#include <utils/Mutex.h>
+
+#include <memory>
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class Composer : public BnComposer {
+ public:
+  Composer() = default;
+
+  binder_status_t dump(int fd, const char** args, uint32_t num_args) override;
+
+  // compser3 api
+  ndk::ScopedAStatus createClient(
+      std::shared_ptr<IComposerClient>* client) override;
+  ndk::ScopedAStatus getCapabilities(std::vector<Capability>* caps) override;
+
+ protected:
+  ::ndk::SpAIBinder createBinder() override;
+
+ private:
+  std::weak_ptr<IComposerClient> client_;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hwc3/ComposerClient.cpp b/hwc3/ComposerClient.cpp
new file mode 100644
index 0000000..f353abb
--- /dev/null
+++ b/hwc3/ComposerClient.cpp
@@ -0,0 +1,1366 @@
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
+#define ATRACE_TAG (ATRACE_TAG_GRAPHICS | ATRACE_TAG_HAL)
+
+#include "ComposerClient.h"
+
+#include <aidlcommonsupport/NativeHandle.h>
+#include <android-base/logging.h>
+#include <android/binder_ibinder_platform.h>
+#include <hardware/hwcomposer2.h>
+
+#include <cinttypes>
+#include <cmath>
+#include <memory>
+#include <unordered_map>
+#include <vector>
+
+#include "aidl/android/hardware/graphics/common/Transform.h"
+#include "aidl/android/hardware/graphics/composer3/ClientTarget.h"
+#include "aidl/android/hardware/graphics/composer3/Composition.h"
+#include "aidl/android/hardware/graphics/composer3/DisplayRequest.h"
+#include "aidl/android/hardware/graphics/composer3/IComposerClient.h"
+#include "aidl/android/hardware/graphics/composer3/PowerMode.h"
+#include "aidl/android/hardware/graphics/composer3/PresentOrValidate.h"
+#include "aidl/android/hardware/graphics/composer3/RenderIntent.h"
+#include "android/binder_auto_utils.h"
+#include "cutils/native_handle.h"
+#include "hardware/hwcomposer_defs.h"
+#include "hwc2_device/HwcDisplay.h"
+#include "hwc2_device/HwcDisplayConfigs.h"
+#include "hwc2_device/HwcLayer.h"
+#include "hwc3/DrmHwcThree.h"
+#include "hwc3/Utils.h"
+
+using ::android::HwcDisplay;
+using ::android::HwcDisplayConfigs;
+
+#include "utils/log.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+namespace {
+
+// clang-format off
+constexpr std::array<float, 16> kIdentityMatrix = {
+    1.0F, 0.0F, 0.0F, 0.0F,
+    0.0F, 1.0F, 0.0F, 0.0F,
+    0.0F, 0.0F, 1.0F, 0.0F,
+    0.0F, 0.0F, 0.0F, 1.0F,
+};
+// clang-format on
+
+}  // namespace
+
+ComposerClient::ComposerClient() {
+  DEBUG_FUNC();
+}
+
+bool ComposerClient::Init() {
+  DEBUG_FUNC();
+  composer_resources_ = ComposerResources::Create();
+  if (composer_resources_) {
+    hwc_ = std::make_unique<DrmHwcThree>(composer_resources_.get());
+  }
+  return composer_resources_ != nullptr;
+}
+
+ComposerClient::~ComposerClient() {
+  DEBUG_FUNC();
+  {
+    // First Deinit the displays to start shutting down the Display's dependent
+    // threads such as VSyncWorker.
+    const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+    hwc_->DeinitDisplays();
+  }
+  // Sleep to wait for threads to complete and exit.
+  const int time_for_threads_to_exit_us = 200000;
+  usleep(time_for_threads_to_exit_us);
+  {
+    // Hold the lock while destructing the hwc_ and the objects that it owns.
+    const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+    hwc_.reset();
+  }
+  LOG(DEBUG) << "removed composer client";
+}
+
+ndk::ScopedAStatus ComposerClient::createLayer(int64_t display_id,
+                                               int32_t buffer_slot_count,
+                                               int64_t* layer_id) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  hwc2_layer_t hwc2_layer_id = 0;
+  auto err = Hwc2toHwc3Error(display->CreateLayer(&hwc2_layer_id));
+  if (err != hwc3::Error::kNone) {
+    return ToBinderStatus(err);
+  }
+
+  const int64_t created_layer_id = Hwc2LayerToHwc3(hwc2_layer_id);
+  err = composer_resources_->AddLayer(display_id, created_layer_id,
+                                      buffer_slot_count);
+  if (err != hwc3::Error::kNone) {
+    destroyLayer(display_id, created_layer_id);
+    return ToBinderStatus(err);
+  }
+
+  *layer_id = created_layer_id;
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::createVirtualDisplay(
+    int32_t width, int32_t height, AidlPixelFormat format_hint,
+    int32_t output_buffer_slot_count, VirtualDisplay* out_display) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+
+  hwc2_display_t hwc2_display_id = 0;
+  // TODO: Format is currently not used in drm_hwcomposer.
+  int32_t hwc2_format = 0;
+  auto err = Hwc2toHwc3Error(hwc_->CreateVirtualDisplay(width, height,
+                                                        &hwc2_format,
+                                                        &hwc2_display_id));
+  if (err != hwc3::Error::kNone) {
+    return ToBinderStatus(err);
+  }
+
+  const int64_t created_display_id = Hwc2DisplayToHwc3(hwc2_display_id);
+  err = composer_resources_->AddVirtualDisplay(hwc2_display_id,
+                                               output_buffer_slot_count);
+  if (err != hwc3::Error::kNone) {
+    hwc_->DestroyVirtualDisplay(hwc2_display_id);
+    return ToBinderStatus(err);
+  }
+
+  out_display->display = created_display_id;
+  out_display->format = format_hint;
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::destroyLayer(int64_t display_id,
+                                                int64_t layer_id) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  auto err = Hwc2toHwc3Error(display->DestroyLayer(Hwc3LayerToHwc2(layer_id)));
+  if (err != hwc3::Error::kNone) {
+    return ToBinderStatus(err);
+  }
+
+  err = composer_resources_->RemoveLayer(display_id, layer_id);
+  return ToBinderStatus(err);
+}
+
+ndk::ScopedAStatus ComposerClient::destroyVirtualDisplay(int64_t display_id) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  auto err = Hwc2toHwc3Error(hwc_->DestroyVirtualDisplay(display_id));
+  return ToBinderStatus(err);
+}
+
+hwc3::Error ComposerClient::ValidateDisplayInternal(
+    HwcDisplay& display, std::vector<int64_t>* out_changed_layers,
+    std::vector<Composition>* out_composition_types,
+    int32_t* out_display_request_mask,
+    std::vector<int64_t>* out_requested_layers,
+    std::vector<int32_t>* out_request_masks,
+    ClientTargetProperty* /*out_client_target_property*/,
+    DimmingStage* /*out_dimming_stage*/) {
+  DEBUG_FUNC();
+
+  uint32_t num_types = 0;
+  uint32_t num_requests = 0;
+  const HWC2::Error hwc2_error = display.ValidateDisplay(&num_types,
+                                                         &num_requests);
+
+  /* Check if display has pending changes and no errors */
+  if (hwc2_error != HWC2::Error::None &&
+      hwc2_error != HWC2::Error::HasChanges) {
+    return Hwc2toHwc3Error(hwc2_error);
+  }
+
+  std::vector<hwc2_layer_t> hwc_changed_layers(num_types);
+  std::vector<int32_t> hwc_composition_types(num_types);
+  hwc3::Error error = Hwc2toHwc3Error(
+      display.GetChangedCompositionTypes(&num_types, hwc_changed_layers.data(),
+                                         hwc_composition_types.data()));
+  if (error != hwc3::Error::kNone) {
+    return error;
+  }
+
+  int32_t display_reqs = 0;
+  out_request_masks->resize(num_requests);
+  std::vector<hwc2_layer_t> hwc_requested_layers(num_requests);
+  error = Hwc2toHwc3Error(
+      display.GetDisplayRequests(&display_reqs, &num_requests,
+                                 hwc_requested_layers.data(),
+                                 out_request_masks->data()));
+  if (error != hwc3::Error::kNone) {
+    return error;
+  }
+
+  for (const auto& layer : hwc_changed_layers) {
+    out_changed_layers->emplace_back(Hwc2LayerToHwc3(layer));
+  }
+  for (const auto& type : hwc_composition_types) {
+    out_composition_types->emplace_back(Hwc2CompositionTypeToHwc3(type));
+  }
+  for (const auto& layer : hwc_requested_layers) {
+    out_requested_layers->emplace_back(Hwc2LayerToHwc3(layer));
+  }
+  *out_display_request_mask = display_reqs;
+
+  /* Client target property/dimming stage unsupported */
+  return hwc3::Error::kNone;
+}
+
+hwc3::Error ComposerClient::PresentDisplayInternal(
+    uint64_t display_id, ::android::base::unique_fd& out_display_fence,
+    std::unordered_map<int64_t, ::android::base::unique_fd>&
+        out_release_fences) {
+  DEBUG_FUNC();
+  auto* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return hwc3::Error::kBadDisplay;
+  }
+
+  if (composer_resources_->MustValidateDisplay(display_id)) {
+    return hwc3::Error::kNotValidated;
+  }
+
+  int32_t present_fence = -1;
+  auto error = Hwc2toHwc3Error(display->PresentDisplay(&present_fence));
+  if (error != hwc3::Error::kNone) {
+    return error;
+  }
+  out_display_fence.reset(present_fence);
+
+  uint32_t release_fence_count = 0;
+  error = Hwc2toHwc3Error(
+      display->GetReleaseFences(&release_fence_count, nullptr, nullptr));
+  if (error != hwc3::Error::kNone) {
+    return error;
+  }
+
+  std::vector<hwc2_layer_t> hwc_layers(release_fence_count);
+  std::vector<int32_t> hwc_fences(release_fence_count);
+  error = Hwc2toHwc3Error(display->GetReleaseFences(&release_fence_count,
+                                                    hwc_layers.data(),
+                                                    hwc_fences.data()));
+  if (error != hwc3::Error::kNone) {
+    return error;
+  }
+
+  for (size_t i = 0; i < hwc_layers.size(); i++) {
+    auto layer = Hwc2LayerToHwc3(hwc_layers[i]);
+    out_release_fences[layer] = ::android::base::unique_fd{hwc_fences[i]};
+  }
+
+  return hwc3::Error::kNone;
+}
+
+::android::HwcDisplay* ComposerClient::GetDisplay(uint64_t display_id) {
+  return hwc_->GetDisplay(display_id);
+}
+
+void ComposerClient::DispatchLayerCommand(int64_t display_id,
+                                          const LayerCommand& command) {
+  auto* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
+    return;
+  }
+
+  auto* layer = display->get_layer(command.layer);
+  if (layer == nullptr) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadLayer);
+    return;
+  }
+
+  HwcLayerWrapper layer_wrapper{command.layer, layer};
+  if (command.buffer) {
+    ExecuteSetLayerBuffer(display_id, layer_wrapper, *command.buffer);
+  }
+  if (command.blendMode) {
+    ExecuteSetLayerBlendMode(display_id, layer_wrapper, *command.blendMode);
+  }
+  if (command.composition) {
+    ExecuteSetLayerComposition(display_id, layer_wrapper, *command.composition);
+  }
+  if (command.dataspace) {
+    ExecuteSetLayerDataspace(display_id, layer_wrapper, *command.dataspace);
+  }
+  if (command.displayFrame) {
+    ExecuteSetLayerDisplayFrame(display_id, layer_wrapper,
+                                *command.displayFrame);
+  }
+  if (command.planeAlpha) {
+    ExecuteSetLayerPlaneAlpha(display_id, layer_wrapper, *command.planeAlpha);
+  }
+  if (command.sourceCrop) {
+    ExecuteSetLayerSourceCrop(display_id, layer_wrapper, *command.sourceCrop);
+  }
+  if (command.transform) {
+    ExecuteSetLayerTransform(display_id, layer_wrapper, *command.transform);
+  }
+  if (command.z) {
+    ExecuteSetLayerZOrder(display_id, layer_wrapper, *command.z);
+  }
+  if (command.brightness) {
+    ExecuteSetLayerBrightness(display_id, layer_wrapper, *command.brightness);
+  }
+
+  // Some unsupported functionality returns kUnsupported, and others
+  // are just a no-op.
+  // TODO: Audit whether some of these should actually return kUnsupported
+  // instead.
+  if (command.sidebandStream) {
+    cmd_result_writer_->AddError(hwc3::Error::kUnsupported);
+  }
+  // TODO: Blocking region handling missing.
+  // TODO: Layer surface damage.
+  // TODO: Layer visible region.
+  // TODO: Per-frame metadata.
+  // TODO: Layer color transform.
+  // TODO: Layer cursor position.
+  // TODO: Layer color.
+}
+
+void ComposerClient::ExecuteDisplayCommand(const DisplayCommand& command) {
+  const int64_t display_id = command.display;
+  if (hwc_->GetDisplay(display_id) == nullptr) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
+    return;
+  }
+
+  for (const auto& layer_cmd : command.layers) {
+    DispatchLayerCommand(command.display, layer_cmd);
+  }
+
+  if (command.brightness) {
+    ExecuteSetDisplayBrightness(command.display, *command.brightness);
+  }
+  if (command.colorTransformMatrix) {
+    ExecuteSetDisplayColorTransform(command.display,
+                                    *command.colorTransformMatrix);
+  }
+  if (command.clientTarget) {
+    ExecuteSetDisplayClientTarget(command.display, *command.clientTarget);
+  }
+  if (command.virtualDisplayOutputBuffer) {
+    ExecuteSetDisplayOutputBuffer(command.display,
+                                  *command.virtualDisplayOutputBuffer);
+  }
+  if (command.validateDisplay) {
+    ExecuteValidateDisplay(command.display, command.expectedPresentTime);
+  }
+  if (command.acceptDisplayChanges) {
+    ExecuteAcceptDisplayChanges(command.display);
+  }
+  if (command.presentDisplay) {
+    ExecutePresentDisplay(command.display);
+  }
+  if (command.presentOrValidateDisplay) {
+    ExecutePresentOrValidateDisplay(command.display,
+                                    command.expectedPresentTime);
+  }
+}
+
+ndk::ScopedAStatus ComposerClient::executeCommands(
+    const std::vector<DisplayCommand>& commands,
+    std::vector<CommandResultPayload>* results) {
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  DEBUG_FUNC();
+  cmd_result_writer_ = std::make_unique<CommandResultWriter>(results);
+  for (const auto& cmd : commands) {
+    ExecuteDisplayCommand(cmd);
+    cmd_result_writer_->IncrementCommand();
+  }
+  cmd_result_writer_.reset();
+
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getActiveConfig(int64_t display_id,
+                                                   int32_t* config) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  uint32_t hwc2_config = 0;
+  const hwc3::Error error = Hwc2toHwc3Error(
+      display->GetActiveConfig(&hwc2_config));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+  *config = Hwc2ConfigIdToHwc3(hwc2_config);
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getColorModes(
+    int64_t display_id, std::vector<ColorMode>* color_modes) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  uint32_t num_modes = 0;
+  auto error = Hwc2toHwc3Error(display->GetColorModes(&num_modes, nullptr));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  std::vector<int32_t> hwc2_color_modes(num_modes);
+  error = Hwc2toHwc3Error(
+      display->GetColorModes(&num_modes, hwc2_color_modes.data()));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  for (const auto& mode : hwc2_color_modes) {
+    color_modes->push_back(Hwc2ColorModeToHwc3(mode));
+  }
+
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getDataspaceSaturationMatrix(
+    common::Dataspace dataspace, std::vector<float>* matrix) {
+  DEBUG_FUNC();
+  if (dataspace != common::Dataspace::SRGB_LINEAR) {
+    return ToBinderStatus(hwc3::Error::kBadParameter);
+  }
+
+  matrix->clear();
+  matrix->insert(matrix->begin(), kIdentityMatrix.begin(),
+                 kIdentityMatrix.end());
+
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayAttribute(
+    int64_t display_id, int32_t config, DisplayAttribute attribute,
+    int32_t* value) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  const hwc3::Error error = Hwc2toHwc3Error(
+      display->GetDisplayAttribute(Hwc3ConfigIdToHwc2(config),
+                                   Hwc3DisplayAttributeToHwc2(attribute),
+                                   value));
+  return ToBinderStatus(error);
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayCapabilities(
+    int64_t display_id, std::vector<DisplayCapability>* caps) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  uint32_t num_capabilities = 0;
+  hwc3::Error error = Hwc2toHwc3Error(
+      display->GetDisplayCapabilities(&num_capabilities, nullptr));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  std::vector<uint32_t> out_caps(num_capabilities);
+  error = Hwc2toHwc3Error(
+      display->GetDisplayCapabilities(&num_capabilities, out_caps.data()));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  caps->reserve(num_capabilities);
+  for (const auto cap : out_caps) {
+    caps->emplace_back(Hwc2DisplayCapabilityToHwc3(cap));
+  }
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayConfigs(
+    int64_t display_id, std::vector<int32_t>* configs) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  uint32_t num_configs = 0;
+  hwc3::Error error = Hwc2toHwc3Error(
+      display->LegacyGetDisplayConfigs(&num_configs, nullptr));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  std::vector<hwc2_config_t> out_configs(num_configs);
+  error = Hwc2toHwc3Error(
+      display->LegacyGetDisplayConfigs(&num_configs, out_configs.data()));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  configs->reserve(num_configs);
+  for (const auto config : out_configs) {
+    configs->emplace_back(Hwc2ConfigIdToHwc3(config));
+  }
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayConnectionType(
+    int64_t display_id, DisplayConnectionType* type) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  uint32_t out_type = 0;
+  const hwc3::Error error = Hwc2toHwc3Error(
+      display->GetDisplayConnectionType(&out_type));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  *type = Hwc2DisplayConnectionTypeToHwc3(out_type);
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayIdentificationData(
+    int64_t display_id, DisplayIdentification* id) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  uint8_t port = 0;
+  uint32_t data_size = 0;
+  hwc3::Error error = Hwc2toHwc3Error(
+      display->GetDisplayIdentificationData(&port, &data_size, nullptr));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  id->data.resize(data_size);
+  error = Hwc2toHwc3Error(
+      display->GetDisplayIdentificationData(&port, &data_size,
+                                            id->data.data()));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  id->port = static_cast<int8_t>(port);
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayName(int64_t display_id,
+                                                  std::string* name) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  uint32_t size = 0;
+  auto error = Hwc2toHwc3Error(display->GetDisplayName(&size, nullptr));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  name->resize(size);
+  error = Hwc2toHwc3Error(display->GetDisplayName(&size, name->data()));
+  return ToBinderStatus(error);
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayVsyncPeriod(
+    int64_t display_id, int32_t* vsync_period) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  uint32_t hwc2_vsync_period = 0;
+  auto error = Hwc2toHwc3Error(
+      display->GetDisplayVsyncPeriod(&hwc2_vsync_period));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  *vsync_period = static_cast<int32_t>(hwc2_vsync_period);
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayedContentSample(
+    int64_t /*display_id*/, int64_t /*max_frames*/, int64_t /*timestamp*/,
+    DisplayContentSample* /*samples*/) {
+  DEBUG_FUNC();
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayedContentSamplingAttributes(
+    int64_t /*display_id*/, DisplayContentSamplingAttributes* /*attrs*/) {
+  DEBUG_FUNC();
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayPhysicalOrientation(
+    int64_t display_id, common::Transform* orientation) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  *orientation = common::Transform::NONE;
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getHdrCapabilities(int64_t display_id,
+                                                      HdrCapabilities* caps) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  /* No HDR capabilities */
+  caps->types.clear();
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getMaxVirtualDisplayCount(int32_t* count) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  *count = static_cast<int32_t>(hwc_->GetMaxVirtualDisplayCount());
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getPerFrameMetadataKeys(
+    int64_t /*display_id*/, std::vector<PerFrameMetadataKey>* /*keys*/) {
+  DEBUG_FUNC();
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getReadbackBufferAttributes(
+    int64_t /*display_id*/, ReadbackBufferAttributes* /*attrs*/) {
+  DEBUG_FUNC();
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getReadbackBufferFence(
+    int64_t /*display_id*/, ndk::ScopedFileDescriptor* /*acquireFence*/) {
+  DEBUG_FUNC();
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getRenderIntents(
+    int64_t display_id, ColorMode mode, std::vector<RenderIntent>* intents) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  const int32_t hwc2_color_mode = Hwc3ColorModeToHwc2(mode);
+  uint32_t out_num_intents = 0;
+  auto error = Hwc2toHwc3Error(
+      display->GetRenderIntents(hwc2_color_mode, &out_num_intents, nullptr));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  std::vector<int32_t> out_intents(out_num_intents);
+  error = Hwc2toHwc3Error(display->GetRenderIntents(hwc2_color_mode,
+                                                    &out_num_intents,
+                                                    out_intents.data()));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  intents->reserve(out_num_intents);
+  for (const auto intent : out_intents) {
+    intents->emplace_back(Hwc2RenderIntentToHwc3(intent));
+  }
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getSupportedContentTypes(
+    int64_t display_id, std::vector<ContentType>* types) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  uint32_t out_num_supported_types = 0;
+  auto error = Hwc2toHwc3Error(
+      display->GetSupportedContentTypes(&out_num_supported_types, nullptr));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  std::vector<uint32_t> out_supported_types(out_num_supported_types);
+  error = Hwc2toHwc3Error(
+      display->GetSupportedContentTypes(&out_num_supported_types,
+                                        out_supported_types.data()));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  for (const auto type : out_supported_types) {
+    types->push_back(Hwc2ContentTypeToHwc3(type));
+  }
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayDecorationSupport(
+    int64_t /*display_id*/,
+    std::optional<common::DisplayDecorationSupport>* /*support_struct*/) {
+  DEBUG_FUNC();
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::registerCallback(
+    const std::shared_ptr<IComposerCallback>& callback) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  // This function is specified to be called exactly once.
+  hwc_->Init(callback);
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::setActiveConfig(int64_t display_id,
+                                                   int32_t config) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  return ToBinderStatus(Hwc2toHwc3Error(display->SetActiveConfig(config)));
+}
+
+ndk::ScopedAStatus ComposerClient::setActiveConfigWithConstraints(
+    int64_t display_id, int32_t config,
+    const VsyncPeriodChangeConstraints& constraints,
+    VsyncPeriodChangeTimeline* timeline) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  hwc_vsync_period_change_constraints_t hwc2_constraints;
+  hwc2_constraints.desiredTimeNanos = constraints.desiredTimeNanos;
+  hwc2_constraints.seamlessRequired = static_cast<uint8_t>(
+      constraints.seamlessRequired);
+
+  hwc_vsync_period_change_timeline_t hwc2_timeline{};
+  auto error = Hwc2toHwc3Error(
+      display->SetActiveConfigWithConstraints(config, &hwc2_constraints,
+                                              &hwc2_timeline));
+  if (error != hwc3::Error::kNone) {
+    return ToBinderStatus(error);
+  }
+
+  timeline->refreshTimeNanos = hwc2_timeline.refreshTimeNanos;
+  timeline->newVsyncAppliedTimeNanos = hwc2_timeline.newVsyncAppliedTimeNanos;
+  timeline->refreshRequired = static_cast<bool>(hwc2_timeline.refreshRequired);
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::setBootDisplayConfig(int64_t /*display_id*/,
+                                                        int32_t /*config*/) {
+  DEBUG_FUNC();
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::clearBootDisplayConfig(
+    int64_t /*display_id*/) {
+  DEBUG_FUNC();
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getPreferredBootDisplayConfig(
+    int64_t /*display_id*/, int32_t* /*config*/) {
+  DEBUG_FUNC();
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::setAutoLowLatencyMode(int64_t display_id,
+                                                         bool on) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  auto error = Hwc2toHwc3Error(display->SetAutoLowLatencyMode(on));
+  return ToBinderStatus(error);
+}
+
+ndk::ScopedAStatus ComposerClient::setClientTargetSlotCount(int64_t display_id,
+                                                            int32_t count) {
+  DEBUG_FUNC();
+  return ToBinderStatus(
+      composer_resources_->SetDisplayClientTargetCacheSize(display_id, count));
+}
+
+ndk::ScopedAStatus ComposerClient::setColorMode(int64_t display_id,
+                                                ColorMode mode,
+                                                RenderIntent intent) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  auto error = display->SetColorModeWithIntent(Hwc3ColorModeToHwc2(mode),
+                                               Hwc3RenderIntentToHwc2(intent));
+  return ToBinderStatus(Hwc2toHwc3Error(error));
+}
+
+ndk::ScopedAStatus ComposerClient::setContentType(int64_t display_id,
+                                                  ContentType type) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  auto error = display->SetContentType(Hwc3ContentTypeToHwc2(type));
+  return ToBinderStatus(Hwc2toHwc3Error(error));
+}
+
+ndk::ScopedAStatus ComposerClient::setDisplayedContentSamplingEnabled(
+    int64_t /*display_id*/, bool /*enable*/,
+    FormatColorComponent /*componentMask*/, int64_t /*maxFrames*/) {
+  DEBUG_FUNC();
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::setPowerMode(int64_t display_id,
+                                                PowerMode mode) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  if (mode == PowerMode::ON_SUSPEND) {
+    return ToBinderStatus(hwc3::Error::kUnsupported);
+  }
+
+  auto error = display->SetPowerMode(Hwc3PowerModeToHwc2(mode));
+  return ToBinderStatus(Hwc2toHwc3Error(error));
+}
+
+ndk::ScopedAStatus ComposerClient::setReadbackBuffer(
+    int64_t /*display_id*/, const AidlNativeHandle& /*aidlBuffer*/,
+    const ndk::ScopedFileDescriptor& /*releaseFence*/) {
+  DEBUG_FUNC();
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::setVsyncEnabled(int64_t display_id,
+                                                   bool enabled) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  auto error = display->SetVsyncEnabled(static_cast<int32_t>(enabled));
+  return ToBinderStatus(Hwc2toHwc3Error(error));
+}
+
+ndk::ScopedAStatus ComposerClient::setIdleTimerEnabled(int64_t /*display_id*/,
+                                                       int32_t /*timeout*/) {
+  DEBUG_FUNC();
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getOverlaySupport(
+    OverlayProperties* /*out_overlay_properties*/) {
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getHdrConversionCapabilities(
+    std::vector<common::HdrConversionCapability>* /*out_capabilities*/) {
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::setHdrConversionStrategy(
+    const common::HdrConversionStrategy& /*conversion_strategy*/,
+    common::Hdr* /*out_hdr*/) {
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::setRefreshRateChangedCallbackDebugEnabled(
+    int64_t /*display*/, bool /*enabled*/) {
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+ndk::ScopedAStatus ComposerClient::getDisplayConfigurations(
+    int64_t display_id, int32_t /*max_frame_interval_ns*/,
+    std::vector<DisplayConfiguration>* configurations) {
+  DEBUG_FUNC();
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  const HwcDisplayConfigs& configs = display->GetDisplayConfigs();
+  for (const auto& [id, config] : configs.hwc_configs) {
+    static const int kNanosecondsPerSecond = 1E9;
+    configurations->emplace_back(
+        DisplayConfiguration{.configId = static_cast<int32_t>(config.id),
+                             .width = config.mode.GetRawMode().hdisplay,
+                             .height = config.mode.GetRawMode().vdisplay,
+                             .configGroup = static_cast<int32_t>(
+                                 config.group_id),
+                             .vsyncPeriod = static_cast<int>(kNanosecondsPerSecond * double(
+                                 1 / config.mode.GetVRefresh()))});
+
+    if (configs.mm_width != 0) {
+      // ideally this should be vdisplay/mm_heigth, however mm_height
+      // comes from edid parsing and is highly unreliable. Viewing the
+      // rarity of anisotropic displays, falling back to a single value
+      // for dpi yield more correct output.
+      static const float kMmPerInch = 25.4;
+      float dpi = float(config.mode.GetRawMode().hdisplay) * kMmPerInch /
+                  float(configs.mm_width);
+      configurations->back().dpi = {.x = dpi, .y = dpi};
+    }
+
+    // TODO: Populate vrrConfig.
+  }
+  return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus ComposerClient::notifyExpectedPresent(
+    int64_t /*display*/, const ClockMonotonicTimestamp& /*expected_present_time*/,
+    int32_t /*frame_interval_ns*/) {
+  return ToBinderStatus(hwc3::Error::kUnsupported);
+}
+
+std::string ComposerClient::Dump() {
+  uint32_t size = 0;
+  hwc_->Dump(&size, nullptr);
+
+  std::string buffer(size, '\0');
+  hwc_->Dump(&size, &buffer.front());
+  return buffer;
+}
+
+::ndk::SpAIBinder ComposerClient::createBinder() {
+  auto binder = BnComposerClient::createBinder();
+  AIBinder_setInheritRt(binder.get(), true);
+  return binder;
+}
+
+void ComposerClient::ExecuteSetLayerBuffer(int64_t display_id,
+                                           HwcLayerWrapper& layer,
+                                           const Buffer& buffer) {
+  buffer_handle_t imported_buffer = nullptr;
+
+  auto releaser = composer_resources_->CreateResourceReleaser(true);
+  auto err = composer_resources_->GetLayerBuffer(display_id, layer.layer_id,
+                                                 buffer, &imported_buffer,
+                                                 releaser.get());
+  if (err != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(err);
+    return;
+  }
+
+  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
+  auto fence_fd = const_cast<ndk::ScopedFileDescriptor&>(buffer.fence)
+                      .release();
+  err = Hwc2toHwc3Error(layer.layer->SetLayerBuffer(imported_buffer, fence_fd));
+  if (err != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(err);
+  }
+}
+
+void ComposerClient::ExecuteSetLayerBlendMode(
+    int64_t /*display_id*/, HwcLayerWrapper& layer,
+    const ParcelableBlendMode& blend_mode) {
+  auto err = Hwc2toHwc3Error(layer.layer->SetLayerBlendMode(
+      Hwc3BlendModeToHwc2(blend_mode.blendMode)));
+  if (err != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(err);
+  }
+}
+
+void ComposerClient::ExecuteSetLayerComposition(
+    int64_t /*display_id*/, HwcLayerWrapper& layer,
+    const ParcelableComposition& composition) {
+  hwc3::Error error = hwc3::Error::kNone;
+  switch (composition.composition) {
+      // Unsupported composition types should set an error for the current
+      // DisplayCommand.
+    case Composition::DISPLAY_DECORATION:
+    case Composition::SIDEBAND:
+      error = hwc3::Error::kUnsupported;
+      break;
+    default:
+      error = Hwc2toHwc3Error(layer.layer->SetLayerCompositionType(
+          Hwc3CompositionToHwc2(composition.composition)));
+  }
+  if (error != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(error);
+  }
+}
+
+void ComposerClient::ExecuteSetLayerDataspace(
+    int64_t /*display_id*/, HwcLayerWrapper& layer,
+    const ParcelableDataspace& dataspace) {
+  auto err = Hwc2toHwc3Error(
+      layer.layer->SetLayerDataspace(Hwc3DataspaceToHwc2(dataspace.dataspace)));
+  if (err != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(err);
+  }
+}
+
+void ComposerClient::ExecuteSetLayerDisplayFrame(int64_t /*display_id*/,
+                                                 HwcLayerWrapper& layer,
+                                                 const common::Rect& rect) {
+  const hwc_rect_t hwc2_rect{rect.left, rect.top, rect.right, rect.bottom};
+  auto err = Hwc2toHwc3Error(layer.layer->SetLayerDisplayFrame(hwc2_rect));
+  if (err != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(err);
+  }
+}
+void ComposerClient::ExecuteSetLayerPlaneAlpha(int64_t /*display_id*/,
+                                               HwcLayerWrapper& layer,
+                                               const PlaneAlpha& plane_alpha) {
+  auto err = Hwc2toHwc3Error(
+      layer.layer->SetLayerPlaneAlpha(plane_alpha.alpha));
+  if (err != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(err);
+  }
+}
+
+void ComposerClient::ExecuteSetLayerSourceCrop(
+    int64_t /*display_id*/, HwcLayerWrapper& layer,
+    const common::FRect& source_crop) {
+  const hwc_frect_t rect{source_crop.left, source_crop.top, source_crop.right,
+                         source_crop.bottom};
+  auto err = Hwc2toHwc3Error(layer.layer->SetLayerSourceCrop(rect));
+  if (err != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(err);
+  }
+}
+void ComposerClient::ExecuteSetLayerTransform(
+    int64_t /*display_id*/, HwcLayerWrapper& layer,
+    const ParcelableTransform& transform) {
+  auto err = Hwc2toHwc3Error(
+      layer.layer->SetLayerTransform(Hwc3TransformToHwc2(transform.transform)));
+  if (err != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(err);
+  }
+}
+void ComposerClient::ExecuteSetLayerZOrder(int64_t /*display_id*/,
+                                           HwcLayerWrapper& layer,
+                                           const ZOrder& z_order) {
+  auto err = Hwc2toHwc3Error(layer.layer->SetLayerZOrder(z_order.z));
+  if (err != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(err);
+  }
+}
+
+void ComposerClient::ExecuteSetLayerBrightness(
+    int64_t /*display_id*/, HwcLayerWrapper& /*layer*/,
+    const LayerBrightness& brightness) {
+  if (std::signbit(brightness.brightness) ||
+      std::isnan(brightness.brightness)) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadParameter);
+  }
+}
+
+void ComposerClient::ExecuteSetDisplayBrightness(
+    uint64_t display_id, const DisplayBrightness& command) {
+  auto* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
+    return;
+  }
+
+  auto error = Hwc2toHwc3Error(
+      display->SetDisplayBrightness(command.brightness));
+  if (error != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(error);
+  }
+}
+void ComposerClient::ExecuteSetDisplayColorTransform(
+    uint64_t display_id, const std::vector<float>& matrix) {
+  auto* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
+    return;
+  }
+
+  auto almost_equal = [](auto a, auto b) {
+    const float epsilon = 0.001F;
+    return std::abs(a - b) < epsilon;
+  };
+  const bool is_identity = std::equal(matrix.begin(), matrix.end(),
+                                      kIdentityMatrix.begin(), almost_equal);
+
+  const int32_t hint = is_identity ? HAL_COLOR_TRANSFORM_IDENTITY
+                                   : HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX;
+
+  auto error = Hwc2toHwc3Error(display->SetColorTransform(matrix.data(), hint));
+  if (error != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(error);
+  }
+}
+void ComposerClient::ExecuteSetDisplayClientTarget(
+    uint64_t display_id, const ClientTarget& command) {
+  auto* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
+    return;
+  }
+
+  hwc_region_t damage_regions;
+  damage_regions.numRects = command.damage.size();
+
+  std::vector<hwc_rect_t> regions(command.damage.size());
+  for (const auto& region : command.damage) {
+    regions.push_back({region.left, region.top, region.right, region.bottom});
+  }
+  damage_regions.rects = regions.data();
+
+  buffer_handle_t imported_buffer = nullptr;
+  auto buf_releaser = composer_resources_->CreateResourceReleaser(true);
+
+  auto error = composer_resources_->GetDisplayClientTarget(display_id,
+                                                           command.buffer,
+                                                           &imported_buffer,
+                                                           buf_releaser.get());
+  if (error != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(error);
+    return;
+  }
+
+  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
+  auto fence = const_cast<::ndk::ScopedFileDescriptor&>(command.buffer.fence)
+                   .release();
+  error = Hwc2toHwc3Error(
+      display->SetClientTarget(imported_buffer, fence,
+                               Hwc3DataspaceToHwc2(command.dataspace),
+                               damage_regions));
+  if (error != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(error);
+  }
+}
+
+void ComposerClient::ExecuteSetDisplayOutputBuffer(uint64_t display_id,
+                                                   const Buffer& buffer) {
+  auto* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
+    return;
+  }
+
+  buffer_handle_t imported_buffer = nullptr;
+  auto buf_releaser = composer_resources_->CreateResourceReleaser(true);
+
+  auto error = composer_resources_->GetDisplayOutputBuffer(display_id, buffer,
+                                                           &imported_buffer,
+                                                           buf_releaser.get());
+  if (error != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(error);
+    return;
+  }
+
+  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
+  auto fence = const_cast<::ndk::ScopedFileDescriptor&>(buffer.fence).release();
+  error = Hwc2toHwc3Error(display->SetOutputBuffer(imported_buffer, fence));
+  if (error != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(error);
+    return;
+  }
+}
+void ComposerClient::ExecuteValidateDisplay(
+    int64_t display_id,
+    std::optional<ClockMonotonicTimestamp> /*expected_present_time*/
+) {
+  auto* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
+    return;
+  }
+
+  /* TODO: Handle expectedPresentTime */
+  /* This can be implemented in multiple ways. For example, the expected present
+   * time property can be implemented by the DRM driver directly as a CRTC
+   * property. See:
+   * https://cs.android.com/android/platform/superproject/main/+/b8b3b1646e64d0235f77b9e717a3e4082e26f2a8:hardware/google/graphics/common/libhwc2.1/libdrmresource/drm/drmcrtc.cpp;drc=468f6172546ab98983de18210222f231f16b21e1;l=88
+   * Unfortunately there doesn't seem to be a standardised way of delaying
+   * presentation with a timestamp in the DRM API. What we can do alternatively
+   * is to spawn a separate presentation thread that could handle the VBlank
+   * events by using DRM_MODE_PAGE_FLIP_EVENT and schedule them appropriately.
+   */
+
+  std::vector<int64_t> changed_layers;
+  std::vector<Composition> composition_types;
+  int32_t display_request_mask = 0;
+  std::vector<int64_t> requested_layers;
+  std::vector<int32_t> request_masks;
+
+  const hwc3::Error error = ValidateDisplayInternal(*display, &changed_layers,
+                                                    &composition_types,
+                                                    &display_request_mask,
+                                                    &requested_layers,
+                                                    &request_masks, nullptr,
+                                                    nullptr);
+
+  if (error != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(error);
+  }
+
+  // If a CommandError has been been set for the current DisplayCommand, then
+  // no other results should be returned besides the error.
+  if (cmd_result_writer_->HasError()) {
+    return;
+  }
+
+  DisplayChanges changes{};
+  for (size_t i = 0; i < composition_types.size(); i++) {
+    changes.AddLayerCompositionChange(display_id, changed_layers[i],
+                                      composition_types[i]);
+  }
+
+  std::vector<DisplayRequest::LayerRequest> layer_requests;
+  for (size_t i = 0; i < requested_layers.size(); i++) {
+    layer_requests.push_back({requested_layers[i], request_masks[i]});
+  }
+
+  const DisplayRequest request_changes{display_id, display_request_mask,
+                                       layer_requests};
+  changes.display_request_changes = request_changes;
+
+  cmd_result_writer_->AddChanges(changes);
+  composer_resources_->SetDisplayMustValidateState(display_id, false);
+}
+
+void ComposerClient::ExecuteAcceptDisplayChanges(int64_t display_id) {
+  auto* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
+    return;
+  }
+
+  auto error = Hwc2toHwc3Error(display->AcceptDisplayChanges());
+  if (error != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(error);
+    return;
+  }
+}
+
+void ComposerClient::ExecutePresentDisplay(int64_t display_id) {
+  auto* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
+    return;
+  }
+
+  ::android::base::unique_fd display_fence;
+  std::unordered_map<int64_t, ::android::base::unique_fd> release_fences;
+  auto error = PresentDisplayInternal(display_id, display_fence,
+                                      release_fences);
+  if (error != hwc3::Error::kNone) {
+    cmd_result_writer_->AddError(error);
+  }
+  if (cmd_result_writer_->HasError()) {
+    return;
+  }
+
+  cmd_result_writer_->AddPresentFence(display_id, std::move(display_fence));
+  cmd_result_writer_->AddReleaseFence(display_id, release_fences);
+}
+
+void ComposerClient::ExecutePresentOrValidateDisplay(
+    int64_t display_id,
+    std::optional<ClockMonotonicTimestamp> expected_present_time) {
+  auto* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
+    return;
+  }
+
+  /* TODO: Handle expectedPresentTime */
+  /* This can be implemented in multiple ways. For example, the expected present
+   * time property can be implemented by the DRM driver directly as a CRTC
+   * property. See:
+   * https://cs.android.com/android/platform/superproject/main/+/b8b3b1646e64d0235f77b9e717a3e4082e26f2a8:hardware/google/graphics/common/libhwc2.1/libdrmresource/drm/drmcrtc.cpp;drc=468f6172546ab98983de18210222f231f16b21e1;l=88
+   * Unfortunately there doesn't seem to be a standardised way of delaying
+   * presentation with a timestamp in the DRM API. What we can do alternatively
+   * is to spawn a separate presentation thread that could handle the VBlank
+   * events by using DRM_MODE_PAGE_FLIP_EVENT and schedule them appropriately.
+   */
+
+  /* TODO: Add check if it's possible to skip display validation */
+  ExecuteValidateDisplay(display_id, expected_present_time);
+  cmd_result_writer_
+      ->AddPresentOrValidateResult(display_id,
+                                   PresentOrValidate::Result::Validated);
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hwc3/ComposerClient.h b/hwc3/ComposerClient.h
new file mode 100644
index 0000000..f6362ad
--- /dev/null
+++ b/hwc3/ComposerClient.h
@@ -0,0 +1,224 @@
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
+#include <memory>
+
+#include "aidl/android/hardware/graphics/composer3/BnComposerClient.h"
+#include "aidl/android/hardware/graphics/composer3/LayerCommand.h"
+#include "hwc3/CommandResultWriter.h"
+#include "hwc3/ComposerResources.h"
+#include "hwc3/Utils.h"
+#include "utils/Mutex.h"
+
+using AidlPixelFormat = aidl::android::hardware::graphics::common::PixelFormat;
+using AidlNativeHandle = aidl::android::hardware::common::NativeHandle;
+
+namespace android {
+
+class HwcDisplay;
+class HwcLayer;
+
+}  // namespace android
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class DrmHwcThree;
+
+struct HwcLayerWrapper {
+  int64_t layer_id;
+  ::android::HwcLayer* layer;
+};
+
+class ComposerClient : public BnComposerClient {
+ public:
+  ComposerClient();
+  ~ComposerClient() override;
+
+  bool Init();
+  std::string Dump();
+
+  // composer3 interface
+  ndk::ScopedAStatus createLayer(int64_t display, int32_t buffer_slot_count,
+                                 int64_t* layer) override;
+  ndk::ScopedAStatus createVirtualDisplay(int32_t width, int32_t height,
+                                          AidlPixelFormat format_hint,
+                                          int32_t output_buffer_slot_count,
+                                          VirtualDisplay* display) override;
+  ndk::ScopedAStatus destroyLayer(int64_t display, int64_t layer) override;
+  ndk::ScopedAStatus destroyVirtualDisplay(int64_t display) override;
+  ndk::ScopedAStatus executeCommands(
+      const std::vector<DisplayCommand>& commands,
+      std::vector<CommandResultPayload>* results) override;
+  ndk::ScopedAStatus getActiveConfig(int64_t display, int32_t* config) override;
+  ndk::ScopedAStatus getColorModes(
+      int64_t display, std::vector<ColorMode>* color_modes) override;
+  ndk::ScopedAStatus getDataspaceSaturationMatrix(
+      common::Dataspace dataspace, std::vector<float>* matrix) override;
+  ndk::ScopedAStatus getDisplayAttribute(int64_t display, int32_t config,
+                                         DisplayAttribute attribute,
+                                         int32_t* value) override;
+  ndk::ScopedAStatus getDisplayCapabilities(
+      int64_t display, std::vector<DisplayCapability>* caps) override;
+  ndk::ScopedAStatus getDisplayConfigs(int64_t display,
+                                       std::vector<int32_t>* configs) override;
+  ndk::ScopedAStatus getDisplayConnectionType(
+      int64_t display, DisplayConnectionType* type) override;
+  ndk::ScopedAStatus getDisplayIdentificationData(
+      int64_t display, DisplayIdentification* id) override;
+  ndk::ScopedAStatus getDisplayName(int64_t display,
+                                    std::string* name) override;
+  ndk::ScopedAStatus getDisplayVsyncPeriod(int64_t display,
+                                           int32_t* vsync_period) override;
+  ndk::ScopedAStatus getDisplayedContentSample(
+      int64_t display, int64_t max_frames, int64_t timestamp,
+      DisplayContentSample* samples) override;
+  ndk::ScopedAStatus getDisplayedContentSamplingAttributes(
+      int64_t display, DisplayContentSamplingAttributes* attrs) override;
+  ndk::ScopedAStatus getDisplayPhysicalOrientation(
+      int64_t display, common::Transform* orientation) override;
+  ndk::ScopedAStatus getHdrCapabilities(int64_t display,
+                                        HdrCapabilities* caps) override;
+  ndk::ScopedAStatus getMaxVirtualDisplayCount(int32_t* count) override;
+  ndk::ScopedAStatus getPerFrameMetadataKeys(
+      int64_t display, std::vector<PerFrameMetadataKey>* keys) override;
+  ndk::ScopedAStatus getReadbackBufferAttributes(
+      int64_t display, ReadbackBufferAttributes* attrs) override;
+  ndk::ScopedAStatus getReadbackBufferFence(
+      int64_t display, ndk::ScopedFileDescriptor* acquire_fence) override;
+  ndk::ScopedAStatus getRenderIntents(
+      int64_t display, ColorMode mode,
+      std::vector<RenderIntent>* intents) override;
+  ndk::ScopedAStatus getSupportedContentTypes(
+      int64_t display, std::vector<ContentType>* types) override;
+  ndk::ScopedAStatus getDisplayDecorationSupport(
+      int64_t display,
+      std::optional<common::DisplayDecorationSupport>* support) override;
+  ndk::ScopedAStatus registerCallback(
+      const std::shared_ptr<IComposerCallback>& callback) override;
+  ndk::ScopedAStatus setActiveConfig(int64_t display, int32_t config) override;
+  ndk::ScopedAStatus setActiveConfigWithConstraints(
+      int64_t display, int32_t config,
+      const VsyncPeriodChangeConstraints& constraints,
+      VsyncPeriodChangeTimeline* timeline) override;
+  ndk::ScopedAStatus setBootDisplayConfig(int64_t display,
+                                          int32_t config) override;
+  ndk::ScopedAStatus clearBootDisplayConfig(int64_t display) override;
+  ndk::ScopedAStatus getPreferredBootDisplayConfig(int64_t display,
+                                                   int32_t* config) override;
+  ndk::ScopedAStatus setAutoLowLatencyMode(int64_t display, bool on) override;
+  ndk::ScopedAStatus setClientTargetSlotCount(int64_t display,
+                                              int32_t count) override;
+  ndk::ScopedAStatus setColorMode(int64_t display, ColorMode mode,
+                                  RenderIntent intent) override;
+  ndk::ScopedAStatus setContentType(int64_t display, ContentType type) override;
+  ndk::ScopedAStatus setDisplayedContentSamplingEnabled(
+      int64_t display, bool enable, FormatColorComponent component_mask,
+      int64_t max_frames) override;
+  ndk::ScopedAStatus setPowerMode(int64_t display, PowerMode mode) override;
+  ndk::ScopedAStatus setReadbackBuffer(
+      int64_t display, const AidlNativeHandle& buffer,
+      const ndk::ScopedFileDescriptor& release_fence) override;
+  ndk::ScopedAStatus setVsyncEnabled(int64_t display, bool enabled) override;
+  ndk::ScopedAStatus setIdleTimerEnabled(int64_t display,
+                                         int32_t timeout) override;
+  ndk::ScopedAStatus getOverlaySupport(
+      OverlayProperties* out_overlay_properties) override;
+  ndk::ScopedAStatus getHdrConversionCapabilities(
+      std::vector<common::HdrConversionCapability>* out_capabilities) override;
+  ndk::ScopedAStatus setHdrConversionStrategy(
+      const common::HdrConversionStrategy& conversion_strategy,
+      common::Hdr* out_hdr) override;
+  ndk::ScopedAStatus setRefreshRateChangedCallbackDebugEnabled(
+      int64_t display, bool enabled) override;
+  ndk::ScopedAStatus getDisplayConfigurations(
+      int64_t display, int32_t max_frame_interval_ns,
+      std::vector<DisplayConfiguration>* configurations) override;
+  ndk::ScopedAStatus notifyExpectedPresent(
+      int64_t display, const ClockMonotonicTimestamp& expected_present_time,
+      int32_t frame_interval_ns) override;
+
+ protected:
+  ::ndk::SpAIBinder createBinder() override;
+
+ private:
+  // Layer commands
+  void DispatchLayerCommand(int64_t display_id, const LayerCommand& command);
+  void ExecuteSetLayerBuffer(int64_t display_id, HwcLayerWrapper& layer_id,
+                             const Buffer& buffer);
+  void ExecuteSetLayerBlendMode(int64_t display_id, HwcLayerWrapper& layer,
+                                const ParcelableBlendMode& blend_mode);
+  void ExecuteSetLayerComposition(int64_t display_id, HwcLayerWrapper& layer,
+                                  const ParcelableComposition& composition);
+  void ExecuteSetLayerDataspace(int64_t display_id, HwcLayerWrapper& layer,
+                                const ParcelableDataspace& dataspace);
+  void ExecuteSetLayerDisplayFrame(int64_t display_id, HwcLayerWrapper& layer,
+                                   const common::Rect& rect);
+  void ExecuteSetLayerPlaneAlpha(int64_t display_id, HwcLayerWrapper& layer,
+                                 const PlaneAlpha& plane_alpha);
+  void ExecuteSetLayerSourceCrop(int64_t display_id, HwcLayerWrapper& layer,
+                                 const common::FRect& source_crop);
+  void ExecuteSetLayerTransform(int64_t display_id, HwcLayerWrapper& layer,
+                                const ParcelableTransform& transform);
+  void ExecuteSetLayerZOrder(int64_t display_id, HwcLayerWrapper& layer,
+                             const ZOrder& z_order);
+  void ExecuteSetLayerBrightness(int64_t display_id, HwcLayerWrapper& layer,
+                                 const LayerBrightness& brightness);
+
+  // Display commands
+  void ExecuteDisplayCommand(const DisplayCommand& command);
+  void ExecuteSetDisplayBrightness(uint64_t display_id,
+                                   const DisplayBrightness& command);
+  void ExecuteSetDisplayColorTransform(uint64_t display_id,
+                                       const std::vector<float>& matrix);
+  void ExecuteSetDisplayClientTarget(uint64_t display_id,
+                                     const ClientTarget& command);
+  void ExecuteSetDisplayOutputBuffer(uint64_t display_id, const Buffer& buffer);
+  void ExecuteValidateDisplay(
+      int64_t display_id,
+      std::optional<ClockMonotonicTimestamp> expected_present_time);
+  void ExecuteAcceptDisplayChanges(int64_t display_id);
+  void ExecutePresentDisplay(int64_t display_id);
+  void ExecutePresentOrValidateDisplay(
+      int64_t display_id,
+      std::optional<ClockMonotonicTimestamp> expected_present_time);
+
+  static hwc3::Error ValidateDisplayInternal(
+      ::android::HwcDisplay& display, std::vector<int64_t>* out_changed_layers,
+      std::vector<Composition>* out_composition_types,
+      int32_t* out_display_request_mask,
+      std::vector<int64_t>* out_requested_layers,
+      std::vector<int32_t>* out_request_masks,
+      ClientTargetProperty* out_client_target_property,
+      DimmingStage* out_dimming_stage);
+
+  hwc3::Error PresentDisplayInternal(
+      uint64_t display_id, ::android::base::unique_fd& out_display_fence,
+      std::unordered_map<int64_t, ::android::base::unique_fd>&
+          out_release_fences);
+
+  ::android::HwcDisplay* GetDisplay(uint64_t display_id);
+
+  std::unique_ptr<CommandResultWriter> cmd_result_writer_;
+
+  // Manages importing and caching gralloc buffers for displays and layers.
+  std::unique_ptr<ComposerResources> composer_resources_;
+
+  std::unique_ptr<DrmHwcThree> hwc_;
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hwc3/ComposerResources.cpp b/hwc3/ComposerResources.cpp
new file mode 100644
index 0000000..ae0edf4
--- /dev/null
+++ b/hwc3/ComposerResources.cpp
@@ -0,0 +1,202 @@
+
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
+#define ATRACE_TAG (ATRACE_TAG_GRAPHICS | ATRACE_TAG_HAL)
+
+#include "ComposerResources.h"
+
+#include <aidlcommonsupport/NativeHandle.h>
+
+#include "hardware/hwcomposer2.h"
+#include "hwc3/Utils.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+::android::hardware::graphics::composer::V2_1::Display ToHwc2Display(
+    uint64_t display_id) {
+  return static_cast<::android::hardware::graphics::composer::V2_1::Display>(
+      display_id);
+}
+
+::android::hardware::graphics::composer::V2_1::Layer ToHwc2Layer(
+    int64_t layer_id) {
+  return static_cast<::android::hardware::graphics::composer::V2_1::Layer>(
+      layer_id);
+}
+
+std::unique_ptr<ComposerResourceReleaser>
+ComposerResources::CreateResourceReleaser(bool is_buffer) {
+  return std::make_unique<ComposerResourceReleaser>(is_buffer);
+}
+
+std::unique_ptr<ComposerResources> ComposerResources::Create() {
+  auto instance = std::unique_ptr<ComposerResources>(new ComposerResources);
+  if (instance->resources_ == nullptr) {
+    ALOGE("%s: Failed to initialise ComposerResources", __func__);
+    return nullptr;
+  }
+
+  return instance;
+}
+
+hwc3::Error ComposerResources::GetLayerBuffer(
+    uint64_t display_id, int64_t layer_id, const Buffer& buffer,
+    buffer_handle_t* out_buffer_handle,
+    ComposerResourceReleaser* buf_releaser) {
+  auto display = ToHwc2Display(display_id);
+  auto layer = ToHwc2Layer(layer_id);
+
+  const bool use_cache = !buffer.handle.has_value();
+  buffer_handle_t buffer_handle = nullptr;
+  if (buffer.handle.has_value()) {
+    buffer_handle = ::android::makeFromAidl(*buffer.handle);
+  }
+
+  auto err = resources_->getLayerBuffer(display, layer, buffer.slot, use_cache,
+                                        buffer_handle, out_buffer_handle,
+                                        buf_releaser->GetReplacedHandle());
+
+  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
+}
+
+hwc3::Error ComposerResources::GetLayerSidebandStream(
+    uint64_t display_id, int64_t layer_id,
+    const aidl::android::hardware::common::NativeHandle& handle,
+    buffer_handle_t* out_handle, ComposerResourceReleaser* releaser) {
+  auto display = ToHwc2Display(display_id);
+  auto layer = ToHwc2Layer(layer_id);
+
+  auto err = resources_->getLayerSidebandStream(display, layer,
+                                                ::android::makeFromAidl(handle),
+                                                out_handle,
+                                                releaser->GetReplacedHandle());
+
+  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
+}
+
+hwc3::Error ComposerResources::AddLayer(uint64_t display_id, int64_t layer_id,
+                                        uint32_t buffer_cache_size) {
+  auto display = ToHwc2Display(display_id);
+  auto layer = ToHwc2Layer(layer_id);
+
+  auto err = resources_->addLayer(display, layer, buffer_cache_size);
+  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
+}
+
+hwc3::Error ComposerResources::RemoveLayer(uint64_t display_id,
+                                           int64_t layer_id) {
+  auto display = ToHwc2Display(display_id);
+  auto layer = ToHwc2Layer(layer_id);
+
+  auto err = resources_->removeLayer(display, layer);
+  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
+}
+
+bool ComposerResources::HasDisplay(uint64_t display_id) {
+  auto display = ToHwc2Display(display_id);
+  return resources_->hasDisplay(display);
+}
+
+hwc3::Error ComposerResources::AddPhysicalDisplay(uint64_t display_id) {
+  auto display = ToHwc2Display(display_id);
+  auto err = resources_->addPhysicalDisplay(display);
+  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
+}
+
+hwc3::Error ComposerResources::AddVirtualDisplay(
+    uint64_t display, uint32_t output_buffer_cache_size) {
+  auto err = resources_->addVirtualDisplay(display, output_buffer_cache_size);
+  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
+}
+
+hwc3::Error ComposerResources::RemoveDisplay(uint64_t display_id) {
+  auto display = ToHwc2Display(display_id);
+  auto err = resources_->removeDisplay(display);
+  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
+}
+
+void ComposerResources::SetDisplayMustValidateState(uint64_t display_id,
+                                                    bool must_validate) {
+  auto display = ToHwc2Display(display_id);
+  resources_->setDisplayMustValidateState(display, must_validate);
+}
+
+bool ComposerResources::MustValidateDisplay(uint64_t display_id) {
+  auto display = ToHwc2Display(display_id);
+  return resources_->mustValidateDisplay(display);
+}
+
+hwc3::Error ComposerResources::GetDisplayClientTarget(
+    uint64_t display_id, const Buffer& buffer, buffer_handle_t* out_handle,
+    ComposerResourceReleaser* releaser) {
+  auto display = ToHwc2Display(display_id);
+
+  const bool use_cache = !buffer.handle.has_value();
+  buffer_handle_t buffer_handle = nullptr;
+  if (buffer.handle.has_value()) {
+    buffer_handle = ::android::makeFromAidl(*buffer.handle);
+  }
+
+  auto err = resources_->getDisplayClientTarget(display, buffer.slot, use_cache,
+                                                buffer_handle, out_handle,
+                                                releaser->GetReplacedHandle());
+  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
+}
+
+hwc3::Error ComposerResources::SetDisplayClientTargetCacheSize(
+    uint64_t display_id, uint32_t client_target_cache_size) {
+  auto display = ToHwc2Display(display_id);
+  auto err = resources_
+                 ->setDisplayClientTargetCacheSize(display,
+                                                   client_target_cache_size);
+  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
+}
+
+hwc3::Error ComposerResources::GetDisplayClientTargetCacheSize(
+    uint64_t display_id, size_t* out_cache_size) {
+  auto display = ToHwc2Display(display_id);
+  auto err = resources_->getDisplayClientTargetCacheSize(display,
+                                                         out_cache_size);
+  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
+}
+
+hwc3::Error ComposerResources::GetDisplayOutputBufferCacheSize(
+    uint64_t display_id, size_t* out_cache_size) {
+  auto display = ToHwc2Display(display_id);
+  auto err = resources_->getDisplayOutputBufferCacheSize(display,
+                                                         out_cache_size);
+  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
+}
+
+hwc3::Error ComposerResources::GetDisplayOutputBuffer(
+    uint64_t display_id, const Buffer& buffer, buffer_handle_t* out_handle,
+    ComposerResourceReleaser* releaser) {
+  auto display = ToHwc2Display(display_id);
+  const bool use_cache = !buffer.handle.has_value();
+
+  buffer_handle_t buffer_handle = nullptr;
+  if (buffer.handle.has_value()) {
+    buffer_handle = ::android::makeFromAidl(*buffer.handle);
+  }
+
+  auto err = resources_->getDisplayOutputBuffer(display, buffer.slot, use_cache,
+                                                buffer_handle, out_handle,
+                                                releaser->GetReplacedHandle());
+  return Hwc2toHwc3Error(static_cast<HWC2::Error>(err));
+}
+}  // namespace aidl::android::hardware::graphics::composer3::impl
\ No newline at end of file
diff --git a/hwc3/ComposerResources.h b/hwc3/ComposerResources.h
new file mode 100644
index 0000000..6f4eee7
--- /dev/null
+++ b/hwc3/ComposerResources.h
@@ -0,0 +1,99 @@
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
+#include <memory>
+
+#include "aidl/android/hardware/graphics/composer3/IComposerClient.h"
+#include "composer-resources/2.2/ComposerResources.h"
+#include "cutils/native_handle.h"
+#include "hwc3/Utils.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class ComposerResourceReleaser {
+ public:
+  explicit ComposerResourceReleaser(bool is_buffer)
+      : replaced_handle_(is_buffer) {
+  }
+  virtual ~ComposerResourceReleaser() = default;
+
+  ::android::hardware::graphics::composer::V2_2::hal::ComposerResources::
+      ReplacedHandle*
+      GetReplacedHandle() {
+    return &replaced_handle_;
+  }
+
+ private:
+  ::android::hardware::graphics::composer::V2_2::hal::ComposerResources::
+      ReplacedHandle replaced_handle_;
+};
+
+class ComposerResources {
+ public:
+  static std::unique_ptr<ComposerResources> Create();
+  ~ComposerResources() = default;
+
+  hwc3::Error GetLayerBuffer(uint64_t display_id, int64_t layer_id,
+                             const Buffer& buffer,
+                             buffer_handle_t* out_buffer_handle,
+                             ComposerResourceReleaser* releaser);
+  hwc3::Error GetLayerSidebandStream(
+      uint64_t display_id, int64_t layer_id,
+      const aidl::android::hardware::common::NativeHandle& handle,
+      buffer_handle_t* out_handle, ComposerResourceReleaser* releaser);
+
+  hwc3::Error AddLayer(uint64_t display, int64_t layer,
+                       uint32_t buffer_cache_size);
+  hwc3::Error RemoveLayer(uint64_t display, int64_t layer);
+
+  bool HasDisplay(uint64_t display);
+  hwc3::Error AddPhysicalDisplay(uint64_t display);
+  hwc3::Error AddVirtualDisplay(uint64_t display,
+                                uint32_t output_buffer_cache_size);
+  hwc3::Error RemoveDisplay(uint64_t display);
+
+  void SetDisplayMustValidateState(uint64_t display_id, bool must_validate);
+  bool MustValidateDisplay(uint64_t display_id);
+
+  hwc3::Error GetDisplayClientTarget(uint64_t display_id, const Buffer& buffer,
+                                     buffer_handle_t* out_handle,
+                                     ComposerResourceReleaser* releaser);
+
+  hwc3::Error SetDisplayClientTargetCacheSize(
+      uint64_t display_id, uint32_t client_target_cache_size);
+  hwc3::Error GetDisplayClientTargetCacheSize(uint64_t display_id,
+                                              size_t* out_cache_size);
+  hwc3::Error GetDisplayOutputBufferCacheSize(uint64_t display,
+                                              size_t* out_cache_size);
+  hwc3::Error GetDisplayOutputBuffer(uint64_t display_id, const Buffer& buffer,
+                                     buffer_handle_t* out_handle,
+                                     ComposerResourceReleaser* releaser);
+
+  static std::unique_ptr<ComposerResourceReleaser> CreateResourceReleaser(
+      bool is_buffer);
+
+ private:
+  ComposerResources() = default;
+
+  std::unique_ptr<
+      ::android::hardware::graphics::composer::V2_2::hal::ComposerResources>
+      resources_ = ::android::hardware::graphics::composer::V2_2::hal::
+          ComposerResources::create();
+};
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
\ No newline at end of file
diff --git a/hwc3/DrmHwcThree.cpp b/hwc3/DrmHwcThree.cpp
new file mode 100644
index 0000000..d758865
--- /dev/null
+++ b/hwc3/DrmHwcThree.cpp
@@ -0,0 +1,132 @@
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
+#include "DrmHwcThree.h"
+
+#include <cinttypes>
+
+#include "Utils.h"
+#include "aidl/android/hardware/graphics/common/Dataspace.h"
+#include "aidl/android/hardware/graphics/common/DisplayHotplugEvent.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+using ::android::HwcDisplay;
+
+DrmHwcThree::~DrmHwcThree() {
+  /* Display deinit routine is handled by resource manager */
+  GetResMan().DeInit();
+}
+
+void DrmHwcThree::Init(std::shared_ptr<IComposerCallback> callback) {
+  composer_callback_ = std::move(callback);
+  GetResMan().Init();
+}
+
+void DrmHwcThree::SendVsyncPeriodTimingChangedEventToClient(
+    uint64_t display_id, int64_t timestamp) const {
+  VsyncPeriodChangeTimeline timeline;
+  timeline.newVsyncAppliedTimeNanos = timestamp;
+  timeline.refreshRequired = false;
+  timeline.refreshTimeNanos = 0;
+
+  composer_callback_->onVsyncPeriodTimingChanged(static_cast<int64_t>(
+                                                     display_id),
+                                                 timeline);
+}
+
+void DrmHwcThree::SendRefreshEventToClient(uint64_t display_id) {
+  composer_resources_->SetDisplayMustValidateState(display_id, true);
+  composer_callback_->onRefresh(static_cast<int64_t>(display_id));
+}
+
+void DrmHwcThree::SendVsyncEventToClient(uint64_t display_id, int64_t timestamp,
+                                         uint32_t vsync_period) const {
+  composer_callback_->onVsync(static_cast<int64_t>(display_id), timestamp,
+                              static_cast<int32_t>(vsync_period));
+}
+
+void DrmHwcThree::SendHotplugEventToClient(hwc2_display_t display_id,
+                                           bool connected) {
+  HandleDisplayHotplugEvent(static_cast<uint64_t>(display_id), connected);
+  common::DisplayHotplugEvent event = connected ? common::DisplayHotplugEvent::CONNECTED : common::DisplayHotplugEvent::DISCONNECTED;
+  composer_callback_->onHotplugEvent(static_cast<int64_t>(display_id), event);
+}
+
+void DrmHwcThree::CleanDisplayResources(uint64_t display_id) {
+  DEBUG_FUNC();
+  HwcDisplay* display = GetDisplay(display_id);
+  if (display == nullptr) {
+    return;
+  }
+
+  display->SetPowerMode(static_cast<int32_t>(PowerMode::OFF));
+
+  size_t cache_size = 0;
+  auto err = composer_resources_->GetDisplayClientTargetCacheSize(display_id,
+                                                                  &cache_size);
+  if (err != hwc3::Error::kNone) {
+    ALOGE("%s: Could not clear target buffer cache for display: %" PRIu64,
+          __func__, display_id);
+    return;
+  }
+
+  for (size_t slot = 0; slot < cache_size; slot++) {
+    buffer_handle_t buffer_handle = nullptr;
+    auto buf_releaser = ComposerResources::CreateResourceReleaser(true);
+
+    Buffer buf{};
+    buf.slot = static_cast<int32_t>(slot);
+    err = composer_resources_->GetDisplayClientTarget(display_id, buf,
+                                                      &buffer_handle,
+                                                      buf_releaser.get());
+    if (err != hwc3::Error::kNone) {
+      continue;
+    }
+
+    err = Hwc2toHwc3Error(
+        display->SetClientTarget(buffer_handle, -1,
+                                 static_cast<int32_t>(
+                                     common::Dataspace::UNKNOWN),
+                                 {}));
+    if (err != hwc3::Error::kNone) {
+      ALOGE(
+          "%s: Could not clear slot %zu of the target buffer cache for "
+          "display %" PRIu64,
+          __func__, slot, display_id);
+    }
+  }
+}
+
+void DrmHwcThree::HandleDisplayHotplugEvent(uint64_t display_id,
+                                            bool connected) {
+  DEBUG_FUNC();
+  if (!connected) {
+    composer_resources_->RemoveDisplay(display_id);
+    Displays().erase(display_id);
+    return;
+  }
+
+  if (composer_resources_->HasDisplay(display_id)) {
+    /* Cleanup existing display resources */
+    CleanDisplayResources(display_id);
+    composer_resources_->RemoveDisplay(display_id);
+    Displays().erase(display_id);
+  }
+  composer_resources_->AddPhysicalDisplay(display_id);
+}
+
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hwc3/DrmHwcThree.h b/hwc3/DrmHwcThree.h
new file mode 100644
index 0000000..8ba96c6
--- /dev/null
+++ b/hwc3/DrmHwcThree.h
@@ -0,0 +1,51 @@
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
+#include <aidl/android/hardware/graphics/composer3/IComposerCallback.h>
+
+#include "drm/DrmHwc.h"
+#include "hwc3/ComposerResources.h"
+
+namespace aidl::android::hardware::graphics::composer3::impl {
+
+class DrmHwcThree : public ::android::DrmHwc {
+ public:
+  explicit DrmHwcThree(ComposerResources* composer_resources)
+      : composer_resources_(composer_resources) {
+  }
+  ~DrmHwcThree() override;
+
+  void Init(std::shared_ptr<IComposerCallback> callback);
+
+  // DrmHwcInterface
+  void SendVsyncEventToClient(hwc2_display_t display_id, int64_t timestamp,
+                              uint32_t vsync_period) const override;
+  void SendVsyncPeriodTimingChangedEventToClient(
+      hwc2_display_t display_id, int64_t timestamp) const override;
+  void SendRefreshEventToClient(uint64_t display_id) override;
+  void SendHotplugEventToClient(hwc2_display_t display_id,
+                                bool connected) override;
+
+ private:
+  void CleanDisplayResources(uint64_t display_id);
+  void HandleDisplayHotplugEvent(uint64_t display_id, bool connected);
+
+  std::shared_ptr<IComposerCallback> composer_callback_;
+  ComposerResources* composer_resources_;
+};
+}  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hwc3/Utils.cpp b/hwc3/Utils.cpp
new file mode 100644
index 0000000..adbd2fb
--- /dev/null
+++ b/hwc3/Utils.cpp
@@ -0,0 +1,58 @@
+
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
+#define ATRACE_TAG (ATRACE_TAG_GRAPHICS | ATRACE_TAG_HAL)
+
+#include "Utils.h"
+
+#include <hardware/hwcomposer2.h>
+
+#include "utils/log.h"
+
+namespace aidl::android::hardware::graphics::composer3 {
+
+hwc3::Error Hwc2toHwc3Error(HWC2::Error error) {
+  switch (error) {
+    case HWC2::Error::None:
+      return hwc3::Error::kNone;
+    case HWC2::Error::BadConfig:
+      return hwc3::Error::kBadConfig;
+    case HWC2::Error::BadDisplay:
+      return hwc3::Error::kBadDisplay;
+    case HWC2::Error::BadLayer:
+      return hwc3::Error::kBadLayer;
+    case HWC2::Error::BadParameter:
+      return hwc3::Error::kBadParameter;
+    case HWC2::Error::NoResources:
+      return hwc3::Error::kNoResources;
+    case HWC2::Error::NotValidated:
+      return hwc3::Error::kNotValidated;
+    case HWC2::Error::Unsupported:
+      return hwc3::Error::kUnsupported;
+    case HWC2::Error::SeamlessNotAllowed:
+      return hwc3::Error::kSeamlessNotAllowed;
+    case HWC2::Error::SeamlessNotPossible:
+      return hwc3::Error::kSeamlessNotPossible;
+    default:
+      ALOGE("Unknown HWC2 error. Could not translate to HWC3 error: %d",
+            static_cast<int32_t>(error));
+      return hwc3::Error::kUnsupported;
+  }
+}
+
+};  // namespace aidl::android::hardware::graphics::composer3
\ No newline at end of file
diff --git a/hwc3/Utils.h b/hwc3/Utils.h
new file mode 100644
index 0000000..23d6bdc
--- /dev/null
+++ b/hwc3/Utils.h
@@ -0,0 +1,209 @@
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
+#include <aidl/android/hardware/graphics/composer3/IComposerClient.h>
+#include <hardware/hwcomposer2.h>
+
+#include <cstdint>
+
+// NOLINTNEXTLINE
+#define DEBUG_FUNC() ALOGV("%s", __func__)
+
+namespace aidl::android::hardware::graphics::composer3 {
+
+namespace hwc3 {
+enum class Error : int32_t {
+  kNone = 0,
+  kBadConfig = IComposerClient::EX_BAD_CONFIG,
+  kBadDisplay = IComposerClient::EX_BAD_DISPLAY,
+  kBadLayer = IComposerClient::EX_BAD_LAYER,
+  kBadParameter = IComposerClient::EX_BAD_PARAMETER,
+  kNoResources = IComposerClient::EX_NO_RESOURCES,
+  kNotValidated = IComposerClient::EX_NOT_VALIDATED,
+  kUnsupported = IComposerClient::EX_UNSUPPORTED,
+  kSeamlessNotAllowed = IComposerClient::EX_SEAMLESS_NOT_ALLOWED,
+  kSeamlessNotPossible = IComposerClient::EX_SEAMLESS_NOT_POSSIBLE,
+};
+}  // namespace hwc3
+
+hwc3::Error Hwc2toHwc3Error(HWC2::Error error);
+
+inline ndk::ScopedAStatus ToBinderStatus(hwc3::Error error) {
+  if (error != hwc3::Error::kNone) {
+    return ndk::ScopedAStatus::fromServiceSpecificError(
+        static_cast<int32_t>(error));
+  }
+  return ndk::ScopedAStatus::ok();
+}
+
+inline ndk::ScopedAStatus ToBinderStatus(HWC2::Error error) {
+  return ToBinderStatus(Hwc2toHwc3Error(error));
+}
+
+// ID conversion. HWC2 uses typedef'd unsigned integer types while HWC3 uses
+// signed integer types. static_cast in between these.
+inline int64_t Hwc2LayerToHwc3(hwc2_layer_t layer) {
+  return static_cast<int64_t>(layer);
+}
+
+inline int64_t Hwc2DisplayToHwc3(hwc2_display_t display) {
+  return static_cast<int64_t>(display);
+}
+
+inline int32_t Hwc2ConfigIdToHwc3(hwc2_config_t config_id) {
+  return static_cast<int32_t>(config_id);
+}
+
+inline hwc2_layer_t Hwc3LayerToHwc2(int64_t layer) {
+  return static_cast<hwc2_layer_t>(layer);
+}
+
+inline hwc2_display_t Hwc3DisplayToHwc2(int64_t display) {
+  return static_cast<hwc2_display_t>(display);
+}
+
+inline hwc2_config_t Hwc3ConfigIdToHwc2(int32_t config_id) {
+  return static_cast<hwc2_config_t>(config_id);
+}
+
+// Values match up to HWC2_COMPOSITION_SIDEBAND, with HWC2 not supporting
+// newer values. static_cast in between shared values.
+// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/Composition.aidl
+// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;drc=d783cabd4d9bddb4b83f2dd38300b7598bb58b24;l=826
+inline Composition Hwc2CompositionTypeToHwc3(int32_t composition_type) {
+  if (composition_type < HWC2_COMPOSITION_INVALID ||
+      composition_type > HWC2_COMPOSITION_SIDEBAND) {
+    return Composition::INVALID;
+  }
+  return static_cast<Composition>(composition_type);
+}
+
+inline int32_t Hwc3CompositionToHwc2(Composition composition_type) {
+  if (composition_type > Composition::SIDEBAND) {
+    return HWC2_COMPOSITION_INVALID;
+  }
+  return static_cast<int32_t>(composition_type);
+}
+
+// Values for color modes match across HWC versions, so static cast is safe:
+// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/ColorMode.aidl
+// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.0.h;drc=7d940ae4afa450696afa25e07982f3a95e17e9b2;l=118
+// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.1.h;drc=7d940ae4afa450696afa25e07982f3a95e17e9b2;l=35
+inline ColorMode Hwc2ColorModeToHwc3(int32_t color_mode) {
+  return static_cast<ColorMode>(color_mode);
+}
+
+inline int32_t Hwc3ColorModeToHwc2(ColorMode color_mode) {
+  return static_cast<int32_t>(color_mode);
+}
+
+// Capabilities match up to DisplayCapability::AUTO_LOW_LATENCY_MODE, with hwc2
+// not defining capabilities beyond that.
+// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/DisplayCapability.aidl#28
+// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;drc=1a0e4a1698c7b080d6763cef9e16592bce75967e;l=418
+inline DisplayCapability Hwc2DisplayCapabilityToHwc3(
+    uint32_t display_capability) {
+  if (display_capability > HWC2_DISPLAY_CAPABILITY_AUTO_LOW_LATENCY_MODE) {
+    return DisplayCapability::INVALID;
+  }
+  return static_cast<DisplayCapability>(display_capability);
+}
+
+// Values match between hwc versions, so static cast is safe.
+// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/DisplayConnectionType.aidl
+// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;l=216;drc=d783cabd4d9bddb4b83f2dd38300b7598bb58b24;bpv=0;bpt=1
+inline DisplayConnectionType Hwc2DisplayConnectionTypeToHwc3(uint32_t type) {
+  if (type > HWC2_DISPLAY_CONNECTION_TYPE_EXTERNAL) {
+    // Arbitrarily return EXTERNAL in this case, which shouldn't happen.
+    // TODO: This will be cleaned up once hwc2<->hwc3 conversion is removed.
+    ALOGE("Unknown HWC2 connection type. Could not translate: %d", type);
+    return DisplayConnectionType::EXTERNAL;
+  }
+  return static_cast<DisplayConnectionType>(type);
+}
+
+// Values match, so static_cast is safe.
+// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/RenderIntent.aidl
+// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.1.h;drc=7d940ae4afa450696afa25e07982f3a95e17e9b2;l=37
+inline RenderIntent Hwc2RenderIntentToHwc3(int32_t intent) {
+  if (intent < HAL_RENDER_INTENT_COLORIMETRIC ||
+      intent > HAL_RENDER_INTENT_TONE_MAP_ENHANCE) {
+    ALOGE("Unknown HWC2 render intent. Could not translate: %d", intent);
+    return RenderIntent::COLORIMETRIC;
+  }
+  return static_cast<RenderIntent>(intent);
+}
+inline int32_t Hwc3RenderIntentToHwc2(RenderIntent render_intent) {
+  return static_cast<int32_t>(render_intent);
+}
+
+// Content type matches, so static_cast is safe.
+// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/ContentType.aidl
+// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;l=350;drc=1a0e4a1698c7b080d6763cef9e16592bce75967e
+inline ContentType Hwc2ContentTypeToHwc3(uint32_t content_type) {
+  if (content_type > HWC2_CONTENT_TYPE_GAME) {
+    ALOGE("Unknown HWC2 content type. Could not translate: %d", content_type);
+    return ContentType::NONE;
+  }
+  return static_cast<ContentType>(content_type);
+}
+inline int32_t Hwc3ContentTypeToHwc2(ContentType content_type) {
+  return static_cast<int32_t>(content_type);
+}
+
+// Values match, so it's safe to do static_cast.
+// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/DisplayAttribute.aidl
+// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;l=58;drc=d783cabd4d9bddb4b83f2dd38300b7598bb58b24
+inline int32_t Hwc3DisplayAttributeToHwc2(DisplayAttribute display_attribute) {
+  return static_cast<int32_t>(display_attribute);
+}
+
+// Values match up to DOZE_SUSPEND.
+// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/PowerMode.aidl
+// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;l=348;drc=d783cabd4d9bddb4b83f2dd38300b7598bb58b24
+inline int32_t Hwc3PowerModeToHwc2(PowerMode power_mode) {
+  if (power_mode > PowerMode::DOZE_SUSPEND) {
+    ALOGE("Unsupported HWC2 power mode. Could not translate: %d", power_mode);
+    return HWC2_POWER_MODE_ON;
+  }
+  return static_cast<int32_t>(power_mode);
+}
+
+// Values match, so static_cast is okay.
+// https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/graphics/common/aidl/android/hardware/graphics/common/BlendMode.aidl;drc=bab1ba54ede32520a5042d616a3af46ad4f55d5f;l=25
+// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;l=72;drc=1a0e4a1698c7b080d6763cef9e16592bce75967e
+inline int32_t Hwc3BlendModeToHwc2(common::BlendMode blend_mode) {
+  return static_cast<int32_t>(blend_mode);
+}
+
+// Values appear to match.
+// https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/graphics/common/aidl/android/hardware/graphics/common/Dataspace.aidl
+// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.0.h;l=43
+// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.1.h;l=22;drc=7d940ae4afa450696afa25e07982f3a95e17e9b2
+inline int32_t Hwc3DataspaceToHwc2(common::Dataspace dataspace) {
+  return static_cast<int32_t>(dataspace);
+}
+
+// Values match, so static_cast is okay.
+// https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/graphics/common/aidl/android/hardware/graphics/common/Transform.aidl
+// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.0.h;l=41
+inline int32_t Hwc3TransformToHwc2(common::Transform transform) {
+  return static_cast<int32_t>(transform);
+}
+
+};  // namespace aidl::android::hardware::graphics::composer3
\ No newline at end of file
diff --git a/hwc3/hwc3-drm.rc b/hwc3/hwc3-drm.rc
new file mode 100644
index 0000000..425dd24
--- /dev/null
+++ b/hwc3/hwc3-drm.rc
@@ -0,0 +1,8 @@
+service vendor.hwcomposer-3 /vendor/bin/hw/android.hardware.composer.hwc3-service.drm
+    class hal animation
+    interface aidl android.hardware.graphics.composer3.IComposer/default
+    user system
+    group graphics drmrpc
+    capabilities SYS_NICE
+    onrestart restart surfaceflinger
+    task_profiles ServiceCapacityLow
diff --git a/hwc3/hwc3-drm.xml b/hwc3/hwc3-drm.xml
new file mode 100644
index 0000000..911f7f8
--- /dev/null
+++ b/hwc3/hwc3-drm.xml
@@ -0,0 +1,10 @@
+<manifest version="1.0" type="device">
+    <hal format="aidl">
+        <name>android.hardware.graphics.composer3</name>
+        <version>3</version>
+        <interface>
+            <name>IComposer</name>
+            <instance>default</instance>
+        </interface>
+    </hal>
+</manifest>
diff --git a/hwc3/meson.build b/hwc3/meson.build
new file mode 100644
index 0000000..2486212
--- /dev/null
+++ b/hwc3/meson.build
@@ -0,0 +1,34 @@
+
+src_hwc3 = files(
+    'ComposerClient.cpp',
+    'Composer.cpp',
+    'DrmHwcThree.cpp',
+    'service.cpp',
+    'ComposerResources.cpp',
+    'Utils.cpp',
+)
+
+executable(
+    'android.hardware.composer.hwc3-service.drm',
+    src_hwc3,
+    cpp_args : common_cpp_flags + hwc2_cpp_flags,
+    dependencies : deps,
+    install : true,
+    link_with: [drmhwc_common, drmhwc_hwc2_common],
+    install_dir : get_option('bindir') / 'hw',
+    include_directories: inc_include,
+)
+
+configure_file(
+  input: 'hwc3-drm.rc',
+  output: '@PLAINNAME@',
+  copy: true,
+  install_dir: get_option('sysconfdir') / 'init',
+)
+
+configure_file(
+  input: 'hwc3-drm.xml',
+  output: '@PLAINNAME@',
+  copy: true,
+  install_dir: get_option('sysconfdir') / 'vintf' / 'manifest',
+)
diff --git a/hwc3/service.cpp b/hwc3/service.cpp
new file mode 100644
index 0000000..920260a
--- /dev/null
+++ b/hwc3/service.cpp
@@ -0,0 +1,60 @@
+/*
+ * Copyright 2024, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#define LOG_TAG "drmhwc"
+#define ATRACE_TAG (ATRACE_TAG_GRAPHICS | ATRACE_TAG_HAL)
+
+#include <android/binder_manager.h>
+#include <android/binder_process.h>
+#include <binder/ProcessState.h>
+#include <sched.h>
+
+#include "Composer.h"
+#include "utils/log.h"
+
+using aidl::android::hardware::graphics::composer3::impl::Composer;
+
+int main(int /*argc*/, char* argv[]) {
+  (void)argv;
+  ALOGI("hwc3-drm starting up");
+
+  // same as SF main thread
+  struct sched_param param = {0};
+  param.sched_priority = 2;
+  if (sched_setscheduler(0, SCHED_FIFO | SCHED_RESET_ON_FORK, &param) != 0) {
+    ALOGE("Couldn't set SCHED_FIFO: %d", errno);
+  }
+
+  auto composer = ndk::SharedRefBase::make<Composer>();
+  if (!composer) {
+    ALOGE("Failed to create composer");
+    return -ENOMEM;
+  }
+
+  const std::string instance = std::string() + Composer::descriptor +
+                               "/default";
+  ALOGI("HWC3 service name %s", instance.c_str());
+  auto status = AServiceManager_addServiceWithFlags(
+      composer->asBinder().get(), instance.c_str(),
+      AServiceManager_AddServiceFlag::ADD_SERVICE_ALLOW_ISOLATED);
+  if (status != STATUS_OK) {
+    ALOGE("Failed to register service. Error %d", (int)status);
+    return -EINVAL;
+  }
+
+  ABinderProcess_joinThreadPool();
+  return EXIT_FAILURE;  // should not reach
+}
diff --git a/meson.build b/meson.build
index c2e5fb6..e9a86ec 100644
--- a/meson.build
+++ b/meson.build
@@ -1,7 +1,7 @@
 project(
     'drm_hwcomposer',
     ['c', 'cpp'],
-    version : '2',
+    version : '3',
     license : 'APACHE-2.0',
     meson_version : '>= 0.56',
     default_options : ['buildtype=debugoptimized', 'b_ndebug=if-release', 'c_std=c11', 'cpp_std=c++17', 'cpp_rtti=false']
@@ -18,6 +18,14 @@ src_common = files(
     'utils/fd.cpp',
 )
 
+srcs_hwc2_device = [
+    'hwc2_device/hwc2_device.cpp',
+    'hwc2_device/DrmHwcTwo.cpp',
+    'hwc2_device/HwcDisplayConfigs.cpp',
+    'hwc2_device/HwcDisplay.cpp',
+    'hwc2_device/HwcLayer.cpp',
+]
+
 deps = [
     dependency('cutils'),
     dependency('drm'),
@@ -27,6 +35,9 @@ deps = [
     dependency('sync'),
     dependency('ui'),
     dependency('utils'),
+    dependency('aidlcommonsupport'),
+    dependency('android.hardware.graphics.composer@2.1-resources'),
+    dependency('android.hardware.graphics.composer@2.2-resources'),
 ]
 
 common_cpp_flags = [
@@ -50,3 +61,4 @@ drmhwc_common = static_library(
 )
 
 subdir('hwc2_device')
+subdir('hwc3')
diff --git a/utils/UEvent.h b/utils/UEvent.h
index 5b9ecea..051b1fc 100644
--- a/utils/UEvent.h
+++ b/utils/UEvent.h
@@ -17,6 +17,8 @@
 #pragma once
 
 #include <linux/netlink.h>
+#include <poll.h>
+#include <sys/eventfd.h>
 #include <sys/socket.h>
 
 #include <cerrno>
@@ -52,12 +54,23 @@ class UEvent {
       return {};
     }
 
-    return std::unique_ptr<UEvent>(new UEvent(fd));
+    auto stop_event_fd = MakeUniqueFd(eventfd(0, EFD_CLOEXEC));
+    if (!stop_event_fd) {
+      ALOGE("Failed to create eventfd: errno=%i", errno);
+      return {};
+    }
+
+    return std::unique_ptr<UEvent>(new UEvent(fd, stop_event_fd));
   }
 
   auto ReadNext() -> std::optional<std::string> {
     constexpr int kUEventBufferSize = 1024;
     char buffer[kUEventBufferSize];
+
+    if (!WaitForData()) {
+      return {};
+    }
+
     ssize_t ret = 0;
     ret = read(*fd_, &buffer, sizeof(buffer));
     if (ret == 0)
@@ -77,9 +90,57 @@ class UEvent {
     return std::string(buffer);
   }
 
+  void Stop() {
+    // Increment the eventfd by writing 1. All subsequent calls to ReadNext will
+    // return false.
+    const uint64_t value = 1;
+    const ssize_t ret = write(*stop_event_fd_, &value, sizeof(value));
+    if (ret == -1) {
+      ALOGE("Error writing to eventfd. errno: %d", errno);
+    } else if (ret != sizeof(value)) {
+      ALOGE("Wrote fewer bytes to eventfd than expected: %zd vs %zd", ret,
+            sizeof(value));
+    }
+  }
+
  private:
-  explicit UEvent(UniqueFd &fd) : fd_(std::move(fd)){};
+  enum { kFdIdx = 0, kStopEventFdIdx, kNumFds };
+
+  UEvent(UniqueFd &fd, UniqueFd &stop_event_fd)
+      : fd_(std::move(fd)), stop_event_fd_(std::move(stop_event_fd)) {};
+
+  // Returns true if there is data to be read off of fd_.
+  bool WaitForData() {
+    struct pollfd poll_fds[kNumFds];
+    poll_fds[kFdIdx].fd = *fd_;
+    poll_fds[kFdIdx].events = POLLIN;
+    poll_fds[kStopEventFdIdx].fd = *stop_event_fd_;
+    poll_fds[kStopEventFdIdx].events = POLLIN;
+
+    const int ret = poll(poll_fds, kNumFds, -1);
+    if (ret == 0) {
+      // Timeout shouldn't happen, but return here anyways.
+      ALOGE("Timed out polling uevent.");
+      return false;
+    }
+    if (ret < 1) {
+      ALOGE("Error polling uevent. errno: %d", errno);
+      return false;
+    }
+
+    if ((poll_fds[kStopEventFdIdx].revents & POLLIN) != 0) {
+      // Stop event has been signalled. Return without reading from the fd to
+      // ensure that this fd stays in a readable state.
+      ALOGI("Stop event signalled.");
+      return false;
+    }
+
+    // Return true if there is data to read.
+    return (poll_fds[kFdIdx].revents & POLLIN) != 0;
+  }
+
   UniqueFd fd_;
+  UniqueFd stop_event_fd_;
 };
 
 }  // namespace android
```

