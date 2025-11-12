```diff
diff --git a/.ci/.gitlab-ci-checkcommit.sh b/.ci/.gitlab-ci-checkcommit.sh
index 5649475..89c8b43 100755
--- a/.ci/.gitlab-ci-checkcommit.sh
+++ b/.ci/.gitlab-ci-checkcommit.sh
@@ -49,18 +49,6 @@ git log --pretty='%h' FETCH_HEAD..HEAD | while read h; do
 
 	commit_body=$(git show -s --pretty=%b "$h")
 
-	author=$(git show -s --format='%an <%ae>' "$h")
-	if findtag "$commit_body" "Signed-off-by" "$author"; then
-		echoerr "Author SoB tag is missing from commit $h"
-		exit 1
-	fi
-
-	committer=$(git show -s --format='%cn <%ce>' "$h")
-	if findtag "$commit_body" "Signed-off-by" "$committer"; then
-		echoerr "Committer SoB tag is missing from commit $h"
-		exit 1
-	fi
-
 	git diff -U0 "$h" -- | clang-format-diff-19 -p 1 -style=file > /tmp/format-fixup.patch
 	if [ -s  /tmp/format-fixup.patch ]; then
 		cat /tmp/format-fixup.patch >&2
diff --git a/.ci/.gitlab-ci.yml b/.ci/.gitlab-ci.yml
new file mode 100644
index 0000000..46d8b75
--- /dev/null
+++ b/.ci/.gitlab-ci.yml
@@ -0,0 +1,110 @@
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
+debian/x86_64_cuttlefish:
+  extends:
+    - .fdo.container-build@debian
+    - .container
+  timeout: 6h
+  variables:
+    FDO_DISTRIBUTION_VERSION: "bookworm-slim"
+    FDO_DISTRIBUTION_EXEC: 'bash .ci/container/debian/x86_64_cuttlefish.sh'
+    HWC_TAG: $DEBIAN_CUTTLEFISH_TAG
+  after_script:
+    - cp "/cache/${CI_PROJECT_PATH}/cuttlefish.log.txt.gz" "${CI_PROJECT_DIR}/"
+    - cp "/cache/${CI_PROJECT_PATH}/${CUTTLEFISH_TARBALL}" "${CI_PROJECT_DIR}/"
+  artifacts:
+    when: on_failure
+    paths:
+      - "${CI_PROJECT_DIR}/cuttlefish.log.txt.gz"
+      - "${CI_PROJECT_DIR}/${CUTTLEFISH_TARBALL}"
+    expire_in: 1 week
+
+.ubuntu/x86_64_hwc:
+  extends:
+    - .fdo.container-build@ubuntu
+    - .container
+  variables:
+    FDO_DISTRIBUTION_VERSION: "24.10"
+
+ubuntu/x86_64_aospless:
+  extends:
+    - .ubuntu/x86_64_hwc
+  variables:
+    FDO_DISTRIBUTION_EXEC: 'bash .ci/container/ubuntu/x86_64_aospless.sh'
+    HWC_TAG: $UBUNTU_AOSPLESS_TAG
+    ANDROID_SDK_VERSION: 35
+
+ubuntu/x86_64_android:
+  extends:
+    - .ubuntu/x86_64_hwc
+  timeout: 2h
+  variables:
+    ANDROID_VERSION: 15
+    ANDROID_SDK_VERSION: 35
+    ANDROID_CTS_DEVICE_ARCH: "x86"
+    ANDROID_CTS_MODULES: >-
+      CtsGraphicsTestCases
+      CtsDisplayTestCases
+    FDO_DISTRIBUTION_EXEC: 'bash .ci/container/ubuntu/x86_64_android.sh'
+    HWC_TAG: $UBUNTU_ANDROID_TAG
+  after_script:
+    - cp /vts.log.txt "${CI_PROJECT_DIR}/vts.log.txt"
+  artifacts:
+    when: always
+    paths:
+      - "${CI_PROJECT_DIR}/vts.log.txt"
+    expire_in: 1 week
+
+.set-image:
+  extends:
+    - .incorporate-templates-commit
+  image: "$CI_REGISTRY_IMAGE/${HWC_IMAGE}:${FDO_DISTRIBUTION_TAG}"
+
+.use-ubuntu/x86_64_aospless:
+  extends:
+    - .fdo.container-build@ubuntu
+    - .set-image
+  variables:
+    HWC_IMAGE: $UBUNTU_AOSPLESS_IMAGE
+    HWC_TAG: $UBUNTU_AOSPLESS_TAG
+  needs:
+    - ubuntu/x86_64_aospless
+
+.use-ubuntu/x86_64_android:
+  extends:
+    - .fdo.container-build@ubuntu
+    - .set-image
+  variables:
+    HWC_IMAGE: $UBUNTU_ANDROID_IMAGE
+    HWC_TAG: $UBUNTU_ANDROID_TAG
+  needs:
+    - ubuntu/x86_64_android
+
+use-debian/x86_64_cuttlefish:
+  extends:
+    - .fdo.container-build@debian
+    - .set-image
+  variables:
+    HWC_IMAGE: $DEBIAN_CUTTLEFISH_IMAGE
+    HWC_TAG: $DEBIAN_CUTTLEFISH_TAG
+  needs:
+    - debian/x86_64_cuttlefish
+  script:
+    - cp -a "/${CUTTLEFISH_TARBALL}" "${CI_PROJECT_DIR}"
+  artifacts:
+    when: always
+    paths:
+      - "${CI_PROJECT_DIR}/${CUTTLEFISH_TARBALL}"
+    expire_in: 1 week
diff --git a/.ci/Makefile b/.ci/Makefile
index d57ea86..fc1f2ce 100644
--- a/.ci/Makefile
+++ b/.ci/Makefile
@@ -11,6 +11,7 @@ SRC_DIR := .
 CXXFLAGS := -Wall -Wextra -Werror -Wno-missing-designated-field-initializers
 CXXFLAGS += -D_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS -Wthread-safety
 CXXFLAGS += -fvisibility-inlines-hidden -std=gnu++17 -DHWC2_USE_CPP11 -DHWC2_INCLUDE_STRINGIFICATION -fno-rtti
+CXXFLAGS += --target=aarch64-linux-android35
 
 CXXARGS := $(shell cat $(BASE_DIR)/toolchain_wrapper/sharedlib.cppflags)
 CXXARGS := $(subst [BASE_DIR],$(BASE_DIR),$(CXXARGS))
@@ -29,8 +30,8 @@ TIDY_FILES_OVERRIDE := \
     drm/DrmUnique.h:FINE                                \
     hwc2_device/DrmHwcTwo.cpp:COARSE                    \
     hwc2_device/DrmHwcTwo.h:COARSE                      \
-    hwc2_device/HwcDisplay.cpp:COARSE                   \
-    hwc2_device/HwcDisplay.h:COARSE                     \
+    hwc/HwcDisplay.cpp:COARSE                           \
+    hwc/HwcDisplay.h:COARSE                             \
     utils/log.h:FINE                                    \
     utils/properties.h:FINE                             \
 
@@ -93,6 +94,8 @@ clean:
 	rm -rf $(OUT_DIR)/
 
 # Build
+# clang-tidy picks up gtest and gmock headers
+SKIP_FILES := stats/CompositionStatsTest.cpp
 
 BUILD_FILES_AUTO := $(shell find -L $(SRC_DIR) -not -path '*/\.*' -not -path '*/tests/test_include/*' -path '*.cpp')
 SKIP_FILES_path := $(foreach file,$(SKIP_FILES),$(SRC_DIR)/$(file))
diff --git a/.ci/android/cts-includes.txt b/.ci/android/cts-includes.txt
new file mode 100644
index 0000000..6d4b811
--- /dev/null
+++ b/.ci/android/cts-includes.txt
@@ -0,0 +1,16 @@
+x86_64 CtsGraphicsTestCases android.graphics.cts.ANativeWindowTest
+x86_64 CtsGraphicsTestCases android.graphics.cts.ASurfaceTextureTest
+x86_64 CtsGraphicsTestCases android.graphics.cts.HardwareRendererTest
+x86_64 CtsGraphicsTestCases android.graphics.cts.EGL14Test
+x86_64 CtsGraphicsTestCases android.graphics.cts.EGL15Test
+x86_64 CtsGraphicsTestCases android.graphics.cts.FrameRateOverrideTest
+x86_64 CtsGraphicsTestCases android.graphics.cts.SetFrameRateTest
+x86_64 CtsGraphicsTestCases android.graphics.cts.MatchContentFrameRateTest
+x86_64 CtsGraphicsTestCases android.graphics.cts.VulkanFeaturesTest0
+x86_64 CtsGraphicsTestCases android.graphics.cts.VulkanPreTransformTest
+x86_64 CtsGraphicsTestCases android.graphics.cts.BasicVulkanGpuTest0
+x86_64 CtsGraphicsTestCases android.graphics.cts.PixelFormatTest
+x86_64 CtsGraphicsTestCases android.graphics.cts.BitmapColorSpaceTest
+x86_64 CtsGraphicsTestCases android.graphics.cts.ColorSpaceTest
+
+x86_64 CtsDisplayTestCases
diff --git a/.ci/android/cts-runner.sh b/.ci/android/cts-runner.sh
new file mode 100755
index 0000000..858ed9f
--- /dev/null
+++ b/.ci/android/cts-runner.sh
@@ -0,0 +1,31 @@
+#!/usr/bin/env bash
+# shellcheck disable=SC1091 # no need to follow references to other shell scripts
+
+set -e
+
+EXIT_CODE=1
+
+if [[ -z ${CI_PROJECT_DIR} ]]; then
+    CI_PROJECT_DIR="$(dirname "${0}")/../.."
+fi
+
+source "${CI_PROJECT_DIR}/.ci/android/launch-cvd.sh"
+
+section_start run_android_cts "run_android_cts"
+set -x
+
+INCLUDE_FILE="${CI_PROJECT_DIR}/.ci/android/cts-includes.txt"
+# shellcheck disable=SC2086 # keep word splitting
+INCLUDE_FILTERS="$(grep -v -E "(^#|^[[:space:]]*$)" "$INCLUDE_FILE" | sed -e 's/\s*$//g' -e 's/.*/--include-filter "\0" /g')"
+
+# shellcheck disable=SC2086 # keep word splitting
+eval /android-tools/android-cts/tools/cts-tradefed run commandAndExit cts-dev \
+  $INCLUDE_FILTERS --log-level-display ASSERT
+
+# Even if there are failed tests, eval will exit with 0, so check for failures manually.
+[ "$(grep "^FAILED" /android-tools/android-cts/results/latest/invocation_summary.txt | tr -d ' ' | cut -d ':' -f 2)" = "0" ]
+export EXIT_CODE=$?
+section_end run_android_cts
+
+cp -r "/android-tools/android-cts/results/latest"/* "${RESULTS_DIR}"
+cp -r "/android-tools/android-cts/logs/latest"/* "${RESULTS_DIR}"
diff --git a/.ci/android/launch-cvd.sh b/.ci/android/launch-cvd.sh
new file mode 100755
index 0000000..ce718ab
--- /dev/null
+++ b/.ci/android/launch-cvd.sh
@@ -0,0 +1,122 @@
+#!/usr/bin/env bash
+# shellcheck disable=SC1091 # no need to follow references to other shell scripts
+
+set -e
+
+EXIT_CODE=1
+
+: "${CI_PROJECT_DIR:=/}"
+
+source "${CI_PROJECT_DIR}/.ci/setup-test-env.sh"
+
+: "${RESULTS_DIR:=./results}"
+
+set -u
+
+mkdir -p "${RESULTS_DIR}"
+
+function my_atexit()
+{
+  # shellcheck disable=SC2317
+  cp /cuttlefish/cuttlefish/instances/cvd-1/logs/logcat "${RESULTS_DIR}" || true
+  # shellcheck disable=SC2317
+  cp /cuttlefish/cuttlefish/instances/cvd-1/kernel.log "${RESULTS_DIR}" || true
+  # shellcheck disable=SC2317
+  cp /cuttlefish/cuttlefish/instances/cvd-1/logs/launcher.log "${RESULTS_DIR}" || true
+  exit $EXIT_CODE
+}
+
+# Cuttlefish is an artifact built earlier in the pipeline
+tar xf "${CI_PROJECT_DIR}/${CUTTLEFISH_TARBALL}" -C /
+cp -r "/cuttlefish/cvd-host_package/." /cuttlefish
+
+export PATH=/cuttlefish/bin:/android-tools/android-cts/jdk/bin/:/android-tools/build-tools:$PATH
+
+[ -e /dev/kvm ] || echo "Warning: /dev/kvm is not available"
+trap my_atexit EXIT
+trap 'exit 2' HUP INT PIPE TERM
+
+section_start launch_cvd "launch_cvd"
+cd /cuttlefish
+
+VSOCK_BASE=10000 # greater than all the default vsock ports
+VSOCK_CID=$((VSOCK_BASE + (CI_JOB_ID & 0xfff)))
+
+ulimit -S -n 1048576
+HOME=/cuttlefish launch_cvd \
+  -daemon \
+  -verbosity=VERBOSE \
+  -file_verbosity=VERBOSE \
+  -use_overlay=false \
+  -enable_bootanimation=false \
+  -guest_enforce_security=false \
+  -report_anonymous_usage_stats=no \
+  -gpu_mode="guest_swiftshader" \
+  -memory_mb 32768 \
+  -blank_sdcard_image_mb 65536 \
+  -data_policy=always_create \
+  -blank_data_image_mb 65536 \
+  -enable_audio=false \
+  -enable-sandbox=false \
+  -enable_modem_simulator=false \
+  -vsock_guest_cid=$VSOCK_CID \
+  -cpus="${FDO_CI_CONCURRENT:-4}"
+
+while [ "$(adb shell dumpsys -l | grep SurfaceFlinger)" = "" ] ; do sleep 1; done
+adb shell dumpsys SurfaceFlinger | grep GLES
+
+section_end launch_cvd
+
+section_start push_drm_hwc "push_drm_hwc"
+set -x
+
+adb wait-for-device root
+adb remount /vendor
+adb reboot
+adb wait-for-device root
+adb remount /vendor
+
+# stop ranchu that comes with the cuttlefish image
+adb shell stop vendor.hwcomposer-3
+adb shell umount /apex/com.android.hardware.graphics.composer.ranchu
+adb shell umount /apex/com.android.hardware.graphics.composer.ranchu@1
+adb shell umount /bootstrap-apex/com.android.hardware.graphics.composer.ranchu@1
+adb shell umount /bootstrap-apex/com.android.hardware.graphics.composer.ranchu
+
+# These artifacts are built earlier in the pipeline
+adb push "${CI_PROJECT_DIR}/install/x86_64/vendor/bin/hw/android.hardware.composer.hwc3-service.drm" \
+  "/vendor/bin/hw/android.hardware.composer.hwc3-service.drm"
+adb push "${CI_PROJECT_DIR}/install/x86_64/vendor/etc/init/hwc3-drm.rc" \
+  "/vendor/etc/init/hwc3-drm.rc"
+adb push "${CI_PROJECT_DIR}/install/x86_64/vendor/etc/vintf/manifest/hwc3-drm.xml" \
+  "/vendor/etc/vintf/manifest/hwc3-drm.xml"
+adb push "${CI_PROJECT_DIR}/install/x86_64/vendor/lib64/hw/hwcomposer.drm.so" \
+  "/vendor/lib64/hw/hwcomposer.drm.so"
+
+# Start drmhwc
+adb shell LD_LIBRARY_PATH=/system/lib64:/apex/com.android.hardware.graphics.composer@1/lib64 \
+  /vendor/bin/hw/android.hardware.composer.hwc3-service.drm &
+adb logcat -d | grep -i hwc
+
+set +x
+
+# If these service is missing, cts-tradefed will fail device pretests
+while [ "$(adb shell dumpsys -l | grep window)" = "" ] ; do sleep 1; done
+echo "window ok"
+
+while [ "$(adb shell dumpsys -l | grep lock_settings)" = "" ] ; do sleep 1; done
+echo "lock_settings ok"
+
+while [ "$(adb shell dumpsys -l | grep display)" = "" ] ; do sleep 1; done
+echo "display ok"
+
+while [ "$(adb shell dumpsys -l | grep input)" = "" ] ; do sleep 1; done
+echo "input ok"
+
+while [ "$(adb shell dumpsys -l | grep logcat)" = "" ] ; do sleep 1; done
+echo "logcat ok"
+
+# Look for other missing services
+adb shell dumpsys > /dev/null
+
+section_end push_drm_hwc
diff --git a/.ci/android/vts-runner.sh b/.ci/android/vts-runner.sh
new file mode 100755
index 0000000..cfb88d4
--- /dev/null
+++ b/.ci/android/vts-runner.sh
@@ -0,0 +1,33 @@
+#!/usr/bin/env bash
+# shellcheck disable=SC1091 # no need to follow references to other shell scripts
+
+set -e
+
+EXIT_CODE=1
+
+if [[ -z ${CI_PROJECT_DIR} ]]; then
+    CI_PROJECT_DIR="$(dirname "${0}")/../.."
+fi
+
+source "${CI_PROJECT_DIR}/.ci/android/launch-cvd.sh"
+
+section_start run_android_vts "run_android_vts"
+set -x
+adb wait-for-device devices
+adb root
+adb push /VtsHalGraphicsComposer3_TargetTest /data/local/tmp/
+adb shell stop surfaceflinger
+
+SKIP_FILE="${CI_PROJECT_DIR}/.ci/android/vts-skips.txt"
+EXCLUDE_FILTERS="$(grep -v -E "^(#|[[:space:]]*$)" "$SKIP_FILE" | paste -sd: -)"
+
+# Run the entire command inside adb shell to capture stdout/err
+adb shell "(/data/local/tmp/VtsHalGraphicsComposer3_TargetTest \
+  --gtest_filter=-$EXCLUDE_FILTERS 2>&1 | tee /data/local/tmp/vts_results.txt)"
+
+adb pull /data/local/tmp/vts_results.txt "${RESULTS_DIR}"
+
+[ "$(grep "FAILED" "${RESULTS_DIR}/vts_results.txt")" = "" ]
+export EXIT_CODE=$?
+
+section_end run_android_vts
diff --git a/.ci/android/vts-skips.txt b/.ci/android/vts-skips.txt
new file mode 100644
index 0000000..ad88650
--- /dev/null
+++ b/.ci/android/vts-skips.txt
@@ -0,0 +1,4 @@
+PerInstance/GraphicsComposerAidlTest.GetColorModes/0_android_hardware_graphics_composer3_IComposer_default
+PerInstance/GraphicsComposerAidlCommandTest.ExpectedPresentTime_NoTimestamp/0_android_hardware_graphics_composer3_IComposer_default
+PerInstance/GraphicsComposerAidlCommandTest.ExpectedPresentTime_0/0_android_hardware_graphics_composer3_IComposer_default
+PerInstance/GraphicsComposerAidlCommandTest.ExpectedPresentTime_5/0_android_hardware_graphics_composer3_IComposer_default
diff --git a/.ci/build-arm64.sh b/.ci/build-arm64.sh
new file mode 100755
index 0000000..92db2b3
--- /dev/null
+++ b/.ci/build-arm64.sh
@@ -0,0 +1,15 @@
+#! /usr/bin/env bash
+# shellcheck disable=SC1091 # no need to follow references to other shell scripts
+
+set -e
+
+source "./.ci/setup-test-env.sh"
+
+section_start build_drmhwc_arm64 "build_drmhwc_arm64"
+set -x
+ln -s "${CI_PROJECT_DIR}" "/aospless_arm64/src"
+make -C /aospless_arm64 install
+mkdir -p "${CI_PROJECT_DIR}/install/arm64"
+cp -r /aospless_arm64/install/* "${CI_PROJECT_DIR}/install/arm64"
+set +x
+section_end build_drmhwc_arm64
diff --git a/.ci/build-x86_64.sh b/.ci/build-x86_64.sh
new file mode 100755
index 0000000..1874717
--- /dev/null
+++ b/.ci/build-x86_64.sh
@@ -0,0 +1,15 @@
+#! /usr/bin/env bash
+# shellcheck disable=SC1091 # no need to follow references to other shell scripts
+
+set -e
+
+source "./.ci/setup-test-env.sh"
+
+section_start build_drmhwc_x86_64 "build_drmhwc_x86_64"
+set -x
+ln -s "${CI_PROJECT_DIR}" "/aospless_x86_64/src"
+make -C /aospless_x86_64 install
+mkdir -p "${CI_PROJECT_DIR}/install/x86_64"
+cp -r /aospless_x86_64/install/* "${CI_PROJECT_DIR}/install/x86_64"
+set +x
+section_end build_drmhwc_arm64
diff --git a/.ci/container/.gitlab-ci.yml b/.ci/container/.gitlab-ci.yml
deleted file mode 100644
index 85024f8..0000000
--- a/.ci/container/.gitlab-ci.yml
+++ /dev/null
@@ -1,37 +0,0 @@
-
-.incorporate-templates-commit:
-  variables:
-    FDO_DISTRIBUTION_TAG: "${HWC_TAG}--${CI_TEMPLATES_COMMIT}"
-
-.container:
-  stage: container
-  extends:
-    - .incorporate-templates-commit
-  variables:
-    FDO_REPO_SUFFIX: $CI_JOB_NAME
-    # no need to pull the whole repo to build the container image
-    GIT_STRATEGY: none
-
-ubuntu/x86_64_hwc:
-  extends:
-    - .fdo.container-build@ubuntu
-    - .container
-  variables:
-    FDO_DISTRIBUTION_VERSION: "24.10"
-    FDO_DISTRIBUTION_EXEC: 'bash .ci/container/ubuntu/x86_64_aospless.sh'
-    HWC_TAG: $UBUNTU_HWC_TAG
-
-.set-image:
-  extends:
-    - .incorporate-templates-commit
-  image: "$CI_REGISTRY_IMAGE/${HWC_IMAGE}:${FDO_DISTRIBUTION_TAG}"
-
-.use-ubuntu/x86_64_hwc:
-  extends:
-    - .fdo.container-build@ubuntu
-    - .set-image
-  variables:
-    HWC_TAG: $UBUNTU_HWC_TAG
-    HWC_IMAGE: $UBUNTU_HWC_IMAGE
-  needs:
-    - ubuntu/x86_64_hwc
diff --git a/.ci/container/debian/x86_64_cuttlefish.sh b/.ci/container/debian/x86_64_cuttlefish.sh
new file mode 100755
index 0000000..e539977
--- /dev/null
+++ b/.ci/container/debian/x86_64_cuttlefish.sh
@@ -0,0 +1,209 @@
+#!/usr/bin/env bash
+# shellcheck disable=SC1091 # no need to follow references to other shell scripts
+# Bump the DEBIAN_CUTTLEFISH_TAG for changes in this file to take effect.
+set -e
+
+function get_repo() {
+  local repo_dir="$1"
+  local repo_url="$2"
+  local commit="$3"
+
+  echo "Fetching ${repo_url} at commit ${commit} into ${repo_dir}"
+  rm -rf "${repo_dir}"
+  mkdir -p "${repo_dir}"
+  pushd "${repo_dir}"
+  git init
+  git remote add origin "${repo_url}"
+  git fetch --depth 1 origin "${commit}"
+  git checkout FETCH_HEAD
+  git reset --hard
+  popd
+}
+
+
+function my_atexit()
+{
+  # This directory survives outside of the container, so use it for job artifacts
+  mkdir -p "/cache/${CI_PROJECT_PATH}"
+  gzip -c "/cuttlefish.log.txt" > "/cache/${CI_PROJECT_PATH}/cuttlefish.log.txt.gz" || true
+  cp "/${CUTTLEFISH_TARBALL}" "/cache/${CI_PROJECT_PATH}/${CUTTLEFISH_TARBALL}" || true
+
+  apt remove -y "${EPHEMERAL_DEPS[@]}"
+
+  # clean up the container to avoid storing > 200GB
+  rm "${TOP}" -rf
+}
+
+trap my_atexit EXIT
+trap 'exit 2' HUP INT PIPE TERM
+
+# remove logs from previous builds
+rm "/cache/${CI_PROJECT_PATH}/cuttlefish.log.txt" || true
+rm "/cache/${CI_PROJECT_PATH}/${CUTTLEFISH_TARBALL}" || true
+
+source "./.ci/setup-test-env.sh"
+
+EPHEMERAL_DEPS=(
+  binutils
+  bison
+  flex
+  glslang-tools
+  libncurses5
+  ninja-build
+  pkg-config
+  pipx
+  python3
+  python3-mako
+  python3-yaml
+  rsync
+  ssh
+  time
+  unzip
+  wget
+  xz-utils
+  zip
+  zstd
+)
+
+DEPS=(
+  ca-certificates
+  curl
+  git
+  gpg
+  gpg-agent
+  sudo
+  vim
+)
+
+export DEBIAN_FRONTEND=noninteractive
+
+section_start install_packages "install_packages"
+set -x
+apt-get update
+apt-get upgrade -y
+apt-get install -y --no-install-recommends "${EPHEMERAL_DEPS[@]}"
+apt-get install -y --no-install-recommends "${DEPS[@]}"
+curl -o /usr/local/bin/repo https://storage.googleapis.com/git-repo-downloads/repo
+chmod a+x /usr/local/bin/repo
+set +x
+section_end install_packages
+
+section_start repo_init "repo_init"
+
+# avoid accidentally reusing the .repo from previous builds
+rm /cache/.repo -rf
+
+TOP="$(pwd)/aosp"
+mkdir "${TOP}"
+cd "${TOP}"
+
+: "${ANDROID_BRANCH:?ANDROID_BRANCH is not set}"
+
+# prevent interactive colour diffs question
+yes n | repo init \
+  -u https://android.googlesource.com/platform/manifest \
+  -b "${ANDROID_BRANCH}" \
+  --depth=1
+
+ # Don't increase parallel jobs or they will be denied
+time repo sync --fail-fast --no-tags -j4
+section_end repo_init
+
+section_start customize_repo "customize_repo"
+
+MESA3D_DIR="${TOP}/external/mesa3d"
+MESA3D_URL="https://gitlab.freedesktop.org/mesa/mesa.git"
+MESA3D_COMMIT=fafdd242850657d58ae66836ee5d154f1187fe8b
+get_repo "${MESA3D_DIR}" "${MESA3D_URL}" "${MESA3D_COMMIT}"
+
+LLVM_PROJECT_DIR="${TOP}/external/llvm-project"
+LLVM_PROJECT_URL="https://github.com/maurossi/llvm-project"
+LLVM_PROJECT_COMMIT=d3ef89ac85fe7c8bc65a6b7871110f32eac76ce1
+get_repo "${LLVM_PROJECT_DIR}" "${LLVM_PROJECT_URL}" "${LLVM_PROJECT_COMMIT}"
+
+LIBDISPLAY_DIR="${TOP}/external/libdisplay_info"
+LIBDISPLAY_URL="https://android.googlesource.com/platform/external/libdisplay-info"
+LIBDISPLAY_COMMIT=eb514a595897b3a87fde977c9b0db3794bb17730
+get_repo "${LIBDISPLAY_DIR}" "${LIBDISPLAY_URL}" "${LIBDISPLAY_COMMIT}"
+
+# Build tools are restricted to approved locations in aosp
+# https://android.googlesource.com/platform/build/+/main/Changes.md#PATH_Tools
+# Don't use TEMPORARY_DISABLE_PATH_RESTRICTIONS=true as it is no longer available
+pipx install meson
+mv "${HOME}/.local/bin/meson" /usr/bin
+
+CROSVM_FILE="${TOP}/device/google/cuttlefish/host/libs/vm_manager/crosvm_manager.cpp"
+sed -i 's/\("androidboot.hardware.egl", \)"angle"/\1"mesa"/' "${CROSVM_FILE}"
+sed -i 's/\("androidboot.hardware.vulkan", \)"pastel"/\1"lvp"/' "${CROSVM_FILE}"
+sed -i '/"lvp"/a \        {"androidboot.hardware.hwcomposer.mode", "client"},' "${CROSVM_FILE}"
+
+cat >> "${TOP}/device/google/cuttlefish/shared/config/init.vendor.rc" <<EOF
+on early-init
+   setprop ro.gfx.angle.supported false
+   setprop mesa.libgl.always.software true
+   setprop mesa.android.no.kms.swrast true
+   setprop debug.hwui.renderer opengl
+   setprop debug.sf.disable_hwc_vds 1
+EOF
+
+cat >> "${TOP}/device/google/cuttlefish/shared/virgl/BoardConfig.mk" <<EOF
+BOARD_MESA3D_USES_MESON_BUILD := true
+BOARD_MESA3D_GALLIUM_DRIVERS := llvmpipe
+BOARD_MESA3D_VULKAN_DRIVERS := swrast
+BUILD_BROKEN_PLUGIN_VALIDATION := soong-llvm18
+EOF
+
+sed -i '$d' "${TOP}/device/google/cuttlefish/shared/virgl/device_vendor.mk"
+cat >>"${TOP}/device/google/cuttlefish/shared/virgl/device_vendor.mk" <<EOF
+PRODUCT_PACKAGES += \\
+  libEGL_mesa \\
+  libGLESv1_CM_mesa \\
+  libGLESv2_mesa \\
+  libgallium_dri \\
+  libglapi \\
+  vulkan.lvp
+EOF
+section_end customize_repo
+
+section_start build_cuttlefish "build_cuttlefish"
+source build/envsetup.sh
+export TARGET_BUILD_VARIANT=userdebug # needed for adb root and remount
+export TARGET_PRODUCT=aosp_cf_x86_64_phone
+export TARGET_RELEASE=trunk_staging
+lunch "${TARGET_PRODUCT}-${TARGET_RELEASE}-${TARGET_BUILD_VARIANT}"
+
+time make -j"${FDO_CI_CONCURRENT:-4}" > "/cuttlefish.log.txt" 2>&1 # Silent or job logs will exceed limit
+echo "Build of ${TARGET_PRODUCT}-${TARGET_RELEASE}-${TARGET_BUILD_VARIANT} complete."
+
+section_end build_cuttlefish
+
+section_start get_cuttlefish_images "get_cuttlefish_images"
+set -x
+
+CUTTLEFISH_DIR="/cuttlefish"
+mkdir -p "${CUTTLEFISH_DIR}"
+cd "${TOP}/out/target/product/vsoc_x86_64"
+
+PHONE_FILES=(
+  boot.img
+  bootloader
+  fastboot-info.txt
+  init_boot.img
+  android-info.txt
+  vendor_boot.img
+  userdata.img
+  vbmeta_system_dlkm.img
+  vbmeta_system.img
+  vbmeta_vendor_dlkm.img
+  vbmeta.img
+  super.img
+);
+
+for file in "${PHONE_FILES[@]}"; do cp -v "$file" "${CUTTLEFISH_DIR}/"; done;
+cd "${TOP}"
+cp -r  "${TOP}/out/host/linux-x86/cvd-host_package" "${CUTTLEFISH_DIR}"
+
+: "${CUTTLEFISH_TARBALL:?CUTTLEFISH_TARBALL is not set}"
+
+tar -cf - "${CUTTLEFISH_DIR}" | xz --best -e -T"${FDO_CI_CONCURRENT:-4}" > "/${CUTTLEFISH_TARBALL}" || true
+section_end get_cuttlefish_images
diff --git a/.ci/container/ubuntu/x86_64_android.sh b/.ci/container/ubuntu/x86_64_android.sh
new file mode 100755
index 0000000..721d7c5
--- /dev/null
+++ b/.ci/container/ubuntu/x86_64_android.sh
@@ -0,0 +1,116 @@
+#!/usr/bin/env bash
+# shellcheck disable=SC1091 # no need to follow references to other shell scripts
+# Bump the UBUNTU_ANDROID_TAG for changes in this file to take effect.
+
+set -e
+
+source "./.ci/setup-test-env.sh"
+
+DEPS=(
+  ca-certificates
+  curl
+  git
+  sudo
+  wget
+  xz-utils
+)
+
+DEPS_FOR_AOSP=(
+  gpg
+  gpg-agent
+  rsync
+  ssh
+  unzip
+)
+
+export DEBIAN_FRONTEND=noninteractive
+ln -fs /usr/share/zoneinfo/UTC /etc/localtime # suppress tzdata prompt
+
+section_start install_packages "install_packages"
+apt-get update
+apt-get upgrade -y
+apt-get install -y --no-remove --no-install-recommends "${DEPS[@]}"
+apt-get install -y --no-remove --no-install-recommends "${DEPS_FOR_AOSP[@]}"
+
+curl -o /usr/local/bin/repo https://storage.googleapis.com/git-repo-downloads/repo
+chmod a+x /usr/local/bin/repo
+section_end install_packages
+
+# Build and install Debian package for cuttlefish
+section_start get_cuttlefish_packages "get_cuttlefish_packages"
+set -x
+ANDROID_CUTTLEFISH_VERSION=v1.0.1
+mkdir /android-cuttlefish
+pushd /android-cuttlefish
+git init
+git remote add origin https://github.com/google/android-cuttlefish.git
+git fetch --depth 1 origin "$ANDROID_CUTTLEFISH_VERSION"
+git checkout FETCH_HEAD
+/android-cuttlefish/tools/buildutils/build_packages.sh
+apt-get install -y --allow-downgrades ./cuttlefish-base_*.deb ./cuttlefish-user_*.deb
+popd
+rm -rf /android-cuttlefish
+set +x
+section_end get_cuttlefish_packages
+
+# Download Android CTS
+section_start get_android_cts "get_android_cts"
+set -x
+ANDROID_CTS_VERSION="${ANDROID_VERSION}_r3"
+mkdir /android-tools
+cd /android-tools
+curl -L --retry 4 -f --retry-all-errors --retry-delay 60 \
+  -o "android-cts-${ANDROID_CTS_VERSION}-linux_x86-${ANDROID_CTS_DEVICE_ARCH}.zip" \
+  "https://dl.google.com/dl/android/cts/android-cts-${ANDROID_CTS_VERSION}-linux_x86-${ANDROID_CTS_DEVICE_ARCH}.zip"
+unzip -q ./*.zip
+rm ./*.zip
+
+# Keep only the interesting tests to save space
+# shellcheck disable=SC2086 # keep word splitting
+ANDROID_CTS_MODULES_KEEP_EXPRESSION=$(printf "%s|" $ANDROID_CTS_MODULES | sed -e 's/|$//g')
+find android-cts/testcases/ -mindepth 1 -type d | grep -v -E "$ANDROID_CTS_MODULES_KEEP_EXPRESSION" | xargs rm -rf
+set +x
+section_end get_android_cts
+
+section_start get_build-tools "get_build-tools"
+set -x
+curl -L --retry 4 -f --retry-all-errors --retry-delay 60 \
+  -o "build-tools_r${ANDROID_SDK_VERSION}-linux.zip" \
+  "https://dl.google.com/android/repository/build-tools_r${ANDROID_SDK_VERSION}_linux.zip"
+unzip "build-tools_r${ANDROID_SDK_VERSION}-linux.zip"
+rm ./*.zip
+mv "android-$ANDROID_VERSION" build-tools #rename the directory
+set +x
+section_end get_build-tools "get_build-tools"
+
+section_start repo_init "repo_init"
+TOP="/aosp"
+mkdir "${TOP}"
+cd "${TOP}"
+
+: "${ANDROID_BRANCH:?ANDROID_BRANCH is not set}"
+
+# prevent interactive colour diffs question
+yes n | repo init \
+  -u https://android.googlesource.com/platform/manifest \
+  -b "${ANDROID_BRANCH}" \
+  --depth=1
+
+ # Don't increase parallel jobs or they will be denied
+time repo sync --fail-fast --no-tags -j2
+section_end repo_init
+
+section_start build_vts "build_vts"
+source "${TOP}/build/envsetup.sh"
+export TARGET_BUILD_VARIANT=userdebug
+export TARGET_PRODUCT=aosp_cf_x86_64_slim
+export TARGET_RELEASE=trunk_staging
+lunch "${TARGET_PRODUCT}-${TARGET_RELEASE}-${TARGET_BUILD_VARIANT}"
+time m VtsHalGraphicsComposer3_TargetTest > "/vts.log.txt" 2>&1
+cp "${TOP}/out/target/product/vsoc_x86_64_only/data/nativetest64/VtsHalGraphicsComposer3_TargetTest/VtsHalGraphicsComposer3_TargetTest" \
+  "/VtsHalGraphicsComposer3_TargetTest"
+set +x
+section_end build_vts
+
+# clean up
+rm "${TOP}" -rf
diff --git a/.ci/container/ubuntu/x86_64_aospless.sh b/.ci/container/ubuntu/x86_64_aospless.sh
old mode 100644
new mode 100755
index 9b6e49d..2a820ee
--- a/.ci/container/ubuntu/x86_64_aospless.sh
+++ b/.ci/container/ubuntu/x86_64_aospless.sh
@@ -1,52 +1,132 @@
 #!/usr/bin/env bash
+# shellcheck disable=SC1091 # no need to follow references to other shell scripts
+# Bump the UBUNTU_AOSPLESS_TAG for changes in this file to take effect.
 
-# For any changes to this file to take effect, the UBUNTU_HWC_TAG has
-# to be bumped to generate a new image.
+set -e
 
-set -ex
+source "./.ci/setup-test-env.sh"
 
 DEPS=(
-    clang
-    llvm
-    clang-19
-    clang-tidy-19
-    clang-format-19
-    ca-certificates
-    git
-    libdrm-dev
-    blueprint-tools
-    libgtest-dev
-    make
-    python3
-    wget
-    sudo
-    rsync
-    lld
-    pkg-config
-    ninja-build
-    meson
-    python3-mako
-    python3-jinja2
-    python3-ply
-    python3-yaml
-    wget
-    gnupg
-    xz-utils
+  ca-certificates
+  git
+  wget
+  xz-utils
+)
+
+DEPS_FOR_AOSP=(
+  curl
+  gpg
+  gpg-agent
+  ssh
+)
+
+DEPS_FOR_BUILD=(
+  clang
+  clang-19
+  git
+  lld
+  llvm
+  make
+  meson
+  pkg-config
+  rsync
+)
+
+DEPS_FOR_TIDY=(
+  clang-tidy-19
+)
+
+DEPS_FOR_CHECK=(
+  blueprint-tools
+  clang-format-19
 )
 
 export DEBIAN_FRONTEND=noninteractive
 
+section_start install_packages "install_packages"
+set -x
 apt-get update
 apt-get upgrade -y
-
 apt-get install -y --no-remove --no-install-recommends "${DEPS[@]}"
+apt-get install -y --no-remove --no-install-recommends "${DEPS_FOR_AOSP[@]}"
+apt-get install -y --no-remove --no-install-recommends "${DEPS_FOR_BUILD[@]}"
+apt-get install -y --no-remove --no-install-recommends "${DEPS_FOR_TIDY[@]}"
+apt-get install -y --no-remove --no-install-recommends "${DEPS_FOR_CHECK[@]}"
+
+curl -o /usr/local/bin/repo https://storage.googleapis.com/git-repo-downloads/repo
+chmod a+x /usr/local/bin/repo
+set +x
+section_end install_packages
 
-wget https://gitlab.freedesktop.org/-/project/5/uploads/cafa930dad28acf7ee44d50101d5e8f0/aospless_drm_hwcomposer_arm64.tar.xz
+section_start repo_init "repo_init"
+set -x
+TOP="$(pwd)/aosp" # $CI_PROJECT_DIR is unavailable in FDO_DISTRIBUTION_EXEC
+mkdir "${TOP}"
+cd "${TOP}"
 
-sha256sum aospless_drm_hwcomposer_arm64.tar.xz
-if echo f792b1140861112f80c8a3a22e1af8e3eccf4910fe4449705e62d2032b713bf9 aospless_drm_hwcomposer_arm64.tar.xz | sha256sum --check; then
-    tar --no-same-owner -xf aospless_drm_hwcomposer_arm64.tar.xz -C /
+: "${ANDROID_BRANCH:?ANDROID_BRANCH is not set}"
+
+yes n | repo init \
+  -u https://android.googlesource.com/platform/manifest \
+  -b "${ANDROID_BRANCH}" \
+  --depth=1
+time repo sync --fail-fast --no-tags -j2
+
+rm external/drm_hwcomposer -rf
+
+git clone "${CI_REPOSITORY_URL}" external/drm_hwcomposer
+if [[ "${CI_PIPELINE_SOURCE}" == "merge_request_event" ]]; then
+  git -C external/drm_hwcomposer fetch origin "${CI_MERGE_REQUEST_REF_PATH}"
 else
-    echo "Tar file check failed"
-    exit 1
+  git -C external/drm_hwcomposer fetch origin "${CI_COMMIT_REF_NAME}"
 fi
+git -C external/drm_hwcomposer checkout FETCH_HEAD
+
+rm external/libdisplay_info -rf
+git clone --depth=1 https://android.googlesource.com/platform/external/libdisplay-info/ external/libdisplay_info
+
+git clone https://github.com/GloDroid/aospext.git
+sed -i "s|cpp_args = \['\[CPP_ARGS\]'\]|cpp_args = ['[CPP_ARGS]', '-D__ANDROID_API__=${ANDROID_SDK_VERSION}']|" "${TOP}/aospext/tools/meson_aosp_cross.cfg"
+cat >> "${TOP}/device/google/cuttlefish/shared/device.mk" <<EOF
+BOARD_BUILD_AOSPEXT_DRMHWCOMPOSER := true
+BOARD_DRMHWCOMPOSER_SRC_DIR := external/drm_hwcomposer
+EOF
+set +x
+source build/envsetup.sh
+section_end repo_init
+
+section_start build_aospless_x86_64 "build_aospless_x86_64"
+set -x
+cd "${TOP}/aospext"
+export TARGET_BUILD_VARIANT=userdebug # needed for adb root and remount
+export TARGET_PRODUCT=aosp_cf_x86_64_slim
+export TARGET_RELEASE=trunk_staging
+lunch "${TARGET_PRODUCT}-${TARGET_RELEASE}-${TARGET_BUILD_VARIANT}"
+mm
+cd "${TOP}/out/target/product/vsoc_x86_64_only/obj/AOSPEXT/DRMHWCOMPOSER/"
+make gen_aospless
+tar --no-same-owner -xf aospless.tar.gz
+# Rename and move the artifacts needed for subsequent jobs to the root directory
+cp -r "./aospless" "/aospless_x86_64"
+set +x
+section_end build_aospless_x86_64
+
+
+section_start build_aospless_arm64 "build_aospless_arm64"
+set -x
+cd "${TOP}/aospext"
+export TARGET_BUILD_VARIANT=userdebug # needed for adb root and remount
+export TARGET_PRODUCT=aosp_cf_arm64_slim
+export TARGET_RELEASE=trunk_staging
+lunch "${TARGET_PRODUCT}-${TARGET_RELEASE}-${TARGET_BUILD_VARIANT}"
+mm
+cd "${TOP}/out/target/product/vsoc_arm64_only/obj/AOSPEXT/DRMHWCOMPOSER/"
+make gen_aospless
+tar --no-same-owner -xf aospless.tar.gz
+# Rename and move the artifacts needed for subsequent jobs to the root directory
+cp -r "./aospless" "/aospless_arm64"
+set +x
+section_end build_aospless_arm64
+
+# clean up
+rm "${TOP}" -rf
diff --git a/.ci/image-tags.yml b/.ci/image-tags.yml
new file mode 100644
index 0000000..4ed4eab
--- /dev/null
+++ b/.ci/image-tags.yml
@@ -0,0 +1,8 @@
+
+variables:
+  DEBIAN_CUTTLEFISH_IMAGE: "debian/x86_64_cuttlefish"
+  DEBIAN_CUTTLEFISH_TAG: "20250422_2_build"
+  UBUNTU_AOSPLESS_IMAGE: "ubuntu/x86_64_aospless"
+  UBUNTU_AOSPLESS_TAG: "20250515_addapi"
+  UBUNTU_ANDROID_IMAGE: "ubuntu/x86_64_android"
+  UBUNTU_ANDROID_TAG: "20250422_build"
diff --git a/.ci/setup-test-env.sh b/.ci/setup-test-env.sh
new file mode 100755
index 0000000..9392cc7
--- /dev/null
+++ b/.ci/setup-test-env.sh
@@ -0,0 +1,81 @@
+#!/usr/bin/env bash
+# shellcheck disable=SC2048
+# shellcheck disable=SC2086 # we want word splitting
+# shellcheck disable=SC2155 # mktemp usually not failing
+
+shopt -s expand_aliases
+
+if [[ -z ${CI_JOB_STARTED_AT} ]]; then
+    CI_JOB_STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
+fi
+
+function _x_store_state {
+    if [[ "$-" == *"x"* ]]; then
+      previous_state_x=1
+    else
+      previous_state_x=0
+    fi
+}
+_x_store_state
+alias x_store_state='{ _x_store_state; } >/dev/null 2>/dev/null'
+
+function _x_off {
+    x_store_state
+    set +x
+}
+alias x_off='{ _x_off; } >/dev/null 2>/dev/null'
+
+function _x_restore {
+  [ $previous_state_x -eq 0 ] || set -x
+}
+alias x_restore='{ _x_restore; } >/dev/null 2>/dev/null'
+
+export JOB_START_S=$(date -u +"%s" -d "${CI_JOB_STARTED_AT:?}")
+
+function get_current_minsec {
+    DATE_S=$(date -u +"%s")
+    CURR_TIME=$((DATE_S-JOB_START_S))
+    printf "%02d:%02d" $((CURR_TIME/60)) $((CURR_TIME%60))
+}
+
+function _build_section_start {
+    local section_params=$1
+    shift
+    local section_name=$1
+    shift
+    CYAN="\e[0;36m"
+    ENDCOLOR="\e[0m"
+
+    CURR_MINSEC=$(get_current_minsec)
+    echo -e "\n\e[0Ksection_start:$(date +%s):$section_name$section_params\r\e[0K${CYAN}[${CURR_MINSEC}] $*${ENDCOLOR}\n"
+    x_restore
+}
+alias build_section_start="x_off; _build_section_start"
+
+function _section_start {
+    build_section_start "[collapsed=true]" $*
+    x_restore
+}
+alias section_start="x_off; _section_start"
+
+
+function _build_section_end {
+    echo -e "\e[0Ksection_end:$(date +%s):$1\r\e[0K"
+    x_restore
+}
+alias build_section_end="x_off; _build_section_end"
+
+function _section_end {
+    build_section_end $*
+    x_restore
+}
+alias section_end="x_off; _section_end"
+
+export -f _x_store_state
+export -f _x_off
+export -f _x_restore
+export -f get_current_minsec
+export -f _build_section_start
+export -f _section_start
+export -f _build_section_end
+export -f _section_end
diff --git a/.gitlab-ci.yml b/.gitlab-ci.yml
index 3d39f17..651bb77 100644
--- a/.gitlab-ci.yml
+++ b/.gitlab-ci.yml
@@ -4,54 +4,109 @@ workflow:
     - if: $CI_PIPELINE_SOURCE == 'push'
 
 variables:
+  ANDROID_BRANCH: android15-release
   DEBIAN_FRONTEND: noninteractive
-  CI_TEMPLATES_COMMIT: &ci-templates-commit e195d80f35b45cc73668be3767b923fd76c70ed5
+  CI_TEMPLATES_COMMIT: &ci-templates-commit ea3f77641d91765396beba192b8defd3085fa343
   FDO_UPSTREAM_REPO: "drm-hwcomposer/drm-hwcomposer"
-  UBUNTU_HWC_IMAGE: "ubuntu/x86_64_hwc"
-  UBUNTU_HWC_TAG: "20250218_hwc"
+  CUTTLEFISH_TARBALL: "cuttlefish.tar.xz"
 
 include:
   - project: 'freedesktop/ci-templates'
     ref: *ci-templates-commit
     file:
+      - '/templates/debian.yml'
       - '/templates/ubuntu.yml'
-  - local: '.ci/container/.gitlab-ci.yml'
+  - local: '.ci/.gitlab-ci.yml'
+  - local: '.ci/image-tags.yml'
 
 stages:
   - container
   - build
   - tidy
   - style
+  - android
 
-build:
+build_arm64:
   stage: build
   extends:
-    .use-ubuntu/x86_64_hwc
+    .use-ubuntu/x86_64_aospless
   script:
-    - ln -s "${CI_PROJECT_DIR}" "/aospless/src"
-    - make -C /aospless install
-    - mkdir -p "${CI_PROJECT_DIR}/install/arm64"
-    - cp -r /aospless/install/* "${CI_PROJECT_DIR}/install/arm64"
+    .ci/build-arm64.sh
   artifacts:
     paths:
       - "${CI_PROJECT_DIR}/install/arm64"
     expire_in: 1 week
 
+build_x86_64:
+  stage: build
+  extends:
+    .use-ubuntu/x86_64_aospless
+  script:
+    "${CI_PROJECT_DIR}/.ci/build-x86_64.sh"
+  artifacts:
+    paths:
+      - "${CI_PROJECT_DIR}/install/x86_64"
+    expire_in: 1 week
+
 tidy:
   stage: tidy
   extends:
-    .use-ubuntu/x86_64_hwc
+    .use-ubuntu/x86_64_aospless
   script:
-    - cp -r /aospless ../
+    - cp -r /aospless_arm64 ../aospless
     - make -j$(nproc) -k -f "${CI_PROJECT_DIR}/.ci/Makefile"
 
 checkstyle:
   stage: style
   extends:
-    .use-ubuntu/x86_64_hwc
+    .use-ubuntu/x86_64_aospless
   script: "./.ci/.gitlab-ci-checkcommit.sh"
   artifacts:
     when: on_failure
     untracked: true
   tags:
     - placeholder-job
+
+android-cts:
+  stage: android
+  extends:
+    .use-ubuntu/x86_64_android
+  variables:
+    RESULTS_DIR: "${CI_PROJECT_DIR}/results"
+  script:
+    - "${CI_PROJECT_DIR}/.ci/android/cts-runner.sh"
+  needs:
+    - job: build_x86_64
+      artifacts: true
+    - job: ubuntu/x86_64_android
+    - job: use-debian/x86_64_cuttlefish
+      artifacts: true
+  artifacts:
+    paths:
+      - "${RESULTS_DIR}"
+    when: always
+    expire_in: 1 week
+  tags:
+    - kvm
+
+android-vts:
+  stage: android
+  extends:
+    .use-ubuntu/x86_64_android
+  variables:
+    RESULTS_DIR: "${CI_PROJECT_DIR}/results"
+  script:
+    - "${CI_PROJECT_DIR}/.ci/android/vts-runner.sh"
+  needs:
+    - job: build_x86_64
+      artifacts: true
+    - job: ubuntu/x86_64_android
+    - job: use-debian/x86_64_cuttlefish
+      artifacts: true
+  artifacts:
+    paths:
+      - "${RESULTS_DIR}"
+    when: always
+    expire_in: 1 week
+  tags:
+    - kvm
diff --git a/Android.bp b/Android.bp
index 47b2cd8..1085495 100644
--- a/Android.bp
+++ b/Android.bp
@@ -42,6 +42,7 @@ cc_defaults {
     name: "hwcomposer.drm_defaults",
 
     shared_libs: [
+        "libbase",
         "libcutils",
         "libdrm",
         "libhardware",
@@ -68,8 +69,6 @@ cc_defaults {
 
     cppflags: [
         "-DHAS_LIBDISPLAY_INFO",
-        "-DHWC2_INCLUDE_STRINGIFICATION",
-        "-DHWC2_USE_CPP11",
     ],
 
     cpp_std: "gnu++17",
@@ -111,11 +110,11 @@ filegroup {
         "backend/BackendClient.cpp",
         "backend/BackendManager.cpp",
 
-        "hwc2_device/DrmHwcTwo.cpp",
-        "hwc2_device/HwcDisplay.cpp",
-        "hwc2_device/HwcDisplayConfigs.cpp",
-        "hwc2_device/HwcLayer.cpp",
-        "hwc2_device/hwc2_device.cpp",
+        "hwc/HwcDisplay.cpp",
+        "hwc/HwcDisplayConfigs.cpp",
+        "hwc/HwcLayer.cpp",
+
+        "stats/CompositionStats.cpp",
 
         "utils/LibdisplayEdidWrapper.cpp",
         "utils/fd.cpp",
@@ -123,13 +122,20 @@ filegroup {
     ],
 }
 
+filegroup {
+    name: "drm_hwcomposer_hwc2",
+    srcs: [
+        "hwc2_device/DrmHwcTwo.cpp",
+        "hwc2_device/hwc2_device.cpp",
+    ],
+}
+
 filegroup {
     name: "drm_hwcomposer_hwc3",
     srcs: [
         "hwc3/Composer.cpp",
         "hwc3/ComposerClient.cpp",
         "hwc3/DrmHwcThree.cpp",
-        "hwc3/Utils.cpp",
     ],
 }
 
@@ -164,11 +170,11 @@ cc_defaults {
     ],
 
     defaults: [
+        "android.hardware.graphics.composer3-ndk_shared",
         "hwcomposer.drm_defaults",
     ],
 
     shared_libs: [
-        "android.hardware.graphics.composer3-V4-ndk",
         "libbase",
         "libbinder_ndk",
         "liblog",
@@ -180,11 +186,6 @@ cc_defaults {
         "-Wall",
         "-Werror",
     ],
-
-    cppflags: [
-        "-DHWC2_INCLUDE_STRINGIFICATION",
-        "-DHWC2_USE_CPP11",
-    ],
 }
 
 cc_binary {
@@ -283,3 +284,15 @@ apex {
         "drm_hwcomposer_hwc3_apex_vintf",
     ],
 }
+
+cc_test_host {
+    name: "drm_hwcomposer_unittests",
+    srcs: [
+        "stats/CompositionStats.cpp",
+        "stats/CompositionStatsTest.cpp",
+    ],
+    static_libs: [
+        "libgmock",
+        "libgtest",
+    ],
+}
diff --git a/METADATA b/METADATA
index c577677..b8b79bf 100644
--- a/METADATA
+++ b/METADATA
@@ -8,12 +8,12 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2025
-    month: 3
-    day: 21
+    month: 5
+    day: 23
   }
   identifier {
     type: "Git"
     value: "https://gitlab.freedesktop.org/drm-hwcomposer/drm-hwcomposer"
-    version: "12d302c4abcef99ab28c94c3fef709754fac48e2"
+    version: "23e05e0b8571ab39783e4214c6981146b47acdb3"
   }
 }
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 305410c..1a02c08 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,12 +1,74 @@
 {
-  "presubmit": [
+  "desktop-presubmit": [
     {
       "name": "VtsHalGraphicsComposer3_TargetTest"
     }
   ],
-  "desktop-presubmit": [
+  "desktop-postsubmit": [
     {
-      "name": "VtsHalGraphicsComposer3_TargetTest"
+      "name": "CtsDisplayTestCases"
+    },
+    {
+      "name": "CtsGraphicsTestCases",
+      "options": [
+          {
+            "include-filter": "android.graphics.cts.ANativeWindowTest"
+          },
+          {
+            "include-filter": "android.graphics.cts.ASurfaceTextureTest"
+          },
+          {
+            "include-filter": "android.graphics.cts.BasicVulkanGpuTest0"
+          },
+          {
+            "include-filter": "android.graphics.cts.BitmapColorSpaceTest"
+          },
+          {
+            "include-filter": "android.graphics.cts.ColorSpaceTest"
+          },
+          {
+            "include-filter": "android.graphics.cts.EGL14Test"
+          },
+          {
+            "include-filter": "android.graphics.cts.EGL15Test"
+          },
+          {
+            "include-filter": "android.graphics.cts.FrameRateOverrideTest"
+          },
+          {
+            "include-filter": "android.graphics.cts.HardwareRendererTest"
+          },
+          {
+            "include-filter": "android.graphics.cts.MatchContentFrameRateTest"
+          },
+          {
+            "include-filter": "android.graphics.cts.PixelFormatTest"
+          },
+          {
+            "include-filter": "android.graphics.cts.SetFrameRateTest"
+          },
+          {
+            "include-filter": "android.graphics.cts.VulkanFeaturesTest0"
+          },
+          {
+            "include-filter": "android.graphics.cts.VulkanPreTransformTest"
+          }
+      ]
+    },
+    {
+      "name": "Vkms2VtsHalGraphicsComposer3"
+    },
+    {
+      "name": "Vkms5WithConfig_VtsHalGraphicsComposer3"
+    },
+    {
+      "name": "test_hotplugs"
+    },
+    {
+      "name": "CfVkmsConnectorsTest"
+    },
+    {
+      "name": "CfVkmsDisplaysTest"
     }
   ]
 }
diff --git a/backend/Backend.cpp b/backend/Backend.cpp
index 12a5fea..c5725df 100644
--- a/backend/Backend.cpp
+++ b/backend/Backend.cpp
@@ -13,6 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
+#define LOG_TAG "drmhwc"
 
 #include "Backend.h"
 
@@ -20,30 +21,29 @@
 
 #include "BackendManager.h"
 #include "bufferinfo/BufferInfoGetter.h"
-#include "hardware/hwcomposer2.h"
+#include "drm/DrmHwc.h"
 
 namespace android {
 
 namespace {
 
-bool HasCursorLayer(const std::vector<HwcLayer *> &layers) {
-  return std::find_if(layers.begin(), layers.end(), [&](auto *layer) -> bool {
-           return layer->GetSfType() == HWC2::Composition::Cursor;
-         }) != layers.end();
+HwcLayer *GetCursorLayer(const std::vector<HwcLayer *> &layers) {
+  auto it = std::find_if(layers.begin(), layers.end(),
+                         [&](auto *layer) -> bool {
+                           return layer->GetSfType() ==
+                                  HwcLayer::CompositionType::kCursor;
+                         });
+  if (it == layers.end()) {
+    return nullptr;
+  }
+  return *it;
 }
 
 }  // namespace
 
-HWC2::Error Backend::ValidateDisplay(HwcDisplay *display, uint32_t *num_types,
-                                     uint32_t *num_requests) {
-  *num_types = 0;
-  *num_requests = 0;
-
+void Backend::ValidateDisplay(HwcDisplay *display) {
   auto layers = display->GetOrderLayersByZPos();
 
-  int client_start = -1;
-  size_t client_size = 0;
-
   auto flatcon = display->GetFlatCon();
   if (flatcon) {
     bool should_flatten = false;
@@ -53,60 +53,67 @@ HWC2::Error Backend::ValidateDisplay(HwcDisplay *display, uint32_t *num_types,
       should_flatten = flatcon->NewFrame();
 
     if (should_flatten) {
-      display->total_stats().frames_flattened_++;
-      MarkValidated(layers, 0, layers.size());
-      *num_types = layers.size();
-      return HWC2::Error::HasChanges;
+      display->total_stats().frames_flattened++;
+      MarkValidated(layers, 0, layers.size(), /*use_cursor_plane=*/false);
+      return;
     }
   }
 
-  std::tie(client_start, client_size) = GetClientLayers(display, layers);
+  int client_start = -1;
+  size_t client_size = 0;
+  auto *cursor_layer = GetCursorLayer(layers);
+  auto cursor_plane = display->GetPipe().GetUsablePlanes().second;
+  bool use_cursor_plane = cursor_layer != nullptr && cursor_plane != nullptr &&
+                          !IsClientLayer(display, cursor_layer) &&
+                          cursor_plane->Get()->IsValidForLayer(
+                              &cursor_layer->GetLayerData());
+
+  // Validates layers and creates a test composition, returning whether it
+  // succeeded.
+  auto validate_and_test = [&]() -> bool {
+    std::tie(client_start, client_size) = GetClientLayers(display, layers,
+                                                          use_cursor_plane);
+    MarkValidated(layers, client_start, client_size, use_cursor_plane);
+
+    bool testing_needed = client_start != 0 || client_size != layers.size();
+    AtomicCommitArgs a_args = {.test_only = true};
+
+    if (testing_needed) {
+      return display->CreateComposition(a_args);
+    }
 
-  MarkValidated(layers, client_start, client_size);
+    return true;
+  };
 
-  auto testing_needed = client_start != 0 || client_size != layers.size();
+  // Initial composition attempt.
+  bool success = validate_and_test();
 
-  AtomicCommitArgs a_args = {.test_only = true};
+  // First fallback: convert cursor layer to device composition and reattempt.
+  if (!success && use_cursor_plane) {
+    ++display->total_stats().failed_kms_cursor_validate;
+    use_cursor_plane = false;
+    success = validate_and_test();
+  }
 
-  if (testing_needed &&
-      display->CreateComposition(a_args) != HWC2::Error::None) {
-    ++display->total_stats().failed_kms_validate_;
+  // Final fallback: convert all layers to client composition.
+  if (!success) {
+    ++display->total_stats().failed_kms_validate;
     client_start = 0;
     client_size = layers.size();
-
-    // Expand the client range to include all layers except the cursor layer (if
-    // there is one) and retry.
-    auto [_, cursor_plane] = display->GetPipe().GetUsablePlanes();
-    if (cursor_plane && HasCursorLayer(layers)) {
-      --client_size;
-      MarkValidated(layers, 0, client_size);
-
-      testing_needed = display->CreateComposition(a_args) != HWC2::Error::None;
-
-      // If testing is still needed, expand the client range to include the
-      // cursor layer for the next retry.
-      if (testing_needed) {
-        ++client_size;
-        ++display->total_stats().failed_kms_validate_;
-      }
-    }
-
-    if (testing_needed) {
-      MarkValidated(layers, 0, client_size);
-    }
+    MarkValidated(layers, client_start, client_size, use_cursor_plane);
   }
 
-  *num_types = client_size;
-
-  display->total_stats().gpu_pixops_ += CalcPixOps(layers, client_start,
-                                                   client_size);
-  display->total_stats().total_pixops_ += CalcPixOps(layers, 0, layers.size());
-
-  return *num_types != 0 ? HWC2::Error::HasChanges : HWC2::Error::None;
+  display->total_stats().gpu_pixops += CalcPixOps(layers, client_start,
+                                                  client_size);
+  display->total_stats().total_pixops += CalcPixOps(layers, 0, layers.size());
+  if (use_cursor_plane) {
+    ++display->total_stats().cursor_plane_frames;
+  }
 }
 
 std::tuple<int, size_t> Backend::GetClientLayers(
-    HwcDisplay *display, const std::vector<HwcLayer *> &layers) {
+    HwcDisplay *display, const std::vector<HwcLayer *> &layers,
+    bool use_cursor_plane) {
   int client_start = -1;
   size_t client_size = 0;
 
@@ -118,7 +125,8 @@ std::tuple<int, size_t> Backend::GetClientLayers(
     }
   }
 
-  return GetExtraClientRange(display, layers, client_start, client_size);
+  return GetExtraClientRange(display, layers, client_start, client_size,
+                             use_cursor_plane);
 }
 
 bool Backend::IsClientLayer(HwcDisplay *display, HwcLayer *layer) {
@@ -128,9 +136,9 @@ bool Backend::IsClientLayer(HwcDisplay *display, HwcLayer *layer) {
           display->GetHwc()->GetResMan().ForcedScalingWithGpu());
 }
 
-bool Backend::HardwareSupportsLayerType(HWC2::Composition comp_type) {
-  return comp_type == HWC2::Composition::Device ||
-         comp_type == HWC2::Composition::Cursor;
+bool Backend::HardwareSupportsLayerType(HwcLayer::CompositionType comp_type) {
+  return comp_type == HwcLayer::CompositionType::kDevice ||
+         comp_type == HwcLayer::CompositionType::kCursor;
 }
 
 uint32_t Backend::CalcPixOps(const std::vector<HwcLayer *> &layers,
@@ -149,28 +157,29 @@ uint32_t Backend::CalcPixOps(const std::vector<HwcLayer *> &layers,
 }
 
 void Backend::MarkValidated(std::vector<HwcLayer *> &layers,
-                            size_t client_first_z, size_t client_size) {
+                            size_t client_first_z, size_t client_size,
+                            bool use_cursor_plane) {
   for (size_t z_order = 0; z_order < layers.size(); ++z_order) {
     if (z_order >= client_first_z && z_order < client_first_z + client_size) {
-      layers[z_order]->SetValidatedType(HWC2::Composition::Client);
-    } else if (layers[z_order]->GetSfType() == HWC2::Composition::Cursor) {
-      layers[z_order]->SetValidatedType(HWC2::Composition::Cursor);
+      layers[z_order]->SetValidatedType(HwcLayer::CompositionType::kClient);
+    } else if (use_cursor_plane && layers[z_order]->GetSfType() ==
+                                       HwcLayer::CompositionType::kCursor) {
+      layers[z_order]->SetValidatedType(HwcLayer::CompositionType::kCursor);
     } else {
-      layers[z_order]->SetValidatedType(HWC2::Composition::Device);
+      layers[z_order]->SetValidatedType(HwcLayer::CompositionType::kDevice);
     }
   }
 }
 
 std::tuple<int, int> Backend::GetExtraClientRange(
     HwcDisplay *display, const std::vector<HwcLayer *> &layers,
-    int client_start, size_t client_size) {
-  auto [planes, cursor_plane] = display->GetPipe().GetUsablePlanes();
-  size_t avail_planes = planes.size();
+    int client_start, size_t client_size, bool use_cursor_plane) {
+  size_t avail_planes = display->GetPipe().GetUsablePlanes().first.size();
   size_t layers_size = layers.size();
 
-  // |cursor_plane| is not counted among |avail_planes|, so the cursor layer
+  // Cursor plane is not counted among |avail_planes|, so the cursor layer
   // shouldn't be counted in |layers_size|.
-  if (cursor_plane && HasCursorLayer(layers)) {
+  if (use_cursor_plane) {
     --layers_size;
   }
 
diff --git a/backend/Backend.h b/backend/Backend.h
index c24e818..716bef5 100644
--- a/backend/Backend.h
+++ b/backend/Backend.h
@@ -16,27 +16,30 @@
 
 #pragma once
 
-#include "hwc2_device/DrmHwcTwo.h"
+#include <vector>
+
+#include "hwc/HwcDisplay.h"
 
 namespace android {
 
 class Backend {
  public:
   virtual ~Backend() = default;
-  virtual HWC2::Error ValidateDisplay(HwcDisplay *display, uint32_t *num_types,
-                                      uint32_t *num_requests);
+  virtual void ValidateDisplay(HwcDisplay *display);
   virtual std::tuple<int, size_t> GetClientLayers(
-      HwcDisplay *display, const std::vector<HwcLayer *> &layers);
+      HwcDisplay *display, const std::vector<HwcLayer *> &layers,
+      bool use_cursor_plane);
   virtual bool IsClientLayer(HwcDisplay *display, HwcLayer *layer);
 
  protected:
-  static bool HardwareSupportsLayerType(HWC2::Composition comp_type);
+  static bool HardwareSupportsLayerType(HwcLayer::CompositionType comp_type);
   static uint32_t CalcPixOps(const std::vector<HwcLayer *> &layers,
                              size_t first_z, size_t size);
   static void MarkValidated(std::vector<HwcLayer *> &layers,
-                            size_t client_first_z, size_t client_size);
+                            size_t client_first_z, size_t client_size,
+                            bool use_cursor_plane);
   static std::tuple<int, int> GetExtraClientRange(
       HwcDisplay *display, const std::vector<HwcLayer *> &layers,
-      int client_start, size_t client_size);
+      int client_start, size_t client_size, bool use_cursor_plane);
 };
 }  // namespace android
diff --git a/backend/BackendClient.cpp b/backend/BackendClient.cpp
index 606dca2..d262ba3 100644
--- a/backend/BackendClient.cpp
+++ b/backend/BackendClient.cpp
@@ -20,14 +20,10 @@
 
 namespace android {
 
-HWC2::Error BackendClient::ValidateDisplay(HwcDisplay *display,
-                                           uint32_t *num_types,
-                                           uint32_t * /*num_requests*/) {
+void BackendClient::ValidateDisplay(HwcDisplay *display) {
   for (auto &[layer_handle, layer] : display->layers()) {
-    layer.SetValidatedType(HWC2::Composition::Client);
-    ++*num_types;
+    layer.SetValidatedType(HwcLayer::CompositionType::kClient);
   }
-  return HWC2::Error::HasChanges;
 }
 
 // clang-format off
diff --git a/backend/BackendClient.h b/backend/BackendClient.h
index 1333eca..6b6f4d5 100644
--- a/backend/BackendClient.h
+++ b/backend/BackendClient.h
@@ -22,7 +22,6 @@ namespace android {
 
 class BackendClient : public Backend {
  public:
-  HWC2::Error ValidateDisplay(HwcDisplay *display, uint32_t *num_types,
-                              uint32_t *num_requests) override;
+  void ValidateDisplay(HwcDisplay *display) override;
 };
 }  // namespace android
diff --git a/backend/BackendManager.h b/backend/BackendManager.h
index 4976744..125410e 100644
--- a/backend/BackendManager.h
+++ b/backend/BackendManager.h
@@ -42,8 +42,6 @@ class BackendManager {
                       BackendConstructorT backend_constructor);
   int SetBackendForDisplay(HwcDisplay *display);
   std::unique_ptr<Backend> GetBackendByName(std::string &name);
-  HWC2::Error ValidateDisplay(HwcDisplay *display, uint32_t *num_types,
-                              uint32_t *num_requests);
 
  private:
   BackendManager() = default;
diff --git a/compositor/DisplayInfo.h b/compositor/DisplayInfo.h
index f580d99..0913b99 100644
--- a/compositor/DisplayInfo.h
+++ b/compositor/DisplayInfo.h
@@ -16,13 +16,28 @@
 
 #pragma once
 
+#include <array>
 #include <cstdint>
 
+/*
+ * 4x4 Identity matrix used for color transformations.
+ */
+constexpr int kColorMatrixSize = 16;
+// clang-format off
+// NOLINTNEXTLINE(clang-diagnostic-unused-const-variable)
+constexpr std::array<float, kColorMatrixSize> kIdentityMatrix = {
+    1.0F, 0.0F, 0.0F, 0.0F,
+    0.0F, 1.0F, 0.0F, 0.0F,
+    0.0F, 0.0F, 1.0F, 0.0F,
+    0.0F, 0.0F, 0.0F, 1.0F,
+};
+// clang-format on
+
 /*
  * Display colorimetry enums.
  */
 // NOLINTBEGIN(readability-identifier-naming)
-enum class Colormode : int32_t {
+enum class ColorMode : int32_t {
   kNative,
   kBt601_625,
   kBt601_625Unadjusted,
@@ -72,6 +87,11 @@ enum PanelOrientation {
   kModePanelOrientationRightUp
 };
 
+/*
+ * Content type to be used for HDMI infoframes.
+ */
+enum class ContentType { kNoData, kGraphics, kPhoto, kCinema, kGame };
+
 struct QueuedConfigTiming {
   // In order for the new config to be applied, the client must send a new frame
   // at this time.
diff --git a/compositor/DrmKmsPlan.cpp b/compositor/DrmKmsPlan.cpp
index 1155697..106023c 100644
--- a/compositor/DrmKmsPlan.cpp
+++ b/compositor/DrmKmsPlan.cpp
@@ -39,9 +39,9 @@ auto DrmKmsPlan::CreateDrmKmsPlan(
                               .plane = cursor_plane,
                               .z_pos = z_pos++});
     } else {
-      // Cursor layer can't use cursor plane, so let it match normally with
-      // others.
-      composition.push_back(std::move(cursor_layer.value()));
+      // Cursor plane can't be used. The cursor layer may need to fallback to
+      // device or client composition.
+      return {};
     }
   }
 
diff --git a/compositor/LayerData.h b/compositor/LayerData.h
index 90ae7be..93793ff 100644
--- a/compositor/LayerData.h
+++ b/compositor/LayerData.h
@@ -51,17 +51,23 @@ struct SrcRectInfo {
   std::optional<FRect> f_rect;
 };
 
+struct IRect {
+  int32_t left;
+  int32_t top;
+  int32_t right;
+  int32_t bottom;
+};
+
 struct DstRectInfo {
-  struct IRect {
-    int32_t left;
-    int32_t top;
-    int32_t right;
-    int32_t bottom;
-  };
   /* nullopt means the whole display */
   std::optional<IRect> i_rect;
 };
 
+struct DamageInfo {
+  /* Empty vector means the whole source buffer may have been modified. */
+  std::vector<IRect> dmg_rects;
+};
+
 constexpr float kAlphaOpaque = 1.0F;
 
 struct PresentInfo {
@@ -69,6 +75,7 @@ struct PresentInfo {
   float alpha = kAlphaOpaque;
   SrcRectInfo source_crop{};
   DstRectInfo display_frame{};
+  DamageInfo damage{};
 
   bool RequireScalingOrPhasing() const {
     if (!source_crop.f_rect || !display_frame.i_rect) {
diff --git a/drm/DrmAtomicStateManager.cpp b/drm/DrmAtomicStateManager.cpp
index 4e4be80..5284799 100644
--- a/drm/DrmAtomicStateManager.cpp
+++ b/drm/DrmAtomicStateManager.cpp
@@ -68,8 +68,6 @@ auto DrmAtomicStateManager::CommitFrame(AtomicCommitArgs &args) -> int {
 
   auto new_frame_state = NewFrameState();
 
-  auto *drm = pipe_->device;
-  auto *connector = pipe_->connector->Get();
   auto *crtc = pipe_->crtc->Get();
 
   auto pset = MakeDrmModeAtomicReqUnique();
@@ -78,31 +76,46 @@ auto DrmAtomicStateManager::CommitFrame(AtomicCommitArgs &args) -> int {
     return -ENOMEM;
   }
 
-  int out_fence = -1;
-  if (!args.writeback_fb) {
-    if (!crtc->GetOutFencePtrProperty().  //
-         AtomicSet(*pset, uint64_t(&out_fence))) {
+  int wb_fence = -1;
+
+  if (pipe_->writeback_connector && args.writeback_fb) {
+    if (!pipe_->writeback_connector->Get()
+             ->GetCrtcIdProperty()
+             .AtomicSet(*pset, crtc->GetId())) {
+      ALOGE("DrmAtomicStateManager: Failed to set writeback CRTC_ID property");
       return -EINVAL;
     }
-  } else {
-    if (!connector->GetWritebackOutFenceProperty().  //
-         AtomicSet(*pset, uint64_t(&out_fence))) {
+
+    if (!pipe_->writeback_connector->Get()
+             ->GetWritebackFbIdProperty()
+             .AtomicSet(*pset, args.writeback_fb->GetFbId())) {
+      ALOGE("DrmAtomicStateManager: Failed to set writeback FB_ID property");
       return -EINVAL;
     }
 
-    if (!connector->GetWritebackFbIdProperty().  //
-         AtomicSet(*pset, args.writeback_fb->GetFbId())) {
+    if (!pipe_->writeback_connector->Get()
+             ->GetWritebackOutFenceProperty()
+             .AtomicSet(*pset, uint64_t(&wb_fence))) {
+      ALOGE(
+          "DrmAtomicStateManager: Failed to set writeback OUT_FENCE_PTR "
+          "property");
       return -EINVAL;
     }
 
+    // Wait on input fence if provided
     if (args.writeback_release_fence) {
       sync_wait(*args.writeback_release_fence, -1);
       args.writeback_release_fence.reset();
     }
   }
 
-  bool nonblock = !args.blocking;
+  int out_fence = -1;
+  if (!crtc->GetOutFencePtrProperty().AtomicSet(*pset, uint64_t(&out_fence))) {
+    return -EINVAL;
+  }
 
+  bool nonblock = !args.blocking;
+  auto *connector = pipe_->connector->Get();
   if (args.active) {
     nonblock = false;
     new_frame_state.crtc_active_state = *args.active;
@@ -110,8 +123,15 @@ auto DrmAtomicStateManager::CommitFrame(AtomicCommitArgs &args) -> int {
         !connector->GetCrtcIdProperty().AtomicSet(*pset, crtc->GetId())) {
       return -EINVAL;
     }
+    if (!*args.active && args.teardown) {
+      if (!connector->GetCrtcIdProperty().AtomicSet(*pset, 0) ||
+          !crtc->GetModeProperty().AtomicSet(*pset, 0)) {
+        return -EINVAL;
+      }
+    }
   }
 
+  auto *drm = pipe_->device;
   if (args.display_mode) {
     new_frame_state.mode_blob = args.display_mode.value().CreateModeBlob(*drm);
 
@@ -151,7 +171,8 @@ auto DrmAtomicStateManager::CommitFrame(AtomicCommitArgs &args) -> int {
 
   if (args.content_type && connector->GetContentTypeProperty()) {
     if (!connector->GetContentTypeProperty().AtomicSet(*pset,
-                                                       *args.content_type))
+                                                       static_cast<uint64_t>(
+                                                           *args.content_type)))
       return -EINVAL;
   }
 
@@ -171,17 +192,19 @@ auto DrmAtomicStateManager::CommitFrame(AtomicCommitArgs &args) -> int {
   }
 
   if (args.min_bpc && connector->GetMinBpcProperty()) {
-    int err;
-    uint64_t range_min, range_max = 0;
+    int err = 0;
+    uint64_t range_min = 0;
+    uint64_t range_max = 0;
     std::tie(err, range_min) = connector->GetMinBpcProperty().RangeMin();
-    if (err)
+    if (err != 0)
       return err;
     std::tie(err, range_max) = connector->GetMinBpcProperty().RangeMax();
-    if (err)
+    if (err != 0)
       return err;
 
     // Adjust requested min bpc to be within the property range
-    int32_t min_bpc_val = std::max(args.min_bpc.value(), static_cast<int32_t>(range_min));
+    int32_t min_bpc_val = std::max(args.min_bpc.value(),
+                                   static_cast<int32_t>(range_min));
     min_bpc_val = std::min(min_bpc_val, static_cast<int32_t>(range_max));
     if (!connector->GetMinBpcProperty().AtomicSet(*pset, min_bpc_val))
       return -EINVAL;
@@ -203,10 +226,12 @@ auto DrmAtomicStateManager::CommitFrame(AtomicCommitArgs &args) -> int {
       auto &v = unused_planes;
       v.erase(std::remove(v.begin(), v.end(), joining.plane), v.end());
 
+      DrmModeUserPropertyBlobUnique damage_blob;
       if (plane->AtomicSetState(*pset, layer, joining.z_pos, crtc->GetId(),
-                                whole_display_rect_) != 0) {
+                                whole_display_rect_, damage_blob) != 0) {
         return -EINVAL;
       }
+      new_frame_state.damage_blobs.push_back(std::move(damage_blob));
     }
   }
 
@@ -219,10 +244,16 @@ auto DrmAtomicStateManager::CommitFrame(AtomicCommitArgs &args) -> int {
   }
 
   uint32_t flags = DRM_MODE_ATOMIC_ALLOW_MODESET;
+  const int error_buf_max_size = 64;
+  char err_buf[error_buf_max_size];
 
   if (args.test_only) {
-    return drmModeAtomicCommit(*drm->GetFd(), pset.get(),
-                               flags | DRM_MODE_ATOMIC_TEST_ONLY, drm);
+    auto err = drmModeAtomicCommit(*drm->GetFd(), pset.get(),
+                                   flags | DRM_MODE_ATOMIC_TEST_ONLY, drm);
+
+    ALOGE_IF(err != 0, "Test-only ret=%d errno=%d strerror=%s\n", err, errno,
+             strerror_r(errno, err_buf, error_buf_max_size));
+    return err;
   }
 
   if (last_present_fence_) {
@@ -244,14 +275,19 @@ auto DrmAtomicStateManager::CommitFrame(AtomicCommitArgs &args) -> int {
   }
 
   auto err = drmModeAtomicCommit(*drm->GetFd(), pset.get(), flags, drm);
-
   if (err != 0) {
-    ALOGE("Failed to commit pset ret=%d\n", err);
+    ALOGE("Failed to commit pset ret=%d errno=%d strerror=%s\n", err, errno,
+          strerror_r(errno, err_buf, error_buf_max_size));
     return err;
   }
 
   args.out_fence = MakeSharedFd(out_fence);
 
+  // Store the writeback fence if this operation used a writeback connector
+  if (pipe_->writeback_connector && args.writeback_fb) {
+    args.out_writeback_complete_fence = MakeSharedFd(wb_fence);
+  }
+
   if (nonblock) {
     {
       const std::unique_lock lock(mutex_);
diff --git a/drm/DrmAtomicStateManager.h b/drm/DrmAtomicStateManager.h
index e4fff56..2422d06 100644
--- a/drm/DrmAtomicStateManager.h
+++ b/drm/DrmAtomicStateManager.h
@@ -34,12 +34,13 @@ struct AtomicCommitArgs {
   /* inputs. All fields are optional, but at least one has to be specified */
   bool test_only = false;
   bool blocking = false;
+  bool teardown = false;
   std::optional<DrmMode> display_mode;
   std::optional<bool> active;
   std::shared_ptr<DrmKmsPlan> composition;
   std::shared_ptr<drm_color_ctm> color_matrix;
   std::optional<Colorspace> colorspace;
-  std::optional<int32_t> content_type;
+  std::optional<ContentType> content_type;
   std::shared_ptr<hdr_output_metadata> hdr_metadata;
   std::optional<int32_t> min_bpc;
 
@@ -47,6 +48,7 @@ struct AtomicCommitArgs {
   SharedFd writeback_release_fence;
 
   /* out */
+  SharedFd out_writeback_complete_fence;
   SharedFd out_fence;
 
   /* helpers */
@@ -87,6 +89,7 @@ class DrmAtomicStateManager {
     DrmModeUserPropertyBlobUnique mode_blob;
     DrmModeUserPropertyBlobUnique ctm_blob;
     DrmModeUserPropertyBlobUnique hdr_metadata_blob;
+    std::vector<DrmModeUserPropertyBlobUnique> damage_blobs;
 
     int release_fence_pt_index{};
 
diff --git a/drm/DrmConnector.cpp b/drm/DrmConnector.cpp
index 82a109b..c5222ee 100644
--- a/drm/DrmConnector.cpp
+++ b/drm/DrmConnector.cpp
@@ -96,13 +96,23 @@ auto DrmConnector::Init()-> bool {
   edid_wrapper_ = std::make_unique<EdidWrapper>();
 #endif
 
-  if (IsWriteback() &&
-      (!GetConnectorProperty("WRITEBACK_PIXEL_FORMATS",
-                             &writeback_pixel_formats_) ||
-       !GetConnectorProperty("WRITEBACK_FB_ID", &writeback_fb_id_) ||
-       !GetConnectorProperty("WRITEBACK_OUT_FENCE_PTR",
-                             &writeback_out_fence_))) {
-    return false;
+  if (IsWriteback()) {
+    if (!GetConnectorProperty("WRITEBACK_PIXEL_FORMATS",
+                              &writeback_pixel_formats_property_)) {
+      ALOGE("Could not get WRITEBACK_PIXEL_FORMATS property");
+      return false;
+    }
+
+    if (!GetConnectorProperty("WRITEBACK_FB_ID", &writeback_fb_id_property_)) {
+      ALOGE("Could not get WRITEBACK_FB_ID property");
+      return false;
+    }
+
+    if (!GetConnectorProperty("WRITEBACK_OUT_FENCE_PTR",
+                              &writeback_out_fence_property_)) {
+      ALOGE("Could not get WRITEBACK_OUT_FENCE_PTR property");
+      return false;
+    }
   }
 
   if (GetOptionalConnectorProperty("Colorspace", &colorspace_property_)) {
diff --git a/drm/DrmConnector.h b/drm/DrmConnector.h
index 4d4f070..0b62424 100644
--- a/drm/DrmConnector.h
+++ b/drm/DrmConnector.h
@@ -124,11 +124,11 @@ class DrmConnector : public PipelineBindable<DrmConnector> {
   }
 
   auto &GetWritebackFbIdProperty() const {
-    return writeback_fb_id_;
+    return writeback_fb_id_property_;
   }
 
   auto &GetWritebackOutFenceProperty() const {
-    return writeback_out_fence_;
+    return writeback_out_fence_property_;
   }
 
   auto &GetPanelOrientationProperty() const {
@@ -181,11 +181,12 @@ class DrmConnector : public PipelineBindable<DrmConnector> {
   DrmProperty hdr_output_metadata_property_;
 
   DrmProperty link_status_property_;
-  DrmProperty writeback_pixel_formats_;
-  DrmProperty writeback_fb_id_;
-  DrmProperty writeback_out_fence_;
   DrmProperty panel_orientation_;
 
+  DrmProperty writeback_pixel_formats_property_;
+  DrmProperty writeback_fb_id_property_;
+  DrmProperty writeback_out_fence_property_;
+
   std::map<Colorspace, uint64_t> colorspace_enum_map_;
   std::map<uint64_t, PanelOrientation> panel_orientation_enum_map_;
 };
diff --git a/drm/DrmDevice.cpp b/drm/DrmDevice.cpp
index f6141d4..21926e8 100644
--- a/drm/DrmDevice.cpp
+++ b/drm/DrmDevice.cpp
@@ -27,6 +27,7 @@
 #include <string>
 
 #include "drm/DrmAtomicStateManager.h"
+#include "drm/DrmConnector.h"
 #include "drm/DrmPlane.h"
 #include "drm/ResourceManager.h"
 #include "utils/log.h"
@@ -252,9 +253,50 @@ auto DrmDevice::GetConnectors()
   return connectors_;
 }
 
-auto DrmDevice::GetWritebackConnectors()
-    -> const std::vector<std::unique_ptr<DrmConnector>> & {
-  return writeback_connectors_;
+auto DrmDevice::RefreshConnectors() -> void {
+  auto res = MakeDrmModeResUnique(*GetFd());
+  if (!res) {
+    ALOGE("Failed to get DrmDevice resources");
+    return;
+  }
+
+  // Remove the stale connectors present in connectors_ but not in DRM resources
+  std::set<uint32_t> conn_ids_present;
+  for (auto it = begin(connectors_); it != end(connectors_);) {
+    auto stale = true;
+    for (int i = 0; i < res->count_connectors; ++i) {
+      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
+      if (it->get()->GetId() == res->connectors[i]) {
+        stale = false;
+        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
+        conn_ids_present.insert(res->connectors[i]);
+        break;
+      }
+    }
+    if (stale && it->get()->GetPipeline() == nullptr) {
+      it = connectors_.erase(it);
+    } else {
+      ALOGE_IF(stale, "Stale connector %d %s has pipeline attached",
+               it->get()->GetId(), it->get()->GetName().c_str());
+      ++it;
+    }
+  }
+
+  // Add new connectors in DRM resources that are not present in connectors_
+  for (int i = 0; i < res->count_connectors; ++i) {
+    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
+    if (conn_ids_present.count(res->connectors[i]) != 0) {
+      continue;
+    }
+    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
+    auto conn = DrmConnector::CreateInstance(*this, res->connectors[i], i);
+    if (!conn) {
+      continue;
+    }
+    if (!conn->IsWriteback()) {
+      connectors_.emplace_back(std::move(conn));
+    }
+  }
 }
 
 auto DrmDevice::GetPlanes() -> const std::vector<std::unique_ptr<DrmPlane>> & {
diff --git a/drm/DrmDevice.h b/drm/DrmDevice.h
index ac20855..d432c0e 100644
--- a/drm/DrmDevice.h
+++ b/drm/DrmDevice.h
@@ -53,12 +53,15 @@ class DrmDevice {
   }
 
   auto GetConnectors() -> const std::vector<std::unique_ptr<DrmConnector>> &;
-  auto GetWritebackConnectors()
-      -> const std::vector<std::unique_ptr<DrmConnector>> &;
   auto GetPlanes() -> const std::vector<std::unique_ptr<DrmPlane>> &;
   auto GetCrtcs() -> const std::vector<std::unique_ptr<DrmCrtc>> &;
   auto GetEncoders() -> const std::vector<std::unique_ptr<DrmEncoder>> &;
 
+  auto GetWritebackConnectors()
+      -> const std::vector<std::unique_ptr<DrmConnector>> & {
+    return writeback_connectors_;
+  }
+
   auto GetMinResolution() const {
     return min_resolution_;
   }
@@ -110,6 +113,8 @@ class DrmDevice {
     return cap_cursor_size_;
   }
 
+  auto RefreshConnectors() -> void;
+
  private:
   explicit DrmDevice(ResourceManager *res_man, uint32_t index);
   auto Init(const char *path) -> int;
diff --git a/drm/DrmDisplayPipeline.cpp b/drm/DrmDisplayPipeline.cpp
index 8062b2c..f15f64f 100644
--- a/drm/DrmDisplayPipeline.cpp
+++ b/drm/DrmDisplayPipeline.cpp
@@ -191,6 +191,18 @@ auto DrmDisplayPipeline::GetUsablePlanes() -> UsablePlanes {
   return pair;
 }
 
+DrmConnector *DrmDisplayPipeline::FindWritebackConnectorForPipeline() const {
+  for (const auto &wb_connector : device->GetWritebackConnectors()) {
+    for (const auto &encoder : device->GetEncoders()) {
+      if (wb_connector->SupportsEncoder(*encoder) &&
+          encoder->SupportsCrtc(*(crtc->Get()))) {
+        return wb_connector.get();
+      }
+    }
+  }
+  return nullptr;
+}
+
 DrmDisplayPipeline::~DrmDisplayPipeline() {
   if (atomic_state_manager)
     atomic_state_manager->StopThread();
diff --git a/drm/DrmDisplayPipeline.h b/drm/DrmDisplayPipeline.h
index 0d05288..83df0f8 100644
--- a/drm/DrmDisplayPipeline.h
+++ b/drm/DrmDisplayPipeline.h
@@ -77,11 +77,14 @@ struct DrmDisplayPipeline {
 
   auto GetUsablePlanes() -> UsablePlanes;
 
+  DrmConnector *FindWritebackConnectorForPipeline() const;
+
   ~DrmDisplayPipeline();
 
   DrmDevice *device;
 
   std::shared_ptr<BindingOwner<DrmConnector>> connector;
+  std::shared_ptr<BindingOwner<DrmConnector>> writeback_connector; 
   std::shared_ptr<BindingOwner<DrmEncoder>> encoder;
   std::shared_ptr<BindingOwner<DrmCrtc>> crtc;
   std::shared_ptr<BindingOwner<DrmPlane>> primary_plane;
diff --git a/drm/DrmHwc.cpp b/drm/DrmHwc.cpp
index 3f30123..4020aba 100644
--- a/drm/DrmHwc.cpp
+++ b/drm/DrmHwc.cpp
@@ -25,8 +25,45 @@
 #include "utils/properties.h"
 
 namespace android {
+namespace {
+// Helper functions for implementing dumpsys support.
+std::string DumpStats(const CompositionStats &stats) {
+  if (stats.total_pixops == 0)
+    return "No stats yet";
+
+  // NOLINTNEXTLINE(readability-magic-numbers)
+  auto ratio = 1.0 - (double(stats.gpu_pixops) / double(stats.total_pixops));
+
+  std::stringstream ss;
+  ss << " Total frames count: " << stats.total_frames << "\n"
+     << " Failed cursor test commit frames: "
+     << stats.failed_kms_cursor_validate << "\n"
+     << " Failed to test commit frames: " << stats.failed_kms_validate << "\n"
+     << " Failed to commit frames: " << stats.failed_kms_present << "\n"
+     << ((stats.failed_kms_present > 0)
+             ? " !!! Internal failure, FIX it please\n"
+             : "")
+     << " Flattened frames: " << stats.frames_flattened << "\n"
+     << " Cursor plane frames: " << stats.cursor_plane_frames << "\n"
+     << " Pixel operations (free units) : [TOTAL: " << stats.total_pixops
+     << " / GPU: " << stats.gpu_pixops << "]\n"
+     << " Composition efficiency: " << ratio;
+  return ss.str();
+}
+
+std::string DumpDisplayStats(HwcDisplay *display, const CompositionStats &stats,
+                             const CompositionStats &delta) {
+  std::stringstream ss;
+  ss << "- Display on: " << display->GetDisplayName() << "\n"
+     << "Statistics since system boot:\n"
+     << DumpStats(stats) << "\n\n"
+     << "Statistics since last dumpsys request:\n"
+     << DumpStats(delta) << "\n\n";
+  return ss.str();
+}
+}  // namespace
 
-DrmHwc::DrmHwc() : resource_manager_(this) {};
+DrmHwc::DrmHwc() : resource_manager_(this), dump_stats_tracker_(this) {};
 
 /* Must be called after every display attach/detach cycle */
 void DrmHwc::FinalizeDisplayBinding() {
@@ -34,7 +71,7 @@ void DrmHwc::FinalizeDisplayBinding() {
     /* Primary display MUST always exist */
     ALOGI("No pipelines available. Creating null-display for headless mode");
     displays_[kPrimaryDisplay] = std::make_unique<
-        HwcDisplay>(kPrimaryDisplay, HWC2::DisplayType::Physical, this);
+        HwcDisplay>(kPrimaryDisplay, /* is_virtual */ false, this);
     /* Initializes null-display */
     displays_[kPrimaryDisplay]->SetPipeline({});
   }
@@ -83,7 +120,7 @@ bool DrmHwc::BindDisplay(std::shared_ptr<DrmDisplayPipeline> pipeline) {
 
   if (displays_.count(disp_handle) == 0) {
     auto disp = std::make_unique<HwcDisplay>(disp_handle,
-                                             HWC2::DisplayType::Physical, this);
+                                             /* is_virtual */ false, this);
     displays_[disp_handle] = std::move(disp);
   }
 
@@ -135,32 +172,36 @@ void DrmHwc::NotifyDisplayLinkStatus(
                        DisplayStatus::kLinkTrainingFailed);
 }
 
-HWC2::Error DrmHwc::CreateVirtualDisplay(
-    uint32_t width, uint32_t height,
-    int32_t *format,  // NOLINT(readability-non-const-parameter)
-    hwc2_display_t *display) {
-  ALOGI("Creating virtual display %dx%d format %d", width, height, *format);
+std::optional<DisplayHandle> DrmHwc::CreateVirtualDisplay(uint32_t width,
+                                                          uint32_t height) {
+  ALOGI("Creating virtual display %dx%d", width, height);
 
   auto virtual_pipeline = resource_manager_.GetVirtualDisplayPipeline();
   if (!virtual_pipeline)
-    return HWC2::Error::Unsupported;
+    return std::nullopt;
 
-  *display = ++last_display_handle_;
-  auto disp = std::make_unique<HwcDisplay>(*display, HWC2::DisplayType::Virtual,
-                                           this);
+  DisplayHandle new_display_handle = ++last_display_handle_;
+  auto disp = std::make_unique<HwcDisplay>(new_display_handle,
+                                           /* is_virtual */ true, this);
 
   disp->SetVirtualDisplayResolution(width, height);
   disp->SetPipeline(virtual_pipeline);
-  displays_[*display] = std::move(disp);
-  return HWC2::Error::None;
+  displays_[new_display_handle] = std::move(disp);
+  return new_display_handle;
 }
 
-HWC2::Error DrmHwc::DestroyVirtualDisplay(hwc2_display_t display) {
+bool DrmHwc::DestroyVirtualDisplay(DisplayHandle display) {
   ALOGI("Destroying virtual display %" PRIu64, display);
 
   if (displays_.count(display) == 0) {
     ALOGE("Trying to destroy non-existent display %" PRIu64, display);
-    return HWC2::Error::BadDisplay;
+    return false;
+  }
+
+  if (displays_[display]->GetDisplayType() !=
+      HwcDisplay::DisplayType::kVirtual) {
+    ALOGE("Trying to destroy non-virtual display %" PRIu64, display);
+    return false;
   }
 
   displays_[display]->SetPipeline({});
@@ -174,26 +215,35 @@ HWC2::Error DrmHwc::DestroyVirtualDisplay(hwc2_display_t display) {
   mutex.lock();
 
   displays_.erase(display);
-
-  return HWC2::Error::None;
+  return true;
 }
 
-void DrmHwc::Dump(uint32_t *out_size, char *out_buffer) {
-  if (out_buffer != nullptr) {
-    auto copied_bytes = dump_string_.copy(out_buffer, *out_size);
-    *out_size = static_cast<uint32_t>(copied_bytes);
-    return;
+auto DrmHwc::PullCompositionStats()
+    -> std::map<DisplayHandle, CompositionStats> {
+  std::map<int64_t, CompositionStats> stats;
+  for (auto &[display_handle, display] : displays_) {
+    stats[static_cast<int64_t>(display_handle)] = display->total_stats();
   }
+  return stats;
+}
 
+std::string DrmHwc::DumpState() {
   std::stringstream output;
 
   output << "-- drm_hwcomposer --\n\n";
 
-  for (auto &disp : displays_)
-    output << disp.second->Dump();
-
-  dump_string_ = output.str();
-  *out_size = static_cast<uint32_t>(dump_string_.size());
+  auto callback = [this, &output](int64_t display_handle,
+                                  const CompositionStats &stats,
+                                  const CompositionStats &delta) {
+    auto *display = GetDisplay(display_handle);
+    ALOGE_IF(display == nullptr, "Display %" PRIu64 " not found",
+             display_handle);
+    if (display) {
+      output << DumpDisplayStats(display, stats, delta);
+    }
+  };
+  dump_stats_tracker_.ReportStats(callback);
+  return output.str();
 }
 
 uint32_t DrmHwc::GetMaxVirtualDisplayCount() {
diff --git a/drm/DrmHwc.h b/drm/DrmHwc.h
index ac97717..096ed19 100644
--- a/drm/DrmHwc.h
+++ b/drm/DrmHwc.h
@@ -18,11 +18,13 @@
 
 #include "drm/DrmDisplayPipeline.h"
 #include "drm/ResourceManager.h"
-#include "hwc2_device/HwcDisplay.h"
+#include "hwc/HwcDisplay.h"
+#include "stats/CompositionStats.h"
 
 namespace android {
 
-class DrmHwc : public PipelineToFrontendBindingInterface {
+class DrmHwc : public PipelineToFrontendBindingInterface,
+               public CompositionStatsProvider {
  public:
   DrmHwc();
   ~DrmHwc() override = default;
@@ -35,23 +37,28 @@ class DrmHwc : public PipelineToFrontendBindingInterface {
   };
 
   // Client Callback functions.:
-  virtual void SendVsyncEventToClient(hwc2_display_t displayid,
+  virtual void SendVsyncEventToClient(DisplayHandle display_handle,
                                       int64_t timestamp,
                                       uint32_t vsync_period) const = 0;
   virtual void SendVsyncPeriodTimingChangedEventToClient(
-      hwc2_display_t displayid, int64_t timestamp) const = 0;
-  virtual void SendRefreshEventToClient(uint64_t displayid) = 0;
-  virtual void SendHotplugEventToClient(hwc2_display_t displayid,
+      DisplayHandle display_handle, int64_t timestamp) const = 0;
+  virtual void SendRefreshEventToClient(DisplayHandle display_handle) = 0;
+  virtual void SendHotplugEventToClient(DisplayHandle display_handle,
                                         enum DisplayStatus display_status) = 0;
 
-  // Device functions
-  HWC2::Error CreateVirtualDisplay(uint32_t width, uint32_t height,
-                                   int32_t *format, hwc2_display_t *display);
-  HWC2::Error DestroyVirtualDisplay(hwc2_display_t display);
-  void Dump(uint32_t *out_size, char *out_buffer);
+  // CompositionStatsProvider:
+  auto PullCompositionStats()
+      -> std::map<DisplayHandle, CompositionStats> override;
+
+  std::string DumpState();
+
+  // Virtual Display functions.
+  std::optional<DisplayHandle> CreateVirtualDisplay(uint32_t width,
+                                                    uint32_t height);
+  bool DestroyVirtualDisplay(DisplayHandle display_handle);
   uint32_t GetMaxVirtualDisplayCount();
 
-  auto GetDisplay(hwc2_display_t display_handle) {
+  auto GetDisplay(DisplayHandle display_handle) {
     return displays_.count(display_handle) != 0
                ? displays_[display_handle].get()
                : nullptr;
@@ -61,9 +68,9 @@ class DrmHwc : public PipelineToFrontendBindingInterface {
     return resource_manager_;
   }
 
-  void ScheduleHotplugEvent(hwc2_display_t displayid,
+  void ScheduleHotplugEvent(DisplayHandle display_handle,
                             enum DisplayStatus display_status) {
-    deferred_hotplug_events_[displayid] = display_status;
+    deferred_hotplug_events_[display_handle] = display_status;
   }
 
   void DeinitDisplays();
@@ -84,15 +91,13 @@ class DrmHwc : public PipelineToFrontendBindingInterface {
 
  private:
   ResourceManager resource_manager_;
-  std::map<hwc2_display_t, std::unique_ptr<HwcDisplay>> displays_;
-  std::map<std::shared_ptr<DrmDisplayPipeline>, hwc2_display_t>
-      display_handles_;
-
-  std::string dump_string_;
+  std::map<DisplayHandle, std::unique_ptr<HwcDisplay>> displays_;
+  std::map<std::shared_ptr<DrmDisplayPipeline>, DisplayHandle> display_handles_;
 
-  std::map<hwc2_display_t, enum DisplayStatus> deferred_hotplug_events_;
-  std::vector<hwc2_display_t> displays_for_removal_list_;
+  std::map<DisplayHandle, enum DisplayStatus> deferred_hotplug_events_;
+  std::vector<DisplayHandle> displays_for_removal_list_;
 
-  uint32_t last_display_handle_ = kPrimaryDisplay;
+  DisplayHandle last_display_handle_ = kPrimaryDisplay;
+  CompositionStatsTracker dump_stats_tracker_;
 };
-}  // namespace android
\ No newline at end of file
+}  // namespace android
diff --git a/drm/DrmPlane.cpp b/drm/DrmPlane.cpp
index 2251a78..a2276d3 100644
--- a/drm/DrmPlane.cpp
+++ b/drm/DrmPlane.cpp
@@ -30,6 +30,16 @@
 
 namespace android {
 
+namespace {
+// Ensure that |src| does not exceed the bounds of the buffer.
+void ClipSourceCrop(SrcRectInfo::FRect &src, const BufferInfo &buffer_info) {
+  src.left = std::max(src.left, 0.F);
+  src.top = std::max(src.top, 0.F);
+  src.right = std::min(src.right, static_cast<float>(buffer_info.width));
+  src.bottom = std::min(src.bottom, static_cast<float>(buffer_info.height));
+}
+}  // namespace
+
 auto DrmPlane::CreateInstance(DrmDevice &dev, uint32_t plane_id)
     -> std::unique_ptr<DrmPlane> {
   auto p = MakeDrmModePlaneUnique(*dev.GetFd(), plane_id);
@@ -138,6 +148,9 @@ int DrmPlane::Init() {
     size_hints_property_.GetBlobData(size_hints_);
   }
 
+  GetPlaneProperty("FB_DAMAGE_CLIPS", fb_damage_clips_property_,
+                   Presence::kOptional);
+
   return 0;
 }
 
@@ -242,9 +255,12 @@ static int To1616FixPt(float in) {
   return int(in * (1 << kBitShift));
 }
 
+// NOLINTNEXTLINE (readability-function-cognitive-complexity)
 auto DrmPlane::AtomicSetState(drmModeAtomicReq &pset, LayerData &layer,
                               uint32_t zpos, uint32_t crtc_id,
-                              DstRectInfo &whole_display_rect) -> int {
+                              DstRectInfo &whole_display_rect,
+                              DrmModeUserPropertyBlobUnique &damage_out) const
+    -> int {
   if (!layer.fb || !layer.bi) {
     ALOGE("%s: Invalid arguments", __func__);
     return -EINVAL;
@@ -291,6 +307,10 @@ auto DrmPlane::AtomicSetState(drmModeAtomicReq &pset, LayerData &layer,
            static_cast<float>(layer.bi->height)};
   }
 
+  // Clip the source crop rect to ensure it does not exceed the bounds of the
+  // framebuffer.
+  ClipSourceCrop(src, *layer.bi);
+
   if (!crtc_property_.AtomicSet(pset, crtc_id) ||
       !fb_property_.AtomicSet(pset, layer.fb->GetFbId()) ||
       !crtc_x_property_.AtomicSet(pset, disp.left) ||
@@ -317,22 +337,50 @@ auto DrmPlane::AtomicSetState(drmModeAtomicReq &pset, LayerData &layer,
 
   if (blending_enum_map_.count(layer.bi->blend_mode) != 0 &&
       !blend_property_.AtomicSet(pset,
-                                 blending_enum_map_[layer.bi->blend_mode])) {
+                                 blending_enum_map_.at(layer.bi->blend_mode))) {
     return -EINVAL;
   }
 
   if (color_encoding_enum_map_.count(layer.bi->color_space) != 0 &&
-      !color_encoding_property_
-           .AtomicSet(pset, color_encoding_enum_map_[layer.bi->color_space])) {
+      !color_encoding_property_.AtomicSet(pset, color_encoding_enum_map_.at(
+                                                    layer.bi->color_space))) {
     return -EINVAL;
   }
 
   if (color_range_enum_map_.count(layer.bi->sample_range) != 0 &&
-      !color_range_property_
-           .AtomicSet(pset, color_range_enum_map_[layer.bi->sample_range])) {
+      !color_range_property_.AtomicSet(pset, color_range_enum_map_.at(
+                                                 layer.bi->sample_range))) {
     return -EINVAL;
   }
 
+  if (fb_damage_clips_property_) {
+    std::vector<drm_mode_rect> plane_damage;
+    for (const auto &rect : layer.pi.damage.dmg_rects) {
+      if (rect.left == rect.right || rect.top == rect.bottom) {
+        // SurfaceFlinger uses empty rects to signal no damage, but kernel
+        // doesn't support this.
+        continue;
+      }
+      plane_damage.emplace_back(drm_mode_rect{.x1 = rect.left,
+                                              .y1 = rect.top,
+                                              .x2 = rect.right,
+                                              .y2 = rect.bottom});
+    }
+
+    if (!plane_damage.empty()) {
+      size_t damage_size = sizeof(drm_mode_rect) * plane_damage.size();
+      damage_out = drm_->RegisterUserPropertyBlob(plane_damage.data(),
+                                                  damage_size);
+      if (!damage_out ||
+          !fb_damage_clips_property_.AtomicSet(pset, *damage_out)) {
+        ALOGE("%s: Failed to set %s property", __func__,
+              fb_damage_clips_property_.GetName().c_str());
+        // Continue without returning error code. FB_DAMAGE_CLIPS is an optional
+        // property. Default behavior is to assume full plane damage.
+      }
+    }
+  }
+
   return 0;
 }
 
diff --git a/drm/DrmPlane.h b/drm/DrmPlane.h
index 2fa6388..5bbf303 100644
--- a/drm/DrmPlane.h
+++ b/drm/DrmPlane.h
@@ -55,7 +55,8 @@ class DrmPlane : public PipelineBindable<DrmPlane> {
   bool HasNonRgbFormat() const;
 
   auto AtomicSetState(drmModeAtomicReq &pset, LayerData &layer, uint32_t zpos,
-                      uint32_t crtc_id, DstRectInfo &whole_display_rect) -> int;
+                      uint32_t crtc_id, DstRectInfo &whole_display_rect,
+                      DrmModeUserPropertyBlobUnique &damage_out) const -> int;
   auto AtomicDisablePlane(drmModeAtomicReq &pset) -> int;
   auto &GetZPosProperty() const {
     return zpos_property_;
@@ -102,6 +103,7 @@ class DrmPlane : public PipelineBindable<DrmPlane> {
   DrmProperty color_encoding_property_;
   DrmProperty color_range_property_;
   DrmProperty size_hints_property_;
+  DrmProperty fb_damage_clips_property_;
 
   std::map<BufferBlendMode, uint64_t> blending_enum_map_;
   std::map<BufferColorSpace, uint64_t> color_encoding_enum_map_;
diff --git a/drm/ResourceManager.cpp b/drm/ResourceManager.cpp
index fee251e..f877a46 100644
--- a/drm/ResourceManager.cpp
+++ b/drm/ResourceManager.cpp
@@ -18,6 +18,7 @@
 
 #include "ResourceManager.h"
 
+#include <android-base/strings.h>
 #include <sys/stat.h>
 
 #include <ctime>
@@ -76,6 +77,10 @@ void ResourceManager::Init() {
     }
   }
 
+  auto display_str = Properties::InternalDisplayNames();
+  auto display_names = base::Tokenize(display_str, ",");
+  displays_.insert(display_names.begin(), display_names.end());
+
   scale_with_gpu_ = Properties::ScaleWithGpu();
 
   char proptext[PROPERTY_VALUE_MAX];
@@ -98,6 +103,9 @@ void ResourceManager::Init() {
 
   uevent_listener_->RegisterHotplugHandler([this] {
     const std::unique_lock lock(GetMainLock());
+    for (auto &drm : drms_) {
+      drm->RefreshConnectors();
+    }
     UpdateFrontendDisplays();
   });
 
@@ -120,6 +128,10 @@ void ResourceManager::DeInit() {
   initialized_ = false;
 }
 
+const std::set<std::string>& ResourceManager::GetInternalDisplayNames() {
+  return displays_;
+}
+
 auto ResourceManager::GetTimeMonotonicNs() -> int64_t {
   struct timespec ts {};
   clock_gettime(CLOCK_MONOTONIC, &ts);
diff --git a/drm/ResourceManager.h b/drm/ResourceManager.h
index 3c4d7ae..301a570 100644
--- a/drm/ResourceManager.h
+++ b/drm/ResourceManager.h
@@ -18,6 +18,7 @@
 
 #include <cstring>
 #include <mutex>
+#include <set>
 
 #include "DrmDevice.h"
 #include "DrmDisplayPipeline.h"
@@ -70,6 +71,7 @@ class ResourceManager {
 
   auto GetVirtualDisplayPipeline() -> std::shared_ptr<DrmDisplayPipeline>;
   auto GetWritebackConnectorsCount() -> uint32_t;
+  auto GetInternalDisplayNames() -> const std::set<std::string>&;
 
   static auto GetTimeMonotonicNs() -> int64_t;
 
@@ -79,6 +81,7 @@ class ResourceManager {
   void DetachAllFrontendDisplays();
 
   std::vector<std::unique_ptr<DrmDevice>> drms_;
+  std::set<std::string> displays_;
 
   // Android properties:
   bool scale_with_gpu_{};
diff --git a/hwc2_device/HwcDisplay.cpp b/hwc/HwcDisplay.cpp
similarity index 56%
rename from hwc2_device/HwcDisplay.cpp
rename to hwc/HwcDisplay.cpp
index 2a47a2a..4761651 100644
--- a/hwc2_device/HwcDisplay.cpp
+++ b/hwc/HwcDisplay.cpp
@@ -43,11 +43,6 @@ namespace {
 constexpr int kCtmRows = 3;
 constexpr int kCtmCols = 3;
 
-constexpr std::array<float, 16> kIdentityMatrix = {
-    1.0F, 0.0F, 0.0F, 0.0F, 0.0F, 1.0F, 0.0F, 0.0F,
-    0.0F, 0.0F, 1.0F, 0.0F, 0.0F, 0.0F, 0.0F, 1.0F,
-};
-
 bool float_equals(float a, float b) {
   const float epsilon = 0.001F;
   return std::abs(a - b) < epsilon;
@@ -106,82 +101,58 @@ auto ToColorTransform(const std::array<float, 16> &color_transform_matrix) {
 
 }  // namespace
 
-std::string HwcDisplay::DumpDelta(HwcDisplay::Stats delta) {
-  if (delta.total_pixops_ == 0)
-    return "No stats yet";
-  auto ratio = 1.0 - (double(delta.gpu_pixops_) / double(delta.total_pixops_));
-
-  std::stringstream ss;
-  ss << " Total frames count: " << delta.total_frames_ << "\n"
-     << " Failed to test commit frames: " << delta.failed_kms_validate_ << "\n"
-     << " Failed to commit frames: " << delta.failed_kms_present_ << "\n"
-     << ((delta.failed_kms_present_ > 0)
-             ? " !!! Internal failure, FIX it please\n"
-             : "")
-     << " Flattened frames: " << delta.frames_flattened_ << "\n"
-     << " Pixel operations (free units)"
-     << " : [TOTAL: " << delta.total_pixops_ << " / GPU: " << delta.gpu_pixops_
-     << "]\n"
-     << " Composition efficiency: " << ratio;
-
-  return ss.str();
+auto HwcDisplay::GetDisplayName() -> std::string {
+  std::ostringstream stream;
+  if (IsInHeadlessMode()) {
+    stream << "null-display";
+  } else {
+    stream << "display-" << GetPipe().connector->Get()->GetId();
+  }
+  return stream.str();
 }
 
-std::string HwcDisplay::Dump() {
-  auto connector_name = IsInHeadlessMode()
-                            ? std::string("NULL-DISPLAY")
-                            : GetPipe().connector->Get()->GetName();
-
-  std::stringstream ss;
-  ss << "- Display on: " << connector_name << "\n"
-     << "Statistics since system boot:\n"
-     << DumpDelta(total_stats_) << "\n\n"
-     << "Statistics since last dumpsys request:\n"
-     << DumpDelta(total_stats_.minus(prev_stats_)) << "\n\n";
-
-  memcpy(&prev_stats_, &total_stats_, sizeof(Stats));
-  return ss.str();
-}
-
-HwcDisplay::HwcDisplay(hwc2_display_t handle, HWC2::DisplayType type,
-                       DrmHwc *hwc)
-    : hwc_(hwc), handle_(handle), type_(type), client_layer_(this) {
-  if (type_ == HWC2::DisplayType::Virtual) {
-    writeback_layer_ = std::make_unique<HwcLayer>(this);
-  }
+HwcDisplay::HwcDisplay(DisplayHandle handle, bool is_virtual, DrmHwc *hwc)
+    : hwc_(hwc), handle_(handle), is_virtual_(is_virtual), client_layer_(this) {
+  // Create writeback layer for both virtual displays and potential readback
+  // operations
+  writeback_layer_ = std::make_unique<HwcLayer>(this);
 
   identity_color_matrix_ = ToColorTransform(kIdentityMatrix);
 }
 
 void HwcDisplay::SetColorTransformMatrix(
     const std::array<float, 16> &color_transform_matrix) {
-  const bool is_identity = std::equal(color_transform_matrix.begin(),
-                                      color_transform_matrix.end(),
-                                      kIdentityMatrix.begin(), float_equals);
-  color_transform_hint_ = is_identity ? HAL_COLOR_TRANSFORM_IDENTITY
-                                      : HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX;
+  color_transform_is_identity_ = std::equal(color_transform_matrix.begin(),
+                                            color_transform_matrix.end(),
+                                            kIdentityMatrix.begin(),
+                                            float_equals);
   ctm_has_offset_ = false;
 
-  if (color_transform_hint_ == is_identity) {
-    SetColorMatrixToIdentity();
-  } else {
-    if (TransformHasOffsetValue(color_transform_matrix.data()))
-      ctm_has_offset_ = true;
+  if (IsInHeadlessMode())
+    return;
 
-    color_matrix_ = ToColorTransform(color_transform_matrix);
+  if (color_transform_is_identity_) {
+    SetColorMatrixToIdentity();
+    return;
   }
+
+  if (TransformHasOffsetValue(color_transform_matrix.data()))
+    ctm_has_offset_ = true;
+
+  color_matrix_ = ToColorTransform(color_transform_matrix);
 }
 
 void HwcDisplay::SetColorMatrixToIdentity() {
+  ctm_has_offset_ = false;
   color_matrix_ = identity_color_matrix_;
-  color_transform_hint_ = HAL_COLOR_TRANSFORM_IDENTITY;
+  color_transform_is_identity_ = true;
 }
 
 HwcDisplay::~HwcDisplay() {
   Deinit();
 };
 
-auto HwcDisplay::GetConfig(hwc2_config_t config_id) const
+auto HwcDisplay::GetConfig(ConfigId config_id) const
     -> const HwcDisplayConfig * {
   auto config_iter = configs_.hwc_configs.find(config_id);
   if (config_iter == configs_.hwc_configs.end()) {
@@ -198,49 +169,46 @@ auto HwcDisplay::GetLastRequestedConfig() const -> const HwcDisplayConfig * {
   return GetConfig(staged_mode_config_id_.value_or(configs_.active_config_id));
 }
 
-HWC2::Error HwcDisplay::SetOutputType(uint32_t hdr_output_type) {
+void HwcDisplay::SetOutputType(uint32_t hdr_output_type) {
   switch (hdr_output_type) {
-    case 3: { // HDR10
-      auto ret = SetHdrOutputMetadata(ui::Hdr::HDR10);
-      if (ret != HWC2::Error::None)
-        return ret;
+    case 3: {  // HDR10
+      SetHdrOutputMetadata(ui::Hdr::HDR10);
       min_bpc_ = 8;
       colorspace_ = Colorspace::kBt2020Rgb;
       break;
     }
-    case 1: { // SYSTEM
+    case 1: {  // SYSTEM
       std::vector<ui::Hdr> hdr_types;
       GetEdid()->GetSupportedHdrTypes(hdr_types);
       if (!hdr_types.empty()) {
-        auto ret = SetHdrOutputMetadata(hdr_types.front());
-        if (ret != HWC2::Error::None)
-          return ret;
+        SetHdrOutputMetadata(hdr_types.front());
         min_bpc_ = 8;
         colorspace_ = Colorspace::kBt2020Rgb;
         break;
-      } else {
-        [[fallthrough]];
       }
+      [[fallthrough]];
     }
     case 0:  // INVALID
       [[fallthrough]];
     case 2:  // SDR
       [[fallthrough]];
     default:
-      hdr_metadata_ = std::make_shared<hdr_output_metadata>();
+      hdr_metadata_.reset();
       min_bpc_ = 6;
       colorspace_ = Colorspace::kDefault;
   }
-
-  return HWC2::Error::None;
 }
 
-HwcDisplay::ConfigError HwcDisplay::SetConfig(hwc2_config_t config) {
+HwcDisplay::ConfigError HwcDisplay::SetConfig(ConfigId config) {
   const HwcDisplayConfig *new_config = GetConfig(config);
   if (new_config == nullptr) {
     ALOGE("Could not find active mode for %u", config);
     return ConfigError::kBadConfig;
   }
+  if (IsInHeadlessMode()) {
+    configs_.active_config_id = config;
+    return ConfigError::kNone;
+  }
 
   const HwcDisplayConfig *current_config = GetCurrentConfig();
 
@@ -278,7 +246,9 @@ HwcDisplay::ConfigError HwcDisplay::SetConfig(hwc2_config_t config) {
   }
 
   ALOGV("Create modeset commit.");
-  SetOutputType(new_config->output_type);
+  // Disable HDR for internal panels due to b/404620167
+  if (GetPipe().connector->Get()->IsExternal())
+    SetOutputType(new_config->output_type);
 
   // Create atomic commit args for a blocking modeset. There's no need to do a
   // separate test commit, since the commit does a test anyways.
@@ -300,7 +270,7 @@ HwcDisplay::ConfigError HwcDisplay::SetConfig(hwc2_config_t config) {
   return ConfigError::kNone;
 }
 
-auto HwcDisplay::QueueConfig(hwc2_config_t config, int64_t desired_time,
+auto HwcDisplay::QueueConfig(ConfigId config, int64_t desired_time,
                              bool seamless, QueuedConfigTiming *out_timing)
     -> ConfigError {
   if (configs_.hwc_configs.count(config) == 0) {
@@ -327,6 +297,12 @@ auto HwcDisplay::QueueConfig(hwc2_config_t config, int64_t desired_time,
   staged_mode_change_time_ = out_timing->refresh_time_ns;
   staged_mode_config_id_ = config;
 
+  // Allow HDR only on external displays
+  if (current_config && !IsInHeadlessMode() &&
+      GetPipe().connector->Get()->IsExternal()) {
+    SetOutputType(current_config->output_type);
+  }
+
   // Enable vsync events until the mode has been applied.
   vsync_worker_->SetVsyncTimestampTracking(true);
 
@@ -338,24 +314,30 @@ auto HwcDisplay::ValidateStagedComposition() -> std::vector<ChangedLayer> {
     return {};
   }
 
+  if (layers_.empty()) {
+    ALOGI("No layers to validate.");
+    return {};
+  }
+
   /* In current drm_hwc design in case previous frame layer was not validated as
    * a CLIENT, it is used by display controller (Front buffer). We have to store
    * this state to provide the CLIENT with the release fences for such buffers.
    */
   for (auto &l : layers_) {
     l.second.SetPriorBufferScanOutFlag(l.second.GetValidatedType() !=
-                                       HWC2::Composition::Client);
-  }
-
-  // ValidateDisplay returns the number of layers that may be changed.
-  uint32_t num_types = 0;
-  uint32_t num_requests = 0;
-  backend_->ValidateDisplay(this, &num_types, &num_requests);
+                                       HwcLayer::CompositionType::kClient);
 
-  if (num_types == 0) {
-    return {};
+    /* Populate layer data for layers that might be mapped to a drm plane. */
+    if (l.second.GetSfType() == HwcLayer::CompositionType::kDevice ||
+        l.second.GetSfType() == HwcLayer::CompositionType::kCursor) {
+      l.second.PopulateLayerData();
+    }
   }
 
+  // ValidateDisplay modifies the composition type in layers_ which can be
+  // checked to see which layers' composition strategies have changed.
+  backend_->ValidateDisplay(this);
+
   // Iterate through the layers to find which layers actually changed.
   std::vector<ChangedLayer> changed_layers;
   for (auto &l : layers_) {
@@ -367,6 +349,9 @@ auto HwcDisplay::ValidateStagedComposition() -> std::vector<ChangedLayer> {
 }
 
 auto HwcDisplay::GetDisplayBoundsMm() -> std::pair<int32_t, int32_t> {
+  if (IsInHeadlessMode()) {
+    return {configs_.mm_width, -1};
+  }
 
   const auto bounds = GetEdid()->GetBoundsMm();
   if (bounds.first > 0 || bounds.second > 0) {
@@ -391,13 +376,15 @@ auto HwcDisplay::PresentStagedComposition(
   if (IsInHeadlessMode()) {
     return true;
   }
-  HWC2::Error ret{};
 
-  ++total_stats_.total_frames_;
+  if (layers_.empty()) {
+    ALOGI("No layers to present.");
+    return true;
+  }
 
-  uint32_t vperiod_ns = 0;
-  GetDisplayVsyncPeriod(&vperiod_ns);
+  ++total_stats_.total_frames;
 
+  uint32_t vperiod_ns = GetCurrentVsyncPeriodNs();
   if (desired_present_time && vperiod_ns != 0) {
     // DRM atomic uAPI does not support specifying that a commit should be
     // applied to some future vsync. Until such uAPI is available, sleep in
@@ -407,17 +394,10 @@ auto HwcDisplay::PresentStagedComposition(
   }
 
   AtomicCommitArgs a_args{};
-  ret = CreateComposition(a_args);
-
-  if (ret != HWC2::Error::None)
-    ++total_stats_.failed_kms_present_;
-
-  if (ret == HWC2::Error::BadLayer) {
-    // Can we really have no client or device layers?
-    return true;
-  }
-  if (ret != HWC2::Error::None)
+  if (!CreateComposition(a_args)) {
+    ++total_stats_.failed_kms_present;
     return false;
+  }
 
   out_present_fence = a_args.out_fence;
 
@@ -439,13 +419,120 @@ auto HwcDisplay::PresentStagedComposition(
   return true;
 }
 
+auto HwcDisplay::GetRawEdid() -> std::vector<uint8_t> {
+  if (IsInHeadlessMode()) {
+    return {};
+  }
+
+  auto *connector = GetPipe().connector->Get();
+  auto blob = connector->GetEdidBlob();
+  if (!blob || blob->length == 0) {
+    return {};
+  }
+  const uint8_t *edid_data = static_cast<uint8_t *>(blob->data);
+  return {edid_data, edid_data + blob->length};
+}
+
+auto HwcDisplay::GetPort() -> uint8_t {
+  if (IsInHeadlessMode()) {
+    return 0;
+  }
+
+  auto *connector = GetPipe().connector->Get();
+
+  constexpr uint8_t kDrmDeviceBitShift = 5U;
+  constexpr uint8_t kDrmDeviceBitMask = 0xE0;
+  constexpr uint8_t kConnectorBitMask = 0x1F;
+  const auto kDrmIdx = static_cast<uint8_t>(
+      connector->GetDev().GetIndexInDevArray());
+  const auto kConnectorIdx = static_cast<uint8_t>(
+      connector->GetIndexInResArray());
+  return (((kDrmIdx << kDrmDeviceBitShift) & kDrmDeviceBitMask) |
+          (kConnectorIdx & kConnectorBitMask));
+}
+
+auto HwcDisplay::GetDisplayType() -> DisplayType {
+  if (is_virtual_) {
+    return kVirtual;
+  }
+
+  if (IsInHeadlessMode()) {
+    return kInternal;
+  }
+
+  /* Primary display should be always internal,
+   * otherwise SF will be unhappy and will crash
+   */
+  if (handle_ == kPrimaryDisplay) {
+    return kInternal;
+  }
+
+  auto displays = GetHwc()->GetResMan().GetInternalDisplayNames();
+  if (!displays.empty()) {
+    std::string name = GetPipe().connector->Get()->GetName();
+    const bool is_internal = (displays.find(name) != displays.end());
+    return is_internal ? kInternal : kExternal;
+  }
+
+  if (GetPipe().connector->Get()->IsInternal())
+    return kInternal;
+
+  ALOGW_IF(!GetPipe().connector->Get()->IsExternal(),
+           "Connector type is neither internal nor external.");
+  return kExternal;
+}
+
+void HwcDisplay::SetVsyncCallbacksEnabled(bool enabled) {
+  // Enabling vsync callbacks for a virtual display succeeds with no effect.
+  if (!vsync_worker_) {
+    ALOGE_IF(!is_virtual_, "Invalid VSyncWorker. Did HwcDisplay::Init fail?");
+    return;
+  }
+
+  vsync_event_en_ = enabled;
+  std::optional<VSyncWorker::VsyncTimestampCallback> callback = std::nullopt;
+  if (vsync_event_en_) {
+    DrmHwc *hwc = hwc_;
+    DisplayHandle id = handle_;
+    // Callback will be called from the vsync thread.
+    callback = [hwc, id](int64_t timestamp, uint32_t period_ns) {
+      hwc->SendVsyncEventToClient(id, timestamp, period_ns);
+    };
+  }
+  vsync_worker_->SetTimestampCallback(std::move(callback));
+}
+
+bool HwcDisplay::SetDisplayEnabled(bool enabled) {
+  if (IsInHeadlessMode()) {
+    return true;
+  }
+  if (enabled) {
+    /*
+     * Setting the display to active before we have a composition
+     * can break some drivers, so skip setting a_args.active to
+     * true, as the next composition frame will implicitly activate
+     * the display
+     */
+    return GetPipe().atomic_state_manager->ActivateDisplayUsingDPMS() == 0;
+  };
+
+  // Disable the display.
+  AtomicCommitArgs a_args{};
+  a_args.active = false;
+
+  auto err = GetPipe().atomic_state_manager->ExecuteAtomicCommit(a_args);
+  ALOGE_IF(err != 0, "Failed to apply the dpms composition err=%d", err);
+  return err == 0;
+}
+
 void HwcDisplay::SetPipeline(std::shared_ptr<DrmDisplayPipeline> pipeline) {
   Deinit();
 
   pipeline_ = std::move(pipeline);
 
   if (pipeline_ != nullptr || handle_ == kPrimaryDisplay) {
-    Init();
+    bool success = Init();
+    ALOGE_IF(!success, "Failed to init HwcDisplay after setting pipeline.");
     hwc_->ScheduleHotplugEvent(handle_, DrmHwc::kConnected);
   } else {
     hwc_->ScheduleHotplugEvent(handle_, DrmHwc::kDisconnected);
@@ -459,6 +546,7 @@ void HwcDisplay::Deinit() {
     GetPipe().atomic_state_manager->ExecuteAtomicCommit(a_args);
     a_args.composition = {};
     a_args.active = false;
+    a_args.teardown = true;
     GetPipe().atomic_state_manager->ExecuteAtomicCommit(a_args);
 
     current_plan_.reset();
@@ -477,14 +565,12 @@ void HwcDisplay::Deinit() {
   client_layer_.ClearSlots();
 }
 
-HWC2::Error HwcDisplay::Init() {
-  ChosePreferredConfig();
-
-  if (type_ != HWC2::DisplayType::Virtual) {
+bool HwcDisplay::Init() {
+  if (!is_virtual_) {
     vsync_worker_ = VSyncWorker::CreateInstance(pipeline_);
     if (!vsync_worker_) {
       ALOGE("Failed to create event worker for d=%d\n", int(handle_));
-      return HWC2::Error::BadDisplay;
+      return false;
     }
   }
 
@@ -492,7 +578,7 @@ HWC2::Error HwcDisplay::Init() {
     auto ret = BackendManager::GetInstance().SetBackendForDisplay(this);
     if (ret) {
       ALOGE("Failed to set backend for d=%d %d\n", int(handle_), ret);
-      return HWC2::Error::BadDisplay;
+      return false;
     }
     auto flatcbk = (struct FlatConCallbacks){
         .trigger = [this]() { hwc_->SendRefreshEventToClient(handle_); }};
@@ -505,7 +591,16 @@ HWC2::Error HwcDisplay::Init() {
 
   SetColorMatrixToIdentity();
 
-  return HWC2::Error::None;
+  if (is_virtual_) {
+    configs_.GenFakeMode(virtual_disp_width_, virtual_disp_height_);
+    pipeline_->writeback_connector = pipeline_->connector;
+  } else if (IsInHeadlessMode()) {
+    configs_.GenFakeMode(0, 0);
+  } else if (!configs_.Update(*pipeline_->connector->Get())) {
+    return false;
+  }
+  return SetConfig(configs_.preferred_config_id) ==
+         HwcDisplay::ConfigError::kNone;
 }
 
 std::optional<PanelOrientation> HwcDisplay::getDisplayPhysicalOrientation() {
@@ -525,22 +620,6 @@ std::optional<PanelOrientation> HwcDisplay::getDisplayPhysicalOrientation() {
   return pipeline.connector->Get()->GetPanelOrientation();
 }
 
-HWC2::Error HwcDisplay::ChosePreferredConfig() {
-  HWC2::Error err{};
-  if (type_ == HWC2::DisplayType::Virtual) {
-    configs_.GenFakeMode(virtual_disp_width_, virtual_disp_height_);
-  } else if (!IsInHeadlessMode()) {
-    err = configs_.Update(*pipeline_->connector->Get());
-  } else {
-    configs_.GenFakeMode(0, 0);
-  }
-  if (!IsInHeadlessMode() && err != HWC2::Error::None) {
-    return HWC2::Error::BadDisplay;
-  }
-
-  return SetActiveConfig(configs_.preferred_config_id);
-}
-
 auto HwcDisplay::CreateLayer(ILayerId new_layer_id) -> bool {
   if (layers_.count(new_layer_id) > 0)
     return false;
@@ -555,186 +634,62 @@ auto HwcDisplay::DestroyLayer(ILayerId layer_id) -> bool {
   return count != 0;
 }
 
-HWC2::Error HwcDisplay::GetActiveConfig(hwc2_config_t *config) const {
-  // If a config has been queued, it is considered the "active" config.
-  const HwcDisplayConfig *hwc_config = GetLastRequestedConfig();
-  if (hwc_config == nullptr)
-    return HWC2::Error::BadConfig;
-
-  *config = hwc_config->id;
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::GetColorModes(uint32_t *num_modes, int32_t *modes) {
-  if (IsInHeadlessMode()) {
-    *num_modes = 1;
-    if (modes)
-      modes[0] = HAL_COLOR_MODE_NATIVE;
-    return HWC2::Error::None;
-  }
+auto HwcDisplay::GetColorModes() -> std::vector<ColorMode> {
+  if (IsInHeadlessMode())
+    return {ColorMode::kNative};
 
-  if (!modes) {
-    std::vector<Colormode> temp_modes;
-    GetEdid()->GetColorModes(temp_modes);
-    *num_modes = temp_modes.size();
-    return HWC2::Error::None;
-  }
+  std::vector<ColorMode> modes;
+  GetEdid()->GetColorModes(modes);
 
-  std::vector<Colormode> temp_modes;
-  std::vector<int32_t> out_modes(modes, modes + *num_modes);
-  GetEdid()->GetColorModes(temp_modes);
-  if (temp_modes.empty()) {
-    out_modes.emplace_back(HAL_COLOR_MODE_NATIVE);
-    return HWC2::Error::None;
-  }
+  if (modes.empty())
+    modes.emplace_back(ColorMode::kNative);
 
-  for (auto &c : temp_modes)
-    out_modes.emplace_back(static_cast<int32_t>(c));
-
-  return HWC2::Error::None;
+  return modes;
 }
 
-HWC2::Error HwcDisplay::GetDisplayAttribute(hwc2_config_t config,
-                                            int32_t attribute_in,
-                                            int32_t *value) {
-  int conf = static_cast<int>(config);
-
-  if (configs_.hwc_configs.count(conf) == 0) {
-    ALOGE("Could not find mode #%d", conf);
-    return HWC2::Error::BadConfig;
-  }
-
-  auto &hwc_config = configs_.hwc_configs[conf];
-
-  static const int32_t kUmPerInch = 25400;
-  auto mm_width = configs_.mm_width;
-  auto attribute = static_cast<HWC2::Attribute>(attribute_in);
-  switch (attribute) {
-    case HWC2::Attribute::Width:
-      *value = static_cast<int>(hwc_config.mode.GetRawMode().hdisplay);
-      break;
-    case HWC2::Attribute::Height:
-      *value = static_cast<int>(hwc_config.mode.GetRawMode().vdisplay);
-      break;
-    case HWC2::Attribute::VsyncPeriod:
-      // in nanoseconds
-      *value = hwc_config.mode.GetVSyncPeriodNs();
+void HwcDisplay::SetColorMode(ColorMode mode) {
+  /* Maps to the Colorspace DRM connector property:
+   * https://elixir.bootlin.com/linux/v6.11/source/include/drm/drm_connector.h#L538
+   */
+  switch (mode) {
+    case ColorMode::kNative:
+      colorspace_ = Colorspace::kDefault;
       break;
-    case HWC2::Attribute::DpiY:
-      *value = GetEdid()->GetDpiY();
-      if (*value < 0) {
-        // default to raw mode DpiX for both x and y when no good value
-        // can be provided from edid.
-        *value = mm_width ? int(hwc_config.mode.GetRawMode().hdisplay *
-                                kUmPerInch / mm_width)
-                          : -1;
-      }
+    case ColorMode::kBt601_625:
+    case ColorMode::kBt601_625Unadjusted:
+    case ColorMode::kBt601_525:
+    case ColorMode::kBt601_525Unadjusted:
+      // The DP spec does not say whether this is the 525 or the 625 line version.
+      colorspace_ = Colorspace::kBt601Ycc;
       break;
-    case HWC2::Attribute::DpiX:
-      // Dots per 1000 inches
-      *value = GetEdid()->GetDpiX();
-      if (*value < 0) {
-        // default to raw mode DpiX for both x and y when no good value
-        // can be provided from edid.
-        *value = mm_width ? int(hwc_config.mode.GetRawMode().hdisplay *
-                                kUmPerInch / mm_width)
-                          : -1;
-      }
+    case ColorMode::kBt709:
+    case ColorMode::kSrgb:
+      colorspace_ = Colorspace::kBt709Ycc;
       break;
-#if __ANDROID_API__ > 29
-    case HWC2::Attribute::ConfigGroup:
-      /* Dispite ConfigGroup is a part of HWC2.4 API, framework
-       * able to request it even if service @2.1 is used */
-      *value = int(hwc_config.group_id);
+    case ColorMode::kDciP3:
+    case ColorMode::kDisplayP3:
+      colorspace_ = Colorspace::kDciP3RgbD65;
       break;
-#endif
-    default:
-      *value = -1;
-      return HWC2::Error::BadConfig;
+    case ColorMode::kDisplayBt2020:
+    case ColorMode::kAdobeRgb:
+    case ColorMode::kBt2020:
+    case ColorMode::kBt2100Pq:
+    case ColorMode::kBt2100Hlg:
+      // HDR color modes should be requested during modeset
+      ALOGW("HDR color modes are not supported with this API.");
+      return;
   }
-  return HWC2::Error::None;
 }
 
-HWC2::Error HwcDisplay::LegacyGetDisplayConfigs(uint32_t *num_configs,
-                                                hwc2_config_t *configs) {
-  uint32_t idx = 0;
-  for (auto &hwc_config : configs_.hwc_configs) {
-    if (hwc_config.second.disabled) {
-      continue;
-    }
-
-    if (configs != nullptr) {
-      if (idx >= *num_configs) {
-        break;
-      }
-      configs[idx] = hwc_config.second.id;
-    }
-
-    idx++;
-  }
-  *num_configs = idx;
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::GetDisplayName(uint32_t *size, char *name) {
-  std::ostringstream stream;
-  if (IsInHeadlessMode()) {
-    stream << "null-display";
-  } else {
-    stream << "display-" << GetPipe().connector->Get()->GetId();
-  }
-  auto string = stream.str();
-  auto length = string.length();
-  if (!name) {
-    *size = length;
-    return HWC2::Error::None;
-  }
-
-  *size = std::min<uint32_t>(static_cast<uint32_t>(length - 1), *size);
-  strncpy(name, string.c_str(), *size);
-  return HWC2::Error::None;
-}
+void HwcDisplay::GetHdrCapabilities(std::vector<ui::Hdr> *types,
+                                    float *max_luminance,
+                                    float *max_average_luminance,
+                                    float *min_luminance) {
+  if (IsInHeadlessMode())
+    return;
 
-HWC2::Error HwcDisplay::GetDisplayType(int32_t *type) {
-  *type = static_cast<int32_t>(type_);
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::GetHdrCapabilities(uint32_t *num_types, int32_t *types,
-                                           float *max_luminance,
-                                           float *max_average_luminance,
-                                           float *min_luminance) {
-  if (IsInHeadlessMode()) {
-    *num_types = 0;
-    return HWC2::Error::None;
-  }
-
-  if (!types) {
-    std::vector<ui::Hdr> temp_types;
-    float lums[3] = {0.F};
-    GetEdid()->GetHdrCapabilities(temp_types, &lums[0], &lums[1], &lums[2]);
-    *num_types = temp_types.size();
-    return HWC2::Error::None;
-  }
-
-  std::vector<ui::Hdr> temp_types;
-  std::vector<int32_t> out_types(types, types + *num_types);
-  GetEdid()->GetHdrCapabilities(temp_types, max_luminance,
-                                max_average_luminance, min_luminance);
-  for (auto &t : temp_types) {
-    switch (t) {
-      case ui::Hdr::HDR10:
-        out_types.emplace_back(HAL_HDR_HDR10);
-        break;
-      case ui::Hdr::HLG:
-        out_types.emplace_back(HAL_HDR_HLG);
-        break;
-      default:
-        // Ignore any other HDR types
-        break;
-    }
-  }
-  return HWC2::Error::None;
+  GetEdid()->GetHdrCapabilities(*types, max_luminance, max_average_luminance,
+                                min_luminance);
 }
 
 AtomicCommitArgs HwcDisplay::CreateModesetCommit(
@@ -800,11 +755,19 @@ void HwcDisplay::WaitForPresentTime(int64_t present_time,
   clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &sleep_until_ts, nullptr);
 }
 
+uint32_t HwcDisplay::GetCurrentVsyncPeriodNs() const {
+  const HwcDisplayConfig *config = GetCurrentConfig();
+  if (config == nullptr) {
+    return 0;
+  }
+  return config->mode.GetVSyncPeriodNs();
+}
+
 // NOLINTNEXTLINE(readability-function-cognitive-complexity)
-HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
+bool HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
   if (IsInHeadlessMode()) {
     ALOGE("%s: Display is in headless mode, should never reach here", __func__);
-    return HWC2::Error::None;
+    return true;
   }
 
   a_args.color_matrix = color_matrix_;
@@ -813,16 +776,14 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
   a_args.hdr_metadata = hdr_metadata_;
   a_args.min_bpc = min_bpc_;
 
-  uint32_t prev_vperiod_ns = 0;
-  GetDisplayVsyncPeriod(&prev_vperiod_ns);
-
+  uint32_t prev_vperiod_ns = GetCurrentVsyncPeriodNs();
   std::optional<uint32_t> new_vsync_period_ns;
   if (staged_mode_config_id_ &&
       staged_mode_change_time_ <= ResourceManager::GetTimeMonotonicNs()) {
     const HwcDisplayConfig *staged_config = GetConfig(
         staged_mode_config_id_.value());
     if (staged_config == nullptr) {
-      return HWC2::Error::BadConfig;
+      return false;
     }
 
     configs_.active_config_id = staged_mode_config_id_.value();
@@ -840,25 +801,27 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
   std::optional<LayerData> cursor_layer = std::nullopt;
   for (auto &[_, layer] : layers_) {
     switch (layer.GetValidatedType()) {
-      case HWC2::Composition::Device:
+      case HwcLayer::CompositionType::kDevice:
         z_map.emplace(layer.GetZOrder(), &layer);
         break;
-      case HWC2::Composition::Cursor:
+      case HwcLayer::CompositionType::kCursor:
         if (!cursor_layer.has_value()) {
-          layer.PopulateLayerData();
           cursor_layer = layer.GetLayerData();
         } else {
           ALOGW("Detected multiple cursor layers");
           z_map.emplace(layer.GetZOrder(), &layer);
         }
         break;
-      case HWC2::Composition::Client:
+      case HwcLayer::CompositionType::kClient:
         // Place it at the z_order of the lowest client layer
         use_client_layer = true;
         client_layer_count++;
         client_z_order = std::min(client_z_order, layer.GetZOrder());
         break;
-      default:
+      case HwcLayer::CompositionType::kSolidColor:
+      case HwcLayer::CompositionType::kInvalid:
+        ALOGE("Invalid layer type: %d",
+              static_cast<int>(layer.GetValidatedType()));
         continue;
     }
   }
@@ -883,24 +846,18 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
        * imported. For example when non-contiguous buffer is imported into
        * contiguous-only DRM/KMS driver.
        */
-      return HWC2::Error::BadLayer;
+      return false;
     }
   }
 
-  if (z_map.empty())
-    return HWC2::Error::BadLayer;
+  ALOGW_IF(z_map.empty() && !cursor_layer.has_value(), "Empty composition");
 
   std::vector<LayerData> composition_layers;
 
-  /* Import & populate */
-  for (std::pair<const uint32_t, HwcLayer *> &l : z_map) {
-    l.second->PopulateLayerData();
-  }
-
   // now that they're ordered by z, add them to the composition
   for (std::pair<const uint32_t, HwcLayer *> &l : z_map) {
     if (!l.second->IsLayerUsableAsDevice()) {
-      return HWC2::Error::BadLayer;
+      return false;
     }
     composition_layers.emplace_back(l.second->GetLayerData());
   }
@@ -911,30 +868,31 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
   current_plan_ = DrmKmsPlan::CreateDrmKmsPlan(GetPipe(),
                                                std::move(composition_layers),
                                                cursor_layer);
+  if (!current_plan_) {
+    ALOGE_IF(!a_args.test_only, "Failed to create DrmKmsPlan");
+    return false;
+  }
+  a_args.composition = current_plan_;
 
-  if (type_ == HWC2::DisplayType::Virtual) {
+  if (pipeline_->writeback_connector) {
     writeback_layer_->PopulateLayerData();
     if (!writeback_layer_->IsLayerUsableAsDevice()) {
-      ALOGE("Output layer must be always usable by DRM/KMS");
-      return HWC2::Error::BadLayer;
+      ALOGE("Writeback layer not usable by DRM/KMS - no valid buffer set");
+      return false;
     }
     a_args.writeback_fb = writeback_layer_->GetLayerData().fb;
     a_args.writeback_release_fence = writeback_layer_->GetLayerData()
                                          .acquire_fence;
   }
 
-  if (!current_plan_) {
-    ALOGE_IF(!a_args.test_only, "Failed to create DrmKmsPlan");
-    return HWC2::Error::BadConfig;
-  }
-
-  a_args.composition = current_plan_;
-
   auto ret = GetPipe().atomic_state_manager->ExecuteAtomicCommit(a_args);
-
   if (ret) {
     ALOGE_IF(!a_args.test_only, "Failed to apply the frame composition ret=%d", ret);
-    return HWC2::Error::BadParameter;
+    return false;
+  }
+
+  if (!a_args.test_only) {
+    writeback_complete_fence_ = a_args.out_writeback_complete_fence;
   }
 
   if (new_vsync_period_ns) {
@@ -950,108 +908,11 @@ HWC2::Error HwcDisplay::CreateComposition(AtomicCommitArgs &a_args) {
     vsync_worker_->SetVsyncPeriodNs(new_vsync_period_ns.value());
   }
 
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::SetActiveConfigInternal(uint32_t config,
-                                                int64_t change_time) {
-  if (configs_.hwc_configs.count(config) == 0) {
-    ALOGE("Could not find active mode for %u", config);
-    return HWC2::Error::BadConfig;
-  }
-
-  staged_mode_change_time_ = change_time;
-  staged_mode_config_id_ = config;
-  if (const HwcDisplayConfig *new_config = GetConfig(config))
-    SetOutputType(new_config->output_type);
-
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::SetActiveConfig(hwc2_config_t config) {
-  return SetActiveConfigInternal(config, ResourceManager::GetTimeMonotonicNs());
-}
-
-HWC2::Error HwcDisplay::SetColorMode(int32_t mode) {
-  /* Maps to the Colorspace DRM connector property:
-   * https://elixir.bootlin.com/linux/v6.11/source/include/drm/drm_connector.h#L538
-   */
-  if (mode < HAL_COLOR_MODE_NATIVE || mode > HAL_COLOR_MODE_DISPLAY_BT2020)
-    return HWC2::Error::BadParameter;
-
-  switch (mode) {
-    case HAL_COLOR_MODE_NATIVE:
-      colorspace_ = Colorspace::kDefault;
-      break;
-    case HAL_COLOR_MODE_STANDARD_BT601_625:
-    case HAL_COLOR_MODE_STANDARD_BT601_625_UNADJUSTED:
-    case HAL_COLOR_MODE_STANDARD_BT601_525:
-    case HAL_COLOR_MODE_STANDARD_BT601_525_UNADJUSTED:
-      // The DP spec does not say whether this is the 525 or the 625 line version.
-      colorspace_ = Colorspace::kBt601Ycc;
-      break;
-    case HAL_COLOR_MODE_STANDARD_BT709:
-    case HAL_COLOR_MODE_SRGB:
-      colorspace_ = Colorspace::kBt709Ycc;
-      break;
-    case HAL_COLOR_MODE_DCI_P3:
-    case HAL_COLOR_MODE_DISPLAY_P3:
-      colorspace_ = Colorspace::kDciP3RgbD65;
-      break;
-    case HAL_COLOR_MODE_DISPLAY_BT2020:
-    case HAL_COLOR_MODE_ADOBE_RGB:
-    case HAL_COLOR_MODE_BT2020:
-    case HAL_COLOR_MODE_BT2100_PQ:
-    case HAL_COLOR_MODE_BT2100_HLG:
-    default:
-      return HWC2::Error::Unsupported;
-  }
-
-  color_mode_ = mode;
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::SetColorTransform(const float *matrix, int32_t hint) {
-  if (hint < HAL_COLOR_TRANSFORM_IDENTITY ||
-      hint > HAL_COLOR_TRANSFORM_CORRECT_TRITANOPIA)
-    return HWC2::Error::BadParameter;
-
-  if (!matrix && hint == HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX)
-    return HWC2::Error::BadParameter;
-
-  color_transform_hint_ = static_cast<android_color_transform_t>(hint);
-  ctm_has_offset_ = false;
-
-  if (IsInHeadlessMode())
-    return HWC2::Error::None;
-
-  if (!GetPipe().crtc->Get()->GetCtmProperty())
-    return HWC2::Error::None;
-
-  switch (color_transform_hint_) {
-    case HAL_COLOR_TRANSFORM_IDENTITY:
-      SetColorMatrixToIdentity();
-      break;
-    case HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX:
-      // Without HW support, we cannot correctly process matrices with an offset.
-      {
-        if (TransformHasOffsetValue(matrix))
-          ctm_has_offset_ = true;
-
-        std::array<float, 16> aidl_matrix = kIdentityMatrix;
-        memcpy(aidl_matrix.data(), matrix, aidl_matrix.size() * sizeof(float));
-        color_matrix_ = ToColorTransform(aidl_matrix);
-      }
-      break;
-    default:
-      return HWC2::Error::Unsupported;
-  }
-
-  return HWC2::Error::None;
+  return true;
 }
 
 bool HwcDisplay::CtmByGpu() {
-  if (color_transform_hint_ == HAL_COLOR_TRANSFORM_IDENTITY)
+  if (color_transform_is_identity_)
     return false;
 
   if (GetPipe().crtc->Get()->GetCtmProperty() && !ctm_has_offset_)
@@ -1063,70 +924,44 @@ bool HwcDisplay::CtmByGpu() {
   return true;
 }
 
-HWC2::Error HwcDisplay::SetPowerMode(int32_t mode_in) {
-  auto mode = static_cast<HWC2::PowerMode>(mode_in);
-
-  AtomicCommitArgs a_args{};
+bool HwcDisplay::IsWritebackSupported() {
+  return !is_virtual_ &&
+         pipeline_->FindWritebackConnectorForPipeline() != nullptr;
+}
 
-  switch (mode) {
-    case HWC2::PowerMode::Off:
-      a_args.active = false;
-      break;
-    case HWC2::PowerMode::On:
-      a_args.active = true;
-      break;
-    case HWC2::PowerMode::Doze:
-    case HWC2::PowerMode::DozeSuspend:
-      return HWC2::Error::Unsupported;
-    default:
-      ALOGE("Incorrect power mode value (%d)\n", mode_in);
-      return HWC2::Error::BadParameter;
+bool HwcDisplay::SetWritebackEnabled(bool enabled) {
+  // Handle Disable
+  if (!enabled) {
+    pipeline_->writeback_connector = nullptr;
+    return true;
   }
 
-  if (IsInHeadlessMode()) {
-    return HWC2::Error::None;
+  // Handle Enable
+  if (pipeline_->writeback_connector != nullptr) {
+    return true;
   }
 
-  if (a_args.active && *a_args.active) {
-    /*
-     * Setting the display to active before we have a composition
-     * can break some drivers, so skip setting a_args.active to
-     * true, as the next composition frame will implicitly activate
-     * the display
-     */
-    return GetPipe().atomic_state_manager->ActivateDisplayUsingDPMS() == 0
-               ? HWC2::Error::None
-               : HWC2::Error::BadParameter;
-  };
-
-  auto err = GetPipe().atomic_state_manager->ExecuteAtomicCommit(a_args);
-  if (err) {
-    ALOGE("Failed to apply the dpms composition err=%d", err);
-    return HWC2::Error::BadParameter;
+  auto *wb_connector = pipeline_->FindWritebackConnectorForPipeline();
+  if (!wb_connector) {
+    ALOGE("HwcDisplay: No writeback connector found");
+    return false;
   }
-  return HWC2::Error::None;
+  auto bound_connector = wb_connector->BindPipeline(pipeline_.get());
+  if (!bound_connector) {
+    ALOGE("HwcDisplay: Failed to bind writeback connector");
+    return false;
+  }
+  pipeline_->writeback_connector = bound_connector;
+  return true;
 }
 
-HWC2::Error HwcDisplay::SetVsyncEnabled(int32_t enabled) {
-  if (type_ == HWC2::DisplayType::Virtual) {
-    return HWC2::Error::None;
-  }
-  if (!vsync_worker_) {
-    return HWC2::Error::NoResources;
+SharedFd HwcDisplay::GetWritebackBufferFence() {
+  if (!writeback_complete_fence_) {
+    ALOGE("HwcDisplay: No readback fence available for display");
+    return nullptr;
   }
 
-  vsync_event_en_ = HWC2_VSYNC_ENABLE == enabled;
-  std::optional<VSyncWorker::VsyncTimestampCallback> callback = std::nullopt;
-  if (vsync_event_en_) {
-    DrmHwc *hwc = hwc_;
-    hwc2_display_t id = handle_;
-    // Callback will be called from the vsync thread.
-    callback = [hwc, id](int64_t timestamp, uint32_t period_ns) {
-      hwc->SendVsyncEventToClient(id, timestamp, period_ns);
-    };
-  }
-  vsync_worker_->SetTimestampCallback(std::move(callback));
-  return HWC2::Error::None;
+  return std::move(writeback_complete_fence_);
 }
 
 std::vector<HwcLayer *> HwcDisplay::GetOrderLayersByZPos() {
@@ -1140,9 +975,9 @@ std::vector<HwcLayer *> HwcDisplay::GetOrderLayersByZPos() {
   std::sort(std::begin(ordered_layers), std::end(ordered_layers),
             [](const HwcLayer *lhs, const HwcLayer *rhs) {
               // Cursor layers should always have highest zpos.
-              if ((lhs->GetSfType() == HWC2::Composition::Cursor) !=
-                  (rhs->GetSfType() == HWC2::Composition::Cursor)) {
-                return rhs->GetSfType() == HWC2::Composition::Cursor;
+              if ((lhs->GetSfType() == HwcLayer::CompositionType::kCursor) !=
+                  (rhs->GetSfType() == HwcLayer::CompositionType::kCursor)) {
+                return rhs->GetSfType() == HwcLayer::CompositionType::kCursor;
               }
 
               return lhs->GetZOrder() < rhs->GetZOrder();
@@ -1151,13 +986,6 @@ std::vector<HwcLayer *> HwcDisplay::GetOrderLayersByZPos() {
   return ordered_layers;
 }
 
-HWC2::Error HwcDisplay::GetDisplayVsyncPeriod(
-    uint32_t *outVsyncPeriod /* ns */) {
-  return GetDisplayAttribute(configs_.active_config_id,
-                             HWC2_ATTRIBUTE_VSYNC_PERIOD,
-                             (int32_t *)(outVsyncPeriod));
-}
-
 // Display primary values are coded as unsigned 16-bit values in units of
 // 0.00002, where 0x0000 represents zero and 0xC350 represents 1.0000.
 static uint64_t ToU16ColorValue(float in) {
@@ -1165,7 +993,7 @@ static uint64_t ToU16ColorValue(float in) {
   return static_cast<uint64_t>(kPrimariesFixedPoint * in);
 }
 
-HWC2::Error HwcDisplay::SetHdrOutputMetadata(ui::Hdr type) {
+void HwcDisplay::SetHdrOutputMetadata(ui::Hdr type) {
   hdr_metadata_ = std::make_shared<hdr_output_metadata>();
   hdr_metadata_->metadata_type = 0;
   auto *m = &hdr_metadata_->hdmi_metadata_type1;
@@ -1179,7 +1007,8 @@ HWC2::Error HwcDisplay::SetHdrOutputMetadata(ui::Hdr type) {
       m->eotf = 3;  // HLG
       break;
     default:
-      return HWC2::Error::Unsupported;
+      ALOGW("HDR type %d is not supported.", type);
+      return;
   }
 
   // Most luminance values are coded as an unsigned 16-bit value in units of 1
@@ -1209,172 +1038,7 @@ HWC2::Error HwcDisplay::SetHdrOutputMetadata(ui::Hdr type) {
   auto whitePoint = gamut.getWhitePoint();
   m->white_point.x = ToU16ColorValue(whitePoint.x);
   m->white_point.y = ToU16ColorValue(whitePoint.y);
-
-  return HWC2::Error::None;
-}
-
-#if __ANDROID_API__ > 29
-HWC2::Error HwcDisplay::GetDisplayConnectionType(uint32_t *outType) {
-  if (IsInHeadlessMode()) {
-    *outType = static_cast<uint32_t>(HWC2::DisplayConnectionType::Internal);
-    return HWC2::Error::None;
-  }
-  /* Primary display should be always internal,
-   * otherwise SF will be unhappy and will crash
-   */
-  if (GetPipe().connector->Get()->IsInternal() || handle_ == kPrimaryDisplay)
-    *outType = static_cast<uint32_t>(HWC2::DisplayConnectionType::Internal);
-  else if (GetPipe().connector->Get()->IsExternal())
-    *outType = static_cast<uint32_t>(HWC2::DisplayConnectionType::External);
-  else
-    return HWC2::Error::BadConfig;
-
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::SetActiveConfigWithConstraints(
-    hwc2_config_t config,
-    hwc_vsync_period_change_constraints_t *vsyncPeriodChangeConstraints,
-    hwc_vsync_period_change_timeline_t *outTimeline) {
-  if (type_ == HWC2::DisplayType::Virtual) {
-    return HWC2::Error::None;
-  }
-
-  if (vsyncPeriodChangeConstraints == nullptr || outTimeline == nullptr) {
-    return HWC2::Error::BadParameter;
-  }
-
-  uint32_t current_vsync_period{};
-  GetDisplayVsyncPeriod(&current_vsync_period);
-
-  if (vsyncPeriodChangeConstraints->seamlessRequired) {
-    return HWC2::Error::SeamlessNotAllowed;
-  }
-
-  outTimeline->refreshTimeNanos = vsyncPeriodChangeConstraints
-                                      ->desiredTimeNanos -
-                                  current_vsync_period;
-  auto ret = SetActiveConfigInternal(config, outTimeline->refreshTimeNanos);
-  if (ret != HWC2::Error::None) {
-    return ret;
-  }
-
-  outTimeline->refreshRequired = true;
-  outTimeline->newVsyncAppliedTimeNanos = vsyncPeriodChangeConstraints
-                                              ->desiredTimeNanos;
-
-  vsync_worker_->SetVsyncTimestampTracking(true);
-
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::SetContentType(int32_t contentType) {
-  /* Maps exactly to the content_type DRM connector property:
-   * https://elixir.bootlin.com/linux/v6.11/source/include/uapi/drm/drm_mode.h#L107
-   */
-  if (contentType < HWC2_CONTENT_TYPE_NONE || contentType > HWC2_CONTENT_TYPE_GAME)
-    return HWC2::Error::BadParameter;
-
-  content_type_ = contentType;
-
-  return HWC2::Error::None;
 }
-#endif
-
-#if __ANDROID_API__ > 28
-HWC2::Error HwcDisplay::GetDisplayIdentificationData(uint8_t *outPort,
-                                                     uint32_t *outDataSize,
-                                                     uint8_t *outData) {
-  if (IsInHeadlessMode()) {
-    return HWC2::Error::Unsupported;
-  }
-
-  auto *connector = GetPipe().connector->Get();
-  auto blob = connector->GetEdidBlob();
-  if (!blob) {
-    return HWC2::Error::Unsupported;
-  }
-
-  constexpr uint8_t kDrmDeviceBitShift = 5U;
-  constexpr uint8_t kDrmDeviceBitMask = 0xE0;
-  constexpr uint8_t kConnectorBitMask = 0x1F;
-  const auto kDrmIdx = static_cast<uint8_t>(
-      connector->GetDev().GetIndexInDevArray());
-  const auto kConnectorIdx = static_cast<uint8_t>(
-      connector->GetIndexInResArray());
-  *outPort = (((kDrmIdx << kDrmDeviceBitShift) & kDrmDeviceBitMask) |
-              (kConnectorIdx & kConnectorBitMask));
-
-  if (outData) {
-    *outDataSize = std::min(*outDataSize, blob->length);
-    memcpy(outData, blob->data, *outDataSize);
-  } else {
-    *outDataSize = blob->length;
-  }
-
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::GetDisplayCapabilities(uint32_t *outNumCapabilities,
-                                               uint32_t *outCapabilities) {
-  if (outNumCapabilities == nullptr) {
-    return HWC2::Error::BadParameter;
-  }
-
-  bool skip_ctm = false;
-
-  // Skip client CTM if user requested DRM_OR_IGNORE
-  if (GetHwc()->GetResMan().GetCtmHandling() == CtmHandling::kDrmOrIgnore)
-    skip_ctm = true;
-
-  if (!skip_ctm) {
-    *outNumCapabilities = 0;
-    return HWC2::Error::None;
-  }
-
-  *outNumCapabilities = 1;
-  if (outCapabilities) {
-    outCapabilities[0] = HWC2_DISPLAY_CAPABILITY_SKIP_CLIENT_COLOR_TRANSFORM;
-  }
-
-  return HWC2::Error::None;
-}
-
-#endif /* __ANDROID_API__ > 28 */
-
-#if __ANDROID_API__ > 27
-
-HWC2::Error HwcDisplay::GetRenderIntents(
-    int32_t mode, uint32_t *outNumIntents,
-    int32_t * /*android_render_intent_v1_1_t*/ outIntents) {
-  if (mode != HAL_COLOR_MODE_NATIVE) {
-    return HWC2::Error::BadParameter;
-  }
-
-  if (outIntents == nullptr) {
-    *outNumIntents = 1;
-    return HWC2::Error::None;
-  }
-  *outNumIntents = 1;
-  outIntents[0] = HAL_RENDER_INTENT_COLORIMETRIC;
-  return HWC2::Error::None;
-}
-
-HWC2::Error HwcDisplay::SetColorModeWithIntent(int32_t mode, int32_t intent) {
-  if (intent < HAL_RENDER_INTENT_COLORIMETRIC ||
-      intent > HAL_RENDER_INTENT_TONE_MAP_ENHANCE)
-    return HWC2::Error::BadParameter;
-
-  if (intent != HAL_RENDER_INTENT_COLORIMETRIC)
-    return HWC2::Error::Unsupported;
-
-  auto err = SetColorMode(mode);
-  if (err != HWC2::Error::None) return err;
-
-  return HWC2::Error::None;
-}
-
-#endif /* __ANDROID_API__ > 27 */
 
 const Backend *HwcDisplay::backend() const {
   return backend_.get();
@@ -1387,8 +1051,8 @@ void HwcDisplay::set_backend(std::unique_ptr<Backend> backend) {
 bool HwcDisplay::NeedsClientLayerUpdate() const {
   return std::any_of(layers_.begin(), layers_.end(), [](const auto &pair) {
     const auto &layer = pair.second;
-    return layer.GetSfType() == HWC2::Composition::Client ||
-           layer.GetValidatedType() == HWC2::Composition::Client;
+    return layer.GetSfType() == HwcLayer::CompositionType::kClient ||
+           layer.GetValidatedType() == HwcLayer::CompositionType::kClient;
   });
 }
 
diff --git a/hwc2_device/HwcDisplay.h b/hwc/HwcDisplay.h
similarity index 64%
rename from hwc2_device/HwcDisplay.h
rename to hwc/HwcDisplay.h
index d493597..caeb56a 100644
--- a/hwc2_device/HwcDisplay.h
+++ b/hwc/HwcDisplay.h
@@ -16,8 +16,6 @@
 
 #pragma once
 
-#include <hardware/hwcomposer2.h>
-
 #include <atomic>
 #include <optional>
 #include <sstream>
@@ -25,16 +23,19 @@
 #include <ui/GraphicTypes.h>
 
 #include "HwcDisplayConfigs.h"
+#include "HwcLayer.h"
 #include "compositor/DisplayInfo.h"
 #include "compositor/FlatteningController.h"
 #include "compositor/LayerData.h"
 #include "drm/DrmAtomicStateManager.h"
 #include "drm/ResourceManager.h"
 #include "drm/VSyncWorker.h"
-#include "hwc2_device/HwcLayer.h"
+#include "stats/CompositionStats.h"
 
 namespace android {
 
+using DisplayHandle = int64_t;
+
 class Backend;
 class DrmHwc;
 
@@ -56,7 +57,9 @@ class HwcDisplay {
     kConfigFailed,
   };
 
-  HwcDisplay(hwc2_display_t handle, HWC2::DisplayType type, DrmHwc *hwc);
+  enum DisplayType { kInternal, kExternal, kVirtual };
+
+  HwcDisplay(DisplayHandle handle, bool is_virtual, DrmHwc *hwc);
   HwcDisplay(const HwcDisplay &) = delete;
   ~HwcDisplay();
 
@@ -66,13 +69,13 @@ class HwcDisplay {
   /* SetPipeline should be carefully used only by DrmHwcTwo hotplug handlers */
   void SetPipeline(std::shared_ptr<DrmDisplayPipeline> pipeline);
 
-  HWC2::Error CreateComposition(AtomicCommitArgs &a_args);
+  bool CreateComposition(AtomicCommitArgs &a_args);
   std::vector<HwcLayer *> GetOrderLayersByZPos();
 
-  void ClearDisplay();
-
   std::string Dump();
 
+  auto GetDisplayName() -> std::string;
+
   const HwcDisplayConfigs &GetDisplayConfigs() const {
     return configs_;
   }
@@ -88,21 +91,21 @@ class HwcDisplay {
   // Set a config synchronously. If the requested config fails to be committed,
   // this will return with an error. Otherwise, the config will have been
   // committed to the kernel on successful return.
-  ConfigError SetConfig(hwc2_config_t config);
+  ConfigError SetConfig(ConfigId config);
 
   // Queue a configuration change to take effect in the future.
-  auto QueueConfig(hwc2_config_t config, int64_t desired_time, bool seamless,
+  auto QueueConfig(ConfigId config, int64_t desired_time, bool seamless,
                    QueuedConfigTiming *out_timing) -> ConfigError;
 
   // Get the HwcDisplayConfig, or nullptor if none.
-  auto GetConfig(hwc2_config_t config_id) const -> const HwcDisplayConfig *;
+  auto GetConfig(ConfigId config_id) const -> const HwcDisplayConfig *;
 
   auto GetDisplayBoundsMm() -> std::pair<int32_t, int32_t>;
 
   // To be called after SetDisplayProperties. Returns an empty vector if the
   // requested layers have been validated, otherwise the vector describes
   // the requested composition type changes.
-  using ChangedLayer = std::pair<ILayerId, HWC2::Composition>;
+  using ChangedLayer = std::pair<ILayerId, HwcLayer::CompositionType>;
   auto ValidateStagedComposition() -> std::vector<ChangedLayer>;
 
   // Mark previously validated properties as ready to present.
@@ -119,6 +122,25 @@ class HwcDisplay {
                                 std::vector<ReleaseFence> &out_release_fences)
       -> bool;
 
+  // Get the edid bytes for this display. Return an empty vector on error.
+  auto GetRawEdid() -> std::vector<uint8_t>;
+
+  // Get the port id that this display is plugged into.
+  auto GetPort() -> uint8_t;
+
+  auto SetContentType(ContentType content_type) {
+    content_type_ = content_type;
+  }
+
+  // Physical displays are either internal or external.
+  auto GetDisplayType() -> DisplayType;
+
+  // Enable or disable vsync callbacks.
+  void SetVsyncCallbacksEnabled(bool enabled);
+
+  // Enable or disable the display.
+  bool SetDisplayEnabled(bool enabled);
+
   auto GetFrontendPrivateData() -> std::shared_ptr<FrontendDisplayBase> {
     return frontend_private_data_;
   }
@@ -130,49 +152,16 @@ class HwcDisplay {
   auto CreateLayer(ILayerId new_layer_id) -> bool;
   auto DestroyLayer(ILayerId layer_id) -> bool;
 
-  // HWC2 Hooks - these should not be used outside of the hwc2 device.
-  HWC2::Error GetActiveConfig(hwc2_config_t *config) const;
-  HWC2::Error GetColorModes(uint32_t *num_modes, int32_t *modes);
-  HWC2::Error GetDisplayAttribute(hwc2_config_t config, int32_t attribute,
-                                  int32_t *value);
-  HWC2::Error LegacyGetDisplayConfigs(uint32_t *num_configs,
-                                      hwc2_config_t *configs);
-  HWC2::Error GetDisplayName(uint32_t *size, char *name);
-  HWC2::Error GetDisplayType(int32_t *type);
-#if __ANDROID_API__ > 27
-  HWC2::Error GetRenderIntents(int32_t mode, uint32_t *outNumIntents,
-                               int32_t *outIntents);
-  HWC2::Error SetColorModeWithIntent(int32_t mode, int32_t intent);
-#endif
-#if __ANDROID_API__ > 28
-  HWC2::Error GetDisplayIdentificationData(uint8_t *outPort,
-                                           uint32_t *outDataSize,
-                                           uint8_t *outData);
-  HWC2::Error GetDisplayCapabilities(uint32_t *outNumCapabilities,
-                                     uint32_t *outCapabilities);
-#endif
-#if __ANDROID_API__ > 29
-  HWC2::Error GetDisplayConnectionType(uint32_t *outType);
-
-  HWC2::Error SetActiveConfigWithConstraints(
-      hwc2_config_t config,
-      hwc_vsync_period_change_constraints_t *vsyncPeriodChangeConstraints,
-      hwc_vsync_period_change_timeline_t *outTimeline);
-
-  HWC2::Error SetContentType(int32_t contentType);
-#endif
-  HWC2::Error GetDisplayVsyncPeriod(uint32_t *outVsyncPeriod);
-
-  HWC2::Error GetHdrCapabilities(uint32_t *num_types, int32_t *types,
-                                 float *max_luminance,
-                                 float *max_average_luminance,
-                                 float *min_luminance);
-  HWC2::Error SetActiveConfig(hwc2_config_t config);
-  HWC2::Error ChosePreferredConfig();
-  HWC2::Error SetColorMode(int32_t mode);
-  HWC2::Error SetColorTransform(const float *matrix, int32_t hint);
-  HWC2::Error SetPowerMode(int32_t mode);
-  HWC2::Error SetVsyncEnabled(int32_t enabled);
+  auto GetColorModes() -> std::vector<ColorMode>;
+  void SetColorMode(ColorMode color_mode);
+
+  void GetHdrCapabilities(std::vector<ui::Hdr> *types, float *max_luminance,
+                          float *max_average_luminance, float *min_luminance);
+
+  bool IsWritebackSupported();
+  bool SetWritebackEnabled(bool enabled);
+  SharedFd GetWritebackBufferFence();
+
   HwcLayer *get_layer(ILayerId layer) {
     auto it = layers_.find(layer);
     if (it == layers_.end())
@@ -180,25 +169,6 @@ class HwcDisplay {
     return &it->second;
   }
 
-  /* Statistics */
-  struct Stats {
-    Stats minus(Stats b) const {
-      return {total_frames_ - b.total_frames_,
-              total_pixops_ - b.total_pixops_,
-              gpu_pixops_ - b.gpu_pixops_,
-              failed_kms_validate_ - b.failed_kms_validate_,
-              failed_kms_present_ - b.failed_kms_present_,
-              frames_flattened_ - b.frames_flattened_};
-    }
-
-    uint32_t total_frames_ = 0;
-    uint64_t total_pixops_ = 0;
-    uint64_t gpu_pixops_ = 0;
-    uint32_t failed_kms_validate_ = 0;
-    uint32_t failed_kms_present_ = 0;
-    uint32_t frames_flattened_ = 0;
-  };
-
   const Backend *backend() const;
   void set_backend(std::unique_ptr<Backend> backend);
 
@@ -216,7 +186,7 @@ class HwcDisplay {
 
   bool CtmByGpu();
 
-  Stats &total_stats() {
+  CompositionStats &total_stats() {
     return total_stats_;
   }
 
@@ -262,12 +232,14 @@ class HwcDisplay {
   // expected vsync time.
   void WaitForPresentTime(int64_t present_time, uint32_t vsync_period_ns);
 
+  uint32_t GetCurrentVsyncPeriodNs() const;
+
   HwcDisplayConfigs configs_;
 
   DrmHwc *const hwc_;
 
   int64_t staged_mode_change_time_{};
-  std::optional<uint32_t> staged_mode_config_id_{};
+  std::optional<ConfigId> staged_mode_config_id_{};
 
   std::shared_ptr<DrmDisplayPipeline> pipeline_;
 
@@ -277,38 +249,36 @@ class HwcDisplay {
   std::unique_ptr<VSyncWorker> vsync_worker_;
   bool vsync_event_en_{};
 
-  const hwc2_display_t handle_;
-  HWC2::DisplayType type_;
+  const DisplayHandle handle_;
+  bool is_virtual_;
 
   std::map<ILayerId, HwcLayer> layers_;
   HwcLayer client_layer_;
   std::unique_ptr<HwcLayer> writeback_layer_;
   uint16_t virtual_disp_width_{};
   uint16_t virtual_disp_height_{};
-  int32_t color_mode_{};
   std::shared_ptr<drm_color_ctm> color_matrix_;
   std::shared_ptr<drm_color_ctm> identity_color_matrix_;
-  android_color_transform_t color_transform_hint_{};
+  bool color_transform_is_identity_{};
   bool ctm_has_offset_ = false;
-  int32_t content_type_{};
+  ContentType content_type_ = ContentType::kNoData;
   Colorspace colorspace_{};
   int32_t min_bpc_{};
   std::shared_ptr<hdr_output_metadata> hdr_metadata_;
 
   std::shared_ptr<DrmKmsPlan> current_plan_;
 
+  SharedFd writeback_complete_fence_;
+
   uint32_t frame_no_ = 0;
-  Stats total_stats_;
-  Stats prev_stats_;
-  std::string DumpDelta(HwcDisplay::Stats delta);
+  CompositionStats total_stats_;
 
   void SetColorMatrixToIdentity();
 
-  HWC2::Error Init();
+  bool Init();
 
-  HWC2::Error SetActiveConfigInternal(uint32_t config, int64_t change_time);
-  HWC2::Error SetHdrOutputMetadata(ui::Hdr hdrType);
-  HWC2::Error SetOutputType(uint32_t hdr_output_type);
+  void SetHdrOutputMetadata(ui::Hdr hdrType);
+  void SetOutputType(uint32_t hdr_output_type);
 
   auto GetEdid() -> EdidWrapperUnique & {
     return GetPipe().connector->Get()->GetParsedEdid();
diff --git a/hwc2_device/HwcDisplayConfigs.cpp b/hwc/HwcDisplayConfigs.cpp
similarity index 95%
rename from hwc2_device/HwcDisplayConfigs.cpp
rename to hwc/HwcDisplayConfigs.cpp
index ca70c14..9696021 100644
--- a/hwc2_device/HwcDisplayConfigs.cpp
+++ b/hwc/HwcDisplayConfigs.cpp
@@ -38,7 +38,7 @@ constexpr uint32_t kHzInKHz = 1000;
 namespace android {
 
 // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
-uint32_t HwcDisplayConfigs::last_config_id = 1;
+ConfigId HwcDisplayConfigs::last_config_id = 1;
 
 void HwcDisplayConfigs::GenFakeMode(uint16_t width, uint16_t height) {
   hwc_configs.clear();
@@ -88,7 +88,7 @@ void HwcDisplayConfigs::GenFakeMode(uint16_t width, uint16_t height) {
 }
 
 // NOLINTNEXTLINE (readability-function-cognitive-complexity): Fixme
-HWC2::Error HwcDisplayConfigs::Update(DrmConnector &connector) {
+bool HwcDisplayConfigs::Update(DrmConnector &connector) {
   /* In case UpdateModes will fail we will still have one mode for headless
    * mode
    */
@@ -97,12 +97,12 @@ HWC2::Error HwcDisplayConfigs::Update(DrmConnector &connector) {
   auto ret = connector.UpdateModes();
   if (ret != 0) {
     ALOGE("Failed to update display modes %d", ret);
-    return HWC2::Error::BadDisplay;
+    return false;
   }
 
   if (connector.GetModes().empty()) {
     ALOGE("No modes reported by KMS");
-    return HWC2::Error::BadDisplay;
+    return false;
   }
 
   hwc_configs.clear();
@@ -218,8 +218,8 @@ HWC2::Error HwcDisplayConfigs::Update(DrmConnector &connector) {
    * otherwise android.graphics.cts.SetFrameRateTest CTS will fail
    */
   constexpr float kMinFpsDelta = 1.0;  // FPS
-  for (uint32_t m1 = first_config_id; m1 < last_config_id; m1++) {
-    for (uint32_t m2 = first_config_id; m2 < last_config_id; m2++) {
+  for (ConfigId m1 = first_config_id; m1 < last_config_id; m1++) {
+    for (ConfigId m2 = first_config_id; m2 < last_config_id; m2++) {
       if (m1 != m2 && hwc_configs[m1].group_id == hwc_configs[m2].group_id &&
           !hwc_configs[m1].disabled && !hwc_configs[m2].disabled &&
           fabsf(hwc_configs[m1].mode.GetVRefresh() -
@@ -235,7 +235,7 @@ HWC2::Error HwcDisplayConfigs::Update(DrmConnector &connector) {
     }
   }
 
-  return HWC2::Error::None;
+  return true;
 }
 
 }  // namespace android
diff --git a/hwc2_device/HwcDisplayConfigs.h b/hwc/HwcDisplayConfigs.h
similarity index 81%
rename from hwc2_device/HwcDisplayConfigs.h
rename to hwc/HwcDisplayConfigs.h
index 8fc89bf..4f22486 100644
--- a/hwc2_device/HwcDisplayConfigs.h
+++ b/hwc/HwcDisplayConfigs.h
@@ -16,18 +16,18 @@
 
 #pragma once
 
-#include <hardware/hwcomposer2.h>
-
 #include <map>
 
 #include "drm/DrmMode.h"
 
 namespace android {
 
+using ConfigId = int32_t;
+
 class DrmConnector;
 
 struct HwcDisplayConfig {
-  uint32_t id{};
+  ConfigId id{};
   uint32_t group_id{};
   DrmMode mode{};
   bool disabled{};
@@ -39,16 +39,16 @@ struct HwcDisplayConfig {
 };
 
 struct HwcDisplayConfigs {
-  HWC2::Error Update(DrmConnector &conn);
+  bool Update(DrmConnector &conn);
   void GenFakeMode(uint16_t width, uint16_t height);
 
-  std::map<uint32_t /*config_id*/, struct HwcDisplayConfig> hwc_configs;
+  std::map<ConfigId, struct HwcDisplayConfig> hwc_configs;
 
-  uint32_t active_config_id = 0;
-  uint32_t preferred_config_id = 0;
+  ConfigId active_config_id = 0;
+  ConfigId preferred_config_id = 0;
 
   // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
-  static uint32_t last_config_id;
+  static ConfigId last_config_id;
 
   uint32_t mm_width = 0;
   uint32_t mm_height = 0;
diff --git a/hwc2_device/HwcLayer.cpp b/hwc/HwcLayer.cpp
similarity index 75%
rename from hwc2_device/HwcLayer.cpp
rename to hwc/HwcLayer.cpp
index 400ac9b..d9dfdfd 100644
--- a/hwc2_device/HwcLayer.cpp
+++ b/hwc/HwcLayer.cpp
@@ -34,12 +34,15 @@ void HwcLayer::SetLayerProperties(const LayerProperties& layer_properties) {
           .bi = layer_properties.slot_buffer->bi.value(),
           .fb = {},
       };
+      bool success = ImportFb(slots_[slot_id]);
+      ALOGE_IF(!success,
+               "Unable to create framebuffer object for layer %p slot %d", this,
+               slot_id);
     }
   }
   if (layer_properties.active_slot) {
     active_slot_id_ = layer_properties.active_slot->slot_id;
     layer_data_.acquire_fence = layer_properties.active_slot->fence;
-    buffer_updated_ = true;
   }
   if (layer_properties.blend_mode) {
     blend_mode_ = layer_properties.blend_mode.value();
@@ -68,40 +71,31 @@ void HwcLayer::SetLayerProperties(const LayerProperties& layer_properties) {
   if (layer_properties.z_order) {
     z_order_ = layer_properties.z_order.value();
   }
-}
-
-void HwcLayer::ImportFb() {
-  if (!IsLayerUsableAsDevice() || !buffer_updated_ ||
-      !active_slot_id_.has_value()) {
-    return;
+  if (layer_properties.damage) {
+    layer_data_.pi.damage = layer_properties.damage.value();
   }
-  buffer_updated_ = false;
+}
 
-  if (slots_[*active_slot_id_].fb) {
-    return;
+bool HwcLayer::ImportFb(BufferSlot& slot) const {
+  if (parent_->IsInHeadlessMode()) {
+    return true;
   }
 
-  auto& fb_importer = parent_->GetPipe().device->GetDrmFbImporter();
-  auto fb = fb_importer.GetOrCreateFbId(&slots_[*active_slot_id_].bi);
-
-  if (!fb) {
-    ALOGE("Unable to create framebuffer object for layer %p", this);
-    fb_import_failed_ = true;
-    return;
+  if (slot.fb == nullptr) {
+    auto& fb_importer = parent_->GetPipe().device->GetDrmFbImporter();
+    slot.fb = fb_importer.GetOrCreateFbId(&slot.bi);
   }
-
-  slots_[*active_slot_id_].fb = fb;
+  return slot.fb != nullptr;
 }
 
 void HwcLayer::PopulateLayerData() {
-  ImportFb();
-
   if (!active_slot_id_.has_value()) {
     ALOGE("Internal error: populate layer data called without active slot");
     return;
   }
 
   if (slots_.count(*active_slot_id_) == 0) {
+    ALOGE("Internal error: active cache slot is not populated.");
     return;
   }
 
@@ -124,4 +118,18 @@ void HwcLayer::ClearSlots() {
   active_slot_id_.reset();
 }
 
+/* Check that the layer has an active slot set, and there is a valid
+   * framebuffer in the active slot.
+ */
+bool HwcLayer::IsLayerUsableAsDevice() const {
+  if (!active_slot_id_.has_value()) {
+    return false;
+  }
+  auto it = slots_.find(*active_slot_id_);
+  if (it == slots_.end()) {
+    return false;
+  }
+  return it->second.fb != nullptr;
+}
+
 }  // namespace android
\ No newline at end of file
diff --git a/hwc2_device/HwcLayer.h b/hwc/HwcLayer.h
similarity index 84%
rename from hwc2_device/HwcLayer.h
rename to hwc/HwcLayer.h
index c335d88..eb83f0b 100644
--- a/hwc2_device/HwcLayer.h
+++ b/hwc/HwcLayer.h
@@ -16,8 +16,6 @@
 
 #pragma once
 
-#include <aidl/android/hardware/graphics/common/Transform.h>
-#include <hardware/hwcomposer2.h>
 #include <memory>
 
 #include "bufferinfo/BufferInfo.h"
@@ -44,6 +42,13 @@ class HwcLayer {
     int32_t slot_id;
     SharedFd fence;
   };
+  enum class CompositionType {
+    kInvalid,
+    kClient,
+    kDevice,
+    kSolidColor,
+    kCursor
+  };
   // A set of properties to be validated.
   struct LayerProperties {
     std::optional<Buffer> slot_buffer;
@@ -51,26 +56,27 @@ class HwcLayer {
     std::optional<BufferBlendMode> blend_mode;
     std::optional<BufferColorSpace> color_space;
     std::optional<BufferSampleRange> sample_range;
-    std::optional<HWC2::Composition> composition_type;
+    std::optional<CompositionType> composition_type;
     std::optional<DstRectInfo> display_frame;
     std::optional<float> alpha;
     std::optional<SrcRectInfo> source_crop;
     std::optional<LayerTransform> transform;
     std::optional<uint32_t> z_order;
+    std::optional<DamageInfo> damage;
   };
 
   explicit HwcLayer(HwcDisplay *parent_display) : parent_(parent_display){};
 
-  HWC2::Composition GetSfType() const {
+  CompositionType GetSfType() const {
     return sf_type_;
   }
-  HWC2::Composition GetValidatedType() const {
+  CompositionType GetValidatedType() const {
     return validated_type_;
   }
   void AcceptTypeChange() {
     sf_type_ = validated_type_;
   }
-  void SetValidatedType(HWC2::Composition type) {
+  void SetValidatedType(CompositionType type) {
     validated_type_ = type;
   }
   bool IsTypeChanged() const {
@@ -106,8 +112,8 @@ class HwcLayer {
  private:
   // sf_type_ stores the initial type given to us by surfaceflinger,
   // validated_type_ stores the type after running ValidateDisplay
-  HWC2::Composition sf_type_ = HWC2::Composition::Invalid;
-  HWC2::Composition validated_type_ = HWC2::Composition::Invalid;
+  CompositionType sf_type_ = CompositionType::kInvalid;
+  CompositionType validated_type_ = CompositionType::kInvalid;
 
   uint32_t z_order_ = 0;
   LayerData layer_data_;
@@ -122,7 +128,6 @@ class HwcLayer {
   BufferColorSpace color_space_{};
   BufferSampleRange sample_range_{};
   BufferBlendMode blend_mode_{};
-  bool buffer_updated_{};
 
   bool prior_buffer_scanout_flag_{};
 
@@ -137,17 +142,12 @@ class HwcLayer {
   };
   std::map<int32_t /*slot*/, BufferSlot> slots_;
 
-  void ImportFb();
-  bool fb_import_failed_{};
+  bool ImportFb(BufferSlot &slot) const;
 
  public:
   void PopulateLayerData();
   void ClearSlots();
-
-  bool IsLayerUsableAsDevice() const {
-    return !fb_import_failed_ && active_slot_id_.has_value() &&
-           slots_.count(*active_slot_id_) > 0;
-  }
+  bool IsLayerUsableAsDevice() const;
 };
 
 }  // namespace android
diff --git a/hwc/meson.build b/hwc/meson.build
new file mode 100644
index 0000000..08efe4e
--- /dev/null
+++ b/hwc/meson.build
@@ -0,0 +1,5 @@
+src_hwc = files(
+    'HwcDisplayConfigs.cpp',
+    'HwcDisplay.cpp',
+    'HwcLayer.cpp',
+)
diff --git a/hwc2_device/DrmHwcTwo.cpp b/hwc2_device/DrmHwcTwo.cpp
index b243199..98af8c8 100644
--- a/hwc2_device/DrmHwcTwo.cpp
+++ b/hwc2_device/DrmHwcTwo.cpp
@@ -68,7 +68,7 @@ HWC2::Error DrmHwcTwo::RegisterCallback(int32_t descriptor,
   return HWC2::Error::None;
 }
 
-void DrmHwcTwo::SendHotplugEventToClient(hwc2_display_t displayid,
+void DrmHwcTwo::SendHotplugEventToClient(DisplayHandle display_handle,
                                          DisplayStatus display_status) {
   auto hc = hotplug_callback_;
 
@@ -76,31 +76,31 @@ void DrmHwcTwo::SendHotplugEventToClient(hwc2_display_t displayid,
     /* For some reason HWC Service will call HWC2 API in hotplug callback
      * handler. This is the reason we're using recursive mutex.
      */
-    hc.first(hc.second, displayid,
+    hc.first(hc.second, display_handle,
              display_status ? HWC2_CONNECTION_CONNECTED
                             : HWC2_CONNECTION_DISCONNECTED);
   }
 }
 
 void DrmHwcTwo::SendVsyncEventToClient(
-    hwc2_display_t displayid, int64_t timestamp,
+    DisplayHandle display_handle, int64_t timestamp,
     [[maybe_unused]] uint32_t vsync_period) const {
   /* vsync callback */
 #if __ANDROID_API__ > 29
   if (vsync_2_4_callback_.first != nullptr &&
       vsync_2_4_callback_.second != nullptr) {
-    vsync_2_4_callback_.first(vsync_2_4_callback_.second, displayid, timestamp,
-                              vsync_period);
+    vsync_2_4_callback_.first(vsync_2_4_callback_.second, display_handle,
+                              timestamp, vsync_period);
   } else
 #endif
       if (vsync_callback_.first != nullptr &&
           vsync_callback_.second != nullptr) {
-    vsync_callback_.first(vsync_callback_.second, displayid, timestamp);
+    vsync_callback_.first(vsync_callback_.second, display_handle, timestamp);
   }
 }
 
 void DrmHwcTwo::SendVsyncPeriodTimingChangedEventToClient(
-    [[maybe_unused]] hwc2_display_t displayid,
+    [[maybe_unused]] DisplayHandle display_handle,
     [[maybe_unused]] int64_t timestamp) const {
 #if __ANDROID_API__ > 29
   hwc_vsync_period_change_timeline_t timeline = {
@@ -111,16 +111,22 @@ void DrmHwcTwo::SendVsyncPeriodTimingChangedEventToClient(
   if (period_timing_changed_callback_.first != nullptr &&
       period_timing_changed_callback_.second != nullptr) {
     period_timing_changed_callback_
-        .first(period_timing_changed_callback_.second, displayid, &timeline);
+        .first(period_timing_changed_callback_.second, display_handle,
+               &timeline);
   }
 #endif
 }
 
-void DrmHwcTwo::SendRefreshEventToClient(hwc2_display_t displayid) {
+void DrmHwcTwo::SendRefreshEventToClient(DisplayHandle display_handle) {
   if (refresh_callback_.first != nullptr &&
       refresh_callback_.second != nullptr) {
-    refresh_callback_.first(refresh_callback_.second, displayid);
+    refresh_callback_.first(refresh_callback_.second, display_handle);
   }
 }
 
+const std::string& DrmHwcTwo::RefreshStateDump() {
+  last_state_dump_ = DumpState();
+  return last_state_dump_;
+}
+
 }  // namespace android
diff --git a/hwc2_device/DrmHwcTwo.h b/hwc2_device/DrmHwcTwo.h
index ac87153..bef88c6 100644
--- a/hwc2_device/DrmHwcTwo.h
+++ b/hwc2_device/DrmHwcTwo.h
@@ -31,14 +31,19 @@ class DrmHwcTwo : public DrmHwc {
                                hwc2_function_pointer_t function);
 
   // DrmHwc
-  void SendVsyncEventToClient(hwc2_display_t displayid, int64_t timestamp,
+  void SendVsyncEventToClient(DisplayHandle display_handle, int64_t timestamp,
                               uint32_t vsync_period) const override;
   void SendVsyncPeriodTimingChangedEventToClient(
-      hwc2_display_t displayid, int64_t timestamp) const override;
-  void SendRefreshEventToClient(uint64_t displayid) override;
-  void SendHotplugEventToClient(hwc2_display_t displayid,
+      DisplayHandle display_handle, int64_t timestamp) const override;
+  void SendRefreshEventToClient(DisplayHandle display_handle) override;
+  void SendHotplugEventToClient(DisplayHandle display_handle,
                                 DisplayStatus display_status) override;
 
+  const std::string& RefreshStateDump();
+  const std::string& GetLastStateDump() const {
+    return last_state_dump_;
+  }
+
  private:
   std::pair<HWC2_PFN_HOTPLUG, hwc2_callback_data_t> hotplug_callback_{};
   std::pair<HWC2_PFN_VSYNC, hwc2_callback_data_t> vsync_callback_{};
@@ -48,5 +53,7 @@ class DrmHwcTwo : public DrmHwc {
       period_timing_changed_callback_{};
 #endif
   std::pair<HWC2_PFN_REFRESH, hwc2_callback_data_t> refresh_callback_{};
+
+  std::string last_state_dump_;
 };
 }  // namespace android
diff --git a/hwc2_device/hwc2_device.cpp b/hwc2_device/hwc2_device.cpp
index 7c9d806..29d64e0 100644
--- a/hwc2_device/hwc2_device.cpp
+++ b/hwc2_device/hwc2_device.cpp
@@ -17,6 +17,7 @@
 // NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
 // #define LOG_NDEBUG 0 // Uncomment to see HWC2 API calls in logcat
 
+#include "system/graphics-base-v1.1.h"
 #define LOG_TAG "drmhwc"
 
 #include <cassert>
@@ -28,11 +29,27 @@
 
 #include "DrmHwcTwo.h"
 #include "backend/Backend.h"
-#include "hwc2_device/HwcLayer.h"
+#include "compositor/DisplayInfo.h"
+#include "hwc/HwcLayer.h"
 #include "utils/log.h"
 
 namespace android {
 
+static int32_t ConfigErrorToHWC2(HwcDisplay::ConfigError result) {
+  switch (result) {
+    case HwcDisplay::ConfigError::kBadConfig:
+      return static_cast<int32_t>(HWC2::Error::BadConfig);
+    case HwcDisplay::ConfigError::kSeamlessNotAllowed:
+      return static_cast<int32_t>(HWC2::Error::SeamlessNotAllowed);
+    case HwcDisplay::ConfigError::kSeamlessNotPossible:
+      return static_cast<int32_t>(HWC2::Error::SeamlessNotPossible);
+    case HwcDisplay::ConfigError::kConfigFailed:
+      return static_cast<int32_t>(HWC2::Error::BadConfig);
+    case HwcDisplay::ConfigError::kNone:
+      return static_cast<int32_t>(HWC2::Error::None);
+  }
+}
+
 /* Converts long __PRETTY_FUNCTION__ result, e.g.:
  * "int32_t android::LayerHook(hwc2_device_t *, hwc2_display_t, hwc2_layer_t,"
  * "Args...) [HookType = HWC2::Error (android::HwcLayer::*)(const native_handle"
@@ -203,7 +220,7 @@ static int32_t DisplayHook(hwc2_device_t *dev, hwc2_display_t display_handle,
         GetFuncName(__PRETTY_FUNCTION__).c_str());
   DrmHwcTwo *hwc = ToDrmHwcTwo(dev);
   const std::unique_lock lock(hwc->GetResMan().GetMainLock());
-  auto *display = hwc->GetDisplay(display_handle);
+  auto *display = hwc->GetDisplay(static_cast<DisplayHandle>(display_handle));
   if (display == nullptr)
     return static_cast<int32_t>(HWC2::Error::BadDisplay);
 
@@ -228,9 +245,9 @@ static void HookDevGetCapabilities(hwc2_device_t * /*dev*/, uint32_t *out_count,
   auto *ihwc = ToDrmHwcTwo(dev); \
   const std::unique_lock lock(ihwc->GetResMan().GetMainLock());
 
-#define GET_DISPLAY(display_id)                  \
-  auto *idisplay = ihwc->GetDisplay(display_id); \
-  if (!idisplay)                                 \
+#define GET_DISPLAY(display_handle)                  \
+  auto *idisplay = ihwc->GetDisplay(display_handle); \
+  if (!idisplay)                                     \
     return static_cast<int32_t>(HWC2::Error::BadDisplay);
 
 #define GET_LAYER(layer_id)                     \
@@ -268,6 +285,57 @@ static BufferSampleRange Hwc2ToSampleRange(int32_t dataspace) {
   }
 }
 
+/* Device functions */
+static int32_t Dump(hwc2_device_t *device, uint32_t *out_size,
+                    char *out_buffer) {
+  DrmHwcTwo *hwc = ToDrmHwcTwo(device);
+  if (out_size == nullptr) {
+    return static_cast<int32_t>(HWC2::Error::BadParameter);
+  }
+
+  if (out_buffer != nullptr) {
+    const std::string &last_dump = hwc->GetLastStateDump();
+    auto copied_bytes = last_dump.copy(out_buffer, *out_size);
+    *out_size = copied_bytes;
+    return 0;
+  }
+
+  const std::string &new_dump = hwc->RefreshStateDump();
+  *out_size = static_cast<uint32_t>(new_dump.size());
+  return 0;
+}
+
+static int32_t CreateVirtualDisplay(hwc2_device_t *device, uint32_t width,
+                                    uint32_t height, int32_t * /*format*/,
+                                    hwc2_display_t *out_display_handle) {
+  ALOGV("CreateVirtualDisplay");
+  LOCK_COMPOSER(device);
+  auto display_handle = ihwc->CreateVirtualDisplay(width, height);
+  if (!display_handle) {
+    return static_cast<int32_t>(HWC2::Error::Unsupported);
+  }
+
+  *out_display_handle = display_handle.value();
+  return 0;
+}
+
+static int32_t DestroyVirtualDisplay(hwc2_device_t *device,
+                                     hwc2_display_t display) {
+  ALOGV("DestroyVirtualDisplay");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+  if (!ihwc->DestroyVirtualDisplay(static_cast<DisplayHandle>(display))) {
+    return static_cast<int32_t>(HWC2::Error::BadParameter);
+  }
+  return 0;
+}
+
+static int32_t GetMaxVirtualDisplayCount(hwc2_device_t *device) {
+  ALOGV("GetMaxVirtualDisplayCount");
+  LOCK_COMPOSER(device);
+  return static_cast<int32_t>(ihwc->GetMaxVirtualDisplayCount());
+}
+
 /* Display functions */
 static int32_t CreateLayer(hwc2_device_t *device, hwc2_display_t display,
                            hwc2_layer_t *out_layer) {
@@ -300,6 +368,21 @@ static int32_t DestroyLayer(hwc2_device_t *device, hwc2_display_t display,
   return 0;
 }
 
+static int32_t GetActiveConfig(hwc2_device_t *device, hwc2_display_t display,
+                               hwc2_config_t *config) {
+  ALOGV("GetActiveConfig");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  // If a config has been queued, it is considered the "active" config.
+  const HwcDisplayConfig *hwc_config = idisplay->GetLastRequestedConfig();
+  if (hwc_config == nullptr)
+    return static_cast<int32_t>(HWC2::Error::BadConfig);
+
+  *config = hwc_config->id;
+  return 0;
+}
+
 static int32_t GetDisplayRequests(hwc2_device_t * /*device*/,
                                   hwc2_display_t /*display*/,
                                   int32_t * /* out_display_requests */,
@@ -312,6 +395,24 @@ static int32_t GetDisplayRequests(hwc2_device_t * /*device*/,
   return 0;
 }
 
+static int32_t GetDisplayType(hwc2_device_t *device, hwc2_display_t display,
+                              int32_t *out_type) {
+  ALOGV("GetDisplayType");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  switch (idisplay->GetDisplayType()) {
+    case HwcDisplay::DisplayType::kVirtual:
+      *out_type = static_cast<int32_t>(HWC2::DisplayType::Virtual);
+      break;
+    case HwcDisplay::DisplayType::kInternal:
+    case HwcDisplay::DisplayType::kExternal:
+      *out_type = static_cast<int32_t>(HWC2::DisplayType::Physical);
+      break;
+  }
+  return 0;
+}
+
 static int32_t GetDozeSupport(hwc2_device_t * /*device*/,
                               hwc2_display_t /*display*/,
                               int32_t *out_support) {
@@ -370,6 +471,192 @@ static int32_t SetClientTarget(hwc2_device_t *device, hwc2_display_t display,
   return 0;
 }
 
+static int32_t GetColorModes(hwc2_device_t *device, hwc2_display_t display,
+                             uint32_t *num_modes, int32_t *out_modes) {
+  ALOGV("GetColorModes");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  const std::vector<ColorMode> modes = idisplay->GetColorModes();
+  if (modes.empty())
+    return static_cast<int32_t>(HWC2::Error::BadConfig);
+
+  for (uint32_t i = 0; i < modes.size(); ++i) {
+    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic):
+    out_modes[i] = static_cast<int32_t>(modes[i]);
+  }
+  *num_modes = modes.size();
+  return 0;
+}
+
+static int32_t GetDisplayAttribute(hwc2_device_t *device,
+                                   hwc2_display_t display, hwc2_config_t config,
+                                   int32_t attribute, int32_t *value) {
+  ALOGV("GetDisplayAttribute");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  const auto *hwc_config = idisplay->GetConfig(static_cast<ConfigId>(config));
+
+  if (hwc_config == nullptr) {
+    ALOGE("Could not find mode #%d", config);
+    return static_cast<int32_t>(HWC2::Error::BadConfig);
+  }
+
+  int mm_width = -1;
+  int mm_height = -1;
+  std::tie(mm_width, mm_height) = idisplay->GetDisplayBoundsMm();
+  std::optional<std::pair<float, float>> dpi_inches = {};
+
+  if (mm_width > 0) {
+    static const float kMmPerInch = 25.4;
+    float dpi_x = float(hwc_config->mode.GetRawMode().hdisplay) * kMmPerInch /
+                  float(mm_width);
+    float dpi_y = mm_height <= 0
+                      ? dpi_x
+                      : float(hwc_config->mode.GetRawMode().vdisplay) *
+                            kMmPerInch / float(mm_height);
+    dpi_inches = std::make_pair(dpi_x, dpi_y);
+  }
+
+  static const int kLegacyDpiUnit = 1000;
+  switch (static_cast<HWC2::Attribute>(attribute)) {
+    case HWC2::Attribute::Width:
+      *value = static_cast<int>(hwc_config->mode.GetRawMode().hdisplay);
+      break;
+    case HWC2::Attribute::Height:
+      *value = static_cast<int>(hwc_config->mode.GetRawMode().vdisplay);
+      break;
+    case HWC2::Attribute::VsyncPeriod:
+      // in nanoseconds
+      *value = hwc_config->mode.GetVSyncPeriodNs();
+      break;
+    case HWC2::Attribute::DpiY:
+      *value = dpi_inches
+                   ? static_cast<int>(dpi_inches->second * kLegacyDpiUnit)
+                   : -1;
+      break;
+    case HWC2::Attribute::DpiX:
+      *value = dpi_inches ? static_cast<int>(dpi_inches->first * kLegacyDpiUnit)
+                          : -1;
+      break;
+#if __ANDROID_API__ > 29
+    case HWC2::Attribute::ConfigGroup:
+      /* Dispite ConfigGroup is a part of HWC2.4 API, framework
+       * able to request it even if service @2.1 is used */
+      *value = int(hwc_config->group_id);
+      break;
+#endif
+    default:
+      *value = -1;
+      return static_cast<int32_t>(HWC2::Error::BadConfig);
+  }
+  return 0;
+}
+
+static int32_t GetDisplayConfigs(hwc2_device_t *device, hwc2_display_t display,
+                                 uint32_t *num_configs,
+                                 hwc2_config_t *configs) {
+  ALOGV("GetDisplayConfigs");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  uint32_t idx = 0;
+  for (const auto &hwc_config : idisplay->GetDisplayConfigs().hwc_configs) {
+    if (hwc_config.second.disabled) {
+      continue;
+    }
+
+    if (configs != nullptr) {
+      if (idx >= *num_configs) {
+        break;
+      }
+      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic):
+      configs[idx] = hwc_config.second.id;
+    }
+
+    idx++;
+  }
+  *num_configs = idx;
+  return 0;
+}
+
+static int32_t GetDisplayName(hwc2_device_t *device, hwc2_display_t display,
+                              uint32_t *size, char *name) {
+  ALOGV("GetDisplayName");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  std::string name_str = idisplay->GetDisplayName();
+
+  auto length = name_str.length();
+  if (name == nullptr) {
+    *size = length;
+    return 0;
+  }
+
+  *size = std::min<uint32_t>(static_cast<uint32_t>(length - 1), *size);
+  strncpy(name, name_str.c_str(), *size);
+  return 0;
+}
+
+static int32_t SetColorMode(hwc2_device_t *device, hwc2_display_t display, int32_t mode) {
+  ALOGV("SetColorMode");
+  if (mode < HAL_COLOR_MODE_NATIVE || mode > HAL_COLOR_MODE_DISPLAY_BT2020)
+    return static_cast<int32_t>(HWC2::Error::BadParameter);
+
+  // HDR color modes should be requested during modeset
+  if (mode == HAL_COLOR_MODE_DISPLAY_BT2020 ||
+      mode == HAL_COLOR_MODE_ADOBE_RGB ||
+      mode == HAL_COLOR_MODE_BT2020 ||
+      mode == HAL_COLOR_MODE_BT2100_PQ ||
+      mode == HAL_COLOR_MODE_BT2100_HLG) {
+    return static_cast<int32_t>(HWC2::Error::Unsupported);
+  }
+
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  // Values for color modes match across HWC versions, so static cast is safe:
+  // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/ColorMode.aidl
+  // https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.0.h;drc=7d940ae4afa450696afa25e07982f3a95e17e9b2;l=118
+  // https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.1.h;drc=7d940ae4afa450696afa25e07982f3a95e17e9b2;l=35
+  idisplay->SetColorMode(static_cast<ColorMode>(mode));
+  return 0;
+}
+
+static int32_t SetColorTransform(hwc2_device_t *device, hwc2_display_t display,
+                                 const float *matrix, int32_t hint) {
+  ALOGV("SetColorTransform");
+  if (hint < HAL_COLOR_TRANSFORM_IDENTITY ||
+      hint > HAL_COLOR_TRANSFORM_CORRECT_TRITANOPIA) {
+    return static_cast<int32_t>(HWC2::Error::BadParameter);
+  }
+
+  if (hint != HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX &&
+      hint != HAL_COLOR_TRANSFORM_IDENTITY) {
+    return static_cast<int32_t>(HWC2::Error::Unsupported);
+  }
+
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  if (matrix == nullptr) {
+    if (hint == HAL_COLOR_TRANSFORM_IDENTITY) {
+      idisplay->SetColorTransformMatrix(kIdentityMatrix);
+      return 0;
+    }
+
+    return static_cast<int32_t>(HWC2::Error::BadParameter);
+  }
+
+  std::array<float, kColorMatrixSize> aidl_matrix = kIdentityMatrix;
+  memcpy(aidl_matrix.data(), matrix, aidl_matrix.size() * sizeof(float));
+  idisplay->SetColorTransformMatrix(aidl_matrix);
+
+  return 0;
+}
+
 static int32_t SetOutputBuffer(hwc2_device_t *device, hwc2_display_t display,
                                buffer_handle_t buffer, int32_t release_fence) {
   ALOGV("SetOutputBuffer");
@@ -414,6 +701,40 @@ static int32_t AcceptDisplayChanges(hwc2_device_t *device,
   return 0;
 }
 
+static int32_t GetHdrCapabilities(hwc2_device_t *device, hwc2_display_t display,
+                                  uint32_t *num_types, int32_t *types,
+                                  float *max_luminance,
+                                  float *max_average_luminance,
+                                  float *min_luminance) {
+  ALOGV("GetHdrCapabilities");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  std::vector<ui::Hdr> temp_types;
+  idisplay->GetHdrCapabilities(&temp_types, max_luminance,
+                               max_average_luminance, min_luminance);
+  uint32_t i = 0;
+  for (auto &t : temp_types) {
+    switch (t) {
+      case ui::Hdr::HDR10:
+        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic):
+        types[i++] = HAL_HDR_HDR10;
+        break;
+      case ui::Hdr::HLG:
+        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic):
+        types[i++] = HAL_HDR_HLG;
+        break;
+      default:
+        // Ignore any other HDR types
+        break;
+    }
+  }
+
+  *num_types = i;
+
+  return 0;
+}
+
 static int32_t GetReleaseFences(hwc2_device_t *device, hwc2_display_t display,
                                 uint32_t *out_num_elements,
                                 hwc2_layer_t *out_layers, int32_t *out_fences) {
@@ -442,6 +763,43 @@ static int32_t GetReleaseFences(hwc2_device_t *device, hwc2_display_t display,
   return static_cast<int32_t>(HWC2::Error::None);
 }
 
+static int32_t SetPowerMode(hwc2_device_t *device, hwc2_display_t display,
+                            int32_t mode) {
+  ALOGV("SetPowerMode");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  switch (mode) {
+    // Supported modes.
+    case static_cast<int32_t>(HWC2::PowerMode::Off):
+    case static_cast<int32_t>(HWC2::PowerMode::On):
+      break;
+    // Unsupported modes.
+    case static_cast<int32_t>(HWC2::PowerMode::Doze):
+    case static_cast<int32_t>(HWC2::PowerMode::DozeSuspend):
+      return static_cast<int32_t>(HWC2::Error::Unsupported);
+    // Bad parameter.
+    default:
+      ALOGE("Incorrect power mode value (%d)\n", mode);
+      return static_cast<int32_t>(HWC2::Error::BadParameter);
+  }
+
+  if (!idisplay->SetDisplayEnabled(mode ==
+                                   static_cast<int32_t>(HWC2::PowerMode::On))) {
+    return static_cast<int32_t>(HWC2::Error::BadParameter);
+  }
+  return static_cast<int32_t>(HWC2::Error::None);
+}
+
+static int32_t SetVsyncEnabled(hwc2_device_t *device, hwc2_display_t display,
+                               int32_t enabled) {
+  ALOGV("SetVsyncEnabled");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+  idisplay->SetVsyncCallbacksEnabled(HWC2_VSYNC_ENABLE == enabled);
+  return static_cast<int32_t>(HWC2::Error::None);
+}
+
 static int32_t ValidateDisplay(hwc2_device_t *device, hwc2_display_t display,
                                uint32_t *out_num_types,
                                uint32_t *out_num_requests) {
@@ -512,6 +870,19 @@ static int32_t PresentDisplay(hwc2_device_t *device, hwc2_display_t display,
   return 0;
 }
 
+static int32_t SetActiveConfig(hwc2_device_t *device, hwc2_display_t display,
+                               hwc2_config_t config) {
+  ALOGV("SetActiveConfig");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  QueuedConfigTiming out_timing{};
+  auto result = idisplay->QueueConfig(static_cast<ConfigId>(config),
+                                      ResourceManager::GetTimeMonotonicNs(),
+                                      false, &out_timing);
+  return ConfigErrorToHWC2(result);
+}
+
 #if __ANDROID_API__ >= 28
 
 static int32_t GetDisplayBrightnessSupport(hwc2_device_t * /*device*/,
@@ -529,9 +900,154 @@ static int32_t SetDisplayBrightness(hwc2_device_t * /*device*/,
   return static_cast<int32_t>(HWC2::Error::Unsupported);
 }
 
+static int32_t GetRenderIntents(hwc2_device_t * /*device*/,
+                                hwc2_display_t /*display*/, int32_t mode,
+                                uint32_t *num_intents, int32_t *intents) {
+  ALOGV("GetRenderIntents");
+
+  if (mode < HAL_COLOR_MODE_NATIVE || mode > HAL_COLOR_MODE_DISPLAY_BT2020)
+    return static_cast<int32_t>(HWC2::Error::BadParameter);
+
+  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic):
+  intents[0] = static_cast<int32_t>(HAL_RENDER_INTENT_COLORIMETRIC);
+  *num_intents = 1;
+
+  return 0;
+}
+
+static int32_t SetColorModeWithRenderIntent(hwc2_device_t *device,
+                                            hwc2_display_t display,
+                                            int32_t mode, int32_t intent) {
+  ALOGV("SetColorModeWithRenderIntent");
+  if (mode < HAL_RENDER_INTENT_COLORIMETRIC ||
+      mode > HAL_RENDER_INTENT_TONE_MAP_ENHANCE) {
+    return static_cast<int32_t>(HWC2::Error::BadParameter);
+  }
+
+  if (intent != HAL_RENDER_INTENT_COLORIMETRIC)
+    return static_cast<int32_t>(HWC2::Error::Unsupported);
+
+  return SetColorMode(device, display, mode);
+}
+
+static int32_t GetDisplayIdentificationData(hwc2_device_t *device,
+                                            hwc2_display_t display,
+                                            uint8_t *out_port,
+                                            uint32_t *out_data_size,
+                                            uint8_t *out_data) {
+  ALOGV("GetDisplayIdentificationData");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  auto edid = idisplay->GetRawEdid();
+  if (edid.empty()) {
+    return static_cast<int32_t>(HWC2::Error::Unsupported);
+  }
+
+  *out_port = idisplay->GetPort();
+
+  if (out_data != nullptr) {
+    *out_data_size = std::min(*out_data_size,
+                              static_cast<uint32_t>(edid.size()));
+    memcpy(out_data, edid.data(), *out_data_size);
+  } else {
+    *out_data_size = edid.size();
+  }
+
+  return static_cast<int32_t>(HWC2::Error::None);
+}
+
+static int32_t GetDisplayCapabilities(hwc2_device_t *device,
+                                      hwc2_display_t display,
+                                      uint32_t *out_num_capabilities,
+                                      uint32_t *out_capabilities) {
+  ALOGV("GetDisplayCapabilities");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  if (out_num_capabilities == nullptr) {
+    return static_cast<int32_t>(HWC2::Error::BadParameter);
+  }
+
+  if (ihwc->GetResMan().GetCtmHandling() == CtmHandling::kDrmOrIgnore) {
+    if (out_capabilities != nullptr && *out_num_capabilities > 0) {
+      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic):
+      out_capabilities[0] = HWC2_DISPLAY_CAPABILITY_SKIP_CLIENT_COLOR_TRANSFORM;
+    }
+    *out_num_capabilities = 1;
+  }
+
+  return static_cast<int32_t>(HWC2::Error::None);
+}
+
 #endif
 
 #if __ANDROID_API__ >= 29
+static int32_t GetDisplayConnectionType(hwc2_device_t *device,
+                                        hwc2_display_t display,
+                                        int32_t *out_connection_type) {
+  ALOGV("GetDisplayConnectionType");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  switch (idisplay->GetDisplayType()) {
+    case HwcDisplay::DisplayType::kVirtual:
+      return static_cast<int32_t>(HWC2::Error::BadDisplay);
+    case HwcDisplay::DisplayType::kInternal:
+      *out_connection_type = static_cast<int32_t>(
+          HWC2::DisplayConnectionType::Internal);
+      break;
+    case HwcDisplay::DisplayType::kExternal:
+      *out_connection_type = static_cast<int32_t>(
+          HWC2::DisplayConnectionType::External);
+      break;
+  }
+  return 0;
+}
+
+static int32_t GetDisplayVsyncPeriod(hwc2_device_t *device,
+                                     hwc2_display_t display,
+                                     hwc2_vsync_period_t *out_vsync_period) {
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  const HwcDisplayConfig *config = idisplay->GetCurrentConfig();
+  if (config == nullptr) {
+    return static_cast<int32_t>(HWC2::Error::BadConfig);
+  }
+
+  *out_vsync_period = config->mode.GetVSyncPeriodNs();
+  return static_cast<int32_t>(HWC2::Error::None);
+}
+
+static int32_t SetActiveConfigWithConstraints(
+    hwc2_device_t *device, hwc2_display_t display, hwc2_config_t config,
+    hwc_vsync_period_change_constraints_t *vsync_period_change_constraints,
+    hwc_vsync_period_change_timeline_t *out_timeline) {
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  if (vsync_period_change_constraints == nullptr || out_timeline == nullptr) {
+    return static_cast<int32_t>(HWC2::Error::BadParameter);
+  }
+
+  if (vsync_period_change_constraints->seamlessRequired != 0) {
+    return static_cast<int32_t>(HWC2::Error::SeamlessNotAllowed);
+  }
+
+  QueuedConfigTiming out_timing{};
+  auto result = idisplay->QueueConfig(static_cast<ConfigId>(config),
+                                      vsync_period_change_constraints
+                                          ->desiredTimeNanos,
+                                      false, &out_timing);
+
+  out_timeline->newVsyncAppliedTimeNanos = out_timing.new_vsync_time_ns;
+  out_timeline->refreshTimeNanos = out_timing.refresh_time_ns;
+  out_timeline->refreshRequired = 1;
+
+  return ConfigErrorToHWC2(result);
+}
+
 static int32_t SetAutoLowLatencyMode(hwc2_device_t * /*device*/,
                                      hwc2_display_t /*display*/, bool /*on*/) {
   ALOGV("SetAutoLowLatencyMode");
@@ -546,6 +1062,22 @@ static int32_t GetSupportedContentTypes(
   *out_num_supported_content_types = 0;
   return static_cast<int32_t>(HWC2::Error::None);
 }
+
+static int32_t SetContentType(hwc2_device_t *device, hwc2_display_t display,
+                              int32_t content_type) {
+  ALOGV("SetContentType");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+
+  if (content_type < HWC2_CONTENT_TYPE_NONE ||
+      content_type > HWC2_CONTENT_TYPE_GAME) {
+    return static_cast<int32_t>(HWC2::Error::BadParameter);
+  }
+
+  idisplay->SetContentType(static_cast<ContentType>(content_type));
+
+  return static_cast<int32_t>(HWC2::Error::None);
+}
 #endif
 
 /* Layer functions */
@@ -648,7 +1180,24 @@ static int32_t SetLayerCompositionType(hwc2_device_t *device,
   GET_LAYER(layer);
 
   HwcLayer::LayerProperties layer_properties;
-  layer_properties.composition_type = static_cast<HWC2::Composition>(type);
+  switch (static_cast<HWC2::Composition>(type)) {
+    case HWC2::Composition::Client:
+      layer_properties.composition_type = HwcLayer::CompositionType::kClient;
+      break;
+    case HWC2::Composition::Device:
+      layer_properties.composition_type = HwcLayer::CompositionType::kDevice;
+      break;
+    case HWC2::Composition::SolidColor:
+      layer_properties
+          .composition_type = HwcLayer::CompositionType::kSolidColor;
+      break;
+    case HWC2::Composition::Cursor:
+      layer_properties.composition_type = HwcLayer::CompositionType::kCursor;
+      break;
+    default:
+      ALOGE("Unsupported composition type t=%d", type);
+      break;
+  }
   ilayer->SetLayerProperties(layer_properties);
 
   return 0;
@@ -663,11 +1212,10 @@ static int32_t SetLayerDisplayFrame(hwc2_device_t *device,
   GET_LAYER(layer);
 
   HwcLayer::LayerProperties layer_properties;
-  layer_properties.display_frame = {
-      .i_rect = DstRectInfo::IRect{.left = frame.left,
-                                   .top = frame.top,
-                                   .right = frame.right,
-                                   .bottom = frame.bottom}};
+  layer_properties.display_frame = {.i_rect = IRect{.left = frame.left,
+                                                    .top = frame.top,
+                                                    .right = frame.right,
+                                                    .bottom = frame.bottom}};
   ilayer->SetLayerProperties(layer_properties);
 
   return 0;
@@ -713,11 +1261,26 @@ static int32_t SetLayerSourceCrop(hwc2_device_t *device, hwc2_display_t display,
   return 0;
 }
 
-static int32_t SetLayerSurfaceDamage(hwc2_device_t * /*device*/,
-                                     hwc2_display_t /*display*/,
-                                     hwc2_layer_t /*layer*/,
-                                     hwc_region_t /*damage*/) {
+static int32_t SetLayerSurfaceDamage(hwc2_device_t *device,
+                                     hwc2_display_t display, hwc2_layer_t layer,
+                                     hwc_region_t damage) {
   ALOGV("SetLayerSurfaceDamage");
+  LOCK_COMPOSER(device);
+  GET_DISPLAY(display);
+  GET_LAYER(layer);
+
+  HwcLayer::LayerProperties layer_properties{.damage = DamageInfo{}};
+  for (size_t i = 0; i < damage.numRects; ++i) {
+    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
+    const auto rect = damage.rects[i];
+    layer_properties.damage->dmg_rects.emplace_back(
+        IRect{.left = rect.left,
+              .top = rect.top,
+              .right = rect.right,
+              .bottom = rect.bottom});
+  }
+  ilayer->SetLayerProperties(layer_properties);
+
   return 0;
 }
 
@@ -770,22 +1333,13 @@ static hwc2_function_pointer_t HookDevGetFunction(struct hwc2_device * /*dev*/,
   switch (func) {
     // Device functions
     case HWC2::FunctionDescriptor::CreateVirtualDisplay:
-      return ToHook<HWC2_PFN_CREATE_VIRTUAL_DISPLAY>(
-          DeviceHook<int32_t, decltype(&DrmHwcTwo::CreateVirtualDisplay),
-                     &DrmHwcTwo::CreateVirtualDisplay, uint32_t, uint32_t,
-                     int32_t *, hwc2_display_t *>);
+      return (hwc2_function_pointer_t)CreateVirtualDisplay;
     case HWC2::FunctionDescriptor::DestroyVirtualDisplay:
-      return ToHook<HWC2_PFN_DESTROY_VIRTUAL_DISPLAY>(
-          DeviceHook<int32_t, decltype(&DrmHwcTwo::DestroyVirtualDisplay),
-                     &DrmHwcTwo::DestroyVirtualDisplay, hwc2_display_t>);
+      return (hwc2_function_pointer_t)DestroyVirtualDisplay;
     case HWC2::FunctionDescriptor::Dump:
-      return ToHook<HWC2_PFN_DUMP>(
-          DeviceHook<void, decltype(&DrmHwcTwo::Dump), &DrmHwcTwo::Dump,
-                     uint32_t *, char *>);
+      return (hwc2_function_pointer_t)Dump;
     case HWC2::FunctionDescriptor::GetMaxVirtualDisplayCount:
-      return ToHook<HWC2_PFN_GET_MAX_VIRTUAL_DISPLAY_COUNT>(
-          DeviceHook<uint32_t, decltype(&DrmHwcTwo::GetMaxVirtualDisplayCount),
-                     &DrmHwcTwo::GetMaxVirtualDisplayCount>);
+      return (hwc2_function_pointer_t)GetMaxVirtualDisplayCount;
     case HWC2::FunctionDescriptor::RegisterCallback:
       return ToHook<HWC2_PFN_REGISTER_CALLBACK>(
           DeviceHook<int32_t, decltype(&DrmHwcTwo::RegisterCallback),
@@ -800,96 +1354,58 @@ static hwc2_function_pointer_t HookDevGetFunction(struct hwc2_device * /*dev*/,
     case HWC2::FunctionDescriptor::DestroyLayer:
       return (hwc2_function_pointer_t)DestroyLayer;
     case HWC2::FunctionDescriptor::GetActiveConfig:
-      return ToHook<HWC2_PFN_GET_ACTIVE_CONFIG>(
-          DisplayHook<decltype(&HwcDisplay::GetActiveConfig),
-                      &HwcDisplay::GetActiveConfig, hwc2_config_t *>);
+      return (hwc2_function_pointer_t)GetActiveConfig;
     case HWC2::FunctionDescriptor::GetChangedCompositionTypes:
       return (hwc2_function_pointer_t)GetChangedCompositionTypes;
     case HWC2::FunctionDescriptor::GetClientTargetSupport:
       return (hwc2_function_pointer_t)GetClientTargetSupport;
     case HWC2::FunctionDescriptor::GetColorModes:
-      return ToHook<HWC2_PFN_GET_COLOR_MODES>(
-          DisplayHook<decltype(&HwcDisplay::GetColorModes),
-                      &HwcDisplay::GetColorModes, uint32_t *, int32_t *>);
+      return (hwc2_function_pointer_t)GetColorModes;
     case HWC2::FunctionDescriptor::GetDisplayAttribute:
-      return ToHook<HWC2_PFN_GET_DISPLAY_ATTRIBUTE>(
-          DisplayHook<decltype(&HwcDisplay::GetDisplayAttribute),
-                      &HwcDisplay::GetDisplayAttribute, hwc2_config_t, int32_t,
-                      int32_t *>);
+      return (hwc2_function_pointer_t)GetDisplayAttribute;
     case HWC2::FunctionDescriptor::GetDisplayConfigs:
-      return ToHook<HWC2_PFN_GET_DISPLAY_CONFIGS>(
-          DisplayHook<decltype(&HwcDisplay::LegacyGetDisplayConfigs),
-                      &HwcDisplay::LegacyGetDisplayConfigs, uint32_t *,
-                      hwc2_config_t *>);
+      return (hwc2_function_pointer_t)GetDisplayConfigs;
     case HWC2::FunctionDescriptor::GetDisplayName:
-      return ToHook<HWC2_PFN_GET_DISPLAY_NAME>(
-          DisplayHook<decltype(&HwcDisplay::GetDisplayName),
-                      &HwcDisplay::GetDisplayName, uint32_t *, char *>);
+      return (hwc2_function_pointer_t)GetDisplayName;
     case HWC2::FunctionDescriptor::GetDisplayRequests:
       return (hwc2_function_pointer_t)GetDisplayRequests;
     case HWC2::FunctionDescriptor::GetDisplayType:
-      return ToHook<HWC2_PFN_GET_DISPLAY_TYPE>(
-          DisplayHook<decltype(&HwcDisplay::GetDisplayType),
-                      &HwcDisplay::GetDisplayType, int32_t *>);
+      return (hwc2_function_pointer_t)GetDisplayType;
     case HWC2::FunctionDescriptor::GetDozeSupport:
       return (hwc2_function_pointer_t)GetDozeSupport;
     case HWC2::FunctionDescriptor::GetHdrCapabilities:
-      return ToHook<HWC2_PFN_GET_HDR_CAPABILITIES>(
-          DisplayHook<decltype(&HwcDisplay::GetHdrCapabilities),
-                      &HwcDisplay::GetHdrCapabilities, uint32_t *, int32_t *,
-                      float *, float *, float *>);
+      return (hwc2_function_pointer_t)GetHdrCapabilities;
     case HWC2::FunctionDescriptor::GetReleaseFences:
       return (hwc2_function_pointer_t)GetReleaseFences;
     case HWC2::FunctionDescriptor::PresentDisplay:
       return (hwc2_function_pointer_t)PresentDisplay;
     case HWC2::FunctionDescriptor::SetActiveConfig:
-      return ToHook<HWC2_PFN_SET_ACTIVE_CONFIG>(
-          DisplayHook<decltype(&HwcDisplay::SetActiveConfig),
-                      &HwcDisplay::SetActiveConfig, hwc2_config_t>);
+      return (hwc2_function_pointer_t)SetActiveConfig;
     case HWC2::FunctionDescriptor::SetClientTarget:
       return (hwc2_function_pointer_t)SetClientTarget;
     case HWC2::FunctionDescriptor::SetColorMode:
-      return ToHook<HWC2_PFN_SET_COLOR_MODE>(
-          DisplayHook<decltype(&HwcDisplay::SetColorMode),
-                      &HwcDisplay::SetColorMode, int32_t>);
+      return (hwc2_function_pointer_t)SetColorMode;
     case HWC2::FunctionDescriptor::SetColorTransform:
-      return ToHook<HWC2_PFN_SET_COLOR_TRANSFORM>(
-          DisplayHook<decltype(&HwcDisplay::SetColorTransform),
-                      &HwcDisplay::SetColorTransform, const float *, int32_t>);
+      return (hwc2_function_pointer_t)SetColorTransform;
     case HWC2::FunctionDescriptor::SetOutputBuffer:
       return (hwc2_function_pointer_t)SetOutputBuffer;
     case HWC2::FunctionDescriptor::SetPowerMode:
-      return ToHook<HWC2_PFN_SET_POWER_MODE>(
-          DisplayHook<decltype(&HwcDisplay::SetPowerMode),
-                      &HwcDisplay::SetPowerMode, int32_t>);
+      return (hwc2_function_pointer_t)SetPowerMode;
     case HWC2::FunctionDescriptor::SetVsyncEnabled:
-      return ToHook<HWC2_PFN_SET_VSYNC_ENABLED>(
-          DisplayHook<decltype(&HwcDisplay::SetVsyncEnabled),
-                      &HwcDisplay::SetVsyncEnabled, int32_t>);
+      return (hwc2_function_pointer_t)SetVsyncEnabled;
     case HWC2::FunctionDescriptor::ValidateDisplay:
       return (hwc2_function_pointer_t)ValidateDisplay;
 #if __ANDROID_API__ > 27
     case HWC2::FunctionDescriptor::GetRenderIntents:
-      return ToHook<HWC2_PFN_GET_RENDER_INTENTS>(
-          DisplayHook<decltype(&HwcDisplay::GetRenderIntents),
-                      &HwcDisplay::GetRenderIntents, int32_t, uint32_t *,
-                      int32_t *>);
+      return (hwc2_function_pointer_t)GetRenderIntents;
     case HWC2::FunctionDescriptor::SetColorModeWithRenderIntent:
-      return ToHook<HWC2_PFN_SET_COLOR_MODE_WITH_RENDER_INTENT>(
-          DisplayHook<decltype(&HwcDisplay::SetColorModeWithIntent),
-                      &HwcDisplay::SetColorModeWithIntent, int32_t, int32_t>);
+      return (hwc2_function_pointer_t)SetColorModeWithRenderIntent;
 #endif
 #if __ANDROID_API__ > 28
     case HWC2::FunctionDescriptor::GetDisplayIdentificationData:
-      return ToHook<HWC2_PFN_GET_DISPLAY_IDENTIFICATION_DATA>(
-          DisplayHook<decltype(&HwcDisplay::GetDisplayIdentificationData),
-                      &HwcDisplay::GetDisplayIdentificationData, uint8_t *,
-                      uint32_t *, uint8_t *>);
+      return (hwc2_function_pointer_t)GetDisplayIdentificationData;
     case HWC2::FunctionDescriptor::GetDisplayCapabilities:
-      return ToHook<HWC2_PFN_GET_DISPLAY_CAPABILITIES>(
-          DisplayHook<decltype(&HwcDisplay::GetDisplayCapabilities),
-                      &HwcDisplay::GetDisplayCapabilities, uint32_t *,
-                      uint32_t *>);
+      return (hwc2_function_pointer_t)GetDisplayCapabilities;
     case HWC2::FunctionDescriptor::GetDisplayBrightnessSupport:
       return (hwc2_function_pointer_t)GetDisplayBrightnessSupport;
     case HWC2::FunctionDescriptor::SetDisplayBrightness:
@@ -897,28 +1413,17 @@ static hwc2_function_pointer_t HookDevGetFunction(struct hwc2_device * /*dev*/,
 #endif /* __ANDROID_API__ > 28 */
 #if __ANDROID_API__ > 29
     case HWC2::FunctionDescriptor::GetDisplayConnectionType:
-      return ToHook<HWC2_PFN_GET_DISPLAY_CONNECTION_TYPE>(
-          DisplayHook<decltype(&HwcDisplay::GetDisplayConnectionType),
-                      &HwcDisplay::GetDisplayConnectionType, uint32_t *>);
+      return (hwc2_function_pointer_t)GetDisplayConnectionType;
     case HWC2::FunctionDescriptor::GetDisplayVsyncPeriod:
-      return ToHook<HWC2_PFN_GET_DISPLAY_VSYNC_PERIOD>(
-          DisplayHook<decltype(&HwcDisplay::GetDisplayVsyncPeriod),
-                      &HwcDisplay::GetDisplayVsyncPeriod,
-                      hwc2_vsync_period_t *>);
+      return (hwc2_function_pointer_t)GetDisplayVsyncPeriod;
     case HWC2::FunctionDescriptor::SetActiveConfigWithConstraints:
-      return ToHook<HWC2_PFN_SET_ACTIVE_CONFIG_WITH_CONSTRAINTS>(
-          DisplayHook<decltype(&HwcDisplay::SetActiveConfigWithConstraints),
-                      &HwcDisplay::SetActiveConfigWithConstraints,
-                      hwc2_config_t, hwc_vsync_period_change_constraints_t *,
-                      hwc_vsync_period_change_timeline_t *>);
+      return (hwc2_function_pointer_t)SetActiveConfigWithConstraints;
     case HWC2::FunctionDescriptor::SetAutoLowLatencyMode:
       return (hwc2_function_pointer_t)SetAutoLowLatencyMode;
     case HWC2::FunctionDescriptor::GetSupportedContentTypes:
       return (hwc2_function_pointer_t)GetSupportedContentTypes;
     case HWC2::FunctionDescriptor::SetContentType:
-      return ToHook<HWC2_PFN_SET_CONTENT_TYPE>(
-          DisplayHook<decltype(&HwcDisplay::SetContentType),
-                      &HwcDisplay::SetContentType, int32_t>);
+      return (hwc2_function_pointer_t)SetContentType;
 #endif
     // Layer functions
     case HWC2::FunctionDescriptor::SetCursorPosition:
diff --git a/hwc2_device/meson.build b/hwc2_device/meson.build
index 6a9a93a..335fb25 100644
--- a/hwc2_device/meson.build
+++ b/hwc2_device/meson.build
@@ -1,9 +1,6 @@
 src_hwc2_device = files(
     'hwc2_device.cpp',
     'DrmHwcTwo.cpp',
-    'HwcDisplayConfigs.cpp',
-    'HwcDisplay.cpp',
-    'HwcLayer.cpp',
 )
 
 drmhwc_hwc2_common = static_library(
diff --git a/hwc3/CommandResultWriter.h b/hwc3/CommandResultWriter.h
index aae6817..3c0ccd7 100644
--- a/hwc3/CommandResultWriter.h
+++ b/hwc3/CommandResultWriter.h
@@ -32,11 +32,11 @@ struct DisplayChanges {
   std::optional<ChangedCompositionTypes> composition_changes;
   std::optional<DisplayRequest> display_request_changes;
 
-  void AddLayerCompositionChange(int64_t display_id, int64_t layer_id,
+  void AddLayerCompositionChange(int64_t display_handle, int64_t layer_id,
                                  Composition layer_composition) {
     if (!composition_changes) {
       composition_changes.emplace();
-      composition_changes->display = display_id;
+      composition_changes->display = display_handle;
     }
 
     ChangedCompositionLayer composition_change;
@@ -84,22 +84,23 @@ class CommandResultWriter {
     has_error_ = true;
   }
 
-  void AddPresentFence(int64_t display_id, ::android::base::unique_fd fence) {
+  void AddPresentFence(int64_t display_handle,
+                       ::android::base::unique_fd fence) {
     if (!fence.ok()) {
       return;
     }
 
     PresentFence present_fence;
     present_fence.fence = ::ndk::ScopedFileDescriptor(fence.release());
-    present_fence.display = display_id;
+    present_fence.display = display_handle;
     results_->emplace_back(std::move(present_fence));
   }
 
   void AddReleaseFence(
-      int64_t display_id,
+      int64_t display_handle,
       std::unordered_map<int64_t, ::android::base::unique_fd>& layer_fences) {
     ReleaseFences release_fences;
-    release_fences.display = display_id;
+    release_fences.display = display_handle;
     for (auto& [layer, fence] : layer_fences) {
       if (!fence.ok()) {
         continue;
@@ -124,10 +125,10 @@ class CommandResultWriter {
     }
   }
 
-  void AddPresentOrValidateResult(int64_t display_id,
+  void AddPresentOrValidateResult(int64_t display_handle,
                                   const PresentOrValidate::Result& pov_result) {
     PresentOrValidate pov_command;
-    pov_command.display = display_id;
+    pov_command.display = display_handle;
     pov_command.result = pov_result;
 
     results_->emplace_back(pov_command);
diff --git a/hwc3/ComposerClient.cpp b/hwc3/ComposerClient.cpp
index bc5932b..81eb33f 100644
--- a/hwc3/ComposerClient.cpp
+++ b/hwc3/ComposerClient.cpp
@@ -40,28 +40,27 @@
 #include <android/binder_auto_utils.h>
 #include <android/binder_ibinder_platform.h>
 #include <cutils/native_handle.h>
-#include <hardware/hwcomposer2.h>
-#include <hardware/hwcomposer_defs.h>
 #include <ui/GraphicBufferMapper.h>
 
 #include "bufferinfo/BufferInfo.h"
 #include "compositor/DisplayInfo.h"
-#include "hwc2_device/HwcDisplay.h"
-#include "hwc2_device/HwcDisplayConfigs.h"
-#include "hwc2_device/HwcLayer.h"
+#include "hwc/HwcDisplay.h"
+#include "hwc/HwcDisplayConfigs.h"
+#include "hwc/HwcLayer.h"
 #include "hwc3/DrmHwcThree.h"
 #include "hwc3/Utils.h"
 
+using ::android::DamageInfo;
+using ::android::DisplayHandle;
 using ::android::DstRectInfo;
 using ::android::HwcDisplay;
 using ::android::HwcDisplayConfig;
 using ::android::HwcDisplayConfigs;
 using ::android::HwcLayer;
+using ::android::IRect;
 using ::android::LayerTransform;
 using ::android::SrcRectInfo;
 
-#include "utils/log.h"
-
 namespace aidl::android::hardware::graphics::composer3::impl {
 namespace {
 
@@ -69,15 +68,6 @@ constexpr int kCtmRows = 4;
 constexpr int kCtmColumns = 4;
 constexpr int kCtmSize = kCtmRows * kCtmColumns;
 
-// clang-format off
-constexpr std::array<float, kCtmSize> kIdentityMatrix = {
-    1.0F, 0.0F, 0.0F, 0.0F,
-    0.0F, 1.0F, 0.0F, 0.0F,
-    0.0F, 0.0F, 1.0F, 0.0F,
-    0.0F, 0.0F, 0.0F, 1.0F,
-};
-// clang-format on
-
 std::optional<BufferBlendMode> AidlToBlendMode(
     const std::optional<ParcelableBlendMode>& aidl_blend_mode) {
   if (!aidl_blend_mode) {
@@ -222,7 +212,7 @@ std::optional<std::array<float, kCtmSize>> AidlToColorTransformMatrix(
   return color_transform_matrix;
 }
 
-std::optional<HWC2::Composition> AidlToCompositionType(
+std::optional<HwcLayer::CompositionType> AidlToCompositionType(
     const std::optional<ParcelableComposition> composition) {
   if (!composition) {
     return std::nullopt;
@@ -230,15 +220,15 @@ std::optional<HWC2::Composition> AidlToCompositionType(
 
   switch (composition->composition) {
     case Composition::INVALID:
-      return HWC2::Composition::Invalid;
+      return HwcLayer::CompositionType::kInvalid;
     case Composition::CLIENT:
-      return HWC2::Composition::Client;
+      return HwcLayer::CompositionType::kClient;
     case Composition::DEVICE:
-      return HWC2::Composition::Device;
+      return HwcLayer::CompositionType::kDevice;
     case Composition::SOLID_COLOR:
-      return HWC2::Composition::SolidColor;
+      return HwcLayer::CompositionType::kSolidColor;
     case Composition::CURSOR:
-      return HWC2::Composition::Cursor;
+      return HwcLayer::CompositionType::kCursor;
 
     // Unsupported composition types.
     case Composition::DISPLAY_DECORATION:
@@ -284,6 +274,11 @@ DisplayConfiguration HwcDisplayConfigToAidlConfiguration(
        .vsyncPeriod = config.mode.GetVSyncPeriodNs(),
        .hdrOutputType = static_cast<OutputType>(config.output_type)};
 
+#if __ANDROID_API__ >= 36
+  aidl_configuration.hdrOutputType = static_cast<OutputType>(
+      config.output_type);
+#endif
+
   if (width > 0) {
     static const float kMmPerInch = 25.4;
     float dpi_x = float(config.mode.GetRawMode().hdisplay) * kMmPerInch /
@@ -297,19 +292,26 @@ DisplayConfiguration HwcDisplayConfigToAidlConfiguration(
   return aidl_configuration;
 }
 
-std::optional<DstRectInfo> AidlToRect(const std::optional<common::Rect>& rect) {
+std::optional<IRect> AidlToIRect(const std::optional<common::Rect>& rect) {
   if (!rect) {
     return std::nullopt;
   }
-  DstRectInfo dst_rec;
-  dst_rec.i_rect = {.left = rect->left,
-                    .top = rect->top,
-                    .right = rect->right,
-                    .bottom = rect->bottom};
-  return dst_rec;
+  return IRect{.left = rect->left,
+               .top = rect->top,
+               .right = rect->right,
+               .bottom = rect->bottom};
+}
+
+std::optional<DstRectInfo> AidlToDstRect(
+    const std::optional<common::Rect>& rect) {
+  auto i_rect = AidlToIRect(rect);
+  if (!i_rect) {
+    return std::nullopt;
+  }
+  return DstRectInfo{.i_rect = i_rect};
 }
 
-std::optional<SrcRectInfo> AidlToFRect(
+std::optional<SrcRectInfo> AidlToSrcRect(
     const std::optional<common::FRect>& rect) {
   if (!rect) {
     return std::nullopt;
@@ -354,6 +356,26 @@ std::optional<LayerTransform> AidlToLayerTransform(
   };
 }
 
+std::optional<DamageInfo> AidlToDamage(
+    const std::optional<std::vector<std::optional<common::Rect>>>& damage) {
+  if (!damage.has_value()) {
+    return std::nullopt;
+  }
+
+  std::optional<DamageInfo> damage_info = std::nullopt;
+  for (const auto& r : damage.value()) {
+    auto i_rect = AidlToIRect(r);
+    if (i_rect.has_value()) {
+      if (!damage_info.has_value()) {
+        damage_info = DamageInfo{};
+      }
+      damage_info->dmg_rects.push_back(i_rect.value());
+    }
+  }
+
+  return damage_info;
+}
+
 }  // namespace
 
 class Hwc3BufferHandle : public PrimeFdsSharedBase {
@@ -486,13 +508,13 @@ ComposerClient::~ComposerClient() {
   LOG(DEBUG) << "removed composer client";
 }
 
-ndk::ScopedAStatus ComposerClient::createLayer(int64_t display_id,
+ndk::ScopedAStatus ComposerClient::createLayer(int64_t display_handle,
                                                int32_t /*buffer_slot_count*/,
                                                int64_t* layer_id) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
 
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
@@ -516,26 +538,23 @@ ndk::ScopedAStatus ComposerClient::createVirtualDisplay(
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
 
-  hwc2_display_t hwc2_display_id = 0;
   // TODO: Format is currently not used in drm_hwcomposer.
-  int32_t hwc2_format = 0;
-  auto err = Hwc2toHwc3Error(hwc_->CreateVirtualDisplay(width, height,
-                                                        &hwc2_format,
-                                                        &hwc2_display_id));
-  if (err != hwc3::Error::kNone) {
-    return ToBinderStatus(err);
+  std::optional<DisplayHandle>
+      display_handle = hwc_->CreateVirtualDisplay(width, height);
+  if (!display_handle) {
+    return ToBinderStatus(hwc3::Error::kUnsupported);
   }
 
-  out_display->display = Hwc2DisplayToHwc3(hwc2_display_id);
+  out_display->display = display_handle.value();
   out_display->format = format_hint;
   return ndk::ScopedAStatus::ok();
 }
 
-ndk::ScopedAStatus ComposerClient::destroyLayer(int64_t display_id,
+ndk::ScopedAStatus ComposerClient::destroyLayer(int64_t display_handle,
                                                 int64_t layer_id) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
@@ -547,20 +566,27 @@ ndk::ScopedAStatus ComposerClient::destroyLayer(int64_t display_id,
   return ToBinderStatus(hwc3::Error::kNone);
 }
 
-ndk::ScopedAStatus ComposerClient::destroyVirtualDisplay(int64_t display_id) {
+ndk::ScopedAStatus ComposerClient::destroyVirtualDisplay(
+    int64_t display_handle) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  auto err = Hwc2toHwc3Error(hwc_->DestroyVirtualDisplay(display_id));
-  return ToBinderStatus(err);
+  auto* display = GetDisplay(display_handle);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+  if (!hwc_->DestroyVirtualDisplay(display_handle)) {
+    return ToBinderStatus(hwc3::Error::kBadParameter);
+  }
+  return ndk::ScopedAStatus::ok();
 }
 
-::android::HwcDisplay* ComposerClient::GetDisplay(uint64_t display_id) {
-  return hwc_->GetDisplay(display_id);
+::android::HwcDisplay* ComposerClient::GetDisplay(int64_t display_handle) {
+  return hwc_->GetDisplay(static_cast<DisplayHandle>(display_handle));
 }
 
-void ComposerClient::DispatchLayerCommand(int64_t display_id,
+void ComposerClient::DispatchLayerCommand(int64_t display_handle,
                                           const LayerCommand& command) {
-  auto* display = GetDisplay(display_id);
+  auto* display = GetDisplay(display_handle);
   if (display == nullptr) {
     cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
     return;
@@ -648,11 +674,12 @@ void ComposerClient::DispatchLayerCommand(int64_t display_id,
   properties.color_space = AidlToColorSpace(command.dataspace);
   properties.sample_range = AidlToSampleRange(command.dataspace);
   properties.composition_type = AidlToCompositionType(command.composition);
-  properties.display_frame = AidlToRect(command.displayFrame);
+  properties.display_frame = AidlToDstRect(command.displayFrame);
   properties.alpha = AidlToAlpha(command.planeAlpha);
-  properties.source_crop = AidlToFRect(command.sourceCrop);
+  properties.source_crop = AidlToSrcRect(command.sourceCrop);
   properties.transform = AidlToLayerTransform(command.transform);
   properties.z_order = AidlToZOrder(command.z);
+  properties.damage = AidlToDamage(command.damage);
 
   layer->SetLayerProperties(properties);
 
@@ -667,7 +694,6 @@ void ComposerClient::DispatchLayerCommand(int64_t display_id,
     cmd_result_writer_->AddError(hwc3::Error::kUnsupported);
   }
   // TODO: Blocking region handling missing.
-  // TODO: Layer surface damage.
   // TODO: Layer visible region.
   // TODO: Per-frame metadata.
   // TODO: Layer color transform.
@@ -676,8 +702,8 @@ void ComposerClient::DispatchLayerCommand(int64_t display_id,
 }
 
 void ComposerClient::ExecuteDisplayCommand(const DisplayCommand& command) {
-  const int64_t display_id = command.display;
-  HwcDisplay* display = hwc_->GetDisplay(display_id);
+  const int64_t display_handle = command.display;
+  HwcDisplay* display = hwc_->GetDisplay(display_handle);
   if (display == nullptr) {
     cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
     return;
@@ -732,7 +758,7 @@ void ComposerClient::ExecuteDisplayCommand(const DisplayCommand& command) {
     }
     cmd_result_writer_->AddChanges(changes);
     auto hwc3_display = DrmHwcThree::GetHwc3Display(*display);
-    hwc3_display->must_validate = false;
+    hwc_->ClearMustValidateDisplay(display_handle);
     hwc3_display->desired_present_time = AidlToPresentTimeNs(
         command.expectedPresentTime);
 
@@ -742,11 +768,11 @@ void ComposerClient::ExecuteDisplayCommand(const DisplayCommand& command) {
   if (command.presentOrValidateDisplay) {
     auto result = PresentOrValidate::Result::Validated;
     if (!display->NeedsClientLayerUpdate() && !changes.HasAnyChanges()) {
-      ALOGV("Skipping SF roundtrip for display %" PRId64, display_id);
+      ALOGV("Skipping SF roundtrip for display %" PRId64, display_handle);
       result = PresentOrValidate::Result::Presented;
       shall_present_now = true;
     }
-    cmd_result_writer_->AddPresentOrValidateResult(display_id, result);
+    cmd_result_writer_->AddPresentOrValidateResult(display_handle, result);
   }
 
   if (command.acceptDisplayChanges) {
@@ -755,7 +781,7 @@ void ComposerClient::ExecuteDisplayCommand(const DisplayCommand& command) {
 
   if (command.presentDisplay || shall_present_now) {
     auto hwc3_display = DrmHwcThree::GetHwc3Display(*display);
-    if (hwc3_display->must_validate) {
+    if (hwc_->GetMustValidateDisplay(display_handle)) {
       cmd_result_writer_->AddError(hwc3::Error::kNotValidated);
       return;
     }
@@ -773,13 +799,13 @@ void ComposerClient::ExecuteDisplayCommand(const DisplayCommand& command) {
 
     using ::android::base::unique_fd;
     cmd_result_writer_->AddPresentFence(  //
-        display_id, unique_fd(::android::DupFd(present_fence)));
+        display_handle, unique_fd(::android::DupFd(present_fence)));
 
     std::unordered_map<int64_t, unique_fd> hal_release_fences;
     for (const auto& [layer_id, release_fence] : release_fences) {
       hal_release_fences[layer_id] = unique_fd(::android::DupFd(release_fence));
     }
-    cmd_result_writer_->AddReleaseFence(display_id, hal_release_fences);
+    cmd_result_writer_->AddReleaseFence(display_handle, hal_release_fences);
   }
 }
 
@@ -798,11 +824,11 @@ ndk::ScopedAStatus ComposerClient::executeCommands(
   return ndk::ScopedAStatus::ok();
 }
 
-ndk::ScopedAStatus ComposerClient::getActiveConfig(int64_t display_id,
+ndk::ScopedAStatus ComposerClient::getActiveConfig(int64_t display_handle,
                                                    int32_t* config_id) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
@@ -812,34 +838,21 @@ ndk::ScopedAStatus ComposerClient::getActiveConfig(int64_t display_id,
     return ToBinderStatus(hwc3::Error::kBadConfig);
   }
 
-  *config_id = Hwc2ConfigIdToHwc3(config->id);
+  *config_id = config->id;
   return ndk::ScopedAStatus::ok();
 }
 
 ndk::ScopedAStatus ComposerClient::getColorModes(
-    int64_t display_id, std::vector<ColorMode>* color_modes) {
+    int64_t display_handle, std::vector<AidlColorMode>* color_modes) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  uint32_t num_modes = 0;
-  auto error = Hwc2toHwc3Error(display->GetColorModes(&num_modes, nullptr));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
-
-  std::vector<int32_t> hwc2_color_modes(num_modes);
-  error = Hwc2toHwc3Error(
-      display->GetColorModes(&num_modes, hwc2_color_modes.data()));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
-
-  for (const auto& mode : hwc2_color_modes) {
-    color_modes->push_back(Hwc2ColorModeToHwc3(mode));
+  for (const auto& mode : display->GetColorModes()) {
+    color_modes->emplace_back(static_cast<AidlColorMode>(mode));
   }
 
   return ndk::ScopedAStatus::ok();
@@ -860,11 +873,11 @@ ndk::ScopedAStatus ComposerClient::getDataspaceSaturationMatrix(
 }
 
 ndk::ScopedAStatus ComposerClient::getDisplayAttribute(
-    int64_t display_id, int32_t config_id, DisplayAttribute attribute,
+    int64_t display_handle, int32_t config_id, DisplayAttribute attribute,
     int32_t* value) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
@@ -914,40 +927,26 @@ ndk::ScopedAStatus ComposerClient::getDisplayAttribute(
 }
 
 ndk::ScopedAStatus ComposerClient::getDisplayCapabilities(
-    int64_t display_id, std::vector<DisplayCapability>* caps) {
+    int64_t display_handle, std::vector<DisplayCapability>* caps) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
-  if (display == nullptr) {
+  if (GetDisplay(display_handle) == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  uint32_t num_capabilities = 0;
-  hwc3::Error error = Hwc2toHwc3Error(
-      display->GetDisplayCapabilities(&num_capabilities, nullptr));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
-
-  std::vector<uint32_t> out_caps(num_capabilities);
-  error = Hwc2toHwc3Error(
-      display->GetDisplayCapabilities(&num_capabilities, out_caps.data()));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
-
-  caps->reserve(num_capabilities);
-  for (const auto cap : out_caps) {
-    caps->emplace_back(Hwc2DisplayCapabilityToHwc3(cap));
+  // Skip color transform altogether if device/drm cannot support it.
+  if (hwc_->GetResMan().GetCtmHandling() ==
+      ::android::CtmHandling::kDrmOrIgnore) {
+    caps->emplace_back(DisplayCapability::SKIP_CLIENT_COLOR_TRANSFORM);
   }
   return ndk::ScopedAStatus::ok();
 }
 
 ndk::ScopedAStatus ComposerClient::getDisplayConfigs(
-    int64_t display_id, std::vector<int32_t>* out_configs) {
+    int64_t display_handle, std::vector<int32_t>* out_configs) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
@@ -960,79 +959,62 @@ ndk::ScopedAStatus ComposerClient::getDisplayConfigs(
 }
 
 ndk::ScopedAStatus ComposerClient::getDisplayConnectionType(
-    int64_t display_id, DisplayConnectionType* type) {
+    int64_t display_handle, DisplayConnectionType* type) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  uint32_t out_type = 0;
-  const hwc3::Error error = Hwc2toHwc3Error(
-      display->GetDisplayConnectionType(&out_type));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
+  switch (display->GetDisplayType()) {
+    case HwcDisplay::DisplayType::kVirtual:
+      return ToBinderStatus(hwc3::Error::kBadDisplay);
+    case HwcDisplay::DisplayType::kInternal:
+      *type = DisplayConnectionType::INTERNAL;
+      break;
+    case HwcDisplay::DisplayType::kExternal:
+      *type = DisplayConnectionType::EXTERNAL;
+      break;
   }
-
-  *type = Hwc2DisplayConnectionTypeToHwc3(out_type);
   return ndk::ScopedAStatus::ok();
 }
 
 ndk::ScopedAStatus ComposerClient::getDisplayIdentificationData(
-    int64_t display_id, DisplayIdentification* id) {
+    int64_t display_handle, DisplayIdentification* id) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  uint8_t port = 0;
-  uint32_t data_size = 0;
-  hwc3::Error error = Hwc2toHwc3Error(
-      display->GetDisplayIdentificationData(&port, &data_size, nullptr));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
-
-  id->data.resize(data_size);
-  error = Hwc2toHwc3Error(
-      display->GetDisplayIdentificationData(&port, &data_size,
-                                            id->data.data()));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
+  id->port = static_cast<int8_t>(display->GetPort());
+  id->data = display->GetRawEdid();
+  if (id->data.empty()) {
+    return ToBinderStatus(hwc3::Error::kUnsupported);
   }
-
-  id->port = static_cast<int8_t>(port);
   return ndk::ScopedAStatus::ok();
 }
 
-ndk::ScopedAStatus ComposerClient::getDisplayName(int64_t display_id,
+ndk::ScopedAStatus ComposerClient::getDisplayName(int64_t display_handle,
                                                   std::string* name) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  uint32_t size = 0;
-  auto error = Hwc2toHwc3Error(display->GetDisplayName(&size, nullptr));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
-
-  name->resize(size);
-  error = Hwc2toHwc3Error(display->GetDisplayName(&size, name->data()));
-  return ToBinderStatus(error);
+  *name = display->GetDisplayName();
+  return ndk::ScopedAStatus::ok();
 }
 
 ndk::ScopedAStatus ComposerClient::getDisplayVsyncPeriod(
-    int64_t display_id, int32_t* vsync_period) {
+    int64_t display_handle, int32_t* vsync_period) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
@@ -1050,20 +1032,20 @@ ndk::ScopedAStatus ComposerClient::getDisplayVsyncPeriod(
 }
 
 ndk::ScopedAStatus ComposerClient::getDisplayedContentSample(
-    int64_t /*display_id*/, int64_t /*max_frames*/, int64_t /*timestamp*/,
+    int64_t /*display_handle*/, int64_t /*max_frames*/, int64_t /*timestamp*/,
     DisplayContentSample* /*samples*/) {
   DEBUG_FUNC();
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
 ndk::ScopedAStatus ComposerClient::getDisplayedContentSamplingAttributes(
-    int64_t /*display_id*/, DisplayContentSamplingAttributes* /*attrs*/) {
+    int64_t /*display_handle*/, DisplayContentSamplingAttributes* /*attrs*/) {
   DEBUG_FUNC();
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
 ndk::ScopedAStatus ComposerClient::getDisplayPhysicalOrientation(
-    int64_t display_id, common::Transform* orientation) {
+    int64_t display_handle, common::Transform* orientation) {
   DEBUG_FUNC();
 
   if (orientation == nullptr) {
@@ -1072,7 +1054,7 @@ ndk::ScopedAStatus ComposerClient::getDisplayPhysicalOrientation(
   }
 
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
@@ -1102,36 +1084,17 @@ ndk::ScopedAStatus ComposerClient::getDisplayPhysicalOrientation(
   return ndk::ScopedAStatus::ok();
 }
 
-ndk::ScopedAStatus ComposerClient::getHdrCapabilities(int64_t display_id,
+ndk::ScopedAStatus ComposerClient::getHdrCapabilities(int64_t display_handle,
                                                       HdrCapabilities* caps) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  uint32_t num_types = 0;
-  hwc3::Error error = Hwc2toHwc3Error(
-      display->GetHdrCapabilities(&num_types, nullptr, nullptr, nullptr,
-                                  nullptr));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
-
-  std::vector<int32_t> out_types(num_types);
-  error = Hwc2toHwc3Error(
-      display->GetHdrCapabilities(&num_types, out_types.data(),
-                                  &caps->maxLuminance,
-                                  &caps->maxAverageLuminance,
-                                  &caps->minLuminance));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
-
-  caps->types.reserve(num_types);
-  for (const auto type : out_types)
-    caps->types.emplace_back(Hwc2HdrTypeToHwc3(type));
+  display->GetHdrCapabilities(&caps->types, &caps->maxLuminance,
+                              &caps->maxAverageLuminance, &caps->minLuminance);
 
   return ndk::ScopedAStatus::ok();
 }
@@ -1144,60 +1107,93 @@ ndk::ScopedAStatus ComposerClient::getMaxVirtualDisplayCount(int32_t* count) {
 }
 
 ndk::ScopedAStatus ComposerClient::getPerFrameMetadataKeys(
-    int64_t /*display_id*/, std::vector<PerFrameMetadataKey>* /*keys*/) {
+    int64_t /*display_handle*/, std::vector<PerFrameMetadataKey>* /*keys*/) {
   DEBUG_FUNC();
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
 ndk::ScopedAStatus ComposerClient::getReadbackBufferAttributes(
-    int64_t /*display_id*/, ReadbackBufferAttributes* /*attrs*/) {
+    int64_t display_handle, ReadbackBufferAttributes* attrs) {
   DEBUG_FUNC();
-  return ToBinderStatus(hwc3::Error::kUnsupported);
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+
+  HwcDisplay* display = GetDisplay(display_handle);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  if (!display->IsWritebackSupported()) {
+    return ToBinderStatus(hwc3::Error::kUnsupported);
+  }
+
+  // TODO(markyacoub): Query the writeback connector to determine the supported
+  // readback buffer attributes (format, dataspace, etc.) Currently, default
+  // values are used.
+  attrs->format = common::PixelFormat::RGBA_8888;
+  attrs->dataspace = common::Dataspace::SRGB;
+  return ndk::ScopedAStatus::ok();
 }
 
 ndk::ScopedAStatus ComposerClient::getReadbackBufferFence(
-    int64_t /*display_id*/, ndk::ScopedFileDescriptor* /*acquireFence*/) {
+    int64_t display_handle, ndk::ScopedFileDescriptor* acquire_fence) {
   DEBUG_FUNC();
-  return ToBinderStatus(hwc3::Error::kUnsupported);
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+
+  *acquire_fence = ndk::ScopedFileDescriptor(-1);
+
+  HwcDisplay* display = GetDisplay(display_handle);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  // Check if this display supports readback operations
+  if (!display->IsWritebackSupported()) {
+    ALOGI("ComposerClient: Display %" PRId64 " does not support readback",
+          display_handle);
+    return ToBinderStatus(hwc3::Error::kUnsupported);
+  }
+
+  ::android::SharedFd fence = display->GetWritebackBufferFence();
+  display->SetWritebackEnabled(false);
+  display->GetWritebackLayer()->ClearSlots();
+  if (!fence) {
+    ALOGE("ComposerClient: Failed to get readback buffer fence");
+    return ToBinderStatus(hwc3::Error::kBadParameter);
+  }
+
+  if (fence && *fence >= 0) {
+    *acquire_fence = ndk::ScopedFileDescriptor(::android::DupFd(fence));
+  }
+
+  return ndk::ScopedAStatus::ok();
 }
 
 ndk::ScopedAStatus ComposerClient::getRenderIntents(
-    int64_t display_id, ColorMode mode, std::vector<RenderIntent>* intents) {
+    int64_t display_handle, AidlColorMode mode,
+    std::vector<RenderIntent>* intents) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  const int32_t hwc2_color_mode = Hwc3ColorModeToHwc2(mode);
-  uint32_t out_num_intents = 0;
-  auto error = Hwc2toHwc3Error(
-      display->GetRenderIntents(hwc2_color_mode, &out_num_intents, nullptr));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
+  // TODO: Remove invalid enum tests from VTS
+  if (mode < AidlColorMode::NATIVE || mode > AidlColorMode::DISPLAY_BT2020)
+    return ToBinderStatus(hwc3::Error::kBadParameter);
 
-  std::vector<int32_t> out_intents(out_num_intents);
-  error = Hwc2toHwc3Error(display->GetRenderIntents(hwc2_color_mode,
-                                                    &out_num_intents,
-                                                    out_intents.data()));
-  if (error != hwc3::Error::kNone) {
-    return ToBinderStatus(error);
-  }
+  intents->clear();
+  intents->reserve(1);
+  intents->emplace_back(RenderIntent::COLORIMETRIC);
 
-  intents->reserve(out_num_intents);
-  for (const auto intent : out_intents) {
-    intents->emplace_back(Hwc2RenderIntentToHwc3(intent));
-  }
   return ndk::ScopedAStatus::ok();
 }
 
 ndk::ScopedAStatus ComposerClient::getSupportedContentTypes(
-    int64_t display_id, std::vector<ContentType>* types) {
+    int64_t display_handle, std::vector<ContentType>* types) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
@@ -1208,7 +1204,7 @@ ndk::ScopedAStatus ComposerClient::getSupportedContentTypes(
 }
 
 ndk::ScopedAStatus ComposerClient::getDisplayDecorationSupport(
-    int64_t /*display_id*/,
+    int64_t /*display_handle*/,
     std::optional<common::DisplayDecorationSupport>* /*support_struct*/) {
   DEBUG_FUNC();
   return ToBinderStatus(hwc3::Error::kUnsupported);
@@ -1223,7 +1219,7 @@ ndk::ScopedAStatus ComposerClient::registerCallback(
   return ndk::ScopedAStatus::ok();
 }
 
-ndk::ScopedAStatus ComposerClient::setActiveConfig(int64_t display_id,
+ndk::ScopedAStatus ComposerClient::setActiveConfig(int64_t display_handle,
                                                    int32_t config) {
   DEBUG_FUNC();
 
@@ -1232,17 +1228,17 @@ ndk::ScopedAStatus ComposerClient::setActiveConfig(int64_t display_id,
       .desiredTimeNanos = ::android::ResourceManager::GetTimeMonotonicNs(),
       .seamlessRequired = false,
   };
-  return setActiveConfigWithConstraints(display_id, config, constraints,
+  return setActiveConfigWithConstraints(display_handle, config, constraints,
                                         &timeline);
 }
 
 ndk::ScopedAStatus ComposerClient::setActiveConfigWithConstraints(
-    int64_t display_id, int32_t config,
+    int64_t display_handle, int32_t config,
     const VsyncPeriodChangeConstraints& constraints,
     VsyncPeriodChangeTimeline* timeline) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
@@ -1273,7 +1269,7 @@ ndk::ScopedAStatus ComposerClient::setActiveConfigWithConstraints(
     client_layer.ClearSlots();
   }
 
-  // If the contraints dictate that this is to be applied in the future, it
+  // If the constraints dictate that this is to be applied in the future, it
   // must be queued. If the new config is in the same config group as the
   // current one, then queue it to reduce jank.
   HwcDisplay::ConfigError result{};
@@ -1306,29 +1302,29 @@ ndk::ScopedAStatus ComposerClient::setActiveConfigWithConstraints(
   }
 }
 
-ndk::ScopedAStatus ComposerClient::setBootDisplayConfig(int64_t /*display_id*/,
-                                                        int32_t /*config*/) {
+ndk::ScopedAStatus ComposerClient::setBootDisplayConfig(
+    int64_t /*display_handle*/, int32_t /*config*/) {
   DEBUG_FUNC();
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
 ndk::ScopedAStatus ComposerClient::clearBootDisplayConfig(
-    int64_t /*display_id*/) {
+    int64_t /*display_handle*/) {
   DEBUG_FUNC();
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
 ndk::ScopedAStatus ComposerClient::getPreferredBootDisplayConfig(
-    int64_t /*display_id*/, int32_t* /*config*/) {
+    int64_t /*display_handle*/, int32_t* /*config*/) {
   DEBUG_FUNC();
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
-ndk::ScopedAStatus ComposerClient::setAutoLowLatencyMode(int64_t display_id,
+ndk::ScopedAStatus ComposerClient::setAutoLowLatencyMode(int64_t display_handle,
                                                          bool /*on*/) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
@@ -1337,31 +1333,40 @@ ndk::ScopedAStatus ComposerClient::setAutoLowLatencyMode(int64_t display_id,
 }
 
 ndk::ScopedAStatus ComposerClient::setClientTargetSlotCount(
-    int64_t /*display_id*/, int32_t /*count*/) {
+    int64_t /*display_handle*/, int32_t /*count*/) {
   DEBUG_FUNC();
   return ToBinderStatus(hwc3::Error::kNone);
 }
 
-ndk::ScopedAStatus ComposerClient::setColorMode(int64_t display_id,
-                                                ColorMode mode,
+ndk::ScopedAStatus ComposerClient::setColorMode(int64_t display_handle,
+                                                AidlColorMode mode,
                                                 RenderIntent intent) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  auto error = display->SetColorModeWithIntent(Hwc3ColorModeToHwc2(mode),
-                                               Hwc3RenderIntentToHwc2(intent));
-  return ToBinderStatus(Hwc2toHwc3Error(error));
+  // TODO: Remove invalid enum tests from VTS
+  if (mode < AidlColorMode::NATIVE || mode > AidlColorMode::DISPLAY_BT2020)
+    return ToBinderStatus(hwc3::Error::kBadParameter);
+
+  if (intent < RenderIntent::COLORIMETRIC || intent > RenderIntent::TONE_MAP_ENHANCE)
+    return ToBinderStatus(hwc3::Error::kBadParameter);
+
+  if (intent != RenderIntent::COLORIMETRIC)
+    return ToBinderStatus(hwc3::Error::kUnsupported);
+
+  display->SetColorMode(static_cast<::ColorMode>(mode));
+  return ToBinderStatus(hwc3::Error::kNone);
 }
 
-ndk::ScopedAStatus ComposerClient::setContentType(int64_t display_id,
+ndk::ScopedAStatus ComposerClient::setContentType(int64_t display_handle,
                                                   ContentType type) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
@@ -1373,51 +1378,114 @@ ndk::ScopedAStatus ComposerClient::setContentType(int64_t display_id,
 }
 
 ndk::ScopedAStatus ComposerClient::setDisplayedContentSamplingEnabled(
-    int64_t /*display_id*/, bool /*enable*/,
+    int64_t /*display_handle*/, bool /*enable*/,
     FormatColorComponent /*componentMask*/, int64_t /*maxFrames*/) {
   DEBUG_FUNC();
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
-ndk::ScopedAStatus ComposerClient::setPowerMode(int64_t display_id,
+ndk::ScopedAStatus ComposerClient::setPowerMode(int64_t display_handle,
                                                 PowerMode mode) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  if (mode == PowerMode::ON_SUSPEND) {
-    return ToBinderStatus(hwc3::Error::kUnsupported);
+  // Only OFF and ON are supported. VTS requires checking for invalid enum
+  // values.
+  switch (static_cast<int32_t>(mode)) {
+    case static_cast<int32_t>(PowerMode::OFF):
+    case static_cast<int32_t>(PowerMode::ON):
+      break;
+    case static_cast<int32_t>(PowerMode::DOZE):
+    case static_cast<int32_t>(PowerMode::DOZE_SUSPEND):
+    case static_cast<int32_t>(PowerMode::ON_SUSPEND):
+      return ToBinderStatus(hwc3::Error::kUnsupported);
+    default:
+      return ToBinderStatus(hwc3::Error::kBadParameter);
   }
 
-  auto error = display->SetPowerMode(Hwc3PowerModeToHwc2(mode));
-  return ToBinderStatus(Hwc2toHwc3Error(error));
+  if (!display->SetDisplayEnabled(mode == PowerMode::ON)) {
+    return ToBinderStatus(hwc3::Error::kBadParameter);
+  }
+  return ndk::ScopedAStatus::ok();
 }
 
 ndk::ScopedAStatus ComposerClient::setReadbackBuffer(
-    int64_t /*display_id*/, const AidlNativeHandle& /*aidlBuffer*/,
-    const ndk::ScopedFileDescriptor& /*releaseFence*/) {
+    int64_t display_handle, const AidlNativeHandle& aidl_buffer,
+    const ndk::ScopedFileDescriptor& release_fence_in) {
   DEBUG_FUNC();
-  return ToBinderStatus(hwc3::Error::kUnsupported);
+  const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
+
+  HwcDisplay* display = GetDisplay(display_handle);
+  if (display == nullptr) {
+    return ToBinderStatus(hwc3::Error::kBadDisplay);
+  }
+
+  if (!display->IsWritebackSupported()) {
+    return ToBinderStatus(hwc3::Error::kUnsupported);
+  }
+
+  if (!display->SetWritebackEnabled(true)) {
+    ALOGE("ComposerClient: Failed to enable writeback");
+    return ToBinderStatus(hwc3::Error::kUnsupported);
+  }
+
+  buffer_handle_t raw_buffer = ::android::makeFromAidl(aidl_buffer);
+  if (raw_buffer == nullptr) {
+    ALOGE("ComposerClient: Failed to convert AIDL handle to buffer_handle_t");
+    return ToBinderStatus(hwc3::Error::kBadParameter);
+  }
+
+  buffer_handle_t imported_handle = nullptr;
+  auto result = ::android::GraphicBufferMapper::get()
+                    .importBufferNoValidate(raw_buffer, &imported_handle);
+  if (result != ::android::OK) {
+    ALOGE("ComposerClient: Failed to import readback buffer handle: %d",
+          result);
+    return ToBinderStatus(hwc3::Error::kBadParameter);
+  }
+  HwcLayer::LayerProperties properties;
+  properties.slot_buffer = {
+      .slot_id = 0,
+      .bi = ::android::BufferInfoGetter::GetInstance()->GetBoInfo(
+          imported_handle),
+  };
+  ndk::ScopedFileDescriptor release_fence = ndk::ScopedFileDescriptor(
+      release_fence_in.get());
+  properties.active_slot = {
+      .slot_id = 0,
+      .fence = ::android::MakeSharedFd(release_fence.release()),
+  };
+  properties.blend_mode = BufferBlendMode::kNone;
+
+  std::unique_ptr<HwcLayer>& writeback_layer = display->GetWritebackLayer();
+  if (!writeback_layer) {
+    ALOGE("HwcDisplay: Writeback layer not available");
+    return ToBinderStatus(hwc3::Error::kBadParameter);
+  }
+  writeback_layer->SetLayerProperties(properties);
+
+  return ndk::ScopedAStatus::ok();
 }
 
-ndk::ScopedAStatus ComposerClient::setVsyncEnabled(int64_t display_id,
+ndk::ScopedAStatus ComposerClient::setVsyncEnabled(int64_t display_handle,
                                                    bool enabled) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
 
-  auto error = display->SetVsyncEnabled(static_cast<int32_t>(enabled));
-  return ToBinderStatus(Hwc2toHwc3Error(error));
+  display->SetVsyncCallbacksEnabled(enabled);
+  return ndk::ScopedAStatus::ok();
 }
 
-ndk::ScopedAStatus ComposerClient::setIdleTimerEnabled(int64_t /*display_id*/,
-                                                       int32_t /*timeout*/) {
+ndk::ScopedAStatus ComposerClient::setIdleTimerEnabled(
+    int64_t /*display_handle*/, int32_t /*timeout*/) {
   DEBUG_FUNC();
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
@@ -1450,11 +1518,11 @@ ndk::ScopedAStatus ComposerClient::setRefreshRateChangedCallbackDebugEnabled(
 #if __ANDROID_API__ >= 35
 
 ndk::ScopedAStatus ComposerClient::getDisplayConfigurations(
-    int64_t display_id, int32_t /*max_frame_interval_ns*/,
+    int64_t display_handle, int32_t /*max_frame_interval_ns*/,
     std::vector<DisplayConfiguration>* configurations) {
   DEBUG_FUNC();
   const std::unique_lock lock(hwc_->GetResMan().GetMainLock());
-  HwcDisplay* display = GetDisplay(display_id);
+  HwcDisplay* display = GetDisplay(display_handle);
   if (display == nullptr) {
     return ToBinderStatus(hwc3::Error::kBadDisplay);
   }
@@ -1477,29 +1545,29 @@ ndk::ScopedAStatus ComposerClient::notifyExpectedPresent(
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
+#endif
+
+#if __ANDROID_API__ >= 36
+
 ndk::ScopedAStatus ComposerClient::startHdcpNegotiation(
-    int64_t /*display*/, const AidlHdcpLevels& /*levels*/) {
+    int64_t /*display*/, const drm::HdcpLevels& /*levels*/) {
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
-#endif
-
-ndk::ScopedAStatus ComposerClient::getMaxLayerPictureProfiles(int64_t, int32_t*) {
+ndk::ScopedAStatus ComposerClient::getMaxLayerPictureProfiles(int64_t,
+                                                              int32_t*) {
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
 ndk::ScopedAStatus ComposerClient::getLuts(int64_t, const std::vector<Buffer>&,
-    std::vector<Luts>*) {
+                                           std::vector<Luts>*) {
   return ToBinderStatus(hwc3::Error::kUnsupported);
 }
 
-std::string ComposerClient::Dump() {
-  uint32_t size = 0;
-  hwc_->Dump(&size, nullptr);
+#endif
 
-  std::string buffer(size, '\0');
-  hwc_->Dump(&size, &buffer.front());
-  return buffer;
+std::string ComposerClient::Dump() {
+  return hwc_->DumpState();
 }
 
 ::ndk::SpAIBinder ComposerClient::createBinder() {
@@ -1509,8 +1577,8 @@ std::string ComposerClient::Dump() {
 }
 
 void ComposerClient::ExecuteSetDisplayClientTarget(
-    uint64_t display_id, const ClientTarget& command) {
-  auto* display = GetDisplay(display_id);
+    int64_t display_handle, const ClientTarget& command) {
+  auto* display = GetDisplay(display_handle);
   if (display == nullptr) {
     cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
     return;
@@ -1547,9 +1615,9 @@ void ComposerClient::ExecuteSetDisplayClientTarget(
   client_layer.SetLayerProperties(properties.value());
 }
 
-void ComposerClient::ExecuteSetDisplayOutputBuffer(uint64_t display_id,
+void ComposerClient::ExecuteSetDisplayOutputBuffer(int64_t display_handle,
                                                    const Buffer& buffer) {
-  auto* display = GetDisplay(display_id);
+  auto* display = GetDisplay(display_handle);
   if (display == nullptr) {
     cmd_result_writer_->AddError(hwc3::Error::kBadDisplay);
     return;
diff --git a/hwc3/ComposerClient.h b/hwc3/ComposerClient.h
index ed47cd6..58fae80 100644
--- a/hwc3/ComposerClient.h
+++ b/hwc3/ComposerClient.h
@@ -20,7 +20,7 @@
 
 #include "aidl/android/hardware/graphics/composer3/BnComposerClient.h"
 #include "aidl/android/hardware/graphics/composer3/LayerCommand.h"
-#include "hwc2_device/HwcLayer.h"
+#include "hwc/HwcLayer.h"
 #include "hwc3/CommandResultWriter.h"
 #include "hwc3/Utils.h"
 #include "utils/Mutex.h"
@@ -34,6 +34,7 @@ class HwcDisplay;
 }  // namespace android
 
 namespace aidl::android::hardware::graphics::composer3::impl {
+using AidlColorMode = ColorMode;
 
 class DrmHwcThree;
 
@@ -94,7 +95,7 @@ class ComposerClient : public BnComposerClient {
   ndk::ScopedAStatus getReadbackBufferFence(
       int64_t display, ndk::ScopedFileDescriptor* acquire_fence) override;
   ndk::ScopedAStatus getRenderIntents(
-      int64_t display, ColorMode mode,
+      int64_t display, AidlColorMode mode,
       std::vector<RenderIntent>* intents) override;
   ndk::ScopedAStatus getSupportedContentTypes(
       int64_t display, std::vector<ContentType>* types) override;
@@ -116,7 +117,7 @@ class ComposerClient : public BnComposerClient {
   ndk::ScopedAStatus setAutoLowLatencyMode(int64_t display, bool on) override;
   ndk::ScopedAStatus setClientTargetSlotCount(int64_t display,
                                               int32_t count) override;
-  ndk::ScopedAStatus setColorMode(int64_t display, ColorMode mode,
+  ndk::ScopedAStatus setColorMode(int64_t display, AidlColorMode mode,
                                   RenderIntent intent) override;
   ndk::ScopedAStatus setContentType(int64_t display, ContentType type) override;
   ndk::ScopedAStatus setDisplayedContentSamplingEnabled(
@@ -152,34 +153,37 @@ class ComposerClient : public BnComposerClient {
   ndk::ScopedAStatus notifyExpectedPresent(
       int64_t display, const ClockMonotonicTimestamp& expected_present_time,
       int32_t frame_interval_ns) override;
-  ndk::ScopedAStatus startHdcpNegotiation(int64_t display,
-      const AidlHdcpLevels& levels) override;
-
 #endif
 
-  ndk::ScopedAStatus getMaxLayerPictureProfiles(
-      int64_t display, int32_t* maxProfiles) override;
+#if __ANDROID_API__ >= 36
+  ndk::ScopedAStatus startHdcpNegotiation(
+      int64_t display, const drm::HdcpLevels& levels) override;
+  ndk::ScopedAStatus getMaxLayerPictureProfiles(int64_t display,
+                                                int32_t* maxProfiles) override;
   ndk::ScopedAStatus getLuts(int64_t, const std::vector<Buffer>&,
                              std::vector<Luts>* out_luts) override;
+#endif
 
  protected:
   ::ndk::SpAIBinder createBinder() override;
 
  private:
-  hwc3::Error ImportLayerBuffer(int64_t display_id, int64_t layer_id,
+  hwc3::Error ImportLayerBuffer(int64_t display_handle, int64_t layer_id,
                                 const Buffer& buffer,
                                 ::android::HwcLayer::Buffer* out_buffer);
 
   // Layer commands
-  void DispatchLayerCommand(int64_t display_id, const LayerCommand& command);
+  void DispatchLayerCommand(int64_t display_handle,
+                            const LayerCommand& command);
 
   // Display commands
   void ExecuteDisplayCommand(const DisplayCommand& command);
-  void ExecuteSetDisplayClientTarget(uint64_t display_id,
+  void ExecuteSetDisplayClientTarget(int64_t display_handle,
                                      const ClientTarget& command);
-  void ExecuteSetDisplayOutputBuffer(uint64_t display_id, const Buffer& buffer);
+  void ExecuteSetDisplayOutputBuffer(int64_t display_handle,
+                                     const Buffer& buffer);
 
-  ::android::HwcDisplay* GetDisplay(uint64_t display_id);
+  ::android::HwcDisplay* GetDisplay(int64_t display_handle);
 
   std::unique_ptr<CommandResultWriter> cmd_result_writer_;
 
diff --git a/hwc3/DrmHwcThree.cpp b/hwc3/DrmHwcThree.cpp
index 6df3022..660a14b 100644
--- a/hwc3/DrmHwcThree.cpp
+++ b/hwc3/DrmHwcThree.cpp
@@ -49,41 +49,38 @@ void DrmHwcThree::Init(std::shared_ptr<IComposerCallback> callback) {
 }
 
 void DrmHwcThree::SendVsyncPeriodTimingChangedEventToClient(
-    uint64_t display_id, int64_t timestamp) const {
+    ::android::DisplayHandle display_handle, int64_t timestamp) const {
   VsyncPeriodChangeTimeline timeline;
   timeline.newVsyncAppliedTimeNanos = timestamp;
   timeline.refreshRequired = false;
   timeline.refreshTimeNanos = 0;
 
   composer_callback_->onVsyncPeriodTimingChanged(static_cast<int64_t>(
-                                                     display_id),
+                                                     display_handle),
                                                  timeline);
 }
 
-void DrmHwcThree::SendRefreshEventToClient(uint64_t display_id) {
+void DrmHwcThree::SendRefreshEventToClient(
+    ::android::DisplayHandle display_handle) {
   {
-    const std::unique_lock lock(GetResMan().GetMainLock());
-    auto* idisplay = GetDisplay(display_id);
-    if (idisplay == nullptr) {
-      ALOGE("Failed to get display %" PRIu64, display_id);
-      return;
-    }
-    auto hwc3_display = GetHwc3Display(*idisplay);
-    hwc3_display->must_validate = true;
+    const std::scoped_lock lock(must_validate_lock_);
+    must_validate_.insert(display_handle);
   }
-  composer_callback_->onRefresh(static_cast<int64_t>(display_id));
+  composer_callback_->onRefresh(static_cast<int64_t>(display_handle));
 }
 
-void DrmHwcThree::SendVsyncEventToClient(uint64_t display_id, int64_t timestamp,
-                                         uint32_t vsync_period) const {
-  composer_callback_->onVsync(static_cast<int64_t>(display_id), timestamp,
+void DrmHwcThree::SendVsyncEventToClient(
+    ::android::DisplayHandle display_handle, int64_t timestamp,
+    uint32_t vsync_period) const {
+  composer_callback_->onVsync(static_cast<int64_t>(display_handle), timestamp,
                               static_cast<int32_t>(vsync_period));
 }
 
 #if __ANDROID_API__ >= 35
 
 void DrmHwcThree::SendHotplugEventToClient(
-    hwc2_display_t display_id, DrmHwc::DisplayStatus display_status) {
+    ::android::DisplayHandle display_handle,
+    DrmHwc::DisplayStatus display_status) {
   common::DisplayHotplugEvent event = common::DisplayHotplugEvent::DISCONNECTED;
   switch (display_status) {
     case DrmHwc::kDisconnected:
@@ -96,17 +93,38 @@ void DrmHwcThree::SendHotplugEventToClient(
       event = common::DisplayHotplugEvent::ERROR_INCOMPATIBLE_CABLE;
       break;
   }
-  composer_callback_->onHotplugEvent(static_cast<int64_t>(display_id), event);
+  if (event == common::DisplayHotplugEvent::DISCONNECTED) {
+    ClearMustValidateDisplay(display_handle);
+  }
+  composer_callback_->onHotplugEvent(static_cast<int64_t>(display_handle),
+                                     event);
 }
 
 #else
 
 void DrmHwcThree::SendHotplugEventToClient(
-    hwc2_display_t display_id, DrmHwc::DisplayStatus display_status) {
+    ::android::DisplayHandle display_handle,
+    DrmHwc::DisplayStatus display_status) {
   bool connected = display_status != DrmHwc::kDisconnected;
-  composer_callback_->onHotplug(static_cast<int64_t>(display_id), connected);
+  if (!connected) {
+    ClearMustValidateDisplay(display_handle);
+  }
+  composer_callback_->onHotplug(static_cast<int64_t>(display_handle),
+                                connected);
 }
 
 #endif
 
+auto DrmHwcThree::GetMustValidateDisplay(
+    ::android::DisplayHandle display_handle) -> bool {
+  std::scoped_lock lock(must_validate_lock_);
+  return must_validate_.find(display_handle) != must_validate_.end();
+}
+
+void DrmHwcThree::ClearMustValidateDisplay(
+    ::android::DisplayHandle display_handle) {
+  std::scoped_lock lock(must_validate_lock_);
+  must_validate_.erase(display_handle);
+}
+
 }  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hwc3/DrmHwcThree.h b/hwc3/DrmHwcThree.h
index 89bcf46..24834db 100644
--- a/hwc3/DrmHwcThree.h
+++ b/hwc3/DrmHwcThree.h
@@ -19,13 +19,13 @@
 #include <aidl/android/hardware/graphics/composer3/IComposerCallback.h>
 
 #include "drm/DrmHwc.h"
-#include "hwc2_device/HwcDisplay.h"
+#include "hwc/HwcDisplay.h"
+#include "utils/thread_annotations.h"
 
 namespace aidl::android::hardware::graphics::composer3::impl {
 
 class Hwc3Display : public ::android::FrontendDisplayBase {
  public:
-  bool must_validate = false;
   // Desired present time for a composition that has been validated but not
   // yet presented. nullopt means it should be presented at the next vsync.
   std::optional<int64_t> desired_present_time = std::nullopt;
@@ -41,18 +41,28 @@ class DrmHwcThree : public ::android::DrmHwc {
   void Init(std::shared_ptr<IComposerCallback> callback);
 
   // DrmHwcInterface
-  void SendVsyncEventToClient(hwc2_display_t display_id, int64_t timestamp,
+  void SendVsyncEventToClient(::android::DisplayHandle display_handle,
+                              int64_t timestamp,
                               uint32_t vsync_period) const override;
   void SendVsyncPeriodTimingChangedEventToClient(
-      hwc2_display_t display_id, int64_t timestamp) const override;
-  void SendRefreshEventToClient(uint64_t display_id) override;
-  void SendHotplugEventToClient(hwc2_display_t display_id,
+      ::android::DisplayHandle display_handle,
+      int64_t timestamp) const override;
+  void SendRefreshEventToClient(
+      ::android::DisplayHandle display_handle) override;
+  void SendHotplugEventToClient(::android::DisplayHandle display_handle,
                                 DrmHwc::DisplayStatus display_status) override;
 
   static auto GetHwc3Display(::android::HwcDisplay& display)
       -> std::shared_ptr<Hwc3Display>;
 
+  auto GetMustValidateDisplay(::android::DisplayHandle display_handle) -> bool;
+  void ClearMustValidateDisplay(::android::DisplayHandle display_handle);
+
  private:
   std::shared_ptr<IComposerCallback> composer_callback_;
+
+  std::mutex must_validate_lock_;
+  std::set<::android::DisplayHandle> must_validate_
+      GUARDED_BY(must_validate_lock_);
 };
 }  // namespace aidl::android::hardware::graphics::composer3::impl
diff --git a/hwc3/Utils.cpp b/hwc3/Utils.cpp
deleted file mode 100644
index adbd2fb..0000000
--- a/hwc3/Utils.cpp
+++ /dev/null
@@ -1,58 +0,0 @@
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
-#include "Utils.h"
-
-#include <hardware/hwcomposer2.h>
-
-#include "utils/log.h"
-
-namespace aidl::android::hardware::graphics::composer3 {
-
-hwc3::Error Hwc2toHwc3Error(HWC2::Error error) {
-  switch (error) {
-    case HWC2::Error::None:
-      return hwc3::Error::kNone;
-    case HWC2::Error::BadConfig:
-      return hwc3::Error::kBadConfig;
-    case HWC2::Error::BadDisplay:
-      return hwc3::Error::kBadDisplay;
-    case HWC2::Error::BadLayer:
-      return hwc3::Error::kBadLayer;
-    case HWC2::Error::BadParameter:
-      return hwc3::Error::kBadParameter;
-    case HWC2::Error::NoResources:
-      return hwc3::Error::kNoResources;
-    case HWC2::Error::NotValidated:
-      return hwc3::Error::kNotValidated;
-    case HWC2::Error::Unsupported:
-      return hwc3::Error::kUnsupported;
-    case HWC2::Error::SeamlessNotAllowed:
-      return hwc3::Error::kSeamlessNotAllowed;
-    case HWC2::Error::SeamlessNotPossible:
-      return hwc3::Error::kSeamlessNotPossible;
-    default:
-      ALOGE("Unknown HWC2 error. Could not translate to HWC3 error: %d",
-            static_cast<int32_t>(error));
-      return hwc3::Error::kUnsupported;
-  }
-}
-
-};  // namespace aidl::android::hardware::graphics::composer3
\ No newline at end of file
diff --git a/hwc3/Utils.h b/hwc3/Utils.h
index 89767c8..153494e 100644
--- a/hwc3/Utils.h
+++ b/hwc3/Utils.h
@@ -16,9 +16,7 @@
 
 #pragma once
 
-#include <aidl/android/hardware/graphics/common/Hdr.h>
 #include <aidl/android/hardware/graphics/composer3/IComposerClient.h>
-#include <hardware/hwcomposer2.h>
 #include <log/log.h>
 
 #include <cstdint>
@@ -44,8 +42,6 @@ enum class Error : int32_t {
 };
 }  // namespace hwc3
 
-hwc3::Error Hwc2toHwc3Error(HWC2::Error error);
-
 inline ndk::ScopedAStatus ToBinderStatus(hwc3::Error error) {
   if (error != hwc3::Error::kNone) {
     return ndk::ScopedAStatus::fromServiceSpecificError(
@@ -54,115 +50,4 @@ inline ndk::ScopedAStatus ToBinderStatus(hwc3::Error error) {
   return ndk::ScopedAStatus::ok();
 }
 
-inline ndk::ScopedAStatus ToBinderStatus(HWC2::Error error) {
-  return ToBinderStatus(Hwc2toHwc3Error(error));
-}
-
-inline int64_t Hwc2DisplayToHwc3(hwc2_display_t display) {
-  return static_cast<int64_t>(display);
-}
-
-inline int32_t Hwc2ConfigIdToHwc3(hwc2_config_t config_id) {
-  return static_cast<int32_t>(config_id);
-}
-
-inline hwc2_display_t Hwc3DisplayToHwc2(int64_t display) {
-  return static_cast<hwc2_display_t>(display);
-}
-
-inline hwc2_config_t Hwc3ConfigIdToHwc2(int32_t config_id) {
-  return static_cast<hwc2_config_t>(config_id);
-}
-
-// Values match up to HWC2_COMPOSITION_SIDEBAND, with HWC2 not supporting
-// newer values. static_cast in between shared values.
-// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/Composition.aidl
-// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;drc=d783cabd4d9bddb4b83f2dd38300b7598bb58b24;l=826
-inline Composition Hwc2CompositionTypeToHwc3(int32_t composition_type) {
-  if (composition_type < HWC2_COMPOSITION_INVALID ||
-      composition_type > HWC2_COMPOSITION_SIDEBAND) {
-    return Composition::INVALID;
-  }
-  return static_cast<Composition>(composition_type);
-}
-
-// Values for color modes match across HWC versions, so static cast is safe:
-// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/ColorMode.aidl
-// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.0.h;drc=7d940ae4afa450696afa25e07982f3a95e17e9b2;l=118
-// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.1.h;drc=7d940ae4afa450696afa25e07982f3a95e17e9b2;l=35
-inline ColorMode Hwc2ColorModeToHwc3(int32_t color_mode) {
-  return static_cast<ColorMode>(color_mode);
-}
-
-inline int32_t Hwc3ColorModeToHwc2(ColorMode color_mode) {
-  return static_cast<int32_t>(color_mode);
-}
-
-// Capabilities match up to DisplayCapability::AUTO_LOW_LATENCY_MODE, with hwc2
-// not defining capabilities beyond that.
-// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/DisplayCapability.aidl#28
-// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;drc=1a0e4a1698c7b080d6763cef9e16592bce75967e;l=418
-inline DisplayCapability Hwc2DisplayCapabilityToHwc3(
-    uint32_t display_capability) {
-  if (display_capability > HWC2_DISPLAY_CAPABILITY_AUTO_LOW_LATENCY_MODE) {
-    return DisplayCapability::INVALID;
-  }
-  return static_cast<DisplayCapability>(display_capability);
-}
-
-// Values match between hwc versions, so static cast is safe.
-// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/DisplayConnectionType.aidl
-// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;l=216;drc=d783cabd4d9bddb4b83f2dd38300b7598bb58b24;bpv=0;bpt=1
-inline DisplayConnectionType Hwc2DisplayConnectionTypeToHwc3(uint32_t type) {
-  if (type > HWC2_DISPLAY_CONNECTION_TYPE_EXTERNAL) {
-    // Arbitrarily return EXTERNAL in this case, which shouldn't happen.
-    // TODO: This will be cleaned up once hwc2<->hwc3 conversion is removed.
-    ALOGE("Unknown HWC2 connection type. Could not translate: %d", type);
-    return DisplayConnectionType::EXTERNAL;
-  }
-  return static_cast<DisplayConnectionType>(type);
-}
-
-// Values match, so static_cast is safe.
-// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/RenderIntent.aidl
-// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.1.h;drc=7d940ae4afa450696afa25e07982f3a95e17e9b2;l=37
-inline RenderIntent Hwc2RenderIntentToHwc3(int32_t intent) {
-  if (intent < HAL_RENDER_INTENT_COLORIMETRIC ||
-      intent > HAL_RENDER_INTENT_TONE_MAP_ENHANCE) {
-    ALOGE("Unknown HWC2 render intent. Could not translate: %d", intent);
-    return RenderIntent::COLORIMETRIC;
-  }
-  return static_cast<RenderIntent>(intent);
-}
-inline int32_t Hwc3RenderIntentToHwc2(RenderIntent render_intent) {
-  return static_cast<int32_t>(render_intent);
-}
-
-// Values match up to DOZE_SUSPEND.
-// https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/graphics/composer/aidl/android/hardware/graphics/composer3/PowerMode.aidl
-// https://cs.android.com/android/platform/superproject/main/+/main:hardware/libhardware/include_all/hardware/hwcomposer2.h;l=348;drc=d783cabd4d9bddb4b83f2dd38300b7598bb58b24
-inline int32_t Hwc3PowerModeToHwc2(PowerMode power_mode) {
-  if (power_mode > PowerMode::DOZE_SUSPEND) {
-    ALOGE("Unsupported HWC2 power mode. Could not translate: %d", power_mode);
-    return HWC2_POWER_MODE_ON;
-  }
-  return static_cast<int32_t>(power_mode);
-}
-
-// Values appear to match.
-// https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/graphics/common/aidl/android/hardware/graphics/common/Dataspace.aidl
-// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.0.h;l=43
-// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.1.h;l=22;drc=7d940ae4afa450696afa25e07982f3a95e17e9b2
-inline int32_t Hwc3DataspaceToHwc2(common::Dataspace dataspace) {
-  return static_cast<int32_t>(dataspace);
-}
-
-// Values appear to match.
-// https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/graphics/common/aidl/android/hardware/graphics/common/Hdr.aidl
-// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.0.h;l=130;drc=7d940ae4afa450696afa25e07982f3a95e17e9b2
-// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libsystem/include/system/graphics-base-v1.2.h;l=12;drc=af7be7616859f8e9e57710b9c37c66cf880a6643
-inline common::Hdr Hwc2HdrTypeToHwc3(int32_t hdr_type) {
-  return static_cast<common::Hdr>(hdr_type);
-}
-
 };  // namespace aidl::android::hardware::graphics::composer3
diff --git a/hwc3/meson.build b/hwc3/meson.build
index c525308..e6e14a9 100644
--- a/hwc3/meson.build
+++ b/hwc3/meson.build
@@ -4,7 +4,6 @@ src_hwc3 = files(
     'Composer.cpp',
     'DrmHwcThree.cpp',
     'service.cpp',
-    'Utils.cpp',
 )
 
 executable(
diff --git a/meson.build b/meson.build
index 3d5c9f0..c55cca2 100644
--- a/meson.build
+++ b/meson.build
@@ -15,6 +15,10 @@ src_common = files(
     'backend/BackendManager.cpp',
     'backend/Backend.cpp',
     'backend/BackendClient.cpp',
+    'hwc/HwcDisplayConfigs.cpp',
+    'hwc/HwcDisplay.cpp',
+    'hwc/HwcLayer.cpp',
+    'stats/CompositionStats.cpp',
     'utils/fd.cpp',
     'utils/LibdisplayEdidWrapper.cpp',
     'utils/properties.cpp',
@@ -23,9 +27,6 @@ src_common = files(
 srcs_hwc2_device = [
     'hwc2_device/hwc2_device.cpp',
     'hwc2_device/DrmHwcTwo.cpp',
-    'hwc2_device/HwcDisplayConfigs.cpp',
-    'hwc2_device/HwcDisplay.cpp',
-    'hwc2_device/HwcLayer.cpp',
 ]
 
 deps = [
diff --git a/stats/CompositionStats.cpp b/stats/CompositionStats.cpp
new file mode 100644
index 0000000..e964558
--- /dev/null
+++ b/stats/CompositionStats.cpp
@@ -0,0 +1,42 @@
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
+#include "stats/CompositionStats.h"
+
+namespace android {
+
+CompositionStats operator-(const CompositionStats& a,
+                           const CompositionStats& b) {
+  return {a.total_frames - b.total_frames,
+          a.total_pixops - b.total_pixops,
+          a.gpu_pixops - b.gpu_pixops,
+          a.failed_kms_validate - b.failed_kms_validate,
+          a.failed_kms_present - b.failed_kms_present,
+          a.frames_flattened - b.frames_flattened,
+          a.cursor_plane_frames - b.cursor_plane_frames,
+          a.failed_kms_cursor_validate - b.failed_kms_cursor_validate};
+}
+
+void CompositionStatsTracker::ReportStats(const Callback& callback) {
+  auto new_stats = provider_->PullCompositionStats();
+  for (auto& [display_handle, cumulative_stats] : new_stats) {
+    auto delta = cumulative_stats - previous_stats_[display_handle];
+    callback(display_handle, cumulative_stats, delta);
+  }
+  previous_stats_ = new_stats;
+}
+
+}  // namespace android
\ No newline at end of file
diff --git a/stats/CompositionStats.h b/stats/CompositionStats.h
new file mode 100644
index 0000000..aa65c91
--- /dev/null
+++ b/stats/CompositionStats.h
@@ -0,0 +1,73 @@
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
+#include <cstdint>
+#include <functional>
+#include <map>
+
+namespace android {
+
+struct CompositionStats {
+  uint32_t total_frames = 0;
+  uint64_t total_pixops = 0;
+  uint64_t gpu_pixops = 0;
+  uint32_t failed_kms_validate = 0;
+  uint32_t failed_kms_present = 0;
+  uint32_t frames_flattened = 0;
+  uint32_t cursor_plane_frames = 0;
+  uint32_t failed_kms_cursor_validate = 0;
+
+  // When adding new stats, update the operator- below as well as
+  // operator== and operator<< which are implemented in the unit test file.
+};
+
+// Used for calculating the delta between two CompositionStats.
+CompositionStats operator-(const CompositionStats& a,
+                           const CompositionStats& b);
+
+// Interface for a reporter of per-display CompositionStats.
+class CompositionStatsProvider {
+ public:
+  // Get cumulative stats per display.
+  virtual auto PullCompositionStats()
+      -> std::map<int64_t, CompositionStats> = 0;
+  virtual ~CompositionStatsProvider() = default;
+};
+
+// CompositionStatsTracker pulls stats from a CompositionStatsProvider on-demand
+// and keeps track of the previous stats state in order to calculate the deltas.
+class CompositionStatsTracker {
+ public:
+  // Arguments are the display ID, the cumulative stats, and the stats delta.
+  using Callback = std::function<void(int64_t display_handle,
+                                      const CompositionStats& cumulative,
+                                      const CompositionStats& delta)>;
+  explicit CompositionStatsTracker(CompositionStatsProvider* provider)
+      : provider_(provider) {
+  }
+
+  // Callback will be called for each display, with the cumulative
+  // stats and the stats delta from the previous invocation.
+  void ReportStats(const Callback& callback);
+
+ private:
+  CompositionStatsProvider* provider_;
+  std::map<int64_t, CompositionStats> previous_stats_;
+};
+
+}  // namespace android
diff --git a/stats/CompositionStatsTest.cpp b/stats/CompositionStatsTest.cpp
new file mode 100644
index 0000000..6ee2caf
--- /dev/null
+++ b/stats/CompositionStatsTest.cpp
@@ -0,0 +1,304 @@
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
+#include <functional>
+#include <map>
+#include <memory>
+
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+
+#include "stats/CompositionStats.h"
+
+using ::testing::Eq;
+using ::testing::NiceMock;
+using ::testing::Return;
+using ::testing::StrictMock;
+
+namespace android {
+
+// Equality operator to be used by Eq, ASSERT_EQ, etc. Needs to be static rather
+// than in anonymous namespace to ensure gmock can find it.
+static bool operator==(const CompositionStats& lhs,
+                       const CompositionStats& rhs) {
+  return lhs.total_frames == rhs.total_frames &&
+         lhs.total_pixops == rhs.total_pixops &&
+         lhs.gpu_pixops == rhs.gpu_pixops &&
+         lhs.failed_kms_validate == rhs.failed_kms_validate &&
+         lhs.failed_kms_present == rhs.failed_kms_present &&
+         lhs.frames_flattened == rhs.frames_flattened &&
+         lhs.cursor_plane_frames == rhs.cursor_plane_frames &&
+         lhs.failed_kms_cursor_validate == rhs.failed_kms_cursor_validate;
+}
+
+// Stream insertion operator for better gtest failure messages.
+static std::ostream& operator<<(std::ostream& os,
+                                const CompositionStats& stats) {
+  os << "CompositionStats { "
+     << "total_frames: " << stats.total_frames
+     << ", total_pixops: " << stats.total_pixops
+     << ", gpu_pixops: " << stats.gpu_pixops
+     << ", failed_kms_validate: " << stats.failed_kms_validate
+     << ", failed_kms_present: " << stats.failed_kms_present
+     << ", frames_flattened: " << stats.frames_flattened
+     << ", cursor_plane_frames: " << stats.cursor_plane_frames
+     << ", failed_kms_cursor_validate: " << stats.failed_kms_cursor_validate
+     << " }";
+  return os;
+}
+
+class MockCompositionStatsProvider : public CompositionStatsProvider {
+ public:
+  MOCK_METHOD((std::map<int64_t, CompositionStats>), PullCompositionStats, (),
+              (override));
+};
+
+// Helper class to facilitate passing std::function to the
+// CompositionStatsTracker and use gmock to validate expectations.
+class MockStatsCallback {
+ public:
+  // Set expectations on the Invoke mock method.
+  MOCK_METHOD(void, Invoke,
+              (int64_t, const CompositionStats&, const CompositionStats&), ());
+
+  // Pass this to CompositionStatsTracker::ReportStats.
+  CompositionStatsTracker::Callback AsStdFunction() {
+    return [this](int64_t id, const CompositionStats& c,
+                  const CompositionStats& d) { this->Invoke(id, c, d); };
+  }
+};
+
+class CompositionStatsTrackerTest : public ::testing::Test {
+ protected:
+  std::unique_ptr<NiceMock<MockCompositionStatsProvider>> mock_provider_;
+  std::unique_ptr<CompositionStatsTracker> tracker_;
+
+  void SetUp() override {
+    mock_provider_ = std::make_unique<NiceMock<MockCompositionStatsProvider>>();
+    tracker_ = std::make_unique<CompositionStatsTracker>(mock_provider_.get());
+  }
+
+  // Helper method to create sample stats. Actual values don't really matter.
+  CompositionStats CreateStats(uint32_t base) {
+    return CompositionStats{.total_frames = base,
+                            .total_pixops = base * 1000,
+                            .gpu_pixops = base * 500,
+                            .failed_kms_validate = base / 10,
+                            .failed_kms_present = base / 20,
+                            .frames_flattened = base / 5,
+                            .cursor_plane_frames = base / 2,
+                            .failed_kms_cursor_validate = base / 50};
+  }
+};
+
+// Initial call to ReportStats reports the same stats for cumulative and delta.
+TEST_F(CompositionStatsTrackerTest, ReportStatsInitialCall) {
+  const int64_t display_handle = 1;
+  CompositionStats current_stats = CreateStats(100);
+  std::map<int64_t, CompositionStats> provider_result = {
+      {display_handle, current_stats}};
+
+  StrictMock<MockStatsCallback> mock_callback;
+
+  EXPECT_CALL(*mock_provider_, PullCompositionStats())
+      .WillOnce(Return(provider_result));
+
+  // Expect that delta is same as cumulative.
+  EXPECT_CALL(mock_callback,
+              Invoke(Eq(display_handle), Eq(current_stats), Eq(current_stats)));
+
+  tracker_->ReportStats(mock_callback.AsStdFunction());
+}
+
+// Subsequent calls to ReportStats with no change in cumulative stats.
+TEST_F(CompositionStatsTrackerTest, ReportStatsSubsequentCallNoChange) {
+  const int64_t display_handle = 1;
+  CompositionStats stats = CreateStats(100);
+  std::map<int64_t, CompositionStats> provider_result = {
+      {display_handle, stats}};
+  CompositionStats zero_delta = {};
+
+  // Same provider result for both calls.
+  EXPECT_CALL(*mock_provider_, PullCompositionStats())
+      .WillRepeatedly(Return(provider_result));
+
+  StrictMock<MockStatsCallback> mock_callback;
+
+  // Initial call.
+  EXPECT_CALL(mock_callback, Invoke(Eq(display_handle), Eq(stats), Eq(stats)));
+  tracker_->ReportStats(mock_callback.AsStdFunction());
+
+  // Second call. Delta should be zero.
+  EXPECT_CALL(mock_callback,
+              Invoke(Eq(display_handle), Eq(stats), Eq(zero_delta)));
+  tracker_->ReportStats(mock_callback.AsStdFunction());
+}
+
+// Test that the delta is reported as expected.
+TEST_F(CompositionStatsTrackerTest, ReportStatsSubsequentCallWithChange) {
+  const int64_t display_handle = 1;
+  CompositionStats stats1 = CreateStats(100);
+  CompositionStats stats2 = CreateStats(150);
+  std::map<int64_t, CompositionStats> provider_result1 = {
+      {display_handle, stats1}};
+  std::map<int64_t, CompositionStats> provider_result2 = {
+      {display_handle, stats2}};
+  CompositionStats expected_delta = stats2 - stats1;
+
+  StrictMock<MockStatsCallback> mock_callback;
+
+  // First call with the initial stats.
+  EXPECT_CALL(*mock_provider_, PullCompositionStats())
+      .WillOnce(Return(provider_result1));
+  EXPECT_CALL(mock_callback,
+              Invoke(Eq(display_handle), Eq(stats1), Eq(stats1)));
+  tracker_->ReportStats(mock_callback.AsStdFunction());
+
+  // Second call with updated stats and non-trivial delta.
+  EXPECT_CALL(*mock_provider_, PullCompositionStats())
+      .WillOnce(Return(provider_result2));
+  EXPECT_CALL(mock_callback,
+              Invoke(Eq(display_handle), Eq(stats2), Eq(expected_delta)));
+  tracker_->ReportStats(mock_callback.AsStdFunction());
+}
+
+// Test that stats for multiple displays are reported correctly.
+TEST_F(CompositionStatsTrackerTest, ReportStatsMultipleDisplays) {
+  const int64_t display_handle1 = 10;
+  const int64_t display_handle2 = 20;
+  CompositionStats display1_stats1 = CreateStats(100);
+  CompositionStats display2_stats1 = CreateStats(200);
+  CompositionStats display1_stats2 = CreateStats(110);
+  CompositionStats display2_stats2 = CreateStats(250);
+
+  std::map<int64_t, CompositionStats> provider_result1 =
+      {{display_handle1, display1_stats1}, {display_handle2, display2_stats1}};
+  std::map<int64_t, CompositionStats> provider_result2 =
+      {{display_handle1, display1_stats2}, {display_handle2, display2_stats2}};
+
+  CompositionStats display1_expected_delta1 = display1_stats1;
+  CompositionStats display1_expected_delta2 = display1_stats2 - display1_stats1;
+  CompositionStats display2_expected_delta1 = display2_stats1;
+  CompositionStats display2_expected_delta2 = display2_stats2 - display2_stats1;
+
+  StrictMock<MockStatsCallback> mock_callback;
+
+  // Initial call. Ordering between displays doesn't matter.
+  EXPECT_CALL(*mock_provider_, PullCompositionStats())
+      .WillOnce(Return(provider_result1));
+  EXPECT_CALL(mock_callback, Invoke(Eq(display_handle1), Eq(display1_stats1),
+                                    Eq(display1_expected_delta1)));
+  EXPECT_CALL(mock_callback, Invoke(Eq(display_handle2), Eq(display2_stats1),
+                                    Eq(display2_expected_delta1)));
+  tracker_->ReportStats(mock_callback.AsStdFunction());
+
+  // Updated call. Ordering between displays doesn't matter.
+  EXPECT_CALL(*mock_provider_, PullCompositionStats())
+      .WillOnce(Return(provider_result2));
+  EXPECT_CALL(mock_callback, Invoke(Eq(display_handle1), Eq(display1_stats2),
+                                    Eq(display1_expected_delta2)));
+  EXPECT_CALL(mock_callback, Invoke(Eq(display_handle2), Eq(display2_stats2),
+                                    Eq(display2_expected_delta2)));
+  tracker_->ReportStats(mock_callback.AsStdFunction());
+}
+
+// No displays in the provider result.
+TEST_F(CompositionStatsTrackerTest, ReportStatsEmptyResult) {
+  std::map<int64_t, CompositionStats> empty_result = {};
+
+  // StrictMock will fail if there are any unexpected calls to Invoke.
+  StrictMock<MockStatsCallback> mock_callback;
+  EXPECT_CALL(*mock_provider_, PullCompositionStats())
+      .WillOnce(Return(empty_result));
+  tracker_->ReportStats(mock_callback.AsStdFunction());
+}
+
+// Display added in between calls to ReportStats.
+TEST_F(CompositionStatsTrackerTest, ReportStatsDisplayAdded) {
+  const int64_t display_handle1 = 10;
+  const int64_t display_handle2 = 20;
+  const CompositionStats display1_stats1 = CreateStats(100);
+  const CompositionStats display1_stats2 = CreateStats(110);
+  const CompositionStats display2_stats = CreateStats(50);
+
+  std::map<int64_t, CompositionStats> provider_result1 = {
+      {display_handle1, display1_stats1}};
+  std::map<int64_t, CompositionStats> provider_result2 =
+      {{display_handle1, display1_stats2}, {display_handle2, display2_stats}};
+
+  const CompositionStats display1_expected_delta1 = display1_stats1;
+  const CompositionStats display1_expected_delta2 = display1_stats2 -
+                                                    display1_stats1;
+  const CompositionStats display2_expected_delta = display2_stats;
+
+  StrictMock<MockStatsCallback> mock_callback;
+
+  // First call only contains display 1.
+  EXPECT_CALL(*mock_provider_, PullCompositionStats())
+      .WillOnce(Return(provider_result1));
+  EXPECT_CALL(mock_callback, Invoke(Eq(display_handle1), Eq(display1_stats1),
+                                    Eq(display1_expected_delta1)));
+  tracker_->ReportStats(mock_callback.AsStdFunction());
+
+  // Second call has both displays.
+  EXPECT_CALL(*mock_provider_, PullCompositionStats())
+      .WillOnce(Return(provider_result2));
+  EXPECT_CALL(mock_callback, Invoke(Eq(display_handle1), Eq(display1_stats2),
+                                    Eq(display1_expected_delta2)));
+  EXPECT_CALL(mock_callback, Invoke(Eq(display_handle2), Eq(display2_stats),
+                                    Eq(display2_expected_delta)));
+  tracker_->ReportStats(mock_callback.AsStdFunction());
+}
+
+// Display removed in between calls to ReportStats.
+TEST_F(CompositionStatsTrackerTest, ReportStatsDisplayRemoved) {
+  const int64_t display_handle1 = 10;
+  const int64_t display_handle2 = 20;
+  const CompositionStats display1_stats1 = CreateStats(100);
+  const CompositionStats display2_stats = CreateStats(200);
+  const CompositionStats display1_stats2 = CreateStats(110);
+
+  std::map<int64_t, CompositionStats> provider_result1 =
+      {{display_handle1, display1_stats1}, {display_handle2, display2_stats}};
+  std::map<int64_t, CompositionStats> provider_result2 = {
+      {display_handle1, display1_stats2}};
+
+  const CompositionStats display1_expected_delta1 = display1_stats1;
+  const CompositionStats display2_expected_delta = display2_stats;
+  const CompositionStats display1_expected_delta2 = display1_stats2 -
+                                                    display1_stats1;
+
+  StrictMock<MockStatsCallback> mock_callback;
+
+  // Initial call has both displays.
+  EXPECT_CALL(*mock_provider_, PullCompositionStats())
+      .WillOnce(Return(provider_result1));
+  EXPECT_CALL(mock_callback, Invoke(Eq(display_handle1), Eq(display1_stats1),
+                                    Eq(display1_expected_delta1)));
+  EXPECT_CALL(mock_callback, Invoke(Eq(display_handle2), Eq(display2_stats),
+                                    Eq(display2_expected_delta)));
+  tracker_->ReportStats(mock_callback.AsStdFunction());
+
+  // Second call has only display 1. StrictMock will fail if Invoke is called
+  // for display_handle2.
+  EXPECT_CALL(*mock_provider_, PullCompositionStats())
+      .WillOnce(Return(provider_result2));
+  EXPECT_CALL(mock_callback, Invoke(Eq(display_handle1), Eq(display1_stats2),
+                                    Eq(display1_expected_delta2)));
+  tracker_->ReportStats(mock_callback.AsStdFunction());
+}
+
+}  // namespace android
diff --git a/utils/EdidWrapper.h b/utils/EdidWrapper.h
index 651c284..1e00a6a 100644
--- a/utils/EdidWrapper.h
+++ b/utils/EdidWrapper.h
@@ -46,16 +46,9 @@ class EdidWrapper {
                                   float * /*min_luminance*/) {
     GetSupportedHdrTypes(types);
   };
-  virtual void GetColorModes(std::vector<Colormode> &color_modes) {
+  virtual void GetColorModes(std::vector<ColorMode> &color_modes) {
     color_modes.clear();
   };
-  virtual int GetDpiX() {
-    return -1;
-  }
-  virtual int GetDpiY() {
-    return -1;
-  }
-
   virtual auto GetBoundsMm() -> std::pair<int32_t, int32_t> {
     return {-1, -1};
   }
@@ -79,10 +72,7 @@ class LibdisplayEdidWrapper final : public EdidWrapper {
                           float *max_average_luminance,
                           float *min_luminance) override;
 
-  void GetColorModes(std::vector<Colormode> &color_modes) override;
-
-  auto GetDpiX() -> int override;
-  auto GetDpiY() -> int override;
+  void GetColorModes(std::vector<ColorMode> &color_modes) override;
 
   auto GetBoundsMm() -> std::pair<int32_t, int32_t> override;
 
@@ -90,8 +80,6 @@ class LibdisplayEdidWrapper final : public EdidWrapper {
   LibdisplayEdidWrapper(di_info *info) : info_(std::move(info)) {
   }
 
-  std::pair<int32_t, int32_t> GetDpi();
-
   di_info *info_{};
 };
 #endif
diff --git a/utils/LibdisplayEdidWrapper.cpp b/utils/LibdisplayEdidWrapper.cpp
index ad737a2..4545d29 100644
--- a/utils/LibdisplayEdidWrapper.cpp
+++ b/utils/LibdisplayEdidWrapper.cpp
@@ -64,9 +64,9 @@ void LibdisplayEdidWrapper::GetHdrCapabilities(
   *min_luminance = hdr_static_meta->desired_content_min_luminance;
 }
 
-void LibdisplayEdidWrapper::GetColorModes(std::vector<Colormode> &color_modes) {
+void LibdisplayEdidWrapper::GetColorModes(std::vector<ColorMode> &color_modes) {
   color_modes.clear();
-  color_modes.emplace_back(Colormode::kNative);
+  color_modes.emplace_back(ColorMode::kNative);
 
   const auto *hdr_static_meta = di_info_get_hdr_static_metadata(info_);
   const auto *colorimetries = di_info_get_supported_signal_colorimetry(info_);
@@ -74,35 +74,27 @@ void LibdisplayEdidWrapper::GetColorModes(std::vector<Colormode> &color_modes) {
   /* Rec. ITU-R BT.2020 constant luminance YCbCr */
   /* Rec. ITU-R BT.2020 non-constant luminance YCbCr */
   if (colorimetries->bt2020_cycc || colorimetries->bt2020_ycc)
-    color_modes.emplace_back(Colormode::kBt2020);
+    color_modes.emplace_back(ColorMode::kBt2020);
 
   /* Rec. ITU-R BT.2020 RGB */
   if (colorimetries->bt2020_rgb)
-    color_modes.emplace_back(Colormode::kDisplayBt2020);
+    color_modes.emplace_back(ColorMode::kDisplayBt2020);
 
   /* SMPTE ST 2113 RGB: P3D65 and P3DCI */
   if (colorimetries->st2113_rgb) {
-    color_modes.emplace_back(Colormode::kDciP3);
-    color_modes.emplace_back(Colormode::kDisplayP3);
+    color_modes.emplace_back(ColorMode::kDciP3);
+    color_modes.emplace_back(ColorMode::kDisplayP3);
   }
 
   /* Rec. ITU-R BT.2100 ICtCp HDR (with PQ and/or HLG) */
   if (colorimetries->ictcp) {
     if (hdr_static_meta->pq)
-      color_modes.emplace_back(Colormode::kBt2100Pq);
+      color_modes.emplace_back(ColorMode::kBt2100Pq);
     if (hdr_static_meta->hlg)
-      color_modes.emplace_back(Colormode::kBt2100Hlg);
+      color_modes.emplace_back(ColorMode::kBt2100Hlg);
   }
 }
 
-auto LibdisplayEdidWrapper::GetDpiX() -> int {
-  return GetDpi().first;
-}
-
-auto LibdisplayEdidWrapper::GetDpiY() -> int {
-  return GetDpi().second;
-}
-
 auto LibdisplayEdidWrapper::GetBoundsMm() -> std::pair<int32_t, int32_t> {
   const auto edid = di_info_get_edid(info_);
   const auto detailed_timing_defs = di_edid_get_detailed_timing_defs(edid);
@@ -118,28 +110,5 @@ auto LibdisplayEdidWrapper::GetBoundsMm() -> std::pair<int32_t, int32_t> {
   return {dtd->horiz_image_mm, dtd->vert_image_mm};
 }
 
-auto LibdisplayEdidWrapper::GetDpi() -> std::pair<int32_t, int32_t> {
-  static const int32_t kUmPerInch = 25400;
-  const auto edid = di_info_get_edid(info_);
-  const auto detailed_timing_defs = di_edid_get_detailed_timing_defs(edid);
-  const auto dtd = detailed_timing_defs[0];
-  if (dtd == nullptr || dtd->horiz_image_mm == 0 || dtd->vert_image_mm == 0) {
-    // try to fallback on display size if no dtd.
-    const auto screen_size = di_edid_get_screen_size(edid);
-    const auto standard_timings = di_edid_get_standard_timings(edid);
-    if (screen_size->width_cm <= 0 || standard_timings == nullptr) {
-      return {-1, -1};
-    }
-
-    // display size is more unreliable so use only horizontal dpi.
-    int32_t horiz_video = standard_timings[0]->horiz_video;
-    int32_t dpi = horiz_video * kUmPerInch / (screen_size->width_cm * 10);
-    return {dpi, dpi};
-  }
-
-  return {dtd->horiz_video * kUmPerInch / dtd->horiz_image_mm,
-          dtd->vert_video * kUmPerInch / dtd->vert_image_mm};
-}
-
 }  // namespace android
 #endif
diff --git a/utils/UEvent.h b/utils/UEvent.h
index 051b1fc..555700e 100644
--- a/utils/UEvent.h
+++ b/utils/UEvent.h
@@ -87,7 +87,7 @@ class UEvent {
       }
     }
 
-    return std::string(buffer);
+    return std::string(buffer, ret);
   }
 
   void Stop() {
diff --git a/utils/properties.cpp b/utils/properties.cpp
index a975822..e0c6d9c 100644
--- a/utils/properties.cpp
+++ b/utils/properties.cpp
@@ -15,6 +15,8 @@
  */
 
 #include "properties.h"
+#include <android-base/properties.h>
+#include <string>
 
 /**
  * @brief Determine if the "Present Not Reliable" property is enabled.
@@ -30,6 +32,12 @@ auto Properties::UseConfigGroups() -> bool {
   return (property_get_bool("ro.vendor.hwc.drm.use_config_groups", 0) != 0);
 }
 
+auto Properties::InternalDisplayNames() -> std::string {
+  char buf[PROPERTY_VALUE_MAX] = {};
+  property_get("vendor.hwc.drm.internal_display_names", buf, "");
+  return {buf};
+}
+
 auto Properties::UseOverlayPlanes() -> bool {
   return (property_get_bool("ro.vendor.hwc.use_overlay_planes", 1) != 0);
 }
diff --git a/utils/properties.h b/utils/properties.h
index 4df79eb..3fd5e56 100644
--- a/utils/properties.h
+++ b/utils/properties.h
@@ -74,10 +74,13 @@ auto inline property_get_bool(const char *key, int8_t default_value) -> int8_t {
 
 #endif
 
+#include <string>
+
 class Properties {
  public:
   static auto IsPresentFenceNotReliable() -> bool;
   static auto UseConfigGroups() -> bool;
+  static auto InternalDisplayNames() -> std::string;
   static auto UseOverlayPlanes() -> bool;
   static auto ScaleWithGpu() -> bool;
   static auto EnableVirtualDisplay() -> bool;
```

