```diff
diff --git a/.github/workflows/border_router.yml b/.github/workflows/border_router.yml
index 86d484ce..4b67f2bf 100644
--- a/.github/workflows/border_router.yml
+++ b/.github/workflows/border_router.yml
@@ -173,15 +173,15 @@ jobs:
       run: |
         export CI_ENV="$(bash <(curl -s https://codecov.io/env)) -e GITHUB_ACTIONS -e OTBR_COVERAGE"
         echo "CI_ENV=${CI_ENV}"
-        (cd third_party/openthread/repo && sudo -E ./script/test cert_suite ${{ matrix.cert_scripts }} || (sudo chmod a+r *.log *.json *.pcap && false))
+        (cd third_party/openthread/repo && sudo -E ./script/test cert_suite ${{ matrix.cert_scripts }} || (sudo chmod a+r ot_testing/* && false))
     - uses: actions/upload-artifact@v4
       if: ${{ failure() && steps.check_cache_result.outputs.cache-hit != 'true' }}
       with:
         name: thread-1-3-backbone-results
         path: |
-          third_party/openthread/repo/*.pcap
-          third_party/openthread/repo/*.json
-          third_party/openthread/repo/*.log
+          third_party/openthread/repo/ot_testing/*.pcap
+          third_party/openthread/repo/ot_testing/*.json
+          third_party/openthread/repo/ot_testing/*.log
     - name: Codecov
       if: ${{ success() && steps.check_cache_result.outputs.cache-hit != 'true' }}
       uses: codecov/codecov-action@v4
diff --git a/.github/workflows/documentation.yml b/.github/workflows/documentation.yml
index 639ba7b4..d9d9e62c 100644
--- a/.github/workflows/documentation.yml
+++ b/.github/workflows/documentation.yml
@@ -57,7 +57,7 @@ jobs:
         cmake -DBUILD_TESTING=OFF -DOTBR_DOC=ON -DOTBR_DBUS=ON ..
         make otbr-doc
     - name: Deploy
-      uses: peaceiris/actions-gh-pages@v3
+      uses: peaceiris/actions-gh-pages@v4
       with:
         github_token: ${{ secrets.GITHUB_TOKEN }}
         publish_dir: ./build-doc/doc/html
diff --git a/.github/workflows/macOS.yml b/.github/workflows/macOS.yml
index a99adde8..c67a75b1 100644
--- a/.github/workflows/macOS.yml
+++ b/.github/workflows/macOS.yml
@@ -54,14 +54,14 @@ jobs:
         rm -f /usr/local/bin/pydoc3*
         rm -f /usr/local/bin/python3*
         brew update
-        brew reinstall boost cmake cpputest dbus jsoncpp ninja protobuf@21 pkg-config
+        brew reinstall boost cmake dbus jsoncpp ninja protobuf@21 pkg-config
         brew upgrade node
     - name: Build
       run: |
         OTBR_OPTIONS="-DOTBR_BORDER_AGENT=OFF \
                       -DOTBR_MDNS=OFF \
-                      -DOTBR_ADVERTISING_PROXY=OFF \
-                      -DOTBR_DISCOVERY_PROXY=OFF \
+                      -DOTBR_SRP_ADVERTISING_PROXY=OFF \
+                      -DOTBR_DNSSD_DISCOVERY_PROXY=OFF \
                       -DOTBR_TREL=OFF \
                       -DOT_FIREWALL=OFF \
                       -DOTBR_DBUS=OFF" ./script/test build
diff --git a/.github/workflows/meshcop.yml b/.github/workflows/meshcop.yml
index 6bbc8503..eade0d45 100644
--- a/.github/workflows/meshcop.yml
+++ b/.github/workflows/meshcop.yml
@@ -60,6 +60,7 @@ jobs:
     - name: Build
       env:
         OTBR_MDNS: ${{ matrix.mdns }}
+        OTBR_COVERAGE: 1
       run: |
         script/bootstrap
         script/test build
diff --git a/.github/workflows/ncp_mode.yml b/.github/workflows/ncp_mode.yml
new file mode 100644
index 00000000..d5b1650e
--- /dev/null
+++ b/.github/workflows/ncp_mode.yml
@@ -0,0 +1,67 @@
+#
+#  Copyright (c) 2024, The OpenThread Authors.
+#  All rights reserved.
+#
+#  Redistribution and use in source and binary forms, with or without
+#  modification, are permitted provided that the following conditions are met:
+#  1. Redistributions of source code must retain the above copyright
+#     notice, this list of conditions and the following disclaimer.
+#  2. Redistributions in binary form must reproduce the above copyright
+#     notice, this list of conditions and the following disclaimer in the
+#     documentation and/or other materials provided with the distribution.
+#  3. Neither the name of the copyright holder nor the
+#     names of its contributors may be used to endorse or promote products
+#     derived from this software without specific prior written permission.
+#
+#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+#  POSSIBILITY OF SUCH DAMAGE.
+#
+
+name: NcpMode
+
+on:
+  push:
+    branches-ignore:
+      - 'dependabot/**'
+  pull_request:
+    branches:
+      - 'main'
+
+concurrency:
+  group: ${{ github.workflow }}-${{ github.event.pull_request.number || (github.repository == 'openthread/ot-br-posix' && github.run_id) || github.ref }}
+  cancel-in-progress: true
+
+jobs:
+
+  ncp_mode:
+    runs-on: ubuntu-22.04
+    strategy:
+      fail-fast: false
+      matrix:
+        mdns: ["mDNSResponder", "avahi"]
+    env:
+        BUILD_TARGET: check
+        OTBR_MDNS: ${{ matrix.mdns }}
+        OTBR_COVERAGE: 1
+    steps:
+    - uses: actions/checkout@v4
+      with:
+        submodules: true
+    - name: Bootstrap
+      run: tests/scripts/bootstrap.sh
+    - name: Build
+      run: |
+        OTBR_BUILD_DIR="./build/temp" script/cmake-build -DCMAKE_BUILD_TYPE=Debug -DOT_THREAD_VERSION=1.3 -DOTBR_COVERAGE=ON -DOTBR_DBUS=ON -DOTBR_FEATURE_FLAGS=ON -DOTBR_TELEMETRY_DATA_API=ON -DOTBR_WEB=ON -DOTBR_UNSECURE_JOIN=ON -DOTBR_TREL=ON
+    - name: Run
+      run: OTBR_VERBOSE=1 OTBR_TOP_BUILDDIR="./build/temp" script/test ncp_mode
+    - name: Codecov
+      uses: codecov/codecov-action@v4
diff --git a/.lgtm.yml b/.lgtm.yml
index db582a3c..a9812dd0 100644
--- a/.lgtm.yml
+++ b/.lgtm.yml
@@ -36,7 +36,6 @@ extraction:
         - libboost-dev
         - libboost-filesystem-dev
         - libboost-system-dev
-        - libcpputest-dev
         - libdbus-1-dev
         - libjsoncpp-dev
         - ninja-build
diff --git a/Android.bp b/Android.bp
index fbd9ebd3..48a5304d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -130,6 +130,7 @@ cc_defaults {
         // will never run on Android U- devices.
         "-Wno-unguarded-availability",
 
+        "-DOTBR_ENABLE_PLATFORM_ANDROID=1",
         "-DOTBR_CONFIG_ANDROID_PROPERTY_ENABLE=1",
         "-DOTBR_CONFIG_ANDROID_VERSION_HEADER_ENABLE=1",
         "-DOTBR_CONFIG_FILE=\"src/android/otbr-config-android.h\"",
@@ -156,6 +157,7 @@ cc_defaults {
         "-DOTBR_ENABLE_DNS_UPSTREAM_QUERY=0",
         "-DOTBR_ENABLE_DHCP6_PD=0",
         "-DOTBR_ENABLE_TREL=0",
+        "-DOTBR_ENABLE_EPSKC=0",
     ],
 
     srcs: [
@@ -165,17 +167,23 @@ cc_defaults {
         "src/android/otdaemon_telemetry.cpp",
         "src/backbone_router/backbone_agent.cpp",
         "src/border_agent/border_agent.cpp",
-        "src/ncp/ncp_openthread.cpp",
-        "src/sdp_proxy/advertising_proxy.cpp",
-        "src/sdp_proxy/discovery_proxy.cpp",
         "src/common/code_utils.cpp",
         "src/common/dns_utils.cpp",
         "src/common/logging.cpp",
-        "src/common/mainloop.cpp",
         "src/common/mainloop_manager.cpp",
+        "src/common/mainloop.cpp",
         "src/common/task_runner.cpp",
         "src/common/types.cpp",
         "src/mdns/mdns.cpp",
+        "src/ncp/async_task.cpp",
+        "src/ncp/ncp_host.cpp",
+        "src/ncp/ncp_spinel.cpp",
+        "src/ncp/posix/netif_linux.cpp",
+        "src/ncp/posix/netif.cpp",
+        "src/ncp/rcp_host.cpp",
+        "src/ncp/thread_host.cpp",
+        "src/sdp_proxy/advertising_proxy.cpp",
+        "src/sdp_proxy/discovery_proxy.cpp",
         "src/utils/crc16.cpp",
         "src/utils/dns_utils.cpp",
         "src/utils/hex.cpp",
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 4fefd279..d31b2096 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -118,7 +118,6 @@ if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
     include(CTest)
 
     if(BUILD_TESTING)
-        pkg_check_modules(CPPUTEST cpputest REQUIRED)
         add_subdirectory(tests)
     endif()
 
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 776c5302..b51407e7 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -2,6 +2,9 @@
   "presubmit": [
     {
       "name": "CtsThreadNetworkTestCases"
+    },
+    {
+      "name": "ThreadNetworkIntegrationTests"
     }
   ],
   "postsubmit": [
diff --git a/etc/cmake/options.cmake b/etc/cmake/options.cmake
index 89c72e0c..4b6c0bb7 100644
--- a/etc/cmake/options.cmake
+++ b/etc/cmake/options.cmake
@@ -108,6 +108,12 @@ if(OTBR_TREL)
     target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_TREL=1)
 endif()
 
+option(OTBR_EPSKC "Enable ephemeral PSKc" ON)
+if (OTBR_EPSKC)
+    target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_EPSKC=1)
+else()
+    target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_EPSKC=0)
+endif()
 
 option(OTBR_WEB "Enable Web GUI" OFF)
 
diff --git a/etc/docker/Dockerfile b/etc/docker/Dockerfile
index 08f160c8..b4eed1f9 100644
--- a/etc/docker/Dockerfile
+++ b/etc/docker/Dockerfile
@@ -73,17 +73,13 @@ ENV OTBR_DOCKER_DEPS git ca-certificates
 
 # Required and installed during build (script/bootstrap), could be removed
 ENV OTBR_BUILD_DEPS apt-utils build-essential psmisc ninja-build cmake wget ca-certificates \
-  libreadline-dev libncurses-dev libcpputest-dev libdbus-1-dev libavahi-common-dev \
+  libreadline-dev libncurses-dev libdbus-1-dev libavahi-common-dev \
   libavahi-client-dev libboost-dev libboost-filesystem-dev libboost-system-dev \
   libnetfilter-queue-dev
 
 # Required for OpenThread Backbone CI
 ENV OTBR_OT_BACKBONE_CI_DEPS curl lcov wget build-essential python3-dbus python3-zeroconf socat
 
-# Required and installed during build (script/bootstrap) when RELEASE=1, could be removed
-ENV OTBR_NORELEASE_DEPS \
-  cpputest-dev
-
 RUN apt-get update \
   && apt-get install --no-install-recommends -y $OTBR_DOCKER_REQS $OTBR_DOCKER_DEPS \
   && ([ "${OT_BACKBONE_CI}" != "1" ] || apt-get install --no-install-recommends -y $OTBR_OT_BACKBONE_CI_DEPS) \
@@ -107,7 +103,6 @@ RUN ([ "${DNS64}" = "0" ] || chmod 644 /etc/bind/named.conf.options) \
     && mv /tmp/etc . \
     && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false $OTBR_DOCKER_DEPS \
     && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false $OTBR_BUILD_DEPS  \
-    && ([ "${RELEASE}" = 1 ] ||  apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false "$OTBR_NORELEASE_DEPS";) \
     && rm -rf /var/lib/apt/lists/* \
     && rm -rf /tmp/* \
   ))
diff --git a/etc/docker/docker_entrypoint.sh b/etc/docker/docker_entrypoint.sh
index 1addb735..5b3439e5 100755
--- a/etc/docker/docker_entrypoint.sh
+++ b/etc/docker/docker_entrypoint.sh
@@ -58,6 +58,11 @@ function parse_args()
                 shift
                 shift
                 ;;
+            --debug-level)
+                DEBUG_LEVEL=$2
+                shift
+                shift
+                ;;
             *)
                 shift
                 ;;
@@ -81,12 +86,14 @@ parse_args "$@"
 [ -n "$TUN_INTERFACE_NAME" ] || TUN_INTERFACE_NAME="wpan0"
 [ -n "$BACKBONE_INTERFACE" ] || BACKBONE_INTERFACE="eth0"
 [ -n "$NAT64_PREFIX" ] || NAT64_PREFIX="64:ff9b::/96"
+[ -n "$DEBUG_LEVEL" ] || DEBUG_LEVEL="7"
 
 echo "RADIO_URL:" $RADIO_URL
 echo "TREL_URL:" "$TREL_URL"
 echo "TUN_INTERFACE_NAME:" $TUN_INTERFACE_NAME
 echo "BACKBONE_INTERFACE: $BACKBONE_INTERFACE"
 echo "NAT64_PREFIX:" $NAT64_PREFIX
+echo "DEBUG_LEVEL:" $DEBUG_LEVEL
 
 NAT64_PREFIX=${NAT64_PREFIX/\//\\\/}
 TAYGA_CONF=/etc/tayga.conf
@@ -96,8 +103,8 @@ BIND_CONF_OPTIONS=/etc/bind/named.conf.options
 ! test -f $BIND_CONF_OPTIONS || sed -i "s/dns64.*$/dns64 $NAT64_PREFIX {};/" $BIND_CONF_OPTIONS
 sed -i "s/$INFRA_IF_NAME/$BACKBONE_INTERFACE/" /etc/sysctl.d/60-otbr-accept-ra.conf
 
-echo "OTBR_AGENT_OPTS=\"-I $TUN_INTERFACE_NAME -B $BACKBONE_INTERFACE -d7 $RADIO_URL $TREL_URL\"" >/etc/default/otbr-agent
-echo "OTBR_WEB_OPTS=\"-I $TUN_INTERFACE_NAME -d7 -p 80\"" >/etc/default/otbr-web
+echo "OTBR_AGENT_OPTS=\"-I $TUN_INTERFACE_NAME -B $BACKBONE_INTERFACE -d${DEBUG_LEVEL} $RADIO_URL $TREL_URL\"" >/etc/default/otbr-agent
+echo "OTBR_WEB_OPTS=\"-I $TUN_INTERFACE_NAME -d${DEBUG_LEVEL} -p 80\"" >/etc/default/otbr-web
 
 /app/script/server
 
diff --git a/etc/openwrt/openthread-br/Makefile b/etc/openwrt/openthread-br/Makefile
index cf0fdfb4..a9199378 100644
--- a/etc/openwrt/openthread-br/Makefile
+++ b/etc/openwrt/openthread-br/Makefile
@@ -52,7 +52,7 @@ CMAKE_OPTIONS+= \
 	-DOT_FIREWALL=ON \
 	-DOT_POSIX_SETTINGS_PATH=\"/etc/openthread\" \
 	-DOT_READLINE=OFF \
-	-DOTBR_NAT64=ON \
+	-DOTBR_NAT64=OFF \
 	-DNAT64_SERVICE=\"openthread\"
 
 TARGET_CFLAGS += -DOPENTHREAD_POSIX_CONFIG_DAEMON_SOCKET_BASENAME=\\\"/var/run/openthread-%s\\\"
diff --git a/script/_initrc b/script/_initrc
index 2ff3c849..7ba2c1eb 100644
--- a/script/_initrc
+++ b/script/_initrc
@@ -83,6 +83,39 @@ without()
     ! with "$1"
 }
 
+HAVE_SYSTEMCTL=0
+if have systemctl; then
+    HAVE_SYSTEMCTL=1
+fi
+HAVE_SERVICE=0
+if have service; then
+    HAVE_SERVICE=1
+fi
+
+start_service()
+{
+    local service_name=$1
+    if [[ ${HAVE_SYSTEMCTL} == 1 ]]; then
+        systemctl is-active "$service_name" || sudo systemctl start "$service_name" || die "Failed to start $service_name!"
+    elif [[ ${HAVE_SERVICE} == 1 ]]; then
+        sudo service "$service_name" status || sudo service "$service_name" start || echo "Failed to start $service_name!"
+    else
+        die 'Unable to find service manager. Try script/console to start in console mode!'
+    fi
+}
+
+stop_service()
+{
+    local service_name=$1
+    if $HAVE_SYSTEMCTL; then
+        systemctl is-active "$service_name" && sudo systemctl stop "$service_name" || echo "Failed to stop $service_name!"
+    elif $HAVE_SERVICE; then
+        sudo service "$service_name" status && sudo service "$service_name" stop || echo "Failed to stop $service_name!"
+    else
+        die 'Unable to find service manager. Try script/console to stop in console mode!'
+    fi
+}
+
 # Platform information is needed to load hooks and default settings.
 
 if [[ ! ${PLATFORM+x} ]]; then
diff --git a/script/bootstrap b/script/bootstrap
index 67d194b1..6cfb7194 100755
--- a/script/bootstrap
+++ b/script/bootstrap
@@ -37,6 +37,10 @@ NAT64_SERVICE="${NAT64_SERVICE:-openthread}"
 
 FIREWALL="${FIREWALL:-1}"
 
+OTBR_MDNS="${OTBR_MDNS:-mDNSResponder}"
+OT_BACKBONE_CI="${OT_BACKBONE_CI:-0}"
+REFERENCE_DEVICE="${REFERENCE_DEVICE:-0}"
+
 install_packages_apt()
 {
     sudo apt-get update
@@ -49,15 +53,21 @@ install_packages_apt()
 
     sudo apt-get install --no-install-recommends -y build-essential ninja-build cmake
 
-    with RELEASE || sudo apt-get install --no-install-recommends -y libcpputest-dev
-
     sudo apt-get install --no-install-recommends -y rsyslog
 
     # For DBus server
-    sudo apt-get install --no-install-recommends -y libdbus-1-dev
+    sudo apt-get install --no-install-recommends -y dbus libdbus-1-dev
 
     # mDNS
-    sudo apt-get install --no-install-recommends -y libavahi-client3 libavahi-common-dev libavahi-client-dev avahi-daemon
+    sudo apt-get install --no-install-recommends -y libavahi-client3 libavahi-common-dev libavahi-client-dev
+
+    # Thread Certification tests require Avahi to publish records for tests. Since the
+    # same image is used for all tests this needs to be installed here. Additionally
+    # Avahi should be included for reference device builds.
+    if [[ ${OTBR_MDNS} == "avahi" || ${OT_BACKBONE_CI} == 1 || ${REFERENCE_DEVICE} == 1 ]]; then
+        sudo apt-get install --no-install-recommends -y avahi-daemon
+    fi
+
     (MDNS_RESPONDER_SOURCE_NAME=mDNSResponder-1790.80.10 \
         && MDNS_RESPONDER_PATCH_PATH=$(realpath "$(dirname "$0")"/../third_party/mDNSResponder) \
         && cd /tmp \
@@ -147,7 +157,7 @@ install_packages_rpm()
 
 install_packages_brew()
 {
-    brew install boost cmake cpputest dbus jsoncpp ninja
+    brew install boost cmake dbus jsoncpp ninja
 }
 
 install_packages_source()
diff --git a/script/clang-format b/script/clang-format
index e31466d2..bd1120ee 100755
--- a/script/clang-format
+++ b/script/clang-format
@@ -43,7 +43,7 @@ if command -v clang-format-14 >/dev/null; then
     alias clang-format=clang-format-14
 elif command -v clang-format >/dev/null; then
     case "$(clang-format --version)" in
-        "$CLANG_FORMAT_VERSION"*) ;;
+        *"$CLANG_FORMAT_VERSION"*) ;;
 
         *)
             die "$(clang-format --version); clang-format 14.0 required"
diff --git a/script/make-aosp-pretty.sh b/script/make-aosp-pretty.sh
new file mode 120000
index 00000000..7c0ee91c
--- /dev/null
+++ b/script/make-aosp-pretty.sh
@@ -0,0 +1 @@
+../../../packages/modules/Connectivity/thread/scripts/make-pretty.sh
\ No newline at end of file
diff --git a/script/make-java-pretty b/script/make-java-pretty
deleted file mode 100755
index 27fa3f48..00000000
--- a/script/make-java-pretty
+++ /dev/null
@@ -1,8 +0,0 @@
-#!/usr/bin/env bash
-
-SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
-
-GOOGLE_JAVA_FORMAT=$SCRIPT_DIR/../../../prebuilts/tools/common/google-java-format/google-java-format
-
-$GOOGLE_JAVA_FORMAT --aosp -i $(find $SCRIPT_DIR/../src -name "*.java")
-$GOOGLE_JAVA_FORMAT --aosp -i $(find $SCRIPT_DIR/../tests -name "*.java")
diff --git a/script/server b/script/server
index b4eaedfb..d4742337 100755
--- a/script/server
+++ b/script/server
@@ -36,6 +36,10 @@
 . script/_dns64
 . script/_firewall
 
+OTBR_MDNS="${OTBR_MDNS:-mDNSResponder}"
+OT_BACKBONE_CI="${OT_BACKBONE_CI:-0}"
+REFERENCE_DEVICE="${REFERENCE_DEVICE:-0}"
+
 startup()
 {
     # shellcheck source=/dev/null
@@ -44,23 +48,21 @@ startup()
     nat64_start || die 'Failed to start NAT64!'
     dns64_start || die 'Failed to start DNS64!'
     firewall_start || die 'Failed to start firewall'
-    if have systemctl; then
-        systemctl is-active rsyslog || sudo systemctl start rsyslog || die 'Failed to start rsyslog!'
-        systemctl is-active dbus || sudo systemctl start dbus || die 'Failed to start dbus!'
-        systemctl is-active avahi-daemon || sudo systemctl start avahi-daemon || die 'Failed to start avahi!'
-        without WEB_GUI || systemctl is-active otbr-web || sudo systemctl start otbr-web || die 'Failed to start otbr-web!'
-        systemctl is-active otbr-agent || sudo systemctl start otbr-agent || die 'Failed to start otbr-agent!'
-    elif have service; then
-        sudo service rsyslog status || sudo service rsyslog start || die 'Failed to start rsyslog!'
-        sudo service dbus status || sudo service dbus start || die 'Failed to start dbus!'
-        # Tolerate the mdns failure as it is installed for only CI docker.
+
+    start_service rsyslog
+    start_service dbus
+    # Thread Certification tests require Avahi to publish records for tests. Since the
+    # same image is used for all tests Avahi needs to be started here and if
+    # building a reference device.
+    if [[ ${OTBR_MDNS} == "avahi" || ${OT_BACKBONE_CI} == 1 || ${REFERENCE_DEVICE} == 1 ]]; then
+        start_service avahi-daemon
+    fi
+    if have service; then
         sudo service mdns status || sudo service mdns start || echo "service mdns is not available!"
-        sudo service avahi-daemon status || sudo service avahi-daemon start || die 'Failed to start avahi!'
-        sudo service otbr-agent status || sudo service otbr-agent start || die 'Failed to start otbr-agent!'
-        without WEB_GUI || sudo service otbr-web status || sudo service otbr-web start || die 'Failed to start otbr-web!'
-    else
-        die 'Unable to find service manager. Try script/console to start in console mode!'
     fi
+    without WEB_GUI || start_service otbr-web
+    start_service otbr-agent
+
     # shellcheck source=/dev/null
     . "$AFTER_HOOK"
 }
@@ -70,22 +72,17 @@ shutdown()
     nat64_stop || echo 'Failed to stop NAT64!'
     dns64_stop || echo 'Failed to stop DNS64!'
     firewall_stop || echo 'Failed to stop firewall'
-    if have systemctl; then
-        systemctl is-active rsyslog && sudo systemctl stop rsyslog || echo 'Failed to stop rsyslog!'
-        systemctl is-active dbus && sudo systemctl stop dbus || echo 'Failed to stop dbus!'
+
+    stop_service rsyslog
+    stop_service dbus
+    if [[ ${OTBR_MDNS} == "avahi" || ${OT_BACKBONE_CI} == 1 || ${REFERENCE_DEVICE} == 1 ]]; then
         systemctl is-active avahi-daemon && sudo systemctl stop avahi-daemon || echo 'Failed to stop avahi!'
-        without WEB_GUI || systemctl is-active otbr-web && sudo systemctl stop otbr-web || echo 'Failed to stop otbr-web!'
-        systemctl is-active otbr-agent && sudo systemctl stop otbr-agent || echo 'Failed to stop otbr-agent!'
-    elif have service; then
-        sudo service rsyslog status && sudo service rsyslog stop || echo 'Failed to stop rsyslog!'
-        sudo service dbus status && sudo service dbus stop || echo 'Failed to stop dbus!'
-        sudo service mdns status && sudo service mdns stop || echo "service mdns is not available!"
-        sudo service avahi-daemon status && sudo service avahi-daemon stop || echo 'Failed to stop avahi!'
-        sudo service otbr-agent status && sudo service otbr-agent stop || echo 'Failed to stop otbr-agent!'
-        without WEB_GUI || sudo service otbr-web status && sudo service otbr-web stop || echo 'Failed to stop otbr-web!'
-    else
-        echo 'Unable to find service manager. Try script/console to stop in console mode!'
     fi
+    if have service; then
+        stop_service mdns
+    fi
+    without WEB_GUI || stop_service otbr-web
+    stop_service otbr-agent
 }
 
 main()
diff --git a/script/test b/script/test
index 93f642cb..31c19c45 100755
--- a/script/test
+++ b/script/test
@@ -62,7 +62,7 @@ readonly OTBR_REST
 OTBR_OPTIONS="${OTBR_OPTIONS-}"
 readonly OTBR_OPTIONS
 
-OTBR_TOP_BUILDDIR="${BUILD_DIR}/otbr"
+OTBR_TOP_BUILDDIR="${OTBR_TOP_BUILDDIR:-${BUILD_DIR}/otbr}"
 readonly OTBR_TOP_BUILDDIR
 
 #######################################
@@ -152,7 +152,8 @@ do_check()
 {
     (cd "${OTBR_TOP_BUILDDIR}" \
         && ninja && sudo ninja install \
-        && CTEST_OUTPUT_ON_FAILURE=1 ninja test)
+        && CTEST_OUTPUT_ON_FAILURE=1 ctest -LE sudo \
+        && CTEST_OUTPUT_ON_FAILURE=1 sudo ctest -L sudo) # Seperate running tests for sudo and non-sudo cases.
 }
 
 do_doxygen()
@@ -236,6 +237,9 @@ main()
             meshcop)
                 top_builddir="${OTBR_TOP_BUILDDIR}" print_result ./tests/scripts/meshcop
                 ;;
+            ncp_mode)
+                top_builddir="${OTBR_TOP_BUILDDIR}" print_result ./tests/scripts/ncp_mode
+                ;;
             openwrt)
                 print_result ./tests/scripts/openwrt
                 ;;
diff --git a/src/agent/application.cpp b/src/agent/application.cpp
index 16f4082d..c656d249 100644
--- a/src/agent/application.cpp
+++ b/src/agent/application.cpp
@@ -60,97 +60,60 @@ Application::Application(const std::string               &aInterfaceName,
 #else
     , mBackboneInterfaceName(aBackboneInterfaceNames.empty() ? "" : aBackboneInterfaceNames.front())
 #endif
-    , mNcp(mInterfaceName.c_str(), aRadioUrls, mBackboneInterfaceName, /* aDryRun */ false, aEnableAutoAttach)
+    , mHost(Ncp::ThreadHost::Create(mInterfaceName.c_str(),
+                                    aRadioUrls,
+                                    mBackboneInterfaceName,
+                                    /* aDryRun */ false,
+                                    aEnableAutoAttach))
 #if OTBR_ENABLE_MDNS
     , mPublisher(Mdns::Publisher::Create([this](Mdns::Publisher::State aState) { this->HandleMdnsState(aState); }))
 #endif
-#if OTBR_ENABLE_BORDER_AGENT
-    , mBorderAgent(mNcp, *mPublisher)
-#endif
-#if OTBR_ENABLE_BACKBONE_ROUTER
-    , mBackboneAgent(mNcp, aInterfaceName, mBackboneInterfaceName)
-#endif
-#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
-    , mAdvertisingProxy(mNcp, *mPublisher)
-#endif
-#if OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
-    , mDiscoveryProxy(mNcp, *mPublisher)
-#endif
-#if OTBR_ENABLE_TREL
-    , mTrelDnssd(mNcp, *mPublisher)
-#endif
-#if OTBR_ENABLE_OPENWRT
-    , mUbusAgent(mNcp)
-#endif
-#if OTBR_ENABLE_REST_SERVER
-    , mRestWebServer(mNcp, aRestListenAddress, aRestListenPort)
-#endif
 #if OTBR_ENABLE_DBUS_SERVER && OTBR_ENABLE_BORDER_AGENT
-    , mDBusAgent(mNcp, *mPublisher)
-#endif
-#if OTBR_ENABLE_VENDOR_SERVER
-    , mVendorServer(vendor::VendorServer::newInstance(*this))
+    , mDBusAgent(MakeUnique<DBus::DBusAgent>(*mHost, *mPublisher))
 #endif
 {
-    OTBR_UNUSED_VARIABLE(aRestListenAddress);
-    OTBR_UNUSED_VARIABLE(aRestListenPort);
+    if (mHost->GetCoprocessorType() == OT_COPROCESSOR_RCP)
+    {
+        CreateRcpMode(aRestListenAddress, aRestListenPort);
+    }
 }
 
 void Application::Init(void)
 {
-    mNcp.Init();
+    mHost->Init();
 
-#if OTBR_ENABLE_MDNS
-    mPublisher->Start();
-#endif
-#if OTBR_ENABLE_BORDER_AGENT
-// This is for delaying publishing the MeshCoP service until the correct
-// vendor name and OUI etc. are correctly set by BorderAgent::SetMeshCopServiceValues()
-#if OTBR_STOP_BORDER_AGENT_ON_INIT
-    mBorderAgent.SetEnabled(false);
-#else
-    mBorderAgent.SetEnabled(true);
-#endif
-#endif
-#if OTBR_ENABLE_BACKBONE_ROUTER
-    mBackboneAgent.Init();
-#endif
-#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
-    mAdvertisingProxy.SetEnabled(true);
-#endif
-#if OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
-    mDiscoveryProxy.SetEnabled(true);
-#endif
-#if OTBR_ENABLE_OPENWRT
-    mUbusAgent.Init();
-#endif
-#if OTBR_ENABLE_REST_SERVER
-    mRestWebServer.Init();
-#endif
-#if OTBR_ENABLE_DBUS_SERVER
-    mDBusAgent.Init();
-#endif
-#if OTBR_ENABLE_VENDOR_SERVER
-    mVendorServer->Init();
-#endif
+    switch (mHost->GetCoprocessorType())
+    {
+    case OT_COPROCESSOR_RCP:
+        InitRcpMode();
+        break;
+    case OT_COPROCESSOR_NCP:
+        InitNcpMode();
+        break;
+    default:
+        DieNow("Unknown coprocessor type!");
+        break;
+    }
+
+    otbrLogInfo("Co-processor version: %s", mHost->GetCoprocessorVersion());
 }
 
 void Application::Deinit(void)
 {
-#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
-    mAdvertisingProxy.SetEnabled(false);
-#endif
-#if OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
-    mDiscoveryProxy.SetEnabled(false);
-#endif
-#if OTBR_ENABLE_BORDER_AGENT
-    mBorderAgent.SetEnabled(false);
-#endif
-#if OTBR_ENABLE_MDNS
-    mPublisher->Stop();
-#endif
+    switch (mHost->GetCoprocessorType())
+    {
+    case OT_COPROCESSOR_RCP:
+        DeinitRcpMode();
+        break;
+    case OT_COPROCESSOR_NCP:
+        DeinitNcpMode();
+        break;
+    default:
+        DieNow("Unknown coprocessor type!");
+        break;
+    }
 
-    mNcp.Deinit();
+    mHost->Deinit();
 }
 
 otbrError Application::Run(void)
@@ -233,16 +196,16 @@ void Application::HandleMdnsState(Mdns::Publisher::State aState)
     OTBR_UNUSED_VARIABLE(aState);
 
 #if OTBR_ENABLE_BORDER_AGENT
-    mBorderAgent.HandleMdnsState(aState);
+    mBorderAgent->HandleMdnsState(aState);
 #endif
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
-    mAdvertisingProxy.HandleMdnsState(aState);
+    mAdvertisingProxy->HandleMdnsState(aState);
 #endif
 #if OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
-    mDiscoveryProxy.HandleMdnsState(aState);
+    mDiscoveryProxy->HandleMdnsState(aState);
 #endif
 #if OTBR_ENABLE_TREL
-    mTrelDnssd.HandleMdnsState(aState);
+    mTrelDnssd->HandleMdnsState(aState);
 #endif
 }
 
@@ -252,4 +215,101 @@ void Application::HandleSignal(int aSignal)
     signal(aSignal, SIG_DFL);
 }
 
+void Application::CreateRcpMode(const std::string &aRestListenAddress, int aRestListenPort)
+{
+    otbr::Ncp::RcpHost &rcpHost = static_cast<otbr::Ncp::RcpHost &>(*mHost);
+#if OTBR_ENABLE_BORDER_AGENT
+    mBorderAgent = MakeUnique<BorderAgent>(rcpHost, *mPublisher);
+#endif
+#if OTBR_ENABLE_BACKBONE_ROUTER
+    mBackboneAgent = MakeUnique<BackboneRouter::BackboneAgent>(rcpHost, mInterfaceName, mBackboneInterfaceName);
+#endif
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    mAdvertisingProxy = MakeUnique<AdvertisingProxy>(rcpHost, *mPublisher);
+#endif
+#if OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
+    mDiscoveryProxy = MakeUnique<Dnssd::DiscoveryProxy>(rcpHost, *mPublisher);
+#endif
+#if OTBR_ENABLE_TREL
+    mTrelDnssd = MakeUnique<TrelDnssd::TrelDnssd>(rcpHost, *mPublisher);
+#endif
+#if OTBR_ENABLE_OPENWRT
+    mUbusAgent = MakeUnique<ubus::UBusAgent>(rcpHost);
+#endif
+#if OTBR_ENABLE_REST_SERVER
+    mRestWebServer = MakeUnique<rest::RestWebServer>(rcpHost, aRestListenAddress, aRestListenPort);
+#endif
+#if OTBR_ENABLE_VENDOR_SERVER
+    mVendorServer = vendor::VendorServer::newInstance(*this);
+#endif
+
+    OT_UNUSED_VARIABLE(aRestListenAddress);
+    OT_UNUSED_VARIABLE(aRestListenPort);
+}
+
+void Application::InitRcpMode(void)
+{
+#if OTBR_ENABLE_MDNS
+    mPublisher->Start();
+#endif
+#if OTBR_ENABLE_BORDER_AGENT
+// This is for delaying publishing the MeshCoP service until the correct
+// vendor name and OUI etc. are correctly set by BorderAgent::SetMeshCopServiceValues()
+#if OTBR_STOP_BORDER_AGENT_ON_INIT
+    mBorderAgent->SetEnabled(false);
+#else
+    mBorderAgent->SetEnabled(true);
+#endif
+#endif
+#if OTBR_ENABLE_BACKBONE_ROUTER
+    mBackboneAgent->Init();
+#endif
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    mAdvertisingProxy->SetEnabled(true);
+#endif
+#if OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
+    mDiscoveryProxy->SetEnabled(true);
+#endif
+#if OTBR_ENABLE_OPENWRT
+    mUbusAgent->Init();
+#endif
+#if OTBR_ENABLE_REST_SERVER
+    mRestWebServer->Init();
+#endif
+#if OTBR_ENABLE_DBUS_SERVER
+    mDBusAgent->Init(*mBorderAgent);
+#endif
+#if OTBR_ENABLE_VENDOR_SERVER
+    mVendorServer->Init();
+#endif
+}
+
+void Application::DeinitRcpMode(void)
+{
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    mAdvertisingProxy->SetEnabled(false);
+#endif
+#if OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
+    mDiscoveryProxy->SetEnabled(false);
+#endif
+#if OTBR_ENABLE_BORDER_AGENT
+    mBorderAgent->SetEnabled(false);
+#endif
+#if OTBR_ENABLE_MDNS
+    mPublisher->Stop();
+#endif
+}
+
+void Application::InitNcpMode(void)
+{
+#if OTBR_ENABLE_DBUS_SERVER
+    mDBusAgent->Init(*mBorderAgent);
+#endif
+}
+
+void Application::DeinitNcpMode(void)
+{
+    /* empty */
+}
+
 } // namespace otbr
diff --git a/src/agent/application.hpp b/src/agent/application.hpp
index 2f92d694..a4a6d3eb 100644
--- a/src/agent/application.hpp
+++ b/src/agent/application.hpp
@@ -44,7 +44,7 @@
 #if OTBR_ENABLE_BORDER_AGENT
 #include "border_agent/border_agent.hpp"
 #endif
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 #if OTBR_ENABLE_BACKBONE_ROUTER
 #include "backbone_router/backbone_agent.hpp"
 #endif
@@ -132,7 +132,7 @@ public:
      *
      * @returns The OpenThread controller object.
      */
-    Ncp::ControllerOpenThread &GetNcp(void) { return mNcp; }
+    Ncp::ThreadHost &GetHost(void) { return *mHost; }
 
 #if OTBR_ENABLE_MDNS
     /**
@@ -154,7 +154,7 @@ public:
      */
     BorderAgent &GetBorderAgent(void)
     {
-        return mBorderAgent;
+        return *mBorderAgent;
     }
 #endif
 
@@ -166,7 +166,7 @@ public:
      */
     BackboneRouter::BackboneAgent &GetBackboneAgent(void)
     {
-        return mBackboneAgent;
+        return *mBackboneAgent;
     }
 #endif
 
@@ -178,7 +178,7 @@ public:
      */
     AdvertisingProxy &GetAdvertisingProxy(void)
     {
-        return mAdvertisingProxy;
+        return *mAdvertisingProxy;
     }
 #endif
 
@@ -190,7 +190,7 @@ public:
      */
     Dnssd::DiscoveryProxy &GetDiscoveryProxy(void)
     {
-        return mDiscoveryProxy;
+        return *mDiscoveryProxy;
     }
 #endif
 
@@ -202,7 +202,7 @@ public:
      */
     TrelDnssd::TrelDnssd &GetTrelDnssd(void)
     {
-        return mTrelDnssd;
+        return *mTrelDnssd;
     }
 #endif
 
@@ -214,7 +214,7 @@ public:
      */
     ubus::UBusAgent &GetUBusAgent(void)
     {
-        return mUbusAgent;
+        return *mUbusAgent;
     }
 #endif
 
@@ -226,7 +226,7 @@ public:
      */
     rest::RestWebServer &GetRestWebServer(void)
     {
-        return mRestWebServer;
+        return *mRestWebServer;
     }
 #endif
 
@@ -238,7 +238,7 @@ public:
      */
     DBus::DBusAgent &GetDBusAgent(void)
     {
-        return mDBusAgent;
+        return *mDBusAgent;
     }
 #endif
 
@@ -256,38 +256,45 @@ private:
 
     static void HandleSignal(int aSignal);
 
+    void CreateRcpMode(const std::string &aRestListenAddress, int aRestListenPort);
+    void InitRcpMode(void);
+    void DeinitRcpMode(void);
+
+    void InitNcpMode(void);
+    void DeinitNcpMode(void);
+
     std::string mInterfaceName;
 #if __linux__
     otbr::Utils::InfraLinkSelector mInfraLinkSelector;
 #endif
-    const char               *mBackboneInterfaceName;
-    Ncp::ControllerOpenThread mNcp;
+    const char                      *mBackboneInterfaceName;
+    std::unique_ptr<Ncp::ThreadHost> mHost;
 #if OTBR_ENABLE_MDNS
     std::unique_ptr<Mdns::Publisher> mPublisher;
 #endif
 #if OTBR_ENABLE_BORDER_AGENT
-    BorderAgent mBorderAgent;
+    std::unique_ptr<BorderAgent> mBorderAgent;
 #endif
 #if OTBR_ENABLE_BACKBONE_ROUTER
-    BackboneRouter::BackboneAgent mBackboneAgent;
+    std::unique_ptr<BackboneRouter::BackboneAgent> mBackboneAgent;
 #endif
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
-    AdvertisingProxy mAdvertisingProxy;
+    std::unique_ptr<AdvertisingProxy> mAdvertisingProxy;
 #endif
 #if OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
-    Dnssd::DiscoveryProxy mDiscoveryProxy;
+    std::unique_ptr<Dnssd::DiscoveryProxy> mDiscoveryProxy;
 #endif
 #if OTBR_ENABLE_TREL
-    TrelDnssd::TrelDnssd mTrelDnssd;
+    std::unique_ptr<TrelDnssd::TrelDnssd> mTrelDnssd;
 #endif
 #if OTBR_ENABLE_OPENWRT
-    ubus::UBusAgent mUbusAgent;
+    std::unique_ptr<ubus::UBusAgent> mUbusAgent;
 #endif
 #if OTBR_ENABLE_REST_SERVER
-    rest::RestWebServer mRestWebServer;
+    std::unique_ptr<rest::RestWebServer> mRestWebServer;
 #endif
 #if OTBR_ENABLE_DBUS_SERVER
-    DBus::DBusAgent mDBusAgent;
+    std::unique_ptr<DBus::DBusAgent> mDBusAgent;
 #endif
 #if OTBR_ENABLE_VENDOR_SERVER
     std::shared_ptr<vendor::VendorServer> mVendorServer;
diff --git a/src/agent/main.cpp b/src/agent/main.cpp
index 776c3e72..e47c9643 100644
--- a/src/agent/main.cpp
+++ b/src/agent/main.cpp
@@ -31,10 +31,6 @@
 #include <openthread-br/config.h>
 
 #include <algorithm>
-#include <fstream>
-#include <mutex>
-#include <sstream>
-#include <string>
 #include <vector>
 
 #include <assert.h>
@@ -47,7 +43,7 @@
 #include <openthread/logging.h>
 #include <openthread/platform/radio.h>
 
-#if __ANDROID__ && OTBR_CONFIG_ANDROID_PROPERTY_ENABLE
+#if OTBR_ENABLE_PLATFORM_ANDROID
 #include <cutils/properties.h>
 #endif
 
@@ -56,7 +52,13 @@
 #include "common/logging.hpp"
 #include "common/mainloop.hpp"
 #include "common/types.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/thread_host.hpp"
+
+#ifdef OTBR_ENABLE_PLATFORM_ANDROID
+#ifndef __ANDROID__
+#error "OTBR_ENABLE_PLATFORM_ANDROID can be enabled for only Android devices"
+#endif
+#endif
 
 static const char kDefaultInterfaceName[] = "wpan0";
 
@@ -79,7 +81,7 @@ enum
     OTBR_OPT_REST_LISTEN_PORT,
 };
 
-#ifndef __ANDROID__
+#ifndef OTBR_ENABLE_PLATFORM_ANDROID
 static jmp_buf sResetJump;
 #endif
 static otbr::Application *gApp = nullptr;
@@ -117,6 +119,7 @@ exit:
     return successful;
 }
 
+#ifndef OTBR_ENABLE_PLATFORM_ANDROID
 static constexpr char kAutoAttachDisableArg[] = "--auto-attach=0";
 static char           sAutoAttachDisableArgStorage[sizeof(kAutoAttachDisableArg)];
 
@@ -134,6 +137,7 @@ static std::vector<char *> AppendAutoAttachDisableArg(int argc, char *argv[])
 
     return args;
 }
+#endif
 
 static void PrintHelp(const char *aProgramName)
 {
@@ -161,7 +165,7 @@ static otbrLogLevel GetDefaultLogLevel(void)
 {
     otbrLogLevel level = OTBR_LOG_INFO;
 
-#if __ANDROID__ && OTBR_CONFIG_ANDROID_PROPERTY_ENABLE
+#if OTBR_ENABLE_PLATFORM_ANDROID
     char value[PROPERTY_VALUE_MAX];
 
     property_get("ro.build.type", value, "user");
@@ -176,17 +180,18 @@ static otbrLogLevel GetDefaultLogLevel(void)
 
 static void PrintRadioVersionAndExit(const std::vector<const char *> &aRadioUrls)
 {
-    otbr::Ncp::ControllerOpenThread ncpOpenThread{/* aInterfaceName */ "", aRadioUrls, /* aBackboneInterfaceName */ "",
-                                                  /* aDryRun */ true, /* aEnableAutoAttach */ false};
-    const char                     *radioVersion;
+    auto host = std::unique_ptr<otbr::Ncp::ThreadHost>(
+        otbr::Ncp::ThreadHost::Create(/* aInterfaceName */ "", aRadioUrls,
+                                      /* aBackboneInterfaceName */ "",
+                                      /* aDryRun */ true, /* aEnableAutoAttach */ false));
+    const char *coprocessorVersion;
 
-    ncpOpenThread.Init();
+    host->Init();
 
-    radioVersion = otPlatRadioGetVersionString(ncpOpenThread.GetInstance());
-    otbrLogNotice("Radio version: %s", radioVersion);
-    printf("%s\n", radioVersion);
+    coprocessorVersion = host->GetCoprocessorVersion();
+    printf("%s\n", coprocessorVersion);
 
-    ncpOpenThread.Deinit();
+    host->Deinit();
 
     exit(EXIT_SUCCESS);
 }
@@ -279,7 +284,7 @@ static int realmain(int argc, char *argv[])
 
     otbrLogInit(argv[0], logLevel, verbose, syslogDisable);
     otbrLogNotice("Running %s", OTBR_PACKAGE_VERSION);
-    otbrLogNotice("Thread version: %s", otbr::Ncp::ControllerOpenThread::GetThreadVersion());
+    otbrLogNotice("Thread version: %s", otbr::Ncp::RcpHost::GetThreadVersion());
     otbrLogNotice("Thread interface: %s", interfaceName);
 
     if (backboneInterfaceNames.empty())
@@ -327,7 +332,7 @@ void otPlatReset(otInstance *aInstance)
     gApp->Deinit();
     gApp = nullptr;
 
-#ifndef __ANDROID__
+#ifndef OTBR_ENABLE_PLATFORM_ANDROID
     longjmp(sResetJump, 1);
     assert(false);
 #else
@@ -339,7 +344,7 @@ void otPlatReset(otInstance *aInstance)
 
 int main(int argc, char *argv[])
 {
-#ifndef __ANDROID__
+#ifndef OTBR_ENABLE_PLATFORM_ANDROID
     if (setjmp(sResetJump))
     {
         std::vector<char *> args = AppendAutoAttachDisableArg(argc, argv);
diff --git a/src/android/aidl/com/android/server/thread/openthread/INsdDiscoverServiceCallback.aidl b/src/android/aidl/com/android/server/thread/openthread/INsdDiscoverServiceCallback.aidl
index 21de2d12..1587d3a1 100644
--- a/src/android/aidl/com/android/server/thread/openthread/INsdDiscoverServiceCallback.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/INsdDiscoverServiceCallback.aidl
@@ -30,7 +30,5 @@ package com.android.server.thread.openthread;
 
 /** Receives the information when a service instance is found/lost. */
 oneway interface INsdDiscoverServiceCallback {
-    void onServiceDiscovered(in String name,
-                             in String type,
-                             boolean isFound);
+    void onServiceDiscovered(in String name, in String type, boolean isFound);
 }
diff --git a/src/android/aidl/com/android/server/thread/openthread/INsdPublisher.aidl b/src/android/aidl/com/android/server/thread/openthread/INsdPublisher.aidl
index 74bec2fb..cc8b0341 100644
--- a/src/android/aidl/com/android/server/thread/openthread/INsdPublisher.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/INsdPublisher.aidl
@@ -29,10 +29,10 @@
 package com.android.server.thread.openthread;
 
 import com.android.server.thread.openthread.DnsTxtAttribute;
-import com.android.server.thread.openthread.INsdStatusReceiver;
 import com.android.server.thread.openthread.INsdDiscoverServiceCallback;
-import com.android.server.thread.openthread.INsdResolveServiceCallback;
 import com.android.server.thread.openthread.INsdResolveHostCallback;
+import com.android.server.thread.openthread.INsdResolveServiceCallback;
+import com.android.server.thread.openthread.INsdStatusReceiver;
 
 /**
  * The service which supports mDNS advertising and discovery by {@link NsdManager}.
@@ -57,14 +57,9 @@ oneway interface INsdPublisher {
      * @param listenerId the ID of the NsdManager.RegistrationListener which is used to
      *                             identify the registration
      */
-    void registerService(in @nullable String hostname,
-                        in String name,
-                        in String type,
-                        in List<String> subtypeList,
-                        int port,
-                        in List<DnsTxtAttribute> txt,
-                        in INsdStatusReceiver receiver,
-                        int listenerId);
+    void registerService(in @nullable String hostname, in String name, in String type,
+            in List<String> subtypeList, int port, in List<DnsTxtAttribute> txt,
+            in INsdStatusReceiver receiver, int listenerId);
 
     /**
      * Registers an mDNS host.
@@ -78,10 +73,8 @@ oneway interface INsdPublisher {
      * @param listenerId the ID of the NsdManager.RegistrationListener which is used to
      *                             identify the registration
      */
-    void registerHost(in String name,
-                      in List<String> addresses,
-                      in INsdStatusReceiver receiver,
-                      int listenerId);
+    void registerHost(in String name, in List<String> addresses, in INsdStatusReceiver receiver,
+            int listenerId);
 
     /**
      * Unregisters an mDNS service.
@@ -109,9 +102,7 @@ oneway interface INsdPublisher {
      * @param listenerId the ID of the NsdManager.DiscoveryListener which is used to identify the
      *                             service discovery operation
      */
-    void discoverService(in String type,
-                         in INsdDiscoverServiceCallback callback,
-                         int listenerId);
+    void discoverService(in String type, in INsdDiscoverServiceCallback callback, int listenerId);
 
     /**
      * Stops discovering services of a specific type.
@@ -136,10 +127,8 @@ oneway interface INsdPublisher {
      * @param listenerId the ID of the NsdManager.ServiceInfoCallback which is used to identify the
      *                             service resolution operation
      */
-    void resolveService(in String name,
-                        in String type,
-                        in INsdResolveServiceCallback callback,
-                        int listenerId);
+    void resolveService(
+            in String name, in String type, in INsdResolveServiceCallback callback, int listenerId);
 
     /**
      * Stops resolving an mDNS service instance.
@@ -162,9 +151,7 @@ oneway interface INsdPublisher {
      * @param listenerId the ID of DnsResolver.Callback which is used to identify the
      *                             host resolution operation
      */
-    void resolveHost(in String name,
-                     in INsdResolveHostCallback callback,
-                     int listenerId);
+    void resolveHost(in String name, in INsdResolveHostCallback callback, int listenerId);
 
     /**
      * Stops resolving an mDNS host.
diff --git a/src/android/aidl/com/android/server/thread/openthread/INsdResolveHostCallback.aidl b/src/android/aidl/com/android/server/thread/openthread/INsdResolveHostCallback.aidl
index 920a181e..8d3c8ed2 100644
--- a/src/android/aidl/com/android/server/thread/openthread/INsdResolveHostCallback.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/INsdResolveHostCallback.aidl
@@ -30,6 +30,5 @@ package com.android.server.thread.openthread;
 
 /** Receives the information of a resolved host. */
 oneway interface INsdResolveHostCallback {
-    void onHostResolved(in String name,
-                        in List<String> addresses);
+    void onHostResolved(in String name, in List<String> addresses);
 }
diff --git a/src/android/aidl/com/android/server/thread/openthread/INsdResolveServiceCallback.aidl b/src/android/aidl/com/android/server/thread/openthread/INsdResolveServiceCallback.aidl
index 48d7b5cc..0e964b5c 100644
--- a/src/android/aidl/com/android/server/thread/openthread/INsdResolveServiceCallback.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/INsdResolveServiceCallback.aidl
@@ -32,11 +32,6 @@ import com.android.server.thread.openthread.DnsTxtAttribute;
 
 /** Receives the information of a resolved service instance. */
 oneway interface INsdResolveServiceCallback {
-    void onServiceResolved(in String hostname,
-                           in String name,
-                           in String type,
-                           int port,
-                           in List<String> addresses,
-                           in List<DnsTxtAttribute> txt,
-                           int ttlSeconds);
+    void onServiceResolved(in String hostname, int netifIndex, in String name, in String type,
+            int port, in List<String> addresses, in List<DnsTxtAttribute> txt, int ttlSeconds);
 }
diff --git a/src/android/aidl/com/android/server/thread/openthread/IOtDaemon.aidl b/src/android/aidl/com/android/server/thread/openthread/IOtDaemon.aidl
index 60ee87b6..15478a77 100644
--- a/src/android/aidl/com/android/server/thread/openthread/IOtDaemon.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/IOtDaemon.aidl
@@ -28,16 +28,17 @@
 
 package com.android.server.thread.openthread;
 
-import android.os.ParcelFileDescriptor;
-
 import android.net.thread.ChannelMaxPower;
-import com.android.server.thread.openthread.BorderRouterConfigurationParcel;
+import android.os.ParcelFileDescriptor;
 import com.android.server.thread.openthread.IChannelMasksReceiver;
-import com.android.server.thread.openthread.Ipv6AddressInfo;
-import com.android.server.thread.openthread.IOtStatusReceiver;
-import com.android.server.thread.openthread.IOtDaemonCallback;
 import com.android.server.thread.openthread.INsdPublisher;
+import com.android.server.thread.openthread.IOtDaemonCallback;
+import com.android.server.thread.openthread.IOtOutputReceiver;
+import com.android.server.thread.openthread.IOtStatusReceiver;
+import com.android.server.thread.openthread.InfraLinkState;
+import com.android.server.thread.openthread.Ipv6AddressInfo;
 import com.android.server.thread.openthread.MeshcopTxtAttributes;
+import com.android.server.thread.openthread.OtDaemonConfiguration;
 
 /**
  * The OpenThread daemon service which provides access to the core Thread stack for
@@ -96,13 +97,9 @@ oneway interface IOtDaemon {
      * @param callback the callback for receiving OtDaemonState changes
      * @param countryCode 2 bytes country code (as defined in ISO 3166) to set
      */
-    void initialize(
-            in ParcelFileDescriptor tunFd,
-            in boolean enabled,
-            in INsdPublisher nsdPublisher,
-            in MeshcopTxtAttributes meshcopTxts,
-            in IOtDaemonCallback callback,
-            in String countryCode);
+    void initialize(in ParcelFileDescriptor tunFd, in boolean enabled,
+            in INsdPublisher nsdPublisher, in MeshcopTxtAttributes meshcopTxts,
+            in IOtDaemonCallback callback, in String countryCode);
 
     /** Terminates the ot-daemon process. */
     void terminate();
@@ -150,12 +147,12 @@ oneway interface IOtDaemon {
      */
     void leave(in IOtStatusReceiver receiver);
 
-    /** Migrates to the new network specified by {@code pendingOpDatasetTlvs}.
+    /**
+     * Migrates to the new network specified by {@code pendingOpDatasetTlvs}.
      *
      * @sa android.net.thread.ThreadNetworkController#scheduleMigration
      */
-    void scheduleMigration(
-        in byte[] pendingOpDatasetTlvs, in IOtStatusReceiver receiver);
+    void scheduleMigration(in byte[] pendingOpDatasetTlvs, in IOtStatusReceiver receiver);
 
     /**
      * Sets the country code.
@@ -166,14 +163,34 @@ oneway interface IOtDaemon {
     oneway void setCountryCode(in String countryCode, in IOtStatusReceiver receiver);
 
     /**
-     * Configures the Border Router features.
+     * Sets the configuration at ot-daemon.
      *
-     * @param brConfig the border router's configuration
+     * @param config the configuration
      * @param receiver the status receiver
      *
      */
-    oneway void configureBorderRouter(
-        in BorderRouterConfigurationParcel brConfig, in IOtStatusReceiver receiver);
+    oneway void setConfiguration(in OtDaemonConfiguration config, in IOtStatusReceiver receiver);
+
+    /**
+     * Sets the infrastructure network interface.
+     *
+     * @param interfaceName the infra network interface name
+     * @param icmp6Socket the ICMPv6 socket on the infrastructure network
+     * @param receiver the status receiver
+     *
+     */
+    oneway void setInfraLinkInterfaceName(in @nullable String interfaceName,
+            in ParcelFileDescriptor icmp6Socket, in IOtStatusReceiver receiver);
+
+    /**
+     * Sets the NAT64 prefix discovered from infrastructure link.
+     *
+     * @param nat64Prefix the NAT64 prefix discovered from the infra link
+     * @param receiver the status receiver
+     *
+     */
+    oneway void setInfraLinkNat64Prefix(
+            in @nullable String nat64Prefix, in IOtStatusReceiver receiver);
 
     /**
      * Gets the supported and preferred channel masks.
@@ -182,13 +199,24 @@ oneway interface IOtDaemon {
      */
     void getChannelMasks(in IChannelMasksReceiver receiver);
 
-   /**
-    * Sets the max power of each channel
-    *
-    * @param channelMaxPowers an array of {@code ChannelMaxPower}.
-    * @param receiver the receiver to the receive result of this operation.
-    */
+    /**
+     * Sets the max power of each channel
+     *
+     * @param channelMaxPowers an array of {@code ChannelMaxPower}.
+     * @param receiver the receiver to the receive result of this operation.
+     */
     void setChannelMaxPowers(in ChannelMaxPower[] channelMaxPowers, in IOtStatusReceiver receiver);
 
+    /**
+     * Runs an ot-ctl command.
+     *
+     * @param command the complete ot-ctl command string, including all arguments. Note that the
+     *         "ot-ctl" prefix itself should be omitted from this string
+     * @param isInteractive indicates whether to run command in interactive mode
+     * @param receiver the callback interface to receive the command's output
+     */
+    oneway void runOtCtlCommand(
+            in String command, in boolean isInteractive, in IOtOutputReceiver receiver);
+
     // TODO: add Border Router APIs
 }
diff --git a/src/android/aidl/com/android/server/thread/openthread/IOtDaemonCallback.aidl b/src/android/aidl/com/android/server/thread/openthread/IOtDaemonCallback.aidl
index 7bd6fde6..844b03a7 100644
--- a/src/android/aidl/com/android/server/thread/openthread/IOtDaemonCallback.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/IOtDaemonCallback.aidl
@@ -30,8 +30,8 @@ package com.android.server.thread.openthread;
 
 import com.android.server.thread.openthread.BackboneRouterState;
 import com.android.server.thread.openthread.Ipv6AddressInfo;
-import com.android.server.thread.openthread.OtDaemonState;
 import com.android.server.thread.openthread.OnMeshPrefixConfig;
+import com.android.server.thread.openthread.OtDaemonState;
 
 /** OpenThread daemon callbacks. */
 oneway interface IOtDaemonCallback {
diff --git a/src/android/aidl/com/android/server/thread/openthread/BorderRouterConfigurationParcel.aidl b/src/android/aidl/com/android/server/thread/openthread/IOtOutputReceiver.aidl
similarity index 78%
rename from src/android/aidl/com/android/server/thread/openthread/BorderRouterConfigurationParcel.aidl
rename to src/android/aidl/com/android/server/thread/openthread/IOtOutputReceiver.aidl
index 2ae5439e..1da31a88 100644
--- a/src/android/aidl/com/android/server/thread/openthread/BorderRouterConfigurationParcel.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/IOtOutputReceiver.aidl
@@ -1,5 +1,5 @@
 /*
- *    Copyright (c) 2023, The OpenThread Authors.
+ *    Copyright (c) 2024, The OpenThread Authors.
  *    All rights reserved.
  *
  *    Redistribution and use in source and binary forms, with or without
@@ -28,13 +28,9 @@
 
 package com.android.server.thread.openthread;
 
-/**
- * The Thread Border Router configuration.
- *
- */
-parcelable BorderRouterConfigurationParcel {
-    boolean isBorderRoutingEnabled; // Whether the border routing feature is enabled.
-    String  infraInterfaceName; // The name of infra network interface.
-    // An ICMPv6 socket on infra network interface. This is required by the border routing feature.
-    ParcelFileDescriptor infraInterfaceIcmp6Socket;
+/** Receives the output of an ot-ctl command which may fail with an {@code otError} code. */
+oneway interface IOtOutputReceiver {
+    void onOutput(in String output);
+    void onComplete();
+    void onError(int errorCode, String errorMessage);
 }
diff --git a/src/android/aidl/com/android/server/thread/openthread/InfraLinkState.aidl b/src/android/aidl/com/android/server/thread/openthread/InfraLinkState.aidl
new file mode 100644
index 00000000..c3eacd2d
--- /dev/null
+++ b/src/android/aidl/com/android/server/thread/openthread/InfraLinkState.aidl
@@ -0,0 +1,37 @@
+/*
+ *    Copyright (c) 2024, The OpenThread Authors.
+ *    All rights reserved.
+ *
+ *    Redistribution and use in source and binary forms, with or without
+ *    modification, are permitted provided that the following conditions are met:
+ *    1. Redistributions of source code must retain the above copyright
+ *       notice, this list of conditions and the following disclaimer.
+ *    2. Redistributions in binary form must reproduce the above copyright
+ *       notice, this list of conditions and the following disclaimer in the
+ *       documentation and/or other materials provided with the distribution.
+ *    3. Neither the name of the copyright holder nor the
+ *       names of its contributors may be used to endorse or promote products
+ *       derived from this software without specific prior written permission.
+ *
+ *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *    POSSIBILITY OF SUCH DAMAGE.
+ */
+
+package com.android.server.thread.openthread;
+
+/** The ot-daemon platform state. */
+@JavaOnlyImmutable
+@JavaDerive(equals=true, toString=true)
+parcelable InfraLinkState {
+    @nullable String interfaceName; // The name of infra network interface.
+    @nullable String nat64Prefix; // The NAT64 prefix.
+}
diff --git a/src/android/aidl/com/android/server/thread/openthread/Ipv6AddressInfo.aidl b/src/android/aidl/com/android/server/thread/openthread/Ipv6AddressInfo.aidl
index 6be019f3..671f3418 100644
--- a/src/android/aidl/com/android/server/thread/openthread/Ipv6AddressInfo.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/Ipv6AddressInfo.aidl
@@ -31,11 +31,12 @@ package com.android.server.thread.openthread;
 /**
  * The Thread IPv6 address information which represents both unicast and multicast address.
  *
- * This is a mapping of <a href="https://openthread.io/reference/struct/ot-ip6-address-info">otIp6AddressInfo</a>
+ * This is a mapping of <a
+ * href="https://openthread.io/reference/struct/ot-ip6-address-info">otIp6AddressInfo</a>
  */
 parcelable Ipv6AddressInfo {
-    byte[]  address; // The raw IPv6 addres bytes, should be 16 bytes
-    int     prefixLength; // Valid for only unicast addresses
+    byte[] address; // The raw IPv6 addres bytes, should be 16 bytes
+    int prefixLength; // Valid for only unicast addresses
     boolean isPreferred; // Valid for only unicast addresses
     boolean isMeshLocal; // Valid for only unicast addresses
     boolean isActiveOmr; // Valid for only unicast addresses. Active OMR means the prefix is added
diff --git a/src/android/aidl/com/android/server/thread/openthread/OnMeshPrefixConfig.aidl b/src/android/aidl/com/android/server/thread/openthread/OnMeshPrefixConfig.aidl
index b7ee7194..6561ca0e 100644
--- a/src/android/aidl/com/android/server/thread/openthread/OnMeshPrefixConfig.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/OnMeshPrefixConfig.aidl
@@ -31,11 +31,12 @@ package com.android.server.thread.openthread;
 /**
  * On-mesh prefix configuration.
  *
- * This is a mapping of <a href="https://openthread.io/reference/struct/ot-border-router-config">otBorderRouterConfig</a>
+ * This is a mapping of <a
+ * href="https://openthread.io/reference/struct/ot-border-router-config">otBorderRouterConfig</a>
  */
 parcelable OnMeshPrefixConfig {
-    byte[]  prefix; // The raw IPv6 prefix bytes, should be 16 bytes
-    int     prefixLength; // The IPv6 prefix length (in bits)
+    byte[] prefix; // The raw IPv6 prefix bytes, should be 16 bytes
+    int prefixLength; // The IPv6 prefix length (in bits)
 
     // More fields of otBorderRouterConfig can be added here when needed.
 }
diff --git a/tests/unit/main.cpp b/src/android/aidl/com/android/server/thread/openthread/OtDaemonConfiguration.aidl
similarity index 87%
rename from tests/unit/main.cpp
rename to src/android/aidl/com/android/server/thread/openthread/OtDaemonConfiguration.aidl
index affea1aa..67cc6921 100644
--- a/tests/unit/main.cpp
+++ b/src/android/aidl/com/android/server/thread/openthread/OtDaemonConfiguration.aidl
@@ -1,5 +1,5 @@
 /*
- *    Copyright (c) 2017, The OpenThread Authors.
+ *    Copyright (c) 2023, The OpenThread Authors.
  *    All rights reserved.
  *
  *    Redistribution and use in source and binary forms, with or without
@@ -26,9 +26,9 @@
  *    POSSIBILITY OF SUCH DAMAGE.
  */
 
-#include <CppUTest/CommandLineTestRunner.h>
+package com.android.server.thread.openthread;
 
-int main(int argc, const char *argv[])
-{
-    return RUN_ALL_TESTS(argc, argv);
-}
+/** The ot-daemon configuration. */
+@JavaOnlyImmutable
+@JavaDerive(equals=true, toString=true)
+parcelable OtDaemonConfiguration {}
diff --git a/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java b/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java
index 993b9fc8..c87f94ba 100644
--- a/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java
+++ b/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java
@@ -41,13 +41,14 @@ import android.os.ParcelFileDescriptor;
 import android.os.RemoteException;
 
 import com.android.server.thread.openthread.BackboneRouterState;
-import com.android.server.thread.openthread.BorderRouterConfigurationParcel;
 import com.android.server.thread.openthread.IChannelMasksReceiver;
 import com.android.server.thread.openthread.INsdPublisher;
 import com.android.server.thread.openthread.IOtDaemon;
 import com.android.server.thread.openthread.IOtDaemonCallback;
+import com.android.server.thread.openthread.IOtOutputReceiver;
 import com.android.server.thread.openthread.IOtStatusReceiver;
 import com.android.server.thread.openthread.MeshcopTxtAttributes;
+import com.android.server.thread.openthread.OtDaemonConfiguration;
 import com.android.server.thread.openthread.OtDaemonState;
 
 import java.time.Duration;
@@ -84,6 +85,7 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
     @Nullable private IOtDaemonCallback mCallback;
     @Nullable private Long mCallbackListenerId;
     @Nullable private RemoteException mJoinException;
+    @Nullable private RemoteException mRunOtCtlCommandException;
     @Nullable private String mCountryCode;
 
     public FakeOtDaemon(Handler handler) {
@@ -343,11 +345,25 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
     }
 
     @Override
-    public void configureBorderRouter(
-            BorderRouterConfigurationParcel config, IOtStatusReceiver receiver)
+    public void setConfiguration(OtDaemonConfiguration config, IOtStatusReceiver receiver)
             throws RemoteException {
         throw new UnsupportedOperationException(
-                "FakeOtDaemon#configureBorderRouter is not implemented!");
+                "FakeOtDaemon#setConfiguration is not implemented!");
+    }
+
+    @Override
+    public void setInfraLinkInterfaceName(
+            String interfaceName, ParcelFileDescriptor fd, IOtStatusReceiver receiver)
+            throws RemoteException {
+        throw new UnsupportedOperationException(
+                "FakeOtDaemon#setInfraLinkInterfaceName is not implemented!");
+    }
+
+    @Override
+    public void setInfraLinkNat64Prefix(String nat64Prefix, IOtStatusReceiver receiver)
+            throws RemoteException {
+        throw new UnsupportedOperationException(
+                "FakeOtDaemon#setInfraLinkNat64Prefix is not implemented!");
     }
 
     @Override
@@ -395,4 +411,35 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
         throw new UnsupportedOperationException(
                 "FakeOtDaemon#setChannelTargetPowers is not implemented!");
     }
+
+    @Override
+    public void runOtCtlCommand(String command, boolean isInteractive, IOtOutputReceiver receiver)
+            throws RemoteException {
+        if (mRunOtCtlCommandException != null) {
+            throw mRunOtCtlCommandException;
+        }
+
+        mHandler.post(
+                () -> {
+                    try {
+                        List<String> outputLines = new ArrayList<>();
+                        outputLines.add("leader");
+                        outputLines.add("\r\n");
+                        outputLines.add("Done");
+                        outputLines.add("\r\n");
+
+                        for (String line : outputLines) {
+                            receiver.onOutput(line);
+                        }
+                        receiver.onComplete();
+                    } catch (RemoteException e) {
+                        throw new AssertionError(e);
+                    }
+                });
+    }
+
+    /** Sets the {@link RemoteException} which will be thrown from {@link #runOtCtlCommand}. */
+    public void setRunOtCtlCommandException(RemoteException exception) {
+        mRunOtCtlCommandException = exception;
+    }
 }
diff --git a/src/android/mdns_publisher.cpp b/src/android/mdns_publisher.cpp
index 0bade461..3458d783 100644
--- a/src/android/mdns_publisher.cpp
+++ b/src/android/mdns_publisher.cpp
@@ -71,6 +71,7 @@ exit:
 }
 
 Status MdnsPublisher::NsdResolveServiceCallback::onServiceResolved(const std::string                  &aHostname,
+                                                                   int                                 aNetifIndex,
                                                                    const std::string                  &aName,
                                                                    const std::string                  &aType,
                                                                    int                                 aPort,
@@ -81,10 +82,11 @@ Status MdnsPublisher::NsdResolveServiceCallback::onServiceResolved(const std::st
     DiscoveredInstanceInfo info;
     TxtList                txtList;
 
-    info.mHostName = aHostname + ".local.";
-    info.mName     = aName;
-    info.mPort     = aPort;
-    info.mTtl      = std::clamp(aTtlSeconds, kMinResolvedTtl, kMaxResolvedTtl);
+    info.mHostName   = aHostname + ".local.";
+    info.mName       = aName;
+    info.mPort       = aPort;
+    info.mTtl        = std::clamp(aTtlSeconds, kMinResolvedTtl, kMaxResolvedTtl);
+    info.mNetifIndex = aNetifIndex;
     for (const auto &addressStr : aAddresses)
     {
         Ip6Address address;
diff --git a/src/android/mdns_publisher.hpp b/src/android/mdns_publisher.hpp
index 723532ea..0930c3d4 100644
--- a/src/android/mdns_publisher.hpp
+++ b/src/android/mdns_publisher.hpp
@@ -205,6 +205,7 @@ public:
         }
 
         Status onServiceResolved(const std::string                  &aHostname,
+                                 int                                 aNetifIndex,
                                  const std::string                  &aName,
                                  const std::string                  &aType,
                                  int                                 aPort,
diff --git a/src/android/otdaemon_fuzzer.cpp b/src/android/otdaemon_fuzzer.cpp
index 9eb32356..7b0716dc 100644
--- a/src/android/otdaemon_fuzzer.cpp
+++ b/src/android/otdaemon_fuzzer.cpp
@@ -32,12 +32,22 @@
 #include "otdaemon_server.hpp"
 
 using android::fuzzService;
+using otbr::Android::MdnsPublisher;
 using otbr::Android::OtDaemonServer;
+using otbr::Mdns::Publisher;
+using otbr::Ncp::RcpHost;
 
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
 {
-    otbr::Application app("", {}, {}, false, "", 0);
-    auto              service = ndk::SharedRefBase::make<OtDaemonServer>(app);
+    RcpHost           rcpHost       = RcpHost{"" /* aInterfaceName */,
+                              {"threadnetwork_hal://binder?none"},
+                              "" /* aBackboneInterfaceName */,
+                              true /* aDryRun */,
+                              false /* aEnableAutoAttach*/};
+    auto              mdnsPublisher = static_cast<MdnsPublisher *>(Publisher::Create([](Publisher::State) {}));
+    otbr::BorderAgent borderAgent{rcpHost, *mdnsPublisher};
+
+    auto service = ndk::SharedRefBase::make<OtDaemonServer>(rcpHost, *mdnsPublisher, borderAgent);
     fuzzService(service->asBinder().get(), FuzzedDataProvider(data, size));
     return 0;
 }
diff --git a/src/android/otdaemon_server.cpp b/src/android/otdaemon_server.cpp
index 5f5ea3c0..ed26e2b3 100644
--- a/src/android/otdaemon_server.cpp
+++ b/src/android/otdaemon_server.cpp
@@ -33,6 +33,8 @@
 #include <net/if.h>
 #include <string.h>
 
+#include <algorithm>
+
 #include <android-base/file.h>
 #include <android-base/stringprintf.h>
 #include <android/binder_manager.h>
@@ -42,6 +44,7 @@
 #include <openthread/icmp6.h>
 #include <openthread/ip6.h>
 #include <openthread/link.h>
+#include <openthread/nat64.h>
 #include <openthread/openthread-system.h>
 #include <openthread/platform/infra_if.h>
 #include <openthread/platform/radio.h>
@@ -58,7 +61,9 @@ namespace vendor {
 
 std::shared_ptr<VendorServer> VendorServer::newInstance(Application &aApplication)
 {
-    return ndk::SharedRefBase::make<Android::OtDaemonServer>(aApplication);
+    return ndk::SharedRefBase::make<Android::OtDaemonServer>(
+        static_cast<otbr::Ncp::RcpHost &>(aApplication.GetHost()),
+        static_cast<otbr::Android::MdnsPublisher &>(aApplication.GetPublisher()), aApplication.GetBorderAgent());
 }
 
 } // namespace vendor
@@ -105,18 +110,21 @@ static const char *ThreadEnabledStateToString(int enabledState)
     }
 }
 
-OtDaemonServer::OtDaemonServer(Application &aApplication)
-    : mApplication(aApplication)
-    , mNcp(aApplication.GetNcp())
-    , mBorderAgent(aApplication.GetBorderAgent())
-    , mMdnsPublisher(static_cast<MdnsPublisher &>(aApplication.GetPublisher()))
-    , mBorderRouterConfiguration()
+OtDaemonServer *OtDaemonServer::sOtDaemonServer = nullptr;
+
+OtDaemonServer::OtDaemonServer(otbr::Ncp::RcpHost    &rcpHost,
+                               otbr::Mdns::Publisher &mdnsPublisher,
+                               otbr::BorderAgent     &borderAgent)
+    : mHost(rcpHost)
+    , mMdnsPublisher(static_cast<MdnsPublisher &>(mdnsPublisher))
+    , mBorderAgent(borderAgent)
+    , mConfiguration()
 {
     mClientDeathRecipient =
         ::ndk::ScopedAIBinder_DeathRecipient(AIBinder_DeathRecipient_new(&OtDaemonServer::BinderDeathCallback));
-    mBorderRouterConfiguration.infraInterfaceName        = "";
-    mBorderRouterConfiguration.infraInterfaceIcmp6Socket = ScopedFileDescriptor();
-    mBorderRouterConfiguration.isBorderRoutingEnabled    = false;
+    mInfraLinkState.interfaceName = "";
+    mInfraIcmp6Socket             = -1;
+    sOtDaemonServer               = this;
 }
 
 void OtDaemonServer::Init(void)
@@ -126,13 +134,14 @@ void OtDaemonServer::Init(void)
 
     assert(GetOtInstance() != nullptr);
 
-    mNcp.AddThreadStateChangedCallback([this](otChangedFlags aFlags) { StateCallback(aFlags); });
+    mHost.AddThreadStateChangedCallback([this](otChangedFlags aFlags) { StateCallback(aFlags); });
     otIp6SetAddressCallback(GetOtInstance(), OtDaemonServer::AddressCallback, this);
     otIp6SetReceiveCallback(GetOtInstance(), OtDaemonServer::ReceiveCallback, this);
     otBackboneRouterSetMulticastListenerCallback(GetOtInstance(), OtDaemonServer::HandleBackboneMulticastListenerEvent,
                                                  this);
     otIcmp6SetEchoMode(GetOtInstance(), OT_ICMP6_ECHO_HANDLER_DISABLED);
     otIp6SetReceiveFilterEnabled(GetOtInstance(), true);
+    otNat64SetReceiveIp4Callback(GetOtInstance(), &OtDaemonServer::ReceiveCallback, this);
 
     mTaskRunner.Post(kTelemetryCheckInterval, [this]() { PushTelemetryIfConditionMatch(); });
 }
@@ -278,8 +287,7 @@ void OtDaemonServer::ReceiveCallback(otMessage *aMessage, void *aBinderServer)
     static_cast<OtDaemonServer *>(aBinderServer)->ReceiveCallback(aMessage);
 }
 
-// FIXME(wgtdkp): We should reuse the same code in openthread/src/posix/platform/netif.cp
-// after the refactor there is done: https://github.com/openthread/openthread/pull/9293
+// TODO: b/291053118 - We should reuse the same code in openthread/src/posix/platform/netif.cpp
 void OtDaemonServer::ReceiveCallback(otMessage *aMessage)
 {
     char     packet[kMaxIp6Size];
@@ -303,8 +311,64 @@ exit:
     otMessageFree(aMessage);
 }
 
-// FIXME(wgtdkp): this doesn't support NAT64, we should use a shared library with ot-posix
-// to handle packet translations between the tunnel interface and Thread.
+int OtDaemonServer::OtCtlCommandCallback(void *aBinderServer, const char *aFormat, va_list aArguments)
+{
+    return static_cast<OtDaemonServer *>(aBinderServer)->OtCtlCommandCallback(aFormat, aArguments);
+}
+
+int OtDaemonServer::OtCtlCommandCallback(const char *aFormat, va_list aArguments)
+{
+    static const std::string kPrompt = "> ";
+    std::string              output;
+
+    VerifyOrExit(mOtCtlOutputReceiver != nullptr, otSysCliInitUsingDaemon(GetOtInstance()));
+
+    android::base::StringAppendV(&output, aFormat, aArguments);
+
+    // Ignore CLI prompt
+    VerifyOrExit(output != kPrompt);
+
+    mOtCtlOutputReceiver->onOutput(output);
+
+    // Check if the command has completed (indicated by "Done" or "Error")
+    if (output.starts_with("Done") || output.starts_with("Error"))
+    {
+        mIsOtCtlOutputComplete = true;
+    }
+
+    // The OpenThread CLI consistently outputs "\r\n" as a newline character. Therefore, we use the presence of "\r\n"
+    // following "Done" or "Error" to signal the completion of a command's output.
+    if (mIsOtCtlOutputComplete && output.ends_with("\r\n"))
+    {
+        if (!mIsOtCtlInteractiveMode)
+        {
+            otSysCliInitUsingDaemon(GetOtInstance());
+        }
+        mIsOtCtlOutputComplete = false;
+        mOtCtlOutputReceiver->onComplete();
+    }
+
+exit:
+    return output.length();
+}
+
+static constexpr uint8_t kIpVersion4 = 4;
+static constexpr uint8_t kIpVersion6 = 6;
+
+// TODO: b/291053118 - We should reuse the same code in openthread/src/posix/platform/netif.cpp
+static uint8_t getIpVersion(const uint8_t *data)
+{
+    assert(data != nullptr);
+
+    // Mute compiler warnings.
+    OT_UNUSED_VARIABLE(kIpVersion4);
+    OT_UNUSED_VARIABLE(kIpVersion6);
+
+    return (static_cast<uint8_t>(data[0]) >> 4) & 0x0F;
+}
+
+// TODO: b/291053118 - we should use a shared library with ot-posix to handle packet translations
+// between the tunnel interface and Thread.
 void OtDaemonServer::TransmitCallback(void)
 {
     char              packet[kMaxIp6Size];
@@ -313,6 +377,7 @@ void OtDaemonServer::TransmitCallback(void)
     otError           error   = OT_ERROR_NONE;
     otMessageSettings settings;
     int               fd = mTunFd.get();
+    bool              isIp4;
 
     assert(GetOtInstance() != nullptr);
 
@@ -336,13 +401,14 @@ void OtDaemonServer::TransmitCallback(void)
     settings.mLinkSecurityEnabled = (otThreadGetDeviceRole(GetOtInstance()) != OT_DEVICE_ROLE_DISABLED);
     settings.mPriority            = OT_MESSAGE_PRIORITY_LOW;
 
-    message = otIp6NewMessage(GetOtInstance(), &settings);
+    isIp4   = (getIpVersion(reinterpret_cast<uint8_t *>(packet)) == kIpVersion4);
+    message = isIp4 ? otIp4NewMessage(GetOtInstance(), &settings) : otIp6NewMessage(GetOtInstance(), &settings);
     VerifyOrExit(message != nullptr, error = OT_ERROR_NO_BUFS);
     otMessageSetOrigin(message, OT_MESSAGE_ORIGIN_HOST_UNTRUSTED);
 
     SuccessOrExit(error = otMessageAppend(message, packet, static_cast<uint16_t>(length)));
 
-    error   = otIp6Send(GetOtInstance(), message);
+    error   = isIp4 ? otNat64Send(GetOtInstance(), message) : otIp6Send(GetOtInstance(), message);
     message = nullptr;
 
 exit:
@@ -423,7 +489,7 @@ exit:
 
 otInstance *OtDaemonServer::GetOtInstance()
 {
-    return mNcp.GetInstance();
+    return mHost.GetInstance();
 }
 
 void OtDaemonServer::Update(MainloopContext &aMainloop)
@@ -792,7 +858,7 @@ exit:
 void OtDaemonServer::FinishLeave(const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
     (void)otInstanceErasePersistentInfo(GetOtInstance());
-    OT_UNUSED_VARIABLE(mApplication); // Avoid the unused-private-field issue.
+
     // TODO: b/323301831 - Re-init the Application class.
     if (aReceiver != nullptr)
     {
@@ -997,15 +1063,26 @@ Status OtDaemonServer::setChannelMaxPowersInternal(const std::vector<ChannelMaxP
         VerifyOrExit((channelMaxPower.channel >= OT_RADIO_2P4GHZ_OQPSK_CHANNEL_MIN) &&
                          (channelMaxPower.channel <= OT_RADIO_2P4GHZ_OQPSK_CHANNEL_MAX),
                      error = OT_ERROR_INVALID_ARGS, message = "The channel is invalid");
-        VerifyOrExit((channelMaxPower.maxPower >= INT16_MIN) && (channelMaxPower.maxPower <= INT16_MAX),
-                     error = OT_ERROR_INVALID_ARGS, message = "The max power is invalid");
     }
 
     for (ChannelMaxPower channelMaxPower : aChannelMaxPowers)
     {
-        channel  = static_cast<uint8_t>(channelMaxPower.channel);
-        maxPower = static_cast<int16_t>(channelMaxPower.maxPower);
-        otbrLogInfo("Set channel max power: channel=%u, maxPower=%d", channel, maxPower);
+        channel = static_cast<uint8_t>(channelMaxPower.channel);
+
+        // INT_MIN indicates that the corresponding channel is disabled in Thread Android API `setChannelMaxPowers()`
+        if (channelMaxPower.maxPower == INT_MIN)
+        {
+            // INT16_MAX indicates that the corresponding channel is disabled in OpenThread API
+            // `otPlatRadioSetChannelTargetPower()`.
+            maxPower = INT16_MAX;
+        }
+        else
+        {
+            maxPower = std::clamp(channelMaxPower.maxPower, INT16_MIN, INT16_MAX - 1);
+        }
+
+        otbrLogInfo("Set channel max power: channel=%u, maxPower=%d", static_cast<unsigned int>(channel),
+                    static_cast<int>(maxPower));
         SuccessOrExit(error   = otPlatRadioSetChannelTargetPower(GetOtInstance(), channel, maxPower),
                       message = "Failed to set channel max power");
     }
@@ -1015,72 +1092,142 @@ exit:
     return Status::ok();
 }
 
-Status OtDaemonServer::configureBorderRouter(const BorderRouterConfigurationParcel    &aBorderRouterConfiguration,
-                                             const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+Status OtDaemonServer::setConfiguration(const OtDaemonConfiguration              &aConfiguration,
+                                        const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    int         icmp6SocketFd               = aBorderRouterConfiguration.infraInterfaceIcmp6Socket.dup().release();
-    std::string infraInterfaceName          = aBorderRouterConfiguration.infraInterfaceName;
-    bool        isBorderRoutingEnabled      = aBorderRouterConfiguration.isBorderRoutingEnabled;
-    bool        isBorderRouterConfigChanged = (mBorderRouterConfiguration != aBorderRouterConfiguration);
+    mTaskRunner.Post([aConfiguration, aReceiver, this]() { setConfigurationInternal(aConfiguration, aReceiver); });
 
-    otbrLogInfo("Configuring Border Router: %s", aBorderRouterConfiguration.toString().c_str());
+    return Status::ok();
+}
 
-    // The copy constructor of `BorderRouterConfigurationParcel` is deleted. It is unable to directly pass the
-    // `aBorderRouterConfiguration` to the lambda function. Only the necessary parameters of
-    // `BorderRouterConfigurationParcel` are passed to the lambda function here.
-    mTaskRunner.Post(
-        [icmp6SocketFd, infraInterfaceName, isBorderRoutingEnabled, isBorderRouterConfigChanged, aReceiver, this]() {
-            configureBorderRouterInternal(icmp6SocketFd, infraInterfaceName, isBorderRoutingEnabled,
-                                          isBorderRouterConfigChanged, aReceiver);
-        });
+void OtDaemonServer::setConfigurationInternal(const OtDaemonConfiguration              &aConfiguration,
+                                              const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+{
+    otError     error = OT_ERROR_NONE;
+    std::string message;
+
+    otbrLogInfo("Configuring Border Router: %s", aConfiguration.toString().c_str());
+
+    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
+    VerifyOrExit(aConfiguration != mConfiguration);
+
+    mConfiguration = aConfiguration;
+
+exit:
+    PropagateResult(error, message, aReceiver);
+}
+
+Status OtDaemonServer::setInfraLinkInterfaceName(const std::optional<std::string>         &aInterfaceName,
+                                                 const ScopedFileDescriptor               &aIcmp6Socket,
+                                                 const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+{
+    int icmp6Socket = aIcmp6Socket.dup().release();
+
+    mTaskRunner.Post([interfaceName = aInterfaceName.value_or(""), icmp6Socket, aReceiver, this]() {
+        setInfraLinkInterfaceNameInternal(interfaceName, icmp6Socket, aReceiver);
+    });
 
     return Status::ok();
 }
 
-void OtDaemonServer::configureBorderRouterInternal(int                aIcmp6SocketFd,
-                                                   const std::string &aInfraInterfaceName,
-                                                   bool               aIsBorderRoutingEnabled,
-                                                   bool               aIsBorderRouterConfigChanged,
-                                                   const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+void OtDaemonServer::setInfraLinkInterfaceNameInternal(const std::string                        &aInterfaceName,
+                                                       int                                       aIcmp6Socket,
+                                                       const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    int         icmp6SocketFd = aIcmp6SocketFd;
-    otError     error         = OT_ERROR_NONE;
-    std::string message;
+    otError           error = OT_ERROR_NONE;
+    std::string       message;
+    const std::string infraIfName  = aInterfaceName;
+    unsigned int      infraIfIndex = if_nametoindex(infraIfName.c_str());
+
+    otbrLogInfo("Setting infra link state: %s", aInterfaceName.c_str());
 
     VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
+    VerifyOrExit(mInfraLinkState.interfaceName != aInterfaceName || aIcmp6Socket != mInfraIcmp6Socket);
 
-    if (aIsBorderRouterConfigChanged)
+    if (infraIfIndex != 0 && aIcmp6Socket > 0)
     {
-        if (aIsBorderRoutingEnabled)
-        {
-            unsigned int infraIfIndex = if_nametoindex(aInfraInterfaceName.c_str());
-            SuccessOrExit(error   = otBorderRoutingSetEnabled(GetOtInstance(), false /* aEnabled */),
-                          message = "failed to disable border routing");
-            otSysSetInfraNetif(aInfraInterfaceName.c_str(), icmp6SocketFd);
-            icmp6SocketFd = -1;
-            SuccessOrExit(error   = otBorderRoutingInit(GetOtInstance(), infraIfIndex, otSysInfraIfIsRunning()),
-                          message = "failed to initialize border routing");
-            SuccessOrExit(error   = otBorderRoutingSetEnabled(GetOtInstance(), true /* aEnabled */),
-                          message = "failed to enable border routing");
-            // TODO: b/320836258 - Make BBR independently configurable
-            otBackboneRouterSetEnabled(GetOtInstance(), true /* aEnabled */);
-        }
-        else
-        {
-            SuccessOrExit(error   = otBorderRoutingSetEnabled(GetOtInstance(), false /* aEnabled */),
-                          message = "failed to disable border routing");
-            otBackboneRouterSetEnabled(GetOtInstance(), false /* aEnabled */);
-        }
+        SuccessOrExit(error   = otBorderRoutingSetEnabled(GetOtInstance(), false /* aEnabled */),
+                      message = "failed to disable border routing");
+        otSysSetInfraNetif(infraIfName.c_str(), aIcmp6Socket);
+        aIcmp6Socket = -1;
+        SuccessOrExit(error   = otBorderRoutingInit(GetOtInstance(), infraIfIndex, otSysInfraIfIsRunning()),
+                      message = "failed to initialize border routing");
+        SuccessOrExit(error   = otBorderRoutingSetEnabled(GetOtInstance(), true /* aEnabled */),
+                      message = "failed to enable border routing");
+        // TODO: b/320836258 - Make BBR independently configurable
+        otBackboneRouterSetEnabled(GetOtInstance(), true /* aEnabled */);
+    }
+    else
+    {
+        SuccessOrExit(error   = otBorderRoutingSetEnabled(GetOtInstance(), false /* aEnabled */),
+                      message = "failed to disable border routing");
+        otBackboneRouterSetEnabled(GetOtInstance(), false /* aEnabled */);
     }
 
-    mBorderRouterConfiguration.isBorderRoutingEnabled = aIsBorderRoutingEnabled;
-    mBorderRouterConfiguration.infraInterfaceName     = aInfraInterfaceName;
+    mInfraLinkState.interfaceName = aInterfaceName;
+    mInfraIcmp6Socket             = aIcmp6Socket;
 
 exit:
     if (error != OT_ERROR_NONE)
     {
-        close(icmp6SocketFd);
+        close(aIcmp6Socket);
+    }
+    PropagateResult(error, message, aReceiver);
+}
+
+Status OtDaemonServer::runOtCtlCommand(const std::string                        &aCommand,
+                                       const bool                                aIsInteractive,
+                                       const std::shared_ptr<IOtOutputReceiver> &aReceiver)
+{
+    mTaskRunner.Post([aCommand, aIsInteractive, aReceiver, this]() {
+        runOtCtlCommandInternal(aCommand, aIsInteractive, aReceiver);
+    });
+
+    return Status::ok();
+}
+
+Status OtDaemonServer::setInfraLinkNat64Prefix(const std::optional<std::string>         &aNat64Prefix,
+                                               const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+{
+    mTaskRunner.Post([nat64Prefix = aNat64Prefix.value_or(""), aReceiver, this]() {
+        setInfraLinkNat64PrefixInternal(nat64Prefix, aReceiver);
+    });
+
+    return Status::ok();
+}
+
+void OtDaemonServer::runOtCtlCommandInternal(const std::string                        &aCommand,
+                                             const bool                                aIsInteractive,
+                                             const std::shared_ptr<IOtOutputReceiver> &aReceiver)
+{
+    otSysCliInitUsingDaemon(GetOtInstance());
+
+    if (!aCommand.empty())
+    {
+        std::string command = aCommand;
+
+        mIsOtCtlInteractiveMode = aIsInteractive;
+        mOtCtlOutputReceiver    = aReceiver;
+
+        otCliInit(GetOtInstance(), OtDaemonServer::OtCtlCommandCallback, this);
+        otCliInputLine(command.data());
     }
+}
+
+void OtDaemonServer::setInfraLinkNat64PrefixInternal(const std::string                        &aNat64Prefix,
+                                                     const std::shared_ptr<IOtStatusReceiver> &aReceiver)
+{
+    otError     error = OT_ERROR_NONE;
+    std::string message;
+
+    otbrLogInfo("Setting infra link NAT64 prefix: %s", aNat64Prefix.c_str());
+
+    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
+
+    mInfraLinkState.nat64Prefix = aNat64Prefix;
+    NotifyNat64PrefixDiscoveryDone();
+
+exit:
     PropagateResult(error, message, aReceiver);
 }
 
@@ -1115,7 +1262,14 @@ binder_status_t OtDaemonServer::dump(int aFd, const char **aArgs, uint32_t aNumA
     DumpCliCommand("srp server state", aFd);
     DumpCliCommand("srp server service", aFd);
     DumpCliCommand("srp server host", aFd);
-    DumpCliCommand("dataset active", aFd);
+    DumpCliCommand("dataset activetimestamp", aFd);
+    DumpCliCommand("dataset channel", aFd);
+    DumpCliCommand("dataset channelmask", aFd);
+    DumpCliCommand("dataset extpanid", aFd);
+    DumpCliCommand("dataset meshlocalprefix", aFd);
+    DumpCliCommand("dataset networkname", aFd);
+    DumpCliCommand("dataset panid", aFd);
+    DumpCliCommand("dataset securitypolicy", aFd);
     DumpCliCommand("leaderdata", aFd);
     DumpCliCommand("eidcache", aFd);
     DumpCliCommand("counters mac", aFd);
@@ -1146,5 +1300,32 @@ exit:
     return;
 }
 
+void OtDaemonServer::NotifyNat64PrefixDiscoveryDone(void)
+{
+    otIp6Prefix nat64Prefix{};
+    uint32_t    infraIfIndex = if_nametoindex(mInfraLinkState.interfaceName.value_or("").c_str());
+
+    otIp6PrefixFromString(mInfraLinkState.nat64Prefix.value_or("").c_str(), &nat64Prefix);
+    otPlatInfraIfDiscoverNat64PrefixDone(GetOtInstance(), infraIfIndex, &nat64Prefix);
+
+exit:
+    return;
+}
+
+extern "C" otError otPlatInfraIfDiscoverNat64Prefix(uint32_t aInfraIfIndex)
+{
+    OT_UNUSED_VARIABLE(aInfraIfIndex);
+
+    OtDaemonServer *otDaemonServer = OtDaemonServer::Get();
+    otError         error          = OT_ERROR_NONE;
+
+    VerifyOrExit(otDaemonServer != nullptr, error = OT_ERROR_INVALID_STATE);
+
+    otDaemonServer->NotifyNat64PrefixDiscoveryDone();
+
+exit:
+    return error;
+}
+
 } // namespace Android
 } // namespace otbr
diff --git a/src/android/otdaemon_server.hpp b/src/android/otdaemon_server.hpp
index 11d42f36..7578e86a 100644
--- a/src/android/otdaemon_server.hpp
+++ b/src/android/otdaemon_server.hpp
@@ -36,6 +36,7 @@
 #include <aidl/com/android/server/thread/openthread/BnOtDaemon.h>
 #include <aidl/com/android/server/thread/openthread/INsdPublisher.h>
 #include <aidl/com/android/server/thread/openthread/IOtDaemon.h>
+#include <aidl/com/android/server/thread/openthread/InfraLinkState.h>
 #include <openthread/instance.h>
 #include <openthread/ip6.h>
 
@@ -43,7 +44,7 @@
 #include "android/mdns_publisher.hpp"
 #include "common/mainloop.hpp"
 #include "common/time.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 namespace Android {
@@ -54,21 +55,23 @@ using Status               = ::ndk::ScopedAStatus;
 using aidl::android::net::thread::ChannelMaxPower;
 using aidl::com::android::server::thread::openthread::BackboneRouterState;
 using aidl::com::android::server::thread::openthread::BnOtDaemon;
-using aidl::com::android::server::thread::openthread::BorderRouterConfigurationParcel;
 using aidl::com::android::server::thread::openthread::IChannelMasksReceiver;
+using aidl::com::android::server::thread::openthread::InfraLinkState;
 using aidl::com::android::server::thread::openthread::INsdPublisher;
 using aidl::com::android::server::thread::openthread::IOtDaemon;
 using aidl::com::android::server::thread::openthread::IOtDaemonCallback;
+using aidl::com::android::server::thread::openthread::IOtOutputReceiver;
 using aidl::com::android::server::thread::openthread::IOtStatusReceiver;
 using aidl::com::android::server::thread::openthread::Ipv6AddressInfo;
 using aidl::com::android::server::thread::openthread::MeshcopTxtAttributes;
 using aidl::com::android::server::thread::openthread::OnMeshPrefixConfig;
+using aidl::com::android::server::thread::openthread::OtDaemonConfiguration;
 using aidl::com::android::server::thread::openthread::OtDaemonState;
 
 class OtDaemonServer : public BnOtDaemon, public MainloopProcessor, public vendor::VendorServer
 {
 public:
-    explicit OtDaemonServer(Application &aApplication);
+    OtDaemonServer(otbr::Ncp::RcpHost &rcpHost, otbr::Mdns::Publisher &mdnsPublisher, otbr::BorderAgent &borderAgent);
     virtual ~OtDaemonServer(void) = default;
 
     // Disallow copy and assign.
@@ -78,6 +81,10 @@ public:
     // Dump information for debugging.
     binder_status_t dump(int aFd, const char **aArgs, uint32_t aNumArgs) override;
 
+    static OtDaemonServer *Get(void) { return sOtDaemonServer; }
+
+    void NotifyNat64PrefixDiscoveryDone(void);
+
 private:
     using LeaveCallback = std::function<void()>;
 
@@ -127,15 +134,28 @@ private:
                                const std::shared_ptr<IOtStatusReceiver> &aReceiver);
     Status setChannelMaxPowersInternal(const std::vector<ChannelMaxPower>       &aChannelMaxPowers,
                                        const std::shared_ptr<IOtStatusReceiver> &aReceiver);
-    Status configureBorderRouter(const BorderRouterConfigurationParcel    &aBorderRouterConfiguration,
-                                 const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
-    void   configureBorderRouterInternal(int                                       aIcmp6SocketFd,
-                                         const std::string                        &aInfraInterfaceName,
-                                         bool                                      aIsBorderRoutingEnabled,
-                                         bool                                      aIsBorderRouterConfigChanged,
-                                         const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    Status setConfiguration(const OtDaemonConfiguration              &aConfiguration,
+                            const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
+    void   setConfigurationInternal(const OtDaemonConfiguration              &aConfiguration,
+                                    const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    Status setInfraLinkInterfaceName(const std::optional<std::string>         &aInterfaceName,
+                                     const ScopedFileDescriptor               &aIcmp6Socket,
+                                     const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
+    void   setInfraLinkInterfaceNameInternal(const std::string                        &aInterfaceName,
+                                             int                                       aIcmp6SocketFd,
+                                             const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    Status setInfraLinkNat64Prefix(const std::optional<std::string>         &aNat64Prefix,
+                                   const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
+    void   setInfraLinkNat64PrefixInternal(const std::string                        &aNat64Prefix,
+                                           const std::shared_ptr<IOtStatusReceiver> &aReceiver);
     Status getChannelMasks(const std::shared_ptr<IChannelMasksReceiver> &aReceiver) override;
     void   getChannelMasksInternal(const std::shared_ptr<IChannelMasksReceiver> &aReceiver);
+    Status runOtCtlCommand(const std::string                        &aCommand,
+                           const bool                                aIsInteractive,
+                           const std::shared_ptr<IOtOutputReceiver> &aReceiver);
+    void   runOtCtlCommandInternal(const std::string                        &aCommand,
+                                   const bool                                aIsInteractive,
+                                   const std::shared_ptr<IOtOutputReceiver> &aReceiver);
 
     bool        RefreshOtDaemonState(otChangedFlags aFlags);
     void        LeaveGracefully(const LeaveCallback &aReceiver);
@@ -149,6 +169,8 @@ private:
     static void         AddressCallback(const otIp6AddressInfo *aAddressInfo, bool aIsAdded, void *aBinderServer);
     static void         ReceiveCallback(otMessage *aMessage, void *aBinderServer);
     void                ReceiveCallback(otMessage *aMessage);
+    static int          OtCtlCommandCallback(void *aBinderServer, const char *aFormat, va_list aArguments);
+    int                 OtCtlCommandCallback(const char *aFormat, va_list aArguments);
     void                TransmitCallback(void);
     BackboneRouterState GetBackboneRouterState(void);
     static void         HandleBackboneMulticastListenerEvent(void                                  *aBinderServer,
@@ -161,10 +183,11 @@ private:
     void UpdateThreadEnabledState(const int aEnabled, const std::shared_ptr<IOtStatusReceiver> &aReceiver);
     void EnableThread(const std::shared_ptr<IOtStatusReceiver> &aReceiver);
 
-    otbr::Application                 &mApplication;
-    otbr::Ncp::ControllerOpenThread   &mNcp;
-    otbr::BorderAgent                 &mBorderAgent;
+    static OtDaemonServer *sOtDaemonServer;
+
+    otbr::Ncp::RcpHost                &mHost;
     MdnsPublisher                     &mMdnsPublisher;
+    otbr::BorderAgent                 &mBorderAgent;
     std::shared_ptr<INsdPublisher>     mINsdPublisher;
     MeshcopTxtAttributes               mMeshcopTxts;
     TaskRunner                         mTaskRunner;
@@ -175,10 +198,16 @@ private:
     std::shared_ptr<IOtStatusReceiver> mJoinReceiver;
     std::shared_ptr<IOtStatusReceiver> mMigrationReceiver;
     std::vector<LeaveCallback>         mLeaveCallbacks;
-    BorderRouterConfigurationParcel    mBorderRouterConfiguration;
+    bool                               mIsOtCtlInteractiveMode;
+    bool                               mIsOtCtlOutputComplete;
+    std::shared_ptr<IOtOutputReceiver> mOtCtlOutputReceiver;
+    OtDaemonConfiguration              mConfiguration;
     std::set<OnMeshPrefixConfig>       mOnMeshPrefixes;
-    static constexpr Seconds           kTelemetryCheckInterval           = Seconds(600);          // 600 seconds
-    static constexpr Seconds           kTelemetryUploadIntervalThreshold = Seconds(60 * 60 * 12); // 12 hours
+    InfraLinkState                     mInfraLinkState;
+    int                                mInfraIcmp6Socket;
+
+    static constexpr Seconds kTelemetryCheckInterval           = Seconds(600);          // 600 seconds
+    static constexpr Seconds kTelemetryUploadIntervalThreshold = Seconds(60 * 60 * 12); // 12 hours
 };
 
 } // namespace Android
diff --git a/src/android/otdaemon_telemetry.cpp b/src/android/otdaemon_telemetry.cpp
index f53cfdee..166e2565 100644
--- a/src/android/otdaemon_telemetry.cpp
+++ b/src/android/otdaemon_telemetry.cpp
@@ -27,6 +27,7 @@
  */
 #include "android/otdaemon_telemetry.hpp"
 
+#include <openthread/nat64.h>
 #include <openthread/openthread-system.h>
 #include <openthread/thread.h>
 #include <openthread/thread_ftd.h>
@@ -49,6 +50,7 @@ namespace Android {
 using android::os::statsd::threadnetwork::ThreadnetworkDeviceInfoReported;
 using android::os::statsd::threadnetwork::ThreadnetworkTelemetryDataReported;
 using android::os::statsd::threadnetwork::ThreadnetworkTopoEntryRepeated;
+using TelemetryData = android::os::statsd::threadnetwork::ThreadnetworkTelemetryDataReported;
 
 static uint32_t TelemetryNodeTypeFromRoleAndLinkMode(const otDeviceRole &aRole, const otLinkModeConfig &aLinkModeCfg)
 {
@@ -145,6 +147,84 @@ void CopyMdnsResponseCounters(const MdnsResponseCounters
     to->set_invalid_state_count(from.mInvalidState);
 }
 
+TelemetryData::Nat64State Nat64StateFromOtNat64State(otNat64State aNat64State)
+{
+    TelemetryData::Nat64State nat64State;
+
+    switch (aNat64State)
+    {
+    case OT_NAT64_STATE_DISABLED:
+        nat64State = TelemetryData::NAT64_STATE_DISABLED;
+        break;
+    case OT_NAT64_STATE_NOT_RUNNING:
+        nat64State = TelemetryData::NAT64_STATE_NOT_RUNNING;
+        break;
+    case OT_NAT64_STATE_IDLE:
+        nat64State = TelemetryData::NAT64_STATE_IDLE;
+        break;
+    case OT_NAT64_STATE_ACTIVE:
+        nat64State = TelemetryData::NAT64_STATE_ACTIVE;
+        break;
+    default:
+        nat64State = TelemetryData::NAT64_STATE_UNSPECIFIED;
+    }
+
+    return nat64State;
+}
+
+void RetrieveNat64State(otInstance *aInstance, TelemetryData::WpanBorderRouter *aWpanBorderRouter)
+{
+    auto nat64State = aWpanBorderRouter->mutable_nat64_state();
+
+    nat64State->set_prefix_manager_state(Nat64StateFromOtNat64State(otNat64GetPrefixManagerState(aInstance)));
+    nat64State->set_translator_state(Nat64StateFromOtNat64State(otNat64GetTranslatorState(aInstance)));
+}
+
+void RetrieveNat64Counters(otInstance *aInstance, TelemetryData::BorderRoutingCounters *aBorderRoutingCounters)
+{
+    {
+        auto nat64IcmpCounters = aBorderRoutingCounters->mutable_nat64_protocol_counters()->mutable_icmp();
+        auto nat64UdpCounters  = aBorderRoutingCounters->mutable_nat64_protocol_counters()->mutable_udp();
+        auto nat64TcpCounters  = aBorderRoutingCounters->mutable_nat64_protocol_counters()->mutable_tcp();
+        otNat64ProtocolCounters otCounters;
+
+        otNat64GetCounters(aInstance, &otCounters);
+        nat64IcmpCounters->set_ipv4_to_ipv6_packets(otCounters.mIcmp.m4To6Packets);
+        nat64IcmpCounters->set_ipv4_to_ipv6_bytes(otCounters.mIcmp.m4To6Bytes);
+        nat64IcmpCounters->set_ipv6_to_ipv4_packets(otCounters.mIcmp.m6To4Packets);
+        nat64IcmpCounters->set_ipv6_to_ipv4_bytes(otCounters.mIcmp.m6To4Bytes);
+        nat64UdpCounters->set_ipv4_to_ipv6_packets(otCounters.mUdp.m4To6Packets);
+        nat64UdpCounters->set_ipv4_to_ipv6_bytes(otCounters.mUdp.m4To6Bytes);
+        nat64UdpCounters->set_ipv6_to_ipv4_packets(otCounters.mUdp.m6To4Packets);
+        nat64UdpCounters->set_ipv6_to_ipv4_bytes(otCounters.mUdp.m6To4Bytes);
+        nat64TcpCounters->set_ipv4_to_ipv6_packets(otCounters.mTcp.m4To6Packets);
+        nat64TcpCounters->set_ipv4_to_ipv6_bytes(otCounters.mTcp.m4To6Bytes);
+        nat64TcpCounters->set_ipv6_to_ipv4_packets(otCounters.mTcp.m6To4Packets);
+        nat64TcpCounters->set_ipv6_to_ipv4_bytes(otCounters.mTcp.m6To4Bytes);
+    }
+
+    {
+        auto                 errorCounters = aBorderRoutingCounters->mutable_nat64_error_counters();
+        otNat64ErrorCounters otCounters;
+        otNat64GetErrorCounters(aInstance, &otCounters);
+
+        errorCounters->mutable_unknown()->set_ipv4_to_ipv6_packets(otCounters.mCount4To6[OT_NAT64_DROP_REASON_UNKNOWN]);
+        errorCounters->mutable_unknown()->set_ipv6_to_ipv4_packets(otCounters.mCount6To4[OT_NAT64_DROP_REASON_UNKNOWN]);
+        errorCounters->mutable_illegal_packet()->set_ipv4_to_ipv6_packets(
+            otCounters.mCount4To6[OT_NAT64_DROP_REASON_ILLEGAL_PACKET]);
+        errorCounters->mutable_illegal_packet()->set_ipv6_to_ipv4_packets(
+            otCounters.mCount6To4[OT_NAT64_DROP_REASON_ILLEGAL_PACKET]);
+        errorCounters->mutable_unsupported_protocol()->set_ipv4_to_ipv6_packets(
+            otCounters.mCount4To6[OT_NAT64_DROP_REASON_UNSUPPORTED_PROTO]);
+        errorCounters->mutable_unsupported_protocol()->set_ipv6_to_ipv4_packets(
+            otCounters.mCount6To4[OT_NAT64_DROP_REASON_UNSUPPORTED_PROTO]);
+        errorCounters->mutable_no_mapping()->set_ipv4_to_ipv6_packets(
+            otCounters.mCount4To6[OT_NAT64_DROP_REASON_NO_MAPPING]);
+        errorCounters->mutable_no_mapping()->set_ipv6_to_ipv4_packets(
+            otCounters.mCount6To4[OT_NAT64_DROP_REASON_NO_MAPPING]);
+    }
+}
+
 otError RetrieveTelemetryAtom(otInstance                         *otInstance,
                               Mdns::Publisher                    *aPublisher,
                               ThreadnetworkTelemetryDataReported &telemetryDataReported,
@@ -154,6 +234,12 @@ otError RetrieveTelemetryAtom(otInstance                         *otInstance,
     otError                     error = OT_ERROR_NONE;
     std::vector<otNeighborInfo> neighborTable;
 
+    // Begin of ThreadnetworkDeviceInfoReported section.
+    deviceInfoReported.set_thread_version(otThreadGetVersion());
+    deviceInfoReported.set_ot_rcp_version(otGetRadioVersionString(otInstance));
+    // TODO: populate ot_host_version, thread_daemon_version.
+    // End of ThreadnetworkDeviceInfoReported section.
+
     // Begin of WpanStats section.
     auto wpanStats = telemetryDataReported.mutable_wpan_stats();
 
@@ -164,6 +250,16 @@ otError RetrieveTelemetryAtom(otInstance                         *otInstance,
         wpanStats->set_node_type(TelemetryNodeTypeFromRoleAndLinkMode(role, otCfg));
     }
 
+    // Disable telemetry retrieval when Thread stack is disabled. DeviceInfo section above is
+    // always uploaded to understand the device count.
+    if (wpanStats->node_type() == ThreadnetworkTelemetryDataReported::NODE_TYPE_DISABLED)
+    {
+        otbrLogDebug("Skip telemetry retrieval since Thread stack is disabled.");
+        // Return error that only partial telemetries are populated.
+        // TODO: refine the error code name to mean: partial data are populated.
+        return OT_ERROR_FAILED;
+    }
+
     wpanStats->set_channel(otLinkGetChannel(otInstance));
 
     {
@@ -394,32 +490,37 @@ otError RetrieveTelemetryAtom(otInstance                         *otInstance,
     {
         // Begin of WpanBorderRouter section.
         auto wpanBorderRouter = telemetryDataReported.mutable_wpan_border_router();
+
         // Begin of BorderRoutingCounters section.
-        auto                           borderRoutingCouters    = wpanBorderRouter->mutable_border_routing_counters();
-        const otBorderRoutingCounters *otBorderRoutingCounters = otIp6GetBorderRoutingCounters(otInstance);
-
-        borderRoutingCouters->mutable_inbound_unicast()->set_packet_count(
-            otBorderRoutingCounters->mInboundUnicast.mPackets);
-        borderRoutingCouters->mutable_inbound_unicast()->set_byte_count(
-            otBorderRoutingCounters->mInboundUnicast.mBytes);
-        borderRoutingCouters->mutable_inbound_multicast()->set_packet_count(
-            otBorderRoutingCounters->mInboundMulticast.mPackets);
-        borderRoutingCouters->mutable_inbound_multicast()->set_byte_count(
-            otBorderRoutingCounters->mInboundMulticast.mBytes);
-        borderRoutingCouters->mutable_outbound_unicast()->set_packet_count(
-            otBorderRoutingCounters->mOutboundUnicast.mPackets);
-        borderRoutingCouters->mutable_outbound_unicast()->set_byte_count(
-            otBorderRoutingCounters->mOutboundUnicast.mBytes);
-        borderRoutingCouters->mutable_outbound_multicast()->set_packet_count(
-            otBorderRoutingCounters->mOutboundMulticast.mPackets);
-        borderRoutingCouters->mutable_outbound_multicast()->set_byte_count(
-            otBorderRoutingCounters->mOutboundMulticast.mBytes);
-        borderRoutingCouters->set_ra_rx(otBorderRoutingCounters->mRaRx);
-        borderRoutingCouters->set_ra_tx_success(otBorderRoutingCounters->mRaTxSuccess);
-        borderRoutingCouters->set_ra_tx_failure(otBorderRoutingCounters->mRaTxFailure);
-        borderRoutingCouters->set_rs_rx(otBorderRoutingCounters->mRsRx);
-        borderRoutingCouters->set_rs_tx_success(otBorderRoutingCounters->mRsTxSuccess);
-        borderRoutingCouters->set_rs_tx_failure(otBorderRoutingCounters->mRsTxFailure);
+        {
+            auto                           borderRoutingCouters = wpanBorderRouter->mutable_border_routing_counters();
+            const otBorderRoutingCounters *otBorderRoutingCounters = otIp6GetBorderRoutingCounters(otInstance);
+
+            borderRoutingCouters->mutable_inbound_unicast()->set_packet_count(
+                otBorderRoutingCounters->mInboundUnicast.mPackets);
+            borderRoutingCouters->mutable_inbound_unicast()->set_byte_count(
+                otBorderRoutingCounters->mInboundUnicast.mBytes);
+            borderRoutingCouters->mutable_inbound_multicast()->set_packet_count(
+                otBorderRoutingCounters->mInboundMulticast.mPackets);
+            borderRoutingCouters->mutable_inbound_multicast()->set_byte_count(
+                otBorderRoutingCounters->mInboundMulticast.mBytes);
+            borderRoutingCouters->mutable_outbound_unicast()->set_packet_count(
+                otBorderRoutingCounters->mOutboundUnicast.mPackets);
+            borderRoutingCouters->mutable_outbound_unicast()->set_byte_count(
+                otBorderRoutingCounters->mOutboundUnicast.mBytes);
+            borderRoutingCouters->mutable_outbound_multicast()->set_packet_count(
+                otBorderRoutingCounters->mOutboundMulticast.mPackets);
+            borderRoutingCouters->mutable_outbound_multicast()->set_byte_count(
+                otBorderRoutingCounters->mOutboundMulticast.mBytes);
+            borderRoutingCouters->set_ra_rx(otBorderRoutingCounters->mRaRx);
+            borderRoutingCouters->set_ra_tx_success(otBorderRoutingCounters->mRaTxSuccess);
+            borderRoutingCouters->set_ra_tx_failure(otBorderRoutingCounters->mRaTxFailure);
+            borderRoutingCouters->set_rs_rx(otBorderRoutingCounters->mRsRx);
+            borderRoutingCouters->set_rs_tx_success(otBorderRoutingCounters->mRsTxSuccess);
+            borderRoutingCouters->set_rs_tx_failure(otBorderRoutingCounters->mRsTxFailure);
+
+            RetrieveNat64Counters(otInstance, borderRoutingCouters);
+        }
 
         // End of BorderRoutingCounters section.
 
@@ -600,11 +701,9 @@ otError RetrieveTelemetryAtom(otInstance                         *otInstance,
             }
         }
         // End of CoexMetrics section.
-    }
 
-    deviceInfoReported.set_thread_version(otThreadGetVersion());
-    deviceInfoReported.set_ot_rcp_version(otGetRadioVersionString(otInstance));
-    // TODO: populate ot_host_version, thread_daemon_version.
+        RetrieveNat64State(otInstance, wpanBorderRouter);
+    }
 
     return error;
 }
diff --git a/src/backbone_router/backbone_agent.cpp b/src/backbone_router/backbone_agent.cpp
index fc79b8f5..b2716e34 100644
--- a/src/backbone_router/backbone_agent.cpp
+++ b/src/backbone_router/backbone_agent.cpp
@@ -47,13 +47,11 @@
 namespace otbr {
 namespace BackboneRouter {
 
-BackboneAgent::BackboneAgent(otbr::Ncp::ControllerOpenThread &aNcp,
-                             std::string                      aInterfaceName,
-                             std::string                      aBackboneInterfaceName)
-    : mNcp(aNcp)
+BackboneAgent::BackboneAgent(otbr::Ncp::RcpHost &aHost, std::string aInterfaceName, std::string aBackboneInterfaceName)
+    : mHost(aHost)
     , mBackboneRouterState(OT_BACKBONE_ROUTER_STATE_DISABLED)
 #if OTBR_ENABLE_DUA_ROUTING
-    , mNdProxyManager(aNcp, aBackboneInterfaceName)
+    , mNdProxyManager(aHost, aBackboneInterfaceName)
     , mDuaRoutingManager(aInterfaceName, aBackboneInterfaceName)
 #endif
 {
@@ -63,16 +61,16 @@ BackboneAgent::BackboneAgent(otbr::Ncp::ControllerOpenThread &aNcp,
 
 void BackboneAgent::Init(void)
 {
-    mNcp.AddThreadStateChangedCallback([this](otChangedFlags aFlags) { HandleThreadStateChanged(aFlags); });
-    otBackboneRouterSetDomainPrefixCallback(mNcp.GetInstance(), &BackboneAgent::HandleBackboneRouterDomainPrefixEvent,
+    mHost.AddThreadStateChangedCallback([this](otChangedFlags aFlags) { HandleThreadStateChanged(aFlags); });
+    otBackboneRouterSetDomainPrefixCallback(mHost.GetInstance(), &BackboneAgent::HandleBackboneRouterDomainPrefixEvent,
                                             this);
 #if OTBR_ENABLE_DUA_ROUTING
-    otBackboneRouterSetNdProxyCallback(mNcp.GetInstance(), &BackboneAgent::HandleBackboneRouterNdProxyEvent, this);
+    otBackboneRouterSetNdProxyCallback(mHost.GetInstance(), &BackboneAgent::HandleBackboneRouterNdProxyEvent, this);
     mNdProxyManager.Init();
 #endif
 
 #if OTBR_ENABLE_BACKBONE_ROUTER_ON_INIT
-    otBackboneRouterSetEnabled(mNcp.GetInstance(), /* aEnabled */ true);
+    otBackboneRouterSetEnabled(mHost.GetInstance(), /* aEnabled */ true);
 #endif
 }
 
@@ -86,7 +84,7 @@ void BackboneAgent::HandleThreadStateChanged(otChangedFlags aFlags)
 
 void BackboneAgent::HandleBackboneRouterState(void)
 {
-    otBackboneRouterState state      = otBackboneRouterGetState(mNcp.GetInstance());
+    otBackboneRouterState state      = otBackboneRouterGetState(mHost.GetInstance());
     bool                  wasPrimary = (mBackboneRouterState == OT_BACKBONE_ROUTER_STATE_PRIMARY);
 
     otbrLogDebug("BackboneAgent: HandleBackboneRouterState: state=%d, mBackboneRouterState=%d", state,
diff --git a/src/backbone_router/backbone_agent.hpp b/src/backbone_router/backbone_agent.hpp
index c7566bcc..67cb4a15 100644
--- a/src/backbone_router/backbone_agent.hpp
+++ b/src/backbone_router/backbone_agent.hpp
@@ -47,7 +47,7 @@
 #include "backbone_router/dua_routing_manager.hpp"
 #include "backbone_router/nd_proxy.hpp"
 #include "common/code_utils.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 namespace BackboneRouter {
@@ -73,12 +73,10 @@ public:
     /**
      * This constructor intiializes the `BackboneAgent` instance.
      *
-     * @param[in] aNcp  The Thread instance.
+     * @param[in] aHost  The Thread controller instance.
      *
      */
-    BackboneAgent(otbr::Ncp::ControllerOpenThread &aNcp,
-                  std::string                      aInterfaceName,
-                  std::string                      aBackboneInterfaceName);
+    BackboneAgent(otbr::Ncp::RcpHost &aHost, std::string aInterfaceName, std::string aBackboneInterfaceName);
 
     /**
      * This method initializes the Backbone agent.
@@ -106,9 +104,9 @@ private:
 
     static const char *StateToString(otBackboneRouterState aState);
 
-    otbr::Ncp::ControllerOpenThread &mNcp;
-    otBackboneRouterState            mBackboneRouterState;
-    Ip6Prefix                        mDomainPrefix;
+    otbr::Ncp::RcpHost   &mHost;
+    otBackboneRouterState mBackboneRouterState;
+    Ip6Prefix             mDomainPrefix;
 #if OTBR_ENABLE_DUA_ROUTING
     NdProxyManager    mNdProxyManager;
     DuaRoutingManager mDuaRoutingManager;
diff --git a/src/backbone_router/dua_routing_manager.hpp b/src/backbone_router/dua_routing_manager.hpp
index daf341df..bb4c929c 100644
--- a/src/backbone_router/dua_routing_manager.hpp
+++ b/src/backbone_router/dua_routing_manager.hpp
@@ -43,7 +43,7 @@
 #include <openthread/backbone_router_ftd.h>
 
 #include "common/code_utils.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 #include "utils/system_utils.hpp"
 
 namespace otbr {
diff --git a/src/backbone_router/nd_proxy.cpp b/src/backbone_router/nd_proxy.cpp
index 15745654..fdc19615 100644
--- a/src/backbone_router/nd_proxy.cpp
+++ b/src/backbone_router/nd_proxy.cpp
@@ -121,14 +121,12 @@ void NdProxyManager::Update(MainloopContext &aMainloop)
 {
     if (mIcmp6RawSock >= 0)
     {
-        FD_SET(mIcmp6RawSock, &aMainloop.mReadFdSet);
-        aMainloop.mMaxFd = std::max(aMainloop.mMaxFd, mIcmp6RawSock);
+        aMainloop.AddFdToReadSet(mIcmp6RawSock);
     }
 
     if (mUnicastNsQueueSock >= 0)
     {
-        FD_SET(mUnicastNsQueueSock, &aMainloop.mReadFdSet);
-        aMainloop.mMaxFd = std::max(aMainloop.mMaxFd, mUnicastNsQueueSock);
+        aMainloop.AddFdToReadSet(mUnicastNsQueueSock);
     }
 }
 
@@ -311,7 +309,7 @@ void NdProxyManager::SendNeighborAdvertisement(const Ip6Address &aTarget, const
     otbrError                  error = OTBR_ERROR_NONE;
     otBackboneRouterNdProxyInfo aNdProxyInfo;
 
-    VerifyOrExit(otBackboneRouterGetNdProxyInfo(mNcp.GetInstance(), reinterpret_cast<const otIp6Address *>(&aTarget),
+    VerifyOrExit(otBackboneRouterGetNdProxyInfo(mHost.GetInstance(), reinterpret_cast<const otIp6Address *>(&aTarget),
                                                 &aNdProxyInfo) == OT_ERROR_NONE,
                  error = OTBR_ERROR_OPENTHREAD);
 
diff --git a/src/backbone_router/nd_proxy.hpp b/src/backbone_router/nd_proxy.hpp
index 3a7a2d26..92823c75 100644
--- a/src/backbone_router/nd_proxy.hpp
+++ b/src/backbone_router/nd_proxy.hpp
@@ -55,7 +55,7 @@
 #include "common/code_utils.hpp"
 #include "common/mainloop.hpp"
 #include "common/types.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 namespace BackboneRouter {
@@ -80,8 +80,8 @@ public:
      * This constructor initializes a NdProxyManager instance.
      *
      */
-    explicit NdProxyManager(otbr::Ncp::ControllerOpenThread &aNcp, std::string aBackboneInterfaceName)
-        : mNcp(aNcp)
+    explicit NdProxyManager(otbr::Ncp::RcpHost &aHost, std::string aBackboneInterfaceName)
+        : mHost(aHost)
         , mBackboneInterfaceName(std::move(aBackboneInterfaceName))
         , mIcmp6RawSock(-1)
         , mUnicastNsQueueSock(-1)
@@ -153,16 +153,16 @@ private:
                                     void                *aContext);
     int HandleNetfilterQueue(struct nfq_q_handle *aNfQueueHandler, struct nfgenmsg *aNfMsg, struct nfq_data *aNfData);
 
-    otbr::Ncp::ControllerOpenThread &mNcp;
-    std::string                      mBackboneInterfaceName;
-    std::set<Ip6Address>             mNdProxySet;
-    uint32_t                         mBackboneIfIndex;
-    int                              mIcmp6RawSock;
-    int                              mUnicastNsQueueSock;
-    struct nfq_handle               *mNfqHandler;      ///< A pointer to an NFQUEUE handler.
-    struct nfq_q_handle             *mNfqQueueHandler; ///< A pointer to a newly created queue.
-    MacAddress                       mMacAddress;
-    Ip6Prefix                        mDomainPrefix;
+    otbr::Ncp::RcpHost  &mHost;
+    std::string          mBackboneInterfaceName;
+    std::set<Ip6Address> mNdProxySet;
+    uint32_t             mBackboneIfIndex;
+    int                  mIcmp6RawSock;
+    int                  mUnicastNsQueueSock;
+    struct nfq_handle   *mNfqHandler;      ///< A pointer to an NFQUEUE handler.
+    struct nfq_q_handle *mNfqQueueHandler; ///< A pointer to a newly created queue.
+    MacAddress           mMacAddress;
+    Ip6Prefix            mDomainPrefix;
 };
 
 /**
diff --git a/src/border_agent/border_agent.cpp b/src/border_agent/border_agent.cpp
index 96700d58..d63c6176 100644
--- a/src/border_agent/border_agent.cpp
+++ b/src/border_agent/border_agent.cpp
@@ -50,13 +50,16 @@
 
 #include <openthread/border_agent.h>
 #include <openthread/border_routing.h>
+#include <openthread/random_crypto.h>
 #include <openthread/random_noncrypto.h>
+#include <openthread/thread.h>
 #include <openthread/thread_ftd.h>
+#include <openthread/verhoeff_checksum.h>
 #include <openthread/platform/settings.h>
 #include <openthread/platform/toolchain.h>
 
 #include "agent/uris.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 #if OTBR_ENABLE_BACKBONE_ROUTER
 #include "backbone_router/backbone_agent.hpp"
 #endif
@@ -67,10 +70,16 @@
 #include "common/types.hpp"
 #include "utils/hex.hpp"
 
+#if !(OTBR_ENABLE_MDNS_AVAHI || OTBR_ENABLE_MDNS_MDNSSD || OTBR_ENABLE_MDNS_MOJO)
+#error "Border Agent feature requires at least one `OTBR_MDNS` implementation"
+#endif
+
 namespace otbr {
 
-static const char    kBorderAgentServiceType[]    = "_meshcop._udp"; ///< Border agent service type of mDNS
-static constexpr int kBorderAgentServiceDummyPort = 49152;
+static const char    kBorderAgentServiceType[]      = "_meshcop._udp";   ///< Border agent service type of mDNS
+static const char    kBorderAgentEpskcServiceType[] = "_meshcop-e._udp"; ///< Border agent ePSKc service
+static constexpr int kBorderAgentServiceDummyPort   = 49152;
+static constexpr int kEpskcRandomGenLen             = 8;
 
 /**
  * Locators
@@ -98,6 +107,14 @@ enum : uint8_t
     kThreadIfStatusActive         = 2,
 };
 
+enum : uint8_t
+{
+    kThreadRoleDisabledOrDetached = 0,
+    kThreadRoleChild              = 1,
+    kThreadRoleRouter             = 2,
+    kThreadRoleLeader             = 3,
+};
+
 enum : uint8_t
 {
     kAvailabilityInfrequent = 0,
@@ -111,6 +128,8 @@ struct StateBitmap
     uint32_t mAvailability : 2;
     uint32_t mBbrIsActive : 1;
     uint32_t mBbrIsPrimary : 1;
+    uint32_t mThreadRole : 2;
+    uint32_t mEpskcSupported : 1;
 
     StateBitmap(void)
         : mConnectionMode(0)
@@ -118,6 +137,8 @@ struct StateBitmap
         , mAvailability(0)
         , mBbrIsActive(0)
         , mBbrIsPrimary(0)
+        , mThreadRole(kThreadRoleDisabledOrDetached)
+        , mEpskcSupported(0)
     {
     }
 
@@ -130,20 +151,50 @@ struct StateBitmap
         bitmap |= mAvailability << 5;
         bitmap |= mBbrIsActive << 7;
         bitmap |= mBbrIsPrimary << 8;
-
+        bitmap |= mThreadRole << 9;
+        bitmap |= mEpskcSupported << 11;
         return bitmap;
     }
 };
 
-BorderAgent::BorderAgent(otbr::Ncp::ControllerOpenThread &aNcp, Mdns::Publisher &aPublisher)
-    : mNcp(aNcp)
+BorderAgent::BorderAgent(otbr::Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher)
+    : mHost(aHost)
     , mPublisher(aPublisher)
     , mIsEnabled(false)
+    , mIsEphemeralKeyEnabled(otThreadGetVersion() >= OT_THREAD_VERSION_1_4)
     , mVendorName(OTBR_VENDOR_NAME)
     , mProductName(OTBR_PRODUCT_NAME)
     , mBaseServiceInstanceName(OTBR_MESHCOP_SERVICE_INSTANCE_NAME)
 {
-    mNcp.AddThreadStateChangedCallback([this](otChangedFlags aFlags) { HandleThreadStateChanged(aFlags); });
+    mHost.AddThreadStateChangedCallback([this](otChangedFlags aFlags) { HandleThreadStateChanged(aFlags); });
+    otbrLogInfo("Ephemeral Key is: %s during initialization", (mIsEphemeralKeyEnabled ? "enabled" : "disabled"));
+}
+
+otbrError BorderAgent::CreateEphemeralKey(std::string &aEphemeralKey)
+{
+    std::string digitString;
+    char        checksum;
+    uint8_t     candidateBuffer[1];
+    otbrError   error = OTBR_ERROR_NONE;
+
+    for (uint8_t i = 0; i < kEpskcRandomGenLen; ++i)
+    {
+        while (true)
+        {
+            SuccessOrExit(otRandomCryptoFillBuffer(candidateBuffer, 1), error = OTBR_ERROR_ABORTED);
+            // Generates a random number in the range [0, 9] with equal probability.
+            if (candidateBuffer[0] < 250)
+            {
+                digitString += static_cast<char>('0' + candidateBuffer[0] % 10);
+                break;
+            }
+        }
+    }
+    SuccessOrExit(otVerhoeffChecksumCalculate(digitString.c_str(), &checksum), error = OTBR_ERROR_INVALID_ARGS);
+    aEphemeralKey = digitString + checksum;
+
+exit:
+    return error;
 }
 
 otbrError BorderAgent::SetMeshCopServiceValues(const std::string              &aServiceInstanceName,
@@ -193,23 +244,45 @@ exit:
     return;
 }
 
+void BorderAgent::SetEphemeralKeyEnabled(bool aIsEnabled)
+{
+    VerifyOrExit(GetEphemeralKeyEnabled() != aIsEnabled);
+    mIsEphemeralKeyEnabled = aIsEnabled;
+
+    if (!mIsEphemeralKeyEnabled)
+    {
+        // If the ePSKc feature is enabled, we call the clear function which
+        // will wait for the session to close if it is in active use before
+        // removing ephemeral key and unpublishing the service.
+        otBorderAgentClearEphemeralKey(mHost.GetInstance());
+    }
+
+    UpdateMeshCopService();
+
+exit:
+    return;
+}
+
 void BorderAgent::Start(void)
 {
     otbrLogInfo("Start Thread Border Agent");
 
 #if OTBR_ENABLE_DBUS_SERVER
-    mNcp.GetThreadHelper()->SetUpdateMeshCopTxtHandler([this](std::map<std::string, std::vector<uint8_t>> aUpdate) {
+    mHost.GetThreadHelper()->SetUpdateMeshCopTxtHandler([this](std::map<std::string, std::vector<uint8_t>> aUpdate) {
         HandleUpdateVendorMeshCoPTxtEntries(std::move(aUpdate));
     });
-    mNcp.RegisterResetHandler([this]() {
-        mNcp.GetThreadHelper()->SetUpdateMeshCopTxtHandler([this](std::map<std::string, std::vector<uint8_t>> aUpdate) {
-            HandleUpdateVendorMeshCoPTxtEntries(std::move(aUpdate));
-        });
+    mHost.RegisterResetHandler([this]() {
+        mHost.GetThreadHelper()->SetUpdateMeshCopTxtHandler(
+            [this](std::map<std::string, std::vector<uint8_t>> aUpdate) {
+                HandleUpdateVendorMeshCoPTxtEntries(std::move(aUpdate));
+            });
     });
 #endif
 
     mServiceInstanceName = GetServiceInstanceNameWithExtAddr(mBaseServiceInstanceName);
     UpdateMeshCopService();
+
+    otBorderAgentSetEphemeralKeyCallback(mHost.GetInstance(), BorderAgent::HandleEpskcStateChanged, this);
 }
 
 void BorderAgent::Stop(void)
@@ -218,6 +291,77 @@ void BorderAgent::Stop(void)
     UnpublishMeshCopService();
 }
 
+void BorderAgent::HandleEpskcStateChanged(void *aContext)
+{
+    BorderAgent *borderAgent = static_cast<BorderAgent *>(aContext);
+
+    if (otBorderAgentIsEphemeralKeyActive(borderAgent->mHost.GetInstance()))
+    {
+        borderAgent->PublishEpskcService();
+    }
+    else
+    {
+        borderAgent->UnpublishEpskcService();
+    }
+
+    for (auto &ephemeralKeyCallback : borderAgent->mEphemeralKeyChangedCallbacks)
+    {
+        ephemeralKeyCallback();
+    }
+}
+
+void BorderAgent::PublishEpskcService()
+{
+    otInstance *instance = mHost.GetInstance();
+    int         port     = otBorderAgentGetUdpPort(instance);
+
+    otbrLogInfo("Publish meshcop-e service %s.%s.local. port %d", mServiceInstanceName.c_str(),
+                kBorderAgentEpskcServiceType, port);
+
+    mPublisher.PublishService(/* aHostName */ "", mServiceInstanceName, kBorderAgentEpskcServiceType,
+                              Mdns::Publisher::SubTypeList{}, port, /* aTxtData */ {}, [this](otbrError aError) {
+                                  if (aError == OTBR_ERROR_ABORTED)
+                                  {
+                                      // OTBR_ERROR_ABORTED is thrown when an ongoing service registration is
+                                      // cancelled. This can happen when the meshcop-e service is being updated
+                                      // frequently. To avoid false alarms, it should not be logged like a real error.
+                                      otbrLogInfo("Cancelled previous publishing meshcop-e service %s.%s.local",
+                                                  mServiceInstanceName.c_str(), kBorderAgentEpskcServiceType);
+                                  }
+                                  else
+                                  {
+                                      otbrLogResult(aError, "Result of publish meshcop-e service %s.%s.local",
+                                                    mServiceInstanceName.c_str(), kBorderAgentEpskcServiceType);
+                                  }
+
+                                  if (aError == OTBR_ERROR_DUPLICATED)
+                                  {
+                                      // Try to unpublish current service in case we are trying to register
+                                      // multiple new services simultaneously when the original service name
+                                      // is conflicted.
+                                      // Potential risk that instance name is not the same with meshcop service.
+                                      UnpublishEpskcService();
+                                      mServiceInstanceName = GetAlternativeServiceInstanceName();
+                                      PublishEpskcService();
+                                  }
+                              });
+}
+
+void BorderAgent::UnpublishEpskcService()
+{
+    otbrLogInfo("Unpublish meshcop-e service %s.%s.local", mServiceInstanceName.c_str(), kBorderAgentEpskcServiceType);
+
+    mPublisher.UnpublishService(mServiceInstanceName, kBorderAgentEpskcServiceType, [this](otbrError aError) {
+        otbrLogResult(aError, "Result of unpublish meshcop-e service %s.%s.local", mServiceInstanceName.c_str(),
+                      kBorderAgentEpskcServiceType);
+    });
+}
+
+void BorderAgent::AddEphemeralKeyChangedCallback(EphemeralKeyChangedCallback aCallback)
+{
+    mEphemeralKeyChangedCallbacks.push_back(std::move(aCallback));
+}
+
 void BorderAgent::HandleMdnsState(Mdns::Publisher::State aState)
 {
     VerifyOrExit(IsEnabled());
@@ -274,12 +418,24 @@ StateBitmap GetStateBitmap(otInstance &aInstance)
     {
     case OT_DEVICE_ROLE_DISABLED:
         state.mThreadIfStatus = kThreadIfStatusNotInitialized;
+        state.mThreadRole     = kThreadRoleDisabledOrDetached;
         break;
     case OT_DEVICE_ROLE_DETACHED:
         state.mThreadIfStatus = kThreadIfStatusInitialized;
+        state.mThreadRole     = kThreadRoleDisabledOrDetached;
         break;
-    default:
+    case OT_DEVICE_ROLE_CHILD:
+        state.mThreadIfStatus = kThreadIfStatusActive;
+        state.mThreadRole     = kThreadRoleChild;
+        break;
+    case OT_DEVICE_ROLE_ROUTER:
+        state.mThreadIfStatus = kThreadIfStatusActive;
+        state.mThreadRole     = kThreadRoleRouter;
+        break;
+    case OT_DEVICE_ROLE_LEADER:
         state.mThreadIfStatus = kThreadIfStatusActive;
+        state.mThreadRole     = kThreadRoleLeader;
+        break;
     }
 
 #if OTBR_ENABLE_BACKBONE_ROUTER
@@ -357,7 +513,7 @@ void BorderAgent::PublishMeshCopService(void)
 {
     StateBitmap              state;
     uint32_t                 stateUint32;
-    otInstance              *instance    = mNcp.GetInstance();
+    otInstance              *instance    = mHost.GetInstance();
     const otExtendedPanId   *extPanId    = otThreadGetExtendedPanId(instance);
     const otExtAddress      *extAddr     = otLinkGetExtendedAddress(instance);
     const char              *networkName = otThreadGetNetworkName(instance);
@@ -401,13 +557,13 @@ void BorderAgent::PublishMeshCopService(void)
     }
     txtList.emplace_back("nn", networkName);
     txtList.emplace_back("xp", extPanId->m8, sizeof(extPanId->m8));
-    txtList.emplace_back("tv", mNcp.GetThreadVersion());
+    txtList.emplace_back("tv", mHost.GetThreadVersion());
 
     // "xa" stands for Extended MAC Address (64-bit) of the Thread Interface of the Border Agent.
     txtList.emplace_back("xa", extAddr->m8, sizeof(extAddr->m8));
-
-    state       = GetStateBitmap(*instance);
-    stateUint32 = htobe32(state.ToUint32());
+    state                 = GetStateBitmap(*instance);
+    state.mEpskcSupported = GetEphemeralKeyEnabled();
+    stateUint32           = htobe32(state.ToUint32());
     txtList.emplace_back("sb", reinterpret_cast<uint8_t *>(&stateUint32), sizeof(stateUint32));
 
     if (state.mThreadIfStatus == kThreadIfStatusActive)
@@ -520,14 +676,14 @@ exit:
 
 bool BorderAgent::IsThreadStarted(void) const
 {
-    otDeviceRole role = otThreadGetDeviceRole(mNcp.GetInstance());
+    otDeviceRole role = mHost.GetDeviceRole();
 
     return role == OT_DEVICE_ROLE_CHILD || role == OT_DEVICE_ROLE_ROUTER || role == OT_DEVICE_ROLE_LEADER;
 }
 
 std::string BorderAgent::GetServiceInstanceNameWithExtAddr(const std::string &aServiceInstanceName) const
 {
-    const otExtAddress *extAddress = otLinkGetExtendedAddress(mNcp.GetInstance());
+    const otExtAddress *extAddress = otLinkGetExtendedAddress(mHost.GetInstance());
     std::stringstream   ss;
 
     ss << aServiceInstanceName << " #";
diff --git a/src/border_agent/border_agent.hpp b/src/border_agent/border_agent.hpp
index b5b71f57..577368af 100644
--- a/src/border_agent/border_agent.hpp
+++ b/src/border_agent/border_agent.hpp
@@ -36,10 +36,6 @@
 
 #include "openthread-br/config.h"
 
-#if !(OTBR_ENABLE_MDNS_AVAHI || OTBR_ENABLE_MDNS_MDNSSD || OTBR_ENABLE_MDNS_MOJO)
-#error "Border Agent feature requires at least one `OTBR_MDNS` implementation"
-#endif
-
 #include <vector>
 
 #include <stdint.h>
@@ -48,7 +44,7 @@
 #include "common/code_utils.hpp"
 #include "common/mainloop.hpp"
 #include "mdns/mdns.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 #include "sdp_proxy/advertising_proxy.hpp"
 #include "sdp_proxy/discovery_proxy.hpp"
 #include "trel_dnssd/trel_dnssd.hpp"
@@ -83,14 +79,17 @@ namespace otbr {
 class BorderAgent : private NonCopyable
 {
 public:
+    /** The callback for receiving ephemeral key changes. */
+    using EphemeralKeyChangedCallback = std::function<void(void)>;
+
     /**
      * The constructor to initialize the Thread border agent.
      *
-     * @param[in] aNcp  A reference to the NCP controller.
+     * @param[in] aHost       A reference to the Thread controller.
      * @param[in] aPublisher  A reference to the mDNS Publisher.
      *
      */
-    BorderAgent(otbr::Ncp::ControllerOpenThread &aNcp, Mdns::Publisher &aPublisher);
+    BorderAgent(otbr::Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher);
 
     ~BorderAgent(void) = default;
 
@@ -126,6 +125,20 @@ public:
      */
     void SetEnabled(bool aIsEnabled);
 
+    /**
+     * This method enables/disables the Border Agent Ephemeral Key feature.
+     *
+     * @param[in] aIsEnabled  Whether to enable the BA Ephemeral Key feature.
+     *
+     */
+    void SetEphemeralKeyEnabled(bool aIsEnabled);
+
+    /**
+     * This method returns the Border Agent Ephemeral Key feature state.
+     *
+     */
+    bool GetEphemeralKeyEnabled(void) const { return mIsEphemeralKeyEnabled; }
+
     /**
      * This method handles mDNS publisher's state changes.
      *
@@ -134,6 +147,25 @@ public:
      */
     void HandleMdnsState(Mdns::Publisher::State aState);
 
+    /**
+     * This method creates ephemeral key in the Border Agent.
+     *
+     * @param[out] aEphemeralKey  The ephemeral key digit string of length 9 with first 8 digits randomly
+     *                            generated, and the last 9th digit as verhoeff checksum.
+     *
+     * @returns OTBR_ERROR_INVALID_ARGS  If Verhoeff checksum calculate returns error.
+     * @returns OTBR_ERROR_NONE          If successfully generate the ePSKc.
+     */
+    static otbrError CreateEphemeralKey(std::string &aEphemeralKey);
+
+    /**
+     * This method adds a callback for ephemeral key changes.
+     *
+     * @param[in] aCallback  The callback to receive ephemeral key changed events.
+     *
+     */
+    void AddEphemeralKeyChangedCallback(EphemeralKeyChangedCallback aCallback);
+
 private:
     void Start(void);
     void Stop(void);
@@ -151,9 +183,14 @@ private:
     std::string GetServiceInstanceNameWithExtAddr(const std::string &aServiceInstanceName) const;
     std::string GetAlternativeServiceInstanceName() const;
 
-    otbr::Ncp::ControllerOpenThread &mNcp;
-    Mdns::Publisher                 &mPublisher;
-    bool                             mIsEnabled;
+    static void HandleEpskcStateChanged(void *aContext);
+    void        PublishEpskcService(void);
+    void        UnpublishEpskcService(void);
+
+    otbr::Ncp::RcpHost &mHost;
+    Mdns::Publisher    &mPublisher;
+    bool                mIsEnabled;
+    bool                mIsEphemeralKeyEnabled;
 
     std::map<std::string, std::vector<uint8_t>> mMeshCopTxtUpdate;
 
@@ -172,6 +209,8 @@ private:
     // conflicts. For example, this value can be "OpenThread Border Router #7AC3" or
     // "OpenThread Border Router #7AC3 (14379)".
     std::string mServiceInstanceName;
+
+    std::vector<EphemeralKeyChangedCallback> mEphemeralKeyChangedCallbacks;
 };
 
 /**
diff --git a/src/common/api_strings.cpp b/src/common/api_strings.cpp
index fcb429f7..77fee923 100644
--- a/src/common/api_strings.cpp
+++ b/src/common/api_strings.cpp
@@ -53,3 +53,25 @@ std::string GetDeviceRoleName(otDeviceRole aRole)
 
     return roleName;
 }
+
+#if OTBR_ENABLE_DHCP6_PD
+std::string GetDhcp6PdStateName(otBorderRoutingDhcp6PdState aState)
+{
+    std::string stateName;
+
+    switch (aState)
+    {
+    case OT_BORDER_ROUTING_DHCP6_PD_STATE_DISABLED:
+        stateName = OTBR_DHCP6_PD_STATE_NAME_DISABLED;
+        break;
+    case OT_BORDER_ROUTING_DHCP6_PD_STATE_STOPPED:
+        stateName = OTBR_DHCP6_PD_STATE_NAME_STOPPED;
+        break;
+    case OT_BORDER_ROUTING_DHCP6_PD_STATE_RUNNING:
+        stateName = OTBR_DHCP6_PD_STATE_NAME_RUNNING;
+        break;
+    }
+
+    return stateName;
+}
+#endif // OTBR_ENABLE_DHCP6_PD
diff --git a/src/common/api_strings.hpp b/src/common/api_strings.hpp
index 8b1eb9fc..30ec9b80 100644
--- a/src/common/api_strings.hpp
+++ b/src/common/api_strings.hpp
@@ -39,6 +39,7 @@
 
 #include <string>
 
+#include <openthread/border_routing.h>
 #include <openthread/thread.h>
 
 #define OTBR_ROLE_NAME_DISABLED "disabled"
@@ -47,6 +48,16 @@
 #define OTBR_ROLE_NAME_ROUTER "router"
 #define OTBR_ROLE_NAME_LEADER "leader"
 
+#if OTBR_ENABLE_DHCP6_PD
+#define OTBR_DHCP6_PD_STATE_NAME_DISABLED "disabled"
+#define OTBR_DHCP6_PD_STATE_NAME_STOPPED "stopped"
+#define OTBR_DHCP6_PD_STATE_NAME_RUNNING "running"
+#endif
+
 std::string GetDeviceRoleName(otDeviceRole aRole);
 
+#if OTBR_ENABLE_DHCP6_PD
+std::string GetDhcp6PdStateName(otBorderRoutingDhcp6PdState aDhcp6PdState);
+#endif // OTBR_ENABLE_DHCP6_PD
+
 #endif // OTBR_COMMON_API_STRINGS_HPP_
diff --git a/src/common/code_utils.hpp b/src/common/code_utils.hpp
index 87791a2b..ade155c0 100644
--- a/src/common/code_utils.hpp
+++ b/src/common/code_utils.hpp
@@ -142,6 +142,19 @@
         }                                                                    \
     } while (false)
 
+/**
+ * This macro prints the message and terminates the program.
+ *
+ * @param[in] aMessage    A message (text string) to print.
+ *
+ */
+#define DieNow(aMessage)                                                 \
+    do                                                                   \
+    {                                                                    \
+        otbrLogEmerg("FAILED %s:%d - %s", __FILE__, __LINE__, aMessage); \
+        exit(-1);                                                        \
+    } while (false)
+
 /**
  *  This unconditionally executes @a ... and branches to the local
  *  label 'exit'.
diff --git a/src/common/mainloop.cpp b/src/common/mainloop.cpp
index f2024fbb..f7400b5c 100644
--- a/src/common/mainloop.cpp
+++ b/src/common/mainloop.cpp
@@ -40,4 +40,36 @@ MainloopProcessor::~MainloopProcessor(void)
 {
     MainloopManager::GetInstance().RemoveMainloopProcessor(this);
 }
+
+void MainloopContext::AddFdToReadSet(int aFd)
+{
+    AddFdToSet(aFd, kReadFdSet);
+}
+
+void MainloopContext::AddFdToSet(int aFd, uint8_t aFdSetsMask)
+{
+    bool isSet = false;
+
+    if (aFdSetsMask & kErrorFdSet)
+    {
+        FD_SET(aFd, &mErrorFdSet);
+        isSet = true;
+    }
+    if (aFdSetsMask & kReadFdSet)
+    {
+        FD_SET(aFd, &mReadFdSet);
+        isSet = true;
+    }
+    if (aFdSetsMask & kWriteFdSet)
+    {
+        FD_SET(aFd, &mWriteFdSet);
+        isSet = true;
+    }
+
+    if (isSet)
+    {
+        mMaxFd = std::max(mMaxFd, aFd);
+    }
+}
+
 } // namespace otbr
diff --git a/src/common/mainloop.hpp b/src/common/mainloop.hpp
index 91ccb589..57e96026 100644
--- a/src/common/mainloop.hpp
+++ b/src/common/mainloop.hpp
@@ -44,7 +44,30 @@ namespace otbr {
  * This type defines the context data for running a mainloop.
  *
  */
-using MainloopContext = otSysMainloopContext;
+class MainloopContext : public otSysMainloopContext
+{
+public:
+    static constexpr uint8_t kErrorFdSet = 1 << 0;
+    static constexpr uint8_t kReadFdSet  = 1 << 1;
+    static constexpr uint8_t kWriteFdSet = 1 << 2;
+
+    /**
+     * This method adds a fd to the read fd set inside the MainloopContext.
+     *
+     * @param[in] aFd  The fd to add.
+     *
+     */
+    void AddFdToReadSet(int aFd);
+
+    /**
+     * This method adds a fd to the fd sets inside the MainloopContext.
+     *
+     * @param[in] aFd          The fd to add.
+     * @param[in] aFdSetsMask  A bitmask indicating which fd sets to add.
+     *
+     */
+    void AddFdToSet(int aFd, uint8_t aFdSetsMask);
+};
 
 /**
  * This abstract class defines the interface of a mainloop processor
diff --git a/src/common/mainloop_manager.hpp b/src/common/mainloop_manager.hpp
index 381ebfb5..739d9de4 100644
--- a/src/common/mainloop_manager.hpp
+++ b/src/common/mainloop_manager.hpp
@@ -42,7 +42,7 @@
 
 #include "common/code_utils.hpp"
 #include "common/mainloop.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 
diff --git a/src/common/task_runner.cpp b/src/common/task_runner.cpp
index 9a7f154d..28c715cd 100644
--- a/src/common/task_runner.cpp
+++ b/src/common/task_runner.cpp
@@ -82,8 +82,7 @@ TaskRunner::TaskId TaskRunner::Post(Milliseconds aDelay, Task<void> aTask)
 
 void TaskRunner::Update(MainloopContext &aMainloop)
 {
-    FD_SET(mEventFd[kRead], &aMainloop.mReadFdSet);
-    aMainloop.mMaxFd = std::max(mEventFd[kRead], aMainloop.mMaxFd);
+    aMainloop.AddFdToReadSet(mEventFd[kRead]);
 
     {
         std::lock_guard<std::mutex> _(mTaskQueueMutex);
diff --git a/src/common/types.cpp b/src/common/types.cpp
index ce583ab0..2fef20f8 100644
--- a/src/common/types.cpp
+++ b/src/common/types.cpp
@@ -41,6 +41,11 @@ Ip6Address::Ip6Address(const uint8_t (&aAddress)[16])
     memcpy(m8, aAddress, sizeof(m8));
 }
 
+Ip6Address::Ip6Address(const otIp6Address &aAddress)
+{
+    memcpy(m8, aAddress.mFields.m8, sizeof(m8));
+}
+
 std::string Ip6Address::ToString() const
 {
     char strbuf[INET6_ADDRSTRLEN];
@@ -104,6 +109,35 @@ Ip6Address Ip6Address::FromString(const char *aStr)
     return addr;
 }
 
+bool Ip6Prefix::operator==(const Ip6Prefix &aOther) const
+{
+    bool    isEqual = false;
+    uint8_t lengthFullBytes;     // the number of complete bytes in the prefix length
+    uint8_t lengthRemainingBits; // the number of remaining bits in the prefix length that do not form a complete byte
+
+    VerifyOrExit(mLength == aOther.mLength);
+
+    lengthFullBytes     = mLength / 8;
+    lengthRemainingBits = mLength % 8;
+    VerifyOrExit(memcmp(mPrefix.m8, aOther.mPrefix.m8, lengthFullBytes) == 0);
+
+    if (lengthRemainingBits > 0)
+    {
+        uint8_t mask = 0xff << (8 - lengthRemainingBits);
+        VerifyOrExit((mPrefix.m8[lengthFullBytes] & mask) == (aOther.mPrefix.m8[lengthFullBytes] & mask));
+    }
+
+    isEqual = true;
+
+exit:
+    return isEqual;
+}
+
+bool Ip6Prefix::operator!=(const Ip6Prefix &aOther) const
+{
+    return !(*this == aOther);
+}
+
 void Ip6Prefix::Set(const otIp6Prefix &aPrefix)
 {
     memcpy(reinterpret_cast<void *>(this), &aPrefix, sizeof(*this));
@@ -135,4 +169,46 @@ std::string MacAddress::ToString(void) const
     return std::string(strbuf);
 }
 
+otError OtbrErrorToOtError(otbrError aError)
+{
+    otError error;
+
+    switch (aError)
+    {
+    case OTBR_ERROR_NONE:
+        error = OT_ERROR_NONE;
+        break;
+
+    case OTBR_ERROR_NOT_FOUND:
+        error = OT_ERROR_NOT_FOUND;
+        break;
+
+    case OTBR_ERROR_PARSE:
+        error = OT_ERROR_PARSE;
+        break;
+
+    case OTBR_ERROR_NOT_IMPLEMENTED:
+        error = OT_ERROR_NOT_IMPLEMENTED;
+        break;
+
+    case OTBR_ERROR_INVALID_ARGS:
+        error = OT_ERROR_INVALID_ARGS;
+        break;
+
+    case OTBR_ERROR_DUPLICATED:
+        error = OT_ERROR_DUPLICATED;
+        break;
+
+    case OTBR_ERROR_INVALID_STATE:
+        error = OT_ERROR_INVALID_STATE;
+        break;
+
+    default:
+        error = OT_ERROR_FAILED;
+        break;
+    }
+
+    return error;
+}
+
 } // namespace otbr
diff --git a/src/common/types.hpp b/src/common/types.hpp
index a5cd5471..c9cb2d07 100644
--- a/src/common/types.hpp
+++ b/src/common/types.hpp
@@ -42,6 +42,9 @@
 #include <string>
 #include <vector>
 
+#include <openthread/error.h>
+#include <openthread/ip6.h>
+
 #include "common/byteswap.hpp"
 
 #ifndef IN6ADDR_ANY
@@ -85,6 +88,7 @@ enum otbrError
     OTBR_ERROR_ABORTED            = -12, ///< The operation is aborted.
     OTBR_ERROR_INVALID_STATE      = -13, ///< The target isn't in a valid state.
     OTBR_ERROR_INFRA_LINK_CHANGED = -14, ///< The infrastructure link is changed.
+    OTBR_ERROR_DROPPED            = -15, ///< The packet is dropped.
 };
 
 namespace otbr {
@@ -141,6 +145,22 @@ public:
      */
     Ip6Address(const uint8_t (&aAddress)[16]);
 
+    /**
+     * Constructor with an otIp6Address.
+     *
+     * @param[in] aAddress  A const reference to an otIp6Address.
+     *
+     */
+    explicit Ip6Address(const otIp6Address &aAddress);
+
+    /**
+     * Constructor with a string.
+     *
+     * @param[in] aString The string representing the IPv6 address.
+     *
+     */
+    Ip6Address(const char *aString) { FromString(aString, *this); }
+
     /**
      * This method overloads `<` operator and compares if the Ip6 address is smaller than the other address.
      *
@@ -161,6 +181,16 @@ public:
      */
     bool operator==(const Ip6Address &aOther) const { return m64[0] == aOther.m64[0] && m64[1] == aOther.m64[1]; }
 
+    /**
+     * This method overloads `!=` operator and compares if the Ip6 address is NOT equal to the other address.
+     *
+     * @param[in] aOther  The other Ip6 address to compare with.
+     *
+     * @returns Whether the Ip6 address is NOT equal to the other address.
+     *
+     */
+    bool operator!=(const Ip6Address &aOther) const { return !(*this == aOther); }
+
     /**
      * Retrieve the 16-bit Thread locator.
      *
@@ -314,6 +344,43 @@ public:
      */
     Ip6Prefix(void) { Clear(); }
 
+    /**
+     * Constructor with an Ip6 address string and prefix length.
+     *
+     * @param[in] aIp6AddrStr The IPv6 address string.
+     * @param[in] aLength     The prefix length.
+     *
+     */
+    Ip6Prefix(const char *aIp6AddrStr, uint8_t aLength)
+        : mPrefix(aIp6AddrStr)
+        , mLength(aLength)
+    {
+    }
+
+    /**
+     * This method overloads `==` operator for comparing two Ip6Prefix objects by comparing their prefix and length.
+     *
+     * Two IpPrefix objects are considered equal if:
+     *  - their lengths are equal, and
+     *  - their first n-bits of the addresses are the same, where n is the length of the prefix.
+     *
+     * @param[in] aOther The Ip6Prefix object to compare with.
+     *
+     * @returns True if the two objects are equal, false otherwise.
+     *
+     */
+    bool operator==(const Ip6Prefix &aOther) const;
+
+    /**
+     * This method overloads `!=` operator for comparing two Ip6Prefix objects.
+
+     * @param[in] aOther The Ip6Prefix object to compare with.
+     *
+     * @returns True if the two objects are NOT equal, false otherwise.
+     *
+     */
+    bool operator!=(const Ip6Prefix &aOther) const;
+
     /**
      * This method sets the Ip6 prefix to an `otIp6Prefix` value.
      *
@@ -344,10 +411,59 @@ public:
      */
     bool IsValid(void) const { return mLength > 0 && mLength <= 128; }
 
+    /**
+     * This method checks if the object is the default route prefix ("::/0")
+     *
+     * @returns true if the object is the default route prefix, false otherwise.
+     *
+     */
+    bool IsDefaultRoutePrefix(void) const { return (*this == Ip6Prefix("::", 0)); }
+
+    /**
+     * This method checks if the object is the ULA prefix ("fc00::/7")
+     *
+     * @returns true if the object is the ULA prefix, false otherwise.
+     *
+     */
+    bool IsUlaPrefix(void) const { return (*this == Ip6Prefix("fc00::", 7)); }
+
     Ip6Address mPrefix; ///< The IPv6 prefix.
     uint8_t    mLength; ///< The IPv6 prefix length (in bits).
 };
 
+/**
+ * This class represents a Ipv6 address and its info.
+ *
+ */
+class Ip6AddressInfo
+{
+public:
+    Ip6AddressInfo(void) { Clear(); }
+
+    Ip6AddressInfo(const otIp6Address &aAddress,
+                   uint8_t             aPrefixLength,
+                   uint8_t             aScope,
+                   bool                aPreferred,
+                   bool                aMeshLocal)
+        : mAddress(aAddress)
+        , mPrefixLength(aPrefixLength)
+        , mScope(aScope)
+        , mPreferred(aPreferred)
+        , mMeshLocal(aMeshLocal)
+    {
+    }
+
+    void Clear(void) { memset(reinterpret_cast<void *>(this), 0, sizeof(*this)); }
+
+    otIp6Address mAddress;
+    uint8_t      mPrefixLength;
+    uint8_t      mScope : 4;
+    bool         mPreferred : 1;
+    bool         mMeshLocal : 1;
+
+    bool operator==(const Ip6AddressInfo &aOther) const { return memcmp(this, &aOther, sizeof(Ip6AddressInfo)) == 0; }
+};
+
 /**
  * This class represents an ethernet MAC address.
  */
@@ -418,6 +534,16 @@ static constexpr size_t kVendorOuiLength      = 3;
 static constexpr size_t kMaxVendorNameLength  = 24;
 static constexpr size_t kMaxProductNameLength = 24;
 
+/**
+ * This method converts a otbrError to a otError.
+ *
+ * @param[in]  aError  a otbrError code.
+ *
+ * @returns  a otError code.
+ *
+ */
+otError OtbrErrorToOtError(otbrError aError);
+
 } // namespace otbr
 
 #endif // OTBR_COMMON_TYPES_HPP_
diff --git a/src/dbus/client/thread_api_dbus.cpp b/src/dbus/client/thread_api_dbus.cpp
index 944c23f5..51f8828e 100644
--- a/src/dbus/client/thread_api_dbus.cpp
+++ b/src/dbus/client/thread_api_dbus.cpp
@@ -463,6 +463,11 @@ ClientError ThreadApiDBus::SetNat64Enabled(bool aEnabled)
     return CallDBusMethodSync(OTBR_DBUS_SET_NAT64_ENABLED_METHOD, std::tie(aEnabled));
 }
 
+ClientError ThreadApiDBus::SetEphemeralKeyEnabled(bool aEnabled)
+{
+    return SetProperty(OTBR_DBUS_PROPERTY_EPHEMERAL_KEY_ENABLED, aEnabled);
+}
+
 ClientError ThreadApiDBus::SetMeshLocalPrefix(const std::array<uint8_t, OTBR_IP6_PREFIX_SIZE> &aPrefix)
 {
     return SetProperty(OTBR_DBUS_PROPERTY_MESH_LOCAL_PREFIX, aPrefix);
@@ -488,6 +493,11 @@ ClientError ThreadApiDBus::SetRadioRegion(const std::string &aRadioRegion)
     return SetProperty(OTBR_DBUS_PROPERTY_RADIO_REGION, aRadioRegion);
 }
 
+ClientError ThreadApiDBus::GetEphemeralKeyEnabled(bool &aEnabled)
+{
+    return GetProperty(OTBR_DBUS_PROPERTY_EPHEMERAL_KEY_ENABLED, aEnabled);
+}
+
 ClientError ThreadApiDBus::GetLinkMode(LinkModeConfig &aConfig)
 {
     return GetProperty(OTBR_DBUS_PROPERTY_LINK_MODE, aConfig);
diff --git a/src/dbus/client/thread_api_dbus.hpp b/src/dbus/client/thread_api_dbus.hpp
index b47aaedc..d881f4e9 100644
--- a/src/dbus/client/thread_api_dbus.hpp
+++ b/src/dbus/client/thread_api_dbus.hpp
@@ -362,7 +362,7 @@ public:
     /**
      * This method sets the NAT64 switch.
      *
-     * @param[in] aEnable  A boolean to enable/disable the NAT64.
+     * @param[in] aEnabled  A boolean to enable/disable the NAT64.
      *
      * @retval ERROR_NONE  Successfully performed the dbus function call
      * @retval ERROR_DBUS  dbus encode/decode error
@@ -371,6 +371,30 @@ public:
      */
     ClientError SetNat64Enabled(bool aEnabled);
 
+    /**
+     * This method sets the Ephemeral Key switch.
+     *
+     * @param[in] aEnabled  A boolean to enable/disable the Ephemeral Key.
+     *
+     * @retval ERROR_NONE  Successfully performed the dbus function call
+     * @retval ERROR_DBUS  dbus encode/decode error
+     * @retval ...         OpenThread defined error value otherwise
+     *
+     */
+    ClientError SetEphemeralKeyEnabled(bool aEnabled);
+
+    /**
+     * This method gets the Ephemeral Key switch.
+     *
+     * @param[out] aEnabled  A boolean of enable/disable for Ephemeral Key state.
+     *
+     * @retval ERROR_NONE  Successfully performed the dbus function call
+     * @retval ERROR_DBUS  dbus encode/decode error
+     * @retval ...         OpenThread defined error value otherwise
+     *
+     */
+    ClientError GetEphemeralKeyEnabled(bool &aEnabled);
+
     /**
      * This method gets the link operating mode.
      *
diff --git a/src/dbus/common/constants.hpp b/src/dbus/common/constants.hpp
index a8e16482..0238bc55 100644
--- a/src/dbus/common/constants.hpp
+++ b/src/dbus/common/constants.hpp
@@ -48,6 +48,7 @@
 #define OTBR_DBUS_ENERGY_SCAN_METHOD "EnergyScan"
 #define OTBR_DBUS_ATTACH_METHOD "Attach"
 #define OTBR_DBUS_DETACH_METHOD "Detach"
+#define OTBR_DBUS_JOIN_METHOD "Join"
 #define OTBR_DBUS_FACTORY_RESET_METHOD "FactoryReset"
 #define OTBR_DBUS_RESET_METHOD "Reset"
 #define OTBR_DBUS_ADD_ON_MESH_PREFIX_METHOD "AddOnMeshPrefix"
@@ -62,6 +63,9 @@
 #define OTBR_DBUS_GET_PROPERTIES_METHOD "GetProperties"
 #define OTBR_DBUS_LEAVE_NETWORK_METHOD "LeaveNetwork"
 #define OTBR_DBUS_SET_NAT64_ENABLED_METHOD "SetNat64Enabled"
+#define OTBR_DBUS_ACTIVATE_EPHEMERAL_KEY_MODE_METHOD "ActivateEphemeralKeyMode"
+#define OTBR_DBUS_DEACTIVATE_EPHEMERAL_KEY_MODE_METHOD "DeactivateEphemeralKeyMode"
+#define OTBR_DBUS_SCHEDULE_MIGRATION_METHOD "ScheduleMigration"
 
 #define OTBR_DBUS_PROPERTY_MESH_LOCAL_PREFIX "MeshLocalPrefix"
 #define OTBR_DBUS_PROPERTY_LINK_MODE "LinkMode"
@@ -115,8 +119,10 @@
 #define OTBR_DBUS_PROPERTY_NAT64_MAPPINGS "Nat64Mappings"
 #define OTBR_DBUS_PROPERTY_NAT64_PROTOCOL_COUNTERS "Nat64ProtocolCounters"
 #define OTBR_DBUS_PROPERTY_NAT64_ERROR_COUNTERS "Nat64ErrorCounters"
+#define OTBR_DBUS_PROPERTY_EPHEMERAL_KEY_ENABLED "EphemeralKeyEnabled"
 #define OTBR_DBUS_PROPERTY_INFRA_LINK_INFO "InfraLinkInfo"
 #define OTBR_DBUS_PROPERTY_DNS_UPSTREAM_QUERY_STATE "DnsUpstreamQueryState"
+#define OTBR_DBUS_PROPERTY_DHCP6_PD_STATE "Dhcp6PdState"
 #define OTBR_DBUS_PROPERTY_TELEMETRY_DATA "TelemetryData"
 #define OTBR_DBUS_PROPERTY_CAPABILITIES "Capabilities"
 
diff --git a/src/dbus/common/dbus_message_helper_openthread.cpp b/src/dbus/common/dbus_message_helper_openthread.cpp
index d0d77700..e8a62b05 100644
--- a/src/dbus/common/dbus_message_helper_openthread.cpp
+++ b/src/dbus/common/dbus_message_helper_openthread.cpp
@@ -1165,9 +1165,9 @@ otbrError DBusMessageEncode(DBusMessageIter *aIter, const InfraLinkInfo &aInfraL
     SuccessOrExit(error = DBusMessageEncode(&sub, aInfraLinkInfo.mIsUp));
     SuccessOrExit(error = DBusMessageEncode(&sub, aInfraLinkInfo.mIsRunning));
     SuccessOrExit(error = DBusMessageEncode(&sub, aInfraLinkInfo.mIsMulticast));
-    SuccessOrExit(error = DBusMessageEncode(&sub, aInfraLinkInfo.mLinkLocalAddresses));
-    SuccessOrExit(error = DBusMessageEncode(&sub, aInfraLinkInfo.mUniqueLocalAddresses));
-    SuccessOrExit(error = DBusMessageEncode(&sub, aInfraLinkInfo.mGlobalUnicastAddresses));
+    SuccessOrExit(error = DBusMessageEncode(&sub, aInfraLinkInfo.mLinkLocalAddressCount));
+    SuccessOrExit(error = DBusMessageEncode(&sub, aInfraLinkInfo.mUniqueLocalAddressCount));
+    SuccessOrExit(error = DBusMessageEncode(&sub, aInfraLinkInfo.mGlobalUnicastAddressCount));
 
     VerifyOrExit(dbus_message_iter_close_container(aIter, &sub), error = OTBR_ERROR_DBUS);
 exit:
@@ -1185,9 +1185,9 @@ otbrError DBusMessageExtract(DBusMessageIter *aIter, InfraLinkInfo &aInfraLinkIn
     SuccessOrExit(error = DBusMessageExtract(&sub, aInfraLinkInfo.mIsUp));
     SuccessOrExit(error = DBusMessageExtract(&sub, aInfraLinkInfo.mIsRunning));
     SuccessOrExit(error = DBusMessageExtract(&sub, aInfraLinkInfo.mIsMulticast));
-    SuccessOrExit(error = DBusMessageExtract(&sub, aInfraLinkInfo.mLinkLocalAddresses));
-    SuccessOrExit(error = DBusMessageExtract(&sub, aInfraLinkInfo.mUniqueLocalAddresses));
-    SuccessOrExit(error = DBusMessageExtract(&sub, aInfraLinkInfo.mGlobalUnicastAddresses));
+    SuccessOrExit(error = DBusMessageExtract(&sub, aInfraLinkInfo.mLinkLocalAddressCount));
+    SuccessOrExit(error = DBusMessageExtract(&sub, aInfraLinkInfo.mUniqueLocalAddressCount));
+    SuccessOrExit(error = DBusMessageExtract(&sub, aInfraLinkInfo.mGlobalUnicastAddressCount));
 
     dbus_message_iter_next(aIter);
 exit:
diff --git a/src/dbus/common/types.hpp b/src/dbus/common/types.hpp
index 14f7fc29..94687e05 100644
--- a/src/dbus/common/types.hpp
+++ b/src/dbus/common/types.hpp
@@ -694,13 +694,13 @@ struct Nat64ErrorCounters
 
 struct InfraLinkInfo
 {
-    std::string mName;                   ///< The name of the infrastructure network interface.
-    bool        mIsUp;                   ///< Whether the infrastructure network interface is up.
-    bool        mIsRunning;              ///< Whether the infrastructure network interface is running.
-    bool        mIsMulticast;            ///< Whether the infrastructure network interface is multicast.
-    uint32_t    mLinkLocalAddresses;     ///< The number of link-local addresses on the infra network interface.
-    uint32_t    mUniqueLocalAddresses;   ///< The number of unique local addresses on the infra network interface.
-    uint32_t    mGlobalUnicastAddresses; ///< The number of global unicast addresses on the infra network interface.
+    std::string mName;                      ///< The name of the infrastructure network interface.
+    bool        mIsUp;                      ///< Whether the infrastructure network interface is up.
+    bool        mIsRunning;                 ///< Whether the infrastructure network interface is running.
+    bool        mIsMulticast;               ///< Whether the infrastructure network interface is multicast.
+    uint32_t    mLinkLocalAddressCount;     ///< The number of link-local addresses on the infra network interface.
+    uint32_t    mUniqueLocalAddressCount;   ///< The number of unique local addresses on the infra network interface.
+    uint32_t    mGlobalUnicastAddressCount; ///< The number of global unicast addresses on the infra network interface.
 };
 
 struct TrelInfo
@@ -715,7 +715,7 @@ struct TrelInfo
     };
 
     bool               mEnabled;      ///< Whether TREL is enabled.
-    u_int16_t          mNumTrelPeers; ///< The number of TREL peers.
+    uint16_t           mNumTrelPeers; ///< The number of TREL peers.
     TrelPacketCounters mTrelCounters; ///< The TREL counters.
 };
 
diff --git a/src/dbus/server/CMakeLists.txt b/src/dbus/server/CMakeLists.txt
index 2d0ae640..f8ee7c4c 100644
--- a/src/dbus/server/CMakeLists.txt
+++ b/src/dbus/server/CMakeLists.txt
@@ -37,7 +37,8 @@ add_custom_target(otbr-dbus-introspect-header ALL
 add_library(otbr-dbus-server STATIC
     dbus_agent.cpp
     dbus_object.cpp
-    dbus_thread_object.cpp
+    dbus_thread_object_ncp.cpp
+    dbus_thread_object_rcp.cpp
     error_helper.cpp
 )
 
@@ -55,7 +56,7 @@ target_link_libraries(otbr-dbus-server PUBLIC
 
 if(OTBR_DOC)
 add_custom_target(otbr-dbus-server-doc ALL
-    COMMAND gdbus-codegen --generate-docbook generated-docs ${CMAKE_CURRENT_SOURCE_DIR}/introspect.xml 
+    COMMAND gdbus-codegen --generate-docbook generated-docs ${CMAKE_CURRENT_SOURCE_DIR}/introspect.xml
     COMMAND xmlto html generated-docs-io.openthread.BorderRouter.xml
     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
     VERBATIM
diff --git a/src/dbus/server/dbus_agent.cpp b/src/dbus/server/dbus_agent.cpp
index c28773e6..6869971f 100644
--- a/src/dbus/server/dbus_agent.cpp
+++ b/src/dbus/server/dbus_agent.cpp
@@ -36,6 +36,8 @@
 
 #include "common/logging.hpp"
 #include "dbus/common/constants.hpp"
+#include "dbus/server/dbus_thread_object_ncp.hpp"
+#include "dbus/server/dbus_thread_object_rcp.hpp"
 #include "mdns/mdns.hpp"
 
 namespace otbr {
@@ -44,14 +46,14 @@ namespace DBus {
 const struct timeval           DBusAgent::kPollTimeout = {0, 0};
 constexpr std::chrono::seconds DBusAgent::kDBusWaitAllowance;
 
-DBusAgent::DBusAgent(otbr::Ncp::ControllerOpenThread &aNcp, Mdns::Publisher &aPublisher)
-    : mInterfaceName(aNcp.GetInterfaceName())
-    , mNcp(aNcp)
+DBusAgent::DBusAgent(otbr::Ncp::ThreadHost &aHost, Mdns::Publisher &aPublisher)
+    : mInterfaceName(aHost.GetInterfaceName())
+    , mHost(aHost)
     , mPublisher(aPublisher)
 {
 }
 
-void DBusAgent::Init(void)
+void DBusAgent::Init(otbr::BorderAgent &aBorderAgent)
 {
     otbrError error = OTBR_ERROR_NONE;
 
@@ -65,8 +67,23 @@ void DBusAgent::Init(void)
 
     VerifyOrDie(mConnection != nullptr, "Failed to get DBus connection");
 
-    mThreadObject =
-        std::unique_ptr<DBusThreadObject>(new DBusThreadObject(mConnection.get(), mInterfaceName, &mNcp, &mPublisher));
+    switch (mHost.GetCoprocessorType())
+    {
+    case OT_COPROCESSOR_RCP:
+        mThreadObject = MakeUnique<DBusThreadObjectRcp>(*mConnection, mInterfaceName,
+                                                        static_cast<Ncp::RcpHost &>(mHost), &mPublisher, aBorderAgent);
+        break;
+
+    case OT_COPROCESSOR_NCP:
+        mThreadObject =
+            MakeUnique<DBusThreadObjectNcp>(*mConnection, mInterfaceName, static_cast<Ncp::NcpHost &>(mHost));
+        break;
+
+    default:
+        DieNow("Unknown coprocessor type!");
+        break;
+    }
+
     error = mThreadObject->Init();
     VerifyOrDie(error == OTBR_ERROR_NONE, "Failed to initialize DBus Agent");
 }
@@ -122,6 +139,7 @@ void DBusAgent::Update(MainloopContext &aMainloop)
 {
     unsigned int flags;
     int          fd;
+    uint8_t      fdSetMask = MainloopContext::kErrorFdSet;
 
     if (dbus_connection_get_dispatch_status(mConnection.get()) == DBUS_DISPATCH_DATA_REMAINS)
     {
@@ -145,17 +163,15 @@ void DBusAgent::Update(MainloopContext &aMainloop)
 
         if (flags & DBUS_WATCH_READABLE)
         {
-            FD_SET(fd, &aMainloop.mReadFdSet);
+            fdSetMask |= MainloopContext::kReadFdSet;
         }
 
         if ((flags & DBUS_WATCH_WRITABLE))
         {
-            FD_SET(fd, &aMainloop.mWriteFdSet);
+            fdSetMask |= MainloopContext::kWriteFdSet;
         }
 
-        FD_SET(fd, &aMainloop.mErrorFdSet);
-
-        aMainloop.mMaxFd = std::max(aMainloop.mMaxFd, fd);
+        aMainloop.AddFdToSet(fd, fdSetMask);
     }
 }
 
diff --git a/src/dbus/server/dbus_agent.hpp b/src/dbus/server/dbus_agent.hpp
index c9308ec3..7825ddc7 100644
--- a/src/dbus/server/dbus_agent.hpp
+++ b/src/dbus/server/dbus_agent.hpp
@@ -46,9 +46,9 @@
 #include "dbus/common/dbus_message_helper.hpp"
 #include "dbus/common/dbus_resources.hpp"
 #include "dbus/server/dbus_object.hpp"
-#include "dbus/server/dbus_thread_object.hpp"
-
-#include "ncp/ncp_openthread.hpp"
+#include "dbus/server/dbus_thread_object_ncp.hpp"
+#include "dbus/server/dbus_thread_object_rcp.hpp"
+#include "ncp/thread_host.hpp"
 
 namespace otbr {
 namespace DBus {
@@ -59,16 +59,17 @@ public:
     /**
      * The constructor of dbus agent.
      *
-     * @param[in] aNcp  A reference to the NCP controller.
+     * @param[in] aHost           A reference to the Thread host.
+     * @param[in] aPublisher      A reference to the MDNS publisher.
      *
      */
-    DBusAgent(otbr::Ncp::ControllerOpenThread &aNcp, Mdns::Publisher &aPublisher);
+    DBusAgent(otbr::Ncp::ThreadHost &aHost, Mdns::Publisher &aPublisher);
 
     /**
      * This method initializes the dbus agent.
      *
      */
-    void Init(void);
+    void Init(otbr::BorderAgent &aBorderAgent);
 
     void Update(MainloopContext &aMainloop) override;
     void Process(const MainloopContext &aMainloop) override;
@@ -85,11 +86,11 @@ private:
 
     static const struct timeval kPollTimeout;
 
-    std::string                       mInterfaceName;
-    std::unique_ptr<DBusThreadObject> mThreadObject;
-    UniqueDBusConnection              mConnection;
-    otbr::Ncp::ControllerOpenThread  &mNcp;
-    Mdns::Publisher                  &mPublisher;
+    std::string                 mInterfaceName;
+    std::unique_ptr<DBusObject> mThreadObject;
+    UniqueDBusConnection        mConnection;
+    otbr::Ncp::ThreadHost      &mHost;
+    Mdns::Publisher            &mPublisher;
 
     /**
      * This map is used to track DBusWatch-es.
diff --git a/src/dbus/server/dbus_object.cpp b/src/dbus/server/dbus_object.cpp
index 64c384a6..4fd0f3cb 100644
--- a/src/dbus/server/dbus_object.cpp
+++ b/src/dbus/server/dbus_object.cpp
@@ -50,6 +50,11 @@ DBusObject::DBusObject(DBusConnection *aConnection, const std::string &aObjectPa
 }
 
 otbrError DBusObject::Init(void)
+{
+    return Initialize(/* aIsAsyncPropertyHandler */ false);
+}
+
+otbrError DBusObject::Initialize(bool aIsAsyncPropertyHandler)
 {
     otbrError            error = OTBR_ERROR_NONE;
     DBusObjectPathVTable vTable;
@@ -60,12 +65,21 @@ otbrError DBusObject::Init(void)
 
     VerifyOrExit(dbus_connection_register_object_path(mConnection, mObjectPath.c_str(), &vTable, this),
                  error = OTBR_ERROR_DBUS);
-    RegisterMethod(DBUS_INTERFACE_PROPERTIES, DBUS_PROPERTY_GET_METHOD,
-                   std::bind(&DBusObject::GetPropertyMethodHandler, this, _1));
-    RegisterMethod(DBUS_INTERFACE_PROPERTIES, DBUS_PROPERTY_SET_METHOD,
-                   std::bind(&DBusObject::SetPropertyMethodHandler, this, _1));
-    RegisterMethod(DBUS_INTERFACE_PROPERTIES, DBUS_PROPERTY_GET_ALL_METHOD,
-                   std::bind(&DBusObject::GetAllPropertiesMethodHandler, this, _1));
+
+    if (aIsAsyncPropertyHandler)
+    {
+        RegisterMethod(DBUS_INTERFACE_PROPERTIES, DBUS_PROPERTY_GET_METHOD,
+                       std::bind(&DBusObject::AsyncGetPropertyMethodHandler, this, _1));
+    }
+    else
+    {
+        RegisterMethod(DBUS_INTERFACE_PROPERTIES, DBUS_PROPERTY_GET_METHOD,
+                       std::bind(&DBusObject::GetPropertyMethodHandler, this, _1));
+        RegisterMethod(DBUS_INTERFACE_PROPERTIES, DBUS_PROPERTY_SET_METHOD,
+                       std::bind(&DBusObject::SetPropertyMethodHandler, this, _1));
+        RegisterMethod(DBUS_INTERFACE_PROPERTIES, DBUS_PROPERTY_GET_ALL_METHOD,
+                       std::bind(&DBusObject::GetAllPropertiesMethodHandler, this, _1));
+    }
 
 exit:
     return error;
@@ -98,6 +112,13 @@ void DBusObject::RegisterSetPropertyHandler(const std::string         &aInterfac
     mSetPropertyHandlers.emplace(fullPath, aHandler);
 }
 
+void DBusObject::RegisterAsyncGetPropertyHandler(const std::string              &aInterfaceName,
+                                                 const std::string              &aPropertyName,
+                                                 const AsyncPropertyHandlerType &aHandler)
+{
+    mAsyncGetPropertyHandlers[aInterfaceName].emplace(aPropertyName, aHandler);
+}
+
 DBusHandlerResult DBusObject::sMessageHandler(DBusConnection *aConnection, DBusMessage *aMessage, void *aData)
 {
     DBusObject *server = reinterpret_cast<DBusObject *>(aData);
@@ -252,6 +273,40 @@ exit:
     return;
 }
 
+void DBusObject::AsyncGetPropertyMethodHandler(DBusRequest &aRequest)
+{
+    DBusMessageIter iter;
+    std::string     interfaceName;
+    otError         error = OT_ERROR_NONE;
+    std::string     propertyName;
+
+    VerifyOrExit(dbus_message_iter_init(aRequest.GetMessage(), &iter), error = OT_ERROR_FAILED);
+    SuccessOrExit(error = OtbrErrorToOtError(DBusMessageExtract(&iter, interfaceName)));
+    SuccessOrExit(error = OtbrErrorToOtError(DBusMessageExtract(&iter, propertyName)));
+
+    {
+        auto propertyIter = mAsyncGetPropertyHandlers.find(interfaceName);
+
+        otbrLogDebug("AsyncGetProperty %s.%s", interfaceName.c_str(), propertyName.c_str());
+        VerifyOrExit(propertyIter != mAsyncGetPropertyHandlers.end(), error = OT_ERROR_NOT_FOUND);
+        {
+            auto &interfaceHandlers = propertyIter->second;
+            auto  interfaceIter     = interfaceHandlers.find(propertyName);
+
+            VerifyOrExit(interfaceIter != interfaceHandlers.end(), error = OT_ERROR_NOT_FOUND);
+            (interfaceIter->second)(aRequest);
+        }
+    }
+
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        otbrLogWarning("GetProperty %s.%s error:%s", interfaceName.c_str(), propertyName.c_str(),
+                       ConvertToDBusErrorName(error));
+        aRequest.ReplyOtResult(error);
+    }
+}
+
 DBusObject::~DBusObject(void)
 {
 }
diff --git a/src/dbus/server/dbus_object.hpp b/src/dbus/server/dbus_object.hpp
index 8aa335ba..f1a628bb 100644
--- a/src/dbus/server/dbus_object.hpp
+++ b/src/dbus/server/dbus_object.hpp
@@ -65,9 +65,9 @@ namespace DBus {
 class DBusObject : private NonCopyable
 {
 public:
-    using MethodHandlerType = std::function<void(DBusRequest &)>;
-
-    using PropertyHandlerType = std::function<otError(DBusMessageIter &)>;
+    using MethodHandlerType        = std::function<void(DBusRequest &)>;
+    using AsyncPropertyHandlerType = std::function<void(DBusRequest &)>;
+    using PropertyHandlerType      = std::function<otError(DBusMessageIter &)>;
 
     /**
      * The constructor of a d-bus object.
@@ -125,6 +125,18 @@ public:
                                             const std::string         &aPropertyName,
                                             const PropertyHandlerType &aHandler);
 
+    /**
+     * This method registers the async get handler for a property.
+     *
+     * @param[in] aInterfaceName  The interface name.
+     * @param[in] aPropertyName   The property name.
+     * @param[in] aHandler        The method handler.
+     *
+     */
+    virtual void RegisterAsyncGetPropertyHandler(const std::string              &aInterfaceName,
+                                                 const std::string              &aPropertyName,
+                                                 const AsyncPropertyHandlerType &aHandler);
+
     /**
      * This method sends a signal.
      *
@@ -220,10 +232,14 @@ public:
      */
     void Flush(void);
 
+protected:
+    otbrError Initialize(bool aIsAsyncPropertyHandler);
+
 private:
     void GetAllPropertiesMethodHandler(DBusRequest &aRequest);
     void GetPropertyMethodHandler(DBusRequest &aRequest);
     void SetPropertyMethodHandler(DBusRequest &aRequest);
+    void AsyncGetPropertyMethodHandler(DBusRequest &aRequest);
 
     static DBusHandlerResult sMessageHandler(DBusConnection *aConnection, DBusMessage *aMessage, void *aData);
     DBusHandlerResult        MessageHandler(DBusConnection *aConnection, DBusMessage *aMessage);
@@ -232,9 +248,11 @@ private:
 
     std::unordered_map<std::string, MethodHandlerType>                                    mMethodHandlers;
     std::unordered_map<std::string, std::unordered_map<std::string, PropertyHandlerType>> mGetPropertyHandlers;
-    std::unordered_map<std::string, PropertyHandlerType>                                  mSetPropertyHandlers;
-    DBusConnection                                                                       *mConnection;
-    std::string                                                                           mObjectPath;
+    std::unordered_map<std::string, std::unordered_map<std::string, AsyncPropertyHandlerType>>
+                                                         mAsyncGetPropertyHandlers;
+    std::unordered_map<std::string, PropertyHandlerType> mSetPropertyHandlers;
+    DBusConnection                                      *mConnection;
+    std::string                                          mObjectPath;
 };
 
 } // namespace DBus
diff --git a/src/dbus/server/dbus_thread_object_ncp.cpp b/src/dbus/server/dbus_thread_object_ncp.cpp
new file mode 100644
index 00000000..526a477f
--- /dev/null
+++ b/src/dbus/server/dbus_thread_object_ncp.cpp
@@ -0,0 +1,164 @@
+/*
+ *    Copyright (c) 2024, The OpenThread Authors.
+ *    All rights reserved.
+ *
+ *    Redistribution and use in source and binary forms, with or without
+ *    modification, are permitted provided that the following conditions are met:
+ *    1. Redistributions of source code must retain the above copyright
+ *       notice, this list of conditions and the following disclaimer.
+ *    2. Redistributions in binary form must reproduce the above copyright
+ *       notice, this list of conditions and the following disclaimer in the
+ *       documentation and/or other materials provided with the distribution.
+ *    3. Neither the name of the copyright holder nor the
+ *       names of its contributors may be used to endorse or promote products
+ *       derived from this software without specific prior written permission.
+ *
+ *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *    POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#include "dbus_thread_object_ncp.hpp"
+
+#include "common/api_strings.hpp"
+#include "common/byteswap.hpp"
+#include "common/code_utils.hpp"
+#include "dbus/common/constants.hpp"
+#include "dbus/server/dbus_agent.hpp"
+#include "utils/thread_helper.hpp"
+
+using std::placeholders::_1;
+using std::placeholders::_2;
+
+namespace otbr {
+namespace DBus {
+
+DBusThreadObjectNcp::DBusThreadObjectNcp(DBusConnection     &aConnection,
+                                         const std::string  &aInterfaceName,
+                                         otbr::Ncp::NcpHost &aHost)
+    : DBusObject(&aConnection, OTBR_DBUS_OBJECT_PREFIX + aInterfaceName)
+    , mHost(aHost)
+{
+}
+
+otbrError DBusThreadObjectNcp::Init(void)
+{
+    otbrError error = OTBR_ERROR_NONE;
+
+    SuccessOrExit(error = DBusObject::Initialize(true));
+
+    RegisterAsyncGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_DEVICE_ROLE,
+                                    std::bind(&DBusThreadObjectNcp::AsyncGetDeviceRoleHandler, this, _1));
+
+    RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_JOIN_METHOD,
+                   std::bind(&DBusThreadObjectNcp::JoinHandler, this, _1));
+    RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_LEAVE_NETWORK_METHOD,
+                   std::bind(&DBusThreadObjectNcp::LeaveHandler, this, _1));
+    RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_SCHEDULE_MIGRATION_METHOD,
+                   std::bind(&DBusThreadObjectNcp::ScheduleMigrationHandler, this, _1));
+
+    SuccessOrExit(error = Signal(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_SIGNAL_READY, std::make_tuple()));
+exit:
+    return error;
+}
+
+void DBusThreadObjectNcp::AsyncGetDeviceRoleHandler(DBusRequest &aRequest)
+{
+    otDeviceRole role = mHost.GetDeviceRole();
+
+    ReplyAsyncGetProperty(aRequest, GetDeviceRoleName(role));
+}
+
+void DBusThreadObjectNcp::ReplyAsyncGetProperty(DBusRequest &aRequest, const std::string &aContent)
+{
+    UniqueDBusMessage reply{dbus_message_new_method_return(aRequest.GetMessage())};
+    DBusMessageIter   replyIter;
+    otError           error = OT_ERROR_NONE;
+
+    dbus_message_iter_init_append(reply.get(), &replyIter);
+    SuccessOrExit(error = OtbrErrorToOtError(DBusMessageEncodeToVariant(&replyIter, aContent)));
+
+exit:
+    if (error == OT_ERROR_NONE)
+    {
+        dbus_connection_send(aRequest.GetConnection(), reply.get(), nullptr);
+    }
+    else
+    {
+        aRequest.ReplyOtResult(error);
+    }
+}
+
+void DBusThreadObjectNcp::JoinHandler(DBusRequest &aRequest)
+{
+    std::vector<uint8_t>     dataset;
+    otOperationalDatasetTlvs activeOpDatasetTlvs;
+    otError                  error = OT_ERROR_NONE;
+
+    auto args = std::tie(dataset);
+
+    SuccessOrExit(DBusMessageToTuple(*aRequest.GetMessage(), args), error = OT_ERROR_INVALID_ARGS);
+
+    VerifyOrExit(dataset.size() <= sizeof(activeOpDatasetTlvs.mTlvs), error = OT_ERROR_INVALID_ARGS);
+    std::copy(dataset.begin(), dataset.end(), activeOpDatasetTlvs.mTlvs);
+    activeOpDatasetTlvs.mLength = dataset.size();
+
+    mHost.Join(activeOpDatasetTlvs, [aRequest](otError aError, const std::string &aErrorInfo) mutable {
+        OT_UNUSED_VARIABLE(aErrorInfo);
+        aRequest.ReplyOtResult(aError);
+    });
+
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        aRequest.ReplyOtResult(error);
+    }
+}
+
+void DBusThreadObjectNcp::LeaveHandler(DBusRequest &aRequest)
+{
+    mHost.Leave([aRequest](otError aError, const std::string &aErrorInfo) mutable {
+        OT_UNUSED_VARIABLE(aErrorInfo);
+        aRequest.ReplyOtResult(aError);
+    });
+}
+
+void DBusThreadObjectNcp::ScheduleMigrationHandler(DBusRequest &aRequest)
+{
+    std::vector<uint8_t>     dataset;
+    uint32_t                 delayInMilli;
+    otOperationalDatasetTlvs pendingOpDatasetTlvs;
+    otError                  error = OT_ERROR_NONE;
+
+    auto args = std::tie(dataset, delayInMilli);
+
+    SuccessOrExit(DBusMessageToTuple(*aRequest.GetMessage(), args), error = OT_ERROR_INVALID_ARGS);
+
+    VerifyOrExit(dataset.size() <= sizeof(pendingOpDatasetTlvs.mTlvs), error = OT_ERROR_INVALID_ARGS);
+    std::copy(dataset.begin(), dataset.end(), pendingOpDatasetTlvs.mTlvs);
+    pendingOpDatasetTlvs.mLength = dataset.size();
+
+    SuccessOrExit(error = agent::ThreadHelper::ProcessDatasetForMigration(pendingOpDatasetTlvs, delayInMilli));
+
+    mHost.ScheduleMigration(pendingOpDatasetTlvs, [aRequest](otError aError, const std::string &aErrorInfo) mutable {
+        OT_UNUSED_VARIABLE(aErrorInfo);
+        aRequest.ReplyOtResult(aError);
+    });
+
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        aRequest.ReplyOtResult(error);
+    }
+}
+
+} // namespace DBus
+} // namespace otbr
diff --git a/src/dbus/server/dbus_thread_object_ncp.hpp b/src/dbus/server/dbus_thread_object_ncp.hpp
new file mode 100644
index 00000000..aa7449ba
--- /dev/null
+++ b/src/dbus/server/dbus_thread_object_ncp.hpp
@@ -0,0 +1,100 @@
+/*
+ *    Copyright (c) 2024, The OpenThread Authors.
+ *    All rights reserved.
+ *
+ *    Redistribution and use in source and binary forms, with or without
+ *    modification, are permitted provided that the following conditions are met:
+ *    1. Redistributions of source code must retain the above copyright
+ *       notice, this list of conditions and the following disclaimer.
+ *    2. Redistributions in binary form must reproduce the above copyright
+ *       notice, this list of conditions and the following disclaimer in the
+ *       documentation and/or other materials provided with the distribution.
+ *    3. Neither the name of the copyright holder nor the
+ *       names of its contributors may be used to endorse or promote products
+ *       derived from this software without specific prior written permission.
+ *
+ *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *    POSSIBILITY OF SUCH DAMAGE.
+ */
+
+/**
+ * @file
+ * This file includes definitions for the d-bus object of Thread service when
+ * the co-processor is an NCP.
+ */
+
+#ifndef OTBR_DBUS_THREAD_OBJECT_NCP_HPP_
+#define OTBR_DBUS_THREAD_OBJECT_NCP_HPP_
+
+#include "openthread-br/config.h"
+
+#include <string>
+
+#include <openthread/link.h>
+
+#include "dbus/server/dbus_object.hpp"
+#include "mdns/mdns.hpp"
+#include "ncp/ncp_host.hpp"
+
+namespace otbr {
+namespace DBus {
+
+/**
+ * @addtogroup border-router-dbus-server
+ *
+ * @brief
+ *   This module includes the <a href="dbus-api.html">dbus server api</a>.
+ *
+ * @{
+ */
+
+class DBusThreadObjectNcp : public DBusObject
+{
+public:
+    /**
+     * This constructor of dbus thread object.
+     *
+     * @param[in] aConnection     The dbus connection.
+     * @param[in] aInterfaceName  The dbus interface name.
+     * @param[in] aHost           The Thread controller.
+     *
+     */
+    DBusThreadObjectNcp(DBusConnection &aConnection, const std::string &aInterfaceName, otbr::Ncp::NcpHost &aHost);
+
+    /**
+     * This method initializes the dbus thread object.
+     *
+     * @retval OTBR_ERROR_NONE  The initialization succeeded.
+     * @retval OTBR_ERROR_DBUS  The initialization failed due to dbus connection.
+     *
+     */
+    otbrError Init(void) override;
+
+private:
+    void AsyncGetDeviceRoleHandler(DBusRequest &aRequest);
+    void ReplyAsyncGetProperty(DBusRequest &aRequest, const std::string &aContent);
+
+    void JoinHandler(DBusRequest &aRequest);
+    void LeaveHandler(DBusRequest &aRequest);
+    void ScheduleMigrationHandler(DBusRequest &aRequest);
+
+    otbr::Ncp::NcpHost &mHost;
+};
+
+/**
+ * @}
+ */
+
+} // namespace DBus
+} // namespace otbr
+
+#endif // OTBR_DBUS_THREAD_OBJECT_NCP_HPP_
diff --git a/src/dbus/server/dbus_thread_object.cpp b/src/dbus/server/dbus_thread_object_rcp.cpp
similarity index 72%
rename from src/dbus/server/dbus_thread_object.cpp
rename to src/dbus/server/dbus_thread_object_rcp.cpp
index eb2c28d2..ceaa07aa 100644
--- a/src/dbus/server/dbus_thread_object.cpp
+++ b/src/dbus/server/dbus_thread_object_rcp.cpp
@@ -30,6 +30,7 @@
 #include <net/if.h>
 #include <string.h>
 
+#include <openthread/border_agent.h>
 #include <openthread/border_router.h>
 #include <openthread/channel_monitor.h>
 #include <openthread/dnssd_server.h>
@@ -50,7 +51,7 @@
 #include "common/code_utils.hpp"
 #include "dbus/common/constants.hpp"
 #include "dbus/server/dbus_agent.hpp"
-#include "dbus/server/dbus_thread_object.hpp"
+#include "dbus/server/dbus_thread_object_rcp.hpp"
 #if OTBR_ENABLE_FEATURE_FLAGS
 #include "proto/feature_flag.pb.h"
 #endif
@@ -59,6 +60,16 @@
 #endif
 #include "proto/capabilities.pb.h"
 
+/**
+ * @def OTBR_CONFIG_BORDER_AGENT_MESHCOP_E_UDP_PORT
+ *
+ * Specifies the border agent UDP port for meshcop-e service.
+ * If zero, an ephemeral port will be used.
+ */
+#ifndef OTBR_CONFIG_BORDER_AGENT_MESHCOP_E_UDP_PORT
+#define OTBR_CONFIG_BORDER_AGENT_MESHCOP_E_UDP_PORT 0
+#endif
+
 using std::placeholders::_1;
 using std::placeholders::_2;
 
@@ -90,195 +101,208 @@ static std::string GetNat64StateName(otNat64State aState)
 namespace otbr {
 namespace DBus {
 
-DBusThreadObject::DBusThreadObject(DBusConnection                  *aConnection,
-                                   const std::string               &aInterfaceName,
-                                   otbr::Ncp::ControllerOpenThread *aNcp,
-                                   Mdns::Publisher                 *aPublisher)
-    : DBusObject(aConnection, OTBR_DBUS_OBJECT_PREFIX + aInterfaceName)
-    , mNcp(aNcp)
+DBusThreadObjectRcp::DBusThreadObjectRcp(DBusConnection     &aConnection,
+                                         const std::string  &aInterfaceName,
+                                         otbr::Ncp::RcpHost &aHost,
+                                         Mdns::Publisher    *aPublisher,
+                                         otbr::BorderAgent  &aBorderAgent)
+    : DBusObject(&aConnection, OTBR_DBUS_OBJECT_PREFIX + aInterfaceName)
+    , mHost(aHost)
     , mPublisher(aPublisher)
+    , mBorderAgent(aBorderAgent)
 {
 }
 
-otbrError DBusThreadObject::Init(void)
+otbrError DBusThreadObjectRcp::Init(void)
 {
     otbrError error        = OTBR_ERROR_NONE;
-    auto      threadHelper = mNcp->GetThreadHelper();
+    auto      threadHelper = mHost.GetThreadHelper();
 
-    SuccessOrExit(error = DBusObject::Init());
+    SuccessOrExit(error = DBusObject::Initialize(false));
 
-    threadHelper->AddDeviceRoleHandler(std::bind(&DBusThreadObject::DeviceRoleHandler, this, _1));
-    threadHelper->AddActiveDatasetChangeHandler(std::bind(&DBusThreadObject::ActiveDatasetChangeHandler, this, _1));
-    mNcp->RegisterResetHandler(std::bind(&DBusThreadObject::NcpResetHandler, this));
+    threadHelper->AddDeviceRoleHandler(std::bind(&DBusThreadObjectRcp::DeviceRoleHandler, this, _1));
+#if OTBR_ENABLE_DHCP6_PD
+    threadHelper->SetDhcp6PdStateCallback(std::bind(&DBusThreadObjectRcp::Dhcp6PdStateHandler, this, _1));
+#endif
+    threadHelper->AddActiveDatasetChangeHandler(std::bind(&DBusThreadObjectRcp::ActiveDatasetChangeHandler, this, _1));
+    mHost.RegisterResetHandler(std::bind(&DBusThreadObjectRcp::NcpResetHandler, this));
 
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_SCAN_METHOD,
-                   std::bind(&DBusThreadObject::ScanHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::ScanHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_ENERGY_SCAN_METHOD,
-                   std::bind(&DBusThreadObject::EnergyScanHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::EnergyScanHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_ATTACH_METHOD,
-                   std::bind(&DBusThreadObject::AttachHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::AttachHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_DETACH_METHOD,
-                   std::bind(&DBusThreadObject::DetachHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::DetachHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_FACTORY_RESET_METHOD,
-                   std::bind(&DBusThreadObject::FactoryResetHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::FactoryResetHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_RESET_METHOD,
-                   std::bind(&DBusThreadObject::ResetHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::ResetHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_JOINER_START_METHOD,
-                   std::bind(&DBusThreadObject::JoinerStartHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::JoinerStartHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_JOINER_STOP_METHOD,
-                   std::bind(&DBusThreadObject::JoinerStopHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::JoinerStopHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PERMIT_UNSECURE_JOIN_METHOD,
-                   std::bind(&DBusThreadObject::PermitUnsecureJoinHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::PermitUnsecureJoinHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_ADD_ON_MESH_PREFIX_METHOD,
-                   std::bind(&DBusThreadObject::AddOnMeshPrefixHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::AddOnMeshPrefixHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_REMOVE_ON_MESH_PREFIX_METHOD,
-                   std::bind(&DBusThreadObject::RemoveOnMeshPrefixHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::RemoveOnMeshPrefixHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_ADD_EXTERNAL_ROUTE_METHOD,
-                   std::bind(&DBusThreadObject::AddExternalRouteHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::AddExternalRouteHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_REMOVE_EXTERNAL_ROUTE_METHOD,
-                   std::bind(&DBusThreadObject::RemoveExternalRouteHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::RemoveExternalRouteHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_ATTACH_ALL_NODES_TO_METHOD,
-                   std::bind(&DBusThreadObject::AttachAllNodesToHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::AttachAllNodesToHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_UPDATE_VENDOR_MESHCOP_TXT_METHOD,
-                   std::bind(&DBusThreadObject::UpdateMeshCopTxtHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::UpdateMeshCopTxtHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_GET_PROPERTIES_METHOD,
-                   std::bind(&DBusThreadObject::GetPropertiesHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::GetPropertiesHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_LEAVE_NETWORK_METHOD,
-                   std::bind(&DBusThreadObject::LeaveNetworkHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::LeaveNetworkHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_SET_NAT64_ENABLED_METHOD,
-                   std::bind(&DBusThreadObject::SetNat64Enabled, this, _1));
+                   std::bind(&DBusThreadObjectRcp::SetNat64Enabled, this, _1));
+    RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_ACTIVATE_EPHEMERAL_KEY_MODE_METHOD,
+                   std::bind(&DBusThreadObjectRcp::ActivateEphemeralKeyModeHandler, this, _1));
+    RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_DEACTIVATE_EPHEMERAL_KEY_MODE_METHOD,
+                   std::bind(&DBusThreadObjectRcp::DeactivateEphemeralKeyModeHandler, this, _1));
 
     RegisterMethod(DBUS_INTERFACE_INTROSPECTABLE, DBUS_INTROSPECT_METHOD,
-                   std::bind(&DBusThreadObject::IntrospectHandler, this, _1));
+                   std::bind(&DBusThreadObjectRcp::IntrospectHandler, this, _1));
 
     RegisterSetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_MESH_LOCAL_PREFIX,
-                               std::bind(&DBusThreadObject::SetMeshLocalPrefixHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::SetMeshLocalPrefixHandler, this, _1));
     RegisterSetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_LINK_MODE,
-                               std::bind(&DBusThreadObject::SetLinkModeHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::SetLinkModeHandler, this, _1));
     RegisterSetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_ACTIVE_DATASET_TLVS,
-                               std::bind(&DBusThreadObject::SetActiveDatasetTlvsHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::SetActiveDatasetTlvsHandler, this, _1));
     RegisterSetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_FEATURE_FLAG_LIST_DATA,
-                               std::bind(&DBusThreadObject::SetFeatureFlagListDataHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::SetFeatureFlagListDataHandler, this, _1));
     RegisterSetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_RADIO_REGION,
-                               std::bind(&DBusThreadObject::SetRadioRegionHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::SetRadioRegionHandler, this, _1));
     RegisterSetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_DNS_UPSTREAM_QUERY_STATE,
-                               std::bind(&DBusThreadObject::SetDnsUpstreamQueryState, this, _1));
+                               std::bind(&DBusThreadObjectRcp::SetDnsUpstreamQueryState, this, _1));
     RegisterSetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_NAT64_CIDR,
-                               std::bind(&DBusThreadObject::SetNat64Cidr, this, _1));
+                               std::bind(&DBusThreadObjectRcp::SetNat64Cidr, this, _1));
+    RegisterSetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_EPHEMERAL_KEY_ENABLED,
+                               std::bind(&DBusThreadObjectRcp::SetEphemeralKeyEnabled, this, _1));
 
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_LINK_MODE,
-                               std::bind(&DBusThreadObject::GetLinkModeHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetLinkModeHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_DEVICE_ROLE,
-                               std::bind(&DBusThreadObject::GetDeviceRoleHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetDeviceRoleHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_NETWORK_NAME,
-                               std::bind(&DBusThreadObject::GetNetworkNameHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetNetworkNameHandler, this, _1));
 
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_PANID,
-                               std::bind(&DBusThreadObject::GetPanIdHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetPanIdHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_EXTPANID,
-                               std::bind(&DBusThreadObject::GetExtPanIdHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetExtPanIdHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_EUI64,
-                               std::bind(&DBusThreadObject::GetEui64Handler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetEui64Handler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_CHANNEL,
-                               std::bind(&DBusThreadObject::GetChannelHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetChannelHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_NETWORK_KEY,
-                               std::bind(&DBusThreadObject::GetNetworkKeyHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetNetworkKeyHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_CCA_FAILURE_RATE,
-                               std::bind(&DBusThreadObject::GetCcaFailureRateHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetCcaFailureRateHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_LINK_COUNTERS,
-                               std::bind(&DBusThreadObject::GetLinkCountersHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetLinkCountersHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_IP6_COUNTERS,
-                               std::bind(&DBusThreadObject::GetIp6CountersHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetIp6CountersHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_SUPPORTED_CHANNEL_MASK,
-                               std::bind(&DBusThreadObject::GetSupportedChannelMaskHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetSupportedChannelMaskHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_PREFERRED_CHANNEL_MASK,
-                               std::bind(&DBusThreadObject::GetPreferredChannelMaskHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetPreferredChannelMaskHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_RLOC16,
-                               std::bind(&DBusThreadObject::GetRloc16Handler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetRloc16Handler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_EXTENDED_ADDRESS,
-                               std::bind(&DBusThreadObject::GetExtendedAddressHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetExtendedAddressHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_ROUTER_ID,
-                               std::bind(&DBusThreadObject::GetRouterIdHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetRouterIdHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_LEADER_DATA,
-                               std::bind(&DBusThreadObject::GetLeaderDataHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetLeaderDataHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_NETWORK_DATA_PRPOERTY,
-                               std::bind(&DBusThreadObject::GetNetworkDataHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetNetworkDataHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_STABLE_NETWORK_DATA_PRPOERTY,
-                               std::bind(&DBusThreadObject::GetStableNetworkDataHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetStableNetworkDataHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_LOCAL_LEADER_WEIGHT,
-                               std::bind(&DBusThreadObject::GetLocalLeaderWeightHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetLocalLeaderWeightHandler, this, _1));
 #if OPENTHREAD_CONFIG_CHANNEL_MONITOR_ENABLE
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_CHANNEL_MONITOR_SAMPLE_COUNT,
-                               std::bind(&DBusThreadObject::GetChannelMonitorSampleCountHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetChannelMonitorSampleCountHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_CHANNEL_MONITOR_ALL_CHANNEL_QUALITIES,
-                               std::bind(&DBusThreadObject::GetChannelMonitorAllChannelQualities, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetChannelMonitorAllChannelQualities, this, _1));
 #endif
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_CHILD_TABLE,
-                               std::bind(&DBusThreadObject::GetChildTableHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetChildTableHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_NEIGHBOR_TABLE_PROEPRTY,
-                               std::bind(&DBusThreadObject::GetNeighborTableHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetNeighborTableHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_PARTITION_ID_PROEPRTY,
-                               std::bind(&DBusThreadObject::GetPartitionIDHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetPartitionIDHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_INSTANT_RSSI,
-                               std::bind(&DBusThreadObject::GetInstantRssiHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetInstantRssiHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_RADIO_TX_POWER,
-                               std::bind(&DBusThreadObject::GetRadioTxPowerHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetRadioTxPowerHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_EXTERNAL_ROUTES,
-                               std::bind(&DBusThreadObject::GetExternalRoutesHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetExternalRoutesHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_ON_MESH_PREFIXES,
-                               std::bind(&DBusThreadObject::GetOnMeshPrefixesHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetOnMeshPrefixesHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_ACTIVE_DATASET_TLVS,
-                               std::bind(&DBusThreadObject::GetActiveDatasetTlvsHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetActiveDatasetTlvsHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_PENDING_DATASET_TLVS,
-                               std::bind(&DBusThreadObject::GetPendingDatasetTlvsHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetPendingDatasetTlvsHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_FEATURE_FLAG_LIST_DATA,
-                               std::bind(&DBusThreadObject::GetFeatureFlagListDataHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetFeatureFlagListDataHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_RADIO_REGION,
-                               std::bind(&DBusThreadObject::GetRadioRegionHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetRadioRegionHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_SRP_SERVER_INFO,
-                               std::bind(&DBusThreadObject::GetSrpServerInfoHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetSrpServerInfoHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_MDNS_TELEMETRY_INFO,
-                               std::bind(&DBusThreadObject::GetMdnsTelemetryInfoHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetMdnsTelemetryInfoHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_DNSSD_COUNTERS,
-                               std::bind(&DBusThreadObject::GetDnssdCountersHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetDnssdCountersHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_OTBR_VERSION,
-                               std::bind(&DBusThreadObject::GetOtbrVersionHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetOtbrVersionHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_OT_HOST_VERSION,
-                               std::bind(&DBusThreadObject::GetOtHostVersionHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetOtHostVersionHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_OT_RCP_VERSION,
-                               std::bind(&DBusThreadObject::GetOtRcpVersionHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetOtRcpVersionHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_THREAD_VERSION,
-                               std::bind(&DBusThreadObject::GetThreadVersionHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetThreadVersionHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_RADIO_SPINEL_METRICS,
-                               std::bind(&DBusThreadObject::GetRadioSpinelMetricsHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetRadioSpinelMetricsHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_RCP_INTERFACE_METRICS,
-                               std::bind(&DBusThreadObject::GetRcpInterfaceMetricsHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetRcpInterfaceMetricsHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_UPTIME,
-                               std::bind(&DBusThreadObject::GetUptimeHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetUptimeHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_RADIO_COEX_METRICS,
-                               std::bind(&DBusThreadObject::GetRadioCoexMetrics, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetRadioCoexMetrics, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_BORDER_ROUTING_COUNTERS,
-                               std::bind(&DBusThreadObject::GetBorderRoutingCountersHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetBorderRoutingCountersHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_NAT64_STATE,
-                               std::bind(&DBusThreadObject::GetNat64State, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetNat64State, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_NAT64_MAPPINGS,
-                               std::bind(&DBusThreadObject::GetNat64Mappings, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetNat64Mappings, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_NAT64_PROTOCOL_COUNTERS,
-                               std::bind(&DBusThreadObject::GetNat64ProtocolCounters, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetNat64ProtocolCounters, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_NAT64_ERROR_COUNTERS,
-                               std::bind(&DBusThreadObject::GetNat64ErrorCounters, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetNat64ErrorCounters, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_NAT64_CIDR,
-                               std::bind(&DBusThreadObject::GetNat64Cidr, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetNat64Cidr, this, _1));
+    RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_EPHEMERAL_KEY_ENABLED,
+                               std::bind(&DBusThreadObjectRcp::GetEphemeralKeyEnabled, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_INFRA_LINK_INFO,
-                               std::bind(&DBusThreadObject::GetInfraLinkInfo, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetInfraLinkInfo, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_TREL_INFO,
-                               std::bind(&DBusThreadObject::GetTrelInfoHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetTrelInfoHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_DNS_UPSTREAM_QUERY_STATE,
-                               std::bind(&DBusThreadObject::GetDnsUpstreamQueryState, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetDnsUpstreamQueryState, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_TELEMETRY_DATA,
-                               std::bind(&DBusThreadObject::GetTelemetryDataHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetTelemetryDataHandler, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_CAPABILITIES,
-                               std::bind(&DBusThreadObject::GetCapabilitiesHandler, this, _1));
+                               std::bind(&DBusThreadObjectRcp::GetCapabilitiesHandler, this, _1));
 
     SuccessOrExit(error = Signal(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_SIGNAL_READY, std::make_tuple()));
 
@@ -286,29 +310,37 @@ exit:
     return error;
 }
 
-void DBusThreadObject::DeviceRoleHandler(otDeviceRole aDeviceRole)
+void DBusThreadObjectRcp::DeviceRoleHandler(otDeviceRole aDeviceRole)
 {
     SignalPropertyChanged(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_DEVICE_ROLE, GetDeviceRoleName(aDeviceRole));
 }
 
-void DBusThreadObject::NcpResetHandler(void)
+#if OTBR_ENABLE_DHCP6_PD
+void DBusThreadObjectRcp::Dhcp6PdStateHandler(otBorderRoutingDhcp6PdState aDhcp6PdState)
+{
+    SignalPropertyChanged(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_DHCP6_PD_STATE,
+                          GetDhcp6PdStateName(aDhcp6PdState));
+}
+#endif
+
+void DBusThreadObjectRcp::NcpResetHandler(void)
 {
-    mNcp->GetThreadHelper()->AddDeviceRoleHandler(std::bind(&DBusThreadObject::DeviceRoleHandler, this, _1));
-    mNcp->GetThreadHelper()->AddActiveDatasetChangeHandler(
-        std::bind(&DBusThreadObject::ActiveDatasetChangeHandler, this, _1));
+    mHost.GetThreadHelper()->AddDeviceRoleHandler(std::bind(&DBusThreadObjectRcp::DeviceRoleHandler, this, _1));
+    mHost.GetThreadHelper()->AddActiveDatasetChangeHandler(
+        std::bind(&DBusThreadObjectRcp::ActiveDatasetChangeHandler, this, _1));
     SignalPropertyChanged(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_DEVICE_ROLE,
                           GetDeviceRoleName(OT_DEVICE_ROLE_DISABLED));
 }
 
-void DBusThreadObject::ScanHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::ScanHandler(DBusRequest &aRequest)
 {
-    auto threadHelper = mNcp->GetThreadHelper();
-    threadHelper->Scan(std::bind(&DBusThreadObject::ReplyScanResult, this, aRequest, _1, _2));
+    auto threadHelper = mHost.GetThreadHelper();
+    threadHelper->Scan(std::bind(&DBusThreadObjectRcp::ReplyScanResult, this, aRequest, _1, _2));
 }
 
-void DBusThreadObject::ReplyScanResult(DBusRequest                           &aRequest,
-                                       otError                                aError,
-                                       const std::vector<otActiveScanResult> &aResult)
+void DBusThreadObjectRcp::ReplyScanResult(DBusRequest                           &aRequest,
+                                          otError                                aError,
+                                          const std::vector<otActiveScanResult> &aResult)
 {
     std::vector<ActiveScanResult> results;
 
@@ -335,16 +367,17 @@ void DBusThreadObject::ReplyScanResult(DBusRequest                           &aR
     }
 }
 
-void DBusThreadObject::EnergyScanHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::EnergyScanHandler(DBusRequest &aRequest)
 {
     otError  error        = OT_ERROR_NONE;
-    auto     threadHelper = mNcp->GetThreadHelper();
+    auto     threadHelper = mHost.GetThreadHelper();
     uint32_t scanDuration;
 
     auto args = std::tie(scanDuration);
 
     VerifyOrExit(DBusMessageToTuple(*aRequest.GetMessage(), args) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
-    threadHelper->EnergyScan(scanDuration, std::bind(&DBusThreadObject::ReplyEnergyScanResult, this, aRequest, _1, _2));
+    threadHelper->EnergyScan(scanDuration,
+                             std::bind(&DBusThreadObjectRcp::ReplyEnergyScanResult, this, aRequest, _1, _2));
 
 exit:
     if (error != OT_ERROR_NONE)
@@ -353,9 +386,9 @@ exit:
     }
 }
 
-void DBusThreadObject::ReplyEnergyScanResult(DBusRequest                           &aRequest,
-                                             otError                                aError,
-                                             const std::vector<otEnergyScanResult> &aResult)
+void DBusThreadObjectRcp::ReplyEnergyScanResult(DBusRequest                           &aRequest,
+                                                otError                                aError,
+                                                const std::vector<otEnergyScanResult> &aResult)
 {
     std::vector<EnergyScanResult> results;
 
@@ -379,9 +412,9 @@ void DBusThreadObject::ReplyEnergyScanResult(DBusRequest
     }
 }
 
-void DBusThreadObject::AttachHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::AttachHandler(DBusRequest &aRequest)
 {
-    auto                 threadHelper = mNcp->GetThreadHelper();
+    auto                 threadHelper = mHost.GetThreadHelper();
     std::string          name;
     uint16_t             panid;
     uint64_t             extPanId;
@@ -414,7 +447,7 @@ void DBusThreadObject::AttachHandler(DBusRequest &aRequest)
     }
 }
 
-void DBusThreadObject::AttachAllNodesToHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::AttachAllNodesToHandler(DBusRequest &aRequest)
 {
     std::vector<uint8_t> dataset;
     otError              error = OT_ERROR_NONE;
@@ -423,7 +456,7 @@ void DBusThreadObject::AttachAllNodesToHandler(DBusRequest &aRequest)
 
     VerifyOrExit(DBusMessageToTuple(*aRequest.GetMessage(), args) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
 
-    mNcp->GetThreadHelper()->AttachAllNodesTo(dataset, [aRequest](otError error, int64_t aAttachDelayMs) mutable {
+    mHost.GetThreadHelper()->AttachAllNodesTo(dataset, [aRequest](otError error, int64_t aAttachDelayMs) mutable {
         aRequest.ReplyOtResult<int64_t>(error, aAttachDelayMs);
     });
 
@@ -434,32 +467,32 @@ exit:
     }
 }
 
-void DBusThreadObject::DetachHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::DetachHandler(DBusRequest &aRequest)
 {
-    aRequest.ReplyOtResult(mNcp->GetThreadHelper()->Detach());
+    aRequest.ReplyOtResult(mHost.GetThreadHelper()->Detach());
 }
 
-void DBusThreadObject::FactoryResetHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::FactoryResetHandler(DBusRequest &aRequest)
 {
     otError error = OT_ERROR_NONE;
 
-    SuccessOrExit(error = mNcp->GetThreadHelper()->Detach());
-    SuccessOrExit(otInstanceErasePersistentInfo(mNcp->GetThreadHelper()->GetInstance()));
-    mNcp->Reset();
+    SuccessOrExit(error = mHost.GetThreadHelper()->Detach());
+    SuccessOrExit(otInstanceErasePersistentInfo(mHost.GetThreadHelper()->GetInstance()));
+    mHost.Reset();
 
 exit:
     aRequest.ReplyOtResult(error);
 }
 
-void DBusThreadObject::ResetHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::ResetHandler(DBusRequest &aRequest)
 {
-    mNcp->Reset();
+    mHost.Reset();
     aRequest.ReplyOtResult(OT_ERROR_NONE);
 }
 
-void DBusThreadObject::JoinerStartHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::JoinerStartHandler(DBusRequest &aRequest)
 {
-    auto        threadHelper = mNcp->GetThreadHelper();
+    auto        threadHelper = mHost.GetThreadHelper();
     std::string pskd, provisionUrl, vendorName, vendorModel, vendorSwVersion, vendorData;
     auto        args = std::tie(pskd, provisionUrl, vendorName, vendorModel, vendorSwVersion, vendorData);
 
@@ -474,18 +507,18 @@ void DBusThreadObject::JoinerStartHandler(DBusRequest &aRequest)
     }
 }
 
-void DBusThreadObject::JoinerStopHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::JoinerStopHandler(DBusRequest &aRequest)
 {
-    auto threadHelper = mNcp->GetThreadHelper();
+    auto threadHelper = mHost.GetThreadHelper();
 
     otJoinerStop(threadHelper->GetInstance());
     aRequest.ReplyOtResult(OT_ERROR_NONE);
 }
 
-void DBusThreadObject::PermitUnsecureJoinHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::PermitUnsecureJoinHandler(DBusRequest &aRequest)
 {
 #ifdef OTBR_ENABLE_UNSECURE_JOIN
-    auto     threadHelper = mNcp->GetThreadHelper();
+    auto     threadHelper = mHost.GetThreadHelper();
     uint16_t port;
     uint32_t timeout;
     auto     args = std::tie(port, timeout);
@@ -503,9 +536,9 @@ void DBusThreadObject::PermitUnsecureJoinHandler(DBusRequest &aRequest)
 #endif
 }
 
-void DBusThreadObject::AddOnMeshPrefixHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::AddOnMeshPrefixHandler(DBusRequest &aRequest)
 {
-    auto                 threadHelper = mNcp->GetThreadHelper();
+    auto                 threadHelper = mHost.GetThreadHelper();
     OnMeshPrefix         onMeshPrefix;
     auto                 args  = std::tie(onMeshPrefix);
     otError              error = OT_ERROR_NONE;
@@ -532,9 +565,9 @@ exit:
     aRequest.ReplyOtResult(error);
 }
 
-void DBusThreadObject::RemoveOnMeshPrefixHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::RemoveOnMeshPrefixHandler(DBusRequest &aRequest)
 {
-    auto        threadHelper = mNcp->GetThreadHelper();
+    auto        threadHelper = mHost.GetThreadHelper();
     Ip6Prefix   onMeshPrefix;
     auto        args  = std::tie(onMeshPrefix);
     otError     error = OT_ERROR_NONE;
@@ -552,9 +585,9 @@ exit:
     aRequest.ReplyOtResult(error);
 }
 
-void DBusThreadObject::AddExternalRouteHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::AddExternalRouteHandler(DBusRequest &aRequest)
 {
-    auto                  threadHelper = mNcp->GetThreadHelper();
+    auto                  threadHelper = mHost.GetThreadHelper();
     ExternalRoute         route;
     auto                  args  = std::tie(route);
     otError               error = OT_ERROR_NONE;
@@ -579,9 +612,9 @@ exit:
     aRequest.ReplyOtResult(error);
 }
 
-void DBusThreadObject::RemoveExternalRouteHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::RemoveExternalRouteHandler(DBusRequest &aRequest)
 {
-    auto        threadHelper = mNcp->GetThreadHelper();
+    auto        threadHelper = mHost.GetThreadHelper();
     Ip6Prefix   routePrefix;
     auto        args  = std::tie(routePrefix);
     otError     error = OT_ERROR_NONE;
@@ -600,7 +633,7 @@ exit:
     aRequest.ReplyOtResult(error);
 }
 
-void DBusThreadObject::IntrospectHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::IntrospectHandler(DBusRequest &aRequest)
 {
     std::string xmlString(
 #include "dbus/server/introspect.hpp"
@@ -609,9 +642,9 @@ void DBusThreadObject::IntrospectHandler(DBusRequest &aRequest)
     aRequest.Reply(std::tie(xmlString));
 }
 
-otError DBusThreadObject::SetMeshLocalPrefixHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::SetMeshLocalPrefixHandler(DBusMessageIter &aIter)
 {
-    auto                                      threadHelper = mNcp->GetThreadHelper();
+    auto                                      threadHelper = mHost.GetThreadHelper();
     otMeshLocalPrefix                         prefix;
     std::array<uint8_t, OTBR_IP6_PREFIX_SIZE> data{};
     otError                                   error = OT_ERROR_NONE;
@@ -624,9 +657,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::SetLinkModeHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::SetLinkModeHandler(DBusMessageIter &aIter)
 {
-    auto             threadHelper = mNcp->GetThreadHelper();
+    auto             threadHelper = mHost.GetThreadHelper();
     LinkModeConfig   cfg;
     otLinkModeConfig otCfg;
     otError          error = OT_ERROR_NONE;
@@ -641,9 +674,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetLinkModeHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetLinkModeHandler(DBusMessageIter &aIter)
 {
-    auto             threadHelper = mNcp->GetThreadHelper();
+    auto             threadHelper = mHost.GetThreadHelper();
     otLinkModeConfig otCfg        = otThreadGetLinkMode(threadHelper->GetInstance());
     LinkModeConfig   cfg;
     otError          error = OT_ERROR_NONE;
@@ -658,9 +691,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetDeviceRoleHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetDeviceRoleHandler(DBusMessageIter &aIter)
 {
-    auto         threadHelper = mNcp->GetThreadHelper();
+    auto         threadHelper = mHost.GetThreadHelper();
     otDeviceRole role         = otThreadGetDeviceRole(threadHelper->GetInstance());
     std::string  roleName     = GetDeviceRoleName(role);
     otError      error        = OT_ERROR_NONE;
@@ -671,9 +704,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetNetworkNameHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNetworkNameHandler(DBusMessageIter &aIter)
 {
-    auto        threadHelper = mNcp->GetThreadHelper();
+    auto        threadHelper = mHost.GetThreadHelper();
     std::string networkName  = otThreadGetNetworkName(threadHelper->GetInstance());
     otError     error        = OT_ERROR_NONE;
 
@@ -683,9 +716,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetPanIdHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetPanIdHandler(DBusMessageIter &aIter)
 {
-    auto     threadHelper = mNcp->GetThreadHelper();
+    auto     threadHelper = mHost.GetThreadHelper();
     uint16_t panId        = otLinkGetPanId(threadHelper->GetInstance());
     otError  error        = OT_ERROR_NONE;
 
@@ -695,9 +728,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetExtPanIdHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetExtPanIdHandler(DBusMessageIter &aIter)
 {
-    auto                   threadHelper = mNcp->GetThreadHelper();
+    auto                   threadHelper = mHost.GetThreadHelper();
     const otExtendedPanId *extPanId     = otThreadGetExtendedPanId(threadHelper->GetInstance());
     uint64_t               extPanIdVal;
     otError                error = OT_ERROR_NONE;
@@ -710,9 +743,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetChannelHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetChannelHandler(DBusMessageIter &aIter)
 {
-    auto     threadHelper = mNcp->GetThreadHelper();
+    auto     threadHelper = mHost.GetThreadHelper();
     uint16_t channel      = otLinkGetChannel(threadHelper->GetInstance());
     otError  error        = OT_ERROR_NONE;
 
@@ -722,9 +755,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetNetworkKeyHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNetworkKeyHandler(DBusMessageIter &aIter)
 {
-    auto         threadHelper = mNcp->GetThreadHelper();
+    auto         threadHelper = mHost.GetThreadHelper();
     otNetworkKey networkKey;
     otError      error = OT_ERROR_NONE;
 
@@ -736,9 +769,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetCcaFailureRateHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetCcaFailureRateHandler(DBusMessageIter &aIter)
 {
-    auto     threadHelper = mNcp->GetThreadHelper();
+    auto     threadHelper = mHost.GetThreadHelper();
     uint16_t failureRate  = otLinkGetCcaFailureRate(threadHelper->GetInstance());
     otError  error        = OT_ERROR_NONE;
 
@@ -748,9 +781,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetLinkCountersHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetLinkCountersHandler(DBusMessageIter &aIter)
 {
-    auto                 threadHelper = mNcp->GetThreadHelper();
+    auto                 threadHelper = mHost.GetThreadHelper();
     const otMacCounters *otCounters   = otLinkGetCounters(threadHelper->GetInstance());
     MacCounters          counters;
     otError              error = OT_ERROR_NONE;
@@ -794,9 +827,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetIp6CountersHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetIp6CountersHandler(DBusMessageIter &aIter)
 {
-    auto                threadHelper = mNcp->GetThreadHelper();
+    auto                threadHelper = mHost.GetThreadHelper();
     const otIpCounters *otCounters   = otThreadGetIp6Counters(threadHelper->GetInstance());
     IpCounters          counters;
     otError             error = OT_ERROR_NONE;
@@ -812,9 +845,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetSupportedChannelMaskHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetSupportedChannelMaskHandler(DBusMessageIter &aIter)
 {
-    auto     threadHelper = mNcp->GetThreadHelper();
+    auto     threadHelper = mHost.GetThreadHelper();
     uint32_t channelMask  = otLinkGetSupportedChannelMask(threadHelper->GetInstance());
     otError  error        = OT_ERROR_NONE;
 
@@ -824,9 +857,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetPreferredChannelMaskHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetPreferredChannelMaskHandler(DBusMessageIter &aIter)
 {
-    auto     threadHelper = mNcp->GetThreadHelper();
+    auto     threadHelper = mHost.GetThreadHelper();
     uint32_t channelMask  = otPlatRadioGetPreferredChannelMask(threadHelper->GetInstance());
     otError  error        = OT_ERROR_NONE;
 
@@ -836,9 +869,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetRloc16Handler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetRloc16Handler(DBusMessageIter &aIter)
 {
-    auto     threadHelper = mNcp->GetThreadHelper();
+    auto     threadHelper = mHost.GetThreadHelper();
     otError  error        = OT_ERROR_NONE;
     uint16_t rloc16       = otThreadGetRloc16(threadHelper->GetInstance());
 
@@ -848,9 +881,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetExtendedAddressHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetExtendedAddressHandler(DBusMessageIter &aIter)
 {
-    auto                threadHelper    = mNcp->GetThreadHelper();
+    auto                threadHelper    = mHost.GetThreadHelper();
     otError             error           = OT_ERROR_NONE;
     const otExtAddress *addr            = otLinkGetExtendedAddress(threadHelper->GetInstance());
     uint64_t            extendedAddress = ConvertOpenThreadUint64(addr->m8);
@@ -861,9 +894,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetRouterIdHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetRouterIdHandler(DBusMessageIter &aIter)
 {
-    auto         threadHelper = mNcp->GetThreadHelper();
+    auto         threadHelper = mHost.GetThreadHelper();
     otError      error        = OT_ERROR_NONE;
     uint16_t     rloc16       = otThreadGetRloc16(threadHelper->GetInstance());
     otRouterInfo info;
@@ -876,9 +909,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetLeaderDataHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetLeaderDataHandler(DBusMessageIter &aIter)
 {
-    auto                threadHelper = mNcp->GetThreadHelper();
+    auto                threadHelper = mHost.GetThreadHelper();
     otError             error        = OT_ERROR_NONE;
     struct otLeaderData data;
     LeaderData          leaderData;
@@ -895,10 +928,10 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetNetworkDataHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNetworkDataHandler(DBusMessageIter &aIter)
 {
     static constexpr size_t kNetworkDataMaxSize = 255;
-    auto                    threadHelper        = mNcp->GetThreadHelper();
+    auto                    threadHelper        = mHost.GetThreadHelper();
     otError                 error               = OT_ERROR_NONE;
     uint8_t                 data[kNetworkDataMaxSize];
     uint8_t                 len = sizeof(data);
@@ -912,10 +945,10 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetStableNetworkDataHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetStableNetworkDataHandler(DBusMessageIter &aIter)
 {
     static constexpr size_t kNetworkDataMaxSize = 255;
-    auto                    threadHelper        = mNcp->GetThreadHelper();
+    auto                    threadHelper        = mHost.GetThreadHelper();
     otError                 error               = OT_ERROR_NONE;
     uint8_t                 data[kNetworkDataMaxSize];
     uint8_t                 len = sizeof(data);
@@ -929,9 +962,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetLocalLeaderWeightHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetLocalLeaderWeightHandler(DBusMessageIter &aIter)
 {
-    auto    threadHelper = mNcp->GetThreadHelper();
+    auto    threadHelper = mHost.GetThreadHelper();
     otError error        = OT_ERROR_NONE;
     uint8_t weight       = otThreadGetLocalLeaderWeight(threadHelper->GetInstance());
 
@@ -941,10 +974,10 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetChannelMonitorSampleCountHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetChannelMonitorSampleCountHandler(DBusMessageIter &aIter)
 {
 #if OPENTHREAD_CONFIG_CHANNEL_MONITOR_ENABLE
-    auto     threadHelper = mNcp->GetThreadHelper();
+    auto     threadHelper = mHost.GetThreadHelper();
     otError  error        = OT_ERROR_NONE;
     uint32_t cnt          = otChannelMonitorGetSampleCount(threadHelper->GetInstance());
 
@@ -958,10 +991,10 @@ exit:
 #endif // OPENTHREAD_CONFIG_CHANNEL_MONITOR_ENABLE
 }
 
-otError DBusThreadObject::GetChannelMonitorAllChannelQualities(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetChannelMonitorAllChannelQualities(DBusMessageIter &aIter)
 {
 #if OPENTHREAD_CONFIG_CHANNEL_MONITOR_ENABLE
-    auto                        threadHelper = mNcp->GetThreadHelper();
+    auto                        threadHelper = mHost.GetThreadHelper();
     otError                     error        = OT_ERROR_NONE;
     uint32_t                    channelMask  = otLinkGetSupportedChannelMask(threadHelper->GetInstance());
     constexpr uint8_t           kNumChannels = sizeof(channelMask) * 8; // 8 bit per byte
@@ -987,9 +1020,9 @@ exit:
 #endif // OPENTHREAD_CONFIG_CHANNEL_MONITOR_ENABLE
 }
 
-otError DBusThreadObject::GetChildTableHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetChildTableHandler(DBusMessageIter &aIter)
 {
-    auto                   threadHelper = mNcp->GetThreadHelper();
+    auto                   threadHelper = mHost.GetThreadHelper();
     otError                error        = OT_ERROR_NONE;
     uint16_t               childIndex   = 0;
     otChildInfo            childInfo;
@@ -1023,9 +1056,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetNeighborTableHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNeighborTableHandler(DBusMessageIter &aIter)
 {
-    auto                      threadHelper = mNcp->GetThreadHelper();
+    auto                      threadHelper = mHost.GetThreadHelper();
     otError                   error        = OT_ERROR_NONE;
     otNeighborInfoIterator    iter         = OT_NEIGHBOR_INFO_ITERATOR_INIT;
     otNeighborInfo            neighborInfo;
@@ -1059,9 +1092,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetPartitionIDHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetPartitionIDHandler(DBusMessageIter &aIter)
 {
-    auto     threadHelper = mNcp->GetThreadHelper();
+    auto     threadHelper = mHost.GetThreadHelper();
     otError  error        = OT_ERROR_NONE;
     uint32_t partitionId  = otThreadGetPartitionId(threadHelper->GetInstance());
 
@@ -1071,9 +1104,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetInstantRssiHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetInstantRssiHandler(DBusMessageIter &aIter)
 {
-    auto    threadHelper = mNcp->GetThreadHelper();
+    auto    threadHelper = mHost.GetThreadHelper();
     otError error        = OT_ERROR_NONE;
     int8_t  rssi         = otPlatRadioGetRssi(threadHelper->GetInstance());
 
@@ -1083,9 +1116,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetRadioTxPowerHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetRadioTxPowerHandler(DBusMessageIter &aIter)
 {
-    auto    threadHelper = mNcp->GetThreadHelper();
+    auto    threadHelper = mHost.GetThreadHelper();
     otError error        = OT_ERROR_NONE;
     int8_t  txPower;
 
@@ -1097,9 +1130,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetExternalRoutesHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetExternalRoutesHandler(DBusMessageIter &aIter)
 {
-    auto                       threadHelper = mNcp->GetThreadHelper();
+    auto                       threadHelper = mHost.GetThreadHelper();
     otError                    error        = OT_ERROR_NONE;
     otNetworkDataIterator      iter         = OT_NETWORK_DATA_ITERATOR_INIT;
     otExternalRouteConfig      config;
@@ -1126,9 +1159,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetOnMeshPrefixesHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetOnMeshPrefixesHandler(DBusMessageIter &aIter)
 {
-    auto                      threadHelper = mNcp->GetThreadHelper();
+    auto                      threadHelper = mHost.GetThreadHelper();
     otError                   error        = OT_ERROR_NONE;
     otNetworkDataIterator     iter         = OT_NETWORK_DATA_ITERATOR_INIT;
     otBorderRouterConfig      config;
@@ -1160,9 +1193,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::SetActiveDatasetTlvsHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::SetActiveDatasetTlvsHandler(DBusMessageIter &aIter)
 {
-    auto                     threadHelper = mNcp->GetThreadHelper();
+    auto                     threadHelper = mHost.GetThreadHelper();
     std::vector<uint8_t>     data;
     otOperationalDatasetTlvs datasetTlvs;
     otError                  error = OT_ERROR_NONE;
@@ -1177,9 +1210,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetActiveDatasetTlvsHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetActiveDatasetTlvsHandler(DBusMessageIter &aIter)
 {
-    auto                     threadHelper = mNcp->GetThreadHelper();
+    auto                     threadHelper = mHost.GetThreadHelper();
     otError                  error        = OT_ERROR_NONE;
     std::vector<uint8_t>     data;
     otOperationalDatasetTlvs datasetTlvs;
@@ -1193,9 +1226,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetPendingDatasetTlvsHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetPendingDatasetTlvsHandler(DBusMessageIter &aIter)
 {
-    auto                     threadHelper = mNcp->GetThreadHelper();
+    auto                     threadHelper = mHost.GetThreadHelper();
     otError                  error        = OT_ERROR_NONE;
     std::vector<uint8_t>     data;
     otOperationalDatasetTlvs datasetTlvs;
@@ -1209,7 +1242,7 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::SetFeatureFlagListDataHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::SetFeatureFlagListDataHandler(DBusMessageIter &aIter)
 {
 #if OTBR_ENABLE_FEATURE_FLAGS
     otError              error = OT_ERROR_NONE;
@@ -1218,7 +1251,11 @@ otError DBusThreadObject::SetFeatureFlagListDataHandler(DBusMessageIter &aIter)
 
     VerifyOrExit(DBusMessageExtractFromVariant(&aIter, data) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
     VerifyOrExit(featureFlagList.ParseFromString(std::string(data.begin(), data.end())), error = OT_ERROR_INVALID_ARGS);
-    VerifyOrExit((error = mNcp->ApplyFeatureFlagList(featureFlagList)) == OT_ERROR_NONE);
+    // TODO: implement the feature flag handler at every component
+    mBorderAgent.SetEphemeralKeyEnabled(featureFlagList.enable_ephemeralkey());
+    otbrLogInfo("Border Agent Ephemeral Key Feature has been %s by feature flag",
+                (featureFlagList.enable_ephemeralkey() ? "enable" : "disable"));
+    VerifyOrExit((error = mHost.ApplyFeatureFlagList(featureFlagList)) == OT_ERROR_NONE);
 exit:
     return error;
 #else
@@ -1227,11 +1264,11 @@ exit:
 #endif
 }
 
-otError DBusThreadObject::GetFeatureFlagListDataHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetFeatureFlagListDataHandler(DBusMessageIter &aIter)
 {
 #if OTBR_ENABLE_FEATURE_FLAGS
     otError              error                       = OT_ERROR_NONE;
-    const std::string    appliedFeatureFlagListBytes = mNcp->GetAppliedFeatureFlagListBytes();
+    const std::string    appliedFeatureFlagListBytes = mHost.GetAppliedFeatureFlagListBytes();
     std::vector<uint8_t> data(appliedFeatureFlagListBytes.begin(), appliedFeatureFlagListBytes.end());
 
     VerifyOrExit(DBusMessageEncodeToVariant(&aIter, data) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
@@ -1244,9 +1281,9 @@ exit:
 #endif
 }
 
-otError DBusThreadObject::SetRadioRegionHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::SetRadioRegionHandler(DBusMessageIter &aIter)
 {
-    auto        threadHelper = mNcp->GetThreadHelper();
+    auto        threadHelper = mHost.GetThreadHelper();
     std::string radioRegion;
     uint16_t    regionCode;
     otError     error = OT_ERROR_NONE;
@@ -1261,9 +1298,9 @@ exit:
     return error;
 }
 
-void DBusThreadObject::UpdateMeshCopTxtHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::UpdateMeshCopTxtHandler(DBusRequest &aRequest)
 {
-    auto                                        threadHelper = mNcp->GetThreadHelper();
+    auto                                        threadHelper = mHost.GetThreadHelper();
     otError                                     error        = OT_ERROR_NONE;
     std::map<std::string, std::vector<uint8_t>> update;
     std::vector<TxtEntry>                       updatedTxtEntries;
@@ -1284,9 +1321,9 @@ exit:
     aRequest.ReplyOtResult(error);
 }
 
-otError DBusThreadObject::GetRadioRegionHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetRadioRegionHandler(DBusMessageIter &aIter)
 {
-    auto        threadHelper = mNcp->GetThreadHelper();
+    auto        threadHelper = mHost.GetThreadHelper();
     otError     error        = OT_ERROR_NONE;
     std::string radioRegion;
     uint16_t    regionCode;
@@ -1302,10 +1339,10 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetSrpServerInfoHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetSrpServerInfoHandler(DBusMessageIter &aIter)
 {
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
-    auto                               threadHelper = mNcp->GetThreadHelper();
+    auto                               threadHelper = mHost.GetThreadHelper();
     auto                               instance     = threadHelper->GetInstance();
     otError                            error        = OT_ERROR_NONE;
     SrpServerInfo                      srpServerInfo{};
@@ -1371,7 +1408,7 @@ exit:
 #endif // OTBR_ENABLE_SRP_ADVERTISING_PROXY
 }
 
-otError DBusThreadObject::GetMdnsTelemetryInfoHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetMdnsTelemetryInfoHandler(DBusMessageIter &aIter)
 {
     otError error = OT_ERROR_NONE;
 
@@ -1381,10 +1418,10 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetDnssdCountersHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetDnssdCountersHandler(DBusMessageIter &aIter)
 {
 #if OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
-    auto            threadHelper = mNcp->GetThreadHelper();
+    auto            threadHelper = mHost.GetThreadHelper();
     auto            instance     = threadHelper->GetInstance();
     otError         error        = OT_ERROR_NONE;
     DnssdCounters   dnssdCounters;
@@ -1410,10 +1447,10 @@ exit:
 #endif // OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
 }
 
-otError DBusThreadObject::GetTrelInfoHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetTrelInfoHandler(DBusMessageIter &aIter)
 {
 #if OTBR_ENABLE_TREL
-    auto           instance = mNcp->GetThreadHelper()->GetInstance();
+    auto           instance = mHost.GetThreadHelper()->GetInstance();
     otError        error    = OT_ERROR_NONE;
     TrelInfo       trelInfo;
     otTrelCounters otTrelCounters = *otTrelGetCounters(instance);
@@ -1437,12 +1474,12 @@ exit:
 #endif // OTBR_ENABLE_TREL
 }
 
-otError DBusThreadObject::GetTelemetryDataHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetTelemetryDataHandler(DBusMessageIter &aIter)
 {
 #if OTBR_ENABLE_TELEMETRY_DATA_API
     otError                      error = OT_ERROR_NONE;
     threadnetwork::TelemetryData telemetryData;
-    auto                         threadHelper = mNcp->GetThreadHelper();
+    auto                         threadHelper = mHost.GetThreadHelper();
 
     if (threadHelper->RetrieveTelemetryData(mPublisher, telemetryData) != OT_ERROR_NONE)
     {
@@ -1464,7 +1501,7 @@ exit:
 #endif
 }
 
-otError DBusThreadObject::GetCapabilitiesHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetCapabilitiesHandler(DBusMessageIter &aIter)
 {
     otError            error = OT_ERROR_NONE;
     otbr::Capabilities capabilities;
@@ -1483,7 +1520,7 @@ exit:
     return error;
 }
 
-void DBusThreadObject::GetPropertiesHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::GetPropertiesHandler(DBusRequest &aRequest)
 {
     UniqueDBusMessage        reply(dbus_message_new_method_return(aRequest.GetMessage()));
     DBusMessageIter          iter;
@@ -1524,15 +1561,15 @@ exit:
     }
 }
 
-void DBusThreadObject::RegisterGetPropertyHandler(const std::string         &aInterfaceName,
-                                                  const std::string         &aPropertyName,
-                                                  const PropertyHandlerType &aHandler)
+void DBusThreadObjectRcp::RegisterGetPropertyHandler(const std::string         &aInterfaceName,
+                                                     const std::string         &aPropertyName,
+                                                     const PropertyHandlerType &aHandler)
 {
     DBusObject::RegisterGetPropertyHandler(aInterfaceName, aPropertyName, aHandler);
     mGetPropertyHandlers[aPropertyName] = aHandler;
 }
 
-otError DBusThreadObject::GetOtbrVersionHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetOtbrVersionHandler(DBusMessageIter &aIter)
 {
     otError     error   = OT_ERROR_NONE;
     std::string version = OTBR_PACKAGE_VERSION;
@@ -1543,7 +1580,7 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetOtHostVersionHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetOtHostVersionHandler(DBusMessageIter &aIter)
 {
     otError     error   = OT_ERROR_NONE;
     std::string version = otGetVersionString();
@@ -1554,9 +1591,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetEui64Handler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetEui64Handler(DBusMessageIter &aIter)
 {
-    auto         threadHelper = mNcp->GetThreadHelper();
+    auto         threadHelper = mHost.GetThreadHelper();
     otError      error        = OT_ERROR_NONE;
     otExtAddress extAddr;
     uint64_t     eui64;
@@ -1571,9 +1608,9 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetOtRcpVersionHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetOtRcpVersionHandler(DBusMessageIter &aIter)
 {
-    auto        threadHelper = mNcp->GetThreadHelper();
+    auto        threadHelper = mHost.GetThreadHelper();
     otError     error        = OT_ERROR_NONE;
     std::string version      = otGetRadioVersionString(threadHelper->GetInstance());
 
@@ -1583,7 +1620,7 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetThreadVersionHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetThreadVersionHandler(DBusMessageIter &aIter)
 {
     otError error = OT_ERROR_NONE;
 
@@ -1593,7 +1630,7 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetRadioSpinelMetricsHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetRadioSpinelMetricsHandler(DBusMessageIter &aIter)
 {
     otError              error = OT_ERROR_NONE;
     RadioSpinelMetrics   radioSpinelMetrics;
@@ -1611,7 +1648,7 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetRcpInterfaceMetricsHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetRcpInterfaceMetricsHandler(DBusMessageIter &aIter)
 {
     otError               error = OT_ERROR_NONE;
     RcpInterfaceMetrics   rcpInterfaceMetrics;
@@ -1633,11 +1670,11 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetUptimeHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetUptimeHandler(DBusMessageIter &aIter)
 {
     otError error = OT_ERROR_NONE;
 
-    VerifyOrExit(DBusMessageEncodeToVariant(&aIter, otInstanceGetUptime(mNcp->GetThreadHelper()->GetInstance())) ==
+    VerifyOrExit(DBusMessageEncodeToVariant(&aIter, otInstanceGetUptime(mHost.GetThreadHelper()->GetInstance())) ==
                      OTBR_ERROR_NONE,
                  error = OT_ERROR_INVALID_ARGS);
 
@@ -1645,13 +1682,13 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetRadioCoexMetrics(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetRadioCoexMetrics(DBusMessageIter &aIter)
 {
     otError            error = OT_ERROR_NONE;
     otRadioCoexMetrics otRadioCoexMetrics;
     RadioCoexMetrics   radioCoexMetrics;
 
-    SuccessOrExit(error = otPlatRadioGetCoexMetrics(mNcp->GetInstance(), &otRadioCoexMetrics));
+    SuccessOrExit(error = otPlatRadioGetCoexMetrics(mHost.GetInstance(), &otRadioCoexMetrics));
 
     radioCoexMetrics.mNumGrantGlitch                     = otRadioCoexMetrics.mNumGrantGlitch;
     radioCoexMetrics.mNumTxRequest                       = otRadioCoexMetrics.mNumTxRequest;
@@ -1680,10 +1717,10 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetBorderRoutingCountersHandler(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetBorderRoutingCountersHandler(DBusMessageIter &aIter)
 {
 #if OTBR_ENABLE_BORDER_ROUTING_COUNTERS
-    auto                           threadHelper = mNcp->GetThreadHelper();
+    auto                           threadHelper = mHost.GetThreadHelper();
     auto                           instance     = threadHelper->GetInstance();
     otError                        error        = OT_ERROR_NONE;
     BorderRoutingCounters          borderRoutingCounters;
@@ -1716,21 +1753,21 @@ exit:
 #endif
 }
 
-void DBusThreadObject::ActiveDatasetChangeHandler(const otOperationalDatasetTlvs &aDatasetTlvs)
+void DBusThreadObjectRcp::ActiveDatasetChangeHandler(const otOperationalDatasetTlvs &aDatasetTlvs)
 {
     std::vector<uint8_t> value(aDatasetTlvs.mLength);
     std::copy(aDatasetTlvs.mTlvs, aDatasetTlvs.mTlvs + aDatasetTlvs.mLength, value.begin());
     SignalPropertyChanged(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_ACTIVE_DATASET_TLVS, value);
 }
 
-void DBusThreadObject::LeaveNetworkHandler(DBusRequest &aRequest)
+void DBusThreadObjectRcp::LeaveNetworkHandler(DBusRequest &aRequest)
 {
     constexpr int kExitCodeShouldRestart = 7;
 
-    mNcp->GetThreadHelper()->DetachGracefully([aRequest, this](otError error) mutable {
+    mHost.GetThreadHelper()->DetachGracefully([aRequest, this](otError error) mutable {
         SuccessOrExit(error);
         mPublisher->Stop();
-        SuccessOrExit(error = otInstanceErasePersistentInfo(mNcp->GetThreadHelper()->GetInstance()));
+        SuccessOrExit(error = otInstanceErasePersistentInfo(mHost.GetThreadHelper()->GetInstance()));
 
     exit:
         aRequest.ReplyOtResult(error);
@@ -1743,27 +1780,27 @@ void DBusThreadObject::LeaveNetworkHandler(DBusRequest &aRequest)
 }
 
 #if OTBR_ENABLE_NAT64
-void DBusThreadObject::SetNat64Enabled(DBusRequest &aRequest)
+void DBusThreadObjectRcp::SetNat64Enabled(DBusRequest &aRequest)
 {
     otError error = OT_ERROR_NONE;
     bool    enable;
     auto    args = std::tie(enable);
 
     VerifyOrExit(DBusMessageToTuple(*aRequest.GetMessage(), args) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
-    otNat64SetEnabled(mNcp->GetThreadHelper()->GetInstance(), enable);
+    otNat64SetEnabled(mHost.GetThreadHelper()->GetInstance(), enable);
 
 exit:
     aRequest.ReplyOtResult(error);
 }
 
-otError DBusThreadObject::GetNat64State(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNat64State(DBusMessageIter &aIter)
 {
     otError error = OT_ERROR_NONE;
 
     Nat64ComponentState state;
 
-    state.mPrefixManagerState = GetNat64StateName(otNat64GetPrefixManagerState(mNcp->GetThreadHelper()->GetInstance()));
-    state.mTranslatorState    = GetNat64StateName(otNat64GetTranslatorState(mNcp->GetThreadHelper()->GetInstance()));
+    state.mPrefixManagerState = GetNat64StateName(otNat64GetPrefixManagerState(mHost.GetThreadHelper()->GetInstance()));
+    state.mTranslatorState    = GetNat64StateName(otNat64GetTranslatorState(mHost.GetThreadHelper()->GetInstance()));
 
     VerifyOrExit(DBusMessageEncodeToVariant(&aIter, state) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
 
@@ -1771,7 +1808,7 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetNat64Mappings(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNat64Mappings(DBusMessageIter &aIter)
 {
     otError error = OT_ERROR_NONE;
 
@@ -1780,8 +1817,8 @@ otError DBusThreadObject::GetNat64Mappings(DBusMessageIter &aIter)
     otNat64AddressMapping            otMapping;
     Nat64AddressMapping              mapping;
 
-    otNat64InitAddressMappingIterator(mNcp->GetThreadHelper()->GetInstance(), &iterator);
-    while (otNat64GetNextAddressMapping(mNcp->GetThreadHelper()->GetInstance(), &iterator, &otMapping) == OT_ERROR_NONE)
+    otNat64InitAddressMappingIterator(mHost.GetThreadHelper()->GetInstance(), &iterator);
+    while (otNat64GetNextAddressMapping(mHost.GetThreadHelper()->GetInstance(), &iterator, &otMapping) == OT_ERROR_NONE)
     {
         mapping.mId = otMapping.mId;
         std::copy(std::begin(otMapping.mIp4.mFields.m8), std::end(otMapping.mIp4.mFields.m8), mapping.mIp4.data());
@@ -1817,13 +1854,13 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetNat64ProtocolCounters(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNat64ProtocolCounters(DBusMessageIter &aIter)
 {
     otError error = OT_ERROR_NONE;
 
     otNat64ProtocolCounters otCounters;
     Nat64ProtocolCounters   counters;
-    otNat64GetCounters(mNcp->GetThreadHelper()->GetInstance(), &otCounters);
+    otNat64GetCounters(mHost.GetThreadHelper()->GetInstance(), &otCounters);
 
     counters.mTotal.m4To6Packets = otCounters.mTotal.m4To6Packets;
     counters.mTotal.m4To6Bytes   = otCounters.mTotal.m4To6Bytes;
@@ -1848,13 +1885,13 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetNat64ErrorCounters(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNat64ErrorCounters(DBusMessageIter &aIter)
 {
     otError error = OT_ERROR_NONE;
 
     otNat64ErrorCounters otCounters;
     Nat64ErrorCounters   counters;
-    otNat64GetErrorCounters(mNcp->GetThreadHelper()->GetInstance(), &otCounters);
+    otNat64GetErrorCounters(mHost.GetThreadHelper()->GetInstance(), &otCounters);
 
     counters.mUnknown.m4To6Packets          = otCounters.mCount4To6[OT_NAT64_DROP_REASON_UNKNOWN];
     counters.mUnknown.m6To4Packets          = otCounters.mCount6To4[OT_NAT64_DROP_REASON_UNKNOWN];
@@ -1871,14 +1908,14 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::GetNat64Cidr(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNat64Cidr(DBusMessageIter &aIter)
 {
     otError error = OT_ERROR_NONE;
 
     otIp4Cidr cidr;
     char      cidrString[OT_IP4_CIDR_STRING_SIZE];
 
-    SuccessOrExit(error = otNat64GetCidr(mNcp->GetThreadHelper()->GetInstance(), &cidr));
+    SuccessOrExit(error = otNat64GetCidr(mHost.GetThreadHelper()->GetInstance(), &cidr));
     otIp4CidrToString(&cidr, cidrString, sizeof(cidrString));
 
     VerifyOrExit(DBusMessageEncodeToVariant(&aIter, std::string(cidrString)) == OTBR_ERROR_NONE,
@@ -1888,7 +1925,7 @@ exit:
     return error;
 }
 
-otError DBusThreadObject::SetNat64Cidr(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::SetNat64Cidr(DBusMessageIter &aIter)
 {
     otError     error = OT_ERROR_NONE;
     std::string cidrString;
@@ -1896,56 +1933,115 @@ otError DBusThreadObject::SetNat64Cidr(DBusMessageIter &aIter)
 
     VerifyOrExit(DBusMessageExtractFromVariant(&aIter, cidrString) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
     SuccessOrExit(error = otIp4CidrFromString(cidrString.c_str(), &cidr));
-    SuccessOrExit(error = otNat64SetIp4Cidr(mNcp->GetThreadHelper()->GetInstance(), &cidr));
+    SuccessOrExit(error = otNat64SetIp4Cidr(mHost.GetThreadHelper()->GetInstance(), &cidr));
 
 exit:
     return error;
 }
 #else  // OTBR_ENABLE_NAT64
-void DBusThreadObject::SetNat64Enabled(DBusRequest &aRequest)
+void DBusThreadObjectRcp::SetNat64Enabled(DBusRequest &aRequest)
 {
     OTBR_UNUSED_VARIABLE(aRequest);
     aRequest.ReplyOtResult(OT_ERROR_NOT_IMPLEMENTED);
 }
 
-otError DBusThreadObject::GetNat64State(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNat64State(DBusMessageIter &aIter)
 {
     OTBR_UNUSED_VARIABLE(aIter);
     return OT_ERROR_NOT_IMPLEMENTED;
 }
 
-otError DBusThreadObject::GetNat64Mappings(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNat64Mappings(DBusMessageIter &aIter)
 {
     OTBR_UNUSED_VARIABLE(aIter);
     return OT_ERROR_NOT_IMPLEMENTED;
 }
 
-otError DBusThreadObject::GetNat64ProtocolCounters(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNat64ProtocolCounters(DBusMessageIter &aIter)
 {
     OTBR_UNUSED_VARIABLE(aIter);
     return OT_ERROR_NOT_IMPLEMENTED;
 }
 
-otError DBusThreadObject::GetNat64ErrorCounters(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNat64ErrorCounters(DBusMessageIter &aIter)
 {
     OTBR_UNUSED_VARIABLE(aIter);
     return OT_ERROR_NOT_IMPLEMENTED;
 }
 
-otError DBusThreadObject::GetNat64Cidr(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetNat64Cidr(DBusMessageIter &aIter)
 {
     OTBR_UNUSED_VARIABLE(aIter);
     return OT_ERROR_NOT_IMPLEMENTED;
 }
 
-otError DBusThreadObject::SetNat64Cidr(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::SetNat64Cidr(DBusMessageIter &aIter)
 {
     OTBR_UNUSED_VARIABLE(aIter);
     return OT_ERROR_NOT_IMPLEMENTED;
 }
 #endif // OTBR_ENABLE_NAT64
 
-otError DBusThreadObject::GetInfraLinkInfo(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetEphemeralKeyEnabled(DBusMessageIter &aIter)
+{
+    otError error = OT_ERROR_NONE;
+
+    SuccessOrExit(DBusMessageEncodeToVariant(&aIter, mBorderAgent.GetEphemeralKeyEnabled()),
+                  error = OT_ERROR_INVALID_ARGS);
+
+exit:
+    return error;
+}
+
+otError DBusThreadObjectRcp::SetEphemeralKeyEnabled(DBusMessageIter &aIter)
+{
+    otError error = OT_ERROR_NONE;
+    bool    enable;
+
+    SuccessOrExit(DBusMessageExtractFromVariant(&aIter, enable), error = OT_ERROR_INVALID_ARGS);
+    mBorderAgent.SetEphemeralKeyEnabled(enable);
+
+exit:
+    return error;
+}
+
+void DBusThreadObjectRcp::DeactivateEphemeralKeyModeHandler(DBusRequest &aRequest)
+{
+    otError error        = OT_ERROR_NONE;
+    auto    threadHelper = mHost.GetThreadHelper();
+
+    otBorderAgentClearEphemeralKey(threadHelper->GetInstance());
+    aRequest.ReplyOtResult(error);
+}
+
+void DBusThreadObjectRcp::ActivateEphemeralKeyModeHandler(DBusRequest &aRequest)
+{
+    otError     error        = OT_ERROR_NONE;
+    auto        threadHelper = mHost.GetThreadHelper();
+    uint32_t    lifetime     = 0;
+    auto        args         = std::tie(lifetime);
+    std::string ePskc;
+
+    SuccessOrExit(DBusMessageToTuple(*aRequest.GetMessage(), args), error = OT_ERROR_INVALID_ARGS);
+
+    SuccessOrExit(mBorderAgent.CreateEphemeralKey(ePskc), error = OT_ERROR_INVALID_ARGS);
+    otbrLogInfo("Created Ephemeral Key: %s", ePskc.c_str());
+
+    SuccessOrExit(error = otBorderAgentSetEphemeralKey(threadHelper->GetInstance(), ePskc.c_str(), lifetime,
+                                                       OTBR_CONFIG_BORDER_AGENT_MESHCOP_E_UDP_PORT));
+
+exit:
+    if (error == OT_ERROR_NONE)
+    {
+        aRequest.Reply(std::tie(ePskc));
+    }
+    else
+    {
+        aRequest.ReplyOtResult(error);
+    }
+}
+
+otError DBusThreadObjectRcp::GetInfraLinkInfo(DBusMessageIter &aIter)
 {
 #if OTBR_ENABLE_BORDER_ROUTING
     otError                        error = OT_ERROR_NONE;
@@ -1956,13 +2052,13 @@ otError DBusThreadObject::GetInfraLinkInfo(DBusMessageIter &aIter)
     ifrFlags = otSysGetInfraNetifFlags();
     otSysCountInfraNetifAddresses(&addressCounters);
 
-    infraLinkInfo.mName                   = otSysGetInfraNetifName();
-    infraLinkInfo.mIsUp                   = (ifrFlags & IFF_UP) != 0;
-    infraLinkInfo.mIsRunning              = (ifrFlags & IFF_RUNNING) != 0;
-    infraLinkInfo.mIsMulticast            = (ifrFlags & IFF_MULTICAST) != 0;
-    infraLinkInfo.mLinkLocalAddresses     = addressCounters.mLinkLocalAddresses;
-    infraLinkInfo.mUniqueLocalAddresses   = addressCounters.mUniqueLocalAddresses;
-    infraLinkInfo.mGlobalUnicastAddresses = addressCounters.mGlobalUnicastAddresses;
+    infraLinkInfo.mName                      = otSysGetInfraNetifName();
+    infraLinkInfo.mIsUp                      = (ifrFlags & IFF_UP) != 0;
+    infraLinkInfo.mIsRunning                 = (ifrFlags & IFF_RUNNING) != 0;
+    infraLinkInfo.mIsMulticast               = (ifrFlags & IFF_MULTICAST) != 0;
+    infraLinkInfo.mLinkLocalAddressCount     = addressCounters.mLinkLocalAddresses;
+    infraLinkInfo.mUniqueLocalAddressCount   = addressCounters.mUniqueLocalAddresses;
+    infraLinkInfo.mGlobalUnicastAddressCount = addressCounters.mGlobalUnicastAddresses;
 
     VerifyOrExit(DBusMessageEncodeToVariant(&aIter, infraLinkInfo) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
 
@@ -1975,14 +2071,14 @@ exit:
 #endif
 }
 
-otError DBusThreadObject::SetDnsUpstreamQueryState(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::SetDnsUpstreamQueryState(DBusMessageIter &aIter)
 {
 #if OTBR_ENABLE_DNS_UPSTREAM_QUERY
     otError error = OT_ERROR_NONE;
     bool    enable;
 
     VerifyOrExit(DBusMessageExtractFromVariant(&aIter, enable) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
-    otDnssdUpstreamQuerySetEnabled(mNcp->GetThreadHelper()->GetInstance(), enable);
+    otDnssdUpstreamQuerySetEnabled(mHost.GetThreadHelper()->GetInstance(), enable);
 
 exit:
     return error;
@@ -1993,13 +2089,13 @@ exit:
 #endif
 }
 
-otError DBusThreadObject::GetDnsUpstreamQueryState(DBusMessageIter &aIter)
+otError DBusThreadObjectRcp::GetDnsUpstreamQueryState(DBusMessageIter &aIter)
 {
 #if OTBR_ENABLE_DNS_UPSTREAM_QUERY
     otError error = OT_ERROR_NONE;
 
     VerifyOrExit(DBusMessageEncodeToVariant(
-                     &aIter, otDnssdUpstreamQueryIsEnabled(mNcp->GetThreadHelper()->GetInstance())) == OTBR_ERROR_NONE,
+                     &aIter, otDnssdUpstreamQueryIsEnabled(mHost.GetThreadHelper()->GetInstance())) == OTBR_ERROR_NONE,
                  error = OT_ERROR_INVALID_ARGS);
 
 exit:
diff --git a/src/dbus/server/dbus_thread_object.hpp b/src/dbus/server/dbus_thread_object_rcp.hpp
similarity index 88%
rename from src/dbus/server/dbus_thread_object.hpp
rename to src/dbus/server/dbus_thread_object_rcp.hpp
index c3fa8d56..15ec6598 100644
--- a/src/dbus/server/dbus_thread_object.hpp
+++ b/src/dbus/server/dbus_thread_object_rcp.hpp
@@ -31,8 +31,8 @@
  * This file includes definitions for the d-bus object of OpenThread service.
  */
 
-#ifndef OTBR_DBUS_THREAD_OBJECT_HPP_
-#define OTBR_DBUS_THREAD_OBJECT_HPP_
+#ifndef OTBR_DBUS_THREAD_OBJECT_RCP_HPP_
+#define OTBR_DBUS_THREAD_OBJECT_RCP_HPP_
 
 #include "openthread-br/config.h"
 
@@ -40,9 +40,10 @@
 
 #include <openthread/link.h>
 
+#include "border_agent/border_agent.hpp"
 #include "dbus/server/dbus_object.hpp"
 #include "mdns/mdns.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 namespace DBus {
@@ -54,13 +55,9 @@ namespace DBus {
  *   This module includes the <a href="dbus-api.html">dbus server api</a>.
  *
  * @{
- * @}
- *
  */
 
-class DBusAgent;
-
-class DBusThreadObject : public DBusObject
+class DBusThreadObjectRcp : public DBusObject
 {
 public:
     /**
@@ -68,14 +65,16 @@ public:
      *
      * @param[in] aConnection     The dbus connection.
      * @param[in] aInterfaceName  The dbus interface name.
-     * @param[in] aNcp            The ncp controller
+     * @param[in] aHost           The Thread controller
      * @param[in] aPublisher      The Mdns::Publisher
+     * @param[in] aBorderAgent    The Border Agent
      *
      */
-    DBusThreadObject(DBusConnection                  *aConnection,
-                     const std::string               &aInterfaceName,
-                     otbr::Ncp::ControllerOpenThread *aNcp,
-                     Mdns::Publisher                 *aPublisher);
+    DBusThreadObjectRcp(DBusConnection     &aConnection,
+                        const std::string  &aInterfaceName,
+                        otbr::Ncp::RcpHost &aHost,
+                        Mdns::Publisher    *aPublisher,
+                        otbr::BorderAgent  &aBorderAgent);
 
     otbrError Init(void) override;
 
@@ -85,6 +84,7 @@ public:
 
 private:
     void DeviceRoleHandler(otDeviceRole aDeviceRole);
+    void Dhcp6PdStateHandler(otBorderRoutingDhcp6PdState aDhcp6PdState);
     void ActiveDatasetChangeHandler(const otOperationalDatasetTlvs &aDatasetTlvs);
     void NcpResetHandler(void);
 
@@ -107,6 +107,8 @@ private:
     void GetPropertiesHandler(DBusRequest &aRequest);
     void LeaveNetworkHandler(DBusRequest &aRequest);
     void SetNat64Enabled(DBusRequest &aRequest);
+    void ActivateEphemeralKeyModeHandler(DBusRequest &aRequest);
+    void DeactivateEphemeralKeyModeHandler(DBusRequest &aRequest);
 
     void IntrospectHandler(DBusRequest &aRequest);
 
@@ -118,6 +120,7 @@ private:
     otError SetRadioRegionHandler(DBusMessageIter &aIter);
     otError SetDnsUpstreamQueryState(DBusMessageIter &aIter);
     otError SetNat64Cidr(DBusMessageIter &aIter);
+    otError SetEphemeralKeyEnabled(DBusMessageIter &aIter);
 
     otError GetLinkModeHandler(DBusMessageIter &aIter);
     otError GetDeviceRoleHandler(DBusMessageIter &aIter);
@@ -170,6 +173,7 @@ private:
     otError GetNat64Mappings(DBusMessageIter &aIter);
     otError GetNat64ProtocolCounters(DBusMessageIter &aIter);
     otError GetNat64ErrorCounters(DBusMessageIter &aIter);
+    otError GetEphemeralKeyEnabled(DBusMessageIter &aIter);
     otError GetInfraLinkInfo(DBusMessageIter &aIter);
     otError GetDnsUpstreamQueryState(DBusMessageIter &aIter);
     otError GetTelemetryDataHandler(DBusMessageIter &aIter);
@@ -178,12 +182,17 @@ private:
     void ReplyScanResult(DBusRequest &aRequest, otError aError, const std::vector<otActiveScanResult> &aResult);
     void ReplyEnergyScanResult(DBusRequest &aRequest, otError aError, const std::vector<otEnergyScanResult> &aResult);
 
-    otbr::Ncp::ControllerOpenThread                     *mNcp;
+    otbr::Ncp::RcpHost                                  &mHost;
     std::unordered_map<std::string, PropertyHandlerType> mGetPropertyHandlers;
     otbr::Mdns::Publisher                               *mPublisher;
+    otbr::BorderAgent                                   &mBorderAgent;
 };
 
+/**
+ * @}
+ */
+
 } // namespace DBus
 } // namespace otbr
 
-#endif // OTBR_DBUS_THREAD_OBJECT_HPP_
+#endif // OTBR_DBUS_THREAD_OBJECT_RCP_HPP_
diff --git a/src/dbus/server/introspect.xml b/src/dbus/server/introspect.xml
index c6f26012..21b358e5 100644
--- a/src/dbus/server/introspect.xml
+++ b/src/dbus/server/introspect.xml
@@ -231,6 +231,25 @@
       <arg name="enable" type="b" direction="in"/>
     </method>
 
+    <property name="EphemeralKeyEnabled" type="b" access="readwrite">
+      <annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="false"/>
+    </property>
+
+    <!-- ActivateEphemeralKeyMode: Activate ePSKc mode.
+      @lifetime: in milliseconds, duration of active ePSKc mode before secure session is established.
+                 0 for OT_BORDER_AGENT_DEFAULT_EPHEMERAL_KEY_TIMEOUT (2 min).
+      @epskc: returns the ephemeral key digit string of length 9 with first 8 digits randomly generated,
+              and the last digit as verhoeff checksum.
+    -->
+    <method name="ActivateEphemeralKeyMode">
+      <arg name="lifetime" type="u" direction="in"/>
+      <arg name="epskc" type="s" direction="out"/>
+    </method>
+
+    <!-- DeactivateEphemeralKeyMode: Deactivate ePSKc mode. -->
+    <method name="DeactivateEphemeralKeyMode">
+    </method>
+
     <!-- MeshLocalPrefix: The /64 mesh-local prefix.  -->
     <property name="MeshLocalPrefix" type="ay" access="readwrite">
       <annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="false"/>
diff --git a/src/mdns/mdns_mdnssd.cpp b/src/mdns/mdns_mdnssd.cpp
index 689634a6..22c13b22 100644
--- a/src/mdns/mdns_mdnssd.cpp
+++ b/src/mdns/mdns_mdnssd.cpp
@@ -312,9 +312,7 @@ void PublisherMDnsSd::Update(MainloopContext &aMainloop)
 
         assert(fd != -1);
 
-        FD_SET(fd, &aMainloop.mReadFdSet);
-
-        aMainloop.mMaxFd = std::max(aMainloop.mMaxFd, fd);
+        aMainloop.AddFdToReadSet(fd);
     }
 
     for (const auto &service : mSubscribedServices)
@@ -419,8 +417,7 @@ void PublisherMDnsSd::DnssdServiceRegistration::Update(MainloopContext &aMainloo
     fd = DNSServiceRefSockFD(mServiceRef);
     VerifyOrExit(fd != -1);
 
-    FD_SET(fd, &aMainloop.mReadFdSet);
-    aMainloop.mMaxFd = std::max(aMainloop.mMaxFd, fd);
+    aMainloop.AddFdToReadSet(fd);
 
 exit:
     return;
@@ -1041,8 +1038,7 @@ void PublisherMDnsSd::ServiceRef::Update(MainloopContext &aMainloop) const
 
     fd = DNSServiceRefSockFD(mServiceRef);
     assert(fd != -1);
-    FD_SET(fd, &aMainloop.mReadFdSet);
-    aMainloop.mMaxFd = std::max(aMainloop.mMaxFd, fd);
+    aMainloop.AddFdToReadSet(fd);
 exit:
     return;
 }
diff --git a/src/ncp/CMakeLists.txt b/src/ncp/CMakeLists.txt
index 1540225b..9e706ee0 100644
--- a/src/ncp/CMakeLists.txt
+++ b/src/ncp/CMakeLists.txt
@@ -26,13 +26,24 @@
 #  POSSIBILITY OF SUCH DAMAGE.
 #
 
+add_subdirectory(posix)
+
 add_library(otbr-ncp
-    ncp_openthread.cpp
-    ncp_openthread.hpp
+    async_task.cpp
+    async_task.hpp
+    ncp_host.cpp
+    ncp_host.hpp
+    ncp_spinel.cpp
+    ncp_spinel.hpp
+    rcp_host.cpp
+    rcp_host.hpp
+    thread_host.cpp
+    thread_host.hpp
 )
 
 target_link_libraries(otbr-ncp PRIVATE
     otbr-common
+    otbr-posix
     $<$<BOOL:${OTBR_FEATURE_FLAGS}>:otbr-proto>
     $<$<BOOL:${OTBR_TELEMETRY_DATA_API}>:otbr-proto>
 )
diff --git a/src/ncp/async_task.cpp b/src/ncp/async_task.cpp
new file mode 100644
index 00000000..94827d80
--- /dev/null
+++ b/src/ncp/async_task.cpp
@@ -0,0 +1,99 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#include "async_task.hpp"
+
+#include <assert.h>
+#include <memory>
+
+#include "common/code_utils.hpp"
+
+namespace otbr {
+namespace Ncp {
+
+AsyncTask::AsyncTask(const ResultHandler &aResultHandler)
+    : mResultHandler(aResultHandler)
+{
+}
+
+AsyncTask::~AsyncTask()
+{
+    if (!mNext)
+    {
+        if (mResultHandler)
+        {
+            mResultHandler(OT_ERROR_FAILED, "AsyncTask ends without setting any result.");
+        }
+    }
+}
+
+void AsyncTask::Run(void)
+{
+    SetResult(OT_ERROR_NONE, "");
+}
+
+void AsyncTask::SetResult(otError aError, const std::string &aErrorInfo)
+{
+    if (mNext)
+    {
+        if (aError == OT_ERROR_NONE)
+        {
+            mThen(std::move(mNext));
+        }
+        else
+        {
+            mNext->SetResult(aError, aErrorInfo);
+        }
+        mThen = nullptr;
+    }
+    else
+    {
+        mResultHandler(aError, aErrorInfo);
+        mResultHandler = nullptr;
+    }
+}
+
+AsyncTaskPtr &AsyncTask::First(const ThenHandler &aFirst)
+{
+    assert(mNext == nullptr);
+
+    return Then(aFirst);
+}
+
+AsyncTaskPtr &AsyncTask::Then(const ThenHandler &aThen)
+{
+    assert(mNext == nullptr);
+
+    mNext = std::make_shared<AsyncTask>(mResultHandler);
+    mThen = aThen;
+
+    return mNext;
+}
+
+} // namespace Ncp
+} // namespace otbr
diff --git a/src/ncp/async_task.hpp b/src/ncp/async_task.hpp
new file mode 100644
index 00000000..5421d34b
--- /dev/null
+++ b/src/ncp/async_task.hpp
@@ -0,0 +1,120 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+/**
+ * @file
+ *   This file includes definitions for chained async task.
+ *   The utility class is used to support the usage of a `Then`-style chained async operations.
+ */
+
+#ifndef OTBR_AGENT_ASYNC_TASK_HPP_
+#define OTBR_AGENT_ASYNC_TASK_HPP_
+
+#include <functional>
+#include <memory>
+
+#include <openthread/error.h>
+
+namespace otbr {
+namespace Ncp {
+
+class AsyncTask;
+using AsyncTaskPtr = std::shared_ptr<AsyncTask>;
+
+class AsyncTask
+{
+public:
+    using ThenHandler   = std::function<void(AsyncTaskPtr)>;
+    using ResultHandler = std::function<void(otError, const std::string &)>;
+
+    /**
+     * Constructor.
+     *
+     * @param[in]  The error handler called when the result is not OT_ERROR_NONE;
+     *
+     */
+    AsyncTask(const ResultHandler &aResultHandler);
+
+    /**
+     * Destructor.
+     *
+     */
+    ~AsyncTask(void);
+
+    /**
+     * Trigger the initial action of the chained async operations.
+     *
+     * This method should be called to trigger the chained async operations.
+     *
+     */
+    void Run(void);
+
+    /**
+     * Set the result of the previous async operation.
+     *
+     * This method should be called when the result of the previous async operation is ready.
+     * This method will pass the result to next operation.
+     *
+     * @param[in] aError  The result for the previous async operation.
+     *
+     */
+    void SetResult(otError aError, const std::string &aErrorInfo);
+
+    /**
+     * Set the initial operation of the chained async operations.
+     *
+     * @param[in] aFirst  A reference to a function object for the initial action.
+     *
+     * @returns  A shared pointer to a AsyncTask object created in this method.
+     *
+     */
+    AsyncTaskPtr &First(const ThenHandler &aFirst);
+
+    /**
+     * Set the next operation of the chained async operations.
+     *
+     * @param[in] aThen  A reference to a function object for the next action.
+     *
+     * @returns A shared pointer to a AsyncTask object created in this method.
+     *
+     */
+    AsyncTaskPtr &Then(const ThenHandler &aThen);
+
+private:
+    union
+    {
+        ThenHandler   mThen;          // Only valid when `mNext` is not nullptr
+        ResultHandler mResultHandler; // Only valid when `mNext` is nullptr
+    };
+    AsyncTaskPtr mNext;
+};
+
+} // namespace Ncp
+} // namespace otbr
+
+#endif // OTBR_AGENT_ASYNC_TASK_HPP_
diff --git a/src/ncp/ncp_host.cpp b/src/ncp/ncp_host.cpp
new file mode 100644
index 00000000..af988feb
--- /dev/null
+++ b/src/ncp/ncp_host.cpp
@@ -0,0 +1,164 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#define OTBR_LOG_TAG "NCP_HOST"
+
+#include "ncp_host.hpp"
+
+#include <memory>
+
+#include <openthread/error.h>
+#include <openthread/thread.h>
+
+#include <openthread/openthread-system.h>
+
+#include "lib/spinel/spinel_driver.hpp"
+
+#include "ncp/async_task.hpp"
+
+namespace otbr {
+namespace Ncp {
+
+// =============================== NcpNetworkProperties ===============================
+
+NcpNetworkProperties::NcpNetworkProperties(void)
+    : mDeviceRole(OT_DEVICE_ROLE_DISABLED)
+{
+}
+
+otDeviceRole NcpNetworkProperties::GetDeviceRole(void) const
+{
+    return mDeviceRole;
+}
+
+void NcpNetworkProperties::SetDeviceRole(otDeviceRole aRole)
+{
+    mDeviceRole = aRole;
+}
+
+// ===================================== NcpHost ======================================
+
+NcpHost::NcpHost(const char *aInterfaceName, bool aDryRun)
+    : mSpinelDriver(*static_cast<ot::Spinel::SpinelDriver *>(otSysGetSpinelDriver()))
+    , mNetif()
+{
+    memset(&mConfig, 0, sizeof(mConfig));
+    mConfig.mInterfaceName = aInterfaceName;
+    mConfig.mDryRun        = aDryRun;
+    mConfig.mSpeedUpFactor = 1;
+}
+
+const char *NcpHost::GetCoprocessorVersion(void)
+{
+    return mSpinelDriver.GetVersion();
+}
+
+void NcpHost::Init(void)
+{
+    otSysInit(&mConfig);
+    mNcpSpinel.Init(mSpinelDriver, *this);
+    mNetif.Init(mConfig.mInterfaceName,
+                [this](const uint8_t *aData, uint16_t aLength) { return mNcpSpinel.Ip6Send(aData, aLength); });
+
+    mNcpSpinel.Ip6SetAddressCallback(
+        [this](const std::vector<Ip6AddressInfo> &aAddrInfos) { mNetif.UpdateIp6UnicastAddresses(aAddrInfos); });
+    mNcpSpinel.Ip6SetAddressMulticastCallback(
+        [this](const std::vector<Ip6Address> &aAddrs) { mNetif.UpdateIp6MulticastAddresses(aAddrs); });
+    mNcpSpinel.NetifSetStateChangedCallback([this](bool aState) { mNetif.SetNetifState(aState); });
+}
+
+void NcpHost::Deinit(void)
+{
+    mNcpSpinel.Deinit();
+    mNetif.Deinit();
+    otSysDeinit();
+}
+
+void NcpHost::Join(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, const AsyncResultReceiver &aReceiver)
+{
+    AsyncTaskPtr task;
+    auto errorHandler = [aReceiver](otError aError, const std::string &aErrorInfo) { aReceiver(aError, aErrorInfo); };
+
+    task = std::make_shared<AsyncTask>(errorHandler);
+    task->First([this, aActiveOpDatasetTlvs](AsyncTaskPtr aNext) {
+            mNcpSpinel.DatasetSetActiveTlvs(aActiveOpDatasetTlvs, std::move(aNext));
+        })
+        ->Then([this](AsyncTaskPtr aNext) { mNcpSpinel.Ip6SetEnabled(true, std::move(aNext)); })
+        ->Then([this](AsyncTaskPtr aNext) { mNcpSpinel.ThreadSetEnabled(true, std::move(aNext)); });
+    task->Run();
+}
+
+void NcpHost::Leave(const AsyncResultReceiver &aReceiver)
+{
+    AsyncTaskPtr task;
+    auto errorHandler = [aReceiver](otError aError, const std::string &aErrorInfo) { aReceiver(aError, aErrorInfo); };
+
+    task = std::make_shared<AsyncTask>(errorHandler);
+    task->First([this](AsyncTaskPtr aNext) { mNcpSpinel.ThreadDetachGracefully(std::move(aNext)); })
+        ->Then([this](AsyncTaskPtr aNext) { mNcpSpinel.ThreadErasePersistentInfo(std::move(aNext)); });
+    task->Run();
+}
+
+void NcpHost::ScheduleMigration(const otOperationalDatasetTlvs &aPendingOpDatasetTlvs,
+                                const AsyncResultReceiver       aReceiver)
+{
+    otDeviceRole role  = GetDeviceRole();
+    otError      error = OT_ERROR_NONE;
+    auto errorHandler  = [aReceiver](otError aError, const std::string &aErrorInfo) { aReceiver(aError, aErrorInfo); };
+
+    VerifyOrExit(role != OT_DEVICE_ROLE_DISABLED && role != OT_DEVICE_ROLE_DETACHED, error = OT_ERROR_INVALID_STATE);
+
+    mNcpSpinel.DatasetMgmtSetPending(std::make_shared<otOperationalDatasetTlvs>(aPendingOpDatasetTlvs),
+                                     std::make_shared<AsyncTask>(errorHandler));
+
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        mTaskRunner.Post(
+            [aReceiver, error](void) { aReceiver(error, "Cannot schedule migration when this device is detached"); });
+    }
+}
+
+void NcpHost::Process(const MainloopContext &aMainloop)
+{
+    mSpinelDriver.Process(&aMainloop);
+}
+
+void NcpHost::Update(MainloopContext &aMainloop)
+{
+    mSpinelDriver.GetSpinelInterface()->UpdateFdSet(&aMainloop);
+
+    if (mSpinelDriver.HasPendingFrame())
+    {
+        aMainloop.mTimeout.tv_sec  = 0;
+        aMainloop.mTimeout.tv_usec = 0;
+    }
+}
+
+} // namespace Ncp
+} // namespace otbr
diff --git a/src/ncp/ncp_host.hpp b/src/ncp/ncp_host.hpp
new file mode 100644
index 00000000..9d74177b
--- /dev/null
+++ b/src/ncp/ncp_host.hpp
@@ -0,0 +1,115 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+/**
+ * @file
+ *   This file includes definitions of OpenThead Host for NCP.
+ */
+
+#ifndef OTBR_AGENT_NCP_HOST_HPP_
+#define OTBR_AGENT_NCP_HOST_HPP_
+
+#include "lib/spinel/coprocessor_type.h"
+#include "lib/spinel/spinel_driver.hpp"
+
+#include "common/mainloop.hpp"
+#include "ncp/ncp_spinel.hpp"
+#include "ncp/thread_host.hpp"
+#include "posix/netif.hpp"
+
+namespace otbr {
+namespace Ncp {
+
+/**
+ * This class implements the NetworkProperties under NCP mode.
+ *
+ */
+class NcpNetworkProperties : virtual public NetworkProperties, public PropsObserver
+{
+public:
+    /**
+     * Constructor
+     *
+     */
+    explicit NcpNetworkProperties(void);
+
+    // NetworkProperties methods
+    otDeviceRole GetDeviceRole(void) const override;
+
+private:
+    // PropsObserver methods
+    void SetDeviceRole(otDeviceRole aRole) override;
+
+    otDeviceRole mDeviceRole;
+};
+
+class NcpHost : public MainloopProcessor, public ThreadHost, public NcpNetworkProperties
+{
+public:
+    /**
+     * Constructor.
+     *
+     * @param[in]   aInterfaceName  A string of the NCP interface name.
+     * @param[in]   aDryRun         TRUE to indicate dry-run mode. FALSE otherwise.
+     *
+     */
+    NcpHost(const char *aInterfaceName, bool aDryRun);
+
+    /**
+     * Destructor.
+     *
+     */
+    ~NcpHost(void) override = default;
+
+    // ThreadHost methods
+    void Join(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, const AsyncResultReceiver &aReceiver) override;
+    void Leave(const AsyncResultReceiver &aReceiver) override;
+    void ScheduleMigration(const otOperationalDatasetTlvs &aPendingOpDatasetTlvs,
+                           const AsyncResultReceiver       aReceiver) override;
+    CoprocessorType GetCoprocessorType(void) override { return OT_COPROCESSOR_NCP; }
+    const char     *GetCoprocessorVersion(void) override;
+    const char     *GetInterfaceName(void) const override { return mConfig.mInterfaceName; }
+    void            Init(void) override;
+    void            Deinit(void) override;
+
+    // MainloopProcessor methods
+    void Update(MainloopContext &aMainloop) override;
+    void Process(const MainloopContext &aMainloop) override;
+
+private:
+    ot::Spinel::SpinelDriver &mSpinelDriver;
+    otPlatformConfig          mConfig;
+    NcpSpinel                 mNcpSpinel;
+    TaskRunner                mTaskRunner;
+    Netif                     mNetif;
+};
+
+} // namespace Ncp
+} // namespace otbr
+
+#endif // OTBR_AGENT_NCP_HOST_HPP_
diff --git a/src/ncp/ncp_spinel.cpp b/src/ncp/ncp_spinel.cpp
new file mode 100644
index 00000000..c9a0458d
--- /dev/null
+++ b/src/ncp/ncp_spinel.cpp
@@ -0,0 +1,620 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#define OTBR_LOG_TAG "NcpSpinel"
+
+#include "ncp_spinel.hpp"
+
+#include <stdarg.h>
+
+#include <algorithm>
+
+#include <openthread/dataset.h>
+#include <openthread/thread.h>
+
+#include "common/code_utils.hpp"
+#include "common/logging.hpp"
+#include "lib/spinel/spinel.h"
+#include "lib/spinel/spinel_decoder.hpp"
+#include "lib/spinel/spinel_driver.hpp"
+#include "lib/spinel/spinel_helper.hpp"
+
+namespace otbr {
+namespace Ncp {
+
+static constexpr char kSpinelDataUnpackFormat[] = "CiiD";
+
+NcpSpinel::NcpSpinel(void)
+    : mSpinelDriver(nullptr)
+    , mCmdTidsInUse(0)
+    , mCmdNextTid(1)
+    , mNcpBuffer(mTxBuffer, kTxBufferSize)
+    , mEncoder(mNcpBuffer)
+    , mIid(SPINEL_HEADER_INVALID_IID)
+    , mPropsObserver(nullptr)
+{
+    std::fill_n(mWaitingKeyTable, SPINEL_PROP_LAST_STATUS, sizeof(mWaitingKeyTable));
+    memset(mCmdTable, 0, sizeof(mCmdTable));
+}
+
+void NcpSpinel::Init(ot::Spinel::SpinelDriver &aSpinelDriver, PropsObserver &aObserver)
+{
+    mSpinelDriver  = &aSpinelDriver;
+    mPropsObserver = &aObserver;
+    mIid           = mSpinelDriver->GetIid();
+    mSpinelDriver->SetFrameHandler(&HandleReceivedFrame, &HandleSavedFrame, this);
+}
+
+void NcpSpinel::Deinit(void)
+{
+    mSpinelDriver              = nullptr;
+    mIp6AddressTableCallback   = nullptr;
+    mNetifStateChangedCallback = nullptr;
+}
+
+otbrError NcpSpinel::SpinelDataUnpack(const uint8_t *aDataIn, spinel_size_t aDataLen, const char *aPackFormat, ...)
+{
+    otbrError      error = OTBR_ERROR_NONE;
+    spinel_ssize_t unpacked;
+    va_list        args;
+
+    va_start(args, aPackFormat);
+    unpacked = spinel_datatype_vunpack(aDataIn, aDataLen, aPackFormat, args);
+    va_end(args);
+
+    VerifyOrExit(unpacked > 0, error = OTBR_ERROR_PARSE);
+
+exit:
+    return error;
+}
+
+void NcpSpinel::DatasetSetActiveTlvs(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, AsyncTaskPtr aAsyncTask)
+{
+    otError      error        = OT_ERROR_NONE;
+    EncodingFunc encodingFunc = [this, &aActiveOpDatasetTlvs] {
+        return mEncoder.WriteData(aActiveOpDatasetTlvs.mTlvs, aActiveOpDatasetTlvs.mLength);
+    };
+
+    VerifyOrExit(mDatasetSetActiveTask == nullptr, error = OT_ERROR_BUSY);
+
+    SuccessOrExit(error = SetProperty(SPINEL_PROP_THREAD_ACTIVE_DATASET_TLVS, encodingFunc));
+    mDatasetSetActiveTask = aAsyncTask;
+
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        mTaskRunner.Post([aAsyncTask, error](void) { aAsyncTask->SetResult(error, "Failed to set active dataset!"); });
+    }
+}
+
+void NcpSpinel::DatasetMgmtSetPending(std::shared_ptr<otOperationalDatasetTlvs> aPendingOpDatasetTlvsPtr,
+                                      AsyncTaskPtr                              aAsyncTask)
+{
+    otError      error        = OT_ERROR_NONE;
+    EncodingFunc encodingFunc = [this, aPendingOpDatasetTlvsPtr] {
+        return mEncoder.WriteData(aPendingOpDatasetTlvsPtr->mTlvs, aPendingOpDatasetTlvsPtr->mLength);
+    };
+
+    VerifyOrExit(mDatasetMgmtSetPendingTask == nullptr, error = OT_ERROR_BUSY);
+
+    SuccessOrExit(error = SetProperty(SPINEL_PROP_THREAD_MGMT_SET_PENDING_DATASET_TLVS, encodingFunc));
+    mDatasetMgmtSetPendingTask = aAsyncTask;
+
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        mTaskRunner.Post([aAsyncTask, error] { aAsyncTask->SetResult(error, "Failed to set pending dataset!"); });
+    }
+}
+
+void NcpSpinel::Ip6SetEnabled(bool aEnable, AsyncTaskPtr aAsyncTask)
+{
+    otError      error        = OT_ERROR_NONE;
+    EncodingFunc encodingFunc = [this, aEnable] { return mEncoder.WriteBool(aEnable); };
+
+    VerifyOrExit(mIp6SetEnabledTask == nullptr, error = OT_ERROR_BUSY);
+
+    SuccessOrExit(error = SetProperty(SPINEL_PROP_NET_IF_UP, encodingFunc));
+    mIp6SetEnabledTask = aAsyncTask;
+
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        mTaskRunner.Post(
+            [aAsyncTask, error](void) { aAsyncTask->SetResult(error, "Failed to enable the network interface!"); });
+    }
+    return;
+}
+
+otbrError NcpSpinel::Ip6Send(const uint8_t *aData, uint16_t aLength)
+{
+    // TODO: Impelement this function.
+    OTBR_UNUSED_VARIABLE(aData);
+    OTBR_UNUSED_VARIABLE(aLength);
+
+    return OTBR_ERROR_NONE;
+}
+
+void NcpSpinel::ThreadSetEnabled(bool aEnable, AsyncTaskPtr aAsyncTask)
+{
+    otError      error        = OT_ERROR_NONE;
+    EncodingFunc encodingFunc = [this, aEnable] { return mEncoder.WriteBool(aEnable); };
+
+    VerifyOrExit(mThreadSetEnabledTask == nullptr, error = OT_ERROR_BUSY);
+
+    SuccessOrExit(error = SetProperty(SPINEL_PROP_NET_STACK_UP, encodingFunc));
+    mThreadSetEnabledTask = aAsyncTask;
+
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        mTaskRunner.Post(
+            [aAsyncTask, error](void) { aAsyncTask->SetResult(error, "Failed to enable the Thread network!"); });
+    }
+    return;
+}
+
+void NcpSpinel::ThreadDetachGracefully(AsyncTaskPtr aAsyncTask)
+{
+    otError      error        = OT_ERROR_NONE;
+    EncodingFunc encodingFunc = [] { return OT_ERROR_NONE; };
+
+    VerifyOrExit(mThreadDetachGracefullyTask == nullptr, error = OT_ERROR_BUSY);
+
+    SuccessOrExit(error = SetProperty(SPINEL_PROP_NET_LEAVE_GRACEFULLY, encodingFunc));
+    mThreadDetachGracefullyTask = aAsyncTask;
+
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        mTaskRunner.Post([aAsyncTask, error](void) { aAsyncTask->SetResult(error, "Failed to detach gracefully!"); });
+    }
+    return;
+}
+
+void NcpSpinel::ThreadErasePersistentInfo(AsyncTaskPtr aAsyncTask)
+{
+    otError      error = OT_ERROR_NONE;
+    spinel_tid_t tid   = GetNextTid();
+
+    VerifyOrExit(mThreadErasePersistentInfoTask == nullptr, error = OT_ERROR_BUSY);
+
+    SuccessOrExit(error = mSpinelDriver->SendCommand(SPINEL_CMD_NET_CLEAR, SPINEL_PROP_LAST_STATUS, tid));
+
+    mWaitingKeyTable[tid]          = SPINEL_PROP_LAST_STATUS;
+    mCmdTable[tid]                 = SPINEL_CMD_NET_CLEAR;
+    mThreadErasePersistentInfoTask = aAsyncTask;
+
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        FreeTidTableItem(tid);
+        mTaskRunner.Post(
+            [aAsyncTask, error](void) { aAsyncTask->SetResult(error, "Failed to erase persistent info!"); });
+    }
+}
+
+void NcpSpinel::HandleReceivedFrame(const uint8_t *aFrame,
+                                    uint16_t       aLength,
+                                    uint8_t        aHeader,
+                                    bool          &aSave,
+                                    void          *aContext)
+{
+    static_cast<NcpSpinel *>(aContext)->HandleReceivedFrame(aFrame, aLength, aHeader, aSave);
+}
+
+void NcpSpinel::HandleReceivedFrame(const uint8_t *aFrame, uint16_t aLength, uint8_t aHeader, bool &aShouldSaveFrame)
+{
+    spinel_tid_t tid = SPINEL_HEADER_GET_TID(aHeader);
+
+    if (tid == 0)
+    {
+        HandleNotification(aFrame, aLength);
+    }
+    else if (tid < kMaxTids)
+    {
+        HandleResponse(tid, aFrame, aLength);
+    }
+    else
+    {
+        otbrLogCrit("Received unexpected tid: %u", tid);
+    }
+
+    aShouldSaveFrame = false;
+}
+
+void NcpSpinel::HandleSavedFrame(const uint8_t *aFrame, uint16_t aLength, void *aContext)
+{
+    /* Intentionally Empty */
+    OT_UNUSED_VARIABLE(aFrame);
+    OT_UNUSED_VARIABLE(aLength);
+    OT_UNUSED_VARIABLE(aContext);
+}
+
+void NcpSpinel::HandleNotification(const uint8_t *aFrame, uint16_t aLength)
+{
+    spinel_prop_key_t key;
+    spinel_size_t     len  = 0;
+    uint8_t          *data = nullptr;
+    uint32_t          cmd;
+    uint8_t           header;
+    otbrError         error = OTBR_ERROR_NONE;
+
+    SuccessOrExit(error = SpinelDataUnpack(aFrame, aLength, kSpinelDataUnpackFormat, &header, &cmd, &key, &data, &len));
+    VerifyOrExit(SPINEL_HEADER_GET_TID(header) == 0, error = OTBR_ERROR_PARSE);
+    VerifyOrExit(cmd == SPINEL_CMD_PROP_VALUE_IS);
+    HandleValueIs(key, data, static_cast<uint16_t>(len));
+
+exit:
+    otbrLogResult(error, "HandleNotification: %s", __FUNCTION__);
+}
+
+void NcpSpinel::HandleResponse(spinel_tid_t aTid, const uint8_t *aFrame, uint16_t aLength)
+{
+    spinel_prop_key_t key;
+    spinel_size_t     len  = 0;
+    uint8_t          *data = nullptr;
+    uint32_t          cmd;
+    uint8_t           header;
+    otbrError         error          = OTBR_ERROR_NONE;
+    FailureHandler    failureHandler = nullptr;
+
+    SuccessOrExit(error = SpinelDataUnpack(aFrame, aLength, kSpinelDataUnpackFormat, &header, &cmd, &key, &data, &len));
+
+    VerifyOrExit(cmd == SPINEL_CMD_PROP_VALUE_IS, error = OTBR_ERROR_INVALID_STATE);
+
+    switch (mCmdTable[aTid])
+    {
+    case SPINEL_CMD_PROP_VALUE_SET:
+    {
+        error = HandleResponseForPropSet(aTid, key, data, len);
+        break;
+    }
+    case SPINEL_CMD_NET_CLEAR:
+    {
+        spinel_status_t status = SPINEL_STATUS_OK;
+
+        SuccessOrExit(error = SpinelDataUnpack(data, len, SPINEL_DATATYPE_UINT_PACKED_S, &status));
+        CallAndClear(mThreadErasePersistentInfoTask, ot::Spinel::SpinelStatusToOtError(status));
+        break;
+    }
+    default:
+        break;
+    }
+
+exit:
+    if (error == OTBR_ERROR_INVALID_STATE)
+    {
+        otbrLogCrit("Received unexpected response with (cmd:%u, key:%u), waiting (cmd:%u, key:%u) for tid:%u", cmd, key,
+                    mCmdTable[aTid], mWaitingKeyTable[aTid], aTid);
+    }
+    else if (error == OTBR_ERROR_PARSE)
+    {
+        otbrLogCrit("Error parsing response with tid:%u", aTid);
+    }
+    FreeTidTableItem(aTid);
+}
+
+void NcpSpinel::HandleValueIs(spinel_prop_key_t aKey, const uint8_t *aBuffer, uint16_t aLength)
+{
+    otbrError error = OTBR_ERROR_NONE;
+
+    switch (aKey)
+    {
+    case SPINEL_PROP_LAST_STATUS:
+    {
+        spinel_status_t status = SPINEL_STATUS_OK;
+
+        SuccessOrExit(error = SpinelDataUnpack(aBuffer, aLength, SPINEL_DATATYPE_UINT_PACKED_S, &status));
+
+        otbrLogInfo("NCP last status: %s", spinel_status_to_cstr(status));
+        break;
+    }
+
+    case SPINEL_PROP_NET_ROLE:
+    {
+        spinel_net_role_t role = SPINEL_NET_ROLE_DISABLED;
+        otDeviceRole      deviceRole;
+
+        SuccessOrExit(error = SpinelDataUnpack(aBuffer, aLength, SPINEL_DATATYPE_UINT8_S, &role));
+
+        deviceRole = SpinelRoleToDeviceRole(role);
+        mPropsObserver->SetDeviceRole(deviceRole);
+
+        otbrLogInfo("Device role changed to %s", otThreadDeviceRoleToString(deviceRole));
+        break;
+    }
+
+    case SPINEL_PROP_NET_LEAVE_GRACEFULLY:
+    {
+        CallAndClear(mThreadDetachGracefullyTask, OT_ERROR_NONE);
+        break;
+    }
+
+    case SPINEL_PROP_THREAD_MGMT_SET_PENDING_DATASET_TLVS:
+    {
+        spinel_status_t status = SPINEL_STATUS_OK;
+
+        SuccessOrExit(error = SpinelDataUnpack(aBuffer, aLength, SPINEL_DATATYPE_UINT_PACKED_S, &status));
+        CallAndClear(mDatasetMgmtSetPendingTask, ot::Spinel::SpinelStatusToOtError(status));
+        break;
+    }
+
+    case SPINEL_PROP_IPV6_ADDRESS_TABLE:
+    {
+        std::vector<Ip6AddressInfo> addressInfoTable;
+
+        VerifyOrExit(ParseIp6AddressTable(aBuffer, aLength, addressInfoTable) == OT_ERROR_NONE,
+                     error = OTBR_ERROR_PARSE);
+        SafeInvoke(mIp6AddressTableCallback, addressInfoTable);
+        break;
+    }
+
+    case SPINEL_PROP_IPV6_MULTICAST_ADDRESS_TABLE:
+    {
+        std::vector<Ip6Address> addressTable;
+
+        VerifyOrExit(ParseIp6MulticastAddresses(aBuffer, aLength, addressTable) == OT_ERROR_NONE,
+                     error = OTBR_ERROR_PARSE);
+        SafeInvoke(mIp6MulticastAddressTableCallback, addressTable);
+        break;
+    }
+
+    case SPINEL_PROP_NET_IF_UP:
+    {
+        bool isUp;
+        SuccessOrExit(error = SpinelDataUnpack(aBuffer, aLength, SPINEL_DATATYPE_BOOL_S, &isUp));
+        SafeInvoke(mNetifStateChangedCallback, isUp);
+        break;
+    }
+
+    default:
+        otbrLogWarning("Received uncognized key: %u", aKey);
+        break;
+    }
+
+exit:
+    otbrLogResult(error, "NcpSpinel: %s", __FUNCTION__);
+    return;
+}
+
+otbrError NcpSpinel::HandleResponseForPropSet(spinel_tid_t      aTid,
+                                              spinel_prop_key_t aKey,
+                                              const uint8_t    *aData,
+                                              uint16_t          aLength)
+{
+    OTBR_UNUSED_VARIABLE(aData);
+    OTBR_UNUSED_VARIABLE(aLength);
+
+    otbrError error = OTBR_ERROR_NONE;
+
+    switch (mWaitingKeyTable[aTid])
+    {
+    case SPINEL_PROP_THREAD_ACTIVE_DATASET_TLVS:
+        VerifyOrExit(aKey == SPINEL_PROP_THREAD_ACTIVE_DATASET_TLVS, error = OTBR_ERROR_INVALID_STATE);
+        CallAndClear(mDatasetSetActiveTask, OT_ERROR_NONE);
+        break;
+
+    case SPINEL_PROP_NET_IF_UP:
+        VerifyOrExit(aKey == SPINEL_PROP_NET_IF_UP, error = OTBR_ERROR_INVALID_STATE);
+        CallAndClear(mIp6SetEnabledTask, OT_ERROR_NONE);
+        {
+            bool isUp;
+            SuccessOrExit(error = SpinelDataUnpack(aData, aLength, SPINEL_DATATYPE_BOOL_S, &isUp));
+            SafeInvoke(mNetifStateChangedCallback, isUp);
+        }
+        break;
+
+    case SPINEL_PROP_NET_STACK_UP:
+        VerifyOrExit(aKey == SPINEL_PROP_NET_STACK_UP, error = OTBR_ERROR_INVALID_STATE);
+        CallAndClear(mThreadSetEnabledTask, OT_ERROR_NONE);
+        break;
+
+    case SPINEL_PROP_THREAD_MGMT_SET_PENDING_DATASET_TLVS:
+        if (aKey == SPINEL_PROP_LAST_STATUS)
+        { // Failed case
+            spinel_status_t status = SPINEL_STATUS_OK;
+
+            SuccessOrExit(error = SpinelDataUnpack(aData, aLength, SPINEL_DATATYPE_UINT_PACKED_S, &status));
+            CallAndClear(mDatasetMgmtSetPendingTask, ot::Spinel::SpinelStatusToOtError(status));
+        }
+        else if (aKey != SPINEL_PROP_THREAD_MGMT_SET_PENDING_DATASET_TLVS)
+        {
+            ExitNow(error = OTBR_ERROR_INVALID_STATE);
+        }
+        break;
+
+    default:
+        VerifyOrExit(aKey == mWaitingKeyTable[aTid], error = OTBR_ERROR_INVALID_STATE);
+        break;
+    }
+
+exit:
+    return error;
+}
+
+spinel_tid_t NcpSpinel::GetNextTid(void)
+{
+    spinel_tid_t tid = mCmdNextTid;
+
+    while (((1 << tid) & mCmdTidsInUse) != 0)
+    {
+        tid = SPINEL_GET_NEXT_TID(tid);
+
+        if (tid == mCmdNextTid)
+        {
+            // We looped back to `mCmdNextTid` indicating that all
+            // TIDs are in-use.
+
+            ExitNow(tid = 0);
+        }
+    }
+
+    mCmdTidsInUse |= (1 << tid);
+    mCmdNextTid = SPINEL_GET_NEXT_TID(tid);
+
+exit:
+    return tid;
+}
+
+void NcpSpinel::FreeTidTableItem(spinel_tid_t aTid)
+{
+    mCmdTidsInUse &= ~(1 << aTid);
+
+    mCmdTable[aTid]        = SPINEL_CMD_NOOP;
+    mWaitingKeyTable[aTid] = SPINEL_PROP_LAST_STATUS;
+}
+
+otError NcpSpinel::SetProperty(spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc)
+{
+    otError      error  = OT_ERROR_NONE;
+    spinel_tid_t tid    = GetNextTid();
+    uint8_t      header = SPINEL_HEADER_FLAG | SPINEL_HEADER_IID(mIid) | tid;
+
+    VerifyOrExit(tid != 0, error = OT_ERROR_BUSY);
+    SuccessOrExit(error = mEncoder.BeginFrame(header, SPINEL_CMD_PROP_VALUE_SET, aKey));
+    SuccessOrExit(error = aEncodingFunc());
+    SuccessOrExit(error = mEncoder.EndFrame());
+    SuccessOrExit(error = SendEncodedFrame());
+
+    mCmdTable[tid]        = SPINEL_CMD_PROP_VALUE_SET;
+    mWaitingKeyTable[tid] = aKey;
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        FreeTidTableItem(tid);
+    }
+    return error;
+}
+
+otError NcpSpinel::SendEncodedFrame(void)
+{
+    otError  error = OT_ERROR_NONE;
+    uint8_t  frame[kTxBufferSize];
+    uint16_t frameLength;
+
+    SuccessOrExit(error = mNcpBuffer.OutFrameBegin());
+    frameLength = mNcpBuffer.OutFrameGetLength();
+    VerifyOrExit(mNcpBuffer.OutFrameRead(frameLength, frame) == frameLength, error = OT_ERROR_FAILED);
+    SuccessOrExit(error = mSpinelDriver->GetSpinelInterface()->SendFrame(frame, frameLength));
+
+exit:
+    error = mNcpBuffer.OutFrameRemove();
+    return error;
+}
+
+otError NcpSpinel::ParseIp6AddressTable(const uint8_t               *aBuf,
+                                        uint16_t                     aLength,
+                                        std::vector<Ip6AddressInfo> &aAddressTable)
+{
+    otError             error = OT_ERROR_NONE;
+    ot::Spinel::Decoder decoder;
+
+    VerifyOrExit(aBuf != nullptr, error = OT_ERROR_INVALID_ARGS);
+    decoder.Init(aBuf, aLength);
+
+    while (!decoder.IsAllReadInStruct())
+    {
+        Ip6AddressInfo      cur;
+        const otIp6Address *addr;
+        uint8_t             prefixLength;
+        uint32_t            preferredLifetime;
+        uint32_t            validLifetime;
+
+        SuccessOrExit(error = decoder.OpenStruct());
+        SuccessOrExit(error = decoder.ReadIp6Address(addr));
+        memcpy(&cur.mAddress, addr, sizeof(otIp6Address));
+        SuccessOrExit(error = decoder.ReadUint8(prefixLength));
+        cur.mPrefixLength = prefixLength;
+        SuccessOrExit(error = decoder.ReadUint32(preferredLifetime));
+        cur.mPreferred = preferredLifetime ? true : false;
+        SuccessOrExit(error = decoder.ReadUint32(validLifetime));
+        OTBR_UNUSED_VARIABLE(validLifetime);
+        SuccessOrExit((error = decoder.CloseStruct()));
+
+        aAddressTable.push_back(cur);
+    }
+
+exit:
+    return error;
+}
+
+otError NcpSpinel::ParseIp6MulticastAddresses(const uint8_t *aBuf, uint8_t aLen, std::vector<Ip6Address> &aAddressList)
+{
+    otError             error = OT_ERROR_NONE;
+    ot::Spinel::Decoder decoder;
+
+    VerifyOrExit(aBuf != nullptr, error = OT_ERROR_INVALID_ARGS);
+
+    decoder.Init(aBuf, aLen);
+
+    while (!decoder.IsAllReadInStruct())
+    {
+        const otIp6Address *addr;
+
+        SuccessOrExit(error = decoder.OpenStruct());
+        SuccessOrExit(error = decoder.ReadIp6Address(addr));
+        aAddressList.emplace_back(Ip6Address(*addr));
+        SuccessOrExit((error = decoder.CloseStruct()));
+    }
+
+exit:
+    return error;
+}
+
+otDeviceRole NcpSpinel::SpinelRoleToDeviceRole(spinel_net_role_t aRole)
+{
+    otDeviceRole role = OT_DEVICE_ROLE_DISABLED;
+
+    switch (aRole)
+    {
+    case SPINEL_NET_ROLE_DISABLED:
+        role = OT_DEVICE_ROLE_DISABLED;
+        break;
+    case SPINEL_NET_ROLE_DETACHED:
+        role = OT_DEVICE_ROLE_DETACHED;
+        break;
+    case SPINEL_NET_ROLE_CHILD:
+        role = OT_DEVICE_ROLE_CHILD;
+        break;
+    case SPINEL_NET_ROLE_ROUTER:
+        role = OT_DEVICE_ROLE_ROUTER;
+        break;
+    case SPINEL_NET_ROLE_LEADER:
+        role = OT_DEVICE_ROLE_LEADER;
+        break;
+    default:
+        otbrLogWarning("Unsupported spinel net role: %u", aRole);
+        break;
+    }
+
+    return role;
+}
+
+} // namespace Ncp
+} // namespace otbr
diff --git a/src/ncp/ncp_spinel.hpp b/src/ncp/ncp_spinel.hpp
new file mode 100644
index 00000000..f60895db
--- /dev/null
+++ b/src/ncp/ncp_spinel.hpp
@@ -0,0 +1,323 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+/**
+ * @file
+ *   This file includes definitions for the spinel based Thread controller.
+ */
+
+#ifndef OTBR_AGENT_NCP_SPINEL_HPP_
+#define OTBR_AGENT_NCP_SPINEL_HPP_
+
+#include <functional>
+#include <memory>
+
+#include <openthread/dataset.h>
+#include <openthread/error.h>
+#include <openthread/link.h>
+#include <openthread/thread.h>
+
+#include "lib/spinel/spinel.h"
+#include "lib/spinel/spinel_buffer.hpp"
+#include "lib/spinel/spinel_driver.hpp"
+#include "lib/spinel/spinel_encoder.hpp"
+
+#include "common/task_runner.hpp"
+#include "common/types.hpp"
+#include "ncp/async_task.hpp"
+
+namespace otbr {
+namespace Ncp {
+
+/**
+ * This interface is an observer to subscribe the network properties from NCP.
+ *
+ */
+class PropsObserver
+{
+public:
+    /**
+     * Updates the device role.
+     *
+     * @param[in] aRole  The device role.
+     *
+     */
+    virtual void SetDeviceRole(otDeviceRole aRole) = 0;
+
+    /**
+     * The destructor.
+     *
+     */
+    virtual ~PropsObserver(void) = default;
+};
+
+/**
+ * The class provides methods for controlling the Thread stack on the network co-processor (NCP).
+ *
+ */
+class NcpSpinel
+{
+public:
+    using Ip6AddressTableCallback          = std::function<void(const std::vector<Ip6AddressInfo> &)>;
+    using Ip6MulticastAddressTableCallback = std::function<void(const std::vector<Ip6Address> &)>;
+    using NetifStateChangedCallback        = std::function<void(bool)>;
+
+    /**
+     * Constructor.
+     *
+     */
+    NcpSpinel(void);
+
+    /**
+     * Do the initialization.
+     *
+     * @param[in]  aSpinelDriver   A reference to the SpinelDriver instance that this object depends.
+     * @param[in]  aObserver       A reference to the Network properties observer.
+     *
+     */
+    void Init(ot::Spinel::SpinelDriver &aSpinelDriver, PropsObserver &aObserver);
+
+    /**
+     * Do the de-initialization.
+     *
+     */
+    void Deinit(void);
+
+    /**
+     * Returns the Co-processor version string.
+     *
+     */
+    const char *GetCoprocessorVersion(void) { return mSpinelDriver->GetVersion(); }
+
+    /**
+     * This method sets the active dataset on the NCP.
+     *
+     * If this method is called again before the previous call completed, no action will be taken.
+     * The new receiver @p aAsyncTask will be set a result OT_ERROR_BUSY.
+     *
+     * @param[in] aActiveOpDatasetTlvs  A reference to the active operational dataset of the Thread network.
+     * @param[in] aAsyncTask            A pointer to an async result to receive the result of this operation.
+     *
+     */
+    void DatasetSetActiveTlvs(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, AsyncTaskPtr aAsyncTask);
+
+    /**
+     * This method instructs the NCP to send a MGMT_SET to set Thread Pending Operational Dataset.
+     *
+     * If this method is called again before the previous call completed, no action will be taken.
+     * The new receiver @p aAsyncTask will be set a result OT_ERROR_BUSY.
+     *
+     * @param[in] aPendingOpDatasetTlvsPtr  A shared pointer to the pending operational dataset of the Thread network.
+     * @param[in] aAsyncTask                A pointer to an async result to receive the result of this operation.
+     *
+     */
+    void DatasetMgmtSetPending(std::shared_ptr<otOperationalDatasetTlvs> aPendingOpDatasetTlvsPtr,
+                               AsyncTaskPtr                              aAsyncTask);
+
+    /**
+     * This method enableds/disables the IP6 on the NCP.
+     *
+     * If this method is called again before the previous call completed, no action will be taken.
+     * The new receiver @p aAsyncTask will be set a result OT_ERROR_BUSY.
+     *
+     * @param[in] aEnable     TRUE to enable and FALSE to disable.
+     * @param[in] aAsyncTask  A pointer to an async result to receive the result of this operation.
+     *
+     */
+    void Ip6SetEnabled(bool aEnable, AsyncTaskPtr aAsyncTask);
+
+    /**
+     * This method sets the callback to receive the IPv6 address table from the NCP.
+     *
+     * The callback will be invoked when receiving an IPv6 address table from the NCP. When the
+     * callback is invoked, the callback MUST copy the otIp6AddressInfo objects and maintain it
+     * if it's not used immediately (within the callback).
+     *
+     * @param[in] aCallback  The callback to handle the IP6 address table.
+     *
+     */
+    void Ip6SetAddressCallback(const Ip6AddressTableCallback &aCallback) { mIp6AddressTableCallback = aCallback; }
+
+    /**
+     * This method sets the callback to receive the IPv6 multicast address table from the NCP.
+     *
+     * @param[in] aCallback  The callback to handle the IPv6 address table.
+     *
+     * The callback will be invoked when receiving an IPv6 multicast address table from the NCP.
+     * When the callback is invoked, the callback MUST copy the otIp6Address objects and maintain it
+     * if it's not used immediately (within the callback).
+     *
+     */
+    void Ip6SetAddressMulticastCallback(const Ip6MulticastAddressTableCallback &aCallback)
+    {
+        mIp6MulticastAddressTableCallback = aCallback;
+    }
+
+    /**
+     * This methods sends an IP6 datagram through the NCP.
+     *
+     * @param[in] aData      A pointer to the beginning of the IP6 datagram.
+     * @param[in] aLength    The length of the datagram.
+     *
+     * @retval OTBR_ERROR_NONE  The datagram is sent to NCP successfully.
+     * @retval OTBR_ERROR_BUSY  NcpSpinel is busy with other requests.
+     *
+     */
+    otbrError Ip6Send(const uint8_t *aData, uint16_t aLength);
+
+    /**
+     * This method enableds/disables the Thread network on the NCP.
+     *
+     * If this method is called again before the previous call completed, no action will be taken.
+     * The new receiver @p aAsyncTask will be set a result OT_ERROR_BUSY.
+     *
+     * @param[in] aEnable     TRUE to enable and FALSE to disable.
+     * @param[in] aAsyncTask  A pointer to an async result to receive the result of this operation.
+     *
+     */
+    void ThreadSetEnabled(bool aEnable, AsyncTaskPtr aAsyncTask);
+
+    /**
+     * This method instructs the device to leave the current network gracefully.
+     *
+     * If this method is called again before the previous call completed, no action will be taken.
+     * The new receiver @p aAsyncTask will be set a result OT_ERROR_BUSY.
+     *
+     * @param[in] aAsyncTask  A pointer to an async result to receive the result of this operation.
+     *
+     */
+    void ThreadDetachGracefully(AsyncTaskPtr aAsyncTask);
+
+    /**
+     * This method instructs the NCP to erase the persistent network info.
+     *
+     * If this method is called again before the previous call completed, no action will be taken.
+     * The new receiver @p aAsyncTask will be set a result OT_ERROR_BUSY.
+     *
+     * @param[in] aAsyncTask  A pointer to an async result to receive the result of this operation.
+     *
+     */
+    void ThreadErasePersistentInfo(AsyncTaskPtr aAsyncTask);
+
+    /**
+     * This method sets the callback invoked when the network interface state changes.
+     *
+     * @param[in] aCallback  The callback invoked when the network interface state changes.
+     *
+     */
+    void NetifSetStateChangedCallback(const NetifStateChangedCallback &aCallback)
+    {
+        mNetifStateChangedCallback = aCallback;
+    }
+
+private:
+    using FailureHandler = std::function<void(otError)>;
+
+    static constexpr uint8_t kMaxTids = 16;
+
+    template <typename Function, typename... Args> static void SafeInvoke(Function &aFunc, Args &&...aArgs)
+    {
+        if (aFunc)
+        {
+            aFunc(std::forward<Args>(aArgs)...);
+        }
+    }
+
+    static void CallAndClear(AsyncTaskPtr &aResult, otError aError, const std::string &aErrorInfo = "")
+    {
+        if (aResult)
+        {
+            aResult->SetResult(aError, aErrorInfo);
+            aResult = nullptr;
+        }
+    }
+
+    static otbrError SpinelDataUnpack(const uint8_t *aDataIn, spinel_size_t aDataLen, const char *aPackFormat, ...);
+
+    static void HandleReceivedFrame(const uint8_t *aFrame,
+                                    uint16_t       aLength,
+                                    uint8_t        aHeader,
+                                    bool          &aSave,
+                                    void          *aContext);
+    void        HandleReceivedFrame(const uint8_t *aFrame, uint16_t aLength, uint8_t aHeader, bool &aShouldSaveFrame);
+    static void HandleSavedFrame(const uint8_t *aFrame, uint16_t aLength, void *aContext);
+
+    static otDeviceRole SpinelRoleToDeviceRole(spinel_net_role_t aRole);
+
+    void      HandleNotification(const uint8_t *aFrame, uint16_t aLength);
+    void      HandleResponse(spinel_tid_t aTid, const uint8_t *aFrame, uint16_t aLength);
+    void      HandleValueIs(spinel_prop_key_t aKey, const uint8_t *aBuffer, uint16_t aLength);
+    otbrError HandleResponseForPropSet(spinel_tid_t      aTid,
+                                       spinel_prop_key_t aKey,
+                                       const uint8_t    *aData,
+                                       uint16_t          aLength);
+
+    spinel_tid_t GetNextTid(void);
+    void         FreeTidTableItem(spinel_tid_t aTid);
+
+    using EncodingFunc = std::function<otError(void)>;
+    otError SetProperty(spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc);
+    otError SendEncodedFrame(void);
+
+    otError ParseIp6AddressTable(const uint8_t *aBuf, uint16_t aLength, std::vector<Ip6AddressInfo> &aAddressTable);
+    otError ParseIp6MulticastAddresses(const uint8_t *aBuf, uint8_t aLen, std::vector<Ip6Address> &aAddressList);
+
+    ot::Spinel::SpinelDriver *mSpinelDriver;
+    uint16_t                  mCmdTidsInUse; ///< Used transaction ids.
+    spinel_tid_t              mCmdNextTid;   ///< Next available transaction id.
+
+    spinel_prop_key_t mWaitingKeyTable[kMaxTids]; ///< The property keys of ongoing transactions.
+    spinel_command_t  mCmdTable[kMaxTids];        ///< The mapping of spinel command and tids when the response
+                                                  ///< is LAST_STATUS.
+
+    static constexpr uint16_t kTxBufferSize = 2048;
+    uint8_t                   mTxBuffer[kTxBufferSize];
+    ot::Spinel::Buffer        mNcpBuffer;
+    ot::Spinel::Encoder       mEncoder;
+    spinel_iid_t              mIid; /// < Interface Id used to in Spinel header
+
+    TaskRunner mTaskRunner;
+
+    PropsObserver *mPropsObserver;
+
+    AsyncTaskPtr mDatasetSetActiveTask;
+    AsyncTaskPtr mDatasetMgmtSetPendingTask;
+    AsyncTaskPtr mIp6SetEnabledTask;
+    AsyncTaskPtr mThreadSetEnabledTask;
+    AsyncTaskPtr mThreadDetachGracefullyTask;
+    AsyncTaskPtr mThreadErasePersistentInfoTask;
+
+    Ip6AddressTableCallback          mIp6AddressTableCallback;
+    Ip6MulticastAddressTableCallback mIp6MulticastAddressTableCallback;
+    NetifStateChangedCallback        mNetifStateChangedCallback;
+};
+
+} // namespace Ncp
+} // namespace otbr
+
+#endif // OTBR_AGENT_NCP_SPINEL_HPP_
diff --git a/tests/unit/CMakeLists.txt b/src/ncp/posix/CMakeLists.txt
similarity index 68%
rename from tests/unit/CMakeLists.txt
rename to src/ncp/posix/CMakeLists.txt
index 784f859e..1f03fd3c 100644
--- a/tests/unit/CMakeLists.txt
+++ b/src/ncp/posix/CMakeLists.txt
@@ -1,5 +1,5 @@
 #
-#  Copyright (c) 2020, The OpenThread Authors.
+#  Copyright (c) 2024, The OpenThread Authors.
 #  All rights reserved.
 #
 #  Redistribution and use in source and binary forms, with or without
@@ -26,30 +26,14 @@
 #  POSSIBILITY OF SUCH DAMAGE.
 #
 
-add_executable(otbr-test-unit
-    $<$<BOOL:${OTBR_DBUS}>:test_dbus_message.cpp>
-    $<$<STREQUAL:${OTBR_MDNS},"mDNSResponder">:test_mdns_mdnssd.cpp>
-    main.cpp
-    test_dns_utils.cpp
-    test_logging.cpp
-    test_once_callback.cpp
-    test_pskc.cpp
-    test_task_runner.cpp
+add_library(otbr-posix
+    netif.cpp
+    netif_linux.cpp
+    netif_unix.cpp
+    netif.hpp
 )
-target_include_directories(otbr-test-unit PRIVATE
-    ${CPPUTEST_INCLUDE_DIRS}
-)
-target_link_libraries(otbr-test-unit
-    $<$<BOOL:${OTBR_DBUS}>:otbr-dbus-common>
-    $<$<STREQUAL:${OTBR_MDNS},"mDNSResponder">:otbr-mdns>
-    $<$<BOOL:${CPPUTEST_LIBRARY_DIRS}>:-L$<JOIN:${CPPUTEST_LIBRARY_DIRS}," -L">>
-    ${CPPUTEST_LIBRARIES}
-    mbedtls
+
+target_link_libraries(otbr-posix
     otbr-common
     otbr-utils
-    pthread
-)
-add_test(
-    NAME unit
-    COMMAND otbr-test-unit
 )
diff --git a/src/ncp/posix/netif.cpp b/src/ncp/posix/netif.cpp
new file mode 100644
index 00000000..89018d2d
--- /dev/null
+++ b/src/ncp/posix/netif.cpp
@@ -0,0 +1,296 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#define OTBR_LOG_TAG "NETIF"
+
+#include "netif.hpp"
+
+#include <errno.h>
+#include <fcntl.h>
+#include <net/if.h>
+#include <net/if_arp.h>
+#include <netinet/in.h>
+#include <stdio.h>
+#include <string.h>
+#include <sys/ioctl.h>
+#include <sys/socket.h>
+#include <unistd.h>
+
+#include <algorithm>
+
+#include "common/code_utils.hpp"
+#include "common/logging.hpp"
+#include "common/types.hpp"
+#include "utils/socket_utils.hpp"
+
+namespace otbr {
+
+Netif::Netif(void)
+    : mTunFd(-1)
+    , mIpFd(-1)
+    , mNetlinkFd(-1)
+    , mNetlinkSequence(0)
+    , mNetifIndex(0)
+{
+}
+
+otbrError Netif::Init(const std::string &aInterfaceName, const Ip6SendFunc &aIp6SendFunc)
+{
+    otbrError error = OTBR_ERROR_NONE;
+
+    VerifyOrExit(aIp6SendFunc, error = OTBR_ERROR_INVALID_ARGS);
+    mIp6SendFunc = aIp6SendFunc;
+
+    mIpFd = SocketWithCloseExec(AF_INET6, SOCK_DGRAM, IPPROTO_IP, kSocketNonBlock);
+    VerifyOrExit(mIpFd >= 0, error = OTBR_ERROR_ERRNO);
+
+    SuccessOrExit(error = CreateTunDevice(aInterfaceName));
+    SuccessOrExit(error = InitNetlink());
+
+    mNetifIndex = if_nametoindex(mNetifName.c_str());
+    VerifyOrExit(mNetifIndex > 0, error = OTBR_ERROR_INVALID_STATE);
+
+    PlatformSpecificInit();
+
+exit:
+    if (error != OTBR_ERROR_NONE)
+    {
+        Clear();
+    }
+    return error;
+}
+
+void Netif::Deinit(void)
+{
+    Clear();
+}
+
+void Netif::Process(const MainloopContext *aContext)
+{
+    if (FD_ISSET(mTunFd, &aContext->mErrorFdSet))
+    {
+        close(mTunFd);
+        DieNow("Error on Tun Fd!");
+    }
+
+    if (FD_ISSET(mTunFd, &aContext->mReadFdSet))
+    {
+        ProcessIp6Send();
+    }
+}
+
+void Netif::UpdateFdSet(MainloopContext *aContext)
+{
+    assert(aContext != nullptr);
+    assert(mTunFd >= 0);
+    assert(mIpFd >= 0);
+
+    aContext->AddFdToSet(mTunFd, MainloopContext::kErrorFdSet | MainloopContext::kReadFdSet);
+}
+
+void Netif::UpdateIp6UnicastAddresses(const std::vector<Ip6AddressInfo> &aAddrInfos)
+{
+    // Remove stale addresses
+    for (const Ip6AddressInfo &addrInfo : mIp6UnicastAddresses)
+    {
+        if (std::find(aAddrInfos.begin(), aAddrInfos.end(), addrInfo) == aAddrInfos.end())
+        {
+            otbrLogInfo("Remove address: %s", Ip6Address(addrInfo.mAddress).ToString().c_str());
+            // TODO: Verify success of the addition or deletion in Netlink response.
+            ProcessUnicastAddressChange(addrInfo, false);
+        }
+    }
+
+    // Add new addresses
+    for (const Ip6AddressInfo &addrInfo : aAddrInfos)
+    {
+        if (std::find(mIp6UnicastAddresses.begin(), mIp6UnicastAddresses.end(), addrInfo) == mIp6UnicastAddresses.end())
+        {
+            otbrLogInfo("Add address: %s", Ip6Address(addrInfo.mAddress).ToString().c_str());
+            // TODO: Verify success of the addition or deletion in Netlink response.
+            ProcessUnicastAddressChange(addrInfo, true);
+        }
+    }
+
+    mIp6UnicastAddresses.assign(aAddrInfos.begin(), aAddrInfos.end());
+}
+
+otbrError Netif::UpdateIp6MulticastAddresses(const std::vector<Ip6Address> &aAddrs)
+{
+    otbrError error = OTBR_ERROR_NONE;
+
+    // Remove stale addresses
+    for (const Ip6Address &address : mIp6MulticastAddresses)
+    {
+        if (std::find(aAddrs.begin(), aAddrs.end(), address) == aAddrs.end())
+        {
+            otbrLogInfo("Remove address: %s", Ip6Address(address).ToString().c_str());
+            SuccessOrExit(error = ProcessMulticastAddressChange(address, /* aIsAdded */ false));
+        }
+    }
+
+    // Add new addresses
+    for (const Ip6Address &address : aAddrs)
+    {
+        if (std::find(mIp6MulticastAddresses.begin(), mIp6MulticastAddresses.end(), address) ==
+            mIp6MulticastAddresses.end())
+        {
+            otbrLogInfo("Add address: %s", Ip6Address(address).ToString().c_str());
+            SuccessOrExit(error = ProcessMulticastAddressChange(address, /* aIsAdded */ true));
+        }
+    }
+
+    mIp6MulticastAddresses.assign(aAddrs.begin(), aAddrs.end());
+
+exit:
+    if (error != OTBR_ERROR_NONE)
+    {
+        mIp6MulticastAddresses.clear();
+    }
+    return error;
+}
+
+otbrError Netif::ProcessMulticastAddressChange(const Ip6Address &aAddress, bool aIsAdded)
+{
+    struct ipv6_mreq mreq;
+    otbrError        error = OTBR_ERROR_NONE;
+    int              err;
+
+    VerifyOrExit(mIpFd >= 0, error = OTBR_ERROR_INVALID_STATE);
+    memcpy(&mreq.ipv6mr_multiaddr, &aAddress, sizeof(mreq.ipv6mr_multiaddr));
+    mreq.ipv6mr_interface = mNetifIndex;
+
+    err = setsockopt(mIpFd, IPPROTO_IPV6, (aIsAdded ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP), &mreq, sizeof(mreq));
+
+    if (err != 0)
+    {
+        otbrLogWarning("%s failure (%d)", aIsAdded ? "IPV6_JOIN_GROUP" : "IPV6_LEAVE_GROUP", errno);
+        ExitNow(error = OTBR_ERROR_ERRNO);
+    }
+
+    otbrLogInfo("%s multicast address %s", aIsAdded ? "Added" : "Removed", Ip6Address(aAddress).ToString().c_str());
+
+exit:
+    return error;
+}
+
+void Netif::SetNetifState(bool aState)
+{
+    otbrError    error = OTBR_ERROR_NONE;
+    struct ifreq ifr;
+    bool         ifState = false;
+
+    VerifyOrExit(mIpFd >= 0);
+    memset(&ifr, 0, sizeof(ifr));
+    strncpy(ifr.ifr_name, mNetifName.c_str(), IFNAMSIZ - 1);
+    VerifyOrExit(ioctl(mIpFd, SIOCGIFFLAGS, &ifr) == 0, error = OTBR_ERROR_ERRNO);
+
+    ifState = ((ifr.ifr_flags & IFF_UP) == IFF_UP) ? true : false;
+
+    otbrLogInfo("Changing interface state to %s%s.", aState ? "up" : "down",
+                (ifState == aState) ? " (already done, ignoring)" : "");
+
+    if (ifState != aState)
+    {
+        ifr.ifr_flags = aState ? (ifr.ifr_flags | IFF_UP) : (ifr.ifr_flags & ~IFF_UP);
+        VerifyOrExit(ioctl(mIpFd, SIOCSIFFLAGS, &ifr) == 0, error = OTBR_ERROR_ERRNO);
+    }
+
+exit:
+    if (error != OTBR_ERROR_NONE)
+    {
+        otbrLogWarning("Failed to update state %s", otbrErrorString(error));
+    }
+}
+
+void Netif::Ip6Receive(const uint8_t *aBuf, uint16_t aLen)
+{
+    otbrError error = OTBR_ERROR_NONE;
+
+    VerifyOrExit(aLen <= kIp6Mtu, error = OTBR_ERROR_DROPPED);
+    VerifyOrExit(mTunFd > 0, error = OTBR_ERROR_INVALID_STATE);
+
+    otbrLogInfo("Packet from NCP (%u bytes)", aLen);
+    VerifyOrExit(write(mTunFd, aBuf, aLen) == aLen, error = OTBR_ERROR_ERRNO);
+
+exit:
+    if (error != OTBR_ERROR_NONE)
+    {
+        otbrLogWarning("Failed to receive, error:%s", otbrErrorString(error));
+    }
+}
+
+void Netif::ProcessIp6Send(void)
+{
+    ssize_t   rval;
+    uint8_t   packet[kIp6Mtu];
+    otbrError error = OTBR_ERROR_NONE;
+
+    rval = read(mTunFd, packet, sizeof(packet));
+    VerifyOrExit(rval > 0, error = OTBR_ERROR_ERRNO);
+
+    otbrLogInfo("Send packet (%hu bytes)", static_cast<uint16_t>(rval));
+
+    if (mIp6SendFunc != nullptr)
+    {
+        error = mIp6SendFunc(packet, rval);
+    }
+exit:
+    if (error == OTBR_ERROR_ERRNO)
+    {
+        otbrLogInfo("Error reading from Tun Fd: %s", strerror(errno));
+    }
+}
+
+void Netif::Clear(void)
+{
+    if (mTunFd != -1)
+    {
+        close(mTunFd);
+        mTunFd = -1;
+    }
+
+    if (mIpFd != -1)
+    {
+        close(mIpFd);
+        mIpFd = -1;
+    }
+
+    if (mNetlinkFd != -1)
+    {
+        close(mNetlinkFd);
+        mNetlinkFd = -1;
+    }
+
+    mNetifIndex = 0;
+    mIp6UnicastAddresses.clear();
+    mIp6MulticastAddresses.clear();
+    mIp6SendFunc = nullptr;
+}
+
+} // namespace otbr
diff --git a/src/ncp/posix/netif.hpp b/src/ncp/posix/netif.hpp
new file mode 100644
index 00000000..4f110833
--- /dev/null
+++ b/src/ncp/posix/netif.hpp
@@ -0,0 +1,97 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+/**
+ * @file
+ *   This file includes definitions of the posix Netif of otbr-agent.
+ */
+
+#ifndef OTBR_AGENT_POSIX_NETIF_HPP_
+#define OTBR_AGENT_POSIX_NETIF_HPP_
+
+#include <net/if.h>
+
+#include <functional>
+#include <vector>
+
+#include <openthread/ip6.h>
+
+#include "common/mainloop.hpp"
+#include "common/types.hpp"
+
+namespace otbr {
+
+class Netif
+{
+public:
+    using Ip6SendFunc = std::function<otbrError(const uint8_t *, uint16_t)>;
+
+    Netif(void);
+
+    otbrError Init(const std::string &aInterfaceName, const Ip6SendFunc &aIp6SendFunc);
+    void      Deinit(void);
+
+    void      Process(const MainloopContext *aContext);
+    void      UpdateFdSet(MainloopContext *aContext);
+    void      UpdateIp6UnicastAddresses(const std::vector<Ip6AddressInfo> &aAddrInfos);
+    otbrError UpdateIp6MulticastAddresses(const std::vector<Ip6Address> &aAddrs);
+    void      SetNetifState(bool aState);
+
+    void Ip6Receive(const uint8_t *aBuf, uint16_t aLen);
+
+private:
+    // TODO: Retrieve the Maximum Ip6 size from the coprocessor.
+    static constexpr size_t kIp6Mtu = 1280;
+
+    void Clear(void);
+
+    otbrError CreateTunDevice(const std::string &aInterfaceName);
+    otbrError InitNetlink(void);
+
+    void      PlatformSpecificInit(void);
+    void      SetAddrGenModeToNone(void);
+    void      ProcessUnicastAddressChange(const Ip6AddressInfo &aAddressInfo, bool aIsAdded);
+    otbrError ProcessMulticastAddressChange(const Ip6Address &aAddress, bool aIsAdded);
+    void      ProcessIp6Send(void);
+
+    int      mTunFd;           ///< Used to exchange IPv6 packets.
+    int      mIpFd;            ///< Used to manage IPv6 stack on the network interface.
+    int      mNetlinkFd;       ///< Used to receive netlink events.
+    uint32_t mNetlinkSequence; ///< Netlink message sequence.
+
+    unsigned int mNetifIndex;
+    std::string  mNetifName;
+
+    std::vector<Ip6AddressInfo> mIp6UnicastAddresses;
+    std::vector<Ip6Address>     mIp6MulticastAddresses;
+    Ip6SendFunc                 mIp6SendFunc;
+};
+
+} // namespace otbr
+
+#endif // OTBR_AGENT_POSIX_NETIF_HPP_
diff --git a/src/ncp/posix/netif_linux.cpp b/src/ncp/posix/netif_linux.cpp
new file mode 100644
index 00000000..37db5d8d
--- /dev/null
+++ b/src/ncp/posix/netif_linux.cpp
@@ -0,0 +1,248 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#ifdef __linux__
+
+#define OTBR_LOG_TAG "NETIF"
+
+#include "netif.hpp"
+
+#include <assert.h>
+#include <fcntl.h>
+#include <linux/if.h>
+#include <linux/if_tun.h>
+#include <linux/netlink.h>
+#include <linux/rtnetlink.h>
+#include <net/if.h>
+#include <net/if_arp.h>
+#include <sys/ioctl.h>
+#include <unistd.h>
+
+#include "common/code_utils.hpp"
+#include "common/logging.hpp"
+#include "common/types.hpp"
+#include "utils/socket_utils.hpp"
+
+#ifndef OTBR_POSIX_TUN_DEVICE
+#define OTBR_POSIX_TUN_DEVICE "/dev/net/tun"
+#endif
+
+namespace otbr {
+
+static struct rtattr *AddRtAttr(nlmsghdr *aHeader, uint32_t aMaxLen, uint8_t aType, const void *aData, uint8_t aLen)
+{
+    uint8_t len = RTA_LENGTH(aLen);
+    rtattr *rta;
+
+    assert(NLMSG_ALIGN(aHeader->nlmsg_len) + RTA_ALIGN(len) <= aMaxLen);
+    OTBR_UNUSED_VARIABLE(aMaxLen);
+
+    rta           = reinterpret_cast<rtattr *>(reinterpret_cast<char *>(aHeader) + NLMSG_ALIGN((aHeader)->nlmsg_len));
+    rta->rta_type = aType;
+    rta->rta_len  = len;
+    if (aLen)
+    {
+        memcpy(RTA_DATA(rta), aData, aLen);
+    }
+    aHeader->nlmsg_len = NLMSG_ALIGN(aHeader->nlmsg_len) + RTA_ALIGN(len);
+
+    return rta;
+}
+
+otbrError Netif::CreateTunDevice(const std::string &aInterfaceName)
+{
+    ifreq     ifr;
+    otbrError error = OTBR_ERROR_NONE;
+
+    VerifyOrExit(aInterfaceName.size() < IFNAMSIZ, error = OTBR_ERROR_INVALID_ARGS);
+
+    memset(&ifr, 0, sizeof(ifr));
+    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
+    if (aInterfaceName.size() > 0)
+    {
+        strncpy(ifr.ifr_name, aInterfaceName.c_str(), aInterfaceName.size());
+    }
+    else
+    {
+        strncpy(ifr.ifr_name, "wpan%d", IFNAMSIZ);
+    }
+
+    mTunFd = open(OTBR_POSIX_TUN_DEVICE, O_RDWR | O_CLOEXEC | O_NONBLOCK);
+    VerifyOrExit(mTunFd >= 0, error = OTBR_ERROR_ERRNO);
+
+    VerifyOrExit(ioctl(mTunFd, TUNSETIFF, &ifr) == 0, error = OTBR_ERROR_ERRNO);
+
+    mNetifName.assign(ifr.ifr_name, strlen(ifr.ifr_name));
+    otbrLogInfo("Netif name: %s", mNetifName.c_str());
+
+    VerifyOrExit(ioctl(mTunFd, TUNSETLINK, ARPHRD_NONE) == 0, error = OTBR_ERROR_ERRNO);
+
+    ifr.ifr_mtu = static_cast<int>(kIp6Mtu);
+    VerifyOrExit(ioctl(mIpFd, SIOCSIFMTU, &ifr) == 0, error = OTBR_ERROR_ERRNO);
+
+exit:
+    return error;
+}
+
+otbrError Netif::InitNetlink(void)
+{
+    otbrError error = OTBR_ERROR_NONE;
+
+    mNetlinkFd = SocketWithCloseExec(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE, kSocketNonBlock);
+    VerifyOrExit(mNetlinkFd >= 0, error = OTBR_ERROR_ERRNO);
+
+#if defined(SOL_NETLINK)
+    {
+        int enable = 1;
+
+#if defined(NETLINK_EXT_ACK)
+        if (setsockopt(mNetlinkFd, SOL_NETLINK, NETLINK_EXT_ACK, &enable, sizeof(enable)) != 0)
+        {
+            otbrLogWarning("Failed to enable NETLINK_EXT_ACK: %s", strerror(errno));
+        }
+#endif
+#if defined(NETLINK_CAP_ACK)
+        if (setsockopt(mNetlinkFd, SOL_NETLINK, NETLINK_CAP_ACK, &enable, sizeof(enable)) != 0)
+        {
+            otbrLogWarning("Failed to enable NETLINK_CAP_ACK: %s", strerror(errno));
+        }
+#endif
+    }
+#endif
+
+    {
+        sockaddr_nl sa;
+
+        memset(&sa, 0, sizeof(sa));
+        sa.nl_family = AF_NETLINK;
+        sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV6_IFADDR;
+        VerifyOrExit(bind(mNetlinkFd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) == 0, error = OTBR_ERROR_ERRNO);
+    }
+
+exit:
+    return error;
+}
+
+void Netif::PlatformSpecificInit(void)
+{
+    SetAddrGenModeToNone();
+}
+
+void Netif::SetAddrGenModeToNone(void)
+{
+    struct
+    {
+        nlmsghdr  nh;
+        ifinfomsg ifi;
+        char      buf[512];
+    } req;
+
+    const uint8_t mode = IN6_ADDR_GEN_MODE_NONE;
+
+    memset(&req, 0, sizeof(req));
+
+    req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(ifinfomsg));
+    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
+    req.nh.nlmsg_type  = RTM_NEWLINK;
+    req.nh.nlmsg_pid   = 0;
+    req.nh.nlmsg_seq   = ++mNetlinkSequence;
+
+    req.ifi.ifi_index  = static_cast<int>(mNetifIndex);
+    req.ifi.ifi_change = 0xffffffff;
+    req.ifi.ifi_flags  = IFF_MULTICAST | IFF_NOARP;
+
+    {
+        rtattr *afSpec           = AddRtAttr(&req.nh, sizeof(req), IFLA_AF_SPEC, 0, 0);
+        rtattr *afInet6          = AddRtAttr(&req.nh, sizeof(req), AF_INET6, 0, 0);
+        rtattr *inet6AddrGenMode = AddRtAttr(&req.nh, sizeof(req), IFLA_INET6_ADDR_GEN_MODE, &mode, sizeof(mode));
+
+        afInet6->rta_len += inet6AddrGenMode->rta_len;
+        afSpec->rta_len += afInet6->rta_len;
+    }
+
+    if (send(mNetlinkFd, &req, req.nh.nlmsg_len, 0) != -1)
+    {
+        otbrLogInfo("Sent request#%u to set addr_gen_mode to %d", mNetlinkSequence, mode);
+    }
+    else
+    {
+        otbrLogWarning("Failed to send request#%u to set addr_gen_mode to %d", mNetlinkSequence, mode);
+    }
+}
+
+void Netif::ProcessUnicastAddressChange(const Ip6AddressInfo &aAddressInfo, bool aIsAdded)
+{
+    struct
+    {
+        nlmsghdr  nh;
+        ifaddrmsg ifa;
+        char      buf[512];
+    } req;
+
+    assert(mIpFd >= 0);
+    memset(&req, 0, sizeof(req));
+
+    req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(ifaddrmsg));
+    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (aIsAdded ? (NLM_F_CREATE | NLM_F_EXCL) : 0);
+    req.nh.nlmsg_type  = aIsAdded ? RTM_NEWADDR : RTM_DELADDR;
+    req.nh.nlmsg_pid   = 0;
+    req.nh.nlmsg_seq   = ++mNetlinkSequence;
+
+    req.ifa.ifa_family    = AF_INET6;
+    req.ifa.ifa_prefixlen = aAddressInfo.mPrefixLength;
+    req.ifa.ifa_flags     = IFA_F_NODAD;
+    req.ifa.ifa_scope     = aAddressInfo.mScope;
+    req.ifa.ifa_index     = mNetifIndex;
+
+    AddRtAttr(&req.nh, sizeof(req), IFA_LOCAL, &aAddressInfo.mAddress, sizeof(aAddressInfo.mAddress));
+
+    if (!aAddressInfo.mPreferred || aAddressInfo.mMeshLocal)
+    {
+        ifa_cacheinfo cacheinfo;
+
+        memset(&cacheinfo, 0, sizeof(cacheinfo));
+        cacheinfo.ifa_valid = UINT32_MAX;
+
+        AddRtAttr(&req.nh, sizeof(req), IFA_CACHEINFO, &cacheinfo, sizeof(cacheinfo));
+    }
+
+    if (send(mNetlinkFd, &req, req.nh.nlmsg_len, 0) != -1)
+    {
+        otbrLogInfo("Sent request#%u to %s %s/%u", mNetlinkSequence, (aIsAdded ? "add" : "remove"),
+                    Ip6Address(aAddressInfo.mAddress).ToString().c_str(), aAddressInfo.mPrefixLength);
+    }
+    else
+    {
+        otbrLogWarning("Failed to send request#%u to %s %s/%u", mNetlinkSequence, (aIsAdded ? "add" : "remove"),
+                       Ip6Address(aAddressInfo.mAddress).ToString().c_str(), aAddressInfo.mPrefixLength);
+    }
+}
+
+} // namespace otbr
+
+#endif // __linux__
diff --git a/src/ncp/posix/netif_unix.cpp b/src/ncp/posix/netif_unix.cpp
new file mode 100644
index 00000000..7a7a4987
--- /dev/null
+++ b/src/ncp/posix/netif_unix.cpp
@@ -0,0 +1,69 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#if defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
+
+#define OTBR_LOG_TAG "NETIF"
+
+#include "netif.hpp"
+
+#include "common/code_utils.hpp"
+
+namespace otbr {
+
+// TODO: implement platform netif functionalities on unix platforms: APPLE, NetBSD, OpenBSD
+//
+// Currently we let otbr-agent can be compiled on unix platforms and can work under RCP mode
+// but NCP mode cannot be used on unix platforms. It will crash at code here.
+
+otbrError Netif::CreateTunDevice(const std::string &aInterfaceName)
+{
+    OTBR_UNUSED_VARIABLE(aInterfaceName);
+    DieNow("OTBR posix not supported on this platform");
+    return OTBR_ERROR_NONE;
+}
+
+otbrError Netif::InitNetlink(void)
+{
+    return OTBR_ERROR_NONE;
+}
+
+void Netif::PlatformSpecificInit(void)
+{
+    /* Empty */
+}
+
+void Netif::ProcessUnicastAddressChange(const Ip6AddressInfo &aAddressInfo, bool aIsAdded)
+{
+    OTBR_UNUSED_VARIABLE(aAddressInfo);
+    OTBR_UNUSED_VARIABLE(aIsAdded);
+}
+
+} // namespace otbr
+
+#endif // __APPLE__ || __NetBSD__ || __OpenBSD__
diff --git a/src/ncp/ncp_openthread.cpp b/src/ncp/rcp_host.cpp
similarity index 74%
rename from src/ncp/ncp_openthread.cpp
rename to src/ncp/rcp_host.cpp
index df3dcd5f..97d6c730 100644
--- a/src/ncp/ncp_openthread.cpp
+++ b/src/ncp/rcp_host.cpp
@@ -26,9 +26,9 @@
  *    POSSIBILITY OF SUCH DAMAGE.
  */
 
-#define OTBR_LOG_TAG "NCP"
+#define OTBR_LOG_TAG "RCP_HOST"
 
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 
 #include <assert.h>
 #include <stdio.h>
@@ -38,6 +38,7 @@
 #include <openthread/border_routing.h>
 #include <openthread/dataset.h>
 #include <openthread/dnssd_server.h>
+#include <openthread/link_metrics.h>
 #include <openthread/logging.h>
 #include <openthread/nat64.h>
 #include <openthread/srp_server.h>
@@ -65,11 +66,30 @@ static const uint16_t kThreadVersion12 = 3; ///< Thread Version 1.2
 static const uint16_t kThreadVersion13 = 4; ///< Thread Version 1.3
 static const uint16_t kThreadVersion14 = 5; ///< Thread Version 1.4
 
-ControllerOpenThread::ControllerOpenThread(const char                      *aInterfaceName,
-                                           const std::vector<const char *> &aRadioUrls,
-                                           const char                      *aBackboneInterfaceName,
-                                           bool                             aDryRun,
-                                           bool                             aEnableAutoAttach)
+// =============================== OtNetworkProperties ===============================
+
+OtNetworkProperties::OtNetworkProperties(void)
+    : mInstance(nullptr)
+{
+}
+
+otDeviceRole OtNetworkProperties::GetDeviceRole(void) const
+{
+    return otThreadGetDeviceRole(mInstance);
+}
+
+void OtNetworkProperties::SetInstance(otInstance *aInstance)
+{
+    mInstance = aInstance;
+}
+
+// =============================== RcpHost ===============================
+
+RcpHost::RcpHost(const char                      *aInterfaceName,
+                 const std::vector<const char *> &aRadioUrls,
+                 const char                      *aBackboneInterfaceName,
+                 bool                             aDryRun,
+                 bool                             aEnableAutoAttach)
     : mInstance(nullptr)
     , mEnableAutoAttach(aEnableAutoAttach)
 {
@@ -83,18 +103,18 @@ ControllerOpenThread::ControllerOpenThread(const char                      *aInt
 
     for (const char *url : aRadioUrls)
     {
-        mConfig.mRadioUrls[mConfig.mRadioUrlNum++] = url;
+        mConfig.mCoprocessorUrls.mUrls[mConfig.mCoprocessorUrls.mNum++] = url;
     }
     mConfig.mSpeedUpFactor = 1;
 }
 
-ControllerOpenThread::~ControllerOpenThread(void)
+RcpHost::~RcpHost(void)
 {
     // Make sure OpenThread Instance was gracefully de-initialized.
     assert(mInstance == nullptr);
 }
 
-otbrLogLevel ControllerOpenThread::ConvertToOtbrLogLevel(otLogLevel aLogLevel)
+otbrLogLevel RcpHost::ConvertToOtbrLogLevel(otLogLevel aLogLevel)
 {
     otbrLogLevel otbrLogLevel;
 
@@ -163,37 +183,7 @@ otbrLogLevel ConvertProtoToOtbrLogLevel(ProtoLogLevel aProtoLogLevel)
 }
 #endif
 
-otLogLevel ControllerOpenThread::ConvertToOtLogLevel(otbrLogLevel aLevel)
-{
-    otLogLevel level;
-
-    switch (aLevel)
-    {
-    case OTBR_LOG_EMERG:
-    case OTBR_LOG_ALERT:
-    case OTBR_LOG_CRIT:
-        level = OT_LOG_LEVEL_CRIT;
-        break;
-    case OTBR_LOG_ERR:
-    case OTBR_LOG_WARNING:
-        level = OT_LOG_LEVEL_WARN;
-        break;
-    case OTBR_LOG_NOTICE:
-        level = OT_LOG_LEVEL_NOTE;
-        break;
-    case OTBR_LOG_INFO:
-        level = OT_LOG_LEVEL_INFO;
-        break;
-    case OTBR_LOG_DEBUG:
-    default:
-        level = OT_LOG_LEVEL_DEBG;
-        break;
-    }
-
-    return level;
-}
-
-otError ControllerOpenThread::SetOtbrAndOtLogLevel(otbrLogLevel aLevel)
+otError RcpHost::SetOtbrAndOtLogLevel(otbrLogLevel aLevel)
 {
     otError error = OT_ERROR_NONE;
     otbrLogSetLevel(aLevel);
@@ -201,7 +191,7 @@ otError ControllerOpenThread::SetOtbrAndOtLogLevel(otbrLogLevel aLevel)
     return error;
 }
 
-void ControllerOpenThread::Init(void)
+void RcpHost::Init(void)
 {
     otbrError  error = OTBR_ERROR_NONE;
     otLogLevel level = ConvertToOtLogLevel(otbrLogGetLevel());
@@ -216,7 +206,7 @@ void ControllerOpenThread::Init(void)
     assert(mInstance != nullptr);
 
     {
-        otError result = otSetStateChangedCallback(mInstance, &ControllerOpenThread::HandleStateChanged, this);
+        otError result = otSetStateChangedCallback(mInstance, &RcpHost::HandleStateChanged, this);
 
         agent::ThreadHelper::LogOpenThreadResult("Set state callback", result);
         VerifyOrExit(result == OT_ERROR_NONE, error = OTBR_ERROR_OPENTHREAD);
@@ -250,14 +240,16 @@ void ControllerOpenThread::Init(void)
 #endif
 #endif // OTBR_ENABLE_FEATURE_FLAGS
 
-    mThreadHelper = std::unique_ptr<otbr::agent::ThreadHelper>(new otbr::agent::ThreadHelper(mInstance, this));
+    mThreadHelper = MakeUnique<otbr::agent::ThreadHelper>(mInstance, this);
+
+    OtNetworkProperties::SetInstance(mInstance);
 
 exit:
-    SuccessOrDie(error, "Failed to initialize NCP!");
+    SuccessOrDie(error, "Failed to initialize the RCP Host!");
 }
 
 #if OTBR_ENABLE_FEATURE_FLAGS
-otError ControllerOpenThread::ApplyFeatureFlagList(const FeatureFlagList &aFeatureFlagList)
+otError RcpHost::ApplyFeatureFlagList(const FeatureFlagList &aFeatureFlagList)
 {
     otError error = OT_ERROR_NONE;
     // Save a cached copy of feature flags for debugging purpose.
@@ -285,23 +277,27 @@ otError ControllerOpenThread::ApplyFeatureFlagList(const FeatureFlagList &aFeatu
 #if OTBR_ENABLE_DHCP6_PD
     otBorderRoutingDhcp6PdSetEnabled(mInstance, aFeatureFlagList.enable_dhcp6_pd());
 #endif
+#if OTBR_ENABLE_LINK_METRICS_TELEMETRY
+    otLinkMetricsManagerSetEnabled(mInstance, aFeatureFlagList.enable_link_metrics_manager());
+#endif
 
     return error;
 }
 #endif
 
-void ControllerOpenThread::Deinit(void)
+void RcpHost::Deinit(void)
 {
     assert(mInstance != nullptr);
 
     otSysDeinit();
     mInstance = nullptr;
 
+    OtNetworkProperties::SetInstance(nullptr);
     mThreadStateChangedCallbacks.clear();
     mResetHandlers.clear();
 }
 
-void ControllerOpenThread::HandleStateChanged(otChangedFlags aFlags)
+void RcpHost::HandleStateChanged(otChangedFlags aFlags)
 {
     for (auto &stateCallback : mThreadStateChangedCallbacks)
     {
@@ -311,7 +307,7 @@ void ControllerOpenThread::HandleStateChanged(otChangedFlags aFlags)
     mThreadHelper->StateChangedCallback(aFlags);
 }
 
-void ControllerOpenThread::Update(MainloopContext &aMainloop)
+void RcpHost::Update(MainloopContext &aMainloop)
 {
     if (otTaskletsArePending(mInstance))
     {
@@ -321,7 +317,7 @@ void ControllerOpenThread::Update(MainloopContext &aMainloop)
     otSysMainloopUpdate(mInstance, &aMainloop);
 }
 
-void ControllerOpenThread::Process(const MainloopContext &aMainloop)
+void RcpHost::Process(const MainloopContext &aMainloop)
 {
     otTaskletsProcess(mInstance);
 
@@ -333,32 +329,32 @@ void ControllerOpenThread::Process(const MainloopContext &aMainloop)
     }
 }
 
-bool ControllerOpenThread::IsAutoAttachEnabled(void)
+bool RcpHost::IsAutoAttachEnabled(void)
 {
     return mEnableAutoAttach;
 }
 
-void ControllerOpenThread::DisableAutoAttach(void)
+void RcpHost::DisableAutoAttach(void)
 {
     mEnableAutoAttach = false;
 }
 
-void ControllerOpenThread::PostTimerTask(Milliseconds aDelay, TaskRunner::Task<void> aTask)
+void RcpHost::PostTimerTask(Milliseconds aDelay, TaskRunner::Task<void> aTask)
 {
     mTaskRunner.Post(std::move(aDelay), std::move(aTask));
 }
 
-void ControllerOpenThread::RegisterResetHandler(std::function<void(void)> aHandler)
+void RcpHost::RegisterResetHandler(std::function<void(void)> aHandler)
 {
     mResetHandlers.emplace_back(std::move(aHandler));
 }
 
-void ControllerOpenThread::AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback)
+void RcpHost::AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback)
 {
     mThreadStateChangedCallbacks.emplace_back(std::move(aCallback));
 }
 
-void ControllerOpenThread::Reset(void)
+void RcpHost::Reset(void)
 {
     gPlatResetReason = OT_PLAT_RESET_REASON_SOFTWARE;
 
@@ -373,7 +369,7 @@ void ControllerOpenThread::Reset(void)
     mEnableAutoAttach = true;
 }
 
-const char *ControllerOpenThread::GetThreadVersion(void)
+const char *RcpHost::GetThreadVersion(void)
 {
     const char *version;
 
@@ -389,7 +385,7 @@ const char *ControllerOpenThread::GetThreadVersion(void)
         version = "1.3.0";
         break;
     case kThreadVersion14:
-        version = "1.4";
+        version = "1.4.0";
         break;
     default:
         otbrLogEmerg("Unexpected thread version %hu", otThreadGetVersion());
@@ -398,6 +394,29 @@ const char *ControllerOpenThread::GetThreadVersion(void)
     return version;
 }
 
+void RcpHost::Join(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, const AsyncResultReceiver &aReceiver)
+{
+    OT_UNUSED_VARIABLE(aActiveOpDatasetTlvs);
+
+    // TODO: Implement Join under RCP mode.
+    mTaskRunner.Post([aReceiver](void) { aReceiver(OT_ERROR_NOT_IMPLEMENTED, "Not implemented!"); });
+}
+
+void RcpHost::Leave(const AsyncResultReceiver &aReceiver)
+{
+    // TODO: Implement Leave under RCP mode.
+    mTaskRunner.Post([aReceiver](void) { aReceiver(OT_ERROR_NOT_IMPLEMENTED, "Not implemented!"); });
+}
+
+void RcpHost::ScheduleMigration(const otOperationalDatasetTlvs &aPendingOpDatasetTlvs,
+                                const AsyncResultReceiver       aReceiver)
+{
+    OT_UNUSED_VARIABLE(aPendingOpDatasetTlvs);
+
+    // TODO: Implement ScheduleMigration under RCP mode.
+    mTaskRunner.Post([aReceiver](void) { aReceiver(OT_ERROR_NOT_IMPLEMENTED, "Not implemented!"); });
+}
+
 /*
  * Provide, if required an "otPlatLog()" function
  */
@@ -405,7 +424,7 @@ extern "C" void otPlatLog(otLogLevel aLogLevel, otLogRegion aLogRegion, const ch
 {
     OT_UNUSED_VARIABLE(aLogRegion);
 
-    otbrLogLevel otbrLogLevel = ControllerOpenThread::ConvertToOtbrLogLevel(aLogLevel);
+    otbrLogLevel otbrLogLevel = RcpHost::ConvertToOtbrLogLevel(aLogLevel);
 
     va_list ap;
     va_start(ap, aFormat);
@@ -415,7 +434,7 @@ extern "C" void otPlatLog(otLogLevel aLogLevel, otLogRegion aLogRegion, const ch
 
 extern "C" void otPlatLogHandleLevelChanged(otLogLevel aLogLevel)
 {
-    otbrLogSetLevel(ControllerOpenThread::ConvertToOtbrLogLevel(aLogLevel));
+    otbrLogSetLevel(RcpHost::ConvertToOtbrLogLevel(aLogLevel));
     otbrLogInfo("OpenThread log level changed to %d", aLogLevel);
 }
 
diff --git a/src/ncp/ncp_openthread.hpp b/src/ncp/rcp_host.hpp
similarity index 76%
rename from src/ncp/ncp_openthread.hpp
rename to src/ncp/rcp_host.hpp
index 51ba31f4..a13e70cc 100644
--- a/src/ncp/ncp_openthread.hpp
+++ b/src/ncp/rcp_host.hpp
@@ -28,11 +28,11 @@
 
 /**
  * @file
- *   This file includes definitions for NCP service.
+ *   This file includes definitions of Thread Controller under RCP mode.
  */
 
-#ifndef OTBR_AGENT_NCP_OPENTHREAD_HPP_
-#define OTBR_AGENT_NCP_OPENTHREAD_HPP_
+#ifndef OTBR_AGENT_RCP_HOST_HPP_
+#define OTBR_AGENT_RCP_HOST_HPP_
 
 #include "openthread-br/config.h"
 
@@ -49,6 +49,7 @@
 #include "common/mainloop.hpp"
 #include "common/task_runner.hpp"
 #include "common/types.hpp"
+#include "ncp/thread_host.hpp"
 #include "utils/thread_helper.hpp"
 
 namespace otbr {
@@ -60,10 +61,33 @@ class FeatureFlagList;
 namespace Ncp {
 
 /**
- * This interface defines NCP Controller functionality.
+ * This class implements the NetworkProperties for architectures where OT APIs are directly accessible.
  *
  */
-class ControllerOpenThread : public MainloopProcessor
+class OtNetworkProperties : virtual public NetworkProperties
+{
+public:
+    /**
+     * Constructor.
+     *
+     */
+    explicit OtNetworkProperties(void);
+
+    // NetworkProperties methods
+    otDeviceRole GetDeviceRole(void) const override;
+
+    // Set the otInstance
+    void SetInstance(otInstance *aInstance);
+
+private:
+    otInstance *mInstance;
+};
+
+/**
+ * This interface defines OpenThread Controller under RCP mode.
+ *
+ */
+class RcpHost : public MainloopProcessor, public ThreadHost, public OtNetworkProperties
 {
 public:
     using ThreadStateChangedCallback = std::function<void(otChangedFlags aFlags)>;
@@ -78,28 +102,28 @@ public:
      * @param[in]   aEnableAutoAttach       Whether or not to automatically attach to the saved network.
      *
      */
-    ControllerOpenThread(const char                      *aInterfaceName,
-                         const std::vector<const char *> &aRadioUrls,
-                         const char                      *aBackboneInterfaceName,
-                         bool                             aDryRun,
-                         bool                             aEnableAutoAttach);
+    RcpHost(const char                      *aInterfaceName,
+            const std::vector<const char *> &aRadioUrls,
+            const char                      *aBackboneInterfaceName,
+            bool                             aDryRun,
+            bool                             aEnableAutoAttach);
 
     /**
-     * This method initialize the NCP controller.
+     * This method initialize the Thread controller.
      *
      */
-    void Init(void);
+    void Init(void) override;
 
     /**
-     * This method deinitialize the NCP controller.
+     * This method deinitialize the Thread controller.
      *
      */
-    void Deinit(void);
+    void Deinit(void) override;
 
     /**
      * Returns an OpenThread instance.
      *
-     * @retval Non-null OpenThread instance if `ControllerOpenThread::Init()` has been called.
+     * @retval Non-null OpenThread instance if `RcpHost::Init()` has been called.
      *         Otherwise, it's guaranteed to be `null`
      */
     otInstance *GetInstance(void) { return mInstance; }
@@ -164,7 +188,7 @@ public:
      * @returns A pointer to the Thread network interface name string.
      *
      */
-    const char *GetInterfaceName(void) const { return mConfig.mInterfaceName; }
+    const char *GetInterfaceName(void) const override { return mConfig.mInterfaceName; }
 
     static otbrLogLevel ConvertToOtbrLogLevel(otLogLevel aLogLevel);
 
@@ -191,12 +215,28 @@ public:
     }
 #endif
 
-    ~ControllerOpenThread(void) override;
+    ~RcpHost(void) override;
+
+    // Thread Control virtual methods
+    void Join(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, const AsyncResultReceiver &aRecevier) override;
+    void Leave(const AsyncResultReceiver &aRecevier) override;
+    void ScheduleMigration(const otOperationalDatasetTlvs &aPendingOpDatasetTlvs,
+                           const AsyncResultReceiver       aReceiver) override;
+
+    CoprocessorType GetCoprocessorType(void) override
+    {
+        return OT_COPROCESSOR_RCP;
+    }
+
+    const char *GetCoprocessorVersion(void) override
+    {
+        return otPlatRadioGetVersionString(mInstance);
+    }
 
 private:
     static void HandleStateChanged(otChangedFlags aFlags, void *aContext)
     {
-        static_cast<ControllerOpenThread *>(aContext)->HandleStateChanged(aFlags);
+        static_cast<RcpHost *>(aContext)->HandleStateChanged(aFlags);
     }
     void HandleStateChanged(otChangedFlags aFlags);
 
@@ -216,8 +256,6 @@ private:
     bool IsAutoAttachEnabled(void);
     void DisableAutoAttach(void);
 
-    static otLogLevel ConvertToOtLogLevel(otbrLogLevel aLevel);
-
     otError SetOtbrAndOtLogLevel(otbrLogLevel aLevel);
 
     otInstance *mInstance;
@@ -228,6 +266,7 @@ private:
     TaskRunner                                 mTaskRunner;
     std::vector<ThreadStateChangedCallback>    mThreadStateChangedCallbacks;
     bool                                       mEnableAutoAttach = false;
+
 #if OTBR_ENABLE_FEATURE_FLAGS
     // The applied FeatureFlagList in ApplyFeatureFlagList call, used for debugging purpose.
     std::string mAppliedFeatureFlagListBytes;
@@ -237,4 +276,4 @@ private:
 } // namespace Ncp
 } // namespace otbr
 
-#endif // OTBR_AGENT_NCP_OPENTHREAD_HPP_
+#endif // OTBR_AGENT_RCP_HOST_HPP_
diff --git a/src/ncp/thread_host.cpp b/src/ncp/thread_host.cpp
new file mode 100644
index 00000000..294060a3
--- /dev/null
+++ b/src/ncp/thread_host.cpp
@@ -0,0 +1,116 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#define OTBR_LOG_TAG "CTRLR"
+
+#include "thread_host.hpp"
+
+#include <openthread/logging.h>
+#include <openthread/openthread-system.h>
+
+#include "lib/spinel/coprocessor_type.h"
+
+#include "ncp_host.hpp"
+#include "rcp_host.hpp"
+
+namespace otbr {
+namespace Ncp {
+
+std::unique_ptr<ThreadHost> ThreadHost::Create(const char                      *aInterfaceName,
+                                               const std::vector<const char *> &aRadioUrls,
+                                               const char                      *aBackboneInterfaceName,
+                                               bool                             aDryRun,
+                                               bool                             aEnableAutoAttach)
+{
+    CoprocessorType             coprocessorType;
+    otPlatformCoprocessorUrls   urls;
+    std::unique_ptr<ThreadHost> host;
+    otLogLevel                  level = ConvertToOtLogLevel(otbrLogGetLevel());
+
+    VerifyOrDie(aRadioUrls.size() <= OT_PLATFORM_CONFIG_MAX_RADIO_URLS, "Too many Radio URLs!");
+
+    urls.mNum = 0;
+    for (const char *url : aRadioUrls)
+    {
+        urls.mUrls[urls.mNum++] = url;
+    }
+
+    VerifyOrDie(otLoggingSetLevel(level) == OT_ERROR_NONE, "Failed to set OT log Level!");
+
+    coprocessorType = otSysInitCoprocessor(&urls);
+
+    switch (coprocessorType)
+    {
+    case OT_COPROCESSOR_RCP:
+        host = MakeUnique<RcpHost>(aInterfaceName, aRadioUrls, aBackboneInterfaceName, aDryRun, aEnableAutoAttach);
+        break;
+
+    case OT_COPROCESSOR_NCP:
+        host = MakeUnique<NcpHost>(aInterfaceName, aDryRun);
+        break;
+
+    default:
+        DieNow("Unknown coprocessor type!");
+        break;
+    }
+
+    return host;
+}
+
+otLogLevel ThreadHost::ConvertToOtLogLevel(otbrLogLevel aLevel)
+{
+    otLogLevel level;
+
+    switch (aLevel)
+    {
+    case OTBR_LOG_EMERG:
+    case OTBR_LOG_ALERT:
+    case OTBR_LOG_CRIT:
+        level = OT_LOG_LEVEL_CRIT;
+        break;
+    case OTBR_LOG_ERR:
+    case OTBR_LOG_WARNING:
+        level = OT_LOG_LEVEL_WARN;
+        break;
+    case OTBR_LOG_NOTICE:
+        level = OT_LOG_LEVEL_NOTE;
+        break;
+    case OTBR_LOG_INFO:
+        level = OT_LOG_LEVEL_INFO;
+        break;
+    case OTBR_LOG_DEBUG:
+    default:
+        level = OT_LOG_LEVEL_DEBG;
+        break;
+    }
+
+    return level;
+}
+
+} // namespace Ncp
+} // namespace otbr
diff --git a/src/ncp/thread_host.hpp b/src/ncp/thread_host.hpp
new file mode 100644
index 00000000..65e06356
--- /dev/null
+++ b/src/ncp/thread_host.hpp
@@ -0,0 +1,191 @@
+/*
+ *  Copyright (c) 2024, The OpenThread Authors.
+ *  All rights reserved.
+ *
+ *  Redistribution and use in source and binary forms, with or without
+ *  modification, are permitted provided that the following conditions are met:
+ *  1. Redistributions of source code must retain the above copyright
+ *     notice, this list of conditions and the following disclaimer.
+ *  2. Redistributions in binary form must reproduce the above copyright
+ *     notice, this list of conditions and the following disclaimer in the
+ *     documentation and/or other materials provided with the distribution.
+ *  3. Neither the name of the copyright holder nor the
+ *     names of its contributors may be used to endorse or promote products
+ *     derived from this software without specific prior written permission.
+ *
+ *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *  POSSIBILITY OF SUCH DAMAGE.
+ */
+
+/**
+ * @file
+ *   This file includes definitions of Thead Controller Interface.
+ */
+
+#ifndef OTBR_AGENT_THREAD_HOST_HPP_
+#define OTBR_AGENT_THREAD_HOST_HPP_
+
+#include <functional>
+#include <memory>
+
+#include <openthread/dataset.h>
+#include <openthread/error.h>
+#include <openthread/thread.h>
+
+#include "lib/spinel/coprocessor_type.h"
+
+#include "common/logging.hpp"
+
+namespace otbr {
+namespace Ncp {
+
+/**
+ * This interface provides access to some Thread network properties in a sync way.
+ *
+ * The APIs are unified for both NCP and RCP cases.
+ */
+class NetworkProperties
+{
+public:
+    /**
+     * Returns the device role.
+     *
+     * @returns the device role.
+     *
+     */
+    virtual otDeviceRole GetDeviceRole(void) const = 0;
+
+    /**
+     * The destructor.
+     *
+     */
+    virtual ~NetworkProperties(void) = default;
+};
+
+/**
+ * This class is an interface which provides a set of async APIs to control the
+ * Thread network.
+ *
+ * The APIs are unified for both NCP and RCP cases.
+ *
+ */
+class ThreadHost : virtual public NetworkProperties
+{
+public:
+    using AsyncResultReceiver = std::function<void(otError, const std::string &)>;
+    using DeviceRoleHandler   = std::function<void(otError, otDeviceRole)>;
+
+    /**
+     * Create a Thread Controller Instance.
+     *
+     * This is a factory method that will decide which implementation class will be created.
+     *
+     * @param[in]   aInterfaceName          A string of the Thread interface name.
+     * @param[in]   aRadioUrls              The radio URLs (can be IEEE802.15.4 or TREL radio).
+     * @param[in]   aBackboneInterfaceName  The Backbone network interface name.
+     * @param[in]   aDryRun                 TRUE to indicate dry-run mode. FALSE otherwise.
+     * @param[in]   aEnableAutoAttach       Whether or not to automatically attach to the saved network.
+     *
+     * @returns Non-null OpenThread Controller instance.
+     *
+     */
+    static std::unique_ptr<ThreadHost> Create(const char                      *aInterfaceName,
+                                              const std::vector<const char *> &aRadioUrls,
+                                              const char                      *aBackboneInterfaceName,
+                                              bool                             aDryRun,
+                                              bool                             aEnableAutoAttach);
+
+    /**
+     * This method joins this device to the network specified by @p aActiveOpDatasetTlvs.
+     *
+     * If there is an ongoing 'Join' operation, no action will be taken and @p aReceiver will be
+     * called after the request is completed. The previous @p aReceiver will also be called.
+     *
+     * @param[in] aActiveOpDatasetTlvs  A reference to the active operational dataset of the Thread network.
+     * @param[in] aReceiver             A receiver to get the async result of this operation.
+     *
+     */
+    virtual void Join(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, const AsyncResultReceiver &aRecevier) = 0;
+
+    /**
+     * This method instructs the device to leave the current network gracefully.
+     *
+     * 1. If there is already an ongoing 'Leave' operation, no action will be taken and @p aReceiver
+     *    will be called after the previous request is completed. The previous @p aReceiver will also
+     *    be called.
+     * 2. If this device is not in disabled state, OTBR sends Address Release Notification (i.e. ADDR_REL.ntf)
+     *    to gracefully detach from the current network and it takes 1 second to finish.
+     * 3. Then Operational Dataset will be removed from persistent storage.
+     * 4. If everything goes fine, @p aReceiver will be invoked with OT_ERROR_NONE. Otherwise, other errors
+     *    will be passed to @p aReceiver when the error happens.
+     *
+     * @param[in] aReceiver  A receiver to get the async result of this operation.
+     *
+     */
+    virtual void Leave(const AsyncResultReceiver &aRecevier) = 0;
+
+    /**
+     * This method migrates this device to the new network specified by @p aPendingOpDatasetTlvs.
+     *
+     * @param[in] aPendingOpDatasetTlvs  A reference to the pending operational dataset of the Thread network.
+     * @param[in] aReceiver              A receiver to get the async result of this operation.
+     *
+     */
+    virtual void ScheduleMigration(const otOperationalDatasetTlvs &aPendingOpDatasetTlvs,
+                                   const AsyncResultReceiver       aReceiver) = 0;
+
+    /**
+     * Returns the co-processor type.
+     *
+     */
+    virtual CoprocessorType GetCoprocessorType(void) = 0;
+
+    /**
+     * Returns the co-processor version string.
+     *
+     */
+    virtual const char *GetCoprocessorVersion(void) = 0;
+
+    /**
+     * This method returns the Thread network interface name.
+     *
+     * @returns A pointer to the Thread network interface name string.
+     *
+     */
+    virtual const char *GetInterfaceName(void) const = 0;
+
+    /**
+     * Initializes the Thread controller.
+     *
+     */
+    virtual void Init(void) = 0;
+
+    /**
+     * Deinitializes the Thread controller.
+     *
+     */
+    virtual void Deinit(void) = 0;
+
+    /**
+     * The destructor.
+     *
+     */
+    virtual ~ThreadHost(void) = default;
+
+protected:
+    static otLogLevel ConvertToOtLogLevel(otbrLogLevel aLevel);
+};
+
+} // namespace Ncp
+} // namespace otbr
+
+#endif // OTBR_AGENT_THREAD_HOST_HPP_
diff --git a/src/openwrt/ubus/otubus.cpp b/src/openwrt/ubus/otubus.cpp
index 4dfaac2a..ef762d0d 100644
--- a/src/openwrt/ubus/otubus.cpp
+++ b/src/openwrt/ubus/otubus.cpp
@@ -44,7 +44,7 @@
 #include <openthread/thread_ftd.h>
 
 #include "common/logging.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 namespace ubus {
@@ -58,12 +58,12 @@ const static int PANID_LENGTH      = 10;
 const static int XPANID_LENGTH     = 64;
 const static int NETWORKKEY_LENGTH = 64;
 
-UbusServer::UbusServer(Ncp::ControllerOpenThread *aController, std::mutex *aMutex)
+UbusServer::UbusServer(Ncp::RcpHost *aHost, std::mutex *aMutex)
     : mIfFinishScan(false)
     , mContext(nullptr)
     , mSockPath(nullptr)
-    , mController(aController)
-    , mNcpThreadMutex(aMutex)
+    , mHost(aHost)
+    , mHostMutex(aMutex)
     , mSecond(0)
 {
     memset(&mNetworkdataBuf, 0, sizeof(mNetworkdataBuf));
@@ -78,9 +78,9 @@ UbusServer &UbusServer::GetInstance(void)
     return *sUbusServerInstance;
 }
 
-void UbusServer::Initialize(Ncp::ControllerOpenThread *aController, std::mutex *aMutex)
+void UbusServer::Initialize(Ncp::RcpHost *aHost, std::mutex *aMutex)
 {
-    sUbusServerInstance = new UbusServer(aController, aMutex);
+    sUbusServerInstance = new UbusServer(aHost, aMutex);
 }
 
 enum
@@ -229,11 +229,11 @@ void UbusServer::ProcessScan(void)
     uint32_t scanChannels = 0;
     uint16_t scanDuration = 0;
 
-    mNcpThreadMutex->lock();
-    SuccessOrExit(error = otLinkActiveScan(mController->GetInstance(), scanChannels, scanDuration,
+    mHostMutex->lock();
+    SuccessOrExit(error = otLinkActiveScan(mHost->GetInstance(), scanChannels, scanDuration,
                                            &UbusServer::HandleActiveScanResult, this));
 exit:
-    mNcpThreadMutex->unlock();
+    mHostMutex->unlock();
     return;
 }
 
@@ -679,8 +679,8 @@ int UbusServer::UbusLeaveHandlerDetail(struct ubus_context      *aContext,
     uint64_t eventNum;
     ssize_t  retval;
 
-    mNcpThreadMutex->lock();
-    otInstanceFactoryReset(mController->GetInstance());
+    mHostMutex->lock();
+    otInstanceFactoryReset(mHost->GetInstance());
 
     eventNum = 1;
     retval   = write(sUbusEfd, &eventNum, sizeof(uint64_t));
@@ -693,7 +693,7 @@ int UbusServer::UbusLeaveHandlerDetail(struct ubus_context      *aContext,
     blob_buf_init(&mBuf, 0);
 
 exit:
-    mNcpThreadMutex->unlock();
+    mHostMutex->unlock();
     AppendResult(error, aContext, aRequest);
     return 0;
 }
@@ -714,19 +714,19 @@ int UbusServer::UbusThreadHandler(struct ubus_context      *aContext,
 
     if (!strcmp(aAction, "start"))
     {
-        mNcpThreadMutex->lock();
-        SuccessOrExit(error = otIp6SetEnabled(mController->GetInstance(), true));
-        SuccessOrExit(error = otThreadSetEnabled(mController->GetInstance(), true));
+        mHostMutex->lock();
+        SuccessOrExit(error = otIp6SetEnabled(mHost->GetInstance(), true));
+        SuccessOrExit(error = otThreadSetEnabled(mHost->GetInstance(), true));
     }
     else if (!strcmp(aAction, "stop"))
     {
-        mNcpThreadMutex->lock();
-        SuccessOrExit(error = otThreadSetEnabled(mController->GetInstance(), false));
-        SuccessOrExit(error = otIp6SetEnabled(mController->GetInstance(), false));
+        mHostMutex->lock();
+        SuccessOrExit(error = otThreadSetEnabled(mHost->GetInstance(), false));
+        SuccessOrExit(error = otIp6SetEnabled(mHost->GetInstance(), false));
     }
 
 exit:
-    mNcpThreadMutex->unlock();
+    mHostMutex->unlock();
     AppendResult(error, aContext, aRequest);
     return 0;
 }
@@ -750,8 +750,8 @@ int UbusServer::UbusParentHandlerDetail(struct ubus_context      *aContext,
 
     blob_buf_init(&mBuf, 0);
 
-    mNcpThreadMutex->lock();
-    SuccessOrExit(error = otThreadGetParentInfo(mController->GetInstance(), &parentInfo));
+    mHostMutex->lock();
+    SuccessOrExit(error = otThreadGetParentInfo(mHost->GetInstance(), &parentInfo));
 
     jsonArray = blobmsg_open_array(&mBuf, "parent_list");
     jsonList  = blobmsg_open_table(&mBuf, "parent");
@@ -772,7 +772,7 @@ int UbusServer::UbusParentHandlerDetail(struct ubus_context      *aContext,
     blobmsg_close_array(&mBuf, jsonArray);
 
 exit:
-    mNcpThreadMutex->unlock();
+    mHostMutex->unlock();
     AppendResult(error, aContext, aRequest);
     return error;
 }
@@ -799,8 +799,8 @@ int UbusServer::UbusNeighborHandlerDetail(struct ubus_context      *aContext,
 
     sJsonUri = blobmsg_open_array(&mBuf, "neighbor_list");
 
-    mNcpThreadMutex->lock();
-    while (otThreadGetNextNeighborInfo(mController->GetInstance(), &iterator, &neighborInfo) == OT_ERROR_NONE)
+    mHostMutex->lock();
+    while (otThreadGetNextNeighborInfo(mHost->GetInstance(), &iterator, &neighborInfo) == OT_ERROR_NONE)
     {
         jsonList = blobmsg_open_table(&mBuf, nullptr);
 
@@ -847,7 +847,7 @@ int UbusServer::UbusNeighborHandlerDetail(struct ubus_context      *aContext,
 
     blobmsg_close_array(&mBuf, sJsonUri);
 
-    mNcpThreadMutex->unlock();
+    mHostMutex->unlock();
 
     AppendResult(error, aContext, aRequest);
     return 0;
@@ -870,7 +870,7 @@ int UbusServer::UbusMgmtset(struct ubus_context      *aContext,
     long                 value;
     int                  length = 0;
 
-    SuccessOrExit(error = otDatasetGetActive(mController->GetInstance(), &dataset));
+    SuccessOrExit(error = otDatasetGetActive(mHost->GetInstance(), &dataset));
 
     blobmsg_parse(mgmtsetPolicy, MGMTSET_MAX, tb, blob_data(aMsg), blob_len(aMsg));
     if (tb[NETWORKKEY] != nullptr)
@@ -919,12 +919,12 @@ int UbusServer::UbusMgmtset(struct ubus_context      *aContext,
         length = 0;
     }
     dataset.mActiveTimestamp.mSeconds++;
-    if (otCommissionerGetState(mController->GetInstance()) == OT_COMMISSIONER_STATE_DISABLED)
+    if (otCommissionerGetState(mHost->GetInstance()) == OT_COMMISSIONER_STATE_DISABLED)
     {
-        otCommissionerStop(mController->GetInstance());
+        otCommissionerStop(mHost->GetInstance());
     }
-    SuccessOrExit(error = otDatasetSendMgmtActiveSet(mController->GetInstance(), &dataset, tlvs,
-                                                     static_cast<uint8_t>(length), /* aCallback */ nullptr,
+    SuccessOrExit(error = otDatasetSendMgmtActiveSet(mHost->GetInstance(), &dataset, tlvs, static_cast<uint8_t>(length),
+                                                     /* aCallback */ nullptr,
                                                      /* aContext */ nullptr));
 exit:
     AppendResult(error, aContext, aRequest);
@@ -944,13 +944,13 @@ int UbusServer::UbusCommissioner(struct ubus_context      *aContext,
 
     otError error = OT_ERROR_NONE;
 
-    mNcpThreadMutex->lock();
+    mHostMutex->lock();
 
     if (!strcmp(aAction, "start"))
     {
-        if (otCommissionerGetState(mController->GetInstance()) == OT_COMMISSIONER_STATE_DISABLED)
+        if (otCommissionerGetState(mHost->GetInstance()) == OT_COMMISSIONER_STATE_DISABLED)
         {
-            error = otCommissionerStart(mController->GetInstance(), &UbusServer::HandleStateChanged,
+            error = otCommissionerStart(mHost->GetInstance(), &UbusServer::HandleStateChanged,
                                         &UbusServer::HandleJoinerEvent, this);
         }
     }
@@ -982,8 +982,8 @@ int UbusServer::UbusCommissioner(struct ubus_context      *aContext,
         }
 
         unsigned long timeout = kDefaultJoinerTimeout;
-        SuccessOrExit(
-            error = otCommissionerAddJoiner(mController->GetInstance(), addrPtr, pskd, static_cast<uint32_t>(timeout)));
+        SuccessOrExit(error =
+                          otCommissionerAddJoiner(mHost->GetInstance(), addrPtr, pskd, static_cast<uint32_t>(timeout)));
     }
     else if (!strcmp(aAction, "joinerremove"))
     {
@@ -1006,11 +1006,11 @@ int UbusServer::UbusCommissioner(struct ubus_context      *aContext,
             }
         }
 
-        SuccessOrExit(error = otCommissionerRemoveJoiner(mController->GetInstance(), addrPtr));
+        SuccessOrExit(error = otCommissionerRemoveJoiner(mHost->GetInstance(), addrPtr));
     }
 
 exit:
-    mNcpThreadMutex->unlock();
+    mHostMutex->unlock();
     blob_buf_init(&mBuf, 0);
     AppendResult(error, aContext, aRequest);
     return 0;
@@ -1087,31 +1087,31 @@ int UbusServer::UbusGetInformation(struct ubus_context      *aContext,
 
     blob_buf_init(&mBuf, 0);
 
-    mNcpThreadMutex->lock();
+    mHostMutex->lock();
     if (!strcmp(aAction, "networkname"))
-        blobmsg_add_string(&mBuf, "NetworkName", otThreadGetNetworkName(mController->GetInstance()));
+        blobmsg_add_string(&mBuf, "NetworkName", otThreadGetNetworkName(mHost->GetInstance()));
     else if (!strcmp(aAction, "interfacename"))
     {
-        blobmsg_add_string(&mBuf, "InterfaceName", mController->GetInterfaceName());
+        blobmsg_add_string(&mBuf, "InterfaceName", mHost->GetInterfaceName());
     }
     else if (!strcmp(aAction, "state"))
     {
         char state[10];
-        GetState(mController->GetInstance(), state);
+        GetState(mHost->GetInstance(), state);
         blobmsg_add_string(&mBuf, "State", state);
     }
     else if (!strcmp(aAction, "channel"))
-        blobmsg_add_u32(&mBuf, "Channel", otLinkGetChannel(mController->GetInstance()));
+        blobmsg_add_u32(&mBuf, "Channel", otLinkGetChannel(mHost->GetInstance()));
     else if (!strcmp(aAction, "panid"))
     {
         char panIdString[PANID_LENGTH];
-        sprintf(panIdString, "0x%04x", otLinkGetPanId(mController->GetInstance()));
+        sprintf(panIdString, "0x%04x", otLinkGetPanId(mHost->GetInstance()));
         blobmsg_add_string(&mBuf, "PanId", panIdString);
     }
     else if (!strcmp(aAction, "rloc16"))
     {
         char rloc[PANID_LENGTH];
-        sprintf(rloc, "0x%04x", otThreadGetRloc16(mController->GetInstance()));
+        sprintf(rloc, "0x%04x", otThreadGetRloc16(mHost->GetInstance()));
         blobmsg_add_string(&mBuf, "rloc16", rloc);
     }
     else if (!strcmp(aAction, "networkkey"))
@@ -1119,7 +1119,7 @@ int UbusServer::UbusGetInformation(struct ubus_context      *aContext,
         char         outputKey[NETWORKKEY_LENGTH] = "";
         otNetworkKey key;
 
-        otThreadGetNetworkKey(mController->GetInstance(), &key);
+        otThreadGetNetworkKey(mHost->GetInstance(), &key);
         OutputBytes(key.m8, OT_NETWORK_KEY_SIZE, outputKey);
         blobmsg_add_string(&mBuf, "Networkkey", outputKey);
     }
@@ -1128,15 +1128,14 @@ int UbusServer::UbusGetInformation(struct ubus_context      *aContext,
         char   outputPskc[NETWORKKEY_LENGTH] = "";
         otPskc pskc;
 
-        otThreadGetPskc(mController->GetInstance(), &pskc);
+        otThreadGetPskc(mHost->GetInstance(), &pskc);
         OutputBytes(pskc.m8, OT_PSKC_MAX_SIZE, outputPskc);
         blobmsg_add_string(&mBuf, "pskc", outputPskc);
     }
     else if (!strcmp(aAction, "extpanid"))
     {
         char           outputExtPanId[XPANID_LENGTH] = "";
-        const uint8_t *extPanId =
-            reinterpret_cast<const uint8_t *>(otThreadGetExtendedPanId(mController->GetInstance()));
+        const uint8_t *extPanId = reinterpret_cast<const uint8_t *>(otThreadGetExtendedPanId(mHost->GetInstance()));
         OutputBytes(extPanId, OT_EXT_PAN_ID_SIZE, outputExtPanId);
         blobmsg_add_string(&mBuf, "ExtPanId", outputExtPanId);
     }
@@ -1147,7 +1146,7 @@ int UbusServer::UbusGetInformation(struct ubus_context      *aContext,
 
         memset(&linkMode, 0, sizeof(otLinkModeConfig));
 
-        linkMode = otThreadGetLinkMode(mController->GetInstance());
+        linkMode = otThreadGetLinkMode(mHost->GetInstance());
 
         if (linkMode.mRxOnWhenIdle)
         {
@@ -1167,13 +1166,13 @@ int UbusServer::UbusGetInformation(struct ubus_context      *aContext,
     }
     else if (!strcmp(aAction, "partitionid"))
     {
-        blobmsg_add_u32(&mBuf, "Partitionid", otThreadGetPartitionId(mController->GetInstance()));
+        blobmsg_add_u32(&mBuf, "Partitionid", otThreadGetPartitionId(mHost->GetInstance()));
     }
     else if (!strcmp(aAction, "leaderdata"))
     {
         otLeaderData leaderData;
 
-        SuccessOrExit(error = otThreadGetLeaderData(mController->GetInstance(), &leaderData));
+        SuccessOrExit(error = otThreadGetLeaderData(mHost->GetInstance(), &leaderData));
 
         sJsonUri = blobmsg_open_table(&mBuf, "leaderdata");
 
@@ -1205,7 +1204,7 @@ int UbusServer::UbusGetInformation(struct ubus_context      *aContext,
             tlvTypes[count++] = static_cast<uint8_t>(OT_NETWORK_DIAGNOSTIC_TLV_CHILD_TABLE);
 
             sBufNum = 0;
-            otThreadSendDiagnosticGet(mController->GetInstance(), &address, tlvTypes, count,
+            otThreadSendDiagnosticGet(mHost->GetInstance(), &address, tlvTypes, count,
                                       &UbusServer::HandleDiagnosticGetResponse, this);
             mSecond = time(nullptr);
         }
@@ -1223,7 +1222,7 @@ int UbusServer::UbusGetInformation(struct ubus_context      *aContext,
         blob_buf_init(&mBuf, 0);
 
         jsonArray = blobmsg_open_array(&mBuf, "joinerList");
-        while (otCommissionerGetNextJoinerInfo(mController->GetInstance(), &iterator, &joinerInfo) == OT_ERROR_NONE)
+        while (otCommissionerGetNextJoinerInfo(mHost->GetInstance(), &iterator, &joinerInfo) == OT_ERROR_NONE)
         {
             memset(eui64, 0, sizeof(eui64));
 
@@ -1258,7 +1257,7 @@ int UbusServer::UbusGetInformation(struct ubus_context      *aContext,
     }
     else if (!strcmp(aAction, "macfilterstate"))
     {
-        otMacFilterAddressMode mode = otLinkFilterGetAddressMode(mController->GetInstance());
+        otMacFilterAddressMode mode = otLinkFilterGetAddressMode(mHost->GetInstance());
 
         blob_buf_init(&mBuf, 0);
 
@@ -1288,7 +1287,7 @@ int UbusServer::UbusGetInformation(struct ubus_context      *aContext,
 
         sJsonUri = blobmsg_open_array(&mBuf, "addrlist");
 
-        while (otLinkFilterGetNextAddress(mController->GetInstance(), &iterator, &entry) == OT_ERROR_NONE)
+        while (otLinkFilterGetNextAddress(mHost->GetInstance(), &iterator, &entry) == OT_ERROR_NONE)
         {
             char extAddress[XPANID_LENGTH] = "";
             OutputBytes(entry.mExtAddress.m8, sizeof(entry.mExtAddress.m8), extAddress);
@@ -1304,7 +1303,7 @@ int UbusServer::UbusGetInformation(struct ubus_context      *aContext,
 
     AppendResult(error, aContext, aRequest);
 exit:
-    mNcpThreadMutex->unlock();
+    mHostMutex->unlock();
     return 0;
 }
 
@@ -1440,7 +1439,7 @@ int UbusServer::UbusSetInformation(struct ubus_context      *aContext,
 
     blob_buf_init(&mBuf, 0);
 
-    mNcpThreadMutex->lock();
+    mHostMutex->lock();
     if (!strcmp(aAction, "networkname"))
     {
         struct blob_attr *tb[SET_NETWORK_MAX];
@@ -1449,7 +1448,7 @@ int UbusServer::UbusSetInformation(struct ubus_context      *aContext,
         if (tb[SETNETWORK] != nullptr)
         {
             char *newName = blobmsg_get_string(tb[SETNETWORK]);
-            SuccessOrExit(error = otThreadSetNetworkName(mController->GetInstance(), newName));
+            SuccessOrExit(error = otThreadSetNetworkName(mHost->GetInstance(), newName));
         }
     }
     else if (!strcmp(aAction, "channel"))
@@ -1460,7 +1459,7 @@ int UbusServer::UbusSetInformation(struct ubus_context      *aContext,
         if (tb[SETNETWORK] != nullptr)
         {
             uint32_t channel = blobmsg_get_u32(tb[SETNETWORK]);
-            SuccessOrExit(error = otLinkSetChannel(mController->GetInstance(), static_cast<uint8_t>(channel)));
+            SuccessOrExit(error = otLinkSetChannel(mHost->GetInstance(), static_cast<uint8_t>(channel)));
         }
     }
     else if (!strcmp(aAction, "panid"))
@@ -1473,7 +1472,7 @@ int UbusServer::UbusSetInformation(struct ubus_context      *aContext,
             long  value;
             char *panid = blobmsg_get_string(tb[SETNETWORK]);
             SuccessOrExit(error = ParseLong(panid, value));
-            error = otLinkSetPanId(mController->GetInstance(), static_cast<otPanId>(value));
+            error = otLinkSetPanId(mHost->GetInstance(), static_cast<otPanId>(value));
         }
     }
     else if (!strcmp(aAction, "networkkey"))
@@ -1487,7 +1486,7 @@ int UbusServer::UbusSetInformation(struct ubus_context      *aContext,
             char        *networkkey = blobmsg_get_string(tb[SETNETWORK]);
 
             VerifyOrExit(Hex2Bin(networkkey, key.m8, sizeof(key.m8)) == OT_NETWORK_KEY_SIZE, error = OT_ERROR_PARSE);
-            SuccessOrExit(error = otThreadSetNetworkKey(mController->GetInstance(), &key));
+            SuccessOrExit(error = otThreadSetNetworkKey(mHost->GetInstance(), &key));
         }
     }
     else if (!strcmp(aAction, "pskc"))
@@ -1501,7 +1500,7 @@ int UbusServer::UbusSetInformation(struct ubus_context      *aContext,
 
             VerifyOrExit(Hex2Bin(blobmsg_get_string(tb[SETNETWORK]), pskc.m8, sizeof(pskc)) == OT_PSKC_MAX_SIZE,
                          error = OT_ERROR_PARSE);
-            SuccessOrExit(error = otThreadSetPskc(mController->GetInstance(), &pskc));
+            SuccessOrExit(error = otThreadSetPskc(mHost->GetInstance(), &pskc));
         }
     }
     else if (!strcmp(aAction, "extpanid"))
@@ -1514,7 +1513,7 @@ int UbusServer::UbusSetInformation(struct ubus_context      *aContext,
             otExtendedPanId extPanId;
             char           *input = blobmsg_get_string(tb[SETNETWORK]);
             VerifyOrExit(Hex2Bin(input, extPanId.m8, sizeof(extPanId)) >= 0, error = OT_ERROR_PARSE);
-            error = otThreadSetExtendedPanId(mController->GetInstance(), &extPanId);
+            error = otThreadSetExtendedPanId(mHost->GetInstance(), &extPanId);
         }
     }
     else if (!strcmp(aAction, "mode"))
@@ -1547,7 +1546,7 @@ int UbusServer::UbusSetInformation(struct ubus_context      *aContext,
                 }
             }
 
-            SuccessOrExit(error = otThreadSetLinkMode(mController->GetInstance(), linkMode));
+            SuccessOrExit(error = otThreadSetLinkMode(mHost->GetInstance(), linkMode));
         }
     }
     else if (!strcmp(aAction, "macfilteradd"))
@@ -1562,7 +1561,7 @@ int UbusServer::UbusSetInformation(struct ubus_context      *aContext,
 
             VerifyOrExit(Hex2Bin(addr, extAddr.m8, OT_EXT_ADDRESS_SIZE) == OT_EXT_ADDRESS_SIZE, error = OT_ERROR_PARSE);
 
-            error = otLinkFilterAddAddress(mController->GetInstance(), &extAddr);
+            error = otLinkFilterAddAddress(mHost->GetInstance(), &extAddr);
 
             VerifyOrExit(error == OT_ERROR_NONE || error == OT_ERROR_ALREADY);
         }
@@ -1578,7 +1577,7 @@ int UbusServer::UbusSetInformation(struct ubus_context      *aContext,
             char *addr = blobmsg_get_string(tb[SETNETWORK]);
             VerifyOrExit(Hex2Bin(addr, extAddr.m8, OT_EXT_ADDRESS_SIZE) == OT_EXT_ADDRESS_SIZE, error = OT_ERROR_PARSE);
 
-            otLinkFilterRemoveAddress(mController->GetInstance(), &extAddr);
+            otLinkFilterRemoveAddress(mHost->GetInstance(), &extAddr);
         }
     }
     else if (!strcmp(aAction, "macfiltersetstate"))
@@ -1592,21 +1591,21 @@ int UbusServer::UbusSetInformation(struct ubus_context      *aContext,
 
             if (strcmp(state, "disable") == 0)
             {
-                otLinkFilterSetAddressMode(mController->GetInstance(), OT_MAC_FILTER_ADDRESS_MODE_DISABLED);
+                otLinkFilterSetAddressMode(mHost->GetInstance(), OT_MAC_FILTER_ADDRESS_MODE_DISABLED);
             }
             else if (strcmp(state, "allowlist") == 0)
             {
-                otLinkFilterSetAddressMode(mController->GetInstance(), OT_MAC_FILTER_ADDRESS_MODE_ALLOWLIST);
+                otLinkFilterSetAddressMode(mHost->GetInstance(), OT_MAC_FILTER_ADDRESS_MODE_ALLOWLIST);
             }
             else if (strcmp(state, "denylist") == 0)
             {
-                otLinkFilterSetAddressMode(mController->GetInstance(), OT_MAC_FILTER_ADDRESS_MODE_DENYLIST);
+                otLinkFilterSetAddressMode(mHost->GetInstance(), OT_MAC_FILTER_ADDRESS_MODE_DENYLIST);
             }
         }
     }
     else if (!strcmp(aAction, "macfilterclear"))
     {
-        otLinkFilterClearAddresses(mController->GetInstance());
+        otLinkFilterClearAddresses(mHost->GetInstance());
     }
     else
     {
@@ -1614,7 +1613,7 @@ int UbusServer::UbusSetInformation(struct ubus_context      *aContext,
     }
 
 exit:
-    mNcpThreadMutex->unlock();
+    mHostMutex->unlock();
     AppendResult(error, aContext, aRequest);
     return 0;
 }
@@ -1810,7 +1809,7 @@ void UBusAgent::Init(void)
 {
     otbr::ubus::sUbusEfd = eventfd(0, 0);
 
-    otbr::ubus::UbusServer::Initialize(&mNcp, &mThreadMutex);
+    otbr::ubus::UbusServer::Initialize(&mHost, &mThreadMutex);
 
     if (otbr::ubus::sUbusEfd == -1)
     {
@@ -1825,13 +1824,7 @@ void UBusAgent::Update(MainloopContext &aMainloop)
 {
     VerifyOrExit(otbr::ubus::sUbusEfd != -1);
 
-    FD_SET(otbr::ubus::sUbusEfd, &aMainloop.mReadFdSet);
-
-    if (aMainloop.mMaxFd < otbr::ubus::sUbusEfd)
-    {
-        aMainloop.mMaxFd = otbr::ubus::sUbusEfd;
-    }
-
+    aMainloop.AddFdToReadSet(otbr::ubus::sUbusEfd);
 exit:
     mThreadMutex.unlock();
     return;
diff --git a/src/openwrt/ubus/otubus.hpp b/src/openwrt/ubus/otubus.hpp
index d82b6c25..8c44255e 100644
--- a/src/openwrt/ubus/otubus.hpp
+++ b/src/openwrt/ubus/otubus.hpp
@@ -46,7 +46,7 @@
 
 #include "common/code_utils.hpp"
 #include "common/mainloop.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 
 extern "C" {
 #include <libubox/blobmsg_json.h>
@@ -58,7 +58,7 @@ extern "C" {
 
 namespace otbr {
 namespace Ncp {
-class ControllerOpenThread;
+class RcpHost;
 }
 
 namespace ubus {
@@ -77,10 +77,10 @@ public:
     /**
      * Constructor
      *
-     * @param[in] aController  A pointer to OpenThread Controller structure.
+     * @param[in] aHost  A pointer to OpenThread Controller structure.
      * @param[in] aMutex       A pointer to mutex.
      */
-    static void Initialize(Ncp::ControllerOpenThread *aController, std::mutex *aMutex);
+    static void Initialize(Ncp::RcpHost *aHost, std::mutex *aMutex);
 
     /**
      * This method return the instance of the global UbusServer.
@@ -787,14 +787,14 @@ public:
     void HandleDiagnosticGetResponse(otError aError, otMessage *aMessage, const otMessageInfo *aMessageInfo);
 
 private:
-    bool                       mIfFinishScan;
-    struct ubus_context       *mContext;
-    const char                *mSockPath;
-    struct blob_buf            mBuf;
-    struct blob_buf            mNetworkdataBuf;
-    Ncp::ControllerOpenThread *mController;
-    std::mutex                *mNcpThreadMutex;
-    time_t                     mSecond;
+    bool                 mIfFinishScan;
+    struct ubus_context *mContext;
+    const char          *mSockPath;
+    struct blob_buf      mBuf;
+    struct blob_buf      mNetworkdataBuf;
+    Ncp::RcpHost        *mHost;
+    std::mutex          *mHostMutex;
+    time_t               mSecond;
     enum
     {
         kDefaultJoinerTimeout = 120,
@@ -803,10 +803,10 @@ private:
     /**
      * Constructor
      *
-     * @param[in] aController  The pointer to OpenThread Controller structure.
-     * @param[in] aMutex       A pointer to mutex.
+     * @param[in] aHost    The pointer to OpenThread Controller structure.
+     * @param[in] aMutex   A pointer to mutex.
      */
-    UbusServer(Ncp::ControllerOpenThread *aController, std::mutex *aMutex);
+    UbusServer(Ncp::RcpHost *aHost, std::mutex *aMutex);
 
     /**
      * This method start scan.
@@ -1149,11 +1149,11 @@ public:
     /**
      * The constructor to initialize the UBus agent.
      *
-     * @param[in] aNcp  A reference to the NCP controller.
+     * @param[in] aHost  A reference to the Thread controller.
      *
      */
-    UBusAgent(otbr::Ncp::ControllerOpenThread &aNcp)
-        : mNcp(aNcp)
+    UBusAgent(otbr::Ncp::RcpHost &aHost)
+        : mHost(aHost)
         , mThreadMutex()
     {
     }
@@ -1170,8 +1170,8 @@ public:
 private:
     static void UbusServerRun(void) { otbr::ubus::UbusServer::GetInstance().InstallUbusObject(); }
 
-    otbr::Ncp::ControllerOpenThread &mNcp;
-    std::mutex                       mThreadMutex;
+    otbr::Ncp::RcpHost &mHost;
+    std::mutex          mThreadMutex;
 };
 } // namespace ubus
 } // namespace otbr
diff --git a/src/proto/feature_flag.proto b/src/proto/feature_flag.proto
index 2b82b896..c156dfc4 100644
--- a/src/proto/feature_flag.proto
+++ b/src/proto/feature_flag.proto
@@ -64,4 +64,8 @@ message FeatureFlagList {
   optional bool enable_dns_upstream_query = 5 [default = false];
   // Whether to enable prefix delegation.
   optional bool enable_dhcp6_pd = 6 [default = false];
+  // Whether to enable link metrics manager.
+  optional bool enable_link_metrics_manager = 7 [default = false];
+  // Whether to enable the ePSKc feature.
+  optional bool enable_ephemeralkey = 8 [default = false];
 }
diff --git a/src/proto/thread_telemetry.proto b/src/proto/thread_telemetry.proto
index b3ad934b..f8ef9f4f 100644
--- a/src/proto/thread_telemetry.proto
+++ b/src/proto/thread_telemetry.proto
@@ -115,6 +115,8 @@ message TelemetryData {
     optional uint32 neighbor_table_size = 15;
     optional int32 instant_rssi = 16;
     optional uint64 extended_pan_id = 17;
+    // Indicates the number peer BR in Thread mesh network (from network data)
+    optional uint32 peer_br_count = 18;
   }
 
   message TopoEntry {
@@ -486,6 +488,86 @@ message TelemetryData {
     optional Nat64ProtocolCounters counters = 3;
   }
 
+  message InfraLinkInfo {
+    optional string name = 1;
+    optional bool is_up = 2;
+    optional bool is_running = 3;
+    optional bool is_multicast = 4;
+    optional uint32 link_local_address_count = 5;
+    optional uint32 unique_local_address_count = 6;
+    optional uint32 global_unicast_address_count = 7;
+    // Indicates how many peer BRs (connected to the same Thread mesh network) are on the infra link.
+    optional uint32 peer_br_count = 8;
+  }
+
+  // Message to indicate the information of external routes in network data.
+  message ExternalRoutes {
+    // Indicates whether the a zero-length prefix (::/0) added from this BR
+    optional bool has_default_route_added = 1;
+
+    // Indicates whether the a ULA prefix (fc00::/7) added from this BR
+    optional bool has_ula_route_added = 2;
+
+    // Indicates whether the other prefixes (other than "::/0" or "fc00::/7") added
+    // from this BR. (BR is a managed infrastructure router).
+    optional bool has_others_route_added = 3;
+  }
+
+  message BorderAgentCounters {
+    // The number of ePSKc activations
+    optional uint32 epskc_activations = 1;
+
+    // The number of ePSKc deactivations due to cleared via API
+    optional uint32 epskc_deactivation_clears = 2;
+
+    // The number of ePSKc deactivations due to timeout
+    optional uint32 epskc_deactivation_timeouts = 3;
+
+    // The number of ePSKc deactivations due to max connection attempts reached
+    optional uint32 epskc_deactivation_max_attempts = 4;
+
+    // The number of ePSKc deactivations due to commissioner disconnected
+    optional uint32 epskc_deactivation_disconnects = 5;
+
+    // The number of ePSKc activation failures caused by invalid border agent state
+    optional uint32 epskc_invalid_ba_state_errors = 6;
+
+    // The number of ePSKc activation failures caused by invalid argument
+    optional uint32 epskc_invalid_args_errors = 7;
+
+    // The number of ePSKc activation failures caused by failed to start secure session
+    optional uint32 epskc_start_secure_session_errors = 8;
+
+    // The number of successful secure session establishment with ePSKc
+    optional uint32 epskc_secure_session_successes = 9;
+
+    // The number of failed secure session establishement with ePSKc
+    optional uint32 epskc_secure_session_failures = 10;
+
+    // The number of active commissioner petitioned over secure session establishment with ePSKc
+    optional uint32 epskc_commissioner_petitions = 11;
+
+    // The number of successful secure session establishment with PSKc
+    optional uint32 pskc_secure_session_successes = 12;
+
+    // The number of failed secure session establishement with PSKc
+    optional uint32 pskc_secure_session_failures = 13;
+
+    // The number of active commissioner petitioned over secure session establishment with PSKc
+    optional uint32 pskc_commissioner_petitions = 14;
+
+    // The number of MGMT_ACTIVE_GET.req received
+    optional uint32 mgmt_active_get_reqs = 15;
+
+    // The number of MGMT_PENDING_GET.req received
+    optional uint32 mgmt_pending_get_reqs = 16;
+  }
+
+  message BorderAgentInfo {
+    // The border agent counters
+    optional BorderAgentCounters border_agent_counters = 1;
+  }
+
   message WpanBorderRouter {
     // Border routing counters
     optional BorderRoutingCounters border_routing_counters = 1;
@@ -519,6 +601,15 @@ message TelemetryData {
 
     // Information about TREL.
     optional TrelInfo trel_info = 11;
+
+    // Information about the infra link
+    optional InfraLinkInfo infra_link_info = 12;
+
+    // Information about the external routes in network data.
+    optional ExternalRoutes external_route_info = 13;
+
+    // Information about the Border Agent
+    optional BorderAgentInfo border_agent_info = 14;
   }
 
   message RcpStabilityStatistics {
diff --git a/src/rest/resource.cpp b/src/rest/resource.cpp
index a60e9d94..ce154c2e 100644
--- a/src/rest/resource.cpp
+++ b/src/rest/resource.cpp
@@ -121,9 +121,9 @@ static std::string GetHttpStatus(HttpStatusCode aErrorCode)
     return httpStatus;
 }
 
-Resource::Resource(ControllerOpenThread *aNcp)
+Resource::Resource(RcpHost *aHost)
     : mInstance(nullptr)
-    , mNcp(aNcp)
+    , mHost(aHost)
 {
     // Resource Handler
     mResourceMap.emplace(OT_REST_RESOURCE_PATH_DIAGNOSTICS, &Resource::Diagnostic);
@@ -146,7 +146,7 @@ Resource::Resource(ControllerOpenThread *aNcp)
 
 void Resource::Init(void)
 {
-    mInstance = mNcp->GetThreadHelper()->GetInstance();
+    mInstance = mHost->GetThreadHelper()->GetInstance();
 }
 
 void Resource::Handle(Request &aRequest, Response &aResponse) const
@@ -262,9 +262,9 @@ void Resource::DeleteNodeInfo(Response &aResponse) const
     otbrError   error = OTBR_ERROR_NONE;
     std::string errorCode;
 
-    VerifyOrExit(mNcp->GetThreadHelper()->Detach() == OT_ERROR_NONE, error = OTBR_ERROR_INVALID_STATE);
+    VerifyOrExit(mHost->GetThreadHelper()->Detach() == OT_ERROR_NONE, error = OTBR_ERROR_INVALID_STATE);
     VerifyOrExit(otInstanceErasePersistentInfo(mInstance) == OT_ERROR_NONE, error = OTBR_ERROR_REST);
-    mNcp->Reset();
+    mHost->Reset();
 
 exit:
     if (error == OTBR_ERROR_NONE)
@@ -710,7 +710,7 @@ void Resource::SetDataset(DatasetType aDatasetType, const Request &aRequest, Res
     if (errorOt == OT_ERROR_NOT_FOUND)
     {
         VerifyOrExit(otDatasetCreateNewNetwork(mInstance, &dataset) == OT_ERROR_NONE, error = OTBR_ERROR_REST);
-        VerifyOrExit(otDatasetConvertToTlvs(&dataset, &datasetTlvs) == OT_ERROR_NONE, error = OTBR_ERROR_REST);
+        otDatasetConvertToTlvs(&dataset, &datasetTlvs);
         errorCode = GetHttpStatus(HttpStatusCode::kStatusCreated);
     }
 
diff --git a/src/rest/resource.hpp b/src/rest/resource.hpp
index d79085db..0929dbcc 100644
--- a/src/rest/resource.hpp
+++ b/src/rest/resource.hpp
@@ -42,7 +42,7 @@
 #include <openthread/border_router.h>
 
 #include "common/api_strings.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 #include "openthread/dataset.h"
 #include "openthread/dataset_ftd.h"
 #include "rest/json.hpp"
@@ -50,7 +50,7 @@
 #include "rest/response.hpp"
 #include "utils/thread_helper.hpp"
 
-using otbr::Ncp::ControllerOpenThread;
+using otbr::Ncp::RcpHost;
 using std::chrono::steady_clock;
 
 namespace otbr {
@@ -66,10 +66,10 @@ public:
     /**
      * The constructor initializes the resource handler instance.
      *
-     * @param[in] aNcp  A pointer to the NCP controller.
+     * @param[in] aHost  A pointer to the Thread controller.
      *
      */
-    Resource(ControllerOpenThread *aNcp);
+    Resource(RcpHost *aHost);
 
     /**
      * This method initialize the Resource handler.
@@ -160,8 +160,8 @@ private:
                                           void                *aContext);
     void        DiagnosticResponseHandler(otError aError, const otMessage *aMessage, const otMessageInfo *aMessageInfo);
 
-    otInstance           *mInstance;
-    ControllerOpenThread *mNcp;
+    otInstance *mInstance;
+    RcpHost    *mHost;
 
     std::unordered_map<std::string, ResourceHandler>         mResourceMap;
     std::unordered_map<std::string, ResourceCallbackHandler> mResourceCallbackMap;
diff --git a/src/rest/rest_web_server.cpp b/src/rest/rest_web_server.cpp
index 0327bb44..4e17acf6 100644
--- a/src/rest/rest_web_server.cpp
+++ b/src/rest/rest_web_server.cpp
@@ -47,8 +47,8 @@ namespace rest {
 // Maximum number of connection a server support at the same time.
 static const uint32_t kMaxServeNum = 500;
 
-RestWebServer::RestWebServer(ControllerOpenThread &aNcp, const std::string &aRestListenAddress, int aRestListenPort)
-    : mResource(Resource(&aNcp))
+RestWebServer::RestWebServer(RcpHost &aHost, const std::string &aRestListenAddress, int aRestListenPort)
+    : mResource(Resource(&aHost))
     , mListenFd(-1)
 {
     mAddress.sin6_family = AF_INET6;
@@ -79,8 +79,7 @@ void RestWebServer::Init(void)
 
 void RestWebServer::Update(MainloopContext &aMainloop)
 {
-    FD_SET(mListenFd, &aMainloop.mReadFdSet);
-    aMainloop.mMaxFd = std::max(aMainloop.mMaxFd, mListenFd);
+    aMainloop.AddFdToReadSet(mListenFd);
 
     return;
 }
diff --git a/src/rest/rest_web_server.hpp b/src/rest/rest_web_server.hpp
index 1da2e013..20e4a5b6 100644
--- a/src/rest/rest_web_server.hpp
+++ b/src/rest/rest_web_server.hpp
@@ -43,7 +43,7 @@
 #include "common/mainloop.hpp"
 #include "rest/connection.hpp"
 
-using otbr::Ncp::ControllerOpenThread;
+using otbr::Ncp::RcpHost;
 using std::chrono::steady_clock;
 
 namespace otbr {
@@ -59,10 +59,10 @@ public:
     /**
      * The constructor to initialize a REST server.
      *
-     * @param[in] aNcp  A reference to the NCP controller.
+     * @param[in] aHost  A reference to the Thread controller.
      *
      */
-    RestWebServer(ControllerOpenThread &aNcp, const std::string &aRestListenAddress, int aRestListenPort);
+    RestWebServer(RcpHost &aHost, const std::string &aRestListenAddress, int aRestListenPort);
 
     /**
      * The destructor destroys the server instance.
diff --git a/src/sdp_proxy/advertising_proxy.cpp b/src/sdp_proxy/advertising_proxy.cpp
index 16a93c4d..ea9dc316 100644
--- a/src/sdp_proxy/advertising_proxy.cpp
+++ b/src/sdp_proxy/advertising_proxy.cpp
@@ -51,54 +51,12 @@
 
 namespace otbr {
 
-static otError OtbrErrorToOtError(otbrError aError)
-{
-    otError error;
-
-    switch (aError)
-    {
-    case OTBR_ERROR_NONE:
-        error = OT_ERROR_NONE;
-        break;
-
-    case OTBR_ERROR_NOT_FOUND:
-        error = OT_ERROR_NOT_FOUND;
-        break;
-
-    case OTBR_ERROR_PARSE:
-        error = OT_ERROR_PARSE;
-        break;
-
-    case OTBR_ERROR_NOT_IMPLEMENTED:
-        error = OT_ERROR_NOT_IMPLEMENTED;
-        break;
-
-    case OTBR_ERROR_INVALID_ARGS:
-        error = OT_ERROR_INVALID_ARGS;
-        break;
-
-    case OTBR_ERROR_DUPLICATED:
-        error = OT_ERROR_DUPLICATED;
-        break;
-
-    case OTBR_ERROR_INVALID_STATE:
-        error = OT_ERROR_INVALID_STATE;
-        break;
-
-    default:
-        error = OT_ERROR_FAILED;
-        break;
-    }
-
-    return error;
-}
-
-AdvertisingProxy::AdvertisingProxy(Ncp::ControllerOpenThread &aNcp, Mdns::Publisher &aPublisher)
-    : mNcp(aNcp)
+AdvertisingProxy::AdvertisingProxy(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher)
+    : mHost(aHost)
     , mPublisher(aPublisher)
     , mIsEnabled(false)
 {
-    mNcp.RegisterResetHandler(
+    mHost.RegisterResetHandler(
         [this]() { otSrpServerSetServiceUpdateHandler(GetInstance(), AdvertisingHandler, this); });
 }
 
diff --git a/src/sdp_proxy/advertising_proxy.hpp b/src/sdp_proxy/advertising_proxy.hpp
index 99566930..4b1931d0 100644
--- a/src/sdp_proxy/advertising_proxy.hpp
+++ b/src/sdp_proxy/advertising_proxy.hpp
@@ -45,7 +45,7 @@
 
 #include "common/code_utils.hpp"
 #include "mdns/mdns.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 
@@ -59,11 +59,11 @@ public:
     /**
      * This constructor initializes the Advertising Proxy object.
      *
-     * @param[in] aNcp        A reference to the NCP controller.
+     * @param[in] aHost       A reference to the NCP controller.
      * @param[in] aPublisher  A reference to the mDNS publisher.
      *
      */
-    explicit AdvertisingProxy(Ncp::ControllerOpenThread &aNcp, Mdns::Publisher &aPublisher);
+    explicit AdvertisingProxy(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher);
 
     /**
      * This method enables/disables the Advertising Proxy.
@@ -126,10 +126,10 @@ private:
      */
     otbrError PublishHostAndItsServices(const otSrpServerHost *aHost, OutstandingUpdate *aUpdate);
 
-    otInstance *GetInstance(void) { return mNcp.GetInstance(); }
+    otInstance *GetInstance(void) { return mHost.GetInstance(); }
 
     // A reference to the NCP controller, has no ownership.
-    Ncp::ControllerOpenThread &mNcp;
+    Ncp::RcpHost &mHost;
 
     // A reference to the mDNS publisher, has no ownership.
     Mdns::Publisher &mPublisher;
diff --git a/src/sdp_proxy/discovery_proxy.cpp b/src/sdp_proxy/discovery_proxy.cpp
index ea0072aa..5aed48f8 100644
--- a/src/sdp_proxy/discovery_proxy.cpp
+++ b/src/sdp_proxy/discovery_proxy.cpp
@@ -58,13 +58,13 @@ static inline bool DnsLabelsEqual(const std::string &aLabel1, const std::string
     return StringUtils::EqualCaseInsensitive(aLabel1, aLabel2);
 }
 
-DiscoveryProxy::DiscoveryProxy(Ncp::ControllerOpenThread &aNcp, Mdns::Publisher &aPublisher)
-    : mNcp(aNcp)
+DiscoveryProxy::DiscoveryProxy(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher)
+    : mHost(aHost)
     , mMdnsPublisher(aPublisher)
     , mIsEnabled(false)
 {
-    mNcp.RegisterResetHandler([this]() {
-        otDnssdQuerySetCallbacks(mNcp.GetInstance(), &DiscoveryProxy::OnDiscoveryProxySubscribe,
+    mHost.RegisterResetHandler([this]() {
+        otDnssdQuerySetCallbacks(mHost.GetInstance(), &DiscoveryProxy::OnDiscoveryProxySubscribe,
                                  &DiscoveryProxy::OnDiscoveryProxyUnsubscribe, this);
     });
 }
@@ -89,7 +89,7 @@ void DiscoveryProxy::Start(void)
 {
     assert(mSubscriberId == 0);
 
-    otDnssdQuerySetCallbacks(mNcp.GetInstance(), &DiscoveryProxy::OnDiscoveryProxySubscribe,
+    otDnssdQuerySetCallbacks(mHost.GetInstance(), &DiscoveryProxy::OnDiscoveryProxySubscribe,
                              &DiscoveryProxy::OnDiscoveryProxyUnsubscribe, this);
 
     mSubscriberId = mMdnsPublisher.AddSubscriptionCallbacks(
@@ -109,7 +109,7 @@ void DiscoveryProxy::Start(void)
 
 void DiscoveryProxy::Stop(void)
 {
-    otDnssdQuerySetCallbacks(mNcp.GetInstance(), nullptr, nullptr, nullptr);
+    otDnssdQuerySetCallbacks(mHost.GetInstance(), nullptr, nullptr, nullptr);
 
     if (mSubscriberId > 0)
     {
@@ -200,7 +200,7 @@ void DiscoveryProxy::OnServiceDiscovered(const std::string
     instanceInfo.mTxtData   = aInstanceInfo.mTxtData.data();
     instanceInfo.mTtl       = CapTtl(aInstanceInfo.mTtl);
 
-    while ((query = otDnssdGetNextQuery(mNcp.GetInstance(), query)) != nullptr)
+    while ((query = otDnssdGetNextQuery(mHost.GetInstance(), query)) != nullptr)
     {
         std::string      instanceName;
         std::string      serviceName;
@@ -238,7 +238,7 @@ void DiscoveryProxy::OnServiceDiscovered(const std::string
             instanceInfo.mFullName = instanceFullName.c_str();
             instanceInfo.mHostName = translatedHostName.c_str();
 
-            otDnssdQueryHandleDiscoveredServiceInstance(mNcp.GetInstance(), serviceFullName.c_str(), &instanceInfo);
+            otDnssdQueryHandleDiscoveredServiceInstance(mHost.GetInstance(), serviceFullName.c_str(), &instanceInfo);
         }
     }
 }
@@ -270,7 +270,7 @@ void DiscoveryProxy::OnHostDiscovered(const std::string
 
     hostInfo.mTtl = CapTtl(aHostInfo.mTtl);
 
-    while ((query = otDnssdGetNextQuery(mNcp.GetInstance(), query)) != nullptr)
+    while ((query = otDnssdGetNextQuery(mHost.GetInstance(), query)) != nullptr)
     {
         std::string      hostName, domain;
         char             queryName[OT_DNS_MAX_NAME_SIZE];
@@ -295,7 +295,7 @@ void DiscoveryProxy::OnHostDiscovered(const std::string
         {
             std::string hostFullName = TranslateDomain(resolvedHostName, domain);
 
-            otDnssdQueryHandleDiscoveredHost(mNcp.GetInstance(), hostFullName.c_str(), &hostInfo);
+            otDnssdQueryHandleDiscoveredHost(mHost.GetInstance(), hostFullName.c_str(), &hostInfo);
         }
     }
 }
@@ -321,7 +321,7 @@ int DiscoveryProxy::GetServiceSubscriptionCount(const DnsNameInfo &aNameInfo) co
     const otDnssdQuery *query = nullptr;
     int                 count = 0;
 
-    while ((query = otDnssdGetNextQuery(mNcp.GetInstance(), query)) != nullptr)
+    while ((query = otDnssdGetNextQuery(mHost.GetInstance(), query)) != nullptr)
     {
         char        queryName[OT_DNS_MAX_NAME_SIZE];
         DnsNameInfo queryInfo;
diff --git a/src/sdp_proxy/discovery_proxy.hpp b/src/sdp_proxy/discovery_proxy.hpp
index c940e892..188a81bf 100644
--- a/src/sdp_proxy/discovery_proxy.hpp
+++ b/src/sdp_proxy/discovery_proxy.hpp
@@ -48,7 +48,7 @@
 
 #include "common/dns_utils.hpp"
 #include "mdns/mdns.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 namespace Dnssd {
@@ -63,11 +63,11 @@ public:
     /**
      * This constructor initializes the Discovery Proxy instance.
      *
-     * @param[in] aNcp        A reference to the OpenThread Controller instance.
+     * @param[in] aHost       A reference to the OpenThread Controller instance.
      * @param[in] aPublisher  A reference to the mDNS Publisher.
      *
      */
-    explicit DiscoveryProxy(Ncp::ControllerOpenThread &aNcp, Mdns::Publisher &aPublisher);
+    explicit DiscoveryProxy(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher);
 
     /**
      * This method enables/disables the Discovery Proxy.
@@ -112,10 +112,10 @@ private:
     void Stop(void);
     bool IsEnabled(void) const { return mIsEnabled; }
 
-    Ncp::ControllerOpenThread &mNcp;
-    Mdns::Publisher           &mMdnsPublisher;
-    bool                       mIsEnabled;
-    uint64_t                   mSubscriberId = 0;
+    Ncp::RcpHost    &mHost;
+    Mdns::Publisher &mMdnsPublisher;
+    bool             mIsEnabled;
+    uint64_t         mSubscriberId = 0;
 };
 
 } // namespace Dnssd
diff --git a/src/trel_dnssd/trel_dnssd.cpp b/src/trel_dnssd/trel_dnssd.cpp
index e328ae39..7cf4adc2 100644
--- a/src/trel_dnssd/trel_dnssd.cpp
+++ b/src/trel_dnssd/trel_dnssd.cpp
@@ -81,9 +81,9 @@ namespace otbr {
 
 namespace TrelDnssd {
 
-TrelDnssd::TrelDnssd(Ncp::ControllerOpenThread &aNcp, Mdns::Publisher &aPublisher)
+TrelDnssd::TrelDnssd(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher)
     : mPublisher(aPublisher)
-    , mNcp(aNcp)
+    , mHost(aHost)
 {
     sTrelDnssd = this;
 }
@@ -229,7 +229,7 @@ exit:
 
 std::string TrelDnssd::GetTrelInstanceName(void)
 {
-    const otExtAddress *extaddr = otLinkGetExtendedAddress(mNcp.GetInstance());
+    const otExtAddress *extaddr = otLinkGetExtendedAddress(mHost.GetInstance());
     std::string         name;
     char                nameBuf[sizeof(otExtAddress) * 2 + 1];
 
@@ -331,7 +331,7 @@ void TrelDnssd::OnTrelServiceInstanceAdded(const Mdns::Publisher::DiscoveredInst
 
         VerifyOrExit(peer.mValid, otbrLogWarning("Peer %s is invalid", aInstanceInfo.mName.c_str()));
 
-        otPlatTrelHandleDiscoveredPeerInfo(mNcp.GetInstance(), &peerInfo);
+        otPlatTrelHandleDiscoveredPeerInfo(mHost.GetInstance(), &peerInfo);
 
         mPeers.emplace(instanceName, peer);
         CheckPeersNumLimit();
@@ -392,7 +392,7 @@ void TrelDnssd::NotifyRemovePeer(const Peer &aPeer)
     peerInfo.mTxtLength = aPeer.mTxtData.size();
     peerInfo.mSockAddr  = aPeer.mSockAddr;
 
-    otPlatTrelHandleDiscoveredPeerInfo(mNcp.GetInstance(), &peerInfo);
+    otPlatTrelHandleDiscoveredPeerInfo(mHost.GetInstance(), &peerInfo);
 }
 
 void TrelDnssd::RemoveAllPeers(void)
diff --git a/src/trel_dnssd/trel_dnssd.hpp b/src/trel_dnssd/trel_dnssd.hpp
index c22e7ba3..6c8555c9 100644
--- a/src/trel_dnssd/trel_dnssd.hpp
+++ b/src/trel_dnssd/trel_dnssd.hpp
@@ -45,7 +45,7 @@
 
 #include "common/types.hpp"
 #include "mdns/mdns.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 
@@ -66,11 +66,11 @@ public:
     /**
      * This constructor initializes the TrelDnssd instance.
      *
-     * @param[in] aNcp        A reference to the OpenThread Controller instance.
+     * @param[in] aHost       A reference to the OpenThread Controller instance.
      * @param[in] aPublisher  A reference to the mDNS Publisher.
      *
      */
-    explicit TrelDnssd(Ncp::ControllerOpenThread &aNcp, Mdns::Publisher &aPublisher);
+    explicit TrelDnssd(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher);
 
     /**
      * This method initializes the TrelDnssd instance.
@@ -176,15 +176,15 @@ private:
     void     RemoveAllPeers(void);
     uint16_t CountDuplicatePeers(const Peer &aPeer);
 
-    Mdns::Publisher           &mPublisher;
-    Ncp::ControllerOpenThread &mNcp;
-    TaskRunner                 mTaskRunner;
-    std::string                mTrelNetif;
-    uint32_t                   mTrelNetifIndex = 0;
-    uint64_t                   mSubscriberId   = 0;
-    RegisterInfo               mRegisterInfo;
-    PeerMap                    mPeers;
-    bool                       mMdnsPublisherReady = false;
+    Mdns::Publisher &mPublisher;
+    Ncp::RcpHost    &mHost;
+    TaskRunner       mTaskRunner;
+    std::string      mTrelNetif;
+    uint32_t         mTrelNetifIndex = 0;
+    uint64_t         mSubscriberId   = 0;
+    RegisterInfo     mRegisterInfo;
+    PeerMap          mPeers;
+    bool             mMdnsPublisherReady = false;
 };
 
 /**
diff --git a/src/utils/infra_link_selector.cpp b/src/utils/infra_link_selector.cpp
index 0f2760be..ac239ab9 100644
--- a/src/utils/infra_link_selector.cpp
+++ b/src/utils/infra_link_selector.cpp
@@ -235,8 +235,7 @@ void InfraLinkSelector::Update(MainloopContext &aMainloop)
 {
     if (mNetlinkSocket != -1)
     {
-        FD_SET(mNetlinkSocket, &aMainloop.mReadFdSet);
-        aMainloop.mMaxFd = std::max(mNetlinkSocket, aMainloop.mMaxFd);
+        aMainloop.AddFdToReadSet(mNetlinkSocket);
     }
 }
 
diff --git a/src/utils/thread_helper.cpp b/src/utils/thread_helper.cpp
index b6419353..b7b62163 100644
--- a/src/utils/thread_helper.cpp
+++ b/src/utils/thread_helper.cpp
@@ -35,6 +35,7 @@
 #include <string.h>
 #include <time.h>
 
+#include <openthread/border_agent.h>
 #include <openthread/border_router.h>
 #include <openthread/channel_manager.h>
 #include <openthread/dataset_ftd.h>
@@ -61,13 +62,14 @@
 #if OTBR_ENABLE_TREL
 #include <openthread/trel.h>
 #endif
+#include <net/if.h>
 #include <openthread/platform/radio.h>
 
 #include "common/byteswap.hpp"
 #include "common/code_utils.hpp"
 #include "common/logging.hpp"
 #include "common/tlv.hpp"
-#include "ncp/ncp_openthread.hpp"
+#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 namespace agent {
@@ -226,9 +228,9 @@ void CopyMdnsResponseCounters(const MdnsResponseCounters &from, threadnetwork::T
 #endif // OTBR_ENABLE_TELEMETRY_DATA_API
 } // namespace
 
-ThreadHelper::ThreadHelper(otInstance *aInstance, otbr::Ncp::ControllerOpenThread *aNcp)
+ThreadHelper::ThreadHelper(otInstance *aInstance, otbr::Ncp::RcpHost *aHost)
     : mInstance(aInstance)
-    , mNcp(aNcp)
+    , mHost(aHost)
 {
 #if OTBR_ENABLE_TELEMETRY_DATA_API && (OTBR_ENABLE_NAT64 || OTBR_ENABLE_DHCP6_PD)
     otError error;
@@ -247,7 +249,7 @@ void ThreadHelper::StateChangedCallback(otChangedFlags aFlags)
 {
     if (aFlags & OT_CHANGED_THREAD_ROLE)
     {
-        otDeviceRole role = otThreadGetDeviceRole(mInstance);
+        otDeviceRole role = mHost->GetDeviceRole();
 
         for (const auto &handler : mDeviceRoleHandlers)
         {
@@ -425,6 +427,29 @@ void ThreadHelper::ActiveScanHandler(otActiveScanResult *aResult)
     }
 }
 
+#if OTBR_ENABLE_DHCP6_PD
+void ThreadHelper::SetDhcp6PdStateCallback(Dhcp6PdStateCallback aCallback)
+{
+    mDhcp6PdCallback = std::move(aCallback);
+    otBorderRoutingDhcp6PdSetRequestCallback(mInstance, &ThreadHelper::BorderRoutingDhcp6PdCallback, this);
+}
+
+void ThreadHelper::BorderRoutingDhcp6PdCallback(otBorderRoutingDhcp6PdState aState, void *aThreadHelper)
+{
+    ThreadHelper *helper = static_cast<ThreadHelper *>(aThreadHelper);
+
+    helper->BorderRoutingDhcp6PdCallback(aState);
+}
+
+void ThreadHelper::BorderRoutingDhcp6PdCallback(otBorderRoutingDhcp6PdState aState)
+{
+    if (mDhcp6PdCallback != nullptr)
+    {
+        mDhcp6PdCallback(aState);
+    }
+}
+#endif // OTBR_ENABLE_DHCP6_PD
+
 void ThreadHelper::EnergyScanCallback(otEnergyScanResult *aResult, void *aThreadHelper)
 {
     ThreadHelper *helper = static_cast<ThreadHelper *>(aThreadHelper);
@@ -646,7 +671,7 @@ otError ThreadHelper::TryResumeNetwork(void)
 {
     otError error = OT_ERROR_NONE;
 
-    if (otLinkGetPanId(mInstance) != UINT16_MAX && otThreadGetDeviceRole(mInstance) == OT_DEVICE_ROLE_DISABLED)
+    if (otLinkGetPanId(mInstance) != UINT16_MAX && mHost->GetDeviceRole() == OT_DEVICE_ROLE_DISABLED)
     {
         if (!otIp6IsEnabled(mInstance))
         {
@@ -684,10 +709,7 @@ void ThreadHelper::AttachAllNodesTo(const std::vector<uint8_t> &aDatasetTlvs, At
     otOperationalDatasetTlvs datasetTlvs;
     otOperationalDataset     dataset;
     otOperationalDataset     emptyDataset{};
-    otDeviceRole             role = otThreadGetDeviceRole(mInstance);
-    Tlv                     *tlv;
-    uint64_t                 pendingTimestamp = 0;
-    timespec                 currentTime;
+    otDeviceRole             role = mHost->GetDeviceRole();
 
     if (aHandler == nullptr)
     {
@@ -712,30 +734,7 @@ void ThreadHelper::AttachAllNodesTo(const std::vector<uint8_t> &aDatasetTlvs, At
     VerifyOrExit(dataset.mComponents.mIsSecurityPolicyPresent, error = OT_ERROR_INVALID_ARGS);
     VerifyOrExit(dataset.mComponents.mIsChannelMaskPresent, error = OT_ERROR_INVALID_ARGS);
 
-    VerifyOrExit(FindTlv(OT_MESHCOP_TLV_PENDINGTIMESTAMP, datasetTlvs.mTlvs, datasetTlvs.mLength) == nullptr &&
-                     FindTlv(OT_MESHCOP_TLV_DELAYTIMER, datasetTlvs.mTlvs, datasetTlvs.mLength) == nullptr,
-                 error = OT_ERROR_INVALID_ARGS);
-
-    // There must be sufficient space for a Pending Timestamp TLV and a Delay Timer TLV.
-    VerifyOrExit(
-        static_cast<int>(datasetTlvs.mLength +
-                         (sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t))    // Pending Timestamp TLV (10 bytes)
-                         + (sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t))) // Delay Timer TLV (6 bytes)
-            <= int{sizeof(datasetTlvs.mTlvs)},
-        error = OT_ERROR_INVALID_ARGS);
-
-    tlv = reinterpret_cast<Tlv *>(datasetTlvs.mTlvs + datasetTlvs.mLength);
-    tlv->SetType(OT_MESHCOP_TLV_PENDINGTIMESTAMP);
-    clock_gettime(CLOCK_REALTIME, &currentTime);
-    pendingTimestamp |= (static_cast<uint64_t>(currentTime.tv_sec) << 16);
-    pendingTimestamp |= (((static_cast<uint64_t>(currentTime.tv_nsec) * 32768 / 1000000000) & 0x7fff) << 1);
-    tlv->SetValue(pendingTimestamp);
-
-    tlv = tlv->GetNext();
-    tlv->SetType(OT_MESHCOP_TLV_DELAYTIMER);
-    tlv->SetValue(kDelayTimerMilliseconds);
-
-    datasetTlvs.mLength = reinterpret_cast<uint8_t *>(tlv->GetNext()) - datasetTlvs.mTlvs;
+    SuccessOrExit(error = ProcessDatasetForMigration(datasetTlvs, kDelayTimerMilliseconds));
 
     assert(datasetTlvs.mLength > 0);
 
@@ -854,7 +853,7 @@ otError ThreadHelper::PermitUnsecureJoin(uint16_t aPort, uint32_t aSeconds)
 
         ++mUnsecurePortRefCounter[aPort];
 
-        mNcp->PostTimerTask(delay, [this, aPort]() {
+        mHost->PostTimerTask(delay, [this, aPort]() {
             assert(mUnsecurePortRefCounter.find(aPort) != mUnsecurePortRefCounter.end());
             assert(mUnsecurePortRefCounter[aPort] > 0);
 
@@ -919,6 +918,175 @@ void ThreadHelper::DetachGracefullyCallback(void)
 }
 
 #if OTBR_ENABLE_TELEMETRY_DATA_API
+#if OTBR_ENABLE_BORDER_ROUTING
+void ThreadHelper::RetrieveInfraLinkInfo(threadnetwork::TelemetryData::InfraLinkInfo &aInfraLinkInfo)
+{
+    {
+        otSysInfraNetIfAddressCounters addressCounters;
+        uint32_t                       ifrFlags = otSysGetInfraNetifFlags();
+
+        otSysCountInfraNetifAddresses(&addressCounters);
+
+        aInfraLinkInfo.set_name(otSysGetInfraNetifName());
+        aInfraLinkInfo.set_is_up((ifrFlags & IFF_UP) != 0);
+        aInfraLinkInfo.set_is_running((ifrFlags & IFF_RUNNING) != 0);
+        aInfraLinkInfo.set_is_multicast((ifrFlags & IFF_MULTICAST) != 0);
+        aInfraLinkInfo.set_link_local_address_count(addressCounters.mLinkLocalAddresses);
+        aInfraLinkInfo.set_unique_local_address_count(addressCounters.mUniqueLocalAddresses);
+        aInfraLinkInfo.set_global_unicast_address_count(addressCounters.mGlobalUnicastAddresses);
+    }
+
+    //---- peer_br_count
+    {
+        uint32_t                           count = 0;
+        otBorderRoutingPrefixTableIterator iterator;
+        otBorderRoutingRouterEntry         entry;
+
+        otBorderRoutingPrefixTableInitIterator(mInstance, &iterator);
+
+        while (otBorderRoutingGetNextRouterEntry(mInstance, &iterator, &entry) == OT_ERROR_NONE)
+        {
+            if (entry.mIsPeerBr)
+            {
+                count++;
+            }
+        }
+
+        aInfraLinkInfo.set_peer_br_count(count);
+    }
+}
+
+void ThreadHelper::RetrieveExternalRouteInfo(threadnetwork::TelemetryData::ExternalRoutes &aExternalRouteInfo)
+{
+    bool      isDefaultRouteAdded = false;
+    bool      isUlaRouteAdded     = false;
+    bool      isOthersRouteAdded  = false;
+    Ip6Prefix prefix;
+    uint16_t  rloc16 = otThreadGetRloc16(mInstance);
+
+    otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;
+    otExternalRouteConfig config;
+
+    while (otNetDataGetNextRoute(mInstance, &iterator, &config) == OT_ERROR_NONE)
+    {
+        if (!config.mStable || config.mRloc16 != rloc16)
+        {
+            continue;
+        }
+
+        prefix.Set(config.mPrefix);
+        if (prefix.IsDefaultRoutePrefix())
+        {
+            isDefaultRouteAdded = true;
+        }
+        else if (prefix.IsUlaPrefix())
+        {
+            isUlaRouteAdded = true;
+        }
+        else
+        {
+            isOthersRouteAdded = true;
+        }
+    }
+
+    aExternalRouteInfo.set_has_default_route_added(isDefaultRouteAdded);
+    aExternalRouteInfo.set_has_ula_route_added(isUlaRouteAdded);
+    aExternalRouteInfo.set_has_others_route_added(isOthersRouteAdded);
+}
+#endif // OTBR_ENABLE_BORDER_ROUTING
+
+#if OTBR_ENABLE_DHCP6_PD
+void ThreadHelper::RetrievePdInfo(threadnetwork::TelemetryData::WpanBorderRouter *aWpanBorderRouter)
+{
+    aWpanBorderRouter->set_dhcp6_pd_state(Dhcp6PdStateFromOtDhcp6PdState(otBorderRoutingDhcp6PdGetState(mInstance)));
+    RetrieveHashedPdPrefix(aWpanBorderRouter->mutable_hashed_pd_prefix());
+    RetrievePdProcessedRaInfo(aWpanBorderRouter->mutable_pd_processed_ra_info());
+}
+
+void ThreadHelper::RetrieveHashedPdPrefix(std::string *aHashedPdPrefix)
+{
+    otBorderRoutingPrefixTableEntry aPrefixInfo;
+    const uint8_t                  *prefixAddr          = nullptr;
+    const uint8_t                  *truncatedHash       = nullptr;
+    constexpr size_t                kHashPrefixLength   = 6;
+    constexpr size_t                kHashedPrefixLength = 2;
+    std::vector<uint8_t>            hashedPdHeader      = {0x20, 0x01, 0x0d, 0xb8};
+    std::vector<uint8_t>            hashedPdTailer      = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
+    std::vector<uint8_t>            hashedPdPrefix;
+    hashedPdPrefix.reserve(16);
+    Sha256       sha256;
+    Sha256::Hash hash;
+
+    SuccessOrExit(otBorderRoutingGetPdOmrPrefix(mInstance, &aPrefixInfo));
+    prefixAddr = aPrefixInfo.mPrefix.mPrefix.mFields.m8;
+
+    // TODO: Put below steps into a reusable function.
+    sha256.Start();
+    sha256.Update(prefixAddr, kHashPrefixLength);
+    sha256.Update(mNat64PdCommonSalt, kNat64PdCommonHashSaltLength);
+    sha256.Finish(hash);
+
+    // Append hashedPdHeader
+    hashedPdPrefix.insert(hashedPdPrefix.end(), hashedPdHeader.begin(), hashedPdHeader.end());
+
+    // Append the first 2 bytes of the hashed prefix
+    truncatedHash = hash.GetBytes();
+    hashedPdPrefix.insert(hashedPdPrefix.end(), truncatedHash, truncatedHash + kHashedPrefixLength);
+
+    // Append ip[6] and ip[7]
+    hashedPdPrefix.push_back(prefixAddr[6]);
+    hashedPdPrefix.push_back(prefixAddr[7]);
+
+    // Append hashedPdTailer
+    hashedPdPrefix.insert(hashedPdPrefix.end(), hashedPdTailer.begin(), hashedPdTailer.end());
+
+    aHashedPdPrefix->append(reinterpret_cast<const char *>(hashedPdPrefix.data()), hashedPdPrefix.size());
+
+exit:
+    return;
+}
+
+void ThreadHelper::RetrievePdProcessedRaInfo(threadnetwork::TelemetryData::PdProcessedRaInfo *aPdProcessedRaInfo)
+{
+    otPdProcessedRaInfo raInfo;
+
+    SuccessOrExit(otBorderRoutingGetPdProcessedRaInfo(mInstance, &raInfo));
+    aPdProcessedRaInfo->set_num_platform_ra_received(raInfo.mNumPlatformRaReceived);
+    aPdProcessedRaInfo->set_num_platform_pio_processed(raInfo.mNumPlatformPioProcessed);
+    aPdProcessedRaInfo->set_last_platform_ra_msec(raInfo.mLastPlatformRaMsec);
+
+exit:
+    return;
+}
+#endif // OTBR_ENABLE_DHCP6_PD
+
+#if OTBR_ENABLE_BORDER_AGENT
+void ThreadHelper::RetrieveBorderAgentInfo(threadnetwork::TelemetryData::BorderAgentInfo *aBorderAgentInfo)
+{
+    auto baCounters            = aBorderAgentInfo->mutable_border_agent_counters();
+    auto otBorderAgentCounters = *otBorderAgentGetCounters(mInstance);
+
+    baCounters->set_epskc_activations(otBorderAgentCounters.mEpskcActivations);
+    baCounters->set_epskc_deactivation_clears(otBorderAgentCounters.mEpskcDeactivationClears);
+    baCounters->set_epskc_deactivation_timeouts(otBorderAgentCounters.mEpskcDeactivationTimeouts);
+    baCounters->set_epskc_deactivation_max_attempts(otBorderAgentCounters.mEpskcDeactivationMaxAttempts);
+    baCounters->set_epskc_deactivation_disconnects(otBorderAgentCounters.mEpskcDeactivationDisconnects);
+    baCounters->set_epskc_invalid_ba_state_errors(otBorderAgentCounters.mEpskcInvalidBaStateErrors);
+    baCounters->set_epskc_invalid_args_errors(otBorderAgentCounters.mEpskcInvalidArgsErrors);
+    baCounters->set_epskc_start_secure_session_errors(otBorderAgentCounters.mEpskcStartSecureSessionErrors);
+    baCounters->set_epskc_secure_session_successes(otBorderAgentCounters.mEpskcSecureSessionSuccesses);
+    baCounters->set_epskc_secure_session_failures(otBorderAgentCounters.mEpskcSecureSessionFailures);
+    baCounters->set_epskc_commissioner_petitions(otBorderAgentCounters.mEpskcCommissionerPetitions);
+
+    baCounters->set_pskc_secure_session_successes(otBorderAgentCounters.mPskcSecureSessionSuccesses);
+    baCounters->set_pskc_secure_session_failures(otBorderAgentCounters.mPskcSecureSessionFailures);
+    baCounters->set_pskc_commissioner_petitions(otBorderAgentCounters.mPskcCommissionerPetitions);
+
+    baCounters->set_mgmt_active_get_reqs(otBorderAgentCounters.mMgmtActiveGets);
+    baCounters->set_mgmt_pending_get_reqs(otBorderAgentCounters.mMgmtPendingGets);
+}
+#endif
+
 otError ThreadHelper::RetrieveTelemetryData(Mdns::Publisher *aPublisher, threadnetwork::TelemetryData &telemetryData)
 {
     otError                     error = OT_ERROR_NONE;
@@ -928,7 +1096,7 @@ otError ThreadHelper::RetrieveTelemetryData(Mdns::Publisher *aPublisher, threadn
     auto wpanStats = telemetryData.mutable_wpan_stats();
 
     {
-        otDeviceRole     role  = otThreadGetDeviceRole(mInstance);
+        otDeviceRole     role  = mHost->GetDeviceRole();
         otLinkModeConfig otCfg = otThreadGetLinkMode(mInstance);
 
         wpanStats->set_node_type(TelemetryNodeTypeFromRoleAndLinkMode(role, otCfg));
@@ -1105,6 +1273,9 @@ otError ThreadHelper::RetrieveTelemetryData(Mdns::Publisher *aPublisher, threadn
 
         extPanIdVal = ConvertOpenThreadUint64(extPanId->m8);
         wpanTopoFull->set_extended_pan_id(extPanIdVal);
+#if OTBR_ENABLE_BORDER_ROUTING
+        wpanTopoFull->set_peer_br_count(otBorderRoutingCountPeerBrs(mInstance, /*minAge=*/nullptr));
+#endif
         // End of WpanTopoFull section.
 
         // Begin of TopoEntry section.
@@ -1262,6 +1433,11 @@ otError ThreadHelper::RetrieveTelemetryData(Mdns::Publisher *aPublisher, threadn
         // End of TrelInfo section.
 #endif // OTBR_ENABLE_TREL
 
+#if OTBR_ENABLE_BORDER_ROUTING
+        RetrieveInfraLinkInfo(*wpanBorderRouter->mutable_infra_link_info());
+        RetrieveExternalRouteInfo(*wpanBorderRouter->mutable_external_route_info());
+#endif
+
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
         // Begin of SrpServerInfo section.
         {
@@ -1421,63 +1597,11 @@ otError ThreadHelper::RetrieveTelemetryData(Mdns::Publisher *aPublisher, threadn
         // End of Nat64Mapping section.
 #endif // OTBR_ENABLE_NAT64
 #if OTBR_ENABLE_DHCP6_PD
-        // Start of Dhcp6PdState section.
-        wpanBorderRouter->set_dhcp6_pd_state(Dhcp6PdStateFromOtDhcp6PdState(otBorderRoutingDhcp6PdGetState(mInstance)));
-        // End of Dhcp6PdState section.
-
-        // Start of Hashed PD prefix
-        {
-            otBorderRoutingPrefixTableEntry aPrefixInfo;
-            const uint8_t                  *prefixAddr          = nullptr;
-            const uint8_t                  *truncatedHash       = nullptr;
-            constexpr size_t                kHashPrefixLength   = 6;
-            constexpr size_t                kHashedPrefixLength = 2;
-            std::vector<uint8_t>            hashedPdHeader      = {0x20, 0x01, 0x0d, 0xb8};
-            std::vector<uint8_t>            hashedPdTailer      = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
-            std::vector<uint8_t>            hashedPdPrefix;
-            hashedPdPrefix.reserve(16);
-            Sha256       sha256;
-            Sha256::Hash hash;
-
-            otBorderRoutingGetPdOmrPrefix(mInstance, &aPrefixInfo);
-            prefixAddr = aPrefixInfo.mPrefix.mPrefix.mFields.m8;
-
-            // TODO: Put below steps into a reusable function.
-            sha256.Start();
-            sha256.Update(prefixAddr, kHashPrefixLength);
-            sha256.Update(mNat64PdCommonSalt, kNat64PdCommonHashSaltLength);
-            sha256.Finish(hash);
-
-            // Append hashedPdHeader
-            hashedPdPrefix.insert(hashedPdPrefix.end(), hashedPdHeader.begin(), hashedPdHeader.end());
-
-            // Append the first 2 bytes of the hashed prefix
-            truncatedHash = hash.GetBytes();
-            hashedPdPrefix.insert(hashedPdPrefix.end(), truncatedHash, truncatedHash + kHashedPrefixLength);
-
-            // Append ip[6] and ip[7]
-            hashedPdPrefix.push_back(prefixAddr[6]);
-            hashedPdPrefix.push_back(prefixAddr[7]);
-
-            // Append hashedPdTailer
-            hashedPdPrefix.insert(hashedPdPrefix.end(), hashedPdTailer.begin(), hashedPdTailer.end());
-
-            wpanBorderRouter->mutable_hashed_pd_prefix()->append(reinterpret_cast<const char *>(hashedPdPrefix.data()),
-                                                                 hashedPdPrefix.size());
-        }
-        // End of Hashed PD prefix
-        // Start of DHCPv6 PD processed RA Info
-        {
-            auto                pdProcessedRaInfo = wpanBorderRouter->mutable_pd_processed_ra_info();
-            otPdProcessedRaInfo raInfo;
-
-            otBorderRoutingGetPdProcessedRaInfo(mInstance, &raInfo);
-            pdProcessedRaInfo->set_num_platform_ra_received(raInfo.mNumPlatformRaReceived);
-            pdProcessedRaInfo->set_num_platform_pio_processed(raInfo.mNumPlatformPioProcessed);
-            pdProcessedRaInfo->set_last_platform_ra_msec(raInfo.mLastPlatformRaMsec);
-        }
-        // End of DHCPv6 PD processed RA Info
+        RetrievePdInfo(wpanBorderRouter);
 #endif // OTBR_ENABLE_DHCP6_PD
+#if OTBR_ENABLE_BORDER_AGENT
+        RetrieveBorderAgentInfo(wpanBorderRouter->mutable_border_agent_info());
+#endif // OTBR_ENABLE_BORDER_AGENT
        // End of WpanBorderRouter section.
 
         // Start of WpanRcp section.
@@ -1575,5 +1699,52 @@ otError ThreadHelper::RetrieveTelemetryData(Mdns::Publisher *aPublisher, threadn
     return error;
 }
 #endif // OTBR_ENABLE_TELEMETRY_DATA_API
+
+otError ThreadHelper::ProcessDatasetForMigration(otOperationalDatasetTlvs &aDatasetTlvs, uint32_t aDelayMilli)
+{
+    otError  error = OT_ERROR_NONE;
+    Tlv     *tlv;
+    timespec currentTime;
+    uint64_t pendingTimestamp = 0;
+
+    VerifyOrExit(FindTlv(OT_MESHCOP_TLV_PENDINGTIMESTAMP, aDatasetTlvs.mTlvs, aDatasetTlvs.mLength) == nullptr,
+                 error = OT_ERROR_INVALID_ARGS);
+    VerifyOrExit(FindTlv(OT_MESHCOP_TLV_DELAYTIMER, aDatasetTlvs.mTlvs, aDatasetTlvs.mLength) == nullptr,
+                 error = OT_ERROR_INVALID_ARGS);
+
+    // There must be sufficient space for a Pending Timestamp TLV and a Delay Timer TLV.
+    VerifyOrExit(
+        static_cast<int>(aDatasetTlvs.mLength +
+                         (sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t))    // Pending Timestamp TLV (10 bytes)
+                         + (sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t))) // Delay Timer TLV (6 bytes)
+            <= int{sizeof(aDatasetTlvs.mTlvs)},
+        error = OT_ERROR_INVALID_ARGS);
+
+    tlv = reinterpret_cast<Tlv *>(aDatasetTlvs.mTlvs + aDatasetTlvs.mLength);
+    /*
+     * Pending Timestamp TLV
+     *
+     * | Type | Value | Timestamp Seconds | Timestamp Ticks | U bit |
+     * |  8   |   8   |         48        |         15      |   1   |
+     *
+     */
+    tlv->SetType(OT_MESHCOP_TLV_PENDINGTIMESTAMP);
+    clock_gettime(CLOCK_REALTIME, &currentTime);
+    pendingTimestamp |= (static_cast<uint64_t>(currentTime.tv_sec) << 16); // Set the 48 bits of Timestamp seconds.
+    pendingTimestamp |= (((static_cast<uint64_t>(currentTime.tv_nsec) * 32768 / 1000000000) & 0x7fff)
+                         << 1); // Set the 15 bits of Timestamp ticks, the fractional Unix Time value in 32.768 kHz
+                                // resolution. Leave the U-bit unset.
+    tlv->SetValue(pendingTimestamp);
+
+    tlv = tlv->GetNext();
+    tlv->SetType(OT_MESHCOP_TLV_DELAYTIMER);
+    tlv->SetValue(aDelayMilli);
+
+    aDatasetTlvs.mLength = reinterpret_cast<uint8_t *>(tlv->GetNext()) - aDatasetTlvs.mTlvs;
+
+exit:
+    return error;
+}
+
 } // namespace agent
 } // namespace otbr
diff --git a/src/utils/thread_helper.hpp b/src/utils/thread_helper.hpp
index aa5f0957..162b6b5c 100644
--- a/src/utils/thread_helper.hpp
+++ b/src/utils/thread_helper.hpp
@@ -43,6 +43,7 @@
 #include <string>
 #include <vector>
 
+#include <openthread/border_routing.h>
 #include <openthread/instance.h>
 #include <openthread/ip6.h>
 #include <openthread/jam_detection.h>
@@ -56,7 +57,7 @@
 
 namespace otbr {
 namespace Ncp {
-class ControllerOpenThread;
+class RcpHost;
 }
 } // namespace otbr
 
@@ -76,15 +77,18 @@ public:
     using AttachHandler           = std::function<void(otError, int64_t)>;
     using UpdateMeshCopTxtHandler = std::function<void(std::map<std::string, std::vector<uint8_t>>)>;
     using DatasetChangeHandler    = std::function<void(const otOperationalDatasetTlvs &)>;
+#if OTBR_ENABLE_DHCP6_PD
+    using Dhcp6PdStateCallback = std::function<void(otBorderRoutingDhcp6PdState)>;
+#endif
 
     /**
      * The constructor of a Thread helper.
      *
      * @param[in] aInstance  The Thread instance.
-     * @param[in] aNcp       The ncp controller.
+     * @param[in] aHost      The Thread controller.
      *
      */
-    ThreadHelper(otInstance *aInstance, otbr::Ncp::ControllerOpenThread *aNcp);
+    ThreadHelper(otInstance *aInstance, otbr::Ncp::RcpHost *aHost);
 
     /**
      * This method adds a callback for device role change.
@@ -94,6 +98,16 @@ public:
      */
     void AddDeviceRoleHandler(DeviceRoleHandler aHandler);
 
+#if OTBR_ENABLE_DHCP6_PD
+    /**
+     * This method adds a callback for DHCPv6 PD state change.
+     *
+     * @param[in] aCallback  The DHCPv6 PD state change callback.
+     *
+     */
+    void SetDhcp6PdStateCallback(Dhcp6PdStateCallback aCallback);
+#endif
+
     /**
      * This method adds a callback for active dataset change.
      *
@@ -223,7 +237,10 @@ public:
      * @returns The underlying instance.
      *
      */
-    otInstance *GetInstance(void) { return mInstance; }
+    otInstance *GetInstance(void)
+    {
+        return mInstance;
+    }
 
     /**
      * This method handles OpenThread state changed notification.
@@ -281,6 +298,25 @@ public:
      */
     static void LogOpenThreadResult(const char *aAction, otError aError);
 
+    /**
+     * This method validates and updates a pending dataset do Thread network migration.
+     *
+     * This method validates that:
+     * 1. the given dataset doesn't contain a meshcop Pending Timestamp TLV or a meshcop Delay Timer TLV.
+     * 2. the given dataset has sufficient space to append a Pending Timestamp TLV and a Delay Timer TLV.
+     *
+     * If it's valid, the method will append a meshcop Pending Timestamp TLV with value being the current unix
+     * timestamp and a meshcop Delay Timer TLV with value being @p aDelayMilli.
+     *
+     * @param[in/out] aDatasetTlvs  The dataset to validate and process in TLVs format.
+     * @param[in]     aDelayMilli   The delay time for migration in milliseconds.
+     *
+     * @retval OT_ERROR_NONE          Dataset is valid to do Thread network migration.
+     * @retval OT_ERROR_INVALID_ARGS  Dataset is invalid to do Thread network migration.
+     *
+     */
+    static otError ProcessDatasetForMigration(otOperationalDatasetTlvs &aDatasetTlvs, uint32_t aDelayMilli);
+
 private:
     static void ActiveScanHandler(otActiveScanResult *aResult, void *aThreadHelper);
     void        ActiveScanHandler(otActiveScanResult *aResult);
@@ -302,9 +338,28 @@ private:
 
     void ActiveDatasetChangedCallback(void);
 
+#if OTBR_ENABLE_DHCP6_PD
+    static void BorderRoutingDhcp6PdCallback(otBorderRoutingDhcp6PdState aState, void *aThreadHelper);
+    void        BorderRoutingDhcp6PdCallback(otBorderRoutingDhcp6PdState aState);
+#endif
+#if OTBR_ENABLE_TELEMETRY_DATA_API
+#if OTBR_ENABLE_BORDER_ROUTING
+    void RetrieveInfraLinkInfo(threadnetwork::TelemetryData::InfraLinkInfo &aInfraLinkInfo);
+    void RetrieveExternalRouteInfo(threadnetwork::TelemetryData::ExternalRoutes &aExternalRouteInfo);
+#endif
+#if OTBR_ENABLE_DHCP6_PD
+    void RetrievePdInfo(threadnetwork::TelemetryData::WpanBorderRouter *aWpanBorderRouter);
+    void RetrieveHashedPdPrefix(std::string *aHashedPdPrefix);
+    void RetrievePdProcessedRaInfo(threadnetwork::TelemetryData::PdProcessedRaInfo *aPdProcessedRaInfo);
+#endif
+#if OTBR_ENABLE_BORDER_AGENT
+    void RetrieveBorderAgentInfo(threadnetwork::TelemetryData::BorderAgentInfo *aBorderAgentInfo);
+#endif
+#endif // OTBR_ENABLE_TELEMETRY_DATA_API
+
     otInstance *mInstance;
 
-    otbr::Ncp::ControllerOpenThread *mNcp;
+    otbr::Ncp::RcpHost *mHost;
 
     ScanHandler                     mScanHandler;
     std::vector<otActiveScanResult> mScanResults;
@@ -328,6 +383,10 @@ private:
 
     std::random_device mRandomDevice;
 
+#if OTBR_ENABLE_DHCP6_PD
+    Dhcp6PdStateCallback mDhcp6PdCallback;
+#endif
+
 #if OTBR_ENABLE_DBUS_SERVER
     UpdateMeshCopTxtHandler mUpdateMeshCopTxtHandler;
 #endif
diff --git a/src/web/web-service/web_server.cpp b/src/web/web-service/web_server.cpp
index 08cef0eb..ff823748 100644
--- a/src/web/web-service/web_server.cpp
+++ b/src/web/web-service/web_server.cpp
@@ -239,7 +239,7 @@ void WebServer::DefaultHttpResponse(void)
 
             auto ifs = std::make_shared<std::ifstream>();
             ifs->open(path.string(), std::ifstream::in | std::ios::binary | std::ios::ate);
-            std::string extension = boost::filesystem::extension(path.string());
+            std::string extension = path.extension().string();
             std::string header    = "";
             if (extension == ".css")
             {
diff --git a/tests/CMakeLists.txt b/tests/CMakeLists.txt
index ae8f322f..395e4c46 100644
--- a/tests/CMakeLists.txt
+++ b/tests/CMakeLists.txt
@@ -39,4 +39,4 @@ if(OTBR_REST)
 endif()
 
 add_subdirectory(tools)
-add_subdirectory(unit)
+add_subdirectory(gtest)
diff --git a/tests/android/Android.bp b/tests/android/Android.bp
index d100717d..829dc5ba 100644
--- a/tests/android/Android.bp
+++ b/tests/android/Android.bp
@@ -40,8 +40,8 @@ android_test {
     ],
 
     libs: [
-        "android.test.base",
-        "android.test.runner",
+        "android.test.base.stubs.system",
+        "android.test.runner.stubs.system",
     ],
     static_libs: [
         "androidx.test.ext.junit",
diff --git a/tests/dbus/test-client b/tests/dbus/test-client
index ea8575bc..52a52dbd 100755
--- a/tests/dbus/test-client
+++ b/tests/dbus/test-client
@@ -145,7 +145,7 @@ otbr_agent_service_start()
 {
     local -r EXIT_CODE_SHOULD_RESTART=7
 
-    sudo systemd-run --collect --no-ask-password -u test-otbr-agent -p "RestartForceExitStatus=$EXIT_CODE_SHOULD_RESTART" "${CMAKE_BINARY_DIR}"/src/agent/otbr-agent -d7 -I wpan0 "spinel+hdlc+forkpty://$(command -v ot-rcp)?forkpty-arg=1"
+    sudo systemd-run --collect --no-ask-password -u test-otbr-agent -p "RestartForceExitStatus=$EXIT_CODE_SHOULD_RESTART" "${CMAKE_BINARY_DIR}"/src/agent/otbr-agent -d7 -I wpan0 -B lo "spinel+hdlc+forkpty://$(command -v ot-rcp)?forkpty-arg=1"
     timeout 2 bash -c "while ! ot_ctl state; do sleep 1; done"
 }
 
@@ -175,7 +175,7 @@ test_ready_signal()
     sudo expect <<EOF
 spawn dbus-monitor --system path=/io/openthread/BorderRouter/wpan0,member=Ready
 set dbus_monitor \$spawn_id
-spawn ${CMAKE_BINARY_DIR}/src/agent/otbr-agent -d7 -I wpan0 spinel+hdlc+forkpty://$(command -v ot-rcp)?forkpty-arg=1
+spawn ${CMAKE_BINARY_DIR}/src/agent/otbr-agent -d7 -I wpan0 -B lo spinel+hdlc+forkpty://$(command -v ot-rcp)?forkpty-arg=1
 set spawn_id \$dbus_monitor
 expect {
     "member=Ready" { exit }
diff --git a/tests/dbus/test_dbus_client.cpp b/tests/dbus/test_dbus_client.cpp
index 486e5e13..eef54162 100644
--- a/tests/dbus/test_dbus_client.cpp
+++ b/tests/dbus/test_dbus_client.cpp
@@ -261,6 +261,38 @@ void CheckNat64(ThreadApiDBus *aApi)
 #endif
 }
 
+void CheckEphemeralKey(ThreadApiDBus *aApi)
+{
+    bool enabled;
+
+    TEST_ASSERT(aApi->SetEphemeralKeyEnabled(false) == OTBR_ERROR_NONE);
+    TEST_ASSERT(aApi->GetEphemeralKeyEnabled(enabled) == OTBR_ERROR_NONE);
+    TEST_ASSERT(enabled == false);
+    TEST_ASSERT(aApi->SetEphemeralKeyEnabled(true) == OTBR_ERROR_NONE);
+    TEST_ASSERT(aApi->GetEphemeralKeyEnabled(enabled) == OTBR_ERROR_NONE);
+    TEST_ASSERT(enabled == true);
+}
+
+void CheckBorderAgentInfo(const threadnetwork::TelemetryData_BorderAgentInfo &aBorderAgentInfo)
+{
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().epskc_activations() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().epskc_deactivation_clears() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().epskc_deactivation_timeouts() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().epskc_deactivation_max_attempts() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().epskc_deactivation_disconnects() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().epskc_invalid_ba_state_errors() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().epskc_invalid_args_errors() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().epskc_start_secure_session_errors() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().epskc_secure_session_successes() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().epskc_secure_session_failures() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().epskc_commissioner_petitions() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().pskc_secure_session_successes() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().pskc_secure_session_failures() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().pskc_commissioner_petitions() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().mgmt_active_get_reqs() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_counters().mgmt_pending_get_reqs() == 0);
+}
+
 #if OTBR_ENABLE_TELEMETRY_DATA_API
 void CheckTelemetryData(ThreadApiDBus *aApi)
 {
@@ -285,12 +317,13 @@ void CheckTelemetryData(ThreadApiDBus *aApi)
     TEST_ASSERT(telemetryData.wpan_stats().phy_tx() > 0);
     TEST_ASSERT(telemetryData.wpan_stats().phy_rx() > 0);
     TEST_ASSERT(telemetryData.wpan_stats().ip_tx_success() > 0);
-    TEST_ASSERT(telemetryData.wpan_topo_full().rloc16() > 0);
+    TEST_ASSERT(telemetryData.wpan_topo_full().rloc16() < 0xffff);
     TEST_ASSERT(telemetryData.wpan_topo_full().network_data().size() > 0);
     TEST_ASSERT(telemetryData.wpan_topo_full().partition_id() > 0);
     TEST_ASSERT(telemetryData.wpan_topo_full().extended_pan_id() > 0);
+    TEST_ASSERT(telemetryData.wpan_topo_full().peer_br_count() == 0);
     TEST_ASSERT(telemetryData.topo_entries_size() == 1);
-    TEST_ASSERT(telemetryData.topo_entries(0).rloc16() > 0);
+    TEST_ASSERT(telemetryData.topo_entries(0).rloc16() < 0xffff);
     TEST_ASSERT(telemetryData.wpan_border_router().border_routing_counters().rs_tx_failure() == 0);
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
     TEST_ASSERT(telemetryData.wpan_border_router().srp_server().state() ==
@@ -304,6 +337,19 @@ void CheckTelemetryData(ThreadApiDBus *aApi)
     TEST_ASSERT(telemetryData.wpan_border_router().trel_info().has_counters());
     TEST_ASSERT(telemetryData.wpan_border_router().trel_info().counters().trel_tx_packets() == 0);
     TEST_ASSERT(telemetryData.wpan_border_router().trel_info().counters().trel_tx_bytes() == 0);
+#endif
+#if OTBR_ENABLE_BORDER_ROUTING
+    TEST_ASSERT(telemetryData.wpan_border_router().infra_link_info().name() == "lo");
+    TEST_ASSERT(telemetryData.wpan_border_router().infra_link_info().is_up());
+    TEST_ASSERT(telemetryData.wpan_border_router().infra_link_info().is_running());
+    TEST_ASSERT(!telemetryData.wpan_border_router().infra_link_info().is_multicast());
+    TEST_ASSERT(telemetryData.wpan_border_router().infra_link_info().link_local_address_count() == 0);
+    TEST_ASSERT(telemetryData.wpan_border_router().infra_link_info().unique_local_address_count() == 0);
+    TEST_ASSERT(telemetryData.wpan_border_router().infra_link_info().global_unicast_address_count() == 0);
+    TEST_ASSERT(telemetryData.wpan_border_router().infra_link_info().peer_br_count() == 0);
+    TEST_ASSERT(telemetryData.wpan_border_router().external_route_info().has_default_route_added() == false);
+    TEST_ASSERT(telemetryData.wpan_border_router().external_route_info().has_ula_route_added() == false);
+    TEST_ASSERT(telemetryData.wpan_border_router().external_route_info().has_others_route_added() == false);
 #endif
     TEST_ASSERT(telemetryData.wpan_border_router().mdns().service_registration_responses().success_count() > 0);
 #if OTBR_ENABLE_NAT64
@@ -311,13 +357,21 @@ void CheckTelemetryData(ThreadApiDBus *aApi)
                 threadnetwork::TelemetryData::NAT64_STATE_NOT_RUNNING);
 #endif
 #if OTBR_ENABLE_DHCP6_PD
-    TEST_ASSERT(!telemetryData.wpan_border_router().hashed_pd_prefix().empty());
+    TEST_ASSERT(telemetryData.wpan_border_router().dhcp6_pd_state() ==
+                threadnetwork::TelemetryData::DHCP6_PD_STATE_DISABLED);
+    TEST_ASSERT(telemetryData.wpan_border_router().hashed_pd_prefix().empty());
+    TEST_ASSERT(telemetryData.wpan_border_router().pd_processed_ra_info().num_platform_ra_received() == 0);
+    TEST_ASSERT(telemetryData.wpan_border_router().pd_processed_ra_info().num_platform_pio_processed() == 0);
+    TEST_ASSERT(telemetryData.wpan_border_router().pd_processed_ra_info().last_platform_ra_msec() == 0);
 #endif
     TEST_ASSERT(telemetryData.wpan_rcp().rcp_interface_statistics().transferred_frames_count() > 0);
     TEST_ASSERT(telemetryData.coex_metrics().count_tx_request() > 0);
 #if OTBR_ENABLE_LINK_METRICS_TELEMETRY
     TEST_ASSERT(telemetryData.low_power_metrics().link_metrics_entries_size() >= 0);
 #endif
+#if OTBR_ENABLE_BORDER_AGENT
+    CheckBorderAgentInfo(telemetryData.wpan_border_router().border_agent_info());
+#endif
 }
 #endif
 
@@ -451,6 +505,7 @@ int main()
                             CheckMdnsInfo(api.get());
                             CheckDnssdCounters(api.get());
                             CheckNat64(api.get());
+                            CheckEphemeralKey(api.get());
 #if OTBR_ENABLE_TELEMETRY_DATA_API
                             CheckTelemetryData(api.get());
 #endif
diff --git a/tests/gtest/CMakeLists.txt b/tests/gtest/CMakeLists.txt
new file mode 100644
index 00000000..f9674ed6
--- /dev/null
+++ b/tests/gtest/CMakeLists.txt
@@ -0,0 +1,84 @@
+#
+#  Copyright (c) 2020, The OpenThread Authors.
+#  All rights reserved.
+#
+#  Redistribution and use in source and binary forms, with or without
+#  modification, are permitted provided that the following conditions are met:
+#  1. Redistributions of source code must retain the above copyright
+#     notice, this list of conditions and the following disclaimer.
+#  2. Redistributions in binary form must reproduce the above copyright
+#     notice, this list of conditions and the following disclaimer in the
+#     documentation and/or other materials provided with the distribution.
+#  3. Neither the name of the copyright holder nor the
+#     names of its contributors may be used to endorse or promote products
+#     derived from this software without specific prior written permission.
+#
+#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+#  POSSIBILITY OF SUCH DAMAGE.
+#
+
+cmake_minimum_required(VERSION 3.14)
+project(openthread-br-gtest)
+
+# GoogleTest requires at least C++14
+set(CMAKE_CXX_STANDARD 14)
+set(CMAKE_CXX_STANDARD_REQUIRED ON)
+
+include(FetchContent)
+FetchContent_Declare(
+    googletest
+    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
+)
+# For Windows: Prevent overriding the parent project's compiler/linker settings
+set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
+FetchContent_MakeAvailable(googletest)
+
+include(GoogleTest)
+
+add_executable(otbr-gtest-unit
+    test_async_task.cpp
+    test_common_types.cpp
+    test_dns_utils.cpp
+    test_logging.cpp
+    test_once_callback.cpp
+    test_pskc.cpp
+    test_task_runner.cpp
+)
+target_link_libraries(otbr-gtest-unit
+    mbedtls
+    otbr-common
+    otbr-ncp
+    otbr-utils
+    GTest::gmock_main
+)
+gtest_discover_tests(otbr-gtest-unit)
+
+if(OTBR_MDNS)
+    add_executable(otbr-gtest-mdns-subscribe
+        test_mdns_subscribe.cpp
+    )
+    target_link_libraries(otbr-gtest-mdns-subscribe
+        otbr-common
+        otbr-mdns
+        GTest::gmock_main
+    )
+    gtest_discover_tests(otbr-gtest-mdns-subscribe)
+endif()
+
+add_executable(otbr-posix-gtest-unit
+    test_netif.cpp
+)
+target_link_libraries(otbr-posix-gtest-unit
+    otbr-posix
+    GTest::gmock_main
+)
+gtest_discover_tests(otbr-posix-gtest-unit PROPERTIES LABELS "sudo")
diff --git a/tests/gtest/test_async_task.cpp b/tests/gtest/test_async_task.cpp
new file mode 100644
index 00000000..46f3649d
--- /dev/null
+++ b/tests/gtest/test_async_task.cpp
@@ -0,0 +1,200 @@
+/*
+ *    Copyright (c) 2024, The OpenThread Authors.
+ *    All rights reserved.
+ *
+ *    Redistribution and use in source and binary forms, with or without
+ *    modification, are permitted provided that the following conditions are met:
+ *    1. Redistributions of source code must retain the above copyright
+ *       notice, this list of conditions and the following disclaimer.
+ *    2. Redistributions in binary form must reproduce the above copyright
+ *       notice, this list of conditions and the following disclaimer in the
+ *       documentation and/or other materials provided with the distribution.
+ *    3. Neither the name of the copyright holder nor the
+ *       names of its contributors may be used to endorse or promote products
+ *       derived from this software without specific prior written permission.
+ *
+ *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *    POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#include <gtest/gtest.h>
+
+#include <memory>
+#include <string>
+
+#include <openthread/error.h>
+
+#include "common/code_utils.hpp"
+#include "ncp/async_task.hpp"
+
+using otbr::Ncp::AsyncTask;
+using otbr::Ncp::AsyncTaskPtr;
+
+TEST(AsyncTask, TestOneStep)
+{
+    AsyncTaskPtr task;
+    AsyncTaskPtr step1;
+    int          resultHandlerCalledTimes = 0;
+    int          stepCount                = 0;
+
+    auto errorHandler = [&resultHandlerCalledTimes](otError aError, const std::string &aErrorInfo) {
+        OTBR_UNUSED_VARIABLE(aError);
+        OTBR_UNUSED_VARIABLE(aErrorInfo);
+
+        resultHandlerCalledTimes++;
+    };
+
+    task = std::make_shared<AsyncTask>(errorHandler);
+    task->First([&stepCount, &step1](AsyncTaskPtr aNext) {
+        step1 = std::move(aNext);
+        stepCount++;
+    });
+    task->Run();
+
+    step1->SetResult(OT_ERROR_NONE, "Success");
+
+    EXPECT_EQ(resultHandlerCalledTimes, 1);
+    EXPECT_EQ(stepCount, 1);
+}
+
+TEST(AsyncTask, TestNoResultReturned)
+{
+    AsyncTaskPtr task;
+    AsyncTaskPtr step1;
+    AsyncTaskPtr step2;
+    AsyncTaskPtr step3;
+
+    int     resultHandlerCalledTimes = 0;
+    int     stepCount                = 0;
+    otError error                    = OT_ERROR_NONE;
+
+    auto errorHandler = [&resultHandlerCalledTimes, &error](otError aError, const std::string &aErrorInfo) {
+        OTBR_UNUSED_VARIABLE(aErrorInfo);
+
+        resultHandlerCalledTimes++;
+        error = aError;
+    };
+
+    task = std::make_shared<AsyncTask>(errorHandler);
+    task->First([&stepCount, &step1](AsyncTaskPtr aNext) {
+            step1 = std::move(aNext);
+            stepCount++;
+        })
+        ->Then([&stepCount, &step2](AsyncTaskPtr aNext) {
+            step2 = std::move(aNext);
+            stepCount++;
+        })
+        ->Then([&stepCount, &step3](AsyncTaskPtr aNext) {
+            step3 = std::move(aNext);
+            stepCount++;
+        });
+    task->Run();
+
+    // Asyn task ends without calling 'SetResult'.
+    step1 = nullptr;
+    task  = nullptr;
+
+    EXPECT_EQ(resultHandlerCalledTimes, 1);
+    EXPECT_EQ(stepCount, 1);
+    EXPECT_EQ(error, OT_ERROR_FAILED);
+}
+
+TEST(AsyncTask, TestMultipleStepsSuccess)
+{
+    AsyncTaskPtr task;
+    AsyncTaskPtr step1;
+    AsyncTaskPtr step2;
+    AsyncTaskPtr step3;
+
+    int     resultHandlerCalledTimes = 0;
+    int     stepCount                = 0;
+    otError error                    = OT_ERROR_NONE;
+
+    auto errorHandler = [&resultHandlerCalledTimes, &error](otError aError, const std::string &aErrorInfo) {
+        OTBR_UNUSED_VARIABLE(aErrorInfo);
+
+        resultHandlerCalledTimes++;
+        error = aError;
+    };
+
+    task = std::make_shared<AsyncTask>(errorHandler);
+    task->First([&stepCount, &step1](AsyncTaskPtr aNext) {
+            step1 = std::move(aNext);
+            stepCount++;
+        })
+        ->Then([&stepCount, &step2](AsyncTaskPtr aNext) {
+            step2 = std::move(aNext);
+            stepCount++;
+        })
+        ->Then([&stepCount, &step3](AsyncTaskPtr aNext) {
+            step3 = std::move(aNext);
+            stepCount++;
+        });
+    task->Run();
+
+    EXPECT_EQ(stepCount, 1);
+    step1->SetResult(OT_ERROR_NONE, "");
+    EXPECT_EQ(resultHandlerCalledTimes, 0);
+
+    EXPECT_EQ(stepCount, 2);
+    step2->SetResult(OT_ERROR_NONE, "");
+    EXPECT_EQ(resultHandlerCalledTimes, 0);
+
+    EXPECT_EQ(stepCount, 3);
+    error = OT_ERROR_GENERIC;
+    step3->SetResult(OT_ERROR_NONE, "");
+    EXPECT_EQ(resultHandlerCalledTimes, 1);
+    EXPECT_EQ(error, OT_ERROR_NONE);
+}
+
+TEST(AsyncTask, TestMultipleStepsFailedHalfWay)
+{
+    AsyncTaskPtr task;
+    AsyncTaskPtr step1;
+    AsyncTaskPtr step2;
+    AsyncTaskPtr step3;
+
+    int     resultHandlerCalledTimes = 0;
+    int     stepCount                = 0;
+    otError error                    = OT_ERROR_NONE;
+
+    auto errorHandler = [&resultHandlerCalledTimes, &error](otError aError, const std::string &aErrorInfo) {
+        OTBR_UNUSED_VARIABLE(aErrorInfo);
+
+        resultHandlerCalledTimes++;
+        error = aError;
+    };
+
+    task = std::make_shared<AsyncTask>(errorHandler);
+    task->First([&stepCount, &step1](AsyncTaskPtr aNext) {
+            step1 = std::move(aNext);
+            stepCount++;
+        })
+        ->Then([&stepCount, &step2](AsyncTaskPtr aNext) {
+            step2 = std::move(aNext);
+            stepCount++;
+        })
+        ->Then([&stepCount, &step3](AsyncTaskPtr aNext) {
+            step3 = std::move(aNext);
+            stepCount++;
+        });
+    task->Run();
+
+    EXPECT_EQ(stepCount, 1);
+    step1->SetResult(OT_ERROR_NONE, "");
+    EXPECT_EQ(resultHandlerCalledTimes, 0);
+
+    EXPECT_EQ(stepCount, 2);
+    step2->SetResult(OT_ERROR_BUSY, "");
+    EXPECT_EQ(resultHandlerCalledTimes, 1);
+    EXPECT_EQ(error, OT_ERROR_BUSY);
+}
diff --git a/tests/gtest/test_common_types.cpp b/tests/gtest/test_common_types.cpp
new file mode 100644
index 00000000..32b2c5a2
--- /dev/null
+++ b/tests/gtest/test_common_types.cpp
@@ -0,0 +1,103 @@
+/*
+ *    Copyright (c) 2024, The OpenThread Authors.
+ *    All rights reserved.
+ *
+ *    Redistribution and use in source and binary forms, with or without
+ *    modification, are permitted provided that the following conditions are met:
+ *    1. Redistributions of source code must retain the above copyright
+ *       notice, this list of conditions and the following disclaimer.
+ *    2. Redistributions in binary form must reproduce the above copyright
+ *       notice, this list of conditions and the following disclaimer in the
+ *       documentation and/or other materials provided with the distribution.
+ *    3. Neither the name of the copyright holder nor the
+ *       names of its contributors may be used to endorse or promote products
+ *       derived from this software without specific prior written permission.
+ *
+ *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *    POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#include <gtest/gtest.h>
+
+#include "common/types.hpp"
+
+//-------------------------------------------------------------
+// Test for Ip6Address
+// TODO: Add Ip6Address tests
+
+//-------------------------------------------------------------
+// Test for Ip6Prefix
+
+TEST(Ip6Prefix, ConstructorWithAddressAndLength)
+{
+    using otbr::Ip6Prefix;
+
+    Ip6Prefix prefix1("::", 0);
+    EXPECT_STREQ(prefix1.ToString().c_str(), "::/0");
+    EXPECT_EQ(prefix1.mLength, 0);
+
+    Ip6Prefix prefix2("fc00::", 7);
+    EXPECT_STREQ(prefix2.ToString().c_str(), "fc00::/7");
+    EXPECT_EQ(prefix2.mLength, 7);
+
+    Ip6Prefix prefix3("2001:db8::", 64);
+    EXPECT_STREQ(prefix3.ToString().c_str(), "2001:db8::/64");
+    EXPECT_EQ(prefix3.mLength, 64);
+
+    Ip6Prefix prefix4("2001:db8::1", 128);
+    EXPECT_STREQ(prefix4.ToString().c_str(), "2001:db8::1/128");
+    EXPECT_EQ(prefix4.mLength, 128);
+}
+
+TEST(Ip6Prefix, EqualityOperator)
+{
+    using otbr::Ip6Prefix;
+
+    // same prefix and length
+    EXPECT_EQ(Ip6Prefix("::", 0), Ip6Prefix("::", 0));
+    EXPECT_EQ(Ip6Prefix("fc00::", 0), Ip6Prefix("fc00::", 0));
+    EXPECT_EQ(Ip6Prefix("2001:db8::", 64), Ip6Prefix("2001:db8::", 64));
+
+    // same prefix, different length
+    EXPECT_NE(Ip6Prefix("::", 0), Ip6Prefix("::", 7));
+    EXPECT_NE(Ip6Prefix("fc00::", 0), Ip6Prefix("fc00::", 7));
+    EXPECT_NE(Ip6Prefix("fc00::", 7), Ip6Prefix("fc00::", 8));
+    EXPECT_NE(Ip6Prefix("2001:db8::", 64), Ip6Prefix("2001:db8::", 32));
+
+    // different prefix object, same length
+    EXPECT_EQ(Ip6Prefix("::", 0), Ip6Prefix("::1", 0));
+    EXPECT_EQ(Ip6Prefix("::", 0), Ip6Prefix("2001::", 0));
+    EXPECT_EQ(Ip6Prefix("::", 0), Ip6Prefix("2001:db8::1", 0));
+    EXPECT_EQ(Ip6Prefix("fc00::", 7), Ip6Prefix("fd00::", 7));
+    EXPECT_EQ(Ip6Prefix("fc00::", 8), Ip6Prefix("fc00:1234::", 8));
+    EXPECT_EQ(Ip6Prefix("2001:db8::", 32), Ip6Prefix("2001:db8:abcd::", 32));
+    EXPECT_EQ(Ip6Prefix("2001:db8:0:1::", 63), Ip6Prefix("2001:db8::", 63));
+    EXPECT_EQ(Ip6Prefix("2001:db8::", 64), Ip6Prefix("2001:db8::1", 64));
+    EXPECT_EQ(Ip6Prefix("2001:db8::3", 127), Ip6Prefix("2001:db8::2", 127));
+
+    EXPECT_NE(Ip6Prefix("fc00::", 7), Ip6Prefix("fe00::", 7));
+    EXPECT_NE(Ip6Prefix("fc00::", 16), Ip6Prefix("fc01::", 16));
+    EXPECT_NE(Ip6Prefix("fc00::", 32), Ip6Prefix("fc00:1::", 32));
+    EXPECT_NE(Ip6Prefix("2001:db8:0:1::", 64), Ip6Prefix("2001:db8::", 64));
+    EXPECT_NE(Ip6Prefix("2001:db8::1", 128), Ip6Prefix("2001:db8::", 128));
+
+    // different prefix object, different length
+    EXPECT_NE(Ip6Prefix("::", 0), Ip6Prefix("2001::", 7));
+    EXPECT_NE(Ip6Prefix("fc00::", 7), Ip6Prefix("fd00::", 8));
+    EXPECT_NE(Ip6Prefix("2001:db8:0:1::", 63), Ip6Prefix("2001:db8::", 64));
+}
+
+// TODO: add more test cases for otbr::Ip6Prefix
+
+//-------------------------------------------------------------
+// Test for MacAddress
+// TODO: Add MacAddress tests
diff --git a/tests/unit/test_dbus_message.cpp b/tests/gtest/test_dbus_message.cpp
similarity index 83%
rename from tests/unit/test_dbus_message.cpp
rename to tests/gtest/test_dbus_message.cpp
index 05079e96..f1afffe9 100644
--- a/tests/unit/test_dbus_message.cpp
+++ b/tests/gtest/test_dbus_message.cpp
@@ -26,12 +26,11 @@
  *    POSSIBILITY OF SUCH DAMAGE.
  */
 
+#include <gtest/gtest.h>
 #include <string.h>
 
 #include "dbus/common/dbus_message_helper.hpp"
 
-#include <CppUTest/TestHarness.h>
-
 using std::array;
 using std::string;
 using std::tuple;
@@ -168,12 +167,12 @@ TEST(DBusMessage, TestVectorMessage)
     tuple<vector<uint8_t>, vector<uint16_t>, vector<uint32_t>, vector<uint64_t>, vector<int16_t>, vector<int32_t>,
           vector<int64_t>>
         getVals({}, {}, {}, {}, {}, {}, {});
-    CHECK(msg != nullptr);
+    EXPECT_NE(msg, nullptr);
 
-    CHECK(TupleToDBusMessage(*msg, setVals) == OTBR_ERROR_NONE);
-    CHECK(DBusMessageToTuple(*msg, getVals) == OTBR_ERROR_NONE);
+    EXPECT_EQ(TupleToDBusMessage(*msg, setVals), OTBR_ERROR_NONE);
+    EXPECT_EQ(DBusMessageToTuple(*msg, getVals), OTBR_ERROR_NONE);
 
-    CHECK(setVals == getVals);
+    EXPECT_EQ(setVals, getVals);
 
     dbus_message_unref(msg);
 }
@@ -184,12 +183,12 @@ TEST(DBusMessage, TestArrayMessage)
     tuple<array<uint8_t, 4>> setVals({1, 2, 3, 4});
     tuple<array<uint8_t, 4>> getVals({0, 0, 0, 0});
 
-    CHECK(msg != nullptr);
+    EXPECT_NE(msg, nullptr);
 
-    CHECK(TupleToDBusMessage(*msg, setVals) == OTBR_ERROR_NONE);
-    CHECK(DBusMessageToTuple(*msg, getVals) == OTBR_ERROR_NONE);
+    EXPECT_EQ(TupleToDBusMessage(*msg, setVals), OTBR_ERROR_NONE);
+    EXPECT_EQ(DBusMessageToTuple(*msg, getVals), OTBR_ERROR_NONE);
 
-    CHECK(setVals == getVals);
+    EXPECT_EQ(setVals, getVals);
 
     dbus_message_unref(msg);
 }
@@ -204,12 +203,12 @@ TEST(DBusMessage, TestNumberMessage)
         std::make_tuple<uint8_t, uint16_t, uint32_t, uint64_t, bool, int16_t, int32_t, int64_t>(0, 0, 0, 0, false, 0, 0,
                                                                                                 0);
 
-    CHECK(msg != nullptr);
+    EXPECT_NE(msg, nullptr);
 
-    CHECK(TupleToDBusMessage(*msg, setVals) == OTBR_ERROR_NONE);
-    CHECK(DBusMessageToTuple(*msg, getVals) == OTBR_ERROR_NONE);
+    EXPECT_EQ(TupleToDBusMessage(*msg, setVals), OTBR_ERROR_NONE);
+    EXPECT_EQ(DBusMessageToTuple(*msg, getVals), OTBR_ERROR_NONE);
 
-    CHECK(setVals == getVals);
+    EXPECT_EQ(setVals, getVals);
 
     dbus_message_unref(msg);
 }
@@ -221,12 +220,12 @@ TEST(DBusMessage, TestStructMessage)
         0x03, {0x04, 0x05}, {"hello", "world"}, {{1, 0xf0a, "test1"}, {2, 0xf0b, "test2"}});
     tuple<uint8_t, vector<int32_t>, vector<string>, vector<TestStruct>> getVals(0, {}, {}, {});
 
-    CHECK(msg != nullptr);
+    EXPECT_NE(msg, nullptr);
 
-    CHECK(TupleToDBusMessage(*msg, setVals) == OTBR_ERROR_NONE);
-    CHECK(DBusMessageToTuple(*msg, getVals) == OTBR_ERROR_NONE);
+    EXPECT_EQ(TupleToDBusMessage(*msg, setVals), OTBR_ERROR_NONE);
+    EXPECT_EQ(DBusMessageToTuple(*msg, getVals), OTBR_ERROR_NONE);
 
-    CHECK(setVals == getVals);
+    EXPECT_EQ(setVals, getVals);
 
     dbus_message_unref(msg);
 }
@@ -237,12 +236,12 @@ TEST(DBusMessage, TestOtbrChannelQuality)
     tuple<std::vector<otbr::DBus::ChannelQuality>> setVals({{1, 2}});
     tuple<std::vector<otbr::DBus::ChannelQuality>> getVals;
 
-    CHECK(msg != nullptr);
+    EXPECT_NE(msg, nullptr);
 
-    CHECK(TupleToDBusMessage(*msg, setVals) == OTBR_ERROR_NONE);
-    CHECK(DBusMessageToTuple(*msg, getVals) == OTBR_ERROR_NONE);
+    EXPECT_EQ(TupleToDBusMessage(*msg, setVals), OTBR_ERROR_NONE);
+    EXPECT_EQ(DBusMessageToTuple(*msg, getVals), OTBR_ERROR_NONE);
 
-    CHECK(std::get<0>(setVals)[0] == std::get<0>(getVals)[0]);
+    EXPECT_EQ(std::get<0>(setVals)[0], std::get<0>(getVals)[0]);
 
     dbus_message_unref(msg);
 }
@@ -253,12 +252,12 @@ TEST(DBusMessage, TestOtbrChildInfo)
     tuple<std::vector<otbr::DBus::ChildInfo>> setVals({{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, true, false, true, false}});
     tuple<std::vector<otbr::DBus::ChildInfo>> getVals;
 
-    CHECK(msg != nullptr);
+    EXPECT_NE(msg, nullptr);
 
-    CHECK(TupleToDBusMessage(*msg, setVals) == OTBR_ERROR_NONE);
-    CHECK(DBusMessageToTuple(*msg, getVals) == OTBR_ERROR_NONE);
+    EXPECT_EQ(TupleToDBusMessage(*msg, setVals), OTBR_ERROR_NONE);
+    EXPECT_EQ(DBusMessageToTuple(*msg, getVals), OTBR_ERROR_NONE);
 
-    CHECK(std::get<0>(setVals)[0] == std::get<0>(getVals)[0]);
+    EXPECT_EQ(std::get<0>(setVals)[0], std::get<0>(getVals)[0]);
 
     dbus_message_unref(msg);
 }
@@ -270,12 +269,12 @@ TEST(DBusMessage, TestOtbrNeighborInfo)
         {{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, true, false, true, false}});
     tuple<std::vector<otbr::DBus::NeighborInfo>> getVals;
 
-    CHECK(msg != nullptr);
+    EXPECT_NE(msg, nullptr);
 
-    CHECK(TupleToDBusMessage(*msg, setVals) == OTBR_ERROR_NONE);
-    CHECK(DBusMessageToTuple(*msg, getVals) == OTBR_ERROR_NONE);
+    EXPECT_EQ(TupleToDBusMessage(*msg, setVals), OTBR_ERROR_NONE);
+    EXPECT_EQ(DBusMessageToTuple(*msg, getVals), OTBR_ERROR_NONE);
 
-    CHECK(std::get<0>(setVals)[0] == std::get<0>(getVals)[0]);
+    EXPECT_EQ(std::get<0>(setVals)[0], std::get<0>(getVals)[0]);
 
     dbus_message_unref(msg);
 }
@@ -286,12 +285,12 @@ TEST(DBusMessage, TestOtbrLeaderData)
     tuple<std::vector<otbr::DBus::LeaderData>> setVals({{1, 2, 3, 4, 5}});
     tuple<std::vector<otbr::DBus::LeaderData>> getVals;
 
-    CHECK(msg != nullptr);
+    EXPECT_NE(msg, nullptr);
 
-    CHECK(TupleToDBusMessage(*msg, setVals) == OTBR_ERROR_NONE);
-    CHECK(DBusMessageToTuple(*msg, getVals) == OTBR_ERROR_NONE);
+    EXPECT_EQ(TupleToDBusMessage(*msg, setVals), OTBR_ERROR_NONE);
+    EXPECT_EQ(DBusMessageToTuple(*msg, getVals), OTBR_ERROR_NONE);
 
-    CHECK(std::get<0>(setVals)[0] == std::get<0>(getVals)[0]);
+    EXPECT_EQ(std::get<0>(setVals)[0], std::get<0>(getVals)[0]);
 
     dbus_message_unref(msg);
 }
@@ -302,12 +301,12 @@ TEST(DBusMessage, TestOtbrActiveScanResults)
     tuple<std::vector<otbr::DBus::ActiveScanResult>> setVals({{1, "a", 2, {3}, 4, 5, 6, 7, 8, 9, true, false}});
     tuple<std::vector<otbr::DBus::ActiveScanResult>> getVals;
 
-    CHECK(msg != nullptr);
+    EXPECT_NE(msg, nullptr);
 
-    CHECK(TupleToDBusMessage(*msg, setVals) == OTBR_ERROR_NONE);
-    CHECK(DBusMessageToTuple(*msg, getVals) == OTBR_ERROR_NONE);
+    EXPECT_EQ(TupleToDBusMessage(*msg, setVals), OTBR_ERROR_NONE);
+    EXPECT_EQ(DBusMessageToTuple(*msg, getVals), OTBR_ERROR_NONE);
 
-    CHECK(std::get<0>(setVals)[0] == std::get<0>(getVals)[0]);
+    EXPECT_EQ(std::get<0>(setVals)[0], std::get<0>(getVals)[0]);
 
     dbus_message_unref(msg);
 }
@@ -320,12 +319,12 @@ TEST(DBusMessage, TestOtbrExternalRoute)
           true}});
     tuple<std::vector<otbr::DBus::ExternalRoute>> getVals;
 
-    CHECK(msg != nullptr);
+    EXPECT_NE(msg, nullptr);
 
-    CHECK(TupleToDBusMessage(*msg, setVals) == OTBR_ERROR_NONE);
-    CHECK(DBusMessageToTuple(*msg, getVals) == OTBR_ERROR_NONE);
+    EXPECT_EQ(TupleToDBusMessage(*msg, setVals), OTBR_ERROR_NONE);
+    EXPECT_EQ(DBusMessageToTuple(*msg, getVals), OTBR_ERROR_NONE);
 
-    CHECK(std::get<0>(setVals)[0] == std::get<0>(getVals)[0]);
+    EXPECT_EQ(std::get<0>(setVals)[0], std::get<0>(getVals)[0]);
 
     dbus_message_unref(msg);
 }
diff --git a/tests/unit/test_dns_utils.cpp b/tests/gtest/test_dns_utils.cpp
similarity index 84%
rename from tests/unit/test_dns_utils.cpp
rename to tests/gtest/test_dns_utils.cpp
index 55d3389c..411206e5 100644
--- a/tests/unit/test_dns_utils.cpp
+++ b/tests/gtest/test_dns_utils.cpp
@@ -29,10 +29,7 @@
 #include "common/dns_utils.hpp"
 
 #include <assert.h>
-
-#include <CppUTest/TestHarness.h>
-
-TEST_GROUP(DnsUtils){};
+#include <gtest/gtest.h>
 
 static void CheckSplitFullDnsName(const std::string &aFullName,
                                   bool               aIsServiceInstance,
@@ -49,23 +46,23 @@ static void CheckSplitFullDnsName(const std::string &aFullName,
 
     info = SplitFullDnsName(aFullName);
 
-    CHECK_EQUAL(aIsServiceInstance, info.IsServiceInstance());
-    CHECK_EQUAL(aIsService, info.IsService());
-    CHECK_EQUAL(aIsHost, info.IsHost());
-    CHECK_EQUAL(aInstanceName, info.mInstanceName);
-    CHECK_EQUAL(aServiceName, info.mServiceName);
-    CHECK_EQUAL(aHostName, info.mHostName);
-    CHECK_EQUAL(aDomain, info.mDomain);
+    EXPECT_EQ(aIsServiceInstance, info.IsServiceInstance());
+    EXPECT_EQ(aIsService, info.IsService());
+    EXPECT_EQ(aIsHost, info.IsHost());
+    EXPECT_EQ(aInstanceName, info.mInstanceName);
+    EXPECT_EQ(aServiceName, info.mServiceName);
+    EXPECT_EQ(aHostName, info.mHostName);
+    EXPECT_EQ(aDomain, info.mDomain);
 
     info = SplitFullDnsName(aFullName + ".");
 
-    CHECK_EQUAL(aIsServiceInstance, info.IsServiceInstance());
-    CHECK_EQUAL(aIsService, info.IsService());
-    CHECK_EQUAL(aIsHost, info.IsHost());
-    CHECK_EQUAL(aInstanceName, info.mInstanceName);
-    CHECK_EQUAL(aServiceName, info.mServiceName);
-    CHECK_EQUAL(aHostName, info.mHostName);
-    CHECK_EQUAL(aDomain, info.mDomain);
+    EXPECT_EQ(aIsServiceInstance, info.IsServiceInstance());
+    EXPECT_EQ(aIsService, info.IsService());
+    EXPECT_EQ(aIsHost, info.IsHost());
+    EXPECT_EQ(aInstanceName, info.mInstanceName);
+    EXPECT_EQ(aServiceName, info.mServiceName);
+    EXPECT_EQ(aHostName, info.mHostName);
+    EXPECT_EQ(aDomain, info.mDomain);
 }
 
 TEST(DnsUtils, TestSplitFullDnsName)
diff --git a/tests/unit/test_logging.cpp b/tests/gtest/test_logging.cpp
similarity index 94%
rename from tests/unit/test_logging.cpp
rename to tests/gtest/test_logging.cpp
index c2997035..104990d8 100644
--- a/tests/unit/test_logging.cpp
+++ b/tests/gtest/test_logging.cpp
@@ -28,15 +28,13 @@
 
 #define OTBR_LOG_TAG "TEST"
 
-#include <CppUTest/TestHarness.h>
-
 #include <stdio.h>
 #include <time.h>
 #include <unistd.h>
 
-#include "common/logging.hpp"
+#include <gtest/gtest.h>
 
-TEST_GROUP(Logging){};
+#include "common/logging.hpp"
 
 TEST(Logging, TestLoggingHigherLevel)
 {
@@ -50,7 +48,7 @@ TEST(Logging, TestLoggingHigherLevel)
 
     char cmd[128];
     snprintf(cmd, sizeof(cmd), "grep '%s.*cool-higher' /var/log/syslog", ident);
-    CHECK(0 != system(cmd));
+    EXPECT_NE(system(cmd), 0);
 }
 
 TEST(Logging, TestLoggingEqualLevel)
@@ -66,7 +64,7 @@ TEST(Logging, TestLoggingEqualLevel)
     char cmd[128];
     snprintf(cmd, sizeof(cmd), "grep '%s.*cool-equal' /var/log/syslog", ident);
     printf("CMD = %s\n", cmd);
-    CHECK(0 == system(cmd));
+    EXPECT_EQ(system(cmd), 0);
 }
 
 TEST(Logging, TestLoggingEqualLevelNoSyslog)
@@ -82,7 +80,7 @@ TEST(Logging, TestLoggingEqualLevelNoSyslog)
     char cmd[128];
     snprintf(cmd, sizeof(cmd), "grep '%s.*cool-equal' /var/log/syslog", ident);
     printf("CMD = %s\n", cmd);
-    CHECK(0 != system(cmd));
+    EXPECT_NE(system(cmd), 0);
 }
 
 TEST(Logging, TestLoggingLowerLevel)
@@ -97,7 +95,7 @@ TEST(Logging, TestLoggingLowerLevel)
     sleep(0);
 
     snprintf(cmd, sizeof(cmd), "grep '%s.*cool-lower' /var/log/syslog", ident);
-    CHECK(0 == system(cmd));
+    EXPECT_EQ(system(cmd), 0);
 }
 
 TEST(Logging, TestLoggingDump)
@@ -121,12 +119,12 @@ TEST(Logging, TestLoggingDump)
 
     snprintf(cmd, sizeof(cmd),
              "grep '%s.*: foobar: 0000: 6f 6e 65 20 73 75 70 65 72 20 6c 6f 6e 67 20 73' /var/log/syslog", ident);
-    CHECK(0 == system(cmd));
+    EXPECT_EQ(system(cmd), 0);
 
     snprintf(cmd, sizeof(cmd),
              "grep '%s.*: foobar: 0010: 74 72 69 6e 67 20 77 69 74 68 20 6c 6f 74 73 20' /var/log/syslog", ident);
-    CHECK(0 == system(cmd));
+    EXPECT_EQ(system(cmd), 0);
 
     snprintf(cmd, sizeof(cmd), "grep '%s.*: foobar: 0020: 6f 66 20 74 65 78 74 00' /var/log/syslog", ident);
-    CHECK(0 == system(cmd));
+    EXPECT_EQ(system(cmd), 0);
 }
diff --git a/tests/gtest/test_mdns_mdnssd.cpp b/tests/gtest/test_mdns_mdnssd.cpp
new file mode 100644
index 00000000..db9bdb45
--- /dev/null
+++ b/tests/gtest/test_mdns_mdnssd.cpp
@@ -0,0 +1,67 @@
+/*
+ *    Copyright (c) 2018, The OpenThread Authors.
+ *    All rights reserved.
+ *
+ *    Redistribution and use in source and binary forms, with or without
+ *    modification, are permitted provided that the following conditions are met:
+ *    1. Redistributions of source code must retain the above copyright
+ *       notice, this list of conditions and the following disclaimer.
+ *    2. Redistributions in binary form must reproduce the above copyright
+ *       notice, this list of conditions and the following disclaimer in the
+ *       documentation and/or other materials provided with the distribution.
+ *    3. Neither the name of the copyright holder nor the
+ *       names of its contributors may be used to endorse or promote products
+ *       derived from this software without specific prior written permission.
+ *
+ *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *    POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#include <gtest/gtest.h>
+
+#include "mdns/mdns_mdnssd.cpp"
+
+TEST(MdnsSd, TestDNSErrorToString)
+{
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoError), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_Unknown), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoSuchName), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoMemory), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadParam), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadReference), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadState), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadFlags), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_Unsupported), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_NotInitialized), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_AlreadyRegistered), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_NameConflict), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_Invalid), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_Firewall), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_Incompatible), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadInterfaceIndex), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_Refused), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoSuchRecord), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoAuth), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoSuchKey), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_NATTraversal), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_DoubleNAT), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadTime), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadSig), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadKey), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_Transient), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_ServiceNotRunning), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_NATPortMappingUnsupported), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_NATPortMappingDisabled), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoRouter), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_PollingMode), nullptr);
+    EXPECT_NE(otbr::Mdns::DNSErrorToString(kDNSServiceErr_Timeout), nullptr);
+}
diff --git a/tests/mdns/test_subscribe.cpp b/tests/gtest/test_mdns_subscribe.cpp
similarity index 84%
rename from tests/mdns/test_subscribe.cpp
rename to tests/gtest/test_mdns_subscribe.cpp
index b01be3eb..24351e77 100644
--- a/tests/mdns/test_subscribe.cpp
+++ b/tests/gtest/test_mdns_subscribe.cpp
@@ -26,6 +26,8 @@
  *    POSSIBILITY OF SUCH DAMAGE.
  */
 
+#include <gtest/gtest.h>
+#include <limits.h>
 #include <netinet/in.h>
 #include <signal.h>
 
@@ -36,29 +38,11 @@
 #include "common/mainloop_manager.hpp"
 #include "mdns/mdns.hpp"
 
-#include <CppUTest/CommandLineTestRunner.h>
-#include <CppUTest/TestHarness.h>
-
 using namespace otbr;
 using namespace otbr::Mdns;
 
-TEST_GROUP(Mdns){};
-
 static constexpr int kTimeoutSeconds = 3;
 
-SimpleString StringFrom(const std::set<Ip6Address> &aAddresses)
-{
-    std::string result = "[";
-
-    for (const auto &address : aAddresses)
-    {
-        result += address.ToString() + ",";
-    }
-    result.back() = ']';
-
-    return SimpleString(result.c_str());
-}
-
 int RunMainloopUntilTimeout(int aSeconds)
 {
     using namespace otbr;
@@ -128,20 +112,23 @@ Ip6Address         sAddr2;
 Ip6Address         sAddr3;
 Ip6Address         sAddr4;
 
-void SetUp(void)
+class MdnsTest : public ::testing::Test
 {
-    otbrLogInit("test-mdns-subscriber", OTBR_LOG_INFO, true, false);
-    SuccessOrDie(Ip6Address::FromString("2002::1", sAddr1), "");
-    SuccessOrDie(Ip6Address::FromString("2002::2", sAddr2), "");
-    SuccessOrDie(Ip6Address::FromString("2002::3", sAddr3), "");
-    SuccessOrDie(Ip6Address::FromString("2002::4", sAddr4), "");
-    SuccessOrDie(Publisher::EncodeTxtData(sTxtList1, sTxtData1), "");
-}
+protected:
+    MdnsTest()
+    {
+        SuccessOrDie(Ip6Address::FromString("2002::1", sAddr1), "");
+        SuccessOrDie(Ip6Address::FromString("2002::2", sAddr2), "");
+        SuccessOrDie(Ip6Address::FromString("2002::3", sAddr3), "");
+        SuccessOrDie(Ip6Address::FromString("2002::4", sAddr4), "");
+        SuccessOrDie(Publisher::EncodeTxtData(sTxtList1, sTxtData1), "");
+    }
+};
 
 std::unique_ptr<Publisher> CreatePublisher(void)
 {
     bool                       ready = false;
-    std::unique_ptr<Publisher> publisher{Publisher::Create([&publisher, &ready](Mdns::Publisher::State aState) {
+    std::unique_ptr<Publisher> publisher{Publisher::Create([&ready](Mdns::Publisher::State aState) {
         if (aState == Publisher::State::kReady)
         {
             ready = true;
@@ -150,7 +137,7 @@ std::unique_ptr<Publisher> CreatePublisher(void)
 
     publisher->Start();
     RunMainloopUntilTimeout(kTimeoutSeconds);
-    CHECK_TRUE(ready);
+    EXPECT_TRUE(ready);
 
     return publisher;
 }
@@ -163,14 +150,14 @@ void CheckServiceInstance(const Publisher::DiscoveredInstanceInfo aInstanceInfo,
                           uint16_t                                aPort,
                           const Publisher::TxtData                aTxtData)
 {
-    CHECK_EQUAL(aRemoved, aInstanceInfo.mRemoved);
-    CHECK_EQUAL(aServiceName, aInstanceInfo.mName);
+    EXPECT_EQ(aRemoved, aInstanceInfo.mRemoved);
+    EXPECT_EQ(aServiceName, aInstanceInfo.mName);
     if (!aRemoved)
     {
-        CHECK_EQUAL(aHostName, aInstanceInfo.mHostName);
-        CHECK_EQUAL(AsSet(aAddresses), AsSet(aInstanceInfo.mAddresses));
-        CHECK_EQUAL(aPort, aInstanceInfo.mPort);
-        CHECK(AsTxtMap(aTxtData) == AsTxtMap(aInstanceInfo.mTxtData));
+        EXPECT_EQ(aHostName, aInstanceInfo.mHostName);
+        EXPECT_EQ(AsSet(aAddresses), AsSet(aInstanceInfo.mAddresses));
+        EXPECT_EQ(aPort, aInstanceInfo.mPort);
+        EXPECT_TRUE(AsTxtMap(aTxtData) == AsTxtMap(aInstanceInfo.mTxtData));
     }
 }
 
@@ -193,11 +180,11 @@ void CheckHostAdded(const Publisher::DiscoveredHostInfo &aHostInfo,
                     const std::string                   &aHostName,
                     const std::vector<Ip6Address>       &aAddresses)
 {
-    CHECK_EQUAL(aHostName, aHostInfo.mHostName);
-    CHECK_EQUAL(AsSet(aAddresses), AsSet(aHostInfo.mAddresses));
+    EXPECT_EQ(aHostName, aHostInfo.mHostName);
+    EXPECT_EQ(AsSet(aAddresses), AsSet(aHostInfo.mAddresses));
 }
 
-TEST(Mdns, SubscribeHost)
+TEST_F(MdnsTest, SubscribeHost)
 {
     std::unique_ptr<Publisher>    pub = CreatePublisher();
     std::string                   lastHostName;
@@ -220,23 +207,23 @@ TEST(Mdns, SubscribeHost)
     pub->PublishService("host1", "service1", "_test._tcp", Publisher::SubTypeList{"_sub1", "_sub2"}, 11111, sTxtData1,
                         NoOpCallback());
     RunMainloopUntilTimeout(kTimeoutSeconds);
-    CHECK_EQUAL("host1", lastHostName);
+    EXPECT_EQ("host1", lastHostName);
     CheckHostAdded(lastHostInfo, "host1.local.", {sAddr1, sAddr2});
     clearLastHost();
 
     pub->PublishService("host1", "service2", "_test._tcp", {}, 22222, {}, NoOpCallback());
     RunMainloopUntilTimeout(kTimeoutSeconds);
-    CHECK_EQUAL("", lastHostName);
+    EXPECT_EQ("", lastHostName);
     clearLastHost();
 
     pub->PublishHost("host2", Publisher::AddressList{sAddr3}, NoOpCallback());
     pub->PublishService("host2", "service3", "_test._tcp", {}, 33333, {}, NoOpCallback());
     RunMainloopUntilTimeout(kTimeoutSeconds);
-    CHECK_EQUAL("", lastHostName);
+    EXPECT_EQ("", lastHostName);
     clearLastHost();
 }
 
-TEST(Mdns, SubscribeServiceInstance)
+TEST_F(MdnsTest, SubscribeServiceInstance)
 {
     std::unique_ptr<Publisher>        pub = CreatePublisher();
     std::string                       lastServiceType;
@@ -260,23 +247,23 @@ TEST(Mdns, SubscribeServiceInstance)
     pub->PublishService("host1", "service1", "_test._tcp", Publisher::SubTypeList{"_sub1", "_sub2"}, 11111, sTxtData1,
                         NoOpCallback());
     RunMainloopUntilTimeout(kTimeoutSeconds);
-    CHECK_EQUAL("_test._tcp", lastServiceType);
+    EXPECT_EQ("_test._tcp", lastServiceType);
     CheckServiceInstanceAdded(lastInstanceInfo, "host1.local.", {sAddr1, sAddr2}, "service1", 11111, sTxtData1);
     clearLastInstance();
 
     pub->PublishService("host1", "service2", "_test._tcp", {}, 22222, {}, NoOpCallback());
     RunMainloopUntilTimeout(kTimeoutSeconds);
-    CHECK_EQUAL("", lastServiceType);
+    EXPECT_EQ("", lastServiceType);
     clearLastInstance();
 
     pub->PublishHost("host2", Publisher::AddressList{sAddr3}, NoOpCallback());
     pub->PublishService("host2", "service3", "_test._tcp", {}, 33333, {}, NoOpCallback());
     RunMainloopUntilTimeout(kTimeoutSeconds);
-    CHECK_EQUAL("", lastServiceType);
+    EXPECT_EQ("", lastServiceType);
     clearLastInstance();
 }
 
-TEST(Mdns, SubscribeServiceType)
+TEST_F(MdnsTest, SubscribeServiceType)
 {
     std::unique_ptr<Publisher>        pub = CreatePublisher();
     std::string                       lastServiceType;
@@ -300,27 +287,27 @@ TEST(Mdns, SubscribeServiceType)
     pub->PublishService("host1", "service1", "_test._tcp", Publisher::SubTypeList{"_sub1", "_sub2"}, 11111, sTxtData1,
                         NoOpCallback());
     RunMainloopUntilTimeout(kTimeoutSeconds);
-    CHECK_EQUAL("_test._tcp", lastServiceType);
+    EXPECT_EQ("_test._tcp", lastServiceType);
     CheckServiceInstanceAdded(lastInstanceInfo, "host1.local.", {sAddr1, sAddr2}, "service1", 11111, sTxtData1);
     clearLastInstance();
 
     pub->PublishService("host1", "service2", "_test._tcp", {}, 22222, {}, NoOpCallback());
     RunMainloopUntilTimeout(kTimeoutSeconds);
-    CHECK_EQUAL("_test._tcp", lastServiceType);
+    EXPECT_EQ("_test._tcp", lastServiceType);
     CheckServiceInstanceAdded(lastInstanceInfo, "host1.local.", {sAddr1, sAddr2}, "service2", 22222, {});
     clearLastInstance();
 
     pub->PublishHost("host2", Publisher::AddressList{sAddr3}, NoOpCallback());
     pub->PublishService("host2", "service3", "_test._tcp", {}, 33333, {}, NoOpCallback());
     RunMainloopUntilTimeout(kTimeoutSeconds);
-    CHECK_EQUAL("_test._tcp", lastServiceType);
+    EXPECT_EQ("_test._tcp", lastServiceType);
     CheckServiceInstanceAdded(lastInstanceInfo, "host2.local.", {sAddr3}, "service3", 33333, {});
     clearLastInstance();
 
     pub->UnpublishHost("host2", NoOpCallback());
     pub->UnpublishService("service3", "_test._tcp", NoOpCallback());
     RunMainloopUntilTimeout(kTimeoutSeconds);
-    CHECK_EQUAL("_test._tcp", lastServiceType);
+    EXPECT_EQ("_test._tcp", lastServiceType);
     CheckServiceInstanceRemoved(lastInstanceInfo, "service3");
     clearLastInstance();
 
@@ -328,20 +315,13 @@ TEST(Mdns, SubscribeServiceType)
     pub->PublishService("host2", "service3", "_test._tcp", {}, 44444, {}, NoOpCallback());
     pub->PublishHost("host2", {sAddr3, sAddr4}, NoOpCallback());
     RunMainloopUntilTimeout(kTimeoutSeconds);
-    CHECK_EQUAL("_test._tcp", lastServiceType);
+    EXPECT_EQ("_test._tcp", lastServiceType);
     CheckServiceInstanceAdded(lastInstanceInfo, "host2.local.", {sAddr3, sAddr4}, "service3", 44444, {});
     clearLastInstance();
 
     pub->PublishHost("host2", {sAddr4}, NoOpCallback());
     RunMainloopUntilTimeout(kTimeoutSeconds);
-    CHECK_EQUAL("_test._tcp", lastServiceType);
+    EXPECT_EQ("_test._tcp", lastServiceType);
     CheckServiceInstanceAdded(lastInstanceInfo, "host2.local.", {sAddr4}, "service3", 44444, {});
     clearLastInstance();
 }
-
-int main(int argc, const char *argv[])
-{
-    SetUp();
-
-    return RUN_ALL_TESTS(argc, argv);
-}
diff --git a/tests/gtest/test_netif.cpp b/tests/gtest/test_netif.cpp
new file mode 100644
index 00000000..1e51aaf6
--- /dev/null
+++ b/tests/gtest/test_netif.cpp
@@ -0,0 +1,606 @@
+/*
+ *    Copyright (c) 2024, The OpenThread Authors.
+ *    All rights reserved.
+ *
+ *    Redistribution and use in source and binary forms, with or without
+ *    modification, are permitted provided that the following conditions are met:
+ *    1. Redistributions of source code must retain the above copyright
+ *       notice, this list of conditions and the following disclaimer.
+ *    2. Redistributions in binary form must reproduce the above copyright
+ *       notice, this list of conditions and the following disclaimer in the
+ *       documentation and/or other materials provided with the distribution.
+ *    3. Neither the name of the copyright holder nor the
+ *       names of its contributors may be used to endorse or promote products
+ *       derived from this software without specific prior written permission.
+ *
+ *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+ *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+ *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+ *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+ *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+ *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+ *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+ *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+ *    POSSIBILITY OF SUCH DAMAGE.
+ */
+
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+
+#include <arpa/inet.h>
+#include <cstring>
+#include <fstream>
+#include <ifaddrs.h>
+#include <iostream>
+#include <net/if.h>
+#include <netinet/in.h>
+#include <netinet/ip6.h>
+#include <netinet/udp.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <string>
+#include <sys/ioctl.h>
+#include <sys/select.h>
+#include <sys/socket.h>
+#include <sys/types.h>
+#include <vector>
+
+#ifdef __linux__
+#include <linux/if_link.h>
+#endif
+
+#include <openthread/ip6.h>
+
+#include "common/code_utils.hpp"
+#include "common/mainloop.hpp"
+#include "common/types.hpp"
+#include "ncp/posix/netif.hpp"
+#include "utils/socket_utils.hpp"
+
+// Only Test on linux platform for now.
+#ifdef __linux__
+
+static constexpr size_t kMaxIp6Size = 1280;
+
+std::vector<std::string> GetAllIp6Addrs(const char *aInterfaceName)
+{
+    struct ifaddrs          *ifaddr, *ifa;
+    int                      family;
+    std::vector<std::string> ip6Addrs;
+
+    if (getifaddrs(&ifaddr) == -1)
+    {
+        perror("getifaddrs");
+        exit(EXIT_FAILURE);
+    }
+
+    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
+    {
+        if (ifa->ifa_addr == NULL)
+        {
+            continue;
+        }
+
+        family = ifa->ifa_addr->sa_family;
+        if (family == AF_INET6 && strcmp(ifa->ifa_name, aInterfaceName) == 0)
+        {
+            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ifa->ifa_addr;
+            char                 addrstr[INET6_ADDRSTRLEN];
+            if (inet_ntop(AF_INET6, &(in6->sin6_addr), addrstr, sizeof(addrstr)) == NULL)
+            {
+                perror("inet_ntop");
+                exit(EXIT_FAILURE);
+            }
+
+            ip6Addrs.emplace_back(addrstr);
+        }
+    }
+
+    freeifaddrs(ifaddr);
+
+    return ip6Addrs;
+}
+
+static int ParseHex(char *aStr, unsigned char *aAddr)
+{
+    int len = 0;
+
+    while (*aStr)
+    {
+        int tmp;
+        if (aStr[1] == 0)
+        {
+            return -1;
+        }
+        if (sscanf(aStr, "%02x", &tmp) != 1)
+        {
+            return -1;
+        }
+        aAddr[len] = tmp;
+        len++;
+        aStr += 2;
+    }
+
+    return len;
+}
+
+std::vector<std::string> GetAllIp6MulAddrs(const char *aInterfaceName)
+{
+    const char              *kPathIgmp6 = "/proc/net/igmp6";
+    std::string              line;
+    std::vector<std::string> ip6MulAddrs;
+
+    std::ifstream file(kPathIgmp6);
+    if (!file.is_open())
+    {
+        perror("Cannot open IGMP6 file");
+        exit(EXIT_FAILURE);
+    }
+
+    while (std::getline(file, line))
+    {
+        char          interfaceName[256] = {0};
+        char          hexa[256]          = {0};
+        int           index;
+        int           users;
+        unsigned char addr[16];
+
+        sscanf(line.c_str(), "%d%s%s%d", &index, interfaceName, hexa, &users);
+        if (strcmp(interfaceName, aInterfaceName) == 0)
+        {
+            char addrStr[INET6_ADDRSTRLEN];
+            ParseHex(hexa, addr);
+            if (inet_ntop(AF_INET6, addr, addrStr, sizeof(addrStr)) == NULL)
+            {
+                perror("inet_ntop");
+                exit(EXIT_FAILURE);
+            }
+            ip6MulAddrs.emplace_back(addrStr);
+        }
+    }
+
+    file.close();
+
+    return ip6MulAddrs;
+}
+
+otbrError Ip6SendEmptyImpl(const uint8_t *aData, uint16_t aLength)
+{
+    OTBR_UNUSED_VARIABLE(aData);
+    OTBR_UNUSED_VARIABLE(aLength);
+    return OTBR_ERROR_NONE;
+}
+
+TEST(Netif, WpanInitWithFullInterfaceName)
+{
+    const char  *wpan = "wpan0";
+    int          sockfd;
+    struct ifreq ifr;
+
+    otbr::Netif netif;
+    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OT_ERROR_NONE);
+
+    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
+    if (sockfd < 0)
+    {
+        FAIL() << "Error creating socket: " << std::strerror(errno);
+    }
+
+    memset(&ifr, 0, sizeof(ifr));
+    strncpy(ifr.ifr_name, wpan, IFNAMSIZ - 1);
+
+    EXPECT_GE(ioctl(sockfd, SIOCGIFFLAGS, &ifr), 0) << "'" << wpan << "' not found";
+
+    netif.Deinit();
+}
+
+TEST(Netif, WpanInitWithFormatInterfaceName)
+{
+    const char  *wpan    = "tun%d";
+    const char  *if_name = "tun0";
+    int          sockfd;
+    struct ifreq ifr;
+
+    otbr::Netif netif;
+    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OT_ERROR_NONE);
+
+    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
+    if (sockfd < 0)
+    {
+        FAIL() << "Error creating socket: " << std::strerror(errno);
+    }
+
+    memset(&ifr, 0, sizeof(ifr));
+    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
+
+    EXPECT_GE(ioctl(sockfd, SIOCGIFFLAGS, &ifr), 0) << "'" << if_name << "' not found";
+
+    netif.Deinit();
+}
+
+TEST(Netif, WpanInitWithEmptyInterfaceName)
+{
+    const char  *if_name = "wpan0";
+    int          sockfd;
+    struct ifreq ifr;
+
+    otbr::Netif netif;
+    EXPECT_EQ(netif.Init("", Ip6SendEmptyImpl), OT_ERROR_NONE);
+
+    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
+    if (sockfd < 0)
+    {
+        FAIL() << "Error creating socket: " << std::strerror(errno);
+    }
+
+    memset(&ifr, 0, sizeof(ifr));
+    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
+
+    EXPECT_GE(ioctl(sockfd, SIOCGIFFLAGS, &ifr), 0) << "'" << if_name << "' not found";
+
+    netif.Deinit();
+}
+
+TEST(Netif, WpanInitWithInvalidInterfaceName)
+{
+    const char *invalid_netif_name = "invalid_netif_name";
+
+    otbr::Netif netif;
+    EXPECT_EQ(netif.Init(invalid_netif_name, Ip6SendEmptyImpl), OTBR_ERROR_INVALID_ARGS);
+}
+
+TEST(Netif, WpanMtuSize)
+{
+    const char  *wpan = "wpan0";
+    int          sockfd;
+    struct ifreq ifr;
+
+    otbr::Netif netif;
+    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OT_ERROR_NONE);
+
+    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
+    if (sockfd < 0)
+    {
+        FAIL() << "Error creating socket: " << std::strerror(errno);
+    }
+
+    memset(&ifr, 0, sizeof(ifr));
+    strncpy(ifr.ifr_name, wpan, IFNAMSIZ - 1);
+    EXPECT_GE(ioctl(sockfd, SIOCGIFMTU, &ifr), 0) << "Error getting MTU for '" << wpan << "': " << std::strerror(errno);
+    EXPECT_EQ(ifr.ifr_mtu, kMaxIp6Size) << "MTU isn't set correctly";
+
+    netif.Deinit();
+}
+
+TEST(Netif, WpanDeinit)
+{
+    const char  *wpan = "wpan0";
+    int          sockfd;
+    struct ifreq ifr;
+
+    otbr::Netif netif;
+    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OT_ERROR_NONE);
+
+    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
+    if (sockfd < 0)
+    {
+        FAIL() << "Error creating socket: " << std::strerror(errno);
+    }
+
+    memset(&ifr, 0, sizeof(ifr));
+    strncpy(ifr.ifr_name, wpan, IFNAMSIZ - 1);
+    EXPECT_GE(ioctl(sockfd, SIOCGIFFLAGS, &ifr), 0) << "'" << wpan << "' not found";
+
+    netif.Deinit();
+    EXPECT_LT(ioctl(sockfd, SIOCGIFFLAGS, &ifr), 0) << "'" << wpan << "' isn't shutdown";
+}
+
+TEST(Netif, WpanAddrGenMode)
+{
+    otbr::Netif netif;
+    EXPECT_EQ(netif.Init("wpan0", Ip6SendEmptyImpl), OT_ERROR_NONE);
+
+    std::fstream file("/proc/sys/net/ipv6/conf/wpan0/addr_gen_mode", std::ios::in);
+    if (!file.is_open())
+    {
+        FAIL() << "wpan0 interface doesn't exist!";
+    }
+    std::string fileContents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
+
+    EXPECT_EQ(std::stoi(fileContents), IN6_ADDR_GEN_MODE_NONE);
+
+    netif.Deinit();
+}
+
+TEST(Netif, WpanIfHasCorrectUnicastAddresses_AfterUpdatingUnicastAddresses)
+{
+    const char *wpan = "wpan0";
+
+    const otIp6Address kLl = {
+        {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x14, 0x03, 0x32, 0x4c, 0xc2, 0xf8, 0xd0}};
+    const otIp6Address kMlEid = {
+        {0xfd, 0x0d, 0x07, 0xfc, 0xa1, 0xb9, 0xf0, 0x50, 0x03, 0xf1, 0x47, 0xce, 0x85, 0xd3, 0x07, 0x7f}};
+    const otIp6Address kMlRloc = {
+        {0xfd, 0x0d, 0x07, 0xfc, 0xa1, 0xb9, 0xf0, 0x50, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xb8, 0x00}};
+    const otIp6Address kMlAloc = {
+        {0xfd, 0x0d, 0x07, 0xfc, 0xa1, 0xb9, 0xf0, 0x50, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xfc, 0x00}};
+
+    const char *kLlStr     = "fe80::8014:332:4cc2:f8d0";
+    const char *kMlEidStr  = "fd0d:7fc:a1b9:f050:3f1:47ce:85d3:77f";
+    const char *kMlRlocStr = "fd0d:7fc:a1b9:f050:0:ff:fe00:b800";
+    const char *kMlAlocStr = "fd0d:7fc:a1b9:f050:0:ff:fe00:fc00";
+
+    otbr::Netif netif;
+    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OT_ERROR_NONE);
+
+    otbr::Ip6AddressInfo testArray1[] = {
+        {kLl, 64, 0, 1, 0},
+        {kMlEid, 64, 0, 1, 1},
+        {kMlRloc, 64, 0, 1, 1},
+    };
+    std::vector<otbr::Ip6AddressInfo> testVec1(testArray1,
+                                               testArray1 + sizeof(testArray1) / sizeof(otbr::Ip6AddressInfo));
+    netif.UpdateIp6UnicastAddresses(testVec1);
+    std::vector<std::string> wpan_addrs = GetAllIp6Addrs(wpan);
+    EXPECT_EQ(wpan_addrs.size(), 3);
+    EXPECT_THAT(wpan_addrs, ::testing::Contains(kLlStr));
+    EXPECT_THAT(wpan_addrs, ::testing::Contains(kMlEidStr));
+    EXPECT_THAT(wpan_addrs, ::testing::Contains(kMlRlocStr));
+
+    otbr::Ip6AddressInfo testArray2[] = {
+        {kLl, 64, 0, 1, 0},
+        {kMlEid, 64, 0, 1, 1},
+        {kMlRloc, 64, 0, 1, 1},
+        {kMlAloc, 64, 0, 1, 1},
+    };
+    std::vector<otbr::Ip6AddressInfo> testVec2(testArray2,
+                                               testArray2 + sizeof(testArray2) / sizeof(otbr::Ip6AddressInfo));
+    netif.UpdateIp6UnicastAddresses(testVec2);
+    wpan_addrs = GetAllIp6Addrs(wpan);
+    EXPECT_EQ(wpan_addrs.size(), 4);
+    EXPECT_THAT(wpan_addrs, ::testing::Contains(kLlStr));
+    EXPECT_THAT(wpan_addrs, ::testing::Contains(kMlEidStr));
+    EXPECT_THAT(wpan_addrs, ::testing::Contains(kMlRlocStr));
+    EXPECT_THAT(wpan_addrs, ::testing::Contains(kMlAlocStr));
+
+    std::vector<otbr::Ip6AddressInfo> testVec3;
+    netif.UpdateIp6UnicastAddresses(testVec3);
+    wpan_addrs = GetAllIp6Addrs(wpan);
+    EXPECT_EQ(wpan_addrs.size(), 0);
+
+    netif.Deinit();
+}
+
+TEST(Netif, WpanIfHasCorrectMulticastAddresses_AfterUpdatingMulticastAddresses)
+{
+    const char *wpan = "wpan0";
+    otbr::Netif netif;
+    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OT_ERROR_NONE);
+
+    otbr::Ip6Address kDefaultMulAddr1 = {
+        {0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};
+    const char *kDefaultMulAddr1Str = "ff01::1";
+    const char *kDefaultMulAddr2Str = "ff02::1";
+    const char *kDefaultMulAddr3Str = "ff02::2";
+
+    otbr::Ip6Address kMulAddr1 = {
+        {0xff, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc}};
+    otbr::Ip6Address kMulAddr2 = {
+        {0xff, 0x32, 0x00, 0x40, 0xfd, 0x0d, 0x07, 0xfc, 0xa1, 0xb9, 0xf0, 0x50, 0x00, 0x00, 0x00, 0x01}};
+    const char *kMulAddr1Str = "ff03::fc";
+    const char *kMulAddr2Str = "ff32:40:fd0d:7fc:a1b9:f050:0:1";
+
+    otbr::Ip6Address testArray1[] = {
+        kMulAddr1,
+    };
+    std::vector<otbr::Ip6Address> testVec1(testArray1, testArray1 + sizeof(testArray1) / sizeof(otbr::Ip6Address));
+    netif.UpdateIp6MulticastAddresses(testVec1);
+    std::vector<std::string> wpanMulAddrs = GetAllIp6MulAddrs(wpan);
+    EXPECT_EQ(wpanMulAddrs.size(), 4);
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kMulAddr1Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr1Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr2Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr3Str));
+
+    otbr::Ip6Address              testArray2[] = {kMulAddr1, kMulAddr2};
+    std::vector<otbr::Ip6Address> testVec2(testArray2, testArray2 + sizeof(testArray2) / sizeof(otbr::Ip6Address));
+    netif.UpdateIp6MulticastAddresses(testVec2);
+    wpanMulAddrs = GetAllIp6MulAddrs(wpan);
+    EXPECT_EQ(wpanMulAddrs.size(), 5);
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kMulAddr1Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kMulAddr2Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr1Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr2Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr3Str));
+
+    otbr::Ip6Address              testArray3[] = {kDefaultMulAddr1};
+    std::vector<otbr::Ip6Address> testVec3(testArray3, testArray3 + sizeof(testArray3) / sizeof(otbr::Ip6Address));
+    netif.UpdateIp6MulticastAddresses(testVec3);
+    wpanMulAddrs = GetAllIp6MulAddrs(wpan);
+    EXPECT_EQ(wpanMulAddrs.size(), 3);
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr1Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr2Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr3Str));
+
+    std::vector<otbr::Ip6Address> empty;
+    netif.UpdateIp6MulticastAddresses(empty);
+    wpanMulAddrs = GetAllIp6MulAddrs(wpan);
+    EXPECT_EQ(wpanMulAddrs.size(), 3);
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr1Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr2Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr3Str));
+
+    netif.Deinit();
+}
+
+TEST(Netif, WpanIfStateChangesCorrectly_AfterSettingNetifState)
+{
+    otbr::Netif netif;
+    const char *wpan = "wpan0";
+    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OTBR_ERROR_NONE);
+
+    int fd = SocketWithCloseExec(AF_INET6, SOCK_DGRAM, IPPROTO_IP, kSocketNonBlock);
+    if (fd < 0)
+    {
+        perror("Failed to create test socket");
+        exit(EXIT_FAILURE);
+    }
+
+    struct ifreq ifr;
+    memset(&ifr, 0, sizeof(ifr));
+    strncpy(ifr.ifr_name, wpan, IFNAMSIZ - 1);
+
+    netif.SetNetifState(true);
+    ioctl(fd, SIOCGIFFLAGS, &ifr);
+    EXPECT_EQ(ifr.ifr_flags & IFF_UP, IFF_UP);
+
+    netif.SetNetifState(false);
+    ioctl(fd, SIOCGIFFLAGS, &ifr);
+    EXPECT_EQ(ifr.ifr_flags & IFF_UP, 0);
+
+    netif.Deinit();
+}
+
+TEST(Netif, WpanIfRecvIp6PacketCorrectly_AfterReceivingFromNetif)
+{
+    otbr::Netif netif;
+    EXPECT_EQ(netif.Init("wpan0", Ip6SendEmptyImpl), OTBR_ERROR_NONE);
+
+    const otIp6Address kOmr = {
+        {0xfd, 0x2a, 0xc3, 0x0c, 0x87, 0xd3, 0x00, 0x01, 0xed, 0x1c, 0x0c, 0x91, 0xcc, 0xb6, 0x57, 0x8b}};
+    std::vector<otbr::Ip6AddressInfo> addrs = {
+        {kOmr, 64, 0, 1, 0},
+    };
+    netif.UpdateIp6UnicastAddresses(addrs);
+    netif.SetNetifState(true);
+
+    // Receive UDP packets on wpan address with specified port.
+    int                 sockFd;
+    const uint16_t      port = 12345;
+    struct sockaddr_in6 listenAddr;
+    const char         *listenIp = "fd2a:c30c:87d3:1:ed1c:c91:ccb6:578b";
+    uint8_t             recvBuf[kMaxIp6Size];
+
+    if ((sockFd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
+    {
+        perror("socket creation failed");
+        exit(EXIT_FAILURE);
+    }
+
+    memset(&listenAddr, 0, sizeof(listenAddr));
+    listenAddr.sin6_family = AF_INET6;
+    listenAddr.sin6_port   = htons(port);
+    inet_pton(AF_INET6, listenIp, &(listenAddr.sin6_addr));
+
+    if (bind(sockFd, (const struct sockaddr *)&listenAddr, sizeof(listenAddr)) < 0)
+    {
+        perror("bind failed");
+        exit(EXIT_FAILURE);
+    }
+
+    // Udp Packet
+    // Ip6 source: fd2a:c30c:87d3:1:ed1c:c91:ccb6:578a
+    // Ip6 destination: fd2a:c30c:87d3:1:ed1c:c91:ccb6:578b
+    // Udp destination port: 12345
+    // Udp payload: "Hello Otbr Netif!"
+    const uint8_t udpPacket[] = {0x60, 0x0e, 0xea, 0x69, 0x00, 0x19, 0x11, 0x40, 0xfd, 0x2a, 0xc3, 0x0c, 0x87,
+                                 0xd3, 0x00, 0x01, 0xed, 0x1c, 0x0c, 0x91, 0xcc, 0xb6, 0x57, 0x8a, 0xfd, 0x2a,
+                                 0xc3, 0x0c, 0x87, 0xd3, 0x00, 0x01, 0xed, 0x1c, 0x0c, 0x91, 0xcc, 0xb6, 0x57,
+                                 0x8b, 0xe7, 0x08, 0x30, 0x39, 0x00, 0x19, 0x36, 0x81, 0x48, 0x65, 0x6c, 0x6c,
+                                 0x6f, 0x20, 0x4f, 0x74, 0x62, 0x72, 0x20, 0x4e, 0x65, 0x74, 0x69, 0x66, 0x21};
+    netif.Ip6Receive(udpPacket, sizeof(udpPacket));
+
+    socklen_t   len = sizeof(listenAddr);
+    int         n   = recvfrom(sockFd, (char *)recvBuf, kMaxIp6Size, MSG_WAITALL, (struct sockaddr *)&listenAddr, &len);
+    std::string udpPayload(reinterpret_cast<const char *>(recvBuf), n);
+    EXPECT_EQ(udpPayload, "Hello Otbr Netif!");
+
+    close(sockFd);
+    netif.Deinit();
+}
+
+TEST(Netif, WpanIfSendIp6PacketCorrectly_AfterReceivingOnIf)
+{
+    bool        received = false;
+    std::string receivedPayload;
+    const char *hello = "Hello Otbr Netif!";
+
+    auto Ip6SendTestImpl = [&received, &receivedPayload](const uint8_t *aData, uint16_t aLength) {
+        const ip6_hdr *ipv6_header = reinterpret_cast<const ip6_hdr *>(aData);
+        if (ipv6_header->ip6_nxt == IPPROTO_UDP)
+        {
+            const uint8_t *udpPayload    = aData + aLength - ntohs(ipv6_header->ip6_plen) + sizeof(udphdr);
+            uint16_t       udpPayloadLen = ntohs(ipv6_header->ip6_plen) - sizeof(udphdr);
+            receivedPayload              = std::string(reinterpret_cast<const char *>(udpPayload), udpPayloadLen);
+
+            received = true;
+        }
+
+        return OTBR_ERROR_NONE;
+    };
+
+    otbr::Netif netif;
+    EXPECT_EQ(netif.Init("wpan0", Ip6SendTestImpl), OT_ERROR_NONE);
+
+    // OMR Prefix: fd76:a5d1:fcb0:1707::/64
+    const otIp6Address kOmr = {
+        {0xfd, 0x76, 0xa5, 0xd1, 0xfc, 0xb0, 0x17, 0x07, 0xf3, 0xc7, 0xd8, 0x8c, 0xef, 0xd1, 0x24, 0xa9}};
+    std::vector<otbr::Ip6AddressInfo> addrs = {
+        {kOmr, 64, 0, 1, 0},
+    };
+    netif.UpdateIp6UnicastAddresses(addrs);
+    netif.SetNetifState(true);
+
+    // Send a UDP packet destined to an address with OMR prefix.
+    {
+        int                 sockFd;
+        const uint16_t      destPort = 12345;
+        struct sockaddr_in6 destAddr;
+        const char         *destIp = "fd76:a5d1:fcb0:1707:3f1:47ce:85d3:77f";
+
+        if ((sockFd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
+        {
+            perror("socket creation failed");
+            exit(EXIT_FAILURE);
+        }
+
+        memset(&destAddr, 0, sizeof(destAddr));
+        destAddr.sin6_family = AF_INET6;
+        destAddr.sin6_port   = htons(destPort);
+        inet_pton(AF_INET6, destIp, &(destAddr.sin6_addr));
+
+        if (sendto(sockFd, hello, strlen(hello), MSG_CONFIRM, (const struct sockaddr *)&destAddr, sizeof(destAddr)) < 0)
+        {
+            FAIL() << "Failed to send UDP packet through WPAN interface";
+        }
+        close(sockFd);
+    }
+
+    otbr::MainloopContext context;
+    while (!received)
+    {
+        context.mMaxFd   = -1;
+        context.mTimeout = {100, 0};
+        FD_ZERO(&context.mReadFdSet);
+        FD_ZERO(&context.mWriteFdSet);
+        FD_ZERO(&context.mErrorFdSet);
+
+        netif.UpdateFdSet(&context);
+        int rval = select(context.mMaxFd + 1, &context.mReadFdSet, &context.mWriteFdSet, &context.mErrorFdSet,
+                          &context.mTimeout);
+        if (rval < 0)
+        {
+            perror("select failed");
+            exit(EXIT_FAILURE);
+        }
+        netif.Process(&context);
+    }
+
+    EXPECT_STREQ(receivedPayload.c_str(), hello);
+
+    netif.Deinit();
+}
+#endif // __linux__
diff --git a/tests/unit/test_once_callback.cpp b/tests/gtest/test_once_callback.cpp
similarity index 91%
rename from tests/unit/test_once_callback.cpp
rename to tests/gtest/test_once_callback.cpp
index b43682c6..a3276f15 100644
--- a/tests/unit/test_once_callback.cpp
+++ b/tests/gtest/test_once_callback.cpp
@@ -26,24 +26,22 @@
  *    POSSIBILITY OF SUCH DAMAGE.
  */
 
-#include "common/callback.hpp"
-
-#include <CppUTest/TestHarness.h>
+#include <gtest/gtest.h>
 
-TEST_GROUP(IsNull){};
+#include "common/callback.hpp"
 
 TEST(IsNull, NullptrIsNull)
 {
     otbr::OnceCallback<void(void)> noop = nullptr;
 
-    CHECK_TRUE(noop.IsNull());
+    EXPECT_TRUE(noop.IsNull());
 }
 
 TEST(IsNull, NonNullptrIsNotNull)
 {
     otbr::OnceCallback<void(void)> noop = [](void) {};
 
-    CHECK_FALSE(noop.IsNull());
+    EXPECT_FALSE(noop.IsNull());
 }
 
 TEST(IsNull, IsNullAfterInvoking)
@@ -52,16 +50,14 @@ TEST(IsNull, IsNullAfterInvoking)
 
     std::move(square)(5);
 
-    CHECK_TRUE(square.IsNull());
+    EXPECT_TRUE(square.IsNull());
 }
 
-TEST_GROUP(VerifyInvocation){};
-
 TEST(VerifyInvocation, CallbackResultIsExpected)
 {
     otbr::OnceCallback<int(int)> square = [](int x) { return x * x; };
 
     int ret = std::move(square)(5);
 
-    CHECK_EQUAL(ret, 25);
+    EXPECT_EQ(ret, 25);
 }
diff --git a/tests/unit/test_pskc.cpp b/tests/gtest/test_pskc.cpp
similarity index 72%
rename from tests/unit/test_pskc.cpp
rename to tests/gtest/test_pskc.cpp
index 12fb6eaa..6120a167 100644
--- a/tests/unit/test_pskc.cpp
+++ b/tests/gtest/test_pskc.cpp
@@ -26,39 +26,40 @@
  *    POSSIBILITY OF SUCH DAMAGE.
  */
 
-#include <CppUTest/TestHarness.h>
+#include <vector>
 
-#include "utils/pskc.hpp"
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
 
-TEST_GROUP(Pskc)
-{
-    otbr::Psk::Pskc mPSKc;
-};
+using ::testing::ElementsAreArray;
+
+#include "utils/pskc.hpp"
 
 TEST(Pskc, Test123456_0001020304050607_OpenThread)
 {
+    otbr::Psk::Pskc pskc;
+
     uint8_t extpanid[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
     uint8_t expected[] = {
         0xb7, 0x83, 0x81, 0x27, 0x89, 0x91, 0x1e, 0xb4, 0xea, 0x76, 0x59, 0x6c, 0x9c, 0xed, 0x2a, 0x69,
     };
-    const uint8_t *pskc = nullptr;
 
-    pskc = mPSKc.ComputePskc(extpanid, "OpenThread", "123456");
-    MEMCMP_EQUAL(expected, pskc, sizeof(expected));
+    const uint8_t *actual = pskc.ComputePskc(extpanid, "OpenThread", "123456");
+    EXPECT_THAT(std::vector<uint8_t>(actual, actual + OT_PSKC_LENGTH), ElementsAreArray(expected));
 }
 
 TEST(Pskc, Test_TruncatedNetworkNamePskc_OpenThread)
 {
-    uint8_t        extpanid[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
-    const uint8_t *pskc       = nullptr;
-    uint8_t        expected[OT_PSKC_LENGTH];
+    otbr::Psk::Pskc pskc;
+    uint8_t         extpanid[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
+    uint8_t         expected[OT_PSKC_LENGTH];
 
     // First run with shorter network name (max)
-    pskc = mPSKc.ComputePskc(extpanid, "OpenThread123456", "123456");
-    memcpy(expected, pskc, OT_PSKC_LENGTH);
+    const uint8_t *actual = pskc.ComputePskc(extpanid, "OpenThread123456", "123456");
+    memcpy(expected, actual, OT_PSKC_LENGTH);
 
     // Second run with longer network name that gets truncated
-    pskc = mPSKc.ComputePskc(extpanid, "OpenThread123456NetworkNameThatExceedsBuffer", "123456");
+    actual = pskc.ComputePskc(extpanid, "OpenThread123456NetworkNameThatExceedsBuffer", "123456");
 
-    MEMCMP_EQUAL(expected, pskc, OT_PSKC_LENGTH);
+    EXPECT_THAT(std::vector<uint8_t>(actual, actual + OT_PSKC_LENGTH), ElementsAreArray(expected));
 }
diff --git a/tests/unit/test_task_runner.cpp b/tests/gtest/test_task_runner.cpp
similarity index 92%
rename from tests/unit/test_task_runner.cpp
rename to tests/gtest/test_task_runner.cpp
index 45aa6187..fedc776d 100644
--- a/tests/unit/test_task_runner.cpp
+++ b/tests/gtest/test_task_runner.cpp
@@ -26,16 +26,14 @@
  *    POSSIBILITY OF SUCH DAMAGE.
  */
 
-#include "common/task_runner.hpp"
-
 #include <atomic>
 #include <mutex>
 #include <thread>
-#include <unistd.h>
 
-#include <CppUTest/TestHarness.h>
+#include <gtest/gtest.h>
+#include <unistd.h>
 
-TEST_GROUP(TaskRunner){};
+#include "common/task_runner.hpp"
 
 TEST(TaskRunner, TestSingleThread)
 {
@@ -63,10 +61,10 @@ TEST(TaskRunner, TestSingleThread)
     taskRunner.Update(mainloop);
     rval = select(mainloop.mMaxFd + 1, &mainloop.mReadFdSet, &mainloop.mWriteFdSet, &mainloop.mErrorFdSet,
                   &mainloop.mTimeout);
-    CHECK_EQUAL(1, rval);
+    EXPECT_EQ(1, rval);
 
     taskRunner.Process(mainloop);
-    CHECK_EQUAL(3, counter);
+    EXPECT_EQ(3, counter);
 }
 
 TEST(TaskRunner, TestTasksOrder)
@@ -90,12 +88,12 @@ TEST(TaskRunner, TestTasksOrder)
     taskRunner.Update(mainloop);
     rval = select(mainloop.mMaxFd + 1, &mainloop.mReadFdSet, &mainloop.mWriteFdSet, &mainloop.mErrorFdSet,
                   &mainloop.mTimeout);
-    CHECK_TRUE(rval == 1);
+    EXPECT_EQ(rval, 1);
 
     taskRunner.Process(mainloop);
 
     // Make sure the tasks are executed in the order of posting.
-    STRCMP_EQUAL("abc", str.c_str());
+    EXPECT_STREQ("abc", str.c_str());
 }
 
 TEST(TaskRunner, TestMultipleThreads)
@@ -125,7 +123,7 @@ TEST(TaskRunner, TestMultipleThreads)
         taskRunner.Update(mainloop);
         rval = select(mainloop.mMaxFd + 1, &mainloop.mReadFdSet, &mainloop.mWriteFdSet, &mainloop.mErrorFdSet,
                       &mainloop.mTimeout);
-        CHECK_EQUAL(1, rval);
+        EXPECT_EQ(1, rval);
 
         taskRunner.Process(mainloop);
     }
@@ -135,7 +133,7 @@ TEST(TaskRunner, TestMultipleThreads)
         th.join();
     }
 
-    CHECK_EQUAL(10, counter.load());
+    EXPECT_EQ(10, counter.load());
 }
 
 TEST(TaskRunner, TestPostAndWait)
@@ -166,7 +164,7 @@ TEST(TaskRunner, TestPostAndWait)
         taskRunner.Update(mainloop);
         rval = select(mainloop.mMaxFd + 1, &mainloop.mReadFdSet, &mainloop.mWriteFdSet, &mainloop.mErrorFdSet,
                       &mainloop.mTimeout);
-        CHECK_EQUAL(1, rval);
+        EXPECT_EQ(1, rval);
 
         taskRunner.Process(mainloop);
     }
@@ -176,8 +174,8 @@ TEST(TaskRunner, TestPostAndWait)
         th.join();
     }
 
-    CHECK_EQUAL(55, total);
-    CHECK_EQUAL(10, counter.load());
+    EXPECT_EQ(55, total);
+    EXPECT_EQ(10, counter.load());
 }
 
 TEST(TaskRunner, TestDelayedTasks)
@@ -207,7 +205,7 @@ TEST(TaskRunner, TestDelayedTasks)
         taskRunner.Update(mainloop);
         rval = select(mainloop.mMaxFd + 1, &mainloop.mReadFdSet, &mainloop.mWriteFdSet, &mainloop.mErrorFdSet,
                       &mainloop.mTimeout);
-        CHECK_TRUE(rval >= 0 || errno == EINTR);
+        EXPECT_TRUE(rval >= 0 || errno == EINTR);
 
         taskRunner.Process(mainloop);
     }
@@ -217,7 +215,7 @@ TEST(TaskRunner, TestDelayedTasks)
         th.join();
     }
 
-    CHECK_EQUAL(10, counter.load());
+    EXPECT_EQ(10, counter.load());
 }
 
 TEST(TaskRunner, TestDelayedTasksOrder)
@@ -244,13 +242,13 @@ TEST(TaskRunner, TestDelayedTasksOrder)
         taskRunner.Update(mainloop);
         rval = select(mainloop.mMaxFd + 1, &mainloop.mReadFdSet, &mainloop.mWriteFdSet, &mainloop.mErrorFdSet,
                       &mainloop.mTimeout);
-        CHECK_TRUE(rval >= 0 || errno == EINTR);
+        EXPECT_TRUE(rval >= 0 || errno == EINTR);
 
         taskRunner.Process(mainloop);
     }
 
     // Make sure that tasks with smaller delay are executed earlier.
-    STRCMP_EQUAL("bac", str.c_str());
+    EXPECT_STREQ("bac", str.c_str());
 }
 
 TEST(TaskRunner, TestCancelDelayedTasks)
@@ -265,11 +263,11 @@ TEST(TaskRunner, TestCancelDelayedTasks)
     tid4 = taskRunner.Post(std::chrono::milliseconds(40), [&]() { str.push_back('d'); });
     tid5 = taskRunner.Post(std::chrono::milliseconds(50), [&]() { str.push_back('e'); });
 
-    CHECK(0 < tid1);
-    CHECK(tid1 < tid2);
-    CHECK(tid2 < tid3);
-    CHECK(tid3 < tid4);
-    CHECK(tid4 < tid5);
+    EXPECT_TRUE(0 < tid1);
+    EXPECT_TRUE(tid1 < tid2);
+    EXPECT_TRUE(tid2 < tid3);
+    EXPECT_TRUE(tid3 < tid4);
+    EXPECT_TRUE(tid4 < tid5);
 
     taskRunner.Cancel(tid2);
 
@@ -294,13 +292,13 @@ TEST(TaskRunner, TestCancelDelayedTasks)
         taskRunner.Update(mainloop);
         rval = select(mainloop.mMaxFd + 1, &mainloop.mReadFdSet, &mainloop.mWriteFdSet, &mainloop.mErrorFdSet,
                       &mainloop.mTimeout);
-        CHECK_TRUE(rval >= 0 || errno == EINTR);
+        EXPECT_TRUE(rval >= 0 || errno == EINTR);
 
         taskRunner.Process(mainloop);
     }
 
     // Make sure the delayed task was not executed.
-    STRCMP_EQUAL("ae", str.c_str());
+    EXPECT_STREQ("ae", str.c_str());
 
     // Make sure it's fine to cancel expired task IDs.
     taskRunner.Cancel(tid1);
@@ -337,7 +335,7 @@ TEST(TaskRunner, TestAllAPIs)
         taskRunner.Update(mainloop);
         rval = select(mainloop.mMaxFd + 1, &mainloop.mReadFdSet, &mainloop.mWriteFdSet, &mainloop.mErrorFdSet,
                       &mainloop.mTimeout);
-        CHECK_TRUE(rval >= 0 || errno == EINTR);
+        EXPECT_TRUE(rval >= 0 || errno == EINTR);
 
         taskRunner.Process(mainloop);
     }
@@ -347,5 +345,5 @@ TEST(TaskRunner, TestAllAPIs)
         th.join();
     }
 
-    CHECK_EQUAL(30, counter.load());
+    EXPECT_EQ(30, counter.load());
 }
diff --git a/tests/mdns/CMakeLists.txt b/tests/mdns/CMakeLists.txt
index 861a79f1..f4778fee 100644
--- a/tests/mdns/CMakeLists.txt
+++ b/tests/mdns/CMakeLists.txt
@@ -87,20 +87,3 @@ set_tests_properties(
     PROPERTIES
         ENVIRONMENT "OTBR_MDNS=${OTBR_MDNS};OTBR_TEST_MDNS=$<TARGET_FILE:otbr-test-mdns>"
 )
-
-add_executable(otbr-test-mdns-subscribe
-    test_subscribe.cpp
-)
-
-target_link_libraries(otbr-test-mdns-subscribe PRIVATE
-    otbr-config
-    otbr-mdns
-    $<$<BOOL:${CPPUTEST_LIBRARY_DIRS}>:-L$<JOIN:${CPPUTEST_LIBRARY_DIRS}," -L">>
-    ${CPPUTEST_LIBRARIES}
-)
-
-
-add_test(
-    NAME mdns-subscribe
-    COMMAND otbr-test-mdns-subscribe
-)
diff --git a/tests/scripts/bootstrap.sh b/tests/scripts/bootstrap.sh
index f3bdf513..9c175970 100755
--- a/tests/scripts/bootstrap.sh
+++ b/tests/scripts/bootstrap.sh
@@ -113,7 +113,7 @@ case "$(uname)" in
 
         if [ "$BUILD_TARGET" == check ] || [ "$BUILD_TARGET" == meshcop ]; then
             install_openthread_binraries
-            sudo apt-get install --no-install-recommends -y avahi-daemon avahi-utils cpputest
+            sudo apt-get install --no-install-recommends -y avahi-daemon avahi-utils
             configure_network
         fi
 
diff --git a/tests/scripts/expect/_common.exp b/tests/scripts/expect/_common.exp
new file mode 100644
index 00000000..bb02ff81
--- /dev/null
+++ b/tests/scripts/expect/_common.exp
@@ -0,0 +1,103 @@
+#!/usr/bin/expect -f
+#
+#  Copyright (c) 2024, The OpenThread Authors.
+#  All rights reserved.
+#
+#  Redistribution and use in source and binary forms, with or without
+#  modification, are permitted provided that the following conditions are met:
+#  1. Redistributions of source code must retain the above copyright
+#     notice, this list of conditions and the following disclaimer.
+#  2. Redistributions in binary form must reproduce the above copyright
+#     notice, this list of conditions and the following disclaimer in the
+#     documentation and/or other materials provided with the distribution.
+#  3. Neither the name of the copyright holder nor the
+#     names of its contributors may be used to endorse or promote products
+#     derived from this software without specific prior written permission.
+#
+#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+#  POSSIBILITY OF SUCH DAMAGE.
+#
+
+proc wait_for {command success {failure {[\r\n]FAILURE_NOT_EXPECTED[\r\n]}}} {
+    set timeout 1
+    for {set i 0} {$i < 40} {incr i} {
+        if {$command != ""} {
+            send "$command\n"
+        }
+
+        expect {
+            -re $success {
+                return 0
+            }
+            -re $failure {
+                fail "Failed due to '$failure' found"
+            }
+            timeout {
+                # Do nothing
+            }
+        }
+    }
+    fail "Failed due to '$success' not found"
+}
+
+proc expect_line {line} {
+    set timeout 10
+    expect -re "\[\r\n \]($line)(?=\[\r\n>\])"
+    return $expect_out(1,string)
+}
+
+# type: The type of the node.
+#   Possible values:
+#   1. cli: The cli app. ot-cli-ftd or ot-cli-mtd
+#   2. otbr: The otbr-agent.
+#
+# sim_app: The path of the simulation app to start the node.
+#   If type is 'cli', sim_app is the path of the cli app.
+#   If type is 'otbr', sim_app is the path of the coprocessor. It could be 'ot-rcp', 'ot-ncp-ftd'
+#     or 'ot-ncp-mtd'.
+proc spawn_node {id type sim_app} {
+    global spawn_id
+    global spawn_ids
+    global argv0
+
+    send_user "\n# ${id} ${type} ${sim_app}\n"
+
+    switch -regexp ${type} {
+        cli {
+            spawn $sim_app $id
+            send "factoryreset\n"
+            wait_for "state" "disabled"
+            expect_line "Done"
+            send "routerselectionjitter 1\n"
+            expect_line "Done"
+
+            expect_after {
+                timeout { fail "Timed out" }
+            }
+        }
+        otbr {
+            spawn $::env(EXP_OTBR_AGENT_PATH) -I $::env(EXP_TUN_NAME) -d7 "spinel+hdlc+forkpty://${sim_app}?forkpty-arg=${id}"
+        }
+    }
+
+    set spawn_ids($id) $spawn_id
+
+    return $spawn_id
+}
+
+proc switch_node {id} {
+    global spawn_ids
+    global spawn_id
+
+    send_user "\n# ${id}\n"
+    set spawn_id $spawn_ids($id)
+}
diff --git a/tests/scripts/expect/ncp_get_device_role.exp b/tests/scripts/expect/ncp_get_device_role.exp
new file mode 100755
index 00000000..72b361b7
--- /dev/null
+++ b/tests/scripts/expect/ncp_get_device_role.exp
@@ -0,0 +1,46 @@
+#!/usr/bin/expect -f
+#
+#  Copyright (c) 2024, The OpenThread Authors.
+#  All rights reserved.
+#
+#  Redistribution and use in source and binary forms, with or without
+#  modification, are permitted provided that the following conditions are met:
+#  1. Redistributions of source code must retain the above copyright
+#     notice, this list of conditions and the following disclaimer.
+#  2. Redistributions in binary form must reproduce the above copyright
+#     notice, this list of conditions and the following disclaimer in the
+#     documentation and/or other materials provided with the distribution.
+#  3. Neither the name of the copyright holder nor the
+#     names of its contributors may be used to endorse or promote products
+#     derived from this software without specific prior written permission.
+#
+#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+#  POSSIBILITY OF SUCH DAMAGE.
+#
+source "tests/scripts/expect/_common.exp"
+
+spawn_node 1 otbr $::env(EXP_OT_NCP_PATH)
+
+sleep 1
+
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --print-reply --reply-timeout=1000 /io/openthread/BorderRouter/wpan0 org.freedesktop.DBus.Properties.Get string:io.openthread.BorderRouter string:DeviceRole
+expect -re {disabled} {
+} timeout {
+    puts "timeout!"
+    exit 1
+}
+expect eof
+
+# Shut down otbr-agent
+switch_node 1
+send "\x04"
+expect eof
diff --git a/tests/scripts/expect/ncp_join_leave.exp b/tests/scripts/expect/ncp_join_leave.exp
new file mode 100755
index 00000000..a6c25ab2
--- /dev/null
+++ b/tests/scripts/expect/ncp_join_leave.exp
@@ -0,0 +1,76 @@
+#!/usr/bin/expect -f
+#
+#  Copyright (c) 2024, The OpenThread Authors.
+#  All rights reserved.
+#
+#  Redistribution and use in source and binary forms, with or without
+#  modification, are permitted provided that the following conditions are met:
+#  1. Redistributions of source code must retain the above copyright
+#     notice, this list of conditions and the following disclaimer.
+#  2. Redistributions in binary form must reproduce the above copyright
+#     notice, this list of conditions and the following disclaimer in the
+#     documentation and/or other materials provided with the distribution.
+#  3. Neither the name of the copyright holder nor the
+#     names of its contributors may be used to endorse or promote products
+#     derived from this software without specific prior written permission.
+#
+#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+#  POSSIBILITY OF SUCH DAMAGE.
+#
+
+source "tests/scripts/expect/_common.exp"
+
+set dataset "0e080000000000010000000300001435060004001fffe002087d61eb42cdc48d6a0708fd0d07fca1b9f0500510ba088fc2bd6c3b3897f7a10f58263ff3030f4f70656e5468726561642d353234660102524f04109dc023ccd447b12b50997ef68020f19e0c0402a0f7f8"
+set dataset_dbus "0x0e,0x08,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x03,0x00,0x00,0x14,0x35,0x06,0x00,0x04,0x00,0x1f,0xff,0xe0,0x02,0x08,0x7d,0x61,0xeb,0x42,0xcd,0xc4,0x8d,0x6a,0x07,0x08,0xfd,0x0d,0x07,0xfc,0xa1,0xb9,0xf0,0x50,0x05,0x10,0xba,0x08,0x8f,0xc2,0xbd,0x6c,0x3b,0x38,0x97,0xf7,0xa1,0x0f,0x58,0x26,0x3f,0xf3,0x03,0x0f,0x4f,0x70,0x65,0x6e,0x54,0x68,0x72,0x65,0x61,0x64,0x2d,0x35,0x32,0x34,0x66,0x01,0x02,0x52,0x4f,0x04,0x10,0x9d,0xc0,0x23,0xcc,0xd4,0x47,0xb1,0x2b,0x50,0x99,0x7e,0xf6,0x80,0x20,0xf1,0x9e,0x0c,0x04,0x02,0xa0,0xf7,0xf8"
+
+# Step 1. Start a Thread node and create a Thread network
+spawn_node 1 cli $::env(EXP_OT_CLI_PATH)
+
+send "dataset set active ${dataset}\n"
+expect_line "Done"
+send "ifconfig up\n"
+expect_line "Done"
+send "thread start\n"
+expect_line "Done"
+wait_for "state" "leader"
+expect_line "Done"
+
+
+# Step 2. Start otbr-agent with a NCP and join the network by dbus join method
+spawn_node 2 otbr $::env(EXP_OT_NCP_PATH)
+sleep 1
+
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 io.openthread.BorderRouter.Join "array:byte:${dataset_dbus}"
+expect eof
+
+# Step 3. Wait 10 seconds, check if the otbr-agent has attached successfully
+sleep 10
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --print-reply --reply-timeout=1000 /io/openthread/BorderRouter/wpan0 org.freedesktop.DBus.Properties.Get string:io.openthread.BorderRouter string:DeviceRole
+expect -re {router|child} {
+} timeout {
+    puts "timeout!"
+    exit 1
+}
+expect eof
+
+# Step 4. Use dbus leave method to let otbr-agent leave the network
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 io.openthread.BorderRouter.LeaveNetwork
+expect eof
+
+# Step 5. Verify the state of otbr-agent is 'disabled'
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --print-reply --reply-timeout=1000 /io/openthread/BorderRouter/wpan0 org.freedesktop.DBus.Properties.Get string:io.openthread.BorderRouter string:DeviceRole
+expect -re {disabled} {
+} timeout {
+    puts "timeout!"
+    exit 1
+}
+expect eof
diff --git a/tests/scripts/expect/ncp_netif_address_update.exp b/tests/scripts/expect/ncp_netif_address_update.exp
new file mode 100755
index 00000000..974b5633
--- /dev/null
+++ b/tests/scripts/expect/ncp_netif_address_update.exp
@@ -0,0 +1,94 @@
+#!/usr/bin/expect -f
+#
+#  Copyright (c) 2024, The OpenThread Authors.
+#  All rights reserved.
+#
+#  Redistribution and use in source and binary forms, with or without
+#  modification, are permitted provided that the following conditions are met:
+#  1. Redistributions of source code must retain the above copyright
+#     notice, this list of conditions and the following disclaimer.
+#  2. Redistributions in binary form must reproduce the above copyright
+#     notice, this list of conditions and the following disclaimer in the
+#     documentation and/or other materials provided with the distribution.
+#  3. Neither the name of the copyright holder nor the
+#     names of its contributors may be used to endorse or promote products
+#     derived from this software without specific prior written permission.
+#
+#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+#  POSSIBILITY OF SUCH DAMAGE.
+#
+source "tests/scripts/expect/_common.exp"
+
+# Dataset
+# Mesh Local Prefix: fd0d:7fc:a1b9:f050::/64
+set dataset_dbus "0x0e,0x08,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x03,0x00,0x00,0x14,0x35,0x06,0x00,0x04,0x00,0x1f,0xff,0xe0,0x02,0x08,0x7d,0x61,0xeb,0x42,0xcd,0xc4,0x8d,0x6a,0x07,0x08,0xfd,0x0d,0x07,0xfc,0xa1,0xb9,0xf0,0x50,0x05,0x10,0xba,0x08,0x8f,0xc2,0xbd,0x6c,0x3b,0x38,0x97,0xf7,0xa1,0x0f,0x58,0x26,0x3f,0xf3,0x03,0x0f,0x4f,0x70,0x65,0x6e,0x54,0x68,0x72,0x65,0x61,0x64,0x2d,0x35,0x32,0x34,0x66,0x01,0x02,0x52,0x4f,0x04,0x10,0x9d,0xc0,0x23,0xcc,0xd4,0x47,0xb1,0x2b,0x50,0x99,0x7e,0xf6,0x80,0x20,0xf1,0x9e,0x0c,0x04,0x02,0xa0,0xf7,0xf8"
+
+# Step 1. Start otbr-agent with a NCP and join the network by dbus join method.
+spawn_node 2 otbr $::env(EXP_OT_NCP_PATH)
+sleep 1
+
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 io.openthread.BorderRouter.Join "array:byte:${dataset_dbus}"
+expect eof
+
+# Step 2. Wait 10 seconds for it becomes a leader.
+sleep 10
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --print-reply --reply-timeout=1000 /io/openthread/BorderRouter/wpan0 org.freedesktop.DBus.Properties.Get string:io.openthread.BorderRouter string:DeviceRole
+expect -re {leader} {
+} timeout {
+    puts "timeout!"
+    exit 1
+}
+expect eof
+
+# Step 3. Verify the addresses on wpan.
+# There should be:
+#   1. ml eid
+#   2. ml anycast
+#   3. ml rloc
+#   4. link local
+spawn ip addr show wpan0
+expect -re {fd0d:7fc:a1b9:f050(:[0-9a-f]{1,4}){4,4}}
+expect -re {fd0d:7fc:a1b9:f050(:[0-9a-f]{1,4}){4,4}}
+expect -re {fd0d:7fc:a1b9:f050(:[0-9a-f]{1,4}){4,4}}
+expect -re {fe80:(:[0-9a-f]{1,4}){4,4}}
+expect eof
+
+# Multicast addresses should contain:
+#   1. ff01::1
+#   2. ff02::1
+#   3. ff02::2
+#   4. ff03::1
+#   5. ff03::2
+spawn ip maddr show dev wpan0
+expect eof
+set maddr_output $expect_out(buffer)
+if {![string match "*ff01::1*" $maddr_output]} { fail "No multicast address ff01::1" }
+if {![string match "*ff02::1*" $maddr_output]} { fail "No multicast address ff02::1" }
+if {![string match "*ff02::2*" $maddr_output]} { fail "No multicast address ff02::2" }
+if {![string match "*ff03::1*" $maddr_output]} { fail "No multicast address ff03::1" }
+if {![string match "*ff03::2*" $maddr_output]} { fail "No multicast address ff03::2" }
+
+# Step 4. Verify the wpan isUp state
+spawn ip link show wpan0
+expect -re {UP}
+expect eof
+
+# Step 5. Use dbus leave method to let the node leave the network
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 io.openthread.BorderRouter.LeaveNetwork
+expect eof
+
+# Step 6. Verify the addresses on wpan.
+# There should be:
+#   1. link local
+spawn ip addr show wpan0
+expect -re {fe80:(:[0-9a-f]{1,4}){4,4}}
+expect eof
diff --git a/tests/scripts/expect/ncp_schedule_migration.exp b/tests/scripts/expect/ncp_schedule_migration.exp
new file mode 100644
index 00000000..c32656f5
--- /dev/null
+++ b/tests/scripts/expect/ncp_schedule_migration.exp
@@ -0,0 +1,80 @@
+#!/usr/bin/expect -f
+#
+#  Copyright (c) 2024, The OpenThread Authors.
+#  All rights reserved.
+#
+#  Redistribution and use in source and binary forms, with or without
+#  modification, are permitted provided that the following conditions are met:
+#  1. Redistributions of source code must retain the above copyright
+#     notice, this list of conditions and the following disclaimer.
+#  2. Redistributions in binary form must reproduce the above copyright
+#     notice, this list of conditions and the following disclaimer in the
+#     documentation and/or other materials provided with the distribution.
+#  3. Neither the name of the copyright holder nor the
+#     names of its contributors may be used to endorse or promote products
+#     derived from this software without specific prior written permission.
+#
+#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+#  POSSIBILITY OF SUCH DAMAGE.
+#
+
+source "tests/scripts/expect/_common.exp"
+
+# Dataset of the initial Thread network
+set dataset "0e080000000000010000000300001435060004001fffe002087d61eb42cdc48d6a0708fd0d07fca1b9f0500510ba088fc2bd6c3b3897f7a10f58263ff3030f4f70656e5468726561642d353234660102524f04109dc023ccd447b12b50997ef68020f19e0c0402a0f7f8"
+set dataset_dbus "0x0e,0x08,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x03,0x00,0x00,0x14,0x35,0x06,0x00,0x04,0x00,0x1f,0xff,0xe0,0x02,0x08,0x7d,0x61,0xeb,0x42,0xcd,0xc4,0x8d,0x6a,0x07,0x08,0xfd,0x0d,0x07,0xfc,0xa1,0xb9,0xf0,0x50,0x05,0x10,0xba,0x08,0x8f,0xc2,0xbd,0x6c,0x3b,0x38,0x97,0xf7,0xa1,0x0f,0x58,0x26,0x3f,0xf3,0x03,0x0f,0x4f,0x70,0x65,0x6e,0x54,0x68,0x72,0x65,0x61,0x64,0x2d,0x35,0x32,0x34,0x66,0x01,0x02,0x52,0x4f,0x04,0x10,0x9d,0xc0,0x23,0xcc,0xd4,0x47,0xb1,0x2b,0x50,0x99,0x7e,0xf6,0x80,0x20,0xf1,0x9e,0x0c,0x04,0x02,0xa0,0xf7,0xf8"
+
+# Dataset of the Thread network to migrate to 
+# (Only updates active timestamp and panid, panid is set to 0x9999)
+set dataset1 "0e080000000000020000000300001435060004001fffe002087d61eb42cdc48d6a0708fd0d07fca1b9f0500510ba088fc2bd6c3b3897f7a10f58263ff3030f4f70656e5468726561642d353234660102999904109dc023ccd447b12b50997ef68020f19e0c0402a0f7f8"
+set dataset1_dbus "0x0e,0x08,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x03,0x00,0x00,0x14,0x35,0x06,0x00,0x04,0x00,0x1f,0xff,0xe0,0x02,0x08,0x7d,0x61,0xeb,0x42,0xcd,0xc4,0x8d,0x6a,0x07,0x08,0xfd,0x0d,0x07,0xfc,0xa1,0xb9,0xf0,0x50,0x05,0x10,0xba,0x08,0x8f,0xc2,0xbd,0x6c,0x3b,0x38,0x97,0xf7,0xa1,0x0f,0x58,0x26,0x3f,0xf3,0x03,0x0f,0x4f,0x70,0x65,0x6e,0x54,0x68,0x72,0x65,0x61,0x64,0x2d,0x35,0x32,0x34,0x66,0x01,0x02,0x99,0x99,0x04,0x10,0x9d,0xc0,0x23,0xcc,0xd4,0x47,0xb1,0x2b,0x50,0x99,0x7e,0xf6,0x80,0x20,0xf1,0x9e,0x0c,0x04,0x02,0xa0,0xf7,0xf8"
+
+# Step 1. Start otbr-agent with a NCP and join the network by dbus join method
+spawn_node 1 otbr $::env(EXP_OT_NCP_PATH)
+sleep 1
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 io.openthread.BorderRouter.Join "array:byte:${dataset_dbus}"
+expect eof
+
+# Step 2. Wait 10 seconds, check if the otbr-agent has attached successfully
+sleep 10
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --print-reply --reply-timeout=1000 /io/openthread/BorderRouter/wpan0 org.freedesktop.DBus.Properties.Get string:io.openthread.BorderRouter string:DeviceRole
+expect -re {leader} {
+} timeout {
+    puts "timeout!"
+    exit 1
+}
+expect eof
+
+# Step 3. Start a Thread node and create a Thread network
+spawn_node 2 cli $::env(EXP_OT_CLI_PATH)
+
+send "dataset set active ${dataset}\n"
+expect_line "Done"
+send "mode rn\n"
+expect_line "Done"
+send "ifconfig up\n"
+expect_line "Done"
+send "thread start\n"
+expect_line "Done"
+wait_for "state" "child"
+expect_line "Done"
+
+# Step 4. Call ScheduleMigration method to migrate to another Thread network after 30s
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 io.openthread.BorderRouter.ScheduleMigration "array:byte:${dataset1_dbus}" "uint32:0x7530"
+expect eof
+
+# Step 5. Wait 31 seconds, check if the otbr-agent has migrated successfully by checking child's panid
+sleep 31
+switch_node 2
+send "panid\n"
+expect_line "0x9999"
+expect_line "Done"
diff --git a/tests/scripts/expect/ncp_test_schedule_migration_dbus_api.exp b/tests/scripts/expect/ncp_test_schedule_migration_dbus_api.exp
new file mode 100755
index 00000000..94909534
--- /dev/null
+++ b/tests/scripts/expect/ncp_test_schedule_migration_dbus_api.exp
@@ -0,0 +1,51 @@
+#!/usr/bin/expect -f
+#
+#  Copyright (c) 2024, The OpenThread Authors.
+#  All rights reserved.
+#
+#  Redistribution and use in source and binary forms, with or without
+#  modification, are permitted provided that the following conditions are met:
+#  1. Redistributions of source code must retain the above copyright
+#     notice, this list of conditions and the following disclaimer.
+#  2. Redistributions in binary form must reproduce the above copyright
+#     notice, this list of conditions and the following disclaimer in the
+#     documentation and/or other materials provided with the distribution.
+#  3. Neither the name of the copyright holder nor the
+#     names of its contributors may be used to endorse or promote products
+#     derived from this software without specific prior written permission.
+#
+#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+#  POSSIBILITY OF SUCH DAMAGE.
+#
+
+source "tests/scripts/expect/_common.exp"
+
+set dataset_valid "0x0e,0x08,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x03,0x00,0x00,0x0d,0x35,0x06,0x00,0x04,0x00,0x1f,0xff,0xe0,0x02,0x08,0x1f,0xeb,0xac,0x0f,0xca,0x10,0x8c,0xcd,0x07,0x08,0xfd,0x26,0x9e,0x9f,0x6b,0x8a,0x2a,0xa1,0x05,0x10,0xd3,0x7e,0x6d,0x55,0x73,0xcc,0x88,0x43,0xdb,0x22,0x3b,0x00,0xcd,0x8f,0xf2,0xb0,0x03,0x0f,0x4f,0x70,0x65,0x6e,0x54,0x68,0x72,0x65,0x61,0x64,0x2d,0x65,0x36,0x62,0x37,0x04,0x10,0x16,0xcc,0x1e,0x42,0x3a,0x9c,0xe9,0x47,0xf6,0x05,0x9a,0xe5,0xb8,0x38,0x17,0xb7,0x0c,0x04,0x02,0xa0,0xf7,0xf8,0x01,0x02,0x99,0x99"
+
+set dataset_has_pending_timestamp "$dataset_valid,0x33,0x08,0x00,0x00,0x07,0x5b,0xcd,0x15,0x00,0x00"
+
+set dataset_has_delay "$dataset_valid,0x34,0x04,0x00,0x00,0x75,0x30"
+
+spawn_node 1 otbr $::env(EXP_OT_NCP_PATH)
+sleep 1
+
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 io.openthread.BorderRouter.ScheduleMigration "array:byte:${dataset_valid}" "uint32:0x7530"
+expect Error.InvalidState
+expect eof
+
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 io.openthread.BorderRouter.ScheduleMigration "array:byte:${dataset_has_pending_timestamp}" "uint32:0x7530"
+expect Error.InvalidArgs
+expect eof
+
+spawn dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 io.openthread.BorderRouter.ScheduleMigration "array:byte:${dataset_has_delay}" "uint32:0x7530"
+expect Error.InvalidArgs
+expect eof
diff --git a/tests/scripts/expect/ncp_version.exp b/tests/scripts/expect/ncp_version.exp
new file mode 100755
index 00000000..7cd3b614
--- /dev/null
+++ b/tests/scripts/expect/ncp_version.exp
@@ -0,0 +1,42 @@
+#!/usr/bin/expect -f
+#
+#  Copyright (c) 2024, The OpenThread Authors.
+#  All rights reserved.
+#
+#  Redistribution and use in source and binary forms, with or without
+#  modification, are permitted provided that the following conditions are met:
+#  1. Redistributions of source code must retain the above copyright
+#     notice, this list of conditions and the following disclaimer.
+#  2. Redistributions in binary form must reproduce the above copyright
+#     notice, this list of conditions and the following disclaimer in the
+#     documentation and/or other materials provided with the distribution.
+#  3. Neither the name of the copyright holder nor the
+#     names of its contributors may be used to endorse or promote products
+#     derived from this software without specific prior written permission.
+#
+#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+#  POSSIBILITY OF SUCH DAMAGE.
+#
+set timeout 1
+
+# Spawn the otbr-agent with NCP in Dry Run mode
+spawn $::env(EXP_OTBR_AGENT_PATH) -I $::env(EXP_TUN_NAME) -v -d7 --radio-version "spinel+hdlc+forkpty://$::env(EXP_OT_NCP_PATH)?forkpty-arg=$::env(EXP_LEADER_NODE_ID)"
+
+# Expect the NCP version
+expect -re {OPENTHREAD/[0-9a-z]{6,9}; SIMULATION} {
+} timeout {
+    puts "timeout!"
+    exit 1
+}
+
+# Wait for the spawned process to terminate
+expect eof
diff --git a/tests/scripts/ncp_mode b/tests/scripts/ncp_mode
new file mode 100755
index 00000000..a6d00067
--- /dev/null
+++ b/tests/scripts/ncp_mode
@@ -0,0 +1,261 @@
+#!/bin/bash
+#
+#  Copyright (c) 2024, The OpenThread Authors.
+#  All rights reserved.
+#
+#  Redistribution and use in source and binary forms, with or without
+#  modification, are permitted provided that the following conditions are met:
+#  1. Redistributions of source code must retain the above copyright
+#     notice, this list of conditions and the following disclaimer.
+#  2. Redistributions in binary form must reproduce the above copyright
+#     notice, this list of conditions and the following disclaimer in the
+#     documentation and/or other materials provided with the distribution.
+#  3. Neither the name of the copyright holder nor the
+#     names of its contributors may be used to endorse or promote products
+#     derived from this software without specific prior written permission.
+#
+#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
+#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
+#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
+#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
+#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
+#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
+#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
+#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
+#  POSSIBILITY OF SUCH DAMAGE.
+#
+# Test basic functionality of otbr-agent under NCP mode.
+#
+# Usage:
+#   ./ncp_mode
+set -euxo pipefail
+
+SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
+readonly SCRIPT_DIR
+EXPECT_SCRIPT_DIR="${SCRIPT_DIR}/expect"
+readonly EXPECT_SCRIPT_DIR
+
+#---------------------------------------
+# Configurations
+#---------------------------------------
+OT_CLI="${OT_CLI:-ot-cli-ftd}"
+readonly OT_CLI
+
+OT_NCP="${OT_NCP:-ot-ncp-ftd}"
+readonly OT_NCP
+
+ABS_TOP_BUILDDIR="$(cd "${top_builddir:-"${SCRIPT_DIR}"/../../}" && pwd)"
+readonly ABS_TOP_BUILDDIR
+
+ABS_TOP_SRCDIR="$(cd "${top_srcdir:-"${SCRIPT_DIR}"/../../}" && pwd)"
+readonly ABS_TOP_SRCDIR
+
+ABS_TOP_OT_SRCDIR="${ABS_TOP_SRCDIR}/third_party/openthread/repo"
+readonly ABS_TOP_OT_SRCDIR
+
+ABS_TOP_OT_BUILDDIR="${ABS_TOP_BUILDDIR}/../simulation"
+readonly ABS_TOP_BUILDDIR
+
+OTBR_COLOR_PASS='\033[0;32m'
+readonly OTBR_COLOR_PASS
+
+OTBR_COLOR_FAIL='\033[0;31m'
+readonly OTBR_COLOR_FAIL
+
+OTBR_COLOR_NONE='\033[0m'
+readonly OTBR_COLOR_NONE
+
+readonly OTBR_VERBOSE="${OTBR_VERBOSE:-0}"
+
+#----------------------------------------
+# Helper functions
+#----------------------------------------
+die()
+{
+    exit_message="$*"
+    echo " *** ERROR: $*"
+    exit 1
+}
+
+exists_or_die()
+{
+    [[ -f $1 ]] || die "Missing file: $1"
+}
+
+executable_or_die()
+{
+    [[ -x $1 ]] || die "Missing executable: $1"
+}
+
+write_syslog()
+{
+    logger -s -p syslog.alert "OTBR_TEST: $*"
+}
+
+#----------------------------------------
+# Test constants
+#----------------------------------------
+TEST_BASE=/tmp/test-otbr
+readonly TEST_BASE
+
+OTBR_AGENT=otbr-agent
+readonly OTBR_AGENT
+
+STAGE_DIR="${TEST_BASE}/stage"
+readonly STAGE_DIR
+
+BUILD_DIR="${TEST_BASE}/build"
+readonly BUILD_DIR
+
+OTBR_DBUS_CONF="${ABS_TOP_BUILDDIR}/src/agent/otbr-agent.conf"
+readonly OTBR_DBUS_CONF
+
+OTBR_AGENT_PATH="${ABS_TOP_BUILDDIR}/src/agent/${OTBR_AGENT}"
+readonly OTBR_AGENT_PATH
+
+# The node ids
+LEADER_NODE_ID=1
+readonly LEADER_NODE_ID
+
+# The TUN device for OpenThread border router.
+TUN_NAME=wpan0
+readonly TUN_NAME
+
+#----------------------------------------
+# Test steps
+#----------------------------------------
+build_ot_simulation()
+{
+    sudo rm -rf "${ABS_TOP_OT_BUILDDIR}/ncp"
+    sudo rm -rf "${ABS_TOP_OT_BUILDDIR}/cli"
+    OT_CMAKE_BUILD_DIR=${ABS_TOP_OT_BUILDDIR}/ncp "${ABS_TOP_OT_SRCDIR}"/script/cmake-build simulation -DOT_MTD=OFF -DOT_APP_CLI=OFF -DOT_APP_RCP=OFF
+    OT_CMAKE_BUILD_DIR=${ABS_TOP_OT_BUILDDIR}/cli "${ABS_TOP_OT_SRCDIR}"/script/cmake-build simulation -DOT_MTD=OFF -DOT_APP_NCP=OFF -DOT_APP_RCP=OFF -DOT_RCP=OFF
+}
+
+test_setup()
+{
+    executable_or_die "${OTBR_AGENT_PATH}"
+
+    # Remove flashes
+    sudo rm -vrf "${TEST_BASE}/tmp"
+    # OPENTHREAD_POSIX_DAEMON_SOCKET_LOCK
+    sudo rm -vf "/tmp/openthread.lock"
+
+    [[ ${BUILD_OT_SIM} == 1 ]] && build_ot_simulation
+    ot_cli=$(find "${ABS_TOP_OT_BUILDDIR}" -name "${OT_CLI}")
+    ot_ncp=$(find "${ABS_TOP_OT_BUILDDIR}" -name "${OT_NCP}")
+
+    # We will be creating a lot of log information
+    # Rotate logs so we have a clean and empty set of logs uncluttered with other stuff
+    if [[ -f /etc/logrotate.conf ]]; then
+        sudo logrotate -f /etc/logrotate.conf || true
+    fi
+
+    # Preparation for otbr-agent
+    exists_or_die "${OTBR_DBUS_CONF}"
+    sudo cp "${OTBR_DBUS_CONF}" /etc/dbus-1/system.d
+
+    write_syslog "AGENT: kill old"
+    sudo killall "${OTBR_AGENT}" || true
+
+    # From now on - all exits are TRAPPED
+    # When they occur, we call the function: output_logs'.
+    trap test_teardown EXIT
+}
+
+test_teardown()
+{
+    # Capture the exit code so we can return it below
+    EXIT_CODE=$?
+    readonly EXIT_CODE
+    write_syslog "EXIT ${EXIT_CODE} - output logs"
+
+    sudo pkill -f "${OTBR_AGENT}" || true
+    sudo pkill -f "${OT_CLI}" || true
+    sudo pkill -f "${OT_NCP}" || true
+    wait
+
+    echo 'clearing all'
+    sudo rm /etc/dbus-1/system.d/otbr-agent.conf || true
+    sudo rm -rf "${STAGE_DIR}" || true
+    sudo rm -rf "${BUILD_DIR}" || true
+
+    exit_message="Test teardown"
+    echo "EXIT ${EXIT_CODE}: MESSAGE: ${exit_message}"
+    exit ${EXIT_CODE}
+}
+
+otbr_exec_expect_script()
+{
+    local log_file="tmp/log_expect"
+
+    for script in "$@"; do
+        echo -e "\n${OTBR_COLOR_PASS}EXEC${OTBR_COLOR_NONE} ${script}"
+        sudo killall ot-rcp || true
+        sudo killall ot-cli || true
+        sudo killall ot-cli-ftd || true
+        sudo killall ot-cli-mtd || true
+        sudo killall ot-ncp-ftd || true
+        sudo killall ot-ncp-mtd || true
+        sudo rm -rf tmp
+        mkdir tmp
+        {
+            sudo -E expect -df "${script}" 2>"${log_file}"
+        } || {
+            local EXIT_CODE=$?
+
+            echo -e "\n${OTBR_COLOR_FAIL}FAIL${OTBR_COLOR_NONE} ${script}"
+            cat "${log_file}" >&2
+            return "${EXIT_CODE}"
+        }
+        echo -e "\n${OTBR_COLOR_PASS}PASS${OTBR_COLOR_NONE} ${script}"
+        if [[ ${OTBR_VERBOSE} == 1 ]]; then
+            cat "${log_file}" >&2
+        fi
+    done
+}
+
+parse_args()
+{
+    BUILD_OT_SIM=1
+    RUN_ALL_TESTS=1
+
+    while [[ $# -gt 0 ]]; do
+        case $1 in
+            --build-ot-sim)
+                BUILD_OT_SIM="$2"
+                shift
+                ;;
+            --one-test)
+                RUN_ALL_TESTS=0
+                TEST_NAME="$2"
+                shift
+                ;;
+        esac
+        shift
+    done
+}
+
+main()
+{
+    parse_args "$@"
+
+    test_setup
+
+    export EXP_OTBR_AGENT_PATH="${OTBR_AGENT_PATH}"
+    export EXP_TUN_NAME="${TUN_NAME}"
+    export EXP_LEADER_NODE_ID="${LEADER_NODE_ID}"
+    export EXP_OT_CLI_PATH="${ot_cli}"
+    export EXP_OT_NCP_PATH="${ot_ncp}"
+
+    if [[ ${RUN_ALL_TESTS} == 0 ]]; then
+        otbr_exec_expect_script "${EXPECT_SCRIPT_DIR}/${TEST_NAME}" || die "ncp expect script failed!"
+    else
+        mapfile -t test_files < <(find "${EXPECT_SCRIPT_DIR}" -type f -name "ncp_*.exp")
+        otbr_exec_expect_script "${test_files[@]}" || die "ncp expect script failed!"
+    fi
+}
+
+main "$@"
diff --git a/tests/unit/test_mdns_mdnssd.cpp b/tests/unit/test_mdns_mdnssd.cpp
deleted file mode 100644
index 6104841a..00000000
--- a/tests/unit/test_mdns_mdnssd.cpp
+++ /dev/null
@@ -1,69 +0,0 @@
-/*
- *    Copyright (c) 2018, The OpenThread Authors.
- *    All rights reserved.
- *
- *    Redistribution and use in source and binary forms, with or without
- *    modification, are permitted provided that the following conditions are met:
- *    1. Redistributions of source code must retain the above copyright
- *       notice, this list of conditions and the following disclaimer.
- *    2. Redistributions in binary form must reproduce the above copyright
- *       notice, this list of conditions and the following disclaimer in the
- *       documentation and/or other materials provided with the distribution.
- *    3. Neither the name of the copyright holder nor the
- *       names of its contributors may be used to endorse or promote products
- *       derived from this software without specific prior written permission.
- *
- *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
- *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
- *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
- *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
- *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
- *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
- *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
- *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
- *    POSSIBILITY OF SUCH DAMAGE.
- */
-
-#include <CppUTest/TestHarness.h>
-
-#include "mdns/mdns_mdnssd.cpp"
-
-TEST_GROUP(MdnsSd){};
-
-TEST(MdnsSd, TestDNSErrorToString)
-{
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoError));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_Unknown));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoSuchName));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoMemory));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadParam));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadReference));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadState));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadFlags));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_Unsupported));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_NotInitialized));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_AlreadyRegistered));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_NameConflict));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_Invalid));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_Firewall));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_Incompatible));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadInterfaceIndex));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_Refused));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoSuchRecord));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoAuth));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoSuchKey));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_NATTraversal));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_DoubleNAT));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadTime));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadSig));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_BadKey));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_Transient));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_ServiceNotRunning));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_NATPortMappingUnsupported));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_NATPortMappingDisabled));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_NoRouter));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_PollingMode));
-    CHECK(nullptr != otbr::Mdns::DNSErrorToString(kDNSServiceErr_Timeout));
-}
diff --git a/third_party/openthread/CMakeLists.txt b/third_party/openthread/CMakeLists.txt
index f07625da..eab6e7c6 100644
--- a/third_party/openthread/CMakeLists.txt
+++ b/third_party/openthread/CMakeLists.txt
@@ -31,6 +31,7 @@ set(OT_ANYCAST_LOCATOR ON CACHE STRING "enable anycast locator" FORCE)
 set(OT_BACKBONE_ROUTER ${OTBR_BACKBONE_ROUTER} CACHE STRING "Enable Backbone Router feature in OpenThread" FORCE)
 set(OT_BACKBONE_ROUTER_DUA_NDPROXYING ${OTBR_DUA_ROUTING} CACHE STRING "Configure DUA ND Proxy feature in OpenThread" FORCE)
 set(OT_BORDER_AGENT ON CACHE STRING "enable border agent" FORCE)
+set(OT_BORDER_AGENT_EPSKC ON CACHE STRING "enable border agent ephemeral PSKc" FORCE)
 set(OT_BORDER_AGENT_ID ON CACHE STRING "enable border agent ID" FORCE)
 set(OT_BORDER_ROUTER ON CACHE STRING "enable border router feature" FORCE)
 set(OT_BORDER_ROUTING ${OTBR_BORDER_ROUTING} CACHE STRING "enable border routing feature" FORCE)
@@ -45,6 +46,7 @@ set(OT_COMMISSIONER ON CACHE STRING "enable commissioner")
 set(OT_DAEMON ON CACHE STRING "enable daemon mode" FORCE)
 set(OT_DATASET_UPDATER ON CACHE STRING "enable dataset updater" FORCE)
 set(OT_DNS_CLIENT ON CACHE STRING "enable DNS client" FORCE)
+set(OT_DNS_CLIENT_OVER_TCP OFF CACHE STRING "disable DNS query over TCP")
 set(OT_DNS_UPSTREAM_QUERY ${OTBR_DNS_UPSTREAM_QUERY} CACHE STRING "enable sending DNS queries to upstream" FORCE)
 set(OT_DNSSD_SERVER ${OTBR_DNSSD_DISCOVERY_PROXY} CACHE STRING "enable DNS-SD server support" FORCE)
 set(OT_ECDSA ON CACHE STRING "enable ECDSA" FORCE)
@@ -66,7 +68,7 @@ set(OT_SERVICE ON CACHE STRING "enable service" FORCE)
 set(OT_SLAAC ON CACHE STRING "enable SLAAC" FORCE)
 set(OT_SRP_CLIENT ON CACHE STRING "enable SRP client" FORCE)
 set(OT_TARGET_OPENWRT ${OTBR_OPENWRT} CACHE STRING "target on OpenWRT" FORCE)
-set(OT_TCP OFF CACHE STRING "disable TCP" FORCE)
+set(OT_TCP OFF CACHE STRING "disable TCP")
 set(OT_TREL ${OTBR_TREL} CACHE STRING "enable TREL" FORCE)
 set(OT_UDP_FORWARD OFF CACHE STRING "disable udp forward" FORCE)
 set(OT_UPTIME ON CACHE STRING "enable uptime" FORCE)
@@ -104,7 +106,6 @@ target_compile_definitions(ot-config INTERFACE
     "-DOPENTHREAD_CONFIG_LOG_CLI=1"
     "-DOPENTHREAD_CONFIG_MAX_STATECHANGE_HANDLERS=3"
     "-DOPENTHREAD_CONFIG_MLE_STEERING_DATA_SET_OOB_ENABLE=1"
-    "-DOPENTHREAD_CONFIG_TCP_ENABLE=0"
     "-DOPENTHREAD_POSIX_CONFIG_FILE=\"${PROJECT_BINARY_DIR}/src/agent/openthread-otbr-posix-config.h\""
 )
 
diff --git a/third_party/openthread/mbedtls-config.h b/third_party/openthread/mbedtls-config.h
index 7646a779..2c1844a0 100644
--- a/third_party/openthread/mbedtls-config.h
+++ b/third_party/openthread/mbedtls-config.h
@@ -103,6 +103,10 @@
 
 #define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8
 
-#include "mbedtls/check_config.h"
+#include "mbedtls/version.h"
+#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
+    // Configuration sanity check. Done automatically in Mbed TLS >= 3.0.
+    #include "mbedtls/check_config.h"
+#endif
 
 #endif // OTBR_MBEDTLS_CONFIG_H_
```

