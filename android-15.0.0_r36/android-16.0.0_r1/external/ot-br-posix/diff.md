```diff
diff --git a/.github/workflows/border_router.yml b/.github/workflows/border_router.yml
index 4b67f2bf..a04e1feb 100644
--- a/.github/workflows/border_router.yml
+++ b/.github/workflows/border_router.yml
@@ -43,7 +43,7 @@ concurrency:
 jobs:
 
   border-router:
-    runs-on: ubuntu-20.04
+    runs-on: ubuntu-22.04
 
     strategy:
       fail-fast: false
@@ -52,65 +52,88 @@ jobs:
           - name: "Border Router (mDNSResponder)"
             otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=OFF -DOTBR_DNS_UPSTREAM_QUERY=ON"
             border_routing: 1
-            nat64: 0
+            internet: 0
+            dnssd_plat: 0
             otbr_mdns: "mDNSResponder"
             cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
             packet_verification: 1
           - name: "Border Router (Avahi)"
             otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=OFF -DOTBR_DNS_UPSTREAM_QUERY=ON"
             border_routing: 1
-            nat64: 0
+            internet: 0
+            dnssd_plat: 0
             otbr_mdns: "avahi"
             cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
             packet_verification: 1
           - name: "Border Router TREL (mDNSResponder)"
             otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=ON -DOTBR_DNS_UPSTREAM_QUERY=ON"
             border_routing: 1
-            nat64: 0
+            internet: 0
+            dnssd_plat: 0
             otbr_mdns: "mDNSResponder"
             cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
             packet_verification: 2
           - name: "Border Router TREL (Avahi)"
             otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=ON -DOTBR_DNS_UPSTREAM_QUERY=ON"
             border_routing: 1
-            nat64: 0
+            internet: 0
+            dnssd_plat: 0
             otbr_mdns: "avahi"
             cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
             packet_verification: 2
           - name: "Border Router MATN (mDNSResponder)"
             otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=OFF -DOTBR_DNS_UPSTREAM_QUERY=ON"
             border_routing: 1
-            nat64: 0
+            internet: 0
+            dnssd_plat: 0
             otbr_mdns: "mDNSResponder"
             cert_scripts: ./tests/scripts/thread-cert/border_router/MATN/*.py
             packet_verification: 1
-          - name: "Border Router NAT64 (mDNSResponder)"
-            otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=OFF -DOTBR_DNS_UPSTREAM_QUERY=ON"
+          - name: "Border Router Internet Access Features (mDNSResponder)"
+            otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=OFF -DOTBR_DNS_UPSTREAM_QUERY=ON -DOTBR_DHCP6_PD=ON"
             border_routing: 1
-            nat64: 1
+            internet: 1
+            dnssd_plat: 0
             otbr_mdns: "mDNSResponder"
-            cert_scripts: ./tests/scripts/thread-cert/border_router/nat64/*.py
+            cert_scripts: ./tests/scripts/thread-cert/border_router/internet/*.py
             packet_verification: 1
           - name: "Backbone Router"
             otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=OFF -DOTBR_DNS_UPSTREAM_QUERY=ON"
             border_routing: 0
-            nat64: 0
+            internet: 0
+            dnssd_plat: 0
             otbr_mdns: "mDNSResponder"
             cert_scripts: ./tests/scripts/thread-cert/backbone/*.py
             packet_verification: 1
           - name: "Border Router TREL with FEATURE_FLAG (avahi)"
             otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_FEATURE_FLAGS=ON -DOTBR_TELEMETRY_DATA_API=ON -DOTBR_TREL=ON -DOTBR_DNS_UPSTREAM_QUERY=ON"
             border_routing: 1
-            nat64: 0
+            internet: 0
+            dnssd_plat: 0
             otbr_mdns: "avahi"
             cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
             packet_verification: 2
-
+          - name: "Border Router with OT Core Advertising Proxy (avahi)"
+            otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=ON -DOTBR_DNS_UPSTREAM_QUERY=ON"
+            border_routing: 1
+            internet: 0
+            dnssd_plat: 1
+            otbr_mdns: "avahi"
+            cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
+            packet_verification: 1
+          - name: "Border Router with OT Core Advertising Proxy (mDNSResponder)"
+            otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=ON -DOTBR_DNS_UPSTREAM_QUERY=ON"
+            border_routing: 1
+            internet: 0
+            dnssd_plat: 1
+            otbr_mdns: "mDNSResponder"
+            cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
+            packet_verification: 1
 
     name: ${{ matrix.name }}
     env:
       PACKET_VERIFICATION: ${{ matrix.packet_verification }}
-      THREAD_VERSION: 1.3
+      THREAD_VERSION: 1.4
       VIRTUAL_TIME: 0
       PYTHONUNBUFFERED: 1
       REFERENCE_DEVICE: 1
@@ -119,8 +142,10 @@ jobs:
       INTER_OP: 0
       INTER_OP_BBR: 0
       BORDER_ROUTING: ${{ matrix.border_routing }}
-      NAT64: ${{ matrix.nat64 }}
+      NAT64: ${{ matrix.internet }}
+      DNSSD_PLAT: ${{ matrix.dnssd_plat }}
       MAX_JOBS: 3
+      VERBOSE: 1
     steps:
     - uses: actions/checkout@v4
       with:
@@ -149,17 +174,19 @@ jobs:
           --build-arg BACKBONE_ROUTER=1 \
           --build-arg REFERENCE_DEVICE=1 \
           --build-arg OT_BACKBONE_CI=1 \
-          --build-arg NAT64="${{ matrix.nat64 }}" \
+          --build-arg NAT64="${{ matrix.internet }}" \
           --build-arg NAT64_SERVICE=openthread \
-          --build-arg DNS64="${{ matrix.nat64 }}" \
+          --build-arg DNS64="${{ matrix.internet }}" \
           --build-arg MDNS="${{ matrix.otbr_mdns }}" \
+          --build-arg DNSSD_PLAT="${{ matrix.dnssd_plat }}" \
           --build-arg OTBR_OPTIONS="${otbr_options} -DCMAKE_CXX_FLAGS='-DOPENTHREAD_CONFIG_DNSSD_SERVER_BIND_UNSPECIFIED_NETIF=1'"
     - name: Bootstrap OpenThread Test
       if: ${{ success() && steps.check_cache_result.outputs.cache-hit != 'true' }}
       run: |
         sudo rm /etc/apt/sources.list.d/* && sudo apt-get update
-        sudo apt-get --no-install-recommends install -y python3-setuptools python3-wheel ninja-build socat nodejs npm
+        sudo apt-get --no-install-recommends install -y python3-setuptools python3-wheel ninja-build nodejs npm
         python3 -m pip install -r third_party/openthread/repo/tests/scripts/thread-cert/requirements.txt
+        sudo bash third_party/openthread/repo/script/install_socat
     - name: Build OpenThread
       if: ${{ success() && steps.check_cache_result.outputs.cache-hit != 'true' }}
       run: |
@@ -177,14 +204,14 @@ jobs:
     - uses: actions/upload-artifact@v4
       if: ${{ failure() && steps.check_cache_result.outputs.cache-hit != 'true' }}
       with:
-        name: thread-1-3-backbone-results
+        name: thread-1-4-backbone-results
         path: |
           third_party/openthread/repo/ot_testing/*.pcap
           third_party/openthread/repo/ot_testing/*.json
           third_party/openthread/repo/ot_testing/*.log
     - name: Codecov
       if: ${{ success() && steps.check_cache_result.outputs.cache-hit != 'true' }}
-      uses: codecov/codecov-action@v4
+      uses: codecov/codecov-action@v5
     - name: Cache test result
       if: ${{ success() && steps.check_cache_result.outputs.cache-hit != 'true' }}
       run: |
diff --git a/.github/workflows/build.yml b/.github/workflows/build.yml
index cbd4e17f..72313759 100644
--- a/.github/workflows/build.yml
+++ b/.github/workflows/build.yml
@@ -52,7 +52,7 @@ jobs:
       run: script/make-pretty check
 
   check:
-    runs-on: ubuntu-20.04
+    runs-on: ubuntu-22.04
     strategy:
       fail-fast: false
       matrix:
@@ -73,10 +73,10 @@ jobs:
     - name: Run
       run: script/test build check
     - name: Codecov
-      uses: codecov/codecov-action@v4
+      uses: codecov/codecov-action@v5
 
   rest-check:
-    runs-on: ubuntu-20.04
+    runs-on: ubuntu-22.04
     strategy:
       fail-fast: false
       matrix:
@@ -96,10 +96,10 @@ jobs:
     - name: Run
       run: script/test build check
     - name: Codecov
-      uses: codecov/codecov-action@v4
+      uses: codecov/codecov-action@v5
 
   script-check:
-    runs-on: ubuntu-20.04
+    runs-on: ubuntu-22.04
     env:
       BUILD_TARGET: script-check
       OTBR_COVERAGE: 1
@@ -112,10 +112,10 @@ jobs:
     - name: Run
       run: tests/scripts/check-scripts
     - name: Codecov
-      uses: codecov/codecov-action@v4
+      uses: codecov/codecov-action@v5
 
   scan-build:
-    runs-on: ubuntu-20.04
+    runs-on: ubuntu-22.04
     env:
       BUILD_TARGET: scan-build
       CC: clang
@@ -130,7 +130,7 @@ jobs:
       run: tests/scripts/check-scan-build
 
   package:
-    runs-on: ubuntu-20.04
+    runs-on: ubuntu-22.04
     env:
       BUILD_TARGET: package
     steps:
diff --git a/.github/workflows/docker.yml b/.github/workflows/docker.yml
index 4a96966a..c96d432d 100644
--- a/.github/workflows/docker.yml
+++ b/.github/workflows/docker.yml
@@ -59,7 +59,7 @@ jobs:
       run: tests/scripts/check-docker
 
   buildx:
-    runs-on: ubuntu-20.04
+    runs-on: ubuntu-24.04
     strategy:
       fail-fast: false
       matrix:
@@ -74,11 +74,6 @@ jobs:
             build_args: ""
             platforms: "linux/amd64,linux/arm64"
             push: yes
-          - image_tag: "jammy"
-            base_image: "ubuntu:jammy"
-            build_args: ""
-            platforms: "linux/amd64,linux/arm64"
-            push: yes
           - image_tag: "reference-device"
             base_image: "ubuntu:bionic"
             build_args: >-
@@ -127,7 +122,7 @@ jobs:
     - name: Set up QEMU
       uses: docker/setup-qemu-action@v3
       with:
-        platforms: all
+        image: tonistiigi/binfmt:qemu-v8.1.5
 
     - name: Set up Docker Buildx
       uses: docker/setup-buildx-action@v3
diff --git a/.github/workflows/macOS.yml b/.github/workflows/macOS.yml
index c67a75b1..d7c10703 100644
--- a/.github/workflows/macOS.yml
+++ b/.github/workflows/macOS.yml
@@ -42,20 +42,15 @@ concurrency:
 
 jobs:
   build-check:
-    runs-on: macos-12
+    runs-on: macos-14
     steps:
     - uses: actions/checkout@v4
       with:
         submodules: true
     - name: Bootstrap
       run: |
-        rm -f /usr/local/bin/2to3*
-        rm -f /usr/local/bin/idle3*
-        rm -f /usr/local/bin/pydoc3*
-        rm -f /usr/local/bin/python3*
         brew update
-        brew reinstall boost cmake dbus jsoncpp ninja protobuf@21 pkg-config
-        brew upgrade node
+        brew reinstall jsoncpp ninja protobuf@21
     - name: Build
       run: |
         OTBR_OPTIONS="-DOTBR_BORDER_AGENT=OFF \
diff --git a/.github/workflows/meshcop.yml b/.github/workflows/meshcop.yml
index eade0d45..804270ba 100644
--- a/.github/workflows/meshcop.yml
+++ b/.github/workflows/meshcop.yml
@@ -81,4 +81,4 @@ jobs:
         OTBR_USE_WEB_COMMISSIONER: 1
       run: OTBR_VERBOSE=${RUNNER_DEBUG:-0} script/test meshcop
     - name: Codecov
-      uses: codecov/codecov-action@v4
+      uses: codecov/codecov-action@v5
diff --git a/.github/workflows/ncp_mode.yml b/.github/workflows/ncp_mode.yml
index d5b1650e..1c6926d4 100644
--- a/.github/workflows/ncp_mode.yml
+++ b/.github/workflows/ncp_mode.yml
@@ -49,9 +49,11 @@ jobs:
       matrix:
         mdns: ["mDNSResponder", "avahi"]
     env:
-        BUILD_TARGET: check
+        BUILD_TARGET: ncp_mode
         OTBR_MDNS: ${{ matrix.mdns }}
         OTBR_COVERAGE: 1
+        OTBR_VERBOSE: 1
+        OTBR_OPTIONS: "-DCMAKE_BUILD_TYPE=Debug -DOT_THREAD_VERSION=1.4 -DOTBR_COVERAGE=ON -DOTBR_DBUS=ON -DOTBR_FEATURE_FLAGS=ON -DOTBR_TELEMETRY_DATA_API=ON -DOTBR_UNSECURE_JOIN=ON -DOTBR_TREL=ON -DOTBR_SRP_ADVERTISING_PROXY=ON -DBUILD_TESTING=OFF"
     steps:
     - uses: actions/checkout@v4
       with:
@@ -60,8 +62,20 @@ jobs:
       run: tests/scripts/bootstrap.sh
     - name: Build
       run: |
-        OTBR_BUILD_DIR="./build/temp" script/cmake-build -DCMAKE_BUILD_TYPE=Debug -DOT_THREAD_VERSION=1.3 -DOTBR_COVERAGE=ON -DOTBR_DBUS=ON -DOTBR_FEATURE_FLAGS=ON -DOTBR_TELEMETRY_DATA_API=ON -DOTBR_WEB=ON -DOTBR_UNSECURE_JOIN=ON -DOTBR_TREL=ON
+        OTBR_BUILD_DIR="./build/temp" script/cmake-build ${OTBR_OPTIONS}
+    - name: Build OTBR Docker Image
+      run: |
+        sudo docker build -t otbr-ncp \
+            -f ./etc/docker/Dockerfile . \
+            --build-arg NAT64=0 \
+            --build-arg NAT64_SERVICE=0 \
+            --build-arg DNS64=0 \
+            --build-arg WEB_GUI=0 \
+            --build-arg REST_API=0 \
+            --build-arg FIREWALL=0 \
+            --build-arg OTBR_OPTIONS="${OTBR_OPTIONS}"
     - name: Run
-      run: OTBR_VERBOSE=1 OTBR_TOP_BUILDDIR="./build/temp" script/test ncp_mode
+      run: |
+        top_builddir="./build/temp" tests/scripts/ncp_mode build_ot_sim expect
     - name: Codecov
-      uses: codecov/codecov-action@v4
+      uses: codecov/codecov-action@v5
diff --git a/.github/workflows/raspbian.yml b/.github/workflows/raspbian.yml
index 47a14909..3efb6ea2 100644
--- a/.github/workflows/raspbian.yml
+++ b/.github/workflows/raspbian.yml
@@ -43,7 +43,7 @@ concurrency:
 jobs:
 
   raspbian-check:
-    runs-on: ubuntu-20.04
+    runs-on: ubuntu-22.04
     env:
       IMAGE_URL: https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2021-01-12/2021-01-11-raspios-buster-armhf-lite.zip
       BUILD_TARGET: raspbian-gcc
diff --git a/.lgtm.yml b/.lgtm.yml
index a9812dd0..11264457 100644
--- a/.lgtm.yml
+++ b/.lgtm.yml
@@ -33,9 +33,6 @@ extraction:
         - cmake
         - libavahi-client-dev
         - libavahi-common-dev
-        - libboost-dev
-        - libboost-filesystem-dev
-        - libboost-system-dev
         - libdbus-1-dev
         - libjsoncpp-dev
         - ninja-build
diff --git a/Android.bp b/Android.bp
index bcc3b809..c330e028 100644
--- a/Android.bp
+++ b/Android.bp
@@ -161,6 +161,9 @@ cc_defaults {
         "-DOTBR_ENABLE_DNS_UPSTREAM_QUERY=0",
         "-DOTBR_ENABLE_DHCP6_PD=0",
         "-DOTBR_ENABLE_EPSKC=0",
+
+        // Used for the SetChannelMaxPowers API.
+        "-DOTBR_ENABLE_POWER_CALIBRATION=1",
     ],
 
     srcs: [
@@ -180,13 +183,15 @@ cc_defaults {
         "src/common/task_runner.cpp",
         "src/common/types.cpp",
         "src/mdns/mdns.cpp",
-        "src/ncp/async_task.cpp",
-        "src/ncp/ncp_host.cpp",
-        "src/ncp/ncp_spinel.cpp",
-        "src/ncp/posix/netif_linux.cpp",
-        "src/ncp/posix/netif.cpp",
-        "src/ncp/rcp_host.cpp",
-        "src/ncp/thread_host.cpp",
+        "src/host/async_task.cpp",
+        "src/host/ncp_host.cpp",
+        "src/host/ncp_spinel.cpp",
+        "src/host/posix/dnssd.cpp",
+        "src/host/posix/infra_if.cpp",
+        "src/host/posix/netif_linux.cpp",
+        "src/host/posix/netif.cpp",
+        "src/host/rcp_host.cpp",
+        "src/host/thread_host.cpp",
         "src/sdp_proxy/advertising_proxy.cpp",
         "src/sdp_proxy/discovery_proxy.cpp",
         "src/trel_dnssd/trel_dnssd.cpp",
@@ -254,6 +259,7 @@ cc_fuzz {
             "wgtdkp@google.com",
         ],
     },
+    apex_available: ["//apex_available:platform"],
 }
 
 cc_library_static {
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 5a1ee70a..26cccb45 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -104,7 +104,7 @@ include(GNUInstallDirs)
 
 pkg_check_modules(SYSTEMD systemd)
 
-if(SYSTEMD_FOUND)
+if(SYSTEMD_FOUND AND (NOT DEFINED INSTALL_SYSTEMD_UNIT OR INSTALL_SYSTEMD_UNIT))
     pkg_get_variable(OTBR_SYSTEMD_UNIT_DIR systemd systemdsystemunitdir)
 endif()
 
diff --git a/METADATA b/METADATA
index 830cabe7..05a89887 100644
--- a/METADATA
+++ b/METADATA
@@ -1,17 +1,20 @@
-name: "ot-br-posix"
-description:
-    "ot-br-posix is an open-source implementation of the Thread Border Router."
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/ot-br-posix
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "ot-br-posix"
+description: "ot-br-posix is an open-source implementation of the Thread Border Router."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/openthread/ot-br-posix"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 3
+    day: 5
   }
-  url {
-    type: GIT
+  homepage: "https://github.com/openthread/ot-br-posix"
+  identifier {
+    type: "Git"
     value: "https://github.com/openthread/ot-br-posix.git"
+    version: "cdd6486759cc6ec254ef0d2a248216ca64880194"
   }
-  version: "c75203a9c7d0df0188527360e556d17e940a945f"
-  last_upgrade_date { year: 2022 month: 11 day: 15 }
-  license_type: NOTICE
 }
diff --git a/NOTICE b/NOTICE
index 04cdb0a7..03148ddb 100644
--- a/NOTICE
+++ b/NOTICE
@@ -1,5 +1,5 @@
-OpenThread is an open source implementation of the Thread 1.3.0 Final Specification.
-The Thread 1.3.0 Final Specification is promulgated by the Thread Group. The Thread
+OpenThread is an open source implementation of the Thread 1.4.0 Final Specification.
+The Thread 1.4.0 Final Specification is promulgated by the Thread Group. The Thread
 Group is a non-profit organization formed for the purposes of defining one or
 more specifications, best practices, reference architectures, implementation
 guidelines and certification programs to promote the availability of compliant
@@ -7,10 +7,10 @@ implementations of the Thread protocol. Information on becoming a Member, includ
 information about the benefits thereof, can be found at http://threadgroup.org.
 
 OpenThread is not affiliated with or endorsed by the Thread Group. Implementation
-of this OpenThread code does not assure compliance with the Thread 1.3.0 Final
+of this OpenThread code does not assure compliance with the Thread 1.4.0 Final
 Specification and does not convey the right to identify any final product as Thread
 certified. Members of the Thread Group may hold patents and other intellectual
-property rights relating to the Thread 1.3.0 Final Specification, ownership and
+property rights relating to the Thread 1.4.0 Final Specification, ownership and
 licenses of which are subject to the Thread Group’s IP Policies, and not this license.
 
 The included copyright to the OpenThread code is subject to the license in the
diff --git a/OWNERS b/OWNERS
index 55c307b5..d2a9141c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 # Bug component: 1203089
 
 include platform/packages/modules/ThreadNetwork:/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/TEST_MAPPING b/TEST_MAPPING
index b51407e7..7d9e7806 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,10 +1,7 @@
 {
-  "presubmit": [
+  "imports": [
     {
-      "name": "CtsThreadNetworkTestCases"
-    },
-    {
-      "name": "ThreadNetworkIntegrationTests"
+      "path": "packages/modules/Connectivity/thread/TEST_MAPPING"
     }
   ],
   "postsubmit": [
diff --git a/etc/cmake/options.cmake b/etc/cmake/options.cmake
index 4b6c0bb7..dfac0586 100644
--- a/etc/cmake/options.cmake
+++ b/etc/cmake/options.cmake
@@ -164,3 +164,17 @@ if (OTBR_LINK_METRICS_TELEMETRY)
 else()
     target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_LINK_METRICS_TELEMETRY=0)
 endif()
+
+option(OTBR_POWER_CALIBRATION "Enable Power Calibration" ON)
+if (OTBR_POWER_CALIBRATION)
+    target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_POWER_CALIBRATION=1)
+else()
+    target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_POWER_CALIBRATION=0)
+endif()
+
+option(OTBR_DNSSD_PLAT "Enable OTBR DNS-SD platform implementation" OFF)
+if (OTBR_DNSSD_PLAT)
+    target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_DNSSD_PLAT=1)
+else()
+    target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_DNSSD_PLAT=0)
+endif()
diff --git a/etc/docker/Dockerfile b/etc/docker/Dockerfile
index b4eed1f9..800b00e3 100644
--- a/etc/docker/Dockerfile
+++ b/etc/docker/Dockerfile
@@ -43,6 +43,7 @@ ARG REST_API
 ARG WEB_GUI
 ARG MDNS
 ARG FIREWALL
+ARG DNSSD_PLAT
 
 ENV INFRA_IF_NAME=${INFRA_IF_NAME:-eth0}
 ENV BORDER_ROUTING=${BORDER_ROUTING:-1}
@@ -61,6 +62,7 @@ ENV DNS64=${DNS64:-0}
 ENV WEB_GUI=${WEB_GUI:-1}
 ENV REST_API=${REST_API:-1}
 ENV FIREWALL=${FIREWALL:-1}
+ENV DNSSD_PLAT=${DNSSD_PLAT:-0}
 ENV DOCKER 1
 
 RUN env
@@ -74,12 +76,18 @@ ENV OTBR_DOCKER_DEPS git ca-certificates
 # Required and installed during build (script/bootstrap), could be removed
 ENV OTBR_BUILD_DEPS apt-utils build-essential psmisc ninja-build cmake wget ca-certificates \
   libreadline-dev libncurses-dev libdbus-1-dev libavahi-common-dev \
-  libavahi-client-dev libboost-dev libboost-filesystem-dev libboost-system-dev \
+  libavahi-client-dev \
   libnetfilter-queue-dev
 
 # Required for OpenThread Backbone CI
 ENV OTBR_OT_BACKBONE_CI_DEPS curl lcov wget build-essential python3-dbus python3-zeroconf socat
 
+# Resolves issue with installing libc-bin
+RUN rm /var/lib/dpkg/info/libc-bin.* \
+  && apt-get clean -y \
+  && apt-get update -y \
+  && apt-get install --no-install-recommends -y libc-bin
+
 RUN apt-get update \
   && apt-get install --no-install-recommends -y $OTBR_DOCKER_REQS $OTBR_DOCKER_DEPS \
   && ([ "${OT_BACKBONE_CI}" != "1" ] || apt-get install --no-install-recommends -y $OTBR_OT_BACKBONE_CI_DEPS) \
diff --git a/etc/docker/README.md b/etc/docker/README.md
new file mode 100644
index 00000000..008d6453
--- /dev/null
+++ b/etc/docker/README.md
@@ -0,0 +1,40 @@
+# OTBR Docker
+
+This file contains troubleshooting for common issues with OTBR Docker.
+
+## rsyslog cannot start
+
+If `rsyslog` cannot start successfully (there is no response) during the OTBR Docker image booting-up:
+
+```
++ sudo service rsyslog status
+ * rsyslogd is not running
++ sudo service rsyslog start
+ * Starting enhanced syslogd rsyslogd
+```
+
+This is caused by the high limit number of file descriptors (`LimitNOFILE`). `rsyslog` takes a long time to run a for loop to close all open file descriptors when this limit is high (for example, `1073741816`).
+
+To solve this issue, add the following configuration to `/etc/docker/daemon.json`:
+
+```
+  "default-ulimits": {
+    "nofile": {
+      "Name": "nofile",
+        "Hard": 1024,
+        "Soft": 1024
+    },
+    "nproc": {
+      "Name": "nproc",
+        "Soft": 65536,
+        "Hard": 65536
+    }
+  }
+```
+
+And then reload & restart the `docker` service:
+
+```
+sudo systemctl daemon-reload
+sudo systemctl restart docker
+```
diff --git a/etc/docker/docker_entrypoint.sh b/etc/docker/docker_entrypoint.sh
index 5b3439e5..d39abed5 100755
--- a/etc/docker/docker_entrypoint.sh
+++ b/etc/docker/docker_entrypoint.sh
@@ -87,6 +87,7 @@ parse_args "$@"
 [ -n "$BACKBONE_INTERFACE" ] || BACKBONE_INTERFACE="eth0"
 [ -n "$NAT64_PREFIX" ] || NAT64_PREFIX="64:ff9b::/96"
 [ -n "$DEBUG_LEVEL" ] || DEBUG_LEVEL="7"
+[ -n "$HTTP_PORT" ] || HTTP_PORT=80
 
 echo "RADIO_URL:" $RADIO_URL
 echo "TREL_URL:" "$TREL_URL"
@@ -104,7 +105,7 @@ BIND_CONF_OPTIONS=/etc/bind/named.conf.options
 sed -i "s/$INFRA_IF_NAME/$BACKBONE_INTERFACE/" /etc/sysctl.d/60-otbr-accept-ra.conf
 
 echo "OTBR_AGENT_OPTS=\"-I $TUN_INTERFACE_NAME -B $BACKBONE_INTERFACE -d${DEBUG_LEVEL} $RADIO_URL $TREL_URL\"" >/etc/default/otbr-agent
-echo "OTBR_WEB_OPTS=\"-I $TUN_INTERFACE_NAME -d${DEBUG_LEVEL} -p 80\"" >/etc/default/otbr-web
+echo "OTBR_WEB_OPTS=\"-I $TUN_INTERFACE_NAME -d${DEBUG_LEVEL} -p $HTTP_PORT\"" >/etc/default/otbr-web
 
 /app/script/server
 
diff --git a/etc/yocto/otbr_git.bb b/etc/yocto/otbr_git.bb
index a36f54ac..a0bb02f8 100644
--- a/etc/yocto/otbr_git.bb
+++ b/etc/yocto/otbr_git.bb
@@ -41,7 +41,7 @@ S = "${WORKDIR}/git"
 SRCREV = "${AUTOREV}"
 PV_append = "+${SRCPV}"
 
-DEPENDS += "avahi boost dbus iproute2 jsoncpp ncurses"
+DEPENDS += "avahi dbus iproute2 jsoncpp ncurses"
 
 inherit autotools cmake
 
diff --git a/examples/platforms/debian/default b/examples/platforms/debian/default
index c76b5423..4482d030 100644
--- a/examples/platforms/debian/default
+++ b/examples/platforms/debian/default
@@ -31,6 +31,7 @@
 NAT64=0
 DNS64=0
 DHCPV6_PD=0
+DHCPV6_PD_REF=0
 NETWORK_MANAGER=0
 BACKBONE_ROUTER=1
 BORDER_ROUTING=1
diff --git a/examples/platforms/raspbian/default b/examples/platforms/raspbian/default
index f5bb3f07..feca7493 100644
--- a/examples/platforms/raspbian/default
+++ b/examples/platforms/raspbian/default
@@ -31,6 +31,7 @@
 NAT64=1
 DNS64=0
 DHCPV6_PD=0
+DHCPV6_PD_REF=0
 NETWORK_MANAGER=0
 BACKBONE_ROUTER=1
 BORDER_ROUTING=1
diff --git a/script/_border_routing b/script/_border_routing
index f17c8fe6..e9b79c76 100644
--- a/script/_border_routing
+++ b/script/_border_routing
@@ -68,27 +68,26 @@ accept_ra_enable()
     fi
 }
 
-# This function disables IPv6 support in dhcpcd.
+# This function disables IPv6 Router Solicitation (RS) in dhcpcd.
 #
 # dhcpcd on raspberry Pi enables IPv6 support by default. The problem with
 # dhcpcd is that it does't support Route Information Option (RIO), so we need
 # to rely on the kernel implementation. dhcpcd will force set accept_ra to 0
-# for all interfaces it is currently running on, if IPv6 is enabled. This
+# for all interfaces it is currently running on, if IPv6 RS is enabled. This
 # conflicts with our accept_ra* configurations.
 #
-dhcpcd_disable_ipv6()
+dhcpcd_disable_ipv6rs()
 {
     if [ -f $DHCPCD_CONF_FILE ]; then
         sudo cp $DHCPCD_CONF_FILE $DHCPCD_CONF_BACKUP_FILE
         sudo tee -a $DHCPCD_CONF_FILE <<EOF
-noipv6
 noipv6rs
 EOF
     fi
 }
 
-# This function enables IPv6 support in dhcpcd.
-dhcpcd_enable_ipv6()
+# This function enables IPv6 Router Solicitation (RS) in dhcpcd.
+dhcpcd_enable_ipv6rs()
 {
     if [ -f $DHCPCD_CONF_BACKUP_FILE ]; then
         sudo cp $DHCPCD_CONF_BACKUP_FILE $DHCPCD_CONF_FILE
@@ -100,14 +99,14 @@ border_routing_uninstall()
     with BORDER_ROUTING || return 0
 
     accept_ra_uninstall
-    dhcpcd_enable_ipv6
+    dhcpcd_enable_ipv6rs
 }
 
 border_routing_install()
 {
     with BORDER_ROUTING || return 0
 
-    dhcpcd_disable_ipv6
+    dhcpcd_disable_ipv6rs
     accept_ra_install
 
     # /proc/sys/net/ipv6/conf/* files are read-only in docker
diff --git a/script/_dhcpv6_pd_ref b/script/_dhcpv6_pd_ref
new file mode 100644
index 00000000..b6f56a26
--- /dev/null
+++ b/script/_dhcpv6_pd_ref
@@ -0,0 +1,169 @@
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
+#   Description:
+#       This script manipulates DHCPv6-PD-REF configuration.
+#
+
+# TODO: set the upstream interface according to the environment variables of `script/setup`.
+UPSTREAM_INTERFACE="eth0"
+
+DHCPCD_ENTER_HOOK="/etc/dhcpcd.enter-hook"
+DHCPCD_EXIT_HOOK="/etc/dhcpcd.exit-hook"
+
+PD_DAEMON_DIR="/opt/pd-daemon"
+PD_DAEMON_PATH="${PD_DAEMON_DIR}/dhcp6_pd_daemon.py"
+PD_DAEMON_SERVICE_NAME="dhcp6_pd_daemon.service"
+PD_DAEMON_SERVICE_PATH="/etc/systemd/system/${PD_DAEMON_SERVICE_NAME}"
+
+DHCP_CONFIG_PATH="/etc/dhcpcd.conf"
+DHCP_CONFIG_ORIG_PATH="/etc/dhcpcd.conf.orig"
+DHCP_CONFIG_PD_PATH="/etc/dhcpcd.conf.pd"
+DHCP_CONFIG_NO_PD_PATH="/etc/dhcpcd.conf.no-pd"
+
+# Create dhcpcd configuration file with ipv6 prefix request.
+create_dhcpcd_conf_pd()
+{
+    sudo tee ${DHCP_CONFIG_PD_PATH} >/dev/null <<EOF
+noipv6rs # disable router solicitation
+interface ${UPSTREAM_INTERFACE}
+  iaid 1
+  ia_pd 2/::/64 -
+release
+# Disable Router Solicitations (RS) again, specifically for ${UPSTREAM_INTERFACE}.
+# This ensures that accept_ra is prevented from being set to 0, allowing
+# the interface to accepting Router Advertisements and configuring IPv6
+# based on them. The exact reason for requiring 'noipv6rs' twice
+# is not fully understood but has been observed to be necessary through 
+# experimentation.
+noipv6rs
+EOF
+}
+
+# Create dhcpcd configuration file with no prefix request.
+create_dhcpcd_conf_no_pd()
+{
+    sudo tee ${DHCP_CONFIG_NO_PD_PATH} >/dev/null <<EOF
+noipv6rs # disable router solicitation
+EOF
+}
+
+create_dhcp6_pd_daemon_service()
+{
+    sudo tee ${PD_DAEMON_SERVICE_PATH} <<EOF
+[Unit]
+Description=Daemon to manage dhcpcd based on otbr-agent's PD state change
+ConditionPathExists=${PD_DAEMON_PATH}
+Requires=otbr-agent.service
+After=otbr-agent.service
+
+[Service]
+Type=simple
+User=root
+ExecStart=/usr/bin/python3 ${PD_DAEMON_PATH}
+Restart=on-failure
+
+[Install]
+WantedBy=multi-user.target
+EOF
+}
+
+dhcpv6_pd_ref_uninstall()
+{
+    with DHCPV6_PD_REF || return 0
+
+    if have systemctl; then
+        sudo systemctl disable ${PD_DAEMON_SERVICE_NAME} || true
+        sudo systemctl stop ${PD_DAEMON_SERVICE_NAME} || true
+        sudo rm -f ${PD_DAEMON_SERVICE_PATH} || true
+    fi
+
+    if [[ -f ${DHCP_CONFIG_ORIG_PATH} ]]; then
+        sudo mv ${DHCP_CONFIG_ORIG_PATH} ${DHCP_CONFIG_PATH}
+    fi
+
+    sudo rm -f ${DHCPCD_ENTER_HOOK} ${DHCPCD_EXIT_HOOK}
+    sudo rm -f ${PD_DAEMON_PATH}
+
+    if have systemctl; then
+        sudo systemctl daemon-reload
+
+        if systemctl is-active dhcpcd; then
+            sudo systemctl restart dhcpcd || true
+        fi
+    fi
+}
+
+dhcpv6_pd_ref_install()
+{
+    with DHCPV6_PD_REF || return 0
+
+    if [[ -f ${DHCP_CONFIG_PATH} ]]; then
+        sudo mv ${DHCP_CONFIG_PATH} ${DHCP_CONFIG_ORIG_PATH}
+    fi
+
+    # Add dhcpcd.hooks
+    sudo install -m 755 "$(dirname "$0")"/reference-device/dhcpcd.enter-hook ${DHCPCD_ENTER_HOOK}
+    sudo install -m 755 "$(dirname "$0")"/reference-device/dhcpcd.exit-hook ${DHCPCD_EXIT_HOOK}
+    sudo mkdir -p ${PD_DAEMON_DIR}
+    sudo install -m 755 "$(dirname "$0")"/reference-device/dhcp6_pd_daemon.py ${PD_DAEMON_PATH}
+
+    create_dhcpcd_conf_pd
+    create_dhcpcd_conf_no_pd
+    create_dhcp6_pd_daemon_service
+
+    # The dhcp6_pd_daemon is currently disabled because it restarts dhcpcd
+    # when the PD state changes. This restart disrupts mDNS, causing
+    # connectivity issues. The daemon and its associated systemd service
+    # files are still installed for potential future use.
+    #
+    # TODO: Re-enable and start the daemon when a solution is found
+    #       for dhcpcd restarts breaking mDNS.
+    #
+    # if have systemctl; then
+    #    sudo systemctl daemon-reload
+    #    sudo systemctl enable ${PD_DAEMON_SERVICE_NAME}
+    #    sudo systemctl start ${PD_DAEMON_SERVICE_NAME}
+    # fi
+
+    # Always enable PD, which is a workaround for the currently disabled
+    # dhcp6_pd_daemon which caused mDNS disruptions.
+    sudo cp ${DHCP_CONFIG_PD_PATH} ${DHCP_CONFIG_PATH}
+
+    if have systemctl; then
+        sudo systemctl daemon-reload
+
+        # Restart dhcpcd only if it's running. This is unnecessary when the dhcp6_pd_daemon
+        # is enabled, as the daemon will handle dhcpcd restarts based on PD state changes.
+        if systemctl is-active dhcpcd; then
+            sudo systemctl restart dhcpcd || true
+        fi
+
+        sudo systemctl enable radvd
+    fi
+}
diff --git a/script/_initrc b/script/_initrc
index 7ba2c1eb..be2c7ca8 100644
--- a/script/_initrc
+++ b/script/_initrc
@@ -107,9 +107,9 @@ start_service()
 stop_service()
 {
     local service_name=$1
-    if $HAVE_SYSTEMCTL; then
+    if [[ ${HAVE_SYSTEMCTL} == 1 ]]; then
         systemctl is-active "$service_name" && sudo systemctl stop "$service_name" || echo "Failed to stop $service_name!"
-    elif $HAVE_SERVICE; then
+    elif [[ ${HAVE_SERVICE} == 1 ]]; then
         sudo service "$service_name" status && sudo service "$service_name" stop || echo "Failed to stop $service_name!"
     else
         die 'Unable to find service manager. Try script/console to stop in console mode!'
diff --git a/script/_otbr b/script/_otbr
index dbccc73c..52748cd7 100644
--- a/script/_otbr
+++ b/script/_otbr
@@ -72,7 +72,6 @@ otbr_install()
         "-DCMAKE_INSTALL_PREFIX=/usr"
         "-DOTBR_DBUS=ON"
         "-DOTBR_DNSSD_DISCOVERY_PROXY=ON"
-        "-DOTBR_SRP_ADVERTISING_PROXY=ON"
         "-DOTBR_INFRA_IF_NAME=${INFRA_IF_NAME}"
         "-DOTBR_MDNS=${OTBR_MDNS:=mDNSResponder}"
         # Force re-evaluation of version strings
@@ -81,6 +80,16 @@ otbr_install()
         "${otbr_options[@]}"
     )
 
+    if with DNSSD_PLAT; then
+        otbr_options+=(
+            "-DOTBR_DNSSD_PLAT=ON"
+        )
+    else
+        otbr_options+=(
+            "-DOTBR_SRP_ADVERTISING_PROXY=ON"
+        )
+    fi
+
     if with WEB_GUI; then
         otbr_options+=("-DOTBR_WEB=ON")
     fi
@@ -91,6 +100,12 @@ otbr_install()
         )
     fi
 
+    if with DHCPV6_PD_REF; then
+        otbr_options+=(
+            "-DOTBR_DHCP6_PD=ON"
+        )
+    fi
+
     if with REST_API; then
         otbr_options+=("-DOTBR_REST=ON")
     fi
diff --git a/script/bootstrap b/script/bootstrap
index 6cfb7194..628e422e 100755
--- a/script/bootstrap
+++ b/script/bootstrap
@@ -66,6 +66,8 @@ install_packages_apt()
     # Avahi should be included for reference device builds.
     if [[ ${OTBR_MDNS} == "avahi" || ${OT_BACKBONE_CI} == 1 || ${REFERENCE_DEVICE} == 1 ]]; then
         sudo apt-get install --no-install-recommends -y avahi-daemon
+        # Increase the object number limit to rid of 'Too many objects' error
+        sudo sed -i 's/^#objects-per-client-max=[0-9]\+/objects-per-client-max=30000/' /etc/avahi/avahi-daemon.conf
     fi
 
     (MDNS_RESPONDER_SOURCE_NAME=mDNSResponder-1790.80.10 \
@@ -83,9 +85,6 @@ install_packages_apt()
         && cd mDNSPosix \
         && make os=linux tls=no && sudo make install os=linux tls=no)
 
-    # Boost
-    sudo apt-get install --no-install-recommends -y libboost-dev libboost-filesystem-dev libboost-system-dev
-
     # nat64
     without NAT64 || {
         [ "$NAT64_SERVICE" != "tayga" ] || sudo apt-get install --no-install-recommends -y tayga
@@ -106,6 +105,20 @@ install_packages_apt()
         fi
     }
 
+    # dhcpv6-pd
+    without DHCPV6_PD_REF || {
+        sudo apt-get install --no-install-recommends -y dhcpcd
+        sudo mkdir -p /etc/systemd/system/dhcpcd.service.d
+        # allow edit system config file eg. /etc/radvd.conf
+        sudo tee /etc/systemd/system/dhcpcd.service.d/custom.conf >/dev/null <<EOF
+[Service]
+ProtectSystem=false
+EOF
+        # reload dhcpcd daemon to activate the custom.conf
+        sudo systemctl daemon-reload
+        sudo apt-get install --no-install-recommends -y radvd
+    }
+
     # network-manager
     without NETWORK_MANAGER || sudo apt-get install --no-install-recommends -y dnsmasq network-manager
 
@@ -116,7 +129,7 @@ install_packages_apt()
     sudo apt-get install --no-install-recommends -y libjsoncpp-dev
 
     # reference device
-    without REFERENCE_DEVICE || sudo apt-get install --no-install-recommends -y radvd dnsutils avahi-utils
+    without REFERENCE_DEVICE || sudo apt-get install --no-install-recommends -y radvd dnsutils avahi-utils iperf3
 
     # backbone-router
     without BACKBONE_ROUTER || sudo apt-get install --no-install-recommends -y libnetfilter-queue1 libnetfilter-queue-dev
@@ -147,7 +160,6 @@ install_packages_rpm()
     with RELEASE || sudo $PM install -y cmake ninja-build
     sudo $PM install -y dbus-devel
     sudo $PM install -y avahi avahi-devel
-    sudo $PM install -y boost-devel boost-filesystem boost-system
     [ "$NAT64_SERVICE" != "tayga" ] || sudo $PM install -y tayga
     sudo $PM install -y iptables
     sudo $PM install -y jsoncpp-devel
@@ -157,7 +169,7 @@ install_packages_rpm()
 
 install_packages_brew()
 {
-    brew install boost cmake dbus jsoncpp ninja
+    brew install cmake dbus jsoncpp ninja
 }
 
 install_packages_source()
diff --git a/script/reference-device/dhcp6_pd_daemon.py b/script/reference-device/dhcp6_pd_daemon.py
new file mode 100755
index 00000000..fa386ed1
--- /dev/null
+++ b/script/reference-device/dhcp6_pd_daemon.py
@@ -0,0 +1,139 @@
+#!/usr/bin/env python3
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
+import logging
+import dbus
+import gi.repository.GLib as GLib
+import subprocess
+import threading
+import os
+
+from dbus.mainloop.glib import DBusGMainLoop
+
+DBusGMainLoop(set_as_default=True)
+
+logging.basicConfig(level=logging.INFO,
+                    format='%(asctime)s - %(levelname)s - %(message)s')
+
+bus = dbus.SystemBus()
+intended_dhcp6pd_state = None
+
+DHCP_CONFIG_PATH = "/etc/dhcpcd.conf"
+DHCP_CONFIG_PD_PATH = "/etc/dhcpcd.conf.pd"
+DHCP_CONFIG_NO_PD_PATH = "/etc/dhcpcd.conf.no-pd"
+
+
+def restart_dhcpcd_service(config_path):
+    if not os.path.isfile(config_path):
+        logging.error(f"{config_path} not found. Cannot apply configuration.")
+        return
+    try:
+        subprocess.run(["cp", config_path, DHCP_CONFIG_PATH], check=True)
+        subprocess.run(["systemctl", "daemon-reload"], check=True)
+        subprocess.run(["service", "dhcpcd", "restart"], check=True)
+        logging.info(
+            f"Successfully restarted dhcpcd service with {config_path}.")
+    except subprocess.CalledProcessError as e:
+        logging.error(f"Error restarting dhcpcd service: {e}")
+
+
+def restart_dhcpcd_with_pd_config():
+    global intended_dhcp6pd_state
+    restart_dhcpcd_service(DHCP_CONFIG_PD_PATH)
+    intended_dhcp6pd_state = None
+
+
+def restart_dhcpcd_with_no_pd_config():
+    restart_dhcpcd_service(DHCP_CONFIG_NO_PD_PATH)
+
+
+def properties_changed_handler(interface_name, changed_properties,
+                               invalidated_properties):
+    global intended_dhcp6pd_state
+    if "Dhcp6PdState" not in changed_properties:
+        return
+    new_state = changed_properties["Dhcp6PdState"]
+    logging.info(f"Dhcp6PdState changed to: {new_state}")
+    if new_state == "running" and intended_dhcp6pd_state != "running":
+        intended_dhcp6pd_state = "running"
+        thread = threading.Thread(target=restart_dhcpcd_with_pd_config)
+        thread.start()
+    elif new_state in ("stopped", "idle",
+                       "disabled") and intended_dhcp6pd_state is None:
+        restart_dhcpcd_with_no_pd_config()
+
+
+def connect_to_signal():
+    try:
+        dbus_obj = bus.get_object('io.openthread.BorderRouter.wpan0',
+                                  '/io/openthread/BorderRouter/wpan0')
+        properties_dbus_iface = dbus.Interface(
+            dbus_obj, 'org.freedesktop.DBus.Properties')
+        dbus_obj.connect_to_signal(
+            "PropertiesChanged",
+            properties_changed_handler,
+            dbus_interface=properties_dbus_iface.dbus_interface)
+        logging.info("Connected to D-Bus signal.")
+    except dbus.DBusException as e:
+        logging.error(f"Error connecting to D-Bus: {e}")
+
+
+def handle_name_owner_changed(new_owner):
+    if new_owner:
+        logging.info(f"New D-Bus owner({new_owner}) assigned, connecting...")
+        connect_to_signal()
+
+
+def main():
+    # Ensure dhcpcd is running in its last known state. This addresses a potential race condition
+    # during system startup due to the loop dependency in dhcpcd-radvd-network.target.
+    #
+    #   - network.target activation relies on the completion of dhcpcd start
+    #   - during bootup, dhcpcd tries to start radvd with PD enabled before network.target is
+    #     active, which leads to a timeout failure
+    #   - so we will prevent radvd from starting before target.network is active
+    #
+    # By restarting dhcpcd here, we ensure it runs after network.target is active, allowing
+    # radvd to start correctly and dhcpcd to configure the interface.
+    try:
+        subprocess.run(["systemctl", "reload-or-restart", "dhcpcd"], check=True)
+        logging.info("Successfully restarting dhcpcd service.")
+    except subprocess.CalledProcessError as e:
+        logging.error(f"Error restarting dhcpcd service: {e}")
+
+    loop = GLib.MainLoop()
+
+    bus.watch_name_owner(bus_name='io.openthread.BorderRouter.wpan0',
+                         callback=handle_name_owner_changed)
+
+    loop.run()
+
+
+if __name__ == '__main__':
+    main()
diff --git a/script/reference-device/dhcpcd.enter-hook b/script/reference-device/dhcpcd.enter-hook
new file mode 100644
index 00000000..82d747dd
--- /dev/null
+++ b/script/reference-device/dhcpcd.enter-hook
@@ -0,0 +1,123 @@
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
+
+# TODO: set the upstream interface according to the environment variables of `script/setup`.
+UPSTREAM_INTERFACE="eth0"
+WPAN_INTERFACE="wpan0"
+
+RADVD_CONF="/etc/radvd.conf"
+LOG_TAG="dhcpcd.enter.hook:"
+
+config_ra()
+{
+    local old_prefix="$1"
+    local old_prefix_len="$2"
+    local new_prefix="$3"
+    local new_prefix_len="$4"
+    local new_pltime="$5"
+    local new_vltime="$6"
+
+    local deprecate_old_prefix=false
+    if [ -n "$old_prefix" ] && [ "$old_prefix/$old_prefix_len" != "$new_prefix/$new_prefix_len" ]; then
+        deprecate_old_prefix=true
+    fi
+
+    local publish_new_prefix=false
+    if [ -n "$new_prefix" ] && [ -n "$new_prefix_len" ] && [ -n "$new_pltime" ] && [ -n "$new_vltime" ]; then
+        publish_new_prefix=true
+    fi
+
+    logger "$LOG_TAG $reason start config radvd"
+
+sudo tee "${RADVD_CONF}" > /dev/null <<EOF
+interface ${WPAN_INTERFACE}
+{
+    IgnoreIfMissing on;
+    AdvSendAdvert on;
+EOF
+
+    if "$deprecate_old_prefix"; then
+        logger "$LOG_TAG Deprecating old prefix $old_prefix/$old_prefix_len"
+sudo tee -a "${RADVD_CONF}" > /dev/null <<EOF
+    prefix ${old_prefix}/${old_prefix_len}
+    {
+        AdvOnLink on;
+        AdvAutonomous on;
+        AdvRouterAddr off;
+        AdvPreferredLifetime 0;
+        AdvValidLifetime 0;
+    };
+EOF
+    fi
+
+    if $publish_new_prefix; then
+        logger "$LOG_TAG Publishing new prefix $new_prefix/$new_prefix_len  PLTime: $new_pltime  VLTime: $new_vltime"
+sudo tee -a "${RADVD_CONF}" > /dev/null <<EOF
+    prefix ${new_prefix}/${new_prefix_len}
+    {
+        AdvOnLink on;
+        AdvAutonomous on;
+        AdvRouterAddr off;
+        AdvPreferredLifetime ${new_pltime};
+        AdvValidLifetime ${new_vltime};
+    };
+EOF
+    fi
+
+sudo tee -a "${RADVD_CONF}" > /dev/null <<EOF
+};
+EOF
+
+}
+
+
+if [ ${interface} = ${UPSTREAM_INTERFACE} ]; then
+
+    for var in $(env); do
+        # Split the variable into name and value
+        name="${var%%=*}"
+        value="${var#*=}"
+        logger "$LOG_TAG $reason sysenv: $name=$value"
+    done
+
+    case $reason in
+        DELEGATED6 | REBIND6 | RENEW6 | BOUND6 )
+            # TODO: Handle multiple IA_PD prefixes (new_dhcp6_ia_pd{i}_prefix{j}, new_dhcp6_ia_pd{i}_prefix{j}_length, etc.)
+            #       and deprecate old prefixes properly for each.  Currently, only one prefix is handled.
+            if { [ -n "$new_dhcp6_ia_pd1_prefix1" ] && [ -n "$new_dhcp6_ia_pd1_prefix1_length" ]; } || \
+               { [ -n "$old_dhcp6_ia_pd1_prefix1" ] && [ -n "$old_dhcp6_ia_pd1_prefix1_length" ]; }; then
+                config_ra "$old_dhcp6_ia_pd1_prefix1" "$old_dhcp6_ia_pd1_prefix1_length" \
+                    "$new_dhcp6_ia_pd1_prefix1" "$new_dhcp6_ia_pd1_prefix1_length" "$new_dhcp6_ia_pd1_prefix1_pltime"  "$new_dhcp6_ia_pd1_prefix1_vltime"
+                if systemctl is-active network.target; then
+                    sudo systemctl reload-or-restart radvd || logger "$LOG_TAG Failed to reload radvd"
+                fi
+            fi
+            ;;
+    esac
+fi
diff --git a/script/reference-device/dhcpcd.exit-hook b/script/reference-device/dhcpcd.exit-hook
new file mode 100644
index 00000000..88470585
--- /dev/null
+++ b/script/reference-device/dhcpcd.exit-hook
@@ -0,0 +1,81 @@
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
+
+# TODO: set the upstream interface according to the environment variables of `script/setup`.
+UPSTREAM_INTERFACE="eth0"
+WPAN_INTERFACE="wpan0"
+
+RADVD_CONF="/etc/radvd.conf"
+LOG_TAG="dhcpcd.exit.hook:"
+
+config_ra()
+{
+    logger "$LOG_TAG $reason start config radvd"
+
+sudo tee "${RADVD_CONF}" > /dev/null <<EOF
+interface ${WPAN_INTERFACE}
+{
+    AdvSendAdvert on;
+    prefix ${1}/${2}
+    {
+        AdvOnLink on;
+        AdvAutonomous on;
+        AdvRouterAddr off;
+        AdvPreferredLifetime ${3};
+        AdvValidLifetime ${4};
+    };
+};
+EOF
+}
+
+
+if [ ${interface} = ${UPSTREAM_INTERFACE} ]; then
+
+    for var in $(env); do
+        # Split the variable into name and value
+        name="${var%%=*}"
+        value="${var#*=}"
+        logger -t "$LOG_TAG $reason sysenv: " "$name=$value"
+    done
+
+    case $reason in
+        EXPIRE6 | STOP6 | RELEASE6 )
+            # TODO: Handle multiple IA_PD prefixes (new_dhcp6_ia_pd{i}_prefix{j}, new_dhcp6_ia_pd{i}_prefix{j}_length, etc.)
+            #       and deprecate old prefixes properly for each.  Currently, only one prefix is handled.)
+            if [ -z "$old_dhcp6_ia_pd1_prefix1" ] || [ -z "$old_dhcp6_ia_pd1_prefix1_length" ]; then
+                logger "$LOG_TAG WARNING: Missing DHCPv6 prefix information. Skipping radvd configuration."
+            else
+                config_ra $old_dhcp6_ia_pd1_prefix1 $old_dhcp6_ia_pd1_prefix1_length 0 0
+                if systemctl is-active network.target; then
+                    sudo systemctl reload-or-restart radvd
+                fi
+            fi
+            ;;
+    esac
+fi
diff --git a/script/setup b/script/setup
index 8262be89..b8878fa5 100755
--- a/script/setup
+++ b/script/setup
@@ -38,6 +38,7 @@
 . script/_nat64
 . script/_dns64
 . script/_dhcpv6_pd
+. script/_dhcpv6_pd_ref
 . script/_network_manager
 . script/_rt_tables
 . script/_swapfile
@@ -56,6 +57,7 @@ main()
     border_routing_uninstall
     network_manager_uninstall
     dhcpv6_pd_uninstall
+    dhcpv6_pd_ref_uninstall
     nat64_uninstall
     dns64_uninstall
     rt_tables_uninstall
@@ -69,6 +71,7 @@ main()
     dns64_install
     network_manager_install
     dhcpv6_pd_install
+    dhcpv6_pd_ref_install
     border_routing_install
     otbr_install
     # shellcheck source=/dev/null
diff --git a/script/test b/script/test
index 31c19c45..7914d235 100755
--- a/script/test
+++ b/script/test
@@ -128,7 +128,7 @@ do_build()
     otbr_options=(
         "-DCMAKE_BUILD_TYPE=${OTBR_BUILD_TYPE}"
         "-DCMAKE_INSTALL_PREFIX=/usr"
-        "-DOT_THREAD_VERSION=1.3"
+        "-DOT_THREAD_VERSION=1.4"
         "-DOTBR_DBUS=ON"
         "-DOTBR_FEATURE_FLAGS=ON"
         "-DOTBR_TELEMETRY_DATA_API=ON"
@@ -232,14 +232,11 @@ main()
                 do_doxygen
                 ;;
             help)
-                print_usage
+                print_usage 1
                 ;;
             meshcop)
                 top_builddir="${OTBR_TOP_BUILDDIR}" print_result ./tests/scripts/meshcop
                 ;;
-            ncp_mode)
-                top_builddir="${OTBR_TOP_BUILDDIR}" print_result ./tests/scripts/ncp_mode
-                ;;
             openwrt)
                 print_result ./tests/scripts/openwrt
                 ;;
diff --git a/src/CMakeLists.txt b/src/CMakeLists.txt
index 15790a45..e54fc8e5 100644
--- a/src/CMakeLists.txt
+++ b/src/CMakeLists.txt
@@ -34,7 +34,7 @@ add_subdirectory(common)
 if(OTBR_DBUS OR OTBR_FEATURE_FLAGS OR OTBR_TELEMETRY_DATA_API)
     add_subdirectory(proto)
 endif()
-add_subdirectory(ncp)
+add_subdirectory(host)
 add_subdirectory(sdp_proxy)
 add_subdirectory(trel_dnssd)
 
diff --git a/src/agent/application.cpp b/src/agent/application.cpp
index c656d249..d0a699c1 100644
--- a/src/agent/application.cpp
+++ b/src/agent/application.cpp
@@ -40,39 +40,38 @@
 #include "agent/application.hpp"
 #include "common/code_utils.hpp"
 #include "common/mainloop_manager.hpp"
+#include "host/posix/dnssd.hpp"
 #include "utils/infra_link_selector.hpp"
 
 namespace otbr {
 
+#ifndef OTBR_MAINLOOP_POLL_TIMEOUT_SEC
+#define OTBR_MAINLOOP_POLL_TIMEOUT_SEC 10
+#endif
+
 std::atomic_bool     Application::sShouldTerminate(false);
-const struct timeval Application::kPollTimeout = {10, 0};
-
-Application::Application(const std::string               &aInterfaceName,
-                         const std::vector<const char *> &aBackboneInterfaceNames,
-                         const std::vector<const char *> &aRadioUrls,
-                         bool                             aEnableAutoAttach,
-                         const std::string               &aRestListenAddress,
-                         int                              aRestListenPort)
+const struct timeval Application::kPollTimeout = {OTBR_MAINLOOP_POLL_TIMEOUT_SEC, 0};
+
+Application::Application(Host::ThreadHost  &aHost,
+                         const std::string &aInterfaceName,
+                         const std::string &aBackboneInterfaceName,
+                         const std::string &aRestListenAddress,
+                         int                aRestListenPort)
     : mInterfaceName(aInterfaceName)
-#if __linux__
-    , mInfraLinkSelector(aBackboneInterfaceNames)
-    , mBackboneInterfaceName(mInfraLinkSelector.Select())
-#else
-    , mBackboneInterfaceName(aBackboneInterfaceNames.empty() ? "" : aBackboneInterfaceNames.front())
-#endif
-    , mHost(Ncp::ThreadHost::Create(mInterfaceName.c_str(),
-                                    aRadioUrls,
-                                    mBackboneInterfaceName,
-                                    /* aDryRun */ false,
-                                    aEnableAutoAttach))
+    , mBackboneInterfaceName(aBackboneInterfaceName.c_str())
+    , mHost(aHost)
 #if OTBR_ENABLE_MDNS
-    , mPublisher(Mdns::Publisher::Create([this](Mdns::Publisher::State aState) { this->HandleMdnsState(aState); }))
+    , mPublisher(
+          Mdns::Publisher::Create([this](Mdns::Publisher::State aState) { mMdnsStateSubject.UpdateState(aState); }))
+#endif
+#if OTBR_ENABLE_DNSSD_PLAT
+    , mDnssdPlatform(*mPublisher)
 #endif
 #if OTBR_ENABLE_DBUS_SERVER && OTBR_ENABLE_BORDER_AGENT
-    , mDBusAgent(MakeUnique<DBus::DBusAgent>(*mHost, *mPublisher))
+    , mDBusAgent(MakeUnique<DBus::DBusAgent>(mHost, *mPublisher))
 #endif
 {
-    if (mHost->GetCoprocessorType() == OT_COPROCESSOR_RCP)
+    if (mHost.GetCoprocessorType() == OT_COPROCESSOR_RCP)
     {
         CreateRcpMode(aRestListenAddress, aRestListenPort);
     }
@@ -80,9 +79,9 @@ Application::Application(const std::string               &aInterfaceName,
 
 void Application::Init(void)
 {
-    mHost->Init();
+    mHost.Init();
 
-    switch (mHost->GetCoprocessorType())
+    switch (mHost.GetCoprocessorType())
     {
     case OT_COPROCESSOR_RCP:
         InitRcpMode();
@@ -95,12 +94,12 @@ void Application::Init(void)
         break;
     }
 
-    otbrLogInfo("Co-processor version: %s", mHost->GetCoprocessorVersion());
+    otbrLogInfo("Co-processor version: %s", mHost.GetCoprocessorVersion());
 }
 
 void Application::Deinit(void)
 {
-    switch (mHost->GetCoprocessorType())
+    switch (mHost.GetCoprocessorType())
     {
     case OT_COPROCESSOR_RCP:
         DeinitRcpMode();
@@ -113,15 +112,13 @@ void Application::Deinit(void)
         break;
     }
 
-    mHost->Deinit();
+    mHost.Deinit();
 }
 
 otbrError Application::Run(void)
 {
     otbrError error = OTBR_ERROR_NONE;
 
-    otbrLogInfo("Thread Border Router started on AIL %s.", mBackboneInterfaceName);
-
 #ifdef HAVE_LIBSYSTEMD
     if (getenv("SYSTEMD_EXEC_PID") != nullptr)
     {
@@ -147,6 +144,9 @@ otbrError Application::Run(void)
     // allow quitting elegantly
     signal(SIGTERM, HandleSignal);
 
+    // avoid exiting on SIGPIPE
+    signal(SIGPIPE, SIG_IGN);
+
     while (!sShouldTerminate)
     {
         otbr::MainloopContext mainloop;
@@ -168,17 +168,14 @@ otbrError Application::Run(void)
         {
             MainloopManager::GetInstance().Process(mainloop);
 
-#if __linux__
+            if (mErrorCondition)
             {
-                const char *newInfraLink = mInfraLinkSelector.Select();
-
-                if (mBackboneInterfaceName != newInfraLink)
+                error = mErrorCondition();
+                if (error != OTBR_ERROR_NONE)
                 {
-                    error = OTBR_ERROR_INFRA_LINK_CHANGED;
                     break;
                 }
             }
-#endif
         }
         else if (errno != EINTR)
         {
@@ -191,24 +188,6 @@ otbrError Application::Run(void)
     return error;
 }
 
-void Application::HandleMdnsState(Mdns::Publisher::State aState)
-{
-    OTBR_UNUSED_VARIABLE(aState);
-
-#if OTBR_ENABLE_BORDER_AGENT
-    mBorderAgent->HandleMdnsState(aState);
-#endif
-#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
-    mAdvertisingProxy->HandleMdnsState(aState);
-#endif
-#if OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
-    mDiscoveryProxy->HandleMdnsState(aState);
-#endif
-#if OTBR_ENABLE_TREL
-    mTrelDnssd->HandleMdnsState(aState);
-#endif
-}
-
 void Application::HandleSignal(int aSignal)
 {
     sShouldTerminate = true;
@@ -217,7 +196,7 @@ void Application::HandleSignal(int aSignal)
 
 void Application::CreateRcpMode(const std::string &aRestListenAddress, int aRestListenPort)
 {
-    otbr::Ncp::RcpHost &rcpHost = static_cast<otbr::Ncp::RcpHost &>(*mHost);
+    otbr::Host::RcpHost &rcpHost = static_cast<otbr::Host::RcpHost &>(mHost);
 #if OTBR_ENABLE_BORDER_AGENT
     mBorderAgent = MakeUnique<BorderAgent>(rcpHost, *mPublisher);
 #endif
@@ -249,10 +228,34 @@ void Application::CreateRcpMode(const std::string &aRestListenAddress, int aRest
 
 void Application::InitRcpMode(void)
 {
+    Host::RcpHost &rcpHost = static_cast<otbr::Host::RcpHost &>(mHost);
+    OTBR_UNUSED_VARIABLE(rcpHost);
+
+#if OTBR_ENABLE_BORDER_AGENT
+    mMdnsStateSubject.AddObserver(*mBorderAgent);
+#endif
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    mMdnsStateSubject.AddObserver(*mAdvertisingProxy);
+#endif
+#if OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
+    mMdnsStateSubject.AddObserver(*mDiscoveryProxy);
+#endif
+#if OTBR_ENABLE_TREL
+    mMdnsStateSubject.AddObserver(*mTrelDnssd);
+#endif
+#if OTBR_ENABLE_DNSSD_PLAT
+    mMdnsStateSubject.AddObserver(mDnssdPlatform);
+    mDnssdPlatform.SetDnssdStateChangedCallback(([&rcpHost](otPlatDnssdState aState) {
+        OTBR_UNUSED_VARIABLE(aState);
+        otPlatDnssdStateHandleStateChange(rcpHost.GetInstance());
+    }));
+#endif
+
 #if OTBR_ENABLE_MDNS
     mPublisher->Start();
 #endif
 #if OTBR_ENABLE_BORDER_AGENT
+    mBorderAgent->Init();
 // This is for delaying publishing the MeshCoP service until the correct
 // vendor name and OUI etc. are correctly set by BorderAgent::SetMeshCopServiceValues()
 #if OTBR_STOP_BORDER_AGENT_ON_INIT
@@ -282,10 +285,16 @@ void Application::InitRcpMode(void)
 #if OTBR_ENABLE_VENDOR_SERVER
     mVendorServer->Init();
 #endif
+#if OTBR_ENABLE_DNSSD_PLAT
+    mDnssdPlatform.Start();
+#endif
 }
 
 void Application::DeinitRcpMode(void)
 {
+#if OTBR_ENABLE_DNSSD_PLAT
+    mDnssdPlatform.Stop();
+#endif
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
     mAdvertisingProxy->SetEnabled(false);
 #endif
@@ -294,14 +303,22 @@ void Application::DeinitRcpMode(void)
 #endif
 #if OTBR_ENABLE_BORDER_AGENT
     mBorderAgent->SetEnabled(false);
+    mBorderAgent->Deinit();
 #endif
 #if OTBR_ENABLE_MDNS
+    mMdnsStateSubject.Clear();
     mPublisher->Stop();
 #endif
 }
 
 void Application::InitNcpMode(void)
 {
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    otbr::Host::NcpHost &ncpHost = static_cast<otbr::Host::NcpHost &>(mHost);
+    ncpHost.SetMdnsPublisher(mPublisher.get());
+    mMdnsStateSubject.AddObserver(ncpHost);
+    mPublisher->Start();
+#endif
 #if OTBR_ENABLE_DBUS_SERVER
     mDBusAgent->Init(*mBorderAgent);
 #endif
@@ -309,7 +326,9 @@ void Application::InitNcpMode(void)
 
 void Application::DeinitNcpMode(void)
 {
-    /* empty */
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    mPublisher->Stop();
+#endif
 }
 
 } // namespace otbr
diff --git a/src/agent/application.hpp b/src/agent/application.hpp
index 92b44ef1..85aca7c3 100644
--- a/src/agent/application.hpp
+++ b/src/agent/application.hpp
@@ -44,7 +44,8 @@
 #if OTBR_ENABLE_BORDER_AGENT
 #include "border_agent/border_agent.hpp"
 #endif
-#include "ncp/rcp_host.hpp"
+#include "host/ncp_host.hpp"
+#include "host/rcp_host.hpp"
 #if OTBR_ENABLE_BACKBONE_ROUTER
 #include "backbone_router/backbone_agent.hpp"
 #endif
@@ -60,6 +61,9 @@
 #if OTBR_ENABLE_VENDOR_SERVER
 #include "agent/vendor.hpp"
 #endif
+#if OTBR_ENABLE_DNSSD_PLAT
+#include "host/posix/dnssd.hpp"
+#endif
 #include "utils/infra_link_selector.hpp"
 
 namespace otbr {
@@ -87,22 +91,22 @@ class VendorServer;
 class Application : private NonCopyable
 {
 public:
+    typedef std::function<otbrError(void)> ErrorCondition;
+
     /**
      * This constructor initializes the Application instance.
      *
+     * @param[in] aHost                  A reference to the ThreadHost object.
      * @param[in] aInterfaceName         Name of the Thread network interface.
      * @param[in] aBackboneInterfaceName Name of the backbone network interface.
-     * @param[in] aRadioUrls             The radio URLs (can be IEEE802.15.4 or TREL radio).
-     * @param[in] aEnableAutoAttach      Whether or not to automatically attach to the saved network.
      * @param[in] aRestListenAddress     Network address to listen on.
      * @param[in] aRestListenPort        Network port to listen on.
      */
-    explicit Application(const std::string               &aInterfaceName,
-                         const std::vector<const char *> &aBackboneInterfaceNames,
-                         const std::vector<const char *> &aRadioUrls,
-                         bool                             aEnableAutoAttach,
-                         const std::string               &aRestListenAddress,
-                         int                              aRestListenPort);
+    explicit Application(Host::ThreadHost  &aHost,
+                         const std::string &aInterfaceName,
+                         const std::string &aBackboneInterfaceName,
+                         const std::string &aRestListenAddress,
+                         int                aRestListenPort);
 
     /**
      * This method initializes the Application instance.
@@ -114,6 +118,16 @@ public:
      */
     void Deinit(void);
 
+    /**
+     * This method sets an error condition for the application.
+     *
+     * If the error condition returns an error other than 'OTBR_ERROR_NONE', the application will
+     * exit the loop in `Run`.
+     *
+     * @param[in] aErrorCondition  The error condition.
+     */
+    void SetErrorCondition(ErrorCondition aErrorCondition) { mErrorCondition = aErrorCondition; }
+
     /**
      * This method runs the application until exit.
      *
@@ -127,7 +141,7 @@ public:
      *
      * @returns The OpenThread controller object.
      */
-    Ncp::ThreadHost &GetHost(void) { return *mHost; }
+    Host::ThreadHost &GetHost(void) { return mHost; }
 
 #if OTBR_ENABLE_MDNS
     /**
@@ -237,13 +251,6 @@ public:
     }
 #endif
 
-    /**
-     * This method handles mDNS publisher's state changes.
-     *
-     * @param[in] aState  The state of mDNS publisher.
-     */
-    void HandleMdnsState(Mdns::Publisher::State aState);
-
 private:
     // Default poll timeout.
     static const struct timeval kPollTimeout;
@@ -257,15 +264,16 @@ private:
     void InitNcpMode(void);
     void DeinitNcpMode(void);
 
-    std::string mInterfaceName;
-#if __linux__
-    otbr::Utils::InfraLinkSelector mInfraLinkSelector;
-#endif
-    const char                      *mBackboneInterfaceName;
-    std::unique_ptr<Ncp::ThreadHost> mHost;
+    std::string       mInterfaceName;
+    const char       *mBackboneInterfaceName;
+    Host::ThreadHost &mHost;
 #if OTBR_ENABLE_MDNS
+    Mdns::StateSubject               mMdnsStateSubject;
     std::unique_ptr<Mdns::Publisher> mPublisher;
 #endif
+#if OTBR_ENABLE_DNSSD_PLAT
+    DnssdPlatform mDnssdPlatform;
+#endif
 #if OTBR_ENABLE_BORDER_AGENT
     std::unique_ptr<BorderAgent> mBorderAgent;
 #endif
@@ -295,6 +303,7 @@ private:
 #endif
 
     static std::atomic_bool sShouldTerminate;
+    ErrorCondition          mErrorCondition;
 };
 
 /**
diff --git a/src/agent/main.cpp b/src/agent/main.cpp
index 80aaec6d..bb8a0150 100644
--- a/src/agent/main.cpp
+++ b/src/agent/main.cpp
@@ -52,7 +52,7 @@
 #include "common/logging.hpp"
 #include "common/mainloop.hpp"
 #include "common/types.hpp"
-#include "ncp/thread_host.hpp"
+#include "host/thread_host.hpp"
 
 #ifdef OTBR_ENABLE_PLATFORM_ANDROID
 #include <log/log.h>
@@ -61,10 +61,12 @@
 #endif
 #endif
 
-static const char kDefaultInterfaceName[] = "wpan0";
+#define DEFAULT_INTERFACE_NAME "wpan0"
+static const char kDefaultInterfaceName[] = DEFAULT_INTERFACE_NAME;
 
 // Port number used by Rest server.
 static const uint32_t kPortNumber = 8081;
+#define HELP_DEFAULT_REST_PORT_NUMBER "8081"
 
 enum
 {
@@ -145,8 +147,20 @@ static void PrintHelp(const char *aProgramName)
     fprintf(stderr,
             "Usage: %s [-I interfaceName] [-B backboneIfName] [-d DEBUG_LEVEL] [-v] [-s] [--auto-attach[=0/1]] "
             "RADIO_URL [RADIO_URL]\n"
-            "    --auto-attach defaults to 1\n"
-            "    -s disables syslog and prints to standard out\n",
+            "     -I, --thread-ifname    Name of the Thread network interface (default: " DEFAULT_INTERFACE_NAME ").\n"
+            "     -B, --backbone-ifname  Name of the backbone network interfaces (can be specified multiple times).\n"
+            "     -d, --debug-level      The log level (EMERG=0, ALERT=1, CRIT=2, ERR=3, WARNING=4, NOTICE=5, INFO=6, "
+            "DEBUG=7).\n"
+            "     -v, --verbose          Enable verbose logging.\n"
+            "     -s, --syslog-disable   Disable syslog and print to standard out.\n"
+            "     -h, --help             Show this help text.\n"
+            "     -V, --version          Print the application's version and exit.\n"
+            "     --radio-version        Print the radio coprocessor version and exit.\n"
+            "     --auto-attach          Whether or not to automatically attach to the saved network (default: 1).\n"
+            "     --rest-listen-address  Network address to listen on for the REST API (default: [::]).\n"
+            "     --rest-listen-port     Network port to listen on for the REST API "
+            "(default: " HELP_DEFAULT_REST_PORT_NUMBER ").\n"
+            "\n",
             aProgramName);
     fprintf(stderr, "%s", otSysGetRadioUrlHelpString());
 }
@@ -186,10 +200,10 @@ static otbrLogLevel GetDefaultLogLevel(void)
 
 static void PrintRadioVersionAndExit(const std::vector<const char *> &aRadioUrls)
 {
-    auto host = std::unique_ptr<otbr::Ncp::ThreadHost>(
-        otbr::Ncp::ThreadHost::Create(/* aInterfaceName */ "", aRadioUrls,
-                                      /* aBackboneInterfaceName */ "",
-                                      /* aDryRun */ true, /* aEnableAutoAttach */ false));
+    auto host = std::unique_ptr<otbr::Host::ThreadHost>(
+        otbr::Host::ThreadHost::Create(/* aInterfaceName */ "", aRadioUrls,
+                                       /* aBackboneInterfaceName */ "",
+                                       /* aDryRun */ true, /* aEnableAutoAttach */ false));
     const char *coprocessorVersion;
 
     host->Init();
@@ -290,7 +304,7 @@ static int realmain(int argc, char *argv[])
 
     otbrLogInit(argv[0], logLevel, verbose, syslogDisable);
     otbrLogNotice("Running %s", OTBR_PACKAGE_VERSION);
-    otbrLogNotice("Thread version: %s", otbr::Ncp::RcpHost::GetThreadVersion());
+    otbrLogNotice("Thread version: %s", otbr::Host::RcpHost::GetThreadVersion());
     otbrLogNotice("Thread interface: %s", interfaceName);
 
     if (backboneInterfaceNames.empty())
@@ -311,11 +325,26 @@ static int realmain(int argc, char *argv[])
     }
 
     {
-        otbr::Application app(interfaceName, backboneInterfaceNames, radioUrls, enableAutoAttach, restListenAddress,
-                              restListenPort);
+#if __linux__
+        otbr::Utils::InfraLinkSelector    infraLinkSelector(backboneInterfaceNames);
+        const std::string                 backboneInterfaceName = infraLinkSelector.Select();
+        otbr::Application::ErrorCondition errorCondition        = [&backboneInterfaceName, &infraLinkSelector](void) {
+            return std::string(infraLinkSelector.Select()) == backboneInterfaceName ? OTBR_ERROR_NONE
+                                                                                           : OTBR_ERROR_INFRA_LINK_CHANGED;
+        };
+#else
+        const std::string backboneInterfaceName = backboneInterfaceNames.empty() ? "" : backboneInterfaceNames.front();
+#endif
+        std::unique_ptr<otbr::Host::ThreadHost> host = otbr::Host::ThreadHost::Create(
+            interfaceName, radioUrls, backboneInterfaceName.c_str(), /* aDryRun */ false, enableAutoAttach);
+
+        otbr::Application app(*host, interfaceName, backboneInterfaceName, restListenAddress, restListenPort);
 
         gApp = &app;
         app.Init();
+#if __linux__
+        app.SetErrorCondition(errorCondition);
+#endif
 
         ret = app.Run();
 
diff --git a/src/android/aidl/com/android/server/thread/openthread/Ipv6AddressInfo.aidl b/src/android/aidl/com/android/server/thread/openthread/Ipv6AddressInfo.aidl
index 671f3418..37e6a837 100644
--- a/src/android/aidl/com/android/server/thread/openthread/Ipv6AddressInfo.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/Ipv6AddressInfo.aidl
@@ -39,6 +39,7 @@ parcelable Ipv6AddressInfo {
     int prefixLength; // Valid for only unicast addresses
     boolean isPreferred; // Valid for only unicast addresses
     boolean isMeshLocal; // Valid for only unicast addresses
+    boolean isMeshLocalEid; // Valid for only unicast address
     boolean isActiveOmr; // Valid for only unicast addresses. Active OMR means the prefix is added
                          // to netdata, if the OMR prefix is removed from netdata then the address
                          // is not active OMR anymore.
diff --git a/src/android/aidl/com/android/server/thread/openthread/OtDaemonConfiguration.aidl b/src/android/aidl/com/android/server/thread/openthread/OtDaemonConfiguration.aidl
index 24a94917..bb318621 100644
--- a/src/android/aidl/com/android/server/thread/openthread/OtDaemonConfiguration.aidl
+++ b/src/android/aidl/com/android/server/thread/openthread/OtDaemonConfiguration.aidl
@@ -28,7 +28,10 @@
 
 package com.android.server.thread.openthread;
 
-/** An internal mirror of {@link android.net.thread.ThreadConfiguration}. */
+/**
+ * A mirror of {@link android.net.thread.ThreadConfiguration} with optionally more internal
+ * parameters.
+ */
 @JavaOnlyImmutable
 @JavaDerive(equals=true, toString=true)
 parcelable OtDaemonConfiguration {
@@ -37,4 +40,24 @@ parcelable OtDaemonConfiguration {
 
     boolean nat64Enabled;
     boolean dhcpv6PdEnabled;
+
+    /** {@code true} if SRP sevrer should wait for border routing getting ready. */
+    boolean srpServerWaitForBorderRoutingEnabled = true;
+
+    /**
+     * {@code true} if this border router automatically joins the previously connected network
+     * after device reboots.
+     */
+    boolean borderRouterAutoJoinEnabled = true;
+
+    /**
+     * {@code true} if setting country code is enabled by OEM.
+     */
+    boolean countryCodeEnabled = true;
+
+    /** The vendor name which will be set to the Vendor Name TLV for diagnostic. */
+    String vendorName;
+
+    /** The model name which will be set to the Vendor Model TLV for diagnostic. */
+    String modelName;
 }
diff --git a/src/android/android_rcp_host.cpp b/src/android/android_rcp_host.cpp
index 79326d30..0460dc8a 100644
--- a/src/android/android_rcp_host.cpp
+++ b/src/android/android_rcp_host.cpp
@@ -40,9 +40,11 @@
 #include <openthread/dnssd_server.h>
 #include <openthread/ip6.h>
 #include <openthread/nat64.h>
+#include <openthread/netdiag.h>
 #include <openthread/openthread-system.h>
 #include <openthread/srp_server.h>
 #include <openthread/thread.h>
+#include <openthread/thread_ftd.h>
 #include <openthread/trel.h>
 #include <openthread/platform/infra_if.h>
 #include <openthread/platform/trel.h>
@@ -55,7 +57,7 @@ namespace Android {
 
 AndroidRcpHost *AndroidRcpHost::sAndroidRcpHost = nullptr;
 
-AndroidRcpHost::AndroidRcpHost(Ncp::RcpHost &aRcpHost)
+AndroidRcpHost::AndroidRcpHost(Host::RcpHost &aRcpHost)
     : mRcpHost(aRcpHost)
     , mConfiguration()
     , mInfraIcmp6Socket(-1)
@@ -71,11 +73,16 @@ void AndroidRcpHost::SetConfiguration(const OtDaemonConfiguration              &
     otError          error = OT_ERROR_NONE;
     std::string      message;
     otLinkModeConfig linkModeConfig;
+    bool             borderRouterEnabled = aConfiguration.borderRouterEnabled;
 
     otbrLogInfo("Set configuration: %s", aConfiguration.toString().c_str());
 
     VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
-    VerifyOrExit(aConfiguration != mConfiguration);
+
+    SuccessOrExit(error   = otThreadSetVendorName(GetOtInstance(), aConfiguration.vendorName.c_str()),
+                  message = "Invalid vendor name " + aConfiguration.vendorName);
+    SuccessOrExit(error   = otThreadSetVendorModel(GetOtInstance(), aConfiguration.modelName.c_str()),
+                  message = "Invalid model name " + aConfiguration.modelName);
 
     // TODO: b/343814054 - Support enabling/disabling DHCPv6-PD.
     VerifyOrExit(!aConfiguration.dhcpv6PdEnabled, error = OT_ERROR_NOT_IMPLEMENTED,
@@ -84,21 +91,35 @@ void AndroidRcpHost::SetConfiguration(const OtDaemonConfiguration              &
     // DNS upstream query is enabled if and only if NAT64 is enabled.
     otDnssdUpstreamQuerySetEnabled(GetOtInstance(), aConfiguration.nat64Enabled);
 
-    linkModeConfig = GetLinkModeConfig(aConfiguration.borderRouterEnabled);
+    // Thread has to be a Router before new Android API is added to support making it a SED (Sleepy End Device)
+    linkModeConfig = GetLinkModeConfig(/* aIsRouter= */ true);
     SuccessOrExit(error = otThreadSetLinkMode(GetOtInstance(), linkModeConfig), message = "Failed to set link mode");
-    if (aConfiguration.borderRouterEnabled)
+
+    // - In non-BR mode, this device should try to be a router only when there are no other routers
+    // - 16 is the default ROUTER_UPGRADE_THRESHOLD value defined in OpenThread
+    otThreadSetRouterUpgradeThreshold(GetOtInstance(), (borderRouterEnabled ? 16 : 1));
+
+    // Sets much lower Leader / Partition weight for a non-BR device so that it would
+    // not attempt to be the new leader after merging partitions. Keeps BR using the
+    // default Leader weight value 64.
+    //
+    // TODO: b/404979710 - sets leader weight higher based on the new Thread 1.4 device
+    // properties feature.
+    otThreadSetLocalLeaderWeight(GetOtInstance(), (borderRouterEnabled ? 64 : 32));
+
+    if (borderRouterEnabled && aConfiguration.srpServerWaitForBorderRoutingEnabled)
     {
+        // This will automatically disable fast-start mode if it was ever enabled
         otSrpServerSetAutoEnableMode(GetOtInstance(), true);
-        SetBorderRouterEnabled(true);
     }
     else
     {
-        // This automatically disables the auto-enable mode which is designed for border router
-        otSrpServerSetEnabled(GetOtInstance(), true);
-
-        SetBorderRouterEnabled(false);
+        otSrpServerSetAutoEnableMode(GetOtInstance(), false);
+        otSrpServerEnableFastStartMode(GetOtInstance());
     }
 
+    SetBorderRouterEnabled(borderRouterEnabled);
+
     mConfiguration = aConfiguration;
 
 exit:
diff --git a/src/android/android_rcp_host.hpp b/src/android/android_rcp_host.hpp
index 39fa12d9..54458290 100644
--- a/src/android/android_rcp_host.hpp
+++ b/src/android/android_rcp_host.hpp
@@ -34,7 +34,7 @@
 #include <memory>
 
 #include "common_utils.hpp"
-#include "ncp/rcp_host.hpp"
+#include "host/rcp_host.hpp"
 
 namespace otbr {
 namespace Android {
@@ -42,7 +42,7 @@ namespace Android {
 class AndroidRcpHost : public AndroidThreadHost
 {
 public:
-    AndroidRcpHost(Ncp::RcpHost &aRcpHost);
+    AndroidRcpHost(Host::RcpHost &aRcpHost);
     ~AndroidRcpHost(void) = default;
 
     void                         SetConfiguration(const OtDaemonConfiguration              &aConfiguration,
@@ -74,7 +74,7 @@ private:
 
     static AndroidRcpHost *sAndroidRcpHost;
 
-    Ncp::RcpHost         &mRcpHost;
+    Host::RcpHost        &mRcpHost;
     OtDaemonConfiguration mConfiguration;
     InfraLinkState        mInfraLinkState;
     int                   mInfraIcmp6Socket;
diff --git a/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java b/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java
index 4d1ce177..901f7053 100644
--- a/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java
+++ b/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java
@@ -89,6 +89,7 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
     @Nullable private IOtDaemonCallback mCallback;
     @Nullable private Long mCallbackListenerId;
     @Nullable private RemoteException mJoinException;
+    @Nullable private String mNat64Cidr;
     @Nullable private RemoteException mSetNat64CidrException;
     @Nullable private RemoteException mRunOtCtlCommandException;
     @Nullable private String mCountryCode;
@@ -403,6 +404,12 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
         }
     }
 
+    /** Returns the configuration set by {@link #initialize} or {@link #setConfiguration}. */
+    @Nullable
+    public OtDaemonConfiguration getConfiguration() {
+        return mConfiguration;
+    }
+
     @Override
     public void setInfraLinkInterfaceName(
             String interfaceName, ParcelFileDescriptor fd, IOtStatusReceiver receiver)
@@ -428,11 +435,18 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
         if (mSetNat64CidrException != null) {
             throw mSetNat64CidrException;
         }
+        mNat64Cidr = nat64Cidr;
         if (receiver != null) {
             receiver.onSuccess();
         }
     }
 
+    /** Returns the NAT64 CIDR set by {@link #setNat64Cidr}. */
+    @Nullable
+    public String getNat64Cidr() {
+        return mNat64Cidr;
+    }
+
     @Override
     public void setInfraLinkDnsServers(List<String> dnsServers, IOtStatusReceiver receiver)
             throws RemoteException {
diff --git a/src/android/otbr-config-android.h b/src/android/otbr-config-android.h
index 7d4d6ba0..70050013 100644
--- a/src/android/otbr-config-android.h
+++ b/src/android/otbr-config-android.h
@@ -28,4 +28,6 @@
 
 #ifdef OTBR_CONFIG_ANDROID_VERSION_HEADER_ENABLE
 #include <otbr-config-android-version.h>
+
+#define OTBR_MAINLOOP_POLL_TIMEOUT_SEC (28 * 24 * 60 * 60)
 #endif
diff --git a/src/android/otdaemon_fuzzer.cpp b/src/android/otdaemon_fuzzer.cpp
index 7b0716dc..bd647341 100644
--- a/src/android/otdaemon_fuzzer.cpp
+++ b/src/android/otdaemon_fuzzer.cpp
@@ -29,25 +29,30 @@
 #include <fuzzbinder/libbinder_ndk_driver.h>
 #include <fuzzer/FuzzedDataProvider.h>
 
-#include "otdaemon_server.hpp"
+#include "android/mdns_publisher.hpp"
+#include "android/otdaemon_server.hpp"
+#include "host/rcp_host.hpp"
+#include "mdns/mdns.hpp"
+#include "sdp_proxy/advertising_proxy.hpp"
 
 using android::fuzzService;
 using otbr::Android::MdnsPublisher;
 using otbr::Android::OtDaemonServer;
+using otbr::Host::RcpHost;
 using otbr::Mdns::Publisher;
-using otbr::Ncp::RcpHost;
 
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
 {
-    RcpHost           rcpHost       = RcpHost{"" /* aInterfaceName */,
+    RcpHost                rcpHost       = RcpHost{"" /* aInterfaceName */,
                               {"threadnetwork_hal://binder?none"},
                               "" /* aBackboneInterfaceName */,
                               true /* aDryRun */,
                               false /* aEnableAutoAttach*/};
-    auto              mdnsPublisher = static_cast<MdnsPublisher *>(Publisher::Create([](Publisher::State) {}));
-    otbr::BorderAgent borderAgent{rcpHost, *mdnsPublisher};
+    auto                   mdnsPublisher = static_cast<MdnsPublisher *>(Publisher::Create([](Publisher::State) {}));
+    otbr::BorderAgent      borderAgent{rcpHost, *mdnsPublisher};
+    otbr::AdvertisingProxy advProxy{rcpHost, *mdnsPublisher};
 
-    auto service = ndk::SharedRefBase::make<OtDaemonServer>(rcpHost, *mdnsPublisher, borderAgent);
+    auto service = ndk::SharedRefBase::make<OtDaemonServer>(rcpHost, *mdnsPublisher, borderAgent, advProxy, []() {});
     fuzzService(service->asBinder().get(), FuzzedDataProvider(data, size));
     return 0;
 }
diff --git a/src/android/otdaemon_server.cpp b/src/android/otdaemon_server.cpp
index acdf7e4b..84bbc229 100644
--- a/src/android/otdaemon_server.cpp
+++ b/src/android/otdaemon_server.cpp
@@ -48,6 +48,7 @@
 #include <openthread/nat64.h>
 #include <openthread/openthread-system.h>
 #include <openthread/srp_server.h>
+#include <openthread/thread_ftd.h>
 #include <openthread/platform/infra_if.h>
 #include <openthread/platform/radio.h>
 
@@ -56,7 +57,7 @@
 #include "android/common_utils.hpp"
 #include "android/otdaemon_telemetry.hpp"
 #include "common/code_utils.hpp"
-#include "ncp/thread_host.hpp"
+#include "host/thread_host.hpp"
 
 #define BYTE_ARR_END(arr) ((arr) + sizeof(arr))
 
@@ -67,8 +68,12 @@ namespace vendor {
 std::shared_ptr<VendorServer> VendorServer::newInstance(Application &aApplication)
 {
     return ndk::SharedRefBase::make<Android::OtDaemonServer>(
-        static_cast<otbr::Ncp::RcpHost &>(aApplication.GetHost()),
-        static_cast<otbr::Android::MdnsPublisher &>(aApplication.GetPublisher()), aApplication.GetBorderAgent());
+        static_cast<otbr::Host::RcpHost &>(aApplication.GetHost()),
+        static_cast<otbr::Android::MdnsPublisher &>(aApplication.GetPublisher()), aApplication.GetBorderAgent(),
+        aApplication.GetAdvertisingProxy(), [&aApplication]() {
+            aApplication.Deinit();
+            aApplication.Init();
+        });
 }
 
 } // namespace vendor
@@ -99,13 +104,17 @@ static const char *ThreadEnabledStateToString(int enabledState)
 
 OtDaemonServer *OtDaemonServer::sOtDaemonServer = nullptr;
 
-OtDaemonServer::OtDaemonServer(otbr::Ncp::RcpHost    &aRcpHost,
-                               otbr::Mdns::Publisher &aMdnsPublisher,
-                               otbr::BorderAgent     &aBorderAgent)
+OtDaemonServer::OtDaemonServer(otbr::Host::RcpHost    &aRcpHost,
+                               otbr::Mdns::Publisher  &aMdnsPublisher,
+                               otbr::BorderAgent      &aBorderAgent,
+                               otbr::AdvertisingProxy &aAdvProxy,
+                               ResetThreadHandler      aResetThreadHandler)
     : mHost(aRcpHost)
     , mAndroidHost(CreateAndroidHost())
     , mMdnsPublisher(static_cast<MdnsPublisher &>(aMdnsPublisher))
     , mBorderAgent(aBorderAgent)
+    , mAdvProxy(aAdvProxy)
+    , mResetThreadHandler(aResetThreadHandler)
 {
     mClientDeathRecipient =
         ::ndk::ScopedAIBinder_DeathRecipient(AIBinder_DeathRecipient_new(&OtDaemonServer::BinderDeathCallback));
@@ -231,7 +240,9 @@ Ipv6AddressInfo OtDaemonServer::ConvertToAddressInfo(const otNetifAddress &aAddr
     addrInfo.prefixLength = aAddress.mPrefixLength;
     addrInfo.isPreferred  = aAddress.mPreferred;
     addrInfo.isMeshLocal  = aAddress.mMeshLocal;
-    addrInfo.isActiveOmr  = otNetDataContainsOmrPrefix(GetOtInstance(), &addressPrefix);
+    addrInfo.isMeshLocalEid =
+        (memcmp(&aAddress.mAddress, otThreadGetMeshLocalEid(GetOtInstance()), sizeof(aAddress.mAddress)) == 0);
+    addrInfo.isActiveOmr = otNetDataContainsOmrPrefix(GetOtInstance(), &addressPrefix);
     return addrInfo;
 }
 
@@ -385,12 +396,6 @@ void OtDaemonServer::HandleEpskcStateChanged(void *aBinderServer)
 void OtDaemonServer::HandleEpskcStateChanged(void)
 {
     mState.ephemeralKeyState = GetEphemeralKeyState();
-
-    NotifyStateChanged(/* aListenerId*/ -1);
-}
-
-void OtDaemonServer::NotifyStateChanged(int64_t aListenerId)
-{
     if (mState.ephemeralKeyState == OT_EPHEMERAL_KEY_DISABLED)
     {
         mState.ephemeralKeyLifetimeMillis = 0;
@@ -402,6 +407,12 @@ void OtDaemonServer::NotifyStateChanged(int64_t aListenerId)
             std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
                 .count();
     }
+
+    NotifyStateChanged(/* aListenerId*/ -1);
+}
+
+void OtDaemonServer::NotifyStateChanged(int64_t aListenerId)
+{
     if (mCallback != nullptr)
     {
         mCallback->onStateChanged(mState, aListenerId);
@@ -412,20 +423,19 @@ int OtDaemonServer::GetEphemeralKeyState(void)
 {
     int ephemeralKeyState;
 
-    if (otBorderAgentIsEphemeralKeyActive(GetOtInstance()))
-    {
-        if (otBorderAgentGetState(GetOtInstance()) == OT_BORDER_AGENT_STATE_ACTIVE)
-        {
-            ephemeralKeyState = OT_EPHEMERAL_KEY_IN_USE;
-        }
-        else
-        {
-            ephemeralKeyState = OT_EPHEMERAL_KEY_ENABLED;
-        }
-    }
-    else
+    switch (otBorderAgentEphemeralKeyGetState(GetOtInstance()))
     {
+    case OT_BORDER_AGENT_STATE_STARTED:
+        ephemeralKeyState = OT_EPHEMERAL_KEY_ENABLED;
+        break;
+    case OT_BORDER_AGENT_STATE_CONNECTED:
+    case OT_BORDER_AGENT_STATE_ACCEPTED:
+        ephemeralKeyState = OT_EPHEMERAL_KEY_IN_USE;
+        break;
+    case OT_BORDER_AGENT_STATE_DISABLED:
+    case OT_BORDER_AGENT_STATE_STOPPED:
         ephemeralKeyState = OT_EPHEMERAL_KEY_DISABLED;
+        break;
     }
 
     return ephemeralKeyState;
@@ -521,7 +531,7 @@ std::unique_ptr<AndroidThreadHost> OtDaemonServer::CreateAndroidHost(void)
     switch (mHost.GetCoprocessorType())
     {
     case OT_COPROCESSOR_RCP:
-        host = std::make_unique<AndroidRcpHost>(static_cast<otbr::Ncp::RcpHost &>(mHost));
+        host = std::make_unique<AndroidRcpHost>(static_cast<otbr::Host::RcpHost &>(mHost));
         break;
 
     case OT_COPROCESSOR_NCP:
@@ -575,10 +585,15 @@ void OtDaemonServer::initializeInternal(const bool
     otbrError                error;
 
     mAndroidHost->SetConfiguration(aConfiguration, nullptr /* aReceiver */);
-    setCountryCodeInternal(aCountryCode, nullptr /* aReceiver */);
+
+    if (aConfiguration.countryCodeEnabled)
+    {
+        setCountryCodeInternal(aCountryCode, nullptr /* aReceiver */);
+    }
     registerStateCallbackInternal(aCallback, -1 /* listenerId */);
 
     mMdnsPublisher.SetINsdPublisher(aINsdPublisher);
+    mAdvProxy.SetAllowMlEid(!aConfiguration.borderRouterEnabled);
 
     for (const auto &txtAttr : aMeshcopTxts.nonStandardTxtEntries)
     {
@@ -593,6 +608,7 @@ void OtDaemonServer::initializeInternal(const bool
 
     mBorderAgent.SetEnabled(aEnabled && aConfiguration.borderRouterEnabled);
     mAndroidHost->SetTrelEnabled(aTrelEnabled);
+    mTrelEnabled = aTrelEnabled;
 
     if (aEnabled)
     {
@@ -641,7 +657,9 @@ void OtDaemonServer::EnableThread(const std::shared_ptr<IOtStatusReceiver> &aRec
 {
     otOperationalDatasetTlvs datasetTlvs;
 
-    if (otDatasetGetActiveTlvs(GetOtInstance(), &datasetTlvs) != OT_ERROR_NOT_FOUND && datasetTlvs.mLength > 0 &&
+    if ((mAndroidHost->GetConfiguration().borderRouterEnabled &&
+         mAndroidHost->GetConfiguration().borderRouterAutoJoinEnabled) &&
+        (otDatasetGetActiveTlvs(GetOtInstance(), &datasetTlvs) != OT_ERROR_NOT_FOUND && datasetTlvs.mLength > 0) &&
         !isAttached())
     {
         (void)otIp6SetEnabled(GetOtInstance(), true);
@@ -681,7 +699,7 @@ void OtDaemonServer::setThreadEnabledInternal(const bool aEnabled, const std::sh
         // `aReceiver` should not be set here because the operation isn't finished yet
         UpdateThreadEnabledState(OT_STATE_DISABLING, nullptr /* aReceiver */);
 
-        LeaveGracefully([aReceiver, this]() {
+        LeaveGracefully(false /* aEraseDataset */, "disableThread", [aReceiver, this]() {
             // Ignore errors as those operations should always succeed
             (void)otThreadSetEnabled(GetOtInstance(), false);
             (void)otIp6SetEnabled(GetOtInstance(), false);
@@ -715,14 +733,16 @@ void OtDaemonServer::activateEphemeralKeyModeInternal(const int64_t
     VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
     VerifyOrExit(isAttached(), error = static_cast<int>(IOtDaemon::ErrorCode::OT_ERROR_FAILED_PRECONDITION),
                  message = "Cannot activate ephemeral key mode when this device is not attached to Thread network");
-    VerifyOrExit(!otBorderAgentIsEphemeralKeyActive(GetOtInstance()), error = OT_ERROR_BUSY,
-                 message = "ephemeral key mode is already activated");
+    VerifyOrExit(otBorderAgentEphemeralKeyGetState(GetOtInstance()) != OT_BORDER_AGENT_STATE_DISABLED,
+                 error = OT_ERROR_INVALID_STATE, message = "ephemeral key manager is disabled");
+    VerifyOrExit(otBorderAgentEphemeralKeyGetState(GetOtInstance()) == OT_BORDER_AGENT_STATE_STOPPED,
+                 error = OT_ERROR_BUSY, message = "ephemeral key mode is already activated");
 
     otbrLogInfo("Activating ephemeral key mode with %lldms lifetime.", aLifetimeMillis);
 
     SuccessOrExit(error = mBorderAgent.CreateEphemeralKey(passcode), message = "Failed to create ephemeral key");
-    SuccessOrExit(error   = otBorderAgentSetEphemeralKey(GetOtInstance(), passcode.c_str(),
-                                                         static_cast<uint32_t>(aLifetimeMillis), 0 /* aUdpPort */),
+    SuccessOrExit(error   = otBorderAgentEphemeralKeyStart(GetOtInstance(), passcode.c_str(),
+                                                           static_cast<uint32_t>(aLifetimeMillis), 0 /* aUdpPort */),
                   message = "Failed to set ephemeral key");
 
 exit:
@@ -730,8 +750,10 @@ exit:
     {
         if (error == OT_ERROR_NONE)
         {
-            mState.ephemeralKeyPasscode = passcode;
-            mEphemeralKeyExpiryMillis   = std::chrono::duration_cast<std::chrono::milliseconds>(
+            mState.ephemeralKeyState          = GetEphemeralKeyState();
+            mState.ephemeralKeyPasscode       = passcode;
+            mState.ephemeralKeyLifetimeMillis = aLifetimeMillis;
+            mEphemeralKeyExpiryMillis         = std::chrono::duration_cast<std::chrono::milliseconds>(
                                             std::chrono::steady_clock::now().time_since_epoch())
                                             .count() +
                                         aLifetimeMillis;
@@ -759,10 +781,11 @@ void OtDaemonServer::deactivateEphemeralKeyModeInternal(const std::shared_ptr<IO
     VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
     otbrLogInfo("Deactivating ephemeral key mode.");
 
-    VerifyOrExit(otBorderAgentIsEphemeralKeyActive(GetOtInstance()), error = OT_ERROR_NONE);
+    VerifyOrExit(otBorderAgentEphemeralKeyGetState(GetOtInstance()) != OT_BORDER_AGENT_STATE_DISABLED &&
+                     otBorderAgentEphemeralKeyGetState(GetOtInstance()) != OT_BORDER_AGENT_STATE_STOPPED,
+                 error = OT_ERROR_NONE);
 
-    otBorderAgentDisconnect(GetOtInstance());
-    otBorderAgentClearEphemeralKey(GetOtInstance());
+    otBorderAgentEphemeralKeyStop(GetOtInstance());
 
 exit:
     PropagateResult(error, message, aReceiver);
@@ -905,19 +928,21 @@ void OtDaemonServer::joinInternal(const std::vector<uint8_t>               &aAct
     error = otDatasetGetActiveTlvs(GetOtInstance(), &curDatasetTlvs);
     if (error == OT_ERROR_NONE && areDatasetsEqual(newDatasetTlvs, curDatasetTlvs) && isAttached())
     {
-        // Do not leave and re-join if this device has already joined the same network. This can help elimilate
-        // unnecessary connectivity and topology disruption and save the time for re-joining. It's more useful for use
-        // cases where Thread networks are dynamically brought up and torn down (e.g. Thread on mobile phones).
+        // Do not leave and re-join if this device has already joined the same network.
+        // This can help elimilate unnecessary connectivity and topology disruption and
+        // save the time for re-joining. It's more useful for use cases where Thread
+        // networks are dynamically brought up and torn down (e.g. Thread on mobile phones).
         aReceiver->onSuccess();
         ExitNow();
     }
 
-    if (otThreadGetDeviceRole(GetOtInstance()) != OT_DEVICE_ROLE_DISABLED)
+    // If this device has ever joined a different network, try to leave from previous
+    // network first. Do this even this device role is detached or disabled, this is for
+    // clearing any in-memory state of the previous network.
+    if (error == OT_ERROR_NONE && !areDatasetsEqual(newDatasetTlvs, curDatasetTlvs))
     {
-        LeaveGracefully([aActiveOpDatasetTlvs, aReceiver, this]() {
-            FinishLeave(true /* aEraseDataset */, nullptr);
-            join(aActiveOpDatasetTlvs, aReceiver);
-        });
+        LeaveGracefully(true /* aEraseDataset */, "join",
+                        [aActiveOpDatasetTlvs, aReceiver, this]() { join(aActiveOpDatasetTlvs, aReceiver); });
         ExitNow();
     }
 
@@ -933,7 +958,7 @@ void OtDaemonServer::joinInternal(const std::vector<uint8_t>               &aAct
     // Abort an ongoing join()
     if (mJoinReceiver != nullptr)
     {
-        mJoinReceiver->onError(OT_ERROR_ABORT, "Join() is aborted");
+        mJoinReceiver->onError(OT_ERROR_ABORT, "Aborted by a new join()");
     }
     mJoinReceiver = aReceiver;
 
@@ -953,48 +978,89 @@ Status OtDaemonServer::leave(bool aEraseDataset, const std::shared_ptr<IOtStatus
 
 void OtDaemonServer::leaveInternal(bool aEraseDataset, const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    std::string message;
-    int         error = OT_ERROR_NONE;
+    if (GetOtInstance() == nullptr)
+    {
+        PropagateResult(OT_ERROR_INVALID_STATE, "OT is not initialized", aReceiver);
+    }
+    else
+    {
+        LeaveGracefully(aEraseDataset, "leave", [aReceiver]() { PropagateResult(OT_ERROR_NONE, "", aReceiver); });
+    }
+}
 
-    VerifyOrExit(GetOtInstance() != nullptr, error = OT_ERROR_INVALID_STATE, message = "OT is not initialized");
+void OtDaemonServer::LeaveGracefully(bool aEraseDataset, const std::string &aCallerTag, const LeaveCallback &aCallback)
+{
+    otOperationalDatasetTlvs curDatasetTlvs;
 
-    VerifyOrExit(mState.threadEnabled != OT_STATE_DISABLING, error = OT_ERROR_BUSY, message = "Thread is disabling");
+    VerifyOrDie(GetOtInstance() != nullptr, "OT is not initialized");
 
-    if (mState.threadEnabled == OT_STATE_DISABLED)
+    if (otThreadGetDeviceRole(GetOtInstance()) != OT_DEVICE_ROLE_DISABLED)
     {
-        FinishLeave(aEraseDataset, aReceiver);
+        otbrLogInfo("Start graceful leave...");
+
+        mLeaveCallbacks.push_back([aEraseDataset, aCallerTag, aCallback, this]() {
+            assert(otThreadGetDeviceRole(GetOtInstance()) == OT_DEVICE_ROLE_DISABLED);
+            LeaveGracefully(aEraseDataset, aCallerTag, aCallback);
+        });
+
+        // Ignores the OT_ERROR_BUSY error if a detach has already been requested.
+        // `otThreadDetachGracefully()` will invoke the `DetachGracefullyCallback`
+        // callabck in 0 seconds if this device role is detached or disabled. So
+        // `DetachGracefullyCallback` is guaranteed to be called in all cases
+        (void)otThreadDetachGracefully(GetOtInstance(), DetachGracefullyCallback, this);
         ExitNow();
     }
 
-    LeaveGracefully([aEraseDataset, aReceiver, this]() { FinishLeave(aEraseDataset, aReceiver); });
-
-exit:
-    if (error != OT_ERROR_NONE)
+    // Any join() or scheduleMigration() onging requests will be aborted
+    if (mJoinReceiver != nullptr)
     {
-        PropagateResult(error, message, aReceiver);
+        mJoinReceiver->onError(OT_ERROR_ABORT, "Aborted by a " + aCallerTag + " operation");
+        mJoinReceiver = nullptr;
     }
-}
 
-void OtDaemonServer::FinishLeave(bool aEraseDataset, const std::shared_ptr<IOtStatusReceiver> &aReceiver)
-{
-    if (aEraseDataset)
+    if (mMigrationReceiver != nullptr)
     {
-        (void)otInstanceErasePersistentInfo(GetOtInstance());
+        mMigrationReceiver->onError(OT_ERROR_ABORT, "Aborted by a " + aCallerTag + " operation");
+        mMigrationReceiver = nullptr;
     }
 
-    // TODO: b/323301831 - Re-init the Application class.
-    if (aReceiver != nullptr)
+    // It's not necessary to reset the OpenThread instance if it has no dataset
+    if (aEraseDataset && otDatasetGetActiveTlvs(GetOtInstance(), &curDatasetTlvs) == OT_ERROR_NONE)
     {
-        aReceiver->onSuccess();
+        SuccessOrDie(otInstanceErasePersistentInfo(GetOtInstance()), "Failed to erase persistent info");
+        mResetThreadHandler();
+
+        // The OtDaemonServer runtime states are outdated after
+        // the OT instances has been destroyed in `mResetThreadHandler`
+        ResetRuntimeStatesAfterLeave();
+
+        initializeInternal(mState.threadEnabled, mAndroidHost->GetConfiguration(), mINsdPublisher, mMeshcopTxts,
+                           mCountryCode, mTrelEnabled, mCallback);
     }
+
+    otbrLogInfo("Leave() is done");
+
+    aCallback();
+
+exit:
+    return;
 }
 
-void OtDaemonServer::LeaveGracefully(const LeaveCallback &aReceiver)
+void OtDaemonServer::ResetRuntimeStatesAfterLeave()
 {
-    mLeaveCallbacks.push_back(aReceiver);
+    bool threadEnabled = mState.threadEnabled;
+
+    assert(mJoinReceiver == nullptr);
+    assert(mMigrationReceiver == nullptr);
 
-    // Ignores the OT_ERROR_BUSY error if a detach has already been requested
-    (void)otThreadDetachGracefully(GetOtInstance(), DetachGracefullyCallback, this);
+    // The Thread Enabled state survives the leave() API call.
+    // This indicates that we should move the threadEnabled state
+    // out of the OtDaemonState class
+    mState               = OtDaemonState();
+    mState.threadEnabled = threadEnabled;
+
+    mOnMeshPrefixes.clear();
+    mEphemeralKeyExpiryMillis = 0;
 }
 
 void OtDaemonServer::DetachGracefullyCallback(void *aBinderServer)
@@ -1005,19 +1071,7 @@ void OtDaemonServer::DetachGracefullyCallback(void *aBinderServer)
 
 void OtDaemonServer::DetachGracefullyCallback(void)
 {
-    otbrLogInfo("detach success...");
-
-    if (mJoinReceiver != nullptr)
-    {
-        mJoinReceiver->onError(OT_ERROR_ABORT, "Aborted by leave/disable operation");
-        mJoinReceiver = nullptr;
-    }
-
-    if (mMigrationReceiver != nullptr)
-    {
-        mMigrationReceiver->onError(OT_ERROR_ABORT, "Aborted by leave/disable operation");
-        mMigrationReceiver = nullptr;
-    }
+    otbrLogInfo("DetachGracefully success...");
 
     for (auto &callback : mLeaveCallbacks)
     {
@@ -1112,7 +1166,12 @@ Status OtDaemonServer::setCountryCode(const std::string                        &
 void OtDaemonServer::setCountryCodeInternal(const std::string                        &aCountryCode,
                                             const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    mHost.SetCountryCode(aCountryCode, [aReceiver](otError aError, const std::string &aMessage) {
+    mHost.SetCountryCode(aCountryCode, [aReceiver, aCountryCode, this](otError aError, const std::string &aMessage) {
+        if (aError == OT_ERROR_NONE)
+        {
+            mCountryCode = aCountryCode;
+        }
+
         PropagateResult(aError, aMessage, aReceiver);
     });
 }
@@ -1148,13 +1207,13 @@ Status OtDaemonServer::setChannelMaxPowersInternal(const std::vector<ChannelMaxP
                                                    const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
     // Transform aidl ChannelMaxPower to ThreadHost::ChannelMaxPower
-    std::vector<Ncp::ThreadHost::ChannelMaxPower> channelMaxPowers(aChannelMaxPowers.size());
+    std::vector<Host::ThreadHost::ChannelMaxPower> channelMaxPowers(aChannelMaxPowers.size());
     std::transform(aChannelMaxPowers.begin(), aChannelMaxPowers.end(), channelMaxPowers.begin(),
                    [](const ChannelMaxPower &aChannelMaxPower) {
                        // INT_MIN indicates that the corresponding channel is disabled in Thread Android API
                        // `setChannelMaxPowers()` INT16_MAX indicates that the corresponding channel is disabled in
                        // OpenThread API `otPlatRadioSetChannelTargetPower()`.
-                       return Ncp::ThreadHost::ChannelMaxPower(
+                       return Host::ThreadHost::ChannelMaxPower(
                            aChannelMaxPower.channel,
                            aChannelMaxPower.maxPower == INT_MIN
                                ? INT16_MAX
@@ -1171,8 +1230,14 @@ Status OtDaemonServer::setChannelMaxPowersInternal(const std::vector<ChannelMaxP
 Status OtDaemonServer::setConfiguration(const OtDaemonConfiguration              &aConfiguration,
                                         const std::shared_ptr<IOtStatusReceiver> &aReceiver)
 {
-    mTaskRunner.Post(
-        [aConfiguration, aReceiver, this]() { mAndroidHost->SetConfiguration(aConfiguration, aReceiver); });
+    mTaskRunner.Post([aConfiguration, aReceiver, this]() {
+        if (aConfiguration != mAndroidHost->GetConfiguration())
+        {
+            mAdvProxy.SetAllowMlEid(!aConfiguration.borderRouterEnabled);
+            mBorderAgent.SetEnabled(mState.threadEnabled && aConfiguration.borderRouterEnabled);
+            mAndroidHost->SetConfiguration(aConfiguration, aReceiver);
+        }
+    });
 
     return Status::ok();
 }
diff --git a/src/android/otdaemon_server.hpp b/src/android/otdaemon_server.hpp
index 4aa7e817..2195e2fa 100644
--- a/src/android/otdaemon_server.hpp
+++ b/src/android/otdaemon_server.hpp
@@ -43,7 +43,8 @@
 #include "android/mdns_publisher.hpp"
 #include "common/mainloop.hpp"
 #include "common/time.hpp"
-#include "ncp/rcp_host.hpp"
+#include "host/rcp_host.hpp"
+#include "sdp_proxy/advertising_proxy.hpp"
 
 namespace otbr {
 namespace Android {
@@ -51,9 +52,13 @@ namespace Android {
 class OtDaemonServer : public BnOtDaemon, public MainloopProcessor, public vendor::VendorServer
 {
 public:
-    OtDaemonServer(otbr::Ncp::RcpHost    &aRcpHost,
-                   otbr::Mdns::Publisher &aMdnsPublisher,
-                   otbr::BorderAgent     &aBorderAgent);
+    using ResetThreadHandler = std::function<void()>;
+
+    OtDaemonServer(otbr::Host::RcpHost    &aRcpHost,
+                   otbr::Mdns::Publisher  &aMdnsPublisher,
+                   otbr::BorderAgent      &aBorderAgent,
+                   otbr::AdvertisingProxy &aAdvProxy,
+                   ResetThreadHandler      aResetThreadHandler);
     virtual ~OtDaemonServer(void) = default;
 
     // Disallow copy and assign.
@@ -109,8 +114,12 @@ private:
                 const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
     void   joinInternal(const std::vector<uint8_t>               &aActiveOpDatasetTlvs,
                         const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+
     Status leave(bool aEraseDataset, const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
     void   leaveInternal(bool aEraseDataset, const std::shared_ptr<IOtStatusReceiver> &aReceiver);
+    void   LeaveGracefully(bool aEraseDataset, const std::string &aCallerTag, const LeaveCallback &aReceiver);
+    void   ResetRuntimeStatesAfterLeave();
+
     Status scheduleMigration(const std::vector<uint8_t>               &aPendingOpDatasetTlvs,
                              const std::shared_ptr<IOtStatusReceiver> &aReceiver) override;
     void   scheduleMigrationInternal(const std::vector<uint8_t>               &aPendingOpDatasetTlvs,
@@ -154,8 +163,6 @@ private:
     void   deactivateEphemeralKeyModeInternal(const std::shared_ptr<IOtStatusReceiver> &aReceiver);
 
     bool        RefreshOtDaemonState(otChangedFlags aFlags);
-    void        LeaveGracefully(const LeaveCallback &aReceiver);
-    void        FinishLeave(bool aEraseDataset, const std::shared_ptr<IOtStatusReceiver> &aReceiver);
     static void DetachGracefullyCallback(void *aBinderServer);
     void        DetachGracefullyCallback(void);
     static void SendMgmtPendingSetCallback(otError aResult, void *aBinderServer);
@@ -183,20 +190,29 @@ private:
 
     static OtDaemonServer *sOtDaemonServer;
 
-    otbr::Ncp::RcpHost                &mHost;
+    // Class dependencies
+    otbr::Host::RcpHost               &mHost;
     std::unique_ptr<AndroidThreadHost> mAndroidHost;
     MdnsPublisher                     &mMdnsPublisher;
     otbr::BorderAgent                 &mBorderAgent;
-    std::shared_ptr<INsdPublisher>     mINsdPublisher;
-    MeshcopTxtAttributes               mMeshcopTxts;
+    otbr::AdvertisingProxy            &mAdvProxy;
+    ResetThreadHandler                 mResetThreadHandler;
     TaskRunner                         mTaskRunner;
+
+    // States initialized in initialize()
     ScopedFileDescriptor               mTunFd;
-    OtDaemonState                      mState;
+    std::shared_ptr<INsdPublisher>     mINsdPublisher;
+    MeshcopTxtAttributes               mMeshcopTxts;
+    std::string                        mCountryCode;
+    bool                               mTrelEnabled = false;
     std::shared_ptr<IOtDaemonCallback> mCallback;
     BinderDeathRecipient               mClientDeathRecipient;
+
+    // Runtime states
     std::shared_ptr<IOtStatusReceiver> mJoinReceiver;
     std::shared_ptr<IOtStatusReceiver> mMigrationReceiver;
     std::vector<LeaveCallback>         mLeaveCallbacks;
+    OtDaemonState                      mState;
     std::set<OnMeshPrefixConfig>       mOnMeshPrefixes;
     int64_t                            mEphemeralKeyExpiryMillis;
 
diff --git a/src/backbone_router/backbone_agent.cpp b/src/backbone_router/backbone_agent.cpp
index b2716e34..7ad54b8c 100644
--- a/src/backbone_router/backbone_agent.cpp
+++ b/src/backbone_router/backbone_agent.cpp
@@ -47,7 +47,7 @@
 namespace otbr {
 namespace BackboneRouter {
 
-BackboneAgent::BackboneAgent(otbr::Ncp::RcpHost &aHost, std::string aInterfaceName, std::string aBackboneInterfaceName)
+BackboneAgent::BackboneAgent(otbr::Host::RcpHost &aHost, std::string aInterfaceName, std::string aBackboneInterfaceName)
     : mHost(aHost)
     , mBackboneRouterState(OT_BACKBONE_ROUTER_STATE_DISABLED)
 #if OTBR_ENABLE_DUA_ROUTING
diff --git a/src/backbone_router/backbone_agent.hpp b/src/backbone_router/backbone_agent.hpp
index 9f1d1884..2477b0e6 100644
--- a/src/backbone_router/backbone_agent.hpp
+++ b/src/backbone_router/backbone_agent.hpp
@@ -47,7 +47,7 @@
 #include "backbone_router/dua_routing_manager.hpp"
 #include "backbone_router/nd_proxy.hpp"
 #include "common/code_utils.hpp"
-#include "ncp/rcp_host.hpp"
+#include "host/rcp_host.hpp"
 
 namespace otbr {
 namespace BackboneRouter {
@@ -74,7 +74,7 @@ public:
      *
      * @param[in] aHost  The Thread controller instance.
      */
-    BackboneAgent(otbr::Ncp::RcpHost &aHost, std::string aInterfaceName, std::string aBackboneInterfaceName);
+    BackboneAgent(otbr::Host::RcpHost &aHost, std::string aInterfaceName, std::string aBackboneInterfaceName);
 
     /**
      * This method initializes the Backbone agent.
@@ -101,7 +101,7 @@ private:
 
     static const char *StateToString(otBackboneRouterState aState);
 
-    otbr::Ncp::RcpHost   &mHost;
+    otbr::Host::RcpHost  &mHost;
     otBackboneRouterState mBackboneRouterState;
     Ip6Prefix             mDomainPrefix;
 #if OTBR_ENABLE_DUA_ROUTING
diff --git a/src/backbone_router/dua_routing_manager.hpp b/src/backbone_router/dua_routing_manager.hpp
index 54d76998..f5c5ab52 100644
--- a/src/backbone_router/dua_routing_manager.hpp
+++ b/src/backbone_router/dua_routing_manager.hpp
@@ -31,8 +31,8 @@
  *   This file includes definition for DUA routing functionalities.
  */
 
-#ifndef BACKBONE_ROUTER_DUA_ROUTING_MANAGER
-#define BACKBONE_ROUTER_DUA_ROUTING_MANAGER
+#ifndef BACKBONE_ROUTER_DUA_ROUTING_MANAGER_HPP_
+#define BACKBONE_ROUTER_DUA_ROUTING_MANAGER_HPP_
 
 #include "openthread-br/config.h"
 
@@ -43,7 +43,7 @@
 #include <openthread/backbone_router_ftd.h>
 
 #include "common/code_utils.hpp"
-#include "ncp/rcp_host.hpp"
+#include "host/rcp_host.hpp"
 #include "utils/system_utils.hpp"
 
 namespace otbr {
@@ -105,4 +105,4 @@ private:
 
 #endif // OTBR_ENABLE_DUA_ROUTING
 
-#endif // BACKBONE_ROUTER_DUA_ROUTING_MANAGER
+#endif // BACKBONE_ROUTER_DUA_ROUTING_MANAGER_HPP_
diff --git a/src/backbone_router/nd_proxy.hpp b/src/backbone_router/nd_proxy.hpp
index 1a6690cb..45450cdb 100644
--- a/src/backbone_router/nd_proxy.hpp
+++ b/src/backbone_router/nd_proxy.hpp
@@ -31,8 +31,8 @@
  *   This file includes definition for ICMPv6 Neighbor Advertisement (ND) proxy management.
  */
 
-#ifndef ND_PROXY_HPP_
-#define ND_PROXY_HPP_
+#ifndef BACKBONE_ROUTER_ND_PROXY_HPP_
+#define BACKBONE_ROUTER_ND_PROXY_HPP_
 
 #include "openthread-br/config.h"
 
@@ -55,7 +55,7 @@
 #include "common/code_utils.hpp"
 #include "common/mainloop.hpp"
 #include "common/types.hpp"
-#include "ncp/rcp_host.hpp"
+#include "host/rcp_host.hpp"
 
 namespace otbr {
 namespace BackboneRouter {
@@ -78,7 +78,7 @@ public:
     /**
      * This constructor initializes a NdProxyManager instance.
      */
-    explicit NdProxyManager(otbr::Ncp::RcpHost &aHost, std::string aBackboneInterfaceName)
+    explicit NdProxyManager(otbr::Host::RcpHost &aHost, std::string aBackboneInterfaceName)
         : mHost(aHost)
         , mBackboneInterfaceName(std::move(aBackboneInterfaceName))
         , mIcmp6RawSock(-1)
@@ -146,7 +146,7 @@ private:
                                     void                *aContext);
     int HandleNetfilterQueue(struct nfq_q_handle *aNfQueueHandler, struct nfgenmsg *aNfMsg, struct nfq_data *aNfData);
 
-    otbr::Ncp::RcpHost  &mHost;
+    otbr::Host::RcpHost &mHost;
     std::string          mBackboneInterfaceName;
     std::set<Ip6Address> mNdProxySet;
     uint32_t             mBackboneIfIndex;
@@ -166,4 +166,4 @@ private:
 } // namespace otbr
 
 #endif // OTBR_ENABLE_DUA_ROUTING
-#endif // ND_PROXY_HPP_
+#endif // BACKBONE_ROUTER_ND_PROXY_HPP_
diff --git a/src/border_agent/border_agent.cpp b/src/border_agent/border_agent.cpp
index 47283972..c778af03 100644
--- a/src/border_agent/border_agent.cpp
+++ b/src/border_agent/border_agent.cpp
@@ -59,7 +59,7 @@
 #include <openthread/platform/toolchain.h>
 
 #include "agent/uris.hpp"
-#include "ncp/rcp_host.hpp"
+#include "host/rcp_host.hpp"
 #if OTBR_ENABLE_BACKBONE_ROUTER
 #include "backbone_router/backbone_agent.hpp"
 #endif
@@ -156,17 +156,22 @@ struct StateBitmap
     }
 };
 
-BorderAgent::BorderAgent(otbr::Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher)
+BorderAgent::BorderAgent(otbr::Host::RcpHost &aHost, Mdns::Publisher &aPublisher)
     : mHost(aHost)
     , mPublisher(aPublisher)
-    , mIsEnabled(false)
-    , mIsEphemeralKeyEnabled(otThreadGetVersion() >= OT_THREAD_VERSION_1_4)
-    , mVendorName(OTBR_VENDOR_NAME)
-    , mProductName(OTBR_PRODUCT_NAME)
-    , mBaseServiceInstanceName(OTBR_MESHCOP_SERVICE_INSTANCE_NAME)
 {
-    mHost.AddThreadStateChangedCallback([this](otChangedFlags aFlags) { HandleThreadStateChanged(aFlags); });
+    ClearState();
+}
+
+void BorderAgent::Init(void)
+{
     otbrLogInfo("Ephemeral Key is: %s during initialization", (mIsEphemeralKeyEnabled ? "enabled" : "disabled"));
+    mHost.AddThreadStateChangedCallback([this](otChangedFlags aFlags) { HandleThreadStateChanged(aFlags); });
+}
+
+void BorderAgent::Deinit(void)
+{
+    ClearState();
 }
 
 otbrError BorderAgent::CreateEphemeralKey(std::string &aEphemeralKey)
@@ -250,10 +255,10 @@ void BorderAgent::SetEphemeralKeyEnabled(bool aIsEnabled)
 
     if (!mIsEphemeralKeyEnabled)
     {
-        // If the ePSKc feature is enabled, we call the clear function which
+        // If the ePSKc feature is enabled, we call the stop function which
         // will wait for the session to close if it is in active use before
         // removing ephemeral key and unpublishing the service.
-        otBorderAgentClearEphemeralKey(mHost.GetInstance());
+        otBorderAgentEphemeralKeyStop(mHost.GetInstance());
     }
 
     UpdateMeshCopService();
@@ -262,6 +267,19 @@ exit:
     return;
 }
 
+void BorderAgent::ClearState(void)
+{
+    mIsEnabled             = false;
+    mIsEphemeralKeyEnabled = (otThreadGetVersion() >= OT_THREAD_VERSION_1_4);
+    mMeshCopTxtUpdate.clear();
+    mVendorOui.clear();
+    mVendorName              = OTBR_VENDOR_NAME;
+    mProductName             = OTBR_PRODUCT_NAME;
+    mBaseServiceInstanceName = OTBR_MESHCOP_SERVICE_INSTANCE_NAME;
+    mServiceInstanceName.clear();
+    mEphemeralKeyChangedCallbacks.clear();
+}
+
 void BorderAgent::Start(void)
 {
     otbrLogInfo("Start Thread Border Agent");
@@ -281,7 +299,7 @@ void BorderAgent::Start(void)
     mServiceInstanceName = GetServiceInstanceNameWithExtAddr(mBaseServiceInstanceName);
     UpdateMeshCopService();
 
-    otBorderAgentSetEphemeralKeyCallback(mHost.GetInstance(), BorderAgent::HandleEpskcStateChanged, this);
+    otBorderAgentEphemeralKeySetCallback(mHost.GetInstance(), BorderAgent::HandleEpskcStateChanged, this);
 }
 
 void BorderAgent::Stop(void)
@@ -292,18 +310,25 @@ void BorderAgent::Stop(void)
 
 void BorderAgent::HandleEpskcStateChanged(void *aContext)
 {
-    BorderAgent *borderAgent = static_cast<BorderAgent *>(aContext);
+    static_cast<BorderAgent *>(aContext)->HandleEpskcStateChanged();
+}
 
-    if (otBorderAgentIsEphemeralKeyActive(borderAgent->mHost.GetInstance()))
-    {
-        borderAgent->PublishEpskcService();
-    }
-    else
+void BorderAgent::HandleEpskcStateChanged(void)
+{
+    switch (otBorderAgentEphemeralKeyGetState(mHost.GetInstance()))
     {
-        borderAgent->UnpublishEpskcService();
+    case OT_BORDER_AGENT_STATE_STARTED:
+    case OT_BORDER_AGENT_STATE_CONNECTED:
+    case OT_BORDER_AGENT_STATE_ACCEPTED:
+        PublishEpskcService();
+        break;
+    case OT_BORDER_AGENT_STATE_DISABLED:
+    case OT_BORDER_AGENT_STATE_STOPPED:
+        UnpublishEpskcService();
+        break;
     }
 
-    for (auto &ephemeralKeyCallback : borderAgent->mEphemeralKeyChangedCallbacks)
+    for (auto &ephemeralKeyCallback : mEphemeralKeyChangedCallbacks)
     {
         ephemeralKeyCallback();
     }
@@ -312,7 +337,7 @@ void BorderAgent::HandleEpskcStateChanged(void *aContext)
 void BorderAgent::PublishEpskcService()
 {
     otInstance *instance = mHost.GetInstance();
-    int         port     = otBorderAgentGetUdpPort(instance);
+    int         port     = otBorderAgentEphemeralKeyGetUdpPort(instance);
 
     otbrLogInfo("Publish meshcop-e service %s.%s.local. port %d", mServiceInstanceName.c_str(),
                 kBorderAgentEpskcServiceType, port);
@@ -583,7 +608,7 @@ void BorderAgent::PublishMeshCopService(void)
 
     AppendVendorTxtEntries(mMeshCopTxtUpdate, txtList);
 
-    if (otBorderAgentGetState(instance) != OT_BORDER_AGENT_STATE_STOPPED)
+    if (otBorderAgentIsActive(instance))
     {
         port = otBorderAgentGetUdpPort(instance);
     }
diff --git a/src/border_agent/border_agent.hpp b/src/border_agent/border_agent.hpp
index ed9686f4..fddeb79c 100644
--- a/src/border_agent/border_agent.hpp
+++ b/src/border_agent/border_agent.hpp
@@ -43,8 +43,8 @@
 #include "backbone_router/backbone_agent.hpp"
 #include "common/code_utils.hpp"
 #include "common/mainloop.hpp"
+#include "host/rcp_host.hpp"
 #include "mdns/mdns.hpp"
-#include "ncp/rcp_host.hpp"
 #include "sdp_proxy/advertising_proxy.hpp"
 #include "sdp_proxy/discovery_proxy.hpp"
 #include "trel_dnssd/trel_dnssd.hpp"
@@ -75,7 +75,7 @@ namespace otbr {
 /**
  * This class implements Thread border agent functionality.
  */
-class BorderAgent : private NonCopyable
+class BorderAgent : public Mdns::StateObserver, private NonCopyable
 {
 public:
     /** The callback for receiving ephemeral key changes. */
@@ -87,10 +87,20 @@ public:
      * @param[in] aHost       A reference to the Thread controller.
      * @param[in] aPublisher  A reference to the mDNS Publisher.
      */
-    BorderAgent(otbr::Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher);
+    BorderAgent(otbr::Host::RcpHost &aHost, Mdns::Publisher &aPublisher);
 
     ~BorderAgent(void) = default;
 
+    /**
+     * Initializes the Thread Border Agent.
+     */
+    void Init(void);
+
+    /**
+     * Deinitializes the Thread Border Agent.
+     */
+    void Deinit(void);
+
     /**
      * Overrides MeshCoP service (i.e. _meshcop._udp) instance name, product name, vendor name and vendor OUI.
      *
@@ -139,7 +149,7 @@ public:
      *
      * @param[in] aState  The state of mDNS publisher.
      */
-    void HandleMdnsState(Mdns::Publisher::State aState);
+    void HandleMdnsState(Mdns::Publisher::State aState) override;
 
     /**
      * This method creates ephemeral key in the Border Agent.
@@ -160,6 +170,7 @@ public:
     void AddEphemeralKeyChangedCallback(EphemeralKeyChangedCallback aCallback);
 
 private:
+    void ClearState(void);
     void Start(void);
     void Stop(void);
     bool IsEnabled(void) const { return mIsEnabled; }
@@ -177,13 +188,14 @@ private:
     std::string GetAlternativeServiceInstanceName() const;
 
     static void HandleEpskcStateChanged(void *aContext);
+    void        HandleEpskcStateChanged(void);
     void        PublishEpskcService(void);
     void        UnpublishEpskcService(void);
 
-    otbr::Ncp::RcpHost &mHost;
-    Mdns::Publisher    &mPublisher;
-    bool                mIsEnabled;
-    bool                mIsEphemeralKeyEnabled;
+    otbr::Host::RcpHost &mHost;
+    Mdns::Publisher     &mPublisher;
+    bool                 mIsEnabled;
+    bool                 mIsEphemeralKeyEnabled;
 
     std::map<std::string, std::vector<uint8_t>> mMeshCopTxtUpdate;
 
diff --git a/src/common/api_strings.cpp b/src/common/api_strings.cpp
index 77fee923..9a392c0a 100644
--- a/src/common/api_strings.cpp
+++ b/src/common/api_strings.cpp
@@ -28,6 +28,8 @@
 
 #include "common/api_strings.hpp"
 
+#include <openthread/instance.h>
+
 std::string GetDeviceRoleName(otDeviceRole aRole)
 {
     std::string roleName;
@@ -70,8 +72,33 @@ std::string GetDhcp6PdStateName(otBorderRoutingDhcp6PdState aState)
     case OT_BORDER_ROUTING_DHCP6_PD_STATE_RUNNING:
         stateName = OTBR_DHCP6_PD_STATE_NAME_RUNNING;
         break;
+#if OPENTHREAD_API_VERSION >= 451
+    case OT_BORDER_ROUTING_DHCP6_PD_STATE_IDLE:
+        stateName = OTBR_DHCP6_PD_STATE_NAME_IDLE;
+        break;
+#endif
     }
 
     return stateName;
 }
 #endif // OTBR_ENABLE_DHCP6_PD
+
+std::string GetCommissionerStateName(otCommissionerState aState)
+{
+    std::string stateName;
+
+    switch (aState)
+    {
+    case OT_COMMISSIONER_STATE_DISABLED:
+        stateName = OTBR_COMMISSIONER_STATE_NAME_DISABLED;
+        break;
+    case OT_COMMISSIONER_STATE_PETITION:
+        stateName = OTBR_COMMISSIONER_STATE_NAME_PETITION;
+        break;
+    case OT_COMMISSIONER_STATE_ACTIVE:
+        stateName = OTBR_COMMISSIONER_STATE_NAME_ACTIVE;
+        break;
+    }
+
+    return stateName;
+}
diff --git a/src/common/api_strings.hpp b/src/common/api_strings.hpp
index 7093e049..c63ea5d0 100644
--- a/src/common/api_strings.hpp
+++ b/src/common/api_strings.hpp
@@ -51,12 +51,19 @@
 #define OTBR_DHCP6_PD_STATE_NAME_DISABLED "disabled"
 #define OTBR_DHCP6_PD_STATE_NAME_STOPPED "stopped"
 #define OTBR_DHCP6_PD_STATE_NAME_RUNNING "running"
+#define OTBR_DHCP6_PD_STATE_NAME_IDLE "idle"
 #endif
 
+#define OTBR_COMMISSIONER_STATE_NAME_DISABLED "disabled"
+#define OTBR_COMMISSIONER_STATE_NAME_PETITION "petitioning"
+#define OTBR_COMMISSIONER_STATE_NAME_ACTIVE "active"
+
 std::string GetDeviceRoleName(otDeviceRole aRole);
 
 #if OTBR_ENABLE_DHCP6_PD
 std::string GetDhcp6PdStateName(otBorderRoutingDhcp6PdState aDhcp6PdState);
 #endif // OTBR_ENABLE_DHCP6_PD
 
+std::string GetCommissionerStateName(otCommissionerState aState);
+
 #endif // OTBR_COMMON_API_STRINGS_HPP_
diff --git a/src/common/mainloop_manager.hpp b/src/common/mainloop_manager.hpp
index f379e2df..212e95b0 100644
--- a/src/common/mainloop_manager.hpp
+++ b/src/common/mainloop_manager.hpp
@@ -42,7 +42,7 @@
 
 #include "common/code_utils.hpp"
 #include "common/mainloop.hpp"
-#include "ncp/rcp_host.hpp"
+#include "host/rcp_host.hpp"
 
 namespace otbr {
 
diff --git a/src/common/task_runner.cpp b/src/common/task_runner.cpp
index 28c715cd..a4dfc177 100644
--- a/src/common/task_runner.cpp
+++ b/src/common/task_runner.cpp
@@ -110,10 +110,10 @@ void TaskRunner::Update(MainloopContext &aMainloop)
 
 void TaskRunner::Process(const MainloopContext &aMainloop)
 {
-    OTBR_UNUSED_VARIABLE(aMainloop);
-
     ssize_t rval;
 
+    VerifyOrExit(FD_ISSET(mEventFd[kRead], &aMainloop.mReadFdSet));
+
     // Read any data in the pipe.
     do
     {
@@ -125,6 +125,7 @@ void TaskRunner::Process(const MainloopContext &aMainloop)
     // Critical error happens, simply die.
     VerifyOrDie(errno == EAGAIN || errno == EWOULDBLOCK, strerror(errno));
 
+exit:
     PopTasks();
 }
 
diff --git a/src/dbus/common/constants.hpp b/src/dbus/common/constants.hpp
index 0238bc55..6f8a6e65 100644
--- a/src/dbus/common/constants.hpp
+++ b/src/dbus/common/constants.hpp
@@ -48,6 +48,7 @@
 #define OTBR_DBUS_ENERGY_SCAN_METHOD "EnergyScan"
 #define OTBR_DBUS_ATTACH_METHOD "Attach"
 #define OTBR_DBUS_DETACH_METHOD "Detach"
+#define OTBR_DBUS_SET_THREAD_ENABLED_METHOD "SetThreadEnabled"
 #define OTBR_DBUS_JOIN_METHOD "Join"
 #define OTBR_DBUS_FACTORY_RESET_METHOD "FactoryReset"
 #define OTBR_DBUS_RESET_METHOD "Reset"
diff --git a/src/dbus/server/dbus_agent.cpp b/src/dbus/server/dbus_agent.cpp
index 6869971f..3cd30d17 100644
--- a/src/dbus/server/dbus_agent.cpp
+++ b/src/dbus/server/dbus_agent.cpp
@@ -46,7 +46,7 @@ namespace DBus {
 const struct timeval           DBusAgent::kPollTimeout = {0, 0};
 constexpr std::chrono::seconds DBusAgent::kDBusWaitAllowance;
 
-DBusAgent::DBusAgent(otbr::Ncp::ThreadHost &aHost, Mdns::Publisher &aPublisher)
+DBusAgent::DBusAgent(otbr::Host::ThreadHost &aHost, Mdns::Publisher &aPublisher)
     : mInterfaceName(aHost.GetInterfaceName())
     , mHost(aHost)
     , mPublisher(aPublisher)
@@ -71,12 +71,12 @@ void DBusAgent::Init(otbr::BorderAgent &aBorderAgent)
     {
     case OT_COPROCESSOR_RCP:
         mThreadObject = MakeUnique<DBusThreadObjectRcp>(*mConnection, mInterfaceName,
-                                                        static_cast<Ncp::RcpHost &>(mHost), &mPublisher, aBorderAgent);
+                                                        static_cast<Host::RcpHost &>(mHost), &mPublisher, aBorderAgent);
         break;
 
     case OT_COPROCESSOR_NCP:
         mThreadObject =
-            MakeUnique<DBusThreadObjectNcp>(*mConnection, mInterfaceName, static_cast<Ncp::NcpHost &>(mHost));
+            MakeUnique<DBusThreadObjectNcp>(*mConnection, mInterfaceName, static_cast<Host::NcpHost &>(mHost));
         break;
 
     default:
diff --git a/src/dbus/server/dbus_agent.hpp b/src/dbus/server/dbus_agent.hpp
index cd6793ef..2a68a6c2 100644
--- a/src/dbus/server/dbus_agent.hpp
+++ b/src/dbus/server/dbus_agent.hpp
@@ -48,7 +48,7 @@
 #include "dbus/server/dbus_object.hpp"
 #include "dbus/server/dbus_thread_object_ncp.hpp"
 #include "dbus/server/dbus_thread_object_rcp.hpp"
-#include "ncp/thread_host.hpp"
+#include "host/thread_host.hpp"
 
 namespace otbr {
 namespace DBus {
@@ -62,7 +62,7 @@ public:
      * @param[in] aHost           A reference to the Thread host.
      * @param[in] aPublisher      A reference to the MDNS publisher.
      */
-    DBusAgent(otbr::Ncp::ThreadHost &aHost, Mdns::Publisher &aPublisher);
+    DBusAgent(otbr::Host::ThreadHost &aHost, Mdns::Publisher &aPublisher);
 
     /**
      * This method initializes the dbus agent.
@@ -87,7 +87,7 @@ private:
     std::string                 mInterfaceName;
     std::unique_ptr<DBusObject> mThreadObject;
     UniqueDBusConnection        mConnection;
-    otbr::Ncp::ThreadHost      &mHost;
+    otbr::Host::ThreadHost     &mHost;
     Mdns::Publisher            &mPublisher;
 
     /**
diff --git a/src/dbus/server/dbus_thread_object_ncp.cpp b/src/dbus/server/dbus_thread_object_ncp.cpp
index 526a477f..104d936f 100644
--- a/src/dbus/server/dbus_thread_object_ncp.cpp
+++ b/src/dbus/server/dbus_thread_object_ncp.cpp
@@ -41,9 +41,9 @@ using std::placeholders::_2;
 namespace otbr {
 namespace DBus {
 
-DBusThreadObjectNcp::DBusThreadObjectNcp(DBusConnection     &aConnection,
-                                         const std::string  &aInterfaceName,
-                                         otbr::Ncp::NcpHost &aHost)
+DBusThreadObjectNcp::DBusThreadObjectNcp(DBusConnection      &aConnection,
+                                         const std::string   &aInterfaceName,
+                                         otbr::Host::NcpHost &aHost)
     : DBusObject(&aConnection, OTBR_DBUS_OBJECT_PREFIX + aInterfaceName)
     , mHost(aHost)
 {
@@ -125,7 +125,7 @@ exit:
 
 void DBusThreadObjectNcp::LeaveHandler(DBusRequest &aRequest)
 {
-    mHost.Leave([aRequest](otError aError, const std::string &aErrorInfo) mutable {
+    mHost.Leave(true /* aEraseDataset */, [aRequest](otError aError, const std::string &aErrorInfo) mutable {
         OT_UNUSED_VARIABLE(aErrorInfo);
         aRequest.ReplyOtResult(aError);
     });
diff --git a/src/dbus/server/dbus_thread_object_ncp.hpp b/src/dbus/server/dbus_thread_object_ncp.hpp
index 542dc260..9ecd0a0e 100644
--- a/src/dbus/server/dbus_thread_object_ncp.hpp
+++ b/src/dbus/server/dbus_thread_object_ncp.hpp
@@ -42,8 +42,8 @@
 #include <openthread/link.h>
 
 #include "dbus/server/dbus_object.hpp"
+#include "host/ncp_host.hpp"
 #include "mdns/mdns.hpp"
-#include "ncp/ncp_host.hpp"
 
 namespace otbr {
 namespace DBus {
@@ -67,7 +67,7 @@ public:
      * @param[in] aInterfaceName  The dbus interface name.
      * @param[in] aHost           The Thread controller.
      */
-    DBusThreadObjectNcp(DBusConnection &aConnection, const std::string &aInterfaceName, otbr::Ncp::NcpHost &aHost);
+    DBusThreadObjectNcp(DBusConnection &aConnection, const std::string &aInterfaceName, otbr::Host::NcpHost &aHost);
 
     /**
      * This method initializes the dbus thread object.
@@ -85,7 +85,7 @@ private:
     void LeaveHandler(DBusRequest &aRequest);
     void ScheduleMigrationHandler(DBusRequest &aRequest);
 
-    otbr::Ncp::NcpHost &mHost;
+    otbr::Host::NcpHost &mHost;
 };
 
 /**
diff --git a/src/dbus/server/dbus_thread_object_rcp.cpp b/src/dbus/server/dbus_thread_object_rcp.cpp
index ceaa07aa..a6a3aa3f 100644
--- a/src/dbus/server/dbus_thread_object_rcp.cpp
+++ b/src/dbus/server/dbus_thread_object_rcp.cpp
@@ -101,11 +101,11 @@ static std::string GetNat64StateName(otNat64State aState)
 namespace otbr {
 namespace DBus {
 
-DBusThreadObjectRcp::DBusThreadObjectRcp(DBusConnection     &aConnection,
-                                         const std::string  &aInterfaceName,
-                                         otbr::Ncp::RcpHost &aHost,
-                                         Mdns::Publisher    *aPublisher,
-                                         otbr::BorderAgent  &aBorderAgent)
+DBusThreadObjectRcp::DBusThreadObjectRcp(DBusConnection      &aConnection,
+                                         const std::string   &aInterfaceName,
+                                         otbr::Host::RcpHost &aHost,
+                                         Mdns::Publisher     *aPublisher,
+                                         otbr::BorderAgent   &aBorderAgent)
     : DBusObject(&aConnection, OTBR_DBUS_OBJECT_PREFIX + aInterfaceName)
     , mHost(aHost)
     , mPublisher(aPublisher)
@@ -121,7 +121,7 @@ otbrError DBusThreadObjectRcp::Init(void)
     SuccessOrExit(error = DBusObject::Initialize(false));
 
     threadHelper->AddDeviceRoleHandler(std::bind(&DBusThreadObjectRcp::DeviceRoleHandler, this, _1));
-#if OTBR_ENABLE_DHCP6_PD
+#if OTBR_ENABLE_DHCP6_PD && OTBR_ENABLE_BORDER_ROUTING
     threadHelper->SetDhcp6PdStateCallback(std::bind(&DBusThreadObjectRcp::Dhcp6PdStateHandler, this, _1));
 #endif
     threadHelper->AddActiveDatasetChangeHandler(std::bind(&DBusThreadObjectRcp::ActiveDatasetChangeHandler, this, _1));
@@ -159,6 +159,10 @@ otbrError DBusThreadObjectRcp::Init(void)
                    std::bind(&DBusThreadObjectRcp::UpdateMeshCopTxtHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_GET_PROPERTIES_METHOD,
                    std::bind(&DBusThreadObjectRcp::GetPropertiesHandler, this, _1));
+    RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_SET_THREAD_ENABLED_METHOD,
+                   std::bind(&DBusThreadObjectRcp::SetThreadEnabledHandler, this, _1));
+    RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_JOIN_METHOD,
+                   std::bind(&DBusThreadObjectRcp::JoinHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_LEAVE_NETWORK_METHOD,
                    std::bind(&DBusThreadObjectRcp::LeaveNetworkHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_SET_NAT64_ENABLED_METHOD,
@@ -477,7 +481,7 @@ void DBusThreadObjectRcp::FactoryResetHandler(DBusRequest &aRequest)
     otError error = OT_ERROR_NONE;
 
     SuccessOrExit(error = mHost.GetThreadHelper()->Detach());
-    SuccessOrExit(otInstanceErasePersistentInfo(mHost.GetThreadHelper()->GetInstance()));
+    SuccessOrExit(otInstanceErasePersistentInfo(mHost.GetInstance()));
     mHost.Reset();
 
 exit:
@@ -1450,7 +1454,7 @@ exit:
 otError DBusThreadObjectRcp::GetTrelInfoHandler(DBusMessageIter &aIter)
 {
 #if OTBR_ENABLE_TREL
-    auto           instance = mHost.GetThreadHelper()->GetInstance();
+    auto           instance = mHost.GetInstance();
     otError        error    = OT_ERROR_NONE;
     TrelInfo       trelInfo;
     otTrelCounters otTrelCounters = *otTrelGetCounters(instance);
@@ -1674,8 +1678,7 @@ otError DBusThreadObjectRcp::GetUptimeHandler(DBusMessageIter &aIter)
 {
     otError error = OT_ERROR_NONE;
 
-    VerifyOrExit(DBusMessageEncodeToVariant(&aIter, otInstanceGetUptime(mHost.GetThreadHelper()->GetInstance())) ==
-                     OTBR_ERROR_NONE,
+    VerifyOrExit(DBusMessageEncodeToVariant(&aIter, otInstanceGetUptime(mHost.GetInstance())) == OTBR_ERROR_NONE,
                  error = OT_ERROR_INVALID_ARGS);
 
 exit:
@@ -1760,6 +1763,52 @@ void DBusThreadObjectRcp::ActiveDatasetChangeHandler(const otOperationalDatasetT
     SignalPropertyChanged(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_ACTIVE_DATASET_TLVS, value);
 }
 
+void DBusThreadObjectRcp::SetThreadEnabledHandler(DBusRequest &aRequest)
+{
+    otError error  = OT_ERROR_NONE;
+    bool    enable = false;
+    auto    args   = std::tie(enable);
+
+    SuccessOrExit(DBusMessageToTuple(*aRequest.GetMessage(), args), error = OT_ERROR_INVALID_ARGS);
+
+    mHost.SetThreadEnabled(enable, [aRequest](otError aError, const std::string &aErrorInfo) mutable {
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
+void DBusThreadObjectRcp::JoinHandler(DBusRequest &aRequest)
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
 void DBusThreadObjectRcp::LeaveNetworkHandler(DBusRequest &aRequest)
 {
     constexpr int kExitCodeShouldRestart = 7;
@@ -1767,7 +1816,7 @@ void DBusThreadObjectRcp::LeaveNetworkHandler(DBusRequest &aRequest)
     mHost.GetThreadHelper()->DetachGracefully([aRequest, this](otError error) mutable {
         SuccessOrExit(error);
         mPublisher->Stop();
-        SuccessOrExit(error = otInstanceErasePersistentInfo(mHost.GetThreadHelper()->GetInstance()));
+        SuccessOrExit(error = otInstanceErasePersistentInfo(mHost.GetInstance()));
 
     exit:
         aRequest.ReplyOtResult(error);
@@ -1787,7 +1836,7 @@ void DBusThreadObjectRcp::SetNat64Enabled(DBusRequest &aRequest)
     auto    args = std::tie(enable);
 
     VerifyOrExit(DBusMessageToTuple(*aRequest.GetMessage(), args) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
-    otNat64SetEnabled(mHost.GetThreadHelper()->GetInstance(), enable);
+    otNat64SetEnabled(mHost.GetInstance(), enable);
 
 exit:
     aRequest.ReplyOtResult(error);
@@ -1799,8 +1848,8 @@ otError DBusThreadObjectRcp::GetNat64State(DBusMessageIter &aIter)
 
     Nat64ComponentState state;
 
-    state.mPrefixManagerState = GetNat64StateName(otNat64GetPrefixManagerState(mHost.GetThreadHelper()->GetInstance()));
-    state.mTranslatorState    = GetNat64StateName(otNat64GetTranslatorState(mHost.GetThreadHelper()->GetInstance()));
+    state.mPrefixManagerState = GetNat64StateName(otNat64GetPrefixManagerState(mHost.GetInstance()));
+    state.mTranslatorState    = GetNat64StateName(otNat64GetTranslatorState(mHost.GetInstance()));
 
     VerifyOrExit(DBusMessageEncodeToVariant(&aIter, state) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
 
@@ -1817,8 +1866,8 @@ otError DBusThreadObjectRcp::GetNat64Mappings(DBusMessageIter &aIter)
     otNat64AddressMapping            otMapping;
     Nat64AddressMapping              mapping;
 
-    otNat64InitAddressMappingIterator(mHost.GetThreadHelper()->GetInstance(), &iterator);
-    while (otNat64GetNextAddressMapping(mHost.GetThreadHelper()->GetInstance(), &iterator, &otMapping) == OT_ERROR_NONE)
+    otNat64InitAddressMappingIterator(mHost.GetInstance(), &iterator);
+    while (otNat64GetNextAddressMapping(mHost.GetInstance(), &iterator, &otMapping) == OT_ERROR_NONE)
     {
         mapping.mId = otMapping.mId;
         std::copy(std::begin(otMapping.mIp4.mFields.m8), std::end(otMapping.mIp4.mFields.m8), mapping.mIp4.data());
@@ -1860,7 +1909,7 @@ otError DBusThreadObjectRcp::GetNat64ProtocolCounters(DBusMessageIter &aIter)
 
     otNat64ProtocolCounters otCounters;
     Nat64ProtocolCounters   counters;
-    otNat64GetCounters(mHost.GetThreadHelper()->GetInstance(), &otCounters);
+    otNat64GetCounters(mHost.GetInstance(), &otCounters);
 
     counters.mTotal.m4To6Packets = otCounters.mTotal.m4To6Packets;
     counters.mTotal.m4To6Bytes   = otCounters.mTotal.m4To6Bytes;
@@ -1891,7 +1940,7 @@ otError DBusThreadObjectRcp::GetNat64ErrorCounters(DBusMessageIter &aIter)
 
     otNat64ErrorCounters otCounters;
     Nat64ErrorCounters   counters;
-    otNat64GetErrorCounters(mHost.GetThreadHelper()->GetInstance(), &otCounters);
+    otNat64GetErrorCounters(mHost.GetInstance(), &otCounters);
 
     counters.mUnknown.m4To6Packets          = otCounters.mCount4To6[OT_NAT64_DROP_REASON_UNKNOWN];
     counters.mUnknown.m6To4Packets          = otCounters.mCount6To4[OT_NAT64_DROP_REASON_UNKNOWN];
@@ -1915,7 +1964,7 @@ otError DBusThreadObjectRcp::GetNat64Cidr(DBusMessageIter &aIter)
     otIp4Cidr cidr;
     char      cidrString[OT_IP4_CIDR_STRING_SIZE];
 
-    SuccessOrExit(error = otNat64GetCidr(mHost.GetThreadHelper()->GetInstance(), &cidr));
+    SuccessOrExit(error = otNat64GetCidr(mHost.GetInstance(), &cidr));
     otIp4CidrToString(&cidr, cidrString, sizeof(cidrString));
 
     VerifyOrExit(DBusMessageEncodeToVariant(&aIter, std::string(cidrString)) == OTBR_ERROR_NONE,
@@ -1933,7 +1982,7 @@ otError DBusThreadObjectRcp::SetNat64Cidr(DBusMessageIter &aIter)
 
     VerifyOrExit(DBusMessageExtractFromVariant(&aIter, cidrString) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
     SuccessOrExit(error = otIp4CidrFromString(cidrString.c_str(), &cidr));
-    SuccessOrExit(error = otNat64SetIp4Cidr(mHost.GetThreadHelper()->GetInstance(), &cidr));
+    SuccessOrExit(error = otNat64SetIp4Cidr(mHost.GetInstance(), &cidr));
 
 exit:
     return error;
@@ -2009,8 +2058,33 @@ void DBusThreadObjectRcp::DeactivateEphemeralKeyModeHandler(DBusRequest &aReques
 {
     otError error        = OT_ERROR_NONE;
     auto    threadHelper = mHost.GetThreadHelper();
+    bool    retain_active_session;
+    auto    args = std::tie(retain_active_session);
+
+    VerifyOrExit(mBorderAgent.GetEphemeralKeyEnabled(), error = OT_ERROR_NOT_CAPABLE);
 
-    otBorderAgentClearEphemeralKey(threadHelper->GetInstance());
+    SuccessOrExit(DBusMessageToTuple(*aRequest.GetMessage(), args), error = OT_ERROR_INVALID_ARGS);
+
+    // Stop the ephemeral key use if
+    //  - there is no active session, or
+    //  - there is a connected session and we should not `retain_active_session`.
+
+    switch (otBorderAgentEphemeralKeyGetState(threadHelper->GetInstance()))
+    {
+    case OT_BORDER_AGENT_STATE_STARTED:
+        break;
+    case OT_BORDER_AGENT_STATE_CONNECTED:
+    case OT_BORDER_AGENT_STATE_ACCEPTED:
+        VerifyOrExit(!retain_active_session);
+        break;
+    case OT_BORDER_AGENT_STATE_DISABLED:
+    case OT_BORDER_AGENT_STATE_STOPPED:
+        ExitNow();
+    }
+
+    otBorderAgentEphemeralKeyStop(threadHelper->GetInstance());
+
+exit:
     aRequest.ReplyOtResult(error);
 }
 
@@ -2022,13 +2096,16 @@ void DBusThreadObjectRcp::ActivateEphemeralKeyModeHandler(DBusRequest &aRequest)
     auto        args         = std::tie(lifetime);
     std::string ePskc;
 
+    VerifyOrExit(mBorderAgent.GetEphemeralKeyEnabled(), error = OT_ERROR_NOT_CAPABLE);
+
     SuccessOrExit(DBusMessageToTuple(*aRequest.GetMessage(), args), error = OT_ERROR_INVALID_ARGS);
+    VerifyOrExit(lifetime <= OT_BORDER_AGENT_MAX_EPHEMERAL_KEY_TIMEOUT, error = OT_ERROR_INVALID_ARGS);
 
     SuccessOrExit(mBorderAgent.CreateEphemeralKey(ePskc), error = OT_ERROR_INVALID_ARGS);
     otbrLogInfo("Created Ephemeral Key: %s", ePskc.c_str());
 
-    SuccessOrExit(error = otBorderAgentSetEphemeralKey(threadHelper->GetInstance(), ePskc.c_str(), lifetime,
-                                                       OTBR_CONFIG_BORDER_AGENT_MESHCOP_E_UDP_PORT));
+    SuccessOrExit(error = otBorderAgentEphemeralKeyStart(threadHelper->GetInstance(), ePskc.c_str(), lifetime,
+                                                         OTBR_CONFIG_BORDER_AGENT_MESHCOP_E_UDP_PORT));
 
 exit:
     if (error == OT_ERROR_NONE)
@@ -2078,7 +2155,7 @@ otError DBusThreadObjectRcp::SetDnsUpstreamQueryState(DBusMessageIter &aIter)
     bool    enable;
 
     VerifyOrExit(DBusMessageExtractFromVariant(&aIter, enable) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
-    otDnssdUpstreamQuerySetEnabled(mHost.GetThreadHelper()->GetInstance(), enable);
+    otDnssdUpstreamQuerySetEnabled(mHost.GetInstance(), enable);
 
 exit:
     return error;
@@ -2094,8 +2171,8 @@ otError DBusThreadObjectRcp::GetDnsUpstreamQueryState(DBusMessageIter &aIter)
 #if OTBR_ENABLE_DNS_UPSTREAM_QUERY
     otError error = OT_ERROR_NONE;
 
-    VerifyOrExit(DBusMessageEncodeToVariant(
-                     &aIter, otDnssdUpstreamQueryIsEnabled(mHost.GetThreadHelper()->GetInstance())) == OTBR_ERROR_NONE,
+    VerifyOrExit(DBusMessageEncodeToVariant(&aIter, otDnssdUpstreamQueryIsEnabled(mHost.GetInstance())) ==
+                     OTBR_ERROR_NONE,
                  error = OT_ERROR_INVALID_ARGS);
 
 exit:
diff --git a/src/dbus/server/dbus_thread_object_rcp.hpp b/src/dbus/server/dbus_thread_object_rcp.hpp
index 7e55907b..67891bc2 100644
--- a/src/dbus/server/dbus_thread_object_rcp.hpp
+++ b/src/dbus/server/dbus_thread_object_rcp.hpp
@@ -42,8 +42,8 @@
 
 #include "border_agent/border_agent.hpp"
 #include "dbus/server/dbus_object.hpp"
+#include "host/rcp_host.hpp"
 #include "mdns/mdns.hpp"
-#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 namespace DBus {
@@ -69,11 +69,11 @@ public:
      * @param[in] aPublisher      The Mdns::Publisher
      * @param[in] aBorderAgent    The Border Agent
      */
-    DBusThreadObjectRcp(DBusConnection     &aConnection,
-                        const std::string  &aInterfaceName,
-                        otbr::Ncp::RcpHost &aHost,
-                        Mdns::Publisher    *aPublisher,
-                        otbr::BorderAgent  &aBorderAgent);
+    DBusThreadObjectRcp(DBusConnection      &aConnection,
+                        const std::string   &aInterfaceName,
+                        otbr::Host::RcpHost &aHost,
+                        Mdns::Publisher     *aPublisher,
+                        otbr::BorderAgent   &aBorderAgent);
 
     otbrError Init(void) override;
 
@@ -103,6 +103,8 @@ private:
     void AddExternalRouteHandler(DBusRequest &aRequest);
     void RemoveExternalRouteHandler(DBusRequest &aRequest);
     void UpdateMeshCopTxtHandler(DBusRequest &aRequest);
+    void SetThreadEnabledHandler(DBusRequest &aRequest);
+    void JoinHandler(DBusRequest &aRequest);
     void GetPropertiesHandler(DBusRequest &aRequest);
     void LeaveNetworkHandler(DBusRequest &aRequest);
     void SetNat64Enabled(DBusRequest &aRequest);
@@ -181,7 +183,7 @@ private:
     void ReplyScanResult(DBusRequest &aRequest, otError aError, const std::vector<otActiveScanResult> &aResult);
     void ReplyEnergyScanResult(DBusRequest &aRequest, otError aError, const std::vector<otEnergyScanResult> &aResult);
 
-    otbr::Ncp::RcpHost                                  &mHost;
+    otbr::Host::RcpHost                                 &mHost;
     std::unordered_map<std::string, PropertyHandlerType> mGetPropertyHandlers;
     otbr::Mdns::Publisher                               *mPublisher;
     otbr::BorderAgent                                   &mBorderAgent;
diff --git a/src/dbus/server/introspect.xml b/src/dbus/server/introspect.xml
index 21b358e5..449dee38 100644
--- a/src/dbus/server/introspect.xml
+++ b/src/dbus/server/introspect.xml
@@ -237,7 +237,8 @@
 
     <!-- ActivateEphemeralKeyMode: Activate ePSKc mode.
       @lifetime: in milliseconds, duration of active ePSKc mode before secure session is established.
-                 0 for OT_BORDER_AGENT_DEFAULT_EPHEMERAL_KEY_TIMEOUT (2 min).
+                 0 for OT_BORDER_AGENT_DEFAULT_EPHEMERAL_KEY_TIMEOUT (2 min). Valid value is [0,
+                 OT_BORDER_AGENT_MAX_EPHEMERAL_KEY_TIMEOUT (10 min)].
       @epskc: returns the ephemeral key digit string of length 9 with first 8 digits randomly generated,
               and the last digit as verhoeff checksum.
     -->
@@ -246,8 +247,15 @@
       <arg name="epskc" type="s" direction="out"/>
     </method>
 
-    <!-- DeactivateEphemeralKeyMode: Deactivate ePSKc mode. -->
+    <!-- DeactivateEphemeralKeyMode: Deactivate ePSKc mode.
+      @retain_active_session: 
+        "false" - Disconnects the Border Agent from any active secure sessions.
+                  Ephemeral key would be cleared after the session is disconnected.
+        "true" - Deactivate ephemeral key mode softly. If there is already an active commissioner
+                 connection, the session will be retained and the ephemeral key mode is still active.
+    -->
     <method name="DeactivateEphemeralKeyMode">
+      <arg name="retain_active_session" type="b" direction="in"/>
     </method>
 
     <!-- MeshLocalPrefix: The /64 mesh-local prefix.  -->
diff --git a/src/ncp/CMakeLists.txt b/src/host/CMakeLists.txt
similarity index 100%
rename from src/ncp/CMakeLists.txt
rename to src/host/CMakeLists.txt
diff --git a/src/ncp/async_task.cpp b/src/host/async_task.cpp
similarity index 98%
rename from src/ncp/async_task.cpp
rename to src/host/async_task.cpp
index 94827d80..6b401cd2 100644
--- a/src/ncp/async_task.cpp
+++ b/src/host/async_task.cpp
@@ -34,7 +34,7 @@
 #include "common/code_utils.hpp"
 
 namespace otbr {
-namespace Ncp {
+namespace Host {
 
 AsyncTask::AsyncTask(const ResultHandler &aResultHandler)
     : mResultHandler(aResultHandler)
@@ -95,5 +95,5 @@ AsyncTaskPtr &AsyncTask::Then(const ThenHandler &aThen)
     return mNext;
 }
 
-} // namespace Ncp
+} // namespace Host
 } // namespace otbr
diff --git a/src/ncp/async_task.hpp b/src/host/async_task.hpp
similarity index 99%
rename from src/ncp/async_task.hpp
rename to src/host/async_task.hpp
index 371f1fa7..1f901ed0 100644
--- a/src/ncp/async_task.hpp
+++ b/src/host/async_task.hpp
@@ -41,7 +41,7 @@
 #include <openthread/error.h>
 
 namespace otbr {
-namespace Ncp {
+namespace Host {
 
 class AsyncTask;
 using AsyncTaskPtr = std::shared_ptr<AsyncTask>;
@@ -108,7 +108,7 @@ private:
     AsyncTaskPtr mNext;
 };
 
-} // namespace Ncp
+} // namespace Host
 } // namespace otbr
 
 #endif // OTBR_AGENT_ASYNC_TASK_HPP_
diff --git a/src/ncp/ncp_host.cpp b/src/host/ncp_host.cpp
similarity index 76%
rename from src/ncp/ncp_host.cpp
rename to src/host/ncp_host.cpp
index f5ad0f78..7bb6edeb 100644
--- a/src/ncp/ncp_host.cpp
+++ b/src/host/ncp_host.cpp
@@ -37,12 +37,11 @@
 
 #include <openthread/openthread-system.h>
 
+#include "host/async_task.hpp"
 #include "lib/spinel/spinel_driver.hpp"
 
-#include "ncp/async_task.hpp"
-
 namespace otbr {
-namespace Ncp {
+namespace Host {
 
 // =============================== NcpNetworkProperties ===============================
 
@@ -94,14 +93,16 @@ void NcpNetworkProperties::GetDatasetPendingTlvs(otOperationalDatasetTlvs &aData
 
 // ===================================== NcpHost ======================================
 
-NcpHost::NcpHost(const char *aInterfaceName, bool aDryRun)
+NcpHost::NcpHost(const char *aInterfaceName, const char *aBackboneInterfaceName, bool aDryRun)
     : mSpinelDriver(*static_cast<ot::Spinel::SpinelDriver *>(otSysGetSpinelDriver()))
-    , mNetif()
+    , mNetif(mNcpSpinel)
+    , mInfraIf(mNcpSpinel)
 {
     memset(&mConfig, 0, sizeof(mConfig));
-    mConfig.mInterfaceName = aInterfaceName;
-    mConfig.mDryRun        = aDryRun;
-    mConfig.mSpeedUpFactor = 1;
+    mConfig.mInterfaceName         = aInterfaceName;
+    mConfig.mBackboneInterfaceName = aBackboneInterfaceName;
+    mConfig.mDryRun                = aDryRun;
+    mConfig.mSpeedUpFactor         = 1;
 }
 
 const char *NcpHost::GetCoprocessorVersion(void)
@@ -113,14 +114,35 @@ void NcpHost::Init(void)
 {
     otSysInit(&mConfig);
     mNcpSpinel.Init(mSpinelDriver, *this);
-    mNetif.Init(mConfig.mInterfaceName,
-                [this](const uint8_t *aData, uint16_t aLength) { return mNcpSpinel.Ip6Send(aData, aLength); });
+    mNetif.Init(mConfig.mInterfaceName);
+    mInfraIf.Init();
 
     mNcpSpinel.Ip6SetAddressCallback(
         [this](const std::vector<Ip6AddressInfo> &aAddrInfos) { mNetif.UpdateIp6UnicastAddresses(aAddrInfos); });
     mNcpSpinel.Ip6SetAddressMulticastCallback(
         [this](const std::vector<Ip6Address> &aAddrs) { mNetif.UpdateIp6MulticastAddresses(aAddrs); });
     mNcpSpinel.NetifSetStateChangedCallback([this](bool aState) { mNetif.SetNetifState(aState); });
+    mNcpSpinel.Ip6SetReceiveCallback(
+        [this](const uint8_t *aData, uint16_t aLength) { mNetif.Ip6Receive(aData, aLength); });
+    mNcpSpinel.InfraIfSetIcmp6NdSendCallback(
+        [this](uint32_t aInfraIfIndex, const otIp6Address &aAddr, const uint8_t *aData, uint16_t aDataLen) {
+            OTBR_UNUSED_VARIABLE(mInfraIf.SendIcmp6Nd(aInfraIfIndex, aAddr, aData, aDataLen));
+        });
+
+    if (mConfig.mBackboneInterfaceName != nullptr && strlen(mConfig.mBackboneInterfaceName) > 0)
+    {
+        mInfraIf.SetInfraIf(mConfig.mBackboneInterfaceName);
+    }
+
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+#if OTBR_ENABLE_SRP_SERVER_AUTO_ENABLE_MODE
+    // Let SRP server use auto-enable mode. The auto-enable mode delegates the control of SRP server to the Border
+    // Routing Manager. SRP server automatically starts when bi-directional connectivity is ready.
+    mNcpSpinel.SrpServerSetAutoEnableMode(/* aEnabled */ true);
+#else
+    mNcpSpinel.SrpServerSetEnabled(/* aEnabled */ true);
+#endif
+#endif
 }
 
 void NcpHost::Deinit(void)
@@ -144,14 +166,23 @@ void NcpHost::Join(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, const A
     task->Run();
 }
 
-void NcpHost::Leave(const AsyncResultReceiver &aReceiver)
+void NcpHost::Leave(bool aEraseDataset, const AsyncResultReceiver &aReceiver)
 {
     AsyncTaskPtr task;
     auto errorHandler = [aReceiver](otError aError, const std::string &aErrorInfo) { aReceiver(aError, aErrorInfo); };
 
     task = std::make_shared<AsyncTask>(errorHandler);
     task->First([this](AsyncTaskPtr aNext) { mNcpSpinel.ThreadDetachGracefully(std::move(aNext)); })
-        ->Then([this](AsyncTaskPtr aNext) { mNcpSpinel.ThreadErasePersistentInfo(std::move(aNext)); });
+        ->Then([this, aEraseDataset](AsyncTaskPtr aNext) {
+            if (aEraseDataset)
+            {
+                mNcpSpinel.ThreadErasePersistentInfo(std::move(aNext));
+            }
+            else
+            {
+                aNext->SetResult(OT_ERROR_NONE, "");
+            }
+        });
     task->Run();
 }
 
@@ -199,6 +230,7 @@ void NcpHost::GetChannelMasks(const ChannelMasksReceiver &aReceiver, const Async
     mTaskRunner.Post([aErrReceiver](void) { aErrReceiver(OT_ERROR_NOT_IMPLEMENTED, "Not implemented!"); });
 }
 
+#if OTBR_ENABLE_POWER_CALIBRATION
 void NcpHost::SetChannelMaxPowers(const std::vector<ChannelMaxPower> &aChannelMaxPowers,
                                   const AsyncResultReceiver          &aReceiver)
 {
@@ -207,6 +239,7 @@ void NcpHost::SetChannelMaxPowers(const std::vector<ChannelMaxPower> &aChannelMa
     // TODO: Implement SetChannelMaxPowers under NCP mode.
     mTaskRunner.Post([aReceiver](void) { aReceiver(OT_ERROR_NOT_IMPLEMENTED, "Not implemented!"); });
 }
+#endif
 
 void NcpHost::AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback)
 {
@@ -214,9 +247,17 @@ void NcpHost::AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback
     OT_UNUSED_VARIABLE(aCallback);
 }
 
+void NcpHost::AddThreadEnabledStateChangedCallback(ThreadEnabledStateCallback aCallback)
+{
+    // TODO: Implement AddThreadEnabledStateChangedCallback under NCP mode.
+    OT_UNUSED_VARIABLE(aCallback);
+}
+
 void NcpHost::Process(const MainloopContext &aMainloop)
 {
     mSpinelDriver.Process(&aMainloop);
+
+    mNetif.Process(&aMainloop);
 }
 
 void NcpHost::Update(MainloopContext &aMainloop)
@@ -228,7 +269,21 @@ void NcpHost::Update(MainloopContext &aMainloop)
         aMainloop.mTimeout.tv_sec  = 0;
         aMainloop.mTimeout.tv_usec = 0;
     }
+
+    mNetif.UpdateFdSet(&aMainloop);
+}
+
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+void NcpHost::SetMdnsPublisher(Mdns::Publisher *aPublisher)
+{
+    mNcpSpinel.SetMdnsPublisher(aPublisher);
+}
+
+void NcpHost::HandleMdnsState(Mdns::Publisher::State aState)
+{
+    mNcpSpinel.DnssdSetState(aState);
 }
+#endif
 
-} // namespace Ncp
+} // namespace Host
 } // namespace otbr
diff --git a/src/ncp/ncp_host.hpp b/src/host/ncp_host.hpp
similarity index 72%
rename from src/ncp/ncp_host.hpp
rename to src/host/ncp_host.hpp
index 18130d9f..f4fb0b0e 100644
--- a/src/ncp/ncp_host.hpp
+++ b/src/host/ncp_host.hpp
@@ -38,12 +38,12 @@
 #include "lib/spinel/spinel_driver.hpp"
 
 #include "common/mainloop.hpp"
-#include "ncp/ncp_spinel.hpp"
-#include "ncp/thread_host.hpp"
+#include "host/ncp_spinel.hpp"
+#include "host/thread_host.hpp"
 #include "posix/netif.hpp"
 
 namespace otbr {
-namespace Ncp {
+namespace Host {
 
 /**
  * This class implements the NetworkProperties under NCP mode.
@@ -72,16 +72,23 @@ private:
     otOperationalDatasetTlvs mDatasetActiveTlvs;
 };
 
-class NcpHost : public MainloopProcessor, public ThreadHost, public NcpNetworkProperties
+class NcpHost : public MainloopProcessor,
+                public ThreadHost,
+                public NcpNetworkProperties
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    ,
+                public Mdns::StateObserver
+#endif
 {
 public:
     /**
      * Constructor.
      *
-     * @param[in]   aInterfaceName  A string of the NCP interface name.
-     * @param[in]   aDryRun         TRUE to indicate dry-run mode. FALSE otherwise.
+     * @param[in]   aInterfaceName          A string of the NCP interface name.
+     * @param[in]   aBackboneInterfaceName  A string of the backbone interface name.
+     * @param[in]   aDryRun                 TRUE to indicate dry-run mode. FALSE otherwise.
      */
-    NcpHost(const char *aInterfaceName, bool aDryRun);
+    NcpHost(const char *aInterfaceName, const char *aBackboneInterfaceName, bool aDryRun);
 
     /**
      * Destructor.
@@ -90,34 +97,52 @@ public:
 
     // ThreadHost methods
     void Join(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, const AsyncResultReceiver &aReceiver) override;
-    void Leave(const AsyncResultReceiver &aReceiver) override;
+    void Leave(bool aEraseDataset, const AsyncResultReceiver &aReceiver) override;
     void ScheduleMigration(const otOperationalDatasetTlvs &aPendingOpDatasetTlvs,
                            const AsyncResultReceiver       aReceiver) override;
     void SetThreadEnabled(bool aEnabled, const AsyncResultReceiver aReceiver) override;
     void SetCountryCode(const std::string &aCountryCode, const AsyncResultReceiver &aReceiver) override;
     void GetChannelMasks(const ChannelMasksReceiver &aReceiver, const AsyncResultReceiver &aErrReceiver) override;
+#if OTBR_ENABLE_POWER_CALIBRATION
     void SetChannelMaxPowers(const std::vector<ChannelMaxPower> &aChannelMaxPowers,
                              const AsyncResultReceiver          &aReceiver) override;
-    void AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback) override;
-    CoprocessorType GetCoprocessorType(void) override { return OT_COPROCESSOR_NCP; }
-    const char     *GetCoprocessorVersion(void) override;
-    const char     *GetInterfaceName(void) const override { return mConfig.mInterfaceName; }
-    void            Init(void) override;
-    void            Deinit(void) override;
+#endif
+    void            AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback) override;
+    void            AddThreadEnabledStateChangedCallback(ThreadEnabledStateCallback aCallback) override;
+    CoprocessorType GetCoprocessorType(void) override
+    {
+        return OT_COPROCESSOR_NCP;
+    }
+    const char *GetCoprocessorVersion(void) override;
+    const char *GetInterfaceName(void) const override
+    {
+        return mConfig.mInterfaceName;
+    }
+    void Init(void) override;
+    void Deinit(void) override;
 
     // MainloopProcessor methods
     void Update(MainloopContext &aMainloop) override;
     void Process(const MainloopContext &aMainloop) override;
 
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    void SetMdnsPublisher(Mdns::Publisher *aPublisher);
+#endif
+
 private:
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    void HandleMdnsState(Mdns::Publisher::State aState) override;
+#endif
+
     ot::Spinel::SpinelDriver &mSpinelDriver;
     otPlatformConfig          mConfig;
     NcpSpinel                 mNcpSpinel;
     TaskRunner                mTaskRunner;
     Netif                     mNetif;
+    InfraIf                   mInfraIf;
 };
 
-} // namespace Ncp
+} // namespace Host
 } // namespace otbr
 
 #endif // OTBR_AGENT_NCP_HOST_HPP_
diff --git a/src/host/ncp_spinel.cpp b/src/host/ncp_spinel.cpp
new file mode 100644
index 00000000..13ff2107
--- /dev/null
+++ b/src/host/ncp_spinel.cpp
@@ -0,0 +1,1155 @@
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
+#include <openthread/platform/dnssd.h>
+
+#include "common/code_utils.hpp"
+#include "common/logging.hpp"
+#include "lib/spinel/spinel.h"
+#include "lib/spinel/spinel_decoder.hpp"
+#include "lib/spinel/spinel_driver.hpp"
+#include "lib/spinel/spinel_encoder.hpp"
+#include "lib/spinel/spinel_helper.hpp"
+#include "lib/spinel/spinel_prop_codec.hpp"
+
+namespace otbr {
+namespace Host {
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
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    , mPublisher(nullptr)
+#endif
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
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    mPublisher = nullptr;
+#endif
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
+    EncodingFunc encodingFunc = [&aActiveOpDatasetTlvs](ot::Spinel::Encoder &aEncoder) {
+        return aEncoder.WriteData(aActiveOpDatasetTlvs.mTlvs, aActiveOpDatasetTlvs.mLength);
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
+    EncodingFunc encodingFunc = [aPendingOpDatasetTlvsPtr](ot::Spinel::Encoder &aEncoder) {
+        return aEncoder.WriteData(aPendingOpDatasetTlvsPtr->mTlvs, aPendingOpDatasetTlvsPtr->mLength);
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
+    EncodingFunc encodingFunc = [aEnable](ot::Spinel::Encoder &aEncoder) { return aEncoder.WriteBool(aEnable); };
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
+    otbrError    error        = OTBR_ERROR_NONE;
+    EncodingFunc encodingFunc = [aData, aLength](ot::Spinel::Encoder &aEncoder) {
+        return aEncoder.WriteDataWithLen(aData, aLength);
+    };
+
+    SuccessOrExit(SetProperty(SPINEL_PROP_STREAM_NET, encodingFunc), error = OTBR_ERROR_OPENTHREAD);
+
+exit:
+    return error;
+}
+
+void NcpSpinel::ThreadSetEnabled(bool aEnable, AsyncTaskPtr aAsyncTask)
+{
+    otError      error        = OT_ERROR_NONE;
+    EncodingFunc encodingFunc = [aEnable](ot::Spinel::Encoder &aEncoder) { return aEncoder.WriteBool(aEnable); };
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
+    EncodingFunc encodingFunc = [](ot::Spinel::Encoder &) { return OT_ERROR_NONE; };
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
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+void NcpSpinel::SrpServerSetAutoEnableMode(bool aEnabled)
+{
+    otError      error;
+    EncodingFunc encodingFunc = [aEnabled](ot::Spinel::Encoder &aEncoder) { return aEncoder.WriteBool(aEnabled); };
+
+    error = SetProperty(SPINEL_PROP_SRP_SERVER_AUTO_ENABLE_MODE, encodingFunc);
+    if (error != OT_ERROR_NONE)
+    {
+        otbrLogWarning("Failed to call SrpServerSetAutoEnableMode, %s", otThreadErrorToString(error));
+    }
+}
+
+void NcpSpinel::SrpServerSetEnabled(bool aEnabled)
+{
+    otError      error;
+    EncodingFunc encodingFunc = [aEnabled](ot::Spinel::Encoder &aEncoder) { return aEncoder.WriteBool(aEnabled); };
+
+    error = SetProperty(SPINEL_PROP_SRP_SERVER_ENABLED, encodingFunc);
+    if (error != OT_ERROR_NONE)
+    {
+        otbrLogWarning("Failed to call SrpServerSetEnabled, %s", otThreadErrorToString(error));
+    }
+}
+
+void NcpSpinel::DnssdSetState(Mdns::Publisher::State aState)
+{
+    otError          error;
+    otPlatDnssdState state = (aState == Mdns::Publisher::State::kReady) ? OT_PLAT_DNSSD_READY : OT_PLAT_DNSSD_STOPPED;
+    EncodingFunc     encodingFunc = [state](ot::Spinel::Encoder &aEncoder) { return aEncoder.WriteUint8(state); };
+
+    error = SetProperty(SPINEL_PROP_DNSSD_STATE, encodingFunc);
+    if (error != OT_ERROR_NONE)
+    {
+        otbrLogWarning("Failed to call DnssdSetState, %s", otThreadErrorToString(error));
+    }
+}
+#endif // OTBR_ENABLE_SRP_ADVERTISING_PROXY
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
+
+    switch (cmd)
+    {
+    case SPINEL_CMD_PROP_VALUE_IS:
+        HandleValueIs(key, data, static_cast<uint16_t>(len));
+        break;
+    case SPINEL_CMD_PROP_VALUE_INSERTED:
+        HandleValueInserted(key, data, static_cast<uint16_t>(len));
+        break;
+    case SPINEL_CMD_PROP_VALUE_REMOVED:
+        HandleValueRemoved(key, data, static_cast<uint16_t>(len));
+        break;
+    }
+
+exit:
+    otbrLogResult(error, "%s", __FUNCTION__);
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
+    switch (mCmdTable[aTid])
+    {
+    case SPINEL_CMD_PROP_VALUE_SET:
+    {
+        error = HandleResponseForPropSet(aTid, key, data, len);
+        break;
+    }
+    case SPINEL_CMD_PROP_VALUE_INSERT:
+    {
+        error = HandleResponseForPropInsert(aTid, cmd, key, data, len);
+        break;
+    }
+    case SPINEL_CMD_PROP_VALUE_REMOVE:
+    {
+        error = HandleResponseForPropRemove(aTid, cmd, key, data, len);
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
+    case SPINEL_PROP_THREAD_CHILD_TABLE:
+    case SPINEL_PROP_THREAD_ON_MESH_NETS:
+    case SPINEL_PROP_THREAD_OFF_MESH_ROUTES:
+    case SPINEL_PROP_THREAD_LEADER_NETWORK_DATA:
+    case SPINEL_PROP_IPV6_LL_ADDR:
+        break;
+
+    case SPINEL_PROP_STREAM_NET:
+    {
+        const uint8_t *data;
+        uint16_t       dataLen;
+
+        SuccessOrExit(ParseIp6StreamNet(aBuffer, aLength, data, dataLen), error = OTBR_ERROR_PARSE);
+        SafeInvoke(mIp6ReceiveCallback, data, dataLen);
+        break;
+    }
+
+    case SPINEL_PROP_INFRA_IF_SEND_ICMP6:
+    {
+        uint32_t            infraIfIndex;
+        const otIp6Address *destAddress;
+        const uint8_t      *data;
+        uint16_t            dataLen;
+
+        SuccessOrExit(ParseInfraIfIcmp6Nd(aBuffer, aLength, infraIfIndex, destAddress, data, dataLen),
+                      error = OTBR_ERROR_PARSE);
+        SafeInvoke(mInfraIfIcmp6NdCallback, infraIfIndex, *destAddress, data, dataLen);
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
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+static std::string KeyNameFor(const otPlatDnssdKey &aKey)
+{
+    std::string name(aKey.mName);
+
+    if (aKey.mServiceType != nullptr)
+    {
+        // TODO: current code would not work with service instance labels that include a '.'
+        name += ".";
+        name += aKey.mServiceType;
+    }
+    return name;
+}
+#endif
+
+void NcpSpinel::HandleValueInserted(spinel_prop_key_t aKey, const uint8_t *aBuffer, uint16_t aLength)
+{
+    otbrError           error = OTBR_ERROR_NONE;
+    ot::Spinel::Decoder decoder;
+
+    VerifyOrExit(aBuffer != nullptr, error = OTBR_ERROR_INVALID_ARGS);
+    decoder.Init(aBuffer, aLength);
+
+    switch (aKey)
+    {
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    case SPINEL_PROP_DNSSD_HOST:
+    {
+        Mdns::Publisher::AddressList addressList;
+        otPlatDnssdHost              host;
+        otPlatDnssdRequestId         requestId;
+        const uint8_t               *callbackData;
+        uint16_t                     callbackDataSize;
+        std::vector<uint8_t>         callbackDataCopy;
+
+        SuccessOrExit(ot::Spinel::DecodeDnssdHost(decoder, host, requestId, callbackData, callbackDataSize));
+        for (uint16_t i = 0; i < host.mAddressesLength; i++)
+        {
+            addressList.push_back(Ip6Address(host.mAddresses[i].mFields.m8));
+        }
+        callbackDataCopy.assign(callbackData, callbackData + callbackDataSize);
+
+        mPublisher->PublishHost(host.mHostName, addressList, [this, requestId, callbackDataCopy](otbrError aError) {
+            OT_UNUSED_VARIABLE(SendDnssdResult(requestId, callbackDataCopy, OtbrErrorToOtError(aError)));
+        });
+        break;
+    }
+    case SPINEL_PROP_DNSSD_SERVICE:
+    {
+        otPlatDnssdService           service;
+        Mdns::Publisher::SubTypeList subTypeList;
+        const char                  *subTypeArray[kMaxSubTypes];
+        uint16_t                     subTypeCount;
+        Mdns::Publisher::TxtData     txtData;
+        otPlatDnssdRequestId         requestId;
+        const uint8_t               *callbackData;
+        uint16_t                     callbackDataSize;
+        std::vector<uint8_t>         callbackDataCopy;
+
+        SuccessOrExit(ot::Spinel::DecodeDnssdService(decoder, service, subTypeArray, subTypeCount, requestId,
+                                                     callbackData, callbackDataSize));
+        for (uint16_t i = 0; i < subTypeCount; i++)
+        {
+            subTypeList.push_back(subTypeArray[i]);
+        }
+        txtData.assign(service.mTxtData, service.mTxtData + service.mTxtDataLength);
+        callbackDataCopy.assign(callbackData, callbackData + callbackDataSize);
+
+        mPublisher->PublishService(service.mHostName, service.mServiceInstance, service.mServiceType, subTypeList,
+                                   service.mPort, txtData, [this, requestId, callbackDataCopy](otbrError aError) {
+                                       OT_UNUSED_VARIABLE(
+                                           SendDnssdResult(requestId, callbackDataCopy, OtbrErrorToOtError(aError)));
+                                   });
+        break;
+    }
+    case SPINEL_PROP_DNSSD_KEY_RECORD:
+    {
+        otPlatDnssdKey           key;
+        Mdns::Publisher::KeyData keyData;
+        otPlatDnssdRequestId     requestId;
+        const uint8_t           *callbackData;
+        uint16_t                 callbackDataSize;
+        std::vector<uint8_t>     callbackDataCopy;
+
+        SuccessOrExit(ot::Spinel::DecodeDnssdKey(decoder, key, requestId, callbackData, callbackDataSize));
+        keyData.assign(key.mKeyData, key.mKeyData + key.mKeyDataLength);
+        callbackDataCopy.assign(callbackData, callbackData + callbackDataSize);
+
+        mPublisher->PublishKey(KeyNameFor(key), keyData, [this, requestId, callbackDataCopy](otbrError aError) {
+            OT_UNUSED_VARIABLE(SendDnssdResult(requestId, callbackDataCopy, OtbrErrorToOtError(aError)));
+        });
+        break;
+    }
+#endif // OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    default:
+        error = OTBR_ERROR_DROPPED;
+        break;
+    }
+
+exit:
+    otbrLogResult(error, "HandleValueInserted, key:%u", aKey);
+    return;
+}
+
+void NcpSpinel::HandleValueRemoved(spinel_prop_key_t aKey, const uint8_t *aBuffer, uint16_t aLength)
+{
+    otbrError           error = OTBR_ERROR_NONE;
+    ot::Spinel::Decoder decoder;
+
+    VerifyOrExit(aBuffer != nullptr, error = OTBR_ERROR_INVALID_ARGS);
+    decoder.Init(aBuffer, aLength);
+
+    switch (aKey)
+    {
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    case SPINEL_PROP_DNSSD_HOST:
+    {
+        otPlatDnssdHost      host;
+        otPlatDnssdRequestId requestId;
+        const uint8_t       *callbackData;
+        uint16_t             callbackDataSize;
+        std::vector<uint8_t> callbackDataCopy;
+
+        SuccessOrExit(ot::Spinel::DecodeDnssdHost(decoder, host, requestId, callbackData, callbackDataSize));
+        callbackDataCopy.assign(callbackData, callbackData + callbackDataSize);
+
+        mPublisher->UnpublishHost(host.mHostName, [this, requestId, callbackDataCopy](otbrError aError) {
+            OT_UNUSED_VARIABLE(SendDnssdResult(requestId, callbackDataCopy, OtbrErrorToOtError(aError)));
+        });
+        break;
+    }
+    case SPINEL_PROP_DNSSD_SERVICE:
+    {
+        otPlatDnssdService   service;
+        const char          *subTypeArray[kMaxSubTypes];
+        uint16_t             subTypeCount;
+        otPlatDnssdRequestId requestId;
+        const uint8_t       *callbackData;
+        uint16_t             callbackDataSize;
+        std::vector<uint8_t> callbackDataCopy;
+
+        SuccessOrExit(ot::Spinel::DecodeDnssdService(decoder, service, subTypeArray, subTypeCount, requestId,
+                                                     callbackData, callbackDataSize));
+        callbackDataCopy.assign(callbackData, callbackData + callbackDataSize);
+
+        mPublisher->UnpublishService(
+            service.mHostName, service.mServiceType, [this, requestId, callbackDataCopy](otbrError aError) {
+                OT_UNUSED_VARIABLE(SendDnssdResult(requestId, callbackDataCopy, OtbrErrorToOtError(aError)));
+            });
+        break;
+    }
+    case SPINEL_PROP_DNSSD_KEY_RECORD:
+    {
+        otPlatDnssdKey       key;
+        otPlatDnssdRequestId requestId;
+        const uint8_t       *callbackData;
+        uint16_t             callbackDataSize;
+        std::vector<uint8_t> callbackDataCopy;
+
+        SuccessOrExit(ot::Spinel::DecodeDnssdKey(decoder, key, requestId, callbackData, callbackDataSize));
+        callbackDataCopy.assign(callbackData, callbackData + callbackDataSize);
+
+        mPublisher->UnpublishKey(KeyNameFor(key), [this, requestId, callbackDataCopy](otbrError aError) {
+            OT_UNUSED_VARIABLE(SendDnssdResult(requestId, callbackDataCopy, OtbrErrorToOtError(aError)));
+        });
+        break;
+    }
+#endif // OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    default:
+        error = OTBR_ERROR_DROPPED;
+        break;
+    }
+
+exit:
+    otbrLogResult(error, "HandleValueRemoved, key:%u", aKey);
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
+    otbrError       error  = OTBR_ERROR_NONE;
+    spinel_status_t status = SPINEL_STATUS_OK;
+
+    switch (mWaitingKeyTable[aTid])
+    {
+    case SPINEL_PROP_THREAD_ACTIVE_DATASET_TLVS:
+        VerifyOrExit(aKey == SPINEL_PROP_THREAD_ACTIVE_DATASET_TLVS, error = OTBR_ERROR_INVALID_STATE);
+        CallAndClear(mDatasetSetActiveTask, OT_ERROR_NONE);
+        {
+            otOperationalDatasetTlvs datasetTlvs;
+            VerifyOrExit(ParseOperationalDatasetTlvs(aData, aLength, datasetTlvs) == OT_ERROR_NONE,
+                         error = OTBR_ERROR_PARSE);
+            mPropsObserver->SetDatasetActiveTlvs(datasetTlvs);
+        }
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
+            SuccessOrExit(error = SpinelDataUnpack(aData, aLength, SPINEL_DATATYPE_UINT_PACKED_S, &status));
+            CallAndClear(mDatasetMgmtSetPendingTask, ot::Spinel::SpinelStatusToOtError(status));
+        }
+        else if (aKey != SPINEL_PROP_THREAD_MGMT_SET_PENDING_DATASET_TLVS)
+        {
+            ExitNow(error = OTBR_ERROR_INVALID_STATE);
+        }
+        break;
+
+    case SPINEL_PROP_STREAM_NET:
+        break;
+
+    case SPINEL_PROP_INFRA_IF_STATE:
+        VerifyOrExit(aKey == SPINEL_PROP_LAST_STATUS, error = OTBR_ERROR_INVALID_STATE);
+        SuccessOrExit(error = SpinelDataUnpack(aData, aLength, SPINEL_DATATYPE_UINT_PACKED_S, &status));
+        otbrLogInfo("Infra If state update result: %s", spinel_status_to_cstr(status));
+        break;
+
+    case SPINEL_PROP_INFRA_IF_RECV_ICMP6:
+        VerifyOrExit(aKey == SPINEL_PROP_LAST_STATUS, error = OTBR_ERROR_INVALID_STATE);
+        SuccessOrExit(error = SpinelDataUnpack(aData, aLength, SPINEL_DATATYPE_UINT_PACKED_S, &status));
+        otbrLogInfo("Infra If handle ICMP6 ND result: %s", spinel_status_to_cstr(status));
+        break;
+
+    case SPINEL_PROP_DNSSD_STATE:
+        VerifyOrExit(aKey == SPINEL_PROP_LAST_STATUS, error = OTBR_ERROR_INVALID_STATE);
+        SuccessOrExit(error = SpinelDataUnpack(aData, aLength, SPINEL_DATATYPE_UINT_PACKED_S, &status));
+        otbrLogInfo("Update dnssd state result: %s", spinel_status_to_cstr(status));
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
+otbrError NcpSpinel::HandleResponseForPropInsert(spinel_tid_t      aTid,
+                                                 spinel_command_t  aCmd,
+                                                 spinel_prop_key_t aKey,
+                                                 const uint8_t    *aData,
+                                                 uint16_t          aLength)
+{
+    otbrError error = OTBR_ERROR_NONE;
+
+    switch (mWaitingKeyTable[aTid])
+    {
+    case SPINEL_PROP_IPV6_MULTICAST_ADDRESS_TABLE:
+        if (aCmd == SPINEL_CMD_PROP_VALUE_IS)
+        {
+            spinel_status_t status = SPINEL_STATUS_OK;
+
+            VerifyOrExit(aKey == SPINEL_PROP_LAST_STATUS, error = OTBR_ERROR_INVALID_STATE);
+            SuccessOrExit(error = SpinelDataUnpack(aData, aLength, SPINEL_DATATYPE_UINT_PACKED_S, &status));
+            otbrLogInfo("Failed to subscribe to multicast address on NCP, error:%s", spinel_status_to_cstr(status));
+        }
+        else
+        {
+            error = aCmd == SPINEL_CMD_PROP_VALUE_INSERTED ? OTBR_ERROR_NONE : OTBR_ERROR_INVALID_STATE;
+        }
+        break;
+    default:
+        break;
+    }
+
+exit:
+    otbrLogResult(error, "HandleResponseForPropInsert, key:%u", mWaitingKeyTable[aTid]);
+    return error;
+}
+
+otbrError NcpSpinel::HandleResponseForPropRemove(spinel_tid_t      aTid,
+                                                 spinel_command_t  aCmd,
+                                                 spinel_prop_key_t aKey,
+                                                 const uint8_t    *aData,
+                                                 uint16_t          aLength)
+{
+    otbrError error = OTBR_ERROR_NONE;
+
+    switch (mWaitingKeyTable[aTid])
+    {
+    case SPINEL_PROP_IPV6_MULTICAST_ADDRESS_TABLE:
+        if (aCmd == SPINEL_CMD_PROP_VALUE_IS)
+        {
+            spinel_status_t status = SPINEL_STATUS_OK;
+
+            VerifyOrExit(aKey == SPINEL_PROP_LAST_STATUS, error = OTBR_ERROR_INVALID_STATE);
+            SuccessOrExit(error = SpinelDataUnpack(aData, aLength, SPINEL_DATATYPE_UINT_PACKED_S, &status));
+            otbrLogInfo("Failed to unsubscribe to multicast address on NCP, error:%s", spinel_status_to_cstr(status));
+        }
+        else
+        {
+            error = aCmd == SPINEL_CMD_PROP_VALUE_REMOVED ? OTBR_ERROR_NONE : OTBR_ERROR_INVALID_STATE;
+        }
+        break;
+    default:
+        break;
+    }
+
+exit:
+    otbrLogResult(error, "HandleResponseForPropRemove, key:%u", mWaitingKeyTable[aTid]);
+    return error;
+}
+
+otbrError NcpSpinel::Ip6MulAddrUpdateSubscription(const otIp6Address &aAddress, bool aIsAdded)
+{
+    otbrError    error        = OTBR_ERROR_NONE;
+    EncodingFunc encodingFunc = [&aAddress](ot::Spinel::Encoder &aEncoder) {
+        return aEncoder.WriteIp6Address(aAddress);
+    };
+
+    if (aIsAdded)
+    {
+        SuccessOrExit(InsertProperty(SPINEL_PROP_IPV6_MULTICAST_ADDRESS_TABLE, encodingFunc),
+                      error = OTBR_ERROR_OPENTHREAD);
+    }
+    else
+    {
+        SuccessOrExit(RemoveProperty(SPINEL_PROP_IPV6_MULTICAST_ADDRESS_TABLE, encodingFunc),
+                      error = OTBR_ERROR_OPENTHREAD);
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
+otError NcpSpinel::SendCommand(spinel_command_t aCmd, spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc)
+{
+    otError      error  = OT_ERROR_NONE;
+    spinel_tid_t tid    = GetNextTid();
+    uint8_t      header = SPINEL_HEADER_FLAG | SPINEL_HEADER_IID(mIid) | tid;
+
+    VerifyOrExit(tid != 0, error = OT_ERROR_BUSY);
+    SuccessOrExit(error = mEncoder.BeginFrame(header, aCmd, aKey));
+    SuccessOrExit(error = aEncodingFunc(mEncoder));
+    SuccessOrExit(error = mEncoder.EndFrame());
+    SuccessOrExit(error = SendEncodedFrame());
+
+    mCmdTable[tid]        = aCmd;
+    mWaitingKeyTable[tid] = aKey;
+exit:
+    if (error != OT_ERROR_NONE)
+    {
+        FreeTidTableItem(tid);
+    }
+    return error;
+}
+
+otError NcpSpinel::SetProperty(spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc)
+{
+    return SendCommand(SPINEL_CMD_PROP_VALUE_SET, aKey, aEncodingFunc);
+}
+
+otError NcpSpinel::InsertProperty(spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc)
+{
+    return SendCommand(SPINEL_CMD_PROP_VALUE_INSERT, aKey, aEncodingFunc);
+}
+
+otError NcpSpinel::RemoveProperty(spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc)
+{
+    return SendCommand(SPINEL_CMD_PROP_VALUE_REMOVE, aKey, aEncodingFunc);
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
+otError NcpSpinel::ParseIp6MulticastAddresses(const uint8_t *aBuf, uint16_t aLen, std::vector<Ip6Address> &aAddressList)
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
+otError NcpSpinel::ParseIp6StreamNet(const uint8_t *aBuf, uint16_t aLen, const uint8_t *&aData, uint16_t &aDataLen)
+{
+    otError             error = OT_ERROR_NONE;
+    ot::Spinel::Decoder decoder;
+
+    VerifyOrExit(aBuf != nullptr, error = OT_ERROR_INVALID_ARGS);
+
+    decoder.Init(aBuf, aLen);
+    error = decoder.ReadDataWithLen(aData, aDataLen);
+
+exit:
+    return error;
+}
+
+otError NcpSpinel::ParseOperationalDatasetTlvs(const uint8_t            *aBuf,
+                                               uint16_t                  aLen,
+                                               otOperationalDatasetTlvs &aDatasetTlvs)
+{
+    otError             error = OT_ERROR_NONE;
+    ot::Spinel::Decoder decoder;
+    const uint8_t      *datasetTlvsData;
+    uint16_t            datasetTlvsLen;
+
+    decoder.Init(aBuf, aLen);
+    SuccessOrExit(error = decoder.ReadData(datasetTlvsData, datasetTlvsLen));
+    VerifyOrExit(datasetTlvsLen <= sizeof(aDatasetTlvs.mTlvs), error = OT_ERROR_PARSE);
+
+    memcpy(aDatasetTlvs.mTlvs, datasetTlvsData, datasetTlvsLen);
+    aDatasetTlvs.mLength = datasetTlvsLen;
+
+exit:
+    return error;
+}
+
+otError NcpSpinel::ParseInfraIfIcmp6Nd(const uint8_t       *aBuf,
+                                       uint8_t              aLen,
+                                       uint32_t            &aInfraIfIndex,
+                                       const otIp6Address *&aAddr,
+                                       const uint8_t      *&aData,
+                                       uint16_t            &aDataLen)
+{
+    otError             error = OT_ERROR_NONE;
+    ot::Spinel::Decoder decoder;
+
+    VerifyOrExit(aBuf != nullptr, error = OT_ERROR_INVALID_ARGS);
+
+    decoder.Init(aBuf, aLen);
+    SuccessOrExit(error = decoder.ReadUint32(aInfraIfIndex));
+    SuccessOrExit(error = decoder.ReadIp6Address(aAddr));
+    SuccessOrExit(error = decoder.ReadDataWithLen(aData, aDataLen));
+
+exit:
+    return error;
+}
+
+otError NcpSpinel::SendDnssdResult(otPlatDnssdRequestId        aRequestId,
+                                   const std::vector<uint8_t> &aCallbackData,
+                                   otError                     aError)
+{
+    otError      error;
+    EncodingFunc encodingFunc = [aRequestId, &aCallbackData, aError](ot::Spinel::Encoder &aEncoder) {
+        otError error = OT_ERROR_NONE;
+
+        SuccessOrExit(aEncoder.WriteUint8(aError));
+        SuccessOrExit(aEncoder.WriteUint32(aRequestId));
+        SuccessOrExit(aEncoder.WriteData(aCallbackData.data(), aCallbackData.size()));
+
+    exit:
+        return error;
+    };
+
+    error = SetProperty(SPINEL_PROP_DNSSD_REQUEST_RESULT, encodingFunc);
+    if (error != OT_ERROR_NONE)
+    {
+        otbrLogWarning("Failed to SendDnssdResult, %s", otThreadErrorToString(error));
+    }
+
+    return error;
+}
+
+otbrError NcpSpinel::SetInfraIf(uint32_t aInfraIfIndex, bool aIsRunning, const std::vector<Ip6Address> &aIp6Addresses)
+{
+    otbrError    error        = OTBR_ERROR_NONE;
+    EncodingFunc encodingFunc = [aInfraIfIndex, aIsRunning, &aIp6Addresses](ot::Spinel::Encoder &aEncoder) {
+        otError error = OT_ERROR_NONE;
+        SuccessOrExit(error = aEncoder.WriteUint32(aInfraIfIndex));
+        SuccessOrExit(error = aEncoder.WriteBool(aIsRunning));
+        for (const Ip6Address &addr : aIp6Addresses)
+        {
+            SuccessOrExit(error = aEncoder.WriteIp6Address(reinterpret_cast<const otIp6Address &>(addr)));
+        }
+
+    exit:
+        return error;
+    };
+
+    SuccessOrExit(SetProperty(SPINEL_PROP_INFRA_IF_STATE, encodingFunc), error = OTBR_ERROR_OPENTHREAD);
+
+exit:
+    return error;
+}
+
+otbrError NcpSpinel::HandleIcmp6Nd(uint32_t          aInfraIfIndex,
+                                   const Ip6Address &aIp6Address,
+                                   const uint8_t    *aData,
+                                   uint16_t          aDataLen)
+{
+    otbrError    error        = OTBR_ERROR_NONE;
+    EncodingFunc encodingFunc = [aInfraIfIndex, &aIp6Address, aData, aDataLen](ot::Spinel::Encoder &aEncoder) {
+        otError error = OT_ERROR_NONE;
+        SuccessOrExit(error = aEncoder.WriteUint32(aInfraIfIndex));
+        SuccessOrExit(error = aEncoder.WriteIp6Address(reinterpret_cast<const otIp6Address &>(aIp6Address)));
+        SuccessOrExit(error = aEncoder.WriteData(aData, aDataLen));
+    exit:
+        return error;
+    };
+
+    SuccessOrExit(SetProperty(SPINEL_PROP_INFRA_IF_RECV_ICMP6, encodingFunc), error = OTBR_ERROR_OPENTHREAD);
+
+exit:
+    if (error != OTBR_ERROR_NONE)
+    {
+        otbrLogWarning("Failed to passthrough ICMP6 ND to NCP, %s", otbrErrorString(error));
+    }
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
+} // namespace Host
+} // namespace otbr
diff --git a/src/ncp/ncp_spinel.hpp b/src/host/ncp_spinel.hpp
similarity index 70%
rename from src/ncp/ncp_spinel.hpp
rename to src/host/ncp_spinel.hpp
index c489b9a2..02f454bb 100644
--- a/src/ncp/ncp_spinel.hpp
+++ b/src/host/ncp_spinel.hpp
@@ -37,10 +37,13 @@
 #include <functional>
 #include <memory>
 
+#include <vector>
+
 #include <openthread/dataset.h>
 #include <openthread/error.h>
 #include <openthread/link.h>
 #include <openthread/thread.h>
+#include <openthread/platform/dnssd.h>
 
 #include "lib/spinel/spinel.h"
 #include "lib/spinel/spinel_buffer.hpp"
@@ -49,10 +52,13 @@
 
 #include "common/task_runner.hpp"
 #include "common/types.hpp"
-#include "ncp/async_task.hpp"
+#include "host/async_task.hpp"
+#include "host/posix/infra_if.hpp"
+#include "host/posix/netif.hpp"
+#include "mdns/mdns.hpp"
 
 namespace otbr {
-namespace Ncp {
+namespace Host {
 
 /**
  * This interface is an observer to subscribe the network properties from NCP.
@@ -83,12 +89,14 @@ public:
 /**
  * The class provides methods for controlling the Thread stack on the network co-processor (NCP).
  */
-class NcpSpinel
+class NcpSpinel : public Netif::Dependencies, public InfraIf::Dependencies
 {
 public:
     using Ip6AddressTableCallback          = std::function<void(const std::vector<Ip6AddressInfo> &)>;
     using Ip6MulticastAddressTableCallback = std::function<void(const std::vector<Ip6Address> &)>;
     using NetifStateChangedCallback        = std::function<void(bool)>;
+    using Ip6ReceiveCallback               = std::function<void(const uint8_t *, uint16_t)>;
+    using InfraIfSendIcmp6NdCallback = std::function<void(uint32_t, const otIp6Address &, const uint8_t *, uint16_t)>;
 
     /**
      * Constructor.
@@ -172,6 +180,13 @@ public:
         mIp6MulticastAddressTableCallback = aCallback;
     }
 
+    /**
+     * This method sets the callback to receive IP6 datagrams.
+     *
+     * @param[in] aCallback  The callback to receive IP6 datagrams.
+     */
+    void Ip6SetReceiveCallback(const Ip6ReceiveCallback &aCallback) { mIp6ReceiveCallback = aCallback; }
+
     /**
      * This methods sends an IP6 datagram through the NCP.
      *
@@ -181,7 +196,7 @@ public:
      * @retval OTBR_ERROR_NONE  The datagram is sent to NCP successfully.
      * @retval OTBR_ERROR_BUSY  NcpSpinel is busy with other requests.
      */
-    otbrError Ip6Send(const uint8_t *aData, uint16_t aLength);
+    otbrError Ip6Send(const uint8_t *aData, uint16_t aLength) override;
 
     /**
      * This method enableds/disables the Thread network on the NCP.
@@ -224,10 +239,55 @@ public:
         mNetifStateChangedCallback = aCallback;
     }
 
+    /**
+     * This method sets the function to send an Icmp6 ND message on the infrastructure link.
+     *
+     * @param[in] aCallback  The callback to send an Icmp6 ND message on the infrastructure link.
+     */
+    void InfraIfSetIcmp6NdSendCallback(const InfraIfSendIcmp6NdCallback &aCallback)
+    {
+        mInfraIfIcmp6NdCallback = aCallback;
+    }
+
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    /**
+     * This method enables/disables the SRP Server on NCP.
+     *
+     * @param[in] aEnable  A boolean to enable/disable the SRP server.
+     */
+    void SrpServerSetEnabled(bool aEnabled);
+
+    /**
+     * This method enables/disables the auto-enable mode on SRP Server on NCP.
+     *
+     * @param[in] aEnable  A boolean to enable/disable the SRP server.
+     */
+    void SrpServerSetAutoEnableMode(bool aEnabled);
+
+    /**
+     * This method sets the dnssd state on NCP.
+     *
+     * @param[in] aState  The dnssd state.
+     */
+    void DnssdSetState(Mdns::Publisher::State aState);
+
+    /**
+     * This method sets the mDNS Publisher object.
+     *
+     * @param[in] aPublisher  A pointer to the mDNS Publisher object.
+     */
+    void SetMdnsPublisher(otbr::Mdns::Publisher *aPublisher)
+    {
+        mPublisher = aPublisher;
+    }
+#endif // OTBR_ENABLE_SRP_ADVERTISING_PROXY
+
 private:
     using FailureHandler = std::function<void(otError)>;
 
-    static constexpr uint8_t kMaxTids = 16;
+    static constexpr uint8_t  kMaxTids             = 16;
+    static constexpr uint16_t kCallbackDataMaxSize = sizeof(uint64_t); // Maximum size of a function pointer.
+    static constexpr uint16_t kMaxSubTypes         = 8;                // Maximum number of sub types in a MDNS service.
 
     template <typename Function, typename... Args> static void SafeInvoke(Function &aFunc, Args &&...aArgs)
     {
@@ -261,22 +321,55 @@ private:
     void      HandleNotification(const uint8_t *aFrame, uint16_t aLength);
     void      HandleResponse(spinel_tid_t aTid, const uint8_t *aFrame, uint16_t aLength);
     void      HandleValueIs(spinel_prop_key_t aKey, const uint8_t *aBuffer, uint16_t aLength);
+    void      HandleValueInserted(spinel_prop_key_t aKey, const uint8_t *aBuffer, uint16_t aLength);
+    void      HandleValueRemoved(spinel_prop_key_t aKey, const uint8_t *aBuffer, uint16_t aLength);
     otbrError HandleResponseForPropSet(spinel_tid_t      aTid,
                                        spinel_prop_key_t aKey,
                                        const uint8_t    *aData,
                                        uint16_t          aLength);
+    otbrError HandleResponseForPropInsert(spinel_tid_t      aTid,
+                                          spinel_command_t  aCmd,
+                                          spinel_prop_key_t aKey,
+                                          const uint8_t    *aData,
+                                          uint16_t          aLength);
+    otbrError HandleResponseForPropRemove(spinel_tid_t      aTid,
+                                          spinel_command_t  aCmd,
+                                          spinel_prop_key_t aKey,
+                                          const uint8_t    *aData,
+                                          uint16_t          aLength);
+
+    otbrError Ip6MulAddrUpdateSubscription(const otIp6Address &aAddress, bool aIsAdded) override;
 
     spinel_tid_t GetNextTid(void);
     void         FreeTidTableItem(spinel_tid_t aTid);
 
-    using EncodingFunc = std::function<otError(void)>;
+    using EncodingFunc = std::function<otError(ot::Spinel::Encoder &aEncoder)>;
+    otError SendCommand(spinel_command_t aCmd, spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc);
     otError SetProperty(spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc);
+    otError InsertProperty(spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc);
+    otError RemoveProperty(spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc);
+
     otError SendEncodedFrame(void);
 
     otError ParseIp6AddressTable(const uint8_t *aBuf, uint16_t aLength, std::vector<Ip6AddressInfo> &aAddressTable);
-    otError ParseIp6MulticastAddresses(const uint8_t *aBuf, uint8_t aLen, std::vector<Ip6Address> &aAddressList);
-    otError ParseIp6StreamNet(const uint8_t *aBuf, uint8_t aLen, const uint8_t *&aData, uint16_t &aDataLen);
-    otError ParseOperationalDatasetTlvs(const uint8_t *aBuf, uint8_t aLen, otOperationalDatasetTlvs &aDatasetTlvs);
+    otError ParseIp6MulticastAddresses(const uint8_t *aBuf, uint16_t aLen, std::vector<Ip6Address> &aAddressList);
+    otError ParseIp6StreamNet(const uint8_t *aBuf, uint16_t aLen, const uint8_t *&aData, uint16_t &aDataLen);
+    otError ParseOperationalDatasetTlvs(const uint8_t *aBuf, uint16_t aLen, otOperationalDatasetTlvs &aDatasetTlvs);
+    otError ParseInfraIfIcmp6Nd(const uint8_t       *aBuf,
+                                uint8_t              aLen,
+                                uint32_t            &aInfraIfIndex,
+                                const otIp6Address *&aAddr,
+                                const uint8_t      *&aData,
+                                uint16_t            &aDataLen);
+    otError SendDnssdResult(otPlatDnssdRequestId aRequestId, const std::vector<uint8_t> &aCallbackData, otError aError);
+
+    otbrError SetInfraIf(uint32_t                       aInfraIfIndex,
+                         bool                           aIsRunning,
+                         const std::vector<Ip6Address> &aIp6Addresses) override;
+    otbrError HandleIcmp6Nd(uint32_t          aInfraIfIndex,
+                            const Ip6Address &aIp6Address,
+                            const uint8_t    *aData,
+                            uint16_t          aDataLen) override;
 
     ot::Spinel::SpinelDriver *mSpinelDriver;
     uint16_t                  mCmdTidsInUse; ///< Used transaction ids.
@@ -295,6 +388,9 @@ private:
     TaskRunner mTaskRunner;
 
     PropsObserver *mPropsObserver;
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    otbr::Mdns::Publisher *mPublisher;
+#endif
 
     AsyncTaskPtr mDatasetSetActiveTask;
     AsyncTaskPtr mDatasetMgmtSetPendingTask;
@@ -305,10 +401,12 @@ private:
 
     Ip6AddressTableCallback          mIp6AddressTableCallback;
     Ip6MulticastAddressTableCallback mIp6MulticastAddressTableCallback;
+    Ip6ReceiveCallback               mIp6ReceiveCallback;
     NetifStateChangedCallback        mNetifStateChangedCallback;
+    InfraIfSendIcmp6NdCallback       mInfraIfIcmp6NdCallback;
 };
 
-} // namespace Ncp
+} // namespace Host
 } // namespace otbr
 
 #endif // OTBR_AGENT_NCP_SPINEL_HPP_
diff --git a/src/ncp/posix/CMakeLists.txt b/src/host/posix/CMakeLists.txt
similarity index 95%
rename from src/ncp/posix/CMakeLists.txt
rename to src/host/posix/CMakeLists.txt
index 1f03fd3c..8b6d41fb 100644
--- a/src/ncp/posix/CMakeLists.txt
+++ b/src/host/posix/CMakeLists.txt
@@ -27,6 +27,11 @@
 #
 
 add_library(otbr-posix
+    cli_daemon.hpp
+    cli_daemon.cpp
+    dnssd.cpp
+    infra_if.hpp
+    infra_if.cpp
     netif.cpp
     netif_linux.cpp
     netif_unix.cpp
diff --git a/src/host/posix/cli_daemon.cpp b/src/host/posix/cli_daemon.cpp
new file mode 100644
index 00000000..1c2e6bdc
--- /dev/null
+++ b/src/host/posix/cli_daemon.cpp
@@ -0,0 +1,116 @@
+/*
+ *  Copyright (c) 2025, The OpenThread Authors.
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
+#define OTBR_LOG_TAG "CLI_DAEMON"
+
+#include "cli_daemon.hpp"
+
+#include <fcntl.h>
+#include <signal.h>
+#include <stdarg.h>
+#include <string.h>
+#include <sys/file.h>
+#include <sys/socket.h>
+#include <sys/stat.h>
+#include <sys/types.h>
+#include <sys/un.h>
+#include <unistd.h>
+
+#include <openthread/cli.h>
+
+#include "utils/socket_utils.hpp"
+
+namespace otbr {
+
+static constexpr char kDefaultNetIfName[] = "wpan0";
+static constexpr char kSocketBaseName[]   = "/run/openthread-";
+static constexpr char kSocketSuffix[]     = ".sock";
+static constexpr char kSocketLockSuffix[] = ".lock";
+
+static constexpr size_t kMaxSocketFilenameLength = sizeof(sockaddr_un::sun_path) - 1;
+
+std::string CliDaemon::GetSocketFilename(const char *aSuffix) const
+{
+    std::string fileName;
+    std::string netIfName = mNetifName.empty() ? kDefaultNetIfName : mNetifName;
+
+    fileName = kSocketBaseName + netIfName + aSuffix;
+    VerifyOrDie(fileName.size() <= kMaxSocketFilenameLength, otbrErrorString(OTBR_ERROR_INVALID_ARGS));
+
+    return fileName;
+}
+
+CliDaemon::CliDaemon(void)
+    : mListenSocket(-1)
+    , mDaemonLock(-1)
+{
+}
+
+void CliDaemon::CreateListenSocketOrDie(void)
+{
+    struct sockaddr_un sockname;
+
+    mListenSocket = SocketWithCloseExec(AF_UNIX, SOCK_STREAM, 0, kSocketNonBlock);
+    VerifyOrDie(mListenSocket != -1, strerror(errno));
+
+    std::string lockfile = GetSocketFilename(kSocketLockSuffix);
+    mDaemonLock          = open(lockfile.c_str(), O_CREAT | O_RDONLY | O_CLOEXEC, 0600);
+    VerifyOrDie(mDaemonLock != -1, strerror(errno));
+
+    VerifyOrDie(flock(mDaemonLock, LOCK_EX | LOCK_NB) != -1, strerror(errno));
+
+    std::string socketfile = GetSocketFilename(kSocketSuffix);
+    memset(&sockname, 0, sizeof(struct sockaddr_un));
+
+    sockname.sun_family = AF_UNIX;
+    strncpy(sockname.sun_path, socketfile.c_str(), sizeof(sockname.sun_path) - 1);
+    OTBR_UNUSED_VARIABLE(unlink(sockname.sun_path));
+
+    VerifyOrDie(bind(mListenSocket, reinterpret_cast<const struct sockaddr *>(&sockname), sizeof(struct sockaddr_un)) !=
+                    -1,
+                strerror(errno));
+}
+
+void CliDaemon::Init(const std::string &aNetIfName)
+{
+    // This allows implementing pseudo reset.
+    VerifyOrExit(mListenSocket == -1);
+
+    mNetifName = aNetIfName;
+    CreateListenSocketOrDie();
+
+    //
+    // only accept 1 connection.
+    //
+    VerifyOrDie(listen(mListenSocket, 1) != -1, strerror(errno));
+
+exit:
+    return;
+}
+
+} // namespace otbr
diff --git a/src/host/posix/cli_daemon.hpp b/src/host/posix/cli_daemon.hpp
new file mode 100644
index 00000000..3df99797
--- /dev/null
+++ b/src/host/posix/cli_daemon.hpp
@@ -0,0 +1,64 @@
+/*
+ *  Copyright (c) 2025, The OpenThread Authors.
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
+ *   This file includes definitions of the Cli Daemon of otbr-agent.
+ */
+
+#ifndef OTBR_AGENT_POSIX_DAEMON_HPP_
+#define OTBR_AGENT_POSIX_DAEMON_HPP_
+
+#include <vector>
+
+#include "common/mainloop.hpp"
+#include "common/types.hpp"
+
+namespace otbr {
+
+class CliDaemon
+{
+public:
+    CliDaemon(void);
+
+    void Init(const std::string &aNetIfName);
+
+private:
+    void CreateListenSocketOrDie(void);
+
+    std::string GetSocketFilename(const char *aSuffix) const;
+
+    int mListenSocket;
+    int mDaemonLock;
+
+    std::string mNetifName;
+};
+
+} // namespace otbr
+
+#endif // OTBR_AGENT_POSIX_DAEMON_HPP_
diff --git a/src/host/posix/dnssd.cpp b/src/host/posix/dnssd.cpp
new file mode 100644
index 00000000..c70f516e
--- /dev/null
+++ b/src/host/posix/dnssd.cpp
@@ -0,0 +1,328 @@
+/*
+ *    Copyright (c) 2025, The OpenThread Authors.
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
+ *   This file includes implementation of OpenThread DNS-SD platform APIs on the posix platform.
+ */
+
+#define OTBR_LOG_TAG "DNSSD"
+
+#include "host/posix/dnssd.hpp"
+
+#include <string>
+
+#include <openthread/platform/dnssd.h>
+
+#include "common/code_utils.hpp"
+#include "common/logging.hpp"
+#include "common/types.hpp"
+
+static otbr::DnssdPlatform::RegisterCallback MakeRegisterCallback(otInstance                 *aInstance,
+                                                                  otPlatDnssdRegisterCallback aCallback)
+{
+    return [aInstance, aCallback](otPlatDnssdRequestId aRequestId, otError aError) {
+        if (aCallback)
+        {
+            aCallback(aInstance, aRequestId, aError);
+        }
+    };
+}
+
+extern "C" otPlatDnssdState otPlatDnssdGetState(otInstance *aInstance)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+
+    return otbr::DnssdPlatform::Get().GetState();
+}
+
+extern "C" void otPlatDnssdRegisterService(otInstance                 *aInstance,
+                                           const otPlatDnssdService   *aService,
+                                           otPlatDnssdRequestId        aRequestId,
+                                           otPlatDnssdRegisterCallback aCallback)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+
+    otbr::DnssdPlatform::Get().RegisterService(*aService, aRequestId, MakeRegisterCallback(aInstance, aCallback));
+}
+
+extern "C" void otPlatDnssdUnregisterService(otInstance                 *aInstance,
+                                             const otPlatDnssdService   *aService,
+                                             otPlatDnssdRequestId        aRequestId,
+                                             otPlatDnssdRegisterCallback aCallback)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+
+    otbr::DnssdPlatform::Get().UnregisterService(*aService, aRequestId, MakeRegisterCallback(aInstance, aCallback));
+}
+
+extern "C" void otPlatDnssdRegisterHost(otInstance                 *aInstance,
+                                        const otPlatDnssdHost      *aHost,
+                                        otPlatDnssdRequestId        aRequestId,
+                                        otPlatDnssdRegisterCallback aCallback)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+
+    otbr::DnssdPlatform::Get().RegisterHost(*aHost, aRequestId, MakeRegisterCallback(aInstance, aCallback));
+}
+
+extern "C" void otPlatDnssdUnregisterHost(otInstance                 *aInstance,
+                                          const otPlatDnssdHost      *aHost,
+                                          otPlatDnssdRequestId        aRequestId,
+                                          otPlatDnssdRegisterCallback aCallback)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+
+    otbr::DnssdPlatform::Get().UnregisterHost(*aHost, aRequestId, MakeRegisterCallback(aInstance, aCallback));
+}
+
+extern "C" void otPlatDnssdRegisterKey(otInstance                 *aInstance,
+                                       const otPlatDnssdKey       *aKey,
+                                       otPlatDnssdRequestId        aRequestId,
+                                       otPlatDnssdRegisterCallback aCallback)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+
+    otbr::DnssdPlatform::Get().RegisterKey(*aKey, aRequestId, MakeRegisterCallback(aInstance, aCallback));
+}
+
+extern "C" void otPlatDnssdUnregisterKey(otInstance                 *aInstance,
+                                         const otPlatDnssdKey       *aKey,
+                                         otPlatDnssdRequestId        aRequestId,
+                                         otPlatDnssdRegisterCallback aCallback)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+
+    otbr::DnssdPlatform::Get().UnregisterKey(*aKey, aRequestId, MakeRegisterCallback(aInstance, aCallback));
+}
+
+extern "C" void otPlatDnssdStartBrowser(otInstance *aInstance, const otPlatDnssdBrowser *aBrowser)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+    OTBR_UNUSED_VARIABLE(aBrowser);
+}
+
+extern "C" void otPlatDnssdStopBrowser(otInstance *aInstance, const otPlatDnssdBrowser *aBrowser)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+    OTBR_UNUSED_VARIABLE(aBrowser);
+}
+
+extern "C" void otPlatDnssdStartSrvResolver(otInstance *aInstance, const otPlatDnssdSrvResolver *aResolver)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+    OTBR_UNUSED_VARIABLE(aResolver);
+}
+
+extern "C" void otPlatDnssdStopSrvResolver(otInstance *aInstance, const otPlatDnssdSrvResolver *aResolver)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+    OTBR_UNUSED_VARIABLE(aResolver);
+}
+
+extern "C" void otPlatDnssdStartTxtResolver(otInstance *aInstance, const otPlatDnssdTxtResolver *aResolver)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+    OTBR_UNUSED_VARIABLE(aResolver);
+}
+
+extern "C" void otPlatDnssdStopTxtResolver(otInstance *aInstance, const otPlatDnssdTxtResolver *aResolver)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+    OTBR_UNUSED_VARIABLE(aResolver);
+}
+
+extern "C" void otPlatDnssdStartIp6AddressResolver(otInstance *aInstance, const otPlatDnssdAddressResolver *aResolver)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+    OTBR_UNUSED_VARIABLE(aResolver);
+}
+
+extern "C" void otPlatDnssdStopIp6AddressResolver(otInstance *aInstance, const otPlatDnssdAddressResolver *aResolver)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+    OTBR_UNUSED_VARIABLE(aResolver);
+}
+
+void otPlatDnssdStartIp4AddressResolver(otInstance *aInstance, const otPlatDnssdAddressResolver *aResolver)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+    OTBR_UNUSED_VARIABLE(aResolver);
+}
+
+void otPlatDnssdStopIp4AddressResolver(otInstance *aInstance, const otPlatDnssdAddressResolver *aResolver)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+    OTBR_UNUSED_VARIABLE(aResolver);
+}
+
+//----------------------------------------------------------------------------------------------------------------------
+
+namespace otbr {
+
+DnssdPlatform *DnssdPlatform::sDnssdPlatform = nullptr;
+
+DnssdPlatform::DnssdPlatform(Mdns::Publisher &aPublisher)
+    : mPublisher(aPublisher)
+    , mState(kStateStopped)
+    , mRunning(false)
+    , mPublisherState(Mdns::Publisher::State::kIdle)
+{
+    sDnssdPlatform = this;
+}
+
+void DnssdPlatform::Start(void)
+{
+    if (!mRunning)
+    {
+        mRunning = true;
+        UpdateState();
+    }
+}
+
+void DnssdPlatform::Stop(void)
+{
+    if (mRunning)
+    {
+        mRunning = false;
+        UpdateState();
+    }
+}
+
+void DnssdPlatform::UpdateState(void)
+{
+    if (mRunning && (mPublisherState == Mdns::Publisher::State::kReady))
+    {
+        VerifyOrExit(mState != kStateReady);
+
+        mState = kStateReady;
+    }
+    else
+    {
+        VerifyOrExit(mState != kStateStopped);
+
+        mState = kStateStopped;
+    }
+
+    if (mStateChangeCallback)
+    {
+        mStateChangeCallback(mState);
+    }
+
+exit:
+    return;
+}
+
+Mdns::Publisher::ResultCallback DnssdPlatform::MakePublisherCallback(RequestId aRequestId, RegisterCallback aCallback)
+{
+    return [aRequestId, aCallback](otbrError aError) {
+        if (aCallback != nullptr)
+        {
+            aCallback(aRequestId, OtbrErrorToOtError(aError));
+        }
+    };
+}
+
+void DnssdPlatform::SetDnssdStateChangedCallback(DnssdStateChangeCallback aCallback)
+{
+    mStateChangeCallback = aCallback;
+}
+
+void DnssdPlatform::RegisterService(const Service &aService, RequestId aRequestId, RegisterCallback aCallback)
+{
+    Mdns::Publisher::SubTypeList subTypeList;
+    Mdns::Publisher::TxtData     txtData(aService.mTxtData, aService.mTxtData + aService.mTxtDataLength);
+
+    for (uint16_t index = 0; index < aService.mSubTypeLabelsLength; index++)
+    {
+        subTypeList.push_back(aService.mSubTypeLabels[index]);
+    }
+
+    mPublisher.PublishService(aService.mHostName, aService.mServiceInstance, aService.mServiceType, subTypeList,
+                              aService.mPort, txtData, MakePublisherCallback(aRequestId, aCallback));
+}
+
+void DnssdPlatform::UnregisterService(const Service &aService, RequestId aRequestId, RegisterCallback aCallback)
+{
+    mPublisher.UnpublishService(aService.mServiceInstance, aService.mServiceType,
+                                MakePublisherCallback(aRequestId, aCallback));
+}
+
+void DnssdPlatform::RegisterHost(const Host &aHost, RequestId aRequestId, RegisterCallback aCallback)
+{
+    Mdns::Publisher::AddressList addressList;
+
+    for (uint16_t index = 0; index < aHost.mAddressesLength; index++)
+    {
+        addressList.push_back(Ip6Address(aHost.mAddresses[index].mFields.m8));
+    }
+
+    mPublisher.PublishHost(aHost.mHostName, addressList, MakePublisherCallback(aRequestId, aCallback));
+}
+
+void DnssdPlatform::UnregisterHost(const Host &aHost, RequestId aRequestId, RegisterCallback aCallback)
+{
+    mPublisher.UnpublishHost(aHost.mHostName, MakePublisherCallback(aRequestId, aCallback));
+}
+
+std::string DnssdPlatform::KeyNameFor(const Key &aKey)
+{
+    std::string name(aKey.mName);
+
+    if (aKey.mServiceType != nullptr)
+    {
+        // TODO: current code would not work with service instance labels that include a '.'
+        name += ".";
+        name += aKey.mServiceType;
+    }
+
+    return name;
+}
+
+void DnssdPlatform::RegisterKey(const Key &aKey, RequestId aRequestId, RegisterCallback aCallback)
+{
+    Mdns::Publisher::KeyData keyData(aKey.mKeyData, aKey.mKeyData + aKey.mKeyDataLength);
+
+    mPublisher.PublishKey(KeyNameFor(aKey), keyData, MakePublisherCallback(aRequestId, aCallback));
+}
+
+void DnssdPlatform::UnregisterKey(const Key &aKey, RequestId aRequestId, RegisterCallback aCallback)
+{
+    mPublisher.UnpublishKey(KeyNameFor(aKey), MakePublisherCallback(aRequestId, aCallback));
+}
+
+void DnssdPlatform::HandleMdnsState(Mdns::Publisher::State aState)
+{
+    if (mPublisherState != aState)
+    {
+        mPublisherState = aState;
+        UpdateState();
+    }
+}
+
+} // namespace otbr
diff --git a/src/host/posix/dnssd.hpp b/src/host/posix/dnssd.hpp
new file mode 100644
index 00000000..7a4a81b7
--- /dev/null
+++ b/src/host/posix/dnssd.hpp
@@ -0,0 +1,136 @@
+/*
+ *    Copyright (c) 2025, The OpenThread Authors.
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
+ *   This file includes definitions for implementing OpenThread DNS-SD platform APIs.
+ */
+
+#ifndef OTBR_AGENT_POSIX_DNSSD_HPP_
+#define OTBR_AGENT_POSIX_DNSSD_HPP_
+
+#include "openthread-br/config.h"
+
+#include <functional>
+#include <string>
+
+#include <openthread/instance.h>
+#include <openthread/platform/dnssd.h>
+
+#include "common/code_utils.hpp"
+#include "common/dns_utils.hpp"
+#include "host/thread_host.hpp"
+#include "mdns/mdns.hpp"
+
+namespace otbr {
+
+/**
+ * This class implements the DNS-SD platform.
+ *
+ */
+class DnssdPlatform : public Mdns::StateObserver, private NonCopyable
+{
+public:
+    /**
+     * Initializes the `DnssdPlatform` instance
+     *
+     * @param[in] aPublisher   A reference to `Mdns::Publisher` to use.
+     */
+    DnssdPlatform(Mdns::Publisher &aPublisher);
+
+    /**
+     * Starts the `DnssdPlatform` module.
+     */
+    void Start(void);
+
+    /**
+     * Stops the `DnssdPlatform` module
+     */
+    void Stop(void);
+
+    /**
+     * Gets the singleton `DnssdPlatform` instance.
+     *
+     * @returns  A reference to the `DnssdPlatform` instance.
+     */
+    static DnssdPlatform &Get(void) { return *sDnssdPlatform; }
+
+    typedef std::function<void(otPlatDnssdState)> DnssdStateChangeCallback;
+
+    /**
+     * Sets a Dnssd State changed callback.
+     *
+     * The main usage of this method is to call `otPlatDnssdStateHandleStateChange` to notify OT core about the change
+     * when the dnssd state changes. We shouldn't directly call `otPlatDnssdStateHandleStateChange` in this module'
+     * because it only fits the RCP case.
+     *
+     * @param[in] aCallback  The callback to be invoked when the dnssd state changes.
+     */
+    void SetDnssdStateChangedCallback(DnssdStateChangeCallback aCallback);
+
+    //-----------------------------------------------------------------------------------------------------------------
+    // `otPlatDnssd` APIs (see `openthread/include/openthread/platform/dnssd.h` for detailed documentation).
+
+    typedef otPlatDnssdState                                   State;
+    typedef otPlatDnssdService                                 Service;
+    typedef otPlatDnssdHost                                    Host;
+    typedef otPlatDnssdKey                                     Key;
+    typedef otPlatDnssdRequestId                               RequestId;
+    typedef std::function<void(otPlatDnssdRequestId, otError)> RegisterCallback;
+
+    State GetState(void) const { return mState; }
+    void  RegisterService(const Service &aService, RequestId aRequestId, RegisterCallback aCallback);
+    void  UnregisterService(const Service &aService, RequestId aRequestId, RegisterCallback aCallback);
+    void  RegisterHost(const Host &aHost, RequestId aRequestId, RegisterCallback aCallback);
+    void  UnregisterHost(const Host &aHost, RequestId aRequestId, RegisterCallback aCallback);
+    void  RegisterKey(const Key &aKey, RequestId aRequestId, RegisterCallback aCallback);
+    void  UnregisterKey(const Key &aKey, RequestId aRequestId, RegisterCallback aCallback);
+
+private:
+    static constexpr State kStateReady   = OT_PLAT_DNSSD_READY;
+    static constexpr State kStateStopped = OT_PLAT_DNSSD_STOPPED;
+
+    void HandleMdnsState(Mdns::Publisher::State aState) override;
+
+    void                            UpdateState(void);
+    Mdns::Publisher::ResultCallback MakePublisherCallback(RequestId aRequestId, RegisterCallback aCallback);
+
+    static std::string KeyNameFor(const Key &aKey);
+
+    static DnssdPlatform *sDnssdPlatform;
+
+    Mdns::Publisher         &mPublisher;
+    State                    mState;
+    bool                     mRunning;
+    Mdns::Publisher::State   mPublisherState;
+    DnssdStateChangeCallback mStateChangeCallback;
+};
+
+} // namespace otbr
+
+#endif // OTBR_AGENT_POSIX_DNSSD_HPP_
diff --git a/src/host/posix/infra_if.cpp b/src/host/posix/infra_if.cpp
new file mode 100644
index 00000000..0f559f8a
--- /dev/null
+++ b/src/host/posix/infra_if.cpp
@@ -0,0 +1,517 @@
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
+#define OTBR_LOG_TAG "INFRAIF"
+
+#ifdef __APPLE__
+#define __APPLE_USE_RFC_3542
+#endif
+
+#include "infra_if.hpp"
+
+#include <ifaddrs.h>
+#ifdef __linux__
+#include <linux/netlink.h>
+#include <linux/rtnetlink.h>
+#endif
+// clang-format off
+#include <netinet/in.h>
+#include <netinet/icmp6.h>
+// clang-format on
+#include <sys/ioctl.h>
+
+#include "utils/socket_utils.hpp"
+
+namespace otbr {
+
+otbrError InfraIf::Dependencies::SetInfraIf(unsigned int                   aInfraIfIndex,
+                                            bool                           aIsRunning,
+                                            const std::vector<Ip6Address> &aIp6Addresses)
+{
+    OTBR_UNUSED_VARIABLE(aInfraIfIndex);
+    OTBR_UNUSED_VARIABLE(aIsRunning);
+    OTBR_UNUSED_VARIABLE(aIp6Addresses);
+
+    return OTBR_ERROR_NONE;
+}
+
+otbrError InfraIf::Dependencies::HandleIcmp6Nd(uint32_t, const Ip6Address &, const uint8_t *, uint16_t)
+{
+    return OTBR_ERROR_NONE;
+}
+
+InfraIf::InfraIf(Dependencies &aDependencies)
+    : mDeps(aDependencies)
+    , mInfraIfIndex(0)
+#ifdef __linux__
+    , mNetlinkSocket(-1)
+#endif
+    , mInfraIfIcmp6Socket(-1)
+{
+}
+
+#ifdef __linux__
+// Create a Netlink socket that subscribes to link & addresses events.
+int CreateNetlinkSocket(void)
+{
+    int                sock;
+    int                rval;
+    struct sockaddr_nl addr;
+
+    sock = SocketWithCloseExec(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE, kSocketBlock);
+    VerifyOrDie(sock != -1, strerror(errno));
+
+    memset(&addr, 0, sizeof(addr));
+    addr.nl_family = AF_NETLINK;
+    addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV6_IFADDR;
+
+    rval = bind(sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
+    VerifyOrDie(rval == 0, strerror(errno));
+
+    return sock;
+}
+#endif // __linux__
+
+void InfraIf::Init(void)
+{
+#ifdef __linux__
+    mNetlinkSocket = CreateNetlinkSocket();
+#endif
+}
+
+void InfraIf::Deinit(void)
+{
+#ifdef __linux__
+    if (mNetlinkSocket != -1)
+    {
+        close(mNetlinkSocket);
+        mNetlinkSocket = -1;
+    }
+#endif
+    mInfraIfIndex = 0;
+
+    if (mInfraIfIcmp6Socket != -1)
+    {
+        close(mInfraIfIcmp6Socket);
+    }
+}
+
+void InfraIf::Process(const MainloopContext &aContext)
+{
+    VerifyOrExit(mInfraIfIcmp6Socket != -1);
+#ifdef __linux__
+    VerifyOrExit(mNetlinkSocket != -1);
+#endif
+
+    if (FD_ISSET(mInfraIfIcmp6Socket, &aContext.mReadFdSet))
+    {
+        ReceiveIcmp6Message();
+    }
+#ifdef __linux__
+    if (FD_ISSET(mNetlinkSocket, &aContext.mReadFdSet))
+    {
+        ReceiveNetlinkMessage();
+    }
+#endif
+
+exit:
+    return;
+}
+
+void InfraIf::UpdateFdSet(MainloopContext &aContext)
+{
+    VerifyOrExit(mInfraIfIcmp6Socket != -1);
+#ifdef __linux__
+    VerifyOrExit(mNetlinkSocket != -1);
+#endif
+
+    FD_SET(mInfraIfIcmp6Socket, &aContext.mReadFdSet);
+    aContext.mMaxFd = std::max(aContext.mMaxFd, mInfraIfIcmp6Socket);
+#ifdef __linux__
+    FD_SET(mNetlinkSocket, &aContext.mReadFdSet);
+    aContext.mMaxFd = std::max(aContext.mMaxFd, mNetlinkSocket);
+#endif
+
+exit:
+    return;
+}
+
+otbrError InfraIf::SetInfraIf(const char *aIfName)
+{
+    otbrError               error = OTBR_ERROR_NONE;
+    std::vector<Ip6Address> addresses;
+
+    VerifyOrExit(aIfName != nullptr && strlen(aIfName) > 0, error = OTBR_ERROR_INVALID_ARGS);
+    VerifyOrExit(strnlen(aIfName, IFNAMSIZ) < IFNAMSIZ, error = OTBR_ERROR_INVALID_ARGS);
+    strcpy(mInfraIfName, aIfName);
+
+    mInfraIfIndex = if_nametoindex(aIfName);
+    VerifyOrExit(mInfraIfIndex != 0, error = OTBR_ERROR_INVALID_STATE);
+
+    if (mInfraIfIcmp6Socket != -1)
+    {
+        close(mInfraIfIcmp6Socket);
+    }
+    mInfraIfIcmp6Socket = CreateIcmp6Socket(aIfName);
+    VerifyOrDie(mInfraIfIcmp6Socket != -1, "Failed to create Icmp6 socket!");
+
+    addresses = GetAddresses();
+
+    SuccessOrExit(mDeps.SetInfraIf(mInfraIfIndex, IsRunning(addresses), addresses), error = OTBR_ERROR_OPENTHREAD);
+exit:
+    otbrLogResult(error, "SetInfraIf");
+
+    return error;
+}
+
+otbrError InfraIf::SendIcmp6Nd(uint32_t            aInfraIfIndex,
+                               const otIp6Address &aDestAddress,
+                               const uint8_t      *aBuffer,
+                               uint16_t            aBufferLength)
+{
+    otbrError error = OTBR_ERROR_NONE;
+
+    struct iovec        iov;
+    struct in6_pktinfo *packetInfo;
+
+    int                 hopLimit = 255;
+    uint8_t             cmsgBuffer[CMSG_SPACE(sizeof(*packetInfo)) + CMSG_SPACE(sizeof(hopLimit))];
+    struct msghdr       msgHeader;
+    struct cmsghdr     *cmsgPointer;
+    ssize_t             rval;
+    struct sockaddr_in6 dest;
+
+    VerifyOrExit(mInfraIfIcmp6Socket >= 0, error = OTBR_ERROR_INVALID_STATE);
+    VerifyOrExit(aInfraIfIndex == mInfraIfIndex, error = OTBR_ERROR_DROPPED);
+
+    memset(cmsgBuffer, 0, sizeof(cmsgBuffer));
+
+    // Send the message
+    memset(&dest, 0, sizeof(dest));
+    dest.sin6_family = AF_INET6;
+    memcpy(&dest.sin6_addr, &aDestAddress, sizeof(aDestAddress));
+    if (IN6_IS_ADDR_LINKLOCAL(&dest.sin6_addr) || IN6_IS_ADDR_MC_LINKLOCAL(&dest.sin6_addr))
+    {
+        dest.sin6_scope_id = mInfraIfIndex;
+    }
+
+    iov.iov_base = const_cast<uint8_t *>(aBuffer);
+    iov.iov_len  = aBufferLength;
+
+    msgHeader.msg_namelen    = sizeof(dest);
+    msgHeader.msg_name       = &dest;
+    msgHeader.msg_iov        = &iov;
+    msgHeader.msg_iovlen     = 1;
+    msgHeader.msg_control    = cmsgBuffer;
+    msgHeader.msg_controllen = sizeof(cmsgBuffer);
+
+    // Specify the interface.
+    cmsgPointer             = CMSG_FIRSTHDR(&msgHeader);
+    cmsgPointer->cmsg_level = IPPROTO_IPV6;
+    cmsgPointer->cmsg_type  = IPV6_PKTINFO;
+    cmsgPointer->cmsg_len   = CMSG_LEN(sizeof(*packetInfo));
+    packetInfo              = (struct in6_pktinfo *)CMSG_DATA(cmsgPointer);
+    memset(packetInfo, 0, sizeof(*packetInfo));
+    packetInfo->ipi6_ifindex = mInfraIfIndex;
+
+    // Per section 6.1.2 of RFC 4861, we need to send the ICMPv6 message with IP Hop Limit 255.
+    cmsgPointer             = CMSG_NXTHDR(&msgHeader, cmsgPointer);
+    cmsgPointer->cmsg_level = IPPROTO_IPV6;
+    cmsgPointer->cmsg_type  = IPV6_HOPLIMIT;
+    cmsgPointer->cmsg_len   = CMSG_LEN(sizeof(hopLimit));
+    memcpy(CMSG_DATA(cmsgPointer), &hopLimit, sizeof(hopLimit));
+
+    rval = sendmsg(mInfraIfIcmp6Socket, &msgHeader, 0);
+
+    if (rval < 0)
+    {
+        otbrLogWarning("failed to send ICMPv6 message: %s", strerror(errno));
+        ExitNow(error = OTBR_ERROR_ERRNO);
+    }
+
+    if (static_cast<size_t>(rval) != iov.iov_len)
+    {
+        otbrLogWarning("failed to send ICMPv6 message: partially sent");
+        ExitNow(error = OTBR_ERROR_ERRNO);
+    }
+
+exit:
+    return error;
+}
+
+int InfraIf::CreateIcmp6Socket(const char *aInfraIfName)
+{
+    int                 sock;
+    int                 rval;
+    struct icmp6_filter filter;
+    const int           kEnable             = 1;
+    const int           kIpv6ChecksumOffset = 2;
+    const int           kHopLimit           = 255;
+
+    // Initializes the ICMPv6 socket.
+    sock = SocketWithCloseExec(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, kSocketBlock);
+    VerifyOrDie(sock != -1, strerror(errno));
+
+    // Only accept Router Advertisements, Router Solicitations and Neighbor Advertisements.
+    ICMP6_FILTER_SETBLOCKALL(&filter);
+    ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);
+    ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);
+    ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filter);
+
+    rval = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
+    VerifyOrDie(rval == 0, strerror(errno));
+
+    // We want a source address and interface index.
+    rval = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &kEnable, sizeof(kEnable));
+    VerifyOrDie(rval == 0, strerror(errno));
+
+#ifdef __linux__
+    rval = setsockopt(sock, IPPROTO_RAW, IPV6_CHECKSUM, &kIpv6ChecksumOffset, sizeof(kIpv6ChecksumOffset));
+#else
+    rval = setsockopt(sock, IPPROTO_IPV6, IPV6_CHECKSUM, &kIpv6ChecksumOffset, sizeof(kIpv6ChecksumOffset));
+#endif
+    VerifyOrDie(rval == 0, strerror(errno));
+
+    // We need to be able to reject RAs arriving from off-link.
+    rval = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &kEnable, sizeof(kEnable));
+    VerifyOrDie(rval == 0, strerror(errno));
+
+    rval = setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &kHopLimit, sizeof(kHopLimit));
+    VerifyOrDie(rval == 0, strerror(errno));
+
+    rval = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &kHopLimit, sizeof(kHopLimit));
+    VerifyOrDie(rval == 0, strerror(errno));
+
+#ifdef __linux__
+    rval = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, aInfraIfName, strlen(aInfraIfName));
+#else  // __NetBSD__ || __FreeBSD__ || __APPLE__
+    rval = setsockopt(sock, IPPROTO_IPV6, IPV6_BOUND_IF, aInfraIfName, strlen(aInfraIfName));
+#endif // __linux__
+    VerifyOrDie(rval == 0, strerror(errno));
+
+    return sock;
+}
+
+bool InfraIf::IsRunning(const std::vector<Ip6Address> &aAddrs) const
+{
+    return mInfraIfIndex ? ((GetFlags() & IFF_RUNNING) && HasLinkLocalAddress(aAddrs)) : false;
+}
+
+short InfraIf::GetFlags(void) const
+{
+    int          sock;
+    struct ifreq ifReq;
+
+    sock = SocketWithCloseExec(AF_INET6, SOCK_DGRAM, IPPROTO_IP, kSocketBlock);
+    VerifyOrDie(sock != -1, otbrErrorString(OTBR_ERROR_ERRNO));
+
+    memset(&ifReq, 0, sizeof(ifReq));
+    strcpy(ifReq.ifr_name, mInfraIfName);
+
+    if (ioctl(sock, SIOCGIFFLAGS, &ifReq) == -1)
+    {
+        otbrLogCrit("The infra link %s may be lost. Exiting.", mInfraIfName);
+        DieNow(otbrErrorString(OTBR_ERROR_ERRNO));
+    }
+
+    close(sock);
+
+    return ifReq.ifr_flags;
+}
+
+std::vector<Ip6Address> InfraIf::GetAddresses(void)
+{
+    struct ifaddrs         *ifAddrs = nullptr;
+    std::vector<Ip6Address> addrs;
+
+    if (getifaddrs(&ifAddrs) < 0)
+    {
+        otbrLogCrit("failed to get netif addresses: %s", strerror(errno));
+        ExitNow();
+    }
+
+    for (struct ifaddrs *addr = ifAddrs; addr != nullptr; addr = addr->ifa_next)
+    {
+        struct sockaddr_in6 *ip6Addr;
+
+        if (strncmp(addr->ifa_name, mInfraIfName, sizeof(mInfraIfName)) != 0 || addr->ifa_addr == nullptr ||
+            addr->ifa_addr->sa_family != AF_INET6)
+        {
+            continue;
+        }
+
+        ip6Addr = reinterpret_cast<sockaddr_in6 *>(addr->ifa_addr);
+        addrs.emplace_back(*reinterpret_cast<otIp6Address *>(&ip6Addr->sin6_addr));
+    }
+
+    freeifaddrs(ifAddrs);
+
+exit:
+    return addrs;
+}
+
+bool InfraIf::HasLinkLocalAddress(const std::vector<Ip6Address> &aAddrs)
+{
+    bool hasLla = false;
+
+    for (const Ip6Address &otAddr : aAddrs)
+    {
+        if (IN6_IS_ADDR_LINKLOCAL(reinterpret_cast<const in6_addr *>(&otAddr)))
+        {
+            hasLla = true;
+            break;
+        }
+    }
+
+    return hasLla;
+}
+
+void InfraIf::ReceiveIcmp6Message(void)
+{
+    static constexpr size_t kIp6Mtu = 1280;
+
+    otbrError error = OTBR_ERROR_NONE;
+    uint8_t   buffer[kIp6Mtu];
+    uint16_t  bufferLength;
+
+    ssize_t         rval;
+    struct msghdr   msg;
+    struct iovec    bufp;
+    char            cmsgbuf[128];
+    struct cmsghdr *cmh;
+    uint32_t        ifIndex  = 0;
+    int             hopLimit = -1;
+
+    struct sockaddr_in6 srcAddr;
+    struct in6_addr     dstAddr;
+
+    memset(&srcAddr, 0, sizeof(srcAddr));
+    memset(&dstAddr, 0, sizeof(dstAddr));
+
+    bufp.iov_base      = buffer;
+    bufp.iov_len       = sizeof(buffer);
+    msg.msg_iov        = &bufp;
+    msg.msg_iovlen     = 1;
+    msg.msg_name       = &srcAddr;
+    msg.msg_namelen    = sizeof(srcAddr);
+    msg.msg_control    = cmsgbuf;
+    msg.msg_controllen = sizeof(cmsgbuf);
+
+    rval = recvmsg(mInfraIfIcmp6Socket, &msg, 0);
+    if (rval < 0)
+    {
+        otbrLogWarning("Failed to receive ICMPv6 message: %s", strerror(errno));
+        ExitNow(error = OTBR_ERROR_DROPPED);
+    }
+
+    bufferLength = static_cast<uint16_t>(rval);
+
+    for (cmh = CMSG_FIRSTHDR(&msg); cmh; cmh = CMSG_NXTHDR(&msg, cmh))
+    {
+        if (cmh->cmsg_level == IPPROTO_IPV6 && cmh->cmsg_type == IPV6_PKTINFO &&
+            cmh->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo)))
+        {
+            const struct in6_pktinfo *pktinfo = reinterpret_cast<struct in6_pktinfo *>(CMSG_DATA(cmh));
+            ifIndex                           = pktinfo->ipi6_ifindex;
+            dstAddr                           = pktinfo->ipi6_addr;
+        }
+        else if (cmh->cmsg_level == IPPROTO_IPV6 && cmh->cmsg_type == IPV6_HOPLIMIT &&
+                 cmh->cmsg_len == CMSG_LEN(sizeof(int)))
+        {
+            hopLimit = *(int *)CMSG_DATA(cmh);
+        }
+    }
+
+    VerifyOrExit(ifIndex == mInfraIfIndex, error = OTBR_ERROR_DROPPED);
+
+    // We currently accept only RA & RS messages for the Border Router and it requires that
+    // the hoplimit must be 255 and the source address must be a link-local address.
+    VerifyOrExit(hopLimit == 255 && IN6_IS_ADDR_LINKLOCAL(&srcAddr.sin6_addr), error = OTBR_ERROR_DROPPED);
+
+    mDeps.HandleIcmp6Nd(mInfraIfIndex, Ip6Address(reinterpret_cast<otIp6Address &>(srcAddr.sin6_addr)), buffer,
+                        bufferLength);
+
+exit:
+    otbrLogResult(error, "InfraIf: %s", __FUNCTION__);
+}
+
+#ifdef __linux__
+void InfraIf::ReceiveNetlinkMessage(void)
+{
+    const size_t kMaxNetlinkBufSize = 8192;
+    ssize_t      len;
+    union
+    {
+        nlmsghdr mHeader;
+        uint8_t  mBuffer[kMaxNetlinkBufSize];
+    } msgBuffer;
+
+    len = recv(mNetlinkSocket, msgBuffer.mBuffer, sizeof(msgBuffer.mBuffer), /* flags */ 0);
+    if (len < 0)
+    {
+        otbrLogCrit("Failed to receive netlink message: %s", strerror(errno));
+        ExitNow();
+    }
+
+    for (struct nlmsghdr *header = &msgBuffer.mHeader; NLMSG_OK(header, static_cast<size_t>(len));
+         header                  = NLMSG_NEXT(header, len))
+    {
+        switch (header->nlmsg_type)
+        {
+        // There are no effective netlink message types to get us notified
+        // of interface RUNNING state changes. But addresses events are
+        // usually associated with interface state changes.
+        case RTM_NEWADDR:
+        case RTM_DELADDR:
+        case RTM_NEWLINK:
+        case RTM_DELLINK:
+        {
+            std::vector<Ip6Address> addresses = GetAddresses();
+
+            mDeps.SetInfraIf(mInfraIfIndex, IsRunning(addresses), addresses);
+            break;
+        }
+        case NLMSG_ERROR:
+        {
+            struct nlmsgerr *errMsg = reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(header));
+
+            OTBR_UNUSED_VARIABLE(errMsg);
+            otbrLogWarning("netlink NLMSG_ERROR response: seq=%u, error=%d", header->nlmsg_seq, errMsg->error);
+            break;
+        }
+        default:
+            break;
+        }
+    }
+
+exit:
+    return;
+}
+#endif // __linux__
+
+} // namespace otbr
diff --git a/src/host/posix/infra_if.hpp b/src/host/posix/infra_if.hpp
new file mode 100644
index 00000000..35163b7b
--- /dev/null
+++ b/src/host/posix/infra_if.hpp
@@ -0,0 +1,105 @@
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
+ *   This file includes definitions of the Infrastructure network interface of otbr-agent.
+ */
+
+#ifndef OTBR_AGENT_POSIX_INFRA_IF_HPP_
+#define OTBR_AGENT_POSIX_INFRA_IF_HPP_
+
+#include <net/if.h>
+
+#include <vector>
+
+#include <openthread/ip6.h>
+
+#include "common/mainloop.hpp"
+#include "common/types.hpp"
+
+namespace otbr {
+
+/**
+ * Host infrastructure network interface module.
+ *
+ * The infrastructure network interface MUST be explicitly set by `SetInfraIf` before the InfraIf module can work.
+ *
+ */
+class InfraIf
+{
+public:
+    class Dependencies
+    {
+    public:
+        virtual ~Dependencies(void) = default;
+
+        virtual otbrError SetInfraIf(unsigned int                   aInfraIfIndex,
+                                     bool                           aIsRunning,
+                                     const std::vector<Ip6Address> &aIp6Addresses);
+        virtual otbrError HandleIcmp6Nd(uint32_t          aInfraIfIndex,
+                                        const Ip6Address &aSrcAddress,
+                                        const uint8_t    *aData,
+                                        uint16_t          aDataLen);
+    };
+
+    InfraIf(Dependencies &aDependencies);
+
+    void      Init(void);
+    void      Deinit(void);
+    void      Process(const MainloopContext &aContext);
+    void      UpdateFdSet(MainloopContext &aContext);
+    otbrError SetInfraIf(const char *aIfName);
+    otbrError SendIcmp6Nd(uint32_t            aInfraIfIndex,
+                          const otIp6Address &aDestAddress,
+                          const uint8_t      *aBuffer,
+                          uint16_t            aBufferLength);
+
+private:
+    static int              CreateIcmp6Socket(const char *aInfraIfName);
+    bool                    IsRunning(const std::vector<Ip6Address> &aAddrs) const;
+    short                   GetFlags(void) const;
+    std::vector<Ip6Address> GetAddresses(void);
+    static bool             HasLinkLocalAddress(const std::vector<Ip6Address> &aAddrs);
+    void                    ReceiveIcmp6Message(void);
+#ifdef __linux__
+    void ReceiveNetlinkMessage(void);
+#endif
+
+    Dependencies &mDeps;
+    char          mInfraIfName[IFNAMSIZ];
+    unsigned int  mInfraIfIndex;
+#ifdef __linux__
+    int mNetlinkSocket;
+#endif
+    int mInfraIfIcmp6Socket;
+};
+
+} // namespace otbr
+
+#endif // OTBR_AGENT_POSIX_INFRA_IF_HPP_
diff --git a/src/ncp/posix/netif.cpp b/src/host/posix/netif.cpp
similarity index 54%
rename from src/ncp/posix/netif.cpp
rename to src/host/posix/netif.cpp
index 89018d2d..13957a01 100644
--- a/src/ncp/posix/netif.cpp
+++ b/src/host/posix/netif.cpp
@@ -30,8 +30,10 @@
 
 #include "netif.hpp"
 
+#include <arpa/inet.h>
 #include <errno.h>
 #include <fcntl.h>
+#include <ifaddrs.h>
 #include <net/if.h>
 #include <net/if_arp.h>
 #include <netinet/in.h>
@@ -50,22 +52,65 @@
 
 namespace otbr {
 
-Netif::Netif(void)
+otbrError Netif::Dependencies::Ip6Send(const uint8_t *aData, uint16_t aLength)
+{
+    OTBR_UNUSED_VARIABLE(aData);
+    OTBR_UNUSED_VARIABLE(aLength);
+
+    return OTBR_ERROR_NONE;
+}
+
+otbrError Netif::Dependencies::Ip6MulAddrUpdateSubscription(const otIp6Address &aAddress, bool aIsAdd)
+{
+    OTBR_UNUSED_VARIABLE(aAddress);
+    OTBR_UNUSED_VARIABLE(aIsAdd);
+
+    return OTBR_ERROR_NONE;
+}
+
+OT_TOOL_PACKED_BEGIN
+struct Mldv2Header
+{
+    uint8_t  mType;
+    uint8_t  _rsv0;
+    uint16_t mChecksum;
+    uint16_t _rsv1;
+    uint16_t mNumRecords;
+} OT_TOOL_PACKED_END;
+
+OT_TOOL_PACKED_BEGIN
+struct Mldv2Record
+{
+    uint8_t         mRecordType;
+    uint8_t         mAuxDataLen;
+    uint16_t        mNumSources;
+    struct in6_addr mMulticastAddress;
+} OT_TOOL_PACKED_END;
+
+enum
+{
+    kIcmpv6Mldv2Type                      = 143,
+    kIcmpv6Mldv2ModeIsIncludeType         = 1,
+    kIcmpv6Mldv2ModeIsExcludeType         = 2,
+    kIcmpv6Mldv2RecordChangeToIncludeType = 3,
+    kIcmpv6Mldv2RecordChangeToExcludeType = 4,
+};
+
+Netif::Netif(Dependencies &aDependencies)
     : mTunFd(-1)
     , mIpFd(-1)
     , mNetlinkFd(-1)
+    , mMldFd(-1)
     , mNetlinkSequence(0)
     , mNetifIndex(0)
+    , mDeps(aDependencies)
 {
 }
 
-otbrError Netif::Init(const std::string &aInterfaceName, const Ip6SendFunc &aIp6SendFunc)
+otbrError Netif::Init(const std::string &aInterfaceName)
 {
     otbrError error = OTBR_ERROR_NONE;
 
-    VerifyOrExit(aIp6SendFunc, error = OTBR_ERROR_INVALID_ARGS);
-    mIp6SendFunc = aIp6SendFunc;
-
     mIpFd = SocketWithCloseExec(AF_INET6, SOCK_DGRAM, IPPROTO_IP, kSocketNonBlock);
     VerifyOrExit(mIpFd >= 0, error = OTBR_ERROR_ERRNO);
 
@@ -75,6 +120,8 @@ otbrError Netif::Init(const std::string &aInterfaceName, const Ip6SendFunc &aIp6
     mNetifIndex = if_nametoindex(mNetifName.c_str());
     VerifyOrExit(mNetifIndex > 0, error = OTBR_ERROR_INVALID_STATE);
 
+    SuccessOrExit(error = InitMldListener());
+
     PlatformSpecificInit();
 
 exit:
@@ -98,10 +145,21 @@ void Netif::Process(const MainloopContext *aContext)
         DieNow("Error on Tun Fd!");
     }
 
+    if (FD_ISSET(mMldFd, &aContext->mErrorFdSet))
+    {
+        close(mMldFd);
+        DieNow("Error on MLD Fd!");
+    }
+
     if (FD_ISSET(mTunFd, &aContext->mReadFdSet))
     {
         ProcessIp6Send();
     }
+
+    if (FD_ISSET(mMldFd, &aContext->mReadFdSet))
+    {
+        ProcessMldEvent();
+    }
 }
 
 void Netif::UpdateFdSet(MainloopContext *aContext)
@@ -109,8 +167,10 @@ void Netif::UpdateFdSet(MainloopContext *aContext)
     assert(aContext != nullptr);
     assert(mTunFd >= 0);
     assert(mIpFd >= 0);
+    assert(mMldFd >= 0);
 
     aContext->AddFdToSet(mTunFd, MainloopContext::kErrorFdSet | MainloopContext::kReadFdSet);
+    aContext->AddFdToSet(mMldFd, MainloopContext::kErrorFdSet | MainloopContext::kReadFdSet);
 }
 
 void Netif::UpdateIp6UnicastAddresses(const std::vector<Ip6AddressInfo> &aAddrInfos)
@@ -256,10 +316,7 @@ void Netif::ProcessIp6Send(void)
 
     otbrLogInfo("Send packet (%hu bytes)", static_cast<uint16_t>(rval));
 
-    if (mIp6SendFunc != nullptr)
-    {
-        error = mIp6SendFunc(packet, rval);
-    }
+    error = mDeps.Ip6Send(packet, rval);
 exit:
     if (error == OTBR_ERROR_ERRNO)
     {
@@ -287,10 +344,158 @@ void Netif::Clear(void)
         mNetlinkFd = -1;
     }
 
+    if (mMldFd != -1)
+    {
+        close(mMldFd);
+        mMldFd = -1;
+    }
+
     mNetifIndex = 0;
     mIp6UnicastAddresses.clear();
     mIp6MulticastAddresses.clear();
-    mIp6SendFunc = nullptr;
+}
+
+static const otIp6Address kMldv2MulticastAddress = {
+    {{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16}}};
+static const otIp6Address kAllRouterLocalMulticastAddress = {
+    {{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}}};
+
+static bool IsMulAddrFiltered(const otIp6Address &aAddr)
+{
+    return Ip6Address(aAddr) == Ip6Address(kMldv2MulticastAddress) ||
+           Ip6Address(aAddr) == Ip6Address(kAllRouterLocalMulticastAddress);
+}
+
+otbrError Netif::InitMldListener(void)
+{
+    otbrError        error = OTBR_ERROR_NONE;
+    struct ipv6_mreq mreq6;
+
+    mMldFd = SocketWithCloseExec(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, kSocketNonBlock);
+    VerifyOrExit(mMldFd != -1, error = OTBR_ERROR_ERRNO);
+
+    mreq6.ipv6mr_interface = mNetifIndex;
+    memcpy(&mreq6.ipv6mr_multiaddr, kMldv2MulticastAddress.mFields.m8, sizeof(kMldv2MulticastAddress.mFields.m8));
+
+    VerifyOrExit(setsockopt(mMldFd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6)) == 0,
+                 error = OTBR_ERROR_ERRNO);
+#ifdef __linux__
+    VerifyOrExit(setsockopt(mMldFd, SOL_SOCKET, SO_BINDTODEVICE, mNetifName.c_str(),
+                            static_cast<socklen_t>(mNetifName.length())) == 0,
+                 error = OTBR_ERROR_ERRNO);
+#endif
+
+exit:
+    return error;
+}
+
+void Netif::ProcessMldEvent(void)
+{
+    const size_t        kMaxMldEvent = 8192;
+    uint8_t             buffer[kMaxMldEvent];
+    ssize_t             bufferLen = -1;
+    struct sockaddr_in6 srcAddr;
+    socklen_t           addrLen  = sizeof(srcAddr);
+    bool                fromSelf = false;
+    Mldv2Header        *hdr      = reinterpret_cast<Mldv2Header *>(buffer);
+    size_t              offset;
+    uint8_t             type;
+    struct ifaddrs     *ifAddrs = nullptr;
+    char                addressString[INET6_ADDRSTRLEN + 1];
+
+    bufferLen = recvfrom(mMldFd, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr *>(&srcAddr), &addrLen);
+    VerifyOrExit(bufferLen > 0);
+
+    type = buffer[0];
+    VerifyOrExit(type == kIcmpv6Mldv2Type && bufferLen >= static_cast<ssize_t>(sizeof(Mldv2Header)));
+
+    // Check whether it is sent by self
+    VerifyOrExit(getifaddrs(&ifAddrs) == 0);
+    for (struct ifaddrs *ifAddr = ifAddrs; ifAddr != nullptr; ifAddr = ifAddr->ifa_next)
+    {
+        if (ifAddr->ifa_addr != nullptr && ifAddr->ifa_addr->sa_family == AF_INET6 &&
+            strncmp(mNetifName.c_str(), ifAddr->ifa_name, IFNAMSIZ) == 0)
+        {
+            struct sockaddr_in6 *addr6 = reinterpret_cast<struct sockaddr_in6 *>(ifAddr->ifa_addr);
+
+            if (memcmp(&addr6->sin6_addr, &srcAddr.sin6_addr, sizeof(in6_addr)) == 0)
+            {
+                fromSelf = true;
+                break;
+            }
+        }
+    }
+    VerifyOrExit(fromSelf);
+
+    hdr    = reinterpret_cast<Mldv2Header *>(buffer);
+    offset = sizeof(Mldv2Header);
+
+    for (size_t i = 0; i < ntohs(hdr->mNumRecords) && offset < static_cast<size_t>(bufferLen); i++)
+    {
+        if (static_cast<size_t>(bufferLen) >= (sizeof(Mldv2Record) + offset))
+        {
+            Mldv2Record *record = reinterpret_cast<Mldv2Record *>(&buffer[offset]);
+
+            otbrError    error = OTBR_ERROR_DROPPED;
+            otIp6Address address;
+
+            memcpy(&address, &record->mMulticastAddress, sizeof(address));
+            if (IsMulAddrFiltered(address))
+            {
+                continue;
+            }
+
+            inet_ntop(AF_INET6, &record->mMulticastAddress, addressString, sizeof(addressString));
+
+            switch (record->mRecordType)
+            {
+            case kIcmpv6Mldv2ModeIsIncludeType:
+            case kIcmpv6Mldv2ModeIsExcludeType:
+                error = OTBR_ERROR_NONE;
+                break;
+            ///< Only update subscription on NCP when the target multicast address is not in `mIp6MulticastAddresses`.
+            ///< This indicates that this is the first time the multicast address subscription needs to be updated.
+            case kIcmpv6Mldv2RecordChangeToIncludeType:
+                if (record->mNumSources == 0)
+                {
+                    if (std::find(mIp6MulticastAddresses.begin(), mIp6MulticastAddresses.end(), Ip6Address(address)) !=
+                        mIp6MulticastAddresses.end())
+                    {
+                        error = mDeps.Ip6MulAddrUpdateSubscription(address, /* isAdd */ false);
+                    }
+                    else
+                    {
+                        error = OTBR_ERROR_NONE;
+                    }
+                }
+                break;
+            case kIcmpv6Mldv2RecordChangeToExcludeType:
+                if (std::find(mIp6MulticastAddresses.begin(), mIp6MulticastAddresses.end(), Ip6Address(address)) ==
+                    mIp6MulticastAddresses.end())
+                {
+                    error = mDeps.Ip6MulAddrUpdateSubscription(address, /* isAdd */ true);
+                }
+                else
+                {
+                    error = OTBR_ERROR_NONE;
+                }
+                break;
+            }
+
+            offset += sizeof(Mldv2Record) + sizeof(in6_addr) * ntohs(record->mNumSources);
+
+            if (error != OTBR_ERROR_NONE)
+            {
+                otbrLogWarning("Failed to Update multicast subscription: %s", otbrErrorString(error));
+            }
+        }
+    }
+
+exit:
+    if (ifAddrs)
+    {
+        freeifaddrs(ifAddrs);
+    }
 }
 
 } // namespace otbr
diff --git a/src/ncp/posix/netif.hpp b/src/host/posix/netif.hpp
similarity index 86%
rename from src/ncp/posix/netif.hpp
rename to src/host/posix/netif.hpp
index 4f110833..0c590f5b 100644
--- a/src/ncp/posix/netif.hpp
+++ b/src/host/posix/netif.hpp
@@ -49,11 +49,18 @@ namespace otbr {
 class Netif
 {
 public:
-    using Ip6SendFunc = std::function<otbrError(const uint8_t *, uint16_t)>;
+    class Dependencies
+    {
+    public:
+        virtual ~Dependencies(void) = default;
 
-    Netif(void);
+        virtual otbrError Ip6Send(const uint8_t *aData, uint16_t aLength);
+        virtual otbrError Ip6MulAddrUpdateSubscription(const otIp6Address &aAddress, bool aIsAdded);
+    };
 
-    otbrError Init(const std::string &aInterfaceName, const Ip6SendFunc &aIp6SendFunc);
+    Netif(Dependencies &aDependencies);
+
+    otbrError Init(const std::string &aInterfaceName);
     void      Deinit(void);
 
     void      Process(const MainloopContext *aContext);
@@ -72,16 +79,19 @@ private:
 
     otbrError CreateTunDevice(const std::string &aInterfaceName);
     otbrError InitNetlink(void);
+    otbrError InitMldListener(void);
 
     void      PlatformSpecificInit(void);
     void      SetAddrGenModeToNone(void);
     void      ProcessUnicastAddressChange(const Ip6AddressInfo &aAddressInfo, bool aIsAdded);
     otbrError ProcessMulticastAddressChange(const Ip6Address &aAddress, bool aIsAdded);
     void      ProcessIp6Send(void);
+    void      ProcessMldEvent(void);
 
     int      mTunFd;           ///< Used to exchange IPv6 packets.
     int      mIpFd;            ///< Used to manage IPv6 stack on the network interface.
     int      mNetlinkFd;       ///< Used to receive netlink events.
+    int      mMldFd;           ///< Used to receive MLD events.
     uint32_t mNetlinkSequence; ///< Netlink message sequence.
 
     unsigned int mNetifIndex;
@@ -89,7 +99,7 @@ private:
 
     std::vector<Ip6AddressInfo> mIp6UnicastAddresses;
     std::vector<Ip6Address>     mIp6MulticastAddresses;
-    Ip6SendFunc                 mIp6SendFunc;
+    Dependencies               &mDeps;
 };
 
 } // namespace otbr
diff --git a/src/ncp/posix/netif_linux.cpp b/src/host/posix/netif_linux.cpp
similarity index 100%
rename from src/ncp/posix/netif_linux.cpp
rename to src/host/posix/netif_linux.cpp
diff --git a/src/ncp/posix/netif_unix.cpp b/src/host/posix/netif_unix.cpp
similarity index 100%
rename from src/ncp/posix/netif_unix.cpp
rename to src/host/posix/netif_unix.cpp
diff --git a/src/ncp/rcp_host.cpp b/src/host/rcp_host.cpp
similarity index 72%
rename from src/ncp/rcp_host.cpp
rename to src/host/rcp_host.cpp
index edfcc7d4..a8aa072c 100644
--- a/src/ncp/rcp_host.cpp
+++ b/src/host/rcp_host.cpp
@@ -28,7 +28,7 @@
 
 #define OTBR_LOG_TAG "RCP_HOST"
 
-#include "ncp/rcp_host.hpp"
+#include "host/rcp_host.hpp"
 
 #include <assert.h>
 #include <limits.h>
@@ -60,7 +60,7 @@
 #endif
 
 namespace otbr {
-namespace Ncp {
+namespace Host {
 
 static const uint16_t kThreadVersion11 = 2; ///< Thread Version 1.1
 static const uint16_t kThreadVersion12 = 3; ///< Thread Version 1.2
@@ -125,6 +125,7 @@ RcpHost::RcpHost(const char                      *aInterfaceName,
                  bool                             aEnableAutoAttach)
     : mInstance(nullptr)
     , mEnableAutoAttach(aEnableAutoAttach)
+    , mThreadEnabledState(ThreadEnabledState::kStateDisabled)
 {
     VerifyOrDie(aRadioUrls.size() <= OT_PLATFORM_CONFIG_MAX_RADIO_URLS, "Too many Radio URLs!");
 
@@ -268,7 +269,7 @@ void RcpHost::Init(void)
 #if OTBR_ENABLE_DNS_UPSTREAM_QUERY
     otDnssdUpstreamQuerySetEnabled(mInstance, /* aEnabled */ true);
 #endif
-#if OTBR_ENABLE_DHCP6_PD
+#if OTBR_ENABLE_DHCP6_PD && OTBR_ENABLE_BORDER_ROUTING
     otBorderRoutingDhcp6PdSetEnabled(mInstance, /* aEnabled */ true);
 #endif
 #endif // OTBR_ENABLE_FEATURE_FLAGS
@@ -327,10 +328,13 @@ void RcpHost::Deinit(void)
 
     OtNetworkProperties::SetInstance(nullptr);
     mThreadStateChangedCallbacks.clear();
+    mThreadEnabledStateChangedCallbacks.clear();
     mResetHandlers.clear();
 
+    mJoinReceiver              = nullptr;
     mSetThreadEnabledReceiver  = nullptr;
     mScheduleMigrationReceiver = nullptr;
+    mDetachGracefullyCallbacks.clear();
 }
 
 void RcpHost::HandleStateChanged(otChangedFlags aFlags)
@@ -341,6 +345,12 @@ void RcpHost::HandleStateChanged(otChangedFlags aFlags)
     }
 
     mThreadHelper->StateChangedCallback(aFlags);
+
+    if ((aFlags & OT_CHANGED_THREAD_ROLE) && IsAttached() && mJoinReceiver != nullptr)
+    {
+        otbrLogInfo("Join succeeded");
+        SafeInvokeAndClear(mJoinReceiver, OT_ERROR_NONE, "Join succeeded");
+    }
 }
 
 void RcpHost::Update(MainloopContext &aMainloop)
@@ -390,6 +400,11 @@ void RcpHost::AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback
     mThreadStateChangedCallbacks.emplace_back(std::move(aCallback));
 }
 
+void RcpHost::AddThreadEnabledStateChangedCallback(ThreadEnabledStateCallback aCallback)
+{
+    mThreadEnabledStateChangedCallbacks.push_back(aCallback);
+}
+
 void RcpHost::Reset(void)
 {
     gPlatResetReason = OT_PLAT_RESET_REASON_SOFTWARE;
@@ -430,18 +445,113 @@ const char *RcpHost::GetThreadVersion(void)
     return version;
 }
 
+static bool noNeedRejoin(const otOperationalDatasetTlvs &aLhs, const otOperationalDatasetTlvs &aRhs)
+{
+    bool result = false;
+
+    otOperationalDataset lhsDataset;
+    otOperationalDataset rhsDataset;
+
+    SuccessOrExit(otDatasetParseTlvs(&aLhs, &lhsDataset));
+    SuccessOrExit(otDatasetParseTlvs(&aRhs, &rhsDataset));
+
+    result =
+        (lhsDataset.mChannel == rhsDataset.mChannel) &&
+        (memcmp(lhsDataset.mNetworkKey.m8, rhsDataset.mNetworkKey.m8, sizeof(lhsDataset.mNetworkKey)) == 0) &&
+        (memcmp(lhsDataset.mExtendedPanId.m8, rhsDataset.mExtendedPanId.m8, sizeof(lhsDataset.mExtendedPanId)) == 0);
+
+exit:
+    return result;
+}
+
 void RcpHost::Join(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, const AsyncResultReceiver &aReceiver)
 {
-    OT_UNUSED_VARIABLE(aActiveOpDatasetTlvs);
+    otError                  error = OT_ERROR_NONE;
+    std::string              errorMsg;
+    bool                     receiveResultHere = true;
+    otOperationalDatasetTlvs curDatasetTlvs;
+
+    VerifyOrExit(mInstance != nullptr, error = OT_ERROR_INVALID_STATE, errorMsg = "OT is not initialized");
+    VerifyOrExit(mThreadEnabledState != ThreadEnabledState::kStateDisabling, error = OT_ERROR_BUSY,
+                 errorMsg = "Thread is disabling");
+    VerifyOrExit(mThreadEnabledState == ThreadEnabledState::kStateEnabled, error = OT_ERROR_INVALID_STATE,
+                 errorMsg = "Thread is not enabled");
+
+    otbrLogInfo("Start joining...");
+
+    error = otDatasetGetActiveTlvs(mInstance, &curDatasetTlvs);
+    if (error == OT_ERROR_NONE && noNeedRejoin(aActiveOpDatasetTlvs, curDatasetTlvs) && IsAttached())
+    {
+        // Do not leave and re-join if this device has already joined the same network. This can help elimilate
+        // unnecessary connectivity and topology disruption and save the time for re-joining. It's more useful for use
+        // cases where Thread networks are dynamically brought up and torn down (e.g. Thread on mobile phones).
+        SuccessOrExit(error    = otDatasetSetActiveTlvs(mInstance, &aActiveOpDatasetTlvs),
+                      errorMsg = "Failed to set Active Operational Dataset");
+        errorMsg = "Already Joined the target network";
+        ExitNow();
+    }
 
-    // TODO: Implement Join under RCP mode.
-    mTaskRunner.Post([aReceiver](void) { aReceiver(OT_ERROR_NOT_IMPLEMENTED, "Not implemented!"); });
+    if (GetDeviceRole() != OT_DEVICE_ROLE_DISABLED)
+    {
+        ThreadDetachGracefully([aActiveOpDatasetTlvs, aReceiver, this] {
+            ConditionalErasePersistentInfo(true);
+            Join(aActiveOpDatasetTlvs, aReceiver);
+        });
+        receiveResultHere = false;
+        ExitNow();
+    }
+
+    SuccessOrExit(error    = otDatasetSetActiveTlvs(mInstance, &aActiveOpDatasetTlvs),
+                  errorMsg = "Failed to set Active Operational Dataset");
+
+    // TODO(b/273160198): check how we can implement join as a child
+    SuccessOrExit(error = otIp6SetEnabled(mInstance, true), errorMsg = "Failed to bring up Thread interface");
+    SuccessOrExit(error = otThreadSetEnabled(mInstance, true), errorMsg = "Failed to bring up Thread stack");
+
+    // Abort an ongoing join()
+    if (mJoinReceiver != nullptr)
+    {
+        SafeInvoke(mJoinReceiver, OT_ERROR_ABORT, "Join() is aborted");
+    }
+    mJoinReceiver     = aReceiver;
+    receiveResultHere = false;
+
+exit:
+    if (receiveResultHere)
+    {
+        mTaskRunner.Post([aReceiver, error, errorMsg](void) { aReceiver(error, errorMsg); });
+    }
 }
 
-void RcpHost::Leave(const AsyncResultReceiver &aReceiver)
+void RcpHost::Leave(bool aEraseDataset, const AsyncResultReceiver &aReceiver)
 {
-    // TODO: Implement Leave under RCP mode.
-    mTaskRunner.Post([aReceiver](void) { aReceiver(OT_ERROR_NOT_IMPLEMENTED, "Not implemented!"); });
+    otError     error = OT_ERROR_NONE;
+    std::string errorMsg;
+    bool        receiveResultHere = true;
+
+    VerifyOrExit(mInstance != nullptr, error = OT_ERROR_INVALID_STATE, errorMsg = "OT is not initialized");
+    VerifyOrExit(mThreadEnabledState != ThreadEnabledState::kStateDisabling, error = OT_ERROR_BUSY,
+                 errorMsg = "Thread is disabling");
+
+    if (mThreadEnabledState == ThreadEnabledState::kStateDisabled)
+    {
+        ConditionalErasePersistentInfo(aEraseDataset);
+        ExitNow();
+    }
+
+    ThreadDetachGracefully([aEraseDataset, aReceiver, this] {
+        ConditionalErasePersistentInfo(aEraseDataset);
+        if (aReceiver)
+        {
+            aReceiver(OT_ERROR_NONE, "");
+        }
+    });
+
+exit:
+    if (receiveResultHere)
+    {
+        mTaskRunner.Post([aReceiver, error, errorMsg](void) { aReceiver(error, errorMsg); });
+    }
 }
 
 void RcpHost::ScheduleMigration(const otOperationalDatasetTlvs &aPendingOpDatasetTlvs,
@@ -452,8 +562,13 @@ void RcpHost::ScheduleMigration(const otOperationalDatasetTlvs &aPendingOpDatase
     otOperationalDataset emptyDataset;
 
     VerifyOrExit(mInstance != nullptr, error = OT_ERROR_INVALID_STATE, errorMsg = "OT is not initialized");
-    VerifyOrExit(IsAttached(), error = OT_ERROR_FAILED,
-                 errorMsg = "Cannot schedule migration when this device is detached");
+
+    VerifyOrExit(mThreadEnabledState != ThreadEnabledState::kStateDisabling, error = OT_ERROR_BUSY,
+                 errorMsg = "Thread is disabling");
+    VerifyOrExit(mThreadEnabledState == ThreadEnabledState::kStateEnabled, error = OT_ERROR_INVALID_STATE,
+                 errorMsg = "Thread is disabled");
+
+    VerifyOrExit(IsAttached(), error = OT_ERROR_INVALID_STATE, errorMsg = "Device is detached");
 
     // TODO: check supported channel mask
 
@@ -488,26 +603,36 @@ void RcpHost::SendMgmtPendingSetCallback(otError aError)
 
 void RcpHost::SetThreadEnabled(bool aEnabled, const AsyncResultReceiver aReceiver)
 {
-    otError error             = OT_ERROR_NONE;
-    bool    receiveResultHere = true;
+    otError     error             = OT_ERROR_NONE;
+    std::string errorMsg          = "";
+    bool        receiveResultHere = true;
 
-    VerifyOrExit(mInstance != nullptr, error = OT_ERROR_INVALID_STATE);
-    VerifyOrExit(mSetThreadEnabledReceiver == nullptr, error = OT_ERROR_BUSY);
+    VerifyOrExit(mInstance != nullptr, error = OT_ERROR_INVALID_STATE, errorMsg = "OT is not initialized");
+    VerifyOrExit(mThreadEnabledState != ThreadEnabledState::kStateDisabling, error = OT_ERROR_BUSY,
+                 errorMsg = "Thread is disabling");
 
     if (aEnabled)
     {
         otOperationalDatasetTlvs datasetTlvs;
 
+        if (mThreadEnabledState == ThreadEnabledState::kStateEnabled)
+        {
+            ExitNow();
+        }
+
         if (otDatasetGetActiveTlvs(mInstance, &datasetTlvs) != OT_ERROR_NOT_FOUND && datasetTlvs.mLength > 0 &&
             otThreadGetDeviceRole(mInstance) == OT_DEVICE_ROLE_DISABLED)
         {
             SuccessOrExit(error = otIp6SetEnabled(mInstance, true));
             SuccessOrExit(error = otThreadSetEnabled(mInstance, true));
         }
+        UpdateThreadEnabledState(ThreadEnabledState::kStateEnabled);
     }
     else
     {
-        SuccessOrExit(error = otThreadDetachGracefully(mInstance, DisableThreadAfterDetach, this));
+        UpdateThreadEnabledState(ThreadEnabledState::kStateDisabling);
+
+        ThreadDetachGracefully([this](void) { DisableThreadAfterDetach(); });
         mSetThreadEnabledReceiver = aReceiver;
         receiveResultHere         = false;
     }
@@ -515,7 +640,7 @@ void RcpHost::SetThreadEnabled(bool aEnabled, const AsyncResultReceiver aReceive
 exit:
     if (receiveResultHere)
     {
-        mTaskRunner.Post([aReceiver, error](void) { aReceiver(error, ""); });
+        mTaskRunner.Post([aReceiver, error, errorMsg](void) { SafeInvoke(aReceiver, error, errorMsg); });
     }
 }
 
@@ -543,6 +668,7 @@ exit:
     }
 }
 
+#if OTBR_ENABLE_POWER_CALIBRATION
 void RcpHost::SetChannelMaxPowers(const std::vector<ChannelMaxPower> &aChannelMaxPowers,
                                   const AsyncResultReceiver          &aReceiver)
 {
@@ -570,10 +696,39 @@ void RcpHost::SetChannelMaxPowers(const std::vector<ChannelMaxPower> &aChannelMa
 exit:
     mTaskRunner.Post([aReceiver, error, errorMsg](void) { aReceiver(error, errorMsg); });
 }
+#endif // OTBR_ENABLE_POWER_CALIBRATION
+
+void RcpHost::ThreadDetachGracefully(const DetachGracefullyCallback &aCallback)
+{
+    mDetachGracefullyCallbacks.push_back(aCallback);
+
+    // Ignores the OT_ERROR_BUSY error if a detach has already been requested
+    OT_UNUSED_VARIABLE(otThreadDetachGracefully(mInstance, ThreadDetachGracefullyCallback, this));
+}
+
+void RcpHost::ThreadDetachGracefullyCallback(void *aContext)
+{
+    static_cast<RcpHost *>(aContext)->ThreadDetachGracefullyCallback();
+}
+
+void RcpHost::ThreadDetachGracefullyCallback(void)
+{
+    SafeInvokeAndClear(mJoinReceiver, OT_ERROR_ABORT, "Aborted by leave/disable operation");
+    SafeInvokeAndClear(mScheduleMigrationReceiver, OT_ERROR_ABORT, "Aborted by leave/disable operation");
+
+    for (auto &callback : mDetachGracefullyCallbacks)
+    {
+        callback();
+    }
+    mDetachGracefullyCallbacks.clear();
+}
 
-void RcpHost::DisableThreadAfterDetach(void *aContext)
+void RcpHost::ConditionalErasePersistentInfo(bool aErase)
 {
-    static_cast<RcpHost *>(aContext)->DisableThreadAfterDetach();
+    if (aErase)
+    {
+        OT_UNUSED_VARIABLE(otInstanceErasePersistentInfo(mInstance));
+    }
 }
 
 void RcpHost::DisableThreadAfterDetach(void)
@@ -584,6 +739,8 @@ void RcpHost::DisableThreadAfterDetach(void)
     SuccessOrExit(error = otThreadSetEnabled(mInstance, false), errorMsg = "Failed to disable Thread stack");
     SuccessOrExit(error = otIp6SetEnabled(mInstance, false), errorMsg = "Failed to disable Thread interface");
 
+    UpdateThreadEnabledState(ThreadEnabledState::kStateDisabled);
+
 exit:
     SafeInvokeAndClear(mSetThreadEnabledReceiver, error, errorMsg);
 }
@@ -615,6 +772,16 @@ bool RcpHost::IsAttached(void)
     return role == OT_DEVICE_ROLE_CHILD || role == OT_DEVICE_ROLE_ROUTER || role == OT_DEVICE_ROLE_LEADER;
 }
 
+void RcpHost::UpdateThreadEnabledState(ThreadEnabledState aState)
+{
+    mThreadEnabledState = aState;
+
+    for (auto &callback : mThreadEnabledStateChangedCallbacks)
+    {
+        callback(mThreadEnabledState);
+    }
+}
+
 /*
  * Provide, if required an "otPlatLog()" function
  */
@@ -636,5 +803,5 @@ extern "C" void otPlatLogHandleLevelChanged(otLogLevel aLogLevel)
     otbrLogInfo("OpenThread log level changed to %d", aLogLevel);
 }
 
-} // namespace Ncp
+} // namespace Host
 } // namespace otbr
diff --git a/src/ncp/rcp_host.hpp b/src/host/rcp_host.hpp
similarity index 86%
rename from src/ncp/rcp_host.hpp
rename to src/host/rcp_host.hpp
index f97a6260..27784351 100644
--- a/src/ncp/rcp_host.hpp
+++ b/src/host/rcp_host.hpp
@@ -49,7 +49,7 @@
 #include "common/mainloop.hpp"
 #include "common/task_runner.hpp"
 #include "common/types.hpp"
-#include "ncp/thread_host.hpp"
+#include "host/thread_host.hpp"
 #include "utils/thread_helper.hpp"
 
 namespace otbr {
@@ -58,7 +58,7 @@ namespace otbr {
 class FeatureFlagList;
 #endif
 
-namespace Ncp {
+namespace Host {
 
 /**
  * This class implements the NetworkProperties for architectures where OT APIs are directly accessible.
@@ -199,15 +199,18 @@ public:
 
     // Thread Control virtual methods
     void Join(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, const AsyncResultReceiver &aRecevier) override;
-    void Leave(const AsyncResultReceiver &aRecevier) override;
+    void Leave(bool aEraseDataset, const AsyncResultReceiver &aRecevier) override;
     void ScheduleMigration(const otOperationalDatasetTlvs &aPendingOpDatasetTlvs,
                            const AsyncResultReceiver       aReceiver) override;
     void SetThreadEnabled(bool aEnabled, const AsyncResultReceiver aReceiver) override;
     void SetCountryCode(const std::string &aCountryCode, const AsyncResultReceiver &aReceiver) override;
     void GetChannelMasks(const ChannelMasksReceiver &aReceiver, const AsyncResultReceiver &aErrReceiver) override;
+#if OTBR_ENABLE_POWER_CALIBRATION
     void SetChannelMaxPowers(const std::vector<ChannelMaxPower> &aChannelMaxPowers,
                              const AsyncResultReceiver          &aReceiver) override;
+#endif
     void AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback) override;
+    void AddThreadEnabledStateChangedCallback(ThreadEnabledStateCallback aCallback) override;
 
     CoprocessorType GetCoprocessorType(void) override
     {
@@ -228,6 +231,13 @@ private:
             aReceiver = nullptr;
         }
     }
+    static void SafeInvoke(const AsyncResultReceiver &aReceiver, otError aError, const std::string &aErrorInfo = "")
+    {
+        if (aReceiver)
+        {
+            aReceiver(aError, aErrorInfo);
+        }
+    }
 
     static void HandleStateChanged(otChangedFlags aFlags, void *aContext)
     {
@@ -235,20 +245,11 @@ private:
     }
     void HandleStateChanged(otChangedFlags aFlags);
 
-    static void HandleBackboneRouterDomainPrefixEvent(void                             *aContext,
-                                                      otBackboneRouterDomainPrefixEvent aEvent,
-                                                      const otIp6Prefix                *aDomainPrefix);
-    void        HandleBackboneRouterDomainPrefixEvent(otBackboneRouterDomainPrefixEvent aEvent,
-                                                      const otIp6Prefix                *aDomainPrefix);
-
-#if OTBR_ENABLE_DUA_ROUTING
-    static void HandleBackboneRouterNdProxyEvent(void                        *aContext,
-                                                 otBackboneRouterNdProxyEvent aEvent,
-                                                 const otIp6Address          *aAddress);
-    void        HandleBackboneRouterNdProxyEvent(otBackboneRouterNdProxyEvent aEvent, const otIp6Address *aAddress);
-#endif
-
-    static void DisableThreadAfterDetach(void *aContext);
+    using DetachGracefullyCallback = std::function<void()>;
+    void        ThreadDetachGracefully(const DetachGracefullyCallback &aCallback);
+    static void ThreadDetachGracefullyCallback(void *aContext);
+    void        ThreadDetachGracefullyCallback(void);
+    void        ConditionalErasePersistentInfo(bool aErase);
     void        DisableThreadAfterDetach(void);
     static void SendMgmtPendingSetCallback(otError aError, void *aContext);
     void        SendMgmtPendingSetCallback(otError aError);
@@ -258,6 +259,8 @@ private:
 
     bool IsAttached(void);
 
+    void UpdateThreadEnabledState(ThreadEnabledState aState);
+
     otError SetOtbrAndOtLogLevel(otbrLogLevel aLevel);
 
     otInstance *mInstance;
@@ -266,11 +269,15 @@ private:
     std::unique_ptr<otbr::agent::ThreadHelper> mThreadHelper;
     std::vector<std::function<void(void)>>     mResetHandlers;
     TaskRunner                                 mTaskRunner;
-    std::vector<ThreadStateChangedCallback>    mThreadStateChangedCallbacks;
-    bool                                       mEnableAutoAttach = false;
 
-    AsyncResultReceiver mSetThreadEnabledReceiver;
-    AsyncResultReceiver mScheduleMigrationReceiver;
+    std::vector<ThreadStateChangedCallback> mThreadStateChangedCallbacks;
+    std::vector<ThreadEnabledStateCallback> mThreadEnabledStateChangedCallbacks;
+    bool                                    mEnableAutoAttach = false;
+    ThreadEnabledState                      mThreadEnabledState;
+    AsyncResultReceiver                     mJoinReceiver;
+    AsyncResultReceiver                     mSetThreadEnabledReceiver;
+    AsyncResultReceiver                     mScheduleMigrationReceiver;
+    std::vector<DetachGracefullyCallback>   mDetachGracefullyCallbacks;
 
 #if OTBR_ENABLE_FEATURE_FLAGS
     // The applied FeatureFlagList in ApplyFeatureFlagList call, used for debugging purpose.
@@ -278,7 +285,7 @@ private:
 #endif
 };
 
-} // namespace Ncp
+} // namespace Host
 } // namespace otbr
 
 #endif // OTBR_AGENT_RCP_HOST_HPP_
diff --git a/src/ncp/thread_host.cpp b/src/host/thread_host.cpp
similarity index 96%
rename from src/ncp/thread_host.cpp
rename to src/host/thread_host.cpp
index b5f1bf25..9b4f8b8f 100644
--- a/src/ncp/thread_host.cpp
+++ b/src/host/thread_host.cpp
@@ -39,7 +39,7 @@
 #include "rcp_host.hpp"
 
 namespace otbr {
-namespace Ncp {
+namespace Host {
 
 std::unique_ptr<ThreadHost> ThreadHost::Create(const char                      *aInterfaceName,
                                                const std::vector<const char *> &aRadioUrls,
@@ -71,7 +71,7 @@ std::unique_ptr<ThreadHost> ThreadHost::Create(const char                      *
         break;
 
     case OT_COPROCESSOR_NCP:
-        host = MakeUnique<NcpHost>(aInterfaceName, aDryRun);
+        host = MakeUnique<NcpHost>(aInterfaceName, aBackboneInterfaceName, aDryRun);
         break;
 
     default:
@@ -82,5 +82,5 @@ std::unique_ptr<ThreadHost> ThreadHost::Create(const char                      *
     return host;
 }
 
-} // namespace Ncp
+} // namespace Host
 } // namespace otbr
diff --git a/src/ncp/thread_host.hpp b/src/host/thread_host.hpp
similarity index 93%
rename from src/ncp/thread_host.hpp
rename to src/host/thread_host.hpp
index 5301c3ec..6fc45d2d 100644
--- a/src/ncp/thread_host.hpp
+++ b/src/host/thread_host.hpp
@@ -46,7 +46,7 @@
 #include "common/logging.hpp"
 
 namespace otbr {
-namespace Ncp {
+namespace Host {
 
 /**
  * This interface provides access to some Thread network properties in a sync way.
@@ -98,6 +98,14 @@ public:
     virtual ~NetworkProperties(void) = default;
 };
 
+enum ThreadEnabledState
+{
+    kStateDisabled  = 0,
+    kStateEnabled   = 1,
+    kStateDisabling = 2,
+    kStateInvalid   = 255,
+};
+
 /**
  * This class is an interface which provides a set of async APIs to control the
  * Thread network.
@@ -112,6 +120,7 @@ public:
         std::function<void(uint32_t /*aSupportedChannelMask*/, uint32_t /*aPreferredChannelMask*/)>;
     using DeviceRoleHandler          = std::function<void(otError, otDeviceRole)>;
     using ThreadStateChangedCallback = std::function<void(otChangedFlags aFlags)>;
+    using ThreadEnabledStateCallback = std::function<void(ThreadEnabledState aState)>;
 
     struct ChannelMaxPower
     {
@@ -157,13 +166,13 @@ public:
      *    be called.
      * 2. If this device is not in disabled state, OTBR sends Address Release Notification (i.e. ADDR_REL.ntf)
      *    to gracefully detach from the current network and it takes 1 second to finish.
-     * 3. Then Operational Dataset will be removed from persistent storage.
+     * 3. Then Operational Dataset will be removed from persistent storage if @p aEraseDataset is true.
      * 4. If everything goes fine, @p aReceiver will be invoked with OT_ERROR_NONE. Otherwise, other errors
      *    will be passed to @p aReceiver when the error happens.
      *
      * @param[in] aReceiver  A receiver to get the async result of this operation.
      */
-    virtual void Leave(const AsyncResultReceiver &aRecevier) = 0;
+    virtual void Leave(bool aEraseDataset, const AsyncResultReceiver &aRecevier) = 0;
 
     /**
      * This method migrates this device to the new network specified by @p aPendingOpDatasetTlvs.
@@ -211,6 +220,7 @@ public:
      */
     virtual void GetChannelMasks(const ChannelMasksReceiver &aReceiver, const AsyncResultReceiver &aErrReceiver) = 0;
 
+#if OTBR_ENABLE_POWER_CALIBRATION
     /**
      * Sets the max power of each channel.
      *
@@ -223,6 +233,7 @@ public:
      */
     virtual void SetChannelMaxPowers(const std::vector<ChannelMaxPower> &aChannelMaxPowers,
                                      const AsyncResultReceiver          &aReceiver) = 0;
+#endif
 
     /**
      * This method adds a event listener for Thread state changes.
@@ -231,6 +242,13 @@ public:
      */
     virtual void AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback) = 0;
 
+    /**
+     * This method adds a event listener for Thread Enabled state changes.
+     *
+     * @param[in] aCallback  The callback to receive Thread Enabled state changed events.
+     */
+    virtual void AddThreadEnabledStateChangedCallback(ThreadEnabledStateCallback aCallback) = 0;
+
     /**
      * Returns the co-processor type.
      */
@@ -264,7 +282,7 @@ public:
     virtual ~ThreadHost(void) = default;
 };
 
-} // namespace Ncp
+} // namespace Host
 } // namespace otbr
 
 #endif // OTBR_AGENT_THREAD_HOST_HPP_
diff --git a/src/mdns/mdns.cpp b/src/mdns/mdns.cpp
index 3774a8b4..7fd050c4 100644
--- a/src/mdns/mdns.cpp
+++ b/src/mdns/mdns.cpp
@@ -779,6 +779,24 @@ void Publisher::RemoveAddress(AddressList &aAddressList, const Ip6Address &aAddr
     }
 }
 
+void StateSubject::AddObserver(StateObserver &aObserver)
+{
+    mObservers.push_back(&aObserver);
+}
+
+void StateSubject::UpdateState(Publisher::State aState)
+{
+    for (StateObserver *observer : mObservers)
+    {
+        observer->HandleMdnsState(aState);
+    }
+}
+
+void StateSubject::Clear(void)
+{
+    mObservers.clear();
+}
+
 } // namespace Mdns
 } // namespace otbr
 
diff --git a/src/mdns/mdns.hpp b/src/mdns/mdns.hpp
index 45dff98d..7044d1c9 100644
--- a/src/mdns/mdns.hpp
+++ b/src/mdns/mdns.hpp
@@ -665,6 +665,64 @@ protected:
     MdnsTelemetryInfo mTelemetryInfo{};
 };
 
+/**
+ * This interface is a mDNS State Observer.
+ */
+class StateObserver
+{
+public:
+    /**
+     * This method notifies the mDNS state to the observer.
+     *
+     * @param[in] aState  The mDNS State.
+     */
+    virtual void HandleMdnsState(Publisher::State aState) = 0;
+
+    /**
+     * The destructor.
+     */
+    virtual ~StateObserver(void) = default;
+};
+
+/**
+ * This class defines a mDNS State Subject.
+ */
+class StateSubject
+{
+public:
+    /**
+     * Constructor.
+     */
+    StateSubject(void) = default;
+
+    /**
+     * Destructor.
+     */
+    ~StateSubject(void) = default;
+
+    /**
+     * This method adds an mDNS State Observer to this subject.
+     *
+     * @param[in] aObserver  A reference to the observer. If it's nullptr, it won't be added.
+     */
+    void AddObserver(StateObserver &aObserver);
+
+    /**
+     * This method updates the mDNS State.
+     *
+     * @param[in] aState  The mDNS State.
+     */
+    void UpdateState(Publisher::State aState);
+
+    /**
+     * This method removes all the observers.
+     */
+    void Clear(void);
+
+private:
+    std::vector<StateObserver *> mObservers;
+};
+
 /**
  * @}
  */
diff --git a/src/mdns/mdns_avahi.cpp b/src/mdns/mdns_avahi.cpp
index 2d9719d6..548bad5f 100644
--- a/src/mdns/mdns_avahi.cpp
+++ b/src/mdns/mdns_avahi.cpp
@@ -1388,7 +1388,7 @@ void PublisherAvahi::ServiceResolver::HandleResolveHostResult(AvahiRecordBrowser
                  avahiError = AVAHI_ERR_INVALID_ADDRESS);
     address = Ip6Address(*static_cast<const uint8_t(*)[OTBR_IP6_ADDRESS_SIZE]>(aRdata));
 
-    VerifyOrExit(!address.IsLinkLocal() && !address.IsMulticast() && !address.IsLoopback() && !address.IsUnspecified(),
+    VerifyOrExit(!address.IsMulticast() && !address.IsLoopback() && !address.IsUnspecified(),
                  avahiError = AVAHI_ERR_INVALID_ADDRESS);
     otbrLogInfo("Resolved host address: %s %s", aEvent == AVAHI_BROWSER_NEW ? "add" : "remove",
                 address.ToString().c_str());
@@ -1519,7 +1519,7 @@ void PublisherAvahi::HostSubscription::HandleResolveResult(AvahiRecordBrowser
                  avahiError = AVAHI_ERR_INVALID_ADDRESS);
     address = Ip6Address(*static_cast<const uint8_t(*)[OTBR_IP6_ADDRESS_SIZE]>(aRdata));
 
-    VerifyOrExit(!address.IsLinkLocal() && !address.IsMulticast() && !address.IsLoopback() && !address.IsUnspecified(),
+    VerifyOrExit(!address.IsMulticast() && !address.IsLoopback() && !address.IsUnspecified(),
                  avahiError = AVAHI_ERR_INVALID_ADDRESS);
     otbrLogInfo("Resolved host address: %s %s", aEvent == AVAHI_BROWSER_NEW ? "add" : "remove",
                 address.ToString().c_str());
diff --git a/src/mdns/mdns_mdnssd.cpp b/src/mdns/mdns_mdnssd.cpp
index 22c13b22..0a35fc3b 100644
--- a/src/mdns/mdns_mdnssd.cpp
+++ b/src/mdns/mdns_mdnssd.cpp
@@ -469,6 +469,8 @@ otbrError PublisherMDnsSd::DnssdServiceRegistration::Register(void)
 
     otbrLogInfo("Registering service %s.%s", mName.c_str(), regType.c_str());
 
+    VerifyOrExit(GetPublisher().IsStarted(), dnsError = kDNSServiceErr_ServiceNotRunning);
+
     dnsError = DNSServiceRegister(&mServiceRef, kDNSServiceFlagsNoAutoRename, kDNSServiceInterfaceIndexAny,
                                   serviceNameCString, regType.c_str(),
                                   /* domain */ nullptr, hostNameCString, htons(mPort), mTxtData.size(), mTxtData.data(),
@@ -484,6 +486,7 @@ otbrError PublisherMDnsSd::DnssdServiceRegistration::Register(void)
         keyReg->Register();
     }
 
+exit:
     return GetPublisher().DnsErrorToOtbrError(dnsError);
 }
 
@@ -491,6 +494,7 @@ void PublisherMDnsSd::DnssdServiceRegistration::Unregister(void)
 {
     DnssdKeyRegistration *keyReg = mRelatedKeyReg;
 
+    VerifyOrExit(GetPublisher().IsStarted());
     VerifyOrExit(mServiceRef != nullptr);
 
     // If we have a related key registration associated with this
@@ -560,6 +564,8 @@ otbrError PublisherMDnsSd::DnssdHostRegistration::Register(void)
 
     otbrLogInfo("Registering new host %s", mName.c_str());
 
+    VerifyOrExit(GetPublisher().IsStarted(), dnsError = kDNSServiceErr_ServiceNotRunning);
+
     for (const Ip6Address &address : mAddresses)
     {
         DNSRecordRef recordRef = nullptr;
@@ -590,6 +596,7 @@ void PublisherMDnsSd::DnssdHostRegistration::Unregister(void)
 {
     DNSServiceErrorType dnsError;
 
+    VerifyOrExit(GetPublisher().IsStarted());
     VerifyOrExit(GetPublisher().mHostsRef != nullptr);
 
     for (size_t index = 0; index < mAddrRecordRefs.size(); index++)
@@ -674,6 +681,8 @@ otbrError PublisherMDnsSd::DnssdKeyRegistration::Register(void)
 
     otbrLogInfo("Registering new key %s", mName.c_str());
 
+    VerifyOrExit(GetPublisher().IsStarted(), dnsError = kDNSServiceErr_ServiceNotRunning);
+
     serviceReg = static_cast<DnssdServiceRegistration *>(GetPublisher().FindServiceRegistration(mName));
 
     if ((serviceReg != nullptr) && (serviceReg->mServiceRef != nullptr))
@@ -743,6 +752,8 @@ void PublisherMDnsSd::DnssdKeyRegistration::Unregister(void)
         otbrLogInfo("Unregistering key %s (was registered individually)", mName.c_str());
     }
 
+    VerifyOrExit(GetPublisher().IsStarted(), dnsError = kDNSServiceErr_ServiceNotRunning);
+
     VerifyOrExit(serviceRef != nullptr);
 
     dnsError = DNSServiceRemoveRecord(serviceRef, mRecordRef, /* flags */ 0);
@@ -1265,7 +1276,8 @@ void PublisherMDnsSd::ServiceInstanceResolution::HandleGetAddrInfoResult(DNSServ
     OTBR_UNUSED_VARIABLE(aInterfaceIndex);
 
     Ip6Address address;
-    bool       isAdd = (aFlags & kDNSServiceFlagsAdd) != 0;
+    bool       isAdd      = (aFlags & kDNSServiceFlagsAdd) != 0;
+    bool       moreComing = (aFlags & kDNSServiceFlagsMoreComing) != 0;
 
     otbrLog(aErrorCode == kDNSServiceErr_NoError ? OTBR_LOG_INFO : OTBR_LOG_WARNING, OTBR_LOG_TAG,
             "DNSServiceGetAddrInfo reply: flags=%" PRIu32 ", host=%s, sa_family=%u, error=%" PRId32, aFlags, aHostName,
@@ -1275,7 +1287,7 @@ void PublisherMDnsSd::ServiceInstanceResolution::HandleGetAddrInfoResult(DNSServ
     VerifyOrExit(aAddress->sa_family == AF_INET6);
 
     address.CopyFrom(*reinterpret_cast<const struct sockaddr_in6 *>(aAddress));
-    VerifyOrExit(!address.IsUnspecified() && !address.IsLinkLocal() && !address.IsMulticast() && !address.IsLoopback(),
+    VerifyOrExit(!address.IsUnspecified() && !address.IsMulticast() && !address.IsLoopback(),
                  otbrLogDebug("DNSServiceGetAddrInfo ignores address %s", address.ToString().c_str()));
 
     otbrLogInfo("DNSServiceGetAddrInfo reply: %s address=%s, ttl=%" PRIu32, isAdd ? "add" : "remove",
@@ -1292,7 +1304,7 @@ void PublisherMDnsSd::ServiceInstanceResolution::HandleGetAddrInfoResult(DNSServ
     mInstanceInfo.mTtl = aTtl;
 
 exit:
-    if (!mInstanceInfo.mAddresses.empty() || aErrorCode != kDNSServiceErr_NoError)
+    if ((!mInstanceInfo.mAddresses.empty() && !moreComing) || aErrorCode != kDNSServiceErr_NoError)
     {
         FinishResolution();
     }
@@ -1347,7 +1359,8 @@ void PublisherMDnsSd::HostSubscription::HandleResolveResult(DNSServiceRef
     OTBR_UNUSED_VARIABLE(aServiceRef);
 
     Ip6Address address;
-    bool       isAdd = (aFlags & kDNSServiceFlagsAdd) != 0;
+    bool       isAdd      = (aFlags & kDNSServiceFlagsAdd) != 0;
+    bool       moreComing = (aFlags & kDNSServiceFlagsMoreComing) != 0;
 
     otbrLog(aErrorCode == kDNSServiceErr_NoError ? OTBR_LOG_INFO : OTBR_LOG_WARNING, OTBR_LOG_TAG,
             "DNSServiceGetAddrInfo reply: flags=%" PRIu32 ", host=%s, sa_family=%u, error=%" PRId32, aFlags, aHostName,
@@ -1357,8 +1370,6 @@ void PublisherMDnsSd::HostSubscription::HandleResolveResult(DNSServiceRef
     VerifyOrExit(aAddress->sa_family == AF_INET6);
 
     address.CopyFrom(*reinterpret_cast<const struct sockaddr_in6 *>(aAddress));
-    VerifyOrExit(!address.IsLinkLocal(),
-                 otbrLogDebug("DNSServiceGetAddrInfo ignore link-local address %s", address.ToString().c_str()));
 
     otbrLogInfo("DNSServiceGetAddrInfo reply: %s address=%s, ttl=%" PRIu32, isAdd ? "add" : "remove",
                 address.ToString().c_str(), aTtl);
@@ -1375,14 +1386,15 @@ void PublisherMDnsSd::HostSubscription::HandleResolveResult(DNSServiceRef
     mHostInfo.mNetifIndex = aInterfaceIndex;
     mHostInfo.mTtl        = aTtl;
 
-    // NOTE: This `HostSubscription` object may be freed in `OnHostResolved`.
-    mPublisher.OnHostResolved(mHostName, mHostInfo);
-
 exit:
     if (aErrorCode != kDNSServiceErr_NoError)
     {
         mPublisher.OnHostResolveFailed(aHostName, aErrorCode);
     }
+    else if (!moreComing && !mHostInfo.mAddresses.empty())
+    {
+        mPublisher.OnHostResolved(mHostName, mHostInfo);
+    }
 }
 
 } // namespace Mdns
diff --git a/src/ncp/ncp_spinel.cpp b/src/ncp/ncp_spinel.cpp
deleted file mode 100644
index f3f0078e..00000000
--- a/src/ncp/ncp_spinel.cpp
+++ /dev/null
@@ -1,660 +0,0 @@
-/*
- *  Copyright (c) 2024, The OpenThread Authors.
- *  All rights reserved.
- *
- *  Redistribution and use in source and binary forms, with or without
- *  modification, are permitted provided that the following conditions are met:
- *  1. Redistributions of source code must retain the above copyright
- *     notice, this list of conditions and the following disclaimer.
- *  2. Redistributions in binary form must reproduce the above copyright
- *     notice, this list of conditions and the following disclaimer in the
- *     documentation and/or other materials provided with the distribution.
- *  3. Neither the name of the copyright holder nor the
- *     names of its contributors may be used to endorse or promote products
- *     derived from this software without specific prior written permission.
- *
- *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
- *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
- *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
- *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
- *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
- *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
- *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
- *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
- *  POSSIBILITY OF SUCH DAMAGE.
- */
-
-#define OTBR_LOG_TAG "NcpSpinel"
-
-#include "ncp_spinel.hpp"
-
-#include <stdarg.h>
-
-#include <algorithm>
-
-#include <openthread/dataset.h>
-#include <openthread/thread.h>
-
-#include "common/code_utils.hpp"
-#include "common/logging.hpp"
-#include "lib/spinel/spinel.h"
-#include "lib/spinel/spinel_decoder.hpp"
-#include "lib/spinel/spinel_driver.hpp"
-#include "lib/spinel/spinel_helper.hpp"
-
-namespace otbr {
-namespace Ncp {
-
-static constexpr char kSpinelDataUnpackFormat[] = "CiiD";
-
-NcpSpinel::NcpSpinel(void)
-    : mSpinelDriver(nullptr)
-    , mCmdTidsInUse(0)
-    , mCmdNextTid(1)
-    , mNcpBuffer(mTxBuffer, kTxBufferSize)
-    , mEncoder(mNcpBuffer)
-    , mIid(SPINEL_HEADER_INVALID_IID)
-    , mPropsObserver(nullptr)
-{
-    std::fill_n(mWaitingKeyTable, SPINEL_PROP_LAST_STATUS, sizeof(mWaitingKeyTable));
-    memset(mCmdTable, 0, sizeof(mCmdTable));
-}
-
-void NcpSpinel::Init(ot::Spinel::SpinelDriver &aSpinelDriver, PropsObserver &aObserver)
-{
-    mSpinelDriver  = &aSpinelDriver;
-    mPropsObserver = &aObserver;
-    mIid           = mSpinelDriver->GetIid();
-    mSpinelDriver->SetFrameHandler(&HandleReceivedFrame, &HandleSavedFrame, this);
-}
-
-void NcpSpinel::Deinit(void)
-{
-    mSpinelDriver              = nullptr;
-    mIp6AddressTableCallback   = nullptr;
-    mNetifStateChangedCallback = nullptr;
-}
-
-otbrError NcpSpinel::SpinelDataUnpack(const uint8_t *aDataIn, spinel_size_t aDataLen, const char *aPackFormat, ...)
-{
-    otbrError      error = OTBR_ERROR_NONE;
-    spinel_ssize_t unpacked;
-    va_list        args;
-
-    va_start(args, aPackFormat);
-    unpacked = spinel_datatype_vunpack(aDataIn, aDataLen, aPackFormat, args);
-    va_end(args);
-
-    VerifyOrExit(unpacked > 0, error = OTBR_ERROR_PARSE);
-
-exit:
-    return error;
-}
-
-void NcpSpinel::DatasetSetActiveTlvs(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs, AsyncTaskPtr aAsyncTask)
-{
-    otError      error        = OT_ERROR_NONE;
-    EncodingFunc encodingFunc = [this, &aActiveOpDatasetTlvs] {
-        return mEncoder.WriteData(aActiveOpDatasetTlvs.mTlvs, aActiveOpDatasetTlvs.mLength);
-    };
-
-    VerifyOrExit(mDatasetSetActiveTask == nullptr, error = OT_ERROR_BUSY);
-
-    SuccessOrExit(error = SetProperty(SPINEL_PROP_THREAD_ACTIVE_DATASET_TLVS, encodingFunc));
-    mDatasetSetActiveTask = aAsyncTask;
-
-exit:
-    if (error != OT_ERROR_NONE)
-    {
-        mTaskRunner.Post([aAsyncTask, error](void) { aAsyncTask->SetResult(error, "Failed to set active dataset!"); });
-    }
-}
-
-void NcpSpinel::DatasetMgmtSetPending(std::shared_ptr<otOperationalDatasetTlvs> aPendingOpDatasetTlvsPtr,
-                                      AsyncTaskPtr                              aAsyncTask)
-{
-    otError      error        = OT_ERROR_NONE;
-    EncodingFunc encodingFunc = [this, aPendingOpDatasetTlvsPtr] {
-        return mEncoder.WriteData(aPendingOpDatasetTlvsPtr->mTlvs, aPendingOpDatasetTlvsPtr->mLength);
-    };
-
-    VerifyOrExit(mDatasetMgmtSetPendingTask == nullptr, error = OT_ERROR_BUSY);
-
-    SuccessOrExit(error = SetProperty(SPINEL_PROP_THREAD_MGMT_SET_PENDING_DATASET_TLVS, encodingFunc));
-    mDatasetMgmtSetPendingTask = aAsyncTask;
-
-exit:
-    if (error != OT_ERROR_NONE)
-    {
-        mTaskRunner.Post([aAsyncTask, error] { aAsyncTask->SetResult(error, "Failed to set pending dataset!"); });
-    }
-}
-
-void NcpSpinel::Ip6SetEnabled(bool aEnable, AsyncTaskPtr aAsyncTask)
-{
-    otError      error        = OT_ERROR_NONE;
-    EncodingFunc encodingFunc = [this, aEnable] { return mEncoder.WriteBool(aEnable); };
-
-    VerifyOrExit(mIp6SetEnabledTask == nullptr, error = OT_ERROR_BUSY);
-
-    SuccessOrExit(error = SetProperty(SPINEL_PROP_NET_IF_UP, encodingFunc));
-    mIp6SetEnabledTask = aAsyncTask;
-
-exit:
-    if (error != OT_ERROR_NONE)
-    {
-        mTaskRunner.Post(
-            [aAsyncTask, error](void) { aAsyncTask->SetResult(error, "Failed to enable the network interface!"); });
-    }
-    return;
-}
-
-otbrError NcpSpinel::Ip6Send(const uint8_t *aData, uint16_t aLength)
-{
-    // TODO: Impelement this function.
-    OTBR_UNUSED_VARIABLE(aData);
-    OTBR_UNUSED_VARIABLE(aLength);
-
-    return OTBR_ERROR_NONE;
-}
-
-void NcpSpinel::ThreadSetEnabled(bool aEnable, AsyncTaskPtr aAsyncTask)
-{
-    otError      error        = OT_ERROR_NONE;
-    EncodingFunc encodingFunc = [this, aEnable] { return mEncoder.WriteBool(aEnable); };
-
-    VerifyOrExit(mThreadSetEnabledTask == nullptr, error = OT_ERROR_BUSY);
-
-    SuccessOrExit(error = SetProperty(SPINEL_PROP_NET_STACK_UP, encodingFunc));
-    mThreadSetEnabledTask = aAsyncTask;
-
-exit:
-    if (error != OT_ERROR_NONE)
-    {
-        mTaskRunner.Post(
-            [aAsyncTask, error](void) { aAsyncTask->SetResult(error, "Failed to enable the Thread network!"); });
-    }
-    return;
-}
-
-void NcpSpinel::ThreadDetachGracefully(AsyncTaskPtr aAsyncTask)
-{
-    otError      error        = OT_ERROR_NONE;
-    EncodingFunc encodingFunc = [] { return OT_ERROR_NONE; };
-
-    VerifyOrExit(mThreadDetachGracefullyTask == nullptr, error = OT_ERROR_BUSY);
-
-    SuccessOrExit(error = SetProperty(SPINEL_PROP_NET_LEAVE_GRACEFULLY, encodingFunc));
-    mThreadDetachGracefullyTask = aAsyncTask;
-
-exit:
-    if (error != OT_ERROR_NONE)
-    {
-        mTaskRunner.Post([aAsyncTask, error](void) { aAsyncTask->SetResult(error, "Failed to detach gracefully!"); });
-    }
-    return;
-}
-
-void NcpSpinel::ThreadErasePersistentInfo(AsyncTaskPtr aAsyncTask)
-{
-    otError      error = OT_ERROR_NONE;
-    spinel_tid_t tid   = GetNextTid();
-
-    VerifyOrExit(mThreadErasePersistentInfoTask == nullptr, error = OT_ERROR_BUSY);
-
-    SuccessOrExit(error = mSpinelDriver->SendCommand(SPINEL_CMD_NET_CLEAR, SPINEL_PROP_LAST_STATUS, tid));
-
-    mWaitingKeyTable[tid]          = SPINEL_PROP_LAST_STATUS;
-    mCmdTable[tid]                 = SPINEL_CMD_NET_CLEAR;
-    mThreadErasePersistentInfoTask = aAsyncTask;
-
-exit:
-    if (error != OT_ERROR_NONE)
-    {
-        FreeTidTableItem(tid);
-        mTaskRunner.Post(
-            [aAsyncTask, error](void) { aAsyncTask->SetResult(error, "Failed to erase persistent info!"); });
-    }
-}
-
-void NcpSpinel::HandleReceivedFrame(const uint8_t *aFrame,
-                                    uint16_t       aLength,
-                                    uint8_t        aHeader,
-                                    bool          &aSave,
-                                    void          *aContext)
-{
-    static_cast<NcpSpinel *>(aContext)->HandleReceivedFrame(aFrame, aLength, aHeader, aSave);
-}
-
-void NcpSpinel::HandleReceivedFrame(const uint8_t *aFrame, uint16_t aLength, uint8_t aHeader, bool &aShouldSaveFrame)
-{
-    spinel_tid_t tid = SPINEL_HEADER_GET_TID(aHeader);
-
-    if (tid == 0)
-    {
-        HandleNotification(aFrame, aLength);
-    }
-    else if (tid < kMaxTids)
-    {
-        HandleResponse(tid, aFrame, aLength);
-    }
-    else
-    {
-        otbrLogCrit("Received unexpected tid: %u", tid);
-    }
-
-    aShouldSaveFrame = false;
-}
-
-void NcpSpinel::HandleSavedFrame(const uint8_t *aFrame, uint16_t aLength, void *aContext)
-{
-    /* Intentionally Empty */
-    OT_UNUSED_VARIABLE(aFrame);
-    OT_UNUSED_VARIABLE(aLength);
-    OT_UNUSED_VARIABLE(aContext);
-}
-
-void NcpSpinel::HandleNotification(const uint8_t *aFrame, uint16_t aLength)
-{
-    spinel_prop_key_t key;
-    spinel_size_t     len  = 0;
-    uint8_t          *data = nullptr;
-    uint32_t          cmd;
-    uint8_t           header;
-    otbrError         error = OTBR_ERROR_NONE;
-
-    SuccessOrExit(error = SpinelDataUnpack(aFrame, aLength, kSpinelDataUnpackFormat, &header, &cmd, &key, &data, &len));
-    VerifyOrExit(SPINEL_HEADER_GET_TID(header) == 0, error = OTBR_ERROR_PARSE);
-    VerifyOrExit(cmd == SPINEL_CMD_PROP_VALUE_IS);
-    HandleValueIs(key, data, static_cast<uint16_t>(len));
-
-exit:
-    otbrLogResult(error, "HandleNotification: %s", __FUNCTION__);
-}
-
-void NcpSpinel::HandleResponse(spinel_tid_t aTid, const uint8_t *aFrame, uint16_t aLength)
-{
-    spinel_prop_key_t key;
-    spinel_size_t     len  = 0;
-    uint8_t          *data = nullptr;
-    uint32_t          cmd;
-    uint8_t           header;
-    otbrError         error          = OTBR_ERROR_NONE;
-    FailureHandler    failureHandler = nullptr;
-
-    SuccessOrExit(error = SpinelDataUnpack(aFrame, aLength, kSpinelDataUnpackFormat, &header, &cmd, &key, &data, &len));
-
-    VerifyOrExit(cmd == SPINEL_CMD_PROP_VALUE_IS, error = OTBR_ERROR_INVALID_STATE);
-
-    switch (mCmdTable[aTid])
-    {
-    case SPINEL_CMD_PROP_VALUE_SET:
-    {
-        error = HandleResponseForPropSet(aTid, key, data, len);
-        break;
-    }
-    case SPINEL_CMD_NET_CLEAR:
-    {
-        spinel_status_t status = SPINEL_STATUS_OK;
-
-        SuccessOrExit(error = SpinelDataUnpack(data, len, SPINEL_DATATYPE_UINT_PACKED_S, &status));
-        CallAndClear(mThreadErasePersistentInfoTask, ot::Spinel::SpinelStatusToOtError(status));
-        break;
-    }
-    default:
-        break;
-    }
-
-exit:
-    if (error == OTBR_ERROR_INVALID_STATE)
-    {
-        otbrLogCrit("Received unexpected response with (cmd:%u, key:%u), waiting (cmd:%u, key:%u) for tid:%u", cmd, key,
-                    mCmdTable[aTid], mWaitingKeyTable[aTid], aTid);
-    }
-    else if (error == OTBR_ERROR_PARSE)
-    {
-        otbrLogCrit("Error parsing response with tid:%u", aTid);
-    }
-    FreeTidTableItem(aTid);
-}
-
-void NcpSpinel::HandleValueIs(spinel_prop_key_t aKey, const uint8_t *aBuffer, uint16_t aLength)
-{
-    otbrError error = OTBR_ERROR_NONE;
-
-    switch (aKey)
-    {
-    case SPINEL_PROP_LAST_STATUS:
-    {
-        spinel_status_t status = SPINEL_STATUS_OK;
-
-        SuccessOrExit(error = SpinelDataUnpack(aBuffer, aLength, SPINEL_DATATYPE_UINT_PACKED_S, &status));
-
-        otbrLogInfo("NCP last status: %s", spinel_status_to_cstr(status));
-        break;
-    }
-
-    case SPINEL_PROP_NET_ROLE:
-    {
-        spinel_net_role_t role = SPINEL_NET_ROLE_DISABLED;
-        otDeviceRole      deviceRole;
-
-        SuccessOrExit(error = SpinelDataUnpack(aBuffer, aLength, SPINEL_DATATYPE_UINT8_S, &role));
-
-        deviceRole = SpinelRoleToDeviceRole(role);
-        mPropsObserver->SetDeviceRole(deviceRole);
-
-        otbrLogInfo("Device role changed to %s", otThreadDeviceRoleToString(deviceRole));
-        break;
-    }
-
-    case SPINEL_PROP_NET_LEAVE_GRACEFULLY:
-    {
-        CallAndClear(mThreadDetachGracefullyTask, OT_ERROR_NONE);
-        break;
-    }
-
-    case SPINEL_PROP_THREAD_MGMT_SET_PENDING_DATASET_TLVS:
-    {
-        spinel_status_t status = SPINEL_STATUS_OK;
-
-        SuccessOrExit(error = SpinelDataUnpack(aBuffer, aLength, SPINEL_DATATYPE_UINT_PACKED_S, &status));
-        CallAndClear(mDatasetMgmtSetPendingTask, ot::Spinel::SpinelStatusToOtError(status));
-        break;
-    }
-
-    case SPINEL_PROP_IPV6_ADDRESS_TABLE:
-    {
-        std::vector<Ip6AddressInfo> addressInfoTable;
-
-        VerifyOrExit(ParseIp6AddressTable(aBuffer, aLength, addressInfoTable) == OT_ERROR_NONE,
-                     error = OTBR_ERROR_PARSE);
-        SafeInvoke(mIp6AddressTableCallback, addressInfoTable);
-        break;
-    }
-
-    case SPINEL_PROP_IPV6_MULTICAST_ADDRESS_TABLE:
-    {
-        std::vector<Ip6Address> addressTable;
-
-        VerifyOrExit(ParseIp6MulticastAddresses(aBuffer, aLength, addressTable) == OT_ERROR_NONE,
-                     error = OTBR_ERROR_PARSE);
-        SafeInvoke(mIp6MulticastAddressTableCallback, addressTable);
-        break;
-    }
-
-    case SPINEL_PROP_NET_IF_UP:
-    {
-        bool isUp;
-        SuccessOrExit(error = SpinelDataUnpack(aBuffer, aLength, SPINEL_DATATYPE_BOOL_S, &isUp));
-        SafeInvoke(mNetifStateChangedCallback, isUp);
-        break;
-    }
-
-    default:
-        otbrLogWarning("Received uncognized key: %u", aKey);
-        break;
-    }
-
-exit:
-    otbrLogResult(error, "NcpSpinel: %s", __FUNCTION__);
-    return;
-}
-
-otbrError NcpSpinel::HandleResponseForPropSet(spinel_tid_t      aTid,
-                                              spinel_prop_key_t aKey,
-                                              const uint8_t    *aData,
-                                              uint16_t          aLength)
-{
-    OTBR_UNUSED_VARIABLE(aData);
-    OTBR_UNUSED_VARIABLE(aLength);
-
-    otbrError error = OTBR_ERROR_NONE;
-
-    switch (mWaitingKeyTable[aTid])
-    {
-    case SPINEL_PROP_THREAD_ACTIVE_DATASET_TLVS:
-        VerifyOrExit(aKey == SPINEL_PROP_THREAD_ACTIVE_DATASET_TLVS, error = OTBR_ERROR_INVALID_STATE);
-        CallAndClear(mDatasetSetActiveTask, OT_ERROR_NONE);
-        {
-            otOperationalDatasetTlvs datasetTlvs;
-            VerifyOrExit(ParseOperationalDatasetTlvs(aData, aLength, datasetTlvs) == OT_ERROR_NONE,
-                         error = OTBR_ERROR_PARSE);
-            mPropsObserver->SetDatasetActiveTlvs(datasetTlvs);
-        }
-        break;
-
-    case SPINEL_PROP_NET_IF_UP:
-        VerifyOrExit(aKey == SPINEL_PROP_NET_IF_UP, error = OTBR_ERROR_INVALID_STATE);
-        CallAndClear(mIp6SetEnabledTask, OT_ERROR_NONE);
-        {
-            bool isUp;
-            SuccessOrExit(error = SpinelDataUnpack(aData, aLength, SPINEL_DATATYPE_BOOL_S, &isUp));
-            SafeInvoke(mNetifStateChangedCallback, isUp);
-        }
-        break;
-
-    case SPINEL_PROP_NET_STACK_UP:
-        VerifyOrExit(aKey == SPINEL_PROP_NET_STACK_UP, error = OTBR_ERROR_INVALID_STATE);
-        CallAndClear(mThreadSetEnabledTask, OT_ERROR_NONE);
-        break;
-
-    case SPINEL_PROP_THREAD_MGMT_SET_PENDING_DATASET_TLVS:
-        if (aKey == SPINEL_PROP_LAST_STATUS)
-        { // Failed case
-            spinel_status_t status = SPINEL_STATUS_OK;
-
-            SuccessOrExit(error = SpinelDataUnpack(aData, aLength, SPINEL_DATATYPE_UINT_PACKED_S, &status));
-            CallAndClear(mDatasetMgmtSetPendingTask, ot::Spinel::SpinelStatusToOtError(status));
-        }
-        else if (aKey != SPINEL_PROP_THREAD_MGMT_SET_PENDING_DATASET_TLVS)
-        {
-            ExitNow(error = OTBR_ERROR_INVALID_STATE);
-        }
-        break;
-
-    default:
-        VerifyOrExit(aKey == mWaitingKeyTable[aTid], error = OTBR_ERROR_INVALID_STATE);
-        break;
-    }
-
-exit:
-    return error;
-}
-
-spinel_tid_t NcpSpinel::GetNextTid(void)
-{
-    spinel_tid_t tid = mCmdNextTid;
-
-    while (((1 << tid) & mCmdTidsInUse) != 0)
-    {
-        tid = SPINEL_GET_NEXT_TID(tid);
-
-        if (tid == mCmdNextTid)
-        {
-            // We looped back to `mCmdNextTid` indicating that all
-            // TIDs are in-use.
-
-            ExitNow(tid = 0);
-        }
-    }
-
-    mCmdTidsInUse |= (1 << tid);
-    mCmdNextTid = SPINEL_GET_NEXT_TID(tid);
-
-exit:
-    return tid;
-}
-
-void NcpSpinel::FreeTidTableItem(spinel_tid_t aTid)
-{
-    mCmdTidsInUse &= ~(1 << aTid);
-
-    mCmdTable[aTid]        = SPINEL_CMD_NOOP;
-    mWaitingKeyTable[aTid] = SPINEL_PROP_LAST_STATUS;
-}
-
-otError NcpSpinel::SetProperty(spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc)
-{
-    otError      error  = OT_ERROR_NONE;
-    spinel_tid_t tid    = GetNextTid();
-    uint8_t      header = SPINEL_HEADER_FLAG | SPINEL_HEADER_IID(mIid) | tid;
-
-    VerifyOrExit(tid != 0, error = OT_ERROR_BUSY);
-    SuccessOrExit(error = mEncoder.BeginFrame(header, SPINEL_CMD_PROP_VALUE_SET, aKey));
-    SuccessOrExit(error = aEncodingFunc());
-    SuccessOrExit(error = mEncoder.EndFrame());
-    SuccessOrExit(error = SendEncodedFrame());
-
-    mCmdTable[tid]        = SPINEL_CMD_PROP_VALUE_SET;
-    mWaitingKeyTable[tid] = aKey;
-exit:
-    if (error != OT_ERROR_NONE)
-    {
-        FreeTidTableItem(tid);
-    }
-    return error;
-}
-
-otError NcpSpinel::SendEncodedFrame(void)
-{
-    otError  error = OT_ERROR_NONE;
-    uint8_t  frame[kTxBufferSize];
-    uint16_t frameLength;
-
-    SuccessOrExit(error = mNcpBuffer.OutFrameBegin());
-    frameLength = mNcpBuffer.OutFrameGetLength();
-    VerifyOrExit(mNcpBuffer.OutFrameRead(frameLength, frame) == frameLength, error = OT_ERROR_FAILED);
-    SuccessOrExit(error = mSpinelDriver->GetSpinelInterface()->SendFrame(frame, frameLength));
-
-exit:
-    error = mNcpBuffer.OutFrameRemove();
-    return error;
-}
-
-otError NcpSpinel::ParseIp6AddressTable(const uint8_t               *aBuf,
-                                        uint16_t                     aLength,
-                                        std::vector<Ip6AddressInfo> &aAddressTable)
-{
-    otError             error = OT_ERROR_NONE;
-    ot::Spinel::Decoder decoder;
-
-    VerifyOrExit(aBuf != nullptr, error = OT_ERROR_INVALID_ARGS);
-    decoder.Init(aBuf, aLength);
-
-    while (!decoder.IsAllReadInStruct())
-    {
-        Ip6AddressInfo      cur;
-        const otIp6Address *addr;
-        uint8_t             prefixLength;
-        uint32_t            preferredLifetime;
-        uint32_t            validLifetime;
-
-        SuccessOrExit(error = decoder.OpenStruct());
-        SuccessOrExit(error = decoder.ReadIp6Address(addr));
-        memcpy(&cur.mAddress, addr, sizeof(otIp6Address));
-        SuccessOrExit(error = decoder.ReadUint8(prefixLength));
-        cur.mPrefixLength = prefixLength;
-        SuccessOrExit(error = decoder.ReadUint32(preferredLifetime));
-        cur.mPreferred = preferredLifetime ? true : false;
-        SuccessOrExit(error = decoder.ReadUint32(validLifetime));
-        OTBR_UNUSED_VARIABLE(validLifetime);
-        SuccessOrExit((error = decoder.CloseStruct()));
-
-        aAddressTable.push_back(cur);
-    }
-
-exit:
-    return error;
-}
-
-otError NcpSpinel::ParseIp6MulticastAddresses(const uint8_t *aBuf, uint8_t aLen, std::vector<Ip6Address> &aAddressList)
-{
-    otError             error = OT_ERROR_NONE;
-    ot::Spinel::Decoder decoder;
-
-    VerifyOrExit(aBuf != nullptr, error = OT_ERROR_INVALID_ARGS);
-
-    decoder.Init(aBuf, aLen);
-
-    while (!decoder.IsAllReadInStruct())
-    {
-        const otIp6Address *addr;
-
-        SuccessOrExit(error = decoder.OpenStruct());
-        SuccessOrExit(error = decoder.ReadIp6Address(addr));
-        aAddressList.emplace_back(Ip6Address(*addr));
-        SuccessOrExit((error = decoder.CloseStruct()));
-    }
-
-exit:
-    return error;
-}
-
-otError NcpSpinel::ParseIp6StreamNet(const uint8_t *aBuf, uint8_t aLen, const uint8_t *&aData, uint16_t &aDataLen)
-{
-    otError             error = OT_ERROR_NONE;
-    ot::Spinel::Decoder decoder;
-
-    VerifyOrExit(aBuf != nullptr, error = OT_ERROR_INVALID_ARGS);
-
-    decoder.Init(aBuf, aLen);
-    error = decoder.ReadDataWithLen(aData, aDataLen);
-
-exit:
-    return error;
-}
-
-otError NcpSpinel::ParseOperationalDatasetTlvs(const uint8_t            *aBuf,
-                                               uint8_t                   aLen,
-                                               otOperationalDatasetTlvs &aDatasetTlvs)
-{
-    otError             error = OT_ERROR_NONE;
-    ot::Spinel::Decoder decoder;
-    const uint8_t      *datasetTlvsData;
-    uint16_t            datasetTlvsLen;
-
-    decoder.Init(aBuf, aLen);
-    SuccessOrExit(error = decoder.ReadData(datasetTlvsData, datasetTlvsLen));
-    VerifyOrExit(datasetTlvsLen <= sizeof(aDatasetTlvs.mTlvs), error = OT_ERROR_PARSE);
-
-    memcpy(aDatasetTlvs.mTlvs, datasetTlvsData, datasetTlvsLen);
-    aDatasetTlvs.mLength = datasetTlvsLen;
-
-exit:
-    return error;
-}
-
-otDeviceRole NcpSpinel::SpinelRoleToDeviceRole(spinel_net_role_t aRole)
-{
-    otDeviceRole role = OT_DEVICE_ROLE_DISABLED;
-
-    switch (aRole)
-    {
-    case SPINEL_NET_ROLE_DISABLED:
-        role = OT_DEVICE_ROLE_DISABLED;
-        break;
-    case SPINEL_NET_ROLE_DETACHED:
-        role = OT_DEVICE_ROLE_DETACHED;
-        break;
-    case SPINEL_NET_ROLE_CHILD:
-        role = OT_DEVICE_ROLE_CHILD;
-        break;
-    case SPINEL_NET_ROLE_ROUTER:
-        role = OT_DEVICE_ROLE_ROUTER;
-        break;
-    case SPINEL_NET_ROLE_LEADER:
-        role = OT_DEVICE_ROLE_LEADER;
-        break;
-    default:
-        otbrLogWarning("Unsupported spinel net role: %u", aRole);
-        break;
-    }
-
-    return role;
-}
-
-} // namespace Ncp
-} // namespace otbr
diff --git a/src/openwrt/ubus/otubus.cpp b/src/openwrt/ubus/otubus.cpp
index ef762d0d..45b9ed4e 100644
--- a/src/openwrt/ubus/otubus.cpp
+++ b/src/openwrt/ubus/otubus.cpp
@@ -44,7 +44,7 @@
 #include <openthread/thread_ftd.h>
 
 #include "common/logging.hpp"
-#include "ncp/rcp_host.hpp"
+#include "host/rcp_host.hpp"
 
 namespace otbr {
 namespace ubus {
@@ -58,7 +58,7 @@ const static int PANID_LENGTH      = 10;
 const static int XPANID_LENGTH     = 64;
 const static int NETWORKKEY_LENGTH = 64;
 
-UbusServer::UbusServer(Ncp::RcpHost *aHost, std::mutex *aMutex)
+UbusServer::UbusServer(Host::RcpHost *aHost, std::mutex *aMutex)
     : mIfFinishScan(false)
     , mContext(nullptr)
     , mSockPath(nullptr)
@@ -78,7 +78,7 @@ UbusServer &UbusServer::GetInstance(void)
     return *sUbusServerInstance;
 }
 
-void UbusServer::Initialize(Ncp::RcpHost *aHost, std::mutex *aMutex)
+void UbusServer::Initialize(Host::RcpHost *aHost, std::mutex *aMutex)
 {
     sUbusServerInstance = new UbusServer(aHost, aMutex);
 }
diff --git a/src/openwrt/ubus/otubus.hpp b/src/openwrt/ubus/otubus.hpp
index f9131c73..f87e9c1c 100644
--- a/src/openwrt/ubus/otubus.hpp
+++ b/src/openwrt/ubus/otubus.hpp
@@ -46,7 +46,7 @@
 
 #include "common/code_utils.hpp"
 #include "common/mainloop.hpp"
-#include "ncp/rcp_host.hpp"
+#include "host/rcp_host.hpp"
 
 extern "C" {
 #include <libubox/blobmsg_json.h>
@@ -57,7 +57,7 @@ extern "C" {
 }
 
 namespace otbr {
-namespace Ncp {
+namespace Host {
 class RcpHost;
 }
 
@@ -79,7 +79,7 @@ public:
      * @param[in] aHost  A pointer to OpenThread Controller structure.
      * @param[in] aMutex       A pointer to mutex.
      */
-    static void Initialize(Ncp::RcpHost *aHost, std::mutex *aMutex);
+    static void Initialize(Host::RcpHost *aHost, std::mutex *aMutex);
 
     /**
      * This method return the instance of the global UbusServer.
@@ -750,7 +750,7 @@ private:
     const char          *mSockPath;
     struct blob_buf      mBuf;
     struct blob_buf      mNetworkdataBuf;
-    Ncp::RcpHost        *mHost;
+    Host::RcpHost       *mHost;
     std::mutex          *mHostMutex;
     time_t               mSecond;
     enum
@@ -764,7 +764,7 @@ private:
      * @param[in] aHost    The pointer to OpenThread Controller structure.
      * @param[in] aMutex   A pointer to mutex.
      */
-    UbusServer(Ncp::RcpHost *aHost, std::mutex *aMutex);
+    UbusServer(Host::RcpHost *aHost, std::mutex *aMutex);
 
     /**
      * This method start scan.
@@ -1083,7 +1083,7 @@ public:
      *
      * @param[in] aHost  A reference to the Thread controller.
      */
-    UBusAgent(otbr::Ncp::RcpHost &aHost)
+    UBusAgent(otbr::Host::RcpHost &aHost)
         : mHost(aHost)
         , mThreadMutex()
     {
@@ -1100,8 +1100,8 @@ public:
 private:
     static void UbusServerRun(void) { otbr::ubus::UbusServer::GetInstance().InstallUbusObject(); }
 
-    otbr::Ncp::RcpHost &mHost;
-    std::mutex          mThreadMutex;
+    otbr::Host::RcpHost &mHost;
+    std::mutex           mThreadMutex;
 };
 } // namespace ubus
 } // namespace otbr
diff --git a/src/proto/CMakeLists.txt b/src/proto/CMakeLists.txt
index 3659b515..81b397c4 100644
--- a/src/proto/CMakeLists.txt
+++ b/src/proto/CMakeLists.txt
@@ -1,9 +1,9 @@
 # Config brew protobuf version for Mac, see .github/workflows/macOS.yml
 if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
     set(Protobuf_PREFIX_PATH
-        "/usr/local/opt/protobuf@21/include"            
-        "/usr/local/opt/protobuf@21/lib"             
-        "/usr/local/opt/protobuf@21/bin")
+        "/opt/homebrew/opt/protobuf@21/include"
+        "/opt/homebrew/opt/protobuf@21/lib"
+        "/opt/homebrew/opt/protobuf@21/bin")
     list(APPEND CMAKE_PREFIX_PATH "${Protobuf_PREFIX_PATH}")
 endif()
 find_package(Protobuf REQUIRED)
diff --git a/src/rest/json.cpp b/src/rest/json.cpp
index d10db85d..943e0ee4 100644
--- a/src/rest/json.cpp
+++ b/src/rest/json.cpp
@@ -30,12 +30,15 @@
 #include <sstream>
 
 #include "common/code_utils.hpp"
-#include "common/types.hpp"
 
 extern "C" {
 #include <cJSON.h>
 }
 
+#ifndef BITS_PER_BYTE
+#define BITS_PER_BYTE 8
+#endif
+
 namespace otbr {
 namespace rest {
 namespace Json {
@@ -926,6 +929,193 @@ exit:
     return ret;
 }
 
+cJSON *JoinerInfo2Json(const otJoinerInfo &aJoinerInfo)
+{
+    cJSON *node = cJSON_CreateObject();
+
+    cJSON_AddItemToObject(node, "Pskd", cJSON_CreateString(aJoinerInfo.mPskd.m8));
+    if (aJoinerInfo.mType == OT_JOINER_INFO_TYPE_EUI64)
+    {
+        cJSON_AddItemToObject(node, "Eui64", Bytes2HexJson(aJoinerInfo.mSharedId.mEui64.m8, OT_EXT_ADDRESS_SIZE));
+    }
+    else if (aJoinerInfo.mType == OT_JOINER_INFO_TYPE_DISCERNER)
+    {
+        char hexValue[((OT_JOINER_MAX_DISCERNER_LENGTH / 8) * 2) + 1]                              = {0};
+        char string[sizeof("0x") + ((OT_JOINER_MAX_DISCERNER_LENGTH / 8) * 2) + sizeof("/xx") + 1] = {0};
+
+        otbr::Utils::Long2Hex(aJoinerInfo.mSharedId.mDiscerner.mValue, hexValue);
+        snprintf(string, sizeof(string), "0x%s/%d", hexValue, aJoinerInfo.mSharedId.mDiscerner.mLength);
+        cJSON_AddItemToObject(node, "Discerner", cJSON_CreateString(string));
+    }
+    else
+    {
+        cJSON_AddItemToObject(node, "JoinerId", cJSON_CreateString("*"));
+    }
+    cJSON_AddItemToObject(node, "Timeout", cJSON_CreateNumber(aJoinerInfo.mExpirationTime));
+
+    return node;
+}
+
+std::string JoinerInfo2JsonString(const otJoinerInfo &aJoinerInfo)
+{
+    cJSON      *node;
+    std::string ret;
+
+    node = JoinerInfo2Json(aJoinerInfo);
+    ret  = Json2String(node);
+    cJSON_Delete(node);
+
+    return ret;
+}
+
+otbrError StringDiscerner2Discerner(char *aString, otJoinerDiscerner &aDiscerner)
+{
+    otbrError error = OTBR_ERROR_NONE;
+    char     *separator;
+    uint8_t   byteLength;
+    uint8_t   byteSwapBuffer[OT_JOINER_MAX_DISCERNER_LENGTH / BITS_PER_BYTE] = {0};
+    uint8_t  *buffer                                                         = (uint8_t *)&aDiscerner.mValue;
+
+    separator = strstr(aString, "/");
+    VerifyOrExit(separator != nullptr, error = OTBR_ERROR_NOT_FOUND);
+    VerifyOrExit(sscanf(separator + 1, "%hhu", &aDiscerner.mLength) == 1, error = OTBR_ERROR_INVALID_ARGS);
+    VerifyOrExit(aDiscerner.mLength > 0 && aDiscerner.mLength <= OT_JOINER_MAX_DISCERNER_LENGTH,
+                 error = OTBR_ERROR_INVALID_ARGS);
+
+    if (memcmp(aString, "0x", 2) == 0)
+    {
+        aString += 2;
+    }
+
+    *separator = '\0';
+    byteLength = Hex2BytesJsonString(std::string(aString), byteSwapBuffer, OT_JOINER_MAX_DISCERNER_LENGTH);
+    VerifyOrExit(byteLength <= (1 + ((aDiscerner.mLength - 1) / BITS_PER_BYTE)), error = OTBR_ERROR_INVALID_ARGS);
+
+    // The discerner is expected to be big endian
+    for (uint8_t i = 0; i < byteLength; i++)
+    {
+        buffer[i] = byteSwapBuffer[byteLength - i - 1];
+    }
+
+exit:
+    return error;
+}
+
+bool JsonJoinerInfo2JoinerInfo(const cJSON *jsonJoinerInfo, otJoinerInfo &aJoinerInfo)
+{
+    cJSON *value;
+    bool   ret = false;
+
+    aJoinerInfo.mType = OT_JOINER_INFO_TYPE_ANY;
+    memset(&aJoinerInfo.mSharedId.mEui64, 0, sizeof(aJoinerInfo.mSharedId.mEui64));
+    memset(&aJoinerInfo.mPskd.m8, 0, sizeof(aJoinerInfo.mPskd.m8));
+
+    value = cJSON_GetObjectItemCaseSensitive(jsonJoinerInfo, "Pskd");
+    if (cJSON_IsString(value))
+    {
+        VerifyOrExit(value->valuestring != nullptr);
+        VerifyOrExit(strlen(value->valuestring) <= OT_JOINER_MAX_PSKD_LENGTH);
+        strncpy(aJoinerInfo.mPskd.m8, value->valuestring, OT_JOINER_MAX_PSKD_LENGTH);
+    }
+    else
+    {
+        ExitNow();
+    }
+
+    value = cJSON_GetObjectItemCaseSensitive(jsonJoinerInfo, "JoinerId");
+    if (cJSON_IsString(value))
+    {
+        VerifyOrExit(aJoinerInfo.mType == OT_JOINER_INFO_TYPE_ANY);
+        VerifyOrExit(value->valuestring != nullptr);
+        if (strncmp(value->valuestring, "*", 1) != 0)
+        {
+            otbrError err = StringDiscerner2Discerner(value->valuestring, aJoinerInfo.mSharedId.mDiscerner);
+            if (err == OTBR_ERROR_NOT_FOUND)
+            {
+                VerifyOrExit(Hex2BytesJsonString(std::string(value->valuestring), aJoinerInfo.mSharedId.mEui64.m8,
+                                                 OT_EXT_ADDRESS_SIZE) == OT_EXT_ADDRESS_SIZE);
+                aJoinerInfo.mType = OT_JOINER_INFO_TYPE_EUI64;
+            }
+            else
+            {
+                VerifyOrExit(err == OTBR_ERROR_NONE);
+                aJoinerInfo.mType = OT_JOINER_INFO_TYPE_DISCERNER;
+            }
+        }
+    }
+
+    value = cJSON_GetObjectItemCaseSensitive(jsonJoinerInfo, "Discerner");
+    if (cJSON_IsString(value))
+    {
+        VerifyOrExit(aJoinerInfo.mType == OT_JOINER_INFO_TYPE_ANY);
+        VerifyOrExit(value->valuestring != nullptr);
+        if (strncmp(value->valuestring, "*", 1) != 0)
+        {
+            VerifyOrExit(StringDiscerner2Discerner(value->valuestring, aJoinerInfo.mSharedId.mDiscerner) ==
+                         OTBR_ERROR_NONE);
+            aJoinerInfo.mType = OT_JOINER_INFO_TYPE_DISCERNER;
+        }
+    }
+
+    value = cJSON_GetObjectItemCaseSensitive(jsonJoinerInfo, "Eui64");
+    if (cJSON_IsString(value))
+    {
+        VerifyOrExit(aJoinerInfo.mType == OT_JOINER_INFO_TYPE_ANY);
+        VerifyOrExit(value->valuestring != nullptr);
+        if (strncmp(value->valuestring, "*", 1) != 0)
+        {
+            VerifyOrExit(Hex2BytesJsonString(std::string(value->valuestring), aJoinerInfo.mSharedId.mEui64.m8,
+                                             OT_EXT_ADDRESS_SIZE) == OT_EXT_ADDRESS_SIZE);
+            aJoinerInfo.mType = OT_JOINER_INFO_TYPE_EUI64;
+        }
+    }
+
+    aJoinerInfo.mExpirationTime = 60;
+    value                       = cJSON_GetObjectItemCaseSensitive(jsonJoinerInfo, "Timeout");
+    if (cJSON_IsNumber(value))
+    {
+        aJoinerInfo.mExpirationTime = value->valueint;
+    }
+
+    ret = true;
+exit:
+    return ret;
+}
+
+bool JsonJoinerInfoString2JoinerInfo(const std::string &aJsonJoinerInfo, otJoinerInfo &aJoinerInfo)
+{
+    cJSON *jsonJoinerInfo;
+    bool   ret = true;
+
+    VerifyOrExit((jsonJoinerInfo = cJSON_Parse(aJsonJoinerInfo.c_str())) != nullptr, ret = false);
+    VerifyOrExit(cJSON_IsObject(jsonJoinerInfo), ret = false);
+
+    ret = JsonJoinerInfo2JoinerInfo(jsonJoinerInfo, aJoinerInfo);
+
+exit:
+    cJSON_Delete(jsonJoinerInfo);
+
+    return ret;
+}
+
+cJSON *JoinerTable2Json(const std::vector<otJoinerInfo> &aJoinerTable)
+{
+    cJSON *table = cJSON_CreateArray();
+
+    for (const otJoinerInfo joiner : aJoinerTable)
+    {
+        cJSON *joinerJson = JoinerInfo2Json(joiner);
+        cJSON_AddItemToArray(table, joinerJson);
+    }
+
+    return table;
+}
+
+std::string JoinerTable2JsonString(const std::vector<otJoinerInfo> &aJoinerTable)
+{
+    return Json2String(JoinerTable2Json(aJoinerTable));
+}
+
 } // namespace Json
 } // namespace rest
 } // namespace otbr
diff --git a/src/rest/json.hpp b/src/rest/json.hpp
index 22cc0f94..850c53d3 100644
--- a/src/rest/json.hpp
+++ b/src/rest/json.hpp
@@ -40,6 +40,7 @@
 #include "openthread/link.h"
 #include "openthread/thread_ftd.h"
 
+#include "common/types.hpp"
 #include "rest/types.hpp"
 #include "utils/hex.hpp"
 
@@ -251,6 +252,14 @@ bool JsonActiveDatasetString2Dataset(const std::string &aJsonActiveDataset, otOp
  */
 bool JsonPendingDatasetString2Dataset(const std::string &aJsonPendingDataset, otOperationalDataset &aDataset);
 
+std::string JoinerInfo2JsonString(const otJoinerInfo &aJoinerInfo);
+
+otbrError StringDiscerner2Discerner(char *aString, otJoinerDiscerner &aDiscerner);
+
+bool JsonJoinerInfoString2JoinerInfo(const std::string &aJsonJoinerInfo, otJoinerInfo &aJoinerInfo);
+
+std::string JoinerTable2JsonString(const std::vector<otJoinerInfo> &aJoinerTable);
+
 }; // namespace Json
 
 } // namespace rest
diff --git a/src/rest/openapi.yaml b/src/rest/openapi.yaml
index 2ba2a4dd..49f10e90 100644
--- a/src/rest/openapi.yaml
+++ b/src/rest/openapi.yaml
@@ -213,7 +213,7 @@ paths:
           content:
             application/json:
               schema:
-                $ref: "#/components/schemas/Dataset"
+                $ref: "#/components/schemas/ActiveDataset"
             text/plain:
               schema:
                 $ref: "#/components/schemas/DatasetTlv"
@@ -291,6 +291,120 @@ paths:
           description: Successfully created the pending operational dataset.
         "400":
           description: Invalid request body.
+  /node/commissioner/state:
+    get:
+      tags: 
+        - node
+        - commissioner
+      summary: Get current Commissioner state.
+      description: |-
+        State describing the current Commissioner role of this Thread node.
+        - disabled
+        - petitioning
+        - active
+      responses:
+        "200":
+          description: Successful operation
+          content:
+            application/json:
+              schema:
+                type: string
+                description: Current state
+                example: "active"
+    put:
+      tags:
+        - node
+        - commissioner
+      summary: Set current Commissioner state.
+      description: |-
+        Enable or disable the Commissioner.
+      responses:
+        "200":
+          description: Successful operation.
+        "204":
+          description: Already in state.
+        "409":
+          description: Cannot set commissioner state because border router state is not active
+      requestBody:
+        description: New Commissioner state
+        content:
+          application/json:
+            schema:
+              type: string
+              description: Can be "enable" or "disable".
+              example: "enable"
+  /node/commissioner/joiner:
+    get:
+      tags:
+        - node
+      summary: Get current joiner data
+      responses:
+        "200":
+          description: Returns an array of currently active joiners
+          content:
+            application/json:
+              schema:
+                type: array
+                items:
+                  $ref: "#/components/schemas/JoinerData"
+    post:
+      tags:
+        - node
+      summary: Adds a new joiner
+      requestBody:
+        content:
+          application/json:
+            schema:
+                $ref: "#/components/schemas/JoinerData"
+      responses:
+        "200":
+          description: Successfully added joiner.
+        "400":
+          description: Invalid request body.
+        "409":
+          description: Adding joiner rejected because commissioner is not active.
+        "507":
+          description: Number of joiners the commissioner supports is full and the new one cannot be added.
+    delete:
+      tags: 
+        - node
+      summary: Removes a joiner from the node
+      requestBody:
+        content:
+          application/json:
+            schema:
+                type: string
+                description: |-
+                  Joiner ID to remove, can be either:
+                   - An EUI64 in the form of a 16 character hex string
+                   - A discerner in the form of the discerner hex value 
+                     (optionally with leading 0x) and bit length separated by a '/'
+                example: "0xabc/12"
+      responses:
+        "200":
+          description: Successfully removed joiner.
+        "204":
+          description: Joiner not found.
+        "400":
+          description: Invalid request body.
+        "409":
+          description: request rejected because commissioner is not active.
+  /node/coprocessor/version:
+    get:
+      tags:
+        - node
+      summary: Get the coprocessor firmware version
+      description: Retrieves the NCP or RCP coprocessor firmware version string.
+      responses:
+        "200":
+          description: Successful operation
+          content:
+            application/json:
+              schema:
+                type: string
+                description: Coprocessor version string
+                example: "OPENTHREAD/thread-reference-20200818-1740-g33cc75ed3; NRF52840; Jun  2 2022 14:25:49"
+
 components:
   schemas:
     LeaderData:
@@ -462,3 +576,30 @@ components:
       type: string
       description: Operational dataset as hex-encoded TLVs.
       example: 0E080000000000010000000300000F35060004001FFFE0020811111111222222220708FDAD70BFE5AA15DD051000112233445566778899AABBCCDDEEFF030E4F70656E54687265616444656D6F010212340410445F2B5CA6F2A93A55CE570A70EFEECB0C0402A0F7F8
+    JoinerData:
+      type: object
+      properties:
+        Pksd:
+          type: string
+          description: Joining device's pre-shared key
+          example: J01N
+        JoinerId:
+          type: string
+          description: A string of the EUI-64, Discerner, or "*", mutually exclusive with Eui64 and Discerner
+          example: "0xabc/12"
+          default: "*"
+        Eui64:
+          type: string
+          description: A string of the EUI-64, mutually exclusive with JoinerId and Discerner
+          example: "0123456789abcdef"
+        Discerner:
+          type: string
+          description: |- 
+            A discerner in the form of the discerner hex value (optionally with leading 0x) 
+            and bit length separated by a '/'.
+            Field is mutually exclusive with JoinerId and Eui64.
+          example: "0xabc/12"
+        Timeout:
+          type: integer
+          description: Joiner expiration time in milliseconds on response and seconds on request 
+          default: 60 
diff --git a/src/rest/resource.cpp b/src/rest/resource.cpp
index ce154c2e..993c1b9c 100644
--- a/src/rest/resource.cpp
+++ b/src/rest/resource.cpp
@@ -29,6 +29,7 @@
 #define OTBR_LOG_TAG "REST"
 
 #include "rest/resource.hpp"
+#include <openthread/commissioner.h>
 
 #define OT_PSKC_MAX_LENGTH 16
 #define OT_EXTENDED_PANID_LENGTH 8
@@ -46,6 +47,10 @@
 #define OT_REST_RESOURCE_PATH_NODE_EXTPANID "/node/ext-panid"
 #define OT_REST_RESOURCE_PATH_NODE_DATASET_ACTIVE "/node/dataset/active"
 #define OT_REST_RESOURCE_PATH_NODE_DATASET_PENDING "/node/dataset/pending"
+#define OT_REST_RESOURCE_PATH_NODE_COMMISSIONER_STATE "/node/commissioner/state"
+#define OT_REST_RESOURCE_PATH_NODE_COMMISSIONER_JOINER "/node/commissioner/joiner"
+#define OT_REST_RESOURCE_PATH_NODE_COPROCESSOR "/node/coprocessor"
+#define OT_REST_RESOURCE_PATH_NODE_COPROCESSOR_VERSION "/node/coprocessor/version"
 #define OT_REST_RESOURCE_PATH_NETWORK "/networks"
 #define OT_REST_RESOURCE_PATH_NETWORK_CURRENT "/networks/current"
 #define OT_REST_RESOURCE_PATH_NETWORK_CURRENT_COMMISSION "/networks/commission"
@@ -60,6 +65,7 @@
 #define OT_REST_HTTP_STATUS_408 "408 Request Timeout"
 #define OT_REST_HTTP_STATUS_409 "409 Conflict"
 #define OT_REST_HTTP_STATUS_500 "500 Internal Server Error"
+#define OT_REST_HTTP_STATUS_507 "507 Insufficient Storage"
 
 using std::chrono::duration_cast;
 using std::chrono::microseconds;
@@ -116,6 +122,9 @@ static std::string GetHttpStatus(HttpStatusCode aErrorCode)
     case HttpStatusCode::kStatusInternalServerError:
         httpStatus = OT_REST_HTTP_STATUS_500;
         break;
+    case HttpStatusCode::kStatusInsufficientStorage:
+        httpStatus = OT_REST_HTTP_STATUS_507;
+        break;
     }
 
     return httpStatus;
@@ -139,6 +148,9 @@ Resource::Resource(RcpHost *aHost)
     mResourceMap.emplace(OT_REST_RESOURCE_PATH_NODE_RLOC, &Resource::Rloc);
     mResourceMap.emplace(OT_REST_RESOURCE_PATH_NODE_DATASET_ACTIVE, &Resource::DatasetActive);
     mResourceMap.emplace(OT_REST_RESOURCE_PATH_NODE_DATASET_PENDING, &Resource::DatasetPending);
+    mResourceMap.emplace(OT_REST_RESOURCE_PATH_NODE_COMMISSIONER_STATE, &Resource::CommissionerState);
+    mResourceMap.emplace(OT_REST_RESOURCE_PATH_NODE_COMMISSIONER_JOINER, &Resource::CommissionerJoiner);
+    mResourceMap.emplace(OT_REST_RESOURCE_PATH_NODE_COPROCESSOR_VERSION, &Resource::CoprocessorVersion);
 
     // Resource callback handler
     mResourceCallbackMap.emplace(OT_REST_RESOURCE_PATH_DIAGNOSTICS, &Resource::HandleDiagnosticCallback);
@@ -800,6 +812,280 @@ void Resource::DatasetPending(const Request &aRequest, Response &aResponse) cons
     Dataset(DatasetType::kPending, aRequest, aResponse);
 }
 
+void Resource::GetCommissionerState(Response &aResponse) const
+{
+    std::string         state;
+    std::string         errorCode;
+    otCommissionerState stateCode;
+
+    stateCode = otCommissionerGetState(mInstance);
+    state     = Json::String2JsonString(GetCommissionerStateName(stateCode));
+    aResponse.SetBody(state);
+    errorCode = GetHttpStatus(HttpStatusCode::kStatusOk);
+    aResponse.SetResponsCode(errorCode);
+}
+
+void Resource::SetCommissionerState(const Request &aRequest, Response &aResponse) const
+{
+    otbrError   error = OTBR_ERROR_NONE;
+    std::string errorCode;
+    std::string body;
+
+    VerifyOrExit(Json::JsonString2String(aRequest.GetBody(), body), error = OTBR_ERROR_INVALID_ARGS);
+    if (body == "enable")
+    {
+        VerifyOrExit(otCommissionerGetState(mInstance) == OT_COMMISSIONER_STATE_DISABLED, error = OTBR_ERROR_NONE);
+        VerifyOrExit(otCommissionerStart(mInstance, NULL, NULL, NULL) == OT_ERROR_NONE,
+                     error = OTBR_ERROR_INVALID_STATE);
+    }
+    else if (body == "disable")
+    {
+        VerifyOrExit(otCommissionerGetState(mInstance) != OT_COMMISSIONER_STATE_DISABLED, error = OTBR_ERROR_NONE);
+        VerifyOrExit(otCommissionerStop(mInstance) == OT_ERROR_NONE, error = OTBR_ERROR_INVALID_STATE);
+    }
+    else
+    {
+        ExitNow(error = OTBR_ERROR_INVALID_ARGS);
+    }
+
+exit:
+    switch (error)
+    {
+    case OTBR_ERROR_NONE:
+        errorCode = GetHttpStatus(HttpStatusCode::kStatusOk);
+        aResponse.SetResponsCode(errorCode);
+        break;
+    case OTBR_ERROR_INVALID_STATE:
+        ErrorHandler(aResponse, HttpStatusCode::kStatusConflict);
+        break;
+    case OTBR_ERROR_INVALID_ARGS:
+        ErrorHandler(aResponse, HttpStatusCode::kStatusBadRequest);
+        break;
+    default:
+        ErrorHandler(aResponse, HttpStatusCode::kStatusInternalServerError);
+        break;
+    }
+}
+
+void Resource::CommissionerState(const Request &aRequest, Response &aResponse) const
+{
+    std::string errorCode;
+
+    switch (aRequest.GetMethod())
+    {
+    case HttpMethod::kGet:
+        GetCommissionerState(aResponse);
+        break;
+    case HttpMethod::kPut:
+        SetCommissionerState(aRequest, aResponse);
+        break;
+    case HttpMethod::kOptions:
+        errorCode = GetHttpStatus(HttpStatusCode::kStatusOk);
+        aResponse.SetResponsCode(errorCode);
+        aResponse.SetComplete();
+        break;
+    default:
+        ErrorHandler(aResponse, HttpStatusCode::kStatusMethodNotAllowed);
+        break;
+    }
+}
+
+void Resource::GetJoiners(Response &aResponse) const
+{
+    uint16_t                  iter = 0;
+    otJoinerInfo              joinerInfo;
+    std::vector<otJoinerInfo> joinerTable;
+    std::string               joinerJson;
+    std::string               errorCode;
+
+    while (otCommissionerGetNextJoinerInfo(mInstance, &iter, &joinerInfo) == OT_ERROR_NONE)
+    {
+        joinerTable.push_back(joinerInfo);
+    }
+
+    joinerJson = Json::JoinerTable2JsonString(joinerTable);
+    aResponse.SetBody(joinerJson);
+    errorCode = GetHttpStatus(HttpStatusCode::kStatusOk);
+    aResponse.SetResponsCode(errorCode);
+}
+
+void Resource::AddJoiner(const Request &aRequest, Response &aResponse) const
+{
+    otbrError           error   = OTBR_ERROR_NONE;
+    otError             errorOt = OT_ERROR_NONE;
+    std::string         errorCode;
+    otJoinerInfo        joiner;
+    const otExtAddress *addrPtr                         = nullptr;
+    const uint8_t       emptyArray[OT_EXT_ADDRESS_SIZE] = {0};
+
+    VerifyOrExit(otCommissionerGetState(mInstance) == OT_COMMISSIONER_STATE_ACTIVE, error = OTBR_ERROR_INVALID_STATE);
+
+    VerifyOrExit(Json::JsonJoinerInfoString2JoinerInfo(aRequest.GetBody(), joiner), error = OTBR_ERROR_INVALID_ARGS);
+
+    addrPtr = &joiner.mSharedId.mEui64;
+    if (memcmp(&joiner.mSharedId.mEui64, emptyArray, OT_EXT_ADDRESS_SIZE) == 0)
+    {
+        addrPtr = nullptr;
+    }
+
+    if (joiner.mType == OT_JOINER_INFO_TYPE_DISCERNER)
+    {
+        errorOt = otCommissionerAddJoinerWithDiscerner(mInstance, &joiner.mSharedId.mDiscerner, joiner.mPskd.m8,
+                                                       joiner.mExpirationTime);
+    }
+    else
+    {
+        errorOt = otCommissionerAddJoiner(mInstance, addrPtr, joiner.mPskd.m8, joiner.mExpirationTime);
+    }
+    VerifyOrExit(errorOt == OT_ERROR_NONE, error = OTBR_ERROR_OPENTHREAD);
+
+exit:
+    switch (error)
+    {
+    case OTBR_ERROR_NONE:
+        errorCode = GetHttpStatus(HttpStatusCode::kStatusOk);
+        aResponse.SetResponsCode(errorCode);
+        break;
+    case OTBR_ERROR_INVALID_STATE:
+        ErrorHandler(aResponse, HttpStatusCode::kStatusConflict);
+        break;
+    case OTBR_ERROR_INVALID_ARGS:
+        ErrorHandler(aResponse, HttpStatusCode::kStatusBadRequest);
+        break;
+    case OTBR_ERROR_OPENTHREAD:
+        switch (errorOt)
+        {
+        case OT_ERROR_INVALID_ARGS:
+            ErrorHandler(aResponse, HttpStatusCode::kStatusBadRequest);
+            break;
+        case OT_ERROR_NO_BUFS:
+            ErrorHandler(aResponse, HttpStatusCode::kStatusInsufficientStorage);
+            break;
+        default:
+            ErrorHandler(aResponse, HttpStatusCode::kStatusInternalServerError);
+            break;
+        }
+        break;
+    default:
+        ErrorHandler(aResponse, HttpStatusCode::kStatusInternalServerError);
+        break;
+    }
+}
+
+void Resource::RemoveJoiner(const Request &aRequest, Response &aResponse) const
+{
+    otbrError         error = OTBR_ERROR_NONE;
+    std::string       errorCode;
+    otExtAddress      eui64;
+    otExtAddress     *addrPtr   = nullptr;
+    otJoinerDiscerner discerner = {
+        .mValue  = 0,
+        .mLength = 0,
+    };
+    std::string body;
+
+    VerifyOrExit(otCommissionerGetState(mInstance) == OT_COMMISSIONER_STATE_ACTIVE, error = OTBR_ERROR_INVALID_STATE);
+
+    VerifyOrExit(Json::JsonString2String(aRequest.GetBody(), body), error = OTBR_ERROR_INVALID_ARGS);
+    if (body != "*")
+    {
+        error = Json::StringDiscerner2Discerner(const_cast<char *>(body.c_str()), discerner);
+        if (error == OTBR_ERROR_NOT_FOUND)
+        {
+            error = OTBR_ERROR_NONE;
+            VerifyOrExit(Json::Hex2BytesJsonString(body, eui64.m8, OT_EXT_ADDRESS_SIZE) == OT_EXT_ADDRESS_SIZE,
+                         error = OTBR_ERROR_INVALID_ARGS);
+            addrPtr = &eui64;
+        }
+        else if (error != OTBR_ERROR_NONE)
+        {
+            ExitNow(error = OTBR_ERROR_INVALID_ARGS);
+        }
+    }
+
+    // These functions should only return OT_ERROR_NONE or OT_ERROR_NOT_FOUND both treated as successful
+    if (discerner.mLength == 0)
+    {
+        (void)otCommissionerRemoveJoiner(mInstance, addrPtr);
+    }
+    else
+    {
+        (void)otCommissionerRemoveJoinerWithDiscerner(mInstance, &discerner);
+    }
+
+exit:
+    switch (error)
+    {
+    case OTBR_ERROR_NONE:
+        errorCode = GetHttpStatus(HttpStatusCode::kStatusOk);
+        aResponse.SetResponsCode(errorCode);
+        break;
+    case OTBR_ERROR_INVALID_STATE:
+        ErrorHandler(aResponse, HttpStatusCode::kStatusConflict);
+        break;
+    case OTBR_ERROR_INVALID_ARGS:
+        ErrorHandler(aResponse, HttpStatusCode::kStatusBadRequest);
+        break;
+    default:
+        ErrorHandler(aResponse, HttpStatusCode::kStatusInternalServerError);
+        break;
+    }
+}
+
+void Resource::CommissionerJoiner(const Request &aRequest, Response &aResponse) const
+{
+    std::string errorCode;
+
+    switch (aRequest.GetMethod())
+    {
+    case HttpMethod::kGet:
+        GetJoiners(aResponse);
+        break;
+    case HttpMethod::kPost:
+        AddJoiner(aRequest, aResponse);
+        break;
+    case HttpMethod::kDelete:
+        RemoveJoiner(aRequest, aResponse);
+        break;
+
+    case HttpMethod::kOptions:
+        errorCode = GetHttpStatus(HttpStatusCode::kStatusOk);
+        aResponse.SetResponsCode(errorCode);
+        aResponse.SetComplete();
+        break;
+    default:
+        ErrorHandler(aResponse, HttpStatusCode::kStatusMethodNotAllowed);
+        break;
+    }
+}
+
+void Resource::GetCoprocessorVersion(Response &aResponse) const
+{
+    std::string coprocessorVersion;
+    std::string errorCode;
+
+    coprocessorVersion = mHost->GetCoprocessorVersion();
+    coprocessorVersion = Json::String2JsonString(coprocessorVersion);
+
+    aResponse.SetBody(coprocessorVersion);
+    errorCode = GetHttpStatus(HttpStatusCode::kStatusOk);
+    aResponse.SetResponsCode(errorCode);
+}
+
+void Resource::CoprocessorVersion(const Request &aRequest, Response &aResponse) const
+{
+    std::string errorCode;
+
+    if (aRequest.GetMethod() == HttpMethod::kGet)
+    {
+        GetCoprocessorVersion(aResponse);
+    }
+    else
+    {
+        ErrorHandler(aResponse, HttpStatusCode::kStatusMethodNotAllowed);
+    }
+}
+
 void Resource::DeleteOutDatedDiagnostic(void)
 {
     auto eraseIt = mDiagSet.begin();
diff --git a/src/rest/resource.hpp b/src/rest/resource.hpp
index 7982843b..4b9e15e1 100644
--- a/src/rest/resource.hpp
+++ b/src/rest/resource.hpp
@@ -42,7 +42,7 @@
 #include <openthread/border_router.h>
 
 #include "common/api_strings.hpp"
-#include "ncp/rcp_host.hpp"
+#include "host/rcp_host.hpp"
 #include "openthread/dataset.h"
 #include "openthread/dataset_ftd.h"
 #include "rest/json.hpp"
@@ -50,7 +50,7 @@
 #include "rest/response.hpp"
 #include "utils/thread_helper.hpp"
 
-using otbr::Ncp::RcpHost;
+using otbr::Host::RcpHost;
 using std::chrono::steady_clock;
 
 namespace otbr {
@@ -125,8 +125,11 @@ private:
     void Dataset(DatasetType aDatasetType, const Request &aRequest, Response &aResponse) const;
     void DatasetActive(const Request &aRequest, Response &aResponse) const;
     void DatasetPending(const Request &aRequest, Response &aResponse) const;
+    void CommissionerState(const Request &aRequest, Response &aResponse) const;
+    void CommissionerJoiner(const Request &aRequest, Response &aResponse) const;
     void Diagnostic(const Request &aRequest, Response &aResponse) const;
     void HandleDiagnosticCallback(const Request &aRequest, Response &aResponse);
+    void CoprocessorVersion(const Request &aRequest, Response &aResponse) const;
 
     void GetNodeInfo(Response &aResponse) const;
     void DeleteNodeInfo(Response &aResponse) const;
@@ -142,6 +145,12 @@ private:
     void GetDataRloc(Response &aResponse) const;
     void GetDataset(DatasetType aDatasetType, const Request &aRequest, Response &aResponse) const;
     void SetDataset(DatasetType aDatasetType, const Request &aRequest, Response &aResponse) const;
+    void GetCommissionerState(Response &aResponse) const;
+    void SetCommissionerState(const Request &aRequest, Response &aResponse) const;
+    void GetJoiners(Response &aResponse) const;
+    void AddJoiner(const Request &aRequest, Response &aResponse) const;
+    void RemoveJoiner(const Request &aRequest, Response &aResponse) const;
+    void GetCoprocessorVersion(Response &aResponse) const;
 
     void DeleteOutDatedDiagnostic(void);
     void UpdateDiag(std::string aKey, std::vector<otNetworkDiagTlv> &aDiag);
diff --git a/src/rest/rest_web_server.hpp b/src/rest/rest_web_server.hpp
index 08074c54..952d1105 100644
--- a/src/rest/rest_web_server.hpp
+++ b/src/rest/rest_web_server.hpp
@@ -43,7 +43,7 @@
 #include "common/mainloop.hpp"
 #include "rest/connection.hpp"
 
-using otbr::Ncp::RcpHost;
+using otbr::Host::RcpHost;
 using std::chrono::steady_clock;
 
 namespace otbr {
diff --git a/src/rest/types.hpp b/src/rest/types.hpp
index aaa11d1b..de8bec12 100644
--- a/src/rest/types.hpp
+++ b/src/rest/types.hpp
@@ -77,6 +77,7 @@ enum class HttpStatusCode : std::uint16_t
     kStatusRequestTimeout      = 408,
     kStatusConflict            = 409,
     kStatusInternalServerError = 500,
+    kStatusInsufficientStorage = 507,
 };
 
 enum class PostError : std::uint8_t
diff --git a/src/sdp_proxy/advertising_proxy.cpp b/src/sdp_proxy/advertising_proxy.cpp
index ea9dc316..37664a3a 100644
--- a/src/sdp_proxy/advertising_proxy.cpp
+++ b/src/sdp_proxy/advertising_proxy.cpp
@@ -51,10 +51,11 @@
 
 namespace otbr {
 
-AdvertisingProxy::AdvertisingProxy(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher)
+AdvertisingProxy::AdvertisingProxy(Host::RcpHost &aHost, Mdns::Publisher &aPublisher)
     : mHost(aHost)
     , mPublisher(aPublisher)
     , mIsEnabled(false)
+    , mAllowMlEid(false)
 {
     mHost.RegisterResetHandler(
         [this]() { otSrpServerSetServiceUpdateHandler(GetInstance(), AdvertisingHandler, this); });
@@ -170,7 +171,7 @@ std::vector<Ip6Address> AdvertisingProxy::GetEligibleAddresses(const otIp6Addres
     {
         Ip6Address address(aHostAddresses[i].mFields.m8);
 
-        if (otIp6PrefixMatch(meshLocalEid, &aHostAddresses[i]) >= OT_IP6_PREFIX_BITSIZE)
+        if (!mAllowMlEid && otIp6PrefixMatch(meshLocalEid, &aHostAddresses[i]) >= OT_IP6_PREFIX_BITSIZE)
         {
             continue;
         }
diff --git a/src/sdp_proxy/advertising_proxy.hpp b/src/sdp_proxy/advertising_proxy.hpp
index 2077d350..571b22d2 100644
--- a/src/sdp_proxy/advertising_proxy.hpp
+++ b/src/sdp_proxy/advertising_proxy.hpp
@@ -44,15 +44,15 @@
 #include <openthread/srp_server.h>
 
 #include "common/code_utils.hpp"
+#include "host/rcp_host.hpp"
 #include "mdns/mdns.hpp"
-#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 
 /**
  * This class implements the Advertising Proxy.
  */
-class AdvertisingProxy : private NonCopyable
+class AdvertisingProxy : public Mdns::StateObserver, private NonCopyable
 {
 public:
     /**
@@ -61,7 +61,7 @@ public:
      * @param[in] aHost       A reference to the NCP controller.
      * @param[in] aPublisher  A reference to the mDNS publisher.
      */
-    explicit AdvertisingProxy(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher);
+    explicit AdvertisingProxy(Host::RcpHost &aHost, Mdns::Publisher &aPublisher);
 
     /**
      * This method enables/disables the Advertising Proxy.
@@ -70,6 +70,9 @@ public:
      */
     void SetEnabled(bool aIsEnabled);
 
+    /** Sets `true` to allow advertising ML-EID. */
+    void SetAllowMlEid(bool aAllowMlEid) { mAllowMlEid = aAllowMlEid; }
+
     /**
      * This method publishes all registered hosts and services.
      */
@@ -80,7 +83,7 @@ public:
      *
      * @param[in] aState  The state of mDNS publisher.
      */
-    void HandleMdnsState(Mdns::Publisher::State aState);
+    void HandleMdnsState(Mdns::Publisher::State aState) override;
 
 private:
     struct OutstandingUpdate
@@ -123,12 +126,13 @@ private:
     otInstance *GetInstance(void) { return mHost.GetInstance(); }
 
     // A reference to the NCP controller, has no ownership.
-    Ncp::RcpHost &mHost;
+    Host::RcpHost &mHost;
 
     // A reference to the mDNS publisher, has no ownership.
     Mdns::Publisher &mPublisher;
 
     bool mIsEnabled;
+    bool mAllowMlEid;
 
     // A vector that tracks outstanding updates.
     std::vector<OutstandingUpdate> mOutstandingUpdates;
diff --git a/src/sdp_proxy/discovery_proxy.cpp b/src/sdp_proxy/discovery_proxy.cpp
index 5aed48f8..71049a0f 100644
--- a/src/sdp_proxy/discovery_proxy.cpp
+++ b/src/sdp_proxy/discovery_proxy.cpp
@@ -58,7 +58,7 @@ static inline bool DnsLabelsEqual(const std::string &aLabel1, const std::string
     return StringUtils::EqualCaseInsensitive(aLabel1, aLabel2);
 }
 
-DiscoveryProxy::DiscoveryProxy(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher)
+DiscoveryProxy::DiscoveryProxy(Host::RcpHost &aHost, Mdns::Publisher &aPublisher)
     : mHost(aHost)
     , mMdnsPublisher(aPublisher)
     , mIsEnabled(false)
@@ -170,23 +170,41 @@ void DiscoveryProxy::OnDiscoveryProxyUnsubscribe(const char *aFullName)
     }
 }
 
+void DiscoveryProxy::FilterLinkLocalAddresses(const AddressList &aAddrList, AddressList &aFilteredList)
+{
+    aFilteredList.clear();
+
+    for (const Ip6Address &address : aAddrList)
+    {
+        if (address.IsLinkLocal())
+        {
+            continue;
+        }
+
+        aFilteredList.push_back(address);
+    }
+}
+
 void DiscoveryProxy::OnServiceDiscovered(const std::string                             &aType,
                                          const Mdns::Publisher::DiscoveredInstanceInfo &aInstanceInfo)
 {
     otDnssdServiceInstanceInfo instanceInfo;
     const otDnssdQuery        *query                 = nullptr;
     std::string                unescapedInstanceName = DnsUtils::UnescapeInstanceName(aInstanceInfo.mName);
+    AddressList                filteredAddrList;
+
+    FilterLinkLocalAddresses(aInstanceInfo.mAddresses, filteredAddrList);
 
     otbrLogInfo("Service discovered: %s, instance %s hostname %s addresses %zu port %d priority %d "
                 "weight %d",
-                aType.c_str(), aInstanceInfo.mName.c_str(), aInstanceInfo.mHostName.c_str(),
-                aInstanceInfo.mAddresses.size(), aInstanceInfo.mPort, aInstanceInfo.mPriority, aInstanceInfo.mWeight);
+                aType.c_str(), aInstanceInfo.mName.c_str(), aInstanceInfo.mHostName.c_str(), filteredAddrList.size(),
+                aInstanceInfo.mPort, aInstanceInfo.mPriority, aInstanceInfo.mWeight);
 
-    instanceInfo.mAddressNum = aInstanceInfo.mAddresses.size();
+    instanceInfo.mAddressNum = filteredAddrList.size();
 
-    if (!aInstanceInfo.mAddresses.empty())
+    if (!filteredAddrList.empty())
     {
-        instanceInfo.mAddresses = reinterpret_cast<const otIp6Address *>(&aInstanceInfo.mAddresses[0]);
+        instanceInfo.mAddresses = reinterpret_cast<const otIp6Address *>(&filteredAddrList[0]);
     }
     else
     {
@@ -249,24 +267,21 @@ void DiscoveryProxy::OnHostDiscovered(const std::string
     otDnssdHostInfo     hostInfo;
     const otDnssdQuery *query            = nullptr;
     std::string         resolvedHostName = aHostInfo.mHostName;
+    AddressList         filteredAddrList;
+
+    FilterLinkLocalAddresses(aHostInfo.mAddresses, filteredAddrList);
+    VerifyOrExit(!filteredAddrList.empty());
 
     otbrLogInfo("Host discovered: %s hostname %s addresses %zu", aHostName.c_str(), aHostInfo.mHostName.c_str(),
-                aHostInfo.mAddresses.size());
+                filteredAddrList.size());
 
     if (resolvedHostName.empty())
     {
         resolvedHostName = aHostName + ".local.";
     }
 
-    hostInfo.mAddressNum = aHostInfo.mAddresses.size();
-    if (!aHostInfo.mAddresses.empty())
-    {
-        hostInfo.mAddresses = reinterpret_cast<const otIp6Address *>(&aHostInfo.mAddresses[0]);
-    }
-    else
-    {
-        hostInfo.mAddresses = nullptr;
-    }
+    hostInfo.mAddressNum = filteredAddrList.size();
+    hostInfo.mAddresses  = reinterpret_cast<const otIp6Address *>(&filteredAddrList[0]);
 
     hostInfo.mTtl = CapTtl(aHostInfo.mTtl);
 
@@ -298,6 +313,9 @@ void DiscoveryProxy::OnHostDiscovered(const std::string
             otDnssdQueryHandleDiscoveredHost(mHost.GetInstance(), hostFullName.c_str(), &hostInfo);
         }
     }
+
+exit:
+    return;
 }
 
 std::string DiscoveryProxy::TranslateDomain(const std::string &aName, const std::string &aTargetDomain)
diff --git a/src/sdp_proxy/discovery_proxy.hpp b/src/sdp_proxy/discovery_proxy.hpp
index 9278cf49..0b4cf502 100644
--- a/src/sdp_proxy/discovery_proxy.hpp
+++ b/src/sdp_proxy/discovery_proxy.hpp
@@ -47,8 +47,8 @@
 #include <openthread/instance.h>
 
 #include "common/dns_utils.hpp"
+#include "host/rcp_host.hpp"
 #include "mdns/mdns.hpp"
-#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 namespace Dnssd {
@@ -56,7 +56,7 @@ namespace Dnssd {
 /**
  * This class implements the DNS-SD Discovery Proxy.
  */
-class DiscoveryProxy : private NonCopyable
+class DiscoveryProxy : public Mdns::StateObserver, private NonCopyable
 {
 public:
     /**
@@ -65,7 +65,7 @@ public:
      * @param[in] aHost       A reference to the OpenThread Controller instance.
      * @param[in] aPublisher  A reference to the mDNS Publisher.
      */
-    explicit DiscoveryProxy(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher);
+    explicit DiscoveryProxy(Host::RcpHost &aHost, Mdns::Publisher &aPublisher);
 
     /**
      * This method enables/disables the Discovery Proxy.
@@ -88,6 +88,8 @@ public:
     }
 
 private:
+    using AddressList = Mdns::Publisher::AddressList;
+
     enum : uint32_t
     {
         kServiceTtlCapLimit = 10, // TTL cap limit for Discovery Proxy (in seconds).
@@ -104,11 +106,13 @@ private:
     void OnHostDiscovered(const std::string &aHostName, const Mdns::Publisher::DiscoveredHostInfo &aHostInfo);
     static uint32_t CapTtl(uint32_t aTtl);
 
+    static void FilterLinkLocalAddresses(const AddressList &aAddrList, AddressList &aFilteredList);
+
     void Start(void);
     void Stop(void);
     bool IsEnabled(void) const { return mIsEnabled; }
 
-    Ncp::RcpHost    &mHost;
+    Host::RcpHost   &mHost;
     Mdns::Publisher &mMdnsPublisher;
     bool             mIsEnabled;
     uint64_t         mSubscriberId = 0;
diff --git a/src/trel_dnssd/trel_dnssd.cpp b/src/trel_dnssd/trel_dnssd.cpp
index a80a2e77..c64d3a30 100644
--- a/src/trel_dnssd/trel_dnssd.cpp
+++ b/src/trel_dnssd/trel_dnssd.cpp
@@ -81,7 +81,7 @@ namespace otbr {
 
 namespace TrelDnssd {
 
-TrelDnssd::TrelDnssd(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher)
+TrelDnssd::TrelDnssd(Host::RcpHost &aHost, Mdns::Publisher &aPublisher)
     : mPublisher(aPublisher)
     , mHost(aHost)
 {
diff --git a/src/trel_dnssd/trel_dnssd.hpp b/src/trel_dnssd/trel_dnssd.hpp
index d6856b1d..b029c915 100644
--- a/src/trel_dnssd/trel_dnssd.hpp
+++ b/src/trel_dnssd/trel_dnssd.hpp
@@ -44,8 +44,8 @@
 #include <openthread/instance.h>
 
 #include "common/types.hpp"
+#include "host/rcp_host.hpp"
 #include "mdns/mdns.hpp"
-#include "ncp/rcp_host.hpp"
 
 namespace otbr {
 
@@ -60,7 +60,7 @@ namespace TrelDnssd {
  * @{
  */
 
-class TrelDnssd
+class TrelDnssd : public Mdns::StateObserver
 {
 public:
     /**
@@ -69,7 +69,7 @@ public:
      * @param[in] aHost       A reference to the OpenThread Controller instance.
      * @param[in] aPublisher  A reference to the mDNS Publisher.
      */
-    explicit TrelDnssd(Ncp::RcpHost &aHost, Mdns::Publisher &aPublisher);
+    explicit TrelDnssd(Host::RcpHost &aHost, Mdns::Publisher &aPublisher);
 
     /**
      * This method initializes the TrelDnssd instance.
@@ -107,7 +107,7 @@ public:
      *
      * @param[in] aState  The state of mDNS publisher.
      */
-    void HandleMdnsState(Mdns::Publisher::State aState);
+    void HandleMdnsState(Mdns::Publisher::State aState) override;
 
 private:
     static constexpr size_t   kPeerCacheSize             = 256;
@@ -170,7 +170,7 @@ private:
     uint16_t CountDuplicatePeers(const Peer &aPeer);
 
     Mdns::Publisher &mPublisher;
-    Ncp::RcpHost    &mHost;
+    Host::RcpHost   &mHost;
     TaskRunner       mTaskRunner;
     std::string      mTrelNetif;
     uint32_t         mTrelNetifIndex = 0;
diff --git a/src/utils/hex.cpp b/src/utils/hex.cpp
index 215e4796..319ef19c 100644
--- a/src/utils/hex.cpp
+++ b/src/utils/hex.cpp
@@ -111,31 +111,30 @@ size_t Bytes2Hex(const uint8_t *aBytes, const uint16_t aBytesLength, char *aHex)
 
 std::string Bytes2Hex(const uint8_t *aBytes, const uint16_t aBytesLength)
 {
-    char        hex[2 * aBytesLength + 1];
+    char       *hex = new char[2 * aBytesLength + 1];
     std::string s;
     size_t      len;
 
     len = Bytes2Hex(aBytes, aBytesLength, hex);
     s   = std::string(hex, len);
+    delete[] hex;
 
     return s;
 }
 
 size_t Long2Hex(const uint64_t aLong, char *aHex)
 {
-    char     byteHex[3];
-    uint64_t longValue = aLong;
+    char byteHex[3];
 
     // Make sure strcat appends at the beginning of the output buffer even
     // if uninitialized.
     aHex[0] = '\0';
 
-    for (uint8_t i = 0; i < sizeof(uint64_t); i++)
+    for (uint8_t i = 0; i < sizeof(aLong); i++)
     {
-        uint8_t byte = longValue & 0xff;
+        uint8_t byte = (aLong >> (8 * (sizeof(aLong) - i - 1))) & 0xff;
         snprintf(byteHex, sizeof(byteHex), "%02X", byte);
         strcat(aHex, byteHex);
-        longValue = longValue >> 8;
     }
 
     return strlen(aHex);
diff --git a/src/utils/hex.hpp b/src/utils/hex.hpp
index 49ba37d5..75835895 100644
--- a/src/utils/hex.hpp
+++ b/src/utils/hex.hpp
@@ -79,7 +79,7 @@ size_t Bytes2Hex(const uint8_t *aBytes, const uint16_t aBytesLength, char *aHex)
 std::string Bytes2Hex(const uint8_t *aBytes, const uint16_t aBytesLength);
 
 /**
- * @brief Converts a 64-bit integer to a hexadecimal string.
+ * @brief Converts a 64-bit integer to a big endian formatted hexadecimal string.
  *
  * @param[in]  aLong The 64-bit integer to be converted.
  * @param[out] aHex A character array to store the resulting hexadecimal string.
diff --git a/src/utils/thread_helper.cpp b/src/utils/thread_helper.cpp
index 7722f1a4..9866225a 100644
--- a/src/utils/thread_helper.cpp
+++ b/src/utils/thread_helper.cpp
@@ -69,7 +69,7 @@
 #include "common/code_utils.hpp"
 #include "common/logging.hpp"
 #include "common/tlv.hpp"
-#include "ncp/rcp_host.hpp"
+#include "host/rcp_host.hpp"
 
 namespace otbr {
 namespace agent {
@@ -228,7 +228,7 @@ void CopyMdnsResponseCounters(const MdnsResponseCounters &from, threadnetwork::T
 #endif // OTBR_ENABLE_TELEMETRY_DATA_API
 } // namespace
 
-ThreadHelper::ThreadHelper(otInstance *aInstance, otbr::Ncp::RcpHost *aHost)
+ThreadHelper::ThreadHelper(otInstance *aInstance, otbr::Host::RcpHost *aHost)
     : mInstance(aInstance)
     , mHost(aHost)
 {
@@ -427,7 +427,7 @@ void ThreadHelper::ActiveScanHandler(otActiveScanResult *aResult)
     }
 }
 
-#if OTBR_ENABLE_DHCP6_PD
+#if OTBR_ENABLE_DHCP6_PD && OTBR_ENABLE_BORDER_ROUTING
 void ThreadHelper::SetDhcp6PdStateCallback(Dhcp6PdStateCallback aCallback)
 {
     mDhcp6PdCallback = std::move(aCallback);
@@ -448,7 +448,7 @@ void ThreadHelper::BorderRoutingDhcp6PdCallback(otBorderRoutingDhcp6PdState aSta
         mDhcp6PdCallback(aState);
     }
 }
-#endif // OTBR_ENABLE_DHCP6_PD
+#endif // OTBR_ENABLE_DHCP6_PD && OTBR_ENABLE_BORDER_ROUTING
 
 void ThreadHelper::EnergyScanCallback(otEnergyScanResult *aResult, void *aThreadHelper)
 {
diff --git a/src/utils/thread_helper.hpp b/src/utils/thread_helper.hpp
index ed55d3a2..2e2de91e 100644
--- a/src/utils/thread_helper.hpp
+++ b/src/utils/thread_helper.hpp
@@ -56,7 +56,7 @@
 #endif
 
 namespace otbr {
-namespace Ncp {
+namespace Host {
 class RcpHost;
 }
 } // namespace otbr
@@ -87,7 +87,7 @@ public:
      * @param[in] aInstance  The Thread instance.
      * @param[in] aHost      The Thread controller.
      */
-    ThreadHelper(otInstance *aInstance, otbr::Ncp::RcpHost *aHost);
+    ThreadHelper(otInstance *aInstance, otbr::Host::RcpHost *aHost);
 
     /**
      * This method adds a callback for device role change.
@@ -340,7 +340,7 @@ private:
 
     otInstance *mInstance;
 
-    otbr::Ncp::RcpHost *mHost;
+    otbr::Host::RcpHost *mHost;
 
     ScanHandler                     mScanHandler;
     std::vector<otActiveScanResult> mScanResults;
diff --git a/src/web/CMakeLists.txt b/src/web/CMakeLists.txt
index 37ba68ff..217341ba 100644
--- a/src/web/CMakeLists.txt
+++ b/src/web/CMakeLists.txt
@@ -27,10 +27,6 @@
 #
 
 pkg_check_modules(JSONCPP jsoncpp REQUIRED)
-set(Boost_USE_STATIC_LIBS ON)
-set(Boost_USE_MULTITHREADED ON)
-set(Boost_USE_STATIC_RUNTIME OFF)
-find_package(Boost REQUIRED COMPONENTS filesystem system)
 set(OTBR_WEB_DATADIR ${CMAKE_INSTALL_FULL_DATADIR}/otbr-web)
 
 add_executable(otbr-web
@@ -42,15 +38,10 @@ add_executable(otbr-web
 target_compile_definitions(otbr-web PRIVATE
     WEB_FILE_PATH=\"${OTBR_WEB_DATADIR}/frontend\"
 )
-# TODO remove this when Simple Http Server is replaced and web-gui is refactored
-target_compile_options(otbr-web PRIVATE
-    -Wno-deprecated-declarations
-    -Wno-unused-lambda-capture
-)
+
 target_include_directories(otbr-web PRIVATE
     ${JSONCPP_INCLUDE_DIRS}
-    ${Boost_INCLUDE_DIRS}
-    ${PROJECT_SOURCE_DIR}/third_party/Simple-web-server/repo
+    ${PROJECT_SOURCE_DIR}/third_party/cpp-httplib/repo
 )
 target_link_libraries(otbr-web PRIVATE
     $<$<BOOL:${JSONCPP_LIBRARY_DIRS}>:-L$<JOIN:${JSONCPP_LIBRARY_DIRS}," -L">>
@@ -60,7 +51,6 @@ target_link_libraries(otbr-web PRIVATE
     openthread-ftd
     openthread-posix
     mbedtls
-    ${Boost_LIBRARIES}
     pthread
 )
 install(
diff --git a/src/web/main.cpp b/src/web/main.cpp
index 922038d8..6db9e8b8 100644
--- a/src/web/main.cpp
+++ b/src/web/main.cpp
@@ -76,9 +76,10 @@ int main(int argc, char **argv)
     otbrLogLevel logLevel       = OTBR_LOG_INFO;
     int          ret            = 0;
     int          opt;
-    uint16_t     port = OT_HTTP_PORT;
+    uint16_t     port          = OT_HTTP_PORT;
+    bool         syslogDisable = false;
 
-    while ((opt = getopt(argc, argv, "d:I:p:va:")) != -1)
+    while ((opt = getopt(argc, argv, "d:I:p:va:s")) != -1)
     {
         switch (opt)
         {
@@ -103,6 +104,10 @@ int main(int argc, char **argv)
             ExitNow();
             break;
 
+        case 's':
+            syslogDisable = true;
+            break;
+
         default:
             fprintf(stderr, "Usage: %s [-d DEBUG_LEVEL] [-I interfaceName] [-p port] [-a listenAddress] [-v]\n",
                     argv[0]);
@@ -111,7 +116,7 @@ int main(int argc, char **argv)
         }
     }
 
-    otbrLogInit(argv[0], logLevel, true, false);
+    otbrLogInit(argv[0], logLevel, true, syslogDisable);
     otbrLogInfo("Running %s", OTBR_PACKAGE_VERSION);
 
     if (interfaceName == nullptr)
diff --git a/src/web/web-service/web_server.cpp b/src/web/web-service/web_server.cpp
index ff823748..7b3f473b 100644
--- a/src/web/web-service/web_server.cpp
+++ b/src/web/web-service/web_server.cpp
@@ -35,12 +35,6 @@
 
 #include "web/web-service/web_server.hpp"
 
-#define BOOST_NO_CXX11_SCOPED_ENUMS
-#include <boost/filesystem.hpp>
-#undef BOOST_NO_CXX11_SCOPED_ENUMS
-
-#include <server_http.hpp>
-
 #include "common/code_utils.hpp"
 #include "common/logging.hpp"
 
@@ -67,47 +61,15 @@
 namespace otbr {
 namespace Web {
 
-static void EscapeHtml(std::string &content)
-{
-    std::string output;
-
-    output.reserve(content.size());
-    for (char c : content)
-    {
-        switch (c)
-        {
-        case '&':
-            output.append("&amp;");
-            break;
-        case '<':
-            output.append("&lt;");
-            break;
-        case '>':
-            output.append("&gt;");
-            break;
-        case '"':
-            output.append("&quot;");
-            break;
-        case '\'':
-            output.append("&apos;");
-            break;
-        default:
-            output.push_back(c);
-            break;
-        }
-    }
-
-    output.swap(content);
-}
+using httplib::Request;
+using httplib::Response;
 
 WebServer::WebServer(void)
-    : mServer(new HttpServer())
 {
 }
 
 WebServer::~WebServer(void)
 {
-    delete mServer;
 }
 
 void WebServer::Init()
@@ -122,11 +84,6 @@ void WebServer::Init()
 
 void WebServer::StartWebServer(const char *aIfName, const char *aListenAddr, uint16_t aPort)
 {
-    if (aListenAddr != nullptr)
-    {
-        mServer->config.address = aListenAddr;
-    }
-    mServer->config.port = aPort;
     mWpanService.SetInterfaceName(aIfName);
     Init();
     ResponseGetQRCode();
@@ -137,144 +94,22 @@ void WebServer::StartWebServer(const char *aIfName, const char *aListenAddr, uin
     ResponseGetStatus();
     ResponseGetAvailableNetwork();
     ResponseCommission();
-    DefaultHttpResponse();
+    mServer.set_mount_point("/", WEB_FILE_PATH);
 
-    try
-    {
-        mServer->start();
-    } catch (const std::exception &e)
-    {
-        otbrLogCrit("failed to start web server: %s", e.what());
-        abort();
-    }
+    mServer.listen(aListenAddr, aPort);
 }
 
 void WebServer::StopWebServer(void)
 {
     try
     {
-        mServer->stop();
+        mServer.stop();
     } catch (const std::exception &e)
     {
         otbrLogCrit("failed to stop web server: %s", e.what());
     }
 }
 
-void WebServer::HandleHttpRequest(const char *aUrl, const char *aMethod, HttpRequestCallback aCallback)
-{
-    mServer->resource[aUrl][aMethod] = [aCallback, this](std::shared_ptr<HttpServer::Response> response,
-                                                         std::shared_ptr<HttpServer::Request>  request) {
-        try
-        {
-            std::string httpResponse;
-            if (aCallback != nullptr)
-            {
-                httpResponse = aCallback(request->content.string(), this);
-            }
-
-            *response << OT_RESPONSE_SUCCESS_STATUS << OT_RESPONSE_HEADER_LENGTH << httpResponse.length()
-                      << OT_RESPONSE_PLACEHOLD << httpResponse;
-        } catch (std::exception &e)
-        {
-            std::string content = e.what();
-            EscapeHtml(content);
-            *response << OT_RESPONSE_FAILURE_STATUS << OT_RESPONSE_HEADER_LENGTH << strlen(e.what())
-                      << OT_RESPONSE_PLACEHOLD << content;
-        }
-    };
-}
-
-void DefaultResourceSend(const HttpServer                            &aServer,
-                         const std::shared_ptr<HttpServer::Response> &aResponse,
-                         const std::shared_ptr<std::ifstream>        &aIfStream)
-{
-    static std::vector<char> buffer(OT_BUFFER_SIZE); // Safe when server is running on one thread
-
-    std::streamsize readLength;
-
-    if ((readLength = aIfStream->read(&buffer[0], buffer.size()).gcount()) > 0)
-    {
-        aResponse->write(&buffer[0], readLength);
-        if (readLength == static_cast<std::streamsize>(buffer.size()))
-        {
-            aResponse->send([&aServer, aResponse, aIfStream](const boost::system::error_code &ec) {
-                if (!ec)
-                {
-                    DefaultResourceSend(aServer, aResponse, aIfStream);
-                }
-                else
-                {
-                    std::cerr << "Connection interrupted" << std::endl;
-                }
-            });
-        }
-    }
-}
-
-void WebServer::DefaultHttpResponse(void)
-{
-    mServer->default_resource[OT_REQUEST_METHOD_GET] = [this](std::shared_ptr<HttpServer::Response> response,
-                                                              std::shared_ptr<HttpServer::Request>  request) {
-        try
-        {
-            auto webRootPath = boost::filesystem::canonical(WEB_FILE_PATH);
-            auto path        = boost::filesystem::canonical(webRootPath / request->path);
-
-            // Check if path is within webRootPath
-            if (std::distance(webRootPath.begin(), webRootPath.end()) > std::distance(path.begin(), path.end()) ||
-                !std::equal(webRootPath.begin(), webRootPath.end(), path.begin()))
-            {
-                throw std::invalid_argument("path must be within root path");
-            }
-            if (boost::filesystem::is_directory(path))
-            {
-                path /= "index.html";
-            }
-            if (!(boost::filesystem::exists(path) && boost::filesystem::is_regular_file(path)))
-            {
-                throw std::invalid_argument("file does not exist");
-            }
-
-            std::string cacheControl, etag;
-
-            auto ifs = std::make_shared<std::ifstream>();
-            ifs->open(path.string(), std::ifstream::in | std::ios::binary | std::ios::ate);
-            std::string extension = path.extension().string();
-            std::string header    = "";
-            if (extension == ".css")
-            {
-                header = OT_RESPONSE_HEADER_CSS_TYPE;
-            }
-            else if (extension == ".html")
-            {
-                header = OT_RESPONSE_HEADER_TEXT_HTML_TYPE;
-            }
-
-            if (*ifs)
-            {
-                auto length = ifs->tellg();
-                ifs->seekg(0, std::ios::beg);
-
-                *response << OT_RESPONSE_SUCCESS_STATUS << cacheControl << etag << OT_RESPONSE_HEADER_LENGTH << length
-                          << header << OT_RESPONSE_PLACEHOLD;
-
-                DefaultResourceSend(*mServer, response, ifs);
-            }
-            else
-            {
-                throw std::invalid_argument("could not read file");
-            }
-
-        } catch (const std::exception &e)
-        {
-            std::string content = "Could not open path `" + request->path + "`: " + e.what();
-            EscapeHtml(content);
-            *response << OT_RESPONSE_FAILURE_STATUS << OT_RESPONSE_HEADER_LENGTH << content.length()
-                      << OT_RESPONSE_PLACEHOLD << content;
-        }
-    };
-}
-
 std::string WebServer::HandleJoinNetworkRequest(const std::string &aJoinRequest, void *aUserData)
 {
     WebServer *webServer = static_cast<WebServer *>(aUserData);
@@ -334,42 +169,66 @@ std::string WebServer::HandleCommission(const std::string &aCommissionRequest, v
 
 void WebServer::ResponseJoinNetwork(void)
 {
-    HandleHttpRequest(OT_JOIN_NETWORK_PATH, OT_REQUEST_METHOD_POST, HandleJoinNetworkRequest);
+    mServer.Post(OT_JOIN_NETWORK_PATH, [this](const Request &aRequest, Response &aResponse) {
+        auto body = HandleJoinNetworkRequest(aRequest.body);
+        aResponse.set_content(body, OT_RESPONSE_HEADER_TYPE);
+    });
 }
 
 void WebServer::ResponseGetQRCode(void)
 {
-    HandleHttpRequest(OT_GET_QRCODE_PATH, OT_REQUEST_METHOD_GET, HandleGetQRCodeRequest);
+    mServer.Get(OT_GET_QRCODE_PATH, [this](const Request &aRequest, Response &aResponse) {
+        auto body = HandleGetQRCodeRequest(aRequest.body);
+        aResponse.set_content(body, OT_RESPONSE_HEADER_TYPE);
+    });
 }
 
 void WebServer::ResponseFormNetwork(void)
 {
-    HandleHttpRequest(OT_FORM_NETWORK_PATH, OT_REQUEST_METHOD_POST, HandleFormNetworkRequest);
+    mServer.Post(OT_FORM_NETWORK_PATH, [this](const Request &aRequest, Response &aResponse) {
+        auto body = HandleFormNetworkRequest(aRequest.body);
+        aResponse.set_content(body, OT_RESPONSE_HEADER_TYPE);
+    });
 }
 
 void WebServer::ResponseAddOnMeshPrefix(void)
 {
-    HandleHttpRequest(OT_ADD_PREFIX_PATH, OT_REQUEST_METHOD_POST, HandleAddPrefixRequest);
+    mServer.Post(OT_ADD_PREFIX_PATH, [this](const Request &aRequest, Response &aResponse) {
+        auto body = HandleAddPrefixRequest(aRequest.body);
+        aResponse.set_content(body, OT_RESPONSE_HEADER_TYPE);
+    });
 }
 
 void WebServer::ResponseDeleteOnMeshPrefix(void)
 {
-    HandleHttpRequest(OT_DELETE_PREFIX_PATH, OT_REQUEST_METHOD_POST, HandleDeletePrefixRequest);
+    mServer.Post(OT_DELETE_PREFIX_PATH, [this](const Request &aRequest, Response &aResponse) {
+        auto body = HandleDeletePrefixRequest(aRequest.body);
+        aResponse.set_content(body, OT_RESPONSE_HEADER_TYPE);
+    });
 }
 
 void WebServer::ResponseGetStatus(void)
 {
-    HandleHttpRequest(OT_GET_NETWORK_PATH, OT_REQUEST_METHOD_GET, HandleGetStatusRequest);
+    mServer.Get(OT_GET_NETWORK_PATH, [this](const Request &aRequest, Response &aResponse) {
+        auto body = HandleGetStatusRequest(aRequest.body);
+        aResponse.set_content(body, OT_RESPONSE_HEADER_TYPE);
+    });
 }
 
 void WebServer::ResponseGetAvailableNetwork(void)
 {
-    HandleHttpRequest(OT_AVAILABLE_NETWORK_PATH, OT_REQUEST_METHOD_GET, HandleGetAvailableNetworkResponse);
+    mServer.Get(OT_AVAILABLE_NETWORK_PATH, [this](const Request &aRequest, Response &aResponse) {
+        auto body = HandleGetAvailableNetworkResponse(aRequest.body);
+        aResponse.set_content(body, OT_RESPONSE_HEADER_TYPE);
+    });
 }
 
 void WebServer::ResponseCommission(void)
 {
-    HandleHttpRequest(OT_COMMISSIONER_START_PATH, OT_REQUEST_METHOD_POST, HandleCommission);
+    mServer.Post(OT_COMMISSIONER_START_PATH, [this](const Request &aRequest, Response &aResponse) {
+        auto body = HandleCommission(aRequest.body);
+        aResponse.set_content(body, OT_RESPONSE_HEADER_TYPE);
+    });
 }
 
 std::string WebServer::HandleJoinNetworkRequest(const std::string &aJoinRequest)
diff --git a/src/web/web-service/web_server.hpp b/src/web/web-service/web_server.hpp
index 4520e41d..c5c70c3b 100644
--- a/src/web/web-service/web_server.hpp
+++ b/src/web/web-service/web_server.hpp
@@ -36,29 +36,16 @@
 
 #include "openthread-br/config.h"
 
-#include <algorithm>
-#include <fstream>
-#include <iostream>
-#include <string>
-#include <vector>
-
+#include <httplib.h>
 #include <net/if.h>
+#include <string>
 #include <syslog.h>
 
-#include <boost/asio/ip/tcp.hpp>
-
 #include "web/web-service/wpan_service.hpp"
 
-namespace SimpleWeb {
-template <class T> class Server;
-typedef boost::asio::ip::tcp::socket HTTP;
-} // namespace SimpleWeb
-
 namespace otbr {
 namespace Web {
 
-typedef SimpleWeb::Server<SimpleWeb::HTTP> HttpServer;
-
 /**
  * This class implements the http server.
  */
@@ -123,7 +110,7 @@ private:
 
     void Init(void);
 
-    HttpServer            *mServer;
+    httplib::Server        mServer;
     otbr::Web::WpanService mWpanService;
 };
 
diff --git a/tests/android/java/com/android/server/thread/openthread/testing/FakeOtDaemonTest.java b/tests/android/java/com/android/server/thread/openthread/testing/FakeOtDaemonTest.java
index 6bb72cdf..1ebaf0f4 100644
--- a/tests/android/java/com/android/server/thread/openthread/testing/FakeOtDaemonTest.java
+++ b/tests/android/java/com/android/server/thread/openthread/testing/FakeOtDaemonTest.java
@@ -318,12 +318,13 @@ public final class FakeOtDaemonTest {
     }
 
     @Test
-    public void setNat64Cidr_onSuccessIsInvoked() throws Exception {
+    public void setNat64Cidr_valueSavedAndOnSuccessIsInvoked() throws Exception {
         IOtStatusReceiver receiver = mock(IOtStatusReceiver.class);
 
         mFakeOtDaemon.setNat64Cidr(TEST_NAT64_CIDR, receiver);
         mTestLooper.dispatchAll();
 
+        assertThat(mFakeOtDaemon.getNat64Cidr()).isEqualTo(TEST_NAT64_CIDR);
         verify(receiver, never()).onError(anyInt(), any());
         verify(receiver, times(1)).onSuccess();
     }
diff --git a/tests/dbus/test-client b/tests/dbus/test-client
index 52a52dbd..ef166acf 100755
--- a/tests/dbus/test-client
+++ b/tests/dbus/test-client
@@ -378,7 +378,7 @@ EOF
     ot_ctl dataset active | grep "Done"
 
     sudo dbus-send --system --dest=io.openthread.BorderRouter.wpan0 \
-        --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 \
+        --type=method_call --reply-timeout=40000 --print-reply /io/openthread/BorderRouter/wpan0 \
         io.openthread.BorderRouter.AttachAllNodesTo \
         "array:byte:${dataset}" \
         | grep "int64 300000"
diff --git a/tests/gtest/CMakeLists.txt b/tests/gtest/CMakeLists.txt
index c0761272..7d59fb7a 100644
--- a/tests/gtest/CMakeLists.txt
+++ b/tests/gtest/CMakeLists.txt
@@ -75,6 +75,8 @@ if(OTBR_MDNS)
 endif()
 
 add_executable(otbr-posix-gtest-unit
+    test_cli_daemon.cpp
+    test_infra_if.cpp
     test_netif.cpp
 )
 target_link_libraries(otbr-posix-gtest-unit
@@ -84,7 +86,7 @@ target_link_libraries(otbr-posix-gtest-unit
 gtest_discover_tests(otbr-posix-gtest-unit PROPERTIES LABELS "sudo")
 
 add_executable(otbr-gtest-host-api
-    ${OTBR_PROJECT_DIRECTORY}/src/ncp/rcp_host.cpp
+    ${OTBR_PROJECT_DIRECTORY}/src/host/rcp_host.cpp
     ${OPENTHREAD_PROJECT_DIRECTORY}/tests/gtest/fake_platform.cpp
     fake_posix_platform.cpp
     test_rcp_host_api.cpp
diff --git a/tests/gtest/test_async_task.cpp b/tests/gtest/test_async_task.cpp
index 46f3649d..549bd982 100644
--- a/tests/gtest/test_async_task.cpp
+++ b/tests/gtest/test_async_task.cpp
@@ -34,10 +34,10 @@
 #include <openthread/error.h>
 
 #include "common/code_utils.hpp"
-#include "ncp/async_task.hpp"
+#include "host/async_task.hpp"
 
-using otbr::Ncp::AsyncTask;
-using otbr::Ncp::AsyncTaskPtr;
+using otbr::Host::AsyncTask;
+using otbr::Host::AsyncTaskPtr;
 
 TEST(AsyncTask, TestOneStep)
 {
diff --git a/tests/gtest/test_cli_daemon.cpp b/tests/gtest/test_cli_daemon.cpp
new file mode 100644
index 00000000..87997ce4
--- /dev/null
+++ b/tests/gtest/test_cli_daemon.cpp
@@ -0,0 +1,83 @@
+/*
+ *    Copyright (c) 2025, The OpenThread Authors.
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
+#include <cstring>
+#include <ifaddrs.h>
+#include <iostream>
+#include <net/if.h>
+#include <netinet/in.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <string>
+#include <sys/ioctl.h>
+#include <sys/socket.h>
+#include <sys/types.h>
+#include <vector>
+
+#include <openthread/ip6.h>
+
+#include "common/types.hpp"
+#include "host/posix/cli_daemon.hpp"
+
+// Only Test on linux platform for now.
+#ifdef __linux__
+
+TEST(CliDaemon, InitSocketCreationWithFullNetIfName)
+{
+    const char *netIfName  = "tun0";
+    const char *socketFile = "/run/openthread-tun0.sock";
+    const char *lockFile   = "/run/openthread-tun0.lock";
+
+    otbr::CliDaemon cliDaemon;
+    cliDaemon.Init(netIfName);
+
+    struct stat st;
+
+    EXPECT_EQ(stat(socketFile, &st), 0);
+    EXPECT_EQ(stat(lockFile, &st), 0);
+}
+
+TEST(CliDaemon, InitSocketCreationWithEmptyNetIfName)
+{
+    const char *socketFile = "/run/openthread-wpan0.sock";
+    const char *lockFile   = "/run/openthread-wpan0.lock";
+
+    otbr::CliDaemon cliDaemon;
+    cliDaemon.Init("");
+
+    struct stat st;
+
+    EXPECT_EQ(stat(socketFile, &st), 0);
+    EXPECT_EQ(stat(lockFile, &st), 0);
+}
+
+#endif // __linux__
diff --git a/tests/gtest/test_infra_if.cpp b/tests/gtest/test_infra_if.cpp
new file mode 100644
index 00000000..84070358
--- /dev/null
+++ b/tests/gtest/test_infra_if.cpp
@@ -0,0 +1,258 @@
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
+#include "host/posix/infra_if.hpp"
+#include "host/posix/netif.hpp"
+
+// Only Test on linux platform for now.
+#ifdef __linux__
+
+class InfraIfDependencyTest : public otbr::InfraIf::Dependencies
+{
+public:
+    InfraIfDependencyTest(void)
+        : mInfraIfIndex(0)
+        , mIsRunning(false)
+        , mSetInfraIfInvoked(false)
+        , mIcmp6NdDataLen(0)
+        , mHandleIcmp6NdInvoked(false)
+    {
+        memset(mIcmp6NdData, 0, sizeof(mIcmp6NdData));
+    }
+
+    otbrError SetInfraIf(unsigned int                         aInfraIfIndex,
+                         bool                                 aIsRunning,
+                         const std::vector<otbr::Ip6Address> &aIp6Addresses) override
+    {
+        mInfraIfIndex      = aInfraIfIndex;
+        mIsRunning         = aIsRunning;
+        mIp6Addresses      = aIp6Addresses;
+        mSetInfraIfInvoked = true;
+
+        return OTBR_ERROR_NONE;
+    }
+
+    otbrError HandleIcmp6Nd(uint32_t                aInfraIfIndex,
+                            const otbr::Ip6Address &aSrcAddress,
+                            const uint8_t          *aData,
+                            uint16_t                aDataLen) override
+    {
+        mInfraIfIndex      = aInfraIfIndex;
+        mIcmp6NdSrcAddress = aSrcAddress;
+        memcpy(mIcmp6NdData, aData, aDataLen);
+        mIcmp6NdDataLen       = aDataLen;
+        mHandleIcmp6NdInvoked = true;
+
+        return OTBR_ERROR_NONE;
+    }
+
+    unsigned int                  mInfraIfIndex;
+    bool                          mIsRunning;
+    std::vector<otbr::Ip6Address> mIp6Addresses;
+    bool                          mSetInfraIfInvoked;
+
+    otbr::Ip6Address mIcmp6NdSrcAddress;
+    uint8_t          mIcmp6NdData[1280];
+    uint16_t         mIcmp6NdDataLen;
+    bool             mHandleIcmp6NdInvoked;
+};
+
+TEST(InfraIf, DepsSetInfraIfInvokedCorrectly_AfterSpecifyingInfraIf)
+{
+    const std::string fakeInfraIf = "wlx123";
+
+    // Utilize the Netif module to create a network interface as the fake infrastructure interface.
+    otbr::Netif::Dependencies defaultNetifDep;
+    otbr::Netif               netif(defaultNetifDep);
+    EXPECT_EQ(netif.Init(fakeInfraIf), OTBR_ERROR_NONE);
+
+    const otIp6Address kTestAddr = {
+        {0xfd, 0x35, 0x7a, 0x7d, 0x0f, 0x16, 0xe7, 0xe3, 0x73, 0xf3, 0x09, 0x00, 0x8e, 0xbe, 0x1b, 0x65}};
+    std::vector<otbr::Ip6AddressInfo> addrs = {
+        {kTestAddr, 64, 0, 1, 0},
+    };
+    netif.UpdateIp6UnicastAddresses(addrs);
+
+    InfraIfDependencyTest testInfraIfDep;
+    otbr::InfraIf         infraIf(testInfraIfDep);
+    EXPECT_EQ(infraIf.SetInfraIf(fakeInfraIf.c_str()), OTBR_ERROR_NONE);
+
+    EXPECT_NE(testInfraIfDep.mInfraIfIndex, 0);
+    EXPECT_EQ(testInfraIfDep.mIsRunning, false);
+    EXPECT_EQ(testInfraIfDep.mIp6Addresses.size(), 1);
+    EXPECT_THAT(testInfraIfDep.mIp6Addresses, ::testing::Contains(otbr::Ip6Address(kTestAddr)));
+
+    netif.Deinit();
+}
+
+TEST(InfraIf, DepsUpdateInfraIfStateInvokedCorrectly_AfterInfraIfStateChange)
+{
+    const std::string     fakeInfraIf = "wlx123";
+    otbr::MainloopContext context;
+
+    // Utilize the Netif module to create a network interface as the fake infrastructure interface.
+    otbr::Netif::Dependencies defaultNetifDep;
+    otbr::Netif               netif(defaultNetifDep);
+    EXPECT_EQ(netif.Init(fakeInfraIf), OTBR_ERROR_NONE);
+
+    const otIp6Address kTestAddr1 = {
+        {0xfd, 0x35, 0x7a, 0x7d, 0x0f, 0x16, 0xe7, 0xe3, 0x73, 0xf3, 0x09, 0x00, 0x8e, 0xbe, 0x1b, 0x65}};
+    const otIp6Address kTestAddr2 = {
+        {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0xa5, 0x42, 0xb7, 0x91, 0x80, 0xc3, 0xf8}};
+    std::vector<otbr::Ip6AddressInfo> addrs = {
+        {kTestAddr1, 64, 0, 1, 0},
+        {kTestAddr2, 64, 0, 1, 0},
+    };
+    netif.UpdateIp6UnicastAddresses(addrs);
+
+    InfraIfDependencyTest testInfraIfDep;
+    otbr::InfraIf         infraIf(testInfraIfDep);
+    infraIf.Init();
+    EXPECT_EQ(infraIf.SetInfraIf(fakeInfraIf.c_str()), OTBR_ERROR_NONE);
+
+    EXPECT_EQ(testInfraIfDep.mIsRunning, false);
+    EXPECT_EQ(testInfraIfDep.mIp6Addresses.size(), 2);
+
+    netif.SetNetifState(true);
+    testInfraIfDep.mSetInfraIfInvoked = false;
+
+    while (!testInfraIfDep.mSetInfraIfInvoked)
+    {
+        context.mMaxFd   = -1;
+        context.mTimeout = {100, 0};
+        FD_ZERO(&context.mReadFdSet);
+        FD_ZERO(&context.mWriteFdSet);
+        FD_ZERO(&context.mErrorFdSet);
+
+        infraIf.UpdateFdSet(context);
+        int rval = select(context.mMaxFd + 1, &context.mReadFdSet, &context.mWriteFdSet, &context.mErrorFdSet,
+                          &context.mTimeout);
+        if (rval < 0)
+        {
+            perror("select failed");
+            exit(EXIT_FAILURE);
+        }
+        infraIf.Process(context);
+    }
+    EXPECT_EQ(testInfraIfDep.mIsRunning, true);
+
+    addrs.clear();
+    netif.UpdateIp6UnicastAddresses(addrs);
+    testInfraIfDep.mSetInfraIfInvoked = false;
+    while (!testInfraIfDep.mSetInfraIfInvoked)
+    {
+        context.mMaxFd   = -1;
+        context.mTimeout = {100, 0};
+        FD_ZERO(&context.mReadFdSet);
+        FD_ZERO(&context.mWriteFdSet);
+        FD_ZERO(&context.mErrorFdSet);
+
+        infraIf.UpdateFdSet(context);
+        int rval = select(context.mMaxFd + 1, &context.mReadFdSet, &context.mWriteFdSet, &context.mErrorFdSet,
+                          &context.mTimeout);
+        if (rval < 0)
+        {
+            perror("select failed");
+            exit(EXIT_FAILURE);
+        }
+        infraIf.Process(context);
+    }
+    EXPECT_EQ(testInfraIfDep.mIp6Addresses.size(), 0);
+    EXPECT_EQ(testInfraIfDep.mIsRunning, false);
+
+    infraIf.Deinit();
+    netif.Deinit();
+}
+
+TEST(InfraIf, DepsHandleIcmp6NdInvokedCorrectly_AfterInfraIfReceivesIcmp6Nd)
+{
+    const std::string     fakeInfraIf = "wlx123";
+    otbr::MainloopContext context;
+
+    // Utilize the Netif module to create a network interface as the fake infrastructure interface.
+    otbr::Netif::Dependencies defaultNetifDep;
+    otbr::Netif               netif(defaultNetifDep);
+    EXPECT_EQ(netif.Init(fakeInfraIf), OTBR_ERROR_NONE);
+
+    const otIp6Address kLinkLocalAddr = {
+        {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0xa5, 0x42, 0xb7, 0x91, 0x80, 0xc3, 0xf8}};
+    const otIp6Address kPeerLinkLocalAddr = {
+        {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xe5, 0x5b, 0xff, 0xfe, 0xc6, 0x8a, 0xf3}};
+    std::vector<otbr::Ip6AddressInfo> addrs = {{kLinkLocalAddr, 64, 0, 1, 0}};
+    netif.UpdateIp6UnicastAddresses(addrs);
+
+    InfraIfDependencyTest testInfraIfDep;
+    otbr::InfraIf         infraIf(testInfraIfDep);
+    infraIf.Init();
+    EXPECT_EQ(infraIf.SetInfraIf(fakeInfraIf.c_str()), OTBR_ERROR_NONE);
+    netif.SetNetifState(true);
+
+    // Let the fake infrastructure interface receive a fake Icmp6 Nd message
+    // - Source Address: fe80::dee5:5bff:fec6:8af3
+    const uint8_t kTestMsg[] = {
+        0x60, 0x06, 0xce, 0x11, 0x00, 0x48, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0xde, 0xe5, 0x5b, 0xff, 0xfe, 0xc6, 0x8a, 0xf3, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0x00, 0xac, 0xf5, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x03, 0x04, 0x40, 0xc0, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00,
+        0xfd, 0x38, 0x5f, 0xf4, 0x61, 0x0b, 0x40, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x18, 0x02, 0x40, 0x00, 0x00, 0x00, 0x07, 0x08, 0xfd, 0x9f, 0x5c, 0xfa, 0x66, 0x3e, 0x00, 0x01,
+    };
+    const uint8_t  kTestMsgBodyOffset = 40;
+    const uint16_t kTestMsgBodySize   = sizeof(kTestMsg) - kTestMsgBodyOffset;
+    netif.Ip6Receive(kTestMsg, sizeof(kTestMsg));
+
+    while (!testInfraIfDep.mHandleIcmp6NdInvoked)
+    {
+        context.mMaxFd   = -1;
+        context.mTimeout = {100, 0};
+        FD_ZERO(&context.mReadFdSet);
+        FD_ZERO(&context.mWriteFdSet);
+        FD_ZERO(&context.mErrorFdSet);
+
+        infraIf.UpdateFdSet(context);
+        int rval = select(context.mMaxFd + 1, &context.mReadFdSet, &context.mWriteFdSet, &context.mErrorFdSet,
+                          &context.mTimeout);
+        if (rval < 0)
+        {
+            perror("select failed");
+            exit(EXIT_FAILURE);
+        }
+        infraIf.Process(context);
+    }
+    EXPECT_EQ(testInfraIfDep.mIcmp6NdSrcAddress, otbr::Ip6Address(kPeerLinkLocalAddr));
+    EXPECT_EQ(testInfraIfDep.mIcmp6NdDataLen, kTestMsgBodySize);
+    EXPECT_EQ(memcmp(testInfraIfDep.mIcmp6NdData, kTestMsg + kTestMsgBodyOffset, kTestMsgBodySize), 0);
+
+    infraIf.Deinit();
+    netif.Deinit();
+}
+#endif // __linux__
diff --git a/tests/gtest/test_netif.cpp b/tests/gtest/test_netif.cpp
index 1e51aaf6..229a826c 100644
--- a/tests/gtest/test_netif.cpp
+++ b/tests/gtest/test_netif.cpp
@@ -57,7 +57,7 @@
 #include "common/code_utils.hpp"
 #include "common/mainloop.hpp"
 #include "common/types.hpp"
-#include "ncp/posix/netif.hpp"
+#include "host/posix/netif.hpp"
 #include "utils/socket_utils.hpp"
 
 // Only Test on linux platform for now.
@@ -167,12 +167,7 @@ std::vector<std::string> GetAllIp6MulAddrs(const char *aInterfaceName)
     return ip6MulAddrs;
 }
 
-otbrError Ip6SendEmptyImpl(const uint8_t *aData, uint16_t aLength)
-{
-    OTBR_UNUSED_VARIABLE(aData);
-    OTBR_UNUSED_VARIABLE(aLength);
-    return OTBR_ERROR_NONE;
-}
+static otbr::Netif::Dependencies sDefaultNetifDependencies;
 
 TEST(Netif, WpanInitWithFullInterfaceName)
 {
@@ -180,8 +175,8 @@ TEST(Netif, WpanInitWithFullInterfaceName)
     int          sockfd;
     struct ifreq ifr;
 
-    otbr::Netif netif;
-    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OT_ERROR_NONE);
+    otbr::Netif netif(sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(wpan), OT_ERROR_NONE);
 
     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0)
@@ -204,8 +199,8 @@ TEST(Netif, WpanInitWithFormatInterfaceName)
     int          sockfd;
     struct ifreq ifr;
 
-    otbr::Netif netif;
-    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OT_ERROR_NONE);
+    otbr::Netif netif(sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(wpan), OT_ERROR_NONE);
 
     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0)
@@ -227,8 +222,8 @@ TEST(Netif, WpanInitWithEmptyInterfaceName)
     int          sockfd;
     struct ifreq ifr;
 
-    otbr::Netif netif;
-    EXPECT_EQ(netif.Init("", Ip6SendEmptyImpl), OT_ERROR_NONE);
+    otbr::Netif netif(sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(""), OT_ERROR_NONE);
 
     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0)
@@ -248,8 +243,8 @@ TEST(Netif, WpanInitWithInvalidInterfaceName)
 {
     const char *invalid_netif_name = "invalid_netif_name";
 
-    otbr::Netif netif;
-    EXPECT_EQ(netif.Init(invalid_netif_name, Ip6SendEmptyImpl), OTBR_ERROR_INVALID_ARGS);
+    otbr::Netif netif(sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(invalid_netif_name), OTBR_ERROR_INVALID_ARGS);
 }
 
 TEST(Netif, WpanMtuSize)
@@ -258,8 +253,8 @@ TEST(Netif, WpanMtuSize)
     int          sockfd;
     struct ifreq ifr;
 
-    otbr::Netif netif;
-    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OT_ERROR_NONE);
+    otbr::Netif netif(sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(wpan), OT_ERROR_NONE);
 
     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0)
@@ -281,8 +276,8 @@ TEST(Netif, WpanDeinit)
     int          sockfd;
     struct ifreq ifr;
 
-    otbr::Netif netif;
-    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OT_ERROR_NONE);
+    otbr::Netif netif(sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(wpan), OT_ERROR_NONE);
 
     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0)
@@ -300,8 +295,8 @@ TEST(Netif, WpanDeinit)
 
 TEST(Netif, WpanAddrGenMode)
 {
-    otbr::Netif netif;
-    EXPECT_EQ(netif.Init("wpan0", Ip6SendEmptyImpl), OT_ERROR_NONE);
+    otbr::Netif netif(sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init("wpan0"), OT_ERROR_NONE);
 
     std::fstream file("/proc/sys/net/ipv6/conf/wpan0/addr_gen_mode", std::ios::in);
     if (!file.is_open())
@@ -333,8 +328,8 @@ TEST(Netif, WpanIfHasCorrectUnicastAddresses_AfterUpdatingUnicastAddresses)
     const char *kMlRlocStr = "fd0d:7fc:a1b9:f050:0:ff:fe00:b800";
     const char *kMlAlocStr = "fd0d:7fc:a1b9:f050:0:ff:fe00:fc00";
 
-    otbr::Netif netif;
-    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OT_ERROR_NONE);
+    otbr::Netif netif(sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(wpan), OT_ERROR_NONE);
 
     otbr::Ip6AddressInfo testArray1[] = {
         {kLl, 64, 0, 1, 0},
@@ -377,14 +372,15 @@ TEST(Netif, WpanIfHasCorrectUnicastAddresses_AfterUpdatingUnicastAddresses)
 TEST(Netif, WpanIfHasCorrectMulticastAddresses_AfterUpdatingMulticastAddresses)
 {
     const char *wpan = "wpan0";
-    otbr::Netif netif;
-    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OT_ERROR_NONE);
+    otbr::Netif netif(sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(wpan), OT_ERROR_NONE);
 
     otbr::Ip6Address kDefaultMulAddr1 = {
         {0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};
     const char *kDefaultMulAddr1Str = "ff01::1";
     const char *kDefaultMulAddr2Str = "ff02::1";
     const char *kDefaultMulAddr3Str = "ff02::2";
+    const char *kDefaultMulAddr4Str = "ff02::16";
 
     otbr::Ip6Address kMulAddr1 = {
         {0xff, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc}};
@@ -399,48 +395,52 @@ TEST(Netif, WpanIfHasCorrectMulticastAddresses_AfterUpdatingMulticastAddresses)
     std::vector<otbr::Ip6Address> testVec1(testArray1, testArray1 + sizeof(testArray1) / sizeof(otbr::Ip6Address));
     netif.UpdateIp6MulticastAddresses(testVec1);
     std::vector<std::string> wpanMulAddrs = GetAllIp6MulAddrs(wpan);
-    EXPECT_EQ(wpanMulAddrs.size(), 4);
+    EXPECT_EQ(wpanMulAddrs.size(), 5);
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kMulAddr1Str));
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr1Str));
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr2Str));
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr3Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr4Str));
 
     otbr::Ip6Address              testArray2[] = {kMulAddr1, kMulAddr2};
     std::vector<otbr::Ip6Address> testVec2(testArray2, testArray2 + sizeof(testArray2) / sizeof(otbr::Ip6Address));
     netif.UpdateIp6MulticastAddresses(testVec2);
     wpanMulAddrs = GetAllIp6MulAddrs(wpan);
-    EXPECT_EQ(wpanMulAddrs.size(), 5);
+    EXPECT_EQ(wpanMulAddrs.size(), 6);
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kMulAddr1Str));
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kMulAddr2Str));
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr1Str));
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr2Str));
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr3Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr4Str));
 
     otbr::Ip6Address              testArray3[] = {kDefaultMulAddr1};
     std::vector<otbr::Ip6Address> testVec3(testArray3, testArray3 + sizeof(testArray3) / sizeof(otbr::Ip6Address));
     netif.UpdateIp6MulticastAddresses(testVec3);
     wpanMulAddrs = GetAllIp6MulAddrs(wpan);
-    EXPECT_EQ(wpanMulAddrs.size(), 3);
+    EXPECT_EQ(wpanMulAddrs.size(), 4);
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr1Str));
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr2Str));
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr3Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr4Str));
 
     std::vector<otbr::Ip6Address> empty;
     netif.UpdateIp6MulticastAddresses(empty);
     wpanMulAddrs = GetAllIp6MulAddrs(wpan);
-    EXPECT_EQ(wpanMulAddrs.size(), 3);
+    EXPECT_EQ(wpanMulAddrs.size(), 4);
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr1Str));
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr2Str));
     EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr3Str));
+    EXPECT_THAT(wpanMulAddrs, ::testing::Contains(kDefaultMulAddr4Str));
 
     netif.Deinit();
 }
 
 TEST(Netif, WpanIfStateChangesCorrectly_AfterSettingNetifState)
 {
-    otbr::Netif netif;
+    otbr::Netif netif(sDefaultNetifDependencies);
     const char *wpan = "wpan0";
-    EXPECT_EQ(netif.Init(wpan, Ip6SendEmptyImpl), OTBR_ERROR_NONE);
+    EXPECT_EQ(netif.Init(wpan), OTBR_ERROR_NONE);
 
     int fd = SocketWithCloseExec(AF_INET6, SOCK_DGRAM, IPPROTO_IP, kSocketNonBlock);
     if (fd < 0)
@@ -466,8 +466,8 @@ TEST(Netif, WpanIfStateChangesCorrectly_AfterSettingNetifState)
 
 TEST(Netif, WpanIfRecvIp6PacketCorrectly_AfterReceivingFromNetif)
 {
-    otbr::Netif netif;
-    EXPECT_EQ(netif.Init("wpan0", Ip6SendEmptyImpl), OTBR_ERROR_NONE);
+    otbr::Netif netif(sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init("wpan0"), OTBR_ERROR_NONE);
 
     const otIp6Address kOmr = {
         {0xfd, 0x2a, 0xc3, 0x0c, 0x87, 0xd3, 0x00, 0x01, 0xed, 0x1c, 0x0c, 0x91, 0xcc, 0xb6, 0x57, 0x8b}};
@@ -522,28 +522,43 @@ TEST(Netif, WpanIfRecvIp6PacketCorrectly_AfterReceivingFromNetif)
     netif.Deinit();
 }
 
-TEST(Netif, WpanIfSendIp6PacketCorrectly_AfterReceivingOnIf)
+class NetifDependencyTestIp6Send : public otbr::Netif::Dependencies
 {
-    bool        received = false;
-    std::string receivedPayload;
-    const char *hello = "Hello Otbr Netif!";
+public:
+    NetifDependencyTestIp6Send(bool &aReceived, std::string &aReceivedPayload)
+        : mReceived(aReceived)
+        , mReceivedPayload(aReceivedPayload)
+    {
+    }
 
-    auto Ip6SendTestImpl = [&received, &receivedPayload](const uint8_t *aData, uint16_t aLength) {
+    otbrError Ip6Send(const uint8_t *aData, uint16_t aLength) override
+    {
         const ip6_hdr *ipv6_header = reinterpret_cast<const ip6_hdr *>(aData);
         if (ipv6_header->ip6_nxt == IPPROTO_UDP)
         {
             const uint8_t *udpPayload    = aData + aLength - ntohs(ipv6_header->ip6_plen) + sizeof(udphdr);
             uint16_t       udpPayloadLen = ntohs(ipv6_header->ip6_plen) - sizeof(udphdr);
-            receivedPayload              = std::string(reinterpret_cast<const char *>(udpPayload), udpPayloadLen);
+            mReceivedPayload             = std::string(reinterpret_cast<const char *>(udpPayload), udpPayloadLen);
 
-            received = true;
+            mReceived = true;
         }
 
         return OTBR_ERROR_NONE;
-    };
+    }
+
+    bool        &mReceived;
+    std::string &mReceivedPayload;
+};
+
+TEST(Netif, WpanIfSendIp6PacketCorrectly_AfterReceivingOnIf)
+{
+    bool                       received = false;
+    std::string                receivedPayload;
+    NetifDependencyTestIp6Send netifDependency(received, receivedPayload);
+    const char                *hello = "Hello Otbr Netif!";
 
-    otbr::Netif netif;
-    EXPECT_EQ(netif.Init("wpan0", Ip6SendTestImpl), OT_ERROR_NONE);
+    otbr::Netif netif(netifDependency);
+    EXPECT_EQ(netif.Init("wpan0"), OT_ERROR_NONE);
 
     // OMR Prefix: fd76:a5d1:fcb0:1707::/64
     const otIp6Address kOmr = {
@@ -603,4 +618,108 @@ TEST(Netif, WpanIfSendIp6PacketCorrectly_AfterReceivingOnIf)
 
     netif.Deinit();
 }
+
+class NetifDependencyTestMulSub : public otbr::Netif::Dependencies
+{
+public:
+    NetifDependencyTestMulSub(bool &aReceived, otIp6Address &aMulAddr, bool &aIsAdded)
+        : mReceived(aReceived)
+        , mMulAddr(aMulAddr)
+        , mIsAdded(aIsAdded)
+    {
+    }
+
+    otbrError Ip6MulAddrUpdateSubscription(const otIp6Address &aAddress, bool aIsAdded) override
+    {
+        mMulAddr  = aAddress;
+        mIsAdded  = aIsAdded;
+        mReceived = true;
+        return OTBR_ERROR_NONE;
+    }
+
+    bool         &mReceived;
+    otIp6Address &mMulAddr;
+    bool         &mIsAdded;
+};
+
+TEST(Netif, WpanIfUpdateMulAddrSubscription_AfterAppJoiningMulGrp)
+{
+    bool                      received = false;
+    otIp6Address              subscribedMulAddr;
+    bool                      isAdded = false;
+    NetifDependencyTestMulSub dependency(received, subscribedMulAddr, isAdded);
+    const char               *multicastGroup = "ff99::1";
+    const char               *wpan           = "wpan0";
+    int                       sockFd;
+    otbr::Netif               netif(dependency);
+    const otIp6Address        expectedMulAddr = {0xff, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
+
+    EXPECT_EQ(netif.Init("wpan0"), OT_ERROR_NONE);
+
+    const otIp6Address kLl = {
+        {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x14, 0x03, 0x32, 0x4c, 0xc2, 0xf8, 0xd0}};
+    std::vector<otbr::Ip6AddressInfo> addrs = {
+        {kLl, 64, 0, 1, 0},
+    };
+    netif.UpdateIp6UnicastAddresses(addrs);
+    netif.SetNetifState(true);
+
+    {
+        struct ipv6_mreq    mreq;
+        struct sockaddr_in6 addr;
+
+        if ((sockFd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
+        {
+            perror("socket creation failed");
+            exit(EXIT_FAILURE);
+        }
+
+        memset(&addr, 0, sizeof(addr));
+        addr.sin6_family = AF_INET6;
+        addr.sin6_addr   = in6addr_any;
+        addr.sin6_port   = htons(9999);
+
+        if (bind(sockFd, (const struct sockaddr *)&addr, sizeof(addr)) < 0)
+        {
+            perror("bind failed");
+            exit(EXIT_FAILURE);
+        }
+
+        inet_pton(AF_INET6, multicastGroup, &(mreq.ipv6mr_multiaddr));
+        mreq.ipv6mr_interface = if_nametoindex(wpan);
+
+        if (setsockopt(sockFd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0)
+        {
+            perror("Error joining multicast group");
+            exit(EXIT_FAILURE);
+        }
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
+    EXPECT_EQ(otbr::Ip6Address(subscribedMulAddr), otbr::Ip6Address(expectedMulAddr));
+    EXPECT_EQ(isAdded, true);
+    close(sockFd);
+    netif.Deinit();
+}
+
 #endif // __linux__
diff --git a/tests/gtest/test_rcp_host_api.cpp b/tests/gtest/test_rcp_host_api.cpp
index 4f49257f..048156e4 100644
--- a/tests/gtest/test_rcp_host_api.cpp
+++ b/tests/gtest/test_rcp_host_api.cpp
@@ -36,7 +36,7 @@
 
 #include "common/mainloop.hpp"
 #include "common/mainloop_manager.hpp"
-#include "ncp/rcp_host.hpp"
+#include "host/rcp_host.hpp"
 
 #include "fake_platform.hpp"
 
@@ -64,27 +64,32 @@ static void MainloopProcessUntil(otbr::MainloopContext    &aMainloop,
 
 TEST(RcpHostApi, DeviceRoleChangesCorrectlyAfterSetThreadEnabled)
 {
-    otError                                    error          = OT_ERROR_FAILED;
-    bool                                       resultReceived = false;
-    otbr::MainloopContext                      mainloop;
-    otbr::Ncp::ThreadHost::AsyncResultReceiver receiver = [&resultReceived, &error](otError            aError,
-                                                                                    const std::string &aErrorMsg) {
+    otError                                     error              = OT_ERROR_FAILED;
+    bool                                        resultReceived     = false;
+    otbr::Host::ThreadEnabledState              threadEnabledState = otbr::Host::ThreadEnabledState::kStateInvalid;
+    otbr::MainloopContext                       mainloop;
+    otbr::Host::ThreadHost::AsyncResultReceiver receiver = [&resultReceived, &error](otError            aError,
+                                                                                     const std::string &aErrorMsg) {
         OT_UNUSED_VARIABLE(aErrorMsg);
         resultReceived = true;
         error          = aError;
     };
-    otbr::Ncp::RcpHost host("wpan0", std::vector<const char *>(), /* aBackboneInterfaceName */ "", /* aDryRun */ false,
-                            /* aEnableAutoAttach */ false);
+    otbr::Host::ThreadHost::ThreadEnabledStateCallback enabledStateCallback =
+        [&threadEnabledState](otbr::Host::ThreadEnabledState aState) { threadEnabledState = aState; };
+    otbr::Host::RcpHost host("wpan0", std::vector<const char *>(), /* aBackboneInterfaceName */ "", /* aDryRun */ false,
+                             /* aEnableAutoAttach */ false);
 
     host.Init();
+    host.AddThreadEnabledStateChangedCallback(enabledStateCallback);
 
     // 1. Active dataset hasn't been set, should succeed with device role still being disabled.
     host.SetThreadEnabled(true, receiver);
     MainloopProcessUntil(mainloop, /* aTimeoutSec */ 1, [&resultReceived]() { return resultReceived; });
     EXPECT_EQ(error, OT_ERROR_NONE);
     EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_DISABLED);
+    EXPECT_EQ(threadEnabledState, otbr::Host::ThreadEnabledState::kStateEnabled);
 
-    // 2. Set active dataset and enable it
+    // 2. Set active dataset and start it
     {
         otOperationalDataset     dataset;
         otOperationalDatasetTlvs datasetTlvs;
@@ -92,26 +97,32 @@ TEST(RcpHostApi, DeviceRoleChangesCorrectlyAfterSetThreadEnabled)
         otDatasetConvertToTlvs(&dataset, &datasetTlvs);
         OT_UNUSED_VARIABLE(otDatasetSetActiveTlvs(ot::FakePlatform::CurrentInstance(), &datasetTlvs));
     }
+    OT_UNUSED_VARIABLE(otIp6SetEnabled(ot::FakePlatform::CurrentInstance(), true));
+    OT_UNUSED_VARIABLE(otThreadSetEnabled(ot::FakePlatform::CurrentInstance(), true));
+
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 1,
+                         [&host]() { return host.GetDeviceRole() != OT_DEVICE_ROLE_DETACHED; });
+    EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_LEADER);
+
+    // 3. Enable again, the enabled state should not change.
     error          = OT_ERROR_FAILED;
     resultReceived = false;
     host.SetThreadEnabled(true, receiver);
     MainloopProcessUntil(mainloop, /* aTimeoutSec */ 1, [&resultReceived]() { return resultReceived; });
     EXPECT_EQ(error, OT_ERROR_NONE);
-    EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_DETACHED);
+    EXPECT_EQ(threadEnabledState, otbr::Host::ThreadEnabledState::kStateEnabled);
 
-    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 1,
-                         [&host]() { return host.GetDeviceRole() != OT_DEVICE_ROLE_DETACHED; });
-    EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_LEADER);
-
-    // 3. Disable it
+    // 4. Disable it
     error          = OT_ERROR_FAILED;
     resultReceived = false;
     host.SetThreadEnabled(false, receiver);
+    EXPECT_EQ(threadEnabledState, otbr::Host::ThreadEnabledState::kStateDisabling);
     MainloopProcessUntil(mainloop, /* aTimeoutSec */ 1, [&resultReceived]() { return resultReceived; });
     EXPECT_EQ(error, OT_ERROR_NONE);
     EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_DISABLED);
+    EXPECT_EQ(threadEnabledState, otbr::Host::ThreadEnabledState::kStateDisabled);
 
-    // 4. Duplicate call, should get OT_ERROR_BUSY
+    // 5. Duplicate call, should get OT_ERROR_BUSY
     error                   = OT_ERROR_FAILED;
     resultReceived          = false;
     otError error2          = OT_ERROR_FAILED;
@@ -126,23 +137,24 @@ TEST(RcpHostApi, DeviceRoleChangesCorrectlyAfterSetThreadEnabled)
                          [&resultReceived, &resultReceived2]() { return resultReceived && resultReceived2; });
     EXPECT_EQ(error, OT_ERROR_NONE);
     EXPECT_EQ(error2, OT_ERROR_BUSY);
+    EXPECT_EQ(threadEnabledState, otbr::Host::ThreadEnabledState::kStateDisabled);
 
     host.Deinit();
 }
 
 TEST(RcpHostApi, SetCountryCodeWorkCorrectly)
 {
-    otError                                    error          = OT_ERROR_FAILED;
-    bool                                       resultReceived = false;
-    otbr::MainloopContext                      mainloop;
-    otbr::Ncp::ThreadHost::AsyncResultReceiver receiver = [&resultReceived, &error](otError            aError,
-                                                                                    const std::string &aErrorMsg) {
+    otError                                     error          = OT_ERROR_FAILED;
+    bool                                        resultReceived = false;
+    otbr::MainloopContext                       mainloop;
+    otbr::Host::ThreadHost::AsyncResultReceiver receiver = [&resultReceived, &error](otError            aError,
+                                                                                     const std::string &aErrorMsg) {
         OT_UNUSED_VARIABLE(aErrorMsg);
         resultReceived = true;
         error          = aError;
     };
-    otbr::Ncp::RcpHost host("wpan0", std::vector<const char *>(), /* aBackboneInterfaceName */ "", /* aDryRun */ false,
-                            /* aEnableAutoAttach */ false);
+    otbr::Host::RcpHost host("wpan0", std::vector<const char *>(), /* aBackboneInterfaceName */ "", /* aDryRun */ false,
+                             /* aEnableAutoAttach */ false);
 
     // 1. Call SetCountryCode when host hasn't been initialized.
     otbr::MainloopManager::GetInstance().RemoveMainloopProcessor(
@@ -182,19 +194,89 @@ TEST(RcpHostApi, SetCountryCodeWorkCorrectly)
     host.Deinit();
 }
 
+TEST(RcpHostApi, StateChangesCorrectlyAfterLeave)
+{
+    otError                                     error          = OT_ERROR_NONE;
+    std::string                                 errorMsg       = "";
+    bool                                        resultReceived = false;
+    otbr::MainloopContext                       mainloop;
+    otbr::Host::ThreadHost::AsyncResultReceiver receiver = [&resultReceived, &error,
+                                                            &errorMsg](otError aError, const std::string &aErrorMsg) {
+        resultReceived = true;
+        error          = aError;
+        errorMsg       = aErrorMsg;
+    };
+
+    otbr::Host::RcpHost host("wpan0", std::vector<const char *>(), /* aBackboneInterfaceName */ "", /* aDryRun */ false,
+                             /* aEnableAutoAttach */ false);
+
+    // 1. Call Leave when host hasn't been initialized.
+    otbr::MainloopManager::GetInstance().RemoveMainloopProcessor(
+        &host); // Temporarily remove RcpHost because it's not initialized yet.
+    host.Leave(/* aEraseDataset */ true, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_INVALID_STATE);
+    EXPECT_STREQ(errorMsg.c_str(), "OT is not initialized");
+    otbr::MainloopManager::GetInstance().AddMainloopProcessor(&host);
+
+    host.Init();
+
+    // 2. Call Leave when disabling Thread.
+    error          = OT_ERROR_NONE;
+    resultReceived = false;
+    host.SetThreadEnabled(false, nullptr);
+    host.Leave(/* aEraseDataset */ true, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_BUSY);
+    EXPECT_STREQ(errorMsg.c_str(), "Thread is disabling");
+
+    // 3. Call Leave when Thread is disabled.
+    error          = OT_ERROR_NONE;
+    resultReceived = false;
+    otOperationalDataset     dataset;
+    otOperationalDatasetTlvs datasetTlvs;
+    OT_UNUSED_VARIABLE(otDatasetCreateNewNetwork(ot::FakePlatform::CurrentInstance(), &dataset));
+    otDatasetConvertToTlvs(&dataset, &datasetTlvs);
+    OT_UNUSED_VARIABLE(otDatasetSetActiveTlvs(ot::FakePlatform::CurrentInstance(), &datasetTlvs));
+    host.Leave(/* aEraseDataset */ true, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_NONE);
+
+    error = otDatasetGetActive(ot::FakePlatform::CurrentInstance(), &dataset);
+    EXPECT_EQ(error, OT_ERROR_NOT_FOUND);
+
+    // 4. Call Leave when Thread is enabled.
+    error          = OT_ERROR_NONE;
+    resultReceived = false;
+    OT_UNUSED_VARIABLE(otDatasetSetActiveTlvs(ot::FakePlatform::CurrentInstance(), &datasetTlvs));
+    host.SetThreadEnabled(true, nullptr);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 1,
+                         [&host]() { return host.GetDeviceRole() != OT_DEVICE_ROLE_DETACHED; });
+    EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_LEADER);
+    host.Leave(/* aEraseDataset */ false, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_NONE);
+
+    error = otDatasetGetActive(ot::FakePlatform::CurrentInstance(), &dataset); // Dataset should still be there.
+    EXPECT_EQ(error, OT_ERROR_NONE);
+
+    host.Deinit();
+}
+
 TEST(RcpHostApi, StateChangesCorrectlyAfterScheduleMigration)
 {
-    otError                                    error          = OT_ERROR_NONE;
-    bool                                       resultReceived = false;
-    otbr::MainloopContext                      mainloop;
-    otbr::Ncp::ThreadHost::AsyncResultReceiver receiver = [&resultReceived, &error](otError            aError,
-                                                                                    const std::string &aErrorMsg) {
-        OT_UNUSED_VARIABLE(aErrorMsg);
+    otError                                     error          = OT_ERROR_NONE;
+    std::string                                 errorMsg       = "";
+    bool                                        resultReceived = false;
+    otbr::MainloopContext                       mainloop;
+    otbr::Host::ThreadHost::AsyncResultReceiver receiver = [&resultReceived, &error,
+                                                            &errorMsg](otError aError, const std::string &aErrorMsg) {
         resultReceived = true;
         error          = aError;
+        errorMsg       = aErrorMsg;
     };
-    otbr::Ncp::RcpHost host("wpan0", std::vector<const char *>(), /* aBackboneInterfaceName */ "", /* aDryRun */ false,
-                            /* aEnableAutoAttach */ false);
+    otbr::Host::RcpHost host("wpan0", std::vector<const char *>(), /* aBackboneInterfaceName */ "", /* aDryRun */ false,
+                             /* aEnableAutoAttach */ false);
 
     otOperationalDataset     dataset;
     otOperationalDatasetTlvs datasetTlvs;
@@ -205,16 +287,18 @@ TEST(RcpHostApi, StateChangesCorrectlyAfterScheduleMigration)
     host.ScheduleMigration(datasetTlvs, receiver);
     MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
     EXPECT_EQ(error, OT_ERROR_INVALID_STATE);
+    EXPECT_STREQ(errorMsg.c_str(), "OT is not initialized");
     otbr::MainloopManager::GetInstance().AddMainloopProcessor(&host);
 
     host.Init();
 
-    // 2. Call ScheduleMigration when the device is not attached.
+    // 2. Call ScheduleMigration when the Thread is not enabled.
     error          = OT_ERROR_NONE;
     resultReceived = false;
     host.ScheduleMigration(datasetTlvs, receiver);
     MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
-    EXPECT_EQ(error, OT_ERROR_FAILED);
+    EXPECT_EQ(error, OT_ERROR_INVALID_STATE);
+    EXPECT_STREQ(errorMsg.c_str(), "Thread is disabled");
 
     // 3. Schedule migration to another network.
     OT_UNUSED_VARIABLE(otDatasetCreateNewNetwork(ot::FakePlatform::CurrentInstance(), &dataset));
@@ -233,3 +317,122 @@ TEST(RcpHostApi, StateChangesCorrectlyAfterScheduleMigration)
 
     host.Deinit();
 }
+
+TEST(RcpHostApi, StateChangesCorrectlyAfterJoin)
+{
+    otError                                     error           = OT_ERROR_NONE;
+    otError                                     error_          = OT_ERROR_NONE;
+    std::string                                 errorMsg        = "";
+    std::string                                 errorMsg_       = "";
+    bool                                        resultReceived  = false;
+    bool                                        resultReceived_ = false;
+    otbr::MainloopContext                       mainloop;
+    otbr::Host::ThreadHost::AsyncResultReceiver receiver = [&resultReceived, &error,
+                                                            &errorMsg](otError aError, const std::string &aErrorMsg) {
+        resultReceived = true;
+        error          = aError;
+        errorMsg       = aErrorMsg;
+    };
+    otbr::Host::ThreadHost::AsyncResultReceiver receiver_ = [&resultReceived_, &error_,
+                                                             &errorMsg_](otError aError, const std::string &aErrorMsg) {
+        resultReceived_ = true;
+        error_          = aError;
+        errorMsg_       = aErrorMsg;
+    };
+    otbr::Host::RcpHost host("wpan0", std::vector<const char *>(), /* aBackboneInterfaceName */ "", /* aDryRun */ false,
+                             /* aEnableAutoAttach */ false);
+
+    otOperationalDataset dataset;
+    (void)dataset;
+    otOperationalDatasetTlvs datasetTlvs;
+
+    // 1. Call Join when host hasn't been initialized.
+    otbr::MainloopManager::GetInstance().RemoveMainloopProcessor(
+        &host); // Temporarily remove RcpHost because it's not initialized yet.
+    host.Join(datasetTlvs, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_INVALID_STATE);
+    EXPECT_STREQ(errorMsg.c_str(), "OT is not initialized");
+    otbr::MainloopManager::GetInstance().AddMainloopProcessor(&host);
+
+    host.Init();
+    OT_UNUSED_VARIABLE(otDatasetCreateNewNetwork(ot::FakePlatform::CurrentInstance(), &dataset));
+    otDatasetConvertToTlvs(&dataset, &datasetTlvs);
+
+    // 2. Call Join when Thread is not enabled.
+    error          = OT_ERROR_NONE;
+    resultReceived = false;
+    host.Join(datasetTlvs, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_INVALID_STATE);
+    EXPECT_STREQ(errorMsg.c_str(), "Thread is not enabled");
+
+    // 3. Call two consecutive Join. The first one should be aborted. The second one should succeed.
+    error          = OT_ERROR_NONE;
+    resultReceived = false;
+    host.SetThreadEnabled(true, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    error          = OT_ERROR_NONE;
+    resultReceived = false;
+    host.Join(datasetTlvs, receiver_);
+    host.Join(datasetTlvs, receiver);
+
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0,
+                         [&resultReceived, &resultReceived_]() { return resultReceived && resultReceived_; });
+    EXPECT_EQ(error_, OT_ERROR_ABORT);
+    EXPECT_STREQ(errorMsg_.c_str(), "Aborted by leave/disable operation"); // The second Join will trigger Leave first.
+    EXPECT_EQ(error, OT_ERROR_NONE);
+    EXPECT_STREQ(errorMsg.c_str(), "Join succeeded");
+    EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_LEADER);
+
+    // 4. Call Join with the same dataset.
+    error          = OT_ERROR_NONE;
+    resultReceived = false;
+    host.Join(datasetTlvs, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    EXPECT_EQ(error, OT_ERROR_NONE);
+    EXPECT_STREQ(errorMsg.c_str(), "Already Joined the target network");
+
+    // 5. Call Disable right after Join (Already Attached).
+    error           = OT_ERROR_NONE;
+    resultReceived  = false;
+    error_          = OT_ERROR_NONE;
+    resultReceived_ = false;
+
+    OT_UNUSED_VARIABLE(otDatasetCreateNewNetwork(ot::FakePlatform::CurrentInstance(), &dataset));
+    otDatasetConvertToTlvs(&dataset, &datasetTlvs); // Use a different dataset.
+
+    host.Join(datasetTlvs, receiver_);
+    host.SetThreadEnabled(false, receiver);
+
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0,
+                         [&resultReceived, &resultReceived_]() { return resultReceived && resultReceived_; });
+    EXPECT_EQ(error_, OT_ERROR_BUSY);
+    EXPECT_STREQ(errorMsg_.c_str(), "Thread is disabling");
+    EXPECT_EQ(error, OT_ERROR_NONE);
+    EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_DISABLED);
+
+    // 6. Call Disable right after Join (not attached).
+    resultReceived = false;
+    host.Leave(true, receiver); // Leave the network first.
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+    resultReceived = false; // Enale Thread.
+    host.SetThreadEnabled(true, receiver);
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0, [&resultReceived]() { return resultReceived; });
+
+    error           = OT_ERROR_NONE;
+    resultReceived  = false;
+    error_          = OT_ERROR_NONE;
+    resultReceived_ = false;
+    host.Join(datasetTlvs, receiver_);
+    host.SetThreadEnabled(false, receiver);
+
+    MainloopProcessUntil(mainloop, /* aTimeoutSec */ 0,
+                         [&resultReceived, &resultReceived_]() { return resultReceived && resultReceived_; });
+    EXPECT_EQ(error_, OT_ERROR_ABORT);
+    EXPECT_STREQ(errorMsg_.c_str(), "Aborted by leave/disable operation");
+    EXPECT_EQ(error, OT_ERROR_NONE);
+    EXPECT_EQ(host.GetDeviceRole(), OT_DEVICE_ROLE_DISABLED);
+
+    host.Deinit();
+}
diff --git a/tests/rest/test_rest.py b/tests/rest/test_rest.py
index b419c2d6..fdccf526 100644
--- a/tests/rest/test_rest.py
+++ b/tests/rest/test_rest.py
@@ -296,6 +296,14 @@ def node_ext_panid_check(data):
     return True
 
 
+def node_coprocessor_version_check(data):
+    assert data is not None
+
+    assert (type(data) == str)
+
+    return True
+
+
 def node_test(thread_num):
     url = rest_api_addr + "/node"
 
@@ -406,6 +414,18 @@ def node_ext_panid_test(thread_num):
     print(" /node/ext-panid : all {}, valid {} ".format(thread_num, valid))
 
 
+def node_coprocessor_version_test(thread_num):
+    url = rest_api_addr + "/node/coprocessor/version"
+
+    response_data = [None] * thread_num
+
+    create_multi_thread(get_data_from_url, url, thread_num, response_data)
+
+    valid = [node_coprocessor_version_check(data) for data in response_data].count(True)
+
+    print(" /node/coprocessor/version : all {}, valid {} ".format(thread_num, valid))
+
+
 def diagnostics_test(thread_num):
     url = rest_api_addr + "/diagnostics"
 
@@ -450,6 +470,7 @@ def main():
     node_leader_data_test(200)
     node_num_of_router_test(200)
     node_ext_panid_test(200)
+    node_coprocessor_version_test(200)
     diagnostics_test(20)
     error_test(10)
 
diff --git a/tests/scripts/bootstrap.sh b/tests/scripts/bootstrap.sh
index 9c175970..d611b310 100755
--- a/tests/scripts/bootstrap.sh
+++ b/tests/scripts/bootstrap.sh
@@ -57,9 +57,6 @@ install_common_dependencies()
         doxygen \
         expect \
         net-tools \
-        libboost-dev \
-        libboost-filesystem-dev \
-        libboost-system-dev \
         libavahi-common-dev \
         libavahi-client-dev \
         libreadline-dev \
@@ -81,8 +78,6 @@ install_openthread_binraries()
     cmake .. -GNinja -DOT_PLATFORM=simulation -DOT_FULL_LOGS=1 -DOT_COMMISSIONER=ON -DOT_JOINER=ON
     ninja
     sudo ninja install
-
-    sudo apt-get install --no-install-recommends -y socat
 }
 
 configure_network()
@@ -99,22 +94,22 @@ case "$(uname)" in
         install_common_dependencies
 
         if [ "$BUILD_TARGET" == script-check ] || [ "$BUILD_TARGET" == docker-check ]; then
+            sudo bash third_party/openthread/repo/script/install_socat
             install_openthread_binraries
             configure_network
             exit 0
         fi
 
-        if [ "$BUILD_TARGET" == otbr-dbus-check ]; then
+        if [ "$BUILD_TARGET" == check ] || [ "$BUILD_TARGET" == meshcop ]; then
+            sudo bash third_party/openthread/repo/script/install_socat
             install_openthread_binraries
+            sudo apt-get install --no-install-recommends -y avahi-daemon avahi-utils
             configure_network
-            install_common_dependencies
-            exit 0
         fi
 
-        if [ "$BUILD_TARGET" == check ] || [ "$BUILD_TARGET" == meshcop ]; then
-            install_openthread_binraries
+        if [ "$BUILD_TARGET" == ncp_mode ]; then
+            sudo bash third_party/openthread/repo/script/install_socat
             sudo apt-get install --no-install-recommends -y avahi-daemon avahi-utils
-            configure_network
         fi
 
         if [ "$BUILD_TARGET" == scan-build ]; then
diff --git a/tests/scripts/check-docker b/tests/scripts/check-docker
index 3387a52a..9d308cfe 100755
--- a/tests/scripts/check-docker
+++ b/tests/scripts/check-docker
@@ -77,9 +77,11 @@ main()
     # shellcheck disable=SC2094
     ot-rcp 1 >"$DEVICE_PTY" <"$DEVICE_PTY" &
 
-    OTBR_DOCKER_PID=$(docker run -d \
-        --sysctl "net.ipv6.conf.all.disable_ipv6=0 net.ipv4.conf.all.forwarding=1 net.ipv6.conf.all.forwarding=1" \
-        --privileged -p 8080:80 --dns=127.0.0.1 --volume "$DOCKER_PTY":/dev/ttyUSB0 otbr --backbone-interface eth0)
+    OTBR_DOCKER_PID=$(
+        docker run -d -e HTTP_PORT=10080 \
+            --sysctl "net.ipv6.conf.all.disable_ipv6=0 net.ipv4.conf.all.forwarding=1 net.ipv6.conf.all.forwarding=1" \
+            --privileged -p 8080:10080 --dns=127.0.0.1 --volume "$DOCKER_PTY":/dev/ttyUSB0 otbr --backbone-interface eth0
+    )
     readonly OTBR_DOCKER_PID
     sleep 10
     sudo lsof -i :8080
diff --git a/tests/scripts/expect/_common.exp b/tests/scripts/expect/_common.exp
index bb02ff81..4e322fee 100644
--- a/tests/scripts/expect/_common.exp
+++ b/tests/scripts/expect/_common.exp
@@ -84,6 +84,10 @@ proc spawn_node {id type sim_app} {
                 timeout { fail "Timed out" }
             }
         }
+        otbr-docker {
+            spawn docker exec -it $sim_app bash
+            expect "app#"
+        }
         otbr {
             spawn $::env(EXP_OTBR_AGENT_PATH) -I $::env(EXP_TUN_NAME) -d7 "spinel+hdlc+forkpty://${sim_app}?forkpty-arg=${id}"
         }
@@ -94,6 +98,39 @@ proc spawn_node {id type sim_app} {
     return $spawn_id
 }
 
+proc create_socat {id} {
+    global socat_pid
+    spawn socat -d -d pty,raw,echo=0 pty,raw,echo=0
+    set socat_pid [exp_pid]
+    set pty1 ""
+    set pty2 ""
+    expect {
+        -re {PTY is (\S+).*PTY is (\S+)} {
+            set pty1 $expect_out(1,string)
+            set pty2 $expect_out(2,string)
+        }
+        timeout {
+            fail "Timed out"
+        }
+    }
+    set spawn_ids($id) $spawn_id
+    return [list $pty1 $pty2]
+}
+
+proc start_otbr_docker {name sim_app sim_id pty1 pty2} {
+    exec $sim_app $sim_id <$pty1 >$pty1 &
+    exec docker run -d \
+        --name $name \
+        --network backbone1 \
+        --cap-add=NET_ADMIN \
+        --privileged \
+        --sysctl net.ipv6.conf.all.disable_ipv6=0 \
+        --sysctl net.ipv4.conf.all.forwarding=1 \
+        --sysctl net.ipv6.conf.all.forwarding=1 \
+        -v $pty2:/dev/ttyUSB0 \
+        $::env(EXP_OTBR_DOCKER_IMAGE)
+}
+
 proc switch_node {id} {
     global spawn_ids
     global spawn_id
@@ -101,3 +138,41 @@ proc switch_node {id} {
     send_user "\n# ${id}\n"
     set spawn_id $spawn_ids($id)
 }
+
+proc dispose_node {id} {
+    switch_node $id
+    send "\x04"
+    expect eof
+}
+proc dispose_socat {} {
+    global socat_pid
+    if { [info exists socat_pid] } {
+        exec kill $socat_pid
+    }
+}
+proc dispose_all {} {
+    global spawn_ids
+    set max_node [array size spawn_ids]
+    for {set i 1} {$i <= $max_node} {incr i} {
+        if { [info exists spawn_ids($i)] } {
+            dispose_node $i
+        }
+    }
+    array unset spawn_ids
+    dispose_socat
+}
+
+proc get_ipaddr {type} {
+    send "ipaddr $type\n"
+    expect "ipaddr $type"
+    set rval [expect_line {([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}}]
+    expect_line "Done"
+
+    return $rval
+}
+
+proc get_omr_addr {} {
+    send "ipaddr -v\r\n"
+    expect -re {(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}(?= origin:slaac)}
+    return $expect_out(0,string)
+}
diff --git a/tests/scripts/expect/ncp_border_routing.exp b/tests/scripts/expect/ncp_border_routing.exp
new file mode 100755
index 00000000..1e5c5bb6
--- /dev/null
+++ b/tests/scripts/expect/ncp_border_routing.exp
@@ -0,0 +1,70 @@
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
+set ptys [create_socat 1]
+set pty1 [lindex $ptys 0]
+set pty2 [lindex $ptys 1]
+
+set container "otbr-ncp"
+
+set dataset "0e080000000000010000000300001435060004001fffe002087d61eb42cdc48d6a0708fd0d07fca1b9f0500510ba088fc2bd6c3b3897f7a10f58263ff3030f4f70656e5468726561642d353234660102524f04109dc023ccd447b12b50997ef68020f19e0c0402a0f7f8"
+set dataset_dbus "0x0e,0x08,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x03,0x00,0x00,0x14,0x35,0x06,0x00,0x04,0x00,0x1f,0xff,0xe0,0x02,0x08,0x7d,0x61,0xeb,0x42,0xcd,0xc4,0x8d,0x6a,0x07,0x08,0xfd,0x0d,0x07,0xfc,0xa1,0xb9,0xf0,0x50,0x05,0x10,0xba,0x08,0x8f,0xc2,0xbd,0x6c,0x3b,0x38,0x97,0xf7,0xa1,0x0f,0x58,0x26,0x3f,0xf3,0x03,0x0f,0x4f,0x70,0x65,0x6e,0x54,0x68,0x72,0x65,0x61,0x64,0x2d,0x35,0x32,0x34,0x66,0x01,0x02,0x52,0x4f,0x04,0x10,0x9d,0xc0,0x23,0xcc,0xd4,0x47,0xb1,0x2b,0x50,0x99,0x7e,0xf6,0x80,0x20,0xf1,0x9e,0x0c,0x04,0x02,0xa0,0xf7,0xf8"
+
+start_otbr_docker $container $::env(EXP_OT_NCP_PATH) 2 $pty1 $pty2
+
+spawn_node 3 otbr-docker $container
+spawn_node 4 cli $::env(EXP_OT_CLI_PATH)
+
+send "dataset set active ${dataset}\n"
+expect_line "Done"
+send "ifconfig up\r\n"
+expect_line "Done"
+send "thread start\r\n"
+expect_line "Done"
+wait_for "state" "leader"
+
+switch_node 3
+send "dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 io.openthread.BorderRouter.Join \"array:byte:${dataset_dbus}\"\n"
+expect "app#"
+sleep 20
+
+switch_node 4
+set omr_addr [get_omr_addr]
+sleep 1
+
+# Test pinging from the host (infrastructure network) to the cli
+set timeout 20
+spawn ping6 -c 10 $omr_addr
+expect -re {10 packets transmitted, 10 received, 0\% packet loss}
+
+exec sudo docker stop $container
+exec sudo docker rm $container
+dispose_all
diff --git a/tests/scripts/expect/ncp_netif_tx_rx.exp b/tests/scripts/expect/ncp_netif_tx_rx.exp
new file mode 100755
index 00000000..8e7d1f3c
--- /dev/null
+++ b/tests/scripts/expect/ncp_netif_tx_rx.exp
@@ -0,0 +1,67 @@
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
+set dest_addr [get_ipaddr mleid]
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
+# Step 4. Verify pinging from otbr-agent NCP to the cli node
+spawn ping6 -c 10 ${dest_addr}
+expect "10 packets transmitted, 10 received, 0% packet loss"
+expect eof
diff --git a/tests/scripts/expect/ncp_schedule_migration.exp b/tests/scripts/expect/ncp_schedule_migration.exp
old mode 100644
new mode 100755
diff --git a/tests/scripts/expect/ncp_srp_server.exp b/tests/scripts/expect/ncp_srp_server.exp
new file mode 100755
index 00000000..b7d6ab24
--- /dev/null
+++ b/tests/scripts/expect/ncp_srp_server.exp
@@ -0,0 +1,77 @@
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
+set ptys [create_socat 1]
+set pty1 [lindex $ptys 0]
+set pty2 [lindex $ptys 1]
+set container "otbr-ncp"
+
+set dataset "0e080000000000010000000300001435060004001fffe002087d61eb42cdc48d6a0708fd0d07fca1b9f0500510ba088fc2bd6c3b3897f7a10f58263ff3030f4f70656e5468726561642d353234660102524f04109dc023ccd447b12b50997ef68020f19e0c0402a0f7f8"
+set dataset_dbus "0x0e,0x08,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x03,0x00,0x00,0x14,0x35,0x06,0x00,0x04,0x00,0x1f,0xff,0xe0,0x02,0x08,0x7d,0x61,0xeb,0x42,0xcd,0xc4,0x8d,0x6a,0x07,0x08,0xfd,0x0d,0x07,0xfc,0xa1,0xb9,0xf0,0x50,0x05,0x10,0xba,0x08,0x8f,0xc2,0xbd,0x6c,0x3b,0x38,0x97,0xf7,0xa1,0x0f,0x58,0x26,0x3f,0xf3,0x03,0x0f,0x4f,0x70,0x65,0x6e,0x54,0x68,0x72,0x65,0x61,0x64,0x2d,0x35,0x32,0x34,0x66,0x01,0x02,0x52,0x4f,0x04,0x10,0x9d,0xc0,0x23,0xcc,0xd4,0x47,0xb1,0x2b,0x50,0x99,0x7e,0xf6,0x80,0x20,0xf1,0x9e,0x0c,0x04,0x02,0xa0,0xf7,0xf8"
+
+start_otbr_docker $container $::env(EXP_OT_NCP_PATH) 2 $pty1 $pty2
+spawn_node 3 otbr-docker $container
+sleep 5
+
+send "dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 io.openthread.BorderRouter.Join \"array:byte:${dataset_dbus}\"\n"
+expect "app#"
+sleep 20
+
+spawn_node 4 cli $::env(EXP_OT_CLI_PATH)
+send "dataset set active ${dataset}\n"
+expect_line "Done"
+send "mode rn\r\n"
+expect_line "Done"
+send "ifconfig up\r\n"
+expect_line "Done"
+send "thread start\r\n"
+expect_line "Done"
+wait_for "state" "child"
+set omr_addr [get_omr_addr]
+sleep 1
+
+send "srp client autostart enable\r\n"
+expect_line "Done"
+send "srp client host name otbr-ncp-test\r\n"
+expect_line "Done"
+send "srp client host address $omr_addr\r\n"
+expect_line "Done"
+send "srp client service add ot-service _ipps._tcp 12345\r\n"
+expect_line "Done"
+sleep 1
+
+spawn avahi-browse -r _ipps._tcp
+expect backbone1
+send "\003"
+expect eof
+
+exec sudo docker stop $container
+exec sudo docker rm $container
+dispose_all
diff --git a/tests/scripts/meshcop b/tests/scripts/meshcop
index f44882dd..104c21e7 100755
--- a/tests/scripts/meshcop
+++ b/tests/scripts/meshcop
@@ -517,7 +517,7 @@ test_meshcop_service()
     service="$(scan_meshcop_service)"
     grep "${OT_SERVICE_INSTANCE}._meshcop\._udp" <<<"${service}"
     grep "rv=1" <<<"${service}"
-    grep "tv=1\.3\.0" <<<"${service}"
+    grep "tv=1\.4\.0" <<<"${service}"
     grep "nn=${network_name}" <<<"${service}"
     grep "xp=${xpanid_txt}" <<<"${service}"
     grep "xa=${extaddr_txt}" <<<"${service}"
diff --git a/tests/scripts/ncp_mode b/tests/scripts/ncp_mode
index a6d00067..2544bf5b 100755
--- a/tests/scripts/ncp_mode
+++ b/tests/scripts/ncp_mode
@@ -46,6 +46,9 @@ readonly OT_CLI
 OT_NCP="${OT_NCP:-ot-ncp-ftd}"
 readonly OT_NCP
 
+OTBR_DOCKER_IMAGE="${OTBR_DOCKER_IMAGE:-otbr-ncp}"
+readonly OTBR_DOCKER_IMAGE
+
 ABS_TOP_BUILDDIR="$(cd "${top_builddir:-"${SCRIPT_DIR}"/../../}" && pwd)"
 readonly ABS_TOP_BUILDDIR
 
@@ -126,12 +129,53 @@ readonly TUN_NAME
 #----------------------------------------
 # Test steps
 #----------------------------------------
-build_ot_simulation()
+do_build_ot_simulation()
 {
     sudo rm -rf "${ABS_TOP_OT_BUILDDIR}/ncp"
     sudo rm -rf "${ABS_TOP_OT_BUILDDIR}/cli"
-    OT_CMAKE_BUILD_DIR=${ABS_TOP_OT_BUILDDIR}/ncp "${ABS_TOP_OT_SRCDIR}"/script/cmake-build simulation -DOT_MTD=OFF -DOT_APP_CLI=OFF -DOT_APP_RCP=OFF
-    OT_CMAKE_BUILD_DIR=${ABS_TOP_OT_BUILDDIR}/cli "${ABS_TOP_OT_SRCDIR}"/script/cmake-build simulation -DOT_MTD=OFF -DOT_APP_NCP=OFF -DOT_APP_RCP=OFF -DOT_RCP=OFF
+    OT_CMAKE_BUILD_DIR=${ABS_TOP_OT_BUILDDIR}/ncp "${ABS_TOP_OT_SRCDIR}"/script/cmake-build simulation \
+        -DOT_MTD=OFF -DOT_RCP=OFF -DOT_APP_CLI=OFF -DOT_APP_RCP=OFF \
+        -DOT_BORDER_ROUTING=ON -DOT_NCP_INFRA_IF=ON -DOT_SIMULATION_INFRA_IF=OFF \
+        -DOT_SRP_SERVER=ON -DOT_SRP_ADV_PROXY=ON -DOT_PLATFORM_DNSSD=ON -DOT_SIMULATION_DNSSD=OFF -DOT_NCP_DNSSD=ON \
+        -DBUILD_TESTING=OFF
+    OT_CMAKE_BUILD_DIR=${ABS_TOP_OT_BUILDDIR}/cli "${ABS_TOP_OT_SRCDIR}"/script/cmake-build simulation \
+        -DOT_MTD=OFF -DOT_RCP=OFF -DOT_APP_NCP=OFF -DOT_APP_RCP=OFF \
+        -DOT_BORDER_ROUTING=OFF \
+        -DBUILD_TESTING=OFF
+}
+
+do_build_otbr_docker()
+{
+    otbr_docker_options=(
+        "-DOT_THREAD_VERSION=1.4"
+        "-DOTBR_DBUS=ON"
+        "-DOTBR_FEATURE_FLAGS=ON"
+        "-DOTBR_TELEMETRY_DATA_API=ON"
+        "-DOTBR_TREL=ON"
+        "-DOTBR_LINK_METRICS_TELEMETRY=ON"
+        "-DOTBR_SRP_ADVERTISING_PROXY=ON"
+    )
+    sudo docker build -t "${OTBR_DOCKER_IMAGE}" \
+        -f ./etc/docker/Dockerfile . \
+        --build-arg NAT64=0 \
+        --build-arg NAT64_SERVICE=0 \
+        --build-arg DNS64=0 \
+        --build-arg WEB_GUI=0 \
+        --build-arg REST_API=0 \
+        --build-arg FIREWALL=0 \
+        --build-arg OTBR_OPTIONS="${otbr_docker_options[*]}"
+}
+
+setup_infraif()
+{
+    if ! ip link show backbone1 >/dev/null 2>&1; then
+        echo "Creating backbone1 with Docker..."
+        docker network create --driver bridge --ipv6 --subnet 9101::/64 -o "com.docker.network.bridge.name"="backbone1" backbone1
+    else
+        echo "backbone1 already exists."
+    fi
+    sudo sysctl -w net.ipv6.conf.backbone1.accept_ra=2
+    sudo sysctl -w net.ipv6.conf.backbone1.accept_ra_rt_info_max_plen=64
 }
 
 test_setup()
@@ -143,9 +187,14 @@ test_setup()
     # OPENTHREAD_POSIX_DAEMON_SOCKET_LOCK
     sudo rm -vf "/tmp/openthread.lock"
 
-    [[ ${BUILD_OT_SIM} == 1 ]] && build_ot_simulation
     ot_cli=$(find "${ABS_TOP_OT_BUILDDIR}" -name "${OT_CLI}")
     ot_ncp=$(find "${ABS_TOP_OT_BUILDDIR}" -name "${OT_NCP}")
+    executable_or_die "${ot_cli}"
+    executable_or_die "${ot_ncp}"
+
+    export EXP_OTBR_AGENT_PATH="${OTBR_AGENT_PATH}"
+    export EXP_OT_CLI_PATH="${ot_cli}"
+    export EXP_OT_NCP_PATH="${ot_ncp}"
 
     # We will be creating a lot of log information
     # Rotate logs so we have a clean and empty set of logs uncluttered with other stuff
@@ -160,6 +209,8 @@ test_setup()
     write_syslog "AGENT: kill old"
     sudo killall "${OTBR_AGENT}" || true
 
+    setup_infraif
+
     # From now on - all exits are TRAPPED
     # When they occur, we call the function: output_logs'.
     trap test_teardown EXIT
@@ -217,45 +268,68 @@ otbr_exec_expect_script()
     done
 }
 
-parse_args()
+do_expect()
 {
-    BUILD_OT_SIM=1
-    RUN_ALL_TESTS=1
+    if [[ $# != 0 ]]; then
+        otbr_exec_expect_script "$@"
+    else
+        mapfile -t test_files < <(find "${EXPECT_SCRIPT_DIR}" -type f -name "ncp_*.exp")
+        otbr_exec_expect_script "${test_files[@]}" || die "ncp expect script failed!"
+    fi
 
-    while [[ $# -gt 0 ]]; do
-        case $1 in
-            --build-ot-sim)
-                BUILD_OT_SIM="$2"
-                shift
-                ;;
-            --one-test)
-                RUN_ALL_TESTS=0
-                TEST_NAME="$2"
-                shift
-                ;;
-        esac
-        shift
-    done
+    exit 0
 }
 
-main()
+print_usage()
 {
-    parse_args "$@"
+    cat <<EOF
+USAGE: $0 COMMAND
+
+COMMAND:
+    build_ot_sim         Build simulated ot-cli-ftd and ot-ncp-ftd for testing.
+    build_otbr_docker    Build otbr docker image for testing.
+    expect               Run expect tests for otbr NCP mode.
+    help                 Print this help.
+
+EXAMPLES:
+    $0 build_ot_sim build_otbr_docker expect
+EOF
+    exit 0
+}
 
-    test_setup
+main()
+{
+    if [[ $# == 0 ]]; then
+        print_usage
+    fi
 
-    export EXP_OTBR_AGENT_PATH="${OTBR_AGENT_PATH}"
     export EXP_TUN_NAME="${TUN_NAME}"
     export EXP_LEADER_NODE_ID="${LEADER_NODE_ID}"
-    export EXP_OT_CLI_PATH="${ot_cli}"
-    export EXP_OT_NCP_PATH="${ot_ncp}"
+    export EXP_OTBR_DOCKER_IMAGE="${OTBR_DOCKER_IMAGE}"
 
-    if [[ ${RUN_ALL_TESTS} == 0 ]]; then
-        otbr_exec_expect_script "${EXPECT_SCRIPT_DIR}/${TEST_NAME}" || die "ncp expect script failed!"
-    else
-        mapfile -t test_files < <(find "${EXPECT_SCRIPT_DIR}" -type f -name "ncp_*.exp")
-        otbr_exec_expect_script "${test_files[@]}" || die "ncp expect script failed!"
-    fi
+    while [[ $# != 0 ]]; do
+        case "$1" in
+            build_ot_sim)
+                do_build_ot_simulation
+                ;;
+            build_otbr_docker)
+                do_build_otbr_docker
+                ;;
+            expect)
+                shift
+                test_setup
+                do_expect "$@"
+                ;;
+            help)
+                print_usage
+                ;;
+            *)
+                echo
+                echo -e "${OTBR_COLOR_FAIL}Warning:${OTBR_COLOR_NONE} Ignoring: '$1'"
+                ;;
+        esac
+        shift
+    done
 }
 
 main "$@"
diff --git a/third_party/Simple-web-server/README.md b/third_party/Simple-web-server/README.md
deleted file mode 100644
index 50d10287..00000000
--- a/third_party/Simple-web-server/README.md
+++ /dev/null
@@ -1,25 +0,0 @@
-# Simple-web-server
-
-## URL
-
-https://gitlab.com/eidheim/Simple-Web-Server
-
-## Version
-
-none
-
-## Commit
-
-2f29926dbbcd8a0425064d98c24f37ac50bd0b5b
-
-## License
-
-MIT License
-
-## License File
-
-[LICENSE](repo/LICENSE.txt)
-
-## Description
-
-A very simple, fast, multithreaded, platform independent HTTP and HTTPS server and client library implemented using C++11 and Boost.Asio. Created to be an easy way to make REST resources available from C++ applications.
diff --git a/third_party/Simple-web-server/repo/CMakeLists.txt b/third_party/Simple-web-server/repo/CMakeLists.txt
deleted file mode 100644
index f7b6c837..00000000
--- a/third_party/Simple-web-server/repo/CMakeLists.txt
+++ /dev/null
@@ -1,95 +0,0 @@
-cmake_minimum_required(VERSION 3.0)
-
-project(Simple-Web-Server)
-
-option(USE_STANDALONE_ASIO "set ON to use standalone Asio instead of Boost.Asio" OFF)
-if(CMAKE_SOURCE_DIR STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
-    option(BUILD_TESTING "set ON to build library tests" ON)
-else()
-    option(BUILD_TESTING "set ON to build library tests" OFF)
-endif()
-option(BUILD_FUZZING "set ON to build library fuzzers" OFF)
-option(USE_OPENSSL "set OFF to build without OpenSSL" ON)
-
-add_library(simple-web-server INTERFACE)
-
-target_include_directories(simple-web-server INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
-
-find_package(Threads REQUIRED)
-target_link_libraries(simple-web-server INTERFACE ${CMAKE_THREAD_LIBS_INIT})
-
-# TODO 2020 when Debian Jessie LTS ends:
-# Remove Boost system, thread, regex components; use Boost::<component> aliases; remove Boost target_include_directories
-if(USE_STANDALONE_ASIO)
-    target_compile_definitions(simple-web-server INTERFACE ASIO_STANDALONE)
-    find_path(ASIO_PATH asio.hpp)
-    if(NOT ASIO_PATH)
-        message(FATAL_ERROR "Standalone Asio not found")
-    else()
-        target_include_directories(simple-web-server INTERFACE ${ASIO_PATH})
-    endif()
-else()
-    find_package(Boost 1.53.0 COMPONENTS system thread REQUIRED)
-    target_link_libraries(simple-web-server INTERFACE ${Boost_LIBRARIES})
-    target_include_directories(simple-web-server INTERFACE ${Boost_INCLUDE_DIR})
-    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9)
-        target_compile_definitions(simple-web-server INTERFACE USE_BOOST_REGEX)
-        find_package(Boost 1.53.0 COMPONENTS regex REQUIRED)
-        target_link_libraries(simple-web-server INTERFACE ${Boost_LIBRARIES})
-        target_include_directories(simple-web-server INTERFACE ${Boost_INCLUDE_DIR})
-    endif()
-endif()
-if(WIN32)
-    target_link_libraries(simple-web-server INTERFACE ws2_32 wsock32)
-endif()
-
-if(APPLE)
-    if(EXISTS /usr/local/opt/openssl)
-        set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
-    elseif(EXISTS /opt/homebrew/opt/openssl)
-        set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl)
-    endif()
-endif()
-if(USE_OPENSSL)
-    find_package(OpenSSL)
-endif()
-if(OPENSSL_FOUND)
-    target_compile_definitions(simple-web-server INTERFACE HAVE_OPENSSL)
-    target_link_libraries(simple-web-server INTERFACE ${OPENSSL_LIBRARIES})
-    target_include_directories(simple-web-server INTERFACE ${OPENSSL_INCLUDE_DIR})
-endif()
-
-# If Simple-Web-Server is not a sub-project:
-if(CMAKE_SOURCE_DIR STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
-    if(NOT MSVC)
-        add_compile_options(-std=c++11 -Wall -Wextra)
-        if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
-            add_compile_options(-Wthread-safety)
-        endif()
-    else()
-        add_compile_options(/W1)
-    endif()
-
-    find_package(Boost 1.53.0 COMPONENTS system thread filesystem)
-    if(Boost_FOUND)
-        add_executable(http_examples http_examples.cpp)
-        target_link_libraries(http_examples simple-web-server)
-        target_link_libraries(http_examples ${Boost_LIBRARIES})
-        target_include_directories(http_examples PRIVATE ${Boost_INCLUDE_DIR})
-        if(OPENSSL_FOUND)
-            add_executable(https_examples https_examples.cpp)
-            target_link_libraries(https_examples simple-web-server)
-            target_link_libraries(https_examples ${Boost_LIBRARIES})
-            target_include_directories(https_examples PRIVATE ${Boost_INCLUDE_DIR})
-        endif()
-     endif()
-
-    install(FILES asio_compatibility.hpp server_http.hpp client_http.hpp server_https.hpp client_https.hpp crypto.hpp utility.hpp status_code.hpp mutex.hpp DESTINATION include/simple-web-server)
-endif()
-
-if(BUILD_TESTING OR BUILD_FUZZING)
-    if(BUILD_TESTING)
-        enable_testing()
-    endif()
-    add_subdirectory(tests)
-endif()
diff --git a/third_party/Simple-web-server/repo/LICENSE b/third_party/Simple-web-server/repo/LICENSE
deleted file mode 100644
index cecca180..00000000
--- a/third_party/Simple-web-server/repo/LICENSE
+++ /dev/null
@@ -1,21 +0,0 @@
-The MIT License (MIT)
-
-Copyright (c) 2014-2020 Ole Christian Eidheim
-
-Permission is hereby granted, free of charge, to any person obtaining a copy
-of this software and associated documentation files (the "Software"), to deal
-in the Software without restriction, including without limitation the rights
-to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-copies of the Software, and to permit persons to whom the Software is
-furnished to do so, subject to the following conditions:
-
-The above copyright notice and this permission notice shall be included in all
-copies or substantial portions of the Software.
-
-THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-SOFTWARE.
diff --git a/third_party/Simple-web-server/repo/README.md b/third_party/Simple-web-server/repo/README.md
deleted file mode 100644
index de81503b..00000000
--- a/third_party/Simple-web-server/repo/README.md
+++ /dev/null
@@ -1,90 +0,0 @@
-# Simple-Web-Server
-
-A very simple, fast, multithreaded, platform independent HTTP and HTTPS server and client library implemented using C++11 and Asio (both Boost.Asio and standalone Asio can be used). Created to be an easy way to make REST resources available from C++ applications. 
-
-See https://gitlab.com/eidheim/Simple-WebSocket-Server for an easy way to make WebSocket/WebSocket Secure endpoints in C++. Also, feel free to check out the new C++ IDE supporting C++11/14/17: https://gitlab.com/cppit/jucipp. 
-
-## Features
-
-* Asynchronous request handling
-* Thread pool if needed
-* Platform independent
-* HTTP/1.1 supported, including persistent connections
-* HTTPS supported
-* Chunked transfer encoding and server-sent events
-* Can set timeouts for request/response and content
-* Can set max request/response size
-* Sending outgoing messages is thread safe
-* Client creates necessary connections and perform reconnects when needed
-
-See also [benchmarks](https://gitlab.com/eidheim/Simple-Web-Server/blob/master/docs/benchmarks.md) for a performance comparisons to a few other HTTP libraries.
-
-## Usage
-
-See [http_examples.cpp](https://gitlab.com/eidheim/Simple-Web-Server/blob/master/http_examples.cpp) or
-[https_examples.cpp](https://gitlab.com/eidheim/Simple-Web-Server/blob/master/https_examples.cpp) for example usage.
-The following server resources are setup using regular expressions to match request paths:
-* `POST /string` - responds with the posted string.
-* `POST /json` - parses the request content as JSON, and responds with some of the parsed values.
-* `GET /info` - responds with information extracted from the request.
-* `GET /match/([0-9]+)` - matches for instance `/match/123` and responds with the matched number `123`.
-* `GET /work` - starts a thread, simulating heavy work, and responds when the work is done.
-* `GET` - a special default_resource handler is called when a request path does not match any of the above resources.
-This resource responds with the content of files in the `web/`-folder if the request path identifies one of these files.
-
-[Documentation](https://eidheim.gitlab.io/Simple-Web-Server/annotated.html) is also available, generated from the master branch.
-
-## Dependencies
-
-* Boost.Asio or standalone Asio
-* Boost is required to compile the examples
-* For HTTPS: OpenSSL libraries
-
-Installation instructions for the dependencies needed to compile the examples on a selection of platforms can be seen below.
-Default build with Boost.Asio is assumed. Turn on CMake option `USE_STANDALONE_ASIO` to instead use standalone Asio.
-
-### Debian based distributions
-
-```sh
-sudo apt-get install libssl-dev libboost-filesystem-dev libboost-thread-dev
-```
-
-### Arch Linux based distributions
-
-```sh
-sudo pacman -S boost
-```
-
-### MacOS
-
-```sh
-brew install openssl boost
-```
-
-## Compile and run
-
-Compile with a C++11 compliant compiler:
-```sh
-cmake -H. -Bbuild
-cmake --build build
-```
-
-### HTTP
-
-Run the server and client examples: `./build/http_examples`
-
-Direct your favorite browser to for instance http://localhost:8080/
-
-### HTTPS
-
-Before running the server, an RSA private key (server.key) and an SSL certificate (server.crt) must be created.
-
-Run the server and client examples: `./build/https_examples`
-
-Direct your favorite browser to for instance https://localhost:8080/
-
-## Contributing
-
-Contributions are welcome, either by creating an issue or a merge request.
-However, before you create a new issue or merge request, please search for previous similar issues or requests.
-A response will normally be given within a few days.
diff --git a/third_party/Simple-web-server/repo/asio_compatibility.hpp b/third_party/Simple-web-server/repo/asio_compatibility.hpp
deleted file mode 100644
index dc086531..00000000
--- a/third_party/Simple-web-server/repo/asio_compatibility.hpp
+++ /dev/null
@@ -1,112 +0,0 @@
-#ifndef SIMPLE_WEB_ASIO_COMPATIBILITY_HPP
-#define SIMPLE_WEB_ASIO_COMPATIBILITY_HPP
-
-#include <memory>
-
-#ifdef ASIO_STANDALONE
-#include <asio.hpp>
-#include <asio/steady_timer.hpp>
-namespace SimpleWeb {
-  namespace error = asio::error;
-  using error_code = std::error_code;
-  using errc = std::errc;
-  using system_error = std::system_error;
-  namespace make_error_code = std;
-} // namespace SimpleWeb
-#else
-#include <boost/asio.hpp>
-#include <boost/asio/steady_timer.hpp>
-namespace SimpleWeb {
-  namespace asio = boost::asio;
-  namespace error = asio::error;
-  using error_code = boost::system::error_code;
-  namespace errc = boost::system::errc;
-  using system_error = boost::system::system_error;
-  namespace make_error_code = boost::system::errc;
-} // namespace SimpleWeb
-#endif
-
-namespace SimpleWeb {
-#if(ASIO_STANDALONE && ASIO_VERSION >= 101300) || BOOST_ASIO_VERSION >= 101300
-  using io_context = asio::io_context;
-  using resolver_results = asio::ip::tcp::resolver::results_type;
-  using async_connect_endpoint = asio::ip::tcp::endpoint;
-
-#if(ASIO_STANDALONE && ASIO_VERSION >= 101800) || BOOST_ASIO_VERSION >= 101800
-  using strand = asio::strand<asio::any_io_executor>;
-#else
-  using strand = asio::strand<asio::executor>;
-#endif
-
-  template <typename handler_type>
-  inline void post(io_context &context, handler_type &&handler) {
-    asio::post(context, std::forward<handler_type>(handler));
-  }
-  inline void restart(io_context &context) noexcept {
-    context.restart();
-  }
-  inline asio::ip::address make_address(const std::string &str) noexcept {
-    return asio::ip::make_address(str);
-  }
-  template <typename socket_type, typename duration_type>
-  inline std::unique_ptr<asio::steady_timer> make_steady_timer(socket_type &socket, std::chrono::duration<duration_type> duration) {
-    return std::unique_ptr<asio::steady_timer>(new asio::steady_timer(socket.get_executor(), duration));
-  }
-  template <typename handler_type>
-  inline void async_resolve(asio::ip::tcp::resolver &resolver, const std::pair<std::string, std::string> &host_port, handler_type &&handler) {
-    resolver.async_resolve(host_port.first, host_port.second, std::forward<handler_type>(handler));
-  }
-  inline asio::executor_work_guard<io_context::executor_type> make_work_guard(io_context &context) {
-    return asio::make_work_guard(context);
-  }
-  template <typename socket_type>
-  inline asio::basic_socket<asio::ip::tcp>::executor_type get_executor(socket_type &socket) {
-    return socket.get_executor();
-  }
-  template <typename execution_context, typename handler_type>
-  inline asio::executor_binder<typename asio::decay<handler_type>::type, typename execution_context::executor_type> bind_executor(strand &strand, handler_type &&handler) {
-    return asio::bind_executor(strand, std::forward<handler_type>(handler));
-  }
-#else
-  using io_context = asio::io_service;
-  using resolver_results = asio::ip::tcp::resolver::iterator;
-  using async_connect_endpoint = asio::ip::tcp::resolver::iterator;
-  using strand = asio::io_service::strand;
-
-  template <typename handler_type>
-  inline void post(io_context &context, handler_type &&handler) {
-    context.post(std::forward<handler_type>(handler));
-  }
-  template <typename handler_type>
-  inline void post(strand &strand, handler_type &&handler) {
-    strand.post(std::forward<handler_type>(handler));
-  }
-  inline void restart(io_context &context) noexcept {
-    context.reset();
-  }
-  inline asio::ip::address make_address(const std::string &str) noexcept {
-    return asio::ip::address::from_string(str);
-  }
-  template <typename socket_type, typename duration_type>
-  inline std::unique_ptr<asio::steady_timer> make_steady_timer(socket_type &socket, std::chrono::duration<duration_type> duration) {
-    return std::unique_ptr<asio::steady_timer>(new asio::steady_timer(socket.get_io_service(), duration));
-  }
-  template <typename handler_type>
-  inline void async_resolve(asio::ip::tcp::resolver &resolver, const std::pair<std::string, std::string> &host_port, handler_type &&handler) {
-    resolver.async_resolve(asio::ip::tcp::resolver::query(host_port.first, host_port.second), std::forward<handler_type>(handler));
-  }
-  inline io_context::work make_work_guard(io_context &context) {
-    return io_context::work(context);
-  }
-  template <typename socket_type>
-  inline io_context &get_executor(socket_type &socket) {
-    return socket.get_io_service();
-  }
-  template <typename handler_type>
-  inline asio::detail::wrapped_handler<strand, handler_type, asio::detail::is_continuation_if_running> bind_executor(strand &strand, handler_type &&handler) {
-    return strand.wrap(std::forward<handler_type>(handler));
-  }
-#endif
-} // namespace SimpleWeb
-
-#endif /* SIMPLE_WEB_ASIO_COMPATIBILITY_HPP */
diff --git a/third_party/Simple-web-server/repo/client_http.hpp b/third_party/Simple-web-server/repo/client_http.hpp
deleted file mode 100644
index e12fcd22..00000000
--- a/third_party/Simple-web-server/repo/client_http.hpp
+++ /dev/null
@@ -1,879 +0,0 @@
-#ifndef SIMPLE_WEB_CLIENT_HTTP_HPP
-#define SIMPLE_WEB_CLIENT_HTTP_HPP
-
-#include "asio_compatibility.hpp"
-#include "mutex.hpp"
-#include "utility.hpp"
-#include <future>
-#include <limits>
-#include <random>
-#include <unordered_set>
-#include <vector>
-
-namespace SimpleWeb {
-  class HeaderEndMatch {
-    int crlfcrlf = 0;
-    int lflf = 0;
-
-  public:
-    /// Match condition for asio::read_until to match both standard and non-standard HTTP header endings.
-    std::pair<asio::buffers_iterator<asio::const_buffers_1>, bool> operator()(asio::buffers_iterator<asio::const_buffers_1> begin, asio::buffers_iterator<asio::const_buffers_1> end) {
-      auto it = begin;
-      for(; it != end; ++it) {
-        if(*it == '\n') {
-          if(crlfcrlf == 1)
-            ++crlfcrlf;
-          else if(crlfcrlf == 2)
-            crlfcrlf = 0;
-          else if(crlfcrlf == 3)
-            return {++it, true};
-          if(lflf == 0)
-            ++lflf;
-          else if(lflf == 1)
-            return {++it, true};
-        }
-        else if(*it == '\r') {
-          if(crlfcrlf == 0)
-            ++crlfcrlf;
-          else if(crlfcrlf == 2)
-            ++crlfcrlf;
-          else
-            crlfcrlf = 0;
-          lflf = 0;
-        }
-        else {
-          crlfcrlf = 0;
-          lflf = 0;
-        }
-      }
-      return {it, false};
-    }
-  };
-} // namespace SimpleWeb
-#ifndef ASIO_STANDALONE
-namespace boost {
-#endif
-  namespace asio {
-    template <>
-    struct is_match_condition<SimpleWeb::HeaderEndMatch> : public std::true_type {};
-  } // namespace asio
-#ifndef ASIO_STANDALONE
-} // namespace boost
-#endif
-
-namespace SimpleWeb {
-  template <class socket_type>
-  class Client;
-
-  template <class socket_type>
-  class ClientBase {
-  public:
-    class Content : public std::istream {
-      friend class ClientBase<socket_type>;
-
-    public:
-      std::size_t size() noexcept {
-        return streambuf.size();
-      }
-      /// Convenience function to return content as a string.
-      std::string string() noexcept {
-        return std::string(asio::buffers_begin(streambuf.data()), asio::buffers_end(streambuf.data()));
-      }
-
-      /// When true, this is the last response content part from server for the current request.
-      bool end = true;
-
-    private:
-      asio::streambuf &streambuf;
-      Content(asio::streambuf &streambuf) noexcept : std::istream(&streambuf), streambuf(streambuf) {}
-    };
-
-  protected:
-    class Connection;
-
-  public:
-    class Response {
-      friend class ClientBase<socket_type>;
-      friend class Client<socket_type>;
-
-      class Shared {
-      public:
-        std::string http_version, status_code;
-
-        CaseInsensitiveMultimap header;
-      };
-
-      asio::streambuf streambuf;
-
-      std::shared_ptr<Shared> shared;
-
-      std::weak_ptr<Connection> connection_weak;
-
-      Response(std::size_t max_response_streambuf_size, const std::shared_ptr<Connection> &connection_) noexcept
-          : streambuf(max_response_streambuf_size), shared(new Shared()), connection_weak(connection_), http_version(shared->http_version), status_code(shared->status_code), header(shared->header), content(streambuf) {}
-
-      /// Constructs a response object that has empty content, but otherwise is equal to the response parameter
-      Response(const Response &response) noexcept
-          : streambuf(response.streambuf.max_size()), shared(response.shared), connection_weak(response.connection_weak), http_version(shared->http_version), status_code(shared->status_code), header(shared->header), content(streambuf) {}
-
-    public:
-      std::string &http_version, &status_code;
-
-      CaseInsensitiveMultimap &header;
-
-      Content content;
-
-      /// Closes the connection to the server, preventing further response content parts from server.
-      void close() noexcept {
-        if(auto connection = this->connection_weak.lock())
-          connection->close();
-      }
-    };
-
-    class Config {
-      friend class ClientBase<socket_type>;
-
-    private:
-      Config() noexcept {}
-
-    public:
-      /// Set timeout on requests in seconds. Default value: 0 (no timeout).
-      long timeout = 0;
-      /// Set connect timeout in seconds. Default value: 0 (Config::timeout is then used instead).
-      long timeout_connect = 0;
-      /// Maximum size of response stream buffer. Defaults to architecture maximum.
-      /// Reaching this limit will result in a message_size error code.
-      std::size_t max_response_streambuf_size = (std::numeric_limits<std::size_t>::max)();
-      /// Set proxy server (server:port)
-      std::string proxy_server;
-    };
-
-  protected:
-    class Connection : public std::enable_shared_from_this<Connection> {
-    public:
-      template <typename... Args>
-      Connection(std::shared_ptr<ScopeRunner> handler_runner_, Args &&...args) noexcept
-          : handler_runner(std::move(handler_runner_)), socket(new socket_type(std::forward<Args>(args)...)) {}
-
-      std::shared_ptr<ScopeRunner> handler_runner;
-
-      std::unique_ptr<socket_type> socket; // Socket must be unique_ptr since asio::ssl::stream<asio::ip::tcp::socket> is not movable
-      bool in_use = false;
-      bool attempt_reconnect = true;
-
-      std::unique_ptr<asio::steady_timer> timer;
-
-      void close() noexcept {
-        error_code ec;
-        socket->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
-        socket->lowest_layer().cancel(ec);
-      }
-
-      void set_timeout(long seconds) noexcept {
-        if(seconds == 0) {
-          timer = nullptr;
-          return;
-        }
-        timer = make_steady_timer(*socket, std::chrono::seconds(seconds));
-        std::weak_ptr<Connection> self_weak(this->shared_from_this()); // To avoid keeping Connection instance alive longer than needed
-        timer->async_wait([self_weak](const error_code &ec) {
-          if(!ec) {
-            if(auto self = self_weak.lock())
-              self->close();
-          }
-        });
-      }
-
-      void cancel_timeout() noexcept {
-        if(timer) {
-          try {
-            timer->cancel();
-          }
-          catch(...) {
-          }
-        }
-      }
-    };
-
-    class Session {
-    public:
-      Session(std::size_t max_response_streambuf_size, std::shared_ptr<Connection> connection_, std::unique_ptr<asio::streambuf> request_streambuf_) noexcept
-          : connection(std::move(connection_)), request_streambuf(std::move(request_streambuf_)), response(new Response(max_response_streambuf_size, connection)) {}
-
-      std::shared_ptr<Connection> connection;
-      std::unique_ptr<asio::streambuf> request_streambuf;
-      std::shared_ptr<Response> response;
-      std::function<void(const error_code &)> callback;
-    };
-
-  public:
-    /// Set before calling a request function.
-    Config config;
-
-    /// If you want to reuse an already created asio::io_service, store its pointer here before calling a request function.
-    /// Do not set when using synchronous request functions.
-    std::shared_ptr<io_context> io_service;
-
-    /// Convenience function to perform synchronous request. The io_service is started in this function.
-    /// Should not be combined with asynchronous request functions.
-    /// If you reuse the io_service for other tasks, use the asynchronous request functions instead.
-    /// When requesting Server-Sent Events: will throw on error::eof, please use asynchronous request functions instead.
-    std::shared_ptr<Response> request(const std::string &method, const std::string &path = {"/"}, string_view content = {}, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
-      return sync_request(method, path, content, header);
-    }
-
-    /// Convenience function to perform synchronous request. The io_service is started in this function.
-    /// Should not be combined with asynchronous request functions.
-    /// If you reuse the io_service for other tasks, use the asynchronous request functions instead.
-    /// When requesting Server-Sent Events: will throw on error::eof, please use asynchronous request functions instead.
-    std::shared_ptr<Response> request(const std::string &method, const std::string &path, std::istream &content, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
-      return sync_request(method, path, content, header);
-    }
-
-    /// Asynchronous request where running Client's io_service is required.
-    /// Do not use concurrently with the synchronous request functions.
-    /// When requesting Server-Sent Events: request_callback might be called more than twice, first call with empty contents on open, and with ec = error::eof on last call
-    void request(const std::string &method, const std::string &path, string_view content, const CaseInsensitiveMultimap &header,
-                 std::function<void(std::shared_ptr<Response>, const error_code &)> &&request_callback_) {
-      auto session = std::make_shared<Session>(config.max_response_streambuf_size, get_connection(), create_request_header(method, path, header));
-      std::weak_ptr<Session> session_weak(session); // To avoid keeping session alive longer than needed
-      auto request_callback = std::make_shared<std::function<void(std::shared_ptr<Response>, const error_code &)>>(std::move(request_callback_));
-      session->callback = [this, session_weak, request_callback](const error_code &ec) {
-        if(auto session = session_weak.lock()) {
-          if(session->response->content.end) {
-            session->connection->cancel_timeout();
-            session->connection->in_use = false;
-          }
-          {
-            LockGuard lock(this->connections_mutex);
-
-            // Remove unused connections, but keep one open for HTTP persistent connection:
-            std::size_t unused_connections = 0;
-            for(auto it = this->connections.begin(); it != this->connections.end();) {
-              if(ec && session->connection == *it)
-                it = this->connections.erase(it);
-              else if((*it)->in_use)
-                ++it;
-              else {
-                ++unused_connections;
-                if(unused_connections > 1)
-                  it = this->connections.erase(it);
-                else
-                  ++it;
-              }
-            }
-          }
-
-          if(*request_callback)
-            (*request_callback)(session->response, ec);
-        }
-      };
-
-      std::ostream write_stream(session->request_streambuf.get());
-      if(content.size() > 0) {
-        auto header_it = header.find("Content-Length");
-        if(header_it == header.end()) {
-          header_it = header.find("Transfer-Encoding");
-          if(header_it == header.end() || header_it->second != "chunked")
-            write_stream << "Content-Length: " << content.size() << "\r\n";
-        }
-      }
-      write_stream << "\r\n";
-      write_stream.write(content.data(), static_cast<std::streamsize>(content.size()));
-
-      connect(session);
-    }
-
-    /// Asynchronous request where running Client's io_service is required.
-    /// Do not use concurrently with the synchronous request functions.
-    /// When requesting Server-Sent Events: request_callback might be called more than twice, first call with empty contents on open, and with ec = error::eof on last call
-    void request(const std::string &method, const std::string &path, string_view content,
-                 std::function<void(std::shared_ptr<Response>, const error_code &)> &&request_callback_) {
-      request(method, path, content, CaseInsensitiveMultimap(), std::move(request_callback_));
-    }
-
-    /// Asynchronous request where running Client's io_service is required.
-    /// Do not use concurrently with the synchronous request functions.
-    /// When requesting Server-Sent Events: request_callback might be called more than twice, first call with empty contents on open, and with ec = error::eof on last call
-    void request(const std::string &method, const std::string &path,
-                 std::function<void(std::shared_ptr<Response>, const error_code &)> &&request_callback_) {
-      request(method, path, std::string(), CaseInsensitiveMultimap(), std::move(request_callback_));
-    }
-
-    /// Asynchronous request where running Client's io_service is required.
-    /// Do not use concurrently with the synchronous request functions.
-    /// When requesting Server-Sent Events: request_callback might be called more than twice, first call with empty contents on open, and with ec = error::eof on last call
-    void request(const std::string &method, std::function<void(std::shared_ptr<Response>, const error_code &)> &&request_callback_) {
-      request(method, std::string("/"), std::string(), CaseInsensitiveMultimap(), std::move(request_callback_));
-    }
-
-    /// Asynchronous request where running Client's io_service is required.
-    /// Do not use concurrently with the synchronous request functions.
-    /// When requesting Server-Sent Events: request_callback might be called more than twice, first call with empty contents on open, and with ec = error::eof on last call
-    void request(const std::string &method, const std::string &path, std::istream &content, const CaseInsensitiveMultimap &header,
-                 std::function<void(std::shared_ptr<Response>, const error_code &)> &&request_callback_) {
-      auto session = std::make_shared<Session>(config.max_response_streambuf_size, get_connection(), create_request_header(method, path, header));
-      std::weak_ptr<Session> session_weak(session); // To avoid keeping session alive longer than needed
-      auto request_callback = std::make_shared<std::function<void(std::shared_ptr<Response>, const error_code &)>>(std::move(request_callback_));
-      session->callback = [this, session_weak, request_callback](const error_code &ec) {
-        if(auto session = session_weak.lock()) {
-          if(session->response->content.end) {
-            session->connection->cancel_timeout();
-            session->connection->in_use = false;
-          }
-          {
-            LockGuard lock(this->connections_mutex);
-
-            // Remove unused connections, but keep one open for HTTP persistent connection:
-            std::size_t unused_connections = 0;
-            for(auto it = this->connections.begin(); it != this->connections.end();) {
-              if(ec && session->connection == *it)
-                it = this->connections.erase(it);
-              else if((*it)->in_use)
-                ++it;
-              else {
-                ++unused_connections;
-                if(unused_connections > 1)
-                  it = this->connections.erase(it);
-                else
-                  ++it;
-              }
-            }
-          }
-
-          if(*request_callback)
-            (*request_callback)(session->response, ec);
-        }
-      };
-
-      content.seekg(0, std::ios::end);
-      auto content_length = content.tellg();
-      content.seekg(0, std::ios::beg);
-      std::ostream write_stream(session->request_streambuf.get());
-      if(content_length > 0) {
-        auto header_it = header.find("Content-Length");
-        if(header_it == header.end()) {
-          header_it = header.find("Transfer-Encoding");
-          if(header_it == header.end() || header_it->second != "chunked")
-            write_stream << "Content-Length: " << content_length << "\r\n";
-        }
-      }
-      write_stream << "\r\n";
-      if(content_length > 0)
-        write_stream << content.rdbuf();
-
-      connect(session);
-    }
-
-    /// Asynchronous request where running Client's io_service is required.
-    /// Do not use concurrently with the synchronous request functions.
-    /// When requesting Server-Sent Events: request_callback might be called more than twice, first call with empty contents on open, and with ec = error::eof on last call
-    void request(const std::string &method, const std::string &path, std::istream &content,
-                 std::function<void(std::shared_ptr<Response>, const error_code &)> &&request_callback_) {
-      request(method, path, content, CaseInsensitiveMultimap(), std::move(request_callback_));
-    }
-
-    /// Close connections.
-    void stop() noexcept {
-      LockGuard lock(connections_mutex);
-      for(auto it = connections.begin(); it != connections.end();) {
-        (*it)->close();
-        it = connections.erase(it);
-      }
-    }
-
-    virtual ~ClientBase() noexcept {
-      handler_runner->stop();
-      stop();
-      if(internal_io_service)
-        io_service->stop();
-    }
-
-  protected:
-    bool internal_io_service = false;
-
-    std::string host;
-    unsigned short port;
-    unsigned short default_port;
-
-    std::unique_ptr<std::pair<std::string, std::string>> host_port;
-
-    Mutex connections_mutex;
-    std::unordered_set<std::shared_ptr<Connection>> connections GUARDED_BY(connections_mutex);
-
-    std::shared_ptr<ScopeRunner> handler_runner;
-
-    Mutex synchronous_request_mutex;
-    bool synchronous_request_called GUARDED_BY(synchronous_request_mutex) = false;
-
-    ClientBase(const std::string &host_port, unsigned short default_port) noexcept : default_port(default_port), handler_runner(new ScopeRunner()) {
-      auto parsed_host_port = parse_host_port(host_port, default_port);
-      host = parsed_host_port.first;
-      port = parsed_host_port.second;
-    }
-
-    template <typename ContentType>
-    std::shared_ptr<Response> sync_request(const std::string &method, const std::string &path, ContentType &content, const CaseInsensitiveMultimap &header) {
-      {
-        LockGuard lock(synchronous_request_mutex);
-        if(!synchronous_request_called) {
-          if(io_service) // Throw if io_service already set
-            throw make_error_code::make_error_code(errc::operation_not_permitted);
-          io_service = std::make_shared<io_context>();
-          internal_io_service = true;
-          auto io_service_ = io_service;
-          std::thread thread([io_service_] {
-            auto work = make_work_guard(*io_service_);
-            io_service_->run();
-          });
-          thread.detach();
-          synchronous_request_called = true;
-        }
-      }
-
-      std::shared_ptr<Response> response;
-      std::promise<std::shared_ptr<Response>> response_promise;
-      auto stop_future_handlers = std::make_shared<bool>(false);
-      request(method, path, content, header, [&response, &response_promise, stop_future_handlers](std::shared_ptr<Response> response_, error_code ec) {
-        if(*stop_future_handlers)
-          return;
-
-        if(!response)
-          response = response_;
-        else if(!ec) {
-          if(response_->streambuf.size() + response->streambuf.size() > response->streambuf.max_size()) {
-            ec = make_error_code::make_error_code(errc::message_size);
-            response->close();
-          }
-          else {
-            // Move partial response_ content to response:
-            auto &source = response_->streambuf;
-            auto &target = response->streambuf;
-            target.commit(asio::buffer_copy(target.prepare(source.size()), source.data()));
-            source.consume(source.size());
-          }
-        }
-
-        if(ec) {
-          response_promise.set_exception(std::make_exception_ptr(system_error(ec)));
-          *stop_future_handlers = true;
-        }
-        else if(response_->content.end)
-          response_promise.set_value(response);
-      });
-
-      return response_promise.get_future().get();
-    }
-
-    std::shared_ptr<Connection> get_connection() noexcept {
-      std::shared_ptr<Connection> connection;
-      LockGuard lock(connections_mutex);
-
-      if(!io_service) {
-        io_service = std::make_shared<io_context>();
-        internal_io_service = true;
-      }
-
-      for(auto it = connections.begin(); it != connections.end(); ++it) {
-        if(!(*it)->in_use) {
-          connection = *it;
-          break;
-        }
-      }
-      if(!connection) {
-        connection = create_connection();
-        connections.emplace(connection);
-      }
-      connection->attempt_reconnect = true;
-      connection->in_use = true;
-
-      if(!host_port) {
-        if(config.proxy_server.empty())
-          host_port = std::unique_ptr<std::pair<std::string, std::string>>(new std::pair<std::string, std::string>(host, std::to_string(port)));
-        else {
-          auto proxy_host_port = parse_host_port(config.proxy_server, 8080);
-          host_port = std::unique_ptr<std::pair<std::string, std::string>>(new std::pair<std::string, std::string>(proxy_host_port.first, std::to_string(proxy_host_port.second)));
-        }
-      }
-
-      return connection;
-    }
-
-    std::pair<std::string, unsigned short> parse_host_port(const std::string &host_port, unsigned short default_port) const noexcept {
-      std::string host, port;
-      host.reserve(host_port.size());
-      bool parse_port = false;
-      int square_count = 0; // To parse IPv6 addresses
-      for(auto chr : host_port) {
-        if(chr == '[')
-          ++square_count;
-        else if(chr == ']')
-          --square_count;
-        else if(square_count == 0 && chr == ':')
-          parse_port = true;
-        else if(!parse_port)
-          host += chr;
-        else
-          port += chr;
-      }
-
-      if(port.empty())
-        return {std::move(host), default_port};
-      else {
-        try {
-          return {std::move(host), static_cast<unsigned short>(std::stoul(port))};
-        }
-        catch(...) {
-          return {std::move(host), default_port};
-        }
-      }
-    }
-
-    virtual std::shared_ptr<Connection> create_connection() noexcept = 0;
-    virtual void connect(const std::shared_ptr<Session> &) = 0;
-
-    std::unique_ptr<asio::streambuf> create_request_header(const std::string &method, const std::string &path, const CaseInsensitiveMultimap &header) const {
-      auto corrected_path = path;
-      if(corrected_path == "")
-        corrected_path = "/";
-      if(!config.proxy_server.empty() && std::is_same<socket_type, asio::ip::tcp::socket>::value)
-        corrected_path = "http://" + host + ':' + std::to_string(port) + corrected_path;
-
-      std::unique_ptr<asio::streambuf> streambuf(new asio::streambuf());
-      std::ostream write_stream(streambuf.get());
-      write_stream << method << " " << corrected_path << " HTTP/1.1\r\n";
-      write_stream << "Host: " << host;
-      if(port != default_port)
-        write_stream << ':' << std::to_string(port);
-      write_stream << "\r\n";
-      for(auto &h : header)
-        write_stream << h.first << ": " << h.second << "\r\n";
-      return streambuf;
-    }
-
-    void write(const std::shared_ptr<Session> &session) {
-      session->connection->set_timeout(config.timeout);
-      asio::async_write(*session->connection->socket, session->request_streambuf->data(), [this, session](const error_code &ec, std::size_t /*bytes_transferred*/) {
-        auto lock = session->connection->handler_runner->continue_lock();
-        if(!lock)
-          return;
-        if(!ec)
-          this->read(session);
-        else {
-          if(session->connection->attempt_reconnect && ec != error::operation_aborted)
-            reconnect(session, ec);
-          else
-            session->callback(ec);
-        }
-      });
-    }
-
-    void read(const std::shared_ptr<Session> &session) {
-      asio::async_read_until(*session->connection->socket, session->response->streambuf, HeaderEndMatch(), [this, session](const error_code &ec, std::size_t bytes_transferred) {
-        auto lock = session->connection->handler_runner->continue_lock();
-        if(!lock)
-          return;
-
-        if(!ec) {
-          session->connection->attempt_reconnect = true;
-          std::size_t num_additional_bytes = session->response->streambuf.size() - bytes_transferred;
-
-          if(!ResponseMessage::parse(session->response->content, session->response->http_version, session->response->status_code, session->response->header)) {
-            session->callback(make_error_code::make_error_code(errc::protocol_error));
-            return;
-          }
-
-          auto header_it = session->response->header.find("Content-Length");
-          if(header_it != session->response->header.end()) {
-            auto content_length = std::stoull(header_it->second);
-            if(content_length > num_additional_bytes)
-              this->read_content(session, content_length - num_additional_bytes);
-            else
-              session->callback(ec);
-          }
-          else if((header_it = session->response->header.find("Transfer-Encoding")) != session->response->header.end() && header_it->second == "chunked") {
-            // Expect hex number to not exceed 16 bytes (64-bit number), but take into account previous additional read bytes
-            auto chunk_size_streambuf = std::make_shared<asio::streambuf>(std::max<std::size_t>(16 + 2, session->response->streambuf.size()));
-
-            // Move leftover bytes
-            auto &source = session->response->streambuf;
-            auto &target = *chunk_size_streambuf;
-            target.commit(asio::buffer_copy(target.prepare(source.size()), source.data()));
-            source.consume(source.size());
-
-            this->read_chunked_transfer_encoded(session, chunk_size_streambuf);
-          }
-          else if(session->response->http_version < "1.1" || ((header_it = session->response->header.find("Connection")) != session->response->header.end() && header_it->second == "close"))
-            read_content(session);
-          else if(((header_it = session->response->header.find("Content-Type")) != session->response->header.end() && header_it->second == "text/event-stream")) {
-            auto events_streambuf = std::make_shared<asio::streambuf>(this->config.max_response_streambuf_size);
-
-            // Move leftover bytes
-            auto &source = session->response->streambuf;
-            auto &target = *events_streambuf;
-            target.commit(asio::buffer_copy(target.prepare(source.size()), source.data()));
-            source.consume(source.size());
-
-            session->callback(ec); // Connection to a Server-Sent Events resource is opened
-
-            this->read_server_sent_event(session, events_streambuf);
-          }
-          else
-            session->callback(ec);
-        }
-        else {
-          if(session->connection->attempt_reconnect && ec != error::operation_aborted)
-            reconnect(session, ec);
-          else
-            session->callback(ec);
-        }
-      });
-    }
-
-    void reconnect(const std::shared_ptr<Session> &session, const error_code &ec) {
-      LockGuard lock(connections_mutex);
-      auto it = connections.find(session->connection);
-      if(it != connections.end()) {
-        connections.erase(it);
-        session->connection = create_connection();
-        session->connection->attempt_reconnect = false;
-        session->connection->in_use = true;
-        session->response = std::shared_ptr<Response>(new Response(this->config.max_response_streambuf_size, session->connection));
-        connections.emplace(session->connection);
-        lock.unlock();
-        this->connect(session);
-      }
-      else {
-        lock.unlock();
-        session->callback(ec);
-      }
-    }
-
-    void read_content(const std::shared_ptr<Session> &session, std::size_t remaining_length) {
-      asio::async_read(*session->connection->socket, session->response->streambuf, asio::transfer_exactly(remaining_length), [this, session, remaining_length](const error_code &ec, std::size_t bytes_transferred) {
-        auto lock = session->connection->handler_runner->continue_lock();
-        if(!lock)
-          return;
-
-        if(!ec) {
-          if(session->response->streambuf.size() == session->response->streambuf.max_size() && remaining_length > bytes_transferred) {
-            session->response->content.end = false;
-            session->callback(ec);
-            session->response = std::shared_ptr<Response>(new Response(*session->response));
-            this->read_content(session, remaining_length - bytes_transferred);
-          }
-          else
-            session->callback(ec);
-        }
-        else
-          session->callback(ec);
-      });
-    }
-
-    /// Ignore end of file error codes
-    virtual error_code clean_error_code(const error_code &ec) {
-      return ec == error::eof ? error_code() : ec;
-    }
-
-    void read_content(const std::shared_ptr<Session> &session) {
-      asio::async_read(*session->connection->socket, session->response->streambuf, [this, session](const error_code &ec_, std::size_t /*bytes_transferred*/) {
-        auto lock = session->connection->handler_runner->continue_lock();
-        if(!lock)
-          return;
-
-        auto ec = clean_error_code(ec_);
-
-        if(!ec) {
-          {
-            LockGuard lock(this->connections_mutex);
-            this->connections.erase(session->connection);
-          }
-          if(session->response->streambuf.size() == session->response->streambuf.max_size()) {
-            session->response->content.end = false;
-            session->callback(ec);
-            session->response = std::shared_ptr<Response>(new Response(*session->response));
-            this->read_content(session);
-          }
-          else
-            session->callback(ec);
-        }
-        else
-          session->callback(ec);
-      });
-    }
-
-    void read_chunked_transfer_encoded(const std::shared_ptr<Session> &session, const std::shared_ptr<asio::streambuf> &chunk_size_streambuf) {
-      asio::async_read_until(*session->connection->socket, *chunk_size_streambuf, "\r\n", [this, session, chunk_size_streambuf](const error_code &ec, size_t bytes_transferred) {
-        auto lock = session->connection->handler_runner->continue_lock();
-        if(!lock)
-          return;
-
-        if(!ec) {
-          std::istream istream(chunk_size_streambuf.get());
-          std::string line;
-          std::getline(istream, line);
-          bytes_transferred -= line.size() + 1;
-          unsigned long chunk_size = 0;
-          try {
-            chunk_size = std::stoul(line, 0, 16);
-          }
-          catch(...) {
-            session->callback(make_error_code::make_error_code(errc::protocol_error));
-            return;
-          }
-
-          if(chunk_size == 0) {
-            session->callback(error_code());
-            return;
-          }
-
-          if(chunk_size + session->response->streambuf.size() > session->response->streambuf.max_size()) {
-            session->response->content.end = false;
-            session->callback(ec);
-            session->response = std::shared_ptr<Response>(new Response(*session->response));
-          }
-
-          auto num_additional_bytes = chunk_size_streambuf->size() - bytes_transferred;
-
-          auto bytes_to_move = std::min<std::size_t>(chunk_size, num_additional_bytes);
-          if(bytes_to_move > 0) {
-            auto &source = *chunk_size_streambuf;
-            auto &target = session->response->streambuf;
-            target.commit(asio::buffer_copy(target.prepare(bytes_to_move), source.data(), bytes_to_move));
-            source.consume(bytes_to_move);
-          }
-
-          if(chunk_size > num_additional_bytes) {
-            asio::async_read(*session->connection->socket, session->response->streambuf, asio::transfer_exactly(chunk_size - num_additional_bytes), [this, session, chunk_size_streambuf](const error_code &ec, size_t /*bytes_transferred*/) {
-              auto lock = session->connection->handler_runner->continue_lock();
-              if(!lock)
-                return;
-
-              if(!ec) {
-                // Remove "\r\n"
-                auto null_buffer = std::make_shared<asio::streambuf>(2);
-                asio::async_read(*session->connection->socket, *null_buffer, asio::transfer_exactly(2), [this, session, chunk_size_streambuf, null_buffer](const error_code &ec, size_t /*bytes_transferred*/) {
-                  auto lock = session->connection->handler_runner->continue_lock();
-                  if(!lock)
-                    return;
-                  if(!ec)
-                    read_chunked_transfer_encoded(session, chunk_size_streambuf);
-                  else
-                    session->callback(ec);
-                });
-              }
-              else
-                session->callback(ec);
-            });
-          }
-          else if(2 + chunk_size > num_additional_bytes) { // If only end of chunk remains unread (\n or \r\n)
-            // Remove "\r\n"
-            if(2 + chunk_size - num_additional_bytes == 1)
-              istream.get();
-            auto null_buffer = std::make_shared<asio::streambuf>(2);
-            asio::async_read(*session->connection->socket, *null_buffer, asio::transfer_exactly(2 + chunk_size - num_additional_bytes), [this, session, chunk_size_streambuf, null_buffer](const error_code &ec, size_t /*bytes_transferred*/) {
-              auto lock = session->connection->handler_runner->continue_lock();
-              if(!lock)
-                return;
-              if(!ec)
-                read_chunked_transfer_encoded(session, chunk_size_streambuf);
-              else
-                session->callback(ec);
-            });
-          }
-          else {
-            // Remove "\r\n"
-            istream.get();
-            istream.get();
-
-            read_chunked_transfer_encoded(session, chunk_size_streambuf);
-          }
-        }
-        else
-          session->callback(ec);
-      });
-    }
-
-    void read_server_sent_event(const std::shared_ptr<Session> &session, const std::shared_ptr<asio::streambuf> &events_streambuf) {
-      asio::async_read_until(*session->connection->socket, *events_streambuf, HeaderEndMatch(), [this, session, events_streambuf](const error_code &ec, std::size_t /*bytes_transferred*/) {
-        auto lock = session->connection->handler_runner->continue_lock();
-        if(!lock)
-          return;
-
-        if(!ec) {
-          session->response->content.end = false;
-          std::istream istream(events_streambuf.get());
-          std::ostream ostream(&session->response->streambuf);
-          std::string line;
-          while(std::getline(istream, line) && !line.empty() && !(line.back() == '\r' && line.size() == 1)) {
-            ostream.write(line.data(), static_cast<std::streamsize>(line.size() - (line.back() == '\r' ? 1 : 0)));
-            ostream.put('\n');
-          }
-
-          session->callback(ec);
-          session->response = std::shared_ptr<Response>(new Response(*session->response));
-          read_server_sent_event(session, events_streambuf);
-        }
-        else
-          session->callback(ec);
-      });
-    }
-  };
-
-  template <class socket_type>
-  class Client : public ClientBase<socket_type> {};
-
-  using HTTP = asio::ip::tcp::socket;
-
-  template <>
-  class Client<HTTP> : public ClientBase<HTTP> {
-  public:
-    /**
-     * Constructs a client object.
-     *
-     * @param server_port_path Server resource given by host[:port][/path]
-     */
-    Client(const std::string &server_port_path) noexcept : ClientBase<HTTP>::ClientBase(server_port_path, 80) {}
-
-  protected:
-    std::shared_ptr<Connection> create_connection() noexcept override {
-      return std::make_shared<Connection>(handler_runner, *io_service);
-    }
-
-    void connect(const std::shared_ptr<Session> &session) override {
-      if(!session->connection->socket->lowest_layer().is_open()) {
-        auto resolver = std::make_shared<asio::ip::tcp::resolver>(*io_service);
-        session->connection->set_timeout(config.timeout_connect);
-        async_resolve(*resolver, *host_port, [this, session, resolver](const error_code &ec, resolver_results results) {
-          session->connection->cancel_timeout();
-          auto lock = session->connection->handler_runner->continue_lock();
-          if(!lock)
-            return;
-          if(!ec) {
-            session->connection->set_timeout(config.timeout_connect);
-            asio::async_connect(*session->connection->socket, results, [this, session, resolver](const error_code &ec, async_connect_endpoint /*endpoint*/) {
-              session->connection->cancel_timeout();
-              auto lock = session->connection->handler_runner->continue_lock();
-              if(!lock)
-                return;
-              if(!ec) {
-                asio::ip::tcp::no_delay option(true);
-                error_code ec;
-                session->connection->socket->set_option(option, ec);
-                this->write(session);
-              }
-              else
-                session->callback(ec);
-            });
-          }
-          else
-            session->callback(ec);
-        });
-      }
-      else
-        write(session);
-    }
-  };
-} // namespace SimpleWeb
-
-#endif /* SIMPLE_WEB_CLIENT_HTTP_HPP */
diff --git a/third_party/Simple-web-server/repo/client_https.hpp b/third_party/Simple-web-server/repo/client_https.hpp
deleted file mode 100644
index 94587236..00000000
--- a/third_party/Simple-web-server/repo/client_https.hpp
+++ /dev/null
@@ -1,166 +0,0 @@
-#ifndef SIMPLE_WEB_CLIENT_HTTPS_HPP
-#define SIMPLE_WEB_CLIENT_HTTPS_HPP
-
-#include "client_http.hpp"
-
-#ifdef ASIO_STANDALONE
-#include <asio/ssl.hpp>
-#else
-#include <boost/asio/ssl.hpp>
-#endif
-
-namespace SimpleWeb {
-  using HTTPS = asio::ssl::stream<asio::ip::tcp::socket>;
-
-  template <>
-  class Client<HTTPS> : public ClientBase<HTTPS> {
-  public:
-    /**
-     * Constructs a client object.
-     *
-     * @param server_port_path   Server resource given by host[:port][/path]
-     * @param verify_certificate Set to true (default) to verify the server's certificate and hostname according to RFC 2818.
-     * @param certification_file If non-empty, sends the given certification file to server. Requires private_key_file.
-     * @param private_key_file   If non-empty, specifies the file containing the private key for certification_file. Requires certification_file.
-     * @param verify_file        If non-empty, use this certificate authority file to perform verification.
-     */
-    Client(const std::string &server_port_path, bool verify_certificate = true, const std::string &certification_file = std::string(),
-           const std::string &private_key_file = std::string(), const std::string &verify_file = std::string())
-        : ClientBase<HTTPS>::ClientBase(server_port_path, 443),
-#if(ASIO_STANDALONE && ASIO_VERSION >= 101300) || BOOST_ASIO_VERSION >= 101300
-          context(asio::ssl::context::tls_client) {
-      // Disabling TLS 1.0 and 1.1 (see RFC 8996)
-      context.set_options(asio::ssl::context::no_tlsv1);
-      context.set_options(asio::ssl::context::no_tlsv1_1);
-#else
-          context(asio::ssl::context::tlsv12) {
-#endif
-      if(certification_file.size() > 0 && private_key_file.size() > 0) {
-        context.use_certificate_chain_file(certification_file);
-        context.use_private_key_file(private_key_file, asio::ssl::context::pem);
-      }
-
-      if(verify_certificate)
-        context.set_verify_callback(asio::ssl::rfc2818_verification(host));
-
-      if(verify_file.size() > 0)
-        context.load_verify_file(verify_file);
-      else
-        context.set_default_verify_paths();
-
-      if(verify_certificate)
-        context.set_verify_mode(asio::ssl::verify_peer);
-      else
-        context.set_verify_mode(asio::ssl::verify_none);
-    }
-
-  protected:
-    asio::ssl::context context;
-
-    /// Ignore for end of file and SSL_R_SHORT_READ error codes
-    error_code clean_error_code(const error_code &ec) override {
-      return ec == error::eof || ec == asio::ssl::error::stream_truncated ? error_code() : ec;
-    }
-
-    std::shared_ptr<Connection> create_connection() noexcept override {
-      return std::make_shared<Connection>(handler_runner, *io_service, context);
-    }
-
-    void connect(const std::shared_ptr<Session> &session) override {
-      if(!session->connection->socket->lowest_layer().is_open()) {
-        auto resolver = std::make_shared<asio::ip::tcp::resolver>(*io_service);
-        session->connection->set_timeout(this->config.timeout_connect);
-        async_resolve(*resolver, *host_port, [this, session, resolver](const error_code &ec, resolver_results results) {
-          session->connection->cancel_timeout();
-          auto lock = session->connection->handler_runner->continue_lock();
-          if(!lock)
-            return;
-          if(!ec) {
-            session->connection->set_timeout(this->config.timeout_connect);
-            asio::async_connect(session->connection->socket->lowest_layer(), results, [this, session, resolver](const error_code &ec, async_connect_endpoint /*endpoint*/) {
-              session->connection->cancel_timeout();
-              auto lock = session->connection->handler_runner->continue_lock();
-              if(!lock)
-                return;
-              if(!ec) {
-                asio::ip::tcp::no_delay option(true);
-                error_code ec;
-                session->connection->socket->lowest_layer().set_option(option, ec);
-
-                if(!this->config.proxy_server.empty()) {
-                  auto write_buffer = std::make_shared<asio::streambuf>();
-                  std::ostream write_stream(write_buffer.get());
-                  auto host_port = this->host + ':' + std::to_string(this->port);
-                  write_stream << "CONNECT " + host_port + " HTTP/1.1\r\n"
-                               << "Host: " << host_port << "\r\n\r\n";
-                  session->connection->set_timeout(this->config.timeout_connect);
-                  asio::async_write(session->connection->socket->next_layer(), *write_buffer, [this, session, write_buffer](const error_code &ec, std::size_t /*bytes_transferred*/) {
-                    session->connection->cancel_timeout();
-                    auto lock = session->connection->handler_runner->continue_lock();
-                    if(!lock)
-                      return;
-                    if(!ec) {
-                      std::shared_ptr<Response> response(new Response(this->config.max_response_streambuf_size, session->connection));
-                      session->connection->set_timeout(this->config.timeout_connect);
-                      asio::async_read_until(session->connection->socket->next_layer(), response->streambuf, "\r\n\r\n", [this, session, response](const error_code &ec, std::size_t /*bytes_transferred*/) {
-                        session->connection->cancel_timeout();
-                        auto lock = session->connection->handler_runner->continue_lock();
-                        if(!lock)
-                          return;
-                        if(response->streambuf.size() == response->streambuf.max_size()) {
-                          session->callback(make_error_code::make_error_code(errc::message_size));
-                          return;
-                        }
-
-                        if(!ec) {
-                          if(!ResponseMessage::parse(response->content, response->http_version, response->status_code, response->header))
-                            session->callback(make_error_code::make_error_code(errc::protocol_error));
-                          else {
-                            if(response->status_code.compare(0, 3, "200") != 0)
-                              session->callback(make_error_code::make_error_code(errc::permission_denied));
-                            else
-                              this->handshake(session);
-                          }
-                        }
-                        else
-                          session->callback(ec);
-                      });
-                    }
-                    else
-                      session->callback(ec);
-                  });
-                }
-                else
-                  this->handshake(session);
-              }
-              else
-                session->callback(ec);
-            });
-          }
-          else
-            session->callback(ec);
-        });
-      }
-      else
-        write(session);
-    }
-
-    void handshake(const std::shared_ptr<Session> &session) {
-      SSL_set_tlsext_host_name(session->connection->socket->native_handle(), this->host.c_str());
-
-      session->connection->set_timeout(this->config.timeout_connect);
-      session->connection->socket->async_handshake(asio::ssl::stream_base::client, [this, session](const error_code &ec) {
-        session->connection->cancel_timeout();
-        auto lock = session->connection->handler_runner->continue_lock();
-        if(!lock)
-          return;
-        if(!ec)
-          this->write(session);
-        else
-          session->callback(ec);
-      });
-    }
-  };
-} // namespace SimpleWeb
-
-#endif /* SIMPLE_WEB_CLIENT_HTTPS_HPP */
diff --git a/third_party/Simple-web-server/repo/crypto.hpp b/third_party/Simple-web-server/repo/crypto.hpp
deleted file mode 100644
index 36295989..00000000
--- a/third_party/Simple-web-server/repo/crypto.hpp
+++ /dev/null
@@ -1,223 +0,0 @@
-#ifndef SIMPLE_WEB_CRYPTO_HPP
-#define SIMPLE_WEB_CRYPTO_HPP
-
-#include <cmath>
-#include <iomanip>
-#include <istream>
-#include <memory>
-#include <sstream>
-#include <string>
-#include <vector>
-
-#include <openssl/buffer.h>
-#include <openssl/evp.h>
-#include <openssl/md5.h>
-#include <openssl/sha.h>
-
-namespace SimpleWeb {
-// TODO 2017: remove workaround for MSVS 2012
-#if _MSC_VER == 1700                       // MSVS 2012 has no definition for round()
-  inline double round(double x) noexcept { // Custom definition of round() for positive numbers
-    return floor(x + 0.5);
-  }
-#endif
-
-  class Crypto {
-    const static std::size_t buffer_size = 131072;
-
-  public:
-    class Base64 {
-    public:
-      /// Returns Base64 encoded string from input string.
-      static std::string encode(const std::string &input) noexcept {
-        std::string base64;
-
-        BIO *bio, *b64;
-        auto bptr = BUF_MEM_new();
-
-        b64 = BIO_new(BIO_f_base64());
-        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
-        bio = BIO_new(BIO_s_mem());
-        BIO_push(b64, bio);
-        BIO_set_mem_buf(b64, bptr, BIO_CLOSE);
-
-        // Write directly to base64-buffer to avoid copy
-        auto base64_length = static_cast<std::size_t>(round(4 * ceil(static_cast<double>(input.size()) / 3.0)));
-        base64.resize(base64_length);
-        bptr->length = 0;
-        bptr->max = base64_length + 1;
-        bptr->data = &base64[0];
-
-        if(BIO_write(b64, &input[0], static_cast<int>(input.size())) <= 0 || BIO_flush(b64) <= 0)
-          base64.clear();
-
-        // To keep &base64[0] through BIO_free_all(b64)
-        bptr->length = 0;
-        bptr->max = 0;
-        bptr->data = nullptr;
-
-        BIO_free_all(b64);
-
-        return base64;
-      }
-
-      /// Returns Base64 decoded string from base64 input.
-      static std::string decode(const std::string &base64) noexcept {
-        std::string ascii((6 * base64.size()) / 8, '\0'); // The size is a up to two bytes too large.
-
-        BIO *b64, *bio;
-
-        b64 = BIO_new(BIO_f_base64());
-        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
-// TODO: Remove in 2022 or later
-#if(defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER < 0x1000214fL) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2080000fL)
-        bio = BIO_new_mem_buf(const_cast<char *>(&base64[0]), static_cast<int>(base64.size()));
-#else
-        bio = BIO_new_mem_buf(&base64[0], static_cast<int>(base64.size()));
-#endif
-        bio = BIO_push(b64, bio);
-
-        auto decoded_length = BIO_read(bio, &ascii[0], static_cast<int>(ascii.size()));
-        if(decoded_length > 0)
-          ascii.resize(static_cast<std::size_t>(decoded_length));
-        else
-          ascii.clear();
-
-        BIO_free_all(b64);
-
-        return ascii;
-      }
-    };
-
-    /// Returns hex string from bytes in input string.
-    static std::string to_hex_string(const std::string &input) noexcept {
-      std::stringstream hex_stream;
-      hex_stream << std::hex << std::internal << std::setfill('0');
-      for(auto &byte : input)
-        hex_stream << std::setw(2) << static_cast<int>(static_cast<unsigned char>(byte));
-      return hex_stream.str();
-    }
-
-    /// Return hash value using specific EVP_MD from input string.
-    static std::string message_digest(const std::string &str, const EVP_MD *evp_md, std::size_t digest_length) noexcept {
-      std::string md(digest_length, '\0');
-
-      auto ctx = EVP_MD_CTX_create();
-      EVP_MD_CTX_init(ctx);
-      EVP_DigestInit_ex(ctx, evp_md, nullptr);
-      EVP_DigestUpdate(ctx, str.data(), str.size());
-      EVP_DigestFinal_ex(ctx, reinterpret_cast<unsigned char *>(&md[0]), nullptr);
-      EVP_MD_CTX_destroy(ctx);
-
-      return md;
-    }
-
-    /// Return hash value using specific EVP_MD from input stream.
-    static std::string stream_digest(std::istream &stream, const EVP_MD *evp_md, std::size_t digest_length) noexcept {
-      std::string md(digest_length, '\0');
-      std::unique_ptr<char[]> buffer(new char[buffer_size]);
-      std::streamsize read_length;
-
-      auto ctx = EVP_MD_CTX_create();
-      EVP_MD_CTX_init(ctx);
-      EVP_DigestInit_ex(ctx, evp_md, nullptr);
-      while((read_length = stream.read(buffer.get(), buffer_size).gcount()) > 0)
-        EVP_DigestUpdate(ctx, buffer.get(), static_cast<std::size_t>(read_length));
-      EVP_DigestFinal_ex(ctx, reinterpret_cast<unsigned char *>(&md[0]), nullptr);
-      EVP_MD_CTX_destroy(ctx);
-
-      return md;
-    }
-
-    /// Returns md5 hash value from input string.
-    static std::string md5(const std::string &input, std::size_t iterations = 1) noexcept {
-      auto evp_md = EVP_md5();
-      auto hash = message_digest(input, evp_md, MD5_DIGEST_LENGTH);
-      for(std::size_t i = 1; i < iterations; ++i)
-        hash = message_digest(hash, evp_md, MD5_DIGEST_LENGTH);
-      return hash;
-    }
-
-    /// Returns md5 hash value from input stream.
-    static std::string md5(std::istream &stream, std::size_t iterations = 1) noexcept {
-      auto evp_md = EVP_md5();
-      auto hash = stream_digest(stream, evp_md, MD5_DIGEST_LENGTH);
-      for(std::size_t i = 1; i < iterations; ++i)
-        hash = message_digest(hash, evp_md, MD5_DIGEST_LENGTH);
-      return hash;
-    }
-
-    /// Returns sha1 hash value from input string.
-    static std::string sha1(const std::string &input, std::size_t iterations = 1) noexcept {
-      auto evp_md = EVP_sha1();
-      auto hash = message_digest(input, evp_md, SHA_DIGEST_LENGTH);
-      for(std::size_t i = 1; i < iterations; ++i)
-        hash = message_digest(hash, evp_md, SHA_DIGEST_LENGTH);
-      return hash;
-    }
-
-    /// Returns sha1 hash value from input stream.
-    static std::string sha1(std::istream &stream, std::size_t iterations = 1) noexcept {
-      auto evp_md = EVP_sha1();
-      auto hash = stream_digest(stream, evp_md, SHA_DIGEST_LENGTH);
-      for(std::size_t i = 1; i < iterations; ++i)
-        hash = message_digest(hash, evp_md, SHA_DIGEST_LENGTH);
-      return hash;
-    }
-
-    /// Returns sha256 hash value from input string.
-    static std::string sha256(const std::string &input, std::size_t iterations = 1) noexcept {
-      auto evp_md = EVP_sha256();
-      auto hash = message_digest(input, evp_md, SHA256_DIGEST_LENGTH);
-      for(std::size_t i = 1; i < iterations; ++i)
-        hash = message_digest(hash, evp_md, SHA256_DIGEST_LENGTH);
-      return hash;
-    }
-
-    /// Returns sha256 hash value from input stream.
-    static std::string sha256(std::istream &stream, std::size_t iterations = 1) noexcept {
-      auto evp_md = EVP_sha256();
-      auto hash = stream_digest(stream, evp_md, SHA256_DIGEST_LENGTH);
-      for(std::size_t i = 1; i < iterations; ++i)
-        hash = message_digest(hash, evp_md, SHA256_DIGEST_LENGTH);
-      return hash;
-    }
-
-    /// Returns sha512 hash value from input string.
-    static std::string sha512(const std::string &input, std::size_t iterations = 1) noexcept {
-      auto evp_md = EVP_sha512();
-      auto hash = message_digest(input, evp_md, SHA512_DIGEST_LENGTH);
-      for(std::size_t i = 1; i < iterations; ++i)
-        hash = message_digest(hash, evp_md, SHA512_DIGEST_LENGTH);
-      return hash;
-    }
-
-    /// Returns sha512 hash value from input stream.
-    static std::string sha512(std::istream &stream, std::size_t iterations = 1) noexcept {
-      auto evp_md = EVP_sha512();
-      auto hash = stream_digest(stream, evp_md, SHA512_DIGEST_LENGTH);
-      for(std::size_t i = 1; i < iterations; ++i)
-        hash = message_digest(hash, evp_md, SHA512_DIGEST_LENGTH);
-      return hash;
-    }
-
-    /**
-     * Returns PBKDF2 derived key from the given password.
-     *
-     * @param password   The password to derive key from.
-     * @param salt       The salt to be used in the algorithm.
-     * @param iterations Number of iterations to be used in the algorithm.
-     * @param key_size   Number of bytes of the returned key.
-     *
-     * @return The PBKDF2 derived key.
-     */
-    static std::string pbkdf2(const std::string &password, const std::string &salt, int iterations, int key_size) noexcept {
-      std::string key(static_cast<std::size_t>(key_size), '\0');
-      PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(),
-                             reinterpret_cast<const unsigned char *>(salt.c_str()), salt.size(), iterations,
-                             key_size, reinterpret_cast<unsigned char *>(&key[0]));
-      return key;
-    }
-  };
-} // namespace SimpleWeb
-#endif /* SIMPLE_WEB_CRYPTO_HPP */
diff --git a/third_party/Simple-web-server/repo/docs/Doxyfile b/third_party/Simple-web-server/repo/docs/Doxyfile
deleted file mode 100644
index cc2a188a..00000000
--- a/third_party/Simple-web-server/repo/docs/Doxyfile
+++ /dev/null
@@ -1,2537 +0,0 @@
-# Doxyfile 1.8.15
-
-# This file describes the settings to be used by the documentation system
-# doxygen (www.doxygen.org) for a project.
-#
-# All text after a double hash (##) is considered a comment and is placed in
-# front of the TAG it is preceding.
-#
-# All text after a single hash (#) is considered a comment and will be ignored.
-# The format is:
-# TAG = value [value, ...]
-# For lists, items can also be appended using:
-# TAG += value [value, ...]
-# Values that contain spaces should be placed between quotes (\" \").
-
-#---------------------------------------------------------------------------
-# Project related configuration options
-#---------------------------------------------------------------------------
-
-# This tag specifies the encoding used for all characters in the configuration
-# file that follow. The default is UTF-8 which is also the encoding used for all
-# text before the first occurrence of this tag. Doxygen uses libiconv (or the
-# iconv built into libc) for the transcoding. See
-# https://www.gnu.org/software/libiconv/ for the list of possible encodings.
-# The default value is: UTF-8.
-
-DOXYFILE_ENCODING      = UTF-8
-
-# The PROJECT_NAME tag is a single word (or a sequence of words surrounded by
-# double-quotes, unless you are using Doxywizard) that should identify the
-# project for which the documentation is generated. This name is used in the
-# title of most generated pages and in a few other places.
-# The default value is: My Project.
-
-PROJECT_NAME           = "Simple-Web-Server"
-
-# The PROJECT_NUMBER tag can be used to enter a project or revision number. This
-# could be handy for archiving the generated documentation or if some version
-# control system is used.
-
-PROJECT_NUMBER         =
-
-# Using the PROJECT_BRIEF tag one can provide an optional one line description
-# for a project that appears at the top of each page and should give viewer a
-# quick idea about the purpose of the project. Keep the description short.
-
-PROJECT_BRIEF          =
-
-# With the PROJECT_LOGO tag one can specify a logo or an icon that is included
-# in the documentation. The maximum height of the logo should not exceed 55
-# pixels and the maximum width should not exceed 200 pixels. Doxygen will copy
-# the logo to the output directory.
-
-PROJECT_LOGO           =
-
-# The OUTPUT_DIRECTORY tag is used to specify the (relative or absolute) path
-# into which the generated documentation will be written. If a relative path is
-# entered, it will be relative to the location where doxygen was started. If
-# left blank the current directory will be used.
-
-OUTPUT_DIRECTORY       = doxygen_output
-
-# If the CREATE_SUBDIRS tag is set to YES then doxygen will create 4096 sub-
-# directories (in 2 levels) under the output directory of each output format and
-# will distribute the generated files over these directories. Enabling this
-# option can be useful when feeding doxygen a huge amount of source files, where
-# putting all generated files in the same directory would otherwise causes
-# performance problems for the file system.
-# The default value is: NO.
-
-CREATE_SUBDIRS         = NO
-
-# If the ALLOW_UNICODE_NAMES tag is set to YES, doxygen will allow non-ASCII
-# characters to appear in the names of generated files. If set to NO, non-ASCII
-# characters will be escaped, for example _xE3_x81_x84 will be used for Unicode
-# U+3044.
-# The default value is: NO.
-
-ALLOW_UNICODE_NAMES    = NO
-
-# The OUTPUT_LANGUAGE tag is used to specify the language in which all
-# documentation generated by doxygen is written. Doxygen will use this
-# information to generate all constant output in the proper language.
-# Possible values are: Afrikaans, Arabic, Armenian, Brazilian, Catalan, Chinese,
-# Chinese-Traditional, Croatian, Czech, Danish, Dutch, English (United States),
-# Esperanto, Farsi (Persian), Finnish, French, German, Greek, Hungarian,
-# Indonesian, Italian, Japanese, Japanese-en (Japanese with English messages),
-# Korean, Korean-en (Korean with English messages), Latvian, Lithuanian,
-# Macedonian, Norwegian, Persian (Farsi), Polish, Portuguese, Romanian, Russian,
-# Serbian, Serbian-Cyrillic, Slovak, Slovene, Spanish, Swedish, Turkish,
-# Ukrainian and Vietnamese.
-# The default value is: English.
-
-OUTPUT_LANGUAGE        = English
-
-# The OUTPUT_TEXT_DIRECTION tag is used to specify the direction in which all
-# documentation generated by doxygen is written. Doxygen will use this
-# information to generate all generated output in the proper direction.
-# Possible values are: None, LTR, RTL and Context.
-# The default value is: None.
-
-OUTPUT_TEXT_DIRECTION  = None
-
-# If the BRIEF_MEMBER_DESC tag is set to YES, doxygen will include brief member
-# descriptions after the members that are listed in the file and class
-# documentation (similar to Javadoc). Set to NO to disable this.
-# The default value is: YES.
-
-BRIEF_MEMBER_DESC      = YES
-
-# If the REPEAT_BRIEF tag is set to YES, doxygen will prepend the brief
-# description of a member or function before the detailed description
-#
-# Note: If both HIDE_UNDOC_MEMBERS and BRIEF_MEMBER_DESC are set to NO, the
-# brief descriptions will be completely suppressed.
-# The default value is: YES.
-
-REPEAT_BRIEF           = YES
-
-# This tag implements a quasi-intelligent brief description abbreviator that is
-# used to form the text in various listings. Each string in this list, if found
-# as the leading text of the brief description, will be stripped from the text
-# and the result, after processing the whole list, is used as the annotated
-# text. Otherwise, the brief description is used as-is. If left blank, the
-# following values are used ($name is automatically replaced with the name of
-# the entity):The $name class, The $name widget, The $name file, is, provides,
-# specifies, contains, represents, a, an and the.
-
-ABBREVIATE_BRIEF       = "The $name class" \
-                         "The $name widget" \
-                         "The $name file" \
-                         is \
-                         provides \
-                         specifies \
-                         contains \
-                         represents \
-                         a \
-                         an \
-                         the
-
-# If the ALWAYS_DETAILED_SEC and REPEAT_BRIEF tags are both set to YES then
-# doxygen will generate a detailed section even if there is only a brief
-# description.
-# The default value is: NO.
-
-ALWAYS_DETAILED_SEC    = NO
-
-# If the INLINE_INHERITED_MEMB tag is set to YES, doxygen will show all
-# inherited members of a class in the documentation of that class as if those
-# members were ordinary class members. Constructors, destructors and assignment
-# operators of the base classes will not be shown.
-# The default value is: NO.
-
-INLINE_INHERITED_MEMB  = NO
-
-# If the FULL_PATH_NAMES tag is set to YES, doxygen will prepend the full path
-# before files name in the file list and in the header files. If set to NO the
-# shortest path that makes the file name unique will be used
-# The default value is: YES.
-
-FULL_PATH_NAMES        = YES
-
-# The STRIP_FROM_PATH tag can be used to strip a user-defined part of the path.
-# Stripping is only done if one of the specified strings matches the left-hand
-# part of the path. The tag can be used to show relative paths in the file list.
-# If left blank the directory from which doxygen is run is used as the path to
-# strip.
-#
-# Note that you can specify absolute paths here, but also relative paths, which
-# will be relative from the directory where doxygen is started.
-# This tag requires that the tag FULL_PATH_NAMES is set to YES.
-
-STRIP_FROM_PATH        =
-
-# The STRIP_FROM_INC_PATH tag can be used to strip a user-defined part of the
-# path mentioned in the documentation of a class, which tells the reader which
-# header file to include in order to use a class. If left blank only the name of
-# the header file containing the class definition is used. Otherwise one should
-# specify the list of include paths that are normally passed to the compiler
-# using the -I flag.
-
-STRIP_FROM_INC_PATH    =
-
-# If the SHORT_NAMES tag is set to YES, doxygen will generate much shorter (but
-# less readable) file names. This can be useful is your file systems doesn't
-# support long names like on DOS, Mac, or CD-ROM.
-# The default value is: NO.
-
-SHORT_NAMES            = NO
-
-# If the JAVADOC_AUTOBRIEF tag is set to YES then doxygen will interpret the
-# first line (until the first dot) of a Javadoc-style comment as the brief
-# description. If set to NO, the Javadoc-style will behave just like regular Qt-
-# style comments (thus requiring an explicit @brief command for a brief
-# description.)
-# The default value is: NO.
-
-JAVADOC_AUTOBRIEF      = NO
-
-# If the QT_AUTOBRIEF tag is set to YES then doxygen will interpret the first
-# line (until the first dot) of a Qt-style comment as the brief description. If
-# set to NO, the Qt-style will behave just like regular Qt-style comments (thus
-# requiring an explicit \brief command for a brief description.)
-# The default value is: NO.
-
-QT_AUTOBRIEF           = NO
-
-# The MULTILINE_CPP_IS_BRIEF tag can be set to YES to make doxygen treat a
-# multi-line C++ special comment block (i.e. a block of //! or /// comments) as
-# a brief description. This used to be the default behavior. The new default is
-# to treat a multi-line C++ comment block as a detailed description. Set this
-# tag to YES if you prefer the old behavior instead.
-#
-# Note that setting this tag to YES also means that rational rose comments are
-# not recognized any more.
-# The default value is: NO.
-
-MULTILINE_CPP_IS_BRIEF = YES
-
-# If the INHERIT_DOCS tag is set to YES then an undocumented member inherits the
-# documentation from any documented member that it re-implements.
-# The default value is: YES.
-
-INHERIT_DOCS           = YES
-
-# If the SEPARATE_MEMBER_PAGES tag is set to YES then doxygen will produce a new
-# page for each member. If set to NO, the documentation of a member will be part
-# of the file/class/namespace that contains it.
-# The default value is: NO.
-
-SEPARATE_MEMBER_PAGES  = NO
-
-# The TAB_SIZE tag can be used to set the number of spaces in a tab. Doxygen
-# uses this value to replace tabs by spaces in code fragments.
-# Minimum value: 1, maximum value: 16, default value: 4.
-
-TAB_SIZE               = 4
-
-# This tag can be used to specify a number of aliases that act as commands in
-# the documentation. An alias has the form:
-# name=value
-# For example adding
-# "sideeffect=@par Side Effects:\n"
-# will allow you to put the command \sideeffect (or @sideeffect) in the
-# documentation, which will result in a user-defined paragraph with heading
-# "Side Effects:". You can put \n's in the value part of an alias to insert
-# newlines (in the resulting output). You can put ^^ in the value part of an
-# alias to insert a newline as if a physical newline was in the original file.
-# When you need a literal { or } or , in the value part of an alias you have to
-# escape them by means of a backslash (\), this can lead to conflicts with the
-# commands \{ and \} for these it is advised to use the version @{ and @} or use
-# a double escape (\\{ and \\})
-
-ALIASES                =
-
-# This tag can be used to specify a number of word-keyword mappings (TCL only).
-# A mapping has the form "name=value". For example adding "class=itcl::class"
-# will allow you to use the command class in the itcl::class meaning.
-
-TCL_SUBST              =
-
-# Set the OPTIMIZE_OUTPUT_FOR_C tag to YES if your project consists of C sources
-# only. Doxygen will then generate output that is more tailored for C. For
-# instance, some of the names that are used will be different. The list of all
-# members will be omitted, etc.
-# The default value is: NO.
-
-OPTIMIZE_OUTPUT_FOR_C  = NO
-
-# Set the OPTIMIZE_OUTPUT_JAVA tag to YES if your project consists of Java or
-# Python sources only. Doxygen will then generate output that is more tailored
-# for that language. For instance, namespaces will be presented as packages,
-# qualified scopes will look different, etc.
-# The default value is: NO.
-
-OPTIMIZE_OUTPUT_JAVA   = NO
-
-# Set the OPTIMIZE_FOR_FORTRAN tag to YES if your project consists of Fortran
-# sources. Doxygen will then generate output that is tailored for Fortran.
-# The default value is: NO.
-
-OPTIMIZE_FOR_FORTRAN   = NO
-
-# Set the OPTIMIZE_OUTPUT_VHDL tag to YES if your project consists of VHDL
-# sources. Doxygen will then generate output that is tailored for VHDL.
-# The default value is: NO.
-
-OPTIMIZE_OUTPUT_VHDL   = NO
-
-# Set the OPTIMIZE_OUTPUT_SLICE tag to YES if your project consists of Slice
-# sources only. Doxygen will then generate output that is more tailored for that
-# language. For instance, namespaces will be presented as modules, types will be
-# separated into more groups, etc.
-# The default value is: NO.
-
-OPTIMIZE_OUTPUT_SLICE  = NO
-
-# Doxygen selects the parser to use depending on the extension of the files it
-# parses. With this tag you can assign which parser to use for a given
-# extension. Doxygen has a built-in mapping, but you can override or extend it
-# using this tag. The format is ext=language, where ext is a file extension, and
-# language is one of the parsers supported by doxygen: IDL, Java, Javascript,
-# Csharp (C#), C, C++, D, PHP, md (Markdown), Objective-C, Python, Slice,
-# Fortran (fixed format Fortran: FortranFixed, free formatted Fortran:
-# FortranFree, unknown formatted Fortran: Fortran. In the later case the parser
-# tries to guess whether the code is fixed or free formatted code, this is the
-# default for Fortran type files), VHDL, tcl. For instance to make doxygen treat
-# .inc files as Fortran files (default is PHP), and .f files as C (default is
-# Fortran), use: inc=Fortran f=C.
-#
-# Note: For files without extension you can use no_extension as a placeholder.
-#
-# Note that for custom extensions you also need to set FILE_PATTERNS otherwise
-# the files are not read by doxygen.
-
-EXTENSION_MAPPING      =
-
-# If the MARKDOWN_SUPPORT tag is enabled then doxygen pre-processes all comments
-# according to the Markdown format, which allows for more readable
-# documentation. See https://daringfireball.net/projects/markdown/ for details.
-# The output of markdown processing is further processed by doxygen, so you can
-# mix doxygen, HTML, and XML commands with Markdown formatting. Disable only in
-# case of backward compatibilities issues.
-# The default value is: YES.
-
-MARKDOWN_SUPPORT       = YES
-
-# When the TOC_INCLUDE_HEADINGS tag is set to a non-zero value, all headings up
-# to that level are automatically included in the table of contents, even if
-# they do not have an id attribute.
-# Note: This feature currently applies only to Markdown headings.
-# Minimum value: 0, maximum value: 99, default value: 0.
-# This tag requires that the tag MARKDOWN_SUPPORT is set to YES.
-
-TOC_INCLUDE_HEADINGS   = 0
-
-# When enabled doxygen tries to link words that correspond to documented
-# classes, or namespaces to their corresponding documentation. Such a link can
-# be prevented in individual cases by putting a % sign in front of the word or
-# globally by setting AUTOLINK_SUPPORT to NO.
-# The default value is: YES.
-
-AUTOLINK_SUPPORT       = YES
-
-# If you use STL classes (i.e. std::string, std::vector, etc.) but do not want
-# to include (a tag file for) the STL sources as input, then you should set this
-# tag to YES in order to let doxygen match functions declarations and
-# definitions whose arguments contain STL classes (e.g. func(std::string);
-# versus func(std::string) {}). This also make the inheritance and collaboration
-# diagrams that involve STL classes more complete and accurate.
-# The default value is: NO.
-
-BUILTIN_STL_SUPPORT    = NO
-
-# If you use Microsoft's C++/CLI language, you should set this option to YES to
-# enable parsing support.
-# The default value is: NO.
-
-CPP_CLI_SUPPORT        = NO
-
-# Set the SIP_SUPPORT tag to YES if your project consists of sip (see:
-# https://www.riverbankcomputing.com/software/sip/intro) sources only. Doxygen
-# will parse them like normal C++ but will assume all classes use public instead
-# of private inheritance when no explicit protection keyword is present.
-# The default value is: NO.
-
-SIP_SUPPORT            = NO
-
-# For Microsoft's IDL there are propget and propput attributes to indicate
-# getter and setter methods for a property. Setting this option to YES will make
-# doxygen to replace the get and set methods by a property in the documentation.
-# This will only work if the methods are indeed getting or setting a simple
-# type. If this is not the case, or you want to show the methods anyway, you
-# should set this option to NO.
-# The default value is: YES.
-
-IDL_PROPERTY_SUPPORT   = YES
-
-# If member grouping is used in the documentation and the DISTRIBUTE_GROUP_DOC
-# tag is set to YES then doxygen will reuse the documentation of the first
-# member in the group (if any) for the other members of the group. By default
-# all members of a group must be documented explicitly.
-# The default value is: NO.
-
-DISTRIBUTE_GROUP_DOC   = NO
-
-# If one adds a struct or class to a group and this option is enabled, then also
-# any nested class or struct is added to the same group. By default this option
-# is disabled and one has to add nested compounds explicitly via \ingroup.
-# The default value is: NO.
-
-GROUP_NESTED_COMPOUNDS = NO
-
-# Set the SUBGROUPING tag to YES to allow class member groups of the same type
-# (for instance a group of public functions) to be put as a subgroup of that
-# type (e.g. under the Public Functions section). Set it to NO to prevent
-# subgrouping. Alternatively, this can be done per class using the
-# \nosubgrouping command.
-# The default value is: YES.
-
-SUBGROUPING            = YES
-
-# When the INLINE_GROUPED_CLASSES tag is set to YES, classes, structs and unions
-# are shown inside the group in which they are included (e.g. using \ingroup)
-# instead of on a separate page (for HTML and Man pages) or section (for LaTeX
-# and RTF).
-#
-# Note that this feature does not work in combination with
-# SEPARATE_MEMBER_PAGES.
-# The default value is: NO.
-
-INLINE_GROUPED_CLASSES = NO
-
-# When the INLINE_SIMPLE_STRUCTS tag is set to YES, structs, classes, and unions
-# with only public data fields or simple typedef fields will be shown inline in
-# the documentation of the scope in which they are defined (i.e. file,
-# namespace, or group documentation), provided this scope is documented. If set
-# to NO, structs, classes, and unions are shown on a separate page (for HTML and
-# Man pages) or section (for LaTeX and RTF).
-# The default value is: NO.
-
-INLINE_SIMPLE_STRUCTS  = NO
-
-# When TYPEDEF_HIDES_STRUCT tag is enabled, a typedef of a struct, union, or
-# enum is documented as struct, union, or enum with the name of the typedef. So
-# typedef struct TypeS {} TypeT, will appear in the documentation as a struct
-# with name TypeT. When disabled the typedef will appear as a member of a file,
-# namespace, or class. And the struct will be named TypeS. This can typically be
-# useful for C code in case the coding convention dictates that all compound
-# types are typedef'ed and only the typedef is referenced, never the tag name.
-# The default value is: NO.
-
-TYPEDEF_HIDES_STRUCT   = NO
-
-# The size of the symbol lookup cache can be set using LOOKUP_CACHE_SIZE. This
-# cache is used to resolve symbols given their name and scope. Since this can be
-# an expensive process and often the same symbol appears multiple times in the
-# code, doxygen keeps a cache of pre-resolved symbols. If the cache is too small
-# doxygen will become slower. If the cache is too large, memory is wasted. The
-# cache size is given by this formula: 2^(16+LOOKUP_CACHE_SIZE). The valid range
-# is 0..9, the default is 0, corresponding to a cache size of 2^16=65536
-# symbols. At the end of a run doxygen will report the cache usage and suggest
-# the optimal cache size from a speed point of view.
-# Minimum value: 0, maximum value: 9, default value: 0.
-
-LOOKUP_CACHE_SIZE      = 0
-
-#---------------------------------------------------------------------------
-# Build related configuration options
-#---------------------------------------------------------------------------
-
-# If the EXTRACT_ALL tag is set to YES, doxygen will assume all entities in
-# documentation are documented, even if no documentation was available. Private
-# class members and static file members will be hidden unless the
-# EXTRACT_PRIVATE respectively EXTRACT_STATIC tags are set to YES.
-# Note: This will also disable the warnings about undocumented members that are
-# normally produced when WARNINGS is set to YES.
-# The default value is: NO.
-
-EXTRACT_ALL            = YES
-
-# If the EXTRACT_PRIVATE tag is set to YES, all private members of a class will
-# be included in the documentation.
-# The default value is: NO.
-
-EXTRACT_PRIVATE        = NO
-
-# If the EXTRACT_PACKAGE tag is set to YES, all members with package or internal
-# scope will be included in the documentation.
-# The default value is: NO.
-
-EXTRACT_PACKAGE        = NO
-
-# If the EXTRACT_STATIC tag is set to YES, all static members of a file will be
-# included in the documentation.
-# The default value is: NO.
-
-EXTRACT_STATIC         = NO
-
-# If the EXTRACT_LOCAL_CLASSES tag is set to YES, classes (and structs) defined
-# locally in source files will be included in the documentation. If set to NO,
-# only classes defined in header files are included. Does not have any effect
-# for Java sources.
-# The default value is: YES.
-
-EXTRACT_LOCAL_CLASSES  = YES
-
-# This flag is only useful for Objective-C code. If set to YES, local methods,
-# which are defined in the implementation section but not in the interface are
-# included in the documentation. If set to NO, only methods in the interface are
-# included.
-# The default value is: NO.
-
-EXTRACT_LOCAL_METHODS  = NO
-
-# If this flag is set to YES, the members of anonymous namespaces will be
-# extracted and appear in the documentation as a namespace called
-# 'anonymous_namespace{file}', where file will be replaced with the base name of
-# the file that contains the anonymous namespace. By default anonymous namespace
-# are hidden.
-# The default value is: NO.
-
-EXTRACT_ANON_NSPACES   = NO
-
-# If the HIDE_UNDOC_MEMBERS tag is set to YES, doxygen will hide all
-# undocumented members inside documented classes or files. If set to NO these
-# members will be included in the various overviews, but no documentation
-# section is generated. This option has no effect if EXTRACT_ALL is enabled.
-# The default value is: NO.
-
-HIDE_UNDOC_MEMBERS     = NO
-
-# If the HIDE_UNDOC_CLASSES tag is set to YES, doxygen will hide all
-# undocumented classes that are normally visible in the class hierarchy. If set
-# to NO, these classes will be included in the various overviews. This option
-# has no effect if EXTRACT_ALL is enabled.
-# The default value is: NO.
-
-HIDE_UNDOC_CLASSES     = NO
-
-# If the HIDE_FRIEND_COMPOUNDS tag is set to YES, doxygen will hide all friend
-# (class|struct|union) declarations. If set to NO, these declarations will be
-# included in the documentation.
-# The default value is: NO.
-
-HIDE_FRIEND_COMPOUNDS  = NO
-
-# If the HIDE_IN_BODY_DOCS tag is set to YES, doxygen will hide any
-# documentation blocks found inside the body of a function. If set to NO, these
-# blocks will be appended to the function's detailed documentation block.
-# The default value is: NO.
-
-HIDE_IN_BODY_DOCS      = NO
-
-# The INTERNAL_DOCS tag determines if documentation that is typed after a
-# \internal command is included. If the tag is set to NO then the documentation
-# will be excluded. Set it to YES to include the internal documentation.
-# The default value is: NO.
-
-INTERNAL_DOCS          = NO
-
-# If the CASE_SENSE_NAMES tag is set to NO then doxygen will only generate file
-# names in lower-case letters. If set to YES, upper-case letters are also
-# allowed. This is useful if you have classes or files whose names only differ
-# in case and if your file system supports case sensitive file names. Windows
-# and Mac users are advised to set this option to NO.
-# The default value is: system dependent.
-
-CASE_SENSE_NAMES       = NO
-
-# If the HIDE_SCOPE_NAMES tag is set to NO then doxygen will show members with
-# their full class and namespace scopes in the documentation. If set to YES, the
-# scope will be hidden.
-# The default value is: NO.
-
-HIDE_SCOPE_NAMES       = NO
-
-# If the HIDE_COMPOUND_REFERENCE tag is set to NO (default) then doxygen will
-# append additional text to a page's title, such as Class Reference. If set to
-# YES the compound reference will be hidden.
-# The default value is: NO.
-
-HIDE_COMPOUND_REFERENCE= NO
-
-# If the SHOW_INCLUDE_FILES tag is set to YES then doxygen will put a list of
-# the files that are included by a file in the documentation of that file.
-# The default value is: YES.
-
-SHOW_INCLUDE_FILES     = YES
-
-# If the SHOW_GROUPED_MEMB_INC tag is set to YES then Doxygen will add for each
-# grouped member an include statement to the documentation, telling the reader
-# which file to include in order to use the member.
-# The default value is: NO.
-
-SHOW_GROUPED_MEMB_INC  = NO
-
-# If the FORCE_LOCAL_INCLUDES tag is set to YES then doxygen will list include
-# files with double quotes in the documentation rather than with sharp brackets.
-# The default value is: NO.
-
-FORCE_LOCAL_INCLUDES   = NO
-
-# If the INLINE_INFO tag is set to YES then a tag [inline] is inserted in the
-# documentation for inline members.
-# The default value is: YES.
-
-INLINE_INFO            = YES
-
-# If the SORT_MEMBER_DOCS tag is set to YES then doxygen will sort the
-# (detailed) documentation of file and class members alphabetically by member
-# name. If set to NO, the members will appear in declaration order.
-# The default value is: YES.
-
-SORT_MEMBER_DOCS       = YES
-
-# If the SORT_BRIEF_DOCS tag is set to YES then doxygen will sort the brief
-# descriptions of file, namespace and class members alphabetically by member
-# name. If set to NO, the members will appear in declaration order. Note that
-# this will also influence the order of the classes in the class list.
-# The default value is: NO.
-
-SORT_BRIEF_DOCS        = NO
-
-# If the SORT_MEMBERS_CTORS_1ST tag is set to YES then doxygen will sort the
-# (brief and detailed) documentation of class members so that constructors and
-# destructors are listed first. If set to NO the constructors will appear in the
-# respective orders defined by SORT_BRIEF_DOCS and SORT_MEMBER_DOCS.
-# Note: If SORT_BRIEF_DOCS is set to NO this option is ignored for sorting brief
-# member documentation.
-# Note: If SORT_MEMBER_DOCS is set to NO this option is ignored for sorting
-# detailed member documentation.
-# The default value is: NO.
-
-SORT_MEMBERS_CTORS_1ST = NO
-
-# If the SORT_GROUP_NAMES tag is set to YES then doxygen will sort the hierarchy
-# of group names into alphabetical order. If set to NO the group names will
-# appear in their defined order.
-# The default value is: NO.
-
-SORT_GROUP_NAMES       = NO
-
-# If the SORT_BY_SCOPE_NAME tag is set to YES, the class list will be sorted by
-# fully-qualified names, including namespaces. If set to NO, the class list will
-# be sorted only by class name, not including the namespace part.
-# Note: This option is not very useful if HIDE_SCOPE_NAMES is set to YES.
-# Note: This option applies only to the class list, not to the alphabetical
-# list.
-# The default value is: NO.
-
-SORT_BY_SCOPE_NAME     = NO
-
-# If the STRICT_PROTO_MATCHING option is enabled and doxygen fails to do proper
-# type resolution of all parameters of a function it will reject a match between
-# the prototype and the implementation of a member function even if there is
-# only one candidate or it is obvious which candidate to choose by doing a
-# simple string match. By disabling STRICT_PROTO_MATCHING doxygen will still
-# accept a match between prototype and implementation in such cases.
-# The default value is: NO.
-
-STRICT_PROTO_MATCHING  = NO
-
-# The GENERATE_TODOLIST tag can be used to enable (YES) or disable (NO) the todo
-# list. This list is created by putting \todo commands in the documentation.
-# The default value is: YES.
-
-GENERATE_TODOLIST      = YES
-
-# The GENERATE_TESTLIST tag can be used to enable (YES) or disable (NO) the test
-# list. This list is created by putting \test commands in the documentation.
-# The default value is: YES.
-
-GENERATE_TESTLIST      = YES
-
-# The GENERATE_BUGLIST tag can be used to enable (YES) or disable (NO) the bug
-# list. This list is created by putting \bug commands in the documentation.
-# The default value is: YES.
-
-GENERATE_BUGLIST       = YES
-
-# The GENERATE_DEPRECATEDLIST tag can be used to enable (YES) or disable (NO)
-# the deprecated list. This list is created by putting \deprecated commands in
-# the documentation.
-# The default value is: YES.
-
-GENERATE_DEPRECATEDLIST= YES
-
-# The ENABLED_SECTIONS tag can be used to enable conditional documentation
-# sections, marked by \if <section_label> ... \endif and \cond <section_label>
-# ... \endcond blocks.
-
-ENABLED_SECTIONS       =
-
-# The MAX_INITIALIZER_LINES tag determines the maximum number of lines that the
-# initial value of a variable or macro / define can have for it to appear in the
-# documentation. If the initializer consists of more lines than specified here
-# it will be hidden. Use a value of 0 to hide initializers completely. The
-# appearance of the value of individual variables and macros / defines can be
-# controlled using \showinitializer or \hideinitializer command in the
-# documentation regardless of this setting.
-# Minimum value: 0, maximum value: 10000, default value: 30.
-
-MAX_INITIALIZER_LINES  = 30
-
-# Set the SHOW_USED_FILES tag to NO to disable the list of files generated at
-# the bottom of the documentation of classes and structs. If set to YES, the
-# list will mention the files that were used to generate the documentation.
-# The default value is: YES.
-
-SHOW_USED_FILES        = YES
-
-# Set the SHOW_FILES tag to NO to disable the generation of the Files page. This
-# will remove the Files entry from the Quick Index and from the Folder Tree View
-# (if specified).
-# The default value is: YES.
-
-SHOW_FILES             = YES
-
-# Set the SHOW_NAMESPACES tag to NO to disable the generation of the Namespaces
-# page. This will remove the Namespaces entry from the Quick Index and from the
-# Folder Tree View (if specified).
-# The default value is: YES.
-
-SHOW_NAMESPACES        = NO
-
-# The FILE_VERSION_FILTER tag can be used to specify a program or script that
-# doxygen should invoke to get the current version for each file (typically from
-# the version control system). Doxygen will invoke the program by executing (via
-# popen()) the command command input-file, where command is the value of the
-# FILE_VERSION_FILTER tag, and input-file is the name of an input file provided
-# by doxygen. Whatever the program writes to standard output is used as the file
-# version. For an example see the documentation.
-
-FILE_VERSION_FILTER    =
-
-# The LAYOUT_FILE tag can be used to specify a layout file which will be parsed
-# by doxygen. The layout file controls the global structure of the generated
-# output files in an output format independent way. To create the layout file
-# that represents doxygen's defaults, run doxygen with the -l option. You can
-# optionally specify a file name after the option, if omitted DoxygenLayout.xml
-# will be used as the name of the layout file.
-#
-# Note that if you run doxygen from a directory containing a file called
-# DoxygenLayout.xml, doxygen will parse it automatically even if the LAYOUT_FILE
-# tag is left empty.
-
-LAYOUT_FILE            =
-
-# The CITE_BIB_FILES tag can be used to specify one or more bib files containing
-# the reference definitions. This must be a list of .bib files. The .bib
-# extension is automatically appended if omitted. This requires the bibtex tool
-# to be installed. See also https://en.wikipedia.org/wiki/BibTeX for more info.
-# For LaTeX the style of the bibliography can be controlled using
-# LATEX_BIB_STYLE. To use this feature you need bibtex and perl available in the
-# search path. See also \cite for info how to create references.
-
-CITE_BIB_FILES         =
-
-#---------------------------------------------------------------------------
-# Configuration options related to warning and progress messages
-#---------------------------------------------------------------------------
-
-# The QUIET tag can be used to turn on/off the messages that are generated to
-# standard output by doxygen. If QUIET is set to YES this implies that the
-# messages are off.
-# The default value is: NO.
-
-QUIET                  = NO
-
-# The WARNINGS tag can be used to turn on/off the warning messages that are
-# generated to standard error (stderr) by doxygen. If WARNINGS is set to YES
-# this implies that the warnings are on.
-#
-# Tip: Turn warnings on while writing the documentation.
-# The default value is: YES.
-
-WARNINGS               = YES
-
-# If the WARN_IF_UNDOCUMENTED tag is set to YES then doxygen will generate
-# warnings for undocumented members. If EXTRACT_ALL is set to YES then this flag
-# will automatically be disabled.
-# The default value is: YES.
-
-WARN_IF_UNDOCUMENTED   = YES
-
-# If the WARN_IF_DOC_ERROR tag is set to YES, doxygen will generate warnings for
-# potential errors in the documentation, such as not documenting some parameters
-# in a documented function, or documenting parameters that don't exist or using
-# markup commands wrongly.
-# The default value is: YES.
-
-WARN_IF_DOC_ERROR      = YES
-
-# This WARN_NO_PARAMDOC option can be enabled to get warnings for functions that
-# are documented, but have no documentation for their parameters or return
-# value. If set to NO, doxygen will only warn about wrong or incomplete
-# parameter documentation, but not about the absence of documentation. If
-# EXTRACT_ALL is set to YES then this flag will automatically be disabled.
-# The default value is: NO.
-
-WARN_NO_PARAMDOC       = NO
-
-# If the WARN_AS_ERROR tag is set to YES then doxygen will immediately stop when
-# a warning is encountered.
-# The default value is: NO.
-
-WARN_AS_ERROR          = NO
-
-# The WARN_FORMAT tag determines the format of the warning messages that doxygen
-# can produce. The string should contain the $file, $line, and $text tags, which
-# will be replaced by the file and line number from which the warning originated
-# and the warning text. Optionally the format may contain $version, which will
-# be replaced by the version of the file (if it could be obtained via
-# FILE_VERSION_FILTER)
-# The default value is: $file:$line: $text.
-
-WARN_FORMAT            = "$file:$line: $text"
-
-# The WARN_LOGFILE tag can be used to specify a file to which warning and error
-# messages should be written. If left blank the output is written to standard
-# error (stderr).
-
-WARN_LOGFILE           =
-
-#---------------------------------------------------------------------------
-# Configuration options related to the input files
-#---------------------------------------------------------------------------
-
-# The INPUT tag is used to specify the files and/or directories that contain
-# documented source files. You may enter file names like myfile.cpp or
-# directories like /usr/src/myproject. Separate the files or directories with
-# spaces. See also FILE_PATTERNS and EXTENSION_MAPPING
-# Note: If this tag is empty the current directory is searched.
-
-INPUT                  =
-
-# This tag can be used to specify the character encoding of the source files
-# that doxygen parses. Internally doxygen uses the UTF-8 encoding. Doxygen uses
-# libiconv (or the iconv built into libc) for the transcoding. See the libiconv
-# documentation (see: https://www.gnu.org/software/libiconv/) for the list of
-# possible encodings.
-# The default value is: UTF-8.
-
-INPUT_ENCODING         = UTF-8
-
-# If the value of the INPUT tag contains directories, you can use the
-# FILE_PATTERNS tag to specify one or more wildcard patterns (like *.cpp and
-# *.h) to filter out the source-files in the directories.
-#
-# Note that for custom extensions or not directly supported extensions you also
-# need to set EXTENSION_MAPPING for the extension otherwise the files are not
-# read by doxygen.
-#
-# If left blank the following patterns are tested:*.c, *.cc, *.cxx, *.cpp,
-# *.c++, *.java, *.ii, *.ixx, *.ipp, *.i++, *.inl, *.idl, *.ddl, *.odl, *.h,
-# *.hh, *.hxx, *.hpp, *.h++, *.cs, *.d, *.php, *.php4, *.php5, *.phtml, *.inc,
-# *.m, *.markdown, *.md, *.mm, *.dox, *.py, *.pyw, *.f90, *.f95, *.f03, *.f08,
-# *.f, *.for, *.tcl, *.vhd, *.vhdl, *.ucf, *.qsf and *.ice.
-
-FILE_PATTERNS          = *.c \
-                         *.cc \
-                         *.cxx \
-                         *.cpp \
-                         *.c++ \
-                         *.java \
-                         *.ii \
-                         *.ixx \
-                         *.ipp \
-                         *.i++ \
-                         *.inl \
-                         *.idl \
-                         *.ddl \
-                         *.odl \
-                         *.h \
-                         *.hh \
-                         *.hxx \
-                         *.hpp \
-                         *.h++ \
-                         *.cs \
-                         *.d \
-                         *.php \
-                         *.php4 \
-                         *.php5 \
-                         *.phtml \
-                         *.inc \
-                         *.m \
-                         *.markdown \
-                         *.md \
-                         *.mm \
-                         *.dox \
-                         *.py \
-                         *.pyw \
-                         *.f90 \
-                         *.f95 \
-                         *.f03 \
-                         *.f08 \
-                         *.f \
-                         *.for \
-                         *.tcl \
-                         *.vhd \
-                         *.vhdl \
-                         *.ucf \
-                         *.qsf \
-                         *.ice
-
-# The RECURSIVE tag can be used to specify whether or not subdirectories should
-# be searched for input files as well.
-# The default value is: NO.
-
-RECURSIVE              = NO
-
-# The EXCLUDE tag can be used to specify files and/or directories that should be
-# excluded from the INPUT source files. This way you can easily exclude a
-# subdirectory from a directory tree whose root is specified with the INPUT tag.
-#
-# Note that relative paths are relative to the directory from which doxygen is
-# run.
-
-EXCLUDE                =
-
-# The EXCLUDE_SYMLINKS tag can be used to select whether or not files or
-# directories that are symbolic links (a Unix file system feature) are excluded
-# from the input.
-# The default value is: NO.
-
-EXCLUDE_SYMLINKS       = NO
-
-# If the value of the INPUT tag contains directories, you can use the
-# EXCLUDE_PATTERNS tag to specify one or more wildcard patterns to exclude
-# certain files from those directories.
-#
-# Note that the wildcards are matched against the file with absolute path, so to
-# exclude all test directories for example use the pattern */test/*
-
-EXCLUDE_PATTERNS       =
-
-# The EXCLUDE_SYMBOLS tag can be used to specify one or more symbol names
-# (namespaces, classes, functions, etc.) that should be excluded from the
-# output. The symbol name can be a fully qualified name, a word, or if the
-# wildcard * is used, a substring. Examples: ANamespace, AClass,
-# AClass::ANamespace, ANamespace::*Test
-#
-# Note that the wildcards are matched against the file with absolute path, so to
-# exclude all test directories use the pattern */test/*
-
-EXCLUDE_SYMBOLS        =
-
-# The EXAMPLE_PATH tag can be used to specify one or more files or directories
-# that contain example code fragments that are included (see the \include
-# command).
-
-EXAMPLE_PATH           =
-
-# If the value of the EXAMPLE_PATH tag contains directories, you can use the
-# EXAMPLE_PATTERNS tag to specify one or more wildcard pattern (like *.cpp and
-# *.h) to filter out the source-files in the directories. If left blank all
-# files are included.
-
-EXAMPLE_PATTERNS       = *
-
-# If the EXAMPLE_RECURSIVE tag is set to YES then subdirectories will be
-# searched for input files to be used with the \include or \dontinclude commands
-# irrespective of the value of the RECURSIVE tag.
-# The default value is: NO.
-
-EXAMPLE_RECURSIVE      = NO
-
-# The IMAGE_PATH tag can be used to specify one or more files or directories
-# that contain images that are to be included in the documentation (see the
-# \image command).
-
-IMAGE_PATH             =
-
-# The INPUT_FILTER tag can be used to specify a program that doxygen should
-# invoke to filter for each input file. Doxygen will invoke the filter program
-# by executing (via popen()) the command:
-#
-# <filter> <input-file>
-#
-# where <filter> is the value of the INPUT_FILTER tag, and <input-file> is the
-# name of an input file. Doxygen will then use the output that the filter
-# program writes to standard output. If FILTER_PATTERNS is specified, this tag
-# will be ignored.
-#
-# Note that the filter must not add or remove lines; it is applied before the
-# code is scanned, but not when the output code is generated. If lines are added
-# or removed, the anchors will not be placed correctly.
-#
-# Note that for custom extensions or not directly supported extensions you also
-# need to set EXTENSION_MAPPING for the extension otherwise the files are not
-# properly processed by doxygen.
-
-INPUT_FILTER           =
-
-# The FILTER_PATTERNS tag can be used to specify filters on a per file pattern
-# basis. Doxygen will compare the file name with each pattern and apply the
-# filter if there is a match. The filters are a list of the form: pattern=filter
-# (like *.cpp=my_cpp_filter). See INPUT_FILTER for further information on how
-# filters are used. If the FILTER_PATTERNS tag is empty or if none of the
-# patterns match the file name, INPUT_FILTER is applied.
-#
-# Note that for custom extensions or not directly supported extensions you also
-# need to set EXTENSION_MAPPING for the extension otherwise the files are not
-# properly processed by doxygen.
-
-FILTER_PATTERNS        =
-
-# If the FILTER_SOURCE_FILES tag is set to YES, the input filter (if set using
-# INPUT_FILTER) will also be used to filter the input files that are used for
-# producing the source files to browse (i.e. when SOURCE_BROWSER is set to YES).
-# The default value is: NO.
-
-FILTER_SOURCE_FILES    = NO
-
-# The FILTER_SOURCE_PATTERNS tag can be used to specify source filters per file
-# pattern. A pattern will override the setting for FILTER_PATTERN (if any) and
-# it is also possible to disable source filtering for a specific pattern using
-# *.ext= (so without naming a filter).
-# This tag requires that the tag FILTER_SOURCE_FILES is set to YES.
-
-FILTER_SOURCE_PATTERNS =
-
-# If the USE_MDFILE_AS_MAINPAGE tag refers to the name of a markdown file that
-# is part of the input, its contents will be placed on the main page
-# (index.html). This can be useful if you have a project on for instance GitHub
-# and want to reuse the introduction page also for the doxygen output.
-
-USE_MDFILE_AS_MAINPAGE = README.md
-
-#---------------------------------------------------------------------------
-# Configuration options related to source browsing
-#---------------------------------------------------------------------------
-
-# If the SOURCE_BROWSER tag is set to YES then a list of source files will be
-# generated. Documented entities will be cross-referenced with these sources.
-#
-# Note: To get rid of all source code in the generated output, make sure that
-# also VERBATIM_HEADERS is set to NO.
-# The default value is: NO.
-
-SOURCE_BROWSER         = NO
-
-# Setting the INLINE_SOURCES tag to YES will include the body of functions,
-# classes and enums directly into the documentation.
-# The default value is: NO.
-
-INLINE_SOURCES         = NO
-
-# Setting the STRIP_CODE_COMMENTS tag to YES will instruct doxygen to hide any
-# special comment blocks from generated source code fragments. Normal C, C++ and
-# Fortran comments will always remain visible.
-# The default value is: YES.
-
-STRIP_CODE_COMMENTS    = YES
-
-# If the REFERENCED_BY_RELATION tag is set to YES then for each documented
-# entity all documented functions referencing it will be listed.
-# The default value is: NO.
-
-REFERENCED_BY_RELATION = NO
-
-# If the REFERENCES_RELATION tag is set to YES then for each documented function
-# all documented entities called/used by that function will be listed.
-# The default value is: NO.
-
-REFERENCES_RELATION    = NO
-
-# If the REFERENCES_LINK_SOURCE tag is set to YES and SOURCE_BROWSER tag is set
-# to YES then the hyperlinks from functions in REFERENCES_RELATION and
-# REFERENCED_BY_RELATION lists will link to the source code. Otherwise they will
-# link to the documentation.
-# The default value is: YES.
-
-REFERENCES_LINK_SOURCE = YES
-
-# If SOURCE_TOOLTIPS is enabled (the default) then hovering a hyperlink in the
-# source code will show a tooltip with additional information such as prototype,
-# brief description and links to the definition and documentation. Since this
-# will make the HTML file larger and loading of large files a bit slower, you
-# can opt to disable this feature.
-# The default value is: YES.
-# This tag requires that the tag SOURCE_BROWSER is set to YES.
-
-SOURCE_TOOLTIPS        = YES
-
-# If the USE_HTAGS tag is set to YES then the references to source code will
-# point to the HTML generated by the htags(1) tool instead of doxygen built-in
-# source browser. The htags tool is part of GNU's global source tagging system
-# (see https://www.gnu.org/software/global/global.html). You will need version
-# 4.8.6 or higher.
-#
-# To use it do the following:
-# - Install the latest version of global
-# - Enable SOURCE_BROWSER and USE_HTAGS in the configuration file
-# - Make sure the INPUT points to the root of the source tree
-# - Run doxygen as normal
-#
-# Doxygen will invoke htags (and that will in turn invoke gtags), so these
-# tools must be available from the command line (i.e. in the search path).
-#
-# The result: instead of the source browser generated by doxygen, the links to
-# source code will now point to the output of htags.
-# The default value is: NO.
-# This tag requires that the tag SOURCE_BROWSER is set to YES.
-
-USE_HTAGS              = NO
-
-# If the VERBATIM_HEADERS tag is set the YES then doxygen will generate a
-# verbatim copy of the header file for each class for which an include is
-# specified. Set to NO to disable this.
-# See also: Section \class.
-# The default value is: YES.
-
-VERBATIM_HEADERS       = YES
-
-#---------------------------------------------------------------------------
-# Configuration options related to the alphabetical class index
-#---------------------------------------------------------------------------
-
-# If the ALPHABETICAL_INDEX tag is set to YES, an alphabetical index of all
-# compounds will be generated. Enable this if the project contains a lot of
-# classes, structs, unions or interfaces.
-# The default value is: YES.
-
-ALPHABETICAL_INDEX     = YES
-
-# The COLS_IN_ALPHA_INDEX tag can be used to specify the number of columns in
-# which the alphabetical index list will be split.
-# Minimum value: 1, maximum value: 20, default value: 5.
-# This tag requires that the tag ALPHABETICAL_INDEX is set to YES.
-
-COLS_IN_ALPHA_INDEX    = 5
-
-# In case all classes in a project start with a common prefix, all classes will
-# be put under the same header in the alphabetical index. The IGNORE_PREFIX tag
-# can be used to specify a prefix (or a list of prefixes) that should be ignored
-# while generating the index headers.
-# This tag requires that the tag ALPHABETICAL_INDEX is set to YES.
-
-IGNORE_PREFIX          =
-
-#---------------------------------------------------------------------------
-# Configuration options related to the HTML output
-#---------------------------------------------------------------------------
-
-# If the GENERATE_HTML tag is set to YES, doxygen will generate HTML output
-# The default value is: YES.
-
-GENERATE_HTML          = YES
-
-# The HTML_OUTPUT tag is used to specify where the HTML docs will be put. If a
-# relative path is entered the value of OUTPUT_DIRECTORY will be put in front of
-# it.
-# The default directory is: html.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_OUTPUT            = html
-
-# The HTML_FILE_EXTENSION tag can be used to specify the file extension for each
-# generated HTML page (for example: .htm, .php, .asp).
-# The default value is: .html.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_FILE_EXTENSION    = .html
-
-# The HTML_HEADER tag can be used to specify a user-defined HTML header file for
-# each generated HTML page. If the tag is left blank doxygen will generate a
-# standard header.
-#
-# To get valid HTML the header file that includes any scripts and style sheets
-# that doxygen needs, which is dependent on the configuration options used (e.g.
-# the setting GENERATE_TREEVIEW). It is highly recommended to start with a
-# default header using
-# doxygen -w html new_header.html new_footer.html new_stylesheet.css
-# YourConfigFile
-# and then modify the file new_header.html. See also section "Doxygen usage"
-# for information on how to generate the default header that doxygen normally
-# uses.
-# Note: The header is subject to change so you typically have to regenerate the
-# default header when upgrading to a newer version of doxygen. For a description
-# of the possible markers and block names see the documentation.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_HEADER            =
-
-# The HTML_FOOTER tag can be used to specify a user-defined HTML footer for each
-# generated HTML page. If the tag is left blank doxygen will generate a standard
-# footer. See HTML_HEADER for more information on how to generate a default
-# footer and what special commands can be used inside the footer. See also
-# section "Doxygen usage" for information on how to generate the default footer
-# that doxygen normally uses.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_FOOTER            =
-
-# The HTML_STYLESHEET tag can be used to specify a user-defined cascading style
-# sheet that is used by each HTML page. It can be used to fine-tune the look of
-# the HTML output. If left blank doxygen will generate a default style sheet.
-# See also section "Doxygen usage" for information on how to generate the style
-# sheet that doxygen normally uses.
-# Note: It is recommended to use HTML_EXTRA_STYLESHEET instead of this tag, as
-# it is more robust and this tag (HTML_STYLESHEET) will in the future become
-# obsolete.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_STYLESHEET        =
-
-# The HTML_EXTRA_STYLESHEET tag can be used to specify additional user-defined
-# cascading style sheets that are included after the standard style sheets
-# created by doxygen. Using this option one can overrule certain style aspects.
-# This is preferred over using HTML_STYLESHEET since it does not replace the
-# standard style sheet and is therefore more robust against future updates.
-# Doxygen will copy the style sheet files to the output directory.
-# Note: The order of the extra style sheet files is of importance (e.g. the last
-# style sheet in the list overrules the setting of the previous ones in the
-# list). For an example see the documentation.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_EXTRA_STYLESHEET  =
-
-# The HTML_EXTRA_FILES tag can be used to specify one or more extra images or
-# other source files which should be copied to the HTML output directory. Note
-# that these files will be copied to the base HTML output directory. Use the
-# $relpath^ marker in the HTML_HEADER and/or HTML_FOOTER files to load these
-# files. In the HTML_STYLESHEET file, use the file name only. Also note that the
-# files will be copied as-is; there are no commands or markers available.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_EXTRA_FILES       =
-
-# The HTML_COLORSTYLE_HUE tag controls the color of the HTML output. Doxygen
-# will adjust the colors in the style sheet and background images according to
-# this color. Hue is specified as an angle on a colorwheel, see
-# https://en.wikipedia.org/wiki/Hue for more information. For instance the value
-# 0 represents red, 60 is yellow, 120 is green, 180 is cyan, 240 is blue, 300
-# purple, and 360 is red again.
-# Minimum value: 0, maximum value: 359, default value: 220.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_COLORSTYLE_HUE    = 220
-
-# The HTML_COLORSTYLE_SAT tag controls the purity (or saturation) of the colors
-# in the HTML output. For a value of 0 the output will use grayscales only. A
-# value of 255 will produce the most vivid colors.
-# Minimum value: 0, maximum value: 255, default value: 100.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_COLORSTYLE_SAT    = 100
-
-# The HTML_COLORSTYLE_GAMMA tag controls the gamma correction applied to the
-# luminance component of the colors in the HTML output. Values below 100
-# gradually make the output lighter, whereas values above 100 make the output
-# darker. The value divided by 100 is the actual gamma applied, so 80 represents
-# a gamma of 0.8, The value 220 represents a gamma of 2.2, and 100 does not
-# change the gamma.
-# Minimum value: 40, maximum value: 240, default value: 80.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_COLORSTYLE_GAMMA  = 80
-
-# If the HTML_TIMESTAMP tag is set to YES then the footer of each generated HTML
-# page will contain the date and time when the page was generated. Setting this
-# to YES can help to show when doxygen was last run and thus if the
-# documentation is up to date.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_TIMESTAMP         = NO
-
-# If the HTML_DYNAMIC_MENUS tag is set to YES then the generated HTML
-# documentation will contain a main index with vertical navigation menus that
-# are dynamically created via Javascript. If disabled, the navigation index will
-# consists of multiple levels of tabs that are statically embedded in every HTML
-# page. Disable this option to support browsers that do not have Javascript,
-# like the Qt help browser.
-# The default value is: YES.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_DYNAMIC_MENUS     = YES
-
-# If the HTML_DYNAMIC_SECTIONS tag is set to YES then the generated HTML
-# documentation will contain sections that can be hidden and shown after the
-# page has loaded.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_DYNAMIC_SECTIONS  = NO
-
-# With HTML_INDEX_NUM_ENTRIES one can control the preferred number of entries
-# shown in the various tree structured indices initially; the user can expand
-# and collapse entries dynamically later on. Doxygen will expand the tree to
-# such a level that at most the specified number of entries are visible (unless
-# a fully collapsed tree already exceeds this amount). So setting the number of
-# entries 1 will produce a full collapsed tree by default. 0 is a special value
-# representing an infinite number of entries and will result in a full expanded
-# tree by default.
-# Minimum value: 0, maximum value: 9999, default value: 100.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-HTML_INDEX_NUM_ENTRIES = 100
-
-# If the GENERATE_DOCSET tag is set to YES, additional index files will be
-# generated that can be used as input for Apple's Xcode 3 integrated development
-# environment (see: https://developer.apple.com/xcode/), introduced with OSX
-# 10.5 (Leopard). To create a documentation set, doxygen will generate a
-# Makefile in the HTML output directory. Running make will produce the docset in
-# that directory and running make install will install the docset in
-# ~/Library/Developer/Shared/Documentation/DocSets so that Xcode will find it at
-# startup. See https://developer.apple.com/library/archive/featuredarticles/Doxy
-# genXcode/_index.html for more information.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-GENERATE_DOCSET        = NO
-
-# This tag determines the name of the docset feed. A documentation feed provides
-# an umbrella under which multiple documentation sets from a single provider
-# (such as a company or product suite) can be grouped.
-# The default value is: Doxygen generated docs.
-# This tag requires that the tag GENERATE_DOCSET is set to YES.
-
-DOCSET_FEEDNAME        = "Doxygen generated docs"
-
-# This tag specifies a string that should uniquely identify the documentation
-# set bundle. This should be a reverse domain-name style string, e.g.
-# com.mycompany.MyDocSet. Doxygen will append .docset to the name.
-# The default value is: org.doxygen.Project.
-# This tag requires that the tag GENERATE_DOCSET is set to YES.
-
-DOCSET_BUNDLE_ID       = org.doxygen.Project
-
-# The DOCSET_PUBLISHER_ID tag specifies a string that should uniquely identify
-# the documentation publisher. This should be a reverse domain-name style
-# string, e.g. com.mycompany.MyDocSet.documentation.
-# The default value is: org.doxygen.Publisher.
-# This tag requires that the tag GENERATE_DOCSET is set to YES.
-
-DOCSET_PUBLISHER_ID    = org.doxygen.Publisher
-
-# The DOCSET_PUBLISHER_NAME tag identifies the documentation publisher.
-# The default value is: Publisher.
-# This tag requires that the tag GENERATE_DOCSET is set to YES.
-
-DOCSET_PUBLISHER_NAME  = Publisher
-
-# If the GENERATE_HTMLHELP tag is set to YES then doxygen generates three
-# additional HTML index files: index.hhp, index.hhc, and index.hhk. The
-# index.hhp is a project file that can be read by Microsoft's HTML Help Workshop
-# (see: https://www.microsoft.com/en-us/download/details.aspx?id=21138) on
-# Windows.
-#
-# The HTML Help Workshop contains a compiler that can convert all HTML output
-# generated by doxygen into a single compiled HTML file (.chm). Compiled HTML
-# files are now used as the Windows 98 help format, and will replace the old
-# Windows help format (.hlp) on all Windows platforms in the future. Compressed
-# HTML files also contain an index, a table of contents, and you can search for
-# words in the documentation. The HTML workshop also contains a viewer for
-# compressed HTML files.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-GENERATE_HTMLHELP      = NO
-
-# The CHM_FILE tag can be used to specify the file name of the resulting .chm
-# file. You can add a path in front of the file if the result should not be
-# written to the html output directory.
-# This tag requires that the tag GENERATE_HTMLHELP is set to YES.
-
-CHM_FILE               =
-
-# The HHC_LOCATION tag can be used to specify the location (absolute path
-# including file name) of the HTML help compiler (hhc.exe). If non-empty,
-# doxygen will try to run the HTML help compiler on the generated index.hhp.
-# The file has to be specified with full path.
-# This tag requires that the tag GENERATE_HTMLHELP is set to YES.
-
-HHC_LOCATION           =
-
-# The GENERATE_CHI flag controls if a separate .chi index file is generated
-# (YES) or that it should be included in the master .chm file (NO).
-# The default value is: NO.
-# This tag requires that the tag GENERATE_HTMLHELP is set to YES.
-
-GENERATE_CHI           = NO
-
-# The CHM_INDEX_ENCODING is used to encode HtmlHelp index (hhk), content (hhc)
-# and project file content.
-# This tag requires that the tag GENERATE_HTMLHELP is set to YES.
-
-CHM_INDEX_ENCODING     =
-
-# The BINARY_TOC flag controls whether a binary table of contents is generated
-# (YES) or a normal table of contents (NO) in the .chm file. Furthermore it
-# enables the Previous and Next buttons.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_HTMLHELP is set to YES.
-
-BINARY_TOC             = NO
-
-# The TOC_EXPAND flag can be set to YES to add extra items for group members to
-# the table of contents of the HTML help documentation and to the tree view.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_HTMLHELP is set to YES.
-
-TOC_EXPAND             = NO
-
-# If the GENERATE_QHP tag is set to YES and both QHP_NAMESPACE and
-# QHP_VIRTUAL_FOLDER are set, an additional index file will be generated that
-# can be used as input for Qt's qhelpgenerator to generate a Qt Compressed Help
-# (.qch) of the generated HTML documentation.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-GENERATE_QHP           = NO
-
-# If the QHG_LOCATION tag is specified, the QCH_FILE tag can be used to specify
-# the file name of the resulting .qch file. The path specified is relative to
-# the HTML output folder.
-# This tag requires that the tag GENERATE_QHP is set to YES.
-
-QCH_FILE               =
-
-# The QHP_NAMESPACE tag specifies the namespace to use when generating Qt Help
-# Project output. For more information please see Qt Help Project / Namespace
-# (see: http://doc.qt.io/archives/qt-4.8/qthelpproject.html#namespace).
-# The default value is: org.doxygen.Project.
-# This tag requires that the tag GENERATE_QHP is set to YES.
-
-QHP_NAMESPACE          = org.doxygen.Project
-
-# The QHP_VIRTUAL_FOLDER tag specifies the namespace to use when generating Qt
-# Help Project output. For more information please see Qt Help Project / Virtual
-# Folders (see: http://doc.qt.io/archives/qt-4.8/qthelpproject.html#virtual-
-# folders).
-# The default value is: doc.
-# This tag requires that the tag GENERATE_QHP is set to YES.
-
-QHP_VIRTUAL_FOLDER     = doc
-
-# If the QHP_CUST_FILTER_NAME tag is set, it specifies the name of a custom
-# filter to add. For more information please see Qt Help Project / Custom
-# Filters (see: http://doc.qt.io/archives/qt-4.8/qthelpproject.html#custom-
-# filters).
-# This tag requires that the tag GENERATE_QHP is set to YES.
-
-QHP_CUST_FILTER_NAME   =
-
-# The QHP_CUST_FILTER_ATTRS tag specifies the list of the attributes of the
-# custom filter to add. For more information please see Qt Help Project / Custom
-# Filters (see: http://doc.qt.io/archives/qt-4.8/qthelpproject.html#custom-
-# filters).
-# This tag requires that the tag GENERATE_QHP is set to YES.
-
-QHP_CUST_FILTER_ATTRS  =
-
-# The QHP_SECT_FILTER_ATTRS tag specifies the list of the attributes this
-# project's filter section matches. Qt Help Project / Filter Attributes (see:
-# http://doc.qt.io/archives/qt-4.8/qthelpproject.html#filter-attributes).
-# This tag requires that the tag GENERATE_QHP is set to YES.
-
-QHP_SECT_FILTER_ATTRS  =
-
-# The QHG_LOCATION tag can be used to specify the location of Qt's
-# qhelpgenerator. If non-empty doxygen will try to run qhelpgenerator on the
-# generated .qhp file.
-# This tag requires that the tag GENERATE_QHP is set to YES.
-
-QHG_LOCATION           =
-
-# If the GENERATE_ECLIPSEHELP tag is set to YES, additional index files will be
-# generated, together with the HTML files, they form an Eclipse help plugin. To
-# install this plugin and make it available under the help contents menu in
-# Eclipse, the contents of the directory containing the HTML and XML files needs
-# to be copied into the plugins directory of eclipse. The name of the directory
-# within the plugins directory should be the same as the ECLIPSE_DOC_ID value.
-# After copying Eclipse needs to be restarted before the help appears.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-GENERATE_ECLIPSEHELP   = NO
-
-# A unique identifier for the Eclipse help plugin. When installing the plugin
-# the directory name containing the HTML and XML files should also have this
-# name. Each documentation set should have its own identifier.
-# The default value is: org.doxygen.Project.
-# This tag requires that the tag GENERATE_ECLIPSEHELP is set to YES.
-
-ECLIPSE_DOC_ID         = org.doxygen.Project
-
-# If you want full control over the layout of the generated HTML pages it might
-# be necessary to disable the index and replace it with your own. The
-# DISABLE_INDEX tag can be used to turn on/off the condensed index (tabs) at top
-# of each HTML page. A value of NO enables the index and the value YES disables
-# it. Since the tabs in the index contain the same information as the navigation
-# tree, you can set this option to YES if you also set GENERATE_TREEVIEW to YES.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-DISABLE_INDEX          = NO
-
-# The GENERATE_TREEVIEW tag is used to specify whether a tree-like index
-# structure should be generated to display hierarchical information. If the tag
-# value is set to YES, a side panel will be generated containing a tree-like
-# index structure (just like the one that is generated for HTML Help). For this
-# to work a browser that supports JavaScript, DHTML, CSS and frames is required
-# (i.e. any modern browser). Windows users are probably better off using the
-# HTML help feature. Via custom style sheets (see HTML_EXTRA_STYLESHEET) one can
-# further fine-tune the look of the index. As an example, the default style
-# sheet generated by doxygen has an example that shows how to put an image at
-# the root of the tree instead of the PROJECT_NAME. Since the tree basically has
-# the same information as the tab index, you could consider setting
-# DISABLE_INDEX to YES when enabling this option.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-GENERATE_TREEVIEW      = NO
-
-# The ENUM_VALUES_PER_LINE tag can be used to set the number of enum values that
-# doxygen will group on one line in the generated HTML documentation.
-#
-# Note that a value of 0 will completely suppress the enum values from appearing
-# in the overview section.
-# Minimum value: 0, maximum value: 20, default value: 4.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-ENUM_VALUES_PER_LINE   = 4
-
-# If the treeview is enabled (see GENERATE_TREEVIEW) then this tag can be used
-# to set the initial width (in pixels) of the frame in which the tree is shown.
-# Minimum value: 0, maximum value: 1500, default value: 250.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-TREEVIEW_WIDTH         = 250
-
-# If the EXT_LINKS_IN_WINDOW option is set to YES, doxygen will open links to
-# external symbols imported via tag files in a separate window.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-EXT_LINKS_IN_WINDOW    = NO
-
-# Use this tag to change the font size of LaTeX formulas included as images in
-# the HTML documentation. When you change the font size after a successful
-# doxygen run you need to manually remove any form_*.png images from the HTML
-# output directory to force them to be regenerated.
-# Minimum value: 8, maximum value: 50, default value: 10.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-FORMULA_FONTSIZE       = 10
-
-# Use the FORMULA_TRANSPARENT tag to determine whether or not the images
-# generated for formulas are transparent PNGs. Transparent PNGs are not
-# supported properly for IE 6.0, but are supported on all modern browsers.
-#
-# Note that when changing this option you need to delete any form_*.png files in
-# the HTML output directory before the changes have effect.
-# The default value is: YES.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-FORMULA_TRANSPARENT    = YES
-
-# Enable the USE_MATHJAX option to render LaTeX formulas using MathJax (see
-# https://www.mathjax.org) which uses client side Javascript for the rendering
-# instead of using pre-rendered bitmaps. Use this if you do not have LaTeX
-# installed or if you want to formulas look prettier in the HTML output. When
-# enabled you may also need to install MathJax separately and configure the path
-# to it using the MATHJAX_RELPATH option.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-USE_MATHJAX            = NO
-
-# When MathJax is enabled you can set the default output format to be used for
-# the MathJax output. See the MathJax site (see:
-# http://docs.mathjax.org/en/latest/output.html) for more details.
-# Possible values are: HTML-CSS (which is slower, but has the best
-# compatibility), NativeMML (i.e. MathML) and SVG.
-# The default value is: HTML-CSS.
-# This tag requires that the tag USE_MATHJAX is set to YES.
-
-MATHJAX_FORMAT         = HTML-CSS
-
-# When MathJax is enabled you need to specify the location relative to the HTML
-# output directory using the MATHJAX_RELPATH option. The destination directory
-# should contain the MathJax.js script. For instance, if the mathjax directory
-# is located at the same level as the HTML output directory, then
-# MATHJAX_RELPATH should be ../mathjax. The default value points to the MathJax
-# Content Delivery Network so you can quickly see the result without installing
-# MathJax. However, it is strongly recommended to install a local copy of
-# MathJax from https://www.mathjax.org before deployment.
-# The default value is: https://cdnjs.cloudflare.com/ajax/libs/mathjax/2.7.5/.
-# This tag requires that the tag USE_MATHJAX is set to YES.
-
-MATHJAX_RELPATH        = https://cdnjs.cloudflare.com/ajax/libs/mathjax/2.7.5/
-
-# The MATHJAX_EXTENSIONS tag can be used to specify one or more MathJax
-# extension names that should be enabled during MathJax rendering. For example
-# MATHJAX_EXTENSIONS = TeX/AMSmath TeX/AMSsymbols
-# This tag requires that the tag USE_MATHJAX is set to YES.
-
-MATHJAX_EXTENSIONS     =
-
-# The MATHJAX_CODEFILE tag can be used to specify a file with javascript pieces
-# of code that will be used on startup of the MathJax code. See the MathJax site
-# (see: http://docs.mathjax.org/en/latest/output.html) for more details. For an
-# example see the documentation.
-# This tag requires that the tag USE_MATHJAX is set to YES.
-
-MATHJAX_CODEFILE       =
-
-# When the SEARCHENGINE tag is enabled doxygen will generate a search box for
-# the HTML output. The underlying search engine uses javascript and DHTML and
-# should work on any modern browser. Note that when using HTML help
-# (GENERATE_HTMLHELP), Qt help (GENERATE_QHP), or docsets (GENERATE_DOCSET)
-# there is already a search function so this one should typically be disabled.
-# For large projects the javascript based search engine can be slow, then
-# enabling SERVER_BASED_SEARCH may provide a better solution. It is possible to
-# search using the keyboard; to jump to the search box use <access key> + S
-# (what the <access key> is depends on the OS and browser, but it is typically
-# <CTRL>, <ALT>/<option>, or both). Inside the search box use the <cursor down
-# key> to jump into the search results window, the results can be navigated
-# using the <cursor keys>. Press <Enter> to select an item or <escape> to cancel
-# the search. The filter options can be selected when the cursor is inside the
-# search box by pressing <Shift>+<cursor down>. Also here use the <cursor keys>
-# to select a filter and <Enter> or <escape> to activate or cancel the filter
-# option.
-# The default value is: YES.
-# This tag requires that the tag GENERATE_HTML is set to YES.
-
-SEARCHENGINE           = YES
-
-# When the SERVER_BASED_SEARCH tag is enabled the search engine will be
-# implemented using a web server instead of a web client using Javascript. There
-# are two flavors of web server based searching depending on the EXTERNAL_SEARCH
-# setting. When disabled, doxygen will generate a PHP script for searching and
-# an index file used by the script. When EXTERNAL_SEARCH is enabled the indexing
-# and searching needs to be provided by external tools. See the section
-# "External Indexing and Searching" for details.
-# The default value is: NO.
-# This tag requires that the tag SEARCHENGINE is set to YES.
-
-SERVER_BASED_SEARCH    = NO
-
-# When EXTERNAL_SEARCH tag is enabled doxygen will no longer generate the PHP
-# script for searching. Instead the search results are written to an XML file
-# which needs to be processed by an external indexer. Doxygen will invoke an
-# external search engine pointed to by the SEARCHENGINE_URL option to obtain the
-# search results.
-#
-# Doxygen ships with an example indexer (doxyindexer) and search engine
-# (doxysearch.cgi) which are based on the open source search engine library
-# Xapian (see: https://xapian.org/).
-#
-# See the section "External Indexing and Searching" for details.
-# The default value is: NO.
-# This tag requires that the tag SEARCHENGINE is set to YES.
-
-EXTERNAL_SEARCH        = NO
-
-# The SEARCHENGINE_URL should point to a search engine hosted by a web server
-# which will return the search results when EXTERNAL_SEARCH is enabled.
-#
-# Doxygen ships with an example indexer (doxyindexer) and search engine
-# (doxysearch.cgi) which are based on the open source search engine library
-# Xapian (see: https://xapian.org/). See the section "External Indexing and
-# Searching" for details.
-# This tag requires that the tag SEARCHENGINE is set to YES.
-
-SEARCHENGINE_URL       =
-
-# When SERVER_BASED_SEARCH and EXTERNAL_SEARCH are both enabled the unindexed
-# search data is written to a file for indexing by an external tool. With the
-# SEARCHDATA_FILE tag the name of this file can be specified.
-# The default file is: searchdata.xml.
-# This tag requires that the tag SEARCHENGINE is set to YES.
-
-SEARCHDATA_FILE        = searchdata.xml
-
-# When SERVER_BASED_SEARCH and EXTERNAL_SEARCH are both enabled the
-# EXTERNAL_SEARCH_ID tag can be used as an identifier for the project. This is
-# useful in combination with EXTRA_SEARCH_MAPPINGS to search through multiple
-# projects and redirect the results back to the right project.
-# This tag requires that the tag SEARCHENGINE is set to YES.
-
-EXTERNAL_SEARCH_ID     =
-
-# The EXTRA_SEARCH_MAPPINGS tag can be used to enable searching through doxygen
-# projects other than the one defined by this configuration file, but that are
-# all added to the same external search index. Each project needs to have a
-# unique id set via EXTERNAL_SEARCH_ID. The search mapping then maps the id of
-# to a relative location where the documentation can be found. The format is:
-# EXTRA_SEARCH_MAPPINGS = tagname1=loc1 tagname2=loc2 ...
-# This tag requires that the tag SEARCHENGINE is set to YES.
-
-EXTRA_SEARCH_MAPPINGS  =
-
-#---------------------------------------------------------------------------
-# Configuration options related to the LaTeX output
-#---------------------------------------------------------------------------
-
-# If the GENERATE_LATEX tag is set to YES, doxygen will generate LaTeX output.
-# The default value is: YES.
-
-GENERATE_LATEX         = NO
-
-# The LATEX_OUTPUT tag is used to specify where the LaTeX docs will be put. If a
-# relative path is entered the value of OUTPUT_DIRECTORY will be put in front of
-# it.
-# The default directory is: latex.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-LATEX_OUTPUT           = latex
-
-# The LATEX_CMD_NAME tag can be used to specify the LaTeX command name to be
-# invoked.
-#
-# Note that when not enabling USE_PDFLATEX the default is latex when enabling
-# USE_PDFLATEX the default is pdflatex and when in the later case latex is
-# chosen this is overwritten by pdflatex. For specific output languages the
-# default can have been set differently, this depends on the implementation of
-# the output language.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-LATEX_CMD_NAME         =
-
-# The MAKEINDEX_CMD_NAME tag can be used to specify the command name to generate
-# index for LaTeX.
-# Note: This tag is used in the Makefile / make.bat.
-# See also: LATEX_MAKEINDEX_CMD for the part in the generated output file
-# (.tex).
-# The default file is: makeindex.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-MAKEINDEX_CMD_NAME     = makeindex
-
-# The LATEX_MAKEINDEX_CMD tag can be used to specify the command name to
-# generate index for LaTeX. In case there is no backslash (\) as first character
-# it will be automatically added in the LaTeX code.
-# Note: This tag is used in the generated output file (.tex).
-# See also: MAKEINDEX_CMD_NAME for the part in the Makefile / make.bat.
-# The default value is: makeindex.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-LATEX_MAKEINDEX_CMD    = makeindex
-
-# If the COMPACT_LATEX tag is set to YES, doxygen generates more compact LaTeX
-# documents. This may be useful for small projects and may help to save some
-# trees in general.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-COMPACT_LATEX          = NO
-
-# The PAPER_TYPE tag can be used to set the paper type that is used by the
-# printer.
-# Possible values are: a4 (210 x 297 mm), letter (8.5 x 11 inches), legal (8.5 x
-# 14 inches) and executive (7.25 x 10.5 inches).
-# The default value is: a4.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-PAPER_TYPE             = a4
-
-# The EXTRA_PACKAGES tag can be used to specify one or more LaTeX package names
-# that should be included in the LaTeX output. The package can be specified just
-# by its name or with the correct syntax as to be used with the LaTeX
-# \usepackage command. To get the times font for instance you can specify :
-# EXTRA_PACKAGES=times or EXTRA_PACKAGES={times}
-# To use the option intlimits with the amsmath package you can specify:
-# EXTRA_PACKAGES=[intlimits]{amsmath}
-# If left blank no extra packages will be included.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-EXTRA_PACKAGES         =
-
-# The LATEX_HEADER tag can be used to specify a personal LaTeX header for the
-# generated LaTeX document. The header should contain everything until the first
-# chapter. If it is left blank doxygen will generate a standard header. See
-# section "Doxygen usage" for information on how to let doxygen write the
-# default header to a separate file.
-#
-# Note: Only use a user-defined header if you know what you are doing! The
-# following commands have a special meaning inside the header: $title,
-# $datetime, $date, $doxygenversion, $projectname, $projectnumber,
-# $projectbrief, $projectlogo. Doxygen will replace $title with the empty
-# string, for the replacement values of the other commands the user is referred
-# to HTML_HEADER.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-LATEX_HEADER           =
-
-# The LATEX_FOOTER tag can be used to specify a personal LaTeX footer for the
-# generated LaTeX document. The footer should contain everything after the last
-# chapter. If it is left blank doxygen will generate a standard footer. See
-# LATEX_HEADER for more information on how to generate a default footer and what
-# special commands can be used inside the footer.
-#
-# Note: Only use a user-defined footer if you know what you are doing!
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-LATEX_FOOTER           =
-
-# The LATEX_EXTRA_STYLESHEET tag can be used to specify additional user-defined
-# LaTeX style sheets that are included after the standard style sheets created
-# by doxygen. Using this option one can overrule certain style aspects. Doxygen
-# will copy the style sheet files to the output directory.
-# Note: The order of the extra style sheet files is of importance (e.g. the last
-# style sheet in the list overrules the setting of the previous ones in the
-# list).
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-LATEX_EXTRA_STYLESHEET =
-
-# The LATEX_EXTRA_FILES tag can be used to specify one or more extra images or
-# other source files which should be copied to the LATEX_OUTPUT output
-# directory. Note that the files will be copied as-is; there are no commands or
-# markers available.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-LATEX_EXTRA_FILES      =
-
-# If the PDF_HYPERLINKS tag is set to YES, the LaTeX that is generated is
-# prepared for conversion to PDF (using ps2pdf or pdflatex). The PDF file will
-# contain links (just like the HTML output) instead of page references. This
-# makes the output suitable for online browsing using a PDF viewer.
-# The default value is: YES.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-PDF_HYPERLINKS         = YES
-
-# If the USE_PDFLATEX tag is set to YES, doxygen will use pdflatex to generate
-# the PDF file directly from the LaTeX files. Set this option to YES, to get a
-# higher quality PDF documentation.
-# The default value is: YES.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-USE_PDFLATEX           = YES
-
-# If the LATEX_BATCHMODE tag is set to YES, doxygen will add the \batchmode
-# command to the generated LaTeX files. This will instruct LaTeX to keep running
-# if errors occur, instead of asking the user for help. This option is also used
-# when generating formulas in HTML.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-LATEX_BATCHMODE        = NO
-
-# If the LATEX_HIDE_INDICES tag is set to YES then doxygen will not include the
-# index chapters (such as File Index, Compound Index, etc.) in the output.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-LATEX_HIDE_INDICES     = NO
-
-# If the LATEX_SOURCE_CODE tag is set to YES then doxygen will include source
-# code with syntax highlighting in the LaTeX output.
-#
-# Note that which sources are shown also depends on other settings such as
-# SOURCE_BROWSER.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-LATEX_SOURCE_CODE      = NO
-
-# The LATEX_BIB_STYLE tag can be used to specify the style to use for the
-# bibliography, e.g. plainnat, or ieeetr. See
-# https://en.wikipedia.org/wiki/BibTeX and \cite for more info.
-# The default value is: plain.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-LATEX_BIB_STYLE        = plain
-
-# If the LATEX_TIMESTAMP tag is set to YES then the footer of each generated
-# page will contain the date and time when the page was generated. Setting this
-# to NO can help when comparing the output of multiple runs.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-LATEX_TIMESTAMP        = NO
-
-# The LATEX_EMOJI_DIRECTORY tag is used to specify the (relative or absolute)
-# path from which the emoji images will be read. If a relative path is entered,
-# it will be relative to the LATEX_OUTPUT directory. If left blank the
-# LATEX_OUTPUT directory will be used.
-# This tag requires that the tag GENERATE_LATEX is set to YES.
-
-LATEX_EMOJI_DIRECTORY  =
-
-#---------------------------------------------------------------------------
-# Configuration options related to the RTF output
-#---------------------------------------------------------------------------
-
-# If the GENERATE_RTF tag is set to YES, doxygen will generate RTF output. The
-# RTF output is optimized for Word 97 and may not look too pretty with other RTF
-# readers/editors.
-# The default value is: NO.
-
-GENERATE_RTF           = NO
-
-# The RTF_OUTPUT tag is used to specify where the RTF docs will be put. If a
-# relative path is entered the value of OUTPUT_DIRECTORY will be put in front of
-# it.
-# The default directory is: rtf.
-# This tag requires that the tag GENERATE_RTF is set to YES.
-
-RTF_OUTPUT             = rtf
-
-# If the COMPACT_RTF tag is set to YES, doxygen generates more compact RTF
-# documents. This may be useful for small projects and may help to save some
-# trees in general.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_RTF is set to YES.
-
-COMPACT_RTF            = NO
-
-# If the RTF_HYPERLINKS tag is set to YES, the RTF that is generated will
-# contain hyperlink fields. The RTF file will contain links (just like the HTML
-# output) instead of page references. This makes the output suitable for online
-# browsing using Word or some other Word compatible readers that support those
-# fields.
-#
-# Note: WordPad (write) and others do not support links.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_RTF is set to YES.
-
-RTF_HYPERLINKS         = NO
-
-# Load stylesheet definitions from file. Syntax is similar to doxygen's
-# configuration file, i.e. a series of assignments. You only have to provide
-# replacements, missing definitions are set to their default value.
-#
-# See also section "Doxygen usage" for information on how to generate the
-# default style sheet that doxygen normally uses.
-# This tag requires that the tag GENERATE_RTF is set to YES.
-
-RTF_STYLESHEET_FILE    =
-
-# Set optional variables used in the generation of an RTF document. Syntax is
-# similar to doxygen's configuration file. A template extensions file can be
-# generated using doxygen -e rtf extensionFile.
-# This tag requires that the tag GENERATE_RTF is set to YES.
-
-RTF_EXTENSIONS_FILE    =
-
-# If the RTF_SOURCE_CODE tag is set to YES then doxygen will include source code
-# with syntax highlighting in the RTF output.
-#
-# Note that which sources are shown also depends on other settings such as
-# SOURCE_BROWSER.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_RTF is set to YES.
-
-RTF_SOURCE_CODE        = NO
-
-#---------------------------------------------------------------------------
-# Configuration options related to the man page output
-#---------------------------------------------------------------------------
-
-# If the GENERATE_MAN tag is set to YES, doxygen will generate man pages for
-# classes and files.
-# The default value is: NO.
-
-GENERATE_MAN           = NO
-
-# The MAN_OUTPUT tag is used to specify where the man pages will be put. If a
-# relative path is entered the value of OUTPUT_DIRECTORY will be put in front of
-# it. A directory man3 will be created inside the directory specified by
-# MAN_OUTPUT.
-# The default directory is: man.
-# This tag requires that the tag GENERATE_MAN is set to YES.
-
-MAN_OUTPUT             = man
-
-# The MAN_EXTENSION tag determines the extension that is added to the generated
-# man pages. In case the manual section does not start with a number, the number
-# 3 is prepended. The dot (.) at the beginning of the MAN_EXTENSION tag is
-# optional.
-# The default value is: .3.
-# This tag requires that the tag GENERATE_MAN is set to YES.
-
-MAN_EXTENSION          = .3
-
-# The MAN_SUBDIR tag determines the name of the directory created within
-# MAN_OUTPUT in which the man pages are placed. If defaults to man followed by
-# MAN_EXTENSION with the initial . removed.
-# This tag requires that the tag GENERATE_MAN is set to YES.
-
-MAN_SUBDIR             =
-
-# If the MAN_LINKS tag is set to YES and doxygen generates man output, then it
-# will generate one additional man file for each entity documented in the real
-# man page(s). These additional files only source the real man page, but without
-# them the man command would be unable to find the correct page.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_MAN is set to YES.
-
-MAN_LINKS              = NO
-
-#---------------------------------------------------------------------------
-# Configuration options related to the XML output
-#---------------------------------------------------------------------------
-
-# If the GENERATE_XML tag is set to YES, doxygen will generate an XML file that
-# captures the structure of the code including all documentation.
-# The default value is: NO.
-
-GENERATE_XML           = NO
-
-# The XML_OUTPUT tag is used to specify where the XML pages will be put. If a
-# relative path is entered the value of OUTPUT_DIRECTORY will be put in front of
-# it.
-# The default directory is: xml.
-# This tag requires that the tag GENERATE_XML is set to YES.
-
-XML_OUTPUT             = xml
-
-# If the XML_PROGRAMLISTING tag is set to YES, doxygen will dump the program
-# listings (including syntax highlighting and cross-referencing information) to
-# the XML output. Note that enabling this will significantly increase the size
-# of the XML output.
-# The default value is: YES.
-# This tag requires that the tag GENERATE_XML is set to YES.
-
-XML_PROGRAMLISTING     = YES
-
-# If the XML_NS_MEMB_FILE_SCOPE tag is set to YES, doxygen will include
-# namespace members in file scope as well, matching the HTML output.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_XML is set to YES.
-
-XML_NS_MEMB_FILE_SCOPE = NO
-
-#---------------------------------------------------------------------------
-# Configuration options related to the DOCBOOK output
-#---------------------------------------------------------------------------
-
-# If the GENERATE_DOCBOOK tag is set to YES, doxygen will generate Docbook files
-# that can be used to generate PDF.
-# The default value is: NO.
-
-GENERATE_DOCBOOK       = NO
-
-# The DOCBOOK_OUTPUT tag is used to specify where the Docbook pages will be put.
-# If a relative path is entered the value of OUTPUT_DIRECTORY will be put in
-# front of it.
-# The default directory is: docbook.
-# This tag requires that the tag GENERATE_DOCBOOK is set to YES.
-
-DOCBOOK_OUTPUT         = docbook
-
-# If the DOCBOOK_PROGRAMLISTING tag is set to YES, doxygen will include the
-# program listings (including syntax highlighting and cross-referencing
-# information) to the DOCBOOK output. Note that enabling this will significantly
-# increase the size of the DOCBOOK output.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_DOCBOOK is set to YES.
-
-DOCBOOK_PROGRAMLISTING = NO
-
-#---------------------------------------------------------------------------
-# Configuration options for the AutoGen Definitions output
-#---------------------------------------------------------------------------
-
-# If the GENERATE_AUTOGEN_DEF tag is set to YES, doxygen will generate an
-# AutoGen Definitions (see http://autogen.sourceforge.net/) file that captures
-# the structure of the code including all documentation. Note that this feature
-# is still experimental and incomplete at the moment.
-# The default value is: NO.
-
-GENERATE_AUTOGEN_DEF   = NO
-
-#---------------------------------------------------------------------------
-# Configuration options related to the Perl module output
-#---------------------------------------------------------------------------
-
-# If the GENERATE_PERLMOD tag is set to YES, doxygen will generate a Perl module
-# file that captures the structure of the code including all documentation.
-#
-# Note that this feature is still experimental and incomplete at the moment.
-# The default value is: NO.
-
-GENERATE_PERLMOD       = NO
-
-# If the PERLMOD_LATEX tag is set to YES, doxygen will generate the necessary
-# Makefile rules, Perl scripts and LaTeX code to be able to generate PDF and DVI
-# output from the Perl module output.
-# The default value is: NO.
-# This tag requires that the tag GENERATE_PERLMOD is set to YES.
-
-PERLMOD_LATEX          = NO
-
-# If the PERLMOD_PRETTY tag is set to YES, the Perl module output will be nicely
-# formatted so it can be parsed by a human reader. This is useful if you want to
-# understand what is going on. On the other hand, if this tag is set to NO, the
-# size of the Perl module output will be much smaller and Perl will parse it
-# just the same.
-# The default value is: YES.
-# This tag requires that the tag GENERATE_PERLMOD is set to YES.
-
-PERLMOD_PRETTY         = YES
-
-# The names of the make variables in the generated doxyrules.make file are
-# prefixed with the string contained in PERLMOD_MAKEVAR_PREFIX. This is useful
-# so different doxyrules.make files included by the same Makefile don't
-# overwrite each other's variables.
-# This tag requires that the tag GENERATE_PERLMOD is set to YES.
-
-PERLMOD_MAKEVAR_PREFIX =
-
-#---------------------------------------------------------------------------
-# Configuration options related to the preprocessor
-#---------------------------------------------------------------------------
-
-# If the ENABLE_PREPROCESSING tag is set to YES, doxygen will evaluate all
-# C-preprocessor directives found in the sources and include files.
-# The default value is: YES.
-
-ENABLE_PREPROCESSING   = YES
-
-# If the MACRO_EXPANSION tag is set to YES, doxygen will expand all macro names
-# in the source code. If set to NO, only conditional compilation will be
-# performed. Macro expansion can be done in a controlled way by setting
-# EXPAND_ONLY_PREDEF to YES.
-# The default value is: NO.
-# This tag requires that the tag ENABLE_PREPROCESSING is set to YES.
-
-MACRO_EXPANSION        = NO
-
-# If the EXPAND_ONLY_PREDEF and MACRO_EXPANSION tags are both set to YES then
-# the macro expansion is limited to the macros specified with the PREDEFINED and
-# EXPAND_AS_DEFINED tags.
-# The default value is: NO.
-# This tag requires that the tag ENABLE_PREPROCESSING is set to YES.
-
-EXPAND_ONLY_PREDEF     = NO
-
-# If the SEARCH_INCLUDES tag is set to YES, the include files in the
-# INCLUDE_PATH will be searched if a #include is found.
-# The default value is: YES.
-# This tag requires that the tag ENABLE_PREPROCESSING is set to YES.
-
-SEARCH_INCLUDES        = YES
-
-# The INCLUDE_PATH tag can be used to specify one or more directories that
-# contain include files that are not input files but should be processed by the
-# preprocessor.
-# This tag requires that the tag SEARCH_INCLUDES is set to YES.
-
-INCLUDE_PATH           =
-
-# You can use the INCLUDE_FILE_PATTERNS tag to specify one or more wildcard
-# patterns (like *.h and *.hpp) to filter out the header-files in the
-# directories. If left blank, the patterns specified with FILE_PATTERNS will be
-# used.
-# This tag requires that the tag ENABLE_PREPROCESSING is set to YES.
-
-INCLUDE_FILE_PATTERNS  =
-
-# The PREDEFINED tag can be used to specify one or more macro names that are
-# defined before the preprocessor is started (similar to the -D option of e.g.
-# gcc). The argument of the tag is a list of macros of the form: name or
-# name=definition (no spaces). If the definition and the "=" are omitted, "=1"
-# is assumed. To prevent a macro definition from being undefined via #undef or
-# recursively expanded use the := operator instead of the = operator.
-# This tag requires that the tag ENABLE_PREPROCESSING is set to YES.
-
-PREDEFINED             =
-
-# If the MACRO_EXPANSION and EXPAND_ONLY_PREDEF tags are set to YES then this
-# tag can be used to specify a list of macro names that should be expanded. The
-# macro definition that is found in the sources will be used. Use the PREDEFINED
-# tag if you want to use a different macro definition that overrules the
-# definition found in the source code.
-# This tag requires that the tag ENABLE_PREPROCESSING is set to YES.
-
-EXPAND_AS_DEFINED      =
-
-# If the SKIP_FUNCTION_MACROS tag is set to YES then doxygen's preprocessor will
-# remove all references to function-like macros that are alone on a line, have
-# an all uppercase name, and do not end with a semicolon. Such function macros
-# are typically used for boiler-plate code, and will confuse the parser if not
-# removed.
-# The default value is: YES.
-# This tag requires that the tag ENABLE_PREPROCESSING is set to YES.
-
-SKIP_FUNCTION_MACROS   = YES
-
-#---------------------------------------------------------------------------
-# Configuration options related to external references
-#---------------------------------------------------------------------------
-
-# The TAGFILES tag can be used to specify one or more tag files. For each tag
-# file the location of the external documentation should be added. The format of
-# a tag file without this location is as follows:
-# TAGFILES = file1 file2 ...
-# Adding location for the tag files is done as follows:
-# TAGFILES = file1=loc1 "file2 = loc2" ...
-# where loc1 and loc2 can be relative or absolute paths or URLs. See the
-# section "Linking to external documentation" for more information about the use
-# of tag files.
-# Note: Each tag file must have a unique name (where the name does NOT include
-# the path). If a tag file is not located in the directory in which doxygen is
-# run, you must also specify the path to the tagfile here.
-
-TAGFILES               =
-
-# When a file name is specified after GENERATE_TAGFILE, doxygen will create a
-# tag file that is based on the input files it reads. See section "Linking to
-# external documentation" for more information about the usage of tag files.
-
-GENERATE_TAGFILE       =
-
-# If the ALLEXTERNALS tag is set to YES, all external class will be listed in
-# the class index. If set to NO, only the inherited external classes will be
-# listed.
-# The default value is: NO.
-
-ALLEXTERNALS           = NO
-
-# If the EXTERNAL_GROUPS tag is set to YES, all external groups will be listed
-# in the modules index. If set to NO, only the current project's groups will be
-# listed.
-# The default value is: YES.
-
-EXTERNAL_GROUPS        = YES
-
-# If the EXTERNAL_PAGES tag is set to YES, all external pages will be listed in
-# the related pages index. If set to NO, only the current project's pages will
-# be listed.
-# The default value is: YES.
-
-EXTERNAL_PAGES         = YES
-
-# The PERL_PATH should be the absolute path and name of the perl script
-# interpreter (i.e. the result of 'which perl').
-# The default file (with absolute path) is: /usr/bin/perl.
-
-PERL_PATH              = /usr/bin/perl
-
-#---------------------------------------------------------------------------
-# Configuration options related to the dot tool
-#---------------------------------------------------------------------------
-
-# If the CLASS_DIAGRAMS tag is set to YES, doxygen will generate a class diagram
-# (in HTML and LaTeX) for classes with base or super classes. Setting the tag to
-# NO turns the diagrams off. Note that this option also works with HAVE_DOT
-# disabled, but it is recommended to install and use dot, since it yields more
-# powerful graphs.
-# The default value is: YES.
-
-CLASS_DIAGRAMS         = YES
-
-# You can define message sequence charts within doxygen comments using the \msc
-# command. Doxygen will then run the mscgen tool (see:
-# http://www.mcternan.me.uk/mscgen/)) to produce the chart and insert it in the
-# documentation. The MSCGEN_PATH tag allows you to specify the directory where
-# the mscgen tool resides. If left empty the tool is assumed to be found in the
-# default search path.
-
-MSCGEN_PATH            =
-
-# You can include diagrams made with dia in doxygen documentation. Doxygen will
-# then run dia to produce the diagram and insert it in the documentation. The
-# DIA_PATH tag allows you to specify the directory where the dia binary resides.
-# If left empty dia is assumed to be found in the default search path.
-
-DIA_PATH               =
-
-# If set to YES the inheritance and collaboration graphs will hide inheritance
-# and usage relations if the target is undocumented or is not a class.
-# The default value is: YES.
-
-HIDE_UNDOC_RELATIONS   = YES
-
-# If you set the HAVE_DOT tag to YES then doxygen will assume the dot tool is
-# available from the path. This tool is part of Graphviz (see:
-# http://www.graphviz.org/), a graph visualization toolkit from AT&T and Lucent
-# Bell Labs. The other options in this section have no effect if this option is
-# set to NO
-# The default value is: NO.
-
-HAVE_DOT               = NO
-
-# The DOT_NUM_THREADS specifies the number of dot invocations doxygen is allowed
-# to run in parallel. When set to 0 doxygen will base this on the number of
-# processors available in the system. You can set it explicitly to a value
-# larger than 0 to get control over the balance between CPU load and processing
-# speed.
-# Minimum value: 0, maximum value: 32, default value: 0.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-DOT_NUM_THREADS        = 0
-
-# When you want a differently looking font in the dot files that doxygen
-# generates you can specify the font name using DOT_FONTNAME. You need to make
-# sure dot is able to find the font, which can be done by putting it in a
-# standard location or by setting the DOTFONTPATH environment variable or by
-# setting DOT_FONTPATH to the directory containing the font.
-# The default value is: Helvetica.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-DOT_FONTNAME           = Helvetica
-
-# The DOT_FONTSIZE tag can be used to set the size (in points) of the font of
-# dot graphs.
-# Minimum value: 4, maximum value: 24, default value: 10.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-DOT_FONTSIZE           = 10
-
-# By default doxygen will tell dot to use the default font as specified with
-# DOT_FONTNAME. If you specify a different font using DOT_FONTNAME you can set
-# the path where dot can find it using this tag.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-DOT_FONTPATH           =
-
-# If the CLASS_GRAPH tag is set to YES then doxygen will generate a graph for
-# each documented class showing the direct and indirect inheritance relations.
-# Setting this tag to YES will force the CLASS_DIAGRAMS tag to NO.
-# The default value is: YES.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-CLASS_GRAPH            = YES
-
-# If the COLLABORATION_GRAPH tag is set to YES then doxygen will generate a
-# graph for each documented class showing the direct and indirect implementation
-# dependencies (inheritance, containment, and class references variables) of the
-# class with other documented classes.
-# The default value is: YES.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-COLLABORATION_GRAPH    = YES
-
-# If the GROUP_GRAPHS tag is set to YES then doxygen will generate a graph for
-# groups, showing the direct groups dependencies.
-# The default value is: YES.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-GROUP_GRAPHS           = YES
-
-# If the UML_LOOK tag is set to YES, doxygen will generate inheritance and
-# collaboration diagrams in a style similar to the OMG's Unified Modeling
-# Language.
-# The default value is: NO.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-UML_LOOK               = NO
-
-# If the UML_LOOK tag is enabled, the fields and methods are shown inside the
-# class node. If there are many fields or methods and many nodes the graph may
-# become too big to be useful. The UML_LIMIT_NUM_FIELDS threshold limits the
-# number of items for each type to make the size more manageable. Set this to 0
-# for no limit. Note that the threshold may be exceeded by 50% before the limit
-# is enforced. So when you set the threshold to 10, up to 15 fields may appear,
-# but if the number exceeds 15, the total amount of fields shown is limited to
-# 10.
-# Minimum value: 0, maximum value: 100, default value: 10.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-UML_LIMIT_NUM_FIELDS   = 10
-
-# If the TEMPLATE_RELATIONS tag is set to YES then the inheritance and
-# collaboration graphs will show the relations between templates and their
-# instances.
-# The default value is: NO.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-TEMPLATE_RELATIONS     = NO
-
-# If the INCLUDE_GRAPH, ENABLE_PREPROCESSING and SEARCH_INCLUDES tags are set to
-# YES then doxygen will generate a graph for each documented file showing the
-# direct and indirect include dependencies of the file with other documented
-# files.
-# The default value is: YES.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-INCLUDE_GRAPH          = YES
-
-# If the INCLUDED_BY_GRAPH, ENABLE_PREPROCESSING and SEARCH_INCLUDES tags are
-# set to YES then doxygen will generate a graph for each documented file showing
-# the direct and indirect include dependencies of the file with other documented
-# files.
-# The default value is: YES.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-INCLUDED_BY_GRAPH      = YES
-
-# If the CALL_GRAPH tag is set to YES then doxygen will generate a call
-# dependency graph for every global function or class method.
-#
-# Note that enabling this option will significantly increase the time of a run.
-# So in most cases it will be better to enable call graphs for selected
-# functions only using the \callgraph command. Disabling a call graph can be
-# accomplished by means of the command \hidecallgraph.
-# The default value is: NO.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-CALL_GRAPH             = NO
-
-# If the CALLER_GRAPH tag is set to YES then doxygen will generate a caller
-# dependency graph for every global function or class method.
-#
-# Note that enabling this option will significantly increase the time of a run.
-# So in most cases it will be better to enable caller graphs for selected
-# functions only using the \callergraph command. Disabling a caller graph can be
-# accomplished by means of the command \hidecallergraph.
-# The default value is: NO.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-CALLER_GRAPH           = NO
-
-# If the GRAPHICAL_HIERARCHY tag is set to YES then doxygen will graphical
-# hierarchy of all classes instead of a textual one.
-# The default value is: YES.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-GRAPHICAL_HIERARCHY    = YES
-
-# If the DIRECTORY_GRAPH tag is set to YES then doxygen will show the
-# dependencies a directory has on other directories in a graphical way. The
-# dependency relations are determined by the #include relations between the
-# files in the directories.
-# The default value is: YES.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-DIRECTORY_GRAPH        = YES
-
-# The DOT_IMAGE_FORMAT tag can be used to set the image format of the images
-# generated by dot. For an explanation of the image formats see the section
-# output formats in the documentation of the dot tool (Graphviz (see:
-# http://www.graphviz.org/)).
-# Note: If you choose svg you need to set HTML_FILE_EXTENSION to xhtml in order
-# to make the SVG files visible in IE 9+ (other browsers do not have this
-# requirement).
-# Possible values are: png, jpg, gif, svg, png:gd, png:gd:gd, png:cairo,
-# png:cairo:gd, png:cairo:cairo, png:cairo:gdiplus, png:gdiplus and
-# png:gdiplus:gdiplus.
-# The default value is: png.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-DOT_IMAGE_FORMAT       = png
-
-# If DOT_IMAGE_FORMAT is set to svg, then this option can be set to YES to
-# enable generation of interactive SVG images that allow zooming and panning.
-#
-# Note that this requires a modern browser other than Internet Explorer. Tested
-# and working are Firefox, Chrome, Safari, and Opera.
-# Note: For IE 9+ you need to set HTML_FILE_EXTENSION to xhtml in order to make
-# the SVG files visible. Older versions of IE do not have SVG support.
-# The default value is: NO.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-INTERACTIVE_SVG        = NO
-
-# The DOT_PATH tag can be used to specify the path where the dot tool can be
-# found. If left blank, it is assumed the dot tool can be found in the path.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-DOT_PATH               =
-
-# The DOTFILE_DIRS tag can be used to specify one or more directories that
-# contain dot files that are included in the documentation (see the \dotfile
-# command).
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-DOTFILE_DIRS           =
-
-# The MSCFILE_DIRS tag can be used to specify one or more directories that
-# contain msc files that are included in the documentation (see the \mscfile
-# command).
-
-MSCFILE_DIRS           =
-
-# The DIAFILE_DIRS tag can be used to specify one or more directories that
-# contain dia files that are included in the documentation (see the \diafile
-# command).
-
-DIAFILE_DIRS           =
-
-# When using plantuml, the PLANTUML_JAR_PATH tag should be used to specify the
-# path where java can find the plantuml.jar file. If left blank, it is assumed
-# PlantUML is not used or called during a preprocessing step. Doxygen will
-# generate a warning when it encounters a \startuml command in this case and
-# will not generate output for the diagram.
-
-PLANTUML_JAR_PATH      =
-
-# When using plantuml, the PLANTUML_CFG_FILE tag can be used to specify a
-# configuration file for plantuml.
-
-PLANTUML_CFG_FILE      =
-
-# When using plantuml, the specified paths are searched for files specified by
-# the !include statement in a plantuml block.
-
-PLANTUML_INCLUDE_PATH  =
-
-# The DOT_GRAPH_MAX_NODES tag can be used to set the maximum number of nodes
-# that will be shown in the graph. If the number of nodes in a graph becomes
-# larger than this value, doxygen will truncate the graph, which is visualized
-# by representing a node as a red box. Note that doxygen if the number of direct
-# children of the root node in a graph is already larger than
-# DOT_GRAPH_MAX_NODES then the graph will not be shown at all. Also note that
-# the size of a graph can be further restricted by MAX_DOT_GRAPH_DEPTH.
-# Minimum value: 0, maximum value: 10000, default value: 50.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-DOT_GRAPH_MAX_NODES    = 50
-
-# The MAX_DOT_GRAPH_DEPTH tag can be used to set the maximum depth of the graphs
-# generated by dot. A depth value of 3 means that only nodes reachable from the
-# root by following a path via at most 3 edges will be shown. Nodes that lay
-# further from the root node will be omitted. Note that setting this option to 1
-# or 2 may greatly reduce the computation time needed for large code bases. Also
-# note that the size of a graph can be further restricted by
-# DOT_GRAPH_MAX_NODES. Using a depth of 0 means no depth restriction.
-# Minimum value: 0, maximum value: 1000, default value: 0.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-MAX_DOT_GRAPH_DEPTH    = 0
-
-# Set the DOT_TRANSPARENT tag to YES to generate images with a transparent
-# background. This is disabled by default, because dot on Windows does not seem
-# to support this out of the box.
-#
-# Warning: Depending on the platform used, enabling this option may lead to
-# badly anti-aliased labels on the edges of a graph (i.e. they become hard to
-# read).
-# The default value is: NO.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-DOT_TRANSPARENT        = NO
-
-# Set the DOT_MULTI_TARGETS tag to YES to allow dot to generate multiple output
-# files in one run (i.e. multiple -o and -T options on the command line). This
-# makes dot run faster, but since only newer versions of dot (>1.8.10) support
-# this, this feature is disabled by default.
-# The default value is: NO.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-DOT_MULTI_TARGETS      = NO
-
-# If the GENERATE_LEGEND tag is set to YES doxygen will generate a legend page
-# explaining the meaning of the various boxes and arrows in the dot generated
-# graphs.
-# The default value is: YES.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-GENERATE_LEGEND        = YES
-
-# If the DOT_CLEANUP tag is set to YES, doxygen will remove the intermediate dot
-# files that are used to generate the various graphs.
-# The default value is: YES.
-# This tag requires that the tag HAVE_DOT is set to YES.
-
-DOT_CLEANUP            = YES
diff --git a/third_party/Simple-web-server/repo/docs/benchmarks.md b/third_party/Simple-web-server/repo/docs/benchmarks.md
deleted file mode 100644
index 746a0a93..00000000
--- a/third_party/Simple-web-server/repo/docs/benchmarks.md
+++ /dev/null
@@ -1,210 +0,0 @@
-# Benchmarks
-
-A simple benchmark of Simple-Web-Server and a few similar web libraries.
-
-Details:
-* Linux distribution: Debian Testing (2019-07-29)
-* Linux kernel: 4.19.0-1-amd64
-* CPU: Intel(R) Core(TM) i7-2600 CPU @ 3.40GHz
-* CPU cores: 4
-* The HTTP load generator [httperf](https://github.com/httperf/httperf) is used
-to create the benchmark results, with the following arguments:
-```sh
-httperf --server=localhost --port=3000 --uri=/ --num-conns=20000 --num-calls=200
-```
-
-The response messages were made identical.
-
-## Express
-
-[Express](https://expressjs.com/) is a popular Node.js web framework.
-
-Versions:
-* Node: v10.15.2
-* Express: 4.17.1
-
-Code:
-```js
-const express = require('express');
-const app = express();
-
-app.get('/', (req, res) => {
-  res.removeHeader('X-Powered-By');
-  res.removeHeader('Connection');
-  res.end('Hello World!')
-});
-
-const port = 3000;
-app.listen(port, () => console.log(`Example app listening on port ${port}!`));
-```
-
-Execution:
-```sh
-NODE_ENV=production node index.js
-```
-
-Example results (13659.7 req/s):
-```sh
-httperf --client=0/1 --server=localhost --port=3000 --uri=/ --send-buffer=4096 --recv-buffer=16384 --num-conns=20000 --num-calls=200
-httperf: warning: open file limit > FD_SETSIZE; limiting max. # of open files to FD_SETSIZE
-Maximum connect burst length: 1
-
-Total: connections 20000 requests 40000 replies 20000 test-duration 2.928 s
-
-Connection rate: 6829.9 conn/s (0.1 ms/conn, <=1 concurrent connections)
-Connection time [ms]: min 0.1 avg 0.1 max 14.8 median 0.5 stddev 0.1
-Connection time [ms]: connect 0.0
-Connection length [replies/conn]: 1.000
-
-Request rate: 13659.7 req/s (0.1 ms/req)
-Request size [B]: 62.0
-
-Reply rate [replies/s]: min 0.0 avg 0.0 max 0.0 stddev 0.0 (0 samples)
-Reply time [ms]: response 0.1 transfer 0.0
-Reply size [B]: header 76.0 content 12.0 footer 0.0 (total 88.0)
-Reply status: 1xx=0 2xx=20000 3xx=0 4xx=0 5xx=0
-
-CPU time [s]: user 0.66 system 2.27 (user 22.4% system 77.5% total 99.9%)
-Net I/O: 1414.0 KB/s (11.6*10^6 bps)
-
-Errors: total 20000 client-timo 0 socket-timo 0 connrefused 0 connreset 20000
-Errors: fd-unavail 0 addrunavail 0 ftab-full 0 other 0
-```
-
-## Hyper
-
-[Hyper](https://hyper.rs/) is a Rust HTTP library that topped the
-[TechEmpower Web Framework Benchmarks results](https://www.techempower.com/benchmarks/#section=data-r18&hw=ph&test=plaintext) in 2019-07-09.
-
-Versions:
-* rustc: 1.38.0-nightly
-* hyper: 0.12
-
-Code (copied from
-https://github.com/hyperium/hyper/blob/0.12.x/examples/hello.rs, but removed `pretty_env_logger`
-calls due to compilation issues):
-```rust
-#![deny(warnings)]
-extern crate hyper;
-// extern crate pretty_env_logger;
-
-use hyper::{Body, Request, Response, Server};
-use hyper::service::service_fn_ok;
-use hyper::rt::{self, Future};
-
-fn main() {
-    // pretty_env_logger::init();
-    let addr = ([127, 0, 0, 1], 3000).into();
-
-    let server = Server::bind(&addr)
-        .serve(|| {
-            // This is the `Service` that will handle the connection.
-            // `service_fn_ok` is a helper to convert a function that
-            // returns a Response into a `Service`.
-            service_fn_ok(move |_: Request<Body>| {
-                Response::new(Body::from("Hello World!"))
-            })
-        })
-        .map_err(|e| eprintln!("server error: {}", e));
-
-    println!("Listening on http://{}", addr);
-
-    rt::run(server);
-}
-```
-
-Compilation and run:
-```sh
-cargo run --release
-```
-
-Example results (60712.3 req/s):
-```sh
-httperf --client=0/1 --server=localhost --port=3000 --uri=/ --send-buffer=4096 --recv-buffer=16384 --num-conns=20000 --num-calls=200
-httperf: warning: open file limit > FD_SETSIZE; limiting max. # of open files to FD_SETSIZE
-Maximum connect burst length: 1
-
-Total: connections 20000 requests 4000000 replies 4000000 test-duration 65.884 s
-
-Connection rate: 303.6 conn/s (3.3 ms/conn, <=1 concurrent connections)
-Connection time [ms]: min 3.0 avg 3.3 max 11.3 median 3.5 stddev 0.3
-Connection time [ms]: connect 0.0
-Connection length [replies/conn]: 200.000
-
-Request rate: 60712.3 req/s (0.0 ms/req)
-Request size [B]: 62.0
-
-Reply rate [replies/s]: min 58704.0 avg 60732.7 max 62587.7 stddev 1021.7 (13 samples)
-Reply time [ms]: response 0.0 transfer 0.0
-Reply size [B]: header 76.0 content 12.0 footer 0.0 (total 88.0)
-Reply status: 1xx=0 2xx=4000000 3xx=0 4xx=0 5xx=0
-
-CPU time [s]: user 15.91 system 49.97 (user 24.1% system 75.8% total 100.0%)
-Net I/O: 8893.4 KB/s (72.9*10^6 bps)
-
-Errors: total 0 client-timo 0 socket-timo 0 connrefused 0 connreset 0
-Errors: fd-unavail 0 addrunavail 0 ftab-full 0 other 0
-```
-
-## Simple-Web-Server
-
-In these simplistic tests, the performance of Simple-Web-Server is similar to
-the Hyper Rust HTTP library, although Hyper seems to be slightly faster more
-often than not.
-
-Versions:
-* g++: 9.1.0
-
-Code (modified `http_examples.cpp`):
-```c++
-#include "server_http.hpp"
-
-using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
-
-int main() {
-  HttpServer server;
-  server.config.port = 3000;
-
-  server.default_resource["GET"] = [](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> /*request*/) {
-    response->write("Hello World!", {{"Date", SimpleWeb::Date::to_string(std::chrono::system_clock::now())}});
-  };
-
-  server.start();
-}
-```
-
-Build, compilation and run:
-```sh
-mkdir build && cd build
-CXX=g++-9 CXXFLAGS="-O2 -DNDEBUG -flto" cmake ..
-make
-./http_examples
-```
-
-Example results (60596.3 req/s):
-```sh
-httperf --client=0/1 --server=localhost --port=3000 --uri=/ --send-buffer=4096 --recv-buffer=16384 --num-conns=20000 --num-calls=200
-httperf: warning: open file limit > FD_SETSIZE; limiting max. # of open files to FD_SETSIZE
-Maximum connect burst length: 1
-
-Total: connections 20000 requests 4000000 replies 4000000 test-duration 66.011 s
-
-Connection rate: 303.0 conn/s (3.3 ms/conn, <=1 concurrent connections)
-Connection time [ms]: min 3.2 avg 3.3 max 8.0 median 3.5 stddev 0.0
-Connection time [ms]: connect 0.0
-Connection length [replies/conn]: 200.000
-
-Request rate: 60596.3 req/s (0.0 ms/req)
-Request size [B]: 62.0
-
-Reply rate [replies/s]: min 60399.6 avg 60596.9 max 60803.8 stddev 130.9 (13 samples)
-Reply time [ms]: response 0.0 transfer 0.0
-Reply size [B]: header 76.0 content 12.0 footer 0.0 (total 88.0)
-Reply status: 1xx=0 2xx=4000000 3xx=0 4xx=0 5xx=0
-
-CPU time [s]: user 16.07 system 49.93 (user 24.3% system 75.6% total 100.0%)
-Net I/O: 8876.4 KB/s (72.7*10^6 bps)
-
-Errors: total 0 client-timo 0 socket-timo 0 connrefused 0 connreset 0
-Errors: fd-unavail 0 addrunavail 0 ftab-full 0 other 0
-```
diff --git a/third_party/Simple-web-server/repo/http_examples.cpp b/third_party/Simple-web-server/repo/http_examples.cpp
deleted file mode 100644
index 847f1bbd..00000000
--- a/third_party/Simple-web-server/repo/http_examples.cpp
+++ /dev/null
@@ -1,254 +0,0 @@
-#include "client_http.hpp"
-#include "server_http.hpp"
-#include <future>
-
-// Added for the json-example
-#define BOOST_SPIRIT_THREADSAFE
-#include <boost/property_tree/json_parser.hpp>
-#include <boost/property_tree/ptree.hpp>
-
-// Added for the default_resource example
-#include <algorithm>
-#include <boost/filesystem.hpp>
-#include <fstream>
-#include <vector>
-#ifdef HAVE_OPENSSL
-#include "crypto.hpp"
-#endif
-
-using namespace std;
-// Added for the json-example:
-using namespace boost::property_tree;
-
-using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
-using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;
-
-int main() {
-  // HTTP-server at port 8080 using 1 thread
-  // Unless you do more heavy non-threaded processing in the resources,
-  // 1 thread is usually faster than several threads
-  HttpServer server;
-  server.config.port = 8080;
-
-  // Add resources using path-regex and method-string, and an anonymous function
-  // POST-example for the path /string, responds the posted string
-  server.resource["^/string$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    // Retrieve string:
-    auto content = request->content.string();
-    // request->content.string() is a convenience function for:
-    // stringstream ss;
-    // ss << request->content.rdbuf();
-    // auto content=ss.str();
-
-    *response << "HTTP/1.1 200 OK\r\nContent-Length: " << content.length() << "\r\n\r\n"
-              << content;
-
-
-    // Alternatively, use one of the convenience functions, for instance:
-    // response->write(content);
-  };
-
-  // POST-example for the path /json, responds firstName+" "+lastName from the posted json
-  // Responds with an appropriate error message if the posted json is not valid, or if firstName or lastName is missing
-  // Example posted json:
-  // {
-  //   "firstName": "John",
-  //   "lastName": "Smith",
-  //   "age": 25
-  // }
-  server.resource["^/json$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    try {
-      ptree pt;
-      read_json(request->content, pt);
-
-      auto name = pt.get<string>("firstName") + " " + pt.get<string>("lastName");
-
-      *response << "HTTP/1.1 200 OK\r\n"
-                << "Content-Length: " << name.length() << "\r\n\r\n"
-                << name;
-    }
-    catch(const exception &e) {
-      *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
-                << e.what();
-    }
-
-
-    // Alternatively, using a convenience function:
-    // try {
-    //     ptree pt;
-    //     read_json(request->content, pt);
-
-    //     auto name=pt.get<string>("firstName")+" "+pt.get<string>("lastName");
-    //     response->write(name);
-    // }
-    // catch(const exception &e) {
-    //     response->write(SimpleWeb::StatusCode::client_error_bad_request, e.what());
-    // }
-  };
-
-  // GET-example for the path /info
-  // Responds with request-information
-  server.resource["^/info$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    stringstream stream;
-    stream << "<h1>Request from " << request->remote_endpoint().address().to_string() << ":" << request->remote_endpoint().port() << "</h1>";
-
-    stream << request->method << " " << request->path << " HTTP/" << request->http_version;
-
-    stream << "<h2>Query Fields</h2>";
-    auto query_fields = request->parse_query_string();
-    for(auto &field : query_fields)
-      stream << field.first << ": " << field.second << "<br>";
-
-    stream << "<h2>Header Fields</h2>";
-    for(auto &field : request->header)
-      stream << field.first << ": " << field.second << "<br>";
-
-    response->write(stream);
-  };
-
-  // GET-example for the path /match/[number], responds with the matched string in path (number)
-  // For instance a request GET /match/123 will receive: 123
-  server.resource["^/match/([0-9]+)$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    response->write(request->path_match[1].str());
-  };
-
-  // GET-example simulating heavy work in a separate thread
-  server.resource["^/work$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> /*request*/) {
-    thread work_thread([response] {
-      this_thread::sleep_for(chrono::seconds(5));
-      response->write("Work done");
-    });
-    work_thread.detach();
-  };
-
-  // Default GET-example. If no other matches, this anonymous function will be called.
-  // Will respond with content in the web/-directory, and its subdirectories.
-  // Default file: index.html
-  // Can for instance be used to retrieve an HTML 5 client that uses REST-resources on this server
-  server.default_resource["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    try {
-      auto web_root_path = boost::filesystem::canonical("web");
-      auto path = boost::filesystem::canonical(web_root_path / request->path);
-      // Check if path is within web_root_path
-      if(distance(web_root_path.begin(), web_root_path.end()) > distance(path.begin(), path.end()) ||
-         !equal(web_root_path.begin(), web_root_path.end(), path.begin()))
-        throw invalid_argument("path must be within root path");
-      if(boost::filesystem::is_directory(path))
-        path /= "index.html";
-
-      SimpleWeb::CaseInsensitiveMultimap header;
-
-      // Uncomment the following line to enable Cache-Control
-      // header.emplace("Cache-Control", "max-age=86400");
-
-#ifdef HAVE_OPENSSL
-//    Uncomment the following lines to enable ETag
-//    {
-//      ifstream ifs(path.string(), ifstream::in | ios::binary);
-//      if(ifs) {
-//        auto hash = SimpleWeb::Crypto::to_hex_string(SimpleWeb::Crypto::md5(ifs));
-//        header.emplace("ETag", "\"" + hash + "\"");
-//        auto it = request->header.find("If-None-Match");
-//        if(it != request->header.end()) {
-//          if(!it->second.empty() && it->second.compare(1, hash.size(), hash) == 0) {
-//            response->write(SimpleWeb::StatusCode::redirection_not_modified, header);
-//            return;
-//          }
-//        }
-//      }
-//      else
-//        throw invalid_argument("could not read file");
-//    }
-#endif
-
-      auto ifs = make_shared<ifstream>();
-      ifs->open(path.string(), ifstream::in | ios::binary | ios::ate);
-
-      if(*ifs) {
-        auto length = ifs->tellg();
-        ifs->seekg(0, ios::beg);
-
-        header.emplace("Content-Length", to_string(length));
-        response->write(header);
-
-        // Trick to define a recursive function within this scope (for example purposes)
-        class FileServer {
-        public:
-          static void read_and_send(const shared_ptr<HttpServer::Response> &response, const shared_ptr<ifstream> &ifs) {
-            // Read and send 128 KB at a time
-            static vector<char> buffer(131072); // Safe when server is running on one thread
-            streamsize read_length;
-            if((read_length = ifs->read(&buffer[0], static_cast<streamsize>(buffer.size())).gcount()) > 0) {
-              response->write(&buffer[0], read_length);
-              if(read_length == static_cast<streamsize>(buffer.size())) {
-                response->send([response, ifs](const SimpleWeb::error_code &ec) {
-                  if(!ec)
-                    read_and_send(response, ifs);
-                  else
-                    cerr << "Connection interrupted" << endl;
-                });
-              }
-            }
-          }
-        };
-        FileServer::read_and_send(response, ifs);
-      }
-      else
-        throw invalid_argument("could not read file");
-    }
-    catch(const exception &e) {
-      response->write(SimpleWeb::StatusCode::client_error_bad_request, "Could not open path " + request->path + ": " + e.what());
-    }
-  };
-
-  server.on_error = [](shared_ptr<HttpServer::Request> /*request*/, const SimpleWeb::error_code & /*ec*/) {
-    // Handle errors here
-    // Note that connection timeouts will also call this handle with ec set to SimpleWeb::errc::operation_canceled
-  };
-
-  // Start server and receive assigned port when server is listening for requests
-  promise<unsigned short> server_port;
-  thread server_thread([&server, &server_port]() {
-    // Start server
-    server.start([&server_port](unsigned short port) {
-      server_port.set_value(port);
-    });
-  });
-  cout << "Server listening on port " << server_port.get_future().get() << endl
-       << endl;
-
-  // Client examples
-  string json_string = "{\"firstName\": \"John\",\"lastName\": \"Smith\",\"age\": 25}";
-
-  // Synchronous request examples
-  {
-    HttpClient client("localhost:8080");
-    try {
-      cout << "Example GET request to http://localhost:8080/match/123" << endl;
-      auto r1 = client.request("GET", "/match/123");
-      cout << "Response content: " << r1->content.rdbuf() << endl // Alternatively, use the convenience function r1->content.string()
-           << endl;
-
-      cout << "Example POST request to http://localhost:8080/string" << endl;
-      auto r2 = client.request("POST", "/string", json_string);
-      cout << "Response content: " << r2->content.rdbuf() << endl
-           << endl;
-    }
-    catch(const SimpleWeb::system_error &e) {
-      cerr << "Client request error: " << e.what() << endl;
-    }
-  }
-
-  // Asynchronous request example
-  {
-    HttpClient client("localhost:8080");
-    cout << "Example POST request to http://localhost:8080/json" << endl;
-    client.request("POST", "/json", json_string, [](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
-      if(!ec)
-        cout << "Response content: " << response->content.rdbuf() << endl;
-    });
-    client.io_service->run();
-  }
-
-  server_thread.join();
-}
diff --git a/third_party/Simple-web-server/repo/https_examples.cpp b/third_party/Simple-web-server/repo/https_examples.cpp
deleted file mode 100644
index 676503b7..00000000
--- a/third_party/Simple-web-server/repo/https_examples.cpp
+++ /dev/null
@@ -1,252 +0,0 @@
-#include "client_https.hpp"
-#include "server_https.hpp"
-#include <future>
-
-// Added for the json-example
-#define BOOST_SPIRIT_THREADSAFE
-#include <boost/property_tree/json_parser.hpp>
-#include <boost/property_tree/ptree.hpp>
-
-// Added for the default_resource example
-#include "crypto.hpp"
-#include <algorithm>
-#include <boost/filesystem.hpp>
-#include <fstream>
-#include <vector>
-
-using namespace std;
-// Added for the json-example:
-using namespace boost::property_tree;
-
-using HttpsServer = SimpleWeb::Server<SimpleWeb::HTTPS>;
-using HttpsClient = SimpleWeb::Client<SimpleWeb::HTTPS>;
-
-int main() {
-  // HTTPS-server at port 8080 using 1 thread
-  // Unless you do more heavy non-threaded processing in the resources,
-  // 1 thread is usually faster than several threads
-  HttpsServer server("server.crt", "server.key");
-  server.config.port = 8080;
-
-  // Add resources using path-regex and method-string, and an anonymous function
-  // POST-example for the path /string, responds the posted string
-  server.resource["^/string$"]["POST"] = [](shared_ptr<HttpsServer::Response> response, shared_ptr<HttpsServer::Request> request) {
-    // Retrieve string:
-    auto content = request->content.string();
-    // request->content.string() is a convenience function for:
-    // stringstream ss;
-    // ss << request->content.rdbuf();
-    // auto content=ss.str();
-
-    *response << "HTTP/1.1 200 OK\r\nContent-Length: " << content.length() << "\r\n\r\n"
-              << content;
-
-
-    // Alternatively, use one of the convenience functions, for instance:
-    // response->write(content);
-  };
-
-  // POST-example for the path /json, responds firstName+" "+lastName from the posted json
-  // Responds with an appropriate error message if the posted json is not valid, or if firstName or lastName is missing
-  // Example posted json:
-  // {
-  //   "firstName": "John",
-  //   "lastName": "Smith",
-  //   "age": 25
-  // }
-  server.resource["^/json$"]["POST"] = [](shared_ptr<HttpsServer::Response> response, shared_ptr<HttpsServer::Request> request) {
-    try {
-      ptree pt;
-      read_json(request->content, pt);
-
-      auto name = pt.get<string>("firstName") + " " + pt.get<string>("lastName");
-
-      *response << "HTTP/1.1 200 OK\r\n"
-                << "Content-Length: " << name.length() << "\r\n\r\n"
-                << name;
-    }
-    catch(const exception &e) {
-      *response << "HTTP/1.1 400 Bad Request\r\nContent-Length: " << strlen(e.what()) << "\r\n\r\n"
-                << e.what();
-    }
-
-
-    // Alternatively, using a convenience function:
-    // try {
-    //     ptree pt;
-    //     read_json(request->content, pt);
-
-    //     auto name=pt.get<string>("firstName")+" "+pt.get<string>("lastName");
-    //     response->write(name);
-    // }
-    // catch(const exception &e) {
-    //     response->write(SimpleWeb::StatusCode::client_error_bad_request, e.what());
-    // }
-  };
-
-  // GET-example for the path /info
-  // Responds with request-information
-  server.resource["^/info$"]["GET"] = [](shared_ptr<HttpsServer::Response> response, shared_ptr<HttpsServer::Request> request) {
-    stringstream stream;
-    stream << "<h1>Request from " << request->remote_endpoint().address().to_string() << ":" << request->remote_endpoint().port() << "</h1>";
-
-    stream << request->method << " " << request->path << " HTTP/" << request->http_version;
-
-    stream << "<h2>Query Fields</h2>";
-    auto query_fields = request->parse_query_string();
-    for(auto &field : query_fields)
-      stream << field.first << ": " << field.second << "<br>";
-
-    stream << "<h2>Header Fields</h2>";
-    for(auto &field : request->header)
-      stream << field.first << ": " << field.second << "<br>";
-
-    response->write(stream);
-  };
-
-  // GET-example for the path /match/[number], responds with the matched string in path (number)
-  // For instance a request GET /match/123 will receive: 123
-  server.resource["^/match/([0-9]+)$"]["GET"] = [](shared_ptr<HttpsServer::Response> response, shared_ptr<HttpsServer::Request> request) {
-    response->write(request->path_match[1].str());
-  };
-
-  // GET-example simulating heavy work in a separate thread
-  server.resource["^/work$"]["GET"] = [](shared_ptr<HttpsServer::Response> response, shared_ptr<HttpsServer::Request> /*request*/) {
-    thread work_thread([response] {
-      this_thread::sleep_for(chrono::seconds(5));
-      response->write("Work done");
-    });
-    work_thread.detach();
-  };
-
-  // Default GET-example. If no other matches, this anonymous function will be called.
-  // Will respond with content in the web/-directory, and its subdirectories.
-  // Default file: index.html
-  // Can for instance be used to retrieve an HTML 5 client that uses REST-resources on this server
-  server.default_resource["GET"] = [](shared_ptr<HttpsServer::Response> response, shared_ptr<HttpsServer::Request> request) {
-    try {
-      auto web_root_path = boost::filesystem::canonical("web");
-      auto path = boost::filesystem::canonical(web_root_path / request->path);
-      // Check if path is within web_root_path
-      if(distance(web_root_path.begin(), web_root_path.end()) > distance(path.begin(), path.end()) ||
-         !equal(web_root_path.begin(), web_root_path.end(), path.begin()))
-        throw invalid_argument("path must be within root path");
-      if(boost::filesystem::is_directory(path))
-        path /= "index.html";
-
-      SimpleWeb::CaseInsensitiveMultimap header;
-
-      // Uncomment the following line to enable Cache-Control
-      // header.emplace("Cache-Control", "max-age=86400");
-
-#ifdef HAVE_OPENSSL
-//    Uncomment the following lines to enable ETag
-//    {
-//      ifstream ifs(path.string(), ifstream::in | ios::binary);
-//      if(ifs) {
-//        auto hash = SimpleWeb::Crypto::to_hex_string(SimpleWeb::Crypto::md5(ifs));
-//        header.emplace("ETag", "\"" + hash + "\"");
-//        auto it = request->header.find("If-None-Match");
-//        if(it != request->header.end()) {
-//          if(!it->second.empty() && it->second.compare(1, hash.size(), hash) == 0) {
-//            response->write(SimpleWeb::StatusCode::redirection_not_modified, header);
-//            return;
-//          }
-//        }
-//      }
-//      else
-//        throw invalid_argument("could not read file");
-//    }
-#endif
-
-      auto ifs = make_shared<ifstream>();
-      ifs->open(path.string(), ifstream::in | ios::binary | ios::ate);
-
-      if(*ifs) {
-        auto length = ifs->tellg();
-        ifs->seekg(0, ios::beg);
-
-        header.emplace("Content-Length", to_string(length));
-        response->write(header);
-
-        // Trick to define a recursive function within this scope (for example purposes)
-        class FileServer {
-        public:
-          static void read_and_send(const shared_ptr<HttpsServer::Response> &response, const shared_ptr<ifstream> &ifs) {
-            // Read and send 128 KB at a time
-            static vector<char> buffer(131072); // Safe when server is running on one thread
-            streamsize read_length;
-            if((read_length = ifs->read(&buffer[0], static_cast<streamsize>(buffer.size())).gcount()) > 0) {
-              response->write(&buffer[0], read_length);
-              if(read_length == static_cast<streamsize>(buffer.size())) {
-                response->send([response, ifs](const SimpleWeb::error_code &ec) {
-                  if(!ec)
-                    read_and_send(response, ifs);
-                  else
-                    cerr << "Connection interrupted" << endl;
-                });
-              }
-            }
-          }
-        };
-        FileServer::read_and_send(response, ifs);
-      }
-      else
-        throw invalid_argument("could not read file");
-    }
-    catch(const exception &e) {
-      response->write(SimpleWeb::StatusCode::client_error_bad_request, "Could not open path " + request->path + ": " + e.what());
-    }
-  };
-
-  server.on_error = [](shared_ptr<HttpsServer::Request> /*request*/, const SimpleWeb::error_code & /*ec*/) {
-    // Handle errors here
-    // Note that connection timeouts will also call this handle with ec set to SimpleWeb::errc::operation_canceled
-  };
-
-  // Start server and receive assigned port when server is listening for requests
-  promise<unsigned short> server_port;
-  thread server_thread([&server, &server_port]() {
-    // Start server
-    server.start([&server_port](unsigned short port) {
-      server_port.set_value(port);
-    });
-  });
-  cout << "Server listening on port " << server_port.get_future().get() << endl
-       << endl;
-
-  // Client examples
-  string json_string = "{\"firstName\": \"John\",\"lastName\": \"Smith\",\"age\": 25}";
-
-  // Synchronous request examples
-  {
-    HttpsClient client("localhost:8080", false);
-    try {
-      cout << "Example GET request to https://localhost:8080/match/123" << endl;
-      auto r1 = client.request("GET", "/match/123");
-      cout << "Response content: " << r1->content.rdbuf() << endl // Alternatively, use the convenience function r1->content.string()
-           << endl;
-
-      cout << "Example POST request to https://localhost:8080/string" << endl;
-      auto r2 = client.request("POST", "/string", json_string);
-      cout << "Response content: " << r2->content.rdbuf() << endl
-           << endl;
-    }
-    catch(const SimpleWeb::system_error &e) {
-      cerr << "Client request error: " << e.what() << endl;
-    }
-  }
-
-  // Asynchronous request example
-  {
-    HttpsClient client("localhost:8080", false);
-    cout << "Example POST request to https://localhost:8080/json" << endl;
-    client.request("POST", "/json", json_string, [](shared_ptr<HttpsClient::Response> response, const SimpleWeb::error_code &ec) {
-      if(!ec)
-        cout << "Response content: " << response->content.rdbuf() << endl;
-    });
-    client.io_service->run();
-  }
-
-  server_thread.join();
-}
diff --git a/third_party/Simple-web-server/repo/mutex.hpp b/third_party/Simple-web-server/repo/mutex.hpp
deleted file mode 100644
index 27118502..00000000
--- a/third_party/Simple-web-server/repo/mutex.hpp
+++ /dev/null
@@ -1,107 +0,0 @@
-// Based on https://clang.llvm.org/docs/ThreadSafetyAnalysis.html
-#ifndef SIMPLE_WEB_MUTEX_HPP
-#define SIMPLE_WEB_MUTEX_HPP
-
-#include <mutex>
-
-// Enable thread safety attributes only with clang.
-#if defined(__clang__) && (!defined(SWIG))
-#define THREAD_ANNOTATION_ATTRIBUTE__(x) __attribute__((x))
-#else
-#define THREAD_ANNOTATION_ATTRIBUTE__(x) // no-op
-#endif
-
-#define CAPABILITY(x) \
-  THREAD_ANNOTATION_ATTRIBUTE__(capability(x))
-
-#define SCOPED_CAPABILITY \
-  THREAD_ANNOTATION_ATTRIBUTE__(scoped_lockable)
-
-#define GUARDED_BY(x) \
-  THREAD_ANNOTATION_ATTRIBUTE__(guarded_by(x))
-
-#define PT_GUARDED_BY(x) \
-  THREAD_ANNOTATION_ATTRIBUTE__(pt_guarded_by(x))
-
-#define ACQUIRED_BEFORE(...) \
-  THREAD_ANNOTATION_ATTRIBUTE__(acquired_before(__VA_ARGS__))
-
-#define ACQUIRED_AFTER(...) \
-  THREAD_ANNOTATION_ATTRIBUTE__(acquired_after(__VA_ARGS__))
-
-#define REQUIRES(...) \
-  THREAD_ANNOTATION_ATTRIBUTE__(requires_capability(__VA_ARGS__))
-
-#define REQUIRES_SHARED(...) \
-  THREAD_ANNOTATION_ATTRIBUTE__(requires_shared_capability(__VA_ARGS__))
-
-#define ACQUIRE(...) \
-  THREAD_ANNOTATION_ATTRIBUTE__(acquire_capability(__VA_ARGS__))
-
-#define ACQUIRE_SHARED(...) \
-  THREAD_ANNOTATION_ATTRIBUTE__(acquire_shared_capability(__VA_ARGS__))
-
-#define RELEASE(...) \
-  THREAD_ANNOTATION_ATTRIBUTE__(release_capability(__VA_ARGS__))
-
-#define RELEASE_SHARED(...) \
-  THREAD_ANNOTATION_ATTRIBUTE__(release_shared_capability(__VA_ARGS__))
-
-#define TRY_ACQUIRE(...) \
-  THREAD_ANNOTATION_ATTRIBUTE__(try_acquire_capability(__VA_ARGS__))
-
-#define TRY_ACQUIRE_SHARED(...) \
-  THREAD_ANNOTATION_ATTRIBUTE__(try_acquire_shared_capability(__VA_ARGS__))
-
-#define EXCLUDES(...) \
-  THREAD_ANNOTATION_ATTRIBUTE__(locks_excluded(__VA_ARGS__))
-
-#define ASSERT_CAPABILITY(x) \
-  THREAD_ANNOTATION_ATTRIBUTE__(assert_capability(x))
-
-#define ASSERT_SHARED_CAPABILITY(x) \
-  THREAD_ANNOTATION_ATTRIBUTE__(assert_shared_capability(x))
-
-#define RETURN_CAPABILITY(x) \
-  THREAD_ANNOTATION_ATTRIBUTE__(lock_returned(x))
-
-#define NO_THREAD_SAFETY_ANALYSIS \
-  THREAD_ANNOTATION_ATTRIBUTE__(no_thread_safety_analysis)
-
-namespace SimpleWeb {
-  /// Mutex class that is annotated for Clang Thread Safety Analysis.
-  class CAPABILITY("mutex") Mutex {
-    std::mutex mutex;
-
-  public:
-    void lock() ACQUIRE() {
-      mutex.lock();
-    }
-
-    void unlock() RELEASE() {
-      mutex.unlock();
-    }
-  };
-
-  /// Scoped mutex guard class that is annotated for Clang Thread Safety Analysis.
-  class SCOPED_CAPABILITY LockGuard {
-    Mutex &mutex;
-    bool locked = true;
-
-  public:
-    LockGuard(Mutex &mutex_) ACQUIRE(mutex_) : mutex(mutex_) {
-      mutex.lock();
-    }
-    void unlock() RELEASE() {
-      mutex.unlock();
-      locked = false;
-    }
-    ~LockGuard() RELEASE() {
-      if(locked)
-        mutex.unlock();
-    }
-  };
-
-} // namespace SimpleWeb
-
-#endif // SIMPLE_WEB_MUTEX_HPP
diff --git a/third_party/Simple-web-server/repo/paper/.markdown-format b/third_party/Simple-web-server/repo/paper/.markdown-format
deleted file mode 100644
index e69de29b..00000000
diff --git a/third_party/Simple-web-server/repo/paper/paper.bib b/third_party/Simple-web-server/repo/paper/paper.bib
deleted file mode 100644
index b81245b6..00000000
--- a/third_party/Simple-web-server/repo/paper/paper.bib
+++ /dev/null
@@ -1,80 +0,0 @@
-@online{asio,
-  author = {Kohlhoff, Christopher M.},
-  title = {Asio C++ Library},
-  year = {2003},
-  url = {https://think-async.com/Asio/},
-  urldate = {2018-07-17}
-}
-
-@online{clang_thread_safety,
-  author = {{The Clang Team}},
-  title = {Clang Thread Safety Analysis},
-  year = {2007},
-  url = {https://clang.llvm.org/docs/ThreadSafetyAnalysis.html},
-  urldate = {2018-07-17}
-}
-
-@online{beast,
-  author = {Falco, Vinnie},
-  title = {Boost.Beast},
-  year = {2016},
-  url = {https://github.com/boostorg/beast},
-  urldate = {2018-07-17}
-}
-
-@online{h20,
-  author = {{DeNA Co., Ltd.}},
-  title = {H2O},
-  year = {2014},
-  url = {https://github.com/h2o/h2o},
-  urldate = {2018-07-17}
-}
-
-@online{websocket_protocol,
-  author = {I. Fette and A. Melnikov},
-  title = {The WebSocket Protocol},
-  howpublished = {Internet Requests for Comments},
-  type = {RFC},
-  number = {6455},
-  year = {2011},
-  month = {December},
-  issn = {2070-1721},
-  publisher = {RFC Editor},
-  institution = {RFC Editor},
-  url = {http://www.rfc-editor.org/rfc/rfc6455.txt},
-  note = {\url{http://www.rfc-editor.org/rfc/rfc6455.txt}},
-  doi = {10.17487/RFC6455}
-}
-
-@online{simple_websocket_server,
-  author = {Eidheim, Ole Christian},
-  title = {Simple-WebSocket-Server},
-  year = {2014},
-  url = {https://gitlab.com/eidheim/Simple-WebSocket-Server},
-  urldate = {2018-07-17}
-}
-
-@online{mame,
-  author = {MAMEDev},
-  title = {MAME},
-  year = {1997},
-  url = {https://www.mamedev.org/},
-  urldate = {2018-07-17}
-}
-
-@online{wakely,
-  author = {Wakely, Jonathan},
-  title = {Working Draft, C++ Extensions for Networking},
-  year = {2017},
-  url = {http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2017/n4656.pdf},
-  urldate = {2018-07-17}
-}
-
-@misc{chung,
-  title = {Point Cloud Framework for Rendering {3D} Models Using {Google} {Tango}},
-  author = {Chung, Maxen and Callin, Julian},
-  year = {2017},
-  publisher = {Santa Clara: Santa Clara University, 2017},
-  url = {https://scholarcommons.scu.edu/cseng_senior/84},
-  howpublished = {Computer Science and Engineering Senior Theses, Santa Clara University},
-}
diff --git a/third_party/Simple-web-server/repo/paper/paper.md b/third_party/Simple-web-server/repo/paper/paper.md
deleted file mode 100644
index cbba733e..00000000
--- a/third_party/Simple-web-server/repo/paper/paper.md
+++ /dev/null
@@ -1,100 +0,0 @@
----
-title: 'Simple-Web-Server: a fast and flexible HTTP/1.1 C++ client and server library'
-tags:
-  - C++
-  - web
-  - http
-  - client
-  - server
-  - library
-  - asio
-authors:
-  - name: Ole Christian Eidheim
-    orcid: 0000-0001-5355-6326
-    affiliation: 1
-affiliations:
-  - name: Department of Computer Science, Norwegian University of Science and Technology
-    index: 1
-date: 18 July 2019
-bibliography: paper.bib
----
-
-# Summary
-
-The programming language C++ is commonly used for resource intensive tasks.
-Simple-Web-Server is a library that can be utilized in C++ applications to
-implement web-resources or perform HTTP or HTTPS requests in a simple manner
-across OS platforms compared to using a networking library directly. Thus,
-Simple-Web-Server can be helpful for any research software written in C++ that
-needs to communicate with remote endpoints through HTTP or HTTPS.
-
-The main features, apart from speed and ease of use, are flexibility and safety.
-The asynchronous I/O library Asio C++ Library [@asio] is used to implement
-networking and asynchronous event handling. The sending of outgoing messages has
-been made thread safe, and event handling in one or several threads is
-supported. The default event handling strategy is using one thread, commonly
-called event-loop, which makes accessing shared resources safe without using
-resource locking through for instance mutexes. Although, accessing shared
-resources in a multithreaded event-handling strategy can be made safer by
-utilizing the annotation offered in Clang Thread Safety Analysis
-[@clang_thread_safety]. In some cases, however, processing requests
-sequentially, in an event-loop scheme, can be faster than processing the
-requests in several threads where shared resources must be protected from
-simultaneous use.
-
-An additional safety feature is stopping of asynchronous handlers when the
-associated client or server object has been destroyed. An atomic instruction
-based class, ScopeRunner, was implemented to achieve this since reader-writer
-locks proved more resource intensive for this specific task. In detail, a
-ScopeRunner object has an internal atomic counter that is increased when an
-asynchronous handler is run. At the end of the handler, the counter is
-decreased. When the destructor of a client or server object is called, the
-ScopeRunner object delays the destructor until its internal counter is 0, then
-sets the counter to a negative value. Finally, when the internal counter is
-negative, the handlers are returned from instead of potentially calling methods
-or using member variables of a destroyed client or server object.
-
-Compared to using a low-level network library, specialized for a specific task,
-a slight performance overhead is expected when using the more generalized
-Simple-Web-Server library. The various utility and safety features, and code
-abstractions contribute to this overhead, but a good balance between safety,
-usability and speed is continuously sought during development of this library.
-Regular expressions can for instance be used to define which functions to be
-called for specific request paths. This can be convenient for the library user,
-but a more specific algorithm can be more efficient than using regular
-expressions.
-
-The Asio C++ Library [@asio] is currently proposed to the C++ standard library
-[@wakely]. If accepted in one of the future revisions of the C++ programming
-language, C++ applications can make use of a standardized event handling system.
-Until then, efforts are made to support old and new versions of the Asio C++
-Library, as well as both the standalone and Boost variants of the library.
-
-Simple-Web-Server is used in teaching at the Norwegian University of Science and
-Technology, and used in many external projects, for instance in the
-multi-purpose emulation framework MAME [@mame]. The library was also used in the
-senior thesis by Chung and Callin [@chung]. Furthermore, one of the motivations
-for the Simple-Web-Server project was to create a HTTP/1.1 library that was
-relatively easy to modify and extend to suit a specific need, which could also
-be positive with regards to source code contributions to the project.
-
-There are several alternatives to Simple-Web-Server. Most notably Boost.Beast
-[@beast], but this library is made for library authors and is thus harder to
-utilize in a C++ application. Additionally, Boost.Beast does not support
-standalone Asio. Another alternative is H2O [@h20] that supports several event
-handling systems, however, Asio is not yet supported. Both Boost.Beast, and to a
-lesser degree H2O, supports the WebSocket protocol [@websocket_protocol]. In the
-case of Simple-Web-Server, WebSocket is supported through a related external
-project named Simple-WebSocket-Server [@simple_websocket_server].
-
-Based on Simple-Web-Server, a new C++ library supporting HTTP/2 is under
-development. HTTP/2 is very different from HTTP/1.1, but the experiences from
-developing Simple-Web-Server, and some its implementations, such as the
-ScopeRunner class, can be helpful when writing an HTTP/2 library.
-
-# Acknowledgments
-
-I would like to thank all those who have contributed to the Simple-Web-Server
-project.
-
-# References
diff --git a/third_party/Simple-web-server/repo/server_http.hpp b/third_party/Simple-web-server/repo/server_http.hpp
deleted file mode 100644
index 1db0368e..00000000
--- a/third_party/Simple-web-server/repo/server_http.hpp
+++ /dev/null
@@ -1,848 +0,0 @@
-#ifndef SIMPLE_WEB_SERVER_HTTP_HPP
-#define SIMPLE_WEB_SERVER_HTTP_HPP
-
-#include "asio_compatibility.hpp"
-#include "mutex.hpp"
-#include "utility.hpp"
-#include <functional>
-#include <iostream>
-#include <limits>
-#include <list>
-#include <map>
-#include <sstream>
-#include <thread>
-#include <unordered_set>
-
-// Late 2017 TODO: remove the following checks and always use std::regex
-#ifdef USE_BOOST_REGEX
-#include <boost/regex.hpp>
-namespace SimpleWeb {
-  namespace regex = boost;
-}
-#else
-#include <regex>
-namespace SimpleWeb {
-  namespace regex = std;
-}
-#endif
-
-namespace SimpleWeb {
-  template <class socket_type>
-  class Server;
-
-  template <class socket_type>
-  class ServerBase {
-  protected:
-    class Connection;
-    class Session;
-
-  public:
-    /// Response class where the content of the response is sent to client when the object is about to be destroyed.
-    class Response : public std::enable_shared_from_this<Response>, public std::ostream {
-      friend class ServerBase<socket_type>;
-      friend class Server<socket_type>;
-
-      std::unique_ptr<asio::streambuf> streambuf = std::unique_ptr<asio::streambuf>(new asio::streambuf());
-
-      std::shared_ptr<Session> session;
-      long timeout_content;
-
-      Mutex send_queue_mutex;
-      std::list<std::pair<std::shared_ptr<asio::streambuf>, std::function<void(const error_code &)>>> send_queue GUARDED_BY(send_queue_mutex);
-
-      Response(std::shared_ptr<Session> session_, long timeout_content) noexcept : std::ostream(nullptr), session(std::move(session_)), timeout_content(timeout_content) {
-        rdbuf(streambuf.get());
-      }
-
-      template <typename size_type>
-      void write_header(const CaseInsensitiveMultimap &header, size_type size) {
-        bool content_length_written = false;
-        bool chunked_transfer_encoding = false;
-        bool event_stream = false;
-        for(auto &field : header) {
-          if(!content_length_written && case_insensitive_equal(field.first, "content-length"))
-            content_length_written = true;
-          else if(!chunked_transfer_encoding && case_insensitive_equal(field.first, "transfer-encoding") && case_insensitive_equal(field.second, "chunked"))
-            chunked_transfer_encoding = true;
-          else if(!event_stream && case_insensitive_equal(field.first, "content-type") && case_insensitive_equal(field.second, "text/event-stream"))
-            event_stream = true;
-
-          *this << field.first << ": " << field.second << "\r\n";
-        }
-        if(!content_length_written && !chunked_transfer_encoding && !event_stream && !close_connection_after_response)
-          *this << "Content-Length: " << size << "\r\n\r\n";
-        else
-          *this << "\r\n";
-      }
-
-      void send_from_queue() REQUIRES(send_queue_mutex) {
-        auto buffer = send_queue.begin()->first->data();
-        auto self = this->shared_from_this();
-        post(session->connection->write_strand, [self, buffer] {
-          auto lock = self->session->connection->handler_runner->continue_lock();
-          if(!lock)
-            return;
-          asio::async_write(*self->session->connection->socket, buffer, [self](const error_code &ec, std::size_t /*bytes_transferred*/) {
-            auto lock = self->session->connection->handler_runner->continue_lock();
-            if(!lock)
-              return;
-            {
-              LockGuard lock(self->send_queue_mutex);
-              if(!ec) {
-                auto it = self->send_queue.begin();
-                auto callback = std::move(it->second);
-                self->send_queue.erase(it);
-                if(self->send_queue.size() > 0)
-                  self->send_from_queue();
-
-                lock.unlock();
-                if(callback)
-                  callback(ec);
-              }
-              else {
-                // All handlers in the queue is called with ec:
-                std::list<std::function<void(const error_code &)>> callbacks;
-                for(auto &pair : self->send_queue) {
-                  if(pair.second)
-                    callbacks.emplace_back(std::move(pair.second));
-                }
-                self->send_queue.clear();
-
-                lock.unlock();
-                for(auto &callback : callbacks)
-                  callback(ec);
-              }
-            }
-          });
-        });
-      }
-
-      void send_on_delete(const std::function<void(const error_code &)> &callback = nullptr) noexcept {
-        auto buffer = streambuf->data();
-        auto self = this->shared_from_this(); // Keep Response instance alive through the following async_write
-        post(session->connection->write_strand, [self, buffer, callback] {
-          auto lock = self->session->connection->handler_runner->continue_lock();
-          if(!lock)
-            return;
-          asio::async_write(*self->session->connection->socket, buffer, [self, callback](const error_code &ec, std::size_t /*bytes_transferred*/) {
-            auto lock = self->session->connection->handler_runner->continue_lock();
-            if(!lock)
-              return;
-            if(callback)
-              callback(ec);
-          });
-        });
-      }
-
-    public:
-      std::size_t size() noexcept {
-        return streambuf->size();
-      }
-
-      /// Send the content of the response stream to client. The callback is called when the send has completed.
-      ///
-      /// Use this function if you need to recursively send parts of a longer message, or when using server-sent events.
-      void send(std::function<void(const error_code &)> callback = nullptr) noexcept {
-        std::shared_ptr<asio::streambuf> streambuf = std::move(this->streambuf);
-        this->streambuf = std::unique_ptr<asio::streambuf>(new asio::streambuf());
-        rdbuf(this->streambuf.get());
-
-        LockGuard lock(send_queue_mutex);
-        send_queue.emplace_back(std::move(streambuf), std::move(callback));
-        if(send_queue.size() == 1)
-          send_from_queue();
-      }
-
-      /// Write directly to stream buffer using std::ostream::write.
-      void write(const char_type *ptr, std::streamsize n) {
-        std::ostream::write(ptr, n);
-      }
-
-      /// Convenience function for writing status line, potential header fields, and empty content.
-      void write(StatusCode status_code = StatusCode::success_ok, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
-        *this << "HTTP/1.1 " << SimpleWeb::status_code(status_code) << "\r\n";
-        write_header(header, 0);
-      }
-
-      /// Convenience function for writing status line, header fields, and content.
-      void write(StatusCode status_code, string_view content, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
-        *this << "HTTP/1.1 " << SimpleWeb::status_code(status_code) << "\r\n";
-        write_header(header, content.size());
-        if(!content.empty())
-          *this << content;
-      }
-
-      /// Convenience function for writing status line, header fields, and content.
-      void write(StatusCode status_code, std::istream &content, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
-        *this << "HTTP/1.1 " << SimpleWeb::status_code(status_code) << "\r\n";
-        content.seekg(0, std::ios::end);
-        auto size = content.tellg();
-        content.seekg(0, std::ios::beg);
-        write_header(header, size);
-        if(size)
-          *this << content.rdbuf();
-      }
-
-      /// Convenience function for writing success status line, header fields, and content.
-      void write(string_view content, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
-        write(StatusCode::success_ok, content, header);
-      }
-
-      /// Convenience function for writing success status line, header fields, and content.
-      void write(std::istream &content, const CaseInsensitiveMultimap &header = CaseInsensitiveMultimap()) {
-        write(StatusCode::success_ok, content, header);
-      }
-
-      /// Convenience function for writing success status line, and header fields.
-      void write(const CaseInsensitiveMultimap &header) {
-        write(StatusCode::success_ok, std::string(), header);
-      }
-
-      /// If set to true, force server to close the connection after the response have been sent.
-      ///
-      /// This is useful when implementing a HTTP/1.0-server sending content
-      /// without specifying the content length.
-      bool close_connection_after_response = false;
-    };
-
-    class Content : public std::istream {
-      friend class ServerBase<socket_type>;
-
-    public:
-      std::size_t size() noexcept {
-        return streambuf.size();
-      }
-      /// Convenience function to return content as std::string.
-      std::string string() noexcept {
-        return std::string(asio::buffers_begin(streambuf.data()), asio::buffers_end(streambuf.data()));
-      }
-
-    private:
-      asio::streambuf &streambuf;
-      Content(asio::streambuf &streambuf) noexcept : std::istream(&streambuf), streambuf(streambuf) {}
-    };
-
-    class Request {
-      friend class ServerBase<socket_type>;
-      friend class Server<socket_type>;
-      friend class Session;
-
-      asio::streambuf streambuf;
-      std::weak_ptr<Connection> connection;
-      std::string optimization = std::to_string(0); // TODO: figure out what goes wrong in gcc optimization without this line
-
-      Request(std::size_t max_request_streambuf_size, const std::shared_ptr<Connection> &connection_) noexcept : streambuf(max_request_streambuf_size), connection(connection_), content(streambuf) {}
-
-    public:
-      std::string method, path, query_string, http_version;
-
-      Content content;
-
-      CaseInsensitiveMultimap header;
-
-      /// The result of the resource regular expression match of the request path.
-      regex::smatch path_match;
-
-      /// The time point when the request header was fully read.
-      std::chrono::system_clock::time_point header_read_time;
-
-      asio::ip::tcp::endpoint remote_endpoint() const noexcept {
-        try {
-          if(auto connection = this->connection.lock())
-            return connection->socket->lowest_layer().remote_endpoint();
-        }
-        catch(...) {
-        }
-        return asio::ip::tcp::endpoint();
-      }
-
-      asio::ip::tcp::endpoint local_endpoint() const noexcept {
-        try {
-          if(auto connection = this->connection.lock())
-            return connection->socket->lowest_layer().local_endpoint();
-        }
-        catch(...) {
-        }
-        return asio::ip::tcp::endpoint();
-      }
-
-      /// Deprecated, please use remote_endpoint().address().to_string() instead.
-      SW_DEPRECATED std::string remote_endpoint_address() const noexcept {
-        try {
-          if(auto connection = this->connection.lock())
-            return connection->socket->lowest_layer().remote_endpoint().address().to_string();
-        }
-        catch(...) {
-        }
-        return std::string();
-      }
-
-      /// Deprecated, please use remote_endpoint().port() instead.
-      SW_DEPRECATED unsigned short remote_endpoint_port() const noexcept {
-        try {
-          if(auto connection = this->connection.lock())
-            return connection->socket->lowest_layer().remote_endpoint().port();
-        }
-        catch(...) {
-        }
-        return 0;
-      }
-
-      /// Returns query keys with percent-decoded values.
-      CaseInsensitiveMultimap parse_query_string() const noexcept {
-        return SimpleWeb::QueryString::parse(query_string);
-      }
-    };
-
-  protected:
-    class Connection : public std::enable_shared_from_this<Connection> {
-    public:
-      template <typename... Args>
-      Connection(std::shared_ptr<ScopeRunner> handler_runner_, Args &&...args) noexcept : handler_runner(std::move(handler_runner_)), socket(new socket_type(std::forward<Args>(args)...)), write_strand(get_executor(socket->lowest_layer())) {}
-
-      std::shared_ptr<ScopeRunner> handler_runner;
-
-      std::unique_ptr<socket_type> socket; // Socket must be unique_ptr since asio::ssl::stream<asio::ip::tcp::socket> is not movable
-
-      /**
-       * Needed for TLS communication where async_write could be called outside of the io_context runners.
-       * For more information see https://stackoverflow.com/a/12801042.
-       */
-      strand write_strand;
-
-      std::unique_ptr<asio::steady_timer> timer;
-
-      void close() noexcept {
-        error_code ec;
-        socket->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
-        socket->lowest_layer().cancel(ec);
-      }
-
-      void set_timeout(long seconds) noexcept {
-        if(seconds == 0) {
-          timer = nullptr;
-          return;
-        }
-
-        timer = make_steady_timer(*socket, std::chrono::seconds(seconds));
-        std::weak_ptr<Connection> self_weak(this->shared_from_this()); // To avoid keeping Connection instance alive longer than needed
-        timer->async_wait([self_weak](const error_code &ec) {
-          if(!ec) {
-            if(auto self = self_weak.lock())
-              self->close();
-          }
-        });
-      }
-
-      void cancel_timeout() noexcept {
-        if(timer) {
-          try {
-            timer->cancel();
-          }
-          catch(...) {
-          }
-        }
-      }
-    };
-
-    class Session {
-    public:
-      Session(std::size_t max_request_streambuf_size, std::shared_ptr<Connection> connection_) noexcept : connection(std::move(connection_)), request(new Request(max_request_streambuf_size, connection)) {}
-
-      std::shared_ptr<Connection> connection;
-      std::shared_ptr<Request> request;
-    };
-
-  public:
-    class Config {
-      friend class ServerBase<socket_type>;
-
-      Config(unsigned short port) noexcept : port(port) {}
-
-    public:
-      /// Port number to use. Defaults to 80 for HTTP and 443 for HTTPS. Set to 0 get an assigned port.
-      unsigned short port;
-      /// If io_service is not set, number of threads that the server will use when start() is called.
-      /// Defaults to 1 thread.
-      std::size_t thread_pool_size = 1;
-      /// Timeout on request completion. Defaults to 5 seconds.
-      long timeout_request = 5;
-      /// Timeout on request/response content completion. Defaults to 300 seconds.
-      long timeout_content = 300;
-      /// Maximum size of request stream buffer. Defaults to architecture maximum.
-      /// Reaching this limit will result in a message_size error code.
-      std::size_t max_request_streambuf_size = (std::numeric_limits<std::size_t>::max)();
-      /// IPv4 address in dotted decimal form or IPv6 address in hexadecimal notation.
-      /// If empty, the address will be any address.
-      std::string address;
-      /// Set to false to avoid binding the socket to an address that is already in use. Defaults to true.
-      bool reuse_address = true;
-      /// Make use of RFC 7413 or TCP Fast Open (TFO)
-      bool fast_open = false;
-    };
-    /// Set before calling start().
-    Config config;
-
-  private:
-    class regex_orderable : public regex::regex {
-    public:
-      std::string str;
-
-      regex_orderable(const char *regex_cstr) : regex::regex(regex_cstr), str(regex_cstr) {}
-      regex_orderable(std::string regex_str_) : regex::regex(regex_str_), str(std::move(regex_str_)) {}
-      bool operator<(const regex_orderable &rhs) const noexcept {
-        return str < rhs.str;
-      }
-    };
-
-  public:
-    /// Use this container to add resources for specific request paths depending on the given regex and method.
-    /// Warning: do not add or remove resources after start() is called
-    std::map<regex_orderable, std::map<std::string, std::function<void(std::shared_ptr<typename ServerBase<socket_type>::Response>, std::shared_ptr<typename ServerBase<socket_type>::Request>)>>> resource;
-
-    /// If the request path does not match a resource regex, this function is called.
-    std::map<std::string, std::function<void(std::shared_ptr<typename ServerBase<socket_type>::Response>, std::shared_ptr<typename ServerBase<socket_type>::Request>)>> default_resource;
-
-    /// Called when an error occurs.
-    std::function<void(std::shared_ptr<typename ServerBase<socket_type>::Request>, const error_code &)> on_error;
-
-    /// Called on upgrade requests.
-    std::function<void(std::unique_ptr<socket_type> &, std::shared_ptr<typename ServerBase<socket_type>::Request>)> on_upgrade;
-
-    /// If you want to reuse an already created asio::io_service, store its pointer here before calling start().
-    std::shared_ptr<io_context> io_service;
-
-    /// Start the server.
-    /// If io_service is not set, an internal io_service is created instead.
-    /// The callback argument is called after the server is accepting connections,
-    /// where its parameter contains the assigned port.
-    void start(const std::function<void(unsigned short /*port*/)> &callback = nullptr) {
-      std::unique_lock<std::mutex> lock(start_stop_mutex);
-
-      asio::ip::tcp::endpoint endpoint;
-      if(!config.address.empty())
-        endpoint = asio::ip::tcp::endpoint(make_address(config.address), config.port);
-      else
-        endpoint = asio::ip::tcp::endpoint(asio::ip::tcp::v6(), config.port);
-
-      if(!io_service) {
-        io_service = std::make_shared<io_context>();
-        internal_io_service = true;
-      }
-
-      if(!acceptor)
-        acceptor = std::unique_ptr<asio::ip::tcp::acceptor>(new asio::ip::tcp::acceptor(*io_service));
-      try {
-        acceptor->open(endpoint.protocol());
-      }
-      catch(const system_error &error) {
-        if(error.code() == asio::error::address_family_not_supported && config.address.empty()) {
-          endpoint = asio::ip::tcp::endpoint(asio::ip::tcp::v4(), config.port);
-          acceptor->open(endpoint.protocol());
-        }
-        else
-          throw;
-      }
-      acceptor->set_option(asio::socket_base::reuse_address(config.reuse_address));
-      if(config.fast_open) {
-#if defined(__linux__) && defined(TCP_FASTOPEN)
-        const int qlen = 5; // This seems to be the value that is used in other examples.
-        error_code ec;
-        acceptor->set_option(asio::detail::socket_option::integer<IPPROTO_TCP, TCP_FASTOPEN>(qlen), ec);
-#endif // End Linux
-      }
-      acceptor->bind(endpoint);
-
-      after_bind();
-
-      auto port = acceptor->local_endpoint().port();
-
-      acceptor->listen();
-      accept();
-
-      if(internal_io_service && io_service->stopped())
-        restart(*io_service);
-
-      if(callback)
-        post(*io_service, [callback, port] {
-          callback(port);
-        });
-
-      if(internal_io_service) {
-        // If thread_pool_size>1, start m_io_service.run() in (thread_pool_size-1) threads for thread-pooling
-        threads.clear();
-        for(std::size_t c = 1; c < config.thread_pool_size; c++) {
-          threads.emplace_back([this]() {
-            this->io_service->run();
-          });
-        }
-
-        lock.unlock();
-
-        // Main thread
-        if(config.thread_pool_size > 0)
-          io_service->run();
-
-        lock.lock();
-
-        // Wait for the rest of the threads, if any, to finish as well
-        for(auto &t : threads)
-          t.join();
-      }
-    }
-
-    /// Stop accepting new requests, and close current connections.
-    void stop() noexcept {
-      std::lock_guard<std::mutex> lock(start_stop_mutex);
-
-      if(acceptor) {
-        error_code ec;
-        acceptor->close(ec);
-
-        {
-          LockGuard lock(connections->mutex);
-          for(auto &connection : connections->set)
-            connection->close();
-          connections->set.clear();
-        }
-
-        if(internal_io_service)
-          io_service->stop();
-      }
-    }
-
-    virtual ~ServerBase() noexcept {
-      handler_runner->stop();
-      stop();
-    }
-
-  protected:
-    std::mutex start_stop_mutex;
-
-    bool internal_io_service = false;
-
-    std::unique_ptr<asio::ip::tcp::acceptor> acceptor;
-    std::vector<std::thread> threads;
-
-    struct Connections {
-      Mutex mutex;
-      std::unordered_set<Connection *> set GUARDED_BY(mutex);
-    };
-    std::shared_ptr<Connections> connections;
-
-    std::shared_ptr<ScopeRunner> handler_runner;
-
-    ServerBase(unsigned short port) noexcept : config(port), connections(new Connections()), handler_runner(new ScopeRunner()) {}
-
-    virtual void after_bind() {}
-    virtual void accept() = 0;
-
-    template <typename... Args>
-    std::shared_ptr<Connection> create_connection(Args &&...args) noexcept {
-      auto connections = this->connections;
-      auto connection = std::shared_ptr<Connection>(new Connection(handler_runner, std::forward<Args>(args)...), [connections](Connection *connection) {
-        {
-          LockGuard lock(connections->mutex);
-          auto it = connections->set.find(connection);
-          if(it != connections->set.end())
-            connections->set.erase(it);
-        }
-        delete connection;
-      });
-      {
-        LockGuard lock(connections->mutex);
-        connections->set.emplace(connection.get());
-      }
-      return connection;
-    }
-
-    void read(const std::shared_ptr<Session> &session) {
-      session->connection->set_timeout(config.timeout_request);
-      asio::async_read_until(*session->connection->socket, session->request->streambuf, "\r\n\r\n", [this, session](const error_code &ec, std::size_t bytes_transferred) {
-        auto lock = session->connection->handler_runner->continue_lock();
-        if(!lock)
-          return;
-        session->request->header_read_time = std::chrono::system_clock::now();
-
-        if(!ec) {
-          session->connection->set_timeout(this->config.timeout_content);
-          // request->streambuf.size() is not necessarily the same as bytes_transferred, from Boost-docs:
-          // "After a successful async_read_until operation, the streambuf may contain additional data beyond the delimiter"
-          // The chosen solution is to extract lines from the stream directly when parsing the header. What is left of the
-          // streambuf (maybe some bytes of the content) is appended to in the async_read-function below (for retrieving content).
-          std::size_t num_additional_bytes = session->request->streambuf.size() - bytes_transferred;
-
-          if(!RequestMessage::parse(session->request->content, session->request->method, session->request->path,
-                                    session->request->query_string, session->request->http_version, session->request->header)) {
-            if(this->on_error)
-              this->on_error(session->request, make_error_code::make_error_code(errc::protocol_error));
-            return;
-          }
-
-          // If content, read that as well
-          auto header_it = session->request->header.find("Content-Length");
-          if(header_it != session->request->header.end()) {
-            unsigned long long content_length = 0;
-            try {
-              content_length = std::stoull(header_it->second);
-            }
-            catch(const std::exception &) {
-              if(this->on_error)
-                this->on_error(session->request, make_error_code::make_error_code(errc::protocol_error));
-              return;
-            }
-            if(content_length > session->request->streambuf.max_size()) {
-              auto response = std::shared_ptr<Response>(new Response(session, this->config.timeout_content));
-              response->write(StatusCode::client_error_payload_too_large);
-              if(this->on_error)
-                this->on_error(session->request, make_error_code::make_error_code(errc::message_size));
-              return;
-            }
-            if(content_length > num_additional_bytes) {
-              asio::async_read(*session->connection->socket, session->request->streambuf, asio::transfer_exactly(content_length - num_additional_bytes), [this, session](const error_code &ec, std::size_t /*bytes_transferred*/) {
-                auto lock = session->connection->handler_runner->continue_lock();
-                if(!lock)
-                  return;
-
-                if(!ec)
-                  this->find_resource(session);
-                else if(this->on_error)
-                  this->on_error(session->request, ec);
-              });
-            }
-            else
-              this->find_resource(session);
-          }
-          else if((header_it = session->request->header.find("Transfer-Encoding")) != session->request->header.end() && header_it->second == "chunked") {
-            // Expect hex number to not exceed 16 bytes (64-bit number), but take into account previous additional read bytes
-            auto chunk_size_streambuf = std::make_shared<asio::streambuf>(std::max<std::size_t>(16 + 2, session->request->streambuf.size()));
-
-            // Move leftover bytes
-            auto &source = session->request->streambuf;
-            auto &target = *chunk_size_streambuf;
-            target.commit(asio::buffer_copy(target.prepare(source.size()), source.data()));
-            source.consume(source.size());
-
-            this->read_chunked_transfer_encoded(session, chunk_size_streambuf);
-          }
-          else
-            this->find_resource(session);
-        }
-        else if(this->on_error)
-          this->on_error(session->request, ec);
-      });
-    }
-
-    void read_chunked_transfer_encoded(const std::shared_ptr<Session> &session, const std::shared_ptr<asio::streambuf> &chunk_size_streambuf) {
-      asio::async_read_until(*session->connection->socket, *chunk_size_streambuf, "\r\n", [this, session, chunk_size_streambuf](const error_code &ec, size_t bytes_transferred) {
-        auto lock = session->connection->handler_runner->continue_lock();
-        if(!lock)
-          return;
-
-        if(!ec) {
-          std::istream istream(chunk_size_streambuf.get());
-          std::string line;
-          std::getline(istream, line);
-          bytes_transferred -= line.size() + 1;
-          unsigned long chunk_size = 0;
-          try {
-            chunk_size = std::stoul(line, 0, 16);
-          }
-          catch(...) {
-            if(this->on_error)
-              this->on_error(session->request, make_error_code::make_error_code(errc::protocol_error));
-            return;
-          }
-
-          if(chunk_size == 0) {
-            this->find_resource(session);
-            return;
-          }
-
-          if(chunk_size + session->request->streambuf.size() > session->request->streambuf.max_size()) {
-            auto response = std::shared_ptr<Response>(new Response(session, this->config.timeout_content));
-            response->write(StatusCode::client_error_payload_too_large);
-            if(this->on_error)
-              this->on_error(session->request, make_error_code::make_error_code(errc::message_size));
-            return;
-          }
-
-          auto num_additional_bytes = chunk_size_streambuf->size() - bytes_transferred;
-
-          auto bytes_to_move = std::min<std::size_t>(chunk_size, num_additional_bytes);
-          if(bytes_to_move > 0) {
-            // Move leftover bytes
-            auto &source = *chunk_size_streambuf;
-            auto &target = session->request->streambuf;
-            target.commit(asio::buffer_copy(target.prepare(bytes_to_move), source.data(), bytes_to_move));
-            source.consume(bytes_to_move);
-          }
-
-          if(chunk_size > num_additional_bytes) {
-            asio::async_read(*session->connection->socket, session->request->streambuf, asio::transfer_exactly(chunk_size - num_additional_bytes), [this, session, chunk_size_streambuf](const error_code &ec, size_t /*bytes_transferred*/) {
-              auto lock = session->connection->handler_runner->continue_lock();
-              if(!lock)
-                return;
-
-              if(!ec) {
-                // Remove "\r\n"
-                auto null_buffer = std::make_shared<asio::streambuf>(2);
-                asio::async_read(*session->connection->socket, *null_buffer, asio::transfer_exactly(2), [this, session, chunk_size_streambuf, null_buffer](const error_code &ec, size_t /*bytes_transferred*/) {
-                  auto lock = session->connection->handler_runner->continue_lock();
-                  if(!lock)
-                    return;
-                  if(!ec)
-                    read_chunked_transfer_encoded(session, chunk_size_streambuf);
-                  else
-                    this->on_error(session->request, ec);
-                });
-              }
-              else if(this->on_error)
-                this->on_error(session->request, ec);
-            });
-          }
-          else if(2 + chunk_size > num_additional_bytes) { // If only end of chunk remains unread (\n or \r\n)
-            // Remove "\r\n"
-            if(2 + chunk_size - num_additional_bytes == 1)
-              istream.get();
-            auto null_buffer = std::make_shared<asio::streambuf>(2);
-            asio::async_read(*session->connection->socket, *null_buffer, asio::transfer_exactly(2 + chunk_size - num_additional_bytes), [this, session, chunk_size_streambuf, null_buffer](const error_code &ec, size_t /*bytes_transferred*/) {
-              auto lock = session->connection->handler_runner->continue_lock();
-              if(!lock)
-                return;
-              if(!ec)
-                read_chunked_transfer_encoded(session, chunk_size_streambuf);
-              else
-                this->on_error(session->request, ec);
-            });
-          }
-          else {
-            // Remove "\r\n"
-            istream.get();
-            istream.get();
-
-            read_chunked_transfer_encoded(session, chunk_size_streambuf);
-          }
-        }
-        else if(this->on_error)
-          this->on_error(session->request, ec);
-      });
-    }
-
-    void find_resource(const std::shared_ptr<Session> &session) {
-      // Upgrade connection
-      if(on_upgrade) {
-        auto it = session->request->header.find("Upgrade");
-        if(it != session->request->header.end()) {
-          // remove connection from connections
-          {
-            LockGuard lock(connections->mutex);
-            auto it = connections->set.find(session->connection.get());
-            if(it != connections->set.end())
-              connections->set.erase(it);
-          }
-
-          on_upgrade(session->connection->socket, session->request);
-          return;
-        }
-      }
-      // Find path- and method-match, and call write
-      for(auto &regex_method : resource) {
-        auto it = regex_method.second.find(session->request->method);
-        if(it != regex_method.second.end()) {
-          regex::smatch sm_res;
-          if(regex::regex_match(session->request->path, sm_res, regex_method.first)) {
-            session->request->path_match = std::move(sm_res);
-            write(session, it->second);
-            return;
-          }
-        }
-      }
-      auto it = default_resource.find(session->request->method);
-      if(it != default_resource.end())
-        write(session, it->second);
-    }
-
-    void write(const std::shared_ptr<Session> &session,
-               std::function<void(std::shared_ptr<typename ServerBase<socket_type>::Response>, std::shared_ptr<typename ServerBase<socket_type>::Request>)> &resource_function) {
-      auto response = std::shared_ptr<Response>(new Response(session, config.timeout_content), [this](Response *response_ptr) {
-        auto response = std::shared_ptr<Response>(response_ptr);
-        response->send_on_delete([this, response](const error_code &ec) {
-          response->session->connection->cancel_timeout();
-          if(!ec) {
-            if(response->close_connection_after_response)
-              return;
-
-            auto range = response->session->request->header.equal_range("Connection");
-            for(auto it = range.first; it != range.second; it++) {
-              if(case_insensitive_equal(it->second, "close"))
-                return;
-              else if(case_insensitive_equal(it->second, "keep-alive")) {
-                auto new_session = std::make_shared<Session>(this->config.max_request_streambuf_size, response->session->connection);
-                this->read(new_session);
-                return;
-              }
-            }
-            if(response->session->request->http_version >= "1.1") {
-              auto new_session = std::make_shared<Session>(this->config.max_request_streambuf_size, response->session->connection);
-              this->read(new_session);
-              return;
-            }
-          }
-          else if(this->on_error)
-            this->on_error(response->session->request, ec);
-        });
-      });
-
-      try {
-        resource_function(response, session->request);
-      }
-      catch(const std::exception &) {
-        if(on_error)
-          on_error(session->request, make_error_code::make_error_code(errc::operation_canceled));
-        return;
-      }
-    }
-  };
-
-  template <class socket_type>
-  class Server : public ServerBase<socket_type> {};
-
-  using HTTP = asio::ip::tcp::socket;
-
-  template <>
-  class Server<HTTP> : public ServerBase<HTTP> {
-  public:
-    /// Constructs a server object.
-    Server() noexcept : ServerBase<HTTP>::ServerBase(80) {}
-
-  protected:
-    void accept() override {
-      auto connection = create_connection(*io_service);
-
-      acceptor->async_accept(*connection->socket, [this, connection](const error_code &ec) {
-        auto lock = connection->handler_runner->continue_lock();
-        if(!lock)
-          return;
-
-        // Immediately start accepting a new connection (unless io_service has been stopped)
-        if(ec != error::operation_aborted)
-          this->accept();
-
-        auto session = std::make_shared<Session>(config.max_request_streambuf_size, connection);
-
-        if(!ec) {
-          asio::ip::tcp::no_delay option(true);
-          error_code ec;
-          session->connection->socket->set_option(option, ec);
-
-          this->read(session);
-        }
-        else if(this->on_error)
-          this->on_error(session->request, ec);
-      });
-    }
-  };
-} // namespace SimpleWeb
-
-#endif /* SIMPLE_WEB_SERVER_HTTP_HPP */
diff --git a/third_party/Simple-web-server/repo/server_https.hpp b/third_party/Simple-web-server/repo/server_https.hpp
deleted file mode 100644
index 67b84916..00000000
--- a/third_party/Simple-web-server/repo/server_https.hpp
+++ /dev/null
@@ -1,102 +0,0 @@
-#ifndef SIMPLE_WEB_SERVER_HTTPS_HPP
-#define SIMPLE_WEB_SERVER_HTTPS_HPP
-
-#include "server_http.hpp"
-
-#ifdef ASIO_STANDALONE
-#include <asio/ssl.hpp>
-#else
-#include <boost/asio/ssl.hpp>
-#endif
-
-#include <algorithm>
-#include <openssl/ssl.h>
-
-namespace SimpleWeb {
-  using HTTPS = asio::ssl::stream<asio::ip::tcp::socket>;
-
-  template <>
-  class Server<HTTPS> : public ServerBase<HTTPS> {
-    bool set_session_id_context = false;
-
-  public:
-    /**
-     * Constructs a server object.
-     *
-     * @param certification_file Sends the given certification file to client.
-     * @param private_key_file   Specifies the file containing the private key for certification_file.
-     * @param verify_file        If non-empty, use this certificate authority file to perform verification of client's certificate and hostname according to RFC 2818.
-     */
-    Server(const std::string &certification_file, const std::string &private_key_file, const std::string &verify_file = std::string())
-        : ServerBase<HTTPS>::ServerBase(443),
-#if(ASIO_STANDALONE && ASIO_VERSION >= 101300) || BOOST_ASIO_VERSION >= 101300
-          context(asio::ssl::context::tls_server) {
-      // Disabling TLS 1.0 and 1.1 (see RFC 8996)
-      context.set_options(asio::ssl::context::no_tlsv1);
-      context.set_options(asio::ssl::context::no_tlsv1_1);
-#else
-          context(asio::ssl::context::tlsv12) {
-#endif
-
-      context.use_certificate_chain_file(certification_file);
-      context.use_private_key_file(private_key_file, asio::ssl::context::pem);
-
-      if(verify_file.size() > 0) {
-        context.load_verify_file(verify_file);
-        context.set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert | asio::ssl::verify_client_once);
-        set_session_id_context = true;
-      }
-    }
-
-  protected:
-    asio::ssl::context context;
-
-    void after_bind() override {
-      if(set_session_id_context) {
-        // Creating session_id_context from address:port but reversed due to small SSL_MAX_SSL_SESSION_ID_LENGTH
-        auto session_id_context = std::to_string(acceptor->local_endpoint().port()) + ':';
-        session_id_context.append(config.address.rbegin(), config.address.rend());
-        SSL_CTX_set_session_id_context(context.native_handle(),
-                                       reinterpret_cast<const unsigned char *>(session_id_context.data()),
-                                       static_cast<unsigned int>(std::min<std::size_t>(session_id_context.size(), SSL_MAX_SSL_SESSION_ID_LENGTH)));
-      }
-    }
-
-    void accept() override {
-      auto connection = create_connection(*io_service, context);
-
-      acceptor->async_accept(connection->socket->lowest_layer(), [this, connection](const error_code &ec) {
-        auto lock = connection->handler_runner->continue_lock();
-        if(!lock)
-          return;
-
-        if(ec != error::operation_aborted)
-          this->accept();
-
-        auto session = std::make_shared<Session>(config.max_request_streambuf_size, connection);
-
-        if(!ec) {
-          asio::ip::tcp::no_delay option(true);
-          error_code ec;
-          session->connection->socket->lowest_layer().set_option(option, ec);
-
-          session->connection->set_timeout(config.timeout_request);
-          session->connection->socket->async_handshake(asio::ssl::stream_base::server, [this, session](const error_code &ec) {
-            session->connection->cancel_timeout();
-            auto lock = session->connection->handler_runner->continue_lock();
-            if(!lock)
-              return;
-            if(!ec)
-              this->read(session);
-            else if(this->on_error)
-              this->on_error(session->request, ec);
-          });
-        }
-        else if(this->on_error)
-          this->on_error(session->request, ec);
-      });
-    }
-  };
-} // namespace SimpleWeb
-
-#endif /* SIMPLE_WEB_SERVER_HTTPS_HPP */
diff --git a/third_party/Simple-web-server/repo/status_code.hpp b/third_party/Simple-web-server/repo/status_code.hpp
deleted file mode 100644
index 9f9ecc56..00000000
--- a/third_party/Simple-web-server/repo/status_code.hpp
+++ /dev/null
@@ -1,176 +0,0 @@
-#ifndef SIMPLE_WEB_STATUS_CODE_HPP
-#define SIMPLE_WEB_STATUS_CODE_HPP
-
-#include <cstdlib>
-#include <map>
-#include <string>
-#include <unordered_map>
-#include <vector>
-
-namespace SimpleWeb {
-  enum class StatusCode {
-    unknown = 0,
-    information_continue = 100,
-    information_switching_protocols,
-    information_processing,
-    success_ok = 200,
-    success_created,
-    success_accepted,
-    success_non_authoritative_information,
-    success_no_content,
-    success_reset_content,
-    success_partial_content,
-    success_multi_status,
-    success_already_reported,
-    success_im_used = 226,
-    redirection_multiple_choices = 300,
-    redirection_moved_permanently,
-    redirection_found,
-    redirection_see_other,
-    redirection_not_modified,
-    redirection_use_proxy,
-    redirection_switch_proxy,
-    redirection_temporary_redirect,
-    redirection_permanent_redirect,
-    client_error_bad_request = 400,
-    client_error_unauthorized,
-    client_error_payment_required,
-    client_error_forbidden,
-    client_error_not_found,
-    client_error_method_not_allowed,
-    client_error_not_acceptable,
-    client_error_proxy_authentication_required,
-    client_error_request_timeout,
-    client_error_conflict,
-    client_error_gone,
-    client_error_length_required,
-    client_error_precondition_failed,
-    client_error_payload_too_large,
-    client_error_uri_too_long,
-    client_error_unsupported_media_type,
-    client_error_range_not_satisfiable,
-    client_error_expectation_failed,
-    client_error_im_a_teapot,
-    client_error_misdirection_required = 421,
-    client_error_unprocessable_entity,
-    client_error_locked,
-    client_error_failed_dependency,
-    client_error_upgrade_required = 426,
-    client_error_precondition_required = 428,
-    client_error_too_many_requests,
-    client_error_request_header_fields_too_large = 431,
-    client_error_unavailable_for_legal_reasons = 451,
-    server_error_internal_server_error = 500,
-    server_error_not_implemented,
-    server_error_bad_gateway,
-    server_error_service_unavailable,
-    server_error_gateway_timeout,
-    server_error_http_version_not_supported,
-    server_error_variant_also_negotiates,
-    server_error_insufficient_storage,
-    server_error_loop_detected,
-    server_error_not_extended = 510,
-    server_error_network_authentication_required
-  };
-
-  inline const std::map<StatusCode, std::string> &status_code_strings() {
-    static const std::map<StatusCode, std::string> status_code_strings = {
-        {StatusCode::unknown, ""},
-        {StatusCode::information_continue, "100 Continue"},
-        {StatusCode::information_switching_protocols, "101 Switching Protocols"},
-        {StatusCode::information_processing, "102 Processing"},
-        {StatusCode::success_ok, "200 OK"},
-        {StatusCode::success_created, "201 Created"},
-        {StatusCode::success_accepted, "202 Accepted"},
-        {StatusCode::success_non_authoritative_information, "203 Non-Authoritative Information"},
-        {StatusCode::success_no_content, "204 No Content"},
-        {StatusCode::success_reset_content, "205 Reset Content"},
-        {StatusCode::success_partial_content, "206 Partial Content"},
-        {StatusCode::success_multi_status, "207 Multi-Status"},
-        {StatusCode::success_already_reported, "208 Already Reported"},
-        {StatusCode::success_im_used, "226 IM Used"},
-        {StatusCode::redirection_multiple_choices, "300 Multiple Choices"},
-        {StatusCode::redirection_moved_permanently, "301 Moved Permanently"},
-        {StatusCode::redirection_found, "302 Found"},
-        {StatusCode::redirection_see_other, "303 See Other"},
-        {StatusCode::redirection_not_modified, "304 Not Modified"},
-        {StatusCode::redirection_use_proxy, "305 Use Proxy"},
-        {StatusCode::redirection_switch_proxy, "306 Switch Proxy"},
-        {StatusCode::redirection_temporary_redirect, "307 Temporary Redirect"},
-        {StatusCode::redirection_permanent_redirect, "308 Permanent Redirect"},
-        {StatusCode::client_error_bad_request, "400 Bad Request"},
-        {StatusCode::client_error_unauthorized, "401 Unauthorized"},
-        {StatusCode::client_error_payment_required, "402 Payment Required"},
-        {StatusCode::client_error_forbidden, "403 Forbidden"},
-        {StatusCode::client_error_not_found, "404 Not Found"},
-        {StatusCode::client_error_method_not_allowed, "405 Method Not Allowed"},
-        {StatusCode::client_error_not_acceptable, "406 Not Acceptable"},
-        {StatusCode::client_error_proxy_authentication_required, "407 Proxy Authentication Required"},
-        {StatusCode::client_error_request_timeout, "408 Request Timeout"},
-        {StatusCode::client_error_conflict, "409 Conflict"},
-        {StatusCode::client_error_gone, "410 Gone"},
-        {StatusCode::client_error_length_required, "411 Length Required"},
-        {StatusCode::client_error_precondition_failed, "412 Precondition Failed"},
-        {StatusCode::client_error_payload_too_large, "413 Payload Too Large"},
-        {StatusCode::client_error_uri_too_long, "414 URI Too Long"},
-        {StatusCode::client_error_unsupported_media_type, "415 Unsupported Media Type"},
-        {StatusCode::client_error_range_not_satisfiable, "416 Range Not Satisfiable"},
-        {StatusCode::client_error_expectation_failed, "417 Expectation Failed"},
-        {StatusCode::client_error_im_a_teapot, "418 I'm a teapot"},
-        {StatusCode::client_error_misdirection_required, "421 Misdirected Request"},
-        {StatusCode::client_error_unprocessable_entity, "422 Unprocessable Entity"},
-        {StatusCode::client_error_locked, "423 Locked"},
-        {StatusCode::client_error_failed_dependency, "424 Failed Dependency"},
-        {StatusCode::client_error_upgrade_required, "426 Upgrade Required"},
-        {StatusCode::client_error_precondition_required, "428 Precondition Required"},
-        {StatusCode::client_error_too_many_requests, "429 Too Many Requests"},
-        {StatusCode::client_error_request_header_fields_too_large, "431 Request Header Fields Too Large"},
-        {StatusCode::client_error_unavailable_for_legal_reasons, "451 Unavailable For Legal Reasons"},
-        {StatusCode::server_error_internal_server_error, "500 Internal Server Error"},
-        {StatusCode::server_error_not_implemented, "501 Not Implemented"},
-        {StatusCode::server_error_bad_gateway, "502 Bad Gateway"},
-        {StatusCode::server_error_service_unavailable, "503 Service Unavailable"},
-        {StatusCode::server_error_gateway_timeout, "504 Gateway Timeout"},
-        {StatusCode::server_error_http_version_not_supported, "505 HTTP Version Not Supported"},
-        {StatusCode::server_error_variant_also_negotiates, "506 Variant Also Negotiates"},
-        {StatusCode::server_error_insufficient_storage, "507 Insufficient Storage"},
-        {StatusCode::server_error_loop_detected, "508 Loop Detected"},
-        {StatusCode::server_error_not_extended, "510 Not Extended"},
-        {StatusCode::server_error_network_authentication_required, "511 Network Authentication Required"}};
-    return status_code_strings;
-  }
-
-  inline StatusCode status_code(const std::string &status_code_string) noexcept {
-    if(status_code_string.size() < 3)
-      return StatusCode::unknown;
-
-    auto number = status_code_string.substr(0, 3);
-    if(number[0] < '0' || number[0] > '9' || number[1] < '0' || number[1] > '9' || number[2] < '0' || number[2] > '9')
-      return StatusCode::unknown;
-
-    class StringToStatusCode : public std::unordered_map<std::string, SimpleWeb::StatusCode> {
-    public:
-      StringToStatusCode() {
-        for(auto &status_code : status_code_strings())
-          emplace(status_code.second.substr(0, 3), status_code.first);
-      }
-    };
-    static StringToStatusCode string_to_status_code;
-
-    auto pos = string_to_status_code.find(number);
-    if(pos == string_to_status_code.end())
-      return static_cast<StatusCode>(atoi(number.c_str()));
-    return pos->second;
-  }
-
-  inline const std::string &status_code(StatusCode status_code_enum) noexcept {
-    auto pos = status_code_strings().find(status_code_enum);
-    if(pos == status_code_strings().end()) {
-      static std::string empty_string;
-      return empty_string;
-    }
-    return pos->second;
-  }
-} // namespace SimpleWeb
-
-#endif // SIMPLE_WEB_STATUS_CODE_HPP
diff --git a/third_party/Simple-web-server/repo/tests/CMakeLists.txt b/third_party/Simple-web-server/repo/tests/CMakeLists.txt
deleted file mode 100644
index 9a577279..00000000
--- a/third_party/Simple-web-server/repo/tests/CMakeLists.txt
+++ /dev/null
@@ -1,60 +0,0 @@
-if(NOT MSVC)
-    add_compile_options(-fno-access-control)
-    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
-        add_compile_options(-Wno-thread-safety)
-    endif()
-    
-    if(BUILD_TESTING)
-        add_executable(sws_io_test io_test.cpp)
-        target_link_libraries(sws_io_test simple-web-server)
-        add_test(NAME sws_io_test COMMAND sws_io_test)
-    
-        add_executable(sws_parse_test parse_test.cpp)
-        target_link_libraries(sws_parse_test simple-web-server)
-        add_test(NAME sws_parse_test COMMAND sws_parse_test)
-    endif()
-endif()
-
-if(OPENSSL_FOUND AND BUILD_TESTING)
-    add_executable(sws_crypto_test crypto_test.cpp)
-    target_link_libraries(sws_crypto_test simple-web-server)
-    add_test(NAME sws_crypto_test COMMAND sws_crypto_test)
-endif()
-
-if(BUILD_TESTING)
-    add_executable(status_code_test status_code_test.cpp)
-    target_link_libraries(status_code_test simple-web-server)
-    add_test(NAME status_code_test COMMAND status_code_test)
-endif()
-
-if(BUILD_FUZZING)
-    add_executable(percent_decode fuzzers/percent_decode.cpp)
-    target_compile_options(percent_decode PRIVATE -fsanitize=address,fuzzer)
-    target_link_options(percent_decode PRIVATE -fsanitize=address,fuzzer)
-    target_link_libraries(percent_decode simple-web-server)
-    
-    add_executable(query_string_parse fuzzers/query_string_parse.cpp)
-    target_compile_options(query_string_parse PRIVATE -fsanitize=address,fuzzer)
-    target_link_options(query_string_parse PRIVATE -fsanitize=address,fuzzer)
-    target_link_libraries(query_string_parse simple-web-server)
-    
-    add_executable(http_header_parse fuzzers/http_header_parse.cpp)
-    target_compile_options(http_header_parse PRIVATE -fsanitize=address,fuzzer)
-    target_link_options(http_header_parse PRIVATE -fsanitize=address,fuzzer)
-    target_link_libraries(http_header_parse simple-web-server)
-    
-    add_executable(http_header_field_value_semicolon_separated_attributes_parse fuzzers/http_header_field_value_semicolon_separated_attributes_parse.cpp)
-    target_compile_options(http_header_field_value_semicolon_separated_attributes_parse PRIVATE -fsanitize=address,fuzzer)
-    target_link_options(http_header_field_value_semicolon_separated_attributes_parse PRIVATE -fsanitize=address,fuzzer)
-    target_link_libraries(http_header_field_value_semicolon_separated_attributes_parse simple-web-server)
-    
-    add_executable(request_message_parse fuzzers/request_message_parse.cpp)
-    target_compile_options(request_message_parse PRIVATE -fsanitize=address,fuzzer)
-    target_link_options(request_message_parse PRIVATE -fsanitize=address,fuzzer)
-    target_link_libraries(request_message_parse simple-web-server)
-    
-    add_executable(response_message_parse fuzzers/response_message_parse.cpp)
-    target_compile_options(response_message_parse PRIVATE -fsanitize=address,fuzzer)
-    target_link_options(response_message_parse PRIVATE -fsanitize=address,fuzzer)
-    target_link_libraries(response_message_parse simple-web-server)
-endif()
\ No newline at end of file
diff --git a/third_party/Simple-web-server/repo/tests/assert.hpp b/third_party/Simple-web-server/repo/tests/assert.hpp
deleted file mode 100644
index 7d55ec7b..00000000
--- a/third_party/Simple-web-server/repo/tests/assert.hpp
+++ /dev/null
@@ -1,9 +0,0 @@
-#ifndef SIMPLE_WEB_ASSERT_HPP
-#define SIMPLE_WEB_ASSERT_HPP
-
-#include <cstdlib>
-#include <iostream>
-
-#define ASSERT(e) ((void)((e) ? ((void)0) : ((void)(std::cerr << "Assertion failed: (" << #e << "), function " << __func__ << ", file " << __FILE__ << ", line " << __LINE__ << ".\n"), std::abort())))
-
-#endif /* SIMPLE_WEB_ASSERT_HPP */
diff --git a/third_party/Simple-web-server/repo/tests/crypto_test.cpp b/third_party/Simple-web-server/repo/tests/crypto_test.cpp
deleted file mode 100644
index 1456cc79..00000000
--- a/third_party/Simple-web-server/repo/tests/crypto_test.cpp
+++ /dev/null
@@ -1,73 +0,0 @@
-#include "assert.hpp"
-#include "crypto.hpp"
-#include <vector>
-
-using namespace std;
-using namespace SimpleWeb;
-
-const vector<pair<string, string>> base64_string_tests = {
-    {"", ""},
-    {"f", "Zg=="},
-    {"fo", "Zm8="},
-    {"foo", "Zm9v"},
-    {"foob", "Zm9vYg=="},
-    {"fooba", "Zm9vYmE="},
-    {"foobar", "Zm9vYmFy"},
-    {"The itsy bitsy spider climbed up the waterspout.\r\nDown came the rain\r\nand washed the spider out.\r\nOut came the sun\r\nand dried up all the rain\r\nand the itsy bitsy spider climbed up the spout again.",
-     "VGhlIGl0c3kgYml0c3kgc3BpZGVyIGNsaW1iZWQgdXAgdGhlIHdhdGVyc3BvdXQuDQpEb3duIGNhbWUgdGhlIHJhaW4NCmFuZCB3YXNoZWQgdGhlIHNwaWRlciBvdXQuDQpPdXQgY2FtZSB0aGUgc3VuDQphbmQgZHJpZWQgdXAgYWxsIHRoZSByYWluDQphbmQgdGhlIGl0c3kgYml0c3kgc3BpZGVyIGNsaW1iZWQgdXAgdGhlIHNwb3V0IGFnYWluLg=="}};
-
-const vector<pair<string, string>> md5_string_tests = {
-    {"", "d41d8cd98f00b204e9800998ecf8427e"},
-    {"The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6"}};
-
-const vector<pair<string, string>> sha1_string_tests = {
-    {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
-    {"The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"}};
-
-const vector<pair<string, string>> sha256_string_tests = {
-    {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
-    {"The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"}};
-
-const vector<pair<string, string>> sha512_string_tests = {
-    {"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
-    {"The quick brown fox jumps over the lazy dog", "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"}};
-
-int main() {
-  for(auto &string_test : base64_string_tests) {
-    ASSERT(Crypto::Base64::encode(string_test.first) == string_test.second);
-    ASSERT(Crypto::Base64::decode(string_test.second) == string_test.first);
-  }
-
-  for(auto &string_test : md5_string_tests) {
-    ASSERT(Crypto::to_hex_string(Crypto::md5(string_test.first)) == string_test.second);
-    stringstream ss(string_test.first);
-    ASSERT(Crypto::to_hex_string(Crypto::md5(ss)) == string_test.second);
-  }
-
-  for(auto &string_test : sha1_string_tests) {
-    ASSERT(Crypto::to_hex_string(Crypto::sha1(string_test.first)) == string_test.second);
-    stringstream ss(string_test.first);
-    ASSERT(Crypto::to_hex_string(Crypto::sha1(ss)) == string_test.second);
-  }
-
-  for(auto &string_test : sha256_string_tests) {
-    ASSERT(Crypto::to_hex_string(Crypto::sha256(string_test.first)) == string_test.second);
-    stringstream ss(string_test.first);
-    ASSERT(Crypto::to_hex_string(Crypto::sha256(ss)) == string_test.second);
-  }
-
-  for(auto &string_test : sha512_string_tests) {
-    ASSERT(Crypto::to_hex_string(Crypto::sha512(string_test.first)) == string_test.second);
-    stringstream ss(string_test.first);
-    ASSERT(Crypto::to_hex_string(Crypto::sha512(ss)) == string_test.second);
-  }
-
-  // Testing iterations
-  ASSERT(Crypto::to_hex_string(Crypto::sha1("Test", 1)) == "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa");
-  ASSERT(Crypto::to_hex_string(Crypto::sha1("Test", 2)) == "af31c6cbdecd88726d0a9b3798c71ef41f1624d5");
-  stringstream ss("Test");
-  ASSERT(Crypto::to_hex_string(Crypto::sha1(ss, 2)) == "af31c6cbdecd88726d0a9b3798c71ef41f1624d5");
-
-  ASSERT(Crypto::to_hex_string(Crypto::pbkdf2("Password", "Salt", 4096, 128 / 8)) == "f66df50f8aaa11e4d9721e1312ff2e66");
-  ASSERT(Crypto::to_hex_string(Crypto::pbkdf2("Password", "Salt", 8192, 512 / 8)) == "a941ccbc34d1ee8ebbd1d34824a419c3dc4eac9cbc7c36ae6c7ca8725e2b618a6ad22241e787af937b0960cf85aa8ea3a258f243e05d3cc9b08af5dd93be046c");
-}
diff --git a/third_party/Simple-web-server/repo/tests/fuzzers/README.md b/third_party/Simple-web-server/repo/tests/fuzzers/README.md
deleted file mode 100644
index 0534d5a8..00000000
--- a/third_party/Simple-web-server/repo/tests/fuzzers/README.md
+++ /dev/null
@@ -1,6 +0,0 @@
-Prior to running the fuzzers, build and prepare for instance as follows:
-```sh
-CXX=clang++ cmake -DBUILD_FUZZING=1 ..
-make
-export LSAN_OPTIONS=detect_leaks=0
-```
diff --git a/third_party/Simple-web-server/repo/tests/fuzzers/http_header_field_value_semicolon_separated_attributes_parse.cpp b/third_party/Simple-web-server/repo/tests/fuzzers/http_header_field_value_semicolon_separated_attributes_parse.cpp
deleted file mode 100644
index e45a2db4..00000000
--- a/third_party/Simple-web-server/repo/tests/fuzzers/http_header_field_value_semicolon_separated_attributes_parse.cpp
+++ /dev/null
@@ -1,6 +0,0 @@
-#include "utility.hpp"
-
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
-  SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse(std::string(reinterpret_cast<const char *>(data), size));
-  return 0;
-}
diff --git a/third_party/Simple-web-server/repo/tests/fuzzers/http_header_parse.cpp b/third_party/Simple-web-server/repo/tests/fuzzers/http_header_parse.cpp
deleted file mode 100644
index e90c28f6..00000000
--- a/third_party/Simple-web-server/repo/tests/fuzzers/http_header_parse.cpp
+++ /dev/null
@@ -1,9 +0,0 @@
-#include "utility.hpp"
-#include <sstream>
-
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
-  std::stringstream ss;
-  ss << std::string(reinterpret_cast<const char *>(data), size);
-  SimpleWeb::HttpHeader::parse(ss);
-  return 0;
-}
diff --git a/third_party/Simple-web-server/repo/tests/fuzzers/percent_decode.cpp b/third_party/Simple-web-server/repo/tests/fuzzers/percent_decode.cpp
deleted file mode 100644
index c1084642..00000000
--- a/third_party/Simple-web-server/repo/tests/fuzzers/percent_decode.cpp
+++ /dev/null
@@ -1,6 +0,0 @@
-#include "utility.hpp"
-
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
-  SimpleWeb::Percent::decode(std::string(reinterpret_cast<const char *>(data), size));
-  return 0;
-}
diff --git a/third_party/Simple-web-server/repo/tests/fuzzers/query_string_parse.cpp b/third_party/Simple-web-server/repo/tests/fuzzers/query_string_parse.cpp
deleted file mode 100644
index 76967ec0..00000000
--- a/third_party/Simple-web-server/repo/tests/fuzzers/query_string_parse.cpp
+++ /dev/null
@@ -1,6 +0,0 @@
-#include "utility.hpp"
-
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
-  SimpleWeb::QueryString::parse(std::string(reinterpret_cast<const char *>(data), size));
-  return 0;
-}
diff --git a/third_party/Simple-web-server/repo/tests/fuzzers/request_message_parse.cpp b/third_party/Simple-web-server/repo/tests/fuzzers/request_message_parse.cpp
deleted file mode 100644
index 51dfb29f..00000000
--- a/third_party/Simple-web-server/repo/tests/fuzzers/request_message_parse.cpp
+++ /dev/null
@@ -1,11 +0,0 @@
-#include "utility.hpp"
-#include <sstream>
-
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
-  std::stringstream ss;
-  ss << std::string(reinterpret_cast<const char *>(data), size);
-  std::string method, path, query_string, version;
-  SimpleWeb::CaseInsensitiveMultimap header;
-  SimpleWeb::RequestMessage::parse(ss, method, path, query_string, version, header);
-  return 0;
-}
diff --git a/third_party/Simple-web-server/repo/tests/fuzzers/response_message_parse.cpp b/third_party/Simple-web-server/repo/tests/fuzzers/response_message_parse.cpp
deleted file mode 100644
index 247b66df..00000000
--- a/third_party/Simple-web-server/repo/tests/fuzzers/response_message_parse.cpp
+++ /dev/null
@@ -1,11 +0,0 @@
-#include "utility.hpp"
-#include <sstream>
-
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
-  std::stringstream ss;
-  ss << std::string(reinterpret_cast<const char *>(data), size);
-  std::string version, status_code;
-  SimpleWeb::CaseInsensitiveMultimap header;
-  SimpleWeb::ResponseMessage::parse(ss, version, status_code, header);
-  return 0;
-}
diff --git a/third_party/Simple-web-server/repo/tests/io_test.cpp b/third_party/Simple-web-server/repo/tests/io_test.cpp
deleted file mode 100644
index c2370f51..00000000
--- a/third_party/Simple-web-server/repo/tests/io_test.cpp
+++ /dev/null
@@ -1,747 +0,0 @@
-#include "assert.hpp"
-#include "client_http.hpp"
-#include "server_http.hpp"
-#include <future>
-
-using namespace std;
-
-using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
-using HttpClient = SimpleWeb::Client<SimpleWeb::HTTP>;
-
-int main() {
-  // Test ScopeRunner
-  {
-    SimpleWeb::ScopeRunner scope_runner;
-    std::thread cancel_thread;
-    {
-      ASSERT(scope_runner.count == 0);
-      auto lock = scope_runner.continue_lock();
-      ASSERT(lock);
-      ASSERT(scope_runner.count == 1);
-      {
-        auto lock = scope_runner.continue_lock();
-        ASSERT(lock);
-        ASSERT(scope_runner.count == 2);
-      }
-      ASSERT(scope_runner.count == 1);
-      cancel_thread = thread([&scope_runner] {
-        scope_runner.stop();
-        ASSERT(scope_runner.count == -1);
-      });
-      this_thread::sleep_for(chrono::milliseconds(500));
-      ASSERT(scope_runner.count == 1);
-    }
-    cancel_thread.join();
-    ASSERT(scope_runner.count == -1);
-    auto lock = scope_runner.continue_lock();
-    ASSERT(!lock);
-    scope_runner.stop();
-    ASSERT(scope_runner.count == -1);
-
-    scope_runner.count = 0;
-
-    vector<thread> threads;
-    for(size_t c = 0; c < 100; ++c) {
-      threads.emplace_back([&scope_runner] {
-        auto lock = scope_runner.continue_lock();
-        ASSERT(scope_runner.count > 0);
-      });
-    }
-    for(auto &thread : threads)
-      thread.join();
-    ASSERT(scope_runner.count == 0);
-  }
-
-  HttpServer server;
-  server.config.port = 8080;
-
-  server.resource["^/string$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    auto content = request->content.string();
-    ASSERT(content == request->content.string());
-
-    *response << "HTTP/1.1 200 OK\r\nContent-Length: " << content.length() << "\r\n\r\n"
-              << content;
-
-    ASSERT(!request->remote_endpoint().address().to_string().empty());
-    ASSERT(request->remote_endpoint().port() != 0);
-  };
-
-  server.resource["^/string/dup$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    auto content = request->content.string();
-
-    // Send content twice, before it has a chance to be written to the socket.
-    *response << "HTTP/1.1 200 OK\r\nContent-Length: " << (content.length() * 2) << "\r\n\r\n"
-              << content;
-    response->send();
-    *response << content;
-    response->send();
-
-    ASSERT(!request->remote_endpoint().address().to_string().empty());
-    ASSERT(request->remote_endpoint().port() != 0);
-  };
-
-  server.resource["^/string2$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    response->write(request->content.string());
-  };
-
-  server.resource["^/string3$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    stringstream stream;
-    stream << request->content.rdbuf();
-    response->write(stream);
-  };
-
-  server.resource["^/string4$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> /*request*/) {
-    response->write(SimpleWeb::StatusCode::client_error_forbidden, {{"Test1", "test2"}, {"tesT3", "test4"}});
-  };
-
-  server.resource["^/info$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    stringstream content_stream;
-    content_stream << request->method << " " << request->path << " " << request->http_version << " ";
-    content_stream << request->header.find("test parameter")->second;
-
-    content_stream.seekp(0, ios::end);
-
-    *response << "HTTP/1.1 200 OK\r\nContent-Length: " << content_stream.tellp() << "\r\n\r\n"
-              << content_stream.rdbuf();
-  };
-
-  server.resource["^/work$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> /*request*/) {
-    thread work_thread([response] {
-      this_thread::sleep_for(chrono::seconds(5));
-      response->write("Work done");
-    });
-    work_thread.detach();
-  };
-
-  server.resource["^/match/([0-9]+)$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    string number = request->path_match[1];
-    *response << "HTTP/1.1 200 OK\r\nContent-Length: " << number.length() << "\r\n\r\n"
-              << number;
-  };
-
-  server.resource["^/header$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    auto content = request->header.find("test1")->second + request->header.find("test2")->second;
-
-    *response << "HTTP/1.1 200 OK\r\nContent-Length: " << content.length() << "\r\n\r\n"
-              << content;
-  };
-
-  server.resource["^/query_string$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    ASSERT(request->path == "/query_string");
-    ASSERT(request->query_string == "testing");
-    auto queries = request->parse_query_string();
-    auto it = queries.find("Testing");
-    ASSERT(it != queries.end() && it->first == "testing" && it->second == "");
-    response->write(request->query_string);
-  };
-
-  server.resource["^/chunked$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    ASSERT(request->path == "/chunked");
-
-    ASSERT(request->content.string() == "SimpleWeb in\r\n\r\nchunks.");
-
-    response->write("6\r\nSimple\r\n3\r\nWeb\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n", {{"Transfer-Encoding", "chunked"}});
-  };
-
-  server.resource["^/chunked2$"]["POST"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> request) {
-    ASSERT(request->path == "/chunked2");
-
-    ASSERT(request->content.string() == "HelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorld");
-
-    response->write("258\r\nHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorld\r\n0\r\n\r\n", {{"Transfer-Encoding", "chunked"}});
-  };
-
-  server.resource["^/event-stream1$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> /*request*/) {
-    thread work_thread([response] {
-      response->close_connection_after_response = true; // Unspecified content length
-
-      // Send header
-      promise<bool> header_error;
-      response->write({{"Content-Type", "text/event-stream"}});
-      response->send([&header_error](const SimpleWeb::error_code &ec) {
-        header_error.set_value(static_cast<bool>(ec));
-      });
-      ASSERT(!header_error.get_future().get());
-
-      *response << "data: 1\n\n";
-      promise<bool> error;
-      response->send([&error](const SimpleWeb::error_code &ec) {
-        error.set_value(static_cast<bool>(ec));
-      });
-      ASSERT(!error.get_future().get());
-
-      // Write result
-      *response << "data: 2\n\n";
-    });
-    work_thread.detach();
-  };
-
-  server.resource["^/event-stream2$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> /*request*/) {
-    thread work_thread([response] {
-      response->close_connection_after_response = true; // Unspecified content length
-
-      // Send header
-      promise<bool> header_error;
-      response->write({{"Content-Type", "text/event-stream"}});
-      response->send([&header_error](const SimpleWeb::error_code &ec) {
-        header_error.set_value(static_cast<bool>(ec));
-      });
-      ASSERT(!header_error.get_future().get());
-
-      *response << "data: 1\r\n\r\n";
-      promise<bool> error;
-      response->send([&error](const SimpleWeb::error_code &ec) {
-        error.set_value(static_cast<bool>(ec));
-      });
-      ASSERT(!error.get_future().get());
-
-      // Write result
-      *response << "data: 2\r\n\r\n";
-    });
-    work_thread.detach();
-  };
-
-  server.resource["^/session-close$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> /*request*/) {
-    response->close_connection_after_response = true; // Unspecified content length
-    response->write("test", {{"Session", "close"}});
-  };
-  server.resource["^/session-close-without-correct-header$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> /*request*/) {
-    response->close_connection_after_response = true; // Unspecified content length
-    response->write("test");
-  };
-
-  server.resource["^/non-standard-line-endings1$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> /*request*/) {
-    *response << "HTTP/1.1 200 OK\r\nname: value\n\n";
-  };
-
-  server.resource["^/non-standard-line-endings2$"]["GET"] = [](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> /*request*/) {
-    *response << "HTTP/1.1 200 OK\nname: value\n\n";
-  };
-
-  std::string long_response;
-  for(int c = 0; c < 1000; ++c)
-    long_response += to_string(c);
-  server.resource["^/long-response$"]["GET"] = [&long_response](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> /*request*/) {
-    response->write(long_response, {{"name", "value"}});
-  };
-
-  thread server_thread([&server]() {
-    // Start server
-    server.start();
-  });
-
-  this_thread::sleep_for(chrono::seconds(1));
-
-  server.stop();
-  server_thread.join();
-
-  server_thread = thread([&server]() {
-    // Start server
-    server.start();
-  });
-
-  this_thread::sleep_for(chrono::seconds(1));
-
-  // Test various request types
-  {
-    HttpClient client("localhost:8080");
-    {
-      stringstream output;
-      auto r = client.request("POST", "/string", "A string");
-      ASSERT(SimpleWeb::status_code(r->status_code) == SimpleWeb::StatusCode::success_ok);
-      output << r->content.rdbuf();
-      ASSERT(output.str() == "A string");
-    }
-
-    {
-      auto r = client.request("POST", "/string", "A string");
-      ASSERT(SimpleWeb::status_code(r->status_code) == SimpleWeb::StatusCode::success_ok);
-      ASSERT(r->content.string() == "A string");
-      ASSERT(r->content.string() == "A string");
-    }
-
-    {
-      stringstream output;
-      auto r = client.request("POST", "/string2", "A string");
-      ASSERT(SimpleWeb::status_code(r->status_code) == SimpleWeb::StatusCode::success_ok);
-      output << r->content.rdbuf();
-      ASSERT(output.str() == "A string");
-    }
-
-    {
-      stringstream output;
-      auto r = client.request("POST", "/string3", "A string");
-      ASSERT(SimpleWeb::status_code(r->status_code) == SimpleWeb::StatusCode::success_ok);
-      output << r->content.rdbuf();
-      ASSERT(output.str() == "A string");
-    }
-
-    {
-      stringstream output;
-      auto r = client.request("POST", "/string4", "A string");
-      ASSERT(SimpleWeb::status_code(r->status_code) == SimpleWeb::StatusCode::client_error_forbidden);
-      ASSERT(r->header.size() == 3);
-      ASSERT(r->header.find("test1")->second == "test2");
-      ASSERT(r->header.find("tEst3")->second == "test4");
-      ASSERT(r->header.find("content-length")->second == "0");
-      output << r->content.rdbuf();
-      ASSERT(output.str() == "");
-    }
-
-    {
-      stringstream output;
-      stringstream content("A string");
-      auto r = client.request("POST", "/string", content);
-      output << r->content.rdbuf();
-      ASSERT(output.str() == "A string");
-    }
-
-    {
-      // Test rapid calls to Response::send
-      stringstream output;
-      stringstream content("A string\n");
-      auto r = client.request("POST", "/string/dup", content);
-      output << r->content.rdbuf();
-      ASSERT(output.str() == "A string\nA string\n");
-    }
-
-    {
-      stringstream output;
-      auto r = client.request("GET", "/info", "", {{"Test Parameter", "test value"}});
-      output << r->content.rdbuf();
-      ASSERT(output.str() == "GET /info 1.1 test value");
-    }
-
-    {
-      stringstream output;
-      auto r = client.request("GET", "/match/123");
-      output << r->content.rdbuf();
-      ASSERT(output.str() == "123");
-    }
-    {
-      auto r = client.request("POST", "/chunked", "6\r\nSimple\r\n3\r\nWeb\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n", {{"Transfer-Encoding", "chunked"}});
-      ASSERT(r->content.string() == "SimpleWeb in\r\n\r\nchunks.");
-    }
-    {
-      auto r = client.request("POST", "/chunked2", "258\r\nHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorld\r\n0\r\n\r\n", {{"Transfer-Encoding", "chunked"}});
-      ASSERT(r->content.string() == "HelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorldHelloWorld");
-    }
-
-    // Test reconnecting
-    for(int c = 0; c < 20; ++c) {
-      auto r = client.request("GET", "/session-close");
-      ASSERT(r->content.string() == "test");
-    }
-    for(int c = 0; c < 20; ++c) {
-      auto r = client.request("GET", "/session-close-without-correct-header");
-      ASSERT(r->content.string() == "test");
-    }
-
-    // Test non-standard line endings
-    {
-      auto r = client.request("GET", "/non-standard-line-endings1");
-      ASSERT(r->http_version == "1.1");
-      ASSERT(r->status_code == "200 OK");
-      ASSERT(r->header.size() == 1);
-      ASSERT(r->header.begin()->first == "name");
-      ASSERT(r->header.begin()->second == "value");
-      ASSERT(r->content.string().empty());
-    }
-    {
-      auto r = client.request("GET", "/non-standard-line-endings2");
-      ASSERT(r->http_version == "1.1");
-      ASSERT(r->status_code == "200 OK");
-      ASSERT(r->header.size() == 1);
-      ASSERT(r->header.begin()->first == "name");
-      ASSERT(r->header.begin()->second == "value");
-      ASSERT(r->content.string().empty());
-    }
-  }
-  {
-    HttpClient client("localhost:8080");
-
-    HttpClient::Connection *connection;
-    {
-      // test performing the stream version of the request methods first
-      stringstream output;
-      stringstream content("A string");
-      auto r = client.request("POST", "/string", content);
-      output << r->content.rdbuf();
-      ASSERT(output.str() == "A string");
-      ASSERT(client.connections.size() == 1);
-      connection = client.connections.begin()->get();
-    }
-
-    {
-      stringstream output;
-      auto r = client.request("POST", "/string", "A string");
-      output << r->content.rdbuf();
-      ASSERT(output.str() == "A string");
-      ASSERT(client.connections.size() == 1);
-      ASSERT(connection == client.connections.begin()->get());
-    }
-
-    {
-      stringstream output;
-      auto r = client.request("GET", "/header", "", {{"test1", "test"}, {"test2", "ing"}});
-      output << r->content.rdbuf();
-      ASSERT(output.str() == "testing");
-      ASSERT(client.connections.size() == 1);
-      ASSERT(connection == client.connections.begin()->get());
-    }
-
-    {
-      stringstream output;
-      auto r = client.request("GET", "/query_string?testing");
-      ASSERT(r->content.string() == "testing");
-      ASSERT(client.connections.size() == 1);
-      ASSERT(connection == client.connections.begin()->get());
-    }
-  }
-
-  // Test large responses
-  {
-    {
-      HttpClient client("localhost:8080");
-      client.config.max_response_streambuf_size = 400;
-      bool thrown = false;
-      try {
-        auto r = client.request("GET", "/long-response");
-      }
-      catch(...) {
-        thrown = true;
-      }
-      ASSERT(thrown);
-    }
-    HttpClient client("localhost:8080");
-    client.config.max_response_streambuf_size = 400;
-    {
-      size_t calls = 0;
-      bool end = false;
-      std::string content;
-      client.request("GET", "/long-response", [&calls, &content, &end](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
-        ASSERT(!ec);
-        content += response->content.string();
-        calls++;
-        if(calls == 1)
-          ASSERT(response->content.end == false);
-        end = response->content.end;
-      });
-      client.io_service->run();
-      ASSERT(content == long_response);
-      ASSERT(calls > 2);
-      ASSERT(end == true);
-    }
-    {
-      size_t calls = 0;
-      std::string content;
-      client.request("GET", "/long-response", [&calls, &content](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
-        if(calls == 0)
-          ASSERT(!ec);
-        content += response->content.string();
-        calls++;
-        response->close();
-      });
-      SimpleWeb::restart(*client.io_service);
-      client.io_service->run();
-      ASSERT(!content.empty());
-      ASSERT(calls >= 2);
-    }
-  }
-
-  // Test client timeout
-  {
-    HttpClient client("localhost:8080");
-    client.config.timeout = 2;
-    bool thrown = false;
-    try {
-      auto r = client.request("GET", "/work");
-    }
-    catch(...) {
-      thrown = true;
-    }
-    ASSERT(thrown);
-  }
-  {
-    HttpClient client("localhost:8080");
-    client.config.timeout = 2;
-    bool call = false;
-    client.request("GET", "/work", [&call](shared_ptr<HttpClient::Response> /*response*/, const SimpleWeb::error_code &ec) {
-      ASSERT(ec);
-      call = true;
-    });
-    SimpleWeb::restart(*client.io_service);
-    client.io_service->run();
-    ASSERT(call);
-  }
-
-  // Test asynchronous requests
-  {
-    HttpClient client("localhost:8080");
-    bool call = false;
-    client.request("GET", "/match/123", [&call](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
-      ASSERT(!ec);
-      stringstream output;
-      output << response->content.rdbuf();
-      ASSERT(output.str() == "123");
-      call = true;
-    });
-    client.io_service->run();
-    ASSERT(call);
-
-    // Test event-stream
-    {
-      vector<int> calls(4, 0);
-      std::size_t call_num = 0;
-      client.request("GET", "/event-stream1", [&calls, &call_num](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
-        calls.at(call_num) = 1;
-        if(call_num == 0) {
-          ASSERT(response->content.string().empty());
-          ASSERT(!ec);
-        }
-        else if(call_num == 1) {
-          ASSERT(response->content.string() == "data: 1\n");
-          ASSERT(!ec);
-        }
-        else if(call_num == 2) {
-          ASSERT(response->content.string() == "data: 2\n");
-          ASSERT(!ec);
-        }
-        else if(call_num == 3) {
-          ASSERT(response->content.string().empty());
-          ASSERT(ec == SimpleWeb::error::eof);
-        }
-        ++call_num;
-      });
-      SimpleWeb::restart(*client.io_service);
-      client.io_service->run();
-      for(auto call : calls)
-        ASSERT(call);
-    }
-    {
-      vector<int> calls(4, 0);
-      std::size_t call_num = 0;
-      client.request("GET", "/event-stream2", [&calls, &call_num](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
-        calls.at(call_num) = 1;
-        if(call_num == 0) {
-          ASSERT(response->content.string().empty());
-          ASSERT(!ec);
-        }
-        else if(call_num == 1) {
-          ASSERT(response->content.string() == "data: 1\n");
-          ASSERT(!ec);
-        }
-        else if(call_num == 2) {
-          ASSERT(response->content.string() == "data: 2\n");
-          ASSERT(!ec);
-        }
-        else if(call_num == 3) {
-          ASSERT(response->content.string().empty());
-          ASSERT(ec == SimpleWeb::error::eof);
-        }
-        ++call_num;
-      });
-      SimpleWeb::restart(*client.io_service);
-      client.io_service->run();
-      for(auto call : calls)
-        ASSERT(call);
-    }
-
-    // Test concurrent requests from same client
-    {
-      vector<int> calls(100, 0);
-      vector<thread> threads;
-      for(size_t c = 0; c < 100; ++c) {
-        threads.emplace_back([c, &client, &calls] {
-          client.request("GET", "/match/123", [c, &calls](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
-            ASSERT(!ec);
-            stringstream output;
-            output << response->content.rdbuf();
-            ASSERT(output.str() == "123");
-            calls[c] = 1;
-          });
-        });
-      }
-      for(auto &thread : threads)
-        thread.join();
-      ASSERT(client.connections.size() == 100);
-      SimpleWeb::restart(*client.io_service);
-      client.io_service->run();
-      ASSERT(client.connections.size() == 1);
-      for(auto call : calls)
-        ASSERT(call);
-    }
-
-    // Test concurrent synchronous request calls from same client
-    {
-      HttpClient client("localhost:8080");
-      {
-        vector<int> calls(5, 0);
-        vector<thread> threads;
-        for(size_t c = 0; c < 5; ++c) {
-          threads.emplace_back([c, &client, &calls] {
-            try {
-              auto r = client.request("GET", "/match/123");
-              ASSERT(SimpleWeb::status_code(r->status_code) == SimpleWeb::StatusCode::success_ok);
-              ASSERT(r->content.string() == "123");
-              calls[c] = 1;
-            }
-            catch(...) {
-              ASSERT(false);
-            }
-          });
-        }
-        for(auto &thread : threads)
-          thread.join();
-        ASSERT(client.connections.size() == 1);
-        for(auto call : calls)
-          ASSERT(call);
-      }
-    }
-
-    // Test concurrent requests from different clients
-    {
-      vector<int> calls(10, 0);
-      vector<thread> threads;
-      for(size_t c = 0; c < 10; ++c) {
-        threads.emplace_back([c, &calls] {
-          HttpClient client("localhost:8080");
-          client.request("POST", "/string", "A string", [c, &calls](shared_ptr<HttpClient::Response> response, const SimpleWeb::error_code &ec) {
-            ASSERT(!ec);
-            ASSERT(response->content.string() == "A string");
-            calls[c] = 1;
-          });
-          client.io_service->run();
-        });
-      }
-      for(auto &thread : threads)
-        thread.join();
-      for(auto call : calls)
-        ASSERT(call);
-    }
-  }
-
-  // Test multiple requests through a persistent connection
-  {
-    HttpClient client("localhost:8080");
-    ASSERT(client.connections.size() == 0);
-    for(size_t c = 0; c < 5000; ++c) {
-      auto r1 = client.request("POST", "/string", "A string");
-      ASSERT(SimpleWeb::status_code(r1->status_code) == SimpleWeb::StatusCode::success_ok);
-      ASSERT(r1->content.string() == "A string");
-      ASSERT(client.connections.size() == 1);
-
-      stringstream content("A string");
-      auto r2 = client.request("POST", "/string", content);
-      ASSERT(SimpleWeb::status_code(r2->status_code) == SimpleWeb::StatusCode::success_ok);
-      ASSERT(r2->content.string() == "A string");
-      ASSERT(client.connections.size() == 1);
-    }
-  }
-
-  // Test multiple requests through new several client objects
-  for(size_t c = 0; c < 100; ++c) {
-    {
-      HttpClient client("localhost:8080");
-      auto r = client.request("POST", "/string", "A string");
-      ASSERT(SimpleWeb::status_code(r->status_code) == SimpleWeb::StatusCode::success_ok);
-      ASSERT(r->content.string() == "A string");
-      ASSERT(client.connections.size() == 1);
-    }
-
-    {
-      HttpClient client("localhost:8080");
-      stringstream content("A string");
-      auto r = client.request("POST", "/string", content);
-      ASSERT(SimpleWeb::status_code(r->status_code) == SimpleWeb::StatusCode::success_ok);
-      ASSERT(r->content.string() == "A string");
-      ASSERT(client.connections.size() == 1);
-    }
-  }
-
-  // Test Client client's stop()
-  for(size_t c = 0; c < 40; ++c) {
-    auto io_service = make_shared<SimpleWeb::io_context>();
-    bool call = false;
-    HttpClient client("localhost:8080");
-    client.io_service = io_service;
-    client.request("GET", "/work", [&call](shared_ptr<HttpClient::Response> /*response*/, const SimpleWeb::error_code &ec) {
-      call = true;
-      ASSERT(ec);
-    });
-    thread thread([io_service] {
-      io_service->run();
-    });
-    this_thread::sleep_for(chrono::milliseconds(100));
-    client.stop();
-    this_thread::sleep_for(chrono::milliseconds(100));
-    thread.join();
-    ASSERT(call);
-  }
-
-  // Test Client destructor that should cancel the client's request
-  for(size_t c = 0; c < 40; ++c) {
-    auto io_service = make_shared<SimpleWeb::io_context>();
-    {
-      HttpClient client("localhost:8080");
-      client.io_service = io_service;
-      client.request("GET", "/work", [](shared_ptr<HttpClient::Response> /*response*/, const SimpleWeb::error_code & /*ec*/) {
-        ASSERT(false);
-      });
-      thread thread([io_service] {
-        io_service->run();
-      });
-      thread.detach();
-      this_thread::sleep_for(chrono::milliseconds(100));
-    }
-    this_thread::sleep_for(chrono::milliseconds(100));
-  }
-
-  server.stop();
-  server_thread.join();
-
-  // Test server destructor
-  {
-    auto io_service = make_shared<SimpleWeb::io_context>();
-    bool call = false;
-    bool client_catch = false;
-    {
-      HttpServer server;
-      server.config.port = 8081;
-      server.io_service = io_service;
-      server.resource["^/test$"]["GET"] = [&call](shared_ptr<HttpServer::Response> response, shared_ptr<HttpServer::Request> /*request*/) {
-        call = true;
-        thread sleep_thread([response] {
-          this_thread::sleep_for(chrono::seconds(5));
-          response->write(SimpleWeb::StatusCode::success_ok, "test");
-          response->send([](const SimpleWeb::error_code & /*ec*/) {
-            ASSERT(false);
-          });
-        });
-        sleep_thread.detach();
-      };
-      server.start();
-      thread server_thread([io_service] {
-        io_service->run();
-      });
-      server_thread.detach();
-      this_thread::sleep_for(chrono::seconds(1));
-      thread client_thread([&client_catch] {
-        HttpClient client("localhost:8081");
-        try {
-          auto r = client.request("GET", "/test");
-          ASSERT(false);
-        }
-        catch(...) {
-          client_catch = true;
-        }
-      });
-      client_thread.detach();
-      this_thread::sleep_for(chrono::seconds(1));
-    }
-    this_thread::sleep_for(chrono::seconds(5));
-    ASSERT(call);
-    ASSERT(client_catch);
-    io_service->stop();
-  }
-}
diff --git a/third_party/Simple-web-server/repo/tests/parse_test.cpp b/third_party/Simple-web-server/repo/tests/parse_test.cpp
deleted file mode 100644
index dd07557d..00000000
--- a/third_party/Simple-web-server/repo/tests/parse_test.cpp
+++ /dev/null
@@ -1,341 +0,0 @@
-#include "assert.hpp"
-#include "client_http.hpp"
-#include "server_http.hpp"
-#include <iostream>
-
-using namespace std;
-using namespace SimpleWeb;
-
-class ServerTest : public ServerBase<HTTP> {
-public:
-  ServerTest() : ServerBase<HTTP>::ServerBase(8080) {}
-
-  void accept() noexcept override {}
-
-  void parse_request_test() {
-    auto session = std::make_shared<Session>(static_cast<size_t>(-1), create_connection(*io_service));
-
-    std::ostream stream(&session->request->content.streambuf);
-    stream << "GET /test/ HTTP/1.1\r\n";
-    stream << "TestHeader: test\r\n";
-    stream << "TestHeader2:test2\r\n";
-    stream << "TestHeader3:test3a\r\n";
-    stream << "TestHeader3:test3b\r\n";
-    stream << "\r\n";
-
-    ASSERT(RequestMessage::parse(session->request->content, session->request->method, session->request->path,
-                                 session->request->query_string, session->request->http_version, session->request->header));
-
-    ASSERT(session->request->method == "GET");
-    ASSERT(session->request->path == "/test/");
-    ASSERT(session->request->http_version == "1.1");
-
-    ASSERT(session->request->header.size() == 4);
-    auto header_it = session->request->header.find("TestHeader");
-    ASSERT(header_it != session->request->header.end() && header_it->second == "test");
-    header_it = session->request->header.find("TestHeader2");
-    ASSERT(header_it != session->request->header.end() && header_it->second == "test2");
-
-    header_it = session->request->header.find("testheader");
-    ASSERT(header_it != session->request->header.end() && header_it->second == "test");
-    header_it = session->request->header.find("testheader2");
-    ASSERT(header_it != session->request->header.end() && header_it->second == "test2");
-
-    auto range = session->request->header.equal_range("testheader3");
-    auto first = range.first;
-    auto second = first;
-    ++second;
-    ASSERT(range.first != session->request->header.end() && range.second != session->request->header.end() &&
-           ((first->second == "test3a" && second->second == "test3b") ||
-            (first->second == "test3b" && second->second == "test3a")));
-  }
-};
-
-class ClientTest : public ClientBase<HTTP> {
-public:
-  ClientTest(const std::string &server_port_path) : ClientBase<HTTP>::ClientBase(server_port_path, 80) {}
-
-  std::shared_ptr<Connection> create_connection() noexcept override {
-    return nullptr;
-  }
-
-  void connect(const std::shared_ptr<Session> &) noexcept override {}
-
-  void parse_response_header_test() {
-    std::shared_ptr<Response> response(new Response(static_cast<size_t>(-1), nullptr));
-
-    ostream stream(&response->streambuf);
-    stream << "HTTP/1.1 200 OK\r\n";
-    stream << "TestHeader: test\r\n";
-    stream << "TestHeader2:  test2\r\n";
-    stream << "TestHeader3:test3a\r\n";
-    stream << "TestHeader3:test3b\r\n";
-    stream << "TestHeader4:\r\n";
-    stream << "TestHeader5: \r\n";
-    stream << "TestHeader6:  \r\n";
-    stream << "\r\n";
-
-    ASSERT(ResponseMessage::parse(response->content, response->http_version, response->status_code, response->header));
-
-    ASSERT(response->http_version == "1.1");
-    ASSERT(response->status_code == "200 OK");
-
-    ASSERT(response->header.size() == 7);
-    auto header_it = response->header.find("TestHeader");
-    ASSERT(header_it != response->header.end() && header_it->second == "test");
-    header_it = response->header.find("TestHeader2");
-    ASSERT(header_it != response->header.end() && header_it->second == "test2");
-
-    header_it = response->header.find("testheader");
-    ASSERT(header_it != response->header.end() && header_it->second == "test");
-    header_it = response->header.find("testheader2");
-    ASSERT(header_it != response->header.end() && header_it->second == "test2");
-
-    auto range = response->header.equal_range("testheader3");
-    auto first = range.first;
-    auto second = first;
-    ++second;
-    ASSERT(range.first != response->header.end() && range.second != response->header.end() &&
-           ((first->second == "test3a" && second->second == "test3b") ||
-            (first->second == "test3b" && second->second == "test3a")));
-
-    header_it = response->header.find("TestHeader4");
-    ASSERT(header_it != response->header.end() && header_it->second == "");
-    header_it = response->header.find("TestHeader5");
-    ASSERT(header_it != response->header.end() && header_it->second == "");
-    header_it = response->header.find("TestHeader6");
-    ASSERT(header_it != response->header.end() && header_it->second == "");
-  }
-};
-
-int main() {
-  ASSERT(case_insensitive_equal("Test", "tesT"));
-  ASSERT(case_insensitive_equal("tesT", "test"));
-  ASSERT(!case_insensitive_equal("test", "tseT"));
-  CaseInsensitiveEqual equal;
-  ASSERT(equal("Test", "tesT"));
-  ASSERT(equal("tesT", "test"));
-  ASSERT(!equal("test", "tset"));
-  CaseInsensitiveHash hash;
-  ASSERT(hash("Test") == hash("tesT"));
-  ASSERT(hash("tesT") == hash("test"));
-  ASSERT(hash("test") != hash("tset"));
-
-  auto percent_decoded = "testing æøå !#$&'()*+,/:;=?@[]123-._~\r\n";
-  auto percent_encoded = "testing%20%C3%A6%C3%B8%C3%A5%20%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D123-._~%0D%0A";
-  ASSERT(Percent::encode(percent_decoded) == percent_encoded);
-  ASSERT(Percent::decode(percent_encoded) == percent_decoded);
-  ASSERT(Percent::decode(Percent::encode(percent_decoded)) == percent_decoded);
-
-  SimpleWeb::CaseInsensitiveMultimap fields = {{"test1", "æøå"}, {"test2", "!#$&'()*+,/:;=?@[]"}};
-  auto query_string1 = "test1=%C3%A6%C3%B8%C3%A5&test2=%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D";
-  auto query_string2 = "test2=%21%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D&test1=%C3%A6%C3%B8%C3%A5";
-  auto query_string_result = QueryString::create(fields);
-  ASSERT(query_string_result == query_string1 || query_string_result == query_string2);
-  auto fields_result1 = QueryString::parse(query_string1);
-  auto fields_result2 = QueryString::parse(query_string2);
-  ASSERT(fields_result1 == fields_result2 && fields_result1 == fields);
-
-  auto serverTest = make_shared<ServerTest>();
-  serverTest->io_service = std::make_shared<io_context>();
-
-  serverTest->parse_request_test();
-
-  {
-    ClientTest clientTest("test.org");
-    ASSERT(clientTest.host == "test.org");
-    ASSERT(clientTest.port == 80);
-    clientTest.parse_response_header_test();
-  }
-
-  {
-    ClientTest clientTest("test.org:8080");
-    ASSERT(clientTest.host == "test.org");
-    ASSERT(clientTest.port == 8080);
-  }
-
-  {
-    ClientTest clientTest("test.org:test");
-    ASSERT(clientTest.host == "test.org");
-    ASSERT(clientTest.port == 80);
-  }
-
-  {
-    ClientTest clientTest("[::1]");
-    ASSERT(clientTest.host == "::1");
-    ASSERT(clientTest.port == 80);
-  }
-
-  {
-    ClientTest clientTest("[::1]:8080");
-    ASSERT(clientTest.host == "::1");
-    ASSERT(clientTest.port == 8080);
-  }
-
-
-  io_context io_service;
-  asio::ip::tcp::socket socket(io_service);
-  SimpleWeb::Server<HTTP>::Request request(static_cast<size_t>(-1), nullptr);
-  {
-    request.query_string = "";
-    auto queries = request.parse_query_string();
-    ASSERT(queries.empty());
-  }
-  {
-    request.query_string = "=";
-    auto queries = request.parse_query_string();
-    ASSERT(queries.empty());
-  }
-  {
-    request.query_string = "=test";
-    auto queries = request.parse_query_string();
-    ASSERT(queries.empty());
-  }
-  {
-    request.query_string = "a=1%202%20%203&b=3+4&c&d=æ%25ø%26å%3F";
-    auto queries = request.parse_query_string();
-    {
-      auto range = queries.equal_range("a");
-      ASSERT(range.first != range.second);
-      ASSERT(range.first->second == "1 2  3");
-    }
-    {
-      auto range = queries.equal_range("b");
-      ASSERT(range.first != range.second);
-      ASSERT(range.first->second == "3 4");
-    }
-    {
-      auto range = queries.equal_range("c");
-      ASSERT(range.first != range.second);
-      ASSERT(range.first->second == "");
-    }
-    {
-      auto range = queries.equal_range("d");
-      ASSERT(range.first != range.second);
-      ASSERT(range.first->second == "æ%ø&å?");
-    }
-  }
-
-  {
-    SimpleWeb::CaseInsensitiveMultimap solution;
-    std::stringstream header;
-    auto parsed = SimpleWeb::HttpHeader::parse(header);
-    ASSERT(parsed == solution);
-  }
-  {
-    SimpleWeb::CaseInsensitiveMultimap solution = {{"Content-Type", "application/json"}};
-    std::stringstream header("Content-Type: application/json");
-    auto parsed = SimpleWeb::HttpHeader::parse(header);
-    ASSERT(parsed == solution);
-  }
-  {
-    SimpleWeb::CaseInsensitiveMultimap solution = {{"Content-Type", "application/json"}};
-    std::stringstream header("Content-Type: application/json\r");
-    auto parsed = SimpleWeb::HttpHeader::parse(header);
-    ASSERT(parsed == solution);
-  }
-  {
-    SimpleWeb::CaseInsensitiveMultimap solution = {{"Content-Type", "application/json"}};
-    std::stringstream header("Content-Type: application/json\r\n");
-    auto parsed = SimpleWeb::HttpHeader::parse(header);
-    ASSERT(parsed == solution);
-  }
-
-  {
-    {
-      SimpleWeb::CaseInsensitiveMultimap solution;
-      auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("");
-      ASSERT(parsed == solution);
-    }
-    {
-      SimpleWeb::CaseInsensitiveMultimap solution = {{"a", ""}};
-      auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("a");
-      ASSERT(parsed == solution);
-    }
-    {
-      SimpleWeb::CaseInsensitiveMultimap solution = {{"a", ""}, {"b", ""}};
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("a; b");
-        ASSERT(parsed == solution);
-      }
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("a;b");
-        ASSERT(parsed == solution);
-      }
-    }
-    {
-      SimpleWeb::CaseInsensitiveMultimap solution = {{"a", ""}, {"b", "c"}};
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("a; b=c");
-        ASSERT(parsed == solution);
-      }
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("a;b=c");
-        ASSERT(parsed == solution);
-      }
-    }
-    {
-      SimpleWeb::CaseInsensitiveMultimap solution = {{"form-data", ""}};
-      auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("form-data");
-      ASSERT(parsed == solution);
-    }
-    {
-      SimpleWeb::CaseInsensitiveMultimap solution = {{"form-data", ""}, {"test", ""}};
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("form-data; test");
-        ASSERT(parsed == solution);
-      }
-    }
-    {
-      SimpleWeb::CaseInsensitiveMultimap solution = {{"form-data", ""}, {"name", "file"}};
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("form-data; name=\"file\"");
-        ASSERT(parsed == solution);
-      }
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("form-data; name=file");
-        ASSERT(parsed == solution);
-      }
-    }
-    {
-      SimpleWeb::CaseInsensitiveMultimap solution = {{"form-data", ""}, {"name", "file"}, {"filename", "filename.png"}};
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("form-data; name=\"file\"; filename=\"filename.png\"");
-        ASSERT(parsed == solution);
-      }
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("form-data;name=\"file\";filename=\"filename.png\"");
-        ASSERT(parsed == solution);
-      }
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("form-data; name=file; filename=filename.png");
-        ASSERT(parsed == solution);
-      }
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("form-data;name=file;filename=filename.png");
-        ASSERT(parsed == solution);
-      }
-    }
-    {
-      SimpleWeb::CaseInsensitiveMultimap solution = {{"form-data", ""}, {"name", "fi le"}, {"filename", "file name.png"}};
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("form-data; name=\"fi le\"; filename=\"file name.png\"");
-        ASSERT(parsed == solution);
-      }
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("form-data; name=\"fi%20le\"; filename=\"file%20name.png\"");
-        ASSERT(parsed == solution);
-      }
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("form-data; name=fi le; filename=file name.png");
-        ASSERT(parsed == solution);
-      }
-      {
-        auto parsed = SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse("form-data; name=fi%20le; filename=file%20name.png");
-        ASSERT(parsed == solution);
-      }
-    }
-  }
-
-  ASSERT(SimpleWeb::Date::to_string(std::chrono::system_clock::now()).size() == 29);
-}
diff --git a/third_party/Simple-web-server/repo/tests/status_code_test.cpp b/third_party/Simple-web-server/repo/tests/status_code_test.cpp
deleted file mode 100644
index 1b784d43..00000000
--- a/third_party/Simple-web-server/repo/tests/status_code_test.cpp
+++ /dev/null
@@ -1,32 +0,0 @@
-#include "assert.hpp"
-#include "status_code.hpp"
-
-using namespace SimpleWeb;
-
-
-int main() {
-  ASSERT(status_code("") == StatusCode::unknown);
-  ASSERT(status_code("Error") == StatusCode::unknown);
-  ASSERT(status_code("000 Error") == StatusCode::unknown);
-  ASSERT(status_code(StatusCode::unknown) == "");
-  ASSERT(static_cast<int>(status_code("050 Custom")) == 50);
-  ASSERT(static_cast<int>(status_code("950 Custom")) == 950);
-  ASSERT(status_code("100 Continue") == StatusCode::information_continue);
-  ASSERT(status_code("100 C") == StatusCode::information_continue);
-  ASSERT(status_code("100") == StatusCode::information_continue);
-  ASSERT(status_code(StatusCode::information_continue) == "100 Continue");
-  ASSERT(status_code("200 OK") == StatusCode::success_ok);
-  ASSERT(status_code(StatusCode::success_ok) == "200 OK");
-  ASSERT(status_code("208 Already Reported") == StatusCode::success_already_reported);
-  ASSERT(status_code(StatusCode::success_already_reported) == "208 Already Reported");
-  ASSERT(status_code("308 Permanent Redirect") == StatusCode::redirection_permanent_redirect);
-  ASSERT(status_code(StatusCode::redirection_permanent_redirect) == "308 Permanent Redirect");
-  ASSERT(status_code("404 Not Found") == StatusCode::client_error_not_found);
-  ASSERT(status_code(StatusCode::client_error_not_found) == "404 Not Found");
-  ASSERT(status_code("502 Bad Gateway") == StatusCode::server_error_bad_gateway);
-  ASSERT(status_code(StatusCode::server_error_bad_gateway) == "502 Bad Gateway");
-  ASSERT(status_code("504 Gateway Timeout") == StatusCode::server_error_gateway_timeout);
-  ASSERT(status_code(StatusCode::server_error_gateway_timeout) == "504 Gateway Timeout");
-  ASSERT(status_code("511 Network Authentication Required") == StatusCode::server_error_network_authentication_required);
-  ASSERT(status_code(StatusCode::server_error_network_authentication_required) == "511 Network Authentication Required");
-}
diff --git a/third_party/Simple-web-server/repo/utility.hpp b/third_party/Simple-web-server/repo/utility.hpp
deleted file mode 100644
index cac7dfa4..00000000
--- a/third_party/Simple-web-server/repo/utility.hpp
+++ /dev/null
@@ -1,480 +0,0 @@
-#ifndef SIMPLE_WEB_UTILITY_HPP
-#define SIMPLE_WEB_UTILITY_HPP
-
-#include "status_code.hpp"
-#include <atomic>
-#include <chrono>
-#include <cstdlib>
-#include <ctime>
-#include <iostream>
-#include <memory>
-#include <mutex>
-#include <string>
-#include <unordered_map>
-
-#ifndef SW_DEPRECATED
-#if defined(__GNUC__) || defined(__clang__)
-#define SW_DEPRECATED __attribute__((deprecated))
-#elif defined(_MSC_VER)
-#define SW_DEPRECATED __declspec(deprecated)
-#else
-#define SW_DEPRECATED
-#endif
-#endif
-
-#if __cplusplus > 201402L || _MSVC_LANG > 201402L
-#include <string_view>
-namespace SimpleWeb {
-  using string_view = std::string_view;
-}
-#elif !defined(ASIO_STANDALONE)
-#include <boost/utility/string_ref.hpp>
-namespace SimpleWeb {
-  using string_view = boost::string_ref;
-}
-#else
-namespace SimpleWeb {
-  using string_view = const std::string &;
-}
-#endif
-
-namespace SimpleWeb {
-  inline bool case_insensitive_equal(const std::string &str1, const std::string &str2) noexcept {
-    return str1.size() == str2.size() &&
-           std::equal(str1.begin(), str1.end(), str2.begin(), [](char a, char b) {
-             return tolower(a) == tolower(b);
-           });
-  }
-  class CaseInsensitiveEqual {
-  public:
-    bool operator()(const std::string &str1, const std::string &str2) const noexcept {
-      return case_insensitive_equal(str1, str2);
-    }
-  };
-  // Based on https://stackoverflow.com/questions/2590677/how-do-i-combine-hash-values-in-c0x/2595226#2595226
-  class CaseInsensitiveHash {
-  public:
-    std::size_t operator()(const std::string &str) const noexcept {
-      std::size_t h = 0;
-      std::hash<int> hash;
-      for(auto c : str)
-        h ^= hash(tolower(c)) + 0x9e3779b9 + (h << 6) + (h >> 2);
-      return h;
-    }
-  };
-
-  using CaseInsensitiveMultimap = std::unordered_multimap<std::string, std::string, CaseInsensitiveHash, CaseInsensitiveEqual>;
-
-  /// Percent encoding and decoding
-  class Percent {
-  public:
-    /// Returns percent-encoded string
-    static std::string encode(const std::string &value) noexcept {
-      static auto hex_chars = "0123456789ABCDEF";
-
-      std::string result;
-      result.reserve(value.size()); // Minimum size of result
-
-      for(auto &chr : value) {
-        if(!((chr >= '0' && chr <= '9') || (chr >= 'A' && chr <= 'Z') || (chr >= 'a' && chr <= 'z') || chr == '-' || chr == '.' || chr == '_' || chr == '~'))
-          result += std::string("%") + hex_chars[static_cast<unsigned char>(chr) >> 4] + hex_chars[static_cast<unsigned char>(chr) & 15];
-        else
-          result += chr;
-      }
-
-      return result;
-    }
-
-    /// Returns percent-decoded string
-    static std::string decode(const std::string &value) noexcept {
-      std::string result;
-      result.reserve(value.size() / 3 + (value.size() % 3)); // Minimum size of result
-
-      for(std::size_t i = 0; i < value.size(); ++i) {
-        auto &chr = value[i];
-        if(chr == '%' && i + 2 < value.size()) {
-          auto hex = value.substr(i + 1, 2);
-          auto decoded_chr = static_cast<char>(std::strtol(hex.c_str(), nullptr, 16));
-          result += decoded_chr;
-          i += 2;
-        }
-        else if(chr == '+')
-          result += ' ';
-        else
-          result += chr;
-      }
-
-      return result;
-    }
-  };
-
-  /// Query string creation and parsing
-  class QueryString {
-  public:
-    /// Returns query string created from given field names and values
-    static std::string create(const CaseInsensitiveMultimap &fields) noexcept {
-      std::string result;
-
-      bool first = true;
-      for(auto &field : fields) {
-        result += (!first ? "&" : "") + field.first + '=' + Percent::encode(field.second);
-        first = false;
-      }
-
-      return result;
-    }
-
-    /// Returns query keys with percent-decoded values.
-    static CaseInsensitiveMultimap parse(const std::string &query_string) noexcept {
-      CaseInsensitiveMultimap result;
-
-      if(query_string.empty())
-        return result;
-
-      std::size_t name_pos = 0;
-      auto name_end_pos = std::string::npos;
-      auto value_pos = std::string::npos;
-      for(std::size_t c = 0; c < query_string.size(); ++c) {
-        if(query_string[c] == '&') {
-          auto name = query_string.substr(name_pos, (name_end_pos == std::string::npos ? c : name_end_pos) - name_pos);
-          if(!name.empty()) {
-            auto value = value_pos == std::string::npos ? std::string() : query_string.substr(value_pos, c - value_pos);
-            result.emplace(std::move(name), Percent::decode(value));
-          }
-          name_pos = c + 1;
-          name_end_pos = std::string::npos;
-          value_pos = std::string::npos;
-        }
-        else if(query_string[c] == '=' && name_end_pos == std::string::npos) {
-          name_end_pos = c;
-          value_pos = c + 1;
-        }
-      }
-      if(name_pos < query_string.size()) {
-        auto name = query_string.substr(name_pos, (name_end_pos == std::string::npos ? std::string::npos : name_end_pos - name_pos));
-        if(!name.empty()) {
-          auto value = value_pos >= query_string.size() ? std::string() : query_string.substr(value_pos);
-          result.emplace(std::move(name), Percent::decode(value));
-        }
-      }
-
-      return result;
-    }
-  };
-
-  class HttpHeader {
-  public:
-    /// Parse header fields from stream
-    static CaseInsensitiveMultimap parse(std::istream &stream) noexcept {
-      CaseInsensitiveMultimap result;
-      std::string line;
-      std::size_t param_end;
-      while(getline(stream, line) && (param_end = line.find(':')) != std::string::npos) {
-        std::size_t value_start = param_end + 1;
-        while(value_start + 1 < line.size() && line[value_start] == ' ')
-          ++value_start;
-        if(value_start < line.size())
-          result.emplace(line.substr(0, param_end), line.substr(value_start, line.size() - value_start - (line.back() == '\r' ? 1 : 0)));
-      }
-      return result;
-    }
-
-    class FieldValue {
-    public:
-      class SemicolonSeparatedAttributes {
-      public:
-        /// Parse Set-Cookie or Content-Disposition from given header field value.
-        /// Attribute values are percent-decoded.
-        static CaseInsensitiveMultimap parse(const std::string &value) {
-          CaseInsensitiveMultimap result;
-
-          std::size_t name_start_pos = std::string::npos;
-          std::size_t name_end_pos = std::string::npos;
-          std::size_t value_start_pos = std::string::npos;
-          for(std::size_t c = 0; c < value.size(); ++c) {
-            if(name_start_pos == std::string::npos) {
-              if(value[c] != ' ' && value[c] != ';')
-                name_start_pos = c;
-            }
-            else {
-              if(name_end_pos == std::string::npos) {
-                if(value[c] == ';') {
-                  result.emplace(value.substr(name_start_pos, c - name_start_pos), std::string());
-                  name_start_pos = std::string::npos;
-                }
-                else if(value[c] == '=')
-                  name_end_pos = c;
-              }
-              else {
-                if(value_start_pos == std::string::npos) {
-                  if(value[c] == '"' && c + 1 < value.size())
-                    value_start_pos = c + 1;
-                  else
-                    value_start_pos = c;
-                }
-                else if(value[c] == '"' || value[c] == ';') {
-                  result.emplace(value.substr(name_start_pos, name_end_pos - name_start_pos), Percent::decode(value.substr(value_start_pos, c - value_start_pos)));
-                  name_start_pos = std::string::npos;
-                  name_end_pos = std::string::npos;
-                  value_start_pos = std::string::npos;
-                }
-              }
-            }
-          }
-          if(name_start_pos != std::string::npos) {
-            if(name_end_pos == std::string::npos)
-              result.emplace(value.substr(name_start_pos), std::string());
-            else if(value_start_pos != std::string::npos) {
-              if(value.back() == '"')
-                result.emplace(value.substr(name_start_pos, name_end_pos - name_start_pos), Percent::decode(value.substr(value_start_pos, value.size() - 1)));
-              else
-                result.emplace(value.substr(name_start_pos, name_end_pos - name_start_pos), Percent::decode(value.substr(value_start_pos)));
-            }
-          }
-
-          return result;
-        }
-      };
-    };
-  };
-
-  class RequestMessage {
-  public:
-    /** Parse request line and header fields from a request stream.
-     *
-     * @param[in]  stream       Stream to parse.
-     * @param[out] method       HTTP method.
-     * @param[out] path         Path from request URI.
-     * @param[out] query_string Query string from request URI.
-     * @param[out] version      HTTP version.
-     * @param[out] header       Header fields.
-     *
-     * @return True if stream is parsed successfully, false if not.
-     */
-    static bool parse(std::istream &stream, std::string &method, std::string &path, std::string &query_string, std::string &version, CaseInsensitiveMultimap &header) noexcept {
-      std::string line;
-      std::size_t method_end;
-      if(getline(stream, line) && (method_end = line.find(' ')) != std::string::npos) {
-        method = line.substr(0, method_end);
-
-        std::size_t query_start = std::string::npos;
-        std::size_t path_and_query_string_end = std::string::npos;
-        for(std::size_t i = method_end + 1; i < line.size(); ++i) {
-          if(line[i] == '?' && (i + 1) < line.size() && query_start == std::string::npos)
-            query_start = i + 1;
-          else if(line[i] == ' ') {
-            path_and_query_string_end = i;
-            break;
-          }
-        }
-        if(path_and_query_string_end != std::string::npos) {
-          if(query_start != std::string::npos) {
-            path = line.substr(method_end + 1, query_start - method_end - 2);
-            query_string = line.substr(query_start, path_and_query_string_end - query_start);
-          }
-          else
-            path = line.substr(method_end + 1, path_and_query_string_end - method_end - 1);
-
-          std::size_t protocol_end;
-          if((protocol_end = line.find('/', path_and_query_string_end + 1)) != std::string::npos) {
-            if(line.compare(path_and_query_string_end + 1, protocol_end - path_and_query_string_end - 1, "HTTP") != 0)
-              return false;
-            version = line.substr(protocol_end + 1, line.size() - protocol_end - 2);
-          }
-          else
-            return false;
-
-          header = HttpHeader::parse(stream);
-        }
-        else
-          return false;
-      }
-      else
-        return false;
-      return true;
-    }
-  };
-
-  class ResponseMessage {
-  public:
-    /** Parse status line and header fields from a response stream.
-     *
-     * @param[in]  stream      Stream to parse.
-     * @param[out] version     HTTP version.
-     * @param[out] status_code HTTP status code.
-     * @param[out] header      Header fields.
-     *
-     * @return True if stream is parsed successfully, false if not.
-     */
-    static bool parse(std::istream &stream, std::string &version, std::string &status_code, CaseInsensitiveMultimap &header) noexcept {
-      std::string line;
-      std::size_t version_end;
-      if(getline(stream, line) && (version_end = line.find(' ')) != std::string::npos) {
-        if(5 < line.size())
-          version = line.substr(5, version_end - 5);
-        else
-          return false;
-        if((version_end + 1) < line.size())
-          status_code = line.substr(version_end + 1, line.size() - (version_end + 1) - (line.back() == '\r' ? 1 : 0));
-        else
-          return false;
-
-        header = HttpHeader::parse(stream);
-      }
-      else
-        return false;
-      return true;
-    }
-  };
-
-  /// Date class working with formats specified in RFC 7231 Date/Time Formats
-  class Date {
-  public:
-    /// Returns the given std::chrono::system_clock::time_point as a string with the following format: Wed, 31 Jul 2019 11:34:23 GMT.
-    static std::string to_string(const std::chrono::system_clock::time_point time_point) noexcept {
-      static std::string result_cache;
-      static std::chrono::system_clock::time_point last_time_point;
-
-      static std::mutex mutex;
-      std::lock_guard<std::mutex> lock(mutex);
-
-      if(std::chrono::duration_cast<std::chrono::seconds>(time_point - last_time_point).count() == 0 && !result_cache.empty())
-        return result_cache;
-
-      last_time_point = time_point;
-
-      std::string result;
-      result.reserve(29);
-
-      auto time = std::chrono::system_clock::to_time_t(time_point);
-      tm tm;
-#if defined(_MSC_VER) || defined(__MINGW32__)
-      if(gmtime_s(&tm, &time) != 0)
-        return {};
-      auto gmtime = &tm;
-#else
-      auto gmtime = gmtime_r(&time, &tm);
-      if(!gmtime)
-        return {};
-#endif
-
-      switch(gmtime->tm_wday) {
-      case 0: result += "Sun, "; break;
-      case 1: result += "Mon, "; break;
-      case 2: result += "Tue, "; break;
-      case 3: result += "Wed, "; break;
-      case 4: result += "Thu, "; break;
-      case 5: result += "Fri, "; break;
-      case 6: result += "Sat, "; break;
-      }
-
-      result += gmtime->tm_mday < 10 ? '0' : static_cast<char>(gmtime->tm_mday / 10 + 48);
-      result += static_cast<char>(gmtime->tm_mday % 10 + 48);
-
-      switch(gmtime->tm_mon) {
-      case 0: result += " Jan "; break;
-      case 1: result += " Feb "; break;
-      case 2: result += " Mar "; break;
-      case 3: result += " Apr "; break;
-      case 4: result += " May "; break;
-      case 5: result += " Jun "; break;
-      case 6: result += " Jul "; break;
-      case 7: result += " Aug "; break;
-      case 8: result += " Sep "; break;
-      case 9: result += " Oct "; break;
-      case 10: result += " Nov "; break;
-      case 11: result += " Dec "; break;
-      }
-
-      auto year = gmtime->tm_year + 1900;
-      result += static_cast<char>(year / 1000 + 48);
-      result += static_cast<char>((year / 100) % 10 + 48);
-      result += static_cast<char>((year / 10) % 10 + 48);
-      result += static_cast<char>(year % 10 + 48);
-      result += ' ';
-
-      result += gmtime->tm_hour < 10 ? '0' : static_cast<char>(gmtime->tm_hour / 10 + 48);
-      result += static_cast<char>(gmtime->tm_hour % 10 + 48);
-      result += ':';
-
-      result += gmtime->tm_min < 10 ? '0' : static_cast<char>(gmtime->tm_min / 10 + 48);
-      result += static_cast<char>(gmtime->tm_min % 10 + 48);
-      result += ':';
-
-      result += gmtime->tm_sec < 10 ? '0' : static_cast<char>(gmtime->tm_sec / 10 + 48);
-      result += static_cast<char>(gmtime->tm_sec % 10 + 48);
-
-      result += " GMT";
-
-      result_cache = result;
-      return result;
-    }
-  };
-} // namespace SimpleWeb
-
-#ifdef __SSE2__
-#include <emmintrin.h>
-namespace SimpleWeb {
-  inline void spin_loop_pause() noexcept { _mm_pause(); }
-} // namespace SimpleWeb
-// TODO: need verification that the following checks are correct:
-#elif defined(_MSC_VER) && _MSC_VER >= 1800 && (defined(_M_X64) || defined(_M_IX86))
-#include <intrin.h>
-namespace SimpleWeb {
-  inline void spin_loop_pause() noexcept { _mm_pause(); }
-} // namespace SimpleWeb
-#else
-namespace SimpleWeb {
-  inline void spin_loop_pause() noexcept {}
-} // namespace SimpleWeb
-#endif
-
-namespace SimpleWeb {
-  /// Makes it possible to for instance cancel Asio handlers without stopping asio::io_service.
-  class ScopeRunner {
-    /// Scope count that is set to -1 if scopes are to be canceled.
-    std::atomic<long> count;
-
-  public:
-    class SharedLock {
-      friend class ScopeRunner;
-      std::atomic<long> &count;
-      SharedLock(std::atomic<long> &count) noexcept : count(count) {}
-      SharedLock &operator=(const SharedLock &) = delete;
-      SharedLock(const SharedLock &) = delete;
-
-    public:
-      ~SharedLock() noexcept {
-        count.fetch_sub(1);
-      }
-    };
-
-    ScopeRunner() noexcept : count(0) {}
-
-    /// Returns nullptr if scope should be exited, or a shared lock otherwise.
-    /// The shared lock ensures that a potential destructor call is delayed until all locks are released.
-    std::unique_ptr<SharedLock> continue_lock() noexcept {
-      long expected = count;
-      while(expected >= 0 && !count.compare_exchange_weak(expected, expected + 1))
-        spin_loop_pause();
-
-      if(expected < 0)
-        return nullptr;
-      else
-        return std::unique_ptr<SharedLock>(new SharedLock(count));
-    }
-
-    /// Blocks until all shared locks are released, then prevents future shared locks.
-    void stop() noexcept {
-      long expected = 0;
-      while(!count.compare_exchange_weak(expected, -1)) {
-        if(expected < 0)
-          return;
-        expected = 0;
-        spin_loop_pause();
-      }
-    }
-  };
-} // namespace SimpleWeb
-
-#endif // SIMPLE_WEB_UTILITY_HPP
diff --git a/third_party/Simple-web-server/repo/web/index.html b/third_party/Simple-web-server/repo/web/index.html
deleted file mode 100644
index 3cf66e4c..00000000
--- a/third_party/Simple-web-server/repo/web/index.html
+++ /dev/null
@@ -1,8 +0,0 @@
-<html>
-    <head>
-        <title>Simple-Web-Server html-file</title>
-    </head>
-    <body>
-        This is the content of index.html
-    </body>
-</html>
diff --git a/third_party/Simple-web-server/repo/web/test.html b/third_party/Simple-web-server/repo/web/test.html
deleted file mode 100644
index af5fe1cc..00000000
--- a/third_party/Simple-web-server/repo/web/test.html
+++ /dev/null
@@ -1,8 +0,0 @@
-<html>
-    <head>
-        <title>Simple-Web-Server html-file</title>
-    </head>
-    <body>
-        This is the content of test.html
-    </body>
-</html>
diff --git a/third_party/cpp-httplib/repo b/third_party/cpp-httplib/repo
new file mode 160000
index 00000000..03cf43eb
--- /dev/null
+++ b/third_party/cpp-httplib/repo
@@ -0,0 +1 @@
+Subproject commit 03cf43ebaa55f27a2778bed870ea3549f7e84e2c
diff --git a/third_party/openthread/CMakeLists.txt b/third_party/openthread/CMakeLists.txt
index eab6e7c6..33033130 100644
--- a/third_party/openthread/CMakeLists.txt
+++ b/third_party/openthread/CMakeLists.txt
@@ -62,22 +62,28 @@ set(OT_NAT64_TRANSLATOR ${OTBR_NAT64} CACHE STRING "enable NAT64 translator" FOR
 set(OT_NETDATA_PUBLISHER ON CACHE STRING "enable netdata publisher" FORCE)
 set(OT_NETDIAG_CLIENT ON CACHE STRING "enable Network Diagnostic client" FORCE)
 set(OT_PLATFORM "posix" CACHE STRING "use posix platform" FORCE)
+set(OT_PLATFORM_DNSSD ${OTBR_DNSSD_PLAT} CACHE STRING "enable platform DNSSD" FORCE)
 set(OT_PLATFORM_NETIF ON CACHE STRING "enable platform netif" FORCE)
 set(OT_PLATFORM_UDP ON CACHE STRING "enable platform UDP" FORCE)
 set(OT_SERVICE ON CACHE STRING "enable service" FORCE)
 set(OT_SLAAC ON CACHE STRING "enable SLAAC" FORCE)
 set(OT_SRP_CLIENT ON CACHE STRING "enable SRP client" FORCE)
+set(OT_SRP_ADV_PROXY ${OTBR_DNSSD_PLAT} CACHE STRING "enable SRP Advertising Proxy" FORCE)
 set(OT_TARGET_OPENWRT ${OTBR_OPENWRT} CACHE STRING "target on OpenWRT" FORCE)
 set(OT_TCP OFF CACHE STRING "disable TCP")
 set(OT_TREL ${OTBR_TREL} CACHE STRING "enable TREL" FORCE)
 set(OT_UDP_FORWARD OFF CACHE STRING "disable udp forward" FORCE)
 set(OT_UPTIME ON CACHE STRING "enable uptime" FORCE)
 
-if (OTBR_SRP_ADVERTISING_PROXY)
+if (OTBR_DNSSD_PLAT OR OTBR_SRP_ADVERTISING_PROXY)
     set(OT_SRP_SERVER ON CACHE STRING "enable SRP server" FORCE)
     set(OT_EXTERNAL_HEAP ON CACHE STRING "enable external heap" FORCE)
 endif()
 
+if (OT_SRP_ADV_PROXY AND OTBR_SRP_ADVERTISING_PROXY)
+    message(FATAL_ERROR "Only one Advertising Proxy can be enabled. ${OTBR_DNSSD_PLAT} ")
+endif()
+
 if (NOT OT_THREAD_VERSION STREQUAL "1.1")
     if (OT_REFERENCE_DEVICE)
         set(OT_DUA ON CACHE STRING "Enable Thread 1.2 DUA for reference devices")
```

