```diff
diff --git a/.github/workflows/border_router.yml b/.github/workflows/border_router.yml
index a04e1feb..876821d8 100644
--- a/.github/workflows/border_router.yml
+++ b/.github/workflows/border_router.yml
@@ -53,7 +53,7 @@ jobs:
             otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=OFF -DOTBR_DNS_UPSTREAM_QUERY=ON"
             border_routing: 1
             internet: 0
-            dnssd_plat: 0
+            ot_srp_adv_proxy: 0
             otbr_mdns: "mDNSResponder"
             cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
             packet_verification: 1
@@ -61,7 +61,7 @@ jobs:
             otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=OFF -DOTBR_DNS_UPSTREAM_QUERY=ON"
             border_routing: 1
             internet: 0
-            dnssd_plat: 0
+            ot_srp_adv_proxy: 0
             otbr_mdns: "avahi"
             cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
             packet_verification: 1
@@ -69,23 +69,15 @@ jobs:
             otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=ON -DOTBR_DNS_UPSTREAM_QUERY=ON"
             border_routing: 1
             internet: 0
-            dnssd_plat: 0
+            ot_srp_adv_proxy: 0
             otbr_mdns: "mDNSResponder"
             cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
             packet_verification: 2
-          - name: "Border Router TREL (Avahi)"
-            otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=ON -DOTBR_DNS_UPSTREAM_QUERY=ON"
-            border_routing: 1
-            internet: 0
-            dnssd_plat: 0
-            otbr_mdns: "avahi"
-            cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
-            packet_verification: 2
           - name: "Border Router MATN (mDNSResponder)"
             otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=OFF -DOTBR_DNS_UPSTREAM_QUERY=ON"
             border_routing: 1
             internet: 0
-            dnssd_plat: 0
+            ot_srp_adv_proxy: 0
             otbr_mdns: "mDNSResponder"
             cert_scripts: ./tests/scripts/thread-cert/border_router/MATN/*.py
             packet_verification: 1
@@ -93,7 +85,7 @@ jobs:
             otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=OFF -DOTBR_DNS_UPSTREAM_QUERY=ON -DOTBR_DHCP6_PD=ON"
             border_routing: 1
             internet: 1
-            dnssd_plat: 0
+            ot_srp_adv_proxy: 0
             otbr_mdns: "mDNSResponder"
             cert_scripts: ./tests/scripts/thread-cert/border_router/internet/*.py
             packet_verification: 1
@@ -101,31 +93,23 @@ jobs:
             otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=OFF -DOTBR_DNS_UPSTREAM_QUERY=ON"
             border_routing: 0
             internet: 0
-            dnssd_plat: 0
+            ot_srp_adv_proxy: 0
             otbr_mdns: "mDNSResponder"
             cert_scripts: ./tests/scripts/thread-cert/backbone/*.py
             packet_verification: 1
-          - name: "Border Router TREL with FEATURE_FLAG (avahi)"
-            otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_FEATURE_FLAGS=ON -DOTBR_TELEMETRY_DATA_API=ON -DOTBR_TREL=ON -DOTBR_DNS_UPSTREAM_QUERY=ON"
-            border_routing: 1
-            internet: 0
-            dnssd_plat: 0
-            otbr_mdns: "avahi"
-            cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
-            packet_verification: 2
           - name: "Border Router with OT Core Advertising Proxy (avahi)"
-            otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=ON -DOTBR_DNS_UPSTREAM_QUERY=ON"
+            otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=OFF -DOTBR_DNS_UPSTREAM_QUERY=ON -DOTBR_BORDER_AGENT_MESHCOP_SERVICE=OFF"
             border_routing: 1
             internet: 0
-            dnssd_plat: 1
+            ot_srp_adv_proxy: 1
             otbr_mdns: "avahi"
             cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
             packet_verification: 1
           - name: "Border Router with OT Core Advertising Proxy (mDNSResponder)"
-            otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=ON -DOTBR_DNS_UPSTREAM_QUERY=ON"
+            otbr_options: "-DOT_DUA=ON -DOT_ECDSA=ON -DOT_MLR=ON -DOT_SERVICE=ON -DOT_SRP_SERVER=ON -DOTBR_COVERAGE=ON -DOTBR_DUA_ROUTING=ON -DOTBR_TREL=OFF -DOTBR_DNS_UPSTREAM_QUERY=ON -DOTBR_BORDER_AGENT_MESHCOP_SERVICE=OFF"
             border_routing: 1
             internet: 0
-            dnssd_plat: 1
+            ot_srp_adv_proxy: 1
             otbr_mdns: "mDNSResponder"
             cert_scripts: ./tests/scripts/thread-cert/border_router/*.py
             packet_verification: 1
@@ -143,7 +127,7 @@ jobs:
       INTER_OP_BBR: 0
       BORDER_ROUTING: ${{ matrix.border_routing }}
       NAT64: ${{ matrix.internet }}
-      DNSSD_PLAT: ${{ matrix.dnssd_plat }}
+      OT_SRP_ADV_PROXY: ${{ matrix.ot_srp_adv_proxy }}
       MAX_JOBS: 3
       VERBOSE: 1
     steps:
@@ -168,17 +152,15 @@ jobs:
         # This should be fixed by enhancing the test script to handle SRP server situations properly.
         otbr_options="${{ matrix.otbr_options }}"
         otbr_image_name="otbr-ot12-backbone-ci"
-        docker build -t "${otbr_image_name}" -f etc/docker/Dockerfile . \
+        docker build -t "${otbr_image_name}" -f etc/docker/test/Dockerfile . \
           --build-arg BORDER_ROUTING=${{ matrix.border_routing }} \
           --build-arg INFRA_IF_NAME=eth0 \
           --build-arg BACKBONE_ROUTER=1 \
           --build-arg REFERENCE_DEVICE=1 \
           --build-arg OT_BACKBONE_CI=1 \
           --build-arg NAT64="${{ matrix.internet }}" \
-          --build-arg NAT64_SERVICE=openthread \
-          --build-arg DNS64="${{ matrix.internet }}" \
           --build-arg MDNS="${{ matrix.otbr_mdns }}" \
-          --build-arg DNSSD_PLAT="${{ matrix.dnssd_plat }}" \
+          --build-arg OT_SRP_ADV_PROXY="${{ matrix.ot_srp_adv_proxy }}" \
           --build-arg OTBR_OPTIONS="${otbr_options} -DCMAKE_CXX_FLAGS='-DOPENTHREAD_CONFIG_DNSSD_SERVER_BIND_UNSPECIFIED_NETIF=1'"
     - name: Bootstrap OpenThread Test
       if: ${{ success() && steps.check_cache_result.outputs.cache-hit != 'true' }}
diff --git a/.github/workflows/build.yml b/.github/workflows/build.yml
index 72313759..dfaa15b7 100644
--- a/.github/workflows/build.yml
+++ b/.github/workflows/build.yml
@@ -62,7 +62,7 @@ jobs:
       BUILD_TARGET: check
       OTBR_BUILD_TYPE: ${{ matrix.build_type }}
       OTBR_MDNS: ${{ matrix.mdns }}
-      OTBR_OPTIONS: "-DOTBR_SRP_ADVERTISING_PROXY=ON -DOTBR_BORDER_ROUTING=ON -DOTBR_NAT64=ON -DOTBR_DHCP6_PD=ON -DOTBR_SRP_SERVER_AUTO_ENABLE=OFF -DOTBR_TREL=ON"
+      OTBR_OPTIONS: "-DOTBR_SRP_ADVERTISING_PROXY=ON -DOTBR_BORDER_ROUTING=ON -DOTBR_NAT64=ON -DOTBR_DHCP6_PD=ON -DOTBR_TREL=ON -DOTBR_SRP_SERVER_ON_INIT=ON"
       OTBR_COVERAGE: 1
     steps:
     - uses: actions/checkout@v4
@@ -85,7 +85,7 @@ jobs:
       BUILD_TARGET: check
       OTBR_REST: ${{ matrix.rest }}
       OTBR_MDNS: mDNSResponder
-      OTBR_OPTIONS: "-DOTBR_SRP_ADVERTISING_PROXY=ON -DOTBR_DNSSD_DISCOVERY_PROXY=ON -DOTBR_TREL=ON"
+      OTBR_OPTIONS: "-DOTBR_SRP_ADVERTISING_PROXY=ON -DOTBR_DNSSD_DISCOVERY_PROXY=ON -DOTBR_TREL=ON -DOTBR_SRP_SERVER_ON_INIT=ON"
       OTBR_COVERAGE: 1
     steps:
     - uses: actions/checkout@v4
@@ -141,8 +141,6 @@ jobs:
       run: |
         tests/scripts/bootstrap.sh
         sudo pip3 install -U scikit-build
-        sudo pip3 install -U cmake==3.10.3
-        cmake --version | grep 3.10.3
     - name: Build
       run: script/test package
 
diff --git a/.github/workflows/docker-border-router.yml b/.github/workflows/docker-border-router.yml
new file mode 100644
index 00000000..05895884
--- /dev/null
+++ b/.github/workflows/docker-border-router.yml
@@ -0,0 +1,169 @@
+#
+#  Copyright (c) 2025, The OpenThread Authors.
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
+name: Docker Border Router
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
+permissions:  # added using https://github.com/step-security/secure-workflows
+  contents: read
+
+env:
+  DOCKERHUB_REPO: openthread/border-router
+
+jobs:
+  build:
+    strategy:
+      fail-fast: false
+      matrix:
+        include:
+          - platform: linux/amd64
+            runner: ubuntu-24.04
+          - platform: linux/arm64
+            runner: ubuntu-24.04-arm
+
+    runs-on: ${{ matrix.runner }}
+
+    steps:
+      - name: Harden Runner
+        uses: step-security/harden-runner@0634a2670c59f64b4a01f0f96f84700a4088b9f0 # v2.12.0
+        with:
+          egress-policy: audit # TODO: change to 'egress-policy: block' after couple of runs
+
+      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
+        with:
+          submodules: true
+
+      - name: Prepare
+        run: |
+          platform=${{ matrix.platform }}
+          echo "PLATFORM_PAIR=${platform//\//-}" >> $GITHUB_ENV
+
+      - name: Docker meta
+        id: meta
+        uses: docker/metadata-action@v5
+        with:
+          images: |
+            ${{ env.DOCKERHUB_REPO }}
+
+      - name: Login to Docker Hub
+        if: success() && github.repository == 'openthread/ot-br-posix' && github.event_name != 'pull_request'
+        uses: docker/login-action@9780b0c442fbb1117ed29e0efdff1e18412f7567 # v3.3.0
+        with:
+          username: ${{ secrets.DOCKER_USERNAME }}
+          password: ${{ secrets.DOCKER_PASSWORD }}
+
+      - name: Set up Docker Buildx
+        uses: docker/setup-buildx-action@b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2 # v3.10.0
+
+      - name: Build and push by digest
+        if: success()
+        id: build
+        uses: docker/build-push-action@v6
+        with:
+          file: etc/docker/border-router/Dockerfile
+          build-args: |
+              GITHUB_REPO=${{ github.repository }}
+              GIT_COMMIT=${{ github.sha }}
+          platforms: ${{ matrix.platform }}
+          labels: ${{ steps.meta.outputs.labels }}
+          outputs: type=image,"name=${{ env.DOCKERHUB_REPO }}",push-by-digest=true,name-canonical=true
+          push: ${{ github.repository == 'openthread/ot-br-posix' && github.event_name != 'pull_request' }}
+
+      - name: Export digest
+        if: success() && github.repository == 'openthread/ot-br-posix' && github.event_name != 'pull_request'
+        run: |
+          mkdir -p ${{ runner.temp }}/digests
+          digest="${{ steps.build.outputs.digest }}"
+          touch "${{ runner.temp }}/digests/${digest#sha256:}"
+
+      - name: Upload digest
+        if: success() && github.repository == 'openthread/ot-br-posix' && github.event_name != 'pull_request'
+        uses: actions/upload-artifact@4cec3d8aa04e39d1a68397de0c4cd6fb9dce8ec1 # v4.6.1
+        with:
+          name: digests-${{ env.PLATFORM_PAIR }}
+          path: ${{ runner.temp }}/digests/*
+          if-no-files-found: error
+          retention-days: 1
+
+  merge:
+    if: success() && github.repository == 'openthread/ot-br-posix' && github.event_name != 'pull_request'
+    runs-on: ubuntu-latest
+    needs:
+      - build
+    steps:
+      - name: Harden Runner
+        uses: step-security/harden-runner@0634a2670c59f64b4a01f0f96f84700a4088b9f0 # v2.12.0
+        with:
+          egress-policy: audit # TODO: change to 'egress-policy: block' after couple of runs
+
+      - name: Download digests
+        uses: actions/download-artifact@v4
+        with:
+          path: ${{ runner.temp }}/digests
+          pattern: digests-*
+          merge-multiple: true
+
+      - name: Login to Docker Hub
+        uses: docker/login-action@9780b0c442fbb1117ed29e0efdff1e18412f7567 # v3.3.0
+        with:
+          username: ${{ secrets.DOCKER_USERNAME }}
+          password: ${{ secrets.DOCKER_PASSWORD }}
+
+      - name: Set up Docker Buildx
+        uses: docker/setup-buildx-action@b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2 # v3.10.0
+
+      - name: Docker meta
+        id: meta
+        uses: docker/metadata-action@v5
+        with:
+          images: |
+            ${{ env.DOCKERHUB_REPO }}
+          tags: |
+            type=ref,event=branch
+            type=raw,value=latest,enable={{is_default_branch}}
+
+      - name: Create manifest list and push
+        working-directory: ${{ runner.temp }}/digests
+        run: |
+          docker buildx imagetools create $(jq -cr '.tags | map("-t " + .) | join(" ")' <<< "$DOCKER_METADATA_OUTPUT_JSON") \
+            $(printf '${{ env.DOCKERHUB_REPO }}@sha256:%s ' *)
+
+      - name: Inspect image
+        run: |
+          docker buildx imagetools inspect ${{ env.DOCKERHUB_REPO }}:${{ steps.meta.outputs.version }}
diff --git a/.github/workflows/docker.yml b/.github/workflows/docker.yml
index c96d432d..8d0ce019 100644
--- a/.github/workflows/docker.yml
+++ b/.github/workflows/docker.yml
@@ -117,7 +117,7 @@ jobs:
           --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
           --build-arg VCS_REF=${GITHUB_SHA::8} \
           ${{ matrix.build_args }} \
-          ${TAGS} --file etc/docker/Dockerfile ." >> $GITHUB_OUTPUT
+          ${TAGS} --file etc/docker/test/Dockerfile ." >> $GITHUB_OUTPUT
 
     - name: Set up QEMU
       uses: docker/setup-qemu-action@v3
diff --git a/.github/workflows/ncp_mode.yml b/.github/workflows/ncp_mode.yml
index 1c6926d4..db737669 100644
--- a/.github/workflows/ncp_mode.yml
+++ b/.github/workflows/ncp_mode.yml
@@ -53,7 +53,7 @@ jobs:
         OTBR_MDNS: ${{ matrix.mdns }}
         OTBR_COVERAGE: 1
         OTBR_VERBOSE: 1
-        OTBR_OPTIONS: "-DCMAKE_BUILD_TYPE=Debug -DOT_THREAD_VERSION=1.4 -DOTBR_COVERAGE=ON -DOTBR_DBUS=ON -DOTBR_FEATURE_FLAGS=ON -DOTBR_TELEMETRY_DATA_API=ON -DOTBR_UNSECURE_JOIN=ON -DOTBR_TREL=ON -DOTBR_SRP_ADVERTISING_PROXY=ON -DBUILD_TESTING=OFF"
+        OTBR_OPTIONS: "-DCMAKE_BUILD_TYPE=Debug -DOT_THREAD_VERSION=1.4 -DOTBR_COVERAGE=ON -DOTBR_DBUS=ON -DOTBR_FEATURE_FLAGS=ON -DOTBR_TELEMETRY_DATA_API=ON -DOTBR_UNSECURE_JOIN=ON -DOTBR_TREL=ON -DOTBR_SRP_ADVERTISING_PROXY=ON -DOTBR_BACKBONE_ROUTER=ON -DBUILD_TESTING=OFF"
     steps:
     - uses: actions/checkout@v4
       with:
@@ -66,16 +66,14 @@ jobs:
     - name: Build OTBR Docker Image
       run: |
         sudo docker build -t otbr-ncp \
-            -f ./etc/docker/Dockerfile . \
+            -f ./etc/docker/test/Dockerfile . \
             --build-arg NAT64=0 \
-            --build-arg NAT64_SERVICE=0 \
-            --build-arg DNS64=0 \
             --build-arg WEB_GUI=0 \
             --build-arg REST_API=0 \
             --build-arg FIREWALL=0 \
             --build-arg OTBR_OPTIONS="${OTBR_OPTIONS}"
     - name: Run
       run: |
-        top_builddir="./build/temp" tests/scripts/ncp_mode build_ot_sim expect
+        top_builddir="./build/temp" tests/scripts/ncp_mode build_ot_sim build_ot_commissioner expect
     - name: Codecov
       uses: codecov/codecov-action@v5
diff --git a/Android.bp b/Android.bp
index c330e028..18cb137a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -140,6 +140,7 @@ cc_defaults {
         "-DOTBR_ENABLE_BORDER_ROUTING=1",
         "-DOTBR_ENABLE_BORDER_ROUTING_COUNTERS=1",
         "-DOTBR_ENABLE_BORDER_AGENT=1",
+        "-DOTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE=1",
         "-DOTBR_ENABLE_PUBLISH_MESHCOP_BA_ID=1",
         // Used for bypassing the macro check. In fact mdnssd is not used because we don't compile
         // the related source files.
@@ -186,10 +187,13 @@ cc_defaults {
         "src/host/async_task.cpp",
         "src/host/ncp_host.cpp",
         "src/host/ncp_spinel.cpp",
+        "src/host/posix/cli_daemon.cpp",
         "src/host/posix/dnssd.cpp",
         "src/host/posix/infra_if.cpp",
+        "src/host/posix/multicast_routing_manager.cpp",
         "src/host/posix/netif_linux.cpp",
         "src/host/posix/netif.cpp",
+        "src/host/posix/udp_proxy.cpp",
         "src/host/rcp_host.cpp",
         "src/host/thread_host.cpp",
         "src/sdp_proxy/advertising_proxy.cpp",
diff --git a/README.md b/README.md
index b3dcc3ef..cf1d0ffe 100644
--- a/README.md
+++ b/README.md
@@ -1,4 +1,4 @@
-[![Build Status][ot-gh-action-build-svg]][ot-gh-action-build] [![Docker Status][ot-gh-action-docker-svg]][ot-gh-action-docker] [![Build Status][otbr-travis-svg]][otbr-travis] [![Coverage Status][otbr-codecov-svg]][otbr-codecov]
+[![Build Status][ot-gh-action-build-svg]][ot-gh-action-build] [![Docker Status][ot-gh-action-docker-svg]][ot-gh-action-docker] [![Build Status][otbr-travis-svg]][otbr-travis] [![Coverage Status][otbr-codecov-svg]][otbr-codecov] [![Ask DeepWiki][deepwiki-svg]][deepwiki]
 
 ---
 
@@ -23,7 +23,6 @@ OTBR includes a number of features, including:
 - Thread Border Agent to support an External Commissioner
 - DHCPv6 Prefix Delegation to obtain IPv6 prefixes for a Thread network
 - NAT64 for connecting to IPv4 networks
-- DNS64 to allow Thread devices to initiate communications by name to an IPv4-only server
 - Docker support
 
 More information about Thread can be found at [threadgroup.org](http://threadgroup.org/). Thread is a registered trademark of the Thread Group, Inc.
@@ -36,6 +35,8 @@ More information about Thread can be found at [threadgroup.org](http://threadgro
 [otbr-travis-svg]: https://travis-ci.org/openthread/ot-br-posix.svg?branch=main
 [otbr-codecov]: https://codecov.io/gh/openthread/ot-br-posix
 [otbr-codecov-svg]: https://codecov.io/gh/openthread/ot-br-posix/branch/main/graph/badge.svg
+[deepwiki]: https://deepwiki.com/openthread/ot-br-posix
+[deepwiki-svg]: https://deepwiki.com/badge.svg
 
 ## Getting started
 
diff --git a/etc/cmake/options.cmake b/etc/cmake/options.cmake
index dfac0586..ff91b2fe 100644
--- a/etc/cmake/options.cmake
+++ b/etc/cmake/options.cmake
@@ -36,6 +36,11 @@ if (OTBR_BORDER_AGENT)
     target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_BORDER_AGENT=1)
 endif()
 
+option(OTBR_BORDER_AGENT_MESHCOP_SERVICE "Enable Border Agent to register MeshCoP mDNS service" ${OTBR_BORDER_AGENT})
+if (OTBR_BORDER_AGENT_MESHCOP_SERVICE)
+    target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE=1)
+endif()
+
 option(OTBR_BACKBONE_ROUTER "Enable Backbone Router" OFF)
 if (OTBR_BACKBONE_ROUTER)
     target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_BACKBONE_ROUTER=1)
@@ -88,12 +93,26 @@ if (OTBR_SRP_ADVERTISING_PROXY)
     target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_SRP_ADVERTISING_PROXY=1)
 endif()
 
-cmake_dependent_option(OTBR_SRP_SERVER_AUTO_ENABLE "Enable SRP server auto enable mode" ON "OTBR_SRP_ADVERTISING_PROXY;OTBR_BORDER_ROUTING" OFF)
+option(OTBR_OT_SRP_ADV_PROXY "Enable OT core Advertising Proxy" OFF)
+if (OTBR_OT_SRP_ADV_PROXY)
+    target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_OT_SRP_ADV_PROXY=1)
+endif()
+
+if (OTBR_OT_SRP_ADV_PROXY AND OTBR_SRP_ADVERTISING_PROXY)
+    message(FATAL_ERROR "Only one Advertising Proxy can be enabled.")
+endif()
+
+option(OTBR_SRP_SERVER_AUTO_ENABLE "Enable SRP server auto enable mode" OFF)
 if (OTBR_SRP_SERVER_AUTO_ENABLE)
     target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_SRP_SERVER_AUTO_ENABLE_MODE=1)
 endif()
 
-option(OTBR_DNSSD_DISCOVERY_PROXY   "Enable DNS-SD Discovery Proxy support" OFF)
+option(OTBR_SRP_SERVER_ON_INIT "Enable SRP server on initialization" OFF)
+if (OTBR_SRP_SERVER_ON_INIT)
+    target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_SRP_SERVER_ON_INIT=1)
+endif()
+
+option(OTBR_DNSSD_DISCOVERY_PROXY "Enable DNS-SD Discovery Proxy support" OFF)
 if (OTBR_DNSSD_DISCOVERY_PROXY)
     target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_DNSSD_DISCOVERY_PROXY=1)
 endif()
@@ -172,7 +191,7 @@ else()
     target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_POWER_CALIBRATION=0)
 endif()
 
-option(OTBR_DNSSD_PLAT "Enable OTBR DNS-SD platform implementation" OFF)
+option(OTBR_DNSSD_PLAT "Enable OTBR DNS-SD platform implementation" ${OTBR_OT_SRP_ADV_PROXY})
 if (OTBR_DNSSD_PLAT)
     target_compile_definitions(otbr-config INTERFACE OTBR_ENABLE_DNSSD_PLAT=1)
 else()
diff --git a/etc/docker/border-router/Dockerfile b/etc/docker/border-router/Dockerfile
new file mode 100644
index 00000000..399b2883
--- /dev/null
+++ b/etc/docker/border-router/Dockerfile
@@ -0,0 +1,107 @@
+#
+#  Copyright (c) 2025, The OpenThread Authors.
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
+FROM ubuntu:24.04
+
+ARG GITHUB_REPO="openthread/ot-br-posix"
+ARG GIT_COMMIT="HEAD"
+ARG TARGETARCH
+
+ENV MDNS_RESPONDER_SOURCE_NAME=mDNSResponder-2600.100.147
+ENV S6_OVERLAY_VERSION=3.2.0.2
+
+SHELL ["/bin/bash", "-o", "pipefail", "-c"]
+
+WORKDIR /usr/src
+
+RUN set -x \
+    && apt-get update \
+    && apt-get install -y --no-install-recommends \
+           build-essential \
+           ca-certificates \
+           cmake \
+           curl \
+           git \
+           ipset \
+           iptables \
+           ninja-build \
+           wget \
+    \
+    && case "${TARGETARCH}" in \
+         amd64) S6_ARCH="x86_64" ;; \
+         arm64) S6_ARCH="aarch64" ;; \
+         *) echo "Unsupported architecture: ${TARGETARCH}"; exit 1 ;; \
+       esac \
+    && curl -L -f -s "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz" \
+        | tar Jxvf - -C / \
+    && curl -L -f -s "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}.tar.xz" \
+        | tar Jxvf - -C / \
+    \
+    && git clone --depth 1 -b main https://github.com/"${GITHUB_REPO}".git \
+    \
+    && (wget --no-check-certificate https://github.com/apple-oss-distributions/mDNSResponder/archive/refs/tags/$MDNS_RESPONDER_SOURCE_NAME.tar.gz \
+        && mkdir -p $MDNS_RESPONDER_SOURCE_NAME \
+        && tar xvf $MDNS_RESPONDER_SOURCE_NAME.tar.gz -C $MDNS_RESPONDER_SOURCE_NAME --strip-components=1 \
+        && cd $MDNS_RESPONDER_SOURCE_NAME \
+        && cd mDNSPosix \
+        && make os=linux tls=no \
+        && make install os=linux tls=no) \
+    \
+    && cd ot-br-posix \
+    && git fetch origin "${GIT_COMMIT}" \
+    && git checkout "${GIT_COMMIT}" \
+    && git submodule update --depth 1 --init \
+    && cmake -GNinja \
+           -DBUILD_TESTING=OFF \
+           -DCMAKE_INSTALL_PREFIX=/usr \
+           -DOTBR_BORDER_ROUTING=ON \
+           -DOTBR_BACKBONE_ROUTER=ON \
+           -DOTBR_DBUS=OFF \
+           -DOTBR_MDNS=mDNSResponder \
+           -DOTBR_DNSSD_DISCOVERY_PROXY=ON \
+           -DOTBR_SRP_ADVERTISING_PROXY=ON \
+           -DOTBR_TREL=ON \
+           -DOTBR_NAT64=ON \
+           -DOTBR_DNS_UPSTREAM_QUERY=ON \
+           -DOT_POSIX_NAT64_CIDR="192.168.255.0/24" \
+           -DOT_FIREWALL=ON \
+    && ninja \
+    && ninja install \
+    && cp -r etc/docker/border-router/rootfs/. / \
+    && apt-get purge -y --auto-remove \
+           build-essential \
+           ca-certificates \
+           cmake \
+           curl \
+           git \
+           ninja-build \
+           wget \
+    && rm -rf /var/lib/apt/lists/* \
+    && rm -rf /usr/src/*
+
+ENTRYPOINT ["/init"]
diff --git a/etc/docker/border-router/otbr-env.list b/etc/docker/border-router/otbr-env.list
new file mode 100644
index 00000000..be30a200
--- /dev/null
+++ b/etc/docker/border-router/otbr-env.list
@@ -0,0 +1,4 @@
+OT_LOG_LEVEL=7
+OT_RCP_DEVICE=spinel+hdlc+uart:///dev/ttyACM0?uart-baudrate=1000000
+OT_INFRA_IF=wlan0
+OT_THREAD_IF=wpan0
diff --git a/examples/platforms/beagleboneblack/default b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/mdns/finish
old mode 100644
new mode 100755
similarity index 88%
rename from examples/platforms/beagleboneblack/default
rename to etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/mdns/finish
index 0f32d414..5b4ffcd2
--- a/examples/platforms/beagleboneblack/default
+++ b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/mdns/finish
@@ -1,6 +1,6 @@
-#!/bin/sh
+#!/usr/bin/env bash
 #
-#  Copyright (c) 2017-2021, The OpenThread Authors.
+#  Copyright (c) 2025, The OpenThread Authors.
 #  All rights reserved.
 #
 #  Redistribution and use in source and binary forms, with or without
@@ -27,12 +27,4 @@
 #  POSSIBILITY OF SUCH DAMAGE.
 #
 
-# shellcheck disable=SC2034
-NAT64=1
-DNS64=0
-DHCPV6_PD=0
-NETWORK_MANAGER=0
-BACKBONE_ROUTER=1
-BORDER_ROUTING=1
-WEB_GUI=1
-REST_API=1
+echo "mDNS ended with exit code ${1} (signal ${2})..."
diff --git a/.github/workflows/documentation.yml b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/mdns/run
old mode 100644
new mode 100755
similarity index 62%
rename from .github/workflows/documentation.yml
rename to etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/mdns/run
index d9d9e62c..9cdddcf4
--- a/.github/workflows/documentation.yml
+++ b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/mdns/run
@@ -1,5 +1,6 @@
+#!/usr/bin/env bash
 #
-#  Copyright (c) 2021, The OpenThread Authors.
+#  Copyright (c) 2025, The OpenThread Authors.
 #  All rights reserved.
 #
 #  Redistribution and use in source and binary forms, with or without
@@ -26,38 +27,6 @@
 #  POSSIBILITY OF SUCH DAMAGE.
 #
 
-name: Documentation
+echo "Starting mDNSResponder..."
 
-on:
-  push:
-    branches:
-      - 'main'
-
-concurrency:
-  group: ${{ github.workflow }}-${{ github.event.pull_request.number || (github.repository == 'openthread/ot-br-posix' && github.run_id) || github.ref }}
-  cancel-in-progress: true
-
-jobs:
-  doxygen:
-    runs-on: ubuntu-latest
-    env:
-      BUILD_TARGET: check
-    steps:
-    - uses: actions/checkout@v4
-      with:
-        submodules: true
-    - name: Bootstrap
-      run: |
-        tests/scripts/bootstrap.sh
-        sudo apt-get install -y libglib2.0-dev-bin xmlto
-    - name: Generate
-      run: |
-        mkdir build-doc
-        cd build-doc
-        cmake -DBUILD_TESTING=OFF -DOTBR_DOC=ON -DOTBR_DBUS=ON ..
-        make otbr-doc
-    - name: Deploy
-      uses: peaceiris/actions-gh-pages@v4
-      with:
-        github_token: ${{ secrets.GITHUB_TOKEN }}
-        publish_dir: ./build-doc/doc/html
+exec /usr/sbin/mdnsd -debug
diff --git a/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/mdns/type b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/mdns/type
new file mode 100644
index 00000000..5883cff0
--- /dev/null
+++ b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/mdns/type
@@ -0,0 +1 @@
+longrun
diff --git a/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/data/check b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/data/check
new file mode 100755
index 00000000..ccfa100c
--- /dev/null
+++ b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/data/check
@@ -0,0 +1,31 @@
+#!/usr/bin/env bash
+#
+#  Copyright (c) 2025, The OpenThread Authors.
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
+test -S /run/openthread-wpan0.sock
+exit
diff --git a/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/dependencies.d/base b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/dependencies.d/base
new file mode 100644
index 00000000..e69de29b
diff --git a/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/dependencies.d/mdns b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/dependencies.d/mdns
new file mode 100644
index 00000000..e69de29b
diff --git a/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/finish b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/finish
new file mode 100755
index 00000000..09de208d
--- /dev/null
+++ b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/finish
@@ -0,0 +1,71 @@
+#!/command/with-contenv bash
+#
+#  Copyright (c) 2025, The OpenThread Authors.
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
+OT_THREAD_IF="${OT_THREAD_IF:-wpan0}"
+readonly OT_THREAD_IF
+
+OT_FORWARD_INGRESS_CHAIN="OT_FORWARD_INGRESS"
+readonly OT_FORWARD_INGRESS_CHAIN
+
+if test "$1" -eq 256 ; then
+  e=$((128 + $2))
+else
+  e="$1"
+fi
+
+echo "otbr-agent exited with code ${1} (by signal ${2})."
+
+ipset_destroy_if_exist()
+{
+    while ipset list -n "$1" 2> /dev/null; do
+        ipset destroy "$1" || true
+    done
+}
+
+while ip6tables -C FORWARD -o "${OT_THREAD_IF}" -j "${OT_FORWARD_INGRESS_CHAIN}" 2> /dev/null; do
+    ip6tables -D FORWARD -o "${OT_THREAD_IF}" -j "${OT_FORWARD_INGRESS_CHAIN}"
+done
+
+if ip6tables -L "${OT_FORWARD_INGRESS_CHAIN}" 2> /dev/null; then
+    ip6tables -w -F "${OT_FORWARD_INGRESS_CHAIN}"
+    ip6tables -w -X "${OT_FORWARD_INGRESS_CHAIN}"
+fi
+
+ipset_destroy_if_exist otbr-ingress-deny-src
+ipset_destroy_if_exist otbr-ingress-deny-src-swap
+ipset_destroy_if_exist otbr-ingress-allow-dst
+ipset_destroy_if_exist otbr-ingress-allow-dst-swap
+
+echo "OpenThread firewall rules removed."
+
+if test "$e" -ne 0; then
+    echo "$e" > /run/s6-linux-init-container-results/exitcode
+    /run/s6/basedir/bin/halt
+    exit 125
+fi
diff --git a/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/notification-fd b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/notification-fd
new file mode 100644
index 00000000..00750edc
--- /dev/null
+++ b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/notification-fd
@@ -0,0 +1 @@
+3
diff --git a/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/run b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/run
new file mode 100755
index 00000000..7ca7476d
--- /dev/null
+++ b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/run
@@ -0,0 +1,84 @@
+#!/command/with-contenv bash
+#
+#  Copyright (c) 2025, The OpenThread Authors.
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
+OT_LOG_LEVEL="${OT_LOG_LEVEL:-7}"
+readonly OT_LOG_LEVEL
+
+OT_RCP_DEVICE="${OT_RCP_DEVICE:-spinel+hdlc+uart:///dev/ttyACM0?uart-baudrate=1000000}"
+readonly OT_RCP_DEVICE
+
+OT_INFRA_IF="${OT_INFRA_IF:-wlan0}"
+readonly OT_INFRA_IF
+
+OT_THREAD_IF="${OT_THREAD_IF:-wpan0}"
+readonly OT_THREAD_IF
+
+OT_FORWARD_INGRESS_CHAIN="OT_FORWARD_INGRESS"
+readonly OT_FORWARD_INGRESS_CHAIN
+
+die()
+{
+    echo >&2 "ERROR: $*"
+    exit 1
+}
+
+mkdir -p /data/thread && ln -sft /var/lib /data/thread || die "Could not create directory /var/lib/thread to store Thread data."
+
+echo "Configuring OpenThread firewall..."
+
+ipset create -exist otbr-ingress-deny-src hash:net family inet6
+ipset create -exist otbr-ingress-deny-src-swap hash:net family inet6
+ipset create -exist otbr-ingress-allow-dst hash:net family inet6
+ipset create -exist otbr-ingress-allow-dst-swap hash:net family inet6
+
+ip6tables -N "${OT_FORWARD_INGRESS_CHAIN}"
+ip6tables -I FORWARD 1 -o "${OT_THREAD_IF}" -j "${OT_FORWARD_INGRESS_CHAIN}"
+
+ip6tables -A "${OT_FORWARD_INGRESS_CHAIN}" -m pkttype --pkt-type unicast -i "${OT_THREAD_IF}" -j DROP
+ip6tables -A "${OT_FORWARD_INGRESS_CHAIN}" -m set --match-set otbr-ingress-deny-src src -j DROP
+ip6tables -A "${OT_FORWARD_INGRESS_CHAIN}" -m set --match-set otbr-ingress-allow-dst dst -j ACCEPT
+ip6tables -A "${OT_FORWARD_INGRESS_CHAIN}" -m pkttype --pkt-type unicast -j DROP
+ip6tables -A "${OT_FORWARD_INGRESS_CHAIN}" -j ACCEPT
+
+echo "Configuring OpenThread NAT64..."
+
+iptables -t mangle -A PREROUTING -i "${OT_THREAD_IF}" -j MARK --set-mark 0x1001
+iptables -t nat -A POSTROUTING -m mark --mark 0x1001 -j MASQUERADE
+iptables -t filter -A FORWARD -o "${OT_INFRA_IF}" -j ACCEPT
+iptables -t filter -A FORWARD -i "${OT_INFRA_IF}" -j ACCEPT
+
+echo "Starting otbr-agent..."
+
+exec s6-notifyoncheck -d -s 300 -w 300 -n 0 stdbuf -oL \
+     "/usr/sbin/otbr-agent" \
+        -d"${OT_LOG_LEVEL}" -v -s \
+        -I "${OT_THREAD_IF}" \
+        -B "${OT_INFRA_IF}" \
+	"${OT_RCP_DEVICE}" \
+        "trel://${OT_INFRA_IF}"
diff --git a/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/type b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/type
new file mode 100644
index 00000000..5883cff0
--- /dev/null
+++ b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/otbr-agent/type
@@ -0,0 +1 @@
+longrun
diff --git a/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/user/contents.d/mdns b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/user/contents.d/mdns
new file mode 100644
index 00000000..e69de29b
diff --git a/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/user/contents.d/otbr-agent b/etc/docker/border-router/rootfs/etc/s6-overlay/s6-rc.d/user/contents.d/otbr-agent
new file mode 100644
index 00000000..e69de29b
diff --git a/etc/docker/border-router/setup-host b/etc/docker/border-router/setup-host
new file mode 100755
index 00000000..4fd3698a
--- /dev/null
+++ b/etc/docker/border-router/setup-host
@@ -0,0 +1,77 @@
+#!/bin/bash
+#
+#  Copyright (c) 2025, The OpenThread Authors.
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
+set -euxo pipefail
+
+INFRA_IF_NAME="${INFRA_IF_NAME:-wlan0}"
+readonly INFRA_IF_NAME
+
+SYSCTL_ACCEPT_RA_FILE="/etc/sysctl.d/60-otbr-accept-ra.conf"
+readonly SYSCTL_ACCEPT_RA_FILE
+
+SYSCTL_IP_FORWARD_FILE="/etc/sysctl.d/60-otbr-ip-forward.conf"
+readonly SYSCTL_IP_FORWARD_FILE
+
+accept_ra_install()
+{
+    sudo tee $SYSCTL_ACCEPT_RA_FILE <<EOF
+net.ipv6.conf.${INFRA_IF_NAME}.accept_ra = 2
+net.ipv6.conf.${INFRA_IF_NAME}.accept_ra_rt_info_max_plen = 64
+EOF
+}
+
+accept_ra_enable()
+{
+    echo 2 | sudo tee /proc/sys/net/ipv6/conf/"${INFRA_IF_NAME}"/accept_ra || die 'Failed to enable IPv6 RA!'
+    echo 64 | sudo tee /proc/sys/net/ipv6/conf/"${INFRA_IF_NAME}"/accept_ra_rt_info_max_plen || die 'Failed to enable IPv6 RIO!'
+}
+
+ipforward_install()
+{
+    sudo tee $SYSCTL_IP_FORWARD_FILE <<EOF
+net.ipv6.conf.all.forwarding = 1
+net.ipv4.ip_forward = 1
+EOF
+}
+
+ipforward_enable()
+{
+    echo 1 | sudo tee /proc/sys/net/ipv6/conf/all/forwarding || die 'Failed to enable IPv6 forwarding!'
+    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward || die 'Failed to enable IPv4 forwarding!'
+}
+
+main()
+{
+    accept_ra_install
+    accept_ra_enable
+    ipforward_install
+    ipforward_enable
+}
+
+main
diff --git a/etc/docker/Dockerfile b/etc/docker/test/Dockerfile
similarity index 91%
rename from etc/docker/Dockerfile
rename to etc/docker/test/Dockerfile
index 800b00e3..3c7eb999 100644
--- a/etc/docker/Dockerfile
+++ b/etc/docker/test/Dockerfile
@@ -33,9 +33,7 @@ ARG BORDER_ROUTING
 ARG BACKBONE_ROUTER
 ARG OT_BACKBONE_CI
 ARG OTBR_OPTIONS
-ARG DNS64
 ARG NAT64
-ARG NAT64_SERVICE
 ARG NAT64_DYNAMIC_POOL
 ARG REFERENCE_DEVICE
 ARG RELEASE
@@ -43,7 +41,7 @@ ARG REST_API
 ARG WEB_GUI
 ARG MDNS
 ARG FIREWALL
-ARG DNSSD_PLAT
+ARG OT_SRP_ADV_PROXY
 
 ENV INFRA_IF_NAME=${INFRA_IF_NAME:-eth0}
 ENV BORDER_ROUTING=${BORDER_ROUTING:-1}
@@ -56,13 +54,11 @@ ENV PLATFORM ubuntu
 ENV REFERENCE_DEVICE=${REFERENCE_DEVICE:-0}
 ENV RELEASE=${RELEASE:-1}
 ENV NAT64=${NAT64:-1}
-ENV NAT64_SERVICE=${NAT64_SERVICE:-openthread}
 ENV NAT64_DYNAMIC_POOL=${NAT64_DYNAMIC_POOL:-192.168.255.0/24}
-ENV DNS64=${DNS64:-0}
 ENV WEB_GUI=${WEB_GUI:-1}
 ENV REST_API=${REST_API:-1}
 ENV FIREWALL=${FIREWALL:-1}
-ENV DNSSD_PLAT=${DNSSD_PLAT:-0}
+ENV OT_SRP_ADV_PROXY=${OT_SRP_ADV_PROXY:-0}
 ENV DOCKER 1
 
 RUN env
@@ -94,15 +90,13 @@ RUN apt-get update \
   && ln -fs /usr/share/zoneinfo/UTC /etc/localtime
 
 COPY ./script /app/script
-COPY ./third_party/mDNSResponder /app/third_party/mDNSResponder
 WORKDIR /app
 
 RUN ./script/bootstrap
 COPY . .
 RUN ./script/setup
 
-RUN ([ "${DNS64}" = "0" ] || chmod 644 /etc/bind/named.conf.options) \
-  && ([ "${OT_BACKBONE_CI}" = "1" ] || ( \
+RUN ([ "${OT_BACKBONE_CI}" = "1" ] || ( \
     mv ./script /tmp \
     && mv ./etc /tmp \
     && find . -delete \
@@ -115,6 +109,6 @@ RUN ([ "${DNS64}" = "0" ] || chmod 644 /etc/bind/named.conf.options) \
     && rm -rf /tmp/* \
   ))
 
-ENTRYPOINT ["/app/etc/docker/docker_entrypoint.sh"]
+ENTRYPOINT ["/app/etc/docker/test/docker_entrypoint.sh"]
 
 EXPOSE 80
diff --git a/etc/docker/README.md b/etc/docker/test/README.md
similarity index 100%
rename from etc/docker/README.md
rename to etc/docker/test/README.md
diff --git a/etc/docker/docker_entrypoint.sh b/etc/docker/test/docker_entrypoint.sh
similarity index 87%
rename from etc/docker/docker_entrypoint.sh
rename to etc/docker/test/docker_entrypoint.sh
index d39abed5..76de8e56 100755
--- a/etc/docker/docker_entrypoint.sh
+++ b/etc/docker/test/docker_entrypoint.sh
@@ -53,11 +53,6 @@ function parse_args()
                 shift
                 shift
                 ;;
-            --nat64-prefix)
-                NAT64_PREFIX=$2
-                shift
-                shift
-                ;;
             --debug-level)
                 DEBUG_LEVEL=$2
                 shift
@@ -85,7 +80,6 @@ parse_args "$@"
 [ -n "$TREL_URL" ] || TREL_URL=""
 [ -n "$TUN_INTERFACE_NAME" ] || TUN_INTERFACE_NAME="wpan0"
 [ -n "$BACKBONE_INTERFACE" ] || BACKBONE_INTERFACE="eth0"
-[ -n "$NAT64_PREFIX" ] || NAT64_PREFIX="64:ff9b::/96"
 [ -n "$DEBUG_LEVEL" ] || DEBUG_LEVEL="7"
 [ -n "$HTTP_PORT" ] || HTTP_PORT=80
 
@@ -93,15 +87,8 @@ echo "RADIO_URL:" $RADIO_URL
 echo "TREL_URL:" "$TREL_URL"
 echo "TUN_INTERFACE_NAME:" $TUN_INTERFACE_NAME
 echo "BACKBONE_INTERFACE: $BACKBONE_INTERFACE"
-echo "NAT64_PREFIX:" $NAT64_PREFIX
 echo "DEBUG_LEVEL:" $DEBUG_LEVEL
 
-NAT64_PREFIX=${NAT64_PREFIX/\//\\\/}
-TAYGA_CONF=/etc/tayga.conf
-BIND_CONF_OPTIONS=/etc/bind/named.conf.options
-
-! test -f $TAYGA_CONF || sed -i "s/^prefix.*$/prefix $NAT64_PREFIX/" $TAYGA_CONF
-! test -f $BIND_CONF_OPTIONS || sed -i "s/dns64.*$/dns64 $NAT64_PREFIX {};/" $BIND_CONF_OPTIONS
 sed -i "s/$INFRA_IF_NAME/$BACKBONE_INTERFACE/" /etc/sysctl.d/60-otbr-accept-ra.conf
 
 echo "OTBR_AGENT_OPTS=\"-I $TUN_INTERFACE_NAME -B $BACKBONE_INTERFACE -d${DEBUG_LEVEL} $RADIO_URL $TREL_URL\"" >/etc/default/otbr-agent
diff --git a/etc/openwrt/openthread-br/Makefile b/etc/openwrt/openthread-br/Makefile
index a9199378..6f540a7b 100644
--- a/etc/openwrt/openthread-br/Makefile
+++ b/etc/openwrt/openthread-br/Makefile
@@ -52,8 +52,7 @@ CMAKE_OPTIONS+= \
 	-DOT_FIREWALL=ON \
 	-DOT_POSIX_SETTINGS_PATH=\"/etc/openthread\" \
 	-DOT_READLINE=OFF \
-	-DOTBR_NAT64=OFF \
-	-DNAT64_SERVICE=\"openthread\"
+	-DOTBR_NAT64=OFF
 
 TARGET_CFLAGS += -DOPENTHREAD_POSIX_CONFIG_DAEMON_SOCKET_BASENAME=\\\"/var/run/openthread-%s\\\"
 
diff --git a/etc/openwrt/openthread-br/README.md b/etc/openwrt/openthread-br/README.md
index a4f91803..a99d5bf6 100644
--- a/etc/openwrt/openthread-br/README.md
+++ b/etc/openwrt/openthread-br/README.md
@@ -61,8 +61,8 @@ NOTES:
 Start otbr-agent manually:
 
 ```bash
-# Assuming that ttyACM0 is a RCP with baudrate 115200.
-/usr/sbin/otbr-agent -I wpan0 'spinel+hdlc+uart:///dev/ttyACM0?uart-baudrate=115200'
+# Assuming that ttyACM0 is a RCP with baudrate 460800.
+/usr/sbin/otbr-agent -I wpan0 'spinel+hdlc+uart:///dev/ttyACM0?uart-baudrate=460800'
 ```
 
 Edit the service file `/etc/init.d/otbr-agent` if RCP device is not `/dev/ttyACM0` and then start with:
diff --git a/examples/platforms/debian/default b/examples/platforms/debian/default
index 4482d030..8d2f1189 100644
--- a/examples/platforms/debian/default
+++ b/examples/platforms/debian/default
@@ -29,10 +29,8 @@
 
 # shellcheck disable=SC2034
 NAT64=0
-DNS64=0
 DHCPV6_PD=0
 DHCPV6_PD_REF=0
-NETWORK_MANAGER=0
 BACKBONE_ROUTER=1
 BORDER_ROUTING=1
 REST_API=1
diff --git a/examples/platforms/fedora/default b/examples/platforms/fedora/default
index 079cc616..24f18b6e 100644
--- a/examples/platforms/fedora/default
+++ b/examples/platforms/fedora/default
@@ -29,9 +29,7 @@
 
 # shellcheck disable=SC2034
 NAT64=0
-DNS64=0
 DHCPV6_PD=0
-NETWORK_MANAGER=0
 BACKBONE_ROUTER=0
 BORDER_ROUTING=0
 WEB_GUI=1
diff --git a/examples/platforms/raspbian/default b/examples/platforms/raspbian/default
index feca7493..b46be6e1 100644
--- a/examples/platforms/raspbian/default
+++ b/examples/platforms/raspbian/default
@@ -29,10 +29,8 @@
 
 # shellcheck disable=SC2034
 NAT64=1
-DNS64=0
 DHCPV6_PD=0
 DHCPV6_PD_REF=0
-NETWORK_MANAGER=0
 BACKBONE_ROUTER=1
 BORDER_ROUTING=1
 WEB_GUI=1
diff --git a/examples/platforms/ubuntu/default b/examples/platforms/ubuntu/default
index f5bb3f07..53f0e7f7 100644
--- a/examples/platforms/ubuntu/default
+++ b/examples/platforms/ubuntu/default
@@ -29,9 +29,7 @@
 
 # shellcheck disable=SC2034
 NAT64=1
-DNS64=0
 DHCPV6_PD=0
-NETWORK_MANAGER=0
 BACKBONE_ROUTER=1
 BORDER_ROUTING=1
 WEB_GUI=1
diff --git a/include/openthread-br/config.h b/include/openthread-br/config.h
index a663fd9d..f36102c8 100644
--- a/include/openthread-br/config.h
+++ b/include/openthread-br/config.h
@@ -37,4 +37,31 @@
 #include OTBR_CONFIG_FILE
 #endif
 
+/**
+ * @def OTBR_ENABLE_SRP_SERVER
+ *
+ * Enable SRP server if Advertising Proxy is enabled.
+ */
+#define OTBR_ENABLE_SRP_SERVER (OTBR_ENABLE_SRP_ADVERTISING_PROXY || OTBR_ENABLE_OT_SRP_ADV_PROXY)
+
+/**
+ * @def OTBR_ENABLE_SRP_SERVER_AUTO_ENABLE_MODE
+ *
+ * By default, enable auto-enable mode for SRP server if SRP server and Border Routing are enabled.
+ */
+#ifndef OTBR_ENABLE_SRP_SERVER_AUTO_ENABLE_MODE
+#if !OTBR_ENABLE_SRP_SERVER_ON_INIT
+#define OTBR_ENABLE_SRP_SERVER_AUTO_ENABLE_MODE (OTBR_ENABLE_SRP_SERVER && OTBR_ENABLE_BORDER_ROUTING)
+#endif
+#endif
+
+/**
+ * @def OTBR_CONFIG_CLI_MAX_LINE_LENGTH
+ *
+ * Defines the maximum length of a line in the CLI.
+ */
+#ifndef OTBR_CONFIG_CLI_MAX_LINE_LENGTH
+#define OTBR_CONFIG_CLI_MAX_LINE_LENGTH 640
+#endif
+
 #endif // OTBR_CONFIG_H_
diff --git a/script/_dhcpv6_pd b/script/_dhcpv6_pd
index b2e9e920..a221c7ca 100644
--- a/script/_dhcpv6_pd
+++ b/script/_dhcpv6_pd
@@ -53,7 +53,7 @@ NCP_STATE_NOTIFIER_SERVICE="/etc/systemd/system/${NCP_STATE_NOTIFIER_SERVICE_NAM
 
 DHCPCD_RELOADER="${NCP_STATE_DISPATCHER}/dhcpcd_reloader"
 
-without DHCPV6_PD || test "$PLATFORM" = beagleboneblack || test "$PLATFORM" = raspbian || test "$PLATFORM" = ubuntu || die "DHCPv6-PD is not tested under $PLATFORM."
+without DHCPV6_PD || test "$PLATFORM" = raspbian || test "$PLATFORM" = ubuntu || die "DHCPv6-PD is not tested under $PLATFORM."
 
 create_dhcpcd_conf_with_dhcpv6_pd()
 {
@@ -114,7 +114,7 @@ ia_pd 3/::/63 $WPAN_INTERFACE/1
 
 EOF
 
-    if [ "$PLATFORM" = "raspbian" ] || with NETWORK_MANAGER_WIFI; then
+    if [ "$PLATFORM" = "raspbian" ]; then
         sudo tee -a ${DHCPCD_CONF} <<EOF
 interface $WLAN_INTERFACE
 iaid 4
diff --git a/script/_disable_services b/script/_disable_services
deleted file mode 100644
index d5697978..00000000
--- a/script/_disable_services
+++ /dev/null
@@ -1,77 +0,0 @@
-#!/bin/bash
-#
-#  Copyright (c) 2017, The OpenThread Authors.
-#  All rights reserved.
-#
-#  Redistribution and use in source and binary forms, with or without
-#  modification, are permitted provided that the following conditions are met:
-#  1. Redistributions of source code must retain the above copyright
-#     notice, this list of conditions and the following disclaimer.
-#  2. Redistributions in binary form must reproduce the above copyright
-#     notice, this list of conditions and the following disclaimer in the
-#     documentation and/or other materials provided with the distribution.
-#  3. Neither the name of the copyright holder nor the
-#     names of its contributors may be used to endorse or promote products
-#     derived from this software without specific prior written permission.
-#
-#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
-#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
-#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
-#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
-#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
-#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-#  POSSIBILITY OF SUCH DAMAGE.
-#
-#  Purpose:
-#       Some platforms automatically run various services that interfere with the
-#       OpenThread web service, this script disables those services
-#
-
-bbb_disable_services()
-{
-    SERVICE_LIST=""
-    SERVICE_LIST="${SERVICE_LIST} apache2 " # Debian jessie
-    SERVICE_LIST="${SERVICE_LIST} nginx "   # Debian stretch
-    SERVICE_LIST="${SERVICE_LIST} bonescript-autorun.service"
-    SERVICE_LIST="${SERVICE_LIST} bonescript.socket"
-    SERVICE_LIST="${SERVICE_LIST} bonescript.service"
-    SERVICE_LIST="${SERVICE_LIST} cloud9.socket"
-    SERVICE_LIST="${SERVICE_LIST} cloud9.service"
-    SERVICE_LIST="${SERVICE_LIST} nodered.service"
-    SERVICE_LIST="${SERVICE_LIST} dnsmasq.service" # Disable well before bind9
-
-    if have systemctl; then
-        for service in $SERVICE_LIST; do
-            if [ "$(sudo systemctl is-active "$service")" != "inactive" ]; then
-                for action in stop disable; do
-                    sudo systemctl "$action" "$service"
-                done
-            fi
-        done
-    fi
-
-    # stop avahi from advertising for cloud9 and nodered
-    sudo rm -rf /etc/avahi/services
-    # default dnsmasq configuration for connman tether conflicts with bind9
-    # removing the directory stops the startup script from creating
-    # /etc/dnsmasq.d/SoftAp0
-    sudo rm -rf /etc/dnsmasq.d
-}
-
-disable_services()
-{
-    case $PLATFORM in
-
-        beagleboneblack)
-            bbb_disable_services
-            ;;
-
-        *)
-            echo "Nothing to disable" >/dev/null
-            ;;
-    esac
-}
diff --git a/script/_dns64 b/script/_dns64
deleted file mode 100644
index 8dc01578..00000000
--- a/script/_dns64
+++ /dev/null
@@ -1,157 +0,0 @@
-#!/bin/bash
-#
-#  Copyright (c) 2017, The OpenThread Authors.
-#  All rights reserved.
-#
-#  Redistribution and use in source and binary forms, with or without
-#  modification, are permitted provided that the following conditions are met:
-#  1. Redistributions of source code must retain the above copyright
-#     notice, this list of conditions and the following disclaimer.
-#  2. Redistributions in binary form must reproduce the above copyright
-#     notice, this list of conditions and the following disclaimer in the
-#     documentation and/or other materials provided with the distribution.
-#  3. Neither the name of the copyright holder nor the
-#     names of its contributors may be used to endorse or promote products
-#     derived from this software without specific prior written permission.
-#
-#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
-#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
-#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
-#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
-#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
-#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-#  POSSIBILITY OF SUCH DAMAGE.
-#
-#   Description:
-#       This script manipulates dns64 configuration.
-#
-
-BIND_CONF_OPTIONS=/etc/bind/named.conf.options
-NAT64_PREFIX=64:ff9b::/96
-
-DNS64_NAMESERVER_ADDR=127.0.0.1
-DNS64_CONF="dns64 $(echo $NAT64_PREFIX | tr \"/\" \"/\") { clients { thread; }; recursive-only yes; };"
-
-# Currently solution was verified only on raspbian and ubuntu.
-#
-without NAT64 || without DNS64 || test "$PLATFORM" = ubuntu || test "$PLATFORM" = beagleboneblack || test "$PLATFORM" = raspbian || die "dns64 is not tested under $PLATFORM."
-
-if [ "$PLATFORM" = raspbian ]; then
-    RESOLV_CONF_HEAD=/etc/resolv.conf.head
-elif [ "$PLATFORM" = beagleboneblack ]; then
-    RESOLV_CONF_HEAD=/etc/resolvconf/resolv.conf.d/head
-elif [ "$PLATFORM" = ubuntu ]; then
-    RESOLV_CONF_HEAD=/etc/resolvconf/resolv.conf.d/head
-fi
-
-dns64_update_resolvconf()
-{
-    if [ "$PLATFORM" = ubuntu ]; then
-        sudo resolvconf -u || true
-    elif [ "$PLATFORM" = beagleboneblack ]; then
-        sudo resolvconf -u || true
-    elif [ "$PLATFORM" = raspbian ]; then
-        if systemctl is-enabled NetworkManager; then
-            sudo systemctl restart NetworkManager || true
-        fi
-
-        if systemctl is-enabled dhcpcd; then
-            sudo systemctl restart dhcpcd || true
-        fi
-    fi
-}
-
-_detect_service_name()
-{
-    dpkg -L bind9 | grep /etc/init.d/ | cut -d/ -f4
-}
-
-dns64_install()
-{
-    with NAT64 && with DNS64 || return 0
-
-    test -f $BIND_CONF_OPTIONS || die 'Cannot find bind9 configuration file!'
-    sudo sed -i '/^};/i\\tlisten-on-v6 { thread; };' $BIND_CONF_OPTIONS
-    sudo sed -i '/^\tlisten-on-v6 { a/d' $BIND_CONF_OPTIONS
-    sudo sed -i '/^};/i\\tallow-query { any; };' $BIND_CONF_OPTIONS
-    sudo sed -i '/^};/i\\tallow-recursion { thread; };' $BIND_CONF_OPTIONS
-    sudo sed -i '/^};/i\\tforwarders { 8.8.8.8; 8.8.8.4; };' $BIND_CONF_OPTIONS
-    sudo sed -i '/^};/i\\tforward only;' $BIND_CONF_OPTIONS
-    sudo sed -i '/^};/i\\t'"$DNS64_CONF" $BIND_CONF_OPTIONS
-    sudo sed -i '1s/^/acl thread {\n\tfe80::\/16;\n\tfc00::\/7;\n\t127.0.0.1;\n};\n\n/' $BIND_CONF_OPTIONS
-
-    service_name="$(_detect_service_name)"
-
-    if without DOCKER; then
-        sudo sh -c "echo \"nameserver $DNS64_NAMESERVER_ADDR\" >> $RESOLV_CONF_HEAD"
-    fi
-
-    if have systemctl; then
-        sudo systemctl stop dnsmasq || true
-        sudo systemctl disable dnsmasq || true
-        sudo systemctl enable "${service_name}" || true
-        sudo systemctl is-enabled "${service_name}" || die 'Failed to enable bind9!'
-        sudo systemctl start "${service_name}" || die 'Failed to start bind9!'
-    fi
-
-    if without DOCKER; then
-        dns64_update_resolvconf
-    fi
-}
-
-dns64_uninstall()
-{
-    with NAT64 && with DNS64 || return 0
-
-    service_name="$(_detect_service_name)"
-
-    dns64_stop
-    sudo sed -i '/^\tlisten-on-v6/d' $BIND_CONF_OPTIONS
-    sudo sed -i '/^\tallow-query/d' $BIND_CONF_OPTIONS
-    sudo sed -i '/^\tallow-recursion/d' $BIND_CONF_OPTIONS
-    sudo sed -i '/^\tforward/d' $BIND_CONF_OPTIONS
-    sudo sed -i '/^};/i\\tlisten-on-v6 { any; };' $BIND_CONF_OPTIONS
-    sudo sed -i '/^\tdns64/d' $BIND_CONF_OPTIONS
-    sudo sed -i '/^acl/,/^options/{/^options/!d}' $BIND_CONF_OPTIONS
-
-    sudo sed -i '/^nameserver '$DNS64_NAMESERVER_ADDR'/d' $RESOLV_CONF_HEAD || true
-
-    if without DOCKER; then
-        dns64_update_resolvconf
-    fi
-
-    if have systemctl; then
-        sudo systemctl stop "${service_name}" || true
-        sudo systemctl disable "${service_name}" || true
-    fi
-}
-
-dns64_start()
-{
-    with NAT64 && with DNS64 || return 0
-
-    service_name="$(_detect_service_name)"
-
-    if have systemctl; then
-        sudo systemctl start "${service_name}" || die 'Failed to start bind9!'
-    elif command -v service; then
-        sudo service "${service_name}" start || die 'Failed to start bind9!'
-    fi
-}
-
-dns64_stop()
-{
-    with NAT64 && with DNS64 || return 0
-
-    service_name="$(_detect_service_name)"
-
-    if have systemctl; then
-        sudo systemctl stop "${service_name}" || true
-    elif command -v service; then
-        sudo service "${service_name}" stop || true
-    fi
-}
diff --git a/script/_initrc b/script/_initrc
index be2c7ca8..c630852a 100644
--- a/script/_initrc
+++ b/script/_initrc
@@ -119,21 +119,15 @@ stop_service()
 # Platform information is needed to load hooks and default settings.
 
 if [[ ! ${PLATFORM+x} ]]; then
-    # BeagleBone Black debian distribution does not support "lsb_release"
-    if grep -s "BeagleBone Black" /sys/firmware/devicetree/base/model; then
-        # Note: 'model' is a binary file with no newline
-        PLATFORM=beagleboneblack
-    else
-        case "${OSTYPE}" in
-            darwin*)
-                PLATFORM=macOS
-                ;;
-            *)
-                have_or_die lsb_release
-                PLATFORM=$(lsb_release -i | cut -c17- | tr '[:upper:]' '[:lower:]')
-                ;;
-        esac
-    fi
+    case "${OSTYPE}" in
+        darwin*)
+            PLATFORM=macOS
+            ;;
+        *)
+            have_or_die lsb_release
+            PLATFORM=$(lsb_release -i | cut -c17- | tr '[:upper:]' '[:lower:]')
+            ;;
+    esac
 fi
 echo "Current platform is $PLATFORM"
 
@@ -141,9 +135,6 @@ echo "Current platform is $PLATFORM"
 # is not supported within dhcpcd.
 with BORDER_ROUTING && with DHCPV6_PD && die "BORDER_ROUTING and DHCPV6_PD cannot coexist!"
 
-# OTBR cannot receive RS messages when NETWORK_MANAGER is enabled.
-with BORDER_ROUTING && with NETWORK_MANAGER && die "BORDER_ROUTING and NETWORK_MANAGER cannot coexist!"
-
 STAGE_DIR=$PWD/stage
 BUILD_DIR=$PWD/build
 
diff --git a/script/_nat64 b/script/_nat64
index 521c4d22..1355aff3 100644
--- a/script/_nat64
+++ b/script/_nat64
@@ -30,14 +30,6 @@
 #       This script manipulates nat64 configuration.
 #
 
-NAT64_SERVICE="${NAT64_SERVICE:-openthread}"
-TAYGA_DEFAULT=/etc/default/tayga
-TAYGA_CONF=/etc/tayga.conf
-TAYGA_IPV4_ADDR=192.168.255.1
-TAYGA_IPV6_ADDR=fdaa:bb:1::1
-TAYGA_TUN_V6_ADDR=fdaa:bb:1::2
-NAT64_PREFIX=64:ff9b::/96
-DYNAMIC_POOL="${NAT64_DYNAMIC_POOL:-192.168.255.0/24}"
 NAT44_SERVICE=/etc/init.d/otbr-nat44
 WLAN_IFNAMES="${INFRA_IF_NAME:-eth0}"
 THREAD_IF="${THREAD_IF:-wpan0}"
@@ -46,60 +38,6 @@ THREAD_IF="${THREAD_IF:-wpan0}"
 #
 #without NAT64 || test $PLATFORM = ubuntu || test $PLATFORM = raspbian || die "nat64 is not tested under $PLATFORM."
 
-tayga_install()
-{
-    test -f $TAYGA_DEFAULT -a -f $TAYGA_CONF || die 'Cannot find tayga configuration file!'
-    sudo sed -i 's/^RUN="no"/RUN="yes"/' $TAYGA_DEFAULT
-    sudo sed -i 's/^IPV4_TUN_ADDR=""/IPV4_TUN_ADDR="'$TAYGA_IPV4_ADDR'"/' $TAYGA_DEFAULT
-    sudo sed -i 's/^IPV6_TUN_ADDR=""/IPV6_TUN_ADDR="'$TAYGA_TUN_V6_ADDR'"/' $TAYGA_DEFAULT
-    sudo sed -i 's/^prefix /##prefix /' $TAYGA_CONF
-    sudo sed -i '/^##prefix /a prefix '$NAT64_PREFIX $TAYGA_CONF
-    sudo sed -i '/^#ipv6-addr/a ipv6-addr '$TAYGA_IPV6_ADDR $TAYGA_CONF
-    sudo sed -i 's/^dynamic-pool /##dynamic-pool /' $TAYGA_CONF
-    sudo sed -i '/^##dynamic-pool /a dynamic-pool '"$DYNAMIC_POOL" $TAYGA_CONF
-
-    if have systemctl; then
-        sudo systemctl restart tayga || die 'Unable to restart taga service!'
-        sudo systemctl enable tayga || die 'Unable to enable taga service!'
-    fi
-}
-
-tayga_uninstall()
-{
-    sudo sed -i 's/^RUN="yes"/RUN="no"/' $TAYGA_DEFAULT
-    sudo sed -i 's/^IPV4_TUN_ADDR="'$TAYGA_IPV4_ADDR'"/IPV4_TUN_ADDR=""/' $TAYGA_DEFAULT
-    sudo sed -i '/^prefix /d' $TAYGA_CONF
-    if grep "##prefix " $TAYGA_CONF; then
-        sudo sed -i 's/^##prefix /prefix /' $TAYGA_CONF
-    else
-        sudo sed -i 's/^# prefix /prefix /' $TAYGA_CONF
-    fi
-    sudo sed -i '/^ipv6-addr '$TAYGA_IPV6_ADDR'/d' $TAYGA_CONF
-    if grep "##dynamic-pool " $TAYGA_CONF; then
-        sudo sed -i '/^dynamic-pool /d' $TAYGA_CONF
-        sudo sed -i 's/^##dynamic-pool /dynamic-pool /' $TAYGA_CONF
-    fi
-}
-
-tayga_start()
-{
-    if with DOCKER; then
-        service tayga start || die 'Failed to start tayga'
-    elif have systemctl; then
-        sudo systemctl start tayga || die 'Failed to start tayga!'
-        sudo systemctl enable tayga || die 'Failed to enable tayga!'
-    fi
-}
-
-tayga_stop()
-{
-    if with DOCKER; then
-        service tayga stop || true
-    elif have systemctl; then
-        sudo systemctl stop tayga || true
-    fi
-}
-
 nat44_install()
 {
     sudo tee $NAT44_SERVICE <<EOF
@@ -150,21 +88,13 @@ nat44_install()
 case "\$1" in
     start)
 EOF
-    if [ "$NAT64_SERVICE" = tayga ]; then
-        # Although Tayga itself also configures a NAT44 iptables route, this iptables route is used with Tayga
-        # due to some history reason. It might be removed when native NAT64 service is ready.
-        for IFNAME in $WLAN_IFNAMES; do
-            echo "        iptables -t nat -A POSTROUTING -o $IFNAME -j MASQUERADE" | sudo tee -a $NAT44_SERVICE
-        done
-    else
-        # Just a random fwmark bits.
-        echo "        iptables -t mangle -A PREROUTING -i $THREAD_IF -j MARK --set-mark 0x1001" | sudo tee -a $NAT44_SERVICE
-        echo "        iptables -t nat -A POSTROUTING -m mark --mark 0x1001 -j MASQUERADE" | sudo tee -a $NAT44_SERVICE
-        for IFNAME in $WLAN_IFNAMES; do
-            echo "        iptables -t filter -A FORWARD -o $IFNAME -j ACCEPT" | sudo tee -a $NAT44_SERVICE
-            echo "        iptables -t filter -A FORWARD -i $IFNAME -j ACCEPT" | sudo tee -a $NAT44_SERVICE
-        done
-    fi
+    # Just a random fwmark bits.
+    echo "        iptables -t mangle -A PREROUTING -i $THREAD_IF -j MARK --set-mark 0x1001" | sudo tee -a $NAT44_SERVICE
+    echo "        iptables -t nat -A POSTROUTING -m mark --mark 0x1001 -j MASQUERADE" | sudo tee -a $NAT44_SERVICE
+    for IFNAME in $WLAN_IFNAMES; do
+        echo "        iptables -t filter -A FORWARD -o $IFNAME -j ACCEPT" | sudo tee -a $NAT44_SERVICE
+        echo "        iptables -t filter -A FORWARD -i $IFNAME -j ACCEPT" | sudo tee -a $NAT44_SERVICE
+    done
     sudo tee -a $NAT44_SERVICE <<EOF
         ;;
     restart|reload|force-reload)
@@ -222,10 +152,6 @@ nat64_install()
 {
     with NAT64 || return 0
 
-    if [ "$NAT64_SERVICE" = tayga ]; then
-        tayga_install
-    fi
-
     nat44_install
 }
 
@@ -234,11 +160,6 @@ nat64_uninstall()
     with NAT64 || return 0
 
     nat64_stop
-
-    if [ "$NAT64_SERVICE" = tayga ]; then
-        tayga_uninstall
-    fi
-
     nat44_uninstall
 }
 
@@ -246,10 +167,6 @@ nat64_start()
 {
     with NAT64 || return 0
 
-    if [ "$NAT64_SERVICE" = tayga ]; then
-        tayga_start
-    fi
-
     nat44_start
 }
 
@@ -257,9 +174,5 @@ nat64_stop()
 {
     with NAT64 || return 0
 
-    if [ "$NAT64_SERVICE" = tayga ]; then
-        tayga_stop
-    fi
-
     nat44_stop
 }
diff --git a/script/_network_manager b/script/_network_manager
deleted file mode 100644
index 1bbdc5b9..00000000
--- a/script/_network_manager
+++ /dev/null
@@ -1,422 +0,0 @@
-#!/bin/bash
-#
-#  Copyright (c) 2017, The OpenThread Authors.
-#  All rights reserved.
-#
-#  Redistribution and use in source and binary forms, with or without
-#  modification, are permitted provided that the following conditions are met:
-#  1. Redistributions of source code must retain the above copyright
-#     notice, this list of conditions and the following disclaimer.
-#  2. Redistributions in binary form must reproduce the above copyright
-#     notice, this list of conditions and the following disclaimer in the
-#     documentation and/or other materials provided with the distribution.
-#  3. Neither the name of the copyright holder nor the
-#     names of its contributors may be used to endorse or promote products
-#     derived from this software without specific prior written permission.
-#
-#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
-#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
-#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
-#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
-#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
-#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-#  POSSIBILITY OF SUCH DAMAGE.
-#
-
-AP_CONN="BorderRouter-AP"
-ETH_CONN="BorderRouter-Eth"
-
-AP_HELPER_SCRIPT="/etc/NetworkManager/dispatcher.d/ap-helper"
-DHCPV6_HELPER_SCRIPT="/etc/NetworkManager/dispatcher.d/dhcpv6-helper"
-
-create_ap_connection()
-{
-    IFNAME=$(nmcli d | grep wifi | cut -d" " -f1)
-
-    sudo nmcli c add type wifi ifname "${IFNAME}" con-name ${AP_CONN} ssid ${AP_CONN}
-    sudo nmcli c modify ${AP_CONN} 802-11-wireless.mode ap 802-11-wireless.band bg ipv4.method shared ipv6.method auto
-    sudo nmcli c modify ${AP_CONN} wifi-sec.key-mgmt wpa-psk
-    sudo nmcli c modify ${AP_CONN} wifi-sec.proto rsn
-    sudo nmcli c modify ${AP_CONN} wifi-sec.psk "12345678"
-}
-
-create_eth_connection()
-{
-    IFNAME=$(nmcli d | grep ethernet | cut -d" " -f1 | grep -v usb)
-
-    sudo nmcli c add type ethernet ifname "${IFNAME}" con-name ${ETH_CONN}
-    sudo nmcli c modify ${ETH_CONN} ipv6.method ignore
-}
-
-create_ap_helper_script()
-{
-    sudo tee ${AP_HELPER_SCRIPT} <<EOF
-#!/bin/sh
-#
-#  Copyright (c) 2017, The OpenThread Authors.
-#  All rights reserved.
-#
-#  Redistribution and use in source and binary forms, with or without
-#  modification, are permitted provided that the following conditions are met:
-#  1. Redistributions of source code must retain the above copyright
-#     notice, this list of conditions and the following disclaimer.
-#  2. Redistributions in binary form must reproduce the above copyright
-#     notice, this list of conditions and the following disclaimer in the
-#     documentation and/or other materials provided with the distribution.
-#  3. Neither the name of the copyright holder nor the
-#     names of its contributors may be used to endorse or promote products
-#     derived from this software without specific prior written permission.
-#
-#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
-#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
-#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
-#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
-#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
-#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-#  POSSIBILITY OF SUCH DAMAGE.
-#
-
-set -euxo pipefail
-
-NAME="ap-helper"
-
-IFNAME=\$1
-ACTION=\$2
-
-AP_CONN="${AP_CONN}"
-
-DHCP_START="10.42.0.2"
-DHCP_END="10.42.0.8"
-
-ROUTER_IP="10.42.0.1"
-
-DNS1=\${ROUTER_IP}
-DNS2="8.8.8.8"
-
-
-log()
-{
-    logger -t "\${NAME}[\${\$}]" \$*
-}
-
-disable_accept_ra()
-{
-    log "Disable accepting Router Advertisements on the interface: '\${IFNAME}'"
-    sysctl -w net.ipv6.conf.\${IFNAME}.accept_ra=1
-}
-
-start_dnsmasq()
-{
-    log "Starting 'dnsmasq' on the interface: '\${IFNAME}'"
-    /usr/sbin/dnsmasq -i \${IFNAME} -a \${ROUTER_IP} -b -z -K -F\${DHCP_START},\${DHCP_END},24h -p0 -O3,\${ROUTER_IP} -O6,\${DNS1},\${DNS2}
-}
-
-kill_dnsmasq()
-{
-    local DNSMASQ_PID=\`pidof dnsmasq\`
-
-    if [ -n \${DNSMASQ_PID} ]; then
-        log "Killing 'dnsmasq' process with PID: '\${DNSMASQ_PID}'"
-        kill -9 \${DNSMASQ_PID}
-    else
-        log "'dnsmasq' is not running"
-    fi
-}
-
-release_dhcpcd()
-{
-    log "Releasing 'dhcpcd' on the interface: '\${IFNAME}'"
-    /sbin/dhcpcd -6 -k \${IFNAME}
-}
-
-handle_action_up()
-{
-    case \${IFNAME} in
-    wlan*)
-        if [ \${CONNECTION_ID} = \${AP_CONN} ]; then
-            release_dhcpcd
-            disable_accept_ra
-            start_dnsmasq
-        fi
-        ;;
-    *)
-        ;;
-    esac
-}
-
-handle_action_down()
-{
-    case \${IFNAME} in
-    wlan*)
-        if [ \${CONNECTION_ID} = \${AP_CONN} ]; then
-            kill_dnsmasq
-        fi
-        ;;
-    *)
-        log "Skipping action: '\${ACTION}' on the interface: '\${IFNAME}'"
-        ;;
-    esac
-}
-
-
-case \${ACTION} in
-up)
-    handle_action_up
-    ;;
-down)
-    handle_action_down
-    ;;
-*)
-    log "Unsupported action: '\${ACTION}'"
-    ;;
-esac
-EOF
-}
-
-create_dhcpv6_helper_script()
-{
-    sudo tee ${DHCPV6_HELPER_SCRIPT} <<EOF
-#!/bin/sh
-#
-#  Copyright (c) 2017, The OpenThread Authors.
-#  All rights reserved.
-#
-#  Redistribution and use in source and binary forms, with or without
-#  modification, are permitted provided that the following conditions are met:
-#  1. Redistributions of source code must retain the above copyright
-#     notice, this list of conditions and the following disclaimer.
-#  2. Redistributions in binary form must reproduce the above copyright
-#     notice, this list of conditions and the following disclaimer in the
-#     documentation and/or other materials provided with the distribution.
-#  3. Neither the name of the copyright holder nor the
-#     names of its contributors may be used to endorse or promote products
-#     derived from this software without specific prior written permission.
-#
-#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
-#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
-#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
-#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
-#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
-#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-#  POSSIBILITY OF SUCH DAMAGE.
-#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-#  POSSIBILITY OF SUCH DAMAGE.
-#
-#   Description:
-#       This script manipulates DHCPv6-PD configuration.
-#
-
-set -euxo pipefail
-
-NAME="dhcpv6-helper"
-
-IFNAME=\$1
-ACTION=\$2
-
-AP_CONN="${AP_CONN}"
-
-DHCPCD_INTERFACES="/tmp/dhcpcd_interfaces"
-
-
-log()
-{
-    logger -t "\${NAME}[\${\$}]" \$*
-}
-
-enable_accept_ra()
-{
-    log "Enable accepting Router Advertisements on the interface: '\${IFNAME}'"
-    sysctl -w net.ipv6.conf.\${IFNAME}.accept_ra=2
-}
-
-kill_dnsmasq()
-{
-    local DNSMASQ_PID=\`pidof dnsmasq\`
-
-    log "Killing 'dnsmasq' process with PID: '\${DNSMASQ_PID}'"
-    kill -9 \${DNSMASQ_PID}
-}
-
-start_dhcpcd()
-{
-    log "Starting 'dhcpcd' on the interface: '\${IFNAME}'"
-    /sbin/dhcpcd -6 -b -K -E \${IFNAME}
-
-    # Add interface to active dhcpcd interfaces.
-    sed -i "/\${IFNAME}/d" \${DHCPCD_INTERFACES}
-    echo "\${IFNAME}" >> \${DHCPCD_INTERFACES}
-}
-
-release_dhcpcd()
-{
-    log "Releasing 'dhcpcd' on the interface: '\${IFNAME}'"
-    /sbin/dhcpcd -6 -k \${IFNAME}
-
-    # Remove interface from active dhcpcd interfaces.
-    sed -i "/\${IFNAME}/d" \${DHCPCD_INTERFACES}
-}
-
-handle_action_up()
-{
-    case \${IFNAME} in
-    enp*)
-        enable_accept_ra
-        start_dhcpcd
-        ;;
-    eth*)
-        enable_accept_ra
-        start_dhcpcd
-        ;;
-    wlan*)
-        if ! [ \${CONNECTION_ID} = \${AP_CONN} ]; then
-            enable_accept_ra
-            start_dhcpcd
-        fi
-        ;;
-    *)
-        ;;
-    esac
-
-}
-
-handle_action_down()
-{
-    case \${IFNAME} in
-    enp*)
-        release_dhcpcd
-        ;;
-    eth*)
-        release_dhcpcd
-        ;;
-    wlan*)
-        if ! [ \${CONNECTION_ID} = \${AP_CONN} ]; then
-            release_dhcpcd
-        fi
-        ;;
-    *)
-        log "Skipping action: '\${ACTION}' on the interface: '\${IFNAME}'"
-        ;;
-    esac
-}
-
-case \${ACTION} in
-up)
-    handle_action_up
-    ;;
-down)
-    handle_action_down
-    ;;
-*)
-    log "Unsupported action: '\${ACTION}'"
-    ;;
-esac
-EOF
-}
-
-network_manager_install()
-{
-    with NETWORK_MANAGER || return 0
-
-    if ! have systemctl; then
-        echo "This script requires systemctl!"
-        return 0
-    fi
-
-    if with DNS64; then
-        # bind9 provides DNS service
-        sudo sed -i 's/^#port=5353/port=0/g' /etc/dnsmasq.conf
-        sudo systemctl restart dnsmasq
-    fi
-
-    sudo systemctl daemon-reload
-
-    sudo systemctl stop wpa_supplicant || true
-    sudo systemctl disable wpa_supplicant || true
-
-    sudo systemctl stop dhcpcd || true
-    sudo systemctl disable dhcpcd || true
-
-    sudo systemctl daemon-reload
-
-    sudo systemctl start NetworkManager || die "Failed to start NetworkManager."
-    sudo systemctl enable NetworkManager || die "Failed to enable NetworkManager."
-
-    # Create AP connection only on raspbian platform.
-    if [ "$PLATFORM" = raspbian ] || with NETWORK_MANAGER_WIFI; then
-        create_ap_helper_script
-        sudo chmod a+x ${AP_HELPER_SCRIPT}
-
-        create_ap_connection
-    fi
-
-    create_dhcpv6_helper_script
-    sudo chmod a+x ${DHCPV6_HELPER_SCRIPT}
-
-    create_eth_connection
-
-    sudo systemctl daemon-reload
-    sudo systemctl restart NetworkManager
-
-    sleep 15
-
-    if [ "$PLATFORM" = raspbian ] || with NETWORK_MANAGER_WIFI; then
-        sudo nmcli c up ${AP_CONN}
-    fi
-
-    sudo nmcli c up ${ETH_CONN}
-}
-
-network_manager_uninstall()
-{
-    with NETWORK_MANAGER || return 0
-
-    if with DNS64; then
-        sudo systemctl stop dnsmasq
-        # revert changes to dnsmasq
-        sudo sed -i 's/^port=0/#port=5353/g' /etc/dnsmasq.conf
-    fi
-
-    if ! have systemctl; then
-        echo "This script requires systemctl!"
-        return 0
-    fi
-
-    if ! systemctl is-active NetworkManager; then
-        sudo systemctl daemon-reload
-        sudo systemctl start NetworkManager
-    fi
-
-    if [ "$PLATFORM" = raspbian ] || with NETWORK_MANAGER_WIFI; then
-        sudo nmcli c down ${AP_CONN} || true
-        sudo nmcli c delete ${AP_CONN} || true
-    fi
-
-    sudo nmcli c down ${ETH_CONN} || true
-    sudo nmcli c delete ${ETH_CONN} || true
-
-    sudo systemctl disable NetworkManager || die 'Failed to disable NetworkManager!'
-    sudo systemctl stop NetworkManager || die 'Failed to stop NetworkManager!'
-
-    sudo rm ${AP_HELPER_SCRIPT} || true
-    sudo rm ${DHCPV6_HELPER_SCRIPT} || true
-
-    sudo systemctl daemon-reload
-
-    sudo systemctl start dhcpcd || true
-    sudo systemctl enable dhcpcd || true
-
-    sudo systemctl start wpa_supplicant || true
-    sudo systemctl enable wpa_supplicant || true
-}
diff --git a/script/_otbr b/script/_otbr
index 52748cd7..ca7811d9 100644
--- a/script/_otbr
+++ b/script/_otbr
@@ -80,9 +80,9 @@ otbr_install()
         "${otbr_options[@]}"
     )
 
-    if with DNSSD_PLAT; then
+    if with OT_SRP_ADV_PROXY; then
         otbr_options+=(
-            "-DOTBR_DNSSD_PLAT=ON"
+            "-DOTBR_OT_SRP_ADV_PROXY=ON"
         )
     else
         otbr_options+=(
@@ -130,7 +130,7 @@ otbr_install()
         )
     fi
 
-    if with NAT64 && [[ ${NAT64_SERVICE-} == "openthread" ]]; then
+    if with NAT64; then
         otbr_options+=(
             "-DOTBR_NAT64=ON"
             "-DOT_POSIX_NAT64_CIDR=${NAT64_DYNAMIC_POOL:-192.168.255.0/24}"
diff --git a/script/bootstrap b/script/bootstrap
index 628e422e..d7cb63ad 100755
--- a/script/bootstrap
+++ b/script/bootstrap
@@ -33,8 +33,6 @@
 # shellcheck source=script/_initrc
 . "$(dirname "$0")"/_initrc
 
-NAT64_SERVICE="${NAT64_SERVICE:-openthread}"
-
 FIREWALL="${FIREWALL:-1}"
 
 OTBR_MDNS="${OTBR_MDNS:-mDNSResponder}"
@@ -70,40 +68,21 @@ install_packages_apt()
         sudo sed -i 's/^#objects-per-client-max=[0-9]\+/objects-per-client-max=30000/' /etc/avahi/avahi-daemon.conf
     fi
 
-    (MDNS_RESPONDER_SOURCE_NAME=mDNSResponder-1790.80.10 \
-        && MDNS_RESPONDER_PATCH_PATH=$(realpath "$(dirname "$0")"/../third_party/mDNSResponder) \
+    (MDNS_RESPONDER_SOURCE_NAME=mDNSResponder-2600.100.147 \
         && cd /tmp \
         && wget --no-check-certificate https://github.com/apple-oss-distributions/mDNSResponder/archive/refs/tags/$MDNS_RESPONDER_SOURCE_NAME.tar.gz \
         && mkdir -p $MDNS_RESPONDER_SOURCE_NAME \
         && tar xvf $MDNS_RESPONDER_SOURCE_NAME.tar.gz -C $MDNS_RESPONDER_SOURCE_NAME --strip-components=1 \
         && cd /tmp/"$MDNS_RESPONDER_SOURCE_NAME" \
-        && (
-            for patch in "$MDNS_RESPONDER_PATCH_PATH"/*.patch; do
-                patch -p1 <"$patch"
-            done
-        ) \
         && cd mDNSPosix \
         && make os=linux tls=no && sudo make install os=linux tls=no)
 
     # nat64
     without NAT64 || {
-        [ "$NAT64_SERVICE" != "tayga" ] || sudo apt-get install --no-install-recommends -y tayga
         sudo apt-get install --no-install-recommends -y iptables
     }
 
-    # dns64
-    without DNS64 || {
-        if [ "$PLATFORM" = "beagleboneblack" ]; then
-            # dnsmasq needs to be stopped before bind9 is installed
-            sudo systemctl disable dnsmasq
-            sudo systemctl stop dnsmasq
-        fi
-        sudo apt-get install --no-install-recommends -y bind9
-        # Resolvconf cannot be installed inside docker environment
-        if without DOCKER; then
-            sudo apt-get install --no-install-recommends -y resolvconf
-        fi
-    }
+    sudo apt-get install --no-install-recommends -y bind9
 
     # dhcpv6-pd
     without DHCPV6_PD_REF || {
@@ -119,9 +98,6 @@ EOF
         sudo apt-get install --no-install-recommends -y radvd
     }
 
-    # network-manager
-    without NETWORK_MANAGER || sudo apt-get install --no-install-recommends -y dnsmasq network-manager
-
     # dhcpcd5
     without DHCPV6_PD || sudo apt-get install --no-install-recommends -y dhcpcd5
 
@@ -129,7 +105,7 @@ EOF
     sudo apt-get install --no-install-recommends -y libjsoncpp-dev
 
     # reference device
-    without REFERENCE_DEVICE || sudo apt-get install --no-install-recommends -y radvd dnsutils avahi-utils iperf3
+    without REFERENCE_DEVICE || sudo apt-get install --no-install-recommends -y radvd dnsutils avahi-utils iperf3 ndisc6
 
     # backbone-router
     without BACKBONE_ROUTER || sudo apt-get install --no-install-recommends -y libnetfilter-queue1 libnetfilter-queue-dev
@@ -160,7 +136,6 @@ install_packages_rpm()
     with RELEASE || sudo $PM install -y cmake ninja-build
     sudo $PM install -y dbus-devel
     sudo $PM install -y avahi avahi-devel
-    [ "$NAT64_SERVICE" != "tayga" ] || sudo $PM install -y tayga
     sudo $PM install -y iptables
     sudo $PM install -y jsoncpp-devel
     sudo $PM install -y wget
diff --git a/script/cmake-build b/script/cmake-build
index 19679381..dac9a3ce 100755
--- a/script/cmake-build
+++ b/script/cmake-build
@@ -75,7 +75,7 @@ main()
     (
         cd "${builddir}" || die "Failed to enter ${builddir}"
 
-        cmake -GNinja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON "${OTBR_TOP_SRCDIR}" "$@"
+        cmake -GNinja -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_EXPORT_COMPILE_COMMANDS=ON "${OTBR_TOP_SRCDIR}" "$@"
 
         if [[ -n ${OTBR_TARGET[*]} ]]; then
             ninja "${OTBR_TARGET[@]}"
diff --git a/script/server b/script/server
index d4742337..d8d80b62 100755
--- a/script/server
+++ b/script/server
@@ -33,7 +33,6 @@
 # shellcheck source=script/_initrc
 . "$(dirname "$0")"/_initrc
 . script/_nat64
-. script/_dns64
 . script/_firewall
 
 OTBR_MDNS="${OTBR_MDNS:-mDNSResponder}"
@@ -46,7 +45,6 @@ startup()
     . "$BEFORE_HOOK"
     sudo sysctl --system
     nat64_start || die 'Failed to start NAT64!'
-    dns64_start || die 'Failed to start DNS64!'
     firewall_start || die 'Failed to start firewall'
 
     start_service rsyslog
@@ -70,7 +68,6 @@ startup()
 shutdown()
 {
     nat64_stop || echo 'Failed to stop NAT64!'
-    dns64_stop || echo 'Failed to stop DNS64!'
     firewall_stop || echo 'Failed to stop firewall'
 
     stop_service rsyslog
diff --git a/script/setup b/script/setup
index b8878fa5..2bf13c05 100755
--- a/script/setup
+++ b/script/setup
@@ -36,14 +36,11 @@
 . script/_otbr
 . script/_ipforward
 . script/_nat64
-. script/_dns64
 . script/_dhcpv6_pd
 . script/_dhcpv6_pd_ref
-. script/_network_manager
 . script/_rt_tables
 . script/_swapfile
 . script/_sudo_extend
-. script/_disable_services
 . script/_firewall
 
 main()
@@ -52,14 +49,11 @@ main()
     . "$BEFORE_HOOK"
     extend_sudo_timeout
     setup_swapfile
-    disable_services
     otbr_uninstall
     border_routing_uninstall
-    network_manager_uninstall
     dhcpv6_pd_uninstall
     dhcpv6_pd_ref_uninstall
     nat64_uninstall
-    dns64_uninstall
     rt_tables_uninstall
     ipforward_uninstall
     firewall_uninstall
@@ -68,8 +62,6 @@ main()
     ipforward_install
     rt_tables_install
     nat64_install
-    dns64_install
-    network_manager_install
     dhcpv6_pd_install
     dhcpv6_pd_ref_install
     border_routing_install
diff --git a/script/standalone_ipv6 b/script/standalone_ipv6
deleted file mode 100755
index 65266b1b..00000000
--- a/script/standalone_ipv6
+++ /dev/null
@@ -1,316 +0,0 @@
-#!/bin/bash
-#
-#  Copyright (c) 2017, The OpenThread Authors.
-#  All rights reserved.
-#
-#  Redistribution and use in source and binary forms, with or without
-#  modification, are permitted provided that the following conditions are met:
-#  1. Redistributions of source code must retain the above copyright
-#     notice, this list of conditions and the following disclaimer.
-#  2. Redistributions in binary form must reproduce the above copyright
-#     notice, this list of conditions and the following disclaimer in the
-#     documentation and/or other materials provided with the distribution.
-#  3. Neither the name of the copyright holder nor the
-#     names of its contributors may be used to endorse or promote products
-#     derived from this software without specific prior written permission.
-#
-#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
-#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
-#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
-#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
-#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
-#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-#  POSSIBILITY OF SUCH DAMAGE.
-#
-#----------------------------------------
-# Purpose:
-#  To understand the purpose of this script see: print_big_ugly_warning() below.
-#----------------------------------------
-#
-
-# remember the name of this script
-SCRIPT_NAME=$0
-
-CWD=$(pwd)
-DATE=$(date)
-
-# shellcheck source=script/_initrc
-. "$(dirname "$0")"/_initrc
-
-ETH0_IPV6_BASE_PREFIX=fd11:33
-
-debug_echo()
-{
-    if [ "${_DEBUG_IPV6}" == "true" ]; then
-        echo "${@}"
-    fi
-}
-
-determine_eth0_name()
-{
-    ETH0_NAME=''
-
-    #
-    # this gives us a sorted list of network interface names
-    for devname in $(
-        cd /sys/class/net || exit
-        ls
-    ); do
-        # We want the physical device
-        # Not things like "usb0" or "wpan0"
-        # And we assume the first one is what we want
-        debug_echo "Consider: ${devname}"
-        ignore=false
-        case ${devname} in
-            usb* | can* | wpan* | br* | wlan* | lo)
-                # by name we can ignore USB-gadget, CANbus, Thread, wireless and loopback
-                ignore=true
-                ;;
-            *)
-                ignore=false
-                ;;
-        esac
-
-        if $ignore; then
-            debug_echo "Ignore ${devname} by name"
-            continue
-        fi
-
-        debug_echo "Consider: ${devname}"
-        if [ ! -L /sys/class/net/"${devname}"/device ]; then
-            debug_echo "Not a DEVICE ${devname}"
-            continue
-        fi
-
-        type=$(cat /sys/class/net/"${devname}"/type)
-        # Type1 = ARPHRD_ETHER
-        if [ "$type" -ne 1 ]; then
-            debug_echo "Not ARPHRD_ETHER"
-            continue
-        fi
-        # We assume the first thing we find is our device
-        ETH0_NAME=${devname}
-        break
-    done
-
-    if [ -z "${ETH0_NAME}" ]; then
-        echo "Cannot determine ETH0 name...."
-        exit 1
-    fi
-    echo "Assuming: Primary ETHERNET name is $ETH0_NAME"
-}
-
-install_radvd()
-{
-    echo "Fetching RADVD..."
-    echo "apt-get install --no-install-recommends radvd"
-    sudo apt-get install --no-install-recommends radvd
-}
-
-choose_random_eth0_address()
-{
-    # steps below are
-    #   Using "od" see http://man7.org/linux/man-pages/man1/od.1.html
-    #      read from /dev/urandom
-    #
-    # We use /dev/urandom not /dev/random for these reasons:
-    # 1) This is for private (not public) test purposes
-    # 2) urandom might stall ... and not give us bytes
-    #
-    # We want data in 16bit hex, hence: --format=x2
-    # We want only 4 bytes, hence --read-bytes=4
-    #
-    # The output looks like:
-    #      0000000 1234 5678
-    #      0000008
-    #
-    # head gives us the first line
-    # cut gives us the items 2 and 3 on the line
-    # tr  converts the space into a ':'
-    #
-    RANDOM_32BIT_VALUE=$(od --read-bytes=4 --format=x2 /dev/urandom \
-        | head -1 \
-        | cut -d' ' -f2,3 \
-        | tr ' ' ':')
-
-    # thus, "RANDOM_32BIT_VALUE=1234:5678"
-
-    # We'll use this for the radvd config
-    ETH0_IPV6_PREFIX=${ETH0_IPV6_BASE_PREFIX}:${RANDOM_32BIT_VALUE}
-
-    # and this for the static network address
-    ETH0_IPV6_STATIC_ADDRESS=${ETH0_IPV6_PREFIX}::1
-}
-
-configure_radvd()
-{
-    # this creates a configuration file for radvd
-    CFG_FILE=/etc/radvd.conf
-    if [ -f $CFG_FILE ]; then
-        echo "radvd config file exists: $CFG_FILE"
-        echo "SKIPPING radvd configuration"
-    else
-        sudo tee -a /etc/radvd.conf <<__EOF__
-#
-# This RADVD configuration file was created
-# by the OpenThread configuration script $SCRIPT_NAME
-# Executed in the directory ${CWD} on ${DATE}
-#
-# The purpose is to configure IPV6 in an issolated and
-# standalone network configuration for the purpose of test only
-#
-# This is by no means a complete IPv6 configuration
-# it is sufficent to allow coap transactions
-# with thread devices on the thread mesh network
-# attched to this boarder router
-#
-interface ${ETH0_NAME} {
-    # We want to send router adverts
-    AdvSendAdvert on;
-
-    # This is not a proper IPv6 router
-    # it is only for openthread
-    AdvDefaultPreference low;
-
-    # We should advertize this prefix
-    prefix ${ETH0_IPV6_PREFIX}::/64 {
-         # we want this "on link"
-         AdvOnLink on;
-         # devices should self-assign addresses with this prefix
-         AdvAutonomous on;
-         AdvRouterAddr on;
-    };
-};
-__EOF__
-    fi
-}
-
-assign_eth0_static_ipv6()
-{
-
-    # this creates a static IPv6 address for Eth0
-    sudo tee -a /etc/network/interfaces <<__EOF__
-
-# This configuration was created by
-# the openthread ${SCRIPT_NAME}
-# executing in the directory ${CWD}
-# and executed on ${DATE}
-#
-# for the purposes of testing ipv6 addresses
-# in an issolated network configuration
-
-# ensure ETH0 is configured at boot
-auto ${ETH0_NAME}
-
-# Configure the IPv6 address static
-# Note: IPv4 is not effected by this
-iface ${ETH0_NAME} inet6 static
-    address ${ETH0_IPV6_STATIC_ADDRESS}
-    netmask 64
-__EOF__
-
-}
-
-# on BBB we do this.
-# other platforms might do something simular
-bbb_main()
-{
-    install_radvd
-    determine_eth0_name
-    choose_random_eth0_address
-    configure_radvd
-    assign_eth0_static_ipv6
-
-    echo "You should now reboot your Device"
-}
-
-print_big_ugly_warning()
-{
-    # Scare our victim.
-
-    cat <<_EOF_
-
-Please understand the purpose of this script.
-
-This script is not intended to be an complete and proper IPv6
-configuration script.
-
-This is only hack that turns on just enough IPv6 to perform simple
-CoAP requests on or across an issolated test network to the Thread
-network.
-
-The example issolated test network consists of these parts:
-
-1) A thread RF radio network.
-
-2) The OpenThread Border router attached to the Thread network
-
-3) The Openthread Border router would typically be connected
-   to a residential home network in some way (wifi, or wired)
-
-   In this case, it is connected to a router that is not
-   connected to an upstream provider - it is issolated.
-
-4) In order to test & develop applications other things on the
-   "home/test network" need to talk to the various Thread end nodes
-   via IPv6
-
-   Examples include:
-
-   * Laptop, or desktop machine
-   * Android/Apple Phone or Tablet
-   * other network devices
-
-To test/develop your applications a means for these other devices on
-your test network to talk to devices on the Thread Network must exist.
-
-The problem:
-
-
-   Most home network routers provide only IPv4 services. They most
-   typically assume the upstream ISP network provider will provide
-   IPv6 addresses and configuration. A test network is often issolated
-   and not connected to the large world wide web, it is completely an
-   island. The upstream ISP provider does not exist.
-
-   In the end something needs to provide a minimal IPv6 configuration.
-
-=========================================================
-The above is the purpose of this ipv6 standalone hack script
-
-Never consider this script a proper IPv6 configuration.
-=========================================================
-
-It is only a quick hack that enables enough IPv6 to work such that:
-
-1) Your local test laptop/cellphone has an IPv6 address and
-2) can perform CoAP transfers between a node on thread network
-
-Now that you have read and understood the above, execute this script
-again like this:
-
-      ${SCRIPT_NAME}   enable_ipv6_hack
-
-_EOF_
-
-}
-
-# ensure user/victim has read the ugly warning.
-if [ "${1}" != "enable_ipv6_hack" ]; then
-    print_big_ugly_warning
-    exit 1
-fi
-
-# platforms specifc
-case ${PLATFORM} in
-    "beagleboneblack")
-        bbb_main
-        ;;
-    *)
-        die "Unsupported/unknown platform ${PLATFORM}"
-        ;;
-esac
diff --git a/script/update b/script/update
index daa859a4..9e55a5a8 100755
--- a/script/update
+++ b/script/update
@@ -37,7 +37,6 @@
 . script/_otbr
 . script/_ipforward
 . script/_nat64
-. script/_dns64
 . script/_dhcpv6_pd
 
 main()
@@ -49,14 +48,12 @@ main()
     otbr_uninstall
     dhcpv6_pd_uninstall
     nat64_uninstall
-    dns64_uninstall
     ipforward_uninstall
     border_routing_uninstall
 
     border_routing_install
     ipforward_install
     nat64_install
-    dns64_install
     dhcpv6_pd_install
     otbr_update
     # shellcheck source=/dev/null
diff --git a/src/agent/application.cpp b/src/agent/application.cpp
index d0a699c1..878eefdd 100644
--- a/src/agent/application.cpp
+++ b/src/agent/application.cpp
@@ -58,7 +58,7 @@ Application::Application(Host::ThreadHost  &aHost,
                          const std::string &aRestListenAddress,
                          int                aRestListenPort)
     : mInterfaceName(aInterfaceName)
-    , mBackboneInterfaceName(aBackboneInterfaceName.c_str())
+    , mBackboneInterfaceName(aBackboneInterfaceName)
     , mHost(aHost)
 #if OTBR_ENABLE_MDNS
     , mPublisher(
@@ -67,14 +67,26 @@ Application::Application(Host::ThreadHost  &aHost,
 #if OTBR_ENABLE_DNSSD_PLAT
     , mDnssdPlatform(*mPublisher)
 #endif
-#if OTBR_ENABLE_DBUS_SERVER && OTBR_ENABLE_BORDER_AGENT
-    , mDBusAgent(MakeUnique<DBus::DBusAgent>(mHost, *mPublisher))
+#if OTBR_ENABLE_BORDER_AGENT
+    , mBorderAgent(*mPublisher)
+    , mBorderAgentUdpProxy(mHost)
+#endif
+#if OTBR_ENABLE_DBUS_SERVER
+    , mDBusAgent(MakeDBusDependentComponents())
 #endif
 {
     if (mHost.GetCoprocessorType() == OT_COPROCESSOR_RCP)
     {
         CreateRcpMode(aRestListenAddress, aRestListenPort);
     }
+    else if (mHost.GetCoprocessorType() == OT_COPROCESSOR_NCP)
+    {
+        CreateNcpMode();
+    }
+    else
+    {
+        DieNow("Unknown Co-processor type!");
+    }
 }
 
 void Application::Init(void)
@@ -94,6 +106,10 @@ void Application::Init(void)
         break;
     }
 
+#if OTBR_ENABLE_DBUS_SERVER
+    mDBusAgent.Init();
+#endif
+
     otbrLogInfo("Co-processor version: %s", mHost.GetCoprocessorVersion());
 }
 
@@ -197,9 +213,6 @@ void Application::HandleSignal(int aSignal)
 void Application::CreateRcpMode(const std::string &aRestListenAddress, int aRestListenPort)
 {
     otbr::Host::RcpHost &rcpHost = static_cast<otbr::Host::RcpHost &>(mHost);
-#if OTBR_ENABLE_BORDER_AGENT
-    mBorderAgent = MakeUnique<BorderAgent>(rcpHost, *mPublisher);
-#endif
 #if OTBR_ENABLE_BACKBONE_ROUTER
     mBackboneAgent = MakeUnique<BackboneRouter::BackboneAgent>(rcpHost, mInterfaceName, mBackboneInterfaceName);
 #endif
@@ -222,8 +235,9 @@ void Application::CreateRcpMode(const std::string &aRestListenAddress, int aRest
     mVendorServer = vendor::VendorServer::newInstance(*this);
 #endif
 
-    OT_UNUSED_VARIABLE(aRestListenAddress);
-    OT_UNUSED_VARIABLE(aRestListenPort);
+    OTBR_UNUSED_VARIABLE(rcpHost);
+    OTBR_UNUSED_VARIABLE(aRestListenAddress);
+    OTBR_UNUSED_VARIABLE(aRestListenPort);
 }
 
 void Application::InitRcpMode(void)
@@ -231,8 +245,8 @@ void Application::InitRcpMode(void)
     Host::RcpHost &rcpHost = static_cast<otbr::Host::RcpHost &>(mHost);
     OTBR_UNUSED_VARIABLE(rcpHost);
 
-#if OTBR_ENABLE_BORDER_AGENT
-    mMdnsStateSubject.AddObserver(*mBorderAgent);
+#if OTBR_ENABLE_BORDER_AGENT && OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
+    mMdnsStateSubject.AddObserver(mBorderAgent);
 #endif
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
     mMdnsStateSubject.AddObserver(*mAdvertisingProxy);
@@ -254,15 +268,16 @@ void Application::InitRcpMode(void)
 #if OTBR_ENABLE_MDNS
     mPublisher->Start();
 #endif
-#if OTBR_ENABLE_BORDER_AGENT
-    mBorderAgent->Init();
-// This is for delaying publishing the MeshCoP service until the correct
-// vendor name and OUI etc. are correctly set by BorderAgent::SetMeshCopServiceValues()
-#if OTBR_STOP_BORDER_AGENT_ON_INIT
-    mBorderAgent->SetEnabled(false);
-#else
-    mBorderAgent->SetEnabled(true);
-#endif
+#if OTBR_ENABLE_BORDER_AGENT && OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
+    mHost.SetBorderAgentMeshCoPServiceChangedCallback(
+        [this](bool aIsActive, uint16_t aPort, const uint8_t *aTxtData, uint16_t aLength) {
+            mBorderAgent.HandleBorderAgentMeshCoPServiceChanged(aIsActive, aPort,
+                                                                std::vector<uint8_t>(aTxtData, aTxtData + aLength));
+        });
+    mHost.AddEphemeralKeyStateChangedCallback([this](otBorderAgentEphemeralKeyState aEpskcState, uint16_t aPort) {
+        mBorderAgent.HandleEpskcStateChanged(aEpskcState, aPort);
+    });
+    SetBorderAgentOnInitState();
 #endif
 #if OTBR_ENABLE_BACKBONE_ROUTER
     mBackboneAgent->Init();
@@ -279,9 +294,6 @@ void Application::InitRcpMode(void)
 #if OTBR_ENABLE_REST_SERVER
     mRestWebServer->Init();
 #endif
-#if OTBR_ENABLE_DBUS_SERVER
-    mDBusAgent->Init(*mBorderAgent);
-#endif
 #if OTBR_ENABLE_VENDOR_SERVER
     mVendorServer->Init();
 #endif
@@ -302,8 +314,8 @@ void Application::DeinitRcpMode(void)
     mDiscoveryProxy->SetEnabled(false);
 #endif
 #if OTBR_ENABLE_BORDER_AGENT
-    mBorderAgent->SetEnabled(false);
-    mBorderAgent->Deinit();
+    mBorderAgent.SetEnabled(false);
+    mBorderAgent.Deinit();
 #endif
 #if OTBR_ENABLE_MDNS
     mMdnsStateSubject.Clear();
@@ -311,24 +323,112 @@ void Application::DeinitRcpMode(void)
 #endif
 }
 
+void Application::CreateNcpMode(void)
+{
+    otbr::Host::NcpHost &ncpHost = static_cast<otbr::Host::NcpHost &>(mHost);
+
+    mNetif   = MakeUnique<Netif>(mInterfaceName, ncpHost);
+    mInfraIf = MakeUnique<InfraIf>(ncpHost);
+#if OTBR_ENABLE_BACKBONE_ROUTER
+    mMulticastRoutingManager = MakeUnique<MulticastRoutingManager>(*mNetif, *mInfraIf, ncpHost);
+#endif
+}
+
 void Application::InitNcpMode(void)
 {
-#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
     otbr::Host::NcpHost &ncpHost = static_cast<otbr::Host::NcpHost &>(mHost);
+
+    SuccessOrDie(mNetif->Init(), "Failed to initialize the Netif!");
+    ncpHost.InitNetifCallbacks(*mNetif);
+
+    mInfraIf->Init();
+    if (!mBackboneInterfaceName.empty())
+    {
+        mInfraIf->SetInfraIf(mBackboneInterfaceName);
+    }
+    ncpHost.InitInfraIfCallbacks(*mInfraIf);
+
+#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
     ncpHost.SetMdnsPublisher(mPublisher.get());
     mMdnsStateSubject.AddObserver(ncpHost);
     mPublisher->Start();
 #endif
-#if OTBR_ENABLE_DBUS_SERVER
-    mDBusAgent->Init(*mBorderAgent);
+#if OTBR_ENABLE_BORDER_AGENT
+    mHost.SetBorderAgentMeshCoPServiceChangedCallback(
+        [this](bool aIsActive, uint16_t aPort, const uint8_t *aTxtData, uint16_t aLength) {
+            if (!aIsActive)
+            {
+                mBorderAgentUdpProxy.Stop();
+            }
+            else
+            {
+                mBorderAgentUdpProxy.Start(aPort);
+            }
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
+            mBorderAgent.HandleBorderAgentMeshCoPServiceChanged(aIsActive, mBorderAgentUdpProxy.GetHostPort(),
+                                                                std::vector<uint8_t>(aTxtData, aTxtData + aLength));
+#else
+            OTBR_UNUSED_VARIABLE(aTxtData);
+            OTBR_UNUSED_VARIABLE(aLength);
+#endif
+        });
+    mHost.SetUdpForwardToHostCallback(
+        [this](const uint8_t *aUdpPayload, uint16_t aLength, const otIp6Address &aPeerAddr, uint16_t aPeerPort) {
+            mBorderAgentUdpProxy.SendToPeer(aUdpPayload, aLength, aPeerAddr, aPeerPort);
+        });
+    SetBorderAgentOnInitState();
+#endif
+#if OTBR_ENABLE_BACKBONE_ROUTER
+    mHost.SetBackboneRouterStateChangedCallback(
+        [this](otBackboneRouterState aState) { mMulticastRoutingManager->HandleStateChange(aState); });
+    mHost.SetBackboneRouterMulticastListenerCallback(
+        [this](otBackboneRouterMulticastListenerEvent aEvent, const Ip6Address &aAddress) {
+            mMulticastRoutingManager->HandleBackboneMulticastListenerEvent(aEvent, aAddress);
+        });
+#if OTBR_ENABLE_BACKBONE_ROUTER_ON_INIT
+    mHost.SetBackboneRouterEnabled(true);
+#endif
 #endif
 }
 
 void Application::DeinitNcpMode(void)
 {
+#if OTBR_ENABLE_BORDER_AGENT
+    mBorderAgent.SetEnabled(false);
+    mBorderAgent.Deinit();
+    mBorderAgentUdpProxy.Stop();
+#endif
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
     mPublisher->Stop();
 #endif
+    mNetif->Deinit();
+    mInfraIf->Deinit();
 }
 
+#if OTBR_ENABLE_BORDER_AGENT
+void Application::SetBorderAgentOnInitState(void)
+{
+    // This is for delaying publishing the MeshCoP service until the correct
+    // vendor name and OUI etc. are correctly set by BorderAgent::SetMeshCopServiceValues()
+#if OTBR_STOP_BORDER_AGENT_ON_INIT
+    mBorderAgent.SetEnabled(false);
+#else
+    mBorderAgent.SetEnabled(true);
+#endif
+}
+#endif
+
+#if OTBR_ENABLE_DBUS_SERVER
+DBus::DependentComponents Application::MakeDBusDependentComponents(void)
+{
+    return DBus::DependentComponents
+    {
+        mHost, *mPublisher,
+#if OTBR_ENABLE_BORDER_AGENT
+            mBorderAgent
+#endif
+    };
+}
+#endif
+
 } // namespace otbr
diff --git a/src/agent/application.hpp b/src/agent/application.hpp
index 85aca7c3..d68fed94 100644
--- a/src/agent/application.hpp
+++ b/src/agent/application.hpp
@@ -64,6 +64,8 @@
 #if OTBR_ENABLE_DNSSD_PLAT
 #include "host/posix/dnssd.hpp"
 #endif
+#include "host/posix/multicast_routing_manager.hpp"
+#include "host/posix/netif.hpp"
 #include "utils/infra_link_selector.hpp"
 
 namespace otbr {
@@ -163,7 +165,7 @@ public:
      */
     BorderAgent &GetBorderAgent(void)
     {
-        return *mBorderAgent;
+        return mBorderAgent;
     }
 #endif
 
@@ -247,7 +249,7 @@ public:
      */
     DBus::DBusAgent &GetDBusAgent(void)
     {
-        return *mDBusAgent;
+        return mDBusAgent;
     }
 #endif
 
@@ -261,12 +263,23 @@ private:
     void InitRcpMode(void);
     void DeinitRcpMode(void);
 
+    void CreateNcpMode(void);
     void InitNcpMode(void);
     void DeinitNcpMode(void);
 
-    std::string       mInterfaceName;
-    const char       *mBackboneInterfaceName;
-    Host::ThreadHost &mHost;
+#if OTBR_ENABLE_BORDER_AGENT
+    void SetBorderAgentOnInitState(void);
+#endif
+#if OTBR_ENABLE_DBUS_SERVER
+    DBus::DependentComponents MakeDBusDependentComponents(void);
+#endif
+
+    const std::string        mInterfaceName;
+    const std::string        mBackboneInterfaceName;
+    Host::ThreadHost        &mHost;
+    std::unique_ptr<Netif>   mNetif;
+    std::unique_ptr<InfraIf> mInfraIf;
+
 #if OTBR_ENABLE_MDNS
     Mdns::StateSubject               mMdnsStateSubject;
     std::unique_ptr<Mdns::Publisher> mPublisher;
@@ -275,10 +288,12 @@ private:
     DnssdPlatform mDnssdPlatform;
 #endif
 #if OTBR_ENABLE_BORDER_AGENT
-    std::unique_ptr<BorderAgent> mBorderAgent;
+    BorderAgent mBorderAgent;
+    UdpProxy    mBorderAgentUdpProxy;
 #endif
 #if OTBR_ENABLE_BACKBONE_ROUTER
     std::unique_ptr<BackboneRouter::BackboneAgent> mBackboneAgent;
+    std::unique_ptr<MulticastRoutingManager>       mMulticastRoutingManager;
 #endif
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
     std::unique_ptr<AdvertisingProxy> mAdvertisingProxy;
@@ -296,7 +311,7 @@ private:
     std::unique_ptr<rest::RestWebServer> mRestWebServer;
 #endif
 #if OTBR_ENABLE_DBUS_SERVER
-    std::unique_ptr<DBus::DBusAgent> mDBusAgent;
+    DBus::DBusAgent mDBusAgent;
 #endif
 #if OTBR_ENABLE_VENDOR_SERVER
     std::shared_ptr<vendor::VendorServer> mVendorServer;
diff --git a/src/agent/main.cpp b/src/agent/main.cpp
index bb8a0150..65b388b2 100644
--- a/src/agent/main.cpp
+++ b/src/agent/main.cpp
@@ -189,7 +189,7 @@ static otbrLogLevel GetDefaultLogLevel(void)
     property_get("ro.build.type", value, "user");
     if (!strcmp(value, "user"))
     {
-        level = OTBR_LOG_WARNING;
+        level = OTBR_LOG_NOTICE;
     }
 #else
     otbrLogLevel level = OTBR_LOG_INFO;
diff --git a/src/android/android_rcp_host.cpp b/src/android/android_rcp_host.cpp
index 0460dc8a..91500ea9 100644
--- a/src/android/android_rcp_host.cpp
+++ b/src/android/android_rcp_host.cpp
@@ -293,34 +293,39 @@ binder_status_t AndroidRcpHost::Dump(int aFd, const char **aArgs, uint32_t aNumA
     OT_UNUSED_VARIABLE(aArgs);
     OT_UNUSED_VARIABLE(aNumArgs);
 
+    VerifyOrExit(GetOtInstance() != nullptr);
+
     otCliInit(GetOtInstance(), OutputCallback, &aFd);
 
+    // Dump device level information
     DumpCliCommand("state", aFd);
     DumpCliCommand("srp server state", aFd);
     DumpCliCommand("srp server service", aFd);
     DumpCliCommand("srp server host", aFd);
-    DumpCliCommand("dataset activetimestamp", aFd);
-    DumpCliCommand("dataset channel", aFd);
-    DumpCliCommand("dataset channelmask", aFd);
-    DumpCliCommand("dataset extpanid", aFd);
-    DumpCliCommand("dataset meshlocalprefix", aFd);
-    DumpCliCommand("dataset networkname", aFd);
-    DumpCliCommand("dataset panid", aFd);
-    DumpCliCommand("dataset securitypolicy", aFd);
-    DumpCliCommand("leaderdata", aFd);
     DumpCliCommand("eidcache", aFd);
     DumpCliCommand("counters mac", aFd);
     DumpCliCommand("counters mle", aFd);
     DumpCliCommand("counters ip", aFd);
-    DumpCliCommand("router table", aFd);
+    DumpCliCommand("counters br", aFd);
     DumpCliCommand("neighbor table", aFd);
     DumpCliCommand("ipaddr -v", aFd);
+    DumpCliCommand("br multiail", aFd);
+    DumpCliCommand("br prefixtable", aFd);
+    DumpCliCommand("br peers", aFd);
+
+    // Dump network level information
+    DumpCliCommand("leaderdata", aFd);
+    DumpCliCommand("dataset active -ns", aFd);
+    DumpCliCommand("router table", aFd);
     DumpCliCommand("netdata show", aFd);
 
+    // TODO: b/420365488 - Add mesh topology dump
+
     fsync(aFd);
 
     otSysCliInitUsingDaemon(GetOtInstance());
 
+exit:
     return STATUS_OK;
 }
 
@@ -415,20 +420,5 @@ exit:
     return;
 }
 
-extern "C" otError otPlatInfraIfDiscoverNat64Prefix(uint32_t aInfraIfIndex)
-{
-    OT_UNUSED_VARIABLE(aInfraIfIndex);
-
-    AndroidRcpHost *androidRcpHost = AndroidRcpHost::Get();
-    otError         error          = OT_ERROR_NONE;
-
-    VerifyOrExit(androidRcpHost != nullptr, error = OT_ERROR_INVALID_STATE);
-
-    androidRcpHost->NotifyNat64PrefixDiscoveryDone();
-
-exit:
-    return error;
-}
-
 } // namespace Android
 } // namespace otbr
diff --git a/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java b/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java
index 901f7053..e91c4ead 100644
--- a/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java
+++ b/src/android/java/com/android/server/thread/openthread/testing/FakeOtDaemon.java
@@ -89,6 +89,7 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
     @Nullable private IOtDaemonCallback mCallback;
     @Nullable private Long mCallbackListenerId;
     @Nullable private RemoteException mJoinException;
+    @Nullable private RemoteException mSetEnabledException;
     @Nullable private String mNat64Cidr;
     @Nullable private RemoteException mSetNat64CidrException;
     @Nullable private RemoteException mRunOtCtlCommandException;
@@ -245,7 +246,12 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
     }
 
     @Override
-    public void setThreadEnabled(boolean enabled, IOtStatusReceiver receiver) {
+    public void setThreadEnabled(boolean enabled, IOtStatusReceiver receiver)
+            throws RemoteException {
+        if (mSetEnabledException != null) {
+            throw mSetEnabledException;
+        }
+
         mHandler.post(
                 () -> {
                     mState.threadEnabled = enabled ? OT_STATE_ENABLED : OT_STATE_DISABLED;
@@ -385,6 +391,11 @@ public final class FakeOtDaemon extends IOtDaemon.Stub {
         mJoinException = exception;
     }
 
+    /** Sets the {@link RemoteException} which will be thrown from {@link #setThreadEnabled}. */
+    public void setSetEnabledException(RemoteException exception) {
+        mSetEnabledException = exception;
+    }
+
     @Override
     public void leave(boolean eraseDataset, IOtStatusReceiver receiver) throws RemoteException {
         throw new UnsupportedOperationException("FakeOtDaemon#leave is not implemented!");
diff --git a/src/android/otdaemon_fuzzer.cpp b/src/android/otdaemon_fuzzer.cpp
index bd647341..33a3164d 100644
--- a/src/android/otdaemon_fuzzer.cpp
+++ b/src/android/otdaemon_fuzzer.cpp
@@ -49,7 +49,7 @@ extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
                               true /* aDryRun */,
                               false /* aEnableAutoAttach*/};
     auto                   mdnsPublisher = static_cast<MdnsPublisher *>(Publisher::Create([](Publisher::State) {}));
-    otbr::BorderAgent      borderAgent{rcpHost, *mdnsPublisher};
+    otbr::BorderAgent      borderAgent{*mdnsPublisher};
     otbr::AdvertisingProxy advProxy{rcpHost, *mdnsPublisher};
 
     auto service = ndk::SharedRefBase::make<OtDaemonServer>(rcpHost, *mdnsPublisher, borderAgent, advProxy, []() {});
diff --git a/src/android/otdaemon_server.cpp b/src/android/otdaemon_server.cpp
index 84bbc229..0cecdae7 100644
--- a/src/android/otdaemon_server.cpp
+++ b/src/android/otdaemon_server.cpp
@@ -136,8 +136,11 @@ void OtDaemonServer::Init(void)
     otIcmp6SetEchoMode(GetOtInstance(), OT_ICMP6_ECHO_HANDLER_DISABLED);
     otIp6SetReceiveFilterEnabled(GetOtInstance(), true);
     otNat64SetReceiveIp4Callback(GetOtInstance(), &OtDaemonServer::ReceiveCallback, this);
-    mBorderAgent.AddEphemeralKeyChangedCallback([this]() { HandleEpskcStateChanged(); });
-    mBorderAgent.SetEphemeralKeyEnabled(true);
+    mHost.AddEphemeralKeyStateChangedCallback([this](otBorderAgentEphemeralKeyState aEpskcState, uint16_t aPort) {
+        HandleEpskcStateChanged(aEpskcState, aPort);
+    });
+
+    otBorderAgentEphemeralKeySetEnabled(GetOtInstance(), true);
     otSysUpstreamDnsServerSetResolvConfEnabled(false);
 
     mTaskRunner.Post(kTelemetryCheckInterval, [this]() { PushTelemetryIfConditionMatch(); });
@@ -388,14 +391,9 @@ exit:
     }
 }
 
-void OtDaemonServer::HandleEpskcStateChanged(void *aBinderServer)
-{
-    static_cast<OtDaemonServer *>(aBinderServer)->HandleEpskcStateChanged();
-}
-
-void OtDaemonServer::HandleEpskcStateChanged(void)
+void OtDaemonServer::HandleEpskcStateChanged(otBorderAgentEphemeralKeyState aEpskcState, uint16_t aPort)
 {
-    mState.ephemeralKeyState = GetEphemeralKeyState();
+    mState.ephemeralKeyState = GetEphemeralKeyState(aEpskcState);
     if (mState.ephemeralKeyState == OT_EPHEMERAL_KEY_DISABLED)
     {
         mState.ephemeralKeyLifetimeMillis = 0;
@@ -419,11 +417,11 @@ void OtDaemonServer::NotifyStateChanged(int64_t aListenerId)
     }
 }
 
-int OtDaemonServer::GetEphemeralKeyState(void)
+int OtDaemonServer::GetEphemeralKeyState(otBorderAgentEphemeralKeyState aEpskcState)
 {
     int ephemeralKeyState;
 
-    switch (otBorderAgentEphemeralKeyGetState(GetOtInstance()))
+    switch (aEpskcState)
     {
     case OT_BORDER_AGENT_STATE_STARTED:
         ephemeralKeyState = OT_EPHEMERAL_KEY_ENABLED;
@@ -599,7 +597,7 @@ void OtDaemonServer::initializeInternal(const bool
     {
         nonStandardTxts.emplace_back(txtAttr.name.c_str(), txtAttr.value.data(), txtAttr.value.size());
     }
-    error = mBorderAgent.SetMeshCopServiceValues(instanceName, aMeshcopTxts.modelName, aMeshcopTxts.vendorName,
+    error = mBorderAgent.SetMeshCoPServiceValues(instanceName, aMeshcopTxts.modelName, aMeshcopTxts.vendorName,
                                                  aMeshcopTxts.vendorOui, nonStandardTxts);
     if (error != OTBR_ERROR_NONE)
     {
@@ -750,7 +748,7 @@ exit:
     {
         if (error == OT_ERROR_NONE)
         {
-            mState.ephemeralKeyState          = GetEphemeralKeyState();
+            mState.ephemeralKeyState          = GetEphemeralKeyState(otBorderAgentEphemeralKeyGetState(GetOtInstance()));
             mState.ephemeralKeyPasscode       = passcode;
             mState.ephemeralKeyLifetimeMillis = aLifetimeMillis;
             mEphemeralKeyExpiryMillis         = std::chrono::duration_cast<std::chrono::milliseconds>(
diff --git a/src/android/otdaemon_server.hpp b/src/android/otdaemon_server.hpp
index 2195e2fa..8273f657 100644
--- a/src/android/otdaemon_server.hpp
+++ b/src/android/otdaemon_server.hpp
@@ -183,9 +183,8 @@ private:
     Ipv6AddressInfo     ConvertToAddressInfo(const otNetifMulticastAddress &aAddress);
     void        UpdateThreadEnabledState(const int aEnabled, const std::shared_ptr<IOtStatusReceiver> &aReceiver);
     void        EnableThread(const std::shared_ptr<IOtStatusReceiver> &aReceiver);
-    static void HandleEpskcStateChanged(void *aBinderServer);
-    void        HandleEpskcStateChanged(void);
-    int         GetEphemeralKeyState(void);
+    void        HandleEpskcStateChanged(otBorderAgentEphemeralKeyState aEpskcState, uint16_t aPort);
+    int         GetEphemeralKeyState(otBorderAgentEphemeralKeyState aEpskcState);
     void        NotifyStateChanged(int64_t aListenerId);
 
     static OtDaemonServer *sOtDaemonServer;
diff --git a/src/android/otdaemon_telemetry.cpp b/src/android/otdaemon_telemetry.cpp
index 99987116..ce96c9b3 100644
--- a/src/android/otdaemon_telemetry.cpp
+++ b/src/android/otdaemon_telemetry.cpp
@@ -28,6 +28,7 @@
 #include "android/otdaemon_telemetry.hpp"
 
 #include <openthread/border_agent.h>
+#include <openthread/border_routing.h>
 #include <openthread/nat64.h>
 #include <openthread/openthread-system.h>
 #include <openthread/thread.h>
@@ -756,6 +757,7 @@ otError RetrieveTelemetryAtom(otInstance                         *otInstance,
         RetrieveNat64State(otInstance, wpanBorderRouter);
         RetrieveBorderAgentInfo(otInstance, wpanBorderRouter->mutable_border_agent_info());
         RetrieveTrelInfo(otInstance, wpanBorderRouter->mutable_trel_info());
+        wpanBorderRouter->set_multi_ail_detected(otBorderRoutingIsMultiAilDetected(otInstance));
     }
 
     return error;
diff --git a/src/border_agent/border_agent.cpp b/src/border_agent/border_agent.cpp
index c778af03..e3088acb 100644
--- a/src/border_agent/border_agent.cpp
+++ b/src/border_agent/border_agent.cpp
@@ -35,6 +35,8 @@
 
 #include "border_agent/border_agent.hpp"
 
+#if OTBR_ENABLE_BORDER_AGENT
+
 #include <arpa/inet.h>
 #include <assert.h>
 #include <errno.h>
@@ -70,105 +72,28 @@
 #include "common/types.hpp"
 #include "utils/hex.hpp"
 
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
 #if !(OTBR_ENABLE_MDNS_AVAHI || OTBR_ENABLE_MDNS_MDNSSD || OTBR_ENABLE_MDNS_MOJO)
-#error "Border Agent feature requires at least one `OTBR_MDNS` implementation"
+#error "Border Agent meshcop service feature requires at least one `OTBR_MDNS` implementation"
+#endif
 #endif
 
 namespace otbr {
 
-static const char    kBorderAgentServiceType[]      = "_meshcop._udp";   ///< Border agent service type of mDNS
-static const char    kBorderAgentEpskcServiceType[] = "_meshcop-e._udp"; ///< Border agent ePSKc service
-static constexpr int kBorderAgentServiceDummyPort   = 49152;
-static constexpr int kEpskcRandomGenLen             = 8;
-
-/**
- * Locators
- */
-enum
-{
-    kAloc16Leader   = 0xfc00, ///< leader anycast locator.
-    kInvalidLocator = 0xffff, ///< invalid locator.
-};
-
-enum : uint8_t
-{
-    kConnectionModeDisabled = 0,
-    kConnectionModePskc     = 1,
-    kConnectionModePskd     = 2,
-    kConnectionModeVendor   = 3,
-    kConnectionModeX509     = 4,
-};
-
-enum : uint8_t
-{
-    kThreadIfStatusNotInitialized = 0,
-    kThreadIfStatusInitialized    = 1,
-    kThreadIfStatusActive         = 2,
-};
-
-enum : uint8_t
-{
-    kThreadRoleDisabledOrDetached = 0,
-    kThreadRoleChild              = 1,
-    kThreadRoleRouter             = 2,
-    kThreadRoleLeader             = 3,
-};
-
-enum : uint8_t
-{
-    kAvailabilityInfrequent = 0,
-    kAvailabilityHigh       = 1,
-};
-
-struct StateBitmap
-{
-    uint32_t mConnectionMode : 3;
-    uint32_t mThreadIfStatus : 2;
-    uint32_t mAvailability : 2;
-    uint32_t mBbrIsActive : 1;
-    uint32_t mBbrIsPrimary : 1;
-    uint32_t mThreadRole : 2;
-    uint32_t mEpskcSupported : 1;
-
-    StateBitmap(void)
-        : mConnectionMode(0)
-        , mThreadIfStatus(0)
-        , mAvailability(0)
-        , mBbrIsActive(0)
-        , mBbrIsPrimary(0)
-        , mThreadRole(kThreadRoleDisabledOrDetached)
-        , mEpskcSupported(0)
-    {
-    }
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
+static const char kBorderAgentServiceType[]      = "_meshcop._udp";   ///< Border agent service type of mDNS
+static const char kBorderAgentEpskcServiceType[] = "_meshcop-e._udp"; ///< Border agent ePSKc service
+#endif
 
-    uint32_t ToUint32(void) const
-    {
-        uint32_t bitmap = 0;
-
-        bitmap |= mConnectionMode << 0;
-        bitmap |= mThreadIfStatus << 3;
-        bitmap |= mAvailability << 5;
-        bitmap |= mBbrIsActive << 7;
-        bitmap |= mBbrIsPrimary << 8;
-        bitmap |= mThreadRole << 9;
-        bitmap |= mEpskcSupported << 11;
-        return bitmap;
-    }
-};
+static constexpr int kBorderAgentServiceDummyPort = 49152;
+static constexpr int kEpskcRandomGenLen           = 8;
 
-BorderAgent::BorderAgent(otbr::Host::RcpHost &aHost, Mdns::Publisher &aPublisher)
-    : mHost(aHost)
-    , mPublisher(aPublisher)
+BorderAgent::BorderAgent(Mdns::Publisher &aPublisher)
+    : mPublisher(aPublisher)
 {
     ClearState();
 }
 
-void BorderAgent::Init(void)
-{
-    otbrLogInfo("Ephemeral Key is: %s during initialization", (mIsEphemeralKeyEnabled ? "enabled" : "disabled"));
-    mHost.AddThreadStateChangedCallback([this](otChangedFlags aFlags) { HandleThreadStateChanged(aFlags); });
-}
-
 void BorderAgent::Deinit(void)
 {
     ClearState();
@@ -201,30 +126,29 @@ exit:
     return error;
 }
 
-otbrError BorderAgent::SetMeshCopServiceValues(const std::string              &aServiceInstanceName,
+otbrError BorderAgent::SetMeshCoPServiceValues(const std::string              &aServiceInstanceName,
                                                const std::string              &aProductName,
                                                const std::string              &aVendorName,
                                                const std::vector<uint8_t>     &aVendorOui,
                                                const Mdns::Publisher::TxtList &aNonStandardTxtEntries)
 {
-    otbrError error = OTBR_ERROR_NONE;
+    otbrError        error = OTBR_ERROR_NONE;
+    VendorTxtEntries vendorEntries;
 
     VerifyOrExit(aProductName.size() <= kMaxProductNameLength, error = OTBR_ERROR_INVALID_ARGS);
     VerifyOrExit(aVendorName.size() <= kMaxVendorNameLength, error = OTBR_ERROR_INVALID_ARGS);
     VerifyOrExit(aVendorOui.empty() || aVendorOui.size() == kVendorOuiLength, error = OTBR_ERROR_INVALID_ARGS);
+
     for (const auto &txtEntry : aNonStandardTxtEntries)
     {
         VerifyOrExit(!txtEntry.mKey.empty() && txtEntry.mKey.front() == 'v', error = OTBR_ERROR_INVALID_ARGS);
+        vendorEntries[txtEntry.mKey] = txtEntry.mValue;
     }
 
     mProductName = aProductName;
     mVendorName  = aVendorName;
     mVendorOui   = aVendorOui;
-    mMeshCopTxtUpdate.clear();
-    for (const auto &txtEntry : aNonStandardTxtEntries)
-    {
-        mMeshCopTxtUpdate[txtEntry.mKey] = txtEntry.mValue;
-    }
+    EncodeVendorTxtData(vendorEntries);
 
     mBaseServiceInstanceName = aServiceInstanceName;
 
@@ -248,102 +172,65 @@ exit:
     return;
 }
 
-void BorderAgent::SetEphemeralKeyEnabled(bool aIsEnabled)
-{
-    VerifyOrExit(GetEphemeralKeyEnabled() != aIsEnabled);
-    mIsEphemeralKeyEnabled = aIsEnabled;
-
-    if (!mIsEphemeralKeyEnabled)
-    {
-        // If the ePSKc feature is enabled, we call the stop function which
-        // will wait for the session to close if it is in active use before
-        // removing ephemeral key and unpublishing the service.
-        otBorderAgentEphemeralKeyStop(mHost.GetInstance());
-    }
-
-    UpdateMeshCopService();
-
-exit:
-    return;
-}
-
 void BorderAgent::ClearState(void)
 {
-    mIsEnabled             = false;
-    mIsEphemeralKeyEnabled = (otThreadGetVersion() >= OT_THREAD_VERSION_1_4);
-    mMeshCopTxtUpdate.clear();
+    VendorTxtEntries emptyTxtEntries;
+
+    mIsEnabled = false;
     mVendorOui.clear();
-    mVendorName              = OTBR_VENDOR_NAME;
-    mProductName             = OTBR_PRODUCT_NAME;
+    mVendorName  = OTBR_VENDOR_NAME;
+    mProductName = OTBR_PRODUCT_NAME;
+    EncodeVendorTxtData(emptyTxtEntries);
     mBaseServiceInstanceName = OTBR_MESHCOP_SERVICE_INSTANCE_NAME;
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
     mServiceInstanceName.clear();
-    mEphemeralKeyChangedCallbacks.clear();
+#endif
 }
 
 void BorderAgent::Start(void)
 {
     otbrLogInfo("Start Thread Border Agent");
 
-#if OTBR_ENABLE_DBUS_SERVER
-    mHost.GetThreadHelper()->SetUpdateMeshCopTxtHandler([this](std::map<std::string, std::vector<uint8_t>> aUpdate) {
-        HandleUpdateVendorMeshCoPTxtEntries(std::move(aUpdate));
-    });
-    mHost.RegisterResetHandler([this]() {
-        mHost.GetThreadHelper()->SetUpdateMeshCopTxtHandler(
-            [this](std::map<std::string, std::vector<uint8_t>> aUpdate) {
-                HandleUpdateVendorMeshCoPTxtEntries(std::move(aUpdate));
-            });
-    });
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
+    mServiceInstanceName = GetServiceInstanceName();
+    UpdateMeshCoPService();
 #endif
-
-    mServiceInstanceName = GetServiceInstanceNameWithExtAddr(mBaseServiceInstanceName);
-    UpdateMeshCopService();
-
-    otBorderAgentEphemeralKeySetCallback(mHost.GetInstance(), BorderAgent::HandleEpskcStateChanged, this);
 }
 
 void BorderAgent::Stop(void)
 {
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
     otbrLogInfo("Stop Thread Border Agent");
-    UnpublishMeshCopService();
+    UnpublishMeshCoPService();
+#endif
 }
 
-void BorderAgent::HandleEpskcStateChanged(void *aContext)
-{
-    static_cast<BorderAgent *>(aContext)->HandleEpskcStateChanged();
-}
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
 
-void BorderAgent::HandleEpskcStateChanged(void)
+void BorderAgent::HandleEpskcStateChanged(otBorderAgentEphemeralKeyState aEpskcState, uint16_t aPort)
 {
-    switch (otBorderAgentEphemeralKeyGetState(mHost.GetInstance()))
+    switch (aEpskcState)
     {
     case OT_BORDER_AGENT_STATE_STARTED:
     case OT_BORDER_AGENT_STATE_CONNECTED:
     case OT_BORDER_AGENT_STATE_ACCEPTED:
-        PublishEpskcService();
+        PublishEpskcService(aPort);
         break;
     case OT_BORDER_AGENT_STATE_DISABLED:
     case OT_BORDER_AGENT_STATE_STOPPED:
         UnpublishEpskcService();
         break;
     }
-
-    for (auto &ephemeralKeyCallback : mEphemeralKeyChangedCallbacks)
-    {
-        ephemeralKeyCallback();
-    }
 }
 
-void BorderAgent::PublishEpskcService()
+void BorderAgent::PublishEpskcService(uint16_t aPort)
 {
-    otInstance *instance = mHost.GetInstance();
-    int         port     = otBorderAgentEphemeralKeyGetUdpPort(instance);
-
     otbrLogInfo("Publish meshcop-e service %s.%s.local. port %d", mServiceInstanceName.c_str(),
-                kBorderAgentEpskcServiceType, port);
+                kBorderAgentEpskcServiceType, aPort);
 
     mPublisher.PublishService(/* aHostName */ "", mServiceInstanceName, kBorderAgentEpskcServiceType,
-                              Mdns::Publisher::SubTypeList{}, port, /* aTxtData */ {}, [this](otbrError aError) {
+                              Mdns::Publisher::SubTypeList{}, aPort, /* aTxtData */ {},
+                              [this, aPort](otbrError aError) {
                                   if (aError == OTBR_ERROR_ABORTED)
                                   {
                                       // OTBR_ERROR_ABORTED is thrown when an ongoing service registration is
@@ -366,7 +253,7 @@ void BorderAgent::PublishEpskcService()
                                       // Potential risk that instance name is not the same with meshcop service.
                                       UnpublishEpskcService();
                                       mServiceInstanceName = GetAlternativeServiceInstanceName();
-                                      PublishEpskcService();
+                                      PublishEpskcService(aPort);
                                   }
                               });
 }
@@ -381,11 +268,6 @@ void BorderAgent::UnpublishEpskcService()
     });
 }
 
-void BorderAgent::AddEphemeralKeyChangedCallback(EphemeralKeyChangedCallback aCallback)
-{
-    mEphemeralKeyChangedCallbacks.push_back(std::move(aCallback));
-}
-
 void BorderAgent::HandleMdnsState(Mdns::Publisher::State aState)
 {
     VerifyOrExit(IsEnabled());
@@ -393,7 +275,7 @@ void BorderAgent::HandleMdnsState(Mdns::Publisher::State aState)
     switch (aState)
     {
     case Mdns::Publisher::State::kReady:
-        UpdateMeshCopService();
+        UpdateMeshCoPService();
         break;
     default:
         otbrLogWarning("mDNS publisher not available!");
@@ -403,226 +285,116 @@ exit:
     return;
 }
 
-static uint64_t ConvertTimestampToUint64(const otTimestamp &aTimestamp)
-{
-    // 64 bits Timestamp fields layout
-    //-----48 bits------//-----15 bits-----//-------1 bit-------//
-    //     Seconds      //      Ticks      //  Authoritative    //
-    return (aTimestamp.mSeconds << 16) | static_cast<uint64_t>(aTimestamp.mTicks << 1) |
-           static_cast<uint64_t>(aTimestamp.mAuthoritative);
-}
-
-#if OTBR_ENABLE_BORDER_ROUTING
-void AppendOmrTxtEntry(otInstance &aInstance, Mdns::Publisher::TxtList &aTxtList)
+void BorderAgent::HandleBorderAgentMeshCoPServiceChanged(bool                        aIsActive,
+                                                         uint16_t                    aPort,
+                                                         const std::vector<uint8_t> &aOtTxtData)
 {
-    otIp6Prefix       omrPrefix;
-    otRoutePreference preference;
-
-    if (OT_ERROR_NONE == otBorderRoutingGetFavoredOmrPrefix(&aInstance, &omrPrefix, &preference))
+    if (aIsActive != mBaIsActive || aPort != mMeshCoPUdpPort)
     {
-        std::vector<uint8_t> omrData;
-
-        omrData.reserve(1 + OT_IP6_PREFIX_SIZE);
-        omrData.push_back(omrPrefix.mLength);
-        std::copy(omrPrefix.mPrefix.mFields.m8, omrPrefix.mPrefix.mFields.m8 + (omrPrefix.mLength + 7) / 8,
-                  std::back_inserter(omrData));
-        aTxtList.emplace_back("omr", omrData.data(), omrData.size());
+        mBaIsActive     = aIsActive;
+        mMeshCoPUdpPort = aPort;
     }
-}
-#endif
-
-StateBitmap GetStateBitmap(otInstance &aInstance)
-{
-    StateBitmap state;
 
-    state.mConnectionMode = kConnectionModePskc;
-    state.mAvailability   = kAvailabilityHigh;
+    mOtTxtData.assign(aOtTxtData.begin(), aOtTxtData.end());
 
-    switch (otThreadGetDeviceRole(&aInstance))
+    // Parse extended address from the encoded data for the first time
+    if (!mIsInitialized)
     {
-    case OT_DEVICE_ROLE_DISABLED:
-        state.mThreadIfStatus = kThreadIfStatusNotInitialized;
-        state.mThreadRole     = kThreadRoleDisabledOrDetached;
-        break;
-    case OT_DEVICE_ROLE_DETACHED:
-        state.mThreadIfStatus = kThreadIfStatusInitialized;
-        state.mThreadRole     = kThreadRoleDisabledOrDetached;
-        break;
-    case OT_DEVICE_ROLE_CHILD:
-        state.mThreadIfStatus = kThreadIfStatusActive;
-        state.mThreadRole     = kThreadRoleChild;
-        break;
-    case OT_DEVICE_ROLE_ROUTER:
-        state.mThreadIfStatus = kThreadIfStatusActive;
-        state.mThreadRole     = kThreadRoleRouter;
-        break;
-    case OT_DEVICE_ROLE_LEADER:
-        state.mThreadIfStatus = kThreadIfStatusActive;
-        state.mThreadRole     = kThreadRoleLeader;
-        break;
-    }
-
-#if OTBR_ENABLE_BACKBONE_ROUTER
-    state.mBbrIsActive = state.mThreadIfStatus == kThreadIfStatusActive &&
-                         otBackboneRouterGetState(&aInstance) != OT_BACKBONE_ROUTER_STATE_DISABLED;
-    state.mBbrIsPrimary = state.mThreadIfStatus == kThreadIfStatusActive &&
-                          otBackboneRouterGetState(&aInstance) == OT_BACKBONE_ROUTER_STATE_PRIMARY;
-#endif
+        Mdns::Publisher::TxtList txtList;
+        otbrError                error = Mdns::Publisher::DecodeTxtData(txtList, mOtTxtData.data(), mOtTxtData.size());
 
-    return state;
-}
+        otbrLogResult(error, "Result of decoding MeshCoP TXT data from OT");
+        SuccessOrExit(error);
 
-#if OTBR_ENABLE_BACKBONE_ROUTER
-void AppendBbrTxtEntries(otInstance &aInstance, StateBitmap aState, Mdns::Publisher::TxtList &aTxtList)
-{
-    if (aState.mBbrIsActive)
-    {
-        otBackboneRouterConfig bbrConfig;
-        uint16_t               bbrPort = htobe16(BackboneRouter::BackboneAgent::kBackboneUdpPort);
+        for (auto &entry : txtList)
+        {
+            if (entry.mKey == "xa")
+            {
+                memcpy(mExtAddress.m8, entry.mValue.data(), sizeof(mExtAddress.m8));
 
-        otBackboneRouterGetConfig(&aInstance, &bbrConfig);
-        aTxtList.emplace_back("sq", &bbrConfig.mSequenceNumber, sizeof(bbrConfig.mSequenceNumber));
-        aTxtList.emplace_back("bb", reinterpret_cast<const uint8_t *>(&bbrPort), sizeof(bbrPort));
+                mServiceInstanceName = GetServiceInstanceName();
+                mIsInitialized       = true;
+                break;
+            }
+        }
     }
 
-    aTxtList.emplace_back("dn", otThreadGetDomainName(&aInstance));
+exit:
+    UpdateMeshCoPService();
 }
-#endif
 
-void AppendActiveTimestampTxtEntry(otInstance &aInstance, Mdns::Publisher::TxtList &aTxtList)
+#endif // OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
+
+void BorderAgent::EncodeVendorTxtData(const VendorTxtEntries &aVendorEntries)
 {
-    otError              error;
-    otOperationalDataset activeDataset;
+    Mdns::Publisher::TxtList txtList{{"rv", "1"}};
 
-    if ((error = otDatasetGetActive(&aInstance, &activeDataset)) != OT_ERROR_NONE)
+    if (!mVendorOui.empty())
     {
-        otbrLogWarning("Failed to get active dataset: %s", otThreadErrorToString(error));
+        txtList.emplace_back("vo", mVendorOui.data(), mVendorOui.size());
     }
-    else
+
+    if (!mVendorName.empty())
     {
-        uint64_t activeTimestampValue = ConvertTimestampToUint64(activeDataset.mActiveTimestamp);
+        txtList.emplace_back("vn", mVendorName.c_str());
+    }
 
-        activeTimestampValue = htobe64(activeTimestampValue);
-        aTxtList.emplace_back("at", reinterpret_cast<uint8_t *>(&activeTimestampValue), sizeof(activeTimestampValue));
+    if (!mProductName.empty())
+    {
+        txtList.emplace_back("mn", mProductName.c_str());
     }
-}
 
-void AppendVendorTxtEntries(const std::map<std::string, std::vector<uint8_t>> &aVendorEntries,
-                            Mdns::Publisher::TxtList                          &aTxtList)
-{
-    for (const auto &entry : aVendorEntries)
+    for (const auto &vendorEntry : aVendorEntries)
     {
-        const std::string          &key   = entry.first;
-        const std::vector<uint8_t> &value = entry.second;
+        const std::string          &key   = vendorEntry.first;
+        const std::vector<uint8_t> &value = vendorEntry.second;
         bool                        found = false;
 
-        for (auto &addedEntry : aTxtList)
+        for (Mdns::Publisher::TxtEntry &txtEntry : txtList)
         {
-            if (addedEntry.mKey == key)
+            if (txtEntry.mKey == key)
             {
-                addedEntry.mValue              = value;
-                addedEntry.mIsBooleanAttribute = false;
-                found                          = true;
+                txtEntry.mValue              = value;
+                txtEntry.mIsBooleanAttribute = false;
+                found                        = true;
                 break;
             }
         }
+
         if (!found)
         {
-            aTxtList.emplace_back(key.c_str(), value.data(), value.size());
+            txtList.emplace_back(key.c_str(), value.data(), value.size());
         }
     }
-}
-
-void BorderAgent::PublishMeshCopService(void)
-{
-    StateBitmap              state;
-    uint32_t                 stateUint32;
-    otInstance              *instance    = mHost.GetInstance();
-    const otExtendedPanId   *extPanId    = otThreadGetExtendedPanId(instance);
-    const otExtAddress      *extAddr     = otLinkGetExtendedAddress(instance);
-    const char              *networkName = otThreadGetNetworkName(instance);
-    Mdns::Publisher::TxtList txtList{{"rv", "1"}};
-    Mdns::Publisher::TxtData txtData;
-    int                      port;
-    otbrError                error;
-
-    OTBR_UNUSED_VARIABLE(error);
 
-    otbrLogInfo("Publish meshcop service %s.%s.local.", mServiceInstanceName.c_str(), kBorderAgentServiceType);
+    mVendorTxtData.clear();
 
-#if OTBR_ENABLE_PUBLISH_MESHCOP_BA_ID
+    if (!txtList.empty())
     {
-        otError         error;
-        otBorderAgentId id;
-
-        error = otBorderAgentGetId(instance, &id);
-        if (error == OT_ERROR_NONE)
-        {
-            txtList.emplace_back("id", id.mId, sizeof(id));
-        }
-        else
-        {
-            otbrLogWarning("Failed to retrieve Border Agent ID: %s", otThreadErrorToString(error));
-        }
-    }
-#endif
+        otbrError error = Mdns::Publisher::EncodeTxtData(txtList, mVendorTxtData);
 
-    if (!mVendorOui.empty())
-    {
-        txtList.emplace_back("vo", mVendorOui.data(), mVendorOui.size());
-    }
-    if (!mVendorName.empty())
-    {
-        txtList.emplace_back("vn", mVendorName.c_str());
+        assert(error == OTBR_ERROR_NONE);
+        OTBR_UNUSED_VARIABLE(error);
     }
-    if (!mProductName.empty())
-    {
-        txtList.emplace_back("mn", mProductName.c_str());
-    }
-    txtList.emplace_back("nn", networkName);
-    txtList.emplace_back("xp", extPanId->m8, sizeof(extPanId->m8));
-    txtList.emplace_back("tv", mHost.GetThreadVersion());
-
-    // "xa" stands for Extended MAC Address (64-bit) of the Thread Interface of the Border Agent.
-    txtList.emplace_back("xa", extAddr->m8, sizeof(extAddr->m8));
-    state                 = GetStateBitmap(*instance);
-    state.mEpskcSupported = GetEphemeralKeyEnabled();
-    stateUint32           = htobe32(state.ToUint32());
-    txtList.emplace_back("sb", reinterpret_cast<uint8_t *>(&stateUint32), sizeof(stateUint32));
-
-    if (state.mThreadIfStatus == kThreadIfStatusActive)
-    {
-        uint32_t partitionId;
+}
 
-        AppendActiveTimestampTxtEntry(*instance, txtList);
-        partitionId = otThreadGetPartitionId(instance);
-        txtList.emplace_back("pt", reinterpret_cast<uint8_t *>(&partitionId), sizeof(partitionId));
-    }
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
 
-#if OTBR_ENABLE_BACKBONE_ROUTER
-    AppendBbrTxtEntries(*instance, state, txtList);
-#endif
-#if OTBR_ENABLE_BORDER_ROUTING
-    AppendOmrTxtEntry(*instance, txtList);
-#endif
+void BorderAgent::PublishMeshCoPService(void)
+{
+    Mdns::Publisher::TxtData txtData;
+    int                      port;
 
-    AppendVendorTxtEntries(mMeshCopTxtUpdate, txtList);
+    otbrLogInfo("Publish meshcop service %s.%s.local.", mServiceInstanceName.c_str(), kBorderAgentServiceType);
 
-    if (otBorderAgentIsActive(instance))
-    {
-        port = otBorderAgentGetUdpPort(instance);
-    }
-    else
-    {
-        // When thread interface is not active, the border agent is not started, thus it's not listening to any port and
-        // not handling requests. In such situation, we use a dummy port number for publishing the MeshCoP service to
-        // advertise the status of the border router. One can learn the thread interface status from `sb` entry so it
-        // doesn't have to send requests to the dummy port when border agent is not running.
-        port = kBorderAgentServiceDummyPort;
-    }
+    // When thread interface is not active, the border agent is not started, thus it's not listening to any port and
+    // not handling requests. In such situation, we use a dummy port number for publishing the MeshCoP service to
+    // advertise the status of the border router. One can learn the thread interface status from `sb` entry so it
+    // doesn't have to send requests to the dummy port when border agent is not running.
+    port = mBaIsActive ? mMeshCoPUdpPort : kBorderAgentServiceDummyPort;
 
-    error = Mdns::Publisher::EncodeTxtData(txtList, txtData);
-    assert(error == OTBR_ERROR_NONE);
+    txtData.insert(txtData.end(), mVendorTxtData.begin(), mVendorTxtData.end());
+    txtData.insert(txtData.end(), mOtTxtData.begin(), mOtTxtData.end());
 
     mPublisher.PublishService(/* aHostName */ "", mServiceInstanceName, kBorderAgentServiceType,
                               Mdns::Publisher::SubTypeList{}, port, txtData, [this](otbrError aError) {
@@ -644,14 +416,14 @@ void BorderAgent::PublishMeshCopService(void)
                                       // Try to unpublish current service in case we are trying to register
                                       // multiple new services simultaneously when the original service name
                                       // is conflicted.
-                                      UnpublishMeshCopService();
+                                      UnpublishMeshCoPService();
                                       mServiceInstanceName = GetAlternativeServiceInstanceName();
-                                      PublishMeshCopService();
+                                      PublishMeshCoPService();
                                   }
                               });
 }
 
-void BorderAgent::UnpublishMeshCopService(void)
+void BorderAgent::UnpublishMeshCoPService(void)
 {
     otbrLogInfo("Unpublish meshcop service %s.%s.local", mServiceInstanceName.c_str(), kBorderAgentServiceType);
 
@@ -661,63 +433,43 @@ void BorderAgent::UnpublishMeshCopService(void)
     });
 }
 
-void BorderAgent::UpdateMeshCopService(void)
+void BorderAgent::UpdateMeshCoPService(void)
 {
+    VerifyOrExit(mIsInitialized);
     VerifyOrExit(IsEnabled());
     VerifyOrExit(mPublisher.IsStarted());
-    PublishMeshCopService();
+    PublishMeshCoPService();
 
 exit:
     return;
 }
 
-#if OTBR_ENABLE_DBUS_SERVER
-void BorderAgent::HandleUpdateVendorMeshCoPTxtEntries(std::map<std::string, std::vector<uint8_t>> aUpdate)
-{
-    mMeshCopTxtUpdate = std::move(aUpdate);
-    UpdateMeshCopService();
-}
 #endif
 
-void BorderAgent::HandleThreadStateChanged(otChangedFlags aFlags)
+#if OTBR_ENABLE_DBUS_SERVER
+void BorderAgent::UpdateVendorMeshCoPTxtEntries(const VendorTxtEntries &aVendorEntries)
 {
-    VerifyOrExit(IsEnabled());
-
-    if (aFlags & OT_CHANGED_THREAD_ROLE)
-    {
-        otbrLogInfo("Thread is %s", (IsThreadStarted() ? "up" : "down"));
-    }
-
-    if (aFlags & (OT_CHANGED_THREAD_ROLE | OT_CHANGED_THREAD_EXT_PANID | OT_CHANGED_THREAD_NETWORK_NAME |
-                  OT_CHANGED_THREAD_BACKBONE_ROUTER_STATE | OT_CHANGED_THREAD_NETDATA))
-    {
-        UpdateMeshCopService();
-    }
-
-exit:
-    return;
+    EncodeVendorTxtData(aVendorEntries);
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
+    UpdateMeshCoPService();
+#endif
 }
+#endif
 
-bool BorderAgent::IsThreadStarted(void) const
-{
-    otDeviceRole role = mHost.GetDeviceRole();
-
-    return role == OT_DEVICE_ROLE_CHILD || role == OT_DEVICE_ROLE_ROUTER || role == OT_DEVICE_ROLE_LEADER;
-}
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
 
-std::string BorderAgent::GetServiceInstanceNameWithExtAddr(const std::string &aServiceInstanceName) const
+std::string BorderAgent::GetServiceInstanceName(void) const
 {
-    const otExtAddress *extAddress = otLinkGetExtendedAddress(mHost.GetInstance());
-    std::stringstream   ss;
+    std::stringstream ss;
 
-    ss << aServiceInstanceName << " #";
+    ss << mBaseServiceInstanceName << " #";
     ss << std::uppercase << std::hex << std::setfill('0');
-    ss << std::setw(2) << static_cast<int>(extAddress->m8[6]);
-    ss << std::setw(2) << static_cast<int>(extAddress->m8[7]);
+    ss << std::setw(2) << static_cast<int>(mExtAddress.m8[6]);
+    ss << std::setw(2) << static_cast<int>(mExtAddress.m8[7]);
     return ss.str();
 }
 
-std::string BorderAgent::GetAlternativeServiceInstanceName() const
+std::string BorderAgent::GetAlternativeServiceInstanceName(void) const
 {
     std::random_device                      r;
     std::default_random_engine              engine(r());
@@ -725,8 +477,12 @@ std::string BorderAgent::GetAlternativeServiceInstanceName() const
     uint16_t                                rand = uniform_dist(engine);
     std::stringstream                       ss;
 
-    ss << GetServiceInstanceNameWithExtAddr(mBaseServiceInstanceName) << " (" << rand << ")";
+    ss << GetServiceInstanceName() << " (" << rand << ")";
     return ss.str();
 }
 
+#endif // OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
+
 } // namespace otbr
+
+#endif // OTBR_ENABLE_BORDER_AGENT
diff --git a/src/border_agent/border_agent.hpp b/src/border_agent/border_agent.hpp
index fddeb79c..190a33c6 100644
--- a/src/border_agent/border_agent.hpp
+++ b/src/border_agent/border_agent.hpp
@@ -36,6 +36,8 @@
 
 #include "openthread-br/config.h"
 
+#if OTBR_ENABLE_BORDER_AGENT
+
 #include <vector>
 
 #include <stdint.h>
@@ -75,27 +77,27 @@ namespace otbr {
 /**
  * This class implements Thread border agent functionality.
  */
-class BorderAgent : public Mdns::StateObserver, private NonCopyable
+class BorderAgent : private NonCopyable
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
+    ,
+                    public Mdns::StateObserver
+#endif
 {
 public:
+    typedef std::map<std::string, std::vector<uint8_t>> VendorTxtEntries; ///< Vendor TXT entry map.
+
     /** The callback for receiving ephemeral key changes. */
     using EphemeralKeyChangedCallback = std::function<void(void)>;
 
     /**
      * The constructor to initialize the Thread border agent.
      *
-     * @param[in] aHost       A reference to the Thread controller.
      * @param[in] aPublisher  A reference to the mDNS Publisher.
      */
-    BorderAgent(otbr::Host::RcpHost &aHost, Mdns::Publisher &aPublisher);
+    BorderAgent(Mdns::Publisher &aPublisher);
 
     ~BorderAgent(void) = default;
 
-    /**
-     * Initializes the Thread Border Agent.
-     */
-    void Init(void);
-
     /**
      * Deinitializes the Thread Border Agent.
      */
@@ -119,7 +121,7 @@ public:
      *                                   allowed ranges or invalid keys are found in aNonStandardTxtEntries
      * @returns OTBR_ERROR_NONE          If successfully set the meshcop service values.
      */
-    otbrError SetMeshCopServiceValues(const std::string              &aServiceInstanceName,
+    otbrError SetMeshCoPServiceValues(const std::string              &aServiceInstanceName,
                                       const std::string              &aProductName,
                                       const std::string              &aVendorName,
                                       const std::vector<uint8_t>     &aVendorOui             = {},
@@ -132,24 +134,33 @@ public:
      */
     void SetEnabled(bool aIsEnabled);
 
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
+
     /**
-     * This method enables/disables the Border Agent Ephemeral Key feature.
+     * This method handles mDNS publisher's state changes.
      *
-     * @param[in] aIsEnabled  Whether to enable the BA Ephemeral Key feature.
+     * @param[in] aState  The state of mDNS publisher.
      */
-    void SetEphemeralKeyEnabled(bool aIsEnabled);
+    void HandleMdnsState(Mdns::Publisher::State aState) override;
 
     /**
-     * This method returns the Border Agent Ephemeral Key feature state.
+     * This method handles Border Agent state changes.
+     *
+     * @param[in] aIsActive     If the Border Agent is active.
+     * @param[in] aPort         The UDP port of the Border Agent service.
+     * @param[in] aOtTxtData    The MeshCoP TXT data generated by OT.
      */
-    bool GetEphemeralKeyEnabled(void) const { return mIsEphemeralKeyEnabled; }
+    void HandleBorderAgentMeshCoPServiceChanged(bool aIsActive, uint16_t aPort, const std::vector<uint8_t> &aOtTxtData);
 
     /**
-     * This method handles mDNS publisher's state changes.
+     * This method handles Epskc state changes.
      *
-     * @param[in] aState  The state of mDNS publisher.
+     * @param[in] aEpskcState    The Epskc state.
+     * @param[in] aPort          The UDP port of the Epskc service if it's active.
      */
-    void HandleMdnsState(Mdns::Publisher::State aState) override;
+    void HandleEpskcStateChanged(otBorderAgentEphemeralKeyState aEpskcState, uint16_t aPort);
+
+#endif // OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
 
     /**
      * This method creates ephemeral key in the Border Agent.
@@ -162,60 +173,69 @@ public:
      */
     static otbrError CreateEphemeralKey(std::string &aEphemeralKey);
 
+#if OTBR_ENABLE_DBUS_SERVER
     /**
-     * This method adds a callback for ephemeral key changes.
+     * This method updates the vendor MeshCoP TXT entries.
      *
-     * @param[in] aCallback  The callback to receive ephemeral key changed events.
+     * @param[in] aVendorEntries  A map of vendor MeshCoP TXT entries.
      */
-    void AddEphemeralKeyChangedCallback(EphemeralKeyChangedCallback aCallback);
+    void UpdateVendorMeshCoPTxtEntries(const VendorTxtEntries &aVendorEntries);
+#endif
 
 private:
     void ClearState(void);
     void Start(void);
     void Stop(void);
-    bool IsEnabled(void) const { return mIsEnabled; }
-    void PublishMeshCopService(void);
-    void UpdateMeshCopService(void);
-    void UnpublishMeshCopService(void);
-#if OTBR_ENABLE_DBUS_SERVER
-    void HandleUpdateVendorMeshCoPTxtEntries(std::map<std::string, std::vector<uint8_t>> aUpdate);
-#endif
+    bool IsEnabled(void) const
+    {
+        return mIsEnabled;
+    }
 
-    void HandleThreadStateChanged(otChangedFlags aFlags);
+    void EncodeVendorTxtData(const VendorTxtEntries &aVendorEntries);
 
-    bool        IsThreadStarted(void) const;
-    std::string GetServiceInstanceNameWithExtAddr(const std::string &aServiceInstanceName) const;
-    std::string GetAlternativeServiceInstanceName() const;
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
+    void PublishMeshCoPService(void);
+    void UpdateMeshCoPService(void);
+    void UnpublishMeshCoPService(void);
 
-    static void HandleEpskcStateChanged(void *aContext);
-    void        HandleEpskcStateChanged(void);
-    void        PublishEpskcService(void);
-    void        UnpublishEpskcService(void);
+    std::string GetServiceInstanceName(void) const;
+    std::string GetAlternativeServiceInstanceName(void) const;
 
-    otbr::Host::RcpHost &mHost;
-    Mdns::Publisher     &mPublisher;
-    bool                 mIsEnabled;
-    bool                 mIsEphemeralKeyEnabled;
+    void PublishEpskcService(uint16_t aPort);
+    void UnpublishEpskcService(void);
+#endif
 
-    std::map<std::string, std::vector<uint8_t>> mMeshCopTxtUpdate;
+    Mdns::Publisher &mPublisher;
+    bool             mIsEnabled;
 
     std::vector<uint8_t> mVendorOui;
 
     std::string mVendorName;
     std::string mProductName;
 
+    std::vector<uint8_t> mVendorTxtData; // Encoded vendor-specific TXT data.
+
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
+    std::vector<uint8_t> mOtTxtData; // Encoded TXT data from OpenThread core Border Agent module
+#endif
+
     // The base service instance name typically consists of the vendor and product name. But it can
-    // also be overridden by `OTBR_MESHCOP_SERVICE_INSTANCE_NAME` or method `SetMeshCopServiceValues()`.
+    // also be overridden by `OTBR_MESHCOP_SERVICE_INSTANCE_NAME` or method `SetMeshCoPServiceValues()`.
     // For example, this value can be "OpenThread Border Router".
     std::string mBaseServiceInstanceName;
 
+#if OTBR_ENABLE_BORDER_AGENT_MESHCOP_SERVICE
     // The actual instance name advertised in the mDNS service. This is usually the value of
     // `mBaseServiceInstanceName` plus the Extended Address and optional random number for avoiding
     // conflicts. For example, this value can be "OpenThread Border Router #7AC3" or
     // "OpenThread Border Router #7AC3 (14379)".
     std::string mServiceInstanceName;
 
-    std::vector<EphemeralKeyChangedCallback> mEphemeralKeyChangedCallbacks;
+    bool         mIsInitialized;
+    otExtAddress mExtAddress;
+    uint16_t     mMeshCoPUdpPort;
+    bool         mBaIsActive;
+#endif
 };
 
 /**
@@ -224,4 +244,6 @@ private:
 
 } // namespace otbr
 
+#endif // OTBR_ENABLE_BORDER_AGENT
+
 #endif // OTBR_AGENT_BORDER_AGENT_HPP_
diff --git a/src/common/types.cpp b/src/common/types.cpp
index 2fef20f8..54209351 100644
--- a/src/common/types.cpp
+++ b/src/common/types.cpp
@@ -67,6 +67,30 @@ Ip6Address Ip6Address::ToSolicitedNodeMulticastAddress(void) const
     return ma;
 }
 
+uint8_t Ip6Address::GetScope(void) const
+{
+    uint8_t rval;
+
+    if (IsMulticast())
+    {
+        rval = m8[1] & 0xf;
+    }
+    else if (IsLinkLocal())
+    {
+        rval = kLinkLocalScope;
+    }
+    else if (IsLoopback())
+    {
+        rval = kNodeLocalScope;
+    }
+    else
+    {
+        rval = kGlobalScope;
+    }
+
+    return rval;
+}
+
 void Ip6Address::CopyTo(struct sockaddr_in6 &aSockAddr) const
 {
     memset(&aSockAddr, 0, sizeof(aSockAddr));
diff --git a/src/common/types.hpp b/src/common/types.hpp
index a102a9eb..6478bb2b 100644
--- a/src/common/types.hpp
+++ b/src/common/types.hpp
@@ -109,6 +109,18 @@ static constexpr char kLinkLocalAllNodesMulticastAddress[] = "ff02::01";
 class Ip6Address
 {
 public:
+    // IPv6 Address Scopes
+    static constexpr uint8_t kNodeLocalScope      = 0;  ///< Node-Local scope
+    static constexpr uint8_t kInterfaceLocalScope = 1;  ///< Interface-Local scope
+    static constexpr uint8_t kLinkLocalScope      = 2;  ///< Link-Local scope
+    static constexpr uint8_t kRealmLocalScope     = 3;  ///< Realm-Local scope
+    static constexpr uint8_t kAdminLocalScope     = 4;  ///< Admin-Local scope
+    static constexpr uint8_t kSiteLocalScope      = 5;  ///< Site-Local scope
+    static constexpr uint8_t kOrgLocalScope       = 8;  ///< Organization-Local scope
+    static constexpr uint8_t kGlobalScope         = 14; ///< Global scope
+
+    static constexpr uint8_t kBitsPerByte = 8;
+
     /**
      * Default constructor.
      */
@@ -231,6 +243,13 @@ public:
      */
     bool IsLoopback(void) const { return (m32[0] == 0 && m32[1] == 0 && m32[2] == 0 && m32[3] == htobe32(1)); }
 
+    /**
+     * Returns the IPv6 address scope.
+     *
+     * @returns The IPv6 address scope.
+     */
+    uint8_t GetScope(void) const;
+
     /**
      * This function returns the wellknown Link Local All Nodes Multicast Address (ff02::1).
      *
diff --git a/src/dbus/server/dbus_agent.cpp b/src/dbus/server/dbus_agent.cpp
index 3cd30d17..7d27ce15 100644
--- a/src/dbus/server/dbus_agent.cpp
+++ b/src/dbus/server/dbus_agent.cpp
@@ -46,14 +46,13 @@ namespace DBus {
 const struct timeval           DBusAgent::kPollTimeout = {0, 0};
 constexpr std::chrono::seconds DBusAgent::kDBusWaitAllowance;
 
-DBusAgent::DBusAgent(otbr::Host::ThreadHost &aHost, Mdns::Publisher &aPublisher)
-    : mInterfaceName(aHost.GetInterfaceName())
-    , mHost(aHost)
-    , mPublisher(aPublisher)
+DBusAgent::DBusAgent(const DependentComponents &aDeps)
+    : mInterfaceName(aDeps.mHost.GetInterfaceName())
+    , mDeps(aDeps)
 {
 }
 
-void DBusAgent::Init(otbr::BorderAgent &aBorderAgent)
+void DBusAgent::Init(void)
 {
     otbrError error = OTBR_ERROR_NONE;
 
@@ -67,16 +66,14 @@ void DBusAgent::Init(otbr::BorderAgent &aBorderAgent)
 
     VerifyOrDie(mConnection != nullptr, "Failed to get DBus connection");
 
-    switch (mHost.GetCoprocessorType())
+    switch (mDeps.mHost.GetCoprocessorType())
     {
     case OT_COPROCESSOR_RCP:
-        mThreadObject = MakeUnique<DBusThreadObjectRcp>(*mConnection, mInterfaceName,
-                                                        static_cast<Host::RcpHost &>(mHost), &mPublisher, aBorderAgent);
+        mThreadObject = MakeUnique<DBusThreadObjectRcp>(*mConnection, mInterfaceName, mDeps);
         break;
 
     case OT_COPROCESSOR_NCP:
-        mThreadObject =
-            MakeUnique<DBusThreadObjectNcp>(*mConnection, mInterfaceName, static_cast<Host::NcpHost &>(mHost));
+        mThreadObject = MakeUnique<DBusThreadObjectNcp>(*mConnection, mInterfaceName, mDeps);
         break;
 
     default:
diff --git a/src/dbus/server/dbus_agent.hpp b/src/dbus/server/dbus_agent.hpp
index 2a68a6c2..d8225865 100644
--- a/src/dbus/server/dbus_agent.hpp
+++ b/src/dbus/server/dbus_agent.hpp
@@ -59,15 +59,14 @@ public:
     /**
      * The constructor of dbus agent.
      *
-     * @param[in] aHost           A reference to the Thread host.
-     * @param[in] aPublisher      A reference to the MDNS publisher.
+     * @param[in]  aDeps   A reference to the DBus server dependent components.
      */
-    DBusAgent(otbr::Host::ThreadHost &aHost, Mdns::Publisher &aPublisher);
+    DBusAgent(const DependentComponents &aDeps);
 
     /**
      * This method initializes the dbus agent.
      */
-    void Init(otbr::BorderAgent &aBorderAgent);
+    void Init(void);
 
     void Update(MainloopContext &aMainloop) override;
     void Process(const MainloopContext &aMainloop) override;
@@ -87,8 +86,7 @@ private:
     std::string                 mInterfaceName;
     std::unique_ptr<DBusObject> mThreadObject;
     UniqueDBusConnection        mConnection;
-    otbr::Host::ThreadHost     &mHost;
-    Mdns::Publisher            &mPublisher;
+    DependentComponents         mDeps;
 
     /**
      * This map is used to track DBusWatch-es.
diff --git a/src/dbus/server/dbus_object.hpp b/src/dbus/server/dbus_object.hpp
index d77f0450..0c2efa61 100644
--- a/src/dbus/server/dbus_object.hpp
+++ b/src/dbus/server/dbus_object.hpp
@@ -47,6 +47,7 @@
 
 #include <dbus/dbus.h>
 
+#include "border_agent/border_agent.hpp"
 #include "common/code_utils.hpp"
 #include "common/types.hpp"
 #include "dbus/common/constants.hpp"
@@ -54,10 +55,22 @@
 #include "dbus/common/dbus_message_helper.hpp"
 #include "dbus/common/dbus_resources.hpp"
 #include "dbus/server/dbus_request.hpp"
+#include "host/thread_host.hpp"
+#include "mdns/mdns.hpp"
 
 namespace otbr {
 namespace DBus {
 
+class DependentComponents
+{
+public:
+    Host::ThreadHost &mHost;
+    Mdns::Publisher  &mPublisher;
+#if OTBR_ENABLE_BORDER_AGENT
+    otbr::BorderAgent &mBorderAgent;
+#endif
+};
+
 /**
  * This class is a base class for implementing a d-bus object.
  */
diff --git a/src/dbus/server/dbus_request.hpp b/src/dbus/server/dbus_request.hpp
index 27a803e6..06bad7f0 100644
--- a/src/dbus/server/dbus_request.hpp
+++ b/src/dbus/server/dbus_request.hpp
@@ -142,16 +142,8 @@ public:
     {
         UniqueDBusMessage reply{nullptr};
 
-        if (aError == OT_ERROR_NONE)
-        {
-            otbrLogInfo("Replied to %s.%s with result %s", dbus_message_get_interface(mMessage),
-                        dbus_message_get_member(mMessage), ConvertToDBusErrorName(aError));
-        }
-        else
-        {
-            otbrLogErr("Replied to %s.%s with result %s", dbus_message_get_interface(mMessage),
-                       dbus_message_get_member(mMessage), ConvertToDBusErrorName(aError));
-        }
+        otbrLogInfo("Replied to %s.%s with result %s", dbus_message_get_interface(mMessage),
+                    dbus_message_get_member(mMessage), ConvertToDBusErrorName(aError));
 
         if (aError == OT_ERROR_NONE)
         {
diff --git a/src/dbus/server/dbus_thread_object_ncp.cpp b/src/dbus/server/dbus_thread_object_ncp.cpp
index 104d936f..789ae5c0 100644
--- a/src/dbus/server/dbus_thread_object_ncp.cpp
+++ b/src/dbus/server/dbus_thread_object_ncp.cpp
@@ -41,11 +41,11 @@ using std::placeholders::_2;
 namespace otbr {
 namespace DBus {
 
-DBusThreadObjectNcp::DBusThreadObjectNcp(DBusConnection      &aConnection,
-                                         const std::string   &aInterfaceName,
-                                         otbr::Host::NcpHost &aHost)
+DBusThreadObjectNcp::DBusThreadObjectNcp(DBusConnection            &aConnection,
+                                         const std::string         &aInterfaceName,
+                                         const DependentComponents &aDeps)
     : DBusObject(&aConnection, OTBR_DBUS_OBJECT_PREFIX + aInterfaceName)
-    , mHost(aHost)
+    , mHost(static_cast<Host::NcpHost &>(aDeps.mHost))
 {
 }
 
diff --git a/src/dbus/server/dbus_thread_object_ncp.hpp b/src/dbus/server/dbus_thread_object_ncp.hpp
index 9ecd0a0e..e09766bc 100644
--- a/src/dbus/server/dbus_thread_object_ncp.hpp
+++ b/src/dbus/server/dbus_thread_object_ncp.hpp
@@ -65,9 +65,11 @@ public:
      *
      * @param[in] aConnection     The dbus connection.
      * @param[in] aInterfaceName  The dbus interface name.
-     * @param[in] aHost           The Thread controller.
+     * @param[in] aDeps           The dependent components.
      */
-    DBusThreadObjectNcp(DBusConnection &aConnection, const std::string &aInterfaceName, otbr::Host::NcpHost &aHost);
+    DBusThreadObjectNcp(DBusConnection            &aConnection,
+                        const std::string         &aInterfaceName,
+                        const DependentComponents &aDeps);
 
     /**
      * This method initializes the dbus thread object.
diff --git a/src/dbus/server/dbus_thread_object_rcp.cpp b/src/dbus/server/dbus_thread_object_rcp.cpp
index a6a3aa3f..82fd3036 100644
--- a/src/dbus/server/dbus_thread_object_rcp.cpp
+++ b/src/dbus/server/dbus_thread_object_rcp.cpp
@@ -101,15 +101,15 @@ static std::string GetNat64StateName(otNat64State aState)
 namespace otbr {
 namespace DBus {
 
-DBusThreadObjectRcp::DBusThreadObjectRcp(DBusConnection      &aConnection,
-                                         const std::string   &aInterfaceName,
-                                         otbr::Host::RcpHost &aHost,
-                                         Mdns::Publisher     *aPublisher,
-                                         otbr::BorderAgent   &aBorderAgent)
+DBusThreadObjectRcp::DBusThreadObjectRcp(DBusConnection            &aConnection,
+                                         const std::string         &aInterfaceName,
+                                         const DependentComponents &aDeps)
     : DBusObject(&aConnection, OTBR_DBUS_OBJECT_PREFIX + aInterfaceName)
-    , mHost(aHost)
-    , mPublisher(aPublisher)
-    , mBorderAgent(aBorderAgent)
+    , mHost(static_cast<Host::RcpHost &>(aDeps.mHost))
+    , mPublisher(&aDeps.mPublisher)
+#if OTBR_ENABLE_BORDER_AGENT
+    , mBorderAgent(aDeps.mBorderAgent)
+#endif
 {
 }
 
@@ -155,8 +155,10 @@ otbrError DBusThreadObjectRcp::Init(void)
                    std::bind(&DBusThreadObjectRcp::RemoveExternalRouteHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_ATTACH_ALL_NODES_TO_METHOD,
                    std::bind(&DBusThreadObjectRcp::AttachAllNodesToHandler, this, _1));
+#if OTBR_ENABLE_BORDER_AGENT
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_UPDATE_VENDOR_MESHCOP_TXT_METHOD,
                    std::bind(&DBusThreadObjectRcp::UpdateMeshCopTxtHandler, this, _1));
+#endif
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_GET_PROPERTIES_METHOD,
                    std::bind(&DBusThreadObjectRcp::GetPropertiesHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_SET_THREAD_ENABLED_METHOD,
@@ -167,11 +169,12 @@ otbrError DBusThreadObjectRcp::Init(void)
                    std::bind(&DBusThreadObjectRcp::LeaveNetworkHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_SET_NAT64_ENABLED_METHOD,
                    std::bind(&DBusThreadObjectRcp::SetNat64Enabled, this, _1));
+#if OTBR_ENABLE_BORDER_AGENT
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_ACTIVATE_EPHEMERAL_KEY_MODE_METHOD,
                    std::bind(&DBusThreadObjectRcp::ActivateEphemeralKeyModeHandler, this, _1));
     RegisterMethod(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_DEACTIVATE_EPHEMERAL_KEY_MODE_METHOD,
                    std::bind(&DBusThreadObjectRcp::DeactivateEphemeralKeyModeHandler, this, _1));
-
+#endif
     RegisterMethod(DBUS_INTERFACE_INTROSPECTABLE, DBUS_INTROSPECT_METHOD,
                    std::bind(&DBusThreadObjectRcp::IntrospectHandler, this, _1));
 
@@ -189,8 +192,10 @@ otbrError DBusThreadObjectRcp::Init(void)
                                std::bind(&DBusThreadObjectRcp::SetDnsUpstreamQueryState, this, _1));
     RegisterSetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_NAT64_CIDR,
                                std::bind(&DBusThreadObjectRcp::SetNat64Cidr, this, _1));
+#if OTBR_ENABLE_BORDER_AGENT
     RegisterSetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_EPHEMERAL_KEY_ENABLED,
                                std::bind(&DBusThreadObjectRcp::SetEphemeralKeyEnabled, this, _1));
+#endif
 
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_LINK_MODE,
                                std::bind(&DBusThreadObjectRcp::GetLinkModeHandler, this, _1));
@@ -295,8 +300,10 @@ otbrError DBusThreadObjectRcp::Init(void)
                                std::bind(&DBusThreadObjectRcp::GetNat64ErrorCounters, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_NAT64_CIDR,
                                std::bind(&DBusThreadObjectRcp::GetNat64Cidr, this, _1));
+#if OTBR_ENABLE_BORDER_AGENT
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_EPHEMERAL_KEY_ENABLED,
                                std::bind(&DBusThreadObjectRcp::GetEphemeralKeyEnabled, this, _1));
+#endif
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_INFRA_LINK_INFO,
                                std::bind(&DBusThreadObjectRcp::GetInfraLinkInfo, this, _1));
     RegisterGetPropertyHandler(OTBR_DBUS_THREAD_INTERFACE, OTBR_DBUS_PROPERTY_TREL_INFO,
@@ -1256,7 +1263,7 @@ otError DBusThreadObjectRcp::SetFeatureFlagListDataHandler(DBusMessageIter &aIte
     VerifyOrExit(DBusMessageExtractFromVariant(&aIter, data) == OTBR_ERROR_NONE, error = OT_ERROR_INVALID_ARGS);
     VerifyOrExit(featureFlagList.ParseFromString(std::string(data.begin(), data.end())), error = OT_ERROR_INVALID_ARGS);
     // TODO: implement the feature flag handler at every component
-    mBorderAgent.SetEphemeralKeyEnabled(featureFlagList.enable_ephemeralkey());
+    otBorderAgentEphemeralKeySetEnabled(mHost.GetInstance(), featureFlagList.enable_ephemeralkey());
     otbrLogInfo("Border Agent Ephemeral Key Feature has been %s by feature flag",
                 (featureFlagList.enable_ephemeralkey() ? "enable" : "disable"));
     VerifyOrExit((error = mHost.ApplyFeatureFlagList(featureFlagList)) == OT_ERROR_NONE);
@@ -1302,10 +1309,10 @@ exit:
     return error;
 }
 
+#if OTBR_ENABLE_BORDER_AGENT
 void DBusThreadObjectRcp::UpdateMeshCopTxtHandler(DBusRequest &aRequest)
 {
-    auto                                        threadHelper = mHost.GetThreadHelper();
-    otError                                     error        = OT_ERROR_NONE;
+    otError                                     error = OT_ERROR_NONE;
     std::map<std::string, std::vector<uint8_t>> update;
     std::vector<TxtEntry>                       updatedTxtEntries;
     auto                                        args = std::tie(updatedTxtEntries);
@@ -1319,11 +1326,12 @@ void DBusThreadObjectRcp::UpdateMeshCopTxtHandler(DBusRequest &aRequest)
     {
         VerifyOrExit(!update.count(reservedKey), error = OT_ERROR_INVALID_ARGS);
     }
-    threadHelper->OnUpdateMeshCopTxt(std::move(update));
+    mBorderAgent.UpdateVendorMeshCoPTxtEntries(update);
 
 exit:
     aRequest.ReplyOtResult(error);
 }
+#endif // OTBR_ENABLE_BORDER_AGENT
 
 otError DBusThreadObjectRcp::GetRadioRegionHandler(DBusMessageIter &aIter)
 {
@@ -1345,7 +1353,7 @@ exit:
 
 otError DBusThreadObjectRcp::GetSrpServerInfoHandler(DBusMessageIter &aIter)
 {
-#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+#if OTBR_ENABLE_SRP_SERVER
     auto                               threadHelper = mHost.GetThreadHelper();
     auto                               instance     = threadHelper->GetInstance();
     otError                            error        = OT_ERROR_NONE;
@@ -1405,11 +1413,11 @@ otError DBusThreadObjectRcp::GetSrpServerInfoHandler(DBusMessageIter &aIter)
 
 exit:
     return error;
-#else  // OTBR_ENABLE_SRP_ADVERTISING_PROXY
+#else  // OTBR_ENABLE_SRP_SERVER
     OTBR_UNUSED_VARIABLE(aIter);
 
     return OT_ERROR_NOT_IMPLEMENTED;
-#endif // OTBR_ENABLE_SRP_ADVERTISING_PROXY
+#endif // OTBR_ENABLE_SRP_SERVER
 }
 
 otError DBusThreadObjectRcp::GetMdnsTelemetryInfoHandler(DBusMessageIter &aIter)
@@ -2031,11 +2039,13 @@ otError DBusThreadObjectRcp::SetNat64Cidr(DBusMessageIter &aIter)
 }
 #endif // OTBR_ENABLE_NAT64
 
+#if OTBR_ENABLE_BORDER_AGENT
 otError DBusThreadObjectRcp::GetEphemeralKeyEnabled(DBusMessageIter &aIter)
 {
     otError error = OT_ERROR_NONE;
 
-    SuccessOrExit(DBusMessageEncodeToVariant(&aIter, mBorderAgent.GetEphemeralKeyEnabled()),
+    SuccessOrExit(DBusMessageEncodeToVariant(&aIter, otBorderAgentEphemeralKeyGetState(mHost.GetInstance()) !=
+                                                         OT_BORDER_AGENT_STATE_DISABLED),
                   error = OT_ERROR_INVALID_ARGS);
 
 exit:
@@ -2048,7 +2058,7 @@ otError DBusThreadObjectRcp::SetEphemeralKeyEnabled(DBusMessageIter &aIter)
     bool    enable;
 
     SuccessOrExit(DBusMessageExtractFromVariant(&aIter, enable), error = OT_ERROR_INVALID_ARGS);
-    mBorderAgent.SetEphemeralKeyEnabled(enable);
+    otBorderAgentEphemeralKeySetEnabled(mHost.GetInstance(), enable);
 
 exit:
     return error;
@@ -2061,8 +2071,6 @@ void DBusThreadObjectRcp::DeactivateEphemeralKeyModeHandler(DBusRequest &aReques
     bool    retain_active_session;
     auto    args = std::tie(retain_active_session);
 
-    VerifyOrExit(mBorderAgent.GetEphemeralKeyEnabled(), error = OT_ERROR_NOT_CAPABLE);
-
     SuccessOrExit(DBusMessageToTuple(*aRequest.GetMessage(), args), error = OT_ERROR_INVALID_ARGS);
 
     // Stop the ephemeral key use if
@@ -2078,6 +2086,7 @@ void DBusThreadObjectRcp::DeactivateEphemeralKeyModeHandler(DBusRequest &aReques
         VerifyOrExit(!retain_active_session);
         break;
     case OT_BORDER_AGENT_STATE_DISABLED:
+        error = OT_ERROR_NOT_CAPABLE;
     case OT_BORDER_AGENT_STATE_STOPPED:
         ExitNow();
     }
@@ -2096,7 +2105,8 @@ void DBusThreadObjectRcp::ActivateEphemeralKeyModeHandler(DBusRequest &aRequest)
     auto        args         = std::tie(lifetime);
     std::string ePskc;
 
-    VerifyOrExit(mBorderAgent.GetEphemeralKeyEnabled(), error = OT_ERROR_NOT_CAPABLE);
+    VerifyOrExit(otBorderAgentEphemeralKeyGetState(threadHelper->GetInstance()) != OT_BORDER_AGENT_STATE_DISABLED,
+                 error = OT_ERROR_NOT_CAPABLE);
 
     SuccessOrExit(DBusMessageToTuple(*aRequest.GetMessage(), args), error = OT_ERROR_INVALID_ARGS);
     VerifyOrExit(lifetime <= OT_BORDER_AGENT_MAX_EPHEMERAL_KEY_TIMEOUT, error = OT_ERROR_INVALID_ARGS);
@@ -2117,6 +2127,7 @@ exit:
         aRequest.ReplyOtResult(error);
     }
 }
+#endif // OTBR_ENABLE_BORDER_AGENT
 
 otError DBusThreadObjectRcp::GetInfraLinkInfo(DBusMessageIter &aIter)
 {
diff --git a/src/dbus/server/dbus_thread_object_rcp.hpp b/src/dbus/server/dbus_thread_object_rcp.hpp
index 67891bc2..c9f24903 100644
--- a/src/dbus/server/dbus_thread_object_rcp.hpp
+++ b/src/dbus/server/dbus_thread_object_rcp.hpp
@@ -65,15 +65,11 @@ public:
      *
      * @param[in] aConnection     The dbus connection.
      * @param[in] aInterfaceName  The dbus interface name.
-     * @param[in] aHost           The Thread controller
-     * @param[in] aPublisher      The Mdns::Publisher
-     * @param[in] aBorderAgent    The Border Agent
+     * @param[in] aDeps           The dependent components.
      */
-    DBusThreadObjectRcp(DBusConnection      &aConnection,
-                        const std::string   &aInterfaceName,
-                        otbr::Host::RcpHost &aHost,
-                        Mdns::Publisher     *aPublisher,
-                        otbr::BorderAgent   &aBorderAgent);
+    DBusThreadObjectRcp(DBusConnection            &aConnection,
+                        const std::string         &aInterfaceName,
+                        const DependentComponents &aDeps);
 
     otbrError Init(void) override;
 
@@ -102,14 +98,18 @@ private:
     void RemoveOnMeshPrefixHandler(DBusRequest &aRequest);
     void AddExternalRouteHandler(DBusRequest &aRequest);
     void RemoveExternalRouteHandler(DBusRequest &aRequest);
+#if OTBR_ENABLE_BORDER_AGENT
     void UpdateMeshCopTxtHandler(DBusRequest &aRequest);
+#endif
     void SetThreadEnabledHandler(DBusRequest &aRequest);
     void JoinHandler(DBusRequest &aRequest);
     void GetPropertiesHandler(DBusRequest &aRequest);
     void LeaveNetworkHandler(DBusRequest &aRequest);
     void SetNat64Enabled(DBusRequest &aRequest);
+#if OTBR_ENABLE_BORDER_AGENT
     void ActivateEphemeralKeyModeHandler(DBusRequest &aRequest);
     void DeactivateEphemeralKeyModeHandler(DBusRequest &aRequest);
+#endif
 
     void IntrospectHandler(DBusRequest &aRequest);
 
@@ -121,7 +121,9 @@ private:
     otError SetRadioRegionHandler(DBusMessageIter &aIter);
     otError SetDnsUpstreamQueryState(DBusMessageIter &aIter);
     otError SetNat64Cidr(DBusMessageIter &aIter);
+#if OTBR_ENABLE_BORDER_AGENT
     otError SetEphemeralKeyEnabled(DBusMessageIter &aIter);
+#endif
 
     otError GetLinkModeHandler(DBusMessageIter &aIter);
     otError GetDeviceRoleHandler(DBusMessageIter &aIter);
@@ -174,7 +176,9 @@ private:
     otError GetNat64Mappings(DBusMessageIter &aIter);
     otError GetNat64ProtocolCounters(DBusMessageIter &aIter);
     otError GetNat64ErrorCounters(DBusMessageIter &aIter);
+#if OTBR_ENABLE_BORDER_AGENT
     otError GetEphemeralKeyEnabled(DBusMessageIter &aIter);
+#endif
     otError GetInfraLinkInfo(DBusMessageIter &aIter);
     otError GetDnsUpstreamQueryState(DBusMessageIter &aIter);
     otError GetTelemetryDataHandler(DBusMessageIter &aIter);
@@ -186,7 +190,9 @@ private:
     otbr::Host::RcpHost                                 &mHost;
     std::unordered_map<std::string, PropertyHandlerType> mGetPropertyHandlers;
     otbr::Mdns::Publisher                               *mPublisher;
-    otbr::BorderAgent                                   &mBorderAgent;
+#if OTBR_ENABLE_BORDER_AGENT
+    otbr::BorderAgent &mBorderAgent;
+#endif
 };
 
 /**
diff --git a/src/dbus/server/introspect.xml b/src/dbus/server/introspect.xml
index 449dee38..9c9637da 100644
--- a/src/dbus/server/introspect.xml
+++ b/src/dbus/server/introspect.xml
@@ -960,6 +960,25 @@
       <annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="false"/>
     </property>
 
+    <!-- TrelInfo: Information about the TREL link
+    <literallayout>
+        struct {
+          bool   enabled          // Whether TREL is enabled.
+          uint16 num_trel_peers   // The number of TREL peers.
+          struct {
+            uint64 tx_packets     // Number of packets transmitted through TREL.
+            uint64 tx_bytes       // Sum of size of packets transmitted through TREL.
+            uint64 tx_failure     // Number of packet transmission failures through TREL.
+            uint64 rx_packets     // Number of packets received through TREL.
+            uint64 rx_bytes       // Sum of size of packets received through TREL.
+          }
+        }
+    </literallayout>
+    -->
+    <property name="TrelInfo" type="(bq(ttttt))" access="read">
+      <annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="false"/>
+    </property>
+
     <!-- DnsUpstreamQueryState: Whether the server will / should forward DNS queries platform
     specified upstream DNS servers. -->
     <property name="DnsUpstreamQueryState" type="b" access="readwrite">
diff --git a/src/host/ncp_host.cpp b/src/host/ncp_host.cpp
index 7bb6edeb..f7e0ec42 100644
--- a/src/host/ncp_host.cpp
+++ b/src/host/ncp_host.cpp
@@ -45,10 +45,15 @@ namespace Host {
 
 // =============================== NcpNetworkProperties ===============================
 
+constexpr otMeshLocalPrefix kMeshLocalPrefixInit = {
+    {0xfd, 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0x00},
+};
+
 NcpNetworkProperties::NcpNetworkProperties(void)
     : mDeviceRole(OT_DEVICE_ROLE_DISABLED)
 {
     memset(&mDatasetActiveTlvs, 0, sizeof(mDatasetActiveTlvs));
+    SetMeshLocalPrefix(kMeshLocalPrefixInit);
 }
 
 otDeviceRole NcpNetworkProperties::GetDeviceRole(void) const
@@ -91,12 +96,21 @@ void NcpNetworkProperties::GetDatasetPendingTlvs(otOperationalDatasetTlvs &aData
     OTBR_UNUSED_VARIABLE(aDatasetTlvs);
 }
 
+void NcpNetworkProperties::SetMeshLocalPrefix(const otMeshLocalPrefix &aMeshLocalPrefix)
+{
+    memcpy(mMeshLocalPrefix.m8, aMeshLocalPrefix.m8, sizeof(mMeshLocalPrefix.m8));
+}
+
+const otMeshLocalPrefix *NcpNetworkProperties::GetMeshLocalPrefix(void) const
+{
+    return &mMeshLocalPrefix;
+}
+
 // ===================================== NcpHost ======================================
 
 NcpHost::NcpHost(const char *aInterfaceName, const char *aBackboneInterfaceName, bool aDryRun)
     : mSpinelDriver(*static_cast<ot::Spinel::SpinelDriver *>(otSysGetSpinelDriver()))
-    , mNetif(mNcpSpinel)
-    , mInfraIf(mNcpSpinel)
+    , mCliDaemon(mNcpSpinel)
 {
     memset(&mConfig, 0, sizeof(mConfig));
     mConfig.mInterfaceName         = aInterfaceName;
@@ -114,25 +128,9 @@ void NcpHost::Init(void)
 {
     otSysInit(&mConfig);
     mNcpSpinel.Init(mSpinelDriver, *this);
-    mNetif.Init(mConfig.mInterfaceName);
-    mInfraIf.Init();
-
-    mNcpSpinel.Ip6SetAddressCallback(
-        [this](const std::vector<Ip6AddressInfo> &aAddrInfos) { mNetif.UpdateIp6UnicastAddresses(aAddrInfos); });
-    mNcpSpinel.Ip6SetAddressMulticastCallback(
-        [this](const std::vector<Ip6Address> &aAddrs) { mNetif.UpdateIp6MulticastAddresses(aAddrs); });
-    mNcpSpinel.NetifSetStateChangedCallback([this](bool aState) { mNetif.SetNetifState(aState); });
-    mNcpSpinel.Ip6SetReceiveCallback(
-        [this](const uint8_t *aData, uint16_t aLength) { mNetif.Ip6Receive(aData, aLength); });
-    mNcpSpinel.InfraIfSetIcmp6NdSendCallback(
-        [this](uint32_t aInfraIfIndex, const otIp6Address &aAddr, const uint8_t *aData, uint16_t aDataLen) {
-            OTBR_UNUSED_VARIABLE(mInfraIf.SendIcmp6Nd(aInfraIfIndex, aAddr, aData, aDataLen));
-        });
+    mCliDaemon.Init(mConfig.mInterfaceName);
 
-    if (mConfig.mBackboneInterfaceName != nullptr && strlen(mConfig.mBackboneInterfaceName) > 0)
-    {
-        mInfraIf.SetInfraIf(mConfig.mBackboneInterfaceName);
-    }
+    mNcpSpinel.CliDaemonSetOutputCallback([this](const char *aOutput) { mCliDaemon.HandleCommandOutput(aOutput); });
 
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
 #if OTBR_ENABLE_SRP_SERVER_AUTO_ENABLE_MODE
@@ -148,7 +146,6 @@ void NcpHost::Init(void)
 void NcpHost::Deinit(void)
 {
     mNcpSpinel.Deinit();
-    mNetif.Deinit();
     otSysDeinit();
 }
 
@@ -253,11 +250,37 @@ void NcpHost::AddThreadEnabledStateChangedCallback(ThreadEnabledStateCallback aC
     OT_UNUSED_VARIABLE(aCallback);
 }
 
+#if OTBR_ENABLE_BACKBONE_ROUTER
+void NcpHost::SetBackboneRouterEnabled(bool aEnabled)
+{
+    mNcpSpinel.SetBackboneRouterEnabled(aEnabled);
+}
+
+void NcpHost::SetBackboneRouterMulticastListenerCallback(BackboneRouterMulticastListenerCallback aCallback)
+{
+    mNcpSpinel.SetBackboneRouterMulticastListenerCallback(std::move(aCallback));
+}
+
+void NcpHost::SetBackboneRouterStateChangedCallback(BackboneRouterStateChangedCallback aCallback)
+{
+    mNcpSpinel.SetBackboneRouterStateChangedCallback(std::move(aCallback));
+}
+#endif
+
+void NcpHost::SetBorderAgentMeshCoPServiceChangedCallback(BorderAgentMeshCoPServiceChangedCallback aCallback)
+{
+    mNcpSpinel.SetBorderAgentMeshCoPServiceChangedCallback(aCallback);
+}
+
+void NcpHost::AddEphemeralKeyStateChangedCallback(EphemeralKeyStateChangedCallback aCallback)
+{
+    OTBR_UNUSED_VARIABLE(aCallback);
+}
+
 void NcpHost::Process(const MainloopContext &aMainloop)
 {
     mSpinelDriver.Process(&aMainloop);
-
-    mNetif.Process(&aMainloop);
+    mCliDaemon.Process(aMainloop);
 }
 
 void NcpHost::Update(MainloopContext &aMainloop)
@@ -270,7 +293,7 @@ void NcpHost::Update(MainloopContext &aMainloop)
         aMainloop.mTimeout.tv_usec = 0;
     }
 
-    mNetif.UpdateFdSet(&aMainloop);
+    mCliDaemon.UpdateFdSet(aMainloop);
 }
 
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
@@ -285,5 +308,66 @@ void NcpHost::HandleMdnsState(Mdns::Publisher::State aState)
 }
 #endif
 
+otbrError NcpHost::UdpForward(const uint8_t      *aUdpPayload,
+                              uint16_t            aLength,
+                              const otIp6Address &aRemoteAddr,
+                              uint16_t            aRemotePort,
+                              const UdpProxy     &aUdpProxy)
+{
+    return mNcpSpinel.UdpForward(aUdpPayload, aLength, aRemoteAddr, aRemotePort, aUdpProxy.GetThreadPort());
+}
+
+void NcpHost::SetUdpForwardToHostCallback(UdpForwardToHostCallback aCallback)
+{
+    mNcpSpinel.SetUdpForwardSendCallback(aCallback);
+}
+
+const otMeshLocalPrefix *NcpHost::GetMeshLocalPrefix(void) const
+{
+    return NcpNetworkProperties::GetMeshLocalPrefix();
+}
+
+void NcpHost::InitNetifCallbacks(Netif &aNetif)
+{
+    mNcpSpinel.Ip6SetAddressCallback(
+        [&aNetif](const std::vector<Ip6AddressInfo> &aAddrInfos) { aNetif.UpdateIp6UnicastAddresses(aAddrInfos); });
+    mNcpSpinel.Ip6SetAddressMulticastCallback(
+        [&aNetif](const std::vector<Ip6Address> &aAddrs) { aNetif.UpdateIp6MulticastAddresses(aAddrs); });
+    mNcpSpinel.NetifSetStateChangedCallback([&aNetif](bool aState) { aNetif.SetNetifState(aState); });
+    mNcpSpinel.Ip6SetReceiveCallback(
+        [&aNetif](const uint8_t *aData, uint16_t aLength) { aNetif.Ip6Receive(aData, aLength); });
+}
+
+void NcpHost::InitInfraIfCallbacks(InfraIf &aInfraIf)
+{
+    mNcpSpinel.InfraIfSetIcmp6NdSendCallback(
+        [&aInfraIf](uint32_t aInfraIfIndex, const otIp6Address &aAddr, const uint8_t *aData, uint16_t aDataLen) {
+            OTBR_UNUSED_VARIABLE(aInfraIf.SendIcmp6Nd(aInfraIfIndex, aAddr, aData, aDataLen));
+        });
+}
+
+otbrError NcpHost::Ip6Send(const uint8_t *aData, uint16_t aLength)
+{
+    return mNcpSpinel.Ip6Send(aData, aLength);
+}
+
+otbrError NcpHost::Ip6MulAddrUpdateSubscription(const otIp6Address &aAddress, bool aIsAdded)
+{
+    return mNcpSpinel.Ip6MulAddrUpdateSubscription(aAddress, aIsAdded);
+}
+
+otbrError NcpHost::SetInfraIf(uint32_t aInfraIfIndex, bool aIsRunning, const std::vector<Ip6Address> &aIp6Addresses)
+{
+    return mNcpSpinel.SetInfraIf(aInfraIfIndex, aIsRunning, aIp6Addresses);
+}
+
+otbrError NcpHost::HandleIcmp6Nd(uint32_t          aInfraIfIndex,
+                                 const Ip6Address &aIp6Address,
+                                 const uint8_t    *aData,
+                                 uint16_t          aDataLen)
+{
+    return mNcpSpinel.HandleIcmp6Nd(aInfraIfIndex, aIp6Address, aData, aDataLen);
+}
+
 } // namespace Host
 } // namespace otbr
diff --git a/src/host/ncp_host.hpp b/src/host/ncp_host.hpp
index f4fb0b0e..6239c170 100644
--- a/src/host/ncp_host.hpp
+++ b/src/host/ncp_host.hpp
@@ -40,6 +40,8 @@
 #include "common/mainloop.hpp"
 #include "host/ncp_spinel.hpp"
 #include "host/thread_host.hpp"
+#include "posix/cli_daemon.hpp"
+#include "posix/infra_if.hpp"
 #include "posix/netif.hpp"
 
 namespace otbr {
@@ -57,24 +59,29 @@ public:
     explicit NcpNetworkProperties(void);
 
     // NetworkProperties methods
-    otDeviceRole GetDeviceRole(void) const override;
-    bool         Ip6IsEnabled(void) const override;
-    uint32_t     GetPartitionId(void) const override;
-    void         GetDatasetActiveTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override;
-    void         GetDatasetPendingTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override;
+    otDeviceRole             GetDeviceRole(void) const override;
+    bool                     Ip6IsEnabled(void) const override;
+    uint32_t                 GetPartitionId(void) const override;
+    void                     GetDatasetActiveTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override;
+    void                     GetDatasetPendingTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override;
+    const otMeshLocalPrefix *GetMeshLocalPrefix(void) const override;
 
 private:
     // PropsObserver methods
     void SetDeviceRole(otDeviceRole aRole) override;
     void SetDatasetActiveTlvs(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs) override;
+    void SetMeshLocalPrefix(const otMeshLocalPrefix &aMeshLocalPrefix) override;
 
     otDeviceRole             mDeviceRole;
     otOperationalDatasetTlvs mDatasetActiveTlvs;
+    otMeshLocalPrefix        mMeshLocalPrefix;
 };
 
 class NcpHost : public MainloopProcessor,
                 public ThreadHost,
-                public NcpNetworkProperties
+                public NcpNetworkProperties,
+                public Netif::Dependencies,
+                public InfraIf::Dependencies
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
     ,
                 public Mdns::StateObserver
@@ -107,8 +114,18 @@ public:
     void SetChannelMaxPowers(const std::vector<ChannelMaxPower> &aChannelMaxPowers,
                              const AsyncResultReceiver          &aReceiver) override;
 #endif
-    void            AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback) override;
-    void            AddThreadEnabledStateChangedCallback(ThreadEnabledStateCallback aCallback) override;
+    void AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback) override;
+    void AddThreadEnabledStateChangedCallback(ThreadEnabledStateCallback aCallback) override;
+#if OTBR_ENABLE_BACKBONE_ROUTER
+    void SetBackboneRouterEnabled(bool aEnabled) override;
+    void SetBackboneRouterMulticastListenerCallback(BackboneRouterMulticastListenerCallback aCallback) override;
+    void SetBackboneRouterStateChangedCallback(BackboneRouterStateChangedCallback aCallback) override;
+#endif
+    void SetBorderAgentMeshCoPServiceChangedCallback(BorderAgentMeshCoPServiceChangedCallback aCallback) override;
+    void AddEphemeralKeyStateChangedCallback(EphemeralKeyStateChangedCallback aCallback) override;
+    void SetUdpForwardToHostCallback(UdpForwardToHostCallback aCallback) override;
+    const otMeshLocalPrefix *GetMeshLocalPrefix(void) const override;
+
     CoprocessorType GetCoprocessorType(void) override
     {
         return OT_COPROCESSOR_NCP;
@@ -129,17 +146,34 @@ public:
     void SetMdnsPublisher(Mdns::Publisher *aPublisher);
 #endif
 
+    void InitNetifCallbacks(Netif &aNetif);
+    void InitInfraIfCallbacks(InfraIf &aInfraIf);
+
 private:
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
     void HandleMdnsState(Mdns::Publisher::State aState) override;
 #endif
+    otbrError UdpForward(const uint8_t      *aUdpPayload,
+                         uint16_t            aLength,
+                         const otIp6Address &aRemoteAddr,
+                         uint16_t            aRemotePort,
+                         const UdpProxy     &aUdpProxy) override;
+
+    otbrError Ip6Send(const uint8_t *aData, uint16_t aLength) override;
+    otbrError Ip6MulAddrUpdateSubscription(const otIp6Address &aAddress, bool aIsAdded) override;
+    otbrError SetInfraIf(uint32_t                       aInfraIfIndex,
+                         bool                           aIsRunning,
+                         const std::vector<Ip6Address> &aIp6Addresses) override;
+    otbrError HandleIcmp6Nd(uint32_t          aInfraIfIndex,
+                            const Ip6Address &aIp6Address,
+                            const uint8_t    *aData,
+                            uint16_t          aDataLen) override;
 
     ot::Spinel::SpinelDriver &mSpinelDriver;
     otPlatformConfig          mConfig;
     NcpSpinel                 mNcpSpinel;
     TaskRunner                mTaskRunner;
-    Netif                     mNetif;
-    InfraIf                   mInfraIf;
+    CliDaemon                 mCliDaemon;
 };
 
 } // namespace Host
diff --git a/src/host/ncp_spinel.cpp b/src/host/ncp_spinel.cpp
index 13ff2107..95a463da 100644
--- a/src/host/ncp_spinel.cpp
+++ b/src/host/ncp_spinel.cpp
@@ -34,6 +34,7 @@
 
 #include <algorithm>
 
+#include <openthread/backbone_router_ftd.h>
 #include <openthread/dataset.h>
 #include <openthread/thread.h>
 #include <openthread/platform/dnssd.h>
@@ -84,6 +85,7 @@ void NcpSpinel::Deinit(void)
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
     mPublisher = nullptr;
 #endif
+    mUdpForwardSendCallback = nullptr;
 }
 
 otbrError NcpSpinel::SpinelDataUnpack(const uint8_t *aDataIn, spinel_size_t aDataLen, const char *aPackFormat, ...)
@@ -173,6 +175,17 @@ exit:
     return error;
 }
 
+otbrError NcpSpinel::InputCommandLine(const char *aLine)
+{
+    otbrError    error        = OTBR_ERROR_NONE;
+    EncodingFunc encodingFunc = [aLine](ot::Spinel::Encoder &aEncoder) { return aEncoder.WriteUtf8(aLine); };
+
+    SuccessOrExit(SetProperty(SPINEL_PROP_STREAM_CLI, encodingFunc), error = OTBR_ERROR_OPENTHREAD);
+
+exit:
+    return error;
+}
+
 void NcpSpinel::ThreadSetEnabled(bool aEnable, AsyncTaskPtr aAsyncTask)
 {
     otError      error        = OT_ERROR_NONE;
@@ -271,6 +284,14 @@ void NcpSpinel::DnssdSetState(Mdns::Publisher::State aState)
 }
 #endif // OTBR_ENABLE_SRP_ADVERTISING_PROXY
 
+void NcpSpinel::SetBorderAgentMeshCoPServiceChangedCallback(const BorderAgentMeshCoPServiceChangedCallback &aCallback)
+{
+    mBorderAgentMeshCoPServiceChangedCallback = aCallback;
+
+    // Get the MeshCoP service state to have an initial value.
+    SuccessOrDie(GetProperty(SPINEL_PROP_BORDER_AGENT_MESHCOP_SERVICE_STATE), "Failed to get MeshCoP Service State");
+}
+
 void NcpSpinel::HandleReceivedFrame(const uint8_t *aFrame,
                                     uint16_t       aLength,
                                     uint8_t        aHeader,
@@ -351,6 +372,11 @@ void NcpSpinel::HandleResponse(spinel_tid_t aTid, const uint8_t *aFrame, uint16_
 
     switch (mCmdTable[aTid])
     {
+    case SPINEL_CMD_PROP_VALUE_GET:
+    {
+        error = HandleResponseForPropGet(aTid, key, data, len);
+        break;
+    }
     case SPINEL_CMD_PROP_VALUE_SET:
     {
         error = HandleResponseForPropSet(aTid, key, data, len);
@@ -471,6 +497,19 @@ void NcpSpinel::HandleValueIs(spinel_prop_key_t aKey, const uint8_t *aBuffer, ui
     case SPINEL_PROP_IPV6_LL_ADDR:
         break;
 
+    case SPINEL_PROP_IPV6_ML_ADDR:
+    {
+        const otIp6Address *addr;
+        ot::Spinel::Decoder decoder;
+        otIp6NetworkPrefix  meshLocalPrefix;
+
+        decoder.Init(aBuffer, aLength);
+        SuccessOrExit(decoder.ReadIp6Address(addr), error = OTBR_ERROR_PARSE);
+        memcpy(meshLocalPrefix.m8, addr->mFields.m8, sizeof(meshLocalPrefix.m8));
+        mPropsObserver->SetMeshLocalPrefix(meshLocalPrefix);
+        break;
+    }
+
     case SPINEL_PROP_STREAM_NET:
     {
         const uint8_t *data;
@@ -481,6 +520,15 @@ void NcpSpinel::HandleValueIs(spinel_prop_key_t aKey, const uint8_t *aBuffer, ui
         break;
     }
 
+    case SPINEL_PROP_STREAM_CLI:
+    {
+        const char *output;
+
+        SuccessOrExit(ParseStreamCliOutput(aBuffer, aLength, output), error = OTBR_ERROR_PARSE);
+        SafeInvoke(mCliDaemonOutputCallback, output);
+        break;
+    }
+
     case SPINEL_PROP_INFRA_IF_SEND_ICMP6:
     {
         uint32_t            infraIfIndex;
@@ -494,6 +542,46 @@ void NcpSpinel::HandleValueIs(spinel_prop_key_t aKey, const uint8_t *aBuffer, ui
         break;
     }
 
+    case SPINEL_PROP_BACKBONE_ROUTER_STATE:
+    {
+        uint8_t backboneRouterState;
+
+        SuccessOrExit(error = SpinelDataUnpack(aBuffer, aLength, SPINEL_DATATYPE_UINT8_S, &backboneRouterState));
+        SafeInvoke(mBackboneRouterStateChangedCallback, static_cast<otBackboneRouterState>(backboneRouterState));
+        break;
+    }
+
+    case SPINEL_PROP_BORDER_AGENT_MESHCOP_SERVICE_STATE:
+    {
+        bool                isActive;
+        uint16_t            port;
+        const uint8_t      *data;
+        uint16_t            dataLen;
+        ot::Spinel::Decoder decoder;
+
+        decoder.Init(aBuffer, aLength);
+        SuccessOrExit(decoder.ReadBool(isActive), error = OTBR_ERROR_PARSE);
+        SuccessOrExit(decoder.ReadUint16(port), error = OTBR_ERROR_PARSE);
+        SuccessOrExit(decoder.ReadData(data, dataLen), error = OTBR_ERROR_PARSE);
+        SafeInvoke(mBorderAgentMeshCoPServiceChangedCallback, isActive, port, data, dataLen);
+        break;
+    }
+
+    case SPINEL_PROP_THREAD_UDP_FORWARD_STREAM:
+    {
+        const uint8_t      *udpPayload;
+        uint16_t            length;
+        const otIp6Address *peerAddress;
+        uint16_t            peerPort;
+        uint16_t            localPort;
+
+        SuccessOrExit(ParseUdpForwardStream(aBuffer, aLength, udpPayload, length, peerAddress, peerPort, localPort),
+                      error = OTBR_ERROR_PARSE);
+        SafeInvoke(mUdpForwardSendCallback, udpPayload, length, *peerAddress, peerPort);
+
+        break;
+    }
+
     default:
         otbrLogWarning("Received uncognized key: %u", aKey);
         break;
@@ -598,6 +686,15 @@ void NcpSpinel::HandleValueInserted(spinel_prop_key_t aKey, const uint8_t *aBuff
         break;
     }
 #endif // OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    case SPINEL_PROP_BACKBONE_ROUTER_MULTICAST_LISTENER:
+    {
+        const otIp6Address *addr;
+
+        VerifyOrExit(decoder.ReadIp6Address(addr) == OT_ERROR_NONE, error = OTBR_ERROR_PARSE);
+        SafeInvoke(mBackboneRouterMulticastListenerCallback, OT_BACKBONE_ROUTER_MULTICAST_LISTENER_ADDED,
+                   Ip6Address(*addr));
+        break;
+    }
     default:
         error = OTBR_ERROR_DROPPED;
         break;
@@ -672,6 +769,15 @@ void NcpSpinel::HandleValueRemoved(spinel_prop_key_t aKey, const uint8_t *aBuffe
         break;
     }
 #endif // OTBR_ENABLE_SRP_ADVERTISING_PROXY
+    case SPINEL_PROP_BACKBONE_ROUTER_MULTICAST_LISTENER:
+    {
+        const otIp6Address *addr;
+
+        VerifyOrExit(decoder.ReadIp6Address(addr) == OT_ERROR_NONE, error = OTBR_ERROR_PARSE);
+        SafeInvoke(mBackboneRouterMulticastListenerCallback, OT_BACKBONE_ROUTER_MULTICAST_LISTENER_REMOVED,
+                   Ip6Address(*addr));
+        break;
+    }
     default:
         error = OTBR_ERROR_DROPPED;
         break;
@@ -682,6 +788,41 @@ exit:
     return;
 }
 
+otbrError NcpSpinel::HandleResponseForPropGet(spinel_tid_t      aTid,
+                                              spinel_prop_key_t aKey,
+                                              const uint8_t    *aData,
+                                              uint16_t          aLength)
+{
+    otbrError error = OTBR_ERROR_NONE;
+
+    switch (mWaitingKeyTable[aTid])
+    {
+    case SPINEL_PROP_BORDER_AGENT_MESHCOP_SERVICE_STATE:
+    {
+        bool                isActive;
+        uint16_t            port;
+        const uint8_t      *data;
+        uint16_t            dataLen;
+        ot::Spinel::Decoder decoder;
+
+        decoder.Init(aData, aLength);
+        SuccessOrExit(decoder.ReadBool(isActive), error = OTBR_ERROR_PARSE);
+        SuccessOrExit(decoder.ReadUint16(port), error = OTBR_ERROR_PARSE);
+        SuccessOrExit(decoder.ReadData(data, dataLen), error = OTBR_ERROR_PARSE);
+
+        SafeInvoke(mBorderAgentMeshCoPServiceChangedCallback, isActive, port, data, dataLen);
+        break;
+    }
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
 otbrError NcpSpinel::HandleResponseForPropSet(spinel_tid_t      aTid,
                                               spinel_prop_key_t aKey,
                                               const uint8_t    *aData,
@@ -736,6 +877,9 @@ otbrError NcpSpinel::HandleResponseForPropSet(spinel_tid_t      aTid,
     case SPINEL_PROP_STREAM_NET:
         break;
 
+    case SPINEL_PROP_STREAM_CLI:
+        break;
+
     case SPINEL_PROP_INFRA_IF_STATE:
         VerifyOrExit(aKey == SPINEL_PROP_LAST_STATUS, error = OTBR_ERROR_INVALID_STATE);
         SuccessOrExit(error = SpinelDataUnpack(aData, aLength, SPINEL_DATATYPE_UINT_PACKED_S, &status));
@@ -905,6 +1049,14 @@ exit:
     return error;
 }
 
+otError NcpSpinel::GetProperty(spinel_prop_key_t aKey)
+{
+    return SendCommand(SPINEL_CMD_PROP_VALUE_GET, aKey, [](ot::Spinel::Encoder &aEncoder) {
+        OTBR_UNUSED_VARIABLE(aEncoder);
+        return OT_ERROR_NONE;
+    });
+}
+
 otError NcpSpinel::SetProperty(spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc)
 {
     return SendCommand(SPINEL_CMD_PROP_VALUE_SET, aKey, aEncodingFunc);
@@ -1009,6 +1161,20 @@ exit:
     return error;
 }
 
+otError NcpSpinel::ParseStreamCliOutput(const uint8_t *aBuf, uint16_t aLen, const char *&aOutput)
+{
+    otError             error = OT_ERROR_NONE;
+    ot::Spinel::Decoder decoder;
+
+    VerifyOrExit(aBuf != nullptr, error = OT_ERROR_INVALID_ARGS);
+
+    decoder.Init(aBuf, aLen);
+    error = decoder.ReadUtf8(aOutput);
+
+exit:
+    return error;
+}
+
 otError NcpSpinel::ParseOperationalDatasetTlvs(const uint8_t            *aBuf,
                                                uint16_t                  aLen,
                                                otOperationalDatasetTlvs &aDatasetTlvs)
@@ -1050,6 +1216,28 @@ exit:
     return error;
 }
 
+otError NcpSpinel::ParseUdpForwardStream(const uint8_t       *aBuf,
+                                         uint16_t             aLen,
+                                         const uint8_t      *&aUdpPayload,
+                                         uint16_t            &aUdpPayloadLen,
+                                         const otIp6Address *&aPeerAddr,
+                                         uint16_t            &aPeerPort,
+                                         uint16_t            &aLocalPort)
+{
+    otError             error = OT_ERROR_NONE;
+    ot::Spinel::Decoder decoder;
+
+    VerifyOrExit(aBuf != nullptr, error = OT_ERROR_INVALID_ARGS);
+    decoder.Init(aBuf, aLen);
+    SuccessOrExit(error = decoder.ReadDataWithLen(aUdpPayload, aUdpPayloadLen));
+    SuccessOrExit(error = decoder.ReadUint16(aPeerPort));
+    SuccessOrExit(error = decoder.ReadIp6Address(aPeerAddr));
+    SuccessOrExit(error = decoder.ReadUint16(aLocalPort));
+
+exit:
+    return error;
+}
+
 otError NcpSpinel::SendDnssdResult(otPlatDnssdRequestId        aRequestId,
                                    const std::vector<uint8_t> &aCallbackData,
                                    otError                     aError)
@@ -1122,6 +1310,48 @@ exit:
     return error;
 }
 
+otbrError NcpSpinel::UdpForward(const uint8_t      *aUdpPayload,
+                                uint16_t            aLength,
+                                const otIp6Address &aRemoteAddr,
+                                uint16_t            aRemotePort,
+                                uint16_t            aLocalPort)
+{
+    otbrError    error        = OTBR_ERROR_NONE;
+    EncodingFunc encodingFunc = [aUdpPayload, aLength, &aRemoteAddr, aRemotePort,
+                                 aLocalPort](ot::Spinel::Encoder &aEncoder) {
+        otError error = OT_ERROR_NONE;
+
+        SuccessOrExit(error = aEncoder.WriteDataWithLen(aUdpPayload, aLength));
+        SuccessOrExit(error = aEncoder.WriteUint16(aRemotePort));
+        SuccessOrExit(error = aEncoder.WriteIp6Address(aRemoteAddr));
+        SuccessOrExit(error = aEncoder.WriteUint16(aLocalPort));
+
+    exit:
+        return error;
+    };
+
+    SuccessOrExit(SetProperty(SPINEL_PROP_THREAD_UDP_FORWARD_STREAM, encodingFunc), error = OTBR_ERROR_OPENTHREAD);
+
+exit:
+    if (error != OTBR_ERROR_NONE)
+    {
+        otbrLogWarning("Failed to do UDP forwarding to NCP, %s", otbrErrorString(error));
+    }
+    return error;
+}
+
+void NcpSpinel::SetBackboneRouterEnabled(bool aEnabled)
+{
+    otError      error;
+    EncodingFunc encodingFunc = [aEnabled](ot::Spinel::Encoder &aEncoder) { return aEncoder.WriteBool(aEnabled); };
+
+    error = SetProperty(SPINEL_PROP_BACKBONE_ROUTER_ENABLE, encodingFunc);
+    if (error != OT_ERROR_NONE)
+    {
+        otbrLogWarning("Failed to call BackboneRouterSetEnabled, %s", otThreadErrorToString(error));
+    }
+}
+
 otDeviceRole NcpSpinel::SpinelRoleToDeviceRole(spinel_net_role_t aRole)
 {
     otDeviceRole role = OT_DEVICE_ROLE_DISABLED;
diff --git a/src/host/ncp_spinel.hpp b/src/host/ncp_spinel.hpp
index 02f454bb..5c6f20d9 100644
--- a/src/host/ncp_spinel.hpp
+++ b/src/host/ncp_spinel.hpp
@@ -39,6 +39,7 @@
 
 #include <vector>
 
+#include <openthread/backbone_router_ftd.h>
 #include <openthread/dataset.h>
 #include <openthread/error.h>
 #include <openthread/link.h>
@@ -53,6 +54,7 @@
 #include "common/task_runner.hpp"
 #include "common/types.hpp"
 #include "host/async_task.hpp"
+#include "host/posix/cli_daemon.hpp"
 #include "host/posix/infra_if.hpp"
 #include "host/posix/netif.hpp"
 #include "mdns/mdns.hpp"
@@ -80,6 +82,13 @@ public:
      */
     virtual void SetDatasetActiveTlvs(const otOperationalDatasetTlvs &aActiveOpDatasetTlvs) = 0;
 
+    /**
+     * Updates the mesh local prefix.
+     *
+     * @param[in] aMeshLocalPrefix  The mesh local prefix.
+     */
+    virtual void SetMeshLocalPrefix(const otIp6NetworkPrefix &aMeshLocalPrefix) = 0;
+
     /**
      * The destructor.
      */
@@ -89,7 +98,7 @@ public:
 /**
  * The class provides methods for controlling the Thread stack on the network co-processor (NCP).
  */
-class NcpSpinel : public Netif::Dependencies, public InfraIf::Dependencies
+class NcpSpinel : public CliDaemon::Dependencies
 {
 public:
     using Ip6AddressTableCallback          = std::function<void(const std::vector<Ip6AddressInfo> &)>;
@@ -97,6 +106,12 @@ public:
     using NetifStateChangedCallback        = std::function<void(bool)>;
     using Ip6ReceiveCallback               = std::function<void(const uint8_t *, uint16_t)>;
     using InfraIfSendIcmp6NdCallback = std::function<void(uint32_t, const otIp6Address &, const uint8_t *, uint16_t)>;
+    using BorderAgentMeshCoPServiceChangedCallback = std::function<void(bool, uint16_t, const uint8_t *, uint16_t)>;
+    using CliDaemonOutputCallback                  = std::function<void(const char *)>;
+    using UdpForwardSendCallback = std::function<void(const uint8_t *, uint16_t, const otIp6Address &, uint16_t)>;
+    using BackboneRouterMulticastListenerCallback =
+        std::function<void(otBackboneRouterMulticastListenerEvent, Ip6Address)>;
+    using BackboneRouterStateChangedCallback = std::function<void(otBackboneRouterState)>;
 
     /**
      * Constructor.
@@ -188,7 +203,7 @@ public:
     void Ip6SetReceiveCallback(const Ip6ReceiveCallback &aCallback) { mIp6ReceiveCallback = aCallback; }
 
     /**
-     * This methods sends an IP6 datagram through the NCP.
+     * This method sends an IP6 datagram through the NCP.
      *
      * @param[in] aData      A pointer to the beginning of the IP6 datagram.
      * @param[in] aLength    The length of the datagram.
@@ -196,7 +211,53 @@ public:
      * @retval OTBR_ERROR_NONE  The datagram is sent to NCP successfully.
      * @retval OTBR_ERROR_BUSY  NcpSpinel is busy with other requests.
      */
-    otbrError Ip6Send(const uint8_t *aData, uint16_t aLength) override;
+    otbrError Ip6Send(const uint8_t *aData, uint16_t aLength);
+
+    /**
+     * This method updates the multicast address subscription on NCP.
+     *
+     * @param[in] aAddress  A reference to the multicast address to update subscription.
+     * @param[in] aIsAdded  `true` to subscribe and `false` to unsubscribe.
+     */
+    otbrError Ip6MulAddrUpdateSubscription(const otIp6Address &aAddress, bool aIsAdded);
+
+    /**
+     * This method sends a CLI command line to the NCP.
+     *
+     * @param[in] aLine  The string of the command line to be input.
+     *
+     * @retval OTBR_ERROR_NONE  The datagram is sent to NCP successfully.
+     * @retval OTBR_ERROR_BUSY  NcpSpinel is busy with other requests.
+     */
+    otbrError InputCommandLine(const char *aLine) override;
+
+    /**
+     * This method sets the infrastructure link interface information on NCP.
+     *
+     * @param[in] aInfraIfIndex  The index of the infrastructure link interface.
+     * @param[in] aIsRunning     Whether the infrastructure link is running.
+     * @param[in] aIp6Addresses  The IPv6 addresses on of the infrastructure link interface.
+     *
+     * @retval OTBR_ERROR_NONE  The infrastructure link interface is set successfully.
+     * @retval OTBR_ERROR_OPENTHREAD  Failed to encode the spinel message.
+     */
+    otbrError SetInfraIf(uint32_t aInfraIfIndex, bool aIsRunning, const std::vector<Ip6Address> &aIp6Addresses);
+
+    /**
+     * This method passes the recevied ICMPv6 ND message to the NCP.
+     *
+     * @param[in] aInfraIfIndex  The index of the infrastructure link interface.
+     * @param[in] aIp6Address    The source IPv6 address of the received ICMPv6 message.
+     * @param[in] aData          The data payload of the received ICMPv6 message.
+     * @param[in] aDatalen       The length of the data payload.
+     *
+     * @retval OTBR_ERROR_NONE  The infrastructure link interface is set successfully.
+     * @retval OTBR_ERROR_OPENTHREAD  Failed to encode the spinel message.
+     */
+    otbrError HandleIcmp6Nd(uint32_t          aInfraIfIndex,
+                            const Ip6Address &aIp6Address,
+                            const uint8_t    *aData,
+                            uint16_t          aDataLen);
 
     /**
      * This method enableds/disables the Thread network on the NCP.
@@ -249,6 +310,13 @@ public:
         mInfraIfIcmp6NdCallback = aCallback;
     }
 
+    /**
+     * This method sets the function to receive the CLI output from the NCP.
+     *
+     * @param[in] aCallback  The callback to receive the CLI output from the NCP.
+     */
+    void CliDaemonSetOutputCallback(const CliDaemonOutputCallback &aCallback) { mCliDaemonOutputCallback = aCallback; }
+
 #if OTBR_ENABLE_SRP_ADVERTISING_PROXY
     /**
      * This method enables/disables the SRP Server on NCP.
@@ -282,6 +350,66 @@ public:
     }
 #endif // OTBR_ENABLE_SRP_ADVERTISING_PROXY
 
+    /**
+     * This method sets a callback that will be invoked when there are any changes on the MeshCoP service from
+     * Thread core.
+     *
+     * @param[in] aCallback  The callback function.
+     */
+    void SetBorderAgentMeshCoPServiceChangedCallback(const BorderAgentMeshCoPServiceChangedCallback &aCallback);
+
+    /**
+     * This method forwards a UDP packet to the NCP.
+     *
+     * @param[in] aUdpPayload    The UDP payload.
+     * @param[in] aLength        The length of the UDP payload.
+     * @param[in] aRemoteAddr    The IPv6 address of the remote side.
+     * @param[in] aRemotePort    The UDP port of the remote side.
+     * @param[in] aLocalPort     The UDP port of the local side (in NCP).
+     */
+    otbrError UdpForward(const uint8_t      *aUdpPayload,
+                         uint16_t            aLength,
+                         const otIp6Address &aRemoteAddr,
+                         uint16_t            aRemotePort,
+                         uint16_t            aLocalPort);
+
+    /**
+     * This method sets a callback to send UDP packet received from the NCP side to the remote side.
+     *
+     * @param[in] aCallback    The callback to send the UDP packet to the remote side.
+     */
+    void SetUdpForwardSendCallback(UdpForwardSendCallback aCallback)
+    {
+        mUdpForwardSendCallback = aCallback;
+    }
+
+    /**
+     * This method enables/disables the Backbone Router.
+     *
+     * @param[in] aEnabled  Whether to enable or disable the Backbone router.
+     */
+    void SetBackboneRouterEnabled(bool aEnabled);
+
+    /**
+     * This method sets the Backbone Router Multicast Listener callback.
+     *
+     * @param[in] aCallback  The Multicast Listener callback.
+     */
+    void SetBackboneRouterStateChangedCallback(const BackboneRouterStateChangedCallback &aCallback)
+    {
+        mBackboneRouterStateChangedCallback = aCallback;
+    }
+
+    /**
+     * This method sets the Backbone Router state change callback.
+     *
+     * @param[in] aCallback  The Backbone Router state change callback.
+     */
+    void SetBackboneRouterMulticastListenerCallback(const BackboneRouterMulticastListenerCallback &aCallback)
+    {
+        mBackboneRouterMulticastListenerCallback = aCallback;
+    }
+
 private:
     using FailureHandler = std::function<void(otError)>;
 
@@ -323,6 +451,10 @@ private:
     void      HandleValueIs(spinel_prop_key_t aKey, const uint8_t *aBuffer, uint16_t aLength);
     void      HandleValueInserted(spinel_prop_key_t aKey, const uint8_t *aBuffer, uint16_t aLength);
     void      HandleValueRemoved(spinel_prop_key_t aKey, const uint8_t *aBuffer, uint16_t aLength);
+    otbrError HandleResponseForPropGet(spinel_tid_t      aTid,
+                                       spinel_prop_key_t aKey,
+                                       const uint8_t    *aData,
+                                       uint16_t          aLength);
     otbrError HandleResponseForPropSet(spinel_tid_t      aTid,
                                        spinel_prop_key_t aKey,
                                        const uint8_t    *aData,
@@ -338,13 +470,12 @@ private:
                                           const uint8_t    *aData,
                                           uint16_t          aLength);
 
-    otbrError Ip6MulAddrUpdateSubscription(const otIp6Address &aAddress, bool aIsAdded) override;
-
     spinel_tid_t GetNextTid(void);
     void         FreeTidTableItem(spinel_tid_t aTid);
 
     using EncodingFunc = std::function<otError(ot::Spinel::Encoder &aEncoder)>;
     otError SendCommand(spinel_command_t aCmd, spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc);
+    otError GetProperty(spinel_prop_key_t aKey);
     otError SetProperty(spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc);
     otError InsertProperty(spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc);
     otError RemoveProperty(spinel_prop_key_t aKey, const EncodingFunc &aEncodingFunc);
@@ -354,6 +485,7 @@ private:
     otError ParseIp6AddressTable(const uint8_t *aBuf, uint16_t aLength, std::vector<Ip6AddressInfo> &aAddressTable);
     otError ParseIp6MulticastAddresses(const uint8_t *aBuf, uint16_t aLen, std::vector<Ip6Address> &aAddressList);
     otError ParseIp6StreamNet(const uint8_t *aBuf, uint16_t aLen, const uint8_t *&aData, uint16_t &aDataLen);
+    otError ParseStreamCliOutput(const uint8_t *aBuf, uint16_t aLen, const char *&aOutput);
     otError ParseOperationalDatasetTlvs(const uint8_t *aBuf, uint16_t aLen, otOperationalDatasetTlvs &aDatasetTlvs);
     otError ParseInfraIfIcmp6Nd(const uint8_t       *aBuf,
                                 uint8_t              aLen,
@@ -361,16 +493,15 @@ private:
                                 const otIp6Address *&aAddr,
                                 const uint8_t      *&aData,
                                 uint16_t            &aDataLen);
+    otError ParseUdpForwardStream(const uint8_t       *aBuf,
+                                  uint16_t             aLen,
+                                  const uint8_t      *&aUdpPayload,
+                                  uint16_t            &aUdpPayloadLen,
+                                  const otIp6Address *&aPeerAddr,
+                                  uint16_t            &aPeerPort,
+                                  uint16_t            &aLocalPort);
     otError SendDnssdResult(otPlatDnssdRequestId aRequestId, const std::vector<uint8_t> &aCallbackData, otError aError);
 
-    otbrError SetInfraIf(uint32_t                       aInfraIfIndex,
-                         bool                           aIsRunning,
-                         const std::vector<Ip6Address> &aIp6Addresses) override;
-    otbrError HandleIcmp6Nd(uint32_t          aInfraIfIndex,
-                            const Ip6Address &aIp6Address,
-                            const uint8_t    *aData,
-                            uint16_t          aDataLen) override;
-
     ot::Spinel::SpinelDriver *mSpinelDriver;
     uint16_t                  mCmdTidsInUse; ///< Used transaction ids.
     spinel_tid_t              mCmdNextTid;   ///< Next available transaction id.
@@ -399,11 +530,16 @@ private:
     AsyncTaskPtr mThreadDetachGracefullyTask;
     AsyncTaskPtr mThreadErasePersistentInfoTask;
 
-    Ip6AddressTableCallback          mIp6AddressTableCallback;
-    Ip6MulticastAddressTableCallback mIp6MulticastAddressTableCallback;
-    Ip6ReceiveCallback               mIp6ReceiveCallback;
-    NetifStateChangedCallback        mNetifStateChangedCallback;
-    InfraIfSendIcmp6NdCallback       mInfraIfIcmp6NdCallback;
+    Ip6AddressTableCallback                  mIp6AddressTableCallback;
+    Ip6MulticastAddressTableCallback         mIp6MulticastAddressTableCallback;
+    Ip6ReceiveCallback                       mIp6ReceiveCallback;
+    NetifStateChangedCallback                mNetifStateChangedCallback;
+    InfraIfSendIcmp6NdCallback               mInfraIfIcmp6NdCallback;
+    BorderAgentMeshCoPServiceChangedCallback mBorderAgentMeshCoPServiceChangedCallback;
+    CliDaemonOutputCallback                  mCliDaemonOutputCallback;
+    UdpForwardSendCallback                   mUdpForwardSendCallback;
+    BackboneRouterStateChangedCallback       mBackboneRouterStateChangedCallback;
+    BackboneRouterMulticastListenerCallback  mBackboneRouterMulticastListenerCallback;
 };
 
 } // namespace Host
diff --git a/src/host/posix/CMakeLists.txt b/src/host/posix/CMakeLists.txt
index 8b6d41fb..e7b31876 100644
--- a/src/host/posix/CMakeLists.txt
+++ b/src/host/posix/CMakeLists.txt
@@ -32,10 +32,14 @@ add_library(otbr-posix
     dnssd.cpp
     infra_if.hpp
     infra_if.cpp
+    multicast_routing_manager.hpp
+    multicast_routing_manager.cpp
     netif.cpp
     netif_linux.cpp
     netif_unix.cpp
     netif.hpp
+    udp_proxy.cpp
+    udp_proxy.hpp
 )
 
 target_link_libraries(otbr-posix
diff --git a/src/host/posix/cli_daemon.cpp b/src/host/posix/cli_daemon.cpp
index 1c2e6bdc..c8169c82 100644
--- a/src/host/posix/cli_daemon.cpp
+++ b/src/host/posix/cli_daemon.cpp
@@ -41,73 +41,245 @@
 #include <sys/un.h>
 #include <unistd.h>
 
-#include <openthread/cli.h>
-
 #include "utils/socket_utils.hpp"
 
 namespace otbr {
 
+otbrError CliDaemon::Dependencies::InputCommandLine(const char *aLine)
+{
+    OTBR_UNUSED_VARIABLE(aLine);
+
+    return OTBR_ERROR_NONE;
+}
+
 static constexpr char kDefaultNetIfName[] = "wpan0";
 static constexpr char kSocketBaseName[]   = "/run/openthread-";
 static constexpr char kSocketSuffix[]     = ".sock";
 static constexpr char kSocketLockSuffix[] = ".lock";
+static constexpr char kTruncatedMsg[]     = "(truncated ...)";
 
 static constexpr size_t kMaxSocketFilenameLength = sizeof(sockaddr_un::sun_path) - 1;
 
-std::string CliDaemon::GetSocketFilename(const char *aSuffix) const
+std::string CliDaemon::GetSocketFilename(const std::string &aNetIfName, const char *aSuffix) const
 {
-    std::string fileName;
-    std::string netIfName = mNetifName.empty() ? kDefaultNetIfName : mNetifName;
+    std::string netIfName = aNetIfName.empty() ? kDefaultNetIfName : aNetIfName;
+
+    std::string fileName = kSocketBaseName + netIfName + aSuffix;
 
-    fileName = kSocketBaseName + netIfName + aSuffix;
     VerifyOrDie(fileName.size() <= kMaxSocketFilenameLength, otbrErrorString(OTBR_ERROR_INVALID_ARGS));
 
     return fileName;
 }
 
-CliDaemon::CliDaemon(void)
+void CliDaemon::HandleCommandOutput(const char *aOutput)
+{
+    int    ret;
+    char   buf[kCliMaxLineLength];
+    size_t length = strlen(aOutput);
+
+    VerifyOrExit(mSessionSocket != -1);
+
+    static_assert(sizeof(kTruncatedMsg) < kCliMaxLineLength, "OTBR_CONFIG_CLI_MAX_LINE_LENGTH is too short!");
+
+    strncpy(buf, aOutput, kCliMaxLineLength);
+
+    if (length >= kCliMaxLineLength)
+    {
+        length = kCliMaxLineLength - 1;
+        memcpy(buf + kCliMaxLineLength - sizeof(kTruncatedMsg), kTruncatedMsg, sizeof(kTruncatedMsg));
+    }
+
+#ifdef __linux__
+    // MSG_NOSIGNAL prevents read() from sending a SIGPIPE in the case of a broken pipe.
+    ret = send(mSessionSocket, buf, length, MSG_NOSIGNAL);
+#else
+    ret = static_cast<int>(write(mSessionSocket, buf, length));
+#endif
+
+    if (ret < 0)
+    {
+        otbrLogWarning("Failed to write CLI output: %s", strerror(errno));
+        Clear();
+    }
+
+exit:
+    return;
+}
+
+CliDaemon::CliDaemon(Dependencies &aDependencies)
     : mListenSocket(-1)
     , mDaemonLock(-1)
+    , mSessionSocket(-1)
+    , mDeps(aDependencies)
 {
 }
 
-void CliDaemon::CreateListenSocketOrDie(void)
+otbrError CliDaemon::CreateListenSocket(const std::string &aNetIfName)
 {
+    otbrError error = OTBR_ERROR_NONE;
+
+    std::string        lockFile;
+    std::string        socketFile;
     struct sockaddr_un sockname;
 
     mListenSocket = SocketWithCloseExec(AF_UNIX, SOCK_STREAM, 0, kSocketNonBlock);
-    VerifyOrDie(mListenSocket != -1, strerror(errno));
+    VerifyOrExit(mListenSocket != -1, error = OTBR_ERROR_ERRNO);
 
-    std::string lockfile = GetSocketFilename(kSocketLockSuffix);
-    mDaemonLock          = open(lockfile.c_str(), O_CREAT | O_RDONLY | O_CLOEXEC, 0600);
-    VerifyOrDie(mDaemonLock != -1, strerror(errno));
+    lockFile    = GetSocketFilename(aNetIfName, kSocketLockSuffix);
+    mDaemonLock = open(lockFile.c_str(), O_CREAT | O_RDONLY | O_CLOEXEC, 0600);
+    VerifyOrExit(mDaemonLock != -1, error = OTBR_ERROR_ERRNO);
 
-    VerifyOrDie(flock(mDaemonLock, LOCK_EX | LOCK_NB) != -1, strerror(errno));
+    VerifyOrExit(flock(mDaemonLock, LOCK_EX | LOCK_NB) != -1, error = OTBR_ERROR_ERRNO);
 
-    std::string socketfile = GetSocketFilename(kSocketSuffix);
-    memset(&sockname, 0, sizeof(struct sockaddr_un));
+    socketFile = GetSocketFilename(aNetIfName, kSocketSuffix);
 
+    memset(&sockname, 0, sizeof(struct sockaddr_un));
     sockname.sun_family = AF_UNIX;
-    strncpy(sockname.sun_path, socketfile.c_str(), sizeof(sockname.sun_path) - 1);
+    strncpy(sockname.sun_path, socketFile.c_str(), sizeof(sockname.sun_path) - 1);
     OTBR_UNUSED_VARIABLE(unlink(sockname.sun_path));
 
-    VerifyOrDie(bind(mListenSocket, reinterpret_cast<const struct sockaddr *>(&sockname), sizeof(struct sockaddr_un)) !=
-                    -1,
-                strerror(errno));
+    VerifyOrExit(
+        bind(mListenSocket, reinterpret_cast<const struct sockaddr *>(&sockname), sizeof(struct sockaddr_un)) != -1,
+        error = OTBR_ERROR_ERRNO);
+
+exit:
+    return error;
+}
+
+void CliDaemon::InitializeSessionSocket(void)
+{
+    int newSessionSocket = -1;
+    int flag             = -1;
+
+    // The `accept()` call uses `nullptr` for `addr` and `addrlen` arguments as we don't need the client address
+    // information.
+    VerifyOrExit((newSessionSocket = accept(mListenSocket, nullptr, nullptr)) != -1);
+    VerifyOrExit((flag = fcntl(newSessionSocket, F_GETFD, 0)) != -1, close(newSessionSocket));
+
+    flag |= FD_CLOEXEC;
+    VerifyOrExit((flag = fcntl(newSessionSocket, F_SETFD, flag)) != -1, close(newSessionSocket));
+
+#ifndef __linux__
+    // some platforms (macOS, Solaris) don't have MSG_NOSIGNAL
+    // SOME of those (macOS, but NOT Solaris) support SO_NOSIGPIPE
+    // if we have SO_NOSIGPIPE, then set it. Otherwise, we're going
+    // to simply ignore it.
+#if defined(SO_NOSIGPIPE)
+    VerifyOrExit((flag = setsockopt(newSessionSocket, SOL_SOCKET, SO_NOSIGPIPE, &flag, sizeof(flag))) != -1,
+                 close(newSessionSocket));
+#else
+#warning "no support for MSG_NOSIGNAL or SO_NOSIGPIPE"
+#endif
+#endif // __linux__
+
+    Clear();
+
+    mSessionSocket = newSessionSocket;
+    otbrLogInfo("Session socket is ready");
+
+exit:
+    if (flag == -1)
+    {
+        otbrLogWarning("Failed to initialize session socket: %s", strerror(errno));
+        Clear();
+    }
 }
 
-void CliDaemon::Init(const std::string &aNetIfName)
+otbrError CliDaemon::Init(const std::string &aNetIfName)
 {
+    otbrError error = OTBR_ERROR_NONE;
+
     // This allows implementing pseudo reset.
-    VerifyOrExit(mListenSocket == -1);
+    VerifyOrExit(mListenSocket == -1, error = OTBR_ERROR_INVALID_STATE);
 
-    mNetifName = aNetIfName;
-    CreateListenSocketOrDie();
+    SuccessOrExit(error = CreateListenSocket(aNetIfName));
 
     //
     // only accept 1 connection.
     //
-    VerifyOrDie(listen(mListenSocket, 1) != -1, strerror(errno));
+    VerifyOrExit(listen(mListenSocket, 1) != -1, error = OTBR_ERROR_ERRNO);
+
+exit:
+    return error;
+}
+
+void CliDaemon::Clear(void)
+{
+    if (mSessionSocket != -1)
+    {
+        close(mSessionSocket);
+        mSessionSocket = -1;
+    }
+}
+
+void CliDaemon::Deinit(void)
+{
+    Clear();
+}
+
+void CliDaemon::UpdateFdSet(MainloopContext &aContext)
+{
+    if (mListenSocket != -1)
+    {
+        aContext.AddFdToSet(mListenSocket, MainloopContext::kErrorFdSet | MainloopContext::kReadFdSet);
+    }
+
+    if (mSessionSocket != -1)
+    {
+        aContext.AddFdToSet(mSessionSocket, MainloopContext::kErrorFdSet | MainloopContext::kReadFdSet);
+    }
+}
+
+void CliDaemon::Process(const MainloopContext &aContext)
+{
+    VerifyOrExit(mListenSocket != -1);
+
+    if (FD_ISSET(mListenSocket, &aContext.mErrorFdSet))
+    {
+        DieNow("daemon socket error");
+    }
+
+    if (FD_ISSET(mListenSocket, &aContext.mReadFdSet))
+    {
+        InitializeSessionSocket();
+    }
+
+    VerifyOrExit(mSessionSocket != -1);
+
+    if (FD_ISSET(mSessionSocket, &aContext.mErrorFdSet))
+    {
+        Clear();
+    }
+    else if (FD_ISSET(mSessionSocket, &aContext.mReadFdSet))
+    {
+        uint8_t   buffer[kCliMaxLineLength];
+        otbrError error = OTBR_ERROR_NONE;
+        ssize_t   received;
+
+        // leave 1 byte for the null terminator
+        received = read(mSessionSocket, buffer, sizeof(buffer) - 1);
+
+        if (received > 0)
+        {
+            buffer[received] = '\0';
+            error            = mDeps.InputCommandLine(reinterpret_cast<char *>(buffer));
+
+            if (error != OTBR_ERROR_NONE)
+            {
+                otbrLogWarning("Failed to input command line, error:%s", otbrErrorString(error));
+            }
+        }
+        else if (received == 0)
+        {
+            otbrLogInfo("Session socket closed by peer");
+            Clear();
+        }
+        else
+        {
+            otbrLogWarning("CLI Daemon read: %s", strerror(errno));
+            Clear();
+        }
+    }
 
 exit:
     return;
diff --git a/src/host/posix/cli_daemon.hpp b/src/host/posix/cli_daemon.hpp
index 3df99797..142bd332 100644
--- a/src/host/posix/cli_daemon.hpp
+++ b/src/host/posix/cli_daemon.hpp
@@ -44,19 +44,38 @@ namespace otbr {
 class CliDaemon
 {
 public:
-    CliDaemon(void);
+    class Dependencies
+    {
+    public:
+        virtual ~Dependencies(void) = default;
 
-    void Init(const std::string &aNetIfName);
+        virtual otbrError InputCommandLine(const char *aLine);
+    };
+
+    explicit CliDaemon(Dependencies &aDependencies);
+
+    otbrError Init(const std::string &aNetIfName);
+    void      Deinit(void);
+
+    void HandleCommandOutput(const char *aOutput);
+    void Process(const MainloopContext &aContext);
+    void UpdateFdSet(MainloopContext &aContext);
 
 private:
-    void CreateListenSocketOrDie(void);
+    static constexpr size_t kCliMaxLineLength = OTBR_CONFIG_CLI_MAX_LINE_LENGTH;
+
+    void Clear(void);
+
+    std::string GetSocketFilename(const std::string &aNetIfName, const char *aSuffix) const;
 
-    std::string GetSocketFilename(const char *aSuffix) const;
+    otbrError CreateListenSocket(const std::string &aNetIfName);
+    void      InitializeSessionSocket(void);
 
     int mListenSocket;
     int mDaemonLock;
+    int mSessionSocket;
 
-    std::string mNetifName;
+    Dependencies &mDeps;
 };
 
 } // namespace otbr
diff --git a/src/host/posix/dnssd.cpp b/src/host/posix/dnssd.cpp
index c70f516e..e3c4ee6a 100644
--- a/src/host/posix/dnssd.cpp
+++ b/src/host/posix/dnssd.cpp
@@ -35,6 +35,8 @@
 
 #include "host/posix/dnssd.hpp"
 
+#if OTBR_ENABLE_DNSSD_PLAT
+
 #include <string>
 
 #include <openthread/platform/dnssd.h>
@@ -181,6 +183,18 @@ void otPlatDnssdStopIp4AddressResolver(otInstance *aInstance, const otPlatDnssdA
     OTBR_UNUSED_VARIABLE(aResolver);
 }
 
+void otPlatDnssdStartRecordQuerier(otInstance *aInstance, const otPlatDnssdRecordQuerier *aQuerier)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+    OTBR_UNUSED_VARIABLE(aQuerier);
+}
+
+void otPlatDnssdStopRecordQuerier(otInstance *aInstance, const otPlatDnssdRecordQuerier *aQuerier)
+{
+    OTBR_UNUSED_VARIABLE(aInstance);
+    OTBR_UNUSED_VARIABLE(aQuerier);
+}
+
 //----------------------------------------------------------------------------------------------------------------------
 
 namespace otbr {
@@ -255,6 +269,7 @@ void DnssdPlatform::SetDnssdStateChangedCallback(DnssdStateChangeCallback aCallb
 
 void DnssdPlatform::RegisterService(const Service &aService, RequestId aRequestId, RegisterCallback aCallback)
 {
+    const char                  *hostName;
     Mdns::Publisher::SubTypeList subTypeList;
     Mdns::Publisher::TxtData     txtData(aService.mTxtData, aService.mTxtData + aService.mTxtDataLength);
 
@@ -263,8 +278,19 @@ void DnssdPlatform::RegisterService(const Service &aService, RequestId aRequestI
         subTypeList.push_back(aService.mSubTypeLabels[index]);
     }
 
-    mPublisher.PublishService(aService.mHostName, aService.mServiceInstance, aService.mServiceType, subTypeList,
-                              aService.mPort, txtData, MakePublisherCallback(aRequestId, aCallback));
+    // When `aService.mHostName` is `nullptr`, the service is for
+    // the local host. `Mdns::Publisher` expects an empty string
+    // to indicate this.
+
+    hostName = aService.mHostName;
+
+    if (hostName == nullptr)
+    {
+        hostName = "";
+    }
+
+    mPublisher.PublishService(hostName, aService.mServiceInstance, aService.mServiceType, subTypeList, aService.mPort,
+                              txtData, MakePublisherCallback(aRequestId, aCallback));
 }
 
 void DnssdPlatform::UnregisterService(const Service &aService, RequestId aRequestId, RegisterCallback aCallback)
@@ -326,3 +352,5 @@ void DnssdPlatform::HandleMdnsState(Mdns::Publisher::State aState)
 }
 
 } // namespace otbr
+
+#endif // OTBR_ENABLE_DNSSD_PLAT
diff --git a/src/host/posix/dnssd.hpp b/src/host/posix/dnssd.hpp
index 7a4a81b7..fa143093 100644
--- a/src/host/posix/dnssd.hpp
+++ b/src/host/posix/dnssd.hpp
@@ -36,6 +36,8 @@
 
 #include "openthread-br/config.h"
 
+#if OTBR_ENABLE_DNSSD_PLAT
+
 #include <functional>
 #include <string>
 
@@ -133,4 +135,6 @@ private:
 
 } // namespace otbr
 
+#endif // OTBR_ENABLE_DNSSD_PLAT
+
 #endif // OTBR_AGENT_POSIX_DNSSD_HPP_
diff --git a/src/host/posix/infra_if.cpp b/src/host/posix/infra_if.cpp
index 0f559f8a..1b0c3147 100644
--- a/src/host/posix/infra_if.cpp
+++ b/src/host/posix/infra_if.cpp
@@ -143,7 +143,7 @@ exit:
     return;
 }
 
-void InfraIf::UpdateFdSet(MainloopContext &aContext)
+void InfraIf::Update(MainloopContext &aContext)
 {
     VerifyOrExit(mInfraIfIcmp6Socket != -1);
 #ifdef __linux__
@@ -161,23 +161,23 @@ exit:
     return;
 }
 
-otbrError InfraIf::SetInfraIf(const char *aIfName)
+otbrError InfraIf::SetInfraIf(std::string aInfraIfName)
 {
     otbrError               error = OTBR_ERROR_NONE;
     std::vector<Ip6Address> addresses;
 
-    VerifyOrExit(aIfName != nullptr && strlen(aIfName) > 0, error = OTBR_ERROR_INVALID_ARGS);
-    VerifyOrExit(strnlen(aIfName, IFNAMSIZ) < IFNAMSIZ, error = OTBR_ERROR_INVALID_ARGS);
-    strcpy(mInfraIfName, aIfName);
+    VerifyOrExit(!aInfraIfName.empty(), error = OTBR_ERROR_INVALID_ARGS);
+    VerifyOrExit(aInfraIfName.size() < IFNAMSIZ, error = OTBR_ERROR_INVALID_ARGS);
+    mInfraIfName = std::move(aInfraIfName);
 
-    mInfraIfIndex = if_nametoindex(aIfName);
+    mInfraIfIndex = if_nametoindex(mInfraIfName.c_str());
     VerifyOrExit(mInfraIfIndex != 0, error = OTBR_ERROR_INVALID_STATE);
 
     if (mInfraIfIcmp6Socket != -1)
     {
         close(mInfraIfIcmp6Socket);
     }
-    mInfraIfIcmp6Socket = CreateIcmp6Socket(aIfName);
+    mInfraIfIcmp6Socket = CreateIcmp6Socket(mInfraIfName.c_str());
     VerifyOrDie(mInfraIfIcmp6Socket != -1, "Failed to create Icmp6 socket!");
 
     addresses = GetAddresses();
@@ -331,11 +331,11 @@ short InfraIf::GetFlags(void) const
     VerifyOrDie(sock != -1, otbrErrorString(OTBR_ERROR_ERRNO));
 
     memset(&ifReq, 0, sizeof(ifReq));
-    strcpy(ifReq.ifr_name, mInfraIfName);
+    strcpy(ifReq.ifr_name, mInfraIfName.c_str());
 
     if (ioctl(sock, SIOCGIFFLAGS, &ifReq) == -1)
     {
-        otbrLogCrit("The infra link %s may be lost. Exiting.", mInfraIfName);
+        otbrLogCrit("The infra link %s may be lost. Exiting.", mInfraIfName.c_str());
         DieNow(otbrErrorString(OTBR_ERROR_ERRNO));
     }
 
@@ -359,8 +359,7 @@ std::vector<Ip6Address> InfraIf::GetAddresses(void)
     {
         struct sockaddr_in6 *ip6Addr;
 
-        if (strncmp(addr->ifa_name, mInfraIfName, sizeof(mInfraIfName)) != 0 || addr->ifa_addr == nullptr ||
-            addr->ifa_addr->sa_family != AF_INET6)
+        if (mInfraIfName != addr->ifa_name || addr->ifa_addr == nullptr || addr->ifa_addr->sa_family != AF_INET6)
         {
             continue;
         }
diff --git a/src/host/posix/infra_if.hpp b/src/host/posix/infra_if.hpp
index 35163b7b..128b42f3 100644
--- a/src/host/posix/infra_if.hpp
+++ b/src/host/posix/infra_if.hpp
@@ -40,6 +40,7 @@
 
 #include <openthread/ip6.h>
 
+#include "common/code_utils.hpp"
 #include "common/mainloop.hpp"
 #include "common/types.hpp"
 
@@ -51,7 +52,7 @@ namespace otbr {
  * The infrastructure network interface MUST be explicitly set by `SetInfraIf` before the InfraIf module can work.
  *
  */
-class InfraIf
+class InfraIf : public MainloopProcessor, private NonCopyable
 {
 public:
     class Dependencies
@@ -72,14 +73,14 @@ public:
 
     void      Init(void);
     void      Deinit(void);
-    void      Process(const MainloopContext &aContext);
-    void      UpdateFdSet(MainloopContext &aContext);
-    otbrError SetInfraIf(const char *aIfName);
+    otbrError SetInfraIf(std::string aInfraIfName);
     otbrError SendIcmp6Nd(uint32_t            aInfraIfIndex,
                           const otIp6Address &aDestAddress,
                           const uint8_t      *aBuffer,
                           uint16_t            aBufferLength);
 
+    unsigned int GetIfIndex(void) const { return mInfraIfIndex; }
+
 private:
     static int              CreateIcmp6Socket(const char *aInfraIfName);
     bool                    IsRunning(const std::vector<Ip6Address> &aAddrs) const;
@@ -91,8 +92,11 @@ private:
     void ReceiveNetlinkMessage(void);
 #endif
 
+    void Process(const MainloopContext &aContext) override;
+    void Update(MainloopContext &aContext) override;
+
     Dependencies &mDeps;
-    char          mInfraIfName[IFNAMSIZ];
+    std::string   mInfraIfName;
     unsigned int  mInfraIfIndex;
 #ifdef __linux__
     int mNetlinkSocket;
diff --git a/src/host/posix/multicast_routing_manager.cpp b/src/host/posix/multicast_routing_manager.cpp
new file mode 100644
index 00000000..112f7164
--- /dev/null
+++ b/src/host/posix/multicast_routing_manager.cpp
@@ -0,0 +1,584 @@
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
+#include "multicast_routing_manager.hpp"
+
+#include <assert.h>
+#include <net/if.h>
+#include <netinet/icmp6.h>
+#include <netinet/in.h>
+#include <stdio.h>
+#include <sys/ioctl.h>
+#include <sys/socket.h>
+#include <sys/types.h>
+#include <unistd.h>
+#ifdef __linux__
+#include <linux/mroute6.h>
+#endif
+
+#include <openthread/ip6.h>
+
+#include "common/code_utils.hpp"
+#include "common/logging.hpp"
+#include "common/types.hpp"
+#include "utils/socket_utils.hpp"
+
+#ifdef __linux__
+#if OTBR_ENABLE_BACKBONE_ROUTER
+
+namespace otbr {
+
+MulticastRoutingManager::MulticastRoutingManager(const Netif                   &aNetif,
+                                                 const InfraIf                 &aInfraIf,
+                                                 const Host::NetworkProperties &aNetworkProperties)
+    : mNetif(aNetif)
+    , mInfraIf(aInfraIf)
+    , mNetworkProperties(aNetworkProperties)
+    , mLastExpireTime(otbr::Timepoint::min())
+    , mMulticastRouterSock(-1)
+{
+}
+
+void MulticastRoutingManager::HandleStateChange(otBackboneRouterState aState)
+{
+    otbrLogInfo("State Change:%u", aState);
+
+    switch (aState)
+    {
+    case OT_BACKBONE_ROUTER_STATE_DISABLED:
+    case OT_BACKBONE_ROUTER_STATE_SECONDARY:
+        Disable();
+        break;
+    case OT_BACKBONE_ROUTER_STATE_PRIMARY:
+        Enable();
+        break;
+    }
+}
+
+void MulticastRoutingManager::HandleBackboneMulticastListenerEvent(otBackboneRouterMulticastListenerEvent aEvent,
+                                                                   const Ip6Address                      &aAddress)
+{
+    switch (aEvent)
+    {
+    case OT_BACKBONE_ROUTER_MULTICAST_LISTENER_ADDED:
+        mMulticastListeners.insert(aAddress);
+        Add(aAddress);
+        break;
+    case OT_BACKBONE_ROUTER_MULTICAST_LISTENER_REMOVED:
+        mMulticastListeners.erase(aAddress);
+        Remove(aAddress);
+        break;
+    }
+}
+
+void MulticastRoutingManager::Update(MainloopContext &aContext)
+{
+    VerifyOrExit(IsEnabled());
+
+    aContext.AddFdToReadSet(mMulticastRouterSock);
+
+exit:
+    return;
+}
+
+void MulticastRoutingManager::Process(const MainloopContext &aContext)
+{
+    VerifyOrExit(IsEnabled());
+
+    ExpireMulticastForwardingCache();
+
+    if (FD_ISSET(mMulticastRouterSock, &aContext.mReadFdSet))
+    {
+        ProcessMulticastRouterMessages();
+    }
+
+exit:
+    return;
+}
+
+void MulticastRoutingManager::Enable(void)
+{
+    VerifyOrExit(!IsEnabled());
+    VerifyOrExit(mInfraIf.GetIfIndex() != 0); // Only enable the MulticastRoutingManager when the Infra If has been set.
+
+    InitMulticastRouterSock();
+
+    otbrLogResult(OTBR_ERROR_NONE, "%s", __FUNCTION__);
+
+exit:
+    return;
+}
+
+void MulticastRoutingManager::Disable(void)
+{
+    FinalizeMulticastRouterSock();
+
+    otbrLogResult(OTBR_ERROR_NONE, "%s", __FUNCTION__);
+}
+
+void MulticastRoutingManager::Add(const Ip6Address &aAddress)
+{
+    VerifyOrExit(IsEnabled());
+
+    UnblockInboundMulticastForwardingCache(aAddress);
+    UpdateMldReport(aAddress, true);
+
+    otbrLogResult(OTBR_ERROR_NONE, "%s: %s", __FUNCTION__, aAddress.ToString().c_str());
+
+exit:
+    return;
+}
+
+void MulticastRoutingManager::Remove(const Ip6Address &aAddress)
+{
+    VerifyOrExit(IsEnabled());
+
+    RemoveInboundMulticastForwardingCache(aAddress);
+    UpdateMldReport(aAddress, false);
+
+    otbrLogResult(OTBR_ERROR_NONE, "%s: %s", __FUNCTION__, aAddress.ToString().c_str());
+
+exit:
+    return;
+}
+
+void MulticastRoutingManager::UpdateMldReport(const Ip6Address &aAddress, bool isAdd)
+{
+    struct ipv6_mreq ipv6mr;
+    otbrError        error = OTBR_ERROR_NONE;
+
+    ipv6mr.ipv6mr_interface = mInfraIf.GetIfIndex();
+    aAddress.CopyTo(ipv6mr.ipv6mr_multiaddr);
+    if (setsockopt(mMulticastRouterSock, IPPROTO_IPV6, (isAdd ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP), (void *)&ipv6mr,
+                   sizeof(ipv6mr)) != 0)
+    {
+        error = OTBR_ERROR_ERRNO;
+    }
+
+    otbrLogResult(error, "%s: address %s %s", __FUNCTION__, aAddress.ToString().c_str(), (isAdd ? "Added" : "Removed"));
+}
+
+bool MulticastRoutingManager::HasMulticastListener(const Ip6Address &aAddress) const
+{
+    return mMulticastListeners.find(aAddress) != mMulticastListeners.end();
+}
+
+void MulticastRoutingManager::InitMulticastRouterSock(void)
+{
+    int                 one = 1;
+    struct icmp6_filter filter;
+    struct mif6ctl      mif6ctl;
+
+    // Create a Multicast Routing socket
+    mMulticastRouterSock = SocketWithCloseExec(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, kSocketBlock);
+    VerifyOrDie(mMulticastRouterSock != -1, "Failed to create socket");
+
+    // Enable Multicast Forwarding in Kernel
+    VerifyOrDie(0 == setsockopt(mMulticastRouterSock, IPPROTO_IPV6, MRT6_INIT, &one, sizeof(one)),
+                "Failed to enable multicast forwarding");
+
+    // Filter all ICMPv6 messages
+    ICMP6_FILTER_SETBLOCKALL(&filter);
+    VerifyOrDie(0 == setsockopt(mMulticastRouterSock, IPPROTO_ICMPV6, ICMP6_FILTER, (void *)&filter, sizeof(filter)),
+                "Failed to set filter");
+
+    memset(&mif6ctl, 0, sizeof(mif6ctl));
+    mif6ctl.mif6c_flags     = 0;
+    mif6ctl.vifc_threshold  = 1;
+    mif6ctl.vifc_rate_limit = 0;
+
+    // Add Thread network interface to MIF
+    mif6ctl.mif6c_mifi = kMifIndexThread;
+    mif6ctl.mif6c_pifi = mNetif.GetIfIndex();
+    VerifyOrDie(mif6ctl.mif6c_pifi > 0, "Thread interface index is invalid");
+    VerifyOrDie(0 == setsockopt(mMulticastRouterSock, IPPROTO_IPV6, MRT6_ADD_MIF, &mif6ctl, sizeof(mif6ctl)),
+                "Failed to add Thread network interface to MIF");
+
+    // Add Backbone network interface to MIF
+    mif6ctl.mif6c_mifi = kMifIndexBackbone;
+    mif6ctl.mif6c_pifi = mInfraIf.GetIfIndex();
+    VerifyOrDie(mif6ctl.mif6c_pifi > 0, "Backbone interface index is invalid");
+    VerifyOrDie(0 == setsockopt(mMulticastRouterSock, IPPROTO_IPV6, MRT6_ADD_MIF, &mif6ctl, sizeof(mif6ctl)),
+                "Failed to add Backbone interface to MIF");
+}
+
+void MulticastRoutingManager::FinalizeMulticastRouterSock(void)
+{
+    VerifyOrExit(IsEnabled());
+
+    close(mMulticastRouterSock);
+    mMulticastRouterSock = -1;
+
+exit:
+    return;
+}
+
+void MulticastRoutingManager::ProcessMulticastRouterMessages(void)
+{
+    otbrError       error = OTBR_ERROR_NONE;
+    char            buf[sizeof(struct mrt6msg)];
+    int             nr;
+    struct mrt6msg *mrt6msg;
+    Ip6Address      src, dst;
+
+    nr = read(mMulticastRouterSock, buf, sizeof(buf));
+
+    VerifyOrExit(nr >= static_cast<int>(sizeof(struct mrt6msg)), error = OTBR_ERROR_ERRNO);
+
+    mrt6msg = reinterpret_cast<struct mrt6msg *>(buf);
+
+    VerifyOrExit(mrt6msg->im6_mbz == 0);
+    VerifyOrExit(mrt6msg->im6_msgtype == MRT6MSG_NOCACHE);
+
+    src.CopyFrom(mrt6msg->im6_src);
+    dst.CopyFrom(mrt6msg->im6_dst);
+
+    error = AddMulticastForwardingCache(src, dst, static_cast<MifIndex>(mrt6msg->im6_mif));
+
+exit:
+    otbrLogResult(error, "%s", __FUNCTION__);
+}
+
+otbrError MulticastRoutingManager::AddMulticastForwardingCache(const Ip6Address &aSrcAddr,
+                                                               const Ip6Address &aGroupAddr,
+                                                               MifIndex          aIif)
+{
+    otbrError      error = OTBR_ERROR_NONE;
+    struct mf6cctl mf6cctl;
+    MifIndex       forwardMif = kMifIndexNone;
+
+    VerifyOrExit(aIif == kMifIndexThread || aIif == kMifIndexBackbone, error = OTBR_ERROR_INVALID_ARGS);
+
+    ExpireMulticastForwardingCache();
+
+    if (aIif == kMifIndexBackbone)
+    {
+        // Forward multicast traffic from Backbone to Thread if the group address is subscribed by any Thread device via
+        // MLR.
+        if (HasMulticastListener(aGroupAddr))
+        {
+            forwardMif = kMifIndexThread;
+        }
+    }
+    else
+    {
+        VerifyOrExit(!aSrcAddr.IsLinkLocal(), error = OTBR_ERROR_NONE);
+        VerifyOrExit(!MatchesMeshLocalPrefix(aSrcAddr, *mNetworkProperties.GetMeshLocalPrefix()),
+                     error = OTBR_ERROR_NONE);
+
+        // Forward multicast traffic from Thread to Backbone if multicast scope > kRealmLocalScope
+        // TODO: (MLR) allow scope configuration of outbound multicast routing
+        if (aGroupAddr.GetScope() > Ip6Address::kRealmLocalScope)
+        {
+            forwardMif = kMifIndexBackbone;
+        }
+    }
+
+    memset(&mf6cctl, 0, sizeof(mf6cctl));
+
+    aSrcAddr.CopyTo(mf6cctl.mf6cc_origin.sin6_addr);
+    aGroupAddr.CopyTo(mf6cctl.mf6cc_mcastgrp.sin6_addr);
+    mf6cctl.mf6cc_parent = aIif;
+
+    if (forwardMif != kMifIndexNone)
+    {
+        IF_SET(forwardMif, &mf6cctl.mf6cc_ifset);
+    }
+
+    // Note that kernel reports repetitive `MRT6MSG_NOCACHE` upcalls with a rate limit (e.g. once per 10s for Linux).
+    // Because of it, we need to add a "blocking" MFC even if there is no forwarding for this group address.
+    // When a  Multicast Listener is later added, the "blocking" MFC will be altered to be a "forwarding" MFC so that
+    // corresponding multicast traffic can be forwarded instantly.
+    VerifyOrExit(0 == setsockopt(mMulticastRouterSock, IPPROTO_IPV6, MRT6_ADD_MFC, &mf6cctl, sizeof(mf6cctl)),
+                 error = OTBR_ERROR_ERRNO);
+
+    SaveMulticastForwardingCache(aSrcAddr, aGroupAddr, aIif, forwardMif);
+exit:
+    otbrLogResult(error, "%s: add dynamic route: %s %s => %s %s", __FUNCTION__, MifIndexToString(aIif),
+                  aSrcAddr.ToString().c_str(), aGroupAddr.ToString().c_str(), MifIndexToString(forwardMif));
+
+    return error;
+}
+
+void MulticastRoutingManager::UnblockInboundMulticastForwardingCache(const Ip6Address &aGroupAddr)
+{
+    struct mf6cctl mf6cctl;
+
+    memset(&mf6cctl, 0, sizeof(mf6cctl));
+    aGroupAddr.CopyTo(mf6cctl.mf6cc_mcastgrp.sin6_addr);
+    mf6cctl.mf6cc_parent = kMifIndexBackbone;
+    IF_SET(kMifIndexThread, &mf6cctl.mf6cc_ifset);
+
+    for (MulticastForwardingCache &mfc : mMulticastForwardingCacheTable)
+    {
+        otbrError error;
+
+        if (!mfc.IsValid() || mfc.mIif != kMifIndexBackbone || mfc.mOif == kMifIndexThread ||
+            mfc.mGroupAddr != aGroupAddr)
+        {
+            continue;
+        }
+
+        // Unblock this inbound route
+        mfc.mSrcAddr.CopyTo(mf6cctl.mf6cc_origin.sin6_addr);
+
+        error = (0 == setsockopt(mMulticastRouterSock, IPPROTO_IPV6, MRT6_ADD_MFC, &mf6cctl, sizeof(mf6cctl)))
+                    ? OTBR_ERROR_NONE
+                    : OTBR_ERROR_ERRNO;
+
+        mfc.Set(kMifIndexBackbone, kMifIndexThread);
+
+        otbrLogResult(error, "%s: %s %s => %s %s", __FUNCTION__, MifIndexToString(mfc.mIif),
+                      mfc.mSrcAddr.ToString().c_str(), mfc.mGroupAddr.ToString().c_str(),
+                      MifIndexToString(kMifIndexThread));
+    }
+}
+
+void MulticastRoutingManager::RemoveInboundMulticastForwardingCache(const Ip6Address &aGroupAddr)
+{
+    for (MulticastForwardingCache &mfc : mMulticastForwardingCacheTable)
+    {
+        if (mfc.IsValid() && mfc.mIif == kMifIndexBackbone && mfc.mGroupAddr == aGroupAddr)
+        {
+            RemoveMulticastForwardingCache(mfc);
+        }
+    }
+}
+
+void MulticastRoutingManager::ExpireMulticastForwardingCache(void)
+{
+    struct sioc_sg_req6 sioc_sg_req6;
+    Timepoint           now = Clock::now();
+    struct mf6cctl      mf6cctl;
+
+    VerifyOrExit(now >= mLastExpireTime + Microseconds(kMulticastForwardingCacheExpiringInterval * kUsPerSecond));
+
+    mLastExpireTime = now;
+
+    memset(&mf6cctl, 0, sizeof(mf6cctl));
+    memset(&sioc_sg_req6, 0, sizeof(sioc_sg_req6));
+
+    for (MulticastForwardingCache &mfc : mMulticastForwardingCacheTable)
+    {
+        if (mfc.IsValid() &&
+            mfc.mLastUseTime + Microseconds(kMulticastForwardingCacheExpireTimeout * kUsPerSecond) < now)
+        {
+            if (!UpdateMulticastRouteInfo(mfc))
+            {
+                // The multicast route is expired
+                RemoveMulticastForwardingCache(mfc);
+            }
+        }
+    }
+
+    DumpMulticastForwardingCache();
+
+exit:
+    return;
+}
+
+bool MulticastRoutingManager::UpdateMulticastRouteInfo(MulticastForwardingCache &aMfc) const
+{
+    bool                updated = false;
+    struct sioc_sg_req6 sioc_sg_req6;
+
+    memset(&sioc_sg_req6, 0, sizeof(sioc_sg_req6));
+
+    aMfc.mSrcAddr.CopyTo(sioc_sg_req6.src.sin6_addr);
+    aMfc.mGroupAddr.CopyTo(sioc_sg_req6.grp.sin6_addr);
+
+    if (ioctl(mMulticastRouterSock, SIOCGETSGCNT_IN6, &sioc_sg_req6) != -1)
+    {
+        unsigned long validPktCnt;
+
+        otbrLogDebug("%s: SIOCGETSGCNT_IN6 %s => %s: bytecnt=%lu, pktcnt=%lu, wrong_if=%lu", __FUNCTION__,
+                     aMfc.mSrcAddr.ToString().c_str(), aMfc.mGroupAddr.ToString().c_str(), sioc_sg_req6.bytecnt,
+                     sioc_sg_req6.pktcnt, sioc_sg_req6.wrong_if);
+
+        validPktCnt = sioc_sg_req6.pktcnt - sioc_sg_req6.wrong_if;
+        if (validPktCnt != aMfc.mValidPktCnt)
+        {
+            aMfc.SetValidPktCnt(validPktCnt);
+
+            updated = true;
+        }
+    }
+    else
+    {
+        otbrLogDebug("%s: SIOCGETSGCNT_IN6 %s => %s failed: %s", __FUNCTION__, aMfc.mSrcAddr.ToString().c_str(),
+                     aMfc.mGroupAddr.ToString().c_str(), strerror(errno));
+    }
+
+    return updated;
+}
+
+const char *MulticastRoutingManager::MifIndexToString(MifIndex aMif)
+{
+    const char *string = "Unknown";
+
+    switch (aMif)
+    {
+    case kMifIndexNone:
+        string = "None";
+        break;
+    case kMifIndexThread:
+        string = "Thread";
+        break;
+    case kMifIndexBackbone:
+        string = "Backbone";
+        break;
+    }
+
+    return string;
+}
+
+void MulticastRoutingManager::DumpMulticastForwardingCache(void) const
+{
+    VerifyOrExit(otbrLogGetLevel() == OTBR_LOG_DEBUG);
+
+    otbrLogDebug("==================== MFC ENTRIES ====================");
+
+    for (const MulticastForwardingCache &mfc : mMulticastForwardingCacheTable)
+    {
+        if (mfc.IsValid())
+        {
+            otbrLogDebug("%s %s => %s %s", MifIndexToString(mfc.mIif), mfc.mSrcAddr.ToString().c_str(),
+                         mfc.mGroupAddr.ToString().c_str(), MifIndexToString(mfc.mOif));
+        }
+    }
+
+    otbrLogDebug("=====================================================");
+
+exit:
+    return;
+}
+
+void MulticastRoutingManager::MulticastForwardingCache::Set(MulticastRoutingManager::MifIndex aIif,
+                                                            MulticastRoutingManager::MifIndex aOif)
+{
+    mIif         = aIif;
+    mOif         = aOif;
+    mValidPktCnt = 0;
+    mLastUseTime = Clock::now();
+}
+
+void MulticastRoutingManager::MulticastForwardingCache::Set(const Ip6Address &aSrcAddr,
+                                                            const Ip6Address &aGroupAddr,
+                                                            MifIndex          aIif,
+                                                            MifIndex          aOif)
+{
+    mSrcAddr   = aSrcAddr;
+    mGroupAddr = aGroupAddr;
+    Set(aIif, aOif);
+}
+
+void MulticastRoutingManager::MulticastForwardingCache::SetValidPktCnt(unsigned long aValidPktCnt)
+{
+    mValidPktCnt = aValidPktCnt;
+    mLastUseTime = Clock::now();
+}
+
+void MulticastRoutingManager::SaveMulticastForwardingCache(const Ip6Address                 &aSrcAddr,
+                                                           const Ip6Address                 &aGroupAddr,
+                                                           MulticastRoutingManager::MifIndex aIif,
+                                                           MulticastRoutingManager::MifIndex aOif)
+{
+    MulticastForwardingCache *invalid = nullptr;
+    MulticastForwardingCache *oldest  = nullptr;
+
+    for (MulticastForwardingCache &mfc : mMulticastForwardingCacheTable)
+    {
+        if (mfc.IsValid())
+        {
+            if (mfc.mSrcAddr == aSrcAddr && mfc.mGroupAddr == aGroupAddr)
+            {
+                mfc.Set(aIif, aOif);
+                ExitNow();
+            }
+
+            if (oldest == nullptr || mfc.mLastUseTime < oldest->mLastUseTime)
+            {
+                oldest = &mfc;
+            }
+        }
+        else if (invalid == nullptr)
+        {
+            invalid = &mfc;
+        }
+    }
+
+    if (invalid != nullptr)
+    {
+        invalid->Set(aSrcAddr, aGroupAddr, aIif, aOif);
+    }
+    else
+    {
+        RemoveMulticastForwardingCache(*oldest);
+        oldest->Set(aSrcAddr, aGroupAddr, aIif, aOif);
+    }
+
+exit:
+    return;
+}
+
+void MulticastRoutingManager::RemoveMulticastForwardingCache(
+    MulticastRoutingManager::MulticastForwardingCache &aMfc) const
+{
+    otbrError      error;
+    struct mf6cctl mf6cctl;
+
+    memset(&mf6cctl, 0, sizeof(mf6cctl));
+
+    aMfc.mSrcAddr.CopyTo(mf6cctl.mf6cc_origin.sin6_addr);
+    aMfc.mGroupAddr.CopyTo(mf6cctl.mf6cc_mcastgrp.sin6_addr);
+
+    mf6cctl.mf6cc_parent = aMfc.mIif;
+
+    error = (0 == setsockopt(mMulticastRouterSock, IPPROTO_IPV6, MRT6_DEL_MFC, &mf6cctl, sizeof(mf6cctl)))
+                ? OTBR_ERROR_NONE
+                : OTBR_ERROR_ERRNO;
+
+    otbrLogResult(error, "%s: %s %s => %s %s", __FUNCTION__, MifIndexToString(aMfc.mIif),
+                  aMfc.mSrcAddr.ToString().c_str(), aMfc.mGroupAddr.ToString().c_str(), MifIndexToString(aMfc.mOif));
+
+    aMfc.Erase();
+}
+
+bool MulticastRoutingManager::MatchesMeshLocalPrefix(const Ip6Address        &aAddress,
+                                                     const otMeshLocalPrefix &aMeshLocalPrefix)
+{
+    otIp6Address matcher{};
+    memcpy(matcher.mFields.m8, aMeshLocalPrefix.m8, sizeof(otMeshLocalPrefix));
+
+    return otIp6PrefixMatch(reinterpret_cast<const otIp6Address *>(aAddress.m8), &matcher) >= OT_IP6_PREFIX_BITSIZE;
+}
+
+} // namespace otbr
+
+#endif // OTBR_ENABLE_BACKBONE_ROUTER
+#endif // __linux__
diff --git a/src/host/posix/multicast_routing_manager.hpp b/src/host/posix/multicast_routing_manager.hpp
new file mode 100644
index 00000000..704d9e7b
--- /dev/null
+++ b/src/host/posix/multicast_routing_manager.hpp
@@ -0,0 +1,141 @@
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
+#ifndef BACKBONE_ROUTER_MULTICAST_ROUTING_MANAGER_HPP_
+#define BACKBONE_ROUTER_MULTICAST_ROUTING_MANAGER_HPP_
+
+#include "openthread-br/config.h"
+
+#include <set>
+
+#include <openthread/backbone_router_ftd.h>
+#include <openthread/dataset.h>
+
+#include "common/code_utils.hpp"
+#include "common/mainloop.hpp"
+#include "common/time.hpp"
+#include "common/types.hpp"
+#include "host/posix/infra_if.hpp"
+#include "host/posix/netif.hpp"
+#include "host/thread_host.hpp"
+
+namespace otbr {
+
+class MulticastRoutingManager : public MainloopProcessor, private NonCopyable
+{
+public:
+    explicit MulticastRoutingManager(const Netif                   &aNetif,
+                                     const InfraIf                 &aInfraIf,
+                                     const Host::NetworkProperties &aNetworkProperties);
+
+    void Deinit(void) { FinalizeMulticastRouterSock(); }
+    bool IsEnabled(void) const { return mMulticastRouterSock >= 0; }
+    void HandleStateChange(otBackboneRouterState aState);
+    void HandleBackboneMulticastListenerEvent(otBackboneRouterMulticastListenerEvent aEvent,
+                                              const Ip6Address                      &aAddress);
+
+private:
+    static constexpr uint32_t kUsPerSecond = 1000000; //< Microseconds per second.
+    static constexpr uint32_t kMulticastForwardingCacheExpireTimeout =
+        300; //< Expire timeout of Multicast Forwarding Cache (in seconds)
+    static constexpr uint32_t kMulticastForwardingCacheExpiringInterval =
+        60; //< Expire interval of Multicast Forwarding Cache (in seconds)
+    static constexpr uint32_t kMulticastMaxListeners = 75; //< The max number of Multicast listeners
+    static constexpr uint32_t kMulticastForwardingCacheTableSize =
+        kMulticastMaxListeners * 10; //< The max size of MFC table.
+
+    enum MifIndex : uint8_t
+    {
+        kMifIndexNone     = 0xff,
+        kMifIndexThread   = 0,
+        kMifIndexBackbone = 1,
+    };
+
+    class MulticastForwardingCache
+    {
+        friend class MulticastRoutingManager;
+
+    private:
+        MulticastForwardingCache()
+            : mIif(kMifIndexNone)
+        {
+        }
+
+        bool IsValid() const { return mIif != kMifIndexNone; }
+        void Set(MifIndex aIif, MifIndex aOif);
+        void Set(const Ip6Address &aSrcAddr, const Ip6Address &aGroupAddr, MifIndex aIif, MifIndex aOif);
+        void Erase(void) { mIif = kMifIndexNone; }
+        void SetValidPktCnt(unsigned long aValidPktCnt);
+
+        Ip6Address    mSrcAddr;
+        Ip6Address    mGroupAddr;
+        Timepoint     mLastUseTime;
+        unsigned long mValidPktCnt;
+        MifIndex      mIif;
+        MifIndex      mOif;
+    };
+
+    void Update(MainloopContext &aContext) override;
+    void Process(const MainloopContext &aContext) override;
+
+    void      Enable(void);
+    void      Disable(void);
+    void      Add(const Ip6Address &aAddress);
+    void      Remove(const Ip6Address &aAddress);
+    void      UpdateMldReport(const Ip6Address &aAddress, bool isAdd);
+    bool      HasMulticastListener(const Ip6Address &aAddress) const;
+    void      InitMulticastRouterSock(void);
+    void      FinalizeMulticastRouterSock(void);
+    void      ProcessMulticastRouterMessages(void);
+    otbrError AddMulticastForwardingCache(const Ip6Address &aSrcAddr, const Ip6Address &aGroupAddr, MifIndex aIif);
+    void      SaveMulticastForwardingCache(const Ip6Address &aSrcAddr,
+                                           const Ip6Address &aGroupAddr,
+                                           MifIndex          aIif,
+                                           MifIndex          aOif);
+    void      UnblockInboundMulticastForwardingCache(const Ip6Address &aGroupAddr);
+    void      RemoveInboundMulticastForwardingCache(const Ip6Address &aGroupAddr);
+    void      ExpireMulticastForwardingCache(void);
+    bool      UpdateMulticastRouteInfo(MulticastForwardingCache &aMfc) const;
+    void      RemoveMulticastForwardingCache(MulticastForwardingCache &aMfc) const;
+    static const char *MifIndexToString(MifIndex aMif);
+    void               DumpMulticastForwardingCache(void) const;
+
+    static bool MatchesMeshLocalPrefix(const Ip6Address &aAddress, const otMeshLocalPrefix &aMeshLocalPrefix);
+
+    const Netif                   &mNetif;
+    const InfraIf                 &mInfraIf;
+    const Host::NetworkProperties &mNetworkProperties;
+    MulticastForwardingCache       mMulticastForwardingCacheTable[kMulticastForwardingCacheTableSize];
+    otbr::Timepoint                mLastExpireTime;
+    int                            mMulticastRouterSock;
+    std::set<Ip6Address>           mMulticastListeners;
+};
+
+} // namespace otbr
+
+#endif // BACKBONE_ROUTER_MULTICAST_ROUTING_MANAGER_HPP_
diff --git a/src/host/posix/netif.cpp b/src/host/posix/netif.cpp
index 13957a01..4320a491 100644
--- a/src/host/posix/netif.cpp
+++ b/src/host/posix/netif.cpp
@@ -96,25 +96,26 @@ enum
     kIcmpv6Mldv2RecordChangeToExcludeType = 4,
 };
 
-Netif::Netif(Dependencies &aDependencies)
+Netif::Netif(const std::string &aInterfaceName, Dependencies &aDependencies)
     : mTunFd(-1)
     , mIpFd(-1)
     , mNetlinkFd(-1)
     , mMldFd(-1)
     , mNetlinkSequence(0)
     , mNetifIndex(0)
+    , mNetifName(aInterfaceName)
     , mDeps(aDependencies)
 {
 }
 
-otbrError Netif::Init(const std::string &aInterfaceName)
+otbrError Netif::Init(void)
 {
     otbrError error = OTBR_ERROR_NONE;
 
     mIpFd = SocketWithCloseExec(AF_INET6, SOCK_DGRAM, IPPROTO_IP, kSocketNonBlock);
     VerifyOrExit(mIpFd >= 0, error = OTBR_ERROR_ERRNO);
 
-    SuccessOrExit(error = CreateTunDevice(aInterfaceName));
+    SuccessOrExit(error = CreateTunDevice(mNetifName));
     SuccessOrExit(error = InitNetlink());
 
     mNetifIndex = if_nametoindex(mNetifName.c_str());
@@ -137,42 +138,6 @@ void Netif::Deinit(void)
     Clear();
 }
 
-void Netif::Process(const MainloopContext *aContext)
-{
-    if (FD_ISSET(mTunFd, &aContext->mErrorFdSet))
-    {
-        close(mTunFd);
-        DieNow("Error on Tun Fd!");
-    }
-
-    if (FD_ISSET(mMldFd, &aContext->mErrorFdSet))
-    {
-        close(mMldFd);
-        DieNow("Error on MLD Fd!");
-    }
-
-    if (FD_ISSET(mTunFd, &aContext->mReadFdSet))
-    {
-        ProcessIp6Send();
-    }
-
-    if (FD_ISSET(mMldFd, &aContext->mReadFdSet))
-    {
-        ProcessMldEvent();
-    }
-}
-
-void Netif::UpdateFdSet(MainloopContext *aContext)
-{
-    assert(aContext != nullptr);
-    assert(mTunFd >= 0);
-    assert(mIpFd >= 0);
-    assert(mMldFd >= 0);
-
-    aContext->AddFdToSet(mTunFd, MainloopContext::kErrorFdSet | MainloopContext::kReadFdSet);
-    aContext->AddFdToSet(mMldFd, MainloopContext::kErrorFdSet | MainloopContext::kReadFdSet);
-}
-
 void Netif::UpdateIp6UnicastAddresses(const std::vector<Ip6AddressInfo> &aAddrInfos)
 {
     // Remove stale addresses
@@ -498,4 +463,39 @@ exit:
     }
 }
 
+void Netif::Update(MainloopContext &aContext)
+{
+    assert(mTunFd >= 0);
+    assert(mIpFd >= 0);
+    assert(mMldFd >= 0);
+
+    aContext.AddFdToSet(mTunFd, MainloopContext::kErrorFdSet | MainloopContext::kReadFdSet);
+    aContext.AddFdToSet(mMldFd, MainloopContext::kErrorFdSet | MainloopContext::kReadFdSet);
+}
+
+void Netif::Process(const MainloopContext &aContext)
+{
+    if (FD_ISSET(mTunFd, &aContext.mErrorFdSet))
+    {
+        close(mTunFd);
+        DieNow("Error on Tun Fd!");
+    }
+
+    if (FD_ISSET(mMldFd, &aContext.mErrorFdSet))
+    {
+        close(mMldFd);
+        DieNow("Error on MLD Fd!");
+    }
+
+    if (FD_ISSET(mTunFd, &aContext.mReadFdSet))
+    {
+        ProcessIp6Send();
+    }
+
+    if (FD_ISSET(mMldFd, &aContext.mReadFdSet))
+    {
+        ProcessMldEvent();
+    }
+}
+
 } // namespace otbr
diff --git a/src/host/posix/netif.hpp b/src/host/posix/netif.hpp
index 0c590f5b..c18ad1e1 100644
--- a/src/host/posix/netif.hpp
+++ b/src/host/posix/netif.hpp
@@ -41,12 +41,13 @@
 
 #include <openthread/ip6.h>
 
+#include "common/code_utils.hpp"
 #include "common/mainloop.hpp"
 #include "common/types.hpp"
 
 namespace otbr {
 
-class Netif
+class Netif : public MainloopProcessor, private NonCopyable
 {
 public:
     class Dependencies
@@ -58,19 +59,19 @@ public:
         virtual otbrError Ip6MulAddrUpdateSubscription(const otIp6Address &aAddress, bool aIsAdded);
     };
 
-    Netif(Dependencies &aDependencies);
+    Netif(const std::string &aInterfaceName, Dependencies &aDependencies);
 
-    otbrError Init(const std::string &aInterfaceName);
+    otbrError Init(void);
     void      Deinit(void);
 
-    void      Process(const MainloopContext *aContext);
-    void      UpdateFdSet(MainloopContext *aContext);
     void      UpdateIp6UnicastAddresses(const std::vector<Ip6AddressInfo> &aAddrInfos);
     otbrError UpdateIp6MulticastAddresses(const std::vector<Ip6Address> &aAddrs);
     void      SetNetifState(bool aState);
 
     void Ip6Receive(const uint8_t *aBuf, uint16_t aLen);
 
+    unsigned int GetIfIndex(void) const { return mNetifIndex; }
+
 private:
     // TODO: Retrieve the Maximum Ip6 size from the coprocessor.
     static constexpr size_t kIp6Mtu = 1280;
@@ -88,6 +89,9 @@ private:
     void      ProcessIp6Send(void);
     void      ProcessMldEvent(void);
 
+    void Update(MainloopContext &aContext) override;
+    void Process(const MainloopContext &aContext) override;
+
     int      mTunFd;           ///< Used to exchange IPv6 packets.
     int      mIpFd;            ///< Used to manage IPv6 stack on the network interface.
     int      mNetlinkFd;       ///< Used to receive netlink events.
diff --git a/src/host/posix/udp_proxy.cpp b/src/host/posix/udp_proxy.cpp
new file mode 100644
index 00000000..442c69ec
--- /dev/null
+++ b/src/host/posix/udp_proxy.cpp
@@ -0,0 +1,277 @@
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
+#define OTBR_LOG_TAG "UDPProxy"
+
+#ifdef __APPLE__
+#define __APPLE_USE_RFC_3542
+#endif
+
+#include "host/posix/udp_proxy.hpp"
+
+#include <assert.h>
+#include <netinet/in.h>
+#include <sys/select.h>
+#include <unistd.h>
+
+#include "common/code_utils.hpp"
+#include "common/logging.hpp"
+#include "host/posix/dnssd.hpp"
+#include "utils/socket_utils.hpp"
+
+namespace otbr {
+
+otbrError UdpProxy::Dependencies::UdpForward(const uint8_t      *aUdpPayload,
+                                             uint16_t            aLength,
+                                             const otIp6Address &aRemoteAddr,
+                                             uint16_t            aRemotePort,
+                                             const UdpProxy     &aUdpProxy)
+{
+    OTBR_UNUSED_VARIABLE(aUdpPayload);
+    OTBR_UNUSED_VARIABLE(aLength);
+    OTBR_UNUSED_VARIABLE(aRemoteAddr);
+    OTBR_UNUSED_VARIABLE(aRemotePort);
+    OTBR_UNUSED_VARIABLE(aUdpProxy);
+
+    return OTBR_ERROR_NONE;
+}
+
+UdpProxy::UdpProxy(Dependencies &aDeps)
+    : mFd(-1)
+    , mHostPort(0)
+    , mThreadPort(0)
+    , mDeps(aDeps)
+{
+}
+
+void UdpProxy::Start(uint16_t aPort)
+{
+    VerifyOrExit(!IsStarted());
+
+    BindToEphemeralPort();
+    mThreadPort = aPort;
+
+exit:
+    return;
+}
+
+void UdpProxy::Stop(void)
+{
+    VerifyOrExit(IsStarted());
+
+    mHostPort = 0;
+
+    if (mFd >= 0)
+    {
+        close(mFd);
+        mFd = -1;
+    }
+
+exit:
+    return;
+}
+
+void UdpProxy::Process(const MainloopContext &aContext)
+{
+    constexpr size_t kMaxUdpSize = 1280;
+
+    uint8_t      payload[kMaxUdpSize];
+    uint16_t     length = sizeof(payload);
+    otIp6Address remoteAddr;
+    uint16_t     remotePort;
+
+    VerifyOrExit(mFd != -1 && IsStarted());
+    VerifyOrExit(FD_ISSET(mFd, &aContext.mReadFdSet));
+
+    SuccessOrExit(ReceivePacket(payload, length, remoteAddr, remotePort));
+
+    // UDP Forward to NCPq
+    mDeps.UdpForward(payload, length, remoteAddr, remotePort, *this);
+
+exit:
+    return;
+}
+
+void UdpProxy::Update(MainloopContext &aContext)
+{
+    VerifyOrExit(mFd != -1);
+    VerifyOrExit(IsStarted());
+
+    aContext.AddFdToReadSet(mFd);
+
+exit:
+    return;
+}
+
+void UdpProxy::SendToPeer(const uint8_t      *aUdpPayload,
+                          uint16_t            aLength,
+                          const otIp6Address &aPeerAddr,
+                          uint16_t            aPeerPort)
+{
+#ifdef __APPLE__
+    // use fixed value for CMSG_SPACE is not a constant expression on macOS
+    constexpr size_t kBufferSize = 128;
+#else
+    constexpr size_t kBufferSize = CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int));
+#endif
+    struct sockaddr_in6 peerAddr;
+    uint8_t             control[kBufferSize];
+    size_t              controlLength = 0;
+    struct iovec        iov;
+    struct msghdr       msg;
+    struct cmsghdr     *cmsg;
+    ssize_t             rval;
+
+    memset(&peerAddr, 0, sizeof(peerAddr));
+    peerAddr.sin6_port   = htons(aPeerPort);
+    peerAddr.sin6_family = AF_INET6;
+    memcpy(&peerAddr.sin6_addr, &aPeerAddr, sizeof(aPeerAddr));
+    memset(control, 0, sizeof(control));
+
+    iov.iov_base = reinterpret_cast<void *>(const_cast<uint8_t *>(aUdpPayload));
+    iov.iov_len  = aLength;
+
+    msg.msg_name       = &peerAddr;
+    msg.msg_namelen    = sizeof(peerAddr);
+    msg.msg_control    = control;
+    msg.msg_controllen = static_cast<decltype(msg.msg_controllen)>(sizeof(control));
+    msg.msg_iov        = &iov;
+    msg.msg_iovlen     = 1;
+    msg.msg_flags      = 0;
+
+    {
+        constexpr int kIp6HopLimit = 64;
+
+        int hopLimit = kIp6HopLimit;
+
+        cmsg             = CMSG_FIRSTHDR(&msg);
+        cmsg->cmsg_level = IPPROTO_IPV6;
+        cmsg->cmsg_type  = IPV6_HOPLIMIT;
+        cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
+
+        memcpy(CMSG_DATA(cmsg), &hopLimit, sizeof(int));
+
+        controlLength += CMSG_SPACE(sizeof(int));
+    }
+
+#ifdef __APPLE__
+    msg.msg_controllen = static_cast<socklen_t>(controlLength);
+#else
+    msg.msg_controllen           = controlLength;
+#endif
+
+    rval = sendmsg(mFd, &msg, 0);
+
+    if (rval == -1)
+    {
+        otbrLogWarning("Failed to sendmsg: %s", strerror(errno));
+    }
+}
+
+otbrError UdpProxy::BindToEphemeralPort(void)
+{
+    otbrError error = OTBR_ERROR_NONE;
+    mFd             = SocketWithCloseExec(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, kSocketNonBlock);
+
+    VerifyOrExit(mFd != 0, error = OTBR_ERROR_ERRNO);
+
+    {
+        struct sockaddr_in6 sin6;
+
+        memset(&sin6, 0, sizeof(sin6));
+        sin6.sin6_family = AF_INET6;
+        sin6.sin6_addr   = in6addr_any;
+        sin6.sin6_port   = 0;
+
+        VerifyOrExit(0 == bind(mFd, reinterpret_cast<struct sockaddr *>(&sin6), sizeof(sin6)),
+                     error = OTBR_ERROR_ERRNO);
+    }
+
+    {
+        int on = 1;
+        VerifyOrExit(0 == setsockopt(mFd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)), error = OTBR_ERROR_ERRNO);
+        VerifyOrExit(0 == setsockopt(mFd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)), error = OTBR_ERROR_ERRNO);
+    }
+
+    {
+        struct sockaddr_in bound_addr;
+        socklen_t          addr_len = sizeof(bound_addr);
+        getsockname(mFd, (struct sockaddr *)&bound_addr, &addr_len);
+
+        mHostPort = ntohs(bound_addr.sin_port);
+        otbrLogInfo("Ephemeral port: %u", mHostPort);
+    }
+
+exit:
+    otbrLogResult(error, "Bind to ephemeral port");
+    if (error != OTBR_ERROR_NONE)
+    {
+        Stop();
+    }
+    return error;
+}
+
+otbrError UdpProxy::ReceivePacket(uint8_t      *aPayload,
+                                  uint16_t     &aLength,
+                                  otIp6Address &aRemoteAddr,
+                                  uint16_t     &aRemotePort)
+{
+    constexpr size_t kMaxUdpSize = 1280;
+
+    struct sockaddr_in6 peerAddr;
+    uint8_t             control[kMaxUdpSize];
+    struct iovec        iov;
+    struct msghdr       msg;
+    ssize_t             rval;
+
+    iov.iov_base = aPayload;
+    iov.iov_len  = aLength;
+
+    msg.msg_name       = &peerAddr;
+    msg.msg_namelen    = sizeof(peerAddr);
+    msg.msg_control    = control;
+    msg.msg_controllen = sizeof(control);
+    msg.msg_iov        = &iov;
+    msg.msg_iovlen     = 1;
+    msg.msg_flags      = 0;
+
+    rval = recvmsg(mFd, &msg, 0);
+    VerifyOrExit(rval > 0, perror("recvmsg"));
+    aLength = static_cast<uint16_t>(rval);
+
+    aRemotePort = ntohs(peerAddr.sin6_port);
+    memcpy(&aRemoteAddr, &peerAddr.sin6_addr, sizeof(otIp6Address));
+
+    otbrLogDebug("Receive a packet, remote address:%s, remote port:%d", Ip6Address(aRemoteAddr).ToString().c_str(),
+                 aRemotePort);
+
+exit:
+    return rval > 0 ? OTBR_ERROR_NONE : OTBR_ERROR_ERRNO;
+}
+
+} // namespace otbr
diff --git a/src/host/posix/udp_proxy.hpp b/src/host/posix/udp_proxy.hpp
new file mode 100644
index 00000000..fa7b53fe
--- /dev/null
+++ b/src/host/posix/udp_proxy.hpp
@@ -0,0 +1,123 @@
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
+ * @brief
+ *   This module includes definition for Thread UDP Proxy.
+ */
+
+#ifndef OTBR_AGENT_POSIX_UDP_PROXY_HPP_
+#define OTBR_AGENT_POSIX_UDP_PROXY_HPP_
+
+#include <openthread/error.h>
+#include <openthread/ip6.h>
+
+#include "common/mainloop.hpp"
+#include "common/types.hpp"
+
+namespace otbr {
+
+class UdpProxy : public MainloopProcessor
+{
+public:
+    class Dependencies
+    {
+    public:
+        virtual ~Dependencies(void) = default;
+
+        virtual otbrError UdpForward(const uint8_t      *aUdpPayload,
+                                     uint16_t            aLength,
+                                     const otIp6Address &aRemoteAddr,
+                                     uint16_t            aRemotePort,
+                                     const UdpProxy     &aUdpProxy);
+    };
+
+    /**
+     * The constructor to initialize the Thread Border Agent UDP Proxy.
+     */
+    explicit UdpProxy(Dependencies &aDeps);
+
+    ~UdpProxy(void) = default;
+
+    /**
+     * Start the UDP Proxy for Thread UDP port @p aPort.
+     *
+     * The UDP Proxy will bind to an ephemeral port and set a mapping between the ephemeral port and @p aPort.
+     *
+     * @param[in] aPort  The UDP port to be proxied in Thread stack.
+     */
+    void Start(uint16_t aPort);
+
+    /**
+     * Stop the UDP Proxy if started.
+     */
+    void Stop(void);
+
+    /**
+     * Get the ephemeral UDP port bound on host.
+     *
+     * @returns The UDP port bound on the host. If the proxy isn't running, `0` will be returned.
+     */
+    uint16_t GetHostPort(void) const { return mHostPort; }
+
+    /**
+     * Get the UDP port on the Thread side.
+     *
+     * @returns The UDP port on the Thread side. If the proxy isn't running, `0` will be returned.
+     */
+    uint16_t GetThreadPort(void) const { return mThreadPort; }
+
+    /**
+     * Sends a UDP packet to the peer.
+     *
+     * @param[in] aUdpPlayload  The UDP payload.
+     * @param[in] aLength       Then length of the UDP payload.
+     * @param[in] aPeerAddr     The address of the peer.
+     * @param[in] aPeerPort     The UDP of the peer.
+     */
+    void SendToPeer(const uint8_t *aUdpPayload, uint16_t aLength, const otIp6Address &aPeerAddr, uint16_t aPeerPort);
+
+private:
+    // MainloopProcessor methods
+    void Process(const MainloopContext &aMainloop) override;
+    void Update(MainloopContext &aMainloop) override;
+
+    bool      IsStarted(void) const { return mHostPort != 0; }
+    otbrError BindToEphemeralPort(void);
+    otbrError ReceivePacket(uint8_t *aPayload, uint16_t &aLength, otIp6Address &aRemoteAddr, uint16_t &aRemotePort);
+
+    int      mFd; ///< Used to proxy UDP packets in Thread network.
+    uint16_t mHostPort;
+    uint16_t mThreadPort;
+
+    Dependencies &mDeps;
+};
+
+} // namespace otbr
+
+#endif // OTBR_AGENT_POSIX_UDP_PROXY_HPP_
diff --git a/src/host/rcp_host.cpp b/src/host/rcp_host.cpp
index a8aa072c..c939da09 100644
--- a/src/host/rcp_host.cpp
+++ b/src/host/rcp_host.cpp
@@ -36,6 +36,7 @@
 #include <string.h>
 
 #include <openthread/backbone_router_ftd.h>
+#include <openthread/border_agent.h>
 #include <openthread/border_routing.h>
 #include <openthread/dataset.h>
 #include <openthread/dnssd_server.h>
@@ -111,6 +112,11 @@ void OtNetworkProperties::GetDatasetPendingTlvs(otOperationalDatasetTlvs &aDatas
     }
 }
 
+const otMeshLocalPrefix *OtNetworkProperties::GetMeshLocalPrefix(void) const
+{
+    return otThreadGetMeshLocalPrefix(mInstance);
+}
+
 void OtNetworkProperties::SetInstance(otInstance *aInstance)
 {
     mInstance = aInstance;
@@ -251,12 +257,19 @@ void RcpHost::Init(void)
     otTrelSetEnabled(mInstance, featureFlagList.enable_trel());
 #endif
 
-#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+#if OTBR_ENABLE_SRP_SERVER_AUTO_ENABLE_MODE && OTBR_ENABLE_SRP_SERVER_ON_INIT
+#error \
+    "OTBR_ENABLE_SRP_SERVER_AUTO_ENABLE_MODE and OTBR_ENABLE_SRP_SERVER_ON_INIT shouldn't be enabled at the same time"
+#endif
+
+#if OTBR_ENABLE_SRP_SERVER
 #if OTBR_ENABLE_SRP_SERVER_AUTO_ENABLE_MODE
     // Let SRP server use auto-enable mode. The auto-enable mode delegates the control of SRP server to the Border
     // Routing Manager. SRP server automatically starts when bi-directional connectivity is ready.
     otSrpServerSetAutoEnableMode(mInstance, /* aEnabled */ true);
-#else
+#endif
+
+#if OTBR_ENABLE_SRP_SERVER_ON_INIT
     otSrpServerSetEnabled(mInstance, /* aEnabled */ true);
 #endif
 #endif
@@ -274,6 +287,9 @@ void RcpHost::Init(void)
 #endif
 #endif // OTBR_ENABLE_FEATURE_FLAGS
 
+    otBorderAgentSetMeshCoPServiceChangedCallback(mInstance, RcpHost::HandleMeshCoPServiceChanged, this);
+    otBorderAgentEphemeralKeySetCallback(mInstance, RcpHost::HandleEpskcStateChanged, this);
+
     mThreadHelper = MakeUnique<otbr::agent::ThreadHelper>(mInstance, this);
 
     OtNetworkProperties::SetInstance(mInstance);
@@ -335,6 +351,8 @@ void RcpHost::Deinit(void)
     mSetThreadEnabledReceiver  = nullptr;
     mScheduleMigrationReceiver = nullptr;
     mDetachGracefullyCallbacks.clear();
+    mBorderAgentMeshCoPServiceChangedCallback = nullptr;
+    mEphemeralKeyStateChangedCallbacks.clear();
 }
 
 void RcpHost::HandleStateChanged(otChangedFlags aFlags)
@@ -405,6 +423,26 @@ void RcpHost::AddThreadEnabledStateChangedCallback(ThreadEnabledStateCallback aC
     mThreadEnabledStateChangedCallbacks.push_back(aCallback);
 }
 
+#if OTBR_ENABLE_BACKBONE_ROUTER
+void RcpHost::SetBackboneRouterEnabled(bool aEnabled)
+{
+    // TODO: Implement this in RCP mode.
+    OTBR_UNUSED_VARIABLE(aEnabled);
+}
+
+void RcpHost::SetBackboneRouterMulticastListenerCallback(BackboneRouterMulticastListenerCallback aCallback)
+{
+    // TODO: Implement this in RCP mode.
+    OTBR_UNUSED_VARIABLE(aCallback);
+}
+
+void RcpHost::SetBackboneRouterStateChangedCallback(BackboneRouterStateChangedCallback aCallback)
+{
+    // TODO: Implement this in RCP mode.
+    OTBR_UNUSED_VARIABLE(aCallback);
+}
+#endif
+
 void RcpHost::Reset(void)
 {
     gPlatResetReason = OT_PLAT_RESET_REASON_SOFTWARE;
@@ -782,6 +820,77 @@ void RcpHost::UpdateThreadEnabledState(ThreadEnabledState aState)
     }
 }
 
+void RcpHost::HandleMeshCoPServiceChanged(void *aContext)
+{
+    static_cast<RcpHost *>(aContext)->HandleMeshCoPServiceChanged();
+}
+
+void RcpHost::HandleMeshCoPServiceChanged(void)
+{
+    otBorderAgentMeshCoPServiceTxtData txtData;
+
+    VerifyOrExit(mBorderAgentMeshCoPServiceChangedCallback != nullptr);
+
+    if (otBorderAgentGetMeshCoPServiceTxtData(mInstance, &txtData) != OT_ERROR_NONE)
+    {
+        otbrLogWarning("Failed to read MeshCoP Service TXT Data");
+    }
+    else
+    {
+        mBorderAgentMeshCoPServiceChangedCallback(otBorderAgentIsActive(mInstance), otBorderAgentGetUdpPort(mInstance),
+                                                  txtData.mData, txtData.mLength);
+    }
+
+exit:
+    return;
+}
+
+void RcpHost::SetBorderAgentMeshCoPServiceChangedCallback(BorderAgentMeshCoPServiceChangedCallback aCallback)
+{
+    mBorderAgentMeshCoPServiceChangedCallback = std::move(aCallback);
+}
+
+void RcpHost::HandleEpskcStateChanged(void *aContext)
+{
+    static_cast<RcpHost *>(aContext)->HandleEpskcStateChanged();
+}
+
+void RcpHost::HandleEpskcStateChanged(void)
+{
+    otBorderAgentEphemeralKeyState epskcState = otBorderAgentEphemeralKeyGetState(mInstance);
+    uint16_t                       port       = otBorderAgentEphemeralKeyGetUdpPort(mInstance);
+
+    for (auto callback : mEphemeralKeyStateChangedCallbacks)
+    {
+        callback(epskcState, port);
+    }
+}
+
+otbrError RcpHost::UdpForward(const uint8_t      *aUdpPayload,
+                              uint16_t            aLength,
+                              const otIp6Address &aRemoteAddr,
+                              uint16_t            aRemotePort,
+                              const UdpProxy     &aUdpProxy)
+{
+    OTBR_UNUSED_VARIABLE(aUdpPayload);
+    OTBR_UNUSED_VARIABLE(aLength);
+    OTBR_UNUSED_VARIABLE(aRemoteAddr);
+    OTBR_UNUSED_VARIABLE(aRemotePort);
+    OTBR_UNUSED_VARIABLE(aUdpProxy);
+
+    return OTBR_ERROR_NOT_IMPLEMENTED;
+}
+
+void RcpHost::AddEphemeralKeyStateChangedCallback(EphemeralKeyStateChangedCallback aCallback)
+{
+    mEphemeralKeyStateChangedCallbacks.push_back(aCallback);
+}
+
+void RcpHost::SetUdpForwardToHostCallback(UdpForwardToHostCallback aCallback)
+{
+    OTBR_UNUSED_VARIABLE(aCallback);
+}
+
 /*
  * Provide, if required an "otPlatLog()" function
  */
diff --git a/src/host/rcp_host.hpp b/src/host/rcp_host.hpp
index 27784351..7b79647a 100644
--- a/src/host/rcp_host.hpp
+++ b/src/host/rcp_host.hpp
@@ -72,11 +72,12 @@ public:
     explicit OtNetworkProperties(void);
 
     // NetworkProperties methods
-    otDeviceRole GetDeviceRole(void) const override;
-    bool         Ip6IsEnabled(void) const override;
-    uint32_t     GetPartitionId(void) const override;
-    void         GetDatasetActiveTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override;
-    void         GetDatasetPendingTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override;
+    otDeviceRole             GetDeviceRole(void) const override;
+    bool                     Ip6IsEnabled(void) const override;
+    uint32_t                 GetPartitionId(void) const override;
+    void                     GetDatasetActiveTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override;
+    void                     GetDatasetPendingTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override;
+    const otMeshLocalPrefix *GetMeshLocalPrefix(void) const override;
 
     // Set the otInstance
     void SetInstance(otInstance *aInstance);
@@ -211,6 +212,14 @@ public:
 #endif
     void AddThreadStateChangedCallback(ThreadStateChangedCallback aCallback) override;
     void AddThreadEnabledStateChangedCallback(ThreadEnabledStateCallback aCallback) override;
+#if OTBR_ENABLE_BACKBONE_ROUTER
+    void SetBackboneRouterEnabled(bool aEnabled) override;
+    void SetBackboneRouterMulticastListenerCallback(BackboneRouterMulticastListenerCallback aCallback) override;
+    void SetBackboneRouterStateChangedCallback(BackboneRouterStateChangedCallback aCallback) override;
+#endif // OTBR_ENABLE_BACKBONE_ROUTER
+    void SetBorderAgentMeshCoPServiceChangedCallback(BorderAgentMeshCoPServiceChangedCallback aCallback) override;
+    void AddEphemeralKeyStateChangedCallback(EphemeralKeyStateChangedCallback aCallback) override;
+    void SetUdpForwardToHostCallback(UdpForwardToHostCallback aCallback) override;
 
     CoprocessorType GetCoprocessorType(void) override
     {
@@ -254,6 +263,17 @@ private:
     static void SendMgmtPendingSetCallback(otError aError, void *aContext);
     void        SendMgmtPendingSetCallback(otError aError);
 
+    static void HandleMeshCoPServiceChanged(void *aContext);
+    void        HandleMeshCoPServiceChanged(void);
+    static void HandleEpskcStateChanged(void *aContext);
+    void        HandleEpskcStateChanged(void);
+
+    otbrError UdpForward(const uint8_t      *aUdpPayload,
+                         uint16_t            aLength,
+                         const otIp6Address &aRemoteAddr,
+                         uint16_t            aRemotePort,
+                         const UdpProxy     &aUdpProxy) override;
+
     bool IsAutoAttachEnabled(void);
     void DisableAutoAttach(void);
 
@@ -270,14 +290,16 @@ private:
     std::vector<std::function<void(void)>>     mResetHandlers;
     TaskRunner                                 mTaskRunner;
 
-    std::vector<ThreadStateChangedCallback> mThreadStateChangedCallbacks;
-    std::vector<ThreadEnabledStateCallback> mThreadEnabledStateChangedCallbacks;
-    bool                                    mEnableAutoAttach = false;
-    ThreadEnabledState                      mThreadEnabledState;
-    AsyncResultReceiver                     mJoinReceiver;
-    AsyncResultReceiver                     mSetThreadEnabledReceiver;
-    AsyncResultReceiver                     mScheduleMigrationReceiver;
-    std::vector<DetachGracefullyCallback>   mDetachGracefullyCallbacks;
+    std::vector<ThreadStateChangedCallback>       mThreadStateChangedCallbacks;
+    std::vector<ThreadEnabledStateCallback>       mThreadEnabledStateChangedCallbacks;
+    bool                                          mEnableAutoAttach = false;
+    ThreadEnabledState                            mThreadEnabledState;
+    AsyncResultReceiver                           mJoinReceiver;
+    AsyncResultReceiver                           mSetThreadEnabledReceiver;
+    AsyncResultReceiver                           mScheduleMigrationReceiver;
+    std::vector<DetachGracefullyCallback>         mDetachGracefullyCallbacks;
+    BorderAgentMeshCoPServiceChangedCallback      mBorderAgentMeshCoPServiceChangedCallback;
+    std::vector<EphemeralKeyStateChangedCallback> mEphemeralKeyStateChangedCallbacks;
 
 #if OTBR_ENABLE_FEATURE_FLAGS
     // The applied FeatureFlagList in ApplyFeatureFlagList call, used for debugging purpose.
diff --git a/src/host/thread_host.hpp b/src/host/thread_host.hpp
index 6fc45d2d..f8dbef6b 100644
--- a/src/host/thread_host.hpp
+++ b/src/host/thread_host.hpp
@@ -37,6 +37,8 @@
 #include <functional>
 #include <memory>
 
+#include <openthread/backbone_router_ftd.h>
+#include <openthread/border_agent.h>
 #include <openthread/dataset.h>
 #include <openthread/error.h>
 #include <openthread/thread.h>
@@ -44,6 +46,7 @@
 #include "lib/spinel/coprocessor_type.h"
 
 #include "common/logging.hpp"
+#include "posix/udp_proxy.hpp"
 
 namespace otbr {
 namespace Host {
@@ -92,6 +95,13 @@ public:
      */
     virtual void GetDatasetPendingTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const = 0;
 
+    /**
+     * Returns the meshlocal prefix.
+     *
+     * @returns The mesh local prefix.
+     */
+    virtual const otMeshLocalPrefix *GetMeshLocalPrefix(void) const = 0;
+
     /**
      * The destructor.
      */
@@ -112,15 +122,21 @@ enum ThreadEnabledState
  *
  * The APIs are unified for both NCP and RCP cases.
  */
-class ThreadHost : virtual public NetworkProperties
+class ThreadHost : virtual public NetworkProperties, public UdpProxy::Dependencies
 {
 public:
     using AsyncResultReceiver = std::function<void(otError, const std::string &)>;
     using ChannelMasksReceiver =
         std::function<void(uint32_t /*aSupportedChannelMask*/, uint32_t /*aPreferredChannelMask*/)>;
-    using DeviceRoleHandler          = std::function<void(otError, otDeviceRole)>;
-    using ThreadStateChangedCallback = std::function<void(otChangedFlags aFlags)>;
-    using ThreadEnabledStateCallback = std::function<void(ThreadEnabledState aState)>;
+    using DeviceRoleHandler                        = std::function<void(otError, otDeviceRole)>;
+    using ThreadStateChangedCallback               = std::function<void(otChangedFlags)>;
+    using ThreadEnabledStateCallback               = std::function<void(ThreadEnabledState)>;
+    using BorderAgentMeshCoPServiceChangedCallback = std::function<void(bool, uint16_t, const uint8_t *, uint16_t)>;
+    using EphemeralKeyStateChangedCallback         = std::function<void(otBorderAgentEphemeralKeyState, uint16_t)>;
+    using UdpForwardToHostCallback = std::function<void(const uint8_t *, uint16_t, const otIp6Address &, uint16_t)>;
+    using BackboneRouterMulticastListenerCallback =
+        std::function<void(otBackboneRouterMulticastListenerEvent, Ip6Address)>;
+    using BackboneRouterStateChangedCallback = std::function<void(otBackboneRouterState)>;
 
     struct ChannelMaxPower
     {
@@ -249,6 +265,51 @@ public:
      */
     virtual void AddThreadEnabledStateChangedCallback(ThreadEnabledStateCallback aCallback) = 0;
 
+    /**
+     * This method sets a callback that will be invoked when there are any changes on the MeshCoP service from
+     * Thread core.
+     *
+     * @param[in] aCallback  The callback function.
+     */
+    virtual void SetBorderAgentMeshCoPServiceChangedCallback(BorderAgentMeshCoPServiceChangedCallback aCallback) = 0;
+
+    /**
+     * This method adds a callback that will be invoked when there are any changes related to the ephemeral key.
+     *
+     * @param[in] aCallback  The callback function.
+     */
+    virtual void AddEphemeralKeyStateChangedCallback(EphemeralKeyStateChangedCallback aCallback) = 0;
+
+    /**
+     * This methods a callback for the Thread stack to forward UDP packet to the host.
+     *
+     * @param[in] aCallback  The callback function.
+     */
+    virtual void SetUdpForwardToHostCallback(UdpForwardToHostCallback aCallback) = 0;
+
+#if OTBR_ENABLE_BACKBONE_ROUTER
+    /**
+     * This method enables/disables the Backbone Router.
+     *
+     * @param[in] aEnabled  Whether to enable or disable the Backbone router.
+     */
+    virtual void SetBackboneRouterEnabled(bool aEnabled) = 0;
+
+    /**
+     * This method sets the Backbone Router Multicast Listener callback.
+     *
+     * @param[in] aCallback  The Multicast Listener callback.
+     */
+    virtual void SetBackboneRouterMulticastListenerCallback(BackboneRouterMulticastListenerCallback aCallback) = 0;
+
+    /**
+     * This method sets the Backbone Router state change callback.
+     *
+     * @param[in] aCallback  The Backbone Router state change callback.
+     */
+    virtual void SetBackboneRouterStateChangedCallback(BackboneRouterStateChangedCallback aCallback) = 0;
+#endif // OTBR_ENABLE_BACKBONE_ROUTER
+
     /**
      * Returns the co-processor type.
      */
diff --git a/src/mdns/mdns.cpp b/src/mdns/mdns.cpp
index 7fd050c4..720abd8e 100644
--- a/src/mdns/mdns.cpp
+++ b/src/mdns/mdns.cpp
@@ -766,7 +766,12 @@ void Publisher::UpdateHostResolutionEmaLatency(const std::string &aHostName, otb
 
 void Publisher::AddAddress(AddressList &aAddressList, const Ip6Address &aAddress)
 {
-    aAddressList.push_back(aAddress);
+    auto it = std::find(aAddressList.begin(), aAddressList.end(), aAddress);
+
+    if (it == aAddressList.end())
+    {
+        aAddressList.push_back(aAddress);
+    }
 }
 
 void Publisher::RemoveAddress(AddressList &aAddressList, const Ip6Address &aAddress)
diff --git a/src/mdns/mdns_avahi.cpp b/src/mdns/mdns_avahi.cpp
index 548bad5f..fe092ca3 100644
--- a/src/mdns/mdns_avahi.cpp
+++ b/src/mdns/mdns_avahi.cpp
@@ -1367,20 +1367,36 @@ void PublisherAvahi::ServiceResolver::HandleResolveHostResult(AvahiRecordBrowser
     OTBR_UNUSED_VARIABLE(aRecordBrowser);
     OTBR_UNUSED_VARIABLE(aInterfaceIndex);
     OTBR_UNUSED_VARIABLE(aProtocol);
-    OTBR_UNUSED_VARIABLE(aEvent);
     OTBR_UNUSED_VARIABLE(aClazz);
     OTBR_UNUSED_VARIABLE(aType);
     OTBR_UNUSED_VARIABLE(aFlags);
 
     Ip6Address address;
-    bool       resolved   = false;
-    int        avahiError = AVAHI_OK;
+    bool       shouldReport = false;
+    int        avahiError   = AVAHI_OK;
 
     otbrLog(aEvent != AVAHI_BROWSER_FAILURE ? OTBR_LOG_INFO : OTBR_LOG_WARNING, OTBR_LOG_TAG,
             "Resolve host reply: %s inf %d protocol %d class %" PRIu16 " type %" PRIu16 " size %zu flags %d event %d",
             aName, aInterfaceIndex, aProtocol, aClazz, aType, aSize, static_cast<int>(aFlags),
             static_cast<int>(aEvent));
 
+    if (aEvent == AVAHI_BROWSER_ALL_FOR_NOW)
+    {
+        // The `AVAHI_BROWSER_ALL_FOR_NOW` event is a one-time event to
+        // notify the user that more records will probably not appear
+        // in the near future. When the browser is initially started,
+        // we wait for this event before marking `mResolved` and
+        // invoking `OnServiceResolved()`. This ensures that we wait and
+        // collect all discovered IPv6 addresses. Afterwards, if there
+        // are new events updating the addresses (adding or removing an
+        // address), we invoke the callback providing the full updated
+        // address list on each such event.
+
+        mResolved    = true;
+        shouldReport = true;
+        ExitNow();
+    }
+
     VerifyOrExit(aEvent == AVAHI_BROWSER_NEW || aEvent == AVAHI_BROWSER_REMOVE);
     VerifyOrExit(aSize == OTBR_IP6_ADDRESS_SIZE || aSize == OTBR_IP4_ADDRESS_SIZE,
                  otbrLogErr("Unexpected address data length: %zu", aSize), avahiError = AVAHI_ERR_INVALID_ADDRESS);
@@ -1400,10 +1416,11 @@ void PublisherAvahi::ServiceResolver::HandleResolveHostResult(AvahiRecordBrowser
     {
         mInstanceInfo.RemoveAddress(address);
     }
-    resolved = true;
+
+    shouldReport = true;
 
 exit:
-    if (resolved)
+    if (mResolved && shouldReport)
     {
         // NOTE: This `HostSubscrption` object may be freed in `OnHostResolved`.
         mPublisherAvahi->OnServiceResolved(mType, mInstanceInfo);
@@ -1498,20 +1515,36 @@ void PublisherAvahi::HostSubscription::HandleResolveResult(AvahiRecordBrowser
 {
     OTBR_UNUSED_VARIABLE(aRecordBrowser);
     OTBR_UNUSED_VARIABLE(aProtocol);
-    OTBR_UNUSED_VARIABLE(aEvent);
     OTBR_UNUSED_VARIABLE(aClazz);
     OTBR_UNUSED_VARIABLE(aType);
     OTBR_UNUSED_VARIABLE(aFlags);
 
     Ip6Address address;
-    bool       resolved   = false;
-    int        avahiError = AVAHI_OK;
+    bool       shouldReport = false;
+    int        avahiError   = AVAHI_OK;
 
     otbrLog(aEvent != AVAHI_BROWSER_FAILURE ? OTBR_LOG_INFO : OTBR_LOG_WARNING, OTBR_LOG_TAG,
             "Resolve host reply: %s inf %d protocol %d class %" PRIu16 " type %" PRIu16 " size %zu flags %d event %d",
             aName, aInterfaceIndex, aProtocol, aClazz, aType, aSize, static_cast<int>(aFlags),
             static_cast<int>(aEvent));
 
+    if (aEvent == AVAHI_BROWSER_ALL_FOR_NOW)
+    {
+        // The `AVAHI_BROWSER_ALL_FOR_NOW` event is a one-time event to
+        // notify the user that more records will probably not appear
+        // in the near future. When the browser is initially started,
+        // we wait for this event before marking `mResolved` and
+        // invoking `OnHostResolved()`. This ensures that we wait and
+        // collect all discovered IPv6 addresses. Afterwards, if there
+        // are new events updating the addresses (adding or removing an
+        // address), we invoke the callback providing the full updated
+        // address list on each such event.
+
+        shouldReport = true;
+        mResolved    = true;
+        ExitNow();
+    }
+
     VerifyOrExit(aEvent == AVAHI_BROWSER_NEW || aEvent == AVAHI_BROWSER_REMOVE);
     VerifyOrExit(aSize == OTBR_IP6_ADDRESS_SIZE || aSize == OTBR_IP4_ADDRESS_SIZE,
                  otbrLogErr("Unexpected address data length: %zu", aSize), avahiError = AVAHI_ERR_INVALID_ADDRESS);
@@ -1536,10 +1569,11 @@ void PublisherAvahi::HostSubscription::HandleResolveResult(AvahiRecordBrowser
     mHostInfo.mNetifIndex = static_cast<uint32_t>(aInterfaceIndex);
     // TODO: Use a more proper TTL
     mHostInfo.mTtl = kDefaultTtl;
-    resolved       = true;
+
+    shouldReport = true;
 
 exit:
-    if (resolved)
+    if (mResolved && shouldReport)
     {
         // NOTE: This `HostSubscrption` object may be freed in `OnHostResolved`.
         mPublisherAvahi->OnHostResolved(mHostName, mHostInfo);
diff --git a/src/mdns/mdns_avahi.hpp b/src/mdns/mdns_avahi.hpp
index 5a76ca24..49db8df6 100644
--- a/src/mdns/mdns_avahi.hpp
+++ b/src/mdns/mdns_avahi.hpp
@@ -196,6 +196,7 @@ private:
             : Subscription(aAvahiPublisher)
             , mHostName(std::move(aHostName))
             , mRecordBrowser(nullptr)
+            , mResolved(false)
         {
         }
 
@@ -229,6 +230,7 @@ private:
         std::string         mHostName;
         DiscoveredHostInfo  mHostInfo;
         AvahiRecordBrowser *mRecordBrowser;
+        bool                mResolved;
     };
 
     struct ServiceResolver
@@ -300,6 +302,7 @@ private:
         AvahiServiceResolver  *mServiceResolver = nullptr;
         AvahiRecordBrowser    *mRecordBrowser   = nullptr;
         DiscoveredInstanceInfo mInstanceInfo;
+        bool                   mResolved = false;
     };
     struct ServiceSubscription : public Subscription
     {
diff --git a/src/openwrt/otbr-agent.uci-config.in b/src/openwrt/otbr-agent.uci-config.in
index 855d7088..eb18eda2 100644
--- a/src/openwrt/otbr-agent.uci-config.in
+++ b/src/openwrt/otbr-agent.uci-config.in
@@ -2,4 +2,4 @@ config otbr-agent 'service'
 	option thread_if_name "wpan0"
 	option infra_if_name "eth0"
 	option uart_device "/dev/ttyACM0"
-	option uart_baudrate 115200
+	option uart_baudrate 460800
diff --git a/src/proto/thread_telemetry.proto b/src/proto/thread_telemetry.proto
index f8ef9f4f..34153022 100644
--- a/src/proto/thread_telemetry.proto
+++ b/src/proto/thread_telemetry.proto
@@ -563,9 +563,35 @@ message TelemetryData {
     optional uint32 mgmt_pending_get_reqs = 16;
   }
 
+  enum EpskcDeactivatedReason {
+      EPSKC_DEACTIVATED_REASON_UNKNOWN = 0;         ///< Deactivated for an unknown reason.
+      EPSKC_DEACTIVATED_REASON_LOCAL_CLOSE = 1;     ///< Deactivated by a call to the API.
+      EPSKC_DEACTIVATED_REASON_REMOTE_CLOSE = 2;    ///< Disconnected by the peer.
+      EPSKC_DEACTIVATED_REASON_SESSION_ERROR = 3;   ///< Disconnected due to some error.
+      EPSKC_DEACTIVATED_REASON_SESSION_TIMEOUT = 4; ///< Disconnected due to timeout.
+      EPSKC_DEACTIVATED_REASON_MAX_ATTEMPTS = 5;    ///< Max allowed attempts reached.
+      EPSKC_DEACTIVATED_REASON_EPSKC_TIMEOUT = 6;   ///< The ePSKc mode timed out.
+  }
+
+  message BorderAgentEpskcJourneyInfo {
+
+      // The timestamp of different events during the ePSKc journey.
+      optional uint32 activated_msec = 1;
+      optional uint32 connected_msec = 2;
+      optional uint32 petitioned_msec = 3;
+      optional uint32 retrieved_active_dataset_msec = 4;
+      optional uint32 retrieved_pending_dataset_msec = 5;
+      optional uint32 keep_alive_msec = 6;
+      optional uint32 deactivated_msec = 7;
+      optional EpskcDeactivatedReason deactivated_reason = 8;
+  }
+
   message BorderAgentInfo {
     // The border agent counters
     optional BorderAgentCounters border_agent_counters = 1;
+
+    // The border agent epskc journey info
+    repeated BorderAgentEpskcJourneyInfo border_agent_epskc_journey_info = 2;
   }
 
   message WpanBorderRouter {
diff --git a/src/proto/threadnetwork_atoms.proto b/src/proto/threadnetwork_atoms.proto
index 29980765..04dc24c3 100644
--- a/src/proto/threadnetwork_atoms.proto
+++ b/src/proto/threadnetwork_atoms.proto
@@ -481,6 +481,9 @@ message ThreadnetworkTelemetryDataReported {
 
     // Information about the Border Agent
     optional BorderAgentInfo border_agent_info = 7;
+
+    // Whether multi-AIL is detected.
+    optional bool multi_ail_detected = 8;
   }
 
   message RcpStabilityStatistics {
diff --git a/src/trel_dnssd/trel_dnssd.cpp b/src/trel_dnssd/trel_dnssd.cpp
index c64d3a30..47346f88 100644
--- a/src/trel_dnssd/trel_dnssd.cpp
+++ b/src/trel_dnssd/trel_dnssd.cpp
@@ -301,25 +301,22 @@ void TrelDnssd::OnTrelServiceInstanceAdded(const Mdns::Publisher::DiscoveredInst
     {
         otbrLogDebug("Peer address: %s", addr.ToString().c_str());
 
-        // Skip anycast (Refer to https://datatracker.ietf.org/doc/html/rfc2373#section-2.6.1)
-        if (addr.m64[1] == 0)
+        // Require link-local. Thread requires TREL peers to advertise link-local via mDNS.
+        if (!addr.IsLinkLocal())
         {
             continue;
         }
 
-        // If there are multiple addresses, we prefer the address
-        // which is numerically smallest. This prefers GUA over ULA
-        // (`fc00::/7`) and then link-local (`fe80::/10`).
-
+        // Pick the smallest link-local to be robust to reorderings.
         if (selectedAddress.IsUnspecified() || (addr < selectedAddress))
         {
             selectedAddress = addr;
         }
     }
 
-    if (aInstanceInfo.mAddresses.empty())
+    if (selectedAddress.IsUnspecified())
     {
-        otbrLogWarning("Peer %s does not have any IPv6 address, ignored", aInstanceInfo.mName.c_str());
+        otbrLogWarning("Peer %s does not have any IPv6 link-local address, ignored", aInstanceInfo.mName.c_str());
         ExitNow();
     }
 
diff --git a/src/utils/CMakeLists.txt b/src/utils/CMakeLists.txt
index 4f9c4202..d049b9e6 100644
--- a/src/utils/CMakeLists.txt
+++ b/src/utils/CMakeLists.txt
@@ -37,6 +37,7 @@ add_library(otbr-utils
     steering_data.cpp
     string_utils.cpp
     system_utils.cpp
+    telemetry_retriever_border_agent.cpp
     thread_helper.cpp
     thread_helper.hpp
 )
diff --git a/src/utils/telemetry_retriever_border_agent.cpp b/src/utils/telemetry_retriever_border_agent.cpp
new file mode 100644
index 00000000..36565b19
--- /dev/null
+++ b/src/utils/telemetry_retriever_border_agent.cpp
@@ -0,0 +1,204 @@
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
+#if OTBR_ENABLE_TELEMETRY_DATA_API && OTBR_ENABLE_BORDER_AGENT
+
+#define OTBR_LOG_TAG "UTILS"
+
+#include "utils/telemetry_retriever_border_agent.hpp"
+
+#include <algorithm>
+
+#include <openthread/history_tracker.h>
+#include <openthread/platform/alarm-milli.h>
+
+#include "common/logging.hpp"
+
+namespace otbr {
+namespace agent {
+namespace TelemetryRetriever {
+
+BorderAgent::BorderAgent(otInstance *aInstance)
+    : mInstance(aInstance)
+    , mEpskcLastRetrievedTimestamp(0)
+{
+}
+
+void BorderAgent::RetrieveEpskcJourneyInfo(threadnetwork::TelemetryData::BorderAgentInfo *aBorderAgentInfo)
+{
+    const auto                                               &unRetrievedEpskcEvents = GetUnretrievedEpskcEvents();
+    threadnetwork::TelemetryData_BorderAgentEpskcJourneyInfo *epskcJourney           = nullptr;
+    bool                                                      journeyCompleted       = true;
+
+    for (size_t i = 0; i < unRetrievedEpskcEvents.size(); i++)
+    {
+        if (journeyCompleted)
+        {
+            epskcJourney     = aBorderAgentInfo->add_border_agent_epskc_journey_info();
+            journeyCompleted = false;
+        }
+
+        switch (unRetrievedEpskcEvents[i].first)
+        {
+        case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_ACTIVATED:
+            epskcJourney->set_activated_msec(unRetrievedEpskcEvents[i].second);
+            break;
+        case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_CONNECTED:
+            epskcJourney->set_connected_msec(unRetrievedEpskcEvents[i].second);
+            break;
+        case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_PETITIONED:
+            epskcJourney->set_petitioned_msec(unRetrievedEpskcEvents[i].second);
+            break;
+        case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_RETRIEVED_ACTIVE_DATASET:
+            epskcJourney->set_retrieved_active_dataset_msec(unRetrievedEpskcEvents[i].second);
+            break;
+        case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_RETRIEVED_PENDING_DATASET:
+            epskcJourney->set_retrieved_pending_dataset_msec(unRetrievedEpskcEvents[i].second);
+            break;
+        case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_KEEP_ALIVE:
+            epskcJourney->set_keep_alive_msec(unRetrievedEpskcEvents[i].second);
+            break;
+        case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_LOCAL_CLOSE:
+            epskcJourney->set_deactivated_reason(threadnetwork::TelemetryData::EPSKC_DEACTIVATED_REASON_LOCAL_CLOSE);
+            break;
+        case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_REMOTE_CLOSE:
+            epskcJourney->set_deactivated_reason(threadnetwork::TelemetryData::EPSKC_DEACTIVATED_REASON_REMOTE_CLOSE);
+            break;
+        case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_SESSION_ERROR:
+            epskcJourney->set_deactivated_reason(threadnetwork::TelemetryData::EPSKC_DEACTIVATED_REASON_SESSION_ERROR);
+            break;
+        case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_SESSION_TIMEOUT:
+            epskcJourney->set_deactivated_reason(
+                threadnetwork::TelemetryData::EPSKC_DEACTIVATED_REASON_SESSION_TIMEOUT);
+            break;
+        case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_MAX_ATTEMPTS:
+            epskcJourney->set_deactivated_reason(threadnetwork::TelemetryData::EPSKC_DEACTIVATED_REASON_MAX_ATTEMPTS);
+            break;
+        case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_EPSKC_TIMEOUT:
+            epskcJourney->set_deactivated_reason(threadnetwork::TelemetryData::EPSKC_DEACTIVATED_REASON_EPSKC_TIMEOUT);
+            break;
+        case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_UNKNOWN:
+            epskcJourney->set_deactivated_reason(threadnetwork::TelemetryData::EPSKC_DEACTIVATED_REASON_UNKNOWN);
+            break;
+        default:
+            // Unexpected event type, log a warning.
+            otbrLogWarning("Unexpected ePSKc event type: %d", unRetrievedEpskcEvents[i].first);
+            break;
+        }
+
+        if (IsEpskcDeactivationEvent(unRetrievedEpskcEvents[i].first))
+        {
+            epskcJourney->set_deactivated_msec(unRetrievedEpskcEvents[i].second);
+            journeyCompleted = true;
+        }
+    }
+}
+
+bool BorderAgent::IsEpskcDeactivationEvent(const otHistoryTrackerBorderAgentEpskcEvent &aEvent)
+{
+    bool result = false;
+
+    switch (aEvent)
+    {
+    case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_ACTIVATED:
+    case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_CONNECTED:
+    case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_PETITIONED:
+    case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_RETRIEVED_ACTIVE_DATASET:
+    case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_RETRIEVED_PENDING_DATASET:
+    case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_KEEP_ALIVE:
+        result = false;
+        break;
+    case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_LOCAL_CLOSE:
+    case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_REMOTE_CLOSE:
+    case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_SESSION_ERROR:
+    case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_SESSION_TIMEOUT:
+    case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_MAX_ATTEMPTS:
+    case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_EPSKC_TIMEOUT:
+    case OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_UNKNOWN:
+        result = true;
+        break;
+    default:
+        result = false;
+        otbrLogWarning("Unexpected ePSKc event type: %d", aEvent);
+        break;
+    }
+
+    return result;
+}
+
+std::vector<std::pair<otHistoryTrackerBorderAgentEpskcEvent, uint32_t>> BorderAgent::GetUnretrievedEpskcEvents(void)
+{
+    std::vector<std::pair<otHistoryTrackerBorderAgentEpskcEvent, uint32_t>> unRetrievedEvents;
+
+    const otHistoryTrackerBorderAgentEpskcEvent *epskcJourney = nullptr;
+    otHistoryTrackerIterator                     iter;
+    uint32_t                                     age;
+    uint32_t                                     curTimestamp;
+
+    otHistoryTrackerInitIterator(&iter);
+    curTimestamp = otPlatAlarmMilliGetNow();
+
+    while ((epskcJourney = otHistoryTrackerIterateBorderAgentEpskcEventHistory(mInstance, &iter, &age)) != nullptr)
+    {
+        /*
+         *       event   event   last retrieve time T1             current time T2
+         *         ^       ^             ^                              ^
+         * | ----- x ----- x ----------- | ------------ x ----- x ----- |
+         *                                              ^
+         *                                          age < T2 - T1
+         */
+        if (age < curTimestamp - mEpskcLastRetrievedTimestamp)
+        {
+            unRetrievedEvents.push_back({*epskcJourney, curTimestamp - age});
+        }
+        else
+        {
+            break;
+        }
+    }
+
+    std::reverse(unRetrievedEvents.begin(), unRetrievedEvents.end());
+
+    ///< Ensure the events retrieved make up a complete journey. The remaining events will be uploaded next time.
+    while (!unRetrievedEvents.empty() && !IsEpskcDeactivationEvent(unRetrievedEvents.back().first))
+    {
+        unRetrievedEvents.pop_back();
+    }
+    if (!unRetrievedEvents.empty())
+    {
+        mEpskcLastRetrievedTimestamp = unRetrievedEvents.back().second;
+    }
+
+    return unRetrievedEvents;
+}
+
+} // namespace TelemetryRetriever
+} // namespace agent
+} // namespace otbr
+
+#endif // OTBR_ENABLE_TELEMETRY_DATA_API && OTBR_ENABLE_BORDER_AGENT
diff --git a/src/utils/telemetry_retriever_border_agent.hpp b/src/utils/telemetry_retriever_border_agent.hpp
new file mode 100644
index 00000000..592a46cc
--- /dev/null
+++ b/src/utils/telemetry_retriever_border_agent.hpp
@@ -0,0 +1,61 @@
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
+#if OTBR_ENABLE_TELEMETRY_DATA_API && OTBR_ENABLE_BORDER_AGENT
+
+#include <utility>
+#include <vector>
+
+#include <openthread/history_tracker.h>
+#include <openthread/instance.h>
+
+#include "proto/thread_telemetry.pb.h"
+
+namespace otbr {
+namespace agent {
+namespace TelemetryRetriever {
+
+class BorderAgent
+{
+public:
+    explicit BorderAgent(otInstance *aInstance);
+    void RetrieveEpskcJourneyInfo(threadnetwork::TelemetryData::BorderAgentInfo *aBorderAgentInfo);
+
+private:
+    bool IsEpskcDeactivationEvent(const otHistoryTrackerBorderAgentEpskcEvent &aEvent);
+    std::vector<std::pair<otHistoryTrackerBorderAgentEpskcEvent, uint32_t>> GetUnretrievedEpskcEvents(void);
+
+    otInstance *mInstance;
+    uint32_t    mEpskcLastRetrievedTimestamp;
+};
+
+} // namespace TelemetryRetriever
+} // namespace agent
+} // namespace otbr
+
+#endif // OTBR_ENABLE_TELEMETRY_DATA_API && OTBR_ENABLE_BORDER_AGENT
diff --git a/src/utils/thread_helper.cpp b/src/utils/thread_helper.cpp
index 9866225a..31534656 100644
--- a/src/utils/thread_helper.cpp
+++ b/src/utils/thread_helper.cpp
@@ -55,7 +55,7 @@
 #if OTBR_ENABLE_LINK_METRICS_TELEMETRY
 #include <openthread/link_metrics.h>
 #endif
-#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+#if OTBR_ENABLE_SRP_SERVER
 #include <openthread/srp_server.h>
 #endif
 #include <openthread/thread_ftd.h>
@@ -132,7 +132,7 @@ static uint32_t TelemetryNodeTypeFromRoleAndLinkMode(const otDeviceRole &aRole,
     return nodeType;
 }
 
-#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+#if OTBR_ENABLE_SRP_SERVER
 threadnetwork::TelemetryData_SrpServerState SrpServerStateFromOtSrpServerState(otSrpServerState srpServerState)
 {
     switch (srpServerState)
@@ -161,7 +161,7 @@ threadnetwork::TelemetryData_SrpServerAddressMode SrpServerAddressModeFromOtSrpS
         return threadnetwork::TelemetryData::SRP_SERVER_ADDRESS_MODE_UNSPECIFIED;
     }
 }
-#endif // OTBR_ENABLE_SRP_ADVERTISING_PROXY
+#endif // OTBR_ENABLE_SRP_SERVER
 
 #if OTBR_ENABLE_NAT64
 threadnetwork::TelemetryData_Nat64State Nat64StateFromOtNat64State(otNat64State nat64State)
@@ -231,6 +231,9 @@ void CopyMdnsResponseCounters(const MdnsResponseCounters &from, threadnetwork::T
 ThreadHelper::ThreadHelper(otInstance *aInstance, otbr::Host::RcpHost *aHost)
     : mInstance(aInstance)
     , mHost(aHost)
+#if OTBR_ENABLE_TELEMETRY_DATA_API && OTBR_ENABLE_BORDER_AGENT
+    , mTelemetryRetriverBorderAgent(aInstance)
+#endif
 {
 #if OTBR_ENABLE_TELEMETRY_DATA_API && (OTBR_ENABLE_NAT64 || OTBR_ENABLE_DHCP6_PD)
     otError error;
@@ -329,20 +332,6 @@ exit:
     }
 }
 
-#if OTBR_ENABLE_DBUS_SERVER
-void ThreadHelper::OnUpdateMeshCopTxt(std::map<std::string, std::vector<uint8_t>> aUpdate)
-{
-    if (mUpdateMeshCopTxtHandler)
-    {
-        mUpdateMeshCopTxtHandler(std::move(aUpdate));
-    }
-    else
-    {
-        otbrLogErr("No UpdateMeshCopTxtHandler");
-    }
-}
-#endif
-
 void ThreadHelper::AddDeviceRoleHandler(DeviceRoleHandler aHandler)
 {
     mDeviceRoleHandlers.emplace_back(aHandler);
@@ -1084,8 +1073,10 @@ void ThreadHelper::RetrieveBorderAgentInfo(threadnetwork::TelemetryData::BorderA
 
     baCounters->set_mgmt_active_get_reqs(otBorderAgentCounters.mMgmtActiveGets);
     baCounters->set_mgmt_pending_get_reqs(otBorderAgentCounters.mMgmtPendingGets);
+
+    mTelemetryRetriverBorderAgent.RetrieveEpskcJourneyInfo(aBorderAgentInfo);
 }
-#endif
+#endif // OTBR_ENABLE_BORDER_AGENT
 
 otError ThreadHelper::RetrieveTelemetryData(Mdns::Publisher *aPublisher, threadnetwork::TelemetryData &telemetryData)
 {
@@ -1438,7 +1429,7 @@ otError ThreadHelper::RetrieveTelemetryData(Mdns::Publisher *aPublisher, threadn
         RetrieveExternalRouteInfo(*wpanBorderRouter->mutable_external_route_info());
 #endif
 
-#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+#if OTBR_ENABLE_SRP_SERVER
         // Begin of SrpServerInfo section.
         {
             auto                               srpServer = wpanBorderRouter->mutable_srp_server();
@@ -1506,7 +1497,7 @@ otError ThreadHelper::RetrieveTelemetryData(Mdns::Publisher *aPublisher, threadn
             srpServerResponseCounters->set_other_count(responseCounters->mOther);
         }
         // End of SrpServerInfo section.
-#endif // OTBR_ENABLE_SRP_ADVERTISING_PROXY
+#endif // OTBR_ENABLE_SRP_SERVER
 
 #if OTBR_ENABLE_DNSSD_DISCOVERY_PROXY
         // Begin of DnsServerInfo section.
diff --git a/src/utils/thread_helper.hpp b/src/utils/thread_helper.hpp
index 2e2de91e..a110f17f 100644
--- a/src/utils/thread_helper.hpp
+++ b/src/utils/thread_helper.hpp
@@ -53,6 +53,7 @@
 #include "mdns/mdns.hpp"
 #if OTBR_ENABLE_TELEMETRY_DATA_API
 #include "proto/thread_telemetry.pb.h"
+#include "utils/telemetry_retriever_border_agent.hpp"
 #endif
 
 namespace otbr {
@@ -235,25 +236,6 @@ public:
      */
     void StateChangedCallback(otChangedFlags aFlags);
 
-#if OTBR_ENABLE_DBUS_SERVER
-    /**
-     * This method sets a callback for calls of UpdateVendorMeshCopTxtEntries D-Bus API.
-     *
-     * @param[in] aHandler  The handler on MeshCoP TXT changes.
-     */
-    void SetUpdateMeshCopTxtHandler(UpdateMeshCopTxtHandler aHandler)
-    {
-        mUpdateMeshCopTxtHandler = std::move(aHandler);
-    }
-
-    /**
-     * This method handles MeshCoP TXT updates done by UpdateVendorMeshCopTxtEntries D-Bus API.
-     *
-     * @param[in] aUpdate  The key-value pairs to be updated in the TXT record.
-     */
-    void OnUpdateMeshCopTxt(std::map<std::string, std::vector<uint8_t>> aUpdate);
-#endif
-
     void DetachGracefully(ResultHandler aHandler);
 
 #if OTBR_ENABLE_TELEMETRY_DATA_API
@@ -368,14 +350,15 @@ private:
     Dhcp6PdStateCallback mDhcp6PdCallback;
 #endif
 
-#if OTBR_ENABLE_DBUS_SERVER
-    UpdateMeshCopTxtHandler mUpdateMeshCopTxtHandler;
-#endif
-
-#if OTBR_ENABLE_TELEMETRY_DATA_API && (OTBR_ENABLE_NAT64 || OTBR_ENABLE_DHCP6_PD)
+#if OTBR_ENABLE_TELEMETRY_DATA_API
+#if (OTBR_ENABLE_NAT64 || OTBR_ENABLE_DHCP6_PD)
     static constexpr uint8_t kNat64PdCommonHashSaltLength = 16;
     uint8_t                  mNat64PdCommonSalt[kNat64PdCommonHashSaltLength];
 #endif
+#if OTBR_ENABLE_BORDER_AGENT
+    TelemetryRetriever::BorderAgent mTelemetryRetriverBorderAgent;
+#endif
+#endif
 };
 
 } // namespace agent
diff --git a/src/web/web-service/wpan_service.cpp b/src/web/web-service/wpan_service.cpp
index ae934ff9..e00c3b7a 100644
--- a/src/web/web-service/wpan_service.cpp
+++ b/src/web/web-service/wpan_service.cpp
@@ -55,7 +55,7 @@ namespace Web {
 std::string WpanService::HandleGetQRCodeRequest()
 {
     Json::Value                 root, networkInfo;
-    Json::FastWriter            jsonWriter;
+    Json::StreamWriterBuilder   writerBuilder;
     std::string                 response;
     int                         ret = kWpanStatus_Ok;
     otbr::Web::OpenThreadClient client(mIfName);
@@ -81,29 +81,31 @@ exit:
         otbrLogErr("Wpan service error: %d", ret);
     }
 
-    response = jsonWriter.write(root);
+    response = Json::writeString(writerBuilder, root);
     return response;
 }
 
 std::string WpanService::HandleJoinNetworkRequest(const std::string &aJoinRequest)
 {
-    Json::Value                 root;
-    Json::Reader                reader;
-    Json::FastWriter            jsonWriter;
-    std::string                 response;
-    int                         index;
-    std::string                 credentialType;
-    std::string                 networkKey;
-    std::string                 pskd;
-    std::string                 prefix;
-    bool                        defaultRoute;
-    int                         ret = kWpanStatus_Ok;
-    otbr::Web::OpenThreadClient client(mIfName);
-    char                       *rval;
+    Json::Value                       root;
+    Json::CharReaderBuilder           readerBuilder;
+    std::unique_ptr<Json::CharReader> reader(readerBuilder.newCharReader());
+    Json::StreamWriterBuilder         writerBuilder;
+    std::string                       response;
+    int                               index;
+    std::string                       credentialType;
+    std::string                       networkKey;
+    std::string                       pskd;
+    std::string                       prefix;
+    bool                              defaultRoute;
+    int                               ret = kWpanStatus_Ok;
+    otbr::Web::OpenThreadClient       client(mIfName);
+    char                             *rval;
 
     VerifyOrExit(client.Connect(), ret = kWpanStatus_SetFailed);
 
-    VerifyOrExit(reader.parse(aJoinRequest.c_str(), root) == true, ret = kWpanStatus_ParseRequestFailed);
+    VerifyOrExit(reader->parse(aJoinRequest.c_str(), aJoinRequest.c_str() + aJoinRequest.size(), &root, nullptr),
+                 ret = kWpanStatus_ParseRequestFailed);
     index          = root["index"].asUInt();
     credentialType = root["credentialType"].asString();
     networkKey     = root["networkKey"].asString();
@@ -177,34 +179,36 @@ exit:
         root["message"] = "Please make sure the provided PSKd matches the one given to the commissioner.";
     }
 
-    response = jsonWriter.write(root);
+    response = Json::writeString(writerBuilder, root);
     return response;
 }
 
 std::string WpanService::HandleFormNetworkRequest(const std::string &aFormRequest)
 {
-    Json::Value                 root;
-    Json::FastWriter            jsonWriter;
-    Json::Reader                reader;
-    std::string                 response;
-    otbr::Psk::Pskc             psk;
-    char                        pskcStr[OT_PSKC_MAX_LENGTH * 2 + 1];
-    uint8_t                     extPanIdBytes[OT_EXTENDED_PANID_LENGTH];
-    std::string                 networkKey;
-    std::string                 prefix;
-    uint16_t                    channel;
-    std::string                 networkName;
-    std::string                 passphrase;
-    uint16_t                    panId;
-    uint64_t                    extPanId;
-    bool                        defaultRoute;
-    int                         ret = kWpanStatus_Ok;
-    otbr::Web::OpenThreadClient client(mIfName);
+    Json::Value                       root;
+    Json::StreamWriterBuilder         writerBuilder;
+    Json::CharReaderBuilder           readerBuilder;
+    std::unique_ptr<Json::CharReader> reader(readerBuilder.newCharReader());
+    std::string                       response;
+    otbr::Psk::Pskc                   psk;
+    char                              pskcStr[OT_PSKC_MAX_LENGTH * 2 + 1];
+    uint8_t                           extPanIdBytes[OT_EXTENDED_PANID_LENGTH];
+    std::string                       networkKey;
+    std::string                       prefix;
+    uint16_t                          channel;
+    std::string                       networkName;
+    std::string                       passphrase;
+    uint16_t                          panId;
+    uint64_t                          extPanId;
+    bool                              defaultRoute;
+    int                               ret = kWpanStatus_Ok;
+    otbr::Web::OpenThreadClient       client(mIfName);
 
     VerifyOrExit(client.Connect(), ret = kWpanStatus_SetFailed);
 
     pskcStr[OT_PSKC_MAX_LENGTH * 2] = '\0'; // for manipulating with strlen
-    VerifyOrExit(reader.parse(aFormRequest.c_str(), root) == true, ret = kWpanStatus_ParseRequestFailed);
+    VerifyOrExit(reader->parse(aFormRequest.c_str(), aFormRequest.c_str() + aFormRequest.size(), &root, nullptr),
+                 ret = kWpanStatus_ParseRequestFailed);
     networkKey  = root["networkKey"].asString();
     prefix      = root["prefix"].asString();
     channel     = root["channel"].asUInt();
@@ -242,24 +246,27 @@ exit:
         otbrLogErr("Wpan service error: %d", ret);
         root["result"] = WPAN_RESPONSE_FAILURE;
     }
-    response = jsonWriter.write(root);
+    response = Json::writeString(writerBuilder, root);
     return response;
 }
 
 std::string WpanService::HandleAddPrefixRequest(const std::string &aAddPrefixRequest)
 {
-    Json::Value                 root;
-    Json::FastWriter            jsonWriter;
-    Json::Reader                reader;
-    std::string                 response;
-    std::string                 prefix;
-    bool                        defaultRoute;
-    int                         ret = kWpanStatus_Ok;
-    otbr::Web::OpenThreadClient client(mIfName);
+    Json::Value                       root;
+    Json::StreamWriterBuilder         writerBuilder;
+    Json::CharReaderBuilder           readerBuilder;
+    std::unique_ptr<Json::CharReader> reader(readerBuilder.newCharReader());
+    std::string                       response;
+    std::string                       prefix;
+    bool                              defaultRoute;
+    int                               ret = kWpanStatus_Ok;
+    otbr::Web::OpenThreadClient       client(mIfName);
 
     VerifyOrExit(client.Connect(), ret = kWpanStatus_SetFailed);
 
-    VerifyOrExit(reader.parse(aAddPrefixRequest.c_str(), root) == true, ret = kWpanStatus_ParseRequestFailed);
+    VerifyOrExit(
+        reader->parse(aAddPrefixRequest.c_str(), aAddPrefixRequest.c_str() + aAddPrefixRequest.size(), &root, nullptr),
+        ret = kWpanStatus_ParseRequestFailed);
     prefix       = root["prefix"].asString();
     defaultRoute = root["defaultRoute"].asBool();
 
@@ -282,23 +289,25 @@ exit:
         otbrLogErr("Wpan service error: %d", ret);
         root["result"] = WPAN_RESPONSE_FAILURE;
     }
-    response = jsonWriter.write(root);
+    response = Json::writeString(writerBuilder, root);
     return response;
 }
 
 std::string WpanService::HandleDeletePrefixRequest(const std::string &aDeleteRequest)
 {
-    Json::Value                 root;
-    Json::FastWriter            jsonWriter;
-    Json::Reader                reader;
-    std::string                 response;
-    std::string                 prefix;
-    int                         ret = kWpanStatus_Ok;
-    otbr::Web::OpenThreadClient client(mIfName);
+    Json::Value                       root;
+    Json::StreamWriterBuilder         writerBuilder;
+    Json::CharReaderBuilder           readerBuilder;
+    std::unique_ptr<Json::CharReader> reader(readerBuilder.newCharReader());
+    std::string                       response;
+    std::string                       prefix;
+    int                               ret = kWpanStatus_Ok;
+    otbr::Web::OpenThreadClient       client(mIfName);
 
     VerifyOrExit(client.Connect(), ret = kWpanStatus_SetFailed);
 
-    VerifyOrExit(reader.parse(aDeleteRequest.c_str(), root) == true, ret = kWpanStatus_ParseRequestFailed);
+    VerifyOrExit(reader->parse(aDeleteRequest.c_str(), aDeleteRequest.c_str() + aDeleteRequest.size(), &root, nullptr),
+                 ret = kWpanStatus_ParseRequestFailed);
     prefix = root["prefix"].asString();
 
     if (prefix.find('/') == std::string::npos)
@@ -319,14 +328,14 @@ exit:
         otbrLogErr("Wpan service error: %d", ret);
         root["result"] = WPAN_RESPONSE_FAILURE;
     }
-    response = jsonWriter.write(root);
+    response = Json::writeString(writerBuilder, root);
     return response;
 }
 
 std::string WpanService::HandleStatusRequest()
 {
     Json::Value                 root, networkInfo;
-    Json::FastWriter            jsonWriter;
+    Json::StreamWriterBuilder   writerBuilder;
     std::string                 response, networkName, extPanId, propertyValue;
     int                         ret = kWpanStatus_Ok;
     otbr::Web::OpenThreadClient client(mIfName);
@@ -462,14 +471,14 @@ exit:
         otbrLogErr("Wpan service error: %d", ret);
     }
     root["error"] = ret;
-    response      = jsonWriter.write(root);
+    response      = Json::writeString(writerBuilder, root);
     return response;
 }
 
 std::string WpanService::HandleAvailableNetworkRequest()
 {
     Json::Value                 root, networks, networkInfo;
-    Json::FastWriter            jsonWriter;
+    Json::StreamWriterBuilder   writerBuilder;
     std::string                 response;
     int                         ret = kWpanStatus_Ok;
     otbr::Web::OpenThreadClient client(mIfName);
@@ -497,7 +506,7 @@ exit:
         otbrLogErr("Error is %d", ret);
     }
     root["error"] = ret;
-    response      = jsonWriter.write(root);
+    response      = Json::writeString(writerBuilder, root);
     return response;
 }
 
@@ -536,15 +545,18 @@ exit:
 
 std::string WpanService::HandleCommission(const std::string &aCommissionRequest)
 {
-    Json::Value      root;
-    Json::Reader     reader;
-    Json::FastWriter jsonWriter;
-    int              ret = kWpanStatus_Ok;
-    std::string      pskd;
-    std::string      response;
-    const char      *rval;
-
-    VerifyOrExit(reader.parse(aCommissionRequest.c_str(), root) == true, ret = kWpanStatus_ParseRequestFailed);
+    Json::Value                       root;
+    Json::CharReaderBuilder           readerBuilder;
+    std::unique_ptr<Json::CharReader> reader(readerBuilder.newCharReader());
+    Json::StreamWriterBuilder         writerBuilder;
+    int                               ret = kWpanStatus_Ok;
+    std::string                       pskd;
+    std::string                       response;
+    const char                       *rval;
+
+    VerifyOrExit(reader->parse(aCommissionRequest.c_str(), aCommissionRequest.c_str() + aCommissionRequest.size(),
+                               &root, nullptr),
+                 ret = kWpanStatus_ParseRequestFailed);
     pskd = root["pskd"].asString();
 
     {
@@ -587,7 +599,7 @@ exit:
         root["result"] = WPAN_RESPONSE_FAILURE;
         otbrLogErr("error: %d", ret);
     }
-    response = jsonWriter.write(root);
+    response = Json::writeString(writerBuilder, root);
 
     return response;
 }
diff --git a/tests/android/java/com/android/server/thread/openthread/testing/FakeOtDaemonTest.java b/tests/android/java/com/android/server/thread/openthread/testing/FakeOtDaemonTest.java
index 1ebaf0f4..dd8a6e04 100644
--- a/tests/android/java/com/android/server/thread/openthread/testing/FakeOtDaemonTest.java
+++ b/tests/android/java/com/android/server/thread/openthread/testing/FakeOtDaemonTest.java
@@ -293,6 +293,22 @@ public final class FakeOtDaemonTest {
         assertThat(mFakeOtDaemon.getEnabledState()).isEqualTo(OT_STATE_ENABLED);
     }
 
+    @Test
+    public void setSetEnabledException_setEnabledFailsWithTheGivenException() {
+        final RemoteException setEnabledException =
+                new RemoteException("setThreadEnabled() failed");
+
+        mFakeOtDaemon.setSetEnabledException(setEnabledException);
+
+        RemoteException thrown =
+                assertThrows(
+                        RemoteException.class,
+                        () ->
+                                mFakeOtDaemon.setThreadEnabled(
+                                        true, new IOtStatusReceiver.Default()));
+        assertThat(thrown).isEqualTo(setEnabledException);
+    }
+
     @Test
     public void setConfiguration_validConfig_onSuccessIsInvoked() throws Exception {
         IOtStatusReceiver receiver = mock(IOtStatusReceiver.class);
diff --git a/tests/dbus/test_dbus_client.cpp b/tests/dbus/test_dbus_client.cpp
index eef54162..3277f045 100644
--- a/tests/dbus/test_dbus_client.cpp
+++ b/tests/dbus/test_dbus_client.cpp
@@ -273,6 +273,8 @@ void CheckEphemeralKey(ThreadApiDBus *aApi)
     TEST_ASSERT(enabled == true);
 }
 
+#if OTBR_ENABLE_TELEMETRY_DATA_API
+
 void CheckBorderAgentInfo(const threadnetwork::TelemetryData_BorderAgentInfo &aBorderAgentInfo)
 {
     TEST_ASSERT(aBorderAgentInfo.border_agent_counters().epskc_activations() == 0);
@@ -291,9 +293,9 @@ void CheckBorderAgentInfo(const threadnetwork::TelemetryData_BorderAgentInfo &aB
     TEST_ASSERT(aBorderAgentInfo.border_agent_counters().pskc_commissioner_petitions() == 0);
     TEST_ASSERT(aBorderAgentInfo.border_agent_counters().mgmt_active_get_reqs() == 0);
     TEST_ASSERT(aBorderAgentInfo.border_agent_counters().mgmt_pending_get_reqs() == 0);
+    TEST_ASSERT(aBorderAgentInfo.border_agent_epskc_journey_info_size() == 0);
 }
 
-#if OTBR_ENABLE_TELEMETRY_DATA_API
 void CheckTelemetryData(ThreadApiDBus *aApi)
 {
     std::vector<uint8_t>         responseTelemetryDataBytes;
@@ -325,7 +327,7 @@ void CheckTelemetryData(ThreadApiDBus *aApi)
     TEST_ASSERT(telemetryData.topo_entries_size() == 1);
     TEST_ASSERT(telemetryData.topo_entries(0).rloc16() < 0xffff);
     TEST_ASSERT(telemetryData.wpan_border_router().border_routing_counters().rs_tx_failure() == 0);
-#if OTBR_ENABLE_SRP_ADVERTISING_PROXY
+#if OTBR_ENABLE_SRP_SERVER
     TEST_ASSERT(telemetryData.wpan_border_router().srp_server().state() ==
                 threadnetwork::TelemetryData::SRP_SERVER_STATE_RUNNING);
 #endif
diff --git a/tests/gtest/CMakeLists.txt b/tests/gtest/CMakeLists.txt
index 7d59fb7a..9b240463 100644
--- a/tests/gtest/CMakeLists.txt
+++ b/tests/gtest/CMakeLists.txt
@@ -75,9 +75,19 @@ if(OTBR_MDNS)
 endif()
 
 add_executable(otbr-posix-gtest-unit
+    ${OPENTHREAD_PROJECT_DIRECTORY}/tests/gtest/fake_platform.cpp
+    fake_posix_platform.cpp
+    test_backbone_multicast_routing.cpp
     test_cli_daemon.cpp
     test_infra_if.cpp
     test_netif.cpp
+    test_udp_proxy.cpp
+)
+target_include_directories(otbr-posix-gtest-unit
+    PRIVATE
+        ${OTBR_PROJECT_DIRECTORY}/src
+        ${OPENTHREAD_PROJECT_DIRECTORY}/src/core
+        ${OPENTHREAD_PROJECT_DIRECTORY}/tests/gtest
 )
 target_link_libraries(otbr-posix-gtest-unit
     otbr-posix
@@ -101,6 +111,27 @@ target_link_libraries(otbr-gtest-host-api
     mbedtls
     otbr-common
     otbr-utils
+    otbr-posix
     GTest::gmock_main
 )
 gtest_discover_tests(otbr-gtest-host-api)
+
+if(OTBR_TELEMETRY_DATA_API)
+    add_executable(otbr-gtest-telemetry
+        ${OTBR_PROJECT_DIRECTORY}/src/utils/telemetry_retriever_border_agent.cpp
+        test_telemetry.cpp
+    )
+    target_include_directories(otbr-gtest-telemetry
+        PRIVATE
+            ${OTBR_PROJECT_DIRECTORY}/include
+            ${OTBR_PROJECT_DIRECTORY}/src
+            ${OPENTHREAD_PROJECT_DIRECTORY}/include
+            ${OPENTHREAD_PROJECT_DIRECTORY}/tests/gtest
+    )
+    target_link_libraries(otbr-gtest-telemetry
+        otbr-config
+        otbr-proto
+        GTest::gmock_main
+    )
+    gtest_discover_tests(otbr-gtest-telemetry)
+endif()
diff --git a/tests/gtest/test_backbone_multicast_routing.cpp b/tests/gtest/test_backbone_multicast_routing.cpp
new file mode 100644
index 00000000..91bcb47e
--- /dev/null
+++ b/tests/gtest/test_backbone_multicast_routing.cpp
@@ -0,0 +1,210 @@
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
+#include <arpa/inet.h>
+#include <array>
+#include <chrono>
+#include <cstdio>
+#include <iostream>
+#include <memory>
+#include <string>
+#include <sys/time.h>
+#include <vector>
+
+#include "common/mainloop.hpp"
+#include "common/mainloop_manager.hpp"
+#include "common/types.hpp"
+#include "host/posix/infra_if.hpp"
+#include "host/posix/multicast_routing_manager.hpp"
+#include "host/posix/netif.hpp"
+#include "host/thread_host.hpp"
+#include "utils/socket_utils.hpp"
+
+// Only Test on linux platform for now.
+#ifdef __linux__
+#if OTBR_ENABLE_BACKBONE_ROUTER
+
+std::string Exec(const char *aCmd)
+{
+    std::array<char, 128>                  buffer;
+    std::string                            result;
+    std::unique_ptr<FILE, int (*)(FILE *)> pipe(popen(aCmd, "r"), pclose);
+    if (!pipe)
+    {
+        perror("Failed to open pipe!");
+        exit(EXIT_FAILURE);
+    }
+    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
+    {
+        result += buffer.data();
+    }
+    return result;
+}
+
+std::vector<std::string> GetMulticastRoutingTable(void)
+{
+    std::vector<std::string> lines;
+    std::stringstream        ss(Exec("ip -6 mroute"));
+    std::string              line;
+
+    while (std::getline(ss, line))
+    {
+        lines.push_back(line);
+    }
+
+    return lines;
+}
+
+static void MainloopProcess(uint32_t aTimeoutMs)
+{
+    otbr::MainloopContext mainloop;
+
+    auto start = std::chrono::high_resolution_clock::now();
+
+    while (true)
+    {
+        FD_ZERO(&mainloop.mReadFdSet);
+        FD_ZERO(&mainloop.mWriteFdSet);
+        FD_ZERO(&mainloop.mErrorFdSet);
+        otbr::MainloopManager::GetInstance().Update(mainloop);
+
+        int rval =
+            select(mainloop.mMaxFd + 1, &mainloop.mReadFdSet, &mainloop.mWriteFdSet, &mainloop.mErrorFdSet, nullptr);
+
+        if (rval >= 0)
+        {
+            otbr::MainloopManager::GetInstance().Process(mainloop);
+        }
+        else
+        {
+            perror("select()");
+            exit(EXIT_FAILURE);
+        }
+
+        auto elapsedTime = std::chrono::high_resolution_clock::now() - start;
+        if (elapsedTime > std::chrono::milliseconds(aTimeoutMs))
+        {
+            break;
+        }
+    }
+}
+
+class DummyNetworkProperties : public otbr::Host::NetworkProperties
+{
+public:
+    otDeviceRole GetDeviceRole(void) const override { return OT_DEVICE_ROLE_DISABLED; }
+    bool         Ip6IsEnabled(void) const override { return false; }
+    uint32_t     GetPartitionId(void) const override { return 0; }
+    void         GetDatasetActiveTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override
+    {
+        OTBR_UNUSED_VARIABLE(aDatasetTlvs);
+    }
+    void GetDatasetPendingTlvs(otOperationalDatasetTlvs &aDatasetTlvs) const override
+    {
+        OTBR_UNUSED_VARIABLE(aDatasetTlvs);
+    }
+    const otMeshLocalPrefix *GetMeshLocalPrefix(void) const override { return &mMeshLocalPrefix; }
+
+    otMeshLocalPrefix mMeshLocalPrefix = {0};
+};
+
+TEST(BbrMcastRouting, MulticastRoutingTableSetCorrectlyAfterHandlingMlrEvents)
+{
+    otbr::Netif::Dependencies defaultNetifDep;
+    otbr::Netif               netif("wpan0", defaultNetifDep);
+    otbr::Netif               fakeInfraIf("wlx123", defaultNetifDep);
+    EXPECT_EQ(netif.Init(), OTBR_ERROR_NONE);
+    EXPECT_EQ(fakeInfraIf.Init(), OTBR_ERROR_NONE);
+
+    const otIp6Address kInfraIfAddr = {
+        {0x91, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}};
+    std::vector<otbr::Ip6AddressInfo> addrs = {
+        {kInfraIfAddr, 64, 0, 1, 0},
+    };
+    fakeInfraIf.UpdateIp6UnicastAddresses(addrs);
+    fakeInfraIf.SetNetifState(true);
+
+    otbr::InfraIf::Dependencies defaultInfraIfDep;
+    otbr::InfraIf               infraIf(defaultInfraIfDep);
+    EXPECT_EQ(infraIf.SetInfraIf("wlx123"), OTBR_ERROR_NONE);
+
+    DummyNetworkProperties        dummyNetworkProperties;
+    otbr::MulticastRoutingManager mcastRtMgr(netif, infraIf, dummyNetworkProperties);
+    mcastRtMgr.HandleStateChange(OT_BACKBONE_ROUTER_STATE_PRIMARY);
+
+    /*
+     * IP6 9101::1 > ff05::abcd: ICMP6, echo request, id 8, seq 1, length 64
+     *   0x0000:  6003 742b 0040 3a05 9101 0000 0000 0000
+     *   0x0010:  0000 0000 0000 0001 ff05 0000 0000 0000
+     *   0x0020:  0000 0000 0000 abcd 8000 f9ae 0008 0001
+     *   0x0030:  49b3 f867 0000 0000 4809 0100 0000 0000
+     *   0x0040:  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f
+     *   0x0050:  2021 2223 2425 2627 2829 2a2b 2c2d 2e2f
+     *   0x0060:  3031 3233 3435 3637
+     */
+    const uint8_t icmp6Packet[] = {
+        0x60, 0x03, 0x74, 0x2b, 0x00, 0x40, 0x3a, 0x05, 0x91, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
+        0x00, 0x00, 0xab, 0xcd, 0x80, 0x00, 0xf9, 0xae, 0x00, 0x08, 0x00, 0x01, 0x49, 0xb3, 0xf8, 0x67, 0x00, 0x00,
+        0x00, 0x00, 0x48, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
+        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
+        0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
+    };
+    fakeInfraIf.Ip6Receive(icmp6Packet, sizeof(icmp6Packet));
+
+    MainloopProcess(10);
+
+    const std::string kAddressPair   = "(9101::1,ff05::abcd)";
+    const std::string kIif           = "Iif: wlx123";
+    const std::string kOifs          = "Oifs: wpan0";
+    const std::string kStateResolved = "State: resolved";
+
+    auto lines = GetMulticastRoutingTable();
+    EXPECT_EQ(lines.size(), 1);
+    EXPECT_THAT(lines.front(), ::testing::HasSubstr(kAddressPair));
+    EXPECT_THAT(lines.front(), ::testing::HasSubstr(kIif));
+    EXPECT_THAT(lines.front(), ::testing::Not(::testing::HasSubstr(kOifs)));
+    EXPECT_THAT(lines.front(), ::testing::HasSubstr(kStateResolved));
+
+    otbr::Ip6Address kMulAddr1 = {
+        {0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd}};
+    mcastRtMgr.HandleBackboneMulticastListenerEvent(OT_BACKBONE_ROUTER_MULTICAST_LISTENER_ADDED, kMulAddr1);
+
+    MainloopProcess(10);
+    lines = GetMulticastRoutingTable();
+    EXPECT_THAT(lines.front(), ::testing::HasSubstr(kAddressPair));
+    EXPECT_THAT(lines.front(), ::testing::HasSubstr(kIif));
+    EXPECT_THAT(lines.front(), ::testing::HasSubstr(kOifs));
+    EXPECT_THAT(lines.front(), ::testing::HasSubstr(kStateResolved));
+}
+
+#endif // OTBR_ENABLE_BACKBONE_ROUTER
+#endif // __linux__
diff --git a/tests/gtest/test_cli_daemon.cpp b/tests/gtest/test_cli_daemon.cpp
index 87997ce4..740adcf9 100644
--- a/tests/gtest/test_cli_daemon.cpp
+++ b/tests/gtest/test_cli_daemon.cpp
@@ -41,23 +41,33 @@
 #include <sys/ioctl.h>
 #include <sys/socket.h>
 #include <sys/types.h>
+#include <sys/un.h>
 #include <vector>
 
-#include <openthread/ip6.h>
-
+#include "common/code_utils.hpp"
+#include "common/mainloop.hpp"
 #include "common/types.hpp"
 #include "host/posix/cli_daemon.hpp"
+#include "utils/socket_utils.hpp"
 
 // Only Test on linux platform for now.
 #ifdef __linux__
 
+using otbr::CliDaemon;
+
+static constexpr size_t kCliMaxLineLength = OTBR_CONFIG_CLI_MAX_LINE_LENGTH;
+static const char      *kTestOutput       = "sample output";
+static const char       kTruncatedMsg[]   = "(truncated ...)";
+
 TEST(CliDaemon, InitSocketCreationWithFullNetIfName)
 {
     const char *netIfName  = "tun0";
     const char *socketFile = "/run/openthread-tun0.sock";
     const char *lockFile   = "/run/openthread-tun0.lock";
 
-    otbr::CliDaemon cliDaemon;
+    CliDaemon::Dependencies sDefaultCliDaemonDependencies;
+    CliDaemon               cliDaemon(sDefaultCliDaemonDependencies);
+
     cliDaemon.Init(netIfName);
 
     struct stat st;
@@ -71,7 +81,8 @@ TEST(CliDaemon, InitSocketCreationWithEmptyNetIfName)
     const char *socketFile = "/run/openthread-wpan0.sock";
     const char *lockFile   = "/run/openthread-wpan0.lock";
 
-    otbr::CliDaemon cliDaemon;
+    CliDaemon::Dependencies sDefaultCliDaemonDependencies;
+    CliDaemon               cliDaemon(sDefaultCliDaemonDependencies);
     cliDaemon.Init("");
 
     struct stat st;
@@ -80,4 +91,232 @@ TEST(CliDaemon, InitSocketCreationWithEmptyNetIfName)
     EXPECT_EQ(stat(lockFile, &st), 0);
 }
 
+class CliDaemonTestInput : public otbr::CliDaemon::Dependencies
+{
+public:
+    CliDaemonTestInput(bool &aReceived, std::string &aReceivedCommand)
+        : mReceived(aReceived)
+        , mReceivedCommand(aReceivedCommand)
+    {
+    }
+
+    otbrError InputCommandLine(const char *aLine) override
+    {
+        mReceivedCommand = std::string(aLine);
+        mReceived        = true;
+        return OTBR_ERROR_NONE;
+    }
+
+    bool        &mReceived;
+    std::string &mReceivedCommand;
+};
+
+TEST(CliDaemon, InputCommandLineCorrectly_AfterReveivingOnSessionSocket)
+{
+    bool               received = false;
+    std::string        receivedCommand;
+    CliDaemonTestInput cliDependency(received, receivedCommand);
+
+    const char *command    = "test command";
+    const char *netIfName  = "tun0";
+    const char *socketFile = "/run/openthread-tun0.sock";
+
+    CliDaemon cliDaemon(cliDependency);
+    EXPECT_EQ(cliDaemon.Init(netIfName), OT_ERROR_NONE);
+
+    {
+        int                clientSocket;
+        struct sockaddr_un serverAddr;
+
+        clientSocket = socket(AF_UNIX, SOCK_STREAM, 0);
+        ASSERT_GE(clientSocket, 0) << "socket creation failed: " << strerror(errno);
+
+        memset(&serverAddr, 0, sizeof(serverAddr));
+        serverAddr.sun_family = AF_UNIX;
+        strncpy(serverAddr.sun_path, socketFile, sizeof(serverAddr.sun_path) - 1);
+        ASSERT_EQ(connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)), 0);
+
+        int rval = send(clientSocket, command, strlen(command), 0);
+        ASSERT_GE(rval, 0) << "Error sending command: " << strerror(errno);
+
+        close(clientSocket);
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
+        cliDaemon.UpdateFdSet(context);
+        int rval = select(context.mMaxFd + 1, &context.mReadFdSet, &context.mWriteFdSet, &context.mErrorFdSet,
+                          &context.mTimeout);
+        ASSERT_GE(rval, 0) << "select failed, error: " << strerror(errno);
+
+        cliDaemon.Process(context);
+    }
+
+    EXPECT_STREQ(receivedCommand.c_str(), command);
+
+    cliDaemon.Deinit();
+}
+
+class CliDaemonTestOutput : public otbr::CliDaemon::Dependencies
+{
+public:
+    // Store a pointer to the CliDaemon to call HandleCommandOutput
+    CliDaemon  *mCliDaemonInstance = nullptr;
+    const char *mOutputToSend      = kTestOutput;
+
+    otbrError InputCommandLine(const char *aLine) override
+    {
+        OTBR_UNUSED_VARIABLE(aLine);
+
+        if (mCliDaemonInstance != nullptr)
+        {
+            mCliDaemonInstance->HandleCommandOutput(mOutputToSend);
+        }
+        return OTBR_ERROR_NONE;
+    }
+};
+
+TEST(CliDaemon, HandleCommandOutputCorrectly_AfterReveivingOnSessionSocket)
+{
+    const char *command    = "test command";
+    const char *netIfName  = "tun0";
+    const char *socketFile = "/run/openthread-tun0.sock";
+
+    CliDaemonTestOutput cliDependency;
+    CliDaemon           cliDaemon(cliDependency);
+    cliDependency.mCliDaemonInstance = &cliDaemon;
+
+    otbr::MainloopContext context;
+
+    EXPECT_EQ(cliDaemon.Init(netIfName), OT_ERROR_NONE);
+
+    int clientSocket = -1;
+    {
+        struct sockaddr_un serverAddr;
+
+        clientSocket = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
+        ASSERT_GE(clientSocket, 0) << "socket creation failed: " << strerror(errno);
+
+        memset(&serverAddr, 0, sizeof(serverAddr));
+        serverAddr.sun_family = AF_UNIX;
+        strncpy(serverAddr.sun_path, socketFile, sizeof(serverAddr.sun_path) - 1);
+        ASSERT_EQ(connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)), 0);
+
+        int rval = send(clientSocket, command, strlen(command), 0);
+        ASSERT_GE(rval, 0) << "Error sending command: " << strerror(errno);
+    }
+
+    char recvBuf[kCliMaxLineLength];
+    bool outputReceived = false;
+
+    while (!outputReceived)
+    {
+        context.mMaxFd   = -1;
+        context.mTimeout = {100, 0};
+        FD_ZERO(&context.mReadFdSet);
+        FD_ZERO(&context.mWriteFdSet);
+        FD_ZERO(&context.mErrorFdSet);
+
+        cliDaemon.UpdateFdSet(context);
+
+        context.AddFdToReadSet(clientSocket);
+
+        int rval = select(context.mMaxFd + 1, &context.mReadFdSet, &context.mWriteFdSet, &context.mErrorFdSet,
+                          &context.mTimeout);
+        ASSERT_GE(rval, 0) << "select failed, error: " << strerror(errno);
+
+        cliDaemon.Process(context);
+
+        if (FD_ISSET(clientSocket, &context.mReadFdSet))
+        {
+            int rval = read(clientSocket, recvBuf, kCliMaxLineLength - 1);
+            ASSERT_GE(rval, 0) << "Error receiving cli output: " << strerror(errno);
+
+            recvBuf[rval]  = '\0';
+            outputReceived = true;
+        }
+    }
+
+    EXPECT_STREQ(recvBuf, kTestOutput);
+
+    cliDaemon.Deinit();
+}
+
+TEST(CliDaemon, HandleCommandOutputTruncatedCorrectly_AfterReceivingOnSessionSocket)
+{
+    const char *command    = "test command";
+    const char *netIfName  = "tun0";
+    const char *socketFile = "/run/openthread-tun0.sock";
+
+    std::string longTestOutput(kCliMaxLineLength + 50, 'A');
+
+    CliDaemonTestOutput cliDependency;
+    CliDaemon           cliDaemon(cliDependency);
+    cliDependency.mCliDaemonInstance = &cliDaemon;
+    cliDependency.mOutputToSend      = longTestOutput.c_str();
+
+    otbr::MainloopContext context;
+
+    EXPECT_EQ(cliDaemon.Init(netIfName), OT_ERROR_NONE);
+
+    int clientSocket = -1;
+    {
+        struct sockaddr_un serverAddr;
+
+        clientSocket = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
+        ASSERT_GE(clientSocket, 0) << "socket creation failed: " << strerror(errno);
+
+        memset(&serverAddr, 0, sizeof(serverAddr));
+        serverAddr.sun_family = AF_UNIX;
+        strncpy(serverAddr.sun_path, socketFile, sizeof(serverAddr.sun_path) - 1);
+        ASSERT_EQ(connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)), 0);
+
+        int rval = send(clientSocket, command, strlen(command), 0);
+        ASSERT_GE(rval, 0) << "Error sending command: " << strerror(errno);
+    }
+
+    char recvBuf[kCliMaxLineLength];
+    bool outputReceived = false;
+
+    while (!outputReceived)
+    {
+        context.mMaxFd   = -1;
+        context.mTimeout = {100, 0};
+        FD_ZERO(&context.mReadFdSet);
+        FD_ZERO(&context.mWriteFdSet);
+        FD_ZERO(&context.mErrorFdSet);
+
+        cliDaemon.UpdateFdSet(context);
+
+        context.AddFdToReadSet(clientSocket);
+
+        int rval = select(context.mMaxFd + 1, &context.mReadFdSet, &context.mWriteFdSet, &context.mErrorFdSet,
+                          &context.mTimeout);
+        ASSERT_GE(rval, 0) << "select failed, error: " << strerror(errno);
+
+        cliDaemon.Process(context);
+
+        if (FD_ISSET(clientSocket, &context.mReadFdSet))
+        {
+            int rval = read(clientSocket, recvBuf, kCliMaxLineLength - 1);
+            ASSERT_GE(rval, 0) << "Error receiving cli output: " << strerror(errno);
+
+            recvBuf[rval]  = '\0';
+            outputReceived = true;
+        }
+    }
+
+    EXPECT_EQ(strncmp(recvBuf, longTestOutput.c_str(), kCliMaxLineLength - sizeof(kTruncatedMsg)), 0);
+    EXPECT_STREQ(recvBuf + kCliMaxLineLength - sizeof(kTruncatedMsg), kTruncatedMsg);
+
+    cliDaemon.Deinit();
+}
+
 #endif // __linux__
diff --git a/tests/gtest/test_infra_if.cpp b/tests/gtest/test_infra_if.cpp
index 84070358..3b903539 100644
--- a/tests/gtest/test_infra_if.cpp
+++ b/tests/gtest/test_infra_if.cpp
@@ -29,6 +29,7 @@
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 
+#include "common/mainloop_manager.hpp"
 #include "host/posix/infra_if.hpp"
 #include "host/posix/netif.hpp"
 
@@ -91,8 +92,8 @@ TEST(InfraIf, DepsSetInfraIfInvokedCorrectly_AfterSpecifyingInfraIf)
 
     // Utilize the Netif module to create a network interface as the fake infrastructure interface.
     otbr::Netif::Dependencies defaultNetifDep;
-    otbr::Netif               netif(defaultNetifDep);
-    EXPECT_EQ(netif.Init(fakeInfraIf), OTBR_ERROR_NONE);
+    otbr::Netif               netif(fakeInfraIf, defaultNetifDep);
+    EXPECT_EQ(netif.Init(), OTBR_ERROR_NONE);
 
     const otIp6Address kTestAddr = {
         {0xfd, 0x35, 0x7a, 0x7d, 0x0f, 0x16, 0xe7, 0xe3, 0x73, 0xf3, 0x09, 0x00, 0x8e, 0xbe, 0x1b, 0x65}};
@@ -103,7 +104,7 @@ TEST(InfraIf, DepsSetInfraIfInvokedCorrectly_AfterSpecifyingInfraIf)
 
     InfraIfDependencyTest testInfraIfDep;
     otbr::InfraIf         infraIf(testInfraIfDep);
-    EXPECT_EQ(infraIf.SetInfraIf(fakeInfraIf.c_str()), OTBR_ERROR_NONE);
+    EXPECT_EQ(infraIf.SetInfraIf(fakeInfraIf), OTBR_ERROR_NONE);
 
     EXPECT_NE(testInfraIfDep.mInfraIfIndex, 0);
     EXPECT_EQ(testInfraIfDep.mIsRunning, false);
@@ -120,8 +121,8 @@ TEST(InfraIf, DepsUpdateInfraIfStateInvokedCorrectly_AfterInfraIfStateChange)
 
     // Utilize the Netif module to create a network interface as the fake infrastructure interface.
     otbr::Netif::Dependencies defaultNetifDep;
-    otbr::Netif               netif(defaultNetifDep);
-    EXPECT_EQ(netif.Init(fakeInfraIf), OTBR_ERROR_NONE);
+    otbr::Netif               netif(fakeInfraIf, defaultNetifDep);
+    EXPECT_EQ(netif.Init(), OTBR_ERROR_NONE);
 
     const otIp6Address kTestAddr1 = {
         {0xfd, 0x35, 0x7a, 0x7d, 0x0f, 0x16, 0xe7, 0xe3, 0x73, 0xf3, 0x09, 0x00, 0x8e, 0xbe, 0x1b, 0x65}};
@@ -136,7 +137,7 @@ TEST(InfraIf, DepsUpdateInfraIfStateInvokedCorrectly_AfterInfraIfStateChange)
     InfraIfDependencyTest testInfraIfDep;
     otbr::InfraIf         infraIf(testInfraIfDep);
     infraIf.Init();
-    EXPECT_EQ(infraIf.SetInfraIf(fakeInfraIf.c_str()), OTBR_ERROR_NONE);
+    EXPECT_EQ(infraIf.SetInfraIf(fakeInfraIf), OTBR_ERROR_NONE);
 
     EXPECT_EQ(testInfraIfDep.mIsRunning, false);
     EXPECT_EQ(testInfraIfDep.mIp6Addresses.size(), 2);
@@ -152,7 +153,7 @@ TEST(InfraIf, DepsUpdateInfraIfStateInvokedCorrectly_AfterInfraIfStateChange)
         FD_ZERO(&context.mWriteFdSet);
         FD_ZERO(&context.mErrorFdSet);
 
-        infraIf.UpdateFdSet(context);
+        otbr::MainloopManager::GetInstance().Update(context);
         int rval = select(context.mMaxFd + 1, &context.mReadFdSet, &context.mWriteFdSet, &context.mErrorFdSet,
                           &context.mTimeout);
         if (rval < 0)
@@ -160,7 +161,7 @@ TEST(InfraIf, DepsUpdateInfraIfStateInvokedCorrectly_AfterInfraIfStateChange)
             perror("select failed");
             exit(EXIT_FAILURE);
         }
-        infraIf.Process(context);
+        otbr::MainloopManager::GetInstance().Process(context);
     }
     EXPECT_EQ(testInfraIfDep.mIsRunning, true);
 
@@ -175,7 +176,7 @@ TEST(InfraIf, DepsUpdateInfraIfStateInvokedCorrectly_AfterInfraIfStateChange)
         FD_ZERO(&context.mWriteFdSet);
         FD_ZERO(&context.mErrorFdSet);
 
-        infraIf.UpdateFdSet(context);
+        otbr::MainloopManager::GetInstance().Update(context);
         int rval = select(context.mMaxFd + 1, &context.mReadFdSet, &context.mWriteFdSet, &context.mErrorFdSet,
                           &context.mTimeout);
         if (rval < 0)
@@ -183,7 +184,7 @@ TEST(InfraIf, DepsUpdateInfraIfStateInvokedCorrectly_AfterInfraIfStateChange)
             perror("select failed");
             exit(EXIT_FAILURE);
         }
-        infraIf.Process(context);
+        otbr::MainloopManager::GetInstance().Process(context);
     }
     EXPECT_EQ(testInfraIfDep.mIp6Addresses.size(), 0);
     EXPECT_EQ(testInfraIfDep.mIsRunning, false);
@@ -199,8 +200,8 @@ TEST(InfraIf, DepsHandleIcmp6NdInvokedCorrectly_AfterInfraIfReceivesIcmp6Nd)
 
     // Utilize the Netif module to create a network interface as the fake infrastructure interface.
     otbr::Netif::Dependencies defaultNetifDep;
-    otbr::Netif               netif(defaultNetifDep);
-    EXPECT_EQ(netif.Init(fakeInfraIf), OTBR_ERROR_NONE);
+    otbr::Netif               netif(fakeInfraIf, defaultNetifDep);
+    EXPECT_EQ(netif.Init(), OTBR_ERROR_NONE);
 
     const otIp6Address kLinkLocalAddr = {
         {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0xa5, 0x42, 0xb7, 0x91, 0x80, 0xc3, 0xf8}};
@@ -212,7 +213,7 @@ TEST(InfraIf, DepsHandleIcmp6NdInvokedCorrectly_AfterInfraIfReceivesIcmp6Nd)
     InfraIfDependencyTest testInfraIfDep;
     otbr::InfraIf         infraIf(testInfraIfDep);
     infraIf.Init();
-    EXPECT_EQ(infraIf.SetInfraIf(fakeInfraIf.c_str()), OTBR_ERROR_NONE);
+    EXPECT_EQ(infraIf.SetInfraIf(fakeInfraIf), OTBR_ERROR_NONE);
     netif.SetNetifState(true);
 
     // Let the fake infrastructure interface receive a fake Icmp6 Nd message
@@ -238,7 +239,7 @@ TEST(InfraIf, DepsHandleIcmp6NdInvokedCorrectly_AfterInfraIfReceivesIcmp6Nd)
         FD_ZERO(&context.mWriteFdSet);
         FD_ZERO(&context.mErrorFdSet);
 
-        infraIf.UpdateFdSet(context);
+        otbr::MainloopManager::GetInstance().Update(context);
         int rval = select(context.mMaxFd + 1, &context.mReadFdSet, &context.mWriteFdSet, &context.mErrorFdSet,
                           &context.mTimeout);
         if (rval < 0)
@@ -246,7 +247,7 @@ TEST(InfraIf, DepsHandleIcmp6NdInvokedCorrectly_AfterInfraIfReceivesIcmp6Nd)
             perror("select failed");
             exit(EXIT_FAILURE);
         }
-        infraIf.Process(context);
+        otbr::MainloopManager::GetInstance().Process(context);
     }
     EXPECT_EQ(testInfraIfDep.mIcmp6NdSrcAddress, otbr::Ip6Address(kPeerLinkLocalAddr));
     EXPECT_EQ(testInfraIfDep.mIcmp6NdDataLen, kTestMsgBodySize);
diff --git a/tests/gtest/test_netif.cpp b/tests/gtest/test_netif.cpp
index 229a826c..a588418c 100644
--- a/tests/gtest/test_netif.cpp
+++ b/tests/gtest/test_netif.cpp
@@ -46,6 +46,7 @@
 #include <sys/select.h>
 #include <sys/socket.h>
 #include <sys/types.h>
+#include <thread>
 #include <vector>
 
 #ifdef __linux__
@@ -56,6 +57,7 @@
 
 #include "common/code_utils.hpp"
 #include "common/mainloop.hpp"
+#include "common/mainloop_manager.hpp"
 #include "common/types.hpp"
 #include "host/posix/netif.hpp"
 #include "utils/socket_utils.hpp"
@@ -175,8 +177,8 @@ TEST(Netif, WpanInitWithFullInterfaceName)
     int          sockfd;
     struct ifreq ifr;
 
-    otbr::Netif netif(sDefaultNetifDependencies);
-    EXPECT_EQ(netif.Init(wpan), OT_ERROR_NONE);
+    otbr::Netif netif(wpan, sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(), OT_ERROR_NONE);
 
     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0)
@@ -199,8 +201,8 @@ TEST(Netif, WpanInitWithFormatInterfaceName)
     int          sockfd;
     struct ifreq ifr;
 
-    otbr::Netif netif(sDefaultNetifDependencies);
-    EXPECT_EQ(netif.Init(wpan), OT_ERROR_NONE);
+    otbr::Netif netif(wpan, sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(), OT_ERROR_NONE);
 
     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0)
@@ -222,8 +224,8 @@ TEST(Netif, WpanInitWithEmptyInterfaceName)
     int          sockfd;
     struct ifreq ifr;
 
-    otbr::Netif netif(sDefaultNetifDependencies);
-    EXPECT_EQ(netif.Init(""), OT_ERROR_NONE);
+    otbr::Netif netif("", sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(), OT_ERROR_NONE);
 
     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0)
@@ -243,8 +245,8 @@ TEST(Netif, WpanInitWithInvalidInterfaceName)
 {
     const char *invalid_netif_name = "invalid_netif_name";
 
-    otbr::Netif netif(sDefaultNetifDependencies);
-    EXPECT_EQ(netif.Init(invalid_netif_name), OTBR_ERROR_INVALID_ARGS);
+    otbr::Netif netif(invalid_netif_name, sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(), OTBR_ERROR_INVALID_ARGS);
 }
 
 TEST(Netif, WpanMtuSize)
@@ -253,8 +255,8 @@ TEST(Netif, WpanMtuSize)
     int          sockfd;
     struct ifreq ifr;
 
-    otbr::Netif netif(sDefaultNetifDependencies);
-    EXPECT_EQ(netif.Init(wpan), OT_ERROR_NONE);
+    otbr::Netif netif(wpan, sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(), OT_ERROR_NONE);
 
     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0)
@@ -276,8 +278,8 @@ TEST(Netif, WpanDeinit)
     int          sockfd;
     struct ifreq ifr;
 
-    otbr::Netif netif(sDefaultNetifDependencies);
-    EXPECT_EQ(netif.Init(wpan), OT_ERROR_NONE);
+    otbr::Netif netif(wpan, sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(), OT_ERROR_NONE);
 
     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0)
@@ -295,8 +297,8 @@ TEST(Netif, WpanDeinit)
 
 TEST(Netif, WpanAddrGenMode)
 {
-    otbr::Netif netif(sDefaultNetifDependencies);
-    EXPECT_EQ(netif.Init("wpan0"), OT_ERROR_NONE);
+    otbr::Netif netif("wpan0", sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(), OT_ERROR_NONE);
 
     std::fstream file("/proc/sys/net/ipv6/conf/wpan0/addr_gen_mode", std::ios::in);
     if (!file.is_open())
@@ -328,8 +330,8 @@ TEST(Netif, WpanIfHasCorrectUnicastAddresses_AfterUpdatingUnicastAddresses)
     const char *kMlRlocStr = "fd0d:7fc:a1b9:f050:0:ff:fe00:b800";
     const char *kMlAlocStr = "fd0d:7fc:a1b9:f050:0:ff:fe00:fc00";
 
-    otbr::Netif netif(sDefaultNetifDependencies);
-    EXPECT_EQ(netif.Init(wpan), OT_ERROR_NONE);
+    otbr::Netif netif(wpan, sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(), OT_ERROR_NONE);
 
     otbr::Ip6AddressInfo testArray1[] = {
         {kLl, 64, 0, 1, 0},
@@ -372,8 +374,8 @@ TEST(Netif, WpanIfHasCorrectUnicastAddresses_AfterUpdatingUnicastAddresses)
 TEST(Netif, WpanIfHasCorrectMulticastAddresses_AfterUpdatingMulticastAddresses)
 {
     const char *wpan = "wpan0";
-    otbr::Netif netif(sDefaultNetifDependencies);
-    EXPECT_EQ(netif.Init(wpan), OT_ERROR_NONE);
+    otbr::Netif netif(wpan, sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(), OT_ERROR_NONE);
 
     otbr::Ip6Address kDefaultMulAddr1 = {
         {0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};
@@ -438,9 +440,9 @@ TEST(Netif, WpanIfHasCorrectMulticastAddresses_AfterUpdatingMulticastAddresses)
 
 TEST(Netif, WpanIfStateChangesCorrectly_AfterSettingNetifState)
 {
-    otbr::Netif netif(sDefaultNetifDependencies);
     const char *wpan = "wpan0";
-    EXPECT_EQ(netif.Init(wpan), OTBR_ERROR_NONE);
+    otbr::Netif netif(wpan, sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(), OTBR_ERROR_NONE);
 
     int fd = SocketWithCloseExec(AF_INET6, SOCK_DGRAM, IPPROTO_IP, kSocketNonBlock);
     if (fd < 0)
@@ -464,10 +466,18 @@ TEST(Netif, WpanIfStateChangesCorrectly_AfterSettingNetifState)
     netif.Deinit();
 }
 
+void receiveTask(int aSockFd, uint8_t *aRecvBuf, struct sockaddr_in6 *aListenAddr)
+{
+    socklen_t   len = sizeof(*aListenAddr);
+    int         n = recvfrom(aSockFd, (char *)aRecvBuf, kMaxIp6Size, MSG_WAITALL, (struct sockaddr *)aListenAddr, &len);
+    std::string udpPayload(reinterpret_cast<const char *>(aRecvBuf), n);
+    EXPECT_EQ(udpPayload, "Hello Otbr Netif!");
+}
+
 TEST(Netif, WpanIfRecvIp6PacketCorrectly_AfterReceivingFromNetif)
 {
-    otbr::Netif netif(sDefaultNetifDependencies);
-    EXPECT_EQ(netif.Init("wpan0"), OTBR_ERROR_NONE);
+    otbr::Netif netif("wpan0", sDefaultNetifDependencies);
+    EXPECT_EQ(netif.Init(), OTBR_ERROR_NONE);
 
     const otIp6Address kOmr = {
         {0xfd, 0x2a, 0xc3, 0x0c, 0x87, 0xd3, 0x00, 0x01, 0xed, 0x1c, 0x0c, 0x91, 0xcc, 0xb6, 0x57, 0x8b}};
@@ -511,13 +521,12 @@ TEST(Netif, WpanIfRecvIp6PacketCorrectly_AfterReceivingFromNetif)
                                  0xc3, 0x0c, 0x87, 0xd3, 0x00, 0x01, 0xed, 0x1c, 0x0c, 0x91, 0xcc, 0xb6, 0x57,
                                  0x8b, 0xe7, 0x08, 0x30, 0x39, 0x00, 0x19, 0x36, 0x81, 0x48, 0x65, 0x6c, 0x6c,
                                  0x6f, 0x20, 0x4f, 0x74, 0x62, 0x72, 0x20, 0x4e, 0x65, 0x74, 0x69, 0x66, 0x21};
-    netif.Ip6Receive(udpPacket, sizeof(udpPacket));
 
-    socklen_t   len = sizeof(listenAddr);
-    int         n   = recvfrom(sockFd, (char *)recvBuf, kMaxIp6Size, MSG_WAITALL, (struct sockaddr *)&listenAddr, &len);
-    std::string udpPayload(reinterpret_cast<const char *>(recvBuf), n);
-    EXPECT_EQ(udpPayload, "Hello Otbr Netif!");
+    std::thread recvThread(receiveTask, sockFd, recvBuf, &listenAddr);
+
+    netif.Ip6Receive(udpPacket, sizeof(udpPacket));
 
+    recvThread.join();
     close(sockFd);
     netif.Deinit();
 }
@@ -557,8 +566,8 @@ TEST(Netif, WpanIfSendIp6PacketCorrectly_AfterReceivingOnIf)
     NetifDependencyTestIp6Send netifDependency(received, receivedPayload);
     const char                *hello = "Hello Otbr Netif!";
 
-    otbr::Netif netif(netifDependency);
-    EXPECT_EQ(netif.Init("wpan0"), OT_ERROR_NONE);
+    otbr::Netif netif("wpan0", netifDependency);
+    EXPECT_EQ(netif.Init(), OT_ERROR_NONE);
 
     // OMR Prefix: fd76:a5d1:fcb0:1707::/64
     const otIp6Address kOmr = {
@@ -603,7 +612,7 @@ TEST(Netif, WpanIfSendIp6PacketCorrectly_AfterReceivingOnIf)
         FD_ZERO(&context.mWriteFdSet);
         FD_ZERO(&context.mErrorFdSet);
 
-        netif.UpdateFdSet(&context);
+        otbr::MainloopManager::GetInstance().Update(context);
         int rval = select(context.mMaxFd + 1, &context.mReadFdSet, &context.mWriteFdSet, &context.mErrorFdSet,
                           &context.mTimeout);
         if (rval < 0)
@@ -611,7 +620,7 @@ TEST(Netif, WpanIfSendIp6PacketCorrectly_AfterReceivingOnIf)
             perror("select failed");
             exit(EXIT_FAILURE);
         }
-        netif.Process(&context);
+        otbr::MainloopManager::GetInstance().Process(context);
     }
 
     EXPECT_STREQ(receivedPayload.c_str(), hello);
@@ -651,11 +660,11 @@ TEST(Netif, WpanIfUpdateMulAddrSubscription_AfterAppJoiningMulGrp)
     const char               *multicastGroup = "ff99::1";
     const char               *wpan           = "wpan0";
     int                       sockFd;
-    otbr::Netif               netif(dependency);
+    otbr::Netif               netif(wpan, dependency);
     const otIp6Address        expectedMulAddr = {0xff, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
 
-    EXPECT_EQ(netif.Init("wpan0"), OT_ERROR_NONE);
+    EXPECT_EQ(netif.Init(), OT_ERROR_NONE);
 
     const otIp6Address kLl = {
         {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x14, 0x03, 0x32, 0x4c, 0xc2, 0xf8, 0xd0}};
@@ -705,7 +714,7 @@ TEST(Netif, WpanIfUpdateMulAddrSubscription_AfterAppJoiningMulGrp)
         FD_ZERO(&context.mWriteFdSet);
         FD_ZERO(&context.mErrorFdSet);
 
-        netif.UpdateFdSet(&context);
+        otbr::MainloopManager::GetInstance().Update(context);
         int rval = select(context.mMaxFd + 1, &context.mReadFdSet, &context.mWriteFdSet, &context.mErrorFdSet,
                           &context.mTimeout);
         if (rval < 0)
@@ -713,7 +722,7 @@ TEST(Netif, WpanIfUpdateMulAddrSubscription_AfterAppJoiningMulGrp)
             perror("select failed");
             exit(EXIT_FAILURE);
         }
-        netif.Process(&context);
+        otbr::MainloopManager::GetInstance().Process(context);
     }
 
     EXPECT_EQ(otbr::Ip6Address(subscribedMulAddr), otbr::Ip6Address(expectedMulAddr));
diff --git a/tests/gtest/test_telemetry.cpp b/tests/gtest/test_telemetry.cpp
new file mode 100644
index 00000000..eb2b6002
--- /dev/null
+++ b/tests/gtest/test_telemetry.cpp
@@ -0,0 +1,212 @@
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
+#if OTBR_ENABLE_TELEMETRY_DATA_API && OTBR_ENABLE_BORDER_AGENT
+
+#define OTBR_LOG_TAG "TEST"
+
+#include <openthread/history_tracker.h>
+#include <openthread/platform/alarm-milli.h>
+
+#include "common/logging.hpp"
+#include "proto/thread_telemetry.pb.h"
+#include "utils/telemetry_retriever_border_agent.hpp"
+
+// Mock implementations
+void otbrLog(otbrLogLevel, const char *, const char *, ...)
+{
+}
+
+uint32_t otPlatAlarmMilliGetNow(void)
+{
+    static uint32_t sNow = 1000000;
+    return sNow++;
+}
+
+class TestEpskcEventTracker
+{
+public:
+    class Iterator : public otHistoryTrackerIterator
+    {
+    public:
+        void     Init(void) { ResetEntryNumber(), SetInitTime(); }
+        uint16_t GetEntryNumber(void) const { return mData16; }
+        void     ResetEntryNumber(void) { mData16 = 0; }
+        void     IncrementEntryNumber(void) { mData16++; }
+        uint32_t GetInitTime(void) const { return mData32; }
+        void     SetInitTime(void) { mData32 = otPlatAlarmMilliGetNow(); }
+    };
+
+    void AddEpskcEvent(otHistoryTrackerBorderAgentEpskcEvent aEvent)
+    {
+        mEvents.push_back({aEvent, otPlatAlarmMilliGetNow()});
+    }
+
+    std::vector<std::pair<otHistoryTrackerBorderAgentEpskcEvent, uint32_t>> mEvents;
+};
+
+static TestEpskcEventTracker sEventTracker;
+
+void otHistoryTrackerInitIterator(otHistoryTrackerIterator *aIterator)
+{
+    static_cast<TestEpskcEventTracker::Iterator *>(aIterator)->Init();
+}
+
+const otHistoryTrackerBorderAgentEpskcEvent *otHistoryTrackerIterateBorderAgentEpskcEventHistory(
+    otInstance               *aInstance,
+    otHistoryTrackerIterator *aIterator,
+    uint32_t                 *aEntryAge)
+{
+    (void)aInstance;
+
+    TestEpskcEventTracker::Iterator       *iterator = static_cast<TestEpskcEventTracker::Iterator *>(aIterator);
+    uint16_t                               entryNum = iterator->GetEntryNumber();
+    otHistoryTrackerBorderAgentEpskcEvent *result   = nullptr;
+
+    if (entryNum < sEventTracker.mEvents.size())
+    {
+        uint16_t reverseIndex = sEventTracker.mEvents.size() - entryNum - 1;
+        result                = &sEventTracker.mEvents[reverseIndex].first;
+        *aEntryAge            = iterator->GetInitTime() - sEventTracker.mEvents[reverseIndex].second;
+        iterator->IncrementEntryNumber();
+    }
+
+    return result;
+}
+
+// Test cases
+TEST(Telemetry, RetrieveEpskcJourneyInfoCorrectly)
+{
+    otbr::agent::TelemetryRetriever::BorderAgent retriever(nullptr);
+    threadnetwork::TelemetryData                 telemetryData;
+    auto borderAgentInfo = telemetryData.mutable_wpan_border_router()->mutable_border_agent_info();
+
+    // 1. Add a basic Epskc journey and verify the fields are correct.
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_ACTIVATED);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_CONNECTED);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_LOCAL_CLOSE);
+
+    retriever.RetrieveEpskcJourneyInfo(borderAgentInfo);
+
+    ASSERT_EQ(borderAgentInfo->border_agent_epskc_journey_info_size(), 1);
+    auto epskcJourneyInfo = borderAgentInfo->border_agent_epskc_journey_info(0);
+    ASSERT_TRUE(epskcJourneyInfo.has_activated_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_connected_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_petitioned_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_retrieved_active_dataset_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_retrieved_pending_dataset_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_keep_alive_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_deactivated_msec());
+    ASSERT_EQ(epskcJourneyInfo.deactivated_reason(),
+              threadnetwork::TelemetryData::EPSKC_DEACTIVATED_REASON_LOCAL_CLOSE);
+
+    // 2. Add two Epskc journeys and verify that the previous one won't be uploaded again.
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_ACTIVATED);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_MAX_ATTEMPTS);
+
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_ACTIVATED);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_CONNECTED);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_PETITIONED);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_REMOTE_CLOSE);
+
+    borderAgentInfo->Clear();
+    retriever.RetrieveEpskcJourneyInfo(borderAgentInfo);
+    ASSERT_EQ(borderAgentInfo->border_agent_epskc_journey_info_size(), 2);
+
+    epskcJourneyInfo = borderAgentInfo->border_agent_epskc_journey_info(0);
+    ASSERT_TRUE(epskcJourneyInfo.has_activated_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_connected_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_petitioned_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_retrieved_active_dataset_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_retrieved_pending_dataset_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_keep_alive_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_deactivated_msec());
+    ASSERT_EQ(epskcJourneyInfo.deactivated_reason(),
+              threadnetwork::TelemetryData::EPSKC_DEACTIVATED_REASON_MAX_ATTEMPTS);
+
+    epskcJourneyInfo = borderAgentInfo->border_agent_epskc_journey_info(1);
+    ASSERT_TRUE(epskcJourneyInfo.has_activated_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_connected_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_petitioned_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_deactivated_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_retrieved_active_dataset_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_retrieved_pending_dataset_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_keep_alive_msec());
+    ASSERT_EQ(epskcJourneyInfo.deactivated_reason(),
+              threadnetwork::TelemetryData::EPSKC_DEACTIVATED_REASON_REMOTE_CLOSE);
+
+    // 3. Add an uncompleted Epskc journey and verify that nothing will be fetched.
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_ACTIVATED);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_CONNECTED);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_PETITIONED);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_RETRIEVED_ACTIVE_DATASET);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_RETRIEVED_PENDING_DATASET);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_KEEP_ALIVE);
+
+    borderAgentInfo->Clear();
+    retriever.RetrieveEpskcJourneyInfo(borderAgentInfo);
+    ASSERT_EQ(borderAgentInfo->border_agent_epskc_journey_info_size(), 0);
+
+    // 4. Complete the last Epskc journey and add one more journey. Verify that there are two journeys.
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_SESSION_TIMEOUT);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_ACTIVATED);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_CONNECTED);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_PETITIONED);
+    sEventTracker.AddEpskcEvent(OT_HISTORY_TRACKER_BORDER_AGENT_EPSKC_EVENT_DEACTIVATED_SESSION_ERROR);
+
+    borderAgentInfo->Clear();
+    retriever.RetrieveEpskcJourneyInfo(borderAgentInfo);
+    ASSERT_EQ(borderAgentInfo->border_agent_epskc_journey_info_size(), 2);
+
+    epskcJourneyInfo = borderAgentInfo->border_agent_epskc_journey_info(0);
+    ASSERT_TRUE(epskcJourneyInfo.has_activated_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_connected_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_petitioned_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_retrieved_active_dataset_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_retrieved_pending_dataset_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_keep_alive_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_deactivated_msec());
+    ASSERT_EQ(epskcJourneyInfo.deactivated_reason(),
+              threadnetwork::TelemetryData::EPSKC_DEACTIVATED_REASON_SESSION_TIMEOUT);
+
+    epskcJourneyInfo = borderAgentInfo->border_agent_epskc_journey_info(1);
+    ASSERT_TRUE(epskcJourneyInfo.has_activated_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_connected_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_petitioned_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_retrieved_active_dataset_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_retrieved_pending_dataset_msec());
+    ASSERT_FALSE(epskcJourneyInfo.has_keep_alive_msec());
+    ASSERT_TRUE(epskcJourneyInfo.has_deactivated_msec());
+    ASSERT_EQ(epskcJourneyInfo.deactivated_reason(),
+              threadnetwork::TelemetryData::EPSKC_DEACTIVATED_REASON_SESSION_ERROR);
+}
+
+#endif // OTBR_ENABLE_TELEMETRY_DATA_API && OTBR_ENABLE_BORDER_AGENT
diff --git a/tests/gtest/test_udp_proxy.cpp b/tests/gtest/test_udp_proxy.cpp
new file mode 100644
index 00000000..b0a66fa0
--- /dev/null
+++ b/tests/gtest/test_udp_proxy.cpp
@@ -0,0 +1,182 @@
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
+#include <arpa/inet.h>
+#include <sys/socket.h>
+#include <unistd.h>
+
+#include "common/mainloop_manager.hpp"
+#include "common/types.hpp"
+#include "host/posix/udp_proxy.hpp"
+
+static constexpr size_t   kMaxUdpSize       = 1280;
+static constexpr uint16_t kTestThreadBaPort = 49191;
+const std::string         kHello            = "Hello UdpProxy!";
+
+class UdpProxyTest : public otbr::UdpProxy::Dependencies
+{
+public:
+    UdpProxyTest(void)
+        : mForwarded(false)
+    {
+    }
+
+    otbrError UdpForward(const uint8_t        *aUdpPayload,
+                         uint16_t              aLength,
+                         const otIp6Address   &aRemoteAddr,
+                         uint16_t              aRemotePort,
+                         const otbr::UdpProxy &aUdpProxy) override
+    {
+        mForwarded = true;
+        assert(aLength < kMaxUdpSize);
+
+        memcpy(mPayload, aUdpPayload, aLength);
+        mLength = aLength;
+        memcpy(mRemoteAddress.mFields.m8, aRemoteAddr.mFields.m8, sizeof(mRemoteAddress));
+        mRemotePort = aRemotePort;
+        mLocalPort  = aUdpProxy.GetThreadPort();
+
+        return OTBR_ERROR_NONE;
+    }
+
+    bool         mForwarded;
+    uint8_t      mPayload[kMaxUdpSize];
+    uint16_t     mLength;
+    otIp6Address mRemoteAddress;
+    uint16_t     mRemotePort;
+    uint16_t     mLocalPort;
+};
+
+TEST(UdpProxy, UdpProxyForwardCorrectlyWhenActive)
+{
+    UdpProxyTest   tester;
+    otbr::UdpProxy udpProxy(tester);
+
+    udpProxy.Start(kTestThreadBaPort);
+    EXPECT_NE(udpProxy.GetHostPort(), 0);
+
+    // Send a UDP packet destined to loopback address.
+    {
+        int                sockFd;
+        struct sockaddr_in destAddr;
+
+        if ((sockFd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
+        {
+            perror("socket creation failed");
+            exit(EXIT_FAILURE);
+        }
+
+        memset(&destAddr, 0, sizeof(destAddr));
+        destAddr.sin_family      = AF_INET;
+        destAddr.sin_port        = htons(udpProxy.GetHostPort());
+        destAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Loopback address
+
+        if (sendto(sockFd, kHello.c_str(), kHello.size(), 0, (const struct sockaddr *)&destAddr, sizeof(destAddr)) < 0)
+        {
+            perror("Failed to send UDP packet through loopback interface");
+            exit(EXIT_FAILURE);
+        }
+        close(sockFd);
+    }
+
+    otbr::MainloopContext context;
+    while (!tester.mForwarded)
+    {
+        context.mMaxFd   = -1;
+        context.mTimeout = {100, 0};
+        FD_ZERO(&context.mReadFdSet);
+        FD_ZERO(&context.mWriteFdSet);
+        FD_ZERO(&context.mErrorFdSet);
+
+        otbr::MainloopManager::GetInstance().Update(context);
+        int rval = select(context.mMaxFd + 1, &context.mReadFdSet, &context.mWriteFdSet, &context.mErrorFdSet,
+                          &context.mTimeout);
+        if (rval < 0)
+        {
+            perror("select failed");
+            exit(EXIT_FAILURE);
+        }
+        otbr::MainloopManager::GetInstance().Process(context);
+    }
+
+    std::string udpPayload(reinterpret_cast<const char *>(tester.mPayload), tester.mLength);
+    EXPECT_EQ(udpPayload, kHello);
+    EXPECT_EQ(tester.mLength, kHello.size());
+    EXPECT_EQ(tester.mLocalPort, kTestThreadBaPort);
+
+    udpProxy.Stop();
+}
+
+TEST(UdpProxy, UdpProxySendToPeerCorrectlyWhenActive)
+{
+    UdpProxyTest   tester;
+    otbr::UdpProxy udpProxy(tester);
+
+    udpProxy.Start(kTestThreadBaPort);
+
+    // Receive UDP packets on loopback address with specified port
+    int                sockFd;
+    const uint16_t     port = 12345;
+    struct sockaddr_in listenAddr;
+    uint8_t            recvBuf[kMaxUdpSize];
+
+    if ((sockFd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
+    {
+        perror("socket creation failed");
+        exit(EXIT_FAILURE);
+    }
+
+    memset(&listenAddr, 0, sizeof(listenAddr));
+    listenAddr.sin_family      = AF_INET;
+    listenAddr.sin_port        = htons(port);
+    listenAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Loopback address
+
+    if (bind(sockFd, (const struct sockaddr *)&listenAddr, sizeof(listenAddr)) < 0)
+    {
+        perror("bind failed");
+        exit(EXIT_FAILURE);
+    }
+
+    // Send a UDP packet through UDP Proxy
+    otIp6Address peerAddress = {
+        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01}};
+    udpProxy.SendToPeer(reinterpret_cast<const uint8_t *>(kHello.c_str()), kHello.size(), peerAddress, port);
+
+    // Receive the UDP packet
+    socklen_t   len = sizeof(listenAddr);
+    int         n   = recvfrom(sockFd, (char *)recvBuf, kMaxUdpSize, MSG_WAITALL, (struct sockaddr *)&listenAddr, &len);
+    std::string udpPayload(reinterpret_cast<const char *>(recvBuf), n);
+    EXPECT_EQ(udpPayload, kHello);
+
+    close(sockFd);
+
+    udpProxy.Stop();
+}
diff --git a/tests/scripts/bootstrap.sh b/tests/scripts/bootstrap.sh
index d611b310..d7a50d66 100755
--- a/tests/scripts/bootstrap.sh
+++ b/tests/scripts/bootstrap.sh
@@ -32,8 +32,6 @@ set -euxo pipefail
 TOOLS_HOME="$HOME"/.cache/tools
 [[ -d $TOOLS_HOME ]] || mkdir -p "$TOOLS_HOME"
 
-MDNSRESPONDER_PATCH_PATH=$(realpath "$(dirname "$0")"/../../third_party/mDNSResponder)
-
 disable_install_recommends()
 {
     OTBR_APT_CONF_FILE=/etc/apt/apt.conf
@@ -123,16 +121,11 @@ case "$(uname)" in
         fi
 
         if [ "${OTBR_MDNS-}" == 'mDNSResponder' ]; then
-            SOURCE_NAME=mDNSResponder-1790.80.10
+            SOURCE_NAME=mDNSResponder-2600.100.147
             wget https://github.com/apple-oss-distributions/mDNSResponder/archive/refs/tags/$SOURCE_NAME.tar.gz \
                 && mkdir -p $SOURCE_NAME \
                 && tar xvf $SOURCE_NAME.tar.gz -C $SOURCE_NAME --strip-components=1 \
                 && cd "$SOURCE_NAME" \
-                && (
-                    for patch in "$MDNSRESPONDER_PATCH_PATH"/*.patch; do
-                        patch -p1 <"$patch"
-                    done
-                ) \
                 && cd mDNSPosix \
                 && make os=linux tls=no && sudo make install os=linux tls=no
         fi
diff --git a/tests/scripts/check-docker b/tests/scripts/check-docker
index 9d308cfe..caebc82a 100755
--- a/tests/scripts/check-docker
+++ b/tests/scripts/check-docker
@@ -52,13 +52,13 @@ on_exit()
 main()
 {
     sudo modprobe ip6table_filter
-    docker build -t otbr \
+    docker build -t otbr-test \
         --build-arg OTBR_OPTIONS=-DOT_POSIX_RCP_SPI_BUS=ON \
         --build-arg BACKBONE_ROUTER=0 \
-        -f etc/docker/Dockerfile .
+        -f etc/docker/test/Dockerfile .
 
     # SPI simulation is not available yet, so just verify the binary runs
-    docker run --rm -t --entrypoint otbr-agent otbr -h | grep 'spi://'
+    docker run --rm -t --entrypoint otbr-agent otbr-test -h | grep 'spi://'
 
     local -r SOCAT_OUTPUT=/tmp/ot-socat
     socat -d -d pty,raw,echo=0 pty,raw,echo=0 2>&1 | tee $SOCAT_OUTPUT &
@@ -80,7 +80,7 @@ main()
     OTBR_DOCKER_PID=$(
         docker run -d -e HTTP_PORT=10080 \
             --sysctl "net.ipv6.conf.all.disable_ipv6=0 net.ipv4.conf.all.forwarding=1 net.ipv6.conf.all.forwarding=1" \
-            --privileged -p 8080:10080 --dns=127.0.0.1 --volume "$DOCKER_PTY":/dev/ttyUSB0 otbr --backbone-interface eth0
+            --privileged -p 8080:10080 --dns=127.0.0.1 --volume "$DOCKER_PTY":/dev/ttyUSB0 otbr-test --backbone-interface eth0
     )
     readonly OTBR_DOCKER_PID
     sleep 10
diff --git a/tests/scripts/check-raspbian b/tests/scripts/check-raspbian
index 6bd97e30..f0cde3cd 100755
--- a/tests/scripts/check-raspbian
+++ b/tests/scripts/check-raspbian
@@ -65,7 +65,7 @@ pip3 install scikit-build
 pip3 install cmake==3.10.3
 cmake --version
 
-su -c 'RELEASE=1 NETWORK_MANAGER=0 script/setup' pi
+su -c 'RELEASE=1 script/setup' pi
 EOF
 
     (
diff --git a/tests/scripts/check-scan-build b/tests/scripts/check-scan-build
index 42faf1c4..e3dbd7ea 100755
--- a/tests/scripts/check-scan-build
+++ b/tests/scripts/check-scan-build
@@ -35,6 +35,7 @@ main()
     (mkdir -p scan-build \
         && cd scan-build \
         && scan-build cmake -GNinja \
+            -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
             -DBUILD_TESTING=OFF \
             -DCMAKE_CXX_COMPILER=clang++ \
             -DCMAKE_C_COMPILER=clang \
diff --git a/tests/scripts/check-scripts b/tests/scripts/check-scripts
index 5af6e3b3..8cc2a7aa 100755
--- a/tests/scripts/check-scripts
+++ b/tests/scripts/check-scripts
@@ -105,7 +105,6 @@ main()
     kill "${SERVICES_PID}"
     sudo killall otbr-web || true
     sudo killall otbr-agent || true
-    sudo service tayga stop || true
     killall ot-rcp
     killall socat
     jobs
diff --git a/tests/scripts/expect/_common.exp b/tests/scripts/expect/_common.exp
index 4e322fee..d5ccd58c 100644
--- a/tests/scripts/expect/_common.exp
+++ b/tests/scripts/expect/_common.exp
@@ -84,6 +84,20 @@ proc spawn_node {id type sim_app} {
                 timeout { fail "Timed out" }
             }
         }
+        commissioner {
+            spawn $sim_app
+            expect ">"
+        }
+        ctl {
+            spawn $sim_app
+            send "factoryreset\n"
+            wait_for "state" "disabled"
+            expect "Done"
+
+            expect_after {
+                timeout { fail "Timed out" }
+            }
+        }
         otbr-docker {
             spawn docker exec -it $sim_app bash
             expect "app#"
@@ -176,3 +190,10 @@ proc get_omr_addr {} {
     expect -re {(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}(?= origin:slaac)}
     return $expect_out(0,string)
 }
+
+proc check_string_contains {haystack needle} {
+    if {![regexp $needle $haystack]} {
+        puts "Error: '$needle' not found."
+        exit 1
+    }
+}
diff --git a/tests/scripts/expect/ncp_backbone_multicast_forwarding.exp b/tests/scripts/expect/ncp_backbone_multicast_forwarding.exp
new file mode 100755
index 00000000..eae87517
--- /dev/null
+++ b/tests/scripts/expect/ncp_backbone_multicast_forwarding.exp
@@ -0,0 +1,90 @@
+#!/usr/bin/expect -f
+#
+#  Copyright (c) 2025, The OpenThread Authors.
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
+set test_maddr "ff05::abcd"
+
+proc clean_up {container} {
+    puts "Performing cleanup..."
+
+    exec sudo docker stop $container
+    exec sudo docker rm $container
+    dispose_all
+}
+
+try {
+
+    start_otbr_docker $container $::env(EXP_OT_NCP_PATH) 2 $pty1 $pty2
+    spawn_node 3 otbr-docker $container
+    sleep 5
+
+    # Join a Thread network.
+    send "dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 io.openthread.BorderRouter.Join \"array:byte:${dataset_dbus}\"\n"
+    expect "dbus-send"
+    expect "app#"
+    send "sysctl -w net.ipv6.icmp.echo_ignore_all=1\n"
+    expect_line "net.ipv6.icmp.echo_ignore_all = 1"
+    sleep 20
+
+    # Starts a cli node as a multicast listener.
+    spawn_node 4 cli $::env(EXP_OT_CLI_PATH)
+    send "dataset set active ${dataset}\n"
+    expect_line "Done"
+    send "ifconfig up\r\n"
+    expect_line "Done"
+    send "thread start\r\n"
+    expect_line "Done"
+    wait_for "state" "child\|router"
+    expect_line "Done"
+
+    # Let the cli node subscribes to a multicast address
+    send "ipmaddr add ${test_maddr}\n"
+    expect_line "Done"
+    sleep 5
+
+    # Ping the multicast address from the infrastructure network
+    set ping_result [exec ping6 -I backbone1 -t 5 -c 10 $test_maddr]
+    puts "$ping_result"
+    check_string_contains $ping_result "10 packets transmitted, 10 received, 0% packet loss"
+
+    clean_up $container
+
+} on error {result} {
+    puts "An error occurred: $result\r\n"
+    clean_up $container
+    exit 1
+}
diff --git a/tests/scripts/expect/ncp_border_agent.exp b/tests/scripts/expect/ncp_border_agent.exp
new file mode 100644
index 00000000..f2987aad
--- /dev/null
+++ b/tests/scripts/expect/ncp_border_agent.exp
@@ -0,0 +1,123 @@
+#!/usr/bin/expect -f
+#
+#  Copyright (c) 2025, The OpenThread Authors.
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
+set pskc "9dc023ccd447b12b50997ef68020f19e"
+set joiner_pwd "J01NU5"
+
+proc clean_up {container} {
+    puts "Performing cleanup..."
+
+    exec sudo docker stop $container
+    exec sudo docker rm $container
+    dispose_all
+}
+
+proc check_common_txt {mdns_browse_result} {
+    check_string_contains $mdns_browse_result "sb="
+    check_string_contains $mdns_browse_result "xa="
+    check_string_contains $mdns_browse_result "tv="
+    check_string_contains $mdns_browse_result "xp="
+    check_string_contains $mdns_browse_result "nn="
+    check_string_contains $mdns_browse_result "id="
+    check_string_contains $mdns_browse_result "mn="
+    check_string_contains $mdns_browse_result "vn="
+    check_string_contains $mdns_browse_result "rv="
+}
+
+try {
+
+    start_otbr_docker $container $::env(EXP_OT_NCP_PATH) 2 $pty1 $pty2
+    spawn_node 3 otbr-docker $container
+    sleep 5
+
+    # Browse when Thread network is not started.
+    set mdns_browse_result [exec avahi-browse -aprt]
+    check_common_txt $mdns_browse_result
+
+    # Join a Thread network.
+    switch_node 3
+    send "dbus-send --system --dest=io.openthread.BorderRouter.wpan0 --type=method_call --print-reply /io/openthread/BorderRouter/wpan0 io.openthread.BorderRouter.Join \"array:byte:${dataset_dbus}\"\n"
+    expect "dbus-send"
+    expect "app#"
+    sleep 20
+
+    # Browse after Thread network starts.
+    set mdns_browse_result [exec avahi-browse -aprt]
+    check_common_txt $mdns_browse_result
+    check_string_contains $mdns_browse_result "pt="
+    check_string_contains $mdns_browse_result "at="
+
+    # Get the Border Agent Service IP address and port from mdns record
+    set regex {([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+);([0-9]+);}
+    puts "$mdns_browse_result"
+    if {[regexp $regex $mdns_browse_result match ip_address port]} {
+        puts "IP Address: $ip_address"
+        puts "Port: $port"
+    } else {
+        puts "No IP address and port is found in the mDNS entry!"
+        exit 1
+    }
+
+    # Start commissioner
+    spawn_node 4 commissioner $::env(EXP_OT_COMMISSIONER_PATH)
+    send "config set pskc ${pskc}\n"
+    expect "done"
+    send "active\n"
+    expect "false"
+    expect "done"
+    send "start $ip_address $port\n"
+    expect "done"
+    send "active\n"
+    expect "true"
+    send "joiner enableall meshcop $joiner_pwd\n"
+    expect "done"
+
+    # Join a cli node
+    spawn_node 5 cli $::env(EXP_OT_CLI_PATH)
+    send "ifconfig up\r\n"
+    expect_line "Done"
+    send "joiner start $joiner_pwd\r\n"
+    expect_line "Done"    
+    expect_line "Join success"
+
+    clean_up $container
+
+} on error {result} {
+    puts "An error occurred: $result"
+    clean_up $container
+    exit 1
+}
diff --git a/tests/scripts/expect/ncp_cli_join_leave.exp b/tests/scripts/expect/ncp_cli_join_leave.exp
new file mode 100755
index 00000000..67eebc72
--- /dev/null
+++ b/tests/scripts/expect/ncp_cli_join_leave.exp
@@ -0,0 +1,71 @@
+#!/usr/bin/expect -f
+#
+#  Copyright (c) 2025, The OpenThread Authors.
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
+# Step 2. Start otbr-agent with a NCP
+spawn_node 2 otbr $::env(EXP_OT_NCP_PATH)
+sleep 1
+
+# Step 3. Start ot-ctl and join the network
+spawn_node 3 ctl $::env(EXP_OT_CTL_PATH)
+
+send "dataset set active ${dataset}\n"
+expect "Done"
+send "ifconfig up\n"
+expect "Done"
+send "thread start\n"
+expect "Done"
+wait_for "state" "router|child"
+expect "Done"
+
+# Step 4. Leave the network
+send "thread stop\n"
+expect "Done"
+send "ifconfig down\n"
+expect "Done"
+
+# Step 5. Verify the state of otbr-agent is 'disabled'
+wait_for "state" "disabled"
+expect "Done"
diff --git a/tests/scripts/meshcop b/tests/scripts/meshcop
index 104c21e7..29170a16 100755
--- a/tests/scripts/meshcop
+++ b/tests/scripts/meshcop
@@ -410,7 +410,7 @@ ot_commissioner_build()
         && git checkout FETCH_HEAD \
         && ./script/bootstrap.sh \
         && mkdir build && cd build \
-        && cmake -GNinja -DCMAKE_BUILD_TYPE=Release .. \
+        && cmake -GNinja -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_BUILD_TYPE=Release .. \
         && ninja)
 }
 
diff --git a/tests/scripts/ncp_mode b/tests/scripts/ncp_mode
index 2544bf5b..a837de41 100755
--- a/tests/scripts/ncp_mode
+++ b/tests/scripts/ncp_mode
@@ -61,6 +61,9 @@ readonly ABS_TOP_OT_SRCDIR
 ABS_TOP_OT_BUILDDIR="${ABS_TOP_BUILDDIR}/../simulation"
 readonly ABS_TOP_BUILDDIR
 
+OT_CTL="${ABS_TOP_BUILDDIR}/third_party/openthread/repo/src/posix/ot-ctl"
+readonly OT_CTL
+
 OTBR_COLOR_PASS='\033[0;32m'
 readonly OTBR_COLOR_PASS
 
@@ -118,6 +121,10 @@ readonly OTBR_DBUS_CONF
 OTBR_AGENT_PATH="${ABS_TOP_BUILDDIR}/src/agent/${OTBR_AGENT}"
 readonly OTBR_AGENT_PATH
 
+# External commissioner
+OT_COMMISSIONER_PATH=${ABS_TOP_OT_BUILDDIR}/ot-commissioner/build/src/app/cli/commissioner-cli
+readonly OT_COMMISSIONER_PATH
+
 # The node ids
 LEADER_NODE_ID=1
 readonly LEADER_NODE_ID
@@ -137,13 +144,32 @@ do_build_ot_simulation()
         -DOT_MTD=OFF -DOT_RCP=OFF -DOT_APP_CLI=OFF -DOT_APP_RCP=OFF \
         -DOT_BORDER_ROUTING=ON -DOT_NCP_INFRA_IF=ON -DOT_SIMULATION_INFRA_IF=OFF \
         -DOT_SRP_SERVER=ON -DOT_SRP_ADV_PROXY=ON -DOT_PLATFORM_DNSSD=ON -DOT_SIMULATION_DNSSD=OFF -DOT_NCP_DNSSD=ON \
+        -DOT_BORDER_AGENT=ON -DOT_BORDER_AGENT_MESHCOP_SERVICE=OFF \
+        -DOT_NCP_CLI_STREAM=ON -DOT_BACKBONE_ROUTER=ON -DOT_BACKBONE_ROUTER_MULTICAST_ROUTING=ON \
         -DBUILD_TESTING=OFF
     OT_CMAKE_BUILD_DIR=${ABS_TOP_OT_BUILDDIR}/cli "${ABS_TOP_OT_SRCDIR}"/script/cmake-build simulation \
         -DOT_MTD=OFF -DOT_RCP=OFF -DOT_APP_NCP=OFF -DOT_APP_RCP=OFF \
-        -DOT_BORDER_ROUTING=OFF \
+        -DOT_BORDER_ROUTING=OFF -DOT_MLR=ON \
         -DBUILD_TESTING=OFF
 }
 
+do_build_ot_commissioner()
+{
+    if [[ -x ${OT_COMMISSIONER_PATH} ]]; then
+        return 0
+    fi
+
+    (mkdir -p "${ABS_TOP_OT_BUILDDIR}/ot-commissioner" \
+        && cd "${ABS_TOP_OT_BUILDDIR}/ot-commissioner" \
+        && (git --git-dir=.git rev-parse --is-inside-work-tree || git --git-dir=.git init .) \
+        && git fetch --depth 1 https://github.com/openthread/ot-commissioner.git main \
+        && git checkout FETCH_HEAD \
+        && ./script/bootstrap.sh \
+        && mkdir build && cd build \
+        && cmake -GNinja -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_BUILD_TYPE=Release .. \
+        && ninja)
+}
+
 do_build_otbr_docker()
 {
     otbr_docker_options=(
@@ -154,12 +180,12 @@ do_build_otbr_docker()
         "-DOTBR_TREL=ON"
         "-DOTBR_LINK_METRICS_TELEMETRY=ON"
         "-DOTBR_SRP_ADVERTISING_PROXY=ON"
+        "-DOTBR_BORDER_AGENT=ON"
+        "-DOTBR_BACKBONE_ROUTER=ON"
     )
     sudo docker build -t "${OTBR_DOCKER_IMAGE}" \
-        -f ./etc/docker/Dockerfile . \
+        -f ./etc/docker/test/Dockerfile . \
         --build-arg NAT64=0 \
-        --build-arg NAT64_SERVICE=0 \
-        --build-arg DNS64=0 \
         --build-arg WEB_GUI=0 \
         --build-arg REST_API=0 \
         --build-arg FIREWALL=0 \
@@ -176,11 +202,14 @@ setup_infraif()
     fi
     sudo sysctl -w net.ipv6.conf.backbone1.accept_ra=2
     sudo sysctl -w net.ipv6.conf.backbone1.accept_ra_rt_info_max_plen=64
+    # Delete the 9101::1/ address to ensure ping through backbone1 use an on-link address.
+    sudo ip addr del 9101::1/64 dev backbone1
 }
 
 test_setup()
 {
     executable_or_die "${OTBR_AGENT_PATH}"
+    executable_or_die "${OT_CTL}"
 
     # Remove flashes
     sudo rm -vrf "${TEST_BASE}/tmp"
@@ -193,6 +222,7 @@ test_setup()
     executable_or_die "${ot_ncp}"
 
     export EXP_OTBR_AGENT_PATH="${OTBR_AGENT_PATH}"
+    export EXP_OT_CTL_PATH="${OT_CTL}"
     export EXP_OT_CLI_PATH="${ot_cli}"
     export EXP_OT_NCP_PATH="${ot_ncp}"
 
@@ -224,6 +254,7 @@ test_teardown()
     write_syslog "EXIT ${EXIT_CODE} - output logs"
 
     sudo pkill -f "${OTBR_AGENT}" || true
+    sudo pkill -f "${OT_CTL}" || true
     sudo pkill -f "${OT_CLI}" || true
     sudo pkill -f "${OT_NCP}" || true
     wait
@@ -238,6 +269,13 @@ test_teardown()
     exit ${EXIT_CODE}
 }
 
+restart_avahi_daemon()
+{
+    # Restart the avahi-daemon on the host to remove stale records from previous test runs.
+    sudo service avahi-daemon restart
+    sleep 1
+}
+
 otbr_exec_expect_script()
 {
     local log_file="tmp/log_expect"
@@ -252,6 +290,7 @@ otbr_exec_expect_script()
         sudo killall ot-ncp-mtd || true
         sudo rm -rf tmp
         mkdir tmp
+        restart_avahi_daemon
         {
             sudo -E expect -df "${script}" 2>"${log_file}"
         } || {
@@ -306,6 +345,7 @@ main()
     export EXP_TUN_NAME="${TUN_NAME}"
     export EXP_LEADER_NODE_ID="${LEADER_NODE_ID}"
     export EXP_OTBR_DOCKER_IMAGE="${OTBR_DOCKER_IMAGE}"
+    export EXP_OT_COMMISSIONER_PATH="${OT_COMMISSIONER_PATH}"
 
     while [[ $# != 0 ]]; do
         case "$1" in
@@ -315,6 +355,9 @@ main()
             build_otbr_docker)
                 do_build_otbr_docker
                 ;;
+            build_ot_commissioner)
+                do_build_ot_commissioner
+                ;;
             expect)
                 shift
                 test_setup
diff --git a/third_party/mDNSResponder/0001-Fix-Linux-build.patch b/third_party/mDNSResponder/0001-Fix-Linux-build.patch
deleted file mode 100644
index 1dc01f3f..00000000
--- a/third_party/mDNSResponder/0001-Fix-Linux-build.patch
+++ /dev/null
@@ -1,32 +0,0 @@
-From e136dcdcdd93ef32ada981e89c195905eb809eea Mon Sep 17 00:00:00 2001
-Message-ID: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-From: Nate Karstens <nate.karstens@garmin.com>
-Date: Thu, 23 Mar 2023 00:15:52 -0500
-Subject: [PATCH] Fix Linux build
-
-The __block qualifier is not used in Linux builds.
-
-Signed-off-by: Nate Karstens <nate.karstens@garmin.com>
----
- mDNSShared/uds_daemon.c | 4 ++++
- 1 file changed, 4 insertions(+)
-
-diff --git a/mDNSShared/uds_daemon.c b/mDNSShared/uds_daemon.c
-index 9ae5f78..5a00bb5 100644
---- a/mDNSShared/uds_daemon.c
-+++ b/mDNSShared/uds_daemon.c
-@@ -2912,7 +2912,11 @@ exit:
- mDNSlocal mStatus add_domain_to_browser(request_state *info, const domainname *d)
- {
-     browser_t *b, *p;
-+#if defined(TARGET_OS_MAC) && TARGET_OS_MAC
-     __block mStatus err;
-+#else
-+    mStatus err;
-+#endif
- 
-     for (p = info->u.browser.browsers; p; p = p->next)
-     {
--- 
-2.41.0
-
diff --git a/third_party/mDNSResponder/0002-Create-subroutine-for-cleaning-recent-interfaces.patch b/third_party/mDNSResponder/0002-Create-subroutine-for-cleaning-recent-interfaces.patch
deleted file mode 100644
index 98da74c5..00000000
--- a/third_party/mDNSResponder/0002-Create-subroutine-for-cleaning-recent-interfaces.patch
+++ /dev/null
@@ -1,64 +0,0 @@
-From 4f7970ac1615aba7a39ae94c1ca14135265574e9 Mon Sep 17 00:00:00 2001
-Message-ID: <4f7970ac1615aba7a39ae94c1ca14135265574e9.1687508149.git.stefan@agner.ch>
-In-Reply-To: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-References: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-From: Nate Karstens <nate.karstens@garmin.com>
-Date: Wed, 28 Jun 2017 17:30:00 -0500
-Subject: [PATCH] Create subroutine for cleaning recent interfaces
-
-Moves functionality for cleaning the list of recent
-interfaces into its own subroutine.
-
-Upstream-Status: Submitted [dts@apple.com]
-
-Signed-off-by: Nate Karstens <nate.karstens@garmin.com>
-Signed-off-by: Alex Kiernan <alex.kiernan@gmail.com>
----
- mDNSPosix/mDNSPosix.c | 24 ++++++++++++++----------
- 1 file changed, 14 insertions(+), 10 deletions(-)
-
-diff --git a/mDNSPosix/mDNSPosix.c b/mDNSPosix/mDNSPosix.c
-index 0a7c3df..fe7242d 100644
---- a/mDNSPosix/mDNSPosix.c
-+++ b/mDNSPosix/mDNSPosix.c
-@@ -1322,6 +1322,19 @@ mDNSlocal int SetupSocket(struct sockaddr *intfAddr, mDNSIPPort port, int interf
-     return err;
- }
- 
-+// Clean up any interfaces that have been hanging around on the RecentInterfaces list for more than a minute
-+mDNSlocal void CleanRecentInterfaces(void)
-+{
-+    PosixNetworkInterface **ri = &gRecentInterfaces;
-+    const mDNSs32 utc = mDNSPlatformUTC();
-+    while (*ri)
-+    {
-+        PosixNetworkInterface *pi = *ri;
-+        if (utc - pi->LastSeen < 60) ri = (PosixNetworkInterface **)&pi->coreIntf.next;
-+        else { *ri = (PosixNetworkInterface *)pi->coreIntf.next; mdns_free(pi); }
-+    }
-+}
-+
- // Creates a PosixNetworkInterface for the interface whose IP address is
- // intfAddr and whose name is intfName and registers it with mDNS core.
- mDNSlocal int SetupOneInterface(mDNS *const m, struct sockaddr *intfAddr, struct sockaddr *intfMask,
-@@ -1559,16 +1572,7 @@ mDNSlocal int SetupInterfaceList(mDNS *const m)
- 
-     // Clean up.
-     if (intfList != NULL) freeifaddrs(intfList);
--
--    // Clean up any interfaces that have been hanging around on the RecentInterfaces list for more than a minute
--    PosixNetworkInterface **ri = &gRecentInterfaces;
--    const mDNSs32 utc = mDNSPlatformUTC();
--    while (*ri)
--    {
--        PosixNetworkInterface *pi = *ri;
--        if (utc - pi->LastSeen < 60) ri = (PosixNetworkInterface **)&pi->coreIntf.next;
--        else { *ri = (PosixNetworkInterface *)pi->coreIntf.next; mdns_free(pi); }
--    }
-+    CleanRecentInterfaces();
- 
-     return err;
- }
--- 
-2.41.0
-
diff --git a/third_party/mDNSResponder/0003-Create-subroutine-for-tearing-down-an-interface.patch b/third_party/mDNSResponder/0003-Create-subroutine-for-tearing-down-an-interface.patch
deleted file mode 100644
index 812bd20c..00000000
--- a/third_party/mDNSResponder/0003-Create-subroutine-for-tearing-down-an-interface.patch
+++ /dev/null
@@ -1,62 +0,0 @@
-From f7ab91f739b936305ca56743adfb4673e3f2f4ba Mon Sep 17 00:00:00 2001
-Message-ID: <f7ab91f739b936305ca56743adfb4673e3f2f4ba.1687508149.git.stefan@agner.ch>
-In-Reply-To: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-References: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-From: Nate Karstens <nate.karstens@garmin.com>
-Date: Wed, 28 Jun 2017 17:30:00 -0500
-Subject: [PATCH] Create subroutine for tearing down an interface
-
-Creates a subroutine for tearing down an interface.
-
-Upstream-Status: Submitted [dts@apple.com]
-
-Signed-off-by: Nate Karstens <nate.karstens@garmin.com>
-Signed-off-by: Alex Kiernan <alex.kiernan@gmail.com>
----
- mDNSPosix/mDNSPosix.c | 22 ++++++++++++++++------
- 1 file changed, 16 insertions(+), 6 deletions(-)
-
-diff --git a/mDNSPosix/mDNSPosix.c b/mDNSPosix/mDNSPosix.c
-index fe7242d..a32a880 100644
---- a/mDNSPosix/mDNSPosix.c
-+++ b/mDNSPosix/mDNSPosix.c
-@@ -1043,6 +1043,19 @@ mDNSlocal void FreePosixNetworkInterface(PosixNetworkInterface *intf)
-     gRecentInterfaces = intf;
- }
- 
-+mDNSlocal void TearDownInterface(mDNS *const m, PosixNetworkInterface *intf)
-+{
-+    mDNS_DeregisterInterface(m, &intf->coreIntf, NormalActivation);
-+    if (gMDNSPlatformPosixVerboseLevel > 0) fprintf(stderr, "Deregistered interface %s\n", intf->intfName);
-+    FreePosixNetworkInterface(intf);
-+
-+    num_registered_interfaces--;
-+    if (num_registered_interfaces == 0) {
-+        num_pkts_accepted = 0;
-+        num_pkts_rejected = 0;
-+    }
-+}
-+
- // Grab the first interface, deregister it, free it, and repeat until done.
- mDNSlocal void ClearInterfaceList(mDNS *const m)
- {
-@@ -1051,13 +1064,10 @@ mDNSlocal void ClearInterfaceList(mDNS *const m)
-     while (m->HostInterfaces)
-     {
-         PosixNetworkInterface *intf = (PosixNetworkInterface*)(m->HostInterfaces);
--        mDNS_DeregisterInterface(m, &intf->coreIntf, NormalActivation);
--        if (gMDNSPlatformPosixVerboseLevel > 0) fprintf(stderr, "Deregistered interface %s\n", intf->intfName);
--        FreePosixNetworkInterface(intf);
-+        TearDownInterface(m, intf);
-     }
--    num_registered_interfaces = 0;
--    num_pkts_accepted = 0;
--    num_pkts_rejected = 0;
-+
-+    assert(num_registered_interfaces == 0);
- }
- 
- mDNSlocal int SetupIPv6Socket(int fd)
--- 
-2.41.0
-
diff --git a/third_party/mDNSResponder/0004-Track-interface-socket-family.patch b/third_party/mDNSResponder/0004-Track-interface-socket-family.patch
deleted file mode 100644
index 48fbc741..00000000
--- a/third_party/mDNSResponder/0004-Track-interface-socket-family.patch
+++ /dev/null
@@ -1,54 +0,0 @@
-From 542c1b2ce1dcc069cf848d11978c8b6ae5982b6e Mon Sep 17 00:00:00 2001
-Message-ID: <542c1b2ce1dcc069cf848d11978c8b6ae5982b6e.1687508149.git.stefan@agner.ch>
-In-Reply-To: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-References: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-From: Nate Karstens <nate.karstens@garmin.com>
-Date: Wed, 28 Jun 2017 17:30:00 -0500
-Subject: [PATCH] Track interface socket family
-
-Tracks the socket family associated with the interface.
-
-Upstream-Status: Submitted [dts@apple.com]
-
-Signed-off-by: Nate Karstens <nate.karstens@garmin.com>
-Signed-off-by: Alex Kiernan <alex.kiernan@gmail.com>
----
- mDNSPosix/mDNSPosix.c | 1 +
- mDNSPosix/mDNSPosix.h | 2 ++
- 2 files changed, 3 insertions(+)
-
-diff --git a/mDNSPosix/mDNSPosix.c b/mDNSPosix/mDNSPosix.c
-index a32a880..9a5b4d7 100644
---- a/mDNSPosix/mDNSPosix.c
-+++ b/mDNSPosix/mDNSPosix.c
-@@ -1415,6 +1415,7 @@ mDNSlocal int SetupOneInterface(mDNS *const m, struct sockaddr *intfAddr, struct
-         // Set up the extra fields in PosixNetworkInterface.
-         assert(intf->intfName != NULL);         // intf->intfName already set up above
-         intf->index                = intfIndex;
-+        intf->sa_family            = intfAddr->sa_family;
-         intf->multicastSocket4     = -1;
- #if HAVE_IPV6
-         intf->multicastSocket6     = -1;
-diff --git a/mDNSPosix/mDNSPosix.h b/mDNSPosix/mDNSPosix.h
-index 9675591..dd7864c 100644
---- a/mDNSPosix/mDNSPosix.h
-+++ b/mDNSPosix/mDNSPosix.h
-@@ -19,6 +19,7 @@
- #define __mDNSPlatformPosix_h
- 
- #include <signal.h>
-+#include <sys/socket.h>
- #include <sys/time.h>
- 
- #ifdef  __cplusplus
-@@ -40,6 +41,7 @@ struct PosixNetworkInterface
-     char *                  intfName;
-     PosixNetworkInterface * aliasIntf;
-     int index;
-+    sa_family_t sa_family;
-     int multicastSocket4;
- #if HAVE_IPV6
-     int multicastSocket6;
--- 
-2.41.0
-
diff --git a/third_party/mDNSResponder/0005-Indicate-loopback-interface-to-mDNS-core.patch b/third_party/mDNSResponder/0005-Indicate-loopback-interface-to-mDNS-core.patch
deleted file mode 100644
index f7aa4617..00000000
--- a/third_party/mDNSResponder/0005-Indicate-loopback-interface-to-mDNS-core.patch
+++ /dev/null
@@ -1,61 +0,0 @@
-From 44385771ef63f081ed7e80eae6f24591046b4c7c Mon Sep 17 00:00:00 2001
-Message-ID: <44385771ef63f081ed7e80eae6f24591046b4c7c.1687508149.git.stefan@agner.ch>
-In-Reply-To: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-References: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-From: Nate Karstens <nate.karstens@garmin.com>
-Date: Tue, 1 Aug 2017 17:06:01 -0500
-Subject: [PATCH] Indicate loopback interface to mDNS core
-
-Tells the mDNS core if an interface is a loopback interface,
-similar to AddInterfaceToList() in the MacOS implementation.
-
-Upstream-Status: Submitted [dts@apple.com]
-
-Signed-off-by: Nate Karstens <nate.karstens@garmin.com>
-Signed-off-by: Alex Kiernan <alex.kiernan@gmail.com>
----
- mDNSPosix/mDNSPosix.c | 7 ++++---
- 1 file changed, 4 insertions(+), 3 deletions(-)
-
-diff --git a/mDNSPosix/mDNSPosix.c b/mDNSPosix/mDNSPosix.c
-index 9a5b4d7..02a19b4 100644
---- a/mDNSPosix/mDNSPosix.c
-+++ b/mDNSPosix/mDNSPosix.c
-@@ -1348,7 +1348,7 @@ mDNSlocal void CleanRecentInterfaces(void)
- // Creates a PosixNetworkInterface for the interface whose IP address is
- // intfAddr and whose name is intfName and registers it with mDNS core.
- mDNSlocal int SetupOneInterface(mDNS *const m, struct sockaddr *intfAddr, struct sockaddr *intfMask,
--    const mDNSu8 *intfHaddr, mDNSu16 intfHlen, const char *intfName, int intfIndex)
-+    const mDNSu8 *intfHaddr, mDNSu16 intfHlen, const char *intfName, int intfIndex, int intfFlags)
- {
-     int err = 0;
-     PosixNetworkInterface *intf;
-@@ -1411,6 +1411,7 @@ mDNSlocal int SetupOneInterface(mDNS *const m, struct sockaddr *intfAddr, struct
- 
-         intf->coreIntf.Advertise = m->AdvertiseLocalAddresses;
-         intf->coreIntf.McastTxRx = mDNStrue;
-+        intf->coreIntf.Loopback = ((intfFlags & IFF_LOOPBACK) != 0) ? mDNStrue : mDNSfalse;
- 
-         // Set up the extra fields in PosixNetworkInterface.
-         assert(intf->intfName != NULL);         // intf->intfName already set up above
-@@ -1561,7 +1562,7 @@ mDNSlocal int SetupInterfaceList(mDNS *const m)
-                     }
- #endif
-                     if (SetupOneInterface(m, i->ifa_addr, i->ifa_netmask,
--                                          hwaddr, hwaddr_len, i->ifa_name, ifIndex) == 0)
-+                                          hwaddr, hwaddr_len, i->ifa_name, ifIndex, i->ifa_flags) == 0)
-                     {
-                         if (i->ifa_addr->sa_family == AF_INET)
-                             foundav4 = mDNStrue;
-@@ -1578,7 +1579,7 @@ mDNSlocal int SetupInterfaceList(mDNS *const m)
-         // if ((m->HostInterfaces == NULL) && (firstLoopback != NULL))
-         if (!foundav4 && firstLoopback)
-             (void) SetupOneInterface(m, firstLoopback->ifa_addr, firstLoopback->ifa_netmask,
--                NULL, 0, firstLoopback->ifa_name, firstLoopbackIndex);
-+                NULL, 0, firstLoopback->ifa_name, firstLoopbackIndex, firstLoopback->ifa_flags);
-     }
- 
-     // Clean up.
--- 
-2.41.0
-
diff --git a/third_party/mDNSResponder/0006-Use-list-for-changed-interfaces.patch b/third_party/mDNSResponder/0006-Use-list-for-changed-interfaces.patch
deleted file mode 100644
index 87ac1907..00000000
--- a/third_party/mDNSResponder/0006-Use-list-for-changed-interfaces.patch
+++ /dev/null
@@ -1,178 +0,0 @@
-From 2a0f873184068f21e1d0d2a3e0d8c26bc705bf88 Mon Sep 17 00:00:00 2001
-Message-ID: <2a0f873184068f21e1d0d2a3e0d8c26bc705bf88.1687508149.git.stefan@agner.ch>
-In-Reply-To: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-References: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-From: Nate Karstens <nate.karstens@garmin.com>
-Date: Thu, 13 Jul 2017 09:00:00 -0500
-Subject: [PATCH] Use list for changed interfaces
-
-Uses a linked list to store the index of changed network interfaces
-instead of a bitfield. This allows for network interfaces with an
-index greater than 31 (an index of 36 was seen on Android).
-
-Upstream-Status: Submitted [dts@apple.com]
-
-Signed-off-by: Nate Karstens <nate.karstens@garmin.com>
-Signed-off-by: Alex Kiernan <alex.kiernan@gmail.com>
-Change-Id: Ibeab0ec68ca0d21da8384d4362e59afd2951f138
----
- mDNSPosix/mDNSPosix.c | 60 +++++++++++++++++++++++++++++++------------
- 1 file changed, 44 insertions(+), 16 deletions(-)
-
-diff --git a/mDNSPosix/mDNSPosix.c b/mDNSPosix/mDNSPosix.c
-index 02a19b4..9867881 100644
---- a/mDNSPosix/mDNSPosix.c
-+++ b/mDNSPosix/mDNSPosix.c
-@@ -74,6 +74,14 @@ struct IfChangeRec
- };
- typedef struct IfChangeRec IfChangeRec;
- 
-+// Used to build a list of network interface indices
-+struct NetworkInterfaceIndex
-+{
-+    int if_index;
-+    struct NetworkInterfaceIndex *Next;
-+};
-+typedef struct NetworkInterfaceIndex NetworkInterfaceIndex;
-+
- // Note that static data is initialized to zero in (modern) C.
- static PosixEventSource *gEventSources;             // linked list of PosixEventSource's
- static sigset_t gEventSignalSet;                // Signals which event loop listens for
-@@ -1621,6 +1629,23 @@ mDNSlocal mStatus OpenIfNotifySocket(int *pFD)
-     return err;
- }
- 
-+mDNSlocal void AddInterfaceIndexToList(GenLinkedList *list, int if_index)
-+{
-+    NetworkInterfaceIndex *item;
-+
-+    for (item = (NetworkInterfaceIndex*)list->Head; item != NULL; item = item->Next)
-+    {
-+        if (if_index == item->if_index) return;
-+    }
-+
-+    item = mdns_malloc(sizeof *item);
-+    if (item == NULL) return;
-+
-+    item->if_index = if_index;
-+    item->Next = NULL;
-+    AddToTail(list, item);
-+}
-+
- #if MDNS_DEBUGMSGS
- mDNSlocal void      PrintNetLinkMsg(const struct nlmsghdr *pNLMsg)
- {
-@@ -1648,14 +1673,13 @@ mDNSlocal void      PrintNetLinkMsg(const struct nlmsghdr *pNLMsg)
- }
- #endif
- 
--mDNSlocal mDNSu32       ProcessRoutingNotification(int sd)
-+mDNSlocal void          ProcessRoutingNotification(int sd, GenLinkedList *changedInterfaces)
- // Read through the messages on sd and if any indicate that any interface records should
- // be torn down and rebuilt, return affected indices as a bitmask. Otherwise return 0.
- {
-     ssize_t readCount;
-     char buff[4096];
-     struct nlmsghdr         *pNLMsg = (struct nlmsghdr*) buff;
--    mDNSu32 result = 0;
- 
-     // The structure here is more complex than it really ought to be because,
-     // unfortunately, there's no good way to size a buffer in advance large
-@@ -1691,9 +1715,9 @@ mDNSlocal mDNSu32       ProcessRoutingNotification(int sd)
- 
-         // Process the NetLink message
-         if (pNLMsg->nlmsg_type == RTM_GETLINK || pNLMsg->nlmsg_type == RTM_NEWLINK)
--            result |= 1 << ((struct ifinfomsg*) NLMSG_DATA(pNLMsg))->ifi_index;
-+            AddInterfaceIndexToList(changedInterfaces, ((struct ifinfomsg*) NLMSG_DATA(pNLMsg))->ifi_index);
-         else if (pNLMsg->nlmsg_type == RTM_DELADDR || pNLMsg->nlmsg_type == RTM_NEWADDR)
--            result |= 1 << ((struct ifaddrmsg*) NLMSG_DATA(pNLMsg))->ifa_index;
-+            AddInterfaceIndexToList(changedInterfaces, ((struct ifaddrmsg*) NLMSG_DATA(pNLMsg))->ifa_index);
- 
-         // Advance pNLMsg to the next message in the buffer
-         if ((pNLMsg->nlmsg_flags & NLM_F_MULTI) != 0 && pNLMsg->nlmsg_type != NLMSG_DONE)
-@@ -1704,8 +1728,6 @@ mDNSlocal mDNSu32       ProcessRoutingNotification(int sd)
-         else
-             break;  // all done!
-     }
--
--    return result;
- }
- 
- #else // USES_NETLINK
-@@ -1737,18 +1759,17 @@ mDNSlocal void      PrintRoutingSocketMsg(const struct ifa_msghdr *pRSMsg)
- }
- #endif
- 
--mDNSlocal mDNSu32       ProcessRoutingNotification(int sd)
-+mDNSlocal void          ProcessRoutingNotification(int sd, GenLinkedList *changedInterfaces)
- // Read through the messages on sd and if any indicate that any interface records should
- // be torn down and rebuilt, return affected indices as a bitmask. Otherwise return 0.
- {
-     ssize_t readCount;
-     char buff[4096];
-     struct ifa_msghdr       *pRSMsg = (struct ifa_msghdr*) buff;
--    mDNSu32 result = 0;
- 
-     readCount = read(sd, buff, sizeof buff);
-     if (readCount < (ssize_t) sizeof(struct ifa_msghdr))
--        return mStatus_UnsupportedErr;      // cannot decipher message
-+        return;      // cannot decipher message
- 
- #if MDNS_DEBUGMSGS
-     PrintRoutingSocketMsg(pRSMsg);
-@@ -1759,12 +1780,10 @@ mDNSlocal mDNSu32       ProcessRoutingNotification(int sd)
-         pRSMsg->ifam_type == RTM_IFINFO)
-     {
-         if (pRSMsg->ifam_type == RTM_IFINFO)
--            result |= 1 << ((struct if_msghdr*) pRSMsg)->ifm_index;
-+            AddInterfaceIndexToList(changedInterfaces, ((struct if_msghdr*) pRSMsg)->ifm_index);
-         else
--            result |= 1 << pRSMsg->ifam_index;
-+            AddInterfaceIndexToList(changedInterfaces, pRSMsg->ifam_index);
-     }
--
--    return result;
- }
- 
- #endif // USES_NETLINK
-@@ -1774,7 +1793,8 @@ mDNSlocal void InterfaceChangeCallback(int fd, void *context)
- {
-     IfChangeRec     *pChgRec = (IfChangeRec*) context;
-     fd_set readFDs;
--    mDNSu32 changedInterfaces = 0;
-+    GenLinkedList changedInterfaces;
-+    NetworkInterfaceIndex *changedInterface;
-     struct timeval zeroTimeout = { 0, 0 };
- 
-     (void)fd; // Unused
-@@ -1782,17 +1802,25 @@ mDNSlocal void InterfaceChangeCallback(int fd, void *context)
-     FD_ZERO(&readFDs);
-     FD_SET(pChgRec->NotifySD, &readFDs);
- 
-+    InitLinkedList(&changedInterfaces, offsetof(NetworkInterfaceIndex, Next));
-+
-     do
-     {
--        changedInterfaces |= ProcessRoutingNotification(pChgRec->NotifySD);
-+        ProcessRoutingNotification(pChgRec->NotifySD, &changedInterfaces);
-     }
-     while (0 < select(pChgRec->NotifySD + 1, &readFDs, (fd_set*) NULL, (fd_set*) NULL, &zeroTimeout));
- 
-     // Currently we rebuild the entire interface list whenever any interface change is
-     // detected. If this ever proves to be a performance issue in a multi-homed
-     // configuration, more care should be paid to changedInterfaces.
--    if (changedInterfaces)
-+    if (changedInterfaces.Head != NULL)
-         mDNSPlatformPosixRefreshInterfaceList(pChgRec->mDNS);
-+
-+    while ((changedInterface = (NetworkInterfaceIndex*)changedInterfaces.Head) != NULL)
-+    {
-+        RemoveFromList(&changedInterfaces, changedInterface);
-+        mdns_free(changedInterface);
-+    }
- }
- 
- // Register with either a Routing Socket or RtNetLink to listen for interface changes.
--- 
-2.41.0
-
diff --git a/third_party/mDNSResponder/0007-Handle-noisy-netlink-sockets.patch b/third_party/mDNSResponder/0007-Handle-noisy-netlink-sockets.patch
deleted file mode 100644
index 08cce016..00000000
--- a/third_party/mDNSResponder/0007-Handle-noisy-netlink-sockets.patch
+++ /dev/null
@@ -1,255 +0,0 @@
-From 00289e89cccb9567d6ea6bd2a394fd14b61e5ad1 Mon Sep 17 00:00:00 2001
-Message-ID: <00289e89cccb9567d6ea6bd2a394fd14b61e5ad1.1687508149.git.stefan@agner.ch>
-In-Reply-To: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-References: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-From: Nate Karstens <nate.karstens@garmin.com>
-Date: Mon, 24 Jul 2017 09:38:55 -0500
-Subject: [PATCH] Handle noisy netlink sockets
-
-The POSIX implementation currently clears all network interfaces
-when netlink indicates that there has been a change. This causes
-the following problems:
-
-  1) Applications are informed that all of the services they are
-     tracking have been removed.
-  2) Increases network load because the client must re-query for
-     all records it is interested in.
-
-This changes netlink notification handling by:
-
-  1) Always comparing with the latest interface list returned
-     by the OS.
-  2) Confirming that the interface has been changed in a way
-     that we care about.
-
-Upstream-Status: Submitted [dts@apple.com]
-
-Signed-off-by: Nate Karstens <nate.karstens@garmin.com>
-Signed-off-by: Alex Kiernan <alex.kiernan@gmail.com>
----
- mDNSPosix/mDNSPosix.c | 182 +++++++++++++++++++++++++++++++++++++++---
- 1 file changed, 172 insertions(+), 10 deletions(-)
-
-diff --git a/mDNSPosix/mDNSPosix.c b/mDNSPosix/mDNSPosix.c
-index 9867881..ad7000d 100644
---- a/mDNSPosix/mDNSPosix.c
-+++ b/mDNSPosix/mDNSPosix.c
-@@ -1788,14 +1788,43 @@ mDNSlocal void          ProcessRoutingNotification(int sd, GenLinkedList *change
- 
- #endif // USES_NETLINK
- 
-+// Test whether the given PosixNetworkInterface matches the given struct ifaddrs
-+mDNSlocal mDNSBool InterfacesMatch(PosixNetworkInterface *intf, struct ifaddrs *ifi)
-+{
-+    mDNSBool match = mDNSfalse;
-+    mDNSAddr ip, mask;
-+    int if_index;
-+
-+    if_index = if_nametoindex(ifi->ifa_name);
-+    if (if_index == 0)
-+        return mDNSfalse;
-+
-+    if((intf->index == if_index) &&
-+       (intf->sa_family == ifi->ifa_addr->sa_family) &&
-+       (strcmp(intf->coreIntf.ifname, ifi->ifa_name) == 0))
-+        {
-+        SockAddrTomDNSAddr(ifi->ifa_addr,    &ip,   NULL);
-+        SockAddrTomDNSAddr(ifi->ifa_netmask, &mask, NULL);
-+
-+        match = mDNSSameAddress(&intf->coreIntf.ip, &ip) &&
-+                mDNSSameAddress(&intf->coreIntf.mask, &mask);
-+        }
-+
-+    return match;
-+}
-+
- // Called when data appears on interface change notification socket
- mDNSlocal void InterfaceChangeCallback(int fd, void *context)
- {
-     IfChangeRec     *pChgRec = (IfChangeRec*) context;
-+    mDNS            *m = pChgRec->mDNS;
-     fd_set readFDs;
-     GenLinkedList changedInterfaces;
-     NetworkInterfaceIndex *changedInterface;
-     struct timeval zeroTimeout = { 0, 0 };
-+    struct ifaddrs *ifa_list, **ifi, *ifa_loop4 = NULL;
-+    PosixNetworkInterface *intf, *intfNext;
-+    mDNSBool found, foundav4;
- 
-     (void)fd; // Unused
- 
-@@ -1810,12 +1839,149 @@ mDNSlocal void InterfaceChangeCallback(int fd, void *context)
-     }
-     while (0 < select(pChgRec->NotifySD + 1, &readFDs, (fd_set*) NULL, (fd_set*) NULL, &zeroTimeout));
- 
--    // Currently we rebuild the entire interface list whenever any interface change is
--    // detected. If this ever proves to be a performance issue in a multi-homed
--    // configuration, more care should be paid to changedInterfaces.
--    if (changedInterfaces.Head != NULL)
--        mDNSPlatformPosixRefreshInterfaceList(pChgRec->mDNS);
-+    CleanRecentInterfaces();
-+
-+    if (changedInterfaces.Head == NULL) goto cleanup;
-+
-+    if (getifaddrs(&ifa_list) < 0) goto cleanup;
-+
-+    for (intf = (PosixNetworkInterface*)(m->HostInterfaces); intf != NULL; intf = intfNext)
-+    {
-+        intfNext = (PosixNetworkInterface*)(intf->coreIntf.next);
-+
-+        // Loopback interface(s) are handled later
-+        if (intf->coreIntf.Loopback) continue;
-+
-+        found = mDNSfalse;
-+        for (ifi = &ifa_list; *ifi != NULL; ifi = &(*ifi)->ifa_next)
-+        {
-+            if (InterfacesMatch(intf, *ifi))
-+            {
-+                found = mDNStrue;
-+                break;
-+            }
-+        }
-+
-+        // Removes changed and old interfaces from m->HostInterfaces
-+        if (!found) TearDownInterface(m, intf);
-+    }
-+
-+    // Add new and changed interfaces in ifa_list
-+    // Save off loopback interface in case it is needed later
-+    for (ifi = &ifa_list; *ifi != NULL; ifi = &(*ifi)->ifa_next)
-+    {
-+        found = mDNSfalse;
-+        for (intf = (PosixNetworkInterface*)(m->HostInterfaces); intf != NULL; intf = intfNext)
-+        {
-+            intfNext = (PosixNetworkInterface*)(intf->coreIntf.next);
-+
-+            // Loopback interface(s) are handled later
-+            if (intf->coreIntf.Loopback) continue;
-+
-+            if (InterfacesMatch(intf, *ifi))
-+            {
-+                found = mDNStrue;
-+                break;
-+            }
-+
-+            // Removes changed and old interfaces from m->HostInterfaces
-+        }
-+        if (found)
-+	    continue;
-+
-+        if ((ifa_loop4 == NULL) &&
-+            ((*ifi)->ifa_addr->sa_family == AF_INET) &&
-+            ((*ifi)->ifa_flags & IFF_UP) &&
-+            ((*ifi)->ifa_flags & IFF_LOOPBACK))
-+        {
-+            ifa_loop4 = *ifi;
-+            continue;
-+        }
-+
-+        if (     (((*ifi)->ifa_addr->sa_family == AF_INET)
-+#if HAVE_IPV6
-+                  || ((*ifi)->ifa_addr->sa_family == AF_INET6)
-+#endif
-+                  ) && ((*ifi)->ifa_flags & IFF_UP)
-+                    && !((*ifi)->ifa_flags & IFF_POINTOPOINT)
-+                    && !((*ifi)->ifa_flags & IFF_LOOPBACK))
-+        {
-+            struct ifaddrs *i = *ifi;
-+
-+#define ethernet_addr_len 6
-+            uint8_t hwaddr[ethernet_addr_len];
-+            int hwaddr_len = 0;
-+
-+#if defined(TARGET_OS_LINUX) && TARGET_OS_LINUX
-+            struct ifreq ifr;
-+            int sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
-+            if (sockfd >= 0)
-+            {
-+                /* Add hardware address */
-+                memcpy(ifr.ifr_name, i->ifa_name, IFNAMSIZ);
-+                if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) != -1)
-+                {
-+                    if (ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER)
-+                    {
-+                        memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ethernet_addr_len);
-+                        hwaddr_len = ethernet_addr_len;
-+                    }
-+                }
-+                close(sockfd);
-+            }
-+            else
-+            {
-+                memset(hwaddr, 0, sizeof(hwaddr));
-+            }
-+#endif // TARGET_OS_LINUX
-+            SetupOneInterface(m, i->ifa_addr, i->ifa_netmask,
-+                              hwaddr, hwaddr_len, i->ifa_name, if_nametoindex(i->ifa_name), i->ifa_flags);
-+        }
-+    }
-+
-+    // Determine if there is at least one non-loopback IPv4 interface. This is to work around issues
-+    // with multicast loopback on IPv6 interfaces -- see corresponding logic in SetupInterfaceList().
-+    foundav4 = mDNSfalse;
-+    for (intf = (PosixNetworkInterface*)(m->HostInterfaces); intf != NULL; intf = (PosixNetworkInterface*)(intf->coreIntf.next))
-+    {
-+        if (intf->sa_family == AF_INET && !intf->coreIntf.Loopback)
-+        {
-+            foundav4 = mDNStrue;
-+            break;
-+        }
-+    }
-+
-+    if (foundav4)
-+    {
-+        for (intf = (PosixNetworkInterface*)(m->HostInterfaces); intf != NULL; intf = intfNext)
-+        {
-+            intfNext = (PosixNetworkInterface*)(intf->coreIntf.next);
-+            if (intf->coreIntf.Loopback) TearDownInterface(m, intf);
-+        }
-+    }
-+    else
-+    {
-+        found = mDNSfalse;
-+
-+        for (intf = (PosixNetworkInterface*)(m->HostInterfaces); intf != NULL; intf = (PosixNetworkInterface*)(intf->coreIntf.next))
-+        {
-+            if (intf->coreIntf.Loopback)
-+            {
-+                found = mDNStrue;
-+                break;
-+            }
-+        }
-+
-+        if (!found && (ifa_loop4 != NULL))
-+        {
-+            SetupOneInterface(m, ifa_loop4->ifa_addr, ifa_loop4->ifa_netmask,
-+                              NULL, 0, ifa_loop4->ifa_name, if_nametoindex(ifa_loop4->ifa_name), ifa_loop4->ifa_flags);
-+        }
-+    }
-+
-+    if (ifa_list != NULL) freeifaddrs(ifa_list);
- 
-+cleanup:
-     while ((changedInterface = (NetworkInterfaceIndex*)changedInterfaces.Head) != NULL)
-     {
-         RemoveFromList(&changedInterfaces, changedInterface);
-@@ -1947,15 +2113,11 @@ mDNSexport void mDNSPlatformClose(mDNS *const m)
- #endif
- }
- 
--// This is used internally by InterfaceChangeCallback.
--// It's also exported so that the Standalone Responder (mDNSResponderPosix)
-+// This is exported so that the Standalone Responder (mDNSResponderPosix)
- // can call it in response to a SIGHUP (mainly for debugging purposes).
- mDNSexport mStatus mDNSPlatformPosixRefreshInterfaceList(mDNS *const m)
- {
-     int err;
--    // This is a pretty heavyweight way to process interface changes --
--    // destroying the entire interface list and then making fresh one from scratch.
--    // We should make it like the OS X version, which leaves unchanged interfaces alone.
-     ClearInterfaceList(m);
-     err = SetupInterfaceList(m);
-     return PosixErrorToStatus(err);
--- 
-2.41.0
-
diff --git a/third_party/mDNSResponder/0008-Mark-deleted-interfaces-as-being-changed.patch b/third_party/mDNSResponder/0008-Mark-deleted-interfaces-as-being-changed.patch
deleted file mode 100644
index 216fde7f..00000000
--- a/third_party/mDNSResponder/0008-Mark-deleted-interfaces-as-being-changed.patch
+++ /dev/null
@@ -1,43 +0,0 @@
-From 8ebfeaf55ab364a1e51a3438dfa9a742a01b8d36 Mon Sep 17 00:00:00 2001
-Message-ID: <8ebfeaf55ab364a1e51a3438dfa9a742a01b8d36.1687508149.git.stefan@agner.ch>
-In-Reply-To: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-References: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-From: Nate Karstens <nate.karstens@garmin.com>
-Date: Wed, 9 Aug 2017 09:16:58 -0500
-Subject: [PATCH] Mark deleted interfaces as being changed
-
-Netlink notification handling ignores messages for deleted links,
-RTM_DELLINK. It does handle RTM_GETLINK. According to libnl docu-
-mentation (http://www.infradead.org/~tgr/libnl/doc/route.html)
-RTM_DELLINK can be sent by the kernel, but RTM_GETLINK cannot.
-There was likely a mixup in the original implementation, so this
-change replaces handling for RTM_GETLINK with RTM_DELLINK.
-
-Testing and Verification Instructions:
-  1. Use ip-link to add and remove a VLAN interface and verify
-     that mDNSResponder handles the deleted link.
-
-Upstream-Status: Submitted [dts@apple.com]
-
-Signed-off-by: Nate Karstens <nate.karstens@garmin.com>
-Signed-off-by: Alex Kiernan <alex.kiernan@gmail.com>
----
- mDNSPosix/mDNSPosix.c | 2 +-
- 1 file changed, 1 insertion(+), 1 deletion(-)
-
-diff --git a/mDNSPosix/mDNSPosix.c b/mDNSPosix/mDNSPosix.c
-index ad7000d..010f266 100644
---- a/mDNSPosix/mDNSPosix.c
-+++ b/mDNSPosix/mDNSPosix.c
-@@ -1714,7 +1714,7 @@ mDNSlocal void          ProcessRoutingNotification(int sd, GenLinkedList *change
- #endif
- 
-         // Process the NetLink message
--        if (pNLMsg->nlmsg_type == RTM_GETLINK || pNLMsg->nlmsg_type == RTM_NEWLINK)
-+        if (pNLMsg->nlmsg_type == RTM_DELLINK || pNLMsg->nlmsg_type == RTM_NEWLINK)
-             AddInterfaceIndexToList(changedInterfaces, ((struct ifinfomsg*) NLMSG_DATA(pNLMsg))->ifi_index);
-         else if (pNLMsg->nlmsg_type == RTM_DELADDR || pNLMsg->nlmsg_type == RTM_NEWADDR)
-             AddInterfaceIndexToList(changedInterfaces, ((struct ifaddrmsg*) NLMSG_DATA(pNLMsg))->ifa_index);
--- 
-2.41.0
-
diff --git a/third_party/mDNSResponder/0009-Handle-errors-from-socket-calls.patch b/third_party/mDNSResponder/0009-Handle-errors-from-socket-calls.patch
deleted file mode 100644
index 2057e2cb..00000000
--- a/third_party/mDNSResponder/0009-Handle-errors-from-socket-calls.patch
+++ /dev/null
@@ -1,66 +0,0 @@
-From dae89c4e97faf408394961c0f4b1577a7d5976cc Mon Sep 17 00:00:00 2001
-Message-ID: <dae89c4e97faf408394961c0f4b1577a7d5976cc.1687508149.git.stefan@agner.ch>
-In-Reply-To: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-References: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-From: Nate Karstens <nate.karstens@garmin.com>
-Date: Thu, 10 Aug 2017 08:27:32 -0500
-Subject: [PATCH] Handle errors from socket calls
-
-Adds handling for socket() or read() returning a
-negative value (indicating an error has occurred).
-
-Upstream-Status: Submitted [dts@apple.com]
-
-Signed-off-by: Nate Karstens <nate.karstens@garmin.com>
-Signed-off-by: Alex Kiernan <alex.kiernan@gmail.com>
----
- mDNSPosix/mDNSPosix.c | 12 +++++++++---
- 1 file changed, 9 insertions(+), 3 deletions(-)
-
-diff --git a/mDNSPosix/mDNSPosix.c b/mDNSPosix/mDNSPosix.c
-index 010f266..89e108f 100644
---- a/mDNSPosix/mDNSPosix.c
-+++ b/mDNSPosix/mDNSPosix.c
-@@ -1677,7 +1677,7 @@ mDNSlocal void          ProcessRoutingNotification(int sd, GenLinkedList *change
- // Read through the messages on sd and if any indicate that any interface records should
- // be torn down and rebuilt, return affected indices as a bitmask. Otherwise return 0.
- {
--    ssize_t readCount;
-+    ssize_t readVal, readCount;
-     char buff[4096];
-     struct nlmsghdr         *pNLMsg = (struct nlmsghdr*) buff;
- 
-@@ -1686,7 +1686,10 @@ mDNSlocal void          ProcessRoutingNotification(int sd, GenLinkedList *change
-     // enough to hold all pending data and so avoid message fragmentation.
-     // (Note that FIONREAD is not supported on AF_NETLINK.)
- 
--    readCount = read(sd, buff, sizeof buff);
-+    readVal = read(sd, buff, sizeof buff);
-+    if (readVal < 0) return;
-+    readCount = readVal;
-+
-     while (1)
-     {
-         // Make sure we've got an entire nlmsghdr in the buffer, and payload, too.
-@@ -1702,7 +1705,9 @@ mDNSlocal void          ProcessRoutingNotification(int sd, GenLinkedList *change
-                 pNLMsg = (struct nlmsghdr*) buff;
- 
-                 // read more data
--                readCount += read(sd, buff + readCount, sizeof buff - readCount);
-+                readVal = read(sd, buff + readCount, sizeof buff - readCount);
-+                if (readVal < 0) return;
-+                readCount += readVal;
-                 continue;                   // spin around and revalidate with new readCount
-             }
-             else
-@@ -2017,6 +2022,7 @@ mDNSlocal mDNSBool mDNSPlatformInit_CanReceiveUnicast(void)
-     int err;
-     int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
-     struct sockaddr_in s5353;
-+    if (s < 0) return mDNSfalse;
-     s5353.sin_family      = AF_INET;
-     s5353.sin_port        = MulticastDNSPort.NotAnInteger;
-     s5353.sin_addr.s_addr = 0;
--- 
-2.41.0
-
diff --git a/third_party/mDNSResponder/0010-Handle-interface-without-ifa_addr.patch b/third_party/mDNSResponder/0010-Handle-interface-without-ifa_addr.patch
deleted file mode 100644
index 602b205e..00000000
--- a/third_party/mDNSResponder/0010-Handle-interface-without-ifa_addr.patch
+++ /dev/null
@@ -1,41 +0,0 @@
-From e501d58e9ec6cb6e19a682d425fa638069585fbc Mon Sep 17 00:00:00 2001
-Message-ID: <e501d58e9ec6cb6e19a682d425fa638069585fbc.1687508149.git.stefan@agner.ch>
-In-Reply-To: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-References: <e136dcdcdd93ef32ada981e89c195905eb809eea.1687508149.git.stefan@agner.ch>
-From: Stefan Agner <stefan@agner.ch>
-Date: Fri, 23 Jun 2023 10:10:00 +0200
-Subject: [PATCH] Handle interface without `ifa_addr`
-
-It seems that certain interface types may have `ifa_addr` set to null.
-Handle this case gracefully.
-
-Signed-off-by: Stefan Agner <stefan@agner.ch>
----
- mDNSPosix/mDNSPosix.c | 4 +++-
- 1 file changed, 3 insertions(+), 1 deletion(-)
-
-diff --git a/mDNSPosix/mDNSPosix.c b/mDNSPosix/mDNSPosix.c
-index 89e108f..2056871 100644
---- a/mDNSPosix/mDNSPosix.c
-+++ b/mDNSPosix/mDNSPosix.c
-@@ -1895,6 +1895,7 @@ mDNSlocal void InterfaceChangeCallback(int fd, void *context)
- 	    continue;
- 
-         if ((ifa_loop4 == NULL) &&
-+            ((*ifi)->ifa_addr != NULL) &&
-             ((*ifi)->ifa_addr->sa_family == AF_INET) &&
-             ((*ifi)->ifa_flags & IFF_UP) &&
-             ((*ifi)->ifa_flags & IFF_LOOPBACK))
-@@ -1903,7 +1904,8 @@ mDNSlocal void InterfaceChangeCallback(int fd, void *context)
-             continue;
-         }
- 
--        if (     (((*ifi)->ifa_addr->sa_family == AF_INET)
-+        if (     ((*ifi)->ifa_addr != NULL) &&
-+                 (((*ifi)->ifa_addr->sa_family == AF_INET)
- #if HAVE_IPV6
-                   || ((*ifi)->ifa_addr->sa_family == AF_INET6)
- #endif
--- 
-2.41.0
-
diff --git a/third_party/openthread/CMakeLists.txt b/third_party/openthread/CMakeLists.txt
index 33033130..8bb5a75d 100644
--- a/third_party/openthread/CMakeLists.txt
+++ b/third_party/openthread/CMakeLists.txt
@@ -68,20 +68,28 @@ set(OT_PLATFORM_UDP ON CACHE STRING "enable platform UDP" FORCE)
 set(OT_SERVICE ON CACHE STRING "enable service" FORCE)
 set(OT_SLAAC ON CACHE STRING "enable SLAAC" FORCE)
 set(OT_SRP_CLIENT ON CACHE STRING "enable SRP client" FORCE)
-set(OT_SRP_ADV_PROXY ${OTBR_DNSSD_PLAT} CACHE STRING "enable SRP Advertising Proxy" FORCE)
+set(OT_SRP_ADV_PROXY ${OTBR_OT_SRP_ADV_PROXY} CACHE STRING "enable SRP Advertising Proxy" FORCE)
 set(OT_TARGET_OPENWRT ${OTBR_OPENWRT} CACHE STRING "target on OpenWRT" FORCE)
 set(OT_TCP OFF CACHE STRING "disable TCP")
 set(OT_TREL ${OTBR_TREL} CACHE STRING "enable TREL" FORCE)
 set(OT_UDP_FORWARD OFF CACHE STRING "disable udp forward" FORCE)
 set(OT_UPTIME ON CACHE STRING "enable uptime" FORCE)
 
-if (OTBR_DNSSD_PLAT OR OTBR_SRP_ADVERTISING_PROXY)
-    set(OT_SRP_SERVER ON CACHE STRING "enable SRP server" FORCE)
-    set(OT_EXTERNAL_HEAP ON CACHE STRING "enable external heap" FORCE)
+if (OTBR_DNSSD_PLAT)
+    set(OT_BORDER_AGENT_SERVICE_NAME ${OTBR_MESHCOP_SERVICE_INSTANCE_NAME} CACHE STRING "set the border agent service base name" FORCE)
+endif()
+
+if (OTBR_BORDER_AGENT)
+    if (OTBR_BORDER_AGENT_MESHCOP_SERVICE)
+        set(OT_BORDER_AGENT_MESHCOP_SERVICE OFF CACHE STRING "border agent meshcop service" FORCE)
+    else()
+        set(OT_BORDER_AGENT_MESHCOP_SERVICE ON CACHE STRING "border agent meshcop service" FORCE)
+    endif()
 endif()
 
-if (OT_SRP_ADV_PROXY AND OTBR_SRP_ADVERTISING_PROXY)
-    message(FATAL_ERROR "Only one Advertising Proxy can be enabled. ${OTBR_DNSSD_PLAT} ")
+if (OTBR_OT_SRP_ADV_PROXY OR OTBR_SRP_ADVERTISING_PROXY)
+    set(OT_SRP_SERVER ON CACHE STRING "enable SRP server" FORCE)
+    set(OT_EXTERNAL_HEAP ON CACHE STRING "enable external heap" FORCE)
 endif()
 
 if (NOT OT_THREAD_VERSION STREQUAL "1.1")
```

