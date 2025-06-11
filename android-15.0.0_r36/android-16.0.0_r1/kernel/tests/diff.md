```diff
diff --git a/net/test/Android.bp b/net/test/Android.bp
index fe063ee..35e8a26 100644
--- a/net/test/Android.bp
+++ b/net/test/Android.bp
@@ -15,11 +15,6 @@ python_test {
         "scapy",
     ],
     main: "all_tests.py",
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     test_config: "vts_kernel_net_tests.xml",
     test_suites: [
         "vts",
@@ -39,10 +34,5 @@ python_test {
         "scapy",
     ],
     main: "all_tests_gki.py",
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     test_config: "vts_kernel_net_tests.xml",
 }
diff --git a/net/test/OWNERS b/net/test/OWNERS
index 76fba4e..e2aecdb 100644
--- a/net/test/OWNERS
+++ b/net/test/OWNERS
@@ -1,6 +1,5 @@
 # Bug component: 31808
 set noparent
-maze@google.com
 file:platform/packages/modules/Connectivity:main:/OWNERS_core_networking_xts
 
-per-file build_rootfs.sh = rammuthiah@google.com, adelva@google.com, muntsinger@google.com
+per-file build_rootfs.sh = rammuthiah@google.com, adelva@google.com
diff --git a/net/test/net_test.py b/net/test/net_test.py
index cdfdc0f..e29884e 100644
--- a/net/test/net_test.py
+++ b/net/test/net_test.py
@@ -24,6 +24,7 @@ import struct
 import sys
 import unittest
 
+from scapy.arch import linux
 from scapy import all as scapy
 
 import binascii
@@ -270,7 +271,7 @@ def CreateSocketPair(family, socktype, addr):
 def GetInterfaceIndex(ifname):
   with UDPSocket(AF_INET) as s:
     ifr = struct.pack("%dsi" % IFNAMSIZ, ifname.encode(), 0)
-    ifr = fcntl.ioctl(s, scapy.SIOCGIFINDEX, ifr)
+    ifr = fcntl.ioctl(s, linux.SIOCGIFINDEX, ifr)
     return struct.unpack("%dsi" % IFNAMSIZ, ifr)[1]
 
 
@@ -289,14 +290,14 @@ def SetInterfaceState(ifname, up):
   ifname_bytes = ifname.encode()
   with UDPSocket(AF_INET) as s:
     ifr = struct.pack("%dsH" % IFNAMSIZ, ifname_bytes, 0)
-    ifr = fcntl.ioctl(s, scapy.SIOCGIFFLAGS, ifr)
+    ifr = fcntl.ioctl(s, linux.SIOCGIFFLAGS, ifr)
     _, flags = struct.unpack("%dsH" % IFNAMSIZ, ifr)
     if up:
-      flags |= scapy.IFF_UP
+      flags |= linux.IFF_UP
     else:
-      flags &= ~scapy.IFF_UP
+      flags &= ~linux.IFF_UP
     ifr = struct.pack("%dsH" % IFNAMSIZ, ifname_bytes, flags)
-    ifr = fcntl.ioctl(s, scapy.SIOCSIFFLAGS, ifr)
+    ifr = fcntl.ioctl(s, linux.SIOCSIFFLAGS, ifr)
 
 
 def SetInterfaceUp(ifname):
diff --git a/net/test/rootfs/OWNERS b/net/test/rootfs/OWNERS
index 9ee1527..728156f 100644
--- a/net/test/rootfs/OWNERS
+++ b/net/test/rootfs/OWNERS
@@ -1,3 +1,2 @@
 adelva@google.com
-muntsinger@google.com
 rammuthiah@google.com
diff --git a/net/test/run_net_test.sh b/net/test/run_net_test.sh
index 8635eab..3a37255 100755
--- a/net/test/run_net_test.sh
+++ b/net/test/run_net_test.sh
@@ -178,9 +178,15 @@ while [[ -n "$1" ]]; do
   elif [[ "$1" == "--nobuild" ]]; then
     nobuild=1
     shift
+  elif [[ "$1" == "--build" ]]; then
+    nobuild=0
+    shift
   elif [[ "$1" == "--norun" ]]; then
     norun=1
     shift
+  elif [[ "$1" == "--run" ]]; then
+    norun=0
+    shift
   elif [[ "$1" == "--verbose" ]]; then
     verbose=1
     shift
diff --git a/net/test/vts_kernel_net_tests.xml b/net/test/vts_kernel_net_tests.xml
index 1be8357..0f6c58a 100644
--- a/net/test/vts_kernel_net_tests.xml
+++ b/net/test/vts_kernel_net_tests.xml
@@ -26,5 +26,7 @@
     <test class="com.android.tradefed.testtype.binary.ExecutableTargetTest" >
         <option name="per-binary-timeout" value="10m" />
         <option name="test-command-line" key="vts_kernel_net_tests" value="/data/local/tmp/vts_kernel_net_tests/kernel_net_tests_bin" />
+        <!-- parse the results with python unit test format -->
+        <option name="parse-python-unit-test" value="true" />
     </test>
 </configuration>
diff --git a/tools/coverage_howto.md b/tools/coverage_howto.md
index 80829aa..c9df271 100644
--- a/tools/coverage_howto.md
+++ b/tools/coverage_howto.md
@@ -1,62 +1,91 @@
-HOW TO COLLECT KERNEL CODE COVERAGE FROM A TRADEFED TEST RUN
-============================================================
+HOW TO COLLECT KERNEL CODE COVERAGE FROM A TEST RUN
+===================================================
 
 
-## Build and use a kernel with GCOV profile enabled
-Build your kernel with the [`--gcov`](https://android.googlesource.com/kernel/build/+/refs/heads/main/kleaf/docs/gcov.md) option to enable
-GCOV profiling from the kernel. This will also trigger the build to save the required *.gcno files needed to viewing the collected count data.
+## 1. Build and use a kernel with GCOV profile enabled
+### Build and install with scripts
+Build and install a GCOV kernel on a Cuttlefish or physical device with one of
+the following commands:
+```
+$ kernel/tests/tools/launch_cvd.sh --gcov
+```
+```
+$ kernel/tests/tools/flash_device.sh --gcov
+```
+To view available options, run the scripts with `--help`.
+
+### Build on your own
+Build a kernel with
+[`--gcov`](https://android.googlesource.com/kernel/build/+/refs/heads/main/kleaf/docs/gcov.md)
+option. This will also trigger the build to save the required *.gcno files
+needed to viewing the collected count data.
+
+For example, build a Cuttlefish kernel with GCOV:
+```
+$ tools/bazel run --gcov //common-modules/virtual-device:virtual_device_x86_64_dist
+```
+
+## 2. Run tests with kernel coverage collection enabled
+### `run_test_only.sh`
+Collect test coverage data with `run_test_only.sh --gcov` and the required
+options. For example,
 
-For example to build a Cuttlefish (CF) kernel with GCOV profiling enabled run:
 ```
-$ bazel run --gcov //common-modules/virtual-device:virtual_device_x86_64_dist
+$ kernel/tests/tools/run_test_only.sh --gcov \
+    --serial 0.0.0.0:6520 --test='selftests kselftest_net_socket'
 ```
 
-## Run your test(s) using tradefed.sh with kernel coverage collection enabled
-'tradefed.sh' can be used to run a number of different types of tests. Adding the appropriate coverage flags
-to the tradefed call will trigger tradefed to take care of mounting debugfs, reseting the gcov counts prior
-to test run, and the collection of gcov data files from debugfs after test completion.
+To view available options, run the script with `--help`.
 
-These coverage arguments are:
+### `tradefed.sh`
+Adding the appropriate coverage flags to the tradefed call will trigger it to
+take care of mounting debugfs, reseting the gcov counts prior to test run, and
+collecting gcov data files from debugfs after test completion. These coverage
+arguments are:
 ```
 --coverage --coverage-toolchain GCOV_KERNEL --auto-collect GCOV_KERNEL_COVERAGE
 ```
 
-The following is a full example call running just the `kselftest_net_socket` test in the
-selftests test suite that exists under the 'bazel-bin/common/testcases' directory. The artifact
-output has been redirected to 'tf-logs' for easier reference needed in the next step.
+The following is a full example call running just the `kselftest_net_socket`
+test in the selftests test suite that exists under the `out/tests/testcases`
+directory. The artifact output has been redirected to `tf-logs` for easier
+reference needed in the next step.
 ```
 $ prebuilts/tradefed/filegroups/tradefed/tradefed.sh run commandAndExit \
     template/local_min --template:map test=suite/test_mapping_suite     \
-    --include-filter 'selftests kselftest_net_socket' --tests-dir=bazel-bin/common/testcases/  \
+    --include-filter 'selftests kselftest_net_socket'                   \
+    --tests-dir=out/tests/testcases                                     \
     --primary-abi-only --log-file-path tf-logs                          \
     --coverage --coverage-toolchain GCOV_KERNEL                         \
     --auto-collect GCOV_KERNEL_COVERAGE
 ```
 
-## Create an lcov tracefile out of the gcov tar artifact from test run
-The previously mentioned tradefed run will produce a tar file artifact in the
-tradefed log folder with a name similar to <test>_kernel_coverage_*.tar.gz.
-This tar file is an archive of all the gcov data files collected into debugfs/
-from the profiled device. In order to make it easier to work with this data,
-it needs to be converted to a single lcov tracefile.
-
-The script 'create-tracefile.py' facilitates this generation by handling the
-required unpacking, file path corrections and ultimate 'lcov' call.
-
-An example where we generate a tracefile only including results from net/socket.c.
-(If no source files are specified as included, then all source file data is used):
+## 3. Create an lcov tracefile out of the gcov tar artifact from test run
+The previously mentioned `run_test_only.sh` or `tradefed.sh` run will produce
+a tar file artifact in the log folder with a name like
+`<test>_kernel_coverage_*.tar.gz`. This tar file is an archive of all the gcov
+data files collected into debugfs from the profiled device. In order to make
+it easier to work with this data, it needs to be converted to a single lcov
+tracefile.
+
+The script `create-tracefile.py` facilitates this generation by handling the
+required unpacking, file path corrections and ultimate `lcov` call.
+`run_test_only.sh` calls `create-tracefile.py` automatically if it can locate
+the kernel source. Otherwise, it shows the arguments for you to run
+`create-tracefile.py` in the kernel source tree.
+
+If you use `tradefed.sh`, you need to issue the `create-tracefile.py` command.
+The following is an example where we generate a tracefile named `cov.info`
+only including results from `net/socket.c`. (If no source files are specified
+as included, then all source file data is used.)
 ```
-$ ./kernel/tests/tools/create-tracefile.py -t tf-logs/ --include net/socket.c
+$ kernel/tests/tools/create-tracefile.py -t tf-logs --include net/socket.c
 ```
 
-This will create a local tracefile named 'cov.info'.
-
-
-## Visualizing Results
-With the created tracefile there a number of different ways to view coverage data from it.
-Check out 'man lcov' for more options.
-### 1. Text Options
-#### 1.1 Summary
+## 4. Visualizing results
+With the created tracefile, there are a number of different ways to view
+coverage data from it. Check out `man lcov` for more options.
+### Summary
 ```
 $ lcov --summary --rc lcov_branch_coverage=1 cov.info
 Reading tracefile cov.info_fix
@@ -65,7 +94,7 @@ Summary coverage rate:
   functions..: 9.6% (10285 of 107304 functions)
   branches...: 3.7% (28639 of 765538 branches)
 ```
-#### 1.2 List
+### List
 ```
 $ lcov --list --rc lcov_branch_coverage=1 cov.info
 Reading tracefile cov.info_fix
@@ -81,18 +110,17 @@ virt/lib/irqbypass.c                           | 0.0%   137| 0.0%   6| 0.0%   88
 ================================================================================
                                          Total:| 6.0% 1369k| 9.6%  0M| 3.7% 764k
 ```
-### 2. HTML
-The `lcov` tool `genhtml` is used to generate html. To create html with the default settings:
+### HTML
+The `lcov` tool `genhtml` is used to generate html. To create html with the
+default settings:
 
 ```
 $ genhtml --branch-coverage -o html cov.info
 ```
 
-The page can be viewed at `html\index.html`.
+The page can be viewed at `html/index.html`.
 
 Options of interest:
  * `--frame`: Creates a left hand macro view in a source file view.
- * `--missed`: Helpful if you want to sort by what source is missing the most as opposed to the default coverage percentages.
-
-
-
+ * `--missed`: Helpful if you want to sort by what source is missing the most
+   as opposed to the default coverage percentages.
diff --git a/tools/flash_device.sh b/tools/flash_device.sh
index 52b7d68..f7f75e0 100755
--- a/tools/flash_device.sh
+++ b/tools/flash_device.sh
@@ -6,9 +6,9 @@
 # Constants
 FETCH_SCRIPT="fetch_artifact.sh"
 # Please see go/cl_flashstation
-FLASH_CLI=/google/bin/releases/android/flashstation/cl_flashstation
+CL_FLASH_CLI=/google/bin/releases/android/flashstation/cl_flashstation
 LOCAL_FLASH_CLI=/google/bin/releases/android/flashstation/local_flashstation
-REMOTE_MIX_SCRIPT_PATH="DATA/local/tmp/build_mixed_kernels_ramdisk"
+MIX_SCRIPT_NAME="build_mixed_kernels_ramdisk"
 FETCH_SCRIPT="kernel/tests/tools/fetch_artifact.sh"
 DOWNLOAD_PATH="/tmp/downloaded_images"
 KERNEL_TF_PREBUILT=prebuilts/tradefed/filegroups/tradefed/tradefed.sh
@@ -17,6 +17,8 @@ KERNEL_JDK_PATH=prebuilts/jdk/jdk11/linux-x86
 PLATFORM_JDK_PATH=prebuilts/jdk/jdk21/linux-x86
 LOCAL_JDK_PATH=/usr/local/buildtools/java/jdk11
 LOG_DIR=$PWD/out/test_logs/$(date +%Y%m%d_%H%M%S)
+MIN_FASTBOOT_VERSION="35.0.2-12583183"
+VENDOR_KERNEL_IMGS=("boot.img" "initramfs.img" "dtb.img" "dtbo.img" "vendor_dlkm.img")
 # Color constants
 BOLD="$(tput bold)"
 END="$(tput sgr0)"
@@ -69,11 +71,13 @@ function print_help() {
     echo "                        as ab://<branch>/<build_target>/<build_id>."
     echo "                        If not specified and the script is running from an Android common kernel repo,"
     echo "                        it will use the kernel in the local repo."
+    echo "                        If string 'None' is set, no kernel build will be flashed,"
     echo "  -vkb <vendor_kernel_build>, --vendor-kernel-build=<vendor_kernel_build>"
     echo "                        [Optional] The vendor kernel build path. Can be a local path or a remote build"
     echo "                        as ab://<branch>/<build_target>/<build_id>."
     echo "                        If not specified, and the script is running from a vendor kernel repo, "
     echo "                        it will use the kernel in the local repo."
+    echo "                        If string 'None' is set, no vendor kernel build will be flashed,"
     echo "  -vkbt <vendor_kernel_build_target>, --vendor-kernel-build-target=<vendor_kernel_build_target>"
     echo "                        [Optional] The vendor kernel build target to be used to build vendor kernel."
     echo "                        If not specified, and the script is running from a vendor kernel repo, "
@@ -274,31 +278,29 @@ function find_repo () {
     case "$manifest_output" in
         *platform/superproject*)
             PLATFORM_REPO_ROOT="$PWD"
-            PLATFORM_VERSION=$(grep -e "platform/superproject" .repo/manifests/default.xml | \
-            grep -oP 'revision="\K[^"]*')
-            print_info "PLATFORM_REPO_ROOT=$PLATFORM_REPO_ROOT, PLATFORM_VERSION=$PLATFORM_VERSION" "$LINENO"
             if [ -z "$PLATFORM_BUILD" ]; then
+                PLATFORM_VERSION=$(grep -e "platform/superproject" .repo/manifests/default.xml | \
+                grep -oP 'revision="\K[^"]*')
+                print_info "PLATFORM_REPO_ROOT=$PLATFORM_REPO_ROOT, PLATFORM_VERSION=$PLATFORM_VERSION" "$LINENO"
                 PLATFORM_BUILD="$PLATFORM_REPO_ROOT"
-            elif [[ "$PLATFORM_BUILD" == "None" ]]; then
-                PLATFORM_BUILD=
             fi
             ;;
         *kernel/private/devices/google/common*|*private/google-modules/soc/gs*)
             VENDOR_KERNEL_REPO_ROOT="$PWD"
-            VENDOR_KERNEL_VERSION=$(grep -e "default revision" .repo/manifests/default.xml | \
-            grep -oP 'revision="\K[^"]*')
-            print_info "VENDOR_KERNEL_REPO_ROOT=$VENDOR_KERNEL_REPO_ROOT" "$LINENO"
-            print_info "VENDOR_KERNEL_VERSION=$VENDOR_KERNEL_VERSION" "$LINENO"
             if [ -z "$VENDOR_KERNEL_BUILD" ]; then
+                VENDOR_KERNEL_VERSION=$(grep -e "default revision" .repo/manifests/default.xml | \
+                grep -oP 'revision="\K[^"]*')
+                print_info "VENDOR_KERNEL_REPO_ROOT=$VENDOR_KERNEL_REPO_ROOT" "$LINENO"
+                print_info "VENDOR_KERNEL_VERSION=$VENDOR_KERNEL_VERSION" "$LINENO"
                 VENDOR_KERNEL_BUILD="$VENDOR_KERNEL_REPO_ROOT"
             fi
             ;;
         *common-modules/virtual-device*)
             KERNEL_REPO_ROOT="$PWD"
-            KERNEL_VERSION=$(grep -e "kernel/superproject" \
-            .repo/manifests/default.xml | grep -oP 'revision="common-\K[^"]*')
-            print_info "KERNEL_REPO_ROOT=$KERNEL_REPO_ROOT, KERNEL_VERSION=$KERNEL_VERSION" "$LINENO"
             if [ -z "$KERNEL_BUILD" ]; then
+                KERNEL_VERSION=$(grep -e "kernel/superproject" \
+                .repo/manifests/default.xml | grep -oP 'revision="common-\K[^"]*')
+                print_info "KERNEL_REPO_ROOT=$KERNEL_REPO_ROOT, KERNEL_VERSION=$KERNEL_VERSION" "$LINENO"
                 KERNEL_BUILD="$KERNEL_REPO_ROOT"
             fi
             ;;
@@ -355,27 +357,213 @@ function build_ack () {
     fi
 }
 
+function format_ab_platform_build_string() {
+    if [[ "$PLATFORM_BUILD" != ab://* ]]; then
+        print_error "Please provide the platform build in the form of ab:// with flag -pb" "$LINENO"
+        return 1
+    fi
+    IFS='/' read -ra array <<< "$PLATFORM_BUILD"
+    local _branch="${array[2]}"
+    local _build_target="${array[3]}"
+    local _build_id="${array[4]}"
+    if [ -z "$_branch" ]; then
+        print_info "Branch is not specified in platform build as ab://<branch>. Using git_main branch" "$LINENO"
+        _branch="git_main"
+    fi
+    if [ -z "$_build_target" ]; then
+        if [ ! -z "$PRODUCT" ]; then
+            _build_target="$PRODUCT-userdebug"
+        else
+            print_error "Can not find platform build target through device info. Please \
+            provide platform build in the form of ab://<branch>/<build_target> or \
+            ab://<branch>/<build_target>/<build_id>" "$LINENO"
+        fi
+    fi
+    if [[ "$_branch" == aosp-main* ]] || [[ "$_branch" == git_main* ]]; then
+        if [[ "$_build_target" != *-trunk_staging-* ]] || [[ "$_build_target" != *-next-* ]]  || [[ "$_build_target" != *-trunk_food-* ]]; then
+            _build_target="${_build_target/-user/-trunk_staging-user}"
+        fi
+    fi
+    if [ -z "$_build_id" ]; then
+        _build_id="latest"
+    fi
+    PLATFORM_BUILD="ab://$_branch/$_build_target/$_build_id"
+    print_info "Platform build to be used is $PLATFORM_BUILD" "$LINENO"
+}
+
+function format_ab_kernel_build_string() {
+    if [[ "$KERNEL_BUILD" != ab://* ]]; then
+        print_error "Please provide the kernel build in the form of ab:// with flag -kb" "$LINENO"
+        return 1
+    fi
+    IFS='/' read -ra array <<< "$KERNEL_BUILD"
+    local _branch="${array[2]}"
+    local _build_target="${array[3]}"
+    local _build_id="${array[4]}"
+    if [ -z "$_branch" ]; then
+        if [ -z "$DEVICE_KERNEL_VERSION" ]; then
+            print_error "Branch is not provided in kernel build $KERNEL_BUILD. \
+            The kernel version can not be retrieved from device to decide GKI kernel build" "$LINENO"
+        fi
+        print_info "Branch is not specified in kernel build as ab://<branch>. Using $DEVICE_KERNEL_VERSION kernel branch." "$LINENO"
+        _branch="$DEVICE_KERNEL_VERSION"
+    fi
+    if [[ "$_branch" == "android"* ]]; then
+        _branch="aosp_kernel-common-$_branch"
+    fi
+    if [ -z "$_build_target" ]; then
+        _build_target="kernel_aarch64"
+    fi
+    if [ -z "$_build_id" ]; then
+        _build_id="latest"
+    fi
+    KERNEL_BUILD="ab://$_branch/$_build_target/$_build_id"
+    print_info "GKI kernel build to be used is $KERNEL_BUILD" "$LINENO"
+}
+
+function format_ab_vendor_kernel_build_string() {
+    if [[ "$VENDOR_KERNEL_BUILD" != ab://* ]]; then
+        print_error "Please provide the vendor kernel build in the form of ab:// with flag -vkb" "$LINENO"
+        return 1
+    fi
+    IFS='/' read -ra array <<< "$VENDOR_KERNEL_BUILD"
+    local _branch="${array[2]}"
+    local _build_target="${array[3]}"
+    local _build_id="${array[4]}"
+    if [ -z "$_branch" ]; then
+        if [ -z "$DEVICE_KERNEL_VERSION" ]; then
+            print_error "Branch is not provided in vendor kernel build $VENDOR_KERNEL_BUILD. \
+            The kernel version can not be retrieved from device to decide vendor kernel build" "$LINENO"
+        fi
+        print_info "Branch is not specified in kernel build as ab://<branch>. Using $DEVICE_KERNEL_VERSION vendor kernel branch." "$LINENO"
+        _branch="$DEVICE_KERNEL_VERSION"
+    fi
+    case "$_branch" in
+        android-mainline )
+            if [[ "$PRODUCT" == "raven" ]] || [[ "$PRODUCT" == "oriole" ]]; then
+                _branch="kernel-android-gs-pixel-mainline"
+                if [ -z "$_build_target" ]; then
+                    _build_target="kernel_raviole_kleaf"
+                fi
+            else
+                print_error "There is no vendor kernel branch $_branch for $PRODUCT device" "$LINENO"
+            fi
+            ;;
+        android16-6.12 )
+            if [[ "$PRODUCT" == "raven" ]] || [[ "$PRODUCT" == "oriole" ]]; then
+                _branch="kernel-android16-6.12-gs101"
+                if [ -z "$_build_target" ]; then
+                    _build_target="kernel_raviole"
+                fi
+            else
+                print_error "There is no vendor kernel branch $_branch for $PRODUCT device" "$LINENO"
+            fi
+            ;;
+        android15-6.6 )
+            if [[ "$PRODUCT" == "raven" ]] || [[ "$PRODUCT" == "oriole" ]]; then
+                _branch="kernel-android15-gs-pixel-6.6"
+                if [ -z "$_build_target" ]; then
+                    _build_target="kernel_raviole"
+                fi
+            else
+                _branch="kernel-pixel-android15-gs-pixel-6.6"
+            fi
+            ;;
+        android14-6.1 )
+            _branch="kernel-android14-gs-pixel-6.1"
+            ;;
+        android14-5.15 )
+            if [[ "$PRODUCT" == "husky" ]] || [[ "$PRODUCT" == "shiba" ]]; then
+                _branch="kernel-android14-gs-pixel-5.15"
+                if [ -z "$_build_target" ]; then
+                    _build_target="shusky"
+                fi
+            elif [[ "$PRODUCT" == "akita" ]]; then
+                _branch="kernel-android14-gs-pixel-5.15"
+                if [ -z "$_build_target" ]; then
+                    _build_target="akita"
+                fi
+            else
+                print_error "There is no vendor kernel branch $_branch for $PRODUCT device" "$LINENO"
+            fi
+            ;;
+        android13-5.15 )
+            if [[ "$PRODUCT" == "raven" ]] || [[ "$PRODUCT" == "oriole" ]]; then
+                _branch="kernel-android13-gs-pixel-5.15-gs101"
+                if [ -z "$_build_target" ]; then
+                    _build_target="kernel_raviole_kleaf"
+                fi
+            else
+                print_error "There is no vendor kernel branch $_branch for $PRODUCT device" "$LINENO"
+            fi
+            ;;
+        android13-5.10 )
+            if [[ "$PRODUCT" == "raven" ]] || [[ "$PRODUCT" == "oriole" ]]; then
+                _branch="kernel-android13-gs-pixel-5.10"
+                if [ -z "$_build_target" ]; then
+                    _build_target="slider_gki"
+                fi
+            elif [[ "$PRODUCT" == "felix" ]] || [[ "$PRODUCT" == "lynx" ]] || [[ "$PRODUCT" == "tangorpro" ]]; then
+                _branch="kernel-android13-gs-pixel-5.10"
+                if [ -z "$_build_target" ]; then
+                    _build_target="$PRODUCT"
+                fi
+            else
+                print_error "There is no vendor kernel branch $_branch for $PRODUCT device" "$LINENO"
+            fi
+            ;;
+        android12-5.10 )
+            print_error "There is no vendor kernel branch $_branch for $PRODUCT device" "$LINENO"
+            ;;
+    esac
+    if [ -z "$_build_target" ]; then
+        case "$PRODUCT" in
+            caiman | komodo | tokay )
+                _build_target="caimito"
+                ;;
+            husky | shiba )
+                _build_target="shusky"
+                ;;
+            panther | cheetah )
+                _build_target="pantah"
+                ;;
+            raven | oriole )
+                _build_target="raviole"
+                ;;
+            * )
+                _build_target="$PRODUCT"
+                ;;
+        esac
+    fi
+    if [ -z "$_build_id" ]; then
+        _build_id="latest"
+    fi
+    VENDOR_KERNEL_BUILD="ab://$_branch/$_build_target/$_build_id"
+    print_info "Vendor kernel build to be used is $VENDOR_KERNEL_BUILD" "$LINENO"
+}
+
 function download_platform_build() {
-    print_info "Downloading $1 to $PWD" "$LINENO"
-    local build_info="$1"
-    local file_patterns=("*$PRODUCT-img-*.zip" "bootloader.img" "radio.img" "misc_info.txt" "otatools.zip")
-    if [[ "$1" == *"user/"* ]]; then
-        file_patterns+=("vendor_ramdisk-debug.img")
+    print_info "Downloading $PLATFORM_BUILD to $PWD" "$LINENO"
+    local _build_info="$PLATFORM_BUILD"
+    local _file_patterns=("*$PRODUCT-img-*.zip" "bootloader.img" "radio.img" "misc_info.txt" "otatools.zip")
+    if [[ "$1" == *git_sc* ]]; then
+        _file_patterns+=("ramdisk.img")
+    elif [[ "$1" == *user/* ]]; then
+        _file_patterns+=("vendor_ramdisk-debug.img")
     else
-        file_patterns+=("vendor_ramdisk.img")
+        _file_patterns+=("vendor_ramdisk.img")
     fi
 
-    echo "Downloading ${file_patterns[@]} from $build_info"
-    for pattern in "${file_patterns[@]}"; do
-        download_file_name="$build_info/$pattern"
-        eval "$FETCH_SCRIPT $download_file_name"
+    for _pattern in "${_file_patterns[@]}"; do
+        print_info "Downloading $_build_info/$_pattern" "$LINENO"
+        eval "$FETCH_SCRIPT $_build_info/$_pattern"
         exit_code=$?
         if [ $exit_code -eq 0 ]; then
-            print_info "Download $download_file_name succeeded" "$LINENO"
+            print_info "Downloading $_build_info/$_pattern succeeded" "$LINENO"
         else
-            print_error "Download $download_file_name failed" "$LINENO"
+            print_error "Downloading $_build_info/$_pattern failed" "$LINENO"
         fi
-        if [[ "$pattern" == "vendor_ramdisk-debug.img" ]]; then
+        if [[ "$_pattern" == "vendor_ramdisk-debug.img" ]]; then
             cp vendor_ramdisk-debug.img vendor_ramdisk.img
         fi
     done
@@ -384,18 +572,27 @@ function download_platform_build() {
 
 function download_gki_build() {
     print_info "Downloading $1 to $PWD" "$LINENO"
-    local build_info="$1"
-    local file_patterns=("Image.lz4" "boot-lz4.img" "system_dlkm_staging_archive.tar.gz" "system_dlkm.flatten.ext4.img" "system_dlkm.flatten.erofs.img")
+    local _build_info="$1"
+    local _file_patterns=( "boot-lz4.img"  )
 
-    echo "Downloading ${file_patterns[@]} from $build_info"
-    for pattern in "${file_patterns[@]}"; do
-        download_file_name="$build_info/$pattern"
-        eval "$FETCH_SCRIPT $download_file_name"
+    if [[ "$PRODUCT" == "oriole" ]] || [[ "$PRODUCT" == "raven" ]]; then
+        if [[ "$_build_info" != *android13* ]]; then
+            _file_patterns+=("system_dlkm_staging_archive.tar.gz" "kernel_aarch64_Module.symvers")
+        fi
+    else
+        _file_patterns+=("system_dlkm.img")
+    fi
+    for _pattern in "${_file_patterns[@]}"; do
+        print_info "Downloading $_build_info/$_pattern" "$LINENO"
+        eval "$FETCH_SCRIPT $_build_info/$_pattern"
         exit_code=$?
         if [ $exit_code -eq 0 ]; then
-            print_info "Download $download_file_name succeeded" "$LINENO"
+            print_info "Downloading $_build_info/$_pattern succeeded" "$LINENO"
         else
-            print_error "Download $download_file_name failed" "$LINENO"
+            print_error "Downloading $_build_info/$_pattern failed" "$LINENO"
+        fi
+        if [[ "$_pattern" == "boot-lz4.img" ]]; then
+            cp boot-lz4.img boot.img
         fi
     done
     echo ""
@@ -403,184 +600,279 @@ function download_gki_build() {
 
 function download_vendor_kernel_build() {
     print_info "Downloading $1 to $PWD" "$LINENO"
-    local build_info="$1"
-    local file_patterns=("vendor_dlkm_staging_archive.tar.gz" "Image.lz4" "dtbo.img" \
-    "initramfs.img" "vendor_dlkm.img" "boot.img" "vendor_dlkm.modules.blocklist" "vendor_dlkm.modules.load" )
+    local _build_info="$1"
+    local _file_patterns=("Image.lz4" "dtbo.img" "initramfs.img")
 
-    if [[ "$VENDOR_KERNEL_VERSION" == *"6.6" ]]; then
-        file_patterns+=("*vendor_dev_nodes_fragment.img")
+    if [[ "$VENDOR_KERNEL_VERSION" == *6.6 ]]; then
+        _file_patterns+=("*vendor_dev_nodes_fragment.img")
     fi
 
     case "$PRODUCT" in
         oriole | raven | bluejay)
-            file_patterns+=( "gs101-a0.dtb" "gs101-b0.dtb")
+            _file_patterns+=( "gs101-a0.dtb" "gs101-b0.dtb" )
+            if [[ "$_build_info" == *android13* ]] || [ -z "$KERNEL_BUILD" ]; then
+                _file_patterns+=("vendor_dlkm.img")
+            else
+                _file_patterns+=("vendor_dlkm_staging_archive.tar.gz" "vendor_dlkm.props" "vendor_dlkm_file_contexts" \
+                "kernel_aarch64_Module.symvers" "abi_gki_aarch64_pixel")
+                if [[ "$_build_info" == *android15* ]] && [[ "$_build_info" == *6.6* ]]; then
+                    _file_patterns+=("vendor_dev_nodes_fragment.img" 'vendor-bootconfig.img')
+                elif [[ "$_build_info" == *pixel-mainline* ]]; then
+                    _file_patterns+=("vendor-bootconfig.img")
+                fi
+            fi
+            ;;
+        felix | lynx | cheetah | tangorpro)
+            _file_patterns+=("vendor_dlkm.img" "system_dlkm.img" "gs201-a0.dtb" "gs201-a0.dtb" )
+            ;;
+        shiba | husky | akita)
+            _file_patterns+=("vendor_dlkm.img" "system_dlkm.img" "zuma-a0-foplp.dtb" "zuma-a0-ipop.dtb" "zuma-b0-foplp.dtb" "zuma-b0-ipop.dtb" )
+            ;;
+        caiman | komodo | tokay | comet)
+            _file_patterns+=("vendor_dlkm.img" "system_dlkm.img" "zuma-a0-foplp.dtb" "zuma-a0-ipop.dtb" "zuma-b0-foplp.dtb" "zuma-b0-ipop.dtb" \
+            "zumapro-a0-foplp.dtb" "zumapro-a0-ipop.dtb" "zumapro-a1-foplp.dtb" "zumapro-a1-ipop.dtb" )
             ;;
         *)
+            _file_pattern+=("vendor_dlkm.img" "system_dlkm.img" "*-a0-foplp.dtb" "*-a0-ipop.dtb" "*-a1-foplp.dtb" \
+            "*-a1-ipop.dtb" "*-a0.dtb" "*-b0.dtb")
             ;;
     esac
 
-    echo "Downloading ${file_patterns[@]} from $build_info"
-    for pattern in "${file_patterns[@]}"; do
-        download_file_name="$build_info/$pattern"
-        eval "$FETCH_SCRIPT $download_file_name"
+    for _pattern in "${_file_patterns[@]}"; do
+        print_info "Downloading $_build_info/$_pattern" "$LINENO"
+        eval "$FETCH_SCRIPT $_build_info/$_pattern"
         exit_code=$?
         if [ $exit_code -eq 0 ]; then
-            print_info "Download $download_file_name succeeded" "$LINENO"
+            print_info "Downloading $_build_info/$_pattern succeeded" "$LINENO"
+            if [[ "$_pattern" == "vendor_dev_nodes_fragment.img" ]]; then
+                cp vendor_dev_nodes_fragment.img vendor_ramdisk_fragment_extra.img
+            fi
+            if [[ "$_pattern" == "abi_gki_aarch64_pixel" ]]; then
+                cp abi_gki_aarch64_pixel extracted_symbols
+            fi
         else
-            print_error "Download $download_file_name failed" "$LINENO"
+            print_warn "Downloading $_build_info/$_pattern failed" "$LINENO"
         fi
     done
     echo ""
 }
 
-function flash_gki_build() {
-    local boot_image_name
-    local system_dlkm_image_name
+function download_vendor_kernel_for_direct_flash() {
+    print_info "Downloading $1 to $PWD" "$LINENO"
+    local build_info="$1"
 
-    case "$PRODUCT" in
-        oriole | raven | bluejay)
-            boot_image_name="boot-lz4.img"
-            # no system_dlkm partition
-            ;;
-        eos | aurora | full_erd8835 | betty | kirkwood)
-            boot_image_name="boot.img"
-            if [[ "$PRODUCT" == "kirkwood" ]] && [[ ! "$KERNEL_VERSION" =~ ^android13 ]]; then  # Check if NOT android13
-                system_dlkm_image_name="system_dlkm.flatten.erofs.img"
-            # no system_dlkm for android12 & android13
-            elif [[ ! "$KERNEL_VERSION" =~ ^android12 ]] && [[ ! "$KERNEL_VERSION" =~ ^android13 ]]; then  # Check if NOT android12 AND NOT android13
-                system_dlkm_image_name="system_dlkm.flatten.erofs.img"
-            fi
-            ;;
-        k6985v1 | k6989v1)
-            boot_image_name="boot-gz.img"
-            # no system_dlkm for android12 & android13
-            if [[ ! "$KERNEL_VERSION" =~ ^android12 ]] && [[ ! "$KERNEL_VERSION" =~ ^android13 ]]; then  # Check if NOT android12 AND NOT android13
-                system_dlkm_image_name="system_dlkm.flatten.ext4.img"
-            fi
-            ;;
-        *)
-            boot_image_name="boot-lz4.img"
-            # no system_dlkm for android12 & android13
-            if [[ ! "$KERNEL_VERSION" =~ ^android12 ]] && [[ ! "$KERNEL_VERSION" =~ ^android13 ]]; then # Check if NOT android12 AND NOT android13
-                system_dlkm_image_name="system_dlkm.flatten.ext4.img"
-            fi
-            ;;
-    esac
+    for pattern in "${VENDOR_KERNEL_IMGS[@]}"; do
+        print_info "Downloading $_build_info/$_pattern" "$LINENO"
+        eval "$FETCH_SCRIPT $build_info/$pattern"
+        exit_code=$?
+        if [ $exit_code -eq 0 ]; then
+            print_info "Downloading $build_info/$pattern succeeded" "$LINENO"
+        else
+            print_error "Downloading $build_info/$pattern failed" "$LINENO"
+        fi
+    done
+    echo ""
 
-    if [ -z "$TRADEFED" ]; then
-        find_tradefed_bin
-    fi
-    if [ -d "$DOWNLOAD_PATH/tf_gki_kernel_dir" ]; then
-        rm -rf "$DOWNLOAD_PATH/tf_gki_kernel_dir"
-    fi
-    local kernel_dir="$DOWNLOAD_PATH/tf_gki_kernel_dir"
-    mkdir -p "$kernel_dir"
-    cd "$vendor_kernel_dir" || $(print_error "Fail to go to $gki_kernel_dir" "$LINENO")
-    cp "$KERNEL_BUILD/$boot_image_name" "$kernel_dir" || $(print_error "Fail to copy $KERNEL_BUILD/$boot_image_name" "$LINENO")
-    tf_cli="$TRADEFED \
-    run commandAndExit template/local_min --log-level-display VERBOSE \
-    --log-file-path=$LOG_DIR -s $SERIAL_NUMBER --disable-verity \
-    --template:map test=example/reboot --num-of-reboots 1 \
-    --template:map preparers=template/preparers/gki-device-flash-preparer \
-    --extra-file gki_boot.img=$kernel_dir/$boot_image_name"
-
-    # Check if system_dlkm_image_name is set before adding it to the command
-    if [ ! -z "$system_dlkm_image_name" ]; then
-        cp "$KERNEL_BUILD/$system_dlkm_image_name" "$kernel_dir" || $(print_error "Fail to copy $KERNEL_BUILD/$system_dlkm_image_name" "$LINENO")
-        tf_cli+=" --extra-file system_dlkm.img=$kernel_dir/$system_dlkm_image_name"
-    fi
-    print_info "Run $tf_cli" "$LINENO"
-    eval "$tf_cli" # Quote the variable expansion
 }
 
-function flash_vendor_kernel_build() {
-    if [ -z "$TRADEFED" ]; then
-        find_tradefed_bin
+function flash_gki_build() {
+    local _flash_cmd
+    if [[ "$KERNEL_BUILD" == ab://* ]]; then
+        IFS='/' read -ra array <<< "$KERNEL_BUILD"
+        KERNEL_VERSION=$(echo "${array[2]}" | sed "s/aosp_kernel-common-//g")
+        _flash_cmd="$CL_FLASH_CLI --nointeractive -w -s $DEVICE_SERIAL_NUMBER "
+        _flash_cmd+=" -t ${array[3]}"
+        if [ ! -z "${array[4]}" ] && [[ "${array[4]}" != latest* ]]; then
+            _flash_cmd+=" --bid ${array[4]}"
+        else
+            _flash_cmd+=" -l ${array[2]}"
+        fi
+    elif [ -d "$KERNEL_BUILD" ]; then
+        _flash_cmd="$LOCAL_FLASH_CLI --nointeractive -w --kernel_dist_dir=$KERNEL_BUILD -s $DEVICE_SERIAL_NUMBER"
+    else
+        print_error "Can not flash GKI kernel from $KERNEL_BUILD" "$LINENO"
+    fi
+
+    IFS='-' read -ra array <<< "$KERNEL_VERSION"
+    KERNEL_VERSION="${array[0]}-${array[1]}"
+    print_info "$KERNEL_BUILD is KERNEL_VERSION $KERNEL_VERSION" "$LINENO"
+    if [ ! -z "$DEVICE_KERNEL_VERSION" ] && [[ "$KERNEL_VERSION" != "$DEVICE_KERNEL_VERSION"* ]]; then
+        print_warn "Device $PRODUCT $SERIAL_NUMBER comes with $DEVICE_KERNEL_STRING $DEVICE_KERNEL_VERSION kernel. \
+        Can't flash $KERNEL_VERSION GKI directly. Please use a platform build with the $KERNEL_VERSION kernel \
+        or use a vendor kernel build by flag -vkb, for example -vkb -vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
+        print_error "Cannot flash $KERNEL_VERSION GKI to device $SERIAL_NUMBER directly." "$LINENO"
     fi
-    local tf_cli="$TRADEFED run commandAndExit template/local_min --log-level-display VERBOSE \
-    --log-file-path=$LOG_DIR -s $SERIAL_NUMBER --disable-verity \
-    --template:map test=example/reboot --num-of-reboots 1 \
-    --template:map preparers=template/preparers/gki-device-flash-preparer"
 
-    if [ -d "$DOWNLOAD_PATH/tf_vendor_kernel_dir" ]; then
-        rm -rf "$DOWNLOAD_PATH/tf_vendor_kernel_dir"
+    print_info "Flashing GKI kernel with: $_flash_cmd" "$LINENO"
+    eval "$_flash_cmd"
+    exit_code=$?
+    if [ $exit_code -eq 0 ]; then
+        echo "Flash GKI kernel succeeded"
+        wait_for_device_in_adb
+        return
+    else
+        echo "Flash GKI kernel failed with exit code $exit_code"
+        exit 1
     fi
-    local vendor_kernel_dir="$DOWNLOAD_PATH/tf_vendor_kernel_dir"
-    mkdir -p "$vendor_kernel_dir"
-    local file_patterns=("boot.img" "initramfs.img" "dtbo.img" "vendor_dlkm.img")
-    for pattern in "${file_patterns[@]}"; do
+}
+
+function check_fastboot_version() {
+    local _fastboot_version=$(fastboot --version | awk 'NR==1 {print $3}')
+
+    # Check if _fastboot_version is less than MIN_FASTBOOT_VERSION
+    if [[ "$_fastboot_version" < "$MIN_FASTBOOT_VERSION" ]]; then
+        print_info "The existing fastboot version $_fastboot_version doesn't meet minimum requirement $MIN_FASTBOOT_VERSION. Download the latest fastboot" "$LINENO"
+
+        local _download_file_name="ab://aosp-sdk-release/sdk/latest/fastboot"
+        mkdir -p "/tmp/fastboot" || $(print_error "Fail to mkdir /tmp/fastboot" "$LINENO")
+        cd /tmp/fastboot || $(print_error "Fail to go to /tmp/fastboot" "$LINENO")
+
+        # Use $FETCH_SCRIPT and $_download_file_name correctly
+        eval "$FETCH_SCRIPT $_download_file_name"
+        exit_code=$?
+        if [ $exit_code -eq 0 ]; then
+            print_info "Download $_download_file_name succeeded" "$LINENO"
+        else
+            print_error "Download $_download_file_name failed" "$LINENO"
+        fi
+
+        chmod +x /tmp/fastboot/fastboot
+        export PATH="/tmp/fastboot:$PATH"
+
+        _fastboot_version=$(fastboot --version | awk 'NR==1 {print $3}')
+        print_info "The fastboot is updated to version $_fastboot_version" "$LINENO"
+    fi
+}
+
+function flash_vendor_kernel_build() {
+    check_fastboot_version
+
+    for pattern in "${VENDOR_KERNEL_IMGS[@]}"; do
         if [ ! -f "$VENDOR_KERNEL_BUILD/$pattern" ]; then
             print_error "$VENDOR_KERNEL_BUILD/$pattern doesn't exist" "$LINENO"
         fi
-        cp "$VENDOR_KERNEL_BUILD/$pattern" "$vendor_kernel_dir"
-        if [[ "$pattern" == "boot.img" ]]; then
-            tf_cli+=" --extra-file gki_boot.img=$vendor_kernel_dir/boot.img"
-        else
-            tf_cli+=" --extra-file $pattern=$vendor_kernel_dir/$pattern"
-        fi
     done
-    print_info "Run $tf_cli" "$LINENO"
-    eval $tf_cli
+
+    cd $VENDOR_KERNEL_BUILD
+
+    # Switch to flashstatoin after b/390489174
+    print_info "Flash vendor kernel from $VENDOR_KERNEL_BUILD" "$LINENO"
+    if [ ! -z "$ADB_SERIAL_NUMBER" ] && (( $(adb devices | grep "$ADB_SERIAL_NUMBER" | wc -l) > 0 )); then
+        print_info "Reboot $ADB_SERIAL_NUMBER into bootloader" "$LINENO"
+        adb -s "$ADB_SERIAL_NUMBER" reboot bootloader
+        sleep 10
+        if [ -z "$FASTBOOT_SERIAL_NUMBER" ]; then
+            find_fastboot_serial_number
+        fi
+    elif [ ! -z "$FASTBOOT_SERIAL_NUMBER" ] && (( $(fastboot devices | grep "$ADB_SERIAL_NUMBER" | wc -l) > 0 )); then
+        print_info "Reboot $FASTBOOT_SERIAL_NUMBER into bootloader" "$LINENO"
+        fastboot -s "$FASTBOOT_SERIAL_NUMBER" reboot bootloader
+        sleep 2
+    fi
+    print_info "Wiping the device" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" -w
+    print_info "Disabling oem verification" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" oem disable-verification
+    print_info "Flashing boot image" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" flash boot "$VENDOR_KERNEL_BUILD"/boot.img
+    print_info "Flashing dtb.img & initramfs.img" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" flash --dtb "$VENDOR_KERNEL_BUILD"/dtb.img vendor_boot:dlkm "$VENDOR_KERNEL_BUILD"/initramfs.img
+    print_info "Flashing dtbo.img" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" flash dtbo "$VENDOR_KERNEL_BUILD"/dtbo.img
+    print_info "Reboot into fastbootd" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" reboot fastboot
+    sleep 10
+    print_info "Flashing vendor_dlkm.img" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" flash vendor_dlkm "$VENDOR_KERNEL_BUILD"/vendor_dlkm.img
+    print_info "Reboot the device" "$LINENO"
+    fastboot -s "$FASTBOOT_SERIAL_NUMBER" reboot
+    wait_for_device_in_adb
 }
 
 # Function to check and wait for an ADB device
-function wait_for_adb_device() {
-  local serial_number="$1"  # Optional serial number
-  local timeout_seconds="${2:-300}"  # Timeout in seconds (default 5 minutes)
+function wait_for_device_in_adb() {
+    local timeout_seconds="${2:-300}"  # Timeout in seconds (default 5 minutes)
+
+    local start_time=$(date +%s)
+    local end_time=$((start_time + timeout_seconds))
+
+    while (( $(date +%s) < end_time )); do
+        if [ -z "$ADB_SERIAL_NUMBER" ] && [ -x pontis ]; then
+            local _pontis_device=$(pontis devices | grep "$DEVICE_SERIAL_NUMBER")
+            if [[ "$_pontis_device" == *ADB* ]]; then
+                print_info "Device $DEVICE_SERIAL_NUMBER is connected through pontis in adb" "$LINENO"
+                find_adb_serial_number
+                get_device_info_from_adb
+                return 0  # Success
+            else
+                sleep 5
+            fi
+        else
+            devices=$(adb devices | grep "$ADB_SERIAL_NUMBER" | wc -l)
 
-  local start_time=$(date +%s)
-  local end_time=$((start_time + timeout_seconds))
+            if (( devices > 0 )); then
+                print_info "Device $ADB_SERIAL_NUMBER is connected with adb" "$LINENO"
+                return 0  # Success
+            fi
+            print_info "Waiting for device $ADB_SERIAL_NUMBER in adb devices" "$LINENO"
+            sleep 5
+        fi
+    done
 
-  while (( $(date +%s) < end_time )); do
-    devices=$(adb devices | grep "$SERIAL_NUMBER" | wc -l)
+    print_error "Timeout waiting for $ADB_SERIAL_NUMBER in adb devices" "$LINENO"
+}
 
-    if (( devices > 0 )); then
-      print_info "Device $SERIAL_NUMBER is connected with adb" "$LINENO"
-      return 0  # Success
+function find_flashstation_binary() {
+    if [ -x "${ANDROID_HOST_OUT}/bin/local_flashstation" ]; then
+        $LOCAL_FLASH_CLI="${ANDROID_HOST_OUT}/bin/local_flashstation"
+    elif [ ! -x "$LOCAL_FLASH_CLI" ]; then
+        if ! which local_flashstation &> /dev/null; then
+            print_error "Can not find local_flashstation binary. \
+            Please see go/web-flashstation-command-line to download it" "$LINENO"
+        else
+            LOCAL_FLASH_CLI="local_flashstation"
+        fi
+    fi
+    if [ -x "${ANDROID_HOST_OUT}/bin/cl_flashstation" ]; then
+        $CL_FLASH_CLI="${ANDROID_HOST_OUT}/bin/cl_flashstation"
+    elif [ ! -x "$CL_FLASH_CLI" ]; then
+        if ! which cl_flashstation &> /dev/null; then
+            print_error "Can not find cl_flashstation binary. \
+            Please see go/web-flashstation-command-line to download it" "$LINENO"
+        else
+            CL_FLASH_CLI="cl_flashstation"
+        fi
     fi
-    print_info "Waiting for device $SERIAL_NUMBER in adb devies" "$LINENO"
-    sleep 1
-  done
-
-  print_error "Timeout waiting for $SERIAL_NUMBER in adb devices" "$LINENO"
 }
 
 function flash_platform_build() {
-    if [[ "$PLATFORM_BUILD" == ab://* ]] && [ -x "$FLASH_CLI" ]; then
-        local flash_cmd="$FLASH_CLI --nointeractive --force_flash_partitions --disable_verity -w -s $SERIAL_NUMBER "
+    local _flash_cmd
+    if [[ "$PLATFORM_BUILD" == ab://* ]]; then
+        _flash_cmd="$CL_FLASH_CLI --nointeractive --force_flash_partitions --disable_verity -w -s $DEVICE_SERIAL_NUMBER "
         IFS='/' read -ra array <<< "$PLATFORM_BUILD"
         if [ ! -z "${array[3]}" ]; then
             local _build_type="${array[3]#*-}"
-            if [[ "$_build_type" == *userdebug ]]; then
-                flash_cmd+=" -t $_build_type"
-            elif [[ "$_build_type" == *user ]]; then
-                flash_cmd+=" -t $_build_type --force_debuggable"
+            if [[ "${array[2]}" == git_main* ]] && [[ "$_build_type" == user* ]]; then
+                print_info "Build variant is not provided, using trunk_staging build" "$LINENO"
+                _build_type="trunk_staging-$_build_type"
+            fi
+            _flash_cmd+=" -t $_build_type"
+            if [[ "$_build_type" == *user ]] && [ ! -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then
+                print_info "Need to flash GKI after flashing platform build, hence enabling --force_debuggable in user build flashing" "$LINENO"
+                _flash_cmd+=" --force_debuggable"
             fi
         fi
         if [ ! -z "${array[4]}" ] && [[ "${array[4]}" != latest* ]]; then
             echo "Flash $SERIAL_NUMBER with platform build from branch $PLATFORM_BUILD..."
-            flash_cmd+=" --bid ${array[4]}"
+            _flash_cmd+=" --bid ${array[4]}"
         else
             echo "Flash $SERIAL_NUMBER with platform build $PLATFORM_BUILD..."
-            flash_cmd+=" -l ${array[2]}"
-        fi
-        print_info "Flash $SERIAL_NUMBER with flash station cli by: $flash_cmd" "$LINENO"
-        eval "$flash_cmd"
-        exit_code=$?
-        if [ $exit_code -eq 0 ]; then
-            echo "Flash platform succeeded"
-            wait_for_adb_device
-            return
-        else
-            echo "Flash platform build failed with exit code $exit_code"
-            exit 1
+            _flash_cmd+=" -l ${array[2]}"
         fi
-    fi
-
-    if [ ! -z "$PLATFORM_REPO_ROOT" ] && [[ "$PLATFORM_BUILD" == "$PLATFORM_REPO_ROOT/out/target/product/$PRODUCT" ]] && \
+    elif [ ! -z "$PLATFORM_REPO_ROOT" ] && [[ "$PLATFORM_BUILD" == "$PLATFORM_REPO_ROOT/out/target/product/$PRODUCT" ]] && \
     [ -x "$PLATFORM_REPO_ROOT/vendor/google/tools/flashall" ]; then
         cd "$PLATFORM_REPO_ROOT"
-        print_info "Flash with vendor/google/tools/flashall" "$LINENO"
+        print_info "Flashing device with vendor/google/tools/flashall" "$LINENO"
         if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != *"$PRODUCT" ]]; then
             if [[ "$PLATFORM_VERSION" == aosp-* ]]; then
                 set_platform_repo "aosp_$PRODUCT"
@@ -588,9 +880,8 @@ function flash_platform_build() {
                 set_platform_repo "$PRODUCT"
             fi
         fi
-        eval "vendor/google/tools/flashall  --nointeractive -w -s $SERIAL_NUMBER"
-        return
-    elif [ -x "${ANDROID_HOST_OUT}/bin/local_flashstation" ] || [ -x "$LOCAL_FLASH_CLI" ]; then
+        _flash_cmd="vendor/google/tools/flashall  --nointeractive -w -s $DEVICE_SERIAL_NUMBER"
+    else
         if [ -z "${TARGET_PRODUCT}" ]; then
             export TARGET_PRODUCT="$PRODUCT"
         fi
@@ -611,30 +902,24 @@ function flash_platform_build() {
         awk '! /baseband/' "$PLATFORM_BUILD"/android-info.txt > temp && mv temp "$PLATFORM_BUILD"/android-info.txt
         awk '! /bootloader/' "$PLATFORM_BUILD"/android-info.txt > temp && mv temp "$PLATFORM_BUILD"/android-info.txt
 
-        flash_cmd="$LOCAL_FLASH_CLI"
-
-        if [ ! -x "$LOCAL_FLASH_CLI" ]; then
-            flash_cmd="${ANDROID_HOST_OUT}/bin/local_flashstation"
-        fi
-
-        flash_cmd+=" --nointeractive --force_flash_partitions --disable_verity --disable_verification  -w -s $SERIAL_NUMBER"
-        print_info "Flash device with: $flash_cmd" "$LINENO"
-        eval "$flash_cmd"
-        exit_code=$?
-        if [ $exit_code -eq 0 ]; then
-            echo "Flash platform succeeded"
-            wait_for_adb_device
-            return
-        else
-            echo "Flash platform build failed with exit code $exit_code"
-            exit 1
-        fi
+        _flash_cmd="$LOCAL_FLASH_CLI --nointeractive --force_flash_partitions --disable_verity --disable_verification  -w -s $DEVICE_SERIAL_NUMBER"
+    fi
+    print_info "Flashing device with: $_flash_cmd" "$LINENO"
+    eval "$_flash_cmd"
+    exit_code=$?
+    if [ $exit_code -eq 0 ]; then
+        echo "Flash platform succeeded"
+        wait_for_device_in_adb
+        return
+    else
+        echo "Flash platform build failed with exit code $exit_code"
+        exit 1
     fi
 
 }
 
 function get_mix_ramdisk_script() {
-    download_file_name="ab://git_main/aosp_cf_x86_64_only_phone-trunk_staging-userdebug/latest/*-tests-*.zip"
+    download_file_name="ab://git_main/aosp_cf_x86_64_only_phone-trunk_staging-userdebug/latest/otatools.zip"
     eval "$FETCH_SCRIPT $download_file_name"
     exit_code=$?
     if [ $exit_code -eq 0 ]; then
@@ -642,19 +927,19 @@ function get_mix_ramdisk_script() {
     else
         print_error "Download $download_file_name failed" "$LINENO" "$LINENO"
     fi
-    eval "unzip -j *-tests-* DATA/local/tmp/build_mixed_kernels_ramdisk"
+    eval "unzip -j otatools.zip bin/$MIX_SCRIPT_NAME"
     echo ""
 }
 
 function mixing_build() {
-    if [ ! -z ${PLATFORM_REPO_ROOT_PATH} ] && [ -f "$PLATFORM_REPO_ROOT_PATH/vendor/google/tools/build_mixed_kernels_ramdisk"]; then
-        mix_kernel_cmd="$PLATFORM_REPO_ROOT_PATH/vendor/google/tools/build_mixed_kernels_ramdisk"
-    elif [ -f "$DOWNLOAD_PATH/build_mixed_kernels_ramdisk" ]; then
-        mix_kernel_cmd="$DOWNLOAD_PATH/build_mixed_kernels_ramdisk"
+    if [ ! -z ${PLATFORM_REPO_ROOT_PATH} ] && [ -f "$PLATFORM_REPO_ROOT_PATH/vendor/google/tools/$MIX_SCRIPT_NAME"]; then
+        mix_kernel_cmd="$PLATFORM_REPO_ROOT_PATH/vendor/google/tools/$MIX_SCRIPT_NAME"
+    elif [ -f "$DOWNLOAD_PATH/$MIX_SCRIPT_NAME" ]; then
+        mix_kernel_cmd="$DOWNLOAD_PATH/$MIX_SCRIPT_NAME"
     else
-        cd "$DOWNLOAD_PATH"
+        cd "$DOWNLOAD_PATH" || $(print_error "Fail to go to $DOWNLOAD_PATH" "$LINENO")
         get_mix_ramdisk_script
-        mix_kernel_cmd="$PWD/build_mixed_kernels_ramdisk"
+        mix_kernel_cmd="$PWD/$MIX_SCRIPT_NAME"
     fi
     if [ ! -f "$mix_kernel_cmd" ]; then
         print_error "$mix_kernel_cmd doesn't exist or is not executable" "$LINENO"
@@ -662,14 +947,13 @@ function mixing_build() {
         print_error "$mix_kernel_cmd is not executable" "$LINENO"
     fi
     if [[ "$PLATFORM_BUILD" == ab://* ]]; then
-        print_info "Download platform build $PLATFORM_BUILD" "$LINENO"
         if [ -d "$DOWNLOAD_PATH/device_dir" ]; then
             rm -rf "$DOWNLOAD_PATH/device_dir"
         fi
         PLATFORM_DIR="$DOWNLOAD_PATH/device_dir"
         mkdir -p "$PLATFORM_DIR"
         cd "$PLATFORM_DIR" || $(print_error "Fail to go to $PLATFORM_DIR" "$LINENO")
-        download_platform_build "$PLATFORM_BUILD"
+        download_platform_build
         PLATFORM_BUILD="$PLATFORM_DIR"
     elif [ ! -z "$PLATFORM_REPO_ROOT" ] && [[ "$PLATFORM_BUILD" == "$PLATFORM_REPO_ROOT"* ]]; then
         print_info "Copy platform build $PLATFORM_BUILD to $DOWNLOAD_PATH/device_dir" "$LINENO"
@@ -700,6 +984,18 @@ function mixing_build() {
         PLATFORM_BUILD="$PLATFORM_DIR"
     fi
 
+    if [[ "$KERNEL_BUILD" == ab://* ]]; then
+        print_info "Download kernel build $KERNEL_BUILD" "$LINENO"
+        if [ -d "$DOWNLOAD_PATH/gki_dir" ]; then
+            rm -rf "$DOWNLOAD_PATH/gki_dir"
+        fi
+        GKI_DIR="$DOWNLOAD_PATH/gki_dir"
+        mkdir -p "$GKI_DIR"
+        cd "$GKI_DIR" || $(print_error "Fail to go to $GKI_DIR" "$LINENO")
+        download_gki_build $KERNEL_BUILD
+        KERNEL_BUILD="$GKI_DIR"
+    fi
+
     local new_device_dir="$DOWNLOAD_PATH/new_device_dir"
     if [ -d "$new_device_dir" ]; then
         rm -rf "$new_device_dir"
@@ -775,41 +1071,6 @@ get_kernel_version_from_boot_image() {
     fi
 }
 
-function gki_build_only_operation {
-    IFS='-' read -ra array <<< "$KERNEL_VERSION"
-    case "$KERNEL_VERSION" in
-        android-mainline | android15-6.6* | android14-6.1* | android14-5.15* )
-            if [[ "$KERNEL_VERSION" == "$DEVICE_KERNEL_VERSION"* ]] && [ ! -z "$SYSTEM_DLKM_INFO" ]; then
-                print_info "Device $SERIAL_NUMBER is with $KERNEL_VERSION kernel. Flash GKI directly" "$LINENO"
-                flash_gki_build
-            elif [ -z "$SYSTEM_DLKM_INFO" ]; then
-                print_warn "Device $SERIAL_NUMBER is $PRODUCT that doesn't have system_dlkm partition. Can't flash GKI directly. \
-Please add vendor kernel build for example by flag -vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
-                print_error "Can not flash GKI to SERIAL_NUMBER without -vkb <vendor_kernel_build> been specified." "$LINENO"
-            elif [[ "$KERNEL_VERSION" != "$DEVICE_KERNEL_VERSION"* ]]; then
-                print_warn "Device $PRODUCT $SERIAL_NUMBER comes with $DEVICE_KERNEL_STRING kernel. Can't flash GKI directly. \
-Please add a platform build with $KERNEL_VERSION kernel or add vendor kernel build for example by flag \
--vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
-                print_error "Cannot flash $KERNEL_VERSION GKI to device directly $SERIAL_NUMBER." "$LINENO"
-            fi
-            ;;
-        android13-5.15* | android13-5.10* | android12-5.10* | android12-5.4* )
-            if [[ "$KERNEL_VERSION" == "$EVICE_KERNEL_VERSION"* ]]; then
-                print_info "Device $SERIAL_NUMBER is with android13-5.15 kernel. Flash GKI directly." "$LINENO"
-                flash_gki_build
-            else
-                print_warn "Device $SERIAL_NUMBER is $PRODUCT comes with $DEVICE_KERNEL_STRING kernel. Can't flash GKI directly. \
-Please add a platform build with $KERNEL_VERSION kernel or add vendor kernel build for example by flag \
--vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
-                print_error "Cannot flash $KERNEL_VERSION GKI to device directly $SERIAL_NUMBER." "$LINENO"
-            fi
-            ;;
-        *)
-            print_error "Unsupported KERNEL_VERSION: $KERNEL_VERSION" "$LINENO" "$LINENO"
-            ;;
-    esac
-}
-
 function extract_device_kernel_version() {
     local kernel_string="$1"
     # Check if the string contains '-android'
@@ -824,72 +1085,141 @@ function extract_device_kernel_version() {
     print_info "Device kernel version is $DEVICE_KERNEL_VERSION" "$LINENO"
 }
 
-function get_device_info {
-    adb_count=$(adb devices | grep "$SERIAL_NUMBER" | wc -l)
-    if (( adb_count > 0 )); then
-        BOARD=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.board)
-        ABI=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.cpu.abi)
-        PRODUCT=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.product)
-        BUILD_TYPE=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.type)
-        DEVICE_KERNEL_STRING=$(adb -s "$SERIAL_NUMBER" shell uname -r)
-        extract_device_kernel_version "$DEVICE_KERNEL_STRING"
-        SYSTEM_DLKM_INFO=$(adb -s "$SERIAL_NUMBER" shell getprop dev.mnt.blk.system_dlkm)
-        print_info "device info: BOARD=$BOARD, ABI=$ABI, PRODUCT=$PRODUCT, BUILD_TYPE=$BUILD_TYPE" "$LINENO"
-        print_info "device info: SYSTEM_DLKM_INFO=$SYSTEM_DLKM_INFO, DEVICE_KERNEL_STRING=$DEVICE_KERNEL_STRING" "$LINENO"
+function find_adb_serial_number() {
+    print_info "Try to find device $DEVICE_SERIAL_NUMBER serial id in adb devices" "$LINENO"
+    local _device_ids=$(adb devices | awk '$2 == "device" {print $1}')
+    devices=()
+    while IFS= read -r device_id; do
+        devices+=("$device_id")
+    done <<< "$_device_ids"
+
+    for device_id in "${devices[@]}"; do
+        local _device_serial_number=$(adb -s "$device_id" shell getprop ro.serialno)
+        #echo "DEVICE $device_id has serialno $_device_serial_number"
+        if [[ "$_device_serial_number" == "$DEVICE_SERIAL_NUMBER" ]]; then
+            ADB_SERIAL_NUMBER="$device_id"
+            print_info "Device $DEVICE_SERIAL_NUMBER shows up as $ADB_SERIAL_NUMBER in adb" "$LINENO"
+            return 0
+        fi
+    done
+    print_error "Can not find device in adb has device serial number $DEVICE_SERIAL_NUMBER. \
+    Check if the device is connected with adb authentication" "$LINENO"
+}
+
+function find_fastboot_serial_number() {
+    print_info "Try to find device $DEVICE_SERIAL_NUMBER serial id in fastboot devices" "$LINENO"
+    local _output=$(fastboot devices | awk '{print $1}')
+    while IFS= read -r device_id; do
+        # Use fastboot getvar to retrieve serial number
+        local _output=$(fastboot -s "$device_id" getvar serialno 2>&1)
+        local _device_serial_number=$(echo "$_output" | grep -Po "serialno: [A-Z0-9]+" | cut -c 11-)
+        #echo "Device $device has serial number $_device_serial_number"
+        if [[ "$_device_serial_number" == "$DEVICE_SERIAL_NUMBER" ]]; then
+            FASTBOOT_SERIAL_NUMBER="$device_id"
+            print_info "Device $DEVICE_SERIAL_NUMBER shows up as $FASTBOOT_SERIAL_NUMBER in fastboot" "$LINENO"
+            return 0
+        fi
+    done <<< "$_output"
+    print_error "Can not find device in fastboot has device serial number $DEVICE_SERIAL_NUMBER" "$LINENO"
+}
+
+function get_device_info_from_adb {
+    if [ -z "$DEVICE_SERIAL_NUMBER" ]; then
+        DEVICE_SERIAL_NUMBER=$(adb -s "$ADB_SERIAL_NUMBER" shell getprop ro.serialno)
+        if [ -z "$DEVICE_SERIAL_NUMBER" ]; then
+            print_error "Can not get device serial adb -s $ADB_SERIAL_NUMBER" "$LINENO"
+        fi
+    fi
+    BOARD=$(adb -s "$ADB_SERIAL_NUMBER" shell getprop ro.product.board)
+    ABI=$(adb -s "$ADB_SERIAL_NUMBER" shell getprop ro.product.cpu.abi)
+
+    # Only get PRODUCT if it's not already set
+    if [ -z "$PRODUCT" ]; then
+        PRODUCT=$(adb -s "$ADB_SERIAL_NUMBER" shell getprop ro.build.product)
+        # Check if PRODUCT is valid after attempting to retrieve it
+        if [ -z "$PRODUCT" ]; then
+            print_error "$ADB_SERIAL_NUMBER does not have a valid product value" "$LINENO"
+        fi
+    fi
+
+    BUILD_TYPE=$(adb -s "$ADB_SERIAL_NUMBER" shell getprop ro.build.type)
+    DEVICE_KERNEL_STRING=$(adb -s "$ADB_SERIAL_NUMBER" shell uname -r)
+    extract_device_kernel_version "$DEVICE_KERNEL_STRING"
+    SYSTEM_DLKM_INFO=$(adb -s "$ADB_SERIAL_NUMBER" shell getprop dev.mnt.blk.system_dlkm)
+    if [[ "$SERIAL_NUMBER" != "$DEVICE_SERIAL_NUMBER" ]]; then
+        print_info "Device $SERIAL_NUMBER has DEVICE_SERIAL_NUMBER=$DEVICE_SERIAL_NUMBER, ADB_SERIAL_NUMBER=$ADB_SERIAL_NUMBER" "$LINENO"
+    fi
+    print_info "Device $SERIAL_NUMBER info: BOARD=$BOARD, ABI=$ABI, PRODUCT=$PRODUCT, BUILD_TYPE=$BUILD_TYPE \
+    SYSTEM_DLKM_INFO=$SYSTEM_DLKM_INFO, DEVICE_KERNEL_STRING=$DEVICE_KERNEL_STRING" "$LINENO"
+}
+
+function get_device_info_from_fastboot {
+    # try get product by fastboot command
+    if [ -z "$DEVICE_SERIAL_NUMBER" ]; then
+        local _output=$(fastboot -s "$FASTBOOT_SERIAL_NUMBER" getvar serialno 2>&1)
+        DEVICE_SERIAL_NUMBER=$(echo "$_output" | grep -Po "serialno: [A-Z0-9]+" | cut -c 11-)
+        if [ -z "$DEVICE_SERIAL_NUMBER" ]; then
+            print_error "Can not get device serial from $SERIAL_NUMBER" "$LINENO"
+        fi
+    fi
+
+    # Only get PRODUCT if it's not already set
+    if [ -z "$PRODUCT" ]; then
+        _output=$(fastboot -s "$FASTBOOT_SERIAL_NUMBER" getvar product 2>&1)
+        PRODUCT=$(echo "$_output" | grep -oP '^product:\s*\K.*' | cut -d' ' -f1)
+        # Check if PRODUCT is valid after attempting to retrieve it
+        if [ -z "$PRODUCT" ]; then
+            print_error "$FASTBOOT_SERIAL_NUMBER does not have a valid product value" "$LINENO"
+        fi
+    fi
+
+    if [[ "$SERIAL_NUMBER" != "$DEVICE_SERIAL_NUMBER" ]]; then
+        print_info "Device $SERIAL_NUMBER has DEVICE_SERIAL_NUMBER=$DEVICE_SERIAL_NUMBER, FASTBOOT_SERIAL_NUMBER=$FASTBOOT_SERIAL_NUMBER" "$LINENO"
+    fi
+    print_info "Device $SERIAL_NUMBER is in fastboot with device info: PRODUCT=$PRODUCT" "$LINENO"
+}
+
+function get_device_info() {
+    local _adb_count=$(adb devices | grep "$SERIAL_NUMBER" | wc -l)
+    if (( _adb_count > 0 )); then
+        print_info "$SERIAL_NUMBER is connected through adb" "$LINENO"
+        ADB_SERIAL_NUMBER="$SERIAL_NUMBER"
+        get_device_info_from_adb
+        if [[ "$ADB_SERIAL_NUMBER" == "$DEVICE_SERIAL_NUMBER" ]]; then
+            FASTBOOT_SERIAL_NUMBER="$SERIAL_NUMBER"
+        fi
         return 0
     fi
-    fastboot_count=$(fastboot devices | grep "$SERIAL_NUMBER" | wc -l)
-    if (( fastboot_count > 0 )); then
-        # try get product by fastboot command
-        local output=$(fastboot -s "$SERIAL_NUMBER" getvar product 2>&1)
-        PRODUCT=$(echo "$output" | grep -oP '^product:\s*\K.*' | cut -d' ' -f1)
-        print_info "$SERIAL_NUMBER is in fastboot with device info: PRODUCT=$PRODUCT" "$LINENO"
+
+    local _fastboot_count=$(fastboot devices | grep "$SERIAL_NUMBER" | wc -l)
+    if (( _fastboot_count > 0 )); then
+        print_info "$SERIAL_NUMBER is connected through fastboot" "$LINENO"
+        FASTBOOT_SERIAL_NUMBER="$SERIAL_NUMBER"
+        get_device_info_from_fastboot
+        if [[ "$FASTBOOT_SERIAL_NUMBER" == "$DEVICE_SERIAL_NUMBER" ]]; then
+            ADB_SERIAL_NUMBER="$SERIAL_NUMBER"
+        fi
         return 0
     fi
-    print_error "$SERIAL_NUMBER is not connected with adb or fastboot"
-}
 
-function find_tradefed_bin {
-    cd "$REPO_ROOT_PATH"
-    if [ -f "${ANDROID_HOST_OUT}/bin/tradefed.sh" ] ; then
-        TRADEFED="${ANDROID_HOST_OUT}/bin/tradefed.sh"
-        print_info "Use the tradefed from the local built path $TRADEFED" "$LINENO"
-        return
-    elif [ -f "$PLATFORM_TF_PREBUILT" ]; then
-        TF_BIN="$PLATFORM_TF_PREBUILT"
-        print_info "Local Tradefed is not built yet. Use the prebuilt from $PLATFORM_TF_PREBUILT" "$LINENO"
-    elif [ -f "$KERNEL_TF_PREBUILT" ]; then
-        TF_BIN="$KERNEL_TF_PREBUILT"
-    elif [ -f "/tmp/tradefed/tradefed.sh" ]; then
-        TF_BIN=/tmp/tradefed/tradefed.sh
-    # No Tradefed found
-    else
-        mkdir -p "/tmp/tradefed"
-        cd /tmp/tradefed
-        eval "$FETCH_SCRIPT ab://tradefed/tradefed/latest/google-tradefed.zip"
-        exit_code=$?
-        if [ $exit_code -eq 0 ]; then
-            print_info "Download tradefed succeeded" "$LINENO"
-        else
-            print_error "Download tradefed failed" "$LINENO"
+    if [ -x pontis ]; then
+        local _pontis_device=$(pontis devices | grep "$SERIAL_NUMBER")
+        if [[ "$_pontis_device" == *Fastboot* ]]; then
+            DEVICE_SERIAL_NUMBER="$SERIAL_NUMBER"
+            print_info "Device $SERIAL_NUMBER is connected through pontis in fastboot" "$LINENO"
+            find_fastboot_serial_number
+            get_device_info_from_fastboot
+            return 0
+        elif [[ "$_pontis_device" == *ADB* ]]; then
+            DEVICE_SERIAL_NUMBER="$SERIAL_NUMBER"
+            print_info "Device $SERIAL_NUMBER is connected through pontis in adb" "$LINENO"
+            find_adb_serial_number
+            get_device_info_from_adb
+            return 0
         fi
-        echo ""
-        eval "unzip -oq google-tradefed.zip"
-        TF_BIN=/tmp/tradefed/tradefed.sh
-        cd "$REPO_ROOT_PATH"
-    fi
-    if [ -d "${ANDROID_JAVA_HOME}" ] ; then
-        JDK_PATH="${ANDROID_JAVA_HOME}"
-    elif [ -d "$PLATFORM_JDK_PATH" ] ; then
-        JDK_PATH="$PLATFORM_JDK_PATH"
-    elif [ -d "$KERNEL_JDK_PATH" ] ; then
-        JDK_PATH="$KERNEL_JDK_PATH"
-    elif [ -d "$LOCAL_JDK_PATH" ] ; then
-        JDK_PATH="$LOCAL_JDK_PATH"
-    else
-        print_error "Can't find JAVA JDK path" "$LINENO"
     fi
-    TRADEFED="JAVA_HOME=$JDK_PATH PATH=$JDK_PATH/bin:$PATH $TF_BIN"
+
+    print_error "$SERIAL_NUMBER is not connected with adb or fastboot" "$LINENO"
 }
 
 adb_checker
@@ -923,13 +1253,27 @@ FETCH_SCRIPT="$REPO_ROOT_PATH/$FETCH_SCRIPT"
 
 find_repo
 
+if [[ "$PLATFORM_BUILD" == "None" ]]; then
+    PLATFORM_BUILD=
+fi
+
+if [[ "$KERNEL_BUILD" == "None" ]]; then
+    KERNEL_BUILD=
+fi
+
+if [[ "$VENDOR_KERNEL_BUILD" == "None" ]]; then
+    VENDOR_KERNEL_BUILD=
+fi
+
 if [ ! -d "$DOWNLOAD_PATH" ]; then
     mkdir -p "$DOWNLOAD_PATH" || $(print_error "Fail to create directory $DOWNLOAD_PATH" "$LINENO")
 fi
 
-if [ ! -z "$PLATFORM_BUILD" ] && [[ "$PLATFORM_BUILD" != ab://* ]] && [ -d "$PLATFORM_BUILD" ]; then
+if [[ "$PLATFORM_BUILD" == ab://* ]]; then
+    format_ab_platform_build_string
+elif [ ! -z "$PLATFORM_BUILD" ] && [ -d "$PLATFORM_BUILD" ]; then
     # Check if PLATFORM_BUILD is an Android platform repo
-    cd "$PLATFORM_BUILD"
+    cd "$PLATFORM_BUILD"  || $(print_error "Fail to go to $PLATFORM_BUILD" "$LINENO")
     PLATFORM_REPO_LIST_OUT=$(repo list 2>&1)
     if [[ "$PLATFORM_REPO_LIST_OUT" != "error"* ]]; then
         go_to_repo_root "$PWD"
@@ -967,7 +1311,7 @@ if [[ "$SYSTEM_BUILD" == ab://* ]]; then
 elif [ ! -z "$SYSTEM_BUILD" ] && [ -d "$SYSTEM_BUILD" ]; then
     print_warn "System build is not supoort yet" "$LINENO"
     # Get GSI build
-    cd "$SYSTEM_BUILD"
+    cd "$SYSTEM_BUILD"  || $(print_error "Fail to go to $SYSTEM_BUILD" "$LINENO")
     SYSTEM_REPO_LIST_OUT=$(repo list 2>&1)
     if [[ "$SYSTEM_REPO_LIST_OUT" != "error"* ]]; then
         go_to_repo_root "$PWD"
@@ -984,30 +1328,13 @@ elif [ ! -z "$SYSTEM_BUILD" ] && [ -d "$SYSTEM_BUILD" ]; then
     fi
 fi
 
+find_flashstation_binary
+
 if [[ "$KERNEL_BUILD" == ab://* ]]; then
-    IFS='/' read -ra array <<< "$KERNEL_BUILD"
-    KERNEL_VERSION=$(echo "${array[2]}" | sed "s/aosp_kernel-common-//g")
-    IFS='-' read -ra array <<< "$KERNEL_VERSION"
-    KERNEL_VERSION="${array[0]}-${array[1]}"
-    print_info "$KERNEL_BUILD is KERNEL_VERSION $KERNEL_VERSION" "$LINENO"
-    if [[ "$KERNEL_VERSION" != "$DEVICE_KERNEL_VERSION"* ]] && [ -z "$PLATFORM_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then
-        print_warn "Device $PRODUCT $SERIAL_NUMBER comes with $DEVICE_KERNEL_STRING $DEVICE_KERNEL_VERSION kernel. \
-Can't flash $KERNEL_VERSION GKI directly. Please use a platform build with the $KERNEL_VERSION kernel \
-or use a vendor kernel build by flag -vkb, for example -vkb -vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
-        print_error "Cannot flash $KERNEL_VERSION GKI to device $SERIAL_NUMBER directly." "$LINENO"
-    fi
-    print_info "Download kernel build $KERNEL_BUILD" "$LINENO"
-    if [ -d "$DOWNLOAD_PATH/gki_dir" ]; then
-        rm -rf "$DOWNLOAD_PATH/gki_dir"
-    fi
-    GKI_DIR="$DOWNLOAD_PATH/gki_dir"
-    mkdir -p "$GKI_DIR"
-    cd "$GKI_DIR" || $(print_error "Fail to go to $GKI_DIR" "$LINENO")
-    download_gki_build $KERNEL_BUILD
-    KERNEL_BUILD="$GKI_DIR"
+    format_ab_kernel_build_string
 elif [ ! -z "$KERNEL_BUILD" ] && [ -d "$KERNEL_BUILD" ]; then
     # Check if kernel repo is provided
-    cd "$KERNEL_BUILD"
+    cd "$KERNEL_BUILD" || $(print_error "Fail to go to $KERNEL_BUILD" "$LINENO")
     KERNEL_REPO_LIST_OUT=$(repo list 2>&1)
     if [[ "$KERNEL_REPO_LIST_OUT" != "error"* ]]; then
         go_to_repo_root "$PWD"
@@ -1029,6 +1356,7 @@ elif [ ! -z "$KERNEL_BUILD" ] && [ -d "$KERNEL_BUILD" ]; then
 fi
 
 if [[ "$VENDOR_KERNEL_BUILD" == ab://* ]]; then
+    format_ab_vendor_kernel_build_string
     print_info "Download vendor kernel build $VENDOR_KERNEL_BUILD" "$LINENO"
     if [ -d "$DOWNLOAD_PATH/vendor_kernel_dir" ]; then
         rm -rf "$DOWNLOAD_PATH/vendor_kernel_dir"
@@ -1036,11 +1364,15 @@ if [[ "$VENDOR_KERNEL_BUILD" == ab://* ]]; then
     VENDOR_KERNEL_DIR="$DOWNLOAD_PATH/vendor_kernel_dir"
     mkdir -p "$VENDOR_KERNEL_DIR"
     cd "$VENDOR_KERNEL_DIR" || $(print_error "Fail to go to $VENDOR_KERNEL_DIR" "$LINENO")
-    download_vendor_kernel_build $VENDOR_KERNEL_BUILD
+    if [ -z "$PLATFORM_BUILD" ]; then
+        download_vendor_kernel_for_direct_flash $VENDOR_KERNEL_BUILD
+    else
+        download_vendor_kernel_build $VENDOR_KERNEL_BUILD
+    fi
     VENDOR_KERNEL_BUILD="$VENDOR_KERNEL_DIR"
 elif [ ! -z "$VENDOR_KERNEL_BUILD" ] && [ -d "$VENDOR_KERNEL_BUILD" ]; then
     # Check if vendor kernel repo is provided
-    cd "$VENDOR_KERNEL_BUILD"
+    cd "$VENDOR_KERNEL_BUILD"  || $(print_error "Fail to go to $VENDOR_KERNEL_BUILD" "$LINENO")
     VENDOR_KERNEL_REPO_LIST_OUT=$(repo list 2>&1)
     if [[ "$VENDOR_KERNEL_REPO_LIST_OUT" != "error"* ]]; then
         go_to_repo_root "$PWD"
@@ -1088,14 +1420,13 @@ if [ -z "$PLATFORM_BUILD" ]; then  # No platform build provided
     if [ -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then  # No kernel or vendor kernel build
         print_info "KERNEL_BUILD=$KERNEL_BUILD VENDOR_KERNEL_BUILD=$VENDOR_KERNEL_BUILD" "$LINENO"
         print_error "Nothing to flash" "$LINENO"
-    elif [ -z "$KERNEL_BUILD" ] && [ ! -z "$VENDOR_KERNEL_BUILD" ]; then  # Only vendor kernel build
+    fi
+    if [ ! -z "$VENDOR_KERNEL_BUILD" ]; then
         print_info "Flash kernel from $VENDOR_KERNEL_BUILD" "$LINENO"
         flash_vendor_kernel_build
-    elif [ ! -z "$KERNEL_BUILD" ] && [ ! -z "$VENDOR_KERNEL_BUILD" ]; then  # Both kernel and vendor kernel builds
-        print_error "Mixing only GKI build & vendor kernel build is not supported. \
-Please add platform build for example -pb ab://git_main/$PRODUCT-trunk_staging-userdebug/latest." "$LINENO"
-    elif [ ! -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then  # Only GKI build
-        gki_build_only_operation
+    fi
+    if [ ! -z "$KERNEL_BUILD" ]; then
+        flash_gki_build
     fi
 else  # Platform build provided
     if [ -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then  # No kernel or vendor kernel build
@@ -1108,7 +1439,7 @@ else  # Platform build provided
     elif [ ! -z "$KERNEL_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then # GKI build and platform build
         flash_platform_build
         get_device_info
-        gki_build_only_operation
+        flash_gki_build
     elif [ ! -z "$KERNEL_BUILD" ] && [ ! -z "$VENDOR_KERNEL_BUILD" ]; then  # All three builds provided
         print_info "Mix GKI kernel, vendor kernel and platform build" "$LINENO"
         mixing_build
diff --git a/tools/launch_cvd.sh b/tools/launch_cvd.sh
index d1be8c0..fee7e36 100755
--- a/tools/launch_cvd.sh
+++ b/tools/launch_cvd.sh
@@ -150,6 +150,66 @@ function adb_checker() {
     fi
 }
 
+function create_kernel_build_cmd() {
+    local cf_kernel_repo_root=$1
+    local cf_kernel_version=$2
+
+    local regex="((?<=android-)mainline|(\K\d+\.\d+(?=-stable)))|((?:android)\K\d+)"
+    local android_version
+    android_version=$(grep -oP "$regex" <(echo "$cf_kernel_version"))
+    local build_cmd=""
+    if [ -f "$cf_kernel_repo_root/common-modules/virtual-device/BUILD.bazel" ]; then
+        # support android-mainline, android16, android15, android14, android13
+        build_cmd+="tools/bazel run --config=fast"
+        if [ "$GCOV" = true ]; then
+            build_cmd+=" --gcov"
+        fi
+        if [ "$DEBUG" = true ]; then
+            build_cmd+=" --debug"
+        fi
+        if [ "$KASAN" = true ]; then
+            build_cmd+=" --kasan"
+        fi
+        build_cmd+=" //common-modules/virtual-device:virtual_device_x86_64_dist"
+    elif [ -f "$cf_kernel_repo_root/build/build.sh" ]; then
+        if [[ "$android_version" == "12" ]]; then
+            build_cmd+="BUILD_CONFIG=common/build.config.gki.x86_64 build/build.sh"
+            build_cmd+=" && "
+            build_cmd+="BUILD_CONFIG=common-modules/virtual-device/build.config.virtual_device.x86_64 build/build.sh"
+        elif [[ "$android_version" == "11" ]] || [[ "$android_version" == "4.19" ]]; then
+            build_cmd+="BUILD_CONFIG=common/build.config.gki.x86_64 build/build.sh"
+            build_cmd+=" && "
+            build_cmd+="BUILD_CONFIG=common-modules/virtual-device/build.config.cuttlefish.x86_64 build/build.sh"
+        else
+            echo "The Kernel build $cf_kernel_version is not yet supported" >&2
+            return 1
+        fi
+    else
+        echo "The Kernel build $cf_kernel_version is not yet supported" >&2
+        return 1
+    fi
+
+    echo "$build_cmd"
+}
+
+function create_kernel_build_path() {
+    local cf_kernel_version=$1
+
+    local regex="((?<=android-)mainline|(\K\d+\.\d+(?=-stable)))|((?:android)\K\d+)"
+    local android_version
+    android_version=$(grep -oP "$regex" <(echo "$cf_kernel_version"))
+    if [ "$android_version" = "mainline" ] || greater_than_or_equal_to "$android_version" "14"; then
+        # support android-mainline, android16, android15, android14
+        echo "out/virtual_device_x86_64/dist"
+    elif greater_than_or_equal_to "$android_version" "11" || [[ "$android_version" == "4.19" ]]; then
+        # support android13, android12, android11, android-4.19-stable
+        echo "out/$cf_kernel_version/dist"
+    else
+        echo "The version of this kernel build $cf_kernel_version is not supported yet" >&2
+        return 1
+    fi
+}
+
 function go_to_repo_root() {
     current_dir="$1"
     while [ ! -d ".repo" ] && [ "$current_dir" != "/" ]; do
@@ -158,6 +218,48 @@ function go_to_repo_root() {
     done
 }
 
+function greater_than_or_equal_to() {
+    local num1="$1"
+    local num2="$2"
+
+    # This regex matches strings formatted as floating-point or integer numbers
+    local num_regex="^[0]([\.][0-9]+)?$|^[1-9][0-9]*([\.][0-9]+)?$"
+    if [[ ! "$num1" =~ $num_regex ]] || [[ ! "$num2" =~ $num_regex ]]; then
+        return 1
+    fi
+
+    if [[ $(echo "$num1 >= $num2" | bc -l) -eq 1 ]]; then
+        return 0
+    else
+        return 1
+    fi
+}
+
+# Checks if target_path is within root_directory
+function is_path_in_root() {
+    local root_directory="$1"
+    local target_path="$2"
+
+    # expand the path variable, for example:
+    # "~/Documents" becomes "/home/user/Documents"
+    root_directory=$(eval echo "$root_directory")
+    target_path=$(eval echo "$target_path")
+
+    # remove the trailing slashes
+    root_directory=$(realpath -m "$root_directory")
+    target_path=$(realpath -m "$target_path")
+
+    # handles the corner case, for example:
+    # $root_directory="/home/user/Doc", $target_path="/home/user/Documents/"
+    root_directory="${root_directory}/"
+
+    if [[ "$target_path" = "$root_directory"* ]]; then
+        return 0
+    else
+        return 1
+    fi
+}
+
 function print_info() {
     echo "[$MY_NAME]: ${GREEN}$1${END}"
 }
@@ -172,7 +274,7 @@ function print_error() {
     exit 1
 }
 
-function set_platform_repo () {
+function set_platform_repo() {
     print_warn "Build target product '${TARGET_PRODUCT}' does not match expected '$1'"
     local lunch_cli="source build/envsetup.sh && lunch $1"
     if [ -f "build/release/release_configs/trunk_staging.textproto" ]; then
@@ -184,7 +286,7 @@ function set_platform_repo () {
     eval "$lunch_cli"
 }
 
-function find_repo () {
+function find_repo() {
     manifest_output=$(grep -e "superproject" -e "gs-pixel" -e "private/google-modules/soc/gs" \
     -e "kernel/common" -e "common-modules/virtual-device" .repo/manifests/default.xml)
     case "$manifest_output" in
@@ -202,10 +304,14 @@ function find_repo () {
                 CF_KERNEL_REPO_ROOT="$PWD"
                 CF_KERNEL_VERSION=$(grep -e "common-modules/virtual-device" \
                 .repo/manifests/default.xml | grep -oP 'revision="\K[^"]*')
-                print_info "CF_KERNEL_REPO_ROOT=$CF_KERNEL_REPO_ROOT, \
-                CF_KERNEL_VERSION=$CF_KERNEL_VERSION"
+                print_info "CF_KERNEL_REPO_ROOT=$CF_KERNEL_REPO_ROOT, CF_KERNEL_VERSION=$CF_KERNEL_VERSION"
                 if [ -z "$KERNEL_BUILD" ]; then
-                    KERNEL_BUILD="$CF_KERNEL_REPO_ROOT/out/virtual_device_x86_64/dist"
+                    output=$(create_kernel_build_path "$CF_KERNEL_VERSION" 2>&1)
+                    if [[ $? -ne 0 ]]; then
+                        print_error "$output"
+                    fi
+                    KERNEL_BUILD="${CF_KERNEL_REPO_ROOT}/$output"
+                    print_info "KERNEL_BUILD=$KERNEL_BUILD"
                 fi
             fi
             ;;
@@ -215,7 +321,7 @@ function find_repo () {
     esac
 }
 
-function rebuild_platform () {
+function rebuild_platform() {
     build_cmd="m -j12"
     print_warn "Flag --skip-build is not set. Rebuilt images at $PWD with: $build_cmd"
     eval "$build_cmd"
@@ -234,8 +340,6 @@ function rebuild_platform () {
 
 adb_checker
 
-# LOCAL_REPO= $ Unused
-
 OLD_PWD=$PWD
 MY_NAME=$0
 
@@ -251,8 +355,6 @@ else
     go_to_repo_root "$PWD"
 fi
 
-# REPO_ROOT_PATH="$PWD" # unused
-
 find_repo
 
 if [ "$SKIP_BUILD" = false ] && [ -n "$PLATFORM_BUILD" ] && [[ "$PLATFORM_BUILD" != ab://* ]] \
@@ -285,49 +387,49 @@ if [ "$SKIP_BUILD" = false ] && [ -n "$SYSTEM_BUILD" ] && [[ "$SYSTEM_BUILD" !=
     fi
 fi
 
-if [ "$SKIP_BUILD" = false ] && [ -n "$KERNEL_BUILD" ] && [[ "$KERNEL_BUILD" != ab://* ]] \
-&& [ -d "$KERNEL_BUILD" ]; then
-    # Check if kernel repo is provided, if yes rebuild
-    cd "$KERNEL_BUILD" || print_error "Failed to cd to $KERNEL_BUILD"
+if [ "$SKIP_BUILD" = false ] && [ -n "$KERNEL_BUILD" ] && [[ "$KERNEL_BUILD" != ab://* ]]; then
+    if [ -d "$CF_KERNEL_REPO_ROOT" ] && [ -n "$CF_KERNEL_VERSION" ] && is_path_in_root "$CF_KERNEL_REPO_ROOT" "$KERNEL_BUILD"; then
+        # Support first-build in the local kernel repository
+        target_path="$CF_KERNEL_REPO_ROOT"
+    elif [ -d $KERNEL_BUILD ]; then
+        target_path="$KERNEL_BUILD"
+    else
+        print_error "Built kernel not found. Either build the kernel or use the default kernel from the local repository"
+    fi
+
+    cd "$target_path" || print_error "Failed to cd to $target_path"
     KERNEL_REPO_LIST_OUT=$(repo list 2>&1)
     if [[ "$KERNEL_REPO_LIST_OUT" != "error"* ]]; then
-        go_to_repo_root "$PWD"
-        if [ ! -f "common-modules/virtual-device/BUILD.bazel" ]; then
-            # TODO(b/365590299): Add build support to android12 and earlier kernels
-            print_error "bazel build common-modules/virtual-device is not supported in this kernel tree"
-        fi
+        go_to_repo_root "$target_path"
+        target_kernel_repo_root="$PWD"
+        target_cf_kernel_version=$(grep -e "common-modules/virtual-device" \
+        .repo/manifests/default.xml | grep -oP 'revision="\K[^"]*')
 
-        # KERNEL_VERSION=$(grep -e "common-modules/virtual-device" .repo/manifests/default.xml | grep -oP 'revision="\K[^"]*') # unused
+        print_info "target_kernel_repo_root=$target_kernel_repo_root, target_cf_kernel_version=$target_cf_kernel_version"
 
-        # Build a new kernel
-        build_cmd="tools/bazel run --config=fast"
-        if [ "$GCOV" = true ]; then
-            build_cmd+=" --gcov"
+        output=$(create_kernel_build_cmd $PWD $target_cf_kernel_version 2>&1)
+        if [[ $? -ne 0 ]]; then
+            print_error "$output"
         fi
-        if [ "$DEBUG" = true ]; then
-            build_cmd+=" --debug"
-        fi
-        if [ "$KASAN" = true ]; then
-            build_cmd+=" --kasan"
-        fi
-        build_cmd+=" //common-modules/virtual-device:virtual_device_x86_64_dist"
+        build_cmd="$output"
         print_warn "Flag --skip-build is not set. Rebuild the kernel with: $build_cmd."
-        eval "$build_cmd"
-        exit_code=$?
-        if [ $exit_code -eq 0 ]; then
-            print_info "$build_cmd succeeded"
-        else
-            print_error "$build_cmd failed"
-        fi
-        KERNEL_BUILD="$PWD/out/virtual_device_x86_64/dist"
+        eval "$build_cmd" && print_info "$build_cmd succeeded" || print_error "$build_cmd failed"
+    else
+        print_warn "Current path $PWD is not a valid Android repo, please ensure it contains the kernel"
     fi
 fi
 
-
 if [ -z "$ACLOUD_BIN" ] || ! [ -x "$ACLOUD_BIN" ]; then
     output=$(which acloud 2>&1)
     if [ -z "$output" ]; then
         print_info "Use acloud binary from $ACLOUD_PREBUILT"
+        if [ -n "${PLATFORM_REPO_ROOT}" ]; then
+            ACLOUD_PREBUILT="${PLATFORM_REPO_ROOT}/${ACLOUD_PREBUILT}"
+        elif  [ -n "${CF_KERNEL_REPO_ROOT}" ]; then
+            ACLOUD_PREBUILT="${CF_KERNEL_REPO_ROOT}/${ACLOUD_PREBUILT}"
+        else
+            print_error "Unable to determine repository root path from repo manifest"
+        fi
         ACLOUD_BIN="$ACLOUD_PREBUILT"
     else
         print_info "Use acloud binary from $output"
diff --git a/tools/run_test_only.sh b/tools/run_test_only.sh
index 65442f7..88843f5 100755
--- a/tools/run_test_only.sh
+++ b/tools/run_test_only.sh
@@ -75,7 +75,7 @@ function print_help() {
     echo "Available options:"
     echo "  -s <serial_number>, --serial=<serial_number>"
     echo "                        The device serial number to run tests with."
-    echo "  -td <test_dir>, --test-dir=<test_dir>"
+    echo "  -td <test_dir>, --test-dir=<test_dir> or -tb <test_build>, --test-build=<test_build>"
     echo "                        The test artifact file name or directory path."
     echo "                        Can be a local file or directory or a remote file"
     echo "                        as ab://<branch>/<build_target>/<build_id>/<file_name>."
@@ -105,7 +105,7 @@ function print_help() {
     exit 0
 }
 
-function set_platform_repo () {
+function set_platform_repo() {
     print_warn "Build target product '${TARGET_PRODUCT}' does not match device product '$PRODUCT'"
     lunch_cli="source build/envsetup.sh && "
     if [ -f "build/release/release_configs/trunk_staging.textproto" ]; then
@@ -117,12 +117,12 @@ function set_platform_repo () {
     eval "$lunch_cli"
 }
 
-function run_test_in_platform_repo () {
+function run_test_in_platform_repo() {
     if [ -z "${TARGET_PRODUCT}" ]; then
         set_platform_repo
     elif [[ "${TARGET_PRODUCT}" != *"x86"* && "${PRODUCT}" == *"x86"* ]] || \
-       [[ "${TARGET_PRODUCT}" == *"x86"* && "${PRODUCT}" != *"x86"* ]]; then
-       set_platform_repo
+        [[ "${TARGET_PRODUCT}" == *"x86"* && "${PRODUCT}" != *"x86"* ]]; then
+        set_platform_repo
     fi
     atest_cli="atest ${TEST_NAMES[*]} -s $SERIAL_NUMBER --"
     if $GCOV; then
@@ -175,7 +175,7 @@ while test $# -gt 0; do
             LOG_DIR=$(echo $1 | sed -e "s/^[^=]*=//g")
             shift
             ;;
-        -td)
+        -td | -tb )
             shift
             if test $# -gt 0; then
                 TEST_DIR=$1
@@ -184,7 +184,7 @@ while test $# -gt 0; do
             fi
             shift
             ;;
-        --test-dir*)
+        --test-dir* | --test-build*)
             TEST_DIR=$(echo $1 | sed -e "s/^[^=]*=//g")
             shift
             ;;
@@ -268,7 +268,7 @@ fi
 
 BOARD=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.board)
 ABI=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.cpu.abi)
-PRODUCT=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.product)
+PRODUCT=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.product.name)
 BUILD_TYPE=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.type)
 
 if [ -z "$TEST_DIR" ]; then
@@ -277,6 +277,7 @@ if [ -z "$TEST_DIR" ]; then
         # In the platform repo
         print_info "Run test with atest" "$LINENO"
         run_test_in_platform_repo
+        return
     elif [[ "$BOARD" == "cutf"* ]] && [[ "$REPO_LIST_OUT" == *"common-modules/virtual-device"* ]]; then
         # In the android kernel repo
         if [[ "$ABI" == "arm64"* ]]; then
@@ -302,17 +303,15 @@ for i in "$TEST_NAMES"; do
 done
 
 if [[ "$TEST_DIR" == ab://* ]]; then
-    # Download test_file if it's remote file ab://
-    if [ -d "$DOWNLOAD_PATH" ]; then
-        rm -rf "$DOWNLOAD_PATH"
+    if [ ! -d "$DOWNLOAD_PATH" ]; then
+        mkdir -p "$DOWNLOAD_PATH" || $(print_error "Fail to create directory $DOWNLOAD_PATH" "$LINENO")
     fi
-    mkdir -p "$DOWNLOAD_PATH" || $(print_error "Fail to create directory $DOWNLOAD_PATH" "$LINENO")
     cd $DOWNLOAD_PATH || $(print_error "Fail to go to $DOWNLOAD_PATH" "$LINENO")
     file_name=${TEST_DIR##*/}
     eval "$FETCH_SCRIPT $TEST_DIR"
     exit_code=$?
     if [ $exit_code -eq 0 ]; then
-        print_info "$TEST_DIR is downloaded succeeded" "$LINENO"
+        print_info "$TEST_DIR is downloaded to $DOWNLOAD_PATH successfully" "$LINENO"
     else
         print_error "Failed to download $TEST_DIR" "$LINENO"
     fi
@@ -340,18 +339,16 @@ elif [ ! -z "$TEST_DIR" ]; then
         print_info "Test_dir $TEST_DIR is from Android platform repo. Run test with atest" "$LINENO"
         go_to_repo_root "$PWD"
         run_test_in_platform_repo
+        return
     fi
 fi
 
 cd "$REPO_ROOT_PATH"
-if [[ "$TEST_DIR" == *".zip"* ]]; then
+if [[ "$TEST_DIR" == *.zip ]]; then
     filename=${TEST_DIR##*/}
-    new_test_dir="$REPO_ROOT_PATH/out/tests"
-    if [ ! -d "$new_test_dir" ]; then
-        mkdir -p "$new_test_dir" || $(print_error "Failed to make directory $new_test_dir" "$LINENO")
-    else
-        folder_name="${filenamef%.*}"
-        rm -r "$new_test_dir/$folder_name"
+    new_test_dir="${TEST_DIR%.*}"
+    if [ -d "$new_test_dir" ]; then
+        rm -r "$new_test_dir"
     fi
     unzip -oq "$TEST_DIR" -d "$new_test_dir" || $(print_error "Failed to unzip $TEST_DIR to $new_test_dir" "$LINENO")
     case $filename in
@@ -367,14 +364,14 @@ fi
 print_info "Will run tests with test artifacts in $TEST_DIR" "$LINENO"
 
 if [ -f "${TEST_DIR}/tools/vts-tradefed" ]; then
-    TRADEFED="${TEST_DIR}/tools/vts-tradefed"
+    TRADEFED="JAVA_HOME=${TEST_DIR}/jdk PATH=${TEST_DIR}/jdk/bin:$PATH ${TEST_DIR}/tools/vts-tradefed"
     print_info "Will run tests with vts-tradefed from $TRADEFED" "$LINENO"
     print_info "Many VTS tests need WIFI connection, please make sure WIFI is connected before you run the test." "$LINENO"
     tf_cli="$TRADEFED run commandAndExit \
     vts --skip-device-info --log-level-display info --log-file-path=$LOG_DIR \
     $TEST_FILTERS -s $SERIAL_NUMBER"
 elif [ -f "${TEST_DIR}/tools/cts-tradefed" ]; then
-    TRADEFED="${TEST_DIR}/tools/cts-tradefed"
+    TRADEFED="JAVA_HOME=${TEST_DIR}/jdk PATH=${TEST_DIR}/jdk/bin:$PATH ${TEST_DIR}/tools/cts-tradefed"
     print_info "Will run tests with cts-tradefed from $TRADEFED" "$LINENO"
     print_info "Many CTS tests need WIFI connection, please make sure WIFI is connected before you run the test." "$LINENO"
     tf_cli="$TRADEFED run commandAndExit cts --skip-device-info \
@@ -410,11 +407,12 @@ fi
 
 # Add GCOV options if enabled
 if $GCOV; then
+    tf_cli+=" --enable-root"
     tf_cli+=$TRADEFED_GCOV_OPTIONS
 fi
 
 # Evaluate the TradeFed command with extra arguments
-print_info "Run test with: $tf_cli" "${TEST_ARGS[*]}" "$LINENO"
+print_info "Run test with: $tf_cli ${TEST_ARGS[*]}" "$LINENO"
 eval "$tf_cli" "${TEST_ARGS[*]}"
 exit_code=$?
 
```

