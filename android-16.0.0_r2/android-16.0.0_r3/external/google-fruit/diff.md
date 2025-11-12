```diff
diff --git a/.github/workflows/test-on-linux.yml b/.github/workflows/test-on-linux.yml
index 26c5972..21f0d0c 100644
--- a/.github/workflows/test-on-linux.yml
+++ b/.github/workflows/test-on-linux.yml
@@ -14,15 +14,16 @@ on:
     # Run at 8:13 on the 1st day of each month
     - cron:  '13 8 1 * *'
 jobs:
-  Ubuntu-22-10:
+  Ubuntu-24-10:
     runs-on: ubuntu-latest
-    container: polettimarco/fruit-basesystem:ubuntu-22.10
+    container: polettimarco/fruit-basesystem:ubuntu-24.10
     env:
       N_JOBS: 2
       ASAN_OPTIONS: ""
       OS: "linux"
       COMPILER: ${{ matrix.config.compiler }}
       STLARG: ${{ matrix.config.stlarg }}
+      CXX_STANDARD: ${{ matrix.config.cxx_standard }}
     steps:
       - uses: actions/checkout@v3
       - name: test
@@ -34,16 +35,51 @@ jobs:
       fail-fast: false
       matrix:
         config:
-          - {compiler: clang-15.0, stlarg: -stdlib=libstdc++, test: ReleasePlain}
-          - {compiler: clang-15.0, stlarg: -stdlib=libstdc++, test: DebugPlain}
-          - {compiler: clang-15.0, stlarg: -stdlib=libstdc++, test: DebugAsanUbsan}
+          - {compiler: clang-19.0, stlarg: -stdlib=libstdc++, test: ReleasePlain}
+          - {compiler: clang-19.0, stlarg: -stdlib=libstdc++, test: DebugPlain}
+          - {compiler: clang-19.0, stlarg: -stdlib=libstdc++, test: DebugAsanUbsan}
+          - {compiler: clang-19.0, stlarg: -stdlib=libstdc++, cxx_standard: 23, test: ReleasePlain}
+          - {compiler: clang-19.0, stlarg: -stdlib=libstdc++, cxx_standard: 23, test: DebugPlain}
+          - {compiler: clang-19.0, stlarg: -stdlib=libstdc++, cxx_standard: 23, test: DebugAsanUbsan}
+          - {compiler: gcc-14, test: ReleasePlain}
+          - {compiler: gcc-14, test: DebugPlain}
+          - {compiler: gcc-14, test: DebugAsanUbsan}
+          - {compiler: clang-14.0, stlarg: -stdlib=libstdc++, test: ReleasePlain}
+          - {compiler: clang-14.0, stlarg: -stdlib=libstdc++, test: DebugPlain}
+          # clang-14 has issues in the DebugAsanUbsan configuration
+          - {compiler: clang-16.0, stlarg: -stdlib=libstdc++, test: DebugAsanUbsan}
+          - {compiler: gcc-11, test: ReleasePlain}
+          - {compiler: gcc-11, test: DebugAsanUbsan}
+
+  Ubuntu-24-04:
+    runs-on: ubuntu-latest
+    container: polettimarco/fruit-basesystem:ubuntu-24.04
+    env:
+      N_JOBS: 2
+      ASAN_OPTIONS: ""
+      OS: "linux"
+      COMPILER: ${{ matrix.config.compiler }}
+      STLARG: ${{ matrix.config.stlarg }}
+    steps:
+      - uses: actions/checkout@v3
+      - name: test
+        run: extras/scripts/postsubmit-helper.sh ${{ matrix.config.test }}
+      - name: Setup tmate session
+        uses: mxschmitt/action-tmate@v3
+        if: ${{ github.event_name == 'workflow_dispatch' && github.event.inputs.debug_enabled && failure() }}
+    strategy:
+      fail-fast: false
+      matrix:
+        config:
+          - {compiler: clang-19.0, stlarg: -stdlib=libstdc++, test: ReleasePlain}
+          - {compiler: clang-19.0, stlarg: -stdlib=libstdc++, test: DebugPlain}
+          - {compiler: clang-19.0, stlarg: -stdlib=libstdc++, test: DebugAsanUbsan}
           - {compiler: gcc-12, test: ReleasePlain}
-          - {compiler: gcc-12, test: DebugPlain}
           - {compiler: gcc-12, test: DebugAsanUbsan}
-          - {compiler: clang-11.0, stlarg: -stdlib=libstdc++, test: ReleasePlain}
-          - {compiler: clang-11.0, stlarg: -stdlib=libstdc++, test: DebugPlain}
-          # clang-11 has issues in the DebugAsanUbsan configuration
-          - {compiler: clang-13.0, stlarg: -stdlib=libstdc++, test: DebugAsanUbsan}
+          - {compiler: clang-14.0, stlarg: -stdlib=libstdc++, test: ReleasePlain}
+          - {compiler: clang-14.0, stlarg: -stdlib=libstdc++, test: DebugPlain}
+          # clang-14 has issues in the DebugAsanUbsan configuration
+          - {compiler: clang-14.0, stlarg: -stdlib=libstdc++, test: DebugAsanUbsan}
           - {compiler: gcc-9, test: ReleasePlain}
           - {compiler: gcc-9, test: DebugAsanUbsan}
 
@@ -67,9 +103,9 @@ jobs:
       fail-fast: false
       matrix:
         config:
-          - {compiler: clang-15.0, stlarg: -stdlib=libstdc++, test: ReleasePlain}
-          - {compiler: clang-15.0, stlarg: -stdlib=libstdc++, test: DebugPlain}
-          - {compiler: clang-15.0, stlarg: -stdlib=libstdc++, test: DebugAsanUbsan}
+          - {compiler: clang-19.0, stlarg: -stdlib=libstdc++, test: ReleasePlain}
+          - {compiler: clang-19.0, stlarg: -stdlib=libstdc++, test: DebugPlain}
+          - {compiler: clang-19.0, stlarg: -stdlib=libstdc++, test: DebugAsanUbsan}
           - {compiler: gcc-12, test: ReleasePlain}
           - {compiler: gcc-12, test: DebugAsanUbsan}
           - {compiler: clang-11.0, stlarg: -stdlib=libstdc++, test: ReleasePlain}
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 5a03e70..110150b 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -1,4 +1,4 @@
-cmake_minimum_required(VERSION 3.2)
+cmake_minimum_required(VERSION 3.2...4.0)
 
 project(Fruit VERSION 3.7.1 LANGUAGES CXX)
 
@@ -121,7 +121,7 @@ set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${FRUIT_ADDITIONAL_L
 set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${FRUIT_ADDITIONAL_LINKER_FLAGS}")
 
 set(FRUIT_CLANG_TIDY_CHECKS
-    bugprone*,-bugprone-reserved-identifier,-bugprone-exception-escape,clang-analyzer*,performance*,google*,-google-readability*,-google-runtime-references,clang-diagnostic-unused-command-line-argument,misc-macro-parentheses,-clang-diagnostic-dtor-name,-performance-avoid-endl,-performance-enum-size)
+    bugprone*,-bugprone-reserved-identifier,-bugprone-exception-escape,clang-analyzer*,performance*,google*,-google-readability*,-google-runtime-references,clang-diagnostic-unused-command-line-argument,misc-macro-parentheses,-clang-diagnostic-dtor-name,-performance-avoid-endl,-performance-enum-size,-performance-unnecessary-value-param)
 
 set(FRUIT_ENABLE_CLANG_TIDY FALSE CACHE BOOL "Whether to run clang-tidy on the Fruit codebase during the build")
 if(${FRUIT_ENABLE_CLANG_TIDY})
diff --git a/METADATA b/METADATA
index 4bad470..6c74a11 100644
--- a/METADATA
+++ b/METADATA
@@ -8,13 +8,13 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2025
-    month: 1
-    day: 16
+    month: 5
+    day: 22
   }
   homepage: "https://github.com/google/fruit"
   identifier {
     type: "Git"
     value: "https://github.com/google/fruit.git"
-    version: "f47f76e4cf02843e9ebc88e3e2f8181553ac3ab2"
+    version: "19f5c05466565ef507a196b33de08f1c96dd0e58"
   }
 }
diff --git a/extras/dockerfiles/Dockerfile.ubuntu-20.04 b/extras/dockerfiles/Dockerfile.ubuntu-20.04
index 3ce7d9c..31cc409 100644
--- a/extras/dockerfiles/Dockerfile.ubuntu-20.04
+++ b/extras/dockerfiles/Dockerfile.ubuntu-20.04
@@ -22,6 +22,10 @@ RUN apt-get install -y --allow-unauthenticated --no-install-recommends \
         clang-8 \
         clang-9 \
         clang-10 \
+        clang-18 \
+        clang-19 \
+        libclang-rt-18-dev \
+        libclang-rt-19-dev \
         python3.8 \
         python3.8-distutils \
         clang-tidy \
diff --git a/extras/dockerfiles/Dockerfile.ubuntu-22.04 b/extras/dockerfiles/Dockerfile.ubuntu-22.04
index 87c3057..5159640 100644
--- a/extras/dockerfiles/Dockerfile.ubuntu-22.04
+++ b/extras/dockerfiles/Dockerfile.ubuntu-22.04
@@ -21,6 +21,10 @@ RUN apt-get install -y --allow-unauthenticated --no-install-recommends \
         clang-13 \
         clang-14 \
         clang-15 \
+        clang-18 \
+        clang-19 \
+        libclang-rt-18-dev \
+        libclang-rt-19-dev \
         python3 \
         python3-distutils \
         python3-pip \
diff --git a/extras/dockerfiles/Dockerfile.ubuntu-22.10 b/extras/dockerfiles/Dockerfile.ubuntu-22.10
deleted file mode 100644
index f8b45e6..0000000
--- a/extras/dockerfiles/Dockerfile.ubuntu-22.10
+++ /dev/null
@@ -1,38 +0,0 @@
-FROM ubuntu:22.10
-MAINTAINER Marco Poletti <poletti.marco@gmail.com>
-
-COPY common_install.sh common_cleanup.sh /
-
-RUN bash -x /common_install.sh
-
-COPY ubuntu-22.10_custom.list /etc/apt/sources.list.d/
-
-RUN apt-get update
-
-RUN apt-get remove -y python3-pip
-
-RUN apt-get install -y --allow-unauthenticated --no-install-recommends \
-        g++-9 \
-        g++-10 \
-        g++-11 \
-        g++-12 \
-        clang-11 \
-        clang-13 \
-        clang-14 \
-        clang-15 \
-        python3 \
-        python3-distutils \
-        python3-pip \
-        clang-tidy \
-        clang-format
-
-RUN pip3 install absl-py
-RUN pip3 install bidict
-RUN pip3 install pytest
-RUN pip3 install pytest-xdist
-RUN pip3 install sh
-RUN pip3 install setuptools
-RUN pip3 install networkx
-RUN pip3 install wheel
-
-RUN bash -x /common_cleanup.sh
diff --git a/extras/dockerfiles/Dockerfile.ubuntu-24.04 b/extras/dockerfiles/Dockerfile.ubuntu-24.04
index dda3f55..51a5bf8 100644
--- a/extras/dockerfiles/Dockerfile.ubuntu-24.04
+++ b/extras/dockerfiles/Dockerfile.ubuntu-24.04
@@ -21,6 +21,13 @@ RUN apt-get install -y --allow-unauthenticated --no-install-recommends \
         clang-16 \
         clang-17 \
         clang-18 \
+        clang-19 \
+        libclang-rt-14-dev \
+        libclang-rt-15-dev \
+        libclang-rt-16-dev \
+        libclang-rt-17-dev \
+        libclang-rt-18-dev \
+        libclang-rt-19-dev \
         python3 \
         python3-absl \
         python3-bidict \
diff --git a/extras/dockerfiles/Dockerfile.ubuntu-23.10 b/extras/dockerfiles/Dockerfile.ubuntu-24.10
similarity index 70%
rename from extras/dockerfiles/Dockerfile.ubuntu-23.10
rename to extras/dockerfiles/Dockerfile.ubuntu-24.10
index be91ff8..2130dd6 100644
--- a/extras/dockerfiles/Dockerfile.ubuntu-23.10
+++ b/extras/dockerfiles/Dockerfile.ubuntu-24.10
@@ -1,30 +1,34 @@
-FROM ubuntu:23.10
+FROM ubuntu:24.10
 MAINTAINER Marco Poletti <poletti.marco@gmail.com>
 
 COPY common_install.sh common_cleanup.sh /
 
 RUN bash -x /common_install.sh
 
-COPY ubuntu-23.10_custom.list /etc/apt/sources.list.d/
+COPY ubuntu-24.10_custom.list /etc/apt/sources.list.d/
 
 RUN apt-get update
 
 RUN apt-get install -y --allow-unauthenticated --no-install-recommends \
-        g++-9 \
-        g++-10 \
         g++-11 \
         g++-12 \
         g++-13 \
-        clang-13 \
+        g++-14 \
         clang-14 \
         clang-15 \
         clang-16 \
         clang-17 \
         clang-18 \
+        clang-19 \
+        libclang-rt-14-dev \
+        libclang-rt-15-dev \
+        libclang-rt-16-dev \
+        libclang-rt-17-dev \
+        libclang-rt-18-dev \
+        libclang-rt-19-dev \
         python3 \
         python3-absl \
         python3-bidict \
-        python3-distutils \
         python3-networkx \
         python3-pytest \
         python3-pytest-xdist \
diff --git a/extras/dockerfiles/rebuild_all.sh b/extras/dockerfiles/rebuild_all.sh
index 48291a7..7e7f0c7 100755
--- a/extras/dockerfiles/rebuild_all.sh
+++ b/extras/dockerfiles/rebuild_all.sh
@@ -7,7 +7,7 @@ docker run --rm --privileged multiarch/qemu-user-static:register --reset
 
 COMMANDS=()
 
-for V in 20.04 22.04 22.10 23.10 24.04
+for V in 20.04 22.04 24.04 24.10
 do
   C="docker build --squash -t polettimarco/fruit-basesystem:ubuntu-$V -f Dockerfile.ubuntu-$V ."
   COMMANDS+=("$C || { echo; echo FAILED: '$C'; echo; exit 1; }")
diff --git a/extras/dockerfiles/ubuntu-20.04_custom.list b/extras/dockerfiles/ubuntu-20.04_custom.list
index c26e2d9..770a393 100644
--- a/extras/dockerfiles/ubuntu-20.04_custom.list
+++ b/extras/dockerfiles/ubuntu-20.04_custom.list
@@ -1,4 +1,4 @@
-deb http://apt.llvm.org/focal/ llvm-toolchain-focal-9 main
-deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-9 main
-deb http://apt.llvm.org/focal/ llvm-toolchain-focal-10 main
-deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-10 main
+deb http://apt.llvm.org/focal/ llvm-toolchain-focal-18 main
+deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-18 main
+deb http://apt.llvm.org/focal/ llvm-toolchain-focal-19 main
+deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-19 main
diff --git a/extras/dockerfiles/ubuntu-22.04_custom.list b/extras/dockerfiles/ubuntu-22.04_custom.list
index 472aa61..959252c 100644
--- a/extras/dockerfiles/ubuntu-22.04_custom.list
+++ b/extras/dockerfiles/ubuntu-22.04_custom.list
@@ -1,4 +1,4 @@
-deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-14 main
-deb-src http://apt.llvm.org/jammy/ llvm-toolchain-jammy-14 main
-deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-15 main
-deb-src http://apt.llvm.org/jammy/ llvm-toolchain-jammy-15 main
+deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main
+deb-src http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main
+deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-19 main
+deb-src http://apt.llvm.org/jammy/ llvm-toolchain-jammy-19 main
diff --git a/extras/dockerfiles/ubuntu-22.10_custom.list b/extras/dockerfiles/ubuntu-22.10_custom.list
deleted file mode 100644
index c91fea3..0000000
--- a/extras/dockerfiles/ubuntu-22.10_custom.list
+++ /dev/null
@@ -1,4 +0,0 @@
-deb http://apt.llvm.org/kinetic/ llvm-toolchain-kinetic-14 main
-deb-src http://apt.llvm.org/kinetic/ llvm-toolchain-kinetic-14 main
-deb http://apt.llvm.org/kinetic/ llvm-toolchain-kinetic-15 main
-deb-src http://apt.llvm.org/kinetic/ llvm-toolchain-kinetic-15 main
diff --git a/extras/dockerfiles/ubuntu-23.10_custom.list b/extras/dockerfiles/ubuntu-23.10_custom.list
deleted file mode 100644
index 1d83246..0000000
--- a/extras/dockerfiles/ubuntu-23.10_custom.list
+++ /dev/null
@@ -1,4 +0,0 @@
-deb http://apt.llvm.org/mantic/ llvm-toolchain-mantic-17 main
-deb-src http://apt.llvm.org/mantic/ llvm-toolchain-mantic-17 main
-deb http://apt.llvm.org/mantic/ llvm-toolchain-mantic-18 main
-deb-src http://apt.llvm.org/mantic/ llvm-toolchain-mantic-18 main
diff --git a/extras/dockerfiles/ubuntu-24.04_custom.list b/extras/dockerfiles/ubuntu-24.04_custom.list
index 797b9f9..6fcbe0d 100644
--- a/extras/dockerfiles/ubuntu-24.04_custom.list
+++ b/extras/dockerfiles/ubuntu-24.04_custom.list
@@ -1,4 +1,4 @@
-deb http://apt.llvm.org/noble/ llvm-toolchain-noble-17 main
-deb-src http://apt.llvm.org/noble/ llvm-toolchain-noble-17 main
+deb http://apt.llvm.org/noble/ llvm-toolchain-noble-19 main
+deb-src http://apt.llvm.org/noble/ llvm-toolchain-noble-19 main
 deb http://apt.llvm.org/noble/ llvm-toolchain-noble-18 main
 deb-src http://apt.llvm.org/noble/ llvm-toolchain-noble-18 main
diff --git a/extras/dockerfiles/ubuntu-24.10_custom.list b/extras/dockerfiles/ubuntu-24.10_custom.list
new file mode 100644
index 0000000..b7a4368
--- /dev/null
+++ b/extras/dockerfiles/ubuntu-24.10_custom.list
@@ -0,0 +1,4 @@
+deb http://apt.llvm.org/oracular/ llvm-toolchain-oracular-18 main
+deb-src http://apt.llvm.org/oracular/ llvm-toolchain-oracular-18 main
+deb http://apt.llvm.org/oracular/ llvm-toolchain-oracular-19 main
+deb-src http://apt.llvm.org/oracular/ llvm-toolchain-oracular-19 main
diff --git a/extras/dockerfiles/ubuntu_arm-16.04_custom.list b/extras/dockerfiles/ubuntu_arm-16.04_custom.list
deleted file mode 100644
index 0ba95de..0000000
--- a/extras/dockerfiles/ubuntu_arm-16.04_custom.list
+++ /dev/null
@@ -1,10 +0,0 @@
-deb http://ppa.launchpad.net/ubuntu-toolchain-r/test/ubuntu xenial main 
-deb-src http://ppa.launchpad.net/ubuntu-toolchain-r/test/ubuntu xenial main
-deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial main
-deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial main
-deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.8 main
-deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.8 main
-deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.9 main
-deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-3.9 main
-deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-4.0 main
-deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-4.0 main
diff --git a/extras/scripts/postsubmit-helper.sh b/extras/scripts/postsubmit-helper.sh
index bdc9499..c007596 100755
--- a/extras/scripts/postsubmit-helper.sh
+++ b/extras/scripts/postsubmit-helper.sh
@@ -162,6 +162,11 @@ clang-18.0)
     export CXX=clang++-18
     ;;
 
+clang-19.0)
+    export CC=clang-19
+    export CXX=clang++-19
+    ;;
+
 clang-default)
     export CC=clang
     export CXX=clang++
@@ -192,30 +197,30 @@ then
     echo Normalized C++ Standard library location: $(readlink -f $(echo '#include <vector>' | $CXX -x c++ -E - | grep 'vector\"' | awk '{print $3}' | sed 's@/vector@@;s@\"@@g' | head -n 1))
 
     case "$1" in
-    DebugPlain)                      CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2") ;;
-    DebugPlainNoClangTidy)           CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2") ;;
-    DebugPlainNoPch)                 CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
-    DebugPlainNoPchNoClangTidy)      CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
-    DebugAsan)                       CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address") ;;
-    DebugAsanNoClangTidy)            CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address") ;;
-    DebugAsanNoPch)                  CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
-    DebugAsanNoPchNoClangTidy)       CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
-    DebugAsanUbsan)                  CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address,undefined") ;;
-    DebugAsanUbsanNoClangTidy)       CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address,undefined") ;;
-    DebugAsanUbsanNoPch)             CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address,undefined" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
-    DebugAsanUbsanNoPchNoClangTidy)  CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address,undefined" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
-    DebugValgrind)                   CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2"     -DRUN_TESTS_UNDER_VALGRIND=TRUE) ;;
-    DebugValgrindNoClangTidy)        CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2"     -DRUN_TESTS_UNDER_VALGRIND=TRUE) ;;
-    DebugValgrindNoPch)              CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2"     -DRUN_TESTS_UNDER_VALGRIND=TRUE -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
-    DebugValgrindNoPchNoClangTidy)   CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2"     -DRUN_TESTS_UNDER_VALGRIND=TRUE -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
-    ReleasePlain)                    CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS") ;;
-    ReleasePlainNoClangTidy)         CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS") ;;
-    ReleasePlainNoPch)               CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
-    ReleasePlainNoPchNoClangTidy)    CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
-    ReleaseValgrind)                 CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS" -DRUN_TESTS_UNDER_VALGRIND=TRUE) ;;
-    ReleaseValgrindNoClangTidy)      CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS" -DRUN_TESTS_UNDER_VALGRIND=TRUE) ;;
-    ReleaseValgrindNoPch)            CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS" -DRUN_TESTS_UNDER_VALGRIND=TRUE -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
-    ReleaseValgrindNoPchNoClangTidy) CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS" -DRUN_TESTS_UNDER_VALGRIND=TRUE -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
+    DebugPlain)                      CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2") ;;
+    DebugPlainNoClangTidy)           CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2") ;;
+    DebugPlainNoPch)                 CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
+    DebugPlainNoPchNoClangTidy)      CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
+    DebugAsan)                       CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address") ;;
+    DebugAsanNoClangTidy)            CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address") ;;
+    DebugAsanNoPch)                  CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
+    DebugAsanNoPchNoClangTidy)       CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
+    DebugAsanUbsan)                  CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address,undefined") ;;
+    DebugAsanUbsanNoClangTidy)       CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address,undefined") ;;
+    DebugAsanUbsanNoPch)             CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address,undefined" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
+    DebugAsanUbsanNoPchNoClangTidy)  CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O0 -fsanitize=address,undefined" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
+    DebugValgrind)                   CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2"     -DRUN_TESTS_UNDER_VALGRIND=TRUE) ;;
+    DebugValgrindNoClangTidy)        CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2"     -DRUN_TESTS_UNDER_VALGRIND=TRUE) ;;
+    DebugValgrindNoPch)              CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2"     -DRUN_TESTS_UNDER_VALGRIND=TRUE -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
+    DebugValgrindNoPchNoClangTidy)   CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Debug   -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS -DFRUIT_DEBUG=1 -DFRUIT_EXTRA_DEBUG=1 -D_GLIBCXX_DEBUG=1 -O2"     -DRUN_TESTS_UNDER_VALGRIND=TRUE -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
+    ReleasePlain)                    CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS") ;;
+    ReleasePlainNoClangTidy)         CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS") ;;
+    ReleasePlainNoPch)               CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
+    ReleasePlainNoPchNoClangTidy)    CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS" -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
+    ReleaseValgrind)                 CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS" -DRUN_TESTS_UNDER_VALGRIND=TRUE) ;;
+    ReleaseValgrindNoClangTidy)      CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS" -DRUN_TESTS_UNDER_VALGRIND=TRUE) ;;
+    ReleaseValgrindNoPch)            CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=TRUE  -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS" -DRUN_TESTS_UNDER_VALGRIND=TRUE -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
+    ReleaseValgrindNoPchNoClangTidy) CMAKE_ARGS=(-DCMAKE_BUILD_TYPE=Release -DFRUIT_ENABLE_CLANG_TIDY=FALSE -DCMAKE_CXX_STANDARD="${CXX_STANDARD}" -DCMAKE_CXX_FLAGS="$COMMON_CXX_FLAGS" -DRUN_TESTS_UNDER_VALGRIND=TRUE -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF) ;;
     *) echo "Error: you need to specify one of the supported postsubmit modes (see postsubmit.sh)."; exit 1 ;;
     esac
     # Setting compilers only via env vars doesn't work when using recent versions of XCode.
@@ -247,7 +252,7 @@ then
     cd tests
     run_make
 
-    python3 -m pytest -n auto -r a "$SOURCES_PATH"/tests
+    python3 -m pytest -n auto -r a
     cd ..
 
     make install
diff --git a/extras/scripts/postsubmit.sh b/extras/scripts/postsubmit.sh
index 5b95134..813f118 100755
--- a/extras/scripts/postsubmit.sh
+++ b/extras/scripts/postsubmit.sh
@@ -26,6 +26,7 @@ linux*)
         export N_JOBS=$N_JOBS;
         export STLARG=$STLARG;
         export ASAN_OPTIONS=$ASAN_OPTIONS;
+        export CXX_STANDARD=$CXX_STANDARD;
         export OS=$OS;
         cd fruit; extras/scripts/postsubmit-helper.sh $1"
     exit $?
@@ -39,6 +40,7 @@ osx)
     export N_JOBS
     export STLARG
     export ASAN_OPTIONS
+    export CXX_STANDARD
     export OS
     extras/scripts/postsubmit-helper.sh "$@"
     exit $?
diff --git a/include/fruit/component.h b/include/fruit/component.h
index cd8be1f..1eeeee9 100644
--- a/include/fruit/component.h
+++ b/include/fruit/component.h
@@ -148,7 +148,8 @@ public:
 
   /**
    * This tells Fruit that "the implementation of I is C".
-   * I must be a base class of C, and it's typically (but not necessarily) an abstract class.
+   * I must be a base class of C (or equal to C if binding a type to itself with different annotations), and it's
+   * typically (but not necessarily) an abstract class.
    * C is typically a concrete class, but it doesn't have to be: for example, if A inherits from B and B inherits from C
    * you can specify bind<C, B>() and bind<B, A>().
    *
diff --git a/include/fruit/impl/component.defn.h b/include/fruit/impl/component.defn.h
index ddc4810..a6707a4 100644
--- a/include/fruit/impl/component.defn.h
+++ b/include/fruit/impl/component.defn.h
@@ -247,7 +247,7 @@ inline PartialComponent<fruit::impl::InstallComponent<fruit::Component<OtherComp
 PartialComponent<Bindings...>::install(fruit::Component<OtherComponentParams...> (*getComponent)(FormalArgs...),
                                        Args&&... args) {
   using IntCollector = int[];
-  (void)IntCollector{0, fruit::impl::checkAcceptableComponentInstallArg<FormalArgs>()...};
+  (void)IntCollector{0, fruit::impl::checkAcceptableComponentInstallArg<FormalArgs, Args>()...};
 
   using Op = OpFor<fruit::impl::InstallComponent<fruit::Component<OtherComponentParams...>(FormalArgs...)>>;
   (void)typename fruit::impl::meta::CheckIfError<Op>::type();
@@ -277,7 +277,7 @@ inline typename PartialComponent<Bindings...>::template PartialComponentWithRepl
 PartialComponent<Bindings...>::replace(fruit::Component<OtherComponentParams...> (*getReplacedComponent)(FormalArgs...),
                                        Args&&... args) {
   using IntCollector = int[];
-  (void)IntCollector{0, fruit::impl::checkAcceptableComponentInstallArg<FormalArgs>()...};
+  (void)IntCollector{0, fruit::impl::checkAcceptableComponentInstallArg<FormalArgs, Args>()...};
 
   std::tuple<FormalArgs...> args_tuple{std::forward<Args>(args)...};
 
@@ -294,7 +294,7 @@ PartialComponent<Bindings...>::
     PartialComponentWithReplacementInProgress<OtherComponent, GetReplacedComponentFormalArgs...>::with(
         OtherComponent (*getReplacementComponent)(GetReplacementComponentFormalArgs...), Args&&... args) {
   using IntCollector = int[];
-  (void)IntCollector{0, fruit::impl::checkAcceptableComponentInstallArg<GetReplacementComponentFormalArgs>()...};
+  (void)IntCollector{0, fruit::impl::checkAcceptableComponentInstallArg<GetReplacementComponentFormalArgs, Args>()...};
 
   std::tuple<GetReplacementComponentFormalArgs...> args_tuple{std::forward<Args>(args)...};
 
diff --git a/include/fruit/impl/component_function.defn.h b/include/fruit/impl/component_function.defn.h
index e006198..ae04f76 100644
--- a/include/fruit/impl/component_function.defn.h
+++ b/include/fruit/impl/component_function.defn.h
@@ -28,7 +28,7 @@ inline ComponentFunction<ComponentType, ComponentFunctionArgs...>::ComponentFunc
         ComponentType (*getComponent)(ComponentFunctionArgs...), ComponentFunctionArgs... args)
     : getComponent(getComponent), args_tuple{args...} {
     using IntCollector = int[];
-    (void)IntCollector{0, fruit::impl::checkAcceptableComponentInstallArg<ComponentFunctionArgs>()...};
+    (void)IntCollector{0, fruit::impl::checkAcceptableComponentInstallArg<ComponentFunctionArgs, ComponentFunctionArgs>()...};
 }
 
 template <typename ComponentType, typename... ComponentFunctionArgs>
diff --git a/include/fruit/impl/component_functors.defn.h b/include/fruit/impl/component_functors.defn.h
index 1df57d0..12b3dd2 100644
--- a/include/fruit/impl/component_functors.defn.h
+++ b/include/fruit/impl/component_functors.defn.h
@@ -155,7 +155,7 @@ struct AddDeferredInterfaceBinding {
     using I = RemoveAnnotations(AnnotatedI);
     using C = RemoveAnnotations(AnnotatedC);
     using type =
-        If(IsSame(I, C), ConstructError(InterfaceBindingToSelfErrorTag, C),
+        If(IsSame(AnnotatedI, AnnotatedC), ConstructError(InterfaceBindingToSelfErrorTag, C),
            If(Not(IsBaseOf(I, C)), ConstructError(NotABaseClassOfErrorTag, I, C),
               If(Not(IsSame(I, NormalizeType(I))), ConstructError(NonClassTypeErrorTag, I, NormalizeUntilStable(I)),
                  If(Not(IsSame(C, NormalizeType(C))),
diff --git a/include/fruit/impl/component_install_arg_checks.defn.h b/include/fruit/impl/component_install_arg_checks.defn.h
index 781848f..ef16fef 100644
--- a/include/fruit/impl/component_install_arg_checks.defn.h
+++ b/include/fruit/impl/component_install_arg_checks.defn.h
@@ -25,21 +25,23 @@
 namespace fruit {
 namespace impl {
 
-template <typename T>
+template <typename FormalT, typename ActualT>
 FRUIT_ALWAYS_INLINE inline int checkAcceptableComponentInstallArg() {
     // This lambda checks that the required operations on T exist.
     // Note that the lambda is never actually executed.
-    auto checkRequirements = [](const T& constRef, T value) {
-        T x1(constRef);
-        T x2(std::move(value));
+    auto checkRequirements = [](const FormalT& constRef, ActualT actual, FormalT value) {
+        FormalT x1(constRef);
+        FormalT x2(std::move(value));
         x1 = constRef;
         x2 = std::move(value);
         bool b = (constRef == constRef);
-        std::size_t h = std::hash<T>()(constRef);
+        std::size_t h = std::hash<FormalT>()(constRef);
+        FormalT from_actual(actual);
         (void)x1;
         (void)x2;
         (void)b;
         (void)h;
+        (void)from_actual;
     };
     (void)checkRequirements;
     return 0;
diff --git a/include/fruit/impl/injection_errors.h b/include/fruit/impl/injection_errors.h
index 68247d2..61c4ef3 100644
--- a/include/fruit/impl/injection_errors.h
+++ b/include/fruit/impl/injection_errors.h
@@ -280,9 +280,9 @@ struct CannotConstructAbstractClassError {
 template <typename C>
 struct InterfaceBindingToSelfError {
   static_assert(AlwaysFalse<C>::value,
-                "The type C was bound to itself. If this was intentional, to \"tell Fruit to inject the type"
-                " C\", this binding is unnecessary, just remove it. bind<I,C>() is to tell Fruit about"
-                " base-derived class relationships.");
+                "The type C was bound to itself, with the same annotations (if any). If this was intentional, to \"tell"
+                " Fruit to inject the type C\", this binding is unnecessary, just remove it. bind<I,C>() is to tell"
+                " Fruit about base-derived class relationships.");
 };
 
 template <typename TypeParameter, typename TypeOfValue>
diff --git a/include/fruit/impl/meta/wrappers.h b/include/fruit/impl/meta/wrappers.h
index 53dd05c..e0a4f4b 100644
--- a/include/fruit/impl/meta/wrappers.h
+++ b/include/fruit/impl/meta/wrappers.h
@@ -20,6 +20,7 @@
 #include <fruit/impl/fruit-config.h>
 
 #include <memory>
+#include <type_traits>
 
 namespace fruit {
 namespace impl {
diff --git a/include/fruit/impl/normalized_component_storage/normalized_component_storage_holder.h b/include/fruit/impl/normalized_component_storage/normalized_component_storage_holder.h
index 2ba3a22..a7131d0 100644
--- a/include/fruit/impl/normalized_component_storage/normalized_component_storage_holder.h
+++ b/include/fruit/impl/normalized_component_storage/normalized_component_storage_holder.h
@@ -21,7 +21,6 @@
 #include <fruit/impl/data_structures/arena_allocator.h>
 #include <fruit/impl/data_structures/memory_pool.h>
 #include <fruit/impl/fruit_internal_forward_decls.h>
-#include <memory>
 
 namespace fruit {
 namespace impl {
@@ -33,7 +32,11 @@ namespace impl {
  */
 class NormalizedComponentStorageHolder {
 private:
-  std::unique_ptr<NormalizedComponentStorage> storage;
+  // This is semantically a std::unique_ptr, but we can't use std::unique_ptr here in C++23
+  // because it would try to instantiate std::unique_ptr<NormalizedComponentStorage>'s destructor
+  // and that requires including the definition of NormalizedComponentStorage (that we don't
+  // want to include from here / fruit.h).
+  NormalizedComponentStorage* storage;
 
   friend class InjectorStorage;
 
@@ -47,7 +50,6 @@ public:
 
   NormalizedComponentStorageHolder() noexcept = default;
 
-
   /**
    * The MemoryPool is only used during construction, the constructed object *can* outlive the memory pool.
    */
@@ -55,14 +57,15 @@ public:
                                    const std::vector<TypeId, ArenaAllocator<TypeId>>& exposed_types,
                                    MemoryPool& memory_pool, WithUndoableCompression);
 
-  NormalizedComponentStorageHolder(NormalizedComponentStorageHolder&&) = default;
+  NormalizedComponentStorageHolder(NormalizedComponentStorageHolder&& other) noexcept
+      : storage(other.storage) {
+      other.storage = nullptr;
+  }
   NormalizedComponentStorageHolder(const NormalizedComponentStorageHolder&) = delete;
 
   NormalizedComponentStorageHolder& operator=(NormalizedComponentStorageHolder&&) = delete;
   NormalizedComponentStorageHolder& operator=(const NormalizedComponentStorageHolder&) = delete;
 
-  // We don't use the default destructor because that would require the inclusion of
-  // normalized_component_storage.h. We define this in the cpp file instead.
   ~NormalizedComponentStorageHolder() noexcept;
 };
 
diff --git a/src/normalized_component_storage_holder.cpp b/src/normalized_component_storage_holder.cpp
index dfc4fd3..7c0fd5d 100644
--- a/src/normalized_component_storage_holder.cpp
+++ b/src/normalized_component_storage_holder.cpp
@@ -28,7 +28,12 @@ NormalizedComponentStorageHolder::NormalizedComponentStorageHolder(
     : storage(new NormalizedComponentStorage(std::move(component), exposed_types, memory_pool,
                                              NormalizedComponentStorage::WithUndoableCompression())) {}
 
-NormalizedComponentStorageHolder::~NormalizedComponentStorageHolder() noexcept {}
+NormalizedComponentStorageHolder::~NormalizedComponentStorageHolder() noexcept {
+    // It can be nullptr if this NormalizedComponentStorageHolder was moved from.
+    if (storage != nullptr) {
+        delete storage;
+    }
+}
 
 } // namespace impl
 } // namespace fruit
diff --git a/tests/CMakeLists.txt b/tests/CMakeLists.txt
index 7b243a3..1f1429f 100644
--- a/tests/CMakeLists.txt
+++ b/tests/CMakeLists.txt
@@ -155,6 +155,7 @@ file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/pytest.ini"
      CONTENT "
 [pytest]
 testpaths = \"${CMAKE_CURRENT_SOURCE_DIR}\"
+pythonpath = \"${CMAKE_CURRENT_SOURCE_DIR}\"
 addopts = -r a
 timeout = 300
 ")
diff --git a/tests/fruit_test_common.py b/tests/fruit_test_common.py
index 88b21b7..46059fb 100644
--- a/tests/fruit_test_common.py
+++ b/tests/fruit_test_common.py
@@ -216,7 +216,7 @@ else:
         '-L' + PATH_TO_COMPILED_TEST_HEADERS,
         '-Wl,-rpath,' + PATH_TO_COMPILED_TEST_HEADERS,
     ]
-    fruit_error_message_extraction_regex = 'static.assert(.*)'
+    fruit_error_message_extraction_regex = 'error: static.assert(.*)'
 
 fruit_tests_include_dirs = ADDITIONAL_INCLUDE_DIRS.splitlines() + [
     PATH_TO_FRUIT_TEST_HEADERS,
@@ -493,13 +493,13 @@ def expect_compile_error(
                 actual_static_assert_error = actual_static_assert_error,
                 error_message = error_message_head)))
 
-        # 6 is just a constant that works for both g++ (<=6.0.0 at least) and clang++ (<=4.0.0 at least).
-        # It might need to be changed.
-        if not disable_error_line_number_check and (actual_fruit_error_line_number > 6 or actual_static_assert_error_line_number > 6):
+        # 6 and 21 are just values that work for both g++ (<=14.0 at least) and clang++ (<=19.0 at least).
+        # They might need to be changed.
+        if not disable_error_line_number_check and (actual_fruit_error_line_number > 6 or actual_static_assert_error_line_number > 21):
             raise Exception(textwrap.dedent('''\
                 The compilation failed with the expected message, but the error message contained too many lines before the relevant ones.
                 The error type was reported on line {actual_fruit_error_line_number} of the message (should be <=6).
-                The static assert was reported on line {actual_static_assert_error_line_number} of the message (should be <=6).
+                The static assert was reported on line {actual_static_assert_error_line_number} of the message (should be <=21).
                 Error message:
                 {error_message}
                 '''.format(
@@ -508,9 +508,9 @@ def expect_compile_error(
                 error_message = error_message_head)))
 
         for line in error_message_lines[:max(actual_fruit_error_line_number, actual_static_assert_error_line_number)]:
-            if re.search('fruit::impl::meta', line):
+            if any(symbol not in ('CheckIfError') for symbol in re.findall('fruit::impl::meta::([A-Za-z0-9_-]+)\b', line)):
                 raise Exception(
-                    'The compilation failed with the expected message, but the error message contained some metaprogramming types in the output (besides Error). Error message:\n%s' + error_message_head)
+                    'The compilation failed with the expected message, but the error message contained some metaprogramming types in the output (besides Error). Error message:\n%s' % error_message_head)
 
     expect_compile_error_helper(check_error, setup_source_code, source_code, test_params, ignore_deprecation_warnings, ignore_warnings)
 
diff --git a/tests/test_bind_interface.py b/tests/test_bind_interface.py
index 5e558b9..da6ee1a 100755
--- a/tests/test_bind_interface.py
+++ b/tests/test_bind_interface.py
@@ -261,7 +261,7 @@ class TestBindInstance(parameterized.TestCase):
             source,
             locals())
 
-    def test_bound_to_itself_with_annotation_error(self):
+    def test_bound_to_itself_with_annotation_ok(self):
         source = '''
             struct X {};
     
@@ -271,9 +271,7 @@ class TestBindInstance(parameterized.TestCase):
                 .bind<fruit::Annotated<Annotation1, X>, X>();
             }
             '''
-        expect_compile_error(
-            'InterfaceBindingToSelfError<X>',
-            'The type C was bound to itself.',
+        expect_success(
             COMMON_DEFINITIONS,
             source)
 
diff --git a/tests/test_component.py b/tests/test_component.py
index a551aa3..4836877 100755
--- a/tests/test_component.py
+++ b/tests/test_component.py
@@ -79,6 +79,7 @@ class TestComponent(parameterized.TestCase):
         expect_generic_compile_error(
             r'error: use of deleted function .fruit::PartialComponent<Bindings>::PartialComponent\(fruit::PartialComponent<Bindings>&&\).'
             r'|error: call to deleted constructor of .(fruit::)?PartialComponent<>.'
+            r'|error: call to deleted constructor of .typename std::remove_reference<PartialComponent<> &>::type. \(aka .fruit::PartialComponent<>.\)'
             # MSVC 2017
             r'|error C2280: .fruit::PartialComponent<>::PartialComponent\(fruit::PartialComponent<> &&\).: attempting to reference a deleted function'
             # MSVC 2015
diff --git a/tests/test_injector.py b/tests/test_injector.py
index b552f4a..e39b5b0 100755
--- a/tests/test_injector.py
+++ b/tests/test_injector.py
@@ -43,6 +43,97 @@ class TestInjector(parameterized.TestCase):
             COMMON_DEFINITIONS,
             source)
 
+    def test_injector_with_parameters(self):
+        source = '''
+            fruit::Component<> getComponent(int n) {
+              (void)n;
+              return fruit::createComponent();
+            }
+    
+            int main() {
+              fruit::Injector<> injector(getComponent, 5);
+            }
+            '''
+        expect_success(
+            COMMON_DEFINITIONS,
+            source)
+
+    def test_injector_with_parameters_too_few_passed(self):
+        source = '''
+            fruit::Component<> getComponent(int n, bool b) {
+              (void)n;
+              (void)b;
+              return fruit::createComponent();
+            }
+    
+            int main() {
+              fruit::Injector<> injector(getComponent, 5);
+            }
+            '''
+        expect_generic_compile_error(
+            # Clang
+            'pack expansion contains parameter packs .FormalArgs. and .Args. that have different lengths \\(2 vs. 1\\)'
+            # GCC
+            '|mismatched argument pack lengths while expanding .checkAcceptableComponentInstallArg<FormalArgs, Args>().',
+            COMMON_DEFINITIONS,
+            source)
+
+    def test_injector_with_parameters_too_many_passed(self):
+        source = '''
+            fruit::Component<> getComponent(int n) {
+              (void)n;
+              return fruit::createComponent();
+            }
+    
+            int main() {
+              fruit::Injector<> injector(getComponent, 5, true);
+            }
+            '''
+        expect_generic_compile_error(
+            # Clang
+            'pack expansion contains parameter packs .FormalArgs. and .Args. that have different lengths \\(1 vs. 2\\)'
+            # GCC
+            '|mismatched argument pack lengths while expanding .checkAcceptableComponentInstallArg<FormalArgs, Args>().',
+            COMMON_DEFINITIONS,
+            source)
+
+    def test_injector_with_parameters_none_passed(self):
+        source = '''
+            fruit::Component<> getComponent(int n) {
+              (void) n;
+              return fruit::createComponent();
+            }
+    
+            int main() {
+              fruit::Injector<> injector(getComponent);
+            }
+            '''
+        expect_generic_compile_error(
+            # Clang
+            'pack expansion contains parameter packs .FormalArgs. and .Args. that have different lengths \\(1 vs. 0\\)'
+            # GCC
+            '|mismatched argument pack lengths while expanding .checkAcceptableComponentInstallArg<FormalArgs, Args>().',
+            COMMON_DEFINITIONS,
+            source)
+
+    def test_injector_without_parameters_but_some_passed(self):
+        source = '''
+            fruit::Component<> getComponent() {
+              return fruit::createComponent();
+            }
+    
+            int main() {
+              fruit::Injector<> injector(getComponent, 1);
+            }
+            '''
+        expect_generic_compile_error(
+            # Clang
+            'pack expansion contains parameter packs .FormalArgs. and .Args. that have different lengths \\(0 vs. 1\\)'
+            # GCC
+            '|mismatched argument pack lengths while expanding .checkAcceptableComponentInstallArg<FormalArgs, Args>().',
+            COMMON_DEFINITIONS,
+            source)
+
     @parameterized.parameters([
         'X',
         'fruit::Annotated<Annotation1, X>',
diff --git a/tests/test_install.py b/tests/test_install.py
index 6afe780..502dbc5 100755
--- a/tests/test_install.py
+++ b/tests/test_install.py
@@ -374,6 +374,102 @@ class TestInstall(parameterized.TestCase):
             '''
         expect_success(COMMON_DEFINITIONS, source)
 
+    def test_install_with_args_too_few_passed(self):
+        source = '''
+            fruit::Component<> getParentComponent(int n, bool b) {
+              (void)n;
+              (void)b;
+              return fruit::createComponent();
+            }
+    
+            fruit::Component<> getComponent() {
+              return fruit::createComponent()
+                .install(getParentComponent, 5);
+            }
+    
+            int main() {
+              fruit::Injector<> injector(getComponent);
+            }
+            '''
+        expect_generic_compile_error(
+            # Clang
+            'pack expansion contains parameter packs .FormalArgs. and .Args. that have different lengths \\(2 vs. 1\\)'
+            # GCC
+            '|mismatched argument pack lengths while expanding .checkAcceptableComponentInstallArg<FormalArgs, Args>().',
+            COMMON_DEFINITIONS,
+            source)
+
+    def test_install_with_args_too_many_passed(self):
+        source = '''
+            fruit::Component<> getParentComponent(int n) {
+              (void)n;
+              return fruit::createComponent();
+            }
+    
+            fruit::Component<> getComponent() {
+              return fruit::createComponent()
+                .install(getParentComponent, 5, true);
+            }
+    
+            int main() {
+              fruit::Injector<> injector(getComponent);
+            }
+            '''
+        expect_generic_compile_error(
+            # Clang
+            'pack expansion contains parameter packs .FormalArgs. and .Args. that have different lengths \\(1 vs. 2\\)'
+            # GCC
+            '|mismatched argument pack lengths while expanding .checkAcceptableComponentInstallArg<FormalArgs, Args>().',
+            COMMON_DEFINITIONS,
+            source)
+
+    def test_install_with_args_none_passed(self):
+        source = '''
+            fruit::Component<> getParentComponent(int n) {
+              (void)n;
+              return fruit::createComponent();
+            }
+    
+            fruit::Component<> getComponent() {
+              return fruit::createComponent()
+                .install(getParentComponent);
+            }
+    
+            int main() {
+              fruit::Injector<> injector(getComponent);
+            }
+            '''
+        expect_generic_compile_error(
+            # Clang
+            'pack expansion contains parameter packs .FormalArgs. and .Args. that have different lengths \\(1 vs. 0\\)'
+            # GCC
+            '|mismatched argument pack lengths while expanding .checkAcceptableComponentInstallArg<FormalArgs, Args>().',
+            COMMON_DEFINITIONS,
+            source)
+
+    def test_install_without_args_but_some_passed(self):
+        source = '''
+            fruit::Component<> getParentComponent() {
+              return fruit::createComponent();
+            }
+    
+            fruit::Component<> getComponent() {
+              return fruit::createComponent()
+                .install(getParentComponent, 5);
+            }
+    
+            int main() {
+              fruit::Injector<> injector(getComponent);
+            }
+            '''
+        expect_generic_compile_error(
+            # Clang
+            'pack expansion contains parameter packs .FormalArgs. and .Args. that have different lengths \\(0 vs. 1\\)'
+            # GCC
+            '|mismatched argument pack lengths while expanding .checkAcceptableComponentInstallArg<FormalArgs, Args>().',
+            COMMON_DEFINITIONS,
+            source)
+
     def test_install_with_args_error_not_move_constructible(self):
         source = '''
             struct Arg {
diff --git a/tests/test_register_factory.py b/tests/test_register_factory.py
index 9fe8e4f..7020382 100755
--- a/tests/test_register_factory.py
+++ b/tests/test_register_factory.py
@@ -1243,6 +1243,7 @@ class TestRegisterFactory(parameterized.TestCase):
         source = '''
             struct Scaler {
               virtual double scale(double x) = 0;
+              virtual ~Scaler() = default;
             };
     
             struct ScalerImpl : public Scaler {
@@ -1430,6 +1431,7 @@ class TestRegisterFactory(parameterized.TestCase):
         source = '''
             struct Scaler {
               virtual double scale(double x) = 0;
+              virtual ~Scaler() = default;
             };
     
             struct ScalerImpl : public Scaler {
@@ -1673,6 +1675,7 @@ class TestRegisterFactory(parameterized.TestCase):
         source = '''
             struct Scaler {
               virtual double scale(double x) = 0;
+              virtual ~Scaler() = default;
             };
     
             struct ScalerImpl : public Scaler {
```

