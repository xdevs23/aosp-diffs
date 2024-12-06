```diff
diff --git a/.ci.sh b/.ci.sh
index 374bc025..b75f815c 100755
--- a/.ci.sh
+++ b/.ci.sh
@@ -11,6 +11,7 @@
 # Copyright (c) 2019      Mohammed Khajapasha <mohammed.khajapasha@intel.com>
 # Copyright (c) 2019      Manish, Kumar <manish3.kumar@intel.com>
 # Copyright (c) 2019      Philippe Antoine <contact@catenacyber.fr>
+# Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -37,8 +38,6 @@ set -e
 if [[ ${RUNNER_OS} = macOS ]]; then
     latest_brew_python3_bin="$(ls -1d /usr/local/Cellar/python/3.*/bin | sort -n | tail -n1)"
     export PATH="${latest_brew_python3_bin}${PATH:+:}${PATH}"
-    export PATH="/usr/local/opt/coreutils/libexec/gnubin${PATH:+:}${PATH}"
-    export PATH="/usr/local/opt/findutils/libexec/gnubin${PATH:+:}${PATH}"
 elif [[ ${RUNNER_OS} = Linux ]]; then
     export PATH="/usr/lib/llvm-18/bin:${PATH}"
 else
@@ -65,7 +64,7 @@ elif [[ ${MODE} = cmake-oos ]]; then
     cmake ${CMAKE_ARGS} ..
     make VERBOSE=1 CTEST_OUTPUT_ON_FAILURE=1 all test
     make DESTDIR="${PWD}"/ROOT install
-    find ROOT -printf "%P\n" | sort
+    find ROOT | cut -c 6- | sort
 elif [[ ${MODE} = coverage-sh ]]; then
     ./coverage.sh
 else
diff --git a/.github/workflows/autotools-cmake.yml b/.github/workflows/autotools-cmake.yml
index 3713d0fe..96e8f342 100644
--- a/.github/workflows/autotools-cmake.yml
+++ b/.github/workflows/autotools-cmake.yml
@@ -5,8 +5,9 @@
 #                      \___/_/\_\ .__/ \__,_|\__|
 #                               |_| XML parser
 #
-# Copyright (c) 2021-2023 Sebastian Pipping <sebastian@pipping.org>
+# Copyright (c) 2021-2024 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2023      Joyce Brum <joycebrum@google.com>
+# Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -35,6 +36,7 @@ on:
   push:
   schedule:
     - cron: '0 2 * * 5'  # Every Friday at 2am
+  workflow_dispatch:
 
 permissions:
   contents: read
@@ -45,7 +47,7 @@ jobs:
     strategy:
       matrix:
         include:
-          - os: macos-11
+          - os: macos-14
             configure_args:
             cmake_args:
           - os: ubuntu-20.04
@@ -59,7 +61,7 @@ jobs:
         shell: bash
     runs-on: "${{ matrix.os }}"
     steps:
-    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
+    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
 
     - name: (Linux) Install build dependencies
       if: "${{ runner.os == 'Linux' }}"
@@ -80,7 +82,6 @@ jobs:
             automake \
             cmake \
             docbook2x \
-            gnu-sed \
             libtool \
             lzip
 
@@ -127,8 +128,14 @@ jobs:
           # Autotools' LT_LIB_M has a hardcoded exclude for "*-*-darwin*" hosts,
           # while macOS does have libm and is successfully found by CMake.
           # We patch the CMake side in line here to get the differ below to empty.
-          export PATH="$(brew --prefix)/opt/gnu-sed/libexec/gnubin:${PATH}"
-          sed 's,-lm,,' -i build_cmake/ROOT/usr/local/lib*/pkgconfig/expat.pc
+          #
+          # Both GNU and BSD sed can edit in-place without creating a backup,
+          # but not with the same syntax.  The syntax for editing in-place
+          # _with_ a backup however is the same, so do that, then remove the
+          # backup so it doesn't show up in the diff later.
+          sed -e 's,-lm,,' -i.bak \
+              build_cmake/ROOT/usr/local/lib*/pkgconfig/expat.pc
+          rm -f build_cmake/ROOT/usr/local/lib*/pkgconfig/expat.pc.bak
         fi
 
         diff \
diff --git a/.github/workflows/clang-format.yml b/.github/workflows/clang-format.yml
index 6f8a6ddf..14132259 100644
--- a/.github/workflows/clang-format.yml
+++ b/.github/workflows/clang-format.yml
@@ -45,7 +45,7 @@ jobs:
     name: Enforce clang-format clean code
     runs-on: ubuntu-22.04
     steps:
-    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
+    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
 
     - name: Install clang-format 18
       run: |-
diff --git a/.github/workflows/clang-tidy.yml b/.github/workflows/clang-tidy.yml
index 17b8bf03..1248e5d6 100644
--- a/.github/workflows/clang-tidy.yml
+++ b/.github/workflows/clang-tidy.yml
@@ -45,7 +45,7 @@ jobs:
     name: Enforce clang-tidy clean code
     runs-on: ubuntu-22.04
     steps:
-    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
+    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
 
     - name: Install clang-tidy 18
       run: |-
diff --git a/.github/workflows/cmake-required-version.yml b/.github/workflows/cmake-required-version.yml
index efbc40cd..ff7fd441 100644
--- a/.github/workflows/cmake-required-version.yml
+++ b/.github/workflows/cmake-required-version.yml
@@ -5,8 +5,9 @@
 #                      \___/_/\_\ .__/ \__,_|\__|
 #                               |_| XML parser
 #
-# Copyright (c) 2021-2023 Sebastian Pipping <sebastian@pipping.org>
+# Copyright (c) 2021-2024 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2023      Joyce Brum <joycebrum@google.com>
+# Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -35,6 +36,7 @@ on:
   push:
   schedule:
     - cron: '0 2 * * 5'  # Every Friday at 2am
+  workflow_dispatch:
 
 permissions:
   contents: read
@@ -44,7 +46,7 @@ jobs:
     name: Ensure realistic minimum CMake version requirement
     runs-on: ubuntu-20.04
     steps:
-    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
+    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
 
     - name: Install ancient CMake
       run: |
@@ -57,7 +59,7 @@ jobs:
         wget --no-verbose "${download_url}"
 
         chmod +x "${installer_filename}"
-        mkdir ~/.local/
+        mkdir -p ~/.local/
 
         ./"${installer_filename}" --prefix="${HOME}"/.local/ --skip-license
 
diff --git a/.github/workflows/codespell.yml b/.github/workflows/codespell.yml
index ba71c821..2871a846 100644
--- a/.github/workflows/codespell.yml
+++ b/.github/workflows/codespell.yml
@@ -5,7 +5,7 @@
 #                      \___/_/\_\ .__/ \__,_|\__|
 #                               |_| XML parser
 #
-# Copyright (c) 2021-2023 Sebastian Pipping <sebastian@pipping.org>
+# Copyright (c) 2021-2024 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2023      Joyce Brum <joycebrum@google.com>
 # Licensed under the MIT license:
 #
@@ -35,6 +35,7 @@ on:
   push:
   schedule:
     - cron: '0 2 * * 5'  # Every Friday at 2am
+  workflow_dispatch:
 
 permissions:
   contents: read
@@ -44,8 +45,8 @@ jobs:
     name: Enforce codespell-clean spelling
     runs-on: ubuntu-22.04
     steps:
-    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
-    - uses: codespell-project/actions-codespell@94259cd8be02ad2903ba34a22d9c13de21a74461  # v2.0
+    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
+    - uses: codespell-project/actions-codespell@406322ec52dd7b488e48c1c4b82e2a8b3a1bf630  # v2.1
       with:
         path: expat/
         # "arameter" is from "[p]arameter" in xmlwf help output
diff --git a/.github/workflows/coverage.yml b/.github/workflows/coverage.yml
index 0d0cfd4e..4c33b627 100644
--- a/.github/workflows/coverage.yml
+++ b/.github/workflows/coverage.yml
@@ -5,8 +5,9 @@
 #                      \___/_/\_\ .__/ \__,_|\__|
 #                               |_| XML parser
 #
-# Copyright (c) 2021-2023 Sebastian Pipping <sebastian@pipping.org>
+# Copyright (c) 2021-2024 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2023      Joyce Brum <joycebrum@google.com>
+# Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -35,6 +36,7 @@ on:
   push:
   schedule:
     - cron: '0 2 * * 5'  # Every Friday at 2am
+  workflow_dispatch:
 
 permissions:
   contents: read
@@ -46,7 +48,7 @@ jobs:
     env:
       CFLAGS: -g3 -pipe
     steps:
-    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
+    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
     - name: Install build dependencies
       run: |-
         set -x -u
@@ -58,18 +60,16 @@ jobs:
 
         sudo apt-get install --yes --no-install-recommends -V \
             cmake \
+            docbook-xml \
             docbook2x \
-            dos2unix \
             gcc-multilib \
             g++-multilib \
             lcov \
             libbsd-dev \
             lzip \
-            moreutils \
-            ppa-purge
+            moreutils
 
         # Install 32bit Wine
-        sudo ppa-purge -y ppa:ubuntu-toolchain-r/test  # to unblock
         sudo apt-get install --yes --no-install-recommends -V \
             mingw-w64 \
             wine-stable \
@@ -84,7 +84,7 @@ jobs:
         exec ./.ci.sh
 
     - name: Store coverage .info and HTML report
-      uses: actions/upload-artifact@5d5d22a31266ced268874388b861e4b58bb5c2f3  # v4.3.1
+      uses: actions/upload-artifact@834a144ee995460fba8ed112a2fc961b36a5ec5a  # v4.3.6
       with:
         name: coverage
         path: expat/coverage__*/
diff --git a/.github/workflows/cppcheck.yml b/.github/workflows/cppcheck.yml
index 051756dc..5ed43e7b 100644
--- a/.github/workflows/cppcheck.yml
+++ b/.github/workflows/cppcheck.yml
@@ -7,6 +7,7 @@
 #
 # Copyright (c) 2021-2024 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2023      Joyce Brum <joycebrum@google.com>
+# Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -35,6 +36,7 @@ on:
   push:
   schedule:
     - cron: '0 2 * * 5'  # Every Friday at 2am
+  workflow_dispatch:
 
 permissions:
   contents: read
@@ -42,12 +44,12 @@ permissions:
 jobs:
   checks:
     name: Run Cppcheck
-    runs-on: macos-12
+    runs-on: macos-14
     steps:
-    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
+    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
     - name: Install runtime dependencies
       run: |
-        exec brew install cppcheck findutils
+        exec brew install cppcheck
     - name: Run Cppcheck
       run: |
         exec .github/workflows/scripts/mass-cppcheck.sh
diff --git a/.github/workflows/data/expat_config_h_cmake__expected.txt b/.github/workflows/data/expat_config_h_cmake__expected.txt
index 9e8910b0..9b1a4605 100644
--- a/.github/workflows/data/expat_config_h_cmake__expected.txt
+++ b/.github/workflows/data/expat_config_h_cmake__expected.txt
@@ -27,7 +27,6 @@ PACKAGE_STRING
 PACKAGE_TARNAME
 PACKAGE_URL
 PACKAGE_VERSION
-size_t
 STDC_HEADERS
 WORDS_BIGENDIAN
 XML_ATTR_INFO
diff --git a/.github/workflows/data/expat_config_h_in__expected.txt b/.github/workflows/data/expat_config_h_in__expected.txt
index f89b54f5..1e438930 100644
--- a/.github/workflows/data/expat_config_h_in__expected.txt
+++ b/.github/workflows/data/expat_config_h_in__expected.txt
@@ -31,7 +31,6 @@ PACKAGE_STRING
 PACKAGE_TARNAME
 PACKAGE_URL
 PACKAGE_VERSION
-size_t
 STDC_HEADERS
 VERSION
 WORDS_BIGENDIAN
diff --git a/.github/workflows/expat_config_h.yml b/.github/workflows/expat_config_h.yml
index 925c6d03..ac8dbf68 100644
--- a/.github/workflows/expat_config_h.yml
+++ b/.github/workflows/expat_config_h.yml
@@ -5,7 +5,7 @@
 #                      \___/_/\_\ .__/ \__,_|\__|
 #                               |_| XML parser
 #
-# Copyright (c) 2020-2023 Sebastian Pipping <sebastian@pipping.org>
+# Copyright (c) 2020-2024 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2023      Joyce Brum <joycebrum@google.com>
 # Licensed under the MIT license:
 #
@@ -35,6 +35,7 @@ on:
   push:
   schedule:
     - cron: '0 2 * * 5'  # Every Friday at 2am
+  workflow_dispatch:
 
 permissions:
   contents: read
@@ -44,7 +45,7 @@ jobs:
     name: Check expat_config.h.{in,cmake} for regressions
     runs-on: ubuntu-20.04
     steps:
-    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
+    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
     - name: Check expat_config.h.{in,cmake} for regressions
       run: |
         set -v
diff --git a/.github/workflows/fuzzing.yml b/.github/workflows/fuzzing.yml
index 68136006..30299950 100644
--- a/.github/workflows/fuzzing.yml
+++ b/.github/workflows/fuzzing.yml
@@ -44,7 +44,7 @@ jobs:
     name: Run fuzzing regression tests
     runs-on: ubuntu-22.04
     steps:
-    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
+    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
 
     - name: Install Clang 18
       run: |-
@@ -120,7 +120,7 @@ jobs:
 
     - name: Store crashing test units
       if: ${{ failure() }}
-      uses: actions/upload-artifact@5d5d22a31266ced268874388b861e4b58bb5c2f3  # v4.3.1
+      uses: actions/upload-artifact@834a144ee995460fba8ed112a2fc961b36a5ec5a  # v4.3.6
       with:
         name: expat_fuzzing_trouble_${{ github.sha }}
         path: expat/build/*-????????????????????????????????????????
diff --git a/.github/workflows/linux.yml b/.github/workflows/linux.yml
index b77ffbba..215b4156 100644
--- a/.github/workflows/linux.yml
+++ b/.github/workflows/linux.yml
@@ -8,6 +8,7 @@
 # Copyright (c) 2021-2024 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2023      Joyce Brum <joycebrum@google.com>
 # Copyright (c) 2023      Hanno Böck <hanno@gentoo.org>
+# Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -36,6 +37,7 @@ on:
   push:
   schedule:
     - cron: '0 2 * * 5'  # Every Friday at 2am
+  workflow_dispatch:
 
 permissions:
   contents: read
@@ -46,8 +48,6 @@ jobs:
     strategy:
       matrix:
         include:
-          # NOTE: This is a quick port from .travis.yml in reaction to
-          #       stability issues at Travis CI.
           - MODE: cmake-oos
           - MODE: distcheck
           - MODE: qa-sh
@@ -88,7 +88,7 @@ jobs:
     env:
       CFLAGS: -g3 -pipe
     steps:
-    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
+    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
     - name: Install build dependencies (MinGW)
       if: "${{ contains(matrix.FLAT_ENV, 'mingw') }}"
       run: |-
@@ -131,7 +131,6 @@ jobs:
         sudo apt-get install --yes --no-install-recommends -V \
             cmake \
             docbook2x \
-            dos2unix \
             gcc-multilib \
             g++-multilib \
             lcov \
diff --git a/.github/workflows/macos.yml b/.github/workflows/macos.yml
index 7df7971e..36a32732 100644
--- a/.github/workflows/macos.yml
+++ b/.github/workflows/macos.yml
@@ -5,8 +5,9 @@
 #                      \___/_/\_\ .__/ \__,_|\__|
 #                               |_| XML parser
 #
-# Copyright (c) 2020-2023 Sebastian Pipping <sebastian@pipping.org>
+# Copyright (c) 2020-2024 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2023      Joyce Brum <joycebrum@google.com>
+# Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -35,6 +36,7 @@ on:
   push:
   schedule:
     - cron: '0 2 * * 5'  # Every Friday at 2am
+  workflow_dispatch:
 
 permissions:
   contents: read
@@ -44,17 +46,15 @@ jobs:
     name: Perform checks
     strategy:
       matrix:
+        os: [macos-12, macos-14]
         include:
-          # NOTE: This is a quick port from .travis.yml in reaction to
-          #       Homebrew issues at Travis CI.  While we have the matrix
-          #       in two places, please keep the two files in sync.  Thank you!
           - MODE: cmake-oos
           - MODE: distcheck
           - MODE: qa-sh
             FLAT_ENV: CC=clang CXX=clang++ LD=clang++ QA_SANITIZER=address
-    runs-on: macos-11
+    runs-on: ${{ matrix.os }}
     steps:
-    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
+    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
     - name: Install build dependencies
       run: |
         sudo rm /usr/local/bin/2to3  # so that "brew link" will work
diff --git a/.github/workflows/scripts/mass-cppcheck.sh b/.github/workflows/scripts/mass-cppcheck.sh
index 0eaa407e..1a5060e8 100755
--- a/.github/workflows/scripts/mass-cppcheck.sh
+++ b/.github/workflows/scripts/mass-cppcheck.sh
@@ -7,6 +7,7 @@
 #                               |_| XML parser
 #
 # Copyright (c) 2021-2024 Sebastian Pipping <sebastian@pipping.org>
+# Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -31,20 +32,15 @@
 PS4='# '
 set -e -u -o pipefail -x
 
-if [[ "$(uname -s)" =~ ^Darwin ]]; then
-    export PATH="/usr/local/opt/findutils/libexec/gnubin${PATH:+:}${PATH}"
-fi
-
 cppcheck --version
 
-find --version | head -n1
-
 for xml_context_bytes in 0 1024; do
     for xml_ge in 0 1; do
         cppcheck_args=(
             --quiet
             --error-exitcode=1
             --force
+            --check-level=exhaustive
             --suppress=objectIndex
             --suppress=unknownMacro
             -DXML_CONTEXT_BYTES=${xml_context_bytes}
@@ -63,6 +59,6 @@ for xml_context_bytes in 0 1024; do
             -exec cppcheck "${cppcheck_args[@]}" {} +
         )
 
-        time find "${find_args[@]}"
+        time find . "${find_args[@]}"
     done
 done
diff --git a/.github/workflows/valid-xml.yml b/.github/workflows/valid-xml.yml
index 56864fc2..095895c5 100644
--- a/.github/workflows/valid-xml.yml
+++ b/.github/workflows/valid-xml.yml
@@ -5,7 +5,7 @@
 #                      \___/_/\_\ .__/ \__,_|\__|
 #                               |_| XML parser
 #
-# Copyright (c) 2021-2023 Sebastian Pipping <sebastian@pipping.org>
+# Copyright (c) 2021-2024 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2023      Joyce Brum <joycebrum@google.com>
 # Licensed under the MIT license:
 #
@@ -35,6 +35,7 @@ on:
   push:
   schedule:
     - cron: '0 2 * * 5'  # Every Friday at 2am
+  workflow_dispatch:
 
 permissions:
   contents: read
@@ -44,7 +45,7 @@ jobs:
     name: Ensure well-formed and valid XML
     runs-on: ubuntu-20.04
     steps:
-    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
+    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
 
     - name: Install build dependencies
       run: |-
diff --git a/Brewfile b/Brewfile
index 740aab51..8f1ae516 100644
--- a/Brewfile
+++ b/Brewfile
@@ -1,10 +1,7 @@
 brew "autoconf"
 brew "automake"
 brew "cmake"
-brew "coreutils"
 brew "docbook2x"
-brew "dos2unix"
-brew "findutils"
 brew "gcc"
 brew "gettext"
 brew "ghostscript"
diff --git a/METADATA b/METADATA
index 4d1f8ab0..f16d011a 100644
--- a/METADATA
+++ b/METADATA
@@ -3,8 +3,8 @@
 # DEPENDING ON IT IN YOUR PROJECT.
 
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update external/<absolute path to project>
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# Usage: tools/external_updater/updater.sh update external/expat
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "expat"
 description: "Expat is a stream-oriented XML parser."
@@ -16,13 +16,13 @@ third_party {
   }
   last_upgrade_date {
     year: 2024
-    month: 4
-    day: 26
+    month: 9
+    day: 18
   }
   homepage: "https://github.com/libexpat/libexpat/"
   identifier {
     type: "Git"
     value: "https://github.com/libexpat/libexpat/"
-    version: "R_2_6_2"
+    version: "R_2_6_3"
   }
 }
diff --git a/appveyor.yml b/appveyor.yml
index 22d6fdc6..8ac58020 100644
--- a/appveyor.yml
+++ b/appveyor.yml
@@ -7,7 +7,7 @@
 #                               |_| XML parser
 #
 # Copyright (c) 2017      José Gutiérrez de la Concha <jose@zeroc.com>
-# Copyright (c) 2017-2022 Sebastian Pipping <sebastian@pipping.org>
+# Copyright (c) 2017-2023 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2017      Franek Korta <fkorta@gmail.com>
 # Licensed under the MIT license:
 #
@@ -52,32 +52,6 @@ configuration: Debug
 # https://cmake.org/cmake/help/latest/manual/cmake-generators.7.html#visual-studio-generators
 environment:
   matrix:
-    # Visual Studio 2017 Win32
-    - GENERATOR: Visual Studio 15 2017
-      PLATFORM: Win32
-      EXPAT_DLL: libexpatd.dll
-      APPVEYOR_BUILD_WORKER_IMAGE: Visual Studio 2017
-
-    # Visual Studio 2017 Win32 XML_UNICODE_WCHAR_T
-    - GENERATOR: Visual Studio 15 2017
-      PLATFORM: Win32
-      CMAKE_ARGS: -DEXPAT_CHAR_TYPE=wchar_t
-      EXPAT_DLL: libexpatwd.dll
-      APPVEYOR_BUILD_WORKER_IMAGE: Visual Studio 2017
-
-    # Visual Studio 2017 x64
-    - GENERATOR: Visual Studio 15 2017 Win64
-      PLATFORM: x64
-      EXPAT_DLL: libexpatd.dll
-      APPVEYOR_BUILD_WORKER_IMAGE: Visual Studio 2017
-
-    # Visual Studio 2017 x64 XML_UNICODE_WCHAR_T
-    - GENERATOR: Visual Studio 15 2017 Win64
-      PLATFORM: x64
-      CMAKE_ARGS: -DEXPAT_CHAR_TYPE=wchar_t
-      EXPAT_DLL: libexpatwd.dll
-      APPVEYOR_BUILD_WORKER_IMAGE: Visual Studio 2017
-
     # Visual Studio 2019 Win32
     - GENERATOR: Visual Studio 16 2019
       PLATFORM: Win32
diff --git a/expat/.gitignore b/expat/.gitignore
index 1556d70a..feb4b2fa 100644
--- a/expat/.gitignore
+++ b/expat/.gitignore
@@ -1,6 +1,5 @@
 /autom4te.cache/
 /cmake-build-debug/
-m4/
 CMakeFiles/
 Testing/
 aclocal.m4
@@ -39,3 +38,4 @@ source__R*
 /stamp-h1
 /libexpat*.dll
 /changelog
+*~
diff --git a/expat/CMake.README b/expat/CMake.README
index 5d5f43e8..6e7e852f 100644
--- a/expat/CMake.README
+++ b/expat/CMake.README
@@ -3,25 +3,25 @@
 The cmake based buildsystem for expat works on Windows (cygwin, mingw, Visual
 Studio) and should work on all other platform cmake supports.
 
-Assuming ~/expat-2.6.2 is the source directory of expat, add a subdirectory
+Assuming ~/expat-2.6.3 is the source directory of expat, add a subdirectory
 build and change into that directory:
-~/expat-2.6.2$ mkdir build && cd build
-~/expat-2.6.2/build$
+~/expat-2.6.3$ mkdir build && cd build
+~/expat-2.6.3/build$
 
 From that directory, call cmake first, then call make, make test and
 make install in the usual way:
-~/expat-2.6.2/build$ cmake ..
+~/expat-2.6.3/build$ cmake ..
 -- The C compiler identification is GNU
 -- The CXX compiler identification is GNU
 ....
 -- Configuring done
 -- Generating done
--- Build files have been written to: /home/patrick/expat-2.6.2/build
+-- Build files have been written to: /home/patrick/expat-2.6.3/build
 
 If you want to specify the install location for your files, append
 -DCMAKE_INSTALL_PREFIX=/your/install/path to the cmake call.
 
-~/expat-2.6.2/build$ make && make test && make install
+~/expat-2.6.3/build$ make && make test && make install
 Scanning dependencies of target expat
 [  5%] Building C object CMakeFiles/expat.dir/lib/xmlparse.c.o
 [ 11%] Building C object CMakeFiles/expat.dir/lib/xmlrole.c.o
@@ -36,7 +36,7 @@ Visual Studio Command Prompt or when using mingw, you must open a cmd.exe and
 make sure that gcc can be called. On Windows, you also might want to specify a
 special Generator for CMake:
 for Visual Studio builds do:
-cmake .. -G "Visual Studio 15 2017" && msbuild /m expat.sln
+cmake .. -G "Visual Studio 16 2019" && msbuild /m expat.sln
 for mingw builds do:
 cmake .. -G "MinGW Makefiles" -DCMAKE_INSTALL_PREFIX=D:\expat-install
     && gmake && gmake install
diff --git a/expat/CMakeLists.txt b/expat/CMakeLists.txt
index ff081550..b2055c18 100644
--- a/expat/CMakeLists.txt
+++ b/expat/CMakeLists.txt
@@ -38,7 +38,7 @@ cmake_minimum_required(VERSION 3.5.0)
 
 project(expat
     VERSION
-        2.6.2
+        2.6.3
     LANGUAGES
         C
 )
@@ -201,8 +201,8 @@ if(MSVC)
     # - https://sourceforge.net/p/predef/wiki/Compilers/
     # - https://en.wikipedia.org/wiki/Microsoft_Visual_Studio#History
     set(_EXPAT_MSVC_REQUIRED_INT 1800)  # i.e. 12.0/2013/1800; see PR #426
-    set(_EXPAT_MSVC_SUPPORTED_INT 1910)
-    set(_EXPAT_MSVC_SUPPORTED_DISPLAY "Visual Studio 15.0/2017/${_EXPAT_MSVC_SUPPORTED_INT}")
+    set(_EXPAT_MSVC_SUPPORTED_INT 1920)
+    set(_EXPAT_MSVC_SUPPORTED_DISPLAY "Visual Studio 16.0/2019/${_EXPAT_MSVC_SUPPORTED_INT}")
 
     if(MSVC_VERSION VERSION_LESS ${_EXPAT_MSVC_SUPPORTED_INT})
         if(MSVC_VERSION VERSION_LESS ${_EXPAT_MSVC_REQUIRED_INT})
@@ -466,7 +466,7 @@ foreach(build_type_upper
 endforeach()
 
 set(LIBCURRENT 10)  # sync
-set(LIBREVISION 2)  # with
+set(LIBREVISION 3)  # with
 set(LIBAGE 9)       # configure.ac!
 math(EXPR LIBCURRENT_MINUS_AGE "${LIBCURRENT} - ${LIBAGE}")
 
diff --git a/expat/Changes b/expat/Changes
index 52b366d5..c1d22efa 100644
--- a/expat/Changes
+++ b/expat/Changes
@@ -30,6 +30,60 @@
 !! THANK YOU!                        Sebastian Pipping -- Berlin, 2024-03-09 !!
 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 
+Release 2.6.3 Wed September 4 2024
+        Security fixes:
+       #887 #890  CVE-2024-45490 -- Calling function XML_ParseBuffer with
+                    len < 0 without noticing and then calling XML_GetBuffer
+                    will have XML_ParseBuffer fail to recognize the problem
+                    and XML_GetBuffer corrupt memory.
+                    With the fix, XML_ParseBuffer now complains with error
+                    XML_ERROR_INVALID_ARGUMENT just like sibling XML_Parse
+                    has been doing since Expat 2.2.1, and now documented.
+                    Impact is denial of service to potentially artitrary code
+                    execution.
+       #888 #891  CVE-2024-45491 -- Internal function dtdCopy can have an
+                    integer overflow for nDefaultAtts on 32-bit platforms
+                    (where UINT_MAX equals SIZE_MAX).
+                    Impact is denial of service to potentially artitrary code
+                    execution.
+       #889 #892  CVE-2024-45492 -- Internal function nextScaffoldPart can
+                    have an integer overflow for m_groupSize on 32-bit
+                    platforms (where UINT_MAX equals SIZE_MAX).
+                    Impact is denial of service to potentially artitrary code
+                    execution.
+
+        Other changes:
+       #851 #879  Autotools: Sync CMake templates with CMake 3.28
+            #853  Autotools: Always provide path to find(1) for portability
+            #861  Autotools: Ensure that the m4 directory always exists.
+            #870  Autotools: Simplify handling of SIZEOF_VOID_P
+            #869  Autotools: Support non-GNU sed
+            #856  Autotools|CMake: Fix main() to main(void)
+            #865  Autotools|CMake: Fix compile tests for HAVE_SYSCALL_GETRANDOM
+            #863  Autotools|CMake: Stop requiring dos2unix
+       #854 #855  CMake: Fix check for symbols size_t and off_t
+            #864  docs|tests: Convert README to Markdown and update
+            #741  Windows: Drop support for Visual Studio <=15.0/2017
+            #886  Drop needless XML_DTD guards around is_param access
+            #885  Fix typo in a code comment
+       #894 #896  Version info bumped from 10:2:9 (libexpat*.so.1.9.2)
+                    to 10:3:9 (libexpat*.so.1.9.3); see https://verbump.de/
+                    for what these numbers do
+
+        Infrastructure:
+            #880  Readme: Promote the call for help
+            #868  CI: Fix various issues
+            #849  CI: Allow triggering GitHub Actions workflows manually
+    #851 #872 ..
+       #873 #879  CI: Adapt to breaking changes in GitHub Actions
+
+        Special thanks to:
+            Alexander Bluhm
+            Berkay Eren Ürün
+            Dag-Erling Smørgrav
+            Ferenc Géczi
+            TaiYou
+
 Release 2.6.2 Wed March 13 2024
         Security fixes:
        #839 #842  CVE-2024-28757 -- Prevent billion laughs attacks with
diff --git a/expat/ConfigureChecks.cmake b/expat/ConfigureChecks.cmake
index 3fc732f0..c06b2f27 100644
--- a/expat/ConfigureChecks.cmake
+++ b/expat/ConfigureChecks.cmake
@@ -46,18 +46,25 @@ else(WORDS_BIGENDIAN)
 endif(WORDS_BIGENDIAN)
 
 if(HAVE_SYS_TYPES_H)
-    check_symbol_exists("off_t" "sys/types.h" off_t)
-    check_symbol_exists("size_t" "sys/types.h" size_t)
-else(HAVE_SYS_TYPES_H)
+    check_c_source_compiles("
+        #include <sys/types.h>
+        int main(void) {
+            const off_t offset = -123;
+            return 0;
+        }"
+        HAVE_OFF_T)
+endif()
+
+if(NOT HAVE_OFF_T)
     set(off_t "long")
-    set(size_t "unsigned")
-endif(HAVE_SYS_TYPES_H)
+endif()
 
 check_c_source_compiles("
+        #define _GNU_SOURCE
         #include <stdlib.h>  /* for NULL */
         #include <unistd.h>  /* for syscall */
         #include <sys/syscall.h>  /* for SYS_getrandom */
-        int main() {
+        int main(void) {
             syscall(SYS_getrandom, NULL, 0, 0);
             return 0;
         }"
diff --git a/expat/Makefile.am b/expat/Makefile.am
index 9c2259d2..7d8e17c2 100644
--- a/expat/Makefile.am
+++ b/expat/Makefile.am
@@ -10,6 +10,8 @@
 # Copyright (c) 2018      KangLin <kl222@126.com>
 # Copyright (c) 2022      Johnny Jazeix <jazeix@gmail.com>
 # Copyright (c) 2023      Sony Corporation / Snild Dolkow <snild@sony.com>
+# Copyright (c) 2024      Alexander Bluhm <alexander.bluhm@gmx.net>
+# Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -114,10 +116,10 @@ buildlib:
 	@echo 'ERROR: is no longer supported.  INSTEAD please:' >&2
 	@echo 'ERROR:' >&2
 	@echo 'ERROR:  * Mass-patch Makefile.am, e.g.' >&2
-	@echo 'ERROR:    # find -name Makefile.am -exec sed \' >&2
+	@echo 'ERROR:    # find . -name Makefile.am -exec sed \' >&2
 	@echo 'ERROR:          -e "s,libexpat\.la,libexpatw.la," \' >&2
 	@echo 'ERROR:          -e "s,libexpat_la,libexpatw_la," \' >&2
-	@echo 'ERROR:          -i {} +' >&2
+	@echo 'ERROR:          -i.bak {} +' >&2
 	@echo 'ERROR:' >&2
 	@echo 'ERROR:  * Run automake to re-generate Makefile.in files' >&2
 	@echo 'ERROR:' >&2
diff --git a/expat/README.md b/expat/README.md
index 3c20adbe..180a68e4 100644
--- a/expat/README.md
+++ b/expat/README.md
@@ -4,8 +4,14 @@
 [![Downloads SourceForge](https://img.shields.io/sourceforge/dt/expat?label=Downloads%20SourceForge)](https://sourceforge.net/projects/expat/files/)
 [![Downloads GitHub](https://img.shields.io/github/downloads/libexpat/libexpat/total?label=Downloads%20GitHub)](https://github.com/libexpat/libexpat/releases)
 
+> [!CAUTION]
+>
+> Expat is **understaffed** and without funding.
+> There is a [call for help with details](https://github.com/libexpat/libexpat/blob/master/expat/Changes)
+> at the top of the `Changes` file.
 
-# Expat, Release 2.6.2
+
+# Expat, Release 2.6.3
 
 This is Expat, a C99 library for parsing
 [XML 1.0 Fourth Edition](https://www.w3.org/TR/2006/REC-xml-20060816/), started by
@@ -20,7 +26,7 @@ Expat supports the following compilers:
 
 - GNU GCC >=4.5
 - LLVM Clang >=3.5
-- Microsoft Visual Studio >=15.0/2017 (rolling `${today} minus 5 years`)
+- Microsoft Visual Studio >=16.0/2019 (rolling `${today} minus 5 years`)
 
 Windows users can use the
 [`expat-win32bin-*.*.*.{exe,zip}` download](https://github.com/libexpat/libexpat/releases),
@@ -158,10 +164,10 @@ support this mode of compilation (yet):
 
 1. Mass-patch `Makefile.am` files to use `libexpatw.la` for a library name:
    <br/>
-   `find -name Makefile.am -exec sed
+   `find . -name Makefile.am -exec sed
        -e 's,libexpat\.la,libexpatw.la,'
        -e 's,libexpat_la,libexpatw_la,'
-       -i {} +`
+       -i.bak {} +`
 
 1. Run `automake` to re-write `Makefile.in` files:<br/>
    `automake`
diff --git a/expat/apply-clang-format.sh b/expat/apply-clang-format.sh
index 8d2cf938..c3012b5e 100755
--- a/expat/apply-clang-format.sh
+++ b/expat/apply-clang-format.sh
@@ -8,6 +8,7 @@
 #
 # Copyright (c) 2019-2024 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2022      Rosen Penev <rosenp@gmail.com>
+# Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -56,5 +57,5 @@ clang-format "${args[@]}" -- "${files[@]}"
 sed \
         -e 's, @$,@,' \
         -e 's,#\( \+\)cmakedefine,#cmakedefine,' \
-        -i \
+        -i.bak \
         expat_config.h.cmake
diff --git a/expat/buildconf.sh b/expat/buildconf.sh
index 5e2b3269..4e506b30 100755
--- a/expat/buildconf.sh
+++ b/expat/buildconf.sh
@@ -8,6 +8,7 @@
 #
 # Copyright (c) 2017-2022 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2018      Marco Maggi <marco.maggi-ipsu@poste.it>
+# Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -31,25 +32,4 @@
 
 set -e
 
-# File expat_config.h.in (as generated by autoheader by autoreconf) contains
-# macro SIZEOF_VOID_P which is (1) not really needed by Expat as of today and
-# (2) a problem to "multilib" systems with one shared installed
-# /usr/include/expat_config.h for two Expats with different "void *" sizes
-# installed in e.g. /usr/lib32 and /usr/lib64.  Hence we patch macro
-# SIZEOF_VOID_P out of template expat_config.h.in so that configure will
-# not put SIZEOF_VOID_P in the eventual expat_config.h.
-patch_expat_config_h_in() {
-    local filename="$1"
-    local sizeof_void_p_line_number="$(grep -F -n SIZEOF_VOID_P "${filename}" | awk -F: '{print $1}')"
-    [[ ${sizeof_void_p_line_number} =~ ^[0-9]+$ ]]  # cheap assert
-    local first_line_to_delete=$(( sizeof_void_p_line_number - 1 ))
-    local last_line_to_delete=$(( sizeof_void_p_line_number + 1 ))
-    # Note: Avoiding "sed -i" only for macOS portability.
-    local tempfile="$(mktemp)"
-    sed "${first_line_to_delete},${last_line_to_delete}d" "${filename}" > "${tempfile}"
-    mv "${tempfile}" "${filename}"
-}
-
-autoreconf --warnings=all --install --verbose "$@"
-
-patch_expat_config_h_in expat_config.h.in
+exec autoreconf --warnings=all --install --verbose "$@"
diff --git a/expat/cmake/autotools/expat-config-version.cmake.in b/expat/cmake/autotools/expat-config-version.cmake.in
index f880e638..17ab1924 100644
--- a/expat/cmake/autotools/expat-config-version.cmake.in
+++ b/expat/cmake/autotools/expat-config-version.cmake.in
@@ -53,13 +53,13 @@ endif()
 
 
 # if the installed or the using project don't have CMAKE_SIZEOF_VOID_P set, ignore it:
-if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "" OR "@ac_cv_sizeof_void_p@" STREQUAL "")
+if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "" OR "@SIZEOF_VOID_P@" STREQUAL "")
   return()
 endif()
 
 # check that the installed version has the same 32/64bit-ness as the one which is currently searching:
-if(NOT CMAKE_SIZEOF_VOID_P STREQUAL "@ac_cv_sizeof_void_p@")
-  math(EXPR installedBits "@ac_cv_sizeof_void_p@ * 8")
+if(NOT CMAKE_SIZEOF_VOID_P STREQUAL "@SIZEOF_VOID_P@")
+  math(EXPR installedBits "@SIZEOF_VOID_P@ * 8")
   set(PACKAGE_VERSION "${PACKAGE_VERSION} (${installedBits}bit)")
   set(PACKAGE_VERSION_UNSUITABLE TRUE)
 endif()
diff --git a/expat/cmake/autotools/expat.cmake b/expat/cmake/autotools/expat.cmake
index b984c794..7850358b 100644
--- a/expat/cmake/autotools/expat.cmake
+++ b/expat/cmake/autotools/expat.cmake
@@ -3,11 +3,11 @@
 if("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}" LESS 2.8)
    message(FATAL_ERROR "CMake >= 2.8.0 required")
 endif()
-if(CMAKE_VERSION VERSION_LESS "2.8.3")
-   message(FATAL_ERROR "CMake >= 2.8.3 required")
+if(CMAKE_VERSION VERSION_LESS "2.8.12")
+   message(FATAL_ERROR "CMake >= 2.8.12 required")
 endif()
 cmake_policy(PUSH)
-cmake_policy(VERSION 2.8.3...3.26)
+cmake_policy(VERSION 2.8.12...3.28)
 #----------------------------------------------------------------
 # Generated CMake target import file.
 #----------------------------------------------------------------
@@ -63,10 +63,6 @@ set_target_properties(expat::expat PROPERTIES
   INTERFACE_LINK_LIBRARIES "m"
 )
 
-if(CMAKE_VERSION VERSION_LESS 2.8.12)
-  message(FATAL_ERROR "This file relies on consumers using CMake 2.8.12 or greater.")
-endif()
-
 # Load information for each installed configuration.
 file(GLOB _cmake_config_files "${CMAKE_CURRENT_LIST_DIR}/expat-*.cmake")
 foreach(_cmake_config_file IN LISTS _cmake_config_files)
@@ -80,9 +76,12 @@ set(_IMPORT_PREFIX)
 
 # Loop over all imported files and verify that they actually exist
 foreach(_cmake_target IN LISTS _cmake_import_check_targets)
-  foreach(_cmake_file IN LISTS "_cmake_import_check_files_for_${_cmake_target}")
-    if(NOT EXISTS "${_cmake_file}")
-      message(FATAL_ERROR "The imported target \"${_cmake_target}\" references the file
+  if(CMAKE_VERSION VERSION_LESS "3.28"
+      OR NOT DEFINED _cmake_import_check_xcframework_for_${_cmake_target}
+      OR NOT IS_DIRECTORY "${_cmake_import_check_xcframework_for_${_cmake_target}}")
+    foreach(_cmake_file IN LISTS "_cmake_import_check_files_for_${_cmake_target}")
+      if(NOT EXISTS "${_cmake_file}")
+        message(FATAL_ERROR "The imported target \"${_cmake_target}\" references the file
    \"${_cmake_file}\"
 but this file does not exist.  Possible reasons include:
 * The file was deleted, renamed, or moved to another location.
@@ -91,8 +90,9 @@ but this file does not exist.  Possible reasons include:
    \"${CMAKE_CURRENT_LIST_FILE}\"
 but not all the files it references.
 ")
-    endif()
-  endforeach()
+      endif()
+    endforeach()
+  endif()
   unset(_cmake_file)
   unset("_cmake_import_check_files_for_${_cmake_target}")
 endforeach()
diff --git a/expat/configure.ac b/expat/configure.ac
index 04415e36..1a930413 100644
--- a/expat/configure.ac
+++ b/expat/configure.ac
@@ -22,6 +22,8 @@ dnl   Copyright (c) 2018      KangLin <kl222@126.com>
 dnl   Copyright (c) 2019      Mohammed Khajapasha <mohammed.khajapasha@intel.com>
 dnl   Copyright (c) 2019      Kishore Kunche <kishore.kunche@intel.com>
 dnl   Copyright (c) 2020      Jeffrey Walton <noloader@gmail.com>
+dnl   Copyright (c) 2024      Ferenc Géczi <ferenc.gm@gmail.com>
+dnl   Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 dnl   Licensed under the MIT license:
 dnl
 dnl   Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -83,7 +85,7 @@ dnl If the API changes incompatibly set LIBAGE back to 0
 dnl
 
 LIBCURRENT=10  # sync
-LIBREVISION=2  # with
+LIBREVISION=3  # with
 LIBAGE=9       # CMakeLists.txt!
 
 AC_CONFIG_HEADERS([expat_config.h])
@@ -160,7 +162,6 @@ AC_C_BIGENDIAN([AC_DEFINE([WORDS_BIGENDIAN], 1)
 AC_DEFINE_UNQUOTED([BYTEORDER], $BYTEORDER, [1234 = LILENDIAN, 4321 = BIGENDIAN])
 
 AC_C_CONST
-AC_TYPE_SIZE_T
 
 AC_ARG_WITH([xmlwf],
   [AS_HELP_STRING([--without-xmlwf], [do not build xmlwf])],
@@ -215,7 +216,7 @@ AC_LINK_IFELSE([AC_LANG_SOURCE([
     #else
     # include <stdlib.h>  /* for arc4random_buf on BSD */
     #endif
-    int main() {
+    int main(void) {
       char dummy[[123]];  // double brackets for m4
       arc4random_buf(dummy, 0U);
       return 0;
@@ -232,7 +233,7 @@ AC_LINK_IFELSE([AC_LANG_SOURCE([
        #else
        # include <stdlib.h>
        #endif
-       int main() {
+       int main(void) {
           arc4random();
           return 0;
        }
@@ -254,7 +255,7 @@ AS_IF([test "x$with_getrandom" != xno],
    AC_LINK_IFELSE([AC_LANG_SOURCE([
        #include <stdlib.h>  /* for NULL */
        #include <sys/random.h>
-       int main() {
+       int main(void) {
          return getrandom(NULL, 0U, 0U);
        }
      ])],
@@ -275,10 +276,11 @@ AS_HELP_STRING([--without-sys-getrandom],
 AS_IF([test "x$with_sys_getrandom" != xno],
   [AC_MSG_CHECKING([for syscall SYS_getrandom (Linux 3.17+)])
    AC_LINK_IFELSE([AC_LANG_SOURCE([
+       #define _GNU_SOURCE
        #include <stdlib.h>  /* for NULL */
        #include <unistd.h>  /* for syscall */
        #include <sys/syscall.h>  /* for SYS_getrandom */
-       int main() {
+       int main(void) {
          syscall(SYS_getrandom, NULL, 0, 0);
          return 0;
      }
@@ -403,7 +405,6 @@ LIBDIR_BASENAME="$(basename "${libdir}")"
 SO_MAJOR="$(expr "${LIBCURRENT}" - "${LIBAGE}")"
 SO_MINOR="${LIBAGE}"
 SO_PATCH="${LIBREVISION}"
-AC_CHECK_SIZEOF([void *])  # sets ac_cv_sizeof_void_p
 AC_SUBST([EXPAT_ATTR_INFO])
 AC_SUBST([EXPAT_DTD])
 AC_SUBST([EXPAT_LARGE_SIZE])
@@ -416,16 +417,13 @@ AC_SUBST([LIBDIR_BASENAME])
 AC_SUBST([SO_MAJOR])
 AC_SUBST([SO_MINOR])
 AC_SUBST([SO_PATCH])
-AC_SUBST([ac_cv_sizeof_void_p])
-
-dnl Protect against generating an expat_config.h that would break multilib
-AS_IF([grep -F -q SIZEOF_VOID_P "${srcdir}"/expat_config.h.in],
-  [AC_MSG_ERROR(
-    [Plain autoreconf/autoheader does not cut it,
-                  please use ./buildconf.sh or imitate its effect
-                  through other means, so that file expat_config.h.in
-                  no longer defines macro SIZEOF_VOID_P, as that would
-                  break multilib support.  Thank you.])])
+
+dnl The canonical way of doing this is AC_CHECK_SIZEOF(void *), but
+dnl that adds SIZEOF_VOID_P to expat_config.h.in, making it difficult
+dnl to have 32-bit and 64-bit versions of libexpat installed on the
+dnl same system with a single, shared copy of the header.
+AC_COMPUTE_INT(SIZEOF_VOID_P, [sizeof(void *)])
+AC_SUBST([SIZEOF_VOID_P])
 
 dnl write the Automake flags we set
 AC_SUBST([AM_CPPFLAGS])
diff --git a/expat/doc/Makefile.am b/expat/doc/Makefile.am
index 9d12923d..3bea96e9 100644
--- a/expat/doc/Makefile.am
+++ b/expat/doc/Makefile.am
@@ -9,6 +9,7 @@
 # Copyright (c) 2017-2024 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2017      Stephen Groat <stephen@groat.us>
 # Copyright (c) 2017      Joe Orton <jorton@redhat.com>
+# Copyright (c) 2024      Tomas Korbar <tkorbar@redhat.com>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
diff --git a/expat/doc/reference.html b/expat/doc/reference.html
index 5614dc34..4cfb2ce9 100644
--- a/expat/doc/reference.html
+++ b/expat/doc/reference.html
@@ -52,7 +52,7 @@
   <div>
     <h1>
       The Expat XML Parser
-      <small>Release 2.6.2</small>
+      <small>Release 2.6.3</small>
     </h1>
   </div>
 <div class="content">
@@ -319,7 +319,7 @@ directions in the next section. Otherwise if you have Microsoft's
 Developer Studio installed,
 you can use CMake to generate a <code>.sln</code> file, e.g.
 <code>
-cmake -G"Visual Studio 15 2017" -DCMAKE_BUILD_TYPE=RelWithDebInfo .
+cmake -G"Visual Studio 16 2019" -DCMAKE_BUILD_TYPE=RelWithDebInfo .
 </code>, and build Expat using <code>msbuild /m expat.sln</code> after.</p>
 
 <p>Alternatively, you may download the Win32 binary package that
@@ -1135,7 +1135,9 @@ containing part (or perhaps all) of the document. The number of bytes of s
 that are part of the document is indicated by <code>len</code>. This means
 that <code>s</code> doesn't have to be null-terminated. It also means that
 if <code>len</code> is larger than the number of bytes in the block of
-memory that <code>s</code> points at, then a memory fault is likely. The
+memory that <code>s</code> points at, then a memory fault is likely.
+Negative values for <code>len</code> are rejected since Expat 2.2.1.
+The
 <code>isFinal</code> parameter informs the parser that this is the last
 piece of the document. Frequently, the last piece is empty (i.e.
 <code>len</code> is zero.)
@@ -1183,11 +1185,17 @@ XML_ParseBuffer(XML_Parser p,
                 int isFinal);
 </pre>
 <div class="fcndef">
+<p>
 This is just like <code><a href= "#XML_Parse" >XML_Parse</a></code>,
 except in this case Expat provides the buffer.  By obtaining the
 buffer from Expat with the <code><a href= "#XML_GetBuffer"
 >XML_GetBuffer</a></code> function, the application can avoid double
 copying of the input.
+</p>
+
+<p>
+Negative values for <code>len</code> are rejected since Expat 2.6.3.
+</p>
 </div>
 
 <h4 id="XML_GetBuffer">XML_GetBuffer</h4>
diff --git a/expat/doc/xmlwf.xml b/expat/doc/xmlwf.xml
index fd77f844..10b29782 100644
--- a/expat/doc/xmlwf.xml
+++ b/expat/doc/xmlwf.xml
@@ -21,7 +21,7 @@
           "http://www.oasis-open.org/docbook/xml/4.2/docbookx.dtd" [
   <!ENTITY dhfirstname "<firstname>Scott</firstname>">
   <!ENTITY dhsurname   "<surname>Bronson</surname>">
-  <!ENTITY dhdate      "<date>March 13, 2024</date>">
+  <!ENTITY dhdate      "<date>September 4, 2024</date>">
   <!-- Please adjust this^^ date whenever cutting a new release. -->
   <!ENTITY dhsection   "<manvolnum>1</manvolnum>">
   <!ENTITY dhemail     "<email>bronson@rinspin.com</email>">
diff --git a/expat/expat_config.h.cmake b/expat/expat_config.h.cmake
index ceb9b4ec..43df67ae 100644
--- a/expat/expat_config.h.cmake
+++ b/expat/expat_config.h.cmake
@@ -119,7 +119,4 @@
 /* Define to `long' if <sys/types.h> does not define. */
 #cmakedefine off_t @off_t@
 
-/* Define to `unsigned' if <sys/types.h> does not define. */
-#cmakedefine size_t @size_t@
-
 #endif // ndef EXPAT_CONFIG_H
diff --git a/expat/fix-xmltest-log.sh b/expat/fix-xmltest-log.sh
index 7981cf3b..4739acab 100755
--- a/expat/fix-xmltest-log.sh
+++ b/expat/fix-xmltest-log.sh
@@ -7,6 +7,7 @@
 #                               |_| XML parser
 #
 # Copyright (c) 2019-2022 Sebastian Pipping <sebastian@pipping.org>
+# Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -32,10 +33,10 @@ set -e
 
 filename="${1:-tests/xmltest.log}"
 
-dos2unix "${filename}"
-
-tempfile="$(mktemp)"
-sed \
+sed -i.bak \
+        -e '# convert DOS line endings to Unix without resorting to dos2unix' \
+        -e $'s/\r//' \
+        \
         -e 's/^wine: Call .* msvcrt\.dll\._wperror, aborting$/ibm49i02.dtd: No such file or directory/' \
         \
         -e '/^wine: /d' \
@@ -46,5 +47,4 @@ sed \
         -e '/^wine client error:/d' \
         -e '/^In ibm\/invalid\/P49\/: Unhandled exception: unimplemented .\+/d' \
         \
-        "${filename}" > "${tempfile}"
-mv "${tempfile}" "${filename}"
+        "${filename}"
diff --git a/expat/gennmtab/gennmtab.c b/expat/gennmtab/gennmtab.c
index c6152cf3..d8cfecad 100644
--- a/expat/gennmtab/gennmtab.c
+++ b/expat/gennmtab/gennmtab.c
@@ -9,7 +9,7 @@
    Copyright (c) 1997-2000 Thai Open Source Software Center Ltd
    Copyright (c) 2000      Clark Cooper <coopercc@users.sourceforge.net>
    Copyright (c) 2002      Fred L. Drake, Jr. <fdrake@users.sourceforge.net>
-   Copyright (c) 2016-2017 Sebastian Pipping <sebastian@pipping.org>
+   Copyright (c) 2016-2024 Sebastian Pipping <sebastian@pipping.org>
    Licensed under the MIT license:
 
    Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -442,7 +442,7 @@ printTabs(char *tab) {
 }
 
 int
-main() {
+main(void) {
   char tab[2 * 65536];
   memset(tab, 0, 65536);
   setTab(tab, nmstrt, sizeof(nmstrt) / sizeof(nmstrt[0]));
diff --git a/expat/lib/expat.h b/expat/lib/expat.h
index c2770be3..d0d6015a 100644
--- a/expat/lib/expat.h
+++ b/expat/lib/expat.h
@@ -1066,7 +1066,7 @@ XML_SetReparseDeferralEnabled(XML_Parser parser, XML_Bool enabled);
 */
 #define XML_MAJOR_VERSION 2
 #define XML_MINOR_VERSION 6
-#define XML_MICRO_VERSION 2
+#define XML_MICRO_VERSION 3
 
 #ifdef __cplusplus
 }
diff --git a/expat/lib/siphash.h b/expat/lib/siphash.h
index a1ed99e6..04f6f745 100644
--- a/expat/lib/siphash.h
+++ b/expat/lib/siphash.h
@@ -126,8 +126,7 @@
    | ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40)                   \
    | ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))
 
-#define SIPHASH_INITIALIZER                                                    \
-  { 0, 0, 0, 0, {0}, 0, 0 }
+#define SIPHASH_INITIALIZER {0, 0, 0, 0, {0}, 0, 0}
 
 struct siphash {
   uint64_t v0, v1, v2, v3;
diff --git a/expat/lib/xmlparse.c b/expat/lib/xmlparse.c
index 2951fec7..d9285b21 100644
--- a/expat/lib/xmlparse.c
+++ b/expat/lib/xmlparse.c
@@ -1,4 +1,4 @@
-/* 2a14271ad4d35e82bde8ba210b4edb7998794bcbae54deab114046a300f9639a (2.6.2+)
+/* ba4cdf9bdb534f355a9def4c9e25d20ee8e72f95b0a4d930be52e563f5080196 (2.6.3+)
                             __  __            _
                          ___\ \/ /_ __   __ _| |_
                         / _ \\  /| '_ \ / _` | __|
@@ -39,6 +39,7 @@
    Copyright (c) 2022      Sean McBride <sean@rogue-research.com>
    Copyright (c) 2023      Owain Davies <owaind@bath.edu>
    Copyright (c) 2023-2024 Sony Corporation / Snild Dolkow <snild@sony.com>
+   Copyright (c) 2024      Berkay Eren Ürün <berkay.ueruen@siemens.com>
    Licensed under the MIT license:
 
    Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -294,7 +295,7 @@ typedef struct {
    The name of the element is stored in both the document and API
    encodings.  The memory buffer 'buf' is a separately-allocated
    memory area which stores the name.  During the XML_Parse()/
-   XMLParseBuffer() when the element is open, the memory for the 'raw'
+   XML_ParseBuffer() when the element is open, the memory for the 'raw'
    version of the name (in the document encoding) is shared with the
    document buffer.  If the element is open across calls to
    XML_Parse()/XML_ParseBuffer(), the buffer is re-allocated to
@@ -2038,6 +2039,12 @@ XML_ParseBuffer(XML_Parser parser, int len, int isFinal) {
 
   if (parser == NULL)
     return XML_STATUS_ERROR;
+
+  if (len < 0) {
+    parser->m_errorCode = XML_ERROR_INVALID_ARGUMENT;
+    return XML_STATUS_ERROR;
+  }
+
   switch (parser->m_parsingStatus.parsing) {
   case XML_SUSPENDED:
     parser->m_errorCode = XML_ERROR_SUSPENDED;
@@ -5846,18 +5853,17 @@ processInternalEntity(XML_Parser parser, ENTITY *entity, XML_Bool betweenDecl) {
   /* Set a safe default value in case 'next' does not get set */
   next = textStart;
 
-#ifdef XML_DTD
   if (entity->is_param) {
     int tok
         = XmlPrologTok(parser->m_internalEncoding, textStart, textEnd, &next);
     result = doProlog(parser, parser->m_internalEncoding, textStart, textEnd,
                       tok, next, &next, XML_FALSE, XML_FALSE,
                       XML_ACCOUNT_ENTITY_EXPANSION);
-  } else
-#endif /* XML_DTD */
+  } else {
     result = doContent(parser, parser->m_tagLevel, parser->m_internalEncoding,
                        textStart, textEnd, &next, XML_FALSE,
                        XML_ACCOUNT_ENTITY_EXPANSION);
+  }
 
   if (result == XML_ERROR_NONE) {
     if (textEnd != next && parser->m_parsingStatus.parsing == XML_SUSPENDED) {
@@ -5894,18 +5900,17 @@ internalEntityProcessor(XML_Parser parser, const char *s, const char *end,
   /* Set a safe default value in case 'next' does not get set */
   next = textStart;
 
-#ifdef XML_DTD
   if (entity->is_param) {
     int tok
         = XmlPrologTok(parser->m_internalEncoding, textStart, textEnd, &next);
     result = doProlog(parser, parser->m_internalEncoding, textStart, textEnd,
                       tok, next, &next, XML_FALSE, XML_TRUE,
                       XML_ACCOUNT_ENTITY_EXPANSION);
-  } else
-#endif /* XML_DTD */
+  } else {
     result = doContent(parser, openEntity->startTagLevel,
                        parser->m_internalEncoding, textStart, textEnd, &next,
                        XML_FALSE, XML_ACCOUNT_ENTITY_EXPANSION);
+  }
 
   if (result != XML_ERROR_NONE)
     return result;
@@ -5932,7 +5937,6 @@ internalEntityProcessor(XML_Parser parser, const char *s, const char *end,
     return XML_ERROR_NONE;
   }
 
-#ifdef XML_DTD
   if (entity->is_param) {
     int tok;
     parser->m_processor = prologProcessor;
@@ -5940,9 +5944,7 @@ internalEntityProcessor(XML_Parser parser, const char *s, const char *end,
     return doProlog(parser, parser->m_encoding, s, end, tok, next, nextPtr,
                     (XML_Bool)! parser->m_parsingStatus.finalBuffer, XML_TRUE,
                     XML_ACCOUNT_DIRECT);
-  } else
-#endif /* XML_DTD */
-  {
+  } else {
     parser->m_processor = contentProcessor;
     /* see externalEntityContentProcessor vs contentProcessor */
     result = doContent(parser, parser->m_parentParser ? 1 : 0,
@@ -7016,6 +7018,16 @@ dtdCopy(XML_Parser oldParser, DTD *newDtd, const DTD *oldDtd,
     if (! newE)
       return 0;
     if (oldE->nDefaultAtts) {
+      /* Detect and prevent integer overflow.
+       * The preprocessor guard addresses the "always false" warning
+       * from -Wtype-limits on platforms where
+       * sizeof(int) < sizeof(size_t), e.g. on x86_64. */
+#if UINT_MAX >= SIZE_MAX
+      if ((size_t)oldE->nDefaultAtts
+          > ((size_t)(-1) / sizeof(DEFAULT_ATTRIBUTE))) {
+        return 0;
+      }
+#endif
       newE->defaultAtts
           = ms->malloc_fcn(oldE->nDefaultAtts * sizeof(DEFAULT_ATTRIBUTE));
       if (! newE->defaultAtts) {
@@ -7558,6 +7570,15 @@ nextScaffoldPart(XML_Parser parser) {
   int next;
 
   if (! dtd->scaffIndex) {
+    /* Detect and prevent integer overflow.
+     * The preprocessor guard addresses the "always false" warning
+     * from -Wtype-limits on platforms where
+     * sizeof(unsigned int) < sizeof(size_t), e.g. on x86_64. */
+#if UINT_MAX >= SIZE_MAX
+    if (parser->m_groupSize > ((size_t)(-1) / sizeof(int))) {
+      return -1;
+    }
+#endif
     dtd->scaffIndex = (int *)MALLOC(parser, parser->m_groupSize * sizeof(int));
     if (! dtd->scaffIndex)
       return -1;
diff --git a/expat/m4/.gitignore b/expat/m4/.gitignore
new file mode 100644
index 00000000..f0636865
--- /dev/null
+++ b/expat/m4/.gitignore
@@ -0,0 +1 @@
+/*.m4
diff --git a/expat/qa.sh b/expat/qa.sh
index a11a1bfa..98bde15d 100755
--- a/expat/qa.sh
+++ b/expat/qa.sh
@@ -9,6 +9,7 @@
 # Copyright (c) 2016-2023 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2019      Philippe Antoine <contact@catenacyber.fr>
 # Copyright (c) 2019      Hanno Böck <hanno@gentoo.org>
+# Copyright (c) 2024      Alexander Bluhm <alexander.bluhm@gmx.net>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -192,7 +193,7 @@ run_processor() {
         local DOT_FORMAT="${DOT_FORMAT:-svg}"
         local o="callgraph.${DOT_FORMAT}"
         ANNOUNCE "egypt ...... | dot ...... > ${o}"
-        find -name '*.expand' \
+        find . -name '*.expand' \
                 | sort \
                 | xargs -r egypt \
                 | unflatten -c 20 \
@@ -209,7 +210,7 @@ run_processor() {
         )
         done
 
-        RUN find -name '*.gcov' | sort
+        RUN find . -name '*.gcov' | sort
         ;;
     esac
 }
diff --git a/expat/tests/Makefile.am b/expat/tests/Makefile.am
index c38c4309..d25376be 100644
--- a/expat/tests/Makefile.am
+++ b/expat/tests/Makefile.am
@@ -9,6 +9,7 @@
 # Copyright (c) 2017-2024 Sebastian Pipping <sebastian@pipping.org>
 # Copyright (c) 2017-2022 Rhodri James <rhodri@wildebeest.org.uk>
 # Copyright (c) 2020      Jeffrey Walton <noloader@gmail.com>
+# Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 # Licensed under the MIT license:
 #
 # Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -92,7 +93,7 @@ EXTRA_DIST = \
     structdata.h \
     minicheck.h \
     memcheck.h \
-    README.txt \
+    README.md \
     udiffer.py \
     xmltest.log.expected \
     xmltest.sh
diff --git a/expat/tests/README.md b/expat/tests/README.md
new file mode 100644
index 00000000..010ca95e
--- /dev/null
+++ b/expat/tests/README.md
@@ -0,0 +1,11 @@
+This directory contains the test suite for Expat.  The tests provide
+general unit testing and regression coverage.  The tests are not
+expected to be useful examples of Expat usage; see the
+[examples](../examples) directory for that.
+
+The Expat tests use a partial internal implementation of the
+[Check](https://libcheck.github.io/check/) unit testing framework for
+C.
+
+Expat must be built and, on some platforms, installed, before the
+tests can be run.
diff --git a/expat/tests/README.txt b/expat/tests/README.txt
deleted file mode 100644
index 30e1d4da..00000000
--- a/expat/tests/README.txt
+++ /dev/null
@@ -1,13 +0,0 @@
-This directory contains the (fledgling) test suite for Expat.  The
-tests provide general unit testing and regression coverage.  The tests
-are not expected to be useful examples of Expat usage; see the
-examples/ directory for that.
-
-The Expat tests use a partial internal implementation of the "Check"
-unit testing framework for C. More information on Check can be found at:
-
-        http://check.sourceforge.net/
-
-Expat must be built and, depending on platform, must be installed, before "make check" can be executed.
-
-This test suite can all change in a later version.
diff --git a/expat/tests/basic_tests.c b/expat/tests/basic_tests.c
index 91c8dd7a..0d97b109 100644
--- a/expat/tests/basic_tests.c
+++ b/expat/tests/basic_tests.c
@@ -2804,6 +2804,61 @@ START_TEST(test_empty_parse) {
 }
 END_TEST
 
+/* Test XML_Parse for len < 0 */
+START_TEST(test_negative_len_parse) {
+  const char *const doc = "<root/>";
+  for (int isFinal = 0; isFinal < 2; isFinal++) {
+    set_subtest("isFinal=%d", isFinal);
+
+    XML_Parser parser = XML_ParserCreate(NULL);
+
+    if (XML_GetErrorCode(parser) != XML_ERROR_NONE)
+      fail("There was not supposed to be any initial parse error.");
+
+    const enum XML_Status status = XML_Parse(parser, doc, -1, isFinal);
+
+    if (status != XML_STATUS_ERROR)
+      fail("Negative len was expected to fail the parse but did not.");
+
+    if (XML_GetErrorCode(parser) != XML_ERROR_INVALID_ARGUMENT)
+      fail("Parse error does not match XML_ERROR_INVALID_ARGUMENT.");
+
+    XML_ParserFree(parser);
+  }
+}
+END_TEST
+
+/* Test XML_ParseBuffer for len < 0 */
+START_TEST(test_negative_len_parse_buffer) {
+  const char *const doc = "<root/>";
+  for (int isFinal = 0; isFinal < 2; isFinal++) {
+    set_subtest("isFinal=%d", isFinal);
+
+    XML_Parser parser = XML_ParserCreate(NULL);
+
+    if (XML_GetErrorCode(parser) != XML_ERROR_NONE)
+      fail("There was not supposed to be any initial parse error.");
+
+    void *const buffer = XML_GetBuffer(parser, (int)strlen(doc));
+
+    if (buffer == NULL)
+      fail("XML_GetBuffer failed.");
+
+    memcpy(buffer, doc, strlen(doc));
+
+    const enum XML_Status status = XML_ParseBuffer(parser, -1, isFinal);
+
+    if (status != XML_STATUS_ERROR)
+      fail("Negative len was expected to fail the parse but did not.");
+
+    if (XML_GetErrorCode(parser) != XML_ERROR_INVALID_ARGUMENT)
+      fail("Parse error does not match XML_ERROR_INVALID_ARGUMENT.");
+
+    XML_ParserFree(parser);
+  }
+}
+END_TEST
+
 /* Test odd corners of the XML_GetBuffer interface */
 static enum XML_Status
 get_feature(enum XML_FeatureEnum feature_id, long *presult) {
@@ -5955,6 +6010,8 @@ make_basic_test_case(Suite *s) {
   tcase_add_test__ifdef_xml_dtd(tc_basic, test_user_parameters);
   tcase_add_test__ifdef_xml_dtd(tc_basic, test_ext_entity_ref_parameter);
   tcase_add_test(tc_basic, test_empty_parse);
+  tcase_add_test(tc_basic, test_negative_len_parse);
+  tcase_add_test(tc_basic, test_negative_len_parse_buffer);
   tcase_add_test(tc_basic, test_get_buffer_1);
   tcase_add_test(tc_basic, test_get_buffer_2);
 #if XML_CONTEXT_BYTES > 0
diff --git a/expat/tests/misc_tests.c b/expat/tests/misc_tests.c
index ffde0563..2ee9320b 100644
--- a/expat/tests/misc_tests.c
+++ b/expat/tests/misc_tests.c
@@ -208,7 +208,7 @@ START_TEST(test_misc_version) {
   if (! versions_equal(&read_version, &parsed_version))
     fail("Version mismatch");
 
-  if (xcstrcmp(version_text, XCS("expat_2.6.2"))) /* needs bump on releases */
+  if (xcstrcmp(version_text, XCS("expat_2.6.3"))) /* needs bump on releases */
     fail("XML_*_VERSION in expat.h out of sync?\n");
 }
 END_TEST
diff --git a/expat/win32/README.txt b/expat/win32/README.txt
index 1d725f38..7a8a0df6 100644
--- a/expat/win32/README.txt
+++ b/expat/win32/README.txt
@@ -5,13 +5,13 @@ Expat can be built on Windows in two ways:
 * Cygwin:
   This follows the Unix build procedures.
 
-* MS Visual Studio 2013, 2015 and 2017:
+* MS Visual Studio 2019 and 2022:
   Use CMake to generate a solution file for Visual Studio, then use msbuild
   to compile.  For example:
 
   md build
   cd build
-  cmake -G"Visual Studio 15 2017" -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
+  cmake -G"Visual Studio 16 2019" -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
   msbuild /m expat.sln
 
 * All MS C/C++ compilers:
diff --git a/expat/win32/build_expat_iss.bat b/expat/win32/build_expat_iss.bat
index 53e4351f..aea73489 100644
--- a/expat/win32/build_expat_iss.bat
+++ b/expat/win32/build_expat_iss.bat
@@ -7,7 +7,7 @@ REM                     |  __//  \| |_) | (_| | |_
 REM                      \___/_/\_\ .__/ \__,_|\__|
 REM                               |_| XML parser
 REM
-REM Copyright (c) 2019-2021 Sebastian Pipping <sebastian@pipping.org>
+REM Copyright (c) 2019-2024 Sebastian Pipping <sebastian@pipping.org>
 REM Licensed under the MIT license:
 REM
 REM Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -29,7 +29,7 @@ REM DAMAGES OR  OTHER LIABILITY, WHETHER  IN AN  ACTION OF CONTRACT,  TORT OR
 REM OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 REM USE OR OTHER DEALINGS IN THE SOFTWARE.
 
-SET GENERATOR=Visual Studio 15 2017
+SET GENERATOR=Visual Studio 16 2019
 
 REM Read by msbuild!
 SET CONFIGURATION=RelWithDebInfo
@@ -43,7 +43,7 @@ MD %BINDIR% || EXIT /b 1
 
 MD build_shared_char || EXIT /b 1
 CD build_shared_char || EXIT /b 1
-    cmake -G"%GENERATOR%" -DCMAKE_BUILD_TYPE=%CONFIGURATION% -DEXPAT_WARNINGS_AS_ERRORS=ON -DEXPAT_MSVC_STATIC_CRT=ON -DEXPAT_BUILD_EXAMPLES=OFF -DEXPAT_BUILD_TESTS=OFF -DEXPAT_BUILD_TOOLS=OFF .. || EXIT /b 1
+    cmake -A Win32 -G"%GENERATOR%" -DCMAKE_BUILD_TYPE=%CONFIGURATION% -DEXPAT_WARNINGS_AS_ERRORS=ON -DEXPAT_MSVC_STATIC_CRT=ON -DEXPAT_BUILD_EXAMPLES=OFF -DEXPAT_BUILD_TESTS=OFF -DEXPAT_BUILD_TOOLS=OFF .. || EXIT /b 1
     msbuild /m expat.sln || EXIT /b 1
     DIR %CONFIGURATION% || EXIT /b 1
     CD .. || EXIT /b 1
@@ -53,7 +53,7 @@ COPY build_shared_char\%CONFIGURATION%\libexpat.lib %BINDIR%\ || EXIT /b 1
 
 MD build_static_char || EXIT /b 1
 CD build_static_char || EXIT /b 1
-    cmake -G"%GENERATOR%" -DCMAKE_BUILD_TYPE=%CONFIGURATION% -DEXPAT_WARNINGS_AS_ERRORS=ON -DEXPAT_MSVC_STATIC_CRT=ON -DEXPAT_BUILD_EXAMPLES=OFF -DEXPAT_BUILD_TESTS=OFF -DEXPAT_SHARED_LIBS=OFF .. || EXIT /b 1
+    cmake -A Win32 -G"%GENERATOR%" -DCMAKE_BUILD_TYPE=%CONFIGURATION% -DEXPAT_WARNINGS_AS_ERRORS=ON -DEXPAT_MSVC_STATIC_CRT=ON -DEXPAT_BUILD_EXAMPLES=OFF -DEXPAT_BUILD_TESTS=OFF -DEXPAT_SHARED_LIBS=OFF .. || EXIT /b 1
     msbuild /m expat.sln || EXIT /b 1
     DIR %CONFIGURATION% || EXIT /b 1
     CD .. || EXIT /b 1
@@ -63,7 +63,7 @@ COPY build_static_char\xmlwf\%CONFIGURATION%\xmlwf.exe %BINDIR%\ || EXIT /b 1
 
 MD build_shared_wchar_t || EXIT /b 1
 CD build_shared_wchar_t || EXIT /b 1
-    cmake -G"%GENERATOR%" -DCMAKE_BUILD_TYPE=%CONFIGURATION% -DEXPAT_WARNINGS_AS_ERRORS=ON -DEXPAT_MSVC_STATIC_CRT=ON -DEXPAT_BUILD_EXAMPLES=OFF -DEXPAT_BUILD_TESTS=OFF -DEXPAT_BUILD_TOOLS=OFF -DEXPAT_CHAR_TYPE=wchar_t .. || EXIT /b 1
+    cmake -A Win32 -G"%GENERATOR%" -DCMAKE_BUILD_TYPE=%CONFIGURATION% -DEXPAT_WARNINGS_AS_ERRORS=ON -DEXPAT_MSVC_STATIC_CRT=ON -DEXPAT_BUILD_EXAMPLES=OFF -DEXPAT_BUILD_TESTS=OFF -DEXPAT_BUILD_TOOLS=OFF -DEXPAT_CHAR_TYPE=wchar_t .. || EXIT /b 1
     msbuild /m expat.sln || EXIT /b 1
     DIR %CONFIGURATION% || EXIT /b 1
     CD .. || EXIT /b 1
@@ -73,7 +73,7 @@ COPY build_shared_wchar_t\%CONFIGURATION%\libexpatw.lib %BINDIR%\ || EXIT /b 1
 
 MD build_static_wchar_t || EXIT /b 1
 CD build_static_wchar_t || EXIT /b 1
-    cmake -G"%GENERATOR%" -DCMAKE_BUILD_TYPE=%CONFIGURATION% -DEXPAT_WARNINGS_AS_ERRORS=ON -DEXPAT_MSVC_STATIC_CRT=ON -DEXPAT_BUILD_EXAMPLES=OFF -DEXPAT_BUILD_TESTS=OFF -DEXPAT_BUILD_TOOLS=OFF -DEXPAT_SHARED_LIBS=OFF -DEXPAT_CHAR_TYPE=wchar_t .. || EXIT /b 1
+    cmake -A Win32 -G"%GENERATOR%" -DCMAKE_BUILD_TYPE=%CONFIGURATION% -DEXPAT_WARNINGS_AS_ERRORS=ON -DEXPAT_MSVC_STATIC_CRT=ON -DEXPAT_BUILD_EXAMPLES=OFF -DEXPAT_BUILD_TESTS=OFF -DEXPAT_BUILD_TOOLS=OFF -DEXPAT_SHARED_LIBS=OFF -DEXPAT_CHAR_TYPE=wchar_t .. || EXIT /b 1
     msbuild /m expat.sln || EXIT /b 1
     DIR %CONFIGURATION% || EXIT /b 1
     CD .. || EXIT /b 1
diff --git a/expat/win32/expat.iss b/expat/win32/expat.iss
index 2a4c87e6..23c18d14 100644
--- a/expat/win32/expat.iss
+++ b/expat/win32/expat.iss
@@ -16,6 +16,7 @@
 ; Copyright (c) 2006-2017 Karl Waclawek <karl@waclawek.net>
 ; Copyright (c) 2007-2024 Sebastian Pipping <sebastian@pipping.org>
 ; Copyright (c) 2022      Johnny Jazeix <jazeix@gmail.com>
+; Copyright (c) 2024      Dag-Erling Smørgrav <des@des.dev>
 ; Licensed under the MIT license:
 ;
 ; Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -37,7 +38,7 @@
 ; OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 ; USE OR OTHER DEALINGS IN THE SOFTWARE.
 
-#define expatVer "2.6.2"
+#define expatVer "2.6.3"
 
 [Setup]
 AppName=Expat
@@ -96,7 +97,7 @@ Flags: ignoreversion; Source: examples\*.c;                 DestDir: "{app}\Sour
 Flags: ignoreversion; Source: tests\*.c;                    DestDir: "{app}\Source\tests"
 Flags: ignoreversion; Source: tests\*.cpp;                  DestDir: "{app}\Source\tests"
 Flags: ignoreversion; Source: tests\*.h;                    DestDir: "{app}\Source\tests"
-Flags: ignoreversion; Source: tests\README.txt;             DestDir: "{app}\Source\tests"
+Flags: ignoreversion; Source: tests\README.md;              DestDir: "{app}\Source\tests"
 Flags: ignoreversion; Source: tests\benchmark\*.c;          DestDir: "{app}\Source\tests\benchmark"
 Flags: ignoreversion; Source: tests\benchmark\README.txt;   DestDir: "{app}\Source\tests\benchmark"
 Flags: ignoreversion; Source: xmlwf\*.c*;                   DestDir: "{app}\Source\xmlwf"
diff --git a/expat_config.h b/expat_config.h
index ae442231..4d816d19 100644
--- a/expat_config.h
+++ b/expat_config.h
@@ -91,7 +91,7 @@
 #define PACKAGE_NAME "expat"
 
 /* Define to the full name and version of this package. */
-#define PACKAGE_STRING "expat 2.6.2"
+#define PACKAGE_STRING "expat 2.6.3"
 
 /* Define to the one symbol short name of this package. */
 #define PACKAGE_TARNAME "expat"
@@ -100,7 +100,7 @@
 #define PACKAGE_URL ""
 
 /* Define to the version of this package. */
-#define PACKAGE_VERSION "2.6.2"
+#define PACKAGE_VERSION "2.6.3"
 
 /* Define to 1 if all of the C90 standard headers exist (not just the ones
    required in a freestanding environment). This macro is provided for
@@ -108,7 +108,7 @@
 #define STDC_HEADERS 1
 
 /* Version number of package */
-#define VERSION "2.6.2"
+#define VERSION "2.6.3"
 
 /* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
    significant byte first (like Motorola and SPARC, unlike Intel). */
@@ -150,7 +150,4 @@
 /* Define to `long int' if <sys/types.h> does not define. */
 /* #undef off_t */
 
-/* Define to `unsigned int' if <sys/types.h> does not define. */
-/* #undef size_t */
-
 #endif // ndef EXPAT_CONFIG_H
```

