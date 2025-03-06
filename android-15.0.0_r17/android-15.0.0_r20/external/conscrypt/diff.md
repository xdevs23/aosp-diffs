```diff
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
new file mode 100644
index 00000000..d7d5c096
--- /dev/null
+++ b/.github/workflows/ci.yml
@@ -0,0 +1,331 @@
+name: Continuous integration
+
+on:
+  push:
+  pull_request:
+  schedule:
+    # Run every day at midnight UTC
+    - cron: '0 0 * * *'
+
+jobs:
+  boringssl_clone:
+    # This step ensures that all builders have the same version of BoringSSL
+    runs-on: ubuntu-latest
+
+    steps:
+      - name: Clone BoringSSL repo
+        run: |
+          git clone --depth 1 --filter=blob:none --no-checkout https://github.com/google/boringssl.git "${{ runner.temp }}/boringssl"
+          echo Using BoringSSL commit: $(cd "${{ runner.temp }}/boringssl"; git rev-parse HEAD)
+
+      - name: Archive BoringSSL source
+        uses: actions/upload-artifact@v4
+        with:
+          name: boringssl-source
+          path: ${{ runner.temp }}/boringssl
+          retention-days: 1
+          include-hidden-files: true
+          if-no-files-found: error
+
+  build:
+    needs: boringssl_clone
+
+    strategy:
+      fail-fast: false
+      matrix:
+        platform: [ubuntu-latest, macos-latest, windows-latest]
+        include:
+          - platform: ubuntu-latest
+            tools_url: https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
+          - platform: macos-latest
+            tools_url: https://dl.google.com/android/repository/commandlinetools-mac-9477386_latest.zip
+          - platform: windows-latest
+            tools_url: https://dl.google.com/android/repository/commandlinetools-win-9477386_latest.zip
+
+    runs-on: ${{ matrix.platform }}
+
+    steps:
+      - name: Set up JDK 11 for toolchains
+        uses: actions/setup-java@v4
+        with:
+          distribution: 'zulu'
+          java-version: 11
+
+      - name: Set runner-specific environment variables
+        shell: bash
+        run: |
+          echo "ANDROID_HOME=${{ runner.temp }}/android-sdk" >> $GITHUB_ENV
+          echo "ANDROID_SDK_ROOT=${{ runner.temp }}/android-sdk" >> $GITHUB_ENV
+          echo "BORINGSSL_HOME=${{ runner.temp }}/boringssl" >> $GITHUB_ENV
+          echo "SDKMANAGER=${{ runner.temp }}/android-sdk/cmdline-tools/bin/sdkmanager" >> $GITHUB_ENV
+          echo "M2_REPO=${{ runner.temp }}/m2" >> $GITHUB_ENV
+
+      - uses: actions/checkout@v4
+
+      - name: Setup Linux environment
+        if: runner.os == 'Linux'
+        run: |
+          echo "CC=clang" >> $GITHUB_ENV
+          echo "CXX=clang++" >> $GITHUB_ENV
+
+          sudo dpkg --add-architecture i386
+          sudo add-apt-repository ppa:openjdk-r/ppa
+          sudo apt-get -qq update
+          sudo apt-get -qq install -y --no-install-recommends \
+            gcc-multilib \
+            g++-multilib \
+            ninja-build \
+            openjdk-11-jre-headless
+
+      - name: Setup macOS environment
+        if: runner.os == 'macOS'
+        run: |
+          brew update || echo update failed
+          brew install ninja || echo update failed
+
+      - name: install Go
+        uses: actions/setup-go@v5
+        with:
+          go-version: '1.20'
+
+      - name: Setup Windows environment
+        if: runner.os == 'Windows'
+        run: |
+          choco install nasm -y
+          choco install ninja -y
+
+      - name: Fetch BoringSSL source
+        uses: actions/download-artifact@v4
+        with:
+          name: boringssl-source
+          path: ${{ runner.temp }}/boringssl
+
+      - name: Checkout BoringSSL master branch
+        shell: bash
+        run: |
+          cd "$BORINGSSL_HOME"
+          git checkout --progress --force -B master
+
+      - name: Build BoringSSL x86 and ARM MacOS
+        if: runner.os == 'macOS'
+        env:
+          # For compatibility, but 10.15 target requires 16-byte stack alignment.
+          MACOSX_DEPLOYMENT_TARGET: 10.13
+        run: |
+          mkdir -p "$BORINGSSL_HOME/build.x86"
+          pushd "$BORINGSSL_HOME/build.x86"
+          cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES=x86_64 -GNinja ..
+          ninja
+          popd
+
+          mkdir -p "$BORINGSSL_HOME/build.arm"
+          pushd "$BORINGSSL_HOME/build.arm"
+          cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES=arm64 -GNinja ..
+          ninja
+          popd
+
+      - name: Build BoringSSL 64-bit Linux
+        if: runner.os == 'Linux'
+        run: |
+          mkdir -p "$BORINGSSL_HOME/build64"
+          pushd "$BORINGSSL_HOME/build64"
+          cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE -DCMAKE_BUILD_TYPE=Release -GNinja ..
+          ninja
+          popd
+
+      - name: Set up MSVC paths on Windows
+        if: runner.os == 'Windows'
+        uses: ilammy/msvc-dev-cmd@v1
+        with:
+            arch: x64
+
+      - name: Build BoringSSL 64-bit Windows
+        if: runner.os == 'Windows'
+        run: |
+          cd $Env:BORINGSSL_HOME
+          mkdir build64
+          pushd build64
+          cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE -DCMAKE_BUILD_TYPE=Release -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded -GNinja ..
+          ninja
+          popd
+
+      - name: Setup Android environment
+        shell: bash
+        if: runner.os == 'Linux'
+        run: |
+          cd "${{ runner.temp }}"
+          curl -L "${{ matrix.tools_url }}" -o android-tools.zip
+          mkdir -p "$ANDROID_HOME"
+          unzip -q android-tools.zip -d "$ANDROID_HOME"
+          yes | "$SDKMANAGER" --sdk_root="$ANDROID_HOME" --licenses || true
+          "$SDKMANAGER" --sdk_root="$ANDROID_HOME" tools
+          "$SDKMANAGER" --sdk_root="$ANDROID_HOME" platform-tools
+          "$SDKMANAGER" --sdk_root="$ANDROID_HOME" 'build-tools;30.0.3'
+          "$SDKMANAGER" --sdk_root="$ANDROID_HOME" 'platforms;android-26'
+          "$SDKMANAGER" --sdk_root="$ANDROID_HOME" 'extras;android;m2repository'
+          "$SDKMANAGER" --sdk_root="$ANDROID_HOME" 'ndk;25.2.9519653'
+          "$SDKMANAGER" --sdk_root="$ANDROID_HOME" 'cmake;3.22.1'
+
+      - name: Build with Gradle
+        shell: bash
+        run: ./gradlew assemble -PcheckErrorQueue
+
+      - name: Test with Gradle
+        shell: bash
+        run: ./gradlew test -PcheckErrorQueue
+
+      - name: Other checks with Gradle
+        shell: bash
+        run: ./gradlew check -PcheckErrorQueue
+
+      - name: Publish to local Maven repo
+        shell: bash
+        run: ./gradlew publishToMavenLocal -Dmaven.repo.local="$M2_REPO"
+
+      - name: Upload Maven respository
+        uses: actions/upload-artifact@v4
+        with:
+          name: m2repo-${{ runner.os }}
+          path: ${{ runner.temp }}/m2
+
+      - name: Build test JAR with dependencies
+        if: runner.os == 'Linux'
+        shell: bash
+        run: ./gradlew :conscrypt-openjdk:testJar -PcheckErrorQueue
+
+      - name: Upload test JAR with dependencies
+        if: runner.os == 'Linux'
+        uses: actions/upload-artifact@v4
+        with:
+          name: testjar
+          path: openjdk/build/libs/conscrypt-openjdk-*-tests.jar
+          if-no-files-found: error
+
+  uberjar:
+    needs: build
+
+    runs-on: ubuntu-latest
+
+    steps:
+      - uses: actions/checkout@v4
+
+      - name: Set runner-specific environment variables
+        shell: bash
+        run: |
+          echo "M2_REPO=${{ runner.temp }}/m2" >> $GITHUB_ENV
+          echo "BORINGSSL_HOME=${{ runner.temp }}/boringssl" >> $GITHUB_ENV
+
+      - name: Fetch BoringSSL source
+        uses: actions/download-artifact@v4
+        with:
+          name: boringssl-source
+          path: ${{ runner.temp }}/boringssl
+
+      - name: Make fake BoringSSL directories
+        shell: bash
+        run: |
+          # TODO: remove this when the check is only performed when building.
+          # BoringSSL is not needed during the UberJAR build, but the
+          # assertion to check happens regardless of whether the project
+          # needs it.
+          mkdir -p "${{ runner.temp }}/boringssl/build64"
+          mkdir -p "${{ runner.temp }}/boringssl/include"
+
+      - name: Download Maven repository for Linux
+        uses: actions/download-artifact@v4
+        with:
+          name: m2repo-Linux
+          path: ${{ runner.temp }}/m2
+
+      - name: Download Maven repository for MacOS
+        uses: actions/download-artifact@v4
+        with:
+          name: m2repo-macOS
+          path: ${{ runner.temp }}/m2
+
+      - name: Download Maven repository for Windows
+        uses: actions/download-artifact@v4
+        with:
+          name: m2repo-Windows
+          path: ${{ runner.temp }}/m2
+
+      - name: Build UberJAR with Gradle
+        shell: bash
+        run: |
+          ./gradlew :conscrypt-openjdk-uber:build -Dorg.conscrypt.openjdk.buildUberJar=true -Dmaven.repo.local="$M2_REPO"
+
+      - name: Publish UberJAR to Maven Local
+        shell: bash
+        run: |
+          ./gradlew :conscrypt-openjdk-uber:publishToMavenLocal -Dorg.conscrypt.openjdk.buildUberJar=true -Dmaven.repo.local="$M2_REPO"
+
+      - name: Upload Maven respository
+        uses: actions/upload-artifact@v4
+        with:
+          name: m2repo-uber
+          path: ${{ runner.temp }}/m2
+
+  openjdk-test:
+    needs: uberjar
+
+    strategy:
+      fail-fast: false
+      matrix:
+        platform: [ubuntu-latest, macos-13, macos-latest, windows-latest]
+        java: [8, 11, 17, 21]
+        dist: ['temurin', 'zulu']
+        include:
+          - platform: ubuntu-latest
+            separator: ':'
+          - platform: macos-latest
+            separator: ':'
+          - platform: macos-13
+            separator: ':'
+          - platform: windows-latest
+            separator: ';'
+        exclude: # Not available on Github runners
+          - platform: macos-latest
+            java: 8
+            dist: 'temurin'
+
+
+    runs-on: ${{ matrix.platform }}
+
+    steps:
+      - name: Set up Java
+        uses: actions/setup-java@v4
+        with:
+          distribution: ${{ matrix.dist }}
+          java-version: ${{ matrix.java }}
+
+      - name: Download UberJAR
+        uses: actions/download-artifact@v4
+        with:
+          name: m2repo-uber
+          path: m2
+
+      - name: Download Test JAR with Dependencies
+        uses: actions/download-artifact@v4
+        with:
+          name: testjar
+          path: testjar
+
+      - name: Download JUnit runner
+        shell: bash
+        run: mvn org.apache.maven.plugins:maven-dependency-plugin:3.8.0:copy -Dartifact=org.junit.platform:junit-platform-console-standalone:1.11.2 -DoutputDirectory=. -Dmdep.stripVersion=true
+
+      - name: Run JUnit tests
+        timeout-minutes: 15
+        shell: bash
+        run: |
+          DIR="$(find m2/org/conscrypt/conscrypt-openjdk-uber -maxdepth 1 -mindepth 1 -type d -print)"
+          VERSION="${DIR##*/}"
+          TESTJAR="$(find testjar -name '*-tests.jar')"
+          java -jar junit-platform-console-standalone.jar execute -cp "$DIR/conscrypt-openjdk-uber-$VERSION.jar${{ matrix.separator }}$TESTJAR" -n='org.conscrypt.ConscryptOpenJdkSuite' --scan-classpath --reports-dir=results --fail-if-no-tests
+
+      - name: Archive test results
+        if: ${{ always() }}
+        uses: actions/upload-artifact@v4
+        with:
+          name: test-results-${{ matrix.platform }}-${{ matrix.java }}-${{ matrix.dist }}
+          path: results
diff --git a/.lgtm.yml b/.lgtm.yml
deleted file mode 100644
index 1254c9f1..00000000
--- a/.lgtm.yml
+++ /dev/null
@@ -1,21 +0,0 @@
-# This configuration file is for https://lgtm.com/ code analysis using Semmle.
-
-extraction:
-  java:
-    prepare:
-      packages:
-      - cmake
-      - golang-go
-      - ninja-build
-    after_prepare:
-    - export BORINGSSL_HOME="$LGTM_WORKSPACE/boringssl"
-    - export CXXFLAGS="-std=c++11"
-    - mkdir -p $BORINGSSL_HOME
-    - curl -Lo - https://boringssl.googlesource.com/boringssl/+archive/refs/heads/master.tar.gz | tar zxvfC - $BORINGSSL_HOME
-    - git config --global user.email "semmle-builder@example.com"
-    - git config --global user.name "Semmle Builder"
-    - ( cd $BORINGSSL_HOME ; git init ; git commit --allow-empty -m "Fake repo" )
-    - mkdir $BORINGSSL_HOME/build64 && pushd $BORINGSSL_HOME/build64
-    - cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE -DCMAKE_BUILD_TYPE=Release -DCMAKE_ASM_FLAGS=-Wa,--noexecstack -GNinja ..
-    - ninja
-    - popd
diff --git a/.travis.yml b/.travis.yml
deleted file mode 100644
index 1910355b..00000000
--- a/.travis.yml
+++ /dev/null
@@ -1,117 +0,0 @@
-language: minimal
-
-env:
-  global:
-    - BORINGSSL_HOME="$HOME/boringssl"
-    - CXXFLAGS="-std=c++11"
-    - GOOGLE_JAVA_FORMAT_VERSION=1.1
-
-cache:
-  directories:
-    - $HOME/.gradle/caches/
-    - $HOME/.gradle/wrapper/dists/
-
-matrix:
-  include:
-    ###
-    ### Linux build is the only platform that builds Android here.
-    ###
-    - os: linux
-      dist: xenial
-
-      env:
-        - ANDROID_TOOLS_URL="https://dl.google.com/android/repository/sdk-tools-linux-4333796.zip"
-        - ANDROID_HOME="$HOME/android-sdk-linux"
-        - JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
-        - JAVA11_HOME=/usr/lib/jvm/java-11-openjdk-amd64
-        - CC=clang-5.0
-        - CXX=clang++-5.0
-        - PATH="$JAVA_HOME/bin:$PATH"
-        - TERM=dumb # to stop verbose build output
-
-      before_install:
-        - curl -L $ANDROID_TOOLS_URL -o $HOME/tools.zip
-        - unzip -q $HOME/tools.zip -d $ANDROID_HOME
-        # Accept all the license agreements
-        - yes | $ANDROID_HOME/tools/bin/sdkmanager --licenses
-        # sdkmanager 26.1.1 produces an enormous amount of progress info
-        # Append tr '\r' '\n' | uniq to all the commands to suppress it
-        - $ANDROID_HOME/tools/bin/sdkmanager tools | tr '\r' '\n' | uniq
-        - $ANDROID_HOME/tools/bin/sdkmanager platform-tools | tr '\r' '\n' | uniq
-        - $ANDROID_HOME/tools/bin/sdkmanager 'build-tools;28.0.3' | tr '\r' '\n' | uniq
-        - $ANDROID_HOME/tools/bin/sdkmanager 'platforms;android-26' | tr '\r' '\n' | uniq
-        - $ANDROID_HOME/tools/bin/sdkmanager 'extras;android;m2repository' | tr '\r' '\n' | uniq
-        - $ANDROID_HOME/tools/bin/sdkmanager 'ndk;21.3.6528147' | tr '\r' '\n' | uniq
-        - $ANDROID_HOME/tools/bin/sdkmanager 'cmake;3.10.2.4988404' | tr '\r' '\n' | uniq
-        - gimme 1.13 # Needed for BoringSSL build
-        - source ~/.gimme/envs/go1.13.env
-
-      addons:
-        apt:
-          sources:
-            - llvm-toolchain-xenial-5.0
-            - openjdk-r-java
-            - ubuntu-toolchain-r-test
-          packages:
-            - clang-5.0
-            - clang-format-5.0  # for style checks
-            - g++-multilib
-            - gcc-multilib
-            - libc6-dev-i386
-            - libc6-dev:i386
-            - linux-libc-dev
-            - ninja-build
-            - openjdk-8-jdk # for building
-            - openjdk-11-jre # for running tests with Java 11
-
-before_cache:
-  - find $HOME/.gradle -name "*.lock" -exec rm {} \;
-  - rm -rf $HOME/.gradle/caches/[1-9]*
-
-before_script:
-  # Get Google Java Format
-  - curl -L https://github.com/google/google-java-format/releases/download/google-java-format-1.1/google-java-format-${GOOGLE_JAVA_FORMAT_VERSION}-all-deps.jar -o $HOME/gjf.jar
-
-  # get BoringSSL
-  - mkdir $BORINGSSL_HOME
-  - git clone --depth 1 https://boringssl.googlesource.com/boringssl $BORINGSSL_HOME
-
-  # Build BoringSSL for 64-bit
-  - mkdir $BORINGSSL_HOME/build64 && pushd $BORINGSSL_HOME/build64
-  - cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE -DCMAKE_BUILD_TYPE=Release -DCMAKE_ASM_FLAGS=-Wa,--noexecstack -GNinja ..
-  - ninja
-  - popd
-
-  # Get git-clang-format
-  - if [ ! -d "$HOME/bin" ]; then mkdir $HOME/bin; fi
-  - curl -L https://llvm.org/svn/llvm-project/cfe/trunk/tools/clang-format/git-clang-format -o $HOME/bin/git-clang-format
-  - chmod 0755 $HOME/bin/git-clang-format
-  - export PATH="$HOME/bin:$PATH"
-
-  # We need this to find the merge-base
-  - if [[ "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_PULL_REQUEST" != "false" ]];
-    then
-        git fetch origin +refs/heads/${TRAVIS_BRANCH}:refs/remotes/origin/${TRAVIS_BRANCH};
-    fi
-
-script:
-  # MacOS (BSD) xargs is missing some nice features that make this easy, so skip it.
-  - if [[ "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_PULL_REQUEST" != "false" ]];
-    then
-        git rev-list $(git merge-base HEAD origin/master)..HEAD | xargs -i git clang-format --binary=$(which clang-format-5.0) --style=file --diff {}^ {} | ( git apply; true ) && git diff --exit-code || { git reset --hard; false; }
-    fi
-  - if [[ "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_PULL_REQUEST" != "false" ]];
-    then
-        git rev-list $(git merge-base HEAD origin/master)..HEAD | xargs -i git diff-tree --no-commit-id --name-only -r {} | grep -E '\.java$' | xargs -r git ls-files | xargs -r java -jar $HOME/gjf.jar -a -i --fix-imports-only && git diff --exit-code || { git reset --hard; false; }
-    fi
-
-  - ./gradlew build -PcheckErrorQueue
-
-  # Also test with Java 11 on linux
-  - if [[ "$TRAVIS_OS_NAME" == "linux" && "$TRAVIS_PULL_REQUEST" != "false" ]];
-    then
-      ./gradlew check -DjavaExecutable64=${JAVA11_HOME}/bin/java -PcheckErrorQueue;
-    fi
-
-after_script:
-  - "[ -f android/build/outputs/lint-results-debug.xml ] && cat android/build/outputs/lint-results-debug.xml"
diff --git a/Android.bp b/Android.bp
index b5702902..44141e3a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -187,9 +187,13 @@ cc_library_host_shared {
 
 aconfig_declarations {
     name: "conscrypt-aconfig-flags",
-    package: "com.android.org.conscrypt",
+    package: "com.android.org.conscrypt.flags",
     container: "com.android.conscrypt",
     srcs: ["conscrypt.aconfig"],
+    exportable: true,
+    visibility: [
+        "//frameworks/base",
+    ],
 }
 
 java_aconfig_library {
@@ -207,7 +211,9 @@ java_aconfig_library {
     ],
     min_sdk_version: "30",
     installable: false,
-    visibility: ["//visibility:private"],
+    visibility: [
+        "//cts/tests/tests/networksecurityconfig:__subpackages__",
+    ],
 }
 
 cc_binary_host {
@@ -277,7 +283,10 @@ java_library {
         ":conscrypt_public_api_files",
     ],
 
-    libs: ["unsupportedappusage"],
+    libs: [
+        "framework-annotations-lib",
+        "unsupportedappusage",
+    ],
     static_libs: [
         "conscrypt-aconfig-flags-lib",
     ],
@@ -397,6 +406,9 @@ java_sdk_library {
     dist_stem: "conscrypt-coreplatform",
     // TODO: remove this when Conscrypt's @CorePlatformApi has been migrated to @SystemApi
     unsafe_ignore_missing_latest_api: true,
+    libs: [
+        "conscrypt-aconfig-flags-lib",
+    ],
 }
 
 // A library containing the public API stubs of the Conscrypt module.
@@ -674,6 +686,50 @@ java_library {
     ],
 }
 
+filegroup {
+    name: "conscrypt-all-test-files",
+    srcs: [
+        "repackaged/platform/src/test/java/**/*.java",
+        "repackaged/common/src/test/java//**/*.java",
+        "publicapi/src/test/java/**/*.java",
+    ],
+}
+
+filegroup {
+    name: "conscrypt-private-api-test-files",
+    srcs: [
+        "repackaged/platform/src/test/java/com/android/org/conscrypt/ct/*.java",
+        "repackaged/platform/src/test/java/com/android/org/conscrypt/CertBlocklistTest.java",
+        "repackaged/common/src/test/java/com/android/org/conscrypt/ct/*.java",
+    ],
+}
+
+filegroup {
+    name: "conscrypt-test-support-files",
+    srcs: [
+        "repackaged/testing/src/main/java/**/*.java",
+    ],
+}
+
+filegroup {
+    name: "conscrypt-xts-test-files",
+    srcs: [
+        ":conscrypt-all-test-files",
+        ":conscrypt-test-support-files",
+    ],
+    exclude_srcs: [
+        ":conscrypt-private-api-test-files",
+    ],
+}
+
+filegroup {
+    name: "conscrypt-private-test-files",
+    srcs: [
+        ":conscrypt-private-api-test-files",
+        ":conscrypt-test-support-files",
+    ],
+}
+
 // Make the conscrypt-tests library.
 java_test {
     name: "conscrypt-tests",
@@ -684,15 +740,9 @@ java_test {
     ],
     hostdex: true,
     srcs: [
-        "repackaged/platform/src/test/java/com/android/org/conscrypt/TrustedCertificateStoreTest.java",
-        "repackaged/platform/src/test/java/com/android/org/conscrypt/metrics/*.java",
-        "repackaged/common/src/test/java/com/android/org/conscrypt/*.java",
-        "repackaged/common/src/test/java/com/android/org/conscrypt/metrics/*.java",
-        "repackaged/common/src/test/java/com/android/org/conscrypt/java/**/*.java",
-        "repackaged/common/src/test/java/com/android/org/conscrypt/javax/**/*.java",
-        "repackaged/testing/src/main/java/**/*.java",
-        "publicapi/src/test/java/**/*.java",
+        ":conscrypt-xts-test-files",
     ],
+
     java_resource_dirs: [
         // Resource directories do not need repackaging.
         "openjdk/src/test/resources",
@@ -738,10 +788,7 @@ java_test {
 android_test {
     name: "ConscryptPrivateTestCases",
     srcs: [
-        "repackaged/platform/src/test/java/com/android/org/conscrypt/ct/*.java",
-        "repackaged/platform/src/test/java/com/android/org/conscrypt/CertBlocklistTest.java",
-        "repackaged/common/src/test/java/com/android/org/conscrypt/ct/*.java",
-        "repackaged/testing/src/main/java/**/*.java",
+        ":conscrypt-private-test-files",
     ],
 
     java_resource_dirs: [
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 7d08c6fc..98b7b30a 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -4,5 +4,7 @@ clang_format = true
 bpfmt = true
 
 [Hook Scripts]
-
 hidden_api_txt_checksorted_hook = ${REPO_ROOT}/tools/platform-compat/hiddenapi/checksorted_sha.sh ${PREUPLOAD_COMMIT} ${REPO_ROOT}
+
+[Builtin Hooks Options]
+clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp,java
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 59d91def..13c83304 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -30,9 +30,7 @@
           "include-filter": "android.security.cts.CertBlocklistFileTest"
         }
       ]
-    }
-  ],
-  "postsubmit": [
+    },
     {
       "name": "ConscryptPrivateTestCases"
     }
diff --git a/android-stub/src/main/java/android/util/StatsEvent.java b/android-stub/src/main/java/android/util/StatsEvent.java
index 81eacb24..928532d3 100644
--- a/android-stub/src/main/java/android/util/StatsEvent.java
+++ b/android-stub/src/main/java/android/util/StatsEvent.java
@@ -16,12 +16,8 @@
 
 package android.util;
 
-@SuppressWarnings("unused")
+@SuppressWarnings({"unused",  "DoNotCallSuggester"})
 public final class StatsEvent {
-    private StatsEvent(int atomId, StatsEvent.Buffer buffer, byte[] payload, int numBytes) {
-        throw new RuntimeException("Stub!");
-    }
-
     public static StatsEvent.Builder newBuilder() {
         throw new RuntimeException("Stub!");
     }
@@ -43,20 +39,10 @@ public final class StatsEvent {
     }
 
     private static final class Buffer {
-        private static StatsEvent.Buffer obtain() {
-            throw new RuntimeException("Stub!");
-        }
-
-        private Buffer() {
-            throw new RuntimeException("Stub!");
-        }
     }
 
+    @SuppressWarnings({"unused",  "DoNotCallSuggester"})
     public static final class Builder {
-        private Builder(StatsEvent.Buffer buffer) {
-            throw new RuntimeException("Stub!");
-        }
-
         public StatsEvent.Builder setAtomId(int atomId) {
             throw new RuntimeException("Stub!");
         }
@@ -89,10 +75,6 @@ public final class StatsEvent {
             throw new RuntimeException("Stub!");
         }
 
-        private void writeByteArray(byte[] value, byte typeId) {
-            throw new RuntimeException("Stub!");
-        }
-
         public StatsEvent.Builder writeAttributionChain(int[] uids, String[] tags) {
             throw new RuntimeException("Stub!");
         }
@@ -112,17 +94,5 @@ public final class StatsEvent {
         public StatsEvent build() {
             throw new RuntimeException("Stub!");
         }
-
-        private void writeTypeId(byte typeId) {
-            throw new RuntimeException("Stub!");
-        }
-
-        private void writeAnnotationCount() {
-            throw new RuntimeException("Stub!");
-        }
-
-        private static byte[] stringToBytes(String value) {
-            throw new RuntimeException("Stub!");
-        }
     }
 }
diff --git a/android-stub/src/main/java/dalvik/system/BlockGuard.java b/android-stub/src/main/java/dalvik/system/BlockGuard.java
index aada6690..b097905a 100644
--- a/android-stub/src/main/java/dalvik/system/BlockGuard.java
+++ b/android-stub/src/main/java/dalvik/system/BlockGuard.java
@@ -16,6 +16,7 @@
 
 package dalvik.system;
 
+@SuppressWarnings("DoNotCallSuggester")
 public class BlockGuard {
     private BlockGuard() {}
 
diff --git a/android-stub/src/main/java/dalvik/system/CloseGuard.java b/android-stub/src/main/java/dalvik/system/CloseGuard.java
index 5ae0d2af..1d9c4741 100644
--- a/android-stub/src/main/java/dalvik/system/CloseGuard.java
+++ b/android-stub/src/main/java/dalvik/system/CloseGuard.java
@@ -16,6 +16,7 @@
 
 package dalvik.system;
 
+@SuppressWarnings("DoNotCallSuggester")
 public class CloseGuard {
     private CloseGuard() {}
 
diff --git a/android/build.gradle b/android/build.gradle
index e02dcfa3..bddeb741 100644
--- a/android/build.gradle
+++ b/android/build.gradle
@@ -4,14 +4,10 @@ buildscript {
         mavenCentral()
     }
     dependencies {
-        classpath libraries.android_tools
+        classpath libs.android.tools
     }
 }
 
-plugins {
-    id 'digital.wup.android-maven-publish' version '3.6.2'
-}
-
 description = 'Conscrypt: Android'
 
 ext {
@@ -58,7 +54,8 @@ if (androidSdkInstalled) {
                     arguments '-DANDROID=True',
                             '-DANDROID_STL=c++_static',
                             "-DBORINGSSL_HOME=$boringsslHome",
-                            "-DCMAKE_CXX_STANDARD=17"
+                            "-DCMAKE_CXX_STANDARD=17",
+                            '-DCMAKE_SHARED_LINKER_FLAGS=-z max-page-size=16384'
                     cFlags '-fvisibility=hidden',
                             '-DBORINGSSL_SHARED_LIBRARY',
                             '-DBORINGSSL_IMPLEMENTATION',
@@ -66,7 +63,6 @@ if (androidSdkInstalled) {
                             '-D_XOPEN_SOURCE=700',
                             '-Wno-unused-parameter'
                     targets 'conscrypt_jni'
-                    version androidCmakeVersion
                 }
             }
             ndk {
@@ -101,6 +97,12 @@ if (androidSdkInstalled) {
         lintOptions {
             lintConfig file('lint.xml')
         }
+
+        publishing {
+            singleVariant("release") {
+                withSourcesJar()
+            }
+        }
     }
 
     configurations {
@@ -127,45 +129,43 @@ if (androidSdkInstalled) {
         compileOnly project(':conscrypt-constants')
     }
 
-    def configureJavaDocs = tasks.register("configureJavadocs") {
-        dependsOn configurations.publicApiDocs
-        doLast {
-            javadocs.options.docletpath = configurations.publicApiDocs.files as List
-        }
-    }
-
     def javadocs = tasks.register("javadocs", Javadoc) {
-        dependsOn configureJavadocs
+        dependsOn configurations.publicApiDocs
         source = android.sourceSets.main.java.srcDirs
-        classpath += project.files(android.getBootClasspath().join(File.pathSeparator)) + project(':conscrypt-android-stub').sourceSets.main.output
-        // TODO(nmittler): Fix the javadoc errors.
-        failOnError false
+        classpath += project.files(android.getBootClasspath().join(File.pathSeparator)) +
+                project(':conscrypt-android-stub').sourceSets.main.output
         options {
+            showFromPublic()
             encoding = 'UTF-8'
-            links "https://docs.oracle.com/javase/7/docs/api/"
-            // TODO(prb): Update doclet to Java 11.
-            // doclet = "org.conscrypt.doclet.FilterDoclet"
+            doclet = "org.conscrypt.doclet.FilterDoclet"
+            links = ['https://docs.oracle.com/en/java/javase/21/docs/api/java.base/']
+            docletpath = configurations.publicApiDocs.files as List
+        }
+        failOnError false
+
+        doLast {
+            copy {
+                from "$rootDir/api-doclet/src/main/resources/styles.css"
+                into "$buildDir/docs/javadoc"
+            }
         }
     }
 
     def javadocsJar = tasks.register("javadocsJar", Jar) {
         dependsOn javadocs
-        classifier = 'javadoc'
+        archiveClassifier = 'javadoc'
         from {
             javadocs.get().destinationDir
         }
     }
 
-    def sourcesJar = tasks.register("sourcesJar", Jar) {
-        classifier = 'sources'
-        from android.sourceSets.main.java.srcDirs
-    }
-
-    apply from: "$rootDir/gradle/publishing.gradle"
-    publishing.publications.maven {
-        from components.android
-        artifact sourcesJar.get()
-        artifact javadocsJar.get()
+    afterEvaluate {
+        apply from: "$rootDir/gradle/publishing.gradle"
+        publishing.publications.maven {
+            pom.packaging = 'aar'
+            from components.release
+            artifact javadocsJar.get()
+        }
     }
 } else {
     logger.warn('Android SDK has not been detected. The Android module will not be built.')
diff --git a/android/src/main/java/org/conscrypt/BaseOpenSSLSocketAdapterFactory.java b/android/src/main/java/org/conscrypt/BaseOpenSSLSocketAdapterFactory.java
index 5f3e60f6..61028074 100644
--- a/android/src/main/java/org/conscrypt/BaseOpenSSLSocketAdapterFactory.java
+++ b/android/src/main/java/org/conscrypt/BaseOpenSSLSocketAdapterFactory.java
@@ -22,6 +22,7 @@ import java.net.Socket;
 import java.net.UnknownHostException;
 import javax.net.ssl.SSLSocketFactory;
 
+@Internal
 public abstract class BaseOpenSSLSocketAdapterFactory extends SSLSocketFactory {
 
     private final OpenSSLSocketFactoryImpl delegate;
diff --git a/android/src/main/java/org/conscrypt/KitKatPlatformOpenSSLSocketAdapterFactory.java b/android/src/main/java/org/conscrypt/KitKatPlatformOpenSSLSocketAdapterFactory.java
index 93ff5e46..0ce57afc 100644
--- a/android/src/main/java/org/conscrypt/KitKatPlatformOpenSSLSocketAdapterFactory.java
+++ b/android/src/main/java/org/conscrypt/KitKatPlatformOpenSSLSocketAdapterFactory.java
@@ -23,6 +23,7 @@ import java.net.Socket;
  * A {@link javax.net.ssl.SSLSocketFactory} which creates unbundled conscrypt SSLSockets and wraps
  * them into KitKat (and newer) platform SSLSockets.
  */
+@Internal
 public class KitKatPlatformOpenSSLSocketAdapterFactory extends BaseOpenSSLSocketAdapterFactory {
 
     public KitKatPlatformOpenSSLSocketAdapterFactory(OpenSSLSocketFactoryImpl delegate) {
diff --git a/android/src/main/java/org/conscrypt/KitKatPlatformOpenSSLSocketImplAdapter.java b/android/src/main/java/org/conscrypt/KitKatPlatformOpenSSLSocketImplAdapter.java
index 980ccf88..5c46c567 100644
--- a/android/src/main/java/org/conscrypt/KitKatPlatformOpenSSLSocketImplAdapter.java
+++ b/android/src/main/java/org/conscrypt/KitKatPlatformOpenSSLSocketImplAdapter.java
@@ -41,6 +41,7 @@ import javax.net.ssl.SSLSession;
  * It delegates all public methods in Socket, SSLSocket, and OpenSSLSocket from
  * KK.
  */
+@Internal
 public class KitKatPlatformOpenSSLSocketImplAdapter
         extends com.android.org.conscrypt.OpenSSLSocketImpl {
 
@@ -432,20 +433,7 @@ public class KitKatPlatformOpenSSLSocketImplAdapter
         delegate.setHandshakeTimeout(handshakeTimeoutMilliseconds);
     }
 
-    @Override
-    @SuppressWarnings("deprecation")
-    public byte[] getNpnSelectedProtocol() {
-        return delegate.getNpnSelectedProtocol();
-    }
-
-    @Override
-    @SuppressWarnings("deprecation")
-    public void setNpnProtocols(byte[] npnProtocols) {
-        delegate.setNpnProtocols(npnProtocols);
-    }
-
     // These aren't in the Platform's OpenSSLSocketImpl but we have them to support duck typing.
-
     @SuppressWarnings("deprecation")
     public byte[] getAlpnSelectedProtocol() {
         return delegate.getAlpnSelectedProtocol();
diff --git a/android/src/main/java/org/conscrypt/Platform.java b/android/src/main/java/org/conscrypt/Platform.java
index b6f80765..3ebc1c21 100644
--- a/android/src/main/java/org/conscrypt/Platform.java
+++ b/android/src/main/java/org/conscrypt/Platform.java
@@ -16,8 +16,6 @@
 
 package org.conscrypt;
 
-import static org.conscrypt.metrics.Source.SOURCE_GMS;
-
 import android.annotation.SuppressLint;
 import android.annotation.TargetApi;
 import android.os.Binder;
@@ -25,8 +23,16 @@ import android.os.Build;
 import android.os.SystemClock;
 import android.system.Os;
 import android.util.Log;
+
 import dalvik.system.BlockGuard;
 import dalvik.system.CloseGuard;
+
+import org.conscrypt.ct.LogStore;
+import org.conscrypt.ct.Policy;
+import org.conscrypt.metrics.Source;
+import org.conscrypt.metrics.StatsLog;
+import org.conscrypt.metrics.StatsLogImpl;
+
 import java.io.FileDescriptor;
 import java.io.IOException;
 import java.lang.reflect.Constructor;
@@ -53,6 +59,7 @@ import java.util.Arrays;
 import java.util.Collection;
 import java.util.Collections;
 import java.util.List;
+
 import javax.net.ssl.SNIHostName;
 import javax.net.ssl.SNIMatcher;
 import javax.net.ssl.SNIServerName;
@@ -62,20 +69,21 @@ import javax.net.ssl.SSLSession;
 import javax.net.ssl.SSLSocketFactory;
 import javax.net.ssl.StandardConstants;
 import javax.net.ssl.X509TrustManager;
-import org.conscrypt.ct.LogStore;
-import org.conscrypt.ct.Policy;
-import org.conscrypt.metrics.CipherSuite;
-import org.conscrypt.metrics.ConscryptStatsLog;
-import org.conscrypt.metrics.Protocol;
+import org.conscrypt.NativeCrypto;
 
 /**
  * Platform-specific methods for unbundled Android.
  */
-final class Platform {
+@Internal
+final public class Platform {
     private static final String TAG = "Conscrypt";
+    static boolean DEPRECATED_TLS_V1 = true;
+    static boolean ENABLED_TLS_V1 = false;
+    private static boolean FILTERED_TLS_V1 = true;
 
     private static Method m_getCurveName;
     static {
+        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
         try {
             m_getCurveName = ECParameterSpec.class.getDeclaredMethod("getCurveName");
             m_getCurveName.setAccessible(true);
@@ -86,7 +94,12 @@ final class Platform {
 
     private Platform() {}
 
-    public static void setup() {}
+    public static void setup(boolean deprecatedTlsV1, boolean enabledTlsV1) {
+        DEPRECATED_TLS_V1 = deprecatedTlsV1;
+        ENABLED_TLS_V1 = enabledTlsV1;
+        FILTERED_TLS_V1 = !enabledTlsV1;
+        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
+    }
 
     /**
      * Default name used in the {@link java.security.Security JCE system} by {@code OpenSSLProvider}
@@ -833,7 +846,7 @@ final class Platform {
         // TODO: Use the platform version on platforms that support it
 
         String property = Security.getProperty("conscrypt.ct.enable");
-        if (property == null || !Boolean.valueOf(property)) {
+        if (property == null || !Boolean.parseBoolean(property)) {
             return false;
         }
 
@@ -847,7 +860,7 @@ final class Platform {
         for (String part : parts) {
             property = Security.getProperty(propertyName + ".*");
             if (property != null) {
-                enable = Boolean.valueOf(property);
+                enable = Boolean.parseBoolean(property);
             }
 
             propertyName = propertyName + "." + part;
@@ -855,7 +868,7 @@ final class Platform {
 
         property = Security.getProperty(propertyName);
         if (property != null) {
-            enable = Boolean.valueOf(property);
+            enable = Boolean.parseBoolean(property);
         }
         return enable;
     }
@@ -930,24 +943,21 @@ final class Platform {
         return SystemClock.elapsedRealtime();
     }
 
-    static void countTlsHandshake(
-            boolean success, String protocol, String cipherSuite, long durationLong) {
-        // Statsd classes appeared in SDK 30 and aren't available in earlier versions
-
+    public static StatsLog getStatsLog() {
         if (Build.VERSION.SDK_INT >= 30) {
-            Protocol proto = Protocol.forName(protocol);
-            CipherSuite suite = CipherSuite.forName(cipherSuite);
-            int duration = (int) durationLong;
-
-            writeStats(success, proto.getId(), suite.getId(), duration);
+            return StatsLogImpl.getInstance();
         }
+        return null;
     }
 
+    public static Source getStatsSource() {
+        return Source.SOURCE_GMS;
+    }
+
+    // Only called from StatsLogImpl, so protected by build version check above.
     @TargetApi(30)
-    private static void writeStats(
-            boolean success, int protocol, int cipherSuite, int duration) {
-        ConscryptStatsLog.write(ConscryptStatsLog.TLS_HANDSHAKE_REPORTED, success, protocol,
-                cipherSuite, duration, SOURCE_GMS, new int[] {Os.getuid(), Binder.getCallingUid()});
+    public static int[] getUids() {
+        return new int[] {Os.getuid(), Binder.getCallingUid()};
     }
 
     public static boolean isJavaxCertificateSupported() {
@@ -955,14 +965,14 @@ final class Platform {
     }
 
     public static boolean isTlsV1Deprecated() {
-        return true;
+        return DEPRECATED_TLS_V1;
     }
 
     public static boolean isTlsV1Filtered() {
-        return false;
+        return FILTERED_TLS_V1;
     }
 
     public static boolean isTlsV1Supported() {
-        return false;
+        return ENABLED_TLS_V1;
     }
 }
diff --git a/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassIndex.kt b/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassIndex.kt
index 811d13a3..054ca2d0 100644
--- a/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassIndex.kt
+++ b/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassIndex.kt
@@ -18,7 +18,6 @@ package org.conscrypt.doclet
 
 import javax.lang.model.element.Element
 import javax.lang.model.element.TypeElement
-import kotlin.streams.toList
 
 class ClassIndex {
     private val index = mutableMapOf<String, ClassInfo>()
@@ -31,27 +30,27 @@ class ClassIndex {
         put(ClassInfo(element as TypeElement))
     }
 
-    fun get(qualifiedName: String) = index[qualifiedName]
+    fun get(qualifiedName: String) = index[qualifiedName]!!
+    fun get(typeElement: TypeElement) = get(typeElement.qualifiedName.toString())
+    fun getParent(typeElement: TypeElement) = get(typeElement.enclosingElement as TypeElement)
     fun contains(qualifiedName: String) = index.containsKey(qualifiedName)
     fun find(name: String) = if (contains(name)) get(name) else findSimple(name)
     private fun findSimple(name: String) = classes().firstOrNull { it.simpleName == name } // XXX dups
 
     fun classes(): Collection<ClassInfo> = index.values
 
-    fun addVisible(elements: Set<Element>) {
-        elements
-            .filterIsInstance<TypeElement>()
-            .filter(Element::isVisibleType)
-            .forEach(::put)
-    }
+    fun addVisible(elements: Set<Element>) = elements
+        .filterIsInstance<TypeElement>()
+        .filter(Element::isVisibleType)
+        .forEach(::put)
 
-    private fun packages(): List<String> = index.values.stream()
+    private fun packages(): List<String> = index.values
         .map { it.packageName }
         .distinct()
         .sorted()
         .toList()
 
-    private fun classesForPackage(packageName: String) = index.values.stream()
+    private fun classesForPackage(packageName: String) = index.values
         .filter { it.packageName == packageName }
         .sorted()
         .toList()
@@ -62,15 +61,30 @@ class ClassIndex {
                 h2("Package $packageName", "package-name")
                 ul("class-list") {
                     classesForPackage(packageName)
-                        .forEach { c ->
-                            li {
-                                a(c.fileName, c.simpleName)
+                        .filter { !it.isInnerClass }
+                        .forEach {
+                            compose {
+                                classAndInners(it)
                             }
                         }
+                }
+            }
+        }
+    }
 
+    private fun classAndInners(classInfo: ClassInfo): String = html {
+        li {
+            a(classInfo.fileName, classInfo.simpleName)
+        }
+        val inners = classInfo.innerClasses()
+        inners.takeIf { it.isNotEmpty() }.let {
+            ul("class-list") {
+                inners.forEach {
+                    compose {
+                        classAndInners(it)
+                    }
                 }
             }
         }
     }
 }
-
diff --git a/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassInfo.kt b/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassInfo.kt
index 582885ba..ad94abe6 100644
--- a/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassInfo.kt
+++ b/api-doclet/src/main/kotlin/org/conscrypt/doclet/ClassInfo.kt
@@ -16,16 +16,72 @@
 
 package org.conscrypt.doclet
 
+import org.conscrypt.doclet.FilterDoclet.Companion.classIndex
+import java.nio.file.Paths
+import java.util.Locale
 import javax.lang.model.element.Element
 import javax.lang.model.element.ExecutableElement
+import javax.lang.model.element.Modifier
 import javax.lang.model.element.TypeElement
+import javax.lang.model.type.TypeMirror
 
 
 data class ClassInfo(val element: TypeElement) : Comparable<ClassInfo> {
     val simpleName = element.simpleName.toString()
     val qualifiedName = element.qualifiedName.toString()
     val packageName = FilterDoclet.elementUtils.getPackageOf(element).qualifiedName.toString()
-    val fileName = qualifiedName.replace('.', '/') + ".html"
+    val fileName = element.baseFileName() + ".html"
+    val isInnerClass = element.enclosingElement.isType()
+
+    fun innerClasses() = element.enclosedElements
+        .filterIsInstance<TypeElement>()
+        .filter(TypeElement::isType)
+        .map(classIndex::get)
+        .sorted()
+
+
+    private fun outerClass() = if (isInnerClass) {
+        classIndex.get(element.enclosingElement as TypeElement)
+    } else {
+        null
+    }
+
+    fun innerName(): String = if (isInnerClass) {
+        "${outerClass()?.innerName()}.$simpleName"
+    } else {
+        simpleName
+    }
+
+    private fun signature(): String {
+        val visibleModifiers = element.modifiers
+            .map(Modifier::toString)
+            .toMutableSet()
+
+        val kind = element.kind.toString().lowercase(Locale.getDefault())
+        if (kind == "interface") {
+            visibleModifiers.remove("abstract")
+        }
+
+        val modifierString = visibleModifiers.joinToString(" ")
+
+        val superName = superDisplayName(element.superclass)
+
+        val interfaces = element.interfaces
+            .joinToString(", ")
+            .prefixIfNotEmpty(" implements ")
+
+        return "$modifierString $kind ${innerName()}$superName$interfaces"
+    }
+
+    private fun superDisplayName(mirror: TypeMirror): String {
+        val name = mirror.toString()
+        return when  {
+            name == "none" || name == "java.lang.Object" -> ""
+            name.startsWith("java.lang.Enum") -> ""
+            else -> " extends $mirror "
+        }
+    }
+
 
     override fun compareTo(other: ClassInfo) = qualifiedName.compareTo(other.qualifiedName)
 
@@ -57,8 +113,13 @@ data class ClassInfo(val element: TypeElement) : Comparable<ClassInfo> {
         nested.takeIf { it.isNotEmpty() }?.let {
             h2("Nested Classes")
             nested.forEach { cls ->
+                val typeElement = cls as TypeElement
+                val info = classIndex.get(typeElement)
+                val parent = classIndex.getParent(typeElement)
                 div("member") {
-                    h4(cls.simpleName.toString())
+                    h4 {
+                        a(relativePath(parent.fileName, info.fileName), info.simpleName)
+                    }
                     compose {
                         cls.commentsAndTagTrees()
                     }
@@ -122,7 +183,7 @@ data class ClassInfo(val element: TypeElement) : Comparable<ClassInfo> {
     fun generateHtml() = html {
         div("package-name") { text("Package: $packageName") }
         h1(simpleName)
-        pre(element.signature(), "class-signature")
+        pre(signature(), "class-signature")
 
         compose {
             description() +
@@ -132,5 +193,10 @@ data class ClassInfo(val element: TypeElement) : Comparable<ClassInfo> {
                     nestedClasses()
         }
     }
+
+    private fun relativePath(from: String, to: String) =
+        Paths.get(from).parent.relativize(Paths.get(to)).toString()
 }
 
+private fun String.prefixIfNotEmpty(prefix: String): String
+        = if (isNotEmpty()) prefix + this else this
diff --git a/api-doclet/src/main/kotlin/org/conscrypt/doclet/ElementUtils.kt b/api-doclet/src/main/kotlin/org/conscrypt/doclet/ElementUtils.kt
index a9fcd00e..5739bf23 100644
--- a/api-doclet/src/main/kotlin/org/conscrypt/doclet/ElementUtils.kt
+++ b/api-doclet/src/main/kotlin/org/conscrypt/doclet/ElementUtils.kt
@@ -17,7 +17,6 @@
 package org.conscrypt.doclet
 
 import com.sun.source.doctree.UnknownBlockTagTree
-import java.util.Locale
 import javax.lang.model.element.Element
 import javax.lang.model.element.ElementKind
 import javax.lang.model.element.ExecutableElement
@@ -39,9 +38,8 @@ fun Element.isVisibleConstructor() = isExecutable() && isVisible() && kind == El
 fun Element.isVisibleField() = isField() && isVisible()
 fun Element.isPublic() = modifiers.contains(Modifier.PUBLIC)
 fun Element.isPrivate() = !isPublic() // Ignore protected for now :)
-fun Element.isHidden() = isPrivate() || hasHideMarker() || parentIsHidden()
 fun Element.isVisible() = !isHidden()
-fun Element.hasHideMarker() = hasAnnotation("org.conscrypt.Internal") || hasHideTag()
+fun Element.isHidden() = isPrivate() || isFiltered() || parentIsHidden()
 fun Element.children(filterFunction: (Element) -> Boolean) = enclosedElements
     .filter(filterFunction)
     .toList()
@@ -53,10 +51,9 @@ fun Element.hasAnnotation(annotationName: String): Boolean = annotationMirrors
     .map { it.annotationType.toString() }
     .any { it == annotationName }
 
-
-fun Element.hasHideTag(): Boolean {
+fun Element.hasJavadocTag(tagName: String): Boolean {
     return docTree()?.blockTags?.any {
-        tag -> tag is UnknownBlockTagTree && tag.tagName == "hide"
+        tag -> tag is UnknownBlockTagTree && tag.tagName == tagName
     } ?: false
 }
 
@@ -79,7 +76,7 @@ fun ExecutableElement.methodSignature(): String {
     val exceptions = thrownTypes
         .joinToString(", ")
         .prefixIfNotEmpty(" throws ")
-    return "$modifiers $typeParams$returnType${simpleName}($parameters)$exceptions"
+    return "$modifiers $typeParams$returnType${name()}($parameters)$exceptions"
 }
 
 fun formatType(typeMirror: TypeMirror): String {
@@ -92,28 +89,11 @@ fun formatType(typeMirror: TypeMirror): String {
     }
 }
 
-fun TypeElement.signature(): String {
-    val modifiers = modifiers.joinToString(" ")
-    val kind = this.kind.toString().lowercase(Locale.getDefault())
-
-    val superName = superDisplayName(superclass)
-
-    val interfaces = interfaces
-        .joinToString(", ")
-        .prefixIfNotEmpty(" implements ")
-
-    return "$modifiers $kind $simpleName$superName$interfaces"
-}
-
-fun superDisplayName(mirror: TypeMirror): String {
-    return when (mirror.toString()) {
-        "none", "java.lang.Object" -> ""
-        else -> " extends $mirror "
-    }
-}
+fun TypeElement.baseFileName(): String =
+    if (enclosingElement.isType())
+        (enclosingElement as TypeElement).baseFileName() + "." + simpleName
+    else
+        qualifiedName.toString().replace('.', '/')
 
 private fun String.prefixIfNotEmpty(prefix: String): String
         = if (isNotEmpty()) prefix + this else this
-
-private fun String.suffixIfNotEmpty(prefix: String): String
-        = if (isNotEmpty()) this + prefix else this
\ No newline at end of file
diff --git a/api-doclet/src/main/kotlin/org/conscrypt/doclet/FilterDoclet.kt b/api-doclet/src/main/kotlin/org/conscrypt/doclet/FilterDoclet.kt
index 77db33ff..94fb5ffd 100644
--- a/api-doclet/src/main/kotlin/org/conscrypt/doclet/FilterDoclet.kt
+++ b/api-doclet/src/main/kotlin/org/conscrypt/doclet/FilterDoclet.kt
@@ -25,33 +25,42 @@ import java.nio.file.Path
 import java.nio.file.Paths
 import java.util.Locale
 import javax.lang.model.SourceVersion
+import javax.lang.model.element.Element
 import javax.lang.model.util.Elements
 import javax.lang.model.util.Types
 
+/**
+ * A Doclet which can filter out internal APIs in various ways and then render the results
+ * as HTML.
+ *
+ * See also: The Element.isFiltered extension function below to see what is filtered.
+ */
 class FilterDoclet : Doclet {
     companion object {
         lateinit var docTrees: DocTrees
         lateinit var elementUtils: Elements
         lateinit var typeUtils: Types
         lateinit var outputPath: Path
-        var baseUrl: String = "https://docs.oracle.com/javase/8/docs/api/"
-        val CSS_FILENAME = "styles.css"
+        lateinit var cssPath: Path
+        var baseUrl: String = "https://docs.oracle.com/en/java/javase/21/docs/api/java.base/"
+        const val CSS_FILENAME = "styles.css"
         var outputDir = "."
-        var docTitle = "DTITLE"
-        var windowTitle = "WTITLE"
+        var docTitle = "DOC TITLE"
+        var windowTitle = "WINDOW TITLE"
         var noTimestamp: Boolean = false
         val classIndex = ClassIndex()
     }
 
     override fun init(locale: Locale?, reporter: Reporter?) = Unit // TODO
     override fun getName() = "FilterDoclet"
-    override fun getSupportedSourceVersion() = SourceVersion.latest()
+    override fun getSupportedSourceVersion(): SourceVersion = SourceVersion.latest()
 
     override fun run(environment: DocletEnvironment): Boolean {
         docTrees = environment.docTrees
         elementUtils = environment.elementUtils
         typeUtils = environment.typeUtils
         outputPath = Paths.get(outputDir)
+        cssPath = outputPath.resolve(CSS_FILENAME)
         Files.createDirectories(outputPath)
 
         classIndex.addVisible(environment.includedElements)
@@ -75,7 +84,7 @@ class FilterDoclet : Doclet {
         html {
             body(
                 title = docTitle,
-                stylesheet = relativePath(indexPath, CSS_FILENAME),
+                stylesheet = relativePath(indexPath, cssPath),
             ) {
                 div("index-container") {
                     h1(docTitle, "index-title")
@@ -94,12 +103,12 @@ class FilterDoclet : Doclet {
     private fun generateClassFile(classInfo: ClassInfo) {
         val classFilePath = outputPath.resolve(classInfo.fileName)
         Files.createDirectories(classFilePath.parent)
-        val simpleName = classInfo.simpleName
+        val name = classInfo.innerName()
 
         html {
             body(
-                title = "$simpleName - conscrypt-openjdk API",
-                stylesheet = relativePath(classFilePath, CSS_FILENAME),
+                title = "$name - Conscrypt API",
+                stylesheet = relativePath(classFilePath, cssPath),
             ) {
                 compose {
                     classInfo.generateHtml()
@@ -112,17 +121,7 @@ class FilterDoclet : Doclet {
         }
     }
 
-    private fun relativePath(from: Path, to: String): String {
-        val fromDir = from.parent
-        val toPath = Paths.get(outputDir).resolve(to)
-
-        if (fromDir == null) {
-            return to
-        }
-
-        val relativePath = fromDir.relativize(toPath)
-        return relativePath.toString().replace('\\', '/')
-    }
+    private fun relativePath(from: Path, to: Path) = from.parent.relativize(to).toString()
 
     override fun getSupportedOptions(): Set<Doclet.Option> {
         return setOf<Doclet.Option>(
@@ -151,4 +150,8 @@ class FilterDoclet : Doclet {
                 "Something"
             ) { noTimestamp = true })
     }
-}
\ No newline at end of file
+}
+
+// Called to determine whether to filter each public API element.
+fun Element.isFiltered() =
+        hasJavadocTag("hide") || hasAnnotation("org.conscrypt.Internal")
diff --git a/api-doclet/src/main/kotlin/org/conscrypt/doclet/HtmlBuilder.kt b/api-doclet/src/main/kotlin/org/conscrypt/doclet/HtmlBuilder.kt
index 0c2758b2..0455c44d 100644
--- a/api-doclet/src/main/kotlin/org/conscrypt/doclet/HtmlBuilder.kt
+++ b/api-doclet/src/main/kotlin/org/conscrypt/doclet/HtmlBuilder.kt
@@ -43,13 +43,21 @@ class HtmlBuilder {
     }
 
     private fun tagBlock(
-        tag: String, cssClass: String? = null, colspan: Int? = null, id: String? = null, block: Block)
+        tag: String,
+        cssClass: String? = null,
+        colspan: Int? = null,
+        id: String? = null,
+        block: Block,
+        inline: Boolean? = false)
     {
-        content.append("\n<$tag")
+        content.append("<$tag")
         cssClass?.let { content.append(""" class="$it"""") }
         colspan?.let { content.append(""" colspan="$it"""") }
         id?.let { content.append(""" id="$it"""") }
         content.append(">")
+        if(inline == false) {
+            content.append("\n")
+        }
         content.append(block.render())
         content.append("</$tag>\n")
     }
@@ -65,28 +73,35 @@ class HtmlBuilder {
     fun tr(cssClass: String? = null, id: String? = null, block: Block) =
         tagBlock("tr", cssClass = cssClass, colspan = null, id, block)
     fun th(cssClass: String? = null, colspan: Int? = null, id: String? = null, block: Block) =
-        tagBlock("th", cssClass, colspan, id, block)
+        tagBlock("th", cssClass, colspan, id, block, true)
     fun td(cssClass: String? = null, colspan: Int? = null, id: String? = null, block: Block) =
-        tagBlock("td", cssClass, colspan, id, block)
+        tagBlock("td", cssClass, colspan, id, block, true)
 
-    private fun tagValue(tag: String, value: String, cssClass: String? = null) {
+    private fun tagValue(tag: String, value: String, cssClass: String? = null, id: String? = null) {
         val classText = cssClass?.let { """ class="$it"""" } ?: ""
-        content.append("<$tag$classText>$value</$tag>\n")
+        val idText = id?.let { """ id="$it"""" } ?: ""
+        content.append("<$tag$classText$idText>$value</$tag>")
+    }
+
+    private fun tagValueNl(tag: String, value: String, cssClass: String? = null) {
+        tagValue(tag, value, cssClass)
+        content.append("\n")
     }
 
-    fun h1(heading: String, cssClass: String? = null) = tagValue("h1", heading, cssClass)
+    fun h1(heading: String, cssClass: String? = null) = tagValueNl("h1", heading, cssClass)
     fun h1(cssClass: String? = null, block: Block) = h1(block.render(), cssClass)
-    fun h2(heading: String, cssClass: String? = null) = tagValue("h2", heading, cssClass)
+    fun h2(heading: String, cssClass: String? = null) = tagValueNl("h2", heading, cssClass)
     fun h2(cssClass: String? = null, block: Block) = h2(block.render(), cssClass)
-    fun h3(heading: String, cssClass: String? = null) = tagValue("h3", heading, cssClass)
+    fun h3(heading: String, cssClass: String? = null) = tagValueNl("h3", heading, cssClass)
     fun h3(cssClass: String? = null, block: Block) = h2(block.render(), cssClass)
-    fun h4(heading: String, cssClass: String? = null) = tagValue("h4", heading, cssClass)
+    fun h4(heading: String, cssClass: String? = null) = tagValueNl("h4", heading, cssClass)
     fun h4(cssClass: String? = null, block: Block) = h2(block.render(), cssClass)
-    fun h5(heading: String, cssClass: String? = null) = tagValue("h5", heading, cssClass)
+    fun h5(heading: String, cssClass: String? = null) = tagValueNl("h5", heading, cssClass)
     fun h5(cssClass: String? = null, block: Block) = h2(block.render(), cssClass)
 
-    fun p(text: String, cssClass: String? = null) = tagValue("p", text, cssClass)
+    fun p(text: String, cssClass: String? = null) = tagValueNl("p", text, cssClass)
     fun p(cssClass: String? = null, block: Block) = p(block.render(), cssClass)
+
     fun b(text: String, cssClass: String? = null) = tagValue("b", text, cssClass)
     fun b(cssClass: String? = null, block: Block) = b(block.render(), cssClass)
     fun pre(text: String, cssClass: String? = null) = tagValue("pre", text, cssClass)
@@ -103,7 +118,7 @@ class HtmlBuilder {
     fun a(href: String, block: Block) = a(href, block.render())
     fun a(href: String) = a(href, href)
 
-    fun li(text: String, cssClass: String? = null) = tagValue("li", text, cssClass)
+    fun li(text: String, cssClass: String? = null) = tagValueNl("li", text, cssClass)
     fun li(cssClass: String? = null, block: Block) = li(block.render(), cssClass)
 
     fun <T> items(collection: Iterable<T>, cssClass: String? = null,
@@ -145,7 +160,7 @@ fun html(block: Block) = block.render()
 fun exampleSubfunction() = html {
     h1("Headings from exampleSubfunction")
     listOf("one", "two", "three").forEach {
-        h1(it)
+        h2(it)
     }
 }
 
@@ -224,56 +239,56 @@ fun example() = html {
                 text("Item $it")
             }
         }
-    }
-    val data1 = listOf(1, 2)
-    val data2 = "3" to "4"
-    val data3 = listOf(
-        "tag1" to "Some value",
-        "tag2" to "Next Value",
-        "tag3" to "Another value"
-    )
+        val data1 = listOf(1, 2)
+        val data2 = "3" to "4"
+        val data3 = listOf(
+            "key1" to "Some value",
+            "key2" to "Next Value",
+            "key3" to "Another value"
+        )
 
-    table("table-class") {
-        tr {
-            th {
-                text("First column")
-            }
-            th {
-                text("Second column")
+        table(cssClass = "table-class", id = "tableId") {
+            tr {
+                th {
+                    text("First column")
+                }
+                th {
+                    text("Second column")
 
+                }
             }
-        }
-        tr("tr-class") {
-            td("td-class") {
-                text("Data 1")
-            }
-            td(colspan = 2, id = "foo") {
+            tr("tr-class") {
+                td("td-class") {
+                    text("Data 1")
+                }
+                td(colspan = 2, id = "foo") {
                     text("Data 2")
+                }
             }
-        }
-        tr {
-            td() {
-                text("Data 3")
-            }
-        }
-        row(data1, "c1") {
-            a(href="www.google.com") { text("$it") }
-        }
-        row(data2) { p:Pair<String, String> ->
-            td {
-                text(p.first)
+            tr {
+                td() {
+                    text("Data 3")
+                }
             }
-            td {
-                text(p.second)
+            row(data1, "c1") {
+                a(href = "www.google.com") { text("$it") }
             }
+            row(data2) { p: Pair<String, String> ->
+                td {
+                    text(p.first)
+                }
+                td {
+                    text(p.second)
+                }
 
-        }
-        rowGroup(data3, title = "Row Group", colspan=2) { p: Pair<String, String> ->
-            td {
-                text(p.first)
             }
-            td {
-                text(p.second)
+            rowGroup(data3, title = "Row Group", colspan = 2) { p: Pair<String, String> ->
+                td {
+                    text(p.first)
+                }
+                td {
+                    text(p.second)
+                }
             }
         }
     }
diff --git a/api-doclet/src/main/resources/styles.css b/api-doclet/src/main/resources/styles.css
index 262f64ed..0a99068b 100644
--- a/api-doclet/src/main/resources/styles.css
+++ b/api-doclet/src/main/resources/styles.css
@@ -2,7 +2,6 @@ body {
     font-family: Arial, sans-serif;
     line-height: 1.2;
     color: #333;
-    /* max-width: 800px; */
     margin: 0 auto;
     padding: 10px;
 }
@@ -75,7 +74,6 @@ body {
     font-size: 14px;
     overflow-x: auto;
 }
-/* Index page styles */
 .index-container {
     margin: 0 auto;
     padding: 20px;
@@ -115,7 +113,6 @@ body {
     color: #2c3e50;
     margin-bottom: 20px;
 }
-
 .class-description {
     margin: 20px 0;
     padding: 15px;
@@ -123,18 +120,15 @@ body {
     font-size: 16px;
     line-height: 1.6;
 }
-
 .class-description p {
     margin-bottom: 10px;
 }
-
 .class-description code {
     background-color: #e9ecef;
     padding: 2px 4px;
     border-radius: 4px;
     font-family: monospace;
 }
-
 .package-name {
     font-family: monospace;
     font-size: 14px;
diff --git a/api/platform/current.txt b/api/platform/current.txt
index b4138e4d..6bf479f1 100644
--- a/api/platform/current.txt
+++ b/api/platform/current.txt
@@ -79,6 +79,7 @@ package com.android.org.conscrypt {
     method public void checkClientTrusted(java.security.cert.X509Certificate[], String, javax.net.ssl.SSLEngine) throws java.security.cert.CertificateException;
     method public void checkServerTrusted(java.security.cert.X509Certificate[], String) throws java.security.cert.CertificateException;
     method public java.util.List<java.security.cert.X509Certificate> checkServerTrusted(java.security.cert.X509Certificate[], String, String) throws java.security.cert.CertificateException;
+    method @FlaggedApi("com.android.org.conscrypt.flags.certificate_transparency_checkservertrusted_api") public java.util.List<java.security.cert.X509Certificate> checkServerTrusted(java.security.cert.X509Certificate[], byte[], byte[], String, String) throws java.security.cert.CertificateException;
     method public void checkServerTrusted(java.security.cert.X509Certificate[], String, java.net.Socket) throws java.security.cert.CertificateException;
     method public void checkServerTrusted(java.security.cert.X509Certificate[], String, javax.net.ssl.SSLEngine) throws java.security.cert.CertificateException;
     method public java.security.cert.X509Certificate[] getAcceptedIssuers();
diff --git a/benchmark-android/build.gradle b/benchmark-android/build.gradle
index 991b7c72..7981a281 100644
--- a/benchmark-android/build.gradle
+++ b/benchmark-android/build.gradle
@@ -4,7 +4,7 @@ buildscript {
         mavenCentral()
     }
     dependencies {
-        classpath libraries.android_tools
+        classpath libs.android.tools
     }
 }
 
@@ -61,14 +61,14 @@ if (androidSdkInstalled) {
 
     dependencies {
         depsJarApi project(path: ':conscrypt-android'),
-                   libraries.bouncycastle_provider,
-                   libraries.bouncycastle_apis
+                   libs.bouncycastle.provider,
+                   libs.bouncycastle.apis
 
         depsJarImplementation project(':conscrypt-benchmark-base'),
                               project(path: ":conscrypt-testing", configuration: "shadow"),
                               project(':conscrypt-libcore-stub')
 
-        implementation 'com.google.caliper:caliper:1.0-beta-2'
+        implementation libs.caliper
     }
 
     // This task bundles up everything we're going to send to the device into a single jar.
diff --git a/benchmark-base/build.gradle b/benchmark-base/build.gradle
index 68bdb324..6c838b14 100644
--- a/benchmark-base/build.gradle
+++ b/benchmark-base/build.gradle
@@ -2,5 +2,5 @@ description = 'Conscrypt: Base library for benchmarks'
 
 dependencies {
     implementation project(path: ":conscrypt-testing", configuration: "shadow"),
-            libraries.junit
+            libs.junit
 }
diff --git a/benchmark-jmh/build.gradle b/benchmark-jmh/build.gradle
index 7b74df64..20393b2e 100644
--- a/benchmark-jmh/build.gradle
+++ b/benchmark-jmh/build.gradle
@@ -1,9 +1,7 @@
 plugins {
-    id 'me.champeau.gradle.jmh' version '0.5.3'
+    alias libs.plugins.jmh
 }
 
-apply plugin: 'idea'
-
 description = 'Conscrypt: JMH on OpenJDK Benchmarks'
 
 evaluationDependsOn(':conscrypt-openjdk')
@@ -31,13 +29,13 @@ jmh {
         setBenchmarkParameters(parseParams(jmhParams))
     }
     warmupIterations = "$jmhWarmupIterations".toInteger()
-    iterations = "$jmhIterations".toInteger();
+    iterations = "$jmhIterations".toInteger()
     fork = "$jmhFork".toInteger()
-    jvmArgs = jmhJvmArgs.toString()
+    // jvmArgs = jmhJvmArgs
     if (jmhJvm != null) {
         jvm = jmhJvm
     }
-    duplicateClassesStrategy = 'warn'
+    duplicateClassesStrategy = DuplicatesStrategy.WARN
 }
 
 configurations {
@@ -65,20 +63,21 @@ sourceSets {
 }
 
 dependencies {
-    implementation project(path: ":conscrypt-openjdk", configuration: "runtimeElements"),
+    implementation project(":conscrypt-openjdk"),
+            project(path: ":conscrypt-testing", configuration: "runtimeElements"),
             project(':conscrypt-benchmark-base'),
             // Add the preferred native openjdk configuration for this platform.
-            project(':conscrypt-openjdk').sourceSets["$preferredSourceSet"].output,
-            libraries.junit,
-            libraries.netty_handler,
-            libraries.netty_tcnative
+            //project(':conscrypt-openjdk').sourceSets["$preferredSourceSet"].output,
+            libs.junit,
+            libs.netty.handler,
+            libs.netty.tcnative
 
-    jmhGeneratorAnnprocess libraries.jmh_generator_annprocess
+    jmhGeneratorAnnprocess libs.jmh.generator.annprocess
 
     // Override the default JMH dependencies with the new versions.
-    jmh libraries.jmh_core,
-            libraries.jmh_generator_reflection,
-            libraries.jmh_generator_bytecode
+    jmh libs.jmh.core,
+            libs.jmh.generator.reflection,
+            libs.jmh.generator.bytecode
 }
 
 // Running benchmarks in IntelliJ seems broken without this.
diff --git a/build.gradle b/build.gradle
index cd5d4582..2c259d49 100644
--- a/build.gradle
+++ b/build.gradle
@@ -2,8 +2,6 @@ import org.ajoberstar.grgit.Grgit
 import org.gradle.util.VersionNumber
 
 buildscript {
-    ext.android_tools = 'com.android.tools.build:gradle:7.4.0'
-    ext.errorproneVersion = '2.31.0'
     repositories {
         google()
         mavenCentral()
@@ -11,17 +9,16 @@ buildscript {
     dependencies {
         // This must be applied in the root project otherwise each subproject will
         // have it in a different ClassLoader.
-        classpath android_tools
+        classpath libs.android.tools
     }
 }
 
 plugins {
-    // Add dependency for build script so we can access Git from our
-    // build script.
-    id 'org.ajoberstar.grgit' version '5.2.2'
-    id 'net.ltgt.errorprone' version '4.0.0'
-    id "com.google.osdetector" version "1.7.3"
-    id "biz.aQute.bnd.builder" version "6.4.0" apply false
+    alias libs.plugins.bnd apply false
+    alias libs.plugins.errorprone
+    alias libs.plugins.grgit
+    alias libs.plugins.osdetector
+    alias libs.plugins.task.tree
 }
 
 subprojects {
@@ -65,9 +62,8 @@ subprojects {
             }
         }
     }
-    apply plugin: "idea"
     apply plugin: "jacoco"
-    apply plugin: "net.ltgt.errorprone"
+    apply plugin: libs.plugins.errorprone.get().pluginId
 
     group = "org.conscrypt"
     description = 'Conscrypt is an alternate Java Security Provider that uses BoringSSL'
@@ -91,28 +87,6 @@ subprojects {
         boringSslGit = Grgit.open(dir: boringsslHome)
         boringSslVersion = boringSslGit.head().id
 
-        jmhVersion = '1.21'
-        libraries = [
-                android_tools: android_tools,
-                roboelectric: 'org.robolectric:android-all:7.1.0_r7-robolectric-0',
-
-                // Test dependencies.
-                bouncycastle_apis: 'org.bouncycastle:bcpkix-jdk15on:1.63',
-                bouncycastle_provider: 'org.bouncycastle:bcprov-jdk15on:1.63',
-                junit  : 'junit:junit:4.12',
-                mockito: 'org.mockito:mockito-core:2.28.2',
-                truth  : 'com.google.truth:truth:1.0',
-
-                // Benchmark dependencies
-                jmh_core: "org.openjdk.jmh:jmh-core:${jmhVersion}",
-                jmh_generator_annprocess: "org.openjdk.jmh:jmh-generator-annprocess:${jmhVersion}",
-                jmh_generator_asm: "org.openjdk.jmh:jmh-generator-asm:${jmhVersion}",
-                jmh_generator_bytecode: "org.openjdk.jmh:jmh-generator-bytecode:${jmhVersion}",
-                jmh_generator_reflection: "org.openjdk.jmh:jmh-generator-reflection:${jmhVersion}",
-                netty_handler: 'io.netty:netty-handler:4.1.24.Final',
-                netty_tcnative: 'io.netty:netty-tcnative-boringssl-static:2.0.26.Final',
-        ]
-
         signJar = { jarPath ->
             if (rootProject.hasProperty('signingKeystore') && rootProject.hasProperty('signingPassword')) {
                 def command = 'jarsigner -keystore ' + rootProject.signingKeystore +
@@ -133,11 +107,21 @@ subprojects {
     }
 
     jacoco {
-        toolVersion = "0.8.4"
+        toolVersion = libs.versions.jacoco
+    }
+
+    configurations {
+        jacocoAnt
+        jacocoAgent
+    }
+
+    dependencies {
+        jacocoAnt libs.jacoco.ant
+        jacocoAgent libs.jacoco.agent
     }
 
     dependencies {
-        errorprone("com.google.errorprone:error_prone_core:$errorproneVersion")
+        errorprone libs.errorprone
     }
 
     tasks.register("generateProperties", WriteProperties) {
@@ -192,12 +176,12 @@ subprojects {
         }
 
         tasks.register("javadocJar", Jar) {
-            classifier = 'javadoc'
+            archiveClassifier = 'javadoc'
             from javadoc
         }
 
         tasks.register("sourcesJar", Jar) {
-            classifier = 'sources'
+            archiveClassifier = 'sources'
             from sourceSets.main.allSource
         }
 
diff --git a/common/src/main/java/org/conscrypt/AbstractConscryptSocket.java b/common/src/main/java/org/conscrypt/AbstractConscryptSocket.java
index 1fe7a238..b177e9d6 100644
--- a/common/src/main/java/org/conscrypt/AbstractConscryptSocket.java
+++ b/common/src/main/java/org/conscrypt/AbstractConscryptSocket.java
@@ -660,22 +660,6 @@ abstract class AbstractConscryptSocket extends SSLSocket {
      */
     abstract void setChannelIdPrivateKey(PrivateKey privateKey);
 
-    /**
-     * Returns null always for backward compatibility.
-     * @deprecated NPN is not supported
-     */
-    @Deprecated
-    byte[] getNpnSelectedProtocol() {
-        return null;
-    }
-
-    /**
-     * This method does nothing and is kept for backward compatibility.
-     * @deprecated NPN is not supported
-     */
-    @Deprecated
-    void setNpnProtocols(byte[] npnProtocols) {}
-
     /**
      * Returns the protocol agreed upon by client and server, or {@code null} if
      * no protocol was agreed upon.
diff --git a/common/src/main/java/org/conscrypt/AbstractSessionContext.java b/common/src/main/java/org/conscrypt/AbstractSessionContext.java
index a3447fde..d4ac04fb 100644
--- a/common/src/main/java/org/conscrypt/AbstractSessionContext.java
+++ b/common/src/main/java/org/conscrypt/AbstractSessionContext.java
@@ -247,7 +247,7 @@ abstract class AbstractSessionContext implements SSLSessionContext {
     }
 
     @Override
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("Finalize")
     protected void finalize() throws Throwable {
         try {
             freeNative();
diff --git a/common/src/main/java/org/conscrypt/AllocatedBuffer.java b/common/src/main/java/org/conscrypt/AllocatedBuffer.java
index 0d9a9423..c4d5ac6c 100644
--- a/common/src/main/java/org/conscrypt/AllocatedBuffer.java
+++ b/common/src/main/java/org/conscrypt/AllocatedBuffer.java
@@ -51,6 +51,7 @@ public abstract class AllocatedBuffer {
      * @deprecated this method is not used
      */
     @Deprecated
+    @SuppressWarnings("InlineMeSuggester")
     public AllocatedBuffer retain() {
         // Do nothing.
         return this;
diff --git a/common/src/main/java/org/conscrypt/ArrayUtils.java b/common/src/main/java/org/conscrypt/ArrayUtils.java
index 63fa5a87..946fa18c 100644
--- a/common/src/main/java/org/conscrypt/ArrayUtils.java
+++ b/common/src/main/java/org/conscrypt/ArrayUtils.java
@@ -37,6 +37,7 @@ public final class ArrayUtils {
     }
 
     @SafeVarargs
+    @SuppressWarnings("varargs")
     public static <T> T[] concatValues(T[] a1, T... values) {
         return concat (a1, values);
     }
diff --git a/common/src/main/java/org/conscrypt/CertificatePriorityComparator.java b/common/src/main/java/org/conscrypt/CertificatePriorityComparator.java
index eb62fca2..831306e1 100644
--- a/common/src/main/java/org/conscrypt/CertificatePriorityComparator.java
+++ b/common/src/main/java/org/conscrypt/CertificatePriorityComparator.java
@@ -75,7 +75,7 @@ public final class CertificatePriorityComparator implements Comparator<X509Certi
     }
 
     @Override
-    @SuppressWarnings("JdkObsolete")  // Certificate uses Date
+    @SuppressWarnings({"JdkObsolete", "JavaUtilDate"})  // Certificate uses Date
     public int compare(X509Certificate lhs, X509Certificate rhs) {
         int result;
         boolean lhsSelfSigned = lhs.getSubjectDN().equals(lhs.getIssuerDN());
diff --git a/common/src/main/java/org/conscrypt/Conscrypt.java b/common/src/main/java/org/conscrypt/Conscrypt.java
index 66595114..53bc16e7 100644
--- a/common/src/main/java/org/conscrypt/Conscrypt.java
+++ b/common/src/main/java/org/conscrypt/Conscrypt.java
@@ -160,6 +160,8 @@ public final class Conscrypt {
         private String name = Platform.getDefaultProviderName();
         private boolean provideTrustManager = Platform.provideTrustManagerByDefault();
         private String defaultTlsProtocol = NativeCrypto.SUPPORTED_PROTOCOL_TLSV1_3;
+        private boolean deprecatedTlsV1 = true;
+        private boolean enabledTlsV1 = false;
 
         private ProviderBuilder() {}
 
@@ -177,6 +179,7 @@ public final class Conscrypt {
          * @deprecated Use provideTrustManager(true)
          */
         @Deprecated
+        @SuppressWarnings("InlineMeSuggester")
         public ProviderBuilder provideTrustManager() {
             return provideTrustManager(true);
         }
@@ -199,8 +202,21 @@ public final class Conscrypt {
             return this;
         }
 
+        /** Specifies whether TLS v1.0 and 1.1 should be deprecated */
+        public ProviderBuilder isTlsV1Deprecated(boolean deprecatedTlsV1) {
+            this.deprecatedTlsV1 = deprecatedTlsV1;
+            return this;
+        }
+
+        /** Specifies whether TLS v1.0 and 1.1 should be enabled */
+        public ProviderBuilder isTlsV1Enabled(boolean enabledTlsV1) {
+            this.enabledTlsV1 = enabledTlsV1;
+            return this;
+        }
+
         public Provider build() {
-            return new OpenSSLProvider(name, provideTrustManager, defaultTlsProtocol);
+            return new OpenSSLProvider(name, provideTrustManager,
+                defaultTlsProtocol, deprecatedTlsV1, enabledTlsV1);
         }
     }
 
diff --git a/common/src/main/java/org/conscrypt/ConscryptEngine.java b/common/src/main/java/org/conscrypt/ConscryptEngine.java
index a58aa73c..b48b219a 100644
--- a/common/src/main/java/org/conscrypt/ConscryptEngine.java
+++ b/common/src/main/java/org/conscrypt/ConscryptEngine.java
@@ -1671,7 +1671,7 @@ final class ConscryptEngine extends AbstractConscryptEngine implements NativeCry
     }
 
     @Override
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("Finalize")
     protected void finalize() throws Throwable {
         try {
             // If ssl is null, object must not be fully constructed so nothing for us to do here.
diff --git a/common/src/main/java/org/conscrypt/ConscryptEngineSocket.java b/common/src/main/java/org/conscrypt/ConscryptEngineSocket.java
index 8b23ea67..af64d998 100644
--- a/common/src/main/java/org/conscrypt/ConscryptEngineSocket.java
+++ b/common/src/main/java/org/conscrypt/ConscryptEngineSocket.java
@@ -16,8 +16,6 @@
 
 package org.conscrypt;
 
-import static javax.net.ssl.SSLEngineResult.Status.CLOSED;
-import static javax.net.ssl.SSLEngineResult.Status.OK;
 import static org.conscrypt.SSLUtils.EngineStates.STATE_CLOSED;
 import static org.conscrypt.SSLUtils.EngineStates.STATE_HANDSHAKE_COMPLETED;
 import static org.conscrypt.SSLUtils.EngineStates.STATE_HANDSHAKE_STARTED;
@@ -25,6 +23,11 @@ import static org.conscrypt.SSLUtils.EngineStates.STATE_NEW;
 import static org.conscrypt.SSLUtils.EngineStates.STATE_READY;
 import static org.conscrypt.SSLUtils.EngineStates.STATE_READY_HANDSHAKE_CUT_THROUGH;
 
+import static javax.net.ssl.SSLEngineResult.Status.CLOSED;
+import static javax.net.ssl.SSLEngineResult.Status.OK;
+
+import org.conscrypt.metrics.StatsLog;
+
 import java.io.EOFException;
 import java.io.IOException;
 import java.io.InputStream;
@@ -36,6 +39,7 @@ import java.nio.ByteBuffer;
 import java.security.PrivateKey;
 import java.security.cert.CertificateException;
 import java.security.cert.X509Certificate;
+
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLEngineResult;
 import javax.net.ssl.SSLEngineResult.HandshakeStatus;
@@ -297,10 +301,12 @@ class ConscryptEngineSocket extends OpenSSLSocketImpl implements SSLParametersIm
 
                 case STATE_READY_HANDSHAKE_CUT_THROUGH:
                     if (handshakeStartedMillis > 0) {
-                        Platform.countTlsHandshake(true,
-                            engine.getSession().getProtocol(),
-                            engine.getSession().getCipherSuite(),
-                            Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                        StatsLog statsLog = Platform.getStatsLog();
+                        if (statsLog != null) {
+                            statsLog.countTlsHandshake(true, engine.getSession().getProtocol(),
+                                    engine.getSession().getCipherSuite(),
+                                    Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                        }
                         handshakeStartedMillis = 0;
                     }
                     notify = true;
@@ -312,11 +318,13 @@ class ConscryptEngineSocket extends OpenSSLSocketImpl implements SSLParametersIm
 
                 case STATE_CLOSED:
                     if (handshakeStartedMillis > 0) {
-                        // Handshake was in progress and so must have failed.
-                        Platform.countTlsHandshake(false,
-                            "TLS_PROTO_FAILED",
-                            "TLS_CIPHER_FAILED",
-                            Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                        StatsLog statsLog = Platform.getStatsLog();
+                        if (statsLog != null) {
+                            // Handshake was in progress and so must have failed.
+                            statsLog.countTlsHandshake(false, "TLS_PROTO_FAILED",
+                                    "TLS_CIPHER_FAILED",
+                                    Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                        }
                         handshakeStartedMillis = 0;
                     }
                     notify = true;
diff --git a/common/src/main/java/org/conscrypt/ConscryptFileDescriptorSocket.java b/common/src/main/java/org/conscrypt/ConscryptFileDescriptorSocket.java
index eeba2bbe..1f7940ec 100644
--- a/common/src/main/java/org/conscrypt/ConscryptFileDescriptorSocket.java
+++ b/common/src/main/java/org/conscrypt/ConscryptFileDescriptorSocket.java
@@ -23,6 +23,10 @@ import static org.conscrypt.SSLUtils.EngineStates.STATE_NEW;
 import static org.conscrypt.SSLUtils.EngineStates.STATE_READY;
 import static org.conscrypt.SSLUtils.EngineStates.STATE_READY_HANDSHAKE_CUT_THROUGH;
 
+import org.conscrypt.ExternalSession.Provider;
+import org.conscrypt.NativeRef.SSL_SESSION;
+import org.conscrypt.metrics.StatsLog;
+
 import java.io.IOException;
 import java.io.InputStream;
 import java.io.OutputStream;
@@ -36,6 +40,7 @@ import java.security.cert.CertificateException;
 import java.security.cert.X509Certificate;
 import java.security.interfaces.ECKey;
 import java.security.spec.ECParameterSpec;
+
 import javax.crypto.SecretKey;
 import javax.net.ssl.SSLException;
 import javax.net.ssl.SSLHandshakeException;
@@ -45,8 +50,6 @@ import javax.net.ssl.SSLSession;
 import javax.net.ssl.X509KeyManager;
 import javax.net.ssl.X509TrustManager;
 import javax.security.auth.x500.X500Principal;
-import org.conscrypt.ExternalSession.Provider;
-import org.conscrypt.NativeRef.SSL_SESSION;
 
 /**
  * Implementation of the class OpenSSLSocketImpl based on OpenSSL.
@@ -1054,7 +1057,7 @@ class ConscryptFileDescriptorSocket extends OpenSSLSocketImpl
     }
 
     @Override
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("Finalize")
     protected final void finalize() throws Throwable {
         try {
             /*
@@ -1192,10 +1195,12 @@ class ConscryptFileDescriptorSocket extends OpenSSLSocketImpl
 
             case STATE_READY:
                 if (handshakeStartedMillis != 0) {
-                    Platform.countTlsHandshake(true,
-                        activeSession.getProtocol(),
-                        activeSession.getCipherSuite(),
-                        Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                    StatsLog statsLog = Platform.getStatsLog();
+                    if (statsLog != null) {
+                        statsLog.countTlsHandshake(true, activeSession.getProtocol(),
+                                activeSession.getCipherSuite(),
+                                Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                    }
                     handshakeStartedMillis = 0;
                 }
                 break;
@@ -1203,10 +1208,11 @@ class ConscryptFileDescriptorSocket extends OpenSSLSocketImpl
             case STATE_CLOSED: {
                 if (handshakeStartedMillis != 0) {
                     // Handshake was in progress so must have failed.
-                    Platform.countTlsHandshake(false,
-                        "TLS_PROTO_FAILED",
-                        "TLS_CIPHER_FAILED",
-                        Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                    StatsLog statsLog = Platform.getStatsLog();
+                    if (statsLog != null) {
+                        statsLog.countTlsHandshake(false, "TLS_PROTO_FAILED", "TLS_CIPHER_FAILED",
+                                Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                    }
                     handshakeStartedMillis = 0;
                 }
                 if (!ssl.isClosed() && state >= STATE_HANDSHAKE_STARTED && state < STATE_CLOSED) {
diff --git a/common/src/main/java/org/conscrypt/CryptoUpcalls.java b/common/src/main/java/org/conscrypt/CryptoUpcalls.java
index 82e4e9f8..53061824 100644
--- a/common/src/main/java/org/conscrypt/CryptoUpcalls.java
+++ b/common/src/main/java/org/conscrypt/CryptoUpcalls.java
@@ -23,6 +23,7 @@ import java.security.Provider;
 import java.security.Security;
 import java.security.Signature;
 import java.util.ArrayList;
+import java.util.List;
 import java.util.logging.Level;
 import java.util.logging.Logger;
 import javax.crypto.Cipher;
@@ -43,8 +44,8 @@ final class CryptoUpcalls {
     /**
      * Finds providers that are not us that provide the requested algorithms.
      */
-    private static ArrayList<Provider> getExternalProviders(String algorithm) {
-        ArrayList<Provider> providers = new ArrayList<Provider>(1);
+    private static List<Provider> getExternalProviders(String algorithm) {
+        List<Provider> providers = new ArrayList<>(1);
         for (Provider p : Security.getProviders(algorithm)) {
             if (!Conscrypt.isConscrypt(p)) {
                 providers.add(p);
@@ -61,7 +62,7 @@ final class CryptoUpcalls {
         // http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
         String keyAlgorithm = javaKey.getAlgorithm();
         if (!"EC".equals(keyAlgorithm)) {
-            throw new RuntimeException("Unexpected key type: " + javaKey.toString());
+            throw new RuntimeException("Unexpected key type: " + javaKey);
         }
 
         return signDigestWithPrivateKey(javaKey, message, "NONEwithECDSA");
@@ -94,7 +95,7 @@ final class CryptoUpcalls {
         // If the preferred provider was us, fall back to trying to find the
         // first not-us provider that initializes correctly.
         if (signature == null) {
-            ArrayList<Provider> providers = getExternalProviders("Signature." + algorithm);
+            List<Provider> providers = getExternalProviders("Signature." + algorithm);
             RuntimeException savedRuntimeException = null;
             for (Provider p : providers) {
                 try {
@@ -169,7 +170,7 @@ final class CryptoUpcalls {
         }
 
         String transformation = "RSA/ECB/" + jcaPadding;
-        Cipher c = null;
+        Cipher c;
 
         // Since this is a delegated key, we cannot handle providing a cipher using this key.
         // Otherwise we wouldn't end up in this class in the first place. The first step is to
@@ -182,10 +183,7 @@ final class CryptoUpcalls {
             if (Conscrypt.isConscrypt(c.getProvider())) {
                 c = null;
             }
-        } catch (NoSuchAlgorithmException e) {
-            logger.warning("Unsupported cipher algorithm: " + transformation);
-            return null;
-        } catch (NoSuchPaddingException e) {
+        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
             logger.warning("Unsupported cipher algorithm: " + transformation);
             return null;
         } catch (InvalidKeyException e) {
@@ -196,17 +194,13 @@ final class CryptoUpcalls {
         // If the preferred provider was us, fall back to trying to find the
         // first not-us provider that initializes correctly.
         if (c == null) {
-            ArrayList<Provider> providers = getExternalProviders("Cipher." + transformation);
+            List<Provider> providers = getExternalProviders("Cipher." + transformation);
             for (Provider p : providers) {
                 try {
                     c = Cipher.getInstance(transformation, p);
                     c.init(cipherMode, javaKey);
                     break;
-                } catch (NoSuchAlgorithmException e) {
-                    c = null;
-                } catch (InvalidKeyException e) {
-                    c = null;
-                } catch (NoSuchPaddingException e) {
+                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
                     c = null;
                 }
             }
diff --git a/common/src/main/java/org/conscrypt/DefaultSSLContextImpl.java b/common/src/main/java/org/conscrypt/DefaultSSLContextImpl.java
index ad5027ab..0fa2a30a 100644
--- a/common/src/main/java/org/conscrypt/DefaultSSLContextImpl.java
+++ b/common/src/main/java/org/conscrypt/DefaultSSLContextImpl.java
@@ -72,14 +72,8 @@ public class DefaultSSLContextImpl extends OpenSSLContextImpl {
         char[] pwd = (keystorepwd == null) ? null : keystorepwd.toCharArray();
 
         KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
-        InputStream is = null;
-        try {
-            is = new BufferedInputStream(new FileInputStream(keystore));
+        try (InputStream is = new BufferedInputStream(new FileInputStream(keystore))) {
             ks.load(is, pwd);
-        } finally {
-            if (is != null) {
-                is.close();
-            }
         }
 
         String kmfAlg = KeyManagerFactory.getDefaultAlgorithm();
@@ -105,14 +99,8 @@ public class DefaultSSLContextImpl extends OpenSSLContextImpl {
 
         // TODO Defaults: jssecacerts; cacerts
         KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
-        InputStream is = null;
-        try {
-            is = new BufferedInputStream(new FileInputStream(keystore));
+        try (InputStream is = new BufferedInputStream(new FileInputStream(keystore))) {
             ks.load(is, pwd);
-        } finally {
-            if (is != null) {
-                is.close();
-            }
         }
         String tmfAlg = TrustManagerFactory.getDefaultAlgorithm();
         TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlg);
diff --git a/common/src/main/java/org/conscrypt/NativeCrypto.java b/common/src/main/java/org/conscrypt/NativeCrypto.java
index ca978649..f33acbce 100644
--- a/common/src/main/java/org/conscrypt/NativeCrypto.java
+++ b/common/src/main/java/org/conscrypt/NativeCrypto.java
@@ -133,19 +133,19 @@ public final class NativeCrypto {
     static native int RSA_private_decrypt(int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey,
             int padding) throws BadPaddingException, SignatureException;
 
-    /**
-     * @return array of {n, e}
+    /*
+     * Returns array of {n, e}
      */
     static native byte[][] get_RSA_public_params(NativeRef.EVP_PKEY rsa);
 
-    /**
-     * @return array of {n, e, d, p, q, dmp1, dmq1, iqmp}
+    /*
+     * Returns array of {n, e, d, p, q, dmp1, dmq1, iqmp}
      */
     static native byte[][] get_RSA_private_params(NativeRef.EVP_PKEY rsa);
 
     // --- ChaCha20 -----------------------
 
-    /**
+    /*
      * Returns the encrypted or decrypted version of the data.
      */
     static native void chacha20_encrypt_decrypt(byte[] in, int inOffset, byte[] out, int outOffset,
@@ -539,6 +539,7 @@ public final class NativeCrypto {
 
     static native byte[] get_X509_tbs_cert(long x509ctx, OpenSSLX509Certificate holder);
 
+
     static native byte[] get_X509_tbs_cert_without_ext(long x509ctx, OpenSSLX509Certificate holder, String oid);
 
     static native byte[] get_X509_signature(long x509ctx, OpenSSLX509Certificate holder);
@@ -1022,29 +1023,48 @@ public final class NativeCrypto {
 
     static native void set_SSL_psk_server_callback_enabled(long ssl, NativeSsl ssl_holder, boolean enabled);
 
-    private static final String[] ENABLED_PROTOCOLS_TLSV1 = Platform.isTlsV1Deprecated()
-            ? new String[0]
-            : new String[] {
+    public static void setTlsV1DeprecationStatus(boolean deprecated, boolean supported) {
+        if (deprecated) {
+            TLSV12_PROTOCOLS = new String[] {
+                SUPPORTED_PROTOCOL_TLSV1_2,
+            };
+            TLSV13_PROTOCOLS = new String[] {
+                SUPPORTED_PROTOCOL_TLSV1_2,
+                SUPPORTED_PROTOCOL_TLSV1_3,
+            };
+        } else {
+            TLSV12_PROTOCOLS = new String[] {
                 DEPRECATED_PROTOCOL_TLSV1,
                 DEPRECATED_PROTOCOL_TLSV1_1,
+                SUPPORTED_PROTOCOL_TLSV1_2,
             };
-
-    private static final String[] SUPPORTED_PROTOCOLS_TLSV1 = Platform.isTlsV1Supported()
-            ? new String[] {
+            TLSV13_PROTOCOLS = new String[] {
+                DEPRECATED_PROTOCOL_TLSV1,
+                DEPRECATED_PROTOCOL_TLSV1_1,
+                SUPPORTED_PROTOCOL_TLSV1_2,
+                SUPPORTED_PROTOCOL_TLSV1_3,
+            };
+        }
+        if (supported) {
+            SUPPORTED_PROTOCOLS = new String[] {
                 DEPRECATED_PROTOCOL_TLSV1,
                 DEPRECATED_PROTOCOL_TLSV1_1,
-            } : new String[0];
+                SUPPORTED_PROTOCOL_TLSV1_2,
+                SUPPORTED_PROTOCOL_TLSV1_3,
+            };
+        } else {
+            SUPPORTED_PROTOCOLS = new String[] {
+                SUPPORTED_PROTOCOL_TLSV1_2,
+                SUPPORTED_PROTOCOL_TLSV1_3,
+            };
+        }
+    }
 
     /** Protocols to enable by default when "TLSv1.3" is requested. */
-    static final String[] TLSV13_PROTOCOLS = ArrayUtils.concatValues(
-            ENABLED_PROTOCOLS_TLSV1,
-            SUPPORTED_PROTOCOL_TLSV1_2,
-            SUPPORTED_PROTOCOL_TLSV1_3);
+    static String[] TLSV13_PROTOCOLS;
 
     /** Protocols to enable by default when "TLSv1.2" is requested. */
-    static final String[] TLSV12_PROTOCOLS = ArrayUtils.concatValues(
-            ENABLED_PROTOCOLS_TLSV1,
-            SUPPORTED_PROTOCOL_TLSV1_2);
+    static String[] TLSV12_PROTOCOLS;
 
     /** Protocols to enable by default when "TLSv1.1" is requested. */
     static final String[] TLSV11_PROTOCOLS = new String[] {
@@ -1056,20 +1076,12 @@ public final class NativeCrypto {
     /** Protocols to enable by default when "TLSv1" is requested. */
     static final String[] TLSV1_PROTOCOLS = TLSV11_PROTOCOLS;
 
-    static final String[] DEFAULT_PROTOCOLS = TLSV13_PROTOCOLS;
-
     // If we ever get a new protocol go look for tests which are skipped using
     // assumeTlsV11Enabled()
-    private static final String[] SUPPORTED_PROTOCOLS = ArrayUtils.concatValues(
-            SUPPORTED_PROTOCOLS_TLSV1,
-            SUPPORTED_PROTOCOL_TLSV1_2,
-            SUPPORTED_PROTOCOL_TLSV1_3);
+    private static String[] SUPPORTED_PROTOCOLS;
 
     public static String[] getDefaultProtocols() {
-        if (Platform.isTlsV1Deprecated()) {
-          return DEFAULT_PROTOCOLS.clone();
-        }
-        return SUPPORTED_PROTOCOLS.clone();
+        return TLSV13_PROTOCOLS.clone();
     }
 
     static String[] getSupportedProtocols() {
diff --git a/common/src/main/java/org/conscrypt/NativeRef.java b/common/src/main/java/org/conscrypt/NativeRef.java
index 6b3f9dc3..c1f27dcf 100644
--- a/common/src/main/java/org/conscrypt/NativeRef.java
+++ b/common/src/main/java/org/conscrypt/NativeRef.java
@@ -27,7 +27,6 @@ abstract class NativeRef {
         if (address == 0) {
             throw new NullPointerException("address == 0");
         }
-
         this.address = address;
     }
 
@@ -42,11 +41,11 @@ abstract class NativeRef {
 
     @Override
     public int hashCode() {
-        return (int) (address ^ (address >>> 32));
+        return Long.hashCode(address);
     }
 
     @Override
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("Finalize")
     protected void finalize() throws Throwable {
         try {
             if (address != 0) {
@@ -57,6 +56,12 @@ abstract class NativeRef {
         }
     }
 
+    // VisibleForTesting
+    public boolean isNull() {
+        return address == 0;
+    }
+
+
     abstract void doFree(long context);
 
     static final class CMAC_CTX extends NativeRef {
diff --git a/common/src/main/java/org/conscrypt/NativeSsl.java b/common/src/main/java/org/conscrypt/NativeSsl.java
index 7d260bce..51ae8456 100644
--- a/common/src/main/java/org/conscrypt/NativeSsl.java
+++ b/common/src/main/java/org/conscrypt/NativeSsl.java
@@ -27,9 +27,7 @@ import static org.conscrypt.NativeConstants.SSL_VERIFY_PEER;
 
 import java.io.FileDescriptor;
 import java.io.IOException;
-import java.io.UnsupportedEncodingException;
 import java.net.SocketException;
-import java.nio.charset.Charset;
 import java.nio.charset.StandardCharsets;
 import java.security.InvalidKeyException;
 import java.security.PrivateKey;
@@ -133,7 +131,7 @@ final class NativeSsl {
         if (label == null) {
             throw new NullPointerException("Label is null");
         }
-        byte[] labelBytes = label.getBytes(Charset.forName("US-ASCII"));
+        byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
         return NativeCrypto.SSL_export_keying_material(ssl, this, labelBytes, context, length);
     }
 
@@ -141,8 +139,8 @@ final class NativeSsl {
         return NativeCrypto.SSL_get_signed_cert_timestamp_list(ssl, this);
     }
 
-    /**
-     * @see NativeCrypto.SSLHandshakeCallbacks#clientPSKKeyRequested(String, byte[], byte[])
+    /*
+     * See NativeCrypto.SSLHandshakeCallbacks#clientPSKKeyRequested(String, byte[], byte[]).
      */
     @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
     int clientPSKKeyRequested(String identityHint, byte[] identityBytesOut, byte[] key) {
@@ -160,11 +158,7 @@ final class NativeSsl {
         } else if (identity.isEmpty()) {
             identityBytes = EmptyArray.BYTE;
         } else {
-            try {
-                identityBytes = identity.getBytes("UTF-8");
-            } catch (UnsupportedEncodingException e) {
-                throw new RuntimeException("UTF-8 encoding not supported", e);
-            }
+            identityBytes = identity.getBytes(StandardCharsets.UTF_8);
         }
         if (identityBytes.length + 1 > identityBytesOut.length) {
             // Insufficient space in the output buffer
@@ -187,8 +181,8 @@ final class NativeSsl {
         return secretKeyBytes.length;
     }
 
-    /**
-     * @see NativeCrypto.SSLHandshakeCallbacks#serverPSKKeyRequested(String, String, byte[])
+    /*
+     * See NativeCrypto.SSLHandshakeCallbacks#serverPSKKeyRequested(String, String, byte[]).
      */
     @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
     int serverPSKKeyRequested(String identityHint, String identity, byte[] key) {
@@ -638,8 +632,8 @@ final class NativeSsl {
     }
 
     @Override
-    @SuppressWarnings("deprecation")
-    protected final void finalize() throws Throwable {
+    @SuppressWarnings("Finalize")
+    protected void finalize() throws Throwable {
         try {
             close();
         } finally {
diff --git a/common/src/main/java/org/conscrypt/NativeSslSession.java b/common/src/main/java/org/conscrypt/NativeSslSession.java
index 06caef2e..ff8aba47 100644
--- a/common/src/main/java/org/conscrypt/NativeSslSession.java
+++ b/common/src/main/java/org/conscrypt/NativeSslSession.java
@@ -340,7 +340,7 @@ abstract class NativeSslSession {
                 return baos.toByteArray();
             } catch (IOException e) {
                 // TODO(nathanmittler): Better error handling?
-                logger.log(Level.WARNING, "Failed to convert saved SSL Session: ", e);
+                logger.log(Level.FINE, "Failed to convert saved SSL Session: ", e);
                 return null;
             } catch (CertificateEncodingException e) {
                 log(e);
@@ -464,7 +464,7 @@ abstract class NativeSslSession {
 
     private static void log(Throwable t) {
         // TODO(nathanmittler): Better error handling?
-        logger.log(Level.INFO, "Error inflating SSL session: {0}",
+        logger.log(Level.FINE, "Error inflating SSL session: {0}",
                 (t.getMessage() != null ? t.getMessage() : t.getClass().getName()));
     }
 
diff --git a/common/src/main/java/org/conscrypt/OpenSSLContextImpl.java b/common/src/main/java/org/conscrypt/OpenSSLContextImpl.java
index a70e5a92..97fc00a0 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLContextImpl.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLContextImpl.java
@@ -73,12 +73,14 @@ public abstract class OpenSSLContextImpl extends SSLContextSpi {
     // END Android-added: Restore missing constructor that is used by apps
 
     /**
-     * Constuctor for the DefaultSSLContextImpl.  The unused boolean parameter is solely to
+     * Constructor for the DefaultSSLContextImpl.  The unused boolean parameter is solely to
      * indicate that this constructor is desired.
      */
     @SuppressWarnings("StaticAssignmentInConstructor")
     OpenSSLContextImpl(String[] protocols, boolean unused)
             throws GeneralSecurityException, IOException {
+        // TODO(prb): It looks like nowadays we can push the synchronisation into
+        // DefaultSSLContextImpl itself, but put it in its own CL for safety.
         synchronized (DefaultSSLContextImpl.class) {
             this.protocols = null;
             // This is the only place defaultSslContextImpl is read or written so all
diff --git a/common/src/main/java/org/conscrypt/OpenSSLProvider.java b/common/src/main/java/org/conscrypt/OpenSSLProvider.java
index 6fc30ff9..00f545af 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLProvider.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLProvider.java
@@ -51,17 +51,29 @@ public final class OpenSSLProvider extends Provider {
 
     @SuppressWarnings("deprecation")
     public OpenSSLProvider(String providerName) {
-        this(providerName, Platform.provideTrustManagerByDefault(), "TLSv1.3");
+        this(providerName, Platform.provideTrustManagerByDefault(), "TLSv1.3",
+            Platform.DEPRECATED_TLS_V1, Platform.ENABLED_TLS_V1);
     }
 
-    OpenSSLProvider(String providerName, boolean includeTrustManager, String defaultTlsProtocol) {
+    OpenSSLProvider(String providerName, boolean includeTrustManager,
+            String defaultTlsProtocol) {
+        this(providerName, includeTrustManager, defaultTlsProtocol,
+            Platform.DEPRECATED_TLS_V1, Platform.ENABLED_TLS_V1);
+    }
+
+    OpenSSLProvider(String providerName, boolean includeTrustManager,
+            String defaultTlsProtocol, boolean deprecatedTlsV1,
+            boolean enabledTlsV1) {
         super(providerName, 1.0, "Android's OpenSSL-backed security provider");
 
         // Ensure that the native library has been loaded.
         NativeCrypto.checkAvailability();
 
+        if (!deprecatedTlsV1 && !enabledTlsV1) {
+            throw new IllegalArgumentException("TLSv1 is not deprecated and cannot be disabled.");
+        }
         // Make sure the platform is initialized.
-        Platform.setup();
+        Platform.setup(deprecatedTlsV1, enabledTlsV1);
 
         /* === SSL Contexts === */
         String classOpenSSLContextImpl = PREFIX + "OpenSSLContextImpl";
diff --git a/common/src/main/java/org/conscrypt/OpenSSLRSAPrivateCrtKey.java b/common/src/main/java/org/conscrypt/OpenSSLRSAPrivateCrtKey.java
index d7d3331a..26be7fc1 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLRSAPrivateCrtKey.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLRSAPrivateCrtKey.java
@@ -97,7 +97,7 @@ final class OpenSSLRSAPrivateCrtKey extends OpenSSLRSAPrivateKey implements RSAP
     }
 
     static OpenSSLKey getInstance(RSAPrivateCrtKey rsaPrivateKey) throws InvalidKeyException {
-        /**
+        /*
          * If the key is not encodable (PKCS11-like key), then wrap it and use
          * JNI upcalls to satisfy requests.
          */
@@ -246,7 +246,7 @@ final class OpenSSLRSAPrivateCrtKey extends OpenSSLRSAPrivateKey implements RSAP
     }
 
     @Override
-    public final int hashCode() {
+    public int hashCode() {
         int hashCode = super.hashCode();
         if (publicExponent != null) {
             hashCode ^= publicExponent.hashCode();
diff --git a/common/src/main/java/org/conscrypt/OpenSSLRSAPrivateKey.java b/common/src/main/java/org/conscrypt/OpenSSLRSAPrivateKey.java
index c7e09feb..253fe721 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLRSAPrivateKey.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLRSAPrivateKey.java
@@ -123,7 +123,7 @@ class OpenSSLRSAPrivateKey implements RSAPrivateKey, OpenSSLKeyHolder {
     }
 
     static OpenSSLKey getInstance(RSAPrivateKey rsaPrivateKey) throws InvalidKeyException {
-        /**
+        /*
          * If the key is not encodable (PKCS11-like key), then wrap it and use
          * JNI upcalls to satisfy requests.
          */
diff --git a/common/src/main/java/org/conscrypt/OpenSSLSignature.java b/common/src/main/java/org/conscrypt/OpenSSLSignature.java
index 9149c713..01ca3960 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLSignature.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLSignature.java
@@ -166,6 +166,7 @@ public class OpenSSLSignature extends SignatureSpi {
 
     @Deprecated
     @Override
+    @SuppressWarnings("InlineMeSuggester")
     protected Object engineGetParameter(String param) throws InvalidParameterException {
         return null;
     }
@@ -453,9 +454,7 @@ public class OpenSSLSignature extends SignatureSpi {
                                 saltSizeBytes,
                                 TRAILER_FIELD_BC_ID));
                 return result;
-            } catch (NoSuchAlgorithmException e) {
-                throw new ProviderException("Failed to create PSS AlgorithmParameters", e);
-            } catch (InvalidParameterSpecException e) {
+            } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
                 throw new ProviderException("Failed to create PSS AlgorithmParameters", e);
             }
         }
diff --git a/common/src/main/java/org/conscrypt/OpenSSLSocketImpl.java b/common/src/main/java/org/conscrypt/OpenSSLSocketImpl.java
index f490f54c..5aabdc35 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLSocketImpl.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLSocketImpl.java
@@ -111,19 +111,18 @@ public abstract class OpenSSLSocketImpl extends AbstractConscryptSocket {
     /**
      * @deprecated NPN is not supported
      */
-    @Override
     @Deprecated
+    @SuppressWarnings("InlineMeSuggester")
     public final byte[] getNpnSelectedProtocol() {
-        return super.getNpnSelectedProtocol();
+        return null;
     }
 
     /**
      * @deprecated NPN is not supported
      */
-    @Override
     @Deprecated
+    @SuppressWarnings("InlineMeSuggester")
     public final void setNpnProtocols(byte[] npnProtocols) {
-        super.setNpnProtocols(npnProtocols);
     }
 
     /**
diff --git a/common/src/main/java/org/conscrypt/OpenSSLX509CRL.java b/common/src/main/java/org/conscrypt/OpenSSLX509CRL.java
index ad974941..5b131d31 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLX509CRL.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLX509CRL.java
@@ -278,11 +278,13 @@ final class OpenSSLX509CRL extends X509CRL {
     }
 
     @Override
+    @SuppressWarnings({"JavaUtilDate"}) // Needed for API compatibility
     public Date getThisUpdate() {
         return (Date) thisUpdate.clone();
     }
 
     @Override
+    @SuppressWarnings({"JavaUtilDate"}) // Needed for API compatibility
     public Date getNextUpdate() {
         return (Date) nextUpdate.clone();
     }
@@ -412,7 +414,7 @@ final class OpenSSLX509CRL extends X509CRL {
     }
 
     @Override
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("Finalize")
     protected void finalize() throws Throwable {
         try {
             long toFree = mContext;
diff --git a/common/src/main/java/org/conscrypt/OpenSSLX509CRLEntry.java b/common/src/main/java/org/conscrypt/OpenSSLX509CRLEntry.java
index 9a3db624..46628afe 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLX509CRLEntry.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLX509CRLEntry.java
@@ -57,7 +57,7 @@ final class OpenSSLX509CRLEntry extends X509CRLEntry {
             return null;
         }
 
-        return new HashSet<String>(Arrays.asList(critOids));
+        return new HashSet<>(Arrays.asList(critOids));
     }
 
     @Override
@@ -82,7 +82,7 @@ final class OpenSSLX509CRLEntry extends X509CRLEntry {
             return null;
         }
 
-        return new HashSet<String>(Arrays.asList(critOids));
+        return new HashSet<>(Arrays.asList(critOids));
     }
 
     @Override
@@ -111,6 +111,7 @@ final class OpenSSLX509CRLEntry extends X509CRLEntry {
     }
 
     @Override
+    @SuppressWarnings("JavaUtilDate") // Needed for API compatibility
     public Date getRevocationDate() {
         return (Date) revocationDate.clone();
     }
diff --git a/common/src/main/java/org/conscrypt/OpenSSLX509Certificate.java b/common/src/main/java/org/conscrypt/OpenSSLX509Certificate.java
index 76849914..38afd3ef 100644
--- a/common/src/main/java/org/conscrypt/OpenSSLX509Certificate.java
+++ b/common/src/main/java/org/conscrypt/OpenSSLX509Certificate.java
@@ -74,13 +74,6 @@ public final class OpenSSLX509Certificate extends X509Certificate {
         notAfter = toDate(NativeCrypto.X509_get_notAfter(mContext, this));
     }
 
-    // A non-throwing constructor used when we have already parsed the dates
-    private OpenSSLX509Certificate(long ctx, Date notBefore, Date notAfter) {
-        mContext = ctx;
-        this.notBefore = notBefore;
-        this.notAfter = notAfter;
-    }
-
     private static Date toDate(long asn1time) throws ParsingException {
         Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
         calendar.set(Calendar.MILLISECOND, 0);
@@ -90,7 +83,6 @@ public final class OpenSSLX509Certificate extends X509Certificate {
 
     public static OpenSSLX509Certificate fromX509DerInputStream(InputStream is)
             throws ParsingException {
-        @SuppressWarnings("resource")
         final OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
 
         try {
@@ -117,7 +109,6 @@ public final class OpenSSLX509Certificate extends X509Certificate {
 
     public static List<OpenSSLX509Certificate> fromPkcs7DerInputStream(InputStream is)
             throws ParsingException {
-        @SuppressWarnings("resource")
         OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
 
         final long[] certRefs;
@@ -148,7 +139,6 @@ public final class OpenSSLX509Certificate extends X509Certificate {
 
     public static OpenSSLX509Certificate fromX509PemInputStream(InputStream is)
             throws ParsingException {
-        @SuppressWarnings("resource")
         final OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
 
         try {
@@ -166,7 +156,6 @@ public final class OpenSSLX509Certificate extends X509Certificate {
 
     public static List<OpenSSLX509Certificate> fromPkcs7PemInputStream(InputStream is)
             throws ParsingException {
-        @SuppressWarnings("resource")
         OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
 
         final long[] certRefs;
@@ -250,14 +239,14 @@ public final class OpenSSLX509Certificate extends X509Certificate {
     }
 
     @Override
-    @SuppressWarnings("JdkObsolete")  // Needed for API compatibility
+    @SuppressWarnings({"JdkObsolete", "JavaUtilDate"})  // Needed for API compatibility
     public void checkValidity() throws CertificateExpiredException,
             CertificateNotYetValidException {
         checkValidity(new Date());
     }
 
     @Override
-    @SuppressWarnings("JdkObsolete")  // Needed for API compatibility
+    @SuppressWarnings({"JdkObsolete", "JavaUtilDate"}) // Needed for API compatibility
     public void checkValidity(Date date) throws CertificateExpiredException,
             CertificateNotYetValidException {
         if (getNotBefore().compareTo(date) > 0) {
@@ -292,11 +281,13 @@ public final class OpenSSLX509Certificate extends X509Certificate {
     }
 
     @Override
+    @SuppressWarnings({"JavaUtilDate"}) // Needed for API compatibility
     public Date getNotBefore() {
         return (Date) notBefore.clone();
     }
 
     @Override
+    @SuppressWarnings({"JavaUtilDate"}) // Needed for API compatibility
     public Date getNotAfter() {
         return (Date) notAfter.clone();
     }
@@ -576,7 +567,7 @@ public final class OpenSSLX509Certificate extends X509Certificate {
     }
 
     @Override
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("Finalize")
     protected void finalize() throws Throwable {
         try {
             long toFree = mContext;
diff --git a/common/src/main/java/org/conscrypt/SSLParametersImpl.java b/common/src/main/java/org/conscrypt/SSLParametersImpl.java
index 3efa1c98..abb09e9c 100644
--- a/common/src/main/java/org/conscrypt/SSLParametersImpl.java
+++ b/common/src/main/java/org/conscrypt/SSLParametersImpl.java
@@ -35,7 +35,6 @@ import javax.net.ssl.KeyManagerFactory;
 import javax.net.ssl.SNIMatcher;
 import javax.net.ssl.TrustManager;
 import javax.net.ssl.TrustManagerFactory;
-import javax.net.ssl.X509ExtendedKeyManager;
 import javax.net.ssl.X509KeyManager;
 import javax.net.ssl.X509TrustManager;
 import javax.security.auth.x500.X500Principal;
@@ -219,44 +218,44 @@ final class SSLParametersImpl implements Cloneable {
         return (SSLParametersImpl) result.clone();
     }
 
-    /**
+    /*
      * Returns the appropriate session context.
      */
     AbstractSessionContext getSessionContext() {
         return client_mode ? clientSessionContext : serverSessionContext;
     }
 
-    /**
-     * @return client session context
+    /*
+     * Returns the client session context.
      */
     ClientSessionContext getClientSessionContext() {
         return clientSessionContext;
     }
 
     /**
-     * @return X.509 key manager or {@code null} for none.
+     * Returns X.509 key manager or null for none.
      */
     X509KeyManager getX509KeyManager() {
         return x509KeyManager;
     }
 
-    /**
-     * @return Pre-Shared Key (PSK) key manager or {@code null} for none.
+    /*
+     * Returns Pre-Shared Key (PSK) key manager or null for none.
      */
     @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
     PSKKeyManager getPSKKeyManager() {
         return pskKeyManager;
     }
 
-    /**
-     * @return X.509 trust manager or {@code null} for none.
+    /*
+     * Returns X.509 trust manager or null for none.
      */
     X509TrustManager getX509TrustManager() {
         return x509TrustManager;
     }
 
-    /**
-     * @return the names of enabled cipher suites
+    /*
+     * Returns the names of enabled cipher suites.
      */
     String[] getEnabledCipherSuites() {
         if (Arrays.asList(enabledProtocols).contains(NativeCrypto.SUPPORTED_PROTOCOL_TLSV1_3)) {
@@ -266,7 +265,7 @@ final class SSLParametersImpl implements Cloneable {
         return enabledCipherSuites.clone();
     }
 
-    /**
+    /*
      * Sets the enabled cipher suites after filtering through OpenSSL.
      */
     void setEnabledCipherSuites(String[] cipherSuites) {
@@ -278,16 +277,15 @@ final class SSLParametersImpl implements Cloneable {
                         NativeCrypto.SUPPORTED_TLS_1_3_CIPHER_SUITES_SET));
     }
 
-    /**
-     * @return the set of enabled protocols
+    /*
+     * Returns the set of enabled protocols.
      */
     String[] getEnabledProtocols() {
         return enabledProtocols.clone();
     }
 
-    /**
+    /*
      * Sets the list of available protocols for use in SSL connection.
-     * @throws IllegalArgumentException if {@code protocols == null}
      */
     void setEnabledProtocols(String[] protocols) {
         if (protocols == null) {
@@ -305,10 +303,8 @@ final class SSLParametersImpl implements Cloneable {
         enabledProtocols = NativeCrypto.checkEnabledProtocols(filteredProtocols).clone();
     }
 
-    /**
+    /*
      * Sets the list of ALPN protocols.
-     *
-     * @param protocols the list of ALPN protocols
      */
     void setApplicationProtocols(String[] protocols) {
         this.applicationProtocols = SSLUtils.encodeProtocols(protocols);
@@ -318,30 +314,29 @@ final class SSLParametersImpl implements Cloneable {
         return SSLUtils.decodeProtocols(applicationProtocols);
     }
 
-    /**
+    /*
      * Used for server-mode only. Sets or clears the application-provided ALPN protocol selector.
-     * If set, will override the protocol list provided by {@link #setApplicationProtocols(String[])}.
+     * If set, will override the protocol list provided by setApplicationProtocols(String[]).
      */
     void setApplicationProtocolSelector(ApplicationProtocolSelectorAdapter applicationProtocolSelector) {
         this.applicationProtocolSelector = applicationProtocolSelector;
     }
 
-    /**
+    /*
      * Returns the application protocol (ALPN) selector for this socket.
      */
     ApplicationProtocolSelectorAdapter getApplicationProtocolSelector() {
         return applicationProtocolSelector;
     }
 
-    /**
+    /*
      * Tunes the peer holding this parameters to work in client mode.
-     * @param   mode if the peer is configured to work in client mode
      */
     void setUseClientMode(boolean mode) {
         client_mode = mode;
     }
 
-    /**
+    /*
      * Returns the value indicating if the parameters configured to work
      * in client mode.
      */
@@ -349,8 +344,8 @@ final class SSLParametersImpl implements Cloneable {
         return client_mode;
     }
 
-    /**
-     * Tunes the peer holding this parameters to require client authentication
+    /*
+     * Tunes the peer holding this parameters to require client authentication.
      */
     void setNeedClientAuth(boolean need) {
         need_client_auth = need;
@@ -358,15 +353,15 @@ final class SSLParametersImpl implements Cloneable {
         want_client_auth = false;
     }
 
-    /**
+    /*
      * Returns the value indicating if the peer with this parameters tuned
-     * to require client authentication
+     * to require client authentication.
      */
     boolean getNeedClientAuth() {
         return need_client_auth;
     }
 
-    /**
+    /*
      * Tunes the peer holding this parameters to request client authentication
      */
     void setWantClientAuth(boolean want) {
@@ -375,7 +370,7 @@ final class SSLParametersImpl implements Cloneable {
         need_client_auth = false;
     }
 
-    /**
+    /*
      * Returns the value indicating if the peer with this parameters
      * tuned to request client authentication
      */
@@ -383,17 +378,17 @@ final class SSLParametersImpl implements Cloneable {
         return want_client_auth;
     }
 
-    /**
+    /*
      * Allows/disallows the peer holding this parameters to
-     * create new SSL session
+     * create new SSL session.
      */
     void setEnableSessionCreation(boolean flag) {
         enable_session_creation = flag;
     }
 
-    /**
+    /*
      * Returns the value indicating if the peer with this parameters
-     * allowed to cteate new SSL session
+     * allowed to cteate new SSL session.
      */
     boolean getEnableSessionCreation() {
         return enable_session_creation;
@@ -403,7 +398,7 @@ final class SSLParametersImpl implements Cloneable {
         this.useSessionTickets = useSessionTickets;
     }
 
-    /**
+    /*
      * Whether connections using this SSL connection should use the TLS
      * extension Server Name Indication (SNI).
      */
@@ -411,7 +406,7 @@ final class SSLParametersImpl implements Cloneable {
         useSni = flag;
     }
 
-    /**
+    /*
      * Returns whether connections using this SSL connection should use the TLS
      * extension Server Name Indication (SNI).
      */
@@ -419,21 +414,21 @@ final class SSLParametersImpl implements Cloneable {
         return useSni != null ? useSni : isSniEnabledByDefault();
     }
 
-    /**
+    /*
      * For testing only.
      */
     void setCTVerificationEnabled(boolean enabled) {
         ctVerificationEnabled = enabled;
     }
 
-    /**
+    /*
      * For testing only.
      */
     void setSCTExtension(byte[] extension) {
         sctExtension = extension;
     }
 
-    /**
+    /*
      * For testing only.
      */
     void setOCSPResponse(byte[] response) {
@@ -444,9 +439,9 @@ final class SSLParametersImpl implements Cloneable {
         return ocspResponse;
     }
 
-    /**
-     * This filters {@code obsoleteProtocol} from the list of {@code protocols}
-     * down to help with app compatibility.
+    /*
+     * Filters obsoleteProtocols from the list of protocols
+     * to help with app compatibility.
      */
     private static String[] filterFromProtocols(String[] protocols,
         List<String> obsoleteProtocols) {
@@ -454,7 +449,7 @@ final class SSLParametersImpl implements Cloneable {
             return EMPTY_STRING_ARRAY;
         }
 
-        ArrayList<String> newProtocols = new ArrayList<String>();
+        ArrayList<String> newProtocols = new ArrayList<>();
         for (String protocol : protocols) {
             if (!obsoleteProtocols.contains(protocol)) {
                 newProtocols.add(protocol);
@@ -467,7 +462,7 @@ final class SSLParametersImpl implements Cloneable {
         if (cipherSuites == null || cipherSuites.length == 0) {
             return cipherSuites;
         }
-        ArrayList<String> newCipherSuites = new ArrayList<String>(cipherSuites.length);
+        ArrayList<String> newCipherSuites = new ArrayList<>(cipherSuites.length);
         for (String cipherSuite : cipherSuites) {
             if (!toRemove.contains(cipherSuite)) {
                 newCipherSuites.add(cipherSuite);
@@ -478,7 +473,7 @@ final class SSLParametersImpl implements Cloneable {
 
     private static final String[] EMPTY_STRING_ARRAY = new String[0];
 
-    /**
+    /*
      * Returns whether Server Name Indication (SNI) is enabled by default for
      * sockets. For more information on SNI, see RFC 6066 section 3.
      */
@@ -498,11 +493,11 @@ final class SSLParametersImpl implements Cloneable {
         }
     }
 
-    /**
+    /*
      * For abstracting the X509KeyManager calls between
-     * {@link X509KeyManager#chooseClientAlias(String[], java.security.Principal[], java.net.Socket)}
+     * X509KeyManager#chooseClientAlias(String[], java.security.Principal[], java.net.Socket)
      * and
-     * {@link X509ExtendedKeyManager#chooseEngineClientAlias(String[], java.security.Principal[], javax.net.ssl.SSLEngine)}
+     * X509ExtendedKeyManager#chooseEngineClientAlias(String[], java.security.Principal[], javax.net.ssl.SSLEngine)
      */
     interface AliasChooser {
         String chooseClientAlias(X509KeyManager keyManager, X500Principal[] issuers,
@@ -511,9 +506,9 @@ final class SSLParametersImpl implements Cloneable {
         String chooseServerAlias(X509KeyManager keyManager, String keyType);
     }
 
-    /**
-     * For abstracting the {@code PSKKeyManager} calls between those taking an {@code SSLSocket} and
-     * those taking an {@code SSLEngine}.
+    /*
+     * For abstracting the PSKKeyManager calls between those taking an SSLSocket and
+     * those taking an SSLEngine.
      */
     @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
     interface PSKCallbacks {
@@ -522,9 +517,9 @@ final class SSLParametersImpl implements Cloneable {
         SecretKey getPSKKey(PSKKeyManager keyManager, String identityHint, String identity);
     }
 
-    /**
+    /*
      * Returns the clone of this object.
-     * @return the clone.
+     * TODO(prb): Shouldn't need to override this anymore.
      */
     @Override
     protected Object clone() {
@@ -569,10 +564,8 @@ final class SSLParametersImpl implements Cloneable {
         }
     }
 
-    /**
-     * Finds the first {@link X509KeyManager} element in the provided array.
-     *
-     * @return the first {@code X509KeyManager} or {@code null} if not found.
+    /*
+     * Returns the first X509KeyManager element in the provided array.
      */
     private static X509KeyManager findFirstX509KeyManager(KeyManager[] kms) {
         for (KeyManager km : kms) {
@@ -583,10 +576,8 @@ final class SSLParametersImpl implements Cloneable {
         return null;
     }
 
-    /**
-     * Finds the first {@link PSKKeyManager} element in the provided array.
-     *
-     * @return the first {@code PSKKeyManager} or {@code null} if not found.
+    /*
+     * Returns the first PSKKeyManager element in the provided array.
      */
     @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
     private static PSKKeyManager findFirstPSKKeyManager(KeyManager[] kms) {
@@ -604,8 +595,8 @@ final class SSLParametersImpl implements Cloneable {
         return null;
     }
 
-    /**
-     * Gets the default X.509 trust manager.
+    /*
+     * Returns the default X.509 trust manager.
      */
     static X509TrustManager getDefaultX509TrustManager()
             throws KeyManagementException {
@@ -638,11 +629,8 @@ final class SSLParametersImpl implements Cloneable {
         }
     }
 
-    /**
-     * Finds the first {@link X509TrustManager} element in the provided array.
-     *
-     * @return the first {@code X509ExtendedTrustManager} or
-     *         {@code X509TrustManager} or {@code null} if not found.
+    /*
+     * Returns the first X509TrustManager element in the provided array.
      */
     private static X509TrustManager findFirstX509TrustManager(TrustManager[] tms) {
         for (TrustManager tm : tms) {
@@ -721,8 +709,8 @@ final class SSLParametersImpl implements Cloneable {
         }
     }
 
-    /**
-     * Check if SCT verification is enforced for a given hostname.
+    /*
+     * Checks whether SCT verification is enforced for a given hostname.
      */
     boolean isCTVerificationEnabled(String hostname) {
         if (hostname == null) {
diff --git a/common/src/main/java/org/conscrypt/TrustManagerImpl.java b/common/src/main/java/org/conscrypt/TrustManagerImpl.java
index 31937ef8..24b63ab9 100644
--- a/common/src/main/java/org/conscrypt/TrustManagerImpl.java
+++ b/common/src/main/java/org/conscrypt/TrustManagerImpl.java
@@ -60,7 +60,6 @@ import java.security.cert.PKIXRevocationChecker.Option;
 import java.security.cert.TrustAnchor;
 import java.security.cert.X509Certificate;
 import java.util.ArrayList;
-import java.util.Arrays;
 import java.util.Collection;
 import java.util.Collections;
 import java.util.Comparator;
@@ -109,7 +108,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     /**
      * The CertPinManager, which validates the chain against a host-to-pin mapping
      */
-    private CertPinManager pinManager;
+    private final CertPinManager pinManager;
 
     /**
      * The backing store for the AndroidCAStore if non-null. This will
@@ -142,7 +141,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     private final Exception err;
     private final CertificateFactory factory;
     private final CertBlocklist blocklist;
-    private LogStore ctLogStore;
+    private final LogStore ctLogStore;
     private Verifier ctVerifier;
     private Policy ctPolicy;
 
@@ -194,10 +193,8 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
                 rootKeyStoreLocal = keyStore;
                 trustedCertificateStoreLocal =
                     (certStore != null) ? certStore : Platform.newDefaultCertStore();
-                acceptedIssuersLocal = null;
                 trustedCertificateIndexLocal = new TrustedCertificateIndex();
             } else {
-                rootKeyStoreLocal = null;
                 trustedCertificateStoreLocal = certStore;
                 acceptedIssuersLocal = acceptedIssuers(keyStore);
                 trustedCertificateIndexLocal
@@ -249,7 +246,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
 
             // TODO remove duplicates if same cert is found in both a
             // PrivateKeyEntry and TrustedCertificateEntry
-            List<X509Certificate> trusted = new ArrayList<X509Certificate>();
+            List<X509Certificate> trusted = new ArrayList<>();
             for (Enumeration<String> en = ks.aliases(); en.hasMoreElements();) {
                 final String alias = en.nextElement();
                 final X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
@@ -257,14 +254,14 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
                     trusted.add(cert);
                 }
             }
-            return trusted.toArray(new X509Certificate[trusted.size()]);
+            return trusted.toArray(new X509Certificate[0]);
         } catch (KeyStoreException e) {
             return new X509Certificate[0];
         }
     }
 
     private static Set<TrustAnchor> trustAnchors(X509Certificate[] certs) {
-        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>(certs.length);
+        Set<TrustAnchor> trustAnchors = new HashSet<>(certs.length);
         for (X509Certificate cert : certs) {
             trustAnchors.add(new TrustAnchor(cert, null));
         }
@@ -333,9 +330,18 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
                 false);
     }
 
+    /**
+     * For compatibility with network stacks that cannot provide an SSLSession nor a
+     * Socket (e.g., Cronet).
+     */
+    public List<X509Certificate> checkServerTrusted(X509Certificate[] chain, byte[] ocspData,
+            byte[] tlsSctData, String authType, String hostname) throws CertificateException {
+        return checkTrusted(chain, ocspData, tlsSctData, authType, hostname, false);
+    }
+
     /**
      * Returns the full trusted certificate chain found from {@code certs}.
-     *
+     * <p>
      * Throws {@link CertificateException} when no trusted chain can be found from {@code certs}.
      */
     public List<X509Certificate> getTrustedChainForServer(X509Certificate[] certs,
@@ -352,7 +358,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
 
     /**
      * Returns the full trusted certificate chain found from {@code certs}.
-     *
+     * <p>
      * Throws {@link CertificateException} when no trusted chain can be found from {@code certs}.
      */
     public List<X509Certificate> getTrustedChainForServer(X509Certificate[] certs,
@@ -476,15 +482,15 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     private List<X509Certificate> checkTrusted(X509Certificate[] certs, byte[] ocspData,
             byte[] tlsSctData, String authType, String host, boolean clientAuth)
             throws CertificateException {
-        if (certs == null || certs.length == 0 || authType == null || authType.length() == 0) {
+        if (certs == null || certs.length == 0 || authType == null || authType.isEmpty()) {
             throw new IllegalArgumentException("null or zero-length parameter");
         }
         if (err != null) {
             throw new CertificateException(err);
         }
-        Set<X509Certificate> used = new HashSet<X509Certificate>();
-        ArrayList<X509Certificate> untrustedChain = new ArrayList<X509Certificate>();
-        ArrayList<TrustAnchor> trustedChain = new ArrayList<TrustAnchor>();
+        Set<X509Certificate> used = new HashSet<>();
+        List<X509Certificate> untrustedChain = new ArrayList<>();
+        List<TrustAnchor> trustedChain = new ArrayList<>();
         // Initialize the chain to contain the leaf certificate. This potentially could be a trust
         // anchor. If the leaf is a trust anchor we still continue with path building to build the
         // complete trusted chain for additional validation such as certificate pinning.
@@ -504,7 +510,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     /**
      * Recursively build certificate chains until a valid chain is found or all possible paths are
      * exhausted.
-     *
+     * <p>
      * The chain is built in two sections, the complete trusted path is the the combination of
      * {@code untrustedChain} and {@code trustAnchorChain}. The chain begins at the leaf
      * certificate and ends in the final trusted root certificate.
@@ -526,7 +532,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
      */
     private List<X509Certificate> checkTrustedRecursive(X509Certificate[] certs, byte[] ocspData,
             byte[] tlsSctData, String host, boolean clientAuth,
-            ArrayList<X509Certificate> untrustedChain, ArrayList<TrustAnchor> trustAnchorChain,
+            List<X509Certificate> untrustedChain, List<TrustAnchor> trustAnchorChain,
             Set<X509Certificate> used) throws CertificateException {
         CertificateException lastException = null;
         X509Certificate current;
@@ -668,8 +674,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
                         "Trust anchor for certification path not found.", null, certPath, -1));
             }
 
-            List<X509Certificate> wholeChain = new ArrayList<X509Certificate>();
-            wholeChain.addAll(untrustedChain);
+            List<X509Certificate> wholeChain = new ArrayList<>(untrustedChain);
             for (TrustAnchor anchor : trustAnchorChain) {
                 wholeChain.add(anchor.getTrustedCert());
             }
@@ -698,7 +703,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
 
             // Validate the untrusted part of the chain
             try {
-                Set<TrustAnchor> anchorSet = new HashSet<TrustAnchor>();
+                Set<TrustAnchor> anchorSet = new HashSet<>();
                 // We know that untrusted chains to the first trust anchor, only add that.
                 anchorSet.add(trustAnchorChain.get(0));
                 PKIXParameters params = new PKIXParameters(anchorSet);
@@ -762,7 +767,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
 
         PKIXRevocationChecker revChecker = null;
         List<PKIXCertPathChecker> checkers =
-                new ArrayList<PKIXCertPathChecker>(params.getCertPathCheckers());
+                new ArrayList<>(params.getCertPathCheckers());
         for (PKIXCertPathChecker checker : checkers) {
             if (checker instanceof PKIXRevocationChecker) {
                 revChecker = (PKIXRevocationChecker) checker;
@@ -803,7 +808,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         if (anchors.size() <= 1) {
             return anchors;
         }
-        List<TrustAnchor> sortedAnchors = new ArrayList<TrustAnchor>(anchors);
+        List<TrustAnchor> sortedAnchors = new ArrayList<>(anchors);
         Collections.sort(sortedAnchors, TRUST_ANCHOR_COMPARATOR);
         return sortedAnchors;
     }
@@ -848,7 +853,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         private static final String EKU_msSGC = "1.3.6.1.4.1.311.10.3.3";
 
         private static final Set<String> SUPPORTED_EXTENSIONS
-                = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(EKU_OID)));
+                = Collections.unmodifiableSet(new HashSet<>(Collections.singletonList(EKU_OID)));
 
         private final boolean clientAuth;
         private final X509Certificate leaf;
@@ -859,7 +864,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         }
 
         @Override
-        public void init(boolean forward) throws CertPathValidatorException {
+        public void init(boolean forward) {
         }
 
         @Override
@@ -946,7 +951,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         if (storeAnchors.isEmpty()) {
             return indexedAnchors;
         }
-        Set<TrustAnchor> result = new HashSet<TrustAnchor>(storeAnchors.size());
+        Set<TrustAnchor> result = new HashSet<>(storeAnchors.size());
         for (X509Certificate storeCert : storeAnchors) {
             result.add(trustedCertificateIndex.index(storeCert));
         }
diff --git a/common/src/main/java/org/conscrypt/ct/CertificateEntry.java b/common/src/main/java/org/conscrypt/ct/CertificateEntry.java
index 137ded1e..2cee3e44 100644
--- a/common/src/main/java/org/conscrypt/ct/CertificateEntry.java
+++ b/common/src/main/java/org/conscrypt/ct/CertificateEntry.java
@@ -42,8 +42,20 @@ import org.conscrypt.OpenSSLX509Certificate;
 @Internal
 public class CertificateEntry {
     public enum LogEntryType {
-        X509_ENTRY,
-        PRECERT_ENTRY
+        X509_ENTRY(0),
+        PRECERT_ENTRY(1)
+        ;
+        private final int value;
+
+        LogEntryType(int value) {
+            this.value = value;
+        }
+
+        int value() {
+            return value;
+        }
+
+
     }
 
     private final LogEntryType entryType;
@@ -124,7 +136,7 @@ public class CertificateEntry {
      * TLS encode the CertificateEntry structure.
      */
     public void encode(OutputStream output) throws SerializationException {
-        Serialization.writeNumber(output, entryType.ordinal(), Constants.LOG_ENTRY_TYPE_LENGTH);
+        Serialization.writeNumber(output, entryType.value(), Constants.LOG_ENTRY_TYPE_LENGTH);
         if (entryType == LogEntryType.PRECERT_ENTRY) {
             Serialization.writeFixedBytes(output, issuerKeyHash);
         }
diff --git a/common/src/main/java/org/conscrypt/ct/LogStore.java b/common/src/main/java/org/conscrypt/ct/LogStore.java
index 10e099c3..70208ad8 100644
--- a/common/src/main/java/org/conscrypt/ct/LogStore.java
+++ b/common/src/main/java/org/conscrypt/ct/LogStore.java
@@ -33,6 +33,14 @@ public interface LogStore {
 
     State getState();
 
+    int getMajorVersion();
+
+    int getMinorVersion();
+
+    int getCompatVersion();
+
+    int getMinCompatVersionAvailable();
+
     long getTimestamp();
 
     LogInfo getKnownLog(byte[] logId);
diff --git a/common/src/main/java/org/conscrypt/ct/SignedCertificateTimestamp.java b/common/src/main/java/org/conscrypt/ct/SignedCertificateTimestamp.java
index 8ad3788b..366079b4 100644
--- a/common/src/main/java/org/conscrypt/ct/SignedCertificateTimestamp.java
+++ b/common/src/main/java/org/conscrypt/ct/SignedCertificateTimestamp.java
@@ -28,19 +28,40 @@ import org.conscrypt.Internal;
 @Internal
 public class SignedCertificateTimestamp {
     public enum Version {
-        V1
-    };
+            V1(0)
+        ;
+
+        private final int value;
+
+        Version(int value) {
+            this.value = value;
+        }
+
+        int value() {
+            return value;
+        }
+    }
 
     public enum SignatureType {
-        CERTIFICATE_TIMESTAMP,
-        TREE_HASH
-    };
+        CERTIFICATE_TIMESTAMP(0),
+        TREE_HASH(1)
+        ;
+        private final int value;
+
+        SignatureType(int value) {
+            this.value = value;
+        }
+
+        int value() {
+            return value;
+        }
+    }
 
     public enum Origin {
         EMBEDDED,
         TLS_EXTENSION,
         OCSP_RESPONSE
-    };
+    }
 
     private final Version version;
     private final byte[] logId;
@@ -88,7 +109,7 @@ public class SignedCertificateTimestamp {
     public static SignedCertificateTimestamp decode(InputStream input, Origin origin)
             throws SerializationException {
         int version = Serialization.readNumber(input, Constants.VERSION_LENGTH);
-        if (version != Version.V1.ordinal()) {
+        if (version != Version.V1.value()) {
             throw new SerializationException("Unsupported SCT version " + version);
         }
 
@@ -112,8 +133,8 @@ public class SignedCertificateTimestamp {
      */
     public void encodeTBS(OutputStream output, CertificateEntry certEntry)
             throws SerializationException {
-        Serialization.writeNumber(output, version.ordinal(), Constants.VERSION_LENGTH);
-        Serialization.writeNumber(output, SignatureType.CERTIFICATE_TIMESTAMP.ordinal(),
+        Serialization.writeNumber(output, version.value(), Constants.VERSION_LENGTH);
+        Serialization.writeNumber(output, SignatureType.CERTIFICATE_TIMESTAMP.value(),
                 Constants.SIGNATURE_TYPE_LENGTH);
         Serialization.writeNumber(output, timestamp, Constants.TIMESTAMP_LENGTH);
         certEntry.encode(output);
diff --git a/common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java b/common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java
deleted file mode 100644
index e8f463a3..00000000
--- a/common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java
+++ /dev/null
@@ -1,47 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
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
-package org.conscrypt.metrics;
-
-import org.conscrypt.Internal;
-
-/**
- * Reimplement with reflection calls the logging class,
- * generated by frameworks/statsd.
- * <p>
- * In case atom is changed, generate new wrapper with stats-log-api-gen
- * tool as shown below and add corresponding methods to ReflexiveStatsEvent's
- * newEvent() method.
- * <p>
- * $ stats-log-api-gen \
- *   --java "common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java" \
- *   --module conscrypt \
- *   --javaPackage org.conscrypt.metrics \
- *   --javaClass ConscryptStatsLog
- **/
-@Internal
-public final class ConscryptStatsLog {
-    public static final int TLS_HANDSHAKE_REPORTED = 317;
-
-    private ConscryptStatsLog() {}
-
-    public static void write(int atomId, boolean success, int protocol, int cipherSuite,
-            int duration, Source source, int[] uids) {
-        ReflexiveStatsEvent event = ReflexiveStatsEvent.buildEvent(
-                atomId, success, protocol, cipherSuite, duration, source.ordinal(), uids);
-
-        ReflexiveStatsLog.write(event);
-    }
-}
diff --git a/common/src/main/java/org/conscrypt/metrics/StatsLog.java b/common/src/main/java/org/conscrypt/metrics/StatsLog.java
new file mode 100644
index 00000000..81f15d5e
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/metrics/StatsLog.java
@@ -0,0 +1,27 @@
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
+package org.conscrypt.metrics;
+
+import org.conscrypt.Internal;
+import org.conscrypt.ct.LogStore;
+
+@Internal
+public interface StatsLog {
+    public void countTlsHandshake(
+            boolean success, String protocol, String cipherSuite, long duration);
+
+    public void updateCTLogListStatusChanged(LogStore logStore);
+}
diff --git a/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java b/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java
new file mode 100644
index 00000000..a47bac9d
--- /dev/null
+++ b/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java
@@ -0,0 +1,155 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+package org.conscrypt.metrics;
+
+import org.conscrypt.Internal;
+import org.conscrypt.Platform;
+import org.conscrypt.ct.LogStore;
+
+import java.lang.Thread.UncaughtExceptionHandler;
+import java.util.concurrent.ArrayBlockingQueue;
+import java.util.concurrent.ExecutorService;
+import java.util.concurrent.Executors;
+import java.util.concurrent.ThreadFactory;
+import java.util.concurrent.ThreadPoolExecutor;
+import java.util.concurrent.TimeUnit;
+
+/**
+ * Reimplement with reflection calls the logging class,
+ * generated by frameworks/statsd.
+ * <p>
+ * In case atom is changed, generate new wrapper with stats-log-api-gen
+ * tool as shown below and add corresponding methods to ReflexiveStatsEvent's
+ * newEvent() method.
+ * <p>
+ * $ stats-log-api-gen \
+ *   --java "common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java" \
+ *   --module conscrypt \
+ *   --javaPackage org.conscrypt.metrics \
+ *   --javaClass StatsLog
+ **/
+@Internal
+public final class StatsLogImpl implements StatsLog {
+    /**
+     * TlsHandshakeReported tls_handshake_reported
+     * Usage: StatsLog.write(StatsLog.TLS_HANDSHAKE_REPORTED, boolean success, int protocol, int
+     * cipher_suite, int handshake_duration_millis, int source, int[] uid);<br>
+     */
+    public static final int TLS_HANDSHAKE_REPORTED = 317;
+
+    /**
+     * CertificateTransparencyLogListStateChanged certificate_transparency_log_list_state_changed
+     * Usage: StatsLog.write(StatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED, int status,
+     * int loaded_compat_version, int min_compat_version_available, int major_version, int
+     * minor_version);<br>
+     */
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED = 934;
+
+    private static final ExecutorService e = Executors.newSingleThreadExecutor(new ThreadFactory() {
+        @Override
+        public Thread newThread(Runnable r) {
+            Thread thread = new Thread(r);
+            thread.setUncaughtExceptionHandler(new UncaughtExceptionHandler() {
+                @Override
+                public void uncaughtException(Thread t, Throwable e) {
+                    // Ignore
+                }
+            });
+            return thread;
+        }
+    });
+
+    private static final StatsLog INSTANCE = new StatsLogImpl();
+    private StatsLogImpl() {}
+    public static StatsLog getInstance() {
+        return INSTANCE;
+    }
+
+    @Override
+    public void countTlsHandshake(
+            boolean success, String protocol, String cipherSuite, long duration) {
+        Protocol proto = Protocol.forName(protocol);
+        CipherSuite suite = CipherSuite.forName(cipherSuite);
+
+        write(TLS_HANDSHAKE_REPORTED, success, proto.getId(), suite.getId(), (int) duration,
+                Platform.getStatsSource().ordinal(), Platform.getUids());
+    }
+
+    private static int logStoreStateToMetricsState(LogStore.State state) {
+        /* These constants must match the atom LogListStatus
+         * from frameworks/proto_logging/stats/atoms/conscrypt/conscrypt_extension_atoms.proto
+         */
+        final int METRIC_UNKNOWN = 0;
+        final int METRIC_SUCCESS = 1;
+        final int METRIC_NOT_FOUND = 2;
+        final int METRIC_PARSING_FAILED = 3;
+        final int METRIC_EXPIRED = 4;
+
+        switch (state) {
+            case UNINITIALIZED:
+            case LOADED:
+                return METRIC_UNKNOWN;
+            case NOT_FOUND:
+                return METRIC_NOT_FOUND;
+            case MALFORMED:
+                return METRIC_PARSING_FAILED;
+            case COMPLIANT:
+                return METRIC_SUCCESS;
+            case NON_COMPLIANT:
+                return METRIC_EXPIRED;
+        }
+        return METRIC_UNKNOWN;
+    }
+
+    @Override
+    public void updateCTLogListStatusChanged(LogStore logStore) {
+        int state = logStoreStateToMetricsState(logStore.getState());
+        write(CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED, state, logStore.getCompatVersion(),
+                logStore.getMinCompatVersionAvailable(), logStore.getMajorVersion(),
+                logStore.getMinorVersion());
+    }
+
+    private void write(int atomId, boolean success, int protocol, int cipherSuite, int duration,
+            int source, int[] uids) {
+        e.execute(new Runnable() {
+            @Override
+            public void run() {
+                ReflexiveStatsEvent event = ReflexiveStatsEvent.buildEvent(
+                        atomId, success, protocol, cipherSuite, duration, source, uids);
+
+                ReflexiveStatsLog.write(event);
+            }
+        });
+    }
+
+    private void write(int atomId, int status, int loadedCompatVersion,
+            int minCompatVersionAvailable, int majorVersion, int minorVersion) {
+        e.execute(new Runnable() {
+            @Override
+            public void run() {
+                ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
+                builder.setAtomId(atomId);
+                builder.writeInt(status);
+                builder.writeInt(loadedCompatVersion);
+                builder.writeInt(minCompatVersionAvailable);
+                builder.writeInt(majorVersion);
+                builder.writeInt(minorVersion);
+                builder.usePooledBuffer();
+                ReflexiveStatsLog.write(builder.build());
+            }
+        });
+    }
+}
diff --git a/common/src/test/java/org/conscrypt/ChainStrengthAnalyzerTest.java b/common/src/test/java/org/conscrypt/ChainStrengthAnalyzerTest.java
index d6b09459..992c272b 100644
--- a/common/src/test/java/org/conscrypt/ChainStrengthAnalyzerTest.java
+++ b/common/src/test/java/org/conscrypt/ChainStrengthAnalyzerTest.java
@@ -20,6 +20,7 @@ import static org.junit.Assert.fail;
 
 import java.io.ByteArrayInputStream;
 import java.io.InputStream;
+import java.nio.charset.StandardCharsets;
 import java.security.NoSuchAlgorithmException;
 import java.security.cert.CertificateException;
 import java.security.cert.CertificateFactory;
@@ -361,7 +362,7 @@ public class ChainStrengthAnalyzerTest {
 
     private static X509Certificate createCert(String pem) throws Exception {
         CertificateFactory cf = CertificateFactory.getInstance("X509");
-        InputStream pemInput = new ByteArrayInputStream(pem.getBytes("UTF-8"));
+        InputStream pemInput = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8));
         return (X509Certificate) cf.generateCertificate(pemInput);
     }
 }
diff --git a/common/src/test/java/org/conscrypt/ct/VerifierTest.java b/common/src/test/java/org/conscrypt/ct/VerifierTest.java
index e99832da..016da7f2 100644
--- a/common/src/test/java/org/conscrypt/ct/VerifierTest.java
+++ b/common/src/test/java/org/conscrypt/ct/VerifierTest.java
@@ -70,6 +70,26 @@ public class VerifierTest {
                 return 0;
             }
 
+            @Override
+            public int getMajorVersion() {
+                return 1;
+            }
+
+            @Override
+            public int getMinorVersion() {
+                return 2;
+            }
+
+            @Override
+            public int getCompatVersion() {
+                return 1;
+            }
+
+            @Override
+            public int getMinCompatVersionAvailable() {
+                return 1;
+            }
+
             @Override
             public LogInfo getKnownLog(byte[] logId) {
                 if (Arrays.equals(logId, log.getID())) {
diff --git a/common/src/test/java/org/conscrypt/java/security/KeyPairGeneratorTest.java b/common/src/test/java/org/conscrypt/java/security/KeyPairGeneratorTest.java
index 7140f1ab..819e1141 100644
--- a/common/src/test/java/org/conscrypt/java/security/KeyPairGeneratorTest.java
+++ b/common/src/test/java/org/conscrypt/java/security/KeyPairGeneratorTest.java
@@ -128,19 +128,15 @@ public class KeyPairGeneratorTest {
             });
     }
 
-    private static final Map<String, List<Integer>> KEY_SIZES
-            = new HashMap<String, List<Integer>>();
+    private static final Map<String, List<Integer>> KEY_SIZES = new HashMap<>();
     private static void putKeySize(String algorithm, int keySize) {
-        algorithm = algorithm.toUpperCase();
-        List<Integer> keySizes = KEY_SIZES.get(algorithm);
-        if (keySizes == null) {
-            keySizes = new ArrayList<Integer>();
-            KEY_SIZES.put(algorithm, keySizes);
-        }
+        algorithm = algorithm.toUpperCase(Locale.ROOT);
+        List<Integer> keySizes = KEY_SIZES.
+                computeIfAbsent(algorithm, k -> new ArrayList<>());
         keySizes.add(keySize);
     }
     private static List<Integer> getKeySizes(String algorithm) throws Exception {
-        algorithm = algorithm.toUpperCase();
+        algorithm = algorithm.toUpperCase(Locale.ROOT);
         List<Integer> keySizes = KEY_SIZES.get(algorithm);
         if (keySizes == null) {
             throw new Exception("Unknown key sizes for KeyPairGenerator." + algorithm);
@@ -203,7 +199,7 @@ public class KeyPairGeneratorTest {
             test_KeyPair(kpg, kpg.genKeyPair());
             test_KeyPair(kpg, kpg.generateKeyPair());
 
-            kpg.initialize(keySize, (SecureRandom) null);
+            kpg.initialize(keySize, null);
             test_KeyPair(kpg, kpg.genKeyPair());
             test_KeyPair(kpg, kpg.generateKeyPair());
 
@@ -224,7 +220,7 @@ public class KeyPairGeneratorTest {
                 test_KeyPair(kpg, kpg.genKeyPair());
                 test_KeyPair(kpg, kpg.generateKeyPair());
 
-                kpg.initialize(new ECGenParameterSpec(curveName), (SecureRandom) null);
+                kpg.initialize(new ECGenParameterSpec(curveName), null);
                 test_KeyPair(kpg, kpg.genKeyPair());
                 test_KeyPair(kpg, kpg.generateKeyPair());
 
@@ -246,7 +242,7 @@ public class KeyPairGeneratorTest {
         if (StandardNames.IS_RI && expectedAlgorithm.equals("DIFFIEHELLMAN")) {
             expectedAlgorithm = "DH";
         }
-        assertEquals(expectedAlgorithm, k.getAlgorithm().toUpperCase());
+        assertEquals(expectedAlgorithm, k.getAlgorithm().toUpperCase(Locale.ROOT));
         if (expectedAlgorithm.equals("DH")) {
             if (k instanceof DHPublicKey) {
                 DHPublicKey dhPub = (DHPublicKey) k;
@@ -375,7 +371,7 @@ public class KeyPairGeneratorTest {
     /**
      * DH parameters pre-generated so that the test doesn't take too long.
      * These parameters were generated with:
-     *
+     * <p>
      * openssl gendh 512 | openssl dhparams -C
      */
     private static DHParameterSpec getDHParams() {
diff --git a/common/src/test/java/org/conscrypt/java/security/MessageDigestTest.java b/common/src/test/java/org/conscrypt/java/security/MessageDigestTest.java
index c711dc16..c69e3b0e 100644
--- a/common/src/test/java/org/conscrypt/java/security/MessageDigestTest.java
+++ b/common/src/test/java/org/conscrypt/java/security/MessageDigestTest.java
@@ -20,9 +20,9 @@ import static org.junit.Assert.assertEquals;
 
 import java.security.MessageDigest;
 import java.security.NoSuchAlgorithmException;
-import java.security.Provider;
 import java.util.Arrays;
 import java.util.HashMap;
+import java.util.Locale;
 import java.util.Map;
 import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
 import org.conscrypt.TestUtils;
@@ -59,44 +59,38 @@ public final class MessageDigestTest {
     }
 
     @Test
-    public void test_getInstance() throws Exception {
+    public void test_getInstance() {
         ServiceTester.test("MessageDigest")
-            .run(new ServiceTester.Test() {
-                @Override
-                public void test(Provider provider, String algorithm) throws Exception {
-                    // MessageDigest.getInstance(String)
-                    MessageDigest md1 = MessageDigest.getInstance(algorithm);
-                    assertEquals(algorithm, md1.getAlgorithm());
-                    test_MessageDigest(md1);
+            .run((provider, algorithm) -> {
+                // MessageDigest.getInstance(String)
+                MessageDigest md1 = MessageDigest.getInstance(algorithm);
+                assertEquals(algorithm, md1.getAlgorithm());
+                test_MessageDigest(md1);
 
-                    // MessageDigest.getInstance(String, Provider)
-                    MessageDigest md2 = MessageDigest.getInstance(algorithm, provider);
-                    assertEquals(algorithm, md2.getAlgorithm());
-                    assertEquals(provider, md2.getProvider());
-                    test_MessageDigest(md2);
+                // MessageDigest.getInstance(String, Provider)
+                MessageDigest md2 = MessageDigest.getInstance(algorithm, provider);
+                assertEquals(algorithm, md2.getAlgorithm());
+                assertEquals(provider, md2.getProvider());
+                test_MessageDigest(md2);
 
-                    // MessageDigest.getInstance(String, String)
-                    MessageDigest md3 = MessageDigest.getInstance(algorithm, provider.getName());
-                    assertEquals(algorithm, md3.getAlgorithm());
-                    assertEquals(provider, md3.getProvider());
-                    test_MessageDigest(md3);
-                }
+                // MessageDigest.getInstance(String, String)
+                MessageDigest md3 = MessageDigest.getInstance(algorithm, provider.getName());
+                assertEquals(algorithm, md3.getAlgorithm());
+                assertEquals(provider, md3.getProvider());
+                test_MessageDigest(md3);
             });
     }
 
     private static final Map<String, Map<String, byte[]>> EXPECTATIONS
-            = new HashMap<String, Map<String, byte[]>>();
+            = new HashMap<>();
     private static void putExpectation(String algorithm, String inputName, byte[] expected) {
-        algorithm = algorithm.toUpperCase();
-        Map<String, byte[]> expectations = EXPECTATIONS.get(algorithm);
-        if (expectations == null) {
-            expectations = new HashMap<String, byte[]>();
-            EXPECTATIONS.put(algorithm, expectations);
-        }
+        algorithm = algorithm.toUpperCase(Locale.ROOT);
+        Map<String, byte[]> expectations =
+                EXPECTATIONS.computeIfAbsent(algorithm, k -> new HashMap<>());
         expectations.put(inputName, expected);
     }
     private static Map<String, byte[]> getExpectations(String algorithm) throws Exception {
-        algorithm = algorithm.toUpperCase();
+        algorithm = algorithm.toUpperCase(Locale.ROOT);
         Map<String, byte[]> expectations = EXPECTATIONS.get(algorithm);
         if (expectations == null) {
             throw new Exception("No expectations for MessageDigest." + algorithm);
@@ -251,7 +245,7 @@ public final class MessageDigestTest {
             if (inputName.equals(INPUT_EMPTY)) {
                 actual = md.digest();
             } else if (inputName.equals(INPUT_256MB)) {
-                byte[] mb = new byte[1 * 1024 * 1024];
+                byte[] mb = new byte[1024 * 1024];
                 for (int i = 0; i < 256; i++) {
                     md.update(mb);
                 }
diff --git a/common/src/test/java/org/conscrypt/java/security/SignatureTest.java b/common/src/test/java/org/conscrypt/java/security/SignatureTest.java
index bfaec851..6182acb9 100644
--- a/common/src/test/java/org/conscrypt/java/security/SignatureTest.java
+++ b/common/src/test/java/org/conscrypt/java/security/SignatureTest.java
@@ -26,6 +26,7 @@ import static org.junit.Assert.fail;
 import java.math.BigInteger;
 import java.nio.ByteBuffer;
 import java.nio.charset.Charset;
+import java.nio.charset.StandardCharsets;
 import java.security.AlgorithmParameters;
 import java.security.InvalidKeyException;
 import java.security.KeyFactory;
@@ -33,7 +34,6 @@ import java.security.KeyPair;
 import java.security.KeyPairGenerator;
 import java.security.MessageDigest;
 import java.security.PrivateKey;
-import java.security.Provider;
 import java.security.ProviderException;
 import java.security.PublicKey;
 import java.security.Security;
@@ -56,12 +56,10 @@ import java.security.spec.RSAPrivateKeySpec;
 import java.security.spec.RSAPublicKeySpec;
 import java.security.spec.X509EncodedKeySpec;
 import java.util.ArrayList;
-import java.util.Arrays;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Locale;
 import java.util.Map;
-import java.util.concurrent.Callable;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.ExecutionException;
 import java.util.concurrent.ExecutorService;
@@ -116,38 +114,35 @@ public class SignatureTest {
             .skipAlgorithm("Ed25519")
             .skipAlgorithm("EdDSA")
             .skipAlgorithm("HSS/LMS")
-            .run(new ServiceTester.Test() {
-                @Override
-                public void test(Provider provider, String algorithm) throws Exception {
-                    KeyPair kp = keyPair(algorithm);
-                    // Signature.getInstance(String)
-                    Signature sig1 = Signature.getInstance(algorithm);
-                    assertEquals(algorithm, sig1.getAlgorithm());
-                    test_Signature(sig1, kp);
-
-                    // Signature.getInstance(String, Provider)
-                    Signature sig2 = Signature.getInstance(algorithm, provider);
-                    assertEquals(algorithm, sig2.getAlgorithm());
-                    assertEquals(provider, sig2.getProvider());
-                    test_Signature(sig2, kp);
-
-                    // Signature.getInstance(String, String)
-                    Signature sig3 = Signature.getInstance(algorithm, provider.getName());
-                    assertEquals(algorithm, sig3.getAlgorithm());
-                    assertEquals(provider, sig3.getProvider());
-                    test_Signature(sig3, kp);
-                }
+            .run((provider, algorithm) -> {
+                KeyPair kp = keyPair(algorithm);
+                // Signature.getInstance(String)
+                Signature sig1 = Signature.getInstance(algorithm);
+                assertEquals(algorithm, sig1.getAlgorithm());
+                test_Signature(sig1, kp);
+
+                // Signature.getInstance(String, Provider)
+                Signature sig2 = Signature.getInstance(algorithm, provider);
+                assertEquals(algorithm, sig2.getAlgorithm());
+                assertEquals(provider, sig2.getProvider());
+                test_Signature(sig2, kp);
+
+                // Signature.getInstance(String, String)
+                Signature sig3 = Signature.getInstance(algorithm, provider.getName());
+                assertEquals(algorithm, sig3.getAlgorithm());
+                assertEquals(provider, sig3.getProvider());
+                test_Signature(sig3, kp);
             });
     }
 
     private final Map<String, KeyPair> keypairAlgorithmToInstance
-            = new HashMap<String, KeyPair>();
+            = new HashMap<>();
 
     private KeyPair keyPair(String sigAlgorithm) throws Exception {
-        String sigAlgorithmUpperCase = sigAlgorithm.toUpperCase(Locale.US);
+        String sigAlgorithmUpperCase = sigAlgorithm.toUpperCase(Locale.ROOT);
         if (sigAlgorithmUpperCase.endsWith("ENCRYPTION")) {
             sigAlgorithm = sigAlgorithm.substring(0, sigAlgorithm.length()-"ENCRYPTION".length());
-            sigAlgorithmUpperCase = sigAlgorithm.toUpperCase(Locale.US);
+            sigAlgorithmUpperCase = sigAlgorithm.toUpperCase(Locale.ROOT);
         }
 
         String kpAlgorithm;
@@ -220,6 +215,7 @@ public class SignatureTest {
                 sig.verify(signature);
                 fail("Expected RI to have a NONEwithDSA bug");
             } catch (SignatureException bug) {
+                // Expected
             }
         } else if (StandardNames.IS_RI
                 && "NONEwithECDSA".equalsIgnoreCase(sig.getAlgorithm())
@@ -229,6 +225,7 @@ public class SignatureTest {
                 sig.verify(signature);
                 fail("Expected RI to have a NONEwithECDSA bug");
             } catch (ProviderException bug) {
+                // Expected
             }
         } else {
             // Calling Signature.verify a second time should not throw
@@ -269,10 +266,10 @@ public class SignatureTest {
             + "56ac8c0e4ae12d97");
 
 
-    /**
+    /*
      * This should actually fail because the ASN.1 encoding is incorrect. It is
      * missing the NULL in the AlgorithmIdentifier field.
-     * <p>
+     *
      * http://code.google.com/p/android/issues/detail?id=18566 <br/>
      * http://b/5038554
      */
@@ -1955,8 +1952,8 @@ public class SignatureTest {
 
         byte[] signature = sig.sign();
         assertNotNull("Signature must not be null", signature);
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, SHA1withRSA_Vector1Signature));
+        assertArrayEquals("Signature should match expected",
+                signature, SHA1withRSA_Vector1Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -1976,9 +1973,7 @@ public class SignatureTest {
         final PrivateKey privKey;
         try {
             privKey = kf.generatePrivate(keySpec);
-        } catch (NullPointerException e) {
-            return;
-        } catch (InvalidKeySpecException e) {
+        } catch (NullPointerException | InvalidKeySpecException e) {
             return;
         }
 
@@ -2001,9 +1996,7 @@ public class SignatureTest {
         final PrivateKey privKey;
         try {
             privKey = kf.generatePrivate(keySpec);
-        } catch (NullPointerException e) {
-            return;
-        } catch (InvalidKeySpecException e) {
+        } catch (NullPointerException | InvalidKeySpecException e) {
             return;
         }
 
@@ -2025,9 +2018,7 @@ public class SignatureTest {
         final PrivateKey privKey;
         try {
             privKey = kf.generatePrivate(keySpec);
-        } catch (NullPointerException e) {
-            return;
-        } catch (InvalidKeySpecException e) {
+        } catch (NullPointerException | InvalidKeySpecException e) {
             return;
         }
 
@@ -2207,8 +2198,8 @@ public class SignatureTest {
         assertNotNull("Signature must not be null", signature);
         assertPSSAlgorithmParametersEquals(
                 SHA1withRSAPSS_NoSalt_Vector2Signature_ParameterSpec, sig.getParameters());
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, SHA1withRSAPSS_NoSalt_Vector2Signature));
+        assertArrayEquals("Signature should match expected",
+                signature, SHA1withRSAPSS_NoSalt_Vector2Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -2286,8 +2277,8 @@ public class SignatureTest {
         assertNotNull("Signature must not be null", signature);
         assertPSSAlgorithmParametersEquals(
                 SHA224withRSAPSS_NoSalt_Vector2Signature_ParameterSpec, sig.getParameters());
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, SHA224withRSAPSS_NoSalt_Vector2Signature));
+        assertArrayEquals("Signature should match expected",
+                signature, SHA224withRSAPSS_NoSalt_Vector2Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -2365,8 +2356,8 @@ public class SignatureTest {
         assertNotNull("Signature must not be null", signature);
         assertPSSAlgorithmParametersEquals(
                 SHA256withRSAPSS_NoSalt_Vector2Signature_ParameterSpec, sig.getParameters());
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, SHA256withRSAPSS_NoSalt_Vector2Signature));
+        assertArrayEquals("Signature should match expected",
+                signature, SHA256withRSAPSS_NoSalt_Vector2Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -2444,8 +2435,8 @@ public class SignatureTest {
         assertNotNull("Signature must not be null", signature);
         assertPSSAlgorithmParametersEquals(
                 SHA384withRSAPSS_NoSalt_Vector2Signature_ParameterSpec, sig.getParameters());
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, SHA384withRSAPSS_NoSalt_Vector2Signature));
+        assertArrayEquals("Signature should match expected",
+                signature, SHA384withRSAPSS_NoSalt_Vector2Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -2523,8 +2514,8 @@ public class SignatureTest {
         assertNotNull("Signature must not be null", signature);
         assertPSSAlgorithmParametersEquals(
                 SHA512withRSAPSS_NoSalt_Vector2Signature_ParameterSpec, sig.getParameters());
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, SHA512withRSAPSS_NoSalt_Vector2Signature));
+        assertArrayEquals("Signature should match expected",
+                signature, SHA512withRSAPSS_NoSalt_Vector2Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -2575,8 +2566,8 @@ public class SignatureTest {
 
         byte[] signature = sig.sign();
         assertNotNull("Signature must not be null", signature);
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, NONEwithRSA_Vector1Signature));
+        assertArrayEquals("Signature should match expected",
+                signature, NONEwithRSA_Vector1Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -2598,7 +2589,7 @@ public class SignatureTest {
         sig.initVerify(pubKey);
         sig.update(Vector1Data);
         assertFalse("Invalid signature must not verify",
-                sig.verify("Invalid".getBytes("UTF-8")));
+                sig.verify("Invalid".getBytes(StandardCharsets.UTF_8)));
     }
 
     @Test
@@ -2703,7 +2694,7 @@ public class SignatureTest {
         sig.update(Vector1Data);
 
         assertFalse("Invalid signature should not verify",
-                sig.verify("Invalid sig".getBytes("UTF-8")));
+                sig.verify("Invalid sig".getBytes(StandardCharsets.UTF_8)));
     }
 
     @Test
@@ -3084,24 +3075,21 @@ public class SignatureTest {
 
         final CountDownLatch latch = new CountDownLatch(THREAD_COUNT);
         final byte[] message = new byte[64];
-        List<Future<Void>> futures = new ArrayList<Future<Void>>();
+        List<Future<Void>> futures = new ArrayList<>();
 
         for (int i = 0; i < THREAD_COUNT; i++) {
-            futures.add(es.submit(new Callable<Void>() {
-                @Override
-                public Void call() throws Exception {
-                    // Try to make sure all the threads are ready first.
-                    latch.countDown();
-                    latch.await();
-
-                    for (int j = 0; j < 100; j++) {
-                        s.initSign(p);
-                        s.update(message);
-                        s.sign();
-                    }
-
-                    return null;
+            futures.add(es.submit(() -> {
+                // Try to make sure all the threads are ready first.
+                latch.countDown();
+                latch.await();
+
+                for (int j = 0; j < 100; j++) {
+                    s.initSign(p);
+                    s.update(message);
+                    s.sign();
                 }
+
+                return null;
             }));
         }
         es.shutdown();
@@ -3154,13 +3142,13 @@ public class SignatureTest {
         ecdsaVerify.initVerify(pub);
         ecdsaVerify.update(NAMED_CURVE_VECTOR);
         boolean result = ecdsaVerify.verify(NAMED_CURVE_SIGNATURE);
-        assertEquals(true, result);
+        assertTrue(result);
 
         ecdsaVerify = Signature.getInstance("SHA1withECDSA");
         ecdsaVerify.initVerify(pub);
-        ecdsaVerify.update("Not Satoshi Nakamoto".getBytes("UTF-8"));
+        ecdsaVerify.update("Not Satoshi Nakamoto".getBytes(StandardCharsets.UTF_8));
         result = ecdsaVerify.verify(NAMED_CURVE_SIGNATURE);
-        assertEquals(false, result);
+        assertFalse(result);
     }
 
     private static void assertPSSAlgorithmParametersEquals(
diff --git a/common/src/test/java/org/conscrypt/java/security/cert/CertificateFactoryTest.java b/common/src/test/java/org/conscrypt/java/security/cert/CertificateFactoryTest.java
index b5da74ab..e8fbbef8 100644
--- a/common/src/test/java/org/conscrypt/java/security/cert/CertificateFactoryTest.java
+++ b/common/src/test/java/org/conscrypt/java/security/cert/CertificateFactoryTest.java
@@ -440,7 +440,7 @@ public class CertificateFactoryTest {
             // which technically doesn't satisfy the method contract, but we'll accept it
             assertTrue((c == null) && cf.getProvider().getName().equals("BC"));
         } catch (CertificateException maybeExpected) {
-            assertFalse(cf.getProvider().getName().equals("BC"));
+            assertNotEquals("BC", cf.getProvider().getName());
         }
 
         try {
@@ -449,7 +449,7 @@ public class CertificateFactoryTest {
             // which technically doesn't satisfy the method contract, but we'll accept it
             assertTrue((c == null) && cf.getProvider().getName().equals("BC"));
         } catch (CertificateException maybeExpected) {
-            assertFalse(cf.getProvider().getName().equals("BC"));
+            assertNotEquals("BC", cf.getProvider().getName());
         }
 
     }
@@ -497,7 +497,7 @@ public class CertificateFactoryTest {
 
     }
 
-    private void test_generateCertificate_InputStream_Empty(CertificateFactory cf) throws Exception {
+    private void test_generateCertificate_InputStream_Empty(CertificateFactory cf) {
         try {
             Certificate c = cf.generateCertificate(new ByteArrayInputStream(new byte[0]));
             if (!"BC".equals(cf.getProvider().getName())) {
@@ -511,8 +511,7 @@ public class CertificateFactoryTest {
         }
     }
 
-    private void test_generateCertificate_InputStream_InvalidStart_Failure(CertificateFactory cf)
-            throws Exception {
+    private void test_generateCertificate_InputStream_InvalidStart_Failure(CertificateFactory cf) {
         try {
             Certificate c = cf.generateCertificate(new ByteArrayInputStream(
                     "-----BEGIN CERTIFICATE-----".getBytes(Charset.defaultCharset())));
@@ -549,7 +548,7 @@ public class CertificateFactoryTest {
 
         private long mMarked = 0;
 
-        private InputStream mStream;
+        private final InputStream mStream;
 
         public MeasuredInputStream(InputStream is) {
             mStream = is;
@@ -660,12 +659,12 @@ public class CertificateFactoryTest {
         KeyHolder cert2 = generateCertificate(false, cert1);
         KeyHolder cert3 = generateCertificate(false, cert2);
 
-        List<X509Certificate> certs = new ArrayList<X509Certificate>();
+        List<X509Certificate> certs = new ArrayList<>();
         certs.add(cert3.certificate);
         certs.add(cert2.certificate);
         certs.add(cert1.certificate);
 
-        List<X509Certificate> duplicatedCerts = new ArrayList<X509Certificate>(certs);
+        List<X509Certificate> duplicatedCerts = new ArrayList<>(certs);
         duplicatedCerts.add(cert2.certificate);
 
         Provider[] providers = Security.getProviders("CertificateFactory.X509");
@@ -805,7 +804,7 @@ public class CertificateFactoryTest {
         public PrivateKey privateKey;
     }
 
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings({"deprecation", "JavaUtilDate"})
     private static KeyHolder generateCertificate(boolean isCa, KeyHolder issuer) throws Exception {
         Date startDate = new Date();
 
@@ -823,7 +822,7 @@ public class CertificateFactoryTest {
         PrivateKey caKey;
         if (issuer != null) {
             serial = issuer.certificate.getSerialNumber().add(BigInteger.ONE);
-            subjectPrincipal = new X500Principal("CN=Test Certificate Serial #" + serial.toString());
+            subjectPrincipal = new X500Principal("CN=Test Certificate Serial #" + serial);
             issuerPrincipal = issuer.certificate.getSubjectX500Principal();
             caKey = issuer.privateKey;
         } else {
@@ -935,7 +934,7 @@ public class CertificateFactoryTest {
             // which technically doesn't satisfy the method contract, but we'll accept it
             assertTrue((c == null) && cf.getProvider().getName().equals("BC"));
         } catch (CRLException maybeExpected) {
-            assertFalse(cf.getProvider().getName().equals("BC"));
+            assertNotEquals("BC", cf.getProvider().getName());
         }
 
         try {
@@ -944,7 +943,7 @@ public class CertificateFactoryTest {
             // which technically doesn't satisfy the method contract, but we'll accept it
             assertTrue((c == null) && cf.getProvider().getName().equals("BC"));
         } catch (CRLException maybeExpected) {
-            assertFalse(cf.getProvider().getName().equals("BC"));
+            assertNotEquals("BC", cf.getProvider().getName());
         }
 
     }
diff --git a/common/src/test/java/org/conscrypt/java/security/cert/X509CRLTest.java b/common/src/test/java/org/conscrypt/java/security/cert/X509CRLTest.java
index 50b16883..41733841 100644
--- a/common/src/test/java/org/conscrypt/java/security/cert/X509CRLTest.java
+++ b/common/src/test/java/org/conscrypt/java/security/cert/X509CRLTest.java
@@ -33,7 +33,9 @@ import java.security.cert.X509CRL;
 import java.security.cert.X509CRLEntry;
 import java.security.cert.X509Certificate;
 import java.util.Collections;
+import java.util.Locale;
 import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;
+
 import org.conscrypt.TestUtils;
 import org.junit.ClassRule;
 import org.junit.Test;
@@ -138,7 +140,7 @@ public class X509CRLTest {
                     X509Certificate ca = (X509Certificate) cf.generateCertificate(
                             new ByteArrayInputStream(CA_CERT.getBytes(StandardCharsets.US_ASCII)));
 
-                    assertEquals("SHA256WITHRSA", crl.getSigAlgName().toUpperCase());
+                    assertEquals("SHA256WITHRSA", crl.getSigAlgName().toUpperCase(Locale.ROOT));
                     crl.verify(ca.getPublicKey());
                     try {
                         crl.verify(revoked.getPublicKey());
diff --git a/common/src/test/java/org/conscrypt/java/security/cert/X509CertificateTest.java b/common/src/test/java/org/conscrypt/java/security/cert/X509CertificateTest.java
index 1af048c4..34ff932e 100644
--- a/common/src/test/java/org/conscrypt/java/security/cert/X509CertificateTest.java
+++ b/common/src/test/java/org/conscrypt/java/security/cert/X509CertificateTest.java
@@ -18,7 +18,6 @@ package org.conscrypt.java.security.cert;
 
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
-import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
@@ -26,7 +25,7 @@ import static org.junit.Assert.fail;
 
 import java.io.ByteArrayInputStream;
 import java.math.BigInteger;
-import java.nio.charset.Charset;
+import java.nio.charset.StandardCharsets;
 import java.security.InvalidKeyException;
 import java.security.NoSuchAlgorithmException;
 import java.security.Provider;
@@ -40,10 +39,10 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Calendar;
 import java.util.Collection;
-import java.util.Collections;
 import java.util.Comparator;
 import java.util.Date;
 import java.util.List;
+import java.util.Locale;
 import java.util.TimeZone;
 import javax.security.auth.x500.X500Principal;
 import org.conscrypt.TestUtils;
@@ -210,7 +209,7 @@ public class X509CertificateTest {
             + "V9IpdAD0vhWHXcQHAiB8HnkUaiGD8Hp0aHlfFJmaaLTxy54VXuYfMlJhXnXJFA==\n"
             + "-----END CERTIFICATE-----\n";
 
-    /**
+    /*
      * This is a certificate with many extensions filled it. It exists to test accessors correctly
      * report fields. It was constructed by hand, so the signature itself is invalid. Add more
      * fields as necessary with https://github.com/google/der-ascii.
@@ -382,8 +381,7 @@ public class X509CertificateTest {
             "0K8A7gKLY0jP8Zp+6rYBcpxc7cylWMbdlhFTHAGiKI+XeQ/9u+RPeocZsn5jGlDt\n" +
             "K3ftMoWFce+baNq/WcMzRj04AA==\n" +
             "-----END CERTIFICATE-----\n";
-    private static Date dateFromUTC(int year, int month, int day, int hour, int minute, int second)
-            throws Exception {
+    private static Date dateFromUTC(int year, int month, int day, int hour, int minute, int second) {
         Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
         c.set(year, month, day, hour, minute, second);
         c.set(Calendar.MILLISECOND, 0);
@@ -394,15 +392,15 @@ public class X509CertificateTest {
             throws CertificateException {
         CertificateFactory cf = CertificateFactory.getInstance("X509", p);
         return (X509Certificate) cf.generateCertificate(
-                new ByteArrayInputStream(pem.getBytes(Charset.forName("US-ASCII"))));
+                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
     }
 
     private static List<Pair<Integer, String>> normalizeGeneralNames(Collection<List<?>> names) {
         // Extract a more convenient type than Java's Collection<List<?>>.
-        List<Pair<Integer, String>> result = new ArrayList<Pair<Integer, String>>();
+        List<Pair<Integer, String>> result = new ArrayList<>();
         for (List<?> tuple : names) {
             assertEquals(2, tuple.size());
-            int type = ((Integer) tuple.get(0)).intValue();
+            int type = (Integer) tuple.get(0);
             // TODO(davidben): Most name types are expected to have a String value, but some use
             // byte[]. Update this logic when testing those name types. See
             // X509Certificate.getSubjectAlternativeNames().
@@ -412,21 +410,13 @@ public class X509CertificateTest {
         // Although there is a natural order (the order in the certificate), Java's API returns a
         // Collection, so there is no guarantee of the provider using a particular order. Normalize
         // the order before comparing.
-        Collections.sort(result, new Comparator<Pair<Integer, String>>() {
-            @Override
-            public int compare(Pair<Integer, String> a, Pair<Integer, String> b) {
-                int cmp = a.getFirst().compareTo(b.getFirst());
-                if (cmp != 0) {
-                    return cmp;
-                }
-                return a.getSecond().compareTo(b.getSecond());
-            }
-        });
+        result.sort(Comparator.comparingInt(
+                (Pair<Integer, String> a) -> a.getFirst()).thenComparing(Pair::getSecond));
         return result;
     }
 
     private static void assertGeneralNamesEqual(
-            Collection<List<?>> expected, Collection<List<?>> actual) throws Exception {
+            Collection<List<?>> expected, Collection<List<?>> actual) {
         assertEquals(normalizeGeneralNames(expected), normalizeGeneralNames(actual));
     }
 
@@ -436,24 +426,21 @@ public class X509CertificateTest {
     //
     // https://errorprone.info/bugpattern/UndefinedEquals
     @SuppressWarnings("UndefinedEquals")
-    private static void assertDatesEqual(Date expected, Date actual) throws Exception {
+    private static void assertDatesEqual(Date expected, Date actual) {
         assertEquals(expected, actual);
     }
 
     // See issue #539.
     @Test
-    public void testMismatchedAlgorithm() throws Exception {
+    public void testMismatchedAlgorithm() {
         ServiceTester.test("CertificateFactory")
             .withAlgorithm("X509")
-            .run(new ServiceTester.Test() {
-                @Override
-                public void test(Provider p, String algorithm) throws Exception {
-                    try {
-                        X509Certificate c = certificateFromPEM(p, MISMATCHED_ALGORITHM_CERT);
-                        c.verify(c.getPublicKey());
-                        fail();
-                    } catch (CertificateException expected) {
-                    }
+            .run((p, algorithm) -> {
+                try {
+                    X509Certificate c = certificateFromPEM(p, MISMATCHED_ALGORITHM_CERT);
+                    c.verify(c.getPublicKey());
+                    fail();
+                } catch (CertificateException expected) {
                 }
             });
     }
@@ -462,53 +449,44 @@ public class X509CertificateTest {
      * Confirm that explicit EC params aren't accepted in certificates.
      */
     @Test
-    public void testExplicitEcParams() throws Exception {
+    public void testExplicitEcParams() {
         ServiceTester.test("CertificateFactory")
             .withAlgorithm("X509")
             // Bouncy Castle allows explicit EC params in certificates, even though they're
             // barred by RFC 5480
             .skipProvider("BC")
-            .run(new ServiceTester.Test() {
-                @Override
-                public void test(Provider p, String algorithm) throws Exception {
-                    try {
-                        X509Certificate c = certificateFromPEM(p, EC_EXPLICIT_KEY_CERT);
-                        c.verify(c.getPublicKey());
-                        fail();
-                    } catch (InvalidKeyException expected) {
-                        // TODO: Should we throw CertificateParsingException at parse time
-                        // instead of waiting for when the user accesses the key?
-                    } catch (CertificateParsingException expected) {
-                    }
+            .run((p, algorithm) -> {
+                try {
+                    X509Certificate c = certificateFromPEM(p, EC_EXPLICIT_KEY_CERT);
+                    c.verify(c.getPublicKey());
+                    fail();
+                } catch (InvalidKeyException expected) {
+                    // TODO: Should we throw CertificateParsingException at parse time
+                    // instead of waiting for when the user accesses the key?
+                } catch (CertificateParsingException expected) {
                 }
             });
     }
 
     @Test
-    public void testSigAlgName() throws Exception {
+    public void testSigAlgName() {
         ServiceTester.test("CertificateFactory")
             .withAlgorithm("X509")
-            .run(new ServiceTester.Test() {
-                @Override
-                public void test(Provider p, String algorithm) throws Exception {
-                    X509Certificate c = certificateFromPEM(p, VALID_CERT);
-                    assertEquals("SHA256WITHRSA", c.getSigAlgName().toUpperCase());
-                    c.verify(c.getPublicKey());
-                }
+            .run((p, algorithm) -> {
+                X509Certificate c = certificateFromPEM(p, VALID_CERT);
+                assertEquals("SHA256WITHRSA", c.getSigAlgName().toUpperCase(Locale.ROOT));
+                c.verify(c.getPublicKey());
             });
     }
 
     @Test
-    public void testUnknownSigAlgOID() throws Exception {
+    public void testUnknownSigAlgOID() {
         ServiceTester.test("CertificateFactory")
             .withAlgorithm("X509")
-            .run(new ServiceTester.Test() {
-                @Override
-                public void test(Provider p, String algorithm) throws Exception {
-                    X509Certificate c = certificateFromPEM(p, UNKNOWN_SIGNATURE_OID);
-                    assertEquals("1.2.840.113554.4.1.72585.2", c.getSigAlgOID());
-                    assertThrows(NoSuchAlgorithmException.class, () -> c.verify(c.getPublicKey()));
-                }
+            .run((p, algorithm) -> {
+                X509Certificate c = certificateFromPEM(p, UNKNOWN_SIGNATURE_OID);
+                assertEquals("1.2.840.113554.4.1.72585.2", c.getSigAlgOID());
+                assertThrows(NoSuchAlgorithmException.class, () -> c.verify(c.getPublicKey()));
             });
     }
 
@@ -520,12 +498,9 @@ public class X509CertificateTest {
             .withAlgorithm("X509")
             .skipProvider("SUN")
             .skipProvider("BC")
-            .run(new ServiceTester.Test() {
-                @Override
-                public void test(Provider p, String algorithm) throws Exception {
-                    X509Certificate c = certificateFromPEM(p, MD5_SIGNATURE);
-                    assertThrows(NoSuchAlgorithmException.class, () -> c.verify(c.getPublicKey()));
-                }
+            .run((p, algorithm) -> {
+                X509Certificate c = certificateFromPEM(p, MD5_SIGNATURE);
+                assertThrows(NoSuchAlgorithmException.class, () -> c.verify(c.getPublicKey()));
             });
     }
 
@@ -537,234 +512,213 @@ public class X509CertificateTest {
         String invalidCert = VALID_CERT.substring(0, index) + "8" + VALID_CERT.substring(index + 1);
         ServiceTester.test("CertificateFactory")
             .withAlgorithm("X509")
-            .run(new ServiceTester.Test() {
-                @Override
-                public void test(Provider p, String algorithm) throws Exception {
-                    X509Certificate c = certificateFromPEM(p, invalidCert);
-                    assertThrows(SignatureException.class, () -> c.verify(c.getPublicKey()));
-                }
+            .run((p, algorithm) -> {
+                X509Certificate c = certificateFromPEM(p, invalidCert);
+                assertThrows(SignatureException.class, () -> c.verify(c.getPublicKey()));
             });
     }
 
     @Test
-    public void testV1Cert() throws Exception {
+    public void testV1Cert() {
         ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
-        tester.run(new ServiceTester.Test() {
-            @Override
-            public void test(Provider p, String algorithm) throws Exception {
-                X509Certificate c = certificateFromPEM(p, X509V1_CERT);
-
-                // Check basic certificate properties.
-                assertEquals(1, c.getVersion());
-                assertEquals(new BigInteger("d94c04da497dbfeb", 16), c.getSerialNumber());
-                assertDatesEqual(
-                        dateFromUTC(2014, Calendar.APRIL, 23, 23, 21, 57), c.getNotBefore());
-                assertDatesEqual(dateFromUTC(2014, Calendar.MAY, 23, 23, 21, 57), c.getNotAfter());
-                assertEquals(new X500Principal("CN=Test Issuer"), c.getIssuerX500Principal());
-                assertEquals(new X500Principal("CN=Test Subject"), c.getSubjectX500Principal());
-                assertEquals("1.2.840.10045.4.1", c.getSigAlgOID());
-                String signatureHex = "3045022100f2a0355e513a36c382799bee27"
-                        + "50858e7006749557d2297400f4be15875dc4"
-                        + "0702207c1e79146a2183f07a7468795f1499"
-                        + "9a68b4f1cb9e155ee61f3252615e75c914";
-                assertArrayEquals(TestUtils.decodeHex(signatureHex), c.getSignature());
-
-                // ECDSA signature AlgorithmIdentifiers omit parameters.
-                assertNull(c.getSigAlgParams());
-
-                // The certificate does not have UIDs.
-                assertNull(c.getIssuerUniqueID());
-                assertNull(c.getSubjectUniqueID());
-
-                // The certificate does not have any extensions.
-                assertEquals(-1, c.getBasicConstraints());
-                assertNull(c.getExtendedKeyUsage());
-                assertNull(c.getIssuerAlternativeNames());
-                assertNull(c.getKeyUsage());
-                assertNull(c.getSubjectAlternativeNames());
-            }
+        tester.run((p, algorithm) -> {
+            X509Certificate c = certificateFromPEM(p, X509V1_CERT);
+
+            // Check basic certificate properties.
+            assertEquals(1, c.getVersion());
+            assertEquals(new BigInteger("d94c04da497dbfeb", 16), c.getSerialNumber());
+            assertDatesEqual(
+                    dateFromUTC(2014, Calendar.APRIL, 23, 23, 21, 57), c.getNotBefore());
+            assertDatesEqual(dateFromUTC(2014, Calendar.MAY, 23, 23, 21, 57), c.getNotAfter());
+            assertEquals(new X500Principal("CN=Test Issuer"), c.getIssuerX500Principal());
+            assertEquals(new X500Principal("CN=Test Subject"), c.getSubjectX500Principal());
+            assertEquals("1.2.840.10045.4.1", c.getSigAlgOID());
+            String signatureHex = "3045022100f2a0355e513a36c382799bee27"
+                    + "50858e7006749557d2297400f4be15875dc4"
+                    + "0702207c1e79146a2183f07a7468795f1499"
+                    + "9a68b4f1cb9e155ee61f3252615e75c914";
+            assertArrayEquals(TestUtils.decodeHex(signatureHex), c.getSignature());
+
+            // ECDSA signature AlgorithmIdentifiers omit parameters.
+            assertNull(c.getSigAlgParams());
+
+            // The certificate does not have UIDs.
+            assertNull(c.getIssuerUniqueID());
+            assertNull(c.getSubjectUniqueID());
+
+            // The certificate does not have any extensions.
+            assertEquals(-1, c.getBasicConstraints());
+            assertNull(c.getExtendedKeyUsage());
+            assertNull(c.getIssuerAlternativeNames());
+            assertNull(c.getKeyUsage());
+            assertNull(c.getSubjectAlternativeNames());
         });
     }
 
     @Test
-    public void testManyExtensions() throws Exception {
+    public void testManyExtensions() {
         ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
-        tester.run(new ServiceTester.Test() {
-            @Override
-            public void test(Provider p, String algorithm) throws Exception {
-                X509Certificate c = certificateFromPEM(p, MANY_EXTENSIONS);
-
-                assertEquals(3, c.getVersion());
-                assertEquals(new BigInteger("b5b622b95a04a521", 16), c.getSerialNumber());
-                assertDatesEqual(dateFromUTC(2016, Calendar.JULY, 9, 4, 38, 9), c.getNotBefore());
-                assertDatesEqual(dateFromUTC(2016, Calendar.AUGUST, 8, 4, 38, 9), c.getNotAfter());
-                assertEquals(new X500Principal("CN=Test Issuer"), c.getIssuerX500Principal());
-                assertEquals(new X500Principal("CN=Test Subject"), c.getSubjectX500Principal());
-                assertEquals("1.2.840.113549.1.1.11", c.getSigAlgOID());
-                String signatureHex = "3ec983af1202b61695ca077d9001f743e6ca"
-                        + "bb791fa0fc2d18be5b6462d5f04dc511042e"
-                        + "77b3589dac72397850c72c298a783e2f79d2"
-                        + "054dfbad8882b22670236fb5be48d427f2fc"
-                        + "c34dbabf5f7dab3a5f7df80f485854841378"
-                        + "fc85937ba623eda6250aed659c8c3c829263"
-                        + "fb181901e11865fac062be18efe88343d093"
-                        + "f56ee83f865365d19c357461983596c02c1d"
-                        + "ddb55ebc8ae9f0e636410cc1b216aedb38c5"
-                        + "ceec711ac61d6cbe88c7faffba7f024fd222"
-                        + "270ce174b09a543ca4fc4064fafe1362e855"
-                        + "df69329594c295b651bb4ee70b064eb639b0"
-                        + "ee39b4534dff2fa3b5485e0750b68a339b1b"
-                        + "fb5710b6a2c8274cf92ff069ebafd0c5ed23"
-                        + "8c679f50";
-                assertArrayEquals(TestUtils.decodeHex(signatureHex), c.getSignature());
-
-                // Although documented to only return null when there are no parameters, the SUN
-                // provider also returns null when the algorithm uses an explicit parameter with a
-                // value of ASN.1 NULL.
-                if (c.getSigAlgParams() != null) {
-                    assertArrayEquals(TestUtils.decodeHex("0500"), c.getSigAlgParams());
-                }
-
-                assertArrayEquals(new boolean[] {true, false, true, false}, c.getIssuerUniqueID());
-                assertArrayEquals(
-                        new boolean[] {false, true, false, true, false}, c.getSubjectUniqueID());
-                assertEquals(10, c.getBasicConstraints());
-                assertEquals(Arrays.asList("1.3.6.1.5.5.7.3.1", "1.2.840.113554.4.1.72585.2"),
-                        c.getExtendedKeyUsage());
-
-                // TODO(davidben): Test the other name types.
-                assertGeneralNamesEqual(
-                        Arrays.<List<?>>asList(Arrays.asList(1, "issuer@example.com"),
-                                Arrays.asList(2, "issuer.example.com"),
-                                Arrays.asList(4, "CN=Test Issuer"),
-                                Arrays.asList(6, "https://example.com/issuer"),
-                                // TODO(https://github.com/google/conscrypt/issues/938): Fix IPv6
-                                // handling and include it in this test.
-                                Arrays.asList(7, "127.0.0.1"),
-                                Arrays.asList(8, "1.2.840.113554.4.1.72585.2")),
-                        c.getIssuerAlternativeNames());
-                assertGeneralNamesEqual(
-                        Arrays.<List<?>>asList(Arrays.asList(1, "subject@example.com"),
-                                Arrays.asList(2, "subject.example.com"),
-                                Arrays.asList(4, "CN=Test Subject"),
-                                Arrays.asList(6, "https://example.com/subject"),
-                                // TODO(https://github.com/google/conscrypt/issues/938): Fix IPv6
-                                // handling and include it in this test.
-                                Arrays.asList(7, "127.0.0.1"),
-                                Arrays.asList(8, "1.2.840.113554.4.1.72585.2")),
-                        c.getSubjectAlternativeNames());
-
-                // Although the BIT STRING in the certificate only has three bits, getKeyUsage()
-                // rounds up to at least 9 bits.
-                assertArrayEquals(
-                        new boolean[] {true, false, true, false, false, false, false, false, false},
-                        c.getKeyUsage());
+        tester.run((p, algorithm) -> {
+            X509Certificate c = certificateFromPEM(p, MANY_EXTENSIONS);
+
+            assertEquals(3, c.getVersion());
+            assertEquals(new BigInteger("b5b622b95a04a521", 16), c.getSerialNumber());
+            assertDatesEqual(dateFromUTC(2016, Calendar.JULY, 9, 4, 38, 9), c.getNotBefore());
+            assertDatesEqual(dateFromUTC(2016, Calendar.AUGUST, 8, 4, 38, 9), c.getNotAfter());
+            assertEquals(new X500Principal("CN=Test Issuer"), c.getIssuerX500Principal());
+            assertEquals(new X500Principal("CN=Test Subject"), c.getSubjectX500Principal());
+            assertEquals("1.2.840.113549.1.1.11", c.getSigAlgOID());
+            String signatureHex = "3ec983af1202b61695ca077d9001f743e6ca"
+                    + "bb791fa0fc2d18be5b6462d5f04dc511042e"
+                    + "77b3589dac72397850c72c298a783e2f79d2"
+                    + "054dfbad8882b22670236fb5be48d427f2fc"
+                    + "c34dbabf5f7dab3a5f7df80f485854841378"
+                    + "fc85937ba623eda6250aed659c8c3c829263"
+                    + "fb181901e11865fac062be18efe88343d093"
+                    + "f56ee83f865365d19c357461983596c02c1d"
+                    + "ddb55ebc8ae9f0e636410cc1b216aedb38c5"
+                    + "ceec711ac61d6cbe88c7faffba7f024fd222"
+                    + "270ce174b09a543ca4fc4064fafe1362e855"
+                    + "df69329594c295b651bb4ee70b064eb639b0"
+                    + "ee39b4534dff2fa3b5485e0750b68a339b1b"
+                    + "fb5710b6a2c8274cf92ff069ebafd0c5ed23"
+                    + "8c679f50";
+            assertArrayEquals(TestUtils.decodeHex(signatureHex), c.getSignature());
+
+            // Although documented to only return null when there are no parameters, the SUN
+            // provider also returns null when the algorithm uses an explicit parameter with a
+            // value of ASN.1 NULL.
+            if (c.getSigAlgParams() != null) {
+                assertArrayEquals(TestUtils.decodeHex("0500"), c.getSigAlgParams());
             }
+
+            assertArrayEquals(new boolean[] {true, false, true, false}, c.getIssuerUniqueID());
+            assertArrayEquals(
+                    new boolean[] {false, true, false, true, false}, c.getSubjectUniqueID());
+            assertEquals(10, c.getBasicConstraints());
+            assertEquals(Arrays.asList("1.3.6.1.5.5.7.3.1", "1.2.840.113554.4.1.72585.2"),
+                    c.getExtendedKeyUsage());
+
+            // TODO(davidben): Test the other name types.
+            assertGeneralNamesEqual(
+                    Arrays.asList(Arrays.asList(1, "issuer@example.com"),
+                            Arrays.asList(2, "issuer.example.com"),
+                            Arrays.asList(4, "CN=Test Issuer"),
+                            Arrays.asList(6, "https://example.com/issuer"),
+                            // TODO(https://github.com/google/conscrypt/issues/938): Fix IPv6
+                            // handling and include it in this test.
+                            Arrays.asList(7, "127.0.0.1"),
+                            Arrays.asList(8, "1.2.840.113554.4.1.72585.2")),
+                    c.getIssuerAlternativeNames());
+            assertGeneralNamesEqual(
+                    Arrays.asList(Arrays.asList(1, "subject@example.com"),
+                            Arrays.asList(2, "subject.example.com"),
+                            Arrays.asList(4, "CN=Test Subject"),
+                            Arrays.asList(6, "https://example.com/subject"),
+                            // TODO(https://github.com/google/conscrypt/issues/938): Fix IPv6
+                            // handling and include it in this test.
+                            Arrays.asList(7, "127.0.0.1"),
+                            Arrays.asList(8, "1.2.840.113554.4.1.72585.2")),
+                    c.getSubjectAlternativeNames());
+
+            // Although the BIT STRING in the certificate only has three bits, getKeyUsage()
+            // rounds up to at least 9 bits.
+            assertArrayEquals(
+                    new boolean[] {true, false, true, false, false, false, false, false, false},
+                    c.getKeyUsage());
         });
     }
 
     @Test
-    public void testBasicConstraints() throws Exception {
+    public void testBasicConstraints() {
         ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
-        tester.run(new ServiceTester.Test() {
-            @Override
-            public void test(Provider p, String algorithm) throws Exception {
-                // Test some additional edge cases in getBasicConstraints() beyond that
-                // testManyExtensions() and testV1Cert() covered.
-
-                // If there is no pathLen constraint but the certificate is a CA,
-                // getBasicConstraints() returns Integer.MAX_VALUE.
-                X509Certificate c = certificateFromPEM(p, BASIC_CONSTRAINTS_NO_PATHLEN);
-                assertEquals(Integer.MAX_VALUE, c.getBasicConstraints());
-
-                // If there is a pathLen constraint of zero, getBasicConstraints() returns it.
-                c = certificateFromPEM(p, BASIC_CONSTRAINTS_PATHLEN_0);
-                assertEquals(0, c.getBasicConstraints());
-
-                // If there is basicConstraints extension indicating a leaf certficate,
-                // getBasicConstraints() returns -1. The accessor does not distinguish between no
-                // basicConstraints extension and a leaf one.
-                c = certificateFromPEM(p, BASIC_CONSTRAINTS_LEAF);
-                assertEquals(-1, c.getBasicConstraints());
-
-                // If some unrelated extension has a syntax error, and that syntax error does not
-                // fail when constructing the certificate, it should not interfere with
-                // getBasicConstraints().
-                try {
-                    c = certificateFromPEM(p, BASIC_CONSTRAINTS_PATHLEN_10_BAD_SAN);
-                } catch (CertificateParsingException e) {
-                    // The certificate has a syntax error, so it would also be valid for the
-                    // provider to reject the certificate at construction. X.509 is an extensible
-                    // format, so different implementations may notice errors at different points.
-                    c = null;
-                }
-                if (c != null) {
-                    assertEquals(10, c.getBasicConstraints());
-                }
+        tester.run((p, algorithm) -> {
+            // Test some additional edge cases in getBasicConstraints() beyond that
+            // testManyExtensions() and testV1Cert() covered.
+
+            // If there is no pathLen constraint but the certificate is a CA,
+            // getBasicConstraints() returns Integer.MAX_VALUE.
+            X509Certificate c = certificateFromPEM(p, BASIC_CONSTRAINTS_NO_PATHLEN);
+            assertEquals(Integer.MAX_VALUE, c.getBasicConstraints());
+
+            // If there is a pathLen constraint of zero, getBasicConstraints() returns it.
+            c = certificateFromPEM(p, BASIC_CONSTRAINTS_PATHLEN_0);
+            assertEquals(0, c.getBasicConstraints());
+
+            // If there is basicConstraints extension indicating a leaf certficate,
+            // getBasicConstraints() returns -1. The accessor does not distinguish between no
+            // basicConstraints extension and a leaf one.
+            c = certificateFromPEM(p, BASIC_CONSTRAINTS_LEAF);
+            assertEquals(-1, c.getBasicConstraints());
+
+            // If some unrelated extension has a syntax error, and that syntax error does not
+            // fail when constructing the certificate, it should not interfere with
+            // getBasicConstraints().
+            try {
+                c = certificateFromPEM(p, BASIC_CONSTRAINTS_PATHLEN_10_BAD_SAN);
+            } catch (CertificateParsingException e) {
+                // The certificate has a syntax error, so it would also be valid for the
+                // provider to reject the certificate at construction. X.509 is an extensible
+                // format, so different implementations may notice errors at different points.
+                c = null;
+            }
+            if (c != null) {
+                assertEquals(10, c.getBasicConstraints());
             }
         });
     }
 
     @Test
-    public void testLargeKeyUsage() throws Exception {
+    public void testLargeKeyUsage() {
         ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
-        tester.run(new ServiceTester.Test() {
-            @Override
-            public void test(Provider p, String algorithm) throws Exception {
-                X509Certificate c = certificateFromPEM(p, LARGE_KEY_USAGE);
-                assertArrayEquals(new boolean[] {true, false, true, false, false, false, false,
-                                          false, false, false, false},
-                        c.getKeyUsage());
-            }
+        tester.run((p, algorithm) -> {
+            X509Certificate c = certificateFromPEM(p, LARGE_KEY_USAGE);
+            assertArrayEquals(new boolean[] {true, false, true, false, false, false, false,
+                                      false, false, false, false},
+                    c.getKeyUsage());
         });
     }
 
     @Test
-    public void testSigAlgParams() throws Exception {
+    public void testSigAlgParams() {
         ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
-        tester.run(new ServiceTester.Test() {
-            @Override
-            public void test(Provider p, String algorithm) throws Exception {
-                X509Certificate c = certificateFromPEM(p, SIGALG_NO_PARAMETER);
-                assertNull(c.getSigAlgParams());
-
-                c = certificateFromPEM(p, SIGALG_NULL_PARAMETER);
-                // Although documented to only return null when there are no parameters, the SUN
-                // provider also returns null when the algorithm uses an explicit parameter with a
-                // value of ASN.1 NULL.
-                if (c.getSigAlgParams() != null) {
-                    assertArrayEquals(TestUtils.decodeHex("0500"), c.getSigAlgParams());
-                }
+        tester.run((p, algorithm) -> {
+            X509Certificate c = certificateFromPEM(p, SIGALG_NO_PARAMETER);
+            assertNull(c.getSigAlgParams());
+
+            c = certificateFromPEM(p, SIGALG_NULL_PARAMETER);
+            // Although documented to only return null when there are no parameters, the SUN
+            // provider also returns null when the algorithm uses an explicit parameter with a
+            // value of ASN.1 NULL.
+            if (c.getSigAlgParams() != null) {
+                assertArrayEquals(TestUtils.decodeHex("0500"), c.getSigAlgParams());
+            }
 
-                c = certificateFromPEM(p, SIGALG_STRING_PARAMETER);
-                assertArrayEquals(TestUtils.decodeHex("0c05706172616d"), c.getSigAlgParams());
+            c = certificateFromPEM(p, SIGALG_STRING_PARAMETER);
+            assertArrayEquals(TestUtils.decodeHex("0c05706172616d"), c.getSigAlgParams());
 
-                c = certificateFromPEM(p, SIGALG_BOOLEAN_PARAMETER);
-                assertArrayEquals(TestUtils.decodeHex("0101ff"), c.getSigAlgParams());
+            c = certificateFromPEM(p, SIGALG_BOOLEAN_PARAMETER);
+            assertArrayEquals(TestUtils.decodeHex("0101ff"), c.getSigAlgParams());
 
-                c = certificateFromPEM(p, SIGALG_SEQUENCE_PARAMETER);
-                assertArrayEquals(TestUtils.decodeHex("3000"), c.getSigAlgParams());
-            }
+            c = certificateFromPEM(p, SIGALG_SEQUENCE_PARAMETER);
+            assertArrayEquals(TestUtils.decodeHex("3000"), c.getSigAlgParams());
         });
     }
 
     // Ensure we don't reject certificates with UTCTIME fields with offsets for now: b/311260068
     @Test
-    public void utcTimeWithOffset() throws Exception {
+    public void utcTimeWithOffset() {
         ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
         tester.skipProvider("SUN") // Sun and BC interpret the offset, Conscrypt just drops it...
                 .skipProvider("BC")
-                .run(new ServiceTester.Test() {
-            @Override
-            public void test(Provider p, String algorithm) throws Exception {
-                X509Certificate c = certificateFromPEM(p, UTCTIME_WITH_OFFSET);
-                assertDatesEqual(
-                        dateFromUTC(2014, Calendar.JULY, 4, 0, 0, 0),
-                        c.getNotBefore());
-                assertDatesEqual(
-                        dateFromUTC(2048, Calendar.AUGUST, 1, 10, 21, 23),
-                        c.getNotAfter());
-            }
-        });
+                .run((p, algorithm) -> {
+                    X509Certificate c = certificateFromPEM(p, UTCTIME_WITH_OFFSET);
+                    assertDatesEqual(
+                            dateFromUTC(2014, Calendar.JULY, 4, 0, 0, 0),
+                            c.getNotBefore());
+                    assertDatesEqual(
+                            dateFromUTC(2048, Calendar.AUGUST, 1, 10, 21, 23),
+                            c.getNotAfter());
+                });
     }
 }
diff --git a/common/src/test/java/org/conscrypt/javax/crypto/CipherTest.java b/common/src/test/java/org/conscrypt/javax/crypto/CipherTest.java
index 687e4d13..b631fb37 100644
--- a/common/src/test/java/org/conscrypt/javax/crypto/CipherTest.java
+++ b/common/src/test/java/org/conscrypt/javax/crypto/CipherTest.java
@@ -16,8 +16,10 @@
 
 package org.conscrypt.javax.crypto;
 
+import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertThrows;
@@ -37,6 +39,7 @@ import java.security.KeyFactory;
 import java.security.KeyPairGenerator;
 import java.security.PrivateKey;
 import java.security.Provider;
+import java.security.ProviderException;
 import java.security.PublicKey;
 import java.security.SecureRandom;
 import java.security.Security;
@@ -158,7 +161,7 @@ public final class CipherTest {
         return true;
     }
 
-    /**
+    /*
      * Checks for algorithms removed from BC in Android 12 and so not usable for these
      * tests.
      *
@@ -190,20 +193,17 @@ public final class CipherTest {
             return false;
         }
         // AESWRAP should be used instead, fails with BC and SunJCE otherwise.
-        if (algorithm.startsWith("AES") || algorithm.startsWith("DESEDE")) {
-            return false;
-        }
-        return true;
+        return !algorithm.startsWith("AES") && !algorithm.startsWith("DESEDE");
     }
 
-    private synchronized static int getEncryptMode(String algorithm) throws Exception {
+    private synchronized static int getEncryptMode(String algorithm) {
         if (isOnlyWrappingAlgorithm(algorithm)) {
             return Cipher.WRAP_MODE;
         }
         return Cipher.ENCRYPT_MODE;
     }
 
-    private synchronized static int getDecryptMode(String algorithm) throws Exception {
+    private synchronized static int getDecryptMode(String algorithm) {
         if (isOnlyWrappingAlgorithm(algorithm)) {
             return Cipher.UNWRAP_MODE;
         }
@@ -320,7 +320,7 @@ public final class CipherTest {
                 || algorithm.contains("/OAEPWITH");
     }
 
-    private static Map<String, Key> ENCRYPT_KEYS = new HashMap<String, Key>();
+    private static final Map<String, Key> ENCRYPT_KEYS = new HashMap<>();
 
     /**
      * Returns the key meant for enciphering for {@code algorithm}.
@@ -355,7 +355,7 @@ public final class CipherTest {
         return key;
     }
 
-    private static Map<String, Key> DECRYPT_KEYS = new HashMap<String, Key>();
+    private static final Map<String, Key> DECRYPT_KEYS = new HashMap<>();
 
     /**
      * Returns the key meant for deciphering for {@code algorithm}.
@@ -384,7 +384,7 @@ public final class CipherTest {
         return key;
     }
 
-    private static Map<String, Integer> EXPECTED_BLOCK_SIZE = new HashMap<String, Integer>();
+    private static final Map<String, Integer> EXPECTED_BLOCK_SIZE = new HashMap<>();
     static {
         setExpectedBlockSize("AES", 16);
         setExpectedBlockSize("AES/CBC/PKCS5PADDING", 16);
@@ -572,7 +572,7 @@ public final class CipherTest {
         return getExpectedSize(EXPECTED_BLOCK_SIZE, algorithm, mode, provider);
     }
 
-    private static Map<String, Integer> EXPECTED_OUTPUT_SIZE = new HashMap<String, Integer>();
+    private static final Map<String, Integer> EXPECTED_OUTPUT_SIZE = new HashMap<>();
     static {
         setExpectedOutputSize("AES/CBC/NOPADDING", 0);
         setExpectedOutputSize("AES/CFB/NOPADDING", 0);
@@ -793,14 +793,14 @@ public final class CipherTest {
         return getExpectedSize(EXPECTED_OUTPUT_SIZE, algorithm, mode, provider);
     }
 
-    private static byte[] ORIGINAL_PLAIN_TEXT = new byte[] { 0x0a, 0x0b, 0x0c };
-    private static byte[] SIXTEEN_BYTE_BLOCK_PLAIN_TEXT = new byte[] { 0x0a, 0x0b, 0x0c, 0x00,
-                                                                       0x00, 0x00, 0x00, 0x00,
-                                                                       0x00, 0x00, 0x00, 0x00,
-                                                                       0x00, 0x00, 0x00, 0x00 };
-    private static byte[] EIGHT_BYTE_BLOCK_PLAIN_TEXT = new byte[] { 0x0a, 0x0b, 0x0c, 0x00,
-                                                                     0x00, 0x00, 0x00, 0x00 };
-    private static byte[] PKCS1_BLOCK_TYPE_00_PADDED_PLAIN_TEXT = new byte[] {
+    private static final byte[] ORIGINAL_PLAIN_TEXT = new byte[] { 0x0a, 0x0b, 0x0c };
+    private static final byte[] SIXTEEN_BYTE_BLOCK_PLAIN_TEXT = new byte[] { 0x0a, 0x0b, 0x0c, 0x00,
+                                                                             0x00, 0x00, 0x00, 0x00,
+                                                                             0x00, 0x00, 0x00, 0x00,
+                                                                             0x00, 0x00, 0x00, 0x00 };
+    private static final byte[] EIGHT_BYTE_BLOCK_PLAIN_TEXT = new byte[] { 0x0a, 0x0b, 0x0c, 0x00,
+            0x00, 0x00, 0x00, 0x00 };
+    private static final byte[] PKCS1_BLOCK_TYPE_00_PADDED_PLAIN_TEXT = new byte[] {
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
@@ -818,7 +818,7 @@ public final class CipherTest {
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0x0b, 0x0c
     };
-    private static byte[] PKCS1_BLOCK_TYPE_01_PADDED_PLAIN_TEXT = new byte[] {
+    private static final byte[] PKCS1_BLOCK_TYPE_01_PADDED_PLAIN_TEXT = new byte[] {
         (byte) 0x00, (byte) 0x01, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
         (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
         (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
@@ -852,7 +852,7 @@ public final class CipherTest {
         (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
         (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c
     };
-    private static byte[] PKCS1_BLOCK_TYPE_02_PADDED_PLAIN_TEXT = new byte[] {
+    private static final byte[] PKCS1_BLOCK_TYPE_02_PADDED_PLAIN_TEXT = new byte[] {
         (byte) 0x00, (byte) 0x02, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
         (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
         (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
@@ -1045,8 +1045,8 @@ public final class CipherTest {
         final ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
         PrintStream out = new PrintStream(errBuffer);
 
-        Set<String> seenBaseCipherNames = new HashSet<String>();
-        Set<String> seenCiphersWithModeAndPadding = new HashSet<String>();
+        Set<String> seenBaseCipherNames = new HashSet<>();
+        Set<String> seenCiphersWithModeAndPadding = new HashSet<>();
 
         Provider[] providers = Security.getProviders();
         for (Provider provider : providers) {
@@ -1135,7 +1135,7 @@ public final class CipherTest {
 
         out.flush();
         if (errBuffer.size() > 0) {
-            throw new Exception("Errors encountered:\n\n" + errBuffer.toString() + "\n\n");
+            throw new Exception("Errors encountered:\n\n" + errBuffer + "\n\n");
         }
     }
 
@@ -1368,7 +1368,7 @@ public final class CipherTest {
 
     private void assertCorrectAlgorithmParameters(String providerName, String cipherID,
             final AlgorithmParameterSpec spec, AlgorithmParameters params)
-            throws InvalidParameterSpecException, Exception {
+            throws Exception {
         if (spec == null) {
             return;
         }
@@ -1405,7 +1405,7 @@ public final class CipherTest {
     }
 
     private static void assertOAEPParametersEqual(OAEPParameterSpec expectedOaepSpec,
-            OAEPParameterSpec actualOaepSpec) throws Exception {
+            OAEPParameterSpec actualOaepSpec) {
         assertEquals(expectedOaepSpec.getDigestAlgorithm(), actualOaepSpec.getDigestAlgorithm());
 
         assertEquals(expectedOaepSpec.getMGFAlgorithm(), actualOaepSpec.getMGFAlgorithm());
@@ -1447,7 +1447,7 @@ public final class CipherTest {
         }
 
         try {
-            c.init(encryptMode, encryptKey, (AlgorithmParameterSpec) null, (SecureRandom) null);
+            c.init(encryptMode, encryptKey, (AlgorithmParameterSpec) null, null);
         } catch (InvalidAlgorithmParameterException e) {
             if (!isPBE(c.getAlgorithm())) {
                 throw e;
@@ -1463,7 +1463,7 @@ public final class CipherTest {
         }
 
         try {
-            c.init(encryptMode, encryptKey, (AlgorithmParameters) null, (SecureRandom) null);
+            c.init(encryptMode, encryptKey, (AlgorithmParameters) null, null);
         } catch (InvalidAlgorithmParameterException e) {
             if (!isPBE(c.getAlgorithm())) {
                 throw e;
@@ -1485,7 +1485,7 @@ public final class CipherTest {
         }
 
         try {
-            c.init(decryptMode, encryptKey, (AlgorithmParameterSpec) null, (SecureRandom) null);
+            c.init(decryptMode, encryptKey, (AlgorithmParameterSpec) null, null);
             if (needsParameters) {
                 fail("Should throw InvalidAlgorithmParameterException with null parameters");
             }
@@ -1507,7 +1507,7 @@ public final class CipherTest {
         }
 
         try {
-            c.init(decryptMode, encryptKey, (AlgorithmParameters) null, (SecureRandom) null);
+            c.init(decryptMode, encryptKey, (AlgorithmParameters) null, null);
             if (needsParameters) {
                 fail("Should throw InvalidAlgorithmParameterException with null parameters");
             }
@@ -1569,9 +1569,9 @@ public final class CipherTest {
         }
         byte[] plainText = c.doFinal(cipherText);
         byte[] expectedPlainText = getExpectedPlainText(algorithm, provider);
-        assertTrue("Expected " + Arrays.toString(expectedPlainText)
-                + " but was " + Arrays.toString(plainText),
-                Arrays.equals(expectedPlainText, plainText));
+        assertArrayEquals("Expected " + Arrays.toString(expectedPlainText) + " but was "
+                + Arrays.toString(plainText)
+                , expectedPlainText, plainText);
     }
 
     @Test
@@ -1748,7 +1748,7 @@ public final class CipherTest {
         }
     }
 
-    private Certificate certificateWithKeyUsage(int keyUsage) throws Exception {
+    private Certificate certificateWithKeyUsage(int keyUsage) {
         // note the rare usage of non-zero keyUsage
         return new TestKeyStore.Builder()
                 .aliasPrefix("rsa-dsa-ec")
@@ -2594,13 +2594,13 @@ public final class CipherTest {
          */
         c.init(Cipher.ENCRYPT_MODE, privKey);
         byte[] encrypted = c.doFinal(RSA_2048_Vector1);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals("Encrypted should match expected",
+                RSA_Vector1_Encrypt_Private, encrypted);
 
         c.init(Cipher.DECRYPT_MODE, privKey);
         encrypted = c.doFinal(RSA_2048_Vector1);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals("Encrypted should match expected",
+                RSA_Vector1_Encrypt_Private, encrypted);
     }
 
     @Test
@@ -2623,14 +2623,14 @@ public final class CipherTest {
         c.init(Cipher.ENCRYPT_MODE, privKey);
         c.update(RSA_2048_Vector1);
         byte[] encrypted = c.doFinal();
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals("Encrypted should match expected",
+                RSA_Vector1_Encrypt_Private, encrypted);
 
         c.init(Cipher.DECRYPT_MODE, privKey);
         c.update(RSA_2048_Vector1);
         encrypted = c.doFinal();
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals("Encrypted should match expected",
+                RSA_Vector1_Encrypt_Private, encrypted);
     }
 
     @Test
@@ -2658,16 +2658,16 @@ public final class CipherTest {
             c.update(RSA_2048_Vector1, i, 1);
         }
         byte[] encrypted = c.doFinal(RSA_2048_Vector1, i, RSA_2048_Vector1.length - i);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals("Encrypted should match expected",
+                RSA_Vector1_Encrypt_Private, encrypted);
 
         c.init(Cipher.DECRYPT_MODE, privKey);
         for (i = 0; i < RSA_2048_Vector1.length / 2; i++) {
             c.update(RSA_2048_Vector1, i, 1);
         }
         encrypted = c.doFinal(RSA_2048_Vector1, i, RSA_2048_Vector1.length - i);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals("Encrypted should match expected",
+                RSA_Vector1_Encrypt_Private, encrypted);
     }
 
     @Test
@@ -2693,16 +2693,16 @@ public final class CipherTest {
                 .doFinal(RSA_2048_Vector1, 0, RSA_2048_Vector1.length, encrypted, 0);
         assertEquals("Encrypted size should match expected", RSA_Vector1_Encrypt_Private.length,
                 encryptLen);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals("Encrypted should match expected",
+                RSA_Vector1_Encrypt_Private, encrypted);
 
         c.init(Cipher.DECRYPT_MODE, privKey);
         final int decryptLen = c
                 .doFinal(RSA_2048_Vector1, 0, RSA_2048_Vector1.length, encrypted, 0);
         assertEquals("Encrypted size should match expected", RSA_Vector1_Encrypt_Private.length,
                 decryptLen);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals("Encrypted should match expected",
+                RSA_Vector1_Encrypt_Private, encrypted);
     }
 
     @Test
@@ -2849,13 +2849,13 @@ public final class CipherTest {
          */
         c.init(Cipher.ENCRYPT_MODE, pubKey);
         byte[] encrypted = c.doFinal(TooShort_Vector);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_ZeroPadded_Encrypted, encrypted));
+        assertArrayEquals("Encrypted should match expected",
+                RSA_Vector1_ZeroPadded_Encrypted, encrypted);
 
         c.init(Cipher.DECRYPT_MODE, pubKey);
         encrypted = c.doFinal(TooShort_Vector);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_ZeroPadded_Encrypted, encrypted));
+        assertArrayEquals("Encrypted should match expected",
+                RSA_Vector1_ZeroPadded_Encrypted, encrypted);
     }
 
     @Test
@@ -2929,7 +2929,7 @@ public final class CipherTest {
             c.doFinal(RSA_Vector1_ZeroPadded_Encrypted);
             fail("Should have error when block size is too big.");
         } catch (IllegalBlockSizeException success) {
-            assertFalse(provider, "BC".equals(provider));
+            assertNotEquals("BC", provider);
         } catch (ArrayIndexOutOfBoundsException success) {
             assertEquals("BC", provider);
         }
@@ -2964,7 +2964,7 @@ public final class CipherTest {
             c.doFinal(RSA_Vector1_ZeroPadded_Encrypted);
             fail("Should have error when block size is too big.");
         } catch (IllegalBlockSizeException success) {
-            assertFalse(provider, "BC".equals(provider));
+            assertNotEquals("BC", provider);
         } catch (ArrayIndexOutOfBoundsException success) {
             assertEquals("BC", provider);
         }
@@ -2999,7 +2999,7 @@ public final class CipherTest {
             c.doFinal(tooBig_Vector);
             fail("Should have error when block size is too big.");
         } catch (IllegalBlockSizeException success) {
-            assertFalse(provider, "BC".equals(provider));
+            assertNotEquals("BC", provider);
         } catch (ArrayIndexOutOfBoundsException success) {
             assertEquals("BC", provider);
         }
@@ -3042,6 +3042,7 @@ public final class CipherTest {
             c.getOutputSize(RSA_2048_Vector1.length);
             fail("Should throw IllegalStateException if getOutputSize is called before init");
         } catch (IllegalStateException success) {
+            // Expected.
         }
     }
 
@@ -3541,7 +3542,7 @@ public final class CipherTest {
         }
     }
 
-    private static List<CipherTestParam> DES_CIPHER_TEST_PARAMS = new ArrayList<CipherTestParam>();
+    private static final List<CipherTestParam> DES_CIPHER_TEST_PARAMS = new ArrayList<>();
     static {
         DES_CIPHER_TEST_PARAMS.add(new CipherTestParam(
                 "DESede/CBC/PKCS5Padding",
@@ -3569,7 +3570,7 @@ public final class CipherTest {
                 ));
     }
 
-    private static List<CipherTestParam> ARC4_CIPHER_TEST_PARAMS = new ArrayList<CipherTestParam>();
+    private static final List<CipherTestParam> ARC4_CIPHER_TEST_PARAMS = new ArrayList<>();
     static {
         ARC4_CIPHER_TEST_PARAMS.add(new CipherTestParam(
                 "ARC4",
@@ -3593,7 +3594,7 @@ public final class CipherTest {
         ));
     }
 
-    private static List<CipherTestParam> CIPHER_TEST_PARAMS = new ArrayList<CipherTestParam>();
+    private static final List<CipherTestParam> CIPHER_TEST_PARAMS = new ArrayList<>();
     static {
         CIPHER_TEST_PARAMS.add(new CipherTestParam(
                 "AES/ECB/PKCS5Padding",
@@ -3651,7 +3652,7 @@ public final class CipherTest {
         }
     }
 
-    private static final List<CipherTestParam> RSA_OAEP_CIPHER_TEST_PARAMS = new ArrayList<CipherTestParam>();
+    private static final List<CipherTestParam> RSA_OAEP_CIPHER_TEST_PARAMS = new ArrayList<>();
     static {
         addRsaOaepTest("SHA-1", MGF1ParameterSpec.SHA1, RSA_Vector2_OAEP_SHA1_MGF1_SHA1);
         addRsaOaepTest("SHA-256", MGF1ParameterSpec.SHA1, RSA_Vector2_OAEP_SHA256_MGF1_SHA1);
@@ -3728,7 +3729,7 @@ public final class CipherTest {
         ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
         PrintStream out = new PrintStream(errBuffer);
         for (CipherTestParam testVector : testVectors) {
-            ArrayList<Provider> providers = new ArrayList<Provider>();
+            ArrayList<Provider> providers = new ArrayList<>();
 
             Provider[] providerArray = Security.getProviders("Cipher." + testVector.transformation);
             if (providerArray != null) {
@@ -3772,7 +3773,7 @@ public final class CipherTest {
         }
         out.flush();
         if (errBuffer.size() > 0) {
-            throw new Exception("Errors encountered:\n\n" + errBuffer.toString() + "\n\n");
+            throw new Exception("Errors encountered:\n\n" + errBuffer + "\n\n");
         }
     }
 
@@ -3788,7 +3789,7 @@ public final class CipherTest {
         }
         out.flush();
         if (errBuffer.size() > 0) {
-            throw new Exception("Errors encountered:\n\n" + errBuffer.toString() + "\n\n");
+            throw new Exception("Errors encountered:\n\n" + errBuffer + "\n\n");
         }
     }
 
@@ -3878,8 +3879,7 @@ public final class CipherTest {
             try {
                 c.updateAAD(new byte[8]);
                 fail("Cipher should not support AAD");
-            } catch (UnsupportedOperationException expected) {
-            } catch (IllegalStateException expected) {
+            } catch (UnsupportedOperationException | IllegalStateException expected) {
             }
         }
 
@@ -3921,6 +3921,14 @@ public final class CipherTest {
                     if (!isAEAD(p.transformation)) {
                         throw maybe;
                     }
+                } catch (ProviderException maybe) {
+                    boolean isShortBufferException
+                            = maybe.getCause() instanceof ShortBufferException;
+                    if (!isAEAD(p.transformation)
+                            || !isBuggyProvider(provider)
+                            || !isShortBufferException) {
+                        throw maybe;
+                    }
                 }
                 try {
                     c.update(new byte[0]);
@@ -3934,6 +3942,14 @@ public final class CipherTest {
                     if (!isAEAD(p.transformation)) {
                         throw maybe;
                     }
+                } catch (ProviderException maybe) {
+                    boolean isShortBufferException
+                            = maybe.getCause() instanceof ShortBufferException;
+                    if (!isAEAD(p.transformation)
+                            || !isBuggyProvider(provider)
+                            || !isShortBufferException) {
+                        throw maybe;
+                    }
                 }
             } else {
                 throw new AssertionError("Define your behavior here for " + provider);
@@ -4028,6 +4044,13 @@ public final class CipherTest {
         }
     }
 
+    // SunJCE has known issues between 17 and 21
+    private boolean isBuggyProvider(String providerName) {
+        return providerName.equals("SunJCE")
+                && TestUtils.isJavaVersion(17)
+                && !TestUtils.isJavaVersion(21);
+    }
+
     /**
      * Gets the Cipher transformation with the same algorithm and mode as the provided one but
      * which uses no padding.
@@ -4039,7 +4062,7 @@ public final class CipherTest {
             fail("No padding mode delimiter: " + transformation);
         }
         String paddingMode = transformation.substring(paddingModeDelimiterIndex + 1);
-        if (!paddingMode.toLowerCase().endsWith("padding")) {
+        if (!paddingMode.toLowerCase(Locale.ROOT).endsWith("padding")) {
             fail("No padding mode specified:" + transformation);
         }
         return transformation.substring(0, paddingModeDelimiterIndex) + "/NoPadding";
@@ -4125,8 +4148,7 @@ public final class CipherTest {
         try {
             c.updateAAD(new byte[8]);
             fail("should not be able to call updateAAD on non-AEAD cipher");
-        } catch (UnsupportedOperationException expected) {
-        } catch (IllegalStateException expected) {
+        } catch (UnsupportedOperationException | IllegalStateException expected) {
         }
     }
 
@@ -4152,7 +4174,7 @@ public final class CipherTest {
         }
         out.flush();
         if (errBuffer.size() > 0) {
-            throw new Exception("Errors encountered:\n\n" + errBuffer.toString() + "\n\n");
+            throw new Exception("Errors encountered:\n\n" + errBuffer + "\n\n");
         }
     }
 
@@ -4218,25 +4240,10 @@ public final class CipherTest {
         String msg = "update() should throw IllegalStateException [mode=" + opmode + "]";
         final int bs = createAesCipher(opmode).getBlockSize();
         assertEquals(16, bs); // check test is set up correctly
-        assertIllegalStateException(msg, new Runnable() {
-            @Override
-            public void run() {
-                createAesCipher(opmode).update(new byte[0]);
-            }
-        });
-        assertIllegalStateException(msg, new Runnable() {
-            @Override
-            public void run() {
-                createAesCipher(opmode).update(new byte[2 * bs]);
-            }
-        });
-        assertIllegalStateException(msg, new Runnable() {
-            @Override
-            public void run() {
-                createAesCipher(opmode).update(
-                        new byte[2 * bs] /* input */, bs /* inputOffset */, 0 /* inputLen */);
-            }
-        });
+        assertIllegalStateException(msg, () -> createAesCipher(opmode).update(new byte[0]));
+        assertIllegalStateException(msg, () -> createAesCipher(opmode).update(new byte[2 * bs]));
+        assertIllegalStateException(msg, () -> createAesCipher(opmode).update(
+                new byte[2 * bs] /* input */, bs /* inputOffset */, 0 /* inputLen */));
         try {
             createAesCipher(opmode).update(new byte[2*bs] /* input */, 0 /* inputOffset */,
                     2 * bs /* inputLen */, new byte[2 * bs] /* output */, 0 /* outputOffset */);
@@ -4364,8 +4371,7 @@ public final class CipherTest {
             try {
                 c.doFinal(null, 0);
                 fail("Should throw NullPointerException on null output buffer");
-            } catch (NullPointerException expected) {
-            } catch (IllegalArgumentException expected) {
+            } catch (NullPointerException | IllegalArgumentException expected) {
             }
         }
 
@@ -4393,7 +4399,7 @@ public final class CipherTest {
         {
             final byte[] output = new byte[c.getBlockSize()];
             assertEquals(AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted.length, c.doFinal(output, 0));
-            assertTrue(Arrays.equals(AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted, output));
+            assertArrayEquals(AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted, output);
         }
     }
 
@@ -4426,7 +4432,7 @@ public final class CipherTest {
         assertEquals(provider, AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext_Padded.length,
                 output.length);
 
-        assertTrue(provider, Arrays.equals(AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted, output));
+        assertArrayEquals(provider, AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted, output);
     }
 
     private static final byte[] AES_IV_ZEROES = new byte[] {
@@ -4480,7 +4486,7 @@ public final class CipherTest {
         String[] expected = new String[LARGEST_KEY_SIZE - SMALLEST_KEY_SIZE];
 
         /* Find all providers that provide ARC4. We must have at least one! */
-        Map<String, String> filter = new HashMap<String, String>();
+        Map<String, String> filter = new HashMap<>();
         filter.put("Cipher.ARC4", "");
         Provider[] providers = Security.getProviders(filter);
         assertTrue("There must be security providers of Cipher.ARC4", providers.length > 0);
@@ -4528,6 +4534,9 @@ public final class CipherTest {
     public void testAES_keyConstrained() throws Exception {
         Provider[] providers = Security.getProviders();
         for (Provider p : providers) {
+            if (isBuggyProvider(p.getName())) {
+                continue;
+            }
             for (Provider.Service s : p.getServices()) {
                 if (s.getType().equals("Cipher")) {
                     if (s.getAlgorithm().startsWith("AES_128/")) {
@@ -4586,7 +4595,7 @@ public final class CipherTest {
                 new String(encryptedBuffer, 0, unencryptedBytes, StandardCharsets.US_ASCII));
     }
 
-    /**
+    /*
      * When using padding in decrypt mode, ensure that empty buffers decode to empty strings
      * (no padding needed for the empty buffer).
      * http://b/19186852
@@ -4618,7 +4627,7 @@ public final class CipherTest {
         }
     }
 
-    /**
+    /*
      * Check that RSA with OAEPPadding is supported.
      * http://b/22208820
      */
@@ -4631,7 +4640,7 @@ public final class CipherTest {
         cipher.doFinal(new byte[] {1,2,3,4});
     }
 
-    /**
+    /*
      * Check that initializing with a GCM AlgorithmParameters produces the same result
      * as initializing with a GCMParameterSpec.
      */
diff --git a/common/src/test/java/org/conscrypt/javax/crypto/KeyGeneratorTest.java b/common/src/test/java/org/conscrypt/javax/crypto/KeyGeneratorTest.java
index 1f25e219..d892a55e 100644
--- a/common/src/test/java/org/conscrypt/javax/crypto/KeyGeneratorTest.java
+++ b/common/src/test/java/org/conscrypt/javax/crypto/KeyGeneratorTest.java
@@ -19,11 +19,11 @@ package org.conscrypt.javax.crypto;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotNull;
 
-import java.security.Provider;
 import java.security.SecureRandom;
 import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.List;
+import java.util.Locale;
 import java.util.Map;
 import javax.crypto.KeyGenerator;
 import javax.crypto.SecretKey;
@@ -61,49 +61,42 @@ public class KeyGeneratorTest {
     }
 
     @Test
-    public void test_getInstance() throws Exception {
+    public void test_getInstance() {
         ServiceTester.test("KeyGenerator")
             // Do not test AndroidKeyStore's KeyGenerator. It cannot be initialized without
             // providing AndroidKeyStore-specific algorithm parameters.
             // It's OKish not to test AndroidKeyStore's KeyGenerator here because it's tested
             // by cts/tests/test/keystore.
             .skipProvider("AndroidKeyStore")
-            .run(new ServiceTester.Test() {
-                @Override
-                public void test(Provider provider, String algorithm) throws Exception {
-                    // KeyGenerator.getInstance(String)
-                    KeyGenerator kg1 = KeyGenerator.getInstance(algorithm);
-                    assertEquals(algorithm, kg1.getAlgorithm());
-                    test_KeyGenerator(kg1);
-
-                    // KeyGenerator.getInstance(String, Provider)
-                    KeyGenerator kg2 = KeyGenerator.getInstance(algorithm, provider);
-                    assertEquals(algorithm, kg2.getAlgorithm());
-                    assertEquals(provider, kg2.getProvider());
-                    test_KeyGenerator(kg2);
-
-                    // KeyGenerator.getInstance(String, String)
-                    KeyGenerator kg3 = KeyGenerator.getInstance(algorithm, provider.getName());
-                    assertEquals(algorithm, kg3.getAlgorithm());
-                    assertEquals(provider, kg3.getProvider());
-                    test_KeyGenerator(kg3);
-                }
+            .run((provider, algorithm) -> {
+                // KeyGenerator.getInstance(String)
+                KeyGenerator kg1 = KeyGenerator.getInstance(algorithm);
+                assertEquals(algorithm, kg1.getAlgorithm());
+                test_KeyGenerator(kg1);
+
+                // KeyGenerator.getInstance(String, Provider)
+                KeyGenerator kg2 = KeyGenerator.getInstance(algorithm, provider);
+                assertEquals(algorithm, kg2.getAlgorithm());
+                assertEquals(provider, kg2.getProvider());
+                test_KeyGenerator(kg2);
+
+                // KeyGenerator.getInstance(String, String)
+                KeyGenerator kg3 = KeyGenerator.getInstance(algorithm, provider.getName());
+                assertEquals(algorithm, kg3.getAlgorithm());
+                assertEquals(provider, kg3.getProvider());
+                test_KeyGenerator(kg3);
             });
     }
 
-    private static final Map<String, List<Integer>> KEY_SIZES
-            = new HashMap<String, List<Integer>>();
+    private static final Map<String, List<Integer>> KEY_SIZES = new HashMap<>();
     private static void putKeySize(String algorithm, int keySize) {
-        algorithm = algorithm.toUpperCase();
-        List<Integer> keySizes = KEY_SIZES.get(algorithm);
-        if (keySizes == null) {
-            keySizes = new ArrayList<Integer>();
-            KEY_SIZES.put(algorithm, keySizes);
-        }
+        algorithm = algorithm.toUpperCase(Locale.ROOT);
+        List<Integer> keySizes =
+                KEY_SIZES.computeIfAbsent(algorithm, k -> new ArrayList<>());
         keySizes.add(keySize);
     }
     private static List<Integer> getKeySizes(String algorithm) throws Exception {
-        algorithm = algorithm.toUpperCase();
+        algorithm = algorithm.toUpperCase(Locale.ROOT);
         List<Integer> keySizes = KEY_SIZES.get(algorithm);
         if (keySizes == null) {
             throw new Exception("Unknown key sizes for KeyGenerator." + algorithm);
@@ -164,7 +157,7 @@ public class KeyGeneratorTest {
             kg.init(keySize);
             test_SecretKey(kg, kg.generateKey());
 
-            kg.init(keySize, (SecureRandom) null);
+            kg.init(keySize, null);
             test_SecretKey(kg, kg.generateKey());
 
             kg.init(keySize, new SecureRandom());
@@ -172,9 +165,10 @@ public class KeyGeneratorTest {
         }
     }
 
-    private void test_SecretKey(KeyGenerator kg, SecretKey sk) throws Exception {
+    private void test_SecretKey(KeyGenerator kg, SecretKey sk) {
         assertNotNull(sk);
-        assertEquals(kg.getAlgorithm().toUpperCase(), sk.getAlgorithm().toUpperCase());
+        assertEquals(kg.getAlgorithm().toUpperCase(Locale.ROOT),
+                sk.getAlgorithm().toUpperCase(Locale.ROOT));
         assertNotNull(sk.getEncoded());
         assertNotNull(sk.getFormat());
     }
diff --git a/common/src/test/java/org/conscrypt/javax/net/ssl/HttpsURLConnectionTest.java b/common/src/test/java/org/conscrypt/javax/net/ssl/HttpsURLConnectionTest.java
index 0e89109b..7f760ea7 100644
--- a/common/src/test/java/org/conscrypt/javax/net/ssl/HttpsURLConnectionTest.java
+++ b/common/src/test/java/org/conscrypt/javax/net/ssl/HttpsURLConnectionTest.java
@@ -23,7 +23,6 @@ import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 
 import java.io.IOException;
-import java.net.HttpURLConnection;
 import java.net.InetAddress;
 import java.net.Socket;
 import java.net.SocketException;
@@ -33,7 +32,6 @@ import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
 import java.util.concurrent.TimeUnit;
-import java.util.concurrent.TimeoutException;
 import javax.net.ssl.HostnameVerifier;
 import javax.net.ssl.HttpsURLConnection;
 import javax.net.ssl.SSLSession;
@@ -41,7 +39,6 @@ import javax.net.ssl.SSLSocketFactory;
 import org.conscrypt.TestUtils;
 import org.conscrypt.VeryBasicHttpServer;
 import org.junit.After;
-import org.junit.Ignore;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
@@ -190,11 +187,7 @@ public class HttpsURLConnectionTest {
             }
             return null;
         });
-        try {
-            future.get(2 * timeoutMillis, TimeUnit.MILLISECONDS);
-        } catch (TimeoutException e) {
-            fail("HttpsURLConnection connection timeout failed.");
-        }
+        future.get(2 * timeoutMillis, TimeUnit.MILLISECONDS);
     }
 
     @Test
diff --git a/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java b/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
index e2cc79bb..2382f28b 100644
--- a/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
+++ b/common/src/test/java/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
@@ -66,6 +66,7 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.List;
+import java.util.Locale;
 import java.util.concurrent.Callable;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
@@ -115,9 +116,7 @@ import org.conscrypt.tlswire.record.TlsRecord;
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Ignore;
-import org.junit.Rule;
 import org.junit.Test;
-import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
 import org.junit.runners.Parameterized;
 import tests.net.DelegatingSSLSocketFactory;
@@ -130,10 +129,6 @@ import tests.util.Pair;
  */
 @RunWith(Parameterized.class)
 public class SSLSocketVersionCompatibilityTest {
-
-    @Rule
-    public TestRule switchTargetSdkVersionRule = SwitchTargetSdkVersionRule.getInstance();
-
     @Parameterized.Parameters(name = "{index}: {0} client, {1} server")
     public static Iterable<Object[]> data() {
         return Arrays.asList(new Object[][] {
@@ -157,12 +152,7 @@ public class SSLSocketVersionCompatibilityTest {
     @Before
     public void setup() {
         threadGroup = new ThreadGroup("SSLSocketVersionedTest");
-        executor = Executors.newCachedThreadPool(new ThreadFactory() {
-            @Override
-            public Thread newThread(Runnable r) {
-                return new Thread(threadGroup, r);
-            }
-        });
+        executor = Executors.newCachedThreadPool(r -> new Thread(threadGroup, r));
     }
 
     @After
@@ -179,27 +169,24 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                server.startHandshake();
-                assertNotNull(server.getSession());
-                assertNull(server.getHandshakeSession());
-                try {
-                    server.getSession().getPeerCertificates();
-                    fail();
-                } catch (SSLPeerUnverifiedException expected) {
-                    // Ignored.
-                }
-                Certificate[] localCertificates = server.getSession().getLocalCertificates();
-                assertNotNull(localCertificates);
-                TestKeyStore.assertChainLength(localCertificates);
-                assertNotNull(localCertificates[0]);
-                TestSSLContext
-                    .assertServerCertificateChain(c.serverTrustManager, localCertificates);
-                TestSSLContext.assertCertificateInKeyStore(localCertificates[0], c.serverKeyStore);
-                return null;
+        Future<Void> future = runAsync(() -> {
+            server.startHandshake();
+            assertNotNull(server.getSession());
+            assertNull(server.getHandshakeSession());
+            try {
+                server.getSession().getPeerCertificates();
+                fail();
+            } catch (SSLPeerUnverifiedException expected) {
+                // Ignored.
             }
+            Certificate[] localCertificates = server.getSession().getLocalCertificates();
+            assertNotNull(localCertificates);
+            TestKeyStore.assertChainLength(localCertificates);
+            assertNotNull(localCertificates[0]);
+            TestSSLContext
+                .assertServerCertificateChain(c.serverTrustManager, localCertificates);
+            TestSSLContext.assertCertificateInKeyStore(localCertificates[0], c.serverKeyStore);
+            return null;
         });
         client.startHandshake();
         assertNotNull(client.getSession());
@@ -244,7 +231,7 @@ public class SSLSocketVersionCompatibilityTest {
         assertNotNull(client1.getSession().getId());
         final byte[] clientSessionId1 = client1.getSession().getId();
         final byte[] serverSessionId1 = future1.get();
-        assertTrue(Arrays.equals(clientSessionId1, serverSessionId1));
+        assertArrayEquals(clientSessionId1, serverSessionId1);
         client1.close();
         server1.close();
         final SSLSocket client2 = (SSLSocket) c.clientContext.getSocketFactory().createSocket(
@@ -256,10 +243,10 @@ public class SSLSocketVersionCompatibilityTest {
         assertNotNull(client2.getSession().getId());
         final byte[] clientSessionId2 = client2.getSession().getId();
         final byte[] serverSessionId2 = future2.get();
-        assertTrue(Arrays.equals(clientSessionId2, serverSessionId2));
+        assertArrayEquals(clientSessionId2, serverSessionId2);
         client2.close();
         server2.close();
-        assertTrue(Arrays.equals(clientSessionId1, clientSessionId2));
+        assertArrayEquals(clientSessionId1, clientSessionId2);
         c.close();
     }
 
@@ -274,17 +261,14 @@ public class SSLSocketVersionCompatibilityTest {
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         client.setEnabledCipherSuites(new String[0]);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    server.startHandshake();
-                    fail();
-                } catch (SSLHandshakeException expected) {
-                    // Ignored.
-                }
-                return null;
+        Future<Void> future = runAsync(() -> {
+            try {
+                server.startHandshake();
+                fail();
+            } catch (SSLHandshakeException expected) {
+                // Ignored.
             }
+            return null;
         });
         try {
             client.startHandshake();
@@ -308,17 +292,14 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    server.startHandshake();
-                    fail();
-                } catch (SSLHandshakeException expected) {
-                    // Ignored.
-                }
-                return null;
+        Future<Void> future = runAsync(() -> {
+            try {
+                server.startHandshake();
+                fail();
+            } catch (SSLHandshakeException expected) {
+                // Ignored.
             }
+            return null;
         });
         try {
             client.startHandshake();
@@ -342,12 +323,9 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                server.startHandshake();
-                return null;
-            }
+        Future<Void> future = runAsync(() -> {
+            server.startHandshake();
+            return null;
         });
         client.startHandshake();
         future.get();
@@ -357,6 +335,7 @@ public class SSLSocketVersionCompatibilityTest {
     }
 
     @Test
+    @SuppressWarnings("deprecation")
     public void test_SSLSocket_HandshakeCompletedListener() throws Exception {
         final TestSSLContext c = new TestSSLContext.Builder()
                 .clientProtocol(clientVersion)
@@ -365,12 +344,9 @@ public class SSLSocketVersionCompatibilityTest {
         final SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                server.startHandshake();
-                return null;
-            }
+        Future<Void> future = runAsync(() -> {
+            server.startHandshake();
+            return null;
         });
         final boolean[] handshakeCompletedListenerCalled = new boolean[1];
         client.addHandshakeCompletedListener(new HandshakeCompletedListener() {
@@ -382,8 +358,6 @@ public class SSLSocketVersionCompatibilityTest {
                     String cipherSuite = event.getCipherSuite();
                     Certificate[] localCertificates = event.getLocalCertificates();
                     Certificate[] peerCertificates = event.getPeerCertificates();
-                    javax.security.cert.X509Certificate[] peerCertificateChain =
-                        event.getPeerCertificateChain();
                     Principal peerPrincipal = event.getPeerPrincipal();
                     Principal localPrincipal = event.getLocalPrincipal();
                     socket = event.getSocket();
@@ -412,17 +386,21 @@ public class SSLSocketVersionCompatibilityTest {
                         .assertServerCertificateChain(c.clientTrustManager, peerCertificates);
                     TestSSLContext
                         .assertCertificateInKeyStore(peerCertificates[0], c.serverKeyStore);
-                    assertNotNull(peerCertificateChain);
-                    TestKeyStore.assertChainLength(peerCertificateChain);
-                    assertNotNull(peerCertificateChain[0]);
-                    TestSSLContext.assertCertificateInKeyStore(
-                        peerCertificateChain[0].getSubjectDN(), c.serverKeyStore);
                     assertNotNull(peerPrincipal);
                     TestSSLContext.assertCertificateInKeyStore(peerPrincipal, c.serverKeyStore);
                     assertNull(localPrincipal);
                     assertNotNull(socket);
                     assertSame(client, socket);
                     assertNull(socket.getHandshakeSession());
+                    if (TestUtils.isJavaxCertificateSupported()) {
+                        javax.security.cert.X509Certificate[] peerCertificateChain =
+                                event.getPeerCertificateChain();
+                        assertNotNull(peerCertificateChain);
+                        TestKeyStore.assertChainLength(peerCertificateChain);
+                        assertNotNull(peerCertificateChain[0]);
+                        TestSSLContext.assertCertificateInKeyStore(
+                                peerCertificateChain[0].getSubjectDN(), c.serverKeyStore);
+                    }
                 } catch (RuntimeException e) {
                     throw e;
                 } catch (Exception e) {
@@ -478,18 +456,12 @@ public class SSLSocketVersionCompatibilityTest {
         final SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                server.startHandshake();
-                return null;
-            }
+        Future<Void> future = runAsync(() -> {
+            server.startHandshake();
+            return null;
         });
-        client.addHandshakeCompletedListener(new HandshakeCompletedListener() {
-            @Override
-            public void handshakeCompleted(HandshakeCompletedEvent event) {
-                throw expectedException;
-            }
+        client.addHandshakeCompletedListener(event -> {
+            throw expectedException;
         });
         client.startHandshake();
         future.get();
@@ -543,7 +515,7 @@ public class SSLSocketVersionCompatibilityTest {
         } catch (SSLHandshakeException expected) {
             // Depending on the timing of the socket closures, this can happen as well.
             assertTrue("Unexpected handshake error: " + expected.getMessage(),
-                    expected.getMessage().toLowerCase().contains("connection closed"));
+                    expected.getMessage().toLowerCase(Locale.ROOT).contains("connection closed"));
         }
     }
 
@@ -556,21 +528,16 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<IOException> future = runAsync(new Callable<IOException>() {
-            @Override
-            public IOException call() throws Exception {
-                try {
-                    if (!serverClientMode) {
-                        server.setSoTimeout(1000);
-                    }
-                    server.setUseClientMode(serverClientMode);
-                    server.startHandshake();
-                    return null;
-                } catch (SSLHandshakeException e) {
-                    return e;
-                } catch (SocketTimeoutException e) {
-                    return e;
+        Future<IOException> future = runAsync(() -> {
+            try {
+                if (!serverClientMode) {
+                    server.setSoTimeout(1000);
                 }
+                server.setUseClientMode(serverClientMode);
+                server.startHandshake();
+                return null;
+            } catch (SSLHandshakeException | SocketTimeoutException e) {
+                return e;
             }
         });
         if (!clientClientMode) {
@@ -598,26 +565,23 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                assertFalse(server.getWantClientAuth());
-                assertFalse(server.getNeedClientAuth());
-                // confirm turning one on by itself
-                server.setWantClientAuth(true);
-                assertTrue(server.getWantClientAuth());
-                assertFalse(server.getNeedClientAuth());
-                // confirm turning setting on toggles the other
-                server.setNeedClientAuth(true);
-                assertFalse(server.getWantClientAuth());
-                assertTrue(server.getNeedClientAuth());
-                // confirm toggling back
-                server.setWantClientAuth(true);
-                assertTrue(server.getWantClientAuth());
-                assertFalse(server.getNeedClientAuth());
-                server.startHandshake();
-                return null;
-            }
+        Future<Void> future = runAsync(() -> {
+            assertFalse(server.getWantClientAuth());
+            assertFalse(server.getNeedClientAuth());
+            // confirm turning one on by itself
+            server.setWantClientAuth(true);
+            assertTrue(server.getWantClientAuth());
+            assertFalse(server.getNeedClientAuth());
+            // confirm turning setting on toggles the other
+            server.setNeedClientAuth(true);
+            assertFalse(server.getWantClientAuth());
+            assertTrue(server.getNeedClientAuth());
+            // confirm toggling back
+            server.setWantClientAuth(true);
+            assertTrue(server.getWantClientAuth());
+            assertFalse(server.getNeedClientAuth());
+            server.startHandshake();
+            return null;
         });
         client.startHandshake();
         assertNotNull(client.getSession().getLocalCertificates());
@@ -680,18 +644,15 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    server.setNeedClientAuth(true);
-                    server.startHandshake();
-                    fail();
-                } catch (SSLHandshakeException expected) {
-                    // Ignored.
-                }
-                return null;
+        Future<Void> future = runAsync(() -> {
+            try {
+                server.setNeedClientAuth(true);
+                server.startHandshake();
+                fail();
+            } catch (SSLHandshakeException expected) {
+                // Ignored.
             }
+            return null;
         });
         try {
             client.startHandshake();
@@ -781,13 +742,10 @@ public class SSLSocketVersionCompatibilityTest {
             SSLSocket client =
                     (SSLSocket) clientContext.getSocketFactory().createSocket(c.host, c.port);
             final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-            Future<Void> future = runAsync(new Callable<Void>() {
-                @Override
-                public Void call() throws Exception {
-                    server.setNeedClientAuth(true);
-                    server.startHandshake();
-                    return null;
-                }
+            Future<Void> future = runAsync(() -> {
+                server.setNeedClientAuth(true);
+                server.startHandshake();
+                return null;
             });
             client.startHandshake();
             assertNotNull(client.getSession().getLocalCertificates());
@@ -812,13 +770,11 @@ public class SSLSocketVersionCompatibilityTest {
         SSLContext clientContext = SSLContext.getInstance("TLS");
         X509TrustManager trustManager = new X509TrustManager() {
             @Override
-            public void checkClientTrusted(X509Certificate[] chain, String authType)
-                    throws CertificateException {
+            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                 throw new AssertionError();
             }
             @Override
-            public void checkServerTrusted(X509Certificate[] chain, String authType)
-                    throws CertificateException {
+            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                 throw new RuntimeException(); // throw a RuntimeException from custom TrustManager
             }
             @Override
@@ -830,17 +786,14 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    server.startHandshake();
-                    fail();
-                } catch (SSLHandshakeException expected) {
-                    // Ignored.
-                }
-                return null;
+        Future<Void> future = runAsync(() -> {
+            try {
+                server.startHandshake();
+                fail();
+            } catch (SSLHandshakeException expected) {
+                // Ignored.
             }
+            return null;
         });
         try {
             client.startHandshake();
@@ -879,18 +832,15 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                server.setEnableSessionCreation(false);
-                try {
-                    server.startHandshake();
-                    fail();
-                } catch (SSLException expected) {
-                    // Ignored.
-                }
-                return null;
+        Future<Void> future = runAsync(() -> {
+            server.setEnableSessionCreation(false);
+            try {
+                server.startHandshake();
+                fail();
+            } catch (SSLException expected) {
+                // Ignored.
             }
+            return null;
         });
         try {
             client.startHandshake();
@@ -913,17 +863,14 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    server.startHandshake();
-                    fail();
-                } catch (SSLException expected) {
-                    // Ignored.
-                }
-                return null;
+        Future<Void> future = runAsync(() -> {
+            try {
+                server.startHandshake();
+                fail();
+            } catch (SSLException expected) {
+                // Ignored.
             }
+            return null;
         });
         client.setEnableSessionCreation(false);
         try {
@@ -959,11 +906,7 @@ public class SSLSocketVersionCompatibilityTest {
         server.close();
         client.close();
         // ...so are a lot of other operations...
-        HandshakeCompletedListener l = new HandshakeCompletedListener() {
-            @Override
-            public void handshakeCompleted(HandshakeCompletedEvent e) {
-            }
-        };
+        HandshakeCompletedListener l = e -> { };
         client.addHandshakeCompletedListener(l);
         assertNotNull(client.getEnabledCipherSuites());
         assertNotNull(client.getEnabledProtocols());
@@ -1011,9 +954,7 @@ public class SSLSocketVersionCompatibilityTest {
             @SuppressWarnings("unused")
             int bytesRead = input.read(null, -1, -1);
             fail();
-        } catch (NullPointerException expected) {
-            // Ignored.
-        } catch (SocketException expected) {
+        } catch (NullPointerException | SocketException expected) {
             // Ignored.
         }
         try {
@@ -1025,9 +966,7 @@ public class SSLSocketVersionCompatibilityTest {
         try {
             output.write(null, -1, -1);
             fail();
-        } catch (NullPointerException expected) {
-            // Ignored.
-        } catch (SocketException expected) {
+        } catch (NullPointerException | SocketException expected) {
             // Ignored.
         }
         // ... and one gives IllegalArgumentException
@@ -1166,17 +1105,14 @@ public class SSLSocketVersionCompatibilityTest {
         final Socket underlying = new Socket(c.host, c.port);
         final SSLSocket wrapping = (SSLSocket) c.clientContext.getSocketFactory().createSocket(
                 underlying, c.host.getHostName(), c.port, false);
-        Future<Void> clientFuture = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                wrapping.startHandshake();
-                wrapping.getOutputStream().write(42);
-                // close the underlying socket,
-                // so that no SSL shutdown is sent
-                underlying.close();
-                wrapping.close();
-                return null;
-            }
+        Future<Void> clientFuture = runAsync(() -> {
+            wrapping.startHandshake();
+            wrapping.getOutputStream().write(42);
+            // close the underlying socket,
+            // so that no SSL shutdown is sent
+            underlying.close();
+            wrapping.close();
+            return null;
         });
         SSLSocket server = (SSLSocket) c.serverSocket.accept();
         server.startHandshake();
@@ -1207,25 +1143,22 @@ public class SSLSocketVersionCompatibilityTest {
             client.setSSLParameters(p);
             client.connect(new InetSocketAddress(c.host, c.port));
             final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-            Future<Void> future = runAsync(new Callable<Void>() {
-                @Override
-                public Void call() throws Exception {
-                    server.startHandshake();
-                    assertNotNull(server.getSession());
-                    try {
-                        server.getSession().getPeerCertificates();
-                        fail();
-                    } catch (SSLPeerUnverifiedException expected) {
-                        // Ignored.
-                    }
-                    Certificate[] localCertificates = server.getSession().getLocalCertificates();
-                    assertNotNull(localCertificates);
-                    TestKeyStore.assertChainLength(localCertificates);
-                    assertNotNull(localCertificates[0]);
-                    TestSSLContext
-                            .assertCertificateInKeyStore(localCertificates[0], c.serverKeyStore);
-                    return null;
+            Future<Void> future = runAsync(() -> {
+                server.startHandshake();
+                assertNotNull(server.getSession());
+                try {
+                    server.getSession().getPeerCertificates();
+                    fail();
+                } catch (SSLPeerUnverifiedException expected) {
+                    // Ignored.
                 }
+                Certificate[] localCertificates = server.getSession().getLocalCertificates();
+                assertNotNull(localCertificates);
+                TestKeyStore.assertChainLength(localCertificates);
+                assertNotNull(localCertificates[0]);
+                TestSSLContext
+                        .assertCertificateInKeyStore(localCertificates[0], c.serverKeyStore);
+                return null;
             });
             client.startHandshake();
             assertNotNull(client.getSession());
@@ -1262,17 +1195,14 @@ public class SSLSocketVersionCompatibilityTest {
             client.setSSLParameters(p);
             client.connect(c.getLoopbackAsHostname("unmatched.example.com", c.port));
             final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-            Future<Void> future = runAsync(new Callable<Void>() {
-                @Override
-                public Void call() throws Exception {
-                    try {
-                        server.startHandshake();
-                        fail("Should receive SSLHandshakeException as server");
-                    } catch (SSLHandshakeException expected) {
-                        // Ignored.
-                    }
-                    return null;
+            Future<Void> future = runAsync(() -> {
+                try {
+                    server.startHandshake();
+                    fail("Should receive SSLHandshakeException as server");
+                } catch (SSLHandshakeException expected) {
+                    // Ignored.
                 }
+                return null;
             });
             try {
                 client.startHandshake();
@@ -1322,12 +1252,9 @@ public class SSLSocketVersionCompatibilityTest {
 
         // Start the handshake.
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                client.startHandshake();
-                return null;
-            }
+        Future<Void> future = runAsync(() -> {
+            client.startHandshake();
+            return null;
         });
         server.startHandshake();
 
@@ -1387,12 +1314,9 @@ public class SSLSocketVersionCompatibilityTest {
             assertTrue(isConscryptSocket(server));
             setNpnProtocols.invoke(server, npnProtocols);
 
-            Future<Void> future = executor.submit(new Callable<Void>() {
-                @Override
-                public Void call() throws Exception {
-                    server.startHandshake();
-                    return null;
-                }
+            Future<Void> future = executor.submit(() -> {
+                server.startHandshake();
+                return null;
             });
             client.startHandshake();
 
@@ -1414,12 +1338,9 @@ public class SSLSocketVersionCompatibilityTest {
 
             final SSLSocket server = (SSLSocket) serverSocket.accept();
 
-            Future<Void> future = executor.submit(new Callable<Void>() {
-                @Override
-                public Void call() throws Exception {
-                    server.startHandshake();
-                    return null;
-                }
+            Future<Void> future = executor.submit(() -> {
+                server.startHandshake();
+                return null;
             });
             client.startHandshake();
 
@@ -1477,12 +1398,9 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket server = (SSLSocket) c.serverSocket.accept();
 
         // Start the handshake.
-        Future<Integer> handshakeFuture = runAsync(new Callable<Integer>() {
-            @Override
-            public Integer call() throws Exception {
-                clientWrapping.startHandshake();
-                return clientWrapping.getInputStream().read();
-            }
+        Future<Integer> handshakeFuture = runAsync(() -> {
+            clientWrapping.startHandshake();
+            return clientWrapping.getInputStream().read();
         });
         server.startHandshake();
         // TLS 1.3 sends some post-handshake management messages, so send a single byte through
@@ -1494,13 +1412,10 @@ public class SSLSocketVersionCompatibilityTest {
         final Socket toClose = closeUnderlying ? underlying : clientWrapping;
 
         // Schedule the socket to be closed in 1 second.
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                Thread.sleep(1000);
-                toClose.close();
-                return null;
-            }
+        Future<Void> future = runAsync(() -> {
+            Thread.sleep(1000);
+            toClose.close();
+            return null;
         });
 
         // Read from the socket.
@@ -1548,21 +1463,18 @@ public class SSLSocketVersionCompatibilityTest {
         // TODO(nmittler): Interrupts do not work with the engine-based socket.
         assumeFalse(isConscryptEngineSocket(wrapping));
 
-        Future<Void> clientFuture = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                wrapping.startHandshake();
-                try {
-                    wrapping.setSoTimeout(readingTimeoutMillis);
-                    wrapping.getInputStream().read();
-                    fail();
-                } catch (SocketException expected) {
-                    // Conscrypt throws an exception complaining that the socket is closed
-                    // if it's interrupted by a close() in the middle of a read()
-                    assertTrue(expected.getMessage().contains("closed"));
-                }
-                return null;
+        Future<Void> clientFuture = runAsync(() -> {
+            wrapping.startHandshake();
+            try {
+                wrapping.setSoTimeout(readingTimeoutMillis);
+                wrapping.getInputStream().read();
+                fail();
+            } catch (SocketException expected) {
+                // Conscrypt throws an exception complaining that the socket is closed
+                // if it's interrupted by a close() in the middle of a read()
+                assertTrue(expected.getMessage().contains("closed"));
             }
+            return null;
         });
         SSLSocket server = (SSLSocket) c.serverSocket.accept();
         server.startHandshake();
@@ -1593,7 +1505,7 @@ public class SSLSocketVersionCompatibilityTest {
         server.close();
     }
 
-    /**
+    /*
      * Test to confirm that an SSLSocket.close() on one
      * thread will interrupt another thread blocked writing on the same
      * socket.
@@ -1606,7 +1518,7 @@ public class SSLSocketVersionCompatibilityTest {
      * See also b/147323301 where close() triggered an infinite loop instead.
      */
     @Test
-    @Ignore
+    @Ignore("See comment above")
     public void test_SSLSocket_interrupt_write_withAutoclose() throws Exception {
         final TestSSLContext c = new TestSSLContext.Builder()
             .clientProtocol(clientVersion)
@@ -1619,22 +1531,19 @@ public class SSLSocketVersionCompatibilityTest {
 
         // TODO(b/161347005): Re-enable once engine-based socket interruption works correctly.
         assumeFalse(isConscryptEngineSocket(wrapping));
-        Future<Void> clientFuture = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                wrapping.startHandshake();
-                try {
-                    for (int i = 0; i < 64; i++) {
-                        wrapping.getOutputStream().write(data);
-                    }
-                    // Failure here means that no exception was thrown, so the data buffer is
-                    // probably too small.
-                    fail();
-                } catch (SocketException expected) {
-                    assertTrue(expected.getMessage().contains("closed"));
+        Future<Void> clientFuture = runAsync(() -> {
+            wrapping.startHandshake();
+            try {
+                for (int i = 0; i < 64; i++) {
+                    wrapping.getOutputStream().write(data);
                 }
-                return null;
+                // Failure here means that no exception was thrown, so the data buffer is
+                // probably too small.
+                fail();
+            } catch (SocketException expected) {
+                assertTrue(expected.getMessage().contains("closed"));
             }
+            return null;
         });
         SSLSocket server = (SSLSocket) c.serverSocket.accept();
         server.startHandshake();
@@ -1685,18 +1594,15 @@ public class SSLSocketVersionCompatibilityTest {
 
     @Test
     public void test_SSLSocket_ClientHello_SNI() throws Exception {
-        ForEachRunner.runNamed(new ForEachRunner.Callback<SSLSocketFactory>() {
-            @Override
-            public void run(SSLSocketFactory sslSocketFactory) throws Exception {
-                ClientHello clientHello = TlsTester
-                    .captureTlsHandshakeClientHello(executor, sslSocketFactory);
-                ServerNameHelloExtension sniExtension =
-                    (ServerNameHelloExtension) clientHello.findExtensionByType(
-                        HelloExtension.TYPE_SERVER_NAME);
-                assertNotNull(sniExtension);
-                assertEquals(
-                    Collections.singletonList("localhost.localdomain"), sniExtension.hostnames);
-            }
+        ForEachRunner.runNamed(sslSocketFactory -> {
+            ClientHello clientHello = TlsTester
+                .captureTlsHandshakeClientHello(executor, sslSocketFactory);
+            ServerNameHelloExtension sniExtension =
+                (ServerNameHelloExtension) clientHello.findExtensionByType(
+                    HelloExtension.TYPE_SERVER_NAME);
+            assertNotNull(sniExtension);
+            assertEquals(
+                Collections.singletonList("localhost.localdomain"), sniExtension.hostnames);
         }, getSSLSocketFactoriesToTest());
     }
 
@@ -1704,29 +1610,26 @@ public class SSLSocketVersionCompatibilityTest {
     public void test_SSLSocket_ClientHello_ALPN() throws Exception {
         final String[] protocolList = new String[] { "h2", "http/1.1" };
 
-        ForEachRunner.runNamed(new ForEachRunner.Callback<SSLSocketFactory>() {
-            @Override
-            public void run(SSLSocketFactory sslSocketFactory) throws Exception {
-                ClientHello clientHello = TlsTester.captureTlsHandshakeClientHello(executor,
-                        new DelegatingSSLSocketFactory(sslSocketFactory) {
-                            @Override public SSLSocket configureSocket(SSLSocket socket) {
-                                Conscrypt.setApplicationProtocols(socket, protocolList);
-                                return socket;
-                            }
-                        });
-                AlpnHelloExtension alpnExtension =
-                        (AlpnHelloExtension) clientHello.findExtensionByType(
-                                HelloExtension.TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
-                assertNotNull(alpnExtension);
-                assertEquals(Arrays.asList(protocolList), alpnExtension.protocols);
-            }
+        ForEachRunner.runNamed(sslSocketFactory -> {
+            ClientHello clientHello = TlsTester.captureTlsHandshakeClientHello(executor,
+                    new DelegatingSSLSocketFactory(sslSocketFactory) {
+                        @Override public SSLSocket configureSocket(SSLSocket socket) {
+                            Conscrypt.setApplicationProtocols(socket, protocolList);
+                            return socket;
+                        }
+                    });
+            AlpnHelloExtension alpnExtension =
+                    (AlpnHelloExtension) clientHello.findExtensionByType(
+                            HelloExtension.TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
+            assertNotNull(alpnExtension);
+            assertEquals(Arrays.asList(protocolList), alpnExtension.protocols);
         }, getSSLSocketFactoriesToTest());
     }
 
     private List<Pair<String, SSLSocketFactory>> getSSLSocketFactoriesToTest()
             throws NoSuchAlgorithmException, KeyManagementException {
         List<Pair<String, SSLSocketFactory>> result =
-                new ArrayList<Pair<String, SSLSocketFactory>>();
+                new ArrayList<>();
         result.add(Pair.of("default", (SSLSocketFactory) SSLSocketFactory.getDefault()));
         for (String sslContextProtocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
             SSLContext sslContext = SSLContext.getInstance(sslContextProtocol);
@@ -1747,14 +1650,12 @@ public class SSLSocketVersionCompatibilityTest {
                 .clientProtocol(clientVersion)
                 .serverProtocol(serverVersion)
                 .build();
-        SSLSocket client =
-            (SSLSocket) context.clientContext.getSocketFactory().createSocket();
-        try {
+        try (SSLSocket client
+                     = (SSLSocket) context.clientContext.getSocketFactory().createSocket()) {
             client.connect(new InetSocketAddress(context.host, context.port));
             setHostname(client);
             assertTrue(client.getPort() > 0);
         } finally {
-            client.close();
             context.close();
         }
     }
@@ -1766,26 +1667,25 @@ public class SSLSocketVersionCompatibilityTest {
                 .clientProtocol(clientVersion)
                 .serverProtocol(serverVersion)
                 .build();
-        final SSLSocket client = (SSLSocket) c.clientContext.getSocketFactory().createSocket();
-        SSLParameters clientParams = client.getSSLParameters();
-        clientParams.setServerNames(
-                Collections.singletonList((SNIServerName) new SNIHostName("www.example.com")));
-        client.setSSLParameters(clientParams);
-        SSLParameters serverParams = c.serverSocket.getSSLParameters();
-        serverParams.setSNIMatchers(
-                Collections.singletonList(SNIHostName.createSNIMatcher("www\\.example\\.com")));
-        c.serverSocket.setSSLParameters(serverParams);
-        client.connect(new InetSocketAddress(c.host, c.port));
-        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        @SuppressWarnings("unused")
-        Future<?> future = runAsync(new Callable<Object>() {
-            @Override
-            public Object call() throws Exception {
+        final SSLSocket server;
+        try (SSLSocket client = (SSLSocket) c.clientContext.getSocketFactory().createSocket()) {
+            SSLParameters clientParams = client.getSSLParameters();
+            clientParams.setServerNames(
+                    Collections.singletonList(new SNIHostName("www.example.com")));
+            client.setSSLParameters(clientParams);
+            SSLParameters serverParams = c.serverSocket.getSSLParameters();
+            serverParams.setSNIMatchers(Collections.singletonList(
+                    SNIHostName.createSNIMatcher("www\\.example\\.com")));
+            c.serverSocket.setSSLParameters(serverParams);
+            client.connect(new InetSocketAddress(c.host, c.port));
+            server = (SSLSocket) c.serverSocket.accept();
+            @SuppressWarnings("unused")
+            Future<?> future = runAsync(() -> {
                 client.startHandshake();
                 return null;
-            }
-        });
-        server.startHandshake();
+            });
+            server.startHandshake();
+        }
         SSLSession serverSession = server.getSession();
         assertTrue(serverSession instanceof ExtendedSSLSession);
         ExtendedSSLSession extendedServerSession = (ExtendedSSLSession) serverSession;
@@ -1797,6 +1697,7 @@ public class SSLSocketVersionCompatibilityTest {
         assertTrue(serverName instanceof SNIHostName);
         SNIHostName serverHostName = (SNIHostName) serverName;
         assertEquals("www.example.com", serverHostName.getAsciiName());
+        server.close();
     }
 
     @Test
@@ -1810,35 +1711,29 @@ public class SSLSocketVersionCompatibilityTest {
         final SSLSocket client = (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                 context.host, listener.getLocalPort());
         final Socket server = listener.accept();
-        Future<Void> c = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    client.startHandshake();
-                    fail("Should receive handshake exception");
-                } catch (SSLHandshakeException expected) {
-                    assertFalse(expected.getMessage().contains("SSL_ERROR_ZERO_RETURN"));
-                    assertFalse(expected.getMessage().contains("You should never see this."));
-                }
-                return null;
+        Future<Void> c = runAsync(() -> {
+            try {
+                client.startHandshake();
+                fail("Should receive handshake exception");
+            } catch (SSLHandshakeException expected) {
+                assertFalse(expected.getMessage().contains("SSL_ERROR_ZERO_RETURN"));
+                assertFalse(expected.getMessage().contains("You should never see this."));
             }
+            return null;
         });
-        Future<Void> s = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                // Wait until the client sends something.
-                byte[] scratch = new byte[8192];
-                @SuppressWarnings("unused")
-                int bytesRead = server.getInputStream().read(scratch);
-                // Write a bogus TLS alert:
-                // TLSv1.2 Record Layer: Alert (Level: Warning, Description: Protocol Version)
-                server.getOutputStream()
-                    .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x46});
-                // TLSv1.2 Record Layer: Alert (Level: Warning, Description: Close Notify)
-                server.getOutputStream()
-                    .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00});
-                return null;
-            }
+        Future<Void> s = runAsync(() -> {
+            // Wait until the client sends something.
+            byte[] scratch = new byte[8192];
+            @SuppressWarnings("unused")
+            int bytesRead = server.getInputStream().read(scratch);
+            // Write a bogus TLS alert:
+            // TLSv1.2 Record Layer: Alert (Level: Warning, Description: Protocol Version)
+            server.getOutputStream()
+                .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x46});
+            // TLSv1.2 Record Layer: Alert (Level: Warning, Description: Close Notify)
+            server.getOutputStream()
+                .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00});
+            return null;
         });
         c.get(5, TimeUnit.SECONDS);
         s.get(5, TimeUnit.SECONDS);
@@ -1857,79 +1752,73 @@ public class SSLSocketVersionCompatibilityTest {
                 .build();
         final Socket client = SocketFactory.getDefault().createSocket(context.host, context.port);
         final SSLSocket server = (SSLSocket) context.serverSocket.accept();
-        Future<Void> s = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    server.startHandshake();
-                    fail("Should receive handshake exception");
-                } catch (SSLHandshakeException expected) {
-                    assertFalse(expected.getMessage().contains("SSL_ERROR_ZERO_RETURN"));
-                    assertFalse(expected.getMessage().contains("You should never see this."));
-                }
-                return null;
+        Future<Void> s = runAsync(() -> {
+            try {
+                server.startHandshake();
+                fail("Should receive handshake exception");
+            } catch (SSLHandshakeException expected) {
+                assertFalse(expected.getMessage().contains("SSL_ERROR_ZERO_RETURN"));
+                assertFalse(expected.getMessage().contains("You should never see this."));
             }
+            return null;
         });
-        Future<Void> c = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                // Send bogus ClientHello:
-                // TLSv1.2 Record Layer: Handshake Protocol: Client Hello
-                client.getOutputStream().write(new byte[]{
-                    (byte) 0x16, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0xb9,
-                    (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0xb5, (byte) 0x03,
-                    (byte) 0x03, (byte) 0x5a, (byte) 0x31, (byte) 0xba, (byte) 0x44,
-                    (byte) 0x24, (byte) 0xfd, (byte) 0xf0, (byte) 0x56, (byte) 0x46,
-                    (byte) 0xea, (byte) 0xee, (byte) 0x1c, (byte) 0x62, (byte) 0x8f,
-                    (byte) 0x18, (byte) 0x04, (byte) 0xbd, (byte) 0x1c, (byte) 0xbc,
-                    (byte) 0xbf, (byte) 0x6d, (byte) 0x84, (byte) 0x12, (byte) 0xe9,
-                    (byte) 0x94, (byte) 0xf5, (byte) 0x1c, (byte) 0x15, (byte) 0x3e,
-                    (byte) 0x79, (byte) 0x01, (byte) 0xe2, (byte) 0x00, (byte) 0x00,
-                    (byte) 0x28, (byte) 0xc0, (byte) 0x2b, (byte) 0xc0, (byte) 0x2c,
-                    (byte) 0xc0, (byte) 0x2f, (byte) 0xc0, (byte) 0x30, (byte) 0x00,
-                    (byte) 0x9e, (byte) 0x00, (byte) 0x9f, (byte) 0xc0, (byte) 0x09,
-                    (byte) 0xc0, (byte) 0x0a, (byte) 0xc0, (byte) 0x13, (byte) 0xc0,
-                    (byte) 0x14, (byte) 0x00, (byte) 0x33, (byte) 0x00, (byte) 0x39,
-                    (byte) 0xc0, (byte) 0x07, (byte) 0xc0, (byte) 0x11, (byte) 0x00,
-                    (byte) 0x9c, (byte) 0x00, (byte) 0x9d, (byte) 0x00, (byte) 0x2f,
-                    (byte) 0x00, (byte) 0x35, (byte) 0x00, (byte) 0x05, (byte) 0x00,
-                    (byte) 0xff, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x64,
-                    (byte) 0x00, (byte) 0x0b, (byte) 0x00, (byte) 0x04, (byte) 0x03,
-                    (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x00, (byte) 0x0a,
-                    (byte) 0x00, (byte) 0x34, (byte) 0x00, (byte) 0x32, (byte) 0x00,
-                    (byte) 0x0e, (byte) 0x00, (byte) 0x0d, (byte) 0x00, (byte) 0x19,
-                    (byte) 0x00, (byte) 0x0b, (byte) 0x00, (byte) 0x0c, (byte) 0x00,
-                    (byte) 0x18, (byte) 0x00, (byte) 0x09, (byte) 0x00, (byte) 0x0a,
-                    (byte) 0x00, (byte) 0x16, (byte) 0x00, (byte) 0x17, (byte) 0x00,
-                    (byte) 0x08, (byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x07,
-                    (byte) 0x00, (byte) 0x14, (byte) 0x00, (byte) 0x15, (byte) 0x00,
-                    (byte) 0x04, (byte) 0x00, (byte) 0x05, (byte) 0x00, (byte) 0x12,
-                    (byte) 0x00, (byte) 0x13, (byte) 0x00, (byte) 0x01, (byte) 0x00,
-                    (byte) 0x02, (byte) 0x00, (byte) 0x03, (byte) 0x00, (byte) 0x0f,
-                    (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x11, (byte) 0x00,
-                    (byte) 0x0d, (byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x1e,
-                    (byte) 0x06, (byte) 0x01, (byte) 0x06, (byte) 0x02, (byte) 0x06,
-                    (byte) 0x03, (byte) 0x05, (byte) 0x01, (byte) 0x05, (byte) 0x02,
-                    (byte) 0x05, (byte) 0x03, (byte) 0x04, (byte) 0x01, (byte) 0x04,
-                    (byte) 0x02, (byte) 0x04, (byte) 0x03, (byte) 0x03, (byte) 0x01,
-                    (byte) 0x03, (byte) 0x02, (byte) 0x03, (byte) 0x03, (byte) 0x02,
-                    (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x03,
-                });
-                // Wait until the server sends something.
-                byte[] scratch = new byte[8192];
-                @SuppressWarnings("unused")
-                int bytesRead = client.getInputStream().read(scratch);
-                // Write a bogus TLS alert:
-                // TLSv1.2 Record Layer: Alert (Level: Warning, Description:
-                // Protocol Version)
-                client.getOutputStream()
-                    .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x46});
-                // TLSv1.2 Record Layer: Alert (Level: Warning, Description:
-                // Close Notify)
-                client.getOutputStream()
-                    .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00});
-                return null;
-            }
+        Future<Void> c = runAsync(() -> {
+            // Send bogus ClientHello:
+            // TLSv1.2 Record Layer: Handshake Protocol: Client Hello
+            client.getOutputStream().write(new byte[]{
+                (byte) 0x16, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0xb9,
+                (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0xb5, (byte) 0x03,
+                (byte) 0x03, (byte) 0x5a, (byte) 0x31, (byte) 0xba, (byte) 0x44,
+                (byte) 0x24, (byte) 0xfd, (byte) 0xf0, (byte) 0x56, (byte) 0x46,
+                (byte) 0xea, (byte) 0xee, (byte) 0x1c, (byte) 0x62, (byte) 0x8f,
+                (byte) 0x18, (byte) 0x04, (byte) 0xbd, (byte) 0x1c, (byte) 0xbc,
+                (byte) 0xbf, (byte) 0x6d, (byte) 0x84, (byte) 0x12, (byte) 0xe9,
+                (byte) 0x94, (byte) 0xf5, (byte) 0x1c, (byte) 0x15, (byte) 0x3e,
+                (byte) 0x79, (byte) 0x01, (byte) 0xe2, (byte) 0x00, (byte) 0x00,
+                (byte) 0x28, (byte) 0xc0, (byte) 0x2b, (byte) 0xc0, (byte) 0x2c,
+                (byte) 0xc0, (byte) 0x2f, (byte) 0xc0, (byte) 0x30, (byte) 0x00,
+                (byte) 0x9e, (byte) 0x00, (byte) 0x9f, (byte) 0xc0, (byte) 0x09,
+                (byte) 0xc0, (byte) 0x0a, (byte) 0xc0, (byte) 0x13, (byte) 0xc0,
+                (byte) 0x14, (byte) 0x00, (byte) 0x33, (byte) 0x00, (byte) 0x39,
+                (byte) 0xc0, (byte) 0x07, (byte) 0xc0, (byte) 0x11, (byte) 0x00,
+                (byte) 0x9c, (byte) 0x00, (byte) 0x9d, (byte) 0x00, (byte) 0x2f,
+                (byte) 0x00, (byte) 0x35, (byte) 0x00, (byte) 0x05, (byte) 0x00,
+                (byte) 0xff, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x64,
+                (byte) 0x00, (byte) 0x0b, (byte) 0x00, (byte) 0x04, (byte) 0x03,
+                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x00, (byte) 0x0a,
+                (byte) 0x00, (byte) 0x34, (byte) 0x00, (byte) 0x32, (byte) 0x00,
+                (byte) 0x0e, (byte) 0x00, (byte) 0x0d, (byte) 0x00, (byte) 0x19,
+                (byte) 0x00, (byte) 0x0b, (byte) 0x00, (byte) 0x0c, (byte) 0x00,
+                (byte) 0x18, (byte) 0x00, (byte) 0x09, (byte) 0x00, (byte) 0x0a,
+                (byte) 0x00, (byte) 0x16, (byte) 0x00, (byte) 0x17, (byte) 0x00,
+                (byte) 0x08, (byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x07,
+                (byte) 0x00, (byte) 0x14, (byte) 0x00, (byte) 0x15, (byte) 0x00,
+                (byte) 0x04, (byte) 0x00, (byte) 0x05, (byte) 0x00, (byte) 0x12,
+                (byte) 0x00, (byte) 0x13, (byte) 0x00, (byte) 0x01, (byte) 0x00,
+                (byte) 0x02, (byte) 0x00, (byte) 0x03, (byte) 0x00, (byte) 0x0f,
+                (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x11, (byte) 0x00,
+                (byte) 0x0d, (byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x1e,
+                (byte) 0x06, (byte) 0x01, (byte) 0x06, (byte) 0x02, (byte) 0x06,
+                (byte) 0x03, (byte) 0x05, (byte) 0x01, (byte) 0x05, (byte) 0x02,
+                (byte) 0x05, (byte) 0x03, (byte) 0x04, (byte) 0x01, (byte) 0x04,
+                (byte) 0x02, (byte) 0x04, (byte) 0x03, (byte) 0x03, (byte) 0x01,
+                (byte) 0x03, (byte) 0x02, (byte) 0x03, (byte) 0x03, (byte) 0x02,
+                (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x03,
+            });
+            // Wait until the server sends something.
+            byte[] scratch = new byte[8192];
+            @SuppressWarnings("unused")
+            int bytesRead = client.getInputStream().read(scratch);
+            // Write a bogus TLS alert:
+            // TLSv1.2 Record Layer: Alert (Level: Warning, Description:
+            // Protocol Version)
+            client.getOutputStream()
+                .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x46});
+            // TLSv1.2 Record Layer: Alert (Level: Warning, Description:
+            // Close Notify)
+            client.getOutputStream()
+                .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00});
+            return null;
         });
         c.get(5, TimeUnit.SECONDS);
         s.get(5, TimeUnit.SECONDS);
@@ -1945,76 +1834,15 @@ public class SSLSocketVersionCompatibilityTest {
                 .clientProtocol(clientVersion)
                 .serverProtocol(serverVersion)
                 .build();
-        final SSLSocket client =
-                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
-        client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1"});
-        assertEquals(2, client.getEnabledProtocols().length);
-    }
-
-    @TargetSdkVersion(35)
-    @Test
-    public void test_SSLSocket_SSLv3Unsupported_35() throws Exception {
-        assumeFalse(isTlsV1Filtered());
-        TestSSLContext context = new TestSSLContext.Builder()
-                .clientProtocol(clientVersion)
-                .serverProtocol(serverVersion)
-                .build();
-        final SSLSocket client =
-                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
-        assertThrows(IllegalArgumentException.class, () -> client.setEnabledProtocols(new String[] {"SSLv3"}));
-        assertThrows(IllegalArgumentException.class, () -> client.setEnabledProtocols(new String[] {"SSL"}));
-    }
-
-    @TargetSdkVersion(34)
-    @Test
-    public void test_SSLSocket_SSLv3Unsupported_34() throws Exception {
-        TestSSLContext context = new TestSSLContext.Builder()
-                .clientProtocol(clientVersion)
-                .serverProtocol(serverVersion)
-                .build();
-        final SSLSocket client =
-                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
-        // For app compatibility, SSLv3 is stripped out when setting only.
-        client.setEnabledProtocols(new String[] {"SSLv3"});
-        assertEquals(0, client.getEnabledProtocols().length);
-        try {
-            client.setEnabledProtocols(new String[] {"SSL"});
-            fail("SSLSocket should not support SSL protocol");
-        } catch (IllegalArgumentException expected) {
-            // Ignored.
+        try (SSLSocket client = (SSLSocket) context.clientContext.getSocketFactory().createSocket())
+        {
+            client.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1"});
+            assertEquals(2, client.getEnabledProtocols().length);
         }
     }
 
-    @TargetSdkVersion(34)
-    @Test
-    public void test_TLSv1Filtered_34() throws Exception {
-        TestSSLContext context = new TestSSLContext.Builder()
-                .clientProtocol(clientVersion)
-                .serverProtocol(serverVersion)
-                .build();
-        final SSLSocket client =
-                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
-        client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"});
-        assertEquals(1, client.getEnabledProtocols().length);
-        assertEquals("TLSv1.2", client.getEnabledProtocols()[0]);
-    }
-
-    @TargetSdkVersion(35)
-    @Test
-    public void test_TLSv1Filtered_35() throws Exception {
-        assumeFalse(isTlsV1Filtered());
-        TestSSLContext context = new TestSSLContext.Builder()
-                .clientProtocol(clientVersion)
-                .serverProtocol(serverVersion)
-                .build();
-        final SSLSocket client =
-                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
-        assertThrows(IllegalArgumentException.class, () ->
-            client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"}));
-    }
-
     @Test
-    public void test_TLSv1Unsupported_notEnabled() throws Exception {
+    public void test_TLSv1Unsupported_notEnabled() {
         assumeTrue(!isTlsV1Supported());
         assertTrue(isTlsV1Deprecated());
     }
@@ -2194,7 +2022,7 @@ public class SSLSocketVersionCompatibilityTest {
             if ("TLSv1.2".equals(negotiatedVersion())) {
                 assertFalse(Arrays.equals(clientEkm, clientContextEkm));
             } else {
-                assertTrue(Arrays.equals(clientEkm, clientContextEkm));
+                assertArrayEquals(clientEkm, clientContextEkm);
             }
         } finally {
             pair.close();
diff --git a/conscrypt.aconfig b/conscrypt.aconfig
index 781a626a..497e630e 100644
--- a/conscrypt.aconfig
+++ b/conscrypt.aconfig
@@ -12,7 +12,7 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-package: "com.android.org.conscrypt"
+package: "com.android.org.conscrypt.flags"
 container: "com.android.conscrypt"
 
 flag {
@@ -24,3 +24,22 @@ flag {
     is_fixed_read_only: true
 }
 
+flag {
+    namespace: "core_libraries"
+    name: "certificate_transparency_checkservertrusted_api"
+    description: "This flag controls whether TrustManagerImpl exposes a checkServerTrusted method for CT verification with OCSP and TLS SCT data"
+    bug: "319829948"
+    # APIs provided by a mainline module can only use a frozen flag.
+    is_fixed_read_only: true
+    is_exported: true
+}
+
+flag {
+    namespace: "core_libraries"
+    name: "spake2plus_api"
+    description: "This flag controls whether SPAKE2+ is exposed by Conscrypt"
+    bug: "382233100"
+    # APIs provided by a mainline module can only use a frozen flag.
+    is_fixed_read_only: true
+    is_exported: true
+}
diff --git a/gradle/libs.versions.toml b/gradle/libs.versions.toml
new file mode 100644
index 00000000..d0120071
--- /dev/null
+++ b/gradle/libs.versions.toml
@@ -0,0 +1,54 @@
+[versions]
+android-tools = "7.4.2"
+bnd = "6.4.0"
+bouncycastle = "1.67"
+caliper = "1.0-beta-2"
+errorprone = "2.31.0"
+errorprone-plugin = "4.0.0"
+grgit = "5.2.2"
+jacoco = "0.8.12"
+jmh = "1.37"
+jmh-plugin = "0.7.2"
+junit = "4.13.2"
+mockito = "2.28.2"
+netty-handler = "4.1.24.Final"
+netty-tcnative = "2.0.26.Final"
+osdetector = "1.7.3"
+shadow = "7.1.2"
+task-tree = "3.0.0"
+
+[plugins]
+bnd = { id = "biz.aQute.bnd.builder", version.ref = "bnd" }
+errorprone = { id = "net.ltgt.errorprone", version.ref = "errorprone-plugin" }
+grgit = { id = "org.ajoberstar.grgit", version.ref = "grgit" }
+jmh = { id = "me.champeau.jmh", version.ref = "jmh-plugin" }
+osdetector = { id = "com.google.osdetector", version.ref = "osdetector" }
+shadow = { id = "com.github.johnrengelman.shadow", version.ref = "shadow" }
+task-tree = { id = "com.dorongold.task-tree", version.ref = "task-tree" }
+
+[libraries]
+# Android tooling
+android-tools = { module = "com.android.tools.build:gradle", version.ref = "android-tools" }
+caliper = { module = "com.google.caliper:caliper", version.ref = "caliper" }
+
+# Bouncycastle
+bouncycastle-apis = { module = "org.bouncycastle:bcpkix-jdk15on", version.ref = "bouncycastle" }
+bouncycastle-provider = { module = "org.bouncycastle:bcprov-jdk15on", version.ref = "bouncycastle" }
+
+# Testing
+errorprone = { module = "com.google.errorprone:error_prone_core", version.ref = "errorprone" }
+jacoco-agent = { module = "org.jacoco:org.jacoco.agent", version.ref = "jacoco" }
+jacoco-ant = { module = "org.jacoco:org.jacoco.ant", version.ref = "jacoco" }
+junit = { module = "junit:junit", version.ref = "junit" }
+mockito = { module = "org.mockito:mockito-core", version.ref = "mockito" }
+
+# JMH Benchmarking
+jmh-core = { module = "org.openjdk.jmh:jmh-core", version.ref = "jmh" }
+jmh-generator-annprocess = { module = "org.openjdk.jmh:jmh-generator-annprocess", version.ref = "jmh" }
+jmh-generator-bytecode = { module = "org.openjdk.jmh:jmh-generator-bytecode", version.ref = "jmh" }
+jmh-generator-reflection = { module = "org.openjdk.jmh:jmh-generator-reflection", version.ref = "jmh" }
+
+# Netty
+netty-handler = { module = "io.netty:netty-handler", version.ref = "netty-handler" }
+netty-tcnative = { module = "io.netty:netty-tcnative-boringssl-static", version.ref = "netty-tcnative" }
+
diff --git a/gradle/publishing.gradle b/gradle/publishing.gradle
index 6b3ef1fd..c9ece053 100644
--- a/gradle/publishing.gradle
+++ b/gradle/publishing.gradle
@@ -2,6 +2,7 @@ apply plugin: 'maven-publish'
 apply plugin: 'signing'
 
 def isSnapshot = project.version.contains('SNAPSHOT')
+def isReleaseVersion = !isSnapshot
 
 publishing {
     publications {
@@ -58,7 +59,7 @@ publishing {
 }
 
 signing {
-    required false
+    required { isReleaseVersion && gradle.taskGraph.hasTask("publish") }
     sign publishing.publications.maven
 }
 
@@ -70,3 +71,7 @@ signMavenPublication.doFirst {
         }
    }
 }
+
+tasks.withType(Sign) {
+    onlyIf { isReleaseVersion } 
+}
diff --git a/libcore-stub/build.gradle b/libcore-stub/build.gradle
index 528c0f54..ca2ce4e2 100644
--- a/libcore-stub/build.gradle
+++ b/libcore-stub/build.gradle
@@ -11,7 +11,7 @@ dependencies {
     // Only compile against this. Other modules will embed the generated code directly.
     compileOnly project(':conscrypt-constants')
 
-    testImplementation libraries.junit
+    testImplementation libs.junit
 }
 
 // Disable the javadoc task.
diff --git a/libcore-stub/src/main/java/libcore/junit/util/SwitchTargetSdkVersionRule.java b/libcore-stub/src/main/java/libcore/junit/util/SwitchTargetSdkVersionRule.java
new file mode 100644
index 00000000..76535ff8
--- /dev/null
+++ b/libcore-stub/src/main/java/libcore/junit/util/SwitchTargetSdkVersionRule.java
@@ -0,0 +1,33 @@
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
+package libcore.junit.util;
+
+import java.lang.annotation.ElementType;
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.lang.annotation.Target;
+
+public class SwitchTargetSdkVersionRule {
+
+    @Retention(RetentionPolicy.RUNTIME)
+    @Target(ElementType.METHOD)
+    public @interface TargetSdkVersion {
+        int value();
+    }
+
+}
+
diff --git a/libcore-stub/src/main/java/libcore/net/NetworkSecurityPolicy.java b/libcore-stub/src/main/java/libcore/net/NetworkSecurityPolicy.java
index e7ca0f19..2a666af3 100644
--- a/libcore-stub/src/main/java/libcore/net/NetworkSecurityPolicy.java
+++ b/libcore-stub/src/main/java/libcore/net/NetworkSecurityPolicy.java
@@ -27,7 +27,7 @@ package libcore.net;
  * permitted. See {@link #isCleartextTrafficPermitted()}.
  */
 public abstract class NetworkSecurityPolicy {
-    private static volatile NetworkSecurityPolicy instance = new DefaultNetworkSecurityPolicy();
+    private static volatile NetworkSecurityPolicy instance;
 
     public static NetworkSecurityPolicy getInstance() {
         return instance;
diff --git a/openjdk-uber/build.gradle b/openjdk-uber/build.gradle
index cc6851fd..80ffac40 100644
--- a/openjdk-uber/build.gradle
+++ b/openjdk-uber/build.gradle
@@ -10,7 +10,7 @@ ext {
 }
 
 if (buildUberJar) {
-    apply plugin: 'biz.aQute.bnd.builder'
+    apply plugin: libs.plugins.bnd.get().pluginId
 
     configurations {
         uberJar
diff --git a/openjdk/build.gradle b/openjdk/build.gradle
index 1dc0884a..cdb51a50 100644
--- a/openjdk/build.gradle
+++ b/openjdk/build.gradle
@@ -1,13 +1,12 @@
 plugins {
-    id 'com.github.johnrengelman.shadow' version '7.1.2'
+    alias libs.plugins.bnd
+    alias libs.plugins.shadow
 }
 
 import aQute.bnd.gradle.BundleTaskConvention
 import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
 import org.codehaus.groovy.runtime.InvokerHelper
 
-apply plugin: 'biz.aQute.bnd.builder'
-
 description = 'Conscrypt: OpenJdk'
 
 // Gradle mostly uses Java os.arch names for architectures which feeds into default
@@ -183,7 +182,7 @@ tasks.register("platformJar", Jar) {
 }
 
 tasks.register("testJar", ShadowJar) {
-    classifier = 'tests'
+    archiveClassifier = 'tests'
     configurations = [project.configurations.testRuntimeClasspath]
     from sourceSets.test.output
 }
@@ -199,7 +198,7 @@ if (isExecutableOnPath('cpplint')) {
         args = sourceFiles
 
         // Capture stderr from the process
-        errorOutput = new ByteArrayOutputStream();
+        errorOutput = new ByteArrayOutputStream()
 
         // Need to ignore exit value so that doLast will execute.
         ignoreExitValue = true
@@ -207,7 +206,7 @@ if (isExecutableOnPath('cpplint')) {
         doLast {
             // Create the report file.
             def reportDir = file("${buildDir}/cpplint")
-            reportDir.mkdirs();
+            reportDir.mkdirs()
             def reportFile = new File(reportDir, "report.txt")
             def reportStream = new FileOutputStream(reportFile)
 
@@ -218,13 +217,13 @@ if (isExecutableOnPath('cpplint')) {
                 }
             } catch (Exception e) {
                 // The process failed - get the error report from the stderr.
-                String report = errorOutput.toString();
+                String report = errorOutput.toString()
 
                 // Write the report to the console.
                 System.err.println(report)
 
                 // Also write the report file.
-                reportStream.write(report.bytes);
+                reportStream.write(report.bytes)
 
                 // Extension method cpplint.output() can be used to obtain the report
                 ext.output = {
@@ -232,9 +231,9 @@ if (isExecutableOnPath('cpplint')) {
                 }
 
                 // Rethrow the exception to terminate the build.
-                throw e;
+                throw e
             } finally {
-                reportStream.close();
+                reportStream.close()
             }
         }
     }
@@ -272,8 +271,8 @@ dependencies {
 
     testImplementation project(':conscrypt-constants'),
             project(path: ':conscrypt-testing', configuration: 'shadow'),
-            libraries.junit,
-            libraries.mockito
+            libs.junit,
+            libs.mockito
 
     testRuntimeOnly sourceSets["$preferredSourceSet"].output
 
@@ -296,7 +295,7 @@ def addNativeJar(NativeBuildInfo nativeBuild) {
         // Depend on the regular classes task
         dependsOn classes
         manifest = jar.manifest
-        classifier = nativeBuild.mavenClassifier()
+        archiveClassifier = nativeBuild.mavenClassifier()
 
         from sourceSet.output + sourceSets.main.output
 
@@ -341,13 +340,18 @@ check.dependsOn testInterop
 jacocoTestReport {
     additionalSourceDirs.from files("$rootDir/openjdk/src/test/java", "$rootDir/common/src/main/java")
     executionData tasks.withType(Test)
+    dependsOn test
 }
 
 javadoc {
-    dependsOn(configurations.publicApiDocs)
-    options.showFromPublic()
-    options.doclet = "org.conscrypt.doclet.FilterDoclet"
-    options.docletpath = configurations.publicApiDocs.files as List
+    dependsOn configurations.publicApiDocs
+    options {
+        showFromPublic()
+        encoding = 'UTF-8'
+        doclet = 'org.conscrypt.doclet.FilterDoclet'
+        links = ['https://docs.oracle.com/en/java/javase/21/docs/api/java.base/']
+        docletpath = configurations.publicApiDocs.files as List
+    }
     failOnError false
 
     doLast {
@@ -526,15 +530,14 @@ boolean isExecutableOnPath(executable) {
     FilenameFilter filter = new FilenameFilter() {
         @Override
         boolean accept(File dir, String name) {
-            return executable.equals(name);
+            return executable == name
         }
     }
     for(String folder : System.getenv('PATH').split("" + File.pathSeparatorChar)) {
         File[] files = file(folder).listFiles(filter)
         if (files != null && files.size() > 0) {
-            return true;
+            return true
         }
     }
-    return false;
-}
-
+    return false
+}
\ No newline at end of file
diff --git a/openjdk/src/main/java/org/conscrypt/HostProperties.java b/openjdk/src/main/java/org/conscrypt/HostProperties.java
index 82f56402..622c4852 100644
--- a/openjdk/src/main/java/org/conscrypt/HostProperties.java
+++ b/openjdk/src/main/java/org/conscrypt/HostProperties.java
@@ -74,7 +74,7 @@ class HostProperties {
          * Returns the value to use when building filenames for this OS.
          */
         public String getFileComponent() {
-            return name().toLowerCase();
+            return name().toLowerCase(Locale.ROOT);
         }
     }
 
@@ -104,7 +104,7 @@ class HostProperties {
          * Returns the value to use when building filenames for this architecture.
          */
         public String getFileComponent() {
-            return name().toLowerCase();
+            return name().toLowerCase(Locale.ROOT);
         }
     }
 
@@ -193,10 +193,10 @@ class HostProperties {
     }
 
     private static String normalize(String value) {
-        return value.toLowerCase(Locale.US).replaceAll("[^a-z0-9]+", "");
+        return value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "");
     }
 
-    /**
+    /*
      * Normalizes the os.name value into the value used by the Maven os plugin
      * (https://github.com/trustin/os-maven-plugin). This plugin is used to generate
      * platform-specific
@@ -241,7 +241,7 @@ class HostProperties {
         return OperatingSystem.UNKNOWN;
     }
 
-    /**
+    /*
      * Normalizes the os.arch value into the value used by the Maven os plugin
      * (https://github.com/trustin/os-maven-plugin). This plugin is used to generate
      * platform-specific
diff --git a/openjdk/src/main/java/org/conscrypt/Platform.java b/openjdk/src/main/java/org/conscrypt/Platform.java
index e50a8ce8..55f871c0 100644
--- a/openjdk/src/main/java/org/conscrypt/Platform.java
+++ b/openjdk/src/main/java/org/conscrypt/Platform.java
@@ -36,6 +36,11 @@ import static java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE;
 import static java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE;
 import static java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE;
 
+import org.conscrypt.ct.LogStore;
+import org.conscrypt.ct.Policy;
+import org.conscrypt.metrics.Source;
+import org.conscrypt.metrics.StatsLog;
+
 import java.io.File;
 import java.io.FileDescriptor;
 import java.io.IOException;
@@ -69,6 +74,7 @@ import java.util.EnumSet;
 import java.util.List;
 import java.util.Locale;
 import java.util.Set;
+
 import javax.crypto.spec.GCMParameterSpec;
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLParameters;
@@ -78,20 +84,23 @@ import javax.net.ssl.TrustManager;
 import javax.net.ssl.TrustManagerFactory;
 import javax.net.ssl.X509ExtendedTrustManager;
 import javax.net.ssl.X509TrustManager;
-import org.conscrypt.ct.LogStore;
-import org.conscrypt.ct.Policy;
+import org.conscrypt.NativeCrypto;
 
 /**
  * Platform-specific methods for OpenJDK.
  *
  * Uses reflection to implement Java 8 SSL features for backwards compatibility.
  */
-final class Platform {
+@Internal
+final public class Platform {
     private static final int JAVA_VERSION = javaVersion0();
     private static final Method GET_CURVE_NAME_METHOD;
+    static boolean DEPRECATED_TLS_V1 = true;
+    static boolean ENABLED_TLS_V1 = false;
+    private static boolean FILTERED_TLS_V1 = true;
 
     static {
-
+        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
         Method getCurveNameMethod = null;
         try {
             getCurveNameMethod = ECParameterSpec.class.getDeclaredMethod("getCurveName");
@@ -104,7 +113,12 @@ final class Platform {
 
     private Platform() {}
 
-    static void setup() {}
+    public static void setup(boolean deprecatedTlsV1, boolean enabledTlsV1) {
+        DEPRECATED_TLS_V1 = deprecatedTlsV1;
+        ENABLED_TLS_V1 = enabledTlsV1;
+        FILTERED_TLS_V1 = !enabledTlsV1;
+        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
+    }
 
 
     /**
@@ -119,7 +133,7 @@ final class Platform {
         prefix = new File(prefix).getName();
         IOException suppressed = null;
         for (int i = 0; i < 10000; i++) {
-            String tempName = String.format(Locale.US, "%s%d%04d%s", prefix, time, i, suffix);
+            String tempName = String.format(Locale.ROOT, "%s%d%04d%s", prefix, time, i, suffix);
             File tempFile = new File(directory, tempName);
             if (!tempName.equals(tempFile.getName())) {
                 // The given prefix or suffix contains path separators.
@@ -588,8 +602,22 @@ final class Platform {
             return originalHostName;
         } catch (InvocationTargetException e) {
             throw new RuntimeException("Failed to get originalHostName", e);
-        } catch (ClassNotFoundException | IllegalAccessException | NoSuchMethodException ignore) {
+        } catch (ClassNotFoundException | IllegalAccessException | NoSuchMethodException ignored) {
             // passthrough and return addr.getHostAddress()
+        } catch (Exception maybeIgnored) {
+            if (!maybeIgnored.getClass().getSimpleName().equals("InaccessibleObjectException")) {
+                throw new RuntimeException("Failed to get originalHostName", maybeIgnored);
+            }
+            // Java versions which prevent reflection to get the original hostname.
+            // Ugly workaround is parse it from toString(), which uses holder.hostname rather
+            // than holder.originalHostName.  But in Java versions up to 21 at least and in the way
+            // used by Conscrypt, hostname always equals originalHostname.
+            String representation = addr.toString();
+            int slash = representation.indexOf('/');
+            if (slash != -1) {
+                return representation.substring(0, slash);
+            }
+            // Give up and return the IP
         }
 
         return addr.getHostAddress();
@@ -627,7 +655,7 @@ final class Platform {
         }
 
         String property = Security.getProperty("conscrypt.ct.enable");
-        if (property == null || !Boolean.valueOf(property.toLowerCase())) {
+        if (property == null || !Boolean.parseBoolean(property.toLowerCase(Locale.ROOT))) {
             return false;
         }
 
@@ -641,15 +669,14 @@ final class Platform {
         for (String part : parts) {
             property = Security.getProperty(propertyName + ".*");
             if (property != null) {
-                enable = Boolean.valueOf(property.toLowerCase());
+                enable = Boolean.parseBoolean(property.toLowerCase(Locale.ROOT));
             }
-
             propertyName.append(".").append(part);
         }
 
         property = Security.getProperty(propertyName.toString());
         if (property != null) {
-            enable = Boolean.valueOf(property.toLowerCase());
+            enable = Boolean.parseBoolean(property.toLowerCase(Locale.ROOT));
         }
         return enable;
     }
@@ -802,23 +829,33 @@ final class Platform {
         return 0;
     }
 
+    public static StatsLog getStatsLog() {
+        return null;
+    }
+
     @SuppressWarnings("unused")
-    static void countTlsHandshake(
-            boolean success, String protocol, String cipherSuite, long duration) {}
+    public static Source getStatsSource() {
+        return null;
+    }
+
+    @SuppressWarnings("unused")
+    public static int[] getUids() {
+        return null;
+    }
 
     public static boolean isJavaxCertificateSupported() {
         return JAVA_VERSION < 15;
     }
 
     public static boolean isTlsV1Deprecated() {
-        return true;
+        return DEPRECATED_TLS_V1;
     }
 
     public static boolean isTlsV1Filtered() {
-        return false;
+        return FILTERED_TLS_V1;
     }
 
     public static boolean isTlsV1Supported() {
-        return false;
+        return ENABLED_TLS_V1;
     }
 }
diff --git a/openjdk/src/test/java/org/conscrypt/AbstractSessionContextTest.java b/openjdk/src/test/java/org/conscrypt/AbstractSessionContextTest.java
index 1401f951..deb19ead 100644
--- a/openjdk/src/test/java/org/conscrypt/AbstractSessionContextTest.java
+++ b/openjdk/src/test/java/org/conscrypt/AbstractSessionContextTest.java
@@ -120,9 +120,6 @@ public abstract class AbstractSessionContextTest<T extends AbstractSessionContex
 
     @Test
     public void testSerializeSession() throws Exception {
-        Certificate mockCert = mock(Certificate.class);
-        when(mockCert.getEncoded()).thenReturn(new byte[] {0x05, 0x06, 0x07, 0x10});
-
         byte[] encodedBytes = new byte[] {0x01, 0x02, 0x03};
         NativeSslSession session = new MockSessionBuilder()
                 .id(new byte[] {0x11, 0x09, 0x03, 0x20})
diff --git a/openjdk/src/test/java/org/conscrypt/AddressUtilsTest.java b/openjdk/src/test/java/org/conscrypt/AddressUtilsTest.java
index b210c0ae..59aba152 100644
--- a/openjdk/src/test/java/org/conscrypt/AddressUtilsTest.java
+++ b/openjdk/src/test/java/org/conscrypt/AddressUtilsTest.java
@@ -16,40 +16,54 @@
 
 package org.conscrypt;
 
-import junit.framework.TestCase;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 
 /**
  * Test for AddressUtils
  */
-public class AddressUtilsTest extends TestCase {
+@RunWith(JUnit4.class)
+public class AddressUtilsTest {
+    @Test
     public void test_isValidSniHostname_Success() throws Exception {
         assertTrue(AddressUtils.isValidSniHostname("www.google.com"));
     }
 
+    @Test
     public void test_isValidSniHostname_NotFQDN_Failure() throws Exception {
         assertFalse(AddressUtils.isValidSniHostname("www"));
     }
 
+    @Test
     public void test_isValidSniHostname_Localhost_Success() throws Exception {
         assertTrue(AddressUtils.isValidSniHostname("LOCALhost"));
     }
 
+    @Test
     public void test_isValidSniHostname_IPv4_Failure() throws Exception {
         assertFalse(AddressUtils.isValidSniHostname("192.168.0.1"));
     }
 
+    @Test
     public void test_isValidSniHostname_IPv6_Failure() throws Exception {
         assertFalse(AddressUtils.isValidSniHostname("2001:db8::1"));
     }
 
+    @Test
     public void test_isValidSniHostname_TrailingDot() throws Exception {
         assertFalse(AddressUtils.isValidSniHostname("www.google.com."));
     }
 
+    @Test
     public void test_isValidSniHostname_NullByte() throws Exception {
         assertFalse(AddressUtils.isValidSniHostname("www\0.google.com"));
     }
 
+    @Test
     public void test_isLiteralIpAddress_IPv4_Success() throws Exception {
         assertTrue(AddressUtils.isLiteralIpAddress("127.0.0.1"));
         assertTrue(AddressUtils.isLiteralIpAddress("255.255.255.255"));
@@ -58,6 +72,7 @@ public class AddressUtilsTest extends TestCase {
         assertTrue(AddressUtils.isLiteralIpAddress("254.249.190.094"));
     }
 
+    @Test
     public void test_isLiteralIpAddress_IPv4_ExtraCharacters_Failure() throws Exception {
         assertFalse(AddressUtils.isLiteralIpAddress("127.0.0.1a"));
         assertFalse(AddressUtils.isLiteralIpAddress(" 255.255.255.255"));
@@ -68,12 +83,14 @@ public class AddressUtilsTest extends TestCase {
         assertFalse(AddressUtils.isLiteralIpAddress("192.168.2.1%eth0"));
     }
 
+    @Test
     public void test_isLiteralIpAddress_IPv4_NumbersTooLarge_Failure() throws Exception {
         assertFalse(AddressUtils.isLiteralIpAddress("256.255.255.255"));
         assertFalse(AddressUtils.isLiteralIpAddress("255.255.255.256"));
         assertFalse(AddressUtils.isLiteralIpAddress("192.168.1.260"));
     }
 
+    @Test
     public void test_isLiteralIpAddress_IPv6_Success() throws Exception {
         assertTrue(AddressUtils.isLiteralIpAddress("::1"));
         assertTrue(AddressUtils.isLiteralIpAddress("2001:Db8::1"));
@@ -85,6 +102,7 @@ public class AddressUtilsTest extends TestCase {
         assertTrue(AddressUtils.isLiteralIpAddress("2001:cdba::3257:9652%int2.3!"));
     }
 
+    @Test
     public void test_isLiteralIpAddress_IPv6_Failure() throws Exception {
         assertFalse(AddressUtils.isLiteralIpAddress(":::1"));
         assertFalse(AddressUtils.isLiteralIpAddress("::11111"));
diff --git a/openjdk/src/test/java/org/conscrypt/ConscryptSocketTest.java b/openjdk/src/test/java/org/conscrypt/ConscryptSocketTest.java
index 4ffc56f6..8594cd47 100644
--- a/openjdk/src/test/java/org/conscrypt/ConscryptSocketTest.java
+++ b/openjdk/src/test/java/org/conscrypt/ConscryptSocketTest.java
@@ -18,12 +18,10 @@ package org.conscrypt;
 
 import static org.conscrypt.TestUtils.openTestFile;
 import static org.conscrypt.TestUtils.readTestFile;
-import static org.hamcrest.CoreMatchers.instanceOf;
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNull;
-import static org.junit.Assert.assertThat;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 import static org.junit.Assume.assumeFalse;
@@ -220,14 +218,17 @@ public class ConscryptSocketTest {
 
     @Parameters(name = "{0} wrapping {1} connecting to {2}")
     public static Object[][] data() {
-        return new Object[][] {
-            {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.NONE, ServerSocketType.PLAIN},
-            {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.NONE, ServerSocketType.CHANNEL},
-            {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.PLAIN, ServerSocketType.PLAIN},
-            {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.PLAIN, ServerSocketType.CHANNEL},
-            {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.CHANNEL, ServerSocketType.PLAIN},
-            {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.CHANNEL, ServerSocketType.CHANNEL},
-            // Not supported: {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.SSL},
+        Object[][] fd_cases = new Object[][] {
+                {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.NONE, ServerSocketType.PLAIN},
+                {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.NONE, ServerSocketType.CHANNEL},
+                {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.PLAIN, ServerSocketType.PLAIN},
+                {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.PLAIN, ServerSocketType.CHANNEL},
+                {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.CHANNEL, ServerSocketType.PLAIN},
+                {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.CHANNEL, ServerSocketType.CHANNEL}
+                // Not supported: {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.SSL},
+        };
+
+        Object[][] engine_cases = new Object[][] {
             {SocketType.ENGINE, UnderlyingSocketType.NONE, ServerSocketType.PLAIN},
             {SocketType.ENGINE, UnderlyingSocketType.NONE, ServerSocketType.CHANNEL},
             {SocketType.ENGINE, UnderlyingSocketType.PLAIN, ServerSocketType.PLAIN},
@@ -236,6 +237,12 @@ public class ConscryptSocketTest {
             {SocketType.ENGINE, UnderlyingSocketType.CHANNEL, ServerSocketType.CHANNEL},
             {SocketType.ENGINE, UnderlyingSocketType.SSL, ServerSocketType.PLAIN},
             {SocketType.ENGINE, UnderlyingSocketType.SSL, ServerSocketType.CHANNEL}};
+
+        if (TestUtils.isJavaVersion(17)) {
+            // FD Socket not feasible on Java 17+
+            return engine_cases;
+        }
+        return ArrayUtils.concat(fd_cases, engine_cases);
     }
 
     @Parameter
@@ -445,16 +452,13 @@ public class ConscryptSocketTest {
         }
 
         Future<AbstractConscryptSocket> handshake(final ServerSocket listener, final Hooks hooks) {
-            return executor.submit(new Callable<AbstractConscryptSocket>() {
-                @Override
-                public AbstractConscryptSocket call() throws Exception {
-                    AbstractConscryptSocket socket = hooks.createSocket(listener);
-                    socket.addHandshakeCompletedListener(hooks);
+            return executor.submit((Callable<AbstractConscryptSocket>) () -> {
+                AbstractConscryptSocket socket = hooks.createSocket(listener);
+                socket.addHandshakeCompletedListener(hooks);
 
-                    socket.startHandshake();
+                socket.startHandshake();
 
-                    return socket;
-                }
+                return socket;
             });
         }
     }
@@ -583,8 +587,8 @@ public class ConscryptSocketTest {
         TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);
 
         connection.doHandshake();
-        assertThat(connection.clientException, instanceOf(SSLHandshakeException.class));
-        assertThat(connection.clientException.getCause(), instanceOf(CertificateException.class));
+        assertTrue(connection.clientException instanceof SSLHandshakeException);
+        assertTrue(connection.clientException.getCause()  instanceof CertificateException);
     }
 
     @Ignore("TODO(nathanmittler): Fix or remove")
@@ -595,16 +599,15 @@ public class ConscryptSocketTest {
         connection.serverHooks.sctTLSExtension = readTestFile("ct-signed-timestamp-list-invalid");
 
         connection.doHandshake();
-        assertThat(connection.clientException, instanceOf(SSLHandshakeException.class));
-        assertThat(connection.clientException.getCause(), instanceOf(CertificateException.class));
+        assertTrue(connection.clientException instanceof SSLHandshakeException);
+        assertTrue(connection.clientException.getCause()  instanceof CertificateException);
     }
 
     @Test
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("deprecation") // setAlpnProtocols is deprecated but still needs testing.
     public void setAlpnProtocolWithNullShouldSucceed() throws Exception {
-        ServerSocket listening = serverSocketType.newServerSocket();
         OpenSSLSocketImpl clientSocket = null;
-        try {
+        try (ServerSocket listening = serverSocketType.newServerSocket()) {
             Socket underlying = new Socket(listening.getInetAddress(), listening.getLocalPort());
             clientSocket = (OpenSSLSocketImpl) socketType.newClientSocket(
                     new ClientHooks().createContext(), listening, underlying);
@@ -616,15 +619,15 @@ public class ConscryptSocketTest {
             if (clientSocket != null) {
                 clientSocket.close();
             }
-            listening.close();
         }
     }
 
     // http://b/27250522
     @Test
     public void test_setSoTimeout_doesNotCreateSocketImpl() throws Exception {
-        ServerSocket listening = serverSocketType.newServerSocket();
-        try {
+        // TODO(prb): Figure out how to test this on Java 17+
+        assumeFalse(TestUtils.isJavaVersion(17));
+        try (ServerSocket listening = serverSocketType.newServerSocket()) {
             Socket underlying = new Socket(listening.getInetAddress(), listening.getLocalPort());
             Socket socket = socketType.newClientSocket(
                     new ClientHooks().createContext(), listening, underlying);
@@ -635,8 +638,6 @@ public class ConscryptSocketTest {
             Field f = Socket.class.getDeclaredField("created");
             f.setAccessible(true);
             assertFalse(f.getBoolean(socket));
-        } finally {
-            listening.close();
         }
     }
 
@@ -750,12 +751,8 @@ public class ConscryptSocketTest {
             throws Exception {
         final byte[] received = new byte[data.length];
 
-        Future<Integer> readFuture = executor.submit(new Callable<Integer>() {
-            @Override
-            public Integer call() throws Exception {
-                return destination.getInputStream().read(received);
-            }
-        });
+        Future<Integer> readFuture = executor.submit(
+                () -> destination.getInputStream().read(received));
 
         source.getOutputStream().write(data);
         assertEquals(data.length, (int) readFuture.get());
diff --git a/openjdk/src/test/java/org/conscrypt/DuckTypedPSKKeyManagerTest.java b/openjdk/src/test/java/org/conscrypt/DuckTypedPSKKeyManagerTest.java
index 5c27f331..7fc6a36a 100644
--- a/openjdk/src/test/java/org/conscrypt/DuckTypedPSKKeyManagerTest.java
+++ b/openjdk/src/test/java/org/conscrypt/DuckTypedPSKKeyManagerTest.java
@@ -20,6 +20,7 @@ import java.lang.reflect.InvocationHandler;
 import java.lang.reflect.Method;
 import java.lang.reflect.Proxy;
 import java.net.Socket;
+import java.nio.charset.StandardCharsets;
 import java.security.Key;
 import java.util.Arrays;
 import javax.crypto.SecretKey;
@@ -139,7 +140,7 @@ public class DuckTypedPSKKeyManagerTest extends TestCase {
         assertSame(identityHint, mockInvocationHandler.lastInvokedMethodArgs[0]);
         assertSame(mSSLEngine, mockInvocationHandler.lastInvokedMethodArgs[1]);
 
-        SecretKey key = new SecretKeySpec("arbitrary".getBytes("UTF-8"), "RAW");
+        SecretKey key = new SecretKeySpec("arbitrary".getBytes(StandardCharsets.UTF_8), "RAW");
         mockInvocationHandler.returnValue = key;
         assertSame(key, pskKeyManager.getKey(identityHint, identity, mSSLSocket));
         assertEquals("getKey", mockInvocationHandler.lastInvokedMethod.getName());
diff --git a/openjdk/src/test/java/org/conscrypt/NativeCryptoTest.java b/openjdk/src/test/java/org/conscrypt/NativeCryptoTest.java
index c4db6e66..af2e9ca7 100644
--- a/openjdk/src/test/java/org/conscrypt/NativeCryptoTest.java
+++ b/openjdk/src/test/java/org/conscrypt/NativeCryptoTest.java
@@ -31,8 +31,8 @@ import static org.conscrypt.TestUtils.openTestFile;
 import static org.conscrypt.TestUtils.readTestFile;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertNotNull;
-import static org.junit.Assert.assertNotSame;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
@@ -44,13 +44,13 @@ import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.FileDescriptor;
 import java.io.IOException;
-import java.io.UnsupportedEncodingException;
 import java.lang.reflect.Method;
 import java.math.BigInteger;
 import java.net.ServerSocket;
 import java.net.Socket;
 import java.net.SocketException;
 import java.net.SocketTimeoutException;
+import java.nio.charset.StandardCharsets;
 import java.security.KeyPair;
 import java.security.KeyPairGenerator;
 import java.security.KeyStore;
@@ -118,10 +118,12 @@ public class NativeCryptoTest {
     @BeforeClass
     @SuppressWarnings("JdkObsolete") // Public API KeyStore.aliases() uses Enumeration
     public static void initStatics() throws Exception {
-        Class<?> c_Platform = TestUtils.conscryptClass("Platform");
-        m_Platform_getFileDescriptor =
-                c_Platform.getDeclaredMethod("getFileDescriptor", Socket.class);
-        m_Platform_getFileDescriptor.setAccessible(true);
+        if (!TestUtils.isJavaVersion(17)) {
+            Class<?> c_Platform = TestUtils.conscryptClass("Platform");
+            m_Platform_getFileDescriptor =
+                    c_Platform.getDeclaredMethod("getFileDescriptor", Socket.class);
+            m_Platform_getFileDescriptor.setAccessible(true);
+        }
 
         PrivateKeyEntry serverPrivateKeyEntry = TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
         SERVER_PRIVATE_KEY = OpenSSLKey.fromPrivateKey(serverPrivateKeyEntry.getPrivateKey());
@@ -236,7 +238,7 @@ public class NativeCryptoTest {
     public void EVP_PKEY_cmp_withNullShouldThrow() throws Exception {
         RSAPrivateCrtKey privKey1 = TEST_RSA_KEY;
         NativeRef.EVP_PKEY pkey1 = getRsaPkey(privKey1);
-        assertNotSame(NULL, pkey1);
+        assertFalse(pkey1.isNull());
         NativeCrypto.EVP_PKEY_cmp(pkey1, null);
     }
 
@@ -245,14 +247,14 @@ public class NativeCryptoTest {
         RSAPrivateCrtKey privKey1 = TEST_RSA_KEY;
 
         NativeRef.EVP_PKEY pkey1 = getRsaPkey(privKey1);
-        assertNotSame(NULL, pkey1);
+        assertFalse(pkey1.isNull());
 
         NativeRef.EVP_PKEY pkey1_copy = getRsaPkey(privKey1);
-        assertNotSame(NULL, pkey1_copy);
+        assertFalse(pkey1_copy.isNull());
 
         // Generate a different key.
         NativeRef.EVP_PKEY pkey2 = getRsaPkey(generateRsaKey());
-        assertNotSame(NULL, pkey2);
+        assertFalse(pkey2.isNull());
 
         assertEquals("Same keys should be the equal", 1, NativeCrypto.EVP_PKEY_cmp(pkey1, pkey1));
 
@@ -587,8 +589,8 @@ public class NativeCryptoTest {
         long c = NativeCrypto.SSL_CTX_new();
         long s = NativeCrypto.SSL_new(c, null);
 
-        List<String> ciphers = new ArrayList<String>(NativeCrypto.SUPPORTED_TLS_1_2_CIPHER_SUITES_SET);
-        NativeCrypto.SSL_set_cipher_lists(s, null, ciphers.toArray(new String[ciphers.size()]));
+        List<String> ciphers = new ArrayList<>(NativeCrypto.SUPPORTED_TLS_1_2_CIPHER_SUITES_SET);
+        NativeCrypto.SSL_set_cipher_lists(s, null, ciphers.toArray(new String[0]));
 
         NativeCrypto.SSL_free(s, null);
         NativeCrypto.SSL_CTX_free(c, null);
@@ -630,7 +632,7 @@ public class NativeCryptoTest {
         public long beforeHandshake(long context) throws SSLException {
             long s = NativeCrypto.SSL_new(context, null);
             // Limit cipher suites to a known set so authMethod is known.
-            List<String> cipherSuites = new ArrayList<String>();
+            List<String> cipherSuites = new ArrayList<>();
             if (enabledCipherSuites == null) {
                 cipherSuites.add("ECDHE-RSA-AES128-SHA");
                 if (pskEnabled) {
@@ -643,7 +645,7 @@ public class NativeCryptoTest {
             }
             // Protocol list is included for determining whether to send TLS_FALLBACK_SCSV
             NativeCrypto.setEnabledCipherSuites(
-                    s, null, cipherSuites.toArray(new String[cipherSuites.size()]), new String[] {"TLSv1.2"});
+                    s, null, cipherSuites.toArray(new String[0]), new String[] {"TLSv1.2"});
 
             if (channelIdPrivateKey != null) {
                 NativeCrypto.SSL_set1_tls_channel_id(s, null, channelIdPrivateKey.getNativeRef());
@@ -852,11 +854,7 @@ public class NativeCryptoTest {
                 if (pskIdentity != null) {
                     // Create a NULL-terminated modified UTF-8 representation of pskIdentity.
                     byte[] b;
-                    try {
-                        b = pskIdentity.getBytes("UTF-8");
-                    } catch (UnsupportedEncodingException e) {
-                        throw new RuntimeException("UTF-8 encoding not supported", e);
-                    }
+                    b = pskIdentity.getBytes(StandardCharsets.UTF_8);
                     callbacks.clientPSKKeyRequestedResultIdentity = Arrays.copyOf(b, b.length + 1);
                 }
                 callbacks.clientPSKKeyRequestedResultKey = pskKey;
@@ -940,12 +938,13 @@ public class NativeCryptoTest {
     public static Future<TestSSLHandshakeCallbacks> handshake(final ServerSocket listener,
             final int timeout, final boolean client, final Hooks hooks, final byte[] alpnProtocols,
             final ApplicationProtocolSelectorAdapter alpnSelector) {
+        // TODO(prb) rewrite for engine socket. FD socket calls infeasible to test on Java 17+
+        assumeFalse(TestUtils.isJavaVersion(17));
         ExecutorService executor = Executors.newSingleThreadExecutor();
         Future<TestSSLHandshakeCallbacks> future =
                 executor.submit(new Callable<TestSSLHandshakeCallbacks>() {
                     @Override
                     public TestSSLHandshakeCallbacks call() throws Exception {
-                        @SuppressWarnings("resource")
                         // Socket needs to remain open after the handshake
                         Socket socket = (client ? new Socket(listener.getInetAddress(),
                                                           listener.getLocalPort())
@@ -1394,7 +1393,7 @@ public class NativeCryptoTest {
         ServerHooks sHooks = new ServerHooks();
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
-        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
+        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
         sHooks.pskKey = cHooks.pskKey;
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
@@ -1431,7 +1430,7 @@ public class NativeCryptoTest {
         ServerHooks sHooks = new ServerHooks();
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
-        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
+        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
         sHooks.pskKey = cHooks.pskKey;
         sHooks.pskIdentityHint = "Some non-ASCII characters: \u00c4\u0332";
         cHooks.pskIdentity = "More non-ASCII characters: \u00f5\u044b";
@@ -1462,7 +1461,7 @@ public class NativeCryptoTest {
     }
 
     @Test
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated but still needs testing.
     public void test_SSL_do_handshake_with_psk_with_identity_and_hint_of_max_length()
             throws Exception {
         // normal TLS-PSK client and server case where the server provides the client with a PSK
@@ -1472,7 +1471,7 @@ public class NativeCryptoTest {
         ServerHooks sHooks = new ServerHooks();
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
-        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
+        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
         sHooks.pskKey = cHooks.pskKey;
         sHooks.pskIdentityHint = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
                 + "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx";
@@ -1509,8 +1508,8 @@ public class NativeCryptoTest {
         ServerHooks sHooks = new ServerHooks();
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
-        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
-        sHooks.pskKey = "1, 2, 3, 3, Testing...".getBytes("UTF-8");
+        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
+        sHooks.pskKey = "1, 2, 3, 3, Testing...".getBytes(StandardCharsets.UTF_8);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -1531,7 +1530,7 @@ public class NativeCryptoTest {
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
         cHooks.pskKey = null;
-        sHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
+        sHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -1551,7 +1550,7 @@ public class NativeCryptoTest {
         ServerHooks sHooks = new ServerHooks();
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
-        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
+        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
         sHooks.pskKey = null;
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
@@ -1566,7 +1565,7 @@ public class NativeCryptoTest {
     }
 
     @Test
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated but still needs testing.
     public void test_SSL_do_handshake_with_psk_key_too_long() throws Exception {
         final ServerSocket listener = newServerSocket();
         ClientHooks cHooks = new ClientHooks() {
@@ -1579,7 +1578,7 @@ public class NativeCryptoTest {
         ServerHooks sHooks = new ServerHooks();
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
-        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
+        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
         sHooks.pskKey = cHooks.pskKey;
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
@@ -1681,7 +1680,7 @@ public class NativeCryptoTest {
     }
 
     @Test
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated but still needs testing.
     public void test_SSL_use_psk_identity_hint() throws Exception {
         long c = NativeCrypto.SSL_CTX_new();
         long s = NativeCrypto.SSL_new(c, null);
@@ -1729,7 +1728,7 @@ public class NativeCryptoTest {
             {
                 Hooks cHooks = new Hooks() {
                     @Override
-                    public long getContext() throws SSLException {
+                    public long getContext() {
                         return clientContext;
                     }
                     @Override
@@ -1742,7 +1741,7 @@ public class NativeCryptoTest {
                 Hooks sHooks = new ServerHooks(
                         SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                     @Override
-                    public long getContext() throws SSLException {
+                    public long getContext() {
                         return serverContext;
                     }
                     @Override
@@ -1763,7 +1762,7 @@ public class NativeCryptoTest {
             {
                 Hooks cHooks = new Hooks() {
                     @Override
-                    public long getContext() throws SSLException {
+                    public long getContext() {
                         return clientContext;
                     }
                     @Override
@@ -1782,7 +1781,7 @@ public class NativeCryptoTest {
                 Hooks sHooks = new ServerHooks(
                         SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                     @Override
-                    public long getContext() throws SSLException {
+                    public long getContext() {
                         return serverContext;
                     }
                     @Override
@@ -1967,7 +1966,7 @@ public class NativeCryptoTest {
             public void afterHandshake(long session, long ssl, long context, Socket socket,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                 byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
-                assertEquals("spdy/2", new String(negotiated, "UTF-8"));
+                assertEquals("spdy/2", new String(negotiated, StandardCharsets.UTF_8));
                 super.afterHandshake(session, ssl, context, socket, fd, callback);
             }
         };
@@ -1976,7 +1975,7 @@ public class NativeCryptoTest {
             public void afterHandshake(long session, long ssl, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                 byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
-                assertEquals("spdy/2", new String(negotiated, "UTF-8"));
+                assertEquals("spdy/2", new String(negotiated, StandardCharsets.UTF_8));
                 super.afterHandshake(session, ssl, c, sock, fd, callback);
             }
         };
@@ -2035,7 +2034,7 @@ public class NativeCryptoTest {
             public void afterHandshake(long session, long ssl, long context, Socket socket,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                 byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
-                assertEquals("spdy/2", new String(negotiated, "UTF-8"));
+                assertEquals("spdy/2", new String(negotiated, StandardCharsets.UTF_8));
                 super.afterHandshake(session, ssl, context, socket, fd, callback);
             }
         };
@@ -2044,7 +2043,7 @@ public class NativeCryptoTest {
             public void afterHandshake(long session, long ssl, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                 byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
-                assertEquals("spdy/2", new String(negotiated, "UTF-8"));
+                assertEquals("spdy/2", new String(negotiated, StandardCharsets.UTF_8));
                 super.afterHandshake(session, ssl, c, sock, fd, callback);
             }
         };
@@ -2604,7 +2603,7 @@ public class NativeCryptoTest {
                 assertTrue(session2 != NULL);
 
                 // Make sure d2i_SSL_SESSION retores SSL_SESSION_cipher value http://b/7091840
-                assertTrue(NativeCrypto.SSL_SESSION_cipher(session2) != null);
+                assertNotNull(NativeCrypto.SSL_SESSION_cipher(session2));
                 assertEquals(NativeCrypto.SSL_SESSION_cipher(session),
                         NativeCrypto.SSL_SESSION_cipher(session2));
 
@@ -2726,7 +2725,7 @@ public class NativeCryptoTest {
     public void test_get_RSA_private_params() throws Exception {
         // Test getting params for the wrong kind of key.
         final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
-        assertFalse(groupCtx == NULL);
+        assertNotEquals(NULL, groupCtx);
         NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupCtx);
         NativeRef.EVP_PKEY ctx = new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(group));
         NativeCrypto.get_RSA_private_params(ctx);
@@ -2741,7 +2740,7 @@ public class NativeCryptoTest {
     public void test_get_RSA_public_params() throws Exception {
         // Test getting params for the wrong kind of key.
         final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
-        assertFalse(groupCtx == NULL);
+        assertNotEquals(NULL, groupCtx);
         NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupCtx);
         NativeRef.EVP_PKEY ctx = new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(group));
         NativeCrypto.get_RSA_public_params(ctx);
@@ -2797,7 +2796,7 @@ public class NativeCryptoTest {
     private void check_EC_GROUP(String name, String pStr, String aStr, String bStr, String xStr,
             String yStr, String nStr, long hLong) throws Exception {
         long groupRef = NativeCrypto.EC_GROUP_new_by_curve_name(name);
-        assertFalse(groupRef == NULL);
+        assertNotEquals(NULL, groupRef);
         NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupRef);
 
         // prime
@@ -2869,7 +2868,7 @@ public class NativeCryptoTest {
     @Test
     public void test_ECDH_compute_key_null_key_Failure() throws Exception {
         final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
-        assertFalse(groupCtx == NULL);
+        assertNotEquals(NULL, groupCtx);
         NativeRef.EC_GROUP groupRef = new NativeRef.EC_GROUP(groupCtx);
         NativeRef.EVP_PKEY pkey1Ref =
                 new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(groupRef));
@@ -2946,7 +2945,7 @@ public class NativeCryptoTest {
         assertTrue(key1.getPublicKey() instanceof RSAPublicKey);
 
         final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
-        assertFalse(groupCtx == NULL);
+        assertNotEquals(NULL, groupCtx);
         NativeRef.EC_GROUP group1 = new NativeRef.EC_GROUP(groupCtx);
         key1 = new OpenSSLKey(NativeCrypto.EC_KEY_generate_key(group1));
         assertTrue(key1.getPublicKey() instanceof ECPublicKey);
@@ -2954,10 +2953,9 @@ public class NativeCryptoTest {
 
     @Test
     public void test_create_BIO_InputStream() throws Exception {
-        byte[] actual = "Test".getBytes("UTF-8");
+        byte[] actual = "Test".getBytes(StandardCharsets.UTF_8);
         ByteArrayInputStream is = new ByteArrayInputStream(actual);
 
-        @SuppressWarnings("resource")
         OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
         try {
             byte[] buffer = new byte[1024];
@@ -2972,7 +2970,7 @@ public class NativeCryptoTest {
 
     @Test
     public void test_create_BIO_OutputStream() throws Exception {
-        byte[] actual = "Test".getBytes("UTF-8");
+        byte[] actual = "Test".getBytes(StandardCharsets.UTF_8);
         ByteArrayOutputStream os = new ByteArrayOutputStream();
 
         long ctx = NativeCrypto.create_BIO_OutputStream(os);
diff --git a/openjdk/src/test/java/org/conscrypt/NativeRefTest.java b/openjdk/src/test/java/org/conscrypt/NativeRefTest.java
index e13297b3..7b71dcdb 100644
--- a/openjdk/src/test/java/org/conscrypt/NativeRefTest.java
+++ b/openjdk/src/test/java/org/conscrypt/NativeRefTest.java
@@ -16,9 +16,15 @@
 
 package org.conscrypt;
 
-import junit.framework.TestCase;
+import static org.junit.Assert.fail;
 
-public class NativeRefTest extends TestCase {
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public class NativeRefTest {
+    @Test
     public void test_zeroContextThrowsNullPointException() {
         try {
             new NativeRef(0) {
diff --git a/openjdk/src/test/java/org/conscrypt/OpenSSLKeyTest.java b/openjdk/src/test/java/org/conscrypt/OpenSSLKeyTest.java
index dc7044f0..0935c499 100644
--- a/openjdk/src/test/java/org/conscrypt/OpenSSLKeyTest.java
+++ b/openjdk/src/test/java/org/conscrypt/OpenSSLKeyTest.java
@@ -16,11 +16,18 @@
 
 package org.conscrypt;
 
+import static org.junit.Assert.assertEquals;
+
 import java.io.ByteArrayInputStream;
 import java.math.BigInteger;
-import junit.framework.TestCase;
+import java.nio.charset.StandardCharsets;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 
-public class OpenSSLKeyTest extends TestCase {
+@RunWith(JUnit4.class)
+public class OpenSSLKeyTest {
     static final String RSA_PUBLIC_KEY =
         "-----BEGIN PUBLIC KEY-----\n" +
         "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3G7PGpfZx68wTY9eLb4b\n" +
@@ -82,16 +89,18 @@ public class OpenSSLKeyTest extends TestCase {
         "13e6825df950a3bd4509f9d3b12da304fe5b00c443ff33326b8bfb3fe111fd4b" +
         "8872822c7f2832dafa0fe10d9aba22310849e978e51c8aa9da7bc1c07511d883", 16);
 
+    @Test
     public void test_fromPublicKeyPemInputStream() throws Exception {
-        ByteArrayInputStream is = new ByteArrayInputStream(RSA_PUBLIC_KEY.getBytes("UTF-8"));
+        ByteArrayInputStream is = new ByteArrayInputStream(RSA_PUBLIC_KEY.getBytes(StandardCharsets.UTF_8));
         OpenSSLKey key = OpenSSLKey.fromPublicKeyPemInputStream(is);
         OpenSSLRSAPublicKey publicKey = (OpenSSLRSAPublicKey)key.getPublicKey();
         assertEquals(RSA_MODULUS, publicKey.getModulus());
         assertEquals(RSA_PUBLIC_EXPONENT, publicKey.getPublicExponent());
     }
 
+    @Test
     public void test_fromPrivateKeyPemInputStream() throws Exception {
-        ByteArrayInputStream is = new ByteArrayInputStream(RSA_PRIVATE_KEY.getBytes("UTF-8"));
+        ByteArrayInputStream is = new ByteArrayInputStream(RSA_PRIVATE_KEY.getBytes(StandardCharsets.UTF_8));
         OpenSSLKey key = OpenSSLKey.fromPrivateKeyPemInputStream(is);
         OpenSSLRSAPrivateKey privateKey = (OpenSSLRSAPrivateKey)key.getPrivateKey();
         assertEquals(RSA_MODULUS, privateKey.getModulus());
diff --git a/openjdk/src/test/java/org/conscrypt/OpenSSLX509CertificateTest.java b/openjdk/src/test/java/org/conscrypt/OpenSSLX509CertificateTest.java
index ec5150a0..546bb7f3 100644
--- a/openjdk/src/test/java/org/conscrypt/OpenSSLX509CertificateTest.java
+++ b/openjdk/src/test/java/org/conscrypt/OpenSSLX509CertificateTest.java
@@ -22,6 +22,7 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeFalse;
 
 import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
@@ -35,6 +36,7 @@ import java.lang.reflect.Method;
 import java.lang.reflect.Modifier;
 import java.util.Arrays;
 import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
+import org.junit.Assume;
 import org.junit.Ignore;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -44,6 +46,8 @@ import org.junit.runners.JUnit4;
 public class OpenSSLX509CertificateTest {
   @Test
     public void testSerialization_NoContextDeserialization() throws Exception {
+      // TODO(prb): Re-work avoiding reflection for Java 17+
+      assumeFalse(TestUtils.isJavaVersion(17));
         // Set correct serialVersionUID
         {
             ObjectStreamClass clDesc = ObjectStreamClass.lookup(OpenSSLX509Certificate.class);
diff --git a/platform/build.gradle b/platform/build.gradle
index e2da924b..95f280fc 100644
--- a/platform/build.gradle
+++ b/platform/build.gradle
@@ -4,7 +4,7 @@ buildscript {
         mavenCentral()
     }
     dependencies {
-        classpath libraries.android_tools
+        classpath(libs.android.tools)
     }
 }
 
@@ -99,7 +99,7 @@ if (androidSdkInstalled) {
         testCompileOnly project(':conscrypt-android-stub'),
                         project(':conscrypt-libcore-stub')
         testImplementation project(path: ":conscrypt-testing", configuration: "shadow"),
-                           libraries.junit
+                           libs.junit
         compileOnly project(':conscrypt-android-stub'),
                     project(':conscrypt-libcore-stub')
 
diff --git a/platform/src/main/java/org/conscrypt/Platform.java b/platform/src/main/java/org/conscrypt/Platform.java
index 4b994a68..17164747 100644
--- a/platform/src/main/java/org/conscrypt/Platform.java
+++ b/platform/src/main/java/org/conscrypt/Platform.java
@@ -18,14 +18,27 @@ package org.conscrypt;
 
 import static android.system.OsConstants.SOL_SOCKET;
 import static android.system.OsConstants.SO_SNDTIMEO;
-import static org.conscrypt.metrics.Source.SOURCE_MAINLINE;
 
 import android.system.ErrnoException;
 import android.system.Os;
 import android.system.StructTimeval;
+
 import dalvik.system.BlockGuard;
 import dalvik.system.CloseGuard;
 import dalvik.system.VMRuntime;
+
+import libcore.net.NetworkSecurityPolicy;
+
+import org.conscrypt.ct.LogStore;
+import org.conscrypt.ct.LogStoreImpl;
+import org.conscrypt.ct.Policy;
+import org.conscrypt.ct.PolicyImpl;
+import org.conscrypt.flags.Flags;
+import org.conscrypt.metrics.OptionalMethod;
+import org.conscrypt.metrics.Source;
+import org.conscrypt.metrics.StatsLog;
+import org.conscrypt.metrics.StatsLogImpl;
+
 import java.io.FileDescriptor;
 import java.io.IOException;
 import java.lang.System;
@@ -50,6 +63,7 @@ import java.security.spec.InvalidParameterSpecException;
 import java.util.Collection;
 import java.util.Collections;
 import java.util.List;
+
 import javax.crypto.spec.GCMParameterSpec;
 import javax.net.ssl.HttpsURLConnection;
 import javax.net.ssl.SNIHostName;
@@ -63,24 +77,29 @@ import javax.net.ssl.StandardConstants;
 import javax.net.ssl.X509ExtendedTrustManager;
 import javax.net.ssl.X509TrustManager;
 import libcore.net.NetworkSecurityPolicy;
-import org.conscrypt.ct.LogStore;
-import org.conscrypt.ct.LogStoreImpl;
-import org.conscrypt.ct.Policy;
-import org.conscrypt.ct.PolicyImpl;
-import org.conscrypt.metrics.CipherSuite;
-import org.conscrypt.metrics.ConscryptStatsLog;
-import org.conscrypt.metrics.OptionalMethod;
-import org.conscrypt.metrics.Protocol;
+import org.conscrypt.NativeCrypto;
 import sun.security.x509.AlgorithmId;
 
-final class Platform {
+@Internal
+final public class Platform {
     private static class NoPreloadHolder { public static final Platform MAPPER = new Platform(); }
+    static boolean DEPRECATED_TLS_V1 = true;
+    static boolean ENABLED_TLS_V1 = false;
+    private static boolean FILTERED_TLS_V1 = true;
+
+    static {
+        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
+    }
 
     /**
      * Runs all the setup for the platform that only needs to run once.
      */
-    public static void setup() {
+    public static void setup(boolean deprecatedTlsV1, boolean enabledTlsV1) {
+        DEPRECATED_TLS_V1 = deprecatedTlsV1;
+        ENABLED_TLS_V1 = enabledTlsV1;
+        FILTERED_TLS_V1 = !enabledTlsV1;
         NoPreloadHolder.MAPPER.ping();
+        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
     }
 
     /**
@@ -529,15 +548,16 @@ final class Platform {
         return System.currentTimeMillis();
     }
 
-    static void countTlsHandshake(
-            boolean success, String protocol, String cipherSuite, long durationLong) {
-        Protocol proto = Protocol.forName(protocol);
-        CipherSuite suite = CipherSuite.forName(cipherSuite);
-        int duration = (int) durationLong;
+    public static StatsLog getStatsLog() {
+        return StatsLogImpl.getInstance();
+    }
+
+    public static Source getStatsSource() {
+        return Source.SOURCE_MAINLINE;
+    }
 
-        ConscryptStatsLog.write(ConscryptStatsLog.TLS_HANDSHAKE_REPORTED, success, proto.getId(),
-                suite.getId(), duration, SOURCE_MAINLINE,
-                new int[] {Os.getuid()});
+    public static int[] getUids() {
+        return new int[] {Os.getuid()};
     }
 
     public static boolean isJavaxCertificateSupported() {
@@ -545,34 +565,34 @@ final class Platform {
     }
 
     public static boolean isTlsV1Deprecated() {
-        return true;
+        return DEPRECATED_TLS_V1;
     }
 
     public static boolean isTlsV1Filtered() {
         Object targetSdkVersion = getTargetSdkVersion();
-        if ((targetSdkVersion != null) && ((int) targetSdkVersion > 34))
+        if ((targetSdkVersion != null) && ((int) targetSdkVersion > 35)
+               && ((int) targetSdkVersion < 100))
             return false;
-        return true;
+        return FILTERED_TLS_V1;
     }
 
     public static boolean isTlsV1Supported() {
-        return false;
+        return ENABLED_TLS_V1;
     }
 
     static Object getTargetSdkVersion() {
         try {
-            Class<?> vmRuntime = Class.forName("dalvik.system.VMRuntime");
-            if (vmRuntime == null) {
-                return null;
-            }
-            OptionalMethod getSdkVersion =
-                    new OptionalMethod(vmRuntime,
-                                        "getTargetSdkVersion");
-            return getSdkVersion.invokeStatic();
-        } catch (ClassNotFoundException e) {
-            return null;
-        } catch (NullPointerException e) {
+            Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");
+            Method getRuntimeMethod = vmRuntimeClass.getDeclaredMethod("getRuntime");
+            Method getTargetSdkVersionMethod =
+                        vmRuntimeClass.getDeclaredMethod("getTargetSdkVersion");
+            Object vmRuntime = getRuntimeMethod.invoke(null);
+            return getTargetSdkVersionMethod.invoke(vmRuntime);
+        } catch (IllegalAccessException |
+          NullPointerException | InvocationTargetException e) {
             return null;
+        } catch (Exception e) {
+            throw new RuntimeException(e);
         }
     }
 }
diff --git a/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java b/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java
index b7141d4c..f01e402a 100644
--- a/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java
+++ b/platform/src/main/java/org/conscrypt/ct/LogStoreImpl.java
@@ -22,6 +22,8 @@ import static java.nio.charset.StandardCharsets.UTF_8;
 import org.conscrypt.ByteArray;
 import org.conscrypt.Internal;
 import org.conscrypt.OpenSSLKey;
+import org.conscrypt.Platform;
+import org.conscrypt.metrics.StatsLog;
 import org.json.JSONArray;
 import org.json.JSONException;
 import org.json.JSONObject;
@@ -35,9 +37,6 @@ import java.nio.file.Paths;
 import java.security.InvalidKeyException;
 import java.security.NoSuchAlgorithmException;
 import java.security.PublicKey;
-import java.text.DateFormat;
-import java.text.ParseException;
-import java.text.SimpleDateFormat;
 import java.util.Arrays;
 import java.util.Base64;
 import java.util.Collections;
@@ -50,28 +49,40 @@ import java.util.logging.Logger;
 @Internal
 public class LogStoreImpl implements LogStore {
     private static final Logger logger = Logger.getLogger(LogStoreImpl.class.getName());
-    public static final String V3_PATH = "/misc/keychain/ct/v3/log_list.json";
-    private static final Path defaultLogList;
+    private static final String BASE_PATH = "misc/keychain/ct";
+    private static final int COMPAT_VERSION = 1;
+    private static final String CURRENT = "current";
+    private static final String LOG_LIST_FILENAME = "log_list.json";
+    private static final Path DEFAULT_LOG_LIST;
 
     static {
-        String ANDROID_DATA = System.getenv("ANDROID_DATA");
-        defaultLogList = Paths.get(ANDROID_DATA, V3_PATH);
+        String androidData = System.getenv("ANDROID_DATA");
+        String compatVersion = String.format("v%d", COMPAT_VERSION);
+        DEFAULT_LOG_LIST =
+                Paths.get(androidData, BASE_PATH, compatVersion, CURRENT, LOG_LIST_FILENAME);
     }
 
     private final Path logList;
+    private StatsLog metrics;
     private State state;
     private Policy policy;
-    private String version;
+    private int majorVersion;
+    private int minorVersion;
     private long timestamp;
     private Map<ByteArray, LogInfo> logs;
 
     public LogStoreImpl() {
-        this(defaultLogList);
+        this(DEFAULT_LOG_LIST);
     }
 
     public LogStoreImpl(Path logList) {
+        this(logList, Platform.getStatsLog());
+    }
+
+    public LogStoreImpl(Path logList, StatsLog metrics) {
         this.state = State.UNINITIALIZED;
         this.logList = logList;
+        this.metrics = metrics;
     }
 
     @Override
@@ -85,6 +96,32 @@ public class LogStoreImpl implements LogStore {
         return timestamp;
     }
 
+    @Override
+    public int getMajorVersion() {
+        return majorVersion;
+    }
+
+    @Override
+    public int getMinorVersion() {
+        return minorVersion;
+    }
+
+    @Override
+    public int getCompatVersion() {
+        // Currently, there is only one compatibility version supported. If we
+        // are loaded or initialized, it means the expected compatibility
+        // version was found.
+        if (state == State.LOADED || state == State.COMPLIANT || state == State.NON_COMPLIANT) {
+            return COMPAT_VERSION;
+        }
+        return 0;
+    }
+
+    @Override
+    public int getMinCompatVersionAvailable() {
+        return getCompatVersion();
+    }
+
     @Override
     public void setPolicy(Policy policy) {
         this.policy = policy;
@@ -111,12 +148,16 @@ public class LogStoreImpl implements LogStore {
      */
     private boolean ensureLogListIsLoaded() {
         synchronized (this) {
+            State previousState = state;
             if (state == State.UNINITIALIZED) {
                 state = loadLogList();
             }
             if (state == State.LOADED && policy != null) {
                 state = policy.isLogStoreCompliant(this) ? State.COMPLIANT : State.NON_COMPLIANT;
             }
+            if (state != previousState && metrics != null) {
+                metrics.updateCTLogListStatusChanged(this);
+            }
             return state == State.COMPLIANT;
         }
     }
@@ -140,8 +181,9 @@ public class LogStoreImpl implements LogStore {
         }
         HashMap<ByteArray, LogInfo> logsMap = new HashMap<>();
         try {
-            version = json.getString("version");
-            timestamp = parseTimestamp(json.getString("log_list_timestamp"));
+            majorVersion = parseMajorVersion(json.getString("version"));
+            minorVersion = parseMinorVersion(json.getString("version"));
+            timestamp = json.getLong("log_list_timestamp");
             JSONArray operators = json.getJSONArray("operators");
             for (int i = 0; i < operators.length(); i++) {
                 JSONObject operator = operators.getJSONObject(i);
@@ -160,9 +202,8 @@ public class LogStoreImpl implements LogStore {
                     JSONObject stateObject = log.optJSONObject("state");
                     if (stateObject != null) {
                         String state = stateObject.keys().next();
-                        String stateTimestamp =
-                                stateObject.getJSONObject(state).getString("timestamp");
-                        builder.setState(parseState(state), parseTimestamp(stateTimestamp));
+                        long stateTimestamp = stateObject.getJSONObject(state).getLong("timestamp");
+                        builder.setState(parseState(state), stateTimestamp);
                     }
 
                     LogInfo logInfo = builder.build();
@@ -184,6 +225,30 @@ public class LogStoreImpl implements LogStore {
         return State.LOADED;
     }
 
+    private static int parseMajorVersion(String version) {
+        int pos = version.indexOf(".");
+        if (pos == -1) {
+            pos = version.length();
+        }
+        try {
+            return Integer.parseInt(version.substring(0, pos));
+        } catch (IndexOutOfBoundsException | NumberFormatException e) {
+            return 0;
+        }
+    }
+
+    private static int parseMinorVersion(String version) {
+        int pos = version.indexOf(".");
+        if (pos != -1 && pos < version.length()) {
+            try {
+                return Integer.parseInt(version.substring(pos + 1, version.length()));
+            } catch (IndexOutOfBoundsException | NumberFormatException e) {
+                return 0;
+            }
+        }
+        return 0;
+    }
+
     private static int parseState(String state) {
         switch (state) {
             case "pending":
@@ -203,19 +268,6 @@ public class LogStoreImpl implements LogStore {
         }
     }
 
-    // ISO 8601
-    private static DateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");
-
-    @SuppressWarnings("JavaUtilDate")
-    private static long parseTimestamp(String timestamp) {
-        try {
-            Date date = dateFormatter.parse(timestamp);
-            return date.getTime();
-        } catch (ParseException e) {
-            throw new IllegalArgumentException(e);
-        }
-    }
-
     private static PublicKey parsePubKey(String key) {
         byte[] pem = ("-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----")
                              .getBytes(US_ASCII);
diff --git a/platform/src/main/java/org/conscrypt/ct/PolicyImpl.java b/platform/src/main/java/org/conscrypt/ct/PolicyImpl.java
index 8bcd4633..652745dc 100644
--- a/platform/src/main/java/org/conscrypt/ct/PolicyImpl.java
+++ b/platform/src/main/java/org/conscrypt/ct/PolicyImpl.java
@@ -74,10 +74,17 @@ public class PolicyImpl implements Policy {
                 ocspOrTLSValidSCTs.add(vsct);
             }
         }
+        PolicyCompliance compliance = PolicyCompliance.NOT_ENOUGH_SCTS;
         if (embeddedValidSCTs.size() > 0) {
-            return conformEmbeddedSCTs(embeddedValidSCTs, leaf, atTime);
+            compliance = conformEmbeddedSCTs(embeddedValidSCTs, leaf, atTime);
+            if (compliance == PolicyCompliance.COMPLY) {
+                return compliance;
+            }
+        }
+        if (ocspOrTLSValidSCTs.size() > 0) {
+            compliance = conformOCSPorTLSSCTs(ocspOrTLSValidSCTs, atTime);
         }
-        return PolicyCompliance.NOT_ENOUGH_SCTS;
+        return compliance;
     }
 
     private void filterOutUnknown(List<VerifiedSCT> scts) {
@@ -185,4 +192,37 @@ public class PolicyImpl implements Policy {
 
         return PolicyCompliance.COMPLY;
     }
+
+    private PolicyCompliance conformOCSPorTLSSCTs(
+            Set<VerifiedSCT> ocspOrTLSValidSCTs, long atTime) {
+        /* 1. At least two SCTs from a CT Log that was Qualified, Usable, or
+         *    ReadOnly at the time of check;
+         */
+        Set<LogInfo> validLogs = new HashSet<>();
+        for (VerifiedSCT vsct : ocspOrTLSValidSCTs) {
+            LogInfo log = vsct.getLogInfo();
+            switch (log.getStateAt(atTime)) {
+                case LogInfo.STATE_QUALIFIED:
+                case LogInfo.STATE_USABLE:
+                case LogInfo.STATE_READONLY:
+                    validLogs.add(log);
+            }
+        }
+        if (validLogs.size() < 2) {
+            return PolicyCompliance.NOT_ENOUGH_SCTS;
+        }
+
+        /* 2. Among the SCTs satisfying requirement 1, at least two SCTs must
+         * be issued from distinct CT Log Operators as recognized by Chrome.
+         */
+        Set<String> operators = new HashSet<>();
+        for (LogInfo logInfo : validLogs) {
+            operators.add(logInfo.getOperator());
+        }
+        if (operators.size() < 2) {
+            return PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS;
+        }
+
+        return PolicyCompliance.COMPLY;
+    }
 }
diff --git a/platform/src/test/java/org/conscrypt/TlsDeprecationTest.java b/platform/src/test/java/org/conscrypt/TlsDeprecationTest.java
new file mode 100644
index 00000000..ca36e0ad
--- /dev/null
+++ b/platform/src/test/java/org/conscrypt/TlsDeprecationTest.java
@@ -0,0 +1,166 @@
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
+package org.conscrypt;
+
+import libcore.junit.util.SwitchTargetSdkVersionRule;
+import libcore.junit.util.SwitchTargetSdkVersionRule.TargetSdkVersion;
+
+import java.security.Provider;
+import javax.net.ssl.SSLSocket;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.rules.TestRule;
+import org.junit.Rule;
+import org.junit.runners.JUnit4;
+import org.conscrypt.javax.net.ssl.TestSSLContext;
+
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.assertThrows;
+import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeFalse;
+
+@RunWith(JUnit4.class)
+public class TlsDeprecationTest {
+    @Rule
+    public final TestRule switchTargetSdkVersionRule = SwitchTargetSdkVersionRule.getInstance();
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(36)
+    public void test_SSLSocket_SSLv3Unsupported_36() throws Exception {
+        assertFalse(TestUtils.isTlsV1Filtered());
+        TestSSLContext context = TestSSLContext.create();
+        final SSLSocket client =
+                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
+        assertThrows(IllegalArgumentException.class, () -> client.setEnabledProtocols(new String[] {"SSLv3"}));
+        assertThrows(IllegalArgumentException.class, () -> client.setEnabledProtocols(new String[] {"SSL"}));
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void test_SSLSocket_SSLv3Unsupported_34() throws Exception {
+        assertTrue(TestUtils.isTlsV1Filtered());
+        TestSSLContext context = TestSSLContext.create();
+        final SSLSocket client =
+                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
+        // For app compatibility, SSLv3 is stripped out when setting only.
+        client.setEnabledProtocols(new String[] {"SSLv3"});
+        assertEquals(0, client.getEnabledProtocols().length);
+        assertThrows(IllegalArgumentException.class, () -> client.setEnabledProtocols(new String[] {"SSL"}));
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void test_TLSv1Filtered_34() throws Exception {
+        assertTrue(TestUtils.isTlsV1Filtered());
+        TestSSLContext context = TestSSLContext.create();
+        final SSLSocket client =
+                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
+        client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"});
+        assertEquals(1, client.getEnabledProtocols().length);
+        assertEquals("TLSv1.2", client.getEnabledProtocols()[0]);
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void test_TLSv1FilteredEmpty_34() throws Exception {
+        assertTrue(TestUtils.isTlsV1Filtered());
+        TestSSLContext context = TestSSLContext.create();
+        final SSLSocket client =
+                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
+        client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1"});
+        assertEquals(0, client.getEnabledProtocols().length);
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(36)
+    public void test_TLSv1Filtered_36() throws Exception {
+        assertFalse(TestUtils.isTlsV1Filtered());
+        TestSSLContext context = TestSSLContext.create();
+        final SSLSocket client =
+                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
+        assertThrows(IllegalArgumentException.class, () ->
+            client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"}));
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void testInitializeDeprecatedEnabled_34() {
+        Provider conscryptProvider = TestUtils.getConscryptProvider(true, true);
+        assertTrue(TestUtils.isTlsV1Deprecated());
+        assertFalse(TestUtils.isTlsV1Filtered());
+        assertTrue(TestUtils.isTlsV1Supported());
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(36)
+    public void testInitializeDeprecatedEnabled_36() {
+        Provider conscryptProvider = TestUtils.getConscryptProvider(true, true);
+        assertTrue(TestUtils.isTlsV1Deprecated());
+        assertFalse(TestUtils.isTlsV1Filtered());
+        assertTrue(TestUtils.isTlsV1Supported());
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void testInitializeDeprecatedDisabled_34() {
+        Provider conscryptProvider = TestUtils.getConscryptProvider(true, false);
+        assertTrue(TestUtils.isTlsV1Deprecated());
+        assertTrue(TestUtils.isTlsV1Filtered());
+        assertFalse(TestUtils.isTlsV1Supported());
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(36)
+    public void testInitializeDeprecatedDisabled_36() {
+        Provider conscryptProvider = TestUtils.getConscryptProvider(true, false);
+        assertTrue(TestUtils.isTlsV1Deprecated());
+        assertFalse(TestUtils.isTlsV1Filtered());
+        assertFalse(TestUtils.isTlsV1Supported());
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void testInitializeUndeprecatedEnabled_34() {
+        Provider conscryptProvider = TestUtils.getConscryptProvider(false, true);
+        assertFalse(TestUtils.isTlsV1Deprecated());
+        assertFalse(TestUtils.isTlsV1Filtered());
+        assertTrue(TestUtils.isTlsV1Supported());
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(36)
+    public void testInitializeUndeprecatedEnabled_36() {
+        Provider conscryptProvider = TestUtils.getConscryptProvider(false, true);
+        assertFalse(TestUtils.isTlsV1Deprecated());
+        assertFalse(TestUtils.isTlsV1Filtered());
+        assertTrue(TestUtils.isTlsV1Supported());
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void testInitializeUndeprecatedDisabled_34() {
+        assertThrows(RuntimeException.class, () -> TestUtils.getConscryptProvider(false, false));
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(36)
+    public void testInitializeUndeprecatedDisabled_36() {
+        assertThrows(RuntimeException.class, () -> TestUtils.getConscryptProvider(false, false));
+    }
+}
\ No newline at end of file
diff --git a/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java b/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java
index e2ec155f..719cbf36 100644
--- a/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java
+++ b/platform/src/test/java/org/conscrypt/ct/LogStoreImplTest.java
@@ -19,12 +19,10 @@ package org.conscrypt.ct;
 import static java.nio.charset.StandardCharsets.US_ASCII;
 import static java.nio.charset.StandardCharsets.UTF_8;
 
-import libcore.test.annotation.NonCts;
-import libcore.test.reasons.NonCtsReasons;
-
 import junit.framework.TestCase;
 
 import org.conscrypt.OpenSSLKey;
+import org.conscrypt.metrics.StatsLog;
 
 import java.io.ByteArrayInputStream;
 import java.io.File;
@@ -35,16 +33,53 @@ import java.io.IOException;
 import java.io.OutputStreamWriter;
 import java.io.PrintWriter;
 import java.security.PublicKey;
+import java.security.cert.X509Certificate;
+import java.util.ArrayList;
 import java.util.Base64;
 
 public class LogStoreImplTest extends TestCase {
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
-    public void test_loadLogList() throws Exception {
+    static class FakeStatsLog implements StatsLog {
+        public ArrayList<LogStore.State> states = new ArrayList<LogStore.State>();
+
+        @Override
+        public void countTlsHandshake(
+                boolean success, String protocol, String cipherSuite, long duration) {}
+        @Override
+        public void updateCTLogListStatusChanged(LogStore logStore) {
+            states.add(logStore.getState());
+        }
+    }
+
+    Policy alwaysCompliantStorePolicy = new Policy() {
+        @Override
+        public boolean isLogStoreCompliant(LogStore store) {
+            return true;
+        }
+        @Override
+        public PolicyCompliance doesResultConformToPolicy(
+                VerificationResult result, X509Certificate leaf) {
+            return PolicyCompliance.COMPLY;
+        }
+    };
+
+    Policy neverCompliantStorePolicy = new Policy() {
+        @Override
+        public boolean isLogStoreCompliant(LogStore store) {
+            return false;
+        }
+        @Override
+        public PolicyCompliance doesResultConformToPolicy(
+                VerificationResult result, X509Certificate leaf) {
+            return PolicyCompliance.COMPLY;
+        }
+    };
+
+    public void test_loadValidLogList() throws Exception {
         // clang-format off
         String content = "" +
 "{" +
 "  \"version\": \"1.1\"," +
-"  \"log_list_timestamp\": \"2024-01-01T11:55:12Z\"," +
+"  \"log_list_timestamp\": 1704070861000," +
 "  \"operators\": [" +
 "    {" +
 "      \"name\": \"Operator 1\"," +
@@ -58,12 +93,12 @@ public class LogStoreImplTest extends TestCase {
 "          \"mmd\": 86400," +
 "          \"state\": {" +
 "            \"usable\": {" +
-"              \"timestamp\": \"2022-11-01T18:54:00Z\"" +
+"              \"timestamp\": 1667328840000" +
 "            }" +
 "          }," +
 "          \"temporal_interval\": {" +
-"            \"start_inclusive\": \"2024-01-01T00:00:00Z\"," +
-"            \"end_exclusive\": \"2025-01-01T00:00:00Z\"" +
+"            \"start_inclusive\": 1704070861000," +
+"            \"end_exclusive\": 1735693261000" +
 "          }" +
 "        }," +
 "        {" +
@@ -74,12 +109,12 @@ public class LogStoreImplTest extends TestCase {
 "          \"mmd\": 86400," +
 "          \"state\": {" +
 "            \"usable\": {" +
-"              \"timestamp\": \"2023-11-26T12:00:00Z\"" +
+"              \"timestamp\": 1700960461000" +
 "            }" +
 "          }," +
 "          \"temporal_interval\": {" +
-"            \"start_inclusive\": \"2025-01-01T00:00:00Z\"," +
-"            \"end_exclusive\": \"2025-07-01T00:00:00Z\"" +
+"            \"start_inclusive\": 1735693261000," +
+"            \"end_exclusive\": 1751331661000" +
 "          }" +
 "        }" +
 "      ]" +
@@ -96,12 +131,12 @@ public class LogStoreImplTest extends TestCase {
 "          \"mmd\": 86400," +
 "          \"state\": {" +
 "            \"usable\": {" +
-"              \"timestamp\": \"2022-11-30T17:00:00Z\"" +
+"              \"timestamp\": 1669770061000" +
 "            }" +
 "          }," +
 "          \"temporal_interval\": {" +
-"            \"start_inclusive\": \"2024-01-01T00:00:00Z\"," +
-"            \"end_exclusive\": \"2025-01-01T00:00:00Z\"" +
+"            \"start_inclusive\": 1704070861000," +
+"            \"end_exclusive\": 1735693261000" +
 "          }" +
 "        }" +
 "      ]" +
@@ -110,14 +145,10 @@ public class LogStoreImplTest extends TestCase {
 "}";
         // clang-format on
 
+        FakeStatsLog metrics = new FakeStatsLog();
         File logList = writeFile(content);
-        LogStore store = new LogStoreImpl(logList.toPath());
-        store.setPolicy(new PolicyImpl() {
-            @Override
-            public boolean isLogStoreCompliant(LogStore store) {
-                return true;
-            }
-        });
+        LogStore store = new LogStoreImpl(logList.toPath(), metrics);
+        store.setPolicy(alwaysCompliantStorePolicy);
 
         assertNull("A null logId should return null", store.getKnownLog(null));
 
@@ -138,6 +169,36 @@ public class LogStoreImplTest extends TestCase {
                         .build();
         byte[] log1Id = Base64.getDecoder().decode("7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=");
         assertEquals("An existing logId should be returned", log1, store.getKnownLog(log1Id));
+        assertEquals("One metric update should be emitted", metrics.states.size(), 1);
+        assertEquals("The metric update for log list state should be compliant",
+                metrics.states.get(0), LogStore.State.COMPLIANT);
+    }
+
+    public void test_loadMalformedLogList() throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        String content = "}}";
+        File logList = writeFile(content);
+        LogStore store = new LogStoreImpl(logList.toPath(), metrics);
+        store.setPolicy(alwaysCompliantStorePolicy);
+
+        assertEquals(
+                "The log state should be malformed", store.getState(), LogStore.State.MALFORMED);
+        assertEquals("One metric update should be emitted", metrics.states.size(), 1);
+        assertEquals("The metric update for log list state should be malformed",
+                metrics.states.get(0), LogStore.State.MALFORMED);
+    }
+
+    public void test_loadMissingLogList() throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        File logList = new File("does_not_exist");
+        LogStore store = new LogStoreImpl(logList.toPath(), metrics);
+        store.setPolicy(alwaysCompliantStorePolicy);
+
+        assertEquals(
+                "The log state should be not found", store.getState(), LogStore.State.NOT_FOUND);
+        assertEquals("One metric update should be emitted", metrics.states.size(), 1);
+        assertEquals("The metric update for log list state should be not found",
+                metrics.states.get(0), LogStore.State.NOT_FOUND);
     }
 
     private File writeFile(String content) throws IOException {
diff --git a/platform/src/test/java/org/conscrypt/ct/PolicyImplTest.java b/platform/src/test/java/org/conscrypt/ct/PolicyImplTest.java
index f023615d..cbee4ace 100644
--- a/platform/src/test/java/org/conscrypt/ct/PolicyImplTest.java
+++ b/platform/src/test/java/org/conscrypt/ct/PolicyImplTest.java
@@ -20,9 +20,6 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
 
-import libcore.test.annotation.NonCts;
-import libcore.test.reasons.NonCtsReasons;
-
 import org.conscrypt.java.security.cert.FakeX509Certificate;
 import org.junit.Assume;
 import org.junit.BeforeClass;
@@ -44,6 +41,7 @@ public class PolicyImplTest {
     private static LogInfo usableOp2Log;
     private static LogInfo retiredOp2Log;
     private static SignedCertificateTimestamp embeddedSCT;
+    private static SignedCertificateTimestamp ocspSCT;
 
     /* Some test dates. By default:
      *  - The verification is occurring in January 2024;
@@ -131,10 +129,11 @@ public class PolicyImplTest {
          */
         embeddedSCT = new SignedCertificateTimestamp(SignedCertificateTimestamp.Version.V1, null,
                 JAN2023, null, null, SignedCertificateTimestamp.Origin.EMBEDDED);
+        ocspSCT = new SignedCertificateTimestamp(SignedCertificateTimestamp.Version.V1, null,
+                JAN2023, null, null, SignedCertificateTimestamp.Origin.OCSP_RESPONSE);
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void emptyVerificationResult() throws Exception {
         PolicyImpl p = new PolicyImpl();
         VerificationResult result = new VerificationResult();
@@ -144,17 +143,15 @@ public class PolicyImplTest {
                 p.doesResultConformToPolicyAt(result, leaf, JAN2024));
     }
 
-    @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
-    public void validVerificationResult() throws Exception {
+    public void validVerificationResult(SignedCertificateTimestamp sct) throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(usableOp1Log1)
                                     .build();
 
-        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(usableOp2Log)
                                     .build();
@@ -169,8 +166,17 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
-    public void validWithRetiredVerificationResult() throws Exception {
+    public void validEmbeddedVerificationResult() throws Exception {
+        validVerificationResult(embeddedSCT);
+    }
+
+    @Test
+    public void validOCSPVerificationResult() throws Exception {
+        validVerificationResult(ocspSCT);
+    }
+
+    @Test
+    public void validEmbeddedWithRetiredVerificationResult() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
         VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
@@ -193,15 +199,39 @@ public class PolicyImplTest {
     }
 
     @Test
-    public void invalidWithRetiredVerificationResult() throws Exception {
+    public void invalidOCSPWithRecentRetiredVerificationResult() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(ocspSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(retiredOp1LogNew)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(ocspSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("One valid, one retired SCTs from different operators",
+                PolicyCompliance.NOT_ENOUGH_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    public void invalidWithRetiredVerificationResult(SignedCertificateTimestamp sct)
+            throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(retiredOp1LogOld)
                                     .build();
 
-        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(usableOp2Log)
                                     .build();
@@ -217,11 +247,19 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
-    public void invalidOneSctVerificationResult() throws Exception {
+    public void invalidEmbeddedWithRetiredVerificationResult() throws Exception {
+        invalidWithRetiredVerificationResult(embeddedSCT);
+    }
+
+    @Test
+    public void invalidOCSPWithRetiredVerificationResult() throws Exception {
+        invalidWithRetiredVerificationResult(ocspSCT);
+    }
+
+    public void invalidOneSctVerificationResult(SignedCertificateTimestamp sct) throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(usableOp1Log1)
                                     .build();
@@ -235,16 +273,25 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
-    public void invalidTwoSctsVerificationResult() throws Exception {
+    public void invalidEmbeddedOneSctVerificationResult() throws Exception {
+        invalidOneSctVerificationResult(embeddedSCT);
+    }
+
+    @Test
+    public void invalidOCSPOneSctVerificationResult() throws Exception {
+        invalidOneSctVerificationResult(ocspSCT);
+    }
+
+    public void invalidTwoRetiredSctsVerificationResult(SignedCertificateTimestamp sct)
+            throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(retiredOp1LogNew)
                                     .build();
 
-        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(retiredOp2Log)
                                     .build();
@@ -259,16 +306,25 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
-    public void invalidTwoSctsSameOperatorVerificationResult() throws Exception {
+    public void invalidEmbeddedTwoRetiredSctsVerificationResult() throws Exception {
+        invalidTwoRetiredSctsVerificationResult(embeddedSCT);
+    }
+
+    @Test
+    public void invalidOCSPTwoRetiredSctsVerificationResult() throws Exception {
+        invalidTwoRetiredSctsVerificationResult(ocspSCT);
+    }
+
+    public void invalidTwoSctsSameOperatorVerificationResult(SignedCertificateTimestamp sct)
+            throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(usableOp1Log1)
                                     .build();
 
-        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(usableOp1Log2)
                                     .build();
@@ -283,7 +339,39 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void invalidEmbeddedTwoSctsSameOperatorVerificationResult() throws Exception {
+        invalidTwoSctsSameOperatorVerificationResult(embeddedSCT);
+    }
+
+    @Test
+    public void invalidOCSPTwoSctsSameOperatorVerificationResult() throws Exception {
+        invalidTwoSctsSameOperatorVerificationResult(ocspSCT);
+    }
+
+    @Test
+    public void invalidOneEmbeddedOneOCSPVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp1Log1)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(ocspSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("Two valid SCTs with different origins", PolicyCompliance.NOT_ENOUGH_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
     public void validRecentLogStore() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
@@ -297,7 +385,6 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void invalidFutureLogStore() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
@@ -311,7 +398,6 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void invalidOldLogStore() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractConscryptSocket.java b/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractConscryptSocket.java
index d601a509..13fcc8f5 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractConscryptSocket.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractConscryptSocket.java
@@ -677,24 +677,6 @@ abstract class AbstractConscryptSocket extends SSLSocket {
     @android.compat.annotation.UnsupportedAppUsage(maxTargetSdk = 30, trackingBug = 170729553)
     abstract void setChannelIdPrivateKey(PrivateKey privateKey);
 
-    /**
-     * Returns null always for backward compatibility.
-     * @deprecated NPN is not supported
-     */
-    @android.compat.annotation.UnsupportedAppUsage(maxTargetSdk = 30, trackingBug = 170729553)
-    @Deprecated
-    byte[] getNpnSelectedProtocol() {
-        return null;
-    }
-
-    /**
-     * This method does nothing and is kept for backward compatibility.
-     * @deprecated NPN is not supported
-     */
-    @android.compat.annotation.UnsupportedAppUsage(maxTargetSdk = 30, trackingBug = 170729553)
-    @Deprecated
-    void setNpnProtocols(byte[] npnProtocols) {}
-
     /**
      * Returns the protocol agreed upon by client and server, or {@code null} if
      * no protocol was agreed upon.
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractSessionContext.java b/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractSessionContext.java
index 58bedbcc..b4117953 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractSessionContext.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/AbstractSessionContext.java
@@ -246,7 +246,7 @@ abstract class AbstractSessionContext implements SSLSessionContext {
     }
 
     @Override
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("Finalize")
     protected void finalize() throws Throwable {
         try {
             freeNative();
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/AllocatedBuffer.java b/repackaged/common/src/main/java/com/android/org/conscrypt/AllocatedBuffer.java
index cc1bc07b..e6c42d51 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/AllocatedBuffer.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/AllocatedBuffer.java
@@ -53,6 +53,7 @@ public abstract class AllocatedBuffer {
      * @deprecated this method is not used
      */
     @Deprecated
+    @SuppressWarnings("InlineMeSuggester")
     public AllocatedBuffer retain() {
         // Do nothing.
         return this;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ArrayUtils.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ArrayUtils.java
index f1cd5bcc..903c4303 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ArrayUtils.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ArrayUtils.java
@@ -39,6 +39,7 @@ public final class ArrayUtils {
     }
 
     @SafeVarargs
+    @SuppressWarnings("varargs")
     public static <T> T[] concatValues(T[] a1, T... values) {
         return concat(a1, values);
     }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/CertificatePriorityComparator.java b/repackaged/common/src/main/java/com/android/org/conscrypt/CertificatePriorityComparator.java
index defb37e1..070412bd 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/CertificatePriorityComparator.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/CertificatePriorityComparator.java
@@ -77,7 +77,7 @@ public final class CertificatePriorityComparator implements Comparator<X509Certi
     }
 
     @Override
-    @SuppressWarnings("JdkObsolete") // Certificate uses Date
+    @SuppressWarnings({"JdkObsolete", "JavaUtilDate"}) // Certificate uses Date
     public int compare(X509Certificate lhs, X509Certificate rhs) {
         int result;
         boolean lhsSelfSigned = lhs.getSubjectDN().equals(lhs.getIssuerDN());
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/Conscrypt.java b/repackaged/common/src/main/java/com/android/org/conscrypt/Conscrypt.java
index 3013640c..d565d2da 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/Conscrypt.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/Conscrypt.java
@@ -171,6 +171,8 @@ public final class Conscrypt {
         private String name = Platform.getDefaultProviderName();
         private boolean provideTrustManager = Platform.provideTrustManagerByDefault();
         private String defaultTlsProtocol = NativeCrypto.SUPPORTED_PROTOCOL_TLSV1_3;
+        private boolean deprecatedTlsV1 = true;
+        private boolean enabledTlsV1 = false;
 
         private ProviderBuilder() {}
 
@@ -188,6 +190,7 @@ public final class Conscrypt {
          * @deprecated Use provideTrustManager(true)
          */
         @Deprecated
+        @SuppressWarnings("InlineMeSuggester")
         public ProviderBuilder provideTrustManager() {
             return provideTrustManager(true);
         }
@@ -210,8 +213,21 @@ public final class Conscrypt {
             return this;
         }
 
+        /** Specifies whether TLS v1.0 and 1.1 should be deprecated */
+        public ProviderBuilder isTlsV1Deprecated(boolean deprecatedTlsV1) {
+            this.deprecatedTlsV1 = deprecatedTlsV1;
+            return this;
+        }
+
+        /** Specifies whether TLS v1.0 and 1.1 should be enabled */
+        public ProviderBuilder isTlsV1Enabled(boolean enabledTlsV1) {
+            this.enabledTlsV1 = enabledTlsV1;
+            return this;
+        }
+
         public Provider build() {
-            return new OpenSSLProvider(name, provideTrustManager, defaultTlsProtocol);
+            return new OpenSSLProvider(name, provideTrustManager,
+                defaultTlsProtocol, deprecatedTlsV1, enabledTlsV1);
         }
     }
 
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngine.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngine.java
index b8fc5193..7484cd9a 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngine.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngine.java
@@ -1671,7 +1671,7 @@ final class ConscryptEngine extends AbstractConscryptEngine implements NativeCry
     }
 
     @Override
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("Finalize")
     protected void finalize() throws Throwable {
         try {
             // If ssl is null, object must not be fully constructed so nothing for us to do here.
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngineSocket.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngineSocket.java
index 0a1933fa..6cd575e4 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngineSocket.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptEngineSocket.java
@@ -27,6 +27,8 @@ import static com.android.org.conscrypt.SSLUtils.EngineStates.STATE_READY_HANDSH
 import static javax.net.ssl.SSLEngineResult.Status.CLOSED;
 import static javax.net.ssl.SSLEngineResult.Status.OK;
 
+import com.android.org.conscrypt.metrics.StatsLog;
+
 import java.io.EOFException;
 import java.io.IOException;
 import java.io.InputStream;
@@ -307,9 +309,12 @@ class ConscryptEngineSocket extends OpenSSLSocketImpl implements SSLParametersIm
 
                 case STATE_READY_HANDSHAKE_CUT_THROUGH:
                     if (handshakeStartedMillis > 0) {
-                        Platform.countTlsHandshake(true, engine.getSession().getProtocol(),
-                                engine.getSession().getCipherSuite(),
-                                Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                        StatsLog statsLog = Platform.getStatsLog();
+                        if (statsLog != null) {
+                            statsLog.countTlsHandshake(true, engine.getSession().getProtocol(),
+                                    engine.getSession().getCipherSuite(),
+                                    Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                        }
                         handshakeStartedMillis = 0;
                     }
                     notify = true;
@@ -321,9 +326,13 @@ class ConscryptEngineSocket extends OpenSSLSocketImpl implements SSLParametersIm
 
                 case STATE_CLOSED:
                     if (handshakeStartedMillis > 0) {
-                        // Handshake was in progress and so must have failed.
-                        Platform.countTlsHandshake(false, "TLS_PROTO_FAILED", "TLS_CIPHER_FAILED",
-                                Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                        StatsLog statsLog = Platform.getStatsLog();
+                        if (statsLog != null) {
+                            // Handshake was in progress and so must have failed.
+                            statsLog.countTlsHandshake(false, "TLS_PROTO_FAILED",
+                                    "TLS_CIPHER_FAILED",
+                                    Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                        }
                         handshakeStartedMillis = 0;
                     }
                     notify = true;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptFileDescriptorSocket.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptFileDescriptorSocket.java
index 129e37f2..ce9a25ca 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptFileDescriptorSocket.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ConscryptFileDescriptorSocket.java
@@ -26,6 +26,7 @@ import static com.android.org.conscrypt.SSLUtils.EngineStates.STATE_READY_HANDSH
 
 import com.android.org.conscrypt.ExternalSession.Provider;
 import com.android.org.conscrypt.NativeRef.SSL_SESSION;
+import com.android.org.conscrypt.metrics.StatsLog;
 
 import java.io.IOException;
 import java.io.InputStream;
@@ -1063,7 +1064,7 @@ class ConscryptFileDescriptorSocket extends OpenSSLSocketImpl
     }
 
     @Override
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("Finalize")
     protected final void finalize() throws Throwable {
         try {
             /*
@@ -1201,9 +1202,12 @@ class ConscryptFileDescriptorSocket extends OpenSSLSocketImpl
 
             case STATE_READY:
                 if (handshakeStartedMillis != 0) {
-                    Platform.countTlsHandshake(true, activeSession.getProtocol(),
-                            activeSession.getCipherSuite(),
-                            Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                    StatsLog statsLog = Platform.getStatsLog();
+                    if (statsLog != null) {
+                        statsLog.countTlsHandshake(true, activeSession.getProtocol(),
+                                activeSession.getCipherSuite(),
+                                Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                    }
                     handshakeStartedMillis = 0;
                 }
                 break;
@@ -1211,8 +1215,11 @@ class ConscryptFileDescriptorSocket extends OpenSSLSocketImpl
             case STATE_CLOSED: {
                 if (handshakeStartedMillis != 0) {
                     // Handshake was in progress so must have failed.
-                    Platform.countTlsHandshake(false, "TLS_PROTO_FAILED", "TLS_CIPHER_FAILED",
-                            Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                    StatsLog statsLog = Platform.getStatsLog();
+                    if (statsLog != null) {
+                        statsLog.countTlsHandshake(false, "TLS_PROTO_FAILED", "TLS_CIPHER_FAILED",
+                                Platform.getMillisSinceBoot() - handshakeStartedMillis);
+                    }
                     handshakeStartedMillis = 0;
                 }
                 if (!ssl.isClosed() && state >= STATE_HANDSHAKE_STARTED && state < STATE_CLOSED) {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/CryptoUpcalls.java b/repackaged/common/src/main/java/com/android/org/conscrypt/CryptoUpcalls.java
index 7e2a4e93..9b31e5d5 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/CryptoUpcalls.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/CryptoUpcalls.java
@@ -24,8 +24,10 @@ import java.security.Provider;
 import java.security.Security;
 import java.security.Signature;
 import java.util.ArrayList;
+import java.util.List;
 import java.util.logging.Level;
 import java.util.logging.Logger;
+
 import javax.crypto.Cipher;
 import javax.crypto.NoSuchPaddingException;
 
@@ -44,8 +46,8 @@ final class CryptoUpcalls {
     /**
      * Finds providers that are not us that provide the requested algorithms.
      */
-    private static ArrayList<Provider> getExternalProviders(String algorithm) {
-        ArrayList<Provider> providers = new ArrayList<Provider>(1);
+    private static List<Provider> getExternalProviders(String algorithm) {
+        List<Provider> providers = new ArrayList<>(1);
         for (Provider p : Security.getProviders(algorithm)) {
             if (!Conscrypt.isConscrypt(p)) {
                 providers.add(p);
@@ -62,7 +64,7 @@ final class CryptoUpcalls {
         // http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
         String keyAlgorithm = javaKey.getAlgorithm();
         if (!"EC".equals(keyAlgorithm)) {
-            throw new RuntimeException("Unexpected key type: " + javaKey.toString());
+            throw new RuntimeException("Unexpected key type: " + javaKey);
         }
 
         return signDigestWithPrivateKey(javaKey, message, "NONEwithECDSA");
@@ -95,7 +97,7 @@ final class CryptoUpcalls {
         // If the preferred provider was us, fall back to trying to find the
         // first not-us provider that initializes correctly.
         if (signature == null) {
-            ArrayList<Provider> providers = getExternalProviders("Signature." + algorithm);
+            List<Provider> providers = getExternalProviders("Signature." + algorithm);
             RuntimeException savedRuntimeException = null;
             for (Provider p : providers) {
                 try {
@@ -170,7 +172,7 @@ final class CryptoUpcalls {
         }
 
         String transformation = "RSA/ECB/" + jcaPadding;
-        Cipher c = null;
+        Cipher c;
 
         // Since this is a delegated key, we cannot handle providing a cipher using this key.
         // Otherwise we wouldn't end up in this class in the first place. The first step is to
@@ -183,10 +185,7 @@ final class CryptoUpcalls {
             if (Conscrypt.isConscrypt(c.getProvider())) {
                 c = null;
             }
-        } catch (NoSuchAlgorithmException e) {
-            logger.warning("Unsupported cipher algorithm: " + transformation);
-            return null;
-        } catch (NoSuchPaddingException e) {
+        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
             logger.warning("Unsupported cipher algorithm: " + transformation);
             return null;
         } catch (InvalidKeyException e) {
@@ -197,17 +196,14 @@ final class CryptoUpcalls {
         // If the preferred provider was us, fall back to trying to find the
         // first not-us provider that initializes correctly.
         if (c == null) {
-            ArrayList<Provider> providers = getExternalProviders("Cipher." + transformation);
+            List<Provider> providers = getExternalProviders("Cipher." + transformation);
             for (Provider p : providers) {
                 try {
                     c = Cipher.getInstance(transformation, p);
                     c.init(cipherMode, javaKey);
                     break;
-                } catch (NoSuchAlgorithmException e) {
-                    c = null;
-                } catch (InvalidKeyException e) {
-                    c = null;
-                } catch (NoSuchPaddingException e) {
+                } catch (
+                        NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
                     c = null;
                 }
             }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/DefaultSSLContextImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/DefaultSSLContextImpl.java
index 41ca3633..6eae5dec 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/DefaultSSLContextImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/DefaultSSLContextImpl.java
@@ -73,14 +73,8 @@ public class DefaultSSLContextImpl extends OpenSSLContextImpl {
         char[] pwd = (keystorepwd == null) ? null : keystorepwd.toCharArray();
 
         KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
-        InputStream is = null;
-        try {
-            is = new BufferedInputStream(new FileInputStream(keystore));
+        try (InputStream is = new BufferedInputStream(new FileInputStream(keystore))) {
             ks.load(is, pwd);
-        } finally {
-            if (is != null) {
-                is.close();
-            }
         }
 
         String kmfAlg = KeyManagerFactory.getDefaultAlgorithm();
@@ -106,14 +100,8 @@ public class DefaultSSLContextImpl extends OpenSSLContextImpl {
 
         // TODO Defaults: jssecacerts; cacerts
         KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
-        InputStream is = null;
-        try {
-            is = new BufferedInputStream(new FileInputStream(keystore));
+        try (InputStream is = new BufferedInputStream(new FileInputStream(keystore))) {
             ks.load(is, pwd);
-        } finally {
-            if (is != null) {
-                is.close();
-            }
         }
         String tmfAlg = TrustManagerFactory.getDefaultAlgorithm();
         TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlg);
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
index e3189d0b..b1b4d70e 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeCrypto.java
@@ -139,19 +139,19 @@ public final class NativeCrypto {
     static native int RSA_private_decrypt(int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey,
             int padding) throws BadPaddingException, SignatureException;
 
-    /**
-     * @return array of {n, e}
+    /*
+     * Returns array of {n, e}
      */
     static native byte[][] get_RSA_public_params(NativeRef.EVP_PKEY rsa);
 
-    /**
-     * @return array of {n, e, d, p, q, dmp1, dmq1, iqmp}
+    /*
+     * Returns array of {n, e, d, p, q, dmp1, dmq1, iqmp}
      */
     static native byte[][] get_RSA_private_params(NativeRef.EVP_PKEY rsa);
 
     // --- ChaCha20 -----------------------
 
-    /**
+    /*
      * Returns the encrypted or decrypted version of the data.
      */
     static native void chacha20_encrypt_decrypt(byte[] in, int inOffset, byte[] out, int outOffset,
@@ -1054,26 +1054,48 @@ public final class NativeCrypto {
 
     static native void set_SSL_psk_server_callback_enabled(long ssl, NativeSsl ssl_holder, boolean enabled);
 
-    private static final String[] ENABLED_PROTOCOLS_TLSV1 = Platform.isTlsV1Deprecated()
-            ? new String[0]
-            : new String[] {
-                      DEPRECATED_PROTOCOL_TLSV1,
-                      DEPRECATED_PROTOCOL_TLSV1_1,
-              };
-
-    private static final String[] SUPPORTED_PROTOCOLS_TLSV1 = Platform.isTlsV1Supported()
-            ? new String[] {
+    public static void setTlsV1DeprecationStatus(boolean deprecated, boolean supported) {
+        if (deprecated) {
+            TLSV12_PROTOCOLS = new String[] {
+                SUPPORTED_PROTOCOL_TLSV1_2,
+            };
+            TLSV13_PROTOCOLS = new String[] {
+                SUPPORTED_PROTOCOL_TLSV1_2,
+                SUPPORTED_PROTOCOL_TLSV1_3,
+            };
+        } else {
+            TLSV12_PROTOCOLS = new String[] {
+                DEPRECATED_PROTOCOL_TLSV1,
+                DEPRECATED_PROTOCOL_TLSV1_1,
+                SUPPORTED_PROTOCOL_TLSV1_2,
+            };
+            TLSV13_PROTOCOLS = new String[] {
                 DEPRECATED_PROTOCOL_TLSV1,
                 DEPRECATED_PROTOCOL_TLSV1_1,
-            } : new String[0];
+                SUPPORTED_PROTOCOL_TLSV1_2,
+                SUPPORTED_PROTOCOL_TLSV1_3,
+            };
+        }
+        if (supported) {
+            SUPPORTED_PROTOCOLS = new String[] {
+                DEPRECATED_PROTOCOL_TLSV1,
+                DEPRECATED_PROTOCOL_TLSV1_1,
+                SUPPORTED_PROTOCOL_TLSV1_2,
+                SUPPORTED_PROTOCOL_TLSV1_3,
+            };
+        } else {
+            SUPPORTED_PROTOCOLS = new String[] {
+                SUPPORTED_PROTOCOL_TLSV1_2,
+                SUPPORTED_PROTOCOL_TLSV1_3,
+            };
+        }
+    }
 
     /** Protocols to enable by default when "TLSv1.3" is requested. */
-    static final String[] TLSV13_PROTOCOLS = ArrayUtils.concatValues(
-            ENABLED_PROTOCOLS_TLSV1, SUPPORTED_PROTOCOL_TLSV1_2, SUPPORTED_PROTOCOL_TLSV1_3);
+    static String[] TLSV13_PROTOCOLS;
 
     /** Protocols to enable by default when "TLSv1.2" is requested. */
-    static final String[] TLSV12_PROTOCOLS =
-            ArrayUtils.concatValues(ENABLED_PROTOCOLS_TLSV1, SUPPORTED_PROTOCOL_TLSV1_2);
+    static String[] TLSV12_PROTOCOLS;
 
     /** Protocols to enable by default when "TLSv1.1" is requested. */
     static final String[] TLSV11_PROTOCOLS = new String[] {
@@ -1085,20 +1107,12 @@ public final class NativeCrypto {
     /** Protocols to enable by default when "TLSv1" is requested. */
     static final String[] TLSV1_PROTOCOLS = TLSV11_PROTOCOLS;
 
-    static final String[] DEFAULT_PROTOCOLS = TLSV13_PROTOCOLS;
-
     // If we ever get a new protocol go look for tests which are skipped using
     // assumeTlsV11Enabled()
-    private static final String[] SUPPORTED_PROTOCOLS = ArrayUtils.concatValues(
-            SUPPORTED_PROTOCOLS_TLSV1,
-            SUPPORTED_PROTOCOL_TLSV1_2,
-            SUPPORTED_PROTOCOL_TLSV1_3);
+    private static String[] SUPPORTED_PROTOCOLS;
 
     public static String[] getDefaultProtocols() {
-        if (Platform.isTlsV1Deprecated()) {
-          return DEFAULT_PROTOCOLS.clone();
-        }
-        return SUPPORTED_PROTOCOLS.clone();
+        return TLSV13_PROTOCOLS.clone();
     }
 
     static String[] getSupportedProtocols() {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeRef.java b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeRef.java
index 9d76c915..011112b6 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeRef.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeRef.java
@@ -28,7 +28,6 @@ abstract class NativeRef {
         if (address == 0) {
             throw new NullPointerException("address == 0");
         }
-
         this.address = address;
     }
 
@@ -43,11 +42,11 @@ abstract class NativeRef {
 
     @Override
     public int hashCode() {
-        return (int) (address ^ (address >>> 32));
+        return Long.hashCode(address);
     }
 
     @Override
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("Finalize")
     protected void finalize() throws Throwable {
         try {
             if (address != 0) {
@@ -58,6 +57,11 @@ abstract class NativeRef {
         }
     }
 
+    // VisibleForTesting
+    public boolean isNull() {
+        return address == 0;
+    }
+
     abstract void doFree(long context);
 
     static final class CMAC_CTX extends NativeRef {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java
index 284894b1..6c10fa19 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSsl.java
@@ -32,9 +32,7 @@ import com.android.org.conscrypt.SSLParametersImpl.PSKCallbacks;
 
 import java.io.FileDescriptor;
 import java.io.IOException;
-import java.io.UnsupportedEncodingException;
 import java.net.SocketException;
-import java.nio.charset.Charset;
 import java.nio.charset.StandardCharsets;
 import java.security.InvalidKeyException;
 import java.security.PrivateKey;
@@ -136,7 +134,7 @@ final class NativeSsl {
         if (label == null) {
             throw new NullPointerException("Label is null");
         }
-        byte[] labelBytes = label.getBytes(Charset.forName("US-ASCII"));
+        byte[] labelBytes = label.getBytes(StandardCharsets.US_ASCII);
         return NativeCrypto.SSL_export_keying_material(ssl, this, labelBytes, context, length);
     }
 
@@ -144,8 +142,8 @@ final class NativeSsl {
         return NativeCrypto.SSL_get_signed_cert_timestamp_list(ssl, this);
     }
 
-    /**
-     * @see NativeCrypto.SSLHandshakeCallbacks#clientPSKKeyRequested(String, byte[], byte[])
+    /*
+     * See NativeCrypto.SSLHandshakeCallbacks#clientPSKKeyRequested(String, byte[], byte[]).
      */
     @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
     int clientPSKKeyRequested(String identityHint, byte[] identityBytesOut, byte[] key) {
@@ -163,11 +161,7 @@ final class NativeSsl {
         } else if (identity.isEmpty()) {
             identityBytes = EmptyArray.BYTE;
         } else {
-            try {
-                identityBytes = identity.getBytes("UTF-8");
-            } catch (UnsupportedEncodingException e) {
-                throw new RuntimeException("UTF-8 encoding not supported", e);
-            }
+            identityBytes = identity.getBytes(StandardCharsets.UTF_8);
         }
         if (identityBytes.length + 1 > identityBytesOut.length) {
             // Insufficient space in the output buffer
@@ -190,8 +184,8 @@ final class NativeSsl {
         return secretKeyBytes.length;
     }
 
-    /**
-     * @see NativeCrypto.SSLHandshakeCallbacks#serverPSKKeyRequested(String, String, byte[])
+    /*
+     * See NativeCrypto.SSLHandshakeCallbacks#serverPSKKeyRequested(String, String, byte[]).
      */
     @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
     int serverPSKKeyRequested(String identityHint, String identity, byte[] key) {
@@ -641,8 +635,8 @@ final class NativeSsl {
     }
 
     @Override
-    @SuppressWarnings("deprecation")
-    protected final void finalize() throws Throwable {
+    @SuppressWarnings("Finalize")
+    protected void finalize() throws Throwable {
         try {
             close();
         } finally {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSslSession.java b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSslSession.java
index 7621ae2b..c95ab570 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSslSession.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/NativeSslSession.java
@@ -341,7 +341,7 @@ abstract class NativeSslSession {
                 return baos.toByteArray();
             } catch (IOException e) {
                 // TODO(nathanmittler): Better error handling?
-                logger.log(Level.WARNING, "Failed to convert saved SSL Session: ", e);
+                logger.log(Level.FINE, "Failed to convert saved SSL Session: ", e);
                 return null;
             } catch (CertificateEncodingException e) {
                 log(e);
@@ -465,7 +465,7 @@ abstract class NativeSslSession {
 
     private static void log(Throwable t) {
         // TODO(nathanmittler): Better error handling?
-        logger.log(Level.INFO, "Error inflating SSL session: {0}",
+        logger.log(Level.FINE, "Error inflating SSL session: {0}",
                 (t.getMessage() != null ? t.getMessage() : t.getClass().getName()));
     }
 
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLContextImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLContextImpl.java
index bcadddfe..358175ab 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLContextImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLContextImpl.java
@@ -77,12 +77,14 @@ public abstract class OpenSSLContextImpl extends SSLContextSpi {
     // END Android-added: Restore missing constructor that is used by apps
 
     /**
-     * Constuctor for the DefaultSSLContextImpl.  The unused boolean parameter is solely to
+     * Constructor for the DefaultSSLContextImpl.  The unused boolean parameter is solely to
      * indicate that this constructor is desired.
      */
     @SuppressWarnings("StaticAssignmentInConstructor")
     OpenSSLContextImpl(String[] protocols, boolean unused)
             throws GeneralSecurityException, IOException {
+        // TODO(prb): It looks like nowadays we can push the synchronisation into
+        // DefaultSSLContextImpl itself, but put it in its own CL for safety.
         synchronized (DefaultSSLContextImpl.class) {
             this.protocols = null;
             // This is the only place defaultSslContextImpl is read or written so all
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLProvider.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLProvider.java
index 5654d815..7dcdde8f 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLProvider.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLProvider.java
@@ -58,17 +58,29 @@ public final class OpenSSLProvider extends Provider {
 
     @SuppressWarnings("deprecation")
     public OpenSSLProvider(String providerName) {
-        this(providerName, Platform.provideTrustManagerByDefault(), "TLSv1.3");
+        this(providerName, Platform.provideTrustManagerByDefault(), "TLSv1.3",
+            Platform.DEPRECATED_TLS_V1, Platform.ENABLED_TLS_V1);
     }
 
-    OpenSSLProvider(String providerName, boolean includeTrustManager, String defaultTlsProtocol) {
+    OpenSSLProvider(String providerName, boolean includeTrustManager,
+            String defaultTlsProtocol) {
+        this(providerName, includeTrustManager, defaultTlsProtocol,
+            Platform.DEPRECATED_TLS_V1, Platform.ENABLED_TLS_V1);
+    }
+
+    OpenSSLProvider(String providerName, boolean includeTrustManager,
+            String defaultTlsProtocol, boolean deprecatedTlsV1,
+            boolean enabledTlsV1) {
         super(providerName, 1.0, "Android's OpenSSL-backed security provider");
 
         // Ensure that the native library has been loaded.
         NativeCrypto.checkAvailability();
 
+        if (!deprecatedTlsV1 && !enabledTlsV1) {
+            throw new IllegalArgumentException("TLSv1 is not deprecated and cannot be disabled.");
+        }
         // Make sure the platform is initialized.
-        Platform.setup();
+        Platform.setup(deprecatedTlsV1, enabledTlsV1);
 
         /* === SSL Contexts === */
         String classOpenSSLContextImpl = PREFIX + "OpenSSLContextImpl";
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLRSAPrivateCrtKey.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLRSAPrivateCrtKey.java
index 59817387..4cc822de 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLRSAPrivateCrtKey.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLRSAPrivateCrtKey.java
@@ -98,7 +98,7 @@ final class OpenSSLRSAPrivateCrtKey extends OpenSSLRSAPrivateKey implements RSAP
     }
 
     static OpenSSLKey getInstance(RSAPrivateCrtKey rsaPrivateKey) throws InvalidKeyException {
-        /**
+        /*
          * If the key is not encodable (PKCS11-like key), then wrap it and use
          * JNI upcalls to satisfy requests.
          */
@@ -247,7 +247,7 @@ final class OpenSSLRSAPrivateCrtKey extends OpenSSLRSAPrivateKey implements RSAP
     }
 
     @Override
-    public final int hashCode() {
+    public int hashCode() {
         int hashCode = super.hashCode();
         if (publicExponent != null) {
             hashCode ^= publicExponent.hashCode();
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLRSAPrivateKey.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLRSAPrivateKey.java
index d74c0bde..2feebe1b 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLRSAPrivateKey.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLRSAPrivateKey.java
@@ -124,7 +124,7 @@ class OpenSSLRSAPrivateKey implements RSAPrivateKey, OpenSSLKeyHolder {
     }
 
     static OpenSSLKey getInstance(RSAPrivateKey rsaPrivateKey) throws InvalidKeyException {
-        /**
+        /*
          * If the key is not encodable (PKCS11-like key), then wrap it and use
          * JNI upcalls to satisfy requests.
          */
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLSignature.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLSignature.java
index cf48e9b7..61ac8dae 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLSignature.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLSignature.java
@@ -168,6 +168,7 @@ public class OpenSSLSignature extends SignatureSpi {
 
     @Deprecated
     @Override
+    @SuppressWarnings("InlineMeSuggester")
     protected Object engineGetParameter(String param) throws InvalidParameterException {
         return null;
     }
@@ -488,9 +489,7 @@ public class OpenSSLSignature extends SignatureSpi {
                                 saltSizeBytes,
                                 TRAILER_FIELD_BC_ID));
                 return result;
-            } catch (NoSuchAlgorithmException e) {
-                throw new ProviderException("Failed to create PSS AlgorithmParameters", e);
-            } catch (InvalidParameterSpecException e) {
+            } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
                 throw new ProviderException("Failed to create PSS AlgorithmParameters", e);
             }
         }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLSocketImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLSocketImpl.java
index ef603bec..df9847a9 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLSocketImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLSocketImpl.java
@@ -137,10 +137,10 @@ public abstract class OpenSSLSocketImpl extends AbstractConscryptSocket {
      */
     @android.compat.annotation.UnsupportedAppUsage
     @libcore.api.CorePlatformApi(status = libcore.api.CorePlatformApi.Status.STABLE)
-    @Override
     @Deprecated
+    @SuppressWarnings("InlineMeSuggester")
     public final byte[] getNpnSelectedProtocol() {
-        return super.getNpnSelectedProtocol();
+        return null;
     }
 
     /**
@@ -148,11 +148,9 @@ public abstract class OpenSSLSocketImpl extends AbstractConscryptSocket {
      */
     @android.compat.annotation.UnsupportedAppUsage
     @libcore.api.CorePlatformApi(status = libcore.api.CorePlatformApi.Status.STABLE)
-    @Override
     @Deprecated
-    public final void setNpnProtocols(byte[] npnProtocols) {
-        super.setNpnProtocols(npnProtocols);
-    }
+    @SuppressWarnings("InlineMeSuggester")
+    public final void setNpnProtocols(byte[] npnProtocols) {}
 
     /**
      * @deprecated use {@link #setApplicationProtocols(String[])} instead.
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CRL.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CRL.java
index 95e1210d..4124a4e2 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CRL.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CRL.java
@@ -281,11 +281,13 @@ final class OpenSSLX509CRL extends X509CRL {
     }
 
     @Override
+    @SuppressWarnings({"JavaUtilDate"}) // Needed for API compatibility
     public Date getThisUpdate() {
         return (Date) thisUpdate.clone();
     }
 
     @Override
+    @SuppressWarnings({"JavaUtilDate"}) // Needed for API compatibility
     public Date getNextUpdate() {
         return (Date) nextUpdate.clone();
     }
@@ -415,7 +417,7 @@ final class OpenSSLX509CRL extends X509CRL {
     }
 
     @Override
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("Finalize")
     protected void finalize() throws Throwable {
         try {
             long toFree = mContext;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CRLEntry.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CRLEntry.java
index d8c5d9e8..3c1371dc 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CRLEntry.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509CRLEntry.java
@@ -58,7 +58,7 @@ final class OpenSSLX509CRLEntry extends X509CRLEntry {
             return null;
         }
 
-        return new HashSet<String>(Arrays.asList(critOids));
+        return new HashSet<>(Arrays.asList(critOids));
     }
 
     @Override
@@ -83,7 +83,7 @@ final class OpenSSLX509CRLEntry extends X509CRLEntry {
             return null;
         }
 
-        return new HashSet<String>(Arrays.asList(critOids));
+        return new HashSet<>(Arrays.asList(critOids));
     }
 
     @Override
@@ -112,6 +112,7 @@ final class OpenSSLX509CRLEntry extends X509CRLEntry {
     }
 
     @Override
+    @SuppressWarnings("JavaUtilDate") // Needed for API compatibility
     public Date getRevocationDate() {
         return (Date) revocationDate.clone();
     }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509Certificate.java b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509Certificate.java
index 97097701..2edb150a 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509Certificate.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/OpenSSLX509Certificate.java
@@ -77,13 +77,6 @@ public final class OpenSSLX509Certificate extends X509Certificate {
         notAfter = toDate(NativeCrypto.X509_get_notAfter(mContext, this));
     }
 
-    // A non-throwing constructor used when we have already parsed the dates
-    private OpenSSLX509Certificate(long ctx, Date notBefore, Date notAfter) {
-        mContext = ctx;
-        this.notBefore = notBefore;
-        this.notAfter = notAfter;
-    }
-
     private static Date toDate(long asn1time) throws ParsingException {
         Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
         calendar.set(Calendar.MILLISECOND, 0);
@@ -93,7 +86,6 @@ public final class OpenSSLX509Certificate extends X509Certificate {
 
     public static OpenSSLX509Certificate fromX509DerInputStream(InputStream is)
             throws ParsingException {
-        @SuppressWarnings("resource")
         final OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
 
         try {
@@ -120,7 +112,6 @@ public final class OpenSSLX509Certificate extends X509Certificate {
 
     public static List<OpenSSLX509Certificate> fromPkcs7DerInputStream(InputStream is)
             throws ParsingException {
-        @SuppressWarnings("resource")
         OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
 
         final long[] certRefs;
@@ -151,7 +142,6 @@ public final class OpenSSLX509Certificate extends X509Certificate {
     @android.compat.annotation.UnsupportedAppUsage
     public static OpenSSLX509Certificate fromX509PemInputStream(InputStream is)
             throws ParsingException {
-        @SuppressWarnings("resource")
         final OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
 
         try {
@@ -169,7 +159,6 @@ public final class OpenSSLX509Certificate extends X509Certificate {
 
     public static List<OpenSSLX509Certificate> fromPkcs7PemInputStream(InputStream is)
             throws ParsingException {
-        @SuppressWarnings("resource")
         OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
 
         final long[] certRefs;
@@ -252,14 +241,14 @@ public final class OpenSSLX509Certificate extends X509Certificate {
     }
 
     @Override
-    @SuppressWarnings("JdkObsolete") // Needed for API compatibility
+    @SuppressWarnings({"JdkObsolete", "JavaUtilDate"}) // Needed for API compatibility
     public void checkValidity()
             throws CertificateExpiredException, CertificateNotYetValidException {
         checkValidity(new Date());
     }
 
     @Override
-    @SuppressWarnings("JdkObsolete") // Needed for API compatibility
+    @SuppressWarnings({"JdkObsolete", "JavaUtilDate"}) // Needed for API compatibility
     public void checkValidity(Date date)
             throws CertificateExpiredException, CertificateNotYetValidException {
         if (getNotBefore().compareTo(date) > 0) {
@@ -294,11 +283,13 @@ public final class OpenSSLX509Certificate extends X509Certificate {
     }
 
     @Override
+    @SuppressWarnings({"JavaUtilDate"}) // Needed for API compatibility
     public Date getNotBefore() {
         return (Date) notBefore.clone();
     }
 
     @Override
+    @SuppressWarnings({"JavaUtilDate"}) // Needed for API compatibility
     public Date getNotAfter() {
         return (Date) notAfter.clone();
     }
@@ -578,7 +569,7 @@ public final class OpenSSLX509Certificate extends X509Certificate {
     }
 
     @Override
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("Finalize")
     protected void finalize() throws Throwable {
         try {
             long toFree = mContext;
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java
index 62f5625f..834d20eb 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/SSLParametersImpl.java
@@ -30,13 +30,13 @@ import java.util.Arrays;
 import java.util.Collection;
 import java.util.List;
 import java.util.Set;
+
 import javax.crypto.SecretKey;
 import javax.net.ssl.KeyManager;
 import javax.net.ssl.KeyManagerFactory;
 import javax.net.ssl.SNIMatcher;
 import javax.net.ssl.TrustManager;
 import javax.net.ssl.TrustManagerFactory;
-import javax.net.ssl.X509ExtendedKeyManager;
 import javax.net.ssl.X509KeyManager;
 import javax.net.ssl.X509TrustManager;
 import javax.security.auth.x500.X500Principal;
@@ -221,45 +221,45 @@ final class SSLParametersImpl implements Cloneable {
         return (SSLParametersImpl) result.clone();
     }
 
-    /**
+    /*
      * Returns the appropriate session context.
      */
     AbstractSessionContext getSessionContext() {
         return client_mode ? clientSessionContext : serverSessionContext;
     }
 
-    /**
-     * @return client session context
+    /*
+     * Returns the client session context.
      */
     ClientSessionContext getClientSessionContext() {
         return clientSessionContext;
     }
 
     /**
-     * @return X.509 key manager or {@code null} for none.
+     * Returns X.509 key manager or null for none.
      */
     X509KeyManager getX509KeyManager() {
         return x509KeyManager;
     }
 
-    /**
-     * @return Pre-Shared Key (PSK) key manager or {@code null} for none.
+    /*
+     * Returns Pre-Shared Key (PSK) key manager or null for none.
      */
     @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
     PSKKeyManager getPSKKeyManager() {
         return pskKeyManager;
     }
 
-    /**
-     * @return X.509 trust manager or {@code null} for none.
+    /*
+     * Returns X.509 trust manager or null for none.
      */
     @android.compat.annotation.UnsupportedAppUsage(maxTargetSdk = 30, trackingBug = 170729553)
     X509TrustManager getX509TrustManager() {
         return x509TrustManager;
     }
 
-    /**
-     * @return the names of enabled cipher suites
+    /*
+     * Returns the names of enabled cipher suites.
      */
     String[] getEnabledCipherSuites() {
         if (Arrays.asList(enabledProtocols).contains(NativeCrypto.SUPPORTED_PROTOCOL_TLSV1_3)) {
@@ -269,7 +269,7 @@ final class SSLParametersImpl implements Cloneable {
         return enabledCipherSuites.clone();
     }
 
-    /**
+    /*
      * Sets the enabled cipher suites after filtering through OpenSSL.
      */
     void setEnabledCipherSuites(String[] cipherSuites) {
@@ -281,16 +281,15 @@ final class SSLParametersImpl implements Cloneable {
                         NativeCrypto.SUPPORTED_TLS_1_3_CIPHER_SUITES_SET));
     }
 
-    /**
-     * @return the set of enabled protocols
+    /*
+     * Returns the set of enabled protocols.
      */
     String[] getEnabledProtocols() {
         return enabledProtocols.clone();
     }
 
-    /**
+    /*
      * Sets the list of available protocols for use in SSL connection.
-     * @throws IllegalArgumentException if {@code protocols == null}
      */
     @android.compat.annotation.UnsupportedAppUsage(maxTargetSdk = 30, trackingBug = 170729553)
     void setEnabledProtocols(String[] protocols) {
@@ -309,10 +308,8 @@ final class SSLParametersImpl implements Cloneable {
         enabledProtocols = NativeCrypto.checkEnabledProtocols(filteredProtocols).clone();
     }
 
-    /**
+    /*
      * Sets the list of ALPN protocols.
-     *
-     * @param protocols the list of ALPN protocols
      */
     void setApplicationProtocols(String[] protocols) {
         this.applicationProtocols = SSLUtils.encodeProtocols(protocols);
@@ -322,30 +319,29 @@ final class SSLParametersImpl implements Cloneable {
         return SSLUtils.decodeProtocols(applicationProtocols);
     }
 
-    /**
+    /*
      * Used for server-mode only. Sets or clears the application-provided ALPN protocol selector.
-     * If set, will override the protocol list provided by {@link #setApplicationProtocols(String[])}.
+     * If set, will override the protocol list provided by setApplicationProtocols(String[]).
      */
     void setApplicationProtocolSelector(ApplicationProtocolSelectorAdapter applicationProtocolSelector) {
         this.applicationProtocolSelector = applicationProtocolSelector;
     }
 
-    /**
+    /*
      * Returns the application protocol (ALPN) selector for this socket.
      */
     ApplicationProtocolSelectorAdapter getApplicationProtocolSelector() {
         return applicationProtocolSelector;
     }
 
-    /**
+    /*
      * Tunes the peer holding this parameters to work in client mode.
-     * @param   mode if the peer is configured to work in client mode
      */
     void setUseClientMode(boolean mode) {
         client_mode = mode;
     }
 
-    /**
+    /*
      * Returns the value indicating if the parameters configured to work
      * in client mode.
      */
@@ -353,8 +349,8 @@ final class SSLParametersImpl implements Cloneable {
         return client_mode;
     }
 
-    /**
-     * Tunes the peer holding this parameters to require client authentication
+    /*
+     * Tunes the peer holding this parameters to require client authentication.
      */
     void setNeedClientAuth(boolean need) {
         need_client_auth = need;
@@ -362,15 +358,15 @@ final class SSLParametersImpl implements Cloneable {
         want_client_auth = false;
     }
 
-    /**
+    /*
      * Returns the value indicating if the peer with this parameters tuned
-     * to require client authentication
+     * to require client authentication.
      */
     boolean getNeedClientAuth() {
         return need_client_auth;
     }
 
-    /**
+    /*
      * Tunes the peer holding this parameters to request client authentication
      */
     void setWantClientAuth(boolean want) {
@@ -379,7 +375,7 @@ final class SSLParametersImpl implements Cloneable {
         need_client_auth = false;
     }
 
-    /**
+    /*
      * Returns the value indicating if the peer with this parameters
      * tuned to request client authentication
      */
@@ -387,17 +383,17 @@ final class SSLParametersImpl implements Cloneable {
         return want_client_auth;
     }
 
-    /**
+    /*
      * Allows/disallows the peer holding this parameters to
-     * create new SSL session
+     * create new SSL session.
      */
     void setEnableSessionCreation(boolean flag) {
         enable_session_creation = flag;
     }
 
-    /**
+    /*
      * Returns the value indicating if the peer with this parameters
-     * allowed to cteate new SSL session
+     * allowed to cteate new SSL session.
      */
     boolean getEnableSessionCreation() {
         return enable_session_creation;
@@ -407,7 +403,7 @@ final class SSLParametersImpl implements Cloneable {
         this.useSessionTickets = useSessionTickets;
     }
 
-    /**
+    /*
      * Whether connections using this SSL connection should use the TLS
      * extension Server Name Indication (SNI).
      */
@@ -415,7 +411,7 @@ final class SSLParametersImpl implements Cloneable {
         useSni = flag;
     }
 
-    /**
+    /*
      * Returns whether connections using this SSL connection should use the TLS
      * extension Server Name Indication (SNI).
      */
@@ -423,21 +419,21 @@ final class SSLParametersImpl implements Cloneable {
         return useSni != null ? useSni : isSniEnabledByDefault();
     }
 
-    /**
+    /*
      * For testing only.
      */
     void setCTVerificationEnabled(boolean enabled) {
         ctVerificationEnabled = enabled;
     }
 
-    /**
+    /*
      * For testing only.
      */
     void setSCTExtension(byte[] extension) {
         sctExtension = extension;
     }
 
-    /**
+    /*
      * For testing only.
      */
     void setOCSPResponse(byte[] response) {
@@ -448,9 +444,9 @@ final class SSLParametersImpl implements Cloneable {
         return ocspResponse;
     }
 
-    /**
-     * This filters {@code obsoleteProtocol} from the list of {@code protocols}
-     * down to help with app compatibility.
+    /*
+     * Filters obsoleteProtocols from the list of protocols
+     * to help with app compatibility.
      */
     private static String[] filterFromProtocols(String[] protocols,
         List<String> obsoleteProtocols) {
@@ -458,7 +454,7 @@ final class SSLParametersImpl implements Cloneable {
             return EMPTY_STRING_ARRAY;
         }
 
-        ArrayList<String> newProtocols = new ArrayList<String>();
+        ArrayList<String> newProtocols = new ArrayList<>();
         for (String protocol : protocols) {
             if (!obsoleteProtocols.contains(protocol)) {
                 newProtocols.add(protocol);
@@ -471,7 +467,7 @@ final class SSLParametersImpl implements Cloneable {
         if (cipherSuites == null || cipherSuites.length == 0) {
             return cipherSuites;
         }
-        ArrayList<String> newCipherSuites = new ArrayList<String>(cipherSuites.length);
+        ArrayList<String> newCipherSuites = new ArrayList<>(cipherSuites.length);
         for (String cipherSuite : cipherSuites) {
             if (!toRemove.contains(cipherSuite)) {
                 newCipherSuites.add(cipherSuite);
@@ -482,7 +478,7 @@ final class SSLParametersImpl implements Cloneable {
 
     private static final String[] EMPTY_STRING_ARRAY = new String[0];
 
-    /**
+    /*
      * Returns whether Server Name Indication (SNI) is enabled by default for
      * sockets. For more information on SNI, see RFC 6066 section 3.
      */
@@ -502,11 +498,12 @@ final class SSLParametersImpl implements Cloneable {
         }
     }
 
-    /**
+    /*
      * For abstracting the X509KeyManager calls between
-     * {@link X509KeyManager#chooseClientAlias(String[], java.security.Principal[], java.net.Socket)}
+     * X509KeyManager#chooseClientAlias(String[], java.security.Principal[], java.net.Socket)
      * and
-     * {@link X509ExtendedKeyManager#chooseEngineClientAlias(String[], java.security.Principal[], javax.net.ssl.SSLEngine)}
+     * X509ExtendedKeyManager#chooseEngineClientAlias(String[], java.security.Principal[],
+     * javax.net.ssl.SSLEngine)
      */
     interface AliasChooser {
         String chooseClientAlias(X509KeyManager keyManager, X500Principal[] issuers,
@@ -515,9 +512,9 @@ final class SSLParametersImpl implements Cloneable {
         String chooseServerAlias(X509KeyManager keyManager, String keyType);
     }
 
-    /**
-     * For abstracting the {@code PSKKeyManager} calls between those taking an {@code SSLSocket} and
-     * those taking an {@code SSLEngine}.
+    /*
+     * For abstracting the PSKKeyManager calls between those taking an SSLSocket and
+     * those taking an SSLEngine.
      */
     @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
     interface PSKCallbacks {
@@ -526,9 +523,9 @@ final class SSLParametersImpl implements Cloneable {
         SecretKey getPSKKey(PSKKeyManager keyManager, String identityHint, String identity);
     }
 
-    /**
+    /*
      * Returns the clone of this object.
-     * @return the clone.
+     * TODO(prb): Shouldn't need to override this anymore.
      */
     @Override
     protected Object clone() {
@@ -573,10 +570,8 @@ final class SSLParametersImpl implements Cloneable {
         }
     }
 
-    /**
-     * Finds the first {@link X509KeyManager} element in the provided array.
-     *
-     * @return the first {@code X509KeyManager} or {@code null} if not found.
+    /*
+     * Returns the first X509KeyManager element in the provided array.
      */
     private static X509KeyManager findFirstX509KeyManager(KeyManager[] kms) {
         for (KeyManager km : kms) {
@@ -587,10 +582,8 @@ final class SSLParametersImpl implements Cloneable {
         return null;
     }
 
-    /**
-     * Finds the first {@link PSKKeyManager} element in the provided array.
-     *
-     * @return the first {@code PSKKeyManager} or {@code null} if not found.
+    /*
+     * Returns the first PSKKeyManager element in the provided array.
      */
     @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
     private static PSKKeyManager findFirstPSKKeyManager(KeyManager[] kms) {
@@ -608,8 +601,8 @@ final class SSLParametersImpl implements Cloneable {
         return null;
     }
 
-    /**
-     * Gets the default X.509 trust manager.
+    /*
+     * Returns the default X.509 trust manager.
      */
     @android.compat.annotation.UnsupportedAppUsage
     static X509TrustManager getDefaultX509TrustManager() throws KeyManagementException {
@@ -642,11 +635,8 @@ final class SSLParametersImpl implements Cloneable {
         }
     }
 
-    /**
-     * Finds the first {@link X509TrustManager} element in the provided array.
-     *
-     * @return the first {@code X509ExtendedTrustManager} or
-     *         {@code X509TrustManager} or {@code null} if not found.
+    /*
+     * Returns the first X509TrustManager element in the provided array.
      */
     private static X509TrustManager findFirstX509TrustManager(TrustManager[] tms) {
         for (TrustManager tm : tms) {
@@ -725,8 +715,8 @@ final class SSLParametersImpl implements Cloneable {
         }
     }
 
-    /**
-     * Check if SCT verification is enforced for a given hostname.
+    /*
+     * Checks whether SCT verification is enforced for a given hostname.
      */
     boolean isCTVerificationEnabled(String hostname) {
         if (hostname == null) {
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/TrustManagerImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/TrustManagerImpl.java
index 5be2d6ba..a051dade 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/TrustManagerImpl.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/TrustManagerImpl.java
@@ -61,7 +61,6 @@ import java.security.cert.PKIXRevocationChecker.Option;
 import java.security.cert.TrustAnchor;
 import java.security.cert.X509Certificate;
 import java.util.ArrayList;
-import java.util.Arrays;
 import java.util.Collection;
 import java.util.Collections;
 import java.util.Comparator;
@@ -110,7 +109,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     /**
      * The CertPinManager, which validates the chain against a host-to-pin mapping
      */
-    private CertPinManager pinManager;
+    private final CertPinManager pinManager;
 
     /**
      * The backing store for the AndroidCAStore if non-null. This will
@@ -143,7 +142,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     private final Exception err;
     private final CertificateFactory factory;
     private final CertBlocklist blocklist;
-    private LogStore ctLogStore;
+    private final LogStore ctLogStore;
     private Verifier ctVerifier;
     private Policy ctPolicy;
 
@@ -197,11 +196,9 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
                     && Platform.supportsConscryptCertStore()) {
                 rootKeyStoreLocal = keyStore;
                 trustedCertificateStoreLocal =
-                    (certStore != null) ? certStore : Platform.newDefaultCertStore();
-                acceptedIssuersLocal = null;
+                        (certStore != null) ? certStore : Platform.newDefaultCertStore();
                 trustedCertificateIndexLocal = new TrustedCertificateIndex();
             } else {
-                rootKeyStoreLocal = null;
                 trustedCertificateStoreLocal = certStore;
                 acceptedIssuersLocal = acceptedIssuers(keyStore);
                 trustedCertificateIndexLocal
@@ -253,7 +250,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
 
             // TODO remove duplicates if same cert is found in both a
             // PrivateKeyEntry and TrustedCertificateEntry
-            List<X509Certificate> trusted = new ArrayList<X509Certificate>();
+            List<X509Certificate> trusted = new ArrayList<>();
             for (Enumeration<String> en = ks.aliases(); en.hasMoreElements();) {
                 final String alias = en.nextElement();
                 final X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
@@ -261,14 +258,14 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
                     trusted.add(cert);
                 }
             }
-            return trusted.toArray(new X509Certificate[trusted.size()]);
+            return trusted.toArray(new X509Certificate[0]);
         } catch (KeyStoreException e) {
             return new X509Certificate[0];
         }
     }
 
     private static Set<TrustAnchor> trustAnchors(X509Certificate[] certs) {
-        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>(certs.length);
+        Set<TrustAnchor> trustAnchors = new HashSet<>(certs.length);
         for (X509Certificate cert : certs) {
             trustAnchors.add(new TrustAnchor(cert, null));
         }
@@ -342,9 +339,22 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
                 false);
     }
 
+    /**
+     * For compatibility with network stacks that cannot provide an SSLSession nor a
+     * Socket (e.g., Cronet).
+     */
+    @android.annotation.FlaggedApi(com.android.org.conscrypt.flags.Flags
+                                           .FLAG_CERTIFICATE_TRANSPARENCY_CHECKSERVERTRUSTED_API)
+    @libcore.api.CorePlatformApi(status = libcore.api.CorePlatformApi.Status.STABLE)
+    public List<X509Certificate>
+    checkServerTrusted(X509Certificate[] chain, byte[] ocspData, byte[] tlsSctData, String authType,
+            String hostname) throws CertificateException {
+        return checkTrusted(chain, ocspData, tlsSctData, authType, hostname, false);
+    }
+
     /**
      * Returns the full trusted certificate chain found from {@code certs}.
-     *
+     * <p>
      * Throws {@link CertificateException} when no trusted chain can be found from {@code certs}.
      */
     @libcore.api.CorePlatformApi(status = libcore.api.CorePlatformApi.Status.STABLE)
@@ -362,7 +372,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
 
     /**
      * Returns the full trusted certificate chain found from {@code certs}.
-     *
+     * <p>
      * Throws {@link CertificateException} when no trusted chain can be found from {@code certs}.
      */
     @libcore.api.CorePlatformApi(status = libcore.api.CorePlatformApi.Status.STABLE)
@@ -488,15 +498,15 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     private List<X509Certificate> checkTrusted(X509Certificate[] certs, byte[] ocspData,
             byte[] tlsSctData, String authType, String host, boolean clientAuth)
             throws CertificateException {
-        if (certs == null || certs.length == 0 || authType == null || authType.length() == 0) {
+        if (certs == null || certs.length == 0 || authType == null || authType.isEmpty()) {
             throw new IllegalArgumentException("null or zero-length parameter");
         }
         if (err != null) {
             throw new CertificateException(err);
         }
-        Set<X509Certificate> used = new HashSet<X509Certificate>();
-        ArrayList<X509Certificate> untrustedChain = new ArrayList<X509Certificate>();
-        ArrayList<TrustAnchor> trustedChain = new ArrayList<TrustAnchor>();
+        Set<X509Certificate> used = new HashSet<>();
+        List<X509Certificate> untrustedChain = new ArrayList<>();
+        List<TrustAnchor> trustedChain = new ArrayList<>();
         // Initialize the chain to contain the leaf certificate. This potentially could be a trust
         // anchor. If the leaf is a trust anchor we still continue with path building to build the
         // complete trusted chain for additional validation such as certificate pinning.
@@ -516,7 +526,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
     /**
      * Recursively build certificate chains until a valid chain is found or all possible paths are
      * exhausted.
-     *
+     * <p>
      * The chain is built in two sections, the complete trusted path is the the combination of
      * {@code untrustedChain} and {@code trustAnchorChain}. The chain begins at the leaf
      * certificate and ends in the final trusted root certificate.
@@ -538,7 +548,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
      */
     private List<X509Certificate> checkTrustedRecursive(X509Certificate[] certs, byte[] ocspData,
             byte[] tlsSctData, String host, boolean clientAuth,
-            ArrayList<X509Certificate> untrustedChain, ArrayList<TrustAnchor> trustAnchorChain,
+            List<X509Certificate> untrustedChain, List<TrustAnchor> trustAnchorChain,
             Set<X509Certificate> used) throws CertificateException {
         CertificateException lastException = null;
         X509Certificate current;
@@ -680,8 +690,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
                         "Trust anchor for certification path not found.", null, certPath, -1));
             }
 
-            List<X509Certificate> wholeChain = new ArrayList<X509Certificate>();
-            wholeChain.addAll(untrustedChain);
+            List<X509Certificate> wholeChain = new ArrayList<>(untrustedChain);
             for (TrustAnchor anchor : trustAnchorChain) {
                 wholeChain.add(anchor.getTrustedCert());
             }
@@ -710,7 +719,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
 
             // Validate the untrusted part of the chain
             try {
-                Set<TrustAnchor> anchorSet = new HashSet<TrustAnchor>();
+                Set<TrustAnchor> anchorSet = new HashSet<>();
                 // We know that untrusted chains to the first trust anchor, only add that.
                 anchorSet.add(trustAnchorChain.get(0));
                 PKIXParameters params = new PKIXParameters(anchorSet);
@@ -773,8 +782,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         }
 
         PKIXRevocationChecker revChecker = null;
-        List<PKIXCertPathChecker> checkers =
-                new ArrayList<PKIXCertPathChecker>(params.getCertPathCheckers());
+        List<PKIXCertPathChecker> checkers = new ArrayList<>(params.getCertPathCheckers());
         for (PKIXCertPathChecker checker : checkers) {
             if (checker instanceof PKIXRevocationChecker) {
                 revChecker = (PKIXRevocationChecker) checker;
@@ -815,7 +823,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         if (anchors.size() <= 1) {
             return anchors;
         }
-        List<TrustAnchor> sortedAnchors = new ArrayList<TrustAnchor>(anchors);
+        List<TrustAnchor> sortedAnchors = new ArrayList<>(anchors);
         Collections.sort(sortedAnchors, TRUST_ANCHOR_COMPARATOR);
         return sortedAnchors;
     }
@@ -859,8 +867,8 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         private static final String EKU_nsSGC = "2.16.840.1.113730.4.1";
         private static final String EKU_msSGC = "1.3.6.1.4.1.311.10.3.3";
 
-        private static final Set<String> SUPPORTED_EXTENSIONS
-                = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(EKU_OID)));
+        private static final Set<String> SUPPORTED_EXTENSIONS =
+                Collections.unmodifiableSet(new HashSet<>(Collections.singletonList(EKU_OID)));
 
         private final boolean clientAuth;
         private final X509Certificate leaf;
@@ -871,8 +879,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         }
 
         @Override
-        public void init(boolean forward) throws CertPathValidatorException {
-        }
+        public void init(boolean forward) {}
 
         @Override
         public boolean isForwardCheckingSupported() {
@@ -958,7 +965,7 @@ public final class TrustManagerImpl extends X509ExtendedTrustManager {
         if (storeAnchors.isEmpty()) {
             return indexedAnchors;
         }
-        Set<TrustAnchor> result = new HashSet<TrustAnchor>(storeAnchors.size());
+        Set<TrustAnchor> result = new HashSet<>(storeAnchors.size());
         for (X509Certificate storeCert : storeAnchors) {
             result.add(trustedCertificateIndex.index(storeCert));
         }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateEntry.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateEntry.java
index ac889236..af6b7d2d 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateEntry.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/CertificateEntry.java
@@ -47,8 +47,17 @@ public class CertificateEntry {
      * @hide This class is not part of the Android public SDK API
      */
     public enum LogEntryType {
-        X509_ENTRY,
-        PRECERT_ENTRY
+        X509_ENTRY(0),
+        PRECERT_ENTRY(1);
+        private final int value;
+
+        LogEntryType(int value) {
+            this.value = value;
+        }
+
+        int value() {
+            return value;
+        }
     }
 
     private final LogEntryType entryType;
@@ -129,7 +138,7 @@ public class CertificateEntry {
      * TLS encode the CertificateEntry structure.
      */
     public void encode(OutputStream output) throws SerializationException {
-        Serialization.writeNumber(output, entryType.ordinal(), Constants.LOG_ENTRY_TYPE_LENGTH);
+        Serialization.writeNumber(output, entryType.value(), Constants.LOG_ENTRY_TYPE_LENGTH);
         if (entryType == LogEntryType.PRECERT_ENTRY) {
             Serialization.writeFixedBytes(output, issuerKeyHash);
         }
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogStore.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogStore.java
index 0e5d0e8a..7baeb251 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogStore.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/LogStore.java
@@ -40,6 +40,14 @@ public interface LogStore {
 
     State getState();
 
+    int getMajorVersion();
+
+    int getMinorVersion();
+
+    int getCompatVersion();
+
+    int getMinCompatVersionAvailable();
+
     long getTimestamp();
 
     LogInfo getKnownLog(byte[] logId);
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/SignedCertificateTimestamp.java b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/SignedCertificateTimestamp.java
index ae312c99..d9864572 100644
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/ct/SignedCertificateTimestamp.java
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/ct/SignedCertificateTimestamp.java
@@ -33,25 +33,40 @@ public class SignedCertificateTimestamp {
      * @hide This class is not part of the Android public SDK API
      */
     public enum Version {
-        V1
-    };
+        V1(0);
+
+        private final int value;
+
+        Version(int value) {
+            this.value = value;
+        }
+
+        int value() {
+            return value;
+        }
+    }
 
     /**
      * @hide This class is not part of the Android public SDK API
      */
     public enum SignatureType {
-        CERTIFICATE_TIMESTAMP,
-        TREE_HASH
-    };
+        CERTIFICATE_TIMESTAMP(0),
+        TREE_HASH(1);
+        private final int value;
+
+        SignatureType(int value) {
+            this.value = value;
+        }
+
+        int value() {
+            return value;
+        }
+    }
 
     /**
      * @hide This class is not part of the Android public SDK API
      */
-    public enum Origin {
-        EMBEDDED,
-        TLS_EXTENSION,
-        OCSP_RESPONSE
-    };
+    public enum Origin { EMBEDDED, TLS_EXTENSION, OCSP_RESPONSE }
 
     private final Version version;
     private final byte[] logId;
@@ -99,7 +114,7 @@ public class SignedCertificateTimestamp {
     public static SignedCertificateTimestamp decode(InputStream input, Origin origin)
             throws SerializationException {
         int version = Serialization.readNumber(input, Constants.VERSION_LENGTH);
-        if (version != Version.V1.ordinal()) {
+        if (version != Version.V1.value()) {
             throw new SerializationException("Unsupported SCT version " + version);
         }
 
@@ -123,8 +138,8 @@ public class SignedCertificateTimestamp {
      */
     public void encodeTBS(OutputStream output, CertificateEntry certEntry)
             throws SerializationException {
-        Serialization.writeNumber(output, version.ordinal(), Constants.VERSION_LENGTH);
-        Serialization.writeNumber(output, SignatureType.CERTIFICATE_TIMESTAMP.ordinal(),
+        Serialization.writeNumber(output, version.value(), Constants.VERSION_LENGTH);
+        Serialization.writeNumber(output, SignatureType.CERTIFICATE_TIMESTAMP.value(),
                 Constants.SIGNATURE_TYPE_LENGTH);
         Serialization.writeNumber(output, timestamp, Constants.TIMESTAMP_LENGTH);
         certEntry.encode(output);
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ConscryptStatsLog.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ConscryptStatsLog.java
deleted file mode 100644
index 8a7a8e55..00000000
--- a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/ConscryptStatsLog.java
+++ /dev/null
@@ -1,49 +0,0 @@
-/* GENERATED SOURCE. DO NOT MODIFY. */
-/*
- * Copyright (C) 2020 The Android Open Source Project
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
-package com.android.org.conscrypt.metrics;
-
-import com.android.org.conscrypt.Internal;
-
-/**
- * Reimplement with reflection calls the logging class,
- * generated by frameworks/statsd.
- * <p>
- * In case atom is changed, generate new wrapper with stats-log-api-gen
- * tool as shown below and add corresponding methods to ReflexiveStatsEvent's
- * newEvent() method.
- * <p>
- * $ stats-log-api-gen \
- *   --java "common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java" \
- *   --module conscrypt \
- *   --javaPackage org.conscrypt.metrics \
- *   --javaClass ConscryptStatsLog
- * @hide This class is not part of the Android public SDK API
- **/
-@Internal
-public final class ConscryptStatsLog {
-    public static final int TLS_HANDSHAKE_REPORTED = 317;
-
-    private ConscryptStatsLog() {}
-
-    public static void write(int atomId, boolean success, int protocol, int cipherSuite,
-            int duration, Source source, int[] uids) {
-        ReflexiveStatsEvent event = ReflexiveStatsEvent.buildEvent(
-                atomId, success, protocol, cipherSuite, duration, source.ordinal(), uids);
-
-        ReflexiveStatsLog.write(event);
-    }
-}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLog.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLog.java
new file mode 100644
index 00000000..8a29a1be
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLog.java
@@ -0,0 +1,31 @@
+/* GENERATED SOURCE. DO NOT MODIFY. */
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
+package com.android.org.conscrypt.metrics;
+
+import com.android.org.conscrypt.Internal;
+import com.android.org.conscrypt.ct.LogStore;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+public interface StatsLog {
+    public void countTlsHandshake(
+            boolean success, String protocol, String cipherSuite, long duration);
+
+    public void updateCTLogListStatusChanged(LogStore logStore);
+}
diff --git a/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLogImpl.java b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLogImpl.java
new file mode 100644
index 00000000..a4557bad
--- /dev/null
+++ b/repackaged/common/src/main/java/com/android/org/conscrypt/metrics/StatsLogImpl.java
@@ -0,0 +1,157 @@
+/* GENERATED SOURCE. DO NOT MODIFY. */
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+package com.android.org.conscrypt.metrics;
+
+import com.android.org.conscrypt.Internal;
+import com.android.org.conscrypt.Platform;
+import com.android.org.conscrypt.ct.LogStore;
+
+import java.lang.Thread.UncaughtExceptionHandler;
+import java.util.concurrent.ArrayBlockingQueue;
+import java.util.concurrent.ExecutorService;
+import java.util.concurrent.Executors;
+import java.util.concurrent.ThreadFactory;
+import java.util.concurrent.ThreadPoolExecutor;
+import java.util.concurrent.TimeUnit;
+
+/**
+ * Reimplement with reflection calls the logging class,
+ * generated by frameworks/statsd.
+ * <p>
+ * In case atom is changed, generate new wrapper with stats-log-api-gen
+ * tool as shown below and add corresponding methods to ReflexiveStatsEvent's
+ * newEvent() method.
+ * <p>
+ * $ stats-log-api-gen \
+ *   --java "common/src/main/java/org/conscrypt/metrics/ConscryptStatsLog.java" \
+ *   --module conscrypt \
+ *   --javaPackage org.conscrypt.metrics \
+ *   --javaClass StatsLog
+ * @hide This class is not part of the Android public SDK API
+ **/
+@Internal
+public final class StatsLogImpl implements StatsLog {
+    /**
+     * TlsHandshakeReported tls_handshake_reported
+     * Usage: StatsLog.write(StatsLog.TLS_HANDSHAKE_REPORTED, boolean success, int protocol, int
+     * cipher_suite, int handshake_duration_millis, int source, int[] uid);<br>
+     */
+    public static final int TLS_HANDSHAKE_REPORTED = 317;
+
+    /**
+     * CertificateTransparencyLogListStateChanged certificate_transparency_log_list_state_changed
+     * Usage: StatsLog.write(StatsLog.CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED, int status,
+     * int loaded_compat_version, int min_compat_version_available, int major_version, int
+     * minor_version);<br>
+     */
+    public static final int CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED = 934;
+
+    private static final ExecutorService e = Executors.newSingleThreadExecutor(new ThreadFactory() {
+        @Override
+        public Thread newThread(Runnable r) {
+            Thread thread = new Thread(r);
+            thread.setUncaughtExceptionHandler(new UncaughtExceptionHandler() {
+                @Override
+                public void uncaughtException(Thread t, Throwable e) {
+                    // Ignore
+                }
+            });
+            return thread;
+        }
+    });
+
+    private static final StatsLog INSTANCE = new StatsLogImpl();
+    private StatsLogImpl() {}
+    public static StatsLog getInstance() {
+        return INSTANCE;
+    }
+
+    @Override
+    public void countTlsHandshake(
+            boolean success, String protocol, String cipherSuite, long duration) {
+        Protocol proto = Protocol.forName(protocol);
+        CipherSuite suite = CipherSuite.forName(cipherSuite);
+
+        write(TLS_HANDSHAKE_REPORTED, success, proto.getId(), suite.getId(), (int) duration,
+                Platform.getStatsSource().ordinal(), Platform.getUids());
+    }
+
+    private static int logStoreStateToMetricsState(LogStore.State state) {
+        /* These constants must match the atom LogListStatus
+         * from frameworks/proto_logging/stats/atoms/conscrypt/conscrypt_extension_atoms.proto
+         */
+        final int METRIC_UNKNOWN = 0;
+        final int METRIC_SUCCESS = 1;
+        final int METRIC_NOT_FOUND = 2;
+        final int METRIC_PARSING_FAILED = 3;
+        final int METRIC_EXPIRED = 4;
+
+        switch (state) {
+            case UNINITIALIZED:
+            case LOADED:
+                return METRIC_UNKNOWN;
+            case NOT_FOUND:
+                return METRIC_NOT_FOUND;
+            case MALFORMED:
+                return METRIC_PARSING_FAILED;
+            case COMPLIANT:
+                return METRIC_SUCCESS;
+            case NON_COMPLIANT:
+                return METRIC_EXPIRED;
+        }
+        return METRIC_UNKNOWN;
+    }
+
+    @Override
+    public void updateCTLogListStatusChanged(LogStore logStore) {
+        int state = logStoreStateToMetricsState(logStore.getState());
+        write(CERTIFICATE_TRANSPARENCY_LOG_LIST_STATE_CHANGED, state, logStore.getCompatVersion(),
+                logStore.getMinCompatVersionAvailable(), logStore.getMajorVersion(),
+                logStore.getMinorVersion());
+    }
+
+    private void write(int atomId, boolean success, int protocol, int cipherSuite, int duration,
+            int source, int[] uids) {
+        e.execute(new Runnable() {
+            @Override
+            public void run() {
+                ReflexiveStatsEvent event = ReflexiveStatsEvent.buildEvent(
+                        atomId, success, protocol, cipherSuite, duration, source, uids);
+
+                ReflexiveStatsLog.write(event);
+            }
+        });
+    }
+
+    private void write(int atomId, int status, int loadedCompatVersion,
+            int minCompatVersionAvailable, int majorVersion, int minorVersion) {
+        e.execute(new Runnable() {
+            @Override
+            public void run() {
+                ReflexiveStatsEvent.Builder builder = ReflexiveStatsEvent.newBuilder();
+                builder.setAtomId(atomId);
+                builder.writeInt(status);
+                builder.writeInt(loadedCompatVersion);
+                builder.writeInt(minCompatVersionAvailable);
+                builder.writeInt(majorVersion);
+                builder.writeInt(minorVersion);
+                builder.usePooledBuffer();
+                ReflexiveStatsLog.write(builder.build());
+            }
+        });
+    }
+}
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/ChainStrengthAnalyzerTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/ChainStrengthAnalyzerTest.java
index fe968b90..bc4c07ee 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/ChainStrengthAnalyzerTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/ChainStrengthAnalyzerTest.java
@@ -19,15 +19,17 @@ package com.android.org.conscrypt;
 
 import static org.junit.Assert.fail;
 
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.ByteArrayInputStream;
 import java.io.InputStream;
+import java.nio.charset.StandardCharsets;
 import java.security.NoSuchAlgorithmException;
 import java.security.cert.CertificateException;
 import java.security.cert.CertificateFactory;
 import java.security.cert.X509Certificate;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
 /**
  * @hide This class is not part of the Android public SDK API
@@ -365,7 +367,7 @@ public class ChainStrengthAnalyzerTest {
 
     private static X509Certificate createCert(String pem) throws Exception {
         CertificateFactory cf = CertificateFactory.getInstance("X509");
-        InputStream pemInput = new ByteArrayInputStream(pem.getBytes("UTF-8"));
+        InputStream pemInput = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8));
         return (X509Certificate) cf.generateCertificate(pemInput);
     }
 }
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/ct/VerifierTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/ct/VerifierTest.java
index 9e4df89d..0fc1dda7 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/ct/VerifierTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/ct/VerifierTest.java
@@ -76,6 +76,26 @@ public class VerifierTest {
                 return 0;
             }
 
+            @Override
+            public int getMajorVersion() {
+                return 1;
+            }
+
+            @Override
+            public int getMinorVersion() {
+                return 2;
+            }
+
+            @Override
+            public int getCompatVersion() {
+                return 1;
+            }
+
+            @Override
+            public int getMinCompatVersionAvailable() {
+                return 1;
+            }
+
             @Override
             public LogInfo getKnownLog(byte[] logId) {
                 if (Arrays.equals(logId, log.getID())) {
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyPairGeneratorTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyPairGeneratorTest.java
index ede2f5a4..309256ad 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyPairGeneratorTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/KeyPairGeneratorTest.java
@@ -137,19 +137,14 @@ public class KeyPairGeneratorTest {
             });
     }
 
-    private static final Map<String, List<Integer>> KEY_SIZES
-            = new HashMap<String, List<Integer>>();
+    private static final Map<String, List<Integer>> KEY_SIZES = new HashMap<>();
     private static void putKeySize(String algorithm, int keySize) {
-        algorithm = algorithm.toUpperCase();
-        List<Integer> keySizes = KEY_SIZES.get(algorithm);
-        if (keySizes == null) {
-            keySizes = new ArrayList<Integer>();
-            KEY_SIZES.put(algorithm, keySizes);
-        }
+        algorithm = algorithm.toUpperCase(Locale.ROOT);
+        List<Integer> keySizes = KEY_SIZES.computeIfAbsent(algorithm, k -> new ArrayList<>());
         keySizes.add(keySize);
     }
     private static List<Integer> getKeySizes(String algorithm) throws Exception {
-        algorithm = algorithm.toUpperCase();
+        algorithm = algorithm.toUpperCase(Locale.ROOT);
         List<Integer> keySizes = KEY_SIZES.get(algorithm);
         if (keySizes == null) {
             throw new Exception("Unknown key sizes for KeyPairGenerator." + algorithm);
@@ -212,7 +207,7 @@ public class KeyPairGeneratorTest {
             test_KeyPair(kpg, kpg.genKeyPair());
             test_KeyPair(kpg, kpg.generateKeyPair());
 
-            kpg.initialize(keySize, (SecureRandom) null);
+            kpg.initialize(keySize, null);
             test_KeyPair(kpg, kpg.genKeyPair());
             test_KeyPair(kpg, kpg.generateKeyPair());
 
@@ -233,7 +228,7 @@ public class KeyPairGeneratorTest {
                 test_KeyPair(kpg, kpg.genKeyPair());
                 test_KeyPair(kpg, kpg.generateKeyPair());
 
-                kpg.initialize(new ECGenParameterSpec(curveName), (SecureRandom) null);
+                kpg.initialize(new ECGenParameterSpec(curveName), null);
                 test_KeyPair(kpg, kpg.genKeyPair());
                 test_KeyPair(kpg, kpg.generateKeyPair());
 
@@ -255,7 +250,7 @@ public class KeyPairGeneratorTest {
         if (StandardNames.IS_RI && expectedAlgorithm.equals("DIFFIEHELLMAN")) {
             expectedAlgorithm = "DH";
         }
-        assertEquals(expectedAlgorithm, k.getAlgorithm().toUpperCase());
+        assertEquals(expectedAlgorithm, k.getAlgorithm().toUpperCase(Locale.ROOT));
         if (expectedAlgorithm.equals("DH")) {
             if (k instanceof DHPublicKey) {
                 DHPublicKey dhPub = (DHPublicKey) k;
@@ -383,7 +378,7 @@ public class KeyPairGeneratorTest {
     /**
      * DH parameters pre-generated so that the test doesn't take too long.
      * These parameters were generated with:
-     *
+     * <p>
      * openssl gendh 512 | openssl dhparams -C
      */
     private static DHParameterSpec getDHParams() {
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/MessageDigestTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/MessageDigestTest.java
index 36f7b680..6e8ba81e 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/MessageDigestTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/MessageDigestTest.java
@@ -31,9 +31,9 @@ import org.junit.runners.JUnit4;
 
 import java.security.MessageDigest;
 import java.security.NoSuchAlgorithmException;
-import java.security.Provider;
 import java.util.Arrays;
 import java.util.HashMap;
+import java.util.Locale;
 import java.util.Map;
 
 import tests.util.ServiceTester;
@@ -67,43 +67,36 @@ public final class MessageDigestTest {
     }
 
     @Test
-    public void test_getInstance() throws Exception {
-        ServiceTester.test("MessageDigest").run(new ServiceTester.Test() {
-            @Override
-            public void test(Provider provider, String algorithm) throws Exception {
-                // MessageDigest.getInstance(String)
-                MessageDigest md1 = MessageDigest.getInstance(algorithm);
-                assertEquals(algorithm, md1.getAlgorithm());
-                test_MessageDigest(md1);
+    public void test_getInstance() {
+        ServiceTester.test("MessageDigest").run((provider, algorithm) -> {
+            // MessageDigest.getInstance(String)
+            MessageDigest md1 = MessageDigest.getInstance(algorithm);
+            assertEquals(algorithm, md1.getAlgorithm());
+            test_MessageDigest(md1);
 
-                // MessageDigest.getInstance(String, Provider)
-                MessageDigest md2 = MessageDigest.getInstance(algorithm, provider);
-                assertEquals(algorithm, md2.getAlgorithm());
-                assertEquals(provider, md2.getProvider());
-                test_MessageDigest(md2);
+            // MessageDigest.getInstance(String, Provider)
+            MessageDigest md2 = MessageDigest.getInstance(algorithm, provider);
+            assertEquals(algorithm, md2.getAlgorithm());
+            assertEquals(provider, md2.getProvider());
+            test_MessageDigest(md2);
 
-                // MessageDigest.getInstance(String, String)
-                MessageDigest md3 = MessageDigest.getInstance(algorithm, provider.getName());
-                assertEquals(algorithm, md3.getAlgorithm());
-                assertEquals(provider, md3.getProvider());
-                test_MessageDigest(md3);
-            }
+            // MessageDigest.getInstance(String, String)
+            MessageDigest md3 = MessageDigest.getInstance(algorithm, provider.getName());
+            assertEquals(algorithm, md3.getAlgorithm());
+            assertEquals(provider, md3.getProvider());
+            test_MessageDigest(md3);
         });
     }
 
-    private static final Map<String, Map<String, byte[]>> EXPECTATIONS
-            = new HashMap<String, Map<String, byte[]>>();
+    private static final Map<String, Map<String, byte[]>> EXPECTATIONS = new HashMap<>();
     private static void putExpectation(String algorithm, String inputName, byte[] expected) {
-        algorithm = algorithm.toUpperCase();
-        Map<String, byte[]> expectations = EXPECTATIONS.get(algorithm);
-        if (expectations == null) {
-            expectations = new HashMap<String, byte[]>();
-            EXPECTATIONS.put(algorithm, expectations);
-        }
+        algorithm = algorithm.toUpperCase(Locale.ROOT);
+        Map<String, byte[]> expectations =
+                EXPECTATIONS.computeIfAbsent(algorithm, k -> new HashMap<>());
         expectations.put(inputName, expected);
     }
     private static Map<String, byte[]> getExpectations(String algorithm) throws Exception {
-        algorithm = algorithm.toUpperCase();
+        algorithm = algorithm.toUpperCase(Locale.ROOT);
         Map<String, byte[]> expectations = EXPECTATIONS.get(algorithm);
         if (expectations == null) {
             throw new Exception("No expectations for MessageDigest." + algorithm);
@@ -258,7 +251,7 @@ public final class MessageDigestTest {
             if (inputName.equals(INPUT_EMPTY)) {
                 actual = md.digest();
             } else if (inputName.equals(INPUT_256MB)) {
-                byte[] mb = new byte[1 * 1024 * 1024];
+                byte[] mb = new byte[1024 * 1024];
                 for (int i = 0; i < 256; i++) {
                     md.update(mb);
                 }
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/SignatureTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/SignatureTest.java
index 6e12df1b..9797cf4f 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/SignatureTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/SignatureTest.java
@@ -40,6 +40,7 @@ import org.junit.runners.JUnit4;
 import java.math.BigInteger;
 import java.nio.ByteBuffer;
 import java.nio.charset.Charset;
+import java.nio.charset.StandardCharsets;
 import java.security.AlgorithmParameters;
 import java.security.InvalidKeyException;
 import java.security.KeyFactory;
@@ -47,7 +48,6 @@ import java.security.KeyPair;
 import java.security.KeyPairGenerator;
 import java.security.MessageDigest;
 import java.security.PrivateKey;
-import java.security.Provider;
 import java.security.ProviderException;
 import java.security.PublicKey;
 import java.security.Security;
@@ -70,12 +70,10 @@ import java.security.spec.RSAPrivateKeySpec;
 import java.security.spec.RSAPublicKeySpec;
 import java.security.spec.X509EncodedKeySpec;
 import java.util.ArrayList;
-import java.util.Arrays;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Locale;
 import java.util.Map;
-import java.util.concurrent.Callable;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.ExecutionException;
 import java.util.concurrent.ExecutorService;
@@ -125,38 +123,34 @@ public class SignatureTest {
                 .skipAlgorithm("Ed25519")
                 .skipAlgorithm("EdDSA")
                 .skipAlgorithm("HSS/LMS")
-                .run(new ServiceTester.Test() {
-                    @Override
-                    public void test(Provider provider, String algorithm) throws Exception {
-                        KeyPair kp = keyPair(algorithm);
-                        // Signature.getInstance(String)
-                        Signature sig1 = Signature.getInstance(algorithm);
-                        assertEquals(algorithm, sig1.getAlgorithm());
-                        test_Signature(sig1, kp);
-
-                        // Signature.getInstance(String, Provider)
-                        Signature sig2 = Signature.getInstance(algorithm, provider);
-                        assertEquals(algorithm, sig2.getAlgorithm());
-                        assertEquals(provider, sig2.getProvider());
-                        test_Signature(sig2, kp);
-
-                        // Signature.getInstance(String, String)
-                        Signature sig3 = Signature.getInstance(algorithm, provider.getName());
-                        assertEquals(algorithm, sig3.getAlgorithm());
-                        assertEquals(provider, sig3.getProvider());
-                        test_Signature(sig3, kp);
-                    }
+                .run((provider, algorithm) -> {
+                    KeyPair kp = keyPair(algorithm);
+                    // Signature.getInstance(String)
+                    Signature sig1 = Signature.getInstance(algorithm);
+                    assertEquals(algorithm, sig1.getAlgorithm());
+                    test_Signature(sig1, kp);
+
+                    // Signature.getInstance(String, Provider)
+                    Signature sig2 = Signature.getInstance(algorithm, provider);
+                    assertEquals(algorithm, sig2.getAlgorithm());
+                    assertEquals(provider, sig2.getProvider());
+                    test_Signature(sig2, kp);
+
+                    // Signature.getInstance(String, String)
+                    Signature sig3 = Signature.getInstance(algorithm, provider.getName());
+                    assertEquals(algorithm, sig3.getAlgorithm());
+                    assertEquals(provider, sig3.getProvider());
+                    test_Signature(sig3, kp);
                 });
     }
 
-    private final Map<String, KeyPair> keypairAlgorithmToInstance
-            = new HashMap<String, KeyPair>();
+    private final Map<String, KeyPair> keypairAlgorithmToInstance = new HashMap<>();
 
     private KeyPair keyPair(String sigAlgorithm) throws Exception {
-        String sigAlgorithmUpperCase = sigAlgorithm.toUpperCase(Locale.US);
+        String sigAlgorithmUpperCase = sigAlgorithm.toUpperCase(Locale.ROOT);
         if (sigAlgorithmUpperCase.endsWith("ENCRYPTION")) {
             sigAlgorithm = sigAlgorithm.substring(0, sigAlgorithm.length()-"ENCRYPTION".length());
-            sigAlgorithmUpperCase = sigAlgorithm.toUpperCase(Locale.US);
+            sigAlgorithmUpperCase = sigAlgorithm.toUpperCase(Locale.ROOT);
         }
 
         String kpAlgorithm;
@@ -229,6 +223,7 @@ public class SignatureTest {
                 sig.verify(signature);
                 fail("Expected RI to have a NONEwithDSA bug");
             } catch (SignatureException bug) {
+                // Expected
             }
         } else if (StandardNames.IS_RI
                 && "NONEwithECDSA".equalsIgnoreCase(sig.getAlgorithm())
@@ -238,6 +233,7 @@ public class SignatureTest {
                 sig.verify(signature);
                 fail("Expected RI to have a NONEwithECDSA bug");
             } catch (ProviderException bug) {
+                // Expected
             }
         } else {
             // Calling Signature.verify a second time should not throw
@@ -277,11 +273,10 @@ public class SignatureTest {
             + "34fdadc44326b9b3f3fa828652bab07f0362ac141c8c3784ebdec44e0b156a5e7bccdc81a56fe954"
             + "56ac8c0e4ae12d97");
 
-
-    /**
+    /*
      * This should actually fail because the ASN.1 encoding is incorrect. It is
      * missing the NULL in the AlgorithmIdentifier field.
-     * <p>
+     *
      * http://code.google.com/p/android/issues/detail?id=18566 <br/>
      * http://b/5038554
      */
@@ -1964,8 +1959,8 @@ public class SignatureTest {
 
         byte[] signature = sig.sign();
         assertNotNull("Signature must not be null", signature);
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, SHA1withRSA_Vector1Signature));
+        assertArrayEquals(
+                "Signature should match expected", signature, SHA1withRSA_Vector1Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -1985,9 +1980,7 @@ public class SignatureTest {
         final PrivateKey privKey;
         try {
             privKey = kf.generatePrivate(keySpec);
-        } catch (NullPointerException e) {
-            return;
-        } catch (InvalidKeySpecException e) {
+        } catch (NullPointerException | InvalidKeySpecException e) {
             return;
         }
 
@@ -2010,9 +2003,7 @@ public class SignatureTest {
         final PrivateKey privKey;
         try {
             privKey = kf.generatePrivate(keySpec);
-        } catch (NullPointerException e) {
-            return;
-        } catch (InvalidKeySpecException e) {
+        } catch (NullPointerException | InvalidKeySpecException e) {
             return;
         }
 
@@ -2034,9 +2025,7 @@ public class SignatureTest {
         final PrivateKey privKey;
         try {
             privKey = kf.generatePrivate(keySpec);
-        } catch (NullPointerException e) {
-            return;
-        } catch (InvalidKeySpecException e) {
+        } catch (NullPointerException | InvalidKeySpecException e) {
             return;
         }
 
@@ -2216,8 +2205,8 @@ public class SignatureTest {
         assertNotNull("Signature must not be null", signature);
         assertPSSAlgorithmParametersEquals(
                 SHA1withRSAPSS_NoSalt_Vector2Signature_ParameterSpec, sig.getParameters());
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, SHA1withRSAPSS_NoSalt_Vector2Signature));
+        assertArrayEquals("Signature should match expected", signature,
+                SHA1withRSAPSS_NoSalt_Vector2Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -2295,8 +2284,8 @@ public class SignatureTest {
         assertNotNull("Signature must not be null", signature);
         assertPSSAlgorithmParametersEquals(
                 SHA224withRSAPSS_NoSalt_Vector2Signature_ParameterSpec, sig.getParameters());
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, SHA224withRSAPSS_NoSalt_Vector2Signature));
+        assertArrayEquals("Signature should match expected", signature,
+                SHA224withRSAPSS_NoSalt_Vector2Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -2374,8 +2363,8 @@ public class SignatureTest {
         assertNotNull("Signature must not be null", signature);
         assertPSSAlgorithmParametersEquals(
                 SHA256withRSAPSS_NoSalt_Vector2Signature_ParameterSpec, sig.getParameters());
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, SHA256withRSAPSS_NoSalt_Vector2Signature));
+        assertArrayEquals("Signature should match expected", signature,
+                SHA256withRSAPSS_NoSalt_Vector2Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -2453,8 +2442,8 @@ public class SignatureTest {
         assertNotNull("Signature must not be null", signature);
         assertPSSAlgorithmParametersEquals(
                 SHA384withRSAPSS_NoSalt_Vector2Signature_ParameterSpec, sig.getParameters());
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, SHA384withRSAPSS_NoSalt_Vector2Signature));
+        assertArrayEquals("Signature should match expected", signature,
+                SHA384withRSAPSS_NoSalt_Vector2Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -2532,8 +2521,8 @@ public class SignatureTest {
         assertNotNull("Signature must not be null", signature);
         assertPSSAlgorithmParametersEquals(
                 SHA512withRSAPSS_NoSalt_Vector2Signature_ParameterSpec, sig.getParameters());
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, SHA512withRSAPSS_NoSalt_Vector2Signature));
+        assertArrayEquals("Signature should match expected", signature,
+                SHA512withRSAPSS_NoSalt_Vector2Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -2584,8 +2573,8 @@ public class SignatureTest {
 
         byte[] signature = sig.sign();
         assertNotNull("Signature must not be null", signature);
-        assertTrue("Signature should match expected",
-                Arrays.equals(signature, NONEwithRSA_Vector1Signature));
+        assertArrayEquals(
+                "Signature should match expected", signature, NONEwithRSA_Vector1Signature);
 
         RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(RSA_2048_modulus,
                 RSA_2048_publicExponent);
@@ -2607,7 +2596,7 @@ public class SignatureTest {
         sig.initVerify(pubKey);
         sig.update(Vector1Data);
         assertFalse("Invalid signature must not verify",
-                sig.verify("Invalid".getBytes("UTF-8")));
+                sig.verify("Invalid".getBytes(StandardCharsets.UTF_8)));
     }
 
     @Test
@@ -2712,7 +2701,7 @@ public class SignatureTest {
         sig.update(Vector1Data);
 
         assertFalse("Invalid signature should not verify",
-                sig.verify("Invalid sig".getBytes("UTF-8")));
+                sig.verify("Invalid sig".getBytes(StandardCharsets.UTF_8)));
     }
 
     @Test
@@ -3136,24 +3125,21 @@ public class SignatureTest {
 
         final CountDownLatch latch = new CountDownLatch(THREAD_COUNT);
         final byte[] message = new byte[64];
-        List<Future<Void>> futures = new ArrayList<Future<Void>>();
+        List<Future<Void>> futures = new ArrayList<>();
 
         for (int i = 0; i < THREAD_COUNT; i++) {
-            futures.add(es.submit(new Callable<Void>() {
-                @Override
-                public Void call() throws Exception {
-                    // Try to make sure all the threads are ready first.
-                    latch.countDown();
-                    latch.await();
-
-                    for (int j = 0; j < 100; j++) {
-                        s.initSign(p);
-                        s.update(message);
-                        s.sign();
-                    }
-
-                    return null;
+            futures.add(es.submit(() -> {
+                // Try to make sure all the threads are ready first.
+                latch.countDown();
+                latch.await();
+
+                for (int j = 0; j < 100; j++) {
+                    s.initSign(p);
+                    s.update(message);
+                    s.sign();
                 }
+
+                return null;
             }));
         }
         es.shutdown();
@@ -3206,13 +3192,13 @@ public class SignatureTest {
         ecdsaVerify.initVerify(pub);
         ecdsaVerify.update(NAMED_CURVE_VECTOR);
         boolean result = ecdsaVerify.verify(NAMED_CURVE_SIGNATURE);
-        assertEquals(true, result);
+        assertTrue(result);
 
         ecdsaVerify = Signature.getInstance("SHA1withECDSA");
         ecdsaVerify.initVerify(pub);
-        ecdsaVerify.update("Not Satoshi Nakamoto".getBytes("UTF-8"));
+        ecdsaVerify.update("Not Satoshi Nakamoto".getBytes(StandardCharsets.UTF_8));
         result = ecdsaVerify.verify(NAMED_CURVE_SIGNATURE);
-        assertEquals(false, result);
+        assertFalse(result);
     }
 
     private static void assertPSSAlgorithmParametersEquals(
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/CertificateFactoryTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/CertificateFactoryTest.java
index b0171e4a..85299edd 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/CertificateFactoryTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/CertificateFactoryTest.java
@@ -452,7 +452,7 @@ public class CertificateFactoryTest {
             // which technically doesn't satisfy the method contract, but we'll accept it
             assertTrue((c == null) && cf.getProvider().getName().equals("BC"));
         } catch (CertificateException maybeExpected) {
-            assertFalse(cf.getProvider().getName().equals("BC"));
+            assertNotEquals("BC", cf.getProvider().getName());
         }
 
         try {
@@ -461,7 +461,7 @@ public class CertificateFactoryTest {
             // which technically doesn't satisfy the method contract, but we'll accept it
             assertTrue((c == null) && cf.getProvider().getName().equals("BC"));
         } catch (CertificateException maybeExpected) {
-            assertFalse(cf.getProvider().getName().equals("BC"));
+            assertNotEquals("BC", cf.getProvider().getName());
         }
     }
 
@@ -508,7 +508,7 @@ public class CertificateFactoryTest {
 
     }
 
-    private void test_generateCertificate_InputStream_Empty(CertificateFactory cf) throws Exception {
+    private void test_generateCertificate_InputStream_Empty(CertificateFactory cf) {
         try {
             Certificate c = cf.generateCertificate(new ByteArrayInputStream(new byte[0]));
             if (!"BC".equals(cf.getProvider().getName())) {
@@ -522,8 +522,7 @@ public class CertificateFactoryTest {
         }
     }
 
-    private void test_generateCertificate_InputStream_InvalidStart_Failure(CertificateFactory cf)
-            throws Exception {
+    private void test_generateCertificate_InputStream_InvalidStart_Failure(CertificateFactory cf) {
         try {
             Certificate c = cf.generateCertificate(new ByteArrayInputStream(
                     "-----BEGIN CERTIFICATE-----".getBytes(Charset.defaultCharset())));
@@ -560,7 +559,7 @@ public class CertificateFactoryTest {
 
         private long mMarked = 0;
 
-        private InputStream mStream;
+        private final InputStream mStream;
 
         public MeasuredInputStream(InputStream is) {
             mStream = is;
@@ -671,12 +670,12 @@ public class CertificateFactoryTest {
         KeyHolder cert2 = generateCertificate(false, cert1);
         KeyHolder cert3 = generateCertificate(false, cert2);
 
-        List<X509Certificate> certs = new ArrayList<X509Certificate>();
+        List<X509Certificate> certs = new ArrayList<>();
         certs.add(cert3.certificate);
         certs.add(cert2.certificate);
         certs.add(cert1.certificate);
 
-        List<X509Certificate> duplicatedCerts = new ArrayList<X509Certificate>(certs);
+        List<X509Certificate> duplicatedCerts = new ArrayList<>(certs);
         duplicatedCerts.add(cert2.certificate);
 
         Provider[] providers = Security.getProviders("CertificateFactory.X509");
@@ -819,7 +818,7 @@ public class CertificateFactoryTest {
         public PrivateKey privateKey;
     }
 
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings({"deprecation", "JavaUtilDate"})
     private static KeyHolder generateCertificate(boolean isCa, KeyHolder issuer) throws Exception {
         Date startDate = new Date();
 
@@ -837,7 +836,7 @@ public class CertificateFactoryTest {
         PrivateKey caKey;
         if (issuer != null) {
             serial = issuer.certificate.getSerialNumber().add(BigInteger.ONE);
-            subjectPrincipal = new X500Principal("CN=Test Certificate Serial #" + serial.toString());
+            subjectPrincipal = new X500Principal("CN=Test Certificate Serial #" + serial);
             issuerPrincipal = issuer.certificate.getSubjectX500Principal();
             caKey = issuer.privateKey;
         } else {
@@ -949,7 +948,7 @@ public class CertificateFactoryTest {
             // which technically doesn't satisfy the method contract, but we'll accept it
             assertTrue((c == null) && cf.getProvider().getName().equals("BC"));
         } catch (CRLException maybeExpected) {
-            assertFalse(cf.getProvider().getName().equals("BC"));
+            assertNotEquals("BC", cf.getProvider().getName());
         }
 
         try {
@@ -958,7 +957,7 @@ public class CertificateFactoryTest {
             // which technically doesn't satisfy the method contract, but we'll accept it
             assertTrue((c == null) && cf.getProvider().getName().equals("BC"));
         } catch (CRLException maybeExpected) {
-            assertFalse(cf.getProvider().getName().equals("BC"));
+            assertNotEquals("BC", cf.getProvider().getName());
         }
     }
 }
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CRLTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CRLTest.java
index 095abb65..1415d34b 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CRLTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CRLTest.java
@@ -44,6 +44,7 @@ import java.security.cert.X509CRL;
 import java.security.cert.X509CRLEntry;
 import java.security.cert.X509Certificate;
 import java.util.Collections;
+import java.util.Locale;
 
 import tests.util.ServiceTester;
 
@@ -145,7 +146,7 @@ public class X509CRLTest {
                     X509Certificate ca = (X509Certificate) cf.generateCertificate(
                             new ByteArrayInputStream(CA_CERT.getBytes(StandardCharsets.US_ASCII)));
 
-                    assertEquals("SHA256WITHRSA", crl.getSigAlgName().toUpperCase());
+                    assertEquals("SHA256WITHRSA", crl.getSigAlgName().toUpperCase(Locale.ROOT));
                     crl.verify(ca.getPublicKey());
                     try {
                         crl.verify(revoked.getPublicKey());
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CertificateTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CertificateTest.java
index 73b92b21..4f84bf73 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CertificateTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/java/security/cert/X509CertificateTest.java
@@ -19,7 +19,6 @@ package com.android.org.conscrypt.java.security.cert;
 
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
-import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
@@ -37,7 +36,7 @@ import org.junit.runners.JUnit4;
 
 import java.io.ByteArrayInputStream;
 import java.math.BigInteger;
-import java.nio.charset.Charset;
+import java.nio.charset.StandardCharsets;
 import java.security.InvalidKeyException;
 import java.security.NoSuchAlgorithmException;
 import java.security.Provider;
@@ -50,10 +49,10 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Calendar;
 import java.util.Collection;
-import java.util.Collections;
 import java.util.Comparator;
 import java.util.Date;
 import java.util.List;
+import java.util.Locale;
 import java.util.TimeZone;
 
 import javax.security.auth.x500.X500Principal;
@@ -217,7 +216,7 @@ public class X509CertificateTest {
             + "V9IpdAD0vhWHXcQHAiB8HnkUaiGD8Hp0aHlfFJmaaLTxy54VXuYfMlJhXnXJFA==\n"
             + "-----END CERTIFICATE-----\n";
 
-    /**
+    /*
      * This is a certificate with many extensions filled it. It exists to test accessors correctly
      * report fields. It was constructed by hand, so the signature itself is invalid. Add more
      * fields as necessary with https://github.com/google/der-ascii.
@@ -389,8 +388,8 @@ public class X509CertificateTest {
             + "0K8A7gKLY0jP8Zp+6rYBcpxc7cylWMbdlhFTHAGiKI+XeQ/9u+RPeocZsn5jGlDt\n"
             + "K3ftMoWFce+baNq/WcMzRj04AA==\n"
             + "-----END CERTIFICATE-----\n";
-    private static Date dateFromUTC(int year, int month, int day, int hour, int minute, int second)
-            throws Exception {
+    private static Date dateFromUTC(
+            int year, int month, int day, int hour, int minute, int second) {
         Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
         c.set(year, month, day, hour, minute, second);
         c.set(Calendar.MILLISECOND, 0);
@@ -401,15 +400,15 @@ public class X509CertificateTest {
             throws CertificateException {
         CertificateFactory cf = CertificateFactory.getInstance("X509", p);
         return (X509Certificate) cf.generateCertificate(
-                new ByteArrayInputStream(pem.getBytes(Charset.forName("US-ASCII"))));
+                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
     }
 
     private static List<Pair<Integer, String>> normalizeGeneralNames(Collection<List<?>> names) {
         // Extract a more convenient type than Java's Collection<List<?>>.
-        List<Pair<Integer, String>> result = new ArrayList<Pair<Integer, String>>();
+        List<Pair<Integer, String>> result = new ArrayList<>();
         for (List<?> tuple : names) {
             assertEquals(2, tuple.size());
-            int type = ((Integer) tuple.get(0)).intValue();
+            int type = (Integer) tuple.get(0);
             // TODO(davidben): Most name types are expected to have a String value, but some use
             // byte[]. Update this logic when testing those name types. See
             // X509Certificate.getSubjectAlternativeNames().
@@ -419,21 +418,13 @@ public class X509CertificateTest {
         // Although there is a natural order (the order in the certificate), Java's API returns a
         // Collection, so there is no guarantee of the provider using a particular order. Normalize
         // the order before comparing.
-        Collections.sort(result, new Comparator<Pair<Integer, String>>() {
-            @Override
-            public int compare(Pair<Integer, String> a, Pair<Integer, String> b) {
-                int cmp = a.getFirst().compareTo(b.getFirst());
-                if (cmp != 0) {
-                    return cmp;
-                }
-                return a.getSecond().compareTo(b.getSecond());
-            }
-        });
+        result.sort(Comparator.comparingInt((Pair<Integer, String> a) -> a.getFirst())
+                            .thenComparing(Pair::getSecond));
         return result;
     }
 
     private static void assertGeneralNamesEqual(
-            Collection<List<?>> expected, Collection<List<?>> actual) throws Exception {
+            Collection<List<?>> expected, Collection<List<?>> actual) {
         assertEquals(normalizeGeneralNames(expected), normalizeGeneralNames(actual));
     }
 
@@ -443,41 +434,34 @@ public class X509CertificateTest {
     //
     // https://errorprone.info/bugpattern/UndefinedEquals
     @SuppressWarnings("UndefinedEquals")
-    private static void assertDatesEqual(Date expected, Date actual) throws Exception {
+    private static void assertDatesEqual(Date expected, Date actual) {
         assertEquals(expected, actual);
     }
 
     // See issue #539.
     @Test
-    public void testMismatchedAlgorithm() throws Exception {
-        ServiceTester.test("CertificateFactory")
-            .withAlgorithm("X509")
-            .run(new ServiceTester.Test() {
-                @Override
-                public void test(Provider p, String algorithm) throws Exception {
-                    try {
-                        X509Certificate c = certificateFromPEM(p, MISMATCHED_ALGORITHM_CERT);
-                        c.verify(c.getPublicKey());
-                        fail();
-                    } catch (CertificateException expected) {
-                    }
-                }
-            });
+    public void testMismatchedAlgorithm() {
+        ServiceTester.test("CertificateFactory").withAlgorithm("X509").run((p, algorithm) -> {
+            try {
+                X509Certificate c = certificateFromPEM(p, MISMATCHED_ALGORITHM_CERT);
+                c.verify(c.getPublicKey());
+                fail();
+            } catch (CertificateException expected) {
+            }
+        });
     }
 
     /**
      * Confirm that explicit EC params aren't accepted in certificates.
      */
     @Test
-    public void testExplicitEcParams() throws Exception {
+    public void testExplicitEcParams() {
         ServiceTester.test("CertificateFactory")
-            .withAlgorithm("X509")
-            // Bouncy Castle allows explicit EC params in certificates, even though they're
-            // barred by RFC 5480
-            .skipProvider("BC")
-            .run(new ServiceTester.Test() {
-                @Override
-                public void test(Provider p, String algorithm) throws Exception {
+                .withAlgorithm("X509")
+                // Bouncy Castle allows explicit EC params in certificates, even though they're
+                // barred by RFC 5480
+                .skipProvider("BC")
+                .run((p, algorithm) -> {
                     try {
                         X509Certificate c = certificateFromPEM(p, EC_EXPLICIT_KEY_CERT);
                         c.verify(c.getPublicKey());
@@ -487,37 +471,25 @@ public class X509CertificateTest {
                         // instead of waiting for when the user accesses the key?
                     } catch (CertificateParsingException expected) {
                     }
-                }
-            });
+                });
     }
 
     @Test
-    public void testSigAlgName() throws Exception {
-        ServiceTester.test("CertificateFactory")
-            .withAlgorithm("X509")
-            .run(new ServiceTester.Test() {
-                @Override
-                public void test(Provider p, String algorithm) throws Exception {
-                    X509Certificate c = certificateFromPEM(p, VALID_CERT);
-                    assertEquals("SHA256WITHRSA", c.getSigAlgName().toUpperCase());
-                    c.verify(c.getPublicKey());
-                }
-            });
+    public void testSigAlgName() {
+        ServiceTester.test("CertificateFactory").withAlgorithm("X509").run((p, algorithm) -> {
+            X509Certificate c = certificateFromPEM(p, VALID_CERT);
+            assertEquals("SHA256WITHRSA", c.getSigAlgName().toUpperCase(Locale.ROOT));
+            c.verify(c.getPublicKey());
+        });
     }
 
     @Test
-    public void testUnknownSigAlgOID() throws Exception {
-        ServiceTester.test("CertificateFactory")
-                .withAlgorithm("X509")
-                .run(new ServiceTester.Test() {
-                    @Override
-                    public void test(Provider p, String algorithm) throws Exception {
-                        X509Certificate c = certificateFromPEM(p, UNKNOWN_SIGNATURE_OID);
-                        assertEquals("1.2.840.113554.4.1.72585.2", c.getSigAlgOID());
-                        assertThrows(
-                                NoSuchAlgorithmException.class, () -> c.verify(c.getPublicKey()));
-                    }
-                });
+    public void testUnknownSigAlgOID() {
+        ServiceTester.test("CertificateFactory").withAlgorithm("X509").run((p, algorithm) -> {
+            X509Certificate c = certificateFromPEM(p, UNKNOWN_SIGNATURE_OID);
+            assertEquals("1.2.840.113554.4.1.72585.2", c.getSigAlgOID());
+            assertThrows(NoSuchAlgorithmException.class, () -> c.verify(c.getPublicKey()));
+        });
     }
 
     // MD5 signed certificates no longer supported by BoringSSL but still supported by OpenJDK 8
@@ -528,13 +500,9 @@ public class X509CertificateTest {
                 .withAlgorithm("X509")
                 .skipProvider("SUN")
                 .skipProvider("BC")
-                .run(new ServiceTester.Test() {
-                    @Override
-                    public void test(Provider p, String algorithm) throws Exception {
-                        X509Certificate c = certificateFromPEM(p, MD5_SIGNATURE);
-                        assertThrows(
-                                NoSuchAlgorithmException.class, () -> c.verify(c.getPublicKey()));
-                    }
+                .run((p, algorithm) -> {
+                    X509Certificate c = certificateFromPEM(p, MD5_SIGNATURE);
+                    assertThrows(NoSuchAlgorithmException.class, () -> c.verify(c.getPublicKey()));
                 });
     }
 
@@ -544,234 +512,208 @@ public class X509CertificateTest {
         int index = VALID_CERT.lastIndexOf('9');
         assertTrue(index > 0);
         String invalidCert = VALID_CERT.substring(0, index) + "8" + VALID_CERT.substring(index + 1);
-        ServiceTester.test("CertificateFactory")
-                .withAlgorithm("X509")
-                .run(new ServiceTester.Test() {
-                    @Override
-                    public void test(Provider p, String algorithm) throws Exception {
-                        X509Certificate c = certificateFromPEM(p, invalidCert);
-                        assertThrows(SignatureException.class, () -> c.verify(c.getPublicKey()));
-                    }
-                });
+        ServiceTester.test("CertificateFactory").withAlgorithm("X509").run((p, algorithm) -> {
+            X509Certificate c = certificateFromPEM(p, invalidCert);
+            assertThrows(SignatureException.class, () -> c.verify(c.getPublicKey()));
+        });
     }
 
     @Test
-    public void testV1Cert() throws Exception {
+    public void testV1Cert() {
         ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
-        tester.run(new ServiceTester.Test() {
-            @Override
-            public void test(Provider p, String algorithm) throws Exception {
-                X509Certificate c = certificateFromPEM(p, X509V1_CERT);
-
-                // Check basic certificate properties.
-                assertEquals(1, c.getVersion());
-                assertEquals(new BigInteger("d94c04da497dbfeb", 16), c.getSerialNumber());
-                assertDatesEqual(
-                        dateFromUTC(2014, Calendar.APRIL, 23, 23, 21, 57), c.getNotBefore());
-                assertDatesEqual(dateFromUTC(2014, Calendar.MAY, 23, 23, 21, 57), c.getNotAfter());
-                assertEquals(new X500Principal("CN=Test Issuer"), c.getIssuerX500Principal());
-                assertEquals(new X500Principal("CN=Test Subject"), c.getSubjectX500Principal());
-                assertEquals("1.2.840.10045.4.1", c.getSigAlgOID());
-                String signatureHex = "3045022100f2a0355e513a36c382799bee27"
-                        + "50858e7006749557d2297400f4be15875dc4"
-                        + "0702207c1e79146a2183f07a7468795f1499"
-                        + "9a68b4f1cb9e155ee61f3252615e75c914";
-                assertArrayEquals(TestUtils.decodeHex(signatureHex), c.getSignature());
-
-                // ECDSA signature AlgorithmIdentifiers omit parameters.
-                assertNull(c.getSigAlgParams());
-
-                // The certificate does not have UIDs.
-                assertNull(c.getIssuerUniqueID());
-                assertNull(c.getSubjectUniqueID());
-
-                // The certificate does not have any extensions.
-                assertEquals(-1, c.getBasicConstraints());
-                assertNull(c.getExtendedKeyUsage());
-                assertNull(c.getIssuerAlternativeNames());
-                assertNull(c.getKeyUsage());
-                assertNull(c.getSubjectAlternativeNames());
-            }
+        tester.run((p, algorithm) -> {
+            X509Certificate c = certificateFromPEM(p, X509V1_CERT);
+
+            // Check basic certificate properties.
+            assertEquals(1, c.getVersion());
+            assertEquals(new BigInteger("d94c04da497dbfeb", 16), c.getSerialNumber());
+            assertDatesEqual(dateFromUTC(2014, Calendar.APRIL, 23, 23, 21, 57), c.getNotBefore());
+            assertDatesEqual(dateFromUTC(2014, Calendar.MAY, 23, 23, 21, 57), c.getNotAfter());
+            assertEquals(new X500Principal("CN=Test Issuer"), c.getIssuerX500Principal());
+            assertEquals(new X500Principal("CN=Test Subject"), c.getSubjectX500Principal());
+            assertEquals("1.2.840.10045.4.1", c.getSigAlgOID());
+            String signatureHex = "3045022100f2a0355e513a36c382799bee27"
+                    + "50858e7006749557d2297400f4be15875dc4"
+                    + "0702207c1e79146a2183f07a7468795f1499"
+                    + "9a68b4f1cb9e155ee61f3252615e75c914";
+            assertArrayEquals(TestUtils.decodeHex(signatureHex), c.getSignature());
+
+            // ECDSA signature AlgorithmIdentifiers omit parameters.
+            assertNull(c.getSigAlgParams());
+
+            // The certificate does not have UIDs.
+            assertNull(c.getIssuerUniqueID());
+            assertNull(c.getSubjectUniqueID());
+
+            // The certificate does not have any extensions.
+            assertEquals(-1, c.getBasicConstraints());
+            assertNull(c.getExtendedKeyUsage());
+            assertNull(c.getIssuerAlternativeNames());
+            assertNull(c.getKeyUsage());
+            assertNull(c.getSubjectAlternativeNames());
         });
     }
 
     @Test
-    public void testManyExtensions() throws Exception {
+    public void testManyExtensions() {
         ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
-        tester.run(new ServiceTester.Test() {
-            @Override
-            public void test(Provider p, String algorithm) throws Exception {
-                X509Certificate c = certificateFromPEM(p, MANY_EXTENSIONS);
-
-                assertEquals(3, c.getVersion());
-                assertEquals(new BigInteger("b5b622b95a04a521", 16), c.getSerialNumber());
-                assertDatesEqual(dateFromUTC(2016, Calendar.JULY, 9, 4, 38, 9), c.getNotBefore());
-                assertDatesEqual(dateFromUTC(2016, Calendar.AUGUST, 8, 4, 38, 9), c.getNotAfter());
-                assertEquals(new X500Principal("CN=Test Issuer"), c.getIssuerX500Principal());
-                assertEquals(new X500Principal("CN=Test Subject"), c.getSubjectX500Principal());
-                assertEquals("1.2.840.113549.1.1.11", c.getSigAlgOID());
-                String signatureHex = "3ec983af1202b61695ca077d9001f743e6ca"
-                        + "bb791fa0fc2d18be5b6462d5f04dc511042e"
-                        + "77b3589dac72397850c72c298a783e2f79d2"
-                        + "054dfbad8882b22670236fb5be48d427f2fc"
-                        + "c34dbabf5f7dab3a5f7df80f485854841378"
-                        + "fc85937ba623eda6250aed659c8c3c829263"
-                        + "fb181901e11865fac062be18efe88343d093"
-                        + "f56ee83f865365d19c357461983596c02c1d"
-                        + "ddb55ebc8ae9f0e636410cc1b216aedb38c5"
-                        + "ceec711ac61d6cbe88c7faffba7f024fd222"
-                        + "270ce174b09a543ca4fc4064fafe1362e855"
-                        + "df69329594c295b651bb4ee70b064eb639b0"
-                        + "ee39b4534dff2fa3b5485e0750b68a339b1b"
-                        + "fb5710b6a2c8274cf92ff069ebafd0c5ed23"
-                        + "8c679f50";
-                assertArrayEquals(TestUtils.decodeHex(signatureHex), c.getSignature());
-
-                // Although documented to only return null when there are no parameters, the SUN
-                // provider also returns null when the algorithm uses an explicit parameter with a
-                // value of ASN.1 NULL.
-                if (c.getSigAlgParams() != null) {
-                    assertArrayEquals(TestUtils.decodeHex("0500"), c.getSigAlgParams());
-                }
-
-                assertArrayEquals(new boolean[] {true, false, true, false}, c.getIssuerUniqueID());
-                assertArrayEquals(
-                        new boolean[] {false, true, false, true, false}, c.getSubjectUniqueID());
-                assertEquals(10, c.getBasicConstraints());
-                assertEquals(Arrays.asList("1.3.6.1.5.5.7.3.1", "1.2.840.113554.4.1.72585.2"),
-                        c.getExtendedKeyUsage());
-
-                // TODO(davidben): Test the other name types.
-                assertGeneralNamesEqual(
-                        Arrays.<List<?>>asList(Arrays.asList(1, "issuer@example.com"),
-                                Arrays.asList(2, "issuer.example.com"),
-                                Arrays.asList(4, "CN=Test Issuer"),
-                                Arrays.asList(6, "https://example.com/issuer"),
-                                // TODO(https://github.com/google/conscrypt/issues/938): Fix IPv6
-                                // handling and include it in this test.
-                                Arrays.asList(7, "127.0.0.1"),
-                                Arrays.asList(8, "1.2.840.113554.4.1.72585.2")),
-                        c.getIssuerAlternativeNames());
-                assertGeneralNamesEqual(
-                        Arrays.<List<?>>asList(Arrays.asList(1, "subject@example.com"),
-                                Arrays.asList(2, "subject.example.com"),
-                                Arrays.asList(4, "CN=Test Subject"),
-                                Arrays.asList(6, "https://example.com/subject"),
-                                // TODO(https://github.com/google/conscrypt/issues/938): Fix IPv6
-                                // handling and include it in this test.
-                                Arrays.asList(7, "127.0.0.1"),
-                                Arrays.asList(8, "1.2.840.113554.4.1.72585.2")),
-                        c.getSubjectAlternativeNames());
-
-                // Although the BIT STRING in the certificate only has three bits, getKeyUsage()
-                // rounds up to at least 9 bits.
-                assertArrayEquals(
-                        new boolean[] {true, false, true, false, false, false, false, false, false},
-                        c.getKeyUsage());
+        tester.run((p, algorithm) -> {
+            X509Certificate c = certificateFromPEM(p, MANY_EXTENSIONS);
+
+            assertEquals(3, c.getVersion());
+            assertEquals(new BigInteger("b5b622b95a04a521", 16), c.getSerialNumber());
+            assertDatesEqual(dateFromUTC(2016, Calendar.JULY, 9, 4, 38, 9), c.getNotBefore());
+            assertDatesEqual(dateFromUTC(2016, Calendar.AUGUST, 8, 4, 38, 9), c.getNotAfter());
+            assertEquals(new X500Principal("CN=Test Issuer"), c.getIssuerX500Principal());
+            assertEquals(new X500Principal("CN=Test Subject"), c.getSubjectX500Principal());
+            assertEquals("1.2.840.113549.1.1.11", c.getSigAlgOID());
+            String signatureHex = "3ec983af1202b61695ca077d9001f743e6ca"
+                    + "bb791fa0fc2d18be5b6462d5f04dc511042e"
+                    + "77b3589dac72397850c72c298a783e2f79d2"
+                    + "054dfbad8882b22670236fb5be48d427f2fc"
+                    + "c34dbabf5f7dab3a5f7df80f485854841378"
+                    + "fc85937ba623eda6250aed659c8c3c829263"
+                    + "fb181901e11865fac062be18efe88343d093"
+                    + "f56ee83f865365d19c357461983596c02c1d"
+                    + "ddb55ebc8ae9f0e636410cc1b216aedb38c5"
+                    + "ceec711ac61d6cbe88c7faffba7f024fd222"
+                    + "270ce174b09a543ca4fc4064fafe1362e855"
+                    + "df69329594c295b651bb4ee70b064eb639b0"
+                    + "ee39b4534dff2fa3b5485e0750b68a339b1b"
+                    + "fb5710b6a2c8274cf92ff069ebafd0c5ed23"
+                    + "8c679f50";
+            assertArrayEquals(TestUtils.decodeHex(signatureHex), c.getSignature());
+
+            // Although documented to only return null when there are no parameters, the SUN
+            // provider also returns null when the algorithm uses an explicit parameter with a
+            // value of ASN.1 NULL.
+            if (c.getSigAlgParams() != null) {
+                assertArrayEquals(TestUtils.decodeHex("0500"), c.getSigAlgParams());
             }
+
+            assertArrayEquals(new boolean[] {true, false, true, false}, c.getIssuerUniqueID());
+            assertArrayEquals(
+                    new boolean[] {false, true, false, true, false}, c.getSubjectUniqueID());
+            assertEquals(10, c.getBasicConstraints());
+            assertEquals(Arrays.asList("1.3.6.1.5.5.7.3.1", "1.2.840.113554.4.1.72585.2"),
+                    c.getExtendedKeyUsage());
+
+            // TODO(davidben): Test the other name types.
+            assertGeneralNamesEqual(Arrays.asList(Arrays.asList(1, "issuer@example.com"),
+                                            Arrays.asList(2, "issuer.example.com"),
+                                            Arrays.asList(4, "CN=Test Issuer"),
+                                            Arrays.asList(6, "https://example.com/issuer"),
+                                            // TODO(https://github.com/google/conscrypt/issues/938):
+                                            // Fix IPv6 handling and include it in this test.
+                                            Arrays.asList(7, "127.0.0.1"),
+                                            Arrays.asList(8, "1.2.840.113554.4.1.72585.2")),
+                    c.getIssuerAlternativeNames());
+            assertGeneralNamesEqual(Arrays.asList(Arrays.asList(1, "subject@example.com"),
+                                            Arrays.asList(2, "subject.example.com"),
+                                            Arrays.asList(4, "CN=Test Subject"),
+                                            Arrays.asList(6, "https://example.com/subject"),
+                                            // TODO(https://github.com/google/conscrypt/issues/938):
+                                            // Fix IPv6 handling and include it in this test.
+                                            Arrays.asList(7, "127.0.0.1"),
+                                            Arrays.asList(8, "1.2.840.113554.4.1.72585.2")),
+                    c.getSubjectAlternativeNames());
+
+            // Although the BIT STRING in the certificate only has three bits, getKeyUsage()
+            // rounds up to at least 9 bits.
+            assertArrayEquals(
+                    new boolean[] {true, false, true, false, false, false, false, false, false},
+                    c.getKeyUsage());
         });
     }
 
     @Test
-    public void testBasicConstraints() throws Exception {
+    public void testBasicConstraints() {
         ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
-        tester.run(new ServiceTester.Test() {
-            @Override
-            public void test(Provider p, String algorithm) throws Exception {
-                // Test some additional edge cases in getBasicConstraints() beyond that
-                // testManyExtensions() and testV1Cert() covered.
-
-                // If there is no pathLen constraint but the certificate is a CA,
-                // getBasicConstraints() returns Integer.MAX_VALUE.
-                X509Certificate c = certificateFromPEM(p, BASIC_CONSTRAINTS_NO_PATHLEN);
-                assertEquals(Integer.MAX_VALUE, c.getBasicConstraints());
-
-                // If there is a pathLen constraint of zero, getBasicConstraints() returns it.
-                c = certificateFromPEM(p, BASIC_CONSTRAINTS_PATHLEN_0);
-                assertEquals(0, c.getBasicConstraints());
-
-                // If there is basicConstraints extension indicating a leaf certficate,
-                // getBasicConstraints() returns -1. The accessor does not distinguish between no
-                // basicConstraints extension and a leaf one.
-                c = certificateFromPEM(p, BASIC_CONSTRAINTS_LEAF);
-                assertEquals(-1, c.getBasicConstraints());
-
-                // If some unrelated extension has a syntax error, and that syntax error does not
-                // fail when constructing the certificate, it should not interfere with
-                // getBasicConstraints().
-                try {
-                    c = certificateFromPEM(p, BASIC_CONSTRAINTS_PATHLEN_10_BAD_SAN);
-                } catch (CertificateParsingException e) {
-                    // The certificate has a syntax error, so it would also be valid for the
-                    // provider to reject the certificate at construction. X.509 is an extensible
-                    // format, so different implementations may notice errors at different points.
-                    c = null;
-                }
-                if (c != null) {
-                    assertEquals(10, c.getBasicConstraints());
-                }
+        tester.run((p, algorithm) -> {
+            // Test some additional edge cases in getBasicConstraints() beyond that
+            // testManyExtensions() and testV1Cert() covered.
+
+            // If there is no pathLen constraint but the certificate is a CA,
+            // getBasicConstraints() returns Integer.MAX_VALUE.
+            X509Certificate c = certificateFromPEM(p, BASIC_CONSTRAINTS_NO_PATHLEN);
+            assertEquals(Integer.MAX_VALUE, c.getBasicConstraints());
+
+            // If there is a pathLen constraint of zero, getBasicConstraints() returns it.
+            c = certificateFromPEM(p, BASIC_CONSTRAINTS_PATHLEN_0);
+            assertEquals(0, c.getBasicConstraints());
+
+            // If there is basicConstraints extension indicating a leaf certficate,
+            // getBasicConstraints() returns -1. The accessor does not distinguish between no
+            // basicConstraints extension and a leaf one.
+            c = certificateFromPEM(p, BASIC_CONSTRAINTS_LEAF);
+            assertEquals(-1, c.getBasicConstraints());
+
+            // If some unrelated extension has a syntax error, and that syntax error does not
+            // fail when constructing the certificate, it should not interfere with
+            // getBasicConstraints().
+            try {
+                c = certificateFromPEM(p, BASIC_CONSTRAINTS_PATHLEN_10_BAD_SAN);
+            } catch (CertificateParsingException e) {
+                // The certificate has a syntax error, so it would also be valid for the
+                // provider to reject the certificate at construction. X.509 is an extensible
+                // format, so different implementations may notice errors at different points.
+                c = null;
+            }
+            if (c != null) {
+                assertEquals(10, c.getBasicConstraints());
             }
         });
     }
 
     @Test
-    public void testLargeKeyUsage() throws Exception {
+    public void testLargeKeyUsage() {
         ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
-        tester.run(new ServiceTester.Test() {
-            @Override
-            public void test(Provider p, String algorithm) throws Exception {
-                X509Certificate c = certificateFromPEM(p, LARGE_KEY_USAGE);
-                assertArrayEquals(new boolean[] {true, false, true, false, false, false, false,
-                                          false, false, false, false},
-                        c.getKeyUsage());
-            }
+        tester.run((p, algorithm) -> {
+            X509Certificate c = certificateFromPEM(p, LARGE_KEY_USAGE);
+            assertArrayEquals(new boolean[] {true, false, true, false, false, false, false, false,
+                                      false, false, false},
+                    c.getKeyUsage());
         });
     }
 
     @Test
-    public void testSigAlgParams() throws Exception {
+    public void testSigAlgParams() {
         ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
-        tester.run(new ServiceTester.Test() {
-            @Override
-            public void test(Provider p, String algorithm) throws Exception {
-                X509Certificate c = certificateFromPEM(p, SIGALG_NO_PARAMETER);
-                assertNull(c.getSigAlgParams());
-
-                c = certificateFromPEM(p, SIGALG_NULL_PARAMETER);
-                // Although documented to only return null when there are no parameters, the SUN
-                // provider also returns null when the algorithm uses an explicit parameter with a
-                // value of ASN.1 NULL.
-                if (c.getSigAlgParams() != null) {
-                    assertArrayEquals(TestUtils.decodeHex("0500"), c.getSigAlgParams());
-                }
-
-                c = certificateFromPEM(p, SIGALG_STRING_PARAMETER);
-                assertArrayEquals(TestUtils.decodeHex("0c05706172616d"), c.getSigAlgParams());
-
-                c = certificateFromPEM(p, SIGALG_BOOLEAN_PARAMETER);
-                assertArrayEquals(TestUtils.decodeHex("0101ff"), c.getSigAlgParams());
-
-                c = certificateFromPEM(p, SIGALG_SEQUENCE_PARAMETER);
-                assertArrayEquals(TestUtils.decodeHex("3000"), c.getSigAlgParams());
+        tester.run((p, algorithm) -> {
+            X509Certificate c = certificateFromPEM(p, SIGALG_NO_PARAMETER);
+            assertNull(c.getSigAlgParams());
+
+            c = certificateFromPEM(p, SIGALG_NULL_PARAMETER);
+            // Although documented to only return null when there are no parameters, the SUN
+            // provider also returns null when the algorithm uses an explicit parameter with a
+            // value of ASN.1 NULL.
+            if (c.getSigAlgParams() != null) {
+                assertArrayEquals(TestUtils.decodeHex("0500"), c.getSigAlgParams());
             }
+
+            c = certificateFromPEM(p, SIGALG_STRING_PARAMETER);
+            assertArrayEquals(TestUtils.decodeHex("0c05706172616d"), c.getSigAlgParams());
+
+            c = certificateFromPEM(p, SIGALG_BOOLEAN_PARAMETER);
+            assertArrayEquals(TestUtils.decodeHex("0101ff"), c.getSigAlgParams());
+
+            c = certificateFromPEM(p, SIGALG_SEQUENCE_PARAMETER);
+            assertArrayEquals(TestUtils.decodeHex("3000"), c.getSigAlgParams());
         });
     }
 
     // Ensure we don't reject certificates with UTCTIME fields with offsets for now: b/311260068
     @Test
-    public void utcTimeWithOffset() throws Exception {
+    public void utcTimeWithOffset() {
         ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
         tester.skipProvider("SUN") // Sun and BC interpret the offset, Conscrypt just drops it...
                 .skipProvider("BC")
-                .run(new ServiceTester.Test() {
-                    @Override
-                    public void test(Provider p, String algorithm) throws Exception {
-                        X509Certificate c = certificateFromPEM(p, UTCTIME_WITH_OFFSET);
-                        assertDatesEqual(
-                                dateFromUTC(2014, Calendar.JULY, 4, 0, 0, 0), c.getNotBefore());
-                        assertDatesEqual(
-                                dateFromUTC(2048, Calendar.AUGUST, 1, 10, 21, 23), c.getNotAfter());
-                    }
+                .run((p, algorithm) -> {
+                    X509Certificate c = certificateFromPEM(p, UTCTIME_WITH_OFFSET);
+                    assertDatesEqual(
+                            dateFromUTC(2014, Calendar.JULY, 4, 0, 0, 0), c.getNotBefore());
+                    assertDatesEqual(
+                            dateFromUTC(2048, Calendar.AUGUST, 1, 10, 21, 23), c.getNotAfter());
                 });
     }
 }
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherTest.java
index 8a27e182..c092d02c 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/CipherTest.java
@@ -17,8 +17,10 @@
 
 package com.android.org.conscrypt.javax.crypto;
 
+import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertThrows;
@@ -56,6 +58,7 @@ import java.security.KeyFactory;
 import java.security.KeyPairGenerator;
 import java.security.PrivateKey;
 import java.security.Provider;
+import java.security.ProviderException;
 import java.security.PublicKey;
 import java.security.SecureRandom;
 import java.security.Security;
@@ -166,7 +169,7 @@ public final class CipherTest {
         return true;
     }
 
-    /**
+    /*
      * Checks for algorithms removed from BC in Android 12 and so not usable for these
      * tests.
      *
@@ -194,20 +197,17 @@ public final class CipherTest {
             return false;
         }
         // AESWRAP should be used instead, fails with BC and SunJCE otherwise.
-        if (algorithm.startsWith("AES") || algorithm.startsWith("DESEDE")) {
-            return false;
-        }
-        return true;
+        return !algorithm.startsWith("AES") && !algorithm.startsWith("DESEDE");
     }
 
-    private synchronized static int getEncryptMode(String algorithm) throws Exception {
+    private synchronized static int getEncryptMode(String algorithm) {
         if (isOnlyWrappingAlgorithm(algorithm)) {
             return Cipher.WRAP_MODE;
         }
         return Cipher.ENCRYPT_MODE;
     }
 
-    private synchronized static int getDecryptMode(String algorithm) throws Exception {
+    private synchronized static int getDecryptMode(String algorithm) {
         if (isOnlyWrappingAlgorithm(algorithm)) {
             return Cipher.UNWRAP_MODE;
         }
@@ -324,7 +324,7 @@ public final class CipherTest {
                 || algorithm.contains("/OAEPWITH");
     }
 
-    private static Map<String, Key> ENCRYPT_KEYS = new HashMap<String, Key>();
+    private static final Map<String, Key> ENCRYPT_KEYS = new HashMap<>();
 
     /**
      * Returns the key meant for enciphering for {@code algorithm}.
@@ -359,7 +359,7 @@ public final class CipherTest {
         return key;
     }
 
-    private static Map<String, Key> DECRYPT_KEYS = new HashMap<String, Key>();
+    private static final Map<String, Key> DECRYPT_KEYS = new HashMap<>();
 
     /**
      * Returns the key meant for deciphering for {@code algorithm}.
@@ -388,7 +388,7 @@ public final class CipherTest {
         return key;
     }
 
-    private static Map<String, Integer> EXPECTED_BLOCK_SIZE = new HashMap<String, Integer>();
+    private static final Map<String, Integer> EXPECTED_BLOCK_SIZE = new HashMap<>();
     static {
         setExpectedBlockSize("AES", 16);
         setExpectedBlockSize("AES/CBC/PKCS5PADDING", 16);
@@ -576,7 +576,7 @@ public final class CipherTest {
         return getExpectedSize(EXPECTED_BLOCK_SIZE, algorithm, mode, provider);
     }
 
-    private static Map<String, Integer> EXPECTED_OUTPUT_SIZE = new HashMap<String, Integer>();
+    private static final Map<String, Integer> EXPECTED_OUTPUT_SIZE = new HashMap<>();
     static {
         setExpectedOutputSize("AES/CBC/NOPADDING", 0);
         setExpectedOutputSize("AES/CFB/NOPADDING", 0);
@@ -797,100 +797,109 @@ public final class CipherTest {
         return getExpectedSize(EXPECTED_OUTPUT_SIZE, algorithm, mode, provider);
     }
 
-    private static byte[] ORIGINAL_PLAIN_TEXT = new byte[] { 0x0a, 0x0b, 0x0c };
-    private static byte[] SIXTEEN_BYTE_BLOCK_PLAIN_TEXT = new byte[] { 0x0a, 0x0b, 0x0c, 0x00,
-                                                                       0x00, 0x00, 0x00, 0x00,
-                                                                       0x00, 0x00, 0x00, 0x00,
-                                                                       0x00, 0x00, 0x00, 0x00 };
-    private static byte[] EIGHT_BYTE_BLOCK_PLAIN_TEXT = new byte[] { 0x0a, 0x0b, 0x0c, 0x00,
-                                                                     0x00, 0x00, 0x00, 0x00 };
-    private static byte[] PKCS1_BLOCK_TYPE_00_PADDED_PLAIN_TEXT = new byte[] {
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
-        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0x0b, 0x0c
-    };
-    private static byte[] PKCS1_BLOCK_TYPE_01_PADDED_PLAIN_TEXT = new byte[] {
-        (byte) 0x00, (byte) 0x01, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c
-    };
-    private static byte[] PKCS1_BLOCK_TYPE_02_PADDED_PLAIN_TEXT = new byte[] {
-        (byte) 0x00, (byte) 0x02, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
-        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c
-    };
-
+    private static final byte[] ORIGINAL_PLAIN_TEXT = new byte[] {0x0a, 0x0b, 0x0c};
+    private static final byte[] SIXTEEN_BYTE_BLOCK_PLAIN_TEXT = new byte[] {0x0a, 0x0b, 0x0c, 0x00,
+            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
+    private static final byte[] EIGHT_BYTE_BLOCK_PLAIN_TEXT =
+            new byte[] {0x0a, 0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00};
+    private static final byte[] PKCS1_BLOCK_TYPE_00_PADDED_PLAIN_TEXT = new byte[] {0, 0, 0, 0, 0,
+            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
+            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0x0b, 0x0c};
+    private static final byte[] PKCS1_BLOCK_TYPE_01_PADDED_PLAIN_TEXT =
+            new byte[] {(byte) 0x00, (byte) 0x01, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0x00, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c};
+    private static final byte[] PKCS1_BLOCK_TYPE_02_PADDED_PLAIN_TEXT =
+            new byte[] {(byte) 0x00, (byte) 0x02, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
+                    (byte) 0xff, (byte) 0x00, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c};
 
     private static byte[] getActualPlainText(String algorithm) {
         // Block mode AES with NoPadding needs to match underlying block size
@@ -1049,8 +1058,8 @@ public final class CipherTest {
         final ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
         PrintStream out = new PrintStream(errBuffer);
 
-        Set<String> seenBaseCipherNames = new HashSet<String>();
-        Set<String> seenCiphersWithModeAndPadding = new HashSet<String>();
+        Set<String> seenBaseCipherNames = new HashSet<>();
+        Set<String> seenCiphersWithModeAndPadding = new HashSet<>();
 
         Provider[] providers = Security.getProviders();
         for (Provider provider : providers) {
@@ -1139,7 +1148,7 @@ public final class CipherTest {
 
         out.flush();
         if (errBuffer.size() > 0) {
-            throw new Exception("Errors encountered:\n\n" + errBuffer.toString() + "\n\n");
+            throw new Exception("Errors encountered:\n\n" + errBuffer + "\n\n");
         }
     }
 
@@ -1371,8 +1380,7 @@ public final class CipherTest {
     }
 
     private void assertCorrectAlgorithmParameters(String providerName, String cipherID,
-            final AlgorithmParameterSpec spec, AlgorithmParameters params)
-            throws InvalidParameterSpecException, Exception {
+            final AlgorithmParameterSpec spec, AlgorithmParameters params) throws Exception {
         if (spec == null) {
             return;
         }
@@ -1408,8 +1416,8 @@ public final class CipherTest {
         }
     }
 
-    private static void assertOAEPParametersEqual(OAEPParameterSpec expectedOaepSpec,
-            OAEPParameterSpec actualOaepSpec) throws Exception {
+    private static void assertOAEPParametersEqual(
+            OAEPParameterSpec expectedOaepSpec, OAEPParameterSpec actualOaepSpec) {
         assertEquals(expectedOaepSpec.getDigestAlgorithm(), actualOaepSpec.getDigestAlgorithm());
 
         assertEquals(expectedOaepSpec.getMGFAlgorithm(), actualOaepSpec.getMGFAlgorithm());
@@ -1451,7 +1459,7 @@ public final class CipherTest {
         }
 
         try {
-            c.init(encryptMode, encryptKey, (AlgorithmParameterSpec) null, (SecureRandom) null);
+            c.init(encryptMode, encryptKey, (AlgorithmParameterSpec) null, null);
         } catch (InvalidAlgorithmParameterException e) {
             if (!isPBE(c.getAlgorithm())) {
                 throw e;
@@ -1467,7 +1475,7 @@ public final class CipherTest {
         }
 
         try {
-            c.init(encryptMode, encryptKey, (AlgorithmParameters) null, (SecureRandom) null);
+            c.init(encryptMode, encryptKey, (AlgorithmParameters) null, null);
         } catch (InvalidAlgorithmParameterException e) {
             if (!isPBE(c.getAlgorithm())) {
                 throw e;
@@ -1489,7 +1497,7 @@ public final class CipherTest {
         }
 
         try {
-            c.init(decryptMode, encryptKey, (AlgorithmParameterSpec) null, (SecureRandom) null);
+            c.init(decryptMode, encryptKey, (AlgorithmParameterSpec) null, null);
             if (needsParameters) {
                 fail("Should throw InvalidAlgorithmParameterException with null parameters");
             }
@@ -1511,7 +1519,7 @@ public final class CipherTest {
         }
 
         try {
-            c.init(decryptMode, encryptKey, (AlgorithmParameters) null, (SecureRandom) null);
+            c.init(decryptMode, encryptKey, (AlgorithmParameters) null, null);
             if (needsParameters) {
                 fail("Should throw InvalidAlgorithmParameterException with null parameters");
             }
@@ -1573,9 +1581,9 @@ public final class CipherTest {
         }
         byte[] plainText = c.doFinal(cipherText);
         byte[] expectedPlainText = getExpectedPlainText(algorithm, provider);
-        assertTrue("Expected " + Arrays.toString(expectedPlainText)
-                + " but was " + Arrays.toString(plainText),
-                Arrays.equals(expectedPlainText, plainText));
+        assertArrayEquals("Expected " + Arrays.toString(expectedPlainText) + " but was "
+                        + Arrays.toString(plainText),
+                expectedPlainText, plainText);
     }
 
     @Test
@@ -1752,7 +1760,7 @@ public final class CipherTest {
         }
     }
 
-    private Certificate certificateWithKeyUsage(int keyUsage) throws Exception {
+    private Certificate certificateWithKeyUsage(int keyUsage) {
         // note the rare usage of non-zero keyUsage
         return new TestKeyStore.Builder()
                 .aliasPrefix("rsa-dsa-ec")
@@ -2589,13 +2597,13 @@ public final class CipherTest {
          */
         c.init(Cipher.ENCRYPT_MODE, privKey);
         byte[] encrypted = c.doFinal(RSA_2048_Vector1);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals(
+                "Encrypted should match expected", RSA_Vector1_Encrypt_Private, encrypted);
 
         c.init(Cipher.DECRYPT_MODE, privKey);
         encrypted = c.doFinal(RSA_2048_Vector1);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals(
+                "Encrypted should match expected", RSA_Vector1_Encrypt_Private, encrypted);
     }
 
     @Test
@@ -2618,14 +2626,14 @@ public final class CipherTest {
         c.init(Cipher.ENCRYPT_MODE, privKey);
         c.update(RSA_2048_Vector1);
         byte[] encrypted = c.doFinal();
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals(
+                "Encrypted should match expected", RSA_Vector1_Encrypt_Private, encrypted);
 
         c.init(Cipher.DECRYPT_MODE, privKey);
         c.update(RSA_2048_Vector1);
         encrypted = c.doFinal();
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals(
+                "Encrypted should match expected", RSA_Vector1_Encrypt_Private, encrypted);
     }
 
     @Test
@@ -2653,16 +2661,16 @@ public final class CipherTest {
             c.update(RSA_2048_Vector1, i, 1);
         }
         byte[] encrypted = c.doFinal(RSA_2048_Vector1, i, RSA_2048_Vector1.length - i);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals(
+                "Encrypted should match expected", RSA_Vector1_Encrypt_Private, encrypted);
 
         c.init(Cipher.DECRYPT_MODE, privKey);
         for (i = 0; i < RSA_2048_Vector1.length / 2; i++) {
             c.update(RSA_2048_Vector1, i, 1);
         }
         encrypted = c.doFinal(RSA_2048_Vector1, i, RSA_2048_Vector1.length - i);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals(
+                "Encrypted should match expected", RSA_Vector1_Encrypt_Private, encrypted);
     }
 
     @Test
@@ -2688,16 +2696,16 @@ public final class CipherTest {
                 .doFinal(RSA_2048_Vector1, 0, RSA_2048_Vector1.length, encrypted, 0);
         assertEquals("Encrypted size should match expected", RSA_Vector1_Encrypt_Private.length,
                 encryptLen);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals(
+                "Encrypted should match expected", RSA_Vector1_Encrypt_Private, encrypted);
 
         c.init(Cipher.DECRYPT_MODE, privKey);
         final int decryptLen = c
                 .doFinal(RSA_2048_Vector1, 0, RSA_2048_Vector1.length, encrypted, 0);
         assertEquals("Encrypted size should match expected", RSA_Vector1_Encrypt_Private.length,
                 decryptLen);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_Encrypt_Private, encrypted));
+        assertArrayEquals(
+                "Encrypted should match expected", RSA_Vector1_Encrypt_Private, encrypted);
     }
 
     @Test
@@ -2844,13 +2852,13 @@ public final class CipherTest {
          */
         c.init(Cipher.ENCRYPT_MODE, pubKey);
         byte[] encrypted = c.doFinal(TooShort_Vector);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_ZeroPadded_Encrypted, encrypted));
+        assertArrayEquals(
+                "Encrypted should match expected", RSA_Vector1_ZeroPadded_Encrypted, encrypted);
 
         c.init(Cipher.DECRYPT_MODE, pubKey);
         encrypted = c.doFinal(TooShort_Vector);
-        assertTrue("Encrypted should match expected",
-                Arrays.equals(RSA_Vector1_ZeroPadded_Encrypted, encrypted));
+        assertArrayEquals(
+                "Encrypted should match expected", RSA_Vector1_ZeroPadded_Encrypted, encrypted);
     }
 
     @Test
@@ -2924,7 +2932,7 @@ public final class CipherTest {
             c.doFinal(RSA_Vector1_ZeroPadded_Encrypted);
             fail("Should have error when block size is too big.");
         } catch (IllegalBlockSizeException success) {
-            assertFalse(provider, "BC".equals(provider));
+            assertNotEquals("BC", provider);
         } catch (ArrayIndexOutOfBoundsException success) {
             assertEquals("BC", provider);
         }
@@ -2959,7 +2967,7 @@ public final class CipherTest {
             c.doFinal(RSA_Vector1_ZeroPadded_Encrypted);
             fail("Should have error when block size is too big.");
         } catch (IllegalBlockSizeException success) {
-            assertFalse(provider, "BC".equals(provider));
+            assertNotEquals("BC", provider);
         } catch (ArrayIndexOutOfBoundsException success) {
             assertEquals("BC", provider);
         }
@@ -2994,7 +3002,7 @@ public final class CipherTest {
             c.doFinal(tooBig_Vector);
             fail("Should have error when block size is too big.");
         } catch (IllegalBlockSizeException success) {
-            assertFalse(provider, "BC".equals(provider));
+            assertNotEquals("BC", provider);
         } catch (ArrayIndexOutOfBoundsException success) {
             assertEquals("BC", provider);
         }
@@ -3037,6 +3045,7 @@ public final class CipherTest {
             c.getOutputSize(RSA_2048_Vector1.length);
             fail("Should throw IllegalStateException if getOutputSize is called before init");
         } catch (IllegalStateException success) {
+            // Expected.
         }
     }
 
@@ -3536,7 +3545,7 @@ public final class CipherTest {
         }
     }
 
-    private static List<CipherTestParam> DES_CIPHER_TEST_PARAMS = new ArrayList<CipherTestParam>();
+    private static final List<CipherTestParam> DES_CIPHER_TEST_PARAMS = new ArrayList<>();
     static {
         DES_CIPHER_TEST_PARAMS.add(new CipherTestParam(
                 "DESede/CBC/PKCS5Padding",
@@ -3564,7 +3573,7 @@ public final class CipherTest {
                 ));
     }
 
-    private static List<CipherTestParam> ARC4_CIPHER_TEST_PARAMS = new ArrayList<CipherTestParam>();
+    private static final List<CipherTestParam> ARC4_CIPHER_TEST_PARAMS = new ArrayList<>();
     static {
         ARC4_CIPHER_TEST_PARAMS.add(new CipherTestParam(
                 "ARC4",
@@ -3588,7 +3597,7 @@ public final class CipherTest {
         ));
     }
 
-    private static List<CipherTestParam> CIPHER_TEST_PARAMS = new ArrayList<CipherTestParam>();
+    private static final List<CipherTestParam> CIPHER_TEST_PARAMS = new ArrayList<>();
     static {
         CIPHER_TEST_PARAMS.add(new CipherTestParam(
                 "AES/ECB/PKCS5Padding",
@@ -3646,7 +3655,7 @@ public final class CipherTest {
         }
     }
 
-    private static final List<CipherTestParam> RSA_OAEP_CIPHER_TEST_PARAMS = new ArrayList<CipherTestParam>();
+    private static final List<CipherTestParam> RSA_OAEP_CIPHER_TEST_PARAMS = new ArrayList<>();
     static {
         addRsaOaepTest("SHA-1", MGF1ParameterSpec.SHA1, RSA_Vector2_OAEP_SHA1_MGF1_SHA1);
         addRsaOaepTest("SHA-256", MGF1ParameterSpec.SHA1, RSA_Vector2_OAEP_SHA256_MGF1_SHA1);
@@ -3723,7 +3732,7 @@ public final class CipherTest {
         ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
         PrintStream out = new PrintStream(errBuffer);
         for (CipherTestParam testVector : testVectors) {
-            ArrayList<Provider> providers = new ArrayList<Provider>();
+            ArrayList<Provider> providers = new ArrayList<>();
 
             Provider[] providerArray = Security.getProviders("Cipher." + testVector.transformation);
             if (providerArray != null) {
@@ -3768,7 +3777,7 @@ public final class CipherTest {
         }
         out.flush();
         if (errBuffer.size() > 0) {
-            throw new Exception("Errors encountered:\n\n" + errBuffer.toString() + "\n\n");
+            throw new Exception("Errors encountered:\n\n" + errBuffer + "\n\n");
         }
     }
 
@@ -3784,7 +3793,7 @@ public final class CipherTest {
         }
         out.flush();
         if (errBuffer.size() > 0) {
-            throw new Exception("Errors encountered:\n\n" + errBuffer.toString() + "\n\n");
+            throw new Exception("Errors encountered:\n\n" + errBuffer + "\n\n");
         }
     }
 
@@ -3874,8 +3883,7 @@ public final class CipherTest {
             try {
                 c.updateAAD(new byte[8]);
                 fail("Cipher should not support AAD");
-            } catch (UnsupportedOperationException expected) {
-            } catch (IllegalStateException expected) {
+            } catch (UnsupportedOperationException | IllegalStateException expected) {
             }
         }
 
@@ -3917,6 +3925,13 @@ public final class CipherTest {
                     if (!isAEAD(p.transformation)) {
                         throw maybe;
                     }
+                } catch (ProviderException maybe) {
+                    boolean isShortBufferException =
+                            maybe.getCause() instanceof ShortBufferException;
+                    if (!isAEAD(p.transformation) || !isBuggyProvider(provider)
+                            || !isShortBufferException) {
+                        throw maybe;
+                    }
                 }
                 try {
                     c.update(new byte[0]);
@@ -3930,6 +3945,13 @@ public final class CipherTest {
                     if (!isAEAD(p.transformation)) {
                         throw maybe;
                     }
+                } catch (ProviderException maybe) {
+                    boolean isShortBufferException =
+                            maybe.getCause() instanceof ShortBufferException;
+                    if (!isAEAD(p.transformation) || !isBuggyProvider(provider)
+                            || !isShortBufferException) {
+                        throw maybe;
+                    }
                 }
             } else {
                 throw new AssertionError("Define your behavior here for " + provider);
@@ -4024,6 +4046,12 @@ public final class CipherTest {
         }
     }
 
+    // SunJCE has known issues between 17 and 21
+    private boolean isBuggyProvider(String providerName) {
+        return providerName.equals("SunJCE") && TestUtils.isJavaVersion(17)
+                && !TestUtils.isJavaVersion(21);
+    }
+
     /**
      * Gets the Cipher transformation with the same algorithm and mode as the provided one but
      * which uses no padding.
@@ -4035,7 +4063,7 @@ public final class CipherTest {
             fail("No padding mode delimiter: " + transformation);
         }
         String paddingMode = transformation.substring(paddingModeDelimiterIndex + 1);
-        if (!paddingMode.toLowerCase().endsWith("padding")) {
+        if (!paddingMode.toLowerCase(Locale.ROOT).endsWith("padding")) {
             fail("No padding mode specified:" + transformation);
         }
         return transformation.substring(0, paddingModeDelimiterIndex) + "/NoPadding";
@@ -4121,8 +4149,7 @@ public final class CipherTest {
         try {
             c.updateAAD(new byte[8]);
             fail("should not be able to call updateAAD on non-AEAD cipher");
-        } catch (UnsupportedOperationException expected) {
-        } catch (IllegalStateException expected) {
+        } catch (UnsupportedOperationException | IllegalStateException expected) {
         }
     }
 
@@ -4148,7 +4175,7 @@ public final class CipherTest {
         }
         out.flush();
         if (errBuffer.size() > 0) {
-            throw new Exception("Errors encountered:\n\n" + errBuffer.toString() + "\n\n");
+            throw new Exception("Errors encountered:\n\n" + errBuffer + "\n\n");
         }
     }
 
@@ -4214,25 +4241,12 @@ public final class CipherTest {
         String msg = "update() should throw IllegalStateException [mode=" + opmode + "]";
         final int bs = createAesCipher(opmode).getBlockSize();
         assertEquals(16, bs); // check test is set up correctly
-        assertIllegalStateException(msg, new Runnable() {
-            @Override
-            public void run() {
-                createAesCipher(opmode).update(new byte[0]);
-            }
-        });
-        assertIllegalStateException(msg, new Runnable() {
-            @Override
-            public void run() {
-                createAesCipher(opmode).update(new byte[2 * bs]);
-            }
-        });
-        assertIllegalStateException(msg, new Runnable() {
-            @Override
-            public void run() {
-                createAesCipher(opmode).update(
-                        new byte[2 * bs] /* input */, bs /* inputOffset */, 0 /* inputLen */);
-            }
-        });
+        assertIllegalStateException(msg, () -> createAesCipher(opmode).update(new byte[0]));
+        assertIllegalStateException(msg, () -> createAesCipher(opmode).update(new byte[2 * bs]));
+        assertIllegalStateException(msg,
+                ()
+                        -> createAesCipher(opmode).update(new byte[2 * bs] /* input */,
+                                bs /* inputOffset */, 0 /* inputLen */));
         try {
             createAesCipher(opmode).update(new byte[2*bs] /* input */, 0 /* inputOffset */,
                     2 * bs /* inputLen */, new byte[2 * bs] /* output */, 0 /* outputOffset */);
@@ -4360,8 +4374,7 @@ public final class CipherTest {
             try {
                 c.doFinal(null, 0);
                 fail("Should throw NullPointerException on null output buffer");
-            } catch (NullPointerException expected) {
-            } catch (IllegalArgumentException expected) {
+            } catch (NullPointerException | IllegalArgumentException expected) {
             }
         }
 
@@ -4389,7 +4402,7 @@ public final class CipherTest {
         {
             final byte[] output = new byte[c.getBlockSize()];
             assertEquals(AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted.length, c.doFinal(output, 0));
-            assertTrue(Arrays.equals(AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted, output));
+            assertArrayEquals(AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted, output);
         }
     }
 
@@ -4422,7 +4435,7 @@ public final class CipherTest {
         assertEquals(provider, AES_128_ECB_PKCS5Padding_TestVector_1_Plaintext_Padded.length,
                 output.length);
 
-        assertTrue(provider, Arrays.equals(AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted, output));
+        assertArrayEquals(provider, AES_128_ECB_PKCS5Padding_TestVector_1_Encrypted, output);
     }
 
     private static final byte[] AES_IV_ZEROES = new byte[] {
@@ -4476,7 +4489,7 @@ public final class CipherTest {
         String[] expected = new String[LARGEST_KEY_SIZE - SMALLEST_KEY_SIZE];
 
         /* Find all providers that provide ARC4. We must have at least one! */
-        Map<String, String> filter = new HashMap<String, String>();
+        Map<String, String> filter = new HashMap<>();
         filter.put("Cipher.ARC4", "");
         Provider[] providers = Security.getProviders(filter);
         assertTrue("There must be security providers of Cipher.ARC4", providers.length > 0);
@@ -4524,6 +4537,9 @@ public final class CipherTest {
     public void testAES_keyConstrained() throws Exception {
         Provider[] providers = Security.getProviders();
         for (Provider p : providers) {
+            if (isBuggyProvider(p.getName())) {
+                continue;
+            }
             for (Provider.Service s : p.getServices()) {
                 if (s.getType().equals("Cipher")) {
                     if (s.getAlgorithm().startsWith("AES_128/")) {
@@ -4582,7 +4598,7 @@ public final class CipherTest {
                 new String(encryptedBuffer, 0, unencryptedBytes, StandardCharsets.US_ASCII));
     }
 
-    /**
+    /*
      * When using padding in decrypt mode, ensure that empty buffers decode to empty strings
      * (no padding needed for the empty buffer).
      * http://b/19186852
@@ -4614,7 +4630,7 @@ public final class CipherTest {
         }
     }
 
-    /**
+    /*
      * Check that RSA with OAEPPadding is supported.
      * http://b/22208820
      */
@@ -4627,7 +4643,7 @@ public final class CipherTest {
         cipher.doFinal(new byte[] {1,2,3,4});
     }
 
-    /**
+    /*
      * Check that initializing with a GCM AlgorithmParameters produces the same result
      * as initializing with a GCMParameterSpec.
      */
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/KeyGeneratorTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/KeyGeneratorTest.java
index aa6e5e39..e5f4a7cd 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/KeyGeneratorTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/crypto/KeyGeneratorTest.java
@@ -32,11 +32,11 @@ import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
-import java.security.Provider;
 import java.security.SecureRandom;
 import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.List;
+import java.util.Locale;
 import java.util.Map;
 
 import javax.crypto.KeyGenerator;
@@ -69,16 +69,15 @@ public class KeyGeneratorTest {
     }
 
     @Test
-    public void test_getInstance() throws Exception {
-        ServiceTester.test("KeyGenerator")
-            // Do not test AndroidKeyStore's KeyGenerator. It cannot be initialized without
-            // providing AndroidKeyStore-specific algorithm parameters.
-            // It's OKish not to test AndroidKeyStore's KeyGenerator here because it's tested
-            // by cts/tests/test/keystore.
-            .skipProvider("AndroidKeyStore")
-            .run(new ServiceTester.Test() {
-                @Override
-                public void test(Provider provider, String algorithm) throws Exception {
+    public void test_getInstance() {
+        ServiceTester
+                .test("KeyGenerator")
+                // Do not test AndroidKeyStore's KeyGenerator. It cannot be initialized without
+                // providing AndroidKeyStore-specific algorithm parameters.
+                // It's OKish not to test AndroidKeyStore's KeyGenerator here because it's tested
+                // by cts/tests/test/keystore.
+                .skipProvider("AndroidKeyStore")
+                .run((provider, algorithm) -> {
                     // KeyGenerator.getInstance(String)
                     KeyGenerator kg1 = KeyGenerator.getInstance(algorithm);
                     assertEquals(algorithm, kg1.getAlgorithm());
@@ -95,23 +94,17 @@ public class KeyGeneratorTest {
                     assertEquals(algorithm, kg3.getAlgorithm());
                     assertEquals(provider, kg3.getProvider());
                     test_KeyGenerator(kg3);
-                }
-            });
+                });
     }
 
-    private static final Map<String, List<Integer>> KEY_SIZES
-            = new HashMap<String, List<Integer>>();
+    private static final Map<String, List<Integer>> KEY_SIZES = new HashMap<>();
     private static void putKeySize(String algorithm, int keySize) {
-        algorithm = algorithm.toUpperCase();
-        List<Integer> keySizes = KEY_SIZES.get(algorithm);
-        if (keySizes == null) {
-            keySizes = new ArrayList<Integer>();
-            KEY_SIZES.put(algorithm, keySizes);
-        }
+        algorithm = algorithm.toUpperCase(Locale.ROOT);
+        List<Integer> keySizes = KEY_SIZES.computeIfAbsent(algorithm, k -> new ArrayList<>());
         keySizes.add(keySize);
     }
     private static List<Integer> getKeySizes(String algorithm) throws Exception {
-        algorithm = algorithm.toUpperCase();
+        algorithm = algorithm.toUpperCase(Locale.ROOT);
         List<Integer> keySizes = KEY_SIZES.get(algorithm);
         if (keySizes == null) {
             throw new Exception("Unknown key sizes for KeyGenerator." + algorithm);
@@ -172,7 +165,7 @@ public class KeyGeneratorTest {
             kg.init(keySize);
             test_SecretKey(kg, kg.generateKey());
 
-            kg.init(keySize, (SecureRandom) null);
+            kg.init(keySize, null);
             test_SecretKey(kg, kg.generateKey());
 
             kg.init(keySize, new SecureRandom());
@@ -180,9 +173,10 @@ public class KeyGeneratorTest {
         }
     }
 
-    private void test_SecretKey(KeyGenerator kg, SecretKey sk) throws Exception {
+    private void test_SecretKey(KeyGenerator kg, SecretKey sk) {
         assertNotNull(sk);
-        assertEquals(kg.getAlgorithm().toUpperCase(), sk.getAlgorithm().toUpperCase());
+        assertEquals(kg.getAlgorithm().toUpperCase(Locale.ROOT),
+                sk.getAlgorithm().toUpperCase(Locale.ROOT));
         assertNotNull(sk.getEncoded());
         assertNotNull(sk.getFormat());
     }
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/HttpsURLConnectionTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/HttpsURLConnectionTest.java
index 8bdf3372..078138cc 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/HttpsURLConnectionTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/HttpsURLConnectionTest.java
@@ -27,13 +27,11 @@ import com.android.org.conscrypt.TestUtils;
 import com.android.org.conscrypt.VeryBasicHttpServer;
 
 import org.junit.After;
-import org.junit.Ignore;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
 import java.io.IOException;
-import java.net.HttpURLConnection;
 import java.net.InetAddress;
 import java.net.Socket;
 import java.net.SocketException;
@@ -43,7 +41,6 @@ import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
 import java.util.concurrent.Future;
 import java.util.concurrent.TimeUnit;
-import java.util.concurrent.TimeoutException;
 
 import javax.net.ssl.HostnameVerifier;
 import javax.net.ssl.HttpsURLConnection;
@@ -186,11 +183,7 @@ public class HttpsURLConnectionTest {
             }
             return null;
         });
-        try {
-            future.get(2 * timeoutMillis, TimeUnit.MILLISECONDS);
-        } catch (TimeoutException e) {
-            fail("HttpsURLConnection connection timeout failed.");
-        }
+        future.get(2 * timeoutMillis, TimeUnit.MILLISECONDS);
     }
 
     @Test
diff --git a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
index 945e1e28..f23ff38a 100644
--- a/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
+++ b/repackaged/common/src/test/java/com/android/org/conscrypt/javax/net/ssl/SSLSocketVersionCompatibilityTest.java
@@ -59,9 +59,7 @@ import libcore.junit.util.SwitchTargetSdkVersionRule.TargetSdkVersion;
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Ignore;
-import org.junit.Rule;
 import org.junit.Test;
-import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
 import org.junit.runners.Parameterized;
 
@@ -91,6 +89,7 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collections;
 import java.util.List;
+import java.util.Locale;
 import java.util.concurrent.Callable;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
@@ -137,10 +136,6 @@ import tests.util.Pair;
  */
 @RunWith(Parameterized.class)
 public class SSLSocketVersionCompatibilityTest {
-
-    @Rule
-    public TestRule switchTargetSdkVersionRule = SwitchTargetSdkVersionRule.getInstance();
-
     @Parameterized.Parameters(name = "{index}: {0} client, {1} server")
     public static Iterable<Object[]> data() {
         return Arrays.asList(new Object[][] {
@@ -164,12 +159,7 @@ public class SSLSocketVersionCompatibilityTest {
     @Before
     public void setup() {
         threadGroup = new ThreadGroup("SSLSocketVersionedTest");
-        executor = Executors.newCachedThreadPool(new ThreadFactory() {
-            @Override
-            public Thread newThread(Runnable r) {
-                return new Thread(threadGroup, r);
-            }
-        });
+        executor = Executors.newCachedThreadPool(r -> new Thread(threadGroup, r));
     }
 
     @After
@@ -186,27 +176,23 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                server.startHandshake();
-                assertNotNull(server.getSession());
-                assertNull(server.getHandshakeSession());
-                try {
-                    server.getSession().getPeerCertificates();
-                    fail();
-                } catch (SSLPeerUnverifiedException expected) {
-                    // Ignored.
-                }
-                Certificate[] localCertificates = server.getSession().getLocalCertificates();
-                assertNotNull(localCertificates);
-                TestKeyStore.assertChainLength(localCertificates);
-                assertNotNull(localCertificates[0]);
-                TestSSLContext
-                    .assertServerCertificateChain(c.serverTrustManager, localCertificates);
-                TestSSLContext.assertCertificateInKeyStore(localCertificates[0], c.serverKeyStore);
-                return null;
+        Future<Void> future = runAsync(() -> {
+            server.startHandshake();
+            assertNotNull(server.getSession());
+            assertNull(server.getHandshakeSession());
+            try {
+                server.getSession().getPeerCertificates();
+                fail();
+            } catch (SSLPeerUnverifiedException expected) {
+                // Ignored.
             }
+            Certificate[] localCertificates = server.getSession().getLocalCertificates();
+            assertNotNull(localCertificates);
+            TestKeyStore.assertChainLength(localCertificates);
+            assertNotNull(localCertificates[0]);
+            TestSSLContext.assertServerCertificateChain(c.serverTrustManager, localCertificates);
+            TestSSLContext.assertCertificateInKeyStore(localCertificates[0], c.serverKeyStore);
+            return null;
         });
         client.startHandshake();
         assertNotNull(client.getSession());
@@ -251,7 +237,7 @@ public class SSLSocketVersionCompatibilityTest {
         assertNotNull(client1.getSession().getId());
         final byte[] clientSessionId1 = client1.getSession().getId();
         final byte[] serverSessionId1 = future1.get();
-        assertTrue(Arrays.equals(clientSessionId1, serverSessionId1));
+        assertArrayEquals(clientSessionId1, serverSessionId1);
         client1.close();
         server1.close();
         final SSLSocket client2 = (SSLSocket) c.clientContext.getSocketFactory().createSocket(
@@ -263,10 +249,10 @@ public class SSLSocketVersionCompatibilityTest {
         assertNotNull(client2.getSession().getId());
         final byte[] clientSessionId2 = client2.getSession().getId();
         final byte[] serverSessionId2 = future2.get();
-        assertTrue(Arrays.equals(clientSessionId2, serverSessionId2));
+        assertArrayEquals(clientSessionId2, serverSessionId2);
         client2.close();
         server2.close();
-        assertTrue(Arrays.equals(clientSessionId1, clientSessionId2));
+        assertArrayEquals(clientSessionId1, clientSessionId2);
         c.close();
     }
 
@@ -281,17 +267,14 @@ public class SSLSocketVersionCompatibilityTest {
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         client.setEnabledCipherSuites(new String[0]);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    server.startHandshake();
-                    fail();
-                } catch (SSLHandshakeException expected) {
-                    // Ignored.
-                }
-                return null;
+        Future<Void> future = runAsync(() -> {
+            try {
+                server.startHandshake();
+                fail();
+            } catch (SSLHandshakeException expected) {
+                // Ignored.
             }
+            return null;
         });
         try {
             client.startHandshake();
@@ -315,17 +298,14 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    server.startHandshake();
-                    fail();
-                } catch (SSLHandshakeException expected) {
-                    // Ignored.
-                }
-                return null;
+        Future<Void> future = runAsync(() -> {
+            try {
+                server.startHandshake();
+                fail();
+            } catch (SSLHandshakeException expected) {
+                // Ignored.
             }
+            return null;
         });
         try {
             client.startHandshake();
@@ -349,12 +329,9 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                server.startHandshake();
-                return null;
-            }
+        Future<Void> future = runAsync(() -> {
+            server.startHandshake();
+            return null;
         });
         client.startHandshake();
         future.get();
@@ -364,6 +341,7 @@ public class SSLSocketVersionCompatibilityTest {
     }
 
     @Test
+    @SuppressWarnings("deprecation")
     public void test_SSLSocket_HandshakeCompletedListener() throws Exception {
         final TestSSLContext c = new TestSSLContext.Builder()
                 .clientProtocol(clientVersion)
@@ -372,12 +350,9 @@ public class SSLSocketVersionCompatibilityTest {
         final SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                server.startHandshake();
-                return null;
-            }
+        Future<Void> future = runAsync(() -> {
+            server.startHandshake();
+            return null;
         });
         final boolean[] handshakeCompletedListenerCalled = new boolean[1];
         client.addHandshakeCompletedListener(new HandshakeCompletedListener() {
@@ -389,8 +364,6 @@ public class SSLSocketVersionCompatibilityTest {
                     String cipherSuite = event.getCipherSuite();
                     Certificate[] localCertificates = event.getLocalCertificates();
                     Certificate[] peerCertificates = event.getPeerCertificates();
-                    javax.security.cert.X509Certificate[] peerCertificateChain =
-                        event.getPeerCertificateChain();
                     Principal peerPrincipal = event.getPeerPrincipal();
                     Principal localPrincipal = event.getLocalPrincipal();
                     socket = event.getSocket();
@@ -417,19 +390,23 @@ public class SSLSocketVersionCompatibilityTest {
                     assertNotNull(peerCertificates[0]);
                     TestSSLContext
                         .assertServerCertificateChain(c.clientTrustManager, peerCertificates);
-                    TestSSLContext
-                        .assertCertificateInKeyStore(peerCertificates[0], c.serverKeyStore);
-                    assertNotNull(peerCertificateChain);
-                    TestKeyStore.assertChainLength(peerCertificateChain);
-                    assertNotNull(peerCertificateChain[0]);
                     TestSSLContext.assertCertificateInKeyStore(
-                        peerCertificateChain[0].getSubjectDN(), c.serverKeyStore);
+                            peerCertificates[0], c.serverKeyStore);
                     assertNotNull(peerPrincipal);
                     TestSSLContext.assertCertificateInKeyStore(peerPrincipal, c.serverKeyStore);
                     assertNull(localPrincipal);
                     assertNotNull(socket);
                     assertSame(client, socket);
                     assertNull(socket.getHandshakeSession());
+                    if (TestUtils.isJavaxCertificateSupported()) {
+                        javax.security.cert.X509Certificate[] peerCertificateChain =
+                                event.getPeerCertificateChain();
+                        assertNotNull(peerCertificateChain);
+                        TestKeyStore.assertChainLength(peerCertificateChain);
+                        assertNotNull(peerCertificateChain[0]);
+                        TestSSLContext.assertCertificateInKeyStore(
+                                peerCertificateChain[0].getSubjectDN(), c.serverKeyStore);
+                    }
                 } catch (RuntimeException e) {
                     throw e;
                 } catch (Exception e) {
@@ -485,19 +462,11 @@ public class SSLSocketVersionCompatibilityTest {
         final SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                server.startHandshake();
-                return null;
-            }
-        });
-        client.addHandshakeCompletedListener(new HandshakeCompletedListener() {
-            @Override
-            public void handshakeCompleted(HandshakeCompletedEvent event) {
-                throw expectedException;
-            }
+        Future<Void> future = runAsync(() -> {
+            server.startHandshake();
+            return null;
         });
+        client.addHandshakeCompletedListener(event -> { throw expectedException; });
         client.startHandshake();
         future.get();
         client.close();
@@ -550,7 +519,7 @@ public class SSLSocketVersionCompatibilityTest {
         } catch (SSLHandshakeException expected) {
             // Depending on the timing of the socket closures, this can happen as well.
             assertTrue("Unexpected handshake error: " + expected.getMessage(),
-                    expected.getMessage().toLowerCase().contains("connection closed"));
+                    expected.getMessage().toLowerCase(Locale.ROOT).contains("connection closed"));
         }
     }
 
@@ -563,21 +532,16 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<IOException> future = runAsync(new Callable<IOException>() {
-            @Override
-            public IOException call() throws Exception {
-                try {
-                    if (!serverClientMode) {
-                        server.setSoTimeout(1000);
-                    }
-                    server.setUseClientMode(serverClientMode);
-                    server.startHandshake();
-                    return null;
-                } catch (SSLHandshakeException e) {
-                    return e;
-                } catch (SocketTimeoutException e) {
-                    return e;
+        Future<IOException> future = runAsync(() -> {
+            try {
+                if (!serverClientMode) {
+                    server.setSoTimeout(1000);
                 }
+                server.setUseClientMode(serverClientMode);
+                server.startHandshake();
+                return null;
+            } catch (SSLHandshakeException | SocketTimeoutException e) {
+                return e;
             }
         });
         if (!clientClientMode) {
@@ -605,26 +569,23 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                assertFalse(server.getWantClientAuth());
-                assertFalse(server.getNeedClientAuth());
-                // confirm turning one on by itself
-                server.setWantClientAuth(true);
-                assertTrue(server.getWantClientAuth());
-                assertFalse(server.getNeedClientAuth());
-                // confirm turning setting on toggles the other
-                server.setNeedClientAuth(true);
-                assertFalse(server.getWantClientAuth());
-                assertTrue(server.getNeedClientAuth());
-                // confirm toggling back
-                server.setWantClientAuth(true);
-                assertTrue(server.getWantClientAuth());
-                assertFalse(server.getNeedClientAuth());
-                server.startHandshake();
-                return null;
-            }
+        Future<Void> future = runAsync(() -> {
+            assertFalse(server.getWantClientAuth());
+            assertFalse(server.getNeedClientAuth());
+            // confirm turning one on by itself
+            server.setWantClientAuth(true);
+            assertTrue(server.getWantClientAuth());
+            assertFalse(server.getNeedClientAuth());
+            // confirm turning setting on toggles the other
+            server.setNeedClientAuth(true);
+            assertFalse(server.getWantClientAuth());
+            assertTrue(server.getNeedClientAuth());
+            // confirm toggling back
+            server.setWantClientAuth(true);
+            assertTrue(server.getWantClientAuth());
+            assertFalse(server.getNeedClientAuth());
+            server.startHandshake();
+            return null;
         });
         client.startHandshake();
         assertNotNull(client.getSession().getLocalCertificates());
@@ -687,18 +648,15 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    server.setNeedClientAuth(true);
-                    server.startHandshake();
-                    fail();
-                } catch (SSLHandshakeException expected) {
-                    // Ignored.
-                }
-                return null;
+        Future<Void> future = runAsync(() -> {
+            try {
+                server.setNeedClientAuth(true);
+                server.startHandshake();
+                fail();
+            } catch (SSLHandshakeException expected) {
+                // Ignored.
             }
+            return null;
         });
         try {
             client.startHandshake();
@@ -788,13 +746,10 @@ public class SSLSocketVersionCompatibilityTest {
             SSLSocket client =
                     (SSLSocket) clientContext.getSocketFactory().createSocket(c.host, c.port);
             final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-            Future<Void> future = runAsync(new Callable<Void>() {
-                @Override
-                public Void call() throws Exception {
-                    server.setNeedClientAuth(true);
-                    server.startHandshake();
-                    return null;
-                }
+            Future<Void> future = runAsync(() -> {
+                server.setNeedClientAuth(true);
+                server.startHandshake();
+                return null;
             });
             client.startHandshake();
             assertNotNull(client.getSession().getLocalCertificates());
@@ -819,13 +774,11 @@ public class SSLSocketVersionCompatibilityTest {
         SSLContext clientContext = SSLContext.getInstance("TLS");
         X509TrustManager trustManager = new X509TrustManager() {
             @Override
-            public void checkClientTrusted(X509Certificate[] chain, String authType)
-                    throws CertificateException {
+            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                 throw new AssertionError();
             }
             @Override
-            public void checkServerTrusted(X509Certificate[] chain, String authType)
-                    throws CertificateException {
+            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                 throw new RuntimeException(); // throw a RuntimeException from custom TrustManager
             }
             @Override
@@ -837,17 +790,14 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    server.startHandshake();
-                    fail();
-                } catch (SSLHandshakeException expected) {
-                    // Ignored.
-                }
-                return null;
+        Future<Void> future = runAsync(() -> {
+            try {
+                server.startHandshake();
+                fail();
+            } catch (SSLHandshakeException expected) {
+                // Ignored.
             }
+            return null;
         });
         try {
             client.startHandshake();
@@ -886,18 +836,15 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                server.setEnableSessionCreation(false);
-                try {
-                    server.startHandshake();
-                    fail();
-                } catch (SSLException expected) {
-                    // Ignored.
-                }
-                return null;
+        Future<Void> future = runAsync(() -> {
+            server.setEnableSessionCreation(false);
+            try {
+                server.startHandshake();
+                fail();
+            } catch (SSLException expected) {
+                // Ignored.
             }
+            return null;
         });
         try {
             client.startHandshake();
@@ -920,17 +867,14 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket client =
                 (SSLSocket) c.clientContext.getSocketFactory().createSocket(c.host, c.port);
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    server.startHandshake();
-                    fail();
-                } catch (SSLException expected) {
-                    // Ignored.
-                }
-                return null;
+        Future<Void> future = runAsync(() -> {
+            try {
+                server.startHandshake();
+                fail();
+            } catch (SSLException expected) {
+                // Ignored.
             }
+            return null;
         });
         client.setEnableSessionCreation(false);
         try {
@@ -966,11 +910,7 @@ public class SSLSocketVersionCompatibilityTest {
         server.close();
         client.close();
         // ...so are a lot of other operations...
-        HandshakeCompletedListener l = new HandshakeCompletedListener() {
-            @Override
-            public void handshakeCompleted(HandshakeCompletedEvent e) {
-            }
-        };
+        HandshakeCompletedListener l = e -> {};
         client.addHandshakeCompletedListener(l);
         assertNotNull(client.getEnabledCipherSuites());
         assertNotNull(client.getEnabledProtocols());
@@ -1018,9 +958,7 @@ public class SSLSocketVersionCompatibilityTest {
             @SuppressWarnings("unused")
             int bytesRead = input.read(null, -1, -1);
             fail();
-        } catch (NullPointerException expected) {
-            // Ignored.
-        } catch (SocketException expected) {
+        } catch (NullPointerException | SocketException expected) {
             // Ignored.
         }
         try {
@@ -1032,9 +970,7 @@ public class SSLSocketVersionCompatibilityTest {
         try {
             output.write(null, -1, -1);
             fail();
-        } catch (NullPointerException expected) {
-            // Ignored.
-        } catch (SocketException expected) {
+        } catch (NullPointerException | SocketException expected) {
             // Ignored.
         }
         // ... and one gives IllegalArgumentException
@@ -1173,17 +1109,14 @@ public class SSLSocketVersionCompatibilityTest {
         final Socket underlying = new Socket(c.host, c.port);
         final SSLSocket wrapping = (SSLSocket) c.clientContext.getSocketFactory().createSocket(
                 underlying, c.host.getHostName(), c.port, false);
-        Future<Void> clientFuture = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                wrapping.startHandshake();
-                wrapping.getOutputStream().write(42);
-                // close the underlying socket,
-                // so that no SSL shutdown is sent
-                underlying.close();
-                wrapping.close();
-                return null;
-            }
+        Future<Void> clientFuture = runAsync(() -> {
+            wrapping.startHandshake();
+            wrapping.getOutputStream().write(42);
+            // close the underlying socket,
+            // so that no SSL shutdown is sent
+            underlying.close();
+            wrapping.close();
+            return null;
         });
         SSLSocket server = (SSLSocket) c.serverSocket.accept();
         server.startHandshake();
@@ -1214,25 +1147,21 @@ public class SSLSocketVersionCompatibilityTest {
             client.setSSLParameters(p);
             client.connect(new InetSocketAddress(c.host, c.port));
             final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-            Future<Void> future = runAsync(new Callable<Void>() {
-                @Override
-                public Void call() throws Exception {
-                    server.startHandshake();
-                    assertNotNull(server.getSession());
-                    try {
-                        server.getSession().getPeerCertificates();
-                        fail();
-                    } catch (SSLPeerUnverifiedException expected) {
-                        // Ignored.
-                    }
-                    Certificate[] localCertificates = server.getSession().getLocalCertificates();
-                    assertNotNull(localCertificates);
-                    TestKeyStore.assertChainLength(localCertificates);
-                    assertNotNull(localCertificates[0]);
-                    TestSSLContext
-                            .assertCertificateInKeyStore(localCertificates[0], c.serverKeyStore);
-                    return null;
+            Future<Void> future = runAsync(() -> {
+                server.startHandshake();
+                assertNotNull(server.getSession());
+                try {
+                    server.getSession().getPeerCertificates();
+                    fail();
+                } catch (SSLPeerUnverifiedException expected) {
+                    // Ignored.
                 }
+                Certificate[] localCertificates = server.getSession().getLocalCertificates();
+                assertNotNull(localCertificates);
+                TestKeyStore.assertChainLength(localCertificates);
+                assertNotNull(localCertificates[0]);
+                TestSSLContext.assertCertificateInKeyStore(localCertificates[0], c.serverKeyStore);
+                return null;
             });
             client.startHandshake();
             assertNotNull(client.getSession());
@@ -1269,17 +1198,14 @@ public class SSLSocketVersionCompatibilityTest {
             client.setSSLParameters(p);
             client.connect(c.getLoopbackAsHostname("unmatched.example.com", c.port));
             final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-            Future<Void> future = runAsync(new Callable<Void>() {
-                @Override
-                public Void call() throws Exception {
-                    try {
-                        server.startHandshake();
-                        fail("Should receive SSLHandshakeException as server");
-                    } catch (SSLHandshakeException expected) {
-                        // Ignored.
-                    }
-                    return null;
+            Future<Void> future = runAsync(() -> {
+                try {
+                    server.startHandshake();
+                    fail("Should receive SSLHandshakeException as server");
+                } catch (SSLHandshakeException expected) {
+                    // Ignored.
                 }
+                return null;
             });
             try {
                 client.startHandshake();
@@ -1329,12 +1255,9 @@ public class SSLSocketVersionCompatibilityTest {
 
         // Start the handshake.
         final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                client.startHandshake();
-                return null;
-            }
+        Future<Void> future = runAsync(() -> {
+            client.startHandshake();
+            return null;
         });
         server.startHandshake();
 
@@ -1394,12 +1317,9 @@ public class SSLSocketVersionCompatibilityTest {
             assertTrue(isConscryptSocket(server));
             setNpnProtocols.invoke(server, npnProtocols);
 
-            Future<Void> future = executor.submit(new Callable<Void>() {
-                @Override
-                public Void call() throws Exception {
-                    server.startHandshake();
-                    return null;
-                }
+            Future<Void> future = executor.submit(() -> {
+                server.startHandshake();
+                return null;
             });
             client.startHandshake();
 
@@ -1421,12 +1341,9 @@ public class SSLSocketVersionCompatibilityTest {
 
             final SSLSocket server = (SSLSocket) serverSocket.accept();
 
-            Future<Void> future = executor.submit(new Callable<Void>() {
-                @Override
-                public Void call() throws Exception {
-                    server.startHandshake();
-                    return null;
-                }
+            Future<Void> future = executor.submit(() -> {
+                server.startHandshake();
+                return null;
             });
             client.startHandshake();
 
@@ -1484,12 +1401,9 @@ public class SSLSocketVersionCompatibilityTest {
         SSLSocket server = (SSLSocket) c.serverSocket.accept();
 
         // Start the handshake.
-        Future<Integer> handshakeFuture = runAsync(new Callable<Integer>() {
-            @Override
-            public Integer call() throws Exception {
-                clientWrapping.startHandshake();
-                return clientWrapping.getInputStream().read();
-            }
+        Future<Integer> handshakeFuture = runAsync(() -> {
+            clientWrapping.startHandshake();
+            return clientWrapping.getInputStream().read();
         });
         server.startHandshake();
         // TLS 1.3 sends some post-handshake management messages, so send a single byte through
@@ -1501,13 +1415,10 @@ public class SSLSocketVersionCompatibilityTest {
         final Socket toClose = closeUnderlying ? underlying : clientWrapping;
 
         // Schedule the socket to be closed in 1 second.
-        Future<Void> future = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                Thread.sleep(1000);
-                toClose.close();
-                return null;
-            }
+        Future<Void> future = runAsync(() -> {
+            Thread.sleep(1000);
+            toClose.close();
+            return null;
         });
 
         // Read from the socket.
@@ -1555,21 +1466,18 @@ public class SSLSocketVersionCompatibilityTest {
         // TODO(nmittler): Interrupts do not work with the engine-based socket.
         assumeFalse(isConscryptEngineSocket(wrapping));
 
-        Future<Void> clientFuture = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                wrapping.startHandshake();
-                try {
-                    wrapping.setSoTimeout(readingTimeoutMillis);
-                    wrapping.getInputStream().read();
-                    fail();
-                } catch (SocketException expected) {
-                    // Conscrypt throws an exception complaining that the socket is closed
-                    // if it's interrupted by a close() in the middle of a read()
-                    assertTrue(expected.getMessage().contains("closed"));
-                }
-                return null;
+        Future<Void> clientFuture = runAsync(() -> {
+            wrapping.startHandshake();
+            try {
+                wrapping.setSoTimeout(readingTimeoutMillis);
+                wrapping.getInputStream().read();
+                fail();
+            } catch (SocketException expected) {
+                // Conscrypt throws an exception complaining that the socket is closed
+                // if it's interrupted by a close() in the middle of a read()
+                assertTrue(expected.getMessage().contains("closed"));
             }
+            return null;
         });
         SSLSocket server = (SSLSocket) c.serverSocket.accept();
         server.startHandshake();
@@ -1600,7 +1508,7 @@ public class SSLSocketVersionCompatibilityTest {
         server.close();
     }
 
-    /**
+    /*
      * Test to confirm that an SSLSocket.close() on one
      * thread will interrupt another thread blocked writing on the same
      * socket.
@@ -1613,7 +1521,7 @@ public class SSLSocketVersionCompatibilityTest {
      * See also b/147323301 where close() triggered an infinite loop instead.
      */
     @Test
-    @Ignore
+    @Ignore("See comment above")
     public void test_SSLSocket_interrupt_write_withAutoclose() throws Exception {
         final TestSSLContext c = new TestSSLContext.Builder()
                                          .clientProtocol(clientVersion)
@@ -1626,22 +1534,19 @@ public class SSLSocketVersionCompatibilityTest {
 
         // TODO(b/161347005): Re-enable once engine-based socket interruption works correctly.
         assumeFalse(isConscryptEngineSocket(wrapping));
-        Future<Void> clientFuture = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                wrapping.startHandshake();
-                try {
-                    for (int i = 0; i < 64; i++) {
-                        wrapping.getOutputStream().write(data);
-                    }
-                    // Failure here means that no exception was thrown, so the data buffer is
-                    // probably too small.
-                    fail();
-                } catch (SocketException expected) {
-                    assertTrue(expected.getMessage().contains("closed"));
+        Future<Void> clientFuture = runAsync(() -> {
+            wrapping.startHandshake();
+            try {
+                for (int i = 0; i < 64; i++) {
+                    wrapping.getOutputStream().write(data);
                 }
-                return null;
+                // Failure here means that no exception was thrown, so the data buffer is
+                // probably too small.
+                fail();
+            } catch (SocketException expected) {
+                assertTrue(expected.getMessage().contains("closed"));
             }
+            return null;
         });
         SSLSocket server = (SSLSocket) c.serverSocket.accept();
         server.startHandshake();
@@ -1691,18 +1596,15 @@ public class SSLSocketVersionCompatibilityTest {
 
     @Test
     public void test_SSLSocket_ClientHello_SNI() throws Exception {
-        ForEachRunner.runNamed(new ForEachRunner.Callback<SSLSocketFactory>() {
-            @Override
-            public void run(SSLSocketFactory sslSocketFactory) throws Exception {
-                ClientHello clientHello = TlsTester
-                    .captureTlsHandshakeClientHello(executor, sslSocketFactory);
-                ServerNameHelloExtension sniExtension =
+        ForEachRunner.runNamed(sslSocketFactory -> {
+            ClientHello clientHello =
+                    TlsTester.captureTlsHandshakeClientHello(executor, sslSocketFactory);
+            ServerNameHelloExtension sniExtension =
                     (ServerNameHelloExtension) clientHello.findExtensionByType(
-                        HelloExtension.TYPE_SERVER_NAME);
-                assertNotNull(sniExtension);
-                assertEquals(
+                            HelloExtension.TYPE_SERVER_NAME);
+            assertNotNull(sniExtension);
+            assertEquals(
                     Collections.singletonList("localhost.localdomain"), sniExtension.hostnames);
-            }
         }, getSSLSocketFactoriesToTest());
     }
 
@@ -1710,29 +1612,25 @@ public class SSLSocketVersionCompatibilityTest {
     public void test_SSLSocket_ClientHello_ALPN() throws Exception {
         final String[] protocolList = new String[] { "h2", "http/1.1" };
 
-        ForEachRunner.runNamed(new ForEachRunner.Callback<SSLSocketFactory>() {
-            @Override
-            public void run(SSLSocketFactory sslSocketFactory) throws Exception {
-                ClientHello clientHello = TlsTester.captureTlsHandshakeClientHello(executor,
-                        new DelegatingSSLSocketFactory(sslSocketFactory) {
-                            @Override public SSLSocket configureSocket(SSLSocket socket) {
-                                Conscrypt.setApplicationProtocols(socket, protocolList);
-                                return socket;
-                            }
-                        });
-                AlpnHelloExtension alpnExtension =
-                        (AlpnHelloExtension) clientHello.findExtensionByType(
-                                HelloExtension.TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
-                assertNotNull(alpnExtension);
-                assertEquals(Arrays.asList(protocolList), alpnExtension.protocols);
-            }
+        ForEachRunner.runNamed(sslSocketFactory -> {
+            ClientHello clientHello = TlsTester.captureTlsHandshakeClientHello(
+                    executor, new DelegatingSSLSocketFactory(sslSocketFactory) {
+                        @Override
+                        public SSLSocket configureSocket(SSLSocket socket) {
+                            Conscrypt.setApplicationProtocols(socket, protocolList);
+                            return socket;
+                        }
+                    });
+            AlpnHelloExtension alpnExtension = (AlpnHelloExtension) clientHello.findExtensionByType(
+                    HelloExtension.TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
+            assertNotNull(alpnExtension);
+            assertEquals(Arrays.asList(protocolList), alpnExtension.protocols);
         }, getSSLSocketFactoriesToTest());
     }
 
     private List<Pair<String, SSLSocketFactory>> getSSLSocketFactoriesToTest()
             throws NoSuchAlgorithmException, KeyManagementException {
-        List<Pair<String, SSLSocketFactory>> result =
-                new ArrayList<Pair<String, SSLSocketFactory>>();
+        List<Pair<String, SSLSocketFactory>> result = new ArrayList<>();
         result.add(Pair.of("default", (SSLSocketFactory) SSLSocketFactory.getDefault()));
         for (String sslContextProtocol : StandardNames.SSL_CONTEXT_PROTOCOLS) {
             SSLContext sslContext = SSLContext.getInstance(sslContextProtocol);
@@ -1753,14 +1651,12 @@ public class SSLSocketVersionCompatibilityTest {
                 .clientProtocol(clientVersion)
                 .serverProtocol(serverVersion)
                 .build();
-        SSLSocket client =
-            (SSLSocket) context.clientContext.getSocketFactory().createSocket();
-        try {
+        try (SSLSocket client =
+                        (SSLSocket) context.clientContext.getSocketFactory().createSocket()) {
             client.connect(new InetSocketAddress(context.host, context.port));
             setHostname(client);
             assertTrue(client.getPort() > 0);
         } finally {
-            client.close();
             context.close();
         }
     }
@@ -1772,26 +1668,25 @@ public class SSLSocketVersionCompatibilityTest {
                 .clientProtocol(clientVersion)
                 .serverProtocol(serverVersion)
                 .build();
-        final SSLSocket client = (SSLSocket) c.clientContext.getSocketFactory().createSocket();
-        SSLParameters clientParams = client.getSSLParameters();
-        clientParams.setServerNames(
-                Collections.singletonList((SNIServerName) new SNIHostName("www.example.com")));
-        client.setSSLParameters(clientParams);
-        SSLParameters serverParams = c.serverSocket.getSSLParameters();
-        serverParams.setSNIMatchers(
-                Collections.singletonList(SNIHostName.createSNIMatcher("www\\.example\\.com")));
-        c.serverSocket.setSSLParameters(serverParams);
-        client.connect(new InetSocketAddress(c.host, c.port));
-        final SSLSocket server = (SSLSocket) c.serverSocket.accept();
-        @SuppressWarnings("unused")
-        Future<?> future = runAsync(new Callable<Object>() {
-            @Override
-            public Object call() throws Exception {
+        final SSLSocket server;
+        try (SSLSocket client = (SSLSocket) c.clientContext.getSocketFactory().createSocket()) {
+            SSLParameters clientParams = client.getSSLParameters();
+            clientParams.setServerNames(
+                    Collections.singletonList(new SNIHostName("www.example.com")));
+            client.setSSLParameters(clientParams);
+            SSLParameters serverParams = c.serverSocket.getSSLParameters();
+            serverParams.setSNIMatchers(
+                    Collections.singletonList(SNIHostName.createSNIMatcher("www\\.example\\.com")));
+            c.serverSocket.setSSLParameters(serverParams);
+            client.connect(new InetSocketAddress(c.host, c.port));
+            server = (SSLSocket) c.serverSocket.accept();
+            @SuppressWarnings("unused")
+            Future<?> future = runAsync(() -> {
                 client.startHandshake();
                 return null;
-            }
-        });
-        server.startHandshake();
+            });
+            server.startHandshake();
+        }
         SSLSession serverSession = server.getSession();
         assertTrue(serverSession instanceof ExtendedSSLSession);
         ExtendedSSLSession extendedServerSession = (ExtendedSSLSession) serverSession;
@@ -1803,6 +1698,7 @@ public class SSLSocketVersionCompatibilityTest {
         assertTrue(serverName instanceof SNIHostName);
         SNIHostName serverHostName = (SNIHostName) serverName;
         assertEquals("www.example.com", serverHostName.getAsciiName());
+        server.close();
     }
 
     @Test
@@ -1816,35 +1712,26 @@ public class SSLSocketVersionCompatibilityTest {
         final SSLSocket client = (SSLSocket) context.clientContext.getSocketFactory().createSocket(
                 context.host, listener.getLocalPort());
         final Socket server = listener.accept();
-        Future<Void> c = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    client.startHandshake();
-                    fail("Should receive handshake exception");
-                } catch (SSLHandshakeException expected) {
-                    assertFalse(expected.getMessage().contains("SSL_ERROR_ZERO_RETURN"));
-                    assertFalse(expected.getMessage().contains("You should never see this."));
-                }
-                return null;
+        Future<Void> c = runAsync(() -> {
+            try {
+                client.startHandshake();
+                fail("Should receive handshake exception");
+            } catch (SSLHandshakeException expected) {
+                assertFalse(expected.getMessage().contains("SSL_ERROR_ZERO_RETURN"));
+                assertFalse(expected.getMessage().contains("You should never see this."));
             }
+            return null;
         });
-        Future<Void> s = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                // Wait until the client sends something.
-                byte[] scratch = new byte[8192];
-                @SuppressWarnings("unused")
-                int bytesRead = server.getInputStream().read(scratch);
-                // Write a bogus TLS alert:
-                // TLSv1.2 Record Layer: Alert (Level: Warning, Description: Protocol Version)
-                server.getOutputStream()
-                    .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x46});
-                // TLSv1.2 Record Layer: Alert (Level: Warning, Description: Close Notify)
-                server.getOutputStream()
-                    .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00});
-                return null;
-            }
+        Future<Void> s = runAsync(() -> {
+            // Wait until the client sends something.
+            byte[] scratch = new byte[8192];
+            @SuppressWarnings("unused") int bytesRead = server.getInputStream().read(scratch);
+            // Write a bogus TLS alert:
+            // TLSv1.2 Record Layer: Alert (Level: Warning, Description: Protocol Version)
+            server.getOutputStream().write(new byte[] {0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x46});
+            // TLSv1.2 Record Layer: Alert (Level: Warning, Description: Close Notify)
+            server.getOutputStream().write(new byte[] {0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00});
+            return null;
         });
         c.get(5, TimeUnit.SECONDS);
         s.get(5, TimeUnit.SECONDS);
@@ -1863,79 +1750,222 @@ public class SSLSocketVersionCompatibilityTest {
                 .build();
         final Socket client = SocketFactory.getDefault().createSocket(context.host, context.port);
         final SSLSocket server = (SSLSocket) context.serverSocket.accept();
-        Future<Void> s = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                try {
-                    server.startHandshake();
-                    fail("Should receive handshake exception");
-                } catch (SSLHandshakeException expected) {
-                    assertFalse(expected.getMessage().contains("SSL_ERROR_ZERO_RETURN"));
-                    assertFalse(expected.getMessage().contains("You should never see this."));
-                }
-                return null;
+        Future<Void> s = runAsync(() -> {
+            try {
+                server.startHandshake();
+                fail("Should receive handshake exception");
+            } catch (SSLHandshakeException expected) {
+                assertFalse(expected.getMessage().contains("SSL_ERROR_ZERO_RETURN"));
+                assertFalse(expected.getMessage().contains("You should never see this."));
             }
+            return null;
         });
-        Future<Void> c = runAsync(new Callable<Void>() {
-            @Override
-            public Void call() throws Exception {
-                // Send bogus ClientHello:
-                // TLSv1.2 Record Layer: Handshake Protocol: Client Hello
-                client.getOutputStream().write(new byte[]{
-                    (byte) 0x16, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0xb9,
-                    (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0xb5, (byte) 0x03,
-                    (byte) 0x03, (byte) 0x5a, (byte) 0x31, (byte) 0xba, (byte) 0x44,
-                    (byte) 0x24, (byte) 0xfd, (byte) 0xf0, (byte) 0x56, (byte) 0x46,
-                    (byte) 0xea, (byte) 0xee, (byte) 0x1c, (byte) 0x62, (byte) 0x8f,
-                    (byte) 0x18, (byte) 0x04, (byte) 0xbd, (byte) 0x1c, (byte) 0xbc,
-                    (byte) 0xbf, (byte) 0x6d, (byte) 0x84, (byte) 0x12, (byte) 0xe9,
-                    (byte) 0x94, (byte) 0xf5, (byte) 0x1c, (byte) 0x15, (byte) 0x3e,
-                    (byte) 0x79, (byte) 0x01, (byte) 0xe2, (byte) 0x00, (byte) 0x00,
-                    (byte) 0x28, (byte) 0xc0, (byte) 0x2b, (byte) 0xc0, (byte) 0x2c,
-                    (byte) 0xc0, (byte) 0x2f, (byte) 0xc0, (byte) 0x30, (byte) 0x00,
-                    (byte) 0x9e, (byte) 0x00, (byte) 0x9f, (byte) 0xc0, (byte) 0x09,
-                    (byte) 0xc0, (byte) 0x0a, (byte) 0xc0, (byte) 0x13, (byte) 0xc0,
-                    (byte) 0x14, (byte) 0x00, (byte) 0x33, (byte) 0x00, (byte) 0x39,
-                    (byte) 0xc0, (byte) 0x07, (byte) 0xc0, (byte) 0x11, (byte) 0x00,
-                    (byte) 0x9c, (byte) 0x00, (byte) 0x9d, (byte) 0x00, (byte) 0x2f,
-                    (byte) 0x00, (byte) 0x35, (byte) 0x00, (byte) 0x05, (byte) 0x00,
-                    (byte) 0xff, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x64,
-                    (byte) 0x00, (byte) 0x0b, (byte) 0x00, (byte) 0x04, (byte) 0x03,
-                    (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x00, (byte) 0x0a,
-                    (byte) 0x00, (byte) 0x34, (byte) 0x00, (byte) 0x32, (byte) 0x00,
-                    (byte) 0x0e, (byte) 0x00, (byte) 0x0d, (byte) 0x00, (byte) 0x19,
-                    (byte) 0x00, (byte) 0x0b, (byte) 0x00, (byte) 0x0c, (byte) 0x00,
-                    (byte) 0x18, (byte) 0x00, (byte) 0x09, (byte) 0x00, (byte) 0x0a,
-                    (byte) 0x00, (byte) 0x16, (byte) 0x00, (byte) 0x17, (byte) 0x00,
-                    (byte) 0x08, (byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x07,
-                    (byte) 0x00, (byte) 0x14, (byte) 0x00, (byte) 0x15, (byte) 0x00,
-                    (byte) 0x04, (byte) 0x00, (byte) 0x05, (byte) 0x00, (byte) 0x12,
-                    (byte) 0x00, (byte) 0x13, (byte) 0x00, (byte) 0x01, (byte) 0x00,
-                    (byte) 0x02, (byte) 0x00, (byte) 0x03, (byte) 0x00, (byte) 0x0f,
-                    (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x11, (byte) 0x00,
-                    (byte) 0x0d, (byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x1e,
-                    (byte) 0x06, (byte) 0x01, (byte) 0x06, (byte) 0x02, (byte) 0x06,
-                    (byte) 0x03, (byte) 0x05, (byte) 0x01, (byte) 0x05, (byte) 0x02,
-                    (byte) 0x05, (byte) 0x03, (byte) 0x04, (byte) 0x01, (byte) 0x04,
-                    (byte) 0x02, (byte) 0x04, (byte) 0x03, (byte) 0x03, (byte) 0x01,
-                    (byte) 0x03, (byte) 0x02, (byte) 0x03, (byte) 0x03, (byte) 0x02,
-                    (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x03,
-                });
-                // Wait until the server sends something.
-                byte[] scratch = new byte[8192];
-                @SuppressWarnings("unused")
-                int bytesRead = client.getInputStream().read(scratch);
-                // Write a bogus TLS alert:
-                // TLSv1.2 Record Layer: Alert (Level: Warning, Description:
-                // Protocol Version)
-                client.getOutputStream()
-                    .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x46});
-                // TLSv1.2 Record Layer: Alert (Level: Warning, Description:
-                // Close Notify)
-                client.getOutputStream()
-                    .write(new byte[]{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00});
-                return null;
-            }
+        Future<Void> c = runAsync(() -> {
+            // Send bogus ClientHello:
+            // TLSv1.2 Record Layer: Handshake Protocol: Client Hello
+            client.getOutputStream().write(new byte[] {
+                    (byte) 0x16,
+                    (byte) 0x03,
+                    (byte) 0x01,
+                    (byte) 0x00,
+                    (byte) 0xb9,
+                    (byte) 0x01,
+                    (byte) 0x00,
+                    (byte) 0x00,
+                    (byte) 0xb5,
+                    (byte) 0x03,
+                    (byte) 0x03,
+                    (byte) 0x5a,
+                    (byte) 0x31,
+                    (byte) 0xba,
+                    (byte) 0x44,
+                    (byte) 0x24,
+                    (byte) 0xfd,
+                    (byte) 0xf0,
+                    (byte) 0x56,
+                    (byte) 0x46,
+                    (byte) 0xea,
+                    (byte) 0xee,
+                    (byte) 0x1c,
+                    (byte) 0x62,
+                    (byte) 0x8f,
+                    (byte) 0x18,
+                    (byte) 0x04,
+                    (byte) 0xbd,
+                    (byte) 0x1c,
+                    (byte) 0xbc,
+                    (byte) 0xbf,
+                    (byte) 0x6d,
+                    (byte) 0x84,
+                    (byte) 0x12,
+                    (byte) 0xe9,
+                    (byte) 0x94,
+                    (byte) 0xf5,
+                    (byte) 0x1c,
+                    (byte) 0x15,
+                    (byte) 0x3e,
+                    (byte) 0x79,
+                    (byte) 0x01,
+                    (byte) 0xe2,
+                    (byte) 0x00,
+                    (byte) 0x00,
+                    (byte) 0x28,
+                    (byte) 0xc0,
+                    (byte) 0x2b,
+                    (byte) 0xc0,
+                    (byte) 0x2c,
+                    (byte) 0xc0,
+                    (byte) 0x2f,
+                    (byte) 0xc0,
+                    (byte) 0x30,
+                    (byte) 0x00,
+                    (byte) 0x9e,
+                    (byte) 0x00,
+                    (byte) 0x9f,
+                    (byte) 0xc0,
+                    (byte) 0x09,
+                    (byte) 0xc0,
+                    (byte) 0x0a,
+                    (byte) 0xc0,
+                    (byte) 0x13,
+                    (byte) 0xc0,
+                    (byte) 0x14,
+                    (byte) 0x00,
+                    (byte) 0x33,
+                    (byte) 0x00,
+                    (byte) 0x39,
+                    (byte) 0xc0,
+                    (byte) 0x07,
+                    (byte) 0xc0,
+                    (byte) 0x11,
+                    (byte) 0x00,
+                    (byte) 0x9c,
+                    (byte) 0x00,
+                    (byte) 0x9d,
+                    (byte) 0x00,
+                    (byte) 0x2f,
+                    (byte) 0x00,
+                    (byte) 0x35,
+                    (byte) 0x00,
+                    (byte) 0x05,
+                    (byte) 0x00,
+                    (byte) 0xff,
+                    (byte) 0x01,
+                    (byte) 0x00,
+                    (byte) 0x00,
+                    (byte) 0x64,
+                    (byte) 0x00,
+                    (byte) 0x0b,
+                    (byte) 0x00,
+                    (byte) 0x04,
+                    (byte) 0x03,
+                    (byte) 0x00,
+                    (byte) 0x01,
+                    (byte) 0x02,
+                    (byte) 0x00,
+                    (byte) 0x0a,
+                    (byte) 0x00,
+                    (byte) 0x34,
+                    (byte) 0x00,
+                    (byte) 0x32,
+                    (byte) 0x00,
+                    (byte) 0x0e,
+                    (byte) 0x00,
+                    (byte) 0x0d,
+                    (byte) 0x00,
+                    (byte) 0x19,
+                    (byte) 0x00,
+                    (byte) 0x0b,
+                    (byte) 0x00,
+                    (byte) 0x0c,
+                    (byte) 0x00,
+                    (byte) 0x18,
+                    (byte) 0x00,
+                    (byte) 0x09,
+                    (byte) 0x00,
+                    (byte) 0x0a,
+                    (byte) 0x00,
+                    (byte) 0x16,
+                    (byte) 0x00,
+                    (byte) 0x17,
+                    (byte) 0x00,
+                    (byte) 0x08,
+                    (byte) 0x00,
+                    (byte) 0x06,
+                    (byte) 0x00,
+                    (byte) 0x07,
+                    (byte) 0x00,
+                    (byte) 0x14,
+                    (byte) 0x00,
+                    (byte) 0x15,
+                    (byte) 0x00,
+                    (byte) 0x04,
+                    (byte) 0x00,
+                    (byte) 0x05,
+                    (byte) 0x00,
+                    (byte) 0x12,
+                    (byte) 0x00,
+                    (byte) 0x13,
+                    (byte) 0x00,
+                    (byte) 0x01,
+                    (byte) 0x00,
+                    (byte) 0x02,
+                    (byte) 0x00,
+                    (byte) 0x03,
+                    (byte) 0x00,
+                    (byte) 0x0f,
+                    (byte) 0x00,
+                    (byte) 0x10,
+                    (byte) 0x00,
+                    (byte) 0x11,
+                    (byte) 0x00,
+                    (byte) 0x0d,
+                    (byte) 0x00,
+                    (byte) 0x20,
+                    (byte) 0x00,
+                    (byte) 0x1e,
+                    (byte) 0x06,
+                    (byte) 0x01,
+                    (byte) 0x06,
+                    (byte) 0x02,
+                    (byte) 0x06,
+                    (byte) 0x03,
+                    (byte) 0x05,
+                    (byte) 0x01,
+                    (byte) 0x05,
+                    (byte) 0x02,
+                    (byte) 0x05,
+                    (byte) 0x03,
+                    (byte) 0x04,
+                    (byte) 0x01,
+                    (byte) 0x04,
+                    (byte) 0x02,
+                    (byte) 0x04,
+                    (byte) 0x03,
+                    (byte) 0x03,
+                    (byte) 0x01,
+                    (byte) 0x03,
+                    (byte) 0x02,
+                    (byte) 0x03,
+                    (byte) 0x03,
+                    (byte) 0x02,
+                    (byte) 0x01,
+                    (byte) 0x02,
+                    (byte) 0x02,
+                    (byte) 0x02,
+                    (byte) 0x03,
+            });
+            // Wait until the server sends something.
+            byte[] scratch = new byte[8192];
+            @SuppressWarnings("unused") int bytesRead = client.getInputStream().read(scratch);
+            // Write a bogus TLS alert:
+            // TLSv1.2 Record Layer: Alert (Level: Warning, Description:
+            // Protocol Version)
+            client.getOutputStream().write(new byte[] {0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x46});
+            // TLSv1.2 Record Layer: Alert (Level: Warning, Description:
+            // Close Notify)
+            client.getOutputStream().write(new byte[] {0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00});
+            return null;
         });
         c.get(5, TimeUnit.SECONDS);
         s.get(5, TimeUnit.SECONDS);
@@ -1951,76 +1981,15 @@ public class SSLSocketVersionCompatibilityTest {
                 .clientProtocol(clientVersion)
                 .serverProtocol(serverVersion)
                 .build();
-        final SSLSocket client =
-                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
-        client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1"});
-        assertEquals(2, client.getEnabledProtocols().length);
-    }
-
-    @TargetSdkVersion(35)
-    @Test
-    public void test_SSLSocket_SSLv3Unsupported_35() throws Exception {
-        assumeFalse(isTlsV1Filtered());
-        TestSSLContext context = new TestSSLContext.Builder()
-                .clientProtocol(clientVersion)
-                .serverProtocol(serverVersion)
-                .build();
-        final SSLSocket client =
-                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
-        assertThrows(IllegalArgumentException.class, () -> client.setEnabledProtocols(new String[] {"SSLv3"}));
-        assertThrows(IllegalArgumentException.class, () -> client.setEnabledProtocols(new String[] {"SSL"}));
-    }
-
-    @TargetSdkVersion(34)
-    @Test
-    public void test_SSLSocket_SSLv3Unsupported_34() throws Exception {
-        TestSSLContext context = new TestSSLContext.Builder()
-                .clientProtocol(clientVersion)
-                .serverProtocol(serverVersion)
-                .build();
-        final SSLSocket client =
-                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
-        // For app compatibility, SSLv3 is stripped out when setting only.
-        client.setEnabledProtocols(new String[] {"SSLv3"});
-        assertEquals(0, client.getEnabledProtocols().length);
-        try {
-            client.setEnabledProtocols(new String[] {"SSL"});
-            fail("SSLSocket should not support SSL protocol");
-        } catch (IllegalArgumentException expected) {
-            // Ignored.
+        try (SSLSocket client =
+                        (SSLSocket) context.clientContext.getSocketFactory().createSocket()) {
+            client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1"});
+            assertEquals(2, client.getEnabledProtocols().length);
         }
     }
 
-    @TargetSdkVersion(34)
-    @Test
-    public void test_TLSv1Filtered_34() throws Exception {
-        TestSSLContext context = new TestSSLContext.Builder()
-                .clientProtocol(clientVersion)
-                .serverProtocol(serverVersion)
-                .build();
-        final SSLSocket client =
-                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
-        client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"});
-        assertEquals(1, client.getEnabledProtocols().length);
-        assertEquals("TLSv1.2", client.getEnabledProtocols()[0]);
-    }
-
-    @TargetSdkVersion(35)
-    @Test
-    public void test_TLSv1Filtered_35() throws Exception {
-        assumeFalse(isTlsV1Filtered());
-        TestSSLContext context = new TestSSLContext.Builder()
-                .clientProtocol(clientVersion)
-                .serverProtocol(serverVersion)
-                .build();
-        final SSLSocket client =
-                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
-        assertThrows(IllegalArgumentException.class, () ->
-            client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"}));
-    }
-
     @Test
-    public void test_TLSv1Unsupported_notEnabled() throws Exception {
+    public void test_TLSv1Unsupported_notEnabled() {
         assumeTrue(!isTlsV1Supported());
         assertTrue(isTlsV1Deprecated());
     }
@@ -2200,7 +2169,7 @@ public class SSLSocketVersionCompatibilityTest {
             if ("TLSv1.2".equals(negotiatedVersion())) {
                 assertFalse(Arrays.equals(clientEkm, clientContextEkm));
             } else {
-                assertTrue(Arrays.equals(clientEkm, clientContextEkm));
+                assertArrayEquals(clientEkm, clientContextEkm);
             }
         } finally {
             pair.close();
diff --git a/repackaged/openjdk/src/main/java/com/android/org/conscrypt/HostProperties.java b/repackaged/openjdk/src/main/java/com/android/org/conscrypt/HostProperties.java
index 7adf9306..67e7840c 100644
--- a/repackaged/openjdk/src/main/java/com/android/org/conscrypt/HostProperties.java
+++ b/repackaged/openjdk/src/main/java/com/android/org/conscrypt/HostProperties.java
@@ -75,7 +75,7 @@ class HostProperties {
          * Returns the value to use when building filenames for this OS.
          */
         public String getFileComponent() {
-            return name().toLowerCase();
+            return name().toLowerCase(Locale.ROOT);
         }
     }
 
@@ -105,7 +105,7 @@ class HostProperties {
          * Returns the value to use when building filenames for this architecture.
          */
         public String getFileComponent() {
-            return name().toLowerCase();
+            return name().toLowerCase(Locale.ROOT);
         }
     }
 
@@ -194,10 +194,10 @@ class HostProperties {
     }
 
     private static String normalize(String value) {
-        return value.toLowerCase(Locale.US).replaceAll("[^a-z0-9]+", "");
+        return value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "");
     }
 
-    /**
+    /*
      * Normalizes the os.name value into the value used by the Maven os plugin
      * (https://github.com/trustin/os-maven-plugin). This plugin is used to generate
      * platform-specific
@@ -242,7 +242,7 @@ class HostProperties {
         return OperatingSystem.UNKNOWN;
     }
 
-    /**
+    /*
      * Normalizes the os.arch value into the value used by the Maven os plugin
      * (https://github.com/trustin/os-maven-plugin). This plugin is used to generate
      * platform-specific
diff --git a/repackaged/openjdk/src/main/java/com/android/org/conscrypt/Platform.java b/repackaged/openjdk/src/main/java/com/android/org/conscrypt/Platform.java
index e0f94348..0d5a7348 100644
--- a/repackaged/openjdk/src/main/java/com/android/org/conscrypt/Platform.java
+++ b/repackaged/openjdk/src/main/java/com/android/org/conscrypt/Platform.java
@@ -37,8 +37,11 @@ import static java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE;
 import static java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE;
 import static java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE;
 
+import com.android.org.conscrypt.NativeCrypto;
 import com.android.org.conscrypt.ct.LogStore;
 import com.android.org.conscrypt.ct.Policy;
+import com.android.org.conscrypt.metrics.Source;
+import com.android.org.conscrypt.metrics.StatsLog;
 
 import java.io.File;
 import java.io.FileDescriptor;
@@ -88,13 +91,18 @@ import javax.net.ssl.X509TrustManager;
  * Platform-specific methods for OpenJDK.
  *
  * Uses reflection to implement Java 8 SSL features for backwards compatibility.
+ * @hide This class is not part of the Android public SDK API
  */
-final class Platform {
+@Internal
+final public class Platform {
     private static final int JAVA_VERSION = javaVersion0();
     private static final Method GET_CURVE_NAME_METHOD;
+    static boolean DEPRECATED_TLS_V1 = true;
+    static boolean ENABLED_TLS_V1 = false;
+    private static boolean FILTERED_TLS_V1 = true;
 
     static {
-
+        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
         Method getCurveNameMethod = null;
         try {
             getCurveNameMethod = ECParameterSpec.class.getDeclaredMethod("getCurveName");
@@ -107,7 +115,12 @@ final class Platform {
 
     private Platform() {}
 
-    static void setup() {}
+    public static void setup(boolean deprecatedTlsV1, boolean enabledTlsV1) {
+        DEPRECATED_TLS_V1 = deprecatedTlsV1;
+        ENABLED_TLS_V1 = enabledTlsV1;
+        FILTERED_TLS_V1 = !enabledTlsV1;
+        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
+    }
 
 
     /**
@@ -122,7 +135,7 @@ final class Platform {
         prefix = new File(prefix).getName();
         IOException suppressed = null;
         for (int i = 0; i < 10000; i++) {
-            String tempName = String.format(Locale.US, "%s%d%04d%s", prefix, time, i, suffix);
+            String tempName = String.format(Locale.ROOT, "%s%d%04d%s", prefix, time, i, suffix);
             File tempFile = new File(directory, tempName);
             if (!tempName.equals(tempFile.getName())) {
                 // The given prefix or suffix contains path separators.
@@ -591,8 +604,22 @@ final class Platform {
             return originalHostName;
         } catch (InvocationTargetException e) {
             throw new RuntimeException("Failed to get originalHostName", e);
-        } catch (ClassNotFoundException | IllegalAccessException | NoSuchMethodException ignore) {
+        } catch (ClassNotFoundException | IllegalAccessException | NoSuchMethodException ignored) {
             // passthrough and return addr.getHostAddress()
+        } catch (Exception maybeIgnored) {
+            if (!maybeIgnored.getClass().getSimpleName().equals("InaccessibleObjectException")) {
+                throw new RuntimeException("Failed to get originalHostName", maybeIgnored);
+            }
+            // Java versions which prevent reflection to get the original hostname.
+            // Ugly workaround is parse it from toString(), which uses holder.hostname rather
+            // than holder.originalHostName.  But in Java versions up to 21 at least and in the way
+            // used by Conscrypt, hostname always equals originalHostname.
+            String representation = addr.toString();
+            int slash = representation.indexOf('/');
+            if (slash != -1) {
+                return representation.substring(0, slash);
+            }
+            // Give up and return the IP
         }
 
         return addr.getHostAddress();
@@ -630,7 +657,7 @@ final class Platform {
         }
 
         String property = Security.getProperty("conscrypt.ct.enable");
-        if (property == null || !Boolean.valueOf(property.toLowerCase())) {
+        if (property == null || !Boolean.parseBoolean(property.toLowerCase(Locale.ROOT))) {
             return false;
         }
 
@@ -644,15 +671,14 @@ final class Platform {
         for (String part : parts) {
             property = Security.getProperty(propertyName + ".*");
             if (property != null) {
-                enable = Boolean.valueOf(property.toLowerCase());
+                enable = Boolean.parseBoolean(property.toLowerCase(Locale.ROOT));
             }
-
             propertyName.append(".").append(part);
         }
 
         property = Security.getProperty(propertyName.toString());
         if (property != null) {
-            enable = Boolean.valueOf(property.toLowerCase());
+            enable = Boolean.parseBoolean(property.toLowerCase(Locale.ROOT));
         }
         return enable;
     }
@@ -805,23 +831,33 @@ final class Platform {
         return 0;
     }
 
+    public static StatsLog getStatsLog() {
+        return null;
+    }
+
     @SuppressWarnings("unused")
-    static void countTlsHandshake(
-            boolean success, String protocol, String cipherSuite, long duration) {}
+    public static Source getStatsSource() {
+        return null;
+    }
+
+    @SuppressWarnings("unused")
+    public static int[] getUids() {
+        return null;
+    }
 
     public static boolean isJavaxCertificateSupported() {
         return JAVA_VERSION < 15;
     }
 
     public static boolean isTlsV1Deprecated() {
-        return true;
+        return DEPRECATED_TLS_V1;
     }
 
     public static boolean isTlsV1Filtered() {
-        return false;
+        return FILTERED_TLS_V1;
     }
 
     public static boolean isTlsV1Supported() {
-        return false;
+        return ENABLED_TLS_V1;
     }
 }
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/AbstractSessionContextTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/AbstractSessionContextTest.java
index 7f3ed102..a698a18c 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/AbstractSessionContextTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/AbstractSessionContextTest.java
@@ -124,9 +124,6 @@ public abstract class AbstractSessionContextTest<T extends AbstractSessionContex
 
     @Test
     public void testSerializeSession() throws Exception {
-        Certificate mockCert = mock(Certificate.class);
-        when(mockCert.getEncoded()).thenReturn(new byte[] {0x05, 0x06, 0x07, 0x10});
-
         byte[] encodedBytes = new byte[] {0x01, 0x02, 0x03};
         NativeSslSession session = new MockSessionBuilder()
                 .id(new byte[] {0x11, 0x09, 0x03, 0x20})
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/AddressUtilsTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/AddressUtilsTest.java
index bdf1fddb..6eeb18f9 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/AddressUtilsTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/AddressUtilsTest.java
@@ -17,41 +17,55 @@
 
 package com.android.org.conscrypt;
 
-import junit.framework.TestCase;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 
 /**
  * Test for AddressUtils
  * @hide This class is not part of the Android public SDK API
  */
-public class AddressUtilsTest extends TestCase {
+@RunWith(JUnit4.class)
+public class AddressUtilsTest {
+    @Test
     public void test_isValidSniHostname_Success() throws Exception {
         assertTrue(AddressUtils.isValidSniHostname("www.google.com"));
     }
 
+    @Test
     public void test_isValidSniHostname_NotFQDN_Failure() throws Exception {
         assertFalse(AddressUtils.isValidSniHostname("www"));
     }
 
+    @Test
     public void test_isValidSniHostname_Localhost_Success() throws Exception {
         assertTrue(AddressUtils.isValidSniHostname("LOCALhost"));
     }
 
+    @Test
     public void test_isValidSniHostname_IPv4_Failure() throws Exception {
         assertFalse(AddressUtils.isValidSniHostname("192.168.0.1"));
     }
 
+    @Test
     public void test_isValidSniHostname_IPv6_Failure() throws Exception {
         assertFalse(AddressUtils.isValidSniHostname("2001:db8::1"));
     }
 
+    @Test
     public void test_isValidSniHostname_TrailingDot() throws Exception {
         assertFalse(AddressUtils.isValidSniHostname("www.google.com."));
     }
 
+    @Test
     public void test_isValidSniHostname_NullByte() throws Exception {
         assertFalse(AddressUtils.isValidSniHostname("www\0.google.com"));
     }
 
+    @Test
     public void test_isLiteralIpAddress_IPv4_Success() throws Exception {
         assertTrue(AddressUtils.isLiteralIpAddress("127.0.0.1"));
         assertTrue(AddressUtils.isLiteralIpAddress("255.255.255.255"));
@@ -60,6 +74,7 @@ public class AddressUtilsTest extends TestCase {
         assertTrue(AddressUtils.isLiteralIpAddress("254.249.190.094"));
     }
 
+    @Test
     public void test_isLiteralIpAddress_IPv4_ExtraCharacters_Failure() throws Exception {
         assertFalse(AddressUtils.isLiteralIpAddress("127.0.0.1a"));
         assertFalse(AddressUtils.isLiteralIpAddress(" 255.255.255.255"));
@@ -70,12 +85,14 @@ public class AddressUtilsTest extends TestCase {
         assertFalse(AddressUtils.isLiteralIpAddress("192.168.2.1%eth0"));
     }
 
+    @Test
     public void test_isLiteralIpAddress_IPv4_NumbersTooLarge_Failure() throws Exception {
         assertFalse(AddressUtils.isLiteralIpAddress("256.255.255.255"));
         assertFalse(AddressUtils.isLiteralIpAddress("255.255.255.256"));
         assertFalse(AddressUtils.isLiteralIpAddress("192.168.1.260"));
     }
 
+    @Test
     public void test_isLiteralIpAddress_IPv6_Success() throws Exception {
         assertTrue(AddressUtils.isLiteralIpAddress("::1"));
         assertTrue(AddressUtils.isLiteralIpAddress("2001:Db8::1"));
@@ -87,6 +104,7 @@ public class AddressUtilsTest extends TestCase {
         assertTrue(AddressUtils.isLiteralIpAddress("2001:cdba::3257:9652%int2.3!"));
     }
 
+    @Test
     public void test_isLiteralIpAddress_IPv6_Failure() throws Exception {
         assertFalse(AddressUtils.isLiteralIpAddress(":::1"));
         assertFalse(AddressUtils.isLiteralIpAddress("::11111"));
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptSocketTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptSocketTest.java
index bd890b6b..81e2a8b8 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptSocketTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/ConscryptSocketTest.java
@@ -20,12 +20,10 @@ package com.android.org.conscrypt;
 import static com.android.org.conscrypt.TestUtils.openTestFile;
 import static com.android.org.conscrypt.TestUtils.readTestFile;
 
-import static org.hamcrest.CoreMatchers.instanceOf;
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNull;
-import static org.junit.Assert.assertThat;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
 import static org.junit.Assume.assumeFalse;
@@ -232,15 +230,17 @@ public class ConscryptSocketTest {
 
     @Parameters(name = "{0} wrapping {1} connecting to {2}")
     public static Object[][] data() {
-        return new Object[][] {
+        Object[][] fd_cases = new Object[][] {
                 {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.NONE, ServerSocketType.PLAIN},
                 {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.NONE, ServerSocketType.CHANNEL},
                 {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.PLAIN, ServerSocketType.PLAIN},
                 {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.PLAIN, ServerSocketType.CHANNEL},
                 {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.CHANNEL, ServerSocketType.PLAIN},
-                {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.CHANNEL,
-                        ServerSocketType.CHANNEL},
+                {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.CHANNEL, ServerSocketType.CHANNEL}
                 // Not supported: {SocketType.FILE_DESCRIPTOR, UnderlyingSocketType.SSL},
+        };
+
+        Object[][] engine_cases = new Object[][] {
                 {SocketType.ENGINE, UnderlyingSocketType.NONE, ServerSocketType.PLAIN},
                 {SocketType.ENGINE, UnderlyingSocketType.NONE, ServerSocketType.CHANNEL},
                 {SocketType.ENGINE, UnderlyingSocketType.PLAIN, ServerSocketType.PLAIN},
@@ -249,6 +249,12 @@ public class ConscryptSocketTest {
                 {SocketType.ENGINE, UnderlyingSocketType.CHANNEL, ServerSocketType.CHANNEL},
                 {SocketType.ENGINE, UnderlyingSocketType.SSL, ServerSocketType.PLAIN},
                 {SocketType.ENGINE, UnderlyingSocketType.SSL, ServerSocketType.CHANNEL}};
+
+        if (TestUtils.isJavaVersion(17)) {
+            // FD Socket not feasible on Java 17+
+            return engine_cases;
+        }
+        return ArrayUtils.concat(fd_cases, engine_cases);
     }
 
     @Parameter
@@ -457,16 +463,13 @@ public class ConscryptSocketTest {
         }
 
         Future<AbstractConscryptSocket> handshake(final ServerSocket listener, final Hooks hooks) {
-            return executor.submit(new Callable<AbstractConscryptSocket>() {
-                @Override
-                public AbstractConscryptSocket call() throws Exception {
-                    AbstractConscryptSocket socket = hooks.createSocket(listener);
-                    socket.addHandshakeCompletedListener(hooks);
+            return executor.submit((Callable<AbstractConscryptSocket>) () -> {
+                AbstractConscryptSocket socket = hooks.createSocket(listener);
+                socket.addHandshakeCompletedListener(hooks);
 
-                    socket.startHandshake();
+                socket.startHandshake();
 
-                    return socket;
-                }
+                return socket;
             });
         }
     }
@@ -597,8 +600,8 @@ public class ConscryptSocketTest {
         TestConnection connection = new TestConnection(new X509Certificate[] {cert, ca}, certKey);
 
         connection.doHandshake();
-        assertThat(connection.clientException, instanceOf(SSLHandshakeException.class));
-        assertThat(connection.clientException.getCause(), instanceOf(CertificateException.class));
+        assertTrue(connection.clientException instanceof SSLHandshakeException);
+        assertTrue(connection.clientException.getCause() instanceof CertificateException);
     }
 
     @Ignore("TODO(nathanmittler): Fix or remove")
@@ -609,16 +612,15 @@ public class ConscryptSocketTest {
         connection.serverHooks.sctTLSExtension = readTestFile("ct-signed-timestamp-list-invalid");
 
         connection.doHandshake();
-        assertThat(connection.clientException, instanceOf(SSLHandshakeException.class));
-        assertThat(connection.clientException.getCause(), instanceOf(CertificateException.class));
+        assertTrue(connection.clientException instanceof SSLHandshakeException);
+        assertTrue(connection.clientException.getCause() instanceof CertificateException);
     }
 
     @Test
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("deprecation") // setAlpnProtocols is deprecated but still needs testing.
     public void setAlpnProtocolWithNullShouldSucceed() throws Exception {
-        ServerSocket listening = serverSocketType.newServerSocket();
         OpenSSLSocketImpl clientSocket = null;
-        try {
+        try (ServerSocket listening = serverSocketType.newServerSocket()) {
             Socket underlying = new Socket(listening.getInetAddress(), listening.getLocalPort());
             clientSocket = (OpenSSLSocketImpl) socketType.newClientSocket(
                     new ClientHooks().createContext(), listening, underlying);
@@ -630,15 +632,15 @@ public class ConscryptSocketTest {
             if (clientSocket != null) {
                 clientSocket.close();
             }
-            listening.close();
         }
     }
 
     // http://b/27250522
     @Test
     public void test_setSoTimeout_doesNotCreateSocketImpl() throws Exception {
-        ServerSocket listening = serverSocketType.newServerSocket();
-        try {
+        // TODO(prb): Figure out how to test this on Java 17+
+        assumeFalse(TestUtils.isJavaVersion(17));
+        try (ServerSocket listening = serverSocketType.newServerSocket()) {
             Socket underlying = new Socket(listening.getInetAddress(), listening.getLocalPort());
             Socket socket = socketType.newClientSocket(
                     new ClientHooks().createContext(), listening, underlying);
@@ -649,8 +651,6 @@ public class ConscryptSocketTest {
             Field f = Socket.class.getDeclaredField("created");
             f.setAccessible(true);
             assertFalse(f.getBoolean(socket));
-        } finally {
-            listening.close();
         }
     }
 
@@ -761,12 +761,8 @@ public class ConscryptSocketTest {
             throws Exception {
         final byte[] received = new byte[data.length];
 
-        Future<Integer> readFuture = executor.submit(new Callable<Integer>() {
-            @Override
-            public Integer call() throws Exception {
-                return destination.getInputStream().read(received);
-            }
-        });
+        Future<Integer> readFuture =
+                executor.submit(() -> destination.getInputStream().read(received));
 
         source.getOutputStream().write(data);
         assertEquals(data.length, (int) readFuture.get());
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/DuckTypedPSKKeyManagerTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/DuckTypedPSKKeyManagerTest.java
index 8d03c219..7e11eb7c 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/DuckTypedPSKKeyManagerTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/DuckTypedPSKKeyManagerTest.java
@@ -17,12 +17,16 @@
 
 package com.android.org.conscrypt;
 
+import junit.framework.TestCase;
+
 import java.lang.reflect.InvocationHandler;
 import java.lang.reflect.Method;
 import java.lang.reflect.Proxy;
 import java.net.Socket;
+import java.nio.charset.StandardCharsets;
 import java.security.Key;
 import java.util.Arrays;
+
 import javax.crypto.SecretKey;
 import javax.crypto.spec.SecretKeySpec;
 import javax.net.ssl.KeyManager;
@@ -30,7 +34,6 @@ import javax.net.ssl.SSLContext;
 import javax.net.ssl.SSLEngine;
 import javax.net.ssl.SSLSocket;
 import javax.net.ssl.SSLSocketFactory;
-import junit.framework.TestCase;
 
 /**
  * @hide This class is not part of the Android public SDK API
@@ -143,7 +146,7 @@ public class DuckTypedPSKKeyManagerTest extends TestCase {
         assertSame(identityHint, mockInvocationHandler.lastInvokedMethodArgs[0]);
         assertSame(mSSLEngine, mockInvocationHandler.lastInvokedMethodArgs[1]);
 
-        SecretKey key = new SecretKeySpec("arbitrary".getBytes("UTF-8"), "RAW");
+        SecretKey key = new SecretKeySpec("arbitrary".getBytes(StandardCharsets.UTF_8), "RAW");
         mockInvocationHandler.returnValue = key;
         assertSame(key, pskKeyManager.getKey(identityHint, identity, mSSLSocket));
         assertEquals("getKey", mockInvocationHandler.lastInvokedMethod.getName());
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeCryptoTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeCryptoTest.java
index 5531e7fd..fc7c18fc 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeCryptoTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeCryptoTest.java
@@ -33,8 +33,8 @@ import static com.android.org.conscrypt.TestUtils.readTestFile;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertNotNull;
-import static org.junit.Assert.assertNotSame;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
@@ -59,13 +59,13 @@ import java.io.ByteArrayInputStream;
 import java.io.ByteArrayOutputStream;
 import java.io.FileDescriptor;
 import java.io.IOException;
-import java.io.UnsupportedEncodingException;
 import java.lang.reflect.Method;
 import java.math.BigInteger;
 import java.net.ServerSocket;
 import java.net.Socket;
 import java.net.SocketException;
 import java.net.SocketTimeoutException;
+import java.nio.charset.StandardCharsets;
 import java.security.KeyPair;
 import java.security.KeyPairGenerator;
 import java.security.KeyStore;
@@ -126,10 +126,12 @@ public class NativeCryptoTest {
     @BeforeClass
     @SuppressWarnings("JdkObsolete") // Public API KeyStore.aliases() uses Enumeration
     public static void initStatics() throws Exception {
-        Class<?> c_Platform = TestUtils.conscryptClass("Platform");
-        m_Platform_getFileDescriptor =
-                c_Platform.getDeclaredMethod("getFileDescriptor", Socket.class);
-        m_Platform_getFileDescriptor.setAccessible(true);
+        if (!TestUtils.isJavaVersion(17)) {
+            Class<?> c_Platform = TestUtils.conscryptClass("Platform");
+            m_Platform_getFileDescriptor =
+                    c_Platform.getDeclaredMethod("getFileDescriptor", Socket.class);
+            m_Platform_getFileDescriptor.setAccessible(true);
+        }
 
         PrivateKeyEntry serverPrivateKeyEntry =
                 TestKeyStore.getServer().getPrivateKey("RSA", "RSA");
@@ -250,7 +252,7 @@ public class NativeCryptoTest {
     public void EVP_PKEY_cmp_withNullShouldThrow() throws Exception {
         RSAPrivateCrtKey privKey1 = TEST_RSA_KEY;
         NativeRef.EVP_PKEY pkey1 = getRsaPkey(privKey1);
-        assertNotSame(NULL, pkey1);
+        assertFalse(pkey1.isNull());
         NativeCrypto.EVP_PKEY_cmp(pkey1, null);
     }
 
@@ -259,14 +261,14 @@ public class NativeCryptoTest {
         RSAPrivateCrtKey privKey1 = TEST_RSA_KEY;
 
         NativeRef.EVP_PKEY pkey1 = getRsaPkey(privKey1);
-        assertNotSame(NULL, pkey1);
+        assertFalse(pkey1.isNull());
 
         NativeRef.EVP_PKEY pkey1_copy = getRsaPkey(privKey1);
-        assertNotSame(NULL, pkey1_copy);
+        assertFalse(pkey1_copy.isNull());
 
         // Generate a different key.
         NativeRef.EVP_PKEY pkey2 = getRsaPkey(generateRsaKey());
-        assertNotSame(NULL, pkey2);
+        assertFalse(pkey2.isNull());
 
         assertEquals("Same keys should be the equal", 1, NativeCrypto.EVP_PKEY_cmp(pkey1, pkey1));
 
@@ -602,8 +604,8 @@ public class NativeCryptoTest {
         long c = NativeCrypto.SSL_CTX_new();
         long s = NativeCrypto.SSL_new(c, null);
 
-        List<String> ciphers = new ArrayList<String>(NativeCrypto.SUPPORTED_TLS_1_2_CIPHER_SUITES_SET);
-        NativeCrypto.SSL_set_cipher_lists(s, null, ciphers.toArray(new String[ciphers.size()]));
+        List<String> ciphers = new ArrayList<>(NativeCrypto.SUPPORTED_TLS_1_2_CIPHER_SUITES_SET);
+        NativeCrypto.SSL_set_cipher_lists(s, null, ciphers.toArray(new String[0]));
 
         NativeCrypto.SSL_free(s, null);
         NativeCrypto.SSL_CTX_free(c, null);
@@ -648,7 +650,7 @@ public class NativeCryptoTest {
         public long beforeHandshake(long context) throws SSLException {
             long s = NativeCrypto.SSL_new(context, null);
             // Limit cipher suites to a known set so authMethod is known.
-            List<String> cipherSuites = new ArrayList<String>();
+            List<String> cipherSuites = new ArrayList<>();
             if (enabledCipherSuites == null) {
                 cipherSuites.add("ECDHE-RSA-AES128-SHA");
                 if (pskEnabled) {
@@ -660,9 +662,8 @@ public class NativeCryptoTest {
                 cipherSuites.addAll(enabledCipherSuites);
             }
             // Protocol list is included for determining whether to send TLS_FALLBACK_SCSV
-            NativeCrypto.setEnabledCipherSuites(s, null,
-                    cipherSuites.toArray(new String[cipherSuites.size()]),
-                    new String[] {"TLSv1.2"});
+            NativeCrypto.setEnabledCipherSuites(
+                    s, null, cipherSuites.toArray(new String[0]), new String[] {"TLSv1.2"});
 
             if (channelIdPrivateKey != null) {
                 NativeCrypto.SSL_set1_tls_channel_id(s, null, channelIdPrivateKey.getNativeRef());
@@ -872,11 +873,7 @@ public class NativeCryptoTest {
                 if (pskIdentity != null) {
                     // Create a NULL-terminated modified UTF-8 representation of pskIdentity.
                     byte[] b;
-                    try {
-                        b = pskIdentity.getBytes("UTF-8");
-                    } catch (UnsupportedEncodingException e) {
-                        throw new RuntimeException("UTF-8 encoding not supported", e);
-                    }
+                    b = pskIdentity.getBytes(StandardCharsets.UTF_8);
                     callbacks.clientPSKKeyRequestedResultIdentity = Arrays.copyOf(b, b.length + 1);
                 }
                 callbacks.clientPSKKeyRequestedResultKey = pskKey;
@@ -960,12 +957,13 @@ public class NativeCryptoTest {
     public static Future<TestSSLHandshakeCallbacks> handshake(final ServerSocket listener,
             final int timeout, final boolean client, final Hooks hooks, final byte[] alpnProtocols,
             final ApplicationProtocolSelectorAdapter alpnSelector) {
+        // TODO(prb) rewrite for engine socket. FD socket calls infeasible to test on Java 17+
+        assumeFalse(TestUtils.isJavaVersion(17));
         ExecutorService executor = Executors.newSingleThreadExecutor();
         Future<TestSSLHandshakeCallbacks> future =
                 executor.submit(new Callable<TestSSLHandshakeCallbacks>() {
                     @Override
                     public TestSSLHandshakeCallbacks call() throws Exception {
-                        @SuppressWarnings("resource")
                         // Socket needs to remain open after the handshake
                         Socket socket = (client ? new Socket(listener.getInetAddress(),
                                                           listener.getLocalPort())
@@ -1406,7 +1404,7 @@ public class NativeCryptoTest {
         ServerHooks sHooks = new ServerHooks();
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
-        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
+        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
         sHooks.pskKey = cHooks.pskKey;
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
@@ -1443,7 +1441,7 @@ public class NativeCryptoTest {
         ServerHooks sHooks = new ServerHooks();
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
-        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
+        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
         sHooks.pskKey = cHooks.pskKey;
         sHooks.pskIdentityHint = "Some non-ASCII characters: \u00c4\u0332";
         cHooks.pskIdentity = "More non-ASCII characters: \u00f5\u044b";
@@ -1474,7 +1472,7 @@ public class NativeCryptoTest {
     }
 
     @Test
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated but still needs testing.
     public void test_SSL_do_handshake_with_psk_with_identity_and_hint_of_max_length()
             throws Exception {
         // normal TLS-PSK client and server case where the server provides the client with a PSK
@@ -1484,7 +1482,7 @@ public class NativeCryptoTest {
         ServerHooks sHooks = new ServerHooks();
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
-        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
+        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
         sHooks.pskKey = cHooks.pskKey;
         sHooks.pskIdentityHint = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
                 + "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx";
@@ -1521,8 +1519,8 @@ public class NativeCryptoTest {
         ServerHooks sHooks = new ServerHooks();
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
-        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
-        sHooks.pskKey = "1, 2, 3, 3, Testing...".getBytes("UTF-8");
+        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
+        sHooks.pskKey = "1, 2, 3, 3, Testing...".getBytes(StandardCharsets.UTF_8);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -1543,7 +1541,7 @@ public class NativeCryptoTest {
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
         cHooks.pskKey = null;
-        sHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
+        sHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
                 handshake(listener, 0, false, sHooks, null, null);
@@ -1563,7 +1561,7 @@ public class NativeCryptoTest {
         ServerHooks sHooks = new ServerHooks();
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
-        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
+        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
         sHooks.pskKey = null;
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
@@ -1578,7 +1576,7 @@ public class NativeCryptoTest {
     }
 
     @Test
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated but still needs testing.
     public void test_SSL_do_handshake_with_psk_key_too_long() throws Exception {
         final ServerSocket listener = newServerSocket();
         ClientHooks cHooks = new ClientHooks() {
@@ -1591,7 +1589,7 @@ public class NativeCryptoTest {
         ServerHooks sHooks = new ServerHooks();
         cHooks.pskEnabled = true;
         sHooks.pskEnabled = true;
-        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes("UTF-8");
+        cHooks.pskKey = "1, 2, 3, 4, Testing...".getBytes(StandardCharsets.UTF_8);
         sHooks.pskKey = cHooks.pskKey;
         Future<TestSSLHandshakeCallbacks> client = handshake(listener, 0, true, cHooks, null, null);
         Future<TestSSLHandshakeCallbacks> server =
@@ -1693,7 +1691,7 @@ public class NativeCryptoTest {
     }
 
     @Test
-    @SuppressWarnings("deprecation")
+    @SuppressWarnings("deprecation") // PSKKeyManager is deprecated but still needs testing.
     public void test_SSL_use_psk_identity_hint() throws Exception {
         long c = NativeCrypto.SSL_CTX_new();
         long s = NativeCrypto.SSL_new(c, null);
@@ -1741,7 +1739,7 @@ public class NativeCryptoTest {
             {
                 Hooks cHooks = new Hooks() {
                     @Override
-                    public long getContext() throws SSLException {
+                    public long getContext() {
                         return clientContext;
                     }
                     @Override
@@ -1753,7 +1751,7 @@ public class NativeCryptoTest {
                 };
                 Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                     @Override
-                    public long getContext() throws SSLException {
+                    public long getContext() {
                         return serverContext;
                     }
                     @Override
@@ -1774,7 +1772,7 @@ public class NativeCryptoTest {
             {
                 Hooks cHooks = new Hooks() {
                     @Override
-                    public long getContext() throws SSLException {
+                    public long getContext() {
                         return clientContext;
                     }
                     @Override
@@ -1792,7 +1790,7 @@ public class NativeCryptoTest {
                 };
                 Hooks sHooks = new ServerHooks(SERVER_PRIVATE_KEY, ENCODED_SERVER_CERTIFICATES) {
                     @Override
-                    public long getContext() throws SSLException {
+                    public long getContext() {
                         return serverContext;
                     }
                     @Override
@@ -1977,7 +1975,7 @@ public class NativeCryptoTest {
             public void afterHandshake(long session, long ssl, long context, Socket socket,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                 byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
-                assertEquals("spdy/2", new String(negotiated, "UTF-8"));
+                assertEquals("spdy/2", new String(negotiated, StandardCharsets.UTF_8));
                 super.afterHandshake(session, ssl, context, socket, fd, callback);
             }
         };
@@ -1986,7 +1984,7 @@ public class NativeCryptoTest {
             public void afterHandshake(long session, long ssl, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                 byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
-                assertEquals("spdy/2", new String(negotiated, "UTF-8"));
+                assertEquals("spdy/2", new String(negotiated, StandardCharsets.UTF_8));
                 super.afterHandshake(session, ssl, c, sock, fd, callback);
             }
         };
@@ -2045,7 +2043,7 @@ public class NativeCryptoTest {
             public void afterHandshake(long session, long ssl, long context, Socket socket,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                 byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
-                assertEquals("spdy/2", new String(negotiated, "UTF-8"));
+                assertEquals("spdy/2", new String(negotiated, StandardCharsets.UTF_8));
                 super.afterHandshake(session, ssl, context, socket, fd, callback);
             }
         };
@@ -2054,7 +2052,7 @@ public class NativeCryptoTest {
             public void afterHandshake(long session, long ssl, long c, Socket sock,
                     FileDescriptor fd, SSLHandshakeCallbacks callback) throws Exception {
                 byte[] negotiated = NativeCrypto.getApplicationProtocol(ssl, null);
-                assertEquals("spdy/2", new String(negotiated, "UTF-8"));
+                assertEquals("spdy/2", new String(negotiated, StandardCharsets.UTF_8));
                 super.afterHandshake(session, ssl, c, sock, fd, callback);
             }
         };
@@ -2614,7 +2612,7 @@ public class NativeCryptoTest {
                 assertTrue(session2 != NULL);
 
                 // Make sure d2i_SSL_SESSION retores SSL_SESSION_cipher value http://b/7091840
-                assertTrue(NativeCrypto.SSL_SESSION_cipher(session2) != null);
+                assertNotNull(NativeCrypto.SSL_SESSION_cipher(session2));
                 assertEquals(NativeCrypto.SSL_SESSION_cipher(session),
                         NativeCrypto.SSL_SESSION_cipher(session2));
 
@@ -2736,7 +2734,7 @@ public class NativeCryptoTest {
     public void test_get_RSA_private_params() throws Exception {
         // Test getting params for the wrong kind of key.
         final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
-        assertFalse(groupCtx == NULL);
+        assertNotEquals(NULL, groupCtx);
         NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupCtx);
         NativeRef.EVP_PKEY ctx = new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(group));
         NativeCrypto.get_RSA_private_params(ctx);
@@ -2751,7 +2749,7 @@ public class NativeCryptoTest {
     public void test_get_RSA_public_params() throws Exception {
         // Test getting params for the wrong kind of key.
         final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
-        assertFalse(groupCtx == NULL);
+        assertNotEquals(NULL, groupCtx);
         NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupCtx);
         NativeRef.EVP_PKEY ctx = new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(group));
         NativeCrypto.get_RSA_public_params(ctx);
@@ -2807,7 +2805,7 @@ public class NativeCryptoTest {
     private void check_EC_GROUP(String name, String pStr, String aStr, String bStr, String xStr,
             String yStr, String nStr, long hLong) throws Exception {
         long groupRef = NativeCrypto.EC_GROUP_new_by_curve_name(name);
-        assertFalse(groupRef == NULL);
+        assertNotEquals(NULL, groupRef);
         NativeRef.EC_GROUP group = new NativeRef.EC_GROUP(groupRef);
 
         // prime
@@ -2879,7 +2877,7 @@ public class NativeCryptoTest {
     @Test
     public void test_ECDH_compute_key_null_key_Failure() throws Exception {
         final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
-        assertFalse(groupCtx == NULL);
+        assertNotEquals(NULL, groupCtx);
         NativeRef.EC_GROUP groupRef = new NativeRef.EC_GROUP(groupCtx);
         NativeRef.EVP_PKEY pkey1Ref =
                 new NativeRef.EVP_PKEY(NativeCrypto.EC_KEY_generate_key(groupRef));
@@ -2956,7 +2954,7 @@ public class NativeCryptoTest {
         assertTrue(key1.getPublicKey() instanceof RSAPublicKey);
 
         final long groupCtx = NativeCrypto.EC_GROUP_new_by_curve_name("prime256v1");
-        assertFalse(groupCtx == NULL);
+        assertNotEquals(NULL, groupCtx);
         NativeRef.EC_GROUP group1 = new NativeRef.EC_GROUP(groupCtx);
         key1 = new OpenSSLKey(NativeCrypto.EC_KEY_generate_key(group1));
         assertTrue(key1.getPublicKey() instanceof ECPublicKey);
@@ -2964,10 +2962,9 @@ public class NativeCryptoTest {
 
     @Test
     public void test_create_BIO_InputStream() throws Exception {
-        byte[] actual = "Test".getBytes("UTF-8");
+        byte[] actual = "Test".getBytes(StandardCharsets.UTF_8);
         ByteArrayInputStream is = new ByteArrayInputStream(actual);
 
-        @SuppressWarnings("resource")
         OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);
         try {
             byte[] buffer = new byte[1024];
@@ -2982,7 +2979,7 @@ public class NativeCryptoTest {
 
     @Test
     public void test_create_BIO_OutputStream() throws Exception {
-        byte[] actual = "Test".getBytes("UTF-8");
+        byte[] actual = "Test".getBytes(StandardCharsets.UTF_8);
         ByteArrayOutputStream os = new ByteArrayOutputStream();
 
         long ctx = NativeCrypto.create_BIO_OutputStream(os);
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeRefTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeRefTest.java
index 18a81aa5..1654813c 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeRefTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/NativeRefTest.java
@@ -17,12 +17,18 @@
 
 package com.android.org.conscrypt;
 
-import junit.framework.TestCase;
+import static org.junit.Assert.fail;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
 
 /**
  * @hide This class is not part of the Android public SDK API
  */
-public class NativeRefTest extends TestCase {
+@RunWith(JUnit4.class)
+public class NativeRefTest {
+    @Test
     public void test_zeroContextThrowsNullPointException() {
         try {
             new NativeRef(0) {
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLKeyTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLKeyTest.java
index e5233190..f211b26d 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLKeyTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLKeyTest.java
@@ -17,14 +17,21 @@
 
 package com.android.org.conscrypt;
 
+import static org.junit.Assert.assertEquals;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
 import java.io.ByteArrayInputStream;
 import java.math.BigInteger;
-import junit.framework.TestCase;
+import java.nio.charset.StandardCharsets;
 
 /**
  * @hide This class is not part of the Android public SDK API
  */
-public class OpenSSLKeyTest extends TestCase {
+@RunWith(JUnit4.class)
+public class OpenSSLKeyTest {
     static final String RSA_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
             + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3G7PGpfZx68wTY9eLb4b\n"
             + "th3Y7MXgh1A2oqB202KTiClKy9Y+Z+HCx5KIXXcycVjAfhK7qG+F/XVeE0TpzR8c\n"
@@ -86,20 +93,23 @@ public class OpenSSLKeyTest extends TestCase {
                             + "8872822c7f2832dafa0fe10d9aba22310849e978e51c8aa9da7bc1c07511d883",
                     16);
 
+    @Test
     public void test_fromPublicKeyPemInputStream() throws Exception {
-        ByteArrayInputStream is = new ByteArrayInputStream(RSA_PUBLIC_KEY.getBytes("UTF-8"));
+        ByteArrayInputStream is =
+                new ByteArrayInputStream(RSA_PUBLIC_KEY.getBytes(StandardCharsets.UTF_8));
         OpenSSLKey key = OpenSSLKey.fromPublicKeyPemInputStream(is);
         OpenSSLRSAPublicKey publicKey = (OpenSSLRSAPublicKey)key.getPublicKey();
         assertEquals(RSA_MODULUS, publicKey.getModulus());
         assertEquals(RSA_PUBLIC_EXPONENT, publicKey.getPublicExponent());
     }
 
+    @Test
     public void test_fromPrivateKeyPemInputStream() throws Exception {
-        ByteArrayInputStream is = new ByteArrayInputStream(RSA_PRIVATE_KEY.getBytes("UTF-8"));
+        ByteArrayInputStream is =
+                new ByteArrayInputStream(RSA_PRIVATE_KEY.getBytes(StandardCharsets.UTF_8));
         OpenSSLKey key = OpenSSLKey.fromPrivateKeyPemInputStream(is);
         OpenSSLRSAPrivateKey privateKey = (OpenSSLRSAPrivateKey)key.getPrivateKey();
         assertEquals(RSA_MODULUS, privateKey.getModulus());
         assertEquals(RSA_PRIVATE_EXPONENT, privateKey.getPrivateExponent());
     }
 }
-
diff --git a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLX509CertificateTest.java b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLX509CertificateTest.java
index ec4089eb..e1ca1640 100644
--- a/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLX509CertificateTest.java
+++ b/repackaged/openjdk/src/test/java/com/android/org/conscrypt/OpenSSLX509CertificateTest.java
@@ -24,9 +24,11 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeFalse;
 
 import com.android.org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;
 
+import org.junit.Assume;
 import org.junit.Ignore;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -51,6 +53,8 @@ import java.util.Arrays;
 public class OpenSSLX509CertificateTest {
     @Test
     public void testSerialization_NoContextDeserialization() throws Exception {
+        // TODO(prb): Re-work avoiding reflection for Java 17+
+        assumeFalse(TestUtils.isJavaVersion(17));
         // Set correct serialVersionUID
         {
             ObjectStreamClass clDesc = ObjectStreamClass.lookup(OpenSSLX509Certificate.class);
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java
index 247c8bfe..aa128721 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/Platform.java
@@ -20,20 +20,20 @@ package com.android.org.conscrypt;
 import static android.system.OsConstants.SOL_SOCKET;
 import static android.system.OsConstants.SO_SNDTIMEO;
 
-import static com.android.org.conscrypt.metrics.Source.SOURCE_MAINLINE;
-
 import android.system.ErrnoException;
 import android.system.Os;
 import android.system.StructTimeval;
 
+import com.android.org.conscrypt.NativeCrypto;
 import com.android.org.conscrypt.ct.LogStore;
 import com.android.org.conscrypt.ct.LogStoreImpl;
 import com.android.org.conscrypt.ct.Policy;
 import com.android.org.conscrypt.ct.PolicyImpl;
-import com.android.org.conscrypt.metrics.CipherSuite;
-import com.android.org.conscrypt.metrics.ConscryptStatsLog;
+import com.android.org.conscrypt.flags.Flags;
 import com.android.org.conscrypt.metrics.OptionalMethod;
-import com.android.org.conscrypt.metrics.Protocol;
+import com.android.org.conscrypt.metrics.Source;
+import com.android.org.conscrypt.metrics.StatsLog;
+import com.android.org.conscrypt.metrics.StatsLogImpl;
 
 import dalvik.system.BlockGuard;
 import dalvik.system.CloseGuard;
@@ -81,14 +81,29 @@ import javax.net.ssl.X509TrustManager;
 
 import sun.security.x509.AlgorithmId;
 
-final class Platform {
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@Internal
+final public class Platform {
     private static class NoPreloadHolder { public static final Platform MAPPER = new Platform(); }
+    static boolean DEPRECATED_TLS_V1 = true;
+    static boolean ENABLED_TLS_V1 = false;
+    private static boolean FILTERED_TLS_V1 = true;
+
+    static {
+        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
+    }
 
     /**
      * Runs all the setup for the platform that only needs to run once.
      */
-    public static void setup() {
+    public static void setup(boolean deprecatedTlsV1, boolean enabledTlsV1) {
         NoPreloadHolder.MAPPER.ping();
+        DEPRECATED_TLS_V1 = deprecatedTlsV1;
+        ENABLED_TLS_V1 = enabledTlsV1;
+        FILTERED_TLS_V1 = !enabledTlsV1;
+        NativeCrypto.setTlsV1DeprecationStatus(DEPRECATED_TLS_V1, ENABLED_TLS_V1);
     }
 
     /**
@@ -537,15 +552,16 @@ final class Platform {
         return System.currentTimeMillis();
     }
 
-    static void countTlsHandshake(
-            boolean success, String protocol, String cipherSuite, long durationLong) {
-        Protocol proto = Protocol.forName(protocol);
-        CipherSuite suite = CipherSuite.forName(cipherSuite);
-        int duration = (int) durationLong;
+    public static StatsLog getStatsLog() {
+        return StatsLogImpl.getInstance();
+    }
+
+    public static Source getStatsSource() {
+        return Source.SOURCE_MAINLINE;
+    }
 
-        ConscryptStatsLog.write(ConscryptStatsLog.TLS_HANDSHAKE_REPORTED, success, proto.getId(),
-                suite.getId(), duration, SOURCE_MAINLINE,
-                new int[] {Os.getuid()});
+    public static int[] getUids() {
+        return new int[] {Os.getuid()};
     }
 
     public static boolean isJavaxCertificateSupported() {
@@ -553,34 +569,34 @@ final class Platform {
     }
 
     public static boolean isTlsV1Deprecated() {
-        return true;
+        return DEPRECATED_TLS_V1;
     }
 
     public static boolean isTlsV1Filtered() {
         Object targetSdkVersion = getTargetSdkVersion();
-        if ((targetSdkVersion != null) && ((int) targetSdkVersion > 34))
+        if ((targetSdkVersion != null) && ((int) targetSdkVersion > 35)
+               && ((int) targetSdkVersion < 100))
             return false;
-        return true;
+        return FILTERED_TLS_V1;
     }
 
     public static boolean isTlsV1Supported() {
-        return false;
+        return ENABLED_TLS_V1;
     }
 
     static Object getTargetSdkVersion() {
         try {
-            Class<?> vmRuntime = Class.forName("dalvik.system.VMRuntime");
-            if (vmRuntime == null) {
-                return null;
-            }
-            OptionalMethod getSdkVersion =
-                    new OptionalMethod(vmRuntime,
-                                        "getTargetSdkVersion");
-            return getSdkVersion.invokeStatic();
-        } catch (ClassNotFoundException e) {
-            return null;
-        } catch (NullPointerException e) {
+            Class<?> vmRuntimeClass = Class.forName("dalvik.system.VMRuntime");
+            Method getRuntimeMethod = vmRuntimeClass.getDeclaredMethod("getRuntime");
+            Method getTargetSdkVersionMethod =
+                        vmRuntimeClass.getDeclaredMethod("getTargetSdkVersion");
+            Object vmRuntime = getRuntimeMethod.invoke(null);
+            return getTargetSdkVersionMethod.invoke(vmRuntime);
+        } catch (IllegalAccessException |
+          NullPointerException | InvocationTargetException e) {
             return null;
+        } catch (Exception e) {
+            throw new RuntimeException(e);
         }
     }
 }
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java
index be57cb71..a9f75df8 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/LogStoreImpl.java
@@ -23,6 +23,8 @@ import static java.nio.charset.StandardCharsets.UTF_8;
 import com.android.org.conscrypt.ByteArray;
 import com.android.org.conscrypt.Internal;
 import com.android.org.conscrypt.OpenSSLKey;
+import com.android.org.conscrypt.Platform;
+import com.android.org.conscrypt.metrics.StatsLog;
 
 import org.json.JSONArray;
 import org.json.JSONException;
@@ -37,9 +39,6 @@ import java.nio.file.Paths;
 import java.security.InvalidKeyException;
 import java.security.NoSuchAlgorithmException;
 import java.security.PublicKey;
-import java.text.DateFormat;
-import java.text.ParseException;
-import java.text.SimpleDateFormat;
 import java.util.Arrays;
 import java.util.Base64;
 import java.util.Collections;
@@ -55,28 +54,40 @@ import java.util.logging.Logger;
 @Internal
 public class LogStoreImpl implements LogStore {
     private static final Logger logger = Logger.getLogger(LogStoreImpl.class.getName());
-    public static final String V3_PATH = "/misc/keychain/ct/v3/log_list.json";
-    private static final Path defaultLogList;
+    private static final String BASE_PATH = "misc/keychain/ct";
+    private static final int COMPAT_VERSION = 1;
+    private static final String CURRENT = "current";
+    private static final String LOG_LIST_FILENAME = "log_list.json";
+    private static final Path DEFAULT_LOG_LIST;
 
     static {
-        String ANDROID_DATA = System.getenv("ANDROID_DATA");
-        defaultLogList = Paths.get(ANDROID_DATA, V3_PATH);
+        String androidData = System.getenv("ANDROID_DATA");
+        String compatVersion = String.format("v%d", COMPAT_VERSION);
+        DEFAULT_LOG_LIST =
+                Paths.get(androidData, BASE_PATH, compatVersion, CURRENT, LOG_LIST_FILENAME);
     }
 
     private final Path logList;
+    private StatsLog metrics;
     private State state;
     private Policy policy;
-    private String version;
+    private int majorVersion;
+    private int minorVersion;
     private long timestamp;
     private Map<ByteArray, LogInfo> logs;
 
     public LogStoreImpl() {
-        this(defaultLogList);
+        this(DEFAULT_LOG_LIST);
     }
 
     public LogStoreImpl(Path logList) {
+        this(logList, Platform.getStatsLog());
+    }
+
+    public LogStoreImpl(Path logList, StatsLog metrics) {
         this.state = State.UNINITIALIZED;
         this.logList = logList;
+        this.metrics = metrics;
     }
 
     @Override
@@ -90,6 +101,32 @@ public class LogStoreImpl implements LogStore {
         return timestamp;
     }
 
+    @Override
+    public int getMajorVersion() {
+        return majorVersion;
+    }
+
+    @Override
+    public int getMinorVersion() {
+        return minorVersion;
+    }
+
+    @Override
+    public int getCompatVersion() {
+        // Currently, there is only one compatibility version supported. If we
+        // are loaded or initialized, it means the expected compatibility
+        // version was found.
+        if (state == State.LOADED || state == State.COMPLIANT || state == State.NON_COMPLIANT) {
+            return COMPAT_VERSION;
+        }
+        return 0;
+    }
+
+    @Override
+    public int getMinCompatVersionAvailable() {
+        return getCompatVersion();
+    }
+
     @Override
     public void setPolicy(Policy policy) {
         this.policy = policy;
@@ -116,12 +153,16 @@ public class LogStoreImpl implements LogStore {
      */
     private boolean ensureLogListIsLoaded() {
         synchronized (this) {
+            State previousState = state;
             if (state == State.UNINITIALIZED) {
                 state = loadLogList();
             }
             if (state == State.LOADED && policy != null) {
                 state = policy.isLogStoreCompliant(this) ? State.COMPLIANT : State.NON_COMPLIANT;
             }
+            if (state != previousState && metrics != null) {
+                metrics.updateCTLogListStatusChanged(this);
+            }
             return state == State.COMPLIANT;
         }
     }
@@ -145,8 +186,9 @@ public class LogStoreImpl implements LogStore {
         }
         HashMap<ByteArray, LogInfo> logsMap = new HashMap<>();
         try {
-            version = json.getString("version");
-            timestamp = parseTimestamp(json.getString("log_list_timestamp"));
+            majorVersion = parseMajorVersion(json.getString("version"));
+            minorVersion = parseMinorVersion(json.getString("version"));
+            timestamp = json.getLong("log_list_timestamp");
             JSONArray operators = json.getJSONArray("operators");
             for (int i = 0; i < operators.length(); i++) {
                 JSONObject operator = operators.getJSONObject(i);
@@ -165,9 +207,8 @@ public class LogStoreImpl implements LogStore {
                     JSONObject stateObject = log.optJSONObject("state");
                     if (stateObject != null) {
                         String state = stateObject.keys().next();
-                        String stateTimestamp =
-                                stateObject.getJSONObject(state).getString("timestamp");
-                        builder.setState(parseState(state), parseTimestamp(stateTimestamp));
+                        long stateTimestamp = stateObject.getJSONObject(state).getLong("timestamp");
+                        builder.setState(parseState(state), stateTimestamp);
                     }
 
                     LogInfo logInfo = builder.build();
@@ -189,6 +230,30 @@ public class LogStoreImpl implements LogStore {
         return State.LOADED;
     }
 
+    private static int parseMajorVersion(String version) {
+        int pos = version.indexOf(".");
+        if (pos == -1) {
+            pos = version.length();
+        }
+        try {
+            return Integer.parseInt(version.substring(0, pos));
+        } catch (IndexOutOfBoundsException | NumberFormatException e) {
+            return 0;
+        }
+    }
+
+    private static int parseMinorVersion(String version) {
+        int pos = version.indexOf(".");
+        if (pos != -1 && pos < version.length()) {
+            try {
+                return Integer.parseInt(version.substring(pos + 1, version.length()));
+            } catch (IndexOutOfBoundsException | NumberFormatException e) {
+                return 0;
+            }
+        }
+        return 0;
+    }
+
     private static int parseState(String state) {
         switch (state) {
             case "pending":
@@ -208,19 +273,6 @@ public class LogStoreImpl implements LogStore {
         }
     }
 
-    // ISO 8601
-    private static DateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");
-
-    @SuppressWarnings("JavaUtilDate")
-    private static long parseTimestamp(String timestamp) {
-        try {
-            Date date = dateFormatter.parse(timestamp);
-            return date.getTime();
-        } catch (ParseException e) {
-            throw new IllegalArgumentException(e);
-        }
-    }
-
     private static PublicKey parsePubKey(String key) {
         byte[] pem = ("-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----")
                              .getBytes(US_ASCII);
diff --git a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/PolicyImpl.java b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/PolicyImpl.java
index a1b0edef..280579f0 100644
--- a/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/PolicyImpl.java
+++ b/repackaged/platform/src/main/java/com/android/org/conscrypt/ct/PolicyImpl.java
@@ -78,10 +78,17 @@ public class PolicyImpl implements Policy {
                 ocspOrTLSValidSCTs.add(vsct);
             }
         }
+        PolicyCompliance compliance = PolicyCompliance.NOT_ENOUGH_SCTS;
         if (embeddedValidSCTs.size() > 0) {
-            return conformEmbeddedSCTs(embeddedValidSCTs, leaf, atTime);
+            compliance = conformEmbeddedSCTs(embeddedValidSCTs, leaf, atTime);
+            if (compliance == PolicyCompliance.COMPLY) {
+                return compliance;
+            }
+        }
+        if (ocspOrTLSValidSCTs.size() > 0) {
+            compliance = conformOCSPorTLSSCTs(ocspOrTLSValidSCTs, atTime);
         }
-        return PolicyCompliance.NOT_ENOUGH_SCTS;
+        return compliance;
     }
 
     private void filterOutUnknown(List<VerifiedSCT> scts) {
@@ -189,4 +196,37 @@ public class PolicyImpl implements Policy {
 
         return PolicyCompliance.COMPLY;
     }
+
+    private PolicyCompliance conformOCSPorTLSSCTs(
+            Set<VerifiedSCT> ocspOrTLSValidSCTs, long atTime) {
+        /* 1. At least two SCTs from a CT Log that was Qualified, Usable, or
+         *    ReadOnly at the time of check;
+         */
+        Set<LogInfo> validLogs = new HashSet<>();
+        for (VerifiedSCT vsct : ocspOrTLSValidSCTs) {
+            LogInfo log = vsct.getLogInfo();
+            switch (log.getStateAt(atTime)) {
+                case LogInfo.STATE_QUALIFIED:
+                case LogInfo.STATE_USABLE:
+                case LogInfo.STATE_READONLY:
+                    validLogs.add(log);
+            }
+        }
+        if (validLogs.size() < 2) {
+            return PolicyCompliance.NOT_ENOUGH_SCTS;
+        }
+
+        /* 2. Among the SCTs satisfying requirement 1, at least two SCTs must
+         * be issued from distinct CT Log Operators as recognized by Chrome.
+         */
+        Set<String> operators = new HashSet<>();
+        for (LogInfo logInfo : validLogs) {
+            operators.add(logInfo.getOperator());
+        }
+        if (operators.size() < 2) {
+            return PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS;
+        }
+
+        return PolicyCompliance.COMPLY;
+    }
 }
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/TlsDeprecationTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/TlsDeprecationTest.java
new file mode 100644
index 00000000..cbeac011
--- /dev/null
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/TlsDeprecationTest.java
@@ -0,0 +1,170 @@
+/* GENERATED SOURCE. DO NOT MODIFY. */
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
+package com.android.org.conscrypt;
+
+import libcore.junit.util.SwitchTargetSdkVersionRule;
+import libcore.junit.util.SwitchTargetSdkVersionRule.TargetSdkVersion;
+
+import java.security.Provider;
+import javax.net.ssl.SSLSocket;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.Rule;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import com.android.org.conscrypt.javax.net.ssl.TestSSLContext;
+
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.assertThrows;
+import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeFalse;
+
+/**
+ * @hide This class is not part of the Android public SDK API
+ */
+@RunWith(JUnit4.class)
+public class TlsDeprecationTest {
+    @Rule
+    public final TestRule switchTargetSdkVersionRule = SwitchTargetSdkVersionRule.getInstance();
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(36)
+    public void test_SSLSocket_SSLv3Unsupported_36() throws Exception {
+        assertFalse(TestUtils.isTlsV1Filtered());
+        TestSSLContext context = TestSSLContext.create();
+        final SSLSocket client =
+                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
+        assertThrows(IllegalArgumentException.class, () -> client.setEnabledProtocols(new String[] {"SSLv3"}));
+        assertThrows(IllegalArgumentException.class, () -> client.setEnabledProtocols(new String[] {"SSL"}));
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void test_SSLSocket_SSLv3Unsupported_34() throws Exception {
+        assertTrue(TestUtils.isTlsV1Filtered());
+        TestSSLContext context = TestSSLContext.create();
+        final SSLSocket client =
+                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
+        // For app compatibility, SSLv3 is stripped out when setting only.
+        client.setEnabledProtocols(new String[] {"SSLv3"});
+        assertEquals(0, client.getEnabledProtocols().length);
+        assertThrows(IllegalArgumentException.class, () -> client.setEnabledProtocols(new String[] {"SSL"}));
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void test_TLSv1Filtered_34() throws Exception {
+        assertTrue(TestUtils.isTlsV1Filtered());
+        TestSSLContext context = TestSSLContext.create();
+        final SSLSocket client =
+                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
+        client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"});
+        assertEquals(1, client.getEnabledProtocols().length);
+        assertEquals("TLSv1.2", client.getEnabledProtocols()[0]);
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void test_TLSv1FilteredEmpty_34() throws Exception {
+        assertTrue(TestUtils.isTlsV1Filtered());
+        TestSSLContext context = TestSSLContext.create();
+        final SSLSocket client =
+                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
+        client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1",});
+        assertEquals(0, client.getEnabledProtocols().length);
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(36)
+    public void test_TLSv1Filtered_36() throws Exception {
+        assertFalse(TestUtils.isTlsV1Filtered());
+        TestSSLContext context = TestSSLContext.create();
+        final SSLSocket client =
+                (SSLSocket) context.clientContext.getSocketFactory().createSocket();
+        assertThrows(IllegalArgumentException.class, () ->
+            client.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"}));
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void testInitializeDeprecatedEnabled_34() {
+        Provider conscryptProvider = TestUtils.getConscryptProvider(true, true);
+        assertTrue(TestUtils.isTlsV1Deprecated());
+        assertFalse(TestUtils.isTlsV1Filtered());
+        assertTrue(TestUtils.isTlsV1Supported());
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(36)
+    public void testInitializeDeprecatedEnabled_36() {
+        Provider conscryptProvider = TestUtils.getConscryptProvider(true, true);
+        assertTrue(TestUtils.isTlsV1Deprecated());
+        assertFalse(TestUtils.isTlsV1Filtered());
+        assertTrue(TestUtils.isTlsV1Supported());
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void testInitializeDeprecatedDisabled_34() {
+        Provider conscryptProvider = TestUtils.getConscryptProvider(true, false);
+        assertTrue(TestUtils.isTlsV1Deprecated());
+        assertTrue(TestUtils.isTlsV1Filtered());
+        assertFalse(TestUtils.isTlsV1Supported());
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(36)
+    public void testInitializeDeprecatedDisabled_36() {
+        Provider conscryptProvider = TestUtils.getConscryptProvider(true, false);
+        assertTrue(TestUtils.isTlsV1Deprecated());
+        assertFalse(TestUtils.isTlsV1Filtered());
+        assertFalse(TestUtils.isTlsV1Supported());
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void testInitializeUndeprecatedEnabled_34() {
+        Provider conscryptProvider = TestUtils.getConscryptProvider(false, true);
+        assertFalse(TestUtils.isTlsV1Deprecated());
+        assertFalse(TestUtils.isTlsV1Filtered());
+        assertTrue(TestUtils.isTlsV1Supported());
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(36)
+    public void testInitializeUndeprecatedEnabled_36() {
+        Provider conscryptProvider = TestUtils.getConscryptProvider(false, true);
+        assertFalse(TestUtils.isTlsV1Deprecated());
+        assertFalse(TestUtils.isTlsV1Filtered());
+        assertTrue(TestUtils.isTlsV1Supported());
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(34)
+    public void testInitializeUndeprecatedDisabled_34() {
+        assertThrows(RuntimeException.class, () -> TestUtils.getConscryptProvider(false, false));
+    }
+
+    @Test
+    @SwitchTargetSdkVersionRule.TargetSdkVersion(36)
+    public void testInitializeUndeprecatedDisabled_36() {
+        assertThrows(RuntimeException.class, () -> TestUtils.getConscryptProvider(false, false));
+    }
+}
\ No newline at end of file
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java
index 2b8f3790..e7b33ac1 100644
--- a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/LogStoreImplTest.java
@@ -21,9 +21,7 @@ import static java.nio.charset.StandardCharsets.US_ASCII;
 import static java.nio.charset.StandardCharsets.UTF_8;
 
 import com.android.org.conscrypt.OpenSSLKey;
-
-import libcore.test.annotation.NonCts;
-import libcore.test.reasons.NonCtsReasons;
+import com.android.org.conscrypt.metrics.StatsLog;
 
 import junit.framework.TestCase;
 
@@ -36,19 +34,56 @@ import java.io.IOException;
 import java.io.OutputStreamWriter;
 import java.io.PrintWriter;
 import java.security.PublicKey;
+import java.security.cert.X509Certificate;
+import java.util.ArrayList;
 import java.util.Base64;
 
 /**
  * @hide This class is not part of the Android public SDK API
  */
 public class LogStoreImplTest extends TestCase {
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
-    public void test_loadLogList() throws Exception {
+    static class FakeStatsLog implements StatsLog {
+        public ArrayList<LogStore.State> states = new ArrayList<LogStore.State>();
+
+        @Override
+        public void countTlsHandshake(
+                boolean success, String protocol, String cipherSuite, long duration) {}
+        @Override
+        public void updateCTLogListStatusChanged(LogStore logStore) {
+            states.add(logStore.getState());
+        }
+    }
+
+    Policy alwaysCompliantStorePolicy = new Policy() {
+        @Override
+        public boolean isLogStoreCompliant(LogStore store) {
+            return true;
+        }
+        @Override
+        public PolicyCompliance doesResultConformToPolicy(
+                VerificationResult result, X509Certificate leaf) {
+            return PolicyCompliance.COMPLY;
+        }
+    };
+
+    Policy neverCompliantStorePolicy = new Policy() {
+        @Override
+        public boolean isLogStoreCompliant(LogStore store) {
+            return false;
+        }
+        @Override
+        public PolicyCompliance doesResultConformToPolicy(
+                VerificationResult result, X509Certificate leaf) {
+            return PolicyCompliance.COMPLY;
+        }
+    };
+
+    public void test_loadValidLogList() throws Exception {
         // clang-format off
         String content = "" +
 "{" +
 "  \"version\": \"1.1\"," +
-"  \"log_list_timestamp\": \"2024-01-01T11:55:12Z\"," +
+"  \"log_list_timestamp\": 1704070861000," +
 "  \"operators\": [" +
 "    {" +
 "      \"name\": \"Operator 1\"," +
@@ -62,12 +97,12 @@ public class LogStoreImplTest extends TestCase {
 "          \"mmd\": 86400," +
 "          \"state\": {" +
 "            \"usable\": {" +
-"              \"timestamp\": \"2022-11-01T18:54:00Z\"" +
+"              \"timestamp\": 1667328840000" +
 "            }" +
 "          }," +
 "          \"temporal_interval\": {" +
-"            \"start_inclusive\": \"2024-01-01T00:00:00Z\"," +
-"            \"end_exclusive\": \"2025-01-01T00:00:00Z\"" +
+"            \"start_inclusive\": 1704070861000," +
+"            \"end_exclusive\": 1735693261000" +
 "          }" +
 "        }," +
 "        {" +
@@ -78,12 +113,12 @@ public class LogStoreImplTest extends TestCase {
 "          \"mmd\": 86400," +
 "          \"state\": {" +
 "            \"usable\": {" +
-"              \"timestamp\": \"2023-11-26T12:00:00Z\"" +
+"              \"timestamp\": 1700960461000" +
 "            }" +
 "          }," +
 "          \"temporal_interval\": {" +
-"            \"start_inclusive\": \"2025-01-01T00:00:00Z\"," +
-"            \"end_exclusive\": \"2025-07-01T00:00:00Z\"" +
+"            \"start_inclusive\": 1735693261000," +
+"            \"end_exclusive\": 1751331661000" +
 "          }" +
 "        }" +
 "      ]" +
@@ -100,12 +135,12 @@ public class LogStoreImplTest extends TestCase {
 "          \"mmd\": 86400," +
 "          \"state\": {" +
 "            \"usable\": {" +
-"              \"timestamp\": \"2022-11-30T17:00:00Z\"" +
+"              \"timestamp\": 1669770061000" +
 "            }" +
 "          }," +
 "          \"temporal_interval\": {" +
-"            \"start_inclusive\": \"2024-01-01T00:00:00Z\"," +
-"            \"end_exclusive\": \"2025-01-01T00:00:00Z\"" +
+"            \"start_inclusive\": 1704070861000," +
+"            \"end_exclusive\": 1735693261000" +
 "          }" +
 "        }" +
 "      ]" +
@@ -114,14 +149,10 @@ public class LogStoreImplTest extends TestCase {
 "}";
         // clang-format on
 
+        FakeStatsLog metrics = new FakeStatsLog();
         File logList = writeFile(content);
-        LogStore store = new LogStoreImpl(logList.toPath());
-        store.setPolicy(new PolicyImpl() {
-            @Override
-            public boolean isLogStoreCompliant(LogStore store) {
-                return true;
-            }
-        });
+        LogStore store = new LogStoreImpl(logList.toPath(), metrics);
+        store.setPolicy(alwaysCompliantStorePolicy);
 
         assertNull("A null logId should return null", store.getKnownLog(null));
 
@@ -142,6 +173,36 @@ public class LogStoreImplTest extends TestCase {
                         .build();
         byte[] log1Id = Base64.getDecoder().decode("7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=");
         assertEquals("An existing logId should be returned", log1, store.getKnownLog(log1Id));
+        assertEquals("One metric update should be emitted", metrics.states.size(), 1);
+        assertEquals("The metric update for log list state should be compliant",
+                metrics.states.get(0), LogStore.State.COMPLIANT);
+    }
+
+    public void test_loadMalformedLogList() throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        String content = "}}";
+        File logList = writeFile(content);
+        LogStore store = new LogStoreImpl(logList.toPath(), metrics);
+        store.setPolicy(alwaysCompliantStorePolicy);
+
+        assertEquals(
+                "The log state should be malformed", store.getState(), LogStore.State.MALFORMED);
+        assertEquals("One metric update should be emitted", metrics.states.size(), 1);
+        assertEquals("The metric update for log list state should be malformed",
+                metrics.states.get(0), LogStore.State.MALFORMED);
+    }
+
+    public void test_loadMissingLogList() throws Exception {
+        FakeStatsLog metrics = new FakeStatsLog();
+        File logList = new File("does_not_exist");
+        LogStore store = new LogStoreImpl(logList.toPath(), metrics);
+        store.setPolicy(alwaysCompliantStorePolicy);
+
+        assertEquals(
+                "The log state should be not found", store.getState(), LogStore.State.NOT_FOUND);
+        assertEquals("One metric update should be emitted", metrics.states.size(), 1);
+        assertEquals("The metric update for log list state should be not found",
+                metrics.states.get(0), LogStore.State.NOT_FOUND);
     }
 
     private File writeFile(String content) throws IOException {
diff --git a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/PolicyImplTest.java b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/PolicyImplTest.java
index 0c0d7f13..d82efb05 100644
--- a/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/PolicyImplTest.java
+++ b/repackaged/platform/src/test/java/com/android/org/conscrypt/ct/PolicyImplTest.java
@@ -23,9 +23,6 @@ import static org.junit.Assert.assertTrue;
 
 import com.android.org.conscrypt.java.security.cert.FakeX509Certificate;
 
-import libcore.test.annotation.NonCts;
-import libcore.test.reasons.NonCtsReasons;
-
 import org.junit.Assume;
 import org.junit.BeforeClass;
 import org.junit.Test;
@@ -49,6 +46,7 @@ public class PolicyImplTest {
     private static LogInfo usableOp2Log;
     private static LogInfo retiredOp2Log;
     private static SignedCertificateTimestamp embeddedSCT;
+    private static SignedCertificateTimestamp ocspSCT;
 
     /* Some test dates. By default:
      *  - The verification is occurring in January 2024;
@@ -136,10 +134,11 @@ public class PolicyImplTest {
          */
         embeddedSCT = new SignedCertificateTimestamp(SignedCertificateTimestamp.Version.V1, null,
                 JAN2023, null, null, SignedCertificateTimestamp.Origin.EMBEDDED);
+        ocspSCT = new SignedCertificateTimestamp(SignedCertificateTimestamp.Version.V1, null,
+                JAN2023, null, null, SignedCertificateTimestamp.Origin.OCSP_RESPONSE);
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void emptyVerificationResult() throws Exception {
         PolicyImpl p = new PolicyImpl();
         VerificationResult result = new VerificationResult();
@@ -149,17 +148,15 @@ public class PolicyImplTest {
                 p.doesResultConformToPolicyAt(result, leaf, JAN2024));
     }
 
-    @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
-    public void validVerificationResult() throws Exception {
+    public void validVerificationResult(SignedCertificateTimestamp sct) throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(usableOp1Log1)
                                     .build();
 
-        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(usableOp2Log)
                                     .build();
@@ -174,8 +171,17 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
-    public void validWithRetiredVerificationResult() throws Exception {
+    public void validEmbeddedVerificationResult() throws Exception {
+        validVerificationResult(embeddedSCT);
+    }
+
+    @Test
+    public void validOCSPVerificationResult() throws Exception {
+        validVerificationResult(ocspSCT);
+    }
+
+    @Test
+    public void validEmbeddedWithRetiredVerificationResult() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
         VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
@@ -198,15 +204,39 @@ public class PolicyImplTest {
     }
 
     @Test
-    public void invalidWithRetiredVerificationResult() throws Exception {
+    public void invalidOCSPWithRecentRetiredVerificationResult() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(ocspSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(retiredOp1LogNew)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(ocspSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("One valid, one retired SCTs from different operators",
+                PolicyCompliance.NOT_ENOUGH_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    public void invalidWithRetiredVerificationResult(SignedCertificateTimestamp sct)
+            throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(retiredOp1LogOld)
                                     .build();
 
-        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(usableOp2Log)
                                     .build();
@@ -222,11 +252,19 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
-    public void invalidOneSctVerificationResult() throws Exception {
+    public void invalidEmbeddedWithRetiredVerificationResult() throws Exception {
+        invalidWithRetiredVerificationResult(embeddedSCT);
+    }
+
+    @Test
+    public void invalidOCSPWithRetiredVerificationResult() throws Exception {
+        invalidWithRetiredVerificationResult(ocspSCT);
+    }
+
+    public void invalidOneSctVerificationResult(SignedCertificateTimestamp sct) throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(usableOp1Log1)
                                     .build();
@@ -240,16 +278,25 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
-    public void invalidTwoSctsVerificationResult() throws Exception {
+    public void invalidEmbeddedOneSctVerificationResult() throws Exception {
+        invalidOneSctVerificationResult(embeddedSCT);
+    }
+
+    @Test
+    public void invalidOCSPOneSctVerificationResult() throws Exception {
+        invalidOneSctVerificationResult(ocspSCT);
+    }
+
+    public void invalidTwoRetiredSctsVerificationResult(SignedCertificateTimestamp sct)
+            throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(retiredOp1LogNew)
                                     .build();
 
-        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(retiredOp2Log)
                                     .build();
@@ -264,16 +311,25 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
-    public void invalidTwoSctsSameOperatorVerificationResult() throws Exception {
+    public void invalidEmbeddedTwoRetiredSctsVerificationResult() throws Exception {
+        invalidTwoRetiredSctsVerificationResult(embeddedSCT);
+    }
+
+    @Test
+    public void invalidOCSPTwoRetiredSctsVerificationResult() throws Exception {
+        invalidTwoRetiredSctsVerificationResult(ocspSCT);
+    }
+
+    public void invalidTwoSctsSameOperatorVerificationResult(SignedCertificateTimestamp sct)
+            throws Exception {
         PolicyImpl p = new PolicyImpl();
 
-        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(usableOp1Log1)
                                     .build();
 
-        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
                                     .setStatus(VerifiedSCT.Status.VALID)
                                     .setLogInfo(usableOp1Log2)
                                     .build();
@@ -288,7 +344,39 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
+    public void invalidEmbeddedTwoSctsSameOperatorVerificationResult() throws Exception {
+        invalidTwoSctsSameOperatorVerificationResult(embeddedSCT);
+    }
+
+    @Test
+    public void invalidOCSPTwoSctsSameOperatorVerificationResult() throws Exception {
+        invalidTwoSctsSameOperatorVerificationResult(ocspSCT);
+    }
+
+    @Test
+    public void invalidOneEmbeddedOneOCSPVerificationResult() throws Exception {
+        PolicyImpl p = new PolicyImpl();
+
+        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp1Log1)
+                                    .build();
+
+        VerifiedSCT vsct2 = new VerifiedSCT.Builder(ocspSCT)
+                                    .setStatus(VerifiedSCT.Status.VALID)
+                                    .setLogInfo(usableOp2Log)
+                                    .build();
+
+        VerificationResult result = new VerificationResult();
+        result.add(vsct1);
+        result.add(vsct2);
+
+        X509Certificate leaf = new FakeX509Certificate();
+        assertEquals("Two valid SCTs with different origins", PolicyCompliance.NOT_ENOUGH_SCTS,
+                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
+    }
+
+    @Test
     public void validRecentLogStore() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
@@ -302,7 +390,6 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void invalidFutureLogStore() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
@@ -316,7 +403,6 @@ public class PolicyImplTest {
     }
 
     @Test
-    @NonCts(reason = NonCtsReasons.INTERNAL_APIS)
     public void invalidOldLogStore() throws Exception {
         PolicyImpl p = new PolicyImpl();
 
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/TestUtils.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/TestUtils.java
index 21ee838b..c94608b1 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/TestUtils.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/TestUtils.java
@@ -241,25 +241,33 @@ public final class TestUtils {
         }
     }
 
-    public static Provider getConscryptProvider() {
+    public static Provider getConscryptProvider(boolean isTlsV1Deprecated,
+            boolean isTlsV1Enabled) {
         try {
             String defaultName = (String) conscryptClass("Platform")
                 .getDeclaredMethod("getDefaultProviderName")
                 .invoke(null);
             Constructor<?> c =
                     conscryptClass("OpenSSLProvider")
-                            .getDeclaredConstructor(String.class, Boolean.TYPE, String.class);
+                            .getDeclaredConstructor(String.class, Boolean.TYPE,
+                                String.class, Boolean.TYPE, Boolean.TYPE);
 
             if (!isClassAvailable("javax.net.ssl.X509ExtendedTrustManager")) {
-                return (Provider) c.newInstance(defaultName, false, "TLSv1.3");
+                return (Provider) c.newInstance(defaultName, false, "TLSv1.3",
+                    isTlsV1Deprecated, isTlsV1Enabled);
             } else {
-                return (Provider) c.newInstance(defaultName, true, "TLSv1.3");
+                return (Provider) c.newInstance(defaultName, true, "TLSv1.3",
+                    isTlsV1Deprecated, isTlsV1Enabled);
             }
         } catch (Exception e) {
             throw new RuntimeException(e);
         }
     }
 
+    public static Provider getConscryptProvider() {
+        return getConscryptProvider(true, false);
+    }
+
     public static synchronized void installConscryptAsDefaultProvider() {
         Provider conscryptProvider = getConscryptProvider();
         Provider[] providers = Security.getProviders();
@@ -324,7 +332,7 @@ public final class TestUtils {
                 if (index < 0) {
                     throw new IllegalStateException("No = found: line " + lineNumber);
                 }
-                String label = line.substring(0, index).trim().toLowerCase();
+                String label = line.substring(0, index).trim().toLowerCase(Locale.ROOT);
                 String value = line.substring(index + 1).trim();
                 if ("name".equals(label)) {
                     current = new TestVector();
@@ -670,7 +678,7 @@ public final class TestUtils {
     /**
      * Decodes the provided hexadecimal string into a byte array.  Odd-length inputs
      * are not allowed.
-     *
+     * <p>
      * Throws an {@code IllegalArgumentException} if the input is malformed.
      */
     public static byte[] decodeHex(String encoded) throws IllegalArgumentException {
@@ -681,7 +689,7 @@ public final class TestUtils {
      * Decodes the provided hexadecimal string into a byte array. If {@code allowSingleChar}
      * is {@code true} odd-length inputs are allowed and the first character is interpreted
      * as the lower bits of the first result byte.
-     *
+     * <p>
      * Throws an {@code IllegalArgumentException} if the input is malformed.
      */
     public static byte[] decodeHex(String encoded, boolean allowSingleChar) throws IllegalArgumentException {
@@ -691,7 +699,7 @@ public final class TestUtils {
     /**
      * Decodes the provided hexadecimal string into a byte array.  Odd-length inputs
      * are not allowed.
-     *
+     * <p>
      * Throws an {@code IllegalArgumentException} if the input is malformed.
      */
     public static byte[] decodeHex(char[] encoded) throws IllegalArgumentException {
@@ -702,7 +710,7 @@ public final class TestUtils {
      * Decodes the provided hexadecimal string into a byte array. If {@code allowSingleChar}
      * is {@code true} odd-length inputs are allowed and the first character is interpreted
      * as the lower bits of the first result byte.
-     *
+     * <p>
      * Throws an {@code IllegalArgumentException} if the input is malformed.
      */
     public static byte[] decodeHex(char[] encoded, boolean allowSingleChar) throws IllegalArgumentException {
@@ -870,40 +878,29 @@ public final class TestUtils {
         Assume.assumeTrue(findClass("java.security.spec.XECPrivateKeySpec") != null);
     }
 
-    // Find base method via reflection due to visibility issues when building with Gradle.
     public static boolean isTlsV1Deprecated() {
-        try {
-            return (Boolean) conscryptClass("Platform")
-                    .getDeclaredMethod("isTlsV1Deprecated")
-                    .invoke(null);
-        } catch (Exception e) {
-            throw new RuntimeException(e);
-        }
+        return callPlatformMethod("isTlsV1Deprecated", false);
     }
 
-    // Find base method via reflection due to possible version skew on Android
-    // and visibility issues when building with Gradle.
     public static boolean isTlsV1Filtered() {
-        try {
-            return (Boolean) conscryptClass("Platform")
-                    .getDeclaredMethod("isTlsV1Filtered")
-                    .invoke(null);
-        } catch (NoSuchMethodException e) {
-            return true;
-        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException e) {
-            throw new IllegalStateException("Reflection failure", e);
-        }
+        return callPlatformMethod("isTlsV1Filtered", true);
     }
 
-    // Find base method via reflection due to possible version skew on Android
-    // and visibility issues when building with Gradle.
     public static boolean isTlsV1Supported() {
+        return callPlatformMethod("isTlsV1Supported", true);
+    }
+
+    public static boolean isJavaxCertificateSupported() {
+        return callPlatformMethod("isJavaxCertificateSupported", true);
+    }
+
+    // Calls a boolean platform method by reflection.  If the method is not present, e.g.
+    // due to version skew etc then return the default value.
+    public static boolean callPlatformMethod(String methodName, boolean defaultValue) {
         try {
-            return (Boolean) conscryptClass("Platform")
-                    .getDeclaredMethod("isTlsV1Supported")
-                    .invoke(null);
+            return (Boolean) conscryptClass("Platform").getDeclaredMethod(methodName).invoke(null);
         } catch (NoSuchMethodException e) {
-            return false;
+            return defaultValue;
         } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException e) {
             throw new IllegalStateException("Reflection failure", e);
         }
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/VeryBasicHttpServer.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/VeryBasicHttpServer.java
index 12f19b4d..579ff9e5 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/VeryBasicHttpServer.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/VeryBasicHttpServer.java
@@ -17,6 +17,8 @@
 
 package com.android.org.conscrypt;
 
+import com.android.org.conscrypt.javax.net.ssl.TestSSLContext;
+
 import java.io.BufferedReader;
 import java.io.IOException;
 import java.io.InputStreamReader;
@@ -27,12 +29,13 @@ import java.net.Socket;
 import java.net.URL;
 import java.nio.charset.StandardCharsets;
 import java.util.HashMap;
+import java.util.List;
 import java.util.Map;
 import java.util.Objects;
 import java.util.concurrent.Callable;
+
 import javax.net.ssl.HttpsURLConnection;
 import javax.net.ssl.SSLSocket;
-import com.android.org.conscrypt.javax.net.ssl.TestSSLContext;
 
 /**
  * Very basic http server. Literally just enough to do some HTTP 1.1 in order
@@ -110,6 +113,7 @@ public class VeryBasicHttpServer {
         }
     }
 
+    @SuppressWarnings("StringSplitter") // It's close enough for government work.
     private Request readRequest(Socket socket) throws Exception {
         Request request = new Request();
         request.outputStream = socket.getOutputStream();
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/AlgorithmParameterAsymmetricHelper.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/AlgorithmParameterAsymmetricHelper.java
index bbc6bd48..c469086e 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/AlgorithmParameterAsymmetricHelper.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/AlgorithmParameterAsymmetricHelper.java
@@ -17,12 +17,13 @@
 
 package com.android.org.conscrypt.java.security;
 
-import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.assertArrayEquals;
 
+import java.nio.charset.StandardCharsets;
 import java.security.AlgorithmParameters;
 import java.security.KeyPair;
 import java.security.KeyPairGenerator;
-import java.util.Arrays;
+
 import javax.crypto.Cipher;
 
 /**
@@ -51,10 +52,10 @@ public class AlgorithmParameterAsymmetricHelper extends TestHelper<AlgorithmPara
 
         Cipher cipher = Cipher.getInstance(algorithmName);
         cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), parameters);
-        byte[] bs = cipher.doFinal(plainData.getBytes("UTF-8"));
+        byte[] bs = cipher.doFinal(plainData.getBytes(StandardCharsets.UTF_8));
 
         cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), parameters);
         byte[] decrypted = cipher.doFinal(bs);
-        assertTrue(Arrays.equals(plainData.getBytes("UTF-8"), decrypted));
+        assertArrayEquals(plainData.getBytes(StandardCharsets.UTF_8), decrypted);
     }
 }
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/AlgorithmParameterSignatureHelper.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/AlgorithmParameterSignatureHelper.java
index 1c45cdf5..4241f1fb 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/AlgorithmParameterSignatureHelper.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/AlgorithmParameterSignatureHelper.java
@@ -19,6 +19,7 @@ package com.android.org.conscrypt.java.security;
 
 import static org.junit.Assert.assertTrue;
 
+import java.nio.charset.StandardCharsets;
 import java.security.AlgorithmParameters;
 import java.security.KeyPair;
 import java.security.KeyPairGenerator;
@@ -59,11 +60,11 @@ public class AlgorithmParameterSignatureHelper<T extends AlgorithmParameterSpec>
         KeyPair keyPair = generator.genKeyPair();
 
         signature.initSign(keyPair.getPrivate());
-        signature.update(plainData.getBytes("UTF-8"));
+        signature.update(plainData.getBytes(StandardCharsets.UTF_8));
         byte[] signed = signature.sign();
 
         signature.initVerify(keyPair.getPublic());
-        signature.update(plainData.getBytes("UTF-8"));
+        signature.update(plainData.getBytes(StandardCharsets.UTF_8));
         assertTrue("signature should verify", signature.verify(signed));
     }
 }
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/AlgorithmParameterSymmetricHelper.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/AlgorithmParameterSymmetricHelper.java
index 8791ecb7..a76d7621 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/AlgorithmParameterSymmetricHelper.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/AlgorithmParameterSymmetricHelper.java
@@ -17,11 +17,12 @@
 
 package com.android.org.conscrypt.java.security;
 
-import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.assertArrayEquals;
 
+import java.nio.charset.StandardCharsets;
 import java.security.AlgorithmParameters;
 import java.security.Key;
-import java.util.Arrays;
+
 import javax.crypto.Cipher;
 import javax.crypto.KeyGenerator;
 
@@ -59,11 +60,11 @@ public class AlgorithmParameterSymmetricHelper extends TestHelper<AlgorithmParam
 
         Cipher cipher = Cipher.getInstance(transformation);
         cipher.init(Cipher.ENCRYPT_MODE, key, parameters);
-        byte[] bs = cipher.doFinal(plainData.getBytes("UTF-8"));
+        byte[] bs = cipher.doFinal(plainData.getBytes(StandardCharsets.UTF_8));
 
         cipher.init(Cipher.DECRYPT_MODE, key, parameters);
         byte[] decrypted = cipher.doFinal(bs);
 
-        assertTrue(Arrays.equals(plainData.getBytes("UTF-8"), decrypted));
+        assertArrayEquals(plainData.getBytes(StandardCharsets.UTF_8), decrypted);
     }
 }
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/CpuFeatures.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/CpuFeatures.java
index 553a7148..51751c66 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/CpuFeatures.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/CpuFeatures.java
@@ -17,7 +17,7 @@
 
 package com.android.org.conscrypt.java.security;
 
-import static java.nio.charset.StandardCharsets.UTF_8;
+import static java.nio.charset.StandardCharsets.US_ASCII;
 
 import java.io.BufferedReader;
 import java.io.FileReader;
@@ -27,6 +27,7 @@ import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.util.Arrays;
 import java.util.List;
+import java.util.Locale;
 import java.util.regex.Matcher;
 import java.util.regex.Pattern;
 
@@ -62,13 +63,8 @@ public class CpuFeatures {
                         nativeCrypto.getDeclaredMethod("EVP_has_aes_hardware");
                 EVP_has_aes_hardware.setAccessible(true);
                 return ((Integer) EVP_has_aes_hardware.invoke(null)) == 1;
-            } catch (NoSuchMethodException ignored) {
-                // Ignored
-            } catch (SecurityException ignored) {
-                // Ignored
-            } catch (IllegalAccessException ignored) {
-                // Ignored
-            } catch (IllegalArgumentException ignored) {
+            } catch (NoSuchMethodException | IllegalArgumentException | IllegalAccessException
+                    | SecurityException ignored) {
                 // Ignored
             } catch (InvocationTargetException e) {
                 throw new IllegalArgumentException(e);
@@ -90,13 +86,11 @@ public class CpuFeatures {
         return null;
     }
 
+    @SuppressWarnings("DefaultCharset")
     private static String getFieldFromCpuinfo(String field) {
         try {
-            @SuppressWarnings("DefaultCharset")
-            BufferedReader br = new BufferedReader(new FileReader("/proc/cpuinfo"));
-            Pattern p = Pattern.compile(field + "\\s*:\\s*(.*)");
-
-            try {
+            try (BufferedReader br = new BufferedReader(new FileReader("/proc/cpuinfo"))) {
+                Pattern p = Pattern.compile(field + "\\s*:\\s*(.*)");
                 String line;
                 while ((line = br.readLine()) != null) {
                     Matcher m = p.matcher(line);
@@ -104,8 +98,6 @@ public class CpuFeatures {
                         return m.group(1);
                     }
                 }
-            } finally {
-                br.close();
             }
         } catch (IOException ignored) {
             // Ignored.
@@ -128,13 +120,13 @@ public class CpuFeatures {
             Process proc = Runtime.getRuntime().exec("sysctl -a");
             if (proc.waitFor() == 0) {
                 BufferedReader reader =
-                        new BufferedReader(new InputStreamReader(proc.getInputStream(), UTF_8));
+                        new BufferedReader(new InputStreamReader(proc.getInputStream(), US_ASCII));
 
                 final String linePrefix = "machdep.cpu.features:";
 
                 String line;
                 while ((line = reader.readLine()) != null) {
-                    line = line.toLowerCase();
+                    line = line.toLowerCase(Locale.ROOT);
                     if (line.startsWith(linePrefix)) {
                         // Strip the line prefix from the results.
                         output.append(line.substring(linePrefix.length())).append(' ');
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/SignatureHelper.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/SignatureHelper.java
index 9717a58f..19009d56 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/SignatureHelper.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/SignatureHelper.java
@@ -19,6 +19,7 @@ package com.android.org.conscrypt.java.security;
 
 import static org.junit.Assert.assertTrue;
 
+import java.nio.charset.StandardCharsets;
 import java.security.KeyPair;
 import java.security.PrivateKey;
 import java.security.PublicKey;
@@ -44,11 +45,11 @@ public class SignatureHelper extends TestHelper<KeyPair> {
     public void test(PrivateKey encryptKey, PublicKey decryptKey) throws Exception {
         Signature signature = Signature.getInstance(algorithmName);
         signature.initSign(encryptKey);
-        signature.update(plainData.getBytes("UTF-8"));
+        signature.update(plainData.getBytes(StandardCharsets.UTF_8));
         byte[] signed = signature.sign();
 
         signature.initVerify(decryptKey);
-        signature.update(plainData.getBytes("UTF-8"));
+        signature.update(plainData.getBytes(StandardCharsets.UTF_8));
         assertTrue("signature could not be verified", signature.verify(signed));
     }
 }
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java
index 8d49bf64..02faf327 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/StandardNames.java
@@ -128,6 +128,8 @@ public final class StandardNames {
         }
         paddings.addAll(Arrays.asList(newPaddings));
     }
+
+    @SuppressWarnings("EnumOrdinal")
     private static void provideSslContextEnabledProtocols(
             String algorithm, TLSVersion minimum, TLSVersion maximum) {
         if (minimum.ordinal() > maximum.ordinal()) {
@@ -140,6 +142,7 @@ public final class StandardNames {
         }
         SSL_CONTEXT_PROTOCOLS_ENABLED.put(algorithm, versionNames);
     }
+
     static {
         // TODO: provideCipherModes and provideCipherPaddings for other Ciphers
         provideCipherModes("AES", new String[] {"CBC", "CFB", "CTR", "CTS", "ECB", "OFB"});
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/TestKeyStore.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/TestKeyStore.java
index aa150dd9..59ae82f0 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/TestKeyStore.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/TestKeyStore.java
@@ -85,7 +85,7 @@ import com.android.org.conscrypt.javax.net.ssl.TestTrustManager;
 /**
  * TestKeyStore is a convenience class for other tests that
  * want a canned KeyStore with a variety of key pairs.
- *
+ * <p>
  * Creating a key store is relatively slow, so a singleton instance is
  * accessible via TestKeyStore.get().
  * @hide This class is not part of the Android public SDK API
@@ -385,13 +385,11 @@ public final class TestKeyStore {
         private PrivateKeyEntry privateEntry;
         private PrivateKeyEntry signer;
         private Certificate rootCa;
-        private final List<KeyPurposeId> extendedKeyUsages = new ArrayList<KeyPurposeId>();
-        private final List<Boolean> criticalExtendedKeyUsages = new ArrayList<Boolean>();
-        private final List<GeneralName> subjectAltNames = new ArrayList<GeneralName>();
-        private final List<GeneralSubtree> permittedNameConstraints =
-                new ArrayList<GeneralSubtree>();
-        private final List<GeneralSubtree> excludedNameConstraints =
-                new ArrayList<GeneralSubtree>();
+        private final List<KeyPurposeId> extendedKeyUsages = new ArrayList<>();
+        private final List<Boolean> criticalExtendedKeyUsages = new ArrayList<>();
+        private final List<GeneralName> subjectAltNames = new ArrayList<>();
+        private final List<GeneralSubtree> permittedNameConstraints = new ArrayList<>();
+        private final List<GeneralSubtree> excludedNameConstraints = new ArrayList<>();
         // Generated randomly if not set
         private BigInteger certificateSerialNumber = null;
 
@@ -552,12 +550,12 @@ public final class TestKeyStore {
          * private alias name. The X509Certificate will be stored on the
          * public alias name and have the given subject distinguished
          * name.
-         *
+         * <p>
          * If a CA is provided, it will be used to sign the generated
          * certificate and OCSP responses. Otherwise, the certificate
          * will be self signed. The certificate will be valid for one
          * day before and one day after the time of creation.
-         *
+         * <p>
          * Based on:
          * org.bouncycastle.jce.provider.test.SigTest
          * org.bouncycastle.jce.provider.test.CertTest
@@ -591,7 +589,6 @@ public final class TestKeyStore {
             if (publicAlias == null && privateAlias == null) {
                 // don't want anything apparently
                 privateKey = null;
-                publicKey = null;
                 x509c = null;
             } else {
                 if (privateEntry == null) {
@@ -620,11 +617,8 @@ public final class TestKeyStore {
                     KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm);
                     if (spec != null) {
                         kpg.initialize(spec);
-                    } else if (keySize != -1) {
-                        kpg.initialize(keySize);
                     } else {
-                        throw new AssertionError(
-                                "Must either have set algorithm parameters or key size!");
+                        kpg.initialize(keySize);
                     }
 
                     KeyPair kp = kpg.generateKeyPair();
@@ -677,14 +671,14 @@ public final class TestKeyStore {
         try {
             X500Principal principal = new X500Principal(subject);
             return createCertificate(publicKey, privateKey, principal, principal, 0, true,
-                    new ArrayList<KeyPurposeId>(), new ArrayList<Boolean>(),
-                    new ArrayList<GeneralName>(), new ArrayList<GeneralSubtree>(),
-                    new ArrayList<GeneralSubtree>(), null /* serialNumber, generated randomly */);
+                    new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), new ArrayList<>(),
+                    new ArrayList<>(), null /* serialNumber, generated randomly */);
         } catch (Exception e) {
             throw new RuntimeException(e);
         }
     }
 
+    @SuppressWarnings("JavaUtilDate")
     private static X509Certificate createCertificate(PublicKey publicKey, PrivateKey privateKey,
             X500Principal subject, X500Principal issuer, int keyUsage, boolean ca,
             List<KeyPurposeId> extendedKeyUsages, List<Boolean> criticalExtendedKeyUsages,
@@ -746,11 +740,8 @@ public final class TestKeyStore {
         }
         if (!permittedNameConstraints.isEmpty() || !excludedNameConstraints.isEmpty()) {
             x509cg.addExtension(Extension.nameConstraints, true,
-                    new NameConstraints(
-                            permittedNameConstraints.toArray(
-                                    new GeneralSubtree[permittedNameConstraints.size()]),
-                            excludedNameConstraints.toArray(
-                                    new GeneralSubtree[excludedNameConstraints.size()])));
+                    new NameConstraints(permittedNameConstraints.toArray(new GeneralSubtree[0]),
+                            excludedNameConstraints.toArray(new GeneralSubtree[0])));
         }
 
         X509CertificateHolder x509holder =
@@ -799,7 +790,7 @@ public final class TestKeyStore {
         if (index == -1) {
             return algorithm;
         }
-        return algorithm.substring(index + 1, algorithm.length());
+        return algorithm.substring(index + 1);
     }
 
     /**
@@ -923,6 +914,7 @@ public final class TestKeyStore {
         return rootCertificate(keyStore, algorithm);
     }
 
+    @SuppressWarnings("JavaUtilDate")
     private static OCSPResp generateOCSPResponse(PrivateKeyEntry server, PrivateKeyEntry issuer,
             CertificateStatus status) throws CertificateException {
         try {
@@ -952,7 +944,8 @@ public final class TestKeyStore {
         }
     }
 
-    public static byte[] getOCSPResponseForGood(PrivateKeyEntry server, PrivateKeyEntry issuer)
+    @SuppressWarnings({"JavaUtilDate", "unused"}) // TODO(prb): Use this.
+    private static byte[] getOCSPResponseForGood(PrivateKeyEntry server, PrivateKeyEntry issuer)
             throws CertificateException {
         try {
             return generateOCSPResponse(server, issuer, CertificateStatus.GOOD).getEncoded();
@@ -961,7 +954,8 @@ public final class TestKeyStore {
         }
     }
 
-    public static byte[] getOCSPResponseForRevoked(PrivateKeyEntry server, PrivateKeyEntry issuer)
+    @SuppressWarnings({"JavaUtilDate", "unused"}) // TODO(prb): Use this.
+    private static byte[] getOCSPResponseForRevoked(PrivateKeyEntry server, PrivateKeyEntry issuer)
             throws CertificateException {
         try {
             return generateOCSPResponse(
@@ -977,6 +971,7 @@ public final class TestKeyStore {
      * the given algorithm. Throws IllegalStateException if there are
      * are more or less than one.
      */
+    @SuppressWarnings("JavaUtilDate")
     public static X509Certificate rootCertificate(KeyStore keyStore, String algorithm) {
         try {
             X509Certificate found = null;
@@ -1025,11 +1020,7 @@ public final class TestKeyStore {
     public static KeyStore.Entry entryByAlias(KeyStore keyStore, String alias) {
         try {
             return keyStore.getEntry(alias, null);
-        } catch (NoSuchAlgorithmException e) {
-            throw new RuntimeException(e);
-        } catch (UnrecoverableEntryException e) {
-            throw new RuntimeException(e);
-        } catch (KeyStoreException e) {
+        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException e) {
             throw new RuntimeException(e);
         }
     }
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/cert/FakeX509Certificate.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/cert/FakeX509Certificate.java
index f4b55f3a..fb496cb9 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/cert/FakeX509Certificate.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/java/security/cert/FakeX509Certificate.java
@@ -26,8 +26,6 @@ import java.security.PublicKey;
 import java.security.SignatureException;
 import java.security.cert.CertificateEncodingException;
 import java.security.cert.CertificateException;
-import java.security.cert.CertificateExpiredException;
-import java.security.cert.CertificateNotYetValidException;
 import java.security.cert.X509Certificate;
 import java.util.Date;
 import java.util.Set;
@@ -35,14 +33,13 @@ import java.util.Set;
 /**
  * @hide This class is not part of the Android public SDK API
  */
+@SuppressWarnings("serial")
 public class FakeX509Certificate extends X509Certificate {
     @Override
-    public void checkValidity()
-            throws CertificateExpiredException, CertificateNotYetValidException {}
+    public void checkValidity() {}
 
     @Override
-    public void checkValidity(Date date)
-            throws CertificateExpiredException, CertificateNotYetValidException {}
+    public void checkValidity(Date date) {}
 
     @Override
     public int getBasicConstraints() {
@@ -65,11 +62,13 @@ public class FakeX509Certificate extends X509Certificate {
     }
 
     @Override
+    @SuppressWarnings("JavaUtilDate")
     public Date getNotAfter() {
         return new Date(System.currentTimeMillis());
     }
 
     @Override
+    @SuppressWarnings("JavaUtilDate")
     public Date getNotBefore() {
         return new Date(System.currentTimeMillis() - 1000);
     }
@@ -104,7 +103,8 @@ public class FakeX509Certificate extends X509Certificate {
         return new MockPrincipal();
     }
 
-    class MockPrincipal implements Principal {
+    static class MockPrincipal implements Principal {
+        @Override
         public String getName() {
             return null;
         }
@@ -115,7 +115,7 @@ public class FakeX509Certificate extends X509Certificate {
     }
 
     @Override
-    public byte[] getTBSCertificate() throws CertificateEncodingException {
+    public byte[] getTBSCertificate() {
         return null;
     }
 
@@ -136,7 +136,7 @@ public class FakeX509Certificate extends X509Certificate {
 
     @Override
     public String toString() {
-        return null;
+        return "null";
     }
 
     @Override
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/tlswire/handshake/AlpnHelloExtension.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/tlswire/handshake/AlpnHelloExtension.java
index f0709ec2..8a0b79a3 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/tlswire/handshake/AlpnHelloExtension.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/tlswire/handshake/AlpnHelloExtension.java
@@ -16,12 +16,14 @@
  */
 package com.android.org.conscrypt.tlswire.handshake;
 
+import com.android.org.conscrypt.tlswire.util.IoUtils;
+
 import java.io.ByteArrayInputStream;
 import java.io.DataInputStream;
 import java.io.IOException;
+import java.nio.charset.StandardCharsets;
 import java.util.ArrayList;
 import java.util.List;
-import com.android.org.conscrypt.tlswire.util.IoUtils;
 
 /**
  * {@code application_layer_protocol_negotiation} {@link HelloExtension} from RFC 7301 section 3.1.
@@ -35,19 +37,16 @@ public class AlpnHelloExtension extends HelloExtension {
     protected void parseData() throws IOException {
         byte[] alpnListBytes = IoUtils.readTlsVariableLengthByteVector(
                 new DataInputStream(new ByteArrayInputStream(data)), 0xffff);
-        protocols = new ArrayList<String>();
+        protocols = new ArrayList<>();
         DataInputStream alpnList = new DataInputStream(new ByteArrayInputStream(alpnListBytes));
         while (alpnList.available() > 0) {
             byte[] alpnValue = IoUtils.readTlsVariableLengthByteVector(alpnList, 0xff);
-            protocols.add(new String(alpnValue, "US-ASCII"));
+            protocols.add(new String(alpnValue, StandardCharsets.US_ASCII));
         }
     }
 
     @Override
     public String toString() {
-        StringBuilder sb = new StringBuilder("HelloExtension{type: elliptic_curves, protocols: ");
-        sb.append(protocols);
-        sb.append('}');
-        return sb.toString();
+        return "HelloExtension{type: elliptic_curves, protocols: " + protocols + '}';
     }
 }
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/tlswire/handshake/HelloExtension.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/tlswire/handshake/HelloExtension.java
index 298bd52f..c7b59f17 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/tlswire/handshake/HelloExtension.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/tlswire/handshake/HelloExtension.java
@@ -34,7 +34,7 @@ public class HelloExtension {
     public static final int TYPE_PADDING = 21;
     public static final int TYPE_SESSION_TICKET = 35;
     public static final int TYPE_RENEGOTIATION_INFO = 65281;
-    private static final Map<Integer, String> TYPE_TO_NAME = new HashMap<Integer, String>();
+    private static final Map<Integer, String> TYPE_TO_NAME = new HashMap<>();
     static {
         TYPE_TO_NAME.put(TYPE_SERVER_NAME, "server_name");
         TYPE_TO_NAME.put(1, "max_fragment_length");
@@ -93,10 +93,9 @@ public class HelloExtension {
         result.parseData();
         return result;
     }
-    /**
-     * @throws IOException
-     */
+
     protected void parseData() throws IOException {}
+
     @Override
     public String toString() {
         return "HelloExtension{type: " + name + ", data: " + new BigInteger(1, data).toString(16)
diff --git a/repackaged/testing/src/main/java/com/android/org/conscrypt/tlswire/handshake/ServerNameHelloExtension.java b/repackaged/testing/src/main/java/com/android/org/conscrypt/tlswire/handshake/ServerNameHelloExtension.java
index 27262dbc..30add90d 100644
--- a/repackaged/testing/src/main/java/com/android/org/conscrypt/tlswire/handshake/ServerNameHelloExtension.java
+++ b/repackaged/testing/src/main/java/com/android/org/conscrypt/tlswire/handshake/ServerNameHelloExtension.java
@@ -16,12 +16,14 @@
  */
 package com.android.org.conscrypt.tlswire.handshake;
 
+import com.android.org.conscrypt.tlswire.util.IoUtils;
+
 import java.io.ByteArrayInputStream;
 import java.io.DataInputStream;
 import java.io.IOException;
+import java.nio.charset.StandardCharsets;
 import java.util.ArrayList;
 import java.util.List;
-import com.android.org.conscrypt.tlswire.util.IoUtils;
 
 /**
  * {@code server_name} (SNI) {@link HelloExtension} from TLS 1.2 RFC 5246.
@@ -36,14 +38,14 @@ public class ServerNameHelloExtension extends HelloExtension {
                 new DataInputStream(new ByteArrayInputStream(data)), 0xffff);
         ByteArrayInputStream serverNameListIn = new ByteArrayInputStream(serverNameListBytes);
         DataInputStream in = new DataInputStream(serverNameListIn);
-        hostnames = new ArrayList<String>();
+        hostnames = new ArrayList<>();
         while (serverNameListIn.available() > 0) {
             int type = in.readUnsignedByte();
             if (type != TYPE_HOST_NAME) {
                 throw new IOException("Unsupported ServerName type: " + type);
             }
             byte[] hostnameBytes = IoUtils.readTlsVariableLengthByteVector(in, 0xffff);
-            String hostname = new String(hostnameBytes, "US-ASCII");
+            String hostname = new String(hostnameBytes, StandardCharsets.US_ASCII);
             hostnames.add(hostname);
         }
     }
diff --git a/repackaged/testing/src/main/java/tests/util/ServiceTester.java b/repackaged/testing/src/main/java/tests/util/ServiceTester.java
index 5d3c37e0..383acab4 100644
--- a/repackaged/testing/src/main/java/tests/util/ServiceTester.java
+++ b/repackaged/testing/src/main/java/tests/util/ServiceTester.java
@@ -162,7 +162,7 @@ public interface Test {
       if (algorithms.isEmpty()) {
         for (Provider.Service s : p.getServices()) {
             if (s.getType().equals(service) && !skipAlgorithms.contains(s.getAlgorithm())
-                    && !shouldSkipCombination(p.getName(), s.getAlgorithm())) {
+                    && shouldUseCombination(p.getName(), s.getAlgorithm())) {
                 doTest(test, p, s.getAlgorithm(), errors);
             }
         }
@@ -170,7 +170,7 @@ public interface Test {
         algorithms.removeAll(skipAlgorithms);
         for (String algorithm : algorithms) {
             if (p.getService(service, algorithm) != null
-                    && !shouldSkipCombination(p.getName(), algorithm)) {
+                    && shouldUseCombination(p.getName(), algorithm)) {
                 doTest(test, p, algorithm, errors);
             }
         }
@@ -178,7 +178,7 @@ public interface Test {
     }
     errors.flush();
     if (errBuffer.size() > 0) {
-      fail("Tests failed:\n\n" + errBuffer.toString());
+        fail("Tests failed:\n\n" + errBuffer);
     }
   }
 
@@ -186,8 +186,8 @@ public interface Test {
     return provider + SEPARATOR + algorithm;
   }
 
-  private boolean shouldSkipCombination(String provider, String algorithm) {
-    return skipCombinations.contains(makeCombination(provider, algorithm));
+  private boolean shouldUseCombination(String provider, String algorithm) {
+      return !skipCombinations.contains(makeCombination(provider, algorithm));
   }
 
   private void doTest(Test test, Provider p, String algorithm, PrintStream errors) {
diff --git a/scripts/publishLocalUber.sh b/scripts/publishLocalUber.sh
new file mode 100755
index 00000000..3c5b92d1
--- /dev/null
+++ b/scripts/publishLocalUber.sh
@@ -0,0 +1,66 @@
+#! /bin/bash
+#
+#  Copyright (C) 2024 The Android Open Source Project
+#
+#  Licensed under the Apache License, Version 2.0 (the "License");
+#  you may not use this file except in compliance with the License.
+#  You may obtain a copy of the License at
+#
+#       http://www.apache.org/licenses/LICENSE-2.0
+#
+#  Unless required by applicable law or agreed to in writing, software
+#  distributed under the License is distributed on an "AS IS" BASIS,
+#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+#  See the License for the specific language governing permissions and
+#  limitations under the License.
+
+# Builds and locally publishes an uber jar for local architectures.
+#
+# Normally an uber jar contains JNI binaries for all supported
+# platforms, but that requires those binaries to be built somewhere.
+# This script infers the binary types that can be built locally and
+# adds only those to the jar.  This allows end to end testing of the
+# build process as well as testing of the uberjar against multiple
+# Java versions (see testLocalUber.sh)
+
+
+CONSCRYPT_HOME="${CONSCRYPT_HOME:-$HOME/src/conscrypt}"
+BUILD="$CONSCRYPT_HOME/build.gradle"
+M2_REPO="${M2_REPO:-$HOME/.m2/repository}"
+PUBLISH_DIR="${M2_REPO}/org/conscrypt"
+
+die() {
+	echo "*** " $@
+	exit 1
+}
+
+case $(uname -s) in
+	Darwin)
+		CLASSIFIERS="osx-x86_64,osx-aarch_64"
+		;;
+	Linux)
+		CLASSIFIERS="linux-x86_64"
+		;;
+	*)
+		die "TODO: Finish this switch statement"
+		;;
+esac
+
+test -f "$BUILD" || die "Conscrypt build file not found.  Check CONSCRYPT_HOME."
+
+VERSION=$(sed -nE 's/^ *version *= *"(.*)"/\1/p' $BUILD)
+test "$VERSION" || die "Unable to figure out Conscrypt version."
+echo "Conscrypt version ${VERSION}."
+
+UBERJAR="$PUBLISH_DIR/conscrypt-openjdk-uber/$VERSION/conscrypt-openjdk-uber-${VERSION}.jar"
+
+cd "$CONSCRYPT_HOME"
+./gradlew :conscrypt-openjdk:publishToMavenLocal \
+		  --console=plain
+./gradlew :conscrypt-openjdk-uber:publishToMavenLocal \
+		  -Dorg.conscrypt.openjdk.uberJarClassifiers="$CLASSIFIERS" \
+		  -Dorg.conscrypt.openjdk.buildUberJar=true \
+		  --console=plain
+
+test -f "$UBERJAR" || die "Uber jar not published."
+ls -l "$UBERJAR"
diff --git a/scripts/testLocalUber.sh b/scripts/testLocalUber.sh
new file mode 100755
index 00000000..2699384b
--- /dev/null
+++ b/scripts/testLocalUber.sh
@@ -0,0 +1,108 @@
+#! /bin/bash
+#
+#  Copyright (C) 2024 The Android Open Source Project
+#
+#  Licensed under the Apache License, Version 2.0 (the "License");
+#  you may not use this file except in compliance with the License.
+#  You may obtain a copy of the License at
+#
+#       http://www.apache.org/licenses/LICENSE-2.0
+#
+#  Unless required by applicable law or agreed to in writing, software
+#  distributed under the License is distributed on an "AS IS" BASIS,
+#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+#  See the License for the specific language governing permissions and
+#
+
+# Allows testing of a locally publish uber jar with against an
+# arbitrary Java version using the JUnit console test runner (which
+# will be downloaded if not present).
+#
+# First build and locally publish an uber jar, e.g. using
+# publishLocalUber.sh
+#
+# Second set up the version of Java to be used for testing, e.g. by
+# setting JAVA_HOME
+#
+# Then run this script which will download the JUnit runner if needed,
+# build the Conscrypt testJar and then run the tests.
+#
+# Essentially these are the same steps as the final test matrix in the
+# Github CI script.
+
+CONSCRYPT_HOME="${CONSCRYPT_HOME:-$HOME/src/conscrypt}"
+BUILD="$CONSCRYPT_HOME/build.gradle"
+M2_REPO="${M2_REPO:-$HOME/.m2/repository}"
+PUBLISH_DIR="${M2_REPO}/org/conscrypt"
+TMPDIR="${TMPDIR:-$HOME/tmp/conscrypt}"
+JUNITJAR="$TMPDIR/junit-platform-console-standalone.jar"
+
+die() {
+	echo "*** " $@
+	exit 1
+}
+
+usage() {
+	echo "testLocalUber.sh [args]"
+	echo ""
+	echo "-h, --help     Help"
+	echo "-v, --verbose  Verbose test output"
+	echo "-d, --debug    Wait for debugger on test startup"
+	exit 0
+}
+
+while [ "$1" ]; do
+	case "$1" in
+		-v|--verbose)
+			VERBOSE="--details=verbose"
+			;;
+		-d|--debug)
+			JAVADEBUG="-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=5005"
+			;;
+		-h|--help)
+			usage
+			;;
+		*)
+			die "Unknown argument $1 - try --help"
+			;;
+	esac
+	shift
+done
+
+mkdir -p "$TMPDIR" || die "Unable to create ${TMPDIR}."
+
+test -f "$BUILD" || die "Conscrypt build.gradle file not found.  Check CONSCRYPT_HOME."
+VERSION=$(sed -nE 's/^ *version *= *"(.*)"/\1/p' $BUILD)
+test "$VERSION" || die "Unable to figure out Conscrypt version."
+echo "Conscrypt version ${VERSION}."
+
+echo "Java version:"
+java -version || die "Cannot run Java."
+
+UBERJAR="${PUBLISH_DIR}/conscrypt-openjdk-uber/$VERSION/conscrypt-openjdk-uber-${VERSION}.jar"
+TESTJAR="${CONSCRYPT_HOME}/openjdk/build/libs/conscrypt-openjdk-${VERSION}-tests.jar"
+test -f "$UBERJAR" || die "Uber jar not found: ${UBERJAR}."
+
+
+if [ -f "$JUNITJAR" ]; then
+	echo "JUnit console runner: ${JUNITJAR}."
+else
+	echo "Downloading JUnit console runner."
+	mvn org.apache.maven.plugins:maven-dependency-plugin:3.8.0:copy \
+		-Dartifact=org.junit.platform:junit-platform-console-standalone:1.11.2 \
+		-DoutputDirectory="$TMPDIR" \
+		-Dmdep.stripVersion=true \
+		|| die "Maven download of junit failed."
+fi
+test -f "$JUNITJAR" || die "JUnit not found."
+
+echo "Building test jar."
+cd $CONSCRYPT_HOME
+./gradlew :conscrypt-openjdk:testJar --console=plain
+test -f "$TESTJAR" || die "Test jar not built."
+
+echo "Running tests."
+java $JAVADEBUG -jar "$JUNITJAR" execute -cp "${UBERJAR}:${TESTJAR}" \
+	 -n='org.conscrypt.ConscryptOpenJdkSuite' \
+	 --scan-classpath --reports-dir=. \
+	 --fail-if-no-tests $VERBOSE
diff --git a/srcgen/flagged-api.json b/srcgen/flagged-api.json
new file mode 100644
index 00000000..1635ec65
--- /dev/null
+++ b/srcgen/flagged-api.json
@@ -0,0 +1,6 @@
+[
+  {
+    "@location": "method:com.android.org.conscrypt.TrustManagerImpl#checkServerTrusted(X509Certificate[],byte[],byte[],String,String)",
+    "value": "com.android.org.conscrypt.flags.Flags.FLAG_CERTIFICATE_TRANSPARENCY_CHECKSERVERTRUSTED_API"
+  }
+]
diff --git a/srcgen/stable-core-platform-api.txt b/srcgen/stable-core-platform-api.txt
index c882063f..d0db6ae1 100644
--- a/srcgen/stable-core-platform-api.txt
+++ b/srcgen/stable-core-platform-api.txt
@@ -40,6 +40,7 @@ method:com.android.org.conscrypt.TrustManagerImpl#checkClientTrusted(X509Certifi
 method:com.android.org.conscrypt.TrustManagerImpl#checkClientTrusted(X509Certificate[],String,Socket)
 method:com.android.org.conscrypt.TrustManagerImpl#checkClientTrusted(X509Certificate[],String,SSLEngine)
 method:com.android.org.conscrypt.TrustManagerImpl#checkServerTrusted(X509Certificate[],String,String)
+method:com.android.org.conscrypt.TrustManagerImpl#checkServerTrusted(X509Certificate[],byte[],byte[],String,String)
 method:com.android.org.conscrypt.TrustManagerImpl#getTrustedChainForServer(X509Certificate[],String,Socket)
 method:com.android.org.conscrypt.TrustManagerImpl#getTrustedChainForServer(X509Certificate[],String,SSLEngine)
 method:com.android.org.conscrypt.TrustManagerImpl#handleTrustStorageUpdate()
diff --git a/srcgen/unsupported-app-usage.json b/srcgen/unsupported-app-usage.json
index 12935e97..666b5818 100644
--- a/srcgen/unsupported-app-usage.json
+++ b/srcgen/unsupported-app-usage.json
@@ -26,11 +26,6 @@
     "maxTargetSdk": 30,
     "trackingBug": 170729553
   },
-  {
-    "@location": "method:com.android.org.conscrypt.AbstractConscryptSocket#getNpnSelectedProtocol()",
-    "maxTargetSdk": 30,
-    "trackingBug": 170729553
-  },
   {
     "@location": "method:com.android.org.conscrypt.AbstractConscryptSocket#getSoWriteTimeout()",
     "maxTargetSdk": 30,
@@ -71,11 +66,6 @@
     "maxTargetSdk": "dalvik.annotation.compat.VersionCodes.Q",
     "publicAlternatives": "Use {@code javax.net.ssl.SSLParameters#setServerNames}."
   },
-  {
-    "@location": "method:com.android.org.conscrypt.AbstractConscryptSocket#setNpnProtocols(byte[])",
-    "maxTargetSdk": 30,
-    "trackingBug": 170729553
-  },
   {
     "@location": "method:com.android.org.conscrypt.AbstractConscryptSocket#setSoWriteTimeout(int)",
     "maxTargetSdk": 30,
diff --git a/testing/build.gradle b/testing/build.gradle
index fafd5faa..984c95bc 100644
--- a/testing/build.gradle
+++ b/testing/build.gradle
@@ -1,5 +1,5 @@
 plugins {
-    id 'com.github.johnrengelman.shadow' version '7.1.2'
+    alias libs.plugins.shadow
 }
 
 description = 'Conscrypt: Testing'
@@ -20,9 +20,9 @@ dependencies {
                 project(':conscrypt-libcore-stub'),
                 project(':conscrypt-android-stub')
 
-    implementation libraries.bouncycastle_apis,
-            libraries.bouncycastle_provider,
-            libraries.junit
+    implementation libs.bouncycastle.apis,
+            libs.bouncycastle.provider,
+            libs.junit
 }
 
 // No public methods here.
diff --git a/testing/src/main/java/org/conscrypt/TestUtils.java b/testing/src/main/java/org/conscrypt/TestUtils.java
index 7b3231d1..c9d626aa 100644
--- a/testing/src/main/java/org/conscrypt/TestUtils.java
+++ b/testing/src/main/java/org/conscrypt/TestUtils.java
@@ -233,24 +233,33 @@ public final class TestUtils {
         }
     }
 
-    public static Provider getConscryptProvider() {
+    public static Provider getConscryptProvider(boolean isTlsV1Deprecated,
+            boolean isTlsV1Enabled) {
         try {
             String defaultName = (String) conscryptClass("Platform")
                 .getDeclaredMethod("getDefaultProviderName")
                 .invoke(null);
-            Constructor<?> c = conscryptClass("OpenSSLProvider")
-                .getDeclaredConstructor(String.class, Boolean.TYPE, String.class);
+            Constructor<?> c =
+                    conscryptClass("OpenSSLProvider")
+                            .getDeclaredConstructor(String.class, Boolean.TYPE,
+                                String.class, Boolean.TYPE, Boolean.TYPE);
 
             if (!isClassAvailable("javax.net.ssl.X509ExtendedTrustManager")) {
-                return (Provider) c.newInstance(defaultName, false, "TLSv1.3");
+                return (Provider) c.newInstance(defaultName, false, "TLSv1.3",
+                    isTlsV1Deprecated, isTlsV1Enabled);
             } else {
-                return (Provider) c.newInstance(defaultName, true, "TLSv1.3");
+                return (Provider) c.newInstance(defaultName, true, "TLSv1.3",
+                    isTlsV1Deprecated, isTlsV1Enabled);
             }
         } catch (Exception e) {
             throw new RuntimeException(e);
         }
     }
 
+    public static Provider getConscryptProvider() {
+        return getConscryptProvider(true, false);
+    }
+
     public static synchronized void installConscryptAsDefaultProvider() {
         Provider conscryptProvider = getConscryptProvider();
         Provider[] providers = Security.getProviders();
@@ -315,7 +324,7 @@ public final class TestUtils {
                 if (index < 0) {
                     throw new IllegalStateException("No = found: line " + lineNumber);
                 }
-                String label = line.substring(0, index).trim().toLowerCase();
+                String label = line.substring(0, index).trim().toLowerCase(Locale.ROOT);
                 String value = line.substring(index + 1).trim();
                 if ("name".equals(label)) {
                     current = new TestVector();
@@ -661,7 +670,7 @@ public final class TestUtils {
     /**
      * Decodes the provided hexadecimal string into a byte array.  Odd-length inputs
      * are not allowed.
-     *
+     * <p>
      * Throws an {@code IllegalArgumentException} if the input is malformed.
      */
     public static byte[] decodeHex(String encoded) throws IllegalArgumentException {
@@ -672,7 +681,7 @@ public final class TestUtils {
      * Decodes the provided hexadecimal string into a byte array. If {@code allowSingleChar}
      * is {@code true} odd-length inputs are allowed and the first character is interpreted
      * as the lower bits of the first result byte.
-     *
+     * <p>
      * Throws an {@code IllegalArgumentException} if the input is malformed.
      */
     public static byte[] decodeHex(String encoded, boolean allowSingleChar) throws IllegalArgumentException {
@@ -682,7 +691,7 @@ public final class TestUtils {
     /**
      * Decodes the provided hexadecimal string into a byte array.  Odd-length inputs
      * are not allowed.
-     *
+     * <p>
      * Throws an {@code IllegalArgumentException} if the input is malformed.
      */
     public static byte[] decodeHex(char[] encoded) throws IllegalArgumentException {
@@ -693,7 +702,7 @@ public final class TestUtils {
      * Decodes the provided hexadecimal string into a byte array. If {@code allowSingleChar}
      * is {@code true} odd-length inputs are allowed and the first character is interpreted
      * as the lower bits of the first result byte.
-     *
+     * <p>
      * Throws an {@code IllegalArgumentException} if the input is malformed.
      */
     public static byte[] decodeHex(char[] encoded, boolean allowSingleChar) throws IllegalArgumentException {
@@ -861,40 +870,31 @@ public final class TestUtils {
         Assume.assumeTrue(findClass("java.security.spec.XECPrivateKeySpec") != null);
     }
 
-    // Find base method via reflection due to visibility issues when building with Gradle.
     public static boolean isTlsV1Deprecated() {
-        try {
-            return (Boolean) conscryptClass("Platform")
-                    .getDeclaredMethod("isTlsV1Deprecated")
-                    .invoke(null);
-        } catch (Exception e) {
-            throw new RuntimeException(e);
-        }
+        return callPlatformMethod("isTlsV1Deprecated", false);
     }
 
-    // Find base method via reflection due to possible version skew on Android
-    // and visibility issues when building with Gradle.
     public static boolean isTlsV1Filtered() {
-        try {
-            return (Boolean) conscryptClass("Platform")
-                    .getDeclaredMethod("isTlsV1Filtered")
-                    .invoke(null);
-        } catch (NoSuchMethodException e) {
-            return true;
-        } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException e) {
-            throw new IllegalStateException("Reflection failure", e);
-        }
+        return callPlatformMethod("isTlsV1Filtered", true);
     }
 
-    // Find base method via reflection due to possible version skew on Android
-    // and visibility issues when building with Gradle.
     public static boolean isTlsV1Supported() {
+        return callPlatformMethod("isTlsV1Supported", true);
+    }
+
+    public static boolean isJavaxCertificateSupported() {
+        return callPlatformMethod("isJavaxCertificateSupported", true);
+    }
+
+    // Calls a boolean platform method by reflection.  If the method is not present, e.g.
+    // due to version skew etc then return the default value.
+    public static boolean callPlatformMethod(String methodName, boolean defaultValue) {
         try {
             return (Boolean) conscryptClass("Platform")
-                    .getDeclaredMethod("isTlsV1Supported")
+                    .getDeclaredMethod(methodName)
                     .invoke(null);
         } catch (NoSuchMethodException e) {
-            return false;
+            return defaultValue;
         } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException e) {
             throw new IllegalStateException("Reflection failure", e);
         }
diff --git a/testing/src/main/java/org/conscrypt/VeryBasicHttpServer.java b/testing/src/main/java/org/conscrypt/VeryBasicHttpServer.java
index 427292c4..71fdbfac 100644
--- a/testing/src/main/java/org/conscrypt/VeryBasicHttpServer.java
+++ b/testing/src/main/java/org/conscrypt/VeryBasicHttpServer.java
@@ -26,6 +26,7 @@ import java.net.Socket;
 import java.net.URL;
 import java.nio.charset.StandardCharsets;
 import java.util.HashMap;
+import java.util.List;
 import java.util.Map;
 import java.util.Objects;
 import java.util.concurrent.Callable;
@@ -108,6 +109,7 @@ public class VeryBasicHttpServer {
         }
     }
 
+    @SuppressWarnings("StringSplitter") // It's close enough for government work.
     private Request readRequest(Socket socket) throws Exception {
         Request request = new Request();
         request.outputStream = socket.getOutputStream();
diff --git a/testing/src/main/java/org/conscrypt/java/security/AlgorithmParameterAsymmetricHelper.java b/testing/src/main/java/org/conscrypt/java/security/AlgorithmParameterAsymmetricHelper.java
index 7f8ded7f..b7e37fad 100644
--- a/testing/src/main/java/org/conscrypt/java/security/AlgorithmParameterAsymmetricHelper.java
+++ b/testing/src/main/java/org/conscrypt/java/security/AlgorithmParameterAsymmetricHelper.java
@@ -16,12 +16,12 @@
 
 package org.conscrypt.java.security;
 
-import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.assertArrayEquals;
 
+import java.nio.charset.StandardCharsets;
 import java.security.AlgorithmParameters;
 import java.security.KeyPair;
 import java.security.KeyPairGenerator;
-import java.util.Arrays;
 import javax.crypto.Cipher;
 
 public class AlgorithmParameterAsymmetricHelper extends TestHelper<AlgorithmParameters> {
@@ -47,10 +47,10 @@ public class AlgorithmParameterAsymmetricHelper extends TestHelper<AlgorithmPara
 
         Cipher cipher = Cipher.getInstance(algorithmName);
         cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), parameters);
-        byte[] bs = cipher.doFinal(plainData.getBytes("UTF-8"));
+        byte[] bs = cipher.doFinal(plainData.getBytes(StandardCharsets.UTF_8));
 
         cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), parameters);
         byte[] decrypted = cipher.doFinal(bs);
-        assertTrue(Arrays.equals(plainData.getBytes("UTF-8"), decrypted));
+        assertArrayEquals(plainData.getBytes(StandardCharsets.UTF_8), decrypted);
     }
 }
diff --git a/testing/src/main/java/org/conscrypt/java/security/AlgorithmParameterSignatureHelper.java b/testing/src/main/java/org/conscrypt/java/security/AlgorithmParameterSignatureHelper.java
index 1e19f8ff..ca97eed1 100644
--- a/testing/src/main/java/org/conscrypt/java/security/AlgorithmParameterSignatureHelper.java
+++ b/testing/src/main/java/org/conscrypt/java/security/AlgorithmParameterSignatureHelper.java
@@ -18,6 +18,7 @@ package org.conscrypt.java.security;
 
 import static org.junit.Assert.assertTrue;
 
+import java.nio.charset.StandardCharsets;
 import java.security.AlgorithmParameters;
 import java.security.KeyPair;
 import java.security.KeyPairGenerator;
@@ -55,11 +56,11 @@ public class AlgorithmParameterSignatureHelper<T extends AlgorithmParameterSpec>
         KeyPair keyPair = generator.genKeyPair();
 
         signature.initSign(keyPair.getPrivate());
-        signature.update(plainData.getBytes("UTF-8"));
+        signature.update(plainData.getBytes(StandardCharsets.UTF_8));
         byte[] signed = signature.sign();
 
         signature.initVerify(keyPair.getPublic());
-        signature.update(plainData.getBytes("UTF-8"));
+        signature.update(plainData.getBytes(StandardCharsets.UTF_8));
         assertTrue("signature should verify", signature.verify(signed));
     }
 }
diff --git a/testing/src/main/java/org/conscrypt/java/security/AlgorithmParameterSymmetricHelper.java b/testing/src/main/java/org/conscrypt/java/security/AlgorithmParameterSymmetricHelper.java
index 83bb3df6..4a400ed7 100644
--- a/testing/src/main/java/org/conscrypt/java/security/AlgorithmParameterSymmetricHelper.java
+++ b/testing/src/main/java/org/conscrypt/java/security/AlgorithmParameterSymmetricHelper.java
@@ -16,11 +16,11 @@
 
 package org.conscrypt.java.security;
 
-import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.assertArrayEquals;
 
+import java.nio.charset.StandardCharsets;
 import java.security.AlgorithmParameters;
 import java.security.Key;
-import java.util.Arrays;
 import javax.crypto.Cipher;
 import javax.crypto.KeyGenerator;
 
@@ -55,11 +55,11 @@ public class AlgorithmParameterSymmetricHelper extends TestHelper<AlgorithmParam
 
         Cipher cipher = Cipher.getInstance(transformation);
         cipher.init(Cipher.ENCRYPT_MODE, key, parameters);
-        byte[] bs = cipher.doFinal(plainData.getBytes("UTF-8"));
+        byte[] bs = cipher.doFinal(plainData.getBytes(StandardCharsets.UTF_8));
 
         cipher.init(Cipher.DECRYPT_MODE, key, parameters);
         byte[] decrypted = cipher.doFinal(bs);
 
-        assertTrue(Arrays.equals(plainData.getBytes("UTF-8"), decrypted));
+        assertArrayEquals(plainData.getBytes(StandardCharsets.UTF_8), decrypted);
     }
 }
diff --git a/testing/src/main/java/org/conscrypt/java/security/CpuFeatures.java b/testing/src/main/java/org/conscrypt/java/security/CpuFeatures.java
index 721f4538..4e238da9 100644
--- a/testing/src/main/java/org/conscrypt/java/security/CpuFeatures.java
+++ b/testing/src/main/java/org/conscrypt/java/security/CpuFeatures.java
@@ -16,7 +16,7 @@
 
 package org.conscrypt.java.security;
 
-import static java.nio.charset.StandardCharsets.UTF_8;
+import static java.nio.charset.StandardCharsets.US_ASCII;
 
 import java.io.BufferedReader;
 import java.io.FileReader;
@@ -26,6 +26,7 @@ import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;
 import java.util.Arrays;
 import java.util.List;
+import java.util.Locale;
 import java.util.regex.Matcher;
 import java.util.regex.Pattern;
 
@@ -58,13 +59,8 @@ public class CpuFeatures {
                         nativeCrypto.getDeclaredMethod("EVP_has_aes_hardware");
                 EVP_has_aes_hardware.setAccessible(true);
                 return ((Integer) EVP_has_aes_hardware.invoke(null)) == 1;
-            } catch (NoSuchMethodException ignored) {
-                // Ignored
-            } catch (SecurityException ignored) {
-                // Ignored
-            } catch (IllegalAccessException ignored) {
-                // Ignored
-            } catch (IllegalArgumentException ignored) {
+            } catch (NoSuchMethodException | IllegalArgumentException | IllegalAccessException |
+                     SecurityException ignored) {
                 // Ignored
             } catch (InvocationTargetException e) {
                 throw new IllegalArgumentException(e);
@@ -86,13 +82,12 @@ public class CpuFeatures {
         return null;
     }
 
+    @SuppressWarnings("DefaultCharset")
     private static String getFieldFromCpuinfo(String field) {
         try {
-            @SuppressWarnings("DefaultCharset")
-            BufferedReader br = new BufferedReader(new FileReader("/proc/cpuinfo"));
-            Pattern p = Pattern.compile(field + "\\s*:\\s*(.*)");
 
-            try {
+            try (BufferedReader br = new BufferedReader(new FileReader("/proc/cpuinfo"))) {
+                Pattern p = Pattern.compile(field + "\\s*:\\s*(.*)");
                 String line;
                 while ((line = br.readLine()) != null) {
                     Matcher m = p.matcher(line);
@@ -100,8 +95,6 @@ public class CpuFeatures {
                         return m.group(1);
                     }
                 }
-            } finally {
-                br.close();
             }
         } catch (IOException ignored) {
             // Ignored.
@@ -124,13 +117,13 @@ public class CpuFeatures {
             Process proc = Runtime.getRuntime().exec("sysctl -a");
             if (proc.waitFor() == 0) {
                 BufferedReader reader =
-                        new BufferedReader(new InputStreamReader(proc.getInputStream(), UTF_8));
+                        new BufferedReader(new InputStreamReader(proc.getInputStream(), US_ASCII));
 
                 final String linePrefix = "machdep.cpu.features:";
 
                 String line;
                 while ((line = reader.readLine()) != null) {
-                    line = line.toLowerCase();
+                    line = line.toLowerCase(Locale.ROOT);
                     if (line.startsWith(linePrefix)) {
                         // Strip the line prefix from the results.
                         output.append(line.substring(linePrefix.length())).append(' ');
diff --git a/testing/src/main/java/org/conscrypt/java/security/SignatureHelper.java b/testing/src/main/java/org/conscrypt/java/security/SignatureHelper.java
index 920a0f3a..7d1adf7d 100644
--- a/testing/src/main/java/org/conscrypt/java/security/SignatureHelper.java
+++ b/testing/src/main/java/org/conscrypt/java/security/SignatureHelper.java
@@ -18,6 +18,7 @@ package org.conscrypt.java.security;
 
 import static org.junit.Assert.assertTrue;
 
+import java.nio.charset.StandardCharsets;
 import java.security.KeyPair;
 import java.security.PrivateKey;
 import java.security.PublicKey;
@@ -40,11 +41,11 @@ public class SignatureHelper extends TestHelper<KeyPair> {
     public void test(PrivateKey encryptKey, PublicKey decryptKey) throws Exception {
         Signature signature = Signature.getInstance(algorithmName);
         signature.initSign(encryptKey);
-        signature.update(plainData.getBytes("UTF-8"));
+        signature.update(plainData.getBytes(StandardCharsets.UTF_8));
         byte[] signed = signature.sign();
 
         signature.initVerify(decryptKey);
-        signature.update(plainData.getBytes("UTF-8"));
+        signature.update(plainData.getBytes(StandardCharsets.UTF_8));
         assertTrue("signature could not be verified", signature.verify(signed));
     }
 }
diff --git a/testing/src/main/java/org/conscrypt/java/security/StandardNames.java b/testing/src/main/java/org/conscrypt/java/security/StandardNames.java
index 9d0af787..8ae50744 100644
--- a/testing/src/main/java/org/conscrypt/java/security/StandardNames.java
+++ b/testing/src/main/java/org/conscrypt/java/security/StandardNames.java
@@ -126,6 +126,8 @@ public final class StandardNames {
         }
         paddings.addAll(Arrays.asList(newPaddings));
     }
+
+    @SuppressWarnings("EnumOrdinal")
     private static void provideSslContextEnabledProtocols(
             String algorithm, TLSVersion minimum, TLSVersion maximum) {
         if (minimum.ordinal() > maximum.ordinal()) {
@@ -138,6 +140,7 @@ public final class StandardNames {
         }
         SSL_CONTEXT_PROTOCOLS_ENABLED.put(algorithm, versionNames);
     }
+
     static {
         // TODO: provideCipherModes and provideCipherPaddings for other Ciphers
         provideCipherModes("AES", new String[] {"CBC", "CFB", "CTR", "CTS", "ECB", "OFB"});
diff --git a/testing/src/main/java/org/conscrypt/java/security/TestKeyStore.java b/testing/src/main/java/org/conscrypt/java/security/TestKeyStore.java
index 6eb3aa56..975a01c6 100644
--- a/testing/src/main/java/org/conscrypt/java/security/TestKeyStore.java
+++ b/testing/src/main/java/org/conscrypt/java/security/TestKeyStore.java
@@ -84,7 +84,7 @@ import org.conscrypt.javax.net.ssl.TestTrustManager;
 /**
  * TestKeyStore is a convenience class for other tests that
  * want a canned KeyStore with a variety of key pairs.
- *
+ * <p>
  * Creating a key store is relatively slow, so a singleton instance is
  * accessible via TestKeyStore.get().
  */
@@ -382,13 +382,13 @@ public final class TestKeyStore {
         private PrivateKeyEntry privateEntry;
         private PrivateKeyEntry signer;
         private Certificate rootCa;
-        private final List<KeyPurposeId> extendedKeyUsages = new ArrayList<KeyPurposeId>();
-        private final List<Boolean> criticalExtendedKeyUsages = new ArrayList<Boolean>();
-        private final List<GeneralName> subjectAltNames = new ArrayList<GeneralName>();
+        private final List<KeyPurposeId> extendedKeyUsages = new ArrayList<>();
+        private final List<Boolean> criticalExtendedKeyUsages = new ArrayList<>();
+        private final List<GeneralName> subjectAltNames = new ArrayList<>();
         private final List<GeneralSubtree> permittedNameConstraints =
-                new ArrayList<GeneralSubtree>();
+                new ArrayList<>();
         private final List<GeneralSubtree> excludedNameConstraints =
-                new ArrayList<GeneralSubtree>();
+                new ArrayList<>();
         // Generated randomly if not set
         private BigInteger certificateSerialNumber = null;
 
@@ -549,12 +549,12 @@ public final class TestKeyStore {
          * private alias name. The X509Certificate will be stored on the
          * public alias name and have the given subject distinguished
          * name.
-         *
+         * <p>
          * If a CA is provided, it will be used to sign the generated
          * certificate and OCSP responses. Otherwise, the certificate
          * will be self signed. The certificate will be valid for one
          * day before and one day after the time of creation.
-         *
+         * <p>
          * Based on:
          * org.bouncycastle.jce.provider.test.SigTest
          * org.bouncycastle.jce.provider.test.CertTest
@@ -588,7 +588,6 @@ public final class TestKeyStore {
             if (publicAlias == null && privateAlias == null) {
                 // don't want anything apparently
                 privateKey = null;
-                publicKey = null;
                 x509c = null;
             } else {
                 if (privateEntry == null) {
@@ -617,11 +616,8 @@ public final class TestKeyStore {
                     KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm);
                     if (spec != null) {
                         kpg.initialize(spec);
-                    } else if (keySize != -1) {
-                        kpg.initialize(keySize);
                     } else {
-                        throw new AssertionError(
-                                "Must either have set algorithm parameters or key size!");
+                        kpg.initialize(keySize);
                     }
 
                     KeyPair kp = kpg.generateKeyPair();
@@ -674,14 +670,15 @@ public final class TestKeyStore {
         try {
             X500Principal principal = new X500Principal(subject);
             return createCertificate(publicKey, privateKey, principal, principal, 0, true,
-                    new ArrayList<KeyPurposeId>(), new ArrayList<Boolean>(),
-                    new ArrayList<GeneralName>(), new ArrayList<GeneralSubtree>(),
-                    new ArrayList<GeneralSubtree>(), null /* serialNumber, generated randomly */);
+                    new ArrayList<>(), new ArrayList<>(),
+                    new ArrayList<>(), new ArrayList<>(),
+                    new ArrayList<>(), null /* serialNumber, generated randomly */);
         } catch (Exception e) {
             throw new RuntimeException(e);
         }
     }
 
+    @SuppressWarnings("JavaUtilDate")
     private static X509Certificate createCertificate(PublicKey publicKey, PrivateKey privateKey,
             X500Principal subject, X500Principal issuer, int keyUsage, boolean ca,
             List<KeyPurposeId> extendedKeyUsages, List<Boolean> criticalExtendedKeyUsages,
@@ -744,10 +741,8 @@ public final class TestKeyStore {
         if (!permittedNameConstraints.isEmpty() || !excludedNameConstraints.isEmpty()) {
             x509cg.addExtension(Extension.nameConstraints, true,
                     new NameConstraints(
-                            permittedNameConstraints.toArray(
-                                    new GeneralSubtree[permittedNameConstraints.size()]),
-                            excludedNameConstraints.toArray(
-                                    new GeneralSubtree[excludedNameConstraints.size()])));
+                            permittedNameConstraints.toArray(new GeneralSubtree[0]),
+                            excludedNameConstraints.toArray(new GeneralSubtree[0])));
         }
 
         X509CertificateHolder x509holder =
@@ -796,7 +791,7 @@ public final class TestKeyStore {
         if (index == -1) {
             return algorithm;
         }
-        return algorithm.substring(index + 1, algorithm.length());
+        return algorithm.substring(index + 1);
     }
 
     /**
@@ -920,6 +915,7 @@ public final class TestKeyStore {
         return rootCertificate(keyStore, algorithm);
     }
 
+    @SuppressWarnings("JavaUtilDate")
     private static OCSPResp generateOCSPResponse(PrivateKeyEntry server, PrivateKeyEntry issuer,
             CertificateStatus status) throws CertificateException {
         try {
@@ -949,7 +945,8 @@ public final class TestKeyStore {
         }
     }
 
-    public static byte[] getOCSPResponseForGood(PrivateKeyEntry server, PrivateKeyEntry issuer)
+    @SuppressWarnings({"JavaUtilDate", "unused"}) // TODO(prb): Use this.
+    private static byte[] getOCSPResponseForGood(PrivateKeyEntry server, PrivateKeyEntry issuer)
             throws CertificateException {
         try {
             return generateOCSPResponse(server, issuer, CertificateStatus.GOOD).getEncoded();
@@ -958,7 +955,8 @@ public final class TestKeyStore {
         }
     }
 
-    public static byte[] getOCSPResponseForRevoked(PrivateKeyEntry server, PrivateKeyEntry issuer)
+    @SuppressWarnings({"JavaUtilDate", "unused"}) // TODO(prb): Use this.
+    private static byte[] getOCSPResponseForRevoked(PrivateKeyEntry server, PrivateKeyEntry issuer)
             throws CertificateException {
         try {
             return generateOCSPResponse(
@@ -974,6 +972,7 @@ public final class TestKeyStore {
      * the given algorithm. Throws IllegalStateException if there are
      * are more or less than one.
      */
+    @SuppressWarnings("JavaUtilDate")
     public static X509Certificate rootCertificate(KeyStore keyStore, String algorithm) {
         try {
             X509Certificate found = null;
@@ -1022,11 +1021,7 @@ public final class TestKeyStore {
     public static KeyStore.Entry entryByAlias(KeyStore keyStore, String alias) {
         try {
             return keyStore.getEntry(alias, null);
-        } catch (NoSuchAlgorithmException e) {
-            throw new RuntimeException(e);
-        } catch (UnrecoverableEntryException e) {
-            throw new RuntimeException(e);
-        } catch (KeyStoreException e) {
+        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException e) {
             throw new RuntimeException(e);
         }
     }
diff --git a/testing/src/main/java/org/conscrypt/java/security/cert/FakeX509Certificate.java b/testing/src/main/java/org/conscrypt/java/security/cert/FakeX509Certificate.java
index ed61cc42..a522f88c 100644
--- a/testing/src/main/java/org/conscrypt/java/security/cert/FakeX509Certificate.java
+++ b/testing/src/main/java/org/conscrypt/java/security/cert/FakeX509Certificate.java
@@ -25,20 +25,17 @@ import java.security.PublicKey;
 import java.security.SignatureException;
 import java.security.cert.CertificateEncodingException;
 import java.security.cert.CertificateException;
-import java.security.cert.CertificateExpiredException;
-import java.security.cert.CertificateNotYetValidException;
 import java.security.cert.X509Certificate;
 import java.util.Date;
 import java.util.Set;
 
+@SuppressWarnings("serial")
 public class FakeX509Certificate extends X509Certificate {
     @Override
-    public void checkValidity()
-            throws CertificateExpiredException, CertificateNotYetValidException {}
+    public void checkValidity() {}
 
     @Override
-    public void checkValidity(Date date)
-            throws CertificateExpiredException, CertificateNotYetValidException {}
+    public void checkValidity(Date date) {}
 
     @Override
     public int getBasicConstraints() {
@@ -61,11 +58,13 @@ public class FakeX509Certificate extends X509Certificate {
     }
 
     @Override
+    @SuppressWarnings("JavaUtilDate")
     public Date getNotAfter() {
         return new Date(System.currentTimeMillis());
     }
 
     @Override
+    @SuppressWarnings("JavaUtilDate")
     public Date getNotBefore() {
         return new Date(System.currentTimeMillis() - 1000);
     }
@@ -100,7 +99,8 @@ public class FakeX509Certificate extends X509Certificate {
         return new MockPrincipal();
     }
 
-    class MockPrincipal implements Principal {
+    static class MockPrincipal implements Principal {
+        @Override
         public String getName() {
             return null;
         }
@@ -111,7 +111,7 @@ public class FakeX509Certificate extends X509Certificate {
     }
 
     @Override
-    public byte[] getTBSCertificate() throws CertificateEncodingException {
+    public byte[] getTBSCertificate() {
         return null;
     }
 
@@ -132,7 +132,7 @@ public class FakeX509Certificate extends X509Certificate {
 
     @Override
     public String toString() {
-        return null;
+        return "null";
     }
 
     @Override
diff --git a/testing/src/main/java/org/conscrypt/tlswire/handshake/AlpnHelloExtension.java b/testing/src/main/java/org/conscrypt/tlswire/handshake/AlpnHelloExtension.java
index 42449178..57e4c23b 100644
--- a/testing/src/main/java/org/conscrypt/tlswire/handshake/AlpnHelloExtension.java
+++ b/testing/src/main/java/org/conscrypt/tlswire/handshake/AlpnHelloExtension.java
@@ -18,6 +18,7 @@ package org.conscrypt.tlswire.handshake;
 import java.io.ByteArrayInputStream;
 import java.io.DataInputStream;
 import java.io.IOException;
+import java.nio.charset.StandardCharsets;
 import java.util.ArrayList;
 import java.util.List;
 import org.conscrypt.tlswire.util.IoUtils;
@@ -33,19 +34,16 @@ public class AlpnHelloExtension extends HelloExtension {
     protected void parseData() throws IOException {
         byte[] alpnListBytes = IoUtils.readTlsVariableLengthByteVector(
                 new DataInputStream(new ByteArrayInputStream(data)), 0xffff);
-        protocols = new ArrayList<String>();
+        protocols = new ArrayList<>();
         DataInputStream alpnList = new DataInputStream(new ByteArrayInputStream(alpnListBytes));
         while (alpnList.available() > 0) {
             byte[] alpnValue = IoUtils.readTlsVariableLengthByteVector(alpnList, 0xff);
-            protocols.add(new String(alpnValue, "US-ASCII"));
+            protocols.add(new String(alpnValue, StandardCharsets.US_ASCII));
         }
     }
 
     @Override
     public String toString() {
-        StringBuilder sb = new StringBuilder("HelloExtension{type: elliptic_curves, protocols: ");
-        sb.append(protocols);
-        sb.append('}');
-        return sb.toString();
+        return "HelloExtension{type: elliptic_curves, protocols: " + protocols + '}';
     }
 }
diff --git a/testing/src/main/java/org/conscrypt/tlswire/handshake/HelloExtension.java b/testing/src/main/java/org/conscrypt/tlswire/handshake/HelloExtension.java
index 07fa271b..9432a24f 100644
--- a/testing/src/main/java/org/conscrypt/tlswire/handshake/HelloExtension.java
+++ b/testing/src/main/java/org/conscrypt/tlswire/handshake/HelloExtension.java
@@ -32,7 +32,7 @@ public class HelloExtension {
     public static final int TYPE_PADDING = 21;
     public static final int TYPE_SESSION_TICKET = 35;
     public static final int TYPE_RENEGOTIATION_INFO = 65281;
-    private static final Map<Integer, String> TYPE_TO_NAME = new HashMap<Integer, String>();
+    private static final Map<Integer, String> TYPE_TO_NAME = new HashMap<>();
     static {
         TYPE_TO_NAME.put(TYPE_SERVER_NAME, "server_name");
         TYPE_TO_NAME.put(1, "max_fragment_length");
@@ -91,10 +91,9 @@ public class HelloExtension {
         result.parseData();
         return result;
     }
-    /**
-     * @throws IOException
-     */
+
     protected void parseData() throws IOException {}
+
     @Override
     public String toString() {
         return "HelloExtension{type: " + name + ", data: " + new BigInteger(1, data).toString(16)
diff --git a/testing/src/main/java/org/conscrypt/tlswire/handshake/ServerNameHelloExtension.java b/testing/src/main/java/org/conscrypt/tlswire/handshake/ServerNameHelloExtension.java
index b91f1953..4eeff44d 100644
--- a/testing/src/main/java/org/conscrypt/tlswire/handshake/ServerNameHelloExtension.java
+++ b/testing/src/main/java/org/conscrypt/tlswire/handshake/ServerNameHelloExtension.java
@@ -18,6 +18,7 @@ package org.conscrypt.tlswire.handshake;
 import java.io.ByteArrayInputStream;
 import java.io.DataInputStream;
 import java.io.IOException;
+import java.nio.charset.StandardCharsets;
 import java.util.ArrayList;
 import java.util.List;
 import org.conscrypt.tlswire.util.IoUtils;
@@ -34,14 +35,14 @@ public class ServerNameHelloExtension extends HelloExtension {
                 new DataInputStream(new ByteArrayInputStream(data)), 0xffff);
         ByteArrayInputStream serverNameListIn = new ByteArrayInputStream(serverNameListBytes);
         DataInputStream in = new DataInputStream(serverNameListIn);
-        hostnames = new ArrayList<String>();
+        hostnames = new ArrayList<>();
         while (serverNameListIn.available() > 0) {
             int type = in.readUnsignedByte();
             if (type != TYPE_HOST_NAME) {
                 throw new IOException("Unsupported ServerName type: " + type);
             }
             byte[] hostnameBytes = IoUtils.readTlsVariableLengthByteVector(in, 0xffff);
-            String hostname = new String(hostnameBytes, "US-ASCII");
+            String hostname = new String(hostnameBytes, StandardCharsets.US_ASCII);
             hostnames.add(hostname);
         }
     }
diff --git a/testing/src/main/java/tests/util/ServiceTester.java b/testing/src/main/java/tests/util/ServiceTester.java
index 813f845c..5dfc7575 100644
--- a/testing/src/main/java/tests/util/ServiceTester.java
+++ b/testing/src/main/java/tests/util/ServiceTester.java
@@ -158,7 +158,7 @@ public final class ServiceTester {
         for (Provider.Service s : p.getServices()) {
           if (s.getType().equals(service)
               && !skipAlgorithms.contains(s.getAlgorithm())
-              && !shouldSkipCombination(p.getName(), s.getAlgorithm())) {
+              && shouldUseCombination(p.getName(), s.getAlgorithm())) {
             doTest(test, p, s.getAlgorithm(), errors);
           }
         }
@@ -166,7 +166,7 @@ public final class ServiceTester {
         algorithms.removeAll(skipAlgorithms);
         for (String algorithm : algorithms) {
           if (p.getService(service, algorithm) != null
-              && !shouldSkipCombination(p.getName(), algorithm)) {
+              && shouldUseCombination(p.getName(), algorithm)) {
             doTest(test, p, algorithm, errors);
           }
         }
@@ -174,7 +174,7 @@ public final class ServiceTester {
     }
     errors.flush();
     if (errBuffer.size() > 0) {
-      fail("Tests failed:\n\n" + errBuffer.toString());
+      fail("Tests failed:\n\n" + errBuffer);
     }
   }
 
@@ -182,8 +182,8 @@ public final class ServiceTester {
     return provider + SEPARATOR + algorithm;
   }
 
-  private boolean shouldSkipCombination(String provider, String algorithm) {
-    return skipCombinations.contains(makeCombination(provider, algorithm));
+  private boolean shouldUseCombination(String provider, String algorithm) {
+    return !skipCombinations.contains(makeCombination(provider, algorithm));
   }
 
   private void doTest(Test test, Provider p, String algorithm, PrintStream errors) {
```

