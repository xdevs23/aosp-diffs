```diff
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index 0bcdf49..7284efb 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -29,22 +29,19 @@ jobs:
       fail-fast: false
       matrix:
         os: [ ubuntu-latest ]
-        java: [ 19, 17, 11.0.16 ]
+        java: [ 21, 17 ]
         experimental: [ false ]
         include:
           # Only test on macos and windows with a single recent JDK to avoid a
           # combinatorial explosion of test configurations.
           - os: macos-latest
-            java: 19
+            java: 21
             experimental: false
           - os: windows-latest
-            java: 19
+            java: 21
             experimental: false
           - os: ubuntu-latest
-            java: 20-ea
-            experimental: true
-          - os: ubuntu-latest
-            java: 21-ea
+            java: EA
             experimental: true
     runs-on: ${{ matrix.os }}
     continue-on-error: ${{ matrix.experimental }}
@@ -55,7 +52,15 @@ jobs:
           access_token: ${{ github.token }}
       - name: 'Check out repository'
         uses: actions/checkout@v2
+      - name: 'Set up JDK ${{ matrix.java }} from jdk.java.net'
+        if: ${{ matrix.java == 'EA' }}
+        uses: oracle-actions/setup-java@v1
+        with:
+          website: jdk.java.net
+          release: ${{ matrix.java }}
+          cache: 'maven'
       - name: 'Set up JDK ${{ matrix.java }}'
+        if: ${{ matrix.java != 'EA' }}
         uses: actions/setup-java@v2
         with:
           java-version: ${{ matrix.java }}
diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml
new file mode 100644
index 0000000..f5a01d7
--- /dev/null
+++ b/.github/workflows/release.yml
@@ -0,0 +1,62 @@
+name: Release turbine
+
+on:
+  workflow_dispatch:
+    inputs:
+      version:
+        description: "version number for this release."
+        required: true
+
+jobs:
+  build-maven-jars:
+    runs-on: ubuntu-latest
+    permissions:
+      contents: write
+    steps:         
+      - name: Checkout
+        uses: actions/checkout@v2.4.0
+
+      - name: Set up JDK
+        uses: actions/setup-java@v2.5.0
+        with:
+          java-version: 17
+          distribution: 'zulu'
+          cache: 'maven'
+          server-id: sonatype-nexus-staging
+          server-username: CI_DEPLOY_USERNAME
+          server-password: CI_DEPLOY_PASSWORD
+          gpg-private-key: ${{ secrets.GPG_SIGNING_KEY }}
+          gpg-passphrase: MAVEN_GPG_PASSPHRASE
+     
+      - name: Bump Version Number
+        run: |
+          mvn --no-transfer-progress versions:set versions:commit -DnewVersion="${{ github.event.inputs.version }}"
+          git ls-files | grep 'pom.xml$' | xargs git add
+          git config --global user.email "${{ github.actor }}@users.noreply.github.com"
+          git config --global user.name "${{ github.actor }}"
+          git commit -m "Release turbine ${{ github.event.inputs.version }}"
+          git tag "v${{ github.event.inputs.version }}"
+          echo "TARGET_COMMITISH=$(git rev-parse HEAD)" >> $GITHUB_ENV
+          git remote set-url origin https://${{ github.actor }}:${{ secrets.GITHUB_TOKEN }}@github.com/google/turbine.git
+          
+      - name: Deploy to Sonatype staging
+        env:
+          CI_DEPLOY_USERNAME: ${{ secrets.CI_DEPLOY_USERNAME }}
+          CI_DEPLOY_PASSWORD: ${{ secrets.CI_DEPLOY_PASSWORD }}
+          GPG_PASSPHRASE: ${{ secrets.GPG_PASSPHRASE }}
+        run:
+          mvn --no-transfer-progress -P sonatype-oss-release clean deploy -Dgpg.passphrase="${{ secrets.GPG_PASSPHRASE }}"
+
+      - name: Push tag
+        run: |
+          git push origin "v${{ github.event.inputs.version }}"
+          
+      - name: Add Jars to Release Entry
+        uses: softprops/action-gh-release@v0.1.14
+        with:
+          draft: true
+          name: ${{ github.event.input.version }} 
+          tag_name: "v${{ github.event.inputs.version }}"
+          target_commitish: ${{ env.TARGET_COMMITISH }}
+          files: |
+            target/turbine-*.jar
diff --git a/Android.bp b/Android.bp
index 2236365..a4a79e5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -44,6 +44,7 @@ java_library_host {
     static_libs: [
         "error_prone_annotations",
         "guava",
+        "jspecify",
     ],
 
     plugins: ["auto_value_plugin"],
diff --git a/KEYS.txt b/KEYS.txt
new file mode 100644
index 0000000..e8c4da5
--- /dev/null
+++ b/KEYS.txt
@@ -0,0 +1,65 @@
+This file contains the PGP and GPG keys used to sign releases.
+
+gpg --list-sigs <your name> && gpg --armor --export <your name>
+
+************************************************************************************************************
+
+pub   rsa4096 2022-01-28 [SC]
+      EE0CA873074092F806F59B65D364ABAA39A47320
+uid           [ultimate] Liam Miller-Cushon (Error Prone releases) <cushon@google.com>
+sig 3        D364ABAA39A47320 2022-01-28  Liam Miller-Cushon (Error Prone releases) <cushon@google.com>
+sub   rsa4096 2022-01-28 [E]
+sig          D364ABAA39A47320 2022-01-28  Liam Miller-Cushon (Error Prone releases) <cushon@google.com>
+
+-----BEGIN PGP PUBLIC KEY BLOCK-----
+
+mQINBGH0NlsBEACnLJ3vl/aV+4ytkJ6QSfDFHrwzSo1eEXyuFZ85mLijvgGuaKRr
+c9/lKed0MuyhLJ7YD752kcFCEIyPbjeqEFsBcgU/RWa1AEfaay4eMLBzLSOwCvhD
+m+1zSFswH2bOqeLSbFZPQ9sVIOzO6AInaOTOoecHChHnUztAhRIOIUYmhABJGiu5
+jCP5SStoXm8YtRWT1unJcduHQ51EztQe02k+RTratQ31OSkeJORle7k7cudCS+yp
+z5gTaS1Bx02v0Y8Qaw17vY9Pn8DmsECRvXL6K7ItX6zKkSdJYVGMtiF/kp4rg94I
+XodrlzrMGPGPga9fTcqMPvx/3ffwgIsgtgaKg7te++L3db/xx48XgZ2qYAU8GssE
+N14xRFQmr8sg+QiCIHL0Az88v9mILYOqgxa3RvQ79tTqAKwPg0o2w/wF/WU0Rw53
+mdNy9JTUjetWKuoTmDaXVZO4LQ2g4W2dQTbgHyomiIgV7BnLFUiqOLPo+imruSCs
+W31Arjpb8q6XGTwjySa8waJxHhyV2AvEdAHUIdNuhD4dmPKXszlfFZwXbo1OOuIF
+tUZ9lsOQiCpuO7IpIprLc8L9d1TRnCrfM8kxMbX4KVGajWL+c8FlLnUwR4gSxT1G
+qIgZZ09wL5QiTeGF3biS5mxvn+gF9ns2Ahr2QmMqA2k5AMBTJimmY/OSWwARAQAB
+tD1MaWFtIE1pbGxlci1DdXNob24gKEVycm9yIFByb25lIHJlbGVhc2VzKSA8Y3Vz
+aG9uQGdvb2dsZS5jb20+iQJOBBMBCgA4FiEE7gyocwdAkvgG9Ztl02SrqjmkcyAF
+AmH0NlsCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQ02SrqjmkcyAtqxAA
+i9e8YpWNNGiRGan+5luHPK7YiXhSoCnvaTK5/EhwQt1xqwWoHuHBTllpXyeKmUa/
+np5wK97i1gewadXFpcRuAyXLZnWN61yOdOiRfq9CoDefGSZOFgJ7/bB/RbZ4Moss
+ZZihN4Vz7CWBTFaVNvq4KVg0QE5uXgcsEOZPmuyJaC8XHK37qMYwawxpkxC0jGJu
+qp1nqkL+wEQBY3go9u2tzyQKX0fpF2g8puPZC92ezwf0p3ctEwhalptDICl74hDD
+R9xAkPk6vimozLFxi/Ld0iDpEuouK91cuFh7nZYpjiJrgBcYKyvuEjtADefhJMWl
+JRWZYmexynoLIas7mYkRGlnSQfkEFGy3dX7UU8TfRn5m1Bk7JTQHCauCNs+COdM0
+nVe8yUTsv+tZhU2yE9DIbeJP+ySUVZxpUNihhWuZFoSpqxWbsaX0XyDhZk1iPLU6
+H2RpUsWXYkMRN6eCs+8iNLBGccYuP8AI0/eMa5+JbsCF+/NToLpMiEqq3ZIeOR7i
+KJY/iDkGnq+hK6eNjEv5/7lYgcW+WACqoiGURm/UKiOTeHyt0AvMXRpTGiVk7DU8
+WitWapGjayQdQEO8U8TSWlVktTdVGZQJCUiUjQT+gUlRaCybyDFIUkOStMPtLqe/
+GlSo8olccB7O1J5VOURi8/17iWUtzOgsp0ZzU5t76US5Ag0EYfQ2WwEQAL2jqb4P
+Yu5saM4nEtAHUGd8E6QUdp2xuRvzZAV2sI2x3jh8mJ5qplU/7pccpVEdI+S3CkTU
+WeNOEEkmwvDBy/BZfAPC8QPnufhsBM+Ws8a4bvH4tFVvEUFN34tBQJwd3em6u69s
+SNB1XniZuB0yoCnl1IDgVzqHaExZUFfgR0uIf/S6LeVSiphMlwHvdTX+NspxuzT5
+xW5cimYA9CkizfSnTBYs4qImqf21NmnB+e2et18u8ovcVlxFB5ZmOofVjC3jNaUJ
+GoYSnvJWqErmCfid8R1JfaSjGvnc46waTY+OHOz/lckuLUVM5yeNrmSSo4+I8YH8
+HECeM8ISxKI4WYXcB/hZ1hrf5Mrz6CAFIR4uOMtrnPKp7F+EAPCBvkBJmK1QSslk
+OEC+ocbB/PdU8Q3LcraQksf6ZpbA5PVlGgmfPd/HAi6AqE/HUzOXCFNyUiScrurY
+I1wHrWkL2WDvQgJbT3Q2CScTYO2aOtEw42FxKS5YYtkEoGBGo3AhMkVwB2Dr599n
+MYuycR37oDb092xd8tL0omqJpu+mIGDxFoABaK/lOqw271hJZRBTMFk7je7wDFO1
+OG4dhmvFqygLewIYhxHLZX15qrjzQNEn26i040y60gdQNVJ2pWI+aaK3T4/JGIJf
+8M54Ee6ZoQ6b5GojE8TyHpbywetgBDsnVrcBABEBAAGJAjYEGAEKACAWIQTuDKhz
+B0CS+Ab1m2XTZKuqOaRzIAUCYfQ2WwIbDAAKCRDTZKuqOaRzICx6EACmzqP6qmPI
+0ZR638HpnuclyhtLGcIg/9z65Q8PWgHpS6G3o1NhZB3CYSovkEbPxY1OwF3RxBi9
+LO2syLPm0IOiIYatZyBbGus3FzURXJ2EFtPg+mIboIFYUKgRc3vr9/Sd3FluOOhs
+SVNdtDqhouHbzXY5q+Ax2IlRUGBeu1+CLn+Hj1alzmj8gMzdt+6N+ufme88iR3sR
+74ZorZhIJPul8rg395bWDVK6ypFDEEoJTcLkxWBWOSkFrzZTSRPFQYMVhRRxL5iO
+GL/Di7KfAhdbSlKXnC/FVXE0F8YUfl+SmuSly5Ven0HpJFUzzm5ShkkVogXKgCFT
+25BB9V7q6DA/0FuHNHMOkl722I5xprPDM2c/lmPfWchXpSW1m7uZVKXUnAhxbFbd
+vfqnge30bmMg9BzzFL6gx3/+nyvixgUHgo5hqzW6RE2IKyGf20l96iGQqP17DHJQ
+1/WtLy45Qm9kLdzddEXwIldGnGYe7ak81/RDEVWGCEtjZwlTU5YaLo3Jk3rkR1+a
+RNt4PF2VI2/z1JMPhWnoyYW2sDglkNJHQGnXMQ8qJLGOkbkWl9W/qVeYVuhrmqRc
+Acb35txpFihe6f7AneKhaj5xAR3L9uxfTf4wcyyazyWKSZ88gZXDvdEXcdeMnwZW
+pOSpujhmmBPD/tnf58BgT+/Gq6GemXYe8Q==
+=BIwO
+-----END PGP PUBLIC KEY BLOCK-----
diff --git a/METADATA b/METADATA
index 841d8e6..e354d0f 100644
--- a/METADATA
+++ b/METADATA
@@ -1,23 +1,20 @@
 # This project was upgraded with external_updater.
-# Usage: tools/external_updater/updater.sh update turbine
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# Usage: tools/external_updater/updater.sh update external/turbine
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "turbine"
 description: "Turbine is a header compiler for Java."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/google/turbine"
-  }
-  url {
-    type: GIT
-    value: "https://github.com/google/turbine"
-  }
-  version: "7c64f0447a967d4717adb7b1b40d8bb856f34186"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2023
-    month: 7
-    day: 24
+    year: 2025
+    month: 1
+    day: 18
+  }
+  homepage: "https://github.com/google/turbine"
+  identifier {
+    type: "Git"
+    value: "https://github.com/google/turbine"
+    version: "5d422e5bc6ff4928223ea049856d27590661db04"
   }
 }
diff --git a/OWNERS b/OWNERS
index 70b375f..5726e17 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 ccross@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/java/com/google/turbine/binder/Binder.java b/java/com/google/turbine/binder/Binder.java
index d2ce948..ee2a674 100644
--- a/java/com/google/turbine/binder/Binder.java
+++ b/java/com/google/turbine/binder/Binder.java
@@ -69,7 +69,7 @@ import com.google.turbine.type.Type;
 import java.time.Duration;
 import java.util.Optional;
 import javax.annotation.processing.Processor;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** The entry point for analysis. */
 public final class Binder {
@@ -91,6 +91,19 @@ public final class Binder {
       ClassPath bootclasspath,
       Optional<String> moduleVersion) {
     TurbineLog log = new TurbineLog();
+    BindingResult br = bind(log, units, classpath, processorInfo, bootclasspath, moduleVersion);
+    log.maybeThrow();
+    return br;
+  }
+
+  /** Binds symbols and types to the given compilation units. */
+  public static @Nullable BindingResult bind(
+      TurbineLog log,
+      ImmutableList<CompUnit> units,
+      ClassPath classpath,
+      ProcessorInfo processorInfo,
+      ClassPath bootclasspath,
+      Optional<String> moduleVersion) {
     BindingResult br;
     try {
       br =
@@ -114,7 +127,6 @@ public final class Binder {
               .addAll(turbineError.diagnostics())
               .build());
     }
-    log.maybeThrow();
     return br;
   }
 
@@ -159,6 +171,8 @@ public final class Binder {
             henv,
             CompoundEnv.<ClassSymbol, HeaderBoundClass>of(classPathEnv).append(henv));
 
+    tenv = PermitsBinder.bindPermits(syms, tenv);
+
     tenv =
         constants(
             syms,
diff --git a/java/com/google/turbine/binder/ClassPath.java b/java/com/google/turbine/binder/ClassPath.java
index eb78099..ab2fe1b 100644
--- a/java/com/google/turbine/binder/ClassPath.java
+++ b/java/com/google/turbine/binder/ClassPath.java
@@ -23,7 +23,7 @@ import com.google.turbine.binder.env.Env;
 import com.google.turbine.binder.lookup.TopLevelIndex;
 import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.binder.sym.ModuleSymbol;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A compilation classpath, e.g. the user or platform class path. May be backed by a search path of
@@ -39,6 +39,5 @@ public interface ClassPath {
   /** The classpath's top level index. */
   TopLevelIndex index();
 
-  @Nullable
-  Supplier<byte[]> resource(String path);
+  @Nullable Supplier<byte[]> resource(String path);
 }
diff --git a/java/com/google/turbine/binder/ClassPathBinder.java b/java/com/google/turbine/binder/ClassPathBinder.java
index 57f30cf..b499fa2 100644
--- a/java/com/google/turbine/binder/ClassPathBinder.java
+++ b/java/com/google/turbine/binder/ClassPathBinder.java
@@ -17,7 +17,6 @@
 package com.google.turbine.binder;
 
 import com.google.common.base.Supplier;
-import com.google.common.base.Suppliers;
 import com.google.common.collect.ImmutableMap;
 import com.google.turbine.binder.bound.ModuleInfo;
 import com.google.turbine.binder.bytecode.BytecodeBinder;
@@ -35,8 +34,7 @@ import java.util.Collection;
 import java.util.HashMap;
 import java.util.LinkedHashMap;
 import java.util.Map;
-import java.util.function.Function;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Sets up an environment for symbols on the classpath. */
 public final class ClassPathBinder {
@@ -47,35 +45,39 @@ public final class ClassPathBinder {
    */
   public static final String TRANSITIVE_PREFIX = "META-INF/TRANSITIVE/";
 
+  /**
+   * The suffix for repackaged transitive dependencies; see {@link
+   * com.google.turbine.deps.Transitive}.
+   */
+  public static final String TRANSITIVE_SUFFIX = ".turbine";
+
   /** Creates an environment containing symbols in the given classpath. */
   public static ClassPath bindClasspath(Collection<Path> paths) throws IOException {
-    // TODO(cushon): this is going to require an env eventually,
-    // e.g. to look up type parameters in enclosing declarations
-    Map<ClassSymbol, BytecodeBoundClass> transitive = new LinkedHashMap<>();
-    Map<ClassSymbol, BytecodeBoundClass> map = new HashMap<>();
+    Map<ClassSymbol, Supplier<BytecodeBoundClass>> transitive = new LinkedHashMap<>();
+    Map<ClassSymbol, Supplier<BytecodeBoundClass>> map = new HashMap<>();
     Map<ModuleSymbol, ModuleInfo> modules = new HashMap<>();
     Map<String, Supplier<byte[]>> resources = new HashMap<>();
-    Env<ClassSymbol, BytecodeBoundClass> benv =
+    Env<ClassSymbol, BytecodeBoundClass> env =
         new Env<ClassSymbol, BytecodeBoundClass>() {
           @Override
           public @Nullable BytecodeBoundClass get(ClassSymbol sym) {
-            return map.get(sym);
+            Supplier<BytecodeBoundClass> supplier = map.get(sym);
+            return supplier == null ? null : supplier.get();
           }
         };
     for (Path path : paths) {
       try {
-        bindJar(path, map, modules, benv, transitive, resources);
+        bindJar(path, map, modules, env, transitive, resources);
       } catch (IOException e) {
         throw new IOException("error reading " + path, e);
       }
     }
-    for (Map.Entry<ClassSymbol, BytecodeBoundClass> entry : transitive.entrySet()) {
+    for (Map.Entry<ClassSymbol, Supplier<BytecodeBoundClass>> entry : transitive.entrySet()) {
       ClassSymbol symbol = entry.getKey();
       map.putIfAbsent(symbol, entry.getValue());
     }
-    SimpleEnv<ClassSymbol, BytecodeBoundClass> env = new SimpleEnv<>(ImmutableMap.copyOf(map));
     SimpleEnv<ModuleSymbol, ModuleInfo> moduleEnv = new SimpleEnv<>(ImmutableMap.copyOf(modules));
-    TopLevelIndex index = SimpleTopLevelIndex.of(env.asMap().keySet());
+    TopLevelIndex index = SimpleTopLevelIndex.of(map.keySet());
     return new ClassPath() {
       @Override
       public Env<ClassSymbol, BytecodeBoundClass> env() {
@@ -101,54 +103,39 @@ public final class ClassPathBinder {
 
   private static void bindJar(
       Path path,
-      Map<ClassSymbol, BytecodeBoundClass> env,
+      Map<ClassSymbol, Supplier<BytecodeBoundClass>> env,
       Map<ModuleSymbol, ModuleInfo> modules,
       Env<ClassSymbol, BytecodeBoundClass> benv,
-      Map<ClassSymbol, BytecodeBoundClass> transitive,
+      Map<ClassSymbol, Supplier<BytecodeBoundClass>> transitive,
       Map<String, Supplier<byte[]>> resources)
       throws IOException {
     // TODO(cushon): don't leak file descriptors
     for (Zip.Entry ze : new Zip.ZipIterable(path)) {
       String name = ze.name();
-      if (!name.endsWith(".class")) {
-        resources.put(name, toByteArrayOrDie(ze));
-        continue;
-      }
       if (name.startsWith(TRANSITIVE_PREFIX)) {
+        if (!name.endsWith(TRANSITIVE_SUFFIX)) {
+          continue;
+        }
         ClassSymbol sym =
             new ClassSymbol(
-                name.substring(TRANSITIVE_PREFIX.length(), name.length() - ".class".length()));
-        transitive.computeIfAbsent(
-            sym,
-            new Function<ClassSymbol, BytecodeBoundClass>() {
-              @Override
-              public BytecodeBoundClass apply(ClassSymbol sym) {
-                return new BytecodeBoundClass(sym, toByteArrayOrDie(ze), benv, path.toString());
-              }
-            });
+                name.substring(
+                    TRANSITIVE_PREFIX.length(), name.length() - TRANSITIVE_SUFFIX.length()));
+        transitive.putIfAbsent(sym, BytecodeBoundClass.lazy(sym, ze, benv, path));
+        continue;
+      }
+      if (!name.endsWith(".class")) {
+        resources.put(name, ze);
         continue;
       }
       if (name.substring(name.lastIndexOf('/') + 1).equals("module-info.class")) {
-        ModuleInfo moduleInfo =
-            BytecodeBinder.bindModuleInfo(path.toString(), toByteArrayOrDie(ze));
+        ModuleInfo moduleInfo = BytecodeBinder.bindModuleInfo(path.toString(), ze);
         modules.put(new ModuleSymbol(moduleInfo.name()), moduleInfo);
         continue;
       }
       ClassSymbol sym = new ClassSymbol(name.substring(0, name.length() - ".class".length()));
-      env.putIfAbsent(
-          sym, new BytecodeBoundClass(sym, toByteArrayOrDie(ze), benv, path.toString()));
+      env.putIfAbsent(sym, BytecodeBoundClass.lazy(sym, ze, benv, path));
     }
   }
 
-  private static Supplier<byte[]> toByteArrayOrDie(Zip.Entry ze) {
-    return Suppliers.memoize(
-        new Supplier<byte[]>() {
-          @Override
-          public byte[] get() {
-            return ze.data();
-          }
-        });
-  }
-
   private ClassPathBinder() {}
 }
diff --git a/java/com/google/turbine/binder/CompUnitPreprocessor.java b/java/com/google/turbine/binder/CompUnitPreprocessor.java
index 98be898..070bb15 100644
--- a/java/com/google/turbine/binder/CompUnitPreprocessor.java
+++ b/java/com/google/turbine/binder/CompUnitPreprocessor.java
@@ -117,7 +117,7 @@ public final class CompUnitPreprocessor {
     for (TyDecl decl : decls) {
       ClassSymbol sym =
           new ClassSymbol((!packageName.isEmpty() ? packageName + "/" : "") + decl.name());
-      int access = access(decl.mods(), decl.tykind());
+      int access = access(decl.mods(), decl);
       ImmutableMap<String, ClassSymbol> children =
           preprocessChildren(unit.source(), types, sym, decl.members(), access);
       types.add(new SourceBoundClass(sym, null, children, access, decl));
@@ -167,12 +167,12 @@ public final class CompUnitPreprocessor {
   }
 
   /** Desugars access flags for a class. */
-  public static int access(ImmutableSet<TurbineModifier> mods, TurbineTyKind tykind) {
+  public static int access(ImmutableSet<TurbineModifier> mods, TyDecl decl) {
     int access = 0;
     for (TurbineModifier m : mods) {
       access |= m.flag();
     }
-    switch (tykind) {
+    switch (decl.tykind()) {
       case CLASS:
         access |= TurbineFlag.ACC_SUPER;
         break;
@@ -180,11 +180,14 @@ public final class CompUnitPreprocessor {
         access |= TurbineFlag.ACC_ABSTRACT | TurbineFlag.ACC_INTERFACE;
         break;
       case ENUM:
-        // Assuming all enums are final is safe, because nothing outside
-        // the compilation unit can extend abstract enums anyways, and
-        // refactoring an existing enum to implement methods in the container
-        // class instead of the constants is not a breaking change.
-        access |= TurbineFlag.ACC_SUPER | TurbineFlag.ACC_ENUM | TurbineFlag.ACC_FINAL;
+        // Assuming all enums are non-abstract is safe, because nothing outside
+        // the compilation unit can extend abstract enums, and refactoring an
+        // existing enum to implement methods in the container class instead
+        // of the constants is not a breaking change.
+        access |= TurbineFlag.ACC_SUPER | TurbineFlag.ACC_ENUM;
+        if (isEnumFinal(decl.members())) {
+          access |= TurbineFlag.ACC_FINAL;
+        }
         break;
       case ANNOTATION:
         access |= TurbineFlag.ACC_ABSTRACT | TurbineFlag.ACC_INTERFACE | TurbineFlag.ACC_ANNOTATION;
@@ -196,9 +199,27 @@ public final class CompUnitPreprocessor {
     return access;
   }
 
+  /**
+   * If any enum constants have a class body (which is recorded in the parser by setting ENUM_IMPL),
+   * the class generated for the enum needs to not have ACC_FINAL set.
+   */
+  private static boolean isEnumFinal(ImmutableList<Tree> declMembers) {
+    for (Tree t : declMembers) {
+      if (t.kind() != Tree.Kind.VAR_DECL) {
+        continue;
+      }
+      Tree.VarDecl var = (Tree.VarDecl) t;
+      if (!var.mods().contains(TurbineModifier.ENUM_IMPL)) {
+        continue;
+      }
+      return false;
+    }
+    return true;
+  }
+
   /** Desugars access flags for an inner class. */
   private static int innerClassAccess(int enclosing, TyDecl decl) {
-    int access = access(decl.mods(), decl.tykind());
+    int access = access(decl.mods(), decl);
 
     // types declared in interfaces and annotations are implicitly public (JLS 9.5)
     if ((enclosing & (TurbineFlag.ACC_INTERFACE | TurbineFlag.ACC_ANNOTATION)) != 0) {
diff --git a/java/com/google/turbine/binder/ConstBinder.java b/java/com/google/turbine/binder/ConstBinder.java
index 29ae710..e75da34 100644
--- a/java/com/google/turbine/binder/ConstBinder.java
+++ b/java/com/google/turbine/binder/ConstBinder.java
@@ -58,7 +58,7 @@ import com.google.turbine.type.Type.WildUnboundedTy;
 import com.google.turbine.type.Type.WildUpperBoundedTy;
 import java.lang.annotation.RetentionPolicy;
 import java.util.Map;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Binding pass to evaluate constant expressions. */
 public class ConstBinder {
diff --git a/java/com/google/turbine/binder/ConstEvaluator.java b/java/com/google/turbine/binder/ConstEvaluator.java
index 771e87f..558c91c 100644
--- a/java/com/google/turbine/binder/ConstEvaluator.java
+++ b/java/com/google/turbine/binder/ConstEvaluator.java
@@ -74,14 +74,15 @@ import java.util.ArrayDeque;
 import java.util.Iterator;
 import java.util.LinkedHashMap;
 import java.util.Map;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Constant expression evaluation.
  *
- * <p>JLS §15.4 requires this class to be strictfp.
+ * <p>This class requires strict floating point operations. In Java SE 17 and later, the Java SE
+ * Platform always requires strict evaluation of floating-point expressions.
  */
-public strictfp class ConstEvaluator {
+public class ConstEvaluator {
 
   /** The symbol of the originating class, for visibility checks. */
   private final @Nullable ClassSymbol origin;
@@ -212,7 +213,7 @@ public strictfp class ConstEvaluator {
     LookupResult result = scope.lookup(new LookupKey(ImmutableList.copyOf(flat)));
     if (result == null) {
       log.error(classTy.position(), ErrorKind.CANNOT_RESOLVE, flat.getFirst());
-      return Type.ErrorTy.create(flat);
+      return Type.ErrorTy.create(flat, ImmutableList.of());
     }
     if (result.sym().symKind() != Symbol.Kind.CLASS) {
       throw error(classTy.position(), ErrorKind.UNEXPECTED_TYPE_PARAMETER, flat.getFirst());
@@ -234,8 +235,7 @@ public strictfp class ConstEvaluator {
   }
 
   /** Evaluates a reference to another constant variable. */
-  @Nullable
-  Const evalConstVar(ConstVarName t) {
+  @Nullable Const evalConstVar(ConstVarName t) {
     FieldInfo field = resolveField(t);
     if (field == null) {
       return null;
@@ -1312,8 +1312,7 @@ public strictfp class ConstEvaluator {
     return new Const.ArrayInitValue(elements.build());
   }
 
-  @Nullable
-  Const evalAnnotationValue(Tree tree, Type ty) {
+  @Nullable Const evalAnnotationValue(Tree tree, Type ty) {
     if (ty == null) {
       throw error(tree.position(), ErrorKind.EXPRESSION_ERROR);
     }
diff --git a/java/com/google/turbine/binder/CtSymClassBinder.java b/java/com/google/turbine/binder/CtSymClassBinder.java
index f0e21f2..8b374a3 100644
--- a/java/com/google/turbine/binder/CtSymClassBinder.java
+++ b/java/com/google/turbine/binder/CtSymClassBinder.java
@@ -16,13 +16,11 @@
 
 package com.google.turbine.binder;
 
-import static com.google.common.base.Ascii.toUpperCase;
 import static com.google.common.base.StandardSystemProperty.JAVA_HOME;
 import static java.util.Objects.requireNonNull;
 
 import com.google.common.annotations.VisibleForTesting;
 import com.google.common.base.Supplier;
-import com.google.common.base.Suppliers;
 import com.google.common.collect.ImmutableMap;
 import com.google.turbine.binder.bound.ModuleInfo;
 import com.google.turbine.binder.bytecode.BytecodeBinder;
@@ -40,19 +38,26 @@ import java.nio.file.Path;
 import java.nio.file.Paths;
 import java.util.HashMap;
 import java.util.Map;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Constructs a platform {@link ClassPath} from the current JDK's ct.sym file. */
 public final class CtSymClassBinder {
 
-  private static final int FEATURE_VERSION = Runtime.version().feature();
-
   public static @Nullable ClassPath bind(int version) throws IOException {
-    String javaHome = JAVA_HOME.value();
-    requireNonNull(javaHome, "attempted to use --release, but JAVA_HOME is not set");
-    Path ctSym = Paths.get(javaHome).resolve("lib/ct.sym");
-    if (!Files.exists(ctSym)) {
-      throw new IllegalStateException("lib/ct.sym does not exist in " + javaHome);
+    Path ctSym;
+    String explicitCtSymPath = System.getProperty("turbine.ctSymPath");
+    if (explicitCtSymPath == null) {
+      String javaHome = JAVA_HOME.value();
+      requireNonNull(javaHome, "attempted to use --release, but JAVA_HOME is not set");
+      ctSym = Paths.get(javaHome).resolve("lib/ct.sym");
+      if (!Files.exists(ctSym)) {
+        throw new IllegalStateException("lib/ct.sym does not exist in " + javaHome);
+      }
+    } else {
+      ctSym = Paths.get(explicitCtSymPath);
+      if (!Files.exists(ctSym)) {
+        throw new IllegalStateException("ct.sym does not exist at " + ctSym);
+      }
     }
     Map<ClassSymbol, BytecodeBoundClass> map = new HashMap<>();
     Map<ModuleSymbol, ModuleInfo> modules = new HashMap<>();
@@ -63,10 +68,7 @@ public final class CtSymClassBinder {
             return map.get(sym);
           }
         };
-    // ct.sym contains directories whose names are the concatentation of a list of target versions
-    // formatted as a single character 0-9 or A-Z (e.g. 789A) and which contain interface class
-    // files with a .sig extension.
-    String releaseString = formatReleaseVersion(version);
+    char releaseChar = formatReleaseVersion(version);
     for (Zip.Entry ze : new Zip.ZipIterable(ctSym)) {
       String name = ze.name();
       if (!name.endsWith(".sig")) {
@@ -77,21 +79,18 @@ public final class CtSymClassBinder {
         continue;
       }
       // check if the directory matches the desired release
-      if (!ze.name().substring(0, idx).contains(releaseString)) {
+      if (ze.name().substring(0, idx).indexOf(releaseChar) == -1) {
         continue;
       }
-      if (FEATURE_VERSION >= 12) {
-        // JDK >= 12 includes the module name as a prefix
-        idx = name.indexOf('/', idx + 1);
-      }
+      // JDK >= 12 includes the module name as a prefix
+      idx = name.indexOf('/', idx + 1);
       if (name.substring(name.lastIndexOf('/') + 1).equals("module-info.sig")) {
-        ModuleInfo moduleInfo = BytecodeBinder.bindModuleInfo(name, toByteArrayOrDie(ze));
+        ModuleInfo moduleInfo = BytecodeBinder.bindModuleInfo(name, ze);
         modules.put(new ModuleSymbol(moduleInfo.name()), moduleInfo);
         continue;
       }
       ClassSymbol sym = new ClassSymbol(name.substring(idx + 1, name.length() - ".sig".length()));
-      map.putIfAbsent(
-          sym, new BytecodeBoundClass(sym, toByteArrayOrDie(ze), benv, ctSym + "!" + ze.name()));
+      map.putIfAbsent(sym, new BytecodeBoundClass(sym, ze, benv, ctSym + "!" + ze.name()));
     }
     if (map.isEmpty()) {
       // we didn't find any classes for the desired release
@@ -123,22 +122,21 @@ public final class CtSymClassBinder {
     };
   }
 
-  private static Supplier<byte[]> toByteArrayOrDie(Zip.Entry ze) {
-    return Suppliers.memoize(
-        new Supplier<byte[]>() {
-          @Override
-          public byte[] get() {
-            return ze.data();
-          }
-        });
-  }
-
+  // ct.sym contains directories whose names are the concatenation of a list of target versions
+  // formatted as a single character 0-9 or A-Z (e.g. 789A) and which contain interface class
+  // files with a .sig extension.
+  // This was updated to use 36 as a radix in https://bugs.openjdk.org/browse/JDK-8245544,
+  // it's not clear what the plan is for JDK 36.
   @VisibleForTesting
-  static String formatReleaseVersion(int n) {
+  static char formatReleaseVersion(int n) {
     if (n <= 4 || n >= 36) {
       throw new IllegalArgumentException("invalid release version: " + n);
     }
-    return toUpperCase(Integer.toString(n, 36));
+    if (n < 10) {
+      return (char) ('0' + n);
+    } else {
+      return (char) ('A' + n - 10);
+    }
   }
 
   private CtSymClassBinder() {}
diff --git a/java/com/google/turbine/binder/FileManagerClassBinder.java b/java/com/google/turbine/binder/FileManagerClassBinder.java
index a807dd7..8f77b9a 100644
--- a/java/com/google/turbine/binder/FileManagerClassBinder.java
+++ b/java/com/google/turbine/binder/FileManagerClassBinder.java
@@ -39,7 +39,7 @@ import javax.tools.FileObject;
 import javax.tools.JavaFileObject;
 import javax.tools.StandardJavaFileManager;
 import javax.tools.StandardLocation;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Binds a {@link StandardJavaFileManager} to an {@link ClassPath}. This can be used to share a
diff --git a/java/com/google/turbine/binder/HierarchyBinder.java b/java/com/google/turbine/binder/HierarchyBinder.java
index 3117d4e..b8ca59d 100644
--- a/java/com/google/turbine/binder/HierarchyBinder.java
+++ b/java/com/google/turbine/binder/HierarchyBinder.java
@@ -35,7 +35,7 @@ import com.google.turbine.tree.Tree;
 import com.google.turbine.tree.Tree.ClassTy;
 import java.util.ArrayDeque;
 import java.util.LinkedHashMap;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Type hierarchy binding. */
 public class HierarchyBinder {
diff --git a/java/com/google/turbine/binder/JimageClassBinder.java b/java/com/google/turbine/binder/JimageClassBinder.java
index 53a6a3a..1d264ec 100644
--- a/java/com/google/turbine/binder/JimageClassBinder.java
+++ b/java/com/google/turbine/binder/JimageClassBinder.java
@@ -53,7 +53,7 @@ import java.util.HashMap;
 import java.util.HashSet;
 import java.util.Map;
 import java.util.Set;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Constructs a platform {@link ClassPath} from the current JDK's jimage file using jrtfs. */
 public class JimageClassBinder {
@@ -105,14 +105,12 @@ public class JimageClassBinder {
     this.modulesRoot = modules;
   }
 
-  @Nullable
-  Path modulePath(String moduleName) {
+  @Nullable Path modulePath(String moduleName) {
     Path path = modulesRoot.resolve(moduleName);
     return Files.exists(path) ? path : null;
   }
 
-  @Nullable
-  ModuleInfo module(String moduleName) {
+  @Nullable ModuleInfo module(String moduleName) {
     ModuleInfo result = moduleMap.get(moduleName);
     if (result == null) {
       Path path = modulePath(moduleName);
diff --git a/java/com/google/turbine/binder/ModuleBinder.java b/java/com/google/turbine/binder/ModuleBinder.java
index e88440d..6d12154 100644
--- a/java/com/google/turbine/binder/ModuleBinder.java
+++ b/java/com/google/turbine/binder/ModuleBinder.java
@@ -136,7 +136,7 @@ public class ModuleBinder {
           break;
       }
     }
-    if (!requiresJavaBase) {
+    if (!requiresJavaBase && !module.module().moduleName().equals(ModuleSymbol.JAVA_BASE.name())) {
       // Everything requires java.base, either explicitly or implicitly.
       ModuleInfo javaBaseModule = moduleEnv.get(ModuleSymbol.JAVA_BASE);
       // Tolerate a missing java.base module, e.g. when compiling a module against a non-modular
diff --git a/java/com/google/turbine/binder/PermitsBinder.java b/java/com/google/turbine/binder/PermitsBinder.java
new file mode 100644
index 0000000..06063d3
--- /dev/null
+++ b/java/com/google/turbine/binder/PermitsBinder.java
@@ -0,0 +1,110 @@
+/*
+ * Copyright 2024 Google Inc. All Rights Reserved.
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
+package com.google.turbine.binder;
+
+import com.google.common.collect.ImmutableList;
+import com.google.common.collect.ImmutableSet;
+import com.google.common.collect.ListMultimap;
+import com.google.common.collect.MultimapBuilder;
+import com.google.turbine.binder.bound.SourceTypeBoundClass;
+import com.google.turbine.binder.env.Env;
+import com.google.turbine.binder.env.SimpleEnv;
+import com.google.turbine.binder.sym.ClassSymbol;
+import com.google.turbine.model.TurbineFlag;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Set;
+
+final class PermitsBinder {
+
+  /**
+   * Given the classes in the current compilation, finds implicit permitted subtypes of sealed
+   * classes.
+   *
+   * <p>See JLS §8.1.1.2 for details of implicit permits.
+   *
+   * @param syms the set of classes being compiled in this compilation unit
+   * @param tenv the environment of the current compilation unit only. Dependencies from the
+   *     classpath or bootclasspath are not required by this pass, because any implicitly permitted
+   *     subtypes are required to be in the same compilation unit as their supertype.
+   */
+  static Env<ClassSymbol, SourceTypeBoundClass> bindPermits(
+      ImmutableSet<ClassSymbol> syms, Env<ClassSymbol, SourceTypeBoundClass> tenv) {
+    Set<ClassSymbol> sealedClassesWithoutExplicitPermits = new HashSet<>();
+    for (ClassSymbol sym : syms) {
+      SourceTypeBoundClass info = tenv.getNonNull(sym);
+      if (((info.access() & TurbineFlag.ACC_SEALED) == TurbineFlag.ACC_SEALED)
+          && info.permits().isEmpty()) {
+        sealedClassesWithoutExplicitPermits.add(sym);
+      }
+    }
+    if (sealedClassesWithoutExplicitPermits.isEmpty()) {
+      // fast path if there were no sealed types with an empty 'permits' clause
+      return tenv;
+    }
+    ListMultimap<ClassSymbol, ClassSymbol> permits =
+        MultimapBuilder.hashKeys().arrayListValues().build();
+    for (ClassSymbol sym : syms) {
+      SourceTypeBoundClass info = tenv.getNonNull(sym);
+      // Check if the current class has a direct supertype that is a sealed class with an empty
+      // 'permits' clause.
+      ClassSymbol superclass = info.superclass();
+      if (superclass != null && sealedClassesWithoutExplicitPermits.contains(superclass)) {
+        permits.put(superclass, sym);
+      }
+      for (ClassSymbol i : info.interfaces()) {
+        if (sealedClassesWithoutExplicitPermits.contains(i)) {
+          permits.put(i, sym);
+        }
+      }
+    }
+    SimpleEnv.Builder<ClassSymbol, SourceTypeBoundClass> builder = SimpleEnv.builder();
+    for (ClassSymbol sym : syms) {
+      List<ClassSymbol> thisPermits = permits.get(sym);
+      SourceTypeBoundClass base = tenv.getNonNull(sym);
+      if (thisPermits.isEmpty()) {
+        builder.put(sym, base);
+      } else {
+        builder.put(
+            sym,
+            new SourceTypeBoundClass(
+                /* interfaceTypes= */ base.interfaceTypes(),
+                /* permits= */ ImmutableList.copyOf(thisPermits),
+                /* superClassType= */ base.superClassType(),
+                /* typeParameterTypes= */ base.typeParameterTypes(),
+                /* access= */ base.access(),
+                /* components= */ base.components(),
+                /* methods= */ base.methods(),
+                /* fields= */ base.fields(),
+                /* owner= */ base.owner(),
+                /* kind= */ base.kind(),
+                /* children= */ base.children(),
+                /* typeParameters= */ base.typeParameters(),
+                /* enclosingScope= */ base.enclosingScope(),
+                /* scope= */ base.scope(),
+                /* memberImports= */ base.memberImports(),
+                /* annotationMetadata= */ base.annotationMetadata(),
+                /* annotations= */ base.annotations(),
+                /* source= */ base.source(),
+                /* decl= */ base.decl()));
+      }
+    }
+    return builder.build();
+  }
+
+  private PermitsBinder() {}
+}
diff --git a/java/com/google/turbine/binder/Processing.java b/java/com/google/turbine/binder/Processing.java
index 83ee905..12c06b9 100644
--- a/java/com/google/turbine/binder/Processing.java
+++ b/java/com/google/turbine/binder/Processing.java
@@ -71,7 +71,7 @@ import javax.annotation.processing.Processor;
 import javax.lang.model.SourceVersion;
 import javax.lang.model.element.TypeElement;
 import javax.tools.Diagnostic;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Top level annotation processing logic, see also {@link Binder}. */
 public class Processing {
@@ -161,7 +161,7 @@ public class Processing {
         SupportedAnnotationTypes supportedAnnotationTypes = e.getValue();
         Set<TypeElement> annotations = new HashSet<>();
         boolean run = supportedAnnotationTypes.everything() || toRun.contains(processor);
-        for (ClassSymbol a : allAnnotations.keys()) {
+        for (ClassSymbol a : allAnnotations.keySet()) {
           if (supportedAnnotationTypes.everything()
               || supportedAnnotationTypes.pattern().matcher(a.toString()).matches()) {
             annotations.add(factory.typeElement(a));
diff --git a/java/com/google/turbine/binder/Resolve.java b/java/com/google/turbine/binder/Resolve.java
index 6b76389..918dd9a 100644
--- a/java/com/google/turbine/binder/Resolve.java
+++ b/java/com/google/turbine/binder/Resolve.java
@@ -31,7 +31,7 @@ import com.google.turbine.tree.Tree;
 import java.util.HashSet;
 import java.util.Objects;
 import java.util.Set;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Qualified name resolution. */
 public final class Resolve {
@@ -101,6 +101,12 @@ public final class Resolve {
           return null;
         }
       }
+
+      @Override
+      public boolean visible(ClassSymbol sym) {
+        String packageName = origin != null ? origin.packageName() : null;
+        return importVisible(env, sym, packageName);
+      }
     };
   }
 
@@ -131,18 +137,23 @@ public final class Resolve {
 
     @Override
     public boolean visible(ClassSymbol sym) {
-      TurbineVisibility visibility = TurbineVisibility.fromAccess(env.getNonNull(sym).access());
-      switch (visibility) {
-        case PUBLIC:
-          return true;
-        case PROTECTED:
-        case PACKAGE:
-          return Objects.equals(sym.packageName(), packagename);
-        case PRIVATE:
-          return false;
-      }
-      throw new AssertionError(visibility);
+      return importVisible(env, sym, packagename);
+    }
+  }
+
+  private static boolean importVisible(
+      Env<ClassSymbol, ? extends BoundClass> env, ClassSymbol sym, @Nullable String packagename) {
+    TurbineVisibility visibility = TurbineVisibility.fromAccess(env.getNonNull(sym).access());
+    switch (visibility) {
+      case PUBLIC:
+        return true;
+      case PROTECTED:
+      case PACKAGE:
+        return Objects.equals(sym.packageName(), packagename);
+      case PRIVATE:
+        return false;
     }
+    throw new AssertionError(visibility);
   }
 
   /**
diff --git a/java/com/google/turbine/binder/TypeBinder.java b/java/com/google/turbine/binder/TypeBinder.java
index ec579e7..03c775f 100644
--- a/java/com/google/turbine/binder/TypeBinder.java
+++ b/java/com/google/turbine/binder/TypeBinder.java
@@ -68,7 +68,7 @@ import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Type binding. */
 public class TypeBinder {
@@ -235,10 +235,15 @@ public class TypeBinder {
     ImmutableList.Builder<ClassSymbol> permits = ImmutableList.builder();
     for (Tree.ClassTy i : base.decl().permits()) {
       Type type = bindClassTy(bindingScope, i);
-      if (!type.tyKind().equals(Type.TyKind.CLASS_TY)) {
-        throw new AssertionError(type.tyKind());
+      switch (type.tyKind()) {
+        case ERROR_TY:
+          continue;
+        case CLASS_TY:
+          permits.add(((Type.ClassTy) type).sym());
+          break;
+        default:
+          throw new AssertionError(type.tyKind());
       }
-      permits.add(((Type.ClassTy) type).sym());
     }
 
     CompoundScope scope =
@@ -297,6 +302,10 @@ public class TypeBinder {
     boolean hasEquals = false;
     boolean hasHashCode = false;
     boolean hasPrimaryConstructor = false;
+    Set<String> componentNamesToDeclare = new HashSet<>();
+    for (RecordComponentInfo c : components) {
+      componentNamesToDeclare.add(c.name());
+    }
     for (MethodInfo m : boundMethods) {
       if (m.name().equals("<init>")) {
         if (isPrimaryConstructor(m, components)) {
@@ -316,7 +325,10 @@ public class TypeBinder {
           case "hashCode":
             hasHashCode = m.parameters().isEmpty();
             break;
-          default: // fall out
+          default:
+            if (m.parameters().isEmpty()) {
+              componentNamesToDeclare.remove(m.name());
+            }
         }
         boundNonConstructors.add(m);
       }
@@ -378,6 +390,9 @@ public class TypeBinder {
               null));
     }
     for (RecordComponentInfo c : components) {
+      if (!componentNamesToDeclare.contains(c.name())) {
+        continue;
+      }
       MethodSymbol componentMethod = syntheticMethods.create(owner, c.name());
       methods.add(
           new MethodInfo(
@@ -956,7 +971,7 @@ public class TypeBinder {
     LookupResult result = scope.lookup(new LookupKey(names));
     if (result == null || result.sym() == null) {
       log.error(names.get(0).position(), ErrorKind.CANNOT_RESOLVE, Joiner.on('.').join(names));
-      return Type.ErrorTy.create(names);
+      return Type.ErrorTy.create(names, bindTyArgs(scope, t.tyargs()));
     }
     Symbol sym = result.sym();
     int annoIdx = flat.size() - result.remaining().size() - 1;
@@ -968,7 +983,7 @@ public class TypeBinder {
       case TY_PARAM:
         if (!result.remaining().isEmpty()) {
           log.error(t.position(), ErrorKind.TYPE_PARAMETER_QUALIFIER);
-          return Type.ErrorTy.create(names);
+          return Type.ErrorTy.create(names, ImmutableList.of());
         }
         return Type.TyVar.create((TyVarSymbol) sym, annos);
       default:
@@ -991,14 +1006,14 @@ public class TypeBinder {
     for (; idx < flat.size(); idx++) {
       Tree.ClassTy curr = flat.get(idx);
       ClassSymbol next = resolveNext(sym, curr.name());
+      ImmutableList<Type> targs = bindTyArgs(scope, curr.tyargs());
       if (next == null) {
-        return Type.ErrorTy.create(bits);
+        return Type.ErrorTy.create(bits, targs);
       }
       sym = next;
 
       annotations = bindAnnotations(scope, curr.annos());
-      classes.add(
-          Type.ClassTy.SimpleClassTy.create(sym, bindTyArgs(scope, curr.tyargs()), annotations));
+      classes.add(Type.ClassTy.SimpleClassTy.create(sym, targs, annotations));
     }
     return Type.ClassTy.create(classes.build());
   }
diff --git a/java/com/google/turbine/binder/bound/AnnotationMetadata.java b/java/com/google/turbine/binder/bound/AnnotationMetadata.java
index 5ae04b0..314f5c7 100644
--- a/java/com/google/turbine/binder/bound/AnnotationMetadata.java
+++ b/java/com/google/turbine/binder/bound/AnnotationMetadata.java
@@ -23,7 +23,7 @@ import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.model.TurbineElementType;
 import java.lang.annotation.RetentionPolicy;
 import java.util.EnumSet;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Annotation metadata, e.g. from {@link java.lang.annotation.Target}, {@link
diff --git a/java/com/google/turbine/binder/bound/BoundClass.java b/java/com/google/turbine/binder/bound/BoundClass.java
index 1e29b42..91af14f 100644
--- a/java/com/google/turbine/binder/bound/BoundClass.java
+++ b/java/com/google/turbine/binder/bound/BoundClass.java
@@ -19,7 +19,7 @@ package com.google.turbine.binder.bound;
 import com.google.common.collect.ImmutableMap;
 import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.model.TurbineTyKind;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * The initial bound tree representation.
@@ -32,8 +32,7 @@ public interface BoundClass {
   TurbineTyKind kind();
 
   /** The enclosing declaration for member types, or {@code null} for top-level declarations. */
-  @Nullable
-  ClassSymbol owner();
+  @Nullable ClassSymbol owner();
 
   /** Class access bits (see JVMS table 4.1). */
   int access();
diff --git a/java/com/google/turbine/binder/bound/EnumConstantValue.java b/java/com/google/turbine/binder/bound/EnumConstantValue.java
index 20a5756..6e6d3a6 100644
--- a/java/com/google/turbine/binder/bound/EnumConstantValue.java
+++ b/java/com/google/turbine/binder/bound/EnumConstantValue.java
@@ -18,7 +18,7 @@ package com.google.turbine.binder.bound;
 
 import com.google.turbine.binder.sym.FieldSymbol;
 import com.google.turbine.model.Const;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** An enum constant. */
 public class EnumConstantValue extends Const {
diff --git a/java/com/google/turbine/binder/bound/HeaderBoundClass.java b/java/com/google/turbine/binder/bound/HeaderBoundClass.java
index 9658016..4639850 100644
--- a/java/com/google/turbine/binder/bound/HeaderBoundClass.java
+++ b/java/com/google/turbine/binder/bound/HeaderBoundClass.java
@@ -20,13 +20,12 @@ import com.google.common.collect.ImmutableList;
 import com.google.common.collect.ImmutableMap;
 import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.binder.sym.TyVarSymbol;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A bound node that augments {@link BoundClass} with superclasses and interfaces. */
 public interface HeaderBoundClass extends BoundClass {
   /** The superclass of the declaration. */
-  @Nullable
-  ClassSymbol superclass();
+  @Nullable ClassSymbol superclass();
 
   /** The interfaces of the declaration. */
   ImmutableList<ClassSymbol> interfaces();
diff --git a/java/com/google/turbine/binder/bound/ModuleInfo.java b/java/com/google/turbine/binder/bound/ModuleInfo.java
index 5dc8720..4ff6f1a 100644
--- a/java/com/google/turbine/binder/bound/ModuleInfo.java
+++ b/java/com/google/turbine/binder/bound/ModuleInfo.java
@@ -19,7 +19,7 @@ package com.google.turbine.binder.bound;
 import com.google.common.collect.ImmutableList;
 import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.type.AnnoInfo;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A bound module declaration (see JLS §7.7). */
 public class ModuleInfo {
diff --git a/java/com/google/turbine/binder/bound/PackageSourceBoundClass.java b/java/com/google/turbine/binder/bound/PackageSourceBoundClass.java
index 77832f9..57cadb2 100644
--- a/java/com/google/turbine/binder/bound/PackageSourceBoundClass.java
+++ b/java/com/google/turbine/binder/bound/PackageSourceBoundClass.java
@@ -23,7 +23,7 @@ import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.diag.SourceFile;
 import com.google.turbine.model.TurbineTyKind;
 import com.google.turbine.tree.Tree;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A {@link BoundClass} with shared lookup scopes for the current compilation unit and package. */
 public class PackageSourceBoundClass implements BoundClass {
diff --git a/java/com/google/turbine/binder/bound/SourceBoundClass.java b/java/com/google/turbine/binder/bound/SourceBoundClass.java
index 7a6f33f..9051e22 100644
--- a/java/com/google/turbine/binder/bound/SourceBoundClass.java
+++ b/java/com/google/turbine/binder/bound/SourceBoundClass.java
@@ -20,7 +20,7 @@ import com.google.common.collect.ImmutableMap;
 import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.model.TurbineTyKind;
 import com.google.turbine.tree.Tree;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A {@link BoundClass} that corresponds to a source file being compiled. */
 public class SourceBoundClass implements BoundClass {
diff --git a/java/com/google/turbine/binder/bound/SourceHeaderBoundClass.java b/java/com/google/turbine/binder/bound/SourceHeaderBoundClass.java
index 210ff0b..51c8f41 100644
--- a/java/com/google/turbine/binder/bound/SourceHeaderBoundClass.java
+++ b/java/com/google/turbine/binder/bound/SourceHeaderBoundClass.java
@@ -25,7 +25,7 @@ import com.google.turbine.binder.sym.TyVarSymbol;
 import com.google.turbine.diag.SourceFile;
 import com.google.turbine.model.TurbineTyKind;
 import com.google.turbine.tree.Tree;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A {@link HeaderBoundClass} that corresponds to a source file being compiled. */
 public class SourceHeaderBoundClass implements HeaderBoundClass {
diff --git a/java/com/google/turbine/binder/bound/SourceModuleInfo.java b/java/com/google/turbine/binder/bound/SourceModuleInfo.java
index 66ba0e4..c1b88fb 100644
--- a/java/com/google/turbine/binder/bound/SourceModuleInfo.java
+++ b/java/com/google/turbine/binder/bound/SourceModuleInfo.java
@@ -24,7 +24,7 @@ import com.google.turbine.binder.bound.ModuleInfo.RequireInfo;
 import com.google.turbine.binder.bound.ModuleInfo.UseInfo;
 import com.google.turbine.diag.SourceFile;
 import com.google.turbine.type.AnnoInfo;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A {@link ModuleInfo} that corresponds to a source file being compiled. */
 public class SourceModuleInfo extends ModuleInfo {
diff --git a/java/com/google/turbine/binder/bound/SourceTypeBoundClass.java b/java/com/google/turbine/binder/bound/SourceTypeBoundClass.java
index 5e9817e..1484daf 100644
--- a/java/com/google/turbine/binder/bound/SourceTypeBoundClass.java
+++ b/java/com/google/turbine/binder/bound/SourceTypeBoundClass.java
@@ -29,7 +29,7 @@ import com.google.turbine.type.AnnoInfo;
 import com.google.turbine.type.Type;
 import com.google.turbine.type.Type.ClassTy;
 import com.google.turbine.type.Type.TyKind;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A HeaderBoundClass for classes compiled from source. */
 public class SourceTypeBoundClass implements TypeBoundClass {
diff --git a/java/com/google/turbine/binder/bound/TurbineAnnotationValue.java b/java/com/google/turbine/binder/bound/TurbineAnnotationValue.java
index b6737d6..fcfd91e 100644
--- a/java/com/google/turbine/binder/bound/TurbineAnnotationValue.java
+++ b/java/com/google/turbine/binder/bound/TurbineAnnotationValue.java
@@ -20,7 +20,7 @@ import com.google.common.collect.ImmutableMap;
 import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.model.Const;
 import com.google.turbine.type.AnnoInfo;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** An annotation literal constant. */
 public class TurbineAnnotationValue extends Const {
diff --git a/java/com/google/turbine/binder/bound/TurbineClassValue.java b/java/com/google/turbine/binder/bound/TurbineClassValue.java
index c6ba6ef..d38f708 100644
--- a/java/com/google/turbine/binder/bound/TurbineClassValue.java
+++ b/java/com/google/turbine/binder/bound/TurbineClassValue.java
@@ -19,7 +19,7 @@ package com.google.turbine.binder.bound;
 import com.google.turbine.model.Const;
 import com.google.turbine.type.Type;
 import java.util.Objects;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A class literal constant. */
 public class TurbineClassValue extends Const {
diff --git a/java/com/google/turbine/binder/bound/TypeBoundClass.java b/java/com/google/turbine/binder/bound/TypeBoundClass.java
index 8321bde..5af0b85 100644
--- a/java/com/google/turbine/binder/bound/TypeBoundClass.java
+++ b/java/com/google/turbine/binder/bound/TypeBoundClass.java
@@ -32,14 +32,13 @@ import com.google.turbine.type.AnnoInfo;
 import com.google.turbine.type.Type;
 import com.google.turbine.type.Type.IntersectionTy;
 import com.google.turbine.type.Type.MethodTy;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A bound node that augments {@link HeaderBoundClass} with type information. */
 public interface TypeBoundClass extends HeaderBoundClass {
 
   /** The super-class type. */
-  @Nullable
-  Type superClassType();
+  @Nullable Type superClassType();
 
   /** Implemented interface types. */
   ImmutableList<Type> interfaceTypes();
@@ -62,8 +61,7 @@ public interface TypeBoundClass extends HeaderBoundClass {
    * Annotation metadata, e.g. from {@link java.lang.annotation.Target}, {@link
    * java.lang.annotation.Retention}, and {@link java.lang.annotation.Repeatable}.
    */
-  @Nullable
-  AnnotationMetadata annotationMetadata();
+  @Nullable AnnotationMetadata annotationMetadata();
 
   /** Declaration annotations. */
   ImmutableList<AnnoInfo> annotations();
diff --git a/java/com/google/turbine/binder/bound/package-info.java b/java/com/google/turbine/binder/bound/package-info.java
index 8839101..d70d7ff 100644
--- a/java/com/google/turbine/binder/bound/package-info.java
+++ b/java/com/google/turbine/binder/bound/package-info.java
@@ -15,5 +15,5 @@
  */
 
 @com.google.errorprone.annotations.CheckReturnValue
-@org.jspecify.nullness.NullMarked
+@org.jspecify.annotations.NullMarked
 package com.google.turbine.binder.bound;
diff --git a/java/com/google/turbine/binder/bytecode/BytecodeBinder.java b/java/com/google/turbine/binder/bytecode/BytecodeBinder.java
index 82f8a8c..4a58467 100644
--- a/java/com/google/turbine/binder/bytecode/BytecodeBinder.java
+++ b/java/com/google/turbine/binder/bytecode/BytecodeBinder.java
@@ -19,7 +19,9 @@ package com.google.turbine.binder.bytecode;
 import static java.util.Objects.requireNonNull;
 
 import com.google.common.collect.ImmutableList;
+import com.google.common.collect.ImmutableListMultimap;
 import com.google.common.collect.ImmutableMap;
+import com.google.common.collect.Iterables;
 import com.google.turbine.binder.bound.EnumConstantValue;
 import com.google.turbine.binder.bound.ModuleInfo;
 import com.google.turbine.binder.bound.TurbineAnnotationValue;
@@ -34,6 +36,7 @@ import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue.ArrayVa
 import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue.ConstTurbineClassValue;
 import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue.ConstValue;
 import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue.EnumConstValue;
+import com.google.turbine.bytecode.ClassFile.TypeAnnotationInfo;
 import com.google.turbine.bytecode.ClassReader;
 import com.google.turbine.bytecode.sig.Sig;
 import com.google.turbine.bytecode.sig.Sig.LowerBoundTySig;
@@ -45,105 +48,225 @@ import com.google.turbine.model.Const.ArrayInitValue;
 import com.google.turbine.model.Const.Value;
 import com.google.turbine.type.AnnoInfo;
 import com.google.turbine.type.Type;
+import java.util.ArrayDeque;
 import java.util.ArrayList;
+import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
-import java.util.function.Function;
 import java.util.function.Supplier;
+import org.jspecify.annotations.Nullable;
 
 /** Bind {@link Type}s from bytecode. */
 public final class BytecodeBinder {
 
-  static Type.ClassTy bindClassTy(Sig.ClassTySig sig, Function<String, TyVarSymbol> scope) {
-    StringBuilder sb = new StringBuilder(sig.pkg());
+  /** Context that is required to create types from type signatures in bytecode. */
+  interface Scope {
+    /** Look up a type variable by name on an enclosing method or class. */
+    TyVarSymbol apply(String input);
+
+    /**
+     * Returns the enclosing class for a nested class, or {@code null}.
+     *
+     * <p>Locating type annotations on nested classes requires knowledge of their enclosing types.
+     */
+    @Nullable ClassSymbol outer(ClassSymbol sym);
+  }
+
+  public static Type.ClassTy bindClassTy(
+      Sig.ClassTySig sig, Scope scope, ImmutableList<TypeAnnotationInfo> annotations) {
+    return bindClassTy(
+        sig, scope, typeAnnotationsByPath(annotations, scope), TypeAnnotationInfo.TypePath.root());
+  }
+
+  private static Type.ClassTy bindClassTy(
+      Sig.ClassTySig sig,
+      Scope scope,
+      ImmutableListMultimap<TypeAnnotationInfo.TypePath, AnnoInfo> annotations,
+      TypeAnnotationInfo.TypePath typePath) {
+    StringBuilder sb = new StringBuilder();
+    if (!sig.pkg().isEmpty()) {
+      sb.append(sig.pkg()).append('/');
+    }
     boolean first = true;
-    List<Type.ClassTy.SimpleClassTy> classes = new ArrayList<>();
+    Map<ClassSymbol, Sig.SimpleClassTySig> syms = new LinkedHashMap<>();
     for (Sig.SimpleClassTySig s : sig.classes()) {
-      sb.append(first ? '/' : '$');
+      if (!first) {
+        sb.append('$');
+      }
       sb.append(s.simpleName());
       ClassSymbol sym = new ClassSymbol(sb.toString());
-
+      syms.put(sym, s);
+      first = false;
+    }
+    ArrayDeque<ClassSymbol> outers = new ArrayDeque<>();
+    for (ClassSymbol curr = Iterables.getLast(syms.keySet());
+        curr != null;
+        curr = scope.outer(curr)) {
+      outers.addFirst(curr);
+    }
+    List<Type.ClassTy.SimpleClassTy> classes = new ArrayList<>();
+    for (ClassSymbol curr : outers) {
       ImmutableList.Builder<Type> tyArgs = ImmutableList.builder();
-      for (Sig.TySig arg : s.tyArgs()) {
-        tyArgs.add(bindTy(arg, scope));
+      Sig.SimpleClassTySig s = syms.get(curr);
+      if (s != null) {
+        for (int i = 0; i < s.tyArgs().size(); i++) {
+          tyArgs.add(bindTy(s.tyArgs().get(i), scope, annotations, typePath.typeArgument(i)));
+        }
       }
-
-      classes.add(Type.ClassTy.SimpleClassTy.create(sym, tyArgs.build(), ImmutableList.of()));
-      first = false;
+      classes.add(
+          Type.ClassTy.SimpleClassTy.create(curr, tyArgs.build(), annotations.get(typePath)));
+      typePath = typePath.nested();
     }
     return Type.ClassTy.create(classes);
   }
 
-  private static Type wildTy(WildTySig sig, Function<String, TyVarSymbol> scope) {
+  private static Type wildTy(
+      WildTySig sig,
+      Scope scope,
+      ImmutableListMultimap<TypeAnnotationInfo.TypePath, AnnoInfo> annotations,
+      TypeAnnotationInfo.TypePath typePath) {
     switch (sig.boundKind()) {
       case NONE:
-        return Type.WildUnboundedTy.create(ImmutableList.of());
+        return Type.WildUnboundedTy.create(annotations.get(typePath));
       case LOWER:
         return Type.WildLowerBoundedTy.create(
-            bindTy(((LowerBoundTySig) sig).bound(), scope), ImmutableList.of());
+            bindTy(((LowerBoundTySig) sig).bound(), scope, annotations, typePath.wild()),
+            annotations.get(typePath));
       case UPPER:
         return Type.WildUpperBoundedTy.create(
-            bindTy(((UpperBoundTySig) sig).bound(), scope), ImmutableList.of());
+            bindTy(((UpperBoundTySig) sig).bound(), scope, annotations, typePath.wild()),
+            annotations.get(typePath));
     }
     throw new AssertionError(sig.boundKind());
   }
 
-  static Type bindTy(Sig.TySig sig, Function<String, TyVarSymbol> scope) {
+  public static Type bindTy(
+      Sig.TySig sig, Scope scope, ImmutableList<TypeAnnotationInfo> annotations) {
+    return bindTy(
+        sig, scope, typeAnnotationsByPath(annotations, scope), TypeAnnotationInfo.TypePath.root());
+  }
+
+  static Type bindTy(
+      Sig.TySig sig,
+      Scope scope,
+      ImmutableListMultimap<TypeAnnotationInfo.TypePath, AnnoInfo> annotations,
+      TypeAnnotationInfo.TypePath typePath) {
     switch (sig.kind()) {
       case BASE_TY_SIG:
-        return Type.PrimTy.create(((Sig.BaseTySig) sig).type(), ImmutableList.of());
+        return Type.PrimTy.create(((Sig.BaseTySig) sig).type(), annotations.get(typePath));
       case CLASS_TY_SIG:
-        return bindClassTy((Sig.ClassTySig) sig, scope);
+        return bindClassTy((Sig.ClassTySig) sig, scope, annotations, typePath);
       case TY_VAR_SIG:
-        return Type.TyVar.create(scope.apply(((Sig.TyVarSig) sig).name()), ImmutableList.of());
+        return Type.TyVar.create(
+            scope.apply(((Sig.TyVarSig) sig).name()), annotations.get(typePath));
       case ARRAY_TY_SIG:
-        return bindArrayTy((Sig.ArrayTySig) sig, scope);
+        return bindArrayTy((Sig.ArrayTySig) sig, scope, annotations, typePath);
       case WILD_TY_SIG:
-        return wildTy((WildTySig) sig, scope);
+        return wildTy((WildTySig) sig, scope, annotations, typePath);
       case VOID_TY_SIG:
         return Type.VOID;
     }
     throw new AssertionError(sig.kind());
   }
 
-  private static Type bindArrayTy(Sig.ArrayTySig arrayTySig, Function<String, TyVarSymbol> scope) {
-    return Type.ArrayTy.create(bindTy(arrayTySig.elementType(), scope), ImmutableList.of());
+  private static Type bindArrayTy(
+      Sig.ArrayTySig arrayTySig,
+      Scope scope,
+      ImmutableListMultimap<TypeAnnotationInfo.TypePath, AnnoInfo> annotations,
+      TypeAnnotationInfo.TypePath typePath) {
+    return Type.ArrayTy.create(
+        bindTy(arrayTySig.elementType(), scope, annotations, typePath.array()),
+        annotations.get(typePath));
   }
 
-  public static Const bindValue(ElementValue value) {
+  private static ImmutableListMultimap<TypeAnnotationInfo.TypePath, AnnoInfo> typeAnnotationsByPath(
+      ImmutableList<TypeAnnotationInfo> typeAnnotations, Scope scope) {
+    if (typeAnnotations.isEmpty()) {
+      return ImmutableListMultimap.of();
+    }
+    ImmutableListMultimap.Builder<TypeAnnotationInfo.TypePath, AnnoInfo> result =
+        ImmutableListMultimap.builder();
+    for (TypeAnnotationInfo typeAnnotation : typeAnnotations) {
+      result.put(typeAnnotation.path(), bindAnnotationValue(typeAnnotation.anno(), scope).info());
+    }
+    return result.build();
+  }
+
+  /**
+   * Similar to {@link Type.ClassTy#asNonParametricClassTy}, but handles any provided type
+   * annotations and attaches them to the corresponding {@link Type.ClassTy.SimpleClassTy}.
+   */
+  public static Type.ClassTy asNonParametricClassTy(
+      ClassSymbol sym, ImmutableList<TypeAnnotationInfo> annotations, Scope scope) {
+    return asNonParametricClassTy(sym, scope, typeAnnotationsByPath(annotations, scope));
+  }
+
+  private static Type.ClassTy asNonParametricClassTy(
+      ClassSymbol sym,
+      Scope scope,
+      ImmutableListMultimap<TypeAnnotationInfo.TypePath, AnnoInfo> annotations) {
+    if (annotations.isEmpty()) {
+      // fast path if there are no type annotations
+      return Type.ClassTy.asNonParametricClassTy(sym);
+    }
+    ArrayDeque<ClassSymbol> outers = new ArrayDeque<>();
+    for (ClassSymbol curr = sym; curr != null; curr = scope.outer(curr)) {
+      outers.addFirst(curr);
+    }
+    List<Type.ClassTy.SimpleClassTy> classes = new ArrayList<>();
+    TypeAnnotationInfo.TypePath typePath = TypeAnnotationInfo.TypePath.root();
+    for (ClassSymbol curr : outers) {
+      classes.add(
+          Type.ClassTy.SimpleClassTy.create(curr, ImmutableList.of(), annotations.get(typePath)));
+      typePath = typePath.nested();
+    }
+    return Type.ClassTy.create(classes);
+  }
+
+  public static Const bindValue(ElementValue value, Scope scope) {
     switch (value.kind()) {
       case ENUM:
         return bindEnumValue((EnumConstValue) value);
       case CONST:
         return ((ConstValue) value).value();
       case ARRAY:
-        return bindArrayValue((ArrayValue) value);
+        return bindArrayValue((ArrayValue) value, scope);
       case CLASS:
         return new TurbineClassValue(
             bindTy(
                 new SigParser(((ConstTurbineClassValue) value).className()).parseType(),
-                x -> {
-                  throw new IllegalStateException(x);
-                }));
+                new Scope() {
+                  @Override
+                  public TyVarSymbol apply(String x) {
+                    throw new IllegalStateException(x);
+                  }
+
+                  @Override
+                  public @Nullable ClassSymbol outer(ClassSymbol sym) {
+                    return scope.outer(sym);
+                  }
+                },
+                /* annotations= */ ImmutableList.of()));
       case ANNOTATION:
-        return bindAnnotationValue(((ElementValue.ConstTurbineAnnotationValue) value).annotation());
+        return bindAnnotationValue(
+            ((ElementValue.ConstTurbineAnnotationValue) value).annotation(), scope);
     }
     throw new AssertionError(value.kind());
   }
 
-  static TurbineAnnotationValue bindAnnotationValue(AnnotationInfo value) {
+  static TurbineAnnotationValue bindAnnotationValue(AnnotationInfo value, Scope scope) {
     ClassSymbol sym = asClassSymbol(value.typeName());
     ImmutableMap.Builder<String, Const> values = ImmutableMap.builder();
     for (Map.Entry<String, ElementValue> e : value.elementValuePairs().entrySet()) {
-      values.put(e.getKey(), bindValue(e.getValue()));
+      values.put(e.getKey(), bindValue(e.getValue(), scope));
     }
     return new TurbineAnnotationValue(new AnnoInfo(null, sym, null, values.buildOrThrow()));
   }
 
-  static ImmutableList<AnnoInfo> bindAnnotations(List<AnnotationInfo> input) {
+  static ImmutableList<AnnoInfo> bindAnnotations(List<AnnotationInfo> input, Scope scope) {
     ImmutableList.Builder<AnnoInfo> result = ImmutableList.builder();
     for (AnnotationInfo annotation : input) {
-      TurbineAnnotationValue anno = bindAnnotationValue(annotation);
+      TurbineAnnotationValue anno = bindAnnotationValue(annotation, scope);
       if (!shouldSkip(anno)) {
         result.add(anno.info());
       }
@@ -161,10 +284,10 @@ public final class BytecodeBinder {
     return new ClassSymbol(s.substring(1, s.length() - 1));
   }
 
-  private static Const bindArrayValue(ArrayValue value) {
+  private static Const bindArrayValue(ArrayValue value, Scope scope) {
     ImmutableList.Builder<Const> elements = ImmutableList.builder();
     for (ElementValue element : value.elements()) {
-      elements.add(bindValue(element));
+      elements.add(bindValue(element, scope));
     }
     return new ArrayInitValue(elements.build());
   }
@@ -173,16 +296,15 @@ public final class BytecodeBinder {
     if (type.tyKind() != Type.TyKind.PRIM_TY) {
       return value;
     }
-    // Deficient numberic types and booleans are all stored as ints in the class file,
+    // Deficient numeric types and booleans are all stored as ints in the class file,
     // coerce them to the target type.
-    // TODO(b/32626659): this is not bug-compatible with javac
     switch (((Type.PrimTy) type).primkind()) {
       case CHAR:
         return new Const.CharValue((char) asInt(value));
       case SHORT:
         return new Const.ShortValue((short) asInt(value));
       case BOOLEAN:
-        // boolean constants are encoded as integers
+        // boolean constants are encoded as integers, see also JDK-8171132
         return new Const.BooleanValue(asInt(value) != 0);
       case BYTE:
         return new Const.ByteValue((byte) asInt(value));
diff --git a/java/com/google/turbine/binder/bytecode/BytecodeBoundClass.java b/java/com/google/turbine/binder/bytecode/BytecodeBoundClass.java
index cc97dcb..05608aa 100644
--- a/java/com/google/turbine/binder/bytecode/BytecodeBoundClass.java
+++ b/java/com/google/turbine/binder/bytecode/BytecodeBoundClass.java
@@ -18,6 +18,7 @@ package com.google.turbine.binder.bytecode;
 
 import static com.google.common.base.MoreObjects.firstNonNull;
 import static com.google.common.base.Verify.verify;
+import static com.google.turbine.binder.bytecode.BytecodeBinder.asNonParametricClassTy;
 import static java.util.Objects.requireNonNull;
 
 import com.google.common.base.Supplier;
@@ -32,6 +33,7 @@ import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.binder.sym.FieldSymbol;
 import com.google.turbine.binder.sym.MethodSymbol;
 import com.google.turbine.binder.sym.ParamSymbol;
+import com.google.turbine.binder.sym.RecordComponentSymbol;
 import com.google.turbine.binder.sym.TyVarSymbol;
 import com.google.turbine.bytecode.ClassFile;
 import com.google.turbine.bytecode.ClassFile.AnnotationInfo;
@@ -41,11 +43,13 @@ import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue.ConstTu
 import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue.EnumConstValue;
 import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue.Kind;
 import com.google.turbine.bytecode.ClassFile.MethodInfo.ParameterInfo;
+import com.google.turbine.bytecode.ClassFile.RecordInfo;
+import com.google.turbine.bytecode.ClassFile.TypeAnnotationInfo;
+import com.google.turbine.bytecode.ClassFile.TypeAnnotationInfo.TargetType;
 import com.google.turbine.bytecode.ClassReader;
 import com.google.turbine.bytecode.sig.Sig;
 import com.google.turbine.bytecode.sig.Sig.ClassSig;
 import com.google.turbine.bytecode.sig.Sig.ClassTySig;
-import com.google.turbine.bytecode.sig.Sig.TySig;
 import com.google.turbine.bytecode.sig.SigParser;
 import com.google.turbine.model.Const;
 import com.google.turbine.model.TurbineElementType;
@@ -56,9 +60,10 @@ import com.google.turbine.type.Type;
 import com.google.turbine.type.Type.ClassTy;
 import com.google.turbine.type.Type.IntersectionTy;
 import java.lang.annotation.RetentionPolicy;
+import java.nio.file.Path;
+import java.util.List;
 import java.util.Map;
-import java.util.function.Function;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A bound class backed by a class file.
@@ -70,6 +75,20 @@ import org.jspecify.nullness.Nullable;
  */
 public class BytecodeBoundClass implements TypeBoundClass {
 
+  public static Supplier<BytecodeBoundClass> lazy(
+      ClassSymbol sym,
+      Supplier<byte[]> bytes,
+      Env<ClassSymbol, BytecodeBoundClass> env,
+      Path path) {
+    return Suppliers.memoize(
+        new Supplier<BytecodeBoundClass>() {
+          @Override
+          public BytecodeBoundClass get() {
+            return new BytecodeBoundClass(sym, bytes, env, path.toString());
+          }
+        });
+  }
+
   private final ClassSymbol sym;
   private final Env<ClassSymbol, BytecodeBoundClass> env;
   private final Supplier<ClassFile> classFile;
@@ -265,11 +284,14 @@ public class BytecodeBoundClass implements TypeBoundClass {
               if (superclass() == null) {
                 return null;
               }
+              ImmutableList<TypeAnnotationInfo> typeAnnotations =
+                  typeAnnotationsForSupertype(65535);
               if (sig.get() == null || sig.get().superClass() == null) {
-                return ClassTy.asNonParametricClassTy(superclass());
+                return asNonParametricClassTy(
+                    superclass(), typeAnnotations, makeScope(env, sym, ImmutableMap.of()));
               }
               return BytecodeBinder.bindClassTy(
-                  sig.get().superClass(), makeScope(env, sym, ImmutableMap.of()));
+                  sig.get().superClass(), makeScope(env, sym, ImmutableMap.of()), typeAnnotations);
             }
           });
 
@@ -283,18 +305,24 @@ public class BytecodeBoundClass implements TypeBoundClass {
           new Supplier<ImmutableList<Type>>() {
             @Override
             public ImmutableList<Type> get() {
-              if (interfaces().isEmpty()) {
+              ImmutableList<ClassSymbol> interfaces = interfaces();
+              if (interfaces.isEmpty()) {
                 return ImmutableList.of();
               }
               ImmutableList.Builder<Type> result = ImmutableList.builder();
-              if (sig.get() == null || sig.get().interfaces() == null) {
-                for (ClassSymbol sym : interfaces()) {
-                  result.add(ClassTy.asNonParametricClassTy(sym));
+              BytecodeBinder.Scope scope = makeScope(env, sym, ImmutableMap.of());
+              ImmutableList<ClassTySig> sigs = sig.get() == null ? null : sig.get().interfaces();
+              if (sigs == null) {
+                for (int i = 0; i < interfaces.size(); i++) {
+                  result.add(
+                      asNonParametricClassTy(
+                          interfaces.get(i), typeAnnotationsForSupertype(i), scope));
                 }
               } else {
-                Function<String, TyVarSymbol> scope = makeScope(env, sym, ImmutableMap.of());
-                for (ClassTySig classTySig : sig.get().interfaces()) {
-                  result.add(BytecodeBinder.bindClassTy(classTySig, scope));
+                for (int i = 0; i < sigs.size(); i++) {
+                  result.add(
+                      BytecodeBinder.bindClassTy(
+                          sigs.get(i), scope, typeAnnotationsForSupertype(i)));
                 }
               }
               return result.build();
@@ -319,26 +347,87 @@ public class BytecodeBoundClass implements TypeBoundClass {
               if (sig.get() == null) {
                 return ImmutableMap.of();
               }
-              ImmutableMap.Builder<TyVarSymbol, TyVarInfo> tparams = ImmutableMap.builder();
-              Function<String, TyVarSymbol> scope = makeScope(env, sym, typeParameters());
-              for (Sig.TyParamSig p : sig.get().tyParams()) {
-                // typeParameters() is constructed to guarantee the requireNonNull call is safe.
-                tparams.put(requireNonNull(typeParameters().get(p.name())), bindTyParam(p, scope));
-              }
-              return tparams.buildOrThrow();
+              BytecodeBinder.Scope scope = makeScope(env, sym, typeParameters());
+              return bindTypeParams(
+                  sig.get().tyParams(),
+                  typeParameters(),
+                  scope,
+                  TargetType.CLASS_TYPE_PARAMETER,
+                  TargetType.CLASS_TYPE_PARAMETER_BOUND,
+                  classFile.get().typeAnnotations());
             }
           });
 
-  private static TyVarInfo bindTyParam(Sig.TyParamSig sig, Function<String, TyVarSymbol> scope) {
+  private static ImmutableMap<TyVarSymbol, TyVarInfo> bindTypeParams(
+      ImmutableList<Sig.TyParamSig> tyParamSigs,
+      ImmutableMap<String, TyVarSymbol> tyParams,
+      BytecodeBinder.Scope scope,
+      TargetType typeParameterTarget,
+      TargetType typeParameterBoundTarget,
+      ImmutableList<TypeAnnotationInfo> typeAnnotations) {
+    ImmutableMap.Builder<TyVarSymbol, TyVarInfo> result = ImmutableMap.builder();
+    for (int i = 0; i < tyParamSigs.size(); i++) {
+      Sig.TyParamSig p = tyParamSigs.get(i);
+      // tyParams is constructed to guarantee the requireNonNull call is safe.
+      result.put(
+          requireNonNull(tyParams.get(p.name())),
+          bindTyParam(p, scope, i, typeParameterTarget, typeParameterBoundTarget, typeAnnotations));
+    }
+    return result.buildOrThrow();
+  }
+
+  private static TyVarInfo bindTyParam(
+      Sig.TyParamSig sig,
+      BytecodeBinder.Scope scope,
+      int typeParameterIndex,
+      TargetType typeParameterTarget,
+      TargetType typeParameterBoundTarget,
+      ImmutableList<TypeAnnotationInfo> typeAnnotations) {
     ImmutableList.Builder<Type> bounds = ImmutableList.builder();
     if (sig.classBound() != null) {
-      bounds.add(BytecodeBinder.bindTy(sig.classBound(), scope));
+      bounds.add(
+          BytecodeBinder.bindTy(
+              sig.classBound(),
+              scope,
+              typeAnnotationsForTarget(
+                  typeAnnotations,
+                  typeParameterBoundTarget,
+                  TypeAnnotationInfo.TypeParameterBoundTarget.create(typeParameterIndex, 0))));
     }
+    int boundIndex = 1;
     for (Sig.TySig t : sig.interfaceBounds()) {
-      bounds.add(BytecodeBinder.bindTy(t, scope));
+      bounds.add(
+          BytecodeBinder.bindTy(
+              t,
+              scope,
+              typeAnnotationsForTarget(
+                  typeAnnotations,
+                  typeParameterBoundTarget,
+                  TypeAnnotationInfo.TypeParameterBoundTarget.create(
+                      typeParameterIndex, boundIndex++))));
     }
     return new TyVarInfo(
-        IntersectionTy.create(bounds.build()), /* lowerBound= */ null, ImmutableList.of());
+        IntersectionTy.create(bounds.build()),
+        /* lowerBound= */ null,
+        bindTyVarAnnotations(scope, typeParameterIndex, typeParameterTarget, typeAnnotations));
+  }
+
+  private static ImmutableList<AnnoInfo> bindTyVarAnnotations(
+      BytecodeBinder.Scope scope,
+      int typeParameterIndex,
+      TargetType typeParameterTarget,
+      ImmutableList<TypeAnnotationInfo> typeAnnotations) {
+    ImmutableList.Builder<AnnoInfo> result = ImmutableList.builder();
+    TypeAnnotationInfo.Target target =
+        TypeAnnotationInfo.TypeParameterTarget.create(typeParameterIndex);
+    for (TypeAnnotationInfo typeAnnotation : typeAnnotations) {
+      if (typeAnnotation.targetType().equals(typeParameterTarget)
+          && typeAnnotation.target().equals(target)
+          && typeAnnotation.path().equals(TypeAnnotationInfo.TypePath.root())) {
+        result.add(BytecodeBinder.bindAnnotationValue(typeAnnotation.anno(), scope).info());
+      }
+    }
+    return result.build();
   }
 
   @Override
@@ -357,14 +446,16 @@ public class BytecodeBoundClass implements TypeBoundClass {
                 Type type =
                     BytecodeBinder.bindTy(
                         new SigParser(firstNonNull(cfi.signature(), cfi.descriptor())).parseType(),
-                        makeScope(env, sym, ImmutableMap.of()));
+                        makeScope(env, sym, ImmutableMap.of()),
+                        typeAnnotationsForTarget(cfi.typeAnnotations(), TargetType.FIELD));
                 int access = cfi.access();
                 Const.Value value = cfi.value();
                 if (value != null) {
                   value = BytecodeBinder.bindConstValue(type, value);
                 }
                 ImmutableList<AnnoInfo> annotations =
-                    BytecodeBinder.bindAnnotations(cfi.annotations());
+                    BytecodeBinder.bindAnnotations(
+                        cfi.annotations(), makeScope(env, sym, ImmutableMap.of()));
                 fields.add(
                     new FieldInfo(fieldSym, type, access, annotations, /* decl= */ null, value));
               }
@@ -411,18 +502,24 @@ public class BytecodeBoundClass implements TypeBoundClass {
 
     ImmutableMap<TyVarSymbol, TyVarInfo> tyParamTypes;
     {
-      ImmutableMap.Builder<TyVarSymbol, TyVarInfo> tparams = ImmutableMap.builder();
-      Function<String, TyVarSymbol> scope = makeScope(env, sym, tyParams);
-      for (Sig.TyParamSig p : sig.tyParams()) {
-        // tyParams is constructed to guarantee the requireNonNull call is safe.
-        tparams.put(requireNonNull(tyParams.get(p.name())), bindTyParam(p, scope));
-      }
-      tyParamTypes = tparams.buildOrThrow();
+      BytecodeBinder.Scope scope = makeScope(env, sym, tyParams);
+      tyParamTypes =
+          bindTypeParams(
+              sig.tyParams(),
+              tyParams,
+              scope,
+              TargetType.METHOD_TYPE_PARAMETER,
+              TargetType.METHOD_TYPE_PARAMETER_BOUND,
+              m.typeAnnotations());
     }
 
-    Function<String, TyVarSymbol> scope = makeScope(env, sym, tyParams);
+    BytecodeBinder.Scope scope = makeScope(env, sym, tyParams);
 
-    Type ret = BytecodeBinder.bindTy(sig.returnType(), scope);
+    Type ret =
+        BytecodeBinder.bindTy(
+            sig.returnType(),
+            scope,
+            typeAnnotationsForTarget(m.typeAnnotations(), TargetType.METHOD_RETURN));
 
     ImmutableList.Builder<ParamInfo> formals = ImmutableList.builder();
     int idx = 0;
@@ -440,12 +537,18 @@ public class BytecodeBoundClass implements TypeBoundClass {
       }
       ImmutableList<AnnoInfo> annotations =
           (idx < m.parameterAnnotations().size())
-              ? BytecodeBinder.bindAnnotations(m.parameterAnnotations().get(idx))
+              ? BytecodeBinder.bindAnnotations(m.parameterAnnotations().get(idx), scope)
               : ImmutableList.of();
       formals.add(
           new ParamInfo(
               new ParamSymbol(methodSymbol, name),
-              BytecodeBinder.bindTy(tySig, scope),
+              BytecodeBinder.bindTy(
+                  tySig,
+                  scope,
+                  typeAnnotationsForTarget(
+                      m.typeAnnotations(),
+                      TargetType.METHOD_FORMAL_PARAMETER,
+                      TypeAnnotationInfo.FormalParameterTarget.create(idx))),
               annotations,
               access));
       idx++;
@@ -453,19 +556,27 @@ public class BytecodeBoundClass implements TypeBoundClass {
 
     ImmutableList.Builder<Type> exceptions = ImmutableList.builder();
     if (!sig.exceptions().isEmpty()) {
-      for (TySig e : sig.exceptions()) {
-        exceptions.add(BytecodeBinder.bindTy(e, scope));
+      ImmutableList<Sig.TySig> exceptionTypes = sig.exceptions();
+      for (int i = 0; i < exceptionTypes.size(); i++) {
+        exceptions.add(
+            BytecodeBinder.bindTy(
+                exceptionTypes.get(i), scope, typeAnnotationsForThrows(m.typeAnnotations(), i)));
       }
     } else {
-      for (String e : m.exceptions()) {
-        exceptions.add(ClassTy.asNonParametricClassTy(new ClassSymbol(e)));
+      List<String> exceptionTypes = m.exceptions();
+      for (int i = 0; i < m.exceptions().size(); i++) {
+        exceptions.add(
+            asNonParametricClassTy(
+                new ClassSymbol(exceptionTypes.get(i)),
+                typeAnnotationsForThrows(m.typeAnnotations(), i),
+                scope));
       }
     }
 
     Const defaultValue =
-        m.defaultValue() != null ? BytecodeBinder.bindValue(m.defaultValue()) : null;
+        m.defaultValue() != null ? BytecodeBinder.bindValue(m.defaultValue(), scope) : null;
 
-    ImmutableList<AnnoInfo> annotations = BytecodeBinder.bindAnnotations(m.annotations());
+    ImmutableList<AnnoInfo> annotations = BytecodeBinder.bindAnnotations(m.annotations(), scope);
 
     int access = m.access();
     if (((classFile.access() & TurbineFlag.ACC_INTERFACE) == TurbineFlag.ACC_INTERFACE)
@@ -473,6 +584,18 @@ public class BytecodeBoundClass implements TypeBoundClass {
       access |= TurbineFlag.ACC_DEFAULT;
     }
 
+    ParamInfo receiver = null;
+    ImmutableList<TypeAnnotationInfo> receiverAnnotations =
+        typeAnnotationsForTarget(m.typeAnnotations(), TargetType.METHOD_RECEIVER_PARAMETER);
+    if (!receiverAnnotations.isEmpty()) {
+      receiver =
+          new ParamInfo(
+              new ParamSymbol(methodSymbol, "this"),
+              BytecodeBinder.asNonParametricClassTy(sym, receiverAnnotations, scope),
+              /* annotations= */ ImmutableList.of(),
+              /* access= */ 0);
+    }
+
     return new MethodInfo(
         methodSymbol,
         tyParamTypes,
@@ -483,7 +606,7 @@ public class BytecodeBoundClass implements TypeBoundClass {
         defaultValue,
         /* decl= */ null,
         annotations,
-        /* receiver= */ null);
+        receiver);
   }
 
   @Override
@@ -491,9 +614,38 @@ public class BytecodeBoundClass implements TypeBoundClass {
     return methods.get();
   }
 
+  private final Supplier<ImmutableList<RecordComponentInfo>> components =
+      Suppliers.memoize(
+          new Supplier<ImmutableList<RecordComponentInfo>>() {
+            @Override
+            public ImmutableList<RecordComponentInfo> get() {
+              var record = classFile.get().record();
+              if (record == null) {
+                return ImmutableList.of();
+              }
+              ImmutableList.Builder<RecordComponentInfo> result = ImmutableList.builder();
+              for (RecordInfo.RecordComponentInfo component : record.recordComponents()) {
+                Type type =
+                    BytecodeBinder.bindTy(
+                        new SigParser(firstNonNull(component.signature(), component.descriptor()))
+                            .parseType(),
+                        makeScope(env, sym, ImmutableMap.of()),
+                        typeAnnotationsForTarget(component.typeAnnotations(), TargetType.FIELD));
+                result.add(
+                    new RecordComponentInfo(
+                        new RecordComponentSymbol(sym, component.name()),
+                        type,
+                        BytecodeBinder.bindAnnotations(
+                            component.annotations(), makeScope(env, sym, ImmutableMap.of())),
+                        /* access= */ 0));
+              }
+              return result.build();
+            }
+          });
+
   @Override
   public ImmutableList<RecordComponentInfo> components() {
-    return ImmutableList.of();
+    return components.get();
   }
 
   private final Supplier<@Nullable AnnotationMetadata> annotationMetadata =
@@ -594,7 +746,8 @@ public class BytecodeBoundClass implements TypeBoundClass {
           new Supplier<ImmutableList<AnnoInfo>>() {
             @Override
             public ImmutableList<AnnoInfo> get() {
-              return BytecodeBinder.bindAnnotations(classFile.get().annotations());
+              return BytecodeBinder.bindAnnotations(
+                  classFile.get().annotations(), makeScope(env, sym, ImmutableMap.of()));
             }
           });
 
@@ -603,15 +756,61 @@ public class BytecodeBoundClass implements TypeBoundClass {
     return annotations.get();
   }
 
+  private static ImmutableList<TypeAnnotationInfo> typeAnnotationsForThrows(
+      ImmutableList<TypeAnnotationInfo> typeAnnotations, int index) {
+    return typeAnnotationsForTarget(
+        typeAnnotations, TargetType.METHOD_THROWS, TypeAnnotationInfo.ThrowsTarget.create(index));
+  }
+
+  private ImmutableList<TypeAnnotationInfo> typeAnnotationsForSupertype(int index) {
+    return typeAnnotationsForTarget(
+        classFile.get().typeAnnotations(),
+        TargetType.SUPERTYPE,
+        TypeAnnotationInfo.SuperTypeTarget.create(index));
+  }
+
+  private static ImmutableList<TypeAnnotationInfo> typeAnnotationsForTarget(
+      ImmutableList<TypeAnnotationInfo> annotations, TargetType target) {
+    return typeAnnotationsForTarget(annotations, target, TypeAnnotationInfo.EMPTY_TARGET);
+  }
+
+  private static ImmutableList<TypeAnnotationInfo> typeAnnotationsForTarget(
+      ImmutableList<TypeAnnotationInfo> typeAnnotations,
+      TargetType targetType,
+      TypeAnnotationInfo.Target target) {
+    ImmutableList.Builder<TypeAnnotationInfo> result = ImmutableList.builder();
+    for (TypeAnnotationInfo typeAnnotation : typeAnnotations) {
+      if (typeAnnotation.targetType().equals(targetType)
+          && typeAnnotation.target().equals(target)) {
+        result.add(typeAnnotation);
+      }
+    }
+    return result.build();
+  }
+
+  private final Supplier<ImmutableMap<ClassSymbol, ClassFile.InnerClass>> innerClasses =
+      Suppliers.memoize(
+          new Supplier<ImmutableMap<ClassSymbol, ClassFile.InnerClass>>() {
+            @Override
+            public ImmutableMap<ClassSymbol, ClassFile.InnerClass> get() {
+              ImmutableMap.Builder<ClassSymbol, ClassFile.InnerClass> result =
+                  ImmutableMap.builder();
+              for (ClassFile.InnerClass inner : classFile.get().innerClasses()) {
+                result.put(new ClassSymbol(inner.innerClass()), inner);
+              }
+              return result.buildOrThrow();
+            }
+          });
+
   /**
    * Create a scope for resolving type variable symbols declared in the class, and any enclosing
    * instances.
    */
-  private static Function<String, TyVarSymbol> makeScope(
+  private BytecodeBinder.Scope makeScope(
       final Env<ClassSymbol, BytecodeBoundClass> env,
       final ClassSymbol sym,
       final Map<String, TyVarSymbol> typeVariables) {
-    return new Function<String, TyVarSymbol>() {
+    return new BytecodeBinder.Scope() {
       @Override
       public TyVarSymbol apply(String input) {
         TyVarSymbol result = typeVariables.get(input);
@@ -632,6 +831,18 @@ public class BytecodeBoundClass implements TypeBoundClass {
         }
         throw new AssertionError(input);
       }
+
+      @Override
+      public @Nullable ClassSymbol outer(ClassSymbol sym) {
+        ClassFile.InnerClass inner = innerClasses.get().get(sym);
+        if (inner == null) {
+          return null;
+        }
+        if ((inner.access() & TurbineFlag.ACC_STATIC) == TurbineFlag.ACC_STATIC) {
+          return null;
+        }
+        return new ClassSymbol(inner.outerClass());
+      }
     };
   }
 
diff --git a/java/com/google/turbine/binder/bytecode/package-info.java b/java/com/google/turbine/binder/bytecode/package-info.java
index d2d9708..d9acdc7 100644
--- a/java/com/google/turbine/binder/bytecode/package-info.java
+++ b/java/com/google/turbine/binder/bytecode/package-info.java
@@ -14,5 +14,5 @@
  * limitations under the License.
  */
 
-@org.jspecify.nullness.NullMarked
+@org.jspecify.annotations.NullMarked
 package com.google.turbine.binder.bytecode;
diff --git a/java/com/google/turbine/binder/env/CompoundEnv.java b/java/com/google/turbine/binder/env/CompoundEnv.java
index 391a2c3..c56569a 100644
--- a/java/com/google/turbine/binder/env/CompoundEnv.java
+++ b/java/com/google/turbine/binder/env/CompoundEnv.java
@@ -19,7 +19,7 @@ package com.google.turbine.binder.env;
 import static java.util.Objects.requireNonNull;
 
 import com.google.turbine.binder.sym.Symbol;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** An {@link Env} that chains two existing envs together. */
 public class CompoundEnv<S extends Symbol, V> implements Env<S, V> {
diff --git a/java/com/google/turbine/binder/env/Env.java b/java/com/google/turbine/binder/env/Env.java
index 463c65d..44f0350 100644
--- a/java/com/google/turbine/binder/env/Env.java
+++ b/java/com/google/turbine/binder/env/Env.java
@@ -18,7 +18,7 @@ package com.google.turbine.binder.env;
 
 import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.binder.sym.Symbol;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * An environment that maps {@link Symbol}s {@code S} to bound nodes {@code V}.
@@ -35,8 +35,7 @@ import org.jspecify.nullness.Nullable;
  */
 public interface Env<S extends Symbol, V> {
   /** Returns the information associated with the given symbol in this environment. */
-  @Nullable
-  V get(S sym);
+  @Nullable V get(S sym);
 
   default V getNonNull(S sym) {
     V result = get(sym);
diff --git a/java/com/google/turbine/binder/env/LazyEnv.java b/java/com/google/turbine/binder/env/LazyEnv.java
index 0b311f7..16f7d5d 100644
--- a/java/com/google/turbine/binder/env/LazyEnv.java
+++ b/java/com/google/turbine/binder/env/LazyEnv.java
@@ -22,7 +22,7 @@ import com.google.turbine.binder.sym.Symbol;
 import java.util.LinkedHashMap;
 import java.util.LinkedHashSet;
 import java.util.Map;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * An env that permits an analysis pass to access information about symbols from the current pass,
@@ -81,8 +81,7 @@ public class LazyEnv<S extends Symbol, T, V extends T> implements Env<S, V> {
   /** A lazy value provider which is given access to the current environment. */
   public interface Completer<S extends Symbol, T, V extends T> {
     /** Provides the value for the given symbol in the current environment. */
-    @Nullable
-    V complete(Env<S, T> env, S k);
+    @Nullable V complete(Env<S, T> env, S k);
   }
 
   /** Indicates that a completer tried to complete itself, possibly transitively. */
diff --git a/java/com/google/turbine/binder/env/SimpleEnv.java b/java/com/google/turbine/binder/env/SimpleEnv.java
index 9de5c9f..d128ad9 100644
--- a/java/com/google/turbine/binder/env/SimpleEnv.java
+++ b/java/com/google/turbine/binder/env/SimpleEnv.java
@@ -21,7 +21,7 @@ import com.google.errorprone.annotations.CanIgnoreReturnValue;
 import com.google.turbine.binder.sym.Symbol;
 import java.util.LinkedHashMap;
 import java.util.Map;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A simple {@link ImmutableMap}-backed {@link Env}. */
 public class SimpleEnv<K extends Symbol, V> implements Env<K, V> {
diff --git a/java/com/google/turbine/binder/env/package-info.java b/java/com/google/turbine/binder/env/package-info.java
index fa57245..306a1ce 100644
--- a/java/com/google/turbine/binder/env/package-info.java
+++ b/java/com/google/turbine/binder/env/package-info.java
@@ -15,5 +15,5 @@
  */
 
 @com.google.errorprone.annotations.CheckReturnValue
-@org.jspecify.nullness.NullMarked
+@org.jspecify.annotations.NullMarked
 package com.google.turbine.binder.env;
diff --git a/java/com/google/turbine/binder/lookup/CanonicalSymbolResolver.java b/java/com/google/turbine/binder/lookup/CanonicalSymbolResolver.java
index d44f4e4..a7fe418 100644
--- a/java/com/google/turbine/binder/lookup/CanonicalSymbolResolver.java
+++ b/java/com/google/turbine/binder/lookup/CanonicalSymbolResolver.java
@@ -18,14 +18,13 @@ package com.google.turbine.binder.lookup;
 
 import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.tree.Tree;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Canonical type resolution. Breaks a circular dependency between binding and import handling. */
 public interface CanonicalSymbolResolver extends ImportScope.ResolveFunction {
   /** Resolves a single member type of the given symbol by canonical name. */
   @Override
-  @Nullable
-  ClassSymbol resolveOne(ClassSymbol sym, Tree.Ident bit);
+  @Nullable ClassSymbol resolveOne(ClassSymbol sym, Tree.Ident bit);
 
   /** Returns true if the given symbol is visible from the current package. */
   boolean visible(ClassSymbol sym);
diff --git a/java/com/google/turbine/binder/lookup/CompoundScope.java b/java/com/google/turbine/binder/lookup/CompoundScope.java
index bedf775..059cab7 100644
--- a/java/com/google/turbine/binder/lookup/CompoundScope.java
+++ b/java/com/google/turbine/binder/lookup/CompoundScope.java
@@ -18,7 +18,7 @@ package com.google.turbine.binder.lookup;
 
 import static com.google.common.base.Preconditions.checkNotNull;
 
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A {@link Scope} that chains other scopes together. */
 public class CompoundScope implements Scope {
diff --git a/java/com/google/turbine/binder/lookup/CompoundTopLevelIndex.java b/java/com/google/turbine/binder/lookup/CompoundTopLevelIndex.java
index e7fa45f..beec541 100644
--- a/java/com/google/turbine/binder/lookup/CompoundTopLevelIndex.java
+++ b/java/com/google/turbine/binder/lookup/CompoundTopLevelIndex.java
@@ -19,7 +19,7 @@ package com.google.turbine.binder.lookup;
 import static com.google.common.base.Preconditions.checkNotNull;
 
 import com.google.common.collect.ImmutableList;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A {@link TopLevelIndex} that aggregates multiple indices into one. */
 // Note: this implementation doesn't detect if the indices contain incompatible information,
diff --git a/java/com/google/turbine/binder/lookup/ImportIndex.java b/java/com/google/turbine/binder/lookup/ImportIndex.java
index bcd9366..138efb0 100644
--- a/java/com/google/turbine/binder/lookup/ImportIndex.java
+++ b/java/com/google/turbine/binder/lookup/ImportIndex.java
@@ -31,7 +31,7 @@ import com.google.turbine.tree.Tree.Ident;
 import com.google.turbine.tree.Tree.ImportDecl;
 import java.util.HashMap;
 import java.util.Map;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A scope that provides entries for the single-type imports in a compilation unit.
diff --git a/java/com/google/turbine/binder/lookup/ImportScope.java b/java/com/google/turbine/binder/lookup/ImportScope.java
index a33a8e2..1749b9f 100644
--- a/java/com/google/turbine/binder/lookup/ImportScope.java
+++ b/java/com/google/turbine/binder/lookup/ImportScope.java
@@ -18,7 +18,7 @@ package com.google.turbine.binder.lookup;
 
 import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.tree.Tree;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A scope for imports. Non-canonical imports depend on hierarchy analysis, so to break the cycle we
@@ -31,15 +31,14 @@ public interface ImportScope {
    * A function that performs non-canonical resolution, see {@link
    * com.google.turbine.binder.Resolve#resolve}.
    */
-  @FunctionalInterface
   interface ResolveFunction {
-    @Nullable
-    ClassSymbol resolveOne(ClassSymbol base, Tree.Ident name);
+    @Nullable ClassSymbol resolveOne(ClassSymbol base, Tree.Ident name);
+
+    boolean visible(ClassSymbol sym);
   }
 
   /** See {@link Scope#lookup(LookupKey)}. */
-  @Nullable
-  LookupResult lookup(LookupKey lookupKey, ResolveFunction resolve);
+  @Nullable LookupResult lookup(LookupKey lookupKey, ResolveFunction resolve);
 
   /** Adds a scope to the chain, in the manner of {@link CompoundScope#append(Scope)}. */
   default ImportScope append(ImportScope next) {
diff --git a/java/com/google/turbine/binder/lookup/MemberImportIndex.java b/java/com/google/turbine/binder/lookup/MemberImportIndex.java
index d825396..b29c0d3 100644
--- a/java/com/google/turbine/binder/lookup/MemberImportIndex.java
+++ b/java/com/google/turbine/binder/lookup/MemberImportIndex.java
@@ -30,7 +30,7 @@ import com.google.turbine.tree.Tree.ImportDecl;
 import java.util.Iterator;
 import java.util.LinkedHashMap;
 import java.util.Map;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** An index for statically imported members, in particular constant variables. */
 public class MemberImportIndex {
diff --git a/java/com/google/turbine/binder/lookup/PackageScope.java b/java/com/google/turbine/binder/lookup/PackageScope.java
index 94e950f..12c0c7b 100644
--- a/java/com/google/turbine/binder/lookup/PackageScope.java
+++ b/java/com/google/turbine/binder/lookup/PackageScope.java
@@ -18,7 +18,7 @@ package com.google.turbine.binder.lookup;
 
 import com.google.common.collect.Iterables;
 import com.google.turbine.binder.sym.ClassSymbol;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A scope that corresponds to a particular package, which supports iteration over its enclosed
diff --git a/java/com/google/turbine/binder/lookup/Scope.java b/java/com/google/turbine/binder/lookup/Scope.java
index eb9f5cb..435581e 100644
--- a/java/com/google/turbine/binder/lookup/Scope.java
+++ b/java/com/google/turbine/binder/lookup/Scope.java
@@ -16,7 +16,7 @@
 
 package com.google.turbine.binder.lookup;
 
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A scope that defines types, and supports qualified name resolution. */
 public interface Scope {
@@ -24,6 +24,5 @@ public interface Scope {
    * Performs qualified name lookup on the given {@link LookupKey}, and returns either a {@link
    * LookupResult} or else {@code null} indicating that the name could not be resolved.
    */
-  @Nullable
-  LookupResult lookup(LookupKey lookupKey);
+  @Nullable LookupResult lookup(LookupKey lookupKey);
 }
diff --git a/java/com/google/turbine/binder/lookup/SimpleTopLevelIndex.java b/java/com/google/turbine/binder/lookup/SimpleTopLevelIndex.java
index 179f603..3ae701a 100644
--- a/java/com/google/turbine/binder/lookup/SimpleTopLevelIndex.java
+++ b/java/com/google/turbine/binder/lookup/SimpleTopLevelIndex.java
@@ -16,14 +16,15 @@
 
 package com.google.turbine.binder.lookup;
 
+import static com.google.common.base.Preconditions.checkNotNull;
+
 import com.google.common.base.Supplier;
 import com.google.common.base.Suppliers;
 import com.google.common.collect.ImmutableList;
 import com.google.turbine.binder.sym.ClassSymbol;
 import java.util.HashMap;
-import java.util.Map;
 import java.util.Objects;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * An index of canonical type names where all members are known statically.
@@ -37,17 +38,20 @@ public class SimpleTopLevelIndex implements TopLevelIndex {
   public static class Node {
 
     public @Nullable Node lookup(String bit) {
-      return children.get(bit);
+      return (children == null) ? null : children.get(bit);
     }
 
     private final @Nullable ClassSymbol sym;
-
-    // TODO(cushon): the set of children is typically going to be small, consider optimizing this
-    // to use a denser representation where appropriate.
-    private final Map<String, Node> children = new HashMap<>();
+    private final @Nullable HashMap<String, Node> children;
 
     Node(@Nullable ClassSymbol sym) {
-      this.sym = sym;
+      if (sym == null) {
+        this.sym = null;
+        this.children = new HashMap<>();
+      } else {
+        this.sym = sym;
+        this.children = null;
+      }
     }
 
     /**
@@ -57,6 +61,7 @@ public class SimpleTopLevelIndex implements TopLevelIndex {
      * @return {@code null} if an existing symbol with the same name has already been inserted.
      */
     private @Nullable Node insert(String name, @Nullable ClassSymbol sym) {
+      checkNotNull(children, "Cannot insert child into a class node '%s'", this.sym);
       Node child = children.get(name);
       if (child != null) {
         if (child.sym != null) {
@@ -73,6 +78,10 @@ public class SimpleTopLevelIndex implements TopLevelIndex {
   /** A builder for {@link TopLevelIndex}es. */
   public static class Builder {
 
+    // If there are a lot of strings, we'll skip the first few map sizes. If not, 1K of memory
+    // isn't significant.
+    private final StringCache stringCache = new StringCache(1024);
+
     public TopLevelIndex build() {
       // Freeze the index. The immutability of nodes is enforced by making insert private, doing
       // a deep copy here isn't necessary.
@@ -89,7 +98,7 @@ public class SimpleTopLevelIndex implements TopLevelIndex {
       int end = binaryName.indexOf('/');
       Node curr = root;
       while (end != -1) {
-        String simpleName = binaryName.substring(start, end);
+        String simpleName = stringCache.getSubstring(binaryName, start, end);
         curr = curr.insert(simpleName, null);
         // If we've already inserted something with the current name (either a package or another
         // symbol), bail out. When inserting elements from the classpath, this results in the
@@ -100,12 +109,12 @@ public class SimpleTopLevelIndex implements TopLevelIndex {
         start = end + 1;
         end = binaryName.indexOf('/', start);
       }
+      // Classname strings are probably unique so not worth caching.
       String simpleName = binaryName.substring(start);
       curr = curr.insert(simpleName, sym);
       if (curr == null || !Objects.equals(curr.sym, sym)) {
         return;
       }
-      return;
     }
   }
 
@@ -191,6 +200,10 @@ public class SimpleTopLevelIndex implements TopLevelIndex {
             new Supplier<ImmutableList<ClassSymbol>>() {
               @Override
               public ImmutableList<ClassSymbol> get() {
+                if (node.children == null) {
+                  return ImmutableList.of();
+                }
+
                 ImmutableList.Builder<ClassSymbol> result = ImmutableList.builder();
                 for (Node child : node.children.values()) {
                   if (child.sym != null) {
diff --git a/java/com/google/turbine/binder/lookup/StringCache.java b/java/com/google/turbine/binder/lookup/StringCache.java
new file mode 100644
index 0000000..95ed6d8
--- /dev/null
+++ b/java/com/google/turbine/binder/lookup/StringCache.java
@@ -0,0 +1,109 @@
+/*
+ * Copyright 2024 Google Inc. All Rights Reserved.
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
+package com.google.turbine.binder.lookup;
+
+import static com.google.common.base.Preconditions.checkArgument;
+
+import com.google.common.collect.Maps;
+import java.util.HashMap;
+import org.jspecify.annotations.Nullable;
+
+/**
+ * A cache for canonicalizing strings and string-like data.
+ *
+ * <p>This class is intended to reduce GC overhead in code where lots of duplicate strings might be
+ * allocated. As such, the internals are optimized not make allocations while searching for cached
+ * string instances.
+ *
+ * <p>Searches can be made with a variety of keys, without materializing the actual string they
+ * represent. Materialization only happens if the search fails.
+ */
+public final class StringCache {
+
+  /**
+   * A map from strings to themselves.
+   *
+   * <p>The key-type is {@link Object} so that {@link SubstringKey} can be used to search the map.
+   * Otherwise we could use a {@link Set}.
+   *
+   * <p>This approach exploits the (documented!) fact that {@link HashMap#get} only ever calls
+   * {@link #equals} on the key parameter, never the stored keys. This allows us to inject our own
+   * definition of equality, without needing to wrap the keys at rest.
+   */
+  private final HashMap<Object, String> cache;
+
+  private final SubstringKey substringKey = new SubstringKey();
+
+  public StringCache(int expectedSize) {
+    this.cache = Maps.newHashMapWithExpectedSize(expectedSize);
+  }
+
+  public String get(String str) {
+    String result = cache.putIfAbsent(str, str);
+    return (result == null) ? str : result;
+  }
+
+  public String getSubstring(String superstring, int start, int end) {
+    checkArgument(0 <= start && start <= end && end <= superstring.length());
+
+    this.substringKey.fill(superstring, start, end);
+    String result = cache.get(this.substringKey);
+    if (result == null) {
+      result = superstring.substring(start, end);
+      cache.put(result, result);
+    }
+    return result;
+  }
+
+  /**
+   * A key based on a substring view.
+   *
+   * <p>There is only one instance of SubstringKey per cache. This is possible because it's only
+   * ever used for searches, never to store values. This reuse prevents a lot of garbage generation.
+   */
+  private static final class SubstringKey {
+    String superstring;
+    int start;
+    int end;
+    int length;
+
+    public void fill(String superstring, int start, int end) {
+      this.superstring = superstring;
+      this.start = start;
+      this.end = end;
+      this.length = end - start;
+    }
+
+    @Override
+    @SuppressWarnings({"EqualsBrokenForNull", "EqualsUnsafeCast", "dereference"})
+    public boolean equals(@Nullable Object that) {
+      String thatString = (String) that;
+      return (thatString.length() == this.length)
+          && thatString.regionMatches(0, this.superstring, this.start, this.length);
+    }
+
+    @Override
+    public int hashCode() {
+      // This implementation must exactly match the documented behavior of String.hashCode().
+      int result = 0;
+      for (int i = this.start; i < this.end; i++) {
+        result = 31 * result + this.superstring.charAt(i);
+      }
+      return result;
+    }
+  }
+}
diff --git a/java/com/google/turbine/binder/lookup/TopLevelIndex.java b/java/com/google/turbine/binder/lookup/TopLevelIndex.java
index 049ac5c..c713be2 100644
--- a/java/com/google/turbine/binder/lookup/TopLevelIndex.java
+++ b/java/com/google/turbine/binder/lookup/TopLevelIndex.java
@@ -16,7 +16,7 @@
 
 package com.google.turbine.binder.lookup;
 
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * An index of canonical type names.
@@ -36,6 +36,5 @@ public interface TopLevelIndex {
   Scope scope();
 
   /** Returns a scope to look up members of the given package. */
-  @Nullable
-  PackageScope lookupPackage(Iterable<String> packagename);
+  @Nullable PackageScope lookupPackage(Iterable<String> packagename);
 }
diff --git a/java/com/google/turbine/binder/lookup/WildImportIndex.java b/java/com/google/turbine/binder/lookup/WildImportIndex.java
index 8b4bab1..bcc5abf 100644
--- a/java/com/google/turbine/binder/lookup/WildImportIndex.java
+++ b/java/com/google/turbine/binder/lookup/WildImportIndex.java
@@ -22,15 +22,13 @@ import com.google.common.collect.ImmutableList;
 import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.tree.Tree;
 import com.google.turbine.tree.Tree.ImportDecl;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A scope that provides best-effort lookup for on-demand imported types in a compilation unit.
  *
  * <p>Resolution is lazy, imports are not evaluated until the first request for a matching simple
  * name.
- *
- * <p>Static on-demand imports of types are not supported.
  */
 public class WildImportIndex implements ImportScope {
 
@@ -160,9 +158,14 @@ public class WildImportIndex implements ImportScope {
         continue;
       }
       LookupResult result = scope.lookup(lookup, resolve);
-      if (result != null) {
-        return result;
+      if (result == null) {
+        continue;
+      }
+      ClassSymbol sym = (ClassSymbol) result.sym();
+      if (!resolve.visible(sym)) {
+        continue;
       }
+      return result;
     }
     return null;
   }
diff --git a/java/com/google/turbine/binder/lookup/package-info.java b/java/com/google/turbine/binder/lookup/package-info.java
index 7784138..a951eed 100644
--- a/java/com/google/turbine/binder/lookup/package-info.java
+++ b/java/com/google/turbine/binder/lookup/package-info.java
@@ -15,5 +15,5 @@
  */
 
 @com.google.errorprone.annotations.CheckReturnValue
-@org.jspecify.nullness.NullMarked
+@org.jspecify.annotations.NullMarked
 package com.google.turbine.binder.lookup;
diff --git a/java/com/google/turbine/binder/package-info.java b/java/com/google/turbine/binder/package-info.java
index 9f550e0..cd669f5 100644
--- a/java/com/google/turbine/binder/package-info.java
+++ b/java/com/google/turbine/binder/package-info.java
@@ -15,5 +15,5 @@
  */
 
 @com.google.errorprone.annotations.CheckReturnValue
-@org.jspecify.nullness.NullMarked
+@org.jspecify.annotations.NullMarked
 package com.google.turbine.binder;
diff --git a/java/com/google/turbine/binder/sym/ClassSymbol.java b/java/com/google/turbine/binder/sym/ClassSymbol.java
index 9bb556f..9587192 100644
--- a/java/com/google/turbine/binder/sym/ClassSymbol.java
+++ b/java/com/google/turbine/binder/sym/ClassSymbol.java
@@ -17,7 +17,7 @@
 package com.google.turbine.binder.sym;
 
 import com.google.errorprone.annotations.Immutable;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A class symbol.
diff --git a/java/com/google/turbine/binder/sym/FieldSymbol.java b/java/com/google/turbine/binder/sym/FieldSymbol.java
index 1040500..5f2d6b1 100644
--- a/java/com/google/turbine/binder/sym/FieldSymbol.java
+++ b/java/com/google/turbine/binder/sym/FieldSymbol.java
@@ -18,7 +18,7 @@ package com.google.turbine.binder.sym;
 
 import com.google.errorprone.annotations.Immutable;
 import java.util.Objects;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A field symbol. */
 @Immutable
diff --git a/java/com/google/turbine/binder/sym/MethodSymbol.java b/java/com/google/turbine/binder/sym/MethodSymbol.java
index 12c1aa5..38bfb24 100644
--- a/java/com/google/turbine/binder/sym/MethodSymbol.java
+++ b/java/com/google/turbine/binder/sym/MethodSymbol.java
@@ -18,7 +18,7 @@ package com.google.turbine.binder.sym;
 
 import com.google.errorprone.annotations.Immutable;
 import java.util.Objects;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A method symbol. */
 @Immutable
diff --git a/java/com/google/turbine/binder/sym/ModuleSymbol.java b/java/com/google/turbine/binder/sym/ModuleSymbol.java
index 4ce5c7a..3afe51a 100644
--- a/java/com/google/turbine/binder/sym/ModuleSymbol.java
+++ b/java/com/google/turbine/binder/sym/ModuleSymbol.java
@@ -17,7 +17,7 @@
 package com.google.turbine.binder.sym;
 
 import com.google.errorprone.annotations.Immutable;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A module symbol. */
 @Immutable
diff --git a/java/com/google/turbine/binder/sym/PackageSymbol.java b/java/com/google/turbine/binder/sym/PackageSymbol.java
index be071e0..19a5888 100644
--- a/java/com/google/turbine/binder/sym/PackageSymbol.java
+++ b/java/com/google/turbine/binder/sym/PackageSymbol.java
@@ -17,7 +17,7 @@
 package com.google.turbine.binder.sym;
 
 import com.google.errorprone.annotations.Immutable;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A package symbol. */
 @Immutable
diff --git a/java/com/google/turbine/binder/sym/ParamSymbol.java b/java/com/google/turbine/binder/sym/ParamSymbol.java
index e939223..19bd101 100644
--- a/java/com/google/turbine/binder/sym/ParamSymbol.java
+++ b/java/com/google/turbine/binder/sym/ParamSymbol.java
@@ -18,7 +18,7 @@ package com.google.turbine.binder.sym;
 
 import com.google.errorprone.annotations.Immutable;
 import java.util.Objects;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A parameter symbol. */
 @Immutable
diff --git a/java/com/google/turbine/binder/sym/RecordComponentSymbol.java b/java/com/google/turbine/binder/sym/RecordComponentSymbol.java
index c3f44f6..fd84a92 100644
--- a/java/com/google/turbine/binder/sym/RecordComponentSymbol.java
+++ b/java/com/google/turbine/binder/sym/RecordComponentSymbol.java
@@ -18,7 +18,7 @@ package com.google.turbine.binder.sym;
 
 import com.google.errorprone.annotations.Immutable;
 import java.util.Objects;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A record component symbol. */
 @Immutable
diff --git a/java/com/google/turbine/binder/sym/TyVarSymbol.java b/java/com/google/turbine/binder/sym/TyVarSymbol.java
index 5ba0788..143a8f8 100644
--- a/java/com/google/turbine/binder/sym/TyVarSymbol.java
+++ b/java/com/google/turbine/binder/sym/TyVarSymbol.java
@@ -18,7 +18,7 @@ package com.google.turbine.binder.sym;
 
 import com.google.errorprone.annotations.Immutable;
 import java.util.Objects;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A type variable symbol. */
 @Immutable
diff --git a/java/com/google/turbine/binder/sym/package-info.java b/java/com/google/turbine/binder/sym/package-info.java
index 96f3a87..17ed6ed 100644
--- a/java/com/google/turbine/binder/sym/package-info.java
+++ b/java/com/google/turbine/binder/sym/package-info.java
@@ -15,5 +15,5 @@
  */
 
 @com.google.errorprone.annotations.CheckReturnValue
-@org.jspecify.nullness.NullMarked
+@org.jspecify.annotations.NullMarked
 package com.google.turbine.binder.sym;
diff --git a/java/com/google/turbine/bytecode/ClassFile.java b/java/com/google/turbine/bytecode/ClassFile.java
index 820f17d..c12a45f 100644
--- a/java/com/google/turbine/bytecode/ClassFile.java
+++ b/java/com/google/turbine/bytecode/ClassFile.java
@@ -18,6 +18,7 @@ package com.google.turbine.bytecode;
 
 import static java.util.Objects.requireNonNull;
 
+import com.google.auto.value.AutoValue;
 import com.google.common.collect.ImmutableList;
 import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue;
 import com.google.turbine.model.Const;
@@ -26,7 +27,7 @@ import java.util.ArrayDeque;
 import java.util.Deque;
 import java.util.List;
 import java.util.Map;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A JVMS §4.1 ClassFile. */
 public class ClassFile {
@@ -380,14 +381,22 @@ public class ClassFile {
   /** The contents of a JVMS §4.7.16 annotation structure. */
   public static class AnnotationInfo {
 
+    /** Whether the annotation is visible at runtime. */
+    public enum RuntimeVisibility {
+      VISIBLE,
+      INVISIBLE
+    }
+
     private final String typeName;
-    private final boolean runtimeVisible;
+    private final RuntimeVisibility runtimeVisibility;
     private final Map<String, ElementValue> elementValuePairs;
 
     public AnnotationInfo(
-        String typeName, boolean runtimeVisible, Map<String, ElementValue> elementValuePairs) {
+        String typeName,
+        RuntimeVisibility runtimeVisibility,
+        Map<String, ElementValue> elementValuePairs) {
       this.typeName = typeName;
-      this.runtimeVisible = runtimeVisible;
+      this.runtimeVisibility = runtimeVisibility;
       this.elementValuePairs = elementValuePairs;
     }
 
@@ -398,7 +407,7 @@ public class ClassFile {
 
     /** Returns true if the annotation is visible at runtime. */
     public boolean isRuntimeVisible() {
-      return runtimeVisible;
+      return runtimeVisibility == RuntimeVisibility.VISIBLE;
     }
 
     /** The element-value pairs of the annotation. */
@@ -571,7 +580,7 @@ public class ClassFile {
       return path;
     }
 
-    /** A JVMS 4.7.20 target_type kind. */
+    /** A JVMS 4.7.20-A target_type kind. */
     public enum TargetType {
       CLASS_TYPE_PARAMETER(0x00),
       METHOD_TYPE_PARAMETER(0x01),
@@ -593,6 +602,37 @@ public class ClassFile {
       public int tag() {
         return tag;
       }
+
+      /**
+       * Returns the {@link TargetType} for the given JVMS 4.7.20-A target_type value, and {@code
+       * null} for target_type values that do not correspond to API elements (see JVMS 4.7.20-B).
+       */
+      static @Nullable TargetType forTag(int targetType) {
+        switch (targetType) {
+          case 0x00:
+            return CLASS_TYPE_PARAMETER;
+          case 0x01:
+            return METHOD_TYPE_PARAMETER;
+          case 0x10:
+            return SUPERTYPE;
+          case 0x11:
+            return CLASS_TYPE_PARAMETER_BOUND;
+          case 0x12:
+            return METHOD_TYPE_PARAMETER_BOUND;
+          case 0x13:
+            return FIELD;
+          case 0x14:
+            return METHOD_RETURN;
+          case 0x15:
+            return METHOD_RECEIVER_PARAMETER;
+          case 0x16:
+            return METHOD_FORMAL_PARAMETER;
+          case 0x17:
+            return METHOD_THROWS;
+          default:
+            return null;
+        }
+      }
     }
 
     /** A JVMS 4.7.20 target_info. */
@@ -612,16 +652,13 @@ public class ClassFile {
     }
 
     /** A JVMS 4.7.20.1 type_parameter_target. */
-    public static class TypeParameterTarget extends Target {
-      private final int index;
-
-      public TypeParameterTarget(int index) {
-        this.index = index;
+    @AutoValue
+    public abstract static class TypeParameterTarget extends Target {
+      public static TypeParameterTarget create(int index) {
+        return new AutoValue_ClassFile_TypeAnnotationInfo_TypeParameterTarget(index);
       }
 
-      public int index() {
-        return index;
-      }
+      public abstract int index();
 
       @Override
       public Target.Kind kind() {
@@ -630,11 +667,10 @@ public class ClassFile {
     }
 
     /** A JVMS 4.7.20.1 supertype_target. */
-    public static class SuperTypeTarget extends Target {
-      private final int index;
-
-      public SuperTypeTarget(int index) {
-        this.index = index;
+    @AutoValue
+    public abstract static class SuperTypeTarget extends Target {
+      public static SuperTypeTarget create(int index) {
+        return new AutoValue_ClassFile_TypeAnnotationInfo_SuperTypeTarget(index);
       }
 
       @Override
@@ -642,19 +678,15 @@ public class ClassFile {
         return Target.Kind.SUPERTYPE;
       }
 
-      public int index() {
-        return index;
-      }
+      public abstract int index();
     }
 
     /** A JVMS 4.7.20.1 type_parameter_bound_target. */
-    public static class TypeParameterBoundTarget extends Target {
-      private final int typeParameterIndex;
-      private final int boundIndex;
-
-      public TypeParameterBoundTarget(int typeParameterIndex, int boundIndex) {
-        this.typeParameterIndex = typeParameterIndex;
-        this.boundIndex = boundIndex;
+    @AutoValue
+    public abstract static class TypeParameterBoundTarget extends Target {
+      public static TypeParameterBoundTarget create(int typeParameterIndex, int boundIndex) {
+        return new AutoValue_ClassFile_TypeAnnotationInfo_TypeParameterBoundTarget(
+            typeParameterIndex, boundIndex);
       }
 
       @Override
@@ -662,13 +694,9 @@ public class ClassFile {
         return Target.Kind.TYPE_PARAMETER_BOUND;
       }
 
-      public int typeParameterIndex() {
-        return typeParameterIndex;
-      }
+      public abstract int typeParameterIndex();
 
-      public int boundIndex() {
-        return boundIndex;
-      }
+      public abstract int boundIndex();
     }
 
     /** A JVMS 4.7.20.1 empty_target. */
@@ -681,11 +709,11 @@ public class ClassFile {
         };
 
     /** A JVMS 4.7.20.1 formal_parameter_target. */
-    public static class FormalParameterTarget extends Target {
-      private final int index;
+    @AutoValue
+    public abstract static class FormalParameterTarget extends Target {
 
-      public FormalParameterTarget(int index) {
-        this.index = index;
+      public static FormalParameterTarget create(int index) {
+        return new AutoValue_ClassFile_TypeAnnotationInfo_FormalParameterTarget(index);
       }
 
       @Override
@@ -693,17 +721,15 @@ public class ClassFile {
         return Target.Kind.FORMAL_PARAMETER;
       }
 
-      public int index() {
-        return index;
-      }
+      public abstract int index();
     }
 
     /** A JVMS 4.7.20.1 throws_target. */
-    public static class ThrowsTarget extends Target {
-      private final int index;
+    @AutoValue
+    public abstract static class ThrowsTarget extends Target {
 
-      public ThrowsTarget(int index) {
-        this.index = index;
+      public static ThrowsTarget create(int index) {
+        return new AutoValue_ClassFile_TypeAnnotationInfo_ThrowsTarget(index);
       }
 
       @Override
@@ -711,9 +737,7 @@ public class ClassFile {
         return Target.Kind.THROWS;
       }
 
-      public int index() {
-        return index;
-      }
+      public abstract int index();
     }
 
     /**
@@ -722,35 +746,36 @@ public class ClassFile {
      * <p>Represented as an immutable linked-list of nodes, which is built out by {@code Lower}
      * while recursively searching for type annotations to process.
      */
-    public static class TypePath {
+    @AutoValue
+    public abstract static class TypePath {
 
       /** The root type_path_kind, used for initialization. */
       public static TypePath root() {
-        return new TypePath(null, null);
+        return create(null, null);
       }
 
       /** Adds an array type_path_kind entry. */
       public TypePath array() {
-        return new TypePath(TypePath.Kind.ARRAY, this);
+        return create(TypePath.Kind.ARRAY, this);
       }
 
       /** Adds a nested type type_path_kind entry. */
       public TypePath nested() {
-        return new TypePath(TypePath.Kind.NESTED, this);
+        return create(TypePath.Kind.NESTED, this);
       }
 
       /** Adds a wildcard bound type_path_kind entry. */
       public TypePath wild() {
-        return new TypePath(TypePath.Kind.WILDCARD_BOUND, this);
+        return create(TypePath.Kind.WILDCARD_BOUND, this);
       }
 
       /** Adds a type argument type_path_kind entry. */
       public TypePath typeArgument(int idx) {
-        return new TypePath(idx, TypePath.Kind.TYPE_ARGUMENT, this);
+        return create(idx, TypePath.Kind.TYPE_ARGUMENT, this);
       }
 
       /** A type_path_kind. */
-      enum Kind {
+      public enum Kind {
         ARRAY(0),
         NESTED(1),
         WILDCARD_BOUND(2),
@@ -763,35 +788,32 @@ public class ClassFile {
         }
       }
 
-      private final @Nullable TypePath parent;
-      private final TypePath.@Nullable Kind kind;
-      private final int index;
+      /** The type argument index; set only if the kind is {@code TYPE_ARGUMENT}. */
+      public abstract int typeArgumentIndex();
 
-      private TypePath(TypePath.@Nullable Kind kind, @Nullable TypePath parent) {
-        // JVMS 4.7.20.2: type_argument_index is 0 if the bound kind is not TYPE_ARGUMENT
-        this(0, kind, parent);
-      }
+      public abstract @Nullable Kind kind();
+
+      public abstract @Nullable TypePath parent();
 
-      private TypePath(int index, TypePath.@Nullable Kind kind, @Nullable TypePath parent) {
-        this.index = index;
-        this.kind = kind;
-        this.parent = parent;
+      private static TypePath create(TypePath.@Nullable Kind kind, @Nullable TypePath parent) {
+        // JVMS 4.7.20.2: type_argument_index is 0 if the bound kind is not TYPE_ARGUMENT
+        return create(0, kind, parent);
       }
 
-      /** The type argument index; set only if the kind is {@code TYPE_ARGUMENT}. */
-      public int typeArgumentIndex() {
-        return index;
+      private static TypePath create(
+          int index, TypePath.@Nullable Kind kind, @Nullable TypePath parent) {
+        return new AutoValue_ClassFile_TypeAnnotationInfo_TypePath(index, kind, parent);
       }
 
       /** The JVMS 4.7.20.2-A serialized value of the type_path_kind. */
       public byte tag() {
-        return (byte) requireNonNull(kind).tag;
+        return (byte) requireNonNull(kind()).tag;
       }
 
       /** Returns a flattened view of the type path. */
       public ImmutableList<TypePath> flatten() {
         Deque<TypePath> flat = new ArrayDeque<>();
-        for (TypePath curr = this; requireNonNull(curr).kind != null; curr = curr.parent) {
+        for (TypePath curr = this; requireNonNull(curr).kind() != null; curr = curr.parent()) {
           flat.addFirst(curr);
         }
         return ImmutableList.copyOf(flat);
diff --git a/java/com/google/turbine/bytecode/ClassReader.java b/java/com/google/turbine/bytecode/ClassReader.java
index e73bc49..3a94cd9 100644
--- a/java/com/google/turbine/bytecode/ClassReader.java
+++ b/java/com/google/turbine/bytecode/ClassReader.java
@@ -28,6 +28,7 @@ import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue.ConstTu
 import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue.ConstTurbineClassValue;
 import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue.ConstValue;
 import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue.EnumConstValue;
+import com.google.turbine.bytecode.ClassFile.AnnotationInfo.RuntimeVisibility;
 import com.google.turbine.bytecode.ClassFile.MethodInfo.ParameterInfo;
 import com.google.turbine.bytecode.ClassFile.ModuleInfo;
 import com.google.turbine.bytecode.ClassFile.ModuleInfo.ExportInfo;
@@ -35,11 +36,13 @@ import com.google.turbine.bytecode.ClassFile.ModuleInfo.OpenInfo;
 import com.google.turbine.bytecode.ClassFile.ModuleInfo.ProvideInfo;
 import com.google.turbine.bytecode.ClassFile.ModuleInfo.RequireInfo;
 import com.google.turbine.bytecode.ClassFile.ModuleInfo.UseInfo;
+import com.google.turbine.bytecode.ClassFile.RecordInfo;
+import com.google.turbine.bytecode.ClassFile.TypeAnnotationInfo;
 import com.google.turbine.model.Const;
 import com.google.turbine.model.TurbineFlag;
 import java.util.ArrayList;
 import java.util.List;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A JVMS §4 class file reader. */
 public class ClassReader {
@@ -107,22 +110,32 @@ public class ClassReader {
     String signature = null;
     List<ClassFile.InnerClass> innerclasses = ImmutableList.of();
     ImmutableList.Builder<ClassFile.AnnotationInfo> annotations = ImmutableList.builder();
+    ImmutableList.Builder<ClassFile.TypeAnnotationInfo> typeAnnotations = ImmutableList.builder();
     ClassFile.ModuleInfo module = null;
     String transitiveJar = null;
+    RecordInfo record = null;
     int attributesCount = reader.u2();
     for (int j = 0; j < attributesCount; j++) {
       int attributeNameIndex = reader.u2();
       String name = constantPool.utf8(attributeNameIndex);
       switch (name) {
         case "RuntimeInvisibleAnnotations":
+          readAnnotations(annotations, constantPool, RuntimeVisibility.INVISIBLE);
+          break;
         case "RuntimeVisibleAnnotations":
-          readAnnotations(annotations, constantPool);
+          readAnnotations(annotations, constantPool, RuntimeVisibility.VISIBLE);
+          break;
+        case "RuntimeInvisibleTypeAnnotations":
+          readTypeAnnotations(typeAnnotations, constantPool, RuntimeVisibility.INVISIBLE);
+          break;
+        case "RuntimeVisibleTypeAnnotations":
+          readTypeAnnotations(typeAnnotations, constantPool, RuntimeVisibility.VISIBLE);
           break;
         case "Signature":
           signature = readSignature(constantPool);
           break;
         case "InnerClasses":
-          innerclasses = readInnerClasses(constantPool, thisClass);
+          innerclasses = readInnerClasses(constantPool);
           break;
         case "Module":
           module = readModule(constantPool);
@@ -130,6 +143,9 @@ public class ClassReader {
         case "TurbineTransitiveJar":
           transitiveJar = readTurbineTransitiveJar(constantPool);
           break;
+        case "Record":
+          record = readRecord(constantPool);
+          break;
         default:
           reader.skip(reader.u4());
           break;
@@ -148,11 +164,11 @@ public class ClassReader {
         fieldinfos,
         annotations.build(),
         innerclasses,
-        ImmutableList.of(),
+        typeAnnotations.build(),
         module,
         /* nestHost= */ null,
         /* nestMembers= */ ImmutableList.of(),
-        /* record= */ null,
+        record,
         transitiveJar);
   }
 
@@ -165,8 +181,7 @@ public class ClassReader {
   }
 
   /** Reads JVMS 4.7.6 InnerClasses attributes. */
-  private List<ClassFile.InnerClass> readInnerClasses(
-      ConstantPoolReader constantPool, String thisClass) {
+  private List<ClassFile.InnerClass> readInnerClasses(ConstantPoolReader constantPool) {
     int unusedLength = reader.u4();
     int numberOfClasses = reader.u2();
     List<ClassFile.InnerClass> innerclasses = new ArrayList<>();
@@ -179,8 +194,7 @@ public class ClassReader {
       int innerNameIndex = reader.u2();
       String innerName = innerNameIndex != 0 ? constantPool.utf8(innerNameIndex) : null;
       int innerClassAccessFlags = reader.u2();
-      if (innerName != null && (thisClass.equals(innerClass) || thisClass.equals(outerClass))) {
-        requireNonNull(outerClass);
+      if (innerName != null && outerClass != null) {
         innerclasses.add(
             new ClassFile.InnerClass(innerClass, outerClass, innerName, innerClassAccessFlags));
       }
@@ -196,17 +210,20 @@ public class ClassReader {
    */
   private void readAnnotations(
       ImmutableList.Builder<ClassFile.AnnotationInfo> annotations,
-      ConstantPoolReader constantPool) {
+      ConstantPoolReader constantPool,
+      RuntimeVisibility runtimeVisibility) {
     int unusedLength = reader.u4();
     int numAnnotations = reader.u2();
     for (int n = 0; n < numAnnotations; n++) {
-      annotations.add(readAnnotation(constantPool));
+      annotations.add(readAnnotation(constantPool, runtimeVisibility));
     }
   }
 
   /** Processes a JVMS 4.7.18 RuntimeVisibleParameterAnnotations attribute */
   public void readParameterAnnotations(
-      List<ImmutableList.Builder<AnnotationInfo>> annotations, ConstantPoolReader constantPool) {
+      List<ImmutableList.Builder<AnnotationInfo>> annotations,
+      ConstantPoolReader constantPool,
+      RuntimeVisibility runtimeVisibility) {
     int unusedLength = reader.u4();
     int numParameters = reader.u1();
     while (annotations.size() < numParameters) {
@@ -215,7 +232,7 @@ public class ClassReader {
     for (int i = 0; i < numParameters; i++) {
       int numAnnotations = reader.u2();
       for (int n = 0; n < numAnnotations; n++) {
-        annotations.get(i).add(readAnnotation(constantPool));
+        annotations.get(i).add(readAnnotation(constantPool, runtimeVisibility));
       }
     }
   }
@@ -320,7 +337,8 @@ public class ClassReader {
    * Extracts an {@link @Retention} or {@link ElementType} {@link ClassFile.AnnotationInfo}, or else
    * skips over the annotation.
    */
-  private ClassFile.AnnotationInfo readAnnotation(ConstantPoolReader constantPool) {
+  private ClassFile.AnnotationInfo readAnnotation(
+      ConstantPoolReader constantPool, RuntimeVisibility runtimeVisibility) {
     int typeIndex = reader.u2();
     String annotationType = constantPool.utf8(typeIndex);
     int numElementValuePairs = reader.u2();
@@ -331,12 +349,131 @@ public class ClassReader {
       ElementValue value = readElementValue(constantPool);
       values.put(key, value);
     }
-    return new ClassFile.AnnotationInfo(
-        annotationType,
-        // The runtimeVisible bit in AnnotationInfo is only used during lowering; earlier passes
-        // read the meta-annotations.
-        /* runtimeVisible= */ false,
-        values.buildOrThrow());
+    return new ClassFile.AnnotationInfo(annotationType, runtimeVisibility, values.buildOrThrow());
+  }
+
+  private void readTypeAnnotations(
+      ImmutableList.Builder<TypeAnnotationInfo> typeAnnotations,
+      ConstantPoolReader constantPool,
+      RuntimeVisibility runtimeVisibility) {
+    int unusedLength = reader.u4();
+    int numAnnotations = reader.u2();
+    for (int n = 0; n < numAnnotations; n++) {
+      TypeAnnotationInfo anno = readTypeAnnotation(constantPool, runtimeVisibility);
+      if (anno != null) {
+        typeAnnotations.add(anno);
+      }
+    }
+  }
+
+  /**
+   * Reads a JVMS 4.7.20 type_annotation struct. If the type_annotation does not correspond to an
+   * API element (it has a target_type that is not listed in JVMS 4.7.20-A), this method skips over
+   * the variable length annotation data and then returns {@code null}.
+   */
+  private @Nullable TypeAnnotationInfo readTypeAnnotation(
+      ConstantPoolReader constantPool, RuntimeVisibility runtimeVisibility) {
+    int targetTypeId = reader.u1();
+    TypeAnnotationInfo.TargetType targetType = TypeAnnotationInfo.TargetType.forTag(targetTypeId);
+    TypeAnnotationInfo.Target target = null;
+    if (targetType != null) {
+      target = readTypeAnnotationTarget(targetType);
+    } else {
+      // These aren't part of the API, we just need to skip over the right number of bytes
+      switch (targetTypeId) {
+        case 0x40:
+        case 0x41:
+          // localvar_target
+          reader.skip(reader.u2() * 6);
+          break;
+        case 0x42:
+        case 0x43:
+        case 0x44:
+        case 0x45:
+        case 0x46:
+          // catch_target, offset_target
+          reader.skip(2);
+          break;
+        case 0x47:
+        case 0x48:
+        case 0x49:
+        case 0x4A:
+        case 0x4B:
+          // type_argument_target
+          reader.skip(3);
+          break;
+        default:
+          throw error("invalid target type: %d", targetTypeId);
+      }
+    }
+    TypeAnnotationInfo.TypePath typePath = TypeAnnotationInfo.TypePath.root();
+    int pathLength = reader.u1();
+    for (int i = 0; i < pathLength; i++) {
+      typePath = readTypePath(typePath);
+    }
+    AnnotationInfo anno = readAnnotation(constantPool, runtimeVisibility);
+    if (targetType == null) {
+      return null;
+    }
+    return new TypeAnnotationInfo(targetType, requireNonNull(target), typePath, anno);
+  }
+
+  private TypeAnnotationInfo.Target readTypeAnnotationTarget(
+      TypeAnnotationInfo.TargetType targetType) {
+    switch (targetType) {
+      case CLASS_TYPE_PARAMETER:
+      case METHOD_TYPE_PARAMETER:
+        {
+          int typeParameterIndex = reader.u1();
+          return TypeAnnotationInfo.TypeParameterTarget.create(typeParameterIndex);
+        }
+      case SUPERTYPE:
+        {
+          int superTypeIndex = reader.u2();
+          return TypeAnnotationInfo.SuperTypeTarget.create(superTypeIndex);
+        }
+      case CLASS_TYPE_PARAMETER_BOUND:
+      case METHOD_TYPE_PARAMETER_BOUND:
+        {
+          int typeParameterIndex = reader.u1();
+          int boundIndex = reader.u1();
+          return TypeAnnotationInfo.TypeParameterBoundTarget.create(typeParameterIndex, boundIndex);
+        }
+      case FIELD:
+      case METHOD_RETURN:
+      case METHOD_RECEIVER_PARAMETER:
+        {
+          return TypeAnnotationInfo.EMPTY_TARGET;
+        }
+      case METHOD_FORMAL_PARAMETER:
+        {
+          int formalParameterIndex = reader.u1();
+          return TypeAnnotationInfo.FormalParameterTarget.create(formalParameterIndex);
+        }
+      case METHOD_THROWS:
+        {
+          int throwsTypeIndex = reader.u2();
+          return TypeAnnotationInfo.ThrowsTarget.create(throwsTypeIndex);
+        }
+    }
+    throw new AssertionError(targetType);
+  }
+
+  private TypeAnnotationInfo.TypePath readTypePath(TypeAnnotationInfo.TypePath typePath) {
+    int typePathKind = reader.u1();
+    int typeArgumentIndex = reader.u1();
+    switch (typePathKind) {
+      case 0:
+        return typePath.array();
+      case 1:
+        return typePath.nested();
+      case 2:
+        return typePath.wild();
+      case 3:
+        return typePath.typeArgument(typeArgumentIndex);
+      default:
+        throw error("invalid type path kind: %d", typePathKind);
+    }
   }
 
   private ElementValue readElementValue(ConstantPoolReader constantPool) {
@@ -372,7 +509,12 @@ public class ClassReader {
           return new ConstTurbineClassValue(className);
         }
       case '@':
-        return new ConstTurbineAnnotationValue(readAnnotation(constantPool));
+        // The runtime visibility stored in the AnnotationInfo is never used for annotations that
+        // appear in element-values of other annotations. For top-level annotations, it determines
+        // the attribute the annotation appears in (e.g. Runtime{Invisible,Visible}Annotations).
+        // See also JVMS 4.7.16.1.
+        return new ConstTurbineAnnotationValue(
+            readAnnotation(constantPool, RuntimeVisibility.INVISIBLE));
       case '[':
         {
           int numValues = reader.u2();
@@ -410,6 +552,7 @@ public class ClassReader {
       String signature = null;
       ImmutableList<String> exceptions = ImmutableList.of();
       ImmutableList.Builder<ClassFile.AnnotationInfo> annotations = ImmutableList.builder();
+      ImmutableList.Builder<ClassFile.TypeAnnotationInfo> typeAnnotations = ImmutableList.builder();
       List<ImmutableList.Builder<ClassFile.AnnotationInfo>> parameterAnnotationsBuilder =
           new ArrayList<>();
       ImmutableList.Builder<ParameterInfo> parameters = ImmutableList.builder();
@@ -428,12 +571,24 @@ public class ClassReader {
             defaultValue = readElementValue(constantPool);
             break;
           case "RuntimeInvisibleAnnotations":
+            readAnnotations(annotations, constantPool, RuntimeVisibility.INVISIBLE);
+            break;
           case "RuntimeVisibleAnnotations":
-            readAnnotations(annotations, constantPool);
+            readAnnotations(annotations, constantPool, RuntimeVisibility.VISIBLE);
+            break;
+          case "RuntimeInvisibleTypeAnnotations":
+            readTypeAnnotations(typeAnnotations, constantPool, RuntimeVisibility.INVISIBLE);
+            break;
+          case "RuntimeVisibleTypeAnnotations":
+            readTypeAnnotations(typeAnnotations, constantPool, RuntimeVisibility.VISIBLE);
             break;
           case "RuntimeInvisibleParameterAnnotations":
+            readParameterAnnotations(
+                parameterAnnotationsBuilder, constantPool, RuntimeVisibility.INVISIBLE);
+            break;
           case "RuntimeVisibleParameterAnnotations":
-            readParameterAnnotations(parameterAnnotationsBuilder, constantPool);
+            readParameterAnnotations(
+                parameterAnnotationsBuilder, constantPool, RuntimeVisibility.VISIBLE);
             break;
           case "MethodParameters":
             readMethodParameters(parameters, constantPool);
@@ -462,7 +617,7 @@ public class ClassReader {
               defaultValue,
               annotations.build(),
               parameterAnnotations.build(),
-              /* typeAnnotations= */ ImmutableList.of(),
+              typeAnnotations.build(),
               parameters.build()));
     }
     return methods;
@@ -492,6 +647,7 @@ public class ClassReader {
       int attributesCount = reader.u2();
       Const.Value value = null;
       ImmutableList.Builder<ClassFile.AnnotationInfo> annotations = ImmutableList.builder();
+      ImmutableList.Builder<ClassFile.TypeAnnotationInfo> typeAnnotations = ImmutableList.builder();
       String signature = null;
       for (int j = 0; j < attributesCount; j++) {
         String attributeName = constantPool.utf8(reader.u2());
@@ -501,8 +657,16 @@ public class ClassReader {
             value = constantPool.constant(reader.u2());
             break;
           case "RuntimeInvisibleAnnotations":
+            readAnnotations(annotations, constantPool, RuntimeVisibility.INVISIBLE);
+            break;
           case "RuntimeVisibleAnnotations":
-            readAnnotations(annotations, constantPool);
+            readAnnotations(annotations, constantPool, RuntimeVisibility.VISIBLE);
+            break;
+          case "RuntimeInvisibleTypeAnnotations":
+            readTypeAnnotations(typeAnnotations, constantPool, RuntimeVisibility.INVISIBLE);
+            break;
+          case "RuntimeVisibleTypeAnnotations":
+            readTypeAnnotations(typeAnnotations, constantPool, RuntimeVisibility.VISIBLE);
             break;
           case "Signature":
             signature = readSignature(constantPool);
@@ -520,7 +684,7 @@ public class ClassReader {
               signature,
               value,
               annotations.build(),
-              /* typeAnnotations= */ ImmutableList.of()));
+              typeAnnotations.build()));
     }
     return fields;
   }
@@ -529,4 +693,47 @@ public class ClassReader {
     int unusedLength = reader.u4();
     return constantPool.utf8(reader.u2());
   }
+
+  private RecordInfo readRecord(ConstantPoolReader constantPool) {
+    int unusedLength = reader.u4();
+    int componentsCount = reader.u2();
+
+    ImmutableList.Builder<RecordInfo.RecordComponentInfo> components = ImmutableList.builder();
+    for (int i = 0; i < componentsCount; i++) {
+      String name = constantPool.utf8(reader.u2());
+      String descriptor = constantPool.utf8(reader.u2());
+
+      int attributesCount = reader.u2();
+      ImmutableList.Builder<ClassFile.AnnotationInfo> annotations = ImmutableList.builder();
+      ImmutableList.Builder<ClassFile.TypeAnnotationInfo> typeAnnotations = ImmutableList.builder();
+      String signature = null;
+      for (int j = 0; j < attributesCount; j++) {
+        String attributeName = constantPool.utf8(reader.u2());
+        switch (attributeName) {
+          case "RuntimeInvisibleAnnotations":
+            readAnnotations(annotations, constantPool, RuntimeVisibility.INVISIBLE);
+            break;
+          case "RuntimeVisibleAnnotations":
+            readAnnotations(annotations, constantPool, RuntimeVisibility.VISIBLE);
+            break;
+          case "RuntimeInvisibleTypeAnnotations":
+            readTypeAnnotations(typeAnnotations, constantPool, RuntimeVisibility.INVISIBLE);
+            break;
+          case "RuntimeVisibleTypeAnnotations":
+            readTypeAnnotations(typeAnnotations, constantPool, RuntimeVisibility.VISIBLE);
+            break;
+          case "Signature":
+            signature = readSignature(constantPool);
+            break;
+          default:
+            reader.skip(reader.u4());
+            break;
+        }
+      }
+      components.add(
+          new RecordInfo.RecordComponentInfo(
+              name, descriptor, signature, annotations.build(), typeAnnotations.build()));
+    }
+    return new RecordInfo(components.build());
+  }
 }
diff --git a/java/com/google/turbine/bytecode/package-info.java b/java/com/google/turbine/bytecode/package-info.java
index 3f0bb60..2cbbf31 100644
--- a/java/com/google/turbine/bytecode/package-info.java
+++ b/java/com/google/turbine/bytecode/package-info.java
@@ -15,5 +15,5 @@
  */
 
 @com.google.errorprone.annotations.CheckReturnValue
-@org.jspecify.nullness.NullMarked
+@org.jspecify.annotations.NullMarked
 package com.google.turbine.bytecode;
diff --git a/java/com/google/turbine/bytecode/sig/Sig.java b/java/com/google/turbine/bytecode/sig/Sig.java
index 99d98cf..2f745aa 100644
--- a/java/com/google/turbine/bytecode/sig/Sig.java
+++ b/java/com/google/turbine/bytecode/sig/Sig.java
@@ -18,7 +18,7 @@ package com.google.turbine.bytecode.sig;
 
 import com.google.common.collect.ImmutableList;
 import com.google.turbine.model.TurbineConstantTypeKind;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** JVMS 4.7.9.1 signatures. */
 public final class Sig {
diff --git a/java/com/google/turbine/bytecode/sig/package-info.java b/java/com/google/turbine/bytecode/sig/package-info.java
index c5f449e..e8960e9 100644
--- a/java/com/google/turbine/bytecode/sig/package-info.java
+++ b/java/com/google/turbine/bytecode/sig/package-info.java
@@ -15,5 +15,5 @@
  */
 
 @com.google.errorprone.annotations.CheckReturnValue
-@org.jspecify.nullness.NullMarked
+@org.jspecify.annotations.NullMarked
 package com.google.turbine.bytecode.sig;
diff --git a/java/com/google/turbine/deps/Dependencies.java b/java/com/google/turbine/deps/Dependencies.java
index 3dd008c..5ce9b5d 100644
--- a/java/com/google/turbine/deps/Dependencies.java
+++ b/java/com/google/turbine/deps/Dependencies.java
@@ -165,7 +165,7 @@ public final class Dependencies {
     }
   }
 
-  private static void addPackageInfos(Set<ClassSymbol> closure, BindingResult bound) {
+  static void addPackageInfos(Set<ClassSymbol> closure, BindingResult bound) {
     Set<ClassSymbol> packages = new LinkedHashSet<>();
     for (ClassSymbol sym : closure) {
       String packageName = sym.packageName();
diff --git a/java/com/google/turbine/deps/Transitive.java b/java/com/google/turbine/deps/Transitive.java
index 2b8bd58..22f4983 100644
--- a/java/com/google/turbine/deps/Transitive.java
+++ b/java/com/google/turbine/deps/Transitive.java
@@ -33,7 +33,7 @@ import com.google.turbine.bytecode.ClassWriter;
 import com.google.turbine.model.TurbineFlag;
 import java.util.LinkedHashSet;
 import java.util.Set;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Collects the minimal compile-time API for symbols in the supertype closure of compiled classes.
@@ -45,7 +45,9 @@ public final class Transitive {
   public static ImmutableMap<String, byte[]> collectDeps(
       ClassPath bootClassPath, BindingResult bound) {
     ImmutableMap.Builder<String, byte[]> transitive = ImmutableMap.builder();
-    for (ClassSymbol sym : superClosure(bound)) {
+    Set<ClassSymbol> closure = superClosure(bound);
+    Dependencies.addPackageInfos(closure, bound);
+    for (ClassSymbol sym : closure) {
       BytecodeBoundClass info = bound.classPathEnv().get(sym);
       if (info == null) {
         // the symbol wasn't loaded from the classpath
@@ -110,7 +112,7 @@ public final class Transitive {
         /* nestHost= */ null,
         /* nestMembers= */ ImmutableList.of(),
         /* record= */ null,
-        /* transitiveJar = */ transitiveJar);
+        /* transitiveJar= */ transitiveJar);
   }
 
   private static Set<ClassSymbol> superClosure(BindingResult bound) {
diff --git a/java/com/google/turbine/diag/SourceFile.java b/java/com/google/turbine/diag/SourceFile.java
index a7c3245..97ee038 100644
--- a/java/com/google/turbine/diag/SourceFile.java
+++ b/java/com/google/turbine/diag/SourceFile.java
@@ -19,7 +19,7 @@ package com.google.turbine.diag;
 import com.google.common.base.Supplier;
 import com.google.common.base.Suppliers;
 import java.util.Objects;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A source file. */
 public class SourceFile {
diff --git a/java/com/google/turbine/diag/TurbineDiagnostic.java b/java/com/google/turbine/diag/TurbineDiagnostic.java
index 1457868..3649dcb 100644
--- a/java/com/google/turbine/diag/TurbineDiagnostic.java
+++ b/java/com/google/turbine/diag/TurbineDiagnostic.java
@@ -21,13 +21,12 @@ import static com.google.common.collect.Iterables.getOnlyElement;
 import static java.util.Objects.requireNonNull;
 
 import com.google.common.base.CharMatcher;
-import com.google.common.base.Strings;
 import com.google.common.collect.ImmutableList;
 import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.diag.TurbineError.ErrorKind;
 import java.util.Objects;
 import javax.tools.Diagnostic;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A compilation error. */
 public class TurbineDiagnostic {
@@ -80,7 +79,7 @@ public class TurbineDiagnostic {
       requireNonNull(source); // line and column imply source is non-null
       sb.append(CharMatcher.breakingWhitespace().trimTrailingFrom(source.lineMap().line(position)))
           .append(System.lineSeparator());
-      sb.append(Strings.repeat(" ", column() - 1)).append('^');
+      sb.append(" ".repeat(column() - 1)).append('^');
     }
     return sb.toString();
   }
@@ -138,6 +137,10 @@ public class TurbineDiagnostic {
     return create(severity, kind, ImmutableList.copyOf(args), source, position);
   }
 
+  public TurbineDiagnostic withPosition(SourceFile source, int position) {
+    return new TurbineDiagnostic(severity, kind, args, source, position);
+  }
+
   @Override
   public int hashCode() {
     return Objects.hash(kind, source, position);
diff --git a/java/com/google/common/escape/SourceCodeEscapers.java b/java/com/google/turbine/escape/SourceCodeEscapers.java
similarity index 89%
rename from java/com/google/common/escape/SourceCodeEscapers.java
rename to java/com/google/turbine/escape/SourceCodeEscapers.java
index c0f9d6b..1c3466d 100644
--- a/java/com/google/common/escape/SourceCodeEscapers.java
+++ b/java/com/google/turbine/escape/SourceCodeEscapers.java
@@ -14,8 +14,10 @@
  * limitations under the License.
  */
 
-package com.google.common.escape;
+package com.google.turbine.escape;
 
+import com.google.common.escape.ArrayBasedCharEscaper;
+import com.google.common.escape.CharEscaper;
 import java.util.HashMap;
 import java.util.Map;
 
@@ -39,7 +41,7 @@ public final class SourceCodeEscapers {
   private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();
 
   /**
-   * Returns an {@link Escaper} instance that escapes special characters in a string so it can
+   * Returns an {@link CharEscaper} instance that escapes special characters in a string so it can
    * safely be included in either a Java character literal or string literal. This is the preferred
    * way to escape Java characters for use in String or character literals.
    *
@@ -83,16 +85,16 @@ public final class SourceCodeEscapers {
 
   // Helper for common case of escaping a single char.
   private static char[] asUnicodeHexEscape(char c) {
-    // Equivalent to String.format("\\u%04x", (int)c);
+    // Equivalent to String.format("\\u%04x", (int) c);
     char[] r = new char[6];
     r[0] = '\\';
     r[1] = 'u';
     r[5] = HEX_DIGITS[c & 0xF];
-    c >>>= 4;
+    c = (char) (c >>> 4);
     r[4] = HEX_DIGITS[c & 0xF];
-    c >>>= 4;
+    c = (char) (c >>> 4);
     r[3] = HEX_DIGITS[c & 0xF];
-    c >>>= 4;
+    c = (char) (c >>> 4);
     r[2] = HEX_DIGITS[c & 0xF];
     return r;
   }
diff --git a/java/com/google/common/escape/package-info.java b/java/com/google/turbine/escape/package-info.java
similarity index 90%
rename from java/com/google/common/escape/package-info.java
rename to java/com/google/turbine/escape/package-info.java
index b69b34e..4797b68 100644
--- a/java/com/google/common/escape/package-info.java
+++ b/java/com/google/turbine/escape/package-info.java
@@ -15,5 +15,5 @@
  */
 
 @com.google.errorprone.annotations.CheckReturnValue
-@org.jspecify.nullness.NullMarked
-package com.google.common.escape;
+@org.jspecify.annotations.NullMarked
+package com.google.turbine.escape;
diff --git a/java/com/google/turbine/lower/Lower.java b/java/com/google/turbine/lower/Lower.java
index 80d8128..ce6ec6d 100644
--- a/java/com/google/turbine/lower/Lower.java
+++ b/java/com/google/turbine/lower/Lower.java
@@ -51,6 +51,7 @@ import com.google.turbine.binder.sym.TyVarSymbol;
 import com.google.turbine.bytecode.ClassFile;
 import com.google.turbine.bytecode.ClassFile.AnnotationInfo;
 import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue;
+import com.google.turbine.bytecode.ClassFile.AnnotationInfo.RuntimeVisibility;
 import com.google.turbine.bytecode.ClassFile.MethodInfo.ParameterInfo;
 import com.google.turbine.bytecode.ClassFile.TypeAnnotationInfo;
 import com.google.turbine.bytecode.ClassFile.TypeAnnotationInfo.Target;
@@ -80,15 +81,13 @@ import com.google.turbine.type.Type.TyVar;
 import com.google.turbine.type.Type.WildTy;
 import com.google.turbine.types.Erasure;
 import java.lang.annotation.RetentionPolicy;
-import java.util.ArrayDeque;
 import java.util.ArrayList;
-import java.util.Deque;
 import java.util.LinkedHashSet;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
 import java.util.function.Function;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Lowering from bound classes to bytecode. */
 public class Lower {
@@ -433,13 +432,13 @@ public class Lower {
       }
       ImmutableList.Builder<AnnotationInfo> parameterAnnotations = ImmutableList.builder();
       for (AnnoInfo annotation : parameter.annotations()) {
-        Boolean visible = isVisible(annotation.sym());
-        if (visible == null) {
+        RuntimeVisibility visibility = getVisibility(annotation.sym());
+        if (visibility == null) {
           continue;
         }
         String desc = sig.objectType(annotation.sym());
         parameterAnnotations.add(
-            new AnnotationInfo(desc, visible, annotationValues(annotation.values())));
+            new AnnotationInfo(desc, visibility, annotationValues(annotation.values())));
       }
       annotations.add(parameterAnnotations.build());
     }
@@ -638,26 +637,26 @@ public class Lower {
   }
 
   private @Nullable AnnotationInfo lowerAnnotation(AnnoInfo annotation) {
-    Boolean visible = isVisible(annotation.sym());
-    if (visible == null) {
+    RuntimeVisibility visibility = getVisibility(annotation.sym());
+    if (visibility == null) {
       return null;
     }
     return new AnnotationInfo(
-        sig.objectType(annotation.sym()), visible, annotationValues(annotation.values()));
+        sig.objectType(annotation.sym()), visibility, annotationValues(annotation.values()));
   }
 
   /**
    * Returns true if the annotation is visible at runtime, false if it is not visible at runtime,
    * and {@code null} if it should not be retained in bytecode.
    */
-  private @Nullable Boolean isVisible(ClassSymbol sym) {
+  private @Nullable RuntimeVisibility getVisibility(ClassSymbol sym) {
     RetentionPolicy retention =
         requireNonNull(env.getNonNull(sym).annotationMetadata()).retention();
     switch (retention) {
       case CLASS:
-        return false;
+        return RuntimeVisibility.INVISIBLE;
       case RUNTIME:
-        return true;
+        return RuntimeVisibility.VISIBLE;
       case SOURCE:
         return null;
     }
@@ -698,14 +697,14 @@ public class Lower {
       case ANNOTATION:
         {
           TurbineAnnotationValue annotationValue = (TurbineAnnotationValue) value;
-          Boolean visible = isVisible(annotationValue.sym());
-          if (visible == null) {
-            visible = true;
+          RuntimeVisibility visibility = getVisibility(annotationValue.sym());
+          if (visibility == null) {
+            visibility = RuntimeVisibility.VISIBLE;
           }
           return new ElementValue.ConstTurbineAnnotationValue(
               new AnnotationInfo(
                   sig.objectType(annotationValue.sym()),
-                  visible,
+                  visibility,
                   annotationValues(annotationValue.values())));
         }
       case PRIMITIVE:
@@ -723,12 +722,12 @@ public class Lower {
             result,
             info.superClassType(),
             TargetType.SUPERTYPE,
-            new TypeAnnotationInfo.SuperTypeTarget(-1));
+            TypeAnnotationInfo.SuperTypeTarget.create(-1));
       }
       int idx = 0;
       for (Type i : info.interfaceTypes()) {
         lowerTypeAnnotations(
-            result, i, TargetType.SUPERTYPE, new TypeAnnotationInfo.SuperTypeTarget(idx++));
+            result, i, TargetType.SUPERTYPE, TypeAnnotationInfo.SuperTypeTarget.create(idx++));
       }
     }
     typeParameterAnnotations(
@@ -752,7 +751,7 @@ public class Lower {
     {
       int idx = 0;
       for (Type e : m.exceptions()) {
-        lowerTypeAnnotations(result, e, TargetType.METHOD_THROWS, new ThrowsTarget(idx++));
+        lowerTypeAnnotations(result, e, TargetType.METHOD_THROWS, ThrowsTarget.create(idx++));
       }
     }
 
@@ -777,7 +776,7 @@ public class Lower {
             result,
             p.type(),
             TargetType.METHOD_FORMAL_PARAMETER,
-            new TypeAnnotationInfo.FormalParameterTarget(idx++));
+            TypeAnnotationInfo.FormalParameterTarget.create(idx++));
       }
     }
 
@@ -803,7 +802,7 @@ public class Lower {
         result.add(
             new TypeAnnotationInfo(
                 targetType,
-                new TypeAnnotationInfo.TypeParameterTarget(typeParameterIndex),
+                TypeAnnotationInfo.TypeParameterTarget.create(typeParameterIndex),
                 TypePath.root(),
                 info));
       }
@@ -817,7 +816,7 @@ public class Lower {
             result,
             i,
             boundTargetType,
-            new TypeAnnotationInfo.TypeParameterBoundTarget(typeParameterIndex, boundIndex++));
+            TypeAnnotationInfo.TypeParameterBoundTarget.create(typeParameterIndex, boundIndex++));
       }
       typeParameterIndex++;
     }
@@ -864,7 +863,7 @@ public class Lower {
           lowerClassTypeTypeAnnotations((ClassTy) type, path);
           break;
         case ARRAY_TY:
-          lowerArrayTypeAnnotations(type, path);
+          lowerArrayTypeAnnotations((ArrayTy) type, path);
           break;
         case WILD_TY:
           lowerWildTyTypeAnnotations((WildTy) type, path);
@@ -903,19 +902,9 @@ public class Lower {
       }
     }
 
-    private void lowerArrayTypeAnnotations(Type type, TypePath path) {
-      Type base = type;
-      Deque<ArrayTy> flat = new ArrayDeque<>();
-      while (base instanceof ArrayTy) {
-        ArrayTy arrayTy = (ArrayTy) base;
-        flat.addFirst(arrayTy);
-        base = arrayTy.elementType();
-      }
-      for (ArrayTy arrayTy : flat) {
-        lowerTypeAnnotations(arrayTy.annos(), path);
-        path = path.array();
-      }
-      lowerTypeAnnotations(base, path);
+    private void lowerArrayTypeAnnotations(ArrayTy type, TypePath path) {
+      lowerTypeAnnotations(type.annos(), path);
+      lowerTypeAnnotations(type.elementType(), path.array());
     }
 
     private void lowerClassTypeTypeAnnotations(ClassTy type, TypePath path) {
diff --git a/java/com/google/turbine/lower/LowerSignature.java b/java/com/google/turbine/lower/LowerSignature.java
index 1960f8e..05a10a1 100644
--- a/java/com/google/turbine/lower/LowerSignature.java
+++ b/java/com/google/turbine/lower/LowerSignature.java
@@ -46,7 +46,7 @@ import java.util.Iterator;
 import java.util.LinkedHashSet;
 import java.util.Map;
 import java.util.Set;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Translator from {@link Type}s to {@link Sig}natures. */
 public class LowerSignature {
diff --git a/java/com/google/turbine/main/Main.java b/java/com/google/turbine/main/Main.java
index c246a7a..226686f 100644
--- a/java/com/google/turbine/main/Main.java
+++ b/java/com/google/turbine/main/Main.java
@@ -83,7 +83,7 @@ public final class Main {
   static final Attributes.Name TARGET_LABEL = new Attributes.Name("Target-Label");
   static final Attributes.Name INJECTING_RULE_KIND = new Attributes.Name("Injecting-Rule-Kind");
 
-  public static void main(String[] args) throws IOException {
+  public static void main(String[] args) {
     boolean ok;
     try {
       compile(args);
@@ -218,7 +218,7 @@ public final class Main {
         }
       }
       if (options.output().isPresent()) {
-        Map<String, byte[]> transitive = Transitive.collectDeps(bootclasspath, bound);
+        ImmutableMap<String, byte[]> transitive = Transitive.collectDeps(bootclasspath, bound);
         writeOutput(options, bound.generatedClasses(), lowered.bytes(), transitive);
       }
       if (options.outputManifest().isPresent()) {
@@ -301,16 +301,7 @@ public final class Main {
     }
 
     if (release.isPresent()) {
-      if (release.getAsInt() == Integer.parseInt(JAVA_SPECIFICATION_VERSION.value())) {
-        // if --release matches the host JDK, use its jimage instead of ct.sym
-        return JimageClassBinder.bindDefault();
-      }
-      // ... otherwise, search ct.sym for a matching release
-      ClassPath bootclasspath = CtSymClassBinder.bind(release.getAsInt());
-      if (bootclasspath == null) {
-        throw new UsageException("not a supported release: " + release);
-      }
-      return bootclasspath;
+      return release(release.getAsInt());
     }
 
     if (options.system().isPresent()) {
@@ -322,6 +313,19 @@ public final class Main {
     return ClassPathBinder.bindClasspath(toPaths(options.bootClassPath()));
   }
 
+  private static ClassPath release(int release) throws IOException {
+    // Search ct.sym for a matching release
+    ClassPath bootclasspath = CtSymClassBinder.bind(release);
+    if (bootclasspath != null) {
+      return bootclasspath;
+    }
+    if (release == Integer.parseInt(JAVA_SPECIFICATION_VERSION.value())) {
+      // if --release matches the host JDK, use its jimage
+      return JimageClassBinder.bindDefault();
+    }
+    throw new UsageException("not a supported release: " + release);
+  }
+
   /** Parse all source files and source jars. */
   // TODO(cushon): parallelize
   private static ImmutableList<CompUnit> parseAll(TurbineOptions options) throws IOException {
@@ -369,10 +373,10 @@ public final class Main {
     try (OutputStream os = Files.newOutputStream(path);
         BufferedOutputStream bos = new BufferedOutputStream(os, BUFFER_SIZE);
         JarOutputStream jos = new JarOutputStream(bos)) {
+      writeManifest(jos, manifest());
       for (SourceFile source : generatedSources.values()) {
         addEntry(jos, source.path(), source.source().getBytes(UTF_8));
       }
-      writeManifest(jos, manifest());
     }
   }
 
@@ -412,19 +416,21 @@ public final class Main {
     try (OutputStream os = Files.newOutputStream(path);
         BufferedOutputStream bos = new BufferedOutputStream(os, BUFFER_SIZE);
         JarOutputStream jos = new JarOutputStream(bos)) {
+      if (options.targetLabel().isPresent()) {
+        writeManifest(jos, manifest(options));
+      }
+      for (Map.Entry<String, byte[]> entry : transitive.entrySet()) {
+        addEntry(
+            jos,
+            ClassPathBinder.TRANSITIVE_PREFIX + entry.getKey() + ClassPathBinder.TRANSITIVE_SUFFIX,
+            entry.getValue());
+      }
       for (Map.Entry<String, byte[]> entry : lowered.entrySet()) {
         addEntry(jos, entry.getKey() + ".class", entry.getValue());
       }
       for (Map.Entry<String, byte[]> entry : generated.entrySet()) {
         addEntry(jos, entry.getKey(), entry.getValue());
       }
-      for (Map.Entry<String, byte[]> entry : transitive.entrySet()) {
-        addEntry(
-            jos, ClassPathBinder.TRANSITIVE_PREFIX + entry.getKey() + ".class", entry.getValue());
-      }
-      if (options.targetLabel().isPresent()) {
-        writeManifest(jos, manifest(options));
-      }
     }
   }
 
diff --git a/java/com/google/turbine/model/Const.java b/java/com/google/turbine/model/Const.java
index bd90f59..40431c6 100644
--- a/java/com/google/turbine/model/Const.java
+++ b/java/com/google/turbine/model/Const.java
@@ -18,10 +18,10 @@ package com.google.turbine.model;
 
 import com.google.common.base.Joiner;
 import com.google.common.collect.ImmutableList;
-import com.google.common.escape.SourceCodeEscapers;
+import com.google.turbine.escape.SourceCodeEscapers;
 import javax.lang.model.element.AnnotationValue;
 import javax.lang.model.element.AnnotationValueVisitor;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Compile-time constant expressions, including literals of primitive or String type, class
diff --git a/java/com/google/turbine/model/TurbineConstantTypeKind.java b/java/com/google/turbine/model/TurbineConstantTypeKind.java
index bb5bea1..8968a4d 100644
--- a/java/com/google/turbine/model/TurbineConstantTypeKind.java
+++ b/java/com/google/turbine/model/TurbineConstantTypeKind.java
@@ -27,7 +27,7 @@ public enum TurbineConstantTypeKind {
   BOOLEAN("boolean"),
   BYTE("byte"),
   STRING("String"),
-  NULL("null");
+  NULL("<nulltype>");
 
   private final String name;
 
diff --git a/java/com/google/turbine/model/TurbineFlag.java b/java/com/google/turbine/model/TurbineFlag.java
index 3e68a5e..abc6770 100644
--- a/java/com/google/turbine/model/TurbineFlag.java
+++ b/java/com/google/turbine/model/TurbineFlag.java
@@ -52,6 +52,9 @@ public final class TurbineFlag {
   /** Default methods. */
   public static final int ACC_DEFAULT = 1 << 16;
 
+  /** Enum constants with class bodies. */
+  public static final int ACC_ENUM_IMPL = 1 << 17;
+
   /** Synthetic constructors (e.g. of inner classes and enums). */
   public static final int ACC_SYNTH_CTOR = 1 << 18;
 
diff --git a/java/com/google/turbine/options/TurbineOptionsParser.java b/java/com/google/turbine/options/TurbineOptionsParser.java
index e68a546..39d1a41 100644
--- a/java/com/google/turbine/options/TurbineOptionsParser.java
+++ b/java/com/google/turbine/options/TurbineOptionsParser.java
@@ -18,8 +18,6 @@ package com.google.turbine.options;
 
 import static com.google.common.base.Preconditions.checkArgument;
 
-import com.google.common.base.CharMatcher;
-import com.google.common.base.Splitter;
 import com.google.common.collect.ImmutableList;
 import com.google.turbine.options.TurbineOptions.ReducedClasspathMode;
 import java.io.IOException;
@@ -150,6 +148,10 @@ public final class TurbineOptionsParser {
           // accepted (and ignored) for compatibility with JavaBuilder command lines
           readOne(next, argumentDeque);
           break;
+        case "--post_processor":
+          // accepted (and ignored) for compatibility with JavaBuilder command lines
+          ImmutableList<String> unused = readList(argumentDeque);
+          break;
         case "--compress_jar":
           // accepted (and ignored) for compatibility with JavaBuilder command lines
           break;
@@ -159,9 +161,6 @@ public final class TurbineOptionsParser {
     }
   }
 
-  private static final Splitter ARG_SPLITTER =
-      Splitter.on(CharMatcher.breakingWhitespace()).omitEmptyStrings().trimResults();
-
   /**
    * Pre-processes an argument list, expanding arguments of the form {@code @filename} by reading
    * the content of the file and appending whitespace-delimited options to {@code argumentDeque}.
@@ -186,7 +185,7 @@ public final class TurbineOptionsParser {
         if (!Files.exists(paramsPath)) {
           throw new AssertionError("params file does not exist: " + paramsPath);
         }
-        expandParamsFiles(argumentDeque, ARG_SPLITTER.split(Files.readString(paramsPath)));
+        expandParamsFiles(argumentDeque, Files.readAllLines(paramsPath));
       } else {
         argumentDeque.addLast(arg);
       }
diff --git a/java/com/google/turbine/options/package-info.java b/java/com/google/turbine/options/package-info.java
index 45bad5e..c6d227a 100644
--- a/java/com/google/turbine/options/package-info.java
+++ b/java/com/google/turbine/options/package-info.java
@@ -14,5 +14,5 @@
  * limitations under the License.
  */
 
-@org.jspecify.nullness.NullMarked
+@org.jspecify.annotations.NullMarked
 package com.google.turbine.options;
diff --git a/java/com/google/turbine/parse/ConstExpressionParser.java b/java/com/google/turbine/parse/ConstExpressionParser.java
index e4aad6b..1db47cb 100644
--- a/java/com/google/turbine/parse/ConstExpressionParser.java
+++ b/java/com/google/turbine/parse/ConstExpressionParser.java
@@ -32,7 +32,7 @@ import com.google.turbine.tree.Tree.Expression;
 import com.google.turbine.tree.Tree.Ident;
 import com.google.turbine.tree.TurbineOperatorKind;
 import java.util.Optional;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A parser for compile-time constant expressions. */
 public class ConstExpressionParser {
diff --git a/java/com/google/turbine/parse/Parser.java b/java/com/google/turbine/parse/Parser.java
index acf84d7..7fed666 100644
--- a/java/com/google/turbine/parse/Parser.java
+++ b/java/com/google/turbine/parse/Parser.java
@@ -60,12 +60,10 @@ import com.google.turbine.tree.Tree.Type;
 import com.google.turbine.tree.Tree.VarDecl;
 import com.google.turbine.tree.Tree.WildTy;
 import com.google.turbine.tree.TurbineModifier;
-import java.util.ArrayDeque;
-import java.util.Deque;
 import java.util.EnumSet;
 import java.util.List;
 import java.util.Optional;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * A parser for the subset of Java required for header compilation.
@@ -212,7 +210,11 @@ public class Parser {
                 && (ident.value().equals("module") || ident.value().equals("open"))) {
               boolean open = false;
               if (ident.value().equals("open")) {
-                ident = eatIdent();
+                next();
+                if (token != IDENT) {
+                  throw error(token);
+                }
+                ident = ident();
                 open = true;
               }
               if (!ident.value().equals("module")) {
@@ -462,12 +464,12 @@ public class Parser {
       if (token == Token.IDENT && lexer.stringValue().equals("transitive")) {
         next();
         access.add(TurbineModifier.TRANSITIVE);
-        break;
+        continue;
       }
       if (token == Token.STATIC) {
         next();
         access.add(TurbineModifier.STATIC);
-        break;
+        continue;
       }
       break;
     }
@@ -552,15 +554,17 @@ public class Parser {
             if (token == Token.LPAREN) {
               dropParens();
             }
+            EnumSet<TurbineModifier> access = EnumSet.copyOf(ENUM_CONSTANT_MODIFIERS);
             // TODO(cushon): consider desugaring enum constants later
             if (token == Token.LBRACE) {
               dropBlocks();
+              access.add(TurbineModifier.ENUM_IMPL);
             }
             maybe(Token.COMMA);
             result.add(
                 new VarDecl(
                     position,
-                    ENUM_CONSTANT_MODIFIERS,
+                    access,
                     annos.build(),
                     new ClassTy(
                         position,
@@ -894,14 +898,12 @@ public class Parser {
                   ident,
                   ImmutableList.<Type>of(),
                   ImmutableList.of());
-          result = maybeDims(maybeAnnos(), result);
           break;
         }
       case LT:
         {
           result =
               new ClassTy(position, Optional.<ClassTy>empty(), ident, tyargs(), ImmutableList.of());
-          result = maybeDims(maybeAnnos(), result);
           break;
         }
       case DOT:
@@ -927,7 +929,7 @@ public class Parser {
       }
       result = classty((ClassTy) result);
     }
-    result = maybeDims(maybeAnnos(), result);
+    result = maybeDims(result);
     pos = position;
     name = eatIdent();
     switch (token) {
@@ -1101,34 +1103,7 @@ public class Parser {
    * int [] @A [] x}, not {@code int @A [] [] x}.
    */
   private Type extraDims(Type ty) {
-    ImmutableList<Anno> annos = maybeAnnos();
-    if (!annos.isEmpty() && token != Token.LBRACK) {
-      // orphaned type annotations
-      throw error(token);
-    }
-    Deque<ImmutableList<Anno>> extra = new ArrayDeque<>();
-    while (maybe(Token.LBRACK)) {
-      eat(Token.RBRACK);
-      extra.push(annos);
-      annos = maybeAnnos();
-    }
-    ty = extraDims(ty, extra);
-    return ty;
-  }
-
-  private Type extraDims(Type type, Deque<ImmutableList<Anno>> extra) {
-    if (extra.isEmpty()) {
-      return type;
-    }
-    if (type == null) {
-      // trailing dims without a type, e.g. for a constructor declaration
-      throw error(token);
-    }
-    if (type.kind() == Kind.ARR_TY) {
-      ArrTy arrTy = (ArrTy) type;
-      return new ArrTy(arrTy.position(), arrTy.annos(), extraDims(arrTy.elem(), extra));
-    }
-    return new ArrTy(type.position(), extra.pop(), extraDims(type, extra));
+    return maybeDims(ty);
   }
 
   private ImmutableList<ClassTy> exceptions() {
@@ -1159,29 +1134,7 @@ public class Parser {
     ImmutableList.Builder<Anno> annos = ImmutableList.builder();
     EnumSet<TurbineModifier> access = modifiersAndAnnotations(annos);
     Type ty = referenceTypeWithoutDims(ImmutableList.of());
-    ImmutableList<Anno> typeAnnos = maybeAnnos();
-    OUTER:
-    while (true) {
-      switch (token) {
-        case LBRACK:
-          next();
-          eat(Token.RBRACK);
-          ty = new ArrTy(position, typeAnnos, ty);
-          typeAnnos = maybeAnnos();
-          break;
-        case ELLIPSIS:
-          next();
-          access.add(VARARGS);
-          ty = new ArrTy(position, typeAnnos, ty);
-          typeAnnos = ImmutableList.of();
-          break OUTER;
-        default:
-          break OUTER;
-      }
-    }
-    if (!typeAnnos.isEmpty()) {
-      throw error(token);
-    }
+    ty = paramDims(access, ty);
     // the parameter name is `this` for receiver parameters, and a qualified this expression
     // for inner classes
     Ident name = identOrThis();
@@ -1195,6 +1148,25 @@ public class Parser {
         position, access, annos.build(), ty, name, Optional.<Expression>empty(), null);
   }
 
+  private Type paramDims(EnumSet<TurbineModifier> access, Type ty) {
+    ImmutableList<Anno> typeAnnos = maybeAnnos();
+    switch (token) {
+      case LBRACK:
+        next();
+        eat(Token.RBRACK);
+        return new ArrTy(position, typeAnnos, paramDims(access, ty));
+      case ELLIPSIS:
+        next();
+        access.add(VARARGS);
+        return new ArrTy(position, typeAnnos, ty);
+      default:
+        if (!typeAnnos.isEmpty()) {
+          throw error(token);
+        }
+        return ty;
+    }
+  }
+
   private Ident identOrThis() {
     switch (token) {
       case IDENT:
@@ -1415,14 +1387,17 @@ public class Parser {
 
   private Type referenceType(ImmutableList<Anno> typeAnnos) {
     Type ty = referenceTypeWithoutDims(typeAnnos);
-    return maybeDims(maybeAnnos(), ty);
+    return maybeDims(ty);
   }
 
-  private Type maybeDims(ImmutableList<Anno> typeAnnos, Type ty) {
-    while (maybe(Token.LBRACK)) {
+  private Type maybeDims(Type ty) {
+    ImmutableList<Anno> typeAnnos = maybeAnnos();
+    if (maybe(Token.LBRACK)) {
       eat(Token.RBRACK);
-      ty = new ArrTy(position, typeAnnos, ty);
-      typeAnnos = maybeAnnos();
+      return new ArrTy(position, typeAnnos, maybeDims(ty));
+    }
+    if (!typeAnnos.isEmpty()) {
+      throw error(token);
     }
     return ty;
   }
diff --git a/java/com/google/turbine/parse/StreamLexer.java b/java/com/google/turbine/parse/StreamLexer.java
index ed79dd0..a14b826 100644
--- a/java/com/google/turbine/parse/StreamLexer.java
+++ b/java/com/google/turbine/parse/StreamLexer.java
@@ -25,7 +25,7 @@ import com.google.common.collect.ImmutableList;
 import com.google.turbine.diag.SourceFile;
 import com.google.turbine.diag.TurbineError;
 import com.google.turbine.diag.TurbineError.ErrorKind;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A {@link Lexer} that streams input from a {@link UnicodeEscapePreprocessor}. */
 public class StreamLexer implements Lexer {
@@ -497,6 +497,17 @@ public class StreamLexer implements Lexer {
           value = translateEscapes(value);
           saveValue(value);
           return Token.STRING_LITERAL;
+        case '\\':
+          // Escapes are handled later (after stripping indentation), but we need to ensure
+          // that \" escapes don't count towards the closing delimiter of the text block.
+          sb.appendCodePoint(ch);
+          eat();
+          if (ch == ASCII_SUB && reader.done()) {
+            return Token.EOF;
+          }
+          sb.appendCodePoint(ch);
+          eat();
+          continue;
         case ASCII_SUB:
           if (reader.done()) {
             return Token.EOF;
@@ -573,10 +584,21 @@ public class StreamLexer implements Lexer {
     return i + 1;
   }
 
-  private static String translateEscapes(String value) {
+  private String translateEscapes(String value) {
     StreamLexer lexer =
         new StreamLexer(new UnicodeEscapePreprocessor(new SourceFile(null, value + ASCII_SUB)));
-    return lexer.translateEscapes();
+    try {
+      return lexer.translateEscapes();
+    } catch (TurbineError e) {
+      // Rethrow since the source positions above are relative to the text block, not the entire
+      // file. This means that diagnostics for invalid escapes in text blocks will be emitted at the
+      // delimiter.
+      // TODO(cushon): consider merging this into stripIndent and tracking the real position
+      throw new TurbineError(
+          e.diagnostics().stream()
+              .map(d -> d.withPosition(reader.source(), reader.position()))
+              .collect(toImmutableList()));
+    }
   }
 
   private String translateEscapes() {
@@ -587,7 +609,20 @@ public class StreamLexer implements Lexer {
       switch (ch) {
         case '\\':
           eat();
-          sb.append(escape());
+          switch (ch) {
+            case '\r':
+              eat();
+              if (ch == '\n') {
+                eat();
+              }
+              break;
+            case '\n':
+              eat();
+              break;
+            default:
+              sb.append(escape());
+              break;
+          }
           continue;
         case ASCII_SUB:
           break OUTER;
@@ -618,6 +653,9 @@ public class StreamLexer implements Lexer {
       case 'r':
         eat();
         return '\r';
+      case 's':
+        eat();
+        return ' ';
       case '"':
         eat();
         return '\"';
diff --git a/java/com/google/turbine/parse/VariableInitializerParser.java b/java/com/google/turbine/parse/VariableInitializerParser.java
index 7f4d40e..3a0a51d 100644
--- a/java/com/google/turbine/parse/VariableInitializerParser.java
+++ b/java/com/google/turbine/parse/VariableInitializerParser.java
@@ -266,7 +266,23 @@ public class VariableInitializerParser {
   }
 
   private void save() {
-    tokens.add(new SavedToken(token, lexer.stringValue(), lexer.position()));
+    String value;
+    switch (token) {
+      case IDENT:
+      case INT_LITERAL:
+      case LONG_LITERAL:
+      case DOUBLE_LITERAL:
+      case FLOAT_LITERAL:
+      case STRING_LITERAL:
+      case CHAR_LITERAL:
+        value = lexer.stringValue();
+        break;
+      default:
+        // memory optimization: don't save string values for tokens that don't require them
+        value = null;
+        break;
+    }
+    tokens.add(new SavedToken(token, value, lexer.position()));
   }
 
   private void dropBracks(int many) {
diff --git a/java/com/google/turbine/processing/ModelFactory.java b/java/com/google/turbine/processing/ModelFactory.java
index 160d5ae..eb332bc 100644
--- a/java/com/google/turbine/processing/ModelFactory.java
+++ b/java/com/google/turbine/processing/ModelFactory.java
@@ -79,6 +79,7 @@ import java.util.HashMap;
 import java.util.Map;
 import java.util.concurrent.atomic.AtomicInteger;
 import javax.lang.model.element.Element;
+import javax.lang.model.element.RecordComponentElement;
 import javax.lang.model.element.VariableElement;
 import javax.lang.model.type.NoType;
 import javax.lang.model.type.NullType;
@@ -270,7 +271,7 @@ public class ModelFactory {
     return paramCache.computeIfAbsent(sym, k -> new TurbineParameterElement(this, sym));
   }
 
-  VariableElement recordComponentElement(RecordComponentSymbol sym) {
+  RecordComponentElement recordComponentElement(RecordComponentSymbol sym) {
     return recordComponentCache.computeIfAbsent(
         sym, k -> new TurbineRecordComponentElement(this, sym));
   }
diff --git a/java/com/google/turbine/processing/TurbineAnnotationMirror.java b/java/com/google/turbine/processing/TurbineAnnotationMirror.java
index f99d211..bab2d3f 100644
--- a/java/com/google/turbine/processing/TurbineAnnotationMirror.java
+++ b/java/com/google/turbine/processing/TurbineAnnotationMirror.java
@@ -45,7 +45,7 @@ import javax.lang.model.element.ExecutableElement;
 import javax.lang.model.type.DeclaredType;
 import javax.lang.model.type.ErrorType;
 import javax.lang.model.type.TypeMirror;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * An implementation of {@link AnnotationMirror} and {@link AnnotationValue} backed by {@link
@@ -91,7 +91,8 @@ class TurbineAnnotationMirror implements TurbineAnnotationValueMirror, Annotatio
               public DeclaredType get() {
                 if (anno.sym() == null) {
                   return (ErrorType)
-                      factory.asTypeMirror(ErrorTy.create(getLast(anno.tree().name()).value()));
+                      factory.asTypeMirror(
+                          ErrorTy.create(getLast(anno.tree().name()).value(), ImmutableList.of()));
                 }
                 return (DeclaredType) factory.typeElement(anno.sym()).asType();
               }
diff --git a/java/com/google/turbine/processing/TurbineElement.java b/java/com/google/turbine/processing/TurbineElement.java
index 95f0f42..72d5ffd 100644
--- a/java/com/google/turbine/processing/TurbineElement.java
+++ b/java/com/google/turbine/processing/TurbineElement.java
@@ -23,6 +23,7 @@ import com.google.common.base.Splitter;
 import com.google.common.base.Supplier;
 import com.google.common.base.Suppliers;
 import com.google.common.collect.ImmutableList;
+import com.google.common.collect.ImmutableMap;
 import com.google.common.collect.ImmutableSet;
 import com.google.common.collect.Iterables;
 import com.google.common.collect.Sets;
@@ -49,9 +50,7 @@ import com.google.turbine.diag.TurbineError.ErrorKind;
 import com.google.turbine.model.Const;
 import com.google.turbine.model.Const.ArrayInitValue;
 import com.google.turbine.model.TurbineFlag;
-import com.google.turbine.tree.Tree;
 import com.google.turbine.tree.Tree.MethDecl;
-import com.google.turbine.tree.Tree.TyDecl;
 import com.google.turbine.tree.Tree.VarDecl;
 import com.google.turbine.type.AnnoInfo;
 import com.google.turbine.type.Type;
@@ -63,6 +62,7 @@ import java.util.ArrayDeque;
 import java.util.ArrayList;
 import java.util.Deque;
 import java.util.EnumSet;
+import java.util.HashMap;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
@@ -78,11 +78,12 @@ import javax.lang.model.element.Modifier;
 import javax.lang.model.element.Name;
 import javax.lang.model.element.NestingKind;
 import javax.lang.model.element.PackageElement;
+import javax.lang.model.element.RecordComponentElement;
 import javax.lang.model.element.TypeElement;
 import javax.lang.model.element.TypeParameterElement;
 import javax.lang.model.element.VariableElement;
 import javax.lang.model.type.TypeMirror;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** An {@link Element} implementation backed by a {@link Symbol}. */
 @SuppressWarnings("nullness") // TODO(cushon): Address nullness diagnostics.
@@ -209,8 +210,7 @@ public abstract class TurbineElement implements Element {
               });
     }
 
-    @Nullable
-    TypeBoundClass info() {
+    @Nullable TypeBoundClass info() {
       return info.get();
     }
 
@@ -264,22 +264,9 @@ public abstract class TurbineElement implements Element {
                   case CLASS:
                   case ENUM:
                   case RECORD:
-                    if (info.superclass() != null) {
+                    if (info.superClassType() != null) {
                       return factory.asTypeMirror(info.superClassType());
                     }
-                    if (info instanceof SourceTypeBoundClass) {
-                      // support simple names for stuff that doesn't exist
-                      TyDecl decl = ((SourceTypeBoundClass) info).decl();
-                      if (decl.xtnds().isPresent()) {
-                        ArrayDeque<Tree.Ident> flat = new ArrayDeque<>();
-                        for (Tree.ClassTy curr = decl.xtnds().get();
-                            curr != null;
-                            curr = curr.base().orElse(null)) {
-                          flat.addFirst(curr.name());
-                        }
-                        return factory.asTypeMirror(ErrorTy.create(flat));
-                      }
-                    }
                     return factory.noType();
                   case INTERFACE:
                   case ANNOTATION:
@@ -339,10 +326,10 @@ public abstract class TurbineElement implements Element {
                 return factory.asTypeMirror(asGenericType(sym));
               }
 
-              ClassTy asGenericType(ClassSymbol symbol) {
+              Type asGenericType(ClassSymbol symbol) {
                 TypeBoundClass info = info();
                 if (info == null) {
-                  return ClassTy.asNonParametricClassTy(symbol);
+                  return ErrorTy.create(getQualifiedName().toString(), ImmutableList.of());
                 }
                 Deque<Type.ClassTy.SimpleClassTy> simples = new ArrayDeque<>();
                 simples.addFirst(simple(symbol, info));
@@ -435,6 +422,24 @@ public abstract class TurbineElement implements Element {
       return enclosing.get();
     }
 
+    private final Supplier<ImmutableList<TypeMirror>> permits =
+        memoize(
+            new Supplier<>() {
+              @Override
+              public ImmutableList<TypeMirror> get() {
+                ImmutableList.Builder<TypeMirror> result = ImmutableList.builder();
+                for (ClassSymbol p : infoNonNull().permits()) {
+                  result.add(factory.asTypeMirror(ClassTy.asNonParametricClassTy(p)));
+                }
+                return result.build();
+              }
+            });
+
+    @Override
+    public List<? extends TypeMirror> getPermittedSubclasses() {
+      return permits.get();
+    }
+
     private final Supplier<ImmutableList<Element>> enclosed =
         memoize(
             new Supplier<ImmutableList<Element>>() {
@@ -560,6 +565,48 @@ public abstract class TurbineElement implements Element {
       }
       return false;
     }
+
+    private final Supplier<ImmutableMap<RecordComponentSymbol, MethodSymbol>> recordAccessors =
+        memoize(
+            new Supplier<ImmutableMap<RecordComponentSymbol, MethodSymbol>>() {
+              @Override
+              public ImmutableMap<RecordComponentSymbol, MethodSymbol> get() {
+                Map<String, MethodSymbol> methods = new HashMap<>();
+                for (MethodInfo method : info().methods()) {
+                  if (method.parameters().isEmpty()) {
+                    methods.put(method.name(), method.sym());
+                  }
+                }
+                ImmutableMap.Builder<RecordComponentSymbol, MethodSymbol> result =
+                    ImmutableMap.builder();
+                for (RecordComponentInfo component : info().components()) {
+                  result.put(component.sym(), methods.get(component.name()));
+                }
+                return result.buildOrThrow();
+              }
+            });
+
+    ExecutableElement recordAccessor(RecordComponentSymbol component) {
+      return factory.executableElement(recordAccessors.get().get(component));
+    }
+
+    private final Supplier<ImmutableList<RecordComponentElement>> recordComponents =
+        memoize(
+            new Supplier<ImmutableList<RecordComponentElement>>() {
+              @Override
+              public ImmutableList<RecordComponentElement> get() {
+                ImmutableList.Builder<RecordComponentElement> result = ImmutableList.builder();
+                for (RecordComponentInfo component : info().components()) {
+                  result.add(factory.recordComponentElement(component.sym()));
+                }
+                return result.build();
+              }
+            });
+
+    @Override
+    public List<? extends RecordComponentElement> getRecordComponents() {
+      return recordComponents.get();
+    }
   }
 
   /** A {@link TypeParameterElement} implementation backed by a {@link TyVarSymbol}. */
@@ -614,7 +661,7 @@ public abstract class TurbineElement implements Element {
 
     @Override
     public TypeMirror asType() {
-      return factory.asTypeMirror(Type.TyVar.create(sym, info().annotations()));
+      return factory.asTypeMirror(Type.TyVar.create(sym, ImmutableList.of()));
     }
 
     @Override
@@ -677,8 +724,7 @@ public abstract class TurbineElement implements Element {
               }
             });
 
-    @Nullable
-    MethodInfo info() {
+    @Nullable MethodInfo info() {
       return info.get();
     }
 
@@ -883,8 +929,7 @@ public abstract class TurbineElement implements Element {
               }
             });
 
-    @Nullable
-    FieldInfo info() {
+    @Nullable FieldInfo info() {
       return info.get();
     }
 
@@ -996,7 +1041,12 @@ public abstract class TurbineElement implements Element {
     if ((access & TurbineFlag.ACC_STRICT) == TurbineFlag.ACC_STRICT) {
       modifiers.add(Modifier.STRICTFP);
     }
-
+    if ((access & TurbineFlag.ACC_SEALED) == TurbineFlag.ACC_SEALED) {
+      modifiers.add(Modifier.SEALED);
+    }
+    if ((access & TurbineFlag.ACC_NON_SEALED) == TurbineFlag.ACC_NON_SEALED) {
+      modifiers.add(Modifier.NON_SEALED);
+    }
     return Sets.immutableEnumSet(modifiers);
   }
 
@@ -1147,8 +1197,7 @@ public abstract class TurbineElement implements Element {
               }
             });
 
-    @Nullable
-    ParamInfo info() {
+    @Nullable ParamInfo info() {
       return info.get();
     }
 
@@ -1218,7 +1267,8 @@ public abstract class TurbineElement implements Element {
   }
 
   /** A {@link VariableElement} implementation for a record info. */
-  static class TurbineRecordComponentElement extends TurbineElement implements VariableElement {
+  static class TurbineRecordComponentElement extends TurbineElement
+      implements RecordComponentElement {
 
     @Override
     public RecordComponentSymbol sym() {
@@ -1252,8 +1302,7 @@ public abstract class TurbineElement implements Element {
               }
             });
 
-    @Nullable
-    RecordComponentInfo info() {
+    @Nullable RecordComponentInfo info() {
       return info.get();
     }
 
@@ -1262,11 +1311,6 @@ public abstract class TurbineElement implements Element {
       this.sym = sym;
     }
 
-    @Override
-    public Object getConstantValue() {
-      return null;
-    }
-
     private final Supplier<TypeMirror> type =
         memoize(
             new Supplier<TypeMirror>() {
@@ -1283,18 +1327,9 @@ public abstract class TurbineElement implements Element {
 
     @Override
     public ElementKind getKind() {
-      return RECORD_COMPONENT.get();
+      return ElementKind.RECORD_COMPONENT;
     }
 
-    private static final Supplier<ElementKind> RECORD_COMPONENT =
-        Suppliers.memoize(
-            new Supplier<ElementKind>() {
-              @Override
-              public ElementKind get() {
-                return ElementKind.valueOf("RECORD_COMPONENT");
-              }
-            });
-
     @Override
     public Set<Modifier> getModifiers() {
       return asModifierSet(ModifierOwner.PARAMETER, info().access());
@@ -1305,6 +1340,20 @@ public abstract class TurbineElement implements Element {
       return new TurbineName(sym.name());
     }
 
+    private final Supplier<ExecutableElement> accessor =
+        Suppliers.memoize(
+            new Supplier<ExecutableElement>() {
+              @Override
+              public ExecutableElement get() {
+                return factory.typeElement(sym.owner()).recordAccessor(sym);
+              }
+            });
+
+    @Override
+    public ExecutableElement getAccessor() {
+      return accessor.get();
+    }
+
     @Override
     public Element getEnclosingElement() {
       return factory.typeElement(sym.owner());
@@ -1317,7 +1366,7 @@ public abstract class TurbineElement implements Element {
 
     @Override
     public <R, P> R accept(ElementVisitor<R, P> v, P p) {
-      return v.visitVariable(this, p);
+      return v.visitRecordComponent(this, p);
     }
 
     @Override
diff --git a/java/com/google/turbine/processing/TurbineElements.java b/java/com/google/turbine/processing/TurbineElements.java
index 9b3ea26..c0ec1fe 100644
--- a/java/com/google/turbine/processing/TurbineElements.java
+++ b/java/com/google/turbine/processing/TurbineElements.java
@@ -53,7 +53,7 @@ import javax.lang.model.element.TypeElement;
 import javax.lang.model.type.DeclaredType;
 import javax.lang.model.type.TypeMirror;
 import javax.lang.model.util.Elements;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** An implementation of {@link Elements} backed by turbine's {@link Element}. */
 @SuppressWarnings("nullness") // TODO(cushon): Address nullness diagnostics.
diff --git a/java/com/google/turbine/processing/TurbineMessager.java b/java/com/google/turbine/processing/TurbineMessager.java
index 8e78b8b..5b66c0e 100644
--- a/java/com/google/turbine/processing/TurbineMessager.java
+++ b/java/com/google/turbine/processing/TurbineMessager.java
@@ -42,7 +42,7 @@ import javax.lang.model.element.AnnotationMirror;
 import javax.lang.model.element.AnnotationValue;
 import javax.lang.model.element.Element;
 import javax.tools.Diagnostic;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Turbine's implementation of {@link Messager}. */
 public class TurbineMessager implements Messager {
diff --git a/java/com/google/turbine/processing/TurbineName.java b/java/com/google/turbine/processing/TurbineName.java
index 5232491..c68be7d 100644
--- a/java/com/google/turbine/processing/TurbineName.java
+++ b/java/com/google/turbine/processing/TurbineName.java
@@ -19,7 +19,7 @@ package com.google.turbine.processing;
 import static java.util.Objects.requireNonNull;
 
 import javax.lang.model.element.Name;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** An implementation of {@link Name} backed by a {@link CharSequence}. */
 public class TurbineName implements Name {
diff --git a/java/com/google/turbine/processing/TurbineProcessingEnvironment.java b/java/com/google/turbine/processing/TurbineProcessingEnvironment.java
index 4f32033..492df8c 100644
--- a/java/com/google/turbine/processing/TurbineProcessingEnvironment.java
+++ b/java/com/google/turbine/processing/TurbineProcessingEnvironment.java
@@ -24,7 +24,7 @@ import javax.annotation.processing.ProcessingEnvironment;
 import javax.lang.model.SourceVersion;
 import javax.lang.model.util.Elements;
 import javax.lang.model.util.Types;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** Turbine's {@link ProcessingEnvironment}. */
 public class TurbineProcessingEnvironment implements ProcessingEnvironment {
diff --git a/java/com/google/turbine/processing/TurbineTypeMirror.java b/java/com/google/turbine/processing/TurbineTypeMirror.java
index 4cd8ba1..60ca690 100644
--- a/java/com/google/turbine/processing/TurbineTypeMirror.java
+++ b/java/com/google/turbine/processing/TurbineTypeMirror.java
@@ -19,7 +19,6 @@ package com.google.turbine.processing;
 import static com.google.common.collect.Iterables.getLast;
 import static java.util.Objects.requireNonNull;
 
-import com.google.common.base.Ascii;
 import com.google.common.base.Joiner;
 import com.google.common.base.Supplier;
 import com.google.common.collect.ImmutableList;
@@ -58,7 +57,7 @@ import javax.lang.model.type.TypeMirror;
 import javax.lang.model.type.TypeVariable;
 import javax.lang.model.type.TypeVisitor;
 import javax.lang.model.type.WildcardType;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A {@link TypeMirror} implementation backed by a {@link Type}. */
 public abstract class TurbineTypeMirror implements TypeMirror {
@@ -100,11 +99,6 @@ public abstract class TurbineTypeMirror implements TypeMirror {
   /** A {@link PrimitiveType} implementation backed by a {@link PrimTy}. */
   static class TurbinePrimitiveType extends TurbineTypeMirror implements PrimitiveType {
 
-    @Override
-    public String toString() {
-      return Ascii.toLowerCase(type.primkind().toString());
-    }
-
     @Override
     public Type asTurbineType() {
       return type;
@@ -182,11 +176,6 @@ public abstract class TurbineTypeMirror implements TypeMirror {
       this.type = type;
     }
 
-    @Override
-    public String toString() {
-      return type.toString();
-    }
-
     final Supplier<Element> element =
         factory.memoize(
             new Supplier<Element>() {
@@ -338,12 +327,7 @@ public abstract class TurbineTypeMirror implements TypeMirror {
 
     @Override
     public List<? extends TypeMirror> getTypeArguments() {
-      return ImmutableList.of();
-    }
-
-    @Override
-    public String toString() {
-      return type.toString();
+      return factory.asTypeMirrors(type.targs());
     }
   }
 
@@ -416,11 +400,6 @@ public abstract class TurbineTypeMirror implements TypeMirror {
       return v.visitNoType(this, p);
     }
 
-    @Override
-    public String toString() {
-      return "none";
-    }
-
     @Override
     public boolean equals(@Nullable Object other) {
       return other instanceof TurbineNoType;
@@ -527,12 +506,7 @@ public abstract class TurbineTypeMirror implements TypeMirror {
     public TypeMirror getLowerBound() {
       return info().lowerBound() != null
           ? factory.asTypeMirror(info().lowerBound())
-          : factory.noType();
-    }
-
-    @Override
-    public String toString() {
-      return type.toString();
+          : factory.nullType();
     }
 
     @Override
@@ -694,11 +668,6 @@ public abstract class TurbineTypeMirror implements TypeMirror {
   /** An {@link ExecutableType} implementation backed by a {@link MethodTy}. */
   public static class TurbineExecutableType extends TurbineTypeMirror implements ExecutableType {
 
-    @Override
-    public String toString() {
-      return type.toString();
-    }
-
     @Override
     public MethodTy asTurbineType() {
       return type;
diff --git a/java/com/google/turbine/processing/TurbineTypes.java b/java/com/google/turbine/processing/TurbineTypes.java
index 0b69bc3..972d629 100644
--- a/java/com/google/turbine/processing/TurbineTypes.java
+++ b/java/com/google/turbine/processing/TurbineTypes.java
@@ -18,6 +18,7 @@ package com.google.turbine.processing;
 
 import static com.google.common.base.Preconditions.checkArgument;
 import static com.google.common.base.Verify.verify;
+import static com.google.turbine.types.Deannotate.deannotate;
 import static java.util.Objects.requireNonNull;
 
 import com.google.common.collect.ImmutableList;
@@ -62,7 +63,7 @@ import javax.lang.model.type.TypeKind;
 import javax.lang.model.type.TypeMirror;
 import javax.lang.model.type.WildcardType;
 import javax.lang.model.util.Types;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** An implementation of {@link Types} backed by turbine's {@link TypeMirror}. */
 @SuppressWarnings("nullness") // TODO(cushon): Address nullness diagnostics.
@@ -109,6 +110,9 @@ public class TurbineTypes implements Types {
   }
 
   private boolean isSameType(Type a, Type b) {
+    if (b.tyKind() == TyKind.ERROR_TY) {
+      return true;
+    }
     switch (a.tyKind()) {
       case PRIM_TY:
         return b.tyKind() == TyKind.PRIM_TY && ((PrimTy) a).primkind() == ((PrimTy) b).primkind();
@@ -131,7 +135,7 @@ public class TurbineTypes implements Types {
       case METHOD_TY:
         return b.tyKind() == TyKind.METHOD_TY && isSameMethodType((MethodTy) a, (MethodTy) b);
       case ERROR_TY:
-        return false;
+        return true;
     }
     throw new AssertionError(a.tyKind());
   }
@@ -327,6 +331,9 @@ public class TurbineTypes implements Types {
    *     conversions.
    */
   private boolean isSubtype(Type a, Type b, boolean strict) {
+    if (a.tyKind() == TyKind.ERROR_TY || b.tyKind() == TyKind.ERROR_TY) {
+      return true;
+    }
     if (b.tyKind() == TyKind.INTERSECTION_TY) {
       for (Type bound : getBounds((IntersectionTy) b)) {
         // TODO(cushon): javac rejects e.g. `|List| isAssignable Serializable&ArrayList<?>`,
@@ -412,7 +419,8 @@ public class TurbineTypes implements Types {
   // https://docs.oracle.com/javase/specs/jls/se11/html/jls-4.html#jls-4.10.1
   private static boolean isPrimSubtype(PrimTy a, Type other) {
     if (other.tyKind() != TyKind.PRIM_TY) {
-      return false;
+      // The null reference can always be assigned or cast to any reference type, see JLS 4.1
+      return a.primkind() == TurbineConstantTypeKind.NULL && isReferenceType(other);
     }
     PrimTy b = (PrimTy) other;
     switch (a.primkind()) {
@@ -482,7 +490,7 @@ public class TurbineTypes implements Types {
       case BOOLEAN:
         return a.primkind() == b.primkind();
       case NULL:
-        break;
+        return isReferenceType(other);
     }
     throw new AssertionError(a.primkind());
   }
@@ -669,10 +677,17 @@ public class TurbineTypes implements Types {
   }
 
   private boolean isAssignable(Type t1, Type t2) {
+    if (t1.tyKind() == TyKind.ERROR_TY || t2.tyKind() == TyKind.ERROR_TY) {
+      return true;
+    }
     switch (t1.tyKind()) {
       case PRIM_TY:
+        TurbineConstantTypeKind primkind = ((PrimTy) t1).primkind();
+        if (primkind == TurbineConstantTypeKind.NULL) {
+          return isReferenceType(t2);
+        }
         if (t2.tyKind() == TyKind.CLASS_TY) {
-          ClassSymbol boxed = boxedClass(((PrimTy) t1).primkind());
+          ClassSymbol boxed = boxedClass(primkind);
           t1 = ClassTy.asNonParametricClassTy(boxed);
         }
         break;
@@ -699,6 +714,14 @@ public class TurbineTypes implements Types {
     return type.tyKind() == TyKind.CLASS_TY && ((ClassTy) type).sym().equals(ClassSymbol.OBJECT);
   }
 
+  private static boolean isReferenceType(Type type) {
+    return switch (type.tyKind()) {
+      case CLASS_TY, ARRAY_TY, TY_VAR, WILD_TY, INTERSECTION_TY, ERROR_TY -> true;
+      case PRIM_TY -> ((PrimTy) type).primkind() == TurbineConstantTypeKind.NULL;
+      case NONE_TY, METHOD_TY, VOID_TY -> false;
+    };
+  }
+
   @Override
   public boolean contains(TypeMirror a, TypeMirror b) {
     return contains(asTurbineType(a), asTurbineType(b), /* strict= */ true);
@@ -711,6 +734,9 @@ public class TurbineTypes implements Types {
   // See JLS 4.5.1, 'type containment'
   // https://docs.oracle.com/javase/specs/jls/se11/html/jls-4.html#jls-4.5.1
   private boolean containedBy(Type t1, Type t2, boolean strict) {
+    if (t1.tyKind() == TyKind.ERROR_TY) {
+      return true;
+    }
     if (t1.tyKind() == TyKind.WILD_TY) {
       WildTy w1 = (WildTy) t1;
       Type t;
@@ -876,19 +902,17 @@ public class TurbineTypes implements Types {
       builder.add(ClassTy.OBJECT);
     }
     for (Type interfaceType : info.interfaceTypes()) {
-      builder.add(raw ? erasure(interfaceType) : subst(interfaceType, mapping));
+      // ErrorTypes are not included in directSupertypes for compatibility with javac
+      if (interfaceType.tyKind() == TyKind.CLASS_TY) {
+        builder.add(raw ? erasure(interfaceType) : subst(interfaceType, mapping));
+      }
     }
     return builder.build();
   }
 
   @Override
   public TypeMirror erasure(TypeMirror typeMirror) {
-    Type t = erasure(asTurbineType(typeMirror));
-    if (t.tyKind() == TyKind.CLASS_TY) {
-      // bug-parity with javac
-      t = deannotate(t);
-    }
-    return factory.asTypeMirror(t);
+    return factory.asTypeMirror(deannotate(erasure(asTurbineType(typeMirror))));
   }
 
   private Type erasure(Type type) {
@@ -902,50 +926,6 @@ public class TurbineTypes implements Types {
         });
   }
 
-  /**
-   * Remove some type annotation metadata for bug-compatibility with javac, which does this
-   * inconsistently (see https://bugs.openjdk.java.net/browse/JDK-8042981).
-   */
-  private static Type deannotate(Type ty) {
-    switch (ty.tyKind()) {
-      case CLASS_TY:
-        return deannotateClassTy((Type.ClassTy) ty);
-      case ARRAY_TY:
-        return deannotateArrayTy((Type.ArrayTy) ty);
-      case TY_VAR:
-      case INTERSECTION_TY:
-      case WILD_TY:
-      case METHOD_TY:
-      case PRIM_TY:
-      case VOID_TY:
-      case ERROR_TY:
-      case NONE_TY:
-        return ty;
-    }
-    throw new AssertionError(ty.tyKind());
-  }
-
-  private static ImmutableList<Type> deannotate(ImmutableList<Type> types) {
-    ImmutableList.Builder<Type> result = ImmutableList.builder();
-    for (Type type : types) {
-      result.add(deannotate(type));
-    }
-    return result.build();
-  }
-
-  private static Type.ArrayTy deannotateArrayTy(Type.ArrayTy ty) {
-    return ArrayTy.create(deannotate(ty.elementType()), /* annos= */ ImmutableList.of());
-  }
-
-  public static Type.ClassTy deannotateClassTy(Type.ClassTy ty) {
-    ImmutableList.Builder<Type.ClassTy.SimpleClassTy> classes = ImmutableList.builder();
-    for (Type.ClassTy.SimpleClassTy c : ty.classes()) {
-      classes.add(
-          SimpleClassTy.create(c.sym(), deannotate(c.targs()), /* annos= */ ImmutableList.of()));
-    }
-    return ClassTy.create(classes.build());
-  }
-
   @Override
   public TypeElement boxedClass(PrimitiveType p) {
     return factory.typeElement(boxedClass(((PrimTy) asTurbineType(p)).primkind()));
diff --git a/java/com/google/turbine/tree/Pretty.java b/java/com/google/turbine/tree/Pretty.java
index 4ebc04f..96643bb 100644
--- a/java/com/google/turbine/tree/Pretty.java
+++ b/java/com/google/turbine/tree/Pretty.java
@@ -35,7 +35,7 @@ import com.google.turbine.tree.Tree.ModUses;
 import java.util.ArrayList;
 import java.util.Collections;
 import java.util.List;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** A pretty-printer for {@link Tree}s. */
 public class Pretty implements Tree.Visitor<@Nullable Void, @Nullable Void> {
@@ -108,17 +108,28 @@ public class Pretty implements Tree.Visitor<@Nullable Void, @Nullable Void> {
 
   @Override
   public @Nullable Void visitArrTy(Tree.ArrTy arrTy, @Nullable Void input) {
-    arrTy.elem().accept(this, null);
-    if (!arrTy.annos().isEmpty()) {
-      append(' ');
-      printAnnos(arrTy.annos());
+    ImmutableList.Builder<Tree.ArrTy> flat = ImmutableList.builder();
+    Tree next = arrTy;
+    do {
+      Tree.ArrTy curr = (Tree.ArrTy) next;
+      flat.add(curr);
+      next = curr.elem();
+    } while (next.kind().equals(Tree.Kind.ARR_TY));
+
+    next.accept(this, null);
+    for (Tree.ArrTy dim : flat.build()) {
+      if (!dim.annos().isEmpty()) {
+        append(' ');
+        printAnnos(dim.annos());
+      }
+      append("[]");
     }
-    append("[]");
     return null;
   }
 
   @Override
   public @Nullable Void visitPrimTy(Tree.PrimTy primTy, @Nullable Void input) {
+    printAnnos(primTy.annos());
     append(primTy.tykind().toString());
     return null;
   }
@@ -545,6 +556,7 @@ public class Pretty implements Tree.Visitor<@Nullable Void, @Nullable Void> {
         case ACC_SYNTHETIC:
         case ACC_BRIDGE:
         case COMPACT_CTOR:
+        case ENUM_IMPL:
           break;
       }
     }
diff --git a/java/com/google/turbine/tree/Tree.java b/java/com/google/turbine/tree/Tree.java
index f7917b9..da09244 100644
--- a/java/com/google/turbine/tree/Tree.java
+++ b/java/com/google/turbine/tree/Tree.java
@@ -29,7 +29,7 @@ import java.util.ArrayDeque;
 import java.util.Deque;
 import java.util.Optional;
 import java.util.Set;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** An AST node. */
 public abstract class Tree {
@@ -856,6 +856,7 @@ public abstract class Tree {
     public Optional<Tree> defaultValue() {
       return defaultValue;
     }
+
     /**
      * A javadoc comment, excluding the opening and closing delimiters but including all interior
      * characters and whitespace.
@@ -1017,6 +1018,7 @@ public abstract class Tree {
     public TurbineTyKind tykind() {
       return tykind;
     }
+
     /**
      * A javadoc comment, excluding the opening and closing delimiters but including all interior
      * characters and whitespace.
diff --git a/java/com/google/turbine/tree/TurbineModifier.java b/java/com/google/turbine/tree/TurbineModifier.java
index 2bfe53e..9400253 100644
--- a/java/com/google/turbine/tree/TurbineModifier.java
+++ b/java/com/google/turbine/tree/TurbineModifier.java
@@ -48,7 +48,8 @@ public enum TurbineModifier {
   TRANSITIVE(TurbineFlag.ACC_TRANSITIVE),
   SEALED(TurbineFlag.ACC_SEALED),
   NON_SEALED(TurbineFlag.ACC_NON_SEALED),
-  COMPACT_CTOR(TurbineFlag.ACC_COMPACT_CTOR);
+  COMPACT_CTOR(TurbineFlag.ACC_COMPACT_CTOR),
+  ENUM_IMPL(TurbineFlag.ACC_ENUM_IMPL);
 
   private final int flag;
 
diff --git a/java/com/google/turbine/tree/package-info.java b/java/com/google/turbine/tree/package-info.java
index 2803c67..47cd970 100644
--- a/java/com/google/turbine/tree/package-info.java
+++ b/java/com/google/turbine/tree/package-info.java
@@ -15,5 +15,5 @@
  */
 
 @com.google.errorprone.annotations.CheckReturnValue
-@org.jspecify.nullness.NullMarked
+@org.jspecify.annotations.NullMarked
 package com.google.turbine.tree;
diff --git a/java/com/google/turbine/type/AnnoInfo.java b/java/com/google/turbine/type/AnnoInfo.java
index d42af5c..805ae75 100644
--- a/java/com/google/turbine/type/AnnoInfo.java
+++ b/java/com/google/turbine/type/AnnoInfo.java
@@ -29,7 +29,7 @@ import com.google.turbine.tree.Tree.Anno;
 import com.google.turbine.tree.Tree.Expression;
 import java.util.Map;
 import java.util.Objects;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** An annotation use. */
 public class AnnoInfo {
diff --git a/java/com/google/turbine/type/Type.java b/java/com/google/turbine/type/Type.java
index 5fbf1b1..51b76c1 100644
--- a/java/com/google/turbine/type/Type.java
+++ b/java/com/google/turbine/type/Type.java
@@ -33,7 +33,7 @@ import com.google.turbine.tree.Tree;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /** JLS 4 types. */
 public interface Type {
@@ -308,6 +308,8 @@ public interface Type {
   }
 
   /** A primitive type. */
+  // TODO: cushon - consider renaming this, since it models things like String and null that can
+  // appear as constants and not primitives.
   @AutoValue
   abstract class PrimTy implements Type {
 
@@ -544,9 +546,11 @@ public interface Type {
   final class ErrorTy implements Type {
 
     private final String name;
+    private final ImmutableList<Type> targs;
 
-    private ErrorTy(String name) {
+    private ErrorTy(String name, ImmutableList<Type> targs) {
       this.name = requireNonNull(name);
+      this.targs = requireNonNull(targs);
     }
 
     /**
@@ -557,16 +561,20 @@ public interface Type {
       return name;
     }
 
-    public static ErrorTy create(Iterable<Tree.Ident> names) {
+    public ImmutableList<Type> targs() {
+      return targs;
+    }
+
+    public static ErrorTy create(Iterable<Tree.Ident> names, ImmutableList<Type> targs) {
       List<String> bits = new ArrayList<>();
       for (Tree.Ident ident : names) {
         bits.add(ident.value());
       }
-      return create(Joiner.on('.').join(bits));
+      return create(Joiner.on('.').join(bits), targs);
     }
 
-    public static ErrorTy create(String name) {
-      return new ErrorTy(name);
+    public static ErrorTy create(String name, ImmutableList<Type> targs) {
+      return new ErrorTy(name, targs);
     }
 
     @Override
@@ -576,7 +584,14 @@ public interface Type {
 
     @Override
     public final String toString() {
-      return name();
+      StringBuilder sb = new StringBuilder();
+      sb.append(name());
+      if (!targs().isEmpty()) {
+        sb.append('<');
+        Joiner.on(',').appendTo(sb, targs());
+        sb.append('>');
+      }
+      return sb.toString();
     }
 
     @Override
diff --git a/java/com/google/turbine/types/Canonicalize.java b/java/com/google/turbine/types/Canonicalize.java
index f944bb5..a92808d 100644
--- a/java/com/google/turbine/types/Canonicalize.java
+++ b/java/com/google/turbine/types/Canonicalize.java
@@ -46,7 +46,7 @@ import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Objects;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 
 /**
  * Canonicalizes qualified type names so qualifiers are always the declaring class of the qualified
@@ -124,9 +124,6 @@ public class Canonicalize {
     if (ty.sym().equals(ClassSymbol.ERROR)) {
       return ty;
     }
-    if (isRaw(ty)) {
-      return Erasure.eraseClassTy(ty);
-    }
     // if the first name is a simple name resolved inside a nested class, add explicit qualifiers
     // for the enclosing declarations
     Iterator<ClassTy.SimpleClassTy> it = ty.classes().iterator();
@@ -140,6 +137,9 @@ public class Canonicalize {
     while (it.hasNext()) {
       canon = canonOne(canon, it.next());
     }
+    if (isRaw(canon)) {
+      canon = Erasure.eraseClassTy(canon);
+    }
     return canon;
   }
 
diff --git a/java/com/google/turbine/types/Deannotate.java b/java/com/google/turbine/types/Deannotate.java
index 1edb11f..d881131 100644
--- a/java/com/google/turbine/types/Deannotate.java
+++ b/java/com/google/turbine/types/Deannotate.java
@@ -46,7 +46,7 @@ public class Deannotate {
     throw new AssertionError(ty.tyKind());
   }
 
-  private static ImmutableList<Type> deannotate(ImmutableList<Type> types) {
+  public static ImmutableList<Type> deannotate(ImmutableList<Type> types) {
     ImmutableList.Builder<Type> result = ImmutableList.builder();
     for (Type type : types) {
       result.add(deannotate(type));
@@ -68,9 +68,9 @@ public class Deannotate {
       case NONE:
         return Type.WildUnboundedTy.create(ImmutableList.of());
       case LOWER:
-        return Type.WildLowerBoundedTy.create(ty.bound(), ImmutableList.of());
+        return Type.WildLowerBoundedTy.create(deannotate(ty.bound()), ImmutableList.of());
       case UPPER:
-        return Type.WildUpperBoundedTy.create(ty.bound(), ImmutableList.of());
+        return Type.WildUpperBoundedTy.create(deannotate(ty.bound()), ImmutableList.of());
     }
     throw new AssertionError(ty.boundKind());
   }
diff --git a/java/com/google/turbine/zip/Zip.java b/java/com/google/turbine/zip/Zip.java
index c08999b..3698d59 100644
--- a/java/com/google/turbine/zip/Zip.java
+++ b/java/com/google/turbine/zip/Zip.java
@@ -18,6 +18,7 @@ package com.google.turbine.zip;
 
 import static java.nio.charset.StandardCharsets.UTF_8;
 
+import com.google.common.base.Supplier;
 import com.google.common.primitives.UnsignedInts;
 import java.io.ByteArrayInputStream;
 import java.io.Closeable;
@@ -82,6 +83,7 @@ public final class Zip {
 
   static final int ENDTOT = 10; // total number of entries
   static final int ENDSIZ = 12; // central directory size in bytes
+  static final int ENDOFF = 16; // central directory offset
   static final int ENDCOM = 20; // zip file comment length
 
   static final int CENHOW = 10; // compression method
@@ -98,6 +100,8 @@ public final class Zip {
 
   static final int ZIP64_MAGICCOUNT = 0xFFFF;
 
+  static final long ZIP64_MAGICVAL = 0xFFFFFFFFL;
+
   /** Iterates over a zip archive. */
   static class ZipIterator implements Iterator<Entry> {
 
@@ -120,7 +124,7 @@ public final class Zip {
       return cdindex < cd.limit();
     }
 
-    /* Returns a {@link Entry} for the current CEN entry. */
+    /** Returns a {@link Entry} for the current CEN entry. */
     @Override
     public Entry next() {
       // TODO(cushon): technically we're supposed to throw NSEE
@@ -185,14 +189,17 @@ public final class Zip {
       checkSignature(path, eocd, index, 5, 6, "ENDSIG");
       int totalEntries = eocd.getChar(index + ENDTOT);
       long cdsize = UnsignedInts.toLong(eocd.getInt(index + ENDSIZ));
+      long cdoffset = UnsignedInts.toLong(eocd.getInt(index + ENDOFF));
       int actualCommentSize = eocd.getChar(index + ENDCOM);
       if (commentSize != actualCommentSize) {
         throw new ZipException(
             String.format(
                 "zip file comment length was %d, expected %d", commentSize, actualCommentSize));
       }
-      // If the number of entries is 0xffff, check if the archive has a zip64 EOCD locator.
-      if (totalEntries == ZIP64_MAGICCOUNT) {
+      // If zip64 sentinal values are present, check if the archive has a zip64 EOCD locator.
+      if (totalEntries == ZIP64_MAGICCOUNT
+          || cdsize == ZIP64_MAGICVAL
+          || cdoffset == ZIP64_MAGICVAL) {
         // Assume the zip64 EOCD has the usual size; we don't support zip64 extensible data sectors.
         long zip64eocdOffset = size - ENDHDR - ZIP64_LOCHDR - ZIP64_ENDHDR;
         // Note that zip reading is necessarily best-effort, since an archive could contain 0xFFFF
@@ -245,7 +252,7 @@ public final class Zip {
   }
 
   /** An entry in a zip archive. */
-  public static class Entry {
+  public static class Entry implements Supplier<byte[]> {
 
     private final Path path;
     private final FileChannel chan;
@@ -271,6 +278,11 @@ public final class Zip {
       // Read the offset and variable lengths from the central directory and then try to map in the
       // data section in one shot.
       long offset = UnsignedInts.toLong(cd.getInt(cdindex + CENOFF));
+      if (offset == ZIP64_MAGICVAL) {
+        // TODO(cushon): read the offset from the 'Zip64 Extended Information Extra Field'
+        throw new AssertionError(
+            String.format("%s: %s requires missing zip64 support, please file a bug", path, name));
+      }
       int nameLength = cd.getChar(cdindex + CENNAM);
       int extLength = cd.getChar(cdindex + CENEXT);
       int compression = cd.getChar(cdindex + CENHOW);
@@ -281,14 +293,14 @@ public final class Zip {
               nameLength,
               extLength,
               UnsignedInts.toLong(cd.getInt(cdindex + CENSIZ)),
-              /*deflate=*/ true);
+              /* deflate= */ true);
         case 0x0:
           return getBytes(
               offset,
               nameLength,
               extLength,
               UnsignedInts.toLong(cd.getInt(cdindex + CENLEN)),
-              /*deflate=*/ false);
+              /* deflate= */ false);
         default:
           throw new AssertionError(
               String.format("unsupported compression mode: 0x%x", compression));
@@ -330,16 +342,20 @@ public final class Zip {
         byte[] bytes = new byte[(int) size];
         fc.get(bytes);
         if (deflate) {
-          bytes =
-              new InflaterInputStream(
-                      new ByteArrayInputStream(bytes), new Inflater(/*nowrap=*/ true))
-                  .readAllBytes();
+          Inflater inf = new Inflater(/* nowrap= */ true);
+          bytes = new InflaterInputStream(new ByteArrayInputStream(bytes), inf).readAllBytes();
+          inf.end();
         }
         return bytes;
       } catch (IOException e) {
         throw new IOError(e);
       }
     }
+
+    @Override
+    public byte[] get() {
+      return data();
+    }
   }
 
   static void checkSignature(
diff --git a/javatests/com/google/turbine/binder/BinderErrorTest.java b/javatests/com/google/turbine/binder/BinderErrorTest.java
index a1bea05..e1e1eff 100644
--- a/javatests/com/google/turbine/binder/BinderErrorTest.java
+++ b/javatests/com/google/turbine/binder/BinderErrorTest.java
@@ -473,6 +473,9 @@ public class BinderErrorTest {
           "<>:3: error: symbol not found java.util.Map$Entry$NoSuch", //
           "  Map.Entry.NoSuch<List> ys;",
           "            ^",
+          "<>:3: error: could not resolve List",
+          "  Map.Entry.NoSuch<List> ys;",
+          "                   ^",
         },
       },
       {
@@ -1007,6 +1010,20 @@ public class BinderErrorTest {
           "      ^",
         },
       },
+      {
+        {
+          "package com.google.foo;", //
+          "sealed interface Iface permits Impl1, Impl2 {}",
+        },
+        {
+          "<>:2: error: could not resolve Impl1",
+          "sealed interface Iface permits Impl1, Impl2 {}",
+          "                               ^",
+          "<>:2: error: could not resolve Impl2",
+          "sealed interface Iface permits Impl1, Impl2 {}",
+          "                                      ^",
+        },
+      },
     };
     return Arrays.asList((Object[][]) testCases);
   }
@@ -1030,7 +1047,7 @@ public class BinderErrorTest {
                         ImmutableList.of(parseLines(source)),
                         ClassPathBinder.bindClasspath(ImmutableList.of()),
                         TURBINE_BOOTCLASSPATH,
-                        /* moduleVersion=*/ Optional.empty())
+                        /* moduleVersion= */ Optional.empty())
                     .units());
     assertThat(e).hasMessageThat().isEqualTo(lines(expected));
   }
@@ -1066,7 +1083,7 @@ public class BinderErrorTest {
                             /* options= */ ImmutableMap.of(),
                             SourceVersion.latestSupported()),
                         TURBINE_BOOTCLASSPATH,
-                        /* moduleVersion=*/ Optional.empty())
+                        /* moduleVersion= */ Optional.empty())
                     .units());
     assertThat(e).hasMessageThat().isEqualTo(lines(expected));
   }
diff --git a/javatests/com/google/turbine/binder/BinderTest.java b/javatests/com/google/turbine/binder/BinderTest.java
index 52b769b..c9cf61c 100644
--- a/javatests/com/google/turbine/binder/BinderTest.java
+++ b/javatests/com/google/turbine/binder/BinderTest.java
@@ -73,7 +73,7 @@ public class BinderTest {
                 units,
                 ClassPathBinder.bindClasspath(ImmutableList.of()),
                 TURBINE_BOOTCLASSPATH,
-                /* moduleVersion=*/ Optional.empty())
+                /* moduleVersion= */ Optional.empty())
             .units();
 
     assertThat(bound.keySet())
@@ -117,7 +117,7 @@ public class BinderTest {
                 units,
                 ClassPathBinder.bindClasspath(ImmutableList.of()),
                 TURBINE_BOOTCLASSPATH,
-                /* moduleVersion=*/ Optional.empty())
+                /* moduleVersion= */ Optional.empty())
             .units();
 
     assertThat(bound.keySet())
@@ -156,7 +156,7 @@ public class BinderTest {
                 units,
                 ClassPathBinder.bindClasspath(ImmutableList.of()),
                 TURBINE_BOOTCLASSPATH,
-                /* moduleVersion=*/ Optional.empty())
+                /* moduleVersion= */ Optional.empty())
             .units();
 
     assertThat(getBoundClass(bound, "other/Foo").superclass())
@@ -188,7 +188,7 @@ public class BinderTest {
                     units,
                     ClassPathBinder.bindClasspath(ImmutableList.of()),
                     TURBINE_BOOTCLASSPATH,
-                    /* moduleVersion=*/ Optional.empty()));
+                    /* moduleVersion= */ Optional.empty()));
     assertThat(e).hasMessageThat().contains("cycle in class hierarchy: a.A -> b.B -> a.A");
   }
 
@@ -206,7 +206,7 @@ public class BinderTest {
                 units,
                 ClassPathBinder.bindClasspath(ImmutableList.of()),
                 TURBINE_BOOTCLASSPATH,
-                /* moduleVersion=*/ Optional.empty())
+                /* moduleVersion= */ Optional.empty())
             .units();
 
     SourceTypeBoundClass a = getBoundClass(bound, "com/test/Annotation");
@@ -235,7 +235,7 @@ public class BinderTest {
                 units,
                 ClassPathBinder.bindClasspath(ImmutableList.of()),
                 TURBINE_BOOTCLASSPATH,
-                /* moduleVersion=*/ Optional.empty())
+                /* moduleVersion= */ Optional.empty())
             .units();
 
     SourceTypeBoundClass a = getBoundClass(bound, "a/A");
@@ -275,7 +275,7 @@ public class BinderTest {
                 units,
                 ClassPathBinder.bindClasspath(ImmutableList.of(libJar)),
                 TURBINE_BOOTCLASSPATH,
-                /* moduleVersion=*/ Optional.empty())
+                /* moduleVersion= */ Optional.empty())
             .units();
 
     SourceTypeBoundClass a = getBoundClass(bound, "C$A");
diff --git a/javatests/com/google/turbine/binder/ClassPathBinderTest.java b/javatests/com/google/turbine/binder/ClassPathBinderTest.java
index 6c6bc3e..5d4e1ad 100644
--- a/javatests/com/google/turbine/binder/ClassPathBinderTest.java
+++ b/javatests/com/google/turbine/binder/ClassPathBinderTest.java
@@ -21,7 +21,6 @@ import static com.google.common.collect.Iterables.getLast;
 import static com.google.common.collect.Iterables.getOnlyElement;
 import static com.google.common.collect.MoreCollectors.onlyElement;
 import static com.google.common.truth.Truth.assertThat;
-import static com.google.common.truth.Truth8.assertThat;
 import static com.google.turbine.testing.TestClassPaths.TURBINE_BOOTCLASSPATH;
 import static com.google.turbine.testing.TestResources.getResourceBytes;
 import static java.nio.charset.StandardCharsets.UTF_8;
diff --git a/javatests/com/google/turbine/binder/CtSymClassBinderTest.java b/javatests/com/google/turbine/binder/CtSymClassBinderTest.java
index d3a2c0e..945f7ca 100644
--- a/javatests/com/google/turbine/binder/CtSymClassBinderTest.java
+++ b/javatests/com/google/turbine/binder/CtSymClassBinderTest.java
@@ -31,12 +31,14 @@ public class CtSymClassBinderTest {
   public void formatReleaseVersion() {
     ImmutableList.of(5, 6, 7, 8, 9)
         .forEach(
-            x -> assertThat(CtSymClassBinder.formatReleaseVersion(x)).isEqualTo(String.valueOf(x)));
+            x ->
+                assertThat(Character.toString(CtSymClassBinder.formatReleaseVersion(x)))
+                    .isEqualTo(String.valueOf(x)));
     ImmutableMap.of(
-            10, "A",
-            11, "B",
-            12, "C",
-            35, "Z")
+            10, 'A',
+            11, 'B',
+            12, 'C',
+            35, 'Z')
         .forEach((k, v) -> assertThat(CtSymClassBinder.formatReleaseVersion(k)).isEqualTo(v));
     ImmutableList.of(4, 36)
         .forEach(
diff --git a/javatests/com/google/turbine/binder/bytecode/BytecodeBoundClassTest.java b/javatests/com/google/turbine/binder/bytecode/BytecodeBoundClassTest.java
index e2d54bd..c8db6f5 100644
--- a/javatests/com/google/turbine/binder/bytecode/BytecodeBoundClassTest.java
+++ b/javatests/com/google/turbine/binder/bytecode/BytecodeBoundClassTest.java
@@ -41,7 +41,7 @@ import java.io.UncheckedIOException;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
diff --git a/javatests/com/google/turbine/binder/lookup/StringCacheTest.java b/javatests/com/google/turbine/binder/lookup/StringCacheTest.java
new file mode 100644
index 0000000..82d90d9
--- /dev/null
+++ b/javatests/com/google/turbine/binder/lookup/StringCacheTest.java
@@ -0,0 +1,128 @@
+/*
+ * Copyright 2024 Google Inc. All Rights Reserved.
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
+package com.google.turbine.binder.lookup;
+
+import static com.google.common.truth.Truth.assertThat;
+import static org.junit.Assert.assertThrows;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public final class StringCacheTest {
+
+  private final StringCache cache = new StringCache(16);
+
+  @Test
+  public void get_string_canonicalizes() {
+    String foo0 = unique("foo");
+    String foo1 = unique("foo");
+    String bar0 = unique("bar");
+
+    String cacheFoo0 = cache.get(foo0);
+    String cacheFoo1 = cache.get(foo1);
+    String cacheBar0 = cache.get(bar0);
+
+    assertThat(cacheFoo0).isSameInstanceAs(foo0);
+    assertThat(cacheFoo1).isSameInstanceAs(foo0);
+    assertThat(cacheBar0).isSameInstanceAs(bar0);
+  }
+
+  @Test
+  public void getSubstring_string_checksBounds() {
+    String length10 = "0123456789";
+
+    assertThrows(Exception.class, () -> cache.getSubstring(length10, -1, 0));
+    assertThrows(Exception.class, () -> cache.getSubstring(length10, -2, -1));
+    assertThrows(Exception.class, () -> cache.getSubstring(length10, 0, 11));
+    assertThrows(Exception.class, () -> cache.getSubstring(length10, 11, 12));
+    assertThrows(Exception.class, () -> cache.getSubstring(length10, 6, 5));
+    assertThat(cache.getSubstring(length10, 5, 6)).isNotNull();
+    assertThat(cache.getSubstring(length10, 0, 0)).isNotNull();
+    assertThat(cache.getSubstring(length10, 10, 10)).isNotNull();
+    assertThat(cache.getSubstring(length10, 0, 10)).isNotNull();
+  }
+
+  @Test
+  public void getSubstring_string_canonicalizes() {
+    String foobarfoobar0 = unique("foobarfoobar");
+
+    String cacheFoo0 = cache.getSubstring(foobarfoobar0, 0, 3);
+    String cacheBar0 = cache.getSubstring(foobarfoobar0, 3, 6);
+    String cacheFoo1 = cache.getSubstring(foobarfoobar0, 6, 9);
+    String cacheBar1 = cache.getSubstring(foobarfoobar0, 9, 12);
+
+    assertThat(cacheFoo0).isEqualTo("foo");
+    assertThat(cacheFoo0).isSameInstanceAs(cacheFoo1);
+    assertThat(cacheBar0).isEqualTo("bar");
+    assertThat(cacheBar0).isSameInstanceAs(cacheBar1);
+  }
+
+  @Test
+  public void crossCanonicalization() {
+    String foo0 = unique("foo");
+    String foofoo0 = unique("foofoo");
+
+    String cacheFoo0 = cache.get(foo0);
+    String cacheFoo1 = cache.getSubstring(foofoo0, 0, 3);
+    String cacheFoo2 = cache.getSubstring(foofoo0, 3, 6);
+
+    assertThat(cacheFoo0).isSameInstanceAs(foo0);
+    assertThat(cacheFoo0).isSameInstanceAs(cacheFoo1);
+    assertThat(cacheFoo0).isSameInstanceAs(cacheFoo2);
+  }
+
+  @Test
+  public void hashCollision() {
+    String nulnulnul0 = unique("\0\0\0");
+
+    String cacheEpsilon0 = cache.getSubstring(nulnulnul0, 0, 0);
+    String cacheEpsilon1 = cache.getSubstring(nulnulnul0, 1, 1);
+    String cacheEpsilon2 = cache.getSubstring(nulnulnul0, 2, 2);
+    String cacheEpsilon3 = cache.getSubstring(nulnulnul0, 3, 3);
+    String cacheNul0 = cache.getSubstring(nulnulnul0, 0, 1);
+    String cacheNul1 = cache.getSubstring(nulnulnul0, 1, 2);
+    String cacheNul2 = cache.getSubstring(nulnulnul0, 2, 3);
+    String cacheNulnul0 = cache.getSubstring(nulnulnul0, 0, 2);
+    String cacheNulnul1 = cache.getSubstring(nulnulnul0, 1, 3);
+    String cacheNulnulnul0 = cache.get(nulnulnul0);
+
+    assertThat(cacheEpsilon0).isEqualTo("");
+    assertThat(cacheEpsilon0.hashCode()).isEqualTo(0);
+    assertThat(cacheEpsilon0).isSameInstanceAs(cacheEpsilon1);
+    assertThat(cacheEpsilon0).isSameInstanceAs(cacheEpsilon2);
+    assertThat(cacheEpsilon0).isSameInstanceAs(cacheEpsilon3);
+
+    assertThat(cacheNul0).isEqualTo("\0");
+    assertThat(cacheNul0.hashCode()).isEqualTo(0);
+    assertThat(cacheNul0).isSameInstanceAs(cacheNul1);
+    assertThat(cacheNul0).isSameInstanceAs(cacheNul2);
+
+    assertThat(cacheNulnul0).isEqualTo("\0\0");
+    assertThat(cacheNulnul0.hashCode()).isEqualTo(0);
+    assertThat(cacheNulnul0).isSameInstanceAs(cacheNulnul1);
+
+    assertThat(cacheNulnulnul0.hashCode()).isEqualTo(0);
+    assertThat(cacheNulnulnul0).isSameInstanceAs(nulnulnul0);
+  }
+
+  @SuppressWarnings("StringCopy") // String literals are already canonicalized per class
+  private static String unique(String s) {
+    return new String(s);
+  }
+}
diff --git a/javatests/com/google/turbine/bytecode/ClassReaderTest.java b/javatests/com/google/turbine/bytecode/ClassReaderTest.java
index d7abea5..a643161 100644
--- a/javatests/com/google/turbine/bytecode/ClassReaderTest.java
+++ b/javatests/com/google/turbine/bytecode/ClassReaderTest.java
@@ -17,11 +17,17 @@
 package com.google.turbine.bytecode;
 
 import static com.google.common.collect.ImmutableList.toImmutableList;
+import static com.google.common.collect.Iterables.getOnlyElement;
+import static com.google.common.collect.MoreCollectors.onlyElement;
 import static com.google.common.truth.Truth.assertThat;
+import static java.lang.annotation.ElementType.TYPE_USE;
+import static java.lang.annotation.RetentionPolicy.RUNTIME;
 import static java.util.Objects.requireNonNull;
 
 import com.google.common.base.Strings;
+import com.google.common.collect.ImmutableList;
 import com.google.common.collect.Iterables;
+import com.google.common.io.ByteStreams;
 import com.google.turbine.bytecode.ClassFile.AnnotationInfo.ElementValue;
 import com.google.turbine.bytecode.ClassFile.ModuleInfo;
 import com.google.turbine.bytecode.ClassFile.ModuleInfo.ExportInfo;
@@ -31,6 +37,14 @@ import com.google.turbine.bytecode.ClassFile.ModuleInfo.RequireInfo;
 import com.google.turbine.model.Const;
 import com.google.turbine.model.TurbineConstantTypeKind;
 import com.google.turbine.model.TurbineFlag;
+import java.io.IOException;
+import java.io.UncheckedIOException;
+import java.lang.annotation.Retention;
+import java.lang.annotation.Target;
+import java.util.ArrayList;
+import java.util.List;
+import java.util.function.Supplier;
+import java.util.jar.JarFile;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
@@ -214,6 +228,7 @@ public class ClassReaderTest {
     cw.visitInnerClass(
         "test/Hello$Inner", "test/Hello", "Inner", Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE);
     cw.visitInnerClass("test/Hello$Inner$InnerMost", "test/Hello$Inner", "InnerMost", 0);
+    cw.visitInnerClass("test/Hello$Local", null, "Local", 0);
     byte[] bytes = cw.toByteArray();
 
     ClassFile classFile = com.google.turbine.bytecode.ClassReader.read(null, bytes);
@@ -383,4 +398,57 @@ public class ClassReaderTest {
     ClassFile cf = ClassReader.read(null, cw.toByteArray());
     assertThat(cf.transitiveJar()).isEqualTo("path/to/transitive.jar");
   }
+
+  static class C {
+    @Target(TYPE_USE)
+    @Retention(RUNTIME)
+    @interface A {
+      int value();
+    }
+
+    @SuppressWarnings("unused")
+    @A(0x14)
+    int f(Object o) {
+      @A(0x40)
+      int local;
+      try (@A(0x41)
+          JarFile jarFile = new JarFile("hello.jar")) {
+      } catch (
+          @A(0x42)
+          IOException e) {
+        throw new UncheckedIOException(e);
+      }
+      if (o instanceof @A(0x43) String) {}
+      new @A(0x44) ArrayList<>();
+      Supplier<List<?>> a = @A(0x45) ArrayList::new;
+      Supplier<List<?>> b = @A(0x46) ImmutableList::of;
+      String s = (@A(0x47) String) o;
+      List<?> xs = new ArrayList<@A(0x48) String>();
+      xs = ImmutableList.<@A(0x49) String>of();
+      Supplier<List<?>> c = ArrayList<@A(0x4A) String>::new;
+      Supplier<List<?>> d = ImmutableList::<@A(0x4B) String>of;
+      return 0;
+    }
+  }
+
+  // Ensure that we skip over JVMS 4.7.20-B target_types, and handle the single API type annotation
+  @Test
+  public void nonApiTypeAnnotations() throws Exception {
+    byte[] bytes =
+        ByteStreams.toByteArray(
+            getClass().getResourceAsStream("/" + C.class.getName().replace('.', '/') + ".class"));
+    ClassFile cf = ClassReader.read(null, bytes);
+    ClassFile.MethodInfo m =
+        cf.methods().stream().filter(x -> x.name().contains("f")).collect(onlyElement());
+    ClassFile.TypeAnnotationInfo ta = getOnlyElement(m.typeAnnotations());
+    assertThat(ta.targetType()).isEqualTo(ClassFile.TypeAnnotationInfo.TargetType.METHOD_RETURN);
+    assertThat(ta.path()).isEqualTo(ClassFile.TypeAnnotationInfo.TypePath.root());
+    assertThat(ta.target()).isEqualTo(ClassFile.TypeAnnotationInfo.EMPTY_TARGET);
+    assertThat(ta.anno().typeName()).isEqualTo("Lcom/google/turbine/bytecode/ClassReaderTest$C$A;");
+    assertThat(
+            ((ElementValue.ConstValue) ta.anno().elementValuePairs().get("value"))
+                .value()
+                .getValue())
+        .isEqualTo(0x14);
+  }
 }
diff --git a/javatests/com/google/turbine/bytecode/ClassWriterTest.java b/javatests/com/google/turbine/bytecode/ClassWriterTest.java
index a6f9234..e775353 100644
--- a/javatests/com/google/turbine/bytecode/ClassWriterTest.java
+++ b/javatests/com/google/turbine/bytecode/ClassWriterTest.java
@@ -202,13 +202,19 @@ public class ClassWriterTest {
                         "Ljava/util/List;",
                         "Ljava/util/List<Ljava/lang/Integer;>;",
                         ImmutableList.of(
-                            new ClassFile.AnnotationInfo("LA;", true, ImmutableMap.of())),
+                            new ClassFile.AnnotationInfo(
+                                "LA;",
+                                ClassFile.AnnotationInfo.RuntimeVisibility.VISIBLE,
+                                ImmutableMap.of())),
                         ImmutableList.of(
                             new ClassFile.TypeAnnotationInfo(
                                 ClassFile.TypeAnnotationInfo.TargetType.FIELD,
                                 ClassFile.TypeAnnotationInfo.EMPTY_TARGET,
                                 ClassFile.TypeAnnotationInfo.TypePath.root(),
-                                new ClassFile.AnnotationInfo("LA;", true, ImmutableMap.of())))),
+                                new ClassFile.AnnotationInfo(
+                                    "LA;",
+                                    ClassFile.AnnotationInfo.RuntimeVisibility.VISIBLE,
+                                    ImmutableMap.of())))),
                     new ClassFile.RecordInfo.RecordComponentInfo(
                         "y", "I", null, ImmutableList.of(), ImmutableList.of()))),
             /* transitiveJar= */ null);
diff --git a/javatests/com/google/turbine/bytecode/sig/SigIntegrationTest.java b/javatests/com/google/turbine/bytecode/sig/SigIntegrationTest.java
index 58c0eff..b90b0cf 100644
--- a/javatests/com/google/turbine/bytecode/sig/SigIntegrationTest.java
+++ b/javatests/com/google/turbine/bytecode/sig/SigIntegrationTest.java
@@ -23,7 +23,8 @@ import static com.google.common.truth.Truth.assertThat;
 import com.google.common.base.Splitter;
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.Streams;
-import org.objectweb.asm.Opcodes;
+import com.google.turbine.bytecode.ClassFile;
+import com.google.turbine.bytecode.ClassReader;
 import java.io.File;
 import java.io.IOException;
 import java.io.UncheckedIOException;
@@ -41,10 +42,6 @@ import java.util.stream.Stream;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
-import org.objectweb.asm.ClassReader;
-import org.objectweb.asm.ClassVisitor;
-import org.objectweb.asm.FieldVisitor;
-import org.objectweb.asm.MethodVisitor;
 
 /**
  * Reads all field, class, and method signatures in the bootclasspath, and round-trips them through
@@ -92,51 +89,31 @@ public class SigIntegrationTest {
     forEachBootclass(
         path -> {
           try {
-            new ClassReader(Files.newInputStream(path))
-                .accept(
-                    new ClassVisitor(Opcodes.ASM9) {
-                      @Override
-                      public void visit(
-                          int version,
-                          int access,
-                          String name,
-                          String signature,
-                          String superName,
-                          String[] interfaces) {
-                        if (signature != null) {
-                          assertThat(SigWriter.classSig(new SigParser(signature).parseClassSig()))
-                              .isEqualTo(signature);
-                          totalSignatures[0]++;
-                        }
-                      }
-
-                      @Override
-                      public FieldVisitor visitField(
-                          int access, String name, String desc, String signature, Object value) {
-                        if (signature != null) {
-                          assertThat(SigWriter.type(new SigParser(signature).parseFieldSig()))
-                              .isEqualTo(signature);
-                          totalSignatures[0]++;
-                        }
-                        return super.visitField(access, name, desc, signature, value);
-                      }
-
-                      @Override
-                      public MethodVisitor visitMethod(
-                          int access,
-                          String name,
-                          String desc,
-                          String signature,
-                          String[] exceptions) {
-                        if (signature != null) {
-                          assertThat(SigWriter.method(new SigParser(signature).parseMethodSig()))
-                              .isEqualTo(signature);
-                          totalSignatures[0]++;
-                        }
-                        return super.visitMethod(access, name, desc, signature, exceptions);
-                      }
-                    },
-                    ClassReader.SKIP_CODE | ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
+            ClassFile classFile = ClassReader.read(path.toString(), Files.readAllBytes(path));
+            {
+              String signature = classFile.signature();
+              if (signature != null) {
+                assertThat(SigWriter.classSig(new SigParser(signature).parseClassSig()))
+                    .isEqualTo(signature);
+                totalSignatures[0]++;
+              }
+            }
+            for (ClassFile.FieldInfo field : classFile.fields()) {
+              String signature = field.signature();
+              if (signature != null) {
+                assertThat(SigWriter.type(new SigParser(signature).parseFieldSig()))
+                    .isEqualTo(signature);
+                totalSignatures[0]++;
+              }
+            }
+            for (ClassFile.MethodInfo method : classFile.methods()) {
+              String signature = method.signature();
+              if (signature != null) {
+                assertThat(SigWriter.method(new SigParser(signature).parseMethodSig()))
+                    .isEqualTo(signature);
+                totalSignatures[0]++;
+              }
+            }
           } catch (IOException e) {
             throw new UncheckedIOException(e);
           }
diff --git a/javatests/com/google/turbine/deps/TransitiveTest.java b/javatests/com/google/turbine/deps/TransitiveTest.java
index 3829ddd..69d719b 100644
--- a/javatests/com/google/turbine/deps/TransitiveTest.java
+++ b/javatests/com/google/turbine/deps/TransitiveTest.java
@@ -125,12 +125,15 @@ public class TransitiveTest {
     // libb repackages A, and any member types
     assertThat(readJar(libb).keySet())
         .containsExactly(
-            "b/B.class",
-            "META-INF/TRANSITIVE/a/A.class",
-            "META-INF/TRANSITIVE/a/A$Anno.class",
-            "META-INF/TRANSITIVE/a/A$Inner.class");
+            "META-INF/",
+            "META-INF/MANIFEST.MF",
+            "META-INF/TRANSITIVE/a/A.turbine",
+            "META-INF/TRANSITIVE/a/A$Anno.turbine",
+            "META-INF/TRANSITIVE/a/A$Inner.turbine",
+            "b/B.class")
+        .inOrder();
 
-    ClassFile a = ClassReader.read(null, readJar(libb).get("META-INF/TRANSITIVE/a/A.class"));
+    ClassFile a = ClassReader.read(null, readJar(libb).get("META-INF/TRANSITIVE/a/A.turbine"));
     // methods and non-constant fields are removed
     assertThat(getOnlyElement(a.fields()).name()).isEqualTo("CONST");
     assertThat(a.methods()).isEmpty();
@@ -139,7 +142,7 @@ public class TransitiveTest {
 
     // annotation interface methods are preserved
     assertThat(
-            ClassReader.read(null, readJar(libb).get("META-INF/TRANSITIVE/a/A$Anno.class"))
+            ClassReader.read(null, readJar(libb).get("META-INF/TRANSITIVE/a/A$Anno.turbine"))
                 .methods())
         .hasSize(1);
 
@@ -176,15 +179,19 @@ public class TransitiveTest {
                 ImmutableList.of(libb).stream().map(Path::toString).collect(toImmutableList()))
             .setOutput(libc.toString())
             .setOutputDeps(libcDeps.toString())
+            .setTargetLabel("//foo:foo")
             .build());
 
     assertThat(readJar(libc).keySet())
         .containsExactly(
-            "c/C.class",
-            "META-INF/TRANSITIVE/b/B.class",
-            "META-INF/TRANSITIVE/a/A.class",
-            "META-INF/TRANSITIVE/a/A$Anno.class",
-            "META-INF/TRANSITIVE/a/A$Inner.class");
+            "META-INF/",
+            "META-INF/MANIFEST.MF",
+            "META-INF/TRANSITIVE/b/B.turbine",
+            "META-INF/TRANSITIVE/a/A.turbine",
+            "META-INF/TRANSITIVE/a/A$Anno.turbine",
+            "META-INF/TRANSITIVE/a/A$Inner.turbine",
+            "c/C.class")
+        .inOrder();
 
     // liba is recorded as an explicit dep, even thought it's only present as a transitive class
     // repackaged in lib
@@ -247,7 +254,12 @@ public class TransitiveTest {
     // libb repackages A and any named member types
     assertThat(readJar(libb).keySet())
         .containsExactly(
-            "b/B.class", "META-INF/TRANSITIVE/a/A.class", "META-INF/TRANSITIVE/a/A$I.class");
+            "META-INF/",
+            "META-INF/MANIFEST.MF",
+            "META-INF/TRANSITIVE/a/A.turbine",
+            "META-INF/TRANSITIVE/a/A$I.turbine",
+            "b/B.class")
+        .inOrder();
   }
 
   @Test
@@ -283,11 +295,52 @@ public class TransitiveTest {
 
     assertThat(readJar(libb).keySet())
         .containsExactly(
-            "b/B.class",
+            "META-INF/",
+            "META-INF/MANIFEST.MF",
+            "META-INF/TRANSITIVE/a/A$I.turbine",
+            "META-INF/TRANSITIVE/a/S.turbine",
+            "META-INF/TRANSITIVE/a/A.turbine",
             "b/B$I.class",
-            "META-INF/TRANSITIVE/a/A.class",
-            "META-INF/TRANSITIVE/a/A$I.class",
-            "META-INF/TRANSITIVE/a/S.class");
+            "b/B.class")
+        .inOrder();
+  }
+
+  @Test
+  public void packageInfo() throws Exception {
+    Path libPackageInfo =
+        runTurbine(
+            new SourceBuilder()
+                .addSourceLines(
+                    "p/Anno.java",
+                    "package p;",
+                    "import java.lang.annotation.Retention;",
+                    "import static java.lang.annotation.RetentionPolicy.RUNTIME;",
+                    "@Retention(RUNTIME)",
+                    "@interface Anno {}")
+                .addSourceLines(
+                    "p/package-info.java", //
+                    "@Anno",
+                    "package p;")
+                .build(),
+            ImmutableList.of());
+
+    Path liba =
+        runTurbine(
+            new SourceBuilder()
+                .addSourceLines(
+                    "p/P.java", //
+                    "package p;",
+                    "public class P {}")
+                .build(),
+            ImmutableList.of(libPackageInfo));
+
+    assertThat(readJar(liba).keySet())
+        .containsExactly(
+            "META-INF/",
+            "META-INF/MANIFEST.MF",
+            "META-INF/TRANSITIVE/p/package-info.turbine",
+            "p/P.class")
+        .inOrder();
   }
 
   private Path runTurbine(ImmutableList<Path> sources, ImmutableList<Path> classpath)
@@ -298,6 +351,7 @@ public class TransitiveTest {
             .setSources(sources.stream().map(Path::toString).collect(toImmutableList()))
             .setClassPath(classpath.stream().map(Path::toString).collect(toImmutableList()))
             .setOutput(out.toString())
+            .setTargetLabel("//foo:foo")
             .build());
     return out;
   }
diff --git a/javatests/com/google/turbine/lower/IntegrationTestSupport.java b/javatests/com/google/turbine/lower/IntegrationTestSupport.java
index 6527a03..7241cf6 100644
--- a/javatests/com/google/turbine/lower/IntegrationTestSupport.java
+++ b/javatests/com/google/turbine/lower/IntegrationTestSupport.java
@@ -70,6 +70,7 @@ import java.util.List;
 import java.util.Map;
 import java.util.Optional;
 import java.util.Set;
+import javax.annotation.processing.Processor;
 import javax.tools.DiagnosticCollector;
 import javax.tools.JavaFileObject;
 import javax.tools.StandardLocation;
@@ -127,14 +128,27 @@ public final class IntegrationTestSupport {
     for (ClassNode n : classes) {
       removeImplementation(n);
       removeUnusedInnerClassAttributes(infos, n);
-      makeEnumsFinal(all, n);
+      makeEnumsNonAbstract(all, n);
       sortAttributes(n);
       undeprecate(n);
+      removePreviewVersion(n);
     }
 
     return toByteCode(classes);
   }
 
+  public static Map<String, byte[]> removeUnsupportedAttributes(Map<String, byte[]> in) {
+    List<ClassNode> classes = toClassNodes(in);
+    for (ClassNode c : classes) {
+      c.nestMembers = null;
+      c.nestHostClass = null;
+      // TODO(b/307939333): class reading for sealed classes
+      c.permittedSubclasses = null;
+      // this is a synthetic access flag that ASM sets if recordComponents is present
+    }
+    return toByteCode(classes);
+  }
+
   private static boolean isLocal(ClassNode n) {
     return n.outerMethod != null;
   }
@@ -160,22 +174,25 @@ public final class IntegrationTestSupport {
         .forEach(f -> f.access &= ~Opcodes.ACC_DEPRECATED);
   }
 
+  // Mask out preview bits from version number
+  private static void removePreviewVersion(ClassNode n) {
+    n.version &= 0xffff;
+  }
+
   private static boolean isDeprecated(List<AnnotationNode> visibleAnnotations) {
     return visibleAnnotations != null
         && visibleAnnotations.stream().anyMatch(a -> a.desc.equals("Ljava/lang/Deprecated;"));
   }
 
-  private static void makeEnumsFinal(Set<String> all, ClassNode n) {
+  private static void makeEnumsNonAbstract(Set<String> all, ClassNode n) {
     n.innerClasses.forEach(
         x -> {
           if (all.contains(x.name) && (x.access & Opcodes.ACC_ENUM) == Opcodes.ACC_ENUM) {
             x.access &= ~Opcodes.ACC_ABSTRACT;
-            x.access |= Opcodes.ACC_FINAL;
           }
         });
     if ((n.access & Opcodes.ACC_ENUM) == Opcodes.ACC_ENUM) {
       n.access &= ~Opcodes.ACC_ABSTRACT;
-      n.access |= Opcodes.ACC_FINAL;
     }
   }
 
@@ -536,7 +553,19 @@ public final class IntegrationTestSupport {
       throws Exception {
     FileSystem fs = Jimfs.newFileSystem(Configuration.unix());
     Path out = fs.getPath("out");
-    return setupJavac(sources, classpath, options, collector, fs, out);
+    return setupJavac(sources, classpath, options, collector, fs, out, ImmutableList.of());
+  }
+
+  public static JavacTask runJavacAnalysis(
+      Map<String, String> sources,
+      Collection<Path> classpath,
+      ImmutableList<String> options,
+      DiagnosticCollector<JavaFileObject> collector,
+      ImmutableList<Processor> processors)
+      throws Exception {
+    FileSystem fs = Jimfs.newFileSystem(Configuration.unix());
+    Path out = fs.getPath("out");
+    return setupJavac(sources, classpath, options, collector, fs, out, processors);
   }
 
   public static Map<String, byte[]> runJavac(
@@ -553,7 +582,8 @@ public final class IntegrationTestSupport {
     FileSystem fs = Jimfs.newFileSystem(Configuration.unix());
     Path out = fs.getPath("out");
 
-    JavacTask task = setupJavac(sources, classpath, options, collector, fs, out);
+    JavacTask task =
+        setupJavac(sources, classpath, options, collector, fs, out, ImmutableList.of());
 
     if (!task.call()) {
       fail(collector.getDiagnostics().stream().map(d -> d.toString()).collect(joining("\n")));
@@ -586,7 +616,8 @@ public final class IntegrationTestSupport {
       ImmutableList<String> options,
       DiagnosticCollector<JavaFileObject> collector,
       FileSystem fs,
-      Path out)
+      Path out,
+      Iterable<? extends Processor> processors)
       throws IOException {
     Path srcs = fs.getPath("srcs");
 
@@ -616,13 +647,16 @@ public final class IntegrationTestSupport {
           StandardLocation.locationFor("MODULE_SOURCE_PATH"), ImmutableList.of(srcs));
     }
 
-    return compiler.getTask(
-        new PrintWriter(new BufferedWriter(new OutputStreamWriter(System.err, UTF_8)), true),
-        fileManager,
-        collector,
-        options,
-        ImmutableList.of(),
-        fileManager.getJavaFileObjectsFromPaths(inputs));
+    JavacTask task =
+        compiler.getTask(
+            new PrintWriter(new BufferedWriter(new OutputStreamWriter(System.err, UTF_8)), true),
+            fileManager,
+            collector,
+            options,
+            ImmutableList.of(),
+            fileManager.getJavaFileObjectsFromPaths(inputs));
+    task.setProcessors(processors);
+    return task;
   }
 
   /** Normalizes and stringifies a collection of class files. */
@@ -693,9 +727,5 @@ public final class IntegrationTestSupport {
     }
   }
 
-  public static int getMajor() {
-    return Runtime.version().feature();
-  }
-
   private IntegrationTestSupport() {}
 }
diff --git a/javatests/com/google/turbine/lower/LongStringIntegrationTest.java b/javatests/com/google/turbine/lower/LongStringIntegrationTest.java
index 33deaee..d7d93ce 100644
--- a/javatests/com/google/turbine/lower/LongStringIntegrationTest.java
+++ b/javatests/com/google/turbine/lower/LongStringIntegrationTest.java
@@ -44,7 +44,7 @@ public class LongStringIntegrationTest {
   public void test() throws Exception {
     Map<String, byte[]> output =
         runTurbineWithStack(
-            /* stackSize= */ 100_000,
+            /* stackSize= */ 200_000,
             /* input= */ ImmutableMap.of("Test.java", source()),
             /* classpath= */ ImmutableList.of());
 
diff --git a/javatests/com/google/turbine/lower/LowerIntegrationTest.java b/javatests/com/google/turbine/lower/LowerIntegrationTest.java
index 6c95d44..bac2b5a 100644
--- a/javatests/com/google/turbine/lower/LowerIntegrationTest.java
+++ b/javatests/com/google/turbine/lower/LowerIntegrationTest.java
@@ -17,19 +17,24 @@
 package com.google.turbine.lower;
 
 import static com.google.common.truth.Truth.assertThat;
+import static com.google.common.truth.TruthJUnit.assume;
 import static com.google.turbine.testing.TestResources.getResource;
+import static java.util.Map.entry;
 import static java.util.stream.Collectors.toList;
-import static org.junit.Assume.assumeTrue;
 
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.ImmutableMap;
 import com.google.common.collect.ImmutableSet;
 import com.google.common.collect.Lists;
+import com.google.turbine.bytecode.ClassFile;
+import com.google.turbine.bytecode.ClassReader;
+import com.google.turbine.bytecode.ClassWriter;
 import java.io.IOError;
 import java.io.IOException;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.nio.file.Paths;
+import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.jar.JarEntry;
@@ -41,23 +46,34 @@ import org.junit.runner.RunWith;
 import org.junit.runners.Parameterized;
 import org.junit.runners.Parameterized.Parameters;
 
+/**
+ * A test that compiles inputs with both javac and turbine, and asserts that the output is
+ * equivalent.
+ */
 @RunWith(Parameterized.class)
 public class LowerIntegrationTest {
 
   private static final ImmutableMap<String, Integer> SOURCE_VERSION =
-      ImmutableMap.of(
-          "record.test", 16, //
-          "record2.test", 16,
-          "record_tostring.test", 16,
-          "record_ctor.test", 16,
-          "sealed.test", 17,
-          "sealed_nested.test", 17,
-          "textblock.test", 15);
+      ImmutableMap.ofEntries(
+          entry("record.test", 16),
+          entry("record2.test", 16),
+          entry("record_tostring.test", 16),
+          entry("record_ctor.test", 16),
+          entry("record_getter_override.test", 16),
+          entry("sealed.test", 17),
+          entry("sealed_nested.test", 17),
+          entry("textblock.test", 15),
+          entry("textblock2.test", 15),
+          entry("B306423115.test", 15),
+          entry("permits.test", 17));
+
+  private static final ImmutableSet<String> SOURCE_VERSION_PREVIEW = ImmutableSet.of();
 
   @Parameters(name = "{index}: {0}")
   public static Iterable<Object[]> parameters() {
     String[] testCases = {
       // keep-sorted start
+      "B306423115.test",
       "B33513475.test",
       "B33513475b.test",
       "B33513475c.test",
@@ -258,6 +274,7 @@ public class LowerIntegrationTest {
       "packagedecl.test",
       "packageprivateprotectedinner.test",
       "param_bound.test",
+      "permits.test",
       "prim_class.test",
       "private_member.test",
       "privateinner.test",
@@ -273,6 +290,7 @@ public class LowerIntegrationTest {
       "record.test",
       "record2.test",
       "record_ctor.test",
+      "record_getter_override.test",
       "record_tostring.test",
       "rek.test",
       "samepkg.test",
@@ -286,6 +304,8 @@ public class LowerIntegrationTest {
       "simplemethod.test",
       "source_anno_retention.test",
       "source_bootclasspath_order.test",
+      "star_import_visibility.test",
+      "star_import_visibility_nested.test",
       "static_final_boxed.test",
       "static_member_type_import.test",
       "static_member_type_import_recursive.test",
@@ -297,6 +317,7 @@ public class LowerIntegrationTest {
       "supplierfunction.test",
       "tbound.test",
       "textblock.test",
+      "textblock2.test",
       "tyanno_inner.test",
       "tyanno_varargs.test",
       "typaram.test",
@@ -310,6 +331,9 @@ public class LowerIntegrationTest {
       "type_anno_c_array.test",
       "type_anno_cstyle_array_dims.test",
       "type_anno_hello.test",
+      "type_anno_nested.test",
+      "type_anno_nested_generic.test",
+      "type_anno_nested_raw.test",
       "type_anno_order.test",
       "type_anno_parameter_index.test",
       "type_anno_qual.test",
@@ -341,6 +365,7 @@ public class LowerIntegrationTest {
     };
     ImmutableSet<String> cases = ImmutableSet.copyOf(testCases);
     assertThat(cases).containsAtLeastElementsIn(SOURCE_VERSION.keySet());
+    assertThat(cases).containsAtLeastElementsIn(SOURCE_VERSION_PREVIEW);
     List<Object[]> tests = cases.stream().map(x -> new Object[] {x}).collect(toList());
     String testShardIndex = System.getenv("TEST_SHARD_INDEX");
     String testTotalShards = System.getenv("TEST_TOTAL_SHARDS");
@@ -388,15 +413,19 @@ public class LowerIntegrationTest {
       classpathJar = ImmutableList.of(lib);
     }
 
-    int version = SOURCE_VERSION.getOrDefault(test, 8);
-    assumeTrue(version <= Runtime.version().feature());
-    ImmutableList<String> javacopts =
-        ImmutableList.of(
-            "-source",
-            String.valueOf(version),
-            "-target",
-            String.valueOf(version),
-            "-Xpkginfo:always");
+    int actualVersion = Runtime.version().feature();
+    int requiredVersion = SOURCE_VERSION.getOrDefault(test, 8);
+    assume().that(actualVersion).isAtLeast(requiredVersion);
+    ImmutableList.Builder<String> javacoptsBuilder = ImmutableList.builder();
+    if (SOURCE_VERSION_PREVIEW.contains(test)) {
+      requiredVersion = actualVersion;
+      javacoptsBuilder.add("--enable-preview");
+    }
+    javacoptsBuilder.add(
+        "-source", String.valueOf(requiredVersion), "-target", String.valueOf(requiredVersion));
+    javacoptsBuilder.add("-Xpkginfo:always");
+
+    ImmutableList<String> javacopts = javacoptsBuilder.build();
 
     Map<String, byte[]> expected =
         IntegrationTestSupport.runJavac(input.sources, classpathJar, javacopts);
@@ -406,5 +435,17 @@ public class LowerIntegrationTest {
 
     assertThat(IntegrationTestSupport.dump(IntegrationTestSupport.sortMembers(actual)))
         .isEqualTo(IntegrationTestSupport.dump(IntegrationTestSupport.canonicalize(expected)));
+
+    Map<String, byte[]> bytecode = new LinkedHashMap<>();
+    actual.forEach(
+        (name, bytes) -> {
+          ClassFile classFile = ClassReader.read(name, bytes);
+          bytecode.put(name, ClassWriter.writeClass(classFile));
+        });
+
+    assertThat(IntegrationTestSupport.dump(bytecode))
+        .isEqualTo(
+            IntegrationTestSupport.dump(
+                IntegrationTestSupport.removeUnsupportedAttributes(actual)));
   }
 }
diff --git a/javatests/com/google/turbine/lower/MissingJavaBaseModule.java b/javatests/com/google/turbine/lower/MissingJavaBaseModuleTest.java
similarity index 87%
rename from javatests/com/google/turbine/lower/MissingJavaBaseModule.java
rename to javatests/com/google/turbine/lower/MissingJavaBaseModuleTest.java
index 230b18f..a9e9052 100644
--- a/javatests/com/google/turbine/lower/MissingJavaBaseModule.java
+++ b/javatests/com/google/turbine/lower/MissingJavaBaseModuleTest.java
@@ -16,15 +16,13 @@
 
 package com.google.turbine.lower;
 
-import static com.google.common.base.StandardSystemProperty.JAVA_CLASS_VERSION;
 import static com.google.common.collect.ImmutableMap.toImmutableMap;
-import static org.junit.Assert.assertEquals;
+import static com.google.common.truth.Truth.assertThat;
 
 import com.google.common.base.Supplier;
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.ImmutableMap;
 import com.google.turbine.binder.ClassPath;
-import com.google.turbine.binder.CtSymClassBinder;
 import com.google.turbine.binder.JimageClassBinder;
 import com.google.turbine.binder.bound.ModuleInfo;
 import com.google.turbine.binder.bytecode.BytecodeBoundClass;
@@ -34,13 +32,13 @@ import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.binder.sym.ModuleSymbol;
 import java.util.Map;
 import java.util.Optional;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
 @RunWith(JUnit4.class)
-public class MissingJavaBaseModule {
+public class MissingJavaBaseModuleTest {
 
   @Test
   public void test() throws Exception {
@@ -51,10 +49,7 @@ public class MissingJavaBaseModule {
         IntegrationTestSupport.runJavac(
             sources, ImmutableList.of(), ImmutableList.of("--release", "9", "--module-version=42"));
 
-    ClassPath base =
-        Double.parseDouble(JAVA_CLASS_VERSION.value()) < 54
-            ? JimageClassBinder.bindDefault()
-            : CtSymClassBinder.bind(9);
+    ClassPath base = JimageClassBinder.bindDefault();
     ClassPath bootclasspath =
         new ClassPath() {
           @Override
@@ -93,7 +88,10 @@ public class MissingJavaBaseModule {
             Optional.of("42"),
             /* javacopts= */ ImmutableList.of());
 
-    assertEquals(dump(expected), dump(actual));
+    // normalize output after https://bugs.openjdk.org/browse/JDK-8320766
+    String expectedOutput = dump(expected).replace("  // version 9\n", "");
+
+    assertThat(dump(actual)).isEqualTo(expectedOutput);
   }
 
   private String dump(Map<String, byte[]> map) throws Exception {
diff --git a/javatests/com/google/turbine/lower/ModuleIntegrationTest.java b/javatests/com/google/turbine/lower/ModuleIntegrationTest.java
index 0157fea..e97e1fd 100644
--- a/javatests/com/google/turbine/lower/ModuleIntegrationTest.java
+++ b/javatests/com/google/turbine/lower/ModuleIntegrationTest.java
@@ -47,6 +47,10 @@ public class ModuleIntegrationTest {
       "module-info.test", //
       "classpath.test",
       "multimodule.test",
+      "module-info-for-base.test",
+      "module-info-open.test",
+      "module-requires-static-transitive.test",
+      "module-requires-transitive-static.test",
     };
     return ImmutableList.copyOf(testCases).stream().map(x -> new Object[] {x}).collect(toList());
   }
@@ -61,11 +65,6 @@ public class ModuleIntegrationTest {
 
   @Test
   public void test() throws Exception {
-    if (Double.parseDouble(JAVA_CLASS_VERSION.value()) < 53) {
-      // only run on JDK 9 and later
-      return;
-    }
-
     IntegrationTestSupport.TestInput input =
         IntegrationTestSupport.TestInput.parse(getResource(getClass(), "moduletestdata/" + test));
 
diff --git a/javatests/com/google/turbine/lower/moduletestdata/module-info-for-base.test b/javatests/com/google/turbine/lower/moduletestdata/module-info-for-base.test
new file mode 100644
index 0000000..567d31f
--- /dev/null
+++ b/javatests/com/google/turbine/lower/moduletestdata/module-info-for-base.test
@@ -0,0 +1,7 @@
+=== java/lang/Object.java ===
+package java.lang;
+
+public class Object {}
+
+=== module-info.java ===
+module java.base {}
\ No newline at end of file
diff --git a/javatests/com/google/turbine/lower/moduletestdata/module-info-open.test b/javatests/com/google/turbine/lower/moduletestdata/module-info-open.test
new file mode 100644
index 0000000..70bd1a9
--- /dev/null
+++ b/javatests/com/google/turbine/lower/moduletestdata/module-info-open.test
@@ -0,0 +1,5 @@
+=== module-info.java ===
+open module com.google.foop.annotation {
+  requires java.base;
+  requires java.compiler;
+}
diff --git a/javatests/com/google/turbine/lower/moduletestdata/module-requires-static-transitive.test b/javatests/com/google/turbine/lower/moduletestdata/module-requires-static-transitive.test
new file mode 100644
index 0000000..84084dc
--- /dev/null
+++ b/javatests/com/google/turbine/lower/moduletestdata/module-requires-static-transitive.test
@@ -0,0 +1,5 @@
+=== module-info.java ===
+
+module foo {
+  requires static transitive java.base;
+}
\ No newline at end of file
diff --git a/javatests/com/google/turbine/lower/moduletestdata/module-requires-transitive-static.test b/javatests/com/google/turbine/lower/moduletestdata/module-requires-transitive-static.test
new file mode 100644
index 0000000..33c0911
--- /dev/null
+++ b/javatests/com/google/turbine/lower/moduletestdata/module-requires-transitive-static.test
@@ -0,0 +1,5 @@
+=== module-info.java ===
+
+module foo {
+  requires transitive static java.base;
+}
\ No newline at end of file
diff --git a/javatests/com/google/turbine/lower/testdata/B306423115.test b/javatests/com/google/turbine/lower/testdata/B306423115.test
new file mode 100644
index 0000000..8e3bc29
--- /dev/null
+++ b/javatests/com/google/turbine/lower/testdata/B306423115.test
@@ -0,0 +1,8 @@
+=== T.java ===
+public class T {
+    public static final String a =
+        """
+        a \
+        b \
+        """;
+}
diff --git a/javatests/com/google/turbine/lower/testdata/enum_abstract.test b/javatests/com/google/turbine/lower/testdata/enum_abstract.test
index e7ef3a4..d318daf 100644
--- a/javatests/com/google/turbine/lower/testdata/enum_abstract.test
+++ b/javatests/com/google/turbine/lower/testdata/enum_abstract.test
@@ -11,3 +11,33 @@ class Test {
     };
   }
 }
+=== I.java ===
+interface I {
+  void f();
+}
+=== EnumConstantImplementsInterface.java ===
+enum EnumConstantImplementsInterface implements I {
+  ONE {
+    @Override
+    public void f() {}
+  };
+}
+=== EnumImplementsInterface.java ===
+enum EnumImplementsInterface implements I {
+  ONE;
+
+  public void f() {}
+}
+=== EnumConstantImplementsMethod.java ===
+enum EnumConstantImplementsMethod {
+  ONE {
+    @Override
+    public void f() {}
+  };
+  public void f() {}
+}
+=== EnumConstantEmptyBody.java ===
+enum EnumConstantEmptyBody {
+  ONE {
+  };
+}
\ No newline at end of file
diff --git a/javatests/com/google/turbine/lower/testdata/golden/outer.txt b/javatests/com/google/turbine/lower/testdata/golden/outer.txt
index b6d541c..dcc6983 100644
--- a/javatests/com/google/turbine/lower/testdata/golden/outer.txt
+++ b/javatests/com/google/turbine/lower/testdata/golden/outer.txt
@@ -16,6 +16,6 @@ public class test/Test implements java/util/List {
   // access flags 0x1
   // signature <V::Ljava/lang/Runnable;E:Ljava/lang/Error;>(I)V^TE;
   // declaration: void g<V extends java.lang.Runnable, E extends java.lang.Error>(int) throws E
-  public g(I)V throws java/lang/Error 
+  public g(I)V throws java/lang/Error
     // parameter  foo
 }
diff --git a/javatests/com/google/turbine/lower/testdata/permits.test b/javatests/com/google/turbine/lower/testdata/permits.test
new file mode 100644
index 0000000..420bc15
--- /dev/null
+++ b/javatests/com/google/turbine/lower/testdata/permits.test
@@ -0,0 +1,5 @@
+=== A.java ===
+sealed interface A {
+  final class B implements A {}
+  record C() implements A {}
+}
\ No newline at end of file
diff --git a/javatests/com/google/turbine/lower/testdata/record_getter_override.test b/javatests/com/google/turbine/lower/testdata/record_getter_override.test
new file mode 100644
index 0000000..b08f13f
--- /dev/null
+++ b/javatests/com/google/turbine/lower/testdata/record_getter_override.test
@@ -0,0 +1,10 @@
+=== Foo.java ===
+import java.util.ArrayList;
+import java.util.List;
+
+public record Foo(int bar, List<String> baz) {
+  /** This should override the default baz() getter. */
+  public List<String> baz() {
+    return baz == null ? new ArrayList<>() : baz;
+  }
+}
\ No newline at end of file
diff --git a/javatests/com/google/turbine/lower/testdata/star_import_visibility.test b/javatests/com/google/turbine/lower/testdata/star_import_visibility.test
new file mode 100644
index 0000000..45acc05
--- /dev/null
+++ b/javatests/com/google/turbine/lower/testdata/star_import_visibility.test
@@ -0,0 +1,21 @@
+=== a/Lib.java ===
+package a;
+class Lib {
+}
+=== b/Lib.java ===
+package b;
+public class Lib {
+}
+=== T.java ===
+import a.*; // a.Lib is not visible, b.Lib should be resolved
+import b.*;
+class T {
+  Lib x;
+}
+=== a/SamePackage.java ===
+package a;
+import a.*; // a.Lib is visible
+import b.*;
+class SamePackage {
+  Lib x;
+}
\ No newline at end of file
diff --git a/javatests/com/google/turbine/lower/testdata/star_import_visibility_nested.test b/javatests/com/google/turbine/lower/testdata/star_import_visibility_nested.test
new file mode 100644
index 0000000..c6f6c7c
--- /dev/null
+++ b/javatests/com/google/turbine/lower/testdata/star_import_visibility_nested.test
@@ -0,0 +1,22 @@
+=== a/Lib.java ===
+package a;
+public class Lib {
+  protected static class Inner {}
+}
+=== b/Lib.java ===
+package b;
+public class Lib {
+  public static class Inner {}
+}
+=== T.java ===
+import a.Lib.*;
+import b.Lib.*;
+class T {
+  Inner x;
+}
+=== S.java ===
+import static a.Lib.*;
+import static b.Lib.*;
+class S {
+  Inner x;
+}
\ No newline at end of file
diff --git a/javatests/com/google/turbine/lower/testdata/textblock2.test b/javatests/com/google/turbine/lower/testdata/textblock2.test
new file mode 100644
index 0000000..f1f0ce4
--- /dev/null
+++ b/javatests/com/google/turbine/lower/testdata/textblock2.test
@@ -0,0 +1,92 @@
+=== T.java ===
+class T {
+  static final String a = """
+    line 1
+    line 2
+    line 3
+    """;
+
+  static final String b = """
+    line 1
+    line 2
+    line 3""";
+
+  static final String c = """
+    """;
+  static final String g =
+      """
+              <html>\r
+                  <body>\r
+                      <p>Hello, world</p>\r
+                  </body>\r
+              </html>\r
+              """;
+  static final String h =
+      """
+    "When I use a word," Humpty Dumpty said,
+    in rather a scornful tone, "it means just what I
+    choose it to mean - neither more nor less."
+    "The question is," said Alice, "whether you
+    can make words mean so many different things."
+    "The question is," said Humpty Dumpty,
+    "which is to be master - that's all."
+    """;
+
+  static final String i = """
+    String empty = "";
+    """;
+
+  static final String j =
+      """
+    String text = \"""
+        A text block inside a text block
+    \""";
+    """;
+
+  static final String k = """
+    A common character
+    in Java programs
+    is \"""";
+
+  static final String l =
+      """
+    The empty string literal
+    is formed from " characters
+    as follows: \"\"""";
+
+  static final String m =
+      """
+    "
+    ""
+    ""\"
+    ""\""
+    ""\"""
+    ""\"""\"
+    ""\"""\""
+    ""\"""\"""
+    ""\"""\"""\"
+    ""\"""\"""\""
+    ""\"""\"""\"""
+    ""\"""\"""\"""\"
+    """;
+
+  static final String n =
+      """
+    Lorem ipsum dolor sit amet, consectetur adipiscing \
+    elit, sed do eiusmod tempor incididunt ut labore \
+    et dolore magna aliqua.\
+    """;
+
+  static final String o = """
+    red  \s
+    green\s
+    blue \s
+    """;
+
+  static final String p =
+      "public void print(Object o) {"
+          + """
+        System.out.println(Objects.toString(o));
+    }
+    """;
+}
diff --git a/javatests/com/google/turbine/lower/testdata/type_anno_cstyle_array_dims.test b/javatests/com/google/turbine/lower/testdata/type_anno_cstyle_array_dims.test
index 117e585..fd22554 100644
--- a/javatests/com/google/turbine/lower/testdata/type_anno_cstyle_array_dims.test
+++ b/javatests/com/google/turbine/lower/testdata/type_anno_cstyle_array_dims.test
@@ -3,13 +3,27 @@ import java.lang.annotation.ElementType;
 import java.lang.annotation.Target;
 import java.util.Map;
 
-@Target(ElementType.TYPE_USE) @interface A {}
+@Target(ElementType.TYPE_USE) @interface A {
+  int value() default 0;
+}
 @Target(ElementType.TYPE_USE) @interface B {}
 @Target(ElementType.TYPE_USE) @interface C {}
 @Target(ElementType.TYPE_USE) @interface D {}
 @Target(ElementType.TYPE_USE) @interface E {}
+@Target(ElementType.TYPE_USE) @interface F {}
+@Target(ElementType.TYPE_USE) @interface G {}
+@Target(ElementType.TYPE_USE) @interface H {}
+@Target(ElementType.TYPE_USE) @interface J {}
+@Target(ElementType.TYPE_USE) @interface K {}
 
 class Test {
   int [] x = {}, y @B @C [] @D @E [] = {{{1}}};
+
+  @A int @B [] @C [] @D [] z @E [] @F [] @G [];
+
   void log(@A Object [] params @B @C [] @D @E []) {}
+
+  @A int @B [] @C [] @D [] f(@A Object @B [] @C [] @D [] params @E [] @F [] @G []) @D [] @E [] @F [] {
+    return null;
+  }
 }
diff --git a/javatests/com/google/turbine/lower/testdata/type_anno_nested.test b/javatests/com/google/turbine/lower/testdata/type_anno_nested.test
new file mode 100644
index 0000000..939329a
--- /dev/null
+++ b/javatests/com/google/turbine/lower/testdata/type_anno_nested.test
@@ -0,0 +1,23 @@
+=== Annotations.java ===
+import static java.lang.annotation.ElementType.TYPE_USE;
+import java.lang.annotation.Target;
+
+@Target(TYPE_USE) @interface A {}
+@Target(TYPE_USE) @interface B {}
+@Target(TYPE_USE) @interface C {}
+
+=== Outer.java ===
+class Outer {
+
+  @A Outer . @B Middle . @C Inner f;
+  Outer . @A MiddleStatic . @B Inner g;
+  Outer . MiddleStatic . @A InnerStatic h;
+
+  class Middle {
+    class Inner {}
+  }
+  static class MiddleStatic {
+    class Inner {}
+    static class InnerStatic {}
+  }
+}
\ No newline at end of file
diff --git a/javatests/com/google/turbine/lower/testdata/type_anno_nested_generic.test b/javatests/com/google/turbine/lower/testdata/type_anno_nested_generic.test
new file mode 100644
index 0000000..fcfe040
--- /dev/null
+++ b/javatests/com/google/turbine/lower/testdata/type_anno_nested_generic.test
@@ -0,0 +1,21 @@
+=== Annotations.java ===
+import static java.lang.annotation.ElementType.TYPE_USE;
+import java.lang.annotation.Target;
+
+@Target(TYPE_USE) @interface A {}
+@Target(TYPE_USE) @interface B {}
+@Target(TYPE_USE) @interface C {}
+@Target(TYPE_USE) @interface D {}
+
+=== Outer.java ===
+class Outer {
+   Outer . Middle<@A Foo . @B Bar> . Inner<@D String @C []> f;
+
+  class Middle<T> {
+    class Inner<U> {}
+  }
+
+  class Foo {
+    class Bar {}
+  }
+}
\ No newline at end of file
diff --git a/javatests/com/google/turbine/lower/testdata/type_anno_nested_raw.test b/javatests/com/google/turbine/lower/testdata/type_anno_nested_raw.test
new file mode 100644
index 0000000..e3fd082
--- /dev/null
+++ b/javatests/com/google/turbine/lower/testdata/type_anno_nested_raw.test
@@ -0,0 +1,32 @@
+=== Annotations.java ===
+import static java.lang.annotation.ElementType.TYPE_USE;
+import java.lang.annotation.Target;
+
+@Target(TYPE_USE) @interface A {}
+@Target(TYPE_USE) @interface B {}
+@Target(TYPE_USE) @interface C {}
+
+=== Outer.java ===
+import java.util.List;
+
+class Outer {
+  static class StaticMiddle<T> {
+    class Inner<U> {}
+    static class StaticInner<U> {}
+
+    // raw types with parameterized enclosing types
+    @A Inner a;
+    @A StaticInner b;
+  }
+
+  Outer . StaticMiddle . @A Inner e;
+  Outer . StaticMiddle . @A StaticInner f;
+  Outer . StaticMiddle<@A String> . @B Inner<@C String> g;
+
+  Outer . StaticMiddle<@A List> . @B Inner<@C List> h;
+  List<Outer . StaticMiddle . @A StaticInner> i;
+
+  // javac rejects these partially raw types
+  // Outer . StaticMiddle<@A String> . @B Inner j;
+  // Outer . StaticMiddle . @B Inner<@C String> k;
+}
diff --git a/javatests/com/google/turbine/main/MainTest.java b/javatests/com/google/turbine/main/MainTest.java
index f65e6c0..c9771d6 100644
--- a/javatests/com/google/turbine/main/MainTest.java
+++ b/javatests/com/google/turbine/main/MainTest.java
@@ -19,7 +19,6 @@ package com.google.turbine.main;
 import static com.google.common.base.StandardSystemProperty.JAVA_CLASS_VERSION;
 import static com.google.common.collect.ImmutableMap.toImmutableMap;
 import static com.google.common.truth.Truth.assertThat;
-import static com.google.common.truth.Truth8.assertThat;
 import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
 import static com.google.turbine.testing.TestClassPaths.optionsWithBootclasspath;
 import static java.nio.charset.StandardCharsets.UTF_8;
@@ -225,6 +224,11 @@ public class MainTest {
                   .toInstant())
           .isEqualTo(
               LocalDateTime.of(2010, 1, 1, 0, 0, 0).atZone(ZoneId.systemDefault()).toInstant());
+      // JarInputStream#getManifest only checks the first two entries for the manifest, so ensure
+      // that turbine writes jars with the manifest at the beginning
+      assertThat(jarFile.stream().limit(2).map(JarEntry::getName))
+          .containsExactly("META-INF/", "META-INF/MANIFEST.MF")
+          .inOrder();
     }
     try (JarFile jarFile = new JarFile(gensrcOutput.toFile())) {
       Manifest manifest = requireNonNull(jarFile.getManifest());
@@ -236,6 +240,9 @@ public class MainTest {
           .containsExactly(
               "Created-By", "bazel",
               "Manifest-Version", "1.0");
+      assertThat(jarFile.stream().limit(2).map(JarEntry::getName))
+          .containsExactly("META-INF/", "META-INF/MANIFEST.MF")
+          .inOrder();
     }
   }
 
diff --git a/javatests/com/google/turbine/options/LanguageVersionTest.java b/javatests/com/google/turbine/options/LanguageVersionTest.java
index a5b303d..81acb64 100644
--- a/javatests/com/google/turbine/options/LanguageVersionTest.java
+++ b/javatests/com/google/turbine/options/LanguageVersionTest.java
@@ -17,7 +17,6 @@
 package com.google.turbine.options;
 
 import static com.google.common.truth.Truth.assertThat;
-import static com.google.common.truth.Truth8.assertThat;
 import static org.junit.Assert.assertThrows;
 
 import com.google.common.collect.ImmutableList;
diff --git a/javatests/com/google/turbine/options/TurbineOptionsTest.java b/javatests/com/google/turbine/options/TurbineOptionsTest.java
index 95eea59..95664de 100644
--- a/javatests/com/google/turbine/options/TurbineOptionsTest.java
+++ b/javatests/com/google/turbine/options/TurbineOptionsTest.java
@@ -17,7 +17,6 @@
 package com.google.turbine.options;
 
 import static com.google.common.truth.Truth.assertThat;
-import static com.google.common.truth.Truth8.assertThat;
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.fail;
 
@@ -193,7 +192,15 @@ public class TurbineOptionsTest {
   public void paramsFile() throws Exception {
     Iterable<String> paramsArgs =
         Iterables.concat(
-            BASE_ARGS, Arrays.asList("--javacopts", "-source", "8", "-target", "8", "--"));
+            BASE_ARGS,
+            Arrays.asList(
+                "--javacopts",
+                "-source",
+                "8",
+                "-target",
+                "8",
+                "-Aconnector.opt=with,space, here",
+                "--"));
     Path params = tmpFolder.newFile("params.txt").toPath();
     Files.write(params, paramsArgs, StandardCharsets.UTF_8);
 
@@ -206,7 +213,9 @@ public class TurbineOptionsTest {
     TurbineOptions options = TurbineOptionsParser.parse(Arrays.asList(lines));
 
     // assert that options were read from params file
-    assertThat(options.javacOpts()).containsExactly("-source", "8", "-target", "8").inOrder();
+    assertThat(options.javacOpts())
+        .containsExactly("-source", "8", "-target", "8", "-Aconnector.opt=with,space, here")
+        .inOrder();
     // ... and directly from the command line
     assertThat(options.targetLabel()).hasValue("//custom/label");
   }
@@ -368,9 +377,18 @@ public class TurbineOptionsTest {
                     "ignored",
                     "--native_header_output",
                     "ignored",
-                    "--compress_jar")));
+                    "--compress_jar",
+                    "--post_processor",
+                    "jacoco",
+                    "paths-for-coverage.txt",
+                    "coverage-metadata",
+                    "-*Test",
+                    "-*TestCase",
+                    "--classpath",
+                    "lib.jar")));
     assertThat(options.outputDeps()).hasValue("output_deps.proto");
     assertThat(options.gensrcOutput()).hasValue("generated_sources.jar");
+    assertThat(options.classPath()).containsExactly("lib.jar");
   }
 
   @Test
diff --git a/javatests/com/google/turbine/parse/JavacLexer.java b/javatests/com/google/turbine/parse/JavacLexer.java
index 6e1a984..6c323c2 100644
--- a/javatests/com/google/turbine/parse/JavacLexer.java
+++ b/javatests/com/google/turbine/parse/JavacLexer.java
@@ -18,7 +18,7 @@ package com.google.turbine.parse;
 
 import com.google.common.base.Function;
 import com.google.common.collect.Lists;
-import com.google.common.escape.SourceCodeEscapers;
+import com.google.turbine.escape.SourceCodeEscapers;
 import com.sun.tools.javac.parser.Scanner;
 import com.sun.tools.javac.parser.ScannerFactory;
 import com.sun.tools.javac.parser.Tokens;
@@ -32,7 +32,7 @@ public final class JavacLexer {
   static List<String> javacLex(final String input) {
     Context context = new Context();
     Scanner scanner =
-        ScannerFactory.instance(context).newScanner(input, /*keepDocComments=*/ false);
+        ScannerFactory.instance(context).newScanner(input, /* keepDocComments= */ false);
     List<Tokens.Token> tokens = new ArrayList<>();
     do {
       scanner.nextToken();
@@ -280,8 +280,9 @@ public final class JavacLexer {
       case CHARLITERAL:
         return String.format(
             "CHAR_LITERAL(%s)", SourceCodeEscapers.javaCharEscaper().escape(token.stringVal()));
+      default:
+        throw new AssertionError("Unknown token kind: " + token.kind);
     }
-    return token.kind.toString();
   }
 
   private JavacLexer() {}
diff --git a/javatests/com/google/turbine/parse/LexerTest.java b/javatests/com/google/turbine/parse/LexerTest.java
index 6a6fe1c..8ec8fba 100644
--- a/javatests/com/google/turbine/parse/LexerTest.java
+++ b/javatests/com/google/turbine/parse/LexerTest.java
@@ -17,11 +17,10 @@
 package com.google.turbine.parse;
 
 import static com.google.common.truth.Truth.assertThat;
-import static org.junit.Assume.assumeTrue;
 
-import com.google.common.escape.SourceCodeEscapers;
 import com.google.common.truth.Expect;
 import com.google.turbine.diag.SourceFile;
+import com.google.turbine.escape.SourceCodeEscapers;
 import java.lang.reflect.Method;
 import java.util.ArrayList;
 import java.util.List;
@@ -383,7 +382,6 @@ public class LexerTest {
 
   @Test
   public void stripIndent() throws Exception {
-    assumeTrue(Runtime.version().feature() >= 13);
     String[] inputs = {
       "",
       "hello",
@@ -401,4 +399,25 @@ public class LexerTest {
       expect.that(StreamLexer.stripIndent(input)).isEqualTo(stripIndent.invoke(input));
     }
   }
+
+  @Test
+  public void textBlockNewlineEscapes() throws Exception {
+    String input =
+        "\"\"\"\n" //
+            + "hello\\\n"
+            + "hello\\\r"
+            + "hello\\\r\n"
+            + "\"\"\"";
+    lexerComparisonTest(input);
+    assertThat(lex(input)).containsExactly("STRING_LITERAL(hellohellohello)", "EOF");
+  }
+
+  // Check for EOF when skipping over escapes in text blocks
+  @Test
+  public void textBlockEOF() {
+    String input = "\"\"\"\n\\";
+    Lexer lexer = new StreamLexer(new UnicodeEscapePreprocessor(new SourceFile(null, input)));
+    assertThat(lexer.next()).isEqualTo(Token.EOF);
+    assertThat(lexer.stringValue()).isEqualTo("\\");
+  }
 }
diff --git a/javatests/com/google/turbine/parse/ParseErrorTest.java b/javatests/com/google/turbine/parse/ParseErrorTest.java
index 4a92648..9abb562 100644
--- a/javatests/com/google/turbine/parse/ParseErrorTest.java
+++ b/javatests/com/google/turbine/parse/ParseErrorTest.java
@@ -240,9 +240,9 @@ public class ParseErrorTest {
         .hasMessageThat()
         .isEqualTo(
             lines(
-                "<>:1: error: unexpected token: <", //
+                "<>:1: error: expected token <identifier>", //
                 "enum\te{p;ullt[].<~>>>L\0",
-                "                ^"));
+                "               ^"));
   }
 
   @Test
@@ -333,6 +333,164 @@ public class ParseErrorTest {
                 "                                               ^"));
   }
 
+  @Test
+  public void textBlockNoTerminator() {
+    String input =
+        lines(
+            "class T {", //
+            "  String a = \"\"\"\"\"\";",
+            "}");
+    TurbineError e = assertThrows(TurbineError.class, () -> Parser.parse(input));
+    assertThat(e)
+        .hasMessageThat()
+        .isEqualTo(
+            lines(
+                "<>:2: error: unexpected input: \"",
+                "  String a = \"\"\"\"\"\";",
+                "                ^"));
+  }
+
+  @Test
+  public void textBlockNoTerminatorSpace() {
+    String input =
+        lines(
+            "class T {", //
+            "  String a = \"\"\" \"\"\";",
+            "}");
+    TurbineError e = assertThrows(TurbineError.class, () -> Parser.parse(input));
+    assertThat(e)
+        .hasMessageThat()
+        .isEqualTo(
+            lines(
+                "<>:2: error: unexpected input: \"",
+                "  String a = \"\"\" \"\"\";",
+                "                 ^"));
+  }
+
+  @Test
+  public void textBlockUnclosed() {
+    String input =
+        lines(
+            "class T {", //
+            "  String a = \"\"\"",
+            "             \"",
+            "}");
+    TurbineError e = assertThrows(TurbineError.class, () -> Parser.parse(input));
+    assertThat(e)
+        .hasMessageThat()
+        .isEqualTo(
+            lines(
+                "<>:2: error: unterminated expression, expected ';' not found",
+                "  String a = \"\"\"",
+                "             ^"));
+  }
+
+  @Test
+  public void textBlockUnescapedBackslash() {
+    String input =
+        lines(
+            "class T {", //
+            "  String a = \"\"\"",
+            "             abc \\ def",
+            "             \"\"\";",
+            "}");
+    TurbineError e = assertThrows(TurbineError.class, () -> Parser.parse(input));
+    assertThat(e)
+        .hasMessageThat()
+        .isEqualTo(
+            lines(
+                "<>:4: error: unexpected input:  ", //
+                "             \"\"\";",
+                "                ^"));
+  }
+
+  // Newline escapes are only allowed in text blocks
+  @Test
+  public void sEscape() {
+    String input =
+        lines(
+            "class T {", //
+            "  String a = \"\\\n" //
+                + "             \";",
+            "}");
+    TurbineError e = assertThrows(TurbineError.class, () -> Parser.parse(input));
+    assertThat(e)
+        .hasMessageThat()
+        .isEqualTo(
+            lines(
+                "<>:2: error: unexpected input: \n", //
+                "  String a = \"\\",
+                "               ^"));
+  }
+
+  @Test
+  public void sEscape_windowsLineEnding() {
+    String input =
+        lines(
+            "class T {", //
+            "  String a = \"\\\r\n" //
+                + "             \";",
+            "}");
+    TurbineError e = assertThrows(TurbineError.class, () -> Parser.parse(input));
+    assertThat(e)
+        .hasMessageThat()
+        .isEqualTo(
+            lines(
+                "<>:2: error: unexpected input: \r", //
+                "  String a = \"\\",
+                "               ^"));
+  }
+
+  @Test
+  public void typeAnnotationAfterDims() {
+    String input =
+        lines(
+            "class T {", //
+            "  int[] @A a;",
+            "}");
+    TurbineError e = assertThrows(TurbineError.class, () -> Parser.parse(input));
+    assertThat(e)
+        .hasMessageThat()
+        .isEqualTo(
+            lines(
+                "<>:2: error: unexpected identifier 'a'", //
+                "  int[] @A a;",
+                "           ^"));
+  }
+
+  @Test
+  public void typeAnnotationBeforeParam() {
+    String input =
+        lines(
+            "class T {", //
+            "  void f(int @A a) {}",
+            "}");
+    TurbineError e = assertThrows(TurbineError.class, () -> Parser.parse(input));
+    assertThat(e)
+        .hasMessageThat()
+        .isEqualTo(
+            lines(
+                "<>:2: error: unexpected identifier 'a'", //
+                "  void f(int @A a) {}",
+                "                ^"));
+  }
+
+  @Test
+  public void moduleInfoOpen() {
+    String input =
+        lines(
+            "open {", //
+            "}");
+    TurbineError e = assertThrows(TurbineError.class, () -> Parser.parse(input));
+    assertThat(e)
+        .hasMessageThat()
+        .isEqualTo(
+            lines(
+                "<>:1: error: unexpected token: {", //
+                "open {",
+                "     ^"));
+  }
+
   private static String lines(String... lines) {
     return Joiner.on(System.lineSeparator()).join(lines);
   }
diff --git a/javatests/com/google/turbine/parse/ParserIntegrationTest.java b/javatests/com/google/turbine/parse/ParserIntegrationTest.java
index 0981815..df58732 100644
--- a/javatests/com/google/turbine/parse/ParserIntegrationTest.java
+++ b/javatests/com/google/turbine/parse/ParserIntegrationTest.java
@@ -72,9 +72,11 @@ public class ParserIntegrationTest {
       "packinfo1.input",
       "weirdstring.input",
       "type_annotations.input",
+      "type_annotations_arrays.input",
       "module-info.input",
       "record.input",
       "sealed.input",
+      "arrays.input",
     };
   }
 
diff --git a/javatests/com/google/turbine/parse/testdata/arrays.input b/javatests/com/google/turbine/parse/testdata/arrays.input
new file mode 100644
index 0000000..6fb55f7
--- /dev/null
+++ b/javatests/com/google/turbine/parse/testdata/arrays.input
@@ -0,0 +1,5 @@
+class T {
+  List<?>[] xs;
+  @A List<?> @B [] ys;
+  List<List<@A int @B []>> zs;
+}
\ No newline at end of file
diff --git a/javatests/com/google/turbine/parse/testdata/type_annotations_arrays.input b/javatests/com/google/turbine/parse/testdata/type_annotations_arrays.input
new file mode 100644
index 0000000..f0439c5
--- /dev/null
+++ b/javatests/com/google/turbine/parse/testdata/type_annotations_arrays.input
@@ -0,0 +1,11 @@
+public class Test {
+  int @A [] @B [] f @C [] @D [];
+  int @A [] @B [] @C [] g @D [] @E [] @F [];
+}
+
+===
+
+public class Test {
+  int @C [] @D [] @A [] @B [] f;
+  int @D [] @E [] @F [] @A [] @B [] @C [] g;
+}
\ No newline at end of file
diff --git a/javatests/com/google/turbine/processing/AbstractTurbineTypesTest.java b/javatests/com/google/turbine/processing/AbstractTurbineTypesTest.java
index 02df1ec..504001b 100644
--- a/javatests/com/google/turbine/processing/AbstractTurbineTypesTest.java
+++ b/javatests/com/google/turbine/processing/AbstractTurbineTypesTest.java
@@ -238,12 +238,15 @@ class AbstractTurbineTypesTest {
     // type annotations
     List<String> annotatedTypes = new ArrayList<>();
     annotatedTypes.add("@A int @B []");
+    annotatedTypes.add("@A int");
     // The string representation of these types changed in JDK 19, see JDK-8281238
     if (Runtime.version().feature() >= 19) {
       annotatedTypes.add("@A List<@B Integer>");
       annotatedTypes.add("@A List");
       annotatedTypes.add("@A List<@A int @B []>");
       annotatedTypes.add("Map.@A Entry<@B Integer, @C Number>");
+      annotatedTypes.add("@A List<@B ? extends @C String>");
+      annotatedTypes.add("@A List<@B ? super @C String>");
     }
 
     List<String> files = new ArrayList<>();
@@ -460,6 +463,9 @@ class AbstractTurbineTypesTest {
 
   /**
    * Discover all types contained in the given element, keyed by their immediate enclosing element.
+   *
+   * <p>This method is executed for both javac and Turbine and is expected to produce the same
+   * results in each case.
    */
   private static void getTypes(
       Types typeUtils, Element element, Multimap<String, TypeMirror> types) {
@@ -506,6 +512,7 @@ class AbstractTurbineTypesTest {
                       if (t.getUpperBound() != null) {
                         types.put(key(e), t.getUpperBound());
                       }
+                      types.put(String.format("getLowerBound(%s)", key(e)), t.getLowerBound());
                       return null;
                     }
                   },
diff --git a/javatests/com/google/turbine/processing/ErrorTypeTest.java b/javatests/com/google/turbine/processing/ErrorTypeTest.java
new file mode 100644
index 0000000..353203d
--- /dev/null
+++ b/javatests/com/google/turbine/processing/ErrorTypeTest.java
@@ -0,0 +1,223 @@
+/*
+ * Copyright 2025 Google Inc. All Rights Reserved.
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
+package com.google.turbine.processing;
+
+import static com.google.common.collect.ImmutableList.toImmutableList;
+import static com.google.common.truth.Truth.assertThat;
+import static org.junit.Assert.assertThrows;
+import static org.junit.Assert.fail;
+
+import com.google.common.base.Joiner;
+import com.google.common.collect.ImmutableList;
+import com.google.common.collect.ImmutableMap;
+import com.google.turbine.binder.Binder;
+import com.google.turbine.binder.ClassPathBinder;
+import com.google.turbine.binder.Processing;
+import com.google.turbine.diag.SourceFile;
+import com.google.turbine.diag.TurbineError;
+import com.google.turbine.lower.IntegrationTestSupport;
+import com.google.turbine.parse.Parser;
+import com.google.turbine.testing.TestClassPaths;
+import com.google.turbine.tree.Tree;
+import com.sun.source.util.JavacTask;
+import java.util.List;
+import java.util.Locale;
+import java.util.Optional;
+import java.util.Set;
+import java.util.function.BiPredicate;
+import java.util.function.Function;
+import javax.annotation.processing.AbstractProcessor;
+import javax.annotation.processing.Processor;
+import javax.annotation.processing.RoundEnvironment;
+import javax.annotation.processing.SupportedAnnotationTypes;
+import javax.lang.model.SourceVersion;
+import javax.lang.model.element.TypeElement;
+import javax.lang.model.element.VariableElement;
+import javax.lang.model.type.DeclaredType;
+import javax.lang.model.type.TypeKind;
+import javax.lang.model.type.TypeMirror;
+import javax.lang.model.type.TypeVariable;
+import javax.lang.model.util.ElementFilter;
+import javax.lang.model.util.Types;
+import javax.tools.Diagnostic;
+import javax.tools.DiagnosticCollector;
+import javax.tools.JavaFileObject;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+// TODO: cushon - consider making the AbstractTurbineTypesTest more similar to this, and using
+// annotation processing to avoid turbine/javac internals.
+public class ErrorTypeTest {
+
+  @SupportedAnnotationTypes("*")
+  static class ErrorTypeProcessor extends AbstractProcessor {
+    @Override
+    public SourceVersion getSupportedSourceVersion() {
+      return SourceVersion.latestSupported();
+    }
+
+    private boolean first = true;
+
+    @Override
+    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
+      if (!first) {
+        return false;
+      }
+      first = false;
+      TypeElement e = processingEnv.getElementUtils().getTypeElement("T");
+      List<VariableElement> field = ElementFilter.fieldsIn(e.getEnclosedElements());
+      Types types = processingEnv.getTypeUtils();
+      for (TypeMirror a : getTypeMirrors(field)) {
+        if (a.getKind() == TypeKind.ERROR) {
+          ImmutableMap<String, Function<TypeMirror, ?>> functions =
+              ImmutableMap.of(
+                  "erasure", types::erasure,
+                  "getTypeVariables",
+                      t ->
+                          t instanceof DeclaredType dt
+                              ? ImmutableList.copyOf(dt.getTypeArguments())
+                              : null,
+                  "directSupertypes", types::directSupertypes);
+          functions.forEach(
+              (name, f) ->
+                  processingEnv
+                      .getMessager()
+                      .printMessage(
+                          Diagnostic.Kind.ERROR,
+                          String.format("%s(%s) = %s", name, a, f.apply(a))));
+        }
+        for (TypeMirror b : getTypeMirrors(field)) {
+          if (a.getKind() != TypeKind.ERROR && b.getKind() != TypeKind.ERROR) {
+            continue;
+          }
+          ImmutableMap<String, BiPredicate<TypeMirror, TypeMirror>> predicates =
+              ImmutableMap.of(
+                  "isSameType", types::isSameType,
+                  "isSubtype", types::isSubtype,
+                  "contains", types::contains,
+                  "isAssignable", types::isAssignable);
+          predicates.forEach(
+              (name, p) ->
+                  processingEnv
+                      .getMessager()
+                      .printMessage(
+                          Diagnostic.Kind.ERROR,
+                          String.format("%s(%s, %s) = %s", name, a, b, p.test(a, b))));
+        }
+      }
+      return false;
+    }
+
+    private static ImmutableList<TypeMirror> getTypeMirrors(List<VariableElement> e) {
+      return e.stream().flatMap(t -> getTypeMirrors(t).stream()).collect(toImmutableList());
+    }
+
+    private static ImmutableList<TypeMirror> getTypeMirrors(VariableElement one) {
+      ImmutableList.Builder<TypeMirror> result = ImmutableList.builder();
+      TypeMirror t = one.asType();
+      result.add(t);
+      if (t.getKind() == TypeKind.TYPEVAR) {
+        result.add(((TypeVariable) t).getLowerBound());
+      }
+      return result.build();
+    }
+  }
+
+  @Test
+  public void errorType() throws Exception {
+
+    IntegrationTestSupport.TestInput input =
+        IntegrationTestSupport.TestInput.parse(
+            """
+            === T.java ===
+            import java.util.List;
+            class T<X> {
+              X a;
+              int b;
+              int[] c;
+              Object o;
+              List<?> l;
+              NoSuch e;
+            }
+            """);
+
+    ImmutableList<String> javacDiagnostics = runJavac(input, new ErrorTypeProcessor());
+
+    ImmutableList<String> turbineDiagnostics = runTurbine(input, new ErrorTypeProcessor());
+
+    assertThat(turbineDiagnostics)
+        .containsExactlyElementsIn(
+            ImmutableList.<String>builder()
+                .addAll(javacDiagnostics)
+                // Both implementations report errors for the missing type NoSuch, but they
+                // aren't exactly the same, and the javac one has been filtered out. We're mostly
+                // interested in the diagnostics about the type predicate results.
+                .add("could not resolve NoSuch")
+                .build());
+  }
+
+  private static ImmutableList<String> runJavac(
+      IntegrationTestSupport.TestInput input, Processor... processors) throws Exception {
+    DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
+    JavacTask task =
+        IntegrationTestSupport.runJavacAnalysis(
+            input.sources,
+            ImmutableList.of(),
+            /* options= */ ImmutableList.of(),
+            diagnostics,
+            ImmutableList.copyOf(processors));
+    if (task.call()) {
+      fail(Joiner.on("\n").join(diagnostics.getDiagnostics()));
+    }
+    return diagnostics.getDiagnostics().stream()
+        .filter(
+            d ->
+                d.getKind() == Diagnostic.Kind.ERROR
+                    && d.getCode().equals("compiler.err.proc.messager"))
+        .map(d -> d.getMessage(Locale.ENGLISH))
+        .collect(toImmutableList());
+  }
+
+  private ImmutableList<String> runTurbine(
+      IntegrationTestSupport.TestInput input, Processor... processors) {
+    ImmutableList<Tree.CompUnit> units =
+        input.sources.entrySet().stream()
+            .map(e -> new SourceFile(e.getKey(), e.getValue()))
+            .map(Parser::parse)
+            .collect(toImmutableList());
+    TurbineError e =
+        assertThrows(
+            TurbineError.class,
+            () ->
+                Binder.bind(
+                    units,
+                    ClassPathBinder.bindClasspath(ImmutableList.of()),
+                    Processing.ProcessorInfo.create(
+                        ImmutableList.copyOf(processors),
+                        getClass().getClassLoader(),
+                        ImmutableMap.of(),
+                        SourceVersion.latestSupported()),
+                    TestClassPaths.TURBINE_BOOTCLASSPATH,
+                    Optional.empty()));
+    return e.diagnostics().stream()
+        .filter(d -> d.severity().equals(Diagnostic.Kind.ERROR))
+        .map(d -> d.message())
+        .collect(toImmutableList());
+  }
+}
diff --git a/javatests/com/google/turbine/processing/ProcessingIntegrationTest.java b/javatests/com/google/turbine/processing/ProcessingIntegrationTest.java
index 65c7ed5..8be0cc3 100644
--- a/javatests/com/google/turbine/processing/ProcessingIntegrationTest.java
+++ b/javatests/com/google/turbine/processing/ProcessingIntegrationTest.java
@@ -19,15 +19,16 @@ package com.google.turbine.processing;
 import static com.google.common.collect.ImmutableList.toImmutableList;
 import static com.google.common.collect.MoreCollectors.onlyElement;
 import static com.google.common.truth.Truth.assertThat;
-import static com.google.common.truth.Truth8.assertThat;
 import static java.nio.charset.StandardCharsets.UTF_8;
 import static java.util.Objects.requireNonNull;
 import static java.util.stream.Collectors.joining;
+import static javax.lang.model.util.ElementFilter.fieldsIn;
 import static javax.lang.model.util.ElementFilter.methodsIn;
 import static javax.lang.model.util.ElementFilter.typesIn;
 import static org.junit.Assert.assertThrows;
-import static org.junit.Assume.assumeTrue;
 
+import com.google.auto.common.MoreElements;
+import com.google.auto.common.MoreTypes;
 import com.google.common.base.Joiner;
 import com.google.common.base.Splitter;
 import com.google.common.collect.ImmutableList;
@@ -35,45 +36,62 @@ import com.google.common.collect.ImmutableMap;
 import com.google.turbine.binder.Binder;
 import com.google.turbine.binder.Binder.BindingResult;
 import com.google.turbine.binder.ClassPathBinder;
-import com.google.turbine.binder.Processing;
 import com.google.turbine.binder.Processing.ProcessorInfo;
+import com.google.turbine.binder.sym.ClassSymbol;
 import com.google.turbine.diag.SourceFile;
 import com.google.turbine.diag.TurbineDiagnostic;
 import com.google.turbine.diag.TurbineError;
+import com.google.turbine.diag.TurbineLog;
 import com.google.turbine.lower.IntegrationTestSupport;
 import com.google.turbine.parse.Parser;
 import com.google.turbine.testing.TestClassPaths;
 import com.google.turbine.tree.Tree;
 import java.io.IOException;
+import java.io.OutputStream;
 import java.io.PrintWriter;
 import java.io.UncheckedIOException;
 import java.io.Writer;
 import java.net.URI;
+import java.nio.file.Files;
 import java.nio.file.Path;
 import java.nio.file.Paths;
+import java.util.Map;
 import java.util.Optional;
 import java.util.Set;
+import java.util.jar.JarEntry;
+import java.util.jar.JarOutputStream;
 import javax.annotation.processing.AbstractProcessor;
 import javax.annotation.processing.ProcessingEnvironment;
+import javax.annotation.processing.Processor;
 import javax.annotation.processing.RoundEnvironment;
 import javax.annotation.processing.SupportedAnnotationTypes;
 import javax.lang.model.SourceVersion;
 import javax.lang.model.element.AnnotationMirror;
 import javax.lang.model.element.Element;
 import javax.lang.model.element.ExecutableElement;
+import javax.lang.model.element.RecordComponentElement;
 import javax.lang.model.element.TypeElement;
+import javax.lang.model.element.VariableElement;
+import javax.lang.model.type.DeclaredType;
+import javax.lang.model.type.ErrorType;
 import javax.lang.model.type.ExecutableType;
+import javax.lang.model.type.TypeMirror;
+import javax.lang.model.util.ElementFilter;
 import javax.tools.Diagnostic;
 import javax.tools.FileObject;
 import javax.tools.JavaFileObject;
 import javax.tools.StandardLocation;
+import org.junit.Rule;
 import org.junit.Test;
+import org.junit.rules.TemporaryFolder;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
 @RunWith(JUnit4.class)
 public class ProcessingIntegrationTest {
 
+  @Rule public final TemporaryFolder temporaryFolder = new TemporaryFolder();
+
   @SupportedAnnotationTypes("*")
   public static class CrashingProcessor extends AbstractProcessor {
 
@@ -96,20 +114,7 @@ public class ProcessingIntegrationTest {
             "@Deprecated",
             "class Test extends NoSuch {",
             "}");
-    TurbineError e =
-        assertThrows(
-            TurbineError.class,
-            () ->
-                Binder.bind(
-                    units,
-                    ClassPathBinder.bindClasspath(ImmutableList.of()),
-                    Processing.ProcessorInfo.create(
-                        ImmutableList.of(new CrashingProcessor()),
-                        getClass().getClassLoader(),
-                        ImmutableMap.of(),
-                        SourceVersion.latestSupported()),
-                    TestClassPaths.TURBINE_BOOTCLASSPATH,
-                    Optional.empty()));
+    TurbineError e = runProcessors(units, new CrashingProcessor());
     ImmutableList<String> messages =
         e.diagnostics().stream().map(TurbineDiagnostic::message).collect(toImmutableList());
     assertThat(messages).hasSize(2);
@@ -156,20 +161,7 @@ public class ProcessingIntegrationTest {
             "@Deprecated",
             "class Test {",
             "}");
-    TurbineError e =
-        assertThrows(
-            TurbineError.class,
-            () ->
-                Binder.bind(
-                    units,
-                    ClassPathBinder.bindClasspath(ImmutableList.of()),
-                    Processing.ProcessorInfo.create(
-                        ImmutableList.of(new WarningProcessor()),
-                        getClass().getClassLoader(),
-                        ImmutableMap.of(),
-                        SourceVersion.latestSupported()),
-                    TestClassPaths.TURBINE_BOOTCLASSPATH,
-                    Optional.empty()));
+    TurbineError e = runProcessors(units, new WarningProcessor());
     ImmutableList<String> diags =
         e.diagnostics().stream().map(d -> d.message()).collect(toImmutableList());
     assertThat(diags).hasSize(2);
@@ -399,20 +391,7 @@ public class ProcessingIntegrationTest {
             "@Deprecated",
             "class Test {",
             "}");
-    TurbineError e =
-        assertThrows(
-            TurbineError.class,
-            () ->
-                Binder.bind(
-                    units,
-                    ClassPathBinder.bindClasspath(ImmutableList.of()),
-                    Processing.ProcessorInfo.create(
-                        ImmutableList.of(new ErrorProcessor(), new FinalRoundErrorProcessor()),
-                        getClass().getClassLoader(),
-                        ImmutableMap.of(),
-                        SourceVersion.latestSupported()),
-                    TestClassPaths.TURBINE_BOOTCLASSPATH,
-                    Optional.empty()));
+    TurbineError e = runProcessors(units, new ErrorProcessor(), new FinalRoundErrorProcessor());
     ImmutableList<String> diags =
         e.diagnostics().stream().map(d -> d.message()).collect(toImmutableList());
     assertThat(diags)
@@ -452,25 +431,29 @@ public class ProcessingIntegrationTest {
             "@Deprecated",
             "class T extends S {",
             "}");
-    TurbineError e =
-        assertThrows(
-            TurbineError.class,
-            () ->
-                Binder.bind(
-                    units,
-                    ClassPathBinder.bindClasspath(ImmutableList.of()),
-                    Processing.ProcessorInfo.create(
-                        ImmutableList.of(new SuperTypeProcessor()),
-                        getClass().getClassLoader(),
-                        ImmutableMap.of(),
-                        SourceVersion.latestSupported()),
-                    TestClassPaths.TURBINE_BOOTCLASSPATH,
-                    Optional.empty()));
+    TurbineError e = runProcessors(units, new SuperTypeProcessor());
     ImmutableList<String> diags =
         e.diagnostics().stream().map(d -> d.message()).collect(toImmutableList());
     assertThat(diags).containsExactly("could not resolve S", "S [S]").inOrder();
   }
 
+  @Test
+  public void superTypeInterfaces() throws IOException {
+    ImmutableList<Tree.CompUnit> units =
+        parseUnit(
+            "=== T.java ===", //
+            "abstract class T implements NoSuch, java.util.List<String> {",
+            "}");
+    TurbineError e = runProcessors(units, new SuperTypeProcessor());
+    ImmutableList<String> diags =
+        e.diagnostics().stream().map(d -> d.message()).collect(toImmutableList());
+    assertThat(diags)
+        .containsExactly(
+            "could not resolve NoSuch",
+            "java.lang.Object [java.lang.Object, java.util.List<java.lang.String>]")
+        .inOrder();
+  }
+
   @SupportedAnnotationTypes("*")
   public static class GenerateAnnotationProcessor extends AbstractProcessor {
 
@@ -547,20 +530,7 @@ public class ProcessingIntegrationTest {
             "=== T.java ===", //
             "class T extends G.I {",
             "}");
-    TurbineError e =
-        assertThrows(
-            TurbineError.class,
-            () ->
-                Binder.bind(
-                    units,
-                    ClassPathBinder.bindClasspath(ImmutableList.of()),
-                    ProcessorInfo.create(
-                        ImmutableList.of(new GenerateQualifiedProcessor()),
-                        getClass().getClassLoader(),
-                        ImmutableMap.of(),
-                        SourceVersion.latestSupported()),
-                    TestClassPaths.TURBINE_BOOTCLASSPATH,
-                    Optional.empty()));
+    TurbineError e = runProcessors(units, new GenerateQualifiedProcessor());
     assertThat(
             e.diagnostics().stream()
                 .filter(d -> d.severity().equals(Diagnostic.Kind.NOTE))
@@ -598,20 +568,7 @@ public class ProcessingIntegrationTest {
         parseUnit(
             "=== T.java ===", //
             "@Deprecated(noSuch = 42) class T {}");
-    TurbineError e =
-        assertThrows(
-            TurbineError.class,
-            () ->
-                Binder.bind(
-                    units,
-                    ClassPathBinder.bindClasspath(ImmutableList.of()),
-                    ProcessorInfo.create(
-                        ImmutableList.of(new ElementValueInspector()),
-                        getClass().getClassLoader(),
-                        ImmutableMap.of(),
-                        SourceVersion.latestSupported()),
-                    TestClassPaths.TURBINE_BOOTCLASSPATH,
-                    Optional.empty()));
+    TurbineError e = runProcessors(units, new ElementValueInspector());
     assertThat(
             e.diagnostics().stream()
                 .filter(d -> d.severity().equals(Diagnostic.Kind.ERROR))
@@ -649,25 +606,11 @@ public class ProcessingIntegrationTest {
 
   @Test
   public void recordProcessing() throws IOException {
-    assumeTrue(Runtime.version().feature() >= 15);
     ImmutableList<Tree.CompUnit> units =
         parseUnit(
             "=== R.java ===", //
             "record R<T>(@Deprecated T x, int... y) {}");
-    TurbineError e =
-        assertThrows(
-            TurbineError.class,
-            () ->
-                Binder.bind(
-                    units,
-                    ClassPathBinder.bindClasspath(ImmutableList.of()),
-                    ProcessorInfo.create(
-                        ImmutableList.of(new RecordProcessor()),
-                        getClass().getClassLoader(),
-                        ImmutableMap.of(),
-                        SourceVersion.latestSupported()),
-                    TestClassPaths.TURBINE_BOOTCLASSPATH,
-                    Optional.empty()));
+    TurbineError e = runProcessors(units, new RecordProcessor());
     assertThat(
             e.diagnostics().stream()
                 .filter(d -> d.severity().equals(Diagnostic.Kind.ERROR))
@@ -684,6 +627,77 @@ public class ProcessingIntegrationTest {
             "METHOD y()");
   }
 
+  @SupportedAnnotationTypes("*")
+  public static class RecordFromADistanceProcessor extends AbstractProcessor {
+    @Override
+    public SourceVersion getSupportedSourceVersion() {
+      return SourceVersion.latestSupported();
+    }
+
+    @Override
+    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
+      processingEnv
+          .getMessager()
+          .printMessage(
+              Diagnostic.Kind.ERROR,
+              roundEnv
+                  .getElementsAnnotatedWith(processingEnv.getElementUtils().getTypeElement("foo.R"))
+                  .stream()
+                  .flatMap(e -> processingEnv.getElementUtils().getAllAnnotationMirrors(e).stream())
+                  .flatMap(a -> a.getElementValues().values().stream())
+                  .flatMap(
+                      x ->
+                          MoreElements.asType(
+                              MoreTypes.asDeclared((TypeMirror) x.getValue()).asElement())
+                              .getRecordComponents()
+                              .stream())
+                  .map(x -> x.getSimpleName())
+                  .collect(toImmutableList())
+                  .toString());
+      return false;
+    }
+  }
+
+  @Test
+  public void bytecodeRecord_componentsAvailable() throws IOException {
+    Map<String, byte[]> library =
+        IntegrationTestSupport.runTurbine(
+            ImmutableMap.of(
+                "MyRecord.java", "package foo; public record MyRecord(int x, int y) {}"),
+            ImmutableList.of());
+    Path libJar = temporaryFolder.newFile("lib.jar").toPath();
+    try (OutputStream os = Files.newOutputStream(libJar);
+        JarOutputStream jos = new JarOutputStream(os)) {
+      jos.putNextEntry(new JarEntry("foo/MyRecord.class"));
+      jos.write(requireNonNull(library.get("foo/MyRecord")));
+    }
+
+    ImmutableList<Tree.CompUnit> units =
+        parseUnit(
+            "=== Y.java ===", //
+            "package foo;",
+            "@interface R { Class<? extends Record> value(); }",
+            "@R(MyRecord.class)",
+            "class Y {}");
+
+    TurbineLog log = new TurbineLog();
+    BindingResult unused =
+        Binder.bind(
+            log,
+            units,
+            ClassPathBinder.bindClasspath(ImmutableList.of(libJar)),
+            ProcessorInfo.create(
+                ImmutableList.of(new RecordFromADistanceProcessor()),
+                getClass().getClassLoader(),
+                ImmutableMap.of(),
+                SourceVersion.latestSupported()),
+            TestClassPaths.TURBINE_BOOTCLASSPATH,
+            Optional.empty());
+    ImmutableList<String> messages =
+        log.diagnostics().stream().map(TurbineDiagnostic::message).collect(toImmutableList());
+    assertThat(messages).contains("[x, y]");
+  }
+
   @Test
   public void missingElementValue() {
     ImmutableList<Tree.CompUnit> units =
@@ -692,21 +706,11 @@ public class ProcessingIntegrationTest {
             "import java.lang.annotation.Retention;",
             "@Retention() @interface T {}");
     TurbineError e =
-        assertThrows(
-            TurbineError.class,
-            () ->
-                Binder.bind(
-                    units,
-                    ClassPathBinder.bindClasspath(ImmutableList.of()),
-                    ProcessorInfo.create(
-                        // missing annotation arguments are not a recoverable error, annotation
-                        // processing shouldn't happen
-                        ImmutableList.of(new CrashingProcessor()),
-                        getClass().getClassLoader(),
-                        ImmutableMap.of(),
-                        SourceVersion.latestSupported()),
-                    TestClassPaths.TURBINE_BOOTCLASSPATH,
-                    Optional.empty()));
+        runProcessors(
+            units,
+            // missing annotation arguments are not a recoverable error, annotation processing
+            // shouldn't happen
+            new CrashingProcessor());
     assertThat(e.diagnostics().stream().map(d -> d.message()))
         .containsExactly("missing required annotation argument: value");
   }
@@ -785,20 +789,7 @@ public class ProcessingIntegrationTest {
             "    return super.f(list);",
             "  }",
             "}");
-    TurbineError e =
-        assertThrows(
-            TurbineError.class,
-            () ->
-                Binder.bind(
-                    units,
-                    ClassPathBinder.bindClasspath(ImmutableList.of()),
-                    ProcessorInfo.create(
-                        ImmutableList.of(new AllMethodsProcessor()),
-                        getClass().getClassLoader(),
-                        ImmutableMap.of(),
-                        SourceVersion.latestSupported()),
-                    TestClassPaths.TURBINE_BOOTCLASSPATH,
-                    Optional.empty()));
+    TurbineError e = runProcessors(units, new AllMethodsProcessor());
     assertThat(e.diagnostics().stream().map(d -> d.message()))
         .containsExactly(
             "A#f<U>(java.util.List<U>)U <: B#f<U>(java.util.List<U>)U ? false",
@@ -844,24 +835,347 @@ public class ProcessingIntegrationTest {
         parseUnit(
             "=== T.java ===", //
             "class T {}");
-    TurbineError e =
-        assertThrows(
-            TurbineError.class,
-            () ->
-                Binder.bind(
-                    units,
-                    ClassPathBinder.bindClasspath(ImmutableList.of()),
-                    ProcessorInfo.create(
-                        ImmutableList.of(new URIProcessor()),
-                        getClass().getClassLoader(),
-                        ImmutableMap.of(),
-                        SourceVersion.latestSupported()),
-                    TestClassPaths.TURBINE_BOOTCLASSPATH,
-                    Optional.empty()));
+    TurbineError e = runProcessors(units, new URIProcessor());
     assertThat(
             e.diagnostics().stream()
                 .filter(d -> d.severity().equals(Diagnostic.Kind.ERROR))
                 .map(d -> d.message()))
         .containsExactly("file:///foo/Bar - " + Paths.get(URI.create("file:///foo/Bar")));
   }
+
+  @SupportedAnnotationTypes("*")
+  public static class MethodAnnotationTypeKindProcessor extends AbstractProcessor {
+    @Override
+    public SourceVersion getSupportedSourceVersion() {
+      return SourceVersion.latestSupported();
+    }
+
+    boolean first = true;
+
+    @Override
+    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
+      if (!first) {
+        return false;
+      }
+      first = false;
+      TypeElement e = processingEnv.getElementUtils().getTypeElement("T");
+      for (AnnotationMirror a : e.getAnnotationMirrors()) {
+        DeclaredType t = a.getAnnotationType();
+        processingEnv
+            .getMessager()
+            .printMessage(Diagnostic.Kind.NOTE, t + "(" + t.getKind() + ")", e);
+        // this shouldn't crash
+        requireNonNull(a.getAnnotationType().asElement().getEnclosedElements());
+      }
+      return false;
+    }
+  }
+
+  @Test
+  public void missingAnnotationType() throws IOException {
+    Map<String, byte[]> library =
+        IntegrationTestSupport.runTurbine(
+            ImmutableMap.of(
+                "A.java", //
+                "@interface A {}",
+                "T.java",
+                "@A class T {}"),
+            ImmutableList.of());
+    Path libJar = temporaryFolder.newFile("lib.jar").toPath();
+    try (OutputStream os = Files.newOutputStream(libJar);
+        JarOutputStream jos = new JarOutputStream(os)) {
+      // deliberately exclude the definition of the annotation
+      jos.putNextEntry(new JarEntry("T.class"));
+      jos.write(requireNonNull(library.get("T")));
+    }
+
+    ImmutableList<Tree.CompUnit> units =
+        parseUnit(
+            "=== Y.java ===", //
+            "class Y {}");
+
+    TurbineLog log = new TurbineLog();
+    BindingResult bound =
+        Binder.bind(
+            log,
+            units,
+            ClassPathBinder.bindClasspath(ImmutableList.of(libJar)),
+            ProcessorInfo.create(
+                ImmutableList.of(new MethodAnnotationTypeKindProcessor()),
+                getClass().getClassLoader(),
+                ImmutableMap.of(),
+                SourceVersion.latestSupported()),
+            TestClassPaths.TURBINE_BOOTCLASSPATH,
+            Optional.empty());
+    assertThat(bound.units().keySet()).containsExactly(new ClassSymbol("Y"));
+    ImmutableList<String> messages =
+        log.diagnostics().stream().map(TurbineDiagnostic::message).collect(toImmutableList());
+    assertThat(messages).containsExactly("A(ERROR)");
+  }
+
+  @SupportedAnnotationTypes("*")
+  public static class RecordComponentProcessor extends AbstractProcessor {
+    @Override
+    public SourceVersion getSupportedSourceVersion() {
+      return SourceVersion.latestSupported();
+    }
+
+    @Override
+    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
+
+      ImmutableList<RecordComponentElement> components =
+          typesIn(roundEnv.getRootElements()).stream()
+              .flatMap(t -> t.getRecordComponents().stream())
+              .collect(toImmutableList());
+      for (RecordComponentElement c : components) {
+        processingEnv
+            .getMessager()
+            .printMessage(
+                Diagnostic.Kind.ERROR,
+                String.format(
+                    "enclosing: %s, name: %s, accessor: %s %s",
+                    c.getEnclosingElement(),
+                    c.getSimpleName(),
+                    c.getAccessor(),
+                    c.getAccessor().getAnnotationMirrors()));
+      }
+      return false;
+    }
+  }
+
+  @Test
+  public void recordComponents() {
+    ImmutableList<Tree.CompUnit> units =
+        parseUnit(
+            "=== C.java ===", //
+            "abstract class C {",
+            "  abstract int x();",
+            "  abstract int t();",
+            "}",
+            "=== R.java ===", //
+            "record R(int x, @Deprecated int y) {",
+            "}");
+    TurbineError e = runProcessors(units, new RecordComponentProcessor());
+    assertThat(e.diagnostics().stream().map(d -> d.message()))
+        .containsExactly(
+            "enclosing: R, name: x, accessor: x() []",
+            "enclosing: R, name: y, accessor: y() [@java.lang.Deprecated]");
+  }
+
+  @SupportedAnnotationTypes("*")
+  public static class ModifiersProcessor extends AbstractProcessor {
+    @Override
+    public SourceVersion getSupportedSourceVersion() {
+      return SourceVersion.latestSupported();
+    }
+
+    @Override
+    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
+      for (Element e : roundEnv.getRootElements()) {
+        processingEnv
+            .getMessager()
+            .printMessage(Diagnostic.Kind.ERROR, String.format("%s %s", e, e.getModifiers()), e);
+      }
+      return false;
+    }
+  }
+
+  @Test
+  public void modifiers() {
+    ImmutableList<Tree.CompUnit> units =
+        parseUnit(
+            "=== I.java ===", //
+            "sealed interface I {}",
+            "non-sealed interface J {}");
+    TurbineError e = runProcessors(units, new ModifiersProcessor());
+    assertThat(e.diagnostics().stream().map(d -> d.message()))
+        .containsExactly("I [abstract, sealed]", "J [abstract, non-sealed]");
+  }
+
+  @SupportedAnnotationTypes("*")
+  public static class PermitsProcessor extends AbstractProcessor {
+    @Override
+    public SourceVersion getSupportedSourceVersion() {
+      return SourceVersion.latestSupported();
+    }
+
+    @Override
+    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
+      for (TypeElement e : ElementFilter.typesIn(roundEnv.getRootElements())) {
+        processingEnv
+            .getMessager()
+            .printMessage(
+                Diagnostic.Kind.ERROR, String.format("%s %s", e, e.getPermittedSubclasses()), e);
+      }
+      return false;
+    }
+  }
+
+  @Test
+  public void permits() {
+    ImmutableList<Tree.CompUnit> units =
+        parseUnit(
+            "=== I.java ===", //
+            "interface I permits J, K {}",
+            "interface J {}",
+            "interface K {}");
+    TurbineError e1 = runProcessors(units, new PermitsProcessor());
+    TurbineError e = e1;
+    assertThat(e.diagnostics().stream().map(d -> d.message()))
+        .containsExactly("I [J, K]", "J []", "K []");
+  }
+
+  @SupportedAnnotationTypes("*")
+  public static class MissingParameterizedTypeProcessor extends AbstractProcessor {
+    @Override
+    public SourceVersion getSupportedSourceVersion() {
+      return SourceVersion.latestSupported();
+    }
+
+    private boolean first = true;
+
+    @Override
+    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
+      if (!first) {
+        return false;
+      }
+      first = false;
+      for (Element root : roundEnv.getRootElements()) {
+        ErrorType superClass = (ErrorType) ((TypeElement) root).getSuperclass();
+        processingEnv
+            .getMessager()
+            .printMessage(
+                Diagnostic.Kind.ERROR,
+                String.format(
+                    "%s supertype: %s, arguments: %s, enclosing: %s",
+                    root,
+                    superClass,
+                    superClass.getTypeArguments(),
+                    superClass.getEnclosingType()));
+        for (Element field : fieldsIn(root.getEnclosedElements())) {
+          ErrorType type = (ErrorType) field.asType();
+          processingEnv
+              .getMessager()
+              .printMessage(
+                  Diagnostic.Kind.ERROR,
+                  String.format(
+                      "%s supertype: %s, arguments: %s, enclosing: %s",
+                      field, type, type.getTypeArguments(), type.getEnclosingType()));
+        }
+      }
+      return false;
+    }
+  }
+
+  @Test
+  public void missingParamterizedType() throws IOException {
+    ImmutableList<Tree.CompUnit> units =
+        parseUnit(
+            "=== T.java ===", //
+            """
+            class T extends M<N> {
+              A a;
+              B<C, D> b;
+              B<C, D>.E<F> c;
+            }
+            """);
+    TurbineError e = runProcessors(units, new MissingParameterizedTypeProcessor());
+    assertThat(
+            e.diagnostics().stream()
+                .filter(d -> d.severity().equals(Diagnostic.Kind.ERROR))
+                .map(d -> d.message()))
+        .containsExactly(
+            "could not resolve M",
+            "could not resolve N",
+            "could not resolve A",
+            "could not resolve B",
+            "could not resolve B.E",
+            "could not resolve C",
+            "could not resolve D",
+            "could not resolve F",
+            "T supertype: M<N>, arguments: [N], enclosing: none",
+            "a supertype: A, arguments: [], enclosing: none",
+            "b supertype: B<C,D>, arguments: [C, D], enclosing: none",
+            "c supertype: B.E<F>, arguments: [F], enclosing: none");
+  }
+
+  @SupportedAnnotationTypes("*")
+  public static class TypeAnnotationFieldType extends AbstractProcessor {
+    @Override
+    public SourceVersion getSupportedSourceVersion() {
+      return SourceVersion.latestSupported();
+    }
+
+    private boolean first = true;
+
+    @Override
+    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
+      if (!first) {
+        return false;
+      }
+      first = false;
+      for (Element root : roundEnv.getRootElements()) {
+        for (VariableElement field : ElementFilter.fieldsIn(root.getEnclosedElements())) {
+          TypeMirror type = field.asType();
+          processingEnv
+              .getMessager()
+              .printMessage(
+                  Diagnostic.Kind.ERROR,
+                  String.format(
+                      "field %s with annotations %s, type '%s' with annotations %s",
+                      field, field.getAnnotationMirrors(), type, type.getAnnotationMirrors()));
+        }
+      }
+      return false;
+    }
+  }
+
+  // Ensure that type annotations are included in the string representation of primtive types
+  @Test
+  public void fieldTypeToString() {
+    ImmutableList<Tree.CompUnit> units =
+        parseUnit(
+            """
+            === T.java ===
+            class T {
+              private final @A int f;
+              private final @A Object g;
+              private final @A int[] h;
+            }
+            === A.java ===
+            import java.lang.annotation.ElementType;
+            import java.lang.annotation.Retention;
+            import java.lang.annotation.RetentionPolicy;
+            import java.lang.annotation.Target;
+            @Retention(RetentionPolicy.SOURCE)
+            @Target({ElementType.TYPE_PARAMETER, ElementType.TYPE_USE})
+            public @interface A {
+            }
+            """);
+    TurbineError e = runProcessors(units, new TypeAnnotationFieldType());
+    assertThat(
+            e.diagnostics().stream()
+                .filter(d -> d.severity().equals(Diagnostic.Kind.ERROR))
+                .map(d -> d.message()))
+        .containsExactly(
+            "field f with annotations [], type '@A int' with annotations [@A]",
+            "field g with annotations [], type 'java.lang.@A Object' with annotations [@A]",
+            "field h with annotations [], type '@A int[]' with annotations []");
+  }
+
+  private TurbineError runProcessors(ImmutableList<Tree.CompUnit> units, Processor... processors) {
+    return assertThrows(
+        TurbineError.class,
+        () ->
+            Binder.bind(
+                units,
+                ClassPathBinder.bindClasspath(ImmutableList.of()),
+                ProcessorInfo.create(
+                    ImmutableList.copyOf(processors),
+                    getClass().getClassLoader(),
+                    ImmutableMap.of(),
+                    SourceVersion.latestSupported()),
+                TestClassPaths.TURBINE_BOOTCLASSPATH,
+                Optional.empty()));
+  }
 }
diff --git a/javatests/com/google/turbine/processing/TurbineElementsHidesTest.java b/javatests/com/google/turbine/processing/TurbineElementsHidesTest.java
index 55e9039..cae2eb3 100644
--- a/javatests/com/google/turbine/processing/TurbineElementsHidesTest.java
+++ b/javatests/com/google/turbine/processing/TurbineElementsHidesTest.java
@@ -25,7 +25,6 @@ import com.google.common.base.Joiner;
 import com.google.common.collect.ImmutableList;
 import com.google.common.collect.ImmutableMap;
 import com.google.common.collect.ImmutableSet;
-import com.google.common.collect.ObjectArrays;
 import com.google.common.truth.Expect;
 import com.google.turbine.binder.Binder;
 import com.google.turbine.binder.ClassPathBinder;
@@ -160,29 +159,20 @@ public class TurbineElementsHidesTest {
         "public class A {",
         "}",
       },
+      {
+        // interfaces
+        "=== A.java ===",
+        "interface A {",
+        "  static void f() {}",
+        "  int x = 42;",
+        "}",
+        "=== B.java ===",
+        "interface B extends A {",
+        "  static void f() {}",
+        "  int x = 42;",
+        "}",
+      }
     };
-    // https://bugs.openjdk.java.net/browse/JDK-8275746
-    if (Runtime.version().feature() >= 11) {
-      inputs =
-          ObjectArrays.concat(
-              inputs,
-              new String[][] {
-                {
-                  // interfaces
-                  "=== A.java ===",
-                  "interface A {",
-                  "  static void f() {}",
-                  "  int x = 42;",
-                  "}",
-                  "=== B.java ===",
-                  "interface B extends A {",
-                  "  static void f() {}",
-                  "  int x = 42;",
-                  "}",
-                }
-              },
-              String[].class);
-    }
     return stream(inputs)
         .map(input -> TestInput.parse(Joiner.on('\n').join(input)))
         .map(x -> new TestInput[] {x})
diff --git a/javatests/com/google/turbine/processing/TurbineFilerTest.java b/javatests/com/google/turbine/processing/TurbineFilerTest.java
index f76a08d..5470e11 100644
--- a/javatests/com/google/turbine/processing/TurbineFilerTest.java
+++ b/javatests/com/google/turbine/processing/TurbineFilerTest.java
@@ -39,7 +39,7 @@ import javax.lang.model.element.Element;
 import javax.tools.FileObject;
 import javax.tools.JavaFileObject;
 import javax.tools.StandardLocation;
-import org.jspecify.nullness.Nullable;
+import org.jspecify.annotations.Nullable;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
diff --git a/javatests/com/google/turbine/processing/TurbineTypeAnnotationMirrorTest.java b/javatests/com/google/turbine/processing/TurbineTypeAnnotationMirrorTest.java
new file mode 100644
index 0000000..fe4d509
--- /dev/null
+++ b/javatests/com/google/turbine/processing/TurbineTypeAnnotationMirrorTest.java
@@ -0,0 +1,588 @@
+/*
+ * Copyright 2023 Google Inc. All Rights Reserved.
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
+package com.google.turbine.processing;
+
+import static com.google.auto.common.AnnotationMirrors.getAnnotationValuesWithDefaults;
+import static com.google.auto.common.MoreElements.asType;
+import static com.google.auto.common.MoreTypes.asDeclared;
+import static com.google.common.collect.ImmutableList.toImmutableList;
+import static com.google.common.collect.ImmutableSet.toImmutableSet;
+import static com.google.common.collect.Iterables.getOnlyElement;
+import static com.google.common.truth.Truth.assertThat;
+import static com.google.common.truth.Truth.assertWithMessage;
+import static java.util.Arrays.stream;
+import static org.junit.Assert.fail;
+
+import com.google.auto.common.AnnotationValues;
+import com.google.auto.common.MoreElements;
+import com.google.auto.common.MoreTypes;
+import com.google.common.base.Joiner;
+import com.google.common.collect.ImmutableList;
+import com.google.common.collect.ImmutableMap;
+import com.google.common.collect.ListMultimap;
+import com.google.common.collect.MultimapBuilder;
+import com.google.turbine.binder.Binder;
+import com.google.turbine.binder.ClassPathBinder;
+import com.google.turbine.binder.Processing;
+import com.google.turbine.diag.SourceFile;
+import com.google.turbine.lower.IntegrationTestSupport;
+import com.google.turbine.lower.IntegrationTestSupport.TestInput;
+import com.google.turbine.lower.Lower;
+import com.google.turbine.parse.Parser;
+import com.google.turbine.testing.TestClassPaths;
+import com.google.turbine.tree.Tree;
+import com.sun.source.util.JavacTask;
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.util.ArrayDeque;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Map;
+import java.util.Optional;
+import java.util.OptionalInt;
+import java.util.Set;
+import java.util.jar.JarEntry;
+import java.util.jar.JarOutputStream;
+import java.util.regex.Pattern;
+import javax.annotation.processing.AbstractProcessor;
+import javax.annotation.processing.RoundEnvironment;
+import javax.annotation.processing.SupportedAnnotationTypes;
+import javax.lang.model.SourceVersion;
+import javax.lang.model.element.AnnotationMirror;
+import javax.lang.model.element.Element;
+import javax.lang.model.element.ElementKind;
+import javax.lang.model.element.ExecutableElement;
+import javax.lang.model.element.Name;
+import javax.lang.model.element.TypeElement;
+import javax.lang.model.element.TypeParameterElement;
+import javax.lang.model.element.VariableElement;
+import javax.lang.model.type.ArrayType;
+import javax.lang.model.type.DeclaredType;
+import javax.lang.model.type.TypeKind;
+import javax.lang.model.type.TypeMirror;
+import javax.lang.model.type.WildcardType;
+import javax.lang.model.util.ElementScanner8;
+import javax.lang.model.util.SimpleTypeVisitor8;
+import javax.tools.DiagnosticCollector;
+import javax.tools.JavaFileObject;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.rules.TemporaryFolder;
+import org.junit.runner.RunWith;
+import org.junit.runners.Parameterized;
+
+/** An integration test for accessing type annotations during annotation processing. */
+@RunWith(Parameterized.class)
+public class TurbineTypeAnnotationMirrorTest {
+
+  @Rule public final TemporaryFolder temporaryFolder = new TemporaryFolder();
+
+  @Parameterized.Parameters
+  public static ImmutableList<Object[]> parameters() {
+    String[][] testCases = {
+      {
+        // super types and interfaces
+        "  interface I {}",
+        "  interface J {}",
+        "  static class CA extends @A(0) Object {}",
+        "  static class CB implements @A(1) I {}",
+        "  static class CC implements @A(2) I, @A(3) J {}",
+        "  static class CD extends @A(4) Object implements @A(5) I, @A(6) J {}",
+      },
+      {
+        // class type parameters
+        "  interface I {}",
+        "  interface J {}",
+        "  class CA<@A(0) X> {}",
+        "  class CB<@A(1) X extends @A(2) Object> {}",
+        "  class CC<@A(3) X extends @A(4) I> {}",
+        "  class CD<@A(5) X extends @A(6) Object & @A(7) I & @A(8) J> {}",
+      },
+      {
+        // method type parameters
+        "  interface I {}",
+        "  interface J {}",
+        "  abstract <@A(0) X> X f();",
+        "  abstract <@A(1) X extends @A(2) Object> X g();",
+        "  abstract <@A(3) X extends @A(4) I> X h();",
+        "  abstract <@A(5) X extends @A(6) Object & @A(7) I & @A(8) J> X i();",
+      },
+      {
+        // constructor type parameters
+        "  interface I {}",
+        "  interface J {}",
+        "  <@A(0) X> Test(X p) {}",
+        "  <@A(1) X extends @A(2) Object> Test(X p, int p2) {}",
+        "  <@A(3) X extends @A(4) I> Test(X p, long p2) {}",
+        "  <@A(5) X extends @A(6) Object & @A(7) I & @A(8) J> Test(X p, double p2) {}",
+      },
+      {
+        // fields
+        "  @A(0) int x;",
+      },
+      {
+        // return types
+        "  abstract @A(0) int f();",
+      },
+      {
+        // method formal parameters
+        "  abstract void f(@A(0) int x, @A(1) int y);", //
+        "  abstract void g(@A(2) Test this, int x, @A(3) int y);",
+      },
+      {
+        // method throws
+        "  abstract void f() throws @A(0) Exception;",
+        "  abstract void g() throws @A(1) Exception, @A(2) RuntimeException;",
+      },
+      {
+        // nested class types
+        "  static class Outer {",
+        "    class Middle {",
+        "      class Inner {}",
+        "    }",
+        "    static class MiddleStatic {",
+        "      class Inner {}",
+        "      static class InnerStatic {}",
+        "    }",
+        "  }",
+        "  @A(0) Outer . @A(1) Middle . @A(2) Inner f;",
+        "  Outer . @A(3) MiddleStatic . @A(4) Inner g;",
+        "  Outer . MiddleStatic . @A(5) InnerStatic h;",
+      },
+      {
+        // wildcards
+        "  interface I<T> {}",
+        "  I<@A(0) ? extends @A(1) String> f;",
+        "  I<@A(2) ? super @A(3) String> g;",
+        "  I<@A(4) ?> h;",
+      },
+      {
+        // arrays
+        "  @A(1) int @A(2) [] @A(3) [] g;",
+      },
+      {
+        // arrays
+        "  @A(0) int @A(1) [] f;",
+        "  @A(2) int @A(3) [] @A(4) [] g;",
+        "  @A(5) int @A(6) [] @A(7) [] @A(8) [] h;",
+      },
+      {
+        // c-style arrays
+        "  @A(0) int @A(1) [] @A(2) [] @A(3) [] h @A(4) [] @A(5) [] @A(6) [];",
+      },
+      {
+        // multi-variable declaration of c-style arrays
+        "  @A(0) int @A(1) [] @A(2) [] x, y @A(3) [] @A(4) [], z @A(5) [] @A(6) [] @A(7) [];",
+      },
+    };
+    return stream(testCases)
+        .map(lines -> new Object[] {String.join("\n", lines)})
+        .collect(toImmutableList());
+  }
+
+  final String test;
+
+  public TurbineTypeAnnotationMirrorTest(String test) {
+    this.test = test;
+  }
+
+  @Test
+  public void test() throws Exception {
+    TestInput input =
+        TestInput.parse(
+            String.join(
+                "\n",
+                "=== Test.java ===",
+                "import java.lang.annotation.ElementType;",
+                "import java.lang.annotation.Retention;",
+                "import java.lang.annotation.RetentionPolicy;",
+                "import java.lang.annotation.Target;",
+                "import java.util.Map;",
+                "import java.util.Map.Entry;",
+                "@Retention(RetentionPolicy.RUNTIME)",
+                "@Target(ElementType.TYPE_USE)",
+                "@interface A {",
+                "  int value();",
+                "}",
+                "abstract class Test {",
+                test,
+                "}",
+                ""));
+
+    Set<String> elements = new HashSet<>();
+
+    // Run javac as a baseline
+    ListMultimap<Integer, String> javacOutput =
+        MultimapBuilder.linkedHashKeys().arrayListValues().build();
+    DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
+    JavacTask task =
+        IntegrationTestSupport.runJavacAnalysis(
+            input.sources,
+            ImmutableList.of(),
+            /* options= */ ImmutableList.of(),
+            diagnostics,
+            ImmutableList.of(new TypeAnnotationRecorder(javacOutput, elements)));
+    if (!task.call()) {
+      fail(Joiner.on("\n").join(diagnostics.getDiagnostics()));
+    }
+
+    ImmutableList<Integer> ids =
+        Pattern.compile("@A\\(([0-9]+)\\)")
+            .matcher(test)
+            .results()
+            .map(match -> Integer.parseInt(match.group(1)))
+            .collect(toImmutableList());
+    assertThat(javacOutput.keySet()).containsExactlyElementsIn(ids);
+
+    // Run the annotation processor using turbine
+    ListMultimap<Integer, String> turbineSource =
+        MultimapBuilder.linkedHashKeys().arrayListValues().build();
+    ImmutableList<Tree.CompUnit> units =
+        input.sources.entrySet().stream()
+            .map(e -> new SourceFile(e.getKey(), e.getValue()))
+            .map(Parser::parse)
+            .collect(toImmutableList());
+    Binder.BindingResult bound =
+        Binder.bind(
+            units,
+            ClassPathBinder.bindClasspath(ImmutableList.of()),
+            Processing.ProcessorInfo.create(
+                ImmutableList.of(new TypeAnnotationRecorder(turbineSource, elements)),
+                getClass().getClassLoader(),
+                ImmutableMap.of(),
+                SourceVersion.latestSupported()),
+            TestClassPaths.TURBINE_BOOTCLASSPATH,
+            Optional.empty());
+
+    // Ensure that the processor produced the same results on both javac and turbine
+    assertWithMessage(test).that(turbineSource).containsExactlyEntriesIn(javacOutput);
+
+    // Run the annotation processor using turbine, with the elements loaded from class files
+    ListMultimap<Integer, String> turbineBytecode =
+        MultimapBuilder.linkedHashKeys().arrayListValues().build();
+    ImmutableMap<String, byte[]> lowered =
+        Lower.lowerAll(
+                Lower.LowerOptions.builder().build(),
+                bound.units(),
+                bound.modules(),
+                bound.classPathEnv())
+            .bytes();
+    Path lib = temporaryFolder.newFile("lib.jar").toPath();
+    try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(lib))) {
+      for (Map.Entry<String, byte[]> entry : lowered.entrySet()) {
+        jos.putNextEntry(new JarEntry(entry.getKey() + ".class"));
+        jos.write(entry.getValue());
+      }
+    }
+    ImmutableList<Path> classpathJar = ImmutableList.of(lib);
+    Binder.BindingResult unused =
+        Binder.bind(
+            // Turbine requires sources to be present to do annotation processing.
+            // The actual element that will be processed is still 'Test' from the classpath.
+            ImmutableList.of(Parser.parse("class Hello {}")),
+            ClassPathBinder.bindClasspath(classpathJar),
+            Processing.ProcessorInfo.create(
+                ImmutableList.of(new TypeAnnotationRecorder(turbineBytecode, elements)),
+                getClass().getClassLoader(),
+                ImmutableMap.of(),
+                SourceVersion.latestSupported()),
+            TestClassPaths.TURBINE_BOOTCLASSPATH,
+            Optional.empty());
+
+    // Ensure that the processor produced the same results on both javac and turbine, when the
+    // elements are loaded from class files
+    assertWithMessage(test).that(turbineBytecode).containsExactlyEntriesIn(javacOutput);
+  }
+
+  /**
+   * An annotation processor that records all type annotations, and their positions, on elements in
+   * the compilation.
+   */
+  @SupportedAnnotationTypes("*")
+  public static class TypeAnnotationRecorder extends AbstractProcessor {
+
+    private final ListMultimap<Integer, String> output;
+    private final Set<String> elements;
+
+    public TypeAnnotationRecorder(ListMultimap<Integer, String> output, Set<String> elements) {
+      this.output = output;
+      this.elements = elements;
+    }
+
+    @Override
+    public SourceVersion getSupportedSourceVersion() {
+      return SourceVersion.latestSupported();
+    }
+
+    boolean first = true;
+
+    @Override
+    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
+      if (first) {
+        // If the given set of elements to process is empty, process all root elements and record
+        // their names in elements. If it's non-empty, process the given elements.
+        // This allows capturing the elements that are discovered during source-based processing,
+        // and then re-processing the same elements when testing bytecode-based processing.
+        boolean writeElements = elements.isEmpty();
+        Set<? extends Element> toProcess =
+            writeElements
+                ? roundEnv.getRootElements()
+                : elements.stream()
+                    .map(processingEnv.getElementUtils()::getTypeElement)
+                    .collect(toImmutableSet());
+        for (Element e : toProcess) {
+          if (writeElements) {
+            elements.add(MoreElements.asType(e).getQualifiedName().toString());
+          }
+          elementVisitor.visit(e);
+        }
+        first = false;
+      }
+      return false;
+    }
+
+    // Visit all elements and record type annotations on types in their signature
+    private final ElementScanner8<Void, Void> elementVisitor =
+        new ElementScanner8<Void, Void>() {
+          @Override
+          public Void visitType(TypeElement e, Void unused) {
+            TypeMirror type = e.getSuperclass();
+            typeVisitor.visit(type, TypePath.of(e, TargetType.EXTENDS));
+            for (int i = 0; i < e.getInterfaces().size(); i++) {
+              TypePath path = TypePath.of(e, TargetType.IMPLEMENTS);
+              typeVisitor.visit(e.getInterfaces().get(i), path);
+            }
+            typeParameters(e.getTypeParameters());
+            return super.visitType(e, unused);
+          }
+
+          @Override
+          public Void visitVariable(VariableElement e, Void unused) {
+            if (e.getKind().equals(ElementKind.FIELD)) {
+              TypeMirror type = e.asType();
+              typeVisitor.visit(type, TypePath.of(e, TargetType.FIELD));
+            }
+            return super.visitVariable(e, unused);
+          }
+
+          @Override
+          public Void visitExecutable(ExecutableElement e, Void unused) {
+            typeVisitor.visit(e.getReturnType(), TypePath.of(e, TargetType.RETURN));
+            if (e.getReceiverType() != null) {
+              // this should never be null, but can be on JDK 11 (see JDK-8222369)
+              typeVisitor.visit(e.getReceiverType(), TypePath.of(e, TargetType.RECEIVER));
+            }
+            for (int i = 0; i < e.getThrownTypes().size(); i++) {
+              TypePath path = TypePath.of(e, TargetType.THROWS, i);
+              typeVisitor.visit(e.getThrownTypes().get(i), path);
+            }
+            for (int i = 0; i < e.getParameters().size(); i++) {
+              VariableElement p = e.getParameters().get(i);
+              TypeMirror type = p.asType();
+              typeVisitor.visit(type, TypePath.of(p, TargetType.FORMAL_PARAMETER, i));
+            }
+            typeParameters(e.getTypeParameters());
+            return super.visitExecutable(e, unused);
+          }
+
+          private void typeParameters(List<? extends TypeParameterElement> typeParameters) {
+            for (int typeParameterIndex = 0;
+                typeParameterIndex < typeParameters.size();
+                typeParameterIndex++) {
+              TypeParameterElement e = typeParameters.get(typeParameterIndex);
+              // type parameter annotations should be on the element, not the elements TypeMirror
+              recordAnnotations(
+                  e.getAnnotationMirrors(), TypePath.of(e, TargetType.TYPE_PARAMETER));
+              typeVisitor.visit(e.asType(), TypePath.of(e, TargetType.TYPE_PARAMETER));
+              for (int boundIndex = 0; boundIndex < e.getBounds().size(); boundIndex++) {
+                TypePath path =
+                    TypePath.of(e, TargetType.TYPE_PARAMETER_BOUND, typeParameterIndex, boundIndex);
+                typeVisitor.visit(e.getBounds().get(boundIndex), path);
+              }
+            }
+          }
+        };
+
+    // Record type annotations on types and their contained types.
+    // There are no new visitX methods in SimpleTypeVisitorN for 9 ≤ N ≤ 21, and there are no new
+    // TYPE_USE annotations locations that were added after 8.
+    private final SimpleTypeVisitor8<Void, TypePath> typeVisitor =
+        new SimpleTypeVisitor8<Void, TypePath>() {
+
+          @Override
+          public Void visitArray(ArrayType t, TypePath path) {
+            defaultAction(t, path);
+            t.getComponentType().accept(this, path.array());
+            return null;
+          }
+
+          @Override
+          public Void visitDeclared(DeclaredType t, TypePath path) {
+            ArrayDeque<DeclaredType> nested = new ArrayDeque<>();
+            for (TypeMirror curr = t;
+                !curr.getKind().equals(TypeKind.NONE);
+                curr = asDeclared(curr).getEnclosingType()) {
+              nested.addFirst(asDeclared(curr));
+            }
+            for (DeclaredType curr : nested) {
+              defaultAction(curr, path);
+              for (int idx = 0; idx < curr.getTypeArguments().size(); idx++) {
+                visit(curr.getTypeArguments().get(idx), path.typeArgument(idx));
+              }
+              path = path.nested();
+            }
+            return null;
+          }
+
+          @Override
+          public Void visitWildcard(WildcardType t, TypePath path) {
+            defaultAction(t, path);
+            if (t.getExtendsBound() != null) {
+              visit(t.getExtendsBound(), path.wildcard());
+            }
+            if (t.getSuperBound() != null) {
+              visit(t.getSuperBound(), path.wildcard());
+            }
+            return null;
+          }
+
+          @Override
+          protected Void defaultAction(TypeMirror t, TypePath path) {
+            recordAnnotations(t.getAnnotationMirrors(), path);
+            return null;
+          }
+        };
+
+    private void recordAnnotations(List<? extends AnnotationMirror> annotations, TypePath path) {
+      for (AnnotationMirror a : annotations) {
+        Name qualifiedName = MoreTypes.asTypeElement(a.getAnnotationType()).getQualifiedName();
+        if (qualifiedName.contentEquals("A")) {
+          int value =
+              AnnotationValues.getInt(getOnlyElement(getAnnotationValuesWithDefaults(a).values()));
+          output.put(value, path.toString());
+        }
+      }
+    }
+
+    enum TargetType {
+      EXTENDS,
+      IMPLEMENTS,
+      FIELD,
+      RETURN,
+      RECEIVER,
+      THROWS,
+      FORMAL_PARAMETER,
+      TYPE_PARAMETER,
+      TYPE_PARAMETER_BOUND;
+    }
+
+    abstract static class TypePath {
+
+      protected abstract void toString(StringBuilder sb);
+
+      @Override
+      public String toString() {
+        StringBuilder sb = new StringBuilder();
+        toString(sb);
+        return sb.toString();
+      }
+
+      static TypePath of(Element base, TargetType targetType) {
+        return new RootPath(base, targetType, OptionalInt.empty(), OptionalInt.empty());
+      }
+
+      static TypePath of(Element base, TargetType targetType, int index) {
+        return new RootPath(base, targetType, OptionalInt.of(index), OptionalInt.empty());
+      }
+
+      static TypePath of(Element base, TargetType targetType, int index, int boundIndex) {
+        return new RootPath(base, targetType, OptionalInt.of(index), OptionalInt.of(boundIndex));
+      }
+
+      static class RootPath extends TypePath {
+        final Element base;
+        final TargetType targetType;
+        final OptionalInt index;
+        final OptionalInt boundIndex;
+
+        RootPath(Element base, TargetType targetType, OptionalInt index, OptionalInt boundIndex) {
+          this.base = base;
+          this.targetType = targetType;
+          this.index = index;
+          this.boundIndex = boundIndex;
+        }
+
+        @Override
+        protected void toString(StringBuilder sb) {
+          sb.append(baseName(base)).append(" ").append(targetType);
+          index.ifPresent(i -> sb.append(" ").append(i));
+          boundIndex.ifPresent(i -> sb.append(" ").append(i));
+        }
+
+        String baseName(Element e) {
+          return e instanceof TypeElement
+              ? asType(e).getQualifiedName().toString()
+              : baseName(e.getEnclosingElement()) + "." + e.getSimpleName();
+        }
+      }
+
+      static class TypeComponentPath extends TypePath {
+
+        enum Kind {
+          ARRAY,
+          NESTED,
+          WILDCARD,
+          TYPE_ARGUMENT,
+        }
+
+        final TypePath parent;
+        final Kind kind;
+        final OptionalInt index;
+
+        TypeComponentPath(TypePath parent, Kind kind, OptionalInt index) {
+          this.parent = parent;
+          this.kind = kind;
+          this.index = index;
+        }
+
+        @Override
+        protected void toString(StringBuilder sb) {
+          parent.toString(sb);
+          sb.append(" -> ");
+          sb.append(kind);
+          index.ifPresent(i -> sb.append(" ").append(i));
+        }
+      }
+
+      public TypePath array() {
+        return new TypeComponentPath(this, TypeComponentPath.Kind.ARRAY, OptionalInt.empty());
+      }
+
+      public TypePath nested() {
+        return new TypeComponentPath(this, TypeComponentPath.Kind.NESTED, OptionalInt.empty());
+      }
+
+      public TypePath typeArgument(int i) {
+        return new TypeComponentPath(this, TypeComponentPath.Kind.TYPE_ARGUMENT, OptionalInt.of(i));
+      }
+
+      public TypePath wildcard() {
+        return new TypeComponentPath(this, TypeComponentPath.Kind.WILDCARD, OptionalInt.empty());
+      }
+    }
+  }
+}
diff --git a/javatests/com/google/turbine/processing/TurbineTypeMirrorTest.java b/javatests/com/google/turbine/processing/TurbineTypeMirrorTest.java
index bf08f89..787e9cf 100644
--- a/javatests/com/google/turbine/processing/TurbineTypeMirrorTest.java
+++ b/javatests/com/google/turbine/processing/TurbineTypeMirrorTest.java
@@ -226,7 +226,7 @@ public class TurbineTypeMirrorTest {
                         .getTypeParameters())
                 .asType();
     assertThat(t.getKind()).isEqualTo(TypeKind.TYPEVAR);
-    assertThat(t.getLowerBound().getKind()).isEqualTo(TypeKind.NONE);
+    assertThat(t.getLowerBound().getKind()).isEqualTo(TypeKind.NULL);
     assertThat(t.getUpperBound().toString()).isEqualTo("java.lang.Comparable<? super T>");
   }
 
diff --git a/javatests/com/google/turbine/processing/TurbineTypesUnaryTest.java b/javatests/com/google/turbine/processing/TurbineTypesUnaryTest.java
index 00eb571..eaa7887 100644
--- a/javatests/com/google/turbine/processing/TurbineTypesUnaryTest.java
+++ b/javatests/com/google/turbine/processing/TurbineTypesUnaryTest.java
@@ -97,6 +97,19 @@ public class TurbineTypesUnaryTest extends AbstractTurbineTypesTest {
   public void erasure() {
     String expected = javacTypes.erasure(javacA).toString();
     String actual = turbineTypes.erasure(turbineA).toString();
+    // Work around javac bug https://bugs.openjdk.org/browse/JDK-8042981 until it is fixed.
+    // The erasure of `@A int @B []` should be just `int[]`, but pre-bugfix javac will report
+    // `@A int @B []`. So for this specific case, change the expected string to what javac *should*
+    // return.
+    switch (turbineA.toString()) {
+      case "@p.Test0.A int @p.Test0.B []":
+        expected = "int[]";
+        break;
+      case "@p.Test0.A int":
+        expected = "int";
+        break;
+      default: // fall out
+    }
     assertWithMessage("erasure(`%s`) = erasure(`%s`)", javacA, turbineA)
         .that(actual)
         .isEqualTo(expected);
@@ -111,6 +124,14 @@ public class TurbineTypesUnaryTest extends AbstractTurbineTypesTest {
 
     String expected = Joiner.on(", ").join(javacTypes.directSupertypes(javacA));
     String actual = Joiner.on(", ").join(turbineTypes.directSupertypes(turbineA));
+    // Work around javac bug https://bugs.openjdk.org/browse/JDK-8042981 until it is fixed.
+    // See comment in the erasure() test method.
+    switch (turbineA.toString()) {
+      case "java.util.@p.Test0.A List<@p.Test0.A int @p.Test0.B []>":
+        expected = "java.lang.Object, java.util.SequencedCollection<int[]>";
+        break;
+      default: // fall out
+    }
     assertWithMessage("directSupertypes(`%s`) = directSupertypes(`%s`)", javacA, turbineA)
         .that(actual)
         .isEqualTo(expected);
diff --git a/javatests/com/google/turbine/testing/AsmUtils.java b/javatests/com/google/turbine/testing/AsmUtils.java
index b7e77bc..c1f2d05 100644
--- a/javatests/com/google/turbine/testing/AsmUtils.java
+++ b/javatests/com/google/turbine/testing/AsmUtils.java
@@ -16,6 +16,10 @@
 
 package com.google.turbine.testing;
 
+import static java.util.stream.Collectors.joining;
+
+import com.google.common.base.CharMatcher;
+import com.google.common.base.Splitter;
 import java.io.PrintWriter;
 import java.io.StringWriter;
 import org.objectweb.asm.ClassReader;
@@ -37,7 +41,12 @@ public final class AsmUtils {
             ClassReader.SKIP_FRAMES
                 | ClassReader.SKIP_CODE
                 | (skipDebug ? ClassReader.SKIP_DEBUG : 0));
-    return sw.toString();
+    // TODO(cushon): Remove this after next ASM update
+    // See https://gitlab.ow2.org/asm/asm/-/commit/af4ee811fde0b14bd7db84aa944a1b3733c37289
+    return Splitter.onPattern("\\R")
+        .splitToStream(sw.toString())
+        .map(CharMatcher.is(' ')::trimTrailingFrom)
+        .collect(joining("\n"));
   }
 
   private AsmUtils() {}
diff --git a/javatests/com/google/turbine/type/TypeTest.java b/javatests/com/google/turbine/type/TypeTest.java
index be3eb9c..3be9b0d 100644
--- a/javatests/com/google/turbine/type/TypeTest.java
+++ b/javatests/com/google/turbine/type/TypeTest.java
@@ -62,7 +62,8 @@ public class TypeTest {
                     ImmutableList.of(
                         new Ident(NO_POSITION, "com"),
                         new Ident(NO_POSITION, "foo"),
-                        new Ident(NO_POSITION, "Bar")))
+                        new Ident(NO_POSITION, "Bar")),
+                    ImmutableList.of())
                 .name())
         .isEqualTo("com.foo.Bar");
   }
diff --git a/javatests/com/google/turbine/zip/ZipTest.java b/javatests/com/google/turbine/zip/ZipTest.java
index b64531a..34c3319 100644
--- a/javatests/com/google/turbine/zip/ZipTest.java
+++ b/javatests/com/google/turbine/zip/ZipTest.java
@@ -32,8 +32,11 @@ import java.nio.file.Files;
 import java.nio.file.Path;
 import java.nio.file.StandardOpenOption;
 import java.nio.file.attribute.FileTime;
+import java.util.ArrayList;
 import java.util.Enumeration;
+import java.util.Iterator;
 import java.util.LinkedHashMap;
+import java.util.List;
 import java.util.Map;
 import java.util.jar.JarEntry;
 import java.util.jar.JarFile;
@@ -324,4 +327,32 @@ public class ZipTest {
     Files.write(path, bytes);
     assertThat(actual(path)).isEqualTo(expected(path));
   }
+
+  @Test
+  public void zip64Offset() throws Exception {
+    Path path = temporaryFolder.newFile("test.jar").toPath();
+    Files.delete(path);
+
+    try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(path))) {
+      byte[] gb = new byte[1 << 30];
+      for (int i = 1; i <= 5; i++) {
+        createEntry(zos, "entry" + i, gb);
+      }
+    }
+
+    List<String> names = new ArrayList<>();
+    Iterator<Zip.Entry> it = new Zip.ZipIterable(path).iterator();
+    Zip.Entry entry = null;
+    while (it.hasNext()) {
+      entry = it.next();
+      names.add(entry.name());
+    }
+    Zip.Entry lastEntry = entry;
+
+    assertThat(names).containsExactly("entry1", "entry2", "entry3", "entry4", "entry5").inOrder();
+    AssertionError e = assertThrows(AssertionError.class, lastEntry::data);
+    assertThat(e)
+        .hasMessageThat()
+        .contains("entry5 requires missing zip64 support, please file a bug");
+  }
 }
diff --git a/pom.xml b/pom.xml
index c96551f..12fa494 100644
--- a/pom.xml
+++ b/pom.xml
@@ -30,15 +30,16 @@
   <url>https://github.com/google/turbine</url>
 
   <properties>
-    <asm.version>9.4</asm.version>
-    <guava.version>31.1-jre</guava.version>
-    <errorprone.version>2.16</errorprone.version>
+    <asm.version>9.7</asm.version>
+    <guava.version>32.1.1-jre</guava.version>
+    <errorprone.version>2.36.0</errorprone.version>
     <maven-javadoc-plugin.version>3.3.1</maven-javadoc-plugin.version>
     <maven-source-plugin.version>3.2.1</maven-source-plugin.version>
     <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
-    <protobuf.version>3.19.2</protobuf.version>
+    <protobuf.version>3.25.5</protobuf.version>
     <grpc.version>1.43.2</grpc.version>
-    <native.maven.plugin.version>0.9.11</native.maven.plugin.version>
+    <native.maven.plugin.version>0.9.23</native.maven.plugin.version>
+    <truth.version>1.4.0</truth.version>
   </properties>
 
   <organization>
@@ -52,6 +53,19 @@
     </developer>
   </developers>
 
+  <scm>
+    <connection>scm:git:https://github.com/google/turbine.git</connection>
+    <developerConnection>scm:git:git@github.com:google/turbine.git</developerConnection>
+    <url>https://github.com/google/turbine</url>
+  </scm>
+
+  <licenses>
+    <license>
+      <name>Apache 2.0</name>
+      <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
+    </license>
+  </licenses>
+
   <dependencies>
     <dependency>
       <groupId>com.google.guava</groupId>
@@ -66,7 +80,7 @@
     <dependency>
       <groupId>org.jspecify</groupId>
       <artifactId>jspecify</artifactId>
-      <version>0.2.0</version>
+      <version>1.0.0</version>
       <optional>true</optional>
     </dependency>
     <dependency>
@@ -101,19 +115,19 @@
     <dependency>
       <groupId>com.google.truth</groupId>
       <artifactId>truth</artifactId>
-      <version>1.1.3</version>
+      <version>${truth.version}</version>
       <scope>test</scope>
     </dependency>
     <dependency>
       <groupId>com.google.truth.extensions</groupId>
       <artifactId>truth-proto-extension</artifactId>
-      <version>1.1.3</version>
+      <version>${truth.version}</version>
       <scope>test</scope>
     </dependency>
     <dependency>
       <groupId>com.google.truth.extensions</groupId>
       <artifactId>truth-java8-extension</artifactId>
-      <version>1.1.3</version>
+      <version>${truth.version}</version>
       <scope>test</scope>
     </dependency>
     <dependency>
@@ -167,13 +181,14 @@
         <artifactId>maven-compiler-plugin</artifactId>
         <version>3.9.0</version>
         <configuration>
-          <source>8</source>
-          <target>8</target>
+          <source>16</source>
+          <target>16</target>
           <encoding>UTF-8</encoding>
           <compilerArgs>
             <arg>-parameters</arg>
             <arg>-XDcompilePolicy=simple</arg>
-            <arg>-Xplugin:ErrorProne</arg>
+            <arg>--should-stop=ifError=FLOW</arg>
+            <arg>-Xplugin:ErrorProne -Xep:EqualsIncompatibleType:ERROR -Xep:TruthIncompatibleType:ERROR</arg>
           </compilerArgs>
           <annotationProcessorPaths>
             <path>
@@ -188,6 +203,23 @@
             </path>
           </annotationProcessorPaths>
         </configuration>
+        <executions>
+          <execution>
+            <id>default-testCompile</id>
+            <phase>test-compile</phase>
+            <goals>
+              <goal>testCompile</goal>
+            </goals>
+            <configuration>
+              <compilerArgs combine.children="append">
+                <arg>--add-exports=jdk.compiler/com.sun.tools.javac.parser=ALL-UNNAMED</arg>
+                <arg>--add-exports=jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED</arg>
+                <arg>--add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED</arg>
+                <arg>--add-exports=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED</arg>
+              </compilerArgs>
+            </configuration>
+          </execution>
+        </executions>
       </plugin>
       <plugin>
         <groupId>org.xolstice.maven.plugins</groupId>
@@ -264,7 +296,7 @@
         <artifactId>maven-javadoc-plugin</artifactId>
         <version>3.3.1</version>
         <configuration>
-          <source>8</source>
+          <source>16</source>
           <detectJavaApiLink>false</detectJavaApiLink>
           <notimestamp>true</notimestamp>
           <doctitle>turbine ${project.version} API</doctitle>
```

