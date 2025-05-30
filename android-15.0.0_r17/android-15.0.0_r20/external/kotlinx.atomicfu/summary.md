```
31c3c49: Version 0.23.1 (mvicsokolova <maria.sokolova@jetbrains.com>)
46cf1c9: Update Kotlin to 1.9.21 (#373) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
0a4ff49: Apply Native IR transformations only if Kotlin version in the project is... (mvicsokolova <82594708+mvicsokolova@users.norepl...)
aedae16: Enable error loglevel for partial linkage messages (#367) (Stanislav Ruban <stanislav.ruban@jetbrains.com>)
f83c00d: Version 0.23.0 (mvicsokolova <maria.sokolova@jetbrains.com>)
c9972c7: Introduce Native IR transformations (#363) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
5fe6c0d: Introduce WebAssembly target (#334) (igoriakovlev <54274820+igoriakovlev@users.norepl...)
9d2a3e4: Integration tests (#345) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
90d52fd: Update Kotlin to 1.9.20 (#361) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
f3e66a2: [infra] Fix error in passing kotlin version for train (Margarita Bobova <margarita.bobova@jetbrains.com...)
899b29d: [infra] Pass the custom repo with dev-builds of kotlinc to AFUGP's testi... (Stanislav Ruban <stanislav.ruban@jetbrains.com>)
2b86fbf: [infra] Remove outdated conditional removal of JS/Legacy-related buildsc... (Stanislav Ruban <stanislav.ruban@jetbrains.com>)
c379bee: [infra] Refactor Kotlin aggregate/Kotlin user project buildscript parts (Stanislav Ruban <stanislav.ruban@jetbrains.com>)
4448c71: [infra] Enable binary compatibility validation (Maria.Dumanskaya <maria.dumanskaya@jetbrains.com...)
c9287d1: [migration] Kotlin LV 2.0: KT-59660 (Stanislav Ruban <stanislav.ruban@jetbrains.com>)
ef96cfc: [migration] Kotlin LV 2.0: bump Gradle version to 8.3 (Stanislav Ruban <stanislav.ruban@jetbrains.com>)
c59a938: Fix the WA for the failing clean task on Windows (#351) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
b2b815f: Set dependency between compileNativeTest tasks and Sign tasks (#347) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
1f78257: clean task can't delete the expanded.lock file on Windows (#350) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
6b97f4b: Upgrade JDK target version to 11 in integration tests. (#349) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
de38382: Get rid of `previous-compilation-data.bin` file in META-INF (#344) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
0a74d6f: Use kotlin.concurrent.AtomicInt in SynchronizedTest instead of the old k... (mvicsokolova <maria.sokolova@jetbrains.com>)
dbdcd85: Fix expect/actual mismatched member scope for `open expect` compilation ... (Nikita Bobko <20517828+nikitabobko@users.noreply...)
75667aa: Update apiVersion/languageVersion to 1.9 for atomics implementation. (mvicsokolova <maria.sokolova@jetbrains.com>)
2036268: Update native atomics implementation (mvicsokolova <maria.sokolova@jetbrains.com>)
dec5b94: Update of Gradle Version to 8.1 revealed the problem that publish task u... (mvicsokolova <82594708+mvicsokolova@users.norepl...)
8345a07: Version 0.22.0 (mvicsokolova <maria.sokolova@jetbrains.com>)
2151dcc: Update of Gradle Version to 8.1 revealed the problem that publish task u... (mvicsokolova <82594708+mvicsokolova@users.norepl...)
cfb2f22: Update atomicfu-gradle-plugin tests according to the atomic properties v... (mvicsokolova <maria.sokolova@jetbrains.com>)
7b764f9: Version 0.22.0 (mvicsokolova <maria.sokolova@jetbrains.com>)
367ad27: Update Kotlin to 1.9.0 (#330) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
b948f11: Update kotlinx.metadata to 0.7.0 (#327) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
46d34fd: Comply with new compiler restriction on actual declaration annotations (... (Roman Efremov <merfemor@users.noreply.github.com...)
b0c444b: Remove obsolete no longer supported kotlin.mpp.enableCompatibilityMetada... (Vsevolod Tolstopyatov <qwwdfsad@gmail.com>)
7697fff: Conditionally remove targets that are removed after 1.9.20. (#320) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
33fbf92: Update gradle version to 8.1 (#319) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
f8a2a75: Updated gradle-node-plugin to be compatible with Gradle 7 (#316) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
8c3b92a: Version 0.21.0 (mvicsokolova <maria.sokolova@jetbrains.com>)
7ff4e2f: Do not rename original destination directory of the compile task. (#312) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
88a5e14: Always configure test compilation classpath (#308) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
fea9b5d: Fix duplicated class files in jar for JVM-only projects (#303) (Yahor Berdnikau <yahor.berdnikau@jetbrains.com>)
fb6555d: Configure jvm transformation task via multiplatform configuration functi... (mvicsokolova <maria.sokolova@jetbrains.com>)
c201c53: Fix target compatibility (mvicsokolova <maria.sokolova@jetbrains.com>)
14ddcd1: Update Kotlin to 1.8.20 (mvicsokolova <maria.sokolova@jetbrains.com>)
0fac729: Update gradle to 7.3 (#300) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
d5962f0: Opt-in into experimental interop (KT-57728) to fix aggregate build (#299... (Vsevolod Tolstopyatov <qwwdfsad@gmail.com>)
4dd0a6c: Remove JS Legacy configurations (updated) (#296) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
0f801b3: Fix build error on using KGP removed method (#297) (#298) (Yahor Berdnikau <yahor.berdnikau@jetbrains.com>)
d235d6e: Version 0.20.2 (mvicsokolova <maria.sokolova@jetbrains.com>)
a9a08b9: compileOnly dependency is not published to the compile classpath of the ... (mvicsokolova <82594708+mvicsokolova@users.norepl...)
bfdd8a7: Version 0.20.1 (mvicsokolova <maria.sokolova@jetbrains.com>)
e2433f3: Set apiVersion and languageVersion back to 1.4, because atomicfu-gradle-... (mvicsokolova <82594708+mvicsokolova@users.norepl...)
f2d2d0b: Fix compiler plugin dependency in AtomicfuGradlePlugin (#286) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
4daefcd: Clearly pass `kotlinx-atomicfu-runtime` dependency to the runtime classp... (mvicsokolova <82594708+mvicsokolova@users.norepl...)
d2bfdcd: Replace 'interop-as-source-set-klib.gradle' with cinterop commonization (Sebastian Sellmair <sebastian.sellmair@jetbrains...)
8cd5571: Move license to the root so that GitHub recognizes it (#280) (Roman Elizarov <elizarov@gmail.com>)
f1d0401: Version 0.20.0 (mvicsokolova <maria.sokolova@jetbrains.com>)
ad78630: Update Kotlin to 1.8.10 (mvicsokolova <maria.sokolova@jetbrains.com>)
2a467e0: Support all official K/N targets (#275) (Vsevolod Tolstopyatov <qwwdfsad@gmail.com>)
38fef80: Version 0.19.0 (mvicsokolova <maria.sokolova@jetbrains.com>)
73391b4: Update LV to 1.8 (#270) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
3a3deb6: Specify legacy JS backend explicitly in atomicfu-gradle-plugin tests (Ko... (mvicsokolova <maria.sokolova@jetbrains.com>)
42a635a: Update Kotlin to 1.8.0 (mvicsokolova <maria.sokolova@jetbrains.com>)
16d679c: Update LV to 1.7 (#267) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
48ba832: Legacy JVM bytecode transformer will not support atomic delegates for Ko... (mvicsokolova <82594708+mvicsokolova@users.norepl...)
eee81a9: WA for 1.7 languageVersion: changes in bytecode generation for unchecked... (mvicsokolova <maria.sokolova@jetbrains.com>)
b9395cf: Update kotlin version for atomicfu-gradle-plugin tests (mvicsokolova <maria.sokolova@jetbrains.com>)
a1aba90: Chore(infra): Prepare atomicfu for including to the Kotlin Aggregate bui... (anastasiiaSpaseeva <anastasiia.spaseeva@jetbrain...)
89a8859: Minor fix in README regarding delegated properties (mvicsokolova <maria.sokolova@jetbrains.com>)
462e5be: Replace jcenter() repo with mavenCentral() (#259) (mvicsokolova <82594708+mvicsokolova@users.norepl...)
```

