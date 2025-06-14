```
5d422e5: TypeMirror#toString should include type annotations for primitive types (Liam Miller-Cushon <cushon@google.com>)
f69f1cb: Type tests are vacuously true for error types, for compatibility with ja... (Liam Miller-Cushon <cushon@google.com>)
ee12b9a: `getLowerBound()` should return `NULL` instead of `NONE` for variables w... (Liam Miller-Cushon <cushon@google.com>)
370011c: Skip `ErrorType`s in `Types#directSupertypes` for compatibility with jav... (Liam Miller-Cushon <cushon@google.com>)
279d30a: Add janitors to the OWNERS file (Sadaf Ebrahimi <sadafebrahimi@google.com>)
706588c: Support record components when reading records from the classpath. (Javac Team <java-team-github-bot@google.com>)
f04e3d2: Update Error Prone to version 2.36.0 (Liam Miller-Cushon <cushon@google.com>)
1a595dd: Promptly end() the Inflater in Turbine. This will more-eagerly release m... (Javac Team <java-team-github-bot@google.com>)
3fcb10a: Optimize SimpleTopLevelIndex by using a StringCache to canonicalize stri... (nickreid <nickreid@google.com>)
b7b5536: Lazily create `BytecodeBoundClass` objects (Liam Miller-Cushon <cushon@google.com>)
81d79e3: Return a `char` from `formatReleaseVersion` (Liam Miller-Cushon <cushon@google.com>)
fdeba1e: Enable some high value Error Prone checks for turbine (Liam Miller-Cushon <cushon@google.com>)
db74c1f: Only allocate a child-map for SimpleTopLevelIndex.Nodes that represent p... (nickreid <nickreid@google.com>)
0c6eb49: Handle implicit `permits` in turbine (Liam Miller-Cushon <cushon@google.com>)
ffafaff: Fix a bug in where Turbine would add java.base to the module graph of ja... (Goktug Gokdogan <goktug@google.com>)
d8c1bf2: Update Error Prone version to 2.34.0 (Liam Miller-Cushon <cushon@google.com>)
c7c39e4: Bump com.google.protobuf:protobuf-java from 3.19.6 to 3.25.5 in the mave... (dependabot[bot] <49699333+dependabot[bot]@users....)
5a874b7: Remove obsolete runtime version checks from turbine (Liam Miller-Cushon <cushon@google.com>)
99442e8: Improve modeling of parameterized erroneous types (Liam Miller-Cushon <cushon@google.com>)
67aca02: Clean up some obsolete error recovery logic in TurbineElement (Liam Miller-Cushon <cushon@google.com>)
f67d011: Remove unnecessary strictfp modifier (Liam Miller-Cushon <cushon@google.com>)
171153d: Implement `getPermittedSubclasses` (Liam Miller-Cushon <cushon@google.com>)
6574ba5: Support sealed and non-sealed modifiers in `getModifiers` (Liam Miller-Cushon <cushon@google.com>)
7dafb70: Update Error Prone version to 2.32.0 (Liam Miller-Cushon <cushon@google.com>)
9298332: Move turbine's fork of SourceCodeEscapers to a new package (Liam Miller-Cushon <cushon@google.com>)
e1ea3c5: Fix parsing of `module-info` `require` directives that are both `static`... (Liam Miller-Cushon <cushon@google.com>)
5bd2dfa: Use `.turbine` instead of `.class` as the file extension for repackaged ... (Liam Miller-Cushon <cushon@google.com>)
eeb5879: Include package-infos in repackaged transitive classes (Liam Miller-Cushon <cushon@google.com>)
15ed1be: Update CI to reflect that JDK 17 is now the minimum supported version (Liam Miller-Cushon <cushon@google.com>)
296a802: Implement `TypeElement.getRecordComponents` (Liam Miller-Cushon <cushon@google.com>)
781a49a: Extract a test helper in ProcessingIntegrationTest (Liam Miller-Cushon <cushon@google.com>)
1ed4779: Avoid saving string values for tokens that don't require them (Liam Miller-Cushon <cushon@google.com>)
74b8aa3: Use JSpecify 1.0! (Liam Miller-Cushon <cushon@google.com>)
3f51235: Fix `--post_processor` handling after https://github.com/google/turbine/... (Javac Team <java-team-github-bot@google.com>)
73d0d1f: Automatic code cleanup. (Kurt Alfred Kluever <kak@google.com>)
331afa7: Automatic code cleanup. (Kurt Alfred Kluever <kak@google.com>)
c32840c: Automatic code cleanup. (Kurt Alfred Kluever <kak@google.com>)
a49edb3: Automatic code cleanup. (Kurt Alfred Kluever <kak@google.com>)
a991d69: Accept (and ignore) JavaBuilder --post_processor flags (Liam Miller-Cushon <cushon@google.com>)
22174aa: Automatic code cleanup. (Liam Miller-Cushon <cushon@google.com>)
70a8b3c: Mark enums that cannot be extended as final (Liam Miller-Cushon <cushon@google.com>)
fed74bf: Remove support for the String Templates preview feature (Liam Miller-Cushon <cushon@google.com>)
4822097: Don't emit duplicate record component getters (Liam Miller-Cushon <cushon@google.com>)
5637a07: No-op refactor after unknown commit (Liam Miller-Cushon <cushon@google.com>)
ff491a5: Check ct.sym first before falling back to jrt (Stig Rohde Døssing <stig.doessing@crowdstrike.co...)
74c2c36: Update to the latest version of ASM (Liam Miller-Cushon <cushon@google.com>)
ff3b0f7: Add partial zip64 support to turbine's zip implementation (Liam Miller-Cushon <cushon@google.com>)
468742f: Don't crash on unresolvable types in the `permits` list (Liam Miller-Cushon <cushon@google.com>)
47fe3e9: Remove an exhaustive switch on the javac token kind enum (Liam Miller-Cushon <cushon@google.com>)
682cd6e: Fix parsing of `open module ... {}` module declarations (Liam Miller-Cushon <cushon@google.com>)
0664571: Consider visibility when resolving wildcard imports (Liam Miller-Cushon <cushon@google.com>)
d4e29ef: Update turbine's JSpecify version (Liam Miller-Cushon <cushon@google.com>)
f0b18b1: Automatic code cleanup. (cpovirk <cpovirk@google.com>)
63cf102: Update Truth to [1.4.0](https://github.com/google/truth/releases/tag/v1.... (cpovirk <cpovirk@google.com>)
3a9d792: Write `META-INF/MANIFEST.MF` entries at the beginning of jars (Liam Miller-Cushon <cushon@google.com>)
bc7e3ca: Automatic code cleanup. (cpovirk <cpovirk@google.com>)
ad61efa: Automatic code cleanup. (cpovirk <cpovirk@google.com>)
ae0c15f: Update Truth version (Liam Miller-Cushon <cushon@google.com>)
76cff37: Update ASM version to 9.6 to support JDK 22 class files (Liam Miller-Cushon <cushon@google.com>)
2b0a592: Handle string templates (Liam Miller-Cushon <cushon@google.com>)
62d9e65: Fix deannotation of wildcard types (Liam Miller-Cushon <cushon@google.com>)
d3b0c98: Fix removal of type annotations from derived types in `javax.lang.model.... (Liam Miller-Cushon <cushon@google.com>)
36d32d4: Prepare a golden test output for https://bugs.openjdk.org/browse/JDK-832... (Liam Miller-Cushon <cushon@google.com>)
f607f6e: Model types of elements that are missing from the classpath as ERROR typ... (Liam Miller-Cushon <cushon@google.com>)
cf3b973: Allow path to `ct.sym` to be specified via a system property (Fabian Meumertzheim <fabian@meumertzhe.im>)
33ed406: Attach type annotations read from bytecode to types (Liam Miller-Cushon <cushon@google.com>)
a1c7f7e: Fix modelling of array types for annotation processing (Liam Miller-Cushon <cushon@google.com>)
cf5258c: Enable another type annotation case in ClassReaderTest (Liam Miller-Cushon <cushon@google.com>)
af956f2: Remove an obsolete TODO (Liam Miller-Cushon <cushon@google.com>)
a86fafc: Automatic code cleanup. (Javac Team <java-team-github-bot@google.com>)
ae935f4: Fix a crash lexing text blocks (Liam Miller-Cushon <cushon@google.com>)
5b357d0: Class file parsing for type annotations (Liam Miller-Cushon <cushon@google.com>)
07207ee: Use a two-element enum for annotation visibility (Liam Miller-Cushon <cushon@google.com>)
d0a0632: Test that integration test class files round-trip through turbine's clas... (Liam Miller-Cushon <cushon@google.com>)
18df6a7: Fix a long-standing bug with type annotation paths on raw inner class ty... (Liam Miller-Cushon <cushon@google.com>)
05fee69: Improve text block handling (Liam Miller-Cushon <cushon@google.com>)
6fec561: Migrate some type annotation implementation classes to AutoValue (Liam Miller-Cushon <cushon@google.com>)
5584bf5: Reformat with the latest google-java-format changes (Liam Miller-Cushon <cushon@google.com>)
a79e7af: Import of https://gitlab.ow2.org/asm/asm. (Liam Miller-Cushon <cushon@google.com>)
61bd721: Add an overload of `bind` that accepts a log (Liam Miller-Cushon <cushon@google.com>)
0a8f212: Update ci.yml (Liam Miller-Cushon <cushon@google.com>)
cdb0499: Update ci.yml (Liam Miller-Cushon <cushon@google.com>)
08e95c1: Update ci.yml for JDK 21 release (Liam Miller-Cushon <cushon@google.com>)
5f2485b: Rename a test that wasn't being run (Liam Miller-Cushon <cushon@google.com>)
0916053: Use turbine's own class file parser in a test (Liam Miller-Cushon <cushon@google.com>)
4854e4e: Fix class reading on inner class attributes containing local classes (Liam Miller-Cushon <cushon@google.com>)
5fff5da: Add info about which signing keys will be used for published artifacts (Liam Miller-Cushon <cushon@google.com>)
c501f77: Add test case for annotation processor option with space (Gunnar Wagenknecht <gunnar@wagenknecht.org>)
3417047: Update dependency versions (Liam Miller-Cushon <cushon@google.com>)
ba8440a: Add license and SCM information to turbine's pom (Liam Miller-Cushon <cushon@google.com>)
2f7ccab: Update release.yml (Liam Miller-Cushon <cushon@google.com>)
d5c6224: Create release.yml (Liam Miller-Cushon <cushon@google.com>)
e50b5a0: Update native-maven-plugin to 0.9.23 (Fabian Meumertzheim <fabian@meumertzhe.im>)
f81c309: Update ASM version (Liam Miller-Cushon <cushon@google.com>)
a13b70b: Update ci.yml (Liam Miller-Cushon <cushon@google.com>)
3a2aeff: Update Guava version (Liam Miller-Cushon <cushon@google.com>)
```

