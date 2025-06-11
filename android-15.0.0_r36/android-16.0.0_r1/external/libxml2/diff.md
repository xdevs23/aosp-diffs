```diff
diff --git a/.gitlab-ci.yml b/.gitlab-ci.yml
index 9c0ccd95..bb5ba44b 100644
--- a/.gitlab-ci.yml
+++ b/.gitlab-ci.yml
@@ -18,7 +18,7 @@ gcc:c89:
   extends: .test
   variables:
     CONFIG: "--without-python"
-    CFLAGS: "-O2 -std=c89 -D_XOPEN_SOURCE=600"
+    CFLAGS: "-O2 -std=c89 -D_XOPEN_SOURCE=600 -Wno-error=unused-function"
 
 gcc:minimum:
   extends: .test
@@ -30,7 +30,7 @@ gcc:medium:
   extends: .test
   variables:
     BASE_CONFIG: "--with-minimum"
-    CONFIG: "--with-threads --with-tree --with-xpath --with-output --with-html --with-iso8859x"
+    CONFIG: "--with-threads --with-tree --with-xpath --with-output --with-html --with-iso8859x --with-valid"
     CFLAGS: "-O2"
 
 gcc:legacy:
@@ -154,6 +154,11 @@ cmake:linux:clang:static:
     CC: clang
     SUFFIX: linux-clang-static
 
+# cmake:mingw is currently broken for unknown reasons.
+#
+# Executing /mingw64/bin/cmake.exe with any arguments fails without error
+# message and exit code 127 since 2025-01-21.
+
 .cmake:mingw:
   tags:
     - win32-ps
@@ -193,6 +198,8 @@ cmake:mingw:w64-i686:static:
 
 cmake:mingw:w64-x86_64:shared:
   extends: .cmake:mingw
+  only:
+    - schedules
   variables:
     BUILD_SHARED_LIBS: "ON"
     MSYSTEM: MINGW64
@@ -286,6 +293,14 @@ cmake:linux:gcc:shared:
     CC: gcc
     SUFFIX: linux-gcc-shared
 
+dist:
+  image: registry.gitlab.gnome.org/gnome/libxml2
+  script:
+    - sh .gitlab-ci/dist.sh
+  artifacts:
+    paths:
+      - libxml2-dist/*.tar.xz
+
 pages:
   script:
     - mkdir -p public
diff --git a/.gitlab-ci/Dockerfile b/.gitlab-ci/Dockerfile
index 82e08c0e..be811557 100644
--- a/.gitlab-ci/Dockerfile
+++ b/.gitlab-ci/Dockerfile
@@ -1,5 +1,12 @@
-# The image is also used for libxslt, that's why we need git and
-# libgcrypt-dev.
+# The image is also used for libxslt.
+#
+# package           required for
+# ------------------------------------------------------------
+# libclang-rt-dev   sanitizer runtimes
+# llvm              llvm-symbolizer (for sanitizer backtraces)
+# git               libxslt
+# libgcrypt-dev     libxslt
+# xz-utils          make dist
 
 FROM ubuntu:24.04
 ENV DEBIAN_FRONTEND=noninteractive
@@ -11,7 +18,8 @@ RUN apt-get update && \
         make gcc clang llvm libclang-rt-dev \
         zlib1g-dev liblzma-dev libgcrypt-dev \
         python3-dev \
-        cmake meson
+        cmake meson \
+        xz-utils
 WORKDIR /tests
 RUN curl https://www.w3.org/XML/Test/xmlts20080827.tar.gz |tar xz
 
diff --git a/.gitlab-ci/dist.sh b/.gitlab-ci/dist.sh
new file mode 100644
index 00000000..59c32425
--- /dev/null
+++ b/.gitlab-ci/dist.sh
@@ -0,0 +1,11 @@
+#!/bin/sh
+
+set -e
+
+mkdir -p libxml2-dist
+cd libxml2-dist
+sh ../autogen.sh
+make distcheck V=1 DISTCHECK_CONFIGURE_FLAGS='--with-legacy'
+if [ -z "$CI_COMMIT_TAG" ]; then
+    mv libxml2-*.tar.xz libxml2-git-$CI_COMMIT_SHORT_SHA.tar.xz
+fi
diff --git a/Android.bp b/Android.bp
index 69f9ca60..038a223f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -71,44 +71,44 @@ license {
 cc_defaults {
     name: "libxml2-defaults",
     srcs: [
-        "entities.c",
+        "SAX2.c",
+        "buf.c",
+        "c14n.c",
+        "catalog.c",
+        "chvalid.c",
+        "debugXML.c",
+        "dict.c",
         "encoding.c",
+        "entities.c",
         "error.c",
-        "parserInternals.c",
-        "parser.c",
-        "tree.c",
+        "globals.c",
         "hash.c",
+        "legacy.c",
         "list.c",
-        "xmlIO.c",
-        "xmlmemory.c",
+        "parser.c",
+        "parserInternals.c",
+        "pattern.c",
+        "relaxng.c",
+        "schematron.c",
+        "threads.c",
+        "tree.c",
         "uri.c",
         "valid.c",
-        "xlink.c",
-        "debugXML.c",
-        "xpath.c",
-        "xpointer.c",
         "xinclude.c",
-        "catalog.c",
-        "globals.c",
-        "threads.c",
-        "c14n.c",
-        "xmlstring.c",
-        "buf.c",
+        "xlink.c",
+        "xmlIO.c",
+        "xmlmemory.c",
+        "xmlmodule.c",
+        "xmlreader.c",
         "xmlregexp.c",
+        "xmlsave.c",
         "xmlschemas.c",
         "xmlschemastypes.c",
+        "xmlstring.c",
         "xmlunicode.c",
-        "xmlreader.c",
-        "relaxng.c",
-        "dict.c",
-        "SAX2.c",
         "xmlwriter.c",
-        "legacy.c",
-        "chvalid.c",
-        "pattern.c",
-        "xmlsave.c",
-        "xmlmodule.c",
-        "schematron.c",
+        "xpath.c",
+        "xpointer.c",
     ],
     stl: "none",
     export_include_dirs: ["include"],
@@ -125,8 +125,8 @@ cc_defaults {
     ],
     static: {
         cflags: [
-            "-fvisibility=hidden",
             "-DSTATIC_LIBXML=1",
+            "-fvisibility=hidden",
         ],
     },
 }
@@ -176,6 +176,7 @@ cc_library_static {
 cc_binary_host {
     name: "xmllint",
     srcs: [
+        "lintmain.c",
         "shell.c",
         "xmllint.c",
     ],
@@ -189,8 +190,8 @@ cc_binary_host {
 cc_binary_host {
     name: "libxml2_genseed",
     srcs: [
-        "fuzz/genSeed.c",
         "fuzz/fuzz.c",
+        "fuzz/genSeed.c",
     ],
     cflags: [
         "-Wno-unused-variable",
@@ -225,9 +226,9 @@ genrule {
     name: "libxml2_schema_fuzz_corpus",
     tools: ["libxml2_genseed"],
     srcs: [
-        "test/schemas/*.xsd",
-        "test/schemas/*.inc",
         "test/schemas/*.imp",
+        "test/schemas/*.inc",
+        "test/schemas/*.xsd",
     ],
     // The genseed tool only writes under its current directory.
     // We move outputs to the correct location after generation..
@@ -239,26 +240,26 @@ genrule {
         "fuzz/seed/schema/570702_0.xsd",
         "fuzz/seed/schema/579746_0.xsd",
         "fuzz/seed/schema/579746_1.xsd",
-        "fuzz/seed/schema/582887_0.xsd",
         "fuzz/seed/schema/582887-attribute.xsd",
         "fuzz/seed/schema/582887-common.xsd",
         "fuzz/seed/schema/582887-element.xsd",
-        "fuzz/seed/schema/582906-1_0.xsd",
+        "fuzz/seed/schema/582887_0.xsd",
         "fuzz/seed/schema/582906-1-common.xsd",
         "fuzz/seed/schema/582906-1-prog1.xsd",
         "fuzz/seed/schema/582906-1-prog2-include.xsd",
         "fuzz/seed/schema/582906-1-prog2.xsd",
-        "fuzz/seed/schema/582906-2_0.xsd",
+        "fuzz/seed/schema/582906-1_0.xsd",
         "fuzz/seed/schema/582906-2-common.xsd",
         "fuzz/seed/schema/582906-2-prog1.xsd",
         "fuzz/seed/schema/582906-2-prog2-include.xsd",
         "fuzz/seed/schema/582906-2-prog2.xsd",
-        "fuzz/seed/schema/all_0.xsd",
+        "fuzz/seed/schema/582906-2_0.xsd",
+        "fuzz/seed/schema/all.xsd",
         "fuzz/seed/schema/all1_0.xsd",
+        "fuzz/seed/schema/all_0.xsd",
         "fuzz/seed/schema/all_1.xsd",
         "fuzz/seed/schema/all_2.xsd",
         "fuzz/seed/schema/allsg_0.xsd",
-        "fuzz/seed/schema/all.xsd",
         "fuzz/seed/schema/annot-err_0.xsd",
         "fuzz/seed/schema/any1_0.xsd",
         "fuzz/seed/schema/any2_0.xsd",
@@ -271,19 +272,19 @@ genrule {
         "fuzz/seed/schema/any7_1.xsd",
         "fuzz/seed/schema/any7_2.xsd",
         "fuzz/seed/schema/any8_1.xsd",
-        "fuzz/seed/schema/anyAttr1_0.xsd",
+        "fuzz/seed/schema/anyAttr-derive-errors1_0.xsd",
         "fuzz/seed/schema/anyAttr-derive1_0.xsd",
         "fuzz/seed/schema/anyAttr-derive2_0.xsd",
-        "fuzz/seed/schema/anyAttr-derive-errors1_0.xsd",
+        "fuzz/seed/schema/anyAttr-processContents-err1_0.xsd",
+        "fuzz/seed/schema/anyAttr-processContents1_0.xsd",
         "fuzz/seed/schema/anyAttr.importA.1_0.xsd",
         "fuzz/seed/schema/anyAttr.importB.1_0.xsd",
-        "fuzz/seed/schema/anyAttr-processContents1_0.xsd",
-        "fuzz/seed/schema/anyAttr-processContents-err1_0.xsd",
+        "fuzz/seed/schema/anyAttr1_0.xsd",
         "fuzz/seed/schema/attr0_0.xsd",
         "fuzz/seed/schema/attruse_0_0.xsd",
         "fuzz/seed/schema/bug141312_0.xsd",
-        "fuzz/seed/schema/bug141333_0.xsd",
         "fuzz/seed/schema/bug141333.xsd",
+        "fuzz/seed/schema/bug141333_0.xsd",
         "fuzz/seed/schema/bug143951_0.xsd",
         "fuzz/seed/schema/bug145246_0.xsd",
         "fuzz/seed/schema/bug152470_1.xsd",
@@ -307,12 +308,12 @@ genrule {
         "fuzz/seed/schema/cos-st-restricts-1-2-err_0.xsd",
         "fuzz/seed/schema/ct-sc-nobase_0.xsd",
         "fuzz/seed/schema/date_0.xsd",
-        "fuzz/seed/schema/decimal-1_1.xsd",
         "fuzz/seed/schema/decimal-1.xsd",
+        "fuzz/seed/schema/decimal-1_1.xsd",
         "fuzz/seed/schema/decimal-2_1.xsd",
         "fuzz/seed/schema/decimal-3_1.xsd",
-        "fuzz/seed/schema/derivation-ok-extension_0.xsd",
         "fuzz/seed/schema/derivation-ok-extension-err_0.xsd",
+        "fuzz/seed/schema/derivation-ok-extension_0.xsd",
         "fuzz/seed/schema/derivation-ok-restriction-2-1-1_0.xsd",
         "fuzz/seed/schema/derivation-ok-restriction-4-1-err_0.xsd",
         "fuzz/seed/schema/derivation-restriction-anyAttr_0.xsd",
@@ -322,9 +323,9 @@ genrule {
         "fuzz/seed/schema/elem0_0.xsd",
         "fuzz/seed/schema/element-err_0.xsd",
         "fuzz/seed/schema/element-minmax-err_0.xsd",
+        "fuzz/seed/schema/empty-value_1.xsd",
         "fuzz/seed/schema/empty_0.xsd",
         "fuzz/seed/schema/empty_1.xsd",
-        "fuzz/seed/schema/empty-value_1.xsd",
         "fuzz/seed/schema/extension0_0.xsd",
         "fuzz/seed/schema/extension1_0.xsd",
         "fuzz/seed/schema/extension2_1.xsd",
@@ -333,10 +334,10 @@ genrule {
         "fuzz/seed/schema/group0_0.xsd",
         "fuzz/seed/schema/hexbinary_0.xsd",
         "fuzz/seed/schema/idc-keyref-err1_1.xsd",
+        "fuzz/seed/schema/import-455953.xsd",
         "fuzz/seed/schema/import0_0.xsd",
         "fuzz/seed/schema/import1_0.xsd",
         "fuzz/seed/schema/import2_0.xsd",
-        "fuzz/seed/schema/import-455953.xsd",
         "fuzz/seed/schema/include1_0.xsd",
         "fuzz/seed/schema/include2_0.xsd",
         "fuzz/seed/schema/include3_0.xsd",
@@ -361,13 +362,13 @@ genrule {
         "fuzz/seed/schema/regexp-char-ref_0.xsd",
         "fuzz/seed/schema/regexp-char-ref_1.xsd",
         "fuzz/seed/schema/restrict-CT-attr-ref_0.xsd",
-        "fuzz/seed/schema/restriction0_0.xsd",
         "fuzz/seed/schema/restriction-attr1_0.xsd",
         "fuzz/seed/schema/restriction-enum-1_1.xsd",
+        "fuzz/seed/schema/restriction0_0.xsd",
         "fuzz/seed/schema/scc-no-xmlns_0.xsd",
         "fuzz/seed/schema/scc-no-xsi_0.xsd",
-        "fuzz/seed/schema/seq0_0.xsd",
         "fuzz/seed/schema/seq-dubl-elem1_0.xsd",
+        "fuzz/seed/schema/seq0_0.xsd",
         "fuzz/seed/schema/src-attribute1_0.xsd",
         "fuzz/seed/schema/src-attribute2_0.xsd",
         "fuzz/seed/schema/src-attribute3-1_0.xsd",
@@ -380,8 +381,8 @@ genrule {
         "fuzz/seed/schema/src-element2-2_0.xsd",
         "fuzz/seed/schema/src-element3_0.xsd",
         "fuzz/seed/schema/subst-group-1_0.xsd",
-        "fuzz/seed/schema/union_0_0.xsd",
         "fuzz/seed/schema/union2_1.xsd",
+        "fuzz/seed/schema/union_0_0.xsd",
         "fuzz/seed/schema/vdv-complexTypes.xsd",
         "fuzz/seed/schema/vdv-first0_0.xsd",
         "fuzz/seed/schema/vdv-first1_0.xsd",
@@ -419,20 +420,20 @@ genrule {
     tools: ["libxml2_genseed"],
     srcs: [
         "test/*",
-        "test/dtds/*.dtd",
-        "test/errors/rec_ext.ent",
-        "test/errors/*.xml",
-        "test/errors10/*.xml",
-        "test/namespaces/*",
-        "test/valid/*.xml",
-        "test/valid/*.dtd",
-        "test/valid/dtds/*",
         "test/VC/*",
         "test/VC/dtds/*.dtd",
         "test/VCM/*",
         "test/XInclude/docs/*",
         "test/XInclude/ents/*",
         "test/XInclude/without-reader/*",
+        "test/dtds/*.dtd",
+        "test/errors/*.xml",
+        "test/errors/rec_ext.ent",
+        "test/errors10/*.xml",
+        "test/namespaces/*",
+        "test/valid/*.dtd",
+        "test/valid/*.xml",
+        "test/valid/dtds/*",
         "test/xmlid/*",
     ],
     // The genseed tool only writes under its current directory.
@@ -442,8 +443,8 @@ genrule {
         "mkdir -p $(genDir)/fuzz/seed/xml && " +
         "mv seed/xml/* $(genDir)/fuzz/seed/xml",
     out: [
-        "fuzz/seed/xml/127772.xml",
         "fuzz/seed/xml/21.xml",
+        "fuzz/seed/xml/127772.xml",
         "fuzz/seed/xml/694228.xml",
         "fuzz/seed/xml/737840.xml",
         "fuzz/seed/xml/754946.xml",
@@ -458,9 +459,32 @@ genrule {
         "fuzz/seed/xml/781205.xml",
         "fuzz/seed/xml/781333.xml",
         "fuzz/seed/xml/781361.xml",
+        "fuzz/seed/xml/AttributeDefaultLegal",
+        "fuzz/seed/xml/AttributeNmtokens",
+        "fuzz/seed/xml/AttributeNmtokens.xml",
+        "fuzz/seed/xml/DuplicateType",
+        "fuzz/seed/xml/ElementValid",
+        "fuzz/seed/xml/ElementValid2",
+        "fuzz/seed/xml/ElementValid3",
+        "fuzz/seed/xml/ElementValid4",
+        "fuzz/seed/xml/ElementValid5",
+        "fuzz/seed/xml/ElementValid6",
+        "fuzz/seed/xml/ElementValid7",
+        "fuzz/seed/xml/ElementValid8",
+        "fuzz/seed/xml/Enumeration",
+        "fuzz/seed/xml/NS1",
+        "fuzz/seed/xml/NS2",
+        "fuzz/seed/xml/NS3",
+        "fuzz/seed/xml/OneID",
+        "fuzz/seed/xml/OneID2",
+        "fuzz/seed/xml/OneID3",
+        "fuzz/seed/xml/PENesting",
+        "fuzz/seed/xml/PENesting2",
+        "fuzz/seed/xml/REC-xml-19980210.xml",
+        "fuzz/seed/xml/UTF16Entity.xml",
+        "fuzz/seed/xml/UniqueElementTypeDeclaration",
+        "fuzz/seed/xml/UniqueElementTypeDeclaration2",
         "fuzz/seed/xml/att1",
-        "fuzz/seed/xml/att10",
-        "fuzz/seed/xml/att11",
         "fuzz/seed/xml/att2",
         "fuzz/seed/xml/att3",
         "fuzz/seed/xml/att4",
@@ -469,36 +493,43 @@ genrule {
         "fuzz/seed/xml/att7",
         "fuzz/seed/xml/att8",
         "fuzz/seed/xml/att9",
+        "fuzz/seed/xml/att10",
+        "fuzz/seed/xml/att11",
         "fuzz/seed/xml/attr1.xml",
         "fuzz/seed/xml/attr2.xml",
         "fuzz/seed/xml/attr3.xml",
         "fuzz/seed/xml/attr4.xml",
-        "fuzz/seed/xml/AttributeDefaultLegal",
-        "fuzz/seed/xml/AttributeNmtokens",
-        "fuzz/seed/xml/AttributeNmtokens.xml",
         "fuzz/seed/xml/attrib.xml",
         "fuzz/seed/xml/badcomment.xml",
         "fuzz/seed/xml/bigentname.xml",
-        "fuzz/seed/xml/bigname2.xml",
         "fuzz/seed/xml/bigname.xml",
+        "fuzz/seed/xml/bigname2.xml",
         "fuzz/seed/xml/cdata",
-        "fuzz/seed/xml/cdata2",
         "fuzz/seed/xml/cdata-2-byte-UTF-8.xml",
         "fuzz/seed/xml/cdata-3-byte-UTF-8.xml",
         "fuzz/seed/xml/cdata-4-byte-UTF-8.xml",
         "fuzz/seed/xml/cdata.xml",
+        "fuzz/seed/xml/cdata2",
         "fuzz/seed/xml/charref1.xml",
+        "fuzz/seed/xml/comment.xml",
         "fuzz/seed/xml/comment1.xml",
         "fuzz/seed/xml/comment2.xml",
         "fuzz/seed/xml/comment3.xml",
         "fuzz/seed/xml/comment4.xml",
         "fuzz/seed/xml/comment5.xml",
         "fuzz/seed/xml/comment6.xml",
-        "fuzz/seed/xml/comment.xml",
         "fuzz/seed/xml/cond_sect1.xml",
         "fuzz/seed/xml/cond_sect2.xml",
         "fuzz/seed/xml/content1.xml",
         "fuzz/seed/xml/dav1",
+        "fuzz/seed/xml/dav2",
+        "fuzz/seed/xml/dav3",
+        "fuzz/seed/xml/dav4",
+        "fuzz/seed/xml/dav5",
+        "fuzz/seed/xml/dav6",
+        "fuzz/seed/xml/dav7",
+        "fuzz/seed/xml/dav8",
+        "fuzz/seed/xml/dav9",
         "fuzz/seed/xml/dav10",
         "fuzz/seed/xml/dav11",
         "fuzz/seed/xml/dav12",
@@ -508,25 +539,13 @@ genrule {
         "fuzz/seed/xml/dav17",
         "fuzz/seed/xml/dav18",
         "fuzz/seed/xml/dav19",
-        "fuzz/seed/xml/dav2",
-        "fuzz/seed/xml/dav3",
-        "fuzz/seed/xml/dav4",
-        "fuzz/seed/xml/dav5",
-        "fuzz/seed/xml/dav6",
-        "fuzz/seed/xml/dav7",
-        "fuzz/seed/xml/dav8",
-        "fuzz/seed/xml/dav9",
-        "fuzz/seed/xml/defattr2.xml",
         "fuzz/seed/xml/defattr.xml",
+        "fuzz/seed/xml/defattr2.xml",
+        "fuzz/seed/xml/dia.xml",
         "fuzz/seed/xml/dia1",
         "fuzz/seed/xml/dia2",
-        "fuzz/seed/xml/dia.xml",
         "fuzz/seed/xml/docids.xml",
         "fuzz/seed/xml/dtd1",
-        "fuzz/seed/xml/dtd10",
-        "fuzz/seed/xml/dtd11",
-        "fuzz/seed/xml/dtd12",
-        "fuzz/seed/xml/dtd13",
         "fuzz/seed/xml/dtd2",
         "fuzz/seed/xml/dtd3",
         "fuzz/seed/xml/dtd4",
@@ -535,35 +554,27 @@ genrule {
         "fuzz/seed/xml/dtd7",
         "fuzz/seed/xml/dtd8",
         "fuzz/seed/xml/dtd9",
-        "fuzz/seed/xml/DuplicateType",
+        "fuzz/seed/xml/dtd10",
+        "fuzz/seed/xml/dtd11",
+        "fuzz/seed/xml/dtd12",
+        "fuzz/seed/xml/dtd13",
         "fuzz/seed/xml/ebcdic_566012.xml",
-        "fuzz/seed/xml/ElementValid",
-        "fuzz/seed/xml/ElementValid2",
-        "fuzz/seed/xml/ElementValid3",
-        "fuzz/seed/xml/ElementValid4",
-        "fuzz/seed/xml/ElementValid5",
-        "fuzz/seed/xml/ElementValid6",
-        "fuzz/seed/xml/ElementValid7",
-        "fuzz/seed/xml/ElementValid8",
         "fuzz/seed/xml/emptycdata.xml",
         "fuzz/seed/xml/ent1",
-        "fuzz/seed/xml/ent10",
-        "fuzz/seed/xml/ent11",
-        "fuzz/seed/xml/ent12",
-        "fuzz/seed/xml/ent13",
         "fuzz/seed/xml/ent2",
         "fuzz/seed/xml/ent3",
         "fuzz/seed/xml/ent4",
         "fuzz/seed/xml/ent5",
         "fuzz/seed/xml/ent6",
         "fuzz/seed/xml/ent7",
-        "fuzz/seed/xml/ent_738805.xml",
         "fuzz/seed/xml/ent8",
         "fuzz/seed/xml/ent9",
-        "fuzz/seed/xml/Enumeration",
+        "fuzz/seed/xml/ent10",
+        "fuzz/seed/xml/ent11",
+        "fuzz/seed/xml/ent12",
+        "fuzz/seed/xml/ent13",
+        "fuzz/seed/xml/ent_738805.xml",
         "fuzz/seed/xml/err_0.xml",
-        "fuzz/seed/xml/err_10.xml",
-        "fuzz/seed/xml/err_11.xml",
         "fuzz/seed/xml/err_1.xml",
         "fuzz/seed/xml/err_2.xml",
         "fuzz/seed/xml/err_3.xml",
@@ -573,15 +584,17 @@ genrule {
         "fuzz/seed/xml/err_7.xml",
         "fuzz/seed/xml/err_8.xml",
         "fuzz/seed/xml/err_9.xml",
+        "fuzz/seed/xml/err_10.xml",
+        "fuzz/seed/xml/err_11.xml",
         "fuzz/seed/xml/eve.xml",
         "fuzz/seed/xml/extparsedent.xml",
+        "fuzz/seed/xml/fallback.xml",
         "fuzz/seed/xml/fallback2.xml",
         "fuzz/seed/xml/fallback3.xml",
         "fuzz/seed/xml/fallback4.xml",
         "fuzz/seed/xml/fallback5.xml",
         "fuzz/seed/xml/fallback6.xml",
         "fuzz/seed/xml/fallback7.xml",
-        "fuzz/seed/xml/fallback.xml",
         "fuzz/seed/xml/icu_parse_test.xml",
         "fuzz/seed/xml/id1.xml",
         "fuzz/seed/xml/id2.xml",
@@ -594,8 +607,8 @@ genrule {
         "fuzz/seed/xml/id_tst4.xml",
         "fuzz/seed/xml/include.xml",
         "fuzz/seed/xml/index.xml",
-        "fuzz/seed/xml/intsubset2.xml",
         "fuzz/seed/xml/intsubset.xml",
+        "fuzz/seed/xml/intsubset2.xml",
         "fuzz/seed/xml/isolat1",
         "fuzz/seed/xml/isolat2",
         "fuzz/seed/xml/isolat3",
@@ -603,67 +616,64 @@ genrule {
         "fuzz/seed/xml/issue424-2.xml",
         "fuzz/seed/xml/japancrlf.xml",
         "fuzz/seed/xml/mixed_ns.xml",
-        "fuzz/seed/xml/name2.xml",
         "fuzz/seed/xml/name.xml",
+        "fuzz/seed/xml/name2.xml",
+        "fuzz/seed/xml/nodes.xml",
         "fuzz/seed/xml/nodes2.xml",
         "fuzz/seed/xml/nodes3.xml",
-        "fuzz/seed/xml/nodes.xml",
         "fuzz/seed/xml/notes.xml",
         "fuzz/seed/xml/ns",
-        "fuzz/seed/xml/NS1",
+        "fuzz/seed/xml/ns.xml",
         "fuzz/seed/xml/ns1.xml",
         "fuzz/seed/xml/ns2",
-        "fuzz/seed/xml/NS2",
         "fuzz/seed/xml/ns2.xml",
         "fuzz/seed/xml/ns3",
-        "fuzz/seed/xml/NS3",
         "fuzz/seed/xml/ns4",
         "fuzz/seed/xml/ns5",
         "fuzz/seed/xml/ns6",
         "fuzz/seed/xml/ns7",
         "fuzz/seed/xml/nsclean.xml",
-        "fuzz/seed/xml/ns.xml",
         "fuzz/seed/xml/objednavka.xml",
-        "fuzz/seed/xml/OneID",
-        "fuzz/seed/xml/OneID2",
-        "fuzz/seed/xml/OneID3",
         "fuzz/seed/xml/p3p",
-        "fuzz/seed/xml/PENesting",
-        "fuzz/seed/xml/PENesting2",
-        "fuzz/seed/xml/pi2.xml",
         "fuzz/seed/xml/pi.xml",
+        "fuzz/seed/xml/pi2.xml",
         "fuzz/seed/xml/rdf1",
         "fuzz/seed/xml/rdf2",
         "fuzz/seed/xml/rec_ext_ent.xml",
         "fuzz/seed/xml/recursive.xml",
-        "fuzz/seed/xml/REC-xml-19980210.xml",
         "fuzz/seed/xml/rss.xml",
-        "fuzz/seed/xml/slashdot16.xml",
         "fuzz/seed/xml/slashdot.rdf",
         "fuzz/seed/xml/slashdot.xml",
+        "fuzz/seed/xml/slashdot16.xml",
         "fuzz/seed/xml/svg1",
         "fuzz/seed/xml/svg2",
         "fuzz/seed/xml/svg3",
-        "fuzz/seed/xml/t10.xml",
-        "fuzz/seed/xml/t11.xml",
-        "fuzz/seed/xml/t4a.xml",
         "fuzz/seed/xml/t4.xml",
+        "fuzz/seed/xml/t4a.xml",
         "fuzz/seed/xml/t6.xml",
-        "fuzz/seed/xml/t8a.xml",
         "fuzz/seed/xml/t8.xml",
-        "fuzz/seed/xml/t9a.xml",
+        "fuzz/seed/xml/t8a.xml",
         "fuzz/seed/xml/t9.xml",
+        "fuzz/seed/xml/t9a.xml",
+        "fuzz/seed/xml/t10.xml",
+        "fuzz/seed/xml/t11.xml",
         "fuzz/seed/xml/title.xml",
         "fuzz/seed/xml/tstblanks.xml",
         "fuzz/seed/xml/tstencoding.xml",
         "fuzz/seed/xml/txtinclude.xml",
-        "fuzz/seed/xml/UniqueElementTypeDeclaration",
-        "fuzz/seed/xml/UniqueElementTypeDeclaration2",
+        "fuzz/seed/xml/utf8bom.xml",
         "fuzz/seed/xml/utf16bebom.xml",
         "fuzz/seed/xml/utf16bom.xml",
-        "fuzz/seed/xml/UTF16Entity.xml",
         "fuzz/seed/xml/utf16lebom.xml",
-        "fuzz/seed/xml/utf8bom.xml",
+        "fuzz/seed/xml/v1.xml",
+        "fuzz/seed/xml/v2.xml",
+        "fuzz/seed/xml/v3.xml",
+        "fuzz/seed/xml/v4.xml",
+        "fuzz/seed/xml/v5.xml",
+        "fuzz/seed/xml/v6.xml",
+        "fuzz/seed/xml/v7.xml",
+        "fuzz/seed/xml/v8.xml",
+        "fuzz/seed/xml/v9.xml",
         "fuzz/seed/xml/v10.xml",
         "fuzz/seed/xml/v11.xml",
         "fuzz/seed/xml/v12.xml",
@@ -674,20 +684,11 @@ genrule {
         "fuzz/seed/xml/v17.xml",
         "fuzz/seed/xml/v18.xml",
         "fuzz/seed/xml/v19.xml",
-        "fuzz/seed/xml/v1.xml",
         "fuzz/seed/xml/v20.xml",
         "fuzz/seed/xml/v21.xml",
         "fuzz/seed/xml/v22.xml",
         "fuzz/seed/xml/v23.xml",
         "fuzz/seed/xml/v24.xml",
-        "fuzz/seed/xml/v2.xml",
-        "fuzz/seed/xml/v3.xml",
-        "fuzz/seed/xml/v4.xml",
-        "fuzz/seed/xml/v5.xml",
-        "fuzz/seed/xml/v6.xml",
-        "fuzz/seed/xml/v7.xml",
-        "fuzz/seed/xml/v8.xml",
-        "fuzz/seed/xml/v9.xml",
         "fuzz/seed/xml/wap.xml",
         "fuzz/seed/xml/winblanks.xml",
         "fuzz/seed/xml/wml.xml",
@@ -725,6 +726,14 @@ genrule {
         "mv seed/xpath/* $(genDir)/fuzz/seed/xpath",
     out: [
         "fuzz/seed/xpath/chapters-1",
+        "fuzz/seed/xpath/chapters-2",
+        "fuzz/seed/xpath/chapters-3",
+        "fuzz/seed/xpath/chapters-4",
+        "fuzz/seed/xpath/chapters-5",
+        "fuzz/seed/xpath/chapters-6",
+        "fuzz/seed/xpath/chapters-7",
+        "fuzz/seed/xpath/chapters-8",
+        "fuzz/seed/xpath/chapters-9",
         "fuzz/seed/xpath/chapters-10",
         "fuzz/seed/xpath/chapters-11",
         "fuzz/seed/xpath/chapters-12",
@@ -735,7 +744,6 @@ genrule {
         "fuzz/seed/xpath/chapters-17",
         "fuzz/seed/xpath/chapters-18",
         "fuzz/seed/xpath/chapters-19",
-        "fuzz/seed/xpath/chapters-2",
         "fuzz/seed/xpath/chapters-20",
         "fuzz/seed/xpath/chapters-21",
         "fuzz/seed/xpath/chapters-22",
@@ -746,7 +754,6 @@ genrule {
         "fuzz/seed/xpath/chapters-27",
         "fuzz/seed/xpath/chapters-28",
         "fuzz/seed/xpath/chapters-29",
-        "fuzz/seed/xpath/chapters-3",
         "fuzz/seed/xpath/chapters-30",
         "fuzz/seed/xpath/chapters-31",
         "fuzz/seed/xpath/chapters-32",
@@ -757,14 +764,105 @@ genrule {
         "fuzz/seed/xpath/chapters-37",
         "fuzz/seed/xpath/chapters-38",
         "fuzz/seed/xpath/chapters-39",
-        "fuzz/seed/xpath/chapters-4",
-        "fuzz/seed/xpath/chapters-5",
-        "fuzz/seed/xpath/chapters-6",
-        "fuzz/seed/xpath/chapters-7",
-        "fuzz/seed/xpath/chapters-8",
-        "fuzz/seed/xpath/chapters-9",
         "fuzz/seed/xpath/expr-1",
+        "fuzz/seed/xpath/expr-2",
+        "fuzz/seed/xpath/expr-3",
+        "fuzz/seed/xpath/expr-4",
+        "fuzz/seed/xpath/expr-5",
+        "fuzz/seed/xpath/expr-6",
+        "fuzz/seed/xpath/expr-7",
+        "fuzz/seed/xpath/expr-8",
+        "fuzz/seed/xpath/expr-9",
         "fuzz/seed/xpath/expr-10",
+        "fuzz/seed/xpath/expr-11",
+        "fuzz/seed/xpath/expr-12",
+        "fuzz/seed/xpath/expr-13",
+        "fuzz/seed/xpath/expr-14",
+        "fuzz/seed/xpath/expr-15",
+        "fuzz/seed/xpath/expr-16",
+        "fuzz/seed/xpath/expr-17",
+        "fuzz/seed/xpath/expr-18",
+        "fuzz/seed/xpath/expr-19",
+        "fuzz/seed/xpath/expr-20",
+        "fuzz/seed/xpath/expr-21",
+        "fuzz/seed/xpath/expr-22",
+        "fuzz/seed/xpath/expr-23",
+        "fuzz/seed/xpath/expr-24",
+        "fuzz/seed/xpath/expr-25",
+        "fuzz/seed/xpath/expr-26",
+        "fuzz/seed/xpath/expr-27",
+        "fuzz/seed/xpath/expr-28",
+        "fuzz/seed/xpath/expr-29",
+        "fuzz/seed/xpath/expr-30",
+        "fuzz/seed/xpath/expr-31",
+        "fuzz/seed/xpath/expr-32",
+        "fuzz/seed/xpath/expr-33",
+        "fuzz/seed/xpath/expr-34",
+        "fuzz/seed/xpath/expr-35",
+        "fuzz/seed/xpath/expr-36",
+        "fuzz/seed/xpath/expr-37",
+        "fuzz/seed/xpath/expr-38",
+        "fuzz/seed/xpath/expr-39",
+        "fuzz/seed/xpath/expr-40",
+        "fuzz/seed/xpath/expr-41",
+        "fuzz/seed/xpath/expr-42",
+        "fuzz/seed/xpath/expr-43",
+        "fuzz/seed/xpath/expr-44",
+        "fuzz/seed/xpath/expr-45",
+        "fuzz/seed/xpath/expr-46",
+        "fuzz/seed/xpath/expr-47",
+        "fuzz/seed/xpath/expr-48",
+        "fuzz/seed/xpath/expr-49",
+        "fuzz/seed/xpath/expr-50",
+        "fuzz/seed/xpath/expr-51",
+        "fuzz/seed/xpath/expr-52",
+        "fuzz/seed/xpath/expr-53",
+        "fuzz/seed/xpath/expr-54",
+        "fuzz/seed/xpath/expr-55",
+        "fuzz/seed/xpath/expr-56",
+        "fuzz/seed/xpath/expr-57",
+        "fuzz/seed/xpath/expr-58",
+        "fuzz/seed/xpath/expr-59",
+        "fuzz/seed/xpath/expr-60",
+        "fuzz/seed/xpath/expr-61",
+        "fuzz/seed/xpath/expr-62",
+        "fuzz/seed/xpath/expr-63",
+        "fuzz/seed/xpath/expr-64",
+        "fuzz/seed/xpath/expr-65",
+        "fuzz/seed/xpath/expr-66",
+        "fuzz/seed/xpath/expr-67",
+        "fuzz/seed/xpath/expr-68",
+        "fuzz/seed/xpath/expr-69",
+        "fuzz/seed/xpath/expr-70",
+        "fuzz/seed/xpath/expr-71",
+        "fuzz/seed/xpath/expr-72",
+        "fuzz/seed/xpath/expr-73",
+        "fuzz/seed/xpath/expr-74",
+        "fuzz/seed/xpath/expr-75",
+        "fuzz/seed/xpath/expr-76",
+        "fuzz/seed/xpath/expr-77",
+        "fuzz/seed/xpath/expr-78",
+        "fuzz/seed/xpath/expr-79",
+        "fuzz/seed/xpath/expr-80",
+        "fuzz/seed/xpath/expr-81",
+        "fuzz/seed/xpath/expr-82",
+        "fuzz/seed/xpath/expr-83",
+        "fuzz/seed/xpath/expr-84",
+        "fuzz/seed/xpath/expr-85",
+        "fuzz/seed/xpath/expr-86",
+        "fuzz/seed/xpath/expr-87",
+        "fuzz/seed/xpath/expr-88",
+        "fuzz/seed/xpath/expr-89",
+        "fuzz/seed/xpath/expr-90",
+        "fuzz/seed/xpath/expr-91",
+        "fuzz/seed/xpath/expr-92",
+        "fuzz/seed/xpath/expr-93",
+        "fuzz/seed/xpath/expr-94",
+        "fuzz/seed/xpath/expr-95",
+        "fuzz/seed/xpath/expr-96",
+        "fuzz/seed/xpath/expr-97",
+        "fuzz/seed/xpath/expr-98",
+        "fuzz/seed/xpath/expr-99",
         "fuzz/seed/xpath/expr-100",
         "fuzz/seed/xpath/expr-101",
         "fuzz/seed/xpath/expr-102",
@@ -775,7 +873,6 @@ genrule {
         "fuzz/seed/xpath/expr-107",
         "fuzz/seed/xpath/expr-108",
         "fuzz/seed/xpath/expr-109",
-        "fuzz/seed/xpath/expr-11",
         "fuzz/seed/xpath/expr-110",
         "fuzz/seed/xpath/expr-111",
         "fuzz/seed/xpath/expr-112",
@@ -786,7 +883,6 @@ genrule {
         "fuzz/seed/xpath/expr-117",
         "fuzz/seed/xpath/expr-118",
         "fuzz/seed/xpath/expr-119",
-        "fuzz/seed/xpath/expr-12",
         "fuzz/seed/xpath/expr-120",
         "fuzz/seed/xpath/expr-121",
         "fuzz/seed/xpath/expr-122",
@@ -797,7 +893,6 @@ genrule {
         "fuzz/seed/xpath/expr-127",
         "fuzz/seed/xpath/expr-128",
         "fuzz/seed/xpath/expr-129",
-        "fuzz/seed/xpath/expr-13",
         "fuzz/seed/xpath/expr-130",
         "fuzz/seed/xpath/expr-131",
         "fuzz/seed/xpath/expr-132",
@@ -808,7 +903,6 @@ genrule {
         "fuzz/seed/xpath/expr-137",
         "fuzz/seed/xpath/expr-138",
         "fuzz/seed/xpath/expr-139",
-        "fuzz/seed/xpath/expr-14",
         "fuzz/seed/xpath/expr-140",
         "fuzz/seed/xpath/expr-141",
         "fuzz/seed/xpath/expr-142",
@@ -819,7 +913,6 @@ genrule {
         "fuzz/seed/xpath/expr-147",
         "fuzz/seed/xpath/expr-148",
         "fuzz/seed/xpath/expr-149",
-        "fuzz/seed/xpath/expr-15",
         "fuzz/seed/xpath/expr-150",
         "fuzz/seed/xpath/expr-151",
         "fuzz/seed/xpath/expr-152",
@@ -830,7 +923,6 @@ genrule {
         "fuzz/seed/xpath/expr-157",
         "fuzz/seed/xpath/expr-158",
         "fuzz/seed/xpath/expr-159",
-        "fuzz/seed/xpath/expr-16",
         "fuzz/seed/xpath/expr-160",
         "fuzz/seed/xpath/expr-161",
         "fuzz/seed/xpath/expr-162",
@@ -841,7 +933,6 @@ genrule {
         "fuzz/seed/xpath/expr-167",
         "fuzz/seed/xpath/expr-168",
         "fuzz/seed/xpath/expr-169",
-        "fuzz/seed/xpath/expr-17",
         "fuzz/seed/xpath/expr-170",
         "fuzz/seed/xpath/expr-171",
         "fuzz/seed/xpath/expr-172",
@@ -852,7 +943,6 @@ genrule {
         "fuzz/seed/xpath/expr-177",
         "fuzz/seed/xpath/expr-178",
         "fuzz/seed/xpath/expr-179",
-        "fuzz/seed/xpath/expr-18",
         "fuzz/seed/xpath/expr-180",
         "fuzz/seed/xpath/expr-181",
         "fuzz/seed/xpath/expr-182",
@@ -863,7 +953,6 @@ genrule {
         "fuzz/seed/xpath/expr-187",
         "fuzz/seed/xpath/expr-188",
         "fuzz/seed/xpath/expr-189",
-        "fuzz/seed/xpath/expr-19",
         "fuzz/seed/xpath/expr-190",
         "fuzz/seed/xpath/expr-191",
         "fuzz/seed/xpath/expr-192",
@@ -874,8 +963,6 @@ genrule {
         "fuzz/seed/xpath/expr-197",
         "fuzz/seed/xpath/expr-198",
         "fuzz/seed/xpath/expr-199",
-        "fuzz/seed/xpath/expr-2",
-        "fuzz/seed/xpath/expr-20",
         "fuzz/seed/xpath/expr-200",
         "fuzz/seed/xpath/expr-201",
         "fuzz/seed/xpath/expr-202",
@@ -886,7 +973,6 @@ genrule {
         "fuzz/seed/xpath/expr-207",
         "fuzz/seed/xpath/expr-208",
         "fuzz/seed/xpath/expr-209",
-        "fuzz/seed/xpath/expr-21",
         "fuzz/seed/xpath/expr-210",
         "fuzz/seed/xpath/expr-211",
         "fuzz/seed/xpath/expr-212",
@@ -897,7 +983,6 @@ genrule {
         "fuzz/seed/xpath/expr-217",
         "fuzz/seed/xpath/expr-218",
         "fuzz/seed/xpath/expr-219",
-        "fuzz/seed/xpath/expr-22",
         "fuzz/seed/xpath/expr-220",
         "fuzz/seed/xpath/expr-221",
         "fuzz/seed/xpath/expr-222",
@@ -908,93 +993,9 @@ genrule {
         "fuzz/seed/xpath/expr-227",
         "fuzz/seed/xpath/expr-228",
         "fuzz/seed/xpath/expr-229",
-        "fuzz/seed/xpath/expr-23",
         "fuzz/seed/xpath/expr-230",
         "fuzz/seed/xpath/expr-231",
         "fuzz/seed/xpath/expr-232",
-        "fuzz/seed/xpath/expr-24",
-        "fuzz/seed/xpath/expr-25",
-        "fuzz/seed/xpath/expr-26",
-        "fuzz/seed/xpath/expr-27",
-        "fuzz/seed/xpath/expr-28",
-        "fuzz/seed/xpath/expr-29",
-        "fuzz/seed/xpath/expr-3",
-        "fuzz/seed/xpath/expr-30",
-        "fuzz/seed/xpath/expr-31",
-        "fuzz/seed/xpath/expr-32",
-        "fuzz/seed/xpath/expr-33",
-        "fuzz/seed/xpath/expr-34",
-        "fuzz/seed/xpath/expr-35",
-        "fuzz/seed/xpath/expr-36",
-        "fuzz/seed/xpath/expr-37",
-        "fuzz/seed/xpath/expr-38",
-        "fuzz/seed/xpath/expr-39",
-        "fuzz/seed/xpath/expr-4",
-        "fuzz/seed/xpath/expr-40",
-        "fuzz/seed/xpath/expr-41",
-        "fuzz/seed/xpath/expr-42",
-        "fuzz/seed/xpath/expr-43",
-        "fuzz/seed/xpath/expr-44",
-        "fuzz/seed/xpath/expr-45",
-        "fuzz/seed/xpath/expr-46",
-        "fuzz/seed/xpath/expr-47",
-        "fuzz/seed/xpath/expr-48",
-        "fuzz/seed/xpath/expr-49",
-        "fuzz/seed/xpath/expr-5",
-        "fuzz/seed/xpath/expr-50",
-        "fuzz/seed/xpath/expr-51",
-        "fuzz/seed/xpath/expr-52",
-        "fuzz/seed/xpath/expr-53",
-        "fuzz/seed/xpath/expr-54",
-        "fuzz/seed/xpath/expr-55",
-        "fuzz/seed/xpath/expr-56",
-        "fuzz/seed/xpath/expr-57",
-        "fuzz/seed/xpath/expr-58",
-        "fuzz/seed/xpath/expr-59",
-        "fuzz/seed/xpath/expr-6",
-        "fuzz/seed/xpath/expr-60",
-        "fuzz/seed/xpath/expr-61",
-        "fuzz/seed/xpath/expr-62",
-        "fuzz/seed/xpath/expr-63",
-        "fuzz/seed/xpath/expr-64",
-        "fuzz/seed/xpath/expr-65",
-        "fuzz/seed/xpath/expr-66",
-        "fuzz/seed/xpath/expr-67",
-        "fuzz/seed/xpath/expr-68",
-        "fuzz/seed/xpath/expr-69",
-        "fuzz/seed/xpath/expr-7",
-        "fuzz/seed/xpath/expr-70",
-        "fuzz/seed/xpath/expr-71",
-        "fuzz/seed/xpath/expr-72",
-        "fuzz/seed/xpath/expr-73",
-        "fuzz/seed/xpath/expr-74",
-        "fuzz/seed/xpath/expr-75",
-        "fuzz/seed/xpath/expr-76",
-        "fuzz/seed/xpath/expr-77",
-        "fuzz/seed/xpath/expr-78",
-        "fuzz/seed/xpath/expr-79",
-        "fuzz/seed/xpath/expr-8",
-        "fuzz/seed/xpath/expr-80",
-        "fuzz/seed/xpath/expr-81",
-        "fuzz/seed/xpath/expr-82",
-        "fuzz/seed/xpath/expr-83",
-        "fuzz/seed/xpath/expr-84",
-        "fuzz/seed/xpath/expr-85",
-        "fuzz/seed/xpath/expr-86",
-        "fuzz/seed/xpath/expr-87",
-        "fuzz/seed/xpath/expr-88",
-        "fuzz/seed/xpath/expr-89",
-        "fuzz/seed/xpath/expr-9",
-        "fuzz/seed/xpath/expr-90",
-        "fuzz/seed/xpath/expr-91",
-        "fuzz/seed/xpath/expr-92",
-        "fuzz/seed/xpath/expr-93",
-        "fuzz/seed/xpath/expr-94",
-        "fuzz/seed/xpath/expr-95",
-        "fuzz/seed/xpath/expr-96",
-        "fuzz/seed/xpath/expr-97",
-        "fuzz/seed/xpath/expr-98",
-        "fuzz/seed/xpath/expr-99",
         "fuzz/seed/xpath/id-1",
         "fuzz/seed/xpath/id-2",
         "fuzz/seed/xpath/id-3",
@@ -1021,6 +1022,14 @@ genrule {
         "fuzz/seed/xpath/ns-4",
         "fuzz/seed/xpath/ns-5",
         "fuzz/seed/xpath/simple-1",
+        "fuzz/seed/xpath/simple-2",
+        "fuzz/seed/xpath/simple-3",
+        "fuzz/seed/xpath/simple-4",
+        "fuzz/seed/xpath/simple-5",
+        "fuzz/seed/xpath/simple-6",
+        "fuzz/seed/xpath/simple-7",
+        "fuzz/seed/xpath/simple-8",
+        "fuzz/seed/xpath/simple-9",
         "fuzz/seed/xpath/simple-10",
         "fuzz/seed/xpath/simple-11",
         "fuzz/seed/xpath/simple-12",
@@ -1031,7 +1040,6 @@ genrule {
         "fuzz/seed/xpath/simple-17",
         "fuzz/seed/xpath/simple-18",
         "fuzz/seed/xpath/simple-19",
-        "fuzz/seed/xpath/simple-2",
         "fuzz/seed/xpath/simple-20",
         "fuzz/seed/xpath/simple-21",
         "fuzz/seed/xpath/simple-22",
@@ -1039,21 +1047,9 @@ genrule {
         "fuzz/seed/xpath/simple-24",
         "fuzz/seed/xpath/simple-25",
         "fuzz/seed/xpath/simple-26",
-        "fuzz/seed/xpath/simple-3",
-        "fuzz/seed/xpath/simple-4",
-        "fuzz/seed/xpath/simple-5",
-        "fuzz/seed/xpath/simple-6",
-        "fuzz/seed/xpath/simple-7",
-        "fuzz/seed/xpath/simple-8",
-        "fuzz/seed/xpath/simple-9",
         "fuzz/seed/xpath/str-1",
         "fuzz/seed/xpath/usr1-1",
         "fuzz/seed/xpath/vid-1",
-        "fuzz/seed/xpath/vid-10",
-        "fuzz/seed/xpath/vid-11",
-        "fuzz/seed/xpath/vid-12",
-        "fuzz/seed/xpath/vid-13",
-        "fuzz/seed/xpath/vid-14",
         "fuzz/seed/xpath/vid-2",
         "fuzz/seed/xpath/vid-3",
         "fuzz/seed/xpath/vid-4",
@@ -1062,6 +1058,11 @@ genrule {
         "fuzz/seed/xpath/vid-7",
         "fuzz/seed/xpath/vid-8",
         "fuzz/seed/xpath/vid-9",
+        "fuzz/seed/xpath/vid-10",
+        "fuzz/seed/xpath/vid-11",
+        "fuzz/seed/xpath/vid-12",
+        "fuzz/seed/xpath/vid-13",
+        "fuzz/seed/xpath/vid-14",
     ],
 }
 
diff --git a/CMakeLists.txt b/CMakeLists.txt
index e38e6b48..5aa5ea82 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -10,6 +10,8 @@ endif()
 
 project(libxml2 VERSION ${VERSION} LANGUAGES C)
 
+set(CMAKE_C_STANDARD 11)
+
 include(CheckCSourceCompiles)
 include(CheckFunctionExists)
 include(CheckIncludeFiles)
@@ -23,10 +25,8 @@ include(FindPkgConfig)
 include(GNUInstallDirs)
 
 option(BUILD_SHARED_LIBS "Build shared libraries" ON)
-set(LIBXML2_WITH_AUTOMATA ON)
 option(LIBXML2_WITH_CATALOG "Add the Catalog support" ON)
 option(LIBXML2_WITH_DEBUG "Add the debugging module" ON)
-set(LIBXML2_WITH_EXPR ON)
 option(LIBXML2_WITH_HTML "Add the HTML support" ON)
 option(LIBXML2_WITH_HTTP "Add the HTTP support" OFF)
 option(LIBXML2_WITH_ICONV "Add ICONV support" ON)
@@ -46,8 +46,8 @@ option(LIBXML2_WITH_SAX1 "Add the older SAX1 interface" ON)
 option(LIBXML2_WITH_TESTS "Build tests" ON)
 option(LIBXML2_WITH_THREADS "Add multithread support" ON)
 option(LIBXML2_WITH_TLS "Enable thread-local storage" OFF)
-set(LIBXML2_WITH_UNICODE ON)
 option(LIBXML2_WITH_VALID "Add the DTD validation support" ON)
+option(LIBXML2_WITH_XINCLUDE "Add the XInclude support" ON)
 option(LIBXML2_WITH_XPATH "Add the XPATH support" ON)
 option(LIBXML2_WITH_ZLIB "Use libz" OFF)
 
@@ -72,9 +72,6 @@ cmake_dependent_option(
 cmake_dependent_option(
     LIBXML2_WITH_WRITER "Add the xmlWriter saving interface" ON
     "LIBXML2_WITH_OUTPUT;LIBXML2_WITH_PUSH" OFF)
-cmake_dependent_option(
-    LIBXML2_WITH_XINCLUDE "Add the XInclude support" ON
-    "LIBXML2_WITH_XPATH" OFF)
 cmake_dependent_option(
     LIBXML2_WITH_XPTR "Add the XPointer support" ON
     "LIBXML2_WITH_XPATH" OFF)
@@ -88,7 +85,7 @@ if(LIBXML2_WITH_PYTHON)
         CACHE PATH "Python bindings install directory")
 endif()
 
-foreach(VARIABLE IN ITEMS WITH_AUTOMATA WITH_C14N WITH_CATALOG WITH_DEBUG WITH_EXPR WITH_HTML WITH_HTTP WITH_ICONV WITH_ICU WITH_ISO8859X WITH_LEGACY WITH_LZMA WITH_MODULES WITH_OUTPUT WITH_PATTERN WITH_PUSH WITH_READER WITH_REGEXPS WITH_SAX1 WITH_SCHEMAS WITH_SCHEMATRON WITH_THREADS WITH_THREAD_ALLOC WITH_UNICODE WITH_VALID WITH_WRITER WITH_XINCLUDE WITH_XPATH WITH_XPTR WITH_ZLIB)
+foreach(VARIABLE IN ITEMS WITH_C14N WITH_CATALOG WITH_DEBUG WITH_HTML WITH_HTTP WITH_ICONV WITH_ICU WITH_ISO8859X WITH_LEGACY WITH_LZMA WITH_MODULES WITH_OUTPUT WITH_PATTERN WITH_PUSH WITH_READER WITH_REGEXPS WITH_SAX1 WITH_SCHEMAS WITH_SCHEMATRON WITH_THREADS WITH_THREAD_ALLOC WITH_VALID WITH_WRITER WITH_XINCLUDE WITH_XPATH WITH_XPTR WITH_ZLIB)
     if(LIBXML2_${VARIABLE})
         set(${VARIABLE} 1)
     else()
@@ -106,19 +103,12 @@ math(EXPR LIBXML_VERSION_NUMBER "
 
 set(MODULE_EXTENSION "${CMAKE_SHARED_LIBRARY_SUFFIX}")
 
-set(PACKAGE "libxml2")
-set(PACKAGE_NAME "libxml2")
-set(PACKAGE_STRING "libxml2 ${VERSION}")
-set(PACKAGE_TARNAME "libxml2")
-set(PACKAGE_URL "https://gitlab.gnome.org/GNOME/libxml2")
-set(PACKAGE_VERSION ${VERSION})
-
 if(LIBXML2_WITH_ICONV)
     find_package(Iconv REQUIRED)
 endif()
 
 if(LIBXML2_WITH_ICU)
-    find_package(ICU REQUIRED COMPONENTS data i18n uc)
+    find_package(ICU REQUIRED COMPONENTS uc)
 endif()
 
 if(LIBXML2_WITH_LZMA)
@@ -234,48 +224,79 @@ set(
 set(
     LIBXML2_SRCS
     buf.c
-    c14n.c
-    catalog.c
     chvalid.c
-    debugXML.c
     dict.c
     encoding.c
     entities.c
     error.c
     globals.c
     hash.c
-    HTMLparser.c
-    HTMLtree.c
-    legacy.c
     list.c
-    nanohttp.c
     parser.c
     parserInternals.c
-    pattern.c
-    relaxng.c
     SAX2.c
-    schematron.c
     threads.c
     tree.c
     uri.c
     valid.c
-    xinclude.c
-    xlink.c
     xmlIO.c
     xmlmemory.c
-    xmlmodule.c
-    xmlreader.c
-    xmlregexp.c
-    xmlsave.c
-    xmlschemas.c
-    xmlschemastypes.c
     xmlstring.c
-    xmlunicode.c
-    xmlwriter.c
-    xpath.c
-    xpointer.c
-    xzlib.c
 )
+if(LIBXML2_WITH_C14N)
+    list(APPEND LIBXML2_SRCS c14n.c)
+endif()
+if(LIBXML2_WITH_CATALOG)
+    list(APPEND LIBXML2_SRCS catalog.c)
+endif()
+if(LIBXML2_WITH_DEBUG)
+    list(APPEND LIBXML2_SRCS debugXML.c)
+endif()
+if(LIBXML2_WITH_HTML)
+    list(APPEND LIBXML2_SRCS HTMLparser.c HTMLtree.c)
+endif()
+if(LIBXML2_WITH_HTTP)
+    list(APPEND LIBXML2_SRCS nanohttp.c)
+endif()
+if(LIBXML2_WITH_LEGACY)
+    list(APPEND LIBXML2_SRCS legacy.c)
+endif()
+if(LIBXML2_WITH_LZMA)
+    list(APPEND LIBXML2_SRCS xzlib.c)
+endif()
+if(LIBXML2_WITH_MODULES)
+    list(APPEND LIBXML2_SRCS xmlmodule.c)
+endif()
+if(LIBXML2_WITH_OUTPUT)
+    list(APPEND LIBXML2_SRCS xmlsave.c)
+endif()
+if(LIBXML2_WITH_PATTERN)
+    list(APPEND LIBXML2_SRCS pattern.c)
+endif()
+if(LIBXML2_WITH_READER)
+    list(APPEND LIBXML2_SRCS xmlreader.c)
+endif()
+if(LIBXML2_WITH_REGEXPS)
+    list(APPEND LIBXML2_SRCS xmlregexp.c xmlunicode.c)
+endif()
+if(LIBXML2_WITH_SCHEMAS)
+    list(APPEND LIBXML2_SRCS relaxng.c xmlschemas.c xmlschemastypes.c)
+endif()
+if(LIBXML2_WITH_SCHEMATRON)
+    list(APPEND LIBXML2_SRCS schematron.c)
+endif()
+if(LIBXML2_WITH_WRITER)
+    list(APPEND LIBXML2_SRCS xmlwriter.c)
+endif()
+if(LIBXML2_WITH_XINCLUDE)
+    list(APPEND LIBXML2_SRCS xinclude.c)
+endif()
+if(LIBXML2_WITH_XPATH)
+    list(APPEND LIBXML2_SRCS xpath.c)
+endif()
+if(LIBXML2_WITH_XPTR)
+    list(APPEND LIBXML2_SRCS xlink.c xpointer.c)
+endif()
 
 if(WIN32)
     list(APPEND LIBXML2_SRCS win32/libxml2.rc)
@@ -292,8 +313,6 @@ endif()
 add_library(LibXml2 ${LIBXML2_HDRS} ${LIBXML2_SRCS})
 add_library(LibXml2::LibXml2 ALIAS LibXml2)
 
-target_compile_definitions(LibXml2 PRIVATE SYSCONFDIR="${CMAKE_INSTALL_FULL_SYSCONFDIR}")
-
 target_include_directories(
     LibXml2
     PUBLIC
@@ -322,10 +341,12 @@ if(UNIX)
 endif()
 
 if(WIN32)
-    target_link_libraries(LibXml2 PRIVATE ws2_32)
-    set(WINSOCK_LIBS "-lws2_32")
     target_link_libraries(LibXml2 PRIVATE bcrypt)
     set(CRYPTO_LIBS "-lbcrypt")
+    if(LIBXML2_WITH_HTTP)
+        target_link_libraries(LibXml2 PRIVATE ws2_32)
+        set(WINSOCK_LIBS "-lws2_32")
+    endif()
 endif()
 
 if(LIBXML2_WITH_ICONV)
@@ -336,16 +357,12 @@ if(LIBXML2_WITH_ICONV)
 endif()
 
 if(LIBXML2_WITH_ICU)
-    target_link_libraries(LibXml2 PRIVATE ICU::data ICU::i18n ICU::uc)
-    if(WIN32)
-        set(ICU_LDFLAGS "-licudt -licuin -licuuc")
-    else()
-        set(ICU_LDFLAGS "-licudata -licui18n -licuuc")
-    endif()
+    target_link_libraries(LibXml2 PRIVATE ICU::uc)
+    set(ICU_LDFLAGS "-licuuc")
     list(APPEND XML_PRIVATE_LIBS "${ICU_LDFLAGS}")
-    pkg_check_modules(ICU_PC IMPORTED_TARGET icu-i18n)
+    pkg_check_modules(ICU_PC IMPORTED_TARGET icu-uc)
     if(ICU_PC_FOUND)
-        list(APPEND XML_PC_REQUIRES icu-i18n)
+        list(APPEND XML_PC_REQUIRES icu-uc)
     else()
         list(APPEND XML_PC_LIBS "${ICU_LDFLAGS}")
     endif()
@@ -427,6 +444,8 @@ if(MSVC)
     endif()
 endif()
 
+set(XML_SYSCONFDIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}")
+
 install(FILES ${LIBXML2_HDRS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libxml2/libxml COMPONENT development)
 
 install(
@@ -442,16 +461,14 @@ if(MSVC AND BUILD_SHARED_LIBS)
 endif()
 
 if(LIBXML2_WITH_PROGRAMS)
-    add_executable(xmllint xmllint.c shell.c)
-    add_executable(xmlcatalog xmlcatalog.c)
-    set(
-        PROGRAMS
-        xmlcatalog
-        xmllint
-    )
+    add_executable(xmllint xmllint.c shell.c lintmain.c)
+    set(PROGRAMS xmllint)
+    if(LIBXML2_WITH_CATALOG AND LIBXML2_WITH_OUTPUT)
+        add_executable(xmlcatalog xmlcatalog.c)
+        list(APPEND PROGRAMS xmlcatalog)
+    endif()
     foreach(PROGRAM ${PROGRAMS})
         add_executable(LibXml2::${PROGRAM} ALIAS ${PROGRAM})
-        target_compile_definitions(${PROGRAM} PRIVATE SYSCONFDIR="${CMAKE_INSTALL_FULL_SYSCONFDIR}")
         target_link_libraries(${PROGRAM} LibXml2)
         if(HAVE_LIBHISTORY)
             target_link_libraries(${PROGRAM} history)
@@ -480,7 +497,6 @@ if(LIBXML2_WITH_TESTS)
     )
     foreach(TEST ${TESTS})
         add_executable(${TEST} ${TEST}.c)
-        target_compile_definitions(${TEST} PRIVATE SYSCONFDIR="${CMAKE_INSTALL_FULL_SYSCONFDIR}")
         target_link_libraries(${TEST} LibXml2)
     endforeach()
     if(Threads_FOUND)
@@ -518,7 +534,7 @@ if(LIBXML2_WITH_PYTHON)
     file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/libxml2.py.in "${LIBXML2CLASS_PY}")
     configure_file(${CMAKE_CURRENT_BINARY_DIR}/libxml2.py.in libxml2.py COPYONLY)
     add_library(
-        LibXml2Mod
+        LibXml2Mod SHARED
         libxml2-py.c
         libxml2-py.h
         python/libxml.c
@@ -583,7 +599,7 @@ install(
 write_basic_package_version_file(
     ${CMAKE_CURRENT_BINARY_DIR}/libxml2-config-version.cmake
     VERSION ${PROJECT_VERSION}
-    COMPATIBILITY ExactVersion
+    COMPATIBILITY SameMajorVersion
 )
 
 install(
diff --git a/Copyright b/Copyright
index f76a86df..8c0b7c15 100644
--- a/Copyright
+++ b/Copyright
@@ -3,6 +3,7 @@ list.c, which are covered by a similar licence but with different Copyright
 notices) all the files are:
 
  Copyright (C) 1998-2012 Daniel Veillard.  All Rights Reserved.
+ Copyright (C) The Libxml2 Contributors.
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
diff --git a/HTMLparser.c b/HTMLparser.c
index 651eac9f..83d70de9 100644
--- a/HTMLparser.c
+++ b/HTMLparser.c
@@ -41,10 +41,12 @@
 #include "private/error.h"
 #include "private/html.h"
 #include "private/io.h"
+#include "private/memory.h"
 #include "private/parser.h"
 #include "private/tree.h"
 
 #define HTML_MAX_NAMELEN 1000
+#define HTML_MAX_ATTRS 100000000 /* 100 million */
 #define HTML_PARSER_BIG_BUFFER_SIZE 1000
 #define HTML_PARSER_BUFFER_SIZE 100
 
@@ -158,15 +160,20 @@ htmlnamePush(htmlParserCtxtPtr ctxt, const xmlChar * value)
     if ((ctxt->html < 10) && (xmlStrEqual(value, BAD_CAST "body")))
         ctxt->html = 10;
     if (ctxt->nameNr >= ctxt->nameMax) {
-        size_t newSize = ctxt->nameMax * 2;
         const xmlChar **tmp;
+        int newSize;
 
-        tmp = xmlRealloc((xmlChar **) ctxt->nameTab,
-                         newSize * sizeof(ctxt->nameTab[0]));
-        if (tmp == NULL) {
+        newSize = xmlGrowCapacity(ctxt->nameMax, sizeof(tmp[0]),
+                                  10, XML_MAX_ITEMS);
+        if (newSize < 0) {
             htmlErrMemory(ctxt);
             return (-1);
         }
+        tmp = xmlRealloc(ctxt->nameTab, newSize * sizeof(tmp[0]));
+        if (tmp == NULL) {
+            htmlErrMemory(ctxt);
+            return(-1);
+        }
         ctxt->nameTab = tmp;
         ctxt->nameMax = newSize;
     }
@@ -214,17 +221,22 @@ static int
 htmlNodeInfoPush(htmlParserCtxtPtr ctxt, htmlParserNodeInfo *value)
 {
     if (ctxt->nodeInfoNr >= ctxt->nodeInfoMax) {
-        if (ctxt->nodeInfoMax == 0)
-                ctxt->nodeInfoMax = 5;
-        ctxt->nodeInfoMax *= 2;
-        ctxt->nodeInfoTab = (htmlParserNodeInfo *)
-                         xmlRealloc((htmlParserNodeInfo *)ctxt->nodeInfoTab,
-                                    ctxt->nodeInfoMax *
-                                    sizeof(ctxt->nodeInfoTab[0]));
-        if (ctxt->nodeInfoTab == NULL) {
+        xmlParserNodeInfo *tmp;
+        int newSize;
+
+        newSize = xmlGrowCapacity(ctxt->nodeInfoMax, sizeof(tmp[0]),
+                                  5, XML_MAX_ITEMS);
+        if (newSize < 0) {
             htmlErrMemory(ctxt);
             return (0);
         }
+        tmp = xmlRealloc(ctxt->nodeInfoTab, newSize * sizeof(tmp[0]));
+        if (tmp == NULL) {
+            htmlErrMemory(ctxt);
+            return (0);
+        }
+        ctxt->nodeInfoTab = tmp;
+        ctxt->nodeInfoMax = newSize;
     }
     ctxt->nodeInfoTab[ctxt->nodeInfoNr] = *value;
     ctxt->nodeInfo = &ctxt->nodeInfoTab[ctxt->nodeInfoNr];
@@ -367,7 +379,8 @@ htmlMaskMatch(htmlAsciiMask mask, unsigned c) {
 }
 
 static int
-htmlValidateUtf8(xmlParserCtxtPtr ctxt, const xmlChar *str, size_t len) {
+htmlValidateUtf8(xmlParserCtxtPtr ctxt, const xmlChar *str, size_t len,
+                 int partial) {
     unsigned c = str[0];
     int size;
 
@@ -412,7 +425,8 @@ htmlValidateUtf8(xmlParserCtxtPtr ctxt, const xmlChar *str, size_t len) {
     return(size);
 
 incomplete:
-    return(0);
+    if (partial)
+        return(0);
 
 invalid:
     /* Only report the first error */
@@ -2412,7 +2426,7 @@ htmlParseHTMLName(htmlParserCtxtPtr ctxt, int attr) {
                 buf[nbchar++] = c;
             }
         } else {
-            size = htmlValidateUtf8(ctxt, in, avail);
+            size = htmlValidateUtf8(ctxt, in, avail, /* partial */ 0);
 
             if (size > 0) {
                 if (nbchar + size <= HTML_PARSER_BUFFER_SIZE) {
@@ -2787,7 +2801,11 @@ htmlParseData(htmlParserCtxtPtr ctxt, htmlAsciiMask mask,
                 if ((input->flags & XML_INPUT_HAS_ENCODING) == 0) {
                     xmlChar * guess;
 
+#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
+                    guess = NULL;
+#else
                     guess = htmlFindEncoding(ctxt);
+#endif
                     if (guess == NULL) {
                         xmlSwitchEncoding(ctxt, XML_CHAR_ENCODING_8859_1);
                     } else {
@@ -2799,7 +2817,7 @@ htmlParseData(htmlParserCtxtPtr ctxt, htmlAsciiMask mask,
                     goto restart;
                 }
 
-                size = htmlValidateUtf8(ctxt, in, avail);
+                size = htmlValidateUtf8(ctxt, in, avail, /* partial */ 0);
 
                 if (size <= 0) {
                     skip = 1;
@@ -2835,7 +2853,7 @@ next_chunk:
 
         if (extraSize > buffer_size - used) {
             size_t newSize = (used + extraSize) * 2;
-            xmlChar *tmp = (xmlChar *) xmlRealloc(buffer, newSize + 1);
+            xmlChar *tmp = xmlRealloc(buffer, newSize + 1);
 
             if (tmp == NULL) {
                 htmlErrMemory(ctxt);
@@ -2971,13 +2989,15 @@ htmlCharDataSAXCallback(htmlParserCtxtPtr ctxt, const xmlChar *buf,
 /**
  * htmlParseCharData:
  * @ctxt:  an HTML parser context
- * @terminate: true if the input buffer is complete
+ * @partial: true if the input buffer is incomplete
  *
  * Parse character data and references.
+ *
+ * Returns 1 if all data was parsed, 0 otherwise.
  */
 
 static int
-htmlParseCharData(htmlParserCtxtPtr ctxt) {
+htmlParseCharData(htmlParserCtxtPtr ctxt, int partial) {
     xmlParserInputPtr input = ctxt->input;
     xmlChar utf8Char[4];
     int complete = 0;
@@ -3030,6 +3050,11 @@ htmlParseCharData(htmlParserCtxtPtr ctxt) {
                 }
 
                 if (avail == 0) {
+                    if ((partial) && (ncr)) {
+                        in -= ncrSize;
+                        ncrSize = 0;
+                    }
+
                     done = 1;
                     break;
                 }
@@ -3092,6 +3117,7 @@ htmlParseCharData(htmlParserCtxtPtr ctxt) {
             case '<':
                 if (mode == 0) {
                     done = 1;
+                    complete = 1;
                     goto next_chunk;
                 }
                 if (mode == DATA_PLAINTEXT)
@@ -3148,8 +3174,7 @@ htmlParseCharData(htmlParserCtxtPtr ctxt) {
                     }
                 }
 
-                if ((mode != 0) && (PARSER_PROGRESSIVE(ctxt))) {
-                    in += 1;
+                if ((partial) && (j >= avail)) {
                     done = 1;
                     goto next_chunk;
                 }
@@ -3169,6 +3194,11 @@ htmlParseCharData(htmlParserCtxtPtr ctxt) {
                         mode = DATA_SCRIPT;
                 }
 
+                if ((partial) && (j >= avail)) {
+                    done = 1;
+                    goto next_chunk;
+                }
+
                 break;
 
             case '&':
@@ -3196,6 +3226,26 @@ htmlParseCharData(htmlParserCtxtPtr ctxt) {
                         }
                     }
                 } else {
+                    if (partial) {
+                        int terminated = 0;
+                        size_t i;
+
+                        /*
+                         * &CounterClockwiseContourIntegral; has 33 bytes.
+                         */
+                        for (i = 1; i < avail; i++) {
+                            if ((i >= 32) || !IS_ASCII_LETTER(in[i])) {
+                                terminated = 1;
+                                break;
+                            }
+                        }
+
+                        if (!terminated) {
+                            done = 1;
+                            goto next_chunk;
+                        }
+                    }
+
                     repl = htmlFindEntityPrefix(in + j,
                                                 avail - j,
                                                 /* isAttr */ 0,
@@ -3208,6 +3258,11 @@ htmlParseCharData(htmlParserCtxtPtr ctxt) {
                     skip = 0;
                 }
 
+                if ((partial) && (j >= avail)) {
+                    done = 1;
+                    goto next_chunk;
+                }
+
                 break;
 
             case '\0':
@@ -3222,6 +3277,11 @@ htmlParseCharData(htmlParserCtxtPtr ctxt) {
                 break;
 
             case '\r':
+                if (partial && avail < 2) {
+                    done = 1;
+                    goto next_chunk;
+                }
+
                 skip = 1;
                 if (in[1] != 0x0A) {
                     repl = BAD_CAST "\x0A";
@@ -3236,7 +3296,14 @@ htmlParseCharData(htmlParserCtxtPtr ctxt) {
                 if ((input->flags & XML_INPUT_HAS_ENCODING) == 0) {
                     xmlChar * guess;
 
+                    if (in > chunk)
+                        goto next_chunk;
+
+#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
+                    guess = NULL;
+#else
                     guess = htmlFindEncoding(ctxt);
+#endif
                     if (guess == NULL) {
                         xmlSwitchEncoding(ctxt, XML_CHAR_ENCODING_8859_1);
                     } else {
@@ -3248,7 +3315,12 @@ htmlParseCharData(htmlParserCtxtPtr ctxt) {
                     goto restart;
                 }
 
-                size = htmlValidateUtf8(ctxt, in, avail);
+                size = htmlValidateUtf8(ctxt, in, avail, partial);
+
+                if ((partial) && (size == 0)) {
+                    done = 1;
+                    goto next_chunk;
+                }
 
                 if (size <= 0) {
                     skip = 1;
@@ -3804,47 +3876,49 @@ htmlParseStartTag(htmlParserCtxtPtr ctxt) {
 	    if (nbatts + 4 > maxatts) {
 	        const xmlChar **tmp;
                 unsigned *utmp;
-                size_t newSize = maxatts ? maxatts * 2 : 22;
+                int newSize;
 
-	        tmp = xmlMalloc(newSize * sizeof(tmp[0]));
+                newSize = xmlGrowCapacity(maxatts,
+                                          sizeof(tmp[0]) * 2 + sizeof(utmp[0]),
+                                          11, HTML_MAX_ATTRS);
+		if (newSize < 0) {
+		    htmlErrMemory(ctxt);
+		    goto failed;
+		}
+#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
+                if (newSize < 2)
+                    newSize = 2;
+#endif
+	        tmp = xmlRealloc(atts, newSize * sizeof(tmp[0]) * 2);
 		if (tmp == NULL) {
 		    htmlErrMemory(ctxt);
-		    if (attvalue != NULL)
-			xmlFree(attvalue);
 		    goto failed;
 		}
+                atts = tmp;
+		ctxt->atts = tmp;
 
-	        utmp = xmlRealloc(ctxt->attallocs,
-                                  newSize / 2 * sizeof(utmp[0]));
+	        utmp = xmlRealloc(ctxt->attallocs, newSize * sizeof(utmp[0]));
 		if (utmp == NULL) {
 		    htmlErrMemory(ctxt);
-		    if (attvalue != NULL)
-			xmlFree(attvalue);
-                    xmlFree(tmp);
 		    goto failed;
 		}
-
-                if (maxatts > 0)
-                    memcpy(tmp, atts, maxatts * sizeof(tmp[0]));
-                xmlFree(atts);
-
-                atts = tmp;
-                maxatts = newSize;
-		ctxt->atts = atts;
                 ctxt->attallocs = utmp;
+
+                maxatts = newSize * 2;
 		ctxt->maxatts = maxatts;
 	    }
 
             ctxt->attallocs[nbatts/2] = hattname.hashValue;
 	    atts[nbatts++] = attname;
 	    atts[nbatts++] = attvalue;
-	}
-	else {
-	    if (attvalue != NULL)
-	        xmlFree(attvalue);
+
+            attvalue = NULL;
 	}
 
 failed:
+        if (attvalue != NULL)
+            xmlFree(attvalue);
+
 	SKIP_BLANKS;
     }
 
@@ -3907,11 +3981,25 @@ failed:
         atts[nbatts] = NULL;
         atts[nbatts + 1] = NULL;
 
+    /*
+     * Apple's new libiconv is so broken that you routinely run into
+     * issues when fuzz testing (by accident with an uninstrumented
+     * libiconv). Here's a harmless (?) example:
+     *
+     * printf '>'             | iconv -f shift_jis -t utf-8 | hexdump -C
+     * printf '\xfc\x00\x00'  | iconv -f shift_jis -t utf-8 | hexdump -C
+     * printf '>\xfc\x00\x00' | iconv -f shift_jis -t utf-8 | hexdump -C
+     *
+     * The last command fails to detect the illegal sequence.
+     */
+#if !defined(__APPLE__) || \
+    !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
         /*
          * Handle specific association to the META tag
          */
         if (meta)
             htmlCheckMeta(ctxt, atts);
+#endif
     }
 
     /*
@@ -3967,6 +4055,15 @@ htmlParseEndTag(htmlParserCtxtPtr ctxt)
 
     SKIP(2);
 
+    if (ctxt->input->cur >= ctxt->input->end) {
+        htmlCheckParagraph(ctxt);
+        if ((ctxt->sax != NULL) && (!ctxt->disableSAX) &&
+            (ctxt->sax->characters != NULL))
+            ctxt->sax->characters(ctxt->userData,
+                                  BAD_CAST "</", 2);
+        return;
+    }
+
     if (CUR == '>') {
         SKIP(1);
         return;
@@ -4085,11 +4182,12 @@ htmlParseEndTag(htmlParserCtxtPtr ctxt)
 
 static void
 htmlParseContent(htmlParserCtxtPtr ctxt) {
+    GROW;
+
     while ((PARSER_STOPPED(ctxt) == 0) &&
            (ctxt->input->cur < ctxt->input->end)) {
         int mode;
 
-        GROW;
         mode = ctxt->endCheckState;
 
         if ((mode == 0) && (CUR == '<')) {
@@ -4124,7 +4222,7 @@ htmlParseContent(htmlParserCtxtPtr ctxt) {
                 SKIP(1);
             }
         } else {
-            htmlParseCharData(ctxt);
+            htmlParseCharData(ctxt, /* partial */ 0);
         }
 
         SHRINK;
@@ -4253,6 +4351,13 @@ htmlParseElement(htmlParserCtxtPtr ctxt) {
     }
 }
 
+/**
+ * htmlCtxtParseContentInternal:
+ * @ctxt:  parser context
+ * @input:  parser input
+ *
+ * Returns a node list.
+ */
 xmlNodePtr
 htmlCtxtParseContentInternal(htmlParserCtxtPtr ctxt, xmlParserInputPtr input) {
     xmlNodePtr root;
@@ -4265,7 +4370,7 @@ htmlCtxtParseContentInternal(htmlParserCtxtPtr ctxt, xmlParserInputPtr input) {
         return(NULL);
     }
 
-    if (xmlPushInput(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeNode(root);
         return(NULL);
     }
@@ -4292,8 +4397,7 @@ htmlCtxtParseContentInternal(htmlParserCtxtPtr ctxt, xmlParserInputPtr input) {
     nodePop(ctxt);
     htmlnamePop(ctxt);
 
-    /* xmlPopInput would free the stream */
-    inputPop(ctxt);
+    xmlCtxtPopInput(ctxt);
 
     xmlFreeNode(root);
     return(list);
@@ -4325,8 +4429,14 @@ htmlParseDocument(htmlParserCtxtPtr ctxt) {
     xmlDetectEncoding(ctxt);
 
     /*
-     * This is wrong but matches long-standing behavior. In most cases,
-     * a document starting with an XML declaration will specify UTF-8.
+     * TODO: Implement HTML5 prescan algorithm
+     */
+
+    /*
+     * This is wrong but matches long-standing behavior. In most
+     * cases, a document starting with an XML declaration will
+     * specify UTF-8. The HTML5 prescan algorithm handles
+     * XML declarations in a better way.
      */
     if (((ctxt->input->flags & XML_INPUT_HAS_ENCODING) == 0) &&
         (xmlStrncmp(ctxt->input->cur, BAD_CAST "<?xm", 4) == 0))
@@ -4606,7 +4716,7 @@ htmlCreateMemoryParserCtxtInternal(const char *url,
         return(NULL);
     }
 
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         xmlFreeParserCtxt(ctxt);
         return(NULL);
@@ -4664,7 +4774,7 @@ htmlCreateDocParserCtxt(const xmlChar *str, const char *url,
 	return(NULL);
     }
 
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         xmlFreeParserCtxt(ctxt);
         return(NULL);
@@ -4680,7 +4790,7 @@ htmlCreateDocParserCtxt(const xmlChar *str, const char *url,
  *									*
  ************************************************************************/
 
-enum xmlLookupStates {
+typedef enum {
     LSTATE_TAG_NAME = 0,
     LSTATE_BEFORE_ATTR_NAME,
     LSTATE_ATTR_NAME,
@@ -4689,7 +4799,7 @@ enum xmlLookupStates {
     LSTATE_ATTR_VALUE_DQUOTED,
     LSTATE_ATTR_VALUE_SQUOTED,
     LSTATE_ATTR_VALUE_UNQUOTED
-};
+} xmlLookupStates;
 
 /**
  * htmlParseLookupGt:
@@ -4866,8 +4976,14 @@ htmlParseLookupCommentEnd(htmlParserCtxtPtr ctxt)
 	mark = htmlParseLookupString(ctxt, 2, "--", 2, 0);
 	if (mark < 0)
             break;
+        /*
+         * <!-->    is a complete comment, but
+         * <!--!>   is not
+         * <!---!>  is not
+         * <!----!> is
+         */
         if ((NXT(mark+2) == '>') ||
-	    ((NXT(mark+2) == '!') && (NXT(mark+3) == '>'))) {
+	    ((mark >= 4) && (NXT(mark+2) == '!') && (NXT(mark+3) == '>'))) {
             ctxt->checkIndex = 0;
 	    break;
 	}
@@ -4891,52 +5007,50 @@ htmlParseLookupCommentEnd(htmlParserCtxtPtr ctxt)
  *
  * Returns zero if no parsing was possible
  */
-static int
+static void
 htmlParseTryOrFinish(htmlParserCtxtPtr ctxt, int terminate) {
-    int ret = 0;
-    htmlParserInputPtr in;
-    ptrdiff_t avail = 0;
-    int cur;
-
-    htmlParserNodeInfo node_info;
-
     while (PARSER_STOPPED(ctxt) == 0) {
+        htmlParserInputPtr in;
+        size_t avail;
 
 	in = ctxt->input;
 	if (in == NULL) break;
 	avail = in->end - in->cur;
-	if ((avail == 0) && (terminate)) {
-	    htmlAutoCloseOnEnd(ctxt);
-	    if ((ctxt->nameNr == 0) && (ctxt->instate != XML_PARSER_EOF)) {
-		/*
-		 * SAX: end of the document processing.
-		 */
-		ctxt->instate = XML_PARSER_EOF;
-		if ((ctxt->sax) && (ctxt->sax->endDocument != NULL))
-		    ctxt->sax->endDocument(ctxt->userData);
-	    }
-	}
-        if (avail < 1)
-	    goto done;
-	cur = in->cur[0];
 
         switch (ctxt->instate) {
             case XML_PARSER_EOF:
 	        /*
 		 * Document parsing is done !
 		 */
-	        goto done;
+	        return;
+
             case XML_PARSER_START:
+                /*
+                 * Very first chars read from the document flow.
+                 */
+                if ((!terminate) && (avail < 4))
+                    return;
+
+                xmlDetectEncoding(ctxt);
+
+                /*
+                 * TODO: Implement HTML5 prescan algorithm
+                 */
+
                 /*
                  * This is wrong but matches long-standing behavior. In most
                  * cases, a document starting with an XML declaration will
-                 * specify UTF-8.
+                 * specify UTF-8. The HTML5 prescan algorithm handles
+                 * XML declarations in a better way.
                  */
                 if (((ctxt->input->flags & XML_INPUT_HAS_ENCODING) == 0) &&
                     (xmlStrncmp(ctxt->input->cur, BAD_CAST "<?xm", 4) == 0)) {
                     xmlSwitchEncoding(ctxt, XML_CHAR_ENCODING_UTF8);
                 }
 
+                /* fall through */
+
+            case XML_PARSER_XML_DECL:
                 if ((ctxt->sax) && (ctxt->sax->setDocumentLocator)) {
                     ctxt->sax->setDocumentLocator(ctxt->userData,
                             (xmlSAXLocator *) &xmlDefaultSAXLocator);
@@ -4945,99 +5059,25 @@ htmlParseTryOrFinish(htmlParserCtxtPtr ctxt, int terminate) {
 	            (!ctxt->disableSAX))
 		    ctxt->sax->startDocument(ctxt->userData);
 
-                /* Allow callback to modify state */
-                if (ctxt->instate == XML_PARSER_START)
+                /* Allow callback to modify state for tests */
+                if ((ctxt->instate == XML_PARSER_START) ||
+                    (ctxt->instate == XML_PARSER_XML_DECL))
                     ctxt->instate = XML_PARSER_MISC;
 		break;
-            case XML_PARSER_START_TAG: {
-	        const xmlChar *name;
-		int next;
-		const htmlElemDesc * info;
 
-		/*
-		 * not enough chars in buffer
-		 */
-		if (avail < 2)
-		    goto done;
-		cur = in->cur[0];
-		next = in->cur[1];
-	        if (cur != '<') {
-		    ctxt->instate = XML_PARSER_CONTENT;
-		    break;
-		}
-		if (next == '/') {
-		    ctxt->instate = XML_PARSER_END_TAG;
-		    ctxt->checkIndex = 0;
-		    break;
-		}
+            case XML_PARSER_START_TAG:
 		if ((!terminate) &&
 		    (htmlParseLookupGt(ctxt) < 0))
-		    goto done;
-
-                /* Capture start position */
-	        if (ctxt->record_info) {
-	             node_info.begin_pos = ctxt->input->consumed +
-	                                (CUR_PTR - ctxt->input->base);
-	             node_info.begin_line = ctxt->input->line;
-	        }
-
-
-		htmlParseStartTag(ctxt);
-		name = ctxt->name;
-		if (name == NULL)
-		    break;
-
-		/*
-		 * Check for an Empty Element labeled the XML/SGML way
-		 */
-		if ((CUR == '/') && (NXT(1) == '>')) {
-		    SKIP(2);
-                    htmlParserFinishElementParsing(ctxt);
-                    if ((ctxt->options & HTML_PARSE_HTML5) == 0) {
-                        if ((ctxt->sax != NULL) &&
-                            (ctxt->sax->endElement != NULL))
-                            ctxt->sax->endElement(ctxt->userData, name);
-                    }
-		    htmlnamePop(ctxt);
-		    ctxt->instate = XML_PARSER_CONTENT;
-		    break;
-		}
-
-		if (CUR != '>')
-                    break;
-		SKIP(1);
-
-		/*
-		 * Lookup the info for that element.
-		 */
-		info = htmlTagLookup(name);
-
-		/*
-		 * Check for an Empty Element from DTD definition
-		 */
-		if ((info != NULL) && (info->empty)) {
-                    htmlParserFinishElementParsing(ctxt);
-                    if ((ctxt->options & HTML_PARSE_HTML5) == 0) {
-                        if ((ctxt->sax != NULL) &&
-                            (ctxt->sax->endElement != NULL))
-                            ctxt->sax->endElement(ctxt->userData, name);
-                    }
-		    htmlnamePop(ctxt);
-		}
-
-		if (info != NULL)
-                    ctxt->endCheckState = info->dataMode;
+		    return;
 
-                if (ctxt->record_info)
-	            htmlNodeInfoPush(ctxt, &node_info);
+                htmlParseElementInternal(ctxt);
 
 		ctxt->instate = XML_PARSER_CONTENT;
                 break;
-	    }
+
             case XML_PARSER_MISC:
             case XML_PARSER_PROLOG:
-            case XML_PARSER_CONTENT:
-            case XML_PARSER_EPILOG: {
+            case XML_PARSER_CONTENT: {
                 int mode;
 
                 if ((ctxt->instate == XML_PARSER_MISC) ||
@@ -5047,34 +5087,22 @@ htmlParseTryOrFinish(htmlParserCtxtPtr ctxt, int terminate) {
                 }
 
 		if (avail < 1)
-		    goto done;
-		cur = in->cur[0];
+		    return;
+                /*
+                 * Note that endCheckState is also used by
+                 * xmlParseLookupGt.
+                 */
                 mode = ctxt->endCheckState;
 
                 if (mode != 0) {
-                    while ((PARSER_STOPPED(ctxt) == 0) &&
-                           (in->cur < in->end)) {
-                        size_t extra;
-
-                        extra = strlen((const char *) ctxt->name) + 2;
-
-                        if ((!terminate) &&
-                            (htmlParseLookupString(ctxt, 0, "<", 1,
-                                                   extra) < 0))
-                            goto done;
-                        ctxt->checkIndex = 0;
-
-                        if (htmlParseCharData(ctxt))
-                            break;
-                    }
-
-                    break;
-		} else if (cur == '<') {
+                    if (htmlParseCharData(ctxt, !terminate) == 0)
+                        return;
+		} else if (in->cur[0] == '<') {
                     int next;
 
                     if (avail < 2) {
                         if (!terminate)
-                            goto done;
+                            return;
                         next = ' ';
                     } else {
                         next = in->cur[1];
@@ -5082,18 +5110,19 @@ htmlParseTryOrFinish(htmlParserCtxtPtr ctxt, int terminate) {
 
                     if (next == '!') {
                         if ((!terminate) && (avail < 4))
-                            goto done;
+                            return;
                         if ((in->cur[2] == '-') && (in->cur[3] == '-')) {
                             if ((!terminate) &&
                                 (htmlParseLookupCommentEnd(ctxt) < 0))
-                                goto done;
+                                return;
                             SKIP(4);
                             htmlParseComment(ctxt, /* bogus */ 0);
+                            /* don't change state */
                             break;
                         }
 
                         if ((!terminate) && (avail < 9))
-                            goto done;
+                            return;
                         if ((UPP(2) == 'D') && (UPP(3) == 'O') &&
                             (UPP(4) == 'C') && (UPP(5) == 'T') &&
                             (UPP(6) == 'Y') && (UPP(7) == 'P') &&
@@ -5101,33 +5130,33 @@ htmlParseTryOrFinish(htmlParserCtxtPtr ctxt, int terminate) {
                             if ((!terminate) &&
                                 (htmlParseLookupString(ctxt, 9, ">", 1,
                                                        0) < 0))
-                                goto done;
+                                return;
                             htmlParseDocTypeDecl(ctxt);
                             if (ctxt->instate == XML_PARSER_MISC)
                                 ctxt->instate = XML_PARSER_PROLOG;
+                            else
+                                ctxt->instate = XML_PARSER_CONTENT;
                         } else {
+                            ctxt->instate = XML_PARSER_CONTENT;
                             if ((!terminate) &&
                                 (htmlParseLookupString(ctxt, 2, ">", 1, 0) < 0))
-                                goto done;
+                                return;
                             SKIP(2);
                             htmlParseComment(ctxt, /* bogus */ 1);
                         }
                     } else if (next == '?') {
                         if ((!terminate) &&
                             (htmlParseLookupString(ctxt, 2, ">", 1, 0) < 0))
-                            goto done;
+                            return;
                         SKIP(1);
                         htmlParseComment(ctxt, /* bogus */ 1);
+                        /* don't change state */
                     } else if (next == '/') {
                         ctxt->instate = XML_PARSER_END_TAG;
                         ctxt->checkIndex = 0;
-                        break;
                     } else if (IS_ASCII_LETTER(next)) {
-                        if ((!terminate) && (next == 0))
-                            goto done;
                         ctxt->instate = XML_PARSER_START_TAG;
                         ctxt->checkIndex = 0;
-                        break;
                     } else {
                         ctxt->instate = XML_PARSER_CONTENT;
                         htmlCheckParagraph(ctxt);
@@ -5138,41 +5167,32 @@ htmlParseTryOrFinish(htmlParserCtxtPtr ctxt, int terminate) {
                         SKIP(1);
                     }
                 } else {
+                    ctxt->instate = XML_PARSER_CONTENT;
                     /*
-                     * check that the text sequence is complete
-                     * before handing out the data to the parser
-                     * to avoid problems with erroneous end of
-                     * data detection.
+                     * We follow the logic of the XML push parser
                      */
-                    if ((!terminate) &&
-                        (htmlParseLookupString(ctxt, 0, "<", 1, 0) < 0))
-                        goto done;
+		    if (avail < HTML_PARSER_BIG_BUFFER_SIZE) {
+                        if ((!terminate) &&
+                            (htmlParseLookupString(ctxt, 0, "<", 1, 0) < 0))
+                            return;
+                    }
                     ctxt->checkIndex = 0;
-                    htmlParseCharData(ctxt);
+                    if (htmlParseCharData(ctxt, !terminate) == 0)
+                        return;
 		}
 
 		break;
 	    }
+
             case XML_PARSER_END_TAG:
-		if ((terminate) && (avail == 2)) {
-                    htmlCheckParagraph(ctxt);
-                    if ((ctxt->sax != NULL) && (!ctxt->disableSAX) &&
-                        (ctxt->sax->characters != NULL))
-                        ctxt->sax->characters(ctxt->userData,
-                                              BAD_CAST "</", 2);
-		    goto done;
-                }
 		if ((!terminate) &&
 		    (htmlParseLookupGt(ctxt) < 0))
-		    goto done;
+		    return;
 		htmlParseEndTag(ctxt);
-		if (ctxt->nameNr == 0) {
-		    ctxt->instate = XML_PARSER_EPILOG;
-		} else {
-		    ctxt->instate = XML_PARSER_CONTENT;
-		}
+		ctxt->instate = XML_PARSER_CONTENT;
 		ctxt->checkIndex = 0;
 	        break;
+
 	    default:
 		htmlParseErr(ctxt, XML_ERR_INTERNAL_ERROR,
 			     "HPP: internal error\n", NULL, NULL);
@@ -5180,33 +5200,6 @@ htmlParseTryOrFinish(htmlParserCtxtPtr ctxt, int terminate) {
 		break;
 	}
     }
-done:
-    if ((avail == 0) && (terminate)) {
-	htmlAutoCloseOnEnd(ctxt);
-	if ((ctxt->nameNr == 0) && (ctxt->instate != XML_PARSER_EOF)) {
-	    /*
-	     * SAX: end of the document processing.
-	     */
-	    ctxt->instate = XML_PARSER_EOF;
-	    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL))
-		ctxt->sax->endDocument(ctxt->userData);
-	}
-    }
-    if ((!(ctxt->options & HTML_PARSE_NODEFDTD)) && (ctxt->myDoc != NULL) &&
-	((terminate) || (ctxt->instate == XML_PARSER_EOF) ||
-	 (ctxt->instate == XML_PARSER_EPILOG))) {
-	xmlDtdPtr dtd;
-	dtd = xmlGetIntSubset(ctxt->myDoc);
-	if (dtd == NULL) {
-	    ctxt->myDoc->intSubset =
-		xmlCreateIntSubset(ctxt->myDoc, BAD_CAST "html",
-		    BAD_CAST "-//W3C//DTD HTML 4.0 Transitional//EN",
-		    BAD_CAST "http://www.w3.org/TR/REC-html40/loose.dtd");
-            if (ctxt->myDoc->intSubset == NULL)
-                htmlErrMemory(ctxt);
-        }
-    }
-    return(ret);
 }
 
 /**
@@ -5251,14 +5244,32 @@ htmlParseChunk(htmlParserCtxtPtr ctxt, const char *chunk, int size,
 	    return (ctxt->errNo);
 	}
     }
+
     htmlParseTryOrFinish(ctxt, terminate);
-    if (terminate) {
-	if (ctxt->instate != XML_PARSER_EOF) {
-	    if ((ctxt->sax) && (ctxt->sax->endDocument != NULL))
-		ctxt->sax->endDocument(ctxt->userData);
-	}
+
+    if ((terminate) && (ctxt->instate != XML_PARSER_EOF)) {
+        htmlAutoCloseOnEnd(ctxt);
+
+        if ((ctxt->sax) && (ctxt->sax->endDocument != NULL))
+            ctxt->sax->endDocument(ctxt->userData);
+
+        if ((!(ctxt->options & HTML_PARSE_NODEFDTD)) &&
+            (ctxt->myDoc != NULL)) {
+            xmlDtdPtr dtd;
+            dtd = xmlGetIntSubset(ctxt->myDoc);
+            if (dtd == NULL) {
+                ctxt->myDoc->intSubset =
+                    xmlCreateIntSubset(ctxt->myDoc, BAD_CAST "html",
+                        BAD_CAST "-//W3C//DTD HTML 4.0 Transitional//EN",
+                        BAD_CAST "http://www.w3.org/TR/REC-html40/loose.dtd");
+                if (ctxt->myDoc->intSubset == NULL)
+                    htmlErrMemory(ctxt);
+            }
+        }
+
 	ctxt->instate = XML_PARSER_EOF;
     }
+
     return((xmlParserErrors) ctxt->errNo);
 }
 
@@ -5301,7 +5312,7 @@ htmlCreatePushParserCtxt(htmlSAXHandlerPtr sax, void *user_data,
 	return(NULL);
     }
 
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         xmlFreeParserCtxt(ctxt);
         return(NULL);
@@ -5411,7 +5422,7 @@ htmlCreateFileParserCtxt(const char *filename, const char *encoding)
 	xmlFreeParserCtxt(ctxt);
 	return(NULL);
     }
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         xmlFreeParserCtxt(ctxt);
         return(NULL);
@@ -5596,7 +5607,7 @@ htmlCtxtReset(htmlParserCtxtPtr ctxt)
 
     dict = ctxt->dict;
 
-    while ((input = inputPop(ctxt)) != NULL) { /* Non consuming */
+    while ((input = xmlCtxtPopInput(ctxt)) != NULL) { /* Non consuming */
         xmlFreeInputStream(input);
     }
     ctxt->inputNr = 0;
@@ -5887,14 +5898,17 @@ htmlCtxtParseDocument(htmlParserCtxtPtr ctxt, xmlParserInputPtr input)
 {
     htmlDocPtr ret;
 
-    if ((ctxt == NULL) || (input == NULL))
+    if ((ctxt == NULL) || (input == NULL)) {
+        xmlFatalErr(ctxt, XML_ERR_ARGUMENT, NULL);
+        xmlFreeInputStream(input);
         return(NULL);
+    }
 
     /* assert(ctxt->inputNr == 0); */
     while (ctxt->inputNr > 0)
-        xmlFreeInputStream(inputPop(ctxt));
+        xmlFreeInputStream(xmlCtxtPopInput(ctxt));
 
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         return(NULL);
     }
@@ -5912,7 +5926,7 @@ htmlCtxtParseDocument(htmlParserCtxtPtr ctxt, xmlParserInputPtr input)
 
     /* assert(ctxt->inputNr == 1); */
     while (ctxt->inputNr > 0)
-        xmlFreeInputStream(inputPop(ctxt));
+        xmlFreeInputStream(xmlCtxtPopInput(ctxt));
 
     return(ret);
 }
@@ -5937,7 +5951,7 @@ htmlReadDoc(const xmlChar *str, const char *url, const char *encoding,
 {
     htmlParserCtxtPtr ctxt;
     xmlParserInputPtr input;
-    htmlDocPtr doc;
+    htmlDocPtr doc = NULL;
 
     ctxt = htmlNewParserCtxt();
     if (ctxt == NULL)
@@ -5948,7 +5962,8 @@ htmlReadDoc(const xmlChar *str, const char *url, const char *encoding,
     input = xmlCtxtNewInputFromString(ctxt, url, (const char *) str, encoding,
                                       XML_INPUT_BUF_STATIC);
 
-    doc = htmlCtxtParseDocument(ctxt, input);
+    if (input != NULL)
+        doc = htmlCtxtParseDocument(ctxt, input);
 
     htmlFreeParserCtxt(ctxt);
     return(doc);
@@ -5972,7 +5987,7 @@ htmlReadFile(const char *filename, const char *encoding, int options)
 {
     htmlParserCtxtPtr ctxt;
     xmlParserInputPtr input;
-    htmlDocPtr doc;
+    htmlDocPtr doc = NULL;
 
     ctxt = htmlNewParserCtxt();
     if (ctxt == NULL)
@@ -5982,7 +5997,8 @@ htmlReadFile(const char *filename, const char *encoding, int options)
 
     input = xmlCtxtNewInputFromUrl(ctxt, filename, NULL, encoding, 0);
 
-    doc = htmlCtxtParseDocument(ctxt, input);
+    if (input != NULL)
+        doc = htmlCtxtParseDocument(ctxt, input);
 
     htmlFreeParserCtxt(ctxt);
     return(doc);
@@ -6009,7 +6025,7 @@ htmlReadMemory(const char *buffer, int size, const char *url,
 {
     htmlParserCtxtPtr ctxt;
     xmlParserInputPtr input;
-    htmlDocPtr doc;
+    htmlDocPtr doc = NULL;
 
     if (size < 0)
 	return(NULL);
@@ -6023,7 +6039,8 @@ htmlReadMemory(const char *buffer, int size, const char *url,
     input = xmlCtxtNewInputFromMemory(ctxt, url, buffer, size, encoding,
                                       XML_INPUT_BUF_STATIC);
 
-    doc = htmlCtxtParseDocument(ctxt, input);
+    if (input != NULL)
+        doc = htmlCtxtParseDocument(ctxt, input);
 
     htmlFreeParserCtxt(ctxt);
     return(doc);
@@ -6051,7 +6068,7 @@ htmlReadFd(int fd, const char *url, const char *encoding, int options)
 {
     htmlParserCtxtPtr ctxt;
     xmlParserInputPtr input;
-    htmlDocPtr doc;
+    htmlDocPtr doc = NULL;
 
     ctxt = htmlNewParserCtxt();
     if (ctxt == NULL)
@@ -6061,7 +6078,8 @@ htmlReadFd(int fd, const char *url, const char *encoding, int options)
 
     input = xmlCtxtNewInputFromFd(ctxt, url, fd, encoding, 0);
 
-    doc = htmlCtxtParseDocument(ctxt, input);
+    if (input != NULL)
+        doc = htmlCtxtParseDocument(ctxt, input);
 
     htmlFreeParserCtxt(ctxt);
     return(doc);
@@ -6089,7 +6107,7 @@ htmlReadIO(xmlInputReadCallback ioread, xmlInputCloseCallback ioclose,
 {
     htmlParserCtxtPtr ctxt;
     xmlParserInputPtr input;
-    htmlDocPtr doc;
+    htmlDocPtr doc = NULL;
 
     ctxt = htmlNewParserCtxt();
     if (ctxt == NULL)
@@ -6100,7 +6118,8 @@ htmlReadIO(xmlInputReadCallback ioread, xmlInputCloseCallback ioclose,
     input = xmlCtxtNewInputFromIO(ctxt, url, ioread, ioclose, ioctx,
                                   encoding, 0);
 
-    doc = htmlCtxtParseDocument(ctxt, input);
+    if (input != NULL)
+        doc = htmlCtxtParseDocument(ctxt, input);
 
     htmlFreeParserCtxt(ctxt);
     return(doc);
@@ -6134,6 +6153,8 @@ htmlCtxtReadDoc(htmlParserCtxtPtr ctxt, const xmlChar *str,
 
     input = xmlCtxtNewInputFromString(ctxt, URL, (const char *) str,
                                       encoding, 0);
+    if (input == NULL)
+        return(NULL);
 
     return(htmlCtxtParseDocument(ctxt, input));
 }
@@ -6165,6 +6186,8 @@ htmlCtxtReadFile(htmlParserCtxtPtr ctxt, const char *filename,
     htmlCtxtUseOptions(ctxt, options);
 
     input = xmlCtxtNewInputFromUrl(ctxt, filename, NULL, encoding, 0);
+    if (input == NULL)
+        return(NULL);
 
     return(htmlCtxtParseDocument(ctxt, input));
 }
@@ -6199,6 +6222,8 @@ htmlCtxtReadMemory(htmlParserCtxtPtr ctxt, const char *buffer, int size,
 
     input = xmlCtxtNewInputFromMemory(ctxt, URL, buffer, size, encoding,
                                       XML_INPUT_BUF_STATIC);
+    if (input == NULL)
+        return(NULL);
 
     return(htmlCtxtParseDocument(ctxt, input));
 }
@@ -6233,6 +6258,8 @@ htmlCtxtReadFd(htmlParserCtxtPtr ctxt, int fd,
     htmlCtxtUseOptions(ctxt, options);
 
     input = xmlCtxtNewInputFromFd(ctxt, URL, fd, encoding, 0);
+    if (input == NULL)
+        return(NULL);
 
     return(htmlCtxtParseDocument(ctxt, input));
 }
@@ -6269,6 +6296,8 @@ htmlCtxtReadIO(htmlParserCtxtPtr ctxt, xmlInputReadCallback ioread,
 
     input = xmlCtxtNewInputFromIO(ctxt, URL, ioread, ioclose, ioctx,
                                   encoding, 0);
+    if (input == NULL)
+        return(NULL);
 
     return(htmlCtxtParseDocument(ctxt, input));
 }
diff --git a/HTMLtree.c b/HTMLtree.c
index 06741c21..3ebacd4d 100644
--- a/HTMLtree.c
+++ b/HTMLtree.c
@@ -26,6 +26,7 @@
 #include "private/buf.h"
 #include "private/error.h"
 #include "private/io.h"
+#include "private/parser.h"
 #include "private/save.h"
 
 /************************************************************************
diff --git a/MAINTAINERS.md b/MAINTAINERS.md
index b2806755..4772c4e0 100644
--- a/MAINTAINERS.md
+++ b/MAINTAINERS.md
@@ -106,9 +106,9 @@ The following changes are allowed (after careful consideration):
 ## Updating the CI Docker image
 
 Note that the CI image is used for libxslt as well. First create a
-GitLab access token with `read_registry` and `write_registry`
-permissions. Then run the following commands with the Dockerfile in the
-.gitlab-ci directory:
+GitLab access token with maintainer role and `read_registry` and
+`write_registry` permissions. Then run the following commands with the
+Dockerfile in the .gitlab-ci directory:
 
     docker login -u <username> -p <access_token> \
         registry.gitlab.gnome.org
diff --git a/METADATA b/METADATA
index 501ec7d7..9799dab1 100644
--- a/METADATA
+++ b/METADATA
@@ -15,14 +15,14 @@ third_party {
     tag: "NVD-CPE2.3:cpe:/a:xmlsoft:libxml2:2.9.2:-"
   }
   last_upgrade_date {
-    year: 2024
-    month: 10
-    day: 22
+    year: 2025
+    month: 2
+    day: 3
   }
   homepage: "http://www.xmlsoft.org/"
   identifier {
     type: "Git"
     value: "https://github.com/GNOME/libxml2/"
-    version: "b7c0f9d2dd0641822eed7a2316109aeb19bf650b"
+    version: "62d4697db6268b71e36ef8fda708953cadf4082a"
   }
 }
diff --git a/Makefile.am b/Makefile.am
index 5caba33e..b30f50dd 100644
--- a/Makefile.am
+++ b/Makefile.am
@@ -26,7 +26,7 @@ check_PROGRAMS = \
 	testparser \
 	testrecurse
 
-bin_PROGRAMS = xmllint xmlcatalog
+bin_PROGRAMS = xmllint
 
 bin_SCRIPTS = xml2-config
 
@@ -48,6 +48,15 @@ if WITH_C14N_SOURCES
 libxml2_la_SOURCES += c14n.c
 endif
 if WITH_CATALOG_SOURCES
+if WITH_OUTPUT_SOURCES
+bin_PROGRAMS += xmlcatalog
+
+xmlcatalog_SOURCES = xmlcatalog.c
+xmlcatalog_CFLAGS = $(AM_CFLAGS) $(RDL_CFLAGS) $(ICONV_CFLAGS)
+xmlcatalog_DEPENDENCIES = $(DEPS)
+xmlcatalog_LDADD = $(RDL_LIBS) $(LDADDS)
+endif
+
 libxml2_la_SOURCES += catalog.c
 endif
 if WITH_DEBUG_SOURCES
@@ -82,9 +91,6 @@ libxml2_la_SOURCES += xmlregexp.c xmlunicode.c
 endif
 if WITH_SCHEMAS_SOURCES
 libxml2_la_SOURCES += relaxng.c xmlschemas.c xmlschemastypes.c
-if !WITH_XPATH_SOURCES
-libxml2_la_SOURCES += xpath.c
-endif
 endif
 if WITH_SCHEMATRON_SOURCES
 libxml2_la_SOURCES += schematron.c
@@ -133,21 +139,16 @@ runsuite_SOURCES=runsuite.c
 runsuite_DEPENDENCIES = $(DEPS)
 runsuite_LDADD= $(LDADDS)
 
-xmllint_SOURCES = xmllint.c shell.c
+xmllint_SOURCES = xmllint.c shell.c lintmain.c
 xmllint_CFLAGS = $(AM_CFLAGS) $(RDL_CFLAGS) $(ICONV_CFLAGS)
 xmllint_DEPENDENCIES = $(DEPS)
 xmllint_LDADD=  $(RDL_LIBS) $(LDADDS)
 
-xmlcatalog_SOURCES=xmlcatalog.c
-xmlcatalog_CFLAGS = $(AM_CFLAGS) $(RDL_CFLAGS) $(ICONV_CFLAGS)
-xmlcatalog_DEPENDENCIES = $(DEPS)
-xmlcatalog_LDADD = $(RDL_LIBS) $(LDADDS)
-
 testModule_SOURCES=testModule.c
 testModule_DEPENDENCIES = $(DEPS)
 testModule_LDADD= $(LDADDS)
 
-noinst_LTLIBRARIES = testdso.la
+check_LTLIBRARIES = testdso.la
 testdso_la_SOURCES = testdso.c
 testdso_la_LDFLAGS = $(AM_LDFLAGS) \
 		     -module -no-undefined -avoid-version -rpath $(libdir)
@@ -208,7 +209,8 @@ CLEANFILES = runsuite.log runxmlconf.log test.out *.gcda *.gcno *.res
 DISTCLEANFILES = COPYING missing.lst
 
 EXTRA_DIST = Copyright libxml2-config.cmake.in autogen.sh \
-	     libxml.h iso8859x.inc \
+	     libxml.h \
+	     html5ent.inc iso8859x.inc \
 	     tools/gentest.py \
 	     tools/genChRanges.py tools/genEscape.py tools/genUnicode.py \
 	     libxml2.syms timsort.h \
diff --git a/NEWS b/NEWS
index ab74d135..14c297d4 100644
--- a/NEWS
+++ b/NEWS
@@ -15,13 +15,17 @@ existing parser context was added.
 
 The xmlSave API now has additional options to replace global settings.
 
-Parser options XML_PARSE_NO_UNZIP, XML_PARSE_NO_SYS_CATALOG and
-XML_PARSE_NO_CATALOG_PI were added.
+Parser options XML_PARSE_UNZIP, XML_PARSE_NO_SYS_CATALOG and
+XML_PARSE_CATALOG_PI were added.
 
 The serialization API will now take user-provided or default encodings
 into account when serializing attribute values, matching the
 serialization of text and avoiding unnecessary escaping.
 
+An API function to install a custom character encoding converter is
+now available. This makes it possible to use ICU for encoding conversion
+even if libxml2 was complied without ICU support, see example/icu.c.
+
 Access to many public struct members is now deprecated. Several accessor
 functions were added.
 
diff --git a/README.md b/README.md
index 8eec01f0..34596840 100644
--- a/README.md
+++ b/README.md
@@ -10,7 +10,9 @@ The git repository is hosted on GNOME's GitLab server:
 <https://gitlab.gnome.org/GNOME/libxml2>
 
 Bugs should be reported at
-<https://gitlab.gnome.org/GNOME/libxml2/-/issues>
+<https://gitlab.gnome.org/GNOME/libxml2/-/issues>.
+Please report *security issues* to our bug tracker as well. Make sure to
+mark the issue as *confidential*.
 
 Documentation is available at
 <https://gitlab.gnome.org/GNOME/libxml2/-/wikis>
@@ -66,7 +68,6 @@ The following options disable or enable code modules and relevant symbols:
     --with-schematron       Schematron support (on)
     --with-threads          multithreading support (on)
     --with-thread-alloc     per-thread malloc hooks (off)
-    --with-tree             DOM like tree manipulation APIs (on)
     --with-valid            DTD validation support (on)
     --with-writer           xmlWriter serialization interface (on)
     --with-xinclude         XInclude 1.0 support (on)
@@ -112,15 +113,17 @@ Common CMake options include:
     -D CMAKE_BUILD_TYPE=Release         # specify build type
     -D CMAKE_INSTALL_PREFIX=/usr/local  # specify the install path
     -D LIBXML2_WITH_ICONV=OFF           # disable iconv
-    -D LIBXML2_WITH_LZMA=OFF            # disable liblzma
     -D LIBXML2_WITH_PYTHON=OFF          # disable Python
-    -D LIBXML2_WITH_ZLIB=OFF            # disable libz
+    -D LIBXML2_WITH_ZLIB=ON             # enable zlib
 
 You can also open the libxml source directory with its CMakeLists.txt
 directly in various IDEs such as CLion, QtCreator, or Visual Studio.
 
 ### Meson
 
+Still somewhat experimental, see
+[issue 743](https://gitlab.gnome.org/GNOME/libxml2/-/issues/743).
+
 Libxml can also be built with meson. Without option, simply call
 
     meson setup builddir
@@ -146,24 +149,24 @@ To launch tests:
 
 ## Dependencies
 
-Libxml does not require any other libraries. A platform with somewhat
-recent POSIX support should be sufficient (please report any violation
-to this rule you may find).
+libxml2 supports POSIX and Windows operating systems.
 
 The iconv function is required for conversion of character encodings.
 This function is part of POSIX.1-2001. If your platform doesn't provide
 iconv, you need an external libiconv library, for example
-[GNU libiconv](https://www.gnu.org/software/libiconv/). Alternatively,
-you can use [ICU](https://icu.unicode.org/).
+[GNU libiconv](https://www.gnu.org/software/libiconv/). Using
+[ICU](https://icu.unicode.org/) is also supported but discouraged.
 
 If enabled, libxml uses [libz](https://zlib.net/) or
 [liblzma](https://tukaani.org/xz/) to support reading compressed files.
 Use of this feature is discouraged.
 
+The xmllint executable uses libreadline and libhistory if enabled.
+
 ## Contributing
 
-The current version of the code can be found in GNOME's GitLab at 
-at <https://gitlab.gnome.org/GNOME/libxml2>. The best way to get involved
+The current version of the code can be found in GNOME's GitLab at
+<https://gitlab.gnome.org/GNOME/libxml2>. The best way to get involved
 is by creating issues and merge requests on GitLab.
 
 All code must conform to C89 and pass the GitLab CI tests. Add regression
diff --git a/SAX2.c b/SAX2.c
index 0d387da4..702041f9 100644
--- a/SAX2.c
+++ b/SAX2.c
@@ -325,7 +325,7 @@ xmlSAX2ExternalSubset(void *ctx, const xmlChar *name,
 	ctxt->inputNr = 0;
 	ctxt->inputMax = 5;
 	ctxt->input = NULL;
-	if (xmlPushInput(ctxt, input) < 0)
+	if (xmlCtxtPushInput(ctxt, input) < 0)
             goto error;
 
 	if (input->filename == NULL)
@@ -346,7 +346,7 @@ xmlSAX2ExternalSubset(void *ctx, const xmlChar *name,
 	 */
 
 	while (ctxt->inputNr > 1)
-	    xmlPopInput(ctxt);
+	    xmlFreeInputStream(xmlCtxtPopInput(ctxt));
 
         consumed = ctxt->input->consumed;
         buffered = ctxt->input->cur - ctxt->input->base;
@@ -396,42 +396,48 @@ xmlSAX2ResolveEntity(void *ctx, const xmlChar *publicId,
 {
     xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
     xmlParserInputPtr ret = NULL;
-    xmlChar *URI;
-    const xmlChar *base = NULL;
-    int res;
+    xmlChar *URI = NULL;
 
     if (ctx == NULL) return(NULL);
-    if (ctxt->input != NULL)
-	base = BAD_CAST ctxt->input->filename;
 
-    /*
-     * We don't really need the 'directory' struct member, but some
-     * users set it manually to a base URI for memory streams.
-     */
-    if (base == NULL)
-        base = BAD_CAST ctxt->directory;
+    if (systemId != NULL) {
+        const xmlChar *base = NULL;
+        int res;
 
-    if ((xmlStrlen(systemId) > XML_MAX_URI_LENGTH) ||
-        (xmlStrlen(base) > XML_MAX_URI_LENGTH)) {
-        xmlFatalErr(ctxt, XML_ERR_RESOURCE_LIMIT, "URI too long");
-        return(NULL);
-    }
-    res = xmlBuildURISafe(systemId, base, &URI);
-    if (URI == NULL) {
-        if (res < 0)
-            xmlSAX2ErrMemory(ctxt);
-        else
-            xmlWarnMsg(ctxt, XML_ERR_INVALID_URI,
-                       "Can't resolve URI: %s\n", systemId);
-        return(NULL);
-    }
-    if (xmlStrlen(URI) > XML_MAX_URI_LENGTH) {
-        xmlFatalErr(ctxt, XML_ERR_RESOURCE_LIMIT, "URI too long");
-    } else {
-        ret = xmlLoadResource(ctxt, (const char *) URI,
-                              (const char *) publicId, XML_RESOURCE_DTD);
+        if (ctxt->input != NULL)
+            base = BAD_CAST ctxt->input->filename;
+
+        /*
+         * We don't really need the 'directory' struct member, but some
+         * users set it manually to a base URI for memory streams.
+         */
+        if (base == NULL)
+            base = BAD_CAST ctxt->directory;
+
+        if ((xmlStrlen(systemId) > XML_MAX_URI_LENGTH) ||
+            (xmlStrlen(base) > XML_MAX_URI_LENGTH)) {
+            xmlFatalErr(ctxt, XML_ERR_RESOURCE_LIMIT, "URI too long");
+            return(NULL);
+        }
+        res = xmlBuildURISafe(systemId, base, &URI);
+        if (URI == NULL) {
+            if (res < 0)
+                xmlSAX2ErrMemory(ctxt);
+            else
+                xmlWarnMsg(ctxt, XML_ERR_INVALID_URI,
+                           "Can't resolve URI: %s\n", systemId);
+            return(NULL);
+        }
+        if (xmlStrlen(URI) > XML_MAX_URI_LENGTH) {
+            xmlFatalErr(ctxt, XML_ERR_RESOURCE_LIMIT, "URI too long");
+            xmlFree(URI);
+            return(NULL);
+        }
     }
 
+    ret = xmlLoadResource(ctxt, (const char *) URI,
+                          (const char *) publicId, XML_RESOURCE_DTD);
+
     xmlFree(URI);
     return(ret);
 }
@@ -2129,12 +2135,14 @@ xmlSAX2StartElementNs(void *ctx,
     /*
      * First check on validity:
      */
-    if (ctxt->validate && (ctxt->myDoc->extSubset == NULL) &&
-        ((ctxt->myDoc->intSubset == NULL) ||
-	 ((ctxt->myDoc->intSubset->notations == NULL) &&
-	  (ctxt->myDoc->intSubset->elements == NULL) &&
-	  (ctxt->myDoc->intSubset->attributes == NULL) &&
-	  (ctxt->myDoc->intSubset->entities == NULL)))) {
+    if (ctxt->validate &&
+        ((ctxt->myDoc == NULL) ||
+         ((ctxt->myDoc->extSubset == NULL) &&
+          ((ctxt->myDoc->intSubset == NULL) ||
+	   ((ctxt->myDoc->intSubset->notations == NULL) &&
+	    (ctxt->myDoc->intSubset->elements == NULL) &&
+	    (ctxt->myDoc->intSubset->attributes == NULL) &&
+	    (ctxt->myDoc->intSubset->entities == NULL)))))) {
 	xmlErrValid(ctxt, XML_DTD_NO_DTD,
 	  "Validation failed: no DTD found !", NULL, NULL);
 	ctxt->validate = 0;
@@ -2558,7 +2566,7 @@ xmlSAX2Text(xmlParserCtxtPtr ctxt, const xmlChar *ch, int len,
         else {
             lastChild->line = USHRT_MAX;
             if (ctxt->options & XML_PARSE_BIG_LINES)
-                lastChild->psvi = (void *) (ptrdiff_t) ctxt->input->line;
+                lastChild->psvi = XML_INT_TO_PTR(ctxt->input->line);
         }
     }
 }
@@ -2725,7 +2733,7 @@ xmlSAXVersion(xmlSAXHandler *hdlr, int version)
     hdlr->reference = xmlSAX2Reference;
     hdlr->characters = xmlSAX2Characters;
     hdlr->cdataBlock = xmlSAX2CDataBlock;
-    hdlr->ignorableWhitespace = xmlSAX2Characters;
+    hdlr->ignorableWhitespace = xmlSAX2IgnorableWhitespace;
     hdlr->processingInstruction = xmlSAX2ProcessingInstruction;
     hdlr->comment = xmlSAX2Comment;
     hdlr->warning = xmlParserWarning;
diff --git a/buf.c b/buf.c
index ebab442f..5205171b 100644
--- a/buf.c
+++ b/buf.c
@@ -622,6 +622,7 @@ xmlBufFromBuffer(xmlBufferPtr buffer) {
 /**
  * xmlBufBackToBuffer:
  * @buf: new buffer wrapping the old one
+ * @ret: old buffer
  *
  * Function to be called once internal processing had been done to
  * update back the buffer provided by the user. This can lead to
@@ -629,7 +630,7 @@ xmlBufFromBuffer(xmlBufferPtr buffer) {
  * than what an xmlBuffer can support on 64 bits (INT_MAX)
  * The xmlBufPtr @buf wrapper is deallocated by this call in any case.
  *
- * Returns the old xmlBufferPtr unless the call failed and NULL is returned
+ * Returns 0 on success, -1 on error.
  */
 int
 xmlBufBackToBuffer(xmlBufPtr buf, xmlBufferPtr ret) {
diff --git a/c14n.c b/c14n.c
index 5e0eed3f..c9bbd22f 100644
--- a/c14n.c
+++ b/c14n.c
@@ -25,6 +25,7 @@
 
 #include "private/error.h"
 #include "private/io.h"
+#include "private/memory.h"
 
 /************************************************************************
  *									*
@@ -306,30 +307,26 @@ xmlC14NVisibleNsStackAdd(xmlC14NVisibleNsStackPtr cur, xmlNsPtr ns, xmlNodePtr n
        ((cur->nsTab != NULL) && (cur->nodeTab == NULL)))
 	return (1);
 
-    if ((cur->nsTab == NULL) && (cur->nodeTab == NULL)) {
-        cur->nsTab = (xmlNsPtr*) xmlMalloc(XML_NAMESPACES_DEFAULT * sizeof(xmlNsPtr));
-        cur->nodeTab = (xmlNodePtr*) xmlMalloc(XML_NAMESPACES_DEFAULT * sizeof(xmlNodePtr));
-	if ((cur->nsTab == NULL) || (cur->nodeTab == NULL))
-	    return (-1);
-	memset(cur->nsTab, 0 , XML_NAMESPACES_DEFAULT * sizeof(xmlNsPtr));
-	memset(cur->nodeTab, 0 , XML_NAMESPACES_DEFAULT * sizeof(xmlNodePtr));
-        cur->nsMax = XML_NAMESPACES_DEFAULT;
-    } else if(cur->nsMax == cur->nsCurEnd) {
-	void *tmp;
-	int tmpSize;
-
-	tmpSize = 2 * cur->nsMax;
-	tmp = xmlRealloc(cur->nsTab, tmpSize * sizeof(xmlNsPtr));
-	if (tmp == NULL)
+    if (cur->nsMax <= cur->nsCurEnd) {
+	xmlNsPtr *tmp1;
+        xmlNodePtr *tmp2;
+	int newSize;
+
+        newSize = xmlGrowCapacity(cur->nsMax,
+                                  sizeof(tmp1[0]) + sizeof(tmp2[0]),
+                                  XML_NAMESPACES_DEFAULT, XML_MAX_ITEMS);
+
+	tmp1 = xmlRealloc(cur->nsTab, newSize * sizeof(tmp1[0]));
+	if (tmp1 == NULL)
 	    return (-1);
-	cur->nsTab = (xmlNsPtr*)tmp;
+	cur->nsTab = tmp1;
 
-	tmp = xmlRealloc(cur->nodeTab, tmpSize * sizeof(xmlNodePtr));
-	if (tmp == NULL)
+	tmp2 = xmlRealloc(cur->nodeTab, newSize * sizeof(tmp2[0]));
+	if (tmp2 == NULL)
 	    return (-1);
-	cur->nodeTab = (xmlNodePtr*)tmp;
+	cur->nodeTab = tmp2;
 
-	cur->nsMax = tmpSize;
+	cur->nsMax = newSize;
     }
     cur->nsTab[cur->nsCurEnd] = ns;
     cur->nodeTab[cur->nsCurEnd] = node;
@@ -2142,14 +2139,20 @@ xmlC11NNormalizeString(const xmlChar * input,
         if ((out - buffer) > (buffer_size - 10)) {
             xmlChar *tmp;
             int indx = out - buffer;
+            int newSize;
 
-            buffer_size *= 2;
-            tmp = xmlRealloc(buffer, buffer_size);
+            newSize = xmlGrowCapacity(buffer_size, 1, 1, XML_MAX_ITEMS);
+            if (newSize < 0) {
+                xmlFree(buffer);
+                return(NULL);
+            }
+            tmp = xmlRealloc(buffer, newSize);
             if (tmp == NULL) {
                 xmlFree(buffer);
                 return(NULL);
             }
             buffer = tmp;
+            buffer_size = newSize;
             out = &buffer[indx];
         }
 
diff --git a/catalog.c b/catalog.c
index 80621768..8aaa0784 100644
--- a/catalog.c
+++ b/catalog.c
@@ -40,6 +40,8 @@
 #include "private/cata.h"
 #include "private/buf.h"
 #include "private/error.h"
+#include "private/memory.h"
+#include "private/parser.h"
 #include "private/threads.h"
 
 #define MAX_DELEGATE	50
@@ -54,10 +56,10 @@
 #define XML_URN_PUBID "urn:publicid:"
 #define XML_CATAL_BREAK ((xmlChar *) -1)
 #ifndef XML_XML_DEFAULT_CATALOG
-#define XML_XML_DEFAULT_CATALOG "file://" SYSCONFDIR "/xml/catalog"
+#define XML_XML_DEFAULT_CATALOG "file://" XML_SYSCONFDIR "/xml/catalog"
 #endif
 #ifndef XML_SGML_DEFAULT_CATALOG
-#define XML_SGML_DEFAULT_CATALOG "file://" SYSCONFDIR "/sgml/catalog"
+#define XML_SGML_DEFAULT_CATALOG "file://" XML_SYSCONFDIR "/sgml/catalog"
 #endif
 
 static xmlChar *xmlCatalogNormalizePublic(const xmlChar *pubID);
@@ -897,7 +899,7 @@ xmlParseCatalogFile(const char *filename) {
     inputStream->buf = buf;
     xmlBufResetInput(buf->buffer, inputStream);
 
-    if (inputPush(ctxt, inputStream) < 0) {
+    if (xmlCtxtPushInput(ctxt, inputStream) < 0) {
         xmlFreeInputStream(inputStream);
         xmlFreeParserCtxt(ctxt);
         return(NULL);
@@ -2128,7 +2130,7 @@ xmlParseSGMLCatalogComment(const xmlChar *cur) {
  */
 static const xmlChar *
 xmlParseSGMLCatalogPubid(const xmlChar *cur, xmlChar **id) {
-    xmlChar *buf = NULL, *tmp;
+    xmlChar *buf = NULL;
     int len = 0;
     int size = 50;
     xmlChar stop;
@@ -2155,14 +2157,23 @@ xmlParseSGMLCatalogPubid(const xmlChar *cur, xmlChar **id) {
 	if ((stop == ' ') && (IS_BLANK_CH(*cur)))
 	    break;
 	if (len + 1 >= size) {
-	    size *= 2;
-	    tmp = (xmlChar *) xmlRealloc(buf, size);
+            xmlChar *tmp;
+            int newSize;
+
+            newSize = xmlGrowCapacity(size, 1, 1, XML_MAX_ITEMS);
+            if (newSize < 0) {
+		xmlCatalogErrMemory();
+		xmlFree(buf);
+		return(NULL);
+            }
+	    tmp = xmlRealloc(buf, newSize);
 	    if (tmp == NULL) {
 		xmlCatalogErrMemory();
 		xmlFree(buf);
 		return(NULL);
 	    }
 	    buf = tmp;
+            size = newSize;
 	}
 	buf[len++] = *cur;
 	NEXT;
@@ -3409,7 +3420,7 @@ xmlCatalogConvert(void) {
  * xmlCatalogGetDefaults:
  *
  * DEPRECATED: Use XML_PARSE_NO_SYS_CATALOG and
- * XML_PARSE_NO_CATALOG_PI.
+ * XML_PARSE_CATALOG_PI.
  *
  * Used to get the user preference w.r.t. to what catalogs should
  * be accepted
@@ -3426,7 +3437,7 @@ xmlCatalogGetDefaults(void) {
  * @allow:  what catalogs should be accepted
  *
  * DEPRECATED: Use XML_PARSE_NO_SYS_CATALOG and
- * XML_PARSE_NO_CATALOG_PI.
+ * XML_PARSE_CATALOG_PI.
  *
  * Used to set the user preference w.r.t. to what catalogs should
  * be accepted
diff --git a/config.h b/config.h
index 6d8a1c13..cd16e98a 100644
--- a/config.h
+++ b/config.h
@@ -102,5 +102,8 @@
 /* Version number of package */
 #define VERSION "2.14.0"
 
+/* System configuration directory (/etc) */
+#define XML_SYSCONFDIR "/usr/local/etc"
+
 /* TLS specifier */
 #define XML_THREAD_LOCAL _Thread_local
diff --git a/config.h.cmake.in b/config.h.cmake.in
index 4da8c765..a2f7d9b6 100644
--- a/config.h.cmake.in
+++ b/config.h.cmake.in
@@ -31,8 +31,8 @@
 /* Define to 1 if you have the <stdint.h> header file. */
 #cmakedefine HAVE_STDINT_H 1
 
-/* Version number of package */
-#cmakedefine VERSION "@VERSION@"
+/* System configuration directory (/etc) */
+#cmakedefine XML_SYSCONFDIR "@XML_SYSCONFDIR@"
 
 /* TLS specifier */
 #cmakedefine XML_THREAD_LOCAL @XML_THREAD_LOCAL@
diff --git a/configure.ac b/configure.ac
index c6dc93d5..fc77fd1b 100644
--- a/configure.ac
+++ b/configure.ac
@@ -7,6 +7,7 @@ AC_INIT([libxml2],[version_macro])
 AC_CONFIG_SRCDIR([entities.c])
 AC_CONFIG_HEADERS([config.h])
 AC_CONFIG_MACRO_DIR([m4])
+AC_CONFIG_AUX_DIR([.])
 AC_CANONICAL_HOST
 
 LIBXML_VERSION=version_macro
@@ -40,9 +41,7 @@ AC_SUBST(LIBXML_VERSION_INFO)
 AC_SUBST(LIBXML_VERSION_NUMBER)
 AC_SUBST(LIBXML_VERSION_EXTRA)
 
-VERSION=${LIBXML_VERSION}
-
-AM_INIT_AUTOMAKE([1.16.3 foreign no-dist-gzip dist-xz])
+AM_INIT_AUTOMAKE([1.16.3 foreign subdir-objects no-dist-gzip dist-xz])
 AM_MAINTAINER_MODE([enable])
 AM_SILENT_RULES([yes])
 
@@ -196,12 +195,6 @@ if test "$with_writer" = "yes"; then
     fi
     with_push=yes
 fi
-if test "$with_xinclude" = "yes"; then
-    if test "$with_xpath" = "no"; then
-        echo WARNING: --with-xinclude overrides --without-xpath
-    fi
-    with_xpath=yes
-fi
 if test "$with_xptr" = "yes"; then
     if test "$with_xpath" = "no"; then
         echo WARNING: --with-xptr overrides --without-xpath
@@ -273,7 +266,6 @@ else
     if test "$with_xpath" = "no"; then
         with_c14n=no
         with_schematron=no
-        with_xinclude=no
         with_xptr=no
     fi
 fi
@@ -984,10 +976,10 @@ if test "$with_icu" != "no" && test "$with_icu" != "" ; then
 
     # Try pkg-config first so that static linking works.
     # If this succeeeds, we ignore the WITH_ICU directory.
-    PKG_CHECK_MODULES([ICU], [icu-i18n], [
-        WITH_ICU=1; XML_PC_REQUIRES="${XML_PC_REQUIRES} icu-i18n"
+    PKG_CHECK_MODULES([ICU], [icu-uc], [
+        WITH_ICU=1; XML_PC_REQUIRES="${XML_PC_REQUIRES} icu-uc"
         m4_ifdef([PKG_CHECK_VAR],
-            [PKG_CHECK_VAR([ICU_DEFS], [icu-i18n], [DEFS])])
+            [PKG_CHECK_VAR([ICU_DEFS], [icu-uc], [DEFS])])
         if test "x$ICU_DEFS" != "x"; then
             ICU_CFLAGS="$ICU_CFLAGS $ICU_DEFS"
         fi],[:])
@@ -1085,6 +1077,10 @@ AC_SUBST(XML_PRIVATE_LIBS)
 AC_SUBST(XML_PRIVATE_CFLAGS)
 AC_SUBST(XML_INCLUDEDIR)
 
+AX_RECURSIVE_EVAL(["$sysconfdir"], [XML_SYSCONFDIR])
+AC_DEFINE_UNQUOTED([XML_SYSCONFDIR], ["$XML_SYSCONFDIR"],
+                   [System configuration directory (/etc)])
+
 # keep on one line for cygwin c.f. #130896
 AC_CONFIG_FILES([Makefile include/Makefile include/libxml/Makefile include/private/Makefile doc/Makefile doc/devhelp/Makefile example/Makefile fuzz/Makefile python/Makefile python/tests/Makefile xstc/Makefile include/libxml/xmlversion.h libxml-2.0.pc libxml2-config.cmake])
 AC_CONFIG_FILES([python/setup.py], [chmod +x python/setup.py])
diff --git a/debugXML.c b/debugXML.c
index f5ffe60c..bcf90a00 100644
--- a/debugXML.c
+++ b/debugXML.c
@@ -24,6 +24,7 @@
 #include <libxml/xmlerror.h>
 
 #include "private/error.h"
+#include "private/parser.h"
 
 #define DUMP_TEXT_TYPE 1
 
diff --git a/dict.c b/dict.c
index ccd8b542..5654be31 100644
--- a/dict.c
+++ b/dict.c
@@ -929,10 +929,13 @@ xmlDictQLookup(xmlDictPtr dict, const xmlChar *prefix, const xmlChar *name) {
   #define WIN32_LEAN_AND_MEAN
   #include <windows.h>
   #include <bcrypt.h>
-#elif HAVE_DECL_GETENTROPY
-  #include <unistd.h>
-  #include <sys/random.h>
 #else
+  #if HAVE_DECL_GETENTROPY
+    /* POSIX 2024 */
+    #include <unistd.h>
+    /* Older platforms */
+    #include <sys/random.h>
+  #endif
   #include <time.h>
 #endif
 
@@ -954,24 +957,50 @@ xmlInitRandom(void) {
 #ifdef _WIN32
         NTSTATUS status;
 
+        /*
+         * You can find many (recent as of 2025) discussions how
+         * to get a pseudo-random seed on Windows in projects like
+         * Golang, Rust, Chromium and Firefox.
+         *
+         * TODO: Support ProcessPrng available since Windows 10.
+         */
         status = BCryptGenRandom(NULL, (unsigned char *) globalRngState,
                                  sizeof(globalRngState),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
         if (!BCRYPT_SUCCESS(status))
             xmlAbort("libxml2: BCryptGenRandom failed with error code %lu\n",
                      GetLastError());
-#elif HAVE_DECL_GETENTROPY
+#else
+        int var;
+
+#if HAVE_DECL_GETENTROPY
         while (1) {
             if (getentropy(globalRngState, sizeof(globalRngState)) == 0)
+                return;
+
+            /*
+             * This most likely means that libxml2 was compiled on
+             * a system supporting certain system calls and is running
+             * on a system that doesn't support these calls, as can
+             * be the case on Linux.
+             */
+            if (errno == ENOSYS)
                 break;
 
+            /*
+             * We really don't want to fallback to the unsafe PRNG
+             * for possibly accidental reasons, so we abort on any
+             * unknown error.
+             */
             if (errno != EINTR)
                 xmlAbort("libxml2: getentropy failed with error code %d\n",
                          errno);
         }
-#else
-        int var;
+#endif
 
+        /*
+         * TODO: Fallback to /dev/urandom for older POSIX systems.
+         */
         globalRngState[0] =
                 (unsigned) time(NULL) ^
                 HASH_ROL((unsigned) ((size_t) &xmlInitRandom & 0xFFFFFFFF), 8);
diff --git a/doc/apibuild.py b/doc/apibuild.py
index a59b39d8..40a2ba0f 100755
--- a/doc/apibuild.py
+++ b/doc/apibuild.py
@@ -21,6 +21,7 @@ debugsym=None
 ignored_files = {
   "config.h": "generated portability layer",
   "libxml.h": "internal only",
+  "legacy.c": "legacy code",
   "testModule.c": "test tool",
   "testapi.c": "generated regression tests",
   "runtest.c": "regression tests program",
@@ -57,6 +58,7 @@ ignored_words = {
   "LIBXML_ATTR_ALLOC_SIZE": (3, "macro for gcc checking extension"),
   "ATTRIBUTE_NO_SANITIZE": (3, "macro keyword"),
   "ATTRIBUTE_NO_SANITIZE_INTEGER": (0, "macro keyword"),
+  "ATTRIBUTE_COUNTED_BY": (3, "macro keyword"),
   "XML_DEPRECATED": (0, "macro keyword"),
   "XML_DEPRECATED_MEMBER": (0, "macro keyword"),
   "XML_GLOBALS_ALLOC": (0, "macro keyword"),
diff --git a/doc/libxml2-api.xml b/doc/libxml2-api.xml
index 2e857751..af18f826 100644
--- a/doc/libxml2-api.xml
+++ b/doc/libxml2-api.xml
@@ -11,7 +11,10 @@
      <exports symbol='HTML_DEPRECATED' type='enum'/>
      <exports symbol='HTML_INVALID' type='enum'/>
      <exports symbol='HTML_NA' type='enum'/>
+     <exports symbol='HTML_PARSE_BIG_LINES' type='enum'/>
      <exports symbol='HTML_PARSE_COMPACT' type='enum'/>
+     <exports symbol='HTML_PARSE_HTML5' type='enum'/>
+     <exports symbol='HTML_PARSE_HUGE' type='enum'/>
      <exports symbol='HTML_PARSE_IGNORE_ENC' type='enum'/>
      <exports symbol='HTML_PARSE_NOBLANKS' type='enum'/>
      <exports symbol='HTML_PARSE_NODEFDTD' type='enum'/>
@@ -54,6 +57,7 @@
      <exports symbol='htmlCtxtReadIO' type='function'/>
      <exports symbol='htmlCtxtReadMemory' type='function'/>
      <exports symbol='htmlCtxtReset' type='function'/>
+     <exports symbol='htmlCtxtSetOptions' type='function'/>
      <exports symbol='htmlCtxtUseOptions' type='function'/>
      <exports symbol='htmlElementAllowedHere' type='function'/>
      <exports symbol='htmlElementStatusHere' type='function'/>
@@ -697,6 +701,7 @@
      <exports symbol='xmlCtxtGetVersion' type='function'/>
      <exports symbol='xmlCtxtParseContent' type='function'/>
      <exports symbol='xmlCtxtParseDocument' type='function'/>
+     <exports symbol='xmlCtxtParseDtd' type='function'/>
      <exports symbol='xmlCtxtReadDoc' type='function'/>
      <exports symbol='xmlCtxtReadFd' type='function'/>
      <exports symbol='xmlCtxtReadFile' type='function'/>
@@ -713,6 +718,8 @@
      <exports symbol='xmlCtxtSetPrivate' type='function'/>
      <exports symbol='xmlCtxtSetResourceLoader' type='function'/>
      <exports symbol='xmlCtxtUseOptions' type='function'/>
+     <exports symbol='xmlCtxtValidateDocument' type='function'/>
+     <exports symbol='xmlCtxtValidateDtd' type='function'/>
      <exports symbol='xmlExternalEntityLoader' type='function'/>
      <exports symbol='xmlFreeParserCtxt' type='function'/>
      <exports symbol='xmlGetExternalEntityLoader' type='function'/>
@@ -789,26 +796,8 @@
      <summary>internals routines and limits exported by the parser.</summary>
      <description>this module exports a number of internal parsing routines they are not really all intended for applications but can prove useful doing low level processing. </description>
      <author>Daniel Veillard </author>
-     <exports symbol='INPUT_CHUNK' type='macro'/>
-     <exports symbol='IS_ASCII_DIGIT' type='macro'/>
-     <exports symbol='IS_ASCII_LETTER' type='macro'/>
-     <exports symbol='IS_BASECHAR' type='macro'/>
      <exports symbol='IS_BLANK' type='macro'/>
      <exports symbol='IS_BLANK_CH' type='macro'/>
-     <exports symbol='IS_BYTE_CHAR' type='macro'/>
-     <exports symbol='IS_CHAR' type='macro'/>
-     <exports symbol='IS_CHAR_CH' type='macro'/>
-     <exports symbol='IS_COMBINING' type='macro'/>
-     <exports symbol='IS_COMBINING_CH' type='macro'/>
-     <exports symbol='IS_DIGIT' type='macro'/>
-     <exports symbol='IS_DIGIT_CH' type='macro'/>
-     <exports symbol='IS_EXTENDER' type='macro'/>
-     <exports symbol='IS_EXTENDER_CH' type='macro'/>
-     <exports symbol='IS_IDEOGRAPHIC' type='macro'/>
-     <exports symbol='IS_LETTER' type='macro'/>
-     <exports symbol='IS_LETTER_CH' type='macro'/>
-     <exports symbol='IS_PUBIDCHAR' type='macro'/>
-     <exports symbol='IS_PUBIDCHAR_CH' type='macro'/>
      <exports symbol='XML_MAX_DICTIONARY_LIMIT' type='macro'/>
      <exports symbol='XML_MAX_HUGE_LENGTH' type='macro'/>
      <exports symbol='XML_MAX_LOOKUP_LIMIT' type='macro'/>
@@ -837,6 +826,8 @@
      <exports symbol='xmlCreateMemoryParserCtxt' type='function'/>
      <exports symbol='xmlCreateURLParserCtxt' type='function'/>
      <exports symbol='xmlCtxtErrMemory' type='function'/>
+     <exports symbol='xmlCtxtPopInput' type='function'/>
+     <exports symbol='xmlCtxtPushInput' type='function'/>
      <exports symbol='xmlCurrentChar' type='function'/>
      <exports symbol='xmlFreeInputStream' type='function'/>
      <exports symbol='xmlIsLetter' type='function'/>
@@ -1438,6 +1429,8 @@
      <exports symbol='_xmlNotation' type='struct'/>
      <exports symbol='_xmlNs' type='struct'/>
      <exports symbol='_xmlRef' type='struct'/>
+     <exports symbol='xmlBufferAllocScheme' type='variable'/>
+     <exports symbol='xmlDefaultBufferSize' type='variable'/>
      <exports symbol='xmlAddChild' type='function'/>
      <exports symbol='xmlAddChildList' type='function'/>
      <exports symbol='xmlAddNextSibling' type='function'/>
@@ -3730,21 +3723,6 @@
     <macro name='HTML_TEXT_NODE' file='HTMLtree'>
       <info>Macro. A text node in a HTML document is really implemented the same way as a text node in an XML document.</info>
     </macro>
-    <macro name='INPUT_CHUNK' file='parserInternals'>
-      <info>The parser tries to always have that amount of input ready. One of the point is providing context when reporting errors.</info>
-    </macro>
-    <macro name='IS_ASCII_DIGIT' file='parserInternals'>
-      <info>Macro to check [0-9]</info>
-      <arg name='c' info='an xmlChar value'/>
-    </macro>
-    <macro name='IS_ASCII_LETTER' file='parserInternals'>
-      <info>Macro to check [a-zA-Z]</info>
-      <arg name='c' info='an xmlChar value'/>
-    </macro>
-    <macro name='IS_BASECHAR' file='parserInternals'>
-      <info>Macro to check the following production in the XML spec:  [85] BaseChar ::= ... long list see REC ...</info>
-      <arg name='c' info='an UNICODE value (int)'/>
-    </macro>
     <macro name='IS_BLANK' file='parserInternals'>
       <info>Macro to check the following production in the XML spec:  [3] S ::= (#x20 | #x9 | #xD | #xA)+</info>
       <arg name='c' info='an UNICODE value (int)'/>
@@ -3753,62 +3731,6 @@
       <info>Behaviour same as IS_BLANK</info>
       <arg name='c' info='an xmlChar value (normally unsigned char)'/>
     </macro>
-    <macro name='IS_BYTE_CHAR' file='parserInternals'>
-      <info>Macro to check the following production in the XML spec:  [2] Char ::= #x9 | #xA | #xD | [#x20...] any byte character in the accepted range</info>
-      <arg name='c' info='an byte value (int)'/>
-    </macro>
-    <macro name='IS_CHAR' file='parserInternals'>
-      <info>Macro to check the following production in the XML spec:  [2] Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF] any Unicode character, excluding the surrogate blocks, FFFE, and FFFF.</info>
-      <arg name='c' info='an UNICODE value (int)'/>
-    </macro>
-    <macro name='IS_CHAR_CH' file='parserInternals'>
-      <info>Behaves like IS_CHAR on single-byte value</info>
-      <arg name='c' info='an xmlChar (usually an unsigned char)'/>
-    </macro>
-    <macro name='IS_COMBINING' file='parserInternals'>
-      <info>Macro to check the following production in the XML spec:  [87] CombiningChar ::= ... long list see REC ...</info>
-      <arg name='c' info='an UNICODE value (int)'/>
-    </macro>
-    <macro name='IS_COMBINING_CH' file='parserInternals'>
-      <info>Always false (all combining chars &gt; 0xff)</info>
-      <arg name='c' info='an xmlChar (usually an unsigned char)'/>
-    </macro>
-    <macro name='IS_DIGIT' file='parserInternals'>
-      <info>Macro to check the following production in the XML spec:  [88] Digit ::= ... long list see REC ...</info>
-      <arg name='c' info='an UNICODE value (int)'/>
-    </macro>
-    <macro name='IS_DIGIT_CH' file='parserInternals'>
-      <info>Behaves like IS_DIGIT but with a single byte argument</info>
-      <arg name='c' info='an xmlChar value (usually an unsigned char)'/>
-    </macro>
-    <macro name='IS_EXTENDER' file='parserInternals'>
-      <info>Macro to check the following production in the XML spec:   [89] Extender ::= #x00B7 | #x02D0 | #x02D1 | #x0387 | #x0640 | #x0E46 | #x0EC6 | #x3005 | [#x3031-#x3035] | [#x309D-#x309E] | [#x30FC-#x30FE]</info>
-      <arg name='c' info='an UNICODE value (int)'/>
-    </macro>
-    <macro name='IS_EXTENDER_CH' file='parserInternals'>
-      <info>Behaves like IS_EXTENDER but with a single-byte argument</info>
-      <arg name='c' info='an xmlChar value (usually an unsigned char)'/>
-    </macro>
-    <macro name='IS_IDEOGRAPHIC' file='parserInternals'>
-      <info>Macro to check the following production in the XML spec:   [86] Ideographic ::= [#x4E00-#x9FA5] | #x3007 | [#x3021-#x3029]</info>
-      <arg name='c' info='an UNICODE value (int)'/>
-    </macro>
-    <macro name='IS_LETTER' file='parserInternals'>
-      <info>Macro to check the following production in the XML spec:   [84] Letter ::= BaseChar | Ideographic</info>
-      <arg name='c' info='an UNICODE value (int)'/>
-    </macro>
-    <macro name='IS_LETTER_CH' file='parserInternals'>
-      <info>Macro behaves like IS_LETTER, but only check base chars</info>
-      <arg name='c' info='an xmlChar value (normally unsigned char)'/>
-    </macro>
-    <macro name='IS_PUBIDCHAR' file='parserInternals'>
-      <info>Macro to check the following production in the XML spec:   [13] PubidChar ::= #x20 | #xD | #xA | [a-zA-Z0-9] | [-&apos;()+,./:=?;!*#@$_%]</info>
-      <arg name='c' info='an UNICODE value (int)'/>
-    </macro>
-    <macro name='IS_PUBIDCHAR_CH' file='parserInternals'>
-      <info>Same as IS_PUBIDCHAR but for single-byte value</info>
-      <arg name='c' info='an xmlChar value (normally unsigned char)'/>
-    </macro>
     <macro name='LIBXML2_NEW_BUFFER' file='tree'>
       <info>Macro used to express that the API use the new buffers for xmlParserInputBuffer and xmlOutputBuffer. The change was introduced in 2.9.0.</info>
     </macro>
@@ -4466,16 +4388,19 @@
     <enum name='HTML_DEPRECATED' file='HTMLparser' value='2' type='htmlStatus'/>
     <enum name='HTML_INVALID' file='HTMLparser' value='1' type='htmlStatus'/>
     <enum name='HTML_NA' file='HTMLparser' value='0' type='htmlStatus' info='something we don&apos;t check at all'/>
+    <enum name='HTML_PARSE_BIG_LINES' file='HTMLparser' value='4194304' type='htmlParserOption' info=' Store big lines numbers in text PSVI field'/>
     <enum name='HTML_PARSE_COMPACT' file='HTMLparser' value='65536' type='htmlParserOption' info='compact small text nodes'/>
-    <enum name='HTML_PARSE_IGNORE_ENC' file='HTMLparser' value='2097152' type='htmlParserOption' info=' ignore internal document encoding hint'/>
+    <enum name='HTML_PARSE_HTML5' file='HTMLparser' value='2' type='htmlParserOption' info='HTML5 support'/>
+    <enum name='HTML_PARSE_HUGE' file='HTMLparser' value='524288' type='htmlParserOption' info='relax any hardcoded limit from the parser'/>
+    <enum name='HTML_PARSE_IGNORE_ENC' file='HTMLparser' value='2097152' type='htmlParserOption' info='ignore internal document encoding hint'/>
     <enum name='HTML_PARSE_NOBLANKS' file='HTMLparser' value='256' type='htmlParserOption' info='remove blank nodes'/>
     <enum name='HTML_PARSE_NODEFDTD' file='HTMLparser' value='4' type='htmlParserOption' info='do not default a doctype if not found'/>
     <enum name='HTML_PARSE_NOERROR' file='HTMLparser' value='32' type='htmlParserOption' info='suppress error reports'/>
     <enum name='HTML_PARSE_NOIMPLIED' file='HTMLparser' value='8192' type='htmlParserOption' info='Do not add implied html/body... elements'/>
-    <enum name='HTML_PARSE_NONET' file='HTMLparser' value='2048' type='htmlParserOption' info='Forbid network access'/>
+    <enum name='HTML_PARSE_NONET' file='HTMLparser' value='2048' type='htmlParserOption' info='No effect'/>
     <enum name='HTML_PARSE_NOWARNING' file='HTMLparser' value='64' type='htmlParserOption' info='suppress warning reports'/>
-    <enum name='HTML_PARSE_PEDANTIC' file='HTMLparser' value='128' type='htmlParserOption' info='pedantic error reporting'/>
-    <enum name='HTML_PARSE_RECOVER' file='HTMLparser' value='1' type='htmlParserOption' info='Relaxed parsing'/>
+    <enum name='HTML_PARSE_PEDANTIC' file='HTMLparser' value='128' type='htmlParserOption' info='No effect'/>
+    <enum name='HTML_PARSE_RECOVER' file='HTMLparser' value='1' type='htmlParserOption' info='No effect'/>
     <enum name='HTML_REQUIRED' file='HTMLparser' value='12' type='htmlStatus' info=' VALID bit set so ( &amp; HTML_VALID ) is TRUE'/>
     <enum name='HTML_VALID' file='HTMLparser' value='4' type='htmlStatus'/>
     <enum name='XLINK_ACTUATE_AUTO' file='xlink' value='1' type='xlinkActuate'/>
@@ -5754,6 +5679,7 @@ crash if you try to modify the tree)'/>
       <field name='attrs_opt' type='const char **'/>
       <field name='attrs_depr' type='const char **'/>
       <field name='attrs_req' type='const char **'/>
+      <field name='dataMode' type='int'/>
     </struct>
     <typedef name='htmlElemDescPtr' file='HTMLparser' type='htmlElemDesc *'/>
     <struct name='htmlEntityDesc' file='HTMLparser' type='struct _htmlEntityDesc'>
@@ -6730,6 +6656,12 @@ crash if you try to modify the tree)'/>
     <variable name='oldXMLWDcompatibility' file='parser' type='const int'>
       <info>DEPRECATED, always 0.</info>
     </variable>
+    <variable name='xmlBufferAllocScheme' file='tree' type='const xmlBufferAllocationScheme'>
+      <info>DEPRECATED: Don&apos;t use.  Global setting, default allocation policy for buffers, default is XML_BUFFER_ALLOC_EXACT</info>
+    </variable>
+    <variable name='xmlDefaultBufferSize' file='tree' type='const int'>
+      <info>DEPRECATED: Don&apos;t use.  Global setting, default buffer size. Default value is BASE_BUFFER_SIZE</info>
+    </variable>
     <variable name='xmlDefaultSAXHandler' file='parser' type='const xmlSAXHandlerV1'>
       <info>DEPRECATED: This handler is unused and will be removed from future versions.  Default SAX version1 handler for XML, builds the DOM tree</info>
     </variable>
@@ -6912,15 +6844,15 @@ crash if you try to modify the tree)'/>
     </functype>
     <function name='htmlAttrAllowed' file='HTMLparser' module='HTMLparser'>
       <cond>defined(LIBXML_HTML_ENABLED)</cond>
-      <info>Checks whether an attribute is valid for an element Has full knowledge of Required and Deprecated attributes</info>
-      <return type='htmlStatus' info='one of HTML_REQUIRED, HTML_VALID, HTML_DEPRECATED, HTML_INVALID'/>
+      <info>DEPRECATED: Don&apos;t use.</info>
+      <return type='htmlStatus' info='HTML_VALID'/>
       <arg name='elt' type='const htmlElemDesc *' info='HTML element'/>
       <arg name='attr' type='const xmlChar *' info='HTML attribute'/>
       <arg name='legacy' type='int' info='whether to allow deprecated attributes'/>
     </function>
     <function name='htmlAutoCloseTag' file='HTMLparser' module='HTMLparser'>
       <cond>defined(LIBXML_HTML_ENABLED)</cond>
-      <info>The HTML DTD allows a tag to implicitly close other tags. The list is kept in htmlStartClose array. This function checks if the element or one of it&apos;s children would autoclose the given tag.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  The HTML DTD allows a tag to implicitly close other tags. The list is kept in htmlStartClose array. This function checks if the element or one of it&apos;s children would autoclose the given tag.</info>
       <return type='int' info='1 if autoclose, 0 otherwise'/>
       <arg name='doc' type='htmlDocPtr' info='the HTML document'/>
       <arg name='name' type='const xmlChar *' info='The tag name'/>
@@ -7016,9 +6948,16 @@ crash if you try to modify the tree)'/>
       <return type='void'/>
       <arg name='ctxt' type='htmlParserCtxtPtr' info='an HTML parser context'/>
     </function>
+    <function name='htmlCtxtSetOptions' file='HTMLparser' module='HTMLparser'>
+      <cond>defined(LIBXML_HTML_ENABLED)</cond>
+      <info>Applies the options to the parser context. Unset options are cleared.  Available since 2.14.0. With older versions, you can use htmlCtxtUseOptions.  HTML_PARSE_RECOVER  No effect as of 2.14.0.  HTML_PARSE_HTML5  Make the tokenizer emit a SAX callback for each token. This results in unbalanced invocations of startElement and endElement.  For now, this is only usable with custom SAX callbacks.  HTML_PARSE_NODEFDTD  Do not default to a doctype if none was found.  HTML_PARSE_NOERROR  Disable error and warning reports to the error handlers. Errors are still accessible with xmlCtxtGetLastError.  HTML_PARSE_NOWARNING  Disable warning reports.  HTML_PARSE_PEDANTIC  No effect.  HTML_PARSE_NOBLANKS  Remove some text nodes containing only whitespace from the result document. Which nodes are removed depends on a conservative heuristic. The reindenting feature of the serialization code relies on this option to be set when parsing. Use of this option is DISCOURAGED.  HTML_PARSE_NONET  No effect.  HTML_PARSE_NOIMPLIED  Do not add implied html, head or body elements.  HTML_PARSE_COMPACT  Store small strings directly in the node struct to save memory.  HTML_PARSE_HUGE  Relax some internal limits.  Available since 2.14.0. Use XML_PARSE_HUGE works with older versions.  Maximum size of text nodes, tags, comments, CDATA sections  normal: 10M huge:    1B  Maximum size of names, system literals, pubid literals  normal: 50K huge:   10M  Maximum nesting depth of elements  normal:  256 huge:   2048  HTML_PARSE_IGNORE_ENC  Ignore the encoding in the HTML declaration. This option is mostly unneeded these days. The only effect is to enforce UTF-8 decoding of ASCII-like data.  HTML_PARSE_BIG_LINES  Enable reporting of line numbers larger than 65535.  Available since 2.14.0.</info>
+      <return type='int' info='0 in case of success, the set of unknown or unimplemented options in case of error.'/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='an HTML parser context'/>
+      <arg name='options' type='int' info='a bitmask of xmlParserOption values'/>
+    </function>
     <function name='htmlCtxtUseOptions' file='HTMLparser' module='HTMLparser'>
       <cond>defined(LIBXML_HTML_ENABLED)</cond>
-      <info>Applies the options to the parser context</info>
+      <info>DEPRECATED: Use htmlCtxtSetOptions.  Applies the options to the parser context. The following options are never cleared and can only be enabled:  HTML_PARSE_NODEFDTD HTML_PARSE_NOERROR HTML_PARSE_NOWARNING HTML_PARSE_NOIMPLIED HTML_PARSE_COMPACT HTML_PARSE_HUGE HTML_PARSE_IGNORE_ENC HTML_PARSE_BIG_LINES</info>
       <return type='int' info='0 in case of success, the set of unknown or unimplemented options in case of error.'/>
       <arg name='ctxt' type='htmlParserCtxtPtr' info='an HTML parser context'/>
       <arg name='options' type='int' info='a combination of htmlParserOption(s)'/>
@@ -7071,15 +7010,15 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='htmlElementAllowedHere' file='HTMLparser' module='HTMLparser'>
       <cond>defined(LIBXML_HTML_ENABLED)</cond>
-      <info>Checks whether an HTML element may be a direct child of a parent element. Note - doesn&apos;t check for deprecated elements</info>
-      <return type='int' info='1 if allowed; 0 otherwise.'/>
+      <info>DEPRECATED: Don&apos;t use.</info>
+      <return type='int' info='1'/>
       <arg name='parent' type='const htmlElemDesc *' info='HTML parent element'/>
       <arg name='elt' type='const xmlChar *' info='HTML element'/>
     </function>
     <function name='htmlElementStatusHere' file='HTMLparser' module='HTMLparser'>
       <cond>defined(LIBXML_HTML_ENABLED)</cond>
-      <info>Checks whether an HTML element may be a direct child of a parent element. and if so whether it is valid or deprecated.</info>
-      <return type='htmlStatus' info='one of HTML_VALID, HTML_DEPRECATED, HTML_INVALID'/>
+      <info>DEPRECATED: Don&apos;t use.</info>
+      <return type='htmlStatus' info='HTML_VALID'/>
       <arg name='parent' type='const htmlElemDesc *' info='HTML parent element'/>
       <arg name='elt' type='const htmlElemDesc *' info='HTML element'/>
     </function>
@@ -7130,14 +7069,14 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='htmlIsAutoClosed' file='HTMLparser' module='HTMLparser'>
       <cond>defined(LIBXML_HTML_ENABLED)</cond>
-      <info>The HTML DTD allows a tag to implicitly close other tags. The list is kept in htmlStartClose array. This function checks if a tag is autoclosed by one of it&apos;s child</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  The HTML DTD allows a tag to implicitly close other tags. The list is kept in htmlStartClose array. This function checks if a tag is autoclosed by one of it&apos;s child</info>
       <return type='int' info='1 if autoclosed, 0 otherwise'/>
       <arg name='doc' type='htmlDocPtr' info='the HTML document'/>
       <arg name='elem' type='htmlNodePtr' info='the HTML element'/>
     </function>
     <function name='htmlIsBooleanAttr' file='HTMLtree' module='HTMLtree'>
       <cond>defined(LIBXML_HTML_ENABLED)</cond>
-      <info>Determine if a given attribute is a boolean attribute.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Determine if a given attribute is a boolean attribute.</info>
       <return type='int' info='false if the attribute is not boolean, true otherwise.'/>
       <arg name='name' type='const xmlChar *' info='the name of the attribute to check'/>
     </function>
@@ -7220,15 +7159,15 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='htmlNodeStatus' file='HTMLparser' module='HTMLparser'>
       <cond>defined(LIBXML_HTML_ENABLED)</cond>
-      <info>Checks whether the tree node is valid.  Experimental (the author only uses the HTML enhancements in a SAX parser)</info>
-      <return type='htmlStatus' info='for Element nodes, a return from htmlElementAllowedHere (if legacy allowed) or htmlElementStatusHere (otherwise). for Attribute nodes, a return from htmlAttrAllowed for other nodes, HTML_NA (no checks performed)'/>
+      <info>DEPRECATED: Don&apos;t use.</info>
+      <return type='htmlStatus' info='HTML_VALID'/>
       <arg name='node' type='htmlNodePtr' info='an htmlNodePtr in a tree'/>
       <arg name='legacy' type='int' info='whether to allow deprecated elements (YES is faster here for Element nodes)'/>
     </function>
     <function name='htmlParseCharRef' file='HTMLparser' module='HTMLparser'>
       <cond>defined(LIBXML_HTML_ENABLED)</cond>
-      <info>DEPRECATED: Internal function, don&apos;t use.  parse Reference declarations  [66] CharRef ::= &apos;&amp;#&apos; [0-9]+ &apos;;&apos; | &apos;&amp;#x&apos; [0-9a-fA-F]+ &apos;;&apos;</info>
-      <return type='int' info='the value parsed (as an int)'/>
+      <info>DEPRECATED: Internal function, don&apos;t use.</info>
+      <return type='int' info='0'/>
       <arg name='ctxt' type='htmlParserCtxtPtr' info='an HTML parser context'/>
     </function>
     <function name='htmlParseChunk' file='HTMLparser' module='HTMLparser'>
@@ -7261,8 +7200,8 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='htmlParseEntityRef' file='HTMLparser' module='HTMLparser'>
       <cond>defined(LIBXML_HTML_ENABLED)</cond>
-      <info>DEPRECATED: Internal function, don&apos;t use.  parse an HTML ENTITY references  [68] EntityRef ::= &apos;&amp;&apos; Name &apos;;&apos;</info>
-      <return type='const htmlEntityDesc *' info='the associated htmlEntityDescPtr if found, or NULL otherwise, if non-NULL *str will have to be freed by the caller.'/>
+      <info>DEPRECATED: Internal function, don&apos;t use.</info>
+      <return type='const htmlEntityDesc *' info='NULL.'/>
       <arg name='ctxt' type='htmlParserCtxtPtr' info='an HTML parser context'/>
       <arg name='str' type='const xmlChar **' info='location to store the entity name'/>
     </function>
@@ -7659,7 +7598,7 @@ crash if you try to modify the tree)'/>
       <arg name='URI' type='const xmlChar *' info='the URI'/>
     </function>
     <function name='xmlAddAttributeDecl' file='valid' module='valid'>
-      <info>Register a new attribute declaration Note that @tree becomes the ownership of the DTD</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Register a new attribute declaration Note that @tree becomes the ownership of the DTD</info>
       <return type='xmlAttributePtr' info='NULL if not new, otherwise the attribute decl'/>
       <arg name='ctxt' type='xmlValidCtxtPtr' info='the validation context'/>
       <arg name='dtd' type='xmlDtdPtr' info='pointer to the DTD'/>
@@ -7704,7 +7643,7 @@ crash if you try to modify the tree)'/>
       <arg name='content' type='const xmlChar *' info='the entity content'/>
     </function>
     <function name='xmlAddElementDecl' file='valid' module='valid'>
-      <info>Register a new element declaration</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Register a new element declaration</info>
       <return type='xmlElementPtr' info='NULL if not, otherwise the entity'/>
       <arg name='ctxt' type='xmlValidCtxtPtr' info='the validation context'/>
       <arg name='dtd' type='xmlDtdPtr' info='pointer to the DTD'/>
@@ -7751,7 +7690,7 @@ crash if you try to modify the tree)'/>
       <arg name='cur' type='xmlNodePtr' info='the new node'/>
     </function>
     <function name='xmlAddNotationDecl' file='valid' module='valid'>
-      <info>Register a new notation declaration</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Register a new notation declaration</info>
       <return type='xmlNotationPtr' info='NULL if not, otherwise the entity'/>
       <arg name='ctxt' type='xmlValidCtxtPtr' info='the validation context'/>
       <arg name='dtd' type='xmlDtdPtr' info='pointer to the DTD'/>
@@ -7781,12 +7720,12 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='xmlAllocOutputBuffer' file='xmlIO' module='xmlIO'>
       <cond>defined(LIBXML_OUTPUT_ENABLED)</cond>
-      <info>Create a buffered parser output</info>
+      <info>Create a buffered parser output  Consumes @encoder even in error case.</info>
       <return type='xmlOutputBufferPtr' info='the new parser output or NULL'/>
       <arg name='encoder' type='xmlCharEncodingHandlerPtr' info='the encoding converter or NULL'/>
     </function>
     <function name='xmlAllocParserInputBuffer' file='xmlIO' module='xmlIO'>
-      <info>Create a buffered parser input for progressive parsing.  The encoding argument is deprecated and should be set to XML_CHAR_ENCODING_NONE. The encoding can be changed with xmlSwitchEncoding or xmlSwitchEncodingName later on.</info>
+      <info>DEPRECATED: Use xmlNewInputFrom*.  Create a buffered parser input for progressive parsing.  The encoding argument is deprecated and should be set to XML_CHAR_ENCODING_NONE. The encoding can be changed with xmlSwitchEncoding or xmlSwitchEncodingName later on.</info>
       <return type='xmlParserInputBufferPtr' info='the new parser input or NULL'/>
       <arg name='enc' type='xmlCharEncoding' info='the charset encoding if known (deprecated)'/>
     </function>
@@ -7982,7 +7921,7 @@ crash if you try to modify the tree)'/>
       <arg name='format' type='int' info='is formatting allowed'/>
     </function>
     <function name='xmlBufShrink' file='tree' module='buf'>
-      <info>Remove the beginning of an XML buffer. NOTE that this routine behaviour differs from xmlBufferShrink() as it will return 0 on error instead of -1 due to size_t being used as the return type.</info>
+      <info>DEPRECATED: Don&apos;t use.  Remove the beginning of an XML buffer. NOTE that this routine behaviour differs from xmlBufferShrink() as it will return 0 on error instead of -1 due to size_t being used as the return type.</info>
       <return type='size_t' info='the number of byte removed or 0 in case of failure'/>
       <arg name='buf' type='xmlBufPtr' info='the buffer to dump'/>
       <arg name='len' type='size_t' info='the number of xmlChar to remove'/>
@@ -7992,115 +7931,115 @@ crash if you try to modify the tree)'/>
       <return type='size_t' info='the length of data in the internal content'/>
       <arg name='buf' type='const xmlBufPtr' info='the buffer'/>
     </function>
-    <function name='xmlBufferAdd' file='tree' module='tree'>
+    <function name='xmlBufferAdd' file='tree' module='buf'>
       <info>Add a string range to an XML buffer. if len == -1, the length of str is recomputed.</info>
-      <return type='int' info='0 successful, a positive error code number otherwise and -1 in case of internal or API error.'/>
+      <return type='int' info='a xmlParserError code.'/>
       <arg name='buf' type='xmlBufferPtr' info='the buffer to dump'/>
       <arg name='str' type='const xmlChar *' info='the #xmlChar string'/>
       <arg name='len' type='int' info='the number of #xmlChar to add'/>
     </function>
-    <function name='xmlBufferAddHead' file='tree' module='tree'>
+    <function name='xmlBufferAddHead' file='tree' module='buf'>
       <info>Add a string range to the beginning of an XML buffer. if len == -1, the length of @str is recomputed.</info>
-      <return type='int' info='0 successful, a positive error code number otherwise and -1 in case of internal or API error.'/>
+      <return type='int' info='a xmlParserError code.'/>
       <arg name='buf' type='xmlBufferPtr' info='the buffer'/>
       <arg name='str' type='const xmlChar *' info='the #xmlChar string'/>
       <arg name='len' type='int' info='the number of #xmlChar to add'/>
     </function>
-    <function name='xmlBufferCCat' file='tree' module='tree'>
+    <function name='xmlBufferCCat' file='tree' module='buf'>
       <info>Append a zero terminated C string to an XML buffer.</info>
       <return type='int' info='0 successful, a positive error code number otherwise and -1 in case of internal or API error.'/>
       <arg name='buf' type='xmlBufferPtr' info='the buffer to dump'/>
       <arg name='str' type='const char *' info='the C char string'/>
     </function>
-    <function name='xmlBufferCat' file='tree' module='tree'>
+    <function name='xmlBufferCat' file='tree' module='buf'>
       <info>Append a zero terminated string to an XML buffer.</info>
       <return type='int' info='0 successful, a positive error code number otherwise and -1 in case of internal or API error.'/>
       <arg name='buf' type='xmlBufferPtr' info='the buffer to add to'/>
       <arg name='str' type='const xmlChar *' info='the #xmlChar string'/>
     </function>
-    <function name='xmlBufferContent' file='tree' module='tree'>
+    <function name='xmlBufferContent' file='tree' module='buf'>
       <info>Function to extract the content of a buffer</info>
       <return type='const xmlChar *' info='the internal content'/>
       <arg name='buf' type='const xmlBuffer *' info='the buffer'/>
     </function>
-    <function name='xmlBufferCreate' file='tree' module='tree'>
+    <function name='xmlBufferCreate' file='tree' module='buf'>
       <info>routine to create an XML buffer.</info>
       <return type='xmlBufferPtr' info='the new structure.'/>
     </function>
-    <function name='xmlBufferCreateSize' file='tree' module='tree'>
+    <function name='xmlBufferCreateSize' file='tree' module='buf'>
       <info>routine to create an XML buffer.</info>
       <return type='xmlBufferPtr' info='the new structure.'/>
       <arg name='size' type='size_t' info='initial size of buffer'/>
     </function>
-    <function name='xmlBufferCreateStatic' file='tree' module='tree'>
+    <function name='xmlBufferCreateStatic' file='tree' module='buf'>
       <info></info>
       <return type='xmlBufferPtr' info='an XML buffer initialized with bytes.'/>
       <arg name='mem' type='void *' info='the memory area'/>
       <arg name='size' type='size_t' info='the size in byte'/>
     </function>
-    <function name='xmlBufferDetach' file='tree' module='tree'>
+    <function name='xmlBufferDetach' file='tree' module='buf'>
       <info>Remove the string contained in a buffer and gie it back to the caller. The buffer is reset to an empty content. This doesn&apos;t work with immutable buffers as they can&apos;t be reset.</info>
       <return type='xmlChar *' info='the previous string contained by the buffer.'/>
       <arg name='buf' type='xmlBufferPtr' info='the buffer'/>
     </function>
-    <function name='xmlBufferDump' file='tree' module='tree'>
+    <function name='xmlBufferDump' file='tree' module='buf'>
       <info>Dumps an XML buffer to  a FILE *.</info>
       <return type='int' info='the number of #xmlChar written'/>
       <arg name='file' type='FILE *' info='the file output'/>
       <arg name='buf' type='xmlBufferPtr' info='the buffer to dump'/>
     </function>
-    <function name='xmlBufferEmpty' file='tree' module='tree'>
+    <function name='xmlBufferEmpty' file='tree' module='buf'>
       <info>empty a buffer.</info>
       <return type='void'/>
       <arg name='buf' type='xmlBufferPtr' info='the buffer'/>
     </function>
-    <function name='xmlBufferFree' file='tree' module='tree'>
+    <function name='xmlBufferFree' file='tree' module='buf'>
       <info>Frees an XML buffer. It frees both the content and the structure which encapsulate it.</info>
       <return type='void'/>
       <arg name='buf' type='xmlBufferPtr' info='the buffer to free'/>
     </function>
-    <function name='xmlBufferGrow' file='tree' module='tree'>
-      <info>Grow the available space of an XML buffer.</info>
+    <function name='xmlBufferGrow' file='tree' module='buf'>
+      <info>DEPRECATED: Don&apos;t use.  Grow the available space of an XML buffer.</info>
       <return type='int' info='the new available space or -1 in case of error'/>
       <arg name='buf' type='xmlBufferPtr' info='the buffer'/>
       <arg name='len' type='unsigned int' info='the minimum free size to allocate'/>
     </function>
-    <function name='xmlBufferLength' file='tree' module='tree'>
+    <function name='xmlBufferLength' file='tree' module='buf'>
       <info>Function to get the length of a buffer</info>
       <return type='int' info='the length of data in the internal content'/>
       <arg name='buf' type='const xmlBuffer *' info='the buffer'/>
     </function>
-    <function name='xmlBufferResize' file='tree' module='tree'>
-      <info>Resize a buffer to accommodate minimum size of @size.</info>
+    <function name='xmlBufferResize' file='tree' module='buf'>
+      <info>DEPRECATED: Don&apos;t use. Resize a buffer to accommodate minimum size of @size.</info>
       <return type='int' info='0 in case of problems, 1 otherwise'/>
       <arg name='buf' type='xmlBufferPtr' info='the buffer to resize'/>
       <arg name='size' type='unsigned int' info='the desired size'/>
     </function>
-    <function name='xmlBufferSetAllocationScheme' file='tree' module='tree'>
-      <info>Sets the allocation scheme for this buffer</info>
+    <function name='xmlBufferSetAllocationScheme' file='tree' module='buf'>
+      <info>Sets the allocation scheme for this buffer.  For libxml2 before 2.14, it is recommended to set this to XML_BUFFER_ALLOC_DOUBLE_IT. Has no effect on 2.14 or later.</info>
       <return type='void'/>
       <arg name='buf' type='xmlBufferPtr' info='the buffer to tune'/>
       <arg name='scheme' type='xmlBufferAllocationScheme' info='allocation scheme to use'/>
     </function>
-    <function name='xmlBufferShrink' file='tree' module='tree'>
-      <info>Remove the beginning of an XML buffer.</info>
+    <function name='xmlBufferShrink' file='tree' module='buf'>
+      <info>DEPRECATED: Don&apos;t use.  Remove the beginning of an XML buffer.</info>
       <return type='int' info='the number of #xmlChar removed, or -1 in case of failure.'/>
       <arg name='buf' type='xmlBufferPtr' info='the buffer to dump'/>
       <arg name='len' type='unsigned int' info='the number of xmlChar to remove'/>
     </function>
-    <function name='xmlBufferWriteCHAR' file='tree' module='tree'>
+    <function name='xmlBufferWriteCHAR' file='tree' module='buf'>
       <info>routine which manages and grows an output buffer. This one adds xmlChars at the end of the buffer.</info>
       <return type='void'/>
       <arg name='buf' type='xmlBufferPtr' info='the XML buffer'/>
       <arg name='string' type='const xmlChar *' info='the string to add'/>
     </function>
-    <function name='xmlBufferWriteChar' file='tree' module='tree'>
+    <function name='xmlBufferWriteChar' file='tree' module='buf'>
       <info>routine which manage and grows an output buffer. This one add C chars at the end of the array.</info>
       <return type='void'/>
       <arg name='buf' type='xmlBufferPtr' info='the XML buffer output'/>
       <arg name='string' type='const char *' info='the string to add'/>
     </function>
-    <function name='xmlBufferWriteQuotedString' file='tree' module='tree'>
+    <function name='xmlBufferWriteQuotedString' file='tree' module='buf'>
       <info>routine which manage and grows an output buffer. This one writes a quoted or double quoted #xmlChar string, checking first if it holds quote or double-quotes internally</info>
       <return type='void'/>
       <arg name='buf' type='xmlBufferPtr' info='the XML buffer output'/>
@@ -8141,7 +8080,7 @@ crash if you try to modify the tree)'/>
       <arg name='valPtr' type='xmlChar **' info='pointer to result URI'/>
     </function>
     <function name='xmlByteConsumed' file='parser' module='encoding'>
-      <info>This function provides the current index of the parser relative to the start of the current entity. This function is computed in bytes from the beginning starting at zero and finishing at the size in byte of the file if parsing a file. The function is of constant cost if the input is UTF-8 but can be costly if run on non-UTF-8 input.</info>
+      <info>DEPRECATED: Don&apos;t use.  This function provides the current index of the parser relative to the start of the current entity. This function is computed in bytes from the beginning starting at zero and finishing at the size in byte of the file if parsing a file. The function is of constant cost if the input is UTF-8 but can be costly if run on non-UTF-8 input.</info>
       <return type='long' info='the index in bytes from the beginning of the entity or -1 in case the index could not be computed.'/>
       <arg name='ctxt' type='xmlParserCtxtPtr' info='an XML parser context'/>
     </function>
@@ -8426,7 +8365,7 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='xmlCheckThreadLocalStorage' file='threads' module='globals'>
       <info>Check whether thread-local storage could be allocated.  In cross-platform code running in multithreaded environments, this function should be called once in each thread before calling other library functions to make sure that thread-local storage was allocated properly.</info>
-      <return type='int' info='0 on success or -1 if a memory allocation failed. A failed allocation signals a typically fatal and irrecoverable out-of-memory situation. Don&apos;t call any library functions in this case.  This function never fails if the library is compiled with support for thread-local storage.  This function never fails for the &quot;main&quot; thread which is the first thread calling xmlInitParser.  Available since v2.12.0.'/>
+      <return type='int' info='0 on success or -1 if a memory allocation failed. A failed allocation signals a typically fatal and irrecoverable out-of-memory situation. Don&apos;t call any library functions in this case.  Available since 2.12.0.'/>
     </function>
     <function name='xmlCheckUTF8' file='xmlstring' module='xmlstring'>
       <info>Checks @utf for being valid UTF-8. @utf is assumed to be null-terminated. This function is not super-strict, as it will allow longer UTF-8 sequences than necessary. Note that Java is capable of producing these sequences if provoked. Also note, this routine checks for the 4-byte maximum size, but does not check for 0x10ffff maximum value.</info>
@@ -8464,7 +8403,7 @@ crash if you try to modify the tree)'/>
       <return type='void'/>
     </function>
     <function name='xmlCleanupParser' file='parser' module='threads'>
-      <info>This function name is somewhat misleading. It does not clean up parser state, it cleans up memory allocated by the library itself. It is a cleanup function for the XML library. It tries to reclaim all related global memory allocated for the library processing. It doesn&apos;t deallocate any document related memory. One should call xmlCleanupParser() only when the process has finished using the library and all XML/HTML documents built with it. See also xmlInitParser() which has the opposite function of preparing the library for operations.  WARNING: if your application is multithreaded or has plugin support calling this may crash the application if another thread or a plugin is still using libxml2. It&apos;s sometimes very hard to guess if libxml2 is in use in the application, some libraries or plugins may use it without notice. In case of doubt abstain from calling this function or do it just before calling exit() to avoid leak reports from valgrind !</info>
+      <info>This function is named somewhat misleadingly. It does not clean up parser state but global memory allocated by the library itself.  Since 2.9.11, cleanup is performed automatically if a shared or dynamic libxml2 library is unloaded. This function should only be used to avoid false positives from memory leak checkers in static builds.  WARNING: xmlCleanupParser assumes that all other threads that called libxml2 functions have terminated. No library calls must be made after calling this function. In general, THIS FUNCTION SHOULD ONLY BE CALLED RIGHT BEFORE THE WHOLE PROCESS EXITS.</info>
       <return type='void'/>
     </function>
     <function name='xmlCleanupThreads' file='threads' module='threads'>
@@ -8488,7 +8427,7 @@ crash if you try to modify the tree)'/>
       <arg name='catal' type='xmlCatalogPtr' info='the catalog'/>
     </function>
     <function name='xmlCopyAttributeTable' file='valid' module='valid'>
-      <info>Build a copy of an attribute table.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Build a copy of an attribute table.</info>
       <return type='xmlAttributeTablePtr' info='the new xmlAttributeTablePtr or NULL in case of error.'/>
       <arg name='table' type='xmlAttributeTablePtr' info='An attribute table'/>
     </function>
@@ -8500,7 +8439,7 @@ crash if you try to modify the tree)'/>
       <arg name='val' type='int' info='the char value'/>
     </function>
     <function name='xmlCopyCharMultiByte' file='parserInternals' module='parserInternals'>
-      <info>append the char value in the array</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  append the char value in the array</info>
       <return type='int' info='the number of xmlChar written'/>
       <arg name='out' type='xmlChar *' info='pointer to an array of xmlChar'/>
       <arg name='val' type='int' info='the char value'/>
@@ -8512,7 +8451,7 @@ crash if you try to modify the tree)'/>
       <arg name='recursive' type='int' info='if not zero do a recursive copy.'/>
     </function>
     <function name='xmlCopyDocElementContent' file='valid' module='valid'>
-      <info>Build a copy of an element content description.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Build a copy of an element content description.</info>
       <return type='xmlElementContentPtr' info='the new xmlElementContentPtr or NULL in case of error.'/>
       <arg name='doc' type='xmlDocPtr' info='the document owning the element declaration'/>
       <arg name='cur' type='xmlElementContentPtr' info='An element content pointer.'/>
@@ -8523,12 +8462,12 @@ crash if you try to modify the tree)'/>
       <arg name='dtd' type='xmlDtdPtr' info='the DTD'/>
     </function>
     <function name='xmlCopyElementContent' file='valid' module='valid'>
-      <info>Build a copy of an element content description. Deprecated, use xmlCopyDocElementContent instead</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Build a copy of an element content description. Deprecated, use xmlCopyDocElementContent instead</info>
       <return type='xmlElementContentPtr' info='the new xmlElementContentPtr or NULL in case of error.'/>
       <arg name='cur' type='xmlElementContentPtr' info='An element content pointer.'/>
     </function>
     <function name='xmlCopyElementTable' file='valid' module='valid'>
-      <info>Build a copy of an element table.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Build a copy of an element table.</info>
       <return type='xmlElementTablePtr' info='the new xmlElementTablePtr or NULL in case of error.'/>
       <arg name='table' type='xmlElementTablePtr' info='An element table'/>
     </function>
@@ -8538,7 +8477,7 @@ crash if you try to modify the tree)'/>
       <arg name='table' type='xmlEntitiesTablePtr' info='An entity table'/>
     </function>
     <function name='xmlCopyEnumeration' file='valid' module='valid'>
-      <info>Copy an enumeration attribute node (recursive).</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Copy an enumeration attribute node (recursive).</info>
       <return type='xmlEnumerationPtr' info='the xmlEnumerationPtr just created or NULL in case of error.'/>
       <arg name='cur' type='xmlEnumerationPtr' info='the tree to copy.'/>
     </function>
@@ -8570,7 +8509,7 @@ crash if you try to modify the tree)'/>
       <arg name='node' type='xmlNodePtr' info='the first node in the list.'/>
     </function>
     <function name='xmlCopyNotationTable' file='valid' module='valid'>
-      <info>Build a copy of a notation table.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Build a copy of a notation table.</info>
       <return type='xmlNotationTablePtr' info='the new xmlNotationTablePtr or NULL in case of error.'/>
       <arg name='table' type='xmlNotationTablePtr' info='A notation table'/>
     </function>
@@ -8612,7 +8551,7 @@ crash if you try to modify the tree)'/>
       <arg name='base' type='const xmlChar *' info='a possible base for the target URI'/>
     </function>
     <function name='xmlCreateEnumeration' file='valid' module='valid'>
-      <info>create and initialize an enumeration attribute node.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  create and initialize an enumeration attribute node.</info>
       <return type='xmlEnumerationPtr' info='the xmlEnumerationPtr just created or NULL in case of error.'/>
       <arg name='name' type='const xmlChar *' info='the enumeration name or NULL'/>
     </function>
@@ -8671,19 +8610,19 @@ crash if you try to modify the tree)'/>
       <arg name='ctxt' type='xmlParserCtxtPtr' info='an XML parser context'/>
     </function>
     <function name='xmlCtxtGetCatalogs' file='parser' module='parserInternals'>
-      <info>ctxt:  parser context  Available since 2.14.0.</info>
+      <info>Available since 2.14.0.</info>
       <return type='void *' info='the local catalogs.'/>
-      <arg name='ctxt' type='xmlParserCtxtPtr' info=''/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='parser context'/>
     </function>
     <function name='xmlCtxtGetDeclaredEncoding' file='parser' module='parserInternals'>
-      <info>ctxt:  parser context  Available since 2.14.0.</info>
+      <info>Available since 2.14.0.</info>
       <return type='const xmlChar *' info='the encoding from the encoding declaration. This can differ from the actual encoding.'/>
-      <arg name='ctxt' type='xmlParserCtxtPtr' info=''/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='parser context'/>
     </function>
     <function name='xmlCtxtGetDict' file='parser' module='parserInternals'>
-      <info>ctxt:  parser context  Available since 2.14.0.</info>
+      <info>Available since 2.14.0.</info>
       <return type='xmlDictPtr' info='the dictionary.'/>
-      <arg name='ctxt' type='xmlParserCtxtPtr' info=''/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='parser context'/>
     </function>
     <function name='xmlCtxtGetLastError' file='xmlerror' module='parserInternals'>
       <info>Get the last parsing error registered.</info>
@@ -8696,14 +8635,14 @@ crash if you try to modify the tree)'/>
       <arg name='ctxt' type='xmlParserCtxtPtr' info='an XML parser context'/>
     </function>
     <function name='xmlCtxtGetPrivate' file='parser' module='parserInternals'>
-      <info>ctxt:  parser context  Available since 2.14.0.</info>
+      <info>Available since 2.14.0.</info>
       <return type='void *' info='the private application data.'/>
-      <arg name='ctxt' type='xmlParserCtxtPtr' info=''/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='parser context'/>
     </function>
     <function name='xmlCtxtGetStandalone' file='parser' module='parser'>
-      <info>ctxt:  parser context  Available since 2.14.0.</info>
+      <info>Available since 2.14.0.</info>
       <return type='int' info='the value from the standalone document declaration.'/>
-      <arg name='ctxt' type='xmlParserCtxtPtr' info=''/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='parser context'/>
     </function>
     <function name='xmlCtxtGetStatus' file='parser' module='parserInternals'>
       <info>Get well-formedness and validation status after parsing. Also reports catastrophic errors which are not related to parsing like out-of-memory, I/O or other errors.  Available since 2.14.0.</info>
@@ -8711,9 +8650,9 @@ crash if you try to modify the tree)'/>
       <arg name='ctxt' type='xmlParserCtxt *' info='an XML parser context'/>
     </function>
     <function name='xmlCtxtGetVersion' file='parser' module='parser'>
-      <info>ctxt:  parser context  Available since 2.14.0.</info>
+      <info>Available since 2.14.0.</info>
       <return type='const xmlChar *' info='the version from the XML declaration.'/>
-      <arg name='ctxt' type='xmlParserCtxtPtr' info=''/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='parser context'/>
     </function>
     <function name='xmlCtxtParseContent' file='parser' module='parser'>
       <info>Parse a well-balanced chunk of XML matching the &apos;content&apos; production.  Namespaces in scope of @node and entities of @node&apos;s document are recognized. When validating, the DTD of @node&apos;s document is used.  Always consumes @input even in error case.  Available since 2.14.0.</info>
@@ -8729,6 +8668,26 @@ crash if you try to modify the tree)'/>
       <arg name='ctxt' type='xmlParserCtxtPtr' info='an XML parser context'/>
       <arg name='input' type='xmlParserInputPtr' info='parser input'/>
     </function>
+    <function name='xmlCtxtParseDtd' file='parser' module='parser'>
+      <cond>defined(LIBXML_VALID_ENABLED)</cond>
+      <info>Parse a DTD.  Option XML_PARSE_DTDLOAD should be enabled in the parser context to make external entities work.  Availabe since 2.14.0.</info>
+      <return type='xmlDtdPtr' info='the resulting xmlDtdPtr or NULL in case of error. @input will be freed by the function in any case.'/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='a parser context'/>
+      <arg name='input' type='xmlParserInputPtr' info='a parser input'/>
+      <arg name='publicId' type='const xmlChar *' info='public ID of the DTD (optional)'/>
+      <arg name='systemId' type='const xmlChar *' info='system ID of the DTD (optional)'/>
+    </function>
+    <function name='xmlCtxtPopInput' file='parserInternals' module='parser'>
+      <info>Pops the top parser input from the input stack</info>
+      <return type='xmlParserInputPtr' info='the input just removed'/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='an XML parser context'/>
+    </function>
+    <function name='xmlCtxtPushInput' file='parserInternals' module='parser'>
+      <info>Pushes a new parser input on top of the input stack</info>
+      <return type='int' info='-1 in case of error, the index in the stack otherwise'/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='an XML parser context'/>
+      <arg name='value' type='xmlParserInputPtr' info='the parser input'/>
+    </function>
     <function name='xmlCtxtReadDoc' file='parser' module='parser'>
       <info>Parse an XML in-memory document and build a tree.  @URL is used as base to resolve external entities and for error reporting.  See xmlCtxtUseOptions for details.</info>
       <return type='xmlDocPtr' info='the resulting document tree'/>
@@ -8796,10 +8755,10 @@ crash if you try to modify the tree)'/>
       <arg name='encoding' type='const char *' info='the document encoding, or NULL'/>
     </function>
     <function name='xmlCtxtSetCatalogs' file='parser' module='parserInternals'>
-      <info>ctxt:  parser context catalogs:  catalogs pointer  Available since 2.14.0.  Set the local catalogs.</info>
+      <info>Available since 2.14.0.  Set the local catalogs.</info>
       <return type='void'/>
-      <arg name='ctxt' type='xmlParserCtxtPtr' info=''/>
-      <arg name='catalogs' type='void *' info=''/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='parser context'/>
+      <arg name='catalogs' type='void *' info='catalogs pointer'/>
     </function>
     <function name='xmlCtxtSetCharEncConvImpl' file='parser' module='parserInternals'>
       <info>Installs a custom implementation to convert between character encodings.  This bypasses legacy feature like global encoding handlers or encoding aliases.  Available since 2.14.0.</info>
@@ -8809,10 +8768,10 @@ crash if you try to modify the tree)'/>
       <arg name='vctxt' type='void *' info='user data'/>
     </function>
     <function name='xmlCtxtSetDict' file='parser' module='parserInternals'>
-      <info>ctxt:  parser context dict:  dictionary  Available since 2.14.0.  Set the dictionary. This should only be done immediately after creating a parser context.</info>
+      <info>Available since 2.14.0.  Set the dictionary. This should only be done immediately after creating a parser context.</info>
       <return type='void'/>
-      <arg name='ctxt' type='xmlParserCtxtPtr' info=''/>
-      <arg name='dict' type='xmlDictPtr' info=''/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='parser context'/>
+      <arg name='dict' type='xmlDictPtr' info='dictionary'/>
     </function>
     <function name='xmlCtxtSetErrorHandler' file='parser' module='parserInternals'>
       <info>Register a callback function that will be called on errors and warnings. If handler is NULL, the error handler will be deactivated.  This is the recommended way to collect errors from the parser and takes precedence over all other error reporting mechanisms. These are (in order of precedence):  - per-context structured handler (xmlCtxtSetErrorHandler) - per-context structured &quot;serror&quot; SAX handler - global structured handler (xmlSetStructuredErrorFunc) - per-context generic &quot;error&quot; and &quot;warning&quot; SAX handlers - global generic handler (xmlSetGenericErrorFunc) - print to stderr  Available since 2.13.0.</info>
@@ -8828,16 +8787,16 @@ crash if you try to modify the tree)'/>
       <arg name='maxAmpl' type='unsigned' info='maximum amplification factor'/>
     </function>
     <function name='xmlCtxtSetOptions' file='parser' module='parser'>
-      <info>Applies the options to the parser context. Unset options are cleared.  Available since 2.13.0. With older versions, you can use xmlCtxtUseOptions.  XML_PARSE_RECOVER  Enable &quot;recovery&quot; mode which allows non-wellformed documents. How this mode behaves exactly is unspecified and may change without further notice. Use of this feature is DISCOURAGED.  XML_PARSE_NOENT  Despite the confusing name, this option enables substitution of entities. The resulting tree won&apos;t contain any entity reference nodes.  This option also enables loading of external entities (both general and parameter entities) which is dangerous. If you process untrusted data, it&apos;s recommended to set the XML_PARSE_NO_XXE option to disable loading of external entities.  XML_PARSE_DTDLOAD  Enables loading of an external DTD and the loading and substitution of external parameter entities. Has no effect if XML_PARSE_NO_XXE is set.  XML_PARSE_DTDATTR  Adds default attributes from the DTD to the result document.  Implies XML_PARSE_DTDLOAD, but loading of external content can be disabled with XML_PARSE_NO_XXE.  XML_PARSE_DTDVALID  This option enables DTD validation which requires to load external DTDs and external entities (both general and parameter entities) unless XML_PARSE_NO_XXE was set.  XML_PARSE_NO_XXE  Disables loading of external DTDs or entities.  XML_PARSE_NOERROR  Disable error and warning reports to the error handlers. Errors are still accessible with xmlCtxtGetLastError.  XML_PARSE_NOWARNING  Disable warning reports.  XML_PARSE_PEDANTIC  Enable some pedantic warnings.  XML_PARSE_NOBLANKS  Remove some text nodes containing only whitespace from the result document. Which nodes are removed depends on DTD element declarations or a conservative heuristic. The reindenting feature of the serialization code relies on this option to be set when parsing. Use of this option is DISCOURAGED.  XML_PARSE_SAX1  Always invoke the deprecated SAX1 startElement and endElement handlers. This option is DEPRECATED.  XML_PARSE_NONET  Disable network access with the builtin HTTP client.  XML_PARSE_NODICT  Create a document without interned strings, making all strings separate memory allocations.  XML_PARSE_NSCLEAN  Remove redundant namespace declarations from the result document.  XML_PARSE_NOCDATA  Output normal text nodes instead of CDATA nodes.  XML_PARSE_COMPACT  Store small strings directly in the node struct to save memory.  XML_PARSE_OLD10  Use old Name productions from before XML 1.0 Fifth Edition. This options is DEPRECATED.  XML_PARSE_HUGE  Relax some internal limits.  Maximum size of text nodes, tags, comments, processing instructions, CDATA sections, entity values  normal: 10M huge:    1B  Maximum size of names, system literals, pubid literals  normal: 50K huge:   10M  Maximum nesting depth of elements  normal:  256 huge:   2048  Maximum nesting depth of entities  normal: 20 huge:   40  XML_PARSE_OLDSAX  Enable an unspecified legacy mode for SAX parsers. This option is DEPRECATED.  XML_PARSE_IGNORE_ENC  Ignore the encoding in the XML declaration. This option is mostly unneeded these days. The only effect is to enforce UTF-8 decoding of ASCII-like data.  XML_PARSE_BIG_LINES  Enable reporting of line numbers larger than 65535.  XML_PARSE_NO_UNZIP  Disables input decompression. Setting this option is recommended to avoid zip bombs.  Available since 2.14.0.  XML_PARSE_NO_SYS_CATALOG  Disables the global system XML catalog.  Available since 2.14.0.  XML_PARSE_NO_CATALOG_PI  Ignore XML catalog processing instructions.  Available since 2.14.0.</info>
+      <info>Applies the options to the parser context. Unset options are cleared.  Available since 2.13.0. With older versions, you can use xmlCtxtUseOptions.  XML_PARSE_RECOVER  Enable &quot;recovery&quot; mode which allows non-wellformed documents. How this mode behaves exactly is unspecified and may change without further notice. Use of this feature is DISCOURAGED.  XML_PARSE_NOENT  Despite the confusing name, this option enables substitution of entities. The resulting tree won&apos;t contain any entity reference nodes.  This option also enables loading of external entities (both general and parameter entities) which is dangerous. If you process untrusted data, it&apos;s recommended to set the XML_PARSE_NO_XXE option to disable loading of external entities.  XML_PARSE_DTDLOAD  Enables loading of an external DTD and the loading and substitution of external parameter entities. Has no effect if XML_PARSE_NO_XXE is set.  XML_PARSE_DTDATTR  Adds default attributes from the DTD to the result document.  Implies XML_PARSE_DTDLOAD, but loading of external content can be disabled with XML_PARSE_NO_XXE.  XML_PARSE_DTDVALID  This option enables DTD validation which requires to load external DTDs and external entities (both general and parameter entities) unless XML_PARSE_NO_XXE was set.  XML_PARSE_NO_XXE  Disables loading of external DTDs or entities.  Available since 2.13.0.  XML_PARSE_NOERROR  Disable error and warning reports to the error handlers. Errors are still accessible with xmlCtxtGetLastError.  XML_PARSE_NOWARNING  Disable warning reports.  XML_PARSE_PEDANTIC  Enable some pedantic warnings.  XML_PARSE_NOBLANKS  Remove some text nodes containing only whitespace from the result document. Which nodes are removed depends on DTD element declarations or a conservative heuristic. The reindenting feature of the serialization code relies on this option to be set when parsing. Use of this option is DISCOURAGED.  XML_PARSE_SAX1  Always invoke the deprecated SAX1 startElement and endElement handlers. This option is DEPRECATED.  XML_PARSE_NONET  Disable network access with the builtin HTTP client.  XML_PARSE_NODICT  Create a document without interned strings, making all strings separate memory allocations.  XML_PARSE_NSCLEAN  Remove redundant namespace declarations from the result document.  XML_PARSE_NOCDATA  Output normal text nodes instead of CDATA nodes.  XML_PARSE_COMPACT  Store small strings directly in the node struct to save memory.  XML_PARSE_OLD10  Use old Name productions from before XML 1.0 Fifth Edition. This options is DEPRECATED.  XML_PARSE_HUGE  Relax some internal limits.  Maximum size of text nodes, tags, comments, processing instructions, CDATA sections, entity values  normal: 10M huge:    1B  Maximum size of names, system literals, pubid literals  normal: 50K huge:   10M  Maximum nesting depth of elements  normal:  256 huge:   2048  Maximum nesting depth of entities  normal: 20 huge:   40  XML_PARSE_OLDSAX  Enable an unspecified legacy mode for SAX parsers. This option is DEPRECATED.  XML_PARSE_IGNORE_ENC  Ignore the encoding in the XML declaration. This option is mostly unneeded these days. The only effect is to enforce UTF-8 decoding of ASCII-like data.  XML_PARSE_BIG_LINES  Enable reporting of line numbers larger than 65535.  XML_PARSE_NO_UNZIP  Disables input decompression. Setting this option is recommended to avoid zip bombs.  Available since 2.14.0.  XML_PARSE_NO_SYS_CATALOG  Disables the global system XML catalog.  Available since 2.14.0.  XML_PARSE_NO_CATALOG_PI  Ignore XML catalog processing instructions.  Available since 2.14.0.</info>
       <return type='int' info='0 in case of success, the set of unknown or unimplemented options in case of error.'/>
       <arg name='ctxt' type='xmlParserCtxtPtr' info='an XML parser context'/>
       <arg name='options' type='int' info='a bitmask of xmlParserOption values'/>
     </function>
     <function name='xmlCtxtSetPrivate' file='parser' module='parserInternals'>
-      <info>ctxt:  parser context priv:  private application data  Available since 2.14.0.  Set the private application data.</info>
+      <info>Available since 2.14.0.  Set the private application data.</info>
       <return type='void'/>
-      <arg name='ctxt' type='xmlParserCtxtPtr' info=''/>
-      <arg name='priv' type='void *' info=''/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='parser context'/>
+      <arg name='priv' type='void *' info='private application data'/>
     </function>
     <function name='xmlCtxtSetResourceLoader' file='parser' module='parserInternals'>
       <info>Installs a custom callback to load documents, DTDs or external entities.  Available since 2.14.0.</info>
@@ -8852,6 +8811,21 @@ crash if you try to modify the tree)'/>
       <arg name='ctxt' type='xmlParserCtxtPtr' info='an XML parser context'/>
       <arg name='options' type='int' info='a combination of xmlParserOption'/>
     </function>
+    <function name='xmlCtxtValidateDocument' file='parser' module='valid'>
+      <cond>defined(LIBXML_VALID_ENABLED)</cond>
+      <info>Validate a document.  Like xmlValidateDocument but uses the parser context&apos;s error handler.  Option XML_PARSE_DTDLOAD should be enabled in the parser context to make external entities work.  Availabe since 2.14.0.</info>
+      <return type='int' info='1 if valid or 0 otherwise.'/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='a parser context'/>
+      <arg name='doc' type='xmlDocPtr' info='a document instance'/>
+    </function>
+    <function name='xmlCtxtValidateDtd' file='parser' module='valid'>
+      <cond>defined(LIBXML_VALID_ENABLED)</cond>
+      <info>Validate a document against a DTD.  Like xmlValidateDtd but uses the parser context&apos;s error handler.  Availabe since 2.14.0.</info>
+      <return type='int' info='1 if valid or 0 otherwise.'/>
+      <arg name='ctxt' type='xmlParserCtxtPtr' info='a parser context'/>
+      <arg name='doc' type='xmlDocPtr' info='a document instance'/>
+      <arg name='dtd' type='xmlDtdPtr' info='a dtd instance'/>
+    </function>
     <function name='xmlCurrentChar' file='parserInternals' module='parserInternals'>
       <info>DEPRECATED: Internal function, do not use.  The current char value, if using UTF-8 this may actually span multiple bytes in the input buffer. Implement the end of line normalization: 2.11 End-of-Line Handling Wherever an external parsed entity or the literal entity value of an internal parsed entity contains either the literal two-character sequence &quot;#xD#xA&quot; or a standalone literal #xD, an XML processor must pass to the application the single character #xA. This behavior can conveniently be produced by normalizing all line breaks to #xA on input, before parsing.)</info>
       <return type='int' info='the current char value and its length'/>
@@ -9225,15 +9199,15 @@ crash if you try to modify the tree)'/>
       <arg name='cur' type='xmlNodePtr' info='the current node'/>
     </function>
     <function name='xmlEncodeEntitiesReentrant' file='entities' module='entities'>
-      <info>Do a global encoding of a string, replacing the predefined entities and non ASCII values with their entities and CharRef counterparts. Contrary to xmlEncodeEntities, this routine is reentrant, and result must be deallocated.</info>
+      <info>Do a global encoding of a string, replacing the predefined entities and non ASCII values with their entities and CharRef counterparts. Contrary to xmlEncodeEntities, this routine is reentrant, and result must be deallocated.  This escapes &apos;&lt;&apos;, &apos;&gt;&apos;, &apos;&amp;&apos; and &apos;\r&apos;. If the document has no encoding, non-ASCII codepoints are escaped. There is some special handling for HTML documents.</info>
       <return type='xmlChar *' info='A newly allocated string with the substitution done.'/>
       <arg name='doc' type='xmlDocPtr' info='the document containing the string'/>
       <arg name='input' type='const xmlChar *' info='A string to convert to XML.'/>
     </function>
     <function name='xmlEncodeSpecialChars' file='entities' module='entities'>
-      <info>Do a global encoding of a string, replacing the predefined entities this routine is reentrant, and result must be deallocated.</info>
+      <info>Do a global encoding of a string, replacing the predefined entities this routine is reentrant, and result must be deallocated.  This escapes &apos;&lt;&apos;, &apos;&gt;&apos;, &apos;&amp;&apos;, &apos;&quot;&apos; and &apos;\r&apos; chars.</info>
       <return type='xmlChar *' info='A newly allocated string with the substitution done.'/>
-      <arg name='doc' type='const xmlDoc *' info='the document containing the string'/>
+      <arg name='doc' type='const xmlDoc *' info='unused'/>
       <arg name='input' type='const xmlChar *' info='A string to convert to XML.'/>
     </function>
     <functype name='xmlExternalEntityLoader' file='parser' module='parser'>
@@ -9283,7 +9257,7 @@ crash if you try to modify the tree)'/>
       <arg name='data' type='void *' info='user data for callback'/>
     </function>
     <function name='xmlFreeAttributeTable' file='valid' module='valid'>
-      <info>Deallocate the memory used by an entities hash table.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Deallocate the memory used by an entities hash table.</info>
       <return type='void'/>
       <arg name='table' type='xmlAttributeTablePtr' info='An attribute table'/>
     </function>
@@ -9305,7 +9279,7 @@ crash if you try to modify the tree)'/>
       <arg name='cur' type='xmlDocPtr' info='pointer to the document'/>
     </function>
     <function name='xmlFreeDocElementContent' file='valid' module='valid'>
-      <info>Free an element content structure. The whole subtree is removed.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Free an element content structure. The whole subtree is removed.</info>
       <return type='void'/>
       <arg name='doc' type='xmlDocPtr' info='the document owning the element declaration'/>
       <arg name='cur' type='xmlElementContentPtr' info='the element content tree to free'/>
@@ -9316,12 +9290,12 @@ crash if you try to modify the tree)'/>
       <arg name='cur' type='xmlDtdPtr' info='the DTD structure to free up'/>
     </function>
     <function name='xmlFreeElementContent' file='valid' module='valid'>
-      <info>Free an element content structure. The whole subtree is removed. Deprecated, use xmlFreeDocElementContent instead</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Free an element content structure. The whole subtree is removed. Deprecated, use xmlFreeDocElementContent instead</info>
       <return type='void'/>
       <arg name='cur' type='xmlElementContentPtr' info='the element content tree to free'/>
     </function>
     <function name='xmlFreeElementTable' file='valid' module='valid'>
-      <info>Deallocate the memory used by an element hash table.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Deallocate the memory used by an element hash table.</info>
       <return type='void'/>
       <arg name='table' type='xmlElementTablePtr' info='An element table'/>
     </function>
@@ -9371,7 +9345,7 @@ crash if you try to modify the tree)'/>
       <arg name='cur' type='xmlNodePtr' info='the first node in the list'/>
     </function>
     <function name='xmlFreeNotationTable' file='valid' module='valid'>
-      <info>Deallocate the memory used by an entities hash table.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Deallocate the memory used by an entities hash table.</info>
       <return type='void'/>
       <arg name='table' type='xmlNotationTablePtr' info='An notation table'/>
     </function>
@@ -9457,7 +9431,7 @@ crash if you try to modify the tree)'/>
       <arg name='cur' type='xmlValidCtxtPtr' info='the validation context to free'/>
     </function>
     <function name='xmlGcMemGet' file='xmlmemory' module='xmlmemory'>
-      <info>Provides the memory access functions set currently in use The mallocAtomicFunc is specialized for atomic block allocations (i.e. of areas  useful for garbage collected memory allocators</info>
+      <info>DEPRECATED: xmlMemGet.  Provides the memory access functions set currently in use The mallocAtomicFunc is specialized for atomic block allocations (i.e. of areas  useful for garbage collected memory allocators</info>
       <return type='int' info='0 on success'/>
       <arg name='freeFunc' type='xmlFreeFunc *' info='place to save the free() function in use'/>
       <arg name='mallocFunc' type='xmlMallocFunc *' info='place to save the malloc() function in use'/>
@@ -9466,7 +9440,7 @@ crash if you try to modify the tree)'/>
       <arg name='strdupFunc' type='xmlStrdupFunc *' info='place to save the strdup() function in use'/>
     </function>
     <function name='xmlGcMemSetup' file='xmlmemory' module='xmlmemory'>
-      <info>Override the default memory access functions with a new set This has to be called before any other libxml routines ! The mallocAtomicFunc is specialized for atomic block allocations (i.e. of areas  useful for garbage collected memory allocators  Should this be blocked if there was already some allocations done ?</info>
+      <info>DEPRECATED: Use xmlMemSetup.  Override the default memory access functions with a new set This has to be called before any other libxml routines ! The mallocAtomicFunc is specialized for atomic block allocations (i.e. of areas  useful for garbage collected memory allocators  Should this be blocked if there was already some allocations done ?</info>
       <return type='int' info='0 on success'/>
       <arg name='freeFunc' type='xmlFreeFunc' info='the free() function to use'/>
       <arg name='mallocFunc' type='xmlMallocFunc' info='the malloc() function to use'/>
@@ -9481,8 +9455,8 @@ crash if you try to modify the tree)'/>
       <arg name='msg' type='const char *' info='the message'/>
       <arg name='...' type='...' info='the extra arguments of the varargs to format the message'/>
     </functype>
-    <function name='xmlGetBufferAllocationScheme' file='tree' module='tree'>
-      <info>Types are XML_BUFFER_ALLOC_EXACT - use exact sizes, keeps memory usage down XML_BUFFER_ALLOC_DOUBLEIT - double buffer when extra needed, improves performance XML_BUFFER_ALLOC_HYBRID - use exact sizes on small strings to keep memory usage tight in normal usage, and doubleit on large strings to avoid pathological performance.</info>
+    <function name='xmlGetBufferAllocationScheme' file='tree' module='buf'>
+      <info>DEPRECATED: Use xmlBufferSetAllocationScheme.  Types are XML_BUFFER_ALLOC_EXACT - use exact sizes, keeps memory usage down XML_BUFFER_ALLOC_DOUBLEIT - double buffer when extra needed, improves performance XML_BUFFER_ALLOC_HYBRID - use exact sizes on small strings to keep memory usage tight in normal usage, and doubleit on large strings to avoid pathological performance.</info>
       <return type='xmlBufferAllocationScheme' info='the current allocation scheme'/>
     </function>
     <function name='xmlGetCharEncodingHandler' file='encoding' module='encoding'>
@@ -9955,7 +9929,7 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='xmlIOParseDTD' file='parser' module='parser'>
       <cond>defined(LIBXML_VALID_ENABLED)</cond>
-      <info>Load and parse a DTD</info>
+      <info>DEPRECATED: Use xmlCtxtParseDtd.  Load and parse a DTD</info>
       <return type='xmlDtdPtr' info='the resulting xmlDtdPtr or NULL in case of error. @input will be freed by the function in any case.'/>
       <arg name='sax' type='xmlSAXHandlerPtr' info='the SAX handler block or NULL'/>
       <arg name='input' type='xmlParserInputBufferPtr' info='an Input Buffer'/>
@@ -9979,7 +9953,7 @@ crash if you try to modify the tree)'/>
       <arg name='seq' type='xmlParserNodeInfoSeqPtr' info='a node info sequence pointer'/>
     </function>
     <function name='xmlInitParser' file='parser' module='threads'>
-      <info>Initialization function for the XML parser.  Call once from the main thread before using the library in multithreaded programs.</info>
+      <info>Initialization function for the XML parser.  For older versions, it&apos;s recommended to call this function once from the main thread before using the library in multithreaded programs.  Since 2.14.0, there&apos;s no distinction between threads. It should be unnecessary to call this function.</info>
       <return type='void'/>
     </function>
     <function name='xmlInitParserCtxt' file='parser' module='parserInternals'>
@@ -10641,7 +10615,7 @@ crash if you try to modify the tree)'/>
       <arg name='content' type='const xmlChar *' info='the comment content'/>
     </function>
     <function name='xmlNewDocElementContent' file='valid' module='valid'>
-      <info>Allocate an element content structure for the document.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Allocate an element content structure for the document.</info>
       <return type='xmlElementContentPtr' info='NULL if not, otherwise the new element content structure'/>
       <arg name='doc' type='xmlDocPtr' info='the document'/>
       <arg name='name' type='const xmlChar *' info='the subelement name or NULL'/>
@@ -10712,7 +10686,7 @@ crash if you try to modify the tree)'/>
       <arg name='SystemID' type='const xmlChar *' info='the system ID (optional)'/>
     </function>
     <function name='xmlNewElementContent' file='valid' module='valid'>
-      <info>Allocate an element content structure. Deprecated in favor of xmlNewDocElementContent</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Allocate an element content structure. Deprecated in favor of xmlNewDocElementContent</info>
       <return type='xmlElementContentPtr' info='NULL if not, otherwise the new element content structure'/>
       <arg name='name' type='const xmlChar *' info='the subelement name or NULL'/>
       <arg name='type' type='xmlElementContentType' info='the type of element content decl'/>
@@ -11045,17 +11019,17 @@ crash if you try to modify the tree)'/>
       <arg name='node' type='const xmlNode *' info='the node'/>
     </function>
     <function name='xmlNodeListGetRawString' file='tree' module='tree'>
-      <info>Serializes attribute children (text and entity reference nodes) into a string. An empty list produces an empty string.  If @inLine is true, entity references will be substituted. Otherwise, entity references will be kept and special characters like &apos;&amp;&apos; will be escaped.</info>
+      <info>Serializes attribute children (text and entity reference nodes) into a string.  If @inLine is true, entity references will be substituted. Otherwise, entity references will be kept and special characters like &apos;&amp;&apos; will be escaped.</info>
       <return type='xmlChar *' info='a string or NULL if a memory allocation failed.'/>
       <arg name='doc' type='const xmlDoc *' info='a document (optional)'/>
-      <arg name='list' type='const xmlNode *' info='a node list of attribute children (optional)'/>
+      <arg name='list' type='const xmlNode *' info='a node list of attribute children'/>
       <arg name='inLine' type='int' info='whether entity references are substituted'/>
     </function>
     <function name='xmlNodeListGetString' file='tree' module='tree'>
-      <info>Serializes attribute children (text and entity reference nodes) into a string. An empty list produces an empty string.  If @inLine is true, entity references will be substituted. Otherwise, entity references will be kept and special characters like &apos;&amp;&apos; as well as non-ASCII chars will be escaped. See xmlNodeListGetRawString for an alternative option.</info>
+      <info>Serializes attribute children (text and entity reference nodes) into a string.  If @inLine is true, entity references will be substituted. Otherwise, entity references will be kept and special characters like &apos;&amp;&apos; as well as non-ASCII chars will be escaped. See xmlNodeListGetRawString for an alternative option.</info>
       <return type='xmlChar *' info='a string or NULL if a memory allocation failed.'/>
       <arg name='doc' type='xmlDocPtr' info='a document (optional)'/>
-      <arg name='list' type='const xmlNode *' info='a node list of attribute children (optional)'/>
+      <arg name='list' type='const xmlNode *' info='a node list of attribute children'/>
       <arg name='inLine' type='int' info='whether entity references are substituted'/>
     </function>
     <function name='xmlNodeSetBase' file='tree' module='tree'>
@@ -11120,28 +11094,28 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='xmlOutputBufferCreateBuffer' file='xmlIO' module='xmlIO'>
       <cond>defined(LIBXML_OUTPUT_ENABLED)</cond>
-      <info>Create a buffered output for the progressive saving to a xmlBuffer</info>
+      <info>Create a buffered output for the progressive saving to a xmlBuffer  Consumes @encoder even in error case.</info>
       <return type='xmlOutputBufferPtr' info='the new parser output or NULL'/>
       <arg name='buffer' type='xmlBufferPtr' info='a xmlBufferPtr'/>
       <arg name='encoder' type='xmlCharEncodingHandlerPtr' info='the encoding converter or NULL'/>
     </function>
     <function name='xmlOutputBufferCreateFd' file='xmlIO' module='xmlIO'>
       <cond>defined(LIBXML_OUTPUT_ENABLED)</cond>
-      <info>Create a buffered output for the progressive saving to a file descriptor</info>
+      <info>Create a buffered output for the progressive saving to a file descriptor  Consumes @encoder even in error case.</info>
       <return type='xmlOutputBufferPtr' info='the new parser output or NULL'/>
       <arg name='fd' type='int' info='a file descriptor number'/>
       <arg name='encoder' type='xmlCharEncodingHandlerPtr' info='the encoding converter or NULL'/>
     </function>
     <function name='xmlOutputBufferCreateFile' file='xmlIO' module='xmlIO'>
       <cond>defined(LIBXML_OUTPUT_ENABLED)</cond>
-      <info>Create a buffered output for the progressive saving to a FILE * buffered C I/O</info>
+      <info>Create a buffered output for the progressive saving to a FILE * buffered C I/O  Consumes @encoder even in error case.</info>
       <return type='xmlOutputBufferPtr' info='the new parser output or NULL'/>
       <arg name='file' type='FILE *' info='a FILE*'/>
       <arg name='encoder' type='xmlCharEncodingHandlerPtr' info='the encoding converter or NULL'/>
     </function>
     <function name='xmlOutputBufferCreateFilename' file='xmlIO' module='xmlIO'>
       <cond>defined(LIBXML_OUTPUT_ENABLED)</cond>
-      <info>Create a buffered  output for the progressive saving of a file If filename is &quot;-&apos; then we use stdout as the output. Automatic support for ZLIB/Compress compressed document is provided by default if found at compile-time. TODO: currently if compression is set, the library only support writing to a local file.</info>
+      <info>Create a buffered  output for the progressive saving of a file If filename is &quot;-&apos; then we use stdout as the output. Automatic support for ZLIB/Compress compressed document is provided by default if found at compile-time. TODO: currently if compression is set, the library only support writing to a local file.  Consumes @encoder even in error case.</info>
       <return type='xmlOutputBufferPtr' info='the new output or NULL'/>
       <arg name='URI' type='const char *' info='a C string containing the URI or filename'/>
       <arg name='encoder' type='xmlCharEncodingHandlerPtr' info='the encoding converter or NULL'/>
@@ -11161,7 +11135,7 @@ crash if you try to modify the tree)'/>
     </functype>
     <function name='xmlOutputBufferCreateIO' file='xmlIO' module='xmlIO'>
       <cond>defined(LIBXML_OUTPUT_ENABLED)</cond>
-      <info>Create a buffered output for the progressive saving to an I/O handler</info>
+      <info>Create a buffered output for the progressive saving to an I/O handler  Consumes @encoder even in error case.</info>
       <return type='xmlOutputBufferPtr' info='the new parser output or NULL'/>
       <arg name='iowrite' type='xmlOutputWriteCallback' info='an I/O write function'/>
       <arg name='ioclose' type='xmlOutputCloseCallback' info='an I/O close function'/>
@@ -11192,7 +11166,7 @@ crash if you try to modify the tree)'/>
       <return type='int' info='the number of chars immediately written, or -1 in case of error.'/>
       <arg name='out' type='xmlOutputBufferPtr' info='a buffered parser output'/>
       <arg name='len' type='int' info='the size in bytes of the array.'/>
-      <arg name='buf' type='const char *' info='an char array'/>
+      <arg name='data' type='const char *' info='an char array'/>
     </function>
     <function name='xmlOutputBufferWriteEscape' file='xmlIO' module='xmlIO'>
       <cond>defined(LIBXML_OUTPUT_ENABLED)</cond>
@@ -11443,7 +11417,7 @@ crash if you try to modify the tree)'/>
       <arg name='ctxt' type='xmlParserCtxtPtr' info='an XML parser context'/>
     </function>
     <function name='xmlParseExtParsedEnt' file='parser' module='parser'>
-      <info>parse a general parsed entity An external general parsed entity is well-formed if it matches the production labeled extParsedEnt.  [78] extParsedEnt ::= TextDecl? content</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  parse a general parsed entity An external general parsed entity is well-formed if it matches the production labeled extParsedEnt.  [78] extParsedEnt ::= TextDecl? content</info>
       <return type='int' info='0, -1 in case of error. the parser context is augmented as a result of the parsing.'/>
       <arg name='ctxt' type='xmlParserCtxtPtr' info='an XML parser context'/>
     </function>
@@ -11467,7 +11441,7 @@ crash if you try to modify the tree)'/>
       <arg name='strict' type='int' info='indicate whether we should restrict parsing to only production [75], see NOTE below'/>
     </function>
     <function name='xmlParseExternalSubset' file='parserInternals' module='parser'>
-      <info>parse Markup declarations from an external subset  [30] extSubset ::= textDecl? extSubsetDecl  [31] extSubsetDecl ::= (markupdecl | conditionalSect | PEReference | S) *</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  parse Markup declarations from an external subset  [30] extSubset ::= textDecl? extSubsetDecl  [31] extSubsetDecl ::= (markupdecl | conditionalSect | PEReference | S) *</info>
       <return type='void'/>
       <arg name='ctxt' type='xmlParserCtxtPtr' info='an XML parser context'/>
       <arg name='ExternalID' type='const xmlChar *' info='the external identifier'/>
@@ -11645,19 +11619,19 @@ crash if you try to modify the tree)'/>
       <arg name='ctxt' type='xmlParserCtxtPtr' info='the parser context'/>
     </function>
     <function name='xmlParserInputBufferCreateFd' file='xmlIO' module='xmlIO'>
-      <info>Create a buffered parser input for the progressive parsing for the input from a file descriptor  The encoding argument is deprecated and should be set to XML_CHAR_ENCODING_NONE. The encoding can be changed with xmlSwitchEncoding or xmlSwitchEncodingName later on.</info>
+      <info>DEPRECATED: Use xmlNewInputFromFd.  Create a buffered parser input for the progressive parsing for the input from a file descriptor  The encoding argument is deprecated and should be set to XML_CHAR_ENCODING_NONE. The encoding can be changed with xmlSwitchEncoding or xmlSwitchEncodingName later on.</info>
       <return type='xmlParserInputBufferPtr' info='the new parser input or NULL'/>
       <arg name='fd' type='int' info='a file descriptor number'/>
       <arg name='enc' type='xmlCharEncoding' info='the charset encoding if known (deprecated)'/>
     </function>
     <function name='xmlParserInputBufferCreateFile' file='xmlIO' module='xmlIO'>
-      <info>Create a buffered parser input for the progressive parsing of a FILE * buffered C I/O  The encoding argument is deprecated and should be set to XML_CHAR_ENCODING_NONE. The encoding can be changed with xmlSwitchEncoding or xmlSwitchEncodingName later on.</info>
+      <info>DEPRECATED: Don&apos;t use.  Create a buffered parser input for the progressive parsing of a FILE * buffered C I/O  The encoding argument is deprecated and should be set to XML_CHAR_ENCODING_NONE. The encoding can be changed with xmlSwitchEncoding or xmlSwitchEncodingName later on.</info>
       <return type='xmlParserInputBufferPtr' info='the new parser input or NULL'/>
       <arg name='file' type='FILE *' info='a FILE*'/>
       <arg name='enc' type='xmlCharEncoding' info='the charset encoding if known (deprecated)'/>
     </function>
     <function name='xmlParserInputBufferCreateFilename' file='xmlIO' module='xmlIO'>
-      <info>Create a buffered parser input for the progressive parsing of a file Automatic support for ZLIB/Compress compressed document is provided by default if found at compile-time. Do an encoding check if enc == XML_CHAR_ENCODING_NONE</info>
+      <info>DEPRECATED: Use xmlNewInputFromUrl.  Create a buffered parser input for the progressive parsing of a file Automatic support for ZLIB/Compress compressed document is provided by default if found at compile-time. Do an encoding check if enc == XML_CHAR_ENCODING_NONE</info>
       <return type='xmlParserInputBufferPtr' info='the new parser input or NULL'/>
       <arg name='URI' type='const char *' info='a C string containing the URI or filename'/>
       <arg name='enc' type='xmlCharEncoding' info='the charset encoding if known'/>
@@ -11674,7 +11648,7 @@ crash if you try to modify the tree)'/>
       <arg name='enc' type='xmlCharEncoding' info='the requested source encoding'/>
     </functype>
     <function name='xmlParserInputBufferCreateIO' file='xmlIO' module='xmlIO'>
-      <info>Create a buffered parser input for the progressive parsing for the input from an I/O handler  The encoding argument is deprecated and should be set to XML_CHAR_ENCODING_NONE. The encoding can be changed with xmlSwitchEncoding or xmlSwitchEncodingName later on.</info>
+      <info>DEPRECATED: Use xmlNewInputFromIO.  Create a buffered parser input for the progressive parsing for the input from an I/O handler  The encoding argument is deprecated and should be set to XML_CHAR_ENCODING_NONE. The encoding can be changed with xmlSwitchEncoding or xmlSwitchEncodingName later on.</info>
       <return type='xmlParserInputBufferPtr' info='the new parser input or NULL'/>
       <arg name='ioread' type='xmlInputReadCallback' info='an I/O read function'/>
       <arg name='ioclose' type='xmlInputCloseCallback' info='an I/O close function'/>
@@ -11682,34 +11656,34 @@ crash if you try to modify the tree)'/>
       <arg name='enc' type='xmlCharEncoding' info='the charset encoding if known (deprecated)'/>
     </function>
     <function name='xmlParserInputBufferCreateMem' file='xmlIO' module='xmlIO'>
-      <info>Create a parser input buffer for parsing from a memory area.  This function makes a copy of the whole input buffer. If you are sure that the contents of the buffer will remain valid until the document was parsed, you can avoid the copy by using xmlParserInputBufferCreateStatic.  The encoding argument is deprecated and should be set to XML_CHAR_ENCODING_NONE. The encoding can be changed with xmlSwitchEncoding or xmlSwitchEncodingName later on.</info>
+      <info>DEPRECATED: Use xmlNewInputFromMemory.  Create a parser input buffer for parsing from a memory area.  This function makes a copy of the whole input buffer. If you are sure that the contents of the buffer will remain valid until the document was parsed, you can avoid the copy by using xmlParserInputBufferCreateStatic.  The encoding argument is deprecated and should be set to XML_CHAR_ENCODING_NONE. The encoding can be changed with xmlSwitchEncoding or xmlSwitchEncodingName later on.</info>
       <return type='xmlParserInputBufferPtr' info='the new parser input or NULL in case of error.'/>
       <arg name='mem' type='const char *' info='the memory input'/>
       <arg name='size' type='int' info='the length of the memory block'/>
       <arg name='enc' type='xmlCharEncoding' info='the charset encoding if known (deprecated)'/>
     </function>
     <function name='xmlParserInputBufferCreateStatic' file='xmlIO' module='xmlIO'>
-      <info>Create a parser input buffer for parsing from a memory area.  This functions assumes that the contents of the input buffer remain valid until the document was parsed. Use xmlParserInputBufferCreateMem otherwise.  The encoding argument is deprecated and should be set to XML_CHAR_ENCODING_NONE. The encoding can be changed with xmlSwitchEncoding or xmlSwitchEncodingName later on.</info>
+      <info>DEPRECATED: Use xmlNewInputFromMemory.  Create a parser input buffer for parsing from a memory area.  This functions assumes that the contents of the input buffer remain valid until the document was parsed. Use xmlParserInputBufferCreateMem otherwise.  The encoding argument is deprecated and should be set to XML_CHAR_ENCODING_NONE. The encoding can be changed with xmlSwitchEncoding or xmlSwitchEncodingName later on.</info>
       <return type='xmlParserInputBufferPtr' info='the new parser input or NULL in case of error.'/>
       <arg name='mem' type='const char *' info='the memory input'/>
       <arg name='size' type='int' info='the length of the memory block'/>
       <arg name='enc' type='xmlCharEncoding' info='the charset encoding if known'/>
     </function>
     <function name='xmlParserInputBufferGrow' file='xmlIO' module='xmlIO'>
-      <info>Grow up the content of the input buffer, the old data are preserved This routine handle the I18N transcoding to internal UTF-8 This routine is used when operating the parser in normal (pull) mode  TODO: one should be able to remove one extra copy by copying directly onto in-&gt;buffer or in-&gt;raw</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Grow up the content of the input buffer, the old data are preserved This routine handle the I18N transcoding to internal UTF-8 This routine is used when operating the parser in normal (pull) mode</info>
       <return type='int' info='the number of chars read and stored in the buffer, or -1 in case of error.'/>
       <arg name='in' type='xmlParserInputBufferPtr' info='a buffered parser input'/>
       <arg name='len' type='int' info='indicative value of the amount of chars to read'/>
     </function>
     <function name='xmlParserInputBufferPush' file='xmlIO' module='xmlIO'>
-      <info>Push the content of the arry in the input buffer This routine handle the I18N transcoding to internal UTF-8 This is used when operating the parser in progressive (push) mode.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Push the content of the arry in the input buffer This routine handle the I18N transcoding to internal UTF-8 This is used when operating the parser in progressive (push) mode.</info>
       <return type='int' info='the number of chars read and stored in the buffer, or -1 in case of error.'/>
       <arg name='in' type='xmlParserInputBufferPtr' info='a buffered parser input'/>
       <arg name='len' type='int' info='the size in bytes of the array.'/>
       <arg name='buf' type='const char *' info='an char array'/>
     </function>
     <function name='xmlParserInputBufferRead' file='xmlIO' module='xmlIO'>
-      <info>Refresh the content of the input buffer, the old data are considered consumed This routine handle the I18N transcoding to internal UTF-8</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Same as xmlParserInputBufferGrow.</info>
       <return type='int' info='the number of chars read and stored in the buffer, or -1 in case of error.'/>
       <arg name='in' type='xmlParserInputBufferPtr' info='a buffered parser input'/>
       <arg name='len' type='int' info='indicative value of the amount of chars to read'/>
@@ -11834,7 +11808,7 @@ crash if you try to modify the tree)'/>
       <arg name='val' type='int' info='int 0 or 1'/>
     </function>
     <function name='xmlPopInput' file='parserInternals' module='parser'>
-      <info>xmlPopInput: the current input pointed by ctxt-&gt;input came to an end pop it and return the next char.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.</info>
       <return type='xmlChar' info='the current xmlChar in the parser context'/>
       <arg name='ctxt' type='xmlParserCtxtPtr' info='an XML parser context'/>
     </function>
@@ -11859,7 +11833,7 @@ crash if you try to modify the tree)'/>
       <arg name='uri' type='xmlURIPtr' info='pointer to an xmlURI'/>
     </function>
     <function name='xmlPushInput' file='parserInternals' module='parser'>
-      <info>Push an input stream onto the stack.</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Push an input stream onto the stack.</info>
       <return type='int' info='-1 in case of error or the index in the input stack'/>
       <arg name='ctxt' type='xmlParserCtxtPtr' info='an XML parser context'/>
       <arg name='input' type='xmlParserInputPtr' info='an XML parser input fragment (entity, XML fragment ...).'/>
@@ -12669,7 +12643,7 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='xmlSAXParseDTD' file='parser' module='parser'>
       <cond>defined(LIBXML_VALID_ENABLED)</cond>
-      <info>DEPRECATED: Don&apos;t use.  Load and parse an external subset.</info>
+      <info>DEPRECATED: Use xmlCtxtParseDtd.  Load and parse an external subset.</info>
       <return type='xmlDtdPtr' info='the resulting xmlDtdPtr or NULL in case of error.'/>
       <arg name='sax' type='xmlSAXHandlerPtr' info='the SAX handler block'/>
       <arg name='ExternalID' type='const xmlChar *' info='a NAME* containing the External ID of the DTD'/>
@@ -12825,14 +12799,14 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='xmlSaveSetAttrEscape' file='xmlsave' module='xmlsave'>
       <cond>defined(LIBXML_OUTPUT_ENABLED)</cond>
-      <info>Set a custom escaping function to be used for text in attribute content</info>
+      <info>DEPRECATED: Don&apos;t use.  Has no effect.</info>
       <return type='int' info='0 if successful or -1 in case of error.'/>
       <arg name='ctxt' type='xmlSaveCtxtPtr' info='a document saving context'/>
       <arg name='escape' type='xmlCharEncodingOutputFunc' info='the escaping function'/>
     </function>
     <function name='xmlSaveSetEscape' file='xmlsave' module='xmlsave'>
       <cond>defined(LIBXML_OUTPUT_ENABLED)</cond>
-      <info>Set a custom escaping function to be used for text in element content</info>
+      <info>DEPRECATED: Don&apos;t use.  Set a custom escaping function to be used for text in element content</info>
       <return type='int' info='0 if successful or -1 in case of error.'/>
       <arg name='ctxt' type='xmlSaveCtxtPtr' info='a document saving context'/>
       <arg name='escape' type='xmlCharEncodingOutputFunc' info='the escaping function'/>
@@ -13468,8 +13442,8 @@ crash if you try to modify the tree)'/>
       <arg name='node' type='xmlNodePtr' info='the current node'/>
       <arg name='href' type='const xmlChar *' info='the namespace value'/>
     </function>
-    <function name='xmlSetBufferAllocationScheme' file='tree' module='tree'>
-      <info>Set the buffer allocation method.  Types are XML_BUFFER_ALLOC_EXACT - use exact sizes, keeps memory usage down XML_BUFFER_ALLOC_DOUBLEIT - double buffer when extra needed, improves performance</info>
+    <function name='xmlSetBufferAllocationScheme' file='tree' module='buf'>
+      <info>DEPRECATED: Use xmlBufferSetAllocationScheme.  Set the buffer allocation method.  Types are XML_BUFFER_ALLOC_EXACT - use exact sizes, keeps memory usage down XML_BUFFER_ALLOC_DOUBLEIT - double buffer when extra needed, improves performance</info>
       <return type='void'/>
       <arg name='scheme' type='xmlBufferAllocationScheme' info='allocation method to use'/>
     </function>
@@ -13548,7 +13522,7 @@ crash if you try to modify the tree)'/>
       <arg name='ctxt' type='xmlParserCtxtPtr' info='the XML parser context'/>
     </function>
     <function name='xmlSnprintfElementContent' file='valid' module='valid'>
-      <info>This will dump the content of the element content definition Intended just for the debug routine</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  This will dump the content of the element content definition Intended just for the debug routine</info>
       <return type='void'/>
       <arg name='buf' type='char *' info='an output buffer'/>
       <arg name='size' type='int' info='the buffer size'/>
@@ -13576,7 +13550,7 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='xmlSprintfElementContent' file='valid' module='valid'>
       <cond>defined(LIBXML_OUTPUT_ENABLED)</cond>
-      <info>Deprecated, unsafe, use xmlSnprintfElementContent</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Deprecated, unsafe, use xmlSnprintfElementContent</info>
       <return type='void'/>
       <arg name='buf' type='char *' info='an output buffer'/>
       <arg name='content' type='xmlElementContentPtr' info='An element table'/>
@@ -13849,7 +13823,7 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='xmlTextReaderByteConsumed' file='xmlreader' module='xmlreader'>
       <cond>defined(LIBXML_READER_ENABLED)</cond>
-      <info>This function provides the current index of the parser used by the reader, relative to the start of the current entity. This function actually just wraps a call to xmlBytesConsumed() for the parser context associated with the reader. See xmlBytesConsumed() for more information.</info>
+      <info>DEPRECATED: The returned value is mostly random and useless. It reflects the parser reading ahead and is in no way related to the current node.  This function provides the current index of the parser used by the reader, relative to the start of the current entity. This function actually just wraps a call to xmlBytesConsumed() for the parser context associated with the reader. See xmlBytesConsumed() for more information.</info>
       <return type='long' info='the index in bytes from the beginning of the entity or -1 in case the index could not be computed.'/>
       <arg name='reader' type='xmlTextReaderPtr' info='an XML reader'/>
     </function>
@@ -16174,9 +16148,9 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='xmlValidateDocument' file='valid' module='valid'>
       <cond>defined(LIBXML_VALID_ENABLED)</cond>
-      <info>Try to validate the document instance  basically it does the all the checks described by the XML Rec i.e. validates the internal and external subset (if present) and validate the document tree.</info>
+      <info>DEPRECATED: This function can&apos;t report malloc or other failures. Use xmlCtxtValidateDocument.  Try to validate the document instance  basically it does the all the checks described by the XML Rec i.e. validates the internal and external subset (if present) and validate the document tree.</info>
       <return type='int' info='1 if valid or 0 otherwise'/>
-      <arg name='ctxt' type='xmlValidCtxtPtr' info='the validation context'/>
+      <arg name='vctxt' type='xmlValidCtxtPtr' info='the validation context'/>
       <arg name='doc' type='xmlDocPtr' info='a document instance'/>
     </function>
     <function name='xmlValidateDocumentFinal' file='valid' module='valid'>
@@ -16718,7 +16692,7 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='xmlXPathEvalExpr' file='xpathInternals' module='xpath'>
       <cond>defined(LIBXML_XPATH_ENABLED)</cond>
-      <info>Parse and evaluate an XPath expression in the given context, then push the result on the context stack</info>
+      <info>DEPRECATED: Internal function, don&apos;t use.  Parse and evaluate an XPath expression in the given context, then push the result on the context stack</info>
       <return type='void'/>
       <arg name='ctxt' type='xmlXPathParserContextPtr' info='the XPath Parser context'/>
     </function>
@@ -17275,7 +17249,7 @@ crash if you try to modify the tree)'/>
     </function>
     <function name='xmlXPathRegisterAllFunctions' file='xpathInternals' module='xpath'>
       <cond>defined(LIBXML_XPATH_ENABLED)</cond>
-      <info>Registers all default XPath functions in this context</info>
+      <info>DEPRECATED: No-op since 2.14.0.  Registers all default XPath functions in this context</info>
       <return type='void'/>
       <arg name='ctxt' type='xmlXPathContextPtr' info='the XPath context'/>
     </function>
diff --git a/doc/xmllint.1 b/doc/xmllint.1
index 855fef3f..2e69cffb 100644
--- a/doc/xmllint.1
+++ b/doc/xmllint.1
@@ -2,12 +2,12 @@
 .\"     Title: xmllint
 .\"    Author: John Fleck <jfleck@inkstain.net>
 .\" Generator: DocBook XSL Stylesheets vsnapshot <http://docbook.sf.net/>
-.\"      Date: 06/12/2024
+.\"      Date: 12/26/2024
 .\"    Manual: xmllint Manual
 .\"    Source: libxml2
 .\"  Language: English
 .\"
-.TH "XMLLINT" "1" "06/12/2024" "libxml2" "xmllint Manual"
+.TH "XMLLINT" "1" "12/26/2024" "libxml2" "xmllint Manual"
 .\" -----------------------------------------------------------------
 .\" * Define some portability stuff
 .\" -----------------------------------------------------------------
@@ -31,9 +31,7 @@
 xmllint \- command line XML tool
 .SH "SYNOPSIS"
 .HP \w'\fBxmllint\fR\ 'u
-\fBxmllint\fR [\fB\-\-version\fR | \fB\-\-debug\fR | \fB\-\-quiet\fR | \fB\-\-shell\fR | \fB\-\-xpath\ "\fR\fB\fIXPath_expression\fR\fR\fB"\fR | \fB\-\-debugent\fR | \fB\-\-copy\fR | \fB\-\-recover\fR | \fB\-\-nodict\fR | \fB\-\-noent\fR | \fB\-\-noout\fR | \fB\-\-nonet\fR | \fB\-\-path\ "\fR\fB\fIPATH(S)\fR\fR\fB"\fR | \fB\-\-load\-trace\fR | \fB\-\-htmlout\fR | \fB\-\-nowrap\fR | \fB\-\-valid\fR | \fB\-\-postvalid\fR | \fB\-\-dtdvalid\ \fR\fB\fIURL\fR\fR | \fB\-\-dtdvalidfpi\ \fR\fB\fIFPI\fR\fR | \fB\-\-timing\fR | \fB\-\-output\ \fR\fB\fIFILE\fR\fR | \fB\-\-repeat\fR | \fB\-\-insert\fR | \fB\-\-compress\fR | \fB\-\-html\fR | \fB\-\-xmlout\fR | \fB\-\-push\fR | \fB\-\-memory\fR | \fB\-\-max\-ampl\ \fR\fB\fIINTEGER\fR\fR | \fB\-\-maxmem\ \fR\fB\fINBBYTES\fR\fR | \fB\-\-nowarning\fR | \fB\-\-noblanks\fR | \fB\-\-nocdata\fR | \fB\-\-format\fR | \fB\-\-encode\ \fR\fB\fIENCODING\fR\fR | \fB\-\-dropdtd\fR | \fB\-\-nsclean\fR | \fB\-\-testIO\fR | \fB\-\-catalogs\fR | \fB\-\-nocatalogs\fR | \fB\-\-auto\fR | \fB\-\-xinclude\fR | \fB\-\-noxincludenode\fR | \fB\-\-loaddtd\fR | \fB\-\-dtdattr\fR | \fB\-\-stream\fR | \fB\-\-walker\fR | \fB\-\-pattern\ \fR\fB\fIPATTERNVALUE\fR\fR | \fB\-\-relaxng\ \fR\fB\fISCHEMA\fR\fR | \fB\-\-schema\ \fR\fB\fISCHEMA\fR\fR | \fB\-\-c14n\fR | \fB\-\-pedantic\fR] {\fIXML\-FILE(S)\fR... | \-}
-.HP \w'\fBxmllint\fR\ 'u
-\fBxmllint\fR \fB\-\-help\fR
+\fBxmllint\fR [\fB\-\-version\fR | \fB\-\-debug\fR | \fB\-\-quiet\fR | \fB\-\-shell\fR | \fB\-\-xpath\ "\fR\fB\fIXPath_expression\fR\fR\fB"\fR | \fB\-\-debugent\fR | \fB\-\-copy\fR | \fB\-\-recover\fR | \fB\-\-huge\fR | \fB\-\-nocompact\fR | \fB\-\-nodefdtd\fR | \fB\-\-nodict\fR | \fB\-\-noenc\fR | \fB\-\-noent\fR | \fB\-\-nofixup\-base\-uris\fR | \fB\-\-noout\fR | \fB\-\-nonet\fR | \fB\-\-path\ "\fR\fB\fIPATH(S)\fR\fR\fB"\fR | \fB\-\-load\-trace\fR | \fB\-\-htmlout\fR | \fB\-\-nowrap\fR | \fB\-\-valid\fR | \fB\-\-postvalid\fR | \fB\-\-dtdvalid\ \fR\fB\fIURL\fR\fR | \fB\-\-dtdvalidfpi\ \fR\fB\fIFPI\fR\fR | \fB\-\-timing\fR | \fB\-\-output\ \fR\fB\fIFILE\fR\fR | \fB\-\-repeat\fR | \fB\-\-insert\fR | \fB\-\-compress\fR | \fB\-\-html\fR | \fB\-\-xmlout\fR | \fB\-\-push\fR | \fB\-\-memory\fR | \fB\-\-max\-ampl\ \fR\fB\fIINTEGER\fR\fR | \fB\-\-maxmem\ \fR\fB\fINBBYTES\fR\fR | \fB\-\-nowarning\fR | \fB\-\-noblanks\fR | \fB\-\-nocdata\fR | \fB\-\-format\fR | \fB\-\-pretty\ \fR\fB\fIINTEGER\fR\fR | \fB\-\-encode\ \fR\fB\fIENCODING\fR\fR | \fB\-\-dropdtd\fR | \fB\-\-nsclean\fR | \fB\-\-testIO\fR | \fB\-\-catalogs\fR | \fB\-\-nocatalogs\fR | \fB\-\-auto\fR | \fB\-\-xinclude\fR | \fB\-\-noxincludenode\fR | \fB\-\-loaddtd\fR | \fB\-\-dtdattr\fR | \fB\-\-stream\fR | \fB\-\-walker\fR | \fB\-\-pattern\ \fR\fB\fIPATTERNVALUE\fR\fR | \fB\-\-relaxng\ \fR\fB\fISCHEMA\fR\fR | \fB\-\-schema\ \fR\fB\fISCHEMA\fR\fR | \fB\-\-schematron\ \fR\fB\fISCHEMA\fR\fR | \fB\-\-c14n\fR | \fB\-\-c14n11\fR | \fB\-\-exc\-c14n\fR | \fB\-\-pedantic\fR | \fB\-\-sax\fR | \fB\-\-sax1\fR | \fB\-\-oldxml10\fR] {\fIXML\-FILE(S)\fR... | \-}
 .SH "DESCRIPTION"
 .PP
 The
@@ -89,7 +87,7 @@ compression of output\&.
 Test the internal copy implementation\&.
 .RE
 .PP
-\fB\-\-c14n\fR
+\fB\-\-c14n\fR, \fB\-\-c14n11\fR, \fB\-\-exc\-c14n\fR
 .RS 4
 Use the W3C
 XML
@@ -151,12 +149,6 @@ Reformat and reindent the output\&. The
 environment variable controls the indentation\&. The default value is two spaces " ")\&.
 .RE
 .PP
-\fB\-\-help\fR
-.RS 4
-Print out a short usage summary for
-\fBxmllint\fR\&.
-.RE
-.PP
 \fB\-\-html\fR
 .RS 4
 Use the
@@ -175,6 +167,11 @@ HTML
 tags surrounding the result tree output so the results can be displayed/viewed in a browser\&.
 .RE
 .PP
+\fB\-\-huge\fR
+.RS 4
+Ignore some hardcoded parser limits\&.
+.RE
+.PP
 \fB\-\-insert\fR
 .RS 4
 Test for valid insertions\&.
@@ -226,11 +223,26 @@ Do not use any catalogs\&.
 Substitute CDATA section by equivalent text nodes\&.
 .RE
 .PP
+\fB\-\-nocompact\fR
+.RS 4
+Do not generate compact text nodes (parser option XML_PARSE_COMPACT)\&. Only for debugging\&.
+.RE
+.PP
+\fB\-\-nodefdtd\fR
+.RS 4
+Do not set default HTML doctype (parser option HTML_PARSE_NODEFDTD)\&.
+.RE
+.PP
 \fB\-\-nodict\fR
 .RS 4
 Don\*(Aqt use dictionaries (parser option XML_PARSE_NODICT)\&. Only for debugging\&.
 .RE
 .PP
+\fB\-\-noenc\fR
+.RS 4
+Ignore encoding declaration (parser option XML_PARSE_IGNORE_ENC)\&.
+.RE
+.PP
 \fB\-\-noent\fR
 .RS 4
 Substitute entity values for entity references\&. By default,
@@ -238,6 +250,11 @@ Substitute entity values for entity references\&. By default,
 leaves entity references in place\&.
 .RE
 .PP
+\fB\-\-nofixup\-base\-uris\fR
+.RS 4
+Don\*(Aqt fix xml:base URIs when processing XIncludes (parser option XML_PARSE_NOBASEFIX)\&.
+.RE
+.PP
 \fB\-\-nonet\fR
 .RS 4
 Do not use the Internet to fetch
@@ -273,6 +290,11 @@ Do XInclude processing but do not generate XInclude start and end nodes\&.
 Remove redundant namespace declarations\&.
 .RE
 .PP
+\fB\-\-oldxml10\fR
+.RS 4
+Use deprecated parsing rules before XML 1\&.0, 5th edition\&.
+.RE
+.PP
 \fB\-\-output \fR\fB\fIFILE\fR\fR
 .RS 4
 Define a file path where
@@ -306,6 +328,11 @@ Enable additional warnings\&.
 Validate after parsing has completed\&.
 .RE
 .PP
+\fB\-\-pretty \fR\fB\fIINTEGER\fR\fR
+.RS 4
+Value 0 means no formatting, 1 means XML_SAVE_FORMAT (same as \-\-format), 2 means XML_SAVE_WSNONSIG\&.
+.RE
+.PP
 \fB\-\-push\fR
 .RS 4
 Use the push mode of the parser\&.
@@ -333,6 +360,16 @@ for validation\&.
 Repeat 100 times, for timing or profiling\&.
 .RE
 .PP
+\fB\-\-sax\fR
+.RS 4
+Print SAX callbacks (only for debugging)\&.
+.RE
+.PP
+\fB\-\-sax1\fR
+.RS 4
+Use deprecated SAX1 interface (only for debugging)\&.
+.RE
+.PP
 \fB\-\-schema \fR\fB\fISCHEMA\fR\fR
 .RS 4
 Use a W3C
@@ -342,6 +379,13 @@ Schema file named
 for validation\&.
 .RE
 .PP
+\fB\-\-schematron \fR\fB\fISCHEMA\fR\fR
+.RS 4
+Use a Schematron file named
+\fISCHEMA\fR
+for validation\&.
+.RE
+.PP
 \fB\-\-shell\fR
 .RS 4
 Run a navigating shell\&. Details on available commands in shell mode are below (see
diff --git a/doc/xmllint.html b/doc/xmllint.html
index dddbb828..f106ddf8 100644
--- a/doc/xmllint.html
+++ b/doc/xmllint.html
@@ -1,4 +1,4 @@
-<html><head><meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1"><title>xmllint</title><meta name="generator" content="DocBook XSL Stylesheets Vsnapshot"></head><body bgcolor="white" text="black" link="#0000FF" vlink="#840084" alink="#0000FF"><div class="refentry"><a name="idm1"></a><div class="titlepage"></div><div class="refnamediv"><h2>Name</h2><p>xmllint &#8212; command line <acronym class="acronym">XML</acronym> tool</p></div><div class="refsynopsisdiv"><h2>Synopsis</h2><div class="cmdsynopsis"><p><code class="command">xmllint</code>  [ <code class="option">--version</code>  |   <code class="option">--debug</code>  |   <code class="option">--quiet</code>  |   <code class="option">--shell</code>  |   <code class="option">--xpath "<em class="replaceable"><code>XPath_expression</code></em>"</code>  |   <code class="option">--debugent</code>  |   <code class="option">--copy</code>  |   <code class="option">--recover</code>  |   <code class="option">--nodict</code>  |   <code class="option">--noent</code>  |   <code class="option">--noout</code>  |   <code class="option">--nonet</code>  |   <code class="option">--path "<em class="replaceable"><code>PATH(S)</code></em>"</code>  |   <code class="option">--load-trace</code>  |   <code class="option">--htmlout</code>  |   <code class="option">--nowrap</code>  |   <code class="option">--valid</code>  |   <code class="option">--postvalid</code>  |   <code class="option">--dtdvalid <em class="replaceable"><code>URL</code></em></code>  |   <code class="option">--dtdvalidfpi <em class="replaceable"><code>FPI</code></em></code>  |   <code class="option">--timing</code>  |   <code class="option">--output <em class="replaceable"><code>FILE</code></em></code>  |   <code class="option">--repeat</code>  |   <code class="option">--insert</code>  |   <code class="option">--compress</code>  |   <code class="option">--html</code>  |   <code class="option">--xmlout</code>  |   <code class="option">--push</code>  |   <code class="option">--memory</code>  |   <code class="option">--max-ampl <em class="replaceable"><code>INTEGER</code></em></code>  |   <code class="option">--maxmem <em class="replaceable"><code>NBBYTES</code></em></code>  |   <code class="option">--nowarning</code>  |   <code class="option">--noblanks</code>  |   <code class="option">--nocdata</code>  |   <code class="option">--format</code>  |   <code class="option">--encode <em class="replaceable"><code>ENCODING</code></em></code>  |   <code class="option">--dropdtd</code>  |   <code class="option">--nsclean</code>  |   <code class="option">--testIO</code>  |   <code class="option">--catalogs</code>  |   <code class="option">--nocatalogs</code>  |   <code class="option">--auto</code>  |   <code class="option">--xinclude</code>  |   <code class="option">--noxincludenode</code>  |   <code class="option">--loaddtd</code>  |   <code class="option">--dtdattr</code>  |   <code class="option">--stream</code>  |   <code class="option">--walker</code>  |   <code class="option">--pattern <em class="replaceable"><code>PATTERNVALUE</code></em></code>  |   <code class="option">--relaxng <em class="replaceable"><code>SCHEMA</code></em></code>  |   <code class="option">--schema <em class="replaceable"><code>SCHEMA</code></em></code>  |   <code class="option">--c14n</code>  |   <code class="option">--pedantic</code> ] { <em class="replaceable"><code>XML-FILE(S)</code></em>...  |   - }</p></div><div class="cmdsynopsis"><p><code class="command">xmllint</code>   <code class="option">--help</code> </p></div></div><div class="refsect1"><a name="description"></a><h2>DESCRIPTION</h2><p>
+<html><head><meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1"><title>xmllint</title><meta name="generator" content="DocBook XSL Stylesheets Vsnapshot"></head><body bgcolor="white" text="black" link="#0000FF" vlink="#840084" alink="#0000FF"><div class="refentry"><a name="id1337"></a><div class="titlepage"></div><div class="refnamediv"><h2>Name</h2><p>xmllint &#8212; command line <acronym class="acronym">XML</acronym> tool</p></div><div class="refsynopsisdiv"><h2>Synopsis</h2><div class="cmdsynopsis"><p><code class="command">xmllint</code>  [ <code class="option">--version</code>  |   <code class="option">--debug</code>  |   <code class="option">--quiet</code>  |   <code class="option">--shell</code>  |   <code class="option">--xpath "<em class="replaceable"><code>XPath_expression</code></em>"</code>  |   <code class="option">--debugent</code>  |   <code class="option">--copy</code>  |   <code class="option">--recover</code>  |   <code class="option">--huge</code>  |   <code class="option">--nocompact</code>  |   <code class="option">--nodefdtd</code>  |   <code class="option">--nodict</code>  |   <code class="option">--noenc</code>  |   <code class="option">--noent</code>  |   <code class="option">--nofixup-base-uris</code>  |   <code class="option">--noout</code>  |   <code class="option">--nonet</code>  |   <code class="option">--path "<em class="replaceable"><code>PATH(S)</code></em>"</code>  |   <code class="option">--load-trace</code>  |   <code class="option">--htmlout</code>  |   <code class="option">--nowrap</code>  |   <code class="option">--valid</code>  |   <code class="option">--postvalid</code>  |   <code class="option">--dtdvalid <em class="replaceable"><code>URL</code></em></code>  |   <code class="option">--dtdvalidfpi <em class="replaceable"><code>FPI</code></em></code>  |   <code class="option">--timing</code>  |   <code class="option">--output <em class="replaceable"><code>FILE</code></em></code>  |   <code class="option">--repeat</code>  |   <code class="option">--insert</code>  |   <code class="option">--compress</code>  |   <code class="option">--html</code>  |   <code class="option">--xmlout</code>  |   <code class="option">--push</code>  |   <code class="option">--memory</code>  |   <code class="option">--max-ampl <em class="replaceable"><code>INTEGER</code></em></code>  |   <code class="option">--maxmem <em class="replaceable"><code>NBBYTES</code></em></code>  |   <code class="option">--nowarning</code>  |   <code class="option">--noblanks</code>  |   <code class="option">--nocdata</code>  |   <code class="option">--format</code>  |   <code class="option">--pretty <em class="replaceable"><code>INTEGER</code></em></code>  |   <code class="option">--encode <em class="replaceable"><code>ENCODING</code></em></code>  |   <code class="option">--dropdtd</code>  |   <code class="option">--nsclean</code>  |   <code class="option">--testIO</code>  |   <code class="option">--catalogs</code>  |   <code class="option">--nocatalogs</code>  |   <code class="option">--auto</code>  |   <code class="option">--xinclude</code>  |   <code class="option">--noxincludenode</code>  |   <code class="option">--loaddtd</code>  |   <code class="option">--dtdattr</code>  |   <code class="option">--stream</code>  |   <code class="option">--walker</code>  |   <code class="option">--pattern <em class="replaceable"><code>PATTERNVALUE</code></em></code>  |   <code class="option">--relaxng <em class="replaceable"><code>SCHEMA</code></em></code>  |   <code class="option">--schema <em class="replaceable"><code>SCHEMA</code></em></code>  |   <code class="option">--schematron <em class="replaceable"><code>SCHEMA</code></em></code>  |   <code class="option">--c14n</code>  |   <code class="option">--c14n11</code>  |   <code class="option">--exc-c14n</code>  |   <code class="option">--pedantic</code>  |   <code class="option">--sax</code>  |   <code class="option">--sax1</code>  |   <code class="option">--oldxml10</code> ] { <em class="replaceable"><code>XML-FILE(S)</code></em>...  |   - }</p></div></div><div class="refsect1"><a name="description"></a><h2>DESCRIPTION</h2><p>
         The <span class="command"><strong>xmllint</strong></span> program parses one or more <acronym class="acronym">XML</acronym> files,
         specified on the command line as <em class="replaceable"><code>XML-FILE</code></em>
         (or the standard input if the filename provided
@@ -15,7 +15,7 @@
                     <code class="filename">${sysconfdir}/xml/catalog</code> are used by default.
                 </p></dd><dt><span class="term"><code class="option">--compress</code></span></dt><dd><p>
                     Turn on <span class="citerefentry"><span class="refentrytitle">gzip</span>(1)</span> compression of output.
-                </p></dd><dt><span class="term"><code class="option">--copy</code></span></dt><dd><p>Test the internal copy implementation.</p></dd><dt><span class="term"><code class="option">--c14n</code></span></dt><dd><p>
+                </p></dd><dt><span class="term"><code class="option">--copy</code></span></dt><dd><p>Test the internal copy implementation.</p></dd><dt><span class="term"><code class="option">--c14n</code>, </span><span class="term"><code class="option">--c14n11</code>, </span><span class="term"><code class="option">--exc-c14n</code></span></dt><dd><p>
                     Use the W3C <acronym class="acronym">XML</acronym> Canonicalisation (<acronym class="acronym">C14N</acronym>) to
                     serialize the result of parsing to <code class="filename">stdout</code>.
                     It keeps comments in the result.
@@ -36,12 +36,12 @@
                     Reformat and reindent the output. The <code class="envar">XMLLINT_INDENT</code>
                     environment variable controls the indentation. The default value is two
                     spaces "  ").
-                </p></dd><dt><span class="term"><code class="option">--help</code></span></dt><dd><p>Print out a short usage summary for <span class="command"><strong>xmllint</strong></span>.</p></dd><dt><span class="term"><code class="option">--html</code></span></dt><dd><p>Use the <acronym class="acronym">HTML</acronym> parser.</p></dd><dt><span class="term"><code class="option">--htmlout</code></span></dt><dd><p>
+                </p></dd><dt><span class="term"><code class="option">--html</code></span></dt><dd><p>Use the <acronym class="acronym">HTML</acronym> parser.</p></dd><dt><span class="term"><code class="option">--htmlout</code></span></dt><dd><p>
                     Output results as an <acronym class="acronym">HTML</acronym> file. This
                     causes <span class="command"><strong>xmllint</strong></span> to output the necessary <acronym class="acronym">HTML</acronym>
                     tags surrounding the result tree output so the results can be
                     displayed/viewed in a browser.
-                </p></dd><dt><span class="term"><code class="option">--insert</code></span></dt><dd><p>Test for valid insertions.</p></dd><dt><span class="term"><code class="option">--loaddtd</code></span></dt><dd><p>Fetch an external <acronym class="acronym">DTD</acronym>.</p></dd><dt><span class="term"><code class="option">--load-trace</code></span></dt><dd><p>
+                </p></dd><dt><span class="term"><code class="option">--huge</code></span></dt><dd><p>Ignore some hardcoded parser limits.</p></dd><dt><span class="term"><code class="option">--insert</code></span></dt><dd><p>Test for valid insertions.</p></dd><dt><span class="term"><code class="option">--loaddtd</code></span></dt><dd><p>Fetch an external <acronym class="acronym">DTD</acronym>.</p></dd><dt><span class="term"><code class="option">--load-trace</code></span></dt><dd><p>
                     Display all the documents loaded during the processing
                     to <code class="filename">stderr</code>.
                 </p></dd><dt><span class="term"><code class="option">--max-ampl <em class="replaceable"><code>INTEGER</code></em></code></span></dt><dd><p>
@@ -55,19 +55,34 @@
                     This can also be used to make sure batch processing
                     of <acronym class="acronym">XML</acronym> files will not exhaust the virtual memory
                     of the server running them.
-                </p></dd><dt><span class="term"><code class="option">--memory</code></span></dt><dd><p>Parse from memory.</p></dd><dt><span class="term"><code class="option">--noblanks</code></span></dt><dd><p>Drop ignorable blank spaces.</p></dd><dt><span class="term"><code class="option">--nocatalogs</code></span></dt><dd><p>Do not use any catalogs.</p></dd><dt><span class="term"><code class="option">--nocdata</code></span></dt><dd><p>Substitute CDATA section by equivalent text nodes.</p></dd><dt><span class="term"><code class="option">--nodict</code></span></dt><dd><p>
+                </p></dd><dt><span class="term"><code class="option">--memory</code></span></dt><dd><p>Parse from memory.</p></dd><dt><span class="term"><code class="option">--noblanks</code></span></dt><dd><p>Drop ignorable blank spaces.</p></dd><dt><span class="term"><code class="option">--nocatalogs</code></span></dt><dd><p>Do not use any catalogs.</p></dd><dt><span class="term"><code class="option">--nocdata</code></span></dt><dd><p>Substitute CDATA section by equivalent text nodes.</p></dd><dt><span class="term"><code class="option">--nocompact</code></span></dt><dd><p>
+                    Do not generate compact text nodes (parser option
+                    XML_PARSE_COMPACT). Only for debugging.
+                </p></dd><dt><span class="term"><code class="option">--nodefdtd</code></span></dt><dd><p>
+                    Do not set default HTML doctype (parser option
+                    HTML_PARSE_NODEFDTD).
+                </p></dd><dt><span class="term"><code class="option">--nodict</code></span></dt><dd><p>
                     Don't use dictionaries (parser option XML_PARSE_NODICT).
                     Only for debugging.
+                </p></dd><dt><span class="term"><code class="option">--noenc</code></span></dt><dd><p>
+                    Ignore encoding declaration (parser option
+                    XML_PARSE_IGNORE_ENC).
                 </p></dd><dt><span class="term"><code class="option">--noent</code></span></dt><dd><p>
                     Substitute entity values for entity references. By default, <span class="command"><strong>xmllint</strong></span>
                     leaves entity references in place.
+                </p></dd><dt><span class="term"><code class="option">--nofixup-base-uris</code></span></dt><dd><p>
+                    Don't fix xml:base URIs when processing XIncludes
+                    (parser option XML_PARSE_NOBASEFIX).
                 </p></dd><dt><span class="term"><code class="option">--nonet</code></span></dt><dd><p>
                     Do not use the Internet to fetch <acronym class="acronym">DTD</acronym>s or entities.
                 </p></dd><dt><span class="term"><code class="option">--noout</code></span></dt><dd><p>
                     Suppress output. By default, <span class="command"><strong>xmllint</strong></span> outputs the result tree.
                 </p></dd><dt><span class="term"><code class="option">--nowarning</code></span></dt><dd><p>Do not emit warnings from the parser and/or validator.</p></dd><dt><span class="term"><code class="option">--nowrap</code></span></dt><dd><p>Do not output <acronym class="acronym">HTML</acronym> doc wrapper.</p></dd><dt><span class="term"><code class="option">--noxincludenode</code></span></dt><dd><p>
                     Do XInclude processing but do not generate XInclude start and end nodes.
-                </p></dd><dt><span class="term"><code class="option">--nsclean</code></span></dt><dd><p>Remove redundant namespace declarations.</p></dd><dt><span class="term"><code class="option">--output <em class="replaceable"><code>FILE</code></em></code></span></dt><dd><p>
+                </p></dd><dt><span class="term"><code class="option">--nsclean</code></span></dt><dd><p>Remove redundant namespace declarations.</p></dd><dt><span class="term"><code class="option">--oldxml10</code></span></dt><dd><p>
+                    Use deprecated parsing rules before XML 1.0,
+                    5th edition.
+                </p></dd><dt><span class="term"><code class="option">--output <em class="replaceable"><code>FILE</code></em></code></span></dt><dd><p>
                     Define a file path where <span class="command"><strong>xmllint</strong></span> will save the result of parsing.
                     Usually the programs build a tree and save it
                     on <code class="filename">stdout</code>, with this option
@@ -81,12 +96,18 @@
                     with the reader interface to the parser. It allows to select some
                     nodes in the document based on an XPath (subset) expression. Used
                     for debugging.
-                </p></dd><dt><span class="term"><code class="option">--pedantic</code></span></dt><dd><p>Enable additional warnings.</p></dd><dt><span class="term"><code class="option">--postvalid</code></span></dt><dd><p>Validate after parsing has completed.</p></dd><dt><span class="term"><code class="option">--push</code></span></dt><dd><p>Use the push mode of the parser.</p></dd><dt><span class="term"><code class="option">--quiet</code></span></dt><dd><p>Don't print informational messages to stderr.</p></dd><dt><span class="term"><code class="option">--recover</code></span></dt><dd><p>Output any parsable portions of an invalid document.</p></dd><dt><span class="term"><code class="option">--relaxng <em class="replaceable"><code>SCHEMA</code></em></code></span></dt><dd><p>
+                </p></dd><dt><span class="term"><code class="option">--pedantic</code></span></dt><dd><p>Enable additional warnings.</p></dd><dt><span class="term"><code class="option">--postvalid</code></span></dt><dd><p>Validate after parsing has completed.</p></dd><dt><span class="term"><code class="option">--pretty <em class="replaceable"><code>INTEGER</code></em></code></span></dt><dd><p>
+                    Value 0 means no formatting, 1 means XML_SAVE_FORMAT
+                    (same as --format), 2 means XML_SAVE_WSNONSIG.
+                </p></dd><dt><span class="term"><code class="option">--push</code></span></dt><dd><p>Use the push mode of the parser.</p></dd><dt><span class="term"><code class="option">--quiet</code></span></dt><dd><p>Don't print informational messages to stderr.</p></dd><dt><span class="term"><code class="option">--recover</code></span></dt><dd><p>Output any parsable portions of an invalid document.</p></dd><dt><span class="term"><code class="option">--relaxng <em class="replaceable"><code>SCHEMA</code></em></code></span></dt><dd><p>
                     Use RelaxNG file named <em class="replaceable"><code>SCHEMA</code></em>
                     for validation.
-                </p></dd><dt><span class="term"><code class="option">--repeat</code></span></dt><dd><p>Repeat 100 times, for timing or profiling.</p></dd><dt><span class="term"><code class="option">--schema <em class="replaceable"><code>SCHEMA</code></em></code></span></dt><dd><p>
+                </p></dd><dt><span class="term"><code class="option">--repeat</code></span></dt><dd><p>Repeat 100 times, for timing or profiling.</p></dd><dt><span class="term"><code class="option">--sax</code></span></dt><dd><p>Print SAX callbacks (only for debugging).</p></dd><dt><span class="term"><code class="option">--sax1</code></span></dt><dd><p>Use deprecated SAX1 interface (only for debugging).</p></dd><dt><span class="term"><code class="option">--schema <em class="replaceable"><code>SCHEMA</code></em></code></span></dt><dd><p>
                     Use a W3C <acronym class="acronym">XML</acronym> Schema file
                     named <em class="replaceable"><code>SCHEMA</code></em> for validation.
+                </p></dd><dt><span class="term"><code class="option">--schematron <em class="replaceable"><code>SCHEMA</code></em></code></span></dt><dd><p>
+                    Use a Schematron file
+                    named <em class="replaceable"><code>SCHEMA</code></em> for validation.
                 </p></dd><dt><span class="term"><code class="option">--shell</code></span></dt><dd><p>
                     Run a navigating shell. Details on available commands in shell mode
                     are below (see <a class="xref" href="#shell" title="SHELL COMMANDS">the section called &#8220;SHELL COMMANDS&#8221;</a>).
diff --git a/doc/xmllint.xml b/doc/xmllint.xml
index 547bf678..3de2b875 100644
--- a/doc/xmllint.xml
+++ b/doc/xmllint.xml
@@ -283,6 +283,10 @@
                     environment variable controls the indentation. The default value is two
                     spaces &quot;  &quot;).
                 </para>
+                <para>
+                    Especially in the absence of a DTD, this feature has never worked reliably
+                    and is fundamentally broken.
+                </para>
             </listitem>
         </varlistentry>
 
diff --git a/encoding.c b/encoding.c
index 1c69d7a9..e808cf4e 100644
--- a/encoding.c
+++ b/encoding.c
@@ -45,6 +45,7 @@
 #include "private/enc.h"
 #include "private/entities.h"
 #include "private/error.h"
+#include "private/memory.h"
 
 #ifdef LIBXML_ICU_ENABLED
 #include <unicode/ucnv.h>
@@ -213,9 +214,9 @@ static const xmlCharEncodingHandler defaultHandlers[31] = {
     MAKE_HANDLER("UCS-4LE", NULL, NULL),
     MAKE_HANDLER("UCS-4BE", NULL, NULL),
     MAKE_HANDLER("IBM037", NULL, NULL),
-    MAKE_HANDLER("ISO-10646-UCS-4", NULL, NULL), /* UCS4_2143 */
-    MAKE_HANDLER("ISO-10646-UCS-4", NULL, NULL), /* UCS4_2143 */
-    MAKE_HANDLER("ISO-10646-UCS-2", NULL, NULL),
+    MAKE_HANDLER(NULL, NULL, NULL), /* UCS4_2143 */
+    MAKE_HANDLER(NULL, NULL, NULL), /* UCS4_3412 */
+    MAKE_HANDLER("UCS-2", NULL, NULL),
     MAKE_HANDLER("ISO-8859-1", latin1ToUTF8, UTF8ToLatin1),
     MAKE_ISO_HANDLER("ISO-8859-2", 2),
     MAKE_ISO_HANDLER("ISO-8859-3", 3),
@@ -286,12 +287,6 @@ xmlDetectCharEncoding(const unsigned char* in, int len)
 	if ((in[0] == 0x3C) && (in[1] == 0x00) &&
 	    (in[2] == 0x00) && (in[3] == 0x00))
 	    return(XML_CHAR_ENCODING_UCS4LE);
-	if ((in[0] == 0x00) && (in[1] == 0x00) &&
-	    (in[2] == 0x3C) && (in[3] == 0x00))
-	    return(XML_CHAR_ENCODING_UCS4_2143);
-	if ((in[0] == 0x00) && (in[1] == 0x3C) &&
-	    (in[2] == 0x00) && (in[3] == 0x00))
-	    return(XML_CHAR_ENCODING_UCS4_3412);
 	if ((in[0] == 0x4C) && (in[1] == 0x6F) &&
 	    (in[2] == 0xA7) && (in[3] == 0x94))
 	    return(XML_CHAR_ENCODING_EBCDIC);
@@ -424,13 +419,13 @@ xmlAddEncodingAlias(const char *name, const char *alias) {
 
     if (xmlCharEncodingAliasesNb >= xmlCharEncodingAliasesMax) {
         xmlCharEncodingAliasPtr tmp;
-        size_t newSize = xmlCharEncodingAliasesMax ?
-                         xmlCharEncodingAliasesMax * 2 :
-                         20;
+        int newSize;
 
-        tmp = (xmlCharEncodingAliasPtr)
-              xmlRealloc(xmlCharEncodingAliases,
-                         newSize * sizeof(xmlCharEncodingAlias));
+        newSize = xmlGrowCapacity(xmlCharEncodingAliasesMax, sizeof(tmp[0]),
+                                  20, XML_MAX_ITEMS);
+        if (newSize < 0)
+            return(-1);
+        tmp = xmlRealloc(xmlCharEncodingAliases, newSize * sizeof(tmp[0]));
         if (tmp == NULL)
             return(-1);
         xmlCharEncodingAliases = tmp;
@@ -572,9 +567,9 @@ xmlGetCharEncodingName(xmlCharEncoding enc) {
         case XML_CHAR_ENCODING_UTF16BE:
 	    return("UTF-16");
         case XML_CHAR_ENCODING_UCS4LE:
-            return("ISO-10646-UCS-4");
+            return("UCS-4");
         case XML_CHAR_ENCODING_UCS4BE:
-            return("ISO-10646-UCS-4");
+            return("UCS-4");
         default:
             break;
     }
@@ -1122,6 +1117,14 @@ xmlIconvConvert(unsigned char *out, int *outlen,
          */
         if (errno == EINVAL)
             return(XML_ENC_ERR_SUCCESS);
+#ifdef __APPLE__
+        /*
+         * Apple's new libiconv can return EOPNOTSUPP under
+         * unknown circumstances (detected when fuzzing).
+         */
+        if (errno == EOPNOTSUPP)
+            return(XML_ENC_ERR_INPUT);
+#endif
         return(XML_ENC_ERR_INTERNAL);
     }
     return(XML_ENC_ERR_SUCCESS);
@@ -1145,6 +1148,38 @@ xmlCharEncIconv(void *vctxt, const char *name, xmlCharEncConverter *conv) {
     iconv_t icv_out;
     int ret;
 
+    /*
+     * POSIX allows "indicator suffixes" like "//IGNORE" to be
+     * passed to iconv_open. This can change the behavior in
+     * unexpected ways.
+     *
+     * Many iconv implementations also support non-standard
+     * codesets like "wchar_t", "char" or the empty string "".
+     * It would make sense to disallow them, but codeset names
+     * are matched fuzzily, so a string like "w-C.hA_rt" could
+     * be interpreted as "wchar_t".
+     *
+     * When escaping characters that aren't supported in the
+     * target encoding, we also rely on GNU libiconv behavior to
+     * stop conversion without trying any kind of fallback.
+     * This violates the POSIX spec which says:
+     *
+     * > If iconv() encounters a character in the input buffer
+     * > that is valid, but for which an identical character does
+     * > not exist in the output codeset [...] iconv() shall
+     * > perform an implementation-defined conversion on the
+     * > character.
+     *
+     * See: https://sourceware.org/bugzilla/show_bug.cgi?id=29913
+     *
+     * Unfortunately, strict POSIX compliance makes it impossible
+     * to detect untranslatable characters.
+     */
+    if (strstr(name, "//") != NULL) {
+        ret = XML_ERR_UNSUPPORTED_ENCODING;
+        goto error;
+    }
+
     inputCtxt = xmlMalloc(sizeof(xmlIconvCtxt));
     if (inputCtxt == NULL) {
         ret = XML_ERR_NO_MEMORY;
@@ -1228,7 +1263,7 @@ struct _uconv_t {
 
 /**
  * xmlUconvConvert:
- * @vctxt:  converison context
+ * @vctxt:  conversion context
  * @out:  a pointer to an array of bytes to store the result
  * @outlen:  the length of @out
  * @in:  a pointer to an array of input bytes
diff --git a/entities.c b/entities.c
index 3b36a2da..a5c814c3 100644
--- a/entities.c
+++ b/entities.c
@@ -28,6 +28,11 @@
 
 #include "private/entities.h"
 #include "private/error.h"
+#include "private/parser.h"
+
+#ifndef SIZE_MAX
+  #define SIZE_MAX ((size_t) -1)
+#endif
 
 /*
  * The XML predefined entities.
@@ -512,6 +517,17 @@ xmlGetDocEntity(const xmlDoc *doc, const xmlChar *name) {
     return(xmlGetPredefinedEntity(name));
 }
 
+/*
+ * xmlSerializeHexCharRef:
+ * @buf:  a char buffer
+ * @val:  a codepoint
+ *
+ * Serializes a hex char ref like &#xA0;
+ *
+ * Writes at most 9 bytes. Does not include a terminating zero byte.
+ *
+ * Returns the number of bytes written.
+ */
 int
 xmlSerializeHexCharRef(char *buf, int val) {
     char *out = buf;
@@ -549,6 +565,17 @@ xmlSerializeHexCharRef(char *buf, int val) {
     return(out - buf);
 }
 
+/*
+ * xmlSerializeDecCharRef:
+ * @buf:  a char buffer
+ * @val:  a codepoint
+ *
+ * Serializes a decimal char ref like &#38;
+ *
+ * Writes at most 10 bytes. Does not include a terminating zero byte.
+ *
+ * Returns the number of bytes written.
+ */
 int
 xmlSerializeDecCharRef(char *buf, int val) {
     char *out = buf;
@@ -588,6 +615,21 @@ static const char xmlEscapeSafe[128] = {
     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
 };
 
+/*
+ * xmlEscapeText:
+ * @text:  input text
+ * @flags:  XML_ESCAPE flags
+ *
+ * Escapes certain characters with char refs.
+ *
+ * XML_ESCAPE_ATTR: for attribute content.
+ * XML_ESCAPE_NON_ASCII: escape non-ASCII chars.
+ * XML_ESCAPE_HTML: for HTML content.
+ * XML_ESCAPE_QUOT: escape double quotes.
+ * XML_ESCAPE_ALLOW_INVALID: allow invalid characters.
+ *
+ * Returns an escaped string or NULL if a memory allocation failed.
+ */
 xmlChar *
 xmlEscapeText(const xmlChar *text, int flags) {
     const xmlChar *cur;
@@ -685,7 +727,7 @@ xmlEscapeText(const xmlChar *text, int flags) {
 
             replSize = xmlSerializeHexCharRef(buf, val);
             repl = BAD_CAST buf;
-	} else if ((flags & XML_ESCAPE_ALLOW_INVALID) ||
+	} else if ((flags & (XML_ESCAPE_ALLOW_INVALID | XML_ESCAPE_HTML)) ||
                    (c >= 0x20) ||
 	           (c == '\n') || (c == '\t') || (c == '\r')) {
 	    /* default case, just copy */
@@ -710,16 +752,23 @@ xmlEscapeText(const xmlChar *text, int flags) {
 
         if (totalSize > size - used) {
             xmlChar *tmp;
+            int newSize;
 
-            size += totalSize;
+            if ((size > (SIZE_MAX - 1) / 2) ||
+                (totalSize > (SIZE_MAX - 1) / 2 - size)) {
+                xmlFree(buffer);
+                return(NULL);
+            }
+            newSize = size + totalSize;
             if (*cur != 0)
-                size *= 2;
-            tmp = xmlRealloc(buffer, size + 1);
+                newSize *= 2;
+            tmp = xmlRealloc(buffer, newSize + 1);
             if (tmp == NULL) {
                 xmlFree(buffer);
                 return(NULL);
             }
             buffer = tmp;
+            size = newSize;
             out = buffer + used;
         }
 
@@ -739,7 +788,7 @@ xmlEscapeText(const xmlChar *text, int flags) {
  * xmlEncodeEntitiesInternal:
  * @doc:  the document containing the string
  * @input:  A string to convert to XML.
- * @attr: are we handling an attribute value
+ * @flags:  XML_ESCAPE flags
  *
  * Do a global encoding of a string, replacing the predefined entities
  * and non ASCII values with their entities and CharRef counterparts.
diff --git a/error.c b/error.c
index fc28bb69..fc5c6dec 100644
--- a/error.c
+++ b/error.c
@@ -20,6 +20,37 @@
 #include "private/globals.h"
 #include "private/string.h"
 
+/**
+ * xmlIsCatastrophicError:
+ * @level:  error level
+ * @code:  error code
+ *
+ * Returns true if an error is catastrophic.
+ */
+int
+xmlIsCatastrophicError(int level, int code) {
+    int fatal = 0;
+
+    if (level != XML_ERR_FATAL)
+        return(0);
+
+    switch (code) {
+        case XML_ERR_NO_MEMORY:
+        /* case XML_ERR_RESOURCE_LIMIT: */
+        case XML_ERR_SYSTEM:
+        case XML_ERR_ARGUMENT:
+        case XML_ERR_INTERNAL_ERROR:
+            fatal = 1;
+            break;
+        default:
+            if ((code >= 1500) && (code <= 1599))
+                fatal = 1;
+            break;
+    }
+
+    return(fatal);
+}
+
 /************************************************************************
  *									*
  *			Error struct					*
@@ -750,7 +781,7 @@ xmlVRaiseError(xmlStructuredErrorFunc schannel,
  * @channel: the old callback channel
  * @data: the callback data
  * @ctx: the parser context or NULL
- * @nod: the node or NULL
+ * @node: the node or NULL
  * @domain: the domain for the error
  * @code: the code for the error
  * @level: the xmlErrorLevel for the error
@@ -1329,11 +1360,25 @@ xmlErrString(xmlParserErrors code) {
     return(errmsg);
 }
 
+/**
+ * xmlVPrintErrorMessage:
+ * @fmt:  printf format string
+ * @ap:  arguments
+ *
+ * Prints to stderr.
+ */
 void
 xmlVPrintErrorMessage(const char *fmt, va_list ap) {
     vfprintf(stderr, fmt, ap);
 }
 
+/**
+ * xmlPrintErrorMessage:
+ * @fmt:  printf format string
+ * @...:  arguments
+ *
+ * Prints to stderr.
+ */
 void
 xmlPrintErrorMessage(const char *fmt, ...) {
     va_list ap;
@@ -1343,6 +1388,13 @@ xmlPrintErrorMessage(const char *fmt, ...) {
     va_end(ap);
 }
 
+/**
+ * xmlAbort:
+ * @fmt:  printf format string
+ * @...:  arguments
+ *
+ * Print message to stderr and abort.
+ */
 void
 xmlAbort(const char *fmt, ...) {
     va_list ap;
diff --git a/example/icu.c b/example/icu.c
new file mode 100644
index 00000000..80c9637b
--- /dev/null
+++ b/example/icu.c
@@ -0,0 +1,241 @@
+/*
+ * icu.c: Example how to use ICU for character encoding conversion
+ *
+ * This example shows how to use ICU by installing a custom character
+ * encoding converter with xmlCtxtSetCharEncConvImpl, available
+ * since libxml2 2.14.
+ *
+ * This approach makes it possible to use ICU even if libxml2 is
+ * compiled without ICU support. It also makes sure that *only* ICU
+ * is used. Many Linux distros currently ship libxml2 with support
+ * for both ICU and iconv which makes the library's behavior hard to
+ * predict.
+ *
+ * The long-term plan is to make libxml2 only support a single
+ * conversion library internally (iconv on POSIX).
+ */
+
+#include <stdio.h>
+#include <libxml/parser.h>
+#include <unicode/ucnv.h>
+
+#define ICU_PIVOT_BUF_SIZE 1024
+
+typedef struct {
+    UConverter *uconv; /* for conversion between an encoding and UTF-16 */
+    UConverter *utf8; /* for conversion between UTF-8 and UTF-16 */
+    UChar      *pivot_source;
+    UChar      *pivot_target;
+    int        isInput;
+    UChar      pivot_buf[ICU_PIVOT_BUF_SIZE];
+} myConvCtxt;
+
+static int
+icuConvert(unsigned char *out, int *outlen,
+           const unsigned char *in, int *inlen, void *vctxt) {
+    myConvCtxt *cd = vctxt;
+    const char *ucv_in = (const char *) in;
+    char *ucv_out = (char *) out;
+    UConverter *target, *source;
+    UErrorCode err = U_ZERO_ERROR;
+    int ret;
+
+    if ((out == NULL) || (outlen == NULL) || (inlen == NULL) || (in == NULL)) {
+        if (outlen != NULL)
+            *outlen = 0;
+        return XML_ENC_ERR_INTERNAL;
+    }
+
+    /*
+     * Note that the ICU API is stateful. It can always consume a certain
+     * amount of input even if the output buffer would overflow. The
+     * remaining input must be processed by calling ucnv_convertEx with a
+     * possibly empty input buffer.
+     *
+     * ucnv_convertEx is always called with reset and flush set to 0,
+     * so we don't mess up the state. This should never generate
+     * U_TRUNCATED_CHAR_FOUND errors.
+     */
+    if (cd->isInput) {
+        source = cd->uconv;
+        target = cd->utf8;
+    } else {
+        source = cd->utf8;
+        target = cd->uconv;
+    }
+
+    ucnv_convertEx(target, source, &ucv_out, ucv_out + *outlen,
+                   &ucv_in, ucv_in + *inlen, cd->pivot_buf,
+                   &cd->pivot_source, &cd->pivot_target,
+                   cd->pivot_buf + ICU_PIVOT_BUF_SIZE, 0, 0, &err);
+
+    *inlen = ucv_in - (const char*) in;
+    *outlen = ucv_out - (char *) out;
+
+    if (U_SUCCESS(err)) {
+        ret = XML_ENC_ERR_SUCCESS;
+    } else {
+        switch (err) {
+            case U_TRUNCATED_CHAR_FOUND:
+                /* Shouldn't happen without flush */
+                ret = XML_ENC_ERR_SUCCESS;
+                break;
+
+            case U_BUFFER_OVERFLOW_ERROR:
+                ret = XML_ENC_ERR_SPACE;
+                break;
+
+            case U_INVALID_CHAR_FOUND:
+            case U_ILLEGAL_CHAR_FOUND:
+            case U_ILLEGAL_ESCAPE_SEQUENCE:
+            case U_UNSUPPORTED_ESCAPE_SEQUENCE:
+                ret = XML_ENC_ERR_INPUT;
+                break;
+
+            case U_MEMORY_ALLOCATION_ERROR:
+                ret = XML_ENC_ERR_MEMORY;
+                break;
+
+            default:
+                ret = XML_ENC_ERR_INTERNAL;
+                break;
+        }
+    }
+
+    return ret;
+}
+
+static int
+icuOpen(const char* name, int isInput, myConvCtxt **out)
+{
+    UErrorCode status;
+    myConvCtxt *cd;
+
+    *out = NULL;
+
+    cd = xmlMalloc(sizeof(myConvCtxt));
+    if (cd == NULL)
+        return XML_ERR_NO_MEMORY;
+
+    cd->isInput = isInput;
+    cd->pivot_source = cd->pivot_buf;
+    cd->pivot_target = cd->pivot_buf;
+
+    status = U_ZERO_ERROR;
+    cd->uconv = ucnv_open(name, &status);
+    if (U_FAILURE(status))
+        goto error;
+
+    status = U_ZERO_ERROR;
+    if (isInput) {
+        ucnv_setToUCallBack(cd->uconv, UCNV_TO_U_CALLBACK_STOP,
+                            NULL, NULL, NULL, &status);
+    }
+    else {
+        ucnv_setFromUCallBack(cd->uconv, UCNV_FROM_U_CALLBACK_STOP,
+                              NULL, NULL, NULL, &status);
+    }
+    if (U_FAILURE(status))
+        goto error;
+
+    status = U_ZERO_ERROR;
+    cd->utf8 = ucnv_open("UTF-8", &status);
+    if (U_FAILURE(status))
+        goto error;
+
+    *out = cd;
+    return 0;
+
+error:
+    if (cd->uconv)
+        ucnv_close(cd->uconv);
+    xmlFree(cd);
+
+    if (status == U_FILE_ACCESS_ERROR)
+        return XML_ERR_UNSUPPORTED_ENCODING;
+    if (status == U_MEMORY_ALLOCATION_ERROR)
+        return XML_ERR_NO_MEMORY;
+    return XML_ERR_SYSTEM;
+}
+
+static void
+icuClose(myConvCtxt *cd)
+{
+    if (cd == NULL)
+        return;
+    ucnv_close(cd->uconv);
+    ucnv_close(cd->utf8);
+    xmlFree(cd);
+}
+
+static void
+icuConvCtxtDtor(void *vctxt) {
+    icuClose(vctxt);
+}
+
+static int
+icuConvImpl(void *vctxt, const char *name,
+            xmlCharEncConverter *conv) {
+    myConvCtxt *inputCtxt = NULL;
+    myConvCtxt *outputCtxt = NULL;
+    int ret;
+
+    ret = icuOpen(name, 1, &inputCtxt);
+    if (ret != 0)
+        goto error;
+    ret = icuOpen(name, 0, &outputCtxt);
+    if (ret != 0)
+        goto error;
+
+    conv->input = icuConvert;
+    conv->output = icuConvert;
+    conv->ctxtDtor = icuConvCtxtDtor;
+    conv->inputCtxt = inputCtxt;
+    conv->outputCtxt = outputCtxt;
+
+    return XML_ERR_OK;
+
+error:
+    if (inputCtxt != NULL)
+        icuClose(inputCtxt);
+    if (outputCtxt != NULL)
+        icuClose(outputCtxt);
+    return ret;
+}
+
+int
+main(void) {
+    xmlParserCtxtPtr ctxt;
+    xmlDocPtr doc;
+    const char *xml;
+    xmlChar *content;
+    int ret = 0;
+
+    /*
+     * We use IBM-1051, an alias for HP Roman, as a simple example that
+     * ICU supports, but iconv (typically) doesn't.
+     *
+     * Character code 0xDE is U+00DF Latin Small Letter Sharp S.
+     */
+    xml = "<doc>\xDE</doc>";
+
+    ctxt = xmlNewParserCtxt();
+    xmlCtxtSetCharEncConvImpl(ctxt, icuConvImpl, NULL);
+    doc = xmlCtxtReadDoc(ctxt, BAD_CAST xml, NULL, "IBM-1051", 0);
+    xmlFreeParserCtxt(ctxt);
+
+    content = xmlNodeGetContent((xmlNodePtr) doc);
+
+    printf("content: %s\n", content);
+
+    if (!xmlStrEqual(content, BAD_CAST "\xC3\x9F")) {
+        fprintf(stderr, "conversion failed\n");
+        ret = 1;
+    }
+
+    xmlFree(content);
+    xmlFreeDoc(doc);
+
+    return ret;
+}
+
diff --git a/fuzz/Makefile.am b/fuzz/Makefile.am
index e85452bc..373aa26f 100644
--- a/fuzz/Makefile.am
+++ b/fuzz/Makefile.am
@@ -143,7 +143,7 @@ seed/lint.stamp: genSeed$(EXEEXT)
 	./genSeed$(EXEEXT) lint $(XML_SEED_CORPUS_SRC)
 	@touch seed/lint.stamp
 
-lint_SOURCES = lint.c fuzz.c
+lint_SOURCES = lint.c fuzz.c ../xmllint.c ../shell.c
 lint_LDFLAGS = -fsanitize=fuzzer
 
 fuzz-lint: lint$(EXEEXT) seed/lint.stamp
diff --git a/fuzz/api.c b/fuzz/api.c
index 49bebcb1..0bbe8ce7 100644
--- a/fuzz/api.c
+++ b/fuzz/api.c
@@ -970,7 +970,7 @@ LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED,
 
 int
 LLVMFuzzerTestOneInput(const char *data, size_t size) {
-    size_t maxAlloc;
+    size_t failurePos;
     int i;
 
     if (size > 1000)
@@ -980,8 +980,8 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
 
     xmlFuzzDataInit(data, size);
 
-    maxAlloc = xmlFuzzReadInt(4) % (size * 50 + 10);
-    xmlFuzzMemSetLimit(maxAlloc);
+    failurePos = xmlFuzzReadInt(4) % (size * 50 + 10);
+    xmlFuzzInjectFailure(failurePos);
 
     /*
      * Interpreter loop
@@ -1002,6 +1002,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
         size_t readSize;
         int op = xmlFuzzReadInt(1);
         int oomReport = -1; /* -1 means unknown */
+        int ioReport = 0;
 
         vars->opName = "[unset]";
 
@@ -1804,7 +1805,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
                     node,
                     BAD_CAST "lang",
                     XML_XML_NAMESPACE);
-                xmlFuzzResetMallocFailed();
+                xmlFuzzResetFailure();
                 removeChildren((xmlNodePtr) attr, 0);
                 res = xmlNodeSetLang(
                     node,
@@ -1838,7 +1839,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
                     node,
                     BAD_CAST "space",
                     XML_XML_NAMESPACE);
-                xmlFuzzResetMallocFailed();
+                xmlFuzzResetFailure();
                 removeChildren((xmlNodePtr) attr, 0);
                 res = xmlNodeSetSpacePreserve(
                     node,
@@ -1890,7 +1891,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
                     node,
                     BAD_CAST "base",
                     XML_XML_NAMESPACE);
-                xmlFuzzResetMallocFailed();
+                xmlFuzzResetFailure();
                 removeChildren((xmlNodePtr) attr, 0);
                 res = xmlNodeSetBase(
                     node,
@@ -2029,7 +2030,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
                     oldAttr = xmlHasNsProp(node, name, NULL);
                 else
                     oldAttr = xmlHasNsProp(node, localName, ns->href);
-                xmlFuzzResetMallocFailed();
+                xmlFuzzResetFailure();
                 if (oldAttr != NULL)
                     removeChildren((xmlNodePtr) oldAttr, 0);
 
@@ -2056,7 +2057,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
                 name = getStr(0);
                 value = getStr(1);
                 oldAttr = xmlHasNsProp(node, name, ns ? ns->href : NULL);
-                xmlFuzzResetMallocFailed();
+                xmlFuzzResetFailure();
                 if (oldAttr != NULL)
                     removeChildren((xmlNodePtr) oldAttr, 0);
                 attr = xmlSetNsProp(node, ns, name, value);
@@ -2105,7 +2106,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
                 node = getNode(0);
                 name = getStr(0);
                 attr = xmlHasNsProp(node, name, NULL);
-                xmlFuzzResetMallocFailed();
+                xmlFuzzResetFailure();
                 if (attr != NULL)
                     removeChildren((xmlNodePtr) attr, 1);
                 setInt(0, xmlUnsetProp(node, name));
@@ -2127,7 +2128,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
                 ns = nodeGetNs(getNode(1), getInt(1));
                 name = getStr(0);
                 attr = xmlHasNsProp(node, name, ns ? ns->href : NULL);
-                xmlFuzzResetMallocFailed();
+                xmlFuzzResetFailure();
                 if (attr != NULL)
                     removeChildren((xmlNodePtr) attr, 1);
                 setInt(0, xmlUnsetNsProp(node, ns, name));
@@ -2389,7 +2390,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
                         xmlAttrPtr attr = xmlHasNsProp(parent, node->name,
                             node->ns ? node->ns->href : NULL);
 
-                        xmlFuzzResetMallocFailed();
+                        xmlFuzzResetFailure();
                         /* Attribute might be replaced */
                         if (attr != NULL && attr != (xmlAttrPtr) node)
                             removeChildren((xmlNodePtr) attr, 1);
@@ -3016,7 +3017,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
                 node = getNode(0);
                 type = node ? node->type : 0;
                 xmlValidCtxtPtr vctxt = xmlNewValidCtxt();
-                xmlFuzzResetMallocFailed();
+                xmlFuzzResetFailure();
 
                 switch (type) {
                     case XML_DOCUMENT_NODE:
@@ -3178,7 +3179,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
 
                 incStrIdx();
                 buffer = xmlBufferCreate();
-                xmlFuzzResetMallocFailed();
+                xmlFuzzResetFailure();
                 node = getNode(0);
                 doc = node ? node->doc : NULL;
                 level = getInt(0);
@@ -3301,8 +3302,9 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
                 }
 
                 incStrIdx();
-                output = xmlAllocOutputBuffer(NULL);
-                xmlFuzzResetMallocFailed();
+                output = xmlOutputBufferCreateIO(xmlFuzzOutputWrite,
+                                                 xmlFuzzOutputClose, NULL, NULL);
+                xmlFuzzResetFailure();
                 node = getNode(0);
                 doc = node ? node->doc : NULL;
                 encoding = (const char *) getStr(1);
@@ -3353,16 +3355,17 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
                 if (closed) {
                     if (res >= 0)
                         oomReport = 0;
+                    else
+                        ioReport = -1;
                     moveStr(0, NULL);
                 } else {
-                    oomReport =
-                        (output != NULL &&
-                         output->error == XML_ERR_NO_MEMORY);
                     if (argsOk && !output->error)
                         copyStr(0, xmlBufContent(output->buffer));
                     else
                         moveStr(0, NULL);
-                    xmlOutputBufferClose(output);
+                    res = xmlOutputBufferClose(output);
+                    oomReport = (res == -XML_ERR_NO_MEMORY);
+                    ioReport  = (res == -XML_IO_EIO);
                 }
                 endOp();
                 break;
@@ -3570,7 +3573,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
                 break;
         }
 
-        xmlFuzzCheckMallocFailure(vars->opName, oomReport);
+        xmlFuzzCheckFailureReport(vars->opName, oomReport, ioReport);
     }
 
     for (i = 0; i < REG_MAX; i++)
@@ -3583,7 +3586,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
         dropNode(node);
     }
 
-    xmlFuzzMemSetLimit(0);
+    xmlFuzzInjectFailure(0);
     xmlFuzzDataCleanup();
     xmlResetLastError();
     return(0);
diff --git a/fuzz/fuzz.c b/fuzz/fuzz.c
index 1b7ae0cd..a1b4df32 100644
--- a/fuzz/fuzz.c
+++ b/fuzz/fuzz.c
@@ -42,9 +42,10 @@ static struct {
     xmlFuzzEntityInfo *mainEntity;
 } fuzzData;
 
-size_t fuzzNumAllocs;
-size_t fuzzMaxAllocs;
+size_t fuzzNumAttempts;
+size_t fuzzFailurePos;
 int fuzzAllocFailed;
+int fuzzIoFailed;
 
 /**
  * xmlFuzzErrorFunc:
@@ -67,30 +68,62 @@ xmlFuzzSErrorFunc(void *ctx ATTRIBUTE_UNUSED,
 }
 
 /*
- * Malloc failure injection.
+ * Failure injection.
  *
- * To debug issues involving malloc failures, it's often helpful to set
- * MALLOC_ABORT to 1. This should provide a backtrace of the failed
- * allocation.
+ * To debug issues involving injected failures, it's often helpful to set
+ * FAILURE_ABORT to 1. This should provide a backtrace of the failed
+ * operation.
  */
 
-#define XML_FUZZ_MALLOC_ABORT   0
+#define XML_FUZZ_FAILURE_ABORT   0
 
-static void *
-xmlFuzzMalloc(size_t size) {
-    void *ret;
+void
+xmlFuzzInjectFailure(size_t failurePos) {
+    fuzzNumAttempts = 0;
+    fuzzFailurePos = failurePos;
+    fuzzAllocFailed = 0;
+    fuzzIoFailed = 0;
+}
 
-    if (fuzzMaxAllocs > 0) {
-        fuzzNumAllocs += 1;
-        if (fuzzNumAllocs == fuzzMaxAllocs) {
-#if XML_FUZZ_MALLOC_ABORT
+static int
+xmlFuzzTryMalloc(void) {
+    if (fuzzFailurePos > 0) {
+        fuzzNumAttempts += 1;
+        if (fuzzNumAttempts == fuzzFailurePos) {
+#if XML_FUZZ_FAILURE_ABORT
             abort();
 #endif
             fuzzAllocFailed = 1;
-            return NULL;
+            return -1;
+        }
+    }
+
+    return 0;
+}
+
+static int
+xmlFuzzTryIo(void) {
+    if (fuzzFailurePos > 0) {
+        fuzzNumAttempts += 1;
+        if (fuzzNumAttempts == fuzzFailurePos) {
+#if XML_FUZZ_FAILURE_ABORT
+            abort();
+#endif
+            fuzzIoFailed = 1;
+            return -1;
         }
     }
 
+    return 0;
+}
+
+static void *
+xmlFuzzMalloc(size_t size) {
+    void *ret;
+
+    if (xmlFuzzTryMalloc() < 0)
+        return NULL;
+
     ret = malloc(size);
     if (ret == NULL)
         fuzzAllocFailed = 1;
@@ -102,16 +135,8 @@ static void *
 xmlFuzzRealloc(void *ptr, size_t size) {
     void *ret;
 
-    if (fuzzMaxAllocs > 0) {
-        fuzzNumAllocs += 1;
-        if (fuzzNumAllocs == fuzzMaxAllocs) {
-#if XML_FUZZ_MALLOC_ABORT
-            abort();
-#endif
-            fuzzAllocFailed = 1;
-            return NULL;
-        }
-    }
+    if (xmlFuzzTryMalloc() < 0)
+        return NULL;
 
     ret = realloc(ptr, size);
     if (ret == NULL)
@@ -125,31 +150,31 @@ xmlFuzzMemSetup(void) {
     xmlMemSetup(free, xmlFuzzMalloc, xmlFuzzRealloc, xmlMemStrdup);
 }
 
-void
-xmlFuzzMemSetLimit(size_t limit) {
-    fuzzNumAllocs = 0;
-    fuzzMaxAllocs = limit;
-    fuzzAllocFailed = 0;
-}
-
 int
 xmlFuzzMallocFailed(void) {
     return fuzzAllocFailed;
 }
 
 void
-xmlFuzzResetMallocFailed(void) {
+xmlFuzzResetFailure(void) {
     fuzzAllocFailed = 0;
+    fuzzIoFailed = 0;
 }
 
 void
-xmlFuzzCheckMallocFailure(const char *func, int error) {
-    if (error >= 0 && fuzzAllocFailed != error) {
+xmlFuzzCheckFailureReport(const char *func, int oomReport, int ioReport) {
+    if (oomReport >= 0 && fuzzAllocFailed != oomReport) {
         fprintf(stderr, "%s: malloc failure %s reported\n",
                 func, fuzzAllocFailed ? "not" : "erroneously");
         abort();
     }
+    if (ioReport >= 0 && fuzzIoFailed != ioReport) {
+        fprintf(stderr, "%s: IO failure %s reported\n",
+                func, fuzzIoFailed ? "not" : "erroneously");
+        abort();
+    }
     fuzzAllocFailed = 0;
+    fuzzIoFailed = 0;
 }
 
 /**
@@ -413,6 +438,10 @@ xmlFuzzResourceLoader(void *data ATTRIBUTE_UNUSED, const char *URL,
     if (entity == NULL)
         return(XML_IO_ENOENT);
 
+    /* IO failure injection */
+    if (xmlFuzzTryIo() < 0)
+        return(XML_IO_EIO);
+
     input = xmlNewInputFromMemory(URL, entity->data, entity->size,
                                   XML_INPUT_BUF_STATIC |
                                   XML_INPUT_BUF_ZERO_TERMINATED);
@@ -423,33 +452,6 @@ xmlFuzzResourceLoader(void *data ATTRIBUTE_UNUSED, const char *URL,
     return(XML_ERR_OK);
 }
 
-/**
- * xmlFuzzEntityLoader:
- *
- * The entity loader for fuzz data.
- */
-xmlParserInputPtr
-xmlFuzzEntityLoader(const char *URL, const char *ID ATTRIBUTE_UNUSED,
-                    xmlParserCtxtPtr ctxt) {
-    xmlParserInputBufferPtr buf;
-    xmlFuzzEntityInfo *entity;
-
-    if (URL == NULL)
-        return(NULL);
-    entity = xmlHashLookup(fuzzData.entities, (xmlChar *) URL);
-    if (entity == NULL)
-        return(NULL);
-
-    buf = xmlParserInputBufferCreateMem(entity->data, entity->size,
-                                        XML_CHAR_ENCODING_NONE);
-    if (buf == NULL) {
-        xmlCtxtErrMemory(ctxt);
-        return(NULL);
-    }
-
-    return(xmlNewIOInputStream(ctxt, buf, XML_CHAR_ENCODING_NONE));
-}
-
 char *
 xmlSlurpFile(const char *path, size_t *sizeRet) {
     FILE *file;
@@ -479,3 +481,20 @@ xmlSlurpFile(const char *path, size_t *sizeRet) {
     return(data);
 }
 
+int
+xmlFuzzOutputWrite(void *ctxt ATTRIBUTE_UNUSED,
+                   const char *buffer ATTRIBUTE_UNUSED, int len) {
+    if (xmlFuzzTryIo() < 0)
+        return -XML_IO_EIO;
+
+    return len;
+}
+
+int
+xmlFuzzOutputClose(void *ctxt ATTRIBUTE_UNUSED) {
+    if (xmlFuzzTryIo() < 0)
+        return XML_IO_EIO;
+
+    return 0;
+}
+
diff --git a/fuzz/fuzz.h b/fuzz/fuzz.h
index 75249c4f..a9a71f7d 100644
--- a/fuzz/fuzz.h
+++ b/fuzz/fuzz.h
@@ -68,16 +68,16 @@ void
 xmlFuzzMemSetup(void);
 
 void
-xmlFuzzMemSetLimit(size_t limit);
+xmlFuzzInjectFailure(size_t failurePos);
 
 int
 xmlFuzzMallocFailed(void);
 
 void
-xmlFuzzResetMallocFailed(void);
+xmlFuzzResetFailure(void);
 
 void
-xmlFuzzCheckMallocFailure(const char *func, int expect);
+xmlFuzzCheckFailureReport(const char *func, int oomReport, int ioReport);
 
 void
 xmlFuzzDataInit(const char *data, size_t size);
@@ -116,12 +116,15 @@ int
 xmlFuzzResourceLoader(void *data, const char *URL, const char *ID,
                       xmlResourceType type, int flags, xmlParserInputPtr *out);
 
-xmlParserInputPtr
-xmlFuzzEntityLoader(const char *URL, const char *ID, xmlParserCtxtPtr ctxt);
-
 char *
 xmlSlurpFile(const char *path, size_t *size);
 
+int
+xmlFuzzOutputWrite(void *ctxt, const char *buffer, int len);
+
+int
+xmlFuzzOutputClose(void *ctxt);
+
 #ifdef __cplusplus
 }
 #endif
diff --git a/fuzz/genSeed.c b/fuzz/genSeed.c
index ca129504..2c4123ea 100644
--- a/fuzz/genSeed.c
+++ b/fuzz/genSeed.c
@@ -27,8 +27,9 @@
 #define SEED_BUF_SIZE 16384
 #define EXPR_SIZE 4500
 
-#define FLAG_READER (1 << 0)
-#define FLAG_LINT   (1 << 1)
+#define FLAG_READER             (1 << 0)
+#define FLAG_LINT               (1 << 1)
+#define FLAG_PUSH_CHUNK_SIZE    (1 << 2)
 
 typedef int
 (*fileFunc)(const char *base, FILE *out);
@@ -142,6 +143,11 @@ processXml(const char *docFile, FILE *out) {
         /* Max allocations. */
         xmlFuzzWriteInt(out, 0, 4);
 
+        if (globalData.flags & FLAG_PUSH_CHUNK_SIZE) {
+            /* Chunk size for push parser */
+            xmlFuzzWriteInt(out, 256, 4);
+        }
+
         if (globalData.flags & FLAG_READER) {
             /* Initial reader program with a couple of OP_READs */
             xmlFuzzWriteString(out, "\x01\x01\x01\x01\x01\x01\x01\x01");
@@ -456,6 +462,7 @@ main(int argc, const char **argv) {
     if (strcmp(fuzzer, "html") == 0) {
 #ifdef HAVE_HTML_FUZZER
         processArg = processPattern;
+        globalData.flags |= FLAG_PUSH_CHUNK_SIZE;
         globalData.processFile = processHtml;
 #endif
     } else if (strcmp(fuzzer, "lint") == 0) {
@@ -488,6 +495,7 @@ main(int argc, const char **argv) {
     } else if (strcmp(fuzzer, "xml") == 0) {
 #ifdef HAVE_XML_FUZZER
         processArg = processPattern;
+        globalData.flags |= FLAG_PUSH_CHUNK_SIZE;
         globalData.processFile = processXml;
 #endif
     } else if (strcmp(fuzzer, "xpath") == 0) {
diff --git a/fuzz/html.c b/fuzz/html.c
index 36913121..f193b7e6 100644
--- a/fuzz/html.c
+++ b/fuzz/html.c
@@ -4,6 +4,10 @@
  * See Copyright for the status of this software.
  */
 
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+
 #include <libxml/HTMLparser.h>
 #include <libxml/HTMLtree.h>
 #include <libxml/catalog.h>
@@ -27,12 +31,19 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
     xmlParserCtxtPtr ctxt;
     htmlDocPtr doc;
     const char *docBuffer;
-    size_t maxAlloc, docSize;
-    int opts;
+    size_t failurePos, docSize, maxChunkSize;
+    int opts, errorCode;
+#ifdef LIBXML_OUTPUT_ENABLED
+    xmlOutputBufferPtr out = NULL;
+#endif
 
     xmlFuzzDataInit(data, size);
     opts = (int) xmlFuzzReadInt(4);
-    maxAlloc = xmlFuzzReadInt(4) % (size + 100);
+    failurePos = xmlFuzzReadInt(4) % (size + 100);
+
+    maxChunkSize = xmlFuzzReadInt(4) % (size + size / 8 + 1);
+    if (maxChunkSize == 0)
+        maxChunkSize = 1;
 
     docBuffer = xmlFuzzReadRemaining(&docSize);
     if (docBuffer == NULL) {
@@ -42,19 +53,22 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
 
     /* Pull parser */
 
-    xmlFuzzMemSetLimit(maxAlloc);
+    xmlFuzzInjectFailure(failurePos);
     ctxt = htmlNewParserCtxt();
-    if (ctxt != NULL) {
+    if (ctxt == NULL) {
+        errorCode = XML_ERR_NO_MEMORY;
+    } else {
         xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
         doc = htmlCtxtReadMemory(ctxt, docBuffer, docSize, NULL, NULL, opts);
-        xmlFuzzCheckMallocFailure("htmlCtxtReadMemory",
-                                  ctxt->errNo == XML_ERR_NO_MEMORY);
+        errorCode = ctxt->errNo;
+        xmlFuzzCheckFailureReport("htmlCtxtReadMemory",
+                                  errorCode == XML_ERR_NO_MEMORY,
+                                  errorCode == XML_IO_EIO);
 
         if (doc != NULL) {
             xmlDocPtr copy;
 
 #ifdef LIBXML_OUTPUT_ENABLED
-            xmlOutputBufferPtr out;
             const xmlChar *content;
 
             /*
@@ -65,13 +79,16 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
             out = xmlAllocOutputBuffer(NULL);
             htmlDocContentDumpOutput(out, doc, NULL);
             content = xmlOutputBufferGetContent(out);
-            xmlOutputBufferClose(out);
-            xmlFuzzCheckMallocFailure("htmlDocContentDumpOutput",
-                                      content == NULL);
+            xmlFuzzCheckFailureReport("htmlDocContentDumpOutput",
+                                      content == NULL, 0);
+            if (content == NULL) {
+                xmlOutputBufferClose(out);
+                out = NULL;
+            }
 #endif
 
             copy = xmlCopyDoc(doc, 1);
-            xmlFuzzCheckMallocFailure("xmlCopyNode", copy == NULL);
+            xmlFuzzCheckFailureReport("xmlCopyNode", copy == NULL, 0);
             xmlFreeDoc(copy);
 
             xmlFreeDoc(doc);
@@ -84,37 +101,120 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
     /* Push parser */
 
 #ifdef LIBXML_PUSH_ENABLED
-    {
-        static const size_t maxChunkSize = 128;
-        size_t consumed, chunkSize;
-
-        xmlFuzzMemSetLimit(maxAlloc);
-        ctxt = htmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL,
-                                        XML_CHAR_ENCODING_NONE);
-
-        if (ctxt != NULL) {
-            xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
-            htmlCtxtUseOptions(ctxt, opts);
-
-            for (consumed = 0; consumed < docSize; consumed += chunkSize) {
-                chunkSize = docSize - consumed;
-                if (chunkSize > maxChunkSize)
-                    chunkSize = maxChunkSize;
-                htmlParseChunk(ctxt, docBuffer + consumed, chunkSize, 0);
+    xmlFuzzInjectFailure(failurePos);
+    ctxt = htmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL,
+                                    XML_CHAR_ENCODING_NONE);
+
+    if (ctxt != NULL) {
+        size_t consumed;
+        int errorCodePush, numChunks, maxChunks;
+
+        xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
+        htmlCtxtUseOptions(ctxt, opts);
+
+        consumed = 0;
+        numChunks = 0;
+        maxChunks = 50 + docSize / 100;
+        while (numChunks == 0 ||
+               (consumed < docSize && numChunks < maxChunks)) {
+            size_t chunkSize;
+            int terminate;
+
+            numChunks += 1;
+            chunkSize = docSize - consumed;
+
+            if (numChunks < maxChunks && chunkSize > maxChunkSize) {
+                chunkSize = maxChunkSize;
+                terminate = 0;
+            } else {
+                terminate = 1;
+            }
+
+            htmlParseChunk(ctxt, docBuffer + consumed, chunkSize, terminate);
+            consumed += chunkSize;
+        }
+
+        errorCodePush = ctxt->errNo;
+        xmlFuzzCheckFailureReport("htmlParseChunk",
+                                  errorCodePush == XML_ERR_NO_MEMORY,
+                                  errorCodePush == XML_IO_EIO);
+        doc = ctxt->myDoc;
+
+        /*
+         * Push and pull parser differ in when exactly they
+         * stop parsing, and the error code is the *last* error
+         * reported, so we can't check whether the codes match.
+         */
+        if (errorCode != XML_ERR_NO_MEMORY &&
+            errorCode != XML_IO_EIO &&
+            errorCodePush != XML_ERR_NO_MEMORY &&
+            errorCodePush != XML_IO_EIO &&
+            (errorCode == XML_ERR_OK) != (errorCodePush == XML_ERR_OK)) {
+            fprintf(stderr, "pull/push parser error mismatch: %d != %d\n",
+                    errorCode, errorCodePush);
+#if 0
+            FILE *f = fopen("c.html", "wb");
+            fwrite(docBuffer, docSize, 1, f);
+            fclose(f);
+            fprintf(stderr, "opts: %X\n", opts);
+#endif
+            abort();
+        }
+
+#ifdef LIBXML_OUTPUT_ENABLED
+        /*
+         * Verify that pull and push parser produce the same result.
+         *
+         * The NOBLANKS option doesn't work reliably in push mode.
+         */
+        if ((opts & XML_PARSE_NOBLANKS) == 0 &&
+            errorCode == XML_ERR_OK &&
+            errorCodePush == XML_ERR_OK &&
+            out != NULL) {
+            xmlOutputBufferPtr outPush;
+            const xmlChar *content, *contentPush;
+
+            outPush = xmlAllocOutputBuffer(NULL);
+            htmlDocContentDumpOutput(outPush, doc, NULL);
+            content = xmlOutputBufferGetContent(out);
+            contentPush = xmlOutputBufferGetContent(outPush);
+
+            if (content != NULL && contentPush != NULL) {
+                size_t outSize = xmlOutputBufferGetSize(out);
+
+                if (outSize != xmlOutputBufferGetSize(outPush) ||
+                    memcmp(content, contentPush, outSize) != 0) {
+                    fprintf(stderr, "pull/push parser roundtrip "
+                            "mismatch\n");
+#if 0
+                    FILE *f = fopen("c.html", "wb");
+                    fwrite(docBuffer, docSize, 1, f);
+                    fclose(f);
+                    fprintf(stderr, "opts: %X\n", opts);
+                    fprintf(stderr, "---\n%s\n---\n%s\n---\n",
+                            xmlOutputBufferGetContent(out),
+                            xmlOutputBufferGetContent(outPush));
+#endif
+                    abort();
+                }
             }
 
-            htmlParseChunk(ctxt, NULL, 0, 1);
-            xmlFuzzCheckMallocFailure("htmlParseChunk",
-                                      ctxt->errNo == XML_ERR_NO_MEMORY);
-            xmlFreeDoc(ctxt->myDoc);
-            htmlFreeParserCtxt(ctxt);
+            xmlOutputBufferClose(outPush);
         }
+#endif
+
+        xmlFreeDoc(doc);
+        htmlFreeParserCtxt(ctxt);
     }
 #endif
 
     /* Cleanup */
 
-    xmlFuzzMemSetLimit(0);
+#ifdef LIBXML_OUTPUT_ENABLED
+    xmlOutputBufferClose(out);
+#endif
+
+    xmlFuzzInjectFailure(0);
     xmlFuzzDataCleanup();
     xmlResetLastError();
 
diff --git a/fuzz/lint.c b/fuzz/lint.c
index 5c41716c..b25e1217 100644
--- a/fuzz/lint.c
+++ b/fuzz/lint.c
@@ -1,5 +1,5 @@
 /*
- * xml.c: a libFuzzer target to test several XML parser interfaces.
+ * lint.c: a libFuzzer target to test the xmllint executable.
  *
  * See Copyright for the status of this software.
  */
@@ -14,10 +14,29 @@
 #include <libxml/xmlerror.h>
 #include <libxml/xmlmemory.h>
 
+#include "private/lint.h"
+
 #include "fuzz.h"
 
-#define XMLLINT_FUZZ
-#include "../xmllint.c"
+/*
+ * Untested options:
+ *
+ * --catalogs: Requires XML catalogs
+ *
+ * --dtdvalid:
+ * --dtdvalidfpi: Requires an external DTD
+ *
+ * --output: Writes to disk
+ *
+ * --path: Requires cooperation with resource loader
+ *
+ * --relaxng:
+ * --schema:
+ * --schematron: Requires schemas
+ *
+ * --shell: We could pipe fuzz data to stdin but this is probably
+ *          not worth it.
+ */
 
 static const char *const switches[] = {
     "--auto",
@@ -58,6 +77,7 @@ static const char *const switches[] = {
     "--pushsmall",
     "--quiet",
     "--recover",
+    "--repeat",
     "--sax1",
     "--testIO",
     "--timing",
@@ -202,7 +222,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
     xmlCatalogSetDefaults(XML_CATA_ALLOW_NONE);
 #endif
 
-    xmllintMain(vars.argi - 1, vars.argv, xmlFuzzResourceLoader);
+    xmllintMain(vars.argi - 1, vars.argv, stdout, xmlFuzzResourceLoader);
 
     xmlMemSetup(free, malloc, realloc, xmlMemStrdup);
 
diff --git a/fuzz/oss-fuzz-build.sh b/fuzz/oss-fuzz-build.sh
index 3e8945fc..07beeb10 100755
--- a/fuzz/oss-fuzz-build.sh
+++ b/fuzz/oss-fuzz-build.sh
@@ -41,10 +41,14 @@ make fuzz.o
 for fuzzer in \
     api html lint reader regexp schema uri valid xinclude xml xpath
 do
-    make $fuzzer.o
+    OBJS="$fuzzer.o"
+    if [ "$fuzzer" = lint ]; then
+        OBJS="$OBJS ../xmllint.o ../shell.o"
+    fi
+    make $OBJS
     # Link with $CXX
     $CXX $CXXFLAGS \
-        $fuzzer.o fuzz.o \
+        $OBJS fuzz.o \
         -o $OUT/$fuzzer \
         $LIB_FUZZING_ENGINE \
         ../.libs/libxml2.a -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic
diff --git a/fuzz/reader.c b/fuzz/reader.c
index 83d6567e..25741a1c 100644
--- a/fuzz/reader.c
+++ b/fuzz/reader.c
@@ -1,5 +1,5 @@
 /*
- * xml.c: a libFuzzer target to test several XML parser interfaces.
+ * reader.c: a libFuzzer target to test the XML Reader API.
  *
  * See Copyright for the status of this software.
  */
@@ -107,14 +107,14 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
     const xmlError *error;
     const char *docBuffer;
     const unsigned char *program;
-    size_t maxAlloc, docSize, programSize, i;
+    size_t failurePos, docSize, programSize, i;
     size_t totalStringSize = 0;
     int opts;
     int oomReport = 0;
 
     xmlFuzzDataInit(data, size);
     opts = (int) xmlFuzzReadInt(4);
-    maxAlloc = xmlFuzzReadInt(4) % (size + 100);
+    failurePos = xmlFuzzReadInt(4) % (size + 100);
 
     program = (const unsigned char *) xmlFuzzReadString(&programSize);
     if (programSize > 1000)
@@ -138,7 +138,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
     fprintf(stderr, "\nEOF\n");
 #endif
 
-    xmlFuzzMemSetLimit(maxAlloc);
+    xmlFuzzInjectFailure(failurePos);
     reader = xmlReaderForMemory(docBuffer, docSize, NULL, NULL, opts);
     if (reader == NULL)
         goto exit;
@@ -539,7 +539,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
     error = xmlTextReaderGetLastError(reader);
     if (error->code == XML_ERR_NO_MEMORY)
         oomReport = 1;
-    xmlFuzzCheckMallocFailure("reader", oomReport);
+    xmlFuzzCheckFailureReport("reader", oomReport, error->code == XML_IO_EIO);
 
     xmlFreeTextReader(reader);
 
@@ -547,7 +547,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
         xmlFreeDoc(doc);
 
 exit:
-    xmlFuzzMemSetLimit(0);
+    xmlFuzzInjectFailure(0);
     xmlFuzzDataCleanup();
     xmlResetLastError();
     return(0);
diff --git a/fuzz/regexp.c b/fuzz/regexp.c
index 919ce1dd..ca27af61 100644
--- a/fuzz/regexp.c
+++ b/fuzz/regexp.c
@@ -20,17 +20,17 @@ LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED,
 int
 LLVMFuzzerTestOneInput(const char *data, size_t size) {
     xmlRegexpPtr regexp;
-    size_t maxAlloc;
+    size_t failurePos;
     const char *str1;
 
     if (size > 200)
         return(0);
 
     xmlFuzzDataInit(data, size);
-    maxAlloc = xmlFuzzReadInt(4) % (size * 8 + 100);
+    failurePos = xmlFuzzReadInt(4) % (size * 8 + 100);
     str1 = xmlFuzzReadString(NULL);
 
-    xmlFuzzMemSetLimit(maxAlloc);
+    xmlFuzzInjectFailure(failurePos);
     regexp = xmlRegexpCompile(BAD_CAST str1);
     if (xmlFuzzMallocFailed() && regexp != NULL) {
         fprintf(stderr, "malloc failure not reported\n");
@@ -42,7 +42,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
 #endif
     xmlRegFreeRegexp(regexp);
 
-    xmlFuzzMemSetLimit(0);
+    xmlFuzzInjectFailure(0);
     xmlFuzzDataCleanup();
     xmlResetLastError();
 
diff --git a/fuzz/schema.c b/fuzz/schema.c
index fb1027ca..a6759a6d 100644
--- a/fuzz/schema.c
+++ b/fuzz/schema.c
@@ -24,24 +24,24 @@ LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED,
 int
 LLVMFuzzerTestOneInput(const char *data, size_t size) {
     xmlSchemaParserCtxtPtr pctxt;
-    size_t maxAlloc;
+    size_t failurePos;
 
     if (size > 50000)
         return(0);
 
-    maxAlloc = xmlFuzzReadInt(4) % (size + 100);
+    failurePos = xmlFuzzReadInt(4) % (size + 100);
 
     xmlFuzzDataInit(data, size);
     xmlFuzzReadEntities();
 
-    xmlFuzzMemSetLimit(maxAlloc);
+    xmlFuzzInjectFailure(failurePos);
     pctxt = xmlSchemaNewParserCtxt(xmlFuzzMainUrl());
     xmlSchemaSetParserStructuredErrors(pctxt, xmlFuzzSErrorFunc, NULL);
     xmlSchemaSetResourceLoader(pctxt, xmlFuzzResourceLoader, NULL);
     xmlSchemaFree(xmlSchemaParse(pctxt));
     xmlSchemaFreeParserCtxt(pctxt);
 
-    xmlFuzzMemSetLimit(0);
+    xmlFuzzInjectFailure(0);
     xmlFuzzDataCleanup();
     xmlResetLastError();
 
diff --git a/fuzz/uri.c b/fuzz/uri.c
index 72c6a293..03fcb24d 100644
--- a/fuzz/uri.c
+++ b/fuzz/uri.c
@@ -18,7 +18,7 @@ LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED,
 int
 LLVMFuzzerTestOneInput(const char *data, size_t size) {
     xmlURIPtr uri;
-    size_t maxAlloc;
+    size_t failurePos;
     const char *str1, *str2;
     char *copy;
     xmlChar *strRes;
@@ -28,20 +28,20 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
         return(0);
 
     xmlFuzzDataInit(data, size);
-    maxAlloc = xmlFuzzReadInt(4) % (size * 8 + 100);
+    failurePos = xmlFuzzReadInt(4) % (size * 8 + 100);
     str1 = xmlFuzzReadString(NULL);
     str2 = xmlFuzzReadString(NULL);
 
-    xmlFuzzMemSetLimit(maxAlloc);
+    xmlFuzzInjectFailure(failurePos);
 
-    xmlFuzzResetMallocFailed();
+    xmlFuzzResetFailure();
     intRes = xmlParseURISafe(str1, &uri);
-    xmlFuzzCheckMallocFailure("xmlParseURISafe", intRes == -1);
+    xmlFuzzCheckFailureReport("xmlParseURISafe", intRes == -1, 0);
 
     if (uri != NULL) {
-        xmlFuzzResetMallocFailed();
+        xmlFuzzResetFailure();
         strRes = xmlSaveUri(uri);
-        xmlFuzzCheckMallocFailure("xmlSaveURI", strRes == NULL);
+        xmlFuzzCheckFailureReport("xmlSaveURI", strRes == NULL, 0);
         xmlFree(strRes);
         xmlFreeURI(uri);
     }
@@ -52,50 +52,51 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
     xmlFree(xmlSaveUri(uri));
     xmlFreeURI(uri);
 
-    xmlFuzzResetMallocFailed();
+    xmlFuzzResetFailure();
     strRes = BAD_CAST xmlURIUnescapeString(str1, -1, NULL);
-    xmlFuzzCheckMallocFailure("xmlURIUnescapeString",
-                              str1 != NULL && strRes == NULL);
+    xmlFuzzCheckFailureReport("xmlURIUnescapeString",
+                              str1 != NULL && strRes == NULL, 0);
     xmlFree(strRes);
 
     xmlFree(xmlURIEscape(BAD_CAST str1));
 
-    xmlFuzzResetMallocFailed();
+    xmlFuzzResetFailure();
     strRes = xmlCanonicPath(BAD_CAST str1);
-    xmlFuzzCheckMallocFailure("xmlCanonicPath",
-                              str1 != NULL && strRes == NULL);
+    xmlFuzzCheckFailureReport("xmlCanonicPath",
+                              str1 != NULL && strRes == NULL, 0);
     xmlFree(strRes);
 
-    xmlFuzzResetMallocFailed();
+    xmlFuzzResetFailure();
     strRes = xmlPathToURI(BAD_CAST str1);
-    xmlFuzzCheckMallocFailure("xmlPathToURI", str1 != NULL && strRes == NULL);
+    xmlFuzzCheckFailureReport("xmlPathToURI",
+                              str1 != NULL && strRes == NULL, 0);
     xmlFree(strRes);
 
-    xmlFuzzResetMallocFailed();
+    xmlFuzzResetFailure();
     intRes = xmlBuildURISafe(BAD_CAST str2, BAD_CAST str1, &strRes);
-    xmlFuzzCheckMallocFailure("xmlBuildURISafe", intRes == -1);
+    xmlFuzzCheckFailureReport("xmlBuildURISafe", intRes == -1, 0);
     xmlFree(strRes);
 
     xmlFree(xmlBuildURI(BAD_CAST str2, BAD_CAST str1));
 
-    xmlFuzzResetMallocFailed();
+    xmlFuzzResetFailure();
     intRes = xmlBuildRelativeURISafe(BAD_CAST str2, BAD_CAST str1, &strRes);
-    xmlFuzzCheckMallocFailure("xmlBuildRelativeURISafe", intRes == -1);
+    xmlFuzzCheckFailureReport("xmlBuildRelativeURISafe", intRes == -1, 0);
     xmlFree(strRes);
 
     xmlFree(xmlBuildRelativeURI(BAD_CAST str2, BAD_CAST str1));
 
-    xmlFuzzResetMallocFailed();
+    xmlFuzzResetFailure();
     strRes = xmlURIEscapeStr(BAD_CAST str1, BAD_CAST str2);
-    xmlFuzzCheckMallocFailure("xmlURIEscapeStr",
-                              str1 != NULL && strRes == NULL);
+    xmlFuzzCheckFailureReport("xmlURIEscapeStr",
+                              str1 != NULL && strRes == NULL, 0);
     xmlFree(strRes);
 
     copy = (char *) xmlCharStrdup(str1);
     xmlNormalizeURIPath(copy);
     xmlFree(copy);
 
-    xmlFuzzMemSetLimit(0);
+    xmlFuzzInjectFailure(0);
     xmlFuzzDataCleanup();
 
     return 0;
diff --git a/fuzz/valid.c b/fuzz/valid.c
index 73216507..cab7cedc 100644
--- a/fuzz/valid.c
+++ b/fuzz/valid.c
@@ -27,16 +27,15 @@ int
 LLVMFuzzerTestOneInput(const char *data, size_t size) {
     xmlParserCtxtPtr ctxt;
     xmlDocPtr doc;
-    xmlValidCtxtPtr vctxt;
     const char *docBuffer, *docUrl;
-    size_t maxAlloc, docSize;
+    size_t failurePos, docSize;
     int opts;
 
     xmlFuzzDataInit(data, size);
     opts = (int) xmlFuzzReadInt(4);
     opts &= ~XML_PARSE_XINCLUDE;
     opts |= XML_PARSE_DTDVALID;
-    maxAlloc = xmlFuzzReadInt(4) % (size + 100);
+    failurePos = xmlFuzzReadInt(4) % (size + 100);
 
     xmlFuzzReadEntities();
     docBuffer = xmlFuzzMainEntity(&docSize);
@@ -46,38 +45,40 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
 
     /* Pull parser */
 
-    xmlFuzzMemSetLimit(maxAlloc);
+    xmlFuzzInjectFailure(failurePos);
     ctxt = xmlNewParserCtxt();
     if (ctxt != NULL) {
         xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
         xmlCtxtSetResourceLoader(ctxt, xmlFuzzResourceLoader, NULL);
         doc = xmlCtxtReadMemory(ctxt, docBuffer, docSize, docUrl, NULL, opts);
-        xmlFuzzCheckMallocFailure("xmlCtxtReadMemory",
-                                  ctxt->errNo == XML_ERR_NO_MEMORY);
+        xmlFuzzCheckFailureReport("xmlCtxtReadMemory",
+                                  ctxt->errNo == XML_ERR_NO_MEMORY,
+                                  ctxt->errNo == XML_IO_EIO);
         xmlFreeDoc(doc);
         xmlFreeParserCtxt(ctxt);
     }
 
     /* Post validation */
 
-    xmlFuzzMemSetLimit(maxAlloc);
+    xmlFuzzInjectFailure(failurePos);
     ctxt = xmlNewParserCtxt();
     if (ctxt != NULL) {
         xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
         xmlCtxtSetResourceLoader(ctxt, xmlFuzzResourceLoader, NULL);
         doc = xmlCtxtReadMemory(ctxt, docBuffer, docSize, docUrl, NULL,
                                 opts & ~XML_PARSE_DTDVALID);
-        xmlFreeParserCtxt(ctxt);
-
-        /* Post validation requires global callbacks */
-        xmlSetGenericErrorFunc(NULL, xmlFuzzErrorFunc);
-        xmlSetExternalEntityLoader(xmlFuzzEntityLoader);
-        vctxt = xmlNewValidCtxt();
-        xmlValidateDocument(vctxt, doc);
-        xmlFreeValidCtxt(vctxt);
+        xmlFuzzCheckFailureReport("xmlCtxtReadMemory",
+                doc == NULL && ctxt->errNo == XML_ERR_NO_MEMORY,
+                doc == NULL && ctxt->errNo == XML_IO_EIO);
+        if (doc != NULL) {
+            int valid = xmlCtxtValidateDocument(ctxt, doc);
+
+            xmlFuzzCheckFailureReport("xmlCtxtValidateDocument",
+                    !valid && ctxt->errNo == XML_ERR_NO_MEMORY,
+                    !valid && ctxt->errNo == XML_IO_EIO);
+        }
         xmlFreeDoc(doc);
-        xmlSetGenericErrorFunc(NULL, NULL);
-        xmlSetExternalEntityLoader(NULL);
+        xmlFreeParserCtxt(ctxt);
     }
 
     /* Push parser */
@@ -87,8 +88,14 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
         static const size_t maxChunkSize = 128;
         size_t consumed, chunkSize;
 
-        xmlFuzzMemSetLimit(maxAlloc);
+        xmlFuzzInjectFailure(failurePos);
+        /*
+         * FIXME: xmlCreatePushParserCtxt can still report OOM errors
+         * to stderr.
+         */
+        xmlSetGenericErrorFunc(NULL, xmlFuzzErrorFunc);
         ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, docUrl);
+        xmlSetGenericErrorFunc(NULL, NULL);
         if (ctxt != NULL) {
             xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
             xmlCtxtSetResourceLoader(ctxt, xmlFuzzResourceLoader, NULL);
@@ -102,8 +109,9 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
             }
 
             xmlParseChunk(ctxt, NULL, 0, 1);
-            xmlFuzzCheckMallocFailure("xmlParseChunk",
-                                      ctxt->errNo == XML_ERR_NO_MEMORY);
+            xmlFuzzCheckFailureReport("xmlParseChunk",
+                                      ctxt->errNo == XML_ERR_NO_MEMORY,
+                                      ctxt->errNo == XML_IO_EIO);
             xmlFreeDoc(ctxt->myDoc);
             xmlFreeParserCtxt(ctxt);
         }
@@ -111,7 +119,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
 #endif
 
 exit:
-    xmlFuzzMemSetLimit(0);
+    xmlFuzzInjectFailure(0);
     xmlFuzzDataCleanup();
     xmlResetLastError();
     return(0);
diff --git a/fuzz/xinclude.c b/fuzz/xinclude.c
index b9c44e59..7bcb2189 100644
--- a/fuzz/xinclude.c
+++ b/fuzz/xinclude.c
@@ -30,13 +30,13 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
     xmlParserCtxtPtr ctxt;
     xmlDocPtr doc;
     const char *docBuffer, *docUrl;
-    size_t maxAlloc, docSize;
+    size_t failurePos, docSize;
     int opts;
 
     xmlFuzzDataInit(data, size);
     opts = (int) xmlFuzzReadInt(4);
     opts |= XML_PARSE_XINCLUDE;
-    maxAlloc = xmlFuzzReadInt(4) % (size + 100);
+    failurePos = xmlFuzzReadInt(4) % (size + 100);
 
     xmlFuzzReadEntities();
     docBuffer = xmlFuzzMainEntity(&docSize);
@@ -46,7 +46,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
 
     /* Pull parser */
 
-    xmlFuzzMemSetLimit(maxAlloc);
+    xmlFuzzInjectFailure(failurePos);
     ctxt = xmlNewParserCtxt();
     if (ctxt != NULL) {
         xmlXIncludeCtxtPtr xinc;
@@ -55,24 +55,27 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
         xmlCtxtSetResourceLoader(ctxt, xmlFuzzResourceLoader, NULL);
 
         doc = xmlCtxtReadMemory(ctxt, docBuffer, docSize, docUrl, NULL, opts);
-        xmlFuzzCheckMallocFailure("xmlCtxtReadMemory",
-                                  ctxt->errNo == XML_ERR_NO_MEMORY);
+        xmlFuzzCheckFailureReport("xmlCtxtReadMemory",
+                doc == NULL && ctxt->errNo == XML_ERR_NO_MEMORY,
+                doc == NULL && ctxt->errNo == XML_IO_EIO);
 
         xinc = xmlXIncludeNewContext(doc);
         xmlXIncludeSetResourceLoader(xinc, xmlFuzzResourceLoader, NULL);
         xmlXIncludeSetFlags(xinc, opts);
         xmlXIncludeProcessNode(xinc, (xmlNodePtr) doc);
         if (doc != NULL) {
-            xmlFuzzCheckMallocFailure("xmlXIncludeProcessNode",
+            xmlFuzzCheckFailureReport("xmlXIncludeProcessNode",
                     xinc == NULL ||
-                    xmlXIncludeGetLastError(xinc) == XML_ERR_NO_MEMORY);
+                    xmlXIncludeGetLastError(xinc) == XML_ERR_NO_MEMORY,
+                    xinc != NULL &&
+                    xmlXIncludeGetLastError(xinc) == XML_IO_EIO);
         }
         xmlXIncludeFreeContext(xinc);
 
-        xmlFuzzResetMallocFailed();
+        xmlFuzzResetFailure();
         copy = xmlCopyDoc(doc, 1);
         if (doc != NULL)
-            xmlFuzzCheckMallocFailure("xmlCopyNode", copy == NULL);
+            xmlFuzzCheckFailureReport("xmlCopyNode", copy == NULL, 0);
         xmlFreeDoc(copy);
 
         xmlFreeDoc(doc);
@@ -80,7 +83,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
     }
 
 exit:
-    xmlFuzzMemSetLimit(0);
+    xmlFuzzInjectFailure(0);
     xmlFuzzDataCleanup();
     xmlResetLastError();
     return(0);
diff --git a/fuzz/xml.c b/fuzz/xml.c
index 1fb1f9f5..f9500f76 100644
--- a/fuzz/xml.c
+++ b/fuzz/xml.c
@@ -4,6 +4,10 @@
  * See Copyright for the status of this software.
  */
 
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+
 #include <libxml/catalog.h>
 #include <libxml/parser.h>
 #include <libxml/tree.h>
@@ -29,8 +33,14 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
     xmlParserCtxtPtr ctxt;
     xmlDocPtr doc;
     const char *docBuffer, *docUrl;
-    size_t maxAlloc, docSize;
+    size_t failurePos, docSize, maxChunkSize;
     int opts;
+    int errorCode;
+#ifdef LIBXML_OUTPUT_ENABLED
+    xmlBufferPtr outbuf = NULL;
+    const char *saveEncoding;
+    int saveOpts;
+#endif
 
     xmlFuzzDataInit(data, size);
     opts = (int) xmlFuzzReadInt(4);
@@ -40,7 +50,17 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
     opts &= ~XML_PARSE_XINCLUDE &
             ~XML_PARSE_DTDVALID &
             ~XML_PARSE_SAX1;
-    maxAlloc = xmlFuzzReadInt(4) % (size + 100);
+    failurePos = xmlFuzzReadInt(4) % (size + 100);
+
+    maxChunkSize = xmlFuzzReadInt(4) % (size + size / 8 + 1);
+    if (maxChunkSize == 0)
+        maxChunkSize = 1;
+
+#ifdef LIBXML_OUTPUT_ENABLED
+    /* TODO: Take from fuzz data */
+    saveOpts = 0;
+    saveEncoding = NULL;
+#endif
 
     xmlFuzzReadEntities();
     docBuffer = xmlFuzzMainEntity(&docSize);
@@ -50,33 +70,44 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
 
     /* Pull parser */
 
-    xmlFuzzMemSetLimit(maxAlloc);
+    xmlFuzzInjectFailure(failurePos);
     ctxt = xmlNewParserCtxt();
-    if (ctxt != NULL) {
+    if (ctxt == NULL) {
+        errorCode = XML_ERR_NO_MEMORY;
+    } else {
         xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
         xmlCtxtSetResourceLoader(ctxt, xmlFuzzResourceLoader, NULL);
         doc = xmlCtxtReadMemory(ctxt, docBuffer, docSize, docUrl, NULL, opts);
-        xmlFuzzCheckMallocFailure("xmlCtxtReadMemory",
-                                  doc == NULL &&
-                                  ctxt->errNo == XML_ERR_NO_MEMORY);
+        errorCode = ctxt->errNo;
+        xmlFuzzCheckFailureReport("xmlCtxtReadMemory",
+                doc == NULL && errorCode == XML_ERR_NO_MEMORY,
+                doc == NULL && errorCode == XML_IO_EIO);
 
         if (doc != NULL) {
 #ifdef LIBXML_OUTPUT_ENABLED
-            xmlBufferPtr buffer;
             xmlSaveCtxtPtr save;
 
+            outbuf = xmlBufferCreate();
+
             /* Also test the serializer. */
-            buffer = xmlBufferCreate();
-            save = xmlSaveToBuffer(buffer, NULL, 0);
-            if (save != NULL) {
-                int errNo;
+            save = xmlSaveToBuffer(outbuf, saveEncoding, saveOpts);
+
+            if (save == NULL) {
+                xmlBufferFree(outbuf);
+                outbuf = NULL;
+            } else {
+                int saveErr;
 
                 xmlSaveDoc(save, doc);
-                errNo = xmlSaveFinish(save);
-                xmlFuzzCheckMallocFailure("xmlSaveDoc",
-                                          errNo == XML_ERR_NO_MEMORY);
+                saveErr = xmlSaveFinish(save);
+                xmlFuzzCheckFailureReport("xmlSaveToBuffer",
+                                          saveErr == XML_ERR_NO_MEMORY,
+                                          saveErr == XML_IO_EIO);
+                if (saveErr != XML_ERR_OK) {
+                    xmlBufferFree(outbuf);
+                    outbuf = NULL;
+                }
             }
-            xmlBufferFree(buffer);
 #endif
             xmlFreeDoc(doc);
         }
@@ -87,35 +118,131 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
     /* Push parser */
 
 #ifdef LIBXML_PUSH_ENABLED
-    {
-        static const size_t maxChunkSize = 128;
-        size_t consumed, chunkSize;
-
-        xmlFuzzMemSetLimit(maxAlloc);
-        ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, docUrl);
-        if (ctxt != NULL) {
-            xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
-            xmlCtxtSetResourceLoader(ctxt, xmlFuzzResourceLoader, NULL);
-            xmlCtxtUseOptions(ctxt, opts);
-
-            for (consumed = 0; consumed < docSize; consumed += chunkSize) {
-                chunkSize = docSize - consumed;
-                if (chunkSize > maxChunkSize)
-                    chunkSize = maxChunkSize;
-                xmlParseChunk(ctxt, docBuffer + consumed, chunkSize, 0);
+    xmlFuzzInjectFailure(failurePos);
+    /*
+     * FIXME: xmlCreatePushParserCtxt can still report OOM errors
+     * to stderr.
+     */
+    xmlSetGenericErrorFunc(NULL, xmlFuzzErrorFunc);
+    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, docUrl);
+    xmlSetGenericErrorFunc(NULL, NULL);
+
+    if (ctxt != NULL) {
+        size_t consumed;
+        int errorCodePush, numChunks, maxChunks;
+
+        xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
+        xmlCtxtSetResourceLoader(ctxt, xmlFuzzResourceLoader, NULL);
+        xmlCtxtUseOptions(ctxt, opts);
+
+        consumed = 0;
+        numChunks = 0;
+        maxChunks = 50 + docSize / 100;
+        while (numChunks == 0 ||
+               (consumed < docSize && numChunks < maxChunks)) {
+            size_t chunkSize;
+            int terminate;
+
+            numChunks += 1;
+            chunkSize = docSize - consumed;
+
+            if (numChunks < maxChunks && chunkSize > maxChunkSize) {
+                chunkSize = maxChunkSize;
+                terminate = 0;
+            } else {
+                terminate = 1;
             }
 
-            xmlParseChunk(ctxt, NULL, 0, 1);
-            xmlFuzzCheckMallocFailure("xmlParseChunk",
-                                      ctxt->errNo == XML_ERR_NO_MEMORY);
-            xmlFreeDoc(ctxt->myDoc);
-            xmlFreeParserCtxt(ctxt);
+            xmlParseChunk(ctxt, docBuffer + consumed, chunkSize, terminate);
+            consumed += chunkSize;
         }
+
+        errorCodePush = ctxt->errNo;
+        xmlFuzzCheckFailureReport("xmlParseChunk",
+                                  errorCodePush == XML_ERR_NO_MEMORY,
+                                  errorCodePush == XML_IO_EIO);
+        doc = ctxt->myDoc;
+
+        /*
+         * Push and pull parser differ in when exactly they
+         * stop parsing, and the error code is the *last* error
+         * reported, so we can't check whether the codes match.
+         */
+        if (errorCode != XML_ERR_NO_MEMORY &&
+            errorCode != XML_IO_EIO &&
+            errorCodePush != XML_ERR_NO_MEMORY &&
+            errorCodePush != XML_IO_EIO &&
+            (errorCode == XML_ERR_OK) != (errorCodePush == XML_ERR_OK)) {
+            fprintf(stderr, "pull/push parser error mismatch: %d != %d\n",
+                    errorCode, errorCodePush);
+#if 0
+            FILE *f = fopen("c.xml", "wb");
+            fwrite(docBuffer, docSize, 1, f);
+            fclose(f);
+#endif
+            abort();
+        }
+
+#ifdef LIBXML_OUTPUT_ENABLED
+        /*
+         * Verify that pull and push parser produce the same result.
+         *
+         * The NOBLANKS option doesn't work reliably in push mode.
+         */
+        if ((opts & XML_PARSE_NOBLANKS) == 0 &&
+            errorCode == XML_ERR_OK &&
+            errorCodePush == XML_ERR_OK &&
+            outbuf != NULL) {
+            xmlBufferPtr outbufPush;
+            xmlSaveCtxtPtr save;
+
+            outbufPush = xmlBufferCreate();
+
+            save = xmlSaveToBuffer(outbufPush, saveEncoding, saveOpts);
+
+            if (save != NULL) {
+                int saveErr;
+
+                xmlSaveDoc(save, doc);
+                saveErr = xmlSaveFinish(save);
+
+                if (saveErr == XML_ERR_OK) {
+                    int outbufSize = xmlBufferLength(outbuf);
+
+                    if (outbufSize != xmlBufferLength(outbufPush) ||
+                        memcmp(xmlBufferContent(outbuf),
+                               xmlBufferContent(outbufPush),
+                               outbufSize) != 0) {
+                        fprintf(stderr, "pull/push parser roundtrip "
+                                "mismatch\n");
+#if 0
+                        FILE *f = fopen("c.xml", "wb");
+                        fwrite(docBuffer, docSize, 1, f);
+                        fclose(f);
+                        fprintf(stderr, "opts: %X\n", opts);
+                        fprintf(stderr, "---\n%s\n---\n%s\n---\n",
+                                xmlBufferContent(outbuf),
+                                xmlBufferContent(outbufPush));
+#endif
+                        abort();
+                    }
+                }
+            }
+
+            xmlBufferFree(outbufPush);
+        }
+#endif
+
+        xmlFreeDoc(doc);
+        xmlFreeParserCtxt(ctxt);
     }
 #endif
 
 exit:
-    xmlFuzzMemSetLimit(0);
+#ifdef LIBXML_OUTPUT_ENABLED
+    xmlBufferFree(outbuf);
+#endif
+    xmlFuzzInjectFailure(0);
     xmlFuzzDataCleanup();
     xmlResetLastError();
     return(0);
diff --git a/fuzz/xpath.c b/fuzz/xpath.c
index 2c25acb7..c7d05b43 100644
--- a/fuzz/xpath.c
+++ b/fuzz/xpath.c
@@ -27,14 +27,14 @@ int
 LLVMFuzzerTestOneInput(const char *data, size_t size) {
     xmlDocPtr doc;
     const char *expr, *xml;
-    size_t maxAlloc, exprSize, xmlSize;
+    size_t failurePos, exprSize, xmlSize;
 
     if (size > 10000)
         return(0);
 
     xmlFuzzDataInit(data, size);
 
-    maxAlloc = xmlFuzzReadInt(4) % (size + 100);
+    failurePos = xmlFuzzReadInt(4) % (size + 100);
     expr = xmlFuzzReadString(&exprSize);
     xml = xmlFuzzReadString(&xmlSize);
 
@@ -43,7 +43,7 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
     if (doc != NULL) {
         xmlXPathContextPtr xpctxt;
 
-        xmlFuzzMemSetLimit(maxAlloc);
+        xmlFuzzInjectFailure(failurePos);
 
         xpctxt = xmlXPathNewContext(doc);
         if (xpctxt != NULL) {
@@ -53,17 +53,16 @@ LLVMFuzzerTestOneInput(const char *data, size_t size) {
             xpctxt->opLimit = 500000;
 
             res = xmlXPathContextSetCache(xpctxt, 1, 4, 0);
-            xmlFuzzCheckMallocFailure("xmlXPathContextSetCache", res == -1);
+            xmlFuzzCheckFailureReport("xmlXPathContextSetCache", res == -1, 0);
 
-            xmlFuzzResetMallocFailed();
+            xmlFuzzResetFailure();
             xmlXPathFreeObject(xmlXPtrEval(BAD_CAST expr, xpctxt));
-            xmlFuzzCheckMallocFailure("xmlXPtrEval",
-                                      xpctxt->lastError.code ==
-                                      XML_ERR_NO_MEMORY);
+            xmlFuzzCheckFailureReport("xmlXPtrEval",
+                    xpctxt->lastError.code == XML_ERR_NO_MEMORY, 0);
             xmlXPathFreeContext(xpctxt);
         }
 
-        xmlFuzzMemSetLimit(0);
+        xmlFuzzInjectFailure(0);
         xmlFreeDoc(doc);
     }
 
diff --git a/globals.c b/globals.c
index 05bc8ed1..ad5092e1 100644
--- a/globals.c
+++ b/globals.c
@@ -58,12 +58,20 @@ static xmlMutex xmlThrDefMutex;
  * On Windows, we either use DllMain when compiling a DLL or a registered
  * wait function for static builds.
  *
- * Compiler TLS isn't really useful. It can make allocation more robust
- * on some platforms but it also increases the memory consumption of each
- * thread by ~250 bytes whether it uses libxml2 or not. The main problem
- * is that be have to deallocate strings in xmlLastError and C offers no
- * simple way to deallocate dynamic data in _Thread_local variables.
- * In C++, one could simply use a thread_local variable with a destructor.
+ * Compiler TLS isn't really useful for now. It can make allocation more
+ * robust on some platforms but it also increases the memory consumption
+ * of each thread by ~250 bytes whether it uses libxml2 or not. The main
+ * problem is that we have to deallocate strings in xmlLastError and C
+ * offers no simple way to deallocate dynamic data in _Thread_local
+ * variables. In C++, one could simply use a thread_local variable with a
+ * destructor.
+ *
+ * At some point, many of the deprecated globals can be removed,
+ * although things like global error handlers will take a while.
+ * Ultimately, the only crucial things seem to be xmlLastError and
+ * RNG state. xmlLastError already involves dynamic allocation, so it
+ * could be allocated dynamically as well, only storing a global
+ * pointer.
  */
 
 #ifdef LIBXML_THREAD_ENABLED
@@ -973,6 +981,11 @@ xmlCheckThreadLocalStorage(void) {
     return(0);
 }
 
+/**
+ * xmlGetLastErrorInternal:
+ *
+ * Returns a pointer to the global error struct.
+ */
 xmlError *
 xmlGetLastErrorInternal(void) {
 #ifdef LIBXML_THREAD_ENABLED
diff --git a/include/libxml/parser.h b/include/libxml/parser.h
index 55c24344..3ca2ff5b 100644
--- a/include/libxml/parser.h
+++ b/include/libxml/parser.h
@@ -1082,31 +1082,42 @@ XMLPUBFUN xmlDocPtr
 		xmlParseMemory		(const char *buffer,
 					 int size);
 #endif /* LIBXML_SAX1_ENABLED */
-XML_DEPRECATED XMLPUBFUN int
+XML_DEPRECATED
+XMLPUBFUN int
 		xmlSubstituteEntitiesDefault(int val);
-XML_DEPRECATED XMLPUBFUN int
+XML_DEPRECATED
+XMLPUBFUN int
                 xmlThrDefSubstituteEntitiesDefaultValue(int v);
 XMLPUBFUN int
 		xmlKeepBlanksDefault	(int val);
-XML_DEPRECATED XMLPUBFUN int
+XML_DEPRECATED
+XMLPUBFUN int
 		xmlThrDefKeepBlanksDefaultValue(int v);
 XMLPUBFUN void
 		xmlStopParser		(xmlParserCtxtPtr ctxt);
-XML_DEPRECATED XMLPUBFUN int
+XML_DEPRECATED
+XMLPUBFUN int
 		xmlPedanticParserDefault(int val);
-XML_DEPRECATED XMLPUBFUN int
+XML_DEPRECATED
+XMLPUBFUN int
                 xmlThrDefPedanticParserDefaultValue(int v);
-XML_DEPRECATED XMLPUBFUN int
+XML_DEPRECATED
+XMLPUBFUN int
 		xmlLineNumbersDefault	(int val);
-XML_DEPRECATED XMLPUBFUN int
+XML_DEPRECATED
+XMLPUBFUN int
                 xmlThrDefLineNumbersDefaultValue(int v);
-XML_DEPRECATED XMLPUBFUN int
+XML_DEPRECATED
+XMLPUBFUN int
                 xmlThrDefDoValidityCheckingDefaultValue(int v);
-XML_DEPRECATED XMLPUBFUN int
+XML_DEPRECATED
+XMLPUBFUN int
                 xmlThrDefGetWarningsDefaultValue(int v);
-XML_DEPRECATED XMLPUBFUN int
+XML_DEPRECATED
+XMLPUBFUN int
                 xmlThrDefLoadExtDtdDefaultValue(int v);
-XML_DEPRECATED XMLPUBFUN int
+XML_DEPRECATED
+XMLPUBFUN int
                 xmlThrDefParserDebugEntities(int v);
 
 #ifdef LIBXML_SAX1_ENABLED
@@ -1130,6 +1141,7 @@ XMLPUBFUN xmlDocPtr
  */
 XMLPUBFUN int
 		xmlParseDocument	(xmlParserCtxtPtr ctxt);
+XML_DEPRECATED
 XMLPUBFUN int
 		xmlParseExtParsedEnt	(xmlParserCtxtPtr ctxt);
 #ifdef LIBXML_SAX1_ENABLED
@@ -1183,6 +1195,18 @@ XMLPUBFUN xmlDocPtr
 #endif /* LIBXML_SAX1_ENABLED */
 
 #ifdef LIBXML_VALID_ENABLED
+XMLPUBFUN xmlDtdPtr
+		xmlCtxtParseDtd		(xmlParserCtxtPtr ctxt,
+					 xmlParserInputPtr input,
+					 const xmlChar *ExternalID,
+					 const xmlChar *SystemID);
+XMLPUBFUN int
+		xmlCtxtValidateDocument	(xmlParserCtxtPtr ctxt,
+					 xmlDocPtr doc);
+XMLPUBFUN int
+		xmlCtxtValidateDtd	(xmlParserCtxtPtr ctxt,
+					 xmlDocPtr doc,
+					 xmlDtdPtr dtd);
 XML_DEPRECATED
 XMLPUBFUN xmlDtdPtr
 		xmlSAXParseDTD		(xmlSAXHandlerPtr sax,
@@ -1319,16 +1343,21 @@ XMLPUBFUN xmlParserInputPtr
 /*
  * Node infos.
  */
+XML_DEPRECATED
 XMLPUBFUN const xmlParserNodeInfo*
 		xmlParserFindNodeInfo	(xmlParserCtxtPtr ctxt,
 				         xmlNodePtr node);
+XML_DEPRECATED
 XMLPUBFUN void
 		xmlInitNodeInfoSeq	(xmlParserNodeInfoSeqPtr seq);
+XML_DEPRECATED
 XMLPUBFUN void
 		xmlClearNodeInfoSeq	(xmlParserNodeInfoSeqPtr seq);
+XML_DEPRECATED
 XMLPUBFUN unsigned long
 		xmlParserFindNodeInfoIndex(xmlParserNodeInfoSeqPtr seq,
                                          xmlNodePtr node);
+XML_DEPRECATED
 XMLPUBFUN void
 		xmlParserAddNodeInfo	(xmlParserCtxtPtr ctxt,
 					 xmlParserNodeInfoPtr info);
@@ -1388,9 +1417,9 @@ typedef enum {
     /* since 2.13.0 */
     XML_PARSE_NO_XXE    = 1<<23,/* disable loading of external content */
     /* since 2.14.0 */
-    XML_PARSE_NO_UNZIP       = 1<<24,/* disable compressed content */
+    XML_PARSE_UNZIP          = 1<<24,/* allow compressed content */
     XML_PARSE_NO_SYS_CATALOG = 1<<25,/* disable global system catalog */
-    XML_PARSE_NO_CATALOG_PI  = 1<<26 /* ignore catalog PIs */
+    XML_PARSE_CATALOG_PI     = 1<<26 /* allow catalog PIs */
 } xmlParserOption;
 
 XMLPUBFUN void
diff --git a/include/libxml/parserInternals.h b/include/libxml/parserInternals.h
index 71fe3450..1a38e324 100644
--- a/include/libxml/parserInternals.h
+++ b/include/libxml/parserInternals.h
@@ -91,50 +91,6 @@ XMLPUBVAR const unsigned int xmlParserMaxDepth;
  */
 #define XML_MAX_NAMELEN 100
 
-/**
- * INPUT_CHUNK:
- *
- * The parser tries to always have that amount of input ready.
- * One of the point is providing context when reporting errors.
- */
-#define INPUT_CHUNK	250
-
-/************************************************************************
- *									*
- * UNICODE version of the macros.					*
- *									*
- ************************************************************************/
-/**
- * IS_BYTE_CHAR:
- * @c:  an byte value (int)
- *
- * Macro to check the following production in the XML spec:
- *
- * [2] Char ::= #x9 | #xA | #xD | [#x20...]
- * any byte character in the accepted range
- */
-#define IS_BYTE_CHAR(c)	 xmlIsChar_ch(c)
-
-/**
- * IS_CHAR:
- * @c:  an UNICODE value (int)
- *
- * Macro to check the following production in the XML spec:
- *
- * [2] Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD]
- *                  | [#x10000-#x10FFFF]
- * any Unicode character, excluding the surrogate blocks, FFFE, and FFFF.
- */
-#define IS_CHAR(c)   xmlIsCharQ(c)
-
-/**
- * IS_CHAR_CH:
- * @c: an xmlChar (usually an unsigned char)
- *
- * Behaves like IS_CHAR on single-byte value
- */
-#define IS_CHAR_CH(c)  xmlIsChar_ch(c)
-
 /**
  * IS_BLANK:
  * @c:  an UNICODE value (int)
@@ -153,147 +109,12 @@ XMLPUBVAR const unsigned int xmlParserMaxDepth;
  */
 #define IS_BLANK_CH(c)  xmlIsBlank_ch(c)
 
-/**
- * IS_BASECHAR:
- * @c:  an UNICODE value (int)
- *
- * Macro to check the following production in the XML spec:
- *
- * [85] BaseChar ::= ... long list see REC ...
- */
-#define IS_BASECHAR(c) xmlIsBaseCharQ(c)
-
-/**
- * IS_DIGIT:
- * @c:  an UNICODE value (int)
- *
- * Macro to check the following production in the XML spec:
- *
- * [88] Digit ::= ... long list see REC ...
- */
-#define IS_DIGIT(c) xmlIsDigitQ(c)
-
-/**
- * IS_DIGIT_CH:
- * @c:  an xmlChar value (usually an unsigned char)
- *
- * Behaves like IS_DIGIT but with a single byte argument
- */
-#define IS_DIGIT_CH(c)  xmlIsDigit_ch(c)
-
-/**
- * IS_COMBINING:
- * @c:  an UNICODE value (int)
- *
- * Macro to check the following production in the XML spec:
- *
- * [87] CombiningChar ::= ... long list see REC ...
- */
-#define IS_COMBINING(c) xmlIsCombiningQ(c)
-
-/**
- * IS_COMBINING_CH:
- * @c:  an xmlChar (usually an unsigned char)
- *
- * Always false (all combining chars > 0xff)
- */
-#define IS_COMBINING_CH(c) 0
-
-/**
- * IS_EXTENDER:
- * @c:  an UNICODE value (int)
- *
- * Macro to check the following production in the XML spec:
- *
- *
- * [89] Extender ::= #x00B7 | #x02D0 | #x02D1 | #x0387 | #x0640 |
- *                   #x0E46 | #x0EC6 | #x3005 | [#x3031-#x3035] |
- *                   [#x309D-#x309E] | [#x30FC-#x30FE]
- */
-#define IS_EXTENDER(c) xmlIsExtenderQ(c)
-
-/**
- * IS_EXTENDER_CH:
- * @c:  an xmlChar value (usually an unsigned char)
- *
- * Behaves like IS_EXTENDER but with a single-byte argument
- */
-#define IS_EXTENDER_CH(c)  xmlIsExtender_ch(c)
-
-/**
- * IS_IDEOGRAPHIC:
- * @c:  an UNICODE value (int)
- *
- * Macro to check the following production in the XML spec:
- *
- *
- * [86] Ideographic ::= [#x4E00-#x9FA5] | #x3007 | [#x3021-#x3029]
- */
-#define IS_IDEOGRAPHIC(c) xmlIsIdeographicQ(c)
-
-/**
- * IS_LETTER:
- * @c:  an UNICODE value (int)
- *
- * Macro to check the following production in the XML spec:
- *
- *
- * [84] Letter ::= BaseChar | Ideographic
- */
-#define IS_LETTER(c) (IS_BASECHAR(c) || IS_IDEOGRAPHIC(c))
-
-/**
- * IS_LETTER_CH:
- * @c:  an xmlChar value (normally unsigned char)
- *
- * Macro behaves like IS_LETTER, but only check base chars
- *
- */
-#define IS_LETTER_CH(c) xmlIsBaseChar_ch(c)
-
-/**
- * IS_ASCII_LETTER:
- * @c: an xmlChar value
- *
- * Macro to check [a-zA-Z]
- *
- */
-#define IS_ASCII_LETTER(c)	((0x61 <= ((c) | 0x20)) && \
-                                 (((c) | 0x20) <= 0x7a))
-
-/**
- * IS_ASCII_DIGIT:
- * @c: an xmlChar value
- *
- * Macro to check [0-9]
- *
- */
-#define IS_ASCII_DIGIT(c)	((0x30 <= (c)) && ((c) <= 0x39))
-
-/**
- * IS_PUBIDCHAR:
- * @c:  an UNICODE value (int)
- *
- * Macro to check the following production in the XML spec:
- *
- *
- * [13] PubidChar ::= #x20 | #xD | #xA | [a-zA-Z0-9] | [-'()+,./:=?;!*#@$_%]
- */
-#define IS_PUBIDCHAR(c)	xmlIsPubidCharQ(c)
-
-/**
- * IS_PUBIDCHAR_CH:
- * @c:  an xmlChar value (normally unsigned char)
- *
- * Same as IS_PUBIDCHAR but for single-byte value
- */
-#define IS_PUBIDCHAR_CH(c) xmlIsPubidChar_ch(c)
-
 /**
  * Global variables used for predefined strings.
  */
 XMLPUBVAR const xmlChar xmlStringText[];
 XMLPUBVAR const xmlChar xmlStringTextNoenc[];
+XML_DEPRECATED
 XMLPUBVAR const xmlChar xmlStringComment[];
 
 XML_DEPRECATED
@@ -310,6 +131,7 @@ XMLPUBFUN xmlParserCtxtPtr
 XMLPUBFUN xmlParserCtxtPtr
 			xmlCreateMemoryParserCtxt(const char *buffer,
 						 int size);
+XML_DEPRECATED
 XMLPUBFUN xmlParserCtxtPtr
 			xmlCreateEntityParserCtxt(const xmlChar *URL,
 						 const xmlChar *ID,
@@ -341,9 +163,16 @@ XML_DEPRECATED
 XMLPUBFUN xmlParserInputPtr
 			xmlNewEntityInputStream	(xmlParserCtxtPtr ctxt,
 						 xmlEntityPtr entity);
+XMLPUBFUN int
+			xmlCtxtPushInput	(xmlParserCtxtPtr ctxt,
+						 xmlParserInputPtr input);
+XMLPUBFUN xmlParserInputPtr
+			xmlCtxtPopInput		(xmlParserCtxtPtr ctxt);
+XML_DEPRECATED
 XMLPUBFUN int
 			xmlPushInput		(xmlParserCtxtPtr ctxt,
 						 xmlParserInputPtr input);
+XML_DEPRECATED
 XMLPUBFUN xmlChar
 			xmlPopInput		(xmlParserCtxtPtr ctxt);
 XMLPUBFUN void
@@ -509,6 +338,7 @@ XMLPUBFUN void
 XML_DEPRECATED
 XMLPUBFUN void
 			xmlParseMisc		(xmlParserCtxtPtr ctxt);
+XML_DEPRECATED
 XMLPUBFUN void
 			xmlParseExternalSubset	(xmlParserCtxtPtr ctxt,
 						 const xmlChar *ExternalID,
@@ -593,6 +423,7 @@ XMLPUBFUN int			xmlCheckLanguageID	(const xmlChar *lang);
 XML_DEPRECATED
 XMLPUBFUN int			xmlCurrentChar		(xmlParserCtxtPtr ctxt,
 						 int *len);
+XML_DEPRECATED
 XMLPUBFUN int		xmlCopyCharMultiByte	(xmlChar *out,
 						 int val);
 XML_DEPRECATED
diff --git a/include/libxml/valid.h b/include/libxml/valid.h
index 7345ca57..00446bc5 100644
--- a/include/libxml/valid.h
+++ b/include/libxml/valid.h
@@ -139,14 +139,17 @@ typedef struct _xmlHashTable xmlRefTable;
 typedef xmlRefTable *xmlRefTablePtr;
 
 /* Notation */
+XML_DEPRECATED
 XMLPUBFUN xmlNotationPtr
 		xmlAddNotationDecl	(xmlValidCtxtPtr ctxt,
 					 xmlDtdPtr dtd,
 					 const xmlChar *name,
 					 const xmlChar *PublicID,
 					 const xmlChar *SystemID);
+XML_DEPRECATED
 XMLPUBFUN xmlNotationTablePtr
 		xmlCopyNotationTable	(xmlNotationTablePtr table);
+XML_DEPRECATED
 XMLPUBFUN void
 		xmlFreeNotationTable	(xmlNotationTablePtr table);
 #ifdef LIBXML_OUTPUT_ENABLED
@@ -162,24 +165,31 @@ XMLPUBFUN void
 
 /* Element Content */
 /* the non Doc version are being deprecated */
+XML_DEPRECATED
 XMLPUBFUN xmlElementContentPtr
 		xmlNewElementContent	(const xmlChar *name,
 					 xmlElementContentType type);
+XML_DEPRECATED
 XMLPUBFUN xmlElementContentPtr
 		xmlCopyElementContent	(xmlElementContentPtr content);
+XML_DEPRECATED
 XMLPUBFUN void
 		xmlFreeElementContent	(xmlElementContentPtr cur);
 /* the new versions with doc argument */
+XML_DEPRECATED
 XMLPUBFUN xmlElementContentPtr
 		xmlNewDocElementContent	(xmlDocPtr doc,
 					 const xmlChar *name,
 					 xmlElementContentType type);
+XML_DEPRECATED
 XMLPUBFUN xmlElementContentPtr
 		xmlCopyDocElementContent(xmlDocPtr doc,
 					 xmlElementContentPtr content);
+XML_DEPRECATED
 XMLPUBFUN void
 		xmlFreeDocElementContent(xmlDocPtr doc,
 					 xmlElementContentPtr cur);
+XML_DEPRECATED
 XMLPUBFUN void
 		xmlSnprintfElementContent(char *buf,
 					 int size,
@@ -194,14 +204,17 @@ XMLPUBFUN void
 #endif /* LIBXML_OUTPUT_ENABLED */
 
 /* Element */
+XML_DEPRECATED
 XMLPUBFUN xmlElementPtr
 		xmlAddElementDecl	(xmlValidCtxtPtr ctxt,
 					 xmlDtdPtr dtd,
 					 const xmlChar *name,
 					 xmlElementTypeVal type,
 					 xmlElementContentPtr content);
+XML_DEPRECATED
 XMLPUBFUN xmlElementTablePtr
 		xmlCopyElementTable	(xmlElementTablePtr table);
+XML_DEPRECATED
 XMLPUBFUN void
 		xmlFreeElementTable	(xmlElementTablePtr table);
 #ifdef LIBXML_OUTPUT_ENABLED
@@ -216,14 +229,18 @@ XMLPUBFUN void
 #endif /* LIBXML_OUTPUT_ENABLED */
 
 /* Enumeration */
+XML_DEPRECATED
 XMLPUBFUN xmlEnumerationPtr
 		xmlCreateEnumeration	(const xmlChar *name);
+/* XML_DEPRECATED, needed for custom attributeDecl SAX handler */
 XMLPUBFUN void
 		xmlFreeEnumeration	(xmlEnumerationPtr cur);
+XML_DEPRECATED
 XMLPUBFUN xmlEnumerationPtr
 		xmlCopyEnumeration	(xmlEnumerationPtr cur);
 
 /* Attribute */
+XML_DEPRECATED
 XMLPUBFUN xmlAttributePtr
 		xmlAddAttributeDecl	(xmlValidCtxtPtr ctxt,
 					 xmlDtdPtr dtd,
@@ -234,8 +251,10 @@ XMLPUBFUN xmlAttributePtr
 					 xmlAttributeDefault def,
 					 const xmlChar *defaultValue,
 					 xmlEnumerationPtr tree);
+XML_DEPRECATED
 XMLPUBFUN xmlAttributeTablePtr
 		xmlCopyAttributeTable  (xmlAttributeTablePtr table);
+XML_DEPRECATED
 XMLPUBFUN void
 		xmlFreeAttributeTable  (xmlAttributeTablePtr table);
 #ifdef LIBXML_OUTPUT_ENABLED
diff --git a/include/libxml/xmlautomata.h b/include/libxml/xmlautomata.h
index f40e8af9..97d0abf9 100644
--- a/include/libxml/xmlautomata.h
+++ b/include/libxml/xmlautomata.h
@@ -39,24 +39,31 @@ typedef xmlAutomataState *xmlAutomataStatePtr;
 /*
  * Building API
  */
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataPtr
 		    xmlNewAutomata		(void);
+XML_DEPRECATED
 XMLPUBFUN void
 		    xmlFreeAutomata		(xmlAutomataPtr am);
 
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataStatePtr
 		    xmlAutomataGetInitState	(xmlAutomataPtr am);
+XML_DEPRECATED
 XMLPUBFUN int
 		    xmlAutomataSetFinalState	(xmlAutomataPtr am,
 						 xmlAutomataStatePtr state);
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataStatePtr
 		    xmlAutomataNewState		(xmlAutomataPtr am);
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataStatePtr
 		    xmlAutomataNewTransition	(xmlAutomataPtr am,
 						 xmlAutomataStatePtr from,
 						 xmlAutomataStatePtr to,
 						 const xmlChar *token,
 						 void *data);
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataStatePtr
 		    xmlAutomataNewTransition2	(xmlAutomataPtr am,
 						 xmlAutomataStatePtr from,
@@ -64,6 +71,7 @@ XMLPUBFUN xmlAutomataStatePtr
 						 const xmlChar *token,
 						 const xmlChar *token2,
 						 void *data);
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataStatePtr
                     xmlAutomataNewNegTrans	(xmlAutomataPtr am,
 						 xmlAutomataStatePtr from,
@@ -72,6 +80,7 @@ XMLPUBFUN xmlAutomataStatePtr
 						 const xmlChar *token2,
 						 void *data);
 
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataStatePtr
 		    xmlAutomataNewCountTrans	(xmlAutomataPtr am,
 						 xmlAutomataStatePtr from,
@@ -80,6 +89,7 @@ XMLPUBFUN xmlAutomataStatePtr
 						 int min,
 						 int max,
 						 void *data);
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataStatePtr
 		    xmlAutomataNewCountTrans2	(xmlAutomataPtr am,
 						 xmlAutomataStatePtr from,
@@ -89,6 +99,7 @@ XMLPUBFUN xmlAutomataStatePtr
 						 int min,
 						 int max,
 						 void *data);
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataStatePtr
 		    xmlAutomataNewOnceTrans	(xmlAutomataPtr am,
 						 xmlAutomataStatePtr from,
@@ -97,6 +108,7 @@ XMLPUBFUN xmlAutomataStatePtr
 						 int min,
 						 int max,
 						 void *data);
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataStatePtr
 		    xmlAutomataNewOnceTrans2	(xmlAutomataPtr am,
 						 xmlAutomataStatePtr from,
@@ -106,32 +118,39 @@ XMLPUBFUN xmlAutomataStatePtr
 						 int min,
 						 int max,
 						 void *data);
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataStatePtr
 		    xmlAutomataNewAllTrans	(xmlAutomataPtr am,
 						 xmlAutomataStatePtr from,
 						 xmlAutomataStatePtr to,
 						 int lax);
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataStatePtr
 		    xmlAutomataNewEpsilon	(xmlAutomataPtr am,
 						 xmlAutomataStatePtr from,
 						 xmlAutomataStatePtr to);
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataStatePtr
 		    xmlAutomataNewCountedTrans	(xmlAutomataPtr am,
 						 xmlAutomataStatePtr from,
 						 xmlAutomataStatePtr to,
 						 int counter);
+XML_DEPRECATED
 XMLPUBFUN xmlAutomataStatePtr
 		    xmlAutomataNewCounterTrans	(xmlAutomataPtr am,
 						 xmlAutomataStatePtr from,
 						 xmlAutomataStatePtr to,
 						 int counter);
+XML_DEPRECATED
 XMLPUBFUN int
 		    xmlAutomataNewCounter	(xmlAutomataPtr am,
 						 int min,
 						 int max);
 
+XML_DEPRECATED
 XMLPUBFUN struct _xmlRegexp *
 		    xmlAutomataCompile		(xmlAutomataPtr am);
+XML_DEPRECATED
 XMLPUBFUN int
 		    xmlAutomataIsDeterminist	(xmlAutomataPtr am);
 
diff --git a/include/libxml/xmlregexp.h b/include/libxml/xmlregexp.h
index 210f99b3..edbdc98d 100644
--- a/include/libxml/xmlregexp.h
+++ b/include/libxml/xmlregexp.h
@@ -70,28 +70,34 @@ typedef void (*xmlRegExecCallbacks) (xmlRegExecCtxtPtr exec,
 /*
  * The progressive API
  */
+XML_DEPRECATED
 XMLPUBFUN xmlRegExecCtxtPtr
 		    xmlRegNewExecCtxt	(xmlRegexpPtr comp,
 					 xmlRegExecCallbacks callback,
 					 void *data);
+XML_DEPRECATED
 XMLPUBFUN void
 		    xmlRegFreeExecCtxt	(xmlRegExecCtxtPtr exec);
+XML_DEPRECATED
 XMLPUBFUN int
 		    xmlRegExecPushString(xmlRegExecCtxtPtr exec,
 					 const xmlChar *value,
 					 void *data);
+XML_DEPRECATED
 XMLPUBFUN int
 		    xmlRegExecPushString2(xmlRegExecCtxtPtr exec,
 					 const xmlChar *value,
 					 const xmlChar *value2,
 					 void *data);
 
+XML_DEPRECATED
 XMLPUBFUN int
 		    xmlRegExecNextValues(xmlRegExecCtxtPtr exec,
 					 int *nbval,
 					 int *nbneg,
 					 xmlChar **values,
 					 int *terminal);
+XML_DEPRECATED
 XMLPUBFUN int
 		    xmlRegExecErrInfo	(xmlRegExecCtxtPtr exec,
 					 const xmlChar **string,
diff --git a/include/libxml/xmlschemas.h b/include/libxml/xmlschemas.h
index adaff3e3..e71dc9a1 100644
--- a/include/libxml/xmlschemas.h
+++ b/include/libxml/xmlschemas.h
@@ -217,7 +217,7 @@ XMLPUBFUN int
 	    xmlSchemaValidateStream	(xmlSchemaValidCtxtPtr ctxt,
 					 xmlParserInputBufferPtr input,
 					 xmlCharEncoding enc,
-					 xmlSAXHandlerPtr sax,
+					 const xmlSAXHandler *sax,
 					 void *user_data);
 XMLPUBFUN int
 	    xmlSchemaValidateFile	(xmlSchemaValidCtxtPtr ctxt,
diff --git a/include/libxml/xmlversion.h b/include/libxml/xmlversion.h
index d4a7cbd1..601a590d 100644
--- a/include/libxml/xmlversion.h
+++ b/include/libxml/xmlversion.h
@@ -36,7 +36,7 @@
  *
  * extra version information, used to show a git commit description
  */
-#define LIBXML_VERSION_EXTRA "-GITv2.13.0-1719-g0a6934a2"
+#define LIBXML_VERSION_EXTRA "-GITv2.13.0-1904-g4d38e2fe"
 
 /**
  * LIBXML_TEST_VERSION:
diff --git a/include/private/Makefile.am b/include/private/Makefile.am
index 5e1cdf84..28def095 100644
--- a/include/private/Makefile.am
+++ b/include/private/Makefile.am
@@ -8,11 +8,11 @@ EXTRA_DIST = \
 	globals.h \
 	html.h \
 	io.h \
+	lint.h \
 	memory.h \
 	parser.h \
 	regexp.h \
 	save.h \
-	shell.h \
 	string.h \
 	threads.h \
 	tree.h \
diff --git a/include/private/error.h b/include/private/error.h
index d99cfea3..b88fd825 100644
--- a/include/private/error.h
+++ b/include/private/error.h
@@ -10,6 +10,9 @@
 
 struct _xmlNode;
 
+XML_HIDDEN int
+xmlIsCatastrophicError(int level, int code);
+
 XML_HIDDEN void
 xmlRaiseMemoryError(xmlStructuredErrorFunc schannel, xmlGenericErrorFunc channel,
                     void *data, int domain, xmlError *error);
diff --git a/include/private/io.h b/include/private/io.h
index 8748c663..da2004fd 100644
--- a/include/private/io.h
+++ b/include/private/io.h
@@ -31,6 +31,9 @@ XML_HIDDEN xmlParserInputBufferPtr
 xmlNewInputBufferMemory(const void *mem, size_t size, int flags,
                         xmlCharEncoding enc);
 
+XML_HIDDEN int
+xmlInputFromFd(xmlParserInputBufferPtr buf, int fd, int unzip);
+
 #ifdef LIBXML_OUTPUT_ENABLED
 XML_HIDDEN void
 xmlOutputBufferWriteQuotedString(xmlOutputBufferPtr buf,
diff --git a/include/private/lint.h b/include/private/lint.h
new file mode 100644
index 00000000..5c055c3f
--- /dev/null
+++ b/include/private/lint.h
@@ -0,0 +1,15 @@
+#ifndef XML_LINT_H_PRIVATE__
+#define XML_LINT_H_PRIVATE__
+
+#include <stdio.h>
+
+#include <libxml/parser.h>
+
+int
+xmllintMain(int argc, const char **argv, FILE *errStream,
+            xmlResourceLoader loader);
+
+void
+xmllintShell(xmlDocPtr doc, const char *filename, FILE *output);
+
+#endif /* XML_LINT_H_PRIVATE__ */
diff --git a/include/private/memory.h b/include/private/memory.h
index ef0497c6..754803b1 100644
--- a/include/private/memory.h
+++ b/include/private/memory.h
@@ -1,9 +1,58 @@
 #ifndef XML_MEMORY_H_PRIVATE__
 #define XML_MEMORY_H_PRIVATE__
 
+#include "../../libxml.h"
+
+#include <limits.h>
+#include <stddef.h>
+
+#ifndef SIZE_MAX
+  #define SIZE_MAX ((size_t) -1)
+#endif
+
+#define XML_MAX_ITEMS 1000000000 /* 1 billion */
+
 XML_HIDDEN void
 xmlInitMemoryInternal(void);
 XML_HIDDEN void
 xmlCleanupMemoryInternal(void);
 
+/**
+ * xmlGrowCapacity:
+ * @array:  pointer to array
+ * @capacity:  pointer to capacity (in/out)
+ * @elemSize:  size of an element in bytes
+ * @min:  elements in initial allocation
+ * @max:  maximum elements in the array
+ *
+ * Grow an array by at least one element, checking for overflow.
+ *
+ * Returns the new array size on success, -1 on failure.
+ */
+static XML_INLINE int
+xmlGrowCapacity(int capacity, size_t elemSize, int min, int max) {
+    int extra;
+
+    if (capacity <= 0) {
+#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
+        (void) min;
+        return(1);
+#else
+        return(min);
+#endif
+    }
+
+    if ((capacity >= max) ||
+        ((size_t) capacity > SIZE_MAX / 2 / elemSize))
+        return(-1);
+
+    /* Grow by 50% */
+    extra = (capacity + 1) / 2;
+
+    if (capacity > max - extra)
+        return(max);
+
+    return(capacity + extra);
+}
+
 #endif /* XML_MEMORY_H_PRIVATE__ */
diff --git a/include/private/parser.h b/include/private/parser.h
index 79a1bf67..47fce207 100644
--- a/include/private/parser.h
+++ b/include/private/parser.h
@@ -46,6 +46,28 @@
      (((ctxt)->input->entity != NULL) && \
       ((ctxt)->input->entity->etype == XML_EXTERNAL_PARAMETER_ENTITY)))
 
+#define IS_BYTE_CHAR(c)     xmlIsChar_ch(c)
+#define IS_CHAR(c)          xmlIsCharQ(c)
+#define IS_BASECHAR(c)      xmlIsBaseCharQ(c)
+#define IS_DIGIT(c)         xmlIsDigitQ(c)
+#define IS_COMBINING(c)     xmlIsCombiningQ(c)
+#define IS_EXTENDER(c)      xmlIsExtenderQ(c)
+#define IS_IDEOGRAPHIC(c)   xmlIsIdeographicQ(c)
+#define IS_LETTER(c)        (IS_BASECHAR(c) || IS_IDEOGRAPHIC(c))
+#define IS_ASCII_LETTER(c)  ((0x61 <= ((c) | 0x20)) && \
+                             (((c) | 0x20) <= 0x7a))
+#define IS_ASCII_DIGIT(c)   ((0x30 <= (c)) && ((c) <= 0x39))
+#define IS_PUBIDCHAR(c)     xmlIsPubidCharQ(c)
+#define IS_PUBIDCHAR_CH(c)  xmlIsPubidChar_ch(c)
+
+/**
+ * INPUT_CHUNK:
+ *
+ * The parser tries to always have that amount of input ready.
+ * One of the point is providing context when reporting errors.
+ */
+#define INPUT_CHUNK	250
+
 struct _xmlAttrHashBucket {
     int index;
 };
@@ -67,6 +89,8 @@ xmlWarningMsg(xmlParserCtxtPtr ctxt, xmlParserErrors error,
               const char *msg, const xmlChar *str1, const xmlChar *str2);
 XML_HIDDEN void
 xmlCtxtErrIO(xmlParserCtxtPtr ctxt, int code, const char *uri);
+XML_HIDDEN int
+xmlCtxtIsCatastrophicError(xmlParserCtxtPtr ctxt);
 
 XML_HIDDEN void
 xmlHaltParser(xmlParserCtxtPtr ctxt);
diff --git a/include/private/shell.h b/include/private/shell.h
deleted file mode 100644
index 53a857e2..00000000
--- a/include/private/shell.h
+++ /dev/null
@@ -1,7 +0,0 @@
-#ifndef XML_SHELL_H_PRIVATE__
-#define XML_SHELL_H_PRIVATE__
-
-void
-xmllintShell(xmlDocPtr doc, const char *filename, FILE *output);
-
-#endif /* XML_SHELL_H_PRIVATE__ */
diff --git a/libxml.h b/libxml.h
index 6065d822..1fb8beb1 100644
--- a/libxml.h
+++ b/libxml.h
@@ -29,15 +29,29 @@
 #include "config.h"
 #include <libxml/xmlversion.h>
 
-/*
- * Due to some Autotools limitations, this variable must be passed as
- * compiler flag. Define a default value if the macro wasn't set by the
- * build system.
- */
-#ifndef SYSCONFDIR
-  #define SYSCONFDIR "/etc"
+#if __STDC_VERSION__ >= 199901L
+  #define XML_INLINE inline
+#elif defined(_MSC_VER)
+  #if _MSC_VER >= 1900
+    #define XML_INLINE inline
+  #else
+    #define XML_INLINE _inline
+  #endif
+#else
+  #define XML_INLINE
+#endif
+
+#if __STDC_VERSION__ >= 199901L || (defined(_MSC_VER) && _MSC_VER >= 1900)
+  #include <stdint.h>
+  #define XML_INTPTR_T intptr_t
+#else
+  #include <stddef.h>
+  #define XML_INTPTR_T ptrdiff_t
 #endif
 
+#define XML_PTR_TO_INT(p) ((XML_INTPTR_T) (p))
+#define XML_INT_TO_PTR(i) ((void *) (XML_INTPTR_T) (i))
+
 #if !defined(_WIN32) && \
     !defined(__CYGWIN__) && \
     (defined(__clang__) || \
@@ -57,6 +71,13 @@
   #define ATTRIBUTE_DESTRUCTOR __attribute__((destructor))
 #endif
 
+#if (defined(__clang__) && __clang_major__ >= 18) || \
+    (defined(__GNUC__) && __GNUC__ >= 15)
+  #define ATTRIBUTE_COUNTED_BY(c) __attribute__((__counted_by__(c)))
+#else
+  #define ATTRIBUTE_COUNTED_BY(c)
+#endif
+
 #if defined(__clang__) || \
     (defined(__GNUC__) && (__GNUC__ >= 8) && !defined(__EDG__))
   #define ATTRIBUTE_NO_SANITIZE(arg) __attribute__((no_sanitize(arg)))
@@ -65,7 +86,8 @@
 #endif
 
 #ifdef __clang__
-  #if __clang_major__ >= 12
+  #if (!defined(__apple_build_version__) && __clang_major__ >= 12) || \
+      (defined(__apple_build_version__) && __clang_major__ >= 13)
     #define ATTRIBUTE_NO_SANITIZE_INTEGER \
       ATTRIBUTE_NO_SANITIZE("unsigned-integer-overflow") \
       ATTRIBUTE_NO_SANITIZE("unsigned-shift-base")
diff --git a/libxml2-config.cmake.cmake.in b/libxml2-config.cmake.cmake.in
index aead949b..de084bdf 100644
--- a/libxml2-config.cmake.cmake.in
+++ b/libxml2-config.cmake.cmake.in
@@ -31,55 +31,55 @@ set(LIBXML2_INCLUDE_DIR    ${PACKAGE_PREFIX_DIR}/@CMAKE_INSTALL_INCLUDEDIR@/libx
 set(LIBXML2_LIBRARY_DIR    ${PACKAGE_PREFIX_DIR}/@CMAKE_INSTALL_LIBDIR@)
 
 macro(select_library_location target basename)
-  if(TARGET ${target})
-    foreach(property IN ITEMS IMPORTED_LOCATION IMPORTED_IMPLIB)
-      get_target_property(${basename}_${property}_DEBUG ${target} ${property}_DEBUG)
-      get_target_property(${basename}_${property}_MINSIZEREL ${target} ${property}_MINSIZEREL)
-      get_target_property(${basename}_${property}_NOCONFIG ${target} ${property}_NOCONFIG)
-      get_target_property(${basename}_${property}_RELEASE ${target} ${property}_RELEASE)
-      get_target_property(${basename}_${property}_RELWITHDEBINFO ${target} ${property}_RELWITHDEBINFO)
-
-      if(${basename}_${property}_DEBUG AND ${basename}_${property}_RELEASE)
-        set(${basename}_LIBRARY debug ${${basename}_${property}_DEBUG} optimized ${${basename}_${property}_RELEASE})
-      elseif(${basename}_${property}_DEBUG AND ${basename}_${property}_RELWITHDEBINFO)
-        set(${basename}_LIBRARY debug ${${basename}_${property}_DEBUG} optimized ${${basename}_${property}_RELWITHDEBINFO})
-      elseif(${basename}_${property}_DEBUG AND ${basename}_${property}_MINSIZEREL)
-        set(${basename}_LIBRARY debug ${${basename}_${property}_DEBUG} optimized ${${basename}_${property}_MINSIZEREL})
-      elseif(${basename}_${property}_RELEASE)
-        set(${basename}_LIBRARY ${${basename}_${property}_RELEASE})
-      elseif(${basename}_${property}_RELWITHDEBINFO)
-        set(${basename}_LIBRARY ${${basename}_${property}_RELWITHDEBINFO})
-      elseif(${basename}_${property}_MINSIZEREL)
-        set(${basename}_LIBRARY ${${basename}_${property}_MINSIZEREL})
-      elseif(${basename}_${property}_DEBUG)
-        set(${basename}_LIBRARY ${${basename}_${property}_DEBUG})
-      elseif(${basename}_${property}_NOCONFIG)
-        set(${basename}_LIBRARY ${${basename}_${property}_NOCONFIG})
-      endif()
-    endforeach()
-  endif()
+    if(TARGET ${target})
+        foreach(property IN ITEMS IMPORTED_LOCATION IMPORTED_IMPLIB)
+            get_target_property(${basename}_${property}_DEBUG ${target} ${property}_DEBUG)
+            get_target_property(${basename}_${property}_MINSIZEREL ${target} ${property}_MINSIZEREL)
+            get_target_property(${basename}_${property}_NOCONFIG ${target} ${property}_NOCONFIG)
+            get_target_property(${basename}_${property}_RELEASE ${target} ${property}_RELEASE)
+            get_target_property(${basename}_${property}_RELWITHDEBINFO ${target} ${property}_RELWITHDEBINFO)
+
+            if(${basename}_${property}_DEBUG AND ${basename}_${property}_RELEASE)
+                set(${basename}_LIBRARY debug ${${basename}_${property}_DEBUG} optimized ${${basename}_${property}_RELEASE})
+            elseif(${basename}_${property}_DEBUG AND ${basename}_${property}_RELWITHDEBINFO)
+                set(${basename}_LIBRARY debug ${${basename}_${property}_DEBUG} optimized ${${basename}_${property}_RELWITHDEBINFO})
+            elseif(${basename}_${property}_DEBUG AND ${basename}_${property}_MINSIZEREL)
+                set(${basename}_LIBRARY debug ${${basename}_${property}_DEBUG} optimized ${${basename}_${property}_MINSIZEREL})
+            elseif(${basename}_${property}_RELEASE)
+                set(${basename}_LIBRARY ${${basename}_${property}_RELEASE})
+            elseif(${basename}_${property}_RELWITHDEBINFO)
+                set(${basename}_LIBRARY ${${basename}_${property}_RELWITHDEBINFO})
+            elseif(${basename}_${property}_MINSIZEREL)
+                set(${basename}_LIBRARY ${${basename}_${property}_MINSIZEREL})
+            elseif(${basename}_${property}_DEBUG)
+                set(${basename}_LIBRARY ${${basename}_${property}_DEBUG})
+            elseif(${basename}_${property}_NOCONFIG)
+                set(${basename}_LIBRARY ${${basename}_${property}_NOCONFIG})
+            endif()
+        endforeach()
+    endif()
 endmacro()
 
 macro(select_executable_location target basename)
-  if(TARGET ${target})
-    get_target_property(${basename}_IMPORTED_LOCATION_DEBUG ${target} IMPORTED_LOCATION_DEBUG)
-    get_target_property(${basename}_IMPORTED_LOCATION_MINSIZEREL ${target} IMPORTED_LOCATION_MINSIZEREL)
-    get_target_property(${basename}_IMPORTED_LOCATION_NOCONFIG ${target} IMPORTED_LOCATION_NOCONFIG)
-    get_target_property(${basename}_IMPORTED_LOCATION_RELEASE ${target} IMPORTED_LOCATION_RELEASE)
-    get_target_property(${basename}_IMPORTED_LOCATION_RELWITHDEBINFO ${target} IMPORTED_LOCATION_RELWITHDEBINFO)
-
-    if(${basename}_IMPORTED_LOCATION_RELEASE)
-      set(${basename}_EXECUTABLE ${${basename}_IMPORTED_LOCATION_RELEASE})
-    elseif(${basename}_IMPORTED_LOCATION_RELWITHDEBINFO)
-      set(${basename}_EXECUTABLE ${${basename}_IMPORTED_LOCATION_RELWITHDEBINFO})
-    elseif(${basename}_IMPORTED_LOCATION_MINSIZEREL)
-      set(${basename}_EXECUTABLE ${${basename}_IMPORTED_LOCATION_MINSIZEREL})
-    elseif(${basename}_IMPORTED_LOCATION_DEBUG)
-      set(${basename}_EXECUTABLE ${${basename}_IMPORTED_LOCATION_DEBUG})
-    elseif(${basename}_IMPORTED_LOCATION_NOCONFIG)
-      set(${basename}_EXECUTABLE ${${basename}_IMPORTED_LOCATION_NOCONFIG})
+    if(TARGET ${target})
+        get_target_property(${basename}_IMPORTED_LOCATION_DEBUG ${target} IMPORTED_LOCATION_DEBUG)
+        get_target_property(${basename}_IMPORTED_LOCATION_MINSIZEREL ${target} IMPORTED_LOCATION_MINSIZEREL)
+        get_target_property(${basename}_IMPORTED_LOCATION_NOCONFIG ${target} IMPORTED_LOCATION_NOCONFIG)
+        get_target_property(${basename}_IMPORTED_LOCATION_RELEASE ${target} IMPORTED_LOCATION_RELEASE)
+        get_target_property(${basename}_IMPORTED_LOCATION_RELWITHDEBINFO ${target} IMPORTED_LOCATION_RELWITHDEBINFO)
+
+        if(${basename}_IMPORTED_LOCATION_RELEASE)
+            set(${basename}_EXECUTABLE ${${basename}_IMPORTED_LOCATION_RELEASE})
+        elseif(${basename}_IMPORTED_LOCATION_RELWITHDEBINFO)
+            set(${basename}_EXECUTABLE ${${basename}_IMPORTED_LOCATION_RELWITHDEBINFO})
+        elseif(${basename}_IMPORTED_LOCATION_MINSIZEREL)
+            set(${basename}_EXECUTABLE ${${basename}_IMPORTED_LOCATION_MINSIZEREL})
+        elseif(${basename}_IMPORTED_LOCATION_DEBUG)
+            set(${basename}_EXECUTABLE ${${basename}_IMPORTED_LOCATION_DEBUG})
+        elseif(${basename}_IMPORTED_LOCATION_NOCONFIG)
+            set(${basename}_EXECUTABLE ${${basename}_IMPORTED_LOCATION_NOCONFIG})
+        endif()
     endif()
-  endif()
 endmacro()
 
 select_library_location(LibXml2::LibXml2 LIBXML2)
@@ -97,68 +97,72 @@ set(LIBXML2_WITH_THREADS @LIBXML2_WITH_THREADS@)
 set(LIBXML2_WITH_ICU @LIBXML2_WITH_ICU@)
 set(LIBXML2_WITH_LZMA @LIBXML2_WITH_LZMA@)
 set(LIBXML2_WITH_ZLIB @LIBXML2_WITH_ZLIB@)
+set(LIBXML2_WITH_HTTP @LIBXML2_WITH_HTTP@)
 
 if(LIBXML2_WITH_ICONV)
-  find_dependency(Iconv)
-  list(APPEND LIBXML2_LIBRARIES    ${Iconv_LIBRARIES})
-  list(APPEND LIBXML2_INCLUDE_DIRS ${Iconv_INCLUDE_DIRS})
-  if(NOT Iconv_FOUND)
-    set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
-    set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "Iconv dependency was not found")
-    return()
-  endif()
+    find_dependency(Iconv)
+    list(APPEND LIBXML2_LIBRARIES    ${Iconv_LIBRARIES})
+    list(APPEND LIBXML2_INCLUDE_DIRS ${Iconv_INCLUDE_DIRS})
+    if(NOT Iconv_FOUND)
+        set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
+        set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "Iconv dependency was not found")
+        return()
+    endif()
 endif()
 
 if(NOT LIBXML2_SHARED)
-  set(LIBXML2_DEFINITIONS -DLIBXML_STATIC)
-
-  if(LIBXML2_WITH_THREADS)
-    find_dependency(Threads)
-    list(APPEND LIBXML2_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
-    if(NOT Threads_FOUND)
-      set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
-      set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "Threads dependency was not found")
-      return()
+    set(LIBXML2_DEFINITIONS -DLIBXML_STATIC)
+
+    if(LIBXML2_WITH_THREADS)
+        find_dependency(Threads)
+        list(APPEND LIBXML2_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
+        if(NOT Threads_FOUND)
+            set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
+            set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "Threads dependency was not found")
+            return()
+        endif()
     endif()
-  endif()
-
-  if(LIBXML2_WITH_ICU)
-    find_dependency(ICU COMPONENTS data i18n uc)
-    list(APPEND LIBXML2_LIBRARIES    ${ICU_LIBRARIES})
-    if(NOT ICU_FOUND)
-      set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
-      set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "ICU dependency was not found")
-      return()
+
+    if(LIBXML2_WITH_ICU)
+        find_dependency(ICU COMPONENTS data i18n uc)
+        list(APPEND LIBXML2_LIBRARIES    ${ICU_LIBRARIES})
+        if(NOT ICU_FOUND)
+            set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
+            set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "ICU dependency was not found")
+            return()
+        endif()
     endif()
-  endif()
-
-  if(LIBXML2_WITH_LZMA)
-    find_dependency(LibLZMA)
-    list(APPEND LIBXML2_LIBRARIES    ${LIBLZMA_LIBRARIES})
-    if(NOT LibLZMA_FOUND)
-      set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
-      set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "LibLZMA dependency was not found")
-      return()
+
+    if(LIBXML2_WITH_LZMA)
+        find_dependency(LibLZMA)
+        list(APPEND LIBXML2_LIBRARIES    ${LIBLZMA_LIBRARIES})
+        if(NOT LibLZMA_FOUND)
+            set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
+            set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "LibLZMA dependency was not found")
+            return()
+        endif()
     endif()
-  endif()
-
-  if(LIBXML2_WITH_ZLIB)
-    find_dependency(ZLIB)
-    list(APPEND LIBXML2_LIBRARIES    ${ZLIB_LIBRARIES})
-    if(NOT ZLIB_FOUND)
-      set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
-      set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "ZLIB dependency was not found")
-      return()
+
+    if(LIBXML2_WITH_ZLIB)
+        find_dependency(ZLIB)
+        list(APPEND LIBXML2_LIBRARIES    ${ZLIB_LIBRARIES})
+        if(NOT ZLIB_FOUND)
+            set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
+            set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "ZLIB dependency was not found")
+            return()
+        endif()
     endif()
-  endif()
 
-  if(UNIX)
-    list(APPEND LIBXML2_LIBRARIES m)
-  endif()
+    if(UNIX)
+        list(APPEND LIBXML2_LIBRARIES m)
+    endif()
 
-  if(WIN32)
-    list(APPEND LIBXML2_LIBRARIES ws2_32)
-  endif()
+    if(WIN32)
+        list(APPEND LIBXML2_LIBRARIES Bcrypt)
+        if(LIBXML2_WITH_HTTP)
+            list(APPEND LIBXML2_LIBRARIES ws2_32)
+        endif()
+    endif()
 endif()
 
 # whether libxml2 has dso support
diff --git a/libxml2-config.cmake.in b/libxml2-config.cmake.in
index 6799fd25..31036805 100644
--- a/libxml2-config.cmake.in
+++ b/libxml2-config.cmake.in
@@ -50,71 +50,76 @@ set(LIBXML2_WITH_THREADS @WITH_THREADS@)
 set(LIBXML2_WITH_ICU @WITH_ICU@)
 set(LIBXML2_WITH_LZMA @WITH_LZMA@)
 set(LIBXML2_WITH_ZLIB @WITH_ZLIB@)
+set(LIBXML2_WITH_HTTP @WITH_HTTP@)
 
 if(LIBXML2_WITH_ICONV)
-  find_dependency(Iconv)
-  list(APPEND LIBXML2_LIBRARIES    ${Iconv_LIBRARIES})
-  list(APPEND LIBXML2_INCLUDE_DIRS ${Iconv_INCLUDE_DIRS})
-  list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "Iconv::Iconv")
-  if(NOT Iconv_FOUND)
-    set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
-    set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "Iconv dependency was not found")
-    return()
-  endif()
+    find_dependency(Iconv)
+    list(APPEND LIBXML2_LIBRARIES    ${Iconv_LIBRARIES})
+    list(APPEND LIBXML2_INCLUDE_DIRS ${Iconv_INCLUDE_DIRS})
+    list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "Iconv::Iconv")
+    if(NOT Iconv_FOUND)
+        set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
+        set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "Iconv dependency was not found")
+        return()
+    endif()
 endif()
 
 if(LIBXML2_WITH_THREADS)
-  find_dependency(Threads)
-  list(APPEND LIBXML2_LIBRARIES    ${CMAKE_THREAD_LIBS_INIT})
-  list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:Threads::Threads>")
-  if(NOT Threads_FOUND)
-    set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
-    set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "Threads dependency was not found")
-    return()
-  endif()
+    find_dependency(Threads)
+    list(APPEND LIBXML2_LIBRARIES    ${CMAKE_THREAD_LIBS_INIT})
+    list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:Threads::Threads>")
+    if(NOT Threads_FOUND)
+        set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
+        set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "Threads dependency was not found")
+        return()
+    endif()
 endif()
 
 if(LIBXML2_WITH_ICU)
-  find_dependency(ICU COMPONENTS data i18n uc)
-  list(APPEND LIBXML2_LIBRARIES    ${ICU_LIBRARIES})
-  list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:ICU::data>;\$<LINK_ONLY:ICU::i18n>;\$<LINK_ONLY:ICU::uc>")
-  if(NOT ICU_FOUND)
-    set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
-    set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "ICU dependency was not found")
-    return()
-  endif()
+    find_dependency(ICU COMPONENTS data i18n uc)
+    list(APPEND LIBXML2_LIBRARIES    ${ICU_LIBRARIES})
+    list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:ICU::data>;\$<LINK_ONLY:ICU::i18n>;\$<LINK_ONLY:ICU::uc>")
+    if(NOT ICU_FOUND)
+        set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
+        set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "ICU dependency was not found")
+        return()
+    endif()
 endif()
 
 if(LIBXML2_WITH_LZMA)
-  find_dependency(LibLZMA)
-  list(APPEND LIBXML2_LIBRARIES    ${LIBLZMA_LIBRARIES})
-  list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:LibLZMA::LibLZMA>")
-  if(NOT LibLZMA_FOUND)
-    set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
-    set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "LibLZMA dependency was not found")
-    return()
-  endif()
+    find_dependency(LibLZMA)
+    list(APPEND LIBXML2_LIBRARIES    ${LIBLZMA_LIBRARIES})
+    list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:LibLZMA::LibLZMA>")
+    if(NOT LibLZMA_FOUND)
+        set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
+        set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "LibLZMA dependency was not found")
+        return()
+    endif()
 endif()
 
 if(LIBXML2_WITH_ZLIB)
-  find_dependency(ZLIB)
-  list(APPEND LIBXML2_LIBRARIES    ${ZLIB_LIBRARIES})
-  list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:ZLIB::ZLIB>")
-  if(NOT ZLIB_FOUND)
-    set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
-    set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "ZLIB dependency was not found")
-    return()
-  endif()
+    find_dependency(ZLIB)
+    list(APPEND LIBXML2_LIBRARIES    ${ZLIB_LIBRARIES})
+    list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:ZLIB::ZLIB>")
+    if(NOT ZLIB_FOUND)
+        set(${CMAKE_FIND_PACKAGE_NAME}_FOUND FALSE)
+        set(${CMAKE_FIND_PACKAGE_NAME}_NOT_FOUND_MESSAGE "ZLIB dependency was not found")
+        return()
+    endif()
 endif()
 
 if(UNIX)
-  list(APPEND LIBXML2_LIBRARIES    m)
-  list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:m>")
+    list(APPEND LIBXML2_LIBRARIES    m)
+    list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:m>")
 endif()
 
 if(WIN32)
-  list(APPEND LIBXML2_LIBRARIES    ws2_32)
-  list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:ws2_32>")
+    list(APPEND LIBXML2_LIBRARIES Bcrypt)
+    list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:Bcrypt>")
+    if(LIBXML2_WITH_HTTP)
+        list(APPEND LIBXML2_LIBRARIES ws2_32)
+        list(APPEND LIBXML2_INTERFACE_LINK_LIBRARIES "\$<LINK_ONLY:ws2_32>")
+    endif()
 endif()
 
 # whether libxml2 has dso support
@@ -123,23 +128,23 @@ set(LIBXML2_MODULES @WITH_MODULES@)
 mark_as_advanced(LIBXML2_LIBRARY LIBXML2_XMLCATALOG_EXECUTABLE LIBXML2_XMLLINT_EXECUTABLE)
 
 if(DEFINED LIBXML2_LIBRARY AND DEFINED LIBXML2_INCLUDE_DIRS)
-  set(LIBXML2_FOUND TRUE)
+    set(LIBXML2_FOUND TRUE)
 endif()
 
 if(NOT TARGET LibXml2::LibXml2 AND DEFINED LIBXML2_LIBRARY AND DEFINED LIBXML2_INCLUDE_DIRS)
-  add_library(LibXml2::LibXml2 UNKNOWN IMPORTED)
-  set_target_properties(LibXml2::LibXml2 PROPERTIES IMPORTED_LOCATION "${LIBXML2_LIBRARY}")
-  set_target_properties(LibXml2::LibXml2 PROPERTIES INTERFACE_COMPILE_OPTIONS "${LIBXML2_DEFINITIONS}")
-  set_target_properties(LibXml2::LibXml2 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${LIBXML2_INCLUDE_DIRS}")
-  set_target_properties(LibXml2::LibXml2 PROPERTIES INTERFACE_LINK_LIBRARIES "${LIBXML2_INTERFACE_LINK_LIBRARIES}")
+    add_library(LibXml2::LibXml2 UNKNOWN IMPORTED)
+    set_target_properties(LibXml2::LibXml2 PROPERTIES IMPORTED_LOCATION "${LIBXML2_LIBRARY}")
+    set_target_properties(LibXml2::LibXml2 PROPERTIES INTERFACE_COMPILE_OPTIONS "${LIBXML2_DEFINITIONS}")
+    set_target_properties(LibXml2::LibXml2 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${LIBXML2_INCLUDE_DIRS}")
+    set_target_properties(LibXml2::LibXml2 PROPERTIES INTERFACE_LINK_LIBRARIES "${LIBXML2_INTERFACE_LINK_LIBRARIES}")
 endif()
 
 if(NOT TARGET LibXml2::xmlcatalog AND DEFINED LIBXML2_XMLCATALOG_EXECUTABLE)
-  add_executable(LibXml2::xmlcatalog IMPORTED)
-  set_target_properties(LibXml2::xmlcatalog PROPERTIES IMPORTED_LOCATION "${LIBXML2_XMLCATALOG_EXECUTABLE}")
+    add_executable(LibXml2::xmlcatalog IMPORTED)
+    set_target_properties(LibXml2::xmlcatalog PROPERTIES IMPORTED_LOCATION "${LIBXML2_XMLCATALOG_EXECUTABLE}")
 endif()
 
 if(NOT TARGET LibXml2::xmllint AND DEFINED LIBXML2_XMLLINT_EXECUTABLE)
-  add_executable(LibXml2::xmllint IMPORTED)
-  set_target_properties(LibXml2::xmllint PROPERTIES IMPORTED_LOCATION "${LIBXML2_XMLLINT_EXECUTABLE}")
+    add_executable(LibXml2::xmllint IMPORTED)
+    set_target_properties(LibXml2::xmllint PROPERTIES IMPORTED_LOCATION "${LIBXML2_XMLLINT_EXECUTABLE}")
 endif()
diff --git a/lintmain.c b/lintmain.c
new file mode 100644
index 00000000..9e49ec6c
--- /dev/null
+++ b/lintmain.c
@@ -0,0 +1,14 @@
+/*
+ * lintmain.c: Main routine for xmllint
+ *
+ * See Copyright for the status of this software.
+ */
+
+#include <stdio.h>
+
+#include "private/lint.h"
+
+int
+main(int argc, char **argv) {
+    return(xmllintMain(argc, (const char **) argv, stderr, NULL));
+}
diff --git a/m4/ax_recursive_eval.m4 b/m4/ax_recursive_eval.m4
new file mode 100644
index 00000000..0625aca2
--- /dev/null
+++ b/m4/ax_recursive_eval.m4
@@ -0,0 +1,56 @@
+# ===========================================================================
+#    https://www.gnu.org/software/autoconf-archive/ax_recursive_eval.html
+# ===========================================================================
+#
+# SYNOPSIS
+#
+#   AX_RECURSIVE_EVAL(VALUE, RESULT)
+#
+# DESCRIPTION
+#
+#   Interpolate the VALUE in loop until it doesn't change, and set the
+#   result to $RESULT. WARNING: It's easy to get an infinite loop with some
+#   unsane input.
+#
+# LICENSE
+#
+#   Copyright (c) 2008 Alexandre Duret-Lutz <adl@gnu.org>
+#
+#   This program is free software; you can redistribute it and/or modify it
+#   under the terms of the GNU General Public License as published by the
+#   Free Software Foundation; either version 2 of the License, or (at your
+#   option) any later version.
+#
+#   This program is distributed in the hope that it will be useful, but
+#   WITHOUT ANY WARRANTY; without even the implied warranty of
+#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
+#   Public License for more details.
+#
+#   You should have received a copy of the GNU General Public License along
+#   with this program. If not, see <https://www.gnu.org/licenses/>.
+#
+#   As a special exception, the respective Autoconf Macro's copyright owner
+#   gives unlimited permission to copy, distribute and modify the configure
+#   scripts that are the output of Autoconf when processing the Macro. You
+#   need not follow the terms of the GNU General Public License when using
+#   or distributing such scripts, even though portions of the text of the
+#   Macro appear in them. The GNU General Public License (GPL) does govern
+#   all other use of the material that constitutes the Autoconf Macro.
+#
+#   This special exception to the GPL applies to versions of the Autoconf
+#   Macro released by the Autoconf Archive. When you make and distribute a
+#   modified version of the Autoconf Macro, you may extend this special
+#   exception to the GPL to apply to your modified version as well.
+
+#serial 1
+
+AC_DEFUN([AX_RECURSIVE_EVAL],
+[_lcl_receval="$1"
+$2=`(test "x$prefix" = xNONE && prefix="$ac_default_prefix"
+     test "x$exec_prefix" = xNONE && exec_prefix="${prefix}"
+     _lcl_receval_old=''
+     while test "[$]_lcl_receval_old" != "[$]_lcl_receval"; do
+       _lcl_receval_old="[$]_lcl_receval"
+       eval _lcl_receval="\"[$]_lcl_receval\""
+     done
+     echo "[$]_lcl_receval")`])
diff --git a/meson.build b/meson.build
index 7b5880e3..55f3d765 100644
--- a/meson.build
+++ b/meson.build
@@ -3,7 +3,11 @@ project(
     'c',
     version: files('VERSION'),
     license: 'MIT',
-    default_options: ['buildtype=debug', 'warning_level=3'],
+    default_options: [
+        'c_std=c11,c99,c89',
+        'buildtype=debug',
+        'warning_level=3',
+    ],
     meson_version: '>= 0.61',
 )
 
@@ -52,6 +56,29 @@ endif
 # binaries
 cc = meson.get_compiler('c')
 
+# global compiler flags
+
+global_args = [
+    '-D_XOPEN_SOURCE=600',
+
+    # Enabled by warning_level=3
+    # '-pedantic',
+    # '-Wall',
+    # '-Wextra',
+
+    '-Wshadow',
+    '-Wpointer-arith',
+    '-Wcast-align',
+    '-Wwrite-strings',
+    '-Wstrict-prototypes',
+    '-Wmissing-prototypes',
+    '-Wno-long-long',
+    '-Wno-format-extra-args',
+    '-Wno-array-bounds',
+]
+global_args = cc.get_supported_arguments(global_args)
+add_project_arguments(global_args, language: 'c')
+
 # options
 
 # disabled by default
@@ -94,6 +121,9 @@ want_threads = want_minimum ? feature.enabled() : feature.allowed()
 feature = get_option('valid')
 want_valid = want_minimum ? feature.enabled() : feature.allowed()
 
+feature = get_option('xinclude')
+want_xinclude = want_minimum ? feature.enabled() : feature.allowed()
+
 # default depends on legacy option
 
 feature = get_option('http')
@@ -138,7 +168,6 @@ feature = get_option('xpath')
 want_xpath = not want_minimum \
     or get_option('c14n').enabled() \
     or get_option('schematron').enabled() \
-    or get_option('xinclude').enabled() \
     or get_option('xptr').enabled() ? \
     feature.allowed() : feature.enabled()
 
@@ -170,10 +199,6 @@ feature = get_option('writer') \
     .require(want_push, error_message: 'writer requires push')
 want_writer = want_minimum ? feature.enabled() : feature.allowed()
 
-feature = get_option('xinclude') \
-    .require(want_xpath, error_message: 'xinclude requires xpath')
-want_xinclude = want_minimum ? feature.enabled() : feature.allowed()
-
 feature = get_option('xptr') \
     .require(want_xpath, error_message: 'xptr requires xpath')
 want_xptr = want_minimum ? feature.enabled() : feature.allowed()
@@ -225,12 +250,8 @@ endforeach
 
 ## config.h
 config_h = configuration_data()
-config_h.set_quoted('PACKAGE_NAME', meson.project_name())
-config_h.set_quoted('PACKAGE_VERSION', meson.project_version())
-config_h.set_quoted('PACKAGE_BIN_DIR', dir_bin)
-config_h.set_quoted('PACKAGE_LIB_DIR', dir_lib)
-config_h.set_quoted('PACKAGE_DATA_DIR', dir_data)
-config_h.set_quoted('LOCALEDIR', dir_locale)
+config_h.set_quoted('XML_SYSCONFDIR',
+                    get_option('prefix') / get_option('sysconfdir'))
 
 # header files
 xml_check_headers = [
@@ -374,8 +395,8 @@ endif
 
 # icu
 if want_icu
-    icu_dep = dependency('icu-i18n', method: 'pkg-config')
-    defs = icu_dep.get_variable(pkgconfig: 'DEFS')
+    icu_dep = dependency('icu-uc')
+    defs = icu_dep.get_variable(pkgconfig: 'DEFS', default_value: '')
     if cc.has_argument(defs)
         libxml2_cflags += defs
     endif
@@ -431,7 +452,6 @@ xml_opt_src = [
     [want_reader, ['xmlreader.c']],
     [want_regexps, ['xmlregexp.c', 'xmlunicode.c']],
     [want_schemas, ['relaxng.c', 'xmlschemas.c', 'xmlschemastypes.c']],
-    [want_schemas and not want_xpath, ['xpath.c']],
     [want_schematron, ['schematron.c']],
     [want_writer, ['xmlwriter.c']],
     [want_xinclude, ['xinclude.c']],
@@ -474,7 +494,7 @@ meson.override_dependency('libxml-2.0', xml_dep)
 
 executable(
     'xmllint',
-    files('xmllint.c', 'shell.c'),
+    files('xmllint.c', 'shell.c', 'lintmain.c'),
     dependencies: [xml_dep, xmllint_deps],
     include_directories: config_dir,
     install: true,
@@ -482,13 +502,15 @@ executable(
 
 ## xmlcatalog tool
 
-executable(
-    'xmlcatalog',
-    files('xmlcatalog.c'),
-    dependencies: [xml_dep, xmllint_deps],
-    include_directories: config_dir,
-    install: true,
-)
+if want_catalog and want_output
+    executable(
+        'xmlcatalog',
+        files('xmlcatalog.c'),
+        dependencies: [xml_dep, xmllint_deps],
+        include_directories: config_dir,
+        install: true,
+    )
+endif
 
 ## testdso module
 
@@ -555,6 +577,7 @@ config_cmake.set('LIBXML_MAJOR_VERSION', v_maj)
 config_cmake.set('LIBXML_MINOR_VERSION', v_min)
 config_cmake.set('LIBXML_MICRO_VERSION', v_mic)
 config_cmake.set('VERSION', meson.project_version())
+config_cmake.set('WITH_HTTP', want_http.to_int().to_string())
 config_cmake.set('WITH_ICONV', want_iconv.to_int().to_string())
 config_cmake.set('WITH_ICU', want_icu.to_int().to_string())
 config_cmake.set('WITH_LZMA', want_lzma.to_int().to_string())
diff --git a/nanohttp.c b/nanohttp.c
index f8c5bdb9..f405da41 100644
--- a/nanohttp.c
+++ b/nanohttp.c
@@ -1581,7 +1581,7 @@ xmlNanoHTTPFetch(const char *URL, const char *filename, char **contentType) {
     if (ctxt == NULL) return(-1);
 
     if (!strcmp(filename, "-"))
-        fd = 0;
+        fd = 1; /* STDOUT_FILENO */
     else {
         fd = open(filename, O_CREAT | O_WRONLY, 00644);
 	if (fd < 0) {
@@ -1627,7 +1627,7 @@ xmlNanoHTTPSave(void *ctxt, const char *filename) {
     if ((ctxt == NULL) || (filename == NULL)) return(-1);
 
     if (!strcmp(filename, "-"))
-        fd = 0;
+        fd = 1; /* STDOUT_FILENO */
     else {
         fd = open(filename, O_CREAT | O_WRONLY, 0666);
 	if (fd < 0) {
diff --git a/parser.c b/parser.c
index 945e80b0..20fedfa3 100644
--- a/parser.c
+++ b/parser.c
@@ -73,6 +73,7 @@
 #include "private/error.h"
 #include "private/html.h"
 #include "private/io.h"
+#include "private/memory.h"
 #include "private/parser.h"
 
 #define NS_INDEX_EMPTY  INT_MAX
@@ -84,6 +85,12 @@
   #define STDIN_FILENO 0
 #endif
 
+#ifndef SIZE_MAX
+  #define SIZE_MAX ((size_t) -1)
+#endif
+
+#define XML_MAX_ATTRS 100000000 /* 100 million */
+
 struct _xmlStartTag {
     const xmlChar *prefix;
     const xmlChar *URI;
@@ -993,7 +1000,7 @@ struct _xmlDefAttrs {
     int maxAttrs;       /* the size of the array */
 #if __STDC_VERSION__ >= 199901L
     /* Using a C99 flexible array member avoids UBSan errors. */
-    xmlDefAttr attrs[]; /* array of localname/prefix/values/external */
+    xmlDefAttr attrs[] ATTRIBUTE_COUNTED_BY(maxAttrs);
 #else
     xmlDefAttr attrs[1];
 #endif
@@ -1100,7 +1107,19 @@ xmlAddDefAttrs(xmlParserCtxtPtr ctxt,
         xmlDefAttrsPtr temp;
         int newSize;
 
-        newSize = (defaults != NULL) ? 2 * defaults->maxAttrs : 4;
+        if (defaults == NULL) {
+            newSize = 4;
+        } else {
+            if ((defaults->maxAttrs >= XML_MAX_ATTRS) ||
+                ((size_t) defaults->maxAttrs >
+                     SIZE_MAX / 2 / sizeof(temp[0]) - sizeof(*defaults)))
+                goto mem_error;
+
+            if (defaults->maxAttrs > XML_MAX_ATTRS / 2)
+                newSize = XML_MAX_ATTRS;
+            else
+                newSize = defaults->maxAttrs * 2;
+        }
         temp = xmlRealloc(defaults,
                           sizeof(*defaults) + newSize * sizeof(xmlDefAttr));
 	if (temp == NULL)
@@ -1180,7 +1199,7 @@ xmlAddSpecialAttr(xmlParserCtxtPtr ctxt,
     }
 
     if (xmlHashAdd2(ctxt->attsSpecial, fullname, fullattr,
-                    (void *) (ptrdiff_t) type) < 0)
+                    XML_INT_TO_PTR(type)) < 0)
         goto mem_error;
     return;
 
@@ -1199,7 +1218,7 @@ xmlCleanSpecialAttrCallback(void *payload, void *data,
                             const xmlChar *unused ATTRIBUTE_UNUSED) {
     xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) data;
 
-    if (((ptrdiff_t) payload) == XML_ATTRIBUTE_CDATA) {
+    if (XML_PTR_TO_INT(payload) == XML_ATTRIBUTE_CDATA) {
         xmlHashRemoveEntry2(ctxt->attsSpecial, fullname, fullattr, NULL);
     }
 }
@@ -1666,9 +1685,11 @@ xmlParserNsGrow(xmlParserCtxtPtr ctxt) {
     xmlParserNsExtra *extra;
     int newSize;
 
-    if (ctxt->nsMax > INT_MAX / 2)
+    newSize = xmlGrowCapacity(ctxt->nsMax,
+                              sizeof(table[0]) + sizeof(extra[0]),
+                              16, XML_MAX_ITEMS);
+    if (newSize < 0)
         goto error;
-    newSize = ctxt->nsMax ? ctxt->nsMax * 2 : 16;
 
     table = xmlRealloc(ctxt->nsTab, 2 * newSize * sizeof(table[0]));
     if (table == NULL)
@@ -1888,37 +1909,42 @@ xmlParserNsPop(xmlParserCtxtPtr ctxt, int nr)
 }
 
 static int
-xmlCtxtGrowAttrs(xmlParserCtxtPtr ctxt, int nr) {
+xmlCtxtGrowAttrs(xmlParserCtxtPtr ctxt) {
     const xmlChar **atts;
     unsigned *attallocs;
-    int maxatts;
-
-    if (nr + 5 > ctxt->maxatts) {
-	maxatts = ctxt->maxatts == 0 ? 55 : (nr + 5) * 2;
-	atts = (const xmlChar **) xmlMalloc(
-				     maxatts * sizeof(const xmlChar *));
-	if (atts == NULL) goto mem_error;
-	attallocs = xmlRealloc(ctxt->attallocs,
-                               (maxatts / 5) * sizeof(attallocs[0]));
-	if (attallocs == NULL) {
-            xmlFree(atts);
-            goto mem_error;
-        }
-        if (ctxt->maxatts > 0)
-            memcpy(atts, ctxt->atts, ctxt->maxatts * sizeof(const xmlChar *));
-        xmlFree(ctxt->atts);
-	ctxt->atts = atts;
-	ctxt->attallocs = attallocs;
-	ctxt->maxatts = maxatts;
-    }
-    return(ctxt->maxatts);
+    int newSize;
+
+    newSize = xmlGrowCapacity(ctxt->maxatts / 5,
+                              sizeof(atts[0]) * 5 + sizeof(attallocs[0]),
+                              10, XML_MAX_ATTRS);
+    if (newSize < 0) {
+        xmlFatalErr(ctxt, XML_ERR_RESOURCE_LIMIT,
+                    "Maximum number of attributes exceeded");
+        return(-1);
+    }
+
+    atts = xmlRealloc(ctxt->atts, newSize * sizeof(atts[0]) * 5);
+    if (atts == NULL)
+        goto mem_error;
+    ctxt->atts = atts;
+
+    attallocs = xmlRealloc(ctxt->attallocs,
+                           newSize * sizeof(attallocs[0]));
+    if (attallocs == NULL)
+        goto mem_error;
+    ctxt->attallocs = attallocs;
+
+    ctxt->maxatts = newSize * 5;
+
+    return(0);
+
 mem_error:
     xmlErrMemory(ctxt);
     return(-1);
 }
 
 /**
- * inputPush:
+ * xmlCtxtPushInput:
  * @ctxt:  an XML parser context
  * @value:  the parser input
  *
@@ -1927,22 +1953,32 @@ mem_error:
  * Returns -1 in case of error, the index in the stack otherwise
  */
 int
-inputPush(xmlParserCtxtPtr ctxt, xmlParserInputPtr value)
+xmlCtxtPushInput(xmlParserCtxtPtr ctxt, xmlParserInputPtr value)
 {
     char *directory = NULL;
+    int maxDepth;
 
     if ((ctxt == NULL) || (value == NULL))
         return(-1);
 
+    maxDepth = (ctxt->options & XML_PARSE_HUGE) ? 40 : 20;
+
     if (ctxt->inputNr >= ctxt->inputMax) {
-        size_t newSize = ctxt->inputMax * 2;
         xmlParserInputPtr *tmp;
+        int newSize;
 
-        tmp = (xmlParserInputPtr *) xmlRealloc(ctxt->inputTab,
-                                               newSize * sizeof(*tmp));
+        newSize = xmlGrowCapacity(ctxt->inputMax, sizeof(tmp[0]),
+                                  5, maxDepth);
+        if (newSize < 0) {
+            xmlFatalErrMsg(ctxt, XML_ERR_RESOURCE_LIMIT,
+                           "Maximum entity nesting depth exceeded");
+            xmlHaltParser(ctxt);
+            return(-1);
+        }
+        tmp = xmlRealloc(ctxt->inputTab, newSize * sizeof(tmp[0]));
         if (tmp == NULL) {
             xmlErrMemory(ctxt);
-            return (-1);
+            return(-1);
         }
         ctxt->inputTab = tmp;
         ctxt->inputMax = newSize;
@@ -1978,8 +2014,9 @@ inputPush(xmlParserCtxtPtr ctxt, xmlParserInputPtr value)
 
     return(ctxt->inputNr++);
 }
+
 /**
- * inputPop:
+ * xmlCtxtPopInput:
  * @ctxt: an XML parser context
  *
  * Pops the top parser input from the input stack
@@ -1987,7 +2024,7 @@ inputPush(xmlParserCtxtPtr ctxt, xmlParserInputPtr value)
  * Returns the input just removed
  */
 xmlParserInputPtr
-inputPop(xmlParserCtxtPtr ctxt)
+xmlCtxtPopInput(xmlParserCtxtPtr ctxt)
 {
     xmlParserInputPtr ret;
 
@@ -2004,6 +2041,34 @@ inputPop(xmlParserCtxtPtr ctxt)
     ctxt->inputTab[ctxt->inputNr] = NULL;
     return (ret);
 }
+
+/**
+ * inputPush:
+ * @ctxt:  an XML parser context
+ * @value:  the parser input
+ *
+ * Pushes a new parser input on top of the input stack
+ *
+ * Returns -1 in case of error, the index in the stack otherwise
+ */
+int
+inputPush(xmlParserCtxtPtr ctxt, xmlParserInputPtr value)
+{
+    return(xmlCtxtPushInput(ctxt, value));
+}
+/**
+ * inputPop:
+ * @ctxt: an XML parser context
+ *
+ * Pops the top parser input from the input stack
+ *
+ * Returns the input just removed
+ */
+xmlParserInputPtr
+inputPop(xmlParserCtxtPtr ctxt)
+{
+    return(xmlCtxtPopInput(ctxt));
+}
 /**
  * nodePush:
  * @ctxt:  an XML parser context
@@ -2018,32 +2083,34 @@ inputPop(xmlParserCtxtPtr ctxt)
 int
 nodePush(xmlParserCtxtPtr ctxt, xmlNodePtr value)
 {
-    int maxDepth;
-
     if (ctxt == NULL)
         return(0);
 
-    maxDepth = (ctxt->options & XML_PARSE_HUGE) ? 2048 : 256;
-    if (ctxt->nodeNr > maxDepth) {
-        xmlFatalErrMsgInt(ctxt, XML_ERR_RESOURCE_LIMIT,
-                "Excessive depth in document: %d use XML_PARSE_HUGE option\n",
-                ctxt->nodeNr);
-        xmlHaltParser(ctxt);
-        return(-1);
-    }
     if (ctxt->nodeNr >= ctxt->nodeMax) {
+        int maxDepth = (ctxt->options & XML_PARSE_HUGE) ? 2048 : 256;
         xmlNodePtr *tmp;
+        int newSize;
 
-	tmp = (xmlNodePtr *) xmlRealloc(ctxt->nodeTab,
-                                      ctxt->nodeMax * 2 *
-                                      sizeof(ctxt->nodeTab[0]));
+        newSize = xmlGrowCapacity(ctxt->nodeMax, sizeof(tmp[0]),
+                                  10, maxDepth);
+        if (newSize < 0) {
+            xmlFatalErrMsgInt(ctxt, XML_ERR_RESOURCE_LIMIT,
+                    "Excessive depth in document: %d,"
+                    " use XML_PARSE_HUGE option\n",
+                    ctxt->nodeNr);
+            xmlHaltParser(ctxt);
+            return(-1);
+        }
+
+	tmp = xmlRealloc(ctxt->nodeTab, newSize * sizeof(tmp[0]));
         if (tmp == NULL) {
             xmlErrMemory(ctxt);
             return (-1);
         }
         ctxt->nodeTab = tmp;
-	ctxt->nodeMax *= 2;
+	ctxt->nodeMax = newSize;
     }
+
     ctxt->nodeTab[ctxt->nodeNr] = value;
     ctxt->node = value;
     return (ctxt->nodeNr++);
@@ -2097,28 +2164,29 @@ nameNsPush(xmlParserCtxtPtr ctxt, const xmlChar * value,
     xmlStartTag *tag;
 
     if (ctxt->nameNr >= ctxt->nameMax) {
-        const xmlChar * *tmp;
+        const xmlChar **tmp;
         xmlStartTag *tmp2;
-        ctxt->nameMax *= 2;
-        tmp = (const xmlChar * *) xmlRealloc((xmlChar * *)ctxt->nameTab,
-                                    ctxt->nameMax *
-                                    sizeof(ctxt->nameTab[0]));
-        if (tmp == NULL) {
-	    ctxt->nameMax /= 2;
+        int newSize;
+
+        newSize = xmlGrowCapacity(ctxt->nameMax,
+                                  sizeof(tmp[0]) + sizeof(tmp2[0]),
+                                  10, XML_MAX_ITEMS);
+        if (newSize < 0)
+            goto mem_error;
+
+        tmp = xmlRealloc(ctxt->nameTab, newSize * sizeof(tmp[0]));
+        if (tmp == NULL)
 	    goto mem_error;
-        }
 	ctxt->nameTab = tmp;
-        tmp2 = (xmlStartTag *) xmlRealloc((void * *)ctxt->pushTab,
-                                    ctxt->nameMax *
-                                    sizeof(ctxt->pushTab[0]));
-        if (tmp2 == NULL) {
-	    ctxt->nameMax /= 2;
+
+        tmp2 = xmlRealloc(ctxt->pushTab, newSize * sizeof(tmp2[0]));
+        if (tmp2 == NULL)
 	    goto mem_error;
-        }
 	ctxt->pushTab = tmp2;
+
+        ctxt->nameMax = newSize;
     } else if (ctxt->pushTab == NULL) {
-        ctxt->pushTab = (xmlStartTag *) xmlMalloc(ctxt->nameMax *
-                                            sizeof(ctxt->pushTab[0]));
+        ctxt->pushTab = xmlMalloc(ctxt->nameMax * sizeof(ctxt->pushTab[0]));
         if (ctxt->pushTab == NULL)
             goto mem_error;
     }
@@ -2178,15 +2246,20 @@ namePush(xmlParserCtxtPtr ctxt, const xmlChar * value)
     if (ctxt == NULL) return (-1);
 
     if (ctxt->nameNr >= ctxt->nameMax) {
-        const xmlChar * *tmp;
-        tmp = (const xmlChar * *) xmlRealloc((xmlChar * *)ctxt->nameTab,
-                                    ctxt->nameMax * 2 *
-                                    sizeof(ctxt->nameTab[0]));
-        if (tmp == NULL) {
+        const xmlChar **tmp;
+        int newSize;
+
+        newSize = xmlGrowCapacity(ctxt->nameMax, sizeof(tmp[0]),
+                                  10, XML_MAX_ITEMS);
+        if (newSize < 0)
+            goto mem_error;
+
+        tmp = xmlRealloc(ctxt->nameTab, newSize * sizeof(tmp[0]));
+        if (tmp == NULL)
 	    goto mem_error;
-        }
 	ctxt->nameTab = tmp;
-        ctxt->nameMax *= 2;
+
+        ctxt->nameMax = newSize;
     }
     ctxt->nameTab[ctxt->nameNr] = value;
     ctxt->name = value;
@@ -2226,16 +2299,23 @@ namePop(xmlParserCtxtPtr ctxt)
 static int spacePush(xmlParserCtxtPtr ctxt, int val) {
     if (ctxt->spaceNr >= ctxt->spaceMax) {
         int *tmp;
+        int newSize;
+
+        newSize = xmlGrowCapacity(ctxt->spaceMax, sizeof(tmp[0]),
+                                  10, XML_MAX_ITEMS);
+        if (newSize < 0) {
+	    xmlErrMemory(ctxt);
+	    return(-1);
+        }
 
-	ctxt->spaceMax *= 2;
-        tmp = (int *) xmlRealloc(ctxt->spaceTab,
-	                         ctxt->spaceMax * sizeof(ctxt->spaceTab[0]));
+        tmp = xmlRealloc(ctxt->spaceTab, newSize * sizeof(tmp[0]));
         if (tmp == NULL) {
 	    xmlErrMemory(ctxt);
-	    ctxt->spaceMax /=2;
 	    return(-1);
 	}
 	ctxt->spaceTab = tmp;
+
+        ctxt->spaceMax = newSize;
     }
     ctxt->spaceTab[ctxt->spaceNr] = val;
     ctxt->space = &ctxt->spaceTab[ctxt->spaceNr];
@@ -2331,9 +2411,7 @@ static int spacePop(xmlParserCtxtPtr ctxt) {
   } while (0)
 
 #define SHRINK \
-    if ((!PARSER_PROGRESSIVE(ctxt)) && \
-        (ctxt->input->cur - ctxt->input->base > 2 * INPUT_CHUNK) && \
-	(ctxt->input->end - ctxt->input->cur < 2 * INPUT_CHUNK)) \
+    if (!PARSER_PROGRESSIVE(ctxt)) \
 	xmlParserShrink(ctxt);
 
 #define GROW \
@@ -2392,10 +2470,6 @@ xmlSkipBlankChars(xmlParserCtxtPtr ctxt) {
     const xmlChar *cur;
     int res = 0;
 
-    /*
-     * It's Okay to use CUR/NEXT here since all the blanks are on
-     * the ASCII range.
-     */
     cur = ctxt->input->cur;
     while (IS_BLANK_CH(*cur)) {
         if (*cur == '\n') {
@@ -2414,6 +2488,9 @@ xmlSkipBlankChars(xmlParserCtxtPtr ctxt) {
     }
     ctxt->input->cur = cur;
 
+    if (res > 4)
+        GROW;
+
     return(res);
 }
 
@@ -2456,9 +2533,11 @@ xmlPopPE(xmlParserCtxtPtr ctxt) {
         ent->flags |= XML_ENT_CHECKED;
     }
 
-    xmlPopInput(ctxt);
+    xmlFreeInputStream(xmlCtxtPopInput(ctxt));
 
     xmlParserEntityCheck(ctxt, ent->expandedSize);
+
+    GROW;
 }
 
 /**
@@ -2482,6 +2561,10 @@ xmlSkipBlankCharsPE(xmlParserCtxtPtr ctxt) {
     if (!inParam && !expandParam)
         return(xmlSkipBlankChars(ctxt));
 
+    /*
+     * It's Okay to use CUR/NEXT here since all the blanks are on
+     * the ASCII range.
+     */
     while (PARSER_STOPPED(ctxt) == 0) {
         if (IS_BLANK_CH(CUR)) { /* CHECKED tstblanks.xml */
             NEXT;
@@ -2536,8 +2619,7 @@ xmlSkipBlankCharsPE(xmlParserCtxtPtr ctxt) {
  * xmlPopInput:
  * @ctxt:  an XML parser context
  *
- * xmlPopInput: the current input pointed by ctxt->input came to an end
- *          pop it and return the next char.
+ * DEPRECATED: Internal function, don't use.
  *
  * Returns the current xmlChar in the parser context
  */
@@ -2546,7 +2628,7 @@ xmlPopInput(xmlParserCtxtPtr ctxt) {
     xmlParserInputPtr input;
 
     if ((ctxt == NULL) || (ctxt->inputNr <= 1)) return(0);
-    input = inputPop(ctxt);
+    input = xmlCtxtPopInput(ctxt);
     xmlFreeInputStream(input);
     if (*ctxt->input->cur == 0)
         xmlParserGrow(ctxt);
@@ -2558,26 +2640,20 @@ xmlPopInput(xmlParserCtxtPtr ctxt) {
  * @ctxt:  an XML parser context
  * @input:  an XML parser input fragment (entity, XML fragment ...).
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Push an input stream onto the stack.
  *
  * Returns -1 in case of error or the index in the input stack
  */
 int
 xmlPushInput(xmlParserCtxtPtr ctxt, xmlParserInputPtr input) {
-    int maxDepth;
     int ret;
 
     if ((ctxt == NULL) || (input == NULL))
         return(-1);
 
-    maxDepth = (ctxt->options & XML_PARSE_HUGE) ? 40 : 20;
-    if (ctxt->inputNr > maxDepth) {
-        xmlFatalErrMsg(ctxt, XML_ERR_RESOURCE_LIMIT,
-                       "Maximum entity nesting depth exceeded");
-        xmlHaltParser(ctxt);
-	return(-1);
-    }
-    ret = inputPush(ctxt, input);
+    ret = xmlCtxtPushInput(ctxt, input);
     if (ret >= 0)
         GROW;
     return(ret);
@@ -2902,13 +2978,6 @@ static int areBlanks(xmlParserCtxtPtr ctxt, const xmlChar *str, int len,
     int i;
     xmlNodePtr lastChild;
 
-    /*
-     * Don't spend time trying to differentiate them, the same callback is
-     * used !
-     */
-    if (ctxt->sax->ignorableWhitespace == ctxt->sax->characters)
-	return(0);
-
     /*
      * Check for xml:space value.
      */
@@ -2952,6 +3021,10 @@ static int areBlanks(xmlParserCtxtPtr ctxt, const xmlChar *str, int len,
 
     /*
      * Otherwise, heuristic :-\
+     *
+     * When push parsing, we could be at the end of a chunk.
+     * This makes the look-ahead and consequently the NOBLANKS
+     * option unreliable.
      */
     if ((RAW != '<') && (RAW != 0xD)) return(0);
     if ((ctxt->node->children == NULL) &&
@@ -3037,15 +3110,22 @@ xmlSplitQName(xmlParserCtxtPtr ctxt, const xmlChar *name, xmlChar **prefixOut) {
 	while ((c != 0) && (c != ':')) { /* tested bigname.xml */
 	    if (len + 10 > max) {
 	        xmlChar *tmp;
+                int newSize;
 
-		max *= 2;
-		tmp = (xmlChar *) xmlRealloc(buffer, max);
-		if (tmp == NULL) {
+                newSize = xmlGrowCapacity(max, 1, 1, XML_MAX_ITEMS);
+                if (newSize < 0) {
+		    xmlErrMemory(ctxt);
 		    xmlFree(buffer);
+		    return(NULL);
+                }
+		tmp = xmlRealloc(buffer, newSize);
+		if (tmp == NULL) {
 		    xmlErrMemory(ctxt);
+		    xmlFree(buffer);
 		    return(NULL);
 		}
 		buffer = tmp;
+		max = newSize;
 	    }
 	    buffer[len++] = c;
 	    c = *cur++;
@@ -3125,9 +3205,15 @@ xmlSplitQName(xmlParserCtxtPtr ctxt, const xmlChar *name, xmlChar **prefixOut) {
 	    while (c != 0) { /* tested bigname2.xml */
 		if (len + 10 > max) {
 		    xmlChar *tmp;
+                    int newSize;
 
-		    max *= 2;
-		    tmp = (xmlChar *) xmlRealloc(buffer, max);
+                    newSize = xmlGrowCapacity(max, 1, 1, XML_MAX_ITEMS);
+                    if (newSize < 0) {
+                        xmlErrMemory(ctxt);
+                        xmlFree(buffer);
+                        return(NULL);
+                    }
+		    tmp = xmlRealloc(buffer, newSize);
 		    if (tmp == NULL) {
 			xmlErrMemory(ctxt);
                         xmlFree(prefix);
@@ -3135,6 +3221,7 @@ xmlSplitQName(xmlParserCtxtPtr ctxt, const xmlChar *name, xmlChar **prefixOut) {
 			return(NULL);
 		    }
 		    buffer = tmp;
+                    max = newSize;
 		}
 		buffer[len++] = c;
 		c = *cur++;
@@ -3621,24 +3708,26 @@ xmlParseStringName(xmlParserCtxtPtr ctxt, const xmlChar** str) {
 	    while (xmlIsNameChar(ctxt, c)) {
 		if (len + 10 > max) {
 		    xmlChar *tmp;
+                    int newSize;
 
-		    max *= 2;
-		    tmp = (xmlChar *) xmlRealloc(buffer, max);
+                    newSize = xmlGrowCapacity(max, 1, 1, maxLength);
+                    if (newSize < 0) {
+                        xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "NCName");
+                        xmlFree(buffer);
+                        return(NULL);
+                    }
+		    tmp = xmlRealloc(buffer, newSize);
 		    if (tmp == NULL) {
 			xmlErrMemory(ctxt);
 			xmlFree(buffer);
 			return(NULL);
 		    }
 		    buffer = tmp;
+                    max = newSize;
 		}
 		COPY_BUF(buffer, len, c);
 		cur += l;
 		c = CUR_SCHAR(cur, l);
-                if (len > maxLength) {
-                    xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "NCName");
-                    xmlFree(buffer);
-                    return(NULL);
-                }
 	    }
 	    buffer[len] = 0;
 	    *str = cur;
@@ -3704,22 +3793,24 @@ xmlParseNmtoken(xmlParserCtxtPtr ctxt) {
 	    while (xmlIsNameChar(ctxt, c)) {
 		if (len + 10 > max) {
 		    xmlChar *tmp;
+                    int newSize;
 
-		    max *= 2;
-		    tmp = (xmlChar *) xmlRealloc(buffer, max);
+                    newSize = xmlGrowCapacity(max, 1, 1, maxLength);
+                    if (newSize < 0) {
+                        xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "NmToken");
+                        xmlFree(buffer);
+                        return(NULL);
+                    }
+		    tmp = xmlRealloc(buffer, newSize);
 		    if (tmp == NULL) {
 			xmlErrMemory(ctxt);
 			xmlFree(buffer);
 			return(NULL);
 		    }
 		    buffer = tmp;
+                    max = newSize;
 		}
 		COPY_BUF(buffer, len, c);
-                if (len > maxLength) {
-                    xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "NmToken");
-                    xmlFree(buffer);
-                    return(NULL);
-                }
 		NEXTL(l);
 		c = xmlCurrentChar(ctxt, &l);
 	    }
@@ -4623,22 +4714,24 @@ xmlParseSystemLiteral(xmlParserCtxtPtr ctxt) {
     while ((IS_CHAR(cur)) && (cur != stop)) { /* checked */
 	if (len + 5 >= size) {
 	    xmlChar *tmp;
+            int newSize;
 
-	    size *= 2;
-	    tmp = (xmlChar *) xmlRealloc(buf, size);
+            newSize = xmlGrowCapacity(size, 1, 1, maxLength);
+            if (newSize < 0) {
+                xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "SystemLiteral");
+                xmlFree(buf);
+                return(NULL);
+            }
+	    tmp = xmlRealloc(buf, newSize);
 	    if (tmp == NULL) {
 	        xmlFree(buf);
 		xmlErrMemory(ctxt);
 		return(NULL);
 	    }
 	    buf = tmp;
+            size = newSize;
 	}
 	COPY_BUF(buf, len, cur);
-        if (len > maxLength) {
-            xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "SystemLiteral");
-            xmlFree(buf);
-            return(NULL);
-        }
 	NEXTL(l);
 	cur = xmlCurrentCharRecover(ctxt, &l);
     }
@@ -4695,22 +4788,24 @@ xmlParsePubidLiteral(xmlParserCtxtPtr ctxt) {
            (PARSER_STOPPED(ctxt) == 0)) { /* checked */
 	if (len + 1 >= size) {
 	    xmlChar *tmp;
+            int newSize;
 
-	    size *= 2;
-	    tmp = (xmlChar *) xmlRealloc(buf, size);
+	    newSize = xmlGrowCapacity(size, 1, 1, maxLength);
+            if (newSize) {
+                xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "Public ID");
+                xmlFree(buf);
+                return(NULL);
+            }
+	    tmp = xmlRealloc(buf, size);
 	    if (tmp == NULL) {
 		xmlErrMemory(ctxt);
 		xmlFree(buf);
 		return(NULL);
 	    }
 	    buf = tmp;
+            size = newSize;
 	}
 	buf[len++] = cur;
-        if (len > maxLength) {
-            xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "Public ID");
-            xmlFree(buf);
-            return(NULL);
-        }
 	NEXT;
 	cur = CUR;
     }
@@ -4763,6 +4858,34 @@ static const unsigned char test_char_data[256] = {
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
 };
 
+static void
+xmlCharacters(xmlParserCtxtPtr ctxt, const xmlChar *buf, int size) {
+    if ((ctxt->sax == NULL) || (ctxt->disableSAX))
+        return;
+
+    /*
+     * Calling areBlanks with only parts of a text node
+     * is fundamentally broken, making the NOBLANKS option
+     * essentially unusable.
+     */
+    if ((!ctxt->keepBlanks) &&
+        (ctxt->sax->ignorableWhitespace != ctxt->sax->characters) &&
+        (areBlanks(ctxt, buf, size, 1))) {
+        if (ctxt->sax->ignorableWhitespace != NULL)
+            ctxt->sax->ignorableWhitespace(ctxt->userData, buf, size);
+    } else {
+        if (ctxt->sax->characters != NULL)
+            ctxt->sax->characters(ctxt->userData, buf, size);
+
+        /*
+         * The old code used to update this value for "complex" data
+         * even if keepBlanks was true. This was probably a bug.
+         */
+        if ((!ctxt->keepBlanks) && (*ctxt->space == -1))
+            *ctxt->space = -2;
+    }
+}
+
 /**
  * xmlParseCharDataInternal:
  * @ctxt:  an XML parser context
@@ -4808,27 +4931,7 @@ get_more_space:
                 const xmlChar *tmp = ctxt->input->cur;
                 ctxt->input->cur = in;
 
-                if ((ctxt->sax != NULL) &&
-                    (ctxt->disableSAX == 0) &&
-                    (ctxt->sax->ignorableWhitespace !=
-                     ctxt->sax->characters)) {
-                    if (areBlanks(ctxt, tmp, nbchar, 1)) {
-                        if (ctxt->sax->ignorableWhitespace != NULL)
-                            ctxt->sax->ignorableWhitespace(ctxt->userData,
-                                                   tmp, nbchar);
-                    } else {
-                        if (ctxt->sax->characters != NULL)
-                            ctxt->sax->characters(ctxt->userData,
-                                                  tmp, nbchar);
-                        if (*ctxt->space == -1)
-                            *ctxt->space = -2;
-                    }
-                } else if ((ctxt->sax != NULL) &&
-                           (ctxt->disableSAX == 0) &&
-                           (ctxt->sax->characters != NULL)) {
-                    ctxt->sax->characters(ctxt->userData,
-                                          tmp, nbchar);
-                }
+                xmlCharacters(ctxt, tmp, nbchar);
             }
             return;
         }
@@ -4853,41 +4956,21 @@ get_more:
                 ctxt->input->cur = in + 1;
                 return;
             }
-            in++;
-            ctxt->input->col++;
-            goto get_more;
+            if ((!partial) || (ctxt->input->end - in >= 2)) {
+                in++;
+                ctxt->input->col++;
+                goto get_more;
+            }
         }
         nbchar = in - ctxt->input->cur;
         if (nbchar > 0) {
-            if ((ctxt->sax != NULL) &&
-                (ctxt->disableSAX == 0) &&
-                (ctxt->sax->ignorableWhitespace !=
-                 ctxt->sax->characters) &&
-                (IS_BLANK_CH(*ctxt->input->cur))) {
-                const xmlChar *tmp = ctxt->input->cur;
-                ctxt->input->cur = in;
+            const xmlChar *tmp = ctxt->input->cur;
+            ctxt->input->cur = in;
 
-                if (areBlanks(ctxt, tmp, nbchar, 0)) {
-                    if (ctxt->sax->ignorableWhitespace != NULL)
-                        ctxt->sax->ignorableWhitespace(ctxt->userData,
-                                                       tmp, nbchar);
-                } else {
-                    if (ctxt->sax->characters != NULL)
-                        ctxt->sax->characters(ctxt->userData,
-                                              tmp, nbchar);
-                    if (*ctxt->space == -1)
-                        *ctxt->space = -2;
-                }
-                line = ctxt->input->line;
-                col = ctxt->input->col;
-            } else if ((ctxt->sax != NULL) &&
-                       (ctxt->disableSAX == 0)) {
-                if (ctxt->sax->characters != NULL)
-                    ctxt->sax->characters(ctxt->userData,
-                                          ctxt->input->cur, nbchar);
-                line = ctxt->input->line;
-                col = ctxt->input->col;
-            }
+            xmlCharacters(ctxt, tmp, nbchar);
+
+            line = ctxt->input->line;
+            col = ctxt->input->col;
         }
         ctxt->input->cur = in;
         if (*in == 0xD) {
@@ -4906,6 +4989,9 @@ get_more:
         if (*in == '&') {
             return;
         }
+        if ((partial) && (*in == ']') && (ctxt->input->end - in < 2)) {
+            return;
+        }
         SHRINK;
         GROW;
         in = ctxt->input->cur;
@@ -4936,6 +5022,8 @@ xmlParseCharDataComplex(xmlParserCtxtPtr ctxt, int partial) {
     cur = xmlCurrentCharRecover(ctxt, &l);
     while ((cur != '<') && /* checked */
            (cur != '&') &&
+           ((!partial) || (cur != ']') ||
+            (ctxt->input->end - ctxt->input->cur >= 2)) &&
 	   (IS_CHAR(cur))) {
 	if ((cur == ']') && (NXT(1) == ']') && (NXT(2) == '>')) {
 	    xmlFatalErr(ctxt, XML_ERR_MISPLACED_CDATA_END, NULL);
@@ -4946,23 +5034,7 @@ xmlParseCharDataComplex(xmlParserCtxtPtr ctxt, int partial) {
 	if (nbchar >= XML_PARSER_BIG_BUFFER_SIZE) {
 	    buf[nbchar] = 0;
 
-	    /*
-	     * OK the segment is to be consumed as chars.
-	     */
-	    if ((ctxt->sax != NULL) && (!ctxt->disableSAX)) {
-		if (areBlanks(ctxt, buf, nbchar, 0)) {
-		    if (ctxt->sax->ignorableWhitespace != NULL)
-			ctxt->sax->ignorableWhitespace(ctxt->userData,
-			                               buf, nbchar);
-		} else {
-		    if (ctxt->sax->characters != NULL)
-			ctxt->sax->characters(ctxt->userData, buf, nbchar);
-		    if ((ctxt->sax->characters !=
-		         ctxt->sax->ignorableWhitespace) &&
-			(*ctxt->space == -1))
-			*ctxt->space = -2;
-		}
-	    }
+            xmlCharacters(ctxt, buf, nbchar);
 	    nbchar = 0;
             SHRINK;
 	}
@@ -4970,21 +5042,8 @@ xmlParseCharDataComplex(xmlParserCtxtPtr ctxt, int partial) {
     }
     if (nbchar != 0) {
         buf[nbchar] = 0;
-	/*
-	 * OK the segment is to be consumed as chars.
-	 */
-	if ((ctxt->sax != NULL) && (!ctxt->disableSAX)) {
-	    if (areBlanks(ctxt, buf, nbchar, 0)) {
-		if (ctxt->sax->ignorableWhitespace != NULL)
-		    ctxt->sax->ignorableWhitespace(ctxt->userData, buf, nbchar);
-	    } else {
-		if (ctxt->sax->characters != NULL)
-		    ctxt->sax->characters(ctxt->userData, buf, nbchar);
-		if ((ctxt->sax->characters != ctxt->sax->ignorableWhitespace) &&
-		    (*ctxt->space == -1))
-		    *ctxt->space = -2;
-	    }
-	}
+
+        xmlCharacters(ctxt, buf, nbchar);
     }
     /*
      * cur == 0 can mean
@@ -5000,7 +5059,7 @@ xmlParseCharDataComplex(xmlParserCtxtPtr ctxt, int partial) {
                         "Incomplete UTF-8 sequence starting with %02X\n", CUR);
                 NEXTL(1);
             }
-        } else if ((cur != '<') && (cur != '&')) {
+        } else if ((cur != '<') && (cur != '&') && (cur != ']')) {
             /* Generate the error and skip the offending character */
             xmlFatalErrMsgInt(ctxt, XML_ERR_INVALID_CHAR,
                               "PCDATA invalid Char value %d\n", cur);
@@ -5116,9 +5175,9 @@ xmlParseCommentComplex(xmlParserCtxtPtr ctxt, xmlChar *buf,
     int q, ql;
     int r, rl;
     int cur, l;
-    size_t maxLength = (ctxt->options & XML_PARSE_HUGE) ?
-                       XML_MAX_HUGE_LENGTH :
-                       XML_MAX_TEXT_LENGTH;
+    int maxLength = (ctxt->options & XML_PARSE_HUGE) ?
+                    XML_MAX_HUGE_LENGTH :
+                    XML_MAX_TEXT_LENGTH;
 
     if (buf == NULL) {
         len = 0;
@@ -5161,26 +5220,26 @@ xmlParseCommentComplex(xmlParserCtxtPtr ctxt, xmlChar *buf,
 	    xmlFatalErr(ctxt, XML_ERR_HYPHEN_IN_COMMENT, NULL);
 	}
 	if (len + 5 >= size) {
-	    xmlChar *new_buf;
-            size_t new_size;
+	    xmlChar *tmp;
+            int newSize;
 
-	    new_size = size * 2;
-	    new_buf = (xmlChar *) xmlRealloc(buf, new_size);
-	    if (new_buf == NULL) {
-		xmlFree (buf);
+	    newSize = xmlGrowCapacity(size, 1, 1, maxLength);
+            if (newSize < 0) {
+                xmlFatalErrMsgStr(ctxt, XML_ERR_COMMENT_NOT_FINISHED,
+                             "Comment too big found", NULL);
+                xmlFree (buf);
+                return;
+            }
+	    tmp = xmlRealloc(buf, newSize);
+	    if (tmp == NULL) {
 		xmlErrMemory(ctxt);
+		xmlFree(buf);
 		return;
 	    }
-	    buf = new_buf;
-            size = new_size;
+	    buf = tmp;
+            size = newSize;
 	}
 	COPY_BUF(buf, len, q);
-        if (len > maxLength) {
-            xmlFatalErrMsgStr(ctxt, XML_ERR_COMMENT_NOT_FINISHED,
-                         "Comment too big found", NULL);
-            xmlFree (buf);
-            return;
-        }
 
 	q = r;
 	ql = rl;
@@ -5282,6 +5341,12 @@ get_more:
 	 * save current set of data
 	 */
 	if (nbchar > 0) {
+            if (nbchar > maxLength - len) {
+                xmlFatalErrMsgStr(ctxt, XML_ERR_COMMENT_NOT_FINISHED,
+                                  "Comment too big found", NULL);
+                xmlFree(buf);
+                return;
+            }
             if (buf == NULL) {
                 if ((*in == '-') && (in[1] == '-'))
                     size = nbchar + 1;
@@ -5295,11 +5360,11 @@ get_more:
                 len = 0;
             } else if (len + nbchar + 1 >= size) {
                 xmlChar *new_buf;
-                size  += len + nbchar + XML_PARSER_BUFFER_SIZE;
-                new_buf = (xmlChar *) xmlRealloc(buf, size);
+                size += len + nbchar + XML_PARSER_BUFFER_SIZE;
+                new_buf = xmlRealloc(buf, size);
                 if (new_buf == NULL) {
-                    xmlFree (buf);
                     xmlErrMemory(ctxt);
+                    xmlFree(buf);
                     return;
                 }
                 buf = new_buf;
@@ -5308,12 +5373,6 @@ get_more:
             len += nbchar;
             buf[len] = 0;
 	}
-        if (len > maxLength) {
-            xmlFatalErrMsgStr(ctxt, XML_ERR_COMMENT_NOT_FINISHED,
-                         "Comment too big found", NULL);
-            xmlFree (buf);
-            return;
-        }
 	ctxt->input->cur = in;
 	if (*in == 0xA) {
 	    in++;
@@ -5545,23 +5604,25 @@ xmlParsePI(xmlParserCtxtPtr ctxt) {
 		   ((cur != '?') || (NXT(1) != '>'))) {
 		if (len + 5 >= size) {
 		    xmlChar *tmp;
-                    size_t new_size = size * 2;
-		    tmp = (xmlChar *) xmlRealloc(buf, new_size);
+                    int newSize;
+
+                    newSize = xmlGrowCapacity(size, 1, 1, maxLength);
+                    if (newSize < 0) {
+                        xmlFatalErrMsgStr(ctxt, XML_ERR_PI_NOT_FINISHED,
+                                          "PI %s too big found", target);
+                        xmlFree(buf);
+                        return;
+                    }
+		    tmp = xmlRealloc(buf, newSize);
 		    if (tmp == NULL) {
 			xmlErrMemory(ctxt);
 			xmlFree(buf);
 			return;
 		    }
 		    buf = tmp;
-                    size = new_size;
+                    size = newSize;
 		}
 		COPY_BUF(buf, len, cur);
-                if (len > maxLength) {
-                    xmlFatalErrMsgStr(ctxt, XML_ERR_PI_NOT_FINISHED,
-                                      "PI %s too big found", target);
-                    xmlFree(buf);
-                    return;
-                }
 		NEXTL(l);
 		cur = xmlCurrentCharRecover(ctxt, &l);
 	    }
@@ -5577,7 +5638,7 @@ xmlParsePI(xmlParserCtxtPtr ctxt) {
 		    (xmlStrEqual(target, XML_CATALOG_PI))) {
 		    xmlCatalogAllow allow = xmlCatalogGetDefaults();
 
-		    if (((ctxt->options & XML_PARSE_NO_CATALOG_PI) == 0) &&
+		    if ((ctxt->options & XML_PARSE_CATALOG_PI) &&
                         ((allow == XML_CATA_ALLOW_DOCUMENT) ||
 			 (allow == XML_CATA_ALLOW_ALL)))
 			xmlParseCatalogPI(ctxt, buf);
@@ -7019,15 +7080,23 @@ xmlParseConditionalSections(xmlParserCtxtPtr ctxt) {
 
                 if (inputIdsSize <= depth) {
                     int *tmp;
-
-                    inputIdsSize = (inputIdsSize == 0 ? 4 : inputIdsSize * 2);
-                    tmp = (int *) xmlRealloc(inputIds,
-                            inputIdsSize * sizeof(int));
+                    int newSize;
+
+                    newSize = xmlGrowCapacity(inputIdsSize, sizeof(tmp[0]),
+                                              4, 1000);
+                    if (newSize < 0) {
+                        xmlFatalErrMsg(ctxt, XML_ERR_RESOURCE_LIMIT,
+                                       "Maximum conditional section nesting"
+                                       " depth exceeded\n");
+                        goto error;
+                    }
+                    tmp = xmlRealloc(inputIds, newSize * sizeof(tmp[0]));
                     if (tmp == NULL) {
                         xmlErrMemory(ctxt);
                         goto error;
                     }
                     inputIds = tmp;
+                    inputIdsSize = newSize;
                 }
                 inputIds[depth] = id;
                 depth++;
@@ -7247,6 +7316,8 @@ xmlParseTextDecl(xmlParserCtxtPtr ctxt) {
  * @ExternalID: the external identifier
  * @SystemID: the system identifier (or URL)
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * parse Markup declarations from an external subset
  *
  * [30] extSubset ::= textDecl? extSubsetDecl
@@ -7488,7 +7559,7 @@ xmlParseReference(xmlParserCtxtPtr ctxt) {
             int len = xmlStrlen(cur->content);
 
             if ((cur->type == XML_TEXT_NODE) ||
-                (ctxt->sax->cdataBlock == NULL)) {
+                (ctxt->options & XML_PARSE_NOCDATA)) {
                 if (ctxt->sax->characters != NULL)
                     ctxt->sax->characters(ctxt, cur->content, len);
             } else {
@@ -7511,7 +7582,7 @@ xmlParseReference(xmlParserCtxtPtr ctxt) {
                 int len = xmlStrlen(cur->content);
 
                 if ((cur->type == XML_TEXT_NODE) ||
-                    (ctxt->sax->cdataBlock == NULL)) {
+                    (ctxt->options & XML_PARSE_NOCDATA)) {
                     if (ctxt->sax->characters != NULL)
                         ctxt->sax->characters(ctxt, cur->content, len);
                 } else {
@@ -7887,13 +7958,15 @@ xmlParsePEReference(xmlParserCtxtPtr ctxt)
             }
 
 	    input = xmlNewEntityInputStream(ctxt, entity);
-	    if (xmlPushInput(ctxt, input) < 0) {
+	    if (xmlCtxtPushInput(ctxt, input) < 0) {
                 xmlFreeInputStream(input);
 		return;
             }
 
             entity->flags |= XML_ENT_EXPANDING;
 
+            GROW;
+
 	    if (entity->etype == XML_EXTERNAL_PARAMETER_ENTITY) {
                 xmlDetectEncoding(ctxt);
 
@@ -7965,7 +8038,7 @@ xmlLoadEntityContent(xmlParserCtxtPtr ctxt, xmlEntityPtr entity) {
 
     xmlBufResetInput(input->buf->buffer, input);
 
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         goto error;
     }
@@ -8034,7 +8107,7 @@ xmlLoadEntityContent(xmlParserCtxtPtr ctxt, xmlEntityPtr entity) {
 
 error:
     while (ctxt->inputNr > 0)
-        xmlFreeInputStream(inputPop(ctxt));
+        xmlFreeInputStream(xmlCtxtPopInput(ctxt));
     xmlFree(ctxt->inputTab);
     xmlFree((xmlChar *) ctxt->encoding);
 
@@ -8165,7 +8238,10 @@ xmlParseDocTypeDecl(xmlParserCtxtPtr ctxt) {
      */
     SKIP(9);
 
-    SKIP_BLANKS;
+    if (SKIP_BLANKS == 0) {
+        xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
+                       "Space required after 'DOCTYPE'\n");
+    }
 
     /*
      * Parse the DOCTYPE name.
@@ -8199,20 +8275,9 @@ xmlParseDocTypeDecl(xmlParserCtxtPtr ctxt) {
 	(!ctxt->disableSAX))
 	ctxt->sax->internalSubset(ctxt->userData, name, ExternalID, URI);
 
-    /*
-     * Is there any internal subset declarations ?
-     * they are handled separately in xmlParseInternalSubset()
-     */
-    if (RAW == '[')
-	return;
-
-    /*
-     * We should be at the end of the DOCTYPE declaration.
-     */
-    if (RAW != '>') {
+    if ((RAW != '[') && (RAW != '>')) {
 	xmlFatalErr(ctxt, XML_ERR_DOCTYPE_NOT_FINISHED, NULL);
     }
-    NEXT;
 }
 
 /**
@@ -8449,52 +8514,50 @@ xmlParseStartTag(xmlParserCtxtPtr ctxt) {
 	    for (i = 0; i < nbatts;i += 2) {
 	        if (xmlStrEqual(atts[i], attname)) {
 		    xmlErrAttributeDup(ctxt, NULL, attname);
-		    xmlFree(attvalue);
 		    goto failed;
 		}
 	    }
 	    /*
 	     * Add the pair to atts
 	     */
-	    if (atts == NULL) {
-	        maxatts = 22; /* allow for 10 attrs by default */
-	        atts = (const xmlChar **)
-		       xmlMalloc(maxatts * sizeof(xmlChar *));
-		if (atts == NULL) {
+	    if (nbatts + 4 > maxatts) {
+	        const xmlChar **n;
+                int newSize;
+
+                newSize = xmlGrowCapacity(maxatts, sizeof(n[0]) * 2,
+                                          11, XML_MAX_ATTRS);
+                if (newSize < 0) {
 		    xmlErrMemory(ctxt);
-		    if (attvalue != NULL)
-			xmlFree(attvalue);
 		    goto failed;
 		}
-		ctxt->atts = atts;
-		ctxt->maxatts = maxatts;
-	    } else if (nbatts + 4 > maxatts) {
-	        const xmlChar **n;
-
-	        maxatts *= 2;
-	        n = (const xmlChar **) xmlRealloc((void *) atts,
-					     maxatts * sizeof(const xmlChar *));
+#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
+                if (newSize < 2)
+                    newSize = 2;
+#endif
+	        n = xmlRealloc(atts, newSize * sizeof(n[0]) * 2);
 		if (n == NULL) {
 		    xmlErrMemory(ctxt);
-		    if (attvalue != NULL)
-			xmlFree(attvalue);
 		    goto failed;
 		}
 		atts = n;
+                maxatts = newSize * 2;
 		ctxt->atts = atts;
 		ctxt->maxatts = maxatts;
 	    }
+
 	    atts[nbatts++] = attname;
 	    atts[nbatts++] = attvalue;
 	    atts[nbatts] = NULL;
 	    atts[nbatts + 1] = NULL;
-	} else {
-	    if (attvalue != NULL)
-		xmlFree(attvalue);
+
+            attvalue = NULL;
 	}
 
 failed:
 
+        if (attvalue != NULL)
+            xmlFree(attvalue);
+
 	GROW
 	if ((RAW == '>') || (((RAW == '/') && (NXT(1) == '>'))))
 	    break;
@@ -8791,10 +8854,7 @@ xmlParseAttribute2(xmlParserCtxtPtr ctxt,
         return(hname);
     }
     name = hname.name;
-    if (hprefix->name != NULL)
-        prefix = hprefix->name;
-    else
-        prefix = NULL;
+    prefix = hprefix->name;
 
     /*
      * get the type if needed
@@ -8802,9 +8862,8 @@ xmlParseAttribute2(xmlParserCtxtPtr ctxt,
     if (ctxt->attsSpecial != NULL) {
         int type;
 
-        type = (int) (ptrdiff_t) xmlHashQLookup2(ctxt->attsSpecial,
-                                                 pref, elem,
-                                                 prefix, name);
+        type = XML_PTR_TO_INT(xmlHashQLookup2(ctxt->attsSpecial, pref, elem,
+                                              prefix, name));
         if (type != 0)
             normalize = 1;
     }
@@ -8907,7 +8966,7 @@ xmlAttrHashInsert(xmlParserCtxtPtr ctxt, unsigned size, const xmlChar *name,
         const xmlChar **atts = &ctxt->atts[bucket->index];
 
         if (name == atts[0]) {
-            int nsIndex = (int) (ptrdiff_t) atts[2];
+            int nsIndex = XML_PTR_TO_INT(atts[2]);
 
             if ((nsIndex == NS_INDEX_EMPTY) ? (uri == NULL) :
                 (nsIndex == NS_INDEX_XML) ? (uri == ctxt->str_xml_ns) :
@@ -8928,6 +8987,35 @@ xmlAttrHashInsert(xmlParserCtxtPtr ctxt, unsigned size, const xmlChar *name,
     return(INT_MAX);
 }
 
+static int
+xmlAttrHashInsertQName(xmlParserCtxtPtr ctxt, unsigned size,
+                       const xmlChar *name, const xmlChar *prefix,
+                       unsigned hashValue, int aindex) {
+    xmlAttrHashBucket *table = ctxt->attrHash;
+    xmlAttrHashBucket *bucket;
+    unsigned hindex;
+
+    hindex = hashValue & (size - 1);
+    bucket = &table[hindex];
+
+    while (bucket->index >= 0) {
+        const xmlChar **atts = &ctxt->atts[bucket->index];
+
+        if ((name == atts[0]) && (prefix == atts[1]))
+            return(bucket->index);
+
+        hindex++;
+        bucket++;
+        if (hindex >= size) {
+            hindex = 0;
+            bucket = table;
+        }
+    }
+
+    bucket->index = aindex;
+
+    return(INT_MAX);
+}
 /**
  * xmlParseStartTag2:
  * @ctxt:  an XML parser context
@@ -8976,6 +9064,8 @@ xmlParseStartTag2(xmlParserCtxtPtr ctxt, const xmlChar **pref,
     int nratts, nbatts, nbdef;
     int i, j, nbNs, nbTotalDef, attval, nsIndex, maxAtts;
     int alloc = 0;
+    int numNsErr = 0;
+    int numDupErr = 0;
 
     if (RAW != '<') return(NULL);
     NEXT1;
@@ -9172,11 +9262,13 @@ xmlParseStartTag2(xmlParserCtxtPtr ctxt, const xmlChar **pref,
              * of xmlChar pointers.
              */
             if ((atts == NULL) || (nbatts + 5 > maxatts)) {
-                if (xmlCtxtGrowAttrs(ctxt, nbatts + 5) < 0) {
-                    goto next_attr;
-                }
+                int res = xmlCtxtGrowAttrs(ctxt);
+
                 maxatts = ctxt->maxatts;
                 atts = ctxt->atts;
+
+                if (res < 0)
+                    goto next_attr;
             }
             ctxt->attallocs[nratts++] = (hattname.hashValue & 0x7FFFFFFF) |
                                         ((unsigned) alloc << 31);
@@ -9247,6 +9339,11 @@ next_attr:
                                       NULL, 1) > 0)
                         nbNs++;
 		} else {
+                    if (nratts + nbTotalDef >= XML_MAX_ATTRS) {
+                        xmlFatalErr(ctxt, XML_ERR_RESOURCE_LIMIT,
+                                    "Maximum number of attributes exceeded");
+                        break;
+                    }
                     nbTotalDef += 1;
                 }
 	    }
@@ -9280,7 +9377,7 @@ next_attr:
             }
         }
 
-        atts[i+2] = (const xmlChar *) (ptrdiff_t) nsIndex;
+        atts[i+2] = XML_INT_TO_PTR(nsIndex);
     }
 
     /*
@@ -9318,7 +9415,7 @@ next_attr:
 
             attname = atts[i];
             aprefix = atts[i+1];
-            nsIndex = (ptrdiff_t) atts[i+2];
+            nsIndex = XML_PTR_TO_INT(atts[i+2]);
             /* Hash values always have bit 31 set, see dict.c */
             nameHashValue = ctxt->attallocs[j] | 0x80000000;
 
@@ -9354,10 +9451,12 @@ next_attr:
             if (res < INT_MAX) {
                 if (aprefix == atts[res+1]) {
                     xmlErrAttributeDup(ctxt, aprefix, attname);
+                    numDupErr += 1;
                 } else {
                     xmlNsErr(ctxt, XML_NS_ERR_ATTRIBUTE_REDEFINED,
                              "Namespaced Attribute %s in '%s' redefined\n",
                              attname, nsuri, NULL);
+                    numNsErr += 1;
                 }
             }
         }
@@ -9432,17 +9531,20 @@ next_attr:
                 xmlParserEntityCheck(ctxt, attr->expandedSize);
 
                 if ((atts == NULL) || (nbatts + 5 > maxatts)) {
-                    if (xmlCtxtGrowAttrs(ctxt, nbatts + 5) < 0) {
+                    res = xmlCtxtGrowAttrs(ctxt);
+
+                    maxatts = ctxt->maxatts;
+                    atts = ctxt->atts;
+
+                    if (res < 0) {
                         localname = NULL;
                         goto done;
                     }
-                    maxatts = ctxt->maxatts;
-                    atts = ctxt->atts;
                 }
 
                 atts[nbatts++] = attname;
                 atts[nbatts++] = aprefix;
-                atts[nbatts++] = (const xmlChar *) (ptrdiff_t) nsIndex;
+                atts[nbatts++] = XML_INT_TO_PTR(nsIndex);
                 atts[nbatts++] = attr->value.name;
                 atts[nbatts++] = attr->valueEnd;
                 if ((ctxt->standalone == 1) && (attr->external != 0)) {
@@ -9456,12 +9558,49 @@ next_attr:
 	}
     }
 
+    /*
+     * Using a single hash table for nsUri/localName pairs cannot
+     * detect duplicate QNames reliably. The following example will
+     * only result in two namespace errors.
+     *
+     * <doc xmlns:a="a" xmlns:b="a">
+     *   <elem a:a="" b:a="" b:a=""/>
+     * </doc>
+     *
+     * If we saw more than one namespace error but no duplicate QNames
+     * were found, we have to scan for duplicate QNames.
+     */
+    if ((numDupErr == 0) && (numNsErr > 1)) {
+        memset(ctxt->attrHash, -1,
+               attrHashSize * sizeof(ctxt->attrHash[0]));
+
+        for (i = 0, j = 0; j < nratts; i += 5, j++) {
+            unsigned hashValue, nameHashValue, prefixHashValue;
+            int res;
+
+            aprefix = atts[i+1];
+            if (aprefix == NULL)
+                continue;
+
+            attname = atts[i];
+            /* Hash values always have bit 31 set, see dict.c */
+            nameHashValue = ctxt->attallocs[j] | 0x80000000;
+            prefixHashValue = xmlDictComputeHash(ctxt->dict, aprefix);
+
+            hashValue = xmlDictCombineHash(nameHashValue, prefixHashValue);
+            res = xmlAttrHashInsertQName(ctxt, attrHashSize, attname,
+                                         aprefix, hashValue, i);
+            if (res < INT_MAX)
+                xmlErrAttributeDup(ctxt, aprefix, attname);
+        }
+    }
+
     /*
      * Reconstruct attribute pointers
      */
     for (i = 0, j = 0; i < nbatts; i += 5, j++) {
         /* namespace URI */
-        nsIndex = (ptrdiff_t) atts[i+2];
+        nsIndex = XML_PTR_TO_INT(atts[i+2]);
         if (nsIndex == INT_MAX)
             atts[i+2] = NULL;
         else if (nsIndex == INT_MAX - 1)
@@ -9470,8 +9609,8 @@ next_attr:
             atts[i+2] = ctxt->nsTab[nsIndex * 2 + 1];
 
         if ((j < nratts) && (ctxt->attallocs[j] & 0x80000000) == 0) {
-            atts[i+3] = BASE_PTR + (ptrdiff_t) atts[i+3];  /* value */
-            atts[i+4] = BASE_PTR + (ptrdiff_t) atts[i+4];  /* valuend */
+            atts[i+3] = BASE_PTR + XML_PTR_TO_INT(atts[i+3]);  /* value */
+            atts[i+4] = BASE_PTR + XML_PTR_TO_INT(atts[i+4]);  /* valuend */
         }
     }
 
@@ -9637,21 +9776,23 @@ xmlParseCDSect(xmlParserCtxtPtr ctxt) {
            ((r != ']') || (s != ']') || (cur != '>'))) {
 	if (len + 5 >= size) {
 	    xmlChar *tmp;
+            int newSize;
 
-	    tmp = (xmlChar *) xmlRealloc(buf, size * 2);
+            newSize = xmlGrowCapacity(size, 1, 1, maxLength);
+            if (newSize < 0) {
+                xmlFatalErrMsg(ctxt, XML_ERR_CDATA_NOT_FINISHED,
+                               "CData section too big found\n");
+                goto out;
+            }
+	    tmp = xmlRealloc(buf, newSize);
 	    if (tmp == NULL) {
 		xmlErrMemory(ctxt);
                 goto out;
 	    }
 	    buf = tmp;
-	    size *= 2;
+	    size = newSize;
 	}
 	COPY_BUF(buf, len, r);
-        if (len > maxLength) {
-            xmlFatalErrMsg(ctxt, XML_ERR_CDATA_NOT_FINISHED,
-                           "CData section too big found\n");
-            goto out;
-        }
 	r = s;
 	rl = sl;
 	s = cur;
@@ -9671,10 +9812,13 @@ xmlParseCDSect(xmlParserCtxtPtr ctxt) {
      * OK the buffer is to be consumed as cdata.
      */
     if ((ctxt->sax != NULL) && (!ctxt->disableSAX)) {
-	if (ctxt->sax->cdataBlock != NULL)
-	    ctxt->sax->cdataBlock(ctxt->userData, buf, len);
-	else if (ctxt->sax->characters != NULL)
-	    ctxt->sax->characters(ctxt->userData, buf, len);
+        if (ctxt->options & XML_PARSE_NOCDATA) {
+            if (ctxt->sax->characters != NULL)
+                ctxt->sax->characters(ctxt->userData, buf, len);
+        } else {
+            if (ctxt->sax->cdataBlock != NULL)
+                ctxt->sax->cdataBlock(ctxt->userData, buf, len);
+        }
     }
 
 out:
@@ -10031,6 +10175,9 @@ xmlParseVersionNum(xmlParserCtxtPtr ctxt) {
     xmlChar *buf = NULL;
     int len = 0;
     int size = 10;
+    int maxLength = (ctxt->options & XML_PARSE_HUGE) ?
+                    XML_MAX_TEXT_LENGTH :
+                    XML_MAX_NAME_LENGTH;
     xmlChar cur;
 
     buf = xmlMalloc(size);
@@ -10056,15 +10203,22 @@ xmlParseVersionNum(xmlParserCtxtPtr ctxt) {
     while ((cur >= '0') && (cur <= '9')) {
 	if (len + 1 >= size) {
 	    xmlChar *tmp;
+            int newSize;
 
-	    size *= 2;
-	    tmp = (xmlChar *) xmlRealloc(buf, size);
+            newSize = xmlGrowCapacity(size, 1, 1, maxLength);
+            if (newSize) {
+                xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "VersionNum");
+                xmlFree(buf);
+                return(NULL);
+            }
+	    tmp = xmlRealloc(buf, newSize);
 	    if (tmp == NULL) {
-	        xmlFree(buf);
 		xmlErrMemory(ctxt);
+	        xmlFree(buf);
 		return(NULL);
 	    }
 	    buf = tmp;
+            size = newSize;
 	}
 	buf[len++] = cur;
 	NEXT;
@@ -10164,22 +10318,24 @@ xmlParseEncName(xmlParserCtxtPtr ctxt) {
 	       (cur == '-')) {
 	    if (len + 1 >= size) {
 	        xmlChar *tmp;
+                int newSize;
 
-		size *= 2;
-		tmp = (xmlChar *) xmlRealloc(buf, size);
+                newSize = xmlGrowCapacity(size, 1, 1, maxLength);
+                if (newSize < 0) {
+                    xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "EncName");
+                    xmlFree(buf);
+                    return(NULL);
+                }
+		tmp = xmlRealloc(buf, newSize);
 		if (tmp == NULL) {
 		    xmlErrMemory(ctxt);
 		    xmlFree(buf);
 		    return(NULL);
 		}
 		buf = tmp;
+                size = newSize;
 	    }
 	    buf[len++] = cur;
-            if (len > maxLength) {
-                xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "EncName");
-                xmlFree(buf);
-                return(NULL);
-            }
 	    NEXT;
 	    cur = CUR;
         }
@@ -10456,7 +10612,7 @@ xmlParseXMLDecl(xmlParserCtxtPtr ctxt) {
 
 /**
  * xmlCtxtGetVersion:
- * ctxt:  parser context
+ * @ctxt:  parser context
  *
  * Available since 2.14.0.
  *
@@ -10472,7 +10628,7 @@ xmlCtxtGetVersion(xmlParserCtxtPtr ctxt) {
 
 /**
  * xmlCtxtGetStandalone:
- * ctxt:  parser context
+ * @ctxt:  parser context
  *
  * Available since 2.14.0.
  *
@@ -10618,7 +10774,9 @@ xmlParseDocument(xmlParserCtxtPtr ctxt) {
 	xmlParseDocTypeDecl(ctxt);
 	if (RAW == '[') {
 	    xmlParseInternalSubset(ctxt);
-	}
+	} else if (RAW == '>') {
+            NEXT;
+        }
 
 	/*
 	 * Create and update the external subset.
@@ -10678,6 +10836,8 @@ xmlParseDocument(xmlParserCtxtPtr ctxt) {
  * xmlParseExtParsedEnt:
  * @ctxt:  an XML parser context
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * parse a general parsed entity
  * An external general parsed entity is well-formed if it matches the
  * production labeled extParsedEnt.
@@ -11342,6 +11502,8 @@ xmlParseTryOrFinish(xmlParserCtxtPtr ctxt, int terminate) {
                                 if (RAW == '[') {
                                     ctxt->instate = XML_PARSER_DTD;
                                 } else {
+                                    if (RAW == '>')
+                                        NEXT;
                                     /*
                                      * Create and update the external subset.
                                      */
@@ -11413,10 +11575,13 @@ done:
  * The last chunk, which will often be empty, must be marked with
  * the @terminate flag. With the default SAX callbacks, the resulting
  * document will be available in ctxt->myDoc. This pointer will not
- * be freed by the library.
+ * be freed when calling xmlFreeParserCtxt and must be freed by the
+ * caller. If the document isn't well-formed, it will still be returned
+ * in ctxt->myDoc.
  *
- * If the document isn't well-formed, ctxt->myDoc is set to NULL.
- * The push parser doesn't support recovery mode.
+ * As an exception, xmlCtxtResetPush will free the document in
+ * ctxt->myDoc. So ctxt->myDoc should be set to NULL after extracting
+ * the document.
  *
  * Returns an xmlParserErrors code (0 on success).
  */
@@ -11539,6 +11704,9 @@ xmlParseChunk(xmlParserCtxtPtr ctxt, const char *chunk, int size,
  *
  * Passing an initial chunk is useless and deprecated.
  *
+ * The push parser doesn't support recovery mode or the
+ * XML_PARSE_NOBLANKS option.
+ *
  * @filename is used as base URI to fetch external entities and for
  * error reports.
  *
@@ -11564,7 +11732,7 @@ xmlCreatePushParserCtxt(xmlSAXHandlerPtr sax, void *user_data,
 	xmlFreeParserCtxt(ctxt);
 	return(NULL);
     }
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         xmlFreeParserCtxt(ctxt);
         return(NULL);
@@ -11623,7 +11791,7 @@ xmlCreateIOParserCtxt(xmlSAXHandlerPtr sax, void *user_data,
 	xmlFreeParserCtxt(ctxt);
         return (NULL);
     }
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         xmlFreeParserCtxt(ctxt);
         return(NULL);
@@ -11639,12 +11807,93 @@ xmlCreateIOParserCtxt(xmlSAXHandlerPtr sax, void *user_data,
  *									*
  ************************************************************************/
 
+/**
+ * xmlCtxtParseDtd:
+ * @ctxt:  a parser context
+ * @input:  a parser input
+ * @publicId:  public ID of the DTD (optional)
+ * @systemId:  system ID of the DTD (optional)
+ *
+ * Parse a DTD.
+ *
+ * Option XML_PARSE_DTDLOAD should be enabled in the parser context
+ * to make external entities work.
+ *
+ * Availabe since 2.14.0.
+ *
+ * Returns the resulting xmlDtdPtr or NULL in case of error.
+ * @input will be freed by the function in any case.
+ */
+xmlDtdPtr
+xmlCtxtParseDtd(xmlParserCtxtPtr ctxt, xmlParserInputPtr input,
+                const xmlChar *publicId, const xmlChar *systemId) {
+    xmlDtdPtr ret = NULL;
+
+    if ((ctxt == NULL) || (input == NULL)) {
+        xmlFatalErr(ctxt, XML_ERR_ARGUMENT, NULL);
+        xmlFreeInputStream(input);
+        return(NULL);
+    }
+
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
+        xmlFreeInputStream(input);
+        return(NULL);
+    }
+
+    if (publicId == NULL)
+        publicId = BAD_CAST "none";
+    if (systemId == NULL)
+        systemId = BAD_CAST "none";
+
+    ctxt->myDoc = xmlNewDoc(BAD_CAST "1.0");
+    if (ctxt->myDoc == NULL) {
+        xmlErrMemory(ctxt);
+        goto error;
+    }
+    ctxt->myDoc->properties = XML_DOC_INTERNAL;
+    ctxt->myDoc->extSubset = xmlNewDtd(ctxt->myDoc, BAD_CAST "none",
+                                       publicId, systemId);
+    if (ctxt->myDoc->extSubset == NULL) {
+        xmlErrMemory(ctxt);
+        xmlFreeDoc(ctxt->myDoc);
+        goto error;
+    }
+
+    xmlParseExternalSubset(ctxt, publicId, systemId);
+
+    if (ctxt->wellFormed) {
+        ret = ctxt->myDoc->extSubset;
+        ctxt->myDoc->extSubset = NULL;
+        if (ret != NULL) {
+            xmlNodePtr tmp;
+
+            ret->doc = NULL;
+            tmp = ret->children;
+            while (tmp != NULL) {
+                tmp->doc = NULL;
+                tmp = tmp->next;
+            }
+        }
+    } else {
+        ret = NULL;
+    }
+    xmlFreeDoc(ctxt->myDoc);
+    ctxt->myDoc = NULL;
+
+error:
+    xmlFreeInputStream(xmlCtxtPopInput(ctxt));
+
+    return(ret);
+}
+
 /**
  * xmlIOParseDTD:
  * @sax:  the SAX handler block or NULL
  * @input:  an Input Buffer
  * @enc:  the charset encoding if known
  *
+ * DEPRECATED: Use xmlCtxtParseDtd.
+ *
  * Load and parse a DTD
  *
  * Returns the resulting xmlDtdPtr or NULL in case of error.
@@ -11666,6 +11915,7 @@ xmlIOParseDTD(xmlSAXHandlerPtr sax, xmlParserInputBufferPtr input,
         xmlFreeParserInputBuffer(input);
 	return(NULL);
     }
+    xmlCtxtSetOptions(ctxt, XML_PARSE_DTDLOAD);
 
     /*
      * generate a parser input from the I/O handler
@@ -11678,54 +11928,13 @@ xmlIOParseDTD(xmlSAXHandlerPtr sax, xmlParserInputBufferPtr input,
 	return(NULL);
     }
 
-    /*
-     * plug some encoding conversion routines here.
-     */
-    if (xmlPushInput(ctxt, pinput) < 0) {
-        xmlFreeInputStream(pinput);
-	xmlFreeParserCtxt(ctxt);
-	return(NULL);
-    }
     if (enc != XML_CHAR_ENCODING_NONE) {
         xmlSwitchEncoding(ctxt, enc);
     }
 
-    /*
-     * let's parse that entity knowing it's an external subset.
-     */
-    ctxt->myDoc = xmlNewDoc(BAD_CAST "1.0");
-    if (ctxt->myDoc == NULL) {
-	xmlErrMemory(ctxt);
-	return(NULL);
-    }
-    ctxt->myDoc->properties = XML_DOC_INTERNAL;
-    ctxt->myDoc->extSubset = xmlNewDtd(ctxt->myDoc, BAD_CAST "none",
-	                               BAD_CAST "none", BAD_CAST "none");
-
-    xmlParseExternalSubset(ctxt, BAD_CAST "none", BAD_CAST "none");
+    ret = xmlCtxtParseDtd(ctxt, pinput, NULL, NULL);
 
-    if (ctxt->myDoc != NULL) {
-	if (ctxt->wellFormed) {
-	    ret = ctxt->myDoc->extSubset;
-	    ctxt->myDoc->extSubset = NULL;
-	    if (ret != NULL) {
-		xmlNodePtr tmp;
-
-		ret->doc = NULL;
-		tmp = ret->children;
-		while (tmp != NULL) {
-		    tmp->doc = NULL;
-		    tmp = tmp->next;
-		}
-	    }
-	} else {
-	    ret = NULL;
-	}
-        xmlFreeDoc(ctxt->myDoc);
-        ctxt->myDoc = NULL;
-    }
     xmlFreeParserCtxt(ctxt);
-
     return(ret);
 }
 
@@ -11735,7 +11944,7 @@ xmlIOParseDTD(xmlSAXHandlerPtr sax, xmlParserInputBufferPtr input,
  * @ExternalID:  a NAME* containing the External ID of the DTD
  * @SystemID:  a NAME* containing the URL to the DTD
  *
- * DEPRECATED: Don't use.
+ * DEPRECATED: Use xmlCtxtParseDtd.
  *
  * Load and parse an external subset.
  *
@@ -11756,6 +11965,7 @@ xmlSAXParseDTD(xmlSAXHandlerPtr sax, const xmlChar *ExternalID,
     if (ctxt == NULL) {
 	return(NULL);
     }
+    xmlCtxtSetOptions(ctxt, XML_PARSE_DTDLOAD);
 
     /*
      * Canonicalise the system ID
@@ -11780,65 +11990,14 @@ xmlSAXParseDTD(xmlSAXHandlerPtr sax, const xmlChar *ExternalID,
 	return(NULL);
     }
 
-    /*
-     * plug some encoding conversion routines here.
-     */
-    if (xmlPushInput(ctxt, input) < 0) {
-        xmlFreeInputStream(input);
-	xmlFreeParserCtxt(ctxt);
-	if (systemIdCanonic != NULL)
-	    xmlFree(systemIdCanonic);
-	return(NULL);
-    }
-
-    xmlDetectEncoding(ctxt);
-
     if (input->filename == NULL)
 	input->filename = (char *) systemIdCanonic;
     else
 	xmlFree(systemIdCanonic);
 
-    /*
-     * let's parse that entity knowing it's an external subset.
-     */
-    ctxt->myDoc = xmlNewDoc(BAD_CAST "1.0");
-    if (ctxt->myDoc == NULL) {
-	xmlErrMemory(ctxt);
-	xmlFreeParserCtxt(ctxt);
-	return(NULL);
-    }
-    ctxt->myDoc->properties = XML_DOC_INTERNAL;
-    ctxt->myDoc->extSubset = xmlNewDtd(ctxt->myDoc, BAD_CAST "none",
-	                               ExternalID, SystemID);
-    if (ctxt->myDoc->extSubset == NULL) {
-        xmlFreeDoc(ctxt->myDoc);
-        xmlFreeParserCtxt(ctxt);
-        return(NULL);
-    }
-    xmlParseExternalSubset(ctxt, ExternalID, SystemID);
+    ret = xmlCtxtParseDtd(ctxt, input, ExternalID, SystemID);
 
-    if (ctxt->myDoc != NULL) {
-	if (ctxt->wellFormed) {
-	    ret = ctxt->myDoc->extSubset;
-	    ctxt->myDoc->extSubset = NULL;
-	    if (ret != NULL) {
-		xmlNodePtr tmp;
-
-		ret->doc = NULL;
-		tmp = ret->children;
-		while (tmp != NULL) {
-		    tmp->doc = NULL;
-		    tmp = tmp->next;
-		}
-	    }
-	} else {
-	    ret = NULL;
-	}
-        xmlFreeDoc(ctxt->myDoc);
-        ctxt->myDoc = NULL;
-    }
     xmlFreeParserCtxt(ctxt);
-
     return(ret);
 }
 
@@ -11881,7 +12040,7 @@ xmlCtxtParseContentInternal(xmlParserCtxtPtr ctxt, xmlParserInputPtr input,
         }
     }
 
-    if (xmlPushInput(ctxt, input) < 0)
+    if (xmlCtxtPushInput(ctxt, input) < 0)
         goto error;
 
     nameNsPush(ctxt, rootName, NULL, NULL, 0, 0);
@@ -11917,7 +12076,7 @@ xmlCtxtParseContentInternal(xmlParserCtxtPtr ctxt, xmlParserInputPtr input,
 	xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, NULL);
 
     if ((ctxt->wellFormed) ||
-        ((ctxt->recovery) && (ctxt->errNo != XML_ERR_NO_MEMORY))) {
+        ((ctxt->recovery) && (!xmlCtxtIsCatastrophicError(ctxt)))) {
         if (root != NULL) {
             xmlNodePtr cur;
 
@@ -11948,8 +12107,7 @@ xmlCtxtParseContentInternal(xmlParserCtxtPtr ctxt, xmlParserInputPtr input,
     namePop(ctxt);
     spacePop(ctxt);
 
-    /* xmlPopInput would free the stream */
-    inputPop(ctxt);
+    xmlCtxtPopInput(ctxt);
 
 error:
     xmlFreeNode(root);
@@ -12011,7 +12169,7 @@ xmlCtxtParseEntity(xmlParserCtxtPtr ctxt, xmlEntityPtr ent) {
      * - xmlCtxtParseEntity
      *
      * The nesting depth is limited by the maximum number of inputs,
-     * see xmlPushInput.
+     * see xmlCtxtPushInput.
      *
      * It's possible to make this non-recursive (minNsIndex must be
      * stored in the input struct) at the expense of code readability.
@@ -12044,6 +12202,15 @@ xmlCtxtParseEntity(xmlParserCtxtPtr ctxt, xmlEntityPtr ent) {
 
         while (list != NULL) {
             list->parent = (xmlNodePtr) ent;
+
+            /*
+             * Downstream code like the nginx xslt module can set
+             * ctxt->myDoc->extSubset to a separate DTD, so the entity
+             * might have a different or a NULL document.
+             */
+            if (list->doc != ent->doc)
+                xmlSetTreeDoc(list, ent->doc);
+
             if (list->next == NULL)
                 ent->last = list;
             list = list->next;
@@ -12593,7 +12760,7 @@ xmlCreateEntityParserCtxt(const xmlChar *URL, const xmlChar *ID,
     if (input == NULL)
         goto error;
 
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         goto error;
     }
@@ -12636,6 +12803,8 @@ xmlCreateURLParserCtxt(const char *filename, int options)
     if (ctxt == NULL)
 	return(NULL);
 
+    options |= XML_PARSE_UNZIP;
+
     xmlCtxtUseOptions(ctxt, options);
     ctxt->linenumbers = 1;
 
@@ -12644,7 +12813,7 @@ xmlCreateURLParserCtxt(const char *filename, int options)
 	xmlFreeParserCtxt(ctxt);
 	return(NULL);
     }
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         xmlFreeParserCtxt(ctxt);
         return(NULL);
@@ -12696,7 +12865,7 @@ xmlCreateFileParserCtxt(const char *filename)
 xmlDocPtr
 xmlSAXParseFileWithData(xmlSAXHandlerPtr sax, const char *filename,
                         int recovery, void *data) {
-    xmlDocPtr ret;
+    xmlDocPtr ret = NULL;
     xmlParserCtxtPtr ctxt;
     xmlParserInputPtr input;
 
@@ -12717,7 +12886,8 @@ xmlSAXParseFileWithData(xmlSAXHandlerPtr sax, const char *filename,
     else
         input = xmlCtxtNewInputFromUrl(ctxt, filename, NULL, NULL, 0);
 
-    ret = xmlCtxtParseDocument(ctxt, input);
+    if (input != NULL)
+        ret = xmlCtxtParseDocument(ctxt, input);
 
     xmlFreeParserCtxt(ctxt);
     return(ret);
@@ -12829,7 +12999,7 @@ xmlSetupParserForBuffer(xmlParserCtxtPtr ctxt, const xmlChar* buffer,
                                       NULL, 0);
     if (input == NULL)
         return;
-    if (inputPush(ctxt, input) < 0)
+    if (xmlCtxtPushInput(ctxt, input) < 0)
         xmlFreeInputStream(input);
 }
 
@@ -12917,7 +13087,7 @@ xmlCreateMemoryParserCtxt(const char *buffer, int size) {
 	xmlFreeParserCtxt(ctxt);
 	return(NULL);
     }
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         xmlFreeParserCtxt(ctxt);
         return(NULL);
@@ -12951,7 +13121,7 @@ xmlCreateMemoryParserCtxt(const char *buffer, int size) {
 xmlDocPtr
 xmlSAXParseMemoryWithData(xmlSAXHandlerPtr sax, const char *buffer,
                           int size, int recovery, void *data) {
-    xmlDocPtr ret;
+    xmlDocPtr ret = NULL;
     xmlParserCtxtPtr ctxt;
     xmlParserInputPtr input;
 
@@ -12973,7 +13143,8 @@ xmlSAXParseMemoryWithData(xmlSAXHandlerPtr sax, const char *buffer,
     input = xmlCtxtNewInputFromMemory(ctxt, NULL, buffer, size, NULL,
                                       XML_INPUT_BUF_STATIC);
 
-    ret = xmlCtxtParseDocument(ctxt, input);
+    if (input != NULL)
+        ret = xmlCtxtParseDocument(ctxt, input);
 
     xmlFreeParserCtxt(ctxt);
     return(ret);
@@ -13107,7 +13278,7 @@ xmlCreateDocParserCtxt(const xmlChar *str) {
 	xmlFreeParserCtxt(ctxt);
 	return(NULL);
     }
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         xmlFreeParserCtxt(ctxt);
         return(NULL);
@@ -13216,7 +13387,7 @@ xmlCtxtReset(xmlParserCtxtPtr ctxt)
 
     dict = ctxt->dict;
 
-    while ((input = inputPop(ctxt)) != NULL) { /* Non consuming */
+    while ((input = xmlCtxtPopInput(ctxt)) != NULL) { /* Non consuming */
         xmlFreeInputStream(input);
     }
     ctxt->inputNr = 0;
@@ -13325,7 +13496,7 @@ xmlCtxtResetPush(xmlParserCtxtPtr ctxt, const char *chunk,
     if (input == NULL)
         return(1);
 
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         return(1);
     }
@@ -13374,9 +13545,9 @@ xmlCtxtSetOptionsInternal(xmlParserCtxtPtr ctxt, int options, int keepMask)
               XML_PARSE_IGNORE_ENC |
               XML_PARSE_BIG_LINES |
               XML_PARSE_NO_XXE |
-              XML_PARSE_NO_UNZIP |
+              XML_PARSE_UNZIP |
               XML_PARSE_NO_SYS_CATALOG |
-              XML_PARSE_NO_CATALOG_PI;
+              XML_PARSE_CATALOG_PI;
 
     ctxt->options = (ctxt->options & keepMask) | (options & allMask);
 
@@ -13403,15 +13574,6 @@ xmlCtxtSetOptionsInternal(xmlParserCtxtPtr ctxt, int options, int keepMask)
     ctxt->keepBlanks = (options & XML_PARSE_NOBLANKS) ? 0 : 1;
     ctxt->dictNames = (options & XML_PARSE_NODICT) ? 0 : 1;
 
-    /*
-     * Changing SAX callbacks is a bad idea. This should be fixed.
-     */
-    if (options & XML_PARSE_NOBLANKS) {
-        ctxt->sax->ignorableWhitespace = xmlSAX2IgnorableWhitespace;
-    }
-    if (options & XML_PARSE_NOCDATA) {
-        ctxt->sax->cdataBlock = NULL;
-    }
     if (options & XML_PARSE_HUGE) {
         if (ctxt->dict != NULL)
             xmlDictSetLimit(ctxt->dict, 0);
@@ -13439,6 +13601,8 @@ xmlCtxtSetOptionsInternal(xmlParserCtxtPtr ctxt, int options, int keepMask)
  * How this mode behaves exactly is unspecified and may change
  * without further notice. Use of this feature is DISCOURAGED.
  *
+ * Not supported by the push parser.
+ *
  * XML_PARSE_NOENT
  *
  * Despite the confusing name, this option enables substitution
@@ -13491,13 +13655,13 @@ xmlCtxtSetOptionsInternal(xmlParserCtxtPtr ctxt, int options, int keepMask)
  *
  * XML_PARSE_NOBLANKS
  *
- * Remove some text nodes containing only whitespace from the
- * result document. Which nodes are removed depends on DTD
- * element declarations or a conservative heuristic. The
- * reindenting feature of the serialization code relies on this
- * option to be set when parsing. Use of this option is
+ * Remove some whitespace from the result document. Where to
+ * remove whitespace depends on DTD element declarations or a
+ * broken heuristic with unfixable bugs. Use of this option is
  * DISCOURAGED.
  *
+ * Not supported by the push parser.
+ *
  * XML_PARSE_SAX1
  *
  * Always invoke the deprecated SAX1 startElement and endElement
@@ -13571,9 +13735,9 @@ xmlCtxtSetOptionsInternal(xmlParserCtxtPtr ctxt, int options, int keepMask)
  *
  * Enable reporting of line numbers larger than 65535.
  *
- * XML_PARSE_NO_UNZIP
+ * XML_PARSE_UNZIP
  *
- * Disables input decompression. Setting this option is recommended
+ * Enable input decompression. Setting this option is discouraged
  * to avoid zip bombs.
  *
  * Available since 2.14.0.
@@ -13584,9 +13748,9 @@ xmlCtxtSetOptionsInternal(xmlParserCtxtPtr ctxt, int options, int keepMask)
  *
  * Available since 2.14.0.
  *
- * XML_PARSE_NO_CATALOG_PI
+ * XML_PARSE_CATALOG_PI
  *
- * Ignore XML catalog processing instructions.
+ * Enable XML catalog processing instructions.
  *
  * Available since 2.14.0.
  *
@@ -13712,14 +13876,17 @@ xmlCtxtParseDocument(xmlParserCtxtPtr ctxt, xmlParserInputPtr input)
 {
     xmlDocPtr ret = NULL;
 
-    if ((ctxt == NULL) || (input == NULL))
+    if ((ctxt == NULL) || (input == NULL)) {
+        xmlFatalErr(ctxt, XML_ERR_ARGUMENT, NULL);
+        xmlFreeInputStream(input);
         return(NULL);
+    }
 
     /* assert(ctxt->inputNr == 0); */
     while (ctxt->inputNr > 0)
-        xmlFreeInputStream(inputPop(ctxt));
+        xmlFreeInputStream(xmlCtxtPopInput(ctxt));
 
-    if (inputPush(ctxt, input) < 0) {
+    if (xmlCtxtPushInput(ctxt, input) < 0) {
         xmlFreeInputStream(input);
         return(NULL);
     }
@@ -13727,7 +13894,7 @@ xmlCtxtParseDocument(xmlParserCtxtPtr ctxt, xmlParserInputPtr input)
     xmlParseDocument(ctxt);
 
     if ((ctxt->wellFormed) ||
-        ((ctxt->recovery) && (ctxt->errNo != XML_ERR_NO_MEMORY))) {
+        ((ctxt->recovery) && (!xmlCtxtIsCatastrophicError(ctxt)))) {
         ret = ctxt->myDoc;
     } else {
         if (ctxt->errNo == XML_ERR_OK)
@@ -13740,7 +13907,7 @@ xmlCtxtParseDocument(xmlParserCtxtPtr ctxt, xmlParserInputPtr input)
 
     /* assert(ctxt->inputNr == 1); */
     while (ctxt->inputNr > 0)
-        xmlFreeInputStream(inputPop(ctxt));
+        xmlFreeInputStream(xmlCtxtPopInput(ctxt));
 
     return(ret);
 }
@@ -13765,7 +13932,7 @@ xmlReadDoc(const xmlChar *cur, const char *URL, const char *encoding,
 {
     xmlParserCtxtPtr ctxt;
     xmlParserInputPtr input;
-    xmlDocPtr doc;
+    xmlDocPtr doc = NULL;
 
     ctxt = xmlNewParserCtxt();
     if (ctxt == NULL)
@@ -13776,7 +13943,8 @@ xmlReadDoc(const xmlChar *cur, const char *URL, const char *encoding,
     input = xmlCtxtNewInputFromString(ctxt, URL, (const char *) cur, encoding,
                                       XML_INPUT_BUF_STATIC);
 
-    doc = xmlCtxtParseDocument(ctxt, input);
+    if (input != NULL)
+        doc = xmlCtxtParseDocument(ctxt, input);
 
     xmlFreeParserCtxt(ctxt);
     return(doc);
@@ -13791,6 +13959,11 @@ xmlReadDoc(const xmlChar *cur, const char *URL, const char *encoding,
  * Convenience function to parse an XML file from the filesystem,
  * the network or a global user-define resource loader.
  *
+ * This function always enables the XML_PARSE_UNZIP option for
+ * backward compatibility. If a "-" filename is passed, it will
+ * read from stdin. Both of these features are potentially
+ * insecure and might be removed from later versions.
+ *
  * See xmlCtxtReadFile for details.
  *
  * Returns the resulting document tree
@@ -13800,12 +13973,14 @@ xmlReadFile(const char *filename, const char *encoding, int options)
 {
     xmlParserCtxtPtr ctxt;
     xmlParserInputPtr input;
-    xmlDocPtr doc;
+    xmlDocPtr doc = NULL;
 
     ctxt = xmlNewParserCtxt();
     if (ctxt == NULL)
         return(NULL);
 
+    options |= XML_PARSE_UNZIP;
+
     xmlCtxtUseOptions(ctxt, options);
 
     /*
@@ -13819,7 +13994,8 @@ xmlReadFile(const char *filename, const char *encoding, int options)
     else
         input = xmlCtxtNewInputFromUrl(ctxt, filename, NULL, encoding, 0);
 
-    doc = xmlCtxtParseDocument(ctxt, input);
+    if (input != NULL)
+        doc = xmlCtxtParseDocument(ctxt, input);
 
     xmlFreeParserCtxt(ctxt);
     return(doc);
@@ -13846,7 +14022,7 @@ xmlReadMemory(const char *buffer, int size, const char *url,
 {
     xmlParserCtxtPtr ctxt;
     xmlParserInputPtr input;
-    xmlDocPtr doc;
+    xmlDocPtr doc = NULL;
 
     if (size < 0)
 	return(NULL);
@@ -13860,7 +14036,8 @@ xmlReadMemory(const char *buffer, int size, const char *url,
     input = xmlCtxtNewInputFromMemory(ctxt, url, buffer, size, encoding,
                                       XML_INPUT_BUF_STATIC);
 
-    doc = xmlCtxtParseDocument(ctxt, input);
+    if (input != NULL)
+        doc = xmlCtxtParseDocument(ctxt, input);
 
     xmlFreeParserCtxt(ctxt);
     return(doc);
@@ -13887,7 +14064,7 @@ xmlReadFd(int fd, const char *URL, const char *encoding, int options)
 {
     xmlParserCtxtPtr ctxt;
     xmlParserInputPtr input;
-    xmlDocPtr doc;
+    xmlDocPtr doc = NULL;
 
     ctxt = xmlNewParserCtxt();
     if (ctxt == NULL)
@@ -13897,7 +14074,8 @@ xmlReadFd(int fd, const char *URL, const char *encoding, int options)
 
     input = xmlCtxtNewInputFromFd(ctxt, URL, fd, encoding, 0);
 
-    doc = xmlCtxtParseDocument(ctxt, input);
+    if (input != NULL)
+        doc = xmlCtxtParseDocument(ctxt, input);
 
     xmlFreeParserCtxt(ctxt);
     return(doc);
@@ -13924,7 +14102,7 @@ xmlReadIO(xmlInputReadCallback ioread, xmlInputCloseCallback ioclose,
 {
     xmlParserCtxtPtr ctxt;
     xmlParserInputPtr input;
-    xmlDocPtr doc;
+    xmlDocPtr doc = NULL;
 
     ctxt = xmlNewParserCtxt();
     if (ctxt == NULL)
@@ -13935,7 +14113,8 @@ xmlReadIO(xmlInputReadCallback ioread, xmlInputCloseCallback ioclose,
     input = xmlCtxtNewInputFromIO(ctxt, URL, ioread, ioclose, ioctx,
                                   encoding, 0);
 
-    doc = xmlCtxtParseDocument(ctxt, input);
+    if (input != NULL)
+        doc = xmlCtxtParseDocument(ctxt, input);
 
     xmlFreeParserCtxt(ctxt);
     return(doc);
@@ -13972,6 +14151,8 @@ xmlCtxtReadDoc(xmlParserCtxtPtr ctxt, const xmlChar *str,
 
     input = xmlCtxtNewInputFromString(ctxt, URL, (const char *) str, encoding,
                                       XML_INPUT_BUF_STATIC);
+    if (input == NULL)
+        return(NULL);
 
     return(xmlCtxtParseDocument(ctxt, input));
 }
@@ -13986,6 +14167,10 @@ xmlCtxtReadDoc(xmlParserCtxtPtr ctxt, const xmlChar *str,
  * Parse an XML file from the filesystem, the network or a user-defined
  * resource loader.
  *
+ * This function always enables the XML_PARSE_UNZIP option for
+ * backward compatibility. This feature is potentially insecure
+ * and might be removed from later versions.
+ *
  * Returns the resulting document tree
  */
 xmlDocPtr
@@ -13997,10 +14182,14 @@ xmlCtxtReadFile(xmlParserCtxtPtr ctxt, const char *filename,
     if (ctxt == NULL)
         return(NULL);
 
+    options |= XML_PARSE_UNZIP;
+
     xmlCtxtReset(ctxt);
     xmlCtxtUseOptions(ctxt, options);
 
     input = xmlCtxtNewInputFromUrl(ctxt, filename, NULL, encoding, 0);
+    if (input == NULL)
+        return(NULL);
 
     return(xmlCtxtParseDocument(ctxt, input));
 }
@@ -14038,6 +14227,8 @@ xmlCtxtReadMemory(xmlParserCtxtPtr ctxt, const char *buffer, int size,
 
     input = xmlCtxtNewInputFromMemory(ctxt, URL, buffer, size, encoding,
                                       XML_INPUT_BUF_STATIC);
+    if (input == NULL)
+        return(NULL);
 
     return(xmlCtxtParseDocument(ctxt, input));
 }
@@ -14075,6 +14266,8 @@ xmlCtxtReadFd(xmlParserCtxtPtr ctxt, int fd,
     xmlCtxtUseOptions(ctxt, options);
 
     input = xmlCtxtNewInputFromFd(ctxt, URL, fd, encoding, 0);
+    if (input == NULL)
+        return(NULL);
 
     return(xmlCtxtParseDocument(ctxt, input));
 }
@@ -14115,6 +14308,8 @@ xmlCtxtReadIO(xmlParserCtxtPtr ctxt, xmlInputReadCallback ioread,
 
     input = xmlCtxtNewInputFromIO(ctxt, URL, ioread, ioclose, ioctx,
                                   encoding, 0);
+    if (input == NULL)
+        return(NULL);
 
     return(xmlCtxtParseDocument(ctxt, input));
 }
diff --git a/parserInternals.c b/parserInternals.c
index a6ddf502..effd566c 100644
--- a/parserInternals.c
+++ b/parserInternals.c
@@ -44,8 +44,13 @@
 #include "private/enc.h"
 #include "private/error.h"
 #include "private/io.h"
+#include "private/memory.h"
 #include "private/parser.h"
 
+#ifndef SIZE_MAX
+  #define SIZE_MAX ((size_t) -1)
+#endif
+
 #define XML_MAX_ERRORS 100
 
 /*
@@ -176,8 +181,10 @@ xmlCtxtErrMemory(xmlParserCtxtPtr ctxt)
     xmlGenericErrorFunc channel = NULL;
     void *data;
 
-    if (ctxt == NULL)
+    if (ctxt == NULL) {
+        xmlRaiseMemoryError(NULL, NULL, NULL, XML_FROM_PARSER, NULL);
         return;
+    }
 
     ctxt->errNo = XML_ERR_NO_MEMORY;
     ctxt->instate = XML_PARSER_EOF; /* TODO: Remove after refactoring */
@@ -254,34 +261,19 @@ xmlCtxtErrIO(xmlParserCtxtPtr ctxt, int code, const char *uri)
                msg, str1, str2);
 }
 
-static int
+/**
+ * xmlCtxtIsCatastrophicError:
+ * @ctxt:  parser context
+ *
+ * Returns true if the last error is catastrophic.
+ */
+int
 xmlCtxtIsCatastrophicError(xmlParserCtxtPtr ctxt) {
-    int fatal = 0;
-    int code;
-
     if (ctxt == NULL)
         return(1);
 
-    if (ctxt->lastError.level != XML_ERR_FATAL)
-        return(0);
-
-    code = ctxt->lastError.code;
-
-    switch (code) {
-        case XML_ERR_NO_MEMORY:
-        case XML_ERR_RESOURCE_LIMIT:
-        case XML_ERR_SYSTEM:
-        case XML_ERR_ARGUMENT:
-        case XML_ERR_INTERNAL_ERROR:
-            fatal = 1;
-            break;
-        default:
-            if ((code >= 1500) && (code <= 1599))
-                fatal = 1;
-            break;
-    }
-
-    return(fatal);
+    return(xmlIsCatastrophicError(ctxt->lastError.level,
+                                  ctxt->lastError.code));
 }
 
 /**
@@ -319,21 +311,34 @@ xmlCtxtVErr(xmlParserCtxtPtr ctxt, xmlNodePtr node, xmlErrorDomain domain,
         return;
     }
 
-    if (ctxt == NULL)
+    if (ctxt == NULL) {
+        res = xmlVRaiseError(NULL, NULL, NULL, NULL, node, domain, code,
+                             level, NULL, 0, (const char *) str1,
+                             (const char *) str2, (const char *) str3,
+                             int1, 0, msg, ap);
+        if (res < 0)
+            xmlRaiseMemoryError(NULL, NULL, NULL, XML_FROM_PARSER, NULL);
+
         return;
+    }
 
     if (PARSER_STOPPED(ctxt))
 	return;
 
+    /* Don't overwrite catastrophic errors */
+    if (xmlCtxtIsCatastrophicError(ctxt))
+        return;
+
     if (level == XML_ERR_WARNING) {
         if (ctxt->nbWarnings >= XML_MAX_ERRORS)
-            goto done;
+            return;
         ctxt->nbWarnings += 1;
     } else {
         /* Report at least one fatal error. */
         if ((ctxt->nbErrors >= XML_MAX_ERRORS) &&
-            ((level < XML_ERR_FATAL) || (ctxt->wellFormed == 0)))
-            goto done;
+            ((level < XML_ERR_FATAL) || (ctxt->wellFormed == 0)) &&
+            (!xmlIsCatastrophicError(level, code)))
+            return;
         ctxt->nbErrors += 1;
     }
 
@@ -384,7 +389,6 @@ xmlCtxtVErr(xmlParserCtxtPtr ctxt, xmlNodePtr node, xmlErrorDomain domain,
         return;
     }
 
-done:
     if (level >= XML_ERR_ERROR)
         ctxt->errNo = code;
     if (level == XML_ERR_FATAL) {
@@ -990,6 +994,8 @@ xmlStringCurrentChar(xmlParserCtxtPtr ctxt ATTRIBUTE_UNUSED,
  * @out:  pointer to an array of xmlChar
  * @val:  the char value
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * append the char value in the array
  *
  * Returns the number of xmlChar written
@@ -1338,7 +1344,16 @@ xmlInputSetEncodingHandler(xmlParserInputPtr input,
         input->consumed += processed;
         in->rawconsumed = processed;
 
-        nbchars = 4000 /* MINLEN */;
+        /*
+         * If we're push-parsing, we must convert the whole buffer.
+         *
+         * If we're pull-parsing, we could be parsing from a huge
+         * memory buffer which we don't want to convert completely.
+         */
+        if (input->flags & XML_INPUT_PROGRESSIVE)
+            nbchars = SIZE_MAX;
+        else
+            nbchars = 4000 /* MINLEN */;
         res = xmlCharEncInput(in, &nbchars);
         if (res < 0)
             code = in->error;
@@ -1439,12 +1454,23 @@ xmlDetectEncoding(xmlParserCtxtPtr ctxt) {
     enc = XML_CHAR_ENCODING_NONE;
     bomSize = 0;
 
+    /*
+     * BOM sniffing and detection of initial bytes of an XML
+     * declaration.
+     *
+     * The HTML5 spec doesn't cover UTF-32 (UCS-4) or EBCDIC.
+     */
     switch (in[0]) {
         case 0x00:
-            if ((in[1] == 0x00) && (in[2] == 0x00) && (in[3] == 0x3C)) {
+            if ((!ctxt->html) &&
+                (in[1] == 0x00) && (in[2] == 0x00) && (in[3] == 0x3C)) {
                 enc = XML_CHAR_ENCODING_UCS4BE;
                 autoFlag = XML_INPUT_AUTO_OTHER;
             } else if ((in[1] == 0x3C) && (in[2] == 0x00) && (in[3] == 0x3F)) {
+                /*
+                 * TODO: The HTML5 spec requires to check that the
+                 * next codepoint is an 'x'.
+                 */
                 enc = XML_CHAR_ENCODING_UTF16BE;
                 autoFlag = XML_INPUT_AUTO_UTF16BE;
             }
@@ -1452,10 +1478,15 @@ xmlDetectEncoding(xmlParserCtxtPtr ctxt) {
 
         case 0x3C:
             if (in[1] == 0x00) {
-                if ((in[2] == 0x00) && (in[3] == 0x00)) {
+                if ((!ctxt->html) &&
+                    (in[2] == 0x00) && (in[3] == 0x00)) {
                     enc = XML_CHAR_ENCODING_UCS4LE;
                     autoFlag = XML_INPUT_AUTO_OTHER;
                 } else if ((in[2] == 0x3F) && (in[3] == 0x00)) {
+                    /*
+                     * TODO: The HTML5 spec requires to check that the
+                     * next codepoint is an 'x'.
+                     */
                     enc = XML_CHAR_ENCODING_UTF16LE;
                     autoFlag = XML_INPUT_AUTO_UTF16LE;
                 }
@@ -1463,7 +1494,8 @@ xmlDetectEncoding(xmlParserCtxtPtr ctxt) {
             break;
 
         case 0x4C:
-	    if ((in[1] == 0x6F) && (in[2] == 0xA7) && (in[3] == 0x94)) {
+	    if ((!ctxt->html) &&
+                (in[1] == 0x6F) && (in[2] == 0xA7) && (in[3] == 0x94)) {
 	        enc = XML_CHAR_ENCODING_EBCDIC;
                 autoFlag = XML_INPUT_AUTO_OTHER;
             }
@@ -1616,7 +1648,7 @@ xmlSetDeclaredEncoding(xmlParserCtxtPtr ctxt, xmlChar *encoding) {
 
 /**
  * xmlCtxtGetDeclaredEncoding:
- * ctxt:  parser context
+ * @ctxt:  parser context
  *
  * Available since 2.14.0.
  *
@@ -1912,7 +1944,7 @@ xmlCtxtNewInputFromString(xmlParserCtxtPtr ctxt, const char *url,
  * xmlNewInputFromFd:
  * @url:  base URL (optional)
  * @fd:  file descriptor
- * @flags:  unused, pass 0
+ * @flags:  input flags
  *
  * Creates a new parser input to read from a zero-terminated string.
  *
@@ -1921,21 +1953,30 @@ xmlCtxtNewInputFromString(xmlParserCtxtPtr ctxt, const char *url,
  *
  * @fd is closed after parsing has finished.
  *
+ * Supported @flags are XML_INPUT_UNZIP to decompress data
+ * automatically. This feature is deprecated and will be removed
+ * in a future release.
+ *
  * Available since 2.14.0.
  *
  * Returns a new parser input or NULL if a memory allocation failed.
  */
 xmlParserInputPtr
-xmlNewInputFromFd(const char *url, int fd, int flags ATTRIBUTE_UNUSED) {
+xmlNewInputFromFd(const char *url, int fd, int flags) {
     xmlParserInputBufferPtr buf;
 
     if (fd < 0)
 	return(NULL);
 
-    buf = xmlParserInputBufferCreateFd(fd, XML_CHAR_ENCODING_NONE);
+    buf = xmlAllocParserInputBuffer(XML_CHAR_ENCODING_NONE);
     if (buf == NULL)
         return(NULL);
 
+    if (xmlInputFromFd(buf, fd, flags) < 0) {
+        xmlFreeParserInputBuffer(buf);
+        return(NULL);
+    }
+
     return(xmlNewInputInternal(buf, url));
 }
 
@@ -1957,6 +1998,9 @@ xmlCtxtNewInputFromFd(xmlParserCtxtPtr ctxt, const char *url,
     if ((ctxt == NULL) || (fd < 0))
 	return(NULL);
 
+    if (ctxt->options & XML_PARSE_UNZIP)
+        flags |= XML_INPUT_UNZIP;
+
     input = xmlNewInputFromFd(url, fd, flags);
     if (input == NULL) {
 	xmlCtxtErrMemory(ctxt);
@@ -2446,7 +2490,7 @@ xmlNewInputFromFile(xmlParserCtxtPtr ctxt, const char *filename) {
     if ((ctxt == NULL) || (filename == NULL))
         return(NULL);
 
-    if ((ctxt->options & XML_PARSE_NO_UNZIP) == 0)
+    if (ctxt->options & XML_PARSE_UNZIP)
         flags |= XML_INPUT_UNZIP;
     if ((ctxt->options & XML_PARSE_NONET) == 0)
         flags |= XML_INPUT_NETWORK;
@@ -2618,7 +2662,7 @@ xmlLoadResource(xmlParserCtxtPtr ctxt, const char *url, const char *publicId,
             url = resource;
 #endif
 
-        if ((ctxt->options & XML_PARSE_NO_UNZIP) == 0)
+        if (ctxt->options & XML_PARSE_UNZIP)
             flags |= XML_INPUT_UNZIP;
         if ((ctxt->options & XML_PARSE_NONET) == 0)
             flags |= XML_INPUT_NETWORK;
@@ -2753,7 +2797,7 @@ xmlInitSAXParserCtxt(xmlParserCtxtPtr ctxt, const xmlSAXHandler *sax,
     }
     if (ctxt->inputTab == NULL)
 	return(-1);
-    while ((input = inputPop(ctxt)) != NULL) { /* Non consuming */
+    while ((input = xmlCtxtPopInput(ctxt)) != NULL) { /* Non consuming */
         xmlFreeInputStream(input);
     }
     ctxt->inputNr = 0;
@@ -2894,7 +2938,7 @@ xmlFreeParserCtxt(xmlParserCtxtPtr ctxt)
 
     if (ctxt == NULL) return;
 
-    while ((input = inputPop(ctxt)) != NULL) { /* Non consuming */
+    while ((input = xmlCtxtPopInput(ctxt)) != NULL) { /* Non consuming */
         xmlFreeInputStream(input);
     }
     if (ctxt->spaceTab != NULL) xmlFree(ctxt->spaceTab);
@@ -3016,7 +3060,7 @@ xmlNewSAXParserCtxt(const xmlSAXHandler *sax, void *userData)
 
 /**
  * xmlCtxtGetPrivate:
- * ctxt:  parser context
+ * @ctxt:  parser context
  *
  * Available since 2.14.0.
  *
@@ -3032,8 +3076,8 @@ xmlCtxtGetPrivate(xmlParserCtxtPtr ctxt) {
 
 /**
  * xmlCtxtSetPrivate:
- * ctxt:  parser context
- * priv:  private application data
+ * @ctxt:  parser context
+ * @priv:  private application data
  *
  * Available since 2.14.0.
  *
@@ -3049,7 +3093,7 @@ xmlCtxtSetPrivate(xmlParserCtxtPtr ctxt, void *priv) {
 
 /**
  * xmlCtxtGetCatalogs:
- * ctxt:  parser context
+ * @ctxt:  parser context
  *
  * Available since 2.14.0.
  *
@@ -3065,8 +3109,8 @@ xmlCtxtGetCatalogs(xmlParserCtxtPtr ctxt) {
 
 /**
  * xmlCtxtSetCatalogs:
- * ctxt:  parser context
- * catalogs:  catalogs pointer
+ * @ctxt:  parser context
+ * @catalogs:  catalogs pointer
  *
  * Available since 2.14.0.
  *
@@ -3082,7 +3126,7 @@ xmlCtxtSetCatalogs(xmlParserCtxtPtr ctxt, void *catalogs) {
 
 /**
  * xmlCtxtGetDict:
- * ctxt:  parser context
+ * @ctxt:  parser context
  *
  * Available since 2.14.0.
  *
@@ -3098,8 +3142,8 @@ xmlCtxtGetDict(xmlParserCtxtPtr ctxt) {
 
 /**
  * xmlCtxtSetDict:
- * ctxt:  parser context
- * dict:  dictionary
+ * @ctxt:  parser context
+ * @dict:  dictionary
  *
  * Available since 2.14.0.
  *
@@ -3279,29 +3323,23 @@ xmlParserAddNodeInfo(xmlParserCtxtPtr ctxt,
 
     /* Otherwise, we need to add new node to buffer */
     else {
-        if ((ctxt->node_seq.length + 1 > ctxt->node_seq.maximum) ||
-	    (ctxt->node_seq.buffer == NULL)) {
-            xmlParserNodeInfo *tmp_buffer;
-            unsigned int byte_size;
-
-            if (ctxt->node_seq.maximum == 0)
-                ctxt->node_seq.maximum = 2;
-            byte_size = (sizeof(*ctxt->node_seq.buffer) *
-			(2 * ctxt->node_seq.maximum));
-
-            if (ctxt->node_seq.buffer == NULL)
-                tmp_buffer = (xmlParserNodeInfo *) xmlMalloc(byte_size);
-            else
-                tmp_buffer =
-                    (xmlParserNodeInfo *) xmlRealloc(ctxt->node_seq.buffer,
-                                                     byte_size);
+        if (ctxt->node_seq.length + 1 > ctxt->node_seq.maximum) {
+            xmlParserNodeInfo *tmp;
+            int newSize;
 
-            if (tmp_buffer == NULL) {
+            newSize = xmlGrowCapacity(ctxt->node_seq.maximum, sizeof(tmp[0]),
+                                      4, XML_MAX_ITEMS);
+            if (newSize < 0) {
+		xmlCtxtErrMemory(ctxt);
+                return;
+            }
+            tmp = xmlRealloc(ctxt->node_seq.buffer, newSize * sizeof(tmp[0]));
+            if (tmp == NULL) {
 		xmlCtxtErrMemory(ctxt);
                 return;
             }
-            ctxt->node_seq.buffer = tmp_buffer;
-            ctxt->node_seq.maximum *= 2;
+            ctxt->node_seq.buffer = tmp;
+            ctxt->node_seq.maximum = newSize;
         }
 
         /* If position is not at end, move elements out of the way */
diff --git a/pattern.c b/pattern.c
index ea4d5a45..0877fc1a 100644
--- a/pattern.c
+++ b/pattern.c
@@ -34,6 +34,9 @@
 #include <libxml/xmlerror.h>
 #include <libxml/parserInternals.h>
 
+#include "private/memory.h"
+#include "private/parser.h"
+
 #ifdef LIBXML_PATTERN_ENABLED
 
 #ifdef ERROR
@@ -207,14 +210,8 @@ xmlNewPattern(void) {
 	return(NULL);
     }
     memset(cur, 0, sizeof(xmlPattern));
-    cur->maxStep = 10;
-    cur->steps = (xmlStepOpPtr) xmlMalloc(cur->maxStep * sizeof(xmlStepOp));
-    if (cur->steps == NULL) {
-        xmlFree(cur);
-	ERROR(NULL, NULL, NULL,
-		"xmlNewPattern : malloc failed\n");
-	return(NULL);
-    }
+    cur->steps = NULL;
+    cur->maxStep = 0;
     return(cur);
 }
 
@@ -332,6 +329,24 @@ xmlFreePatParserContext(xmlPatParserContextPtr ctxt) {
     xmlFree(ctxt);
 }
 
+static int
+xmlPatternGrow(xmlPatternPtr comp) {
+    xmlStepOpPtr temp;
+    int newSize;
+
+    newSize = xmlGrowCapacity(comp->maxStep, sizeof(temp[0]),
+                              10, XML_MAX_ITEMS);
+    if (newSize < 0)
+        return(-1);
+    temp = xmlRealloc(comp->steps, newSize * sizeof(temp[0]));
+    if (temp == NULL)
+        return(-1);
+    comp->steps = temp;
+    comp->maxStep = newSize;
+
+    return(0);
+}
+
 /**
  * xmlPatternAdd:
  * @comp:  the compiled match expression
@@ -348,23 +363,16 @@ xmlPatternAdd(xmlPatParserContextPtr ctxt, xmlPatternPtr comp,
               xmlPatOp op, xmlChar * value, xmlChar * value2)
 {
     if (comp->nbStep >= comp->maxStep) {
-        xmlStepOpPtr temp;
-	temp = (xmlStepOpPtr) xmlRealloc(comp->steps, comp->maxStep * 2 *
-	                                 sizeof(xmlStepOp));
-        if (temp == NULL) {
-	    ERROR(ctxt, NULL, NULL,
-			     "xmlPatternAdd: realloc failed\n");
+        if (xmlPatternGrow(comp) < 0) {
             ctxt->error = -1;
-	    return (-1);
-	}
-	comp->steps = temp;
-	comp->maxStep *= 2;
+            return(-1);
+        }
     }
     comp->steps[comp->nbStep].op = op;
     comp->steps[comp->nbStep].value = value;
     comp->steps[comp->nbStep].value2 = value2;
     comp->nbStep++;
-    return (0);
+    return(0);
 }
 
 /**
@@ -390,18 +398,15 @@ xmlReversePattern(xmlPatternPtr comp) {
 	}
 	comp->nbStep--;
     }
+
+    /*
+     * Grow to add OP_END later
+     */
     if (comp->nbStep >= comp->maxStep) {
-        xmlStepOpPtr temp;
-	temp = (xmlStepOpPtr) xmlRealloc(comp->steps, comp->maxStep * 2 *
-	                                 sizeof(xmlStepOp));
-        if (temp == NULL) {
-	    ERROR(ctxt, NULL, NULL,
-			     "xmlReversePattern: realloc failed\n");
-	    return (-1);
-	}
-	comp->steps = temp;
-	comp->maxStep *= 2;
+        if (xmlPatternGrow(comp) < 0)
+            return(-1);
     }
+
     i = 0;
     j = comp->nbStep - 1;
     while (j > i) {
@@ -419,6 +424,7 @@ xmlReversePattern(xmlPatternPtr comp) {
 	j--;
 	i++;
     }
+
     comp->steps[comp->nbStep].value = NULL;
     comp->steps[comp->nbStep].value2 = NULL;
     comp->steps[comp->nbStep++].op = XML_OP_END;
@@ -434,14 +440,18 @@ xmlReversePattern(xmlPatternPtr comp) {
 static int
 xmlPatPushState(xmlStepStates *states, int step, xmlNodePtr node) {
     if (states->maxstates <= states->nbstates) {
-        size_t newSize = states->maxstates ? states->maxstates * 2 : 4;
         xmlStepState *tmp;
+        int newSize;
 
+        newSize = xmlGrowCapacity(states->maxstates, sizeof(tmp[0]),
+                                  4, XML_MAX_ITEMS);
+        if (newSize < 0)
+	    return(-1);
 	tmp = xmlRealloc(states->states, newSize * sizeof(tmp[0]));
 	if (tmp == NULL)
 	    return(-1);
 	states->states = tmp;
-	states->maxstates *= 2;
+	states->maxstates = newSize;
     }
     states->states[states->nbstates].step = step;
     states->states[states->nbstates++].node = node;
@@ -1343,15 +1353,24 @@ xmlStreamCompAddStep(xmlStreamCompPtr comp, const xmlChar *name,
     xmlStreamStepPtr cur;
 
     if (comp->nbStep >= comp->maxStep) {
-	cur = (xmlStreamStepPtr) xmlRealloc(comp->steps,
-				 comp->maxStep * 2 * sizeof(xmlStreamStep));
+        xmlStreamStepPtr tmp;
+        int newSize;
+
+        newSize = xmlGrowCapacity(comp->maxStep, sizeof(tmp[0]),
+                                  4, XML_MAX_ITEMS);
+        if (newSize < 0) {
+	    ERROR(NULL, NULL, NULL,
+		  "xmlNewStreamComp: growCapacity failed\n");
+	    return(-1);
+        }
+	cur = xmlRealloc(comp->steps, newSize * sizeof(tmp[0]));
 	if (cur == NULL) {
 	    ERROR(NULL, NULL, NULL,
 		  "xmlNewStreamComp: malloc failed\n");
 	    return(-1);
 	}
 	comp->steps = cur;
-        comp->maxStep *= 2;
+        comp->maxStep = newSize;
     }
     cur = &comp->steps[comp->nbStep++];
     cur->flags = flags;
@@ -1559,15 +1578,9 @@ xmlNewStreamCtxt(xmlStreamCompPtr stream) {
 	return(NULL);
     }
     memset(cur, 0, sizeof(xmlStreamCtxt));
-    cur->states = (int *) xmlMalloc(4 * 2 * sizeof(int));
-    if (cur->states == NULL) {
-	xmlFree(cur);
-	ERROR(NULL, NULL, NULL,
-	      "xmlNewStreamCtxt: malloc failed\n");
-	return(NULL);
-    }
+    cur->states = NULL;
     cur->nbState = 0;
-    cur->maxState = 4;
+    cur->maxState = 0;
     cur->level = 0;
     cur->comp = stream;
     cur->blockLevel = -1;
@@ -1613,17 +1626,24 @@ xmlStreamCtxtAddState(xmlStreamCtxtPtr comp, int idx, int level) {
 	}
     }
     if (comp->nbState >= comp->maxState) {
-        int *cur;
+        int *tmp;
+        int newSize;
 
-	cur = (int *) xmlRealloc(comp->states,
-				 comp->maxState * 4 * sizeof(int));
-	if (cur == NULL) {
+        newSize = xmlGrowCapacity(comp->maxState, sizeof(tmp[0]) * 2,
+                                  4, XML_MAX_ITEMS);
+        if (newSize < 0) {
+	    ERROR(NULL, NULL, NULL,
+		  "xmlNewStreamCtxt: growCapacity failed\n");
+	    return(-1);
+        }
+	tmp = xmlRealloc(comp->states, newSize * sizeof(tmp[0]) * 2);
+	if (tmp == NULL) {
 	    ERROR(NULL, NULL, NULL,
 		  "xmlNewStreamCtxt: malloc failed\n");
 	    return(-1);
 	}
-	comp->states = cur;
-        comp->maxState *= 2;
+	comp->states = tmp;
+        comp->maxState = newSize;
     }
     comp->states[2 * comp->nbState] = idx;
     comp->states[2 * comp->nbState++ + 1] = level;
diff --git a/python/generator.py b/python/generator.py
index 0d175d2d..9efdbab4 100755
--- a/python/generator.py
+++ b/python/generator.py
@@ -308,6 +308,8 @@ deprecated_funcs = {
     'xmlCleanupCharEncodingHandlers': True,
     'xmlCleanupGlobals': True,
     'xmlCopyChar': True,
+    'xmlCopyCharMultiByte': True,
+    'xmlCreateEntityParserCtxt': True,
     'xmlDefaultSAXHandlerInit': True,
     'xmlDictCleanup': True,
     'xmlFileMatch': True,
@@ -341,6 +343,8 @@ deprecated_funcs = {
     'xmlParseEntity': True,
     'xmlParseEntityDecl': True,
     'xmlParseEntityRef': True,
+    'xmlParseExtParsedEnt': True,
+    'xmlParseExternalSubset': True,
     'xmlParseMarkupDecl': True,
     'xmlParseMisc': True,
     'xmlParseName': True,
@@ -368,6 +372,7 @@ deprecated_funcs = {
     'xmlParserSetReplaceEntities': True,
     'xmlParserSetValidate': True,
     'xmlPedanticParserDefault': True,
+    'xmlPopInput': True,
     'xmlRecoverDoc': True,
     'xmlRecoverFile': True,
     'xmlRecoverMemory': True,
diff --git a/python/libxml.c b/python/libxml.c
index f6e0fb4f..d47e63a7 100644
--- a/python/libxml.c
+++ b/python/libxml.c
@@ -30,7 +30,7 @@
 #include "libxml2-py.h"
 
 #if PY_MAJOR_VERSION >= 3
-PyObject *PyInit_libxml2mod(void);
+PyMODINIT_FUNC PyInit_libxml2mod(void);
 
 #define PY_IMPORT_STRING_SIZE PyUnicode_FromStringAndSize
 #define PY_IMPORT_STRING PyUnicode_FromString
@@ -3639,7 +3639,7 @@ extern void initlibxsltmod(void);
 #endif
 
 #if PY_MAJOR_VERSION >= 3
-PyObject *PyInit_libxml2mod(void)
+PyMODINIT_FUNC PyInit_libxml2mod(void)
 #else
 void initlibxml2mod(void)
 #endif
diff --git a/python/tests/reader2.py b/python/tests/reader2.py
index 59141a88..0857c232 100755
--- a/python/tests/reader2.py
+++ b/python/tests/reader2.py
@@ -42,9 +42,6 @@ value
 """{0}/781333.xml:4: element a: validity error : Element a content does not follow the DTD, expecting ( ..., got 
 <a/>
     ^
-{0}/781333.xml:5: element a: validity error : Element a content does not follow the DTD, Expecting more children
-
-^
 """.format(dir_prefix),
     'cond_sect2':
 """{0}/dtds/cond_sect2.dtd:15: parser error : All markup of the conditional section is not in the same entity
diff --git a/relaxng.c b/relaxng.c
index d452fcea..f5b64505 100644
--- a/relaxng.c
+++ b/relaxng.c
@@ -35,6 +35,7 @@
 #include <libxml/xmlschemastypes.h>
 
 #include "private/error.h"
+#include "private/parser.h"
 #include "private/regexp.h"
 #include "private/string.h"
 
@@ -4325,7 +4326,7 @@ xmlRelaxNGComputeInterleaves(void *payload, void *data,
                 if ((*tmp)->type == XML_RELAXNG_TEXT) {
                     res = xmlHashAddEntry2(partitions->triage,
                                            BAD_CAST "#text", NULL,
-                                           (void *) (ptrdiff_t) (i + 1));
+                                           XML_INT_TO_PTR(i + 1));
                     if (res != 0)
                         is_determinist = -1;
                 } else if (((*tmp)->type == XML_RELAXNG_ELEMENT) &&
@@ -4333,22 +4334,22 @@ xmlRelaxNGComputeInterleaves(void *payload, void *data,
                     if (((*tmp)->ns == NULL) || ((*tmp)->ns[0] == 0))
                         res = xmlHashAddEntry2(partitions->triage,
                                                (*tmp)->name, NULL,
-                                               (void *) (ptrdiff_t) (i + 1));
+                                               XML_INT_TO_PTR(i + 1));
                     else
                         res = xmlHashAddEntry2(partitions->triage,
                                                (*tmp)->name, (*tmp)->ns,
-                                               (void *) (ptrdiff_t) (i + 1));
+                                               XML_INT_TO_PTR(i + 1));
                     if (res != 0)
                         is_determinist = -1;
                 } else if ((*tmp)->type == XML_RELAXNG_ELEMENT) {
                     if (((*tmp)->ns == NULL) || ((*tmp)->ns[0] == 0))
                         res = xmlHashAddEntry2(partitions->triage,
                                                BAD_CAST "#any", NULL,
-                                               (void *) (ptrdiff_t) (i + 1));
+                                               XML_INT_TO_PTR(i + 1));
                     else
                         res = xmlHashAddEntry2(partitions->triage,
                                                BAD_CAST "#any", (*tmp)->ns,
-                                               (void *) (ptrdiff_t) (i + 1));
+                                               XML_INT_TO_PTR(i + 1));
                     if ((*tmp)->nameClass != NULL)
                         is_determinist = 2;
                     if (res != 0)
@@ -9231,7 +9232,7 @@ xmlRelaxNGValidateInterleave(xmlRelaxNGValidCtxtPtr ctxt,
             if (tmp == NULL) {
                 i = nbgroups;
             } else {
-                i = ((ptrdiff_t) tmp) - 1;
+                i = XML_PTR_TO_INT(tmp) - 1;
                 if (partitions->flags & IS_NEEDCHECK) {
                     group = partitions->groups[i];
                     if (!xmlRelaxNGNodeMatchesList(cur, group->defs))
diff --git a/result/HTML/758518-entity.html.sax b/result/HTML/758518-entity.html.sax
index 3f8e8bd1..25aa72a2 100644
--- a/result/HTML/758518-entity.html.sax
+++ b/result/HTML/758518-entity.html.sax
@@ -3,7 +3,8 @@ SAX.startDocument()
 SAX.startElement(html)
 SAX.startElement(body)
 SAX.startElement(p)
-SAX.characters(&amp;j&Ugrave;, 4)
+SAX.characters(&amp;j, 2)
+SAX.characters(&Ugrave;, 2)
 SAX.endElement(p)
 SAX.endElement(body)
 SAX.endElement(html)
diff --git a/result/HTML/758605.html.sax b/result/HTML/758605.html.sax
index ac2bc208..c6dc85ae 100644
--- a/result/HTML/758605.html.sax
+++ b/result/HTML/758605.html.sax
@@ -3,8 +3,9 @@ SAX.startDocument()
 SAX.startElement(html)
 SAX.startElement(body)
 SAX.startElement(p)
-SAX.characters(&amp;:&ecirc;
-, 5)
+SAX.characters(&amp;:, 2)
+SAX.characters(&ecirc;
+, 3)
 SAX.endElement(p)
 SAX.endElement(body)
 SAX.endElement(html)
diff --git a/result/HTML/wired.html.sax b/result/HTML/wired.html.sax
index ba27111f..341675f1 100644
--- a/result/HTML/wired.html.sax
+++ b/result/HTML/wired.html.sax
@@ -2013,7 +2013,8 @@ SAX.characters(
 , 1)
 SAX.startElement(font, size='2', face='Arial, Helvetica, sans-serif', color='#000000')
 SAX.startElement(b)
-SAX.characters(F&uuml;hrer Furor, 13)
+SAX.characters(F, 1)
+SAX.characters(&uuml;hrer Furor, 12)
 SAX.endElement(b)
 SAX.endElement(font)
 SAX.startElement(br)
diff --git a/result/VC/ElementValid2.rdr b/result/VC/ElementValid2.rdr
index cae331b5..db47c897 100644
--- a/result/VC/ElementValid2.rdr
+++ b/result/VC/ElementValid2.rdr
@@ -1,6 +1,3 @@
 ./test/VC/ElementValid2:4: element p: validity error : No declaration for element p
 <doc><p/></doc>
          ^
-./test/VC/ElementValid2:5: element p: validity error : No declaration for element p
-
-^
diff --git a/result/VC/ElementValid3.rdr b/result/VC/ElementValid3.rdr
index 5f4e03e2..2fc236d5 100644
--- a/result/VC/ElementValid3.rdr
+++ b/result/VC/ElementValid3.rdr
@@ -1,6 +1,3 @@
 ./test/VC/ElementValid3:4: element doc: validity error : Element doc was declared EMPTY this one has content
 <doc>Oops, this element was declared EMPTY</doc>
                                                 ^
-./test/VC/ElementValid3:5: element doc: validity error : Element doc was declared EMPTY this one has content
-
-^
diff --git a/result/VC/ElementValid4.rdr b/result/VC/ElementValid4.rdr
index 289a527e..4791db5d 100644
--- a/result/VC/ElementValid4.rdr
+++ b/result/VC/ElementValid4.rdr
@@ -1,6 +1,3 @@
 ./test/VC/ElementValid4:7: element doc: validity error : Element c is not declared in doc list of possible children
 <doc> This <b>seems</b> Ok <a/> but this <c>was not declared</c></doc>
                                                                       ^
-./test/VC/ElementValid4:8: element doc: validity error : Element c is not declared in doc list of possible children
-
-^
diff --git a/result/VC/ElementValid5.rdr b/result/VC/ElementValid5.rdr
index 91eef9c6..bd064f6b 100644
--- a/result/VC/ElementValid5.rdr
+++ b/result/VC/ElementValid5.rdr
@@ -1,9 +1,3 @@
 ./test/VC/ElementValid5:7: element doc: validity error : Element doc content does not follow the DTD, expecting (a , b* , c+), got (a b c b)
 <doc><a/><b> but this</b><c>was not declared</c><b>seems</b></doc>
                                                                   ^
-./test/VC/ElementValid5:8: element doc: validity error : Element doc content does not follow the DTD, Misplaced b
-
-^
-./test/VC/ElementValid5:8: element doc: validity error : Element doc content does not follow the DTD, Expecting more children
-
-^
diff --git a/result/VC/ElementValid6.rdr b/result/VC/ElementValid6.rdr
index 3b51d1a1..1cbf8fdb 100644
--- a/result/VC/ElementValid6.rdr
+++ b/result/VC/ElementValid6.rdr
@@ -1,6 +1,3 @@
 ./test/VC/ElementValid6:7: element doc: validity error : Element doc content does not follow the DTD, expecting (a , b? , c+)?, got (a b)
 <doc><a/><b>lacks c</b></doc>
                              ^
-./test/VC/ElementValid6:8: element doc: validity error : Element doc content does not follow the DTD, Expecting more children
-
-^
diff --git a/result/VC/ElementValid7.rdr b/result/VC/ElementValid7.rdr
index ecafd1db..4ce9dbfe 100644
--- a/result/VC/ElementValid7.rdr
+++ b/result/VC/ElementValid7.rdr
@@ -1,6 +1,3 @@
 ./test/VC/ElementValid7:7: element doc: validity error : Element doc content does not follow the DTD, expecting ((a | b)* , c+ , a , b? , c , a?), got (a b a c c a)
 <doc><a/><b/><a/><c/><c/><a/></doc>
                                    ^
-./test/VC/ElementValid7:8: element doc: validity error : Element doc content does not follow the DTD, Expecting more children
-
-^
diff --git a/result/XPath/tests/unicodesimple b/result/XPath/tests/unicodesimple
new file mode 100644
index 00000000..92aa5365
--- /dev/null
+++ b/result/XPath/tests/unicodesimple
@@ -0,0 +1,6 @@
+
+========================
+Expression: /文書
+Object is a Node Set :
+Set contains 1 nodes:
+1  ELEMENT #E6#96#87#E6#9B#B8
diff --git a/result/errors/759573.xml.ent b/result/errors/759573.xml.ent
index 3c6be9a8..46f12d75 100644
--- a/result/errors/759573.xml.ent
+++ b/result/errors/759573.xml.ent
@@ -1,3 +1,6 @@
+./test/errors/759573.xml:1: parser error : Space required after 'DOCTYPE'
+<?h?><!DOCTYPEt[<!ELEMENT t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;00
+              ^
 ./test/errors/759573.xml:1: parser error : Space required after '<!ENTITY'
 ELEMENT t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITY
                                                                                ^
@@ -7,15 +10,9 @@ LEMENT t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITYz
 ./test/errors/759573.xml:1: parser error : Entity value required
 LEMENT t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITYz
                                                                                ^
-./test/errors/759573.xml:1: parser error : PEReference: no name
+./test/errors/759573.xml:1: parser error : Entity 'xx' not defined
 T t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITYz>%xx;
                                                                                ^
-Entity: line 1: 
-%<![INCLUDE[000%ஸ000%z;
- ^
 ./test/errors/759573.xml:1: parser error : Content error in the internal subset
 T t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITYz>%xx;
                                                                                ^
-Entity: line 1: 
-%<![INCLUDE[000%ஸ000%z;
-   ^
diff --git a/result/errors/759573.xml.err b/result/errors/759573.xml.err
index 3c6be9a8..e403ab44 100644
--- a/result/errors/759573.xml.err
+++ b/result/errors/759573.xml.err
@@ -1,3 +1,6 @@
+./test/errors/759573.xml:1: parser error : Space required after 'DOCTYPE'
+<?h?><!DOCTYPEt[<!ELEMENT t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;00
+              ^
 ./test/errors/759573.xml:1: parser error : Space required after '<!ENTITY'
 ELEMENT t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITY
                                                                                ^
@@ -7,15 +10,9 @@ LEMENT t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITYz
 ./test/errors/759573.xml:1: parser error : Entity value required
 LEMENT t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITYz
                                                                                ^
-./test/errors/759573.xml:1: parser error : PEReference: no name
+./test/errors/759573.xml:1: parser warning : Entity 'xx' not defined
 T t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITYz>%xx;
                                                                                ^
-Entity: line 1: 
-%<![INCLUDE[000%ஸ000%z;
- ^
 ./test/errors/759573.xml:1: parser error : Content error in the internal subset
 T t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITYz>%xx;
                                                                                ^
-Entity: line 1: 
-%<![INCLUDE[000%ஸ000%z;
-   ^
diff --git a/result/errors/759573.xml.str b/result/errors/759573.xml.str
index 2736393b..459431d9 100644
--- a/result/errors/759573.xml.str
+++ b/result/errors/759573.xml.str
@@ -1,22 +1,4 @@
-./test/errors/759573.xml:1: parser error : Space required after '<!ENTITY'
-ELEMENT t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITY
-                                                                               ^
-./test/errors/759573.xml:1: parser error : Space required after the entity name
-LEMENT t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITYz
-                                                                               ^
-./test/errors/759573.xml:1: parser error : Entity value required
-LEMENT t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITYz
-                                                                               ^
-./test/errors/759573.xml:1: parser error : PEReference: no name
-T t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITYz>%xx;
-                                                                               ^
-Entity: line 1: 
-%<![INCLUDE[000%ஸ000%z;
- ^
-./test/errors/759573.xml:1: parser error : Content error in the internal subset
-T t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;000&#37;z;'><!ENTITYz>%xx;
-                                                                               ^
-Entity: line 1: 
-%<![INCLUDE[000%ஸ000%z;
-   ^
+./test/errors/759573.xml:1: parser error : Space required after 'DOCTYPE'
+<?h?><!DOCTYPEt[<!ELEMENT t (A)><!ENTITY % xx '&#37;<![INCLUDE[000&#37;&#3000;00
+              ^
 ./test/errors/759573.xml : failed to parse
diff --git a/result/errors/doctype1.xml.ent b/result/errors/doctype1.xml.ent
new file mode 100644
index 00000000..71283ea2
--- /dev/null
+++ b/result/errors/doctype1.xml.ent
@@ -0,0 +1,3 @@
+./test/errors/doctype1.xml:1: parser error : Start tag expected, '<' not found
+<!DOCTYPE doc>[]>
+              ^
diff --git a/result/errors/doctype1.xml.err b/result/errors/doctype1.xml.err
new file mode 100644
index 00000000..71283ea2
--- /dev/null
+++ b/result/errors/doctype1.xml.err
@@ -0,0 +1,3 @@
+./test/errors/doctype1.xml:1: parser error : Start tag expected, '<' not found
+<!DOCTYPE doc>[]>
+              ^
diff --git a/result/errors/doctype1.xml.str b/result/errors/doctype1.xml.str
new file mode 100644
index 00000000..5e63269b
--- /dev/null
+++ b/result/errors/doctype1.xml.str
@@ -0,0 +1,4 @@
+./test/errors/doctype1.xml:1: parser error : Start tag expected, '<' not found
+<!DOCTYPE doc>[]>
+              ^
+./test/errors/doctype1.xml : failed to parse
diff --git a/result/errors/doctype2.xml.ent b/result/errors/doctype2.xml.ent
new file mode 100644
index 00000000..ddb4f563
--- /dev/null
+++ b/result/errors/doctype2.xml.ent
@@ -0,0 +1,3 @@
+./test/errors/doctype2.xml:1: parser error : Space required after 'DOCTYPE'
+<!DOCTYPEdoc>
+         ^
diff --git a/result/errors/doctype2.xml.err b/result/errors/doctype2.xml.err
new file mode 100644
index 00000000..ddb4f563
--- /dev/null
+++ b/result/errors/doctype2.xml.err
@@ -0,0 +1,3 @@
+./test/errors/doctype2.xml:1: parser error : Space required after 'DOCTYPE'
+<!DOCTYPEdoc>
+         ^
diff --git a/result/errors/doctype2.xml.str b/result/errors/doctype2.xml.str
new file mode 100644
index 00000000..1e7f4c2b
--- /dev/null
+++ b/result/errors/doctype2.xml.str
@@ -0,0 +1,4 @@
+./test/errors/doctype2.xml:1: parser error : Space required after 'DOCTYPE'
+<!DOCTYPEdoc>
+         ^
+./test/errors/doctype2.xml : failed to parse
diff --git a/result/errors/dup-xml-attr2.xml.ent b/result/errors/dup-xml-attr2.xml.ent
new file mode 100644
index 00000000..ab28d807
--- /dev/null
+++ b/result/errors/dup-xml-attr2.xml.ent
@@ -0,0 +1,9 @@
+./test/errors/dup-xml-attr2.xml:2: namespace error : Namespaced Attribute a in 'urn:a' redefined
+    <elem a:a="" b:a="" b:a=""/>
+                              ^
+./test/errors/dup-xml-attr2.xml:2: namespace error : Namespaced Attribute a in 'urn:a' redefined
+    <elem a:a="" b:a="" b:a=""/>
+                              ^
+./test/errors/dup-xml-attr2.xml:2: parser error : Attribute b:a redefined
+    <elem a:a="" b:a="" b:a=""/>
+                              ^
diff --git a/result/errors/dup-xml-attr2.xml.err b/result/errors/dup-xml-attr2.xml.err
new file mode 100644
index 00000000..ab28d807
--- /dev/null
+++ b/result/errors/dup-xml-attr2.xml.err
@@ -0,0 +1,9 @@
+./test/errors/dup-xml-attr2.xml:2: namespace error : Namespaced Attribute a in 'urn:a' redefined
+    <elem a:a="" b:a="" b:a=""/>
+                              ^
+./test/errors/dup-xml-attr2.xml:2: namespace error : Namespaced Attribute a in 'urn:a' redefined
+    <elem a:a="" b:a="" b:a=""/>
+                              ^
+./test/errors/dup-xml-attr2.xml:2: parser error : Attribute b:a redefined
+    <elem a:a="" b:a="" b:a=""/>
+                              ^
diff --git a/result/errors/dup-xml-attr2.xml.str b/result/errors/dup-xml-attr2.xml.str
new file mode 100644
index 00000000..45dbb9e1
--- /dev/null
+++ b/result/errors/dup-xml-attr2.xml.str
@@ -0,0 +1,10 @@
+./test/errors/dup-xml-attr2.xml:2: namespace error : Namespaced Attribute a in 'urn:a' redefined
+    <elem a:a="" b:a="" b:a=""/>
+                              ^
+./test/errors/dup-xml-attr2.xml:2: namespace error : Namespaced Attribute a in 'urn:a' redefined
+    <elem a:a="" b:a="" b:a=""/>
+                              ^
+./test/errors/dup-xml-attr2.xml:2: parser error : Attribute b:a redefined
+    <elem a:a="" b:a="" b:a=""/>
+                              ^
+./test/errors/dup-xml-attr2.xml : failed to parse
diff --git a/result/valid/781333.xml.err.rdr b/result/valid/781333.xml.err.rdr
index dd9df08f..b401b49a 100644
--- a/result/valid/781333.xml.err.rdr
+++ b/result/valid/781333.xml.err.rdr
@@ -1,6 +1,3 @@
 ./test/valid/781333.xml:4: element a: validity error : Element a content does not follow the DTD, expecting ( ..., got 
 <a/>
     ^
-./test/valid/781333.xml:5: element a: validity error : Element a content does not follow the DTD, Expecting more children
-
-^
diff --git a/runtest.c b/runtest.c
index 779e7ffa..f1d7a750 100644
--- a/runtest.c
+++ b/runtest.c
@@ -1797,6 +1797,8 @@ htmlTokenizerTest(const char *filename, const char *result,
         config.startTag = BAD_CAST startTag;
         config.inCharacters = 0;
         ctxt->_private = &config;
+        /* Skip charset auto-detection */
+        ctxt->instate = XML_PARSER_XML_DECL;
         htmlCtxtUseOptions(ctxt, options | HTML_PARSE_HTML5);
         htmlParseChunk(ctxt, data, size, 1);
         htmlFreeParserCtxt(ctxt);
@@ -2254,9 +2256,13 @@ pushBoundaryTest(const char *filename, const char *result,
                 if ((options & XML_PARSE_HTML) &&
                     (ctxt->endCheckState)) {
                     max = strlen((const char *) ctxt->name) + 2;
+                } else if (c == '&') {
+                    max = (options & XML_PARSE_HTML) ? 32 : 1;
+                } else if (c == '<') {
+                    max = 1;
                 } else {
                     /* 3 bytes for partial UTF-8 */
-                    max = ((c == '<') || (c == '&')) ? 1 : 3;
+                    max = 3;
                 }
             } else if (ctxt->instate == XML_PARSER_CDATA_SECTION) {
                 /* 2 bytes for terminator, 3 bytes for UTF-8 */
@@ -3389,8 +3395,11 @@ static int urip_rlen;
  */
 static int
 uripMatch(const char * URI) {
-    if ((URI == NULL) || (!strcmp(URI, "file://" SYSCONFDIR "/xml/catalog")))
+#ifdef LIBXML_CATALOG_ENABLED
+    if ((URI == NULL) ||
+        (!strcmp(URI, "file://" XML_SYSCONFDIR "/xml/catalog")))
         return(0);
+#endif
     /* Verify we received the escaped URL */
     if (strcmp(urip_rcvsURLs[urip_current], URI))
 	urip_success = 0;
@@ -3408,8 +3417,11 @@ uripMatch(const char * URI) {
  */
 static void *
 uripOpen(const char * URI) {
-    if ((URI == NULL) || (!strcmp(URI, "file://" SYSCONFDIR "/xml/catalog")))
+#ifdef LIBXML_CATALOG_ENABLED
+    if ((URI == NULL) ||
+        (!strcmp(URI, "file://" XML_SYSCONFDIR "/xml/catalog")))
         return(NULL);
+#endif
     /* Verify we received the escaped URL */
     if (strcmp(urip_rcvsURLs[urip_current], URI))
 	urip_success = 0;
diff --git a/runxmlconf.c b/runxmlconf.c
index 62401e8e..ec0e96ca 100644
--- a/runxmlconf.c
+++ b/runxmlconf.c
@@ -29,7 +29,11 @@
 static FILE *logfile = NULL;
 static int verbose = 0;
 
-#define NB_EXPECTED_ERRORS 15
+#ifdef LIBXML_REGEXP_ENABLED
+  #define NB_EXPECTED_ERRORS 15
+#else
+  #define NB_EXPECTED_ERRORS 16
+#endif
 
 
 const char *skipped_tests[] = {
diff --git a/shell.c b/shell.c
index a1572b28..ebefb50a 100644
--- a/shell.c
+++ b/shell.c
@@ -35,7 +35,7 @@
 #include <libxml/relaxng.h>
 #endif
 
-#include "private/shell.h"
+#include "private/lint.h"
 
 #ifndef STDIN_FILENO
   #define STDIN_FILENO 0
@@ -1096,7 +1096,6 @@ xmllintShellReadline(char *prompt) {
  * xmllintShell:
  * @doc:  the initial document
  * @filename:  the output buffer
- * @input:  the line reading function
  * @output:  the output FILE*, defaults to stdout if NULL
  *
  * Implements the XML shell
diff --git a/test/XPath/docs/unicode b/test/XPath/docs/unicode
new file mode 100644
index 00000000..8be1ea26
--- /dev/null
+++ b/test/XPath/docs/unicode
@@ -0,0 +1 @@
+<文書>text1</文書>
diff --git a/test/XPath/tests/unicodesimple b/test/XPath/tests/unicodesimple
new file mode 100644
index 00000000..d53f4f5f
--- /dev/null
+++ b/test/XPath/tests/unicodesimple
@@ -0,0 +1 @@
+/文書
diff --git a/test/errors/doctype1.xml b/test/errors/doctype1.xml
new file mode 100644
index 00000000..25ac8e6d
--- /dev/null
+++ b/test/errors/doctype1.xml
@@ -0,0 +1,2 @@
+<!DOCTYPE doc>[]>
+<doc/>
diff --git a/test/errors/doctype2.xml b/test/errors/doctype2.xml
new file mode 100644
index 00000000..0ee04064
--- /dev/null
+++ b/test/errors/doctype2.xml
@@ -0,0 +1,2 @@
+<!DOCTYPEdoc>
+<doc/>
diff --git a/test/errors/dup-xml-attr2.xml b/test/errors/dup-xml-attr2.xml
new file mode 100644
index 00000000..9bc014de
--- /dev/null
+++ b/test/errors/dup-xml-attr2.xml
@@ -0,0 +1,3 @@
+<doc xmlns:a="urn:a" xmlns:b="urn:a">
+    <elem a:a="" b:a="" b:a=""/>
+</doc>
diff --git a/testapi.c b/testapi.c
index 438acfbc..10427c4a 100644
--- a/testapi.c
+++ b/testapi.c
@@ -1849,6 +1849,47 @@ test_htmlCtxtReset(void) {
 }
 
 
+static int
+test_htmlCtxtSetOptions(void) {
+    int test_ret = 0;
+
+#if defined(LIBXML_HTML_ENABLED)
+    int mem_base;
+    int ret_val;
+    xmlParserCtxtPtr ctxt; /* an HTML parser context */
+    int n_ctxt;
+    int options; /* a bitmask of xmlParserOption values */
+    int n_options;
+
+    for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
+    for (n_options = 0;n_options < gen_nb_int;n_options++) {
+        mem_base = xmlMemBlocks();
+        ctxt = gen_xmlParserCtxtPtr(n_ctxt, 0);
+        options = gen_int(n_options, 1);
+
+        ret_val = htmlCtxtSetOptions(ctxt, options);
+        desret_int(ret_val);
+        call_tests++;
+        des_xmlParserCtxtPtr(n_ctxt, ctxt, 0);
+        des_int(n_options, options, 1);
+        xmlResetLastError();
+        if (mem_base != xmlMemBlocks()) {
+            printf("Leak of %d blocks found in htmlCtxtSetOptions",
+	           xmlMemBlocks() - mem_base);
+	    test_ret++;
+            printf(" %d", n_ctxt);
+            printf(" %d", n_options);
+            printf("\n");
+        }
+    }
+    }
+    function_tests++;
+#endif
+
+    return(test_ret);
+}
+
+
 static int
 test_htmlCtxtUseOptions(void) {
     int test_ret = 0;
@@ -2916,7 +2957,7 @@ static int
 test_HTMLparser(void) {
     int test_ret = 0;
 
-    if (quiet == 0) printf("Testing HTMLparser : 36 of 42 functions ...\n");
+    if (quiet == 0) printf("Testing HTMLparser : 37 of 43 functions ...\n");
     test_ret += test_UTF8ToHtml();
     test_ret += test_htmlAttrAllowed();
     test_ret += test_htmlAutoCloseTag();
@@ -2928,6 +2969,7 @@ test_HTMLparser(void) {
     test_ret += test_htmlCtxtReadFile();
     test_ret += test_htmlCtxtReadMemory();
     test_ret += test_htmlCtxtReset();
+    test_ret += test_htmlCtxtSetOptions();
     test_ret += test_htmlCtxtUseOptions();
     test_ret += test_htmlElementAllowedHere();
     test_ret += test_htmlElementStatusHere();
@@ -8905,7 +8947,7 @@ test_xmlEncodeSpecialChars(void) {
 
     int mem_base;
     xmlChar * ret_val;
-    const xmlDoc * doc; /* the document containing the string */
+    const xmlDoc * doc; /* unused */
     int n_doc;
     const xmlChar * input; /* A string to convert to XML. */
     int n_input;
@@ -11837,7 +11879,7 @@ test_xmlCtxtGetCatalogs(void) {
 
     int mem_base;
     void * ret_val;
-    xmlParserCtxtPtr ctxt; /*  */
+    xmlParserCtxtPtr ctxt; /* parser context */
     int n_ctxt;
 
     for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
@@ -11869,7 +11911,7 @@ test_xmlCtxtGetDeclaredEncoding(void) {
 
     int mem_base;
     const xmlChar * ret_val;
-    xmlParserCtxtPtr ctxt; /*  */
+    xmlParserCtxtPtr ctxt; /* parser context */
     int n_ctxt;
 
     for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
@@ -11933,7 +11975,7 @@ test_xmlCtxtGetPrivate(void) {
 
     int mem_base;
     void * ret_val;
-    xmlParserCtxtPtr ctxt; /*  */
+    xmlParserCtxtPtr ctxt; /* parser context */
     int n_ctxt;
 
     for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
@@ -11965,7 +12007,7 @@ test_xmlCtxtGetStandalone(void) {
 
     int mem_base;
     int ret_val;
-    xmlParserCtxtPtr ctxt; /*  */
+    xmlParserCtxtPtr ctxt; /* parser context */
     int n_ctxt;
 
     for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
@@ -12033,7 +12075,7 @@ test_xmlCtxtGetVersion(void) {
 
     int mem_base;
     const xmlChar * ret_val;
-    xmlParserCtxtPtr ctxt; /*  */
+    xmlParserCtxtPtr ctxt; /* parser context */
     int n_ctxt;
 
     for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
@@ -12151,6 +12193,61 @@ test_xmlCtxtParseDocument(void) {
 }
 
 
+static int
+test_xmlCtxtParseDtd(void) {
+    int test_ret = 0;
+
+#if defined(LIBXML_VALID_ENABLED)
+    int mem_base;
+    xmlDtdPtr ret_val;
+    xmlParserCtxtPtr ctxt; /* a parser context */
+    int n_ctxt;
+    xmlParserInputPtr input; /* a parser input */
+    int n_input;
+    const xmlChar * publicId; /* public ID of the DTD (optional) */
+    int n_publicId;
+    const xmlChar * systemId; /* system ID of the DTD (optional) */
+    int n_systemId;
+
+    for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
+    for (n_input = 0;n_input < gen_nb_xmlParserInputPtr;n_input++) {
+    for (n_publicId = 0;n_publicId < gen_nb_const_xmlChar_ptr;n_publicId++) {
+    for (n_systemId = 0;n_systemId < gen_nb_const_xmlChar_ptr;n_systemId++) {
+        mem_base = xmlMemBlocks();
+        ctxt = gen_xmlParserCtxtPtr(n_ctxt, 0);
+        input = gen_xmlParserInputPtr(n_input, 1);
+        publicId = gen_const_xmlChar_ptr(n_publicId, 2);
+        systemId = gen_const_xmlChar_ptr(n_systemId, 3);
+
+        ret_val = xmlCtxtParseDtd(ctxt, input, publicId, systemId);
+        desret_xmlDtdPtr(ret_val);
+        call_tests++;
+        des_xmlParserCtxtPtr(n_ctxt, ctxt, 0);
+        des_xmlParserInputPtr(n_input, input, 1);
+        des_const_xmlChar_ptr(n_publicId, publicId, 2);
+        des_const_xmlChar_ptr(n_systemId, systemId, 3);
+        xmlResetLastError();
+        if (mem_base != xmlMemBlocks()) {
+            printf("Leak of %d blocks found in xmlCtxtParseDtd",
+	           xmlMemBlocks() - mem_base);
+	    test_ret++;
+            printf(" %d", n_ctxt);
+            printf(" %d", n_input);
+            printf(" %d", n_publicId);
+            printf(" %d", n_systemId);
+            printf("\n");
+        }
+    }
+    }
+    }
+    }
+    function_tests++;
+#endif
+
+    return(test_ret);
+}
+
+
 static int
 test_xmlCtxtReadDoc(void) {
     int test_ret = 0;
@@ -12432,9 +12529,9 @@ test_xmlCtxtSetCatalogs(void) {
     int test_ret = 0;
 
     int mem_base;
-    xmlParserCtxtPtr ctxt; /*  */
+    xmlParserCtxtPtr ctxt; /* parser context */
     int n_ctxt;
-    void * catalogs; /*  */
+    void * catalogs; /* catalogs pointer */
     int n_catalogs;
 
     for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
@@ -12479,9 +12576,9 @@ test_xmlCtxtSetDict(void) {
     int test_ret = 0;
 
     int mem_base;
-    xmlParserCtxtPtr ctxt; /*  */
+    xmlParserCtxtPtr ctxt; /* parser context */
     int n_ctxt;
-    xmlDictPtr dict; /*  */
+    xmlDictPtr dict; /* dictionary */
     int n_dict;
 
     for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
@@ -12575,9 +12672,9 @@ test_xmlCtxtSetPrivate(void) {
     int test_ret = 0;
 
     int mem_base;
-    xmlParserCtxtPtr ctxt; /*  */
+    xmlParserCtxtPtr ctxt; /* parser context */
     int n_ctxt;
-    void * priv; /*  */
+    void * priv; /* private application data */
     int n_priv;
 
     for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
@@ -12656,6 +12753,95 @@ test_xmlCtxtUseOptions(void) {
 }
 
 
+static int
+test_xmlCtxtValidateDocument(void) {
+    int test_ret = 0;
+
+#if defined(LIBXML_VALID_ENABLED)
+    int mem_base;
+    int ret_val;
+    xmlParserCtxtPtr ctxt; /* a parser context */
+    int n_ctxt;
+    xmlDocPtr doc; /* a document instance */
+    int n_doc;
+
+    for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
+    for (n_doc = 0;n_doc < gen_nb_xmlDocPtr;n_doc++) {
+        mem_base = xmlMemBlocks();
+        ctxt = gen_xmlParserCtxtPtr(n_ctxt, 0);
+        doc = gen_xmlDocPtr(n_doc, 1);
+
+        ret_val = xmlCtxtValidateDocument(ctxt, doc);
+        desret_int(ret_val);
+        call_tests++;
+        des_xmlParserCtxtPtr(n_ctxt, ctxt, 0);
+        des_xmlDocPtr(n_doc, doc, 1);
+        xmlResetLastError();
+        if (mem_base != xmlMemBlocks()) {
+            printf("Leak of %d blocks found in xmlCtxtValidateDocument",
+	           xmlMemBlocks() - mem_base);
+	    test_ret++;
+            printf(" %d", n_ctxt);
+            printf(" %d", n_doc);
+            printf("\n");
+        }
+    }
+    }
+    function_tests++;
+#endif
+
+    return(test_ret);
+}
+
+
+static int
+test_xmlCtxtValidateDtd(void) {
+    int test_ret = 0;
+
+#if defined(LIBXML_VALID_ENABLED)
+    int mem_base;
+    int ret_val;
+    xmlParserCtxtPtr ctxt; /* a parser context */
+    int n_ctxt;
+    xmlDocPtr doc; /* a document instance */
+    int n_doc;
+    xmlDtdPtr dtd; /* a dtd instance */
+    int n_dtd;
+
+    for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
+    for (n_doc = 0;n_doc < gen_nb_xmlDocPtr;n_doc++) {
+    for (n_dtd = 0;n_dtd < gen_nb_xmlDtdPtr;n_dtd++) {
+        mem_base = xmlMemBlocks();
+        ctxt = gen_xmlParserCtxtPtr(n_ctxt, 0);
+        doc = gen_xmlDocPtr(n_doc, 1);
+        dtd = gen_xmlDtdPtr(n_dtd, 2);
+
+        ret_val = xmlCtxtValidateDtd(ctxt, doc, dtd);
+        desret_int(ret_val);
+        call_tests++;
+        des_xmlParserCtxtPtr(n_ctxt, ctxt, 0);
+        des_xmlDocPtr(n_doc, doc, 1);
+        des_xmlDtdPtr(n_dtd, dtd, 2);
+        xmlResetLastError();
+        if (mem_base != xmlMemBlocks()) {
+            printf("Leak of %d blocks found in xmlCtxtValidateDtd",
+	           xmlMemBlocks() - mem_base);
+	    test_ret++;
+            printf(" %d", n_ctxt);
+            printf(" %d", n_doc);
+            printf(" %d", n_dtd);
+            printf("\n");
+        }
+    }
+    }
+    }
+    function_tests++;
+#endif
+
+    return(test_ret);
+}
+
+
 static int
 test_xmlGetExternalEntityLoader(void) {
     int test_ret = 0;
@@ -15335,7 +15521,7 @@ static int
 test_parser(void) {
     int test_ret = 0;
 
-    if (quiet == 0) printf("Testing parser : 86 of 102 functions ...\n");
+    if (quiet == 0) printf("Testing parser : 89 of 105 functions ...\n");
     test_ret += test_xmlByteConsumed();
     test_ret += test_xmlCleanupGlobals();
     test_ret += test_xmlClearNodeInfoSeq();
@@ -15351,6 +15537,7 @@ test_parser(void) {
     test_ret += test_xmlCtxtGetVersion();
     test_ret += test_xmlCtxtParseContent();
     test_ret += test_xmlCtxtParseDocument();
+    test_ret += test_xmlCtxtParseDtd();
     test_ret += test_xmlCtxtReadDoc();
     test_ret += test_xmlCtxtReadFile();
     test_ret += test_xmlCtxtReadMemory();
@@ -15365,6 +15552,8 @@ test_parser(void) {
     test_ret += test_xmlCtxtSetPrivate();
     test_ret += test_xmlCtxtSetResourceLoader();
     test_ret += test_xmlCtxtUseOptions();
+    test_ret += test_xmlCtxtValidateDocument();
+    test_ret += test_xmlCtxtValidateDtd();
     test_ret += test_xmlGetExternalEntityLoader();
     test_ret += test_xmlHasFeature();
     test_ret += test_xmlIOParseDTD();
@@ -15955,6 +16144,77 @@ test_xmlCtxtErrMemory(void) {
 }
 
 
+static int
+test_xmlCtxtPopInput(void) {
+    int test_ret = 0;
+
+    int mem_base;
+    xmlParserInputPtr ret_val;
+    xmlParserCtxtPtr ctxt; /* an XML parser context */
+    int n_ctxt;
+
+    for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
+        mem_base = xmlMemBlocks();
+        ctxt = gen_xmlParserCtxtPtr(n_ctxt, 0);
+
+        ret_val = xmlCtxtPopInput(ctxt);
+        desret_xmlParserInputPtr(ret_val);
+        call_tests++;
+        des_xmlParserCtxtPtr(n_ctxt, ctxt, 0);
+        xmlResetLastError();
+        if (mem_base != xmlMemBlocks()) {
+            printf("Leak of %d blocks found in xmlCtxtPopInput",
+	           xmlMemBlocks() - mem_base);
+	    test_ret++;
+            printf(" %d", n_ctxt);
+            printf("\n");
+        }
+    }
+    function_tests++;
+
+    return(test_ret);
+}
+
+
+static int
+test_xmlCtxtPushInput(void) {
+    int test_ret = 0;
+
+    int mem_base;
+    int ret_val;
+    xmlParserCtxtPtr ctxt; /* an XML parser context */
+    int n_ctxt;
+    xmlParserInputPtr value; /* the parser input */
+    int n_value;
+
+    for (n_ctxt = 0;n_ctxt < gen_nb_xmlParserCtxtPtr;n_ctxt++) {
+    for (n_value = 0;n_value < gen_nb_xmlParserInputPtr;n_value++) {
+        mem_base = xmlMemBlocks();
+        ctxt = gen_xmlParserCtxtPtr(n_ctxt, 0);
+        value = gen_xmlParserInputPtr(n_value, 1);
+
+        ret_val = xmlCtxtPushInput(ctxt, value);
+        desret_int(ret_val);
+        call_tests++;
+        des_xmlParserCtxtPtr(n_ctxt, ctxt, 0);
+        des_xmlParserInputPtr(n_value, value, 1);
+        xmlResetLastError();
+        if (mem_base != xmlMemBlocks()) {
+            printf("Leak of %d blocks found in xmlCtxtPushInput",
+	           xmlMemBlocks() - mem_base);
+	    test_ret++;
+            printf(" %d", n_ctxt);
+            printf(" %d", n_value);
+            printf("\n");
+        }
+    }
+    }
+    function_tests++;
+
+    return(test_ret);
+}
+
+
 static int
 test_xmlCurrentChar(void) {
     int test_ret = 0;
@@ -16708,7 +16968,7 @@ static int
 test_parserInternals(void) {
     int test_ret = 0;
 
-    if (quiet == 0) printf("Testing parserInternals : 32 of 79 functions ...\n");
+    if (quiet == 0) printf("Testing parserInternals : 34 of 81 functions ...\n");
     test_ret += test_inputPop();
     test_ret += test_inputPush();
     test_ret += test_namePop();
@@ -16723,6 +16983,8 @@ test_parserInternals(void) {
     test_ret += test_xmlCreateMemoryParserCtxt();
     test_ret += test_xmlCreateURLParserCtxt();
     test_ret += test_xmlCtxtErrMemory();
+    test_ret += test_xmlCtxtPopInput();
+    test_ret += test_xmlCtxtPushInput();
     test_ret += test_xmlCurrentChar();
     test_ret += test_xmlIsLetter();
     test_ret += test_xmlNewEntityInputStream();
@@ -22646,7 +22908,7 @@ test_xmlNodeListGetRawString(void) {
     xmlChar * ret_val;
     const xmlDoc * doc; /* a document (optional) */
     int n_doc;
-    const xmlNode * list; /* a node list of attribute children (optional) */
+    const xmlNode * list; /* a node list of attribute children */
     int n_list;
     int inLine; /* whether entity references are substituted */
     int n_inLine;
@@ -22692,7 +22954,7 @@ test_xmlNodeListGetString(void) {
     xmlChar * ret_val;
     xmlDocPtr doc; /* a document (optional) */
     int n_doc;
-    const xmlNode * list; /* a node list of attribute children (optional) */
+    const xmlNode * list; /* a node list of attribute children */
     int n_list;
     int inLine; /* whether entity references are substituted */
     int n_inLine;
@@ -26683,28 +26945,28 @@ test_xmlValidateDocument(void) {
 #if defined(LIBXML_VALID_ENABLED)
     int mem_base;
     int ret_val;
-    xmlValidCtxtPtr ctxt; /* the validation context */
-    int n_ctxt;
+    xmlValidCtxtPtr vctxt; /* the validation context */
+    int n_vctxt;
     xmlDocPtr doc; /* a document instance */
     int n_doc;
 
-    for (n_ctxt = 0;n_ctxt < gen_nb_xmlValidCtxtPtr;n_ctxt++) {
+    for (n_vctxt = 0;n_vctxt < gen_nb_xmlValidCtxtPtr;n_vctxt++) {
     for (n_doc = 0;n_doc < gen_nb_xmlDocPtr;n_doc++) {
         mem_base = xmlMemBlocks();
-        ctxt = gen_xmlValidCtxtPtr(n_ctxt, 0);
+        vctxt = gen_xmlValidCtxtPtr(n_vctxt, 0);
         doc = gen_xmlDocPtr(n_doc, 1);
 
-        ret_val = xmlValidateDocument(ctxt, doc);
+        ret_val = xmlValidateDocument(vctxt, doc);
         desret_int(ret_val);
         call_tests++;
-        des_xmlValidCtxtPtr(n_ctxt, ctxt, 0);
+        des_xmlValidCtxtPtr(n_vctxt, vctxt, 0);
         des_xmlDocPtr(n_doc, doc, 1);
         xmlResetLastError();
         if (mem_base != xmlMemBlocks()) {
             printf("Leak of %d blocks found in xmlValidateDocument",
 	           xmlMemBlocks() - mem_base);
 	    test_ret++;
-            printf(" %d", n_ctxt);
+            printf(" %d", n_vctxt);
             printf(" %d", n_doc);
             printf("\n");
         }
@@ -28874,26 +29136,26 @@ test_xmlOutputBufferWrite(void) {
     int n_out;
     int len; /* the size in bytes of the array. */
     int n_len;
-    const char * buf; /* an char array */
-    int n_buf;
+    const char * data; /* an char array */
+    int n_data;
 
     for (n_out = 0;n_out < gen_nb_xmlOutputBufferPtr;n_out++) {
     for (n_len = 0;n_len < gen_nb_int;n_len++) {
-    for (n_buf = 0;n_buf < gen_nb_const_char_ptr;n_buf++) {
+    for (n_data = 0;n_data < gen_nb_const_char_ptr;n_data++) {
         mem_base = xmlMemBlocks();
         out = gen_xmlOutputBufferPtr(n_out, 0);
         len = gen_int(n_len, 1);
-        buf = gen_const_char_ptr(n_buf, 2);
-        if ((buf != NULL) &&
-            (len > xmlStrlen(BAD_CAST buf)))
+        data = gen_const_char_ptr(n_data, 2);
+        if ((data != NULL) &&
+            (len > xmlStrlen(BAD_CAST data)))
             len = 0;
 
-        ret_val = xmlOutputBufferWrite(out, len, buf);
+        ret_val = xmlOutputBufferWrite(out, len, data);
         desret_int(ret_val);
         call_tests++;
         des_xmlOutputBufferPtr(n_out, out, 0);
         des_int(n_len, len, 1);
-        des_const_char_ptr(n_buf, buf, 2);
+        des_const_char_ptr(n_data, data, 2);
         xmlResetLastError();
         if (mem_base != xmlMemBlocks()) {
             printf("Leak of %d blocks found in xmlOutputBufferWrite",
@@ -28901,7 +29163,7 @@ test_xmlOutputBufferWrite(void) {
 	    test_ret++;
             printf(" %d", n_out);
             printf(" %d", n_len);
-            printf(" %d", n_buf);
+            printf(" %d", n_data);
             printf("\n");
         }
     }
diff --git a/testchar.c b/testchar.c
index 15d163ba..02570b66 100644
--- a/testchar.c
+++ b/testchar.c
@@ -667,7 +667,7 @@ static int testCharRanges(void) {
     input->cur =
     input->base = xmlBufContent(input->buf->buffer);
     input->end = input->base + 4;
-    inputPush(ctxt, input);
+    xmlCtxtPushInput(ctxt, input);
 
     printf("testing char range: 1");
     fflush(stdout);
diff --git a/testdict.c b/testdict.c
index 94f18c2c..f9a1d991 100644
--- a/testdict.c
+++ b/testdict.c
@@ -1,3 +1,5 @@
+#include "libxml.h"
+
 #include <stdlib.h>
 #include <string.h>
 #include <libxml/parser.h>
@@ -6,19 +8,6 @@
 
 /**** dictionary tests ****/
 
-#ifdef __clang__
-  #if __clang_major__ >= 12
-    #define ATTRIBUTE_NO_SANITIZE_INTEGER \
-      __attribute__ ((no_sanitize("unsigned-integer-overflow"))) \
-      __attribute__ ((no_sanitize("unsigned-shift-base")))
-  #else
-    #define ATTRIBUTE_NO_SANITIZE_INTEGER \
-      __attribute__ ((no_sanitize("unsigned-integer-overflow")))
-  #endif
-#else
-  #define ATTRIBUTE_NO_SANITIZE_INTEGER
-#endif
-
 /* #define WITH_PRINT */
 
 static const char *seeds1[] = {
diff --git a/testparser.c b/testparser.c
index 11008dbb..a59b3e53 100644
--- a/testparser.c
+++ b/testparser.c
@@ -128,6 +128,57 @@ testCFileIO(void) {
     return err;
 }
 
+#ifdef LIBXML_VALID_ENABLED
+static void
+testSwitchDtdExtSubset(void *vctxt, const xmlChar *name ATTRIBUTE_UNUSED,
+                       const xmlChar *externalId ATTRIBUTE_UNUSED,
+                       const xmlChar *systemId ATTRIBUTE_UNUSED) {
+    xmlParserCtxtPtr ctxt = vctxt;
+
+    ctxt->myDoc->extSubset = ctxt->_private;
+}
+
+static int
+testSwitchDtd(void) {
+    const char dtdContent[] =
+        "<!ENTITY test '<elem1/><elem2/>'>\n";
+    const char docContent[] =
+        "<!DOCTYPE doc SYSTEM 'entities.dtd'>\n"
+        "<doc>&test;</doc>\n";
+    xmlParserInputBufferPtr input;
+    xmlParserCtxtPtr ctxt;
+    xmlDtdPtr dtd;
+    xmlDocPtr doc;
+    xmlEntityPtr ent;
+    int err = 0;
+
+    input = xmlParserInputBufferCreateStatic(dtdContent,
+                                             sizeof(dtdContent) - 1,
+                                             XML_CHAR_ENCODING_NONE);
+    dtd = xmlIOParseDTD(NULL, input, XML_CHAR_ENCODING_NONE);
+
+    ctxt = xmlNewParserCtxt();
+    ctxt->_private = dtd;
+    ctxt->sax->externalSubset = testSwitchDtdExtSubset;
+    doc = xmlCtxtReadMemory(ctxt, docContent, sizeof(docContent) - 1, NULL,
+                            NULL, XML_PARSE_NOENT | XML_PARSE_DTDLOAD);
+    xmlFreeParserCtxt(ctxt);
+
+    ent = xmlGetDocEntity(doc, BAD_CAST "test");
+    if (ent->children->doc != NULL) {
+        fprintf(stderr, "Entity content should have NULL doc\n");
+        err = 1;
+    }
+
+    /* Free doc before DTD */
+    doc->extSubset = NULL;
+    xmlFreeDoc(doc);
+    xmlFreeDtd(dtd);
+
+    return err;
+}
+#endif /* LIBXML_VALID_ENABLED */
+
 #ifdef LIBXML_OUTPUT_ENABLED
 static xmlChar *
 dumpNodeList(xmlNodePtr list) {
@@ -289,9 +340,95 @@ testHugeEncodedChunk(void) {
     xmlFreeParserCtxt(ctxt);
     xmlFree(chunk);
 
+    /*
+     * Test the push parser with
+     *
+     * - a single call to xmlParseChunk,
+     * - a non-UTF8 encoding,
+     * - a chunk larger then MINLEN (4000 bytes).
+     *
+     * This verifies that the whole buffer is processed in the initial
+     * charset conversion.
+     */
+    buf = xmlBufferCreate();
+    xmlBufferCat(buf,
+            BAD_CAST "<?xml version='1.0' encoding='ISO-8859-1'?>\n");
+    xmlBufferCat(buf, BAD_CAST "<doc>");
+    /* 20,000 characters */
+    for (i = 0; i < 2000; i++)
+        xmlBufferCat(buf, BAD_CAST "0123456789");
+    xmlBufferCat(buf, BAD_CAST "</doc>");
+    chunk = xmlBufferDetach(buf);
+    xmlBufferFree(buf);
+
+    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
+
+    xmlParseChunk(ctxt, (char *) chunk, xmlStrlen(chunk), 1);
+
+    err = ctxt->wellFormed ? 0 : 1;
+    xmlFreeDoc(ctxt->myDoc);
+    xmlFreeParserCtxt(ctxt);
+    xmlFree(chunk);
+
     return err;
 }
-#endif
+
+static int
+testPushCDataEnd(void) {
+    int err = 0;
+    int k;
+
+    for (k = 0; k < 2; k++) {
+        xmlBufferPtr buf;
+        xmlChar *chunk;
+        xmlParserCtxtPtr ctxt;
+        int i;
+
+        ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
+        xmlCtxtSetOptions(ctxt, XML_PARSE_NOERROR);
+
+        /*
+         * Push parse text data with ']]>' split across chunks.
+         */
+        buf = xmlBufferCreate();
+        xmlBufferCCat(buf, "<doc>");
+
+        /*
+         * Also test xmlParseCharDataCopmlex
+         */
+        if (k == 0)
+            xmlBufferCCat(buf, "x");
+        else
+            xmlBufferCCat(buf, "\xC3\xA4");
+
+        /*
+         * Create enough data to trigger a "characters" SAX callback.
+         * (XML_PARSER_BIG_BUFFER_SIZE = 300)
+         */
+        for (i = 0; i < 2000; i++)
+            xmlBufferCCat(buf, "x");
+
+        xmlBufferCCat(buf, "]");
+        chunk = xmlBufferDetach(buf);
+        xmlBufferFree(buf);
+
+        xmlParseChunk(ctxt, (char *) chunk, xmlStrlen(chunk), 0);
+        xmlParseChunk(ctxt, "]>xxx</doc>", 11, 1);
+
+        if (ctxt->errNo != XML_ERR_MISPLACED_CDATA_END) {
+            fprintf(stderr, "xmlParseChunk failed to detect CData end: %d\n",
+                    ctxt->errNo);
+            err = 1;
+        }
+
+        xmlFree(chunk);
+        xmlFreeDoc(ctxt->myDoc);
+        xmlFreeParserCtxt(ctxt);
+    }
+
+    return err;
+}
+#endif /* PUSH */
 
 #ifdef LIBXML_HTML_ENABLED
 static int
@@ -416,6 +553,76 @@ testReaderContent(void) {
     return err;
 }
 
+static int
+testReaderNode(xmlTextReader *reader) {
+    xmlChar *string;
+    int type;
+    int err = 0;
+
+    type = xmlTextReaderNodeType(reader);
+    string = xmlTextReaderReadString(reader);
+
+    if (type == XML_READER_TYPE_ELEMENT) {
+        xmlNodePtr node = xmlTextReaderCurrentNode(reader);
+
+        if ((node->children == NULL) != (string == NULL))
+            err = 1;
+    } else if (type == XML_READER_TYPE_TEXT ||
+               type == XML_READER_TYPE_CDATA ||
+               type == XML_READER_TYPE_WHITESPACE ||
+               type == XML_READER_TYPE_SIGNIFICANT_WHITESPACE) {
+        if (string == NULL)
+            err = 1;
+    } else {
+        if (string != NULL)
+            err = 1;
+    }
+
+    if (err)
+        fprintf(stderr, "xmlTextReaderReadString failed for %d\n", type);
+
+    xmlFree(string);
+
+    return err;
+}
+
+static int
+testReader(void) {
+    xmlTextReader *reader;
+    const xmlChar *xml = BAD_CAST
+        "<d>\n"
+        "  x<e a='v'>y</e><f>z</f>\n"
+        "  <![CDATA[cdata]]>\n"
+        "  <!-- comment -->\n"
+        "  <?pi content?>\n"
+        "  <empty/>\n"
+        "</d>";
+    int err = 0;
+
+    reader = xmlReaderForDoc(xml, NULL, NULL, 0);
+
+    while (xmlTextReaderRead(reader) > 0) {
+        if (testReaderNode(reader) > 0) {
+            err = 1;
+            break;
+        }
+
+        if (xmlTextReaderMoveToFirstAttribute(reader) > 0) {
+            do {
+                if (testReaderNode(reader) > 0) {
+                    err = 1;
+                    break;
+                }
+            } while (xmlTextReaderMoveToNextAttribute(reader) > 0);
+
+            xmlTextReaderMoveToElement(reader);
+        }
+    }
+
+    xmlFreeTextReader(reader);
+    return err;
+}
+
 #ifdef LIBXML_XINCLUDE_ENABLED
 typedef struct {
     char *message;
@@ -668,6 +875,81 @@ testBuildRelativeUri(void) {
     return err;
 }
 
+#if defined(_WIN32) || defined(__CYGWIN__)
+static int
+testWindowsUri(void) {
+    const char *url = "c:/a%20b/file.txt";
+    xmlURIPtr uri;
+    xmlChar *res;
+    int err = 0;
+    int i;
+
+    static const xmlRelativeUriTest tests[] = {
+        {
+            "c:/a%20b/file.txt",
+            "base.xml",
+            "c:/a b/file.txt"
+        }, {
+            "file:///c:/a%20b/file.txt",
+            "base.xml",
+            "file:///c:/a%20b/file.txt"
+        }, {
+            "Z:/a%20b/file.txt",
+            "http://example.com/",
+            "Z:/a b/file.txt"
+        }, {
+            "a%20b/b1/c1",
+            "C:/a/b2/c2",
+            "C:/a/b2/a b/b1/c1"
+        }, {
+            "a%20b/b1/c1",
+            "\\a\\b2\\c2",
+            "/a/b2/a b/b1/c1"
+        }, {
+            "a%20b/b1/c1",
+            "\\\\?\\a\\b2\\c2",
+            "//?/a/b2/a b/b1/c1"
+        }, {
+            "a%20b/b1/c1",
+            "\\\\\\\\server\\b2\\c2",
+            "//server/b2/a b/b1/c1"
+        }
+    };
+
+    uri = xmlParseURI(url);
+    if (uri == NULL) {
+        fprintf(stderr, "xmlParseURI failed\n");
+        err = 1;
+    } else {
+        if (uri->scheme != NULL) {
+            fprintf(stderr, "invalid scheme: %s\n", uri->scheme);
+            err = 1;
+        }
+        if (uri->path == NULL || strcmp(uri->path, "c:/a b/file.txt") != 0) {
+            fprintf(stderr, "invalid path: %s\n", uri->path);
+            err = 1;
+        }
+
+        xmlFreeURI(uri);
+    }
+
+    for (i = 0; (size_t) i < sizeof(tests) / sizeof(tests[0]); i++) {
+        const xmlRelativeUriTest *test = tests + i;
+
+        res = xmlBuildURI(BAD_CAST test->uri, BAD_CAST test->base);
+        if (res == NULL || !xmlStrEqual(res, BAD_CAST test->result)) {
+            fprintf(stderr, "xmlBuildURI failed uri=%s base=%s "
+                    "result=%s expected=%s\n", test->uri, test->base,
+                    res, test->result);
+            err = 1;
+        }
+        xmlFree(res);
+    }
+
+    return err;
+}
+#endif /* WIN32 */
+
 static int charEncConvImplError;
 
 static int
@@ -761,6 +1043,9 @@ main(void) {
     err |= testUnsupportedEncoding();
     err |= testNodeGetContent();
     err |= testCFileIO();
+#ifdef LIBXML_VALID_ENABLED
+    err |= testSwitchDtd();
+#endif
 #ifdef LIBXML_OUTPUT_ENABLED
     err |= testCtxtParseContent();
 #endif
@@ -770,6 +1055,7 @@ main(void) {
 #ifdef LIBXML_PUSH_ENABLED
     err |= testHugePush();
     err |= testHugeEncodedChunk();
+    err |= testPushCDataEnd();
 #endif
 #ifdef LIBXML_HTML_ENABLED
     err |= testHtmlIds();
@@ -780,6 +1066,7 @@ main(void) {
 #ifdef LIBXML_READER_ENABLED
     err |= testReaderEncoding();
     err |= testReaderContent();
+    err |= testReader();
 #ifdef LIBXML_XINCLUDE_ENABLED
     err |= testReaderXIncludeError();
 #endif
@@ -788,6 +1075,9 @@ main(void) {
     err |= testWriterClose();
 #endif
     err |= testBuildRelativeUri();
+#if defined(_WIN32) || defined(__CYGWIN__)
+    err |= testWindowsUri();
+#endif
     err |= testCharEncConvImpl();
 
     return err;
diff --git a/threads.c b/threads.c
index 4a087562..a8a07f61 100644
--- a/threads.c
+++ b/threads.c
@@ -159,6 +159,12 @@ xmlMutexUnlock(xmlMutexPtr tok)
 #endif
 }
 
+/**
+ * xmlInitRMutex:
+ * @tok:  mutex
+ *
+ * Initialize the mutex.
+ */
 void
 xmlInitRMutex(xmlRMutexPtr tok) {
     (void) tok;
@@ -195,6 +201,12 @@ xmlNewRMutex(void)
     return (tok);
 }
 
+/**
+ * xmlCleanupRMutex:
+ * @tok:  mutex
+ *
+ * Cleanup the mutex.
+ */
 void
 xmlCleanupRMutex(xmlRMutexPtr tok) {
     (void) tok;
diff --git a/tree.c b/tree.c
index 1b79b992..e9be7ebf 100644
--- a/tree.c
+++ b/tree.c
@@ -45,6 +45,8 @@
 #include "private/buf.h"
 #include "private/entities.h"
 #include "private/error.h"
+#include "private/memory.h"
+#include "private/parser.h"
 #include "private/tree.h"
 
 /*
@@ -3305,7 +3307,7 @@ xmlAddChildList(xmlNodePtr parent, xmlNodePtr cur) {
  *
  * If @cur is an attribute node, it is appended to the attributes of
  * @parent. If the attribute list contains an attribute with a name
- * matching @elem, the old attribute is destroyed.
+ * matching @cur, the old attribute is destroyed.
  *
  * General notes:
  *
@@ -3332,7 +3334,7 @@ xmlAddChildList(xmlNodePtr parent, xmlNodePtr cur) {
  *
  * Moving DTDs between documents isn't supported.
  *
- * Returns @elem or a sibling if @elem was merged. Returns NULL
+ * Returns @cur or a sibling if @cur was merged. Returns NULL
  * if arguments are invalid or a memory allocation failed.
  */
 xmlNodePtr
@@ -4679,7 +4681,7 @@ xmlGetLineNoInternal(const xmlNode *node, int depth)
 	(node->type == XML_PI_NODE)) {
 	if (node->line == 65535) {
 	    if ((node->type == XML_TEXT_NODE) && (node->psvi != NULL))
-	        result = (long) (ptrdiff_t) node->psvi;
+	        result = XML_PTR_TO_INT(node->psvi);
 	    else if ((node->type == XML_ELEMENT_NODE) &&
 	             (node->children != NULL))
 	        result = xmlGetLineNoInternal(node->children, depth + 1);
@@ -4689,7 +4691,7 @@ xmlGetLineNoInternal(const xmlNode *node, int depth)
 	        result = xmlGetLineNoInternal(node->prev, depth + 1);
 	}
 	if ((result == -1) || (result == 65535))
-	    result = (long) node->line;
+	    result = node->line;
     } else if ((node->prev != NULL) &&
              ((node->prev->type == XML_ELEMENT_NODE) ||
 	      (node->prev->type == XML_TEXT_NODE) ||
@@ -4732,8 +4734,8 @@ xmlChar *
 xmlGetNodePath(const xmlNode *node)
 {
     const xmlNode *cur, *tmp, *next;
-    xmlChar *buffer = NULL, *temp;
-    size_t buf_len;
+    xmlChar *buffer = NULL;
+    size_t buf_len, len;
     xmlChar *buf;
     const char *sep;
     const char *name;
@@ -4930,23 +4932,36 @@ xmlGetNodePath(const xmlNode *node)
         /*
          * Make sure there is enough room
          */
-        if (xmlStrlen(buffer) + sizeof(nametemp) + 20 > buf_len) {
-            buf_len =
-                2 * buf_len + xmlStrlen(buffer) + sizeof(nametemp) + 20;
-            temp = (xmlChar *) xmlRealloc(buffer, buf_len);
+        len = strlen((const char *) buffer);
+        if (buf_len - len < sizeof(nametemp) + 20) {
+            xmlChar *temp;
+            int newSize;
+
+            if ((buf_len > SIZE_MAX / 2) ||
+                (2 * buf_len > SIZE_MAX - len - sizeof(nametemp) - 20)) {
+                xmlFree(buf);
+                xmlFree(buffer);
+                return (NULL);
+            }
+            newSize = 2 * buf_len + len + sizeof(nametemp) + 20;
+
+            temp = xmlRealloc(buffer, newSize);
             if (temp == NULL) {
                 xmlFree(buf);
                 xmlFree(buffer);
                 return (NULL);
             }
             buffer = temp;
-            temp = (xmlChar *) xmlRealloc(buf, buf_len);
+
+            temp = xmlRealloc(buf, newSize);
             if (temp == NULL) {
                 xmlFree(buf);
                 xmlFree(buffer);
                 return (NULL);
             }
             buf = temp;
+
+            buf_len = newSize;
         }
         if (occur == 0)
             snprintf((char *) buf, buf_len, "%s%s%s",
@@ -5843,16 +5858,26 @@ xmlGetNsListSafe(const xmlDoc *doc ATTRIBUTE_UNUSED, const xmlNode *node,
                 if (i >= nbns) {
                     if (nbns >= maxns) {
                         xmlNsPtr *tmp;
+                        int newSize;
 
-                        maxns = maxns ? maxns * 2 : 10;
-                        tmp = (xmlNsPtr *) xmlRealloc(namespaces,
-                                                      (maxns + 1) *
-                                                      sizeof(xmlNsPtr));
+                        newSize = xmlGrowCapacity(maxns, sizeof(tmp[0]),
+                                                  10, XML_MAX_ITEMS);
+                        if (newSize < 0) {
+                            xmlFree(namespaces);
+                            return(-1);
+                        }
+#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
+                        if (newSize < 2)
+                            newSize = 2;
+#endif
+                        tmp = xmlRealloc(namespaces,
+                                         (newSize + 1) * sizeof(tmp[0]));
                         if (tmp == NULL) {
                             xmlFree(namespaces);
                             return(-1);
                         }
                         namespaces = tmp;
+                        maxns = newSize;
                     }
                     namespaces[nbns++] = cur;
                     namespaces[nbns] = NULL;
@@ -6273,6 +6298,24 @@ typedef struct {
     xmlNsPtr newNs;
 } xmlNsCache;
 
+static int
+xmlGrowNsCache(xmlNsCache **cache, int *capacity) {
+    xmlNsCache *tmp;
+    int newSize;
+
+    newSize = xmlGrowCapacity(*capacity, sizeof(tmp[0]),
+                              10, XML_MAX_ITEMS);
+    if (newSize < 0)
+        return(-1);
+    tmp = xmlRealloc(*cache, newSize * sizeof(tmp[0]));
+    if (tmp == NULL)
+        return(-1);
+    *cache = tmp;
+    *capacity = newSize;
+
+    return(0);
+}
+
 /**
  * xmlReconciliateNs:
  * @doc:  the document
@@ -6323,19 +6366,10 @@ xmlReconciliateNs(xmlDocPtr doc, xmlNodePtr tree) {
 		    /*
 		     * check if we need to grow the cache buffers.
 		     */
-		    if (sizeCache <= nbCache) {
-                        xmlNsCache *tmp;
-                        size_t newSize = sizeCache ? sizeCache * 2 : 10;
-
-			tmp = xmlRealloc(cache, newSize * sizeof(tmp[0]));
-		        if (tmp == NULL) {
-                            ret = -1;
-			} else {
-                            cache = tmp;
-                            sizeCache = newSize;
-                        }
-		    }
-		    if (nbCache < sizeCache) {
+		    if ((sizeCache <= nbCache) &&
+                        (xmlGrowNsCache(&cache, &sizeCache) < 0)) {
+                        ret = -1;
+		    } else {
                         cache[nbCache].newNs = n;
                         cache[nbCache++].oldNs = node->ns;
                     }
@@ -6367,21 +6401,10 @@ xmlReconciliateNs(xmlDocPtr doc, xmlNodePtr tree) {
 			    /*
 			     * check if we need to grow the cache buffers.
 			     */
-			    if (sizeCache <= nbCache) {
-                                xmlNsCache *tmp;
-                                size_t newSize = sizeCache ?
-                                        sizeCache * 2 : 10;
-
-                                tmp = xmlRealloc(cache,
-                                        newSize * sizeof(tmp[0]));
-                                if (tmp == NULL) {
-                                    ret = -1;
-                                } else {
-                                    cache = tmp;
-                                    sizeCache = newSize;
-                                }
-			    }
-			    if (nbCache < sizeCache) {
+                            if ((sizeCache <= nbCache) &&
+                                (xmlGrowNsCache(&cache, &sizeCache) < 0)) {
+                                ret = -1;
+                            } else {
                                 cache[nbCache].newNs = n;
                                 cache[nbCache++].oldNs = attr->ns;
 			    }
@@ -7388,9 +7411,11 @@ xmlDOMWrapNSNormAddNsMapItem2(xmlNsPtr **list, int *size, int *number,
 {
     if (*number >= *size) {
         xmlNsPtr *tmp;
-        size_t newSize;
+        int newSize;
 
-        newSize = *size ? *size * 2 : 3;
+        newSize = xmlGrowCapacity(*size, 2 * sizeof(tmp[0]), 3, XML_MAX_ITEMS);
+        if (newSize < 0)
+            return(-1);
         tmp = xmlRealloc(*list, newSize * 2 * sizeof(tmp[0]));
         if (tmp == NULL)
             return(-1);
@@ -8605,8 +8630,7 @@ xmlDOMWrapCloneNode(xmlDOMWrapCtxtPtr ctxt,
 		/*
 		* Attributes (xmlAttr).
 		*/
-                /* Use xmlRealloc to avoid -Warray-bounds warning */
-		clone = (xmlNodePtr) xmlRealloc(NULL, sizeof(xmlAttr));
+		clone = xmlMalloc(sizeof(xmlAttr));
 		if (clone == NULL)
 		    goto internal_error;
 		memset(clone, 0, sizeof(xmlAttr));
diff --git a/uri.c b/uri.c
index 94c831fb..a94acb4d 100644
--- a/uri.c
+++ b/uri.c
@@ -19,6 +19,7 @@
 #include <libxml/xmlerror.h>
 
 #include "private/error.h"
+#include "private/memory.h"
 
 /**
  * MAX_URI_LENGTH:
@@ -231,6 +232,15 @@ xmlParse3986Scheme(xmlURIPtr uri, const char **str) {
     if (!ISA_ALPHA(cur))
 	return(1);
     cur++;
+
+#if defined(_WIN32) || defined(__CYGWIN__)
+    /*
+     * Don't treat Windows drive letters as scheme.
+     */
+    if (*cur == ':')
+        return(1);
+#endif
+
     while (ISA_ALPHA(cur) || ISA_DIGIT(cur) ||
            (*cur == '+') || (*cur == '-') || (*cur == '.')) cur++;
     if (uri != NULL) {
@@ -582,11 +592,21 @@ xmlParse3986Segment(xmlURIPtr uri, const char **str, char forbid, int empty)
     const char *cur;
 
     cur = *str;
-    if (!ISA_PCHAR(uri, cur)) {
+    if (!ISA_PCHAR(uri, cur) || (*cur == forbid)) {
         if (empty)
 	    return(0);
 	return(1);
     }
+    NEXT(cur);
+
+#if defined(_WIN32) || defined(__CYGWIN__)
+    /*
+     * Allow Windows drive letters.
+     */
+    if ((forbid == ':') && (*cur == forbid))
+        NEXT(cur);
+#endif
+
     while (ISA_PCHAR(uri, cur) && (*cur != forbid))
         NEXT(cur);
     *str = cur;
@@ -1100,15 +1120,15 @@ xmlCreateURI(void) {
 static xmlChar *
 xmlSaveUriRealloc(xmlChar *ret, int *max) {
     xmlChar *temp;
-    int tmp;
+    int newSize;
 
-    if (*max > MAX_URI_LENGTH)
+    newSize = xmlGrowCapacity(*max, 1, 80, MAX_URI_LENGTH);
+    if (newSize < 0)
         return(NULL);
-    tmp = *max * 2;
-    temp = (xmlChar *) xmlRealloc(ret, (tmp + 1));
+    temp = xmlRealloc(ret, newSize + 1);
     if (temp == NULL)
         return(NULL);
-    *max = tmp;
+    *max = newSize;
     return(temp);
 }
 
@@ -1676,7 +1696,6 @@ xmlURIUnescapeString(const char *str, int len, char *target) {
 xmlChar *
 xmlURIEscapeStr(const xmlChar *str, const xmlChar *list) {
     xmlChar *ret, ch;
-    xmlChar *temp;
     const xmlChar *in;
     int len, out;
 
@@ -1694,15 +1713,21 @@ xmlURIEscapeStr(const xmlChar *str, const xmlChar *list) {
     out = 0;
     while(*in != 0) {
 	if (len - out <= 3) {
-            if (len > INT_MAX / 2)
+            xmlChar *temp;
+            int newSize;
+
+            newSize = xmlGrowCapacity(len, 1, 1, XML_MAX_ITEMS);
+            if (newSize < 0) {
+		xmlFree(ret);
                 return(NULL);
-            temp = xmlRealloc(ret, len * 2);
+            }
+            temp = xmlRealloc(ret, newSize);
 	    if (temp == NULL) {
 		xmlFree(ret);
 		return(NULL);
 	    }
 	    ret = temp;
-            len *= 2;
+            len = newSize;
 	}
 
 	ch = *in;
@@ -2064,6 +2089,23 @@ xmlBuildURISafe(const xmlChar *URI, const xmlChar *base, xmlChar **valPtr) {
         return(xmlResolvePath(URI, base, valPtr));
     }
 
+#if defined(_WIN32) || defined(__CYGWIN__)
+    /*
+     * Resolve paths with a Windows drive letter as filesystem path
+     * even if base has a scheme.
+     */
+    if ((ref != NULL) && (ref->path != NULL)) {
+        int c = ref->path[0];
+
+        if ((((c >= 'A') && (c <= 'Z')) ||
+             ((c >= 'a') && (c <= 'z'))) &&
+            (ref->path[1] == ':')) {
+            xmlFreeURI(ref);
+            return(xmlResolvePath(URI, base, valPtr));
+        }
+    }
+#endif
+
     ret = xmlParseURISafe((const char *) base, &bas);
     if (ret < 0)
         goto done;
diff --git a/valid.c b/valid.c
index ac985d02..a3a9e3a1 100644
--- a/valid.c
+++ b/valid.c
@@ -24,6 +24,7 @@
 #include <libxml/xmlsave.h>
 
 #include "private/error.h"
+#include "private/memory.h"
 #include "private/parser.h"
 #include "private/regexp.h"
 #include "private/save.h"
@@ -204,27 +205,23 @@ typedef struct _xmlValidState {
 
 static int
 vstateVPush(xmlValidCtxtPtr ctxt, xmlElementPtr elemDecl, xmlNodePtr node) {
-    if ((ctxt->vstateMax == 0) || (ctxt->vstateTab == NULL)) {
-	ctxt->vstateMax = 10;
-	ctxt->vstateTab = (xmlValidState *) xmlMalloc(ctxt->vstateMax *
-		              sizeof(ctxt->vstateTab[0]));
-        if (ctxt->vstateTab == NULL) {
-	    xmlVErrMemory(ctxt);
-	    return(-1);
-	}
-    }
-
     if (ctxt->vstateNr >= ctxt->vstateMax) {
         xmlValidState *tmp;
+        int newSize;
 
-	tmp = (xmlValidState *) xmlRealloc(ctxt->vstateTab,
-	             2 * ctxt->vstateMax * sizeof(ctxt->vstateTab[0]));
+        newSize = xmlGrowCapacity(ctxt->vstateMax, sizeof(tmp[0]),
+                                  10, XML_MAX_ITEMS);
+        if (newSize < 0) {
+	    xmlVErrMemory(ctxt);
+	    return(-1);
+	}
+	tmp = xmlRealloc(ctxt->vstateTab, newSize * sizeof(tmp[0]));
         if (tmp == NULL) {
 	    xmlVErrMemory(ctxt);
 	    return(-1);
 	}
-	ctxt->vstateMax *= 2;
 	ctxt->vstateTab = tmp;
+	ctxt->vstateMax = newSize;
     }
     ctxt->vstate = &ctxt->vstateTab[ctxt->vstateNr];
     ctxt->vstateTab[ctxt->vstateNr].elemDecl = elemDecl;
@@ -312,29 +309,20 @@ vstateVPush(xmlValidCtxtPtr ctxt, xmlElementContentPtr cont,
 	    unsigned char state) {
     int i = ctxt->vstateNr - 1;
 
-    if (ctxt->vstateNr > MAX_RECURSE) {
-	return(-1);
-    }
-    if (ctxt->vstateTab == NULL) {
-	ctxt->vstateMax = 8;
-	ctxt->vstateTab = (xmlValidState *) xmlMalloc(
-		     ctxt->vstateMax * sizeof(ctxt->vstateTab[0]));
-	if (ctxt->vstateTab == NULL) {
-	    xmlVErrMemory(ctxt);
-	    return(-1);
-	}
-    }
     if (ctxt->vstateNr >= ctxt->vstateMax) {
         xmlValidState *tmp;
+        int newSize;
 
-        tmp = (xmlValidState *) xmlRealloc(ctxt->vstateTab,
-	             2 * ctxt->vstateMax * sizeof(ctxt->vstateTab[0]));
+        newSize = xmlGrowCapacity(ctxt->vstateMax, sizeof(tmp[0]),
+                                  8, MAX_RECURSE);
+	    return(-1);
+        tmp = xmlRealloc(ctxt->vstateTab, newSize * sizeof(tmp[0]));
         if (tmp == NULL) {
 	    xmlVErrMemory(ctxt);
 	    return(-1);
 	}
-	ctxt->vstateMax *= 2;
 	ctxt->vstateTab = tmp;
+	ctxt->vstateMax = newSize;
 	ctxt->vstate = &ctxt->vstateTab[0];
     }
     /*
@@ -372,27 +360,23 @@ vstateVPop(xmlValidCtxtPtr ctxt) {
 static int
 nodeVPush(xmlValidCtxtPtr ctxt, xmlNodePtr value)
 {
-    if (ctxt->nodeMax <= 0) {
-        ctxt->nodeMax = 4;
-        ctxt->nodeTab =
-            (xmlNodePtr *) xmlMalloc(ctxt->nodeMax *
-                                     sizeof(ctxt->nodeTab[0]));
-        if (ctxt->nodeTab == NULL) {
-	    xmlVErrMemory(ctxt);
-            ctxt->nodeMax = 0;
-            return (0);
-        }
-    }
     if (ctxt->nodeNr >= ctxt->nodeMax) {
         xmlNodePtr *tmp;
-        tmp = (xmlNodePtr *) xmlRealloc(ctxt->nodeTab,
-			      ctxt->nodeMax * 2 * sizeof(ctxt->nodeTab[0]));
+        int newSize;
+
+        newSize = xmlGrowCapacity(ctxt->nodeMax, sizeof(tmp[0]),
+                                  4, XML_MAX_ITEMS);
+        if (newSize < 0) {
+	    xmlVErrMemory(ctxt);
+            return (-1);
+        }
+        tmp = xmlRealloc(ctxt->nodeTab, newSize * sizeof(tmp[0]));
         if (tmp == NULL) {
 	    xmlVErrMemory(ctxt);
-            return (0);
+            return (-1);
         }
-        ctxt->nodeMax *= 2;
 	ctxt->nodeTab = tmp;
+        ctxt->nodeMax = newSize;
     }
     ctxt->nodeTab[ctxt->nodeNr] = value;
     ctxt->node = value;
@@ -707,6 +691,8 @@ xmlFreeValidCtxt(xmlValidCtxtPtr cur) {
  * @name:  the subelement name or NULL
  * @type:  the type of element content decl
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Allocate an element content structure for the document.
  *
  * Returns NULL if not, otherwise the new element content structure
@@ -785,6 +771,8 @@ error:
  * @name:  the subelement name or NULL
  * @type:  the type of element content decl
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Allocate an element content structure.
  * Deprecated in favor of xmlNewDocElementContent
  *
@@ -800,6 +788,8 @@ xmlNewElementContent(const xmlChar *name, xmlElementContentType type) {
  * @doc:  the document owning the element declaration
  * @cur:  An element content pointer.
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Build a copy of an element content description.
  *
  * Returns the new xmlElementContentPtr or NULL in case of error.
@@ -893,6 +883,8 @@ error:
  * xmlCopyElementContent:
  * @cur:  An element content pointer.
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Build a copy of an element content description.
  * Deprecated, use xmlCopyDocElementContent instead
  *
@@ -908,6 +900,8 @@ xmlCopyElementContent(xmlElementContentPtr cur) {
  * @doc: the document owning the element declaration
  * @cur:  the element content tree to free
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Free an element content structure. The whole subtree is removed.
  */
 void
@@ -973,6 +967,8 @@ xmlFreeDocElementContent(xmlDocPtr doc, xmlElementContentPtr cur) {
  * xmlFreeElementContent:
  * @cur:  the element content tree to free
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Free an element content structure. The whole subtree is removed.
  * Deprecated, use xmlFreeDocElementContent instead
  */
@@ -988,6 +984,8 @@ xmlFreeElementContent(xmlElementContentPtr cur) {
  * @content:  An element table
  * @englob: 1 if one must print the englobing parenthesis, 0 otherwise
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Deprecated, unsafe, use xmlSnprintfElementContent
  */
 void
@@ -1004,6 +1002,8 @@ xmlSprintfElementContent(char *buf ATTRIBUTE_UNUSED,
  * @content:  An element table
  * @englob: 1 if one must print the englobing parenthesis, 0 otherwise
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * This will dump the content of the element content definition
  * Intended just for the debug routine
  */
@@ -1136,6 +1136,8 @@ xmlFreeElement(xmlElementPtr elem) {
  * @type:  the element type
  * @content:  the element content tree or NULL
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Register a new element declaration
  *
  * Returns NULL if not, otherwise the entity
@@ -1345,6 +1347,8 @@ xmlFreeElementTableEntry(void *elem, const xmlChar *name ATTRIBUTE_UNUSED) {
  * xmlFreeElementTable:
  * @table:  An element table
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Deallocate the memory used by an element hash table.
  */
 void
@@ -1399,6 +1403,8 @@ error:
  * xmlCopyElementTable:
  * @table:  An element table
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Build a copy of an element table.
  *
  * Returns the new xmlElementTablePtr or NULL in case of error.
@@ -1473,6 +1479,8 @@ xmlDumpElementTable(xmlBufferPtr buf, xmlElementTablePtr table) {
  * xmlCreateEnumeration:
  * @name:  the enumeration name or NULL
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * create and initialize an enumeration attribute node.
  *
  * Returns the xmlEnumerationPtr just created or NULL in case
@@ -1520,6 +1528,8 @@ xmlFreeEnumeration(xmlEnumerationPtr cur) {
  * xmlCopyEnumeration:
  * @cur:  the tree to copy.
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Copy an enumeration attribute node (recursive).
  *
  * Returns the xmlEnumerationPtr just created or NULL in case
@@ -1638,6 +1648,8 @@ xmlFreeAttribute(xmlAttributePtr attr) {
  * @defaultValue:  the attribute default value
  * @tree:  if it's an enumeration, the associated list
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Register a new attribute declaration
  * Note that @tree becomes the ownership of the DTD
  *
@@ -1880,6 +1892,8 @@ xmlFreeAttributeTableEntry(void *attr, const xmlChar *name ATTRIBUTE_UNUSED) {
  * xmlFreeAttributeTable:
  * @table:  An attribute table
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Deallocate the memory used by an entities hash table.
  */
 void
@@ -1943,6 +1957,8 @@ error:
  * xmlCopyAttributeTable:
  * @table:  An attribute table
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Build a copy of an attribute table.
  *
  * Returns the new xmlAttributeTablePtr or NULL in case of error.
@@ -2045,6 +2061,8 @@ xmlFreeNotation(xmlNotationPtr nota) {
  * @PublicID:  the public identifier or NULL
  * @SystemID:  the system identifier or NULL
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Register a new notation declaration
  *
  * Returns NULL if not, otherwise the entity
@@ -2136,6 +2154,8 @@ xmlFreeNotationTableEntry(void *nota, const xmlChar *name ATTRIBUTE_UNUSED) {
  * xmlFreeNotationTable:
  * @table:  An notation table
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Deallocate the memory used by an entities hash table.
  */
 void
@@ -2186,6 +2206,8 @@ error:
  * xmlCopyNotationTable:
  * @table:  A notation table
  *
+ * DEPRECATED: Internal function, don't use.
+ *
  * Build a copy of a notation table.
  *
  * Returns the new xmlNotationTablePtr or NULL in case of error.
@@ -5088,7 +5110,10 @@ xmlValidateElementContent(xmlValidCtxtPtr ctxt, xmlNodePtr child,
                      */
                     if ((cur->children != NULL) &&
                         (cur->children->children != NULL)) {
-                        nodeVPush(ctxt, cur);
+                        if (nodeVPush(ctxt, cur) < 0) {
+                            ret = -1;
+                            goto fail;
+                        }
                         cur = cur->children->children;
                         continue;
                     }
@@ -5192,7 +5217,11 @@ fail:
 		     */
 		    if ((cur->children != NULL) &&
 			(cur->children->children != NULL)) {
-			nodeVPush(ctxt, cur);
+			if (nodeVPush(ctxt, cur) < 0) {
+                            xmlFreeNodeList(repl);
+                            ret = -1;
+                            goto done;
+                        }
 			cur = cur->children->children;
 			continue;
 		    }
@@ -5200,9 +5229,8 @@ fail:
 		case XML_TEXT_NODE:
 		    if (xmlIsBlankNode(cur))
 			break;
-		    /* no break on purpose */
+		    /* falls through */
 		case XML_CDATA_SECTION_NODE:
-		    /* no break on purpose */
 		case XML_ELEMENT_NODE:
 		    /*
 		     * Allocate a new node and minimally fills in
@@ -5360,7 +5388,10 @@ xmlValidateOneCdataElement(xmlValidCtxtPtr ctxt, xmlDocPtr doc,
 		 */
 		if ((cur->children != NULL) &&
 		    (cur->children->children != NULL)) {
-		    nodeVPush(ctxt, cur);
+		    if (nodeVPush(ctxt, cur) < 0) {
+                        ret = 0;
+                        goto done;
+                    }
 		    cur = cur->children->children;
 		    continue;
 		}
@@ -5517,12 +5548,6 @@ xmlValidGetElemDecl(xmlValidCtxtPtr ctxt, xmlDocPtr doc,
 		*extsubset = 1;
 	}
     }
-    if (elemDecl == NULL) {
-	xmlErrValidNode(ctxt, elem,
-			XML_DTD_UNKNOWN_ELEM,
-	       "No declaration for element %s\n",
-	       elem->name, NULL, NULL);
-    }
     return(elemDecl);
 }
 
@@ -5565,10 +5590,6 @@ xmlValidatePushElement(xmlValidCtxtPtr ctxt, xmlDocPtr doc,
 		    ret = 0;
 		    break;
 		case XML_ELEMENT_TYPE_EMPTY:
-		    xmlErrValidNode(ctxt, state->node,
-				    XML_DTD_NOT_EMPTY,
-	       "Element %s was declared EMPTY this one has content\n",
-			   state->node->name, NULL, NULL);
 		    ret = 0;
 		    break;
 		case XML_ELEMENT_TYPE_ANY:
@@ -5579,20 +5600,10 @@ xmlValidatePushElement(xmlValidCtxtPtr ctxt, xmlDocPtr doc,
 		    if ((elemDecl->content != NULL) &&
 			(elemDecl->content->type ==
 			 XML_ELEMENT_CONTENT_PCDATA)) {
-			xmlErrValidNode(ctxt, state->node,
-					XML_DTD_NOT_PCDATA,
-	       "Element %s was declared #PCDATA but contains non text nodes\n",
-				state->node->name, NULL, NULL);
 			ret = 0;
 		    } else {
 			ret = xmlValidateCheckMixed(ctxt, elemDecl->content,
 				                    qname);
-			if (ret != 1) {
-			    xmlErrValidNode(ctxt, state->node,
-					    XML_DTD_INVALID_CHILD,
-	       "Element %s is not declared in %s list of possible children\n",
-				    qname, state->node->name, NULL);
-			}
 		    }
 		    break;
 		case XML_ELEMENT_TYPE_ELEMENT:
@@ -5609,10 +5620,6 @@ xmlValidatePushElement(xmlValidCtxtPtr ctxt, xmlDocPtr doc,
                             return(0);
                         }
 			if (ret < 0) {
-			    xmlErrValidNode(ctxt, state->node,
-					    XML_DTD_CONTENT_MODEL,
-	       "Element %s content does not follow the DTD, Misplaced %s\n",
-				   state->node->name, qname, NULL);
 			    ret = 0;
 			} else {
 			    ret = 1;
@@ -5662,10 +5669,6 @@ xmlValidatePushCData(xmlValidCtxtPtr ctxt, const xmlChar *data, int len) {
 		    ret = 0;
 		    break;
 		case XML_ELEMENT_TYPE_EMPTY:
-		    xmlErrValidNode(ctxt, state->node,
-				    XML_DTD_NOT_EMPTY,
-	       "Element %s was declared EMPTY this one has content\n",
-			   state->node->name, NULL, NULL);
 		    ret = 0;
 		    break;
 		case XML_ELEMENT_TYPE_ANY:
@@ -5738,11 +5741,6 @@ xmlValidatePopElement(xmlValidCtxtPtr ctxt, xmlDocPtr doc ATTRIBUTE_UNUSED,
 		    if (ret <= 0) {
                         if (ret == XML_REGEXP_OUT_OF_MEMORY)
                             xmlVErrMemory(ctxt);
-                        else
-			    xmlErrValidNode(ctxt, state->node,
-			                    XML_DTD_CONTENT_MODEL,
-	   "Element %s content does not follow the DTD, Expecting more children\n",
-			       state->node->name, NULL,NULL);
 			ret = 0;
 		    } else {
 			/*
@@ -5815,8 +5813,13 @@ xmlValidateOneElement(xmlValidCtxtPtr ctxt, xmlDocPtr doc,
      * Fetch the declaration
      */
     elemDecl = xmlValidGetElemDecl(ctxt, doc, elem, &extsubset);
-    if (elemDecl == NULL)
+    if (elemDecl == NULL) {
+	xmlErrValidNode(ctxt, elem,
+			XML_DTD_UNKNOWN_ELEM,
+	       "No declaration for element %s\n",
+	       elem->name, NULL, NULL);
 	return(0);
+    }
 
     /*
      * If vstateNr is not zero that means continuous validation is
@@ -6479,6 +6482,30 @@ xmlValidateDtd(xmlValidCtxtPtr ctxt, xmlDocPtr doc, xmlDtdPtr dtd) {
     return(ret);
 }
 
+/**
+ * xmlCtxtValidateDtd:
+ * @ctxt:  a parser context
+ * @doc:  a document instance
+ * @dtd:  a dtd instance
+ *
+ * Validate a document against a DTD.
+ *
+ * Like xmlValidateDtd but uses the parser context's error handler.
+ *
+ * Availabe since 2.14.0.
+ *
+ * Returns 1 if valid or 0 otherwise.
+ */
+int
+xmlCtxtValidateDtd(xmlParserCtxtPtr ctxt, xmlDocPtr doc, xmlDtdPtr dtd) {
+    if ((ctxt == NULL) || (ctxt->html))
+        return(0);
+
+    xmlCtxtReset(ctxt);
+
+    return(xmlValidateDtd(&ctxt->vctxt, doc, dtd));
+}
+
 static void
 xmlValidateNotationCallback(void *payload, void *data,
 	                    const xmlChar *name ATTRIBUTE_UNUSED) {
@@ -6639,56 +6666,75 @@ xmlValidateDtdFinal(xmlValidCtxtPtr ctxt, xmlDocPtr doc) {
 }
 
 /**
- * xmlValidateDocument:
- * @ctxt:  the validation context
- * @doc:  a document instance
+ * xmlValidateDocumentInternal:
+ * @ctxt:  parser context (optional)
+ * @vctxt:  validation context (optional)
+ * @doc:  document
  *
- * Try to validate the document instance
+ * Validate a document.
  *
- * basically it does the all the checks described by the XML Rec
- * i.e. validates the internal and external subset (if present)
- * and validate the document tree.
- *
- * returns 1 if valid or 0 otherwise
+ * Returns 1 if valid or 0 otherwise
  */
-
-int
-xmlValidateDocument(xmlValidCtxtPtr ctxt, xmlDocPtr doc) {
+static int
+xmlValidateDocumentInternal(xmlParserCtxtPtr ctxt, xmlValidCtxtPtr vctxt,
+                            xmlDocPtr doc) {
     int ret;
     xmlNodePtr root;
 
     if (doc == NULL)
         return(0);
     if ((doc->intSubset == NULL) && (doc->extSubset == NULL)) {
-        xmlErrValid(ctxt, XML_DTD_NO_DTD,
+        xmlErrValid(vctxt, XML_DTD_NO_DTD,
 	            "no DTD found!\n", NULL);
 	return(0);
     }
+
     if ((doc->intSubset != NULL) && ((doc->intSubset->SystemID != NULL) ||
 	(doc->intSubset->ExternalID != NULL)) && (doc->extSubset == NULL)) {
-	xmlChar *sysID;
+	xmlChar *sysID = NULL;
+
 	if (doc->intSubset->SystemID != NULL) {
-	    sysID = xmlBuildURI(doc->intSubset->SystemID,
-			doc->URL);
-	    if (sysID == NULL) {
-	        xmlErrValid(ctxt, XML_DTD_LOAD_ERROR,
+            int res;
+
+            res = xmlBuildURISafe(doc->intSubset->SystemID, doc->URL, &sysID);
+            if (res < 0) {
+                xmlVErrMemory(vctxt);
+                return 0;
+            } else if (res != 0) {
+                xmlErrValid(vctxt, XML_DTD_LOAD_ERROR,
 			"Could not build URI for external subset \"%s\"\n",
 			(const char *) doc->intSubset->SystemID);
 		return 0;
 	    }
-	} else
-	    sysID = NULL;
-        doc->extSubset = xmlParseDTD(doc->intSubset->ExternalID,
-			(const xmlChar *)sysID);
+	}
+
+        if (ctxt != NULL) {
+            xmlParserInputPtr input;
+
+            input = xmlLoadResource(ctxt, (const char *) sysID,
+                    (const char *) doc->intSubset->ExternalID,
+                    XML_RESOURCE_DTD);
+            if (input == NULL) {
+                xmlFree(sysID);
+                return 0;
+            }
+
+            doc->extSubset = xmlCtxtParseDtd(ctxt, input,
+                                             doc->intSubset->ExternalID,
+                                             sysID);
+        } else {
+            doc->extSubset = xmlParseDTD(doc->intSubset->ExternalID, sysID);
+        }
+
 	if (sysID != NULL)
 	    xmlFree(sysID);
         if (doc->extSubset == NULL) {
 	    if (doc->intSubset->SystemID != NULL) {
-		xmlErrValid(ctxt, XML_DTD_LOAD_ERROR,
+		xmlErrValid(vctxt, XML_DTD_LOAD_ERROR,
 		       "Could not load the external subset \"%s\"\n",
 		       (const char *) doc->intSubset->SystemID);
 	    } else {
-		xmlErrValid(ctxt, XML_DTD_LOAD_ERROR,
+		xmlErrValid(vctxt, XML_DTD_LOAD_ERROR,
 		       "Could not load the external subset \"%s\"\n",
 		       (const char *) doc->intSubset->ExternalID);
 	    }
@@ -6704,15 +6750,62 @@ xmlValidateDocument(xmlValidCtxtPtr ctxt, xmlDocPtr doc) {
           xmlFreeRefTable(doc->refs);
           doc->refs = NULL;
     }
-    ret = xmlValidateDtdFinal(ctxt, doc);
-    if (!xmlValidateRoot(ctxt, doc)) return(0);
+    ret = xmlValidateDtdFinal(vctxt, doc);
+    if (!xmlValidateRoot(vctxt, doc)) return(0);
 
     root = xmlDocGetRootElement(doc);
-    ret &= xmlValidateElement(ctxt, doc, root);
-    ret &= xmlValidateDocumentFinal(ctxt, doc);
+    ret &= xmlValidateElement(vctxt, doc, root);
+    ret &= xmlValidateDocumentFinal(vctxt, doc);
     return(ret);
 }
 
+/**
+ * xmlValidateDocument:
+ * @vctxt:  the validation context
+ * @doc:  a document instance
+ *
+ * DEPRECATED: This function can't report malloc or other failures.
+ * Use xmlCtxtValidateDocument.
+ *
+ * Try to validate the document instance
+ *
+ * basically it does the all the checks described by the XML Rec
+ * i.e. validates the internal and external subset (if present)
+ * and validate the document tree.
+ *
+ * returns 1 if valid or 0 otherwise
+ */
+int
+xmlValidateDocument(xmlValidCtxtPtr vctxt, xmlDocPtr doc) {
+    return(xmlValidateDocumentInternal(NULL, vctxt, doc));
+}
+
+/**
+ * xmlCtxtValidateDocument:
+ * @ctxt:  a parser context
+ * @doc:  a document instance
+ *
+ * Validate a document.
+ *
+ * Like xmlValidateDocument but uses the parser context's error handler.
+ *
+ * Option XML_PARSE_DTDLOAD should be enabled in the parser context
+ * to make external entities work.
+ *
+ * Availabe since 2.14.0.
+ *
+ * Returns 1 if valid or 0 otherwise.
+ */
+int
+xmlCtxtValidateDocument(xmlParserCtxtPtr ctxt, xmlDocPtr doc) {
+    if ((ctxt == NULL) || (ctxt->html))
+        return(0);
+
+    xmlCtxtReset(ctxt);
+
+    return(xmlValidateDocumentInternal(ctxt, &ctxt->vctxt, doc));
+}
+
 /************************************************************************
  *									*
  *		Routines for dynamic validation editing			*
diff --git a/win32/win32config.h b/win32/win32config.h
index edd87633..0a0ad3b1 100644
--- a/win32/win32config.h
+++ b/win32/win32config.h
@@ -14,5 +14,7 @@
   #endif
 #endif
 
+#define XML_SYSCONFDIR "/etc"
+
 #endif /* __LIBXML_WIN32_CONFIG__ */
 
diff --git a/xinclude.c b/xinclude.c
index d4a40712..0e9edd4a 100644
--- a/xinclude.c
+++ b/xinclude.c
@@ -28,6 +28,7 @@
 
 #include "private/buf.h"
 #include "private/error.h"
+#include "private/memory.h"
 #include "private/parser.h"
 #include "private/tree.h"
 #include "private/xinclude.h"
@@ -102,7 +103,9 @@ struct _xmlXIncludeCtxt {
     int			depth; /* recursion depth */
     int		     isStream; /* streaming mode */
 
+#ifdef LIBXML_XPTR_ENABLED
     xmlXPathContextPtr xpctxt;
+#endif
 
     xmlStructuredErrorFunc errorHandler;
     void *errorCtxt;
@@ -162,6 +165,11 @@ xmlXIncludeErr(xmlXIncludeCtxtPtr ctxt, xmlNodePtr node, int error,
     void *data = NULL;
     int res;
 
+    if (error == XML_ERR_NO_MEMORY) {
+        xmlXIncludeErrMemory(ctxt);
+        return;
+    }
+
     if (ctxt->fatalErr != 0)
         return;
     ctxt->nbErrors++;
@@ -183,6 +191,14 @@ xmlXIncludeErr(xmlXIncludeCtxtPtr ctxt, xmlNodePtr node, int error,
         ctxt->fatalErr = 1;
     } else {
         ctxt->errNo = error;
+        /*
+         * Note that we treat IO errors except ENOENT as fatal
+         * although the XInclude spec could be interpreted in a
+         * way that at least some IO errors should be handled
+         * gracefully.
+         */
+        if (xmlIsCatastrophicError(XML_ERR_FATAL, error))
+            ctxt->fatalErr = 1;
     }
 }
 
@@ -294,8 +310,10 @@ xmlXIncludeFreeContext(xmlXIncludeCtxtPtr ctxt) {
 	}
 	xmlFree(ctxt->txtTab);
     }
+#ifdef LIBXML_XPTR_ENABLED
     if (ctxt->xpctxt != NULL)
 	xmlXPathFreeContext(ctxt->xpctxt);
+#endif
     xmlFree(ctxt);
 }
 
@@ -351,7 +369,7 @@ xmlXIncludeParseFile(xmlXIncludeCtxtPtr ctxt, const char *URL) {
     if (inputStream == NULL)
         goto error;
 
-    if (inputPush(pctxt, inputStream) < 0) {
+    if (xmlCtxtPushInput(pctxt, inputStream) < 0) {
         xmlFreeInputStream(inputStream);
         goto error;
     }
@@ -369,8 +387,8 @@ xmlXIncludeParseFile(xmlXIncludeCtxtPtr ctxt, const char *URL) {
     }
 
 error:
-    if (pctxt->errNo == XML_ERR_NO_MEMORY)
-        xmlXIncludeErrMemory(ctxt);
+    if (xmlCtxtIsCatastrophicError(pctxt))
+        xmlXIncludeErr(ctxt, NULL, pctxt->errNo, "parser error", NULL);
     xmlFreeParserCtxt(pctxt);
 
     return(ret);
@@ -549,14 +567,15 @@ xmlXIncludeAddNode(xmlXIncludeCtxtPtr ctxt, xmlNodePtr cur) {
 
     if (ctxt->incNr >= ctxt->incMax) {
         xmlXIncludeRefPtr *table;
-#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
-        size_t newSize = ctxt->incMax ? ctxt->incMax * 2 : 1;
-#else
-        size_t newSize = ctxt->incMax ? ctxt->incMax * 2 : 4;
-#endif
+        int newSize;
 
-        table = (xmlXIncludeRefPtr *) xmlRealloc(ctxt->incTab,
-	             newSize * sizeof(ctxt->incTab[0]));
+        newSize = xmlGrowCapacity(ctxt->incMax, sizeof(table[0]),
+                                  4, XML_MAX_ITEMS);
+        if (newSize < 0) {
+	    xmlXIncludeErrMemory(ctxt);
+	    goto error;
+	}
+        table = xmlRealloc(ctxt->incTab, newSize * sizeof(table[0]));
         if (table == NULL) {
 	    xmlXIncludeErrMemory(ctxt);
 	    goto error;
@@ -1120,13 +1139,16 @@ xmlXIncludeLoadDoc(xmlXIncludeCtxtPtr ctxt, xmlXIncludeRefPtr ref) {
     /* Also cache NULL docs */
     if (ctxt->urlNr >= ctxt->urlMax) {
         xmlXIncludeDoc *tmp;
-#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
-        size_t newSize = ctxt->urlMax ? ctxt->urlMax * 2 : 1;
-#else
-        size_t newSize = ctxt->urlMax ? ctxt->urlMax * 2 : 8;
-#endif
+        int newSize;
 
-        tmp = xmlRealloc(ctxt->urlTab, sizeof(xmlXIncludeDoc) * newSize);
+        newSize = xmlGrowCapacity(ctxt->urlMax, sizeof(tmp[0]),
+                                  8, XML_MAX_ITEMS);
+        if (newSize < 0) {
+            xmlXIncludeErrMemory(ctxt);
+            xmlFreeDoc(doc);
+            goto error;
+        }
+        tmp = xmlRealloc(ctxt->urlTab, newSize * sizeof(tmp[0]));
         if (tmp == NULL) {
             xmlXIncludeErrMemory(ctxt);
             xmlFreeDoc(doc);
@@ -1313,9 +1335,10 @@ loaded:
         ref->inc = xmlXIncludeCopyXPointer(ctxt, xptr, ref->base);
         xmlXPathFreeObject(xptr);
     }
-#endif
 
 done:
+#endif
+
     ret = 0;
 
 error:
@@ -1471,13 +1494,15 @@ xmlXIncludeLoadTxt(xmlXIncludeCtxtPtr ctxt, xmlXIncludeRefPtr ref) {
 
     if (ctxt->txtNr >= ctxt->txtMax) {
         xmlXIncludeTxt *tmp;
-#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
-        size_t newSize = ctxt->txtMax ? ctxt->txtMax * 2 : 1;
-#else
-        size_t newSize = ctxt->txtMax ? ctxt->txtMax * 2 : 8;
-#endif
+        int newSize;
 
-        tmp = xmlRealloc(ctxt->txtTab, sizeof(xmlXIncludeTxt) * newSize);
+        newSize = xmlGrowCapacity(ctxt->txtMax, sizeof(tmp[0]),
+                                  8, XML_MAX_ITEMS);
+        if (newSize < 0) {
+            xmlXIncludeErrMemory(ctxt);
+	    goto error;
+        }
+        tmp = xmlRealloc(ctxt->txtTab, newSize * sizeof(tmp[0]));
         if (tmp == NULL) {
             xmlXIncludeErrMemory(ctxt);
 	    goto error;
diff --git a/xmlIO.c b/xmlIO.c
index 4f9b5142..cc861402 100644
--- a/xmlIO.c
+++ b/xmlIO.c
@@ -438,6 +438,10 @@ xmlConvertUriToPath(const char *uri, char **out) {
     return(0);
 }
 
+typedef struct {
+    int fd;
+} xmlFdIOCtxt;
+
 /**
  * xmlFdOpen:
  * @filename:  the URI for matching
@@ -517,7 +521,8 @@ xmlFdOpen(const char *filename, int write, int *out) {
  */
 static int
 xmlFdRead(void *context, char *buffer, int len) {
-    int fd = (int) (ptrdiff_t) context;
+    xmlFdIOCtxt *fdctxt = context;
+    int fd = fdctxt->fd;
     int ret = 0;
     int bytes;
 
@@ -555,7 +560,8 @@ xmlFdRead(void *context, char *buffer, int len) {
  */
 static int
 xmlFdWrite(void *context, const char *buffer, int len) {
-    int fd = (int) (ptrdiff_t) context;
+    xmlFdIOCtxt *fdctxt = context;
+    int fd = fdctxt->fd;
     int ret = 0;
     int bytes;
 
@@ -572,6 +578,12 @@ xmlFdWrite(void *context, const char *buffer, int len) {
 }
 #endif /* LIBXML_OUTPUT_ENABLED */
 
+static int
+xmlFdFree(void *context) {
+    xmlFree(context);
+    return(XML_ERR_OK);
+}
+
 /**
  * xmlFdClose:
  * @context:  the I/O context
@@ -582,9 +594,14 @@ xmlFdWrite(void *context, const char *buffer, int len) {
  */
 static int
 xmlFdClose (void * context) {
+    xmlFdIOCtxt *fdctxt = context;
+    int fd = fdctxt->fd;
     int ret;
 
-    ret = close((int) (ptrdiff_t) context);
+    ret = close(fd);
+
+    xmlFree(fdctxt);
+
     if (ret < 0)
         return(xmlIOErr(errno));
 
@@ -1020,55 +1037,37 @@ xmlIODefaultMatch(const char *filename ATTRIBUTE_UNUSED) {
     return(1);
 }
 
-/**
- * xmlInputDefaultOpen:
- * @buf:  input buffer to be filled
- * @filename:  filename or URI
- * @flags:  XML_INPUT flags
- *
- * Returns an xmlParserErrors code.
- */
-static int
-xmlInputDefaultOpen(xmlParserInputBufferPtr buf, const char *filename,
-                    int flags) {
-    int ret;
-    int fd;
+int
+xmlInputFromFd(xmlParserInputBufferPtr buf, int fd, int flags) {
+    xmlFdIOCtxt *fdctxt;
+    int copy;
 
-    /* Avoid unused variable warning */
     (void) flags;
 
-#ifdef LIBXML_HTTP_ENABLED
-    if (xmlIOHTTPMatch(filename)) {
-        if ((flags & XML_INPUT_NETWORK) == 0)
-            return(XML_IO_NETWORK_ATTEMPT);
-
-        buf->context = xmlIOHTTPOpen(filename);
-
-        if (buf->context != NULL) {
-            buf->readcallback = xmlIOHTTPRead;
-            buf->closecallback = xmlIOHTTPClose;
-            return(XML_ERR_OK);
-        }
-    }
-#endif /* LIBXML_HTTP_ENABLED */
-
-    if (!xmlFileMatch(filename))
-        return(XML_IO_ENOENT);
-
 #ifdef LIBXML_LZMA_ENABLED
     if (flags & XML_INPUT_UNZIP) {
         xzFile xzStream;
+        off_t pos;
 
-        ret = xmlFdOpen(filename, 0, &fd);
-        if (ret != XML_ERR_OK)
-            return(ret);
+        pos = lseek(fd, 0, SEEK_CUR);
+
+        copy = dup(fd);
+        if (copy == -1)
+            return(xmlIOErr(errno));
 
-        xzStream = __libxml2_xzdopen(filename, fd, "rb");
+        xzStream = __libxml2_xzdopen("?", copy, "rb");
 
         if (xzStream == NULL) {
-            close(fd);
+            close(copy);
         } else {
-            if (__libxml2_xzcompressed(xzStream) > 0) {
+            if ((__libxml2_xzcompressed(xzStream) > 0) ||
+                /* Try to rewind if not gzip compressed */
+                (pos < 0) ||
+                (lseek(fd, pos, SEEK_SET) < 0)) {
+                /*
+                 * If a file isn't seekable, we pipe uncompressed
+                 * input through xzlib.
+                 */
                 buf->context = xzStream;
                 buf->readcallback = xmlXzfileRead;
                 buf->closecallback = xmlXzfileClose;
@@ -1085,22 +1084,27 @@ xmlInputDefaultOpen(xmlParserInputBufferPtr buf, const char *filename,
 #ifdef LIBXML_ZLIB_ENABLED
     if (flags & XML_INPUT_UNZIP) {
         gzFile gzStream;
+        off_t pos;
 
-        ret = xmlFdOpen(filename, 0, &fd);
-        if (ret != XML_ERR_OK)
-            return(ret);
+        pos = lseek(fd, 0, SEEK_CUR);
 
-        gzStream = gzdopen(fd, "rb");
+        copy = dup(fd);
+        if (copy == -1)
+            return(xmlIOErr(errno));
+
+        gzStream = gzdopen(copy, "rb");
 
         if (gzStream == NULL) {
-            close(fd);
+            close(copy);
         } else {
-            char buff4[4];
-
-            if ((gzread(gzStream, buff4, 4) > 0) &&
-                (gzdirect(gzStream) == 0)) {
-                gzrewind(gzStream);
-
+            if ((gzdirect(gzStream) == 0) ||
+                /* Try to rewind if not gzip compressed */
+                (pos < 0) ||
+                (lseek(fd, pos, SEEK_SET) < 0)) {
+                /*
+                 * If a file isn't seekable, we pipe uncompressed
+                 * input through zlib.
+                 */
                 buf->context = gzStream;
                 buf->readcallback = xmlGzfileRead;
                 buf->closecallback = xmlGzfileClose;
@@ -1114,16 +1118,67 @@ xmlInputDefaultOpen(xmlParserInputBufferPtr buf, const char *filename,
     }
 #endif /* LIBXML_ZLIB_ENABLED */
 
-    ret = xmlFdOpen(filename, 0, &fd);
-    if (ret != XML_ERR_OK)
-        return(ret);
+    copy = dup(fd);
+    if (copy == -1)
+        return(xmlIOErr(errno));
 
-    buf->context = (void *) (ptrdiff_t) fd;
+    fdctxt = xmlMalloc(sizeof(*fdctxt));
+    if (fdctxt == NULL) {
+        close(copy);
+        return(XML_ERR_NO_MEMORY);
+    }
+    fdctxt->fd = copy;
+
+    buf->context = fdctxt;
     buf->readcallback = xmlFdRead;
     buf->closecallback = xmlFdClose;
+
     return(XML_ERR_OK);
 }
 
+/**
+ * xmlInputDefaultOpen:
+ * @buf:  input buffer to be filled
+ * @filename:  filename or URI
+ * @flags:  XML_INPUT flags
+ *
+ * Returns an xmlParserErrors code.
+ */
+static int
+xmlInputDefaultOpen(xmlParserInputBufferPtr buf, const char *filename,
+                    int flags) {
+    int ret;
+    int fd;
+
+#ifdef LIBXML_HTTP_ENABLED
+    if (xmlIOHTTPMatch(filename)) {
+        if ((flags & XML_INPUT_NETWORK) == 0)
+            return(XML_IO_NETWORK_ATTEMPT);
+
+        buf->context = xmlIOHTTPOpen(filename);
+
+        if (buf->context != NULL) {
+            buf->readcallback = xmlIOHTTPRead;
+            buf->closecallback = xmlIOHTTPClose;
+            return(XML_ERR_OK);
+        }
+    }
+#endif /* LIBXML_HTTP_ENABLED */
+
+    if (!xmlFileMatch(filename))
+        return(XML_IO_ENOENT);
+
+    ret = xmlFdOpen(filename, 0, &fd);
+    if (ret != XML_ERR_OK)
+        return(ret);
+
+    ret = xmlInputFromFd(buf, fd, flags);
+
+    close(fd);
+
+    return(ret);
+}
+
 #ifdef LIBXML_OUTPUT_ENABLED
 /**
  * xmlOutputDefaultOpen:
@@ -1137,6 +1192,7 @@ xmlInputDefaultOpen(xmlParserInputBufferPtr buf, const char *filename,
 static int
 xmlOutputDefaultOpen(xmlOutputBufferPtr buf, const char *filename,
                      int compression) {
+    xmlFdIOCtxt *fdctxt;
     int fd;
 
     (void) compression;
@@ -1175,7 +1231,14 @@ xmlOutputDefaultOpen(xmlOutputBufferPtr buf, const char *filename,
     }
 #endif /* LIBXML_ZLIB_ENABLED */
 
-    buf->context = (void *) (ptrdiff_t) fd;
+    fdctxt = xmlMalloc(sizeof(*fdctxt));
+    if (fdctxt == NULL) {
+        close(fd);
+        return(XML_ERR_NO_MEMORY);
+    }
+    fdctxt->fd = fd;
+
+    buf->context = fdctxt;
     buf->writecallback = xmlFdWrite;
     buf->closecallback = xmlFdClose;
     return(XML_ERR_OK);
@@ -1334,7 +1397,8 @@ xmlOutputBufferClose(xmlOutputBufferPtr out)
     if (out->closecallback != NULL) {
         int code = out->closecallback(out->context);
 
-        if ((code != XML_ERR_OK) && (out->error == XML_ERR_OK)) {
+        if ((code != XML_ERR_OK) &&
+            (!xmlIsCatastrophicError(XML_ERR_FATAL, out->error))) {
             if (code < 0)
                 out->error = XML_IO_UNKNOWN;
             else
@@ -1453,11 +1517,25 @@ __xmlParserInputBufferCreateFilename(const char *URI, xmlCharEncoding enc) {
 xmlParserInputBufferPtr
 xmlParserInputBufferCreateFilename(const char *URI, xmlCharEncoding enc) {
     xmlParserInputBufferPtr ret;
+    int code;
 
     if (xmlParserInputBufferCreateFilenameValue != NULL)
         return(xmlParserInputBufferCreateFilenameValue(URI, enc));
 
-    xmlParserInputBufferCreateUrl(URI, enc, 0, &ret);
+    code = xmlParserInputBufferCreateUrl(URI, enc, 0, &ret);
+
+    /*
+     * xmlParserInputBufferCreateFilename has no way to return
+     * the kind of error although it really is crucial.
+     * All we can do is to set the global error.
+     */
+    if ((code != XML_ERR_OK) && (code != XML_IO_ENOENT)) {
+        if (xmlRaiseError(NULL, NULL, NULL, NULL, NULL, XML_FROM_IO, code,
+                          XML_ERR_ERROR, URI, 0, NULL, NULL, NULL, 0, 0,
+                          "Failed to open file\n") < 0)
+            xmlRaiseMemoryError(NULL, NULL, NULL, XML_FROM_IO, NULL);
+    }
+
     return(ret);
 }
 
@@ -1466,7 +1544,7 @@ xmlOutputBufferPtr
 __xmlOutputBufferCreateFilename(const char *URI,
                               xmlCharEncodingHandlerPtr encoder,
                               int compression) {
-    xmlOutputBufferPtr ret;
+    xmlOutputBufferPtr ret = NULL;
     xmlURIPtr puri;
     int i = 0;
     char *unescaped = NULL;
@@ -1474,7 +1552,7 @@ __xmlOutputBufferCreateFilename(const char *URI,
     xmlInitParser();
 
     if (URI == NULL)
-        return(NULL);
+        goto error;
 
     puri = xmlParseURI(URI);
     if (puri != NULL) {
@@ -1485,8 +1563,7 @@ __xmlOutputBufferCreateFilename(const char *URI,
             unescaped = xmlURIUnescapeString(URI, 0, NULL);
             if (unescaped == NULL) {
                 xmlFreeURI(puri);
-                xmlCharEncCloseFunc(encoder);
-                return(NULL);
+                goto error;
             }
             URI = unescaped;
         }
@@ -1497,10 +1574,9 @@ __xmlOutputBufferCreateFilename(const char *URI,
      * Allocate the Output buffer front-end.
      */
     ret = xmlAllocOutputBuffer(encoder);
-    if (ret == NULL) {
-        xmlFree(unescaped);
-        return(NULL);
-    }
+    encoder = NULL;
+    if (ret == NULL)
+        goto error;
 
     /*
      * Try to find one of the output accept method accepting that scheme
@@ -1531,7 +1607,10 @@ __xmlOutputBufferCreateFilename(const char *URI,
 	ret = NULL;
     }
 
+error:
     xmlFree(unescaped);
+    if (encoder != NULL)
+        xmlCharEncCloseFunc(encoder);
     return(ret);
 }
 
@@ -1612,7 +1691,10 @@ xmlOutputBufferPtr
 xmlOutputBufferCreateFile(FILE *file, xmlCharEncodingHandlerPtr encoder) {
     xmlOutputBufferPtr ret;
 
-    if (file == NULL) return(NULL);
+    if (file == NULL) {
+        xmlCharEncCloseFunc(encoder);
+        return(NULL);
+    }
 
     ret = xmlAllocOutputBuffer(encoder);
     if (ret != NULL) {
@@ -1640,7 +1722,10 @@ xmlOutputBufferCreateBuffer(xmlBufferPtr buffer,
                             xmlCharEncodingHandlerPtr encoder) {
     xmlOutputBufferPtr ret;
 
-    if (buffer == NULL) return(NULL);
+    if (buffer == NULL) {
+        xmlCharEncCloseFunc(encoder);
+        return(NULL);
+    }
 
     ret = xmlOutputBufferCreateIO(xmlBufferWrite, NULL, (void *) buffer,
                                   encoder);
@@ -1707,8 +1792,17 @@ xmlParserInputBufferCreateFd(int fd, xmlCharEncoding enc) {
 
     ret = xmlAllocParserInputBuffer(enc);
     if (ret != NULL) {
-        ret->context = (void *) (ptrdiff_t) fd;
+        xmlFdIOCtxt *fdctxt;
+
+        fdctxt = xmlMalloc(sizeof(*fdctxt));
+        if (fdctxt == NULL) {
+            return(NULL);
+        }
+        fdctxt->fd = fd;
+
+        ret->context = fdctxt;
 	ret->readcallback = xmlFdRead;
+        ret->closecallback = xmlFdFree;
     }
 
     return(ret);
@@ -1905,13 +1999,24 @@ xmlOutputBufferPtr
 xmlOutputBufferCreateFd(int fd, xmlCharEncodingHandlerPtr encoder) {
     xmlOutputBufferPtr ret;
 
-    if (fd < 0) return(NULL);
+    if (fd < 0) {
+        xmlCharEncCloseFunc(encoder);
+        return(NULL);
+    }
 
     ret = xmlAllocOutputBuffer(encoder);
     if (ret != NULL) {
-        ret->context = (void *) (ptrdiff_t) fd;
+        xmlFdIOCtxt *fdctxt;
+
+        fdctxt = xmlMalloc(sizeof(*fdctxt));
+        if (fdctxt == NULL) {
+            return(NULL);
+        }
+        fdctxt->fd = fd;
+
+        ret->context = fdctxt;
 	ret->writecallback = xmlFdWrite;
-	ret->closecallback = NULL;
+        ret->closecallback = xmlFdFree;
     }
 
     return(ret);
diff --git a/xmlcatalog.c b/xmlcatalog.c
index a32f688e..8b37852f 100644
--- a/xmlcatalog.c
+++ b/xmlcatalog.c
@@ -50,7 +50,7 @@ static char *filename = NULL;
 
 
 #ifndef XML_SGML_DEFAULT_CATALOG
-#define XML_SGML_DEFAULT_CATALOG SYSCONFDIR "/sgml/catalog"
+#define XML_SGML_DEFAULT_CATALOG XML_SYSCONFDIR "/sgml/catalog"
 #endif
 
 /************************************************************************
diff --git a/xmllint.c b/xmllint.c
index 47eab392..d8dde636 100644
--- a/xmllint.c
+++ b/xmllint.c
@@ -12,13 +12,9 @@
 #include <stdarg.h>
 #include <stdio.h>
 #include <stdlib.h>
-#include <assert.h>
-#include <time.h>
 #include <errno.h>
 #include <limits.h>
-
 #include <fcntl.h>
-#include <sys/stat.h>
 
 #ifdef _WIN32
   #include <io.h>
@@ -30,6 +26,7 @@
 
 #if HAVE_DECL_MMAP
   #include <sys/mman.h>
+  #include <sys/stat.h>
   /* seems needed for Solaris */
   #ifndef MAP_FAILED
     #define MAP_FAILED ((void *) -1)
@@ -43,6 +40,7 @@
 #include <libxml/HTMLtree.h>
 #include <libxml/tree.h>
 #include <libxml/xpath.h>
+#include <libxml/xpathInternals.h>
 #include <libxml/debugXML.h>
 #include <libxml/xmlerror.h>
 #ifdef LIBXML_XINCLUDE_ENABLED
@@ -69,22 +67,28 @@
 #include <libxml/xmlsave.h>
 #endif
 
-#include "private/shell.h"
+#include "private/lint.h"
 
-#ifdef XMLLINT_FUZZ
-  #define ERR_STREAM stdout
-#else
-  #define ERR_STREAM stderr
+#ifndef STDIN_FILENO
+  #define STDIN_FILENO 0
 #endif
-
-#ifndef XML_XML_DEFAULT_CATALOG
-#define XML_XML_DEFAULT_CATALOG "file://" SYSCONFDIR "/xml/catalog"
+#ifndef STDOUT_FILENO
+  #define STDOUT_FILENO 1
 #endif
 
-#ifndef STDIN_FILENO
-  #define STDIN_FILENO 0
+#define MAX_PATHS 64
+
+#ifdef _WIN32
+  #define PATH_SEPARATOR ';'
+#else
+  #define PATH_SEPARATOR ':'
 #endif
 
+#define HTML_BUF_SIZE 50000
+
+/* Internal parser option */
+#define XML_PARSE_UNZIP     (1 << 24)
+
 typedef enum {
     XMLLINT_RETURN_OK = 0,	    /* No error */
     XMLLINT_ERR_UNCLASS = 1,	    /* Unclassified */
@@ -100,103 +104,133 @@ typedef enum {
     XMLLINT_ERR_XPATH_EMPTY = 11    /* XPath result is empty */
 } xmllintReturnCode;
 
-static int shell = 0;
+#ifdef _WIN32
+typedef __time64_t xmlSeconds;
+#else
+typedef time_t xmlSeconds;
+#endif
+
+typedef struct {
+   xmlSeconds sec;
+   int usec;
+} xmlTime;
+
+typedef struct {
+    FILE *errStream;
+    xmlParserCtxtPtr ctxt;
+    xmlResourceLoader defaultResourceLoader;
+
+    int version;
+    int maxmem;
+    int nowrap;
+    int sax;
+    int callbacks;
+    int shell;
 #ifdef LIBXML_DEBUG_ENABLED
-static int debugent = 0;
+    int debugent;
 #endif
-static int debug = 0;
-static int maxmem = 0;
-static int copy = 0;
-static int noout = 0;
+    int debug;
+    int copy;
+    int noout;
 #ifdef LIBXML_OUTPUT_ENABLED
-static const char *output = NULL;
-static int format = 0;
-static const char *encoding = NULL;
-static int compress = 0;
+    const char *output;
+    int format;
+    const char *encoding;
+    int compress;
 #endif /* LIBXML_OUTPUT_ENABLED */
 #ifdef LIBXML_VALID_ENABLED
-static int postvalid = 0;
-static const char *dtdvalid = NULL;
-static const char *dtdvalidfpi = NULL;
-static int insert = 0;
+    int postvalid;
+    const char *dtdvalid;
+    const char *dtdvalidfpi;
+    int insert;
 #endif
 #ifdef LIBXML_SCHEMAS_ENABLED
-static const char *relaxng = NULL;
-static xmlRelaxNGPtr relaxngschemas = NULL;
-static const char *schema = NULL;
-static xmlSchemaPtr wxschemas = NULL;
+    const char *relaxng;
+    xmlRelaxNGPtr relaxngschemas;
+    const char *schema;
+    xmlSchemaPtr wxschemas;
 #endif
 #ifdef LIBXML_SCHEMATRON_ENABLED
-static const char *schematron = NULL;
-static xmlSchematronPtr wxschematron = NULL;
+    const char *schematron;
+    xmlSchematronPtr wxschematron;
 #endif
-static int repeat = 0;
+    int repeat;
 #if defined(LIBXML_HTML_ENABLED)
-static int html = 0;
-static int xmlout = 0;
+    int html;
+    int xmlout;
 #endif
-static int htmlout = 0;
+    int htmlout;
 #ifdef LIBXML_PUSH_ENABLED
-static int push = 0;
-static const int pushsize = 4096;
+    int push;
 #endif /* LIBXML_PUSH_ENABLED */
 #if HAVE_DECL_MMAP
-static int memory = 0;
-static char *memoryData;
-static size_t memorySize;
+    int memory;
+    char *memoryData;
+    size_t memorySize;
 #endif
-static int testIO = 0;
+    int testIO;
 #ifdef LIBXML_XINCLUDE_ENABLED
-static int xinclude = 0;
+    int xinclude;
 #endif
-static xmllintReturnCode progresult = XMLLINT_RETURN_OK;
-static int quiet = 0;
-static int timing = 0;
-static int generate = 0;
-static int dropdtd = 0;
+    xmllintReturnCode progresult;
+    int quiet;
+    int timing;
+    int generate;
+    int dropdtd;
 #ifdef LIBXML_C14N_ENABLED
-static int canonical = 0;
-static int canonical_11 = 0;
-static int exc_canonical = 0;
+    int canonical;
+    int canonical_11;
+    int exc_canonical;
 #endif
 #ifdef LIBXML_READER_ENABLED
-static int walker = 0;
+    int stream;
+    int walker;
 #ifdef LIBXML_PATTERN_ENABLED
-static const char *pattern = NULL;
-static xmlPatternPtr patternc = NULL;
-static xmlStreamCtxtPtr patstream = NULL;
+    const char *pattern;
+    xmlPatternPtr patternc;
+    xmlStreamCtxtPtr patstream;
 #endif
 #endif /* LIBXML_READER_ENABLED */
 #ifdef LIBXML_XPATH_ENABLED
-static const char *xpathquery = NULL;
+    const char *xpathquery;
+#endif
+#ifdef LIBXML_CATALOG_ENABLED
+    int catalogs;
+    int nocatalogs;
 #endif
-static int options = XML_PARSE_COMPACT | XML_PARSE_BIG_LINES;
-static unsigned maxAmpl = 0;
+    int options;
+    unsigned maxAmpl;
+
+    xmlChar *paths[MAX_PATHS + 1];
+    int nbpaths;
+    int load_trace;
+
+    char *htmlBuf;
+    int htmlBufLen;
+
+    xmlTime begin, end;
+} xmllintState;
+
+static int xmllintMaxmem;
+static int xmllintMaxmemReached;
+static int xmllintOom;
 
 /************************************************************************
  *									*
  *		 Entity loading control and customization.		*
  *									*
  ************************************************************************/
-#define MAX_PATHS 64
-#ifdef _WIN32
-# define PATH_SEPARATOR ';'
-#else
-# define PATH_SEPARATOR ':'
-#endif
-static xmlChar *paths[MAX_PATHS + 1];
-static int nbpaths = 0;
-static int load_trace = 0;
 
-static
-void parsePath(const xmlChar *path) {
+static void
+parsePath(xmllintState *lint, const xmlChar *path) {
     const xmlChar *cur;
 
     if (path == NULL)
 	return;
     while (*path != 0) {
-	if (nbpaths >= MAX_PATHS) {
-	    fprintf(ERR_STREAM, "MAX_PATHS reached: too many paths\n");
+	if (lint->nbpaths >= MAX_PATHS) {
+	    fprintf(lint->errStream, "MAX_PATHS reached: too many paths\n");
+            lint->progresult = XMLLINT_ERR_UNCLASS;
 	    return;
 	}
 	cur = path;
@@ -206,26 +240,25 @@ void parsePath(const xmlChar *path) {
 	while ((*cur != 0) && (*cur != ' ') && (*cur != PATH_SEPARATOR))
 	    cur++;
 	if (cur != path) {
-	    paths[nbpaths] = xmlStrndup(path, cur - path);
-	    if (paths[nbpaths] != NULL)
-		nbpaths++;
+	    lint->paths[lint->nbpaths] = xmlStrndup(path, cur - path);
+	    if (lint->paths[lint->nbpaths] != NULL)
+		lint->nbpaths++;
 	    path = cur;
 	}
     }
 }
 
-static xmlResourceLoader defaultResourceLoader = NULL;
-
 static int
-xmllintResourceLoader(void *ctxt ATTRIBUTE_UNUSED, const char *URL,
+xmllintResourceLoader(void *ctxt, const char *URL,
                       const char *ID, xmlResourceType type, int flags,
 		      xmlParserInputPtr *out) {
+    xmllintState *lint = ctxt;
     int code;
     int i;
     const char *lastsegment = URL;
     const char *iter = URL;
 
-    if ((nbpaths > 0) && (iter != NULL)) {
+    if ((lint->nbpaths > 0) && (iter != NULL)) {
 	while (*iter != 0) {
 	    if (*iter == '/')
 		lastsegment = iter + 1;
@@ -233,33 +266,33 @@ xmllintResourceLoader(void *ctxt ATTRIBUTE_UNUSED, const char *URL,
 	}
     }
 
-    if (defaultResourceLoader != NULL)
-        code = defaultResourceLoader(NULL, URL, ID, type, flags, out);
+    if (lint->defaultResourceLoader != NULL)
+        code = lint->defaultResourceLoader(NULL, URL, ID, type, flags, out);
     else
         code = xmlNewInputFromUrl(URL, flags, out);
     if (code != XML_IO_ENOENT) {
-        if ((load_trace) && (code == XML_ERR_OK)) {
-            fprintf(ERR_STREAM, "Loaded URL=\"%s\" ID=\"%s\"\n",
+        if ((lint->load_trace) && (code == XML_ERR_OK)) {
+            fprintf(lint->errStream, "Loaded URL=\"%s\" ID=\"%s\"\n",
                     URL, ID ? ID : "(null)");
         }
         return(code);
     }
 
-    for (i = 0; i < nbpaths; i++) {
+    for (i = 0; i < lint->nbpaths; i++) {
 	xmlChar *newURL;
 
-	newURL = xmlStrdup((const xmlChar *) paths[i]);
+	newURL = xmlStrdup((const xmlChar *) lint->paths[i]);
 	newURL = xmlStrcat(newURL, (const xmlChar *) "/");
 	newURL = xmlStrcat(newURL, (const xmlChar *) lastsegment);
 	if (newURL != NULL) {
-            if (defaultResourceLoader != NULL)
-                code = defaultResourceLoader(NULL, (const char *) newURL, ID,
-                                             type, flags, out);
+            if (lint->defaultResourceLoader != NULL)
+                code = lint->defaultResourceLoader(NULL, (const char *) newURL,
+                                                   ID, type, flags, out);
             else
                 code = xmlNewInputFromUrl((const char *) newURL, flags, out);
             if (code != XML_IO_ENOENT) {
-                if ((load_trace) && (code == XML_ERR_OK)) {
-                    fprintf(ERR_STREAM, "Loaded URL=\"%s\" ID=\"%s\"\n",
+                if ((lint->load_trace) && (code == XML_ERR_OK)) {
+                    fprintf(lint->errStream, "Loaded URL=\"%s\" ID=\"%s\"\n",
                             newURL, ID ? ID : "(null)");
                 }
 	        xmlFree(newURL);
@@ -292,22 +325,60 @@ myClose(void *context) {
 }
 
 static xmlDocPtr
-parseXml(xmlParserCtxtPtr ctxt, const char *filename) {
+parseXml(xmllintState *lint, const char *filename) {
+    xmlParserCtxtPtr ctxt = lint->ctxt;
     xmlDocPtr doc;
 
-    xmlCtxtSetResourceLoader(ctxt, xmllintResourceLoader, NULL);
-    if (maxAmpl > 0)
-        xmlCtxtSetMaxAmplification(ctxt, maxAmpl);
+#ifdef LIBXML_PUSH_ENABLED
+    if (lint->push) {
+        FILE *f;
+        int res;
+        char chars[4096];
+
+        if ((filename[0] == '-') && (filename[1] == 0)) {
+            f = stdin;
+        } else {
+            f = fopen(filename, "rb");
+            if (f == NULL) {
+                fprintf(lint->errStream, "Can't open %s\n", filename);
+                lint->progresult = XMLLINT_ERR_RDFILE;
+                return(NULL);
+            }
+        }
+
+        while ((res = fread(chars, 1, 4096, f)) > 0) {
+            xmlParseChunk(ctxt, chars, res, 0);
+        }
+        xmlParseChunk(ctxt, chars, 0, 1);
+
+        doc = ctxt->myDoc;
+        ctxt->myDoc = NULL;
+        if (f != stdin)
+            fclose(f);
+
+        /*
+         * The push parser leaves non-wellformed documents
+         * in ctxt->myDoc.
+         */
+        if (!ctxt->wellFormed) {
+            xmlFreeDoc(doc);
+            doc = NULL;
+        }
+
+        return(doc);
+    }
+#endif /* LIBXML_PUSH_ENABLED */
 
 #if HAVE_DECL_MMAP
-    if (memory) {
+    if (lint->memory) {
         xmlParserInputPtr input;
 
-        input = xmlNewInputFromMemory(filename, memoryData, memorySize,
+        input = xmlNewInputFromMemory(filename,
+                                      lint->memoryData, lint->memorySize,
                                       XML_INPUT_BUF_STATIC |
                                       XML_INPUT_BUF_ZERO_TERMINATED);
         if (input == NULL) {
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             return(NULL);
         }
         doc = xmlCtxtParseDocument(ctxt, input);
@@ -315,7 +386,7 @@ parseXml(xmlParserCtxtPtr ctxt, const char *filename) {
     }
 #endif
 
-    if (testIO) {
+    if (lint->testIO) {
         FILE *f;
 
         if ((filename[0] == '-') && (filename[1] == 0)) {
@@ -323,19 +394,21 @@ parseXml(xmlParserCtxtPtr ctxt, const char *filename) {
         } else {
             f = fopen(filename, "rb");
             if (f == NULL) {
-                fprintf(ERR_STREAM, "Can't open %s\n", filename);
-                progresult = XMLLINT_ERR_RDFILE;
+                fprintf(lint->errStream, "Can't open %s\n", filename);
+                lint->progresult = XMLLINT_ERR_RDFILE;
                 return(NULL);
             }
         }
 
         doc = xmlCtxtReadIO(ctxt, myRead, myClose, f, filename, NULL,
-                            options);
+                            lint->options);
     } else {
         if (strcmp(filename, "-") == 0)
-            doc = xmlCtxtReadFd(ctxt, STDIN_FILENO, "-", NULL, options);
+            doc = xmlCtxtReadFd(ctxt, STDIN_FILENO, "-", NULL,
+                                lint->options | XML_PARSE_UNZIP);
         else
-            doc = xmlCtxtReadFile(ctxt, filename, NULL, options);
+            doc = xmlCtxtReadFile(ctxt, filename, NULL,
+                                  lint->options | XML_PARSE_UNZIP);
     }
 
     return(doc);
@@ -343,18 +416,50 @@ parseXml(xmlParserCtxtPtr ctxt, const char *filename) {
 
 #ifdef LIBXML_HTML_ENABLED
 static xmlDocPtr
-parseHtml(htmlParserCtxtPtr ctxt, const char *filename) {
+parseHtml(xmllintState *lint, const char *filename) {
+    xmlParserCtxtPtr ctxt = lint->ctxt;
     xmlDocPtr doc;
 
+#ifdef LIBXML_PUSH_ENABLED
+    if (lint->push) {
+        FILE *f;
+        int res;
+        char chars[4096];
+
+        if ((filename[0] == '-') && (filename[1] == 0)) {
+            f = stdin;
+        } else {
+	    f = fopen(filename, "rb");
+            if (f == NULL) {
+                fprintf(lint->errStream, "Can't open %s\n", filename);
+                lint->progresult = XMLLINT_ERR_RDFILE;
+                return(NULL);
+            }
+        }
+
+        while ((res = fread(chars, 1, 4096, f)) > 0) {
+            htmlParseChunk(ctxt, chars, res, 0);
+        }
+        htmlParseChunk(ctxt, chars, 0, 1);
+        doc = ctxt->myDoc;
+        ctxt->myDoc = NULL;
+        if (f != stdin)
+            fclose(f);
+
+        return(doc);
+    }
+#endif /* LIBXML_PUSH_ENABLED */
+
 #if HAVE_DECL_MMAP
-    if (memory) {
+    if (lint->memory) {
         xmlParserInputPtr input;
 
-        input = xmlNewInputFromMemory(filename, memoryData, memorySize,
+        input = xmlNewInputFromMemory(filename,
+                                      lint->memoryData, lint->memorySize,
                                       XML_INPUT_BUF_STATIC |
                                       XML_INPUT_BUF_ZERO_TERMINATED);
         if (input == NULL) {
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             return(NULL);
         }
         doc = htmlCtxtParseDocument(ctxt, input);
@@ -363,9 +468,10 @@ parseHtml(htmlParserCtxtPtr ctxt, const char *filename) {
 #endif
 
     if (strcmp(filename, "-") == 0)
-        doc = htmlCtxtReadFd(ctxt, STDIN_FILENO, "-", NULL, options);
+        doc = htmlCtxtReadFd(ctxt, STDIN_FILENO, "-", NULL,
+                             lint->options);
     else
-        doc = htmlCtxtReadFile(ctxt, filename, NULL, options);
+        doc = htmlCtxtReadFile(ctxt, filename, NULL, lint->options);
 
     return(doc);
 }
@@ -377,60 +483,83 @@ parseHtml(htmlParserCtxtPtr ctxt, const char *filename) {
  *									*
  ************************************************************************/
 
-static void
-OOM(void)
-{
-    fprintf(ERR_STREAM, "Ran out of memory needs > %d bytes\n", maxmem);
-    progresult = XMLLINT_ERR_MEM;
-}
+#define XMLLINT_ABORT_ON_FAILURE 0
 
 static void
-myFreeFunc(void *mem)
-{
+myFreeFunc(void *mem) {
     xmlMemFree(mem);
 }
+
 static void *
-myMallocFunc(size_t size)
-{
+myMallocFunc(size_t size) {
     void *ret;
 
-    ret = xmlMemMalloc(size);
-    if (ret != NULL) {
-        if (xmlMemUsed() > maxmem) {
-            OOM();
-            xmlMemFree(ret);
-            return (NULL);
-        }
+    if (xmlMemUsed() + size > (size_t) xmllintMaxmem) {
+#if XMLLINT_ABORT_ON_FAILURE
+        abort();
+#endif
+        xmllintMaxmemReached = 1;
+        xmllintOom = 1;
+        return(NULL);
     }
-    return (ret);
+
+    ret = xmlMemMalloc(size);
+    if (ret == NULL)
+        xmllintOom = 1;
+
+    return(ret);
 }
+
 static void *
-myReallocFunc(void *mem, size_t size)
-{
+myReallocFunc(void *mem, size_t size) {
+    void *ret;
     size_t oldsize = xmlMemSize(mem);
 
-    if (xmlMemUsed() + size - oldsize > (size_t) maxmem) {
-        OOM();
-        return (NULL);
+    if (xmlMemUsed() + size - oldsize > (size_t) xmllintMaxmem) {
+#if XMLLINT_ABORT_ON_FAILURE
+        abort();
+#endif
+        xmllintMaxmemReached = 1;
+        xmllintOom = 1;
+        return(NULL);
     }
 
-    return (xmlMemRealloc(mem, size));
+    ret = xmlMemRealloc(mem, size);
+    if (ret == NULL)
+        xmllintOom = 1;
+
+    return(ret);
 }
+
 static char *
-myStrdupFunc(const char *str)
-{
+myStrdupFunc(const char *str) {
+    size_t size;
     char *ret;
 
-    ret = xmlMemoryStrdup(str);
-    if (ret != NULL) {
-        if (xmlMemUsed() > maxmem) {
-            OOM();
-            xmlMemFree(ret);
-            return (NULL);
-        }
+    if (str == NULL)
+        return(NULL);
+
+    size = strlen(str) + 1;
+    if (xmlMemUsed() + size > (size_t) xmllintMaxmem) {
+#if XMLLINT_ABORT_ON_FAILURE
+        abort();
+#endif
+        xmllintMaxmemReached = 1;
+        xmllintOom = 1;
+        return(NULL);
+    }
+
+    ret = xmlMemMalloc(size);
+    if (ret == NULL) {
+        xmllintOom = 1;
+        return(NULL);
     }
-    return (ret);
+
+    memcpy(ret, str, size);
+
+    return(ret);
 }
+
 /************************************************************************
  *									*
  * Internal timing routines to remove the necessity to have		*
@@ -438,19 +567,6 @@ myStrdupFunc(const char *str)
  *									*
  ************************************************************************/
 
-#ifdef _WIN32
-typedef __time64_t xmlSeconds;
-#else
-typedef time_t xmlSeconds;
-#endif
-
-typedef struct {
-   xmlSeconds sec;
-   int usec;
-} xmlTime;
-
-static xmlTime begin, end;
-
 static void
 getTime(xmlTime *time) {
 #ifdef _WIN32
@@ -472,9 +588,9 @@ getTime(xmlTime *time) {
  * startTimer: call where you want to start timing
  */
 static void
-startTimer(void)
+startTimer(xmllintState *lint)
 {
-    getTime(&begin);
+    getTime(&lint->begin);
 }
 
 /*
@@ -482,22 +598,22 @@ startTimer(void)
  *           message about the timing performed; format is a printf
  *           type argument
  */
-static void LIBXML_ATTR_FORMAT(1,2)
-endTimer(const char *fmt, ...)
+static void LIBXML_ATTR_FORMAT(2,3)
+endTimer(xmllintState *lint, const char *fmt, ...)
 {
     xmlSeconds msec;
     va_list ap;
 
-    getTime(&end);
-    msec = end.sec - begin.sec;
+    getTime(&lint->end);
+    msec = lint->end.sec - lint->begin.sec;
     msec *= 1000;
-    msec += (end.usec - begin.usec) / 1000;
+    msec += (lint->end.usec - lint->begin.usec) / 1000;
 
     va_start(ap, fmt);
-    vfprintf(ERR_STREAM, fmt, ap);
+    vfprintf(lint->errStream, fmt, ap);
     va_end(ap);
 
-    fprintf(ERR_STREAM, " took %ld ms\n", (long) msec);
+    fprintf(lint->errStream, " took %ld ms\n", (long) msec);
 }
 
 /************************************************************************
@@ -505,11 +621,9 @@ endTimer(const char *fmt, ...)
  *			HTML output					*
  *									*
  ************************************************************************/
-static char buffer[50000];
-static int htmlBufLen;
 
 static void
-xmlHTMLEncodeSend(void) {
+xmlHTMLEncodeSend(xmllintState *lint) {
     char *result;
 
     /*
@@ -517,30 +631,32 @@ xmlHTMLEncodeSend(void) {
      * end with a truncated UTF-8 sequence. This is a hack to at least avoid
      * an out-of-bounds read.
      */
-    memset(&buffer[sizeof(buffer)-4], 0, 4);
-    result = (char *) xmlEncodeEntitiesReentrant(NULL, BAD_CAST buffer);
+    memset(&lint->htmlBuf[HTML_BUF_SIZE - 4], 0, 4);
+    result = (char *) xmlEncodeEntitiesReentrant(NULL, BAD_CAST lint->htmlBuf);
     if (result) {
-	fprintf(ERR_STREAM, "%s", result);
+	fprintf(lint->errStream, "%s", result);
 	xmlFree(result);
     }
 
-    htmlBufLen = 0;
+    lint->htmlBufLen = 0;
 }
 
 static void
-xmlHTMLBufCat(void *data ATTRIBUTE_UNUSED, const char *fmt, ...) {
+xmlHTMLBufCat(void *data, const char *fmt, ...) {
+    xmllintState *lint = data;
     va_list ap;
     int res;
 
     va_start(ap, fmt);
-    res = vsnprintf(&buffer[htmlBufLen], sizeof(buffer) - htmlBufLen, fmt, ap);
+    res = vsnprintf(&lint->htmlBuf[lint->htmlBufLen],
+                    HTML_BUF_SIZE - lint->htmlBufLen, fmt, ap);
     va_end(ap);
 
     if (res > 0) {
-        if ((size_t) res > sizeof(buffer) - htmlBufLen - 1)
-            htmlBufLen = sizeof(buffer) - 1;
+        if (res > HTML_BUF_SIZE - lint->htmlBufLen - 1)
+            lint->htmlBufLen = HTML_BUF_SIZE - 1;
         else
-            htmlBufLen += res;
+            lint->htmlBufLen += res;
     }
 }
 
@@ -556,7 +672,8 @@ xmlHTMLBufCat(void *data ATTRIBUTE_UNUSED, const char *fmt, ...) {
 static void
 xmlHTMLError(void *vctxt, const xmlError *error)
 {
-    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) vctxt;
+    xmlParserCtxtPtr ctxt = vctxt;
+    xmllintState *lint = ctxt->_private;
     xmlParserInputPtr input;
     xmlGenericErrorFunc oldError;
     void *oldErrorCtxt;
@@ -568,30 +685,30 @@ xmlHTMLError(void *vctxt, const xmlError *error)
 
     oldError = xmlGenericError;
     oldErrorCtxt = xmlGenericErrorContext;
-    xmlSetGenericErrorFunc(NULL, xmlHTMLBufCat);
+    xmlSetGenericErrorFunc(lint, xmlHTMLBufCat);
 
-    fprintf(ERR_STREAM, "<p>");
+    fprintf(lint->errStream, "<p>");
 
     xmlParserPrintFileInfo(input);
-    xmlHTMLEncodeSend();
+    xmlHTMLEncodeSend(lint);
 
-    fprintf(ERR_STREAM, "<b>%s%s</b>: ",
+    fprintf(lint->errStream, "<b>%s%s</b>: ",
             (error->domain == XML_FROM_VALID) ||
             (error->domain == XML_FROM_DTD) ? "validity " : "",
             error->level == XML_ERR_WARNING ? "warning" : "error");
 
-    snprintf(buffer, sizeof(buffer), "%s", error->message);
-    xmlHTMLEncodeSend();
+    snprintf(lint->htmlBuf, HTML_BUF_SIZE, "%s", error->message);
+    xmlHTMLEncodeSend(lint);
 
-    fprintf(ERR_STREAM, "</p>\n");
+    fprintf(lint->errStream, "</p>\n");
 
     if (input != NULL) {
-        fprintf(ERR_STREAM, "<pre>\n");
+        fprintf(lint->errStream, "<pre>\n");
 
         xmlParserPrintFileContext(input);
-        xmlHTMLEncodeSend();
+        xmlHTMLEncodeSend(lint);
 
-        fprintf(ERR_STREAM, "</pre>");
+        fprintf(lint->errStream, "</pre>");
     }
 
     xmlSetGenericErrorFunc(oldErrorCtxt, oldError);
@@ -606,7 +723,7 @@ xmlHTMLError(void *vctxt, const xmlError *error)
 /*
  * empty SAX block
  */
-static xmlSAXHandler emptySAXHandlerStruct = {
+static const xmlSAXHandler emptySAXHandler = {
     NULL, /* internalSubset */
     NULL, /* isStandalone */
     NULL, /* hasInternalSubset */
@@ -641,10 +758,6 @@ static xmlSAXHandler emptySAXHandlerStruct = {
     NULL  /* xmlStructuredErrorFunc */
 };
 
-static xmlSAXHandlerPtr emptySAXHandler = &emptySAXHandlerStruct;
-extern xmlSAXHandlerPtr debugSAXHandler;
-static int callbacks;
-
 /**
  * isStandaloneDebug:
  * @ctxt:  An XML parser context
@@ -654,10 +767,12 @@ static int callbacks;
  * Returns 1 if true
  */
 static int
-isStandaloneDebug(void *ctx ATTRIBUTE_UNUSED)
+isStandaloneDebug(void *ctx)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return(0);
     fprintf(stdout, "SAX.isStandalone()\n");
     return(0);
@@ -672,10 +787,12 @@ isStandaloneDebug(void *ctx ATTRIBUTE_UNUSED)
  * Returns 1 if true
  */
 static int
-hasInternalSubsetDebug(void *ctx ATTRIBUTE_UNUSED)
+hasInternalSubsetDebug(void *ctx)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return(0);
     fprintf(stdout, "SAX.hasInternalSubset()\n");
     return(0);
@@ -690,10 +807,12 @@ hasInternalSubsetDebug(void *ctx ATTRIBUTE_UNUSED)
  * Returns 1 if true
  */
 static int
-hasExternalSubsetDebug(void *ctx ATTRIBUTE_UNUSED)
+hasExternalSubsetDebug(void *ctx)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return(0);
     fprintf(stdout, "SAX.hasExternalSubset()\n");
     return(0);
@@ -706,11 +825,13 @@ hasExternalSubsetDebug(void *ctx ATTRIBUTE_UNUSED)
  * Does this document has an internal subset
  */
 static void
-internalSubsetDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name,
+internalSubsetDebug(void *ctx, const xmlChar *name,
 	       const xmlChar *ExternalID, const xmlChar *SystemID)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.internalSubset(%s,", name);
     if (ExternalID == NULL)
@@ -730,11 +851,13 @@ internalSubsetDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name,
  * Does this document has an external subset
  */
 static void
-externalSubsetDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name,
+externalSubsetDebug(void *ctx, const xmlChar *name,
 	       const xmlChar *ExternalID, const xmlChar *SystemID)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.externalSubset(%s,", name);
     if (ExternalID == NULL)
@@ -762,10 +885,12 @@ externalSubsetDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name,
  * Returns the xmlParserInputPtr if inlined or NULL for DOM behaviour.
  */
 static xmlParserInputPtr
-resolveEntityDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *publicId, const xmlChar *systemId)
+resolveEntityDebug(void *ctx, const xmlChar *publicId, const xmlChar *systemId)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return(NULL);
     /* xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx; */
 
@@ -792,10 +917,12 @@ resolveEntityDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *publicId, const xm
  * Returns the xmlParserInputPtr if inlined or NULL for DOM behaviour.
  */
 static xmlEntityPtr
-getEntityDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name)
+getEntityDebug(void *ctx, const xmlChar *name)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return(NULL);
     fprintf(stdout, "SAX.getEntity(%s)\n", name);
     return(NULL);
@@ -811,10 +938,12 @@ getEntityDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name)
  * Returns the xmlParserInputPtr
  */
 static xmlEntityPtr
-getParameterEntityDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name)
+getParameterEntityDebug(void *ctx, const xmlChar *name)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return(NULL);
     fprintf(stdout, "SAX.getParameterEntity(%s)\n", name);
     return(NULL);
@@ -833,10 +962,12 @@ getParameterEntityDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name)
  * An entity definition has been parsed
  */
 static void
-entityDeclDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name, int type,
+entityDeclDebug(void *ctx, const xmlChar *name, int type,
           const xmlChar *publicId, const xmlChar *systemId, xmlChar *content)
 {
-const xmlChar *nullstr = BAD_CAST "(null)";
+    xmllintState *lint = ctx;
+    const xmlChar *nullstr = BAD_CAST "(null)";
+
     /* not all libraries handle printing null pointers nicely */
     if (publicId == NULL)
         publicId = nullstr;
@@ -844,8 +975,8 @@ const xmlChar *nullstr = BAD_CAST "(null)";
         systemId = nullstr;
     if (content == NULL)
         content = (xmlChar *)nullstr;
-    callbacks++;
-    if (noout)
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.entityDecl(%s, %d, %s, %s, %s)\n",
             name, type, publicId, systemId, content);
@@ -860,12 +991,14 @@ const xmlChar *nullstr = BAD_CAST "(null)";
  * An attribute definition has been parsed
  */
 static void
-attributeDeclDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar * elem,
+attributeDeclDebug(void *ctx, const xmlChar * elem,
                    const xmlChar * name, int type, int def,
                    const xmlChar * defaultValue, xmlEnumerationPtr tree)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
         return;
     if (defaultValue == NULL)
         fprintf(stdout, "SAX.attributeDecl(%s, %s, %d, %d, NULL, ...)\n",
@@ -886,11 +1019,13 @@ attributeDeclDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar * elem,
  * An element definition has been parsed
  */
 static void
-elementDeclDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name, int type,
+elementDeclDebug(void *ctx, const xmlChar *name, int type,
 	    xmlElementContentPtr content ATTRIBUTE_UNUSED)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.elementDecl(%s, %d, ...)\n",
             name, type);
@@ -906,11 +1041,13 @@ elementDeclDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name, int type,
  * What to do when a notation declaration has been parsed.
  */
 static void
-notationDeclDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name,
+notationDeclDebug(void *ctx, const xmlChar *name,
 	     const xmlChar *publicId, const xmlChar *systemId)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.notationDecl(%s, %s, %s)\n",
             (char *) name, (char *) publicId, (char *) systemId);
@@ -927,11 +1064,12 @@ notationDeclDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name,
  * What to do when an unparsed entity declaration is parsed
  */
 static void
-unparsedEntityDeclDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name,
+unparsedEntityDeclDebug(void *ctx, const xmlChar *name,
 		   const xmlChar *publicId, const xmlChar *systemId,
 		   const xmlChar *notationName)
 {
-const xmlChar *nullstr = BAD_CAST "(null)";
+    xmllintState *lint = ctx;
+    const xmlChar *nullstr = BAD_CAST "(null)";
 
     if (publicId == NULL)
         publicId = nullstr;
@@ -939,8 +1077,8 @@ const xmlChar *nullstr = BAD_CAST "(null)";
         systemId = nullstr;
     if (notationName == NULL)
         notationName = nullstr;
-    callbacks++;
-    if (noout)
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.unparsedEntityDecl(%s, %s, %s, %s)\n",
             (char *) name, (char *) publicId, (char *) systemId,
@@ -956,10 +1094,12 @@ const xmlChar *nullstr = BAD_CAST "(null)";
  * Everything is available on the context, so this is useless in our case.
  */
 static void
-setDocumentLocatorDebug(void *ctx ATTRIBUTE_UNUSED, xmlSAXLocatorPtr loc ATTRIBUTE_UNUSED)
+setDocumentLocatorDebug(void *ctx, xmlSAXLocatorPtr loc ATTRIBUTE_UNUSED)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.setDocumentLocator()\n");
 }
@@ -971,10 +1111,12 @@ setDocumentLocatorDebug(void *ctx ATTRIBUTE_UNUSED, xmlSAXLocatorPtr loc ATTRIBU
  * called when the document start being processed.
  */
 static void
-startDocumentDebug(void *ctx ATTRIBUTE_UNUSED)
+startDocumentDebug(void *ctx)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.startDocument()\n");
 }
@@ -986,14 +1128,17 @@ startDocumentDebug(void *ctx ATTRIBUTE_UNUSED)
  * called when the document end has been detected.
  */
 static void
-endDocumentDebug(void *ctx ATTRIBUTE_UNUSED)
+endDocumentDebug(void *ctx)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.endDocument()\n");
 }
 
+#ifdef LIBXML_SAX1_ENABLED
 /**
  * startElementDebug:
  * @ctxt:  An XML parser context
@@ -1002,12 +1147,13 @@ endDocumentDebug(void *ctx ATTRIBUTE_UNUSED)
  * called when an opening tag has been processed.
  */
 static void
-startElementDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name, const xmlChar **atts)
+startElementDebug(void *ctx, const xmlChar *name, const xmlChar **atts)
 {
+    xmllintState *lint = ctx;
     int i;
 
-    callbacks++;
-    if (noout)
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.startElement(%s", (char *) name);
     if (atts != NULL) {
@@ -1028,13 +1174,16 @@ startElementDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name, const xmlChar
  * called when the end of an element has been detected.
  */
 static void
-endElementDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name)
+endElementDebug(void *ctx, const xmlChar *name)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.endElement(%s)\n", (char *) name);
 }
+#endif /* LIBXML_SAX1_ENABLED */
 
 /**
  * charactersDebug:
@@ -1046,13 +1195,14 @@ endElementDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name)
  * Question: how much at a time ???
  */
 static void
-charactersDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *ch, int len)
+charactersDebug(void *ctx, const xmlChar *ch, int len)
 {
+    xmllintState *lint = ctx;
     char out[40];
     int i;
 
-    callbacks++;
-    if (noout)
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     for (i = 0;(i<len) && (i < 30);i++)
 	out[i] = (char) ch[i];
@@ -1069,10 +1219,12 @@ charactersDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *ch, int len)
  * called when an entity reference is detected.
  */
 static void
-referenceDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name)
+referenceDebug(void *ctx, const xmlChar *name)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.reference(%s)\n", name);
 }
@@ -1088,13 +1240,14 @@ referenceDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *name)
  * Question: how much at a time ???
  */
 static void
-ignorableWhitespaceDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *ch, int len)
+ignorableWhitespaceDebug(void *ctx, const xmlChar *ch, int len)
 {
+    xmllintState *lint = ctx;
     char out[40];
     int i;
 
-    callbacks++;
-    if (noout)
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     for (i = 0;(i<len) && (i < 30);i++)
 	out[i] = ch[i];
@@ -1112,11 +1265,13 @@ ignorableWhitespaceDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *ch, int len)
  * A processing instruction has been parsed.
  */
 static void
-processingInstructionDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *target,
+processingInstructionDebug(void *ctx, const xmlChar *target,
                       const xmlChar *data)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     if (data != NULL)
 	fprintf(stdout, "SAX.processingInstruction(%s, %s)\n",
@@ -1135,10 +1290,12 @@ processingInstructionDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *target,
  * called when a pcdata block has been parsed
  */
 static void
-cdataBlockDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *value, int len)
+cdataBlockDebug(void *ctx, const xmlChar *value, int len)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.pcdata(%.20s, %d)\n",
 	    (char *) value, len);
@@ -1152,10 +1309,12 @@ cdataBlockDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *value, int len)
  * A comment has been parsed.
  */
 static void
-commentDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *value)
+commentDebug(void *ctx, const xmlChar *value)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.comment(%s)\n", value);
 }
@@ -1170,12 +1329,13 @@ commentDebug(void *ctx ATTRIBUTE_UNUSED, const xmlChar *value)
  * extra parameters.
  */
 static void LIBXML_ATTR_FORMAT(2,3)
-warningDebug(void *ctx ATTRIBUTE_UNUSED, const char *msg, ...)
+warningDebug(void *ctx, const char *msg, ...)
 {
+    xmllintState *lint = ctx;
     va_list args;
 
-    callbacks++;
-    if (noout)
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     va_start(args, msg);
     fprintf(stdout, "SAX.warning: ");
@@ -1193,12 +1353,13 @@ warningDebug(void *ctx ATTRIBUTE_UNUSED, const char *msg, ...)
  * extra parameters.
  */
 static void LIBXML_ATTR_FORMAT(2,3)
-errorDebug(void *ctx ATTRIBUTE_UNUSED, const char *msg, ...)
+errorDebug(void *ctx, const char *msg, ...)
 {
+    xmllintState *lint = ctx;
     va_list args;
 
-    callbacks++;
-    if (noout)
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     va_start(args, msg);
     fprintf(stdout, "SAX.error: ");
@@ -1216,12 +1377,13 @@ errorDebug(void *ctx ATTRIBUTE_UNUSED, const char *msg, ...)
  * extra parameters.
  */
 static void LIBXML_ATTR_FORMAT(2,3)
-fatalErrorDebug(void *ctx ATTRIBUTE_UNUSED, const char *msg, ...)
+fatalErrorDebug(void *ctx, const char *msg, ...)
 {
+    xmllintState *lint = ctx;
     va_list args;
 
-    callbacks++;
-    if (noout)
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     va_start(args, msg);
     fprintf(stdout, "SAX.fatalError: ");
@@ -1229,7 +1391,8 @@ fatalErrorDebug(void *ctx ATTRIBUTE_UNUSED, const char *msg, ...)
     va_end(args);
 }
 
-static xmlSAXHandler debugSAXHandlerStruct = {
+#ifdef LIBXML_SAX1_ENABLED
+static const xmlSAXHandler debugSAXHandler = {
     internalSubsetDebug,
     isStandaloneDebug,
     hasInternalSubsetDebug,
@@ -1263,8 +1426,7 @@ static xmlSAXHandler debugSAXHandlerStruct = {
     NULL,
     NULL
 };
-
-xmlSAXHandlerPtr debugSAXHandler = &debugSAXHandlerStruct;
+#endif
 
 /*
  * SAX2 specific callbacks
@@ -1277,7 +1439,7 @@ xmlSAXHandlerPtr debugSAXHandler = &debugSAXHandlerStruct;
  * called when an opening tag has been processed.
  */
 static void
-startElementNsDebug(void *ctx ATTRIBUTE_UNUSED,
+startElementNsDebug(void *ctx,
                     const xmlChar *localname,
                     const xmlChar *prefix,
                     const xmlChar *URI,
@@ -1287,10 +1449,11 @@ startElementNsDebug(void *ctx ATTRIBUTE_UNUSED,
 		    int nb_defaulted,
 		    const xmlChar **attributes)
 {
+    xmllintState *lint = ctx;
     int i;
 
-    callbacks++;
-    if (noout)
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.startElementNs(%s", (char *) localname);
     if (prefix == NULL)
@@ -1334,13 +1497,15 @@ startElementNsDebug(void *ctx ATTRIBUTE_UNUSED,
  * called when the end of an element has been detected.
  */
 static void
-endElementNsDebug(void *ctx ATTRIBUTE_UNUSED,
+endElementNsDebug(void *ctx,
                   const xmlChar *localname,
                   const xmlChar *prefix,
                   const xmlChar *URI)
 {
-    callbacks++;
-    if (noout)
+    xmllintState *lint = ctx;
+
+    lint->callbacks++;
+    if (lint->noout)
 	return;
     fprintf(stdout, "SAX.endElementNs(%s", (char *) localname);
     if (prefix == NULL)
@@ -1353,7 +1518,7 @@ endElementNsDebug(void *ctx ATTRIBUTE_UNUSED,
 	fprintf(stdout, ", '%s')\n", (char *) URI);
 }
 
-static xmlSAXHandler debugSAX2HandlerStruct = {
+static const xmlSAXHandler debugSAX2Handler = {
     internalSubsetDebug,
     isStandaloneDebug,
     hasInternalSubsetDebug,
@@ -1388,27 +1553,12 @@ static xmlSAXHandler debugSAX2HandlerStruct = {
     NULL
 };
 
-static xmlSAXHandlerPtr debugSAX2Handler = &debugSAX2HandlerStruct;
-
 static void
-testSAX(const char *filename) {
-    xmlSAXHandlerPtr handler;
-    const char *user_data = "user_data"; /* mostly for debugging */
-
-    callbacks = 0;
-
-    if (noout) {
-        handler = emptySAXHandler;
-#ifdef LIBXML_SAX1_ENABLED
-    } else if (options & XML_PARSE_SAX1) {
-        handler = debugSAXHandler;
-#endif
-    } else {
-        handler = debugSAX2Handler;
-    }
+testSAX(xmllintState *lint, const char *filename) {
+    lint->callbacks = 0;
 
 #ifdef LIBXML_SCHEMAS_ENABLED
-    if (wxschemas != NULL) {
+    if (lint->wxschemas != NULL) {
         int ret;
 	xmlSchemaValidCtxtPtr vctxt;
         xmlParserInputBufferPtr buf;
@@ -1422,65 +1572,39 @@ testSAX(const char *filename) {
         if (buf == NULL)
             return;
 
-	vctxt = xmlSchemaNewValidCtxt(wxschemas);
+	vctxt = xmlSchemaNewValidCtxt(lint->wxschemas);
         if (vctxt == NULL) {
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             xmlFreeParserInputBuffer(buf);
             return;
         }
 	xmlSchemaValidateSetFilename(vctxt, filename);
 
-	ret = xmlSchemaValidateStream(vctxt, buf, 0, handler,
-	                              (void *)user_data);
-	if (repeat == 0) {
+	ret = xmlSchemaValidateStream(vctxt, buf, 0, lint->ctxt->sax, lint);
+	if (lint->repeat == 1) {
 	    if (ret == 0) {
-	        if (!quiet) {
-	            fprintf(ERR_STREAM, "%s validates\n", filename);
+	        if (!lint->quiet) {
+	            fprintf(lint->errStream, "%s validates\n", filename);
 	        }
 	    } else if (ret > 0) {
-		fprintf(ERR_STREAM, "%s fails to validate\n", filename);
-		progresult = XMLLINT_ERR_VALID;
+		fprintf(lint->errStream, "%s fails to validate\n", filename);
+		lint->progresult = XMLLINT_ERR_VALID;
 	    } else {
-		fprintf(ERR_STREAM, "%s validation generated an internal error\n",
+		fprintf(lint->errStream, "%s validation generated an internal error\n",
 		       filename);
-		progresult = XMLLINT_ERR_VALID;
+		lint->progresult = XMLLINT_ERR_VALID;
 	    }
 	}
 	xmlSchemaFreeValidCtxt(vctxt);
     } else
 #endif
 #ifdef LIBXML_HTML_ENABLED
-    if (html) {
-        htmlParserCtxtPtr ctxt = NULL;
-
-	ctxt = htmlNewSAXParserCtxt(handler, (void *) user_data);
-	if (ctxt == NULL) {
-            progresult = XMLLINT_ERR_MEM;
-	    return;
-	}
-
-        parseHtml(ctxt, filename);
-
-        htmlFreeParserCtxt(ctxt);
+    if (lint->html) {
+        parseHtml(lint, filename);
     } else
 #endif
     {
-        xmlParserCtxtPtr ctxt = NULL;
-
-	ctxt = xmlNewSAXParserCtxt(handler, (void *) user_data);
-	if (ctxt == NULL) {
-            progresult = XMLLINT_ERR_MEM;
-	    return;
-	}
-
-        parseXml(ctxt, filename);
-
-	if (ctxt->myDoc != NULL) {
-	    fprintf(ERR_STREAM, "SAX generated a doc !\n");
-	    xmlFreeDoc(ctxt->myDoc);
-	    ctxt->myDoc = NULL;
-	}
-        xmlFreeParserCtxt(ctxt);
+        parseXml(lint, filename);
     }
 }
 
@@ -1490,14 +1614,14 @@ testSAX(const char *filename) {
  *									*
  ************************************************************************/
 #ifdef LIBXML_READER_ENABLED
-static void processNode(xmlTextReaderPtr reader) {
+static void processNode(xmllintState *lint, xmlTextReaderPtr reader) {
     const xmlChar *name, *value;
     int type, empty;
 
     type = xmlTextReaderNodeType(reader);
     empty = xmlTextReaderIsEmptyElement(reader);
 
-    if (debug) {
+    if (lint->debug) {
 	name = xmlTextReaderConstName(reader);
 	if (name == NULL)
 	    name = BAD_CAST "--";
@@ -1518,53 +1642,54 @@ static void processNode(xmlTextReaderPtr reader) {
 	}
     }
 #ifdef LIBXML_PATTERN_ENABLED
-    if (patternc) {
+    if (lint->patternc) {
         xmlChar *path = NULL;
         int match = -1;
 
 	if (type == XML_READER_TYPE_ELEMENT) {
 	    /* do the check only on element start */
-	    match = xmlPatternMatch(patternc, xmlTextReaderCurrentNode(reader));
+	    match = xmlPatternMatch(lint->patternc,
+                                    xmlTextReaderCurrentNode(reader));
 
 	    if (match) {
 		path = xmlGetNodePath(xmlTextReaderCurrentNode(reader));
-		printf("Node %s matches pattern %s\n", path, pattern);
+		printf("Node %s matches pattern %s\n", path, lint->pattern);
 	    }
 	}
-	if (patstream != NULL) {
+	if (lint->patstream != NULL) {
 	    int ret;
 
 	    if (type == XML_READER_TYPE_ELEMENT) {
-		ret = xmlStreamPush(patstream,
+		ret = xmlStreamPush(lint->patstream,
 		                    xmlTextReaderConstLocalName(reader),
 				    xmlTextReaderConstNamespaceUri(reader));
 		if (ret < 0) {
-		    fprintf(ERR_STREAM, "xmlStreamPush() failure\n");
-                    xmlFreeStreamCtxt(patstream);
-		    patstream = NULL;
+		    fprintf(lint->errStream, "xmlStreamPush() failure\n");
+                    xmlFreeStreamCtxt(lint->patstream);
+		    lint->patstream = NULL;
 		} else if (ret != match) {
 		    if (path == NULL) {
 		        path = xmlGetNodePath(
 		                       xmlTextReaderCurrentNode(reader));
 		    }
-		    fprintf(ERR_STREAM,
+		    fprintf(lint->errStream,
 		            "xmlPatternMatch and xmlStreamPush disagree\n");
                     if (path != NULL)
-                        fprintf(ERR_STREAM, "  pattern %s node %s\n",
-                                pattern, path);
+                        fprintf(lint->errStream, "  pattern %s node %s\n",
+                                lint->pattern, path);
                     else
-		        fprintf(ERR_STREAM, "  pattern %s node %s\n",
-			    pattern, xmlTextReaderConstName(reader));
+		        fprintf(lint->errStream, "  pattern %s node %s\n",
+			    lint->pattern, xmlTextReaderConstName(reader));
 		}
 
 	    }
 	    if ((type == XML_READER_TYPE_END_ELEMENT) ||
 	        ((type == XML_READER_TYPE_ELEMENT) && (empty))) {
-	        ret = xmlStreamPop(patstream);
+	        ret = xmlStreamPop(lint->patstream);
 		if (ret < 0) {
-		    fprintf(ERR_STREAM, "xmlStreamPop() failure\n");
-                    xmlFreeStreamCtxt(patstream);
-		    patstream = NULL;
+		    fprintf(lint->errStream, "xmlStreamPop() failure\n");
+                    xmlFreeStreamCtxt(lint->patstream);
+		    lint->patstream = NULL;
 		}
 	    }
 	}
@@ -1574,149 +1699,189 @@ static void processNode(xmlTextReaderPtr reader) {
 #endif
 }
 
-static void streamFile(const char *filename) {
+static void streamFile(xmllintState *lint, const char *filename) {
+    xmlParserInputBufferPtr input = NULL;
+    FILE *errStream = lint->errStream;
     xmlTextReaderPtr reader;
     int ret;
+
 #if HAVE_DECL_MMAP
-    if (memory) {
-	reader = xmlReaderForMemory(memoryData, memorySize, filename,
-	                            NULL, options);
+    if (lint->memory) {
+	reader = xmlReaderForMemory(lint->memoryData, lint->memorySize,
+                                    filename, NULL, lint->options);
     } else
 #endif
-    if (strcmp(filename, "-") == 0)
-	reader = xmlReaderForFd(STDIN_FILENO, "-", NULL, options);
-    else
-	reader = xmlReaderForFile(filename, NULL, options);
+    {
+        if (strcmp(filename, "-") == 0) {
+            reader = xmlReaderForFd(STDIN_FILENO, "-", NULL, lint->options);
+        }
+        else {
+            /*
+             * There's still no easy way to get a reader for a file with
+             * adequate error repoting.
+             */
+
+            xmlResetLastError();
+            input = xmlParserInputBufferCreateFilename(filename,
+                                                       XML_CHAR_ENCODING_NONE);
+            if (input == NULL) {
+                const xmlError *error = xmlGetLastError();
+
+                if ((error != NULL) && (error->code == XML_ERR_NO_MEMORY)) {
+                    lint->progresult = XMLLINT_ERR_MEM;
+                } else {
+                    fprintf(errStream, "Unable to open %s\n", filename);
+                    lint->progresult = XMLLINT_ERR_RDFILE;
+                }
+                return;
+            }
+
+            reader = xmlNewTextReader(input, filename);
+            if (reader == NULL) {
+                lint->progresult = XMLLINT_ERR_MEM;
+                xmlFreeParserInputBuffer(input);
+                return;
+            }
+            if (xmlTextReaderSetup(reader, NULL, NULL, NULL,
+                                   lint->options) < 0) {
+                lint->progresult = XMLLINT_ERR_MEM;
+                xmlFreeParserInputBuffer(input);
+                return;
+            }
+        }
+    }
+    if (reader == NULL) {
+        lint->progresult = XMLLINT_ERR_MEM;
+        return;
+    }
+
 #ifdef LIBXML_PATTERN_ENABLED
-    if (patternc != NULL) {
-        patstream = xmlPatternGetStreamCtxt(patternc);
-	if (patstream != NULL) {
-	    ret = xmlStreamPush(patstream, NULL, NULL);
+    if (lint->patternc != NULL) {
+        lint->patstream = xmlPatternGetStreamCtxt(lint->patternc);
+	if (lint->patstream != NULL) {
+	    ret = xmlStreamPush(lint->patstream, NULL, NULL);
 	    if (ret < 0) {
-		fprintf(ERR_STREAM, "xmlStreamPush() failure\n");
-		xmlFreeStreamCtxt(patstream);
-		patstream = NULL;
+		fprintf(errStream, "xmlStreamPush() failure\n");
+		xmlFreeStreamCtxt(lint->patstream);
+		lint->patstream = NULL;
             }
 	}
     }
 #endif
 
 
-    if (reader != NULL) {
-        xmlTextReaderSetResourceLoader(reader, xmllintResourceLoader, NULL);
-        if (maxAmpl > 0)
-            xmlTextReaderSetMaxAmplification(reader, maxAmpl);
+    xmlTextReaderSetResourceLoader(reader, xmllintResourceLoader, lint);
+    if (lint->maxAmpl > 0)
+        xmlTextReaderSetMaxAmplification(reader, lint->maxAmpl);
 
 #ifdef LIBXML_SCHEMAS_ENABLED
-	if (relaxng != NULL) {
-	    if ((timing) && (!repeat)) {
-		startTimer();
-	    }
-	    ret = xmlTextReaderRelaxNGValidate(reader, relaxng);
-	    if (ret < 0) {
-		fprintf(ERR_STREAM,
-			"Relax-NG schema %s failed to compile\n", relaxng);
-		progresult = XMLLINT_ERR_SCHEMACOMP;
-		relaxng = NULL;
-	    }
-	    if ((timing) && (!repeat)) {
-		endTimer("Compiling the schemas");
-	    }
-	}
-	if (schema != NULL) {
-	    if ((timing) && (!repeat)) {
-		startTimer();
-	    }
-	    ret = xmlTextReaderSchemaValidate(reader, schema);
-	    if (ret < 0) {
-		fprintf(ERR_STREAM,
-			"XSD schema %s failed to compile\n", schema);
-		progresult = XMLLINT_ERR_SCHEMACOMP;
-		schema = NULL;
-	    }
-	    if ((timing) && (!repeat)) {
-		endTimer("Compiling the schemas");
-	    }
-	}
+    if (lint->relaxng != NULL) {
+        if ((lint->timing) && (lint->repeat == 1)) {
+            startTimer(lint);
+        }
+        ret = xmlTextReaderRelaxNGValidate(reader, lint->relaxng);
+        if (ret < 0) {
+            fprintf(errStream, "Relax-NG schema %s failed to compile\n",
+                    lint->relaxng);
+            lint->progresult = XMLLINT_ERR_SCHEMACOMP;
+            lint->relaxng = NULL;
+        }
+        if ((lint->timing) && (lint->repeat == 1)) {
+            endTimer(lint, "Compiling the schemas");
+        }
+    }
+    if (lint->schema != NULL) {
+        if ((lint->timing) && (lint->repeat == 1)) {
+            startTimer(lint);
+        }
+        ret = xmlTextReaderSchemaValidate(reader, lint->schema);
+        if (ret < 0) {
+            fprintf(errStream, "XSD schema %s failed to compile\n",
+                    lint->schema);
+            lint->progresult = XMLLINT_ERR_SCHEMACOMP;
+            lint->schema = NULL;
+        }
+        if ((lint->timing) && (lint->repeat == 1)) {
+            endTimer(lint, "Compiling the schemas");
+        }
+    }
 #endif
 
-	/*
-	 * Process all nodes in sequence
-	 */
-	if ((timing) && (!repeat)) {
-	    startTimer();
-	}
-	ret = xmlTextReaderRead(reader);
-	while (ret == 1) {
-	    if ((debug)
+    /*
+     * Process all nodes in sequence
+     */
+    if ((lint->timing) && (lint->repeat == 1)) {
+        startTimer(lint);
+    }
+    ret = xmlTextReaderRead(reader);
+    while (ret == 1) {
+        if ((lint->debug)
 #ifdef LIBXML_PATTERN_ENABLED
-	        || (patternc)
+            || (lint->patternc)
 #endif
-	       )
-		processNode(reader);
-	    ret = xmlTextReaderRead(reader);
-	}
-	if ((timing) && (!repeat)) {
+           )
+            processNode(lint, reader);
+        ret = xmlTextReaderRead(reader);
+    }
+    if ((lint->timing) && (lint->repeat == 1)) {
 #ifdef LIBXML_SCHEMAS_ENABLED
-	    if (relaxng != NULL)
-		endTimer("Parsing and validating");
-	    else
+        if (lint->relaxng != NULL)
+            endTimer(lint, "Parsing and validating");
+        else
 #endif
 #ifdef LIBXML_VALID_ENABLED
-	    if (options & XML_PARSE_DTDVALID)
-		endTimer("Parsing and validating");
-	    else
+        if (lint->options & XML_PARSE_DTDVALID)
+            endTimer(lint, "Parsing and validating");
+        else
 #endif
-	    endTimer("Parsing");
-	}
+        endTimer(lint, "Parsing");
+    }
 
 #ifdef LIBXML_VALID_ENABLED
-	if (options & XML_PARSE_DTDVALID) {
-	    if (xmlTextReaderIsValid(reader) != 1) {
-		fprintf(ERR_STREAM,
-			"Document %s does not validate\n", filename);
-		progresult = XMLLINT_ERR_VALID;
-	    }
-	}
+    if (lint->options & XML_PARSE_DTDVALID) {
+        if (xmlTextReaderIsValid(reader) != 1) {
+            fprintf(errStream,
+                    "Document %s does not validate\n", filename);
+            lint->progresult = XMLLINT_ERR_VALID;
+        }
+    }
 #endif /* LIBXML_VALID_ENABLED */
 #ifdef LIBXML_SCHEMAS_ENABLED
-	if ((relaxng != NULL) || (schema != NULL)) {
-	    if (xmlTextReaderIsValid(reader) != 1) {
-		fprintf(ERR_STREAM, "%s fails to validate\n", filename);
-		progresult = XMLLINT_ERR_VALID;
-	    } else {
-	        if (!quiet) {
-	            fprintf(ERR_STREAM, "%s validates\n", filename);
-	        }
-	    }
-	}
+    if ((lint->relaxng != NULL) || (lint->schema != NULL)) {
+        if (xmlTextReaderIsValid(reader) != 1) {
+            fprintf(errStream, "%s fails to validate\n", filename);
+            lint->progresult = XMLLINT_ERR_VALID;
+        } else {
+            if (!lint->quiet) {
+                fprintf(errStream, "%s validates\n", filename);
+            }
+        }
+    }
 #endif
-	/*
-	 * Done, cleanup and status
-	 */
-	xmlFreeTextReader(reader);
-	if (ret != 0) {
-	    fprintf(ERR_STREAM, "%s : failed to parse\n", filename);
-	    progresult = XMLLINT_ERR_UNCLASS;
-	}
-    } else {
-	fprintf(ERR_STREAM, "Unable to open %s\n", filename);
-	progresult = XMLLINT_ERR_UNCLASS;
+    /*
+     * Done, cleanup and status
+     */
+    xmlFreeTextReader(reader);
+    xmlFreeParserInputBuffer(input);
+    if (ret != 0) {
+        fprintf(errStream, "%s : failed to parse\n", filename);
+        lint->progresult = XMLLINT_ERR_UNCLASS;
     }
 #ifdef LIBXML_PATTERN_ENABLED
-    if (patstream != NULL) {
-	xmlFreeStreamCtxt(patstream);
-	patstream = NULL;
+    if (lint->patstream != NULL) {
+	xmlFreeStreamCtxt(lint->patstream);
+	lint->patstream = NULL;
     }
 #endif
 }
 
-static void walkDoc(xmlDocPtr doc) {
+static void walkDoc(xmllintState *lint, xmlDocPtr doc) {
+    FILE *errStream = lint->errStream;
     xmlTextReaderPtr reader;
     int ret;
 
 #ifdef LIBXML_PATTERN_ENABLED
-    if (pattern != NULL) {
+    if (lint->pattern != NULL) {
         xmlNodePtr root;
         const xmlChar *namespaces[22];
         int i;
@@ -1724,9 +1889,9 @@ static void walkDoc(xmlDocPtr doc) {
 
         root = xmlDocGetRootElement(doc);
         if (root == NULL ) {
-            fprintf(ERR_STREAM,
+            fprintf(errStream,
                     "Document does not have a root element");
-            progresult = XMLLINT_ERR_UNCLASS;
+            lint->progresult = XMLLINT_ERR_UNCLASS;
             return;
         }
         for (ns = root->nsDef, i = 0;ns != NULL && i < 20;ns=ns->next) {
@@ -1736,70 +1901,70 @@ static void walkDoc(xmlDocPtr doc) {
         namespaces[i++] = NULL;
         namespaces[i] = NULL;
 
-        ret = xmlPatternCompileSafe((const xmlChar *) pattern, doc->dict,
-                                    0, &namespaces[0], &patternc);
-	if (patternc == NULL) {
+        ret = xmlPatternCompileSafe((const xmlChar *) lint->pattern, doc->dict,
+                                    0, &namespaces[0], &lint->patternc);
+	if (lint->patternc == NULL) {
             if (ret < 0) {
-                progresult = XMLLINT_ERR_MEM;
+                lint->progresult = XMLLINT_ERR_MEM;
             } else {
-                fprintf(ERR_STREAM,
-                        "Pattern %s failed to compile\n", pattern);
-                progresult = XMLLINT_ERR_SCHEMAPAT;
+                fprintf(errStream, "Pattern %s failed to compile\n",
+                        lint->pattern);
+                lint->progresult = XMLLINT_ERR_SCHEMAPAT;
             }
             goto error;
 	}
 
-        patstream = xmlPatternGetStreamCtxt(patternc);
-        if (patstream == NULL) {
-            progresult = XMLLINT_ERR_MEM;
+        lint->patstream = xmlPatternGetStreamCtxt(lint->patternc);
+        if (lint->patstream == NULL) {
+            lint->progresult = XMLLINT_ERR_MEM;
             goto error;
         }
 
-        ret = xmlStreamPush(patstream, NULL, NULL);
+        ret = xmlStreamPush(lint->patstream, NULL, NULL);
         if (ret < 0) {
-            fprintf(ERR_STREAM, "xmlStreamPush() failure\n");
-            progresult = XMLLINT_ERR_MEM;
+            fprintf(errStream, "xmlStreamPush() failure\n");
+            lint->progresult = XMLLINT_ERR_MEM;
             goto error;
         }
     }
 #endif /* LIBXML_PATTERN_ENABLED */
     reader = xmlReaderWalker(doc);
     if (reader != NULL) {
-	if ((timing) && (!repeat)) {
-	    startTimer();
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    startTimer(lint);
 	}
 	ret = xmlTextReaderRead(reader);
 	while (ret == 1) {
-	    if ((debug)
+	    if ((lint->debug)
 #ifdef LIBXML_PATTERN_ENABLED
-	        || (patternc)
+	        || (lint->patternc)
 #endif
 	       )
-		processNode(reader);
+		processNode(lint, reader);
 	    ret = xmlTextReaderRead(reader);
 	}
-	if ((timing) && (!repeat)) {
-	    endTimer("walking through the doc");
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    endTimer(lint, "walking through the doc");
 	}
 	xmlFreeTextReader(reader);
 	if (ret != 0) {
-	    fprintf(ERR_STREAM, "failed to walk through the doc\n");
-	    progresult = XMLLINT_ERR_UNCLASS;
+	    fprintf(errStream, "failed to walk through the doc\n");
+	    lint->progresult = XMLLINT_ERR_UNCLASS;
 	}
     } else {
-	fprintf(ERR_STREAM, "Failed to crate a reader from the document\n");
-	progresult = XMLLINT_ERR_UNCLASS;
+	fprintf(errStream, "Failed to create a reader from the document\n");
+	lint->progresult = XMLLINT_ERR_UNCLASS;
     }
 
 #ifdef LIBXML_PATTERN_ENABLED
 error:
-    if (patternc != NULL) {
-        xmlFreePattern(patternc);
-        patternc = NULL;
+    if (lint->patternc != NULL) {
+        xmlFreePattern(lint->patternc);
+        lint->patternc = NULL;
     }
-    if (patstream != NULL) {
-	xmlFreeStreamCtxt(patstream);
-	patstream = NULL;
+    if (lint->patstream != NULL) {
+	xmlFreeStreamCtxt(lint->patstream);
+	lint->patstream = NULL;
     }
 #endif
 }
@@ -1812,7 +1977,8 @@ error:
  *									*
  ************************************************************************/
 
-static void doXPathDump(xmlXPathObjectPtr cur) {
+static void
+doXPathDump(xmllintState *lint, xmlXPathObjectPtr cur) {
     switch(cur->type) {
         case XPATH_NODESET: {
 #ifdef LIBXML_OUTPUT_ENABLED
@@ -1821,16 +1987,15 @@ static void doXPathDump(xmlXPathObjectPtr cur) {
             int i;
 
             if ((cur->nodesetval == NULL) || (cur->nodesetval->nodeNr <= 0)) {
-                progresult = XMLLINT_ERR_XPATH_EMPTY;
-                if (!quiet) {
-                    fprintf(ERR_STREAM, "XPath set is empty\n");
+                lint->progresult = XMLLINT_ERR_XPATH_EMPTY;
+                if (!lint->quiet) {
+                    fprintf(lint->errStream, "XPath set is empty\n");
                 }
                 break;
             }
             buf = xmlOutputBufferCreateFile(stdout, NULL);
             if (buf == NULL) {
-                fprintf(ERR_STREAM, "Out of memory for XPath\n");
-                progresult = XMLLINT_ERR_MEM;
+                lint->progresult = XMLLINT_ERR_MEM;
                 return;
             }
             for (i = 0;i < cur->nodesetval->nodeNr;i++) {
@@ -1868,37 +2033,56 @@ static void doXPathDump(xmlXPathObjectPtr cur) {
 	    printf("%s\n", (const char *) cur->stringval);
 	    break;
         case XPATH_UNDEFINED:
-	    fprintf(ERR_STREAM, "XPath Object is uninitialized\n");
-            progresult = XMLLINT_ERR_XPATH;
+	    fprintf(lint->errStream, "XPath Object is uninitialized\n");
+            lint->progresult = XMLLINT_ERR_XPATH;
 	    break;
 	default:
-	    fprintf(ERR_STREAM, "XPath object of unexpected type\n");
-            progresult = XMLLINT_ERR_XPATH;
+	    fprintf(lint->errStream, "XPath object of unexpected type\n");
+            lint->progresult = XMLLINT_ERR_XPATH;
 	    break;
     }
 }
 
-static void doXPathQuery(xmlDocPtr doc, const char *query) {
-    xmlXPathContextPtr ctxt;
-    xmlXPathObjectPtr res;
+static void
+doXPathQuery(xmllintState *lint, xmlDocPtr doc, const char *query) {
+    xmlXPathContextPtr ctxt = NULL;
+    xmlXPathCompExprPtr comp = NULL;
+    xmlXPathObjectPtr res = NULL;
 
     ctxt = xmlXPathNewContext(doc);
     if (ctxt == NULL) {
-        fprintf(ERR_STREAM, "Out of memory for XPath\n");
-        progresult = XMLLINT_ERR_MEM;
-        return;
+        lint->progresult = XMLLINT_ERR_MEM;
+        goto error;
     }
-    ctxt->node = (xmlNodePtr) doc;
-    res = xmlXPathEval(BAD_CAST query, ctxt);
-    xmlXPathFreeContext(ctxt);
 
+    comp = xmlXPathCtxtCompile(ctxt, BAD_CAST query);
+    if (comp == NULL) {
+        fprintf(lint->errStream, "XPath compilation failure\n");
+        lint->progresult = XMLLINT_ERR_XPATH;
+        goto error;
+    }
+
+#ifdef LIBXML_DEBUG_ENABLED
+    if (lint->debug) {
+        xmlXPathDebugDumpCompExpr(stdout, comp, 0);
+        printf("\n");
+    }
+#endif
+
+    ctxt->node = (xmlNodePtr) doc;
+    res = xmlXPathCompiledEval(comp, ctxt);
     if (res == NULL) {
-        fprintf(ERR_STREAM, "XPath evaluation failure\n");
-        progresult = XMLLINT_ERR_XPATH;
-        return;
+        fprintf(lint->errStream, "XPath evaluation failure\n");
+        lint->progresult = XMLLINT_ERR_XPATH;
+        goto error;
     }
-    doXPathDump(res);
+
+    doXPathDump(lint, res);
+
+error:
     xmlXPathFreeObject(res);
+    xmlXPathFreeCompExpr(comp);
+    xmlXPathFreeContext(ctxt);
 }
 #endif /* LIBXML_XPATH_ENABLED */
 
@@ -1909,28 +2093,27 @@ static void doXPathQuery(xmlDocPtr doc, const char *query) {
  ************************************************************************/
 
 static xmlDocPtr
-parseFile(const char *filename, xmlParserCtxtPtr rectxt) {
-    xmlParserCtxtPtr ctxt;
+parseFile(xmllintState *lint, const char *filename) {
     xmlDocPtr doc = NULL;
 
-    if ((generate) && (filename == NULL)) {
+    if ((lint->generate) && (filename == NULL)) {
         xmlNodePtr n;
 
         doc = xmlNewDoc(BAD_CAST "1.0");
         if (doc == NULL) {
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             return(NULL);
         }
         n = xmlNewDocNode(doc, NULL, BAD_CAST "info", NULL);
         if (n == NULL) {
             xmlFreeDoc(doc);
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             return(NULL);
         }
         if (xmlNodeSetContent(n, BAD_CAST "abc") < 0) {
             xmlFreeNode(n);
             xmlFreeDoc(doc);
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             return(NULL);
         }
         xmlDocSetRootElement(doc, n);
@@ -1939,153 +2122,53 @@ parseFile(const char *filename, xmlParserCtxtPtr rectxt) {
     }
 
 #ifdef LIBXML_HTML_ENABLED
-#ifdef LIBXML_PUSH_ENABLED
-    if ((html) && (push)) {
-        FILE *f;
-        int res;
-        char chars[4096];
-
-        if ((filename[0] == '-') && (filename[1] == 0)) {
-            f = stdin;
-        } else {
-	    f = fopen(filename, "rb");
-            if (f == NULL) {
-                fprintf(ERR_STREAM, "Can't open %s\n", filename);
-                progresult = XMLLINT_ERR_RDFILE;
-                return(NULL);
-            }
-        }
-
-        res = fread(chars, 1, 4, f);
-        ctxt = htmlCreatePushParserCtxt(NULL, NULL,
-                    chars, res, filename, XML_CHAR_ENCODING_NONE);
-        if (ctxt == NULL) {
-            progresult = XMLLINT_ERR_MEM;
-            if (f != stdin)
-                fclose(f);
-            return(NULL);
-        }
-        htmlCtxtUseOptions(ctxt, options);
-        while ((res = fread(chars, 1, pushsize, f)) > 0) {
-            htmlParseChunk(ctxt, chars, res, 0);
-        }
-        htmlParseChunk(ctxt, chars, 0, 1);
-        doc = ctxt->myDoc;
-        htmlFreeParserCtxt(ctxt);
-        if (f != stdin)
-            fclose(f);
-
-        return(doc);
-    }
-#endif /* LIBXML_PUSH_ENABLED */
-
-    if (html) {
-        ctxt = htmlNewParserCtxt();
-        doc = parseHtml(ctxt, filename);
-        htmlFreeParserCtxt(ctxt);
+    if (lint->html) {
+        doc = parseHtml(lint, filename);
         return(doc);
     }
 #endif /* LIBXML_HTML_ENABLED */
-
-#ifdef LIBXML_PUSH_ENABLED
-    if (push) {
-        FILE *f;
-        int res;
-        char chars[4096];
-
-        if ((filename[0] == '-') && (filename[1] == 0)) {
-            f = stdin;
-        } else {
-            f = fopen(filename, "rb");
-            if (f == NULL) {
-                fprintf(ERR_STREAM, "Can't open %s\n", filename);
-                progresult = XMLLINT_ERR_RDFILE;
-                return(NULL);
-            }
-        }
-
-        res = fread(chars, 1, 4, f);
-        ctxt = xmlCreatePushParserCtxt(NULL, NULL,
-                    chars, res, filename);
-        if (ctxt == NULL) {
-            progresult = XMLLINT_ERR_MEM;
-            if (f != stdin)
-                fclose(f);
-            return(NULL);
-        }
-
-        xmlCtxtSetResourceLoader(ctxt, xmllintResourceLoader, NULL);
-        xmlCtxtUseOptions(ctxt, options);
-        if (maxAmpl > 0)
-            xmlCtxtSetMaxAmplification(ctxt, maxAmpl);
-
-        if (htmlout)
-            xmlCtxtSetErrorHandler(ctxt, xmlHTMLError, ctxt);
-
-        while ((res = fread(chars, 1, pushsize, f)) > 0) {
-            xmlParseChunk(ctxt, chars, res, 0);
-        }
-        xmlParseChunk(ctxt, chars, 0, 1);
-
-        doc = ctxt->myDoc;
-        if (f != stdin)
-            fclose(f);
-    } else
-#endif /* LIBXML_PUSH_ENABLED */
     {
-        if (rectxt == NULL) {
-            ctxt = xmlNewParserCtxt();
-            if (ctxt == NULL) {
-                progresult = XMLLINT_ERR_MEM;
-                return(NULL);
-            }
-        } else {
-            ctxt = rectxt;
-        }
-
-        doc = parseXml(ctxt, filename);
-
-        if (htmlout)
-            xmlCtxtSetErrorHandler(ctxt, xmlHTMLError, ctxt);
+        doc = parseXml(lint, filename);
     }
 
     if (doc == NULL) {
-        if (ctxt->errNo == XML_ERR_NO_MEMORY)
-            progresult = XMLLINT_ERR_MEM;
+        if (lint->ctxt->errNo == XML_ERR_NO_MEMORY)
+            lint->progresult = XMLLINT_ERR_MEM;
         else
-	    progresult = XMLLINT_ERR_RDFILE;
+	    lint->progresult = XMLLINT_ERR_RDFILE;
     } else {
 #ifdef LIBXML_VALID_ENABLED
-        if ((options & XML_PARSE_DTDVALID) && (ctxt->valid == 0))
-            progresult = XMLLINT_ERR_VALID;
+        if ((lint->options & XML_PARSE_DTDVALID) && (lint->ctxt->valid == 0))
+            lint->progresult = XMLLINT_ERR_VALID;
 #endif /* LIBXML_VALID_ENABLED */
     }
 
-    if (ctxt != rectxt)
-        xmlFreeParserCtxt(ctxt);
-
     return(doc);
 }
 
 static void
-parseAndPrintFile(const char *filename, xmlParserCtxtPtr rectxt) {
+parseAndPrintFile(xmllintState *lint, const char *filename) {
+    FILE *errStream = lint->errStream;
     xmlDocPtr doc;
 
-    if ((timing) && (!repeat))
-	startTimer();
+    /* Avoid unused variable warning */
+    (void) errStream;
+
+    if ((lint->timing) && (lint->repeat == 1))
+	startTimer(lint);
 
-    doc = parseFile(filename, rectxt);
+    doc = parseFile(lint, filename);
     if (doc == NULL) {
-        if (progresult == XMLLINT_RETURN_OK)
-            progresult = XMLLINT_ERR_UNCLASS;
+        if (lint->progresult == XMLLINT_RETURN_OK)
+            lint->progresult = XMLLINT_ERR_UNCLASS;
 	return;
     }
 
-    if ((timing) && (!repeat)) {
-	endTimer("Parsing");
+    if ((lint->timing) && (lint->repeat == 1)) {
+	endTimer(lint, "Parsing");
     }
 
-    if (dropdtd) {
+    if (lint->dropdtd) {
 	xmlDtdPtr dtd;
 
 	dtd = xmlGetIntSubset(doc);
@@ -2096,68 +2179,70 @@ parseAndPrintFile(const char *filename, xmlParserCtxtPtr rectxt) {
     }
 
 #ifdef LIBXML_XINCLUDE_ENABLED
-    if (xinclude) {
-	if ((timing) && (!repeat)) {
-	    startTimer();
+    if (lint->xinclude) {
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    startTimer(lint);
 	}
-	if (xmlXIncludeProcessFlags(doc, options) < 0)
-	    progresult = XMLLINT_ERR_UNCLASS;
-	if ((timing) && (!repeat)) {
-	    endTimer("Xinclude processing");
+	if (xmlXIncludeProcessFlags(doc, lint->options) < 0) {
+	    lint->progresult = XMLLINT_ERR_UNCLASS;
+            goto done;
+        }
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    endTimer(lint, "Xinclude processing");
 	}
     }
 #endif
 
-#ifdef LIBXML_XPATH_ENABLED
-    if (xpathquery != NULL) {
-        doXPathQuery(doc, xpathquery);
-    }
-#endif
-
-#ifndef XMLLINT_FUZZ
     /*
      * shell interaction
      */
-    if (shell) {
+    if (lint->shell) {
 #ifdef LIBXML_XPATH_ENABLED
         xmlXPathOrderDocElems(doc);
 #endif
         xmllintShell(doc, filename, stdout);
+        goto done;
+    }
+
+#ifdef LIBXML_XPATH_ENABLED
+    if (lint->xpathquery != NULL) {
+	xmlXPathOrderDocElems(doc);
+        doXPathQuery(lint, doc, lint->xpathquery);
     }
 #endif
 
     /*
      * test intermediate copy if needed.
      */
-    if (copy) {
+    if (lint->copy) {
         xmlDocPtr tmp;
 
         tmp = doc;
-	if (timing) {
-	    startTimer();
+	if (lint->timing) {
+	    startTimer(lint);
 	}
 	doc = xmlCopyDoc(doc, 1);
         if (doc == NULL) {
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             xmlFreeDoc(tmp);
             return;
         }
-	if (timing) {
-	    endTimer("Copying");
+	if (lint->timing) {
+	    endTimer(lint, "Copying");
 	}
-	if (timing) {
-	    startTimer();
+	if (lint->timing) {
+	    startTimer(lint);
 	}
 	xmlFreeDoc(tmp);
-	if (timing) {
-	    endTimer("Freeing original");
+	if (lint->timing) {
+	    endTimer(lint, "Freeing original");
 	}
     }
 
 #ifdef LIBXML_VALID_ENABLED
-    if ((insert)
+    if ((lint->insert)
 #ifdef LIBXML_HTML_ENABLED
-        && (!html)
+        && (!lint->html)
 #endif
     ) {
         const xmlChar* list[256];
@@ -2173,204 +2258,211 @@ parseAndPrintFile(const char *filename, xmlParserCtxtPtr rectxt) {
 	    if (node != NULL) {
 		nb = xmlValidGetValidElements(node->last, NULL, list, 256);
 		if (nb < 0) {
-		    fprintf(ERR_STREAM, "could not get valid list of elements\n");
+		    fprintf(errStream, "could not get valid list of elements\n");
 		} else if (nb == 0) {
-		    fprintf(ERR_STREAM, "No element can be inserted under root\n");
+		    fprintf(errStream, "No element can be inserted under root\n");
 		} else {
-		    fprintf(ERR_STREAM, "%d element types can be inserted under root:\n",
+		    fprintf(errStream, "%d element types can be inserted under root:\n",
 		           nb);
 		    for (i = 0;i < nb;i++) {
-			 fprintf(ERR_STREAM, "%s\n", (char *) list[i]);
+			 fprintf(errStream, "%s\n", (char *) list[i]);
 		    }
 		}
 	    }
 	}
-    }else
+    } else
 #endif /* LIBXML_VALID_ENABLED */
 #ifdef LIBXML_READER_ENABLED
-    if (walker) {
-        walkDoc(doc);
+    if (lint->walker) {
+        walkDoc(lint, doc);
     }
 #endif /* LIBXML_READER_ENABLED */
 #ifdef LIBXML_OUTPUT_ENABLED
-    if (noout == 0) {
-        if (compress)
+    if (lint->noout == 0) {
+        if (lint->compress)
             xmlSetDocCompressMode(doc, 9);
 
 	/*
 	 * print it.
 	 */
 #ifdef LIBXML_DEBUG_ENABLED
-	if (!debug) {
+	if (!lint->debug) {
 #endif
-	    if ((timing) && (!repeat)) {
-		startTimer();
+	    if ((lint->timing) && (lint->repeat == 1)) {
+		startTimer(lint);
 	    }
 #ifdef LIBXML_HTML_ENABLED
-            if ((html) && (!xmlout)) {
-		if (compress) {
-		    htmlSaveFile(output ? output : "-", doc);
+            if ((lint->html) && (!lint->xmlout)) {
+		if (lint->compress) {
+		    htmlSaveFile(lint->output ? lint->output : "-", doc);
 		}
-		else if (encoding != NULL) {
-		    if (format == 1) {
-			htmlSaveFileFormat(output ? output : "-", doc, encoding, 1);
+		else if (lint->encoding != NULL) {
+		    if (lint->format == 1) {
+			htmlSaveFileFormat(lint->output ? lint->output : "-",
+                                           doc, lint->encoding, 1);
 		    }
 		    else {
-			htmlSaveFileFormat(output ? output : "-", doc, encoding, 0);
+			htmlSaveFileFormat(lint->output ? lint->output : "-",
+                                           doc, lint->encoding, 0);
 		    }
 		}
-		else if (format == 1) {
-		    htmlSaveFileFormat(output ? output : "-", doc, NULL, 1);
+		else if (lint->format == 1) {
+		    htmlSaveFileFormat(lint->output ? lint->output : "-",
+                                       doc, NULL, 1);
 		}
 		else {
 		    FILE *out;
-		    if (output == NULL)
+		    if (lint->output == NULL)
 			out = stdout;
 		    else {
-			out = fopen(output,"wb");
+			out = fopen(lint->output,"wb");
 		    }
 		    if (out != NULL) {
 			if (htmlDocDump(out, doc) < 0)
-			    progresult = XMLLINT_ERR_OUT;
+			    lint->progresult = XMLLINT_ERR_OUT;
 
-			if (output != NULL)
+			if (lint->output != NULL)
 			    fclose(out);
 		    } else {
-			fprintf(ERR_STREAM, "failed to open %s\n", output);
-			progresult = XMLLINT_ERR_OUT;
+			fprintf(errStream, "failed to open %s\n",
+                                lint->output);
+			lint->progresult = XMLLINT_ERR_OUT;
 		    }
 		}
-		if ((timing) && (!repeat)) {
-		    endTimer("Saving");
+		if ((lint->timing) && (lint->repeat == 1)) {
+		    endTimer(lint, "Saving");
 		}
 	    } else
 #endif
 #ifdef LIBXML_C14N_ENABLED
-            if (canonical) {
+            if (lint->canonical) {
 	        xmlChar *result = NULL;
 		int size;
 
 		size = xmlC14NDocDumpMemory(doc, NULL, XML_C14N_1_0, NULL, 1, &result);
 		if (size >= 0) {
 		    if (write(1, result, size) == -1) {
-		        fprintf(ERR_STREAM, "Can't write data\n");
+		        fprintf(errStream, "Can't write data\n");
 		    }
 		    xmlFree(result);
 		} else {
-		    fprintf(ERR_STREAM, "Failed to canonicalize\n");
-		    progresult = XMLLINT_ERR_OUT;
+		    fprintf(errStream, "Failed to canonicalize\n");
+		    lint->progresult = XMLLINT_ERR_OUT;
 		}
-	    } else if (canonical_11) {
+	    } else if (lint->canonical_11) {
 	        xmlChar *result = NULL;
 		int size;
 
 		size = xmlC14NDocDumpMemory(doc, NULL, XML_C14N_1_1, NULL, 1, &result);
 		if (size >= 0) {
 		    if (write(1, result, size) == -1) {
-		        fprintf(ERR_STREAM, "Can't write data\n");
+		        fprintf(errStream, "Can't write data\n");
 		    }
 		    xmlFree(result);
 		} else {
-		    fprintf(ERR_STREAM, "Failed to canonicalize\n");
-		    progresult = XMLLINT_ERR_OUT;
+		    fprintf(errStream, "Failed to canonicalize\n");
+		    lint->progresult = XMLLINT_ERR_OUT;
 		}
-	    } else
-            if (exc_canonical) {
+	    } else if (lint->exc_canonical) {
 	        xmlChar *result = NULL;
 		int size;
 
 		size = xmlC14NDocDumpMemory(doc, NULL, XML_C14N_EXCLUSIVE_1_0, NULL, 1, &result);
 		if (size >= 0) {
 		    if (write(1, result, size) == -1) {
-		        fprintf(ERR_STREAM, "Can't write data\n");
+		        fprintf(errStream, "Can't write data\n");
 		    }
 		    xmlFree(result);
 		} else {
-		    fprintf(ERR_STREAM, "Failed to canonicalize\n");
-		    progresult = XMLLINT_ERR_OUT;
+		    fprintf(errStream, "Failed to canonicalize\n");
+		    lint->progresult = XMLLINT_ERR_OUT;
 		}
 	    } else
 #endif
 #if HAVE_DECL_MMAP
-	    if (memory) {
+	    if (lint->memory) {
 		xmlChar *result;
 		int len;
 
-		if (encoding != NULL) {
-		    if (format == 1) {
-		        xmlDocDumpFormatMemoryEnc(doc, &result, &len, encoding, 1);
+		if (lint->encoding != NULL) {
+		    if (lint->format == 1) {
+		        xmlDocDumpFormatMemoryEnc(doc, &result, &len,
+                                                  lint->encoding, 1);
 		    } else {
-			xmlDocDumpMemoryEnc(doc, &result, &len, encoding);
+			xmlDocDumpMemoryEnc(doc, &result, &len,
+                                            lint->encoding);
 		    }
 		} else {
-		    if (format == 1)
+		    if (lint->format == 1)
 			xmlDocDumpFormatMemory(doc, &result, &len, 1);
 		    else
 			xmlDocDumpMemory(doc, &result, &len);
 		}
 		if (result == NULL) {
-		    fprintf(ERR_STREAM, "Failed to save\n");
-		    progresult = XMLLINT_ERR_OUT;
+		    fprintf(errStream, "Failed to save\n");
+		    lint->progresult = XMLLINT_ERR_OUT;
 		} else {
 		    if (write(1, result, len) == -1) {
-		        fprintf(ERR_STREAM, "Can't write data\n");
+		        fprintf(errStream, "Can't write data\n");
 		    }
 		    xmlFree(result);
 		}
 
 	    } else
 #endif /* HAVE_DECL_MMAP */
-	    if (compress) {
-		xmlSaveFile(output ? output : "-", doc);
+	    if (lint->compress) {
+		xmlSaveFile(lint->output ? lint->output : "-", doc);
 	    } else {
 	        xmlSaveCtxtPtr ctxt;
 		int saveOpts = 0;
 
-                if (format == 1)
+                if (lint->format == 1)
 		    saveOpts |= XML_SAVE_FORMAT;
-                else if (format == 2)
+                else if (lint->format == 2)
                     saveOpts |= XML_SAVE_WSNONSIG;
 
 #if defined(LIBXML_HTML_ENABLED)
-                if (xmlout)
+                if (lint->xmlout)
                     saveOpts |= XML_SAVE_AS_XML;
 #endif
 
-		if (output == NULL)
-		    ctxt = xmlSaveToFd(1, encoding, saveOpts);
+		if (lint->output == NULL)
+		    ctxt = xmlSaveToFd(STDOUT_FILENO, lint->encoding,
+                                       saveOpts);
 		else
-		    ctxt = xmlSaveToFilename(output, encoding, saveOpts);
+		    ctxt = xmlSaveToFilename(lint->output, lint->encoding,
+                                             saveOpts);
 
 		if (ctxt != NULL) {
 		    if (xmlSaveDoc(ctxt, doc) < 0) {
-			fprintf(ERR_STREAM, "failed save to %s\n",
-				output ? output : "-");
-			progresult = XMLLINT_ERR_OUT;
+			fprintf(errStream, "failed save to %s\n",
+				lint->output ? lint->output : "-");
+			lint->progresult = XMLLINT_ERR_OUT;
 		    }
 		    xmlSaveClose(ctxt);
 		} else {
-		    progresult = XMLLINT_ERR_OUT;
+		    lint->progresult = XMLLINT_ERR_OUT;
 		}
 	    }
-	    if ((timing) && (!repeat)) {
-		endTimer("Saving");
+	    if ((lint->timing) && (lint->repeat == 1)) {
+		endTimer(lint, "Saving");
 	    }
 #ifdef LIBXML_DEBUG_ENABLED
 	} else {
 	    FILE *out;
-	    if (output == NULL)
+	    if (lint->output == NULL)
 	        out = stdout;
 	    else {
-		out = fopen(output,"wb");
+		out = fopen(lint->output, "wb");
 	    }
 	    if (out != NULL) {
 		xmlDebugDumpDocument(out, doc);
 
-		if (output != NULL)
+		if (lint->output != NULL)
 		    fclose(out);
 	    } else {
-		fprintf(ERR_STREAM, "failed to open %s\n", output);
-		progresult = XMLLINT_ERR_OUT;
+		fprintf(errStream, "failed to open %s\n", lint->output);
+		lint->progresult = XMLLINT_ERR_OUT;
 	    }
 	}
 #endif
@@ -2381,210 +2473,210 @@ parseAndPrintFile(const char *filename, xmlParserCtxtPtr rectxt) {
     /*
      * A posteriori validation test
      */
-    if ((dtdvalid != NULL) || (dtdvalidfpi != NULL)) {
+    if ((lint->dtdvalid != NULL) || (lint->dtdvalidfpi != NULL)) {
 	xmlDtdPtr dtd;
 
-	if ((timing) && (!repeat)) {
-	    startTimer();
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    startTimer(lint);
 	}
-	if (dtdvalid != NULL)
-	    dtd = xmlParseDTD(NULL, (const xmlChar *)dtdvalid);
+	if (lint->dtdvalid != NULL)
+	    dtd = xmlParseDTD(NULL, BAD_CAST lint->dtdvalid);
 	else
-	    dtd = xmlParseDTD((const xmlChar *)dtdvalidfpi, NULL);
-	if ((timing) && (!repeat)) {
-	    endTimer("Parsing DTD");
+	    dtd = xmlParseDTD(BAD_CAST lint->dtdvalidfpi, NULL);
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    endTimer(lint, "Parsing DTD");
 	}
 	if (dtd == NULL) {
-	    if (dtdvalid != NULL)
-		fprintf(ERR_STREAM,
-			"Could not parse DTD %s\n", dtdvalid);
+	    if (lint->dtdvalid != NULL)
+		fprintf(errStream, "Could not parse DTD %s\n",
+                        lint->dtdvalid);
 	    else
-		fprintf(ERR_STREAM,
-			"Could not parse DTD %s\n", dtdvalidfpi);
-	    progresult = XMLLINT_ERR_DTD;
+		fprintf(errStream, "Could not parse DTD %s\n",
+                        lint->dtdvalidfpi);
+	    lint->progresult = XMLLINT_ERR_DTD;
 	} else {
 	    xmlValidCtxtPtr cvp;
 
 	    cvp = xmlNewValidCtxt();
 	    if (cvp == NULL) {
-		fprintf(ERR_STREAM,
-			"Couldn't allocate validation context\n");
-                progresult = XMLLINT_ERR_MEM;
+                lint->progresult = XMLLINT_ERR_MEM;
                 xmlFreeDtd(dtd);
                 return;
 	    }
 
-	    if ((timing) && (!repeat)) {
-		startTimer();
+	    if ((lint->timing) && (lint->repeat == 1)) {
+		startTimer(lint);
 	    }
 	    if (!xmlValidateDtd(cvp, doc, dtd)) {
-		if (dtdvalid != NULL)
-		    fprintf(ERR_STREAM,
+		if (lint->dtdvalid != NULL)
+		    fprintf(errStream,
 			    "Document %s does not validate against %s\n",
-			    filename, dtdvalid);
+			    filename, lint->dtdvalid);
 		else
-		    fprintf(ERR_STREAM,
+		    fprintf(errStream,
 			    "Document %s does not validate against %s\n",
-			    filename, dtdvalidfpi);
-		progresult = XMLLINT_ERR_VALID;
+			    filename, lint->dtdvalidfpi);
+		lint->progresult = XMLLINT_ERR_VALID;
 	    }
-	    if ((timing) && (!repeat)) {
-		endTimer("Validating against DTD");
+	    if ((lint->timing) && (lint->repeat == 1)) {
+		endTimer(lint, "Validating against DTD");
 	    }
 	    xmlFreeValidCtxt(cvp);
 	    xmlFreeDtd(dtd);
 	}
-    } else if (postvalid) {
+    } else if (lint->postvalid) {
 	xmlValidCtxtPtr cvp;
 
 	cvp = xmlNewValidCtxt();
 	if (cvp == NULL) {
-	    fprintf(ERR_STREAM,
-		    "Couldn't allocate validation context\n");
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             xmlFreeDoc(doc);
             return;
 	}
 
-	if ((timing) && (!repeat)) {
-	    startTimer();
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    startTimer(lint);
 	}
 	if (!xmlValidateDocument(cvp, doc)) {
-	    fprintf(ERR_STREAM,
+	    fprintf(errStream,
 		    "Document %s does not validate\n", filename);
-	    progresult = XMLLINT_ERR_VALID;
+	    lint->progresult = XMLLINT_ERR_VALID;
 	}
-	if ((timing) && (!repeat)) {
-	    endTimer("Validating");
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    endTimer(lint, "Validating");
 	}
 	xmlFreeValidCtxt(cvp);
     }
 #endif /* LIBXML_VALID_ENABLED */
 #ifdef LIBXML_SCHEMATRON_ENABLED
-    if (wxschematron != NULL) {
+    if (lint->wxschematron != NULL) {
 	xmlSchematronValidCtxtPtr ctxt;
 	int ret;
 	int flag;
 
-	if ((timing) && (!repeat)) {
-	    startTimer();
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    startTimer(lint);
 	}
 
-	if (debug)
+	if (lint->debug)
 	    flag = XML_SCHEMATRON_OUT_XML;
 	else
 	    flag = XML_SCHEMATRON_OUT_TEXT;
-	if (noout)
+	if (lint->noout)
 	    flag |= XML_SCHEMATRON_OUT_QUIET;
-	ctxt = xmlSchematronNewValidCtxt(wxschematron, flag);
+	ctxt = xmlSchematronNewValidCtxt(lint->wxschematron, flag);
         if (ctxt == NULL) {
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             xmlFreeDoc(doc);
             return;
         }
 	ret = xmlSchematronValidateDoc(ctxt, doc);
 	if (ret == 0) {
-	    if (!quiet) {
-	        fprintf(ERR_STREAM, "%s validates\n", filename);
+	    if (!lint->quiet) {
+	        fprintf(errStream, "%s validates\n", filename);
 	    }
 	} else if (ret > 0) {
-	    fprintf(ERR_STREAM, "%s fails to validate\n", filename);
-	    progresult = XMLLINT_ERR_VALID;
+	    fprintf(errStream, "%s fails to validate\n", filename);
+	    lint->progresult = XMLLINT_ERR_VALID;
 	} else {
-	    fprintf(ERR_STREAM, "%s validation generated an internal error\n",
+	    fprintf(errStream, "%s validation generated an internal error\n",
 		   filename);
-	    progresult = XMLLINT_ERR_VALID;
+	    lint->progresult = XMLLINT_ERR_VALID;
 	}
 	xmlSchematronFreeValidCtxt(ctxt);
-	if ((timing) && (!repeat)) {
-	    endTimer("Validating");
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    endTimer(lint, "Validating");
 	}
     }
 #endif
 #ifdef LIBXML_SCHEMAS_ENABLED
-    if (relaxngschemas != NULL) {
+    if (lint->relaxngschemas != NULL) {
 	xmlRelaxNGValidCtxtPtr ctxt;
 	int ret;
 
-	if ((timing) && (!repeat)) {
-	    startTimer();
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    startTimer(lint);
 	}
 
-	ctxt = xmlRelaxNGNewValidCtxt(relaxngschemas);
+	ctxt = xmlRelaxNGNewValidCtxt(lint->relaxngschemas);
         if (ctxt == NULL) {
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             xmlFreeDoc(doc);
             return;
         }
 	ret = xmlRelaxNGValidateDoc(ctxt, doc);
 	if (ret == 0) {
-	    if (!quiet) {
-	        fprintf(ERR_STREAM, "%s validates\n", filename);
+	    if (!lint->quiet) {
+	        fprintf(errStream, "%s validates\n", filename);
 	    }
 	} else if (ret > 0) {
-	    fprintf(ERR_STREAM, "%s fails to validate\n", filename);
-	    progresult = XMLLINT_ERR_VALID;
+	    fprintf(errStream, "%s fails to validate\n", filename);
+	    lint->progresult = XMLLINT_ERR_VALID;
 	} else {
-	    fprintf(ERR_STREAM, "%s validation generated an internal error\n",
+	    fprintf(errStream, "%s validation generated an internal error\n",
 		   filename);
-	    progresult = XMLLINT_ERR_VALID;
+	    lint->progresult = XMLLINT_ERR_VALID;
 	}
 	xmlRelaxNGFreeValidCtxt(ctxt);
-	if ((timing) && (!repeat)) {
-	    endTimer("Validating");
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    endTimer(lint, "Validating");
 	}
-    } else if (wxschemas != NULL) {
+    } else if (lint->wxschemas != NULL) {
 	xmlSchemaValidCtxtPtr ctxt;
 	int ret;
 
-	if ((timing) && (!repeat)) {
-	    startTimer();
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    startTimer(lint);
 	}
 
-	ctxt = xmlSchemaNewValidCtxt(wxschemas);
+	ctxt = xmlSchemaNewValidCtxt(lint->wxschemas);
         if (ctxt == NULL) {
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             xmlFreeDoc(doc);
             return;
         }
 	ret = xmlSchemaValidateDoc(ctxt, doc);
 	if (ret == 0) {
-	    if (!quiet) {
-	        fprintf(ERR_STREAM, "%s validates\n", filename);
+	    if (!lint->quiet) {
+	        fprintf(errStream, "%s validates\n", filename);
 	    }
 	} else if (ret > 0) {
-	    fprintf(ERR_STREAM, "%s fails to validate\n", filename);
-	    progresult = XMLLINT_ERR_VALID;
+	    fprintf(errStream, "%s fails to validate\n", filename);
+	    lint->progresult = XMLLINT_ERR_VALID;
 	} else {
-	    fprintf(ERR_STREAM, "%s validation generated an internal error\n",
+	    fprintf(errStream, "%s validation generated an internal error\n",
 		   filename);
-	    progresult = XMLLINT_ERR_VALID;
+	    lint->progresult = XMLLINT_ERR_VALID;
 	}
 	xmlSchemaFreeValidCtxt(ctxt);
-	if ((timing) && (!repeat)) {
-	    endTimer("Validating");
+	if ((lint->timing) && (lint->repeat == 1)) {
+	    endTimer(lint, "Validating");
 	}
     }
 #endif
 
 #ifdef LIBXML_DEBUG_ENABLED
-    if ((debugent)
+    if ((lint->debugent)
 #if defined(LIBXML_HTML_ENABLED)
-        && (!html)
+        && (!lint->html)
 #endif
     )
-	xmlDebugDumpEntities(ERR_STREAM, doc);
+	xmlDebugDumpEntities(errStream, doc);
 #endif
 
+    /* Avoid unused label warning */
+    goto done;
+
+done:
     /*
      * free it.
      */
-    if ((timing) && (!repeat)) {
-	startTimer();
+    if ((lint->timing) && (lint->repeat == 1)) {
+	startTimer(lint);
     }
     xmlFreeDoc(doc);
-    if ((timing) && (!repeat)) {
-	endTimer("Freeing");
+    if ((lint->timing) && (lint->repeat == 1)) {
+	endTimer(lint, "Freeing");
     }
 }
 
@@ -2594,40 +2686,40 @@ parseAndPrintFile(const char *filename, xmlParserCtxtPtr rectxt) {
  *									*
  ************************************************************************/
 
-static void showVersion(const char *name) {
-    fprintf(ERR_STREAM, "%s: using libxml version %s\n", name, xmlParserVersion);
-    fprintf(ERR_STREAM, "   compiled with: ");
-    if (xmlHasFeature(XML_WITH_THREAD)) fprintf(ERR_STREAM, "Threads ");
-    if (xmlHasFeature(XML_WITH_TREE)) fprintf(ERR_STREAM, "Tree ");
-    if (xmlHasFeature(XML_WITH_OUTPUT)) fprintf(ERR_STREAM, "Output ");
-    if (xmlHasFeature(XML_WITH_PUSH)) fprintf(ERR_STREAM, "Push ");
-    if (xmlHasFeature(XML_WITH_READER)) fprintf(ERR_STREAM, "Reader ");
-    if (xmlHasFeature(XML_WITH_PATTERN)) fprintf(ERR_STREAM, "Patterns ");
-    if (xmlHasFeature(XML_WITH_WRITER)) fprintf(ERR_STREAM, "Writer ");
-    if (xmlHasFeature(XML_WITH_SAX1)) fprintf(ERR_STREAM, "SAXv1 ");
-    if (xmlHasFeature(XML_WITH_HTTP)) fprintf(ERR_STREAM, "HTTP ");
-    if (xmlHasFeature(XML_WITH_VALID)) fprintf(ERR_STREAM, "DTDValid ");
-    if (xmlHasFeature(XML_WITH_HTML)) fprintf(ERR_STREAM, "HTML ");
-    if (xmlHasFeature(XML_WITH_LEGACY)) fprintf(ERR_STREAM, "Legacy ");
-    if (xmlHasFeature(XML_WITH_C14N)) fprintf(ERR_STREAM, "C14N ");
-    if (xmlHasFeature(XML_WITH_CATALOG)) fprintf(ERR_STREAM, "Catalog ");
-    if (xmlHasFeature(XML_WITH_XPATH)) fprintf(ERR_STREAM, "XPath ");
-    if (xmlHasFeature(XML_WITH_XPTR)) fprintf(ERR_STREAM, "XPointer ");
-    if (xmlHasFeature(XML_WITH_XINCLUDE)) fprintf(ERR_STREAM, "XInclude ");
-    if (xmlHasFeature(XML_WITH_ICONV)) fprintf(ERR_STREAM, "Iconv ");
-    if (xmlHasFeature(XML_WITH_ICU)) fprintf(ERR_STREAM, "ICU ");
-    if (xmlHasFeature(XML_WITH_ISO8859X)) fprintf(ERR_STREAM, "ISO8859X ");
-    if (xmlHasFeature(XML_WITH_UNICODE)) fprintf(ERR_STREAM, "Unicode ");
-    if (xmlHasFeature(XML_WITH_REGEXP)) fprintf(ERR_STREAM, "Regexps ");
-    if (xmlHasFeature(XML_WITH_AUTOMATA)) fprintf(ERR_STREAM, "Automata ");
-    if (xmlHasFeature(XML_WITH_EXPR)) fprintf(ERR_STREAM, "Expr ");
-    if (xmlHasFeature(XML_WITH_SCHEMAS)) fprintf(ERR_STREAM, "Schemas ");
-    if (xmlHasFeature(XML_WITH_SCHEMATRON)) fprintf(ERR_STREAM, "Schematron ");
-    if (xmlHasFeature(XML_WITH_MODULES)) fprintf(ERR_STREAM, "Modules ");
-    if (xmlHasFeature(XML_WITH_DEBUG)) fprintf(ERR_STREAM, "Debug ");
-    if (xmlHasFeature(XML_WITH_ZLIB)) fprintf(ERR_STREAM, "Zlib ");
-    if (xmlHasFeature(XML_WITH_LZMA)) fprintf(ERR_STREAM, "Lzma ");
-    fprintf(ERR_STREAM, "\n");
+static void showVersion(FILE *errStream, const char *name) {
+    fprintf(errStream, "%s: using libxml version %s\n", name, xmlParserVersion);
+    fprintf(errStream, "   compiled with: ");
+    if (xmlHasFeature(XML_WITH_THREAD)) fprintf(errStream, "Threads ");
+    if (xmlHasFeature(XML_WITH_TREE)) fprintf(errStream, "Tree ");
+    if (xmlHasFeature(XML_WITH_OUTPUT)) fprintf(errStream, "Output ");
+    if (xmlHasFeature(XML_WITH_PUSH)) fprintf(errStream, "Push ");
+    if (xmlHasFeature(XML_WITH_READER)) fprintf(errStream, "Reader ");
+    if (xmlHasFeature(XML_WITH_PATTERN)) fprintf(errStream, "Patterns ");
+    if (xmlHasFeature(XML_WITH_WRITER)) fprintf(errStream, "Writer ");
+    if (xmlHasFeature(XML_WITH_SAX1)) fprintf(errStream, "SAXv1 ");
+    if (xmlHasFeature(XML_WITH_HTTP)) fprintf(errStream, "HTTP ");
+    if (xmlHasFeature(XML_WITH_VALID)) fprintf(errStream, "DTDValid ");
+    if (xmlHasFeature(XML_WITH_HTML)) fprintf(errStream, "HTML ");
+    if (xmlHasFeature(XML_WITH_LEGACY)) fprintf(errStream, "Legacy ");
+    if (xmlHasFeature(XML_WITH_C14N)) fprintf(errStream, "C14N ");
+    if (xmlHasFeature(XML_WITH_CATALOG)) fprintf(errStream, "Catalog ");
+    if (xmlHasFeature(XML_WITH_XPATH)) fprintf(errStream, "XPath ");
+    if (xmlHasFeature(XML_WITH_XPTR)) fprintf(errStream, "XPointer ");
+    if (xmlHasFeature(XML_WITH_XINCLUDE)) fprintf(errStream, "XInclude ");
+    if (xmlHasFeature(XML_WITH_ICONV)) fprintf(errStream, "Iconv ");
+    if (xmlHasFeature(XML_WITH_ICU)) fprintf(errStream, "ICU ");
+    if (xmlHasFeature(XML_WITH_ISO8859X)) fprintf(errStream, "ISO8859X ");
+    if (xmlHasFeature(XML_WITH_UNICODE)) fprintf(errStream, "Unicode ");
+    if (xmlHasFeature(XML_WITH_REGEXP)) fprintf(errStream, "Regexps ");
+    if (xmlHasFeature(XML_WITH_AUTOMATA)) fprintf(errStream, "Automata ");
+    if (xmlHasFeature(XML_WITH_EXPR)) fprintf(errStream, "Expr ");
+    if (xmlHasFeature(XML_WITH_SCHEMAS)) fprintf(errStream, "Schemas ");
+    if (xmlHasFeature(XML_WITH_SCHEMATRON)) fprintf(errStream, "Schematron ");
+    if (xmlHasFeature(XML_WITH_MODULES)) fprintf(errStream, "Modules ");
+    if (xmlHasFeature(XML_WITH_DEBUG)) fprintf(errStream, "Debug ");
+    if (xmlHasFeature(XML_WITH_ZLIB)) fprintf(errStream, "Zlib ");
+    if (xmlHasFeature(XML_WITH_LZMA)) fprintf(errStream, "Lzma ");
+    fprintf(errStream, "\n");
 }
 
 static void usage(FILE *f, const char *name) {
@@ -2709,7 +2801,8 @@ static void usage(FILE *f, const char *name) {
 #ifdef LIBXML_CATALOG_ENABLED
     fprintf(f, "\t--catalogs : use SGML catalogs from $SGML_CATALOG_FILES\n");
     fprintf(f, "\t             otherwise XML Catalogs starting from \n");
-    fprintf(f, "\t         %s are activated by default\n", XML_XML_DEFAULT_CATALOG);
+    fprintf(f, "\t         file://" XML_SYSCONFDIR "/xml/catalog "
+            "are activated by default\n");
     fprintf(f, "\t--nocatalogs: deactivate all catalogs\n");
 #endif
     fprintf(f, "\t--auto : generate a small doc on the fly\n");
@@ -2748,7 +2841,7 @@ static void usage(FILE *f, const char *name) {
 }
 
 static unsigned long
-parseInteger(const char *ctxt, const char *str,
+parseInteger(FILE *errStream, const char *ctxt, const char *str,
              unsigned long min, unsigned long max) {
     char *strEnd;
     unsigned long val;
@@ -2756,11 +2849,11 @@ parseInteger(const char *ctxt, const char *str,
     errno = 0;
     val = strtoul(str, &strEnd, 10);
     if (errno == EINVAL || *strEnd != 0) {
-        fprintf(ERR_STREAM, "%s: invalid integer: %s\n", ctxt, str);
+        fprintf(errStream, "%s: invalid integer: %s\n", ctxt, str);
         exit(XMLLINT_ERR_UNCLASS);
     }
     if (errno != 0 || val < min || val > max) {
-        fprintf(ERR_STREAM, "%s: integer out of range: %s\n", ctxt, str);
+        fprintf(errStream, "%s: integer out of range: %s\n", ctxt, str);
         exit(XMLLINT_ERR_UNCLASS);
     }
 
@@ -2815,454 +2908,365 @@ skipArgs(const char *arg) {
     return(0);
 }
 
-static int
-xmllintMain(int argc, const char **argv, xmlResourceLoader loader) {
-    int i, acount;
-    int files = 0;
-    int version = 0;
-    int nowrap = 0;
-    int sax = 0;
-#ifdef LIBXML_READER_ENABLED
-    int stream = 0;
-#endif
-#ifdef LIBXML_CATALOG_ENABLED
-    int catalogs = 0;
-    int nocatalogs = 0;
-#endif
-
-    defaultResourceLoader = loader;
+static void
+xmllintInit(xmllintState *lint) {
+    memset(lint, 0, sizeof(*lint));
 
-#ifdef XMLLINT_FUZZ
-#ifdef LIBXML_DEBUG_ENABLED
-    shell = 0;
-    debugent = 0;
-#endif
-    debug = 0;
-    maxmem = 0;
-    copy = 0;
-    noout = 0;
-#ifdef LIBXML_OUTPUT_ENABLED
-    format = 0;
-    output = NULL;
-    compress = 0;
-#endif /* LIBXML_OUTPUT_ENABLED */
-#ifdef LIBXML_VALID_ENABLED
-    postvalid = 0;
-    dtdvalid = NULL;
-    dtdvalidfpi = NULL;
-    insert = 0;
-#endif
-#ifdef LIBXML_SCHEMAS_ENABLED
-    relaxng = NULL;
-    relaxngschemas = NULL;
-    schema = NULL;
-    wxschemas = NULL;
-#endif
-#ifdef LIBXML_SCHEMATRON_ENABLED
-    schematron = NULL;
-    wxschematron = NULL;
-#endif
-    repeat = 0;
-#if defined(LIBXML_HTML_ENABLED)
-    html = 0;
-    xmlout = 0;
-#endif
-    htmlout = 0;
-#ifdef LIBXML_PUSH_ENABLED
-    push = 0;
-#endif /* LIBXML_PUSH_ENABLED */
-#if HAVE_DECL_MMAP
-    memory = 0;
-    memoryData = NULL;
-    memorySize = 0;
-#endif
-    testIO = 0;
-    encoding = NULL;
-#ifdef LIBXML_XINCLUDE_ENABLED
-    xinclude = 0;
-#endif
-    progresult = XMLLINT_RETURN_OK;
-    quiet = 0;
-    timing = 0;
-    generate = 0;
-    dropdtd = 0;
-#ifdef LIBXML_C14N_ENABLED
-    canonical = 0;
-    canonical_11 = 0;
-    exc_canonical = 0;
-#endif
-#ifdef LIBXML_READER_ENABLED
-    walker = 0;
-#ifdef LIBXML_PATTERN_ENABLED
-    pattern = NULL;
-    patternc = NULL;
-    patstream = NULL;
-#endif
-#endif /* LIBXML_READER_ENABLED */
-#ifdef LIBXML_XPATH_ENABLED
-    xpathquery = NULL;
-#endif
-    options = XML_PARSE_COMPACT | XML_PARSE_BIG_LINES;
-    maxAmpl = 0;
-#endif /* XMLLINT_FUZZ */
+    lint->repeat = 1;
+    lint->progresult = XMLLINT_RETURN_OK;
+    lint->options = XML_PARSE_COMPACT | XML_PARSE_BIG_LINES;
+}
 
-#ifdef _WIN32
-    _setmode(_fileno(stdin), _O_BINARY);
-    _setmode(_fileno(stdout), _O_BINARY);
-    _setmode(_fileno(stderr), _O_BINARY);
-#endif
+static int
+xmllintParseOptions(xmllintState *lint, int argc, const char **argv) {
+    FILE *errStream = lint->errStream;
+    int i;
 
     if (argc <= 1) {
-	usage(ERR_STREAM, argv[0]);
-	return(XMLLINT_ERR_UNCLASS);
+        usage(errStream, argv[0]);
+        return(XMLLINT_ERR_UNCLASS);
     }
 
-    /* xmlMemSetup must be called before initializing the parser. */
     for (i = 1; i < argc ; i++) {
-	if ((!strcmp(argv[i], "-maxmem")) ||
-	    (!strcmp(argv[i], "--maxmem"))) {
+        if (argv[i][0] != '-' || argv[i][1] == 0)
+            continue;
+
+        if ((!strcmp(argv[i], "-maxmem")) ||
+            (!strcmp(argv[i], "--maxmem"))) {
             i++;
             if (i >= argc) {
-                fprintf(ERR_STREAM, "maxmem: missing integer value\n");
+                fprintf(errStream, "maxmem: missing integer value\n");
                 return(XMLLINT_ERR_UNCLASS);
             }
             errno = 0;
-            maxmem = parseInteger("maxmem", argv[i], 0, INT_MAX);
-        } else if (argv[i][0] == '-') {
-            i += skipArgs(argv[i]);
-	}
-    }
-    if (maxmem != 0)
-        xmlMemSetup(myFreeFunc, myMallocFunc, myReallocFunc, myStrdupFunc);
-
-    LIBXML_TEST_VERSION
-
-    for (i = 1; i < argc ; i++) {
-	if (argv[i][0] != '-' || argv[i][1] == 0)
-	    continue;
-
-	if ((!strcmp(argv[i], "-debug")) || (!strcmp(argv[i], "--debug")))
-	    debug++;
-	else
-	if ((!strcmp(argv[i], "-shell")) ||
-	         (!strcmp(argv[i], "--shell"))) {
-	    shell++;
-            noout = 1;
-        } else
-	if ((!strcmp(argv[i], "-copy")) || (!strcmp(argv[i], "--copy")))
-	    copy++;
-	else
-	if ((!strcmp(argv[i], "-recover")) ||
-	         (!strcmp(argv[i], "--recover"))) {
-	    options |= XML_PARSE_RECOVER;
-	} else if ((!strcmp(argv[i], "-huge")) ||
-	         (!strcmp(argv[i], "--huge"))) {
-	    options |= XML_PARSE_HUGE;
-	} else if ((!strcmp(argv[i], "-noent")) ||
-	         (!strcmp(argv[i], "--noent"))) {
-	    options |= XML_PARSE_NOENT;
-	} else if ((!strcmp(argv[i], "-noenc")) ||
-	         (!strcmp(argv[i], "--noenc"))) {
-	    options |= XML_PARSE_IGNORE_ENC;
-	} else if ((!strcmp(argv[i], "-nsclean")) ||
-	         (!strcmp(argv[i], "--nsclean"))) {
-	    options |= XML_PARSE_NSCLEAN;
-	} else if ((!strcmp(argv[i], "-nocdata")) ||
-	         (!strcmp(argv[i], "--nocdata"))) {
-	    options |= XML_PARSE_NOCDATA;
-	} else if ((!strcmp(argv[i], "-nodict")) ||
-	         (!strcmp(argv[i], "--nodict"))) {
-	    options |= XML_PARSE_NODICT;
-	} else if ((!strcmp(argv[i], "-version")) ||
-	         (!strcmp(argv[i], "--version"))) {
-	    showVersion(argv[0]);
-	    version = 1;
-	} else if ((!strcmp(argv[i], "-noout")) ||
-	         (!strcmp(argv[i], "--noout")))
-	    noout++;
-	else if ((!strcmp(argv[i], "-htmlout")) ||
-	         (!strcmp(argv[i], "--htmlout")))
-	    htmlout++;
-	else if ((!strcmp(argv[i], "-nowrap")) ||
-	         (!strcmp(argv[i], "--nowrap")))
-	    nowrap++;
+            lint->maxmem = parseInteger(errStream, "maxmem", argv[i],
+                                        0, INT_MAX);
+        } else if ((!strcmp(argv[i], "-debug")) ||
+                   (!strcmp(argv[i], "--debug"))) {
+            lint->debug = 1;
+        } else if ((!strcmp(argv[i], "-shell")) ||
+                   (!strcmp(argv[i], "--shell"))) {
+            lint->shell = 1;
+        } else if ((!strcmp(argv[i], "-copy")) ||
+                   (!strcmp(argv[i], "--copy"))) {
+            lint->copy = 1;
+        } else if ((!strcmp(argv[i], "-recover")) ||
+                   (!strcmp(argv[i], "--recover"))) {
+            lint->options |= XML_PARSE_RECOVER;
+        } else if ((!strcmp(argv[i], "-huge")) ||
+                   (!strcmp(argv[i], "--huge"))) {
+            lint->options |= XML_PARSE_HUGE;
+        } else if ((!strcmp(argv[i], "-noent")) ||
+                   (!strcmp(argv[i], "--noent"))) {
+            lint->options |= XML_PARSE_NOENT;
+        } else if ((!strcmp(argv[i], "-noenc")) ||
+                   (!strcmp(argv[i], "--noenc"))) {
+            lint->options |= XML_PARSE_IGNORE_ENC;
+        } else if ((!strcmp(argv[i], "-nsclean")) ||
+                   (!strcmp(argv[i], "--nsclean"))) {
+            lint->options |= XML_PARSE_NSCLEAN;
+        } else if ((!strcmp(argv[i], "-nocdata")) ||
+                   (!strcmp(argv[i], "--nocdata"))) {
+            lint->options |= XML_PARSE_NOCDATA;
+        } else if ((!strcmp(argv[i], "-nodict")) ||
+                   (!strcmp(argv[i], "--nodict"))) {
+            lint->options |= XML_PARSE_NODICT;
+        } else if ((!strcmp(argv[i], "-version")) ||
+                   (!strcmp(argv[i], "--version"))) {
+            showVersion(errStream, argv[0]);
+            lint->version = 1;
+        } else if ((!strcmp(argv[i], "-noout")) ||
+                   (!strcmp(argv[i], "--noout"))) {
+            lint->noout = 1;
+        } else if ((!strcmp(argv[i], "-htmlout")) ||
+                   (!strcmp(argv[i], "--htmlout"))) {
+            lint->htmlout = 1;
+        } else if ((!strcmp(argv[i], "-nowrap")) ||
+                   (!strcmp(argv[i], "--nowrap"))) {
+            lint->nowrap = 1;
 #ifdef LIBXML_HTML_ENABLED
-	else if ((!strcmp(argv[i], "-html")) ||
-	         (!strcmp(argv[i], "--html"))) {
-	    html++;
-        }
-	else if ((!strcmp(argv[i], "-xmlout")) ||
-	         (!strcmp(argv[i], "--xmlout"))) {
-	    xmlout++;
-	} else if ((!strcmp(argv[i], "-nodefdtd")) ||
-	         (!strcmp(argv[i], "--nodefdtd"))) {
-	    options |= HTML_PARSE_NODEFDTD;
-        }
+        } else if ((!strcmp(argv[i], "-html")) ||
+                   (!strcmp(argv[i], "--html"))) {
+            lint->html = 1;
+        } else if ((!strcmp(argv[i], "-xmlout")) ||
+                   (!strcmp(argv[i], "--xmlout"))) {
+            lint->xmlout = 1;
+        } else if ((!strcmp(argv[i], "-nodefdtd")) ||
+                   (!strcmp(argv[i], "--nodefdtd"))) {
+            lint->options |= HTML_PARSE_NODEFDTD;
 #endif /* LIBXML_HTML_ENABLED */
-	else if ((!strcmp(argv[i], "-loaddtd")) ||
-	         (!strcmp(argv[i], "--loaddtd"))) {
-	    options |= XML_PARSE_DTDLOAD;
-	} else if ((!strcmp(argv[i], "-dtdattr")) ||
-	         (!strcmp(argv[i], "--dtdattr"))) {
-	    options |= XML_PARSE_DTDATTR;
-	}
+        } else if ((!strcmp(argv[i], "-loaddtd")) ||
+                   (!strcmp(argv[i], "--loaddtd"))) {
+            lint->options |= XML_PARSE_DTDLOAD;
+        } else if ((!strcmp(argv[i], "-dtdattr")) ||
+                   (!strcmp(argv[i], "--dtdattr"))) {
+            lint->options |= XML_PARSE_DTDATTR;
 #ifdef LIBXML_VALID_ENABLED
-	else if ((!strcmp(argv[i], "-valid")) ||
-	         (!strcmp(argv[i], "--valid"))) {
-	    options |= XML_PARSE_DTDVALID;
-	} else if ((!strcmp(argv[i], "-postvalid")) ||
-	         (!strcmp(argv[i], "--postvalid"))) {
-	    postvalid++;
-	    options |= XML_PARSE_DTDLOAD;
-	} else if ((!strcmp(argv[i], "-dtdvalid")) ||
-	         (!strcmp(argv[i], "--dtdvalid"))) {
-	    i++;
-	    dtdvalid = argv[i];
-	    options |= XML_PARSE_DTDLOAD;
-	} else if ((!strcmp(argv[i], "-dtdvalidfpi")) ||
-	         (!strcmp(argv[i], "--dtdvalidfpi"))) {
-	    i++;
-	    dtdvalidfpi = argv[i];
-	    options |= XML_PARSE_DTDLOAD;
-        }
-	else if ((!strcmp(argv[i], "-insert")) ||
-	         (!strcmp(argv[i], "--insert")))
-	    insert++;
+        } else if ((!strcmp(argv[i], "-valid")) ||
+                   (!strcmp(argv[i], "--valid"))) {
+            lint->options |= XML_PARSE_DTDVALID;
+        } else if ((!strcmp(argv[i], "-postvalid")) ||
+                   (!strcmp(argv[i], "--postvalid"))) {
+            lint->postvalid = 1;
+            lint->options |= XML_PARSE_DTDLOAD;
+        } else if ((!strcmp(argv[i], "-dtdvalid")) ||
+                   (!strcmp(argv[i], "--dtdvalid"))) {
+            i++;
+            lint->dtdvalid = argv[i];
+            lint->options |= XML_PARSE_DTDLOAD;
+        } else if ((!strcmp(argv[i], "-dtdvalidfpi")) ||
+                   (!strcmp(argv[i], "--dtdvalidfpi"))) {
+            i++;
+            lint->dtdvalidfpi = argv[i];
+            lint->options |= XML_PARSE_DTDLOAD;
+        } else if ((!strcmp(argv[i], "-insert")) ||
+                   (!strcmp(argv[i], "--insert"))) {
+            lint->insert = 1;
 #endif /* LIBXML_VALID_ENABLED */
-	else if ((!strcmp(argv[i], "-dropdtd")) ||
-	         (!strcmp(argv[i], "--dropdtd")))
-	    dropdtd++;
-	else if ((!strcmp(argv[i], "-quiet")) ||
-	         (!strcmp(argv[i], "--quiet")))
-	    quiet++;
-	else if ((!strcmp(argv[i], "-timing")) ||
-	         (!strcmp(argv[i], "--timing")))
-	    timing++;
-	else if ((!strcmp(argv[i], "-auto")) ||
-	         (!strcmp(argv[i], "--auto")))
-	    generate++;
-	else if ((!strcmp(argv[i], "-repeat")) ||
-	         (!strcmp(argv[i], "--repeat"))) {
-	    if (repeat)
-	        repeat *= 10;
-	    else
-	        repeat = 100;
-	}
+        } else if ((!strcmp(argv[i], "-dropdtd")) ||
+                   (!strcmp(argv[i], "--dropdtd"))) {
+            lint->dropdtd = 1;
+        } else if ((!strcmp(argv[i], "-quiet")) ||
+                   (!strcmp(argv[i], "--quiet"))) {
+            lint->quiet = 1;
+        } else if ((!strcmp(argv[i], "-timing")) ||
+                   (!strcmp(argv[i], "--timing"))) {
+            lint->timing = 1;
+        } else if ((!strcmp(argv[i], "-auto")) ||
+                   (!strcmp(argv[i], "--auto"))) {
+            lint->generate = 1;
+        } else if ((!strcmp(argv[i], "-repeat")) ||
+                   (!strcmp(argv[i], "--repeat"))) {
+#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
+            lint->repeat = 2;
+#else
+            if (lint->repeat > 1)
+                lint->repeat *= 10;
+            else
+                lint->repeat = 100;
+#endif
 #ifdef LIBXML_PUSH_ENABLED
-	else if ((!strcmp(argv[i], "-push")) ||
-	         (!strcmp(argv[i], "--push")))
-	    push++;
+        } else if ((!strcmp(argv[i], "-push")) ||
+                   (!strcmp(argv[i], "--push"))) {
+            lint->push = 1;
 #endif /* LIBXML_PUSH_ENABLED */
 #if HAVE_DECL_MMAP
-	else if ((!strcmp(argv[i], "-memory")) ||
-	         (!strcmp(argv[i], "--memory")))
-	    memory++;
+        } else if ((!strcmp(argv[i], "-memory")) ||
+                   (!strcmp(argv[i], "--memory"))) {
+            lint->memory = 1;
 #endif
-	else if ((!strcmp(argv[i], "-testIO")) ||
-	         (!strcmp(argv[i], "--testIO")))
-	    testIO++;
+        } else if ((!strcmp(argv[i], "-testIO")) ||
+                   (!strcmp(argv[i], "--testIO"))) {
+            lint->testIO = 1;
 #ifdef LIBXML_XINCLUDE_ENABLED
-	else if ((!strcmp(argv[i], "-xinclude")) ||
-	         (!strcmp(argv[i], "--xinclude"))) {
-	    xinclude++;
-	    options |= XML_PARSE_XINCLUDE;
-	}
-	else if ((!strcmp(argv[i], "-noxincludenode")) ||
-	         (!strcmp(argv[i], "--noxincludenode"))) {
-	    xinclude++;
-	    options |= XML_PARSE_XINCLUDE;
-	    options |= XML_PARSE_NOXINCNODE;
-	}
-	else if ((!strcmp(argv[i], "-nofixup-base-uris")) ||
-	         (!strcmp(argv[i], "--nofixup-base-uris"))) {
-	    xinclude++;
-	    options |= XML_PARSE_XINCLUDE;
-	    options |= XML_PARSE_NOBASEFIX;
-	}
-#endif
-	else if ((!strcmp(argv[i], "-nowarning")) ||
-	         (!strcmp(argv[i], "--nowarning"))) {
-	    options |= XML_PARSE_NOWARNING;
-            options &= ~XML_PARSE_PEDANTIC;
-        }
-	else if ((!strcmp(argv[i], "-pedantic")) ||
-	         (!strcmp(argv[i], "--pedantic"))) {
-	    options |= XML_PARSE_PEDANTIC;
-            options &= ~XML_PARSE_NOWARNING;
-        }
+        } else if ((!strcmp(argv[i], "-xinclude")) ||
+                   (!strcmp(argv[i], "--xinclude"))) {
+            lint->xinclude = 1;
+            lint->options |= XML_PARSE_XINCLUDE;
+        } else if ((!strcmp(argv[i], "-noxincludenode")) ||
+                   (!strcmp(argv[i], "--noxincludenode"))) {
+            lint->xinclude = 1;
+            lint->options |= XML_PARSE_XINCLUDE;
+            lint->options |= XML_PARSE_NOXINCNODE;
+        } else if ((!strcmp(argv[i], "-nofixup-base-uris")) ||
+                   (!strcmp(argv[i], "--nofixup-base-uris"))) {
+            lint->xinclude = 1;
+            lint->options |= XML_PARSE_XINCLUDE;
+            lint->options |= XML_PARSE_NOBASEFIX;
+#endif
+        } else if ((!strcmp(argv[i], "-nowarning")) ||
+                   (!strcmp(argv[i], "--nowarning"))) {
+            lint->options |= XML_PARSE_NOWARNING;
+            lint->options &= ~XML_PARSE_PEDANTIC;
+        } else if ((!strcmp(argv[i], "-pedantic")) ||
+                   (!strcmp(argv[i], "--pedantic"))) {
+            lint->options |= XML_PARSE_PEDANTIC;
+            lint->options &= ~XML_PARSE_NOWARNING;
 #ifdef LIBXML_DEBUG_ENABLED
-	else if ((!strcmp(argv[i], "-debugent")) ||
-		 (!strcmp(argv[i], "--debugent"))) {
-	    debugent++;
-	}
+        } else if ((!strcmp(argv[i], "-debugent")) ||
+                   (!strcmp(argv[i], "--debugent"))) {
+            lint->debugent = 1;
 #endif
 #ifdef LIBXML_C14N_ENABLED
-	else if ((!strcmp(argv[i], "-c14n")) ||
-		 (!strcmp(argv[i], "--c14n"))) {
-	    canonical++;
-	    options |= XML_PARSE_NOENT | XML_PARSE_DTDATTR | XML_PARSE_DTDLOAD;
-	}
-	else if ((!strcmp(argv[i], "-c14n11")) ||
-		 (!strcmp(argv[i], "--c14n11"))) {
-	    canonical_11++;
-	    options |= XML_PARSE_NOENT | XML_PARSE_DTDATTR | XML_PARSE_DTDLOAD;
-	}
-	else if ((!strcmp(argv[i], "-exc-c14n")) ||
-		 (!strcmp(argv[i], "--exc-c14n"))) {
-	    exc_canonical++;
-	    options |= XML_PARSE_NOENT | XML_PARSE_DTDATTR | XML_PARSE_DTDLOAD;
-	}
+        } else if ((!strcmp(argv[i], "-c14n")) ||
+                   (!strcmp(argv[i], "--c14n"))) {
+            lint->canonical = 1;
+            lint->options |= XML_PARSE_NOENT | XML_PARSE_DTDATTR | XML_PARSE_DTDLOAD;
+        } else if ((!strcmp(argv[i], "-c14n11")) ||
+                   (!strcmp(argv[i], "--c14n11"))) {
+            lint->canonical_11 = 1;
+            lint->options |= XML_PARSE_NOENT | XML_PARSE_DTDATTR | XML_PARSE_DTDLOAD;
+        } else if ((!strcmp(argv[i], "-exc-c14n")) ||
+                   (!strcmp(argv[i], "--exc-c14n"))) {
+            lint->exc_canonical = 1;
+            lint->options |= XML_PARSE_NOENT | XML_PARSE_DTDATTR | XML_PARSE_DTDLOAD;
 #endif
 #ifdef LIBXML_CATALOG_ENABLED
-	else if ((!strcmp(argv[i], "-catalogs")) ||
-		 (!strcmp(argv[i], "--catalogs"))) {
-	    catalogs++;
-	} else if ((!strcmp(argv[i], "-nocatalogs")) ||
-		 (!strcmp(argv[i], "--nocatalogs"))) {
-	    nocatalogs++;
-	}
-#endif
-	else if ((!strcmp(argv[i], "-noblanks")) ||
-	         (!strcmp(argv[i], "--noblanks"))) {
-            options |= XML_PARSE_NOBLANKS;
-        }
-	else if ((!strcmp(argv[i], "-maxmem")) ||
-	         (!strcmp(argv[i], "--maxmem"))) {
-	     i++;
-        }
+        } else if ((!strcmp(argv[i], "-catalogs")) ||
+                   (!strcmp(argv[i], "--catalogs"))) {
+            lint->catalogs = 1;
+        } else if ((!strcmp(argv[i], "-nocatalogs")) ||
+                   (!strcmp(argv[i], "--nocatalogs"))) {
+            lint->nocatalogs = 1;
+#endif
+        } else if ((!strcmp(argv[i], "-noblanks")) ||
+                   (!strcmp(argv[i], "--noblanks"))) {
+            lint->options |= XML_PARSE_NOBLANKS;
 #ifdef LIBXML_OUTPUT_ENABLED
-	else if ((!strcmp(argv[i], "-o")) ||
-	         (!strcmp(argv[i], "-output")) ||
-	         (!strcmp(argv[i], "--output"))) {
-	    i++;
-	    output = argv[i];
-	}
-	else if ((!strcmp(argv[i], "-format")) ||
-	         (!strcmp(argv[i], "--format"))) {
-	    format = 1;
-            options |= XML_PARSE_NOBLANKS;
-	}
-	else if ((!strcmp(argv[i], "-encode")) ||
-	         (!strcmp(argv[i], "--encode"))) {
-	    i++;
-	    encoding = argv[i];
-	    /*
-	     * OK it's for testing purposes
-	     */
-	    xmlAddEncodingAlias("UTF-8", "DVEnc");
-        }
-	else if ((!strcmp(argv[i], "-pretty")) ||
-	         (!strcmp(argv[i], "--pretty"))) {
-	    i++;
+        } else if ((!strcmp(argv[i], "-o")) ||
+                   (!strcmp(argv[i], "-output")) ||
+                   (!strcmp(argv[i], "--output"))) {
+            i++;
+            lint->output = argv[i];
+        } else if ((!strcmp(argv[i], "-format")) ||
+                   (!strcmp(argv[i], "--format"))) {
+            lint->format = 1;
+            lint->options |= XML_PARSE_NOBLANKS;
+        } else if ((!strcmp(argv[i], "-encode")) ||
+                   (!strcmp(argv[i], "--encode"))) {
+            i++;
+            lint->encoding = argv[i];
+        } else if ((!strcmp(argv[i], "-pretty")) ||
+                   (!strcmp(argv[i], "--pretty"))) {
+            i++;
             if (argv[i] != NULL)
-	        format = atoi(argv[i]);
-	}
+                lint->format = atoi(argv[i]);
 #ifdef LIBXML_ZLIB_ENABLED
-	else if ((!strcmp(argv[i], "-compress")) ||
-	         (!strcmp(argv[i], "--compress"))) {
-	    compress++;
-        }
+        } else if ((!strcmp(argv[i], "-compress")) ||
+                   (!strcmp(argv[i], "--compress"))) {
+            lint->compress = 1;
 #endif
 #endif /* LIBXML_OUTPUT_ENABLED */
 #ifdef LIBXML_READER_ENABLED
-	else if ((!strcmp(argv[i], "-stream")) ||
-	         (!strcmp(argv[i], "--stream"))) {
-	     stream++;
-	}
-	else if ((!strcmp(argv[i], "-walker")) ||
-	         (!strcmp(argv[i], "--walker"))) {
-	     walker++;
-             noout++;
-        }
+        } else if ((!strcmp(argv[i], "-stream")) ||
+                   (!strcmp(argv[i], "--stream"))) {
+             lint->stream = 1;
+        } else if ((!strcmp(argv[i], "-walker")) ||
+                   (!strcmp(argv[i], "--walker"))) {
+             lint->walker = 1;
+             lint->noout = 1;
 #ifdef LIBXML_PATTERN_ENABLED
-        else if ((!strcmp(argv[i], "-pattern")) ||
+        } else if ((!strcmp(argv[i], "-pattern")) ||
                    (!strcmp(argv[i], "--pattern"))) {
-	    i++;
-	    pattern = argv[i];
-	}
+            i++;
+            lint->pattern = argv[i];
 #endif
 #endif /* LIBXML_READER_ENABLED */
 #ifdef LIBXML_SAX1_ENABLED
-	else if ((!strcmp(argv[i], "-sax1")) ||
-	         (!strcmp(argv[i], "--sax1"))) {
-	    options |= XML_PARSE_SAX1;
-	}
+        } else if ((!strcmp(argv[i], "-sax1")) ||
+                   (!strcmp(argv[i], "--sax1"))) {
+            lint->options |= XML_PARSE_SAX1;
 #endif /* LIBXML_SAX1_ENABLED */
-	else if ((!strcmp(argv[i], "-sax")) ||
-	         (!strcmp(argv[i], "--sax"))) {
-	    sax++;
-        }
+        } else if ((!strcmp(argv[i], "-sax")) ||
+                   (!strcmp(argv[i], "--sax"))) {
+            lint->sax = 1;
 #ifdef LIBXML_SCHEMAS_ENABLED
-	else if ((!strcmp(argv[i], "-relaxng")) ||
-	         (!strcmp(argv[i], "--relaxng"))) {
-	    i++;
-	    relaxng = argv[i];
-	    options |= XML_PARSE_NOENT;
-	} else if ((!strcmp(argv[i], "-schema")) ||
-	         (!strcmp(argv[i], "--schema"))) {
-	    i++;
-	    schema = argv[i];
-	    options |= XML_PARSE_NOENT;
-        }
+        } else if ((!strcmp(argv[i], "-relaxng")) ||
+                   (!strcmp(argv[i], "--relaxng"))) {
+            i++;
+            lint->relaxng = argv[i];
+            lint->options |= XML_PARSE_NOENT;
+        } else if ((!strcmp(argv[i], "-schema")) ||
+                 (!strcmp(argv[i], "--schema"))) {
+            i++;
+            lint->schema = argv[i];
+            lint->options |= XML_PARSE_NOENT;
 #endif
 #ifdef LIBXML_SCHEMATRON_ENABLED
-	else if ((!strcmp(argv[i], "-schematron")) ||
-	         (!strcmp(argv[i], "--schematron"))) {
-	    i++;
-	    schematron = argv[i];
-	    options |= XML_PARSE_NOENT;
-        }
+        } else if ((!strcmp(argv[i], "-schematron")) ||
+                   (!strcmp(argv[i], "--schematron"))) {
+            i++;
+            lint->schematron = argv[i];
+            lint->options |= XML_PARSE_NOENT;
 #endif
-        else if ((!strcmp(argv[i], "-nonet")) ||
+        } else if ((!strcmp(argv[i], "-nonet")) ||
                    (!strcmp(argv[i], "--nonet"))) {
-	    options |= XML_PARSE_NONET;
+            lint->options |= XML_PARSE_NONET;
         } else if ((!strcmp(argv[i], "-nocompact")) ||
                    (!strcmp(argv[i], "--nocompact"))) {
-	    options &= ~XML_PARSE_COMPACT;
-	} else if ((!strcmp(argv[i], "-load-trace")) ||
-	           (!strcmp(argv[i], "--load-trace"))) {
-	    load_trace++;
+            lint->options &= ~XML_PARSE_COMPACT;
+        } else if ((!strcmp(argv[i], "-load-trace")) ||
+                   (!strcmp(argv[i], "--load-trace"))) {
+            lint->load_trace = 1;
         } else if ((!strcmp(argv[i], "-path")) ||
                    (!strcmp(argv[i], "--path"))) {
-	    i++;
-	    parsePath(BAD_CAST argv[i]);
-        }
+            i++;
+            parsePath(lint, BAD_CAST argv[i]);
 #ifdef LIBXML_XPATH_ENABLED
-        else if ((!strcmp(argv[i], "-xpath")) ||
+        } else if ((!strcmp(argv[i], "-xpath")) ||
                    (!strcmp(argv[i], "--xpath"))) {
-	    i++;
-	    noout++;
-	    xpathquery = argv[i];
-        }
-#endif
-	else if ((!strcmp(argv[i], "-oldxml10")) ||
-	           (!strcmp(argv[i], "--oldxml10"))) {
-	    options |= XML_PARSE_OLD10;
-	} else if ((!strcmp(argv[i], "-max-ampl")) ||
-	           (!strcmp(argv[i], "--max-ampl"))) {
+            i++;
+            lint->noout++;
+            lint->xpathquery = argv[i];
+#endif
+        } else if ((!strcmp(argv[i], "-oldxml10")) ||
+                   (!strcmp(argv[i], "--oldxml10"))) {
+            lint->options |= XML_PARSE_OLD10;
+        } else if ((!strcmp(argv[i], "-max-ampl")) ||
+                   (!strcmp(argv[i], "--max-ampl"))) {
             i++;
             if (i >= argc) {
-                fprintf(ERR_STREAM, "max-ampl: missing integer value\n");
+                fprintf(errStream, "max-ampl: missing integer value\n");
                 return(XMLLINT_ERR_UNCLASS);
             }
-            maxAmpl = parseInteger("max-ampl", argv[i], 1, UINT_MAX);
-	} else {
-	    fprintf(ERR_STREAM, "Unknown option %s\n", argv[i]);
-	    usage(ERR_STREAM, argv[0]);
-	    return(XMLLINT_ERR_UNCLASS);
-	}
+            lint->maxAmpl = parseInteger(errStream, "max-ampl", argv[i],
+                                         1, UINT_MAX);
+        } else {
+            fprintf(errStream, "Unknown option %s\n", argv[i]);
+            usage(errStream, argv[0]);
+            return(XMLLINT_ERR_UNCLASS);
+        }
     }
 
+    if (lint->shell)
+        lint->repeat = 1;
+
+    return(XMLLINT_RETURN_OK);
+}
+
+int
+xmllintMain(int argc, const char **argv, FILE *errStream,
+            xmlResourceLoader loader) {
+    xmllintState state, *lint;
+    int i, j, res;
+    int files = 0;
+
+#ifdef _WIN32
+    _setmode(_fileno(stdin), _O_BINARY);
+    _setmode(_fileno(stdout), _O_BINARY);
+    _setmode(_fileno(stderr), _O_BINARY);
+#endif
+
+    lint = &state;
+    xmllintInit(lint);
+    lint->errStream = errStream;
+    lint->defaultResourceLoader = loader;
+
+    res = xmllintParseOptions(lint, argc, argv);
+    if (res != XMLLINT_RETURN_OK) {
+        lint->progresult = res;
+        goto error;
+    }
+
+    if (lint->maxmem != 0) {
+        xmllintMaxmem = 0;
+        xmllintMaxmemReached = 0;
+        xmllintOom = 0;
+        xmlMemSetup(myFreeFunc, myMallocFunc, myReallocFunc, myStrdupFunc);
+    }
+
+    LIBXML_TEST_VERSION
+
 #ifdef LIBXML_CATALOG_ENABLED
-    if (nocatalogs == 0) {
-	if (catalogs) {
+    if (lint->nocatalogs == 0) {
+	if (lint->catalogs) {
 	    const char *catal;
 
 	    catal = getenv("SGML_CATALOG_FILES");
 	    if (catal != NULL) {
 		xmlLoadCatalogs(catal);
 	    } else {
-		fprintf(ERR_STREAM, "Variable $SGML_CATALOG_FILES not set\n");
+		fprintf(errStream, "Variable $SGML_CATALOG_FILES not set\n");
 	    }
 	}
     }
@@ -3277,121 +3281,139 @@ xmllintMain(int argc, const char **argv, xmlResourceLoader loader) {
     }
 #endif
 
-    if ((htmlout) && (!nowrap)) {
-	fprintf(ERR_STREAM,
-         "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\"\n");
-	fprintf(ERR_STREAM,
-		"\t\"http://www.w3.org/TR/REC-html40/loose.dtd\">\n");
-	fprintf(ERR_STREAM,
-	 "<html><head><title>%s output</title></head>\n",
-		argv[0]);
-	fprintf(ERR_STREAM,
-	 "<body bgcolor=\"#ffffff\"><h1 align=\"center\">%s output</h1>\n",
-		argv[0]);
+    if (lint->htmlout) {
+        lint->htmlBuf = xmlMalloc(HTML_BUF_SIZE);
+        if (lint->htmlBuf == NULL) {
+            lint->progresult = XMLLINT_ERR_MEM;
+            goto error;
+        }
+
+        if (!lint->nowrap) {
+            fprintf(errStream,
+             "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\"\n");
+            fprintf(errStream,
+                    "\t\"http://www.w3.org/TR/REC-html40/loose.dtd\">\n");
+            fprintf(errStream,
+             "<html><head><title>%s output</title></head>\n",
+                    argv[0]);
+            fprintf(errStream,
+             "<body bgcolor=\"#ffffff\"><h1 align=\"center\">%s output</h1>\n",
+                    argv[0]);
+        }
     }
 
 #ifdef LIBXML_SCHEMATRON_ENABLED
-    if ((schematron != NULL) && (sax == 0)
+    if ((lint->schematron != NULL) && (lint->sax == 0)
 #ifdef LIBXML_READER_ENABLED
-        && (stream == 0)
+        && (lint->stream == 0)
 #endif /* LIBXML_READER_ENABLED */
 	) {
 	xmlSchematronParserCtxtPtr ctxt;
 
         /* forces loading the DTDs */
-	options |= XML_PARSE_DTDLOAD;
-	if (timing) {
-	    startTimer();
+	lint->options |= XML_PARSE_DTDLOAD;
+	if (lint->timing) {
+	    startTimer(lint);
 	}
-	ctxt = xmlSchematronNewParserCtxt(schematron);
+	ctxt = xmlSchematronNewParserCtxt(lint->schematron);
         if (ctxt == NULL) {
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             goto error;
         }
-	wxschematron = xmlSchematronParse(ctxt);
-	if (wxschematron == NULL) {
-	    fprintf(ERR_STREAM,
-		    "Schematron schema %s failed to compile\n", schematron);
-            progresult = XMLLINT_ERR_SCHEMACOMP;
-	    schematron = NULL;
+	lint->wxschematron = xmlSchematronParse(ctxt);
+	if (lint->wxschematron == NULL) {
+	    fprintf(errStream, "Schematron schema %s failed to compile\n",
+                    lint->schematron);
+            lint->progresult = XMLLINT_ERR_SCHEMACOMP;
+            goto error;
 	}
 	xmlSchematronFreeParserCtxt(ctxt);
-	if (timing) {
-	    endTimer("Compiling the schemas");
+	if (lint->timing) {
+	    endTimer(lint, "Compiling the schemas");
 	}
     }
 #endif
+
 #ifdef LIBXML_SCHEMAS_ENABLED
-    if ((relaxng != NULL) && (sax == 0)
+    if ((lint->relaxng != NULL) && (lint->sax == 0)
 #ifdef LIBXML_READER_ENABLED
-        && (stream == 0)
+        && (lint->stream == 0)
 #endif /* LIBXML_READER_ENABLED */
 	) {
 	xmlRelaxNGParserCtxtPtr ctxt;
 
         /* forces loading the DTDs */
-	options |= XML_PARSE_DTDLOAD;
-	if (timing) {
-	    startTimer();
+	lint->options |= XML_PARSE_DTDLOAD;
+	if (lint->timing) {
+	    startTimer(lint);
 	}
-	ctxt = xmlRelaxNGNewParserCtxt(relaxng);
+	ctxt = xmlRelaxNGNewParserCtxt(lint->relaxng);
         if (ctxt == NULL) {
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             goto error;
         }
-        xmlRelaxNGSetResourceLoader(ctxt, xmllintResourceLoader, NULL);
-	relaxngschemas = xmlRelaxNGParse(ctxt);
-	if (relaxngschemas == NULL) {
-	    fprintf(ERR_STREAM,
-		    "Relax-NG schema %s failed to compile\n", relaxng);
-            progresult = XMLLINT_ERR_SCHEMACOMP;
-	    relaxng = NULL;
+        xmlRelaxNGSetResourceLoader(ctxt, xmllintResourceLoader, lint);
+	lint->relaxngschemas = xmlRelaxNGParse(ctxt);
+	if (lint->relaxngschemas == NULL) {
+	    fprintf(errStream, "Relax-NG schema %s failed to compile\n",
+                    lint->relaxng);
+            lint->progresult = XMLLINT_ERR_SCHEMACOMP;
+            goto error;
 	}
 	xmlRelaxNGFreeParserCtxt(ctxt);
-	if (timing) {
-	    endTimer("Compiling the schemas");
+	if (lint->timing) {
+	    endTimer(lint, "Compiling the schemas");
 	}
-    } else if ((schema != NULL)
+    } else if ((lint->schema != NULL)
 #ifdef LIBXML_READER_ENABLED
-		&& (stream == 0)
+		&& (lint->stream == 0)
 #endif
 	) {
 	xmlSchemaParserCtxtPtr ctxt;
 
-	if (timing) {
-	    startTimer();
+	if (lint->timing) {
+	    startTimer(lint);
 	}
-	ctxt = xmlSchemaNewParserCtxt(schema);
+	ctxt = xmlSchemaNewParserCtxt(lint->schema);
         if (ctxt == NULL) {
-            progresult = XMLLINT_ERR_MEM;
+            lint->progresult = XMLLINT_ERR_MEM;
             goto error;
         }
-        xmlSchemaSetResourceLoader(ctxt, xmllintResourceLoader, NULL);
-	wxschemas = xmlSchemaParse(ctxt);
-	if (wxschemas == NULL) {
-	    fprintf(ERR_STREAM,
-		    "WXS schema %s failed to compile\n", schema);
-            progresult = XMLLINT_ERR_SCHEMACOMP;
-	    schema = NULL;
+        xmlSchemaSetResourceLoader(ctxt, xmllintResourceLoader, lint);
+	lint->wxschemas = xmlSchemaParse(ctxt);
+	if (lint->wxschemas == NULL) {
+	    fprintf(errStream, "WXS schema %s failed to compile\n",
+                    lint->schema);
+            lint->progresult = XMLLINT_ERR_SCHEMACOMP;
+            goto error;
 	}
 	xmlSchemaFreeParserCtxt(ctxt);
-	if (timing) {
-	    endTimer("Compiling the schemas");
+	if (lint->timing) {
+	    endTimer(lint, "Compiling the schemas");
 	}
     }
 #endif /* LIBXML_SCHEMAS_ENABLED */
+
 #if defined(LIBXML_READER_ENABLED) && defined(LIBXML_PATTERN_ENABLED)
-    if ((pattern != NULL) && (walker == 0)) {
-        patternc = xmlPatterncompile((const xmlChar *) pattern, NULL, 0, NULL);
-	if (patternc == NULL) {
-	    fprintf(ERR_STREAM,
-		    "Pattern %s failed to compile\n", pattern);
-            progresult = XMLLINT_ERR_SCHEMAPAT;
-	    pattern = NULL;
+    if ((lint->pattern != NULL) && (lint->walker == 0)) {
+        res = xmlPatternCompileSafe(BAD_CAST lint->pattern, NULL, 0, NULL,
+                                    &lint->patternc);
+	if (lint->patternc == NULL) {
+            if (res < 0) {
+                lint->progresult = XMLLINT_ERR_MEM;
+            } else {
+                fprintf(errStream, "Pattern %s failed to compile\n",
+                        lint->pattern);
+                lint->progresult = XMLLINT_ERR_SCHEMAPAT;
+            }
+            goto error;
 	}
     }
 #endif /* LIBXML_READER_ENABLED && LIBXML_PATTERN_ENABLED */
 
+    /*
+     * The main loop over input documents
+     */
     for (i = 1; i < argc ; i++) {
         const char *filename = argv[i];
 #if HAVE_DECL_MMAP
@@ -3404,118 +3426,180 @@ xmllintMain(int argc, const char **argv, xmlResourceLoader loader) {
         }
 
 #if HAVE_DECL_MMAP
-        if (memory) {
+        if (lint->memory) {
             struct stat info;
             if (stat(filename, &info) < 0) {
-                progresult = XMLLINT_ERR_RDFILE;
+                lint->progresult = XMLLINT_ERR_RDFILE;
                 break;
             }
             memoryFd = open(filename, O_RDONLY);
             if (memoryFd < 0) {
-                progresult = XMLLINT_ERR_RDFILE;
+                lint->progresult = XMLLINT_ERR_RDFILE;
                 break;
             }
-            memoryData = mmap(NULL, info.st_size + 1, PROT_READ, MAP_SHARED,
-                              memoryFd, 0);
-            if (memoryData == (void *) MAP_FAILED) {
+            lint->memoryData = mmap(NULL, info.st_size + 1, PROT_READ,
+                                    MAP_SHARED, memoryFd, 0);
+            if (lint->memoryData == (void *) MAP_FAILED) {
                 close(memoryFd);
-                fprintf(ERR_STREAM, "mmap failure for file %s\n", filename);
-                progresult = XMLLINT_ERR_RDFILE;
+                fprintf(errStream, "mmap failure for file %s\n", filename);
+                lint->progresult = XMLLINT_ERR_RDFILE;
                 break;
             }
-            memorySize = info.st_size;
+            lint->memorySize = info.st_size;
         }
 #endif /* HAVE_DECL_MMAP */
 
-	if ((timing) && (repeat))
-	    startTimer();
-        if (repeat) {
+	if ((lint->timing) && (lint->repeat > 1))
+	    startTimer(lint);
+
+#ifdef LIBXML_READER_ENABLED
+        if (lint->stream != 0) {
+            for (j = 0; j < lint->repeat; j++)
+                streamFile(lint, filename);
+        } else
+#endif /* LIBXML_READER_ENABLED */
+        {
             xmlParserCtxtPtr ctxt;
 
-            ctxt = xmlNewParserCtxt();
+#ifdef LIBXML_HTML_ENABLED
+            if (lint->html) {
+#ifdef LIBXML_PUSH_ENABLED
+                if (lint->push) {
+                    ctxt = htmlCreatePushParserCtxt(NULL, NULL, NULL, 0,
+                                                    filename,
+                                                    XML_CHAR_ENCODING_NONE);
+                    htmlCtxtUseOptions(ctxt, lint->options);
+                } else
+#endif /* LIBXML_PUSH_ENABLED */
+                {
+                    ctxt = htmlNewParserCtxt();
+                }
+            } else
+#endif /* LIBXML_HTML_ENABLED */
+            {
+#ifdef LIBXML_PUSH_ENABLED
+                if (lint->push) {
+                    ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0,
+                                                   filename);
+                    xmlCtxtUseOptions(ctxt, lint->options);
+                } else
+#endif /* LIBXML_PUSH_ENABLED */
+                {
+                    ctxt = xmlNewParserCtxt();
+                }
+            }
             if (ctxt == NULL) {
-                progresult = XMLLINT_ERR_MEM;
+                lint->progresult = XMLLINT_ERR_MEM;
                 goto error;
             }
 
-            for (acount = 0;acount < repeat;acount++) {
-#ifdef LIBXML_READER_ENABLED
-                if (stream != 0) {
-                    streamFile(filename);
+            if (lint->sax) {
+                const xmlSAXHandler *handler;
+
+                if (lint->noout) {
+                    handler = &emptySAXHandler;
+#ifdef LIBXML_SAX1_ENABLED
+                } else if (lint->options & XML_PARSE_SAX1) {
+                    handler = &debugSAXHandler;
+#endif
                 } else {
-#endif /* LIBXML_READER_ENABLED */
-                    if (sax) {
-                        testSAX(filename);
-                    } else {
-                        parseAndPrintFile(filename, ctxt);
-                    }
-#ifdef LIBXML_READER_ENABLED
+                    handler = &debugSAX2Handler;
                 }
-#endif /* LIBXML_READER_ENABLED */
+
+                *ctxt->sax = *handler;
+                ctxt->userData = lint;
             }
 
-            xmlFreeParserCtxt(ctxt);
-        } else {
-#ifdef LIBXML_READER_ENABLED
-            if (stream != 0)
-                streamFile(filename);
-            else
-#endif /* LIBXML_READER_ENABLED */
-            if (sax) {
-                testSAX(filename);
-            } else {
-                parseAndPrintFile(filename, NULL);
+            xmlCtxtSetResourceLoader(ctxt, xmllintResourceLoader, lint);
+            if (lint->maxAmpl > 0)
+                xmlCtxtSetMaxAmplification(ctxt, lint->maxAmpl);
+
+            if (lint->htmlout) {
+                ctxt->_private = lint;
+                xmlCtxtSetErrorHandler(ctxt, xmlHTMLError, ctxt);
             }
+
+            lint->ctxt = ctxt;
+
+            for (j = 0; j < lint->repeat; j++) {
+#ifdef LIBXML_PUSH_ENABLED
+                if ((lint->push) && (j > 0))
+                    xmlCtxtResetPush(ctxt, NULL, 0, NULL, NULL);
+#endif
+                if (lint->sax) {
+                    testSAX(lint, filename);
+                } else {
+                    parseAndPrintFile(lint, filename);
+                }
+            }
+
+            xmlFreeParserCtxt(ctxt);
         }
-        files ++;
-        if ((timing) && (repeat)) {
-            endTimer("%d iterations", repeat);
+
+        if ((lint->timing) && (lint->repeat > 1)) {
+            endTimer(lint, "%d iterations", lint->repeat);
         }
 
+        files += 1;
+
 #if HAVE_DECL_MMAP
-        if (memory) {
-            munmap(memoryData, memorySize);
+        if (lint->memory) {
+            munmap(lint->memoryData, lint->memorySize);
             close(memoryFd);
         }
 #endif
     }
-    if (generate)
-	parseAndPrintFile(NULL, NULL);
-    if ((htmlout) && (!nowrap)) {
-	fprintf(ERR_STREAM, "</body></html>\n");
+
+    if (lint->generate)
+	parseAndPrintFile(lint, NULL);
+
+    if ((lint->htmlout) && (!lint->nowrap)) {
+	fprintf(errStream, "</body></html>\n");
     }
-    if ((files == 0) && (!generate) && (version == 0)) {
-	usage(ERR_STREAM, argv[0]);
-        progresult = XMLLINT_ERR_UNCLASS;
+
+    if ((files == 0) && (!lint->generate) && (lint->version == 0)) {
+	usage(errStream, argv[0]);
+        lint->progresult = XMLLINT_ERR_UNCLASS;
     }
+
+error:
+
+    if (lint->htmlout)
+        xmlFree(lint->htmlBuf);
+
 #ifdef LIBXML_SCHEMATRON_ENABLED
-    if (wxschematron != NULL)
-	xmlSchematronFree(wxschematron);
+    if (lint->wxschematron != NULL)
+	xmlSchematronFree(lint->wxschematron);
 #endif
 #ifdef LIBXML_SCHEMAS_ENABLED
-    if (relaxngschemas != NULL)
-	xmlRelaxNGFree(relaxngschemas);
-    if (wxschemas != NULL)
-	xmlSchemaFree(wxschemas);
+    if (lint->relaxngschemas != NULL)
+	xmlRelaxNGFree(lint->relaxngschemas);
+    if (lint->wxschemas != NULL)
+	xmlSchemaFree(lint->wxschemas);
 #endif
 #if defined(LIBXML_READER_ENABLED) && defined(LIBXML_PATTERN_ENABLED)
-    if (patternc != NULL)
-        xmlFreePattern(patternc);
+    if (lint->patternc != NULL)
+        xmlFreePattern(lint->patternc);
 #endif
 
-    /* Avoid unused label warning if features are disabled. */
-    goto error;
-
-error:
     xmlCleanupParser();
 
-    return(progresult);
-}
+    if ((lint->maxmem) && (xmllintMaxmemReached)) {
+        fprintf(errStream, "Maximum memory exceeded (%d bytes)\n",
+                xmllintMaxmem);
+    } else if (lint->progresult == XMLLINT_ERR_MEM) {
+        fprintf(errStream, "Out-of-memory error reported\n");
+    }
 
-#ifndef XMLLINT_FUZZ
-int
-main(int argc, char **argv) {
-    return(xmllintMain(argc, (const char **) argv, NULL));
-}
+#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
+    if ((lint->maxmem) &&
+        (xmllintOom != (lint->progresult == XMLLINT_ERR_MEM))) {
+        fprintf(stderr, "xmllint: malloc failure %s reported\n",
+                xmllintOom ? "not" : "erroneously");
+        abort();
+    }
 #endif
 
+    return(lint->progresult);
+}
+
diff --git a/xmlreader.c b/xmlreader.c
index 142e51f2..6d815a94 100644
--- a/xmlreader.c
+++ b/xmlreader.c
@@ -41,8 +41,9 @@
 
 #include "private/buf.h"
 #include "private/error.h"
-#include "private/tree.h"
+#include "private/memory.h"
 #include "private/parser.h"
+#include "private/tree.h"
 #ifdef LIBXML_XINCLUDE_ENABLED
 #include "private/xinclude.h"
 #endif
@@ -574,11 +575,16 @@ static int
 xmlTextReaderEntPush(xmlTextReaderPtr reader, xmlNodePtr value)
 {
     if (reader->entNr >= reader->entMax) {
-        size_t newSize = reader->entMax == 0 ? 10 : reader->entMax * 2;
         xmlNodePtr *tmp;
+        int newSize;
 
-        tmp = (xmlNodePtr *) xmlRealloc(reader->entTab,
-                                        newSize * sizeof(*tmp));
+        newSize = xmlGrowCapacity(reader->entMax, sizeof(tmp[0]),
+                                  10, XML_MAX_ITEMS);
+        if (newSize < 0) {
+            xmlTextReaderErrMemory(reader);
+            return (-1);
+        }
+        tmp = xmlRealloc(reader->entTab, newSize * sizeof(tmp[0]));
         if (tmp == NULL) {
             xmlTextReaderErrMemory(reader);
             return (-1);
@@ -1458,8 +1464,11 @@ node_found:
         if (xmlXIncludeProcessNode(reader->xincctxt, reader->node) < 0) {
             int err = xmlXIncludeGetLastError(reader->xincctxt);
 
-            if (err == XML_ERR_NO_MEMORY)
-                xmlTextReaderErrMemory(reader);
+            if (xmlIsCatastrophicError(XML_ERR_FATAL, err)) {
+                xmlFatalErr(reader->ctxt, err, NULL);
+                reader->mode = XML_TEXTREADER_MODE_ERROR;
+                reader->state = XML_TEXTREADER_ERROR;
+            }
             return(-1);
         }
     }
@@ -1733,8 +1742,9 @@ xmlTextReaderReadOuterXml(xmlTextReaderPtr reader)
  *
  * Reads the contents of an element or a text node as a string.
  *
- * Returns a string containing the contents of the Element or Text node,
- *         or NULL if the reader is positioned on any other type of node.
+ * Returns a string containing the contents of the non-empty Element or
+ *         Text node (including CDATA sections), or NULL if the reader
+ *         is positioned on any other type of node.
  *         The string must be deallocated by the caller.
  */
 xmlChar *
@@ -1753,14 +1763,12 @@ xmlTextReaderReadString(xmlTextReaderPtr reader)
         case XML_CDATA_SECTION_NODE:
             break;
         case XML_ELEMENT_NODE:
-            if (xmlTextReaderDoExpand(reader) == -1)
+            if ((xmlTextReaderDoExpand(reader) == -1) ||
+                (node->children == NULL))
                 return(NULL);
             break;
-        case XML_ATTRIBUTE_NODE:
-            /* TODO */
-            break;
         default:
-            break;
+            return(NULL);
     }
 
     buf = xmlBufCreate(50);
@@ -3947,27 +3955,23 @@ xmlTextReaderPreservePattern(xmlTextReaderPtr reader, const xmlChar *pattern,
     if (comp == NULL)
         return(-1);
 
-    if (reader->patternMax <= 0) {
-	reader->patternMax = 4;
-	reader->patternTab = (xmlPatternPtr *) xmlMalloc(reader->patternMax *
-					      sizeof(reader->patternTab[0]));
-        if (reader->patternTab == NULL) {
-            xmlTextReaderErrMemory(reader);
-            return (-1);
-        }
-    }
     if (reader->patternNr >= reader->patternMax) {
         xmlPatternPtr *tmp;
-        reader->patternMax *= 2;
-	tmp = (xmlPatternPtr *) xmlRealloc(reader->patternTab,
-                                      reader->patternMax *
-                                      sizeof(reader->patternTab[0]));
+        int newSize;
+
+        newSize = xmlGrowCapacity(reader->patternMax, sizeof(tmp[0]),
+                                  4, XML_MAX_ITEMS);
+        if (newSize < 0) {
+            xmlTextReaderErrMemory(reader);
+            return(-1);
+        }
+	tmp = xmlRealloc(reader->patternTab, newSize * sizeof(tmp[0]));
         if (tmp == NULL) {
             xmlTextReaderErrMemory(reader);
-	    reader->patternMax /= 2;
-            return (-1);
+            return(-1);
         }
 	reader->patternTab = tmp;
+        reader->patternMax = newSize;
     }
     reader->patternTab[reader->patternNr] = comp;
     return(reader->patternNr++);
@@ -4918,7 +4922,7 @@ xmlTextReaderSetup(xmlTextReaderPtr reader,
 	    inputStream->buf = buf;
             xmlBufResetInput(buf->buffer, inputStream);
 
-            if (inputPush(reader->ctxt, inputStream) < 0) {
+            if (xmlCtxtPushInput(reader->ctxt, inputStream) < 0) {
                 xmlFreeInputStream(inputStream);
                 return(-1);
             }
@@ -5005,6 +5009,8 @@ xmlTextReaderSetup(xmlTextReaderPtr reader,
 void
 xmlTextReaderSetMaxAmplification(xmlTextReaderPtr reader, unsigned maxAmpl)
 {
+    if (reader == NULL)
+        return;
     xmlCtxtSetMaxAmplification(reader->ctxt, maxAmpl);
 }
 
@@ -5019,7 +5025,7 @@ xmlTextReaderSetMaxAmplification(xmlTextReaderPtr reader, unsigned maxAmpl)
 const xmlError *
 xmlTextReaderGetLastError(xmlTextReaderPtr reader)
 {
-    if (reader == NULL)
+    if ((reader == NULL) || (reader->ctxt == NULL))
         return(NULL);
     return(&reader->ctxt->lastError);
 }
diff --git a/xmlregexp.c b/xmlregexp.c
index fda8713d..c7604244 100644
--- a/xmlregexp.c
+++ b/xmlregexp.c
@@ -30,6 +30,8 @@
 #include <libxml/xmlunicode.h>
 
 #include "private/error.h"
+#include "private/memory.h"
+#include "private/parser.h"
 #include "private/regexp.h"
 
 #ifndef SIZE_MAX
@@ -1174,26 +1176,23 @@ xmlRegAtomAddRange(xmlRegParserCtxtPtr ctxt, xmlRegAtomPtr atom,
 	ERROR("add range: atom is not ranges");
 	return(NULL);
     }
-    if (atom->maxRanges == 0) {
-	atom->maxRanges = 4;
-	atom->ranges = (xmlRegRangePtr *) xmlMalloc(atom->maxRanges *
-		                             sizeof(xmlRegRangePtr));
-	if (atom->ranges == NULL) {
+    if (atom->nbRanges >= atom->maxRanges) {
+	xmlRegRangePtr *tmp;
+        int newSize;
+
+        newSize = xmlGrowCapacity(atom->maxRanges, sizeof(tmp[0]),
+                                  4, XML_MAX_ITEMS);
+        if (newSize < 0) {
 	    xmlRegexpErrMemory(ctxt);
-	    atom->maxRanges = 0;
 	    return(NULL);
-	}
-    } else if (atom->nbRanges >= atom->maxRanges) {
-	xmlRegRangePtr *tmp;
-	atom->maxRanges *= 2;
-	tmp = (xmlRegRangePtr *) xmlRealloc(atom->ranges, atom->maxRanges *
-		                             sizeof(xmlRegRangePtr));
+        }
+	tmp = xmlRealloc(atom->ranges, newSize * sizeof(tmp[0]));
 	if (tmp == NULL) {
 	    xmlRegexpErrMemory(ctxt);
-	    atom->maxRanges /= 2;
 	    return(NULL);
 	}
 	atom->ranges = tmp;
+	atom->maxRanges = newSize;
     }
     range = xmlRegNewRange(ctxt, neg, type, start, end);
     if (range == NULL)
@@ -1206,26 +1205,23 @@ xmlRegAtomAddRange(xmlRegParserCtxtPtr ctxt, xmlRegAtomPtr atom,
 
 static int
 xmlRegGetCounter(xmlRegParserCtxtPtr ctxt) {
-    if (ctxt->maxCounters == 0) {
-	ctxt->maxCounters = 4;
-	ctxt->counters = (xmlRegCounter *) xmlMalloc(ctxt->maxCounters *
-		                             sizeof(xmlRegCounter));
-	if (ctxt->counters == NULL) {
+    if (ctxt->nbCounters >= ctxt->maxCounters) {
+	xmlRegCounter *tmp;
+        int newSize;
+
+        newSize = xmlGrowCapacity(ctxt->maxCounters, sizeof(tmp[0]),
+                                  4, XML_MAX_ITEMS);
+	if (newSize < 0) {
 	    xmlRegexpErrMemory(ctxt);
-	    ctxt->maxCounters = 0;
 	    return(-1);
 	}
-    } else if (ctxt->nbCounters >= ctxt->maxCounters) {
-	xmlRegCounter *tmp;
-	ctxt->maxCounters *= 2;
-	tmp = (xmlRegCounter *) xmlRealloc(ctxt->counters, ctxt->maxCounters *
-		                           sizeof(xmlRegCounter));
+	tmp = xmlRealloc(ctxt->counters, newSize * sizeof(tmp[0]));
 	if (tmp == NULL) {
 	    xmlRegexpErrMemory(ctxt);
-	    ctxt->maxCounters /= 2;
 	    return(-1);
 	}
 	ctxt->counters = tmp;
+	ctxt->maxCounters = newSize;
     }
     ctxt->counters[ctxt->nbCounters].min = -1;
     ctxt->counters[ctxt->nbCounters].max = -1;
@@ -1239,10 +1235,16 @@ xmlRegAtomPush(xmlRegParserCtxtPtr ctxt, xmlRegAtomPtr atom) {
 	return(-1);
     }
     if (ctxt->nbAtoms >= ctxt->maxAtoms) {
-        size_t newSize = ctxt->maxAtoms ? ctxt->maxAtoms * 2 : 4;
 	xmlRegAtomPtr *tmp;
+        int newSize;
 
-	tmp = xmlRealloc(ctxt->atoms, newSize * sizeof(xmlRegAtomPtr));
+        newSize = xmlGrowCapacity(ctxt->maxAtoms, sizeof(tmp[0]),
+                                  4, XML_MAX_ITEMS);
+	if (newSize < 0) {
+	    xmlRegexpErrMemory(ctxt);
+	    return(-1);
+	}
+	tmp = xmlRealloc(ctxt->atoms, newSize * sizeof(tmp[0]));
 	if (tmp == NULL) {
 	    xmlRegexpErrMemory(ctxt);
 	    return(-1);
@@ -1258,26 +1260,23 @@ xmlRegAtomPush(xmlRegParserCtxtPtr ctxt, xmlRegAtomPtr atom) {
 static void
 xmlRegStateAddTransTo(xmlRegParserCtxtPtr ctxt, xmlRegStatePtr target,
                       int from) {
-    if (target->maxTransTo == 0) {
-	target->maxTransTo = 8;
-	target->transTo = (int *) xmlMalloc(target->maxTransTo *
-		                             sizeof(int));
-	if (target->transTo == NULL) {
+    if (target->nbTransTo >= target->maxTransTo) {
+	int *tmp;
+        int newSize;
+
+        newSize = xmlGrowCapacity(target->maxTransTo, sizeof(tmp[0]),
+                                  8, XML_MAX_ITEMS);
+	if (newSize < 0) {
 	    xmlRegexpErrMemory(ctxt);
-	    target->maxTransTo = 0;
 	    return;
 	}
-    } else if (target->nbTransTo >= target->maxTransTo) {
-	int *tmp;
-	target->maxTransTo *= 2;
-	tmp = (int *) xmlRealloc(target->transTo, target->maxTransTo *
-		                             sizeof(int));
+	tmp = xmlRealloc(target->transTo, newSize * sizeof(tmp[0]));
 	if (tmp == NULL) {
 	    xmlRegexpErrMemory(ctxt);
-	    target->maxTransTo /= 2;
 	    return;
 	}
 	target->transTo = tmp;
+	target->maxTransTo = newSize;
     }
     target->transTo[target->nbTransTo] = from;
     target->nbTransTo++;
@@ -1314,26 +1313,23 @@ xmlRegStateAddTrans(xmlRegParserCtxtPtr ctxt, xmlRegStatePtr state,
 	}
     }
 
-    if (state->maxTrans == 0) {
-	state->maxTrans = 8;
-	state->trans = (xmlRegTrans *) xmlMalloc(state->maxTrans *
-		                             sizeof(xmlRegTrans));
-	if (state->trans == NULL) {
+    if (state->nbTrans >= state->maxTrans) {
+	xmlRegTrans *tmp;
+        int newSize;
+
+        newSize = xmlGrowCapacity(state->maxTrans, sizeof(tmp[0]),
+                                  8, XML_MAX_ITEMS);
+	if (newSize < 0) {
 	    xmlRegexpErrMemory(ctxt);
-	    state->maxTrans = 0;
 	    return;
 	}
-    } else if (state->nbTrans >= state->maxTrans) {
-	xmlRegTrans *tmp;
-	state->maxTrans *= 2;
-	tmp = (xmlRegTrans *) xmlRealloc(state->trans, state->maxTrans *
-		                             sizeof(xmlRegTrans));
+	tmp = xmlRealloc(state->trans, newSize * sizeof(tmp[0]));
 	if (tmp == NULL) {
 	    xmlRegexpErrMemory(ctxt);
-	    state->maxTrans /= 2;
 	    return;
 	}
 	state->trans = tmp;
+	state->maxTrans = newSize;
     }
 
     state->trans[state->nbTrans].atom = atom;
@@ -1350,9 +1346,15 @@ xmlRegStatePush(xmlRegParserCtxtPtr ctxt) {
     xmlRegStatePtr state;
 
     if (ctxt->nbStates >= ctxt->maxStates) {
-        size_t newSize = ctxt->maxStates ? ctxt->maxStates * 2 : 4;
 	xmlRegStatePtr *tmp;
+        int newSize;
 
+        newSize = xmlGrowCapacity(ctxt->maxStates, sizeof(tmp[0]),
+                                  4, XML_MAX_ITEMS);
+	if (newSize < 0) {
+	    xmlRegexpErrMemory(ctxt);
+	    return(NULL);
+	}
 	tmp = xmlRealloc(ctxt->states, newSize * sizeof(tmp[0]));
 	if (tmp == NULL) {
 	    xmlRegexpErrMemory(ctxt);
@@ -3034,30 +3036,24 @@ xmlFARegExecSave(xmlRegExecCtxtPtr exec) {
     exec->nbPush++;
 #endif
 
-    if (exec->maxRollbacks == 0) {
-	exec->maxRollbacks = 4;
-	exec->rollbacks = (xmlRegExecRollback *) xmlMalloc(exec->maxRollbacks *
-		                             sizeof(xmlRegExecRollback));
-	if (exec->rollbacks == NULL) {
-	    exec->maxRollbacks = 0;
+    if (exec->nbRollbacks >= exec->maxRollbacks) {
+	xmlRegExecRollback *tmp;
+        int newSize;
+	int len = exec->nbRollbacks;
+
+        newSize = xmlGrowCapacity(exec->maxRollbacks, sizeof(tmp[0]),
+                                  4, XML_MAX_ITEMS);
+	if (newSize < 0) {
             exec->status = XML_REGEXP_OUT_OF_MEMORY;
 	    return;
 	}
-	memset(exec->rollbacks, 0,
-	       exec->maxRollbacks * sizeof(xmlRegExecRollback));
-    } else if (exec->nbRollbacks >= exec->maxRollbacks) {
-	xmlRegExecRollback *tmp;
-	int len = exec->maxRollbacks;
-
-	exec->maxRollbacks *= 2;
-	tmp = (xmlRegExecRollback *) xmlRealloc(exec->rollbacks,
-			exec->maxRollbacks * sizeof(xmlRegExecRollback));
+	tmp = xmlRealloc(exec->rollbacks, newSize * sizeof(tmp[0]));
 	if (tmp == NULL) {
-	    exec->maxRollbacks /= 2;
             exec->status = XML_REGEXP_OUT_OF_MEMORY;
 	    return;
 	}
 	exec->rollbacks = tmp;
+	exec->maxRollbacks = newSize;
 	tmp = &exec->rollbacks[len];
 	memset(tmp, 0, (exec->maxRollbacks - len) * sizeof(xmlRegExecRollback));
     }
@@ -3512,27 +3508,27 @@ xmlRegExecSetErrString(xmlRegExecCtxtPtr exec, const xmlChar *value) {
 static void
 xmlFARegExecSaveInputString(xmlRegExecCtxtPtr exec, const xmlChar *value,
 	                    void *data) {
-    if (exec->inputStackMax == 0) {
-	exec->inputStackMax = 4;
-	exec->inputStack = (xmlRegInputTokenPtr)
-	    xmlMalloc(exec->inputStackMax * sizeof(xmlRegInputToken));
-	if (exec->inputStack == NULL) {
-	    exec->inputStackMax = 0;
+    if (exec->inputStackNr + 1 >= exec->inputStackMax) {
+	xmlRegInputTokenPtr tmp;
+        int newSize;
+
+        newSize = xmlGrowCapacity(exec->inputStackMax, sizeof(tmp[0]),
+                                  4, XML_MAX_ITEMS);
+	if (newSize < 0) {
             exec->status = XML_REGEXP_OUT_OF_MEMORY;
 	    return;
 	}
-    } else if (exec->inputStackNr + 1 >= exec->inputStackMax) {
-	xmlRegInputTokenPtr tmp;
-
-	exec->inputStackMax *= 2;
-	tmp = (xmlRegInputTokenPtr) xmlRealloc(exec->inputStack,
-			exec->inputStackMax * sizeof(xmlRegInputToken));
+#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
+        if (newSize < 2)
+            newSize = 2;
+#endif
+	tmp = xmlRealloc(exec->inputStack, newSize * sizeof(tmp[0]));
 	if (tmp == NULL) {
-	    exec->inputStackMax /= 2;
             exec->status = XML_REGEXP_OUT_OF_MEMORY;
 	    return;
 	}
 	exec->inputStack = tmp;
+	exec->inputStackMax = newSize;
     }
     if (value == NULL) {
         exec->inputStack[exec->inputStackNr].value = NULL;
@@ -7514,14 +7510,21 @@ xmlExpExpDeriveInt(xmlExpCtxtPtr ctxt, xmlExpNodePtr exp, xmlExpNodePtr sub) {
     len = xmlExpGetStartInt(ctxt, sub, tab, ctxt->tabSize, 0);
     while (len < 0) {
         const xmlChar **temp;
-	temp = (const xmlChar **) xmlRealloc((xmlChar **) tab, ctxt->tabSize * 2 *
-	                                     sizeof(const xmlChar *));
+        int newSize;
+
+        newSize = xmlGrowCapacity(ctxt->tabSize, sizeof(temp[0]),
+                                  40, XML_MAX_ITEMS);
+	if (newSize < 0) {
+	    xmlFree(tab);
+	    return(NULL);
+	}
+	temp = xmlRealloc(tab, newSize * sizeof(temp[0]));
 	if (temp == NULL) {
-	    xmlFree((xmlChar **) tab);
+	    xmlFree(tab);
 	    return(NULL);
 	}
 	tab = temp;
-	ctxt->tabSize *= 2;
+	ctxt->tabSize = newSize;
 	len = xmlExpGetStartInt(ctxt, sub, tab, ctxt->tabSize, 0);
     }
     for (i = 0;i < len;i++) {
diff --git a/xmlsave.c b/xmlsave.c
index d0492ee4..118ddbed 100644
--- a/xmlsave.c
+++ b/xmlsave.c
@@ -26,6 +26,7 @@
 #include "private/entities.h"
 #include "private/error.h"
 #include "private/io.h"
+#include "private/parser.h"
 #include "private/save.h"
 
 #ifdef LIBXML_OUTPUT_ENABLED
@@ -83,8 +84,10 @@ xmlSaveErr(xmlOutputBufferPtr out, int code, xmlNodePtr node,
     const char *msg = NULL;
     int res;
 
-    /* Don't overwrite memory errors */
-    if ((out != NULL) && (out->error == XML_ERR_NO_MEMORY))
+    /* Don't overwrite catastrophic errors */
+    if ((out != NULL) &&
+        (out->error != XML_ERR_OK) &&
+        (xmlIsCatastrophicError(XML_ERR_FATAL, out->error)))
         return;
 
     if (code == XML_ERR_NO_MEMORY) {
@@ -2197,8 +2200,14 @@ xmlSaveFinish(xmlSaveCtxtPtr ctxt)
 
     if (ctxt == NULL)
         return(XML_ERR_INTERNAL_ERROR);
-    xmlSaveFlush(ctxt);
-    ret = ctxt->buf->error;
+
+    ret = xmlOutputBufferClose(ctxt->buf);
+    ctxt->buf = NULL;
+    if (ret < 0)
+        ret = -ret;
+    else
+        ret = XML_ERR_OK;
+
     xmlFreeSaveCtxt(ctxt);
     return(ret);
 }
diff --git a/xmlschemas.c b/xmlschemas.c
index f5958327..256fef0d 100644
--- a/xmlschemas.c
+++ b/xmlschemas.c
@@ -77,6 +77,8 @@
 #endif
 
 #include "private/error.h"
+#include "private/memory.h"
+#include "private/parser.h"
 #include "private/string.h"
 
 /* #define WXS_ELEM_DECL_CONS_ENABLED */
@@ -285,7 +287,10 @@ static const xmlChar *xmlNamespaceNs = (const xmlChar *)
 
 #define WXS_ADD_LOCAL(ctx, item) \
     do { \
-        if (xmlSchemaAddItemSize(&(WXS_BUCKET(ctx)->locals), 10, item) < 0) { \
+        if ((item != NULL) && \
+            (xmlSchemaAddItemSize(&(WXS_BUCKET(ctx)->locals), 10, \
+                                  item) < 0)) { \
+            xmlSchemaPErrMemory(ctx); \
             xmlFree(item); \
             item = NULL; \
         } \
@@ -293,14 +298,23 @@ static const xmlChar *xmlNamespaceNs = (const xmlChar *)
 
 #define WXS_ADD_GLOBAL(ctx, item) \
     do { \
-        if (xmlSchemaAddItemSize(&(WXS_BUCKET(ctx)->globals), 5, item) < 0) { \
+        if ((item != NULL) && \
+            (xmlSchemaAddItemSize(&(WXS_BUCKET(ctx)->globals), 5, \
+                                  item) < 0)) { \
+            xmlSchemaPErrMemory(ctx); \
             xmlFree(item); \
             item = NULL; \
         } \
     } while (0)
 
 #define WXS_ADD_PENDING(ctx, item) \
-    xmlSchemaAddItemSize(&((ctx)->constructor->pending), 10, item)
+    do { \
+        if ((item != NULL) && \
+            (xmlSchemaAddItemSize(&((ctx)->constructor->pending), 10, \
+                                  item) < 0)) { \
+            xmlSchemaPErrMemory(ctx); \
+        } \
+    } while (0)
 /*
 * xmlSchemaItemList macros.
 */
@@ -858,19 +872,19 @@ struct _xmlSchemaIDCMatcher {
 /*
 * Element info flags.
 */
-#define XML_SCHEMA_NODE_INFO_FLAG_OWNED_NAMES  1<<0
-#define XML_SCHEMA_NODE_INFO_FLAG_OWNED_VALUES 1<<1
-#define XML_SCHEMA_ELEM_INFO_NILLED	       1<<2
-#define XML_SCHEMA_ELEM_INFO_LOCAL_TYPE	       1<<3
+#define XML_SCHEMA_NODE_INFO_FLAG_OWNED_NAMES  (1<<0)
+#define XML_SCHEMA_NODE_INFO_FLAG_OWNED_VALUES (1<<1)
+#define XML_SCHEMA_ELEM_INFO_NILLED            (1<<2)
+#define XML_SCHEMA_ELEM_INFO_LOCAL_TYPE        (1<<3)
 
-#define XML_SCHEMA_NODE_INFO_VALUE_NEEDED      1<<4
-#define XML_SCHEMA_ELEM_INFO_EMPTY             1<<5
-#define XML_SCHEMA_ELEM_INFO_HAS_CONTENT       1<<6
+#define XML_SCHEMA_NODE_INFO_VALUE_NEEDED      (1<<4)
+#define XML_SCHEMA_ELEM_INFO_EMPTY             (1<<5)
+#define XML_SCHEMA_ELEM_INFO_HAS_CONTENT       (1<<6)
 
-#define XML_SCHEMA_ELEM_INFO_HAS_ELEM_CONTENT  1<<7
-#define XML_SCHEMA_ELEM_INFO_ERR_BAD_CONTENT  1<<8
-#define XML_SCHEMA_NODE_INFO_ERR_NOT_EXPECTED  1<<9
-#define XML_SCHEMA_NODE_INFO_ERR_BAD_TYPE  1<<10
+#define XML_SCHEMA_ELEM_INFO_HAS_ELEM_CONTENT  (1<<7)
+#define XML_SCHEMA_ELEM_INFO_ERR_BAD_CONTENT   (1<<8)
+#define XML_SCHEMA_NODE_INFO_ERR_NOT_EXPECTED  (1<<9)
+#define XML_SCHEMA_NODE_INFO_ERR_BAD_TYPE      (1<<10)
 
 /**
  * xmlSchemaNodeInfo:
@@ -3427,21 +3441,23 @@ xmlSchemaItemListClear(xmlSchemaItemListPtr list)
 }
 
 static int
-xmlSchemaItemListAdd(xmlSchemaItemListPtr list, void *item)
+xmlSchemaItemListGrow(xmlSchemaItemListPtr list, int initialSize)
 {
-    if (list->sizeItems <= list->nbItems) {
-        void **tmp;
-        size_t newSize = list->sizeItems == 0 ? 20 : list->sizeItems * 2;
+    void **tmp;
+    int newSize;
 
-	tmp = (void **) xmlRealloc(list->items, newSize * sizeof(void *));
-	if (tmp == NULL) {
-	    xmlSchemaPErrMemory(NULL);
-	    return(-1);
-	}
-        list->items = tmp;
-	list->sizeItems = newSize;
-    }
-    list->items[list->nbItems++] = item;
+    if (initialSize <= 0)
+        initialSize = 1;
+    newSize = xmlGrowCapacity(list->sizeItems, sizeof(tmp[0]),
+                              initialSize, XML_MAX_ITEMS);
+    if (newSize < 0)
+        return(-1);
+    tmp = xmlRealloc(list->items, newSize * sizeof(tmp[0]));
+    if (tmp == NULL)
+        return(-1);
+
+    list->items = tmp;
+    list->sizeItems = newSize;
     return(0);
 }
 
@@ -3450,90 +3466,33 @@ xmlSchemaItemListAddSize(xmlSchemaItemListPtr list,
 			 int initialSize,
 			 void *item)
 {
-    if (list->items == NULL) {
-	if (initialSize <= 0)
-	    initialSize = 1;
-	list->items = (void **) xmlMalloc(
-	    initialSize * sizeof(void *));
-	if (list->items == NULL) {
-	    xmlSchemaPErrMemory(NULL);
-	    return(-1);
-	}
-	list->sizeItems = initialSize;
-    } else if (list->sizeItems <= list->nbItems) {
-        void **tmp;
-
-	list->sizeItems *= 2;
-	tmp = (void **) xmlRealloc(list->items,
-	    list->sizeItems * sizeof(void *));
-	if (tmp == NULL) {
+    if (list->sizeItems <= list->nbItems) {
+        if (xmlSchemaItemListGrow(list, initialSize) < 0) {
 	    xmlSchemaPErrMemory(NULL);
-	    list->sizeItems /= 2;
 	    return(-1);
-	}
-        list->items = tmp;
+        }
     }
+
     list->items[list->nbItems++] = item;
     return(0);
 }
 
 static int
-xmlSchemaItemListInsert(xmlSchemaItemListPtr list, void *item, int idx)
+xmlSchemaItemListAdd(xmlSchemaItemListPtr list, void *item)
 {
-    if (list->sizeItems <= list->nbItems) {
-        void **tmp;
-        size_t newSize = list->sizeItems == 0 ? 20 : list->sizeItems * 2;
-
-	tmp = (void **) xmlRealloc(list->items, newSize * sizeof(void *));
-	if (tmp == NULL) {
-	    xmlSchemaPErrMemory(NULL);
-	    return(-1);
-	}
-        list->items = tmp;
-	list->sizeItems = newSize;
-    }
-    /*
-    * Just append if the index is greater/equal than the item count.
-    */
-    if (idx >= list->nbItems) {
-	list->items[list->nbItems++] = item;
-    } else {
-	int i;
-	for (i = list->nbItems; i > idx; i--)
-	    list->items[i] = list->items[i-1];
-	list->items[idx] = item;
-	list->nbItems++;
-    }
-    return(0);
+    return(xmlSchemaItemListAddSize(list, 20, item));
 }
 
-#if 0 /* enable if ever needed */
 static int
-xmlSchemaItemListInsertSize(xmlSchemaItemListPtr list,
-			    int initialSize,
-			    void *item,
-			    int idx)
-{
-    if (list->items == NULL) {
-	if (initialSize <= 0)
-	    initialSize = 1;
-	list->items = (void **) xmlMalloc(
-	    initialSize * sizeof(void *));
-	if (list->items == NULL) {
-	    xmlSchemaPErrMemory(NULL);
-	    return(-1);
-	}
-	list->sizeItems = initialSize;
-    } else if (list->sizeItems <= list->nbItems) {
-	list->sizeItems *= 2;
-	list->items = (void **) xmlRealloc(list->items,
-	    list->sizeItems * sizeof(void *));
-	if (list->items == NULL) {
+xmlSchemaItemListInsert(xmlSchemaItemListPtr list, void *item, int idx)
+{
+    if (list->sizeItems <= list->nbItems) {
+        if (xmlSchemaItemListGrow(list, 20) < 0) {
 	    xmlSchemaPErrMemory(NULL);
-	    list->sizeItems = 0;
 	    return(-1);
-	}
+        }
     }
+
     /*
     * Just append if the index is greater/equal than the item count.
     */
@@ -3548,7 +3507,6 @@ xmlSchemaItemListInsertSize(xmlSchemaItemListPtr list,
     }
     return(0);
 }
-#endif
 
 static int
 xmlSchemaItemListRemove(xmlSchemaItemListPtr list, int idx)
@@ -8904,17 +8862,14 @@ xmlSchemaParseUnion(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
 		}
 		link->type = NULL;
 		link->next = NULL;
-		if (lastLink == NULL)
-		    type->memberTypes = link;
-		else
-		    lastLink->next = link;
-		lastLink = link;
 		/*
 		* Create a reference item.
 		*/
 		ref = xmlSchemaNewQNameRef(ctxt, XML_SCHEMA_TYPE_SIMPLE,
 		    localName, nsName);
 		if (ref == NULL) {
+                    xmlSchemaPErrMemory(ctxt);
+                    xmlFree(link);
 		    FREE_AND_NULL(tmp)
 		    return (-1);
 		}
@@ -8923,6 +8878,12 @@ xmlSchemaParseUnion(xmlSchemaParserCtxtPtr ctxt, xmlSchemaPtr schema,
 		* later during fixup of the union simple type.
 		*/
 		link->type = (xmlSchemaTypePtr) ref;
+
+		if (lastLink == NULL)
+		    type->memberTypes = link;
+		else
+		    lastLink->next = link;
+		lastLink = link;
 	    }
 	    FREE_AND_NULL(tmp)
 	    cur = end;
@@ -21922,8 +21883,15 @@ xmlSchemaVAddNodeQName(xmlSchemaValidCtxtPtr vctxt,
     }
     /* Add new entry. */
     i = vctxt->nodeQNames->nbItems;
-    xmlSchemaItemListAdd(vctxt->nodeQNames, (void *) lname);
-    xmlSchemaItemListAdd(vctxt->nodeQNames, (void *) nsname);
+    if (xmlSchemaItemListAdd(vctxt->nodeQNames, (void *) lname) < 0) {
+        xmlSchemaVErrMemory(vctxt);
+        return(-1);
+    }
+    if (xmlSchemaItemListAdd(vctxt->nodeQNames, (void *) nsname) < 0) {
+        vctxt->nodeQNames->nbItems--;
+        xmlSchemaVErrMemory(vctxt);
+        return(-1);
+    }
     return(i);
 }
 
@@ -22029,26 +21997,27 @@ xmlSchemaIDCStoreNodeTableItem(xmlSchemaValidCtxtPtr vctxt,
     /*
     * Add to global list.
     */
-    if (vctxt->idcNodes == NULL) {
-	vctxt->idcNodes = (xmlSchemaPSVIIDCNodePtr *)
-	    xmlMalloc(20 * sizeof(xmlSchemaPSVIIDCNodePtr));
-	if (vctxt->idcNodes == NULL) {
+    if (vctxt->sizeIdcNodes <= vctxt->nbIdcNodes) {
+        xmlSchemaPSVIIDCNodePtr *tmp;
+        int newSize;
+
+        newSize = xmlGrowCapacity(vctxt->sizeIdcNodes, sizeof(tmp[0]),
+                                  20, XML_MAX_ITEMS);
+	if (newSize < 0) {
 	    xmlSchemaVErrMemory(vctxt);
 	    return (-1);
 	}
-	vctxt->sizeIdcNodes = 20;
-    } else if (vctxt->sizeIdcNodes <= vctxt->nbIdcNodes) {
-	vctxt->sizeIdcNodes *= 2;
-	vctxt->idcNodes = (xmlSchemaPSVIIDCNodePtr *)
-	    xmlRealloc(vctxt->idcNodes, vctxt->sizeIdcNodes *
-	    sizeof(xmlSchemaPSVIIDCNodePtr));
-	if (vctxt->idcNodes == NULL) {
+	tmp = xmlRealloc(vctxt->idcNodes, newSize * sizeof(tmp[0]));
+	if (tmp == NULL) {
 	    xmlSchemaVErrMemory(vctxt);
 	    return (-1);
 	}
+
+        vctxt->idcNodes = tmp;
+        vctxt->sizeIdcNodes = newSize;
     }
-    vctxt->idcNodes[vctxt->nbIdcNodes++] = item;
 
+    vctxt->idcNodes[vctxt->nbIdcNodes++] = item;
     return (0);
 }
 
@@ -22068,26 +22037,27 @@ xmlSchemaIDCStoreKey(xmlSchemaValidCtxtPtr vctxt,
     /*
     * Add to global list.
     */
-    if (vctxt->idcKeys == NULL) {
-	vctxt->idcKeys = (xmlSchemaPSVIIDCKeyPtr *)
-	    xmlMalloc(40 * sizeof(xmlSchemaPSVIIDCKeyPtr));
-	if (vctxt->idcKeys == NULL) {
+    if (vctxt->sizeIdcKeys <= vctxt->nbIdcKeys) {
+        xmlSchemaPSVIIDCKeyPtr *tmp;
+        int newSize;
+
+        newSize = xmlGrowCapacity(vctxt->sizeIdcKeys, sizeof(tmp[0]),
+                                  20, XML_MAX_ITEMS);
+	if (newSize < 0) {
 	    xmlSchemaVErrMemory(vctxt);
 	    return (-1);
 	}
-	vctxt->sizeIdcKeys = 40;
-    } else if (vctxt->sizeIdcKeys <= vctxt->nbIdcKeys) {
-	vctxt->sizeIdcKeys *= 2;
-	vctxt->idcKeys = (xmlSchemaPSVIIDCKeyPtr *)
-	    xmlRealloc(vctxt->idcKeys, vctxt->sizeIdcKeys *
-	    sizeof(xmlSchemaPSVIIDCKeyPtr));
-	if (vctxt->idcKeys == NULL) {
+	tmp = xmlRealloc(vctxt->idcKeys, newSize * sizeof(tmp[0]));
+	if (tmp == NULL) {
 	    xmlSchemaVErrMemory(vctxt);
 	    return (-1);
 	}
+
+        vctxt->idcKeys = tmp;
+        vctxt->sizeIdcKeys = newSize;
     }
-    vctxt->idcKeys[vctxt->nbIdcKeys++] = key;
 
+    vctxt->idcKeys[vctxt->nbIdcKeys++] = key;
     return (0);
 }
 
@@ -22104,24 +22074,26 @@ static int
 xmlSchemaIDCAppendNodeTableItem(xmlSchemaPSVIIDCBindingPtr bind,
 				xmlSchemaPSVIIDCNodePtr ntItem)
 {
-    if (bind->nodeTable == NULL) {
-	bind->sizeNodes = 10;
-	bind->nodeTable = (xmlSchemaPSVIIDCNodePtr *)
-	    xmlMalloc(10 * sizeof(xmlSchemaPSVIIDCNodePtr));
-	if (bind->nodeTable == NULL) {
+    if (bind->sizeNodes <= bind->nbNodes) {
+        xmlSchemaPSVIIDCNodePtr *tmp;
+        int newSize;
+
+        newSize = xmlGrowCapacity(bind->sizeNodes, sizeof(tmp[0]),
+                                  10, XML_MAX_ITEMS);
+	if (newSize < 0) {
 	    xmlSchemaVErrMemory(NULL);
 	    return(-1);
 	}
-    } else if (bind->sizeNodes <= bind->nbNodes) {
-	bind->sizeNodes *= 2;
-	bind->nodeTable = (xmlSchemaPSVIIDCNodePtr *)
-	    xmlRealloc(bind->nodeTable, bind->sizeNodes *
-		sizeof(xmlSchemaPSVIIDCNodePtr));
-	if (bind->nodeTable == NULL) {
+	tmp = xmlRealloc(bind->nodeTable, newSize * sizeof(tmp[0]));
+	if (tmp == NULL) {
 	    xmlSchemaVErrMemory(NULL);
 	    return(-1);
 	}
+
+        bind->nodeTable = tmp;
+        bind->sizeNodes = newSize;
     }
+
     bind->nodeTable[bind->nbNodes++] = ntItem;
     return(0);
 }
@@ -22170,11 +22142,14 @@ xmlSchemaIDCAcquireBinding(xmlSchemaValidCtxtPtr vctxt,
 }
 
 static xmlSchemaItemListPtr
-xmlSchemaIDCAcquireTargetList(xmlSchemaValidCtxtPtr vctxt ATTRIBUTE_UNUSED,
-			     xmlSchemaIDCMatcherPtr matcher)
+xmlSchemaIDCAcquireTargetList(xmlSchemaValidCtxtPtr vctxt,
+			      xmlSchemaIDCMatcherPtr matcher)
 {
-    if (matcher->targets == NULL)
+    if (matcher->targets == NULL) {
 	matcher->targets = xmlSchemaItemListCreate();
+        if (matcher->targets == NULL)
+            xmlSchemaVErrMemory(vctxt);
+    }
     return(matcher->targets);
 }
 
@@ -22463,21 +22438,24 @@ xmlSchemaXPathEvaluate(xmlSchemaValidCtxtPtr vctxt,
 	/*
 	* Register a match in the state object history.
 	*/
-	if (sto->history == NULL) {
-	    sto->history = (int *) xmlMalloc(5 * sizeof(int));
-	    if (sto->history == NULL) {
-		xmlSchemaVErrMemory(NULL);
-		return(-1);
-	    }
-	    sto->sizeHistory = 5;
-	} else if (sto->sizeHistory <= sto->nbHistory) {
-	    sto->sizeHistory *= 2;
-	    sto->history = (int *) xmlRealloc(sto->history,
-		sto->sizeHistory * sizeof(int));
-	    if (sto->history == NULL) {
-		xmlSchemaVErrMemory(NULL);
-		return(-1);
-	    }
+        if (sto->sizeHistory <= sto->nbHistory) {
+            int *tmp;
+            int newSize;
+
+            newSize = xmlGrowCapacity(sto->sizeHistory, sizeof(tmp[0]),
+                                      5, XML_MAX_ITEMS);
+            if (newSize < 0) {
+                xmlSchemaVErrMemory(vctxt);
+                return (-1);
+            }
+            tmp = xmlRealloc(sto->history, newSize * sizeof(tmp[0]));
+            if (tmp == NULL) {
+                xmlSchemaVErrMemory(vctxt);
+                return (-1);
+            }
+
+            sto->history = tmp;
+            sto->sizeHistory = newSize;
 	}
 	sto->history[sto->nbHistory++] = depth;
 
@@ -22734,38 +22712,32 @@ xmlSchemaXPathProcessHistory(xmlSchemaValidCtxtPtr vctxt,
 		/*
 		* Create/grow the array of key-sequences.
 		*/
-		if (matcher->keySeqs == NULL) {
-		    if (pos > 9)
-			matcher->sizeKeySeqs = pos * 2;
-		    else
-			matcher->sizeKeySeqs = 10;
-		    matcher->keySeqs = (xmlSchemaPSVIIDCKeyPtr **)
-			xmlMalloc(matcher->sizeKeySeqs *
-			sizeof(xmlSchemaPSVIIDCKeyPtr *));
-		    if (matcher->keySeqs == NULL) {
-			xmlSchemaVErrMemory(NULL);
-			return(-1);
-		    }
-		    memset(matcher->keySeqs, 0,
-			matcher->sizeKeySeqs *
-			sizeof(xmlSchemaPSVIIDCKeyPtr *));
-		} else if (pos >= matcher->sizeKeySeqs) {
-		    int i = matcher->sizeKeySeqs;
-
-		    matcher->sizeKeySeqs = pos * 2;
-		    matcher->keySeqs = (xmlSchemaPSVIIDCKeyPtr **)
-			xmlRealloc(matcher->keySeqs,
-			matcher->sizeKeySeqs *
-			sizeof(xmlSchemaPSVIIDCKeyPtr *));
-		    if (matcher->keySeqs == NULL) {
-			xmlSchemaVErrMemory(NULL);
-			return (-1);
-		    }
+                if (pos >= matcher->sizeKeySeqs) {
+                    xmlSchemaPSVIIDCKeyPtr **tmp;
+                    int oldSize = matcher->sizeKeySeqs;
+                    int newSize, i;
+
+                    newSize = xmlGrowCapacity(pos, sizeof(tmp[0]),
+                                              10, XML_MAX_ITEMS);
+                    if (newSize < 0) {
+                        xmlSchemaVErrMemory(vctxt);
+                        return (-1);
+                    }
+                    tmp = xmlRealloc(matcher->keySeqs,
+                                     newSize * sizeof(tmp[0]));
+                    if (tmp == NULL) {
+                        xmlSchemaVErrMemory(vctxt);
+                        return (-1);
+                    }
+
+                    matcher->keySeqs = tmp;
+                    matcher->sizeKeySeqs = newSize;
+
 		    /*
 		    * The array needs to be NULLed.
 		    * TODO: Use memset?
 		    */
-		    for (; i < matcher->sizeKeySeqs; i++)
+		    for (i = oldSize; i < newSize; i++)
 			matcher->keySeqs[i] = NULL;
 		}
 
@@ -22918,6 +22890,9 @@ create_key:
 	    bind = xmlSchemaIDCAcquireBinding(vctxt, matcher);
 #endif
 	    targets = xmlSchemaIDCAcquireTargetList(vctxt, matcher);
+            if (targets == NULL)
+                return(-1);
+
 	    if ((idc->type != XML_SCHEMA_TYPE_IDC_KEYREF) &&
 		(targets->nbItems != 0)) {
 		xmlSchemaPSVIIDCKeyPtr ckey, bkey, *bkeySeq;
@@ -23045,6 +23020,10 @@ create_key:
 		  matcher->htab = xmlHashCreate(4);
 		xmlSchemaHashKeySequence(vctxt, &value, ntItem->keys, nbKeys);
 		e = xmlMalloc(sizeof *e);
+                if (e == NULL) {
+                    xmlSchemaVErrMemory(vctxt);
+                    goto mem_error;
+                }
 		e->index = targets->nbItems - 1;
 		r = xmlHashLookup(matcher->htab, value);
 		if (r) {
@@ -23052,8 +23031,12 @@ create_key:
 		    r->next = e;
 		} else {
 		    e->next = NULL;
-		    xmlHashAddEntry(matcher->htab, value, e);
+		    if (xmlHashAddEntry(matcher->htab, value, e) < 0) {
+                        xmlSchemaVErrMemory(vctxt);
+                        xmlFree(e);
+                    }
 		}
+mem_error:
 		FREE_AND_NULL(value);
 	    }
 
@@ -23286,6 +23269,8 @@ xmlSchemaIDCFillNodeTables(xmlSchemaValidCtxtPtr vctxt,
 	    /*
 	    * Transfer all IDC target-nodes to the IDC node-table.
 	    */
+            if (bind->nodeTable != NULL)
+                xmlFree(bind->nodeTable);
 	    bind->nodeTable =
 		(xmlSchemaPSVIIDCNodePtr *) matcher->targets->items;
 	    bind->sizeNodes = matcher->targets->sizeItems;
@@ -23611,23 +23596,26 @@ xmlSchemaBubbleIDCNodeTables(xmlSchemaValidCtxtPtr vctxt)
 			* Add the node-table entry (node and key-sequence) of
 			* the child node to the node table of the parent node.
 			*/
-			if (parBind->nodeTable == NULL) {
-			    parBind->nodeTable = (xmlSchemaPSVIIDCNodePtr *)
-				xmlMalloc(10 * sizeof(xmlSchemaPSVIIDCNodePtr));
-			    if (parBind->nodeTable == NULL) {
-				xmlSchemaVErrMemory(NULL);
-				goto internal_error;
-			    }
-			    parBind->sizeNodes = 1;
-			} else if (parBind->nbNodes >= parBind->sizeNodes) {
-			    parBind->sizeNodes *= 2;
-			    parBind->nodeTable = (xmlSchemaPSVIIDCNodePtr *)
-				xmlRealloc(parBind->nodeTable, parBind->sizeNodes *
-				sizeof(xmlSchemaPSVIIDCNodePtr));
-			    if (parBind->nodeTable == NULL) {
-				xmlSchemaVErrMemory(NULL);
-				goto internal_error;
-			    }
+                        if (parBind->nbNodes >= parBind->sizeNodes) {
+                            xmlSchemaPSVIIDCNodePtr *tmp;
+                            int newSize;
+
+                            newSize = xmlGrowCapacity(parBind->sizeNodes,
+                                                      sizeof(tmp[0]),
+                                                      10, XML_MAX_ITEMS);
+                            if (newSize < 0) {
+                                xmlSchemaVErrMemory(vctxt);
+                                goto internal_error;
+                            }
+                            tmp = xmlRealloc(parBind->nodeTable,
+                                             newSize * sizeof(tmp[0]));
+                            if (tmp == NULL) {
+                                xmlSchemaVErrMemory(vctxt);
+                                goto internal_error;
+                            }
+
+                            parBind->nodeTable = tmp;
+                            parBind->sizeNodes = newSize;
 			}
 			parNodes = parBind->nodeTable;
 			/*
@@ -23767,6 +23755,10 @@ xmlSchemaCheckCVCIDCKeyRef(xmlSchemaValidCtxtPtr vctxt)
 		    keys = bind->nodeTable[j]->keys;
 		    xmlSchemaHashKeySequence(vctxt, &value, keys, nbFields);
 		    e = xmlMalloc(sizeof *e);
+                    if (e == NULL) {
+                        xmlSchemaVErrMemory(vctxt);
+                        goto mem_error;
+                    }
 		    e->index = j;
 		    r = xmlHashLookup(table, value);
 		    if (r) {
@@ -23774,8 +23766,12 @@ xmlSchemaCheckCVCIDCKeyRef(xmlSchemaValidCtxtPtr vctxt)
 			r->next = e;
 		    } else {
 			e->next = NULL;
-			xmlHashAddEntry(table, value, e);
+                        if (xmlHashAddEntry(table, value, e) < 0) {
+                            xmlSchemaVErrMemory(vctxt);
+                            xmlFree(e);
+                        }
 		    }
+mem_error:
 		    FREE_AND_NULL(value);
 		}
 	    }
@@ -23882,33 +23878,41 @@ xmlSchemaGetFreshAttrInfo(xmlSchemaValidCtxtPtr vctxt)
     /*
     * Grow/create list of attribute infos.
     */
-    if (vctxt->attrInfos == NULL) {
-	vctxt->attrInfos = (xmlSchemaAttrInfoPtr *)
-	    xmlMalloc(sizeof(xmlSchemaAttrInfoPtr));
-	vctxt->sizeAttrInfos = 1;
-	if (vctxt->attrInfos == NULL) {
+    if (vctxt->sizeAttrInfos <= vctxt->nbAttrInfos) {
+        xmlSchemaAttrInfoPtr *tmp;
+        int oldSize = vctxt->sizeAttrInfos;
+        int newSize, i;
+
+        newSize = xmlGrowCapacity(oldSize, sizeof(tmp[0]), 5, XML_MAX_ITEMS);
+	if (newSize < 0) {
 	    xmlSchemaVErrMemory(vctxt);
 	    return (NULL);
 	}
-    } else if (vctxt->sizeAttrInfos <= vctxt->nbAttrInfos) {
-	vctxt->sizeAttrInfos++;
-	vctxt->attrInfos = (xmlSchemaAttrInfoPtr *)
-	    xmlRealloc(vctxt->attrInfos,
-		vctxt->sizeAttrInfos * sizeof(xmlSchemaAttrInfoPtr));
-	if (vctxt->attrInfos == NULL) {
+	tmp = xmlRealloc(vctxt->attrInfos, newSize * sizeof(tmp[0]));
+	if (tmp == NULL) {
 	    xmlSchemaVErrMemory(vctxt);
 	    return (NULL);
 	}
-    } else {
-	iattr = vctxt->attrInfos[vctxt->nbAttrInfos++];
+
+        vctxt->attrInfos = tmp;
+        vctxt->sizeAttrInfos = newSize;
+
+        for (i = oldSize; i < newSize; i++)
+            vctxt->attrInfos[i] = NULL;
+    }
+
+    iattr = vctxt->attrInfos[vctxt->nbAttrInfos];
+    if (iattr != NULL) {
 	if (iattr->localName != NULL) {
 	    VERROR_INT("xmlSchemaGetFreshAttrInfo",
 		"attr info not cleared");
 	    return (NULL);
 	}
 	iattr->nodeType = XML_ATTRIBUTE_NODE;
+        vctxt->nbAttrInfos++;
 	return (iattr);
     }
+
     /*
     * Create an attribute info.
     */
@@ -24062,31 +24066,30 @@ xmlSchemaGetFreshElemInfo(xmlSchemaValidCtxtPtr vctxt)
 	    "inconsistent depth encountered");
 	return (NULL);
     }
-    if (vctxt->elemInfos == NULL) {
-	vctxt->elemInfos = (xmlSchemaNodeInfoPtr *)
-	    xmlMalloc(10 * sizeof(xmlSchemaNodeInfoPtr));
-	if (vctxt->elemInfos == NULL) {
-	    xmlSchemaVErrMemory(vctxt);
-	    return (NULL);
-	}
-	memset(vctxt->elemInfos, 0, 10 * sizeof(xmlSchemaNodeInfoPtr));
-	vctxt->sizeElemInfos = 10;
-    } else if (vctxt->sizeElemInfos <= vctxt->depth) {
-	int i = vctxt->sizeElemInfos;
+    if (vctxt->sizeElemInfos <= vctxt->depth) {
+        xmlSchemaNodeInfoPtr *tmp;
+        int oldSize = vctxt->sizeElemInfos;
+        int newSize, i;
+
+        newSize = xmlGrowCapacity(oldSize, sizeof(tmp[0]), 10, XML_MAX_ITEMS);
+        if (newSize < 0) {
+            xmlSchemaVErrMemory(vctxt);
+            return (NULL);
+        }
+        tmp = xmlRealloc(vctxt->elemInfos, newSize * sizeof(tmp[0]));
+        if (tmp == NULL) {
+            xmlSchemaVErrMemory(vctxt);
+            return (NULL);
+        }
+
+        vctxt->elemInfos = tmp;
+        vctxt->sizeElemInfos = newSize;
 
-	vctxt->sizeElemInfos *= 2;
-	vctxt->elemInfos = (xmlSchemaNodeInfoPtr *)
-	    xmlRealloc(vctxt->elemInfos, vctxt->sizeElemInfos *
-	    sizeof(xmlSchemaNodeInfoPtr));
-	if (vctxt->elemInfos == NULL) {
-	    xmlSchemaVErrMemory(vctxt);
-	    return (NULL);
-	}
 	/*
 	* We need the new memory to be NULLed.
 	* TODO: Use memset instead?
 	*/
-	for (; i < vctxt->sizeElemInfos; i++)
+	for (i = oldSize; i < newSize; i++)
 	    vctxt->elemInfos[i] = NULL;
     } else
 	info = vctxt->elemInfos[vctxt->depth];
@@ -26689,6 +26692,8 @@ xmlSchemaVPushText(xmlSchemaValidCtxtPtr vctxt,
 		* When working on a tree.
 		*/
 		vctxt->inode->value = value;
+		vctxt->inode->flags &=
+		    ~XML_SCHEMA_NODE_INFO_FLAG_OWNED_VALUES;
 		break;
 	    case XML_SCHEMA_PUSH_TEXT_CREATED:
 		/*
@@ -27239,26 +27244,25 @@ xmlSchemaSAXHandleStartElementNs(void *ctx,
 	    /*
 	    * Store prefix and namespace name.
 	    */
-	    if (ielem->nsBindings == NULL) {
-		ielem->nsBindings =
-		    (const xmlChar **) xmlMalloc(10 *
-			sizeof(const xmlChar *));
-		if (ielem->nsBindings == NULL) {
-		    xmlSchemaVErrMemory(vctxt);
-		    goto internal_error;
-		}
-		ielem->nbNsBindings = 0;
-		ielem->sizeNsBindings = 5;
-	    } else if (ielem->sizeNsBindings <= ielem->nbNsBindings) {
-		ielem->sizeNsBindings *= 2;
-		ielem->nsBindings =
-		    (const xmlChar **) xmlRealloc(
-			(void *) ielem->nsBindings,
-			ielem->sizeNsBindings * 2 * sizeof(const xmlChar *));
-		if (ielem->nsBindings == NULL) {
-		    xmlSchemaVErrMemory(vctxt);
-		    goto internal_error;
-		}
+            if (ielem->sizeNsBindings <= ielem->nbNsBindings) {
+                const xmlChar **tmp;
+                size_t elemSize = 2 * sizeof(tmp[0]);
+                int newSize;
+
+                newSize = xmlGrowCapacity(ielem->sizeNsBindings, elemSize,
+                                          5, XML_MAX_ITEMS);
+                if (newSize < 0) {
+                    xmlSchemaVErrMemory(vctxt);
+                    goto internal_error;
+                }
+                tmp = xmlRealloc(ielem->nsBindings, newSize * elemSize);
+                if (tmp == NULL) {
+                    xmlSchemaVErrMemory(vctxt);
+                    goto internal_error;
+                }
+
+                ielem->nsBindings = tmp;
+                ielem->sizeNsBindings = newSize;
 	    }
 
 	    ielem->nsBindings[ielem->nbNsBindings * 2] = namespaces[j];
@@ -27415,7 +27419,15 @@ xmlSchemaNewValidCtxt(xmlSchemaPtr schema)
     memset(ret, 0, sizeof(xmlSchemaValidCtxt));
     ret->type = XML_SCHEMA_CTXT_VALIDATOR;
     ret->dict = xmlDictCreate();
+    if (ret->dict == NULL) {
+        xmlSchemaFreeValidCtxt(ret);
+        return(NULL);
+    }
     ret->nodeQNames = xmlSchemaItemListCreate();
+    if (ret->nodeQNames == NULL) {
+        xmlSchemaFreeValidCtxt(ret);
+        return(NULL);
+    }
     ret->schema = schema;
     return (ret);
 }
@@ -27845,10 +27857,14 @@ xmlSchemaVDocWalk(xmlSchemaValidCtxtPtr vctxt)
 	    if (node->properties != NULL) {
 		attr = node->properties;
 		do {
+                    xmlChar *content;
+
 		    if (attr->ns != NULL)
 			nsName = attr->ns->href;
 		    else
 			nsName = NULL;
+                    content = xmlNodeListGetString(attr->doc,
+                                                   attr->children, 1);
 		    ret = xmlSchemaValidatorPushAttribute(vctxt,
 			(xmlNodePtr) attr,
 			/*
@@ -27857,10 +27873,11 @@ xmlSchemaVDocWalk(xmlSchemaValidCtxtPtr vctxt)
 			*/
 			ielem->nodeLine,
 			attr->name, nsName, 0,
-			xmlNodeListGetString(attr->doc, attr->children, 1), 1);
+			content, 1);
 		    if (ret == -1) {
 			VERROR_INT("xmlSchemaDocWalk",
 			    "calling xmlSchemaValidatorPushAttribute()");
+                        xmlFree(content);
 			goto internal_error;
 		    }
 		    attr = attr->next;
@@ -28772,7 +28789,7 @@ done:
 int
 xmlSchemaValidateStream(xmlSchemaValidCtxtPtr ctxt,
                         xmlParserInputBufferPtr input, xmlCharEncoding enc,
-                        xmlSAXHandlerPtr sax, void *user_data)
+                        const xmlSAXHandler *sax, void *user_data)
 {
     xmlParserCtxtPtr pctxt = NULL;
     xmlParserInputPtr inputStream = NULL;
@@ -28806,7 +28823,7 @@ xmlSchemaValidateStream(xmlSchemaValidCtxtPtr ctxt,
         ret = -1;
 	goto done;
     }
-    if (inputPush(pctxt, inputStream) < 0) {
+    if (xmlCtxtPushInput(pctxt, inputStream) < 0) {
         xmlFreeInputStream(inputStream);
         ret = -1;
         goto done;
diff --git a/xmlschemastypes.c b/xmlschemastypes.c
index 1d91aaf2..24c68b94 100644
--- a/xmlschemastypes.c
+++ b/xmlschemastypes.c
@@ -35,6 +35,7 @@
 #include <libxml/xmlschemastypes.h>
 
 #include "private/error.h"
+#include "private/parser.h"
 
 #ifndef isnan
   #define isnan(x) (!((x) == (x)))
@@ -327,8 +328,11 @@ xmlSchemaInitBasicType(const char *name, xmlSchemaValType type,
 	    ret->flags |= XML_SCHEMAS_TYPE_VARIETY_ATOMIC;
 	    break;
     }
-    xmlHashAddEntry2(xmlSchemaTypesBank, ret->name,
-	             XML_SCHEMAS_NAMESPACE_NAME, ret);
+    if (xmlHashAddEntry2(xmlSchemaTypesBank, ret->name,
+	                 XML_SCHEMAS_NAMESPACE_NAME, ret) < 0) {
+        xmlSchemaFreeType(ret);
+        return(NULL);
+    }
     ret->builtInType = type;
     return(ret);
 }
@@ -496,13 +500,20 @@ xmlSchemaCleanupTypesInternal(void) {
         xmlSchemaFreeWildcard(xmlSchemaTypeAnyTypeDef->attributeWildcard);
         /* Content type. */
         particle = (xmlSchemaParticlePtr) xmlSchemaTypeAnyTypeDef->subtypes;
-        /* Wildcard. */
-        xmlSchemaFreeWildcard((xmlSchemaWildcardPtr)
-            particle->children->children->children);
-        xmlFree((xmlSchemaParticlePtr) particle->children->children);
-        /* Sequence model group. */
-        xmlFree((xmlSchemaModelGroupPtr) particle->children);
-        xmlFree((xmlSchemaParticlePtr) particle);
+        if (particle != NULL) {
+            if (particle->children != NULL) {
+                if (particle->children->children != NULL) {
+                    /* Wildcard. */
+                    xmlSchemaFreeWildcard((xmlSchemaWildcardPtr)
+                        particle->children->children->children);
+                    xmlFree((xmlSchemaParticlePtr)
+                        particle->children->children);
+                }
+                /* Sequence model group. */
+                xmlFree((xmlSchemaModelGroupPtr) particle->children);
+            }
+            xmlFree((xmlSchemaParticlePtr) particle);
+        }
         xmlSchemaTypeAnyTypeDef->subtypes = NULL;
         xmlSchemaTypeAnyTypeDef = NULL;
     }
@@ -2223,6 +2234,8 @@ xmlSchemaWhiteSpaceReplace(const xmlChar *value) {
     if (*cur == 0)
 	return (NULL);
     ret = xmlStrdup(value);
+    if (ret == NULL)
+        return(NULL);
     /* TODO FIXME: I guess gcc will bark at this. */
     mcur = (xmlChar *)  (ret + (cur - value));
     do {
@@ -2392,6 +2405,8 @@ static int xmlSchemaParseUInt(const xmlChar **str, xmlSchemaValDecimalPtr val) {
         }
         /*  sign, dot, fractional 0 and NULL terminator */
         val->str = xmlMalloc(i + 4);
+        if (val->str == NULL)
+            return(-1);
     }
     val->fractionalPlaces = 1;
     val->integralPlaces = i;
@@ -2678,6 +2693,7 @@ xmlSchemaValAtomicType(xmlSchemaTypePtr type, const xmlChar * value,
                         decimal.str = xmlMalloc(bufsize);
                         if (!decimal.str)
                         {
+                            xmlSchemaFreeValue(v);
                             goto error;
                         }
                         snprintf((char *)decimal.str, bufsize, "%c%.*s.%.*s", sign, decimal.integralPlaces, integralStart,
@@ -3578,10 +3594,12 @@ xmlSchemaValAtomicType(xmlSchemaTypePtr type, const xmlChar * value,
                 }
                 if (val != NULL) {
                     v = xmlSchemaNewValue(type->builtInType);
-                    if (v != NULL) {
-                        v->value.decimal = decimal;
-                        *val = v;
+                    if (v == NULL) {
+                        xmlFree(decimal.str);
+                        goto error;
                     }
+                    v->value.decimal = decimal;
+                    *val = v;
                 }
                 else if(decimal.str != NULL)
                 {
@@ -4103,11 +4121,12 @@ xmlSchemaDateNormalize (xmlSchemaValPtr dt, double offset)
     dur->value.date.sec -= offset;
 
     ret = _xmlSchemaDateAdd(dt, dur);
-    if (ret == NULL)
-        return NULL;
 
     xmlSchemaFreeValue(dur);
 
+    if (ret == NULL)
+        return NULL;
+
     /* ret->value.date.tzo = 0; */
     return ret;
 }
diff --git a/xpath.c b/xpath.c
index e3ca1e16..30ba4871 100644
--- a/xpath.c
+++ b/xpath.c
@@ -46,6 +46,8 @@
 
 #include "private/buf.h"
 #include "private/error.h"
+#include "private/memory.h"
+#include "private/parser.h"
 #include "private/xpath.h"
 
 /* Disabled for now */
@@ -133,11 +135,48 @@
 
 #if defined(LIBXML_XPATH_ENABLED)
 
-/************************************************************************
- *									*
- *			Floating point stuff				*
- *									*
- ************************************************************************/
+static void
+xmlXPathNameFunction(xmlXPathParserContextPtr ctxt, int nargs);
+
+static const struct {
+    const char *name;
+    xmlXPathFunction func;
+} xmlXPathStandardFunctions[] = {
+    { "boolean", xmlXPathBooleanFunction },
+    { "ceiling", xmlXPathCeilingFunction },
+    { "count", xmlXPathCountFunction },
+    { "concat", xmlXPathConcatFunction },
+    { "contains", xmlXPathContainsFunction },
+    { "id", xmlXPathIdFunction },
+    { "false", xmlXPathFalseFunction },
+    { "floor", xmlXPathFloorFunction },
+    { "last", xmlXPathLastFunction },
+    { "lang", xmlXPathLangFunction },
+    { "local-name", xmlXPathLocalNameFunction },
+    { "not", xmlXPathNotFunction },
+    { "name", xmlXPathNameFunction },
+    { "namespace-uri", xmlXPathNamespaceURIFunction },
+    { "normalize-space", xmlXPathNormalizeFunction },
+    { "number", xmlXPathNumberFunction },
+    { "position", xmlXPathPositionFunction },
+    { "round", xmlXPathRoundFunction },
+    { "string", xmlXPathStringFunction },
+    { "string-length", xmlXPathStringLengthFunction },
+    { "starts-with", xmlXPathStartsWithFunction },
+    { "substring", xmlXPathSubstringFunction },
+    { "substring-before", xmlXPathSubstringBeforeFunction },
+    { "substring-after", xmlXPathSubstringAfterFunction },
+    { "sum", xmlXPathSumFunction },
+    { "true", xmlXPathTrueFunction },
+    { "translate", xmlXPathTranslateFunction }
+};
+
+#define NUM_STANDARD_FUNCTIONS \
+    (sizeof(xmlXPathStandardFunctions) / sizeof(xmlXPathStandardFunctions[0]))
+
+#define SF_HASH_SIZE 64
+
+static unsigned char xmlXPathSFHash[SF_HASH_SIZE];
 
 double xmlXPathNAN = 0.0;
 double xmlXPathPINF = 0.0;
@@ -153,6 +192,18 @@ xmlXPathInit(void) {
     xmlInitParser();
 }
 
+ATTRIBUTE_NO_SANITIZE_INTEGER
+static unsigned
+xmlXPathSFComputeHash(const xmlChar *name) {
+    unsigned hashValue = 5381;
+    const xmlChar *ptr;
+
+    for (ptr = name; *ptr; ptr++)
+        hashValue = hashValue * 33 + *ptr;
+
+    return(hashValue);
+}
+
 /**
  * xmlInitXPathInternal:
  *
@@ -161,6 +212,8 @@ xmlXPathInit(void) {
 ATTRIBUTE_NO_SANITIZE("float-divide-by-zero")
 void
 xmlInitXPathInternal(void) {
+    size_t i;
+
 #if defined(NAN) && defined(INFINITY)
     xmlXPathNAN = NAN;
     xmlXPathPINF = INFINITY;
@@ -172,8 +225,34 @@ xmlInitXPathInternal(void) {
     xmlXPathPINF = 1.0 / zero;
     xmlXPathNINF = -xmlXPathPINF;
 #endif
+
+    /*
+     * Initialize hash table for standard functions
+     */
+
+    for (i = 0; i < SF_HASH_SIZE; i++)
+        xmlXPathSFHash[i] = UCHAR_MAX;
+
+    for (i = 0; i < NUM_STANDARD_FUNCTIONS; i++) {
+        const char *name = xmlXPathStandardFunctions[i].name;
+        int bucketIndex = xmlXPathSFComputeHash(BAD_CAST name) % SF_HASH_SIZE;
+
+        while (xmlXPathSFHash[bucketIndex] != UCHAR_MAX) {
+            bucketIndex += 1;
+            if (bucketIndex >= SF_HASH_SIZE)
+                bucketIndex = 0;
+        }
+
+        xmlXPathSFHash[bucketIndex] = i;
+    }
 }
 
+/************************************************************************
+ *									*
+ *			Floating point stuff				*
+ *									*
+ ************************************************************************/
+
 /**
  * xmlXPathIsNaN:
  * @val:  a double value
@@ -230,7 +309,10 @@ static const xmlNs *const xmlXPathXMLNamespace = &xmlXPathXMLNamespaceStruct;
 static void
 xmlXPathNodeSetClear(xmlNodeSetPtr set, int hasNsNodes);
 
+#define XML_NODE_SORT_VALUE(n) XML_PTR_TO_INT((n)->content)
+
 #ifdef XP_OPTIMIZED_NON_ELEM_COMPARISON
+
 /**
  * xmlXPathCmpNodesExt:
  * @node1:  the first node
@@ -248,7 +330,7 @@ xmlXPathCmpNodesExt(xmlNodePtr node1, xmlNodePtr node2) {
     int misc = 0, precedence1 = 0, precedence2 = 0;
     xmlNodePtr miscNode1 = NULL, miscNode2 = NULL;
     xmlNodePtr cur, root;
-    ptrdiff_t l1, l2;
+    XML_INTPTR_T l1, l2;
 
     if ((node1 == NULL) || (node2 == NULL))
 	return(-2);
@@ -262,12 +344,12 @@ xmlXPathCmpNodesExt(xmlNodePtr node1, xmlNodePtr node2) {
     switch (node1->type) {
 	case XML_ELEMENT_NODE:
 	    if (node2->type == XML_ELEMENT_NODE) {
-		if ((0 > (ptrdiff_t) node1->content) &&
-		    (0 > (ptrdiff_t) node2->content) &&
+		if ((0 > XML_NODE_SORT_VALUE(node1)) &&
+		    (0 > XML_NODE_SORT_VALUE(node2)) &&
 		    (node1->doc == node2->doc))
 		{
-		    l1 = -((ptrdiff_t) node1->content);
-		    l2 = -((ptrdiff_t) node2->content);
+		    l1 = -XML_NODE_SORT_VALUE(node1);
+		    l2 = -XML_NODE_SORT_VALUE(node2);
 		    if (l1 < l2)
 			return(1);
 		    if (l1 > l2)
@@ -312,7 +394,7 @@ xmlXPathCmpNodesExt(xmlNodePtr node1, xmlNodePtr node2) {
 		node1 = node1->parent;
 	    }
 	    if ((node1 == NULL) || (node1->type != XML_ELEMENT_NODE) ||
-		(0 <= (ptrdiff_t) node1->content)) {
+		(0 <= XML_NODE_SORT_VALUE(node1))) {
 		/*
 		* Fallback for whatever case.
 		*/
@@ -362,7 +444,7 @@ xmlXPathCmpNodesExt(xmlNodePtr node1, xmlNodePtr node2) {
 		node2 = node2->parent;
 	    }
 	    if ((node2 == NULL) || (node2->type != XML_ELEMENT_NODE) ||
-		(0 <= (ptrdiff_t) node2->content))
+		(0 <= XML_NODE_SORT_VALUE(node2)))
 	    {
 		node2 = miscNode2;
 		precedence2 = 0;
@@ -435,12 +517,12 @@ xmlXPathCmpNodesExt(xmlNodePtr node1, xmlNodePtr node2) {
      */
     if ((node1->type == XML_ELEMENT_NODE) &&
 	(node2->type == XML_ELEMENT_NODE) &&
-	(0 > (ptrdiff_t) node1->content) &&
-	(0 > (ptrdiff_t) node2->content) &&
+	(0 > XML_NODE_SORT_VALUE(node1)) &&
+	(0 > XML_NODE_SORT_VALUE(node2)) &&
 	(node1->doc == node2->doc)) {
 
-	l1 = -((ptrdiff_t) node1->content);
-	l2 = -((ptrdiff_t) node2->content);
+	l1 = -XML_NODE_SORT_VALUE(node1);
+	l2 = -XML_NODE_SORT_VALUE(node2);
 	if (l1 < l2)
 	    return(1);
 	if (l1 > l2)
@@ -503,12 +585,12 @@ turtle_comparison:
      */
     if ((node1->type == XML_ELEMENT_NODE) &&
 	(node2->type == XML_ELEMENT_NODE) &&
-	(0 > (ptrdiff_t) node1->content) &&
-	(0 > (ptrdiff_t) node2->content) &&
+	(0 > XML_NODE_SORT_VALUE(node1)) &&
+	(0 > XML_NODE_SORT_VALUE(node2)) &&
 	(node1->doc == node2->doc)) {
 
-	l1 = -((ptrdiff_t) node1->content);
-	l2 = -((ptrdiff_t) node2->content);
+	l1 = -XML_NODE_SORT_VALUE(node1);
+	l2 = -XML_NODE_SORT_VALUE(node2);
 	if (l1 < l2)
 	    return(1);
 	if (l1 > l2)
@@ -963,20 +1045,21 @@ xmlXPathCompExprAdd(xmlXPathParserContextPtr ctxt, int ch1, int ch2,
     xmlXPathCompExprPtr comp = ctxt->comp;
     if (comp->nbStep >= comp->maxStep) {
 	xmlXPathStepOp *real;
+        int newSize;
 
-        if (comp->maxStep >= XPATH_MAX_STEPS) {
+        newSize = xmlGrowCapacity(comp->maxStep, sizeof(real[0]),
+                                  10, XPATH_MAX_STEPS);
+        if (newSize < 0) {
 	    xmlXPathPErrMemory(ctxt);
 	    return(-1);
         }
-	comp->maxStep *= 2;
-	real = (xmlXPathStepOp *) xmlRealloc(comp->steps,
-		                      comp->maxStep * sizeof(xmlXPathStepOp));
+	real = xmlRealloc(comp->steps, newSize * sizeof(real[0]));
 	if (real == NULL) {
-	    comp->maxStep /= 2;
 	    xmlXPathPErrMemory(ctxt);
 	    return(-1);
 	}
 	comp->steps = real;
+	comp->maxStep = newSize;
     }
     comp->last = comp->nbStep;
     comp->steps[comp->nbStep].ch1 = ch1;
@@ -1384,6 +1467,10 @@ xmlXPathDebugDumpStepOp(FILE *output, xmlXPathCompExprPtr comp,
     }
     fprintf(output, "\n");
 finish:
+    /* OP_VALUE has invalid ch1. */
+    if (op->op == XPATH_OP_VALUE)
+        return;
+
     if (op->ch1 >= 0)
 	xmlXPathDebugDumpStepOp(output, comp, &comp->steps[op->ch1], depth + 1);
     if (op->ch2 >= 0)
@@ -1970,22 +2057,23 @@ valuePush(xmlXPathParserContextPtr ctxt, xmlXPathObjectPtr value)
     }
     if (ctxt->valueNr >= ctxt->valueMax) {
         xmlXPathObjectPtr *tmp;
+        int newSize;
 
-        if (ctxt->valueMax >= XPATH_MAX_STACK_DEPTH) {
+        newSize = xmlGrowCapacity(ctxt->valueMax, sizeof(tmp[0]),
+                                  10, XPATH_MAX_STACK_DEPTH);
+        if (newSize < 0) {
             xmlXPathPErrMemory(ctxt);
             xmlXPathFreeObject(value);
             return (-1);
         }
-        tmp = (xmlXPathObjectPtr *) xmlRealloc(ctxt->valueTab,
-                                             2 * ctxt->valueMax *
-                                             sizeof(ctxt->valueTab[0]));
+        tmp = xmlRealloc(ctxt->valueTab, newSize * sizeof(tmp[0]));
         if (tmp == NULL) {
             xmlXPathPErrMemory(ctxt);
             xmlXPathFreeObject(value);
             return (-1);
         }
-        ctxt->valueMax *= 2;
 	ctxt->valueTab = tmp;
+        ctxt->valueMax = newSize;
     }
     ctxt->valueTab[ctxt->valueNr] = value;
     ctxt->value = value;
@@ -2336,7 +2424,7 @@ xmlXPathFormatNumber(double number, char buffer[], int buffersize)
  */
 long
 xmlXPathOrderDocElems(xmlDocPtr doc) {
-    ptrdiff_t count = 0;
+    XML_INTPTR_T count = 0;
     xmlNodePtr cur;
 
     if (doc == NULL)
@@ -2344,7 +2432,8 @@ xmlXPathOrderDocElems(xmlDocPtr doc) {
     cur = doc->children;
     while (cur != NULL) {
 	if (cur->type == XML_ELEMENT_NODE) {
-	    cur->content = (void *) (-(++count));
+            count += 1;
+            cur->content = XML_INT_TO_PTR(-count);
 	    if (cur->children != NULL) {
 		cur = cur->children;
 		continue;
@@ -2436,13 +2525,13 @@ xmlXPathCmpNodes(xmlNodePtr node1, xmlNodePtr node2) {
      */
     if ((node1->type == XML_ELEMENT_NODE) &&
 	(node2->type == XML_ELEMENT_NODE) &&
-	(0 > (ptrdiff_t) node1->content) &&
-	(0 > (ptrdiff_t) node2->content) &&
+	(0 > XML_NODE_SORT_VALUE(node1)) &&
+	(0 > XML_NODE_SORT_VALUE(node2)) &&
 	(node1->doc == node2->doc)) {
-	ptrdiff_t l1, l2;
+	XML_INTPTR_T l1, l2;
 
-	l1 = -((ptrdiff_t) node1->content);
-	l2 = -((ptrdiff_t) node2->content);
+	l1 = -XML_NODE_SORT_VALUE(node1);
+	l2 = -XML_NODE_SORT_VALUE(node2);
 	if (l1 < l2)
 	    return(1);
 	if (l1 > l2)
@@ -2499,13 +2588,13 @@ xmlXPathCmpNodes(xmlNodePtr node1, xmlNodePtr node2) {
      */
     if ((node1->type == XML_ELEMENT_NODE) &&
 	(node2->type == XML_ELEMENT_NODE) &&
-	(0 > (ptrdiff_t) node1->content) &&
-	(0 > (ptrdiff_t) node2->content) &&
+	(0 > XML_NODE_SORT_VALUE(node1)) &&
+	(0 > XML_NODE_SORT_VALUE(node2)) &&
 	(node1->doc == node2->doc)) {
-	ptrdiff_t l1, l2;
+	XML_INTPTR_T l1, l2;
 
-	l1 = -((ptrdiff_t) node1->content);
-	l2 = -((ptrdiff_t) node2->content);
+	l1 = -XML_NODE_SORT_VALUE(node1);
+	l2 = -XML_NODE_SORT_VALUE(node2);
 	if (l1 < l2)
 	    return(1);
 	if (l1 > l2)
@@ -2714,6 +2803,24 @@ xmlXPathNodeSetContains (xmlNodeSetPtr cur, xmlNodePtr val) {
     return(0);
 }
 
+static int
+xmlXPathNodeSetGrow(xmlNodeSetPtr cur) {
+    xmlNodePtr *temp;
+    int newSize;
+
+    newSize = xmlGrowCapacity(cur->nodeMax, sizeof(temp[0]),
+                              XML_NODESET_DEFAULT, XPATH_MAX_NODESET_LENGTH);
+    if (newSize < 0)
+        return(-1);
+    temp = xmlRealloc(cur->nodeTab, newSize * sizeof(temp[0]));
+    if (temp == NULL)
+        return(-1);
+    cur->nodeMax = newSize;
+    cur->nodeTab = temp;
+
+    return(0);
+}
+
 /**
  * xmlXPathNodeSetAddNs:
  * @cur:  the initial node set
@@ -2749,25 +2856,9 @@ xmlXPathNodeSetAddNs(xmlNodeSetPtr cur, xmlNodePtr node, xmlNsPtr ns) {
     /*
      * grow the nodeTab if needed
      */
-    if (cur->nodeMax == 0) {
-        cur->nodeTab = (xmlNodePtr *) xmlMalloc(XML_NODESET_DEFAULT *
-					     sizeof(xmlNodePtr));
-	if (cur->nodeTab == NULL)
-	    return(-1);
-	memset(cur->nodeTab, 0 ,
-	       XML_NODESET_DEFAULT * sizeof(xmlNodePtr));
-        cur->nodeMax = XML_NODESET_DEFAULT;
-    } else if (cur->nodeNr == cur->nodeMax) {
-        xmlNodePtr *temp;
-
-        if (cur->nodeMax >= XPATH_MAX_NODESET_LENGTH)
+    if (cur->nodeNr >= cur->nodeMax) {
+        if (xmlXPathNodeSetGrow(cur) < 0)
             return(-1);
-	temp = (xmlNodePtr *) xmlRealloc(cur->nodeTab, cur->nodeMax * 2 *
-				      sizeof(xmlNodePtr));
-	if (temp == NULL)
-	    return(-1);
-        cur->nodeMax *= 2;
-	cur->nodeTab = temp;
     }
     nsNode = xmlXPathNodeSetDupNs(node, ns);
     if(nsNode == NULL)
@@ -2801,26 +2892,11 @@ xmlXPathNodeSetAdd(xmlNodeSetPtr cur, xmlNodePtr val) {
     /*
      * grow the nodeTab if needed
      */
-    if (cur->nodeMax == 0) {
-        cur->nodeTab = (xmlNodePtr *) xmlMalloc(XML_NODESET_DEFAULT *
-					     sizeof(xmlNodePtr));
-	if (cur->nodeTab == NULL)
-	    return(-1);
-	memset(cur->nodeTab, 0 ,
-	       XML_NODESET_DEFAULT * sizeof(xmlNodePtr));
-        cur->nodeMax = XML_NODESET_DEFAULT;
-    } else if (cur->nodeNr == cur->nodeMax) {
-        xmlNodePtr *temp;
-
-        if (cur->nodeMax >= XPATH_MAX_NODESET_LENGTH)
+    if (cur->nodeNr >= cur->nodeMax) {
+        if (xmlXPathNodeSetGrow(cur) < 0)
             return(-1);
-	temp = (xmlNodePtr *) xmlRealloc(cur->nodeTab, cur->nodeMax * 2 *
-				      sizeof(xmlNodePtr));
-	if (temp == NULL)
-	    return(-1);
-        cur->nodeMax *= 2;
-	cur->nodeTab = temp;
     }
+
     if (val->type == XML_NAMESPACE_DECL) {
 	xmlNsPtr ns = (xmlNsPtr) val;
         xmlNodePtr nsNode = xmlXPathNodeSetDupNs((xmlNodePtr) ns->next, ns);
@@ -2851,26 +2927,11 @@ xmlXPathNodeSetAddUnique(xmlNodeSetPtr cur, xmlNodePtr val) {
     /*
      * grow the nodeTab if needed
      */
-    if (cur->nodeMax == 0) {
-        cur->nodeTab = (xmlNodePtr *) xmlMalloc(XML_NODESET_DEFAULT *
-					     sizeof(xmlNodePtr));
-	if (cur->nodeTab == NULL)
-	    return(-1);
-	memset(cur->nodeTab, 0 ,
-	       XML_NODESET_DEFAULT * sizeof(xmlNodePtr));
-        cur->nodeMax = XML_NODESET_DEFAULT;
-    } else if (cur->nodeNr == cur->nodeMax) {
-        xmlNodePtr *temp;
-
-        if (cur->nodeMax >= XPATH_MAX_NODESET_LENGTH)
+    if (cur->nodeNr >= cur->nodeMax) {
+        if (xmlXPathNodeSetGrow(cur) < 0)
             return(-1);
-	temp = (xmlNodePtr *) xmlRealloc(cur->nodeTab, cur->nodeMax * 2 *
-				      sizeof(xmlNodePtr));
-	if (temp == NULL)
-	    return(-1);
-	cur->nodeTab = temp;
-        cur->nodeMax *= 2;
     }
+
     if (val->type == XML_NAMESPACE_DECL) {
 	xmlNsPtr ns = (xmlNsPtr) val;
         xmlNodePtr nsNode = xmlXPathNodeSetDupNs((xmlNodePtr) ns->next, ns);
@@ -2939,26 +3000,10 @@ xmlXPathNodeSetMerge(xmlNodeSetPtr val1, xmlNodeSetPtr val2) {
 	/*
 	 * grow the nodeTab if needed
 	 */
-	if (val1->nodeMax == 0) {
-	    val1->nodeTab = (xmlNodePtr *) xmlMalloc(XML_NODESET_DEFAULT *
-						    sizeof(xmlNodePtr));
-	    if (val1->nodeTab == NULL)
-		goto error;
-	    memset(val1->nodeTab, 0 ,
-		   XML_NODESET_DEFAULT * sizeof(xmlNodePtr));
-	    val1->nodeMax = XML_NODESET_DEFAULT;
-	} else if (val1->nodeNr == val1->nodeMax) {
-	    xmlNodePtr *temp;
-
-            if (val1->nodeMax >= XPATH_MAX_NODESET_LENGTH)
+        if (val1->nodeNr >= val1->nodeMax) {
+            if (xmlXPathNodeSetGrow(val1) < 0)
                 goto error;
-	    temp = (xmlNodePtr *) xmlRealloc(val1->nodeTab, val1->nodeMax * 2 *
-					     sizeof(xmlNodePtr));
-	    if (temp == NULL)
-		goto error;
-	    val1->nodeTab = temp;
-	    val1->nodeMax *= 2;
-	}
+        }
 	if (n2->type == XML_NAMESPACE_DECL) {
 	    xmlNsPtr ns = (xmlNsPtr) n2;
             xmlNodePtr nsNode = xmlXPathNodeSetDupNs((xmlNodePtr) ns->next, ns);
@@ -3025,26 +3070,10 @@ xmlXPathNodeSetMergeAndClear(xmlNodeSetPtr set1, xmlNodeSetPtr set2)
 	    /*
 	    * grow the nodeTab if needed
 	    */
-	    if (set1->nodeMax == 0) {
-		set1->nodeTab = (xmlNodePtr *) xmlMalloc(
-		    XML_NODESET_DEFAULT * sizeof(xmlNodePtr));
-		if (set1->nodeTab == NULL)
-		    goto error;
-		memset(set1->nodeTab, 0,
-		    XML_NODESET_DEFAULT * sizeof(xmlNodePtr));
-		set1->nodeMax = XML_NODESET_DEFAULT;
-	    } else if (set1->nodeNr >= set1->nodeMax) {
-		xmlNodePtr *temp;
-
-                if (set1->nodeMax >= XPATH_MAX_NODESET_LENGTH)
+            if (set1->nodeNr >= set1->nodeMax) {
+                if (xmlXPathNodeSetGrow(set1) < 0)
                     goto error;
-		temp = (xmlNodePtr *) xmlRealloc(
-		    set1->nodeTab, set1->nodeMax * 2 * sizeof(xmlNodePtr));
-		if (temp == NULL)
-		    goto error;
-		set1->nodeTab = temp;
-		set1->nodeMax *= 2;
-	    }
+            }
 	    set1->nodeTab[set1->nodeNr++] = n2;
 skip_node:
             set2->nodeTab[i] = NULL;
@@ -3080,26 +3109,10 @@ xmlXPathNodeSetMergeAndClearNoDupls(xmlNodeSetPtr set1, xmlNodeSetPtr set2)
 
 	for (i = 0;i < set2->nodeNr;i++) {
 	    n2 = set2->nodeTab[i];
-	    if (set1->nodeMax == 0) {
-		set1->nodeTab = (xmlNodePtr *) xmlMalloc(
-		    XML_NODESET_DEFAULT * sizeof(xmlNodePtr));
-		if (set1->nodeTab == NULL)
-		    goto error;
-		memset(set1->nodeTab, 0,
-		    XML_NODESET_DEFAULT * sizeof(xmlNodePtr));
-		set1->nodeMax = XML_NODESET_DEFAULT;
-	    } else if (set1->nodeNr >= set1->nodeMax) {
-		xmlNodePtr *temp;
-
-                if (set1->nodeMax >= XPATH_MAX_NODESET_LENGTH)
+            if (set1->nodeNr >= set1->nodeMax) {
+                if (xmlXPathNodeSetGrow(set1) < 0)
                     goto error;
-		temp = (xmlNodePtr *) xmlRealloc(
-		    set1->nodeTab, set1->nodeMax * 2 * sizeof(xmlNodePtr));
-		if (temp == NULL)
-		    goto error;
-		set1->nodeTab = temp;
-		set1->nodeMax *= 2;
-	    }
+            }
 	    set1->nodeTab[set1->nodeNr++] = n2;
             set2->nodeTab[i] = NULL;
 	}
@@ -3858,18 +3871,6 @@ xmlXPathRegisterFuncLookup (xmlXPathContextPtr ctxt,
  */
 xmlXPathFunction
 xmlXPathFunctionLookup(xmlXPathContextPtr ctxt, const xmlChar *name) {
-    if (ctxt == NULL)
-	return (NULL);
-
-    if (ctxt->funcLookupFunc != NULL) {
-	xmlXPathFunction ret;
-	xmlXPathFuncLookupFunc f;
-
-	f = ctxt->funcLookupFunc;
-	ret = f(ctxt->funcLookupData, name, NULL);
-	if (ret != NULL)
-	    return(ret);
-    }
     return(xmlXPathFunctionLookupNS(ctxt, name, NULL));
 }
 
@@ -3894,6 +3895,22 @@ xmlXPathFunctionLookupNS(xmlXPathContextPtr ctxt, const xmlChar *name,
     if (name == NULL)
 	return(NULL);
 
+    if (ns_uri == NULL) {
+        int bucketIndex = xmlXPathSFComputeHash(name) % SF_HASH_SIZE;
+
+        while (xmlXPathSFHash[bucketIndex] != UCHAR_MAX) {
+            int funcIndex = xmlXPathSFHash[bucketIndex];
+
+            if (strcmp(xmlXPathStandardFunctions[funcIndex].name,
+                       (char *) name) == 0)
+                return(xmlXPathStandardFunctions[funcIndex].func);
+
+            bucketIndex += 1;
+            if (bucketIndex >= SF_HASH_SIZE)
+                bucketIndex = 0;
+        }
+    }
+
     if (ctxt->funcLookupFunc != NULL) {
 	xmlXPathFuncLookupFunc f;
 
@@ -4924,8 +4941,8 @@ xmlXPathNewContext(xmlDocPtr doc) {
     ret->nsHash = NULL;
     ret->user = NULL;
 
-    ret->contextSize = -1;
-    ret->proximityPosition = -1;
+    ret->contextSize = 1;
+    ret->proximityPosition = 1;
 
 #ifdef XP_DEFAULT_CACHE_ON
     if (xmlXPathContextSetCache(ret, 1, -1, 0) == -1) {
@@ -4934,13 +4951,6 @@ xmlXPathNewContext(xmlDocPtr doc) {
     }
 #endif
 
-    xmlXPathRegisterAllFunctions(ret);
-
-    if (ret->lastError.code != XML_ERR_OK) {
-	xmlXPathFreeContext(ret);
-	return(NULL);
-    }
-
     return(ret);
 }
 
@@ -8657,18 +8667,22 @@ xmlXPathParseNameComplex(xmlXPathParserContextPtr ctxt, int qualified) {
 		   (IS_EXTENDER(c))) {
 		if (len + 10 > max) {
                     xmlChar *tmp;
-                    if (max > XML_MAX_NAME_LENGTH) {
+                    int newSize;
+
+                    newSize = xmlGrowCapacity(max, 1, 1, XML_MAX_NAME_LENGTH);
+                    if (newSize < 0) {
                         xmlFree(buffer);
-                        XP_ERRORNULL(XPATH_EXPR_ERROR);
+                        xmlXPathPErrMemory(ctxt);
+                        return(NULL);
                     }
-		    max *= 2;
-		    tmp = (xmlChar *) xmlRealloc(buffer, max);
+		    tmp = xmlRealloc(buffer, newSize);
 		    if (tmp == NULL) {
                         xmlFree(buffer);
                         xmlXPathPErrMemory(ctxt);
                         return(NULL);
 		    }
                     buffer = tmp;
+		    max = newSize;
 		}
 		COPY_BUF(buffer,len,c);
 		NEXTL(l);
@@ -10081,8 +10095,9 @@ xmlXPathCompLocationPath(xmlXPathParserContextPtr ctxt) {
 	    } else if (CUR == '/') {
 		NEXT;
 		SKIP_BLANKS;
-		if ((CUR != 0 ) &&
-		    ((IS_ASCII_LETTER(CUR)) || (CUR == '_') || (CUR == '.') ||
+		if ((CUR != 0) &&
+		    ((IS_ASCII_LETTER(CUR)) || (CUR >= 0x80) ||
+                     (CUR == '_') || (CUR == '.') ||
 		     (CUR == '@') || (CUR == '*')))
 		    xmlXPathCompRelativeLocationPath(ctxt);
 	    }
@@ -12684,186 +12699,17 @@ xmlXPathEvalExpression(const xmlChar *str, xmlXPathContextPtr ctxt) {
     return(xmlXPathEval(str, ctxt));
 }
 
-/************************************************************************
- *									*
- *	Extra functions not pertaining to the XPath spec		*
- *									*
- ************************************************************************/
-/**
- * xmlXPathEscapeUriFunction:
- * @ctxt:  the XPath Parser context
- * @nargs:  the number of arguments
- *
- * Implement the escape-uri() XPath function
- *    string escape-uri(string $str, bool $escape-reserved)
- *
- * This function applies the URI escaping rules defined in section 2 of [RFC
- * 2396] to the string supplied as $uri-part, which typically represents all
- * or part of a URI. The effect of the function is to replace any special
- * character in the string by an escape sequence of the form %xx%yy...,
- * where xxyy... is the hexadecimal representation of the octets used to
- * represent the character in UTF-8.
- *
- * The set of characters that are escaped depends on the setting of the
- * boolean argument $escape-reserved.
- *
- * If $escape-reserved is true, all characters are escaped other than lower
- * case letters a-z, upper case letters A-Z, digits 0-9, and the characters
- * referred to in [RFC 2396] as "marks": specifically, "-" | "_" | "." | "!"
- * | "~" | "*" | "'" | "(" | ")". The "%" character itself is escaped only
- * if it is not followed by two hexadecimal digits (that is, 0-9, a-f, and
- * A-F).
- *
- * If $escape-reserved is false, the behavior differs in that characters
- * referred to in [RFC 2396] as reserved characters are not escaped. These
- * characters are ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" | "$" | ",".
- *
- * [RFC 2396] does not define whether escaped URIs should use lower case or
- * upper case for hexadecimal digits. To ensure that escaped URIs can be
- * compared using string comparison functions, this function must always use
- * the upper-case letters A-F.
- *
- * Generally, $escape-reserved should be set to true when escaping a string
- * that is to form a single part of a URI, and to false when escaping an
- * entire URI or URI reference.
- *
- * In the case of non-ascii characters, the string is encoded according to
- * utf-8 and then converted according to RFC 2396.
- *
- * Examples
- *  xf:escape-uri ("gopher://spinaltap.micro.umn.edu/00/Weather/California/Los%20Angeles#ocean"), true())
- *  returns "gopher%3A%2F%2Fspinaltap.micro.umn.edu%2F00%2FWeather%2FCalifornia%2FLos%20Angeles%23ocean"
- *  xf:escape-uri ("gopher://spinaltap.micro.umn.edu/00/Weather/California/Los%20Angeles#ocean"), false())
- *  returns "gopher://spinaltap.micro.umn.edu/00/Weather/California/Los%20Angeles%23ocean"
- *
- */
-static void
-xmlXPathEscapeUriFunction(xmlXPathParserContextPtr ctxt, int nargs) {
-    xmlXPathObjectPtr str;
-    int escape_reserved;
-    xmlBufPtr target;
-    xmlChar *cptr;
-    xmlChar escape[4];
-
-    CHECK_ARITY(2);
-
-    escape_reserved = xmlXPathPopBoolean(ctxt);
-
-    CAST_TO_STRING;
-    str = valuePop(ctxt);
-
-    target = xmlBufCreate(50);
-
-    escape[0] = '%';
-    escape[3] = 0;
-
-    if (target) {
-	for (cptr = str->stringval; *cptr; cptr++) {
-	    if ((*cptr >= 'A' && *cptr <= 'Z') ||
-		(*cptr >= 'a' && *cptr <= 'z') ||
-		(*cptr >= '0' && *cptr <= '9') ||
-		*cptr == '-' || *cptr == '_' || *cptr == '.' ||
-		*cptr == '!' || *cptr == '~' || *cptr == '*' ||
-		*cptr == '\''|| *cptr == '(' || *cptr == ')' ||
-		(*cptr == '%' &&
-		 ((cptr[1] >= 'A' && cptr[1] <= 'F') ||
-		  (cptr[1] >= 'a' && cptr[1] <= 'f') ||
-		  (cptr[1] >= '0' && cptr[1] <= '9')) &&
-		 ((cptr[2] >= 'A' && cptr[2] <= 'F') ||
-		  (cptr[2] >= 'a' && cptr[2] <= 'f') ||
-		  (cptr[2] >= '0' && cptr[2] <= '9'))) ||
-		(!escape_reserved &&
-		 (*cptr == ';' || *cptr == '/' || *cptr == '?' ||
-		  *cptr == ':' || *cptr == '@' || *cptr == '&' ||
-		  *cptr == '=' || *cptr == '+' || *cptr == '$' ||
-		  *cptr == ','))) {
-		xmlBufAdd(target, cptr, 1);
-	    } else {
-		if ((*cptr >> 4) < 10)
-		    escape[1] = '0' + (*cptr >> 4);
-		else
-		    escape[1] = 'A' - 10 + (*cptr >> 4);
-		if ((*cptr & 0xF) < 10)
-		    escape[2] = '0' + (*cptr & 0xF);
-		else
-		    escape[2] = 'A' - 10 + (*cptr & 0xF);
-
-		xmlBufAdd(target, &escape[0], 3);
-	    }
-	}
-    }
-    valuePush(ctxt, xmlXPathCacheNewString(ctxt, xmlBufContent(target)));
-    xmlBufFree(target);
-    xmlXPathReleaseObject(ctxt->context, str);
-}
-
 /**
  * xmlXPathRegisterAllFunctions:
  * @ctxt:  the XPath context
  *
+ * DEPRECATED: No-op since 2.14.0.
+ *
  * Registers all default XPath functions in this context
  */
 void
-xmlXPathRegisterAllFunctions(xmlXPathContextPtr ctxt)
+xmlXPathRegisterAllFunctions(xmlXPathContextPtr ctxt ATTRIBUTE_UNUSED)
 {
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"boolean",
-                         xmlXPathBooleanFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"ceiling",
-                         xmlXPathCeilingFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"count",
-                         xmlXPathCountFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"concat",
-                         xmlXPathConcatFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"contains",
-                         xmlXPathContainsFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"id",
-                         xmlXPathIdFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"false",
-                         xmlXPathFalseFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"floor",
-                         xmlXPathFloorFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"last",
-                         xmlXPathLastFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"lang",
-                         xmlXPathLangFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"local-name",
-                         xmlXPathLocalNameFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"not",
-                         xmlXPathNotFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"name",
-                         xmlXPathNameFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"namespace-uri",
-                         xmlXPathNamespaceURIFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"normalize-space",
-                         xmlXPathNormalizeFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"number",
-                         xmlXPathNumberFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"position",
-                         xmlXPathPositionFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"round",
-                         xmlXPathRoundFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"string",
-                         xmlXPathStringFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"string-length",
-                         xmlXPathStringLengthFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"starts-with",
-                         xmlXPathStartsWithFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"substring",
-                         xmlXPathSubstringFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"substring-before",
-                         xmlXPathSubstringBeforeFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"substring-after",
-                         xmlXPathSubstringAfterFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"sum",
-                         xmlXPathSumFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"true",
-                         xmlXPathTrueFunction);
-    xmlXPathRegisterFunc(ctxt, (const xmlChar *)"translate",
-                         xmlXPathTranslateFunction);
-
-    xmlXPathRegisterFuncNS(ctxt, (const xmlChar *)"escape-uri",
-	 (const xmlChar *)"http://www.w3.org/2002/08/xquery-functions",
-                         xmlXPathEscapeUriFunction);
 }
 
 #endif /* LIBXML_XPATH_ENABLED */
diff --git a/xpointer.c b/xpointer.c
index 6c995b77..01205d50 100644
--- a/xpointer.c
+++ b/xpointer.c
@@ -45,6 +45,7 @@
 #define XPTR_XMLNS_SCHEME
 
 #include "private/error.h"
+#include "private/parser.h"
 #include "private/xpath.h"
 
 /************************************************************************
```

