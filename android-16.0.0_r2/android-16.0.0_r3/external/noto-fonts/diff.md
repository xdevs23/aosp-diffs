```diff
diff --git a/Android.bp b/Android.bp
index 37ab91e..55cd315 100644
--- a/Android.bp
+++ b/Android.bp
@@ -58,9 +58,11 @@ filegroup {
         "notosanscjk/NotoSansCJK-Regular.ttc",
         "notonaskharabicui/NotoNaskhArabicUI-Regular.ttf",
         "notosansarmenian/NotoSansArmenian-VF.ttf",
+        "notosansarmenian/font/2.005/NotoSansArmenian-Regular.ttf",
         "notosansbengaliui/NotoSansBengaliUI-VF.ttf",
         "notosansdevanagariui/NotoSansDevanagariUI-VF.ttf",
         "notosansethiopic/NotoSansEthiopic-VF.ttf",
+        "notosansethiopic/font/2.000/NotoSansEthiopic-Regular.ttf",
         "notosansgeorgian/NotoSansGeorgian-VF.ttf",
         "notosansgujaratiui/NotoSansGujaratiUI-Regular.ttf",
         "notosansgurmukhiui/NotoSansGurmukhiUI-VF.ttf",
@@ -69,6 +71,7 @@ filegroup {
         "notosanskhmerui/NotoSansKhmerUI-Regular.ttf",
         "notosanslaoui/NotoSansLaoUI-Regular.ttf",
         "notosansmalayalamui/NotoSansMalayalamUI-VF.ttf",
+        "notosansmalayalamui/font/2.103/NotoSansMalayalamUI-Regular.ttf",
         "notosansmyanmarui/NotoSansMyanmarUI-Regular.otf",
         "notosansoriya/NotoSansOriya-Regular.ttf",
         "notosanssinhalaui/NotoSansSinhalaUI-VF.ttf",
diff --git a/notonaskharabic/Android.bp b/notonaskharabic/Android.bp
index e795de1..78a872b 100644
--- a/notonaskharabic/Android.bp
+++ b/notonaskharabic/Android.bp
@@ -47,17 +47,20 @@ license {
 
 prebuilt_font {
     name: "NotoNaskhArabic-Bold.ttf",
-    src: "NotoNaskhArabic-Bold.ttf",
+    src: "font/1.070/NotoNaskhArabic-Bold.ttf",
 }
 
-prebuilt_font {
+prebuilt_versioned_font {
     name: "NotoNaskhArabic-Regular.ttf",
-    src: "NotoNaskhArabic-Regular.ttf",
+    fontFile: "NotoNaskhArabic.ttf",
+    versionFlag: "RELEASE_PACKAGE_NOTO_NASKH_ARABIC_VERSION",
+    defaultVersion: "1.070",
 }
 
-filegroup {
+versioned_font_config {
     name: "NotoNaskhArabic",
-    srcs: ["font_config.json"],
+    defaultVersion: "1.070",
+    versionFlag: "RELEASE_PACKAGE_NOTO_NASKH_ARABIC_VERSION",
     required: [
         "NotoNaskhArabic-Bold.ttf",
         "NotoNaskhArabic-Regular.ttf",
diff --git a/notonaskharabic/NotoNaskhArabic-Bold.ttf b/notonaskharabic/font/1.070/NotoNaskhArabic-Bold.ttf
similarity index 100%
rename from notonaskharabic/NotoNaskhArabic-Bold.ttf
rename to notonaskharabic/font/1.070/NotoNaskhArabic-Bold.ttf
diff --git a/notonaskharabic/NotoNaskhArabic-Regular.ttf b/notonaskharabic/font/1.070/NotoNaskhArabic.ttf
similarity index 100%
rename from notonaskharabic/NotoNaskhArabic-Regular.ttf
rename to notonaskharabic/font/1.070/NotoNaskhArabic.ttf
diff --git a/notonaskharabic/font_config.json b/notonaskharabic/font/1.070/font_config.json
similarity index 100%
rename from notonaskharabic/font_config.json
rename to notonaskharabic/font/1.070/font_config.json
diff --git a/notonaskharabic/font/2.019/NotoNaskhArabic.ttf b/notonaskharabic/font/2.019/NotoNaskhArabic.ttf
new file mode 100644
index 0000000..35ce45c
Binary files /dev/null and b/notonaskharabic/font/2.019/NotoNaskhArabic.ttf differ
diff --git a/notonaskharabic/font/2.019/font_config.json b/notonaskharabic/font/2.019/font_config.json
new file mode 100644
index 0000000..9dc8a79
--- /dev/null
+++ b/notonaskharabic/font/2.019/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Arab",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoNaskhArabic-Regular.ttf",
+                "supportedAxes": "wght",
+                "style": "normal"
+            }
+        ]
+    }
+]
diff --git a/notosansarmenian/Android.bp b/notosansarmenian/Android.bp
index 7d581c9..6beb92b 100644
--- a/notosansarmenian/Android.bp
+++ b/notosansarmenian/Android.bp
@@ -45,9 +45,11 @@ license {
     ],
 }
 
-prebuilt_font {
+prebuilt_versioned_font {
     name: "NotoSansArmenian-VF.ttf",
-    src: "NotoSansArmenian-VF.ttf",
+    fontFile: "NotoSansArmenian-Regular.ttf",
+    versionFlag: "RELEASE_PACKAGE_NOTO_SANS_ARMENIAN_VERSION",
+    defaultVersion: "2.005",
 }
 
 filegroup {
diff --git a/notosansarmenian/NotoSansArmenian-VF.ttf b/notosansarmenian/NotoSansArmenian-VF.ttf
deleted file mode 100644
index 769660a..0000000
Binary files a/notosansarmenian/NotoSansArmenian-VF.ttf and /dev/null differ
diff --git a/notosansarmenian/NotoSansArmenian-VF.ttf b/notosansarmenian/NotoSansArmenian-VF.ttf
new file mode 120000
index 0000000..9639d55
--- /dev/null
+++ b/notosansarmenian/NotoSansArmenian-VF.ttf
@@ -0,0 +1 @@
+font/2.005/NotoSansArmenian-Regular.ttf
\ No newline at end of file
diff --git a/notosansarmenian/font/2.005/NotoSansArmenian-Regular.ttf b/notosansarmenian/font/2.005/NotoSansArmenian-Regular.ttf
new file mode 100644
index 0000000..769660a
Binary files /dev/null and b/notosansarmenian/font/2.005/NotoSansArmenian-Regular.ttf differ
diff --git a/notosansarmenian/font/2.008/NotoSansArmenian-Regular.ttf b/notosansarmenian/font/2.008/NotoSansArmenian-Regular.ttf
new file mode 100644
index 0000000..e1038d1
Binary files /dev/null and b/notosansarmenian/font/2.008/NotoSansArmenian-Regular.ttf differ
diff --git a/notosansdevanagari/Android.bp b/notosansdevanagari/Android.bp
index f73dfd5..c2239a9 100644
--- a/notosansdevanagari/Android.bp
+++ b/notosansdevanagari/Android.bp
@@ -45,9 +45,11 @@ license {
     ],
 }
 
-prebuilt_font {
+prebuilt_versioned_font {
     name: "NotoSansDevanagari-VF.ttf",
-    src: "NotoSansDevanagari-VF.ttf",
+    fontFile: "NotoSansDevanagari-Regular.ttf",
+    versionFlag: "RELEASE_PACKAGE_NOTO_SANS_DEVANAGARI_VERSION",
+    defaultVersion: "2.000",
 }
 
 filegroup {
diff --git a/notosansdevanagari/NotoSansDevanagari-VF.ttf b/notosansdevanagari/font/2.000/NotoSansDevanagari-Regular.ttf
similarity index 100%
rename from notosansdevanagari/NotoSansDevanagari-VF.ttf
rename to notosansdevanagari/font/2.000/NotoSansDevanagari-Regular.ttf
diff --git a/notosansdevanagari/font/2.006/NotoSansDevanagari-Regular.ttf b/notosansdevanagari/font/2.006/NotoSansDevanagari-Regular.ttf
new file mode 100644
index 0000000..969034c
Binary files /dev/null and b/notosansdevanagari/font/2.006/NotoSansDevanagari-Regular.ttf differ
diff --git a/notosansethiopic/Android.bp b/notosansethiopic/Android.bp
index 441a0d7..9ecd050 100644
--- a/notosansethiopic/Android.bp
+++ b/notosansethiopic/Android.bp
@@ -45,9 +45,11 @@ license {
     ],
 }
 
-prebuilt_font {
+prebuilt_versioned_font {
     name: "NotoSansEthiopic-VF.ttf",
-    src: "NotoSansEthiopic-VF.ttf",
+    fontFile: "NotoSansEthiopic-Regular.ttf",
+    versionFlag: "RELEASE_PACKAGE_NOTO_SANS_ETHIOPIC_VERSION",
+    defaultVersion: "2.000",
 }
 
 filegroup {
diff --git a/notosansethiopic/NotoSansEthiopic-VF.ttf b/notosansethiopic/NotoSansEthiopic-VF.ttf
deleted file mode 100644
index e2f46a9..0000000
Binary files a/notosansethiopic/NotoSansEthiopic-VF.ttf and /dev/null differ
diff --git a/notosansethiopic/NotoSansEthiopic-VF.ttf b/notosansethiopic/NotoSansEthiopic-VF.ttf
new file mode 120000
index 0000000..15deec8
--- /dev/null
+++ b/notosansethiopic/NotoSansEthiopic-VF.ttf
@@ -0,0 +1 @@
+font/2.000/NotoSansEthiopic-Regular.ttf
\ No newline at end of file
diff --git a/notosansethiopic/font/2.000/NotoSansEthiopic-Regular.ttf b/notosansethiopic/font/2.000/NotoSansEthiopic-Regular.ttf
new file mode 100644
index 0000000..e2f46a9
Binary files /dev/null and b/notosansethiopic/font/2.000/NotoSansEthiopic-Regular.ttf differ
diff --git a/notosansethiopic/font/2.102/NotoSansEthiopic-Regular.ttf b/notosansethiopic/font/2.102/NotoSansEthiopic-Regular.ttf
new file mode 100644
index 0000000..162865e
Binary files /dev/null and b/notosansethiopic/font/2.102/NotoSansEthiopic-Regular.ttf differ
diff --git a/notosansgujarati/Android.bp b/notosansgujarati/Android.bp
index 632d561..465828d 100644
--- a/notosansgujarati/Android.bp
+++ b/notosansgujarati/Android.bp
@@ -47,17 +47,20 @@ license {
 
 prebuilt_font {
     name: "NotoSansGujarati-Bold.ttf",
-    src: "NotoSansGujarati-Bold.ttf",
+    src: "font/1.030/NotoSansGujarati-Bold.ttf",
 }
 
-prebuilt_font {
+prebuilt_versioned_font {
     name: "NotoSansGujarati-Regular.ttf",
-    src: "NotoSansGujarati-Regular.ttf",
+    fontFile: "NotoSansGujarati.ttf",
+    versionFlag: "RELEASE_PACKAGE_NOTO_SANS_GUJARATI_VERSION",
+    defaultVersion: "1.030",
 }
 
-filegroup {
+versioned_font_config {
     name: "NotoSansGujarati",
-    srcs: ["font_config.json"],
+    defaultVersion: "1.030",
+    versionFlag: "RELEASE_PACKAGE_NOTO_SANS_GUJARATI_VERSION",
     required: [
         "NotoSansGujarati-Regular.ttf",
         "NotoSansGujarati-Bold.ttf",
diff --git a/notosansgujarati/NotoSansGujarati-Bold.ttf b/notosansgujarati/font/1.030/NotoSansGujarati-Bold.ttf
similarity index 100%
rename from notosansgujarati/NotoSansGujarati-Bold.ttf
rename to notosansgujarati/font/1.030/NotoSansGujarati-Bold.ttf
diff --git a/notosansgujarati/NotoSansGujarati-Regular.ttf b/notosansgujarati/font/1.030/NotoSansGujarati.ttf
similarity index 100%
rename from notosansgujarati/NotoSansGujarati-Regular.ttf
rename to notosansgujarati/font/1.030/NotoSansGujarati.ttf
diff --git a/notosansgujarati/font_config.json b/notosansgujarati/font/1.030/font_config.json
similarity index 100%
rename from notosansgujarati/font_config.json
rename to notosansgujarati/font/1.030/font_config.json
diff --git a/notosansgujarati/font/2.106/NotoSansGujarati.ttf b/notosansgujarati/font/2.106/NotoSansGujarati.ttf
new file mode 100644
index 0000000..e0717ad
Binary files /dev/null and b/notosansgujarati/font/2.106/NotoSansGujarati.ttf differ
diff --git a/notosansgujarati/font/2.106/font_config.json b/notosansgujarati/font/2.106/font_config.json
new file mode 100644
index 0000000..6c8ac7d
--- /dev/null
+++ b/notosansgujarati/font/2.106/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Gujr",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansGujarati-Regular.ttf",
+                "style": "normal",
+                "supportedAxes": "wght"
+            }
+        ],
+        "id": "NotoSansGujarati_und-Gujr"
+    }
+]
diff --git a/notosansgurmukhi/Android.bp b/notosansgurmukhi/Android.bp
index 8cb2282..c36f166 100644
--- a/notosansgurmukhi/Android.bp
+++ b/notosansgurmukhi/Android.bp
@@ -45,9 +45,11 @@ license {
     ],
 }
 
-prebuilt_font {
+prebuilt_versioned_font {
     name: "NotoSansGurmukhi-VF.ttf",
-    src: "NotoSansGurmukhi-VF.ttf",
+    fontFile: "NotoSansGurmukhi-Regular.ttf",
+    versionFlag: "RELEASE_PACKAGE_NOTO_SANS_GURMUKHI_VERSION",
+    defaultVersion: "2.001",
 }
 
 filegroup {
diff --git a/notosansgurmukhi/NotoSansGurmukhi-VF.ttf b/notosansgurmukhi/font/2.001/NotoSansGurmukhi-Regular.ttf
similarity index 100%
rename from notosansgurmukhi/NotoSansGurmukhi-VF.ttf
rename to notosansgurmukhi/font/2.001/NotoSansGurmukhi-Regular.ttf
diff --git a/notosansgurmukhi/font/2.004/NotoSansGurmukhi-Regular.ttf b/notosansgurmukhi/font/2.004/NotoSansGurmukhi-Regular.ttf
new file mode 100644
index 0000000..be235e8
Binary files /dev/null and b/notosansgurmukhi/font/2.004/NotoSansGurmukhi-Regular.ttf differ
diff --git a/notosanskannada/Android.bp b/notosanskannada/Android.bp
index bd959f4..33741b6 100644
--- a/notosanskannada/Android.bp
+++ b/notosanskannada/Android.bp
@@ -45,9 +45,11 @@ license {
     ],
 }
 
-prebuilt_font {
+prebuilt_versioned_font {
     name: "NotoSansKannada-VF.ttf",
-    src: "NotoSansKannada-VF.ttf",
+    fontFile: "NotoSansKannada-Regular.ttf",
+    versionFlag: "RELEASE_PACKAGE_NOTO_SANS_KANNADA_VERSION",
+    defaultVersion: "2.001",
 }
 
 filegroup {
diff --git a/notosanskannada/NotoSansKannada-VF.ttf b/notosanskannada/font/2.001/NotoSansKannada-Regular.ttf
similarity index 100%
rename from notosanskannada/NotoSansKannada-VF.ttf
rename to notosanskannada/font/2.001/NotoSansKannada-Regular.ttf
diff --git a/notosanskannada/font/2.006/NotoSansKannada-Regular.ttf b/notosanskannada/font/2.006/NotoSansKannada-Regular.ttf
new file mode 100644
index 0000000..dbed3db
Binary files /dev/null and b/notosanskannada/font/2.006/NotoSansKannada-Regular.ttf differ
diff --git a/notosanslao/Android.bp b/notosanslao/Android.bp
index 06b1e80..f8f6745 100644
--- a/notosanslao/Android.bp
+++ b/notosanslao/Android.bp
@@ -45,19 +45,21 @@ license {
     ],
 }
 
-prebuilt_font {
-    name: "NotoSansLao-Bold.ttf",
-    src: "NotoSansLao-Bold.ttf",
+prebuilt_versioned_font {
+    name: "NotoSansLao-Regular.ttf",
+    versionFlag: "RELEASE_PACKAGE_NOTO_SANS_LAO_VERSION",
+    defaultVersion: "2.001",
 }
 
 prebuilt_font {
-    name: "NotoSansLao-Regular.ttf",
-    src: "NotoSansLao-Regular.ttf",
+    name: "NotoSansLao-Bold.ttf",
+    src: "font/2.001/NotoSansLao-Bold.ttf",
 }
 
-filegroup {
+versioned_font_config {
     name: "NotoSansLao",
-    srcs: ["font_config.json"],
+    versionFlag: "RELEASE_PACKAGE_NOTO_SANS_LAO_VERSION",
+    defaultVersion: "2.001",
     required: [
         "NotoSansLao-Regular.ttf",
         "NotoSansLao-Bold.ttf",
diff --git a/notosanslao/NotoSansLao-Bold.ttf b/notosanslao/font/2.001/NotoSansLao-Bold.ttf
similarity index 100%
rename from notosanslao/NotoSansLao-Bold.ttf
rename to notosanslao/font/2.001/NotoSansLao-Bold.ttf
diff --git a/notosanslao/NotoSansLao-Regular.ttf b/notosanslao/font/2.001/NotoSansLao-Regular.ttf
similarity index 100%
rename from notosanslao/NotoSansLao-Regular.ttf
rename to notosanslao/font/2.001/NotoSansLao-Regular.ttf
diff --git a/notosanslao/font_config.json b/notosanslao/font/2.001/font_config.json
similarity index 100%
rename from notosanslao/font_config.json
rename to notosanslao/font/2.001/font_config.json
diff --git a/notosanslao/font/2.003/NotoSansLao-Regular.ttf b/notosanslao/font/2.003/NotoSansLao-Regular.ttf
new file mode 100644
index 0000000..24f00b7
Binary files /dev/null and b/notosanslao/font/2.003/NotoSansLao-Regular.ttf differ
diff --git a/notosanslao/font/2.003/font_config.json b/notosanslao/font/2.003/font_config.json
new file mode 100644
index 0000000..3e7457d
--- /dev/null
+++ b/notosanslao/font/2.003/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Laoo",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansLao-Regular.ttf",
+                "supportedAxes": "wght",
+                "style": "normal"
+            }
+        ],
+        "id": "NotoSansLao_und-Laoo"
+    }
+]
diff --git a/notosansmalayalam/Android.bp b/notosansmalayalam/Android.bp
index 27235e4..e49d00c 100644
--- a/notosansmalayalam/Android.bp
+++ b/notosansmalayalam/Android.bp
@@ -45,9 +45,11 @@ license {
     ],
 }
 
-prebuilt_font {
+prebuilt_versioned_font {
     name: "NotoSansMalayalam-VF.ttf",
-    src: "NotoSansMalayalam-VF.ttf",
+    fontFile: "NotoSansMalayalam-Regular.ttf",
+    versionFlag: "RELEASE_PACKAGE_NOTO_SANS_MALAYALAM_VERSION",
+    defaultVersion: "2.001",
 }
 
 filegroup {
diff --git a/notosansmalayalam/NotoSansMalayalam-VF.ttf b/notosansmalayalam/font/2.001/NotoSansMalayalam-Regular.ttf
similarity index 100%
rename from notosansmalayalam/NotoSansMalayalam-VF.ttf
rename to notosansmalayalam/font/2.001/NotoSansMalayalam-Regular.ttf
diff --git a/notosansmalayalam/font/2.104/NotoSansMalayalam-Regular.ttf b/notosansmalayalam/font/2.104/NotoSansMalayalam-Regular.ttf
new file mode 100644
index 0000000..88281d7
Binary files /dev/null and b/notosansmalayalam/font/2.104/NotoSansMalayalam-Regular.ttf differ
diff --git a/notosansmalayalamui/Android.bp b/notosansmalayalamui/Android.bp
index c0e7876..0c088d4 100644
--- a/notosansmalayalamui/Android.bp
+++ b/notosansmalayalamui/Android.bp
@@ -45,9 +45,11 @@ license {
     ],
 }
 
-prebuilt_font {
+prebuilt_versioned_font {
     name: "NotoSansMalayalamUI-VF.ttf",
-    src: "NotoSansMalayalamUI-VF.ttf",
+    fontFile: "NotoSansMalayalamUI-Regular.ttf",
+    versionFlag: "RELEASE_PACKAGE_NOTO_SANS_MALAYALAM_UI_VERSION",
+    defaultVersion: "2.103",
 }
 
 filegroup {
diff --git a/notosansmalayalamui/NotoSansMalayalamUI-VF.ttf b/notosansmalayalamui/NotoSansMalayalamUI-VF.ttf
deleted file mode 100644
index cf38b96..0000000
Binary files a/notosansmalayalamui/NotoSansMalayalamUI-VF.ttf and /dev/null differ
diff --git a/notosansmalayalamui/NotoSansMalayalamUI-VF.ttf b/notosansmalayalamui/NotoSansMalayalamUI-VF.ttf
new file mode 120000
index 0000000..273df68
--- /dev/null
+++ b/notosansmalayalamui/NotoSansMalayalamUI-VF.ttf
@@ -0,0 +1 @@
+font/2.103/NotoSansMalayalamUI-Regular.ttf
\ No newline at end of file
diff --git a/notosansmalayalamui/font/2.103/NotoSansMalayalamUI-Regular.ttf b/notosansmalayalamui/font/2.103/NotoSansMalayalamUI-Regular.ttf
new file mode 100644
index 0000000..cf38b96
Binary files /dev/null and b/notosansmalayalamui/font/2.103/NotoSansMalayalamUI-Regular.ttf differ
diff --git a/notosansmalayalamui/font/2.104/NotoSansMalayalamUI-Regular.ttf b/notosansmalayalamui/font/2.104/NotoSansMalayalamUI-Regular.ttf
new file mode 100644
index 0000000..aea092e
Binary files /dev/null and b/notosansmalayalamui/font/2.104/NotoSansMalayalamUI-Regular.ttf differ
diff --git a/notosansmyanmar/Android.bp b/notosansmyanmar/Android.bp
index baeb090..de90427 100644
--- a/notosansmyanmar/Android.bp
+++ b/notosansmyanmar/Android.bp
@@ -47,25 +47,27 @@ license {
 
 prebuilt_font {
     name: "NotoSansMyanmar-Medium.otf",
-    src: "NotoSansMyanmar-Medium.otf",
+    src: "font/2.001/NotoSansMyanmar-Medium.otf",
 }
 
-prebuilt_font {
+prebuilt_versioned_font {
     name: "NotoSansMyanmar-Regular.otf",
-    src: "NotoSansMyanmar-Regular.otf",
+    versionFlag: "RELEASE_PACKAGE_NOTO_SANS_MYANMAR_VERSION",
+    defaultVersion: "2.001",
 }
 
 prebuilt_font {
     name: "NotoSansMyanmar-Bold.otf",
-    src: "NotoSansMyanmar-Bold.otf",
+    src: "font/2.001/NotoSansMyanmar-Bold.otf",
 }
 
-filegroup {
+versioned_font_config {
     name: "NotoSansMyanmar",
-    srcs: ["font_config.json"],
     required: [
         "NotoSansMyanmar-Regular.otf",
         "NotoSansMyanmar-Medium.otf",
         "NotoSansMyanmar-Bold.otf",
     ],
+    versionFlag: "RELEASE_PACKAGE_NOTO_SANS_MYANMAR_VERSION",
+    defaultVersion: "2.001",
 }
diff --git a/notosansmyanmar/NotoSansMyanmar-Bold.otf b/notosansmyanmar/font/2.001/NotoSansMyanmar-Bold.otf
similarity index 100%
rename from notosansmyanmar/NotoSansMyanmar-Bold.otf
rename to notosansmyanmar/font/2.001/NotoSansMyanmar-Bold.otf
diff --git a/notosansmyanmar/NotoSansMyanmar-Medium.otf b/notosansmyanmar/font/2.001/NotoSansMyanmar-Medium.otf
similarity index 100%
rename from notosansmyanmar/NotoSansMyanmar-Medium.otf
rename to notosansmyanmar/font/2.001/NotoSansMyanmar-Medium.otf
diff --git a/notosansmyanmar/NotoSansMyanmar-Regular.otf b/notosansmyanmar/font/2.001/NotoSansMyanmar-Regular.otf
similarity index 100%
rename from notosansmyanmar/NotoSansMyanmar-Regular.otf
rename to notosansmyanmar/font/2.001/NotoSansMyanmar-Regular.otf
diff --git a/notosansmyanmar/font_config.json b/notosansmyanmar/font/2.001/font_config.json
similarity index 100%
rename from notosansmyanmar/font_config.json
rename to notosansmyanmar/font/2.001/font_config.json
diff --git a/notosansmyanmar/font/2.107/NotoSansMyanmar-Regular.otf b/notosansmyanmar/font/2.107/NotoSansMyanmar-Regular.otf
new file mode 100644
index 0000000..75a259f
Binary files /dev/null and b/notosansmyanmar/font/2.107/NotoSansMyanmar-Regular.otf differ
diff --git a/notosansmyanmar/font/2.107/font_config.json b/notosansmyanmar/font/2.107/font_config.json
new file mode 100644
index 0000000..93084f4
--- /dev/null
+++ b/notosansmyanmar/font/2.107/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Mymr",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansMyanmar-Regular.otf",
+                "style": "normal",
+                "supportedAxes": "wght"
+            }
+        ],
+        "id": "NotoSansMyanmar_und-Mymr"
+    }
+]
```

