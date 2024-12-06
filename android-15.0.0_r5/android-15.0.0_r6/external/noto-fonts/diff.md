```diff
diff --git a/Android.bp b/Android.bp
index b2ce5ba..b7f2478 100644
--- a/Android.bp
+++ b/Android.bp
@@ -55,25 +55,192 @@ filegroup {
     name: "recovery_noto-fonts_dep",
     export_to_make_var: "recovery_noto-fonts_dep",
     srcs: [
-      "notosanscjk/NotoSansCJK-Regular.ttc",
-      "notonaskharabicui/NotoNaskhArabicUI-Regular.ttf",
-      "notosansarmenian/NotoSansArmenian-VF.ttf",
-      "notosansbengaliui/NotoSansBengaliUI-VF.ttf",
-      "notosansdevanagariui/NotoSansDevanagariUI-VF.ttf",
-      "notosansethiopic/NotoSansEthiopic-VF.ttf",
-      "notosansgeorgian/NotoSansGeorgian-VF.ttf",
-      "notosansgujaratiui/NotoSansGujaratiUI-Regular.ttf",
-      "notosansgurmukhiui/NotoSansGurmukhiUI-VF.ttf",
-      "notosanshebrew/1.04/NotoSansHebrew-Regular.ttf",
-      "notosanskannadaui/NotoSansKannadaUI-VF.ttf",
-      "notosanskhmerui/NotoSansKhmerUI-Regular.ttf",
-      "notosanslaoui/NotoSansLaoUI-Regular.ttf",
-      "notosansmalayalamui/NotoSansMalayalamUI-VF.ttf",
-      "notosansmyanmarui/NotoSansMyanmarUI-Regular.otf",
-      "notosansoriya/NotoSansOriya-Regular.ttf",
-      "notosanssinhalaui/NotoSansSinhalaUI-VF.ttf",
-      "notosanstamilui/NotoSansTamilUI-VF.ttf",
-      "notosansteluguui/NotoSansTeluguUI-VF.ttf",
-      "notosansthaiui/NotoSansThaiUI-Regular.ttf",
+        "notosanscjk/NotoSansCJK-Regular.ttc",
+        "notonaskharabicui/NotoNaskhArabicUI-Regular.ttf",
+        "notosansarmenian/NotoSansArmenian-VF.ttf",
+        "notosansbengaliui/NotoSansBengaliUI-VF.ttf",
+        "notosansdevanagariui/NotoSansDevanagariUI-VF.ttf",
+        "notosansethiopic/NotoSansEthiopic-VF.ttf",
+        "notosansgeorgian/NotoSansGeorgian-VF.ttf",
+        "notosansgujaratiui/NotoSansGujaratiUI-Regular.ttf",
+        "notosansgurmukhiui/NotoSansGurmukhiUI-VF.ttf",
+        "notosanshebrew/1.04/NotoSansHebrew-Regular.ttf",
+        "notosanskannadaui/NotoSansKannadaUI-VF.ttf",
+        "notosanskhmerui/NotoSansKhmerUI-Regular.ttf",
+        "notosanslaoui/NotoSansLaoUI-Regular.ttf",
+        "notosansmalayalamui/NotoSansMalayalamUI-VF.ttf",
+        "notosansmyanmarui/NotoSansMyanmarUI-Regular.otf",
+        "notosansoriya/NotoSansOriya-Regular.ttf",
+        "notosanssinhalaui/NotoSansSinhalaUI-VF.ttf",
+        "notosanstamilui/NotoSansTamilUI-VF.ttf",
+        "notosansteluguui/NotoSansTeluguUI-VF.ttf",
+        "notosansthaiui/NotoSansThaiUI-Regular.ttf",
+    ],
+}
+
+filegroup {
+    name: "noto-fonts",
+    srcs: [
+        ":NotoColorEmoji",
+        ":NotoNaskhArabic",
+        ":NotoNaskhArabicUI",
+        ":NotoSansAdlam-VF",
+        ":NotoSansAhom",
+        ":NotoSansAnatolianHieroglyphs",
+        ":NotoSansArmenian-VF",
+        ":NotoSansAvestan",
+        ":NotoSansBalinese",
+        ":NotoSansBamum",
+        ":NotoSansBassaVah",
+        ":NotoSansBatak",
+        ":NotoSansBengali-VF",
+        ":NotoSansBengaliUI-VF",
+        ":NotoSansBhaiksuki",
+        ":NotoSansBrahmi",
+        ":NotoSansBuginese",
+        ":NotoSansBuhid",
+        ":NotoSansCJK",
+        ":NotoSansCanadianAboriginal",
+        ":NotoSansCarian",
+        ":NotoSansChakma",
+        ":NotoSansCham",
+        ":NotoSansCherokee",
+        ":NotoSansCoptic",
+        ":NotoSansCuneiform",
+        ":NotoSansCypriot",
+        ":NotoSansDeseret",
+        ":NotoSansDevanagari-VF",
+        ":NotoSansDevanagariUI-VF",
+        ":NotoSansEgyptianHieroglyphs",
+        ":NotoSansElbasan",
+        ":NotoSansEthiopic-VF",
+        ":NotoSansGeorgian-VF",
+        ":NotoSansGlagolitic",
+        ":NotoSansGothic",
+        ":NotoSansGrantha",
+        ":NotoSansGujarati",
+        ":NotoSansGujaratiUI",
+        ":NotoSansGunjalaGondi",
+        ":NotoSansGurmukhi-VF",
+        ":NotoSansGurmukhiUI-VF",
+        ":NotoSansHanifiRohingya",
+        ":NotoSansHanunoo",
+        ":NotoSansHatran",
+        ":NotoSansHebrew",
+        ":NotoSansImperialAramaic",
+        ":NotoSansInscriptionalPahlavi",
+        ":NotoSansInscriptionalParthian",
+        ":NotoSansJavanese",
+        ":NotoSansKaithi",
+        ":NotoSansKannada-VF",
+        ":NotoSansKannadaUI-VF",
+        ":NotoSansKayahLi",
+        ":NotoSansKharoshthi",
+        ":NotoSansKhmer-VF",
+        ":NotoSansKhmerUI",
+        ":NotoSansKhojki",
+        ":NotoSansLao",
+        ":NotoSansLaoUI",
+        ":NotoSansLepcha",
+        ":NotoSansLimbu",
+        ":NotoSansLinearA",
+        ":NotoSansLinearB",
+        ":NotoSansLisu",
+        ":NotoSansLycian",
+        ":NotoSansLydian",
+        ":NotoSansMalayalam-VF",
+        ":NotoSansMalayalamUI-VF",
+        ":NotoSansMandaic",
+        ":NotoSansManichaean",
+        ":NotoSansMarchen",
+        ":NotoSansMasaramGondi",
+        ":NotoSansMedefaidrin-VF",
+        ":NotoSansMeeteiMayek",
+        ":NotoSansMeroitic",
+        ":NotoSansMiao",
+        ":NotoSansModi",
+        ":NotoSansMongolian",
+        ":NotoSansMro",
+        ":NotoSansMultani",
+        ":NotoSansMyanmar",
+        ":NotoSansMyanmarUI",
+        ":NotoSansNKo",
+        ":NotoSansNabataean",
+        ":NotoSansNewTaiLue",
+        ":NotoSansNewa",
+        ":NotoSansOgham",
+        ":NotoSansOlChiki",
+        ":NotoSansOldItalic",
+        ":NotoSansOldNorthArabian",
+        ":NotoSansOldPermic",
+        ":NotoSansOldPersian",
+        ":NotoSansOldSouthArabian",
+        ":NotoSansOldTurkic",
+        ":NotoSansOriya",
+        ":NotoSansOriyaUI",
+        ":NotoSansOsage",
+        ":NotoSansOsmanya",
+        ":NotoSansPahawhHmong",
+        ":NotoSansPalmyrene",
+        ":NotoSansPauCinHau",
+        ":NotoSansPhagsPa",
+        ":NotoSansPhoenician",
+        ":NotoSansRejang",
+        ":NotoSansRunic",
+        ":NotoSansSamaritan",
+        ":NotoSansSaurashtra",
+        ":NotoSansSharada",
+        ":NotoSansShavian",
+        ":NotoSansSinhala-VF",
+        ":NotoSansSinhalaUI-VF",
+        ":NotoSansSoraSompeng",
+        ":NotoSansSoyombo-VF",
+        ":NotoSansSundanese",
+        ":NotoSansSylotiNagri",
+        ":NotoSansSymbols-Regular-Subsetted",
+        ":NotoSansSyriac",
+        ":NotoSansTagalog",
+        ":NotoSansTagbanwa",
+        ":NotoSansTaiLe",
+        ":NotoSansTaiTham",
+        ":NotoSansTaiViet",
+        ":NotoSansTakri-VF",
+        ":NotoSansTamil-VF",
+        ":NotoSansTamilUI-VF",
+        ":NotoSansTelugu-VF",
+        ":NotoSansTeluguUI-VF",
+        ":NotoSansThaana",
+        ":NotoSansThai",
+        ":NotoSansThaiUI",
+        ":NotoSansTifinagh",
+        ":NotoSansUgaritic",
+        ":NotoSansVai",
+        ":NotoSansWancho",
+        ":NotoSansWarangCiti",
+        ":NotoSansYi",
+        ":NotoSerif",
+        ":NotoSerifArmenian-VF",
+        ":NotoSerifBengali-VF",
+        ":NotoSerifCJK",
+        ":NotoSerifDevanagari-VF",
+        ":NotoSerifDogra",
+        ":NotoSerifEthiopic-VF",
+        ":NotoSerifGeorgian-VF",
+        ":NotoSerifGujarati-VF",
+        ":NotoSerifGurmukhi-VF",
+        ":NotoSerifHebrew",
+        ":NotoSerifHentaigana",
+        ":NotoSerifKannada-VF",
+        ":NotoSerifKhmer",
+        ":NotoSerifLao",
+        ":NotoSerifMalayalam-VF",
+        ":NotoSerifMyanmar",
+        ":NotoSerifNyiakengPuachueHmong-VF",
+        ":NotoSerifSinhala-VF",
+        ":NotoSerifTamil-VF",
+        ":NotoSerifTelugu-VF",
+        ":NotoSerifThai",
+        ":NotoSerifTibetan-VF",
+        ":NotoSerifYezidi-VF",
     ],
 }
diff --git a/emoji-compat/Android.bp b/emoji-compat/Android.bp
index 5acb491..4ea10ca 100644
--- a/emoji-compat/Android.bp
+++ b/emoji-compat/Android.bp
@@ -107,8 +107,8 @@ android_test {
     ],
 
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
     ],
 
     static_libs: [
@@ -130,3 +130,12 @@ android_test {
     manifest: "tests/AndroidManifest.xml",
     test_config: "tests/AndroidTest.xml",
 }
+
+filegroup {
+    name: "NotoColorEmoji",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoColorEmoji.ttf",
+        "NotoColorEmojiFlags.ttf",
+    ],
+}
diff --git a/emoji-compat/font_config.json b/emoji-compat/font_config.json
new file mode 100644
index 0000000..d61c1ee
--- /dev/null
+++ b/emoji-compat/font_config.json
@@ -0,0 +1,25 @@
+[
+    {
+        "lang": "und-Zsye",
+        "priority": 0,
+        "fonts": [
+            {
+                "file": "NotoColorEmoji.ttf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    },
+    {
+        "lang": "und-Zsye",
+        // Flags emoji should come next to the regular NotoColorEmoji
+        "priority": 50,
+        "fonts": [
+            {
+                "file": "NotoColorEmojiFlags.ttf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
diff --git a/notonaskharabic/Android.bp b/notonaskharabic/Android.bp
index d69a530..e795de1 100644
--- a/notonaskharabic/Android.bp
+++ b/notonaskharabic/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoNaskhArabic-Regular.ttf",
     src: "NotoNaskhArabic-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoNaskhArabic",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoNaskhArabic-Bold.ttf",
+        "NotoNaskhArabic-Regular.ttf",
+    ],
+}
diff --git a/notonaskharabic/font_config.json b/notonaskharabic/font_config.json
new file mode 100644
index 0000000..5e5b3e0
--- /dev/null
+++ b/notonaskharabic/font_config.json
@@ -0,0 +1,19 @@
+[
+    {
+        "lang": "und-Arab",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoNaskhArabic-Regular.ttf",
+                "postScriptName": "NotoNaskhArabic",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoNaskhArabic-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notonaskharabicui/Android.bp b/notonaskharabicui/Android.bp
index 9287f52..8fd046d 100644
--- a/notonaskharabicui/Android.bp
+++ b/notonaskharabicui/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoNaskhArabicUI-Regular.ttf",
     src: "NotoNaskhArabicUI-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoNaskhArabicUI",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoNaskhArabicUI-Regular.ttf",
+        "NotoNaskhArabicUI-Bold.ttf",
+    ],
+}
diff --git a/notonaskharabicui/font_config.json b/notonaskharabicui/font_config.json
new file mode 100644
index 0000000..1804ee5
--- /dev/null
+++ b/notonaskharabicui/font_config.json
@@ -0,0 +1,19 @@
+[
+    {
+        "lang": "und-Arab",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoNaskhArabicUI-Regular.ttf",
+                "postScriptName": "NotoNaskhArabicUI",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoNaskhArabicUI-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansadlam/Android.bp b/notosansadlam/Android.bp
index abe13d2..34cb611 100644
--- a/notosansadlam/Android.bp
+++ b/notosansadlam/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansAdlam-VF.ttf",
     src: "NotoSansAdlam-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansAdlam-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansAdlam-VF.ttf",
+    ],
+}
diff --git a/notosansadlam/font_config.json b/notosansadlam/font_config.json
new file mode 100644
index 0000000..bce452f
--- /dev/null
+++ b/notosansadlam/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Adlm",
+        "fonts": [
+            {
+                "file": "NotoSansAdlam-VF.ttf",
+                "postScriptName": "NotoSansAdlam-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansanatolianhieroglyphs/Android.bp b/notosansanatolianhieroglyphs/Android.bp
index 30600e3..5f85344 100644
--- a/notosansanatolianhieroglyphs/Android.bp
+++ b/notosansanatolianhieroglyphs/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansAnatolianHieroglyphs-Regular.otf",
     src: "NotoSansAnatolianHieroglyphs-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansAnatolianHieroglyphs",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansAnatolianHieroglyphs-Regular.otf",
+    ],
+}
diff --git a/notosansanatolianhieroglyphs/font_config.json b/notosansanatolianhieroglyphs/font_config.json
new file mode 100644
index 0000000..7bfc592
--- /dev/null
+++ b/notosansanatolianhieroglyphs/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Hluw",
+        "fonts": [
+            {
+                "file": "NotoSansAnatolianHieroglyphs-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansarmenian/Android.bp b/notosansarmenian/Android.bp
index 123063c..7d581c9 100644
--- a/notosansarmenian/Android.bp
+++ b/notosansarmenian/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansArmenian-VF.ttf",
     src: "NotoSansArmenian-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansArmenian-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansArmenian-VF.ttf",
+    ],
+}
diff --git a/notosansarmenian/font_config.json b/notosansarmenian/font_config.json
new file mode 100644
index 0000000..6fb4763
--- /dev/null
+++ b/notosansarmenian/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Armn",
+        "fonts": [
+            {
+                "file": "NotoSansArmenian-VF.ttf",
+                "postScriptName": "NotoSansArmenian-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "id": "NotoSansArmenian-VF_und-Armn"
+    }
+]
\ No newline at end of file
diff --git a/notosansavestan/Android.bp b/notosansavestan/Android.bp
index bbc8501..244e22e 100644
--- a/notosansavestan/Android.bp
+++ b/notosansavestan/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansAvestan-Regular.ttf",
     src: "NotoSansAvestan-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansAvestan",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansAvestan-Regular.ttf",
+    ],
+}
diff --git a/notosansavestan/font_config.json b/notosansavestan/font_config.json
new file mode 100644
index 0000000..3d29516
--- /dev/null
+++ b/notosansavestan/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Avst",
+        "fonts": [
+            {
+                "file": "NotoSansAvestan-Regular.ttf",
+                "postScriptName": "NotoSansAvestan",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansbalinese/Android.bp b/notosansbalinese/Android.bp
index 80eb6e7..82ba024 100644
--- a/notosansbalinese/Android.bp
+++ b/notosansbalinese/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansBalinese-Regular.ttf",
     src: "NotoSansBalinese-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansBalinese",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansBalinese-Regular.ttf",
+    ],
+}
diff --git a/notosansbalinese/font_config.json b/notosansbalinese/font_config.json
new file mode 100644
index 0000000..8ed1901
--- /dev/null
+++ b/notosansbalinese/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Bali",
+        "fonts": [
+            {
+                "file": "NotoSansBalinese-Regular.ttf",
+                "postScriptName": "NotoSansBalinese",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansbamum/Android.bp b/notosansbamum/Android.bp
index 19bdfae..fc60984 100644
--- a/notosansbamum/Android.bp
+++ b/notosansbamum/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansBamum-Regular.ttf",
     src: "NotoSansBamum-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansBamum",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansBamum-Regular.ttf",
+    ],
+}
diff --git a/notosansbamum/font_config.json b/notosansbamum/font_config.json
new file mode 100644
index 0000000..232f8dc
--- /dev/null
+++ b/notosansbamum/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Bamu",
+        "fonts": [
+            {
+                "file": "NotoSansBamum-Regular.ttf",
+                "postScriptName": "NotoSansBamum",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansbassavah/Android.bp b/notosansbassavah/Android.bp
index 6c25f58..b4446ba 100644
--- a/notosansbassavah/Android.bp
+++ b/notosansbassavah/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansBassaVah-Regular.otf",
     src: "NotoSansBassaVah-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansBassaVah",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansBassaVah-Regular.otf",
+    ],
+}
diff --git a/notosansbassavah/font_config.json b/notosansbassavah/font_config.json
new file mode 100644
index 0000000..079f165
--- /dev/null
+++ b/notosansbassavah/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Bass",
+        "fonts": [
+            {
+                "file": "NotoSansBassaVah-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansbatak/Android.bp b/notosansbatak/Android.bp
index 6588d93..0f30bb6 100644
--- a/notosansbatak/Android.bp
+++ b/notosansbatak/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansBatak-Regular.ttf",
     src: "NotoSansBatak-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansBatak",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansBatak-Regular.ttf",
+    ],
+}
diff --git a/notosansbatak/font_config.json b/notosansbatak/font_config.json
new file mode 100644
index 0000000..e3c6237
--- /dev/null
+++ b/notosansbatak/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Batk",
+        "fonts": [
+            {
+                "file": "NotoSansBatak-Regular.ttf",
+                "postScriptName": "NotoSansBatak",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansbengali/Android.bp b/notosansbengali/Android.bp
index cd1060e..9ca1371 100644
--- a/notosansbengali/Android.bp
+++ b/notosansbengali/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansBengali-VF.ttf",
     src: "NotoSansBengali-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansBengali-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansBengali-VF.ttf",
+    ],
+}
diff --git a/notosansbengali/font_config.json b/notosansbengali/font_config.json
new file mode 100644
index 0000000..99e891c
--- /dev/null
+++ b/notosansbengali/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Beng",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansBengali-VF.ttf",
+                "postScriptName": "NotoSansBengali-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "id": "NotoSansBengali-VF_und-Beng"
+    }
+]
\ No newline at end of file
diff --git a/notosansbengaliui/Android.bp b/notosansbengaliui/Android.bp
index 8f45cf5..64d8d3b 100644
--- a/notosansbengaliui/Android.bp
+++ b/notosansbengaliui/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansBengaliUI-VF.ttf",
     src: "NotoSansBengaliUI-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansBengaliUI-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansBengaliUI-VF.ttf",
+    ],
+}
diff --git a/notosansbengaliui/font_config.json b/notosansbengaliui/font_config.json
new file mode 100644
index 0000000..b4cd643
--- /dev/null
+++ b/notosansbengaliui/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Beng",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansBengaliUI-VF.ttf",
+                "postScriptName": "NotoSansBengaliUI-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansbhaiksuki/Android.bp b/notosansbhaiksuki/Android.bp
index d7cf0ee..d06b1da 100644
--- a/notosansbhaiksuki/Android.bp
+++ b/notosansbhaiksuki/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansBhaiksuki-Regular.otf",
     src: "NotoSansBhaiksuki-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansBhaiksuki",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansBhaiksuki-Regular.otf",
+    ],
+}
diff --git a/notosansbhaiksuki/font_config.json b/notosansbhaiksuki/font_config.json
new file mode 100644
index 0000000..41baea6
--- /dev/null
+++ b/notosansbhaiksuki/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Bhks",
+        "fonts": [
+            {
+                "file": "NotoSansBhaiksuki-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansbrahmi/Android.bp b/notosansbrahmi/Android.bp
index 9805a50..61f0559 100644
--- a/notosansbrahmi/Android.bp
+++ b/notosansbrahmi/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansBrahmi-Regular.ttf",
     src: "NotoSansBrahmi-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansBrahmi",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansBrahmi-Regular.ttf",
+    ],
+}
diff --git a/notosansbrahmi/font_config.json b/notosansbrahmi/font_config.json
new file mode 100644
index 0000000..53bf0c7
--- /dev/null
+++ b/notosansbrahmi/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Brah",
+        "fonts": [
+            {
+                "file": "NotoSansBrahmi-Regular.ttf",
+                "postScriptName": "NotoSansBrahmi",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansbuginese/Android.bp b/notosansbuginese/Android.bp
index 6d4ebb8..2f080b4 100644
--- a/notosansbuginese/Android.bp
+++ b/notosansbuginese/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansBuginese-Regular.ttf",
     src: "NotoSansBuginese-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansBuginese",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansBuginese-Regular.ttf",
+    ],
+}
diff --git a/notosansbuginese/font_config.json b/notosansbuginese/font_config.json
new file mode 100644
index 0000000..5023b0a
--- /dev/null
+++ b/notosansbuginese/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Bugi",
+        "fonts": [
+            {
+                "file": "NotoSansBuginese-Regular.ttf",
+                "postScriptName": "NotoSansBuginese",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansbuhid/Android.bp b/notosansbuhid/Android.bp
index e5830ed..586ef09 100644
--- a/notosansbuhid/Android.bp
+++ b/notosansbuhid/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansBuhid-Regular.ttf",
     src: "NotoSansBuhid-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansBuhid",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansBuhid-Regular.ttf",
+    ],
+}
diff --git a/notosansbuhid/font_config.json b/notosansbuhid/font_config.json
new file mode 100644
index 0000000..46792ab
--- /dev/null
+++ b/notosansbuhid/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Buhd",
+        "fonts": [
+            {
+                "file": "NotoSansBuhid-Regular.ttf",
+                "postScriptName": "NotoSansBuhid",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanscanadianaboriginal/Android.bp b/notosanscanadianaboriginal/Android.bp
index efb14d1..c00e005 100644
--- a/notosanscanadianaboriginal/Android.bp
+++ b/notosanscanadianaboriginal/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansCanadianAboriginal-Regular.ttf",
     src: "NotoSansCanadianAboriginal-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansCanadianAboriginal",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansCanadianAboriginal-Regular.ttf",
+    ],
+}
diff --git a/notosanscanadianaboriginal/font_config.json b/notosanscanadianaboriginal/font_config.json
new file mode 100644
index 0000000..3ad0bb7
--- /dev/null
+++ b/notosanscanadianaboriginal/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Cans",
+        "fonts": [
+            {
+                "file": "NotoSansCanadianAboriginal-Regular.ttf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanscarian/Android.bp b/notosanscarian/Android.bp
index 6d3a7a8..da751e6 100644
--- a/notosanscarian/Android.bp
+++ b/notosanscarian/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansCarian-Regular.ttf",
     src: "NotoSansCarian-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansCarian",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansCarian-Regular.ttf",
+    ],
+}
diff --git a/notosanscarian/font_config.json b/notosanscarian/font_config.json
new file mode 100644
index 0000000..deef82d
--- /dev/null
+++ b/notosanscarian/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Cari",
+        "fonts": [
+            {
+                "file": "NotoSansCarian-Regular.ttf",
+                "postScriptName": "NotoSansCarian",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanschakma/Android.bp b/notosanschakma/Android.bp
index 37389ed..7f42050 100644
--- a/notosanschakma/Android.bp
+++ b/notosanschakma/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansChakma-Regular.otf",
     src: "NotoSansChakma-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansChakma",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansChakma-Regular.otf",
+    ],
+}
diff --git a/notosanschakma/font_config.json b/notosanschakma/font_config.json
new file mode 100644
index 0000000..b381a5e
--- /dev/null
+++ b/notosanschakma/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Cakm",
+        "fonts": [
+            {
+                "file": "NotoSansChakma-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanscham/Android.bp b/notosanscham/Android.bp
index 1c18100..da12668 100644
--- a/notosanscham/Android.bp
+++ b/notosanscham/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSansCham-Bold.ttf",
     src: "NotoSansCham-Bold.ttf",
 }
+
+filegroup {
+    name: "NotoSansCham",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansCham-Bold.ttf",
+        "NotoSansCham-Regular.ttf",
+    ],
+}
diff --git a/notosanscham/font_config.json b/notosanscham/font_config.json
new file mode 100644
index 0000000..0e92544
--- /dev/null
+++ b/notosanscham/font_config.json
@@ -0,0 +1,18 @@
+[
+    {
+        "lang": "und-Cham",
+        "fonts": [
+            {
+                "file": "NotoSansCham-Regular.ttf",
+                "postScriptName": "NotoSansCham",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansCham-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanscherokee/Android.bp b/notosanscherokee/Android.bp
index f1bf1ad..8294bcf 100644
--- a/notosanscherokee/Android.bp
+++ b/notosanscherokee/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansCherokee-Regular.ttf",
     src: "NotoSansCherokee-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansCherokee",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansCherokee-Regular.ttf",
+    ],
+}
diff --git a/notosanscherokee/font_config.json b/notosanscherokee/font_config.json
new file mode 100644
index 0000000..bc0a850
--- /dev/null
+++ b/notosanscherokee/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Cher",
+        "fonts": [
+            {
+                "file": "NotoSansCherokee-Regular.ttf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanscjk/Android.bp b/notosanscjk/Android.bp
index eb989bd..4f76787 100644
--- a/notosanscjk/Android.bp
+++ b/notosanscjk/Android.bp
@@ -54,15 +54,38 @@ soong_config_module_type {
     module_type: "prebuilt_font",
     config_namespace: "noto_sans_cjk_config",
     bool_variables: ["use_var_font"],
-    properties: [ "src" ],
+    properties: ["src"],
 }
 
 prebuilt_noto_sans_cjk {
     name: "NotoSansCJK-Regular.ttc",
     src: "NotoSansCJK-Regular.ttc",
     soong_config_variables: {
-      use_var_font: {
-        src: "NotoSansCJK-wght-400-900.otf.ttc",
-      },
+        use_var_font: {
+            src: "NotoSansCJK-wght-400-900.otf.ttc",
+        },
+    },
+}
+
+soong_config_module_type {
+    name: "filegroup_for_vf",
+    module_type: "filegroup",
+    config_namespace: "noto_sans_cjk_config",
+    bool_variables: ["use_var_font"],
+    properties: ["srcs"],
+}
+
+filegroup_for_vf {
+    name: "NotoSansCJK",
+    required: [
+        "NotoSansCJK-Regular.ttc",
+    ],
+    soong_config_variables: {
+        use_var_font: {
+            srcs: ["font_config_vf.json"],
+            conditions_default: {
+                srcs: ["font_config.json"],
+            },
+        },
     },
 }
diff --git a/notosanscjk/font_config.json b/notosanscjk/font_config.json
new file mode 100644
index 0000000..8a56897
--- /dev/null
+++ b/notosanscjk/font_config.json
@@ -0,0 +1,54 @@
+[
+    {
+        "lang": "zh-Hans",
+        "fonts": [
+            {
+                "file": "NotoSansCJK-Regular.ttc",
+                "postScriptName": "NotoSansCJKJP-Regular",
+                "weight": "400",
+                "style": "normal",
+                "index": "2"
+            }
+        ],
+        "id": "NotoSansCJK_zh-Hans"
+    },
+    {
+        "lang": "zh-Hant,zh-Bopo",
+        "fonts": [
+            {
+                "file": "NotoSansCJK-Regular.ttc",
+                "postScriptName": "NotoSansCJKJP-Regular",
+                "weight": "400",
+                "style": "normal",
+                "index": "3"
+            }
+        ],
+        "id": "NotoSansCJK_zh-Hant,zh-Bopo"
+    },
+    {
+        "lang": "ja",
+        "fonts": [
+            {
+                "file": "NotoSansCJK-Regular.ttc",
+                "postScriptName": "NotoSansCJKJP-Regular",
+                "weight": "400",
+                "style": "normal",
+                "index": "0"
+            }
+        ],
+        "id": "NotoSansCJK_ja"
+    },
+    {
+        "lang": "ko",
+        "fonts": [
+            {
+                "file": "NotoSansCJK-Regular.ttc",
+                "postScriptName": "NotoSansCJKJP-Regular",
+                "weight": "400",
+                "style": "normal",
+                "index": "1"
+            }
+        ],
+        "id": "NotoSansCJK_ko"
+    }
+]
diff --git a/notosanscjk/font_config_vf.json b/notosanscjk/font_config_vf.json
new file mode 100644
index 0000000..c09d6ea
--- /dev/null
+++ b/notosanscjk/font_config_vf.json
@@ -0,0 +1,70 @@
+[
+    {
+        "lang": "zh-Hans",
+        "fonts": [
+            {
+                "file": "NotoSansCJK-Regular.ttc",
+                "postScriptName": "NotoSansCJKJP-Regular",
+                "weight": "400",
+                "style": "normal",
+                "supportedAxes": "wght",
+                "axes": {
+                    "wght": "400"
+                },
+                "index": "2"
+            }
+        ],
+        "id": "NotoSansCJK_zh-Hans"
+    },
+    {
+        "lang": "zh-Hant,zh-Bopo",
+        "fonts": [
+            {
+                "file": "NotoSansCJK-Regular.ttc",
+                "postScriptName": "NotoSansCJKJP-Regular",
+                "weight": "400",
+                "style": "normal",
+                "supportedAxes": "wght",
+                "axes": {
+                    "wght": "400"
+                },
+                "index": "3"
+            }
+        ],
+        "id": "NotoSansCJK_zh-Hant,zh-Bopo"
+    },
+    {
+        "lang": "ja",
+        "fonts": [
+            {
+                "file": "NotoSansCJK-Regular.ttc",
+                "postScriptName": "NotoSansCJKJP-Regular",
+                "weight": "400",
+                "style": "normal",
+                "supportedAxes": "wght",
+                "axes": {
+                    "wght": "400"
+                },
+                "index": "0"
+            }
+        ],
+        "id": "NotoSansCJK_ja"
+    },
+    {
+        "lang": "ko",
+        "fonts": [
+            {
+                "file": "NotoSansCJK-Regular.ttc",
+                "postScriptName": "NotoSansCJKJP-Regular",
+                "weight": "400",
+                "style": "normal",
+                "supportedAxes": "wght",
+                "axes": {
+                    "wght": "400"
+                },
+                "index": "1"
+            }
+        ],
+        "id": "NotoSansCJK_ko"
+    }
+]
\ No newline at end of file
diff --git a/notosanscoptic/Android.bp b/notosanscoptic/Android.bp
index 0d86c0b..16fbd93 100644
--- a/notosanscoptic/Android.bp
+++ b/notosanscoptic/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansCoptic-Regular.ttf",
     src: "NotoSansCoptic-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansCoptic",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansCoptic-Regular.ttf",
+    ],
+}
diff --git a/notosanscoptic/font_config.json b/notosanscoptic/font_config.json
new file mode 100644
index 0000000..5b9c0c8
--- /dev/null
+++ b/notosanscoptic/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Copt",
+        "fonts": [
+            {
+                "file": "NotoSansCoptic-Regular.ttf",
+                "postScriptName": "NotoSansCoptic",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanscuneiform/Android.bp b/notosanscuneiform/Android.bp
index 1b94e36..a1c0b12 100644
--- a/notosanscuneiform/Android.bp
+++ b/notosanscuneiform/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansCuneiform-Regular.ttf",
     src: "NotoSansCuneiform-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansCuneiform",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansCuneiform-Regular.ttf",
+    ],
+}
diff --git a/notosanscuneiform/font_config.json b/notosanscuneiform/font_config.json
new file mode 100644
index 0000000..f46ea06
--- /dev/null
+++ b/notosanscuneiform/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Xsux",
+        "fonts": [
+            {
+                "file": "NotoSansCuneiform-Regular.ttf",
+                "postScriptName": "NotoSansCuneiform",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanscypriot/Android.bp b/notosanscypriot/Android.bp
index 168f214..f512ecc 100644
--- a/notosanscypriot/Android.bp
+++ b/notosanscypriot/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansCypriot-Regular.ttf",
     src: "NotoSansCypriot-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansCypriot",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansCypriot-Regular.ttf",
+    ],
+}
diff --git a/notosanscypriot/font_config.json b/notosanscypriot/font_config.json
new file mode 100644
index 0000000..9dcdc1b
--- /dev/null
+++ b/notosanscypriot/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Cprt",
+        "fonts": [
+            {
+                "file": "NotoSansCypriot-Regular.ttf",
+                "postScriptName": "NotoSansCypriot",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansdeseret/Android.bp b/notosansdeseret/Android.bp
index 01e8b5d..fb367a1 100644
--- a/notosansdeseret/Android.bp
+++ b/notosansdeseret/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansDeseret-Regular.ttf",
     src: "NotoSansDeseret-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansDeseret",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansDeseret-Regular.ttf",
+    ],
+}
diff --git a/notosansdeseret/font_config.json b/notosansdeseret/font_config.json
new file mode 100644
index 0000000..d975a98
--- /dev/null
+++ b/notosansdeseret/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Dsrt",
+        "fonts": [
+            {
+                "file": "NotoSansDeseret-Regular.ttf",
+                "postScriptName": "NotoSansDeseret",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansdevanagari/Android.bp b/notosansdevanagari/Android.bp
index 5e39e1a..f73dfd5 100644
--- a/notosansdevanagari/Android.bp
+++ b/notosansdevanagari/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansDevanagari-VF.ttf",
     src: "NotoSansDevanagari-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansDevanagari-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansDevanagari-VF.ttf",
+    ],
+}
diff --git a/notosansdevanagari/font_config.json b/notosansdevanagari/font_config.json
new file mode 100644
index 0000000..1c39142
--- /dev/null
+++ b/notosansdevanagari/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Deva",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansDevanagari-VF.ttf",
+                "postScriptName": "NotoSansDevanagari-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "id": "NotoSansDevanagari-VF_und-Deva"
+    }
+]
\ No newline at end of file
diff --git a/notosansdevanagariui/Android.bp b/notosansdevanagariui/Android.bp
index 7259f53..d2fcd0b 100644
--- a/notosansdevanagariui/Android.bp
+++ b/notosansdevanagariui/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansDevanagariUI-VF.ttf",
     src: "NotoSansDevanagariUI-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansDevanagariUI-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansDevanagariUI-VF.ttf",
+    ],
+}
diff --git a/notosansdevanagariui/font_config.json b/notosansdevanagariui/font_config.json
new file mode 100644
index 0000000..68dcf74
--- /dev/null
+++ b/notosansdevanagariui/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Deva",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansDevanagariUI-VF.ttf",
+                "postScriptName": "NotoSansDevanagariUI-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansegyptianhieroglyphs/Android.bp b/notosansegyptianhieroglyphs/Android.bp
index f2fbbb2..0ad5d2d 100644
--- a/notosansegyptianhieroglyphs/Android.bp
+++ b/notosansegyptianhieroglyphs/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansEgyptianHieroglyphs-Regular.ttf",
     src: "NotoSansEgyptianHieroglyphs-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansEgyptianHieroglyphs",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansEgyptianHieroglyphs-Regular.ttf",
+    ],
+}
diff --git a/notosansegyptianhieroglyphs/font_config.json b/notosansegyptianhieroglyphs/font_config.json
new file mode 100644
index 0000000..8c8d3b6
--- /dev/null
+++ b/notosansegyptianhieroglyphs/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Egyp",
+        "fonts": [
+            {
+                "file": "NotoSansEgyptianHieroglyphs-Regular.ttf",
+                "postScriptName": "NotoSansEgyptianHieroglyphs",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanselbasan/Android.bp b/notosanselbasan/Android.bp
index eb8f15f..24cbaca 100644
--- a/notosanselbasan/Android.bp
+++ b/notosanselbasan/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansElbasan-Regular.otf",
     src: "NotoSansElbasan-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansElbasan",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansElbasan-Regular.otf",
+    ],
+}
diff --git a/notosanselbasan/font_config.json b/notosanselbasan/font_config.json
new file mode 100644
index 0000000..6b75600
--- /dev/null
+++ b/notosanselbasan/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Elba",
+        "fonts": [
+            {
+                "file": "NotoSansElbasan-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansethiopic/Android.bp b/notosansethiopic/Android.bp
index dca8cd2..441a0d7 100644
--- a/notosansethiopic/Android.bp
+++ b/notosansethiopic/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansEthiopic-VF.ttf",
     src: "NotoSansEthiopic-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansEthiopic-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansEthiopic-VF.ttf",
+    ],
+}
diff --git a/notosansethiopic/font_config.json b/notosansethiopic/font_config.json
new file mode 100644
index 0000000..85a9333
--- /dev/null
+++ b/notosansethiopic/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Ethi",
+        "fonts": [
+            {
+                "file": "NotoSansEthiopic-VF.ttf",
+                "postScriptName": "NotoSansEthiopic-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "id": "NotoSansEthiopic-VF_und-Ethi"
+    }
+]
\ No newline at end of file
diff --git a/notosansgeorgian/Android.bp b/notosansgeorgian/Android.bp
index 919f299..2dea565 100644
--- a/notosansgeorgian/Android.bp
+++ b/notosansgeorgian/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansGeorgian-VF.ttf",
     src: "NotoSansGeorgian-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansGeorgian-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansGeorgian-VF.ttf",
+    ],
+}
diff --git a/notosansgeorgian/font_config.json b/notosansgeorgian/font_config.json
new file mode 100644
index 0000000..4d86b42
--- /dev/null
+++ b/notosansgeorgian/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Geor,und-Geok",
+        "fonts": [
+            {
+                "file": "NotoSansGeorgian-VF.ttf",
+                "postScriptName": "NotoSansGeorgian-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "id": "NotoSansGeorgian-VF_und-Geor,und-Geok"
+    }
+]
\ No newline at end of file
diff --git a/notosansglagolitic/Android.bp b/notosansglagolitic/Android.bp
index 5b99823..64fff46 100644
--- a/notosansglagolitic/Android.bp
+++ b/notosansglagolitic/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansGlagolitic-Regular.ttf",
     src: "NotoSansGlagolitic-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansGlagolitic",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansGlagolitic-Regular.ttf",
+    ],
+}
diff --git a/notosansglagolitic/font_config.json b/notosansglagolitic/font_config.json
new file mode 100644
index 0000000..b0417c6
--- /dev/null
+++ b/notosansglagolitic/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Glag",
+        "fonts": [
+            {
+                "file": "NotoSansGlagolitic-Regular.ttf",
+                "postScriptName": "NotoSansGlagolitic",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansgothic/Android.bp b/notosansgothic/Android.bp
index 77baae0..6fa771e 100644
--- a/notosansgothic/Android.bp
+++ b/notosansgothic/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansGothic-Regular.ttf",
     src: "NotoSansGothic-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansGothic",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansGothic-Regular.ttf",
+    ],
+}
diff --git a/notosansgothic/font_config.json b/notosansgothic/font_config.json
new file mode 100644
index 0000000..c976891
--- /dev/null
+++ b/notosansgothic/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Goth",
+        "fonts": [
+            {
+                "file": "NotoSansGothic-Regular.ttf",
+                "postScriptName": "NotoSansGothic",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansgrantha/Android.bp b/notosansgrantha/Android.bp
index 620c02a..5513a2a 100644
--- a/notosansgrantha/Android.bp
+++ b/notosansgrantha/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansGrantha-Regular.ttf",
     src: "NotoSansGrantha-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansGrantha",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansGrantha-Regular.ttf",
+    ],
+}
diff --git a/notosansgrantha/font_config.json b/notosansgrantha/font_config.json
new file mode 100644
index 0000000..91c8205
--- /dev/null
+++ b/notosansgrantha/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Gran",
+        "fonts": [
+            {
+                "file": "NotoSansGrantha-Regular.ttf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansgujarati/Android.bp b/notosansgujarati/Android.bp
index 1122cbf..632d561 100644
--- a/notosansgujarati/Android.bp
+++ b/notosansgujarati/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSansGujarati-Regular.ttf",
     src: "NotoSansGujarati-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansGujarati",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansGujarati-Regular.ttf",
+        "NotoSansGujarati-Bold.ttf",
+    ],
+}
diff --git a/notosansgujarati/font_config.json b/notosansgujarati/font_config.json
new file mode 100644
index 0000000..c3ba706
--- /dev/null
+++ b/notosansgujarati/font_config.json
@@ -0,0 +1,20 @@
+[
+    {
+        "lang": "und-Gujr",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansGujarati-Regular.ttf",
+                "postScriptName": "NotoSansGujarati",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansGujarati-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ],
+        "id": "NotoSansGujarati_und-Gujr"
+    }
+]
\ No newline at end of file
diff --git a/notosansgujaratiui/Android.bp b/notosansgujaratiui/Android.bp
index 6f202f1..90d89dd 100644
--- a/notosansgujaratiui/Android.bp
+++ b/notosansgujaratiui/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSansGujaratiUI-Regular.ttf",
     src: "NotoSansGujaratiUI-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansGujaratiUI",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansGujaratiUI-Bold.ttf",
+        "NotoSansGujaratiUI-Regular.ttf",
+    ],
+}
diff --git a/notosansgujaratiui/font_config.json b/notosansgujaratiui/font_config.json
new file mode 100644
index 0000000..252a7dd
--- /dev/null
+++ b/notosansgujaratiui/font_config.json
@@ -0,0 +1,19 @@
+[
+    {
+        "lang": "und-Gujr",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansGujaratiUI-Regular.ttf",
+                "postScriptName": "NotoSansGujaratiUI",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansGujaratiUI-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansgunjalagondi/Android.bp b/notosansgunjalagondi/Android.bp
index e2d8ad4..b80e639 100644
--- a/notosansgunjalagondi/Android.bp
+++ b/notosansgunjalagondi/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansGunjalaGondi-Regular.otf",
     src: "NotoSansGunjalaGondi-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansGunjalaGondi",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansGunjalaGondi-Regular.otf",
+    ],
+}
diff --git a/notosansgunjalagondi/font_config.json b/notosansgunjalagondi/font_config.json
new file mode 100644
index 0000000..ef352bb
--- /dev/null
+++ b/notosansgunjalagondi/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Gong",
+        "fonts": [
+            {
+                "file": "NotoSansGunjalaGondi-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansgurmukhi/Android.bp b/notosansgurmukhi/Android.bp
index 09c2e7a..8cb2282 100644
--- a/notosansgurmukhi/Android.bp
+++ b/notosansgurmukhi/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansGurmukhi-VF.ttf",
     src: "NotoSansGurmukhi-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansGurmukhi-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansGurmukhi-VF.ttf",
+    ],
+}
diff --git a/notosansgurmukhi/font_config.json b/notosansgurmukhi/font_config.json
new file mode 100644
index 0000000..dbdfc37
--- /dev/null
+++ b/notosansgurmukhi/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Guru",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansGurmukhi-VF.ttf",
+                "postScriptName": "NotoSansGurmukhi-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "id": "NotoSansGurmukhi-VF_und-Guru"
+    }
+]
\ No newline at end of file
diff --git a/notosansgurmukhiui/Android.bp b/notosansgurmukhiui/Android.bp
index 4787b4b..4b36b72 100644
--- a/notosansgurmukhiui/Android.bp
+++ b/notosansgurmukhiui/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansGurmukhiUI-VF.ttf",
     src: "NotoSansGurmukhiUI-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansGurmukhiUI-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansGurmukhiUI-VF.ttf",
+    ],
+}
diff --git a/notosansgurmukhiui/font_config.json b/notosansgurmukhiui/font_config.json
new file mode 100644
index 0000000..f737c86
--- /dev/null
+++ b/notosansgurmukhiui/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Guru",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansGurmukhiUI-VF.ttf",
+                "postScriptName": "NotoSansGurmukhiUI-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanshanifirohingya/Android.bp b/notosanshanifirohingya/Android.bp
index e321ecc..33c1170 100644
--- a/notosanshanifirohingya/Android.bp
+++ b/notosanshanifirohingya/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansHanifiRohingya-Regular.otf",
     src: "NotoSansHanifiRohingya-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansHanifiRohingya",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansHanifiRohingya-Regular.otf",
+    ],
+}
diff --git a/notosanshanifirohingya/font_config.json b/notosanshanifirohingya/font_config.json
new file mode 100644
index 0000000..ca37e2d
--- /dev/null
+++ b/notosanshanifirohingya/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Rohg",
+        "fonts": [
+            {
+                "file": "NotoSansHanifiRohingya-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanshanunoo/Android.bp b/notosanshanunoo/Android.bp
index 18cc95c..3c0bd0d 100644
--- a/notosanshanunoo/Android.bp
+++ b/notosanshanunoo/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansHanunoo-Regular.ttf",
     src: "NotoSansHanunoo-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansHanunoo",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansHanunoo-Regular.ttf",
+    ],
+}
diff --git a/notosanshanunoo/font_config.json b/notosanshanunoo/font_config.json
new file mode 100644
index 0000000..7afc50b
--- /dev/null
+++ b/notosanshanunoo/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Hano",
+        "fonts": [
+            {
+                "file": "NotoSansHanunoo-Regular.ttf",
+                "postScriptName": "NotoSansHanunoo",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanshatran/Android.bp b/notosanshatran/Android.bp
index 114af24..434f3a3 100644
--- a/notosanshatran/Android.bp
+++ b/notosanshatran/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansHatran-Regular.otf",
     src: "NotoSansHatran-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansHatran",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansHatran-Regular.otf",
+    ],
+}
diff --git a/notosanshatran/font_config.json b/notosanshatran/font_config.json
new file mode 100644
index 0000000..715b7af
--- /dev/null
+++ b/notosanshatran/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Hatr",
+        "fonts": [
+            {
+                "file": "NotoSansHatran-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanshebrew/Android.bp b/notosanshebrew/Android.bp
index e328f14..5faa58d 100644
--- a/notosanshebrew/Android.bp
+++ b/notosanshebrew/Android.bp
@@ -72,3 +72,12 @@ prebuilt_hebrew_font {
         },
     },
 }
+
+filegroup {
+    name: "NotoSansHebrew",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansHebrew-Bold.ttf",
+        "NotoSansHebrew-Regular.ttf",
+    ],
+}
diff --git a/notosanshebrew/font_config.json b/notosanshebrew/font_config.json
new file mode 100644
index 0000000..3aebc7c
--- /dev/null
+++ b/notosanshebrew/font_config.json
@@ -0,0 +1,19 @@
+[
+    {
+        "lang": "und-Hebr",
+        "fonts": [
+            {
+                "file": "NotoSansHebrew-Regular.ttf",
+                "postScriptName": "NotoSansHebrew",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansHebrew-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ],
+        "id": "NotoSansHebrew_und-Hebr"
+    }
+]
\ No newline at end of file
diff --git a/notosansimperialaramaic/Android.bp b/notosansimperialaramaic/Android.bp
index f2ccf18..3e9b836 100644
--- a/notosansimperialaramaic/Android.bp
+++ b/notosansimperialaramaic/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansImperialAramaic-Regular.ttf",
     src: "NotoSansImperialAramaic-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansImperialAramaic",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansImperialAramaic-Regular.ttf",
+    ],
+}
diff --git a/notosansimperialaramaic/font_config.json b/notosansimperialaramaic/font_config.json
new file mode 100644
index 0000000..3208a5e
--- /dev/null
+++ b/notosansimperialaramaic/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Armi",
+        "fonts": [
+            {
+                "file": "NotoSansImperialAramaic-Regular.ttf",
+                "postScriptName": "NotoSansImperialAramaic",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansinscriptionalpahlavi/Android.bp b/notosansinscriptionalpahlavi/Android.bp
index bc80c78..644f558 100644
--- a/notosansinscriptionalpahlavi/Android.bp
+++ b/notosansinscriptionalpahlavi/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansInscriptionalPahlavi-Regular.ttf",
     src: "NotoSansInscriptionalPahlavi-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansInscriptionalPahlavi",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansInscriptionalPahlavi-Regular.ttf",
+    ],
+}
diff --git a/notosansinscriptionalpahlavi/font_config.json b/notosansinscriptionalpahlavi/font_config.json
new file mode 100644
index 0000000..28652ce
--- /dev/null
+++ b/notosansinscriptionalpahlavi/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Phli",
+        "fonts": [
+            {
+                "file": "NotoSansInscriptionalPahlavi-Regular.ttf",
+                "postScriptName": "NotoSansInscriptionalPahlavi",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansinscriptionalparthian/Android.bp b/notosansinscriptionalparthian/Android.bp
index f5a3d7d..9a81e31 100644
--- a/notosansinscriptionalparthian/Android.bp
+++ b/notosansinscriptionalparthian/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansInscriptionalParthian-Regular.ttf",
     src: "NotoSansInscriptionalParthian-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansInscriptionalParthian",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansInscriptionalParthian-Regular.ttf",
+    ],
+}
diff --git a/notosansinscriptionalparthian/font_config.json b/notosansinscriptionalparthian/font_config.json
new file mode 100644
index 0000000..2a78b47
--- /dev/null
+++ b/notosansinscriptionalparthian/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Prti",
+        "fonts": [
+            {
+                "file": "NotoSansInscriptionalParthian-Regular.ttf",
+                "postScriptName": "NotoSansInscriptionalParthian",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansjavanese/Android.bp b/notosansjavanese/Android.bp
index ec83337..98b0735 100644
--- a/notosansjavanese/Android.bp
+++ b/notosansjavanese/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansJavanese-Regular.otf",
     src: "NotoSansJavanese-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansJavanese",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansJavanese-Regular.otf",
+    ],
+}
diff --git a/notosansjavanese/font_config.json b/notosansjavanese/font_config.json
new file mode 100644
index 0000000..59fac54
--- /dev/null
+++ b/notosansjavanese/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Java",
+        "fonts": [
+            {
+                "file": "NotoSansJavanese-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanskaithi/Android.bp b/notosanskaithi/Android.bp
index 05ffb04..fde1f78 100644
--- a/notosanskaithi/Android.bp
+++ b/notosanskaithi/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansKaithi-Regular.ttf",
     src: "NotoSansKaithi-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansKaithi",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansKaithi-Regular.ttf",
+    ],
+}
diff --git a/notosanskaithi/font_config.json b/notosanskaithi/font_config.json
new file mode 100644
index 0000000..79d0e7d
--- /dev/null
+++ b/notosanskaithi/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Kthi",
+        "fonts": [
+            {
+                "file": "NotoSansKaithi-Regular.ttf",
+                "postScriptName": "NotoSansKaithi",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanskannada/Android.bp b/notosanskannada/Android.bp
index e7176a0..bd959f4 100644
--- a/notosanskannada/Android.bp
+++ b/notosanskannada/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansKannada-VF.ttf",
     src: "NotoSansKannada-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansKannada-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansKannada-VF.ttf",
+    ],
+}
diff --git a/notosanskannada/font_config.json b/notosanskannada/font_config.json
new file mode 100644
index 0000000..006e98c
--- /dev/null
+++ b/notosanskannada/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Knda",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansKannada-VF.ttf",
+                "postScriptName": "NotoSansKannada-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "id": "NotoSansKannada-VF_und-Knda"
+    }
+]
\ No newline at end of file
diff --git a/notosanskannadaui/Android.bp b/notosanskannadaui/Android.bp
index a123515..e94d733 100644
--- a/notosanskannadaui/Android.bp
+++ b/notosanskannadaui/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansKannadaUI-VF.ttf",
     src: "NotoSansKannadaUI-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansKannadaUI-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansKannadaUI-VF.ttf",
+    ],
+}
diff --git a/notosanskannadaui/font_config.json b/notosanskannadaui/font_config.json
new file mode 100644
index 0000000..0170646
--- /dev/null
+++ b/notosanskannadaui/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Knda",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansKannadaUI-VF.ttf",
+                "postScriptName": "NotoSansKannadaUI-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanskayahli/Android.bp b/notosanskayahli/Android.bp
index 1d7b5f0..b066a13 100644
--- a/notosanskayahli/Android.bp
+++ b/notosanskayahli/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansKayahLi-Regular.ttf",
     src: "NotoSansKayahLi-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansKayahLi",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansKayahLi-Regular.ttf",
+    ],
+}
diff --git a/notosanskayahli/font_config.json b/notosanskayahli/font_config.json
new file mode 100644
index 0000000..e39439c
--- /dev/null
+++ b/notosanskayahli/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Kali",
+        "fonts": [
+            {
+                "file": "NotoSansKayahLi-Regular.ttf",
+                "postScriptName": "NotoSansKayahLi",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanskharoshthi/Android.bp b/notosanskharoshthi/Android.bp
index 1d3270c..baa77be 100644
--- a/notosanskharoshthi/Android.bp
+++ b/notosanskharoshthi/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansKharoshthi-Regular.ttf",
     src: "NotoSansKharoshthi-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansKharoshthi",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansKharoshthi-Regular.ttf",
+    ],
+}
diff --git a/notosanskharoshthi/font_config.json b/notosanskharoshthi/font_config.json
new file mode 100644
index 0000000..7665ad7
--- /dev/null
+++ b/notosanskharoshthi/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Khar",
+        "fonts": [
+            {
+                "file": "NotoSansKharoshthi-Regular.ttf",
+                "postScriptName": "NotoSansKharoshthi",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanskhmer/Android.bp b/notosanskhmer/Android.bp
index d61d2e3..835fc75 100644
--- a/notosanskhmer/Android.bp
+++ b/notosanskhmer/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansKhmer-VF.ttf",
     src: "NotoSansKhmer-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansKhmer-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansKhmer-VF.ttf",
+    ],
+}
diff --git a/notosanskhmer/font_config.json b/notosanskhmer/font_config.json
new file mode 100644
index 0000000..dfe07ad
--- /dev/null
+++ b/notosanskhmer/font_config.json
@@ -0,0 +1,99 @@
+[
+    {
+        "lang": "und-Khmr",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansKhmer-VF.ttf",
+                "postScriptName": "NotoSansKhmer-Regular",
+                "weight": "100",
+                "style": "normal",
+                "axes": {
+                    "wdth": "100.0",
+                    "wght": "26.0"
+                }
+            },
+            {
+                "file": "NotoSansKhmer-VF.ttf",
+                "postScriptName": "NotoSansKhmer-Regular",
+                "weight": "200",
+                "style": "normal",
+                "axes": {
+                    "wdth": "100.0",
+                    "wght": "39.0"
+                }
+            },
+            {
+                "file": "NotoSansKhmer-VF.ttf",
+                "postScriptName": "NotoSansKhmer-Regular",
+                "weight": "300",
+                "style": "normal",
+                "axes": {
+                    "wdth": "100.0",
+                    "wght": "58.0"
+                }
+            },
+            {
+                "file": "NotoSansKhmer-VF.ttf",
+                "postScriptName": "NotoSansKhmer-Regular",
+                "weight": "400",
+                "style": "normal",
+                "axes": {
+                    "wdth": "100.0",
+                    "wght": "90.0"
+                }
+            },
+            {
+                "file": "NotoSansKhmer-VF.ttf",
+                "postScriptName": "NotoSansKhmer-Regular",
+                "weight": "500",
+                "style": "normal",
+                "axes": {
+                    "wdth": "100.0",
+                    "wght": "108.0"
+                }
+            },
+            {
+                "file": "NotoSansKhmer-VF.ttf",
+                "postScriptName": "NotoSansKhmer-Regular",
+                "weight": "600",
+                "style": "normal",
+                "axes": {
+                    "wdth": "100.0",
+                    "wght": "128.0"
+                }
+            },
+            {
+                "file": "NotoSansKhmer-VF.ttf",
+                "postScriptName": "NotoSansKhmer-Regular",
+                "weight": "700",
+                "style": "normal",
+                "axes": {
+                    "wdth": "100.0",
+                    "wght": "151.0"
+                }
+            },
+            {
+                "file": "NotoSansKhmer-VF.ttf",
+                "postScriptName": "NotoSansKhmer-Regular",
+                "weight": "800",
+                "style": "normal",
+                "axes": {
+                    "wdth": "100.0",
+                    "wght": "169.0"
+                }
+            },
+            {
+                "file": "NotoSansKhmer-VF.ttf",
+                "postScriptName": "NotoSansKhmer-Regular",
+                "weight": "900",
+                "style": "normal",
+                "axes": {
+                    "wdth": "100.0",
+                    "wght": "190.0"
+                }
+            }
+        ],
+        "id": "NotoSansKhmer-VF_und-Khmr"
+    }
+]
\ No newline at end of file
diff --git a/notosanskhmerui/Android.bp b/notosanskhmerui/Android.bp
index 5b95571..2a79191 100644
--- a/notosanskhmerui/Android.bp
+++ b/notosanskhmerui/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSansKhmerUI-Bold.ttf",
     src: "NotoSansKhmerUI-Bold.ttf",
 }
+
+filegroup {
+    name: "NotoSansKhmerUI",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansKhmerUI-Bold.ttf",
+        "NotoSansKhmerUI-Regular.ttf",
+    ],
+}
diff --git a/notosanskhmerui/font_config.json b/notosanskhmerui/font_config.json
new file mode 100644
index 0000000..d9d7e3e
--- /dev/null
+++ b/notosanskhmerui/font_config.json
@@ -0,0 +1,19 @@
+[
+    {
+        "lang": "und-Khmr",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansKhmerUI-Regular.ttf",
+                "postScriptName": "NotoSansKhmerUI",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansKhmerUI-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanskhojki/Android.bp b/notosanskhojki/Android.bp
index 2487b38..7b264a1 100644
--- a/notosanskhojki/Android.bp
+++ b/notosanskhojki/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansKhojki-Regular.otf",
     src: "NotoSansKhojki-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansKhojki",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansKhojki-Regular.otf",
+    ],
+}
diff --git a/notosanskhojki/font_config.json b/notosanskhojki/font_config.json
new file mode 100644
index 0000000..a829704
--- /dev/null
+++ b/notosanskhojki/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Khoj",
+        "fonts": [
+            {
+                "file": "NotoSansKhojki-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanslao/Android.bp b/notosanslao/Android.bp
index bde22f2..06b1e80 100644
--- a/notosanslao/Android.bp
+++ b/notosanslao/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSansLao-Regular.ttf",
     src: "NotoSansLao-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansLao",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansLao-Regular.ttf",
+        "NotoSansLao-Bold.ttf",
+    ],
+}
diff --git a/notosanslao/font_config.json b/notosanslao/font_config.json
new file mode 100644
index 0000000..2ee1f8b
--- /dev/null
+++ b/notosanslao/font_config.json
@@ -0,0 +1,19 @@
+[
+    {
+        "lang": "und-Laoo",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansLao-Regular.ttf",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansLao-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ],
+        "id": "NotoSansLao_und-Laoo"
+    }
+]
\ No newline at end of file
diff --git a/notosanslaoui/Android.bp b/notosanslaoui/Android.bp
index 36748ef..d68e966 100644
--- a/notosanslaoui/Android.bp
+++ b/notosanslaoui/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSansLaoUI-Regular.ttf",
     src: "NotoSansLaoUI-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansLaoUI",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansLaoUI-Bold.ttf",
+        "NotoSansLaoUI-Regular.ttf",
+    ],
+}
diff --git a/notosanslaoui/font_config.json b/notosanslaoui/font_config.json
new file mode 100644
index 0000000..3986186
--- /dev/null
+++ b/notosanslaoui/font_config.json
@@ -0,0 +1,19 @@
+[
+    {
+        "lang": "und-Laoo",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansLaoUI-Regular.ttf",
+                "postScriptName": "NotoSansLaoUI",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansLaoUI-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanslepcha/Android.bp b/notosanslepcha/Android.bp
index 943d3a5..e51a9fb 100644
--- a/notosanslepcha/Android.bp
+++ b/notosanslepcha/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansLepcha-Regular.ttf",
     src: "NotoSansLepcha-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansLepcha",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansLepcha-Regular.ttf",
+    ],
+}
diff --git a/notosanslepcha/font_config.json b/notosanslepcha/font_config.json
new file mode 100644
index 0000000..026c0e7
--- /dev/null
+++ b/notosanslepcha/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Lepc",
+        "fonts": [
+            {
+                "file": "NotoSansLepcha-Regular.ttf",
+                "postScriptName": "NotoSansLepcha",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanslimbu/Android.bp b/notosanslimbu/Android.bp
index 3e70c80..dbca204 100644
--- a/notosanslimbu/Android.bp
+++ b/notosanslimbu/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansLimbu-Regular.ttf",
     src: "NotoSansLimbu-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansLimbu",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansLimbu-Regular.ttf",
+    ],
+}
diff --git a/notosanslimbu/font_config.json b/notosanslimbu/font_config.json
new file mode 100644
index 0000000..ae312d8
--- /dev/null
+++ b/notosanslimbu/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Limb",
+        "fonts": [
+            {
+                "file": "NotoSansLimbu-Regular.ttf",
+                "postScriptName": "NotoSansLimbu",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanslineara/Android.bp b/notosanslineara/Android.bp
index 1b069db..ab98f39 100644
--- a/notosanslineara/Android.bp
+++ b/notosanslineara/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansLinearA-Regular.otf",
     src: "NotoSansLinearA-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansLinearA",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansLinearA-Regular.otf",
+    ],
+}
diff --git a/notosanslineara/font_config.json b/notosanslineara/font_config.json
new file mode 100644
index 0000000..b52837d
--- /dev/null
+++ b/notosanslineara/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Lina",
+        "fonts": [
+            {
+                "file": "NotoSansLinearA-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanslinearb/Android.bp b/notosanslinearb/Android.bp
index af55a06..6b76e8c 100644
--- a/notosanslinearb/Android.bp
+++ b/notosanslinearb/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansLinearB-Regular.ttf",
     src: "NotoSansLinearB-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansLinearB",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansLinearB-Regular.ttf",
+    ],
+}
diff --git a/notosanslinearb/font_config.json b/notosanslinearb/font_config.json
new file mode 100644
index 0000000..4089948
--- /dev/null
+++ b/notosanslinearb/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Linb",
+        "fonts": [
+            {
+                "file": "NotoSansLinearB-Regular.ttf",
+                "postScriptName": "NotoSansLinearB",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanslisu/Android.bp b/notosanslisu/Android.bp
index 53792ef..7d5bbb4 100644
--- a/notosanslisu/Android.bp
+++ b/notosanslisu/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansLisu-Regular.ttf",
     src: "NotoSansLisu-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansLisu",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansLisu-Regular.ttf",
+    ],
+}
diff --git a/notosanslisu/font_config.json b/notosanslisu/font_config.json
new file mode 100644
index 0000000..da8c159
--- /dev/null
+++ b/notosanslisu/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Lisu",
+        "fonts": [
+            {
+                "file": "NotoSansLisu-Regular.ttf",
+                "postScriptName": "NotoSansLisu",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanslycian/Android.bp b/notosanslycian/Android.bp
index 68510e5..86ead40 100644
--- a/notosanslycian/Android.bp
+++ b/notosanslycian/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansLycian-Regular.ttf",
     src: "NotoSansLycian-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansLycian",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansLycian-Regular.ttf",
+    ],
+}
diff --git a/notosanslycian/font_config.json b/notosanslycian/font_config.json
new file mode 100644
index 0000000..8af501a
--- /dev/null
+++ b/notosanslycian/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Lyci",
+        "fonts": [
+            {
+                "file": "NotoSansLycian-Regular.ttf",
+                "postScriptName": "NotoSansLycian",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanslydian/Android.bp b/notosanslydian/Android.bp
index f0cb055..a9eef9f 100644
--- a/notosanslydian/Android.bp
+++ b/notosanslydian/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansLydian-Regular.ttf",
     src: "NotoSansLydian-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansLydian",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansLydian-Regular.ttf",
+    ],
+}
diff --git a/notosanslydian/font_config.json b/notosanslydian/font_config.json
new file mode 100644
index 0000000..48e27e0
--- /dev/null
+++ b/notosanslydian/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Lydi",
+        "fonts": [
+            {
+                "file": "NotoSansLydian-Regular.ttf",
+                "postScriptName": "NotoSansLydian",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmalayalam/Android.bp b/notosansmalayalam/Android.bp
index 016fb3d..27235e4 100644
--- a/notosansmalayalam/Android.bp
+++ b/notosansmalayalam/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansMalayalam-VF.ttf",
     src: "NotoSansMalayalam-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansMalayalam-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMalayalam-VF.ttf",
+    ],
+}
diff --git a/notosansmalayalam/font_config.json b/notosansmalayalam/font_config.json
new file mode 100644
index 0000000..361115e
--- /dev/null
+++ b/notosansmalayalam/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Mlym",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansMalayalam-VF.ttf",
+                "postScriptName": "NotoSansMalayalam-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "id": "NotoSansMalayalam-VF_und-Mlym"
+    }
+]
\ No newline at end of file
diff --git a/notosansmalayalamui/Android.bp b/notosansmalayalamui/Android.bp
index 8f8dd62..c0e7876 100644
--- a/notosansmalayalamui/Android.bp
+++ b/notosansmalayalamui/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansMalayalamUI-VF.ttf",
     src: "NotoSansMalayalamUI-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansMalayalamUI-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMalayalamUI-VF.ttf",
+    ],
+}
diff --git a/notosansmalayalamui/font_config.json b/notosansmalayalamui/font_config.json
new file mode 100644
index 0000000..7252f6f
--- /dev/null
+++ b/notosansmalayalamui/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Mlym",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansMalayalamUI-VF.ttf",
+                "postScriptName": "NotoSansMalayalamUI-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmandaic/Android.bp b/notosansmandaic/Android.bp
index 1143a58..8c183e9 100644
--- a/notosansmandaic/Android.bp
+++ b/notosansmandaic/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansMandaic-Regular.ttf",
     src: "NotoSansMandaic-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansMandaic",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMandaic-Regular.ttf",
+    ],
+}
diff --git a/notosansmandaic/font_config.json b/notosansmandaic/font_config.json
new file mode 100644
index 0000000..46e179f
--- /dev/null
+++ b/notosansmandaic/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Mand",
+        "fonts": [
+            {
+                "file": "NotoSansMandaic-Regular.ttf",
+                "postScriptName": "NotoSansMandaic",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmanichaean/Android.bp b/notosansmanichaean/Android.bp
index 799cd9c..04f14d8 100644
--- a/notosansmanichaean/Android.bp
+++ b/notosansmanichaean/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansManichaean-Regular.otf",
     src: "NotoSansManichaean-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansManichaean",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansManichaean-Regular.otf",
+    ],
+}
diff --git a/notosansmanichaean/font_config.json b/notosansmanichaean/font_config.json
new file mode 100644
index 0000000..e7471b6
--- /dev/null
+++ b/notosansmanichaean/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Mani",
+        "fonts": [
+            {
+                "file": "NotoSansManichaean-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmarchen/Android.bp b/notosansmarchen/Android.bp
index 52a50c4..3a8848b 100644
--- a/notosansmarchen/Android.bp
+++ b/notosansmarchen/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansMarchen-Regular.otf",
     src: "NotoSansMarchen-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansMarchen",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMarchen-Regular.otf",
+    ],
+}
diff --git a/notosansmarchen/font_config.json b/notosansmarchen/font_config.json
new file mode 100644
index 0000000..1a2df2b
--- /dev/null
+++ b/notosansmarchen/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Marc",
+        "fonts": [
+            {
+                "file": "NotoSansMarchen-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmasaramgondi/Android.bp b/notosansmasaramgondi/Android.bp
index d26d64b..cdeaf94 100644
--- a/notosansmasaramgondi/Android.bp
+++ b/notosansmasaramgondi/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansMasaramGondi-Regular.otf",
     src: "NotoSansMasaramGondi-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansMasaramGondi",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMasaramGondi-Regular.otf",
+    ],
+}
diff --git a/notosansmasaramgondi/font_config.json b/notosansmasaramgondi/font_config.json
new file mode 100644
index 0000000..3537fba
--- /dev/null
+++ b/notosansmasaramgondi/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Gonm",
+        "fonts": [
+            {
+                "file": "NotoSansMasaramGondi-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmedefaidrin/Android.bp b/notosansmedefaidrin/Android.bp
index a2ee832..0255831 100644
--- a/notosansmedefaidrin/Android.bp
+++ b/notosansmedefaidrin/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansMedefaidrin-VF.ttf",
     src: "NotoSansMedefaidrin-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansMedefaidrin-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMedefaidrin-VF.ttf",
+    ],
+}
diff --git a/notosansmedefaidrin/font_config.json b/notosansmedefaidrin/font_config.json
new file mode 100644
index 0000000..1861aff
--- /dev/null
+++ b/notosansmedefaidrin/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Medf",
+        "fonts": [
+            {
+                "file": "NotoSansMedefaidrin-VF.ttf",
+                "postScriptName": "NotoSansMedefaidrin-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmeeteimayek/Android.bp b/notosansmeeteimayek/Android.bp
index 268de7f..5b62108 100644
--- a/notosansmeeteimayek/Android.bp
+++ b/notosansmeeteimayek/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansMeeteiMayek-Regular.ttf",
     src: "NotoSansMeeteiMayek-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansMeeteiMayek",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMeeteiMayek-Regular.ttf",
+    ],
+}
diff --git a/notosansmeeteimayek/font_config.json b/notosansmeeteimayek/font_config.json
new file mode 100644
index 0000000..6efcd9e
--- /dev/null
+++ b/notosansmeeteimayek/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Mtei",
+        "fonts": [
+            {
+                "file": "NotoSansMeeteiMayek-Regular.ttf",
+                "postScriptName": "NotoSansMeeteiMayek",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmeroitic/Android.bp b/notosansmeroitic/Android.bp
index 87baaac..3f40402 100644
--- a/notosansmeroitic/Android.bp
+++ b/notosansmeroitic/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansMeroitic-Regular.otf",
     src: "NotoSansMeroitic-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansMeroitic",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMeroitic-Regular.otf",
+    ],
+}
diff --git a/notosansmeroitic/font_config.json b/notosansmeroitic/font_config.json
new file mode 100644
index 0000000..479e71a
--- /dev/null
+++ b/notosansmeroitic/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Merc",
+        "fonts": [
+            {
+                "file": "NotoSansMeroitic-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmiao/Android.bp b/notosansmiao/Android.bp
index b9a741f..55238a7 100644
--- a/notosansmiao/Android.bp
+++ b/notosansmiao/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansMiao-Regular.otf",
     src: "NotoSansMiao-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansMiao",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMiao-Regular.otf",
+    ],
+}
diff --git a/notosansmiao/font_config.json b/notosansmiao/font_config.json
new file mode 100644
index 0000000..b4c5c58
--- /dev/null
+++ b/notosansmiao/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Plrd",
+        "fonts": [
+            {
+                "file": "NotoSansMiao-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmodi/Android.bp b/notosansmodi/Android.bp
index d5612e0..190355b 100644
--- a/notosansmodi/Android.bp
+++ b/notosansmodi/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansModi-Regular.ttf",
     src: "NotoSansModi-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansModi",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansModi-Regular.ttf",
+    ],
+}
diff --git a/notosansmodi/font_config.json b/notosansmodi/font_config.json
new file mode 100644
index 0000000..652ddde
--- /dev/null
+++ b/notosansmodi/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Modi",
+        "fonts": [
+            {
+                "file": "NotoSansModi-Regular.ttf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmongolian/Android.bp b/notosansmongolian/Android.bp
index 72b09a1..9a042c5 100644
--- a/notosansmongolian/Android.bp
+++ b/notosansmongolian/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansMongolian-Regular.ttf",
     src: "NotoSansMongolian-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansMongolian",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMongolian-Regular.ttf",
+    ],
+}
diff --git a/notosansmongolian/font_config.json b/notosansmongolian/font_config.json
new file mode 100644
index 0000000..482dec0
--- /dev/null
+++ b/notosansmongolian/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Mong",
+        "fonts": [
+            {
+                "file": "NotoSansMongolian-Regular.ttf",
+                "postScriptName": "NotoSansMongolian",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmro/Android.bp b/notosansmro/Android.bp
index 786c48e..69bcd40 100644
--- a/notosansmro/Android.bp
+++ b/notosansmro/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansMro-Regular.otf",
     src: "NotoSansMro-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansMro",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMro-Regular.otf",
+    ],
+}
diff --git a/notosansmro/font_config.json b/notosansmro/font_config.json
new file mode 100644
index 0000000..99daeb5
--- /dev/null
+++ b/notosansmro/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Mroo",
+        "fonts": [
+            {
+                "file": "NotoSansMro-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmultani/Android.bp b/notosansmultani/Android.bp
index 6047166..bddaa21 100644
--- a/notosansmultani/Android.bp
+++ b/notosansmultani/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansMultani-Regular.otf",
     src: "NotoSansMultani-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansMultani",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMultani-Regular.otf",
+    ],
+}
diff --git a/notosansmultani/font_config.json b/notosansmultani/font_config.json
new file mode 100644
index 0000000..e44546d
--- /dev/null
+++ b/notosansmultani/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Mult",
+        "fonts": [
+            {
+                "file": "NotoSansMultani-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansmyanmar/Android.bp b/notosansmyanmar/Android.bp
index 9da4ae9..baeb090 100644
--- a/notosansmyanmar/Android.bp
+++ b/notosansmyanmar/Android.bp
@@ -59,3 +59,13 @@ prebuilt_font {
     name: "NotoSansMyanmar-Bold.otf",
     src: "NotoSansMyanmar-Bold.otf",
 }
+
+filegroup {
+    name: "NotoSansMyanmar",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMyanmar-Regular.otf",
+        "NotoSansMyanmar-Medium.otf",
+        "NotoSansMyanmar-Bold.otf",
+    ],
+}
diff --git a/notosansmyanmar/font_config.json b/notosansmyanmar/font_config.json
new file mode 100644
index 0000000..b791bfa
--- /dev/null
+++ b/notosansmyanmar/font_config.json
@@ -0,0 +1,24 @@
+[
+    {
+        "lang": "und-Mymr",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansMyanmar-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansMyanmar-Medium.otf",
+                "weight": "500",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansMyanmar-Bold.otf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ],
+        "id": "NotoSansMyanmar_und-Mymr"
+    }
+]
\ No newline at end of file
diff --git a/notosansmyanmarui/Android.bp b/notosansmyanmarui/Android.bp
index cf1036d..3ee9253 100644
--- a/notosansmyanmarui/Android.bp
+++ b/notosansmyanmarui/Android.bp
@@ -59,3 +59,13 @@ prebuilt_font {
     name: "NotoSansMyanmarUI-Bold.otf",
     src: "NotoSansMyanmarUI-Bold.otf",
 }
+
+filegroup {
+    name: "NotoSansMyanmarUI",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansMyanmarUI-Medium.otf",
+        "NotoSansMyanmarUI-Regular.otf",
+        "NotoSansMyanmarUI-Bold.otf",
+    ],
+}
diff --git a/notosansmyanmarui/font_config.json b/notosansmyanmarui/font_config.json
new file mode 100644
index 0000000..8e7ff39
--- /dev/null
+++ b/notosansmyanmarui/font_config.json
@@ -0,0 +1,23 @@
+[
+    {
+        "lang": "und-Mymr",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansMyanmarUI-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansMyanmarUI-Medium.otf",
+                "weight": "500",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansMyanmarUI-Bold.otf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansnabataean/Android.bp b/notosansnabataean/Android.bp
index 5e46a5e..1e1f9ba 100644
--- a/notosansnabataean/Android.bp
+++ b/notosansnabataean/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansNabataean-Regular.otf",
     src: "NotoSansNabataean-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansNabataean",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansNabataean-Regular.otf",
+    ],
+}
diff --git a/notosansnabataean/font_config.json b/notosansnabataean/font_config.json
new file mode 100644
index 0000000..d8eb0b1
--- /dev/null
+++ b/notosansnabataean/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Nbat",
+        "fonts": [
+            {
+                "file": "NotoSansNabataean-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansnewa/Android.bp b/notosansnewa/Android.bp
index e3ff76b..f647fcd 100644
--- a/notosansnewa/Android.bp
+++ b/notosansnewa/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansNewa-Regular.otf",
     src: "NotoSansNewa-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansNewa",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansNewa-Regular.otf",
+    ],
+}
diff --git a/notosansnewa/font_config.json b/notosansnewa/font_config.json
new file mode 100644
index 0000000..f5eb397
--- /dev/null
+++ b/notosansnewa/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Newa",
+        "fonts": [
+            {
+                "file": "NotoSansNewa-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansnewtailue/Android.bp b/notosansnewtailue/Android.bp
index c6853f0..3fd024f 100644
--- a/notosansnewtailue/Android.bp
+++ b/notosansnewtailue/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansNewTaiLue-Regular.ttf",
     src: "NotoSansNewTaiLue-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansNewTaiLue",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansNewTaiLue-Regular.ttf",
+    ],
+}
diff --git a/notosansnewtailue/font_config.json b/notosansnewtailue/font_config.json
new file mode 100644
index 0000000..9e02ed5
--- /dev/null
+++ b/notosansnewtailue/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Talu",
+        "fonts": [
+            {
+                "file": "NotoSansNewTaiLue-Regular.ttf",
+                "postScriptName": "NotoSansNewTaiLue",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansnko_todelist/Android.bp b/notosansnko_todelist/Android.bp
index c55d315..f07f5f6 100644
--- a/notosansnko_todelist/Android.bp
+++ b/notosansnko_todelist/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansNKo-Regular.ttf",
     src: "NotoSansNKo-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansNKo",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansNKo-Regular.ttf",
+    ],
+}
diff --git a/notosansnko_todelist/font_config.json b/notosansnko_todelist/font_config.json
new file mode 100644
index 0000000..5ec7cad
--- /dev/null
+++ b/notosansnko_todelist/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Nkoo",
+        "fonts": [
+            {
+                "file": "NotoSansNKo-Regular.ttf",
+                "postScriptName": "NotoSansNKo",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansogham/Android.bp b/notosansogham/Android.bp
index 8b1d29d..8c5d218 100644
--- a/notosansogham/Android.bp
+++ b/notosansogham/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansOgham-Regular.ttf",
     src: "NotoSansOgham-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansOgham",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansOgham-Regular.ttf",
+    ],
+}
diff --git a/notosansogham/font_config.json b/notosansogham/font_config.json
new file mode 100644
index 0000000..a5a3a4a
--- /dev/null
+++ b/notosansogham/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Ogam",
+        "fonts": [
+            {
+                "file": "NotoSansOgham-Regular.ttf",
+                "postScriptName": "NotoSansOgham",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansolchiki/Android.bp b/notosansolchiki/Android.bp
index 4059337..2524148 100644
--- a/notosansolchiki/Android.bp
+++ b/notosansolchiki/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansOlChiki-Regular.ttf",
     src: "NotoSansOlChiki-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansOlChiki",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansOlChiki-Regular.ttf",
+    ],
+}
diff --git a/notosansolchiki/font_config.json b/notosansolchiki/font_config.json
new file mode 100644
index 0000000..f6cab1d
--- /dev/null
+++ b/notosansolchiki/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Olck",
+        "fonts": [
+            {
+                "file": "NotoSansOlChiki-Regular.ttf",
+                "postScriptName": "NotoSansOlChiki",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansolditalic/Android.bp b/notosansolditalic/Android.bp
index 59543d4..2f95fa2 100644
--- a/notosansolditalic/Android.bp
+++ b/notosansolditalic/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansOldItalic-Regular.ttf",
     src: "NotoSansOldItalic-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansOldItalic",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansOldItalic-Regular.ttf",
+    ],
+}
diff --git a/notosansolditalic/font_config.json b/notosansolditalic/font_config.json
new file mode 100644
index 0000000..c3c2bd8
--- /dev/null
+++ b/notosansolditalic/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Ital",
+        "fonts": [
+            {
+                "file": "NotoSansOldItalic-Regular.ttf",
+                "postScriptName": "NotoSansOldItalic",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansoldnortharabian/Android.bp b/notosansoldnortharabian/Android.bp
index 72eb35d..650f330 100644
--- a/notosansoldnortharabian/Android.bp
+++ b/notosansoldnortharabian/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansOldNorthArabian-Regular.otf",
     src: "NotoSansOldNorthArabian-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansOldNorthArabian",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansOldNorthArabian-Regular.otf",
+    ],
+}
diff --git a/notosansoldnortharabian/font_config.json b/notosansoldnortharabian/font_config.json
new file mode 100644
index 0000000..cce1754
--- /dev/null
+++ b/notosansoldnortharabian/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Narb",
+        "fonts": [
+            {
+                "file": "NotoSansOldNorthArabian-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansoldpermic/Android.bp b/notosansoldpermic/Android.bp
index 32fbd78..0b74fe0 100644
--- a/notosansoldpermic/Android.bp
+++ b/notosansoldpermic/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansOldPermic-Regular.otf",
     src: "NotoSansOldPermic-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansOldPermic",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansOldPermic-Regular.otf",
+    ],
+}
diff --git a/notosansoldpermic/font_config.json b/notosansoldpermic/font_config.json
new file mode 100644
index 0000000..ab0307c
--- /dev/null
+++ b/notosansoldpermic/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Perm",
+        "fonts": [
+            {
+                "file": "NotoSansOldPermic-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansoldpersian/Android.bp b/notosansoldpersian/Android.bp
index d65f374..9fb30e1 100644
--- a/notosansoldpersian/Android.bp
+++ b/notosansoldpersian/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansOldPersian-Regular.ttf",
     src: "NotoSansOldPersian-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansOldPersian",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansOldPersian-Regular.ttf",
+    ],
+}
diff --git a/notosansoldpersian/font_config.json b/notosansoldpersian/font_config.json
new file mode 100644
index 0000000..759f9d9
--- /dev/null
+++ b/notosansoldpersian/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Xpeo",
+        "fonts": [
+            {
+                "file": "NotoSansOldPersian-Regular.ttf",
+                "postScriptName": "NotoSansOldPersian",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansoldsoutharabian/Android.bp b/notosansoldsoutharabian/Android.bp
index f8bcd4c..9cd064e 100644
--- a/notosansoldsoutharabian/Android.bp
+++ b/notosansoldsoutharabian/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansOldSouthArabian-Regular.ttf",
     src: "NotoSansOldSouthArabian-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansOldSouthArabian",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansOldSouthArabian-Regular.ttf",
+    ],
+}
diff --git a/notosansoldsoutharabian/font_config.json b/notosansoldsoutharabian/font_config.json
new file mode 100644
index 0000000..aacbca9
--- /dev/null
+++ b/notosansoldsoutharabian/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Sarb",
+        "fonts": [
+            {
+                "file": "NotoSansOldSouthArabian-Regular.ttf",
+                "postScriptName": "NotoSansOldSouthArabian",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansoldturkic/Android.bp b/notosansoldturkic/Android.bp
index 0ac1398..5164152 100644
--- a/notosansoldturkic/Android.bp
+++ b/notosansoldturkic/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansOldTurkic-Regular.ttf",
     src: "NotoSansOldTurkic-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansOldTurkic",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansOldTurkic-Regular.ttf",
+    ],
+}
diff --git a/notosansoldturkic/font_config.json b/notosansoldturkic/font_config.json
new file mode 100644
index 0000000..ea58790
--- /dev/null
+++ b/notosansoldturkic/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Orkh",
+        "fonts": [
+            {
+                "file": "NotoSansOldTurkic-Regular.ttf",
+                "postScriptName": "NotoSansOldTurkic",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansoriya/Android.bp b/notosansoriya/Android.bp
index 7df4c5e..624f607 100644
--- a/notosansoriya/Android.bp
+++ b/notosansoriya/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSansOriya-Regular.ttf",
     src: "NotoSansOriya-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansOriya",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansOriya-Bold.ttf",
+        "NotoSansOriya-Regular.ttf",
+    ],
+}
diff --git a/notosansoriya/font_config.json b/notosansoriya/font_config.json
new file mode 100644
index 0000000..1e09083
--- /dev/null
+++ b/notosansoriya/font_config.json
@@ -0,0 +1,19 @@
+[
+    {
+        "lang": "und-Orya",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansOriya-Regular.ttf",
+                "postScriptName": "NotoSansOriya",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansOriya-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansoriyaui/Android.bp b/notosansoriyaui/Android.bp
index a6dfdd1..4c16e72 100644
--- a/notosansoriyaui/Android.bp
+++ b/notosansoriyaui/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSansOriyaUI-Bold.ttf",
     src: "NotoSansOriyaUI-Bold.ttf",
 }
+
+filegroup {
+    name: "NotoSansOriyaUI",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansOriyaUI-Regular.ttf",
+        "NotoSansOriyaUI-Bold.ttf",
+    ],
+}
diff --git a/notosansoriyaui/font_config.json b/notosansoriyaui/font_config.json
new file mode 100644
index 0000000..8526207
--- /dev/null
+++ b/notosansoriyaui/font_config.json
@@ -0,0 +1,19 @@
+[
+    {
+        "lang": "und-Orya",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansOriyaUI-Regular.ttf",
+                "postScriptName": "NotoSansOriyaUI",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansOriyaUI-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansosage/Android.bp b/notosansosage/Android.bp
index 189697f..8f5d6ef 100644
--- a/notosansosage/Android.bp
+++ b/notosansosage/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansOsage-Regular.ttf",
     src: "NotoSansOsage-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansOsage",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansOsage-Regular.ttf",
+    ],
+}
diff --git a/notosansosage/font_config.json b/notosansosage/font_config.json
new file mode 100644
index 0000000..163870a
--- /dev/null
+++ b/notosansosage/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Osge",
+        "fonts": [
+            {
+                "file": "NotoSansOsage-Regular.ttf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansosmanya/Android.bp b/notosansosmanya/Android.bp
index f81416f..4c0f838 100644
--- a/notosansosmanya/Android.bp
+++ b/notosansosmanya/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansOsmanya-Regular.ttf",
     src: "NotoSansOsmanya-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansOsmanya",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansOsmanya-Regular.ttf",
+    ],
+}
diff --git a/notosansosmanya/font_config.json b/notosansosmanya/font_config.json
new file mode 100644
index 0000000..76e9203
--- /dev/null
+++ b/notosansosmanya/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Osma",
+        "fonts": [
+            {
+                "file": "NotoSansOsmanya-Regular.ttf",
+                "postScriptName": "NotoSansOsmanya",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanspahawhhmong/Android.bp b/notosanspahawhhmong/Android.bp
index 045ce90..4295012 100644
--- a/notosanspahawhhmong/Android.bp
+++ b/notosanspahawhhmong/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansPahawhHmong-Regular.otf",
     src: "NotoSansPahawhHmong-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansPahawhHmong",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansPahawhHmong-Regular.otf",
+    ],
+}
diff --git a/notosanspahawhhmong/font_config.json b/notosanspahawhhmong/font_config.json
new file mode 100644
index 0000000..3341224
--- /dev/null
+++ b/notosanspahawhhmong/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Hmng",
+        "fonts": [
+            {
+                "file": "NotoSansPahawhHmong-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanspalmyrene/Android.bp b/notosanspalmyrene/Android.bp
index d8735b5..aa3f494 100644
--- a/notosanspalmyrene/Android.bp
+++ b/notosanspalmyrene/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansPalmyrene-Regular.otf",
     src: "NotoSansPalmyrene-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansPalmyrene",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansPalmyrene-Regular.otf",
+    ],
+}
diff --git a/notosanspalmyrene/font_config.json b/notosanspalmyrene/font_config.json
new file mode 100644
index 0000000..6828947
--- /dev/null
+++ b/notosanspalmyrene/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Palm",
+        "fonts": [
+            {
+                "file": "NotoSansPalmyrene-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanspaucinhau/Android.bp b/notosanspaucinhau/Android.bp
index e3b128a..4c21812 100644
--- a/notosanspaucinhau/Android.bp
+++ b/notosanspaucinhau/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansPauCinHau-Regular.otf",
     src: "NotoSansPauCinHau-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansPauCinHau",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansPauCinHau-Regular.otf",
+    ],
+}
diff --git a/notosanspaucinhau/font_config.json b/notosanspaucinhau/font_config.json
new file mode 100644
index 0000000..f9fc404
--- /dev/null
+++ b/notosanspaucinhau/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Pauc",
+        "fonts": [
+            {
+                "file": "NotoSansPauCinHau-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansphagspa/Android.bp b/notosansphagspa/Android.bp
index edfae74..df0c011 100644
--- a/notosansphagspa/Android.bp
+++ b/notosansphagspa/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansPhagsPa-Regular.ttf",
     src: "NotoSansPhagsPa-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansPhagsPa",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansPhagsPa-Regular.ttf",
+    ],
+}
diff --git a/notosansphagspa/font_config.json b/notosansphagspa/font_config.json
new file mode 100644
index 0000000..39e097f
--- /dev/null
+++ b/notosansphagspa/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Phag",
+        "fonts": [
+            {
+                "file": "NotoSansPhagsPa-Regular.ttf",
+                "postScriptName": "NotoSansPhagsPa",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansphoenician/Android.bp b/notosansphoenician/Android.bp
index 7aabf61..52f7d15 100644
--- a/notosansphoenician/Android.bp
+++ b/notosansphoenician/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansPhoenician-Regular.ttf",
     src: "NotoSansPhoenician-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansPhoenician",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansPhoenician-Regular.ttf",
+    ],
+}
diff --git a/notosansphoenician/font_config.json b/notosansphoenician/font_config.json
new file mode 100644
index 0000000..536afed
--- /dev/null
+++ b/notosansphoenician/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Phnx",
+        "fonts": [
+            {
+                "file": "NotoSansPhoenician-Regular.ttf",
+                "postScriptName": "NotoSansPhoenician",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansrejang/Android.bp b/notosansrejang/Android.bp
index cf0a470..807bbd5 100644
--- a/notosansrejang/Android.bp
+++ b/notosansrejang/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansRejang-Regular.ttf",
     src: "NotoSansRejang-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansRejang",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansRejang-Regular.ttf",
+    ],
+}
diff --git a/notosansrejang/font_config.json b/notosansrejang/font_config.json
new file mode 100644
index 0000000..15c5075
--- /dev/null
+++ b/notosansrejang/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Rjng",
+        "fonts": [
+            {
+                "file": "NotoSansRejang-Regular.ttf",
+                "postScriptName": "NotoSansRejang",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansrunic/Android.bp b/notosansrunic/Android.bp
index e438bb2..4aabc8d 100644
--- a/notosansrunic/Android.bp
+++ b/notosansrunic/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansRunic-Regular.ttf",
     src: "NotoSansRunic-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansRunic",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansRunic-Regular.ttf",
+    ],
+}
diff --git a/notosansrunic/font_config.json b/notosansrunic/font_config.json
new file mode 100644
index 0000000..5fe55c5
--- /dev/null
+++ b/notosansrunic/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Runr",
+        "fonts": [
+            {
+                "file": "NotoSansRunic-Regular.ttf",
+                "postScriptName": "NotoSansRunic",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanssamaritan/Android.bp b/notosanssamaritan/Android.bp
index d22529c..9d3a078 100644
--- a/notosanssamaritan/Android.bp
+++ b/notosanssamaritan/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansSamaritan-Regular.ttf",
     src: "NotoSansSamaritan-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansSamaritan",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansSamaritan-Regular.ttf",
+    ],
+}
diff --git a/notosanssamaritan/font_config.json b/notosanssamaritan/font_config.json
new file mode 100644
index 0000000..a126f15
--- /dev/null
+++ b/notosanssamaritan/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Samr",
+        "fonts": [
+            {
+                "file": "NotoSansSamaritan-Regular.ttf",
+                "postScriptName": "NotoSansSamaritan",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanssaurashtra/Android.bp b/notosanssaurashtra/Android.bp
index 1c70a9d..61aace6 100644
--- a/notosanssaurashtra/Android.bp
+++ b/notosanssaurashtra/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansSaurashtra-Regular.ttf",
     src: "NotoSansSaurashtra-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansSaurashtra",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansSaurashtra-Regular.ttf",
+    ],
+}
diff --git a/notosanssaurashtra/font_config.json b/notosanssaurashtra/font_config.json
new file mode 100644
index 0000000..297d00f
--- /dev/null
+++ b/notosanssaurashtra/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Saur",
+        "fonts": [
+            {
+                "file": "NotoSansSaurashtra-Regular.ttf",
+                "postScriptName": "NotoSansSaurashtra",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanssharada/Android.bp b/notosanssharada/Android.bp
index e842474..39f2e8b 100644
--- a/notosanssharada/Android.bp
+++ b/notosanssharada/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansSharada-Regular.otf",
     src: "NotoSansSharada-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansSharada",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansSharada-Regular.otf",
+    ],
+}
diff --git a/notosanssharada/font_config.json b/notosanssharada/font_config.json
new file mode 100644
index 0000000..9909da7
--- /dev/null
+++ b/notosanssharada/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Shrd",
+        "fonts": [
+            {
+                "file": "NotoSansSharada-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansshavian/Android.bp b/notosansshavian/Android.bp
index 4e74afb..c6e3c3c 100644
--- a/notosansshavian/Android.bp
+++ b/notosansshavian/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansShavian-Regular.ttf",
     src: "NotoSansShavian-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansShavian",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansShavian-Regular.ttf",
+    ],
+}
diff --git a/notosansshavian/font_config.json b/notosansshavian/font_config.json
new file mode 100644
index 0000000..b712058
--- /dev/null
+++ b/notosansshavian/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Shaw",
+        "fonts": [
+            {
+                "file": "NotoSansShavian-Regular.ttf",
+                "postScriptName": "NotoSansShavian",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanssinhala/Android.bp b/notosanssinhala/Android.bp
index 7c2b072..5a7da99 100644
--- a/notosanssinhala/Android.bp
+++ b/notosanssinhala/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansSinhala-VF.ttf",
     src: "NotoSansSinhala-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansSinhala-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansSinhala-VF.ttf",
+    ],
+}
diff --git a/notosanssinhala/font_config.json b/notosanssinhala/font_config.json
new file mode 100644
index 0000000..9b669e4
--- /dev/null
+++ b/notosanssinhala/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Sinh",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansSinhala-VF.ttf",
+                "postScriptName": "NotoSansSinhala-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "id": "NotoSansSinhala-VF_und-Sinh"
+    }
+]
\ No newline at end of file
diff --git a/notosanssinhalaui/Android.bp b/notosanssinhalaui/Android.bp
index 96dea15..9e8bb9d 100644
--- a/notosanssinhalaui/Android.bp
+++ b/notosanssinhalaui/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansSinhalaUI-VF.ttf",
     src: "NotoSansSinhalaUI-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansSinhalaUI-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansSinhalaUI-VF.ttf",
+    ],
+}
diff --git a/notosanssinhalaui/font_config.json b/notosanssinhalaui/font_config.json
new file mode 100644
index 0000000..5289291
--- /dev/null
+++ b/notosanssinhalaui/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Sinh",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansSinhalaUI-VF.ttf",
+                "postScriptName": "NotoSansSinhalaUI-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanssorasompeng/Android.bp b/notosanssorasompeng/Android.bp
index d10580e..fc5d75c 100644
--- a/notosanssorasompeng/Android.bp
+++ b/notosanssorasompeng/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansSoraSompeng-Regular.otf",
     src: "NotoSansSoraSompeng-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansSoraSompeng",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansSoraSompeng-Regular.otf",
+    ],
+}
diff --git a/notosanssorasompeng/font_config.json b/notosanssorasompeng/font_config.json
new file mode 100644
index 0000000..9860f95
--- /dev/null
+++ b/notosanssorasompeng/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Sora",
+        "fonts": [
+            {
+                "file": "NotoSansSoraSompeng-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanssoyombo/Android.bp b/notosanssoyombo/Android.bp
index 5d52948..314536b 100644
--- a/notosanssoyombo/Android.bp
+++ b/notosanssoyombo/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansSoyombo-VF.ttf",
     src: "NotoSansSoyombo-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansSoyombo-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansSoyombo-VF.ttf",
+    ],
+}
diff --git a/notosanssoyombo/font_config.json b/notosanssoyombo/font_config.json
new file mode 100644
index 0000000..973c6c6
--- /dev/null
+++ b/notosanssoyombo/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Soyo",
+        "fonts": [
+            {
+                "file": "NotoSansSoyombo-VF.ttf",
+                "postScriptName": "NotoSansSoyombo-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
diff --git a/notosanssundanese/Android.bp b/notosanssundanese/Android.bp
index 2842e31..a971fe1 100644
--- a/notosanssundanese/Android.bp
+++ b/notosanssundanese/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansSundanese-Regular.ttf",
     src: "NotoSansSundanese-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansSundanese",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansSundanese-Regular.ttf",
+    ],
+}
diff --git a/notosanssundanese/font_config.json b/notosanssundanese/font_config.json
new file mode 100644
index 0000000..3fcf84d
--- /dev/null
+++ b/notosanssundanese/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Sund",
+        "fonts": [
+            {
+                "file": "NotoSansSundanese-Regular.ttf",
+                "postScriptName": "NotoSansSundanese",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanssylotinagri/Android.bp b/notosanssylotinagri/Android.bp
index 9913b0a..756e32f 100644
--- a/notosanssylotinagri/Android.bp
+++ b/notosanssylotinagri/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansSylotiNagri-Regular.ttf",
     src: "NotoSansSylotiNagri-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansSylotiNagri",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansSylotiNagri-Regular.ttf",
+    ],
+}
diff --git a/notosanssylotinagri/font_config.json b/notosanssylotinagri/font_config.json
new file mode 100644
index 0000000..9d8effd
--- /dev/null
+++ b/notosanssylotinagri/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Sylo",
+        "fonts": [
+            {
+                "file": "NotoSansSylotiNagri-Regular.ttf",
+                "postScriptName": "NotoSansSylotiNagri",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanssymbols/Android.bp b/notosanssymbols/Android.bp
index f904644..69d01cd 100644
--- a/notosanssymbols/Android.bp
+++ b/notosanssymbols/Android.bp
@@ -59,3 +59,12 @@ prebuilt_font {
     name: "NotoSansSymbols-Regular-Subsetted2.ttf",
     src: "NotoSansSymbols-Regular-Subsetted2.ttf",
 }
+
+filegroup {
+    name: "NotoSansSymbols-Regular-Subsetted",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansSymbols-Regular-Subsetted2.ttf",
+        "NotoSansSymbols-Regular-Subsetted.ttf",
+    ],
+}
diff --git a/notosanssymbols/font_config.json b/notosanssymbols/font_config.json
new file mode 100644
index 0000000..869b0f4
--- /dev/null
+++ b/notosanssymbols/font_config.json
@@ -0,0 +1,22 @@
+[
+    {
+        "fonts": [
+            {
+                "file": "NotoSansSymbols-Regular-Subsetted.ttf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ],
+        "id": "NotoSansSymbols-Regular-Subsetted"
+    },
+    {
+        "lang": "und-Zsym",
+        "fonts": [
+            {
+                "file": "NotoSansSymbols-Regular-Subsetted2.ttf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
diff --git a/notosanssyriac/Android.bp b/notosanssyriac/Android.bp
index e918e4f..550a9b8 100644
--- a/notosanssyriac/Android.bp
+++ b/notosanssyriac/Android.bp
@@ -59,3 +59,13 @@ prebuilt_font {
     name: "NotoSansSyriacWestern-Regular.ttf",
     src: "NotoSansSyriacWestern-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansSyriac",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansSyriacEstrangela-Regular.ttf",
+        "NotoSansSyriacWestern-Regular.ttf",
+        "NotoSansSyriacEastern-Regular.ttf",
+    ],
+}
diff --git a/notosanssyriac/font_config.json b/notosanssyriac/font_config.json
new file mode 100644
index 0000000..b4c5692
--- /dev/null
+++ b/notosanssyriac/font_config.json
@@ -0,0 +1,35 @@
+[
+    {
+        "lang": "und-Syre",
+        "fonts": [
+            {
+                "file": "NotoSansSyriacEstrangela-Regular.ttf",
+                "postScriptName": "NotoSansSyriacEstrangela",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    },
+    {
+        "lang": "und-Syrn",
+        "fonts": [
+            {
+                "file": "NotoSansSyriacEastern-Regular.ttf",
+                "postScriptName": "NotoSansSyriacEastern",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    },
+    {
+        "lang": "und-Syrj",
+        "fonts": [
+            {
+                "file": "NotoSansSyriacWestern-Regular.ttf",
+                "postScriptName": "NotoSansSyriacWestern",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanstagalog/Android.bp b/notosanstagalog/Android.bp
index b058afe..4dda6d2 100644
--- a/notosanstagalog/Android.bp
+++ b/notosanstagalog/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansTagalog-Regular.ttf",
     src: "NotoSansTagalog-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansTagalog",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansTagalog-Regular.ttf",
+    ],
+}
diff --git a/notosanstagalog/font_config.json b/notosanstagalog/font_config.json
new file mode 100644
index 0000000..57e7889
--- /dev/null
+++ b/notosanstagalog/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Tglg",
+        "fonts": [
+            {
+                "file": "NotoSansTagalog-Regular.ttf",
+                "postScriptName": "NotoSansTagalog",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanstagbanwa/Android.bp b/notosanstagbanwa/Android.bp
index 1976e11..abeee3e 100644
--- a/notosanstagbanwa/Android.bp
+++ b/notosanstagbanwa/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansTagbanwa-Regular.ttf",
     src: "NotoSansTagbanwa-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansTagbanwa",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansTagbanwa-Regular.ttf",
+    ],
+}
diff --git a/notosanstagbanwa/font_config.json b/notosanstagbanwa/font_config.json
new file mode 100644
index 0000000..7c850cc
--- /dev/null
+++ b/notosanstagbanwa/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Tagb",
+        "fonts": [
+            {
+                "file": "NotoSansTagbanwa-Regular.ttf",
+                "postScriptName": "NotoSansTagbanwa",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanstaile/Android.bp b/notosanstaile/Android.bp
index 9ec3b42..8af0b84 100644
--- a/notosanstaile/Android.bp
+++ b/notosanstaile/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansTaiLe-Regular.ttf",
     src: "NotoSansTaiLe-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansTaiLe",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansTaiLe-Regular.ttf",
+    ],
+}
diff --git a/notosanstaile/font_config.json b/notosanstaile/font_config.json
new file mode 100644
index 0000000..bbd7173
--- /dev/null
+++ b/notosanstaile/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Tale",
+        "fonts": [
+            {
+                "file": "NotoSansTaiLe-Regular.ttf",
+                "postScriptName": "NotoSansTaiLe",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanstaitham/Android.bp b/notosanstaitham/Android.bp
index c2d9eb5..3ea915c 100644
--- a/notosanstaitham/Android.bp
+++ b/notosanstaitham/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansTaiTham-Regular.ttf",
     src: "NotoSansTaiTham-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansTaiTham",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansTaiTham-Regular.ttf",
+    ],
+}
diff --git a/notosanstaitham/font_config.json b/notosanstaitham/font_config.json
new file mode 100644
index 0000000..080a12c
--- /dev/null
+++ b/notosanstaitham/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Lana",
+        "fonts": [
+            {
+                "file": "NotoSansTaiTham-Regular.ttf",
+                "postScriptName": "NotoSansTaiTham",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanstaiviet/Android.bp b/notosanstaiviet/Android.bp
index cc81c51..4baf888 100644
--- a/notosanstaiviet/Android.bp
+++ b/notosanstaiviet/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansTaiViet-Regular.ttf",
     src: "NotoSansTaiViet-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansTaiViet",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansTaiViet-Regular.ttf",
+    ],
+}
diff --git a/notosanstaiviet/font_config.json b/notosanstaiviet/font_config.json
new file mode 100644
index 0000000..a030a27
--- /dev/null
+++ b/notosanstaiviet/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Tavt",
+        "fonts": [
+            {
+                "file": "NotoSansTaiViet-Regular.ttf",
+                "postScriptName": "NotoSansTaiViet",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanstakri/Android.bp b/notosanstakri/Android.bp
index c8794c5..c9b0ea6 100644
--- a/notosanstakri/Android.bp
+++ b/notosanstakri/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansTakri-VF.ttf",
     src: "NotoSansTakri-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansTakri-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansTakri-VF.ttf",
+    ],
+}
diff --git a/notosanstakri/font_config.json b/notosanstakri/font_config.json
new file mode 100644
index 0000000..d95899a
--- /dev/null
+++ b/notosanstakri/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Takr",
+        "fonts": [
+            {
+                "file": "NotoSansTakri-VF.ttf",
+                "postScriptName": "NotoSansTakri-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
diff --git a/notosanstamil/Android.bp b/notosanstamil/Android.bp
index 237a158..f8a643b 100644
--- a/notosanstamil/Android.bp
+++ b/notosanstamil/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansTamil-VF.ttf",
     src: "NotoSansTamil-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansTamil-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansTamil-VF.ttf",
+    ],
+}
diff --git a/notosanstamil/font_config.json b/notosanstamil/font_config.json
new file mode 100644
index 0000000..b011a8c
--- /dev/null
+++ b/notosanstamil/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Taml",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansTamil-VF.ttf",
+                "postScriptName": "NotoSansTamil-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "id": "NotoSansTamil-VF_und-Taml"
+    }
+]
\ No newline at end of file
diff --git a/notosanstamilui/Android.bp b/notosanstamilui/Android.bp
index 915fda7..2b5fe6d 100644
--- a/notosanstamilui/Android.bp
+++ b/notosanstamilui/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansTamilUI-VF.ttf",
     src: "NotoSansTamilUI-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansTamilUI-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansTamilUI-VF.ttf",
+    ],
+}
diff --git a/notosanstamilui/font_config.json b/notosanstamilui/font_config.json
new file mode 100644
index 0000000..0003107
--- /dev/null
+++ b/notosanstamilui/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Taml",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansTamilUI-VF.ttf",
+                "postScriptName": "NotoSansTamilUI-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanstelugu/Android.bp b/notosanstelugu/Android.bp
index f0c96b6..8abdb3e 100644
--- a/notosanstelugu/Android.bp
+++ b/notosanstelugu/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansTelugu-VF.ttf",
     src: "NotoSansTelugu-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansTelugu-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansTelugu-VF.ttf",
+    ],
+}
diff --git a/notosanstelugu/font_config.json b/notosanstelugu/font_config.json
new file mode 100644
index 0000000..6f8c172
--- /dev/null
+++ b/notosanstelugu/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Telu",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansTelugu-VF.ttf",
+                "postScriptName": "NotoSansTelugu-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "id": "NotoSansTelugu-VF_und-Telu"
+    }
+]
\ No newline at end of file
diff --git a/notosansteluguui/Android.bp b/notosansteluguui/Android.bp
index d40c255..42e77b2 100644
--- a/notosansteluguui/Android.bp
+++ b/notosansteluguui/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansTeluguUI-VF.ttf",
     src: "NotoSansTeluguUI-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSansTeluguUI-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansTeluguUI-VF.ttf",
+    ],
+}
diff --git a/notosansteluguui/font_config.json b/notosansteluguui/font_config.json
new file mode 100644
index 0000000..6fbc7b6
--- /dev/null
+++ b/notosansteluguui/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Telu",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansTeluguUI-VF.ttf",
+                "postScriptName": "NotoSansTeluguUI-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansthaana/Android.bp b/notosansthaana/Android.bp
index 91ad391..d276c69 100644
--- a/notosansthaana/Android.bp
+++ b/notosansthaana/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSansThaana-Bold.ttf",
     src: "NotoSansThaana-Bold.ttf",
 }
+
+filegroup {
+    name: "NotoSansThaana",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansThaana-Regular.ttf",
+        "NotoSansThaana-Bold.ttf",
+    ],
+}
diff --git a/notosansthaana/font_config.json b/notosansthaana/font_config.json
new file mode 100644
index 0000000..79be3b3
--- /dev/null
+++ b/notosansthaana/font_config.json
@@ -0,0 +1,18 @@
+[
+    {
+        "lang": "und-Thaa",
+        "fonts": [
+            {
+                "file": "NotoSansThaana-Regular.ttf",
+                "postScriptName": "NotoSansThaana",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansThaana-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansthai/Android.bp b/notosansthai/Android.bp
index ae19e18..4da0b42 100644
--- a/notosansthai/Android.bp
+++ b/notosansthai/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSansThai-Bold.ttf",
     src: "NotoSansThai-Bold.ttf",
 }
+
+filegroup {
+    name: "NotoSansThai",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansThai-Regular.ttf",
+        "NotoSansThai-Bold.ttf",
+    ],
+}
diff --git a/notosansthai/font_config.json b/notosansthai/font_config.json
new file mode 100644
index 0000000..e255932
--- /dev/null
+++ b/notosansthai/font_config.json
@@ -0,0 +1,20 @@
+[
+    {
+        "lang": "und-Thai",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSansThai-Regular.ttf",
+                "postScriptName": "NotoSansThai",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansThai-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ],
+        "id": "NotoSansThai_und-Thai"
+    }
+]
\ No newline at end of file
diff --git a/notosansthaiui/Android.bp b/notosansthaiui/Android.bp
index ce572d8..1cab262 100644
--- a/notosansthaiui/Android.bp
+++ b/notosansthaiui/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSansThaiUI-Bold.ttf",
     src: "NotoSansThaiUI-Bold.ttf",
 }
+
+filegroup {
+    name: "NotoSansThaiUI",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansThaiUI-Regular.ttf",
+        "NotoSansThaiUI-Bold.ttf",
+    ],
+}
diff --git a/notosansthaiui/font_config.json b/notosansthaiui/font_config.json
new file mode 100644
index 0000000..e3e5581
--- /dev/null
+++ b/notosansthaiui/font_config.json
@@ -0,0 +1,19 @@
+[
+    {
+        "lang": "und-Thai",
+        "variant": "compact",
+        "fonts": [
+            {
+                "file": "NotoSansThaiUI-Regular.ttf",
+                "postScriptName": "NotoSansThaiUI",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSansThaiUI-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanstifinagh/Android.bp b/notosanstifinagh/Android.bp
index 8153f38..85bd9ba 100644
--- a/notosanstifinagh/Android.bp
+++ b/notosanstifinagh/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansTifinagh-Regular.otf",
     src: "NotoSansTifinagh-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansTifinagh",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansTifinagh-Regular.otf",
+    ],
+}
diff --git a/notosanstifinagh/font_config.json b/notosanstifinagh/font_config.json
new file mode 100644
index 0000000..d8ffb25
--- /dev/null
+++ b/notosanstifinagh/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Tfng",
+        "fonts": [
+            {
+                "file": "NotoSansTifinagh-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansugaritic/Android.bp b/notosansugaritic/Android.bp
index 44fea2f..0862c59 100644
--- a/notosansugaritic/Android.bp
+++ b/notosansugaritic/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansUgaritic-Regular.ttf",
     src: "NotoSansUgaritic-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansUgaritic",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansUgaritic-Regular.ttf",
+    ],
+}
diff --git a/notosansugaritic/font_config.json b/notosansugaritic/font_config.json
new file mode 100644
index 0000000..0cc0002
--- /dev/null
+++ b/notosansugaritic/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Ugar",
+        "fonts": [
+            {
+                "file": "NotoSansUgaritic-Regular.ttf",
+                "postScriptName": "NotoSansUgaritic",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansvai/Android.bp b/notosansvai/Android.bp
index 2c5cac9..178ea27 100644
--- a/notosansvai/Android.bp
+++ b/notosansvai/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansVai-Regular.ttf",
     src: "NotoSansVai-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansVai",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansVai-Regular.ttf",
+    ],
+}
diff --git a/notosansvai/font_config.json b/notosansvai/font_config.json
new file mode 100644
index 0000000..0c823dc
--- /dev/null
+++ b/notosansvai/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Vaii",
+        "fonts": [
+            {
+                "file": "NotoSansVai-Regular.ttf",
+                "postScriptName": "NotoSansVai",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanswancho/Android.bp b/notosanswancho/Android.bp
index d2fa67e..b3c88a6 100644
--- a/notosanswancho/Android.bp
+++ b/notosanswancho/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansWancho-Regular.otf",
     src: "NotoSansWancho-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansWancho",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansWancho-Regular.otf",
+    ],
+}
diff --git a/notosanswancho/font_config.json b/notosanswancho/font_config.json
new file mode 100644
index 0000000..dc01775
--- /dev/null
+++ b/notosanswancho/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Wcho",
+        "fonts": [
+            {
+                "file": "NotoSansWancho-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosanswarangciti/Android.bp b/notosanswarangciti/Android.bp
index 6ae8546..fa860cc 100644
--- a/notosanswarangciti/Android.bp
+++ b/notosanswarangciti/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansWarangCiti-Regular.otf",
     src: "NotoSansWarangCiti-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansWarangCiti",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansWarangCiti-Regular.otf",
+    ],
+}
diff --git a/notosanswarangciti/font_config.json b/notosanswarangciti/font_config.json
new file mode 100644
index 0000000..53b09b1
--- /dev/null
+++ b/notosanswarangciti/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Wara",
+        "fonts": [
+            {
+                "file": "NotoSansWarangCiti-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notosansyi/Android.bp b/notosansyi/Android.bp
index 9fd56a7..9e6569f 100644
--- a/notosansyi/Android.bp
+++ b/notosansyi/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansYi-Regular.ttf",
     src: "NotoSansYi-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSansYi",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansYi-Regular.ttf",
+    ],
+}
diff --git a/notosansyi/font_config.json b/notosansyi/font_config.json
new file mode 100644
index 0000000..90c727d
--- /dev/null
+++ b/notosansyi/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "lang": "und-Yiii",
+        "fonts": [
+            {
+                "file": "NotoSansYi-Regular.ttf",
+                "postScriptName": "NotoSansYi",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notoserif/Android.bp b/notoserif/Android.bp
index ab93c8e..23bf943 100644
--- a/notoserif/Android.bp
+++ b/notoserif/Android.bp
@@ -64,3 +64,14 @@ prebuilt_font {
     name: "NotoSerif-Italic.ttf",
     src: "NotoSerif-Italic.ttf",
 }
+
+filegroup {
+    name: "NotoSerif",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerif-Regular.ttf",
+        "NotoSerif-Bold.ttf",
+        "NotoSerif-Italic.ttf",
+        "NotoSerif-BoldItalic.ttf",
+    ],
+}
diff --git a/notoserif/font_config.json b/notoserif/font_config.json
new file mode 100644
index 0000000..f9e64a2
--- /dev/null
+++ b/notoserif/font_config.json
@@ -0,0 +1,28 @@
+[
+    {
+        "name": "serif",
+        "fonts": [
+            {
+                "file": "NotoSerif-Regular.ttf",
+                "postScriptName": "NotoSerif",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSerif-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSerif-Italic.ttf",
+                "weight": "400",
+                "style": "italic"
+            },
+            {
+                "file": "NotoSerif-BoldItalic.ttf",
+                "weight": "700",
+                "style": "italic"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notoserifahom/Android.bp b/notoserifahom/Android.bp
index 817afdf..550e787 100644
--- a/notoserifahom/Android.bp
+++ b/notoserifahom/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSansAhom-Regular.otf", // TODO: Rename to Serif
     src: "NotoSansAhom-Regular.otf",
 }
+
+filegroup {
+    name: "NotoSansAhom",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSansAhom-Regular.otf",
+    ],
+}
diff --git a/notoserifahom/font_config.json b/notoserifahom/font_config.json
new file mode 100644
index 0000000..0abba6f
--- /dev/null
+++ b/notoserifahom/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Ahom",
+        "fonts": [
+            {
+                "file": "NotoSansAhom-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notoserifarmenian/Android.bp b/notoserifarmenian/Android.bp
index ef9acc2..3db72c5 100644
--- a/notoserifarmenian/Android.bp
+++ b/notoserifarmenian/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifArmenian-VF.ttf",
     src: "NotoSerifArmenian-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifArmenian-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifArmenian-VF.ttf",
+    ],
+}
diff --git a/notoserifarmenian/font_config.json b/notoserifarmenian/font_config.json
new file mode 100644
index 0000000..afd8f0b
--- /dev/null
+++ b/notoserifarmenian/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Armn",
+        "fonts": [
+            {
+                "file": "NotoSerifArmenian-VF.ttf",
+                "postScriptName": "NotoSerifArmenian-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansArmenian-VF_und-Armn"
+    }
+]
\ No newline at end of file
diff --git a/notoserifbengali/Android.bp b/notoserifbengali/Android.bp
index 3e6ceb0..03fe28a 100644
--- a/notoserifbengali/Android.bp
+++ b/notoserifbengali/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifBengali-VF.ttf",
     src: "NotoSerifBengali-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifBengali-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifBengali-VF.ttf",
+    ],
+}
diff --git a/notoserifbengali/font_config.json b/notoserifbengali/font_config.json
new file mode 100644
index 0000000..f11de70
--- /dev/null
+++ b/notoserifbengali/font_config.json
@@ -0,0 +1,15 @@
+[
+    {
+        "lang": "und-Beng",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSerifBengali-VF.ttf",
+                "postScriptName": "NotoSerifBengali-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansBengali-VF_und-Beng"
+    }
+]
diff --git a/notoserifcjk/Android.bp b/notoserifcjk/Android.bp
index 6a8e590..5d31980 100644
--- a/notoserifcjk/Android.bp
+++ b/notoserifcjk/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifCJK-Regular.ttc",
     src: "NotoSerifCJK-Regular.ttc",
 }
+
+filegroup {
+    name: "NotoSerifCJK",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifCJK-Regular.ttc",
+    ],
+}
diff --git a/notoserifcjk/font_config.json b/notoserifcjk/font_config.json
new file mode 100644
index 0000000..827e439
--- /dev/null
+++ b/notoserifcjk/font_config.json
@@ -0,0 +1,58 @@
+[
+    {
+        "lang": "zh-Hans",
+        "fonts": [
+            {
+                "file": "NotoSerifCJK-Regular.ttc",
+                "postScriptName": "NotoSerifCJKjp-Regular",
+                "weight": "400",
+                "style": "normal",
+                "index": "2"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansCJK_zh-Hans"
+    },
+    {
+        "lang": "zh-Hant,zh-Bopo",
+        "fonts": [
+            {
+                "file": "NotoSerifCJK-Regular.ttc",
+                "postScriptName": "NotoSerifCJKjp-Regular",
+                "weight": "400",
+                "style": "normal",
+                "index": "3"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansCJK_zh-Hant,zh-Bopo"
+    },
+    {
+        "lang": "ja",
+        "fonts": [
+            {
+                "file": "NotoSerifCJK-Regular.ttc",
+                "postScriptName": "NotoSerifCJKjp-Regular",
+                "weight": "400",
+                "style": "normal",
+                "index": "0"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansCJK_ja"
+    },
+    {
+        "lang": "ko",
+        "fonts": [
+            {
+                "file": "NotoSerifCJK-Regular.ttc",
+                "postScriptName": "NotoSerifCJKjp-Regular",
+                "weight": "400",
+                "style": "normal",
+                "index": "1"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansCJK_ko"
+    }
+]
\ No newline at end of file
diff --git a/notoserifdevanagari/Android.bp b/notoserifdevanagari/Android.bp
index c6de88f..4178fba 100644
--- a/notoserifdevanagari/Android.bp
+++ b/notoserifdevanagari/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifDevanagari-VF.ttf",
     src: "NotoSerifDevanagari-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifDevanagari-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifDevanagari-VF.ttf",
+    ],
+}
diff --git a/notoserifdevanagari/font_config.json b/notoserifdevanagari/font_config.json
new file mode 100644
index 0000000..0e7a8ce
--- /dev/null
+++ b/notoserifdevanagari/font_config.json
@@ -0,0 +1,15 @@
+[
+    {
+        "lang": "und-Deva",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSerifDevanagari-VF.ttf",
+                "postScriptName": "NotoSerifDevanagari-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansDevanagari-VF_und-Deva"
+    }
+]
\ No newline at end of file
diff --git a/notoserifdogra/Android.bp b/notoserifdogra/Android.bp
index 0b04f01..d7c1f93 100644
--- a/notoserifdogra/Android.bp
+++ b/notoserifdogra/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifDogra-Regular.ttf",
     src: "NotoSerifDogra-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSerifDogra",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifDogra-Regular.ttf",
+    ],
+}
diff --git a/notoserifdogra/font_config.json b/notoserifdogra/font_config.json
new file mode 100644
index 0000000..d80a3ef
--- /dev/null
+++ b/notoserifdogra/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Dogr",
+        "fonts": [
+            {
+                "file": "NotoSerifDogra-Regular.ttf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notoserifethiopic/Android.bp b/notoserifethiopic/Android.bp
index d73f08e..667f768 100644
--- a/notoserifethiopic/Android.bp
+++ b/notoserifethiopic/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifEthiopic-VF.ttf",
     src: "NotoSerifEthiopic-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifEthiopic-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifEthiopic-VF.ttf",
+    ],
+}
diff --git a/notoserifethiopic/font_config.json b/notoserifethiopic/font_config.json
new file mode 100644
index 0000000..d086962
--- /dev/null
+++ b/notoserifethiopic/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Ethi",
+        "fonts": [
+            {
+                "file": "NotoSerifEthiopic-VF.ttf",
+                "postScriptName": "NotoSerifEthiopic-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansEthiopic-VF_und-Ethi"
+    }
+]
\ No newline at end of file
diff --git a/notoserifgeorgian/Android.bp b/notoserifgeorgian/Android.bp
index aefd812..281a82a 100644
--- a/notoserifgeorgian/Android.bp
+++ b/notoserifgeorgian/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifGeorgian-VF.ttf",
     src: "NotoSerifGeorgian-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifGeorgian-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifGeorgian-VF.ttf",
+    ],
+}
diff --git a/notoserifgeorgian/font_config.json b/notoserifgeorgian/font_config.json
new file mode 100644
index 0000000..7104945
--- /dev/null
+++ b/notoserifgeorgian/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "lang": "und-Geor,und-Geok",
+        "fonts": [
+            {
+                "file": "NotoSerifGeorgian-VF.ttf",
+                "postScriptName": "NotoSerifGeorgian-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansGeorgian-VF_und-Geor,und-Geok"
+    }
+]
\ No newline at end of file
diff --git a/notoserifgujarati/Android.bp b/notoserifgujarati/Android.bp
index 27f3894..1d42846 100644
--- a/notoserifgujarati/Android.bp
+++ b/notoserifgujarati/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifGujarati-VF.ttf",
     src: "NotoSerifGujarati-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifGujarati-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifGujarati-VF.ttf",
+    ],
+}
diff --git a/notoserifgujarati/font_config.json b/notoserifgujarati/font_config.json
new file mode 100644
index 0000000..2f18ac0
--- /dev/null
+++ b/notoserifgujarati/font_config.json
@@ -0,0 +1,16 @@
+[
+    {
+        "lang": "und-Gujr",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSerifGujarati-VF.ttf",
+                "postScriptName": "NotoSerifGujarati-Regular",
+                "style": "normal",
+                "supportedAxes": "wght"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansGujarati_und-Gujr"
+    }
+]
\ No newline at end of file
diff --git a/notoserifgurmukhi/Android.bp b/notoserifgurmukhi/Android.bp
index 7ac8cc0..75aaa92 100644
--- a/notoserifgurmukhi/Android.bp
+++ b/notoserifgurmukhi/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifGurmukhi-VF.ttf",
     src: "NotoSerifGurmukhi-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifGurmukhi-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifGurmukhi-VF.ttf",
+    ],
+}
diff --git a/notoserifgurmukhi/font_config.json b/notoserifgurmukhi/font_config.json
new file mode 100644
index 0000000..62f79f6
--- /dev/null
+++ b/notoserifgurmukhi/font_config.json
@@ -0,0 +1,15 @@
+[
+    {
+        "lang": "und-Guru",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSerifGurmukhi-VF.ttf",
+                "postScriptName": "NotoSerifGurmukhi-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansGurmukhi-VF_und-Guru"
+    }
+]
\ No newline at end of file
diff --git a/notoserifhebrew/Android.bp b/notoserifhebrew/Android.bp
index 8ad69e6..9f8d64f 100644
--- a/notoserifhebrew/Android.bp
+++ b/notoserifhebrew/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSerifHebrew-Bold.ttf",
     src: "NotoSerifHebrew-Bold.ttf",
 }
+
+filegroup {
+    name: "NotoSerifHebrew",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifHebrew-Regular.ttf",
+        "NotoSerifHebrew-Bold.ttf",
+    ],
+}
diff --git a/notoserifhebrew/font_config.json b/notoserifhebrew/font_config.json
new file mode 100644
index 0000000..b6d51ea
--- /dev/null
+++ b/notoserifhebrew/font_config.json
@@ -0,0 +1,19 @@
+[
+    {
+        "lang": "und-Hebr",
+        "fonts": [
+            {
+                "file": "NotoSerifHebrew-Regular.ttf",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSerifHebrew-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansHebrew_und-Hebr"
+    }
+]
\ No newline at end of file
diff --git a/notoserifhentaigana/Android.bp b/notoserifhentaigana/Android.bp
index a648c35..cc06826 100644
--- a/notoserifhentaigana/Android.bp
+++ b/notoserifhentaigana/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifHentaigana.ttf",
     src: "NotoSerifHentaigana.ttf",
 }
+
+filegroup {
+    name: "NotoSerifHentaigana",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifHentaigana.ttf",
+    ],
+}
diff --git a/notoserifhentaigana/font_config.json b/notoserifhentaigana/font_config.json
new file mode 100644
index 0000000..6802df9
--- /dev/null
+++ b/notoserifhentaigana/font_config.json
@@ -0,0 +1,16 @@
+[
+    {
+        "lang": "ja",
+        "priority": 100,
+        "fonts": [
+            {
+                "file": "NotoSerifHentaigana.ttf",
+                "postScriptName": "NotoSerifHentaigana-ExtraLight",
+                "supportedAxes": "wght",
+                "axes": {
+                    "wght": "400"
+                }
+            }
+        ]
+    }
+]
diff --git a/notoserifkannada/Android.bp b/notoserifkannada/Android.bp
index 19b7545..cdfef4b 100644
--- a/notoserifkannada/Android.bp
+++ b/notoserifkannada/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifKannada-VF.ttf",
     src: "NotoSerifKannada-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifKannada-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifKannada-VF.ttf",
+    ],
+}
diff --git a/notoserifkannada/font_config.json b/notoserifkannada/font_config.json
new file mode 100644
index 0000000..d052448
--- /dev/null
+++ b/notoserifkannada/font_config.json
@@ -0,0 +1,15 @@
+[
+    {
+        "lang": "und-Knda",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSerifKannada-VF.ttf",
+                "postScriptName": "NotoSerifKannada-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansKannada-VF_und-Knda"
+    }
+]
\ No newline at end of file
diff --git a/notoserifkhmer/Android.bp b/notoserifkhmer/Android.bp
index 0a69f0a..a984515 100644
--- a/notoserifkhmer/Android.bp
+++ b/notoserifkhmer/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSerifKhmer-Bold.otf",
     src: "NotoSerifKhmer-Bold.otf",
 }
+
+filegroup {
+    name: "NotoSerifKhmer",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifKhmer-Regular.otf",
+        "NotoSerifKhmer-Bold.otf",
+    ],
+}
diff --git a/notoserifkhmer/font_config.json b/notoserifkhmer/font_config.json
new file mode 100644
index 0000000..26a7a80
--- /dev/null
+++ b/notoserifkhmer/font_config.json
@@ -0,0 +1,20 @@
+[
+    {
+        "lang": "und-Khmr",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSerifKhmer-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSerifKhmer-Bold.otf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansKhmer-VF_und-Khmr"
+    }
+]
\ No newline at end of file
diff --git a/notoseriflao/Android.bp b/notoseriflao/Android.bp
index 9d7ea57..e6ce335 100644
--- a/notoseriflao/Android.bp
+++ b/notoseriflao/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSerifLao-Regular.ttf",
     src: "NotoSerifLao-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSerifLao",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifLao-Bold.ttf",
+        "NotoSerifLao-Regular.ttf",
+    ],
+}
diff --git a/notoseriflao/font_config.json b/notoseriflao/font_config.json
new file mode 100644
index 0000000..d50e58c
--- /dev/null
+++ b/notoseriflao/font_config.json
@@ -0,0 +1,20 @@
+[
+    {
+        "lang": "und-Laoo",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSerifLao-Regular.ttf",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSerifLao-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansLao_und-Laoo"
+    }
+]
\ No newline at end of file
diff --git a/notoserifmalayalam/Android.bp b/notoserifmalayalam/Android.bp
index 5977575..a7f9942 100644
--- a/notoserifmalayalam/Android.bp
+++ b/notoserifmalayalam/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifMalayalam-VF.ttf",
     src: "NotoSerifMalayalam-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifMalayalam-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifMalayalam-VF.ttf",
+    ],
+}
diff --git a/notoserifmalayalam/font_config.json b/notoserifmalayalam/font_config.json
new file mode 100644
index 0000000..55bb392
--- /dev/null
+++ b/notoserifmalayalam/font_config.json
@@ -0,0 +1,15 @@
+[
+    {
+        "lang": "und-Mlym",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSerifMalayalam-VF.ttf",
+                "postScriptName": "NotoSerifMalayalam-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansMalayalam-VF_und-Mlym"
+    }
+]
\ No newline at end of file
diff --git a/notoserifmyanmar/Android.bp b/notoserifmyanmar/Android.bp
index c63e1b0..0566698 100644
--- a/notoserifmyanmar/Android.bp
+++ b/notoserifmyanmar/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSerifMyanmar-Bold.otf",
     src: "NotoSerifMyanmar-Bold.otf",
 }
+
+filegroup {
+    name: "NotoSerifMyanmar",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifMyanmar-Regular.otf",
+        "NotoSerifMyanmar-Bold.otf",
+    ],
+}
diff --git a/notoserifmyanmar/font_config.json b/notoserifmyanmar/font_config.json
new file mode 100644
index 0000000..6b1a913
--- /dev/null
+++ b/notoserifmyanmar/font_config.json
@@ -0,0 +1,20 @@
+[
+    {
+        "lang": "und-Mymr",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSerifMyanmar-Regular.otf",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSerifMyanmar-Bold.otf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansMyanmar_und-Mymr"
+    }
+]
\ No newline at end of file
diff --git a/notoserifnyiakengpuachuehmong/Android.bp b/notoserifnyiakengpuachuehmong/Android.bp
index b189747..8904784 100644
--- a/notoserifnyiakengpuachuehmong/Android.bp
+++ b/notoserifnyiakengpuachuehmong/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifNyiakengPuachueHmong-VF.ttf",
     src: "NotoSerifNyiakengPuachueHmong-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifNyiakengPuachueHmong-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifNyiakengPuachueHmong-VF.ttf",
+    ],
+}
diff --git a/notoserifnyiakengpuachuehmong/font_config.json b/notoserifnyiakengpuachuehmong/font_config.json
new file mode 100644
index 0000000..b7d988e
--- /dev/null
+++ b/notoserifnyiakengpuachuehmong/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Hmnp",
+        "fonts": [
+            {
+                "file": "NotoSerifNyiakengPuachueHmong-VF.ttf",
+                "postScriptName": "NotoSerifHmongNyiakeng-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
diff --git a/notoserifsinhala/Android.bp b/notoserifsinhala/Android.bp
index 97447c5..3fd7f48 100644
--- a/notoserifsinhala/Android.bp
+++ b/notoserifsinhala/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifSinhala-VF.ttf",
     src: "NotoSerifSinhala-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifSinhala-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifSinhala-VF.ttf",
+    ],
+}
diff --git a/notoserifsinhala/font_config.json b/notoserifsinhala/font_config.json
new file mode 100644
index 0000000..d4668c3
--- /dev/null
+++ b/notoserifsinhala/font_config.json
@@ -0,0 +1,15 @@
+[
+    {
+        "lang": "und-Sinh",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSerifSinhala-VF.ttf",
+                "postScriptName": "NotoSerifSinhala-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansSinhala-VF_und-Sinh"
+    }
+]
diff --git a/notoseriftamil/Android.bp b/notoseriftamil/Android.bp
index 166794a..c1fa723 100644
--- a/notoseriftamil/Android.bp
+++ b/notoseriftamil/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifTamil-VF.ttf",
     src: "NotoSerifTamil-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifTamil-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifTamil-VF.ttf",
+    ],
+}
diff --git a/notoseriftamil/font_config.json b/notoseriftamil/font_config.json
new file mode 100644
index 0000000..5a7d70f
--- /dev/null
+++ b/notoseriftamil/font_config.json
@@ -0,0 +1,15 @@
+[
+    {
+        "lang": "und-Taml",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSerifTamil-VF.ttf",
+                "postScriptName": "NotoSerifTamil-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansTamil-VF_und-Taml"
+    }
+]
\ No newline at end of file
diff --git a/notoseriftelugu/Android.bp b/notoseriftelugu/Android.bp
index 91d9c59..266bdd3 100644
--- a/notoseriftelugu/Android.bp
+++ b/notoseriftelugu/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifTelugu-VF.ttf",
     src: "NotoSerifTelugu-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifTelugu-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifTelugu-VF.ttf",
+    ],
+}
diff --git a/notoseriftelugu/font_config.json b/notoseriftelugu/font_config.json
new file mode 100644
index 0000000..f8658f2
--- /dev/null
+++ b/notoseriftelugu/font_config.json
@@ -0,0 +1,15 @@
+[
+    {
+        "lang": "und-Telu",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSerifTelugu-VF.ttf",
+                "postScriptName": "NotoSerifTelugu-Regular",
+                "supportedAxes": "wght"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansTelugu-VF_und-Telu"
+    }
+]
\ No newline at end of file
diff --git a/notoserifthai/Android.bp b/notoserifthai/Android.bp
index bf6ac86..d543d26 100644
--- a/notoserifthai/Android.bp
+++ b/notoserifthai/Android.bp
@@ -54,3 +54,12 @@ prebuilt_font {
     name: "NotoSerifThai-Regular.ttf",
     src: "NotoSerifThai-Regular.ttf",
 }
+
+filegroup {
+    name: "NotoSerifThai",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifThai-Bold.ttf",
+        "NotoSerifThai-Regular.ttf",
+    ],
+}
diff --git a/notoserifthai/font_config.json b/notoserifthai/font_config.json
new file mode 100644
index 0000000..475d103
--- /dev/null
+++ b/notoserifthai/font_config.json
@@ -0,0 +1,20 @@
+[
+    {
+        "lang": "und-Thai",
+        "variant": "elegant",
+        "fonts": [
+            {
+                "file": "NotoSerifThai-Regular.ttf",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "NotoSerifThai-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            }
+        ],
+        "fallbackFor": "serif",
+        "target": "NotoSansThai_und-Thai"
+    }
+]
\ No newline at end of file
diff --git a/notoseriftibetan/Android.bp b/notoseriftibetan/Android.bp
index bb37dbd..804590b 100644
--- a/notoseriftibetan/Android.bp
+++ b/notoseriftibetan/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifTibetan-VF.ttf",
     src: "NotoSerifTibetan-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifTibetan-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifTibetan-VF.ttf",
+    ],
+}
diff --git a/notoseriftibetan/font_config.json b/notoseriftibetan/font_config.json
new file mode 100644
index 0000000..dbbf5aa
--- /dev/null
+++ b/notoseriftibetan/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Tibt",
+        "fonts": [
+            {
+                "file": "NotoSerifTibetan-VF.ttf",
+                "postScriptName": "NotoSerifTibetan-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
\ No newline at end of file
diff --git a/notoserifyezidi/Android.bp b/notoserifyezidi/Android.bp
index 20b0a5e..354aa1b 100644
--- a/notoserifyezidi/Android.bp
+++ b/notoserifyezidi/Android.bp
@@ -49,3 +49,11 @@ prebuilt_font {
     name: "NotoSerifYezidi-VF.ttf",
     src: "NotoSerifYezidi-VF.ttf",
 }
+
+filegroup {
+    name: "NotoSerifYezidi-VF",
+    srcs: ["font_config.json"],
+    required: [
+        "NotoSerifYezidi-VF.ttf",
+    ],
+}
diff --git a/notoserifyezidi/font_config.json b/notoserifyezidi/font_config.json
new file mode 100644
index 0000000..e21812d
--- /dev/null
+++ b/notoserifyezidi/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "lang": "und-Yezi",
+        "fonts": [
+            {
+                "file": "NotoSerifYezidi-VF.ttf",
+                "postScriptName": "NotoSerifYezidi-Regular",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
```

