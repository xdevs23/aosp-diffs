```diff
diff --git a/Android.bp b/Android.bp
index b916f20..30ea069 100644
--- a/Android.bp
+++ b/Android.bp
@@ -36,7 +36,7 @@ java_import {
     name: "error_prone_annotations",
     host_supported: true,
     visibility: ["//visibility:public"],
-    jars: ["error_prone/error_prone_annotations-2.36.0.jar"],
+    jars: ["error_prone/error_prone_annotations-2.37.0.jar"],
     min_sdk_version: "29",
     apex_available: [
         "//apex_available:anyapex",
@@ -53,8 +53,8 @@ java_import {
     name: "error_prone_core_jars",
     host_supported: true,
     jars: [
-        "error_prone/error_prone_core-2.36.0-with-dependencies.jar",
-        "error_prone/error_prone_annotations-2.36.0.jar",
+        "error_prone/error_prone_core-2.37.0-with-dependencies.jar",
+        "error_prone/error_prone_annotations-2.37.0.jar",
     ],
 }
 
@@ -75,7 +75,7 @@ java_import {
     host_supported: true,
     visibility: ["//visibility:public"],
     jars: [
-        "error_prone/error_prone_test_helpers-2.36.0.jar",
+        "error_prone/error_prone_test_helpers-2.37.0.jar",
         "jimfs/jimfs-1.1.jar",
     ],
 }
diff --git a/checkerframework/METADATA b/checkerframework/METADATA
index 7d90205..c10da33 100644
--- a/checkerframework/METADATA
+++ b/checkerframework/METADATA
@@ -18,5 +18,5 @@ third_party {
     value: "https://repo1.maven.org/maven2/org/checkerframework/javacutil/3.15.0/javacutil-3.15.0-sources.jar"
   }
   version: "3.39.0"
-  last_upgrade_date { year: 2024 month: 12 day: 2}
+  last_upgrade_date { year: 2025 month: 4 day: 10}
 }
diff --git a/error_prone/METADATA b/error_prone/METADATA
index ea757f1..aac9d88 100644
--- a/error_prone/METADATA
+++ b/error_prone/METADATA
@@ -10,8 +10,8 @@ third_party {
   }
   url {
     type: ARCHIVE
-    value: "https://oss.sonatype.org/service/local/repositories/releases/content/com/google/errorprone/error_prone_core/2.36.0/error_prone_core-2.36.0-with-dependencies.jar"
+    value: "https://oss.sonatype.org/service/local/repositories/releases/content/com/google/errorprone/error_prone_core/2.37.0/error_prone_core-2.37.0-with-dependencies.jar"
   }
-  version: "2.36.0"
-  last_upgrade_date { year: 2024 month: 12 day: 2}
+  version: "2.37.0"
+  last_upgrade_date { year: 2025 month: 4 day: 10}
 }
diff --git a/error_prone/error_prone_annotations-2.36.0.jar b/error_prone/error_prone_annotations-2.36.0.jar
deleted file mode 100644
index 740268b..0000000
Binary files a/error_prone/error_prone_annotations-2.36.0.jar and /dev/null differ
diff --git a/error_prone/error_prone_annotations-2.36.0.jar.asc b/error_prone/error_prone_annotations-2.36.0.jar.asc
deleted file mode 100644
index c684b01..0000000
--- a/error_prone/error_prone_annotations-2.36.0.jar.asc
+++ /dev/null
@@ -1,16 +0,0 @@
------BEGIN PGP SIGNATURE-----
-
-iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmc73gkACgkQ02Srqjmk
-cyAnfRAAis7vXEp/79sLw0XkblPDIwDf38P52Cnpm9dhY9emG00Wz+RuB0W6pbBT
-8Ct6cVtQVE6JPNiDCN+WSoZ/0Pi8ipeoZkmygmz5LZGRdcAGfmM/wOjO/Drxn72B
-eOZyjeHcRVo6C28SpormZHC3cOiqdUp6v8w9DVhwxWuC37vmhFqT4DlZgUfl2J8/
-EUp5+Z3+xgmM5+IJP0fjZOGJXYIyknwQRKJVkUjvbwKFOuT4122zNiPBDLz/58bE
-nAVQ1yvOW9iqnQvEE8IGxcK/9wTakCyfnM3AW+ykedL2sR6yRgtTeExalBeP4QoZ
-Bk7xAyOdUpmpFG9fa2iX8itnATSLkYw0YcBFShNiALw7EDHV/1op1iQCkcTZ4y9U
-BG61c2rpOxu0ylKAVF4JRkndnb7VJhWjohfj4YQ/XfUpBhB9IeaV4hnl7VLuQmV6
-8SFEm++clyhCoE8tyqPPFomm+VfBVz0OywxnTOjFPA44qLdwdlUyc7WHV9vh5UBq
-esiy5RStDr1KgTV3dCp9C92fi7XURCkEqzxo7/gRynos/K15RbbS6x66Ro2Qb2Ws
-YtD61DHGCPYDcftUFb1E+S07PUd5snvLNZjy/A+RTdFGVjzvy2vZlwNQByeyGDQW
-/WCvwYGzGuT6OZE8pIJgWX7paamWY2yV/wkNQ62+2+rHy0alpXA=
-=N2/n
------END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_annotations-2.36.0.jar.sha1 b/error_prone/error_prone_annotations-2.36.0.jar.sha1
deleted file mode 100644
index 2770835..0000000
--- a/error_prone/error_prone_annotations-2.36.0.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-227d4d4957ccc3dc5761bd897e3a0ee587e750a7
\ No newline at end of file
diff --git a/error_prone/error_prone_annotations-2.37.0.jar b/error_prone/error_prone_annotations-2.37.0.jar
new file mode 100644
index 0000000..3a12ce8
Binary files /dev/null and b/error_prone/error_prone_annotations-2.37.0.jar differ
diff --git a/error_prone/error_prone_annotations-2.37.0.jar.asc b/error_prone/error_prone_annotations-2.37.0.jar.asc
new file mode 100644
index 0000000..3f58948
--- /dev/null
+++ b/error_prone/error_prone_annotations-2.37.0.jar.asc
@@ -0,0 +1,16 @@
+-----BEGIN PGP SIGNATURE-----
+
+iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmfa4rQACgkQ02Srqjmk
+cyAX7hAAiwXxjTrgr2E8q+7G1ijalNbJiKSOJtuzTgOgBR3Jw7alXAOTfxj6vhJA
+H1CvBWTvFo6ht9kxOx0ndTJtNRoL71SxtxElqTN4aFOuElLDnyb8sjZNSFQRsa7G
+RUG5WFH8Ja18nHRJaa/b36++cmkq37c6JkplnuaLqQfgZFcOtP9EnG9uk2TG0f6Y
+Q//43AgJzS1wcLz6vvWuPewKt202E/eolQHuNlTcrUpnl4Ylz9mKPie3oLDUpVqa
+fJPtGIXbQ4dX6pWfjtEtp8gpgXwGDJ/qr7FhmsW+hDtA3jo6LYNo3cSzEehymUbl
+/fm5lIjqyFngY8HgG59jQea8LXB2A/8AyybDivPseQU7s/PUWNeGlYAtfQzlmfAw
+qGtUBO34kr4IuqIHQ5r13Jzq5dLns4sOMKnbkAkmJXJk/AIW/+kk5c4PH4B/yfTZ
+uIbAJp6Z1vygJGS0+mxOJgRh3ZBTTmDD0ob33tZP3FHJa27WPvsUZhCA1B4scdOz
+1enWwH5YqEODa+ic40FFFaEVKyNKvRTNd+2w3GcOVNQ90piVmq7QpLDpp0dK3bak
+zeqthKL+nArakEYw+1UUdShEfRMZZk5IfDV+GVGz+uXnCYyb/98Db7y56IoabH9b
+6bdgfglcaabunts8x/kCFT1jAHWPb8gPj/xws4ow0VAmAUZmZp0=
+=Reai
+-----END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_annotations-2.37.0.jar.sha1 b/error_prone/error_prone_annotations-2.37.0.jar.sha1
new file mode 100644
index 0000000..1560bb7
--- /dev/null
+++ b/error_prone/error_prone_annotations-2.37.0.jar.sha1
@@ -0,0 +1 @@
+8512660d1269d166fad497f51de35da61447f063
\ No newline at end of file
diff --git a/error_prone/error_prone_core-2.36.0-with-dependencies.jar.asc b/error_prone/error_prone_core-2.36.0-with-dependencies.jar.asc
deleted file mode 100644
index f32cd96..0000000
--- a/error_prone/error_prone_core-2.36.0-with-dependencies.jar.asc
+++ /dev/null
@@ -1,16 +0,0 @@
------BEGIN PGP SIGNATURE-----
-
-iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmc73uEACgkQ02Srqjmk
-cyDFIg//aS0bx8g2OromeFeZmWVLTlKRLi1pF4/kuC89K5Wluq5XU7FVKNIa/hJG
-+HZieDN/GC3jrseY2Wp1OS3+WKIlPpoY+VdwHosev/qcPNrtDVt8xLWZ1chK1eOT
-YulIxt1qXCapLatWav1dQGoehmoZtwLG+jPNn/CRzcl9KHLQlV1nkbeLo2g6rqEc
-tRwuui1gFbx0lckVlYf8xtxS0QRIZHlqG4zzF0JCqH5wlHQVsJxpra0dtKvdbPJz
-YfML6P423Nvcnbnew+iEXqRgU8ua/wrJI1hgN3rhroj8hVBBB/FFDQtSPSWG896Q
-lUsCaC2FrMkDo+tVQ8WlorqDgL1DpBN7R1SzzSyv+pYuAjlOpvnZ87RRy+dJUHsC
-OcSVCR3LTiWQNZV6fmki/LuWPf1NQCvxukFa0lRNvmTCIpxbE5Ga8N27q4dMLwzv
-N+r0VVzKIvVf2PTtXvtACvqQK76fDjdkQU/TbFjgGCq4sSN1RM4dmFwIDvR5xkqy
-c1NvEoDzWj5CXYwArlQ1k+x0lfXueBw6Ii4VJIaL5nVVZyB0oPCoACtIeINDwlvu
-DG96vM3JN7Mncpr/Um3kAzZ9Pxik5UH/l9FENte0ttcg/5XS1t7DsooXcXTX0jUk
-hzUN2L9uWcK7ZZbRvoSImNz6ESkvfB4lBUe+sXsMhzSsyvYW59E=
-=U7JC
------END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_core-2.36.0-with-dependencies.jar.sha1 b/error_prone/error_prone_core-2.36.0-with-dependencies.jar.sha1
deleted file mode 100644
index a0204e0..0000000
--- a/error_prone/error_prone_core-2.36.0-with-dependencies.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-3cefb3562928b6e91c13424ae83083994f7230e1
\ No newline at end of file
diff --git a/error_prone/error_prone_core-2.36.0-with-dependencies.jar b/error_prone/error_prone_core-2.37.0-with-dependencies.jar
similarity index 80%
rename from error_prone/error_prone_core-2.36.0-with-dependencies.jar
rename to error_prone/error_prone_core-2.37.0-with-dependencies.jar
index 3708b73..4c275b6 100644
Binary files a/error_prone/error_prone_core-2.36.0-with-dependencies.jar and b/error_prone/error_prone_core-2.37.0-with-dependencies.jar differ
diff --git a/error_prone/error_prone_core-2.37.0-with-dependencies.jar.asc b/error_prone/error_prone_core-2.37.0-with-dependencies.jar.asc
new file mode 100644
index 0000000..9d837d8
--- /dev/null
+++ b/error_prone/error_prone_core-2.37.0-with-dependencies.jar.asc
@@ -0,0 +1,16 @@
+-----BEGIN PGP SIGNATURE-----
+
+iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmfa44wACgkQ02Srqjmk
+cyAcHRAAgejkX9j7Y8/WG+zUql4N8+IfOnVsW/B0xSkjis5wkd6hnapDf/bPmsDT
++qfgE+J9Lj9eboS/OlLSWPU/PeQstEUwPl92UMw+aqpC9kJzNE6CyaCPXBS+vGCZ
+ycgJ8uq4yhMvafOTx00Hniu0FIYXlJpLpiWEKaSd7D2LHi+qH8w+qvRGyIRfVlzj
+rc/91m+YZhQ2Zw7wg0QguikQid/Q9GNYP6S8qQKaX9c/mriK2K5exlduC8NbDnza
+Kx+J7/srwKeh+kSQPFc2vq/mYiK0LiwHvah/pPdjfIX5tY8bgfZ7Np3JOOS9sjxk
+iPlYP3yhwqopjsolXCQOYF4reF0lehfHHxw4BoG6F1oWtd7sVk7KbCHPg+vyoNJn
+G7Y0cUMO9XoSztp5k5AYlvmzTj9zXKlRV5IhTGT1HiOVbEtEUt9A+pK/RRFensh3
+VhD9yDL9iWMU96c8wJRoqLKspCseJGp9yQnvWCy+YwSv6hYB1/K0DkmV152uEp6V
+9uHorufGcGwf4i4Yao1WJbR71GuM5dtP0o9+B5lKUWrIAgz43tOjPMkJle3kCWyA
+lQm8Qz9qRPkyVOGL/+mURz/qyak0wzT0zyPM011u1iKpp1r7afVrOcRrth/xL5DW
+Q8vZIKlz+bCeLXZqZJU66QofbA/nqVbVTa/g+laIpVc7DrdMD0E=
+=zDQd
+-----END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_core-2.37.0-with-dependencies.jar.sha1 b/error_prone/error_prone_core-2.37.0-with-dependencies.jar.sha1
new file mode 100644
index 0000000..3db5eec
--- /dev/null
+++ b/error_prone/error_prone_core-2.37.0-with-dependencies.jar.sha1
@@ -0,0 +1 @@
+909b8fdebc84ab4176ea3e047654ef3213ff8456
\ No newline at end of file
diff --git a/error_prone/error_prone_test_helpers-2.36.0.jar b/error_prone/error_prone_test_helpers-2.36.0.jar
deleted file mode 100644
index 39053cb..0000000
Binary files a/error_prone/error_prone_test_helpers-2.36.0.jar and /dev/null differ
diff --git a/error_prone/error_prone_test_helpers-2.36.0.jar.asc b/error_prone/error_prone_test_helpers-2.36.0.jar.asc
deleted file mode 100644
index 4f2cd67..0000000
--- a/error_prone/error_prone_test_helpers-2.36.0.jar.asc
+++ /dev/null
@@ -1,16 +0,0 @@
------BEGIN PGP SIGNATURE-----
-
-iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmc73iIACgkQ02Srqjmk
-cyCAixAAl3/4f7l11jv3NbtuOJeDxTf64bw5NTvRf+YdynQmDJGGbpt9/zYvmZbW
-GiViPEHvncHDc26bvl6qWEAjHKyCJx4mNcIKZahT8qc1jHL1CJSLcMiLb0kVVNqv
-FQLLy7mSyTsRKhvyF1dEDU034zXtDs9lhwbOZijPcqzSbLRa+vorOfFKDG/AfTCJ
-IaD8V7s7GcXzDpBuIXKQlj+zLVi14RJCCVuRjtKrRthE3stusxCDwaLSHarBrT0D
-crPtnyaQg85CzTWddOiVujbjgs5Rgn6fqYuTONpcdXcIvbD3cjl++mZHCgG7Z4of
-jAaGk0OMVVrLgd0sTI5X5gBg+TlZ5yMRKUdiqDTEVGh04VnxoSD7fAcJ3OT1F4Wv
-sZREMA9QfkTuo+3RQexcPJsn7EwF6SLNXysUA3XCtaZ3ibiSpmC5nwCYe2+UzU/1
-Zytl7WGrui/Y0Ubtd5daizBgaQuUVhs5rFAAEiC3qLrENNkC2SNDYKGHWD5BzMQy
-j0Thoa5zNkNS5wW+i6vhkViW8Lljr4PraDxvPcsC6jvLeLfE1QReZVU6vPm8dY28
-MNKq5WP2sNg4cm0GSKRsVtXCI85fDWFQd0eqch1sTwLIYEsym1GmMWAukWkEskLS
-5MhfV6MGSnH+z9k26x+Jn0wJQvswXX8FzMXbjpeneRwSLUrNroM=
-=9R9O
------END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_test_helpers-2.36.0.jar.sha1 b/error_prone/error_prone_test_helpers-2.36.0.jar.sha1
deleted file mode 100644
index dde2cb0..0000000
--- a/error_prone/error_prone_test_helpers-2.36.0.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-fb272f69c7ba9cc46fb517e9889021481517612d
\ No newline at end of file
diff --git a/error_prone/error_prone_test_helpers-2.37.0.jar b/error_prone/error_prone_test_helpers-2.37.0.jar
new file mode 100644
index 0000000..5d2e342
Binary files /dev/null and b/error_prone/error_prone_test_helpers-2.37.0.jar differ
diff --git a/error_prone/error_prone_test_helpers-2.37.0.jar.asc b/error_prone/error_prone_test_helpers-2.37.0.jar.asc
new file mode 100644
index 0000000..8ccb2d7
--- /dev/null
+++ b/error_prone/error_prone_test_helpers-2.37.0.jar.asc
@@ -0,0 +1,16 @@
+-----BEGIN PGP SIGNATURE-----
+
+iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmfa4s8ACgkQ02Srqjmk
+cyCr+A/+KDgGsKJ10BRxM28avkzrtq63VXzJoobe3wEsoBOrksqeKAfC0nLXidkx
+TLiVEf00qxk7tYr8ajEThBo5hHfai3HsbDb6hdw/a5MGVPEHrXYKjr6DSFn3CgxZ
+1y8dJqDi32xwyJ4TcViYj45tyv3zTGUdU66vrWJl2oVnKSwWveZqdoMCMdx+3bhk
+m14Kq6foVKNuM4LwVCyY+GlhLwgeQkMRAqYPTPeqRxGeBpmTl1mLFhZzRILzFfbL
+sbEf/uNZN79oOcY1HnatNj+mHBKASAcGLMFIhhSEhvmnonctyjH9VPP+zGI4oaL1
+GJ/SgO+8Cnifqnd+XMJQmIYqG7sgLp9MKW8f2DTb0vy+ksSvBrsMJW92ukoHJ/j8
+L0la63IsFTQqqvgyX5q2P5vt2L7ngaTyPcBH/iCg+1nW5WwPdC5H5WUrcGJUTM0H
+KkrT7gSOUhd1pdDNSulwlX7tCz9ZCVoZlUbOlT9FC6ZTZ1/hslxiE+MwjJ2vXaRl
+ip2RjqRVvcmwGmHU3IPhjZFUYszYDZeDESj2O+B3cjv45HGfQP/woyIi68qbOrkO
+lyKB1lCqyFtg3GDenGiAbqdXRHnl4XQ4CwSQ+pJJEOcGwPsI/w6Mfxfn/Nx5Nxa+
+Z6M04Gi7QWSmV29l6L6Fuiysz/z1NnQgeQti1kHsl9gNOAoglzE=
+=R3tH
+-----END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_test_helpers-2.37.0.jar.sha1 b/error_prone/error_prone_test_helpers-2.37.0.jar.sha1
new file mode 100644
index 0000000..b380eed
--- /dev/null
+++ b/error_prone/error_prone_test_helpers-2.37.0.jar.sha1
@@ -0,0 +1 @@
+fa70e49f5491d092254400641f3c5011e08abf6c
\ No newline at end of file
diff --git a/error_prone/error_prone_type_annotations-2.36.0.jar b/error_prone/error_prone_type_annotations-2.36.0.jar
deleted file mode 100644
index e63a437..0000000
Binary files a/error_prone/error_prone_type_annotations-2.36.0.jar and /dev/null differ
diff --git a/error_prone/error_prone_type_annotations-2.36.0.jar.asc b/error_prone/error_prone_type_annotations-2.36.0.jar.asc
deleted file mode 100644
index 98549b7..0000000
--- a/error_prone/error_prone_type_annotations-2.36.0.jar.asc
+++ /dev/null
@@ -1,16 +0,0 @@
------BEGIN PGP SIGNATURE-----
-
-iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmc73iYACgkQ02Srqjmk
-cyC1JxAAiPcs5CylbY/xdJN61fY80/B4TizLuS3jJ9vpIACK4evwB+mM9n9Xlueo
-2PfTYQROnYTaMJoL26cwUG1AD7q297zq1hfvmQhUqXCs0CznTk2Ku8dSW0G9cFWO
-6NpaGkdMsOhUdGkwUE962JUMZReONtg7Z2+CP6XZo9m0+PfUMYqCOWaKkaFtKjF+
-eSz0FuEYQ7GYSxkQ5XuiQFJsZOLW0jKplF5llaCgt8SKt3I6oloI69FMdtoabVhr
-+NhD6g5eH89517EiUfrekpjeIQ/riuXsCO5bpH82/LLNOe4IF6ckamhZbTvyrx3O
-EUd6ouBQxN693p8uz7bCgwhXFsSfEhuYs9fXFob45bGbInAf3KWvKHYl0rp2vFO0
-8+WR8+FS5GXJYNQGAnqas9md6cyZBu+Fz1rtf/BWnF2wSbDfKa3mLOc5cCqF1PhZ
-2fGg0Ii5SeTinshyfoC7MNoczNU6OxSGe/e5VTG+T+C8fKNnKbbzBOjcuFpSF42A
-zRdblncF1GtlgcgfMDJZC8W6yCUL4WK04l0yyGVdz4C3rHGxUVxNhyn4U9JPCAgs
-bm+1r5sgD1qcob1SzXlHhqJGI4YclNuDa42FK4DzZCSTux8Z8PX7R/udzgHFZJJo
-yuEkDjwgwD8AKyHvBaZzp0boHbsFBANeYeuPDYefn6A2LK0Sfdc=
-=TflN
------END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_type_annotations-2.36.0.jar.sha1 b/error_prone/error_prone_type_annotations-2.36.0.jar.sha1
deleted file mode 100644
index d106798..0000000
--- a/error_prone/error_prone_type_annotations-2.36.0.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-e8cf97ae8ae15010636e6847b3715d1cfb559420
\ No newline at end of file
diff --git a/error_prone/error_prone_type_annotations-2.37.0.jar b/error_prone/error_prone_type_annotations-2.37.0.jar
new file mode 100644
index 0000000..d3391b7
Binary files /dev/null and b/error_prone/error_prone_type_annotations-2.37.0.jar differ
diff --git a/error_prone/error_prone_type_annotations-2.37.0.jar.asc b/error_prone/error_prone_type_annotations-2.37.0.jar.asc
new file mode 100644
index 0000000..262fe79
--- /dev/null
+++ b/error_prone/error_prone_type_annotations-2.37.0.jar.asc
@@ -0,0 +1,16 @@
+-----BEGIN PGP SIGNATURE-----
+
+iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmfa4q4ACgkQ02Srqjmk
+cyBoew/+NrBQ0qnYUTU21gw5f7XWIa4DWP7PSINjdhvPGoepRGv7h7Frgd/8b2k6
+NemAxMpZUIBuB85nkp43pTau8/01fDBl/WGGqhxGXmU72qTzGDyD4CWnzzSx8iJQ
+ol/t9jAtq0BC/rUFil6Ou3YYhkSOGk8DVeZtG3vf86K1Ldd8H8443ixpRXqZC9pj
+YFtYTgCZE0xaMcg+2p900UA6ZPzPjg+ID/3FVxHPaFINaB3+6O+F3yc7ik41In65
+pHvkxMaS8VxSfbHBP3ZZ9iwx/NlYKgPbaqLH+iqcmMQgH9AE6bx01jLdGvhorX2M
+7wKLI+5HqCkdbO9DTXtJ+ZtrcA+nk6eXaGXDLmpRYILM+v5zkow8ved1I3h5YtI+
+c+QiN68XLWe3a0ac6wMCSn5GBjO/oQcyzqGyc6bVTdkkaA5AVJ/vAmHRPIIe+Ywb
+6L4P7f/FJeu1XzJPpXaEPXVQKEaZs5Km7KM42gC4Kyim5nkqh+maZM/cbocgtkrZ
+yOnSrTW4alV0J19mDt9EC9IV24Tj8dx0T/ituL1niUxCYlaGA4Mj0788pZJvAV+m
+2WgjLrdJPlfrBrhgzz6PaI03HanLwA/BEnca6UZZ6m5/mZAi9Tge4qWdff8gcAKG
+d3s0fIh5t5pr3W0M7Z7Sur8eK7OpbF8z1a8vKNafvTReiwnHtXw=
+=/qcP
+-----END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_type_annotations-2.37.0.jar.sha1 b/error_prone/error_prone_type_annotations-2.37.0.jar.sha1
new file mode 100644
index 0000000..e28e5bc
--- /dev/null
+++ b/error_prone/error_prone_type_annotations-2.37.0.jar.sha1
@@ -0,0 +1 @@
+fcfcfaee56c933a2dd44e2a870818ce090131fc5
\ No newline at end of file
diff --git a/soong/error_prone.go b/soong/error_prone.go
index 5d66a3c..6075acc 100644
--- a/soong/error_prone.go
+++ b/soong/error_prone.go
@@ -22,9 +22,9 @@ func init() {
 	// These values are set into build/soong/java/config/config.go so that soong doesn't have any
 	// references to external/error_prone, which may not always exist.
 	config.ErrorProneClasspath = []string{
-		"external/error_prone/error_prone/error_prone_core-2.36.0-with-dependencies.jar",
-		"external/error_prone/error_prone/error_prone_annotations-2.36.0.jar",
-		"external/error_prone/error_prone/error_prone_type_annotations-2.36.0.jar",
+		"external/error_prone/error_prone/error_prone_core-2.37.0-with-dependencies.jar",
+		"external/error_prone/error_prone/error_prone_annotations-2.37.0.jar",
+		"external/error_prone/error_prone/error_prone_type_annotations-2.37.0.jar",
 		"external/error_prone/checkerframework/dataflow-errorprone-3.39.0.jar",
 		"external/error_prone/jFormatString/jFormatString-3.0.0.jar",
 	}
```

