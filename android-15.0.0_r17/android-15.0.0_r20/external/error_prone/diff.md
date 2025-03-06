```diff
diff --git a/Android.bp b/Android.bp
index b0c8010..b916f20 100644
--- a/Android.bp
+++ b/Android.bp
@@ -36,8 +36,8 @@ java_import {
     name: "error_prone_annotations",
     host_supported: true,
     visibility: ["//visibility:public"],
-    jars: ["error_prone/error_prone_annotations-2.23.0.jar"],
-    min_sdk_version : "29",
+    jars: ["error_prone/error_prone_annotations-2.36.0.jar"],
+    min_sdk_version: "29",
     apex_available: [
         "//apex_available:anyapex",
         "//apex_available:platform",
@@ -53,8 +53,8 @@ java_import {
     name: "error_prone_core_jars",
     host_supported: true,
     jars: [
-        "error_prone/error_prone_core-2.23.0-with-dependencies.jar",
-        "error_prone/error_prone_annotations-2.23.0.jar",
+        "error_prone/error_prone_core-2.36.0-with-dependencies.jar",
+        "error_prone/error_prone_annotations-2.36.0.jar",
     ],
 }
 
@@ -65,18 +65,17 @@ java_library {
     static_libs: [
         "error_prone_checkerframework_dataflow_errorprone",
         "error_prone_core_jars",
-        "error_prone_javac",
         "error_prone_jFormatString",
     ],
     sdk_version: "core_current",
 }
 
 java_import {
-    name:  "error_prone_test_helpers",
+    name: "error_prone_test_helpers",
     host_supported: true,
     visibility: ["//visibility:public"],
     jars: [
-        "error_prone/error_prone_test_helpers-2.23.0.jar",
+        "error_prone/error_prone_test_helpers-2.36.0.jar",
         "jimfs/jimfs-1.1.jar",
     ],
 }
diff --git a/checkerframework/METADATA b/checkerframework/METADATA
index d586bc5..7d90205 100644
--- a/checkerframework/METADATA
+++ b/checkerframework/METADATA
@@ -18,5 +18,5 @@ third_party {
     value: "https://repo1.maven.org/maven2/org/checkerframework/javacutil/3.15.0/javacutil-3.15.0-sources.jar"
   }
   version: "3.39.0"
-  last_upgrade_date { year: 2023 month: 11 day: 14}
+  last_upgrade_date { year: 2024 month: 12 day: 2}
 }
diff --git a/error_prone/METADATA b/error_prone/METADATA
index 74a2a3f..ea757f1 100644
--- a/error_prone/METADATA
+++ b/error_prone/METADATA
@@ -10,8 +10,8 @@ third_party {
   }
   url {
     type: ARCHIVE
-    value: "https://oss.sonatype.org/service/local/repositories/releases/content/com/google/errorprone/error_prone_core/2.23.0/error_prone_core-2.23.0-with-dependencies.jar"
+    value: "https://oss.sonatype.org/service/local/repositories/releases/content/com/google/errorprone/error_prone_core/2.36.0/error_prone_core-2.36.0-with-dependencies.jar"
   }
-  version: "2.23.0"
-  last_upgrade_date { year: 2023 month: 11 day: 14}
+  version: "2.36.0"
+  last_upgrade_date { year: 2024 month: 12 day: 2}
 }
diff --git a/error_prone/error_prone_annotations-2.23.0.jar b/error_prone/error_prone_annotations-2.23.0.jar
deleted file mode 100644
index c0f20d8..0000000
Binary files a/error_prone/error_prone_annotations-2.23.0.jar and /dev/null differ
diff --git a/error_prone/error_prone_annotations-2.23.0.jar.asc b/error_prone/error_prone_annotations-2.23.0.jar.asc
deleted file mode 100644
index 3a64720..0000000
--- a/error_prone/error_prone_annotations-2.23.0.jar.asc
+++ /dev/null
@@ -1,16 +0,0 @@
------BEGIN PGP SIGNATURE-----
-
-iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmUwJK8ACgkQ02Srqjmk
-cyC1tA//QclSI6+ttVc/U74YXcMkVSahcgn7ZCuZD3huZilP9PJ3r/UL7y8IkvO6
-5Rdh590Xkalz9yFLjmCrxC/JxMp6AKafN13sMSoHyB1mNqFL3F/Y5xwV1Pv7lwtF
-5cyW9V1dMDDIj3FaOlvmb8FgeuvbgBbokgv1XWioRNBvqGFmvcGDJReM3swHl1bG
-4o3Ar6pgEjBU93pJGzdMMxWrkH7bxpmjLlMXdhD7wj/FwSqKdxN73jrwxEKVCS9m
-ecNjYx7D1AyiJFkbD2eX40pYq+lXsR78ic1gXC+vC+0jREgKIhEMeZiZrovhm/lk
-kOQFiFAEmstDqhMEQLxLIKPVCEwh04dzXd2HD8tV1+xmJsaWXmaVtZUVlcv4IJ6Z
-rW1/5g354ewoEW9zdTBpr3Ny9gFpS7BNg0tSvIkkT2o5aHPJildWbzG8gxZN91Z0
-RyowWH03e68QuXaQj0CRc0LLo4X2aBoWjgAlczaV5JYFQUxphEi6ZnjszM0O/o/I
-j3/ORpWI9irOyzPRaRFVoCpQYFeL0my+9dMTcptw1CTFPEQWqgmUcpfDyA6tXlfB
-Kd28XK80x1rDeO3d8gyBE0GjX5u3xX/pkdDId16q9kSSIT39B7r0njdXQ3WbjRwa
-VI+pGQbvaBDkRQ+AGLoGJW8QCkFBHHoc9ySnt9lPVSpIavcQXSI=
-=mDEN
------END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_annotations-2.23.0.jar.sha1 b/error_prone/error_prone_annotations-2.23.0.jar.sha1
deleted file mode 100644
index 9fb2bd9..0000000
--- a/error_prone/error_prone_annotations-2.23.0.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-43a27853b6c7d54893e0b1997c2c778c347179eb
\ No newline at end of file
diff --git a/error_prone/error_prone_annotations-2.36.0.jar b/error_prone/error_prone_annotations-2.36.0.jar
new file mode 100644
index 0000000..740268b
Binary files /dev/null and b/error_prone/error_prone_annotations-2.36.0.jar differ
diff --git a/error_prone/error_prone_annotations-2.36.0.jar.asc b/error_prone/error_prone_annotations-2.36.0.jar.asc
new file mode 100644
index 0000000..c684b01
--- /dev/null
+++ b/error_prone/error_prone_annotations-2.36.0.jar.asc
@@ -0,0 +1,16 @@
+-----BEGIN PGP SIGNATURE-----
+
+iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmc73gkACgkQ02Srqjmk
+cyAnfRAAis7vXEp/79sLw0XkblPDIwDf38P52Cnpm9dhY9emG00Wz+RuB0W6pbBT
+8Ct6cVtQVE6JPNiDCN+WSoZ/0Pi8ipeoZkmygmz5LZGRdcAGfmM/wOjO/Drxn72B
+eOZyjeHcRVo6C28SpormZHC3cOiqdUp6v8w9DVhwxWuC37vmhFqT4DlZgUfl2J8/
+EUp5+Z3+xgmM5+IJP0fjZOGJXYIyknwQRKJVkUjvbwKFOuT4122zNiPBDLz/58bE
+nAVQ1yvOW9iqnQvEE8IGxcK/9wTakCyfnM3AW+ykedL2sR6yRgtTeExalBeP4QoZ
+Bk7xAyOdUpmpFG9fa2iX8itnATSLkYw0YcBFShNiALw7EDHV/1op1iQCkcTZ4y9U
+BG61c2rpOxu0ylKAVF4JRkndnb7VJhWjohfj4YQ/XfUpBhB9IeaV4hnl7VLuQmV6
+8SFEm++clyhCoE8tyqPPFomm+VfBVz0OywxnTOjFPA44qLdwdlUyc7WHV9vh5UBq
+esiy5RStDr1KgTV3dCp9C92fi7XURCkEqzxo7/gRynos/K15RbbS6x66Ro2Qb2Ws
+YtD61DHGCPYDcftUFb1E+S07PUd5snvLNZjy/A+RTdFGVjzvy2vZlwNQByeyGDQW
+/WCvwYGzGuT6OZE8pIJgWX7paamWY2yV/wkNQ62+2+rHy0alpXA=
+=N2/n
+-----END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_annotations-2.36.0.jar.sha1 b/error_prone/error_prone_annotations-2.36.0.jar.sha1
new file mode 100644
index 0000000..2770835
--- /dev/null
+++ b/error_prone/error_prone_annotations-2.36.0.jar.sha1
@@ -0,0 +1 @@
+227d4d4957ccc3dc5761bd897e3a0ee587e750a7
\ No newline at end of file
diff --git a/error_prone/error_prone_core-2.23.0-with-dependencies.jar.asc b/error_prone/error_prone_core-2.23.0-with-dependencies.jar.asc
deleted file mode 100644
index 9df46fa..0000000
--- a/error_prone/error_prone_core-2.23.0-with-dependencies.jar.asc
+++ /dev/null
@@ -1,16 +0,0 @@
------BEGIN PGP SIGNATURE-----
-
-iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmUwJaAACgkQ02Srqjmk
-cyAx5BAAjZnMJPi2uuuGWytjaN2+N796fIeRlqoNbSSN27BLWZKveE6zVnOPvq2p
-eBSdDhWzg5brPLGiw0GVAnlUWhyxiCr77s6gnPgDklWni64QrbYMuIhuJxmEWMd9
-6nHGAcEVfZSDZJZy1IbB96IQllaRsx2iZGltzjzs4lxrH6v6KRMOc13FnJzuj52X
-tEg+CtM6C2/bILTOt7wrDHjtJEi4RXMUudUyfuarh3U9CsXAYIsgVe9LHg00BPxI
-4f7CID/kGkELzudaC5LIOwkWQ9HnVl1yylmey+iir1DqNqXwkuduR3/h//+ctKB3
-nArPUk4WjtgMtVbGxugOgFVQVdPyBQSRfct0N7F0ebU+77HyZkHAOfrhh1MoYWea
-Px55XfwDldWTLtvZmHKAhZxUkX0R/9a1GAZqGHJ/2bmc4hNGHChfLcT9utpgpg5B
-5koELb9ZMc+dJgry9rDCAaPQx6Fn1ozLvTe5kC6/YZPk1NlPMdcdY9gwx/x0P2To
-nal4muOrjSjEq91sNPpRsHZ06IPxqumwKvQ4+g/bpOYrI2uFTEE1bWjRCDBVqST0
-iYWf00nR6lzXBT0732inMEurngthrPVP6I4FcliYjVLRYO/sSrLxyQXbCl0ESQqP
-E5+1iGtVYzerSgqe2dUmLRiMT+nrmFs6nlSARWVepZRwyUEgFjc=
-=zC99
------END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_core-2.23.0-with-dependencies.jar.sha1 b/error_prone/error_prone_core-2.23.0-with-dependencies.jar.sha1
deleted file mode 100644
index 5467ebc..0000000
--- a/error_prone/error_prone_core-2.23.0-with-dependencies.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-ee64ac4f22941d5d8e4472bf0188b5e59eb9588d
\ No newline at end of file
diff --git a/error_prone/error_prone_core-2.23.0-with-dependencies.jar b/error_prone/error_prone_core-2.36.0-with-dependencies.jar
similarity index 65%
rename from error_prone/error_prone_core-2.23.0-with-dependencies.jar
rename to error_prone/error_prone_core-2.36.0-with-dependencies.jar
index 8f58a20..3708b73 100644
Binary files a/error_prone/error_prone_core-2.23.0-with-dependencies.jar and b/error_prone/error_prone_core-2.36.0-with-dependencies.jar differ
diff --git a/error_prone/error_prone_core-2.36.0-with-dependencies.jar.asc b/error_prone/error_prone_core-2.36.0-with-dependencies.jar.asc
new file mode 100644
index 0000000..f32cd96
--- /dev/null
+++ b/error_prone/error_prone_core-2.36.0-with-dependencies.jar.asc
@@ -0,0 +1,16 @@
+-----BEGIN PGP SIGNATURE-----
+
+iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmc73uEACgkQ02Srqjmk
+cyDFIg//aS0bx8g2OromeFeZmWVLTlKRLi1pF4/kuC89K5Wluq5XU7FVKNIa/hJG
++HZieDN/GC3jrseY2Wp1OS3+WKIlPpoY+VdwHosev/qcPNrtDVt8xLWZ1chK1eOT
+YulIxt1qXCapLatWav1dQGoehmoZtwLG+jPNn/CRzcl9KHLQlV1nkbeLo2g6rqEc
+tRwuui1gFbx0lckVlYf8xtxS0QRIZHlqG4zzF0JCqH5wlHQVsJxpra0dtKvdbPJz
+YfML6P423Nvcnbnew+iEXqRgU8ua/wrJI1hgN3rhroj8hVBBB/FFDQtSPSWG896Q
+lUsCaC2FrMkDo+tVQ8WlorqDgL1DpBN7R1SzzSyv+pYuAjlOpvnZ87RRy+dJUHsC
+OcSVCR3LTiWQNZV6fmki/LuWPf1NQCvxukFa0lRNvmTCIpxbE5Ga8N27q4dMLwzv
+N+r0VVzKIvVf2PTtXvtACvqQK76fDjdkQU/TbFjgGCq4sSN1RM4dmFwIDvR5xkqy
+c1NvEoDzWj5CXYwArlQ1k+x0lfXueBw6Ii4VJIaL5nVVZyB0oPCoACtIeINDwlvu
+DG96vM3JN7Mncpr/Um3kAzZ9Pxik5UH/l9FENte0ttcg/5XS1t7DsooXcXTX0jUk
+hzUN2L9uWcK7ZZbRvoSImNz6ESkvfB4lBUe+sXsMhzSsyvYW59E=
+=U7JC
+-----END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_core-2.36.0-with-dependencies.jar.sha1 b/error_prone/error_prone_core-2.36.0-with-dependencies.jar.sha1
new file mode 100644
index 0000000..a0204e0
--- /dev/null
+++ b/error_prone/error_prone_core-2.36.0-with-dependencies.jar.sha1
@@ -0,0 +1 @@
+3cefb3562928b6e91c13424ae83083994f7230e1
\ No newline at end of file
diff --git a/error_prone/error_prone_test_helpers-2.23.0.jar b/error_prone/error_prone_test_helpers-2.23.0.jar
deleted file mode 100644
index 3e2c6bc..0000000
Binary files a/error_prone/error_prone_test_helpers-2.23.0.jar and /dev/null differ
diff --git a/error_prone/error_prone_test_helpers-2.23.0.jar.asc b/error_prone/error_prone_test_helpers-2.23.0.jar.asc
deleted file mode 100644
index 4512558..0000000
--- a/error_prone/error_prone_test_helpers-2.23.0.jar.asc
+++ /dev/null
@@ -1,16 +0,0 @@
------BEGIN PGP SIGNATURE-----
-
-iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmUwJMcACgkQ02Srqjmk
-cyAXQw//deP2qrMyhOAL3Ce809LMQofPl0PlGibaypQ7cRSDFj/nHspYxTOVzFmL
-YGS7sEX/c/o/W7v+Zwm+870tNSFgRyrTQCvavFwKNXD+318UbzjD3z00GIyfU8bI
-FLIBkEK763opZv/Nau6Dc3QGrILgAYPyZVjmoBnd8mSTJHzuqrSKkfhVdu4CqVMk
-b15NY+Ee7n1ZDozPGQu/YHapgd8GSCPyzUF8oKpIIReBfuRhdmUgGPqVDIk8cPjz
-PuJBvcW0EqoBzaRwtvFBk210JqzAlVXH4cxhtycKqUcpn5JtRPOj4urYGxfJ9gww
-Y1CXtrGYyufN93TKKfHpk8n35EWC/wJrs67+MH1B2VLptzES4RuND3roXRXPW03y
-W2ZWiwAfZUMNuJNRWGeJ/rALtHsCws7mbdOC1D7q40KvxrVF9kKXPKMqr0V97kDt
-+OiWPmf9i3wzKwq1Uo58j4EMQvSo8wAcQfq9Glg2pzDtQsv5SLrBT6U947zjip5S
-plXY4cavlxAvvdS5n8IwsVqJuY/ji7IAhIMie6Zl5aEiKgY9u4z0LhL0TTlrN7B2
-gZ1LR9ybdBWv354hBhTvFz1BELBzLCvdB91pLqBW2oRDutskUOYjhhBpZwZCJElL
-sxXQ4/sxfgMHt/tH4i8Pw2UcGbjZ26DMj1787+XTFgXWYQZvyxA=
-=DvEC
------END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_test_helpers-2.23.0.jar.sha1 b/error_prone/error_prone_test_helpers-2.23.0.jar.sha1
deleted file mode 100644
index 30cc34f..0000000
--- a/error_prone/error_prone_test_helpers-2.23.0.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-961647e808489dc61e6f46e1e2f07a80c161de27
\ No newline at end of file
diff --git a/error_prone/error_prone_test_helpers-2.36.0.jar b/error_prone/error_prone_test_helpers-2.36.0.jar
new file mode 100644
index 0000000..39053cb
Binary files /dev/null and b/error_prone/error_prone_test_helpers-2.36.0.jar differ
diff --git a/error_prone/error_prone_test_helpers-2.36.0.jar.asc b/error_prone/error_prone_test_helpers-2.36.0.jar.asc
new file mode 100644
index 0000000..4f2cd67
--- /dev/null
+++ b/error_prone/error_prone_test_helpers-2.36.0.jar.asc
@@ -0,0 +1,16 @@
+-----BEGIN PGP SIGNATURE-----
+
+iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmc73iIACgkQ02Srqjmk
+cyCAixAAl3/4f7l11jv3NbtuOJeDxTf64bw5NTvRf+YdynQmDJGGbpt9/zYvmZbW
+GiViPEHvncHDc26bvl6qWEAjHKyCJx4mNcIKZahT8qc1jHL1CJSLcMiLb0kVVNqv
+FQLLy7mSyTsRKhvyF1dEDU034zXtDs9lhwbOZijPcqzSbLRa+vorOfFKDG/AfTCJ
+IaD8V7s7GcXzDpBuIXKQlj+zLVi14RJCCVuRjtKrRthE3stusxCDwaLSHarBrT0D
+crPtnyaQg85CzTWddOiVujbjgs5Rgn6fqYuTONpcdXcIvbD3cjl++mZHCgG7Z4of
+jAaGk0OMVVrLgd0sTI5X5gBg+TlZ5yMRKUdiqDTEVGh04VnxoSD7fAcJ3OT1F4Wv
+sZREMA9QfkTuo+3RQexcPJsn7EwF6SLNXysUA3XCtaZ3ibiSpmC5nwCYe2+UzU/1
+Zytl7WGrui/Y0Ubtd5daizBgaQuUVhs5rFAAEiC3qLrENNkC2SNDYKGHWD5BzMQy
+j0Thoa5zNkNS5wW+i6vhkViW8Lljr4PraDxvPcsC6jvLeLfE1QReZVU6vPm8dY28
+MNKq5WP2sNg4cm0GSKRsVtXCI85fDWFQd0eqch1sTwLIYEsym1GmMWAukWkEskLS
+5MhfV6MGSnH+z9k26x+Jn0wJQvswXX8FzMXbjpeneRwSLUrNroM=
+=9R9O
+-----END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_test_helpers-2.36.0.jar.sha1 b/error_prone/error_prone_test_helpers-2.36.0.jar.sha1
new file mode 100644
index 0000000..dde2cb0
--- /dev/null
+++ b/error_prone/error_prone_test_helpers-2.36.0.jar.sha1
@@ -0,0 +1 @@
+fb272f69c7ba9cc46fb517e9889021481517612d
\ No newline at end of file
diff --git a/error_prone/error_prone_type_annotations-2.23.0.jar b/error_prone/error_prone_type_annotations-2.23.0.jar
deleted file mode 100644
index 57092fa..0000000
Binary files a/error_prone/error_prone_type_annotations-2.23.0.jar and /dev/null differ
diff --git a/error_prone/error_prone_type_annotations-2.23.0.jar.asc b/error_prone/error_prone_type_annotations-2.23.0.jar.asc
deleted file mode 100644
index 7da967e..0000000
--- a/error_prone/error_prone_type_annotations-2.23.0.jar.asc
+++ /dev/null
@@ -1,16 +0,0 @@
------BEGIN PGP SIGNATURE-----
-
-iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmUwJMoACgkQ02Srqjmk
-cyAlPQ/8CJ55k4b0Y/oCWKcdj8OjRoTKK1OU6z+ef9jQ5WyVM33Q0wAz3USKkl6X
-/NoOnEUwahJ/rK5ZK9CDJCJCB3R8R6NEITBWOhEs8sw8/S2hrazMFLNnSj2B+Vnt
-tAgOPQq/6GgTjWf6jqhXeohFmniTNiEgsb7MXbCeoGqMriq++T50dlQZzhjwpOOy
-a0lhp4vYUpriobVHtAXXnpOCknUgkiqnKO8unqzbUZuJW1NROC8WjhZ2UoqnrqTz
-JJp5I9RG9cG9jb9bnWAvRo9PDF8t8+kkp4zMWGj6uX2puWIR5fmFMREHuhzRjsGF
-/Fo/LYdkTev2I2GVwmubZYTN/U3a+oMyLdnykpsOTXz4dmthn7P7V/M/GWt8YRkb
-IZM8hwmC5kajurFSOgmy/WKt5C7wJ1xqWd+fLwcWsZrTWzfx2EElb/+LxKE+Ex5J
-1eNyhkIkc0l/WIfWJPI0R2CsH9bFC2wJBF7TdTxI4dwrYUP2I1pnFVPC/qxUnlkY
-m8b7Jr2CdnBIGH099E+taiQpzYtEf7z1gSbc+H+hmha83zKacVFD/vY5OHldEeom
-hwAKaiCetVJfvoNeIJ0Em5QZnrwRjQ7ykqv09ExpVMOJuVf4ZreR7uWE75p8Y7uO
-pcv10QXwrf0+MqjUX/8yZhcgwUuKL0BMWeEtpQATBDd6ahss2q8=
-=Pe3J
------END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_type_annotations-2.23.0.jar.sha1 b/error_prone/error_prone_type_annotations-2.23.0.jar.sha1
deleted file mode 100644
index cf927e5..0000000
--- a/error_prone/error_prone_type_annotations-2.23.0.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-6d4e88342dfb4c1a2c90cc1735abd6e3e96d0a44
\ No newline at end of file
diff --git a/error_prone/error_prone_type_annotations-2.36.0.jar b/error_prone/error_prone_type_annotations-2.36.0.jar
new file mode 100644
index 0000000..e63a437
Binary files /dev/null and b/error_prone/error_prone_type_annotations-2.36.0.jar differ
diff --git a/error_prone/error_prone_type_annotations-2.36.0.jar.asc b/error_prone/error_prone_type_annotations-2.36.0.jar.asc
new file mode 100644
index 0000000..98549b7
--- /dev/null
+++ b/error_prone/error_prone_type_annotations-2.36.0.jar.asc
@@ -0,0 +1,16 @@
+-----BEGIN PGP SIGNATURE-----
+
+iQIzBAABCgAdFiEE7gyocwdAkvgG9Ztl02SrqjmkcyAFAmc73iYACgkQ02Srqjmk
+cyC1JxAAiPcs5CylbY/xdJN61fY80/B4TizLuS3jJ9vpIACK4evwB+mM9n9Xlueo
+2PfTYQROnYTaMJoL26cwUG1AD7q297zq1hfvmQhUqXCs0CznTk2Ku8dSW0G9cFWO
+6NpaGkdMsOhUdGkwUE962JUMZReONtg7Z2+CP6XZo9m0+PfUMYqCOWaKkaFtKjF+
+eSz0FuEYQ7GYSxkQ5XuiQFJsZOLW0jKplF5llaCgt8SKt3I6oloI69FMdtoabVhr
++NhD6g5eH89517EiUfrekpjeIQ/riuXsCO5bpH82/LLNOe4IF6ckamhZbTvyrx3O
+EUd6ouBQxN693p8uz7bCgwhXFsSfEhuYs9fXFob45bGbInAf3KWvKHYl0rp2vFO0
+8+WR8+FS5GXJYNQGAnqas9md6cyZBu+Fz1rtf/BWnF2wSbDfKa3mLOc5cCqF1PhZ
+2fGg0Ii5SeTinshyfoC7MNoczNU6OxSGe/e5VTG+T+C8fKNnKbbzBOjcuFpSF42A
+zRdblncF1GtlgcgfMDJZC8W6yCUL4WK04l0yyGVdz4C3rHGxUVxNhyn4U9JPCAgs
+bm+1r5sgD1qcob1SzXlHhqJGI4YclNuDa42FK4DzZCSTux8Z8PX7R/udzgHFZJJo
+yuEkDjwgwD8AKyHvBaZzp0boHbsFBANeYeuPDYefn6A2LK0Sfdc=
+=TflN
+-----END PGP SIGNATURE-----
diff --git a/error_prone/error_prone_type_annotations-2.36.0.jar.sha1 b/error_prone/error_prone_type_annotations-2.36.0.jar.sha1
new file mode 100644
index 0000000..d106798
--- /dev/null
+++ b/error_prone/error_prone_type_annotations-2.36.0.jar.sha1
@@ -0,0 +1 @@
+e8cf97ae8ae15010636e6847b3715d1cfb559420
\ No newline at end of file
diff --git a/javac/Android.bp b/javac/Android.bp
deleted file mode 100644
index d9d74b8..0000000
--- a/javac/Android.bp
+++ /dev/null
@@ -1,30 +0,0 @@
-// Copyright (C) 2022 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["external_error_prone_javac_license"],
-}
-
-license {
-    name: "external_error_prone_javac_license",
-    package_name: "Google Error Prone javac",
-    license_kinds: ["SPDX-license-identifier-GPL-2.0-with-classpath-exception"],
-    license_text: ["LICENSE"],
-}
-
-java_import {
-    name: "error_prone_javac",
-    host_supported: true,
-    jars: ["javac-9+181-r4173-1.jar"],
-}
diff --git a/javac/LICENSE b/javac/LICENSE
deleted file mode 100644
index fd91b6f..0000000
--- a/javac/LICENSE
+++ /dev/null
@@ -1,363 +0,0 @@
-                    GNU GENERAL PUBLIC LICENSE
-                       Version 2, June 1991
-
- Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
- Everyone is permitted to copy and distribute verbatim copies
- of this license document, but changing it is not allowed.
-
-                            Preamble
-
-  The licenses for most software are designed to take away your
-freedom to share and change it.  By contrast, the GNU General Public
-License is intended to guarantee your freedom to share and change free
-software--to make sure the software is free for all its users.  This
-General Public License applies to most of the Free Software
-Foundation's software and to any other program whose authors commit to
-using it.  (Some other Free Software Foundation software is covered by
-the GNU Lesser General Public License instead.)  You can apply it to
-your programs, too.
-
-  When we speak of free software, we are referring to freedom, not
-price.  Our General Public Licenses are designed to make sure that you
-have the freedom to distribute copies of free software (and charge for
-this service if you wish), that you receive source code or can get it
-if you want it, that you can change the software or use pieces of it
-in new free programs; and that you know you can do these things.
-
-  To protect your rights, we need to make restrictions that forbid
-anyone to deny you these rights or to ask you to surrender the rights.
-These restrictions translate to certain responsibilities for you if you
-distribute copies of the software, or if you modify it.
-
-  For example, if you distribute copies of such a program, whether
-gratis or for a fee, you must give the recipients all the rights that
-you have.  You must make sure that they, too, receive or can get the
-source code.  And you must show them these terms so they know their
-rights.
-
-  We protect your rights with two steps: (1) copyright the software, and
-(2) offer you this license which gives you legal permission to copy,
-distribute and/or modify the software.
-
-  Also, for each author's protection and ours, we want to make certain
-that everyone understands that there is no warranty for this free
-software.  If the software is modified by someone else and passed on, we
-want its recipients to know that what they have is not the original, so
-that any problems introduced by others will not reflect on the original
-authors' reputations.
-
-  Finally, any free program is threatened constantly by software
-patents.  We wish to avoid the danger that redistributors of a free
-program will individually obtain patent licenses, in effect making the
-program proprietary.  To prevent this, we have made it clear that any
-patent must be licensed for everyone's free use or not licensed at all.
-
-  The precise terms and conditions for copying, distribution and
-modification follow.
-
-                    GNU GENERAL PUBLIC LICENSE
-   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
-
-  0. This License applies to any program or other work which contains
-a notice placed by the copyright holder saying it may be distributed
-under the terms of this General Public License.  The "Program", below,
-refers to any such program or work, and a "work based on the Program"
-means either the Program or any derivative work under copyright law:
-that is to say, a work containing the Program or a portion of it,
-either verbatim or with modifications and/or translated into another
-language.  (Hereinafter, translation is included without limitation in
-the term "modification".)  Each licensee is addressed as "you".
-
-Activities other than copying, distribution and modification are not
-covered by this License; they are outside its scope.  The act of
-running the Program is not restricted, and the output from the Program
-is covered only if its contents constitute a work based on the
-Program (independent of having been made by running the Program).
-Whether that is true depends on what the Program does.
-
-  1. You may copy and distribute verbatim copies of the Program's
-source code as you receive it, in any medium, provided that you
-conspicuously and appropriately publish on each copy an appropriate
-copyright notice and disclaimer of warranty; keep intact all the
-notices that refer to this License and to the absence of any warranty;
-and give any other recipients of the Program a copy of this License
-along with the Program.
-
-You may charge a fee for the physical act of transferring a copy, and
-you may at your option offer warranty protection in exchange for a fee.
-
-  2. You may modify your copy or copies of the Program or any portion
-of it, thus forming a work based on the Program, and copy and
-distribute such modifications or work under the terms of Section 1
-above, provided that you also meet all of these conditions:
-
-    a) You must cause the modified files to carry prominent notices
-    stating that you changed the files and the date of any change.
-
-    b) You must cause any work that you distribute or publish, that in
-    whole or in part contains or is derived from the Program or any
-    part thereof, to be licensed as a whole at no charge to all third
-    parties under the terms of this License.
-
-    c) If the modified program normally reads commands interactively
-    when run, you must cause it, when started running for such
-    interactive use in the most ordinary way, to print or display an
-    announcement including an appropriate copyright notice and a
-    notice that there is no warranty (or else, saying that you provide
-    a warranty) and that users may redistribute the program under
-    these conditions, and telling the user how to view a copy of this
-    License.  (Exception: if the Program itself is interactive but
-    does not normally print such an announcement, your work based on
-    the Program is not required to print an announcement.)
-
-These requirements apply to the modified work as a whole.  If
-identifiable sections of that work are not derived from the Program,
-and can be reasonably considered independent and separate works in
-themselves, then this License, and its terms, do not apply to those
-sections when you distribute them as separate works.  But when you
-distribute the same sections as part of a whole which is a work based
-on the Program, the distribution of the whole must be on the terms of
-this License, whose permissions for other licensees extend to the
-entire whole, and thus to each and every part regardless of who wrote it.
-
-Thus, it is not the intent of this section to claim rights or contest
-your rights to work written entirely by you; rather, the intent is to
-exercise the right to control the distribution of derivative or
-collective works based on the Program.
-
-In addition, mere aggregation of another work not based on the Program
-with the Program (or with a work based on the Program) on a volume of
-a storage or distribution medium does not bring the other work under
-the scope of this License.
-
-  3. You may copy and distribute the Program (or a work based on it,
-under Section 2) in object code or executable form under the terms of
-Sections 1 and 2 above provided that you also do one of the following:
-
-    a) Accompany it with the complete corresponding machine-readable
-    source code, which must be distributed under the terms of Sections
-    1 and 2 above on a medium customarily used for software interchange; or,
-
-    b) Accompany it with a written offer, valid for at least three
-    years, to give any third party, for a charge no more than your
-    cost of physically performing source distribution, a complete
-    machine-readable copy of the corresponding source code, to be
-    distributed under the terms of Sections 1 and 2 above on a medium
-    customarily used for software interchange; or,
-
-    c) Accompany it with the information you received as to the offer
-    to distribute corresponding source code.  (This alternative is
-    allowed only for noncommercial distribution and only if you
-    received the program in object code or executable form with such
-    an offer, in accord with Subsection b above.)
-
-The source code for a work means the preferred form of the work for
-making modifications to it.  For an executable work, complete source
-code means all the source code for all modules it contains, plus any
-associated interface definition files, plus the scripts used to
-control compilation and installation of the executable.  However, as a
-special exception, the source code distributed need not include
-anything that is normally distributed (in either source or binary
-form) with the major components (compiler, kernel, and so on) of the
-operating system on which the executable runs, unless that component
-itself accompanies the executable.
-
-If distribution of executable or object code is made by offering
-access to copy from a designated place, then offering equivalent
-access to copy the source code from the same place counts as
-distribution of the source code, even though third parties are not
-compelled to copy the source along with the object code.
-
-  4. You may not copy, modify, sublicense, or distribute the Program
-except as expressly provided under this License.  Any attempt
-otherwise to copy, modify, sublicense or distribute the Program is
-void, and will automatically terminate your rights under this License.
-However, parties who have received copies, or rights, from you under
-this License will not have their licenses terminated so long as such
-parties remain in full compliance.
-
-  5. You are not required to accept this License, since you have not
-signed it.  However, nothing else grants you permission to modify or
-distribute the Program or its derivative works.  These actions are
-prohibited by law if you do not accept this License.  Therefore, by
-modifying or distributing the Program (or any work based on the
-Program), you indicate your acceptance of this License to do so, and
-all its terms and conditions for copying, distributing or modifying
-the Program or works based on it.
-
-  6. Each time you redistribute the Program (or any work based on the
-Program), the recipient automatically receives a license from the
-original licensor to copy, distribute or modify the Program subject to
-these terms and conditions.  You may not impose any further
-restrictions on the recipients' exercise of the rights granted herein.
-You are not responsible for enforcing compliance by third parties to
-this License.
-
-  7. If, as a consequence of a court judgment or allegation of patent
-infringement or for any other reason (not limited to patent issues),
-conditions are imposed on you (whether by court order, agreement or
-otherwise) that contradict the conditions of this License, they do not
-excuse you from the conditions of this License.  If you cannot
-distribute so as to satisfy simultaneously your obligations under this
-License and any other pertinent obligations, then as a consequence you
-may not distribute the Program at all.  For example, if a patent
-license would not permit royalty-free redistribution of the Program by
-all those who receive copies directly or indirectly through you, then
-the only way you could satisfy both it and this License would be to
-refrain entirely from distribution of the Program.
-
-If any portion of this section is held invalid or unenforceable under
-any particular circumstance, the balance of the section is intended to
-apply and the section as a whole is intended to apply in other
-circumstances.
-
-It is not the purpose of this section to induce you to infringe any
-patents or other property right claims or to contest validity of any
-such claims; this section has the sole purpose of protecting the
-integrity of the free software distribution system, which is
-implemented by public license practices.  Many people have made
-generous contributions to the wide range of software distributed
-through that system in reliance on consistent application of that
-system; it is up to the author/donor to decide if he or she is willing
-to distribute software through any other system and a licensee cannot
-impose that choice.
-
-This section is intended to make thoroughly clear what is believed to
-be a consequence of the rest of this License.
-
-  8. If the distribution and/or use of the Program is restricted in
-certain countries either by patents or by copyrighted interfaces, the
-original copyright holder who places the Program under this License
-may add an explicit geographical distribution limitation excluding
-those countries, so that distribution is permitted only in or among
-countries not thus excluded.  In such case, this License incorporates
-the limitation as if written in the body of this License.
-
-  9. The Free Software Foundation may publish revised and/or new versions
-of the General Public License from time to time.  Such new versions will
-be similar in spirit to the present version, but may differ in detail to
-address new problems or concerns.
-
-Each version is given a distinguishing version number.  If the Program
-specifies a version number of this License which applies to it and "any
-later version", you have the option of following the terms and conditions
-either of that version or of any later version published by the Free
-Software Foundation.  If the Program does not specify a version number of
-this License, you may choose any version ever published by the Free Software
-Foundation.
-
-  10. If you wish to incorporate parts of the Program into other free
-programs whose distribution conditions are different, write to the author
-to ask for permission.  For software which is copyrighted by the Free
-Software Foundation, write to the Free Software Foundation; we sometimes
-make exceptions for this.  Our decision will be guided by the two goals
-of preserving the free status of all derivatives of our free software and
-of promoting the sharing and reuse of software generally.
-
-                            NO WARRANTY
-
-  11. BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
-FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
-OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
-PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
-OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
-MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
-TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
-PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
-REPAIR OR CORRECTION.
-
-  12. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
-WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
-REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
-INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
-OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
-TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
-YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
-PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
-POSSIBILITY OF SUCH DAMAGES.
-
-                     END OF TERMS AND CONDITIONS
-
-            How to Apply These Terms to Your New Programs
-
-  If you develop a new program, and you want it to be of the greatest
-possible use to the public, the best way to achieve this is to make it
-free software which everyone can redistribute and change under these terms.
-
-  To do so, attach the following notices to the program.  It is safest
-to attach them to the start of each source file to most effectively
-convey the exclusion of warranty; and each file should have at least
-the "copyright" line and a pointer to where the full notice is found.
-
-    <one line to give the program's name and a brief idea of what it does.>
-    Copyright (C) <year>  <name of author>
-
-    This program is free software; you can redistribute it and/or modify
-    it under the terms of the GNU General Public License as published by
-    the Free Software Foundation; either version 2 of the License, or
-    (at your option) any later version.
-
-    This program is distributed in the hope that it will be useful,
-    but WITHOUT ANY WARRANTY; without even the implied warranty of
-    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-    GNU General Public License for more details.
-
-    You should have received a copy of the GNU General Public License along
-    with this program; if not, write to the Free Software Foundation, Inc.,
-    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
-
-Also add information on how to contact you by electronic and paper mail.
-
-If the program is interactive, make it output a short notice like this
-when it starts in an interactive mode:
-
-    Gnomovision version 69, Copyright (C) year name of author
-    Gnomovision comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
-    This is free software, and you are welcome to redistribute it
-    under certain conditions; type `show c' for details.
-
-The hypothetical commands `show w' and `show c' should show the appropriate
-parts of the General Public License.  Of course, the commands you use may
-be called something other than `show w' and `show c'; they could even be
-mouse-clicks or menu items--whatever suits your program.
-
-You should also get your employer (if you work as a programmer) or your
-school, if any, to sign a "copyright disclaimer" for the program, if
-necessary.  Here is a sample; alter the names:
-
-  Yoyodyne, Inc., hereby disclaims all copyright interest in the program
-  `Gnomovision' (which makes passes at compilers) written by James Hacker.
-
-  <signature of Ty Coon>, 1 April 1989
-  Ty Coon, President of Vice
-
-This General Public License does not permit incorporating your program into
-proprietary programs.  If your program is a subroutine library, you may
-consider it more useful to permit linking proprietary applications with the
-library.  If this is what you want to do, use the GNU Lesser General
-Public License instead of this License.
-
-
-"CLASSPATH" EXCEPTION TO THE GPL
-
-Certain source files distributed by Oracle America and/or its affiliates are
-subject to the following clarification and special exception to the GPL, but
-only where Oracle has expressly included in the particular source file's header
-the words "Oracle designates this particular file as subject to the "Classpath"
-exception as provided by Oracle in the LICENSE file that accompanied this code."
-
-    Linking this library statically or dynamically with other modules is making
-    a combined work based on this library.  Thus, the terms and conditions of
-    the GNU General Public License cover the whole combination.
-
-    As a special exception, the copyright holders of this library give you
-    permission to link this library with independent modules to produce an
-    executable, regardless of the license terms of these independent modules,
-    and to copy and distribute the resulting executable under terms of your
-    choice, provided that you also meet, for each linked independent module,
-    the terms and conditions of the license of that module.  An independent
-    module is a module which is not derived from or based on this library.  If
-    you modify this library, you may extend this exception to your version of
-    the library, but you are not obligated to do so.  If you do not wish to do
-    so, delete this exception statement from your version.
diff --git a/javac/METADATA b/javac/METADATA
deleted file mode 100644
index dae8662..0000000
--- a/javac/METADATA
+++ /dev/null
@@ -1,16 +0,0 @@
-name: "errorprone_javac"
-description:
-    "A repackaged copy of javac for error-prone to depend on"
-
-third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/google/error-prone-javac"
-  }
-  url {
-    type: ARCHIVE
-    value: "https://oss.sonatype.org/service/local/repositories/releases/content/com/google/errorprone/javac/9+181-r4173-1/javac-9+181-r4173-1.jar"
-  }
-  version: "9+181-r4173-1"
-  last_upgrade_date { year: 2023 month: 11 day: 14}
-}
diff --git a/javac/MODULE_LICENSE_GPL_WITH_CLASSPATH_EXCEPTION b/javac/MODULE_LICENSE_GPL_WITH_CLASSPATH_EXCEPTION
deleted file mode 100644
index e69de29..0000000
diff --git a/javac/javac-9+181-r4173-1-sources.jar b/javac/javac-9+181-r4173-1-sources.jar
deleted file mode 100644
index 8a1f20f..0000000
Binary files a/javac/javac-9+181-r4173-1-sources.jar and /dev/null differ
diff --git a/javac/javac-9+181-r4173-1-sources.jar.asc b/javac/javac-9+181-r4173-1-sources.jar.asc
deleted file mode 100644
index 0e55092..0000000
--- a/javac/javac-9+181-r4173-1-sources.jar.asc
+++ /dev/null
@@ -1,17 +0,0 @@
------BEGIN PGP SIGNATURE-----
-Version: GnuPG v1
-
-iQIcBAABAgAGBQJaTmrPAAoJEJolnH7mNsXtukEP+gLBpkD/I+ItgvjuPFtRkcp2
-5LCyrcVUxES2qN2w/uWGwSpr9W15qoC90LP+KzW9AFZpPwKKs7fyLaApImxCBqQv
-fktP5FlQajVXquIhzPJCsxUQzW5YI9n3pOdC7vRrkMW0xnlVbbl9g1N6TVbf6p2l
-mFimjYS3ztoPEj/RJVW9AsdW6IenPi8VDLlBmAx5lpl3HhonX1vcjPx1wGj7XjeU
-bcz6XSncV+N71rjbwAFgxoXkJv3FpSSGRg+6wps5bnzFs3BsRYVMFm5Dlm6lUQBC
-5DfPRl37VfFKpxmBkl5lvyV5OFpFe618LiLy5nRxTqlZC/S2XLkJbF7sJkXJeszT
-3WCOUo9kFzQx+MNXm9HSPoS2YajomnMYxyBTFcEYexHDpqTcfsrPfMRkpFRFm/EN
-/XF27pnWi/qTSGP+15PCmBjFdtF0Acl8GCdknI4vz6zrWznpc4xOJ6shQMTmtpEW
-U4xsBBll+3abkoCCLvEtDwPZZT/uJiIzd9mG0HkjMIZxsNPLA4iqvGnLe3lr70J/
-q9EwQXKeAyyobLPMmt252qSJ0QZGIPOKIHsvPUwMODvqNZt4Qpv1O67oQD2xD119
-kWqvgZtLUeghFYUtjQYWmZcK9Z6m7gocqV899HxL1CWGYNAStKHl4k9JRRxZlxNU
-zaWTYBT6rO3gESminVVH
-=Tp0A
------END PGP SIGNATURE-----
diff --git a/javac/javac-9+181-r4173-1-sources.jar.sha1 b/javac/javac-9+181-r4173-1-sources.jar.sha1
deleted file mode 100644
index 50fb4f4..0000000
--- a/javac/javac-9+181-r4173-1-sources.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-8180e0b5be81aa91a2edb26cfe079c65dc2fc813
\ No newline at end of file
diff --git a/javac/javac-9+181-r4173-1.jar b/javac/javac-9+181-r4173-1.jar
deleted file mode 100644
index 168633d..0000000
Binary files a/javac/javac-9+181-r4173-1.jar and /dev/null differ
diff --git a/javac/javac-9+181-r4173-1.jar.asc b/javac/javac-9+181-r4173-1.jar.asc
deleted file mode 100644
index ae8c163..0000000
--- a/javac/javac-9+181-r4173-1.jar.asc
+++ /dev/null
@@ -1,17 +0,0 @@
------BEGIN PGP SIGNATURE-----
-Version: GnuPG v1
-
-iQIcBAABAgAGBQJaTmrAAAoJEJolnH7mNsXt50AQAJBrZEefogwtFcjds7LqgxD+
-YltYISa0Wzis5sy0zrzNUhJAumoa1INk13Ft9mdkAovTM+Bzz1C8Gyk67dLik93W
-tP9TijNOt+/QHEouIsDJkf/PbR1PC5vLJgUv4tjEnQvEYYTIy2jYgzH+Lo1A+anw
-uRr0hhFbZA8xXGMhPWyaYAIz+MuG6cSwUlpzUaxL1E6x+hpLEkzeLF5eGZcHGSDJ
-V0Ion6Li5Z+kuWpZLA0/V6CBsq6LLiZRJYIdUnz1uKizaeBeetXWMTEWDd3WQV22
-pIklIC2qgx1JerWaa1Yy6fwTEEFWK1lvkDndIy9GmAmseC6cqPFv114s88L5MzGS
-QgnFiEXxNMV4sVEo0/9EGA7TXNo9CIcHuAy5n/0Pw/mz5dBWUCDHt3fa8dcHpNi2
-3PLRfyUDiRicluzhBGAxZ9F/BiUxgwMu0ycVXnz0Uwl2j8EzSxXLMclSQiMgmXFa
-Ss+ecNw1k1LeTjY3GzYqgND1uja2gOO5YnonkW2AWjBwAwwuI0LvXG4ttfdRQa95
-7crezxObuOHWt6JpgOKFSRxO3VZyBbWUvbwmqJbMGcdEMjBxJSqFPFCAAm0X6rC+
-xTLL6vUHjOYEYPE8OsdA8QLOd1SPO2HxKaGAsAOXfrR4ZlRcKj20ob6U2/iaWt6p
-xkcwrph9vSMYToEAMOQZ
-=CEvz
------END PGP SIGNATURE-----
diff --git a/javac/javac-9+181-r4173-1.jar.sha1 b/javac/javac-9+181-r4173-1.jar.sha1
deleted file mode 100644
index 66e5d08..0000000
--- a/javac/javac-9+181-r4173-1.jar.sha1
+++ /dev/null
@@ -1 +0,0 @@
-bdf4c0aa7d540ee1f7bf14d47447aea4bbf450c5
\ No newline at end of file
diff --git a/soong/error_prone.go b/soong/error_prone.go
index 7660ea5..5d66a3c 100644
--- a/soong/error_prone.go
+++ b/soong/error_prone.go
@@ -22,9 +22,9 @@ func init() {
 	// These values are set into build/soong/java/config/config.go so that soong doesn't have any
 	// references to external/error_prone, which may not always exist.
 	config.ErrorProneClasspath = []string{
-		"external/error_prone/error_prone/error_prone_core-2.23.0-with-dependencies.jar",
-		"external/error_prone/error_prone/error_prone_annotations-2.23.0.jar",
-		"external/error_prone/error_prone/error_prone_type_annotations-2.23.0.jar",
+		"external/error_prone/error_prone/error_prone_core-2.36.0-with-dependencies.jar",
+		"external/error_prone/error_prone/error_prone_annotations-2.36.0.jar",
+		"external/error_prone/error_prone/error_prone_type_annotations-2.36.0.jar",
 		"external/error_prone/checkerframework/dataflow-errorprone-3.39.0.jar",
 		"external/error_prone/jFormatString/jFormatString-3.0.0.jar",
 	}
@@ -73,7 +73,6 @@ func init() {
 		"-Xep:JUnit4ClassAnnotationNonStatic:ERROR",
 		"-Xep:JUnit4SetUpNotRun:ERROR",
 		"-Xep:JUnit4TearDownNotRun:ERROR",
-		"-Xep:JUnit4TestNotRun:ERROR",
 		"-Xep:JUnitAssertSameCheck:ERROR",
 		"-Xep:JavaxInjectOnAbstractMethod:ERROR",
 		"-Xep:LiteByteStringUtf8:ERROR",
@@ -116,13 +115,14 @@ func init() {
 		"-Xep:ComparisonOutOfRange:WARN",
 		"-Xep:EqualsHashCode:WARN",
 		"-Xep:GuardedBy:WARN",
-		"-Xep:IgnoredPureGetter:WARN",
 		"-Xep:ImmutableAnnotationChecker:WARN",
 		"-Xep:ImmutableEnumChecker:WARN",
 		"-Xep:IsLoggableTagLength:WARN",
+		"-Xep:JUnit4TestNotRun:WARN",
 		"-Xep:MissingSuperCall:WARN",
 		"-Xep:RectIntersectReturnValueIgnored:WARN",
-		"-Xep:ReturnValueIgnored:WARN",
+		"-Xep:SelfAssertion:WARN",
+		"-Xep:DuplicateBranches:WARN",
 	}
 
 	// The checks that are default-disabled
@@ -155,6 +155,9 @@ func init() {
 		// requirement. The warning is overtriggered when source depends on the API stubs, which
 		// may not include the toString() method.
 		"-Xep:ObjectToString:OFF",
+		// Disable the check which is introduced by the Java target 21 until modules 
+		// can be fixed individually (b/377918299).
+		"-Xep:PatternMatchingInstanceof:OFF",
 	}
 
 	config.ErrorProneFlags = []string{
@@ -166,6 +169,8 @@ func init() {
 		"-XDuseStructuralMostSpecificResolution=true",
 		"-XDuseGraphInference=true",
 		"-XDandroidCompatible=true",
+		// https://github.com/google/error-prone/issues/4595#issuecomment-2424140062
+		"--should-stop=ifError=FLOW",
 		// As we emit errors as warnings,
 		// increase the warning limit.
 		"-Xmaxwarns 9999999",
@@ -173,14 +178,14 @@ func init() {
 		// Extra flags needed by ErrorProne for OpenJDK9 from
 		// http://errorprone.info/docs/installation
 		"-J--add-exports=jdk.compiler/com.sun.tools.javac.api=ALL-UNNAMED",
-		"-J--add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED",
-		"-J--add-exports=jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED",
+		"-J--add-exports=jdk.compiler/com.sun.tools.javac.file=ALL-UNNAMED",
 		"-J--add-exports=jdk.compiler/com.sun.tools.javac.main=ALL-UNNAMED",
-		"-J--add-exports=jdk.compiler/com.sun.tools.javac.code=ALL-UNNAMED",
-		"-J--add-exports=jdk.compiler/com.sun.tools.javac.processing=ALL-UNNAMED",
-		"-J--add-exports=jdk.compiler/com.sun.tools.javac.parser=ALL-UNNAMED",
 		"-J--add-exports=jdk.compiler/com.sun.tools.javac.model=ALL-UNNAMED",
-		"-J--add-exports=jdk.compiler/com.sun.tools.javac.comp=ALL-UNNAMED",
+		"-J--add-exports=jdk.compiler/com.sun.tools.javac.parser=ALL-UNNAMED",
+		"-J--add-exports=jdk.compiler/com.sun.tools.javac.processing=ALL-UNNAMED",
+		"-J--add-exports=jdk.compiler/com.sun.tools.javac.tree=ALL-UNNAMED",
+		"-J--add-exports=jdk.compiler/com.sun.tools.javac.util=ALL-UNNAMED",
+		"-J--add-opens=jdk.compiler/com.sun.tools.javac.code=ALL-UNNAMED",
 		"-J--add-opens=jdk.compiler/com.sun.tools.javac.comp=ALL-UNNAMED",
 	}
 }
diff --git a/update.sh b/update.sh
index db399d5..270e886 100755
--- a/update.sh
+++ b/update.sh
@@ -2,7 +2,7 @@
 # Force stop on first error.
 set -e
 if [ $# -ne 2 -a $# -ne 3 ]; then
-    echo "$0 <error prone version> <error prone javac version> [checkerframework version]" >&2
+    echo "$0 <error prone version> [checkerframework version]" >&2
     exit 1;
 fi
 if [ -z "$ANDROID_BUILD_TOP" ]; then
@@ -10,16 +10,13 @@ if [ -z "$ANDROID_BUILD_TOP" ]; then
     exit 1
 fi
 EP_VERSION="$1"
-JAVAC_VERSION="$2"
 # checkerframework
-CF_VERSION="$3"
+CF_VERSION="$2"
 JAR_REPO="https://oss.sonatype.org/service/local/repositories/releases/content/com/google/errorprone"
 EP_JAR_URL="${JAR_REPO}/error_prone_core/${EP_VERSION}/error_prone_core-${EP_VERSION}-with-dependencies.jar"
 EP_ANNO_JAR_URL="${JAR_REPO}/error_prone_annotations/${EP_VERSION}/error_prone_annotations-${EP_VERSION}.jar"
 EP_TYPE_ANNO_JAR_URL="${JAR_REPO}/error_prone_type_annotations/${EP_VERSION}/error_prone_type_annotations-${EP_VERSION}.jar"
 EP_TEST_HELPERS_JAR_URL="${JAR_REPO}/error_prone_test_helpers/${EP_VERSION}/error_prone_test_helpers-${EP_VERSION}.jar"
-JAVAC_JAR_URL="${JAR_REPO}/javac/${JAVAC_VERSION}/javac-${JAVAC_VERSION}.jar"
-JAVAC_SOURCES_JAR_URL="${JAR_REPO}/javac/${JAVAC_VERSION}/javac-${JAVAC_VERSION}-sources.jar"
 CF_DATAFLOW_JAR_URL="https://repo1.maven.org/maven2/org/checkerframework/dataflow-errorprone/${CF_VERSION}/dataflow-errorprone-${CF_VERSION}.jar"
 CF_DATAFLOW_SOURCES_JAR_URL="https://repo1.maven.org/maven2/org/checkerframework/dataflow-errorprone/${CF_VERSION}/dataflow-errorprone-${CF_VERSION}-sources.jar"
 TOOLS_DIR=$(dirname $0)
@@ -41,18 +38,14 @@ function update_jar {
 }
 
 rm -f error_prone/*.jar*
-rm -f javac/*.jar*
 
 update_jar "${EP_VERSION}" "${EP_JAR_URL}" "${TOOLS_DIR}/error_prone"
 update_jar "${EP_VERSION}" "${EP_ANNO_JAR_URL}" "${TOOLS_DIR}/error_prone"
 update_jar "${EP_VERSION}" "${EP_TYPE_ANNO_JAR_URL}" "${TOOLS_DIR}/error_prone"
 update_jar "${EP_VERSION}" "${EP_TEST_HELPERS_JAR_URL}" "${TOOLS_DIR}/error_prone"
-update_jar "${JAVAC_VERSION}" "${JAVAC_SOURCES_JAR_URL}" "${TOOLS_DIR}/javac"
-update_jar "${JAVAC_VERSION}" "${JAVAC_JAR_URL}" "${TOOLS_DIR}/javac"
 
 # Update the versions in the build file
 perl -pi -e "\
-    s|\"(javac/javac).*\"|\"\\1-${JAVAC_VERSION}.jar\"|;\
     s|\"(error_prone/error_prone_core).*\"|\"\\1-${EP_VERSION}-with-dependencies.jar\"|;\
     s|\"(error_prone/error_prone_annotations).*\"|\"\\1-${EP_VERSION}.jar\"|;\
     s|\"(error_prone/error_prone_type_annotations).*\"|\"\\1-${EP_VERSION}.jar\"|;\
@@ -61,7 +54,6 @@ perl -pi -e "\
 
 # Update the versions for soong
 perl -pi -e "\
-    s|\"(external/error_prone/javac/javac).*\"|\"\\1-${JAVAC_VERSION}.jar\"|;\
     s|\"(external/error_prone/error_prone/error_prone_core).*\"|\"\\1-${EP_VERSION}-with-dependencies.jar\"|;\
     s|\"(external/error_prone/error_prone/error_prone_annotations).*\"|\"\\1-${EP_VERSION}.jar\"|;\
     s|\"(external/error_prone/error_prone/error_prone_type_annotations).*\"|\"\\1-${EP_VERSION}.jar\"|;\
```

