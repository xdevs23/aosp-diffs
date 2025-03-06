```diff
diff --git a/.gitmodules b/.gitmodules
deleted file mode 100644
index 06f3c42..0000000
--- a/.gitmodules
+++ /dev/null
@@ -1,39 +0,0 @@
-[submodule "aws-common-runtime/aws-c-common"]
-	path = crt/aws-c-common
-	url = https://github.com/awslabs/aws-c-common.git
-[submodule "aws-common-runtime/aws-c-io"]
-	path = crt/aws-c-io
-	url = https://github.com/awslabs/aws-c-io.git
-[submodule "aws-common-runtime/aws-c-compression"]
-	path = crt/aws-c-compression
-	url = https://github.com/awslabs/aws-c-compression.git
-[submodule "aws-common-runtime/aws-c-cal"]
-	path = crt/aws-c-cal
-	url = https://github.com/awslabs/aws-c-cal.git
-[submodule "aws-common-runtime/aws-c-auth"]
-	path = crt/aws-c-auth
-	url = https://github.com/awslabs/aws-c-auth.git
-[submodule "aws-common-runtime/aws-c-http"]
-	path = crt/aws-c-http
-	url = https://github.com/awslabs/aws-c-http.git
-[submodule "aws-common-runtime/aws-c-mqtt"]
-	path = crt/aws-c-mqtt
-	url = https://github.com/awslabs/aws-c-mqtt.git
-[submodule "aws-common-runtime/s2n"]
-	path = crt/s2n
-	url = https://github.com/awslabs/s2n.git
-[submodule "crt/aws-c-event-stream"]
-	path = crt/aws-c-event-stream
-	url = https://github.com/awslabs/aws-c-event-stream.git
-[submodule "crt/aws-checksums"]
-	path = crt/aws-checksums
-	url = https://github.com/awslabs/aws-checksums.git
-[submodule "crt/aws-c-s3"]
-	path = crt/aws-c-s3
-	url = https://github.com/awslabs/aws-c-s3.git
-[submodule "aws-lc"]
-	path = crt/aws-lc
-	url = https://github.com/awslabs/aws-lc.git
-[submodule "crt/aws-c-sdkutils"]
-	path = crt/aws-c-sdkutils
-	url = https://github.com/awslabs/aws-c-sdkutils.git
diff --git a/Android.bp b/Android.bp
index 04aa59a..fc843ae 100644
--- a/Android.bp
+++ b/Android.bp
@@ -23,4 +23,3 @@ java_library_host {
         },
     },
 }
-
diff --git a/crt/aws-c-auth b/crt/aws-c-auth
deleted file mode 160000
index 8e5e461..0000000
--- a/crt/aws-c-auth
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit 8e5e46188105c2072f06da366a02378074e40177
diff --git a/crt/aws-c-cal b/crt/aws-c-cal
deleted file mode 160000
index b52d9e8..0000000
--- a/crt/aws-c-cal
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit b52d9e8ee7af8155e6928c977ec5fde25a507ba0
diff --git a/crt/aws-c-common b/crt/aws-c-common
deleted file mode 160000
index 8eaa098..0000000
--- a/crt/aws-c-common
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit 8eaa0986ad3cfd46c87432a2e4c8ab81a786085f
diff --git a/crt/aws-c-compression b/crt/aws-c-compression
deleted file mode 160000
index 99ec79e..0000000
--- a/crt/aws-c-compression
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit 99ec79ee2970f1a045d4ced1501b97ee521f2f85
diff --git a/crt/aws-c-event-stream b/crt/aws-c-event-stream
deleted file mode 160000
index b7a96fd..0000000
--- a/crt/aws-c-event-stream
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit b7a96fd2dc43f4625d784ea51106e1fac4255f7a
diff --git a/crt/aws-c-http b/crt/aws-c-http
deleted file mode 160000
index 6a1c157..0000000
--- a/crt/aws-c-http
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit 6a1c157c20640a607102738909e89561a41e91e9
diff --git a/crt/aws-c-io b/crt/aws-c-io
deleted file mode 160000
index 4c65ce5..0000000
--- a/crt/aws-c-io
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit 4c65ce51d2d7050e1ce1030881b6a4df22d33544
diff --git a/crt/aws-c-mqtt b/crt/aws-c-mqtt
deleted file mode 160000
index 17ee24a..0000000
--- a/crt/aws-c-mqtt
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit 17ee24a2177fc64cf9773d430a24e6fa06a89dd0
diff --git a/crt/aws-c-s3 b/crt/aws-c-s3
deleted file mode 160000
index 63da70e..0000000
--- a/crt/aws-c-s3
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit 63da70e4b812ce24156baef4b89e7bd607921102
diff --git a/crt/aws-c-sdkutils b/crt/aws-c-sdkutils
deleted file mode 160000
index 6c7764e..0000000
--- a/crt/aws-c-sdkutils
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit 6c7764eed43a528b6577906a993e47018b06095f
diff --git a/crt/aws-checksums b/crt/aws-checksums
deleted file mode 160000
index 321b805..0000000
--- a/crt/aws-checksums
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit 321b805559c8e911be5bddba13fcbd222a3e2d3a
diff --git a/crt/aws-lc b/crt/aws-lc
deleted file mode 160000
index 19d9ace..0000000
--- a/crt/aws-lc
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit 19d9ace40f6770e062b1e9ec1d46935b300b948e
diff --git a/crt/s2n b/crt/s2n
deleted file mode 160000
index c74f442..0000000
--- a/crt/s2n
+++ /dev/null
@@ -1 +0,0 @@
-Subproject commit c74f442b55589872b1374559bb03878c49761ca6
```

