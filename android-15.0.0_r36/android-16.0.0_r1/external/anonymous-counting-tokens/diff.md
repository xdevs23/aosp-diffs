```diff
diff --git a/Android.bp b/Android.bp
index fe6ba0d..0081294 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,5 +1,5 @@
 package {
-    default_visibility : ["//visibility:private"],
+    default_visibility: ["//visibility:private"],
     default_applicable_licenses: ["libact_license"],
 }
 
@@ -29,74 +29,77 @@ cc_library_static {
     defaults: ["libact_defaults"],
     min_sdk_version: "30",
     sdk_version: "current",
-    stl: "libc++_static",    
+    stl: "libc++_static",
     srcs: [
-      "act/act.proto",
-      "act/act_v0/act_v0.cc",
-      "act/act_v0/act_v0.proto",
-      "act/act_v0/parameters.cc",
-      "act/util.proto",
+        "act/act.proto",
+        "act/act_v0/act_v0.cc",
+        "act/act_v0/act_v0.proto",
+        "act/act_v0/parameters.cc",
+        "act/util.proto",
     ],
     shared_libs: [
-      "libcrypto",
-      "liblog",
+        "libcrypto",
+        "liblog",
     ],
     whole_static_libs: [
-      "libpjc_crypto",
-      "libpjc_third_party_libabsl",
+        "libpjc_crypto",
+        "libabsl",
     ],
     cflags: ["-Wno-unused-parameter"],
     export_include_dirs: ["."],
     include_dirs: [
-      "external/protobuf",
-      "external/protobuf/src",
+        "external/protobuf",
+        "external/protobuf/src",
     ],
     proto: {
-      type: "lite",
-      export_proto_headers: true,
-      local_include_dirs: [
-        ".",
-      ],
-      include_dirs: [
-        "external/private-join-and-compute",
-        "external/protobuf",
-        "external/protobuf/src",        
-      ]
+        type: "lite",
+        export_proto_headers: true,
+        local_include_dirs: [
+            ".",
+        ],
+        include_dirs: [
+            "external/private-join-and-compute",
+            "external/protobuf",
+            "external/protobuf/src",
+        ],
     },
     sanitize: {
-      integer_overflow: true,
-      misc_undefined: ["bounds"],
+        integer_overflow: true,
+        misc_undefined: ["bounds"],
     },
-    apex_available: ["com.android.adservices", "com.android.extservices",],
+    apex_available: [
+        "com.android.adservices",
+        "com.android.extservices",
+    ],
     visibility: [
-    	"//packages/modules/AdServices:__subpackages__",
+        "//packages/modules/AdServices:__subpackages__",
     ],
     target: {
-	android: {
-	    whole_static_libs: [
-	        "libprotobuf-cpp-lite-ndk",
-	    ]
-	}
-    }
+        android: {
+            whole_static_libs: [
+                "libprotobuf-cpp-lite-ndk",
+            ],
+        },
+    },
 }
 
 cc_test {
     name: "libact_fake_act_test",
     defaults: ["libact_defaults"],
     srcs: [
-      "act/fake_act.cc",
-      "act/fake_act_test.cc",
+        "act/fake_act.cc",
+        "act/fake_act_test.cc",
     ],
     shared_libs: [
-      "libcrypto",
-      "liblog",
-      "libprotobuf-cpp-lite",
+        "libcrypto",
+        "liblog",
+        "libprotobuf-cpp-lite",
     ],
     static_libs: [
-      "libpjc_crypto",
-      "libact",
-      "libgmock",
-      "libpjc_third_party_libabsl",
+        "libpjc_crypto",
+        "libact",
+        "libgmock",
+        "libabsl",
     ],
     cflags: ["-Wno-unused-parameter"],
 }
@@ -105,18 +108,18 @@ cc_test {
     name: "libact_test",
     defaults: ["libact_defaults"],
     srcs: [
-      "act/act_v0/act_v0_test.cc",
+        "act/act_v0/act_v0_test.cc",
     ],
     shared_libs: [
-      "libcrypto",
-      "liblog",
-      "libprotobuf-cpp-lite",
+        "libcrypto",
+        "liblog",
+        "libprotobuf-cpp-lite",
     ],
     static_libs: [
-      "libpjc_crypto",
-      "libact",
-      "libgmock",
-      "libpjc_third_party_libabsl",
+        "libpjc_crypto",
+        "libact",
+        "libgmock",
+        "libabsl",
     ],
     cflags: ["-Wno-unused-parameter"],
     test_suites: ["general-tests"],
@@ -128,18 +131,18 @@ cc_test {
     defaults: ["libact_defaults"],
     enabled: false,
     srcs: [
-      "act/act_v0/parameters_test.cc",
+        "act/act_v0/parameters_test.cc",
     ],
     shared_libs: [
-      "libcrypto",
-      "liblog",
-      "libprotobuf-cpp-lite",
+        "libcrypto",
+        "liblog",
+        "libprotobuf-cpp-lite",
     ],
     static_libs: [
-      "libpjc_crypto",
-      "libact",
-      "libgmock",
-      "libpjc_third_party_libabsl",
+        "libpjc_crypto",
+        "libact",
+        "libgmock",
+        "libabsl",
     ],
     cflags: ["-Wno-unused-parameter"],
 }
diff --git a/METADATA b/METADATA
index 2fa0a5e..e0cab8b 100644
--- a/METADATA
+++ b/METADATA
@@ -1,13 +1,15 @@
 name: "anonymous-counting-tokens"
-description:
-""
-
+description: ""
 third_party {
-  url {
-    type: GIT
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2023
+    month: 11
+    day: 13
+  }
+  identifier {
+    type: "Git"
     value: "https://github.com/google/anonymous-counting-tokens"
+    version: "3dea51443eaabde75c00cd325bc31e3b848a767f"
   }
-  version: "827d2aa796804f9ed28fc1c35ada56e0c62800be"
-  last_upgrade_date { year: 2023 month: 4 day: 25 }
-  license_type: NOTICE
 }
diff --git a/OWNERS b/OWNERS
index 99aa2e0..f2942fb 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 shwetachahar@google.com
 niagra@google.com
 kmg@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/act/act_v0/act_v0.cc b/act/act_v0/act_v0.cc
index d4418e7..f2a072a 100644
--- a/act/act_v0/act_v0.cc
+++ b/act/act_v0/act_v0.cc
@@ -21,6 +21,9 @@
 #include <utility>
 #include <vector>
 
+// ANDROID: Not sure how upstream worked without this header
+#include <absl/strings/str_cat.h>
+
 #include <google/protobuf/io/zero_copy_stream_impl_lite.h>
 #include "act/act.pb.h"
 #include "act/act_v0/act_v0.pb.h"
```

