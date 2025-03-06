```diff
diff --git a/Android.bp b/Android.bp
index 921d69b..ddd8229 100644
--- a/Android.bp
+++ b/Android.bp
@@ -29,3 +29,9 @@ license {
 }
 
 subdirs = ["*"]
+
+dirgroup {
+    name: "trusty_dirgroup_system_authgraph",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/Cargo.toml b/Cargo.toml
new file mode 100644
index 0000000..69ef11f
--- /dev/null
+++ b/Cargo.toml
@@ -0,0 +1,12 @@
+[workspace]
+members = [
+  "core",
+  "derive",
+  "wire",
+]
+resolver = "2"
+
+[patch.crates-io]
+authgraph_derive = { path = "derive" }
+authgraph_core = { path = "core" }
+authgraph_wire = { path = "wire" }
diff --git a/core/Cargo.toml b/core/Cargo.toml
new file mode 100644
index 0000000..fe75c24
--- /dev/null
+++ b/core/Cargo.toml
@@ -0,0 +1,20 @@
+# Note that Cargo is not an officially supported build tool (Android's Soong is the official
+# tool).  This Cargo.toml file is included purely for the convenience of developers.
+
+[package]
+name = "authgraph_core"
+version = "0.1.0"
+authors = ["Hasini Gunasinghe <hasinitg@google.com>", "David Drysdale <drysdale@google.com>"]
+edition = "2021"
+license = "Apache-2.0"
+
+[dependencies]
+authgraph_wire = "*"
+ciborium = { version = "0.2.2", default-features = false }
+ciborium-io = "0.2.2"
+coset = "0.3.3"
+log = "0.4"
+zeroize = { version = "^1.5.6", features = ["alloc", "zeroize_derive"] }
+
+[dev-dependencies]
+hex = "0.4.3"
diff --git a/derive/Cargo.toml b/derive/Cargo.toml
index 2cb9f7a..1eb039e 100644
--- a/derive/Cargo.toml
+++ b/derive/Cargo.toml
@@ -1,5 +1,8 @@
+# Note that Cargo is not an officially supported build tool (Android's Soong is the official
+# tool).  This Cargo.toml file is included purely for the convenience of developers.
+
 [package]
-name = "authgraph-derive"
+name = "authgraph_derive"
 version = "0.1.0"
 authors = ["David Drysdale <drysdale@google.com>"]
 edition = "2021"
@@ -8,6 +11,6 @@ edition = "2021"
 proc-macro = true
 
 [dependencies]
-proc-macro2 = "^1.0"
-quote = "^1.0"
+proc-macro2 = "1.0.69"
+quote = "1.0.36"
 syn = { version = "2.0.38", features = ["derive", "parsing"] }
diff --git a/wire/Cargo.toml b/wire/Cargo.toml
new file mode 100644
index 0000000..81c8144
--- /dev/null
+++ b/wire/Cargo.toml
@@ -0,0 +1,18 @@
+# Note that Cargo is not an officially supported build tool (Android's Soong is the official
+# tool).  This Cargo.toml file is included purely for the convenience of developers.
+
+[package]
+name = "authgraph_wire"
+version = "0.1.0"
+authors = ["David Drysdale <drysdale@google.com>"]
+edition = "2021"
+license = "Apache-2.0"
+
+[dependencies]
+authgraph_derive = "*"
+ciborium = { version = "0.2.2", default-features = false }
+ciborium-io = "0.2.2"
+enumn = "0.1.8"
+
+[dev-dependencies]
+hex = "0.4.3"
```

