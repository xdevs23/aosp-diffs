```diff
diff --git a/aconfigd/Android.bp b/aconfigd/Android.bp
index c3168bf..29f9969 100644
--- a/aconfigd/Android.bp
+++ b/aconfigd/Android.bp
@@ -11,8 +11,8 @@ rust_binary {
         // TODO(370864013): Remove this once the CTS annotation issue is fixed.
         "libcts_flags_tests_rust",
     ],
-    cfgs: select(release_flag("RELEASE_DISABLE_SYSTEM_ACONFIGD_SOCKET"), {
-        true: ["disable_system_aconfigd_socket"],
+    cfgs: select(release_flag("RELEASE_ENABLE_SYSTEM_ACONFIGD_SOCKET"), {
+        true: ["enable_system_aconfigd_socket"],
         default: [],
     }),
     native_coverage: false,
diff --git a/aconfigd/new_aconfig_storage.aconfig b/aconfigd/new_aconfig_storage.aconfig
index 55f0ea5..a5517b6 100644
--- a/aconfigd/new_aconfig_storage.aconfig
+++ b/aconfigd/new_aconfig_storage.aconfig
@@ -52,3 +52,14 @@ flag {
     purpose: PURPOSE_BUGFIX
   }
 }
+
+flag {
+  name: "optimize_boot_copy_creation"
+  namespace: "core_experiments_team_internal"
+  bug: "409943165"
+  description: "Fix the issue that boot storage files are created unecessarily"
+  is_fixed_read_only: true
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
diff --git a/aconfigd/src/aconfigd_commands.rs b/aconfigd/src/aconfigd_commands.rs
index 8b630aa..930b323 100644
--- a/aconfigd/src/aconfigd_commands.rs
+++ b/aconfigd/src/aconfigd_commands.rs
@@ -83,7 +83,9 @@ pub fn platform_init() -> Result<()> {
     };
 
     let mut aconfigd = Aconfigd::new(Path::new(ACONFIGD_ROOT_DIR), Path::new(storage_records));
-    aconfigd.remove_boot_files()?;
+    if !aconfig_new_storage_flags::optimize_boot_copy_creation() {
+        aconfigd.remove_boot_files()?;
+    }
     aconfigd.initialize_from_storage_record()?;
     Ok(aconfigd.initialize_platform_storage()?)
 }
diff --git a/aconfigd/src/main.rs b/aconfigd/src/main.rs
index 4a1145c..3737103 100644
--- a/aconfigd/src/main.rs
+++ b/aconfigd/src/main.rs
@@ -69,12 +69,12 @@ fn main() {
     let cli = Cli::parse();
     let command_return = match cli.command {
         Command::StartSocket => {
-            if cfg!(disable_system_aconfigd_socket) {
-                info!("aconfigd_system is build-disabled, exiting");
-                Ok(())
-            } else {
+            if cfg!(enable_system_aconfigd_socket) {
                 info!("aconfigd_system is build-enabled, starting socket");
                 aconfigd_commands::start_socket()
+            } else {
+                info!("aconfigd_system is build-disabled, exiting");
+                Ok(())
             }
         }
         Command::PlatformInit => aconfigd_commands::platform_init(),
diff --git a/libflags/Android.bp b/libflags/Android.bp
index 1cdb7f2..376f3a6 100644
--- a/libflags/Android.bp
+++ b/libflags/Android.bp
@@ -62,6 +62,11 @@ cc_library_static {
     ],
     host_supported: true,
     min_sdk_version: "33",
+    target: {
+        windows: {
+            enabled: true,
+        },
+    },
 }
 
 genrule {
@@ -79,7 +84,6 @@ rust_library {
     rustlibs: ["libcxx"],
     static_libs: ["libflags_rust_cpp_bridge"],
     shared_libs: [
-        "libc++",
         "server_configurable_flags",
     ],
     apex_available: [
@@ -88,4 +92,16 @@ rust_library {
     ],
     host_supported: true,
     min_sdk_version: "33",
+    target: {
+        android: {
+            shared_libs: ["libc++"],
+        },
+        not_windows: {
+            shared_libs: ["libc++"],
+        },
+        windows: {
+            enabled: true,
+            static_libs: ["libc++_static"],
+        },
+    },
 }
```

