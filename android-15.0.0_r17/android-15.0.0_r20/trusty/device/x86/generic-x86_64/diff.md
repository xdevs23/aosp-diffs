```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..eca0ecb
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_trusty_device_x86_generic-x86_64",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/project/generic-x86_64-inc.mk b/project/generic-x86_64-inc.mk
index 342c8f1..bce0606 100644
--- a/project/generic-x86_64-inc.mk
+++ b/project/generic-x86_64-inc.mk
@@ -23,6 +23,16 @@ WITH_LINKER_GC := 1
 
 TRUSTY_USER_ARCH := x86
 
+# enable LTO in user-tasks modules
+USER_LTO_ENABLED ?= true
+
+# enable LTO in kernel modules
+KERNEL_LTO_ENABLED ?= true
+
+# enable cfi in trusty modules
+USER_CFI_ENABLED ?= true
+KERNEL_CFI_ENABLED ?= true
+
 # Limit heap grows
 GLOBAL_DEFINES += HEAP_GROW_SIZE=8192
 
@@ -40,6 +50,9 @@ STATIC_SYSTEM_STATE_FLAG_PROVISIONING_ALLOWED := 1
 # Enable Secure Storage AIDL interface
 STORAGE_AIDL_ENABLED ?= true
 
+# Non-secure KeyMint Trusty VM is used on x86_64 / cuttlefish
+KEYMINT_TRUSTY_VM ?= nonsecure
+
 MODULES += \
 	trusty/kernel/lib/trusty \
 	trusty/kernel/services/apploader \
```

