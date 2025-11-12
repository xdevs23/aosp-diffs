```diff
diff --git a/arm64/desktop-arm64/project/desktop-arm64-test-debug.mk b/arm64/desktop-arm64/project/desktop-arm64-test-debug.mk
index 396b450..a7462d8 100644
--- a/arm64/desktop-arm64/project/desktop-arm64-test-debug.mk
+++ b/arm64/desktop-arm64/project/desktop-arm64-test-debug.mk
@@ -18,6 +18,9 @@ DEBUG := 2
 
 RELEASE_BUILD ?= false
 
+MODULES += \
+       trusty/kernel/platform/desktop/arm64/rust \
+
 include ../../../arm/generic-arm64/project/debugging-inc.mk
 include ../../../arm/generic-arm64/project/generic-arm-inc.mk
 include ../../common/desktop-inc-test.mk
diff --git a/arm64/desktop-arm64/project/desktop-arm64-test.mk b/arm64/desktop-arm64/project/desktop-arm64-test.mk
index 7aed3a4..5ec92ea 100644
--- a/arm64/desktop-arm64/project/desktop-arm64-test.mk
+++ b/arm64/desktop-arm64/project/desktop-arm64-test.mk
@@ -18,6 +18,9 @@ DEBUG := 1
 
 RELEASE_BUILD ?= false
 
+MODULES += \
+       trusty/kernel/platform/desktop/arm64/rust \
+
 include ../../../arm/generic-arm64/project/generic-arm-virt-inc.mk
 include ../../../arm/generic-arm64/project/generic-arm-inc.mk
 include ../../common/desktop-inc-test.mk
diff --git a/arm64/desktop-arm64/project/desktop-arm64.mk b/arm64/desktop-arm64/project/desktop-arm64.mk
index 2ba1b34..c02f3ee 100644
--- a/arm64/desktop-arm64/project/desktop-arm64.mk
+++ b/arm64/desktop-arm64/project/desktop-arm64.mk
@@ -16,6 +16,9 @@
 KERNEL_32BIT := false
 DEBUG := 1
 
+MODULES += \
+       trusty/kernel/platform/desktop/arm64/rust \
+
 include ../../../arm/generic-arm64/project/generic-arm-virt-inc.mk
 include ../../../arm/generic-arm64/project/generic-arm-inc.mk
 include ../../common/desktop-inc.mk
diff --git a/arm64/desktop-arm64/project/qemu-desktop-arm64-test-debug.mk b/arm64/desktop-arm64/project/qemu-desktop-arm64-test-debug.mk
index 34e551a..c57d210 100644
--- a/arm64/desktop-arm64/project/qemu-desktop-arm64-test-debug.mk
+++ b/arm64/desktop-arm64/project/qemu-desktop-arm64-test-debug.mk
@@ -21,5 +21,8 @@ KERNEL_BTI_ENABLED ?= true
 # D-cache lines are 64 bytes on QEMU arm64
 GLOBAL_DEFINES += CACHE_LINE=64
 
+MODULES += \
+       trusty/kernel/platform/desktop/arm64/rust \
+
 include ../../../arm/generic-arm64/project/debugging-inc.mk
 include ../../../arm/generic-arm64/project/qemu-inc.mk
diff --git a/common/desktop-inc-test.mk b/common/desktop-inc-test.mk
index 3c7fed5..d213725 100644
--- a/common/desktop-inc-test.mk
+++ b/common/desktop-inc-test.mk
@@ -19,7 +19,10 @@ include ../../common/desktop-inc.mk
 
 TRUSTY_RUST_USER_TESTS += \
 	trusty/user/app/keymint \
-	trusty/user/desktop/lib/boot_params \
 	trusty/user/desktop/app/finger_guard \
+	trusty/user/desktop/app/gsc_svc \
+	trusty/user/desktop/app/pinweaver \
+	trusty/user/desktop/lib/boot_params \
+	trusty/user/desktop/lib/gsc_svc_client \
 
 TEST_BUILD := true
diff --git a/common/desktop-inc.mk b/common/desktop-inc.mk
index 876f588..5c431f3 100644
--- a/common/desktop-inc.mk
+++ b/common/desktop-inc.mk
@@ -19,21 +19,24 @@ TRUSTY_BUILTIN_USER_TASKS := \
 	trusty/user/app/gatekeeper \
 	trusty/user/app/keymint/app \
 	trusty/user/app/storage \
-	trusty/user/base/app/apploader \
 	trusty/user/base/app/system_state_server_static \
 	trusty/user/desktop/app/gsc_svc/app \
 	trusty/user/desktop/app/pinweaver/app \
 	trusty/user/desktop/app/finger_guard/app \
+	trusty/user/desktop/app/hwbcc \
+	trusty/user/desktop/app/hwkey/rust \
+
+# Desktop specific keymint access policy.
+TRUSTY_KM_RUST_ACCESS_POLICY := trusty/user/desktop/lib/keymint_access_policy
 
 # TODO(359377657): Until we have real applications that leverage the GSC, use
 # sample services with fake implementations. Having these applications available
 # enables the Desktop image to pass the KeyMint unit tests and boot the OS. This
 # useful for development.
 TRUSTY_BUILTIN_USER_TASKS += \
-	trusty/user/app/sample/hwbcc \
 	trusty/user/app/sample/hwcrypto \
 
 WITH_FAKE_HWRNG ?= true
-WITH_FAKE_HWKEY ?= true
+WITH_FAKE_HWKEY ?= false
 WITH_FAKE_KEYBOX ?= true
 # Remove lines above once real services exist.
diff --git a/x86_64/desktop-x86_64/project/desktop-x86_64-test.mk b/x86_64/desktop-x86_64/project/desktop-x86_64-test.mk
index 7b3f874..1c84c2d 100644
--- a/x86_64/desktop-x86_64/project/desktop-x86_64-test.mk
+++ b/x86_64/desktop-x86_64/project/desktop-x86_64-test.mk
@@ -15,5 +15,8 @@
 
 RELEASE_BUILD ?= false
 
+MODULES += \
+       trusty/kernel/platform/desktop/x86_64/rust \
+
 include ../../../x86/generic-x86_64/project/generic-x86_64-inc.mk
 include ../../common/desktop-inc-test.mk
diff --git a/x86_64/desktop-x86_64/project/desktop-x86_64.mk b/x86_64/desktop-x86_64/project/desktop-x86_64.mk
index d2f98f5..631ce5d 100644
--- a/x86_64/desktop-x86_64/project/desktop-x86_64.mk
+++ b/x86_64/desktop-x86_64/project/desktop-x86_64.mk
@@ -13,5 +13,8 @@
 # limitations under the License.
 #
 
+MODULES += \
+       trusty/kernel/platform/desktop/x86_64/rust \
+
 include ../../../x86/generic-x86_64/project/generic-x86_64-inc.mk
 include ../../common/desktop-inc.mk
```

