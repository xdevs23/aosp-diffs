```diff
diff --git a/OWNERS b/OWNERS
new file mode 100644
index 0000000..ef86412
--- /dev/null
+++ b/OWNERS
@@ -0,0 +1,2 @@
+# Bug component: 86431
+include platform/art:/OWNERS
diff --git a/arm_v7_v8/BoardConfig.mk b/arm_v7_v8/BoardConfig.mk
index b252033..c5618f5 100644
--- a/arm_v7_v8/BoardConfig.mk
+++ b/arm_v7_v8/BoardConfig.mk
@@ -24,13 +24,9 @@ TARGET_ARCH_VARIANT := armv8-a
 
 TARGET_2ND_ARCH := arm
 TARGET_2ND_ARCH_VARIANT := armv7-a-neon
-TARGET_2ND_CPU_VARIANT := cortex-a15
+TARGET_2ND_CPU_VARIANT := generic
 TARGET_2ND_CPU_ABI := armeabi-v7a
 TARGET_2ND_CPU_ABI2 := armeabi
 
 TARGET_SUPPORTS_32_BIT_APPS := true
 TARGET_SUPPORTS_64_BIT_APPS := true
-
-
-# Disable dexpreopt for an unbundled ART build.
-WITH_DEXPREOPT := false
```

