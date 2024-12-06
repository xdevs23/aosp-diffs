```diff
diff --git a/Android.mk b/Android.mk
deleted file mode 100644
index e019b18..0000000
--- a/Android.mk
+++ /dev/null
@@ -1 +0,0 @@
-$(eval $(call declare-1p-copy-files,hardware/libhardware_legacy,))
diff --git a/power_test.cpp b/power_test.cpp
index 7e0b68e..24e443b 100644
--- a/power_test.cpp
+++ b/power_test.cpp
@@ -133,9 +133,10 @@ TEST_F(WakeLockTest, WakeLockDestructor) {
         ASSERT_TRUE(info.isActive);
     }
 
-    // SystemSuspend receives wake lock release requests on hwbinder thread, while stats requests
-    // come on binder thread. Sleep to make sure that stats are reported *after* wake lock release.
-    std::this_thread::sleep_for(1ms);
+    // Allow the system suspend service sufficient time to release the wake
+    // lock, obtain the autosuspend lock to decrement the suspend counter and
+    // update the wake lock stats.
+    std::this_thread::sleep_for(50ms);
     WakeLockInfo info;
     auto success = findWakeLockInfoByName(name, &info);
     ASSERT_TRUE(success);
```

