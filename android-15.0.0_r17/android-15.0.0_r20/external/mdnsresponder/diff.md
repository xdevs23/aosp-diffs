```diff
diff --git a/Android.bp b/Android.bp
index 1d44087..46dab6b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -34,6 +34,9 @@ license {
 cc_defaults {
     name: "mdnsresponder_default_cflags",
 
+    // This code has a variety of C23 issues,
+    // and is likely to be removed soon anyway.
+    c_std: "gnu17",
     cflags: [
         "-O2",
         "-g",
diff --git a/mDNSPosix/PosixDaemon.c b/mDNSPosix/PosixDaemon.c
index e714509..75d0dfc 100644
--- a/mDNSPosix/PosixDaemon.c
+++ b/mDNSPosix/PosixDaemon.c
@@ -229,7 +229,8 @@ int main(int argc, char **argv)
 		LogMsg("ExitCallback: udsserver_exit failed");
  
  #if MDNS_DEBUGMSGS > 0
-	printf("mDNSResponder exiting normally with %ld\n", err);
+ 	//ANDROID customization.
+	printf("mDNSResponder exiting normally with %d\n", err);
  #endif
  
 	return err;
```

