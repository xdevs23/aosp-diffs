```diff
diff --git a/ServiceManager.cpp b/ServiceManager.cpp
index f80386b..73582d2 100644
--- a/ServiceManager.cpp
+++ b/ServiceManager.cpp
@@ -47,6 +47,9 @@ AccessControl::CallingContext getBinderCallingContext() {
             android_errorWriteLog(0x534e4554, "121035042");
         }
 
+        CHECK_EQ(nullptr, self->getServingStackPointer())
+                << "Pid " << pid << " missing service context.";
+
         return AccessControl::getCallingContext(pid);
     } else {
         return { true, sid, pid };
```

