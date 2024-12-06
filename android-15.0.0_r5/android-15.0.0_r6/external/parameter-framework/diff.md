```diff
diff --git a/OWNERS b/OWNERS
index 7e76603..596a005 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,4 @@
 # This project does not seem be updated for about 3 years.
 # Please update this list if you find better candidates.
 rtenneti@google.com
-krocard@google.com
 elaurent@google.com
diff --git a/upstream/parameter/ParameterMgr.cpp b/upstream/parameter/ParameterMgr.cpp
index d515af0..fe09942 100644
--- a/upstream/parameter/ParameterMgr.cpp
+++ b/upstream/parameter/ParameterMgr.cpp
@@ -928,6 +928,13 @@ CParameterMgr::CCommandHandler::CommandStatus CParameterMgr::statusCommandProces
 CParameterMgr::CCommandHandler::CommandStatus CParameterMgr::setTuningModeCommandProcess(
     const IRemoteCommand &remoteCommand, string &strResult)
 {
+    // Tuning allowed? Check done only when trying to access from python command bindings.
+    if (!getConstFrameworkConfiguration()->isTuningAllowed()) {
+
+        strResult = "Tuning prohibited";
+
+        return CCommandHandler::EFailed;
+    }
     if (remoteCommand.getArgument(0) == "on") {
 
         if (setTuningMode(true, strResult)) {
@@ -2115,13 +2122,6 @@ bool CParameterMgr::setTuningMode(bool bOn, string &strError)
         strError = "Tuning mode is already in the state requested";
         return false;
     }
-    // Tuning allowed?
-    if (bOn && !getConstFrameworkConfiguration()->isTuningAllowed()) {
-
-        strError = "Tuning prohibited";
-
-        return false;
-    }
     // Lock state
     lock_guard<mutex> autoLock(getBlackboardMutex());
 
```

