```diff
diff --git a/src/com/android/providers/userdictionary/UserDictionaryProvider.java b/src/com/android/providers/userdictionary/UserDictionaryProvider.java
index 5abeefa..8b6728c 100644
--- a/src/com/android/providers/userdictionary/UserDictionaryProvider.java
+++ b/src/com/android/providers/userdictionary/UserDictionaryProvider.java
@@ -336,7 +336,8 @@ public class UserDictionaryProvider extends ContentProvider {
             }
         }
 
-        SpellCheckerInfo[] scInfos = mTextServiceManager.getEnabledSpellCheckers();
+        SpellCheckerInfo[] scInfos =
+                mTextServiceManager == null ? null : mTextServiceManager.getEnabledSpellCheckers();
         if (scInfos != null) {
             for (SpellCheckerInfo scInfo : scInfos) {
                 if (scInfo.getServiceInfo().applicationInfo.uid == callingUid
```

