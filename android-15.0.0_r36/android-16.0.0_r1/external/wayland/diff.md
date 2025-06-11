```diff
diff --git a/OWNERS b/OWNERS
index 8bf11ca..3cefc76 100644
--- a/OWNERS
+++ b/OWNERS
@@ -6,3 +6,4 @@ xutan@google.com #{LAST_RESORT_SUGGESTION}
 
 # Allow Soong team to make build changes
 per-file Android.bp = file:platform/build/soong:/OWNERS #{LAST_RESORT_SUGGESTION}
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

