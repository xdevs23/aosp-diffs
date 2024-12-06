```diff
diff --git a/soong/error_prone.go b/soong/error_prone.go
index 545ab32..7660ea5 100644
--- a/soong/error_prone.go
+++ b/soong/error_prone.go
@@ -114,16 +114,13 @@ func init() {
 	config.ErrorProneChecksWarning = []string{
 		// Errorprone default severity ERROR
 		"-Xep:ComparisonOutOfRange:WARN",
-		"-Xep:DoubleBraceInitialization:WARN",
 		"-Xep:EqualsHashCode:WARN",
 		"-Xep:GuardedBy:WARN",
 		"-Xep:IgnoredPureGetter:WARN",
 		"-Xep:ImmutableAnnotationChecker:WARN",
 		"-Xep:ImmutableEnumChecker:WARN",
 		"-Xep:IsLoggableTagLength:WARN",
-		"-Xep:LenientFormatStringValidation:WARN",
 		"-Xep:MissingSuperCall:WARN",
-		"-Xep:ProtocolBufferOrdinal:WARN",
 		"-Xep:RectIntersectReturnValueIgnored:WARN",
 		"-Xep:ReturnValueIgnored:WARN",
 	}
```

