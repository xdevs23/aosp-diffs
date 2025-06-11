```diff
diff --git a/OWNERS b/OWNERS
index 211348f1..a6e21cc5 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 jeffv@google.com
 tweek@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/libselinux/src/android/android_unittest.cpp b/libselinux/src/android/android_unittest.cpp
index 28a75247..af47326a 100644
--- a/libselinux/src/android/android_unittest.cpp
+++ b/libselinux/src/android/android_unittest.cpp
@@ -1,6 +1,7 @@
 #include <gtest/gtest.h>
 
 #include <android-base/file.h>
+#include <android-base/macros.h>
 #include <android-base/stringprintf.h>
 
 #include "android_internal.h"
@@ -12,7 +13,38 @@ using std::string;
 
 class AndroidSELinuxTest : public ::testing::Test {
     protected:
+	const char* kUnknownDomain = "u:r:unknown";
 	TemporaryDir tdir_;
+
+	int LoadSeAppContexts(string content)
+	{
+		string seapp_contexts = StringPrintf("%s/seapp_contexts", tdir_.path);
+		WriteStringToFile(content, seapp_contexts);
+		path_alts_t seapp_paths = {
+			.paths = {
+				{ seapp_contexts.c_str() }
+			},
+			.partitions = {
+				"system"
+			}
+		};
+		return seapp_context_reload_internal(&seapp_paths);
+	}
+
+        /* Resolve the context for a specific `seinfo` and ensures that it matches
+         * `expected`. If `expected` is NULL, ensures that the context is not modified
+         */
+        void ExpectContextForSeInfo(const char* seinfo, const char* expected)
+	{
+		context_t ctx = context_new(kUnknownDomain);
+		int ret = seapp_context_lookup_internal(SEAPP_DOMAIN, 10001, false, seinfo, "com.android.test", ctx);
+		EXPECT_EQ(ret, 0);
+		if (!expected) {
+			expected = kUnknownDomain;
+		}
+		EXPECT_STREQ(context_str(ctx), expected);
+		context_free(ctx);
+	}
 };
 
 TEST_F(AndroidSELinuxTest, LoadAndLookupServiceContext)
@@ -84,22 +116,15 @@ TEST_F(AndroidSELinuxTest, FailLoadingServiceContext)
 
 TEST_F(AndroidSELinuxTest, LoadAndLookupSeAppContext)
 {
-	string seapp_contexts =
-		StringPrintf("%s/seapp_contexts", tdir_.path);
-
-	WriteStringToFile(
+	int ret = LoadSeAppContexts(
 		"# some comment\n"
-		"user=_app seinfo=platform domain=platform_app type=app_data_file levelFrom=user\n",
-	seapp_contexts);
+		"user=_app seinfo=platform domain=platform_app type=app_data_file levelFrom=user\n"
+	);
 
-	const path_alts_t seapp_paths = { .paths = {
-		{ seapp_contexts.c_str() }
-	}};
-
-	EXPECT_EQ(seapp_context_reload_internal(&seapp_paths), 0);
+	EXPECT_EQ(ret, 0);
 
 	context_t ctx = context_new("u:r:unknown");
-	int ret = seapp_context_lookup_internal(SEAPP_DOMAIN, 10001, false, "platform", "com.android.test1", ctx);
+	ret = seapp_context_lookup_internal(SEAPP_DOMAIN, 10001, false, "platform", "com.android.test1", ctx);
 	EXPECT_EQ(ret, 0);
 	EXPECT_STREQ(context_str(ctx), "u:r:platform_app:s0:c512,c768");
 	context_free(ctx);
@@ -111,6 +136,74 @@ TEST_F(AndroidSELinuxTest, LoadAndLookupSeAppContext)
 	context_free(ctx);
 }
 
+TEST_F(AndroidSELinuxTest, LoadAndLookupSeAppContextBooleanDefault)
+{
+	int ret = LoadSeAppContexts(
+		"user=_app domain=catchall_app type=x levelFrom=user\n"
+	);
+
+	EXPECT_EQ(ret, 0);
+
+	ExpectContextForSeInfo("default:privapp:partition=system:complete", "u:r:catchall_app:s0:c512,c768");
+	ExpectContextForSeInfo("default:ephemeralapp:partition=system:complete", "u:r:catchall_app:s0:c512,c768");
+
+	ExpectContextForSeInfo("default:isolatedComputeApp:partition=system:complete", nullptr);
+	ExpectContextForSeInfo("default:isSdkSandboxAudit:partition=system:complete", nullptr);
+	ExpectContextForSeInfo("default:isSdkSandboxNext:partition=system:complete", nullptr);
+	ExpectContextForSeInfo("default:fromRunAs:partition=system:complete", nullptr);
+}
+
+TEST_F(AndroidSELinuxTest, LoadAndLookupSeAppContextBooleanFalse)
+{
+	int ret = LoadSeAppContexts(
+		"user=_app isPrivApp=false domain=noprivapp type=x levelFrom=user\n"
+		"user=_app isEphemeralApp=false domain=noephemeralapp type=x levelFrom=user\n"
+		"user=_app domain=catchall_app type=x levelFrom=user\n"
+	);
+
+	EXPECT_EQ(ret, 0);
+
+	ExpectContextForSeInfo("default:privapp:partition=system:complete", "u:r:noephemeralapp:s0:c512,c768");
+	ExpectContextForSeInfo("default:ephemeralapp:partition=system:complete", "u:r:noprivapp:s0:c512,c768");
+	// isEphemeralApp has precedence over isPrivApp.
+	ExpectContextForSeInfo("default:partition=system:complete", "u:r:noephemeralapp:s0:c512,c768");
+
+        // For the boolean selectors with a default value, check that the
+        // loading fail (as this is a duplicate of the catchall).
+        string defaultFalseBooleans[] = { "isIsolatedComputeApp", "isSdkSandboxAudit", "isSdkSandboxNext", "fromRunAs" };
+	for (int i=0; i < arraysize(defaultFalseBooleans); i++) {
+		string seapp_contexts =
+			"user=_app " + defaultFalseBooleans[i] + "=false domain=y type=x levelFrom=user\n"
+			"user=_app domain=catchall_app type=x levelFrom=user\n";
+		ret = LoadSeAppContexts(seapp_contexts);
+		EXPECT_EQ(ret, -1); // we expect a failure because of the duplicate.
+	}
+}
+
+TEST_F(AndroidSELinuxTest, LoadAndLookupSeAppContextBooleanTrue)
+{
+	int ret = LoadSeAppContexts(
+		"user=_app isPrivApp=true domain=privapp type=x levelFrom=user\n"
+		"user=_app isEphemeralApp=true domain=ephemeralapp type=x levelFrom=user\n"
+		"user=_app isIsolatedComputeApp=true domain=isolatedapp type=x levelFrom=user\n"
+		"user=_app isSdkSandboxAudit=true domain=sdk_audit type=x levelFrom=user\n"
+		"user=_app isSdkSandboxNext=true domain=sdk_next type=x levelFrom=user\n"
+		"user=_app fromRunAs=true domain=runas type=x levelFrom=user\n"
+		"user=_app domain=catchall_app type=x levelFrom=user\n"
+	);
+
+	EXPECT_EQ(ret, 0);
+
+	ExpectContextForSeInfo("default:privapp:partition=system:complete", "u:r:privapp:s0:c512,c768");
+	ExpectContextForSeInfo("default:ephemeralapp:partition=system:complete", "u:r:ephemeralapp:s0:c512,c768");
+	ExpectContextForSeInfo("default:isolatedComputeApp:partition=system:complete", "u:r:isolatedapp:s0:c512,c768");
+	ExpectContextForSeInfo("default:isSdkSandboxAudit:partition=system:complete", "u:r:sdk_audit:s0:c512,c768");
+	ExpectContextForSeInfo("default:isSdkSandboxNext:partition=system:complete", "u:r:sdk_next:s0:c512,c768");
+	ExpectContextForSeInfo("default:fromRunAs:partition=system:complete", "u:r:runas:s0:c512,c768");
+
+	ExpectContextForSeInfo("default:partition=system:complete", "u:r:catchall_app:s0:c512,c768");
+}
+
 TEST(AndroidSeAppTest, ParseValidSeInfo)
 {
 	struct parsed_seinfo info;
```

