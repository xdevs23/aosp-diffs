```diff
diff --git a/java/com/android/libraries/entitlement/eapaka/EapAkaApi.java b/java/com/android/libraries/entitlement/eapaka/EapAkaApi.java
index b3f438c..c26f74b 100644
--- a/java/com/android/libraries/entitlement/eapaka/EapAkaApi.java
+++ b/java/com/android/libraries/entitlement/eapaka/EapAkaApi.java
@@ -39,6 +39,7 @@ import com.android.libraries.entitlement.ServiceEntitlementRequest;
 import com.android.libraries.entitlement.http.HttpClient;
 import com.android.libraries.entitlement.http.HttpConstants.ContentType;
 import com.android.libraries.entitlement.http.HttpConstants.RequestMethod;
+import com.android.libraries.entitlement.http.HttpCookieJar;
 import com.android.libraries.entitlement.http.HttpRequest;
 import com.android.libraries.entitlement.http.HttpResponse;
 
@@ -215,10 +216,13 @@ public class EapAkaApi {
                         ERROR_MALFORMED_HTTP_RESPONSE,
                         "Failed to parse EAP-AKA challenge: " + challengeResponse.body());
             }
+            ImmutableList<String> cookies = HttpCookieJar
+                    .parseSetCookieHeaders(challengeResponse.cookies())
+                    .toCookieHeaders();
             return respondToEapAkaChallenge(
                     carrierConfig,
                     eapAkaChallenge,
-                    challengeResponse.cookies(),
+                    cookies,
                     MAX_EAP_AKA_ATTEMPTS,
                     request.acceptContentType(),
                     request.terminalVendor(),
@@ -441,10 +445,13 @@ public class EapAkaApi {
                         ERROR_MALFORMED_HTTP_RESPONSE,
                         "Failed to parse EAP-AKA challenge: " + challengeResponse.body());
             }
+            ImmutableList<String> cookies = HttpCookieJar
+                    .parseSetCookieHeaders(challengeResponse.cookies())
+                    .toCookieHeaders();
             return respondToEapAkaChallenge(
                     carrierConfig,
                     eapAkaChallenge,
-                    challengeResponse.cookies(),
+                    cookies,
                     MAX_EAP_AKA_ATTEMPTS,
                     request.acceptContentType(),
                     request.terminalVendor(),
diff --git a/java/com/android/libraries/entitlement/eapaka/EapAkaResponse.java b/java/com/android/libraries/entitlement/eapaka/EapAkaResponse.java
index 12716f5..97a8b9b 100644
--- a/java/com/android/libraries/entitlement/eapaka/EapAkaResponse.java
+++ b/java/com/android/libraries/entitlement/eapaka/EapAkaResponse.java
@@ -113,7 +113,7 @@ public class EapAkaResponse {
                             securityContext.getIk(),
                             securityContext.getCk());
             // K_aut is the key used to calculate MAC
-            if (mk.getAut() == null) {
+            if (mk == null || mk.getAut() == null) {
                 throw new ServiceEntitlementException(
                         ERROR_ICC_AUTHENTICATION_NOT_AVAILABLE, "Can't generate K_Aut!");
             }
diff --git a/java/com/android/libraries/entitlement/http/HttpCookieJar.java b/java/com/android/libraries/entitlement/http/HttpCookieJar.java
new file mode 100644
index 0000000..d8d747f
--- /dev/null
+++ b/java/com/android/libraries/entitlement/http/HttpCookieJar.java
@@ -0,0 +1,87 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.libraries.entitlement.http;
+
+import static com.android.libraries.entitlement.utils.DebugUtils.logPii;
+
+import com.google.common.collect.ImmutableList;
+
+import java.net.HttpCookie;
+import java.util.List;
+
+/**
+ * Simple cookie management.
+ *
+ * <p>Use {@link #parseSetCookieHeaders} to parse the "Set-Cookie" headers in HTTP responses
+ * from the server, and use {@link #toCookieHeaders} to generate the "Cookie" headers in
+ * follow-up HTTP requests.
+ */
+public class HttpCookieJar {
+    private final ImmutableList<HttpCookie> mCookies;
+
+    private HttpCookieJar(ImmutableList<HttpCookie> cookies) {
+        mCookies = cookies;
+    }
+
+    /**
+     * Parses the "Set-Cookie" headers in HTTP responses from servers.
+     */
+    public static HttpCookieJar parseSetCookieHeaders(List<String> rawCookies) {
+        ImmutableList.Builder<HttpCookie> parsedCookies = ImmutableList.builder();
+        for (String rawCookie : rawCookies) {
+            List<HttpCookie> cookies = parseCookiesSafely(rawCookie);
+            parsedCookies.addAll(cookies);
+        }
+        return new HttpCookieJar(parsedCookies.build());
+    }
+
+    /**
+     * Returns the cookies as "Cookie" headers in HTTP requests to servers.
+     */
+    public ImmutableList<String> toCookieHeaders() {
+        ImmutableList.Builder<String> cookieHeader = ImmutableList.builder();
+        for (HttpCookie cookie : mCookies) {
+            cookieHeader.add(removeObsoleteCookieAttributes(cookie).toString());
+        }
+        return cookieHeader.build();
+    }
+
+    private static List<HttpCookie> parseCookiesSafely(String rawCookie) {
+        try {
+            return HttpCookie.parse(rawCookie);
+        } catch (IllegalArgumentException e) {
+            logPii("Failed to parse cookie: " + rawCookie);
+            return ImmutableList.of();
+        }
+    }
+
+    /**
+     * Removes some attributes of the cookie that should not be set in HTTP requests.
+     *
+     * <p>Unfortunately, {@link HttpCookie#toString()} preserves some cookie attributes:
+     * Domain, Path, and Port as per RFC 2965. Such behavior is obsoleted by the RFC 6265.
+     *
+     * <p>To be clear, Domain and Path are valid attributes by RFC 6265, but cookie attributes
+     * be set in HTTP request "Cookie" headers.
+     */
+    private static HttpCookie removeObsoleteCookieAttributes(HttpCookie cookie) {
+        cookie.setDomain(null);
+        cookie.setPath(null);
+        cookie.setPortlist(null);
+        return cookie;
+    }
+}
diff --git a/tests/src/com/android/libraries/entitlement/http/HttpCookieJarTest.java b/tests/src/com/android/libraries/entitlement/http/HttpCookieJarTest.java
new file mode 100644
index 0000000..fb91e44
--- /dev/null
+++ b/tests/src/com/android/libraries/entitlement/http/HttpCookieJarTest.java
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package com.android.libraries.entitlement.http;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import androidx.test.runner.AndroidJUnit4;
+
+import com.google.common.collect.ImmutableList;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@RunWith(AndroidJUnit4.class)
+public class HttpCookieJarTest {
+    @Test
+    public void parseSetCookieHeaders_and_toCookieHeaders() {
+        ImmutableList<String> setCookieHeaders = ImmutableList.of(
+                "DEGCID=WnA8oHIgPbrYMbe+fDai/yhrNTY=; Path=/; Domain=.mobile.com",
+                "SID=dNbG%3D; Secure; HttpOnly"
+        );
+        ImmutableList<String> cookieHeaders = ImmutableList.of(
+                "DEGCID=WnA8oHIgPbrYMbe+fDai/yhrNTY=",
+                "SID=dNbG%3D"
+        );
+
+        HttpCookieJar cookieJar = HttpCookieJar.parseSetCookieHeaders(setCookieHeaders);
+
+        assertThat(cookieJar.toCookieHeaders()).isEqualTo(cookieHeaders);
+    }
+}
```

