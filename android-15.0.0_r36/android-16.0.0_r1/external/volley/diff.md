```diff
diff --git a/.github/ISSUE_TEMPLATE/bug_report.md b/.github/ISSUE_TEMPLATE/bug_report.md
new file mode 100644
index 0000000..3519f25
--- /dev/null
+++ b/.github/ISSUE_TEMPLATE/bug_report.md
@@ -0,0 +1,32 @@
+---
+name: Bug report
+about: Create a report to help us improve
+title: ''
+labels: ''
+assignees: ''
+
+---
+
+**Describe the bug**
+A clear and concise description of what the bug is.
+
+**To Reproduce**
+Steps to reproduce the behavior (e.g. sequence of API calls):
+1. Go to '...'
+2. Click on '....'
+3. Scroll down to '....'
+4. See error
+
+**Expected behavior**
+A clear and concise description of what you expected to happen.
+
+**Actual behavior**
+A clear and concise description of what you observed. In the case of a crash, please include the full stack trace.
+
+**Smartphone (please complete the following information):**
+ - Device: [e.g. Pixel 9, Emulator]
+ - OS: [e.g. Android 13]
+ - Library version [e.g. 1.1.1]
+
+**Additional context**
+Add any other context about the problem here. If at all possible, provide a sample app or code to reproduce the issue.
diff --git a/.github/workflows/codeql.yml b/.github/workflows/codeql.yml
new file mode 100644
index 0000000..655f8e1
--- /dev/null
+++ b/.github/workflows/codeql.yml
@@ -0,0 +1,42 @@
+name: "CodeQL"
+
+on:
+  push:
+    branches: [ 'master' ]
+  pull_request:
+    # The branches below must be a subset of the branches above
+    branches: [ 'master' ]
+  schedule:
+    - cron: '4 0 * * 6'
+
+jobs:
+  analyze:
+    name: Analyze
+    runs-on: ubuntu-latest
+    permissions:
+      actions: read
+      contents: read
+      security-events: write
+
+    strategy:
+      fail-fast: false
+      matrix:
+        language: [ 'java' ]
+
+    steps:
+    - name: Checkout repository
+      uses: actions/checkout@v3
+
+    # Initializes the CodeQL tools for scanning.
+    - name: Initialize CodeQL
+      uses: github/codeql-action/init@v2
+      with:
+        languages: ${{ matrix.language }}
+
+    - name: Autobuild
+      uses: github/codeql-action/autobuild@v2
+
+    - name: Perform CodeQL Analysis
+      uses: github/codeql-action/analyze@v2
+      with:
+        category: "/language:${{matrix.language}}"
diff --git a/.github/workflows/gradle-build.yaml b/.github/workflows/gradle-build.yaml
index c42648c..da0d26b 100644
--- a/.github/workflows/gradle-build.yaml
+++ b/.github/workflows/gradle-build.yaml
@@ -8,10 +8,11 @@ jobs:
 
     steps:
       - uses: actions/checkout@v2
-      - name: Set up JDK 1.8
-        uses: actions/setup-java@v1
+      - name: Set up JDK 11
+        uses: actions/setup-java@v3
         with:
-          java-version: 1.8
+          distribution: 'zulu'
+          java-version: '11'
       - name: Cache Gradle packages
         uses: actions/cache@v2
         with:
diff --git a/METADATA b/METADATA
index d97975c..df9d9d9 100644
--- a/METADATA
+++ b/METADATA
@@ -1,3 +1,16 @@
+name: "volley"
+description: "Volley is an HTTP library that makes networking for Android apps easier and, most importantly, faster."
 third_party {
   license_type: NOTICE
+  last_upgrade_date {
+    year: 2017
+    month: 2
+    day: 24
+  }
+  homepage: "https://google.github.io/volley"
+  identifier {
+    type: "Git"
+    value: "https://github.com/google/volley"
+    version: "9424680a52bc7804e0c7f0f71c2f1ea282f10cdd"
+  }
 }
diff --git a/OWNERS b/OWNERS
index 37eb132..825ef7b 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,3 +2,4 @@
 # Please update this list if you find better candidates.
 jpd@google.com
 yilanliu@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
index 78ca41e..e5cbe1c 100644
--- a/README.md
+++ b/README.md
@@ -3,5 +3,4 @@
 Volley is an HTTP library that makes networking for Android apps easier and, most
 importantly, faster.
 
-For more information about Volley and how to use it, visit the [Android developer training
-page](https://developer.android.com/training/volley/index.html).
+For more information about Volley and how to use it, visit the [documentation page](https://google.github.io/volley/).
diff --git a/build.gradle b/build.gradle
index b8db952..dc9c78c 100644
--- a/build.gradle
+++ b/build.gradle
@@ -1,21 +1,18 @@
 buildscript {
     repositories {
         gradlePluginPortal()
-        jcenter()
         google()
     }
     dependencies {
-        classpath 'com.android.tools.build:gradle:3.2.1'
-        classpath 'gradle.plugin.com.github.sherter.google-java-format:google-java-format-gradle-plugin:0.6'
-        // NOTE: 0.7 or newer will require upgrading to a newer Android gradle plugin:
-        // https://github.com/tbroyer/gradle-errorprone-plugin/commit/65b1026ebeae1b7ed8c28578c7f6eea512c16bea
-        classpath 'net.ltgt.errorprone:net.ltgt.errorprone.gradle.plugin:0.6.1'
+        classpath 'com.android.tools.build:gradle:7.4.1'
+        classpath 'gradle.plugin.com.github.sherter.google-java-format:google-java-format-gradle-plugin:0.9'
+        classpath 'net.ltgt.errorprone:net.ltgt.errorprone.gradle.plugin:2.0.2'
     }
 }
 
 allprojects {
     repositories {
-        jcenter()
+        mavenCentral()
         google()
     }
 }
@@ -41,13 +38,13 @@ subprojects {
     }
 
     group = 'com.android.volley'
-    version = '1.2.1-SNAPSHOT'
+    version = '1.2.2-SNAPSHOT'
 
     android {
         useLibrary 'org.apache.http.legacy'
 
         compileSdkVersion 28
-        buildToolsVersion = '28.0.3'
+        buildToolsVersion = '30.0.3'
 
         defaultConfig {
             minSdkVersion 8
diff --git a/core/build.gradle b/core/build.gradle
index 812968c..584ec06 100644
--- a/core/build.gradle
+++ b/core/build.gradle
@@ -5,24 +5,17 @@ android {
 }
 
 dependencies {
-    implementation "androidx.annotation:annotation:1.0.1"
+    compileOnly "androidx.annotation:annotation:1.0.1"
 
     testImplementation project(":testing")
     testImplementation "junit:junit:4.12"
     testImplementation "org.hamcrest:hamcrest-library:1.3"
     testImplementation "org.mockito:mockito-core:2.19.0"
-    testImplementation "org.robolectric:robolectric:3.4.2"
+    testImplementation "org.robolectric:robolectric:4.8.2"
+    // TODO(#424): Fix this dependency at the library level.
+    testImplementation "androidx.annotation:annotation:1.0.1"
 }
 
-publishing {
-    publications {
-        library(MavenPublication) {
-            artifactId 'volley'
-            pom {
-                name = 'Volley'
-                description = 'An HTTP library that makes networking for Android apps easier and, most importantly, faster.'
-            }
-            artifact "$buildDir/outputs/aar/core-release.aar"
-        }
-    }
-}
+project.ext.artifactId = 'volley'
+project.ext.pomName = 'Volley'
+project.ext.pomDescription = 'An HTTP library that makes networking for Android apps easier and, most importantly, faster.'
diff --git a/core/src/main/java/com/android/volley/toolbox/BasicAsyncNetwork.java b/core/src/main/java/com/android/volley/toolbox/BasicAsyncNetwork.java
index cdedaff..4d6924d 100644
--- a/core/src/main/java/com/android/volley/toolbox/BasicAsyncNetwork.java
+++ b/core/src/main/java/com/android/volley/toolbox/BasicAsyncNetwork.java
@@ -16,7 +16,7 @@
 
 package com.android.volley.toolbox;
 
-import static com.android.volley.toolbox.NetworkUtility.logSlowRequests;
+import static com.android.volley.toolbox.NetworkUtility.logRequestSummary;
 
 import android.os.SystemClock;
 import androidx.annotation.NonNull;
@@ -213,9 +213,9 @@ public class BasicAsyncNetwork extends AsyncNetwork {
             OnRequestComplete callback,
             List<Header> responseHeaders,
             byte[] responseContents) {
-        // if the request is slow, log it.
+        // log request when debugging is enabled.
         long requestLifetime = SystemClock.elapsedRealtime() - requestStartMs;
-        logSlowRequests(requestLifetime, request, responseContents, statusCode);
+        logRequestSummary(requestLifetime, request, responseContents, statusCode);
 
         if (statusCode < 200 || statusCode > 299) {
             onRequestFailed(
diff --git a/core/src/main/java/com/android/volley/toolbox/BasicNetwork.java b/core/src/main/java/com/android/volley/toolbox/BasicNetwork.java
index 552e628..8cd817e 100644
--- a/core/src/main/java/com/android/volley/toolbox/BasicNetwork.java
+++ b/core/src/main/java/com/android/volley/toolbox/BasicNetwork.java
@@ -124,9 +124,9 @@ public class BasicNetwork implements Network {
                     responseContents = new byte[0];
                 }
 
-                // if the request is slow, log it.
+                // log request when debugging is enabled.
                 long requestLifetime = SystemClock.elapsedRealtime() - requestStart;
-                NetworkUtility.logSlowRequests(
+                NetworkUtility.logRequestSummary(
                         requestLifetime, request, responseContents, statusCode);
 
                 if (statusCode < 200 || statusCode > 299) {
diff --git a/core/src/main/java/com/android/volley/toolbox/NetworkUtility.java b/core/src/main/java/com/android/volley/toolbox/NetworkUtility.java
index 58a3bb3..5683f16 100644
--- a/core/src/main/java/com/android/volley/toolbox/NetworkUtility.java
+++ b/core/src/main/java/com/android/volley/toolbox/NetworkUtility.java
@@ -43,14 +43,12 @@ import java.util.List;
  * BasicAsyncNetwork}
  */
 final class NetworkUtility {
-    private static final int SLOW_REQUEST_THRESHOLD_MS = 3000;
-
     private NetworkUtility() {}
 
-    /** Logs requests that took over SLOW_REQUEST_THRESHOLD_MS to complete. */
-    static void logSlowRequests(
+    /** Logs a summary about the request when debug logging is enabled. */
+    static void logRequestSummary(
             long requestLifetime, Request<?> request, byte[] responseContents, int statusCode) {
-        if (VolleyLog.DEBUG || requestLifetime > SLOW_REQUEST_THRESHOLD_MS) {
+        if (VolleyLog.DEBUG) {
             VolleyLog.d(
                     "HTTP response for request=<%s> [lifetime=%d], [size=%s], "
                             + "[rc=%d], [retryCount=%s]",
diff --git a/core/src/test/java/com/android/volley/CacheDispatcherTest.java b/core/src/test/java/com/android/volley/CacheDispatcherTest.java
index aef6785..1196fd8 100644
--- a/core/src/test/java/com/android/volley/CacheDispatcherTest.java
+++ b/core/src/test/java/com/android/volley/CacheDispatcherTest.java
@@ -19,7 +19,7 @@ package com.android.volley;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertSame;
 import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.Matchers.anyString;
+import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.inOrder;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
diff --git a/cronet/build.gradle b/cronet/build.gradle
index 5ee53d6..e98355b 100644
--- a/cronet/build.gradle
+++ b/cronet/build.gradle
@@ -1,24 +1,17 @@
 dependencies {
-    implementation project(":core")
-    implementation "androidx.annotation:annotation:1.0.1"
-    compileOnly "org.chromium.net:cronet-embedded:76.3809.111"
+    api project(":core")
+    compileOnly "androidx.annotation:annotation:1.0.1"
+    compileOnly "org.chromium.net:cronet-embedded:113.5672.61"
 
     testImplementation project(":testing")
-    testImplementation "org.chromium.net:cronet-embedded:76.3809.111"
+    testImplementation "org.chromium.net:cronet-embedded:113.5672.61"
     testImplementation "junit:junit:4.12"
     testImplementation "org.mockito:mockito-core:2.19.0"
-    testImplementation "org.robolectric:robolectric:3.4.2"
+    testImplementation "org.robolectric:robolectric:4.8.2"
+    // TODO(#424): Fix this dependency at the library level.
+    testImplementation "androidx.annotation:annotation:1.0.1"
 }
 
-publishing {
-    publications {
-        library(MavenPublication) {
-            artifactId 'volley-cronet'
-            pom {
-                name = 'Volley Cronet'
-                description = 'Cronet support for Volley.'
-            }
-            artifact "$buildDir/outputs/aar/cronet-release.aar"
-        }
-    }
-}
+project.ext.artifactId = 'volley-cronet'
+project.ext.pomName = 'Volley Cronet'
+project.ext.pomDescription = 'Cronet support for Volley.'
diff --git a/cronet/src/main/java/com/android/volley/cronet/CronetHttpStack.java b/cronet/src/main/java/com/android/volley/cronet/CronetHttpStack.java
index 874029b..14aea6f 100644
--- a/cronet/src/main/java/com/android/volley/cronet/CronetHttpStack.java
+++ b/cronet/src/main/java/com/android/volley/cronet/CronetHttpStack.java
@@ -171,7 +171,8 @@ public class CronetHttpStack extends AsyncHttpStack {
                         .newUrlRequestBuilder(url, urlCallback, getNonBlockingExecutor())
                         .allowDirectExecutor()
                         .disableCache()
-                        .setPriority(getPriority(request));
+                        .setPriority(getPriority(request))
+                        .setTrafficStatsTag(request.getTrafficStatsTag());
         // request.getHeaders() may be blocking, so submit it to the blocking executor.
         getBlockingExecutor()
                 .execute(
diff --git a/docs/_config.yml b/docs/_config.yml
new file mode 100644
index 0000000..64f1aaf
--- /dev/null
+++ b/docs/_config.yml
@@ -0,0 +1 @@
+title: Volley
diff --git a/docs/_data/navigation.yml b/docs/_data/navigation.yml
new file mode 100644
index 0000000..c240a21
--- /dev/null
+++ b/docs/_data/navigation.yml
@@ -0,0 +1,11 @@
+nav:
+  - title: "Overview"
+    url: "/"
+  - title: "Send a simple request"
+    url: "/simple.html"
+  - title: "Set up a RequestQueue"
+    url: "/requestqueue.html"
+  - title: "Make a standard request"
+    url: "/request.html"
+  - title: "Implement a custom request"
+    url: "/request-custom.html"
diff --git a/docs/_layouts/default.html b/docs/_layouts/default.html
new file mode 100644
index 0000000..2d75bdc
--- /dev/null
+++ b/docs/_layouts/default.html
@@ -0,0 +1,44 @@
+<!DOCTYPE html>
+<html lang="{{ site.lang | default: "en-US" }}">
+<head>
+    <meta charset="UTF-8">
+    <meta http-equiv="X-UA-Compatible" content="IE=edge">
+    <meta name="viewport" content="width=device-width, initial-scale=1">
+    {% seo %}
+    <link rel="stylesheet" href="{{ "/assets/css/style.css?v=" | append: site.github.build_revision | relative_url }}">
+</head>
+<body>
+<div class="sidebar">
+    <div class="header">
+        <h1><a href="{{ "/" | relative_url }}">{{ site.title | default: "Documentation" }}</a></h1>
+    </div>
+    <input type="checkbox" id="nav-toggle" class="nav-toggle">
+    <label for="nav-toggle" class="expander">
+        <span class="arrow"></span>
+    </label>
+    <nav>
+        <ul>
+            {% for item in site.data.navigation.nav %}
+            <a href="{{item.url | relative_url }}">
+                <li class="{% if item.url == page.url %}active{% endif %}">
+                    {{ item.title }}
+                </li>
+            </a>
+            {% endfor %}
+        </ul>
+    </nav>
+</div>
+<div class="main markdown-body">
+    <div class="main-inner">
+        {{ content }}
+    </div>
+    <div class="footer">
+        Volley &middot;
+        <a href="https://github.com/google/volley">GitHub Repository</a> &middot;
+        <a href="https://github.com/google/volley/blob/master/LICENSE">License</a>
+    </div>
+</div>
+<script src="https://cdnjs.cloudflare.com/ajax/libs/anchor-js/4.1.0/anchor.min.js" integrity="sha256-lZaRhKri35AyJSypXXs4o6OPFTbTmUoltBbDCbdzegg=" crossorigin="anonymous"></script>
+<script>anchors.add('.main h2, .main h3, .main h4, .main h5, .main h6');</script>
+</body>
+</html>
diff --git a/docs/_sass/main.scss b/docs/_sass/main.scss
new file mode 100644
index 0000000..6d1ee26
--- /dev/null
+++ b/docs/_sass/main.scss
@@ -0,0 +1,199 @@
+// Color variables are defined in
+// https://github.com/pages-themes/primer/tree/master/_sass/primer-support/lib/variables
+
+$sidebar-width: 260px;
+
+body {
+  display: flex;
+  margin: 0;
+}
+
+.sidebar {
+  background: $black;
+  color: $text-white;
+  flex-shrink: 0;
+  height: 100vh;
+  overflow: auto;
+  position: sticky;
+  top: 0;
+  width: $sidebar-width;
+}
+
+.sidebar h1 {
+  font-size: 1.5em;
+}
+
+.sidebar h2 {
+  color: $gray-light;
+  font-size: 0.8em;
+  font-weight: normal;
+  margin-bottom: 0.8em;
+  padding-left: 2.5em;
+  text-transform: uppercase;
+}
+
+.sidebar .header {
+  background: $black;
+  padding: 2em;
+  position: sticky;
+  top: 0;
+  width: 100%;
+}
+
+.sidebar .header a {
+  color: $text-white;
+  text-decoration: none;
+}
+
+.sidebar .nav-toggle {
+  display: none;
+}
+
+.sidebar .expander {
+  cursor: pointer;
+  display: none;
+  height: 3em;
+  position: absolute;
+  right: 1em;
+  top: 1.5em;
+  width: 3em;
+}
+
+.sidebar .expander .arrow {
+  border: solid $white;
+  border-width: 0 3px 3px 0;
+  display: block;
+  height: 0.7em;
+  margin: 1em auto;
+  transform: rotate(45deg);
+  transition: transform 0.5s;
+  width: 0.7em;
+}
+
+.sidebar nav {
+  width: 100%;
+}
+
+.sidebar nav ul {
+  list-style-type: none;
+  margin-bottom: 1em;
+  padding: 0;
+
+  &:last-child {
+    margin-bottom: 2em;
+  }
+
+  a {
+   text-decoration: none;
+  }
+
+  li {
+    color: $text-white;
+    padding-left: 2em;
+    text-decoration: none;
+  }
+
+  li.active {
+    background: $border-gray-darker;
+    font-weight: bold;
+  }
+
+  li:hover {
+    background: $border-gray-darker;
+  }
+}
+
+.main {
+  background-color: $bg-gray;
+  width: calc(100% - #{$sidebar-width});
+}
+
+.main .main-inner {
+  background-color: $white;
+  padding: 2em;
+}
+
+.main .footer {
+  margin: 0;
+  padding: 2em;
+}
+
+.main table th {
+  text-align: left;
+}
+
+.main .callout {
+  border-left: 0.25em solid $white;
+  padding: 1em;
+
+  a {
+    text-decoration: underline;
+  }
+
+  &.important {
+    background-color: $bg-yellow-light;
+    border-color: $bg-yellow;
+    color: $black;
+  }
+
+  &.note {
+    background-color: $bg-blue-light;
+    border-color: $text-blue;
+    color: $text-blue;
+  }
+
+  &.tip {
+    background-color: $green-000;
+    border-color: $green-700;
+    color: $green-700;
+  }
+
+  &.warning {
+    background-color: $red-000;
+    border-color: $text-red;
+    color: $text-red;
+  }
+}
+
+.main .good pre {
+  background-color: $bg-green-light;
+}
+
+.main .bad pre {
+  background-color: $red-000;
+}
+
+@media all and (max-width: 768px) {
+  body {
+    flex-direction: column;
+  }
+
+  .sidebar {
+    height: auto;
+    position: relative;
+    width: 100%;
+  }
+
+  .sidebar .expander {
+    display: block;
+  }
+
+  .sidebar nav {
+    height: 0;
+    overflow: hidden;
+  }
+
+  .sidebar .nav-toggle:checked {
+    & ~ nav {
+      height: auto;
+    }
+
+    & + .expander .arrow {
+      transform: rotate(-135deg);
+    }
+  }
+
+  .main {
+    width: 100%;
+  }
+}
\ No newline at end of file
diff --git a/docs/assets/css/style.scss b/docs/assets/css/style.scss
new file mode 100644
index 0000000..bb30f41
--- /dev/null
+++ b/docs/assets/css/style.scss
@@ -0,0 +1,5 @@
+---
+---
+
+@import "jekyll-theme-primer";
+@import "main";
diff --git a/docs/images/volley-request.png b/docs/images/volley-request.png
new file mode 100644
index 0000000..e495ae4
Binary files /dev/null and b/docs/images/volley-request.png differ
diff --git a/docs/index.md b/docs/index.md
new file mode 100644
index 0000000..8fad81c
--- /dev/null
+++ b/docs/index.md
@@ -0,0 +1,81 @@
+# Volley overview
+
+Volley is an HTTP library that makes networking for Android apps easier and most importantly,
+faster. Volley is available on [GitHub](https://github.com/google/volley).
+
+Volley offers the following benefits:
+
+- Automatic scheduling of network requests.
+- Multiple concurrent network connections.
+- Transparent disk and memory response caching with standard HTTP 
+  [cache coherence](https://en.wikipedia.org/wiki/Cache_coherence).
+- Support for request prioritization.
+- Cancellation request API. You can cancel a single request, or you can set blocks or scopes of 
+  requests to cancel.
+- Ease of customization, for example, for retry and backoff.
+- Strong ordering that makes it easy to correctly populate your UI with data fetched asynchronously 
+  from the network.
+- Debugging and tracing tools.
+
+Volley excels at RPC-type operations used to populate a UI, such as fetching a page of
+search results as structured data. It integrates easily with any protocol and comes out of
+the box with support for raw strings, images, and JSON. By providing built-in support for
+the features you need, Volley frees you from writing boilerplate code and allows you to
+concentrate on the logic that is specific to your app.
+Volley is not suitable for large download or streaming operations, since Volley holds
+all responses in memory during parsing. For large download operations, consider using an
+alternative like
+[`DownloadManager`](https://developer.android.com/reference/android/app/DownloadManager).
+
+The core Volley library is developed on [GitHub](https://github.com/google/volley) and
+contains the main request dispatch pipeline as well as a set of commonly applicable utilities,
+available in the Volley "toolbox." The easiest way to add Volley to your project is to add the
+following dependency to your app's build.gradle file:
+
+*Groovy*
+
+```groovy
+dependencies {
+    implementation 'com.android.volley:volley:1.2.1'
+}
+```
+
+*Kotlin*
+
+```kotlin
+dependencies {
+    implementation("com.android.volley:volley:1.2.1")
+}
+```
+
+You can also clone the Volley repository and set it as a library project:
+
+1. Git clone the repository by typing the following at the command line:
+
+    ```console
+    git clone https://github.com/google/volley
+    ```
+
+2. Import the downloaded source into your app project as an Android library module as described
+   in [Create an Android Library](https://developer.android.com/studio/projects/android-library).
+
+## Lessons
+
+[**Send a simple request**](./simple.md)
+
+Learn how to send a simple request using the default behaviors of Volley, and how
+to cancel a request.
+
+[**Set up RequestQueue**](./requestqueue.md)
+
+Learn how to set up a `RequestQueue`, and how to implement a singleton
+pattern to create a `RequestQueue` that lasts the lifetime of your app.
+
+[**Make a standard request**](./request.md)
+
+Learn how to send a request using one of Volley's out-of-the-box request types
+(raw strings, images, and JSON).
+
+[**Implement a custom request**](./request-custom.md)
+
+Learn how to implement a custom request.
diff --git a/docs/request-custom.md b/docs/request-custom.md
new file mode 100644
index 0000000..f714c8d
--- /dev/null
+++ b/docs/request-custom.md
@@ -0,0 +1,208 @@
+# Implement a custom request
+
+This lesson describes how to implement your own custom request types, for types that
+don't have out-of-the-box Volley support.
+
+## Write a custom request
+
+Most requests have ready-to-use implementations in the toolbox; if your response is a string,
+image, or JSON, you probably won't need to implement a custom `Request`.
+
+For cases where you do need to implement a custom request, this is all you need
+to do:
+
+- Extend the `Request<T>` class, where `<T>` represents the type of parsed response
+  the request expects. So if your parsed response is a string, for example,
+  create your custom request by extending `Request<String>`. See the Volley
+  toolbox classes `StringRequest` and `ImageRequest` for examples of
+  extending `Request<T>`.
+- Implement the abstract methods `parseNetworkResponse()`
+  and `deliverResponse()`, described in more detail below.
+
+### parseNetworkResponse
+
+A `Response` encapsulates a parsed response for delivery, for a given type
+(such as string, image, or JSON). Here is a sample implementation of
+`parseNetworkResponse()`:
+
+*Kotlin*
+
+```kotlin
+override fun parseNetworkResponse(response: NetworkResponse?): Response<T> {
+    return try {
+        val json = String(
+                response?.data ?: ByteArray(0),
+                Charset.forName(HttpHeaderParser.parseCharset(response?.headers)))
+        Response.success(
+                gson.fromJson(json, clazz),
+                HttpHeaderParser.parseCacheHeaders(response))
+    }
+    // handle errors
+}
+```
+
+*Java*
+
+```java
+@Override
+protected Response<T> parseNetworkResponse(NetworkResponse response) {
+    try {
+        String json = new String(response.data,
+                HttpHeaderParser.parseCharset(response.headers));
+        return Response.success(gson.fromJson(json, clazz),
+                HttpHeaderParser.parseCacheHeaders(response));
+    }
+    // handle errors
+}
+```
+
+Note the following:
+
+- `parseNetworkResponse()` takes as its parameter a `NetworkResponse`, which
+  contains the response payload as a byte[], HTTP status code, and response headers.
+- Your implementation must return a `Response<T>`, which contains your typed
+  response object and cache metadata or an error, such as in the case of a parse failure.
+
+If your protocol has non-standard cache semantics, you can build a `Cache.Entry`
+yourself, but most requests are fine with something like this:
+
+*Kotlin*
+
+```kotlin
+return Response.success(myDecodedObject,
+        HttpHeaderParser.parseCacheHeaders(response))
+```
+
+*Java*
+
+```java
+return Response.success(myDecodedObject,
+        HttpHeaderParser.parseCacheHeaders(response));
+```
+
+Volley calls `parseNetworkResponse()` from a worker thread. This ensures that
+expensive parsing operations, such as decoding a JPEG into a Bitmap, don't block the UI
+thread.
+
+### deliverResponse
+
+Volley calls you back on the main thread with the object you returned in
+`parseNetworkResponse()`. Most requests invoke a callback interface here,
+for example:
+
+*Kotlin*
+
+```kotlin
+override fun deliverResponse(response: T) = listener.onResponse(response)
+```
+
+*Java*
+
+```java
+protected void deliverResponse(T response) {
+    listener.onResponse(response);
+}
+```
+
+## Example: GsonRequest
+
+[Gson](https://github.com/google/gson) is a library for converting
+Java objects to and from JSON using reflection. You can define Java objects that have the
+same names as their corresponding JSON keys, pass Gson the class object, and Gson will fill
+in the fields for you. Here's a complete implementation of a Volley request that uses
+Gson for parsing:
+
+*Kotlin*
+
+```kotlin
+/**
+ * Make a GET request and return a parsed object from JSON.
+ *
+ * @param url URL of the request to make
+ * @param clazz Relevant class object, for Gson's reflection
+ * @param headers Map of request headers
+ */
+class GsonRequest<T>(
+        url: String,
+        private val clazz: Class<T>,
+        private val headers: MutableMap<String, String>?,
+        private val listener: Response.Listener<T>,
+        errorListener: Response.ErrorListener
+) : Request<T>(Method.GET, url, errorListener) {
+    private val gson = Gson()
+
+    override fun getHeaders(): MutableMap<String, String> = headers ?: super.getHeaders()
+
+    override fun deliverResponse(response: T) = listener.onResponse(response)
+
+    override fun parseNetworkResponse(response: NetworkResponse?): Response<T> {
+        return try {
+            val json = String(
+                    response?.data ?: ByteArray(0),
+                    Charset.forName(HttpHeaderParser.parseCharset(response?.headers)))
+            Response.success(
+                    gson.fromJson(json, clazz),
+                    HttpHeaderParser.parseCacheHeaders(response))
+        } catch (e: UnsupportedEncodingException) {
+            Response.error(ParseError(e))
+        } catch (e: JsonSyntaxException) {
+            Response.error(ParseError(e))
+        }
+    }
+}
+```
+
+*Java*
+
+```java
+public class GsonRequest<T> extends Request<T> {
+    private final Gson gson = new Gson();
+    private final Class<T> clazz;
+    private final Map<String, String> headers;
+    private final Listener<T> listener;
+
+    /**
+     * Make a GET request and return a parsed object from JSON.
+     *
+     * @param url URL of the request to make
+     * @param clazz Relevant class object, for Gson's reflection
+     * @param headers Map of request headers
+     */
+    public GsonRequest(String url, Class<T> clazz, Map<String, String> headers,
+            Listener<T> listener, ErrorListener errorListener) {
+        super(Method.GET, url, errorListener);
+        this.clazz = clazz;
+        this.headers = headers;
+        this.listener = listener;
+    }
+
+    @Override
+    public Map<String, String> getHeaders() throws AuthFailureError {
+        return headers != null ? headers : super.getHeaders();
+    }
+
+    @Override
+    protected void deliverResponse(T response) {
+        listener.onResponse(response);
+    }
+
+    @Override
+    protected Response<T> parseNetworkResponse(NetworkResponse response) {
+        try {
+            String json = new String(
+                    response.data,
+                    HttpHeaderParser.parseCharset(response.headers));
+            return Response.success(
+                    gson.fromJson(json, clazz),
+                    HttpHeaderParser.parseCacheHeaders(response));
+        } catch (UnsupportedEncodingException e) {
+            return Response.error(new ParseError(e));
+        } catch (JsonSyntaxException e) {
+            return Response.error(new ParseError(e));
+        }
+    }
+}
+```
+
+Volley provides ready-to-use `JsonArrayRequest` and `JsonArrayObject` classes
+if you prefer to take that approach. See [Make a standard request](request.md) for more information.
diff --git a/docs/request.md b/docs/request.md
new file mode 100644
index 0000000..9e66989
--- /dev/null
+++ b/docs/request.md
@@ -0,0 +1,78 @@
+# Make a standard request
+
+This lesson describes how to use the common request types that Volley supports:
+
+- `StringRequest`. Specify a URL and receive a raw string in response. See
+  [Set up a RequestQueue](requestqueue.md) for an example.
+- `JsonObjectRequest` and `JsonArrayRequest` (both subclasses of
+  `JsonRequest`). Specify a URL and get a JSON object or array (respectively) in
+  response.
+
+If your expected response is one of these types, you probably don't have to implement a
+custom request. This lesson describes how to use these standard request types. For
+information on how to implement your own custom request, see
+[Implement a custom request](./request-custom.md).
+
+## Request JSON
+
+Volley provides the following classes for JSON requests:
+
+- `JsonArrayRequest`: A request for retrieving a
+  [`JSONArray`](https://developer.android.com/reference/org/json/JSONArray)
+  response body at a given URL.
+- `JsonObjectRequest`: A request for retrieving a
+  [`JSONObject`](https://developer.android.com/reference/org/json/JSONObject)
+  response body at a given URL, allowing for an optional
+  [`JSONObject`](https://developer.android.com/reference/org/json/JSONObject)
+  to be passed in as part of the request body.
+
+Both classes are based on the common base class `JsonRequest`. You use them
+following the same basic pattern you use for other types of requests. For example, this
+snippet fetches a JSON feed and displays it as text in the UI:
+
+*Kotlin*
+
+```kotlin
+val url = "http://my-json-feed"
+
+val jsonObjectRequest = JsonObjectRequest(Request.Method.GET, url, null,
+        Response.Listener { response ->
+            textView.text = "Response: %s".format(response.toString())
+        },
+        Response.ErrorListener { error ->
+            // TODO: Handle error
+        }
+)
+
+// Access the RequestQueue through your singleton class.
+MySingleton.getInstance(this).addToRequestQueue(jsonObjectRequest)
+```
+
+*Java*
+
+```java
+String url = "http://my-json-feed";
+
+JsonObjectRequest jsonObjectRequest = new JsonObjectRequest
+        (Request.Method.GET, url, null, new Response.Listener<JSONObject>() {
+
+    @Override
+    public void onResponse(JSONObject response) {
+        textView.setText("Response: " + response.toString());
+    }
+}, new Response.ErrorListener() {
+
+    @Override
+    public void onErrorResponse(VolleyError error) {
+        // TODO: Handle error
+
+    }
+});
+
+// Access the RequestQueue through your singleton class.
+MySingleton.getInstance(this).addToRequestQueue(jsonObjectRequest);
+```
+
+For an example of implementing a custom JSON request based on
+[Gson](https://github.com/google/gson), see the next lesson,
+[Implement a custom request](request-custom.md).
diff --git a/docs/requestqueue.md b/docs/requestqueue.md
new file mode 100644
index 0000000..e020175
--- /dev/null
+++ b/docs/requestqueue.md
@@ -0,0 +1,246 @@
+# Set up a RequestQueue
+
+The previous lesson showed you how to use the convenience method
+`Volley.newRequestQueue` to set up a `RequestQueue`, taking advantage of
+Volley's default behaviors. This lesson walks you through the explicit steps of creating a
+`RequestQueue`, to allow you to supply your own custom behavior.
+
+This lesson also describes the recommended practice of creating a `RequestQueue`
+as a singleton, which makes the `RequestQueue` last the lifetime of your app.
+
+## Set up a network and cache
+
+A `RequestQueue` needs two things to do its job: a network to perform transport
+of the requests, and a cache to handle caching. There are standard implementations of these
+available in the Volley toolbox: `DiskBasedCache` provides a one-file-per-response
+cache with an in-memory index, and `BasicNetwork` provides a network transport based
+on your preferred HTTP client.
+
+`BasicNetwork` is Volley's default network implementation. A `BasicNetwork`
+must be initialized with the HTTP client your app is using to connect to the network.
+Typically this is an
+[`HttpURLConnection`](https://developer.android.com/reference/java/net/HttpURLConnection).
+
+This snippet shows you the steps involved in setting up a `RequestQueue`:
+
+*Kotlin*
+
+```kotlin
+// Instantiate the cache
+val cache = DiskBasedCache(cacheDir, 1024 * 1024) // 1MB cap
+
+// Set up the network to use HttpURLConnection as the HTTP client.
+val network = BasicNetwork(HurlStack())
+
+// Instantiate the RequestQueue with the cache and network. Start the queue.
+val requestQueue = RequestQueue(cache, network).apply {
+    start()
+}
+
+val url = "http://www.example.com"
+
+// Formulate the request and handle the response.
+val stringRequest = StringRequest(Request.Method.GET, url,
+         Response.Listener<String> { response ->
+            // Do something with the response
+        },
+        Response.ErrorListener { error ->
+            // Handle error
+            textView.text = "ERROR: %s".format(error.toString())
+        })
+
+// Add the request to the RequestQueue.
+requestQueue.add(stringRequest)
+
+// ...
+```
+
+*Java*
+
+```java
+RequestQueue requestQueue;
+
+// Instantiate the cache
+Cache cache = new DiskBasedCache(getCacheDir(), 1024 * 1024); // 1MB cap
+
+// Set up the network to use HttpURLConnection as the HTTP client.
+Network network = new BasicNetwork(new HurlStack());
+
+// Instantiate the RequestQueue with the cache and network.
+requestQueue = new RequestQueue(cache, network);
+
+// Start the queue
+requestQueue.start();
+
+String url = "http://www.example.com";
+
+// Formulate the request and handle the response.
+StringRequest stringRequest = new StringRequest(Request.Method.GET, url,
+        new Response.Listener<String>() {
+    @Override
+    public void onResponse(String response) {
+        // Do something with the response
+    }
+},
+    new Response.ErrorListener() {
+        @Override
+        public void onErrorResponse(VolleyError error) {
+            // Handle error
+    }
+});
+
+// Add the request to the RequestQueue.
+requestQueue.add(stringRequest);
+
+// ...
+```
+
+If you just need to make a one-time request and don't want to leave the thread pool
+around, you can create the `RequestQueue` wherever you need it and call `stop()` on the
+`RequestQueue` once your response or error has come back, using the
+`Volley.newRequestQueue()` method described in [Sending a Simple Request](./simple.md).
+But the more common use case is to create the `RequestQueue` as a
+singleton to keep it running for the lifetime of your app, as described in the next section.
+
+## Use a singleton pattern
+
+If your application makes constant use of the network, it's probably most efficient to
+set up a single instance of `RequestQueue` that will last the lifetime of your app.
+You can achieve this in various ways. The recommended approach is to implement a singleton
+class that encapsulates `RequestQueue` and other Volley functionality. Another approach is to
+subclass [`Application`](https://developer.android.com/reference/android/app/Application) and 
+set up the `RequestQueue` in
+[`Application.onCreate()`](https://developer.android.com/reference/android/app/Application#onCreate()).
+But this approach is discouraged; a static singleton can provide the same functionality in a 
+more modular way.
+
+A key concept is that the `RequestQueue` must be instantiated with the
+[`Application`](https://developer.android.com/reference/android/app/Application) context, not an
+[`Activity`](https://developer.android.com/reference/android/app/Activity) context. This
+ensures that the `RequestQueue` will last for the lifetime of your app, instead of
+being recreated every time the activity is recreated (for example, when the user
+rotates the device).
+
+Here is an example of a singleton class that provides `RequestQueue` and
+`ImageLoader` functionality:
+
+*Kotlin*
+
+```kotlin
+class MySingleton constructor(context: Context) {
+    companion object {
+        @Volatile
+        private var INSTANCE: MySingleton? = null
+        fun getInstance(context: Context) =
+            INSTANCE ?: synchronized(this) {
+                INSTANCE ?: MySingleton(context).also {
+                    INSTANCE = it
+                }
+            }
+    }
+    val imageLoader: ImageLoader by lazy {
+        ImageLoader(requestQueue,
+                object : ImageLoader.ImageCache {
+                    private val cache = LruCache<String, Bitmap>(20)
+                    override fun getBitmap(url: String): Bitmap? {
+                        return cache.get(url)
+                    }
+                    override fun putBitmap(url: String, bitmap: Bitmap) {
+                        cache.put(url, bitmap)
+                    }
+                })
+    }
+    val requestQueue: RequestQueue by lazy {
+        // applicationContext is key, it keeps you from leaking the
+        // Activity or BroadcastReceiver if someone passes one in.
+        Volley.newRequestQueue(context.applicationContext)
+    }
+    fun <T> addToRequestQueue(req: Request<T>) {
+        requestQueue.add(req)
+    }
+}
+```
+
+*Java*
+
+```java
+public class MySingleton {
+    private static MySingleton instance;
+    private RequestQueue requestQueue;
+    private ImageLoader imageLoader;
+    private static Context ctx;
+
+    private MySingleton(Context context) {
+        ctx = context;
+        requestQueue = getRequestQueue();
+
+        imageLoader = new ImageLoader(requestQueue,
+                new ImageLoader.ImageCache() {
+            private final LruCache<String, Bitmap>
+                    cache = new LruCache<String, Bitmap>(20);
+
+            @Override
+            public Bitmap getBitmap(String url) {
+                return cache.get(url);
+            }
+
+            @Override
+            public void putBitmap(String url, Bitmap bitmap) {
+                cache.put(url, bitmap);
+            }
+        });
+    }
+
+    public static synchronized MySingleton getInstance(Context context) {
+        if (instance == null) {
+            instance = new MySingleton(context);
+        }
+        return instance;
+    }
+
+    public RequestQueue getRequestQueue() {
+        if (requestQueue == null) {
+            // getApplicationContext() is key, it keeps you from leaking the
+            // Activity or BroadcastReceiver if someone passes one in.
+            requestQueue = Volley.newRequestQueue(ctx.getApplicationContext());
+        }
+        return requestQueue;
+    }
+
+    public <T> void addToRequestQueue(Request<T> req) {
+        getRequestQueue().add(req);
+    }
+
+    public ImageLoader getImageLoader() {
+        return imageLoader;
+    }
+}
+```
+
+Here are some examples of performing `RequestQueue` operations using the singleton
+class:
+
+*Kotlin*
+
+```kotlin
+// Get a RequestQueue
+val queue = MySingleton.getInstance(this.applicationContext).requestQueue
+
+// ...
+
+// Add a request (in this example, called stringRequest) to your RequestQueue.
+MySingleton.getInstance(this).addToRequestQueue(stringRequest)
+```
+
+*Java*
+
+```java
+// Get a RequestQueue
+RequestQueue queue = MySingleton.getInstance(this.getApplicationContext()).
+    getRequestQueue();
+
+// ...
+
+// Add a request (in this example, called stringRequest) to your RequestQueue.
+MySingleton.getInstance(this).addToRequestQueue(stringRequest);
+```
diff --git a/docs/simple.md b/docs/simple.md
new file mode 100644
index 0000000..1130400
--- /dev/null
+++ b/docs/simple.md
@@ -0,0 +1,192 @@
+# Send a simple request
+
+At a high level, you use Volley by creating a `RequestQueue` and passing it
+`Request` objects. The `RequestQueue` manages worker threads for running the
+network operations, reading from and writing to the cache, and parsing responses. Requests
+do the parsing of raw responses and Volley takes care of dispatching the parsed response
+back to the main thread for delivery.
+
+This lesson describes how to send a request using the `Volley.newRequestQueue`
+convenience method, which sets up a `RequestQueue` for you.
+See the next lesson, [Setting Up a RequestQueue](./requestqueue.md), for information on how to set
+up a `RequestQueue` yourself.
+
+This lesson also describes how to add a request to a `RequestQueue` and cancel a
+request.
+
+## Add the INTERNET permission
+
+To use Volley, you must add the
+[`android.permission.INTERNET`](https://developer.android.com/reference/android/Manifest.permission#INTERNET)
+permission to your app's manifest. Without this, your app won't be able to connect to the network.
+
+## Use newRequestQueue
+
+Volley provides a convenience method `Volley.newRequestQueue` that sets up a
+`RequestQueue` for you, using default values, and starts the queue. For example:
+
+*Kotlin*
+
+```kotlin
+val textView = findViewById<TextView>(R.id.text)
+// ...
+
+// Instantiate the RequestQueue.
+val queue = Volley.newRequestQueue(this)
+val url = "https://www.google.com"
+
+// Request a string response from the provided URL.
+val stringRequest = StringRequest(Request.Method.GET, url,
+        Response.Listener<String> { response ->
+            // Display the first 500 characters of the response string.
+            textView.text = "Response is: ${response.substring(0, 500)}"
+        },
+        Response.ErrorListener { textView.text = "That didn't work!" })
+
+// Add the request to the RequestQueue.
+queue.add(stringRequest)
+```
+
+*Java*
+
+```java
+final TextView textView = (TextView) findViewById(R.id.text);
+// ...
+
+// Instantiate the RequestQueue.
+RequestQueue queue = Volley.newRequestQueue(this);
+String url = "https://www.google.com";
+
+// Request a string response from the provided URL.
+StringRequest stringRequest = new StringRequest(Request.Method.GET, url,
+            new Response.Listener<String>() {
+    @Override
+    public void onResponse(String response) {
+        // Display the first 500 characters of the response string.
+        textView.setText("Response is: " + response.substring(0,500));
+    }
+}, new Response.ErrorListener() {
+    @Override
+    public void onErrorResponse(VolleyError error) {
+        textView.setText("That didn't work!");
+    }
+});
+
+// Add the request to the RequestQueue.
+queue.add(stringRequest);
+```
+
+Volley always delivers parsed responses on the main thread. Running on the main thread
+is convenient for populating UI controls with received data, as you can freely modify UI
+controls directly from your response handler, but it's especially critical to many of the
+important semantics provided by the library, particularly related to canceling requests.
+
+See [Setting Up a RequestQueue](requestqueue.md) for a
+description of how to set up a `RequestQueue` yourself, instead of using the
+`Volley.newRequestQueue` convenience method.
+
+## Send a request
+
+To send a request, you simply construct one and add it to the `RequestQueue` with
+`add()`, as shown above. Once you add the request it moves through the pipeline,
+gets serviced, and has its raw response parsed and delivered.
+
+When you call `add()`, Volley runs one cache processing thread and a pool of
+network dispatch threads. When you add a request to the queue, it is picked up by the cache
+thread and triaged: if the request can be serviced from cache, the cached response is
+parsed on the cache thread and the parsed response is delivered on the main thread. If the
+request cannot be serviced from cache, it is placed on the network queue. The first
+available network thread takes the request from the queue, performs the HTTP transaction,
+parses the response on the worker thread, writes the response to cache, and posts the parsed
+response back to the main thread for delivery.
+
+Note that expensive operations like blocking I/O and parsing/decoding are done on worker
+threads. You can add a request from any thread, but responses are always delivered on the
+main thread.
+
+This figure illustrates the life of a request:
+
+![Life of a request](./images/volley-request.png)
+
+## Cancel a request
+
+To cancel a request, call `cancel()` on your `Request` object. Once cancelled,
+Volley guarantees that your response handler will never be called. What this means in
+practice is that you can cancel all of your pending requests in your activity's
+[`onStop()`](https://developer.android.com/reference/android/app/Activity#onStop())
+method and you don't have to litter your response handlers with checks for `getActivity() == null`,
+whether `onSaveInstanceState()` has been called already, or other defensive
+boilerplate.
+
+To take advantage of this behavior, you would typically have to
+track all in-flight requests in order to be able to cancel them at the
+appropriate time. There is an easier way: you can associate a tag object with each
+request. You can then use this tag to provide a scope of requests to cancel. For
+example, you can tag all of your requests with the 
+[`Activity`](https://developer.android.com/reference/android/app/Activity)
+they are being made on behalf of, and call `requestQueue.cancelAll(this)` from
+[`onStop()`](https://developer.android.com/reference/android/app/Activity#onStop()).
+Similarly, you could tag all thumbnail image requests in a
+[`ViewPager`](https://developer.android.com/reference/androidx/viewpager/widget/ViewPager)
+tab with their respective tabs and cancel on swipe
+to make sure that the new tab isn't being held up by requests from another one.
+
+Here is an example that uses a string value for the tag:
+
+1. Define your tag and add it to your requests.
+   
+    *Kotlin*
+
+    ```kotlin
+    val TAG = "MyTag"
+    val stringRequest: StringRequest // Assume this exists.
+    val requestQueue: RequestQueue? // Assume this exists.
+    
+    // Set the tag on the request.
+    stringRequest.tag = TAG
+    
+    // Add the request to the RequestQueue.
+    requestQueue?.add(stringRequest)
+    ```
+
+    *Java*
+
+    ```java
+    public static final String TAG = "MyTag";
+    StringRequest stringRequest; // Assume this exists.
+    RequestQueue requestQueue;  // Assume this exists.
+    
+    // Set the tag on the request.
+    stringRequest.setTag(TAG);
+    
+    // Add the request to the RequestQueue.
+    requestQueue.add(stringRequest);
+    ```
+
+2. In your activity's [`onStop()`](https://developer.android.com/reference/android/app/Activity#onStop())
+   method, cancel all requests that have this tag.
+
+   *Kotlin*
+
+   ```kotlin
+   protected fun onStop() {
+       super.onStop()
+       requestQueue?.cancelAll(TAG)
+   }
+   ```
+
+   *Java*
+
+   ```java
+   @Override
+   protected void onStop() {
+       super.onStop();
+       if (requestQueue != null) {
+           requestQueue.cancelAll(TAG);
+       }
+   }
+   ```
+
+Take care when canceling requests. If you are depending on your response handler to
+advance a state or kick off another process, you need to account for this. Again, the
+response handler will not be called.
diff --git a/gradle.properties b/gradle.properties
index 5465fec..dbb7bf7 100644
--- a/gradle.properties
+++ b/gradle.properties
@@ -1,2 +1,2 @@
 android.enableJetifier=true
-android.useAndroidX=true
\ No newline at end of file
+android.useAndroidX=true
diff --git a/gradle/wrapper/gradle-wrapper.properties b/gradle/wrapper/gradle-wrapper.properties
index 104b82e..747bfa1 100644
--- a/gradle/wrapper/gradle-wrapper.properties
+++ b/gradle/wrapper/gradle-wrapper.properties
@@ -3,4 +3,4 @@ distributionBase=GRADLE_USER_HOME
 distributionPath=wrapper/dists
 zipStoreBase=GRADLE_USER_HOME
 zipStorePath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-4.10.2-all.zip
+distributionUrl=https\://services.gradle.org/distributions/gradle-7.5-all.zip
diff --git a/publish.gradle b/publish.gradle
index 429df4d..ec6fe8c 100644
--- a/publish.gradle
+++ b/publish.gradle
@@ -12,7 +12,7 @@ task javadoc(type: Javadoc) {
 
 afterEvaluate {
     javadoc.classpath += files(android.libraryVariants.collect { variant ->
-        variant.getJavaCompile().classpath.files
+        variant.getJavaCompileProvider().get().classpath.files
     })
 }
 
@@ -26,46 +26,53 @@ artifacts {
     archives sourcesJar
 }
 
-publishing {
-    publications {
-        library(MavenPublication) {
-            groupId 'com.android.volley'
-            version project.version
-            pom {
-                name = 'Volley'
-                url = 'https://github.com/google/volley'
-                packaging 'aar'
-                licenses {
-                    license {
-                      name = "The Apache License, Version 2.0"
-                      url = "http://www.apache.org/licenses/LICENSE-2.0.txt"
-                    }
-                }
-                scm {
-                    connection = 'scm:git:git://github.com/google/volley.git'
-                    developerConnection = 'scm:git:ssh://git@github.com/google/volley.git'
+afterEvaluate {
+    publishing {
+        publications {
+            release(MavenPublication) {
+                // Depend on the release AAR
+                from project.components.release
+
+                groupId 'com.android.volley'
+                artifactId project.artifactId
+                version project.version
+                pom {
+                    name = project.pomName
+                    description = project.pomDescription
                     url = 'https://github.com/google/volley'
-                }
-                developers {
-                    developer {
-                        name = 'The Volley Team'
-                        email = 'noreply+volley@google.com'
+                    packaging 'aar'
+                    licenses {
+                        license {
+                            name = "The Apache License, Version 2.0"
+                            url = "http://www.apache.org/licenses/LICENSE-2.0.txt"
+                        }
+                    }
+                    scm {
+                        connection = 'scm:git:git://github.com/google/volley.git'
+                        developerConnection = 'scm:git:ssh://git@github.com/google/volley.git'
+                        url = 'https://github.com/google/volley'
+                    }
+                    developers {
+                        developer {
+                            name = 'The Volley Team'
+                            email = 'noreply+volley@google.com'
+                        }
                     }
                 }
-            }
 
-            // Release AAR, Sources, and JavaDoc
-            artifact sourcesJar
-            artifact javadocJar
+                // Also include sources and JavaDoc
+                artifact sourcesJar
+                artifact javadocJar
+            }
         }
-    }
 
-    repositories {
-        maven {
-            url = "https://oss.sonatype.org/content/repositories/snapshots/"
-            credentials {
-                username = System.env.OSSRH_DEPLOY_USERNAME
-                password = System.env.OSSRH_DEPLOY_PASSWORD
+        repositories {
+            maven {
+                url = "https://oss.sonatype.org/content/repositories/snapshots/"
+                credentials {
+                    username = System.env.OSSRH_DEPLOY_USERNAME
+                    password = System.env.OSSRH_DEPLOY_PASSWORD
+                }
             }
         }
     }
```

