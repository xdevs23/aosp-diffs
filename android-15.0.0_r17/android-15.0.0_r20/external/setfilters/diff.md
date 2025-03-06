```diff
diff --git a/Android.bp b/Android.bp
index 503be33..5abb1cb 100644
--- a/Android.bp
+++ b/Android.bp
@@ -34,7 +34,6 @@ android_test {
         "cuckoofilter",
         "junit",
         "truth",
-        "truth-java8-extension",
     ],
     certificate: "platform",
 
diff --git a/javatests/com/google/setfilters/cuckoofilter/CuckooFilterTableTest.java b/javatests/com/google/setfilters/cuckoofilter/CuckooFilterTableTest.java
index 0e91adb..b5acf1a 100644
--- a/javatests/com/google/setfilters/cuckoofilter/CuckooFilterTableTest.java
+++ b/javatests/com/google/setfilters/cuckoofilter/CuckooFilterTableTest.java
@@ -15,7 +15,6 @@
 package com.google.setfilters.cuckoofilter;
 
 import static com.google.common.truth.Truth.assertThat;
-import static com.google.common.truth.Truth8.assertThat;
 import static org.junit.Assert.assertThrows;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.when;
```

