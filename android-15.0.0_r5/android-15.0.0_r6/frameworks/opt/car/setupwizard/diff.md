```diff
diff --git a/library/main/build.gradle b/library/main/build.gradle
index 8af3194..a8d16c0 100644
--- a/library/main/build.gradle
+++ b/library/main/build.gradle
@@ -75,7 +75,7 @@ dependencies {
     implementation 'androidx.recyclerview:recyclerview:1.2.0'
     implementation 'androidx.gridlayout:gridlayout:1.0.0'
     implementation 'androidx.preference:preference:1.1.1'
-    implementation 'androidx.constraintlayout:constraintlayout:2.0.4'
+    implementation libs.androidx.constraintlayout
     implementation 'androidx.core:core:1.3.2'
     implementation 'androidx.annotation:annotation:1.2.0'
     implementation 'androidx.test:core:1.4.0'
```

