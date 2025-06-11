```diff
diff --git a/OWNERS b/OWNERS
index 672c16d..df4273f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,4 @@
 # TLs
-igorr@google.com
 yiqunw@google.com
 arnaudberry@google.com
 
diff --git a/preinstalled-packages-com.android.car.dialer.xml b/preinstalled-packages-com.android.car.dialer.xml
index e2c7f70..06587bc 100644
--- a/preinstalled-packages-com.android.car.dialer.xml
+++ b/preinstalled-packages-com.android.car.dialer.xml
@@ -20,5 +20,6 @@
 <config>
     <install-in-user-type package="com.android.car.dialer">
         <install-in user-type="FULL" />
+        <do-not-install-in user-type="SYSTEM" />
     </install-in-user-type>
 </config>
```

