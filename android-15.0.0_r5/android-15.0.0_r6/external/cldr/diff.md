```diff
diff --git a/OWNERS b/OWNERS
index a5768343..9b6b2acb 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,9 +1,10 @@
-icu-team+reviews@google.com
-mscherer@google.com
-roubert@google.com
-
-android-libcore-team+review@google.com
+# Default reviewers
 vichang@google.com
-nfuller@google.com
-ngeoffray@google.com
 mingaleev@google.com
+
+# Bug component: 24949
+# libcore team is the larger team owning the library.
+include platform/libcore:/OWNERS
+
+# Email
+android-libcore-team+review@google.com
diff --git a/common/supplemental/supplementalData.xml b/common/supplemental/supplementalData.xml
index d425def4..c2abae5b 100644
--- a/common/supplemental/supplementalData.xml
+++ b/common/supplemental/supplementalData.xml
@@ -4804,7 +4804,7 @@ XXX Code for transations where no currency is involved
 		<!-- The first workday of the week (after the weekend) is distinct, and can be determined as the day after the weekendEnd day. -->
           <firstDay day="mon"  territories="
 			001
-			AD AI AL AM AN AR AT AU AX AZ
+			AD AE AI AL AM AN AR AT AU AX AZ
 			BA BE BG BM BN BY
 			CH CL CM CN CR CY CZ
 			DE DK
@@ -4826,7 +4826,7 @@ XXX Code for transations where no currency is involved
 			XK"
 		  />
 		<firstDay day="fri" territories="MV"/>
-		<firstDay day="sat" territories="AE AF BH DJ DZ EG IQ IR JO KW LY OM QA SD SY"/>
+		<firstDay day="sat" territories="AF BH DJ DZ EG IQ IR JO KW LY OM QA SD SY"/>
           <firstDay day="sun"  territories="
 			AG AS
 			BD BR BS BT BW BZ
diff --git a/common/supplemental/units.xml b/common/supplemental/units.xml
index 33d6d68d..b12fde6e 100644
--- a/common/supplemental/units.xml
+++ b/common/supplemental/units.xml
@@ -562,7 +562,7 @@ For terms of use, see http://www.unicode.org/copyright.html
         </unitPreferences>
         <unitPreferences category="speed" usage="wind">
             <unitPreference regions="001">kilometer-per-hour</unitPreference>
-            <unitPreference regions="FI KR NO PL RU SE">meter-per-second</unitPreference>
+            <unitPreference regions="CN DK FI JP KR NO PL RU SE">meter-per-second</unitPreference>
             <unitPreference regions="GB US">mile-per-hour</unitPreference>
         </unitPreferences>
         <unitPreferences category="temperature" usage="default">
```

