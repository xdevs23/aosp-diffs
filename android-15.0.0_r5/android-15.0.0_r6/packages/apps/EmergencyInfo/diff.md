```diff
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 5836d21..b1f0106 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -64,13 +64,13 @@
     <!-- no translation found for blood_type_content_description:9 (1362921785855892976) -->
     <string name="o_positive" msgid="5944181307873488422">"O positive"</string>
     <string name="o_negative" msgid="5261178297066132923">"O negative"</string>
-    <string name="a_positive" msgid="160635169929713435">"A positive"</string>
-    <string name="a_negative" msgid="6680390511183224469">"A negative"</string>
+    <string name="a_positive" msgid="160635169929713435">"A, positive"</string>
+    <string name="a_negative" msgid="6680390511183224469">"A, negative"</string>
     <string name="b_positive" msgid="8225619238000785345">"B positive"</string>
     <string name="b_negative" msgid="4110646487598488955">"B negative"</string>
-    <string name="ab_positive" msgid="1931300033534642005">"AB positive"</string>
-    <string name="ab_negative" msgid="2064555613093591729">"AB negative"</string>
-    <string name="h_h" msgid="2183333409760379720">"HH"</string>
+    <string name="ab_positive" msgid="1931300033534642005">"A B positive"</string>
+    <string name="ab_negative" msgid="2064555613093591729">"A B negative"</string>
+    <string name="h_h" msgid="2183333409760379720">"H H"</string>
     <string name="allergies" msgid="2789200777539258165">"Allergies"</string>
     <string name="unknown_allergies" msgid="4383115953418061237">"Unknown"</string>
     <string name="allergies_hint" msgid="5488918780522184147">"For example, peanuts"</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 0a3da35..4020a62 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -104,8 +104,8 @@
     <string name="clear" msgid="3648880442502887163">"తీసివేయండి"</string>
     <string name="clear_all_message" msgid="1548432000373861295">"మొత్తం సమాచారం మరియు కాంటాక్ట్‌లను తీసివేయాలా?"</string>
     <string name="emergency_info_footer" msgid="8751758742506410146">"వైద్య సమాచారం మరియు అత్యవసర కాంటాక్ట్‌లను జోడిస్తే, అత్యవసర పరిస్థితిలో ముందుగా ప్రతిస్పందించే వారికి సహాయకరంగా ఉంటాయి.\n\nఎవరైనా సరే, మీ ఫోన్‌ని అన్‌లాక్ చేయకుండానే మీ లాక్ స్క్రీన్ నుండి ఈ సమాచారాన్ని చదవగలరు మరియు మీ కాంటాక్ట్‌ల పేర్లు ట్యాప్ చేయడం ద్వారా వారికి కాల్ చేయగలరు."</string>
-    <string name="settings_suggestion_title" msgid="2503369576806243476">"అత్యవసర సమాచారాన్ని జోడించండి"</string>
-    <string name="settings_suggestion_body" msgid="5559349261345837716">"మీ సమాచారాన్ని మొదటగా ప్రతిస్పందించే వారిని చూడనివ్వండి"</string>
+    <string name="settings_suggestion_title" msgid="2503369576806243476">"ఎమర్జెన్సీ సమాచారాన్ని జోడించండి"</string>
+    <string name="settings_suggestion_body" msgid="5559349261345837716">"ఎమర్జెన్సీలో సాయం చేసే వారికి, మీ సమాచారం కనబడుతుంది"</string>
     <string name="user_image_take_photo" msgid="2779924488370750102">"ఫోటోను తీయి"</string>
     <string name="user_image_choose_photo" msgid="2442095378052415700">"చిత్రాన్ని ఎంచుకోండి"</string>
     <string name="user_image_photo_selector" msgid="8941966433899876760">"ఫోటోను ఎంచుకోండి"</string>
diff --git a/tests/unit/Android.bp b/tests/unit/Android.bp
index 326f262..1230cad 100644
--- a/tests/unit/Android.bp
+++ b/tests/unit/Android.bp
@@ -19,7 +19,7 @@ package {
 
 android_test {
     name: "EmergencyInfoUnitTests",
-    libs: ["android.test.runner"],
+    libs: ["android.test.runner.stubs.system"],
     static_libs: [
         "androidx.test.rules",
         "emergencyinfo-test-common",
```

