```diff
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index 3f65e35..bda7657 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -21,7 +21,7 @@
     <string name="eq_dialog_title" msgid="3237402214371962070">"Эквалайзер"</string>
     <string name="headset_plug" msgid="1774198554148807517">"Каб праслухаць гэтыя эфекты, падключыце навушнікі."</string>
     <string name="bass_boost_strength" msgid="8643071340166812205">"Узмацненне нізкіх частот"</string>
-    <string name="virtualizer_strength" msgid="2139410708760989842">"Аб\'ёмны гук"</string>
+    <string name="virtualizer_strength" msgid="2139410708760989842">"Аб’ёмны гук"</string>
     <string name="setup" msgid="4811197673396615722">"Наладзіць"</string>
     <string name="normal" msgid="757786146857325609">"Стандарт"</string>
     <string name="classical" msgid="1975693421508209132">"Класіка"</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 3e902b0..1e6a9cd 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -18,7 +18,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="2227320688818248940">"MusicFX"</string>
     <string name="no_effects" msgid="9023408561505030260">"Effects not available."</string>
-    <string name="eq_dialog_title" msgid="3237402214371962070">"Equaliser"</string>
+    <string name="eq_dialog_title" msgid="3237402214371962070">"Equalizer"</string>
     <string name="headset_plug" msgid="1774198554148807517">"Plug in headphones for these effects."</string>
     <string name="bass_boost_strength" msgid="8643071340166812205">"Bass boost"</string>
     <string name="virtualizer_strength" msgid="2139410708760989842">"Surround sound"</string>
@@ -28,8 +28,8 @@
     <string name="dance" msgid="212617702657103572">"Dance"</string>
     <string name="flat" msgid="2844441946717126606">"Flat"</string>
     <string name="folk" msgid="5648693824262941979">"Folk"</string>
-    <string name="heavy_metal" msgid="3885222304402494034">"Heavy metal"</string>
-    <string name="hip_hop" msgid="4147534012796302488">"Hip hop"</string>
+    <string name="heavy_metal" msgid="3885222304402494034">"Heavy Metal"</string>
+    <string name="hip_hop" msgid="4147534012796302488">"Hip Hop"</string>
     <string name="jazz" msgid="556328727821095055">"Jazz"</string>
     <string name="pop" msgid="8568493898002509539">"Pop"</string>
     <string name="rock" msgid="4226553710464965901">"Rock"</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 287bc1d..c55eebb 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -20,7 +20,7 @@
     <string name="no_effects" msgid="9023408561505030260">"Effets indisponibles."</string>
     <string name="eq_dialog_title" msgid="3237402214371962070">"Égalisateur"</string>
     <string name="headset_plug" msgid="1774198554148807517">"Veuillez brancher un casque d\'écoute pour écouter ces effets."</string>
-    <string name="bass_boost_strength" msgid="8643071340166812205">"Amplification des basses"</string>
+    <string name="bass_boost_strength" msgid="8643071340166812205">"Amplification des graves"</string>
     <string name="virtualizer_strength" msgid="2139410708760989842">"Son ambiophonique"</string>
     <string name="setup" msgid="4811197673396615722">"Configuration"</string>
     <string name="normal" msgid="757786146857325609">"Normal"</string>
diff --git a/src/com/android/musicfx/ActivityMusic.java b/src/com/android/musicfx/ActivityMusic.java
index d275a85..68b0001 100644
--- a/src/com/android/musicfx/ActivityMusic.java
+++ b/src/com/android/musicfx/ActivityMusic.java
@@ -251,7 +251,7 @@ public class ActivityMusic extends Activity implements OnSeekBarChangeListener {
             if (deviceInfo == null) {
                 continue;
             }
-            final int type = deviceInfo.getType();
+            final @AudioDeviceInfo.AudioDeviceType int type = deviceInfo.getType();
             if (HEADSET_DEVICE_TYPES.contains(type)) {
                 Log.v(TAG, " at least a HeadSet device type " + type + " connected");
                 return true;
```

