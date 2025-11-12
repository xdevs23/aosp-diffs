```diff
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index c55eebb..df9b5ca 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -18,7 +18,7 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="2227320688818248940">"MusicFX"</string>
     <string name="no_effects" msgid="9023408561505030260">"Effets indisponibles."</string>
-    <string name="eq_dialog_title" msgid="3237402214371962070">"Égalisateur"</string>
+    <string name="eq_dialog_title" msgid="3237402214371962070">"Égaliseur"</string>
     <string name="headset_plug" msgid="1774198554148807517">"Veuillez brancher un casque d\'écoute pour écouter ces effets."</string>
     <string name="bass_boost_strength" msgid="8643071340166812205">"Amplification des graves"</string>
     <string name="virtualizer_strength" msgid="2139410708760989842">"Son ambiophonique"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index e564ecd..3d555a5 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -19,7 +19,7 @@
     <string name="app_name" msgid="2227320688818248940">"MusicFX"</string>
     <string name="no_effects" msgid="9023408561505030260">"Effecten niet beschikbaar."</string>
     <string name="eq_dialog_title" msgid="3237402214371962070">"Equalizer"</string>
-    <string name="headset_plug" msgid="1774198554148807517">"Gebruik een hoofdtelefoon om deze effecten te beluisteren."</string>
+    <string name="headset_plug" msgid="1774198554148807517">"Gebruik een koptelefoon om deze effecten te beluisteren."</string>
     <string name="bass_boost_strength" msgid="8643071340166812205">"Basversterking"</string>
     <string name="virtualizer_strength" msgid="2139410708760989842">"Surround sound"</string>
     <string name="setup" msgid="4811197673396615722">"Instellen"</string>
diff --git a/src/com/android/musicfx/ActivityMusic.java b/src/com/android/musicfx/ActivityMusic.java
index 68b0001..5eedadf 100644
--- a/src/com/android/musicfx/ActivityMusic.java
+++ b/src/com/android/musicfx/ActivityMusic.java
@@ -527,9 +527,7 @@ public class ActivityMusic extends Activity implements OnSeekBarChangeListener {
             ((TextView) findViewById(R.id.noEffectsTextView)).setVisibility(View.VISIBLE);
         }
 
-        if (com.android.media.audio.Flags.musicFxEdgeToEdge()) {
-            setupEdgeToEdge();
-        }
+        setupEdgeToEdge();
     }
 
     /*
```

