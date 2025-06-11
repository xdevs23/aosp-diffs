```diff
diff --git a/FrameworkPackageStubs/res/values-af/strings.xml b/FrameworkPackageStubs/res/values-af/strings.xml
index 859ba75..99b0ea8 100644
--- a/FrameworkPackageStubs/res/values-af/strings.xml
+++ b/FrameworkPackageStubs/res/values-af/strings.xml
@@ -2,6 +2,6 @@
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="app_name" msgid="1051886861071228918">"Activity Stub"</string>
-    <string name="message_not_supported" msgid="5269947674108844893">"Jy het nie \'n program wat dit kan doen nie"</string>
+    <string name="message_not_supported" msgid="5269947674108844893">"Jy het nie ’n appwat dit kan doen nie"</string>
     <string name="stub_name" msgid="2907730040872891281">"Geen"</string>
 </resources>
diff --git a/MdnsOffloadManagerService/OWNERS b/MdnsOffloadManagerService/OWNERS
new file mode 100644
index 0000000..d97785d
--- /dev/null
+++ b/MdnsOffloadManagerService/OWNERS
@@ -0,0 +1,10 @@
+# Bug component: 1750103
+# Android > Android OS & Apps > TV > Connectivity > Networking
+
+agazal@google.com
+hisbilir@google.com
+arjundhaliwal@google.com
+gubailey@google.com
+maitrim@google.com
+
+include /OWNERS
\ No newline at end of file
diff --git a/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/InterfaceOffloadManager.java b/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/InterfaceOffloadManager.java
index 8759883..efe2112 100644
--- a/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/InterfaceOffloadManager.java
+++ b/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/InterfaceOffloadManager.java
@@ -81,6 +81,17 @@ public class InterfaceOffloadManager {
                 mOffloadIntentStore.getPassthroughIntentsForInterface(mNetworkInterface));
     }
 
+    void retrieveAndClearMetrics() {
+        if (!mIsNetworkAvailable) {
+            return;
+        }
+        if (!mOffloadWriter.isVendorServiceConnected()) {
+            Log.e(TAG, "Vendor service disconnected, cannot apply mDNS offload state");
+            return;
+        }
+        mOffloadWriter.retrieveAndClearMetrics(mCurrentOffloadKeys);
+    }
+
     private void clearProtocolResponses() {
         applyOffloadIntents(Collections.emptySet());
     }
diff --git a/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/MdnsOffloadManagerService.java b/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/MdnsOffloadManagerService.java
index 153e55b..1053427 100644
--- a/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/MdnsOffloadManagerService.java
+++ b/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/MdnsOffloadManagerService.java
@@ -483,7 +483,8 @@ public class MdnsOffloadManagerService extends Service {
                 if (Intent.ACTION_SCREEN_ON.equals(action)) {
                     Log.d(TAG, "SCREEN_ON");
                     mOffloadWriter.setOffloadState(false);
-                    mOffloadWriter.retrieveAndClearMetrics(mOffloadIntentStore.getRecordKeys());
+                    mInterfaceOffloadManagers.values().forEach(
+                            InterfaceOffloadManager::retrieveAndClearMetrics);
                 } else if (Intent.ACTION_SCREEN_OFF.equals(action)) {
                     Log.d(TAG, "SCREEN_OFF");
                     try {
diff --git a/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/NsdManagerWrapper.java b/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/NsdManagerWrapper.java
index 4e3d70f..66708af 100644
--- a/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/NsdManagerWrapper.java
+++ b/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/NsdManagerWrapper.java
@@ -41,6 +41,7 @@ public class NsdManagerWrapper {
             long offloadCapability,
             @NonNull Executor executor,
             @NonNull OffloadEngine engine) {
+        Log.d(TAG, "Register offload engine for iface {" + ifaceName + "}.") ;
         try {
             mManager.registerOffloadEngine(ifaceName, offloadType, offloadCapability, executor, engine);
         } catch (IllegalStateException e) {
@@ -50,6 +51,12 @@ public class NsdManagerWrapper {
     }
 
     public void unregisterOffloadEngine(@NonNull OffloadEngine engine) {
-        mManager.unregisterOffloadEngine(engine);
+        Log.d(TAG, "Unregister offload engine");
+        try {
+          mManager.unregisterOffloadEngine(engine);
+        } catch (IllegalStateException e) {
+            Log.e(TAG,"Error while unregistering offload engine.", e);
+        }
+
     }
 }
diff --git a/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/OffloadWriter.java b/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/OffloadWriter.java
index 84a6900..29b49a3 100644
--- a/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/OffloadWriter.java
+++ b/MdnsOffloadManagerService/src/com/android/tv/mdnsoffloadmanager/OffloadWriter.java
@@ -88,7 +88,7 @@ public class OffloadWriter {
             return;
         }
         try {
-            Log.e(TAG, "Setting offload state: %b".formatted(enabled));
+            Log.d(TAG, "Setting offload state: %b".formatted(enabled));
             mVendorService.setOffloadState(enabled);
         } catch (RemoteException | ServiceSpecificException e) {
             Log.e(TAG, "Failed to set offload state to {" + enabled + "}.", e);
diff --git a/OWNERS b/OWNERS
index fe296c4..25c6f1c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,6 +1,5 @@
 # Bug component: 760438
 
 hgchen@google.com
-qingxun@google.com
 quxiangfang@google.com
 wyau@google.com
diff --git a/emulator_x86/device.mk b/emulator_x86/device.mk
index 8a9d8da..0fe29f6 100644
--- a/emulator_x86/device.mk
+++ b/emulator_x86/device.mk
@@ -20,8 +20,3 @@ PRODUCT_SOONG_NAMESPACES += device/generic/goldfish-opengl # for goldfish deps.
 ifdef NET_ETH0_STARTONBOOT
   PRODUCT_VENDOR_PROPERTIES += net.eth0.startonboot=1
 endif
-
-# Ensure we package the BIOS files too.
-PRODUCT_HOST_PACKAGES += \
-	bios.bin \
-	vgabios-cirrus.bin \
diff --git a/libraries/BluetoothServices/OWNERS b/libraries/BluetoothServices/OWNERS
index 242a7f2..de36d35 100644
--- a/libraries/BluetoothServices/OWNERS
+++ b/libraries/BluetoothServices/OWNERS
@@ -2,7 +2,6 @@
 # Android > Android OS & Apps > TV > Connectivity > BT
 hisbilir@google.com
 arjundhaliwal@google.com
-xincheny@google.com
 agazal@google.com
 gubailey@google.com
 maitrim@google.com
diff --git a/libraries/BluetoothServices/res/values-af/arrays.xml b/libraries/BluetoothServices/res/values-af/arrays.xml
index f5eaa18..56ddd05 100644
--- a/libraries/BluetoothServices/res/values-af/arrays.xml
+++ b/libraries/BluetoothServices/res/values-af/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Geskeduleer"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Die agterlig sal nooit met elke klik verlig nie."</item>
-    <item msgid="2183471491302242879">"Die agterlig sal met elke klik verlig. Die verligting sal vir 5 sekondes duur elke keer wat dit geaktiveer word."</item>
-    <item msgid="4339318499911916123">"Die agterlig sal net in die nagtelike ure (18:00-06:00) met elke klik verlig. Die verligting sal vir 5 sekondes duur elke keer wat dit geaktiveer word."</item>
+    <item msgid="5834948533097349983">"Die agterlig sal nooit met elke druk verlig nie."</item>
+    <item msgid="2571249757867129366">"Die agterlig sal met elke druk verlig. Die verligting sal vir 5 sekondes duur elke keer wat dit geaktiveer word."</item>
+    <item msgid="6724077490859797929">"Die agterlig sal net in die nagtelike ure (18:00-06:00) met elke druk verlig. Die verligting sal vir 5 sekondes duur elke keer wat dit geaktiveer word."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-am/arrays.xml b/libraries/BluetoothServices/res/values-am/arrays.xml
index 5513278..6a65c65 100644
--- a/libraries/BluetoothServices/res/values-am/arrays.xml
+++ b/libraries/BluetoothServices/res/values-am/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"መርሃግብር ተይዞለታል"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"የኋላ ብርሃኑ በእያንዳንዱ ጠቅታ በጭራሽ አይበራም።"</item>
-    <item msgid="2183471491302242879">"የኋላ ብርሃኑ በእያንዳንዱ ጠቅታ ይበራል። ብርሃኑ በነቃ ቁጥር ለ5 ሰከንዶች ይቆያል።"</item>
-    <item msgid="4339318499911916123">"የኋላው ብርሃን በእያንዳንዱ ጠቅታ የሚያበራው በምሽት ሰዓታት (6ፒኤም~6ኤኤም) ላይ ብቻ ነው። ብርሃኑ በነቃ ቁጥር ለ5 ሰከንዶች ይቆያል።"</item>
+    <item msgid="5834948533097349983">"የኋላ ብርሃኑ በእያንዳንዱ ጫን ማለት በጭራሽ አይበራም።"</item>
+    <item msgid="2571249757867129366">"የኋላ ብርሃኑ በእያንዳንዱ ጫን ማለት ይበራል። ብርሃኑ በነቃ ቁጥር ለ5 ሰከንዶች ይቆያል።"</item>
+    <item msgid="6724077490859797929">"የኋላው ብርሃን በእያንዳንዱ ጫን ማለት የሚያበራው በምሽት ሰዓታት (6ማታ~6ጠዋት) ላይ ብቻ ነው። ብርሃኑ በነቃ ቁጥር ለ5 ሰከንዶች ይቆያል።"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ar/arrays.xml b/libraries/BluetoothServices/res/values-ar/arrays.xml
index fefc12d..99510e5 100644
--- a/libraries/BluetoothServices/res/values-ar/arrays.xml
+++ b/libraries/BluetoothServices/res/values-ar/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"مُجدوَل"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"لن تضيء الإضاءة الخلفية أبدًا مع كل نقرة."</item>
-    <item msgid="2183471491302242879">"ستضيء الإضاءة الخلفية مع كل نقرة. ستستمر الإضاءة لمدة 5 ثوانٍ في كل مرة يتم تنشيطها."</item>
-    <item msgid="4339318499911916123">"ستضيء الإضاءة الخلفية مع كل نقرة خلال وقت الليل فقط (من 6 مساءً حتى 6 صباحًا). ستستمر الإضاءة لمدة 5 ثوانٍ في كل مرة يتم تنشيطها."</item>
+    <item msgid="5834948533097349983">"لن يتم تشغيل الإضاءة الخلفية عند الضغط عليها."</item>
+    <item msgid="2571249757867129366">"سيتم تشغيل الإضاءة الخلفية عند الضغط عليها. ستستمرّ الإضاءة لمدة 5 ثوانٍ في كل مرة يتم تشغيلها."</item>
+    <item msgid="6724077490859797929">"سيتم تشغيل الإضاءة الخلفية عند الضغط عليها في الليل فقط (من الساعة 6 مساءً حتى 6 صباحًا). ستستمرّ الإضاءة لمدة 5 ثوانٍ في كل مرة يتم تشغيلها."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-as/arrays.xml b/libraries/BluetoothServices/res/values-as/arrays.xml
index 2a34cda..53f4fbc 100644
--- a/libraries/BluetoothServices/res/values-as/arrays.xml
+++ b/libraries/BluetoothServices/res/values-as/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"সময়সূচী নিৰ্ধাৰণ কৰা হৈছে"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"প্ৰতিবাৰ টিপোঁতে বেকলাইট নজ্বলে।"</item>
-    <item msgid="2183471491302242879">"প্ৰতিবাৰ টিপোঁতে বেকলাইট জ্বলিব। প্ৰতিবাৰ সক্ৰিয় কৰিলে পোহৰ ৫ ছেকেণ্ডলৈকে থাকিব।"</item>
-    <item msgid="4339318499911916123">"কেৱল নিশাৰ সময়ত (সন্ধ্যা ৬ টাৰ পৰা পুৱা ৬ টালৈকে) প্ৰতিবাৰ টিপোঁতে বেকলাইট জ্বলিব। প্ৰতিবাৰ সক্ৰিয় কৰিলে পোহৰ ৫ ছেকেণ্ডলৈকে থাকিব।"</item>
+    <item msgid="5834948533097349983">"প্ৰতিবাৰ টিপোঁতে বেকলাইট কেতিয়াও নজ্বলিব।"</item>
+    <item msgid="2571249757867129366">"প্ৰতিবাৰ টিপোঁতে বেকলাইট জ্বলিব। প্ৰতিবাৰ সক্ৰিয় কৰিলে পোহৰ ৫ ছেকেণ্ডলৈকে থাকিব।"</item>
+    <item msgid="6724077490859797929">"কেৱল নিশাৰ সময়ত (সন্ধ্যা ৬ টাৰ পৰা প্ৰায় পুৱা ৬ টালৈকে) প্ৰতিবাৰ টিপোঁতে বেকলাইট জ্বলিব। প্ৰতিবাৰ সক্ৰিয় কৰিলে পোহৰ ৫ ছেকেণ্ডলৈকে থাকিব।"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-az/arrays.xml b/libraries/BluetoothServices/res/values-az/arrays.xml
index 98395c1..4076baf 100644
--- a/libraries/BluetoothServices/res/values-az/arrays.xml
+++ b/libraries/BluetoothServices/res/values-az/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Planlaşdırılıb"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Hər klikdə arxa işıq yanmayacaq."</item>
-    <item msgid="2183471491302242879">"Hər klikdə arxa işıq yanacaq. İşıqlandırma hər dəfə aktivləşdirildikdə 5 saniyə davam edəcək."</item>
-    <item msgid="4339318499911916123">"Arxa işıq yalnız gecə saatlarında (18:00 ~ 06:00) hər klikdə yanacaq. İşıqlandırma hər dəfə aktivləşdirildikdə 5 saniyə davam edəcək."</item>
+    <item msgid="5834948533097349983">"Arxa işıq hər basma əməliyyatında yanmayacaq."</item>
+    <item msgid="2571249757867129366">"Arxa işıq hər basma əməliyyatında yanacaq. İşıqlandırma hər dəfə aktivləşdirildikdə 5 saniyə davam edəcək."</item>
+    <item msgid="6724077490859797929">"Arxa işıq yalnız gecə saatlarında (18:00~06:00) hər basma əməliyyatında yanacaq. İşıqlandırma hər dəfə aktivləşdirildikdə 5 saniyə davam edəcək."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-b+sr+Latn/arrays.xml b/libraries/BluetoothServices/res/values-b+sr+Latn/arrays.xml
index df31893..6ae1ced 100644
--- a/libraries/BluetoothServices/res/values-b+sr+Latn/arrays.xml
+++ b/libraries/BluetoothServices/res/values-b+sr+Latn/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Zakazano"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Pozadinsko osvetljenje se neće uključivati za svaki klik."</item>
-    <item msgid="2183471491302242879">"Pozadinsko osvetljenje će se uključivati za svaki klik. Osvetljenje će trajati 5 sekundi svaki put kada se aktivira."</item>
-    <item msgid="4339318499911916123">"Pozadinsko osvetljenje će se uključivati za svaki klik samo tokom noći (okvirno od 18:00 do 6:00). Osvetljenje će trajati 5 sekundi svaki put kada se aktivira."</item>
+    <item msgid="5834948533097349983">"Pozadinsko osvetljenje se neće uključivati za svaki pritisak."</item>
+    <item msgid="2571249757867129366">"Pozadinsko osvetljenje će se uključivati za svaki pritisak. Osvetljenje će trajati 5 sekundi svaki put kada se aktivira."</item>
+    <item msgid="6724077490859797929">"Pozadinsko osvetljenje će se uključivati za svaki pritisak samo tokom noći (okvirno od 18:00 do 6:00). Osvetljenje će trajati 5 sekundi svaki put kada se aktivira."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-be/arrays.xml b/libraries/BluetoothServices/res/values-be/arrays.xml
index 4fcc5aa..1c7388f 100644
--- a/libraries/BluetoothServices/res/values-be/arrays.xml
+++ b/libraries/BluetoothServices/res/values-be/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Запланаванае"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Падсветка не будзе з’яўляцца падчас кожнага націскання."</item>
-    <item msgid="2183471491302242879">"Падсветка будзе з’яўляцца падчас кожнага націскання. Падсветка будзе гарэць 5 секунд пасля кожнага ўключэння."</item>
-    <item msgid="4339318499911916123">"Падсветка будзе з’яўляцца падчас кожнага націскання толькі ноччу (прыблізна з 6 гадзін вечара да 6 гадзін раніцы). Падсветка будзе гарэць 5 секунд пасля кожнага ўключэння."</item>
+    <item msgid="5834948533097349983">"Падсветка не будзе ўключацца пры кожным націску."</item>
+    <item msgid="2571249757867129366">"Падсветка будзе ўключацца пры кожным націску. Падсветка будзе гарэць 5 секунд пасля кожнага ўключэння."</item>
+    <item msgid="6724077490859797929">"Падсветка будзе ўключацца пры кожным націску толькі ноччу (прыблізна з 6 гадзін вечара да 6 гадзін раніцы). Падсветка будзе гарэць 5 секунд пасля кожнага ўключэння."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-bg/arrays.xml b/libraries/BluetoothServices/res/values-bg/arrays.xml
index 2028869..44dd027 100644
--- a/libraries/BluetoothServices/res/values-bg/arrays.xml
+++ b/libraries/BluetoothServices/res/values-bg/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Насрочено"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Фоновото осветление никога няма да осветява при всяко кликване."</item>
-    <item msgid="2183471491302242879">"Фоновото осветление ще осветява при всяко кликване. Осветяването ще трае 5 секунди при всяко активиране."</item>
-    <item msgid="4339318499911916123">"Фоновото осветление ще осветява при всяко кликване само през нощта (18:00 – ~6:00 ч.). Осветяването ще трае 5 секунди при всяко активиране."</item>
+    <item msgid="5834948533097349983">"Фоновото осветление никога няма да осветява при всяко натискане."</item>
+    <item msgid="2571249757867129366">"Фоновото осветление ще осветява при всяко натискане. Осветяването ще трае 5 секунди при всяко активиране."</item>
+    <item msgid="6724077490859797929">"Фоновото осветление ще осветява при всяко натискане само през нощта (18:00 – ~6:00 ч.). Осветяването ще трае 5 секунди при всяко активиране."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-bn/arrays.xml b/libraries/BluetoothServices/res/values-bn/arrays.xml
index 0ce0396..ac153ee 100644
--- a/libraries/BluetoothServices/res/values-bn/arrays.xml
+++ b/libraries/BluetoothServices/res/values-bn/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"শিডিউল করা আছে"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"প্রত্যেকবার ক্লিক করার পরে কখনও ব্যাকলাইট জ্বলবে না।"</item>
-    <item msgid="2183471491302242879">"প্রত্যেকবার ক্লিক করার পরে ব্যাকলাইট জ্বলবে। প্রত্যেকবার এটি চালু হলে ৫ সেকেন্ড জ্বলে থাকবে।"</item>
-    <item msgid="4339318499911916123">"শুধুমাত্র রাতের বেলা(সন্ধে ৬টা~সকাল ৬টা) প্রত্যেকবার ক্লিক করার পরে ব্যাকলাইট জ্বলবে। প্রত্যেকবার এটি চালু হলে ৫ সেকেন্ড জ্বলে থাকবে।"</item>
+    <item msgid="5834948533097349983">"প্রত্যেকবার প্রেস করার পরে কখনও ব্যাকলাইট জ্বলবে না।"</item>
+    <item msgid="2571249757867129366">"প্রত্যেকবার প্রেস করার পরে ব্যাকলাইট জ্বলবে। প্রত্যেকবার এটি চালু করার পরে ৫ সেকেন্ড করে জ্বলবে।"</item>
+    <item msgid="6724077490859797929">"শুধু রাতের বেলাতেই (সন্ধ্যা ৬টা~সকাল ৬টা) প্রত্যেকবার প্রেস করার পরে ব্যাকলাইট জ্বলবে। প্রত্যেকবার এটি চালু করার পরে ৫ সেকেন্ড করে জ্বলবে।"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-bs/arrays.xml b/libraries/BluetoothServices/res/values-bs/arrays.xml
index 975cac8..1ef3d2c 100644
--- a/libraries/BluetoothServices/res/values-bs/arrays.xml
+++ b/libraries/BluetoothServices/res/values-bs/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Zakazano"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Pozadinsko osvjetljenje se neće uključivati prilikom svakog klika."</item>
-    <item msgid="2183471491302242879">"Pozadinsko osvjetljenje će se uključivati prilikom svakog klika. Osvjetljenje će trajati 5 sekundi svaki put kada se aktivira."</item>
-    <item msgid="4339318499911916123">"Pozadinsko osvjetljenje će se uključivati prilikom svakog klika samo tokom noći (18:00–6:00). Osvjetljenje će trajati 5 sekundi svaki put kada se aktivira."</item>
+    <item msgid="5834948533097349983">"Pozadinsko osvjetljenje se neće uključivati prilikom svakog pritiska."</item>
+    <item msgid="2571249757867129366">"Pozadinsko osvjetljenje će se uključivati prilikom svakog pritiska. Osvjetljenje će trajati 5 sekundi svaki put kada se aktivira."</item>
+    <item msgid="6724077490859797929">"Pozadinsko osvjetljenje će se uključivati prilikom svakog pritiska samo tokom noći (18:00–6:00). Osvjetljenje će trajati 5 sekundi svaki put kada se aktivira."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ca/arrays.xml b/libraries/BluetoothServices/res/values-ca/arrays.xml
index e0b800b..771e76d 100644
--- a/libraries/BluetoothServices/res/values-ca/arrays.xml
+++ b/libraries/BluetoothServices/res/values-ca/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Programat"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"La retroil·luminació mai no s\'il·luminarà amb cada clic."</item>
-    <item msgid="2183471491302242879">"La retroil·luminació s\'il·luminarà amb cada clic. La il·luminació durarà 5 segons cada vegada que s\'activi."</item>
-    <item msgid="4339318499911916123">"La retroil·luminació s\'il·luminarà amb cada clic només durant la nit (18:00-6:00). La il·luminació durarà 5 segons cada vegada que s\'activi."</item>
+    <item msgid="5834948533097349983">"La retroil·luminació mai no s\'il·luminarà amb cada pulsació."</item>
+    <item msgid="2571249757867129366">"La retroil·luminació s\'il·luminarà amb cada pulsació. La il·luminació durarà 5 segons cada vegada que s\'activi."</item>
+    <item msgid="6724077490859797929">"La retroil·luminació s\'il·luminarà amb cada pulsació només durant la nit (18:00-6:00). La il·luminació durarà 5 segons cada vegada que s\'activi."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-cs/arrays.xml b/libraries/BluetoothServices/res/values-cs/arrays.xml
index a41680c..a62d6c9 100644
--- a/libraries/BluetoothServices/res/values-cs/arrays.xml
+++ b/libraries/BluetoothServices/res/values-cs/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Plánované"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Podsvícení se při stisknutí neaktivuje."</item>
-    <item msgid="2183471491302242879">"Podsvícení se aktivuje při každém stisknutí. Po aktivaci bude trvat minimálně pět sekund."</item>
-    <item msgid="4339318499911916123">"Podsvícení se aktivuje při každém stisknutí jen během noci (18:00–6:00). Po aktivaci bude trvat minimálně pět sekund."</item>
+    <item msgid="5834948533097349983">"Podsvícení se nebude aktivovat při každém stisknutí."</item>
+    <item msgid="2571249757867129366">"Podsvícení se aktivuje při každém stisknutí. Po aktivaci bude trvat minimálně pět sekund."</item>
+    <item msgid="6724077490859797929">"Podsvícení se aktivuje při každém stisknutí jen během noci (18:00–6:00). Po aktivaci bude trvat minimálně pět sekund."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-da/arrays.xml b/libraries/BluetoothServices/res/values-da/arrays.xml
index 0a651cd..89fdf69 100644
--- a/libraries/BluetoothServices/res/values-da/arrays.xml
+++ b/libraries/BluetoothServices/res/values-da/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Planlagt"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Baggrundslyset aktiveres aldrig ved klik."</item>
-    <item msgid="2183471491302242879">"Baggrundslyset aktiveres ved hvert klik. Det lyser i 5 sekunder, hver gang det aktiveres."</item>
-    <item msgid="4339318499911916123">"Baggrundslyset aktiveres kun ved klik om natten (mellem kl 18 og 6) Det lyser i 5 sekunder, hver gang det aktiveres."</item>
+    <item msgid="5834948533097349983">"Baggrundslyset aktiveres aldrig ved hvert tryk."</item>
+    <item msgid="2571249757867129366">"Baggrundslyset aktiveres ved hvert tryk. Det lyser i 5 sekunder, hver gang det aktiveres."</item>
+    <item msgid="6724077490859797929">"Baggrundslyset aktiveres kun ved tryk om aftenen og natten (mellem kl. 18 og 6) Det lyser i 5 sekunder, hver gang det aktiveres."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-de/arrays.xml b/libraries/BluetoothServices/res/values-de/arrays.xml
index f732e27..931aa07 100644
--- a/libraries/BluetoothServices/res/values-de/arrays.xml
+++ b/libraries/BluetoothServices/res/values-de/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Geplant"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Die Hintergrundbeleuchtung leuchtet beim Klicken nicht auf."</item>
-    <item msgid="2183471491302242879">"Die Hintergrundbeleuchtung leuchtet bei jedem Klick auf. Die Beleuchtung hält jedes Mal 5 Sekunden lang an, wenn sie aktiviert wird."</item>
-    <item msgid="4339318499911916123">"Die Hintergrundbeleuchtung leuchtet nachts zwischen 18 und 6 Uhr bei jedem Klick auf. Die Beleuchtung hält jedes Mal 5 Sekunden lang an, wenn sie aktiviert wird."</item>
+    <item msgid="5834948533097349983">"Die Hintergrundbeleuchtung leuchtet beim Drücken nie auf."</item>
+    <item msgid="2571249757867129366">"Die Hintergrundbeleuchtung leuchtet beim Drücken auf. Sie hält jedes Mal 5 Sekunden lang an, wenn sie aktiviert wird."</item>
+    <item msgid="6724077490859797929">"Die Hintergrundbeleuchtung leuchtet nachts zwischen 18 und 6 Uhr beim Drücken auf. Sie hält jedes Mal 5 Sekunden lang an, wenn sie aktiviert wird."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-el/arrays.xml b/libraries/BluetoothServices/res/values-el/arrays.xml
index da38727..7e6f4ad 100644
--- a/libraries/BluetoothServices/res/values-el/arrays.xml
+++ b/libraries/BluetoothServices/res/values-el/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Προγραμματισμένος"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Ο οπίσθιος φωτισμός δεν θα ενεργοποιείται ποτέ με κάθε κλικ."</item>
-    <item msgid="2183471491302242879">"Ο οπίσθιος φωτισμός θα ενεργοποιείται με κάθε κλικ. Ο φωτισμός θα διαρκεί για 5 δευτερόλεπτα κάθε φορά που ενεργοποιείται."</item>
-    <item msgid="4339318499911916123">"Ο οπίσθιος φωτισμός θα ενεργοποιείται με κάθε κλικ μόνο κατά τις νυχτερινές ώρες (6μ.μ.~6π.μ.). Ο φωτισμός θα διαρκεί για 5 δευτερόλεπτα κάθε φορά που ενεργοποιείται."</item>
+    <item msgid="5834948533097349983">"Ο οπίσθιος φωτισμός δεν θα ενεργοποιείται με κάθε πάτημα."</item>
+    <item msgid="2571249757867129366">"Ο οπίσθιος φωτισμός θα ενεργοποιείται με κάθε πάτημα. Ο φωτισμός θα διαρκεί 5 δευτερόλεπτα κάθε φορά που ενεργοποιείται."</item>
+    <item msgid="6724077490859797929">"Ο οπίσθιος φωτισμός θα ενεργοποιείται με κάθε πάτημα μόνο κατά τις νυχτερινές ώρες (6 μ.μ.~6 π.μ.). Ο φωτισμός θα διαρκεί 5 δευτερόλεπτα κάθε φορά που ενεργοποιείται."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-en-rAU/arrays.xml b/libraries/BluetoothServices/res/values-en-rAU/arrays.xml
index 706d66f..4890508 100644
--- a/libraries/BluetoothServices/res/values-en-rAU/arrays.xml
+++ b/libraries/BluetoothServices/res/values-en-rAU/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Scheduled"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"The backlight will never illuminate with each press."</item>
-    <item msgid="2183471491302242879">"The backlight will illuminate with each press. The illumination will last for five seconds each time that it is activated."</item>
-    <item msgid="4339318499911916123">"The backlight will illuminate with each press only during nighttime hours (6.00 p.m.–6.00 a.m.). The illumination will last for five seconds each time that it is activated."</item>
+    <item msgid="5834948533097349983">"The backlight will never illuminate with each press."</item>
+    <item msgid="2571249757867129366">"The backlight will illuminate with each press. The illumination will last for five seconds each time that it is activated."</item>
+    <item msgid="6724077490859797929">"The backlight will illuminate with each press only during night-time hours (6.00 p.m. ~ 6.00 a.m.). The illumination will last for five seconds each time that it is activated."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-en-rCA/arrays.xml b/libraries/BluetoothServices/res/values-en-rCA/arrays.xml
index c09e3ce..d520ea0 100644
--- a/libraries/BluetoothServices/res/values-en-rCA/arrays.xml
+++ b/libraries/BluetoothServices/res/values-en-rCA/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Scheduled"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"The backlight will never illuminate with each click."</item>
-    <item msgid="2183471491302242879">"The backlight will illuminate with each click. The illumination will last for 5 seconds each time it is activated."</item>
-    <item msgid="4339318499911916123">"The backlight will illuminate with each click only during nighttime hours(6pm~6am). The illumination will last for 5 seconds each time it is activated."</item>
+    <item msgid="5834948533097349983">"The backlight will never illuminate with each press."</item>
+    <item msgid="2571249757867129366">"The backlight will illuminate with each press. The illumination will last for 5 seconds each time it is activated."</item>
+    <item msgid="6724077490859797929">"The backlight will illuminate with each press only during nighttime hours (6pm~6am). The illumination will last for 5 seconds each time it is activated."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-en-rGB/arrays.xml b/libraries/BluetoothServices/res/values-en-rGB/arrays.xml
index 706d66f..4890508 100644
--- a/libraries/BluetoothServices/res/values-en-rGB/arrays.xml
+++ b/libraries/BluetoothServices/res/values-en-rGB/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Scheduled"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"The backlight will never illuminate with each press."</item>
-    <item msgid="2183471491302242879">"The backlight will illuminate with each press. The illumination will last for five seconds each time that it is activated."</item>
-    <item msgid="4339318499911916123">"The backlight will illuminate with each press only during nighttime hours (6.00 p.m.–6.00 a.m.). The illumination will last for five seconds each time that it is activated."</item>
+    <item msgid="5834948533097349983">"The backlight will never illuminate with each press."</item>
+    <item msgid="2571249757867129366">"The backlight will illuminate with each press. The illumination will last for five seconds each time that it is activated."</item>
+    <item msgid="6724077490859797929">"The backlight will illuminate with each press only during night-time hours (6.00 p.m. ~ 6.00 a.m.). The illumination will last for five seconds each time that it is activated."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-en-rIN/arrays.xml b/libraries/BluetoothServices/res/values-en-rIN/arrays.xml
index 706d66f..4890508 100644
--- a/libraries/BluetoothServices/res/values-en-rIN/arrays.xml
+++ b/libraries/BluetoothServices/res/values-en-rIN/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Scheduled"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"The backlight will never illuminate with each press."</item>
-    <item msgid="2183471491302242879">"The backlight will illuminate with each press. The illumination will last for five seconds each time that it is activated."</item>
-    <item msgid="4339318499911916123">"The backlight will illuminate with each press only during nighttime hours (6.00 p.m.–6.00 a.m.). The illumination will last for five seconds each time that it is activated."</item>
+    <item msgid="5834948533097349983">"The backlight will never illuminate with each press."</item>
+    <item msgid="2571249757867129366">"The backlight will illuminate with each press. The illumination will last for five seconds each time that it is activated."</item>
+    <item msgid="6724077490859797929">"The backlight will illuminate with each press only during night-time hours (6.00 p.m. ~ 6.00 a.m.). The illumination will last for five seconds each time that it is activated."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-es-rUS/arrays.xml b/libraries/BluetoothServices/res/values-es-rUS/arrays.xml
index 734d679..0c75cfd 100644
--- a/libraries/BluetoothServices/res/values-es-rUS/arrays.xml
+++ b/libraries/BluetoothServices/res/values-es-rUS/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Programado"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"La retroiluminación no se encenderá cada vez que presiones el botón."</item>
-    <item msgid="2183471491302242879">"La retroiluminación se encenderá cada vez que presiones el botón. La luz se mantendrá encendida durante 5 segundos cada vez que se active."</item>
-    <item msgid="4339318499911916123">"La retroiluminación se encenderá cada vez que presiones el botón durante la noche (de 6 p.m. a 6 a.m.) La luz se mantendrá encendida durante 5 segundos cada vez que se active."</item>
+    <item msgid="5834948533097349983">"La retroiluminación no se encenderá cada vez que presiones un botón."</item>
+    <item msgid="2571249757867129366">"La retroiluminación se encenderá cada vez que presiones un botón. La luz se mantendrá encendida durante 5 segundos cada vez que se active."</item>
+    <item msgid="6724077490859797929">"La retroiluminación se encenderá cada vez que presiones un botón durante la noche (de 6 p.m. a 6 a.m.) La luz se mantendrá encendida durante 5 segundos cada vez que se active."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-es/arrays.xml b/libraries/BluetoothServices/res/values-es/arrays.xml
index e4716d2..3fd2b24 100644
--- a/libraries/BluetoothServices/res/values-es/arrays.xml
+++ b/libraries/BluetoothServices/res/values-es/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Programada"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"La retroiluminación no se iluminará con cada clic."</item>
-    <item msgid="2183471491302242879">"La retroiluminación se iluminará con cada clic. La iluminación durará 5 segundos cada vez que se active."</item>
-    <item msgid="4339318499911916123">"La retroiluminación se iluminará con cada clic solo durante la noche (18:00-6:00). La iluminación durará 5 segundos cada vez que se active."</item>
+    <item msgid="5834948533097349983">"La retroiluminación nunca se encenderá con cada pulsación."</item>
+    <item msgid="2571249757867129366">"La retroiluminación se encenderá con cada pulsación. La iluminación durará 5 segundos cada vez que se active."</item>
+    <item msgid="6724077490859797929">"La retroiluminación se encenderá con cada pulsación solo durante la noche (18:00-6:00). La iluminación durará 5 segundos cada vez que se active."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-et/arrays.xml b/libraries/BluetoothServices/res/values-et/arrays.xml
index 1fbe761..5d96642 100644
--- a/libraries/BluetoothServices/res/values-et/arrays.xml
+++ b/libraries/BluetoothServices/res/values-et/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Ajastatud"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Taustavalgustus ei sütti kunagi iga klikiga."</item>
-    <item msgid="2183471491302242879">"Taustavalgustus süttib iga klikiga. Valgustus on sees viis sekundit iga kord, kui see aktiveeritakse."</item>
-    <item msgid="4339318499911916123">"Taustavalgustus süttib iga klikiga ainult öisel ajal (umbes 18.00–6.00). Valgustus on sees viis sekundit iga kord, kui see aktiveeritakse."</item>
+    <item msgid="5834948533097349983">"Taustavalgustus ei sütti iga vajutusega."</item>
+    <item msgid="2571249757867129366">"Taustavalgustus süttib iga vajutusega. Valgustus süttib iga kord 5 sekundiks."</item>
+    <item msgid="6724077490859797929">"Taustavalgustus süttib iga vajutusega ainult öisel ajal (umbes 18.00–6.00). Valgustus süttib iga kord 5 sekundiks."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-et/strings.xml b/libraries/BluetoothServices/res/values-et/strings.xml
index 8ebe2c6..5eec53a 100644
--- a/libraries/BluetoothServices/res/values-et/strings.xml
+++ b/libraries/BluetoothServices/res/values-et/strings.xml
@@ -31,7 +31,7 @@
     <string name="settings_bt_update_not_necessary" msgid="6906777343269759565">"Kaugjuhtimispult on ajakohane"</string>
     <string name="settings_bt_update_failed" msgid="2593228509570726064">"Puldi värskendamine ebaõnnestus"</string>
     <string name="settings_bt_update_error" msgid="6267154862961568780">"Teie kaugjuhtimispuldi värskendamisel tekkis probleem. Proovige uuesti."</string>
-    <string name="settings_bt_update_please_wait" msgid="8029641271132945499">"Oodake"</string>
+    <string name="settings_bt_update_please_wait" msgid="8029641271132945499">"Palun oodake"</string>
     <string name="settings_bt_update_needs_repair" msgid="1310917691218455907">"Siduge oma kaugjuhtimispult uuesti"</string>
     <string name="settings_enabled" msgid="431464375814187683">"Lubatud"</string>
     <string name="settings_disabled" msgid="1459717258643130682">"Keelatud"</string>
diff --git a/libraries/BluetoothServices/res/values-eu/arrays.xml b/libraries/BluetoothServices/res/values-eu/arrays.xml
index c0c98d3..dec0490 100644
--- a/libraries/BluetoothServices/res/values-eu/arrays.xml
+++ b/libraries/BluetoothServices/res/values-eu/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Programatuta"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Hondoko argia ez da inoiz piztuko sakatzean."</item>
-    <item msgid="2183471491302242879">"Sakatzen duzun aldiro piztuko da hondoko argia. Argiztapenak 5 segundo iraungo ditu aktibatzen den bakoitzean."</item>
-    <item msgid="4339318499911916123">"Sakatzen duzun aldiro piztuko da hondoko argia, gaueko orduetan soilik (18:00-06:00). Argiztapenak 5 segundo iraungo ditu aktibatzen den bakoitzean."</item>
+    <item msgid="5834948533097349983">"Hondoko argia ez da inoiz piztuko sakatzean."</item>
+    <item msgid="2571249757867129366">"Sakatzen duzun aldiro piztuko da hondoko argia. Argiztapenak 5 segundo iraungo ditu aktibatzen den bakoitzean."</item>
+    <item msgid="6724077490859797929">"Sakatzen duzun aldiro piztuko da hondoko argia, gaueko orduetan soilik (18:00-06:00). Argiztapenak 5 segundo iraungo ditu aktibatzen den bakoitzean."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-fa/arrays.xml b/libraries/BluetoothServices/res/values-fa/arrays.xml
index f9bf143..a0901de 100644
--- a/libraries/BluetoothServices/res/values-fa/arrays.xml
+++ b/libraries/BluetoothServices/res/values-fa/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"زمان‌بندی‌شده"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"نور پس‌زمینه با هر کلیک هرگز روشن نمی‌شود."</item>
-    <item msgid="2183471491302242879">"نور پس‌زمینه با هر کلیک روشن می‌شود. این روشنایی پس‌از هربار فعال شدن، ۵ ثانیه طول می‌کشد."</item>
-    <item msgid="4339318499911916123">"نور پس‌زمینه با هر کلیک فقط درطول ساعات شب (۶ عصر تا ۶ صبح) روشن می‌شود. این روشنایی پس‌از هربار فعال شدن، ۵ ثانیه طول می‌کشد."</item>
+    <item msgid="5834948533097349983">"نور پس‌زمینه با فشردن روشن نمی‌شود."</item>
+    <item msgid="2571249757867129366">"نور پس‌زمینه با هر فشردن روشن می‌شود. این روشنایی پس‌از هربار فعال شدن، ۵ ثانیه طول می‌کشد."</item>
+    <item msgid="6724077490859797929">"نور پس‌زمینه با هر فشردن فقط درطول ساعات شب (۶ عصر تا ۶ صبح) روشن می‌شود. این روشنایی پس‌از هربار فعال شدن، ۵ ثانیه طول می‌کشد."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-fa/strings.xml b/libraries/BluetoothServices/res/values-fa/strings.xml
index 01064a6..941fb37 100644
--- a/libraries/BluetoothServices/res/values-fa/strings.xml
+++ b/libraries/BluetoothServices/res/values-fa/strings.xml
@@ -35,7 +35,7 @@
     <string name="settings_bt_update_needs_repair" msgid="1310917691218455907">"کنترل ازراه‌دور را دوباره مرتبط کنید"</string>
     <string name="settings_enabled" msgid="431464375814187683">"فعال"</string>
     <string name="settings_disabled" msgid="1459717258643130682">"غیرفعال"</string>
-    <string name="settings_remote_battery_level_label" msgid="3644348379742819020">"میزان شارژ باتری"</string>
+    <string name="settings_remote_battery_level_label" msgid="3644348379742819020">"سطح باتری"</string>
     <string name="settings_remote_battery_level_percentage_label" msgid="7301487906665476276">"%1$d%%"</string>
     <string name="settings_remote_firmware_label" msgid="2132403094910284670">"سفت‌افزار"</string>
     <string name="settings_remote_serial_number_label" msgid="7591347399882767241">"نشانی بلوتوث"</string>
@@ -72,7 +72,7 @@
     <string name="find_my_remote_slice_description" msgid="4802810369433859327">"دکمه پشت «جاری‌ساز Google TV» را فشار دهید تا صدایی به‌مدت ۳۰ ثانیه در کنترل از دور پخش شود. این ویژگی فقط در «کنترل از دور صوتی جاری‌ساز Google TV» کار می‌کند.\n\nبرای قطع کردن صدا، هر دکمه‌ای را روی کنترل از دور فشار دهید."</string>
     <string name="find_my_remote_integration_hint" msgid="7131212049012673631">"وقتی روشن باشد، بااستفاده از این دکمه در دستگاهتان می‌توانید صدایی پخش کنید و کنترل از دور را پیدا کنید. وقتی خاموش باشد، این دکمه کار نمی‌کند. همچنان می‌توانید با روش‌های دیگر از «پیدا کردن کنترل از راه دور» استفاده کنید."</string>
     <string name="find_my_remote_play_sound" msgid="1799877650759138251">"پخش صدا"</string>
-    <string name="settings_remote_battery_level" msgid="1817513765913707505">"میزان شارژ باتری: %1$s"</string>
+    <string name="settings_remote_battery_level" msgid="1817513765913707505">"سطح باتری: %1$s"</string>
     <string name="settings_known_devices_category" msgid="2307810690946536753">"لوازم جانبی"</string>
     <string name="settings_official_remote_category" msgid="1373956695709331265">"کنترل ازراه‌دور"</string>
     <string name="settings_devices_connected" msgid="3256213134907921013">"متصل"</string>
diff --git a/libraries/BluetoothServices/res/values-fi/arrays.xml b/libraries/BluetoothServices/res/values-fi/arrays.xml
index 5f4abab..4fe132c 100644
--- a/libraries/BluetoothServices/res/values-fi/arrays.xml
+++ b/libraries/BluetoothServices/res/values-fi/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Ajoitettu"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Taustavalo ei koskaan valaise joka klikkauksella."</item>
-    <item msgid="2183471491302242879">"Taustavalo valaisee joka klikkauksella. Valaisu kestää 5 sekunnin ajan aina, kun se aktivoituu."</item>
-    <item msgid="4339318499911916123">"Taustavalo valaisee joka klikkauksella ainoastaan yöaikaan (noin klo. 18–6). Valaisu kestää 5 sekunnin ajan aina, kun se aktivoituu."</item>
+    <item msgid="5834948533097349983">"Taustavalo ei koskaan valaise jokaisella painalluksella."</item>
+    <item msgid="2571249757867129366">"Taustavalo valaisee joka painalluksella. Valaisu kestää 5 sekunnin ajan aina, kun se aktivoituu."</item>
+    <item msgid="6724077490859797929">"Taustavalo valaisee joka painalluksella ainoastaan yöaikaan (noin klo. 18–6). Valaisu kestää 5 sekunnin ajan aina, kun se aktivoituu."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-fr-rCA/arrays.xml b/libraries/BluetoothServices/res/values-fr-rCA/arrays.xml
index bebc832..dc12d3d 100644
--- a/libraries/BluetoothServices/res/values-fr-rCA/arrays.xml
+++ b/libraries/BluetoothServices/res/values-fr-rCA/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Programmé"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Le rétroéclairage ne s\'activera pas avec tous les appuis."</item>
-    <item msgid="2183471491302242879">"Le rétroéclairage s\'activera avec chaque appui. La lumière restera allumée pendant cinq secondes après chaque appui."</item>
-    <item msgid="4339318499911916123">"Le rétroéclairage sera activé avec chaque appui pendant la nuit seulement (autour de 18 h à 6 h). La lumière restera allumée pendant cinq secondes après chaque appui."</item>
+    <item msgid="5834948533097349983">"Le rétroéclairage ne s\'activera pas avec chaque appui."</item>
+    <item msgid="2571249757867129366">"Le rétroéclairage s\'activera avec chaque appui. La lumière restera allumée pendant cinq secondes chaque fois qu\'elle est activée."</item>
+    <item msgid="6724077490859797929">"Le rétroéclairage sera activé avec chaque appui pendant la nuit seulement (autour de 18 h à 6 h). La lumière restera allumée pendant cinq secondes chaque fois qu\'elle est activée."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-fr/arrays.xml b/libraries/BluetoothServices/res/values-fr/arrays.xml
index ebe4486..115c10f 100644
--- a/libraries/BluetoothServices/res/values-fr/arrays.xml
+++ b/libraries/BluetoothServices/res/values-fr/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Planifié"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Le rétroéclairage ne s\'allumera pas à chaque clic."</item>
-    <item msgid="2183471491302242879">"Le rétroéclairage s\'allumera à chaque clic. Chaque activation durera 5 secondes."</item>
-    <item msgid="4339318499911916123">"Le rétroéclairage s\'allumera à chaque clic la nuit uniquement (de 18h à 6h). Chaque activation durera 5 secondes."</item>
+    <item msgid="5834948533097349983">"Le rétroéclairage ne s\'allumera jamais à chaque appui."</item>
+    <item msgid="2571249757867129366">"Le rétroéclairage s\'allumera à chaque appui. Chaque activation durera 5 secondes."</item>
+    <item msgid="6724077490859797929">"Le rétroéclairage s\'allumera à chaque appui la nuit uniquement (de 18h à 6h). Chaque activation durera 5 secondes."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-gl/arrays.xml b/libraries/BluetoothServices/res/values-gl/arrays.xml
index 52524c4..33a8278 100644
--- a/libraries/BluetoothServices/res/values-gl/arrays.xml
+++ b/libraries/BluetoothServices/res/values-gl/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Planificado"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"A retroiluminación non se activará con cada pulsación."</item>
-    <item msgid="2183471491302242879">"A retroiluminación activarase con cada pulsación. A iluminación durará 5 segundos cada vez que se active."</item>
-    <item msgid="4339318499911916123">"A retroiluminación activarase con cada pulsación só durante a noite (entre as 18:00 e as 6:00). A iluminación durará 5 segundos cada vez que se active."</item>
+    <item msgid="5834948533097349983">"A retroiluminación non se activará con cada pulsación."</item>
+    <item msgid="2571249757867129366">"A retroiluminación activarase con cada pulsación. A iluminación durará 5 segundos cada vez que se active."</item>
+    <item msgid="6724077490859797929">"A retroiluminación activarase con cada pulsación só durante a noite (entre as 18:00 e as 6:00). A iluminación durará 5 segundos cada vez que se active."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-gu/arrays.xml b/libraries/BluetoothServices/res/values-gu/arrays.xml
index 3e6307a..34bdead 100644
--- a/libraries/BluetoothServices/res/values-gu/arrays.xml
+++ b/libraries/BluetoothServices/res/values-gu/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"શેડ્યૂલ કરેલા"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"દરેક ક્લિક સાથે બૅકલાઇટ ક્યારેય પ્રકાશિત થશે નહીં."</item>
-    <item msgid="2183471491302242879">"દરેક ક્લિક સાથે બૅકલાઇટ પ્રકાશિત થશે. તે સક્રિય થવા પર દરેક વખતે 5 સેકન્ડ સુધી પ્રકાશિત રહેશે."</item>
-    <item msgid="4339318499911916123">"માત્ર રાતના કલાકો (સાંજના 6~સવારના 6) દરમિયાન દરેક ક્લિક સાથે બૅકલાઇટ પ્રકાશિત થશે. તે સક્રિય થવા પર દરેક વખતે 5 સેકન્ડ સુધી પ્રકાશિત રહેશે."</item>
+    <item msgid="5834948533097349983">"દબાવવાથી દરેક વખતે બૅકલાઇટ ક્યારેય પ્રકાશિત થશે નહીં."</item>
+    <item msgid="2571249757867129366">"દબાવવાથી દરેક વખતે બૅકલાઇટ પ્રકાશિત થશે. તે સક્રિય થવા પર દરેક વખતે 5 સેકન્ડ સુધી પ્રકાશિત રહેશે."</item>
+    <item msgid="6724077490859797929">"માત્ર રાતના કલાકો(સાંજના 6~સવારના 6) દરમિયાન, દબાવવાથી દરેક વખતે બૅકલાઇટ પ્રકાશિત થશે. તે સક્રિય થવા પર દરેક વખતે 5 સેકન્ડ સુધી પ્રકાશિત રહેશે."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-hi/arrays.xml b/libraries/BluetoothServices/res/values-hi/arrays.xml
index abc67c5..e25acc9 100644
--- a/libraries/BluetoothServices/res/values-hi/arrays.xml
+++ b/libraries/BluetoothServices/res/values-hi/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"शेड्यूल की गई"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"क्लिक करने पर कभी भी बैकलाइट नहीं जलेगी."</item>
-    <item msgid="2183471491302242879">"जब भी क्लिक किया जाएगा, बैकलाइट जलेगी. इसके चालू होने पर, हर बार पांच सेकंड तक बैकलाइट जली रहेगी."</item>
-    <item msgid="4339318499911916123">"शाम 6 बजे से सुबह 6 बजे के दौरान ही, जब भी क्लिक किया जाएगा, बैकलाइट जलेगी. इसके चालू होने पर, हर बार पांच सेकंड तक बैकलाइट जली रहेगी."</item>
+    <item msgid="5834948533097349983">"हर बार बटन दबाने पर बैकलाइट नहीं जलेगी."</item>
+    <item msgid="2571249757867129366">"हर बार बटन दबाने पर बैकलाइट जलेगी. इसके चालू होने पर, हर बार पांच सेकंड तक बैकलाइट जली रहेगी."</item>
+    <item msgid="6724077490859797929">"सिर्फ़ शाम 6 बजे से सुबह 6 बजे के दौरान, हर बार बटन दबाने पर बैकलाइट जलेगी. इसके चालू होने पर, हर बार पांच सेकंड तक बैकलाइट जली रहेगी."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-hr/arrays.xml b/libraries/BluetoothServices/res/values-hr/arrays.xml
index cd68a23..28bb504 100644
--- a/libraries/BluetoothServices/res/values-hr/arrays.xml
+++ b/libraries/BluetoothServices/res/values-hr/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Zakazano"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Pozadinsko svjetlo nikad neće zasvijetlliti na svaki pritisak gumba."</item>
-    <item msgid="2183471491302242879">"Pozadinsko će svjetlo zasvijetliti na svaki pritisak gumba. Osvjetljenje će trajati pet sekundi svaki put kada se aktivira."</item>
-    <item msgid="4339318499911916123">"Pozadinsko će svjetlo zasvijetliti na svaki pritisak gumba samo tijekom noćnih sati (otprilike od 18 do 6 sati). Osvjetljenje će trajati pet sekundi svaki put kada se aktivira."</item>
+    <item msgid="5834948533097349983">"Pozadinsko svjetlo nikad neće zasvijetliti na svaki pritisak gumba."</item>
+    <item msgid="2571249757867129366">"Pozadinsko svjetlo zasvijetlit će na svaki pritisak gumba. Osvjetljenje će trajati pet sekundi svaki put kada se aktivira."</item>
+    <item msgid="6724077490859797929">"Pozadinsko svjetlo zasvijetlit će na svaki pritisak gumba samo tijekom noćnih sati (približno u razdoblju između 18 i 6 sati). Osvjetljenje će trajati pet sekundi svaki put kada se aktivira."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-hu/arrays.xml b/libraries/BluetoothServices/res/values-hu/arrays.xml
index 0b9acb0..28116ad 100644
--- a/libraries/BluetoothServices/res/values-hu/arrays.xml
+++ b/libraries/BluetoothServices/res/values-hu/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Ütemezve"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"A háttérvilágítás nem fog bekapcsolni gombnyomáskor."</item>
-    <item msgid="2183471491302242879">"A háttérvilágítás minden gombnyomáskor bekapcsol. A világítás 5 másodpercig marad aktív minden aktiválás után."</item>
-    <item msgid="4339318499911916123">"A háttérvilágítás minden gombnyomáskor bekapcsol, de csak éjszaka (18:00–6:00). A világítás 5 másodpercig marad aktív minden aktiválás után."</item>
+    <item msgid="5834948533097349983">"A háttérvilágítás nem kapcsol be lenyomáskor."</item>
+    <item msgid="2571249757867129366">"A háttérvilágítás minden lenyomáskor bekapcsol. A világítás 5 másodpercig marad aktív minden aktiválás után."</item>
+    <item msgid="6724077490859797929">"A háttérvilágítás minden lenyomáskor bekapcsol, de csak 18:00 és 6:00 között. A világítás 5 másodpercig marad aktív minden aktiválás után."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-hy/arrays.xml b/libraries/BluetoothServices/res/values-hy/arrays.xml
index 2eb578a..07a7c7d 100644
--- a/libraries/BluetoothServices/res/values-hy/arrays.xml
+++ b/libraries/BluetoothServices/res/values-hy/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Պլանավորված"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Հետնալույսը երբեք չի վառվի յուրաքանչյուր սեղմումով։"</item>
-    <item msgid="2183471491302242879">"Հետնալույսը կվառվի յուրաքանչյուր սեղմումով։ Լույսը վառված կմնա 5 վայրկյան ամեն անգամ, երբ միանա։"</item>
-    <item msgid="4339318499911916123">"Հետնալույսը կվառվի յուրաքանչյուր սեղմումով՝ միայն գիշերային ժամերին (18:00-ից մինչև 06:00)։ Լույսը վառված կմնա 5 վայրկյան ամեն անգամ, երբ միանա։"</item>
+    <item msgid="5834948533097349983">"Հետնալույսը երբեք չի վառվի յուրաքանչյուր սեղմման ժամանակ։"</item>
+    <item msgid="2571249757867129366">"Հետնալույսը կվառվի յուրաքանչյուր սեղմման ժամանակ։ Լույսը վառված կմնա 5 վայրկյան ամեն անգամ, երբ միանա։"</item>
+    <item msgid="6724077490859797929">"Հետնալույսը կվառվի յուրաքանչյուր սեղմման ժամանակ միայն գիշերային ժամերին (18:00-ից մինչև 06:00)։ Լույսը վառված կմնա 5 վայրկյան ամեն անգամ, երբ միանա։"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-in/arrays.xml b/libraries/BluetoothServices/res/values-in/arrays.xml
index 6d45259..1bbde57 100644
--- a/libraries/BluetoothServices/res/values-in/arrays.xml
+++ b/libraries/BluetoothServices/res/values-in/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Terjadwal"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Lampu latar tidak akan menyala setiap kali mengklik."</item>
-    <item msgid="2183471491302242879">"Lampu latar akan menyala setiap kali mengklik. Cahaya akan bertahan selama 5 detik setiap kali diaktifkan."</item>
-    <item msgid="4339318499911916123">"Lampu latar tidak akan menyala setiap kali mengklik, hanya saat malam hari (18.00 - 06.00) Cahaya akan bertahan selama 5 detik setiap kali diaktifkan."</item>
+    <item msgid="5834948533097349983">"Lampu latar tidak akan pernah menyala setiap kali tombol ditekan."</item>
+    <item msgid="2571249757867129366">"Lampu latar akan menyala setiap kali tombol ditekan. Cahaya lampu latar akan bertahan selama 5 detik setiap kali diaktifkan."</item>
+    <item msgid="6724077490859797929">"Lampu latar akan menyala setiap kali tombol ditekan hanya saat malam hari (18.00–06.00). Cahaya lampu latar akan bertahan selama 5 detik setiap kali diaktifkan."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-is/arrays.xml b/libraries/BluetoothServices/res/values-is/arrays.xml
index 6e83f54..73c77db 100644
--- a/libraries/BluetoothServices/res/values-is/arrays.xml
+++ b/libraries/BluetoothServices/res/values-is/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Tímasett"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Aldrei mun kvikna á baklýsingu með hverjum smelli."</item>
-    <item msgid="2183471491302242879">"Kvikna mun á baklýsingu með hverjum smelli. Lýsingin mun vara í fimm sekúndur í hvert sinn sem kviknar á henni."</item>
-    <item msgid="4339318499911916123">"Aðeins mun kvikna á baklýsingu með hverjum smelli á kvöldin og nóttunni (18:00–06:00). Lýsingin mun vara í fimm sekúndur í hvert sinn sem kviknar á henni."</item>
+    <item msgid="5834948533097349983">"Baklýsing mun ekki kvikna í hvert skipti sem ýtt er."</item>
+    <item msgid="2571249757867129366">"Baklýsing mun kvikna í hvert skipti sem ýtt er. Lýsingin mun vara í fimm sekúndur í hvert sinn sem kviknar á henni."</item>
+    <item msgid="6724077490859797929">"Aðeins mun kvikna á baklýsingu í hvert sinn sem ýtt er á kvöldin og nóttunni (18:00–06:00). Lýsingin mun vara í fimm sekúndur í hvert sinn sem kviknar á henni."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-it/arrays.xml b/libraries/BluetoothServices/res/values-it/arrays.xml
index 0ddf921..3f3d958 100644
--- a/libraries/BluetoothServices/res/values-it/arrays.xml
+++ b/libraries/BluetoothServices/res/values-it/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Programmato"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"La retroilluminazione non si accende mai a ogni clic."</item>
-    <item msgid="2183471491302242879">"La retroilluminazione si accende a ogni clic. L\'illuminazione dura 5 secondi ogni volta che viene attivata."</item>
-    <item msgid="4339318499911916123">"La retroilluminazione si accende a ogni clic solo nelle ore notturne (18:00~06:00). L\'illuminazione dura 5 secondi ogni volta che viene attivata."</item>
+    <item msgid="5834948533097349983">"La retroilluminazione non si accende mai a ogni pressione."</item>
+    <item msgid="2571249757867129366">"La retroilluminazione si accende a ogni pressione. L\'illuminazione dura 5 secondi ogni volta che viene attivata."</item>
+    <item msgid="6724077490859797929">"La retroilluminazione si accende a ogni pressione solo nelle ore notturne (18:00~06:00). L\'illuminazione dura 5 secondi ogni volta che viene attivata."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-iw/arrays.xml b/libraries/BluetoothServices/res/values-iw/arrays.xml
index e96e7b7..2f5f02c 100644
--- a/libraries/BluetoothServices/res/values-iw/arrays.xml
+++ b/libraries/BluetoothServices/res/values-iw/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"מתוזמן"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"התאורה האחורית אף פעם לא תפעל בכל לחיצה."</item>
-    <item msgid="2183471491302242879">"התאורה האחורית תפעל בכל לחיצה. התאורה תימשך 5 שניות בכל פעם שהיא תופעל."</item>
-    <item msgid="4339318499911916123">"התאורה האחורית תפעל בכל לחיצה רק במשך שעות הלילה (מ-18:00 עד 6:00). התאורה תימשך 5 שניות בכל פעם שהיא תופעל."</item>
+    <item msgid="5834948533097349983">"התאורה האחורית אף פעם לא תפעל בכל לחיצה."</item>
+    <item msgid="2571249757867129366">"התאורה האחורית תפעל בכל לחיצה. התאורה תפעל למשך 5 שניות בכל פעם."</item>
+    <item msgid="6724077490859797929">"התאורה האחורית תפעל בכל לחיצה רק בשעות הלילה (מ-18:00 עד 6:00). התאורה תפעל למשך 5 שניות בכל פעם."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-iw/strings.xml b/libraries/BluetoothServices/res/values-iw/strings.xml
index 5fc898e..060d262 100644
--- a/libraries/BluetoothServices/res/values-iw/strings.xml
+++ b/libraries/BluetoothServices/res/values-iw/strings.xml
@@ -38,7 +38,7 @@
     <string name="settings_remote_battery_level_label" msgid="3644348379742819020">"רמת הטעינה של הסוללה"</string>
     <string name="settings_remote_battery_level_percentage_label" msgid="7301487906665476276">"‎%1$d%%‎"</string>
     <string name="settings_remote_firmware_label" msgid="2132403094910284670">"קושחה"</string>
-    <string name="settings_remote_serial_number_label" msgid="7591347399882767241">"כתובת Bluetooth"</string>
+    <string name="settings_remote_serial_number_label" msgid="7591347399882767241">"כתובת ה-Bluetooth"</string>
     <string name="settings_bt_battery_low" msgid="3547517382697124858">"עליך להחליף את הסוללה"</string>
     <string name="settings_bt_battery_low_warning" msgid="721091326401791089">"הסוללה חלשה"</string>
     <string name="connected_devices_pref_title" msgid="8985364841073196008">"מכשירים מחוברים"</string>
@@ -64,13 +64,13 @@
     <string name="settings_cec_explain" msgid="282126756909187653">"בעזרת HDMI-CEC אפשר לשלוט, וגם להפעיל ולכבות באופן אוטומטי, מכשירים אחרים שמופעלת בהם התכונה HDMI-CEC, באמצעות שלט רחוק אחד.\n\nהערה: יש לוודא שהתכונה HDMI-CEC מופעלת בטלוויזיה ובמכשירי HDMI אחרים. ל-HDMI-CEC יש שמות שונים אצל יצרנים שונים, לדוגמה:"</string>
     <string name="settings_cec_feature_names" msgid="3250254903330955270">"Samsung:‎ Anynet+\nLG:‎ SimpLink\nSony:‎ BRAVIA Sync\nPhilips:‎ EasyLink\nSharp:‎ Aquos Link"</string>
     <string name="settings_cec_go_to_sleep_on_active_source_lost_title" msgid="8678213062009082466">"כניסה למצב המתנה בזמן שינוי הקלט למקור אחר"</string>
-    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"כשמפעילים את ההגדרה הזו ומפעילים את HDMI-CEC בטלוויזיה, המכשיר הזה עובר למצב המתנה באופן אוטומטי זמן קצר אחרי שמעבירים את הקלט בטלוויזיה למקור אחר. האפשרות הזו עשויה לעזור להשהות תוכן ולהפחית את צריכת החשמל כשלא צופים בתוכן באופן פעיל."</string>
-    <string name="settings_axel" msgid="8253298947221430993">"הגדרת הלחצנים בשלט הרחוק"</string>
+    <string name="settings_cec_go_to_sleep_on_active_source_lost_description" msgid="3308324454326515797">"אם מפעילים את ההגדרה הזו ומפעילים את HDMI-CEC בטלוויזיה, אז זמן קצר אחרי שמעבירים את הקלט בטלוויזיה למקור אחר, המכשיר הזה יעבור אוטומטית למצב המתנה. האפשרות הזו עוזרת להשהות תוכן ולהפחית את צריכת החשמל כשלא צופים בטלוויזיה."</string>
+    <string name="settings_axel" msgid="8253298947221430993">"הגדרת הכפתורים בשלט הרחוק"</string>
     <string name="settings_axel_description" msgid="5432968671905160994">"שליטה בעוצמת הקול, בהפעלה, בקלט של טלוויזיות, ברסיברים ובמקרני קול"</string>
     <string name="settings_find_my_remote_title" msgid="618883575610472525">"איפה השלט שלי"</string>
     <string name="settings_find_my_remote_description" msgid="2434088262598422577">"ניתן להשמיע צליל כדי לאתר שלט רחוק של Google TV שאבד"</string>
-    <string name="find_my_remote_slice_description" msgid="4802810369433859327">"לוחצים על הלחצן בחלק האחורי של הסטרימר של Google TV כדי להשמיע צליל בשלט הרחוק למשך 30 שניות. הפעולה הזו עובדת רק בשליטה קולית מרחוק בסטרימר של Google TV.\n\nכדי להפסיק את הצליל, לוחצים על כל לחצן בשלט הרחוק."</string>
-    <string name="find_my_remote_integration_hint" msgid="7131212049012673631">"כשהאפשרות מופעלת, אפשר להשתמש בלחצן במכשיר כדי להשמיע צליל ולאתר את השלט הרחוק. כשהאפשרות מושבתת, הלחצן הזה לא יעבוד. עדיין תהיה לך אפשרות להשתמש בתכונה \'איפה השלט\' באמצעות שיטות אחרות."</string>
+    <string name="find_my_remote_slice_description" msgid="4802810369433859327">"לוחצים על הכפתור בחלק האחורי של הסטרימר של Google TV כדי להשמיע צליל בשלט הרחוק למשך 30 שניות. הפעולה הזו עובדת רק בשליטה קולית מרחוק בסטרימר של Google TV.\n\nכדי להפסיק את הצליל, לוחצים על כל כפתור בשלט הרחוק."</string>
+    <string name="find_my_remote_integration_hint" msgid="7131212049012673631">"כשהאפשרות מופעלת, אפשר להשתמש בכפתור במכשיר כדי להשמיע צליל ולאתר את השלט הרחוק. כשהאפשרות מושבתת, הכפתור הזה לא יעבוד. עדיין תהיה לך אפשרות להשתמש בתכונה \'איפה השלט\' באמצעות שיטות אחרות."</string>
     <string name="find_my_remote_play_sound" msgid="1799877650759138251">"השמעת צליל"</string>
     <string name="settings_remote_battery_level" msgid="1817513765913707505">"רמת הטעינה של הסוללה: %1$s"</string>
     <string name="settings_known_devices_category" msgid="2307810690946536753">"אביזרים"</string>
@@ -99,6 +99,6 @@
     <string name="settings_bt_pair_toast_connected" msgid="3073130641004809067">"%1$s מחובר"</string>
     <string name="settings_bt_pair_toast_disconnected" msgid="2046165143924352053">"%1$s מנותק"</string>
     <string name="settings_backlight_title" msgid="2013564937830315646">"מצב \'תאורה אחורית\'"</string>
-    <string name="settings_backlight_description" msgid="2672529254045062504">"תאורה של הלחצנים בשלט הרחוק בכל לחיצה."</string>
+    <string name="settings_backlight_description" msgid="2672529254045062504">"תאורה של הכפתורים בשלט הרחוק בכל לחיצה."</string>
     <string name="backlight_slice_description" msgid="2417058213200444743">"בשלטים רחוקים שנתמכים על ידי Google TV, לחיצה על השלט מפעילה את התאורה האחורית."</string>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ja/arrays.xml b/libraries/BluetoothServices/res/values-ja/arrays.xml
index f4736e3..9fc5faf 100644
--- a/libraries/BluetoothServices/res/values-ja/arrays.xml
+++ b/libraries/BluetoothServices/res/values-ja/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"スケジュール設定済み"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"押してもバックライトが点灯しなくなります。"</item>
-    <item msgid="2183471491302242879">"押すたびにバックライトが点灯します。一度点灯したバックライトは 5 秒後に消えます。"</item>
-    <item msgid="4339318499911916123">"夜間（午後 6 時～午前 6 時）は押すたびにバックライトが点灯します。一度点灯したバックライトは 5 秒後に消えます。"</item>
+    <item msgid="5834948533097349983">"押してもバックライトは点灯しません。"</item>
+    <item msgid="2571249757867129366">"押すたびにバックライトが点灯します。一度点灯したバックライトは 5 秒後に消えます。"</item>
+    <item msgid="6724077490859797929">"夜間（午後 6 時～午前 6 時）は押すたびにバックライトが点灯します。一度点灯したバックライトは 5 秒後に消えます。"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ka/arrays.xml b/libraries/BluetoothServices/res/values-ka/arrays.xml
index 63b693c..27b48d0 100644
--- a/libraries/BluetoothServices/res/values-ka/arrays.xml
+++ b/libraries/BluetoothServices/res/values-ka/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"დაგეგმილი"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"შენათება არასდროს გაანათებს ყოველ დაწკაპუნებაზე."</item>
-    <item msgid="2183471491302242879">"შენათება გაანათებს ყოველ დაწკაპუნებაზე. განათება გასტანს 5 წამს ყოველი გააქტიურებისას."</item>
-    <item msgid="4339318499911916123">"შენათება გაანათებს ყოველ დაწკაპუნებაზე მხოლოდ ღამის საათებში(18:00~06:00). განათება გასტანს 5 წამს ყოველი გააქტიურებისას."</item>
+    <item msgid="5834948533097349983">"შენათება არასდროს ჩაირთვება ყოველ დაჭერაზე."</item>
+    <item msgid="2571249757867129366">"შენათება ჩაირთვება ყოველ დაჭერაზე. ყოველი გააქტიურებისას განათება ხუთი წამის განმავლობაში გაგრძელდება."</item>
+    <item msgid="6724077490859797929">"შენათება ჩაირთვება ყოველ დაჭერაზე მხოლოდ ღამის საათებში (18:00-06:00). ყოველი გააქტიურებისას განათება ხუთი წამის განმავლობაში გაგრძელდება."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-kk/arrays.xml b/libraries/BluetoothServices/res/values-kk/arrays.xml
index a904000..77070c0 100644
--- a/libraries/BluetoothServices/res/values-kk/arrays.xml
+++ b/libraries/BluetoothServices/res/values-kk/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Жоспарланған"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Артқы жарық басқан сайын жанбайды."</item>
-    <item msgid="2183471491302242879">"Артқы жарық басқан сайын жанады. Жарықтандыру іске қосылған сайын 5 секундқа созылады."</item>
-    <item msgid="4339318499911916123">"Артқы жарық басқан сайын тек түнгі уақытта (18:00-ден 6:00-ге дейін) жанады. Жарықтандыру іске қосылған сайын 5 секундқа созылады."</item>
+    <item msgid="5834948533097349983">"Артқы жарық басқан сайын жанбайды."</item>
+    <item msgid="2571249757867129366">"Артқы жарық басқан сайын жанады. Жарықтандыру іске қосылған сайын 5 секундқа созылады."</item>
+    <item msgid="6724077490859797929">"Артқы жарық басқан сайын тек түнгі уақытта (18:00-ден 6:00-ге дейін) жанады. Жарықтандыру іске қосылған сайын 5 секундқа созылады."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-km/arrays.xml b/libraries/BluetoothServices/res/values-km/arrays.xml
index d41d71b..5d8c842 100644
--- a/libraries/BluetoothServices/res/values-km/arrays.xml
+++ b/libraries/BluetoothServices/res/values-km/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"បាន​កំណត់ពេល"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"ពន្លឺក្រោយនឹងមិនបង្ហាញនៅពេលចុចម្ដងៗទេ។"</item>
-    <item msgid="2183471491302242879">"ពន្លឺក្រោយនឹងបង្ហាញនៅពេលចុចម្ដងៗ។ ពន្លឺនឹងមានរយៈពេល 5 វិនាទី រាល់ពេលដែលវាត្រូវបានបើកដំណើរការ។"</item>
-    <item msgid="4339318499911916123">"ពន្លឺក្រោយនឹងបង្ហាញនៅពេលចុចម្ដងៗ ក្នុងអំឡុងម៉ោងពេលយប់ (6 ល្ងាច~6 ព្រឹក) តែប៉ុណ្ណោះ។ ពន្លឺនឹងមានរយៈពេល 5 វិនាទី រាល់ពេលដែលវាត្រូវបានបើកដំណើរការ។"</item>
+    <item msgid="5834948533097349983">"ពន្លឺក្រោយនឹងមិនបំភ្លឺនៅពេលចុចម្ដងៗទេ។"</item>
+    <item msgid="2571249757867129366">"ពន្លឺក្រោយនឹងបំភ្លឺនៅពេលចុចម្ដងៗ។ ការបំភ្លឺនឹងមានរយៈពេល 5 វិនាទី រាល់ពេលដែលវាត្រូវបានបើកដំណើរការ។"</item>
+    <item msgid="6724077490859797929">"ពន្លឺក្រោយនឹងបំភ្លឺនៅពេលចុចម្ដងៗ ក្នុងអំឡុងម៉ោងពេលយប់ (6 ល្ងាច~6 ព្រឹក) តែប៉ុណ្ណោះ។ ការបំភ្លឺនឹងមានរយៈពេល 5 វិនាទី រាល់ពេលដែលវាត្រូវបានបើកដំណើរការ។"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-kn/arrays.xml b/libraries/BluetoothServices/res/values-kn/arrays.xml
index a8280f2..d4087fa 100644
--- a/libraries/BluetoothServices/res/values-kn/arrays.xml
+++ b/libraries/BluetoothServices/res/values-kn/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"ನಿಗದಿತ"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"ಪ್ರತಿ ಕ್ಲಿಕ್‌ನೊಂದಿಗೆ ಬ್ಯಾಕ್‌ಲೈಟ್ ಎಂದಿಗೂ ಬೆಳಗುವುದಿಲ್ಲ."</item>
-    <item msgid="2183471491302242879">"ಪ್ರತಿ ಕ್ಲಿಕ್‌ನೊಂದಿಗೆ ಬ್ಯಾಕ್‌ಲೈಟ್ ಬೆಳಗುತ್ತದೆ. ಪ್ರತಿ ಬಾರಿ ಸಕ್ರಿಯಗೊಳಿಸಿದಾಗ ಇಲ್ಯುಮಿನೇಷನ್ 5 ಸೆಕೆಂಡುಗಳವರೆಗೆ ಇರುತ್ತದೆ."</item>
-    <item msgid="4339318499911916123">"ಬ್ಯಾಕ್‌ಲೈಟ್ ಪ್ರತಿ ಕ್ಲಿಕ್‌ನೊಂದಿಗೆ ರಾತ್ರಿಯ ಸಮಯದಲ್ಲಿ ಮಾತ್ರ ಬೆಳಗುತ್ತದೆ (6pm~6am). ಪ್ರತಿ ಬಾರಿ ಸಕ್ರಿಯಗೊಳಿಸಿದಾಗ ಇಲ್ಯುಮಿನೇಷನ್ 5 ಸೆಕೆಂಡುಗಳವರೆಗೆ ಇರುತ್ತದೆ."</item>
+    <item msgid="5834948533097349983">"ಪ್ರತಿ ಬಾರಿ ಒತ್ತಿದಾಗ ಬ್ಯಾಕ್‌ಲೈಟ್ ಎಂದಿಗೂ ಬೆಳಗುವುದಿಲ್ಲ."</item>
+    <item msgid="2571249757867129366">"ಪ್ರತಿ ಬಾರಿ ಒತ್ತಿದಾಗ ಬ್ಯಾಕ್‌ಲೈಟ್ ಬೆಳಗುತ್ತದೆ. ಪ್ರತಿ ಬಾರಿ ಸಕ್ರಿಯಗೊಳಿಸಿದಾಗ ಅದು 5 ಸೆಕೆಂಡುಗಳ ಕಾಲ ಬೆಳಗುತ್ತಿರುತ್ತದೆ."</item>
+    <item msgid="6724077490859797929">"ಪ್ರತಿ ಬಾರಿ ಒತ್ತಿದಾಗ ಬ್ಯಾಕ್‌ಲೈಟ್ ರಾತ್ರಿಯ ಸಮಯದಲ್ಲಿ ಮಾತ್ರ ಬೆಳಗುತ್ತದೆ (6pm~6am). ಪ್ರತಿ ಬಾರಿ ಸಕ್ರಿಯಗೊಳಿಸಿದಾಗ ಅದು 5 ಸೆಕೆಂಡುಗಳ ಕಾಲ ಬೆಳಗುತ್ತಿರುತ್ತದೆ."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ko/arrays.xml b/libraries/BluetoothServices/res/values-ko/arrays.xml
index eae2929..c8bf038 100644
--- a/libraries/BluetoothServices/res/values-ko/arrays.xml
+++ b/libraries/BluetoothServices/res/values-ko/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"예약됨"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"클릭할 때마다 백라이트가 켜지지 않습니다."</item>
-    <item msgid="2183471491302242879">"클릭할 때마다 백라이트가 켜지며, 조명이 활성화될 때마다 5초 동안 지속됩니다."</item>
-    <item msgid="4339318499911916123">"밤 동안(오후 6시~오전 6시)에만 클릭할 때마다 백라이트가 켜지며, 조명이 활성화될 때마다 5초 동안 지속됩니다."</item>
+    <item msgid="5834948533097349983">"누를 때마다 백라이트가 켜지지 않습니다."</item>
+    <item msgid="2571249757867129366">"누를 때마다 백라이트가 켜지며, 조명이 활성화될 때마다 5초 동안 지속됩니다."</item>
+    <item msgid="6724077490859797929">"밤 동안(오후 6시~오전 6시)에만 누를 때마다 백라이트가 켜지며, 조명이 활성화될 때마다 5초 동안 지속됩니다."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ky/arrays.xml b/libraries/BluetoothServices/res/values-ky/arrays.xml
index 7b67f9a..cf701f6 100644
--- a/libraries/BluetoothServices/res/values-ky/arrays.xml
+++ b/libraries/BluetoothServices/res/values-ky/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"График боюнча"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Арткы жарык баскычтарды басканыңызда жанбайт."</item>
-    <item msgid="2183471491302242879">"Арткы жарык баскычтарды басканыңызда 5 секундга жанат."</item>
-    <item msgid="4339318499911916123">"Арткы жарык баскычтарды түнкү убакытта (18:00~06:00) гана басканыңызда 5 секундга жанат."</item>
+    <item msgid="5834948533097349983">"Арткы жарык баскычтарды басканыңызда эч качан жанбайт."</item>
+    <item msgid="2571249757867129366">"Арткы жарык баскычтарды басканыңызда 5 секундга жанат."</item>
+    <item msgid="6724077490859797929">"Арткы жарык баскычтарды түнкү убакытта (18:00~06:00) гана басканыңызда 5 секундга жанат."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-lo/arrays.xml b/libraries/BluetoothServices/res/values-lo/arrays.xml
index 84fd3cf..4285e50 100644
--- a/libraries/BluetoothServices/res/values-lo/arrays.xml
+++ b/libraries/BluetoothServices/res/values-lo/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"ຕາມກຳນົດເວລາ"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"ແສງພື້ນຫຼັງຈະບໍ່ສ່ອງສະຫວ່າງທຸກເທື່ອທີ່ຄລິກ."</item>
-    <item msgid="2183471491302242879">"ແສງພື້ນຫຼັງຈະສະຫວ່າງຂຶ້ນທຸກເທື່ອທີ່ຄລິກ. ໂດຍຈະສະຫວ່າງຢູ່ເປັນເວລາ 5 ວິນາທີໃນແຕ່ລະເທື່ອທີ່ມີການເປີດການນຳໃຊ້."</item>
-    <item msgid="4339318499911916123">"ແສງພື້ນຫຼັງຈະສະຫວ່າງຂຶ້ນທຸກເທື່ອທີ່ຄລິກສະເພາະໃນຕອນກາງຄືນ (18:00 ~ 06:00 ໂມງ). ໂດຍຈະສະຫວ່າງຢູ່ເປັນເວລາ 5 ວິນາທີໃນແຕ່ລະເທື່ອທີ່ມີການເປີດການນຳໃຊ້."</item>
+    <item msgid="5834948533097349983">"ໄຟພື້ນຫຼັງຈະບໍ່ສະຫວ່າງຂຶ້ນແຕ່ລະເທື່ອທີ່ກົດປຸ່ມ."</item>
+    <item msgid="2571249757867129366">"ໄຟພື້ນຫຼັງຈະສະຫວ່າງຂຶ້ນແຕ່ລະເທື່ອທີ່ກົດປຸ່ມ. ໂດຍໄຟຈະສະຫວ່າງຢູ່ເປັນເວລາ 5 ວິນາທີໃນແຕ່ລະເທື່ອທີ່ມີການເປີດນຳໃຊ້."</item>
+    <item msgid="6724077490859797929">"ໄຟພື້ນຫຼັງຈະສະຫວ່າງຂຶ້ນແຕ່ລະເທື່ອທີ່ກົດປຸ່ມສະເພາະໃນຊ່ວງເວລາກາງຄືນ (ປະມານ 18:00-06:00 ໂມງ). ໂດຍໄຟຈະສະຫວ່າງຢູ່ເປັນເວລາ 5 ວິນາທີໃນແຕ່ລະເທື່ອທີ່ມີການເປີດນຳໃຊ້."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-lt/arrays.xml b/libraries/BluetoothServices/res/values-lt/arrays.xml
index 9a0bf92..8e7f272 100644
--- a/libraries/BluetoothServices/res/values-lt/arrays.xml
+++ b/libraries/BluetoothServices/res/values-lt/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Suplanuotas"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Kiekvieną kartą spustelėjus nebus suaktyvintas foninis apšvietimas."</item>
-    <item msgid="2183471491302242879">"Kiekvieną kartą spustelėjus bus suaktyvintas foninis apšvietimas. Kiekvieną kartą suaktyvinus apšvietimas bus įjungtas penkias sekundes."</item>
-    <item msgid="4339318499911916123">"Kiekvieną kartą spustelėjus foninis apšvietimas bus suaktyvintas tik nakties valandomis (18.00–6.00 val.). Kiekvieną kartą suaktyvinus apšvietimas bus įjungtas penkias sekundes."</item>
+    <item msgid="5834948533097349983">"Foninis apšvietimas niekada nebus suaktyvintas kiekvieną kartą paspaudžiant."</item>
+    <item msgid="2571249757867129366">"Kiekvieną kartą paspaudus bus suaktyvintas foninis apšvietimas. Kiekvieną kartą suaktyvinus apšvietimas bus įjungtas penkias sekundes."</item>
+    <item msgid="6724077490859797929">"Kiekvieną kartą paspaudus foninis apšvietimas bus suaktyvintas tik nakties valandomis (18.00–6.00 val.). Kiekvieną kartą suaktyvinus apšvietimas bus įjungtas penkias sekundes."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-lv/arrays.xml b/libraries/BluetoothServices/res/values-lv/arrays.xml
index 3318211..27a2d03 100644
--- a/libraries/BluetoothServices/res/values-lv/arrays.xml
+++ b/libraries/BluetoothServices/res/values-lv/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Ieplānots"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Fona apgaismojums nekad netiks aktivizēts katram klikšķim."</item>
-    <item msgid="2183471491302242879">"Fona apgaismojums tiks aktivizēts katram klikšķim. Katrā aktivizēšanas reizē izgaismojums ilgs 5 sekundes."</item>
-    <item msgid="4339318499911916123">"Fona apgaismojums tiks aktivizēts katram klikšķim tikai vakarā un naktī (~18:00–6:00). Katrā aktivizēšanas reizē izgaismojums ilgs 5 sekundes."</item>
+    <item msgid="5834948533097349983">"Fona apgaismojums nekad netiks aktivizēts katram nospiešanas gadījumam."</item>
+    <item msgid="2571249757867129366">"Fona apgaismojums tiks aktivizēts katram nospiešanas gadījumam. Katrā aktivizēšanas reizē izgaismojums ilgs 5 sekundes."</item>
+    <item msgid="6724077490859797929">"Fona apgaismojums tiks aktivizēts katram nospiešanas gadījumam tikai vakarā un naktī (~18:00–6:00). Katrā aktivizēšanas reizē izgaismojums ilgs 5 sekundes."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-mk/arrays.xml b/libraries/BluetoothServices/res/values-mk/arrays.xml
index c7c7cec..35da212 100644
--- a/libraries/BluetoothServices/res/values-mk/arrays.xml
+++ b/libraries/BluetoothServices/res/values-mk/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Закажано"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Заднинското осветлување нема да свети со секој клик."</item>
-    <item msgid="2183471491302242879">"Заднинското осветлување ќе свети со секој клик. Светењето ќе трае 5 секунди при секое активирање."</item>
-    <item msgid="4339318499911916123">"Заднинското осветлување ќе свети со секој клик само во текот на ноќните часови (18:00 – 6:00 часот). Светењето ќе трае 5 секунди при секое активирање."</item>
+    <item msgid="5834948533097349983">"Заднинското осветлување нема да свети при секое притискање."</item>
+    <item msgid="2571249757867129366">"Заднинското осветлување ќе свети при секое притискање. Светењето ќе трае 5 секунди при секое активирање."</item>
+    <item msgid="6724077490859797929">"Заднинското осветлување ќе свети при секое притискање само во текот на ноќните часови (18:00 – 6:00). Светењето ќе трае 5 секунди при секое активирање."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ml/arrays.xml b/libraries/BluetoothServices/res/values-ml/arrays.xml
index 18507e6..ed42fd0 100644
--- a/libraries/BluetoothServices/res/values-ml/arrays.xml
+++ b/libraries/BluetoothServices/res/values-ml/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"ഷെഡ്യൂൾ ചെയ്‌തത്"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"ഓരോ തവണ ക്ലിക്ക് ചെയ്യുമ്പോഴും ബാക്ക്‌ലൈറ്റ് തിളങ്ങുകയേ ഇല്ല."</item>
-    <item msgid="2183471491302242879">"ഓരോ തവണ ക്ലിക്ക് ചെയ്യുമ്പോഴും ബാക്ക്‌ലൈറ്റ് തിളങ്ങും. ഓരോ തവണ സജീവമാക്കപ്പെടുമ്പോഴും തിളക്കം 5 സെക്കന്റ് നീണ്ടുനിൽക്കും."</item>
-    <item msgid="4339318499911916123">"രാത്രിസമയത്ത് (6pm~6am) മാത്രം, ഓരോ തവണ ക്ലിക്ക് ചെയ്യുമ്പോഴും ബാക്ക്‌ലൈറ്റ് തിളങ്ങും. ഓരോ തവണ സജീവമാക്കപ്പെടുമ്പോഴും തിളക്കം 5 സെക്കന്റ് നീണ്ടുനിൽക്കും."</item>
+    <item msgid="5834948533097349983">"ഓരോ തവണ അമർത്തുമ്പോഴും എല്ലായ്‌പ്പോഴും ബാക്ക്‌ലൈറ്റ് പ്രകാശിക്കില്ല."</item>
+    <item msgid="2571249757867129366">"ഓരോ തവണ അമർത്തുമ്പോഴും ബാക്ക്‌ലൈറ്റ് പ്രകാശിക്കും. ഓരോ തവണ സജീവമാക്കുമ്പോഴും പ്രകാശം 5 സെക്കന്റ് നീണ്ടുനിൽക്കും."</item>
+    <item msgid="6724077490859797929">"രാത്രിയിൽ (6PM~6AM) മാത്രമേ, ഓരോ തവണ അമർത്തുമ്പോഴും ബാക്ക്‌ലൈറ്റ് പ്രകാശിക്കൂ. ഓരോ തവണ സജീവമാക്കുമ്പോഴും പ്രകാശം 5 സെക്കന്റ് നീണ്ടുനിൽക്കും."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-mn/arrays.xml b/libraries/BluetoothServices/res/values-mn/arrays.xml
index 13c1d68..67fcc28 100644
--- a/libraries/BluetoothServices/res/values-mn/arrays.xml
+++ b/libraries/BluetoothServices/res/values-mn/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Хуваарьт"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Товших бүрд арын гэрэлтүүлэг хэзээ ч асахгүй."</item>
-    <item msgid="2183471491302242879">"Товших бүрд арын гэрэлтүүлэг асна. Идэвхжүүлэх бүрд гэрэлтүүлэг 5 секундийн турш асна."</item>
-    <item msgid="4339318499911916123">"Зөвхөн шөнийн цагаар (18:00~06:00) товших бүрд арын гэрэл асна. Идэвхжүүлэх бүрд гэрэлтүүлэг 5 секундийн турш асна."</item>
+    <item msgid="5834948533097349983">"Дарах бүрд арын гэрэлтүүлэг хэзээ ч асахгүй."</item>
+    <item msgid="2571249757867129366">"Дарах бүрд арын гэрэлтүүлэг асна. Гэрэлтүүлэг идэвхжих бүрдээ 5 секундийн турш асна."</item>
+    <item msgid="6724077490859797929">"Зөвхөн шөнийн цагаар (18:00~06:00) дарах бүрд арын гэрэлтүүлэг асна. Гэрэлтүүлэг идэвхжих бүрдээ 5 секундийн турш асна."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-mr/arrays.xml b/libraries/BluetoothServices/res/values-mr/arrays.xml
index 2d65b20..b5d2db0 100644
--- a/libraries/BluetoothServices/res/values-mr/arrays.xml
+++ b/libraries/BluetoothServices/res/values-mr/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"शेड्यूल केलेले"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"प्रत्येक क्लिकवर बॅकलाइट कधीही प्रकाशित होणार नाही."</item>
-    <item msgid="2183471491302242879">"प्रत्येक क्लिकवर बॅकलाइट प्रकाशित होईल. इल्यूमिनेशन अ‍ॅक्टिव्हेट झाल्यानंतर, प्रत्येक वेळी ५ सेकंदांसाठी दिसेल."</item>
-    <item msgid="4339318499911916123">"फक्त रात्रीच्यावेळी (संध्याकाळी६~ सकाळी६) या तासांदरम्यान प्रत्येक क्लिकवर बॅकलाइट प्रकाशित होईल. इल्यूमिनेशन अ‍ॅक्टिव्हेट झाल्यानंतर, प्रत्येक वेळी ५ सेकंदांसाठी दिसेल."</item>
+    <item msgid="5834948533097349983">"प्रत्येक वेळी प्रेस केल्यावर बॅकलाइट कधीही प्रकाशित होणार नाही."</item>
+    <item msgid="2571249757867129366">"प्रत्येक वेळी प्रेस केल्यावर बॅकलाइट प्रकाशित होईल. इल्यूमिनेशन अ‍ॅक्टिव्हेट झाल्यानंतर, प्रत्येक वेळी ५ सेकंदांसाठी दिसेल."</item>
+    <item msgid="6724077490859797929">"फक्त रात्रीच्यावेळी (संध्याकाळी६~ सकाळी६) या तासांदरम्यान प्रत्येक वेळी प्रेस केल्यावर बॅकलाइट प्रकाशित होईल. इल्यूमिनेशन अ‍ॅक्टिव्हेट झाल्यानंतर, प्रत्येक वेळी ५ सेकंदांसाठी दिसेल."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ms/arrays.xml b/libraries/BluetoothServices/res/values-ms/arrays.xml
index 40b871d..cd102ec 100644
--- a/libraries/BluetoothServices/res/values-ms/arrays.xml
+++ b/libraries/BluetoothServices/res/values-ms/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Dijadualkan"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Lampu latar tidak akan sekali-kali memancarkan cahaya dengan setiap klik."</item>
-    <item msgid="2183471491302242879">"Lampu latar akan memancarkan cahaya dengan setiap klik. Cahaya akan dipancarkan selama 5 saat setiap kali lampu latar diaktifkan."</item>
-    <item msgid="4339318499911916123">"Lampu latar akan memancarkan cahaya dengan setiap klik hanya pada waktu malam (6ptg~6pg). Cahaya akan dipancarkan selama 5 saat setiap kali lampu latar diaktifkan."</item>
+    <item msgid="5834948533097349983">"Lampu latar tidak akan memancarkan cahaya setiap kali butang ditekan."</item>
+    <item msgid="2571249757867129366">"Lampu latar akan memancarkan cahaya setiap kali butang ditekan. Cahaya akan dipancarkan selama 5 saat setiap kali lampu latar diaktifkan."</item>
+    <item msgid="6724077490859797929">"Lampu latar akan memancarkan cahaya setiap kali butang ditekan hanya pada waktu malam (6ptg~6pg). Cahaya akan dipancarkan selama 5 saat setiap kali lampu latar diaktifkan."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-my/arrays.xml b/libraries/BluetoothServices/res/values-my/arrays.xml
index df19c4c..2ce8bb0 100644
--- a/libraries/BluetoothServices/res/values-my/arrays.xml
+++ b/libraries/BluetoothServices/res/values-my/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"စီစဉ်ထားသည်"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"နှိပ်လိုက်တိုင်း နောက်ခံမီး ဘယ်တော့မှမလင်းပါ။"</item>
-    <item msgid="2183471491302242879">"နှိပ်လိုက်တိုင်း နောက်ခံမီး လင်းပါမည်။ စဖွင့်ချိန်တိုင်း ၅ စက္ကန့်ကြာ မီးလင်းပါမည်။"</item>
-    <item msgid="4339318499911916123">"ညအချိန် (ည ၆ ~ မနက် ၆) အတွင်းသာ နှိပ်လိုက်တိုင်း နောက်ခံမီး လင်းပါမည်။ စဖွင့်ချိန်တိုင်း ၅ စက္ကန့်ကြာ မီးလင်းပါမည်။"</item>
+    <item msgid="5834948533097349983">"နှိပ်လိုက်တိုင်း နောက်ခံမီး ဘယ်တော့မှမလင်းပါ။"</item>
+    <item msgid="2571249757867129366">"နှိပ်လိုက်တိုင်း နောက်ခံမီး လင်းပါမည်။ စဖွင့်ချိန်တိုင်း ၅ စက္ကန့်ကြာ မီးလင်းပါမည်။"</item>
+    <item msgid="6724077490859797929">"ညအချိန် (ည ၆ ~ မနက် ၆) အတွင်းသာ နှိပ်လိုက်တိုင်း နောက်ခံမီး လင်းပါမည်။ စဖွင့်ချိန်တိုင်း ၅ စက္ကန့်ကြာ မီးလင်းပါမည်။"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-nb/arrays.xml b/libraries/BluetoothServices/res/values-nb/arrays.xml
index 99c1ddf..b37b007 100644
--- a/libraries/BluetoothServices/res/values-nb/arrays.xml
+++ b/libraries/BluetoothServices/res/values-nb/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Planlagt"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Bakgrunnsbelysningen lyser aldri med hvert klikk."</item>
-    <item msgid="2183471491302242879">"Bakgrunnsbelysningen lyser med hvert klikk. Lyset varer 5 sekunder hver gang det aktiveres."</item>
-    <item msgid="4339318499911916123">"Bakgrunnsbelysningen lyser bare med hvert klikk når det er kveld/natt (18:00~06:00). Lyset varer 5 sekunder hver gang det aktiveres."</item>
+    <item msgid="5834948533097349983">"Bakgrunnsbelysningen lyser aldri med hvert trykk."</item>
+    <item msgid="2571249757867129366">"Bakgrunnsbelysningen lyser med hvert trykk. Lyset varer 5 sekunder hver gang det aktiveres."</item>
+    <item msgid="6724077490859797929">"Bakgrunnsbelysningen lyser bare med hvert trykk når det er kveld/natt (18:00~06:00). Lyset varer 5 sekunder hver gang det aktiveres."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ne/arrays.xml b/libraries/BluetoothServices/res/values-ne/arrays.xml
index 76e2428..e576da3 100644
--- a/libraries/BluetoothServices/res/values-ne/arrays.xml
+++ b/libraries/BluetoothServices/res/values-ne/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"मिति तय गरिएको"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"अबदेखि हरेक पटक क्लिक गर्दा कहिल्यै पनि ब्याकलाइट बल्ने छैन।"</item>
-    <item msgid="2183471491302242879">"हरेक पटक क्लिक गर्दा ब्याकलाइट बल्ने छ। हरेक पटक डिभाइस एक्टिभेट गर्दा ब्याकलाइट ५ सेकेन्डसम्म बल्ने छ।"</item>
-    <item msgid="4339318499911916123">"हरेक पटक रातको समयमा (बेलुका ६ बजेदेखि बिहान ६ बजेसम्म) मात्र क्लिक गर्दा ब्याकलाइट बल्ने छ। हरेक पटक डिभाइस एक्टिभेट गर्दा ब्याकलाइट ५ सेकेन्डसम्म बल्ने छ।"</item>
+    <item msgid="5834948533097349983">"हरेक पटक बटन थिच्दा ब्याकलाइट बल्ने छैन।"</item>
+    <item msgid="2571249757867129366">"हरेक पटक बटन थिच्दा ब्याकलाइट बल्ने छ। हरेक पटक ब्याकलाइट एक्टिभेट गर्दा यो ५ सेकेन्डसम्म बल्ने छ।"</item>
+    <item msgid="6724077490859797929">"रातको समयमा (बेलुका ६ बजेदेखि बिहान ६ बजेसम्म) मात्र हरेक पटक बटन थिच्दा ब्याकलाइट बल्ने छ। हरेक पटक ब्याकलाइट एक्टिभेट गर्दा यो ५ सेकेन्डसम्म बल्ने छ।"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ne/strings.xml b/libraries/BluetoothServices/res/values-ne/strings.xml
index 0d25d31..2b58966 100644
--- a/libraries/BluetoothServices/res/values-ne/strings.xml
+++ b/libraries/BluetoothServices/res/values-ne/strings.xml
@@ -81,7 +81,7 @@
     <string name="bluetooth_disconnect" msgid="1385608885917484057">"विच्छेद गर्नुहोस्"</string>
     <string name="bluetooth_connect" msgid="6283971929092004620">"कनेक्ट गर्नुहोस्"</string>
     <string name="bluetooth_rename" msgid="4433577238394058486">"नाम बदल्नुहोस्"</string>
-    <string name="bluetooth_forget" msgid="4933552074497360964">"बिर्सनुहोस्"</string>
+    <string name="bluetooth_forget" msgid="4933552074497360964">"हटाउनुहोस्"</string>
     <string name="bluetooth_toggle_active_audio_output" msgid="494557568422711885">"टिभीको अडियोका लागि प्रयोग गर्नुहोस्"</string>
     <string name="bluetooth_connected_status" msgid="8391804274846835227">"कनेक्ट गरिएको छ"</string>
     <string name="bluetooth_disconnected_status" msgid="972515438988962457">"डिस्कनेक्ट भयो"</string>
diff --git a/libraries/BluetoothServices/res/values-nl/arrays.xml b/libraries/BluetoothServices/res/values-nl/arrays.xml
index 75234ae..4574514 100644
--- a/libraries/BluetoothServices/res/values-nl/arrays.xml
+++ b/libraries/BluetoothServices/res/values-nl/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Gepland"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"De achtergrondverlichting gaat nooit aan bij elke druk."</item>
-    <item msgid="2183471491302242879">"De achtergrondverlichting gaat aan bij elke druk. De verlichting gaat elke keer 5 seconden aan."</item>
-    <item msgid="4339318499911916123">"De achtergrondverlichting gaat alleen aan bij elke druk gedurende de nacht (18:00 - 06:00 uur). De verlichting gaat elke keer 5 seconden aan."</item>
+    <item msgid="5834948533097349983">"De achtergrondverlichting gaat nooit aan als op de knop wordt gedrukt."</item>
+    <item msgid="2571249757867129366">"De achtergrondverlichting gaat elke keer aan als op de knop wordt gedrukt. De verlichting gaat telkens 5 seconden aan."</item>
+    <item msgid="6724077490859797929">"De achtergrondverlichting gaat alleen elke keer aan als op de knop wordt gedrukt in de avond en nacht (18:00 - 06:00 uur). De verlichting gaat telkens 5 seconden aan."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-or/arrays.xml b/libraries/BluetoothServices/res/values-or/arrays.xml
index b3c5464..88453c8 100644
--- a/libraries/BluetoothServices/res/values-or/arrays.xml
+++ b/libraries/BluetoothServices/res/values-or/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"ସିଡୁଲ କରାଯାଇଛି"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"ପ୍ରତ୍ୟେକ କ୍ଲିକରେ ବେକଲାଇଟ କେବେ ବି ଇଲୁମିନେଟ ହେବ ନାହିଁ।"</item>
-    <item msgid="2183471491302242879">"ପ୍ରତ୍ୟେକ କ୍ଲିକରେ ବେକଲାଇଟ ଇଲୁମିନେଟ ହେବ। ପ୍ରତିଥର ଇଲୁମିନେସନ ସକ୍ରିୟ ହେଲେ ଏହା 5 ସେକେଣ୍ଡ ପର୍ଯ୍ୟନ୍ତ ରହିବ।"</item>
-    <item msgid="4339318499911916123">"କେବଳ ରାତ୍ରି ସମୟରେ (6pm~6am) ପ୍ରତ୍ୟେକ କ୍ଲିକରେ ବେକଲାଇଟ ଇଲୁମିନେଟ ହେବ। ପ୍ରତିଥର ଇଲୁମିନେସନ ସକ୍ରିୟ ହେଲେ ଏହା 5 ସେକେଣ୍ଡ ପର୍ଯ୍ୟନ୍ତ ରହିବ।"</item>
+    <item msgid="5834948533097349983">"ପ୍ରତ୍ୟେକ ଥର ଦବାଇଲେ ବେକଲାଇଟ କେବେ ବି ଇଲୁମିନେଟ ହେବ ନାହିଁ।"</item>
+    <item msgid="2571249757867129366">"ପ୍ରତ୍ୟେକ ଥର ଦବାଇଲେ ବେକଲାଇଟ ଇଲୁମିନେଟ ହେବ। ପ୍ରତ୍ୟେକ ଥର ଇଲୁମିନେସନ ସକ୍ରିୟ ହେଲେ ଏହା 5 ସେକେଣ୍ଡ ପର୍ଯ୍ୟନ୍ତ ରହିବ।"</item>
+    <item msgid="6724077490859797929">"କେବଳ ରାତ୍ରି ସମୟରେ (6pm~6am) ପ୍ରତ୍ୟେକ ଥର ଦବାଇଲେ ବେକଲାଇଟ ଇଲୁମିନେଟ ହେବ। ପ୍ରତ୍ୟେକ ଥର ଇଲୁମିନେସନ ସକ୍ରିୟ ହେଲେ ଏହା 5 ସେକେଣ୍ଡ ପର୍ଯ୍ୟନ୍ତ ରହିବ।"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-or/strings.xml b/libraries/BluetoothServices/res/values-or/strings.xml
index 146f248..86ee52b 100644
--- a/libraries/BluetoothServices/res/values-or/strings.xml
+++ b/libraries/BluetoothServices/res/values-or/strings.xml
@@ -81,7 +81,7 @@
     <string name="bluetooth_disconnect" msgid="1385608885917484057">"ଡିସକନେକ୍ଟ କରନ୍ତୁ"</string>
     <string name="bluetooth_connect" msgid="6283971929092004620">"କନେକ୍ଟ କରନ୍ତୁ"</string>
     <string name="bluetooth_rename" msgid="4433577238394058486">"ରିନେମ କରନ୍ତୁ"</string>
-    <string name="bluetooth_forget" msgid="4933552074497360964">"ଭୁଲିଯାଆନ୍ତୁ"</string>
+    <string name="bluetooth_forget" msgid="4933552074497360964">"ଭୁଲି ଯାଆନ୍ତୁ"</string>
     <string name="bluetooth_toggle_active_audio_output" msgid="494557568422711885">"ଟିଭି ଅଡିଓ ପାଇଁ ବ୍ୟବହାର କରନ୍ତୁ"</string>
     <string name="bluetooth_connected_status" msgid="8391804274846835227">"କନେକ୍ଟ କରାଯାଇଛି"</string>
     <string name="bluetooth_disconnected_status" msgid="972515438988962457">"ବିଚ୍ଛିନ୍ନ କରାଯାଇଛି"</string>
diff --git a/libraries/BluetoothServices/res/values-pa/arrays.xml b/libraries/BluetoothServices/res/values-pa/arrays.xml
index 5c52b84..5dcd454 100644
--- a/libraries/BluetoothServices/res/values-pa/arrays.xml
+++ b/libraries/BluetoothServices/res/values-pa/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"ਨਿਯਤ"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"ਕਲਿੱਕ ਕਰਨ \'ਤੇ ਬੈਕਲਾਈਟ ਕਦੇ ਵੀ ਪ੍ਰਕਾਸ਼ਮਾਨ ਨਹੀਂ ਹੋਵੇਗੀ।"</item>
-    <item msgid="2183471491302242879">"ਹਰ ਵਾਰ ਕਲਿੱਕ ਕਰਨ \'ਤੇ ਬੈਕਲਾਈਟ ਪ੍ਰਕਾਸ਼ਮਾਨ ਹੋਵੇਗੀ। ਇਸਦੇ ਕਿਰਿਆਸ਼ੀਲ ਹੋਣ \'ਤੇ ਰੋਸ਼ਨੀ ਹਰ ਵਾਰ 5 ਸਕਿੰਟਾਂ ਤੱਕ ਪ੍ਰਕਾਸ਼ਮਾਨ ਰਹੇਗੀ।"</item>
-    <item msgid="4339318499911916123">"ਬੈਕਲਾਈਟ ਹਰੇਕ ਕਲਿੱਕ \'ਤੇ ਸਿਰਫ਼ ਰਾਤ ਦੇ ਸਮੇਂ (ਸ਼ਾਮ 6 ਵਜੇ~ਸਵੇਰ 6 ਵਜੇ) ਦੌਰਾਨ ਹੀ ਪ੍ਰਕਾਸ਼ਮਾਨ ਹੋਵੇਗੀ। ਇਸਦੇ ਕਿਰਿਆਸ਼ੀਲ ਹੋਣ \'ਤੇ ਰੋਸ਼ਨੀ ਹਰ ਵਾਰ 5 ਸਕਿੰਟਾਂ ਤੱਕ ਪ੍ਰਕਾਸ਼ਮਾਨ ਰਹੇਗੀ।"</item>
+    <item msgid="5834948533097349983">"ਬੈਕਲਾਈਟ ਹਰ ਵਾਰ ਦਬਾਉਣ \'ਤੇ ਕਦੇ ਵੀ ਪ੍ਰਕਾਸ਼ਮਾਨ ਨਹੀਂ ਹੋਵੇਗੀ।"</item>
+    <item msgid="2571249757867129366">"ਬੈਕਲਾਈਟ ਹਰ ਵਾਰ ਦਬਾਉਣ \'ਤੇ ਪ੍ਰਕਾਸ਼ਮਾਨ ਹੋਵੇਗੀ। ਇਸਦੇ ਕਿਰਿਆਸ਼ੀਲ ਹੋਣ \'ਤੇ ਰੋਸ਼ਨੀ ਹਰ ਵਾਰ 5 ਸਕਿੰਟਾਂ ਤੱਕ ਪ੍ਰਕਾਸ਼ਮਾਨ ਰਹੇਗੀ।"</item>
+    <item msgid="6724077490859797929">"ਬੈਕਲਾਈਟ ਹਰ ਵਾਰ ਦਬਾਉਣ \'ਤੇ ਸਿਰਫ਼ ਰਾਤ ਦੇ ਸਮੇਂ (ਸ਼ਾਮ 6 ਵਜੇ~ਸਵੇਰ 6 ਵਜੇ) ਦੌਰਾਨ ਹੀ ਪ੍ਰਕਾਸ਼ਮਾਨ ਹੋਵੇਗੀ। ਇਸਦੇ ਕਿਰਿਆਸ਼ੀਲ ਹੋਣ \'ਤੇ ਰੋਸ਼ਨੀ ਹਰ ਵਾਰ 5 ਸਕਿੰਟਾਂ ਤੱਕ ਪ੍ਰਕਾਸ਼ਮਾਨ ਰਹੇਗੀ।"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-pl/arrays.xml b/libraries/BluetoothServices/res/values-pl/arrays.xml
index 74dc896..ce85c2b 100644
--- a/libraries/BluetoothServices/res/values-pl/arrays.xml
+++ b/libraries/BluetoothServices/res/values-pl/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Zaplanowane"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Podświetlenie nie będzie się zawsze włączać przy każdym kliknięciu."</item>
-    <item msgid="2183471491302242879">"Podświetlenie będzie się zawsze włączać przy każdym kliknięciu. Będzie włączone przez 5 sekund po każdej aktywacji."</item>
-    <item msgid="4339318499911916123">"Podświetlenie będzie się włączać przy każdym kliknięciu tylko w porze nocnej (18:00–6:00). Będzie włączone przez 5 sekund po każdej aktywacji."</item>
+    <item msgid="5834948533097349983">"Podświetlenie nie będzie nigdy włączać się przy każdym naciśnięciu."</item>
+    <item msgid="2571249757867129366">"Podświetlenie będzie się włączać przy każdym naciśnięciu. Będzie włączone przez 5 sekund po każdej aktywacji."</item>
+    <item msgid="6724077490859797929">"Podświetlenie będzie się włączać przy każdym naciśnięciu tylko w porze nocnej (18:00–6:00). Będzie włączone przez 5 sekund po każdej aktywacji."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-pt-rBR/arrays.xml b/libraries/BluetoothServices/res/values-pt-rBR/arrays.xml
index cd763f5..6752f6f 100644
--- a/libraries/BluetoothServices/res/values-pt-rBR/arrays.xml
+++ b/libraries/BluetoothServices/res/values-pt-rBR/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Programada"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"A luz de fundo nunca acende a cada clique."</item>
-    <item msgid="2183471491302242879">"A luz de fundo acende a cada clique. A iluminação vai durar 5 segundos cada vez que for ativada."</item>
-    <item msgid="4339318499911916123">"A luz de fundo acende a cada clique apenas durante a noite, das 18h às 6h. A iluminação vai durar 5 segundos cada vez que for ativada."</item>
+    <item msgid="5834948533097349983">"A luz de fundo nunca acende a cada toque."</item>
+    <item msgid="2571249757867129366">"A luz de fundo acende a cada toque. A iluminação vai durar cinco segundos cada vez que for ativada."</item>
+    <item msgid="6724077490859797929">"A luz de fundo acende a cada toque apenas durante a noite, das 18h às 6h. A iluminação vai durar cinco segundos cada vez que for ativada."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-pt-rPT/arrays.xml b/libraries/BluetoothServices/res/values-pt-rPT/arrays.xml
index 597c61d..9e6b657 100644
--- a/libraries/BluetoothServices/res/values-pt-rPT/arrays.xml
+++ b/libraries/BluetoothServices/res/values-pt-rPT/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Agendada"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"A retroiluminação nunca se acende quando clica."</item>
-    <item msgid="2183471491302242879">"A retroiluminação acende-se quando clica. A iluminação dura 5 segundos sempre que é ativada."</item>
-    <item msgid="4339318499911916123">"A retroiluminação acende-se quando clica apenas durante a noite (18:00-06:00). A iluminação dura 5 segundos sempre que é ativada."</item>
+    <item msgid="5834948533097349983">"A retroiluminação nunca se acende quando os botões são premidos."</item>
+    <item msgid="2571249757867129366">"A retroiluminação acende-se quando os botões são premidos. A iluminação dura 5 segundos sempre que é ativada."</item>
+    <item msgid="6724077490859797929">"A retroiluminação acende-se quando os botões são premidos apenas durante a noite (18:00-06:00). A iluminação dura 5 segundos sempre que é ativada."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-pt/arrays.xml b/libraries/BluetoothServices/res/values-pt/arrays.xml
index cd763f5..6752f6f 100644
--- a/libraries/BluetoothServices/res/values-pt/arrays.xml
+++ b/libraries/BluetoothServices/res/values-pt/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Programada"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"A luz de fundo nunca acende a cada clique."</item>
-    <item msgid="2183471491302242879">"A luz de fundo acende a cada clique. A iluminação vai durar 5 segundos cada vez que for ativada."</item>
-    <item msgid="4339318499911916123">"A luz de fundo acende a cada clique apenas durante a noite, das 18h às 6h. A iluminação vai durar 5 segundos cada vez que for ativada."</item>
+    <item msgid="5834948533097349983">"A luz de fundo nunca acende a cada toque."</item>
+    <item msgid="2571249757867129366">"A luz de fundo acende a cada toque. A iluminação vai durar cinco segundos cada vez que for ativada."</item>
+    <item msgid="6724077490859797929">"A luz de fundo acende a cada toque apenas durante a noite, das 18h às 6h. A iluminação vai durar cinco segundos cada vez que for ativada."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ro/arrays.xml b/libraries/BluetoothServices/res/values-ro/arrays.xml
index 0059d53..e5e0ddf 100644
--- a/libraries/BluetoothServices/res/values-ro/arrays.xml
+++ b/libraries/BluetoothServices/res/values-ro/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Programat"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Iluminarea din spate nu se va aprinde la fiecare apăsare."</item>
-    <item msgid="2183471491302242879">"Iluminarea din spate se va aprinde la fiecare apăsare. Iluminarea va dura 5 secunde de fiecare dată când este activată."</item>
-    <item msgid="4339318499911916123">"Iluminarea din spate se va aprinde la fiecare apăsare numai noaptea (06:00 – 18:00). Iluminarea va dura 5 secunde de fiecare dată când este activată."</item>
+    <item msgid="5834948533097349983">"Iluminarea din spate nu se va aprinde la fiecare apăsare."</item>
+    <item msgid="2571249757867129366">"Iluminarea din spate se va aprinde la fiecare apăsare. Iluminarea va dura 5 secunde de fiecare dată când este activată."</item>
+    <item msgid="6724077490859797929">"Iluminarea din spate se va aprinde la fiecare apăsare numai noaptea (18:00 – 6:00). Iluminarea va dura 5 secunde de fiecare dată când este activată."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ru/arrays.xml b/libraries/BluetoothServices/res/values-ru/arrays.xml
index 87e16c6..2351eea 100644
--- a/libraries/BluetoothServices/res/values-ru/arrays.xml
+++ b/libraries/BluetoothServices/res/values-ru/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"По расписанию"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Подсветка не включается."</item>
-    <item msgid="2183471491302242879">"Кнопки подсвечиваются в течение пяти секунд после того, как вы нажали одну из них."</item>
-    <item msgid="4339318499911916123">"Подсветка включается на 5 секунд по нажатию кнопок только вечером, ночью и рано утром (примерно с 18:00 и до 06:00)."</item>
+    <item msgid="5834948533097349983">"Подсветка не будет включаться при каждом нажатии."</item>
+    <item msgid="2571249757867129366">"Кнопки будут подсвечиваться в течение пяти секунд после того, как вы нажмете одну из них."</item>
+    <item msgid="6724077490859797929">"Подсветка будет включаться на пять секунд по нажатию кнопок только вечером, ночью и рано утром (примерно с 18:00 до 06:00)."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-si/arrays.xml b/libraries/BluetoothServices/res/values-si/arrays.xml
index 5f3a992..598a1e3 100644
--- a/libraries/BluetoothServices/res/values-si/arrays.xml
+++ b/libraries/BluetoothServices/res/values-si/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"කාලසටහන්ගත"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"එක් එක් ක්ලික් කිරීමකින් පසු ආලෝකය කිසි විටෙකත් ආලෝකවත් නොවේ."</item>
-    <item msgid="2183471491302242879">"එක් එක් ක්ලික් කිරීමකින් පසු ආලෝකය ආලෝකමත් වේ. එය සක්‍රිය කරන එක් එක් අවස්ථාවේ ආලෝකය තත්පර 5ක් පවතිනු ඇත."</item>
-    <item msgid="4339318499911916123">"එක් එක් ක්ලික් කිරීමකින් පසු ආලෝකය රාත්‍රී කාලයේ (ප.ව.6~පෙ.ව.6) පමණක් ආලෝකමත් වේ. එය සක්‍රිය කරන එක් එක් අවස්ථාවේ ආලෝකය තත්පර 5ක් පවතිනු ඇත."</item>
+    <item msgid="5834948533097349983">"එක් එක් එබීම සමග පසුබිම් ආලෝකය ආලෝකවත් නොවනු ඇත."</item>
+    <item msgid="2571249757867129366">"එක් එක් එබීම සමග පසුබිම් ආලෝකය ආලෝකවත් වනු ඇත. එය සක්‍රිය කරන එක් එක් අවස්ථාවේ ආලෝකය තත්පර 5ක් පවතිනු ඇත."</item>
+    <item msgid="6724077490859797929">"එක් එක් එබීම සමග පසුබිම් ආලෝකය රාත්‍රී කාලයේ (ප.ව.6~පෙ.ව.6) පමණක් ආලෝකමත් වනු ඇත. එය සක්‍රිය කරන එක් එක් අවස්ථාවේ ආලෝකය තත්පර 5ක් පවතිනු ඇත."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-sk/arrays.xml b/libraries/BluetoothServices/res/values-sk/arrays.xml
index e0e4fe0..1d066b6 100644
--- a/libraries/BluetoothServices/res/values-sk/arrays.xml
+++ b/libraries/BluetoothServices/res/values-sk/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Naplánované"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Podsvietenie sa po každom stlačení nikdy nerozsvieti."</item>
-    <item msgid="2183471491302242879">"Podsvietenie sa po každom stlačení rozsvieti. Po každej aktivácii bude svietiť päť sekúnd."</item>
-    <item msgid="4339318499911916123">"Podsvietenie sa po každom stlačení rozsvieti iba počas večerných a nočných hodín (18:00 ~ 6:00). Po každej aktivácii bude svietiť päť sekúnd."</item>
+    <item msgid="5834948533097349983">"Podsvietenie sa po každom stlačení nikdy nerozsvieti."</item>
+    <item msgid="2571249757867129366">"Podsvietenie sa po každom stlačení rozsvieti. Po každej aktivácii bude svietiť päť sekúnd."</item>
+    <item msgid="6724077490859797929">"Podsvietenie sa po každom stlačení rozsvieti iba počas večerných a nočných hodín (18:00 ~ 6:00). Po každej aktivácii bude svietiť päť sekúnd."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-sl/arrays.xml b/libraries/BluetoothServices/res/values-sl/arrays.xml
index fc48904..9756260 100644
--- a/libraries/BluetoothServices/res/values-sl/arrays.xml
+++ b/libraries/BluetoothServices/res/values-sl/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Načrtovano"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Osvetlitev ozadja ne zasveti z vsakim klikom."</item>
-    <item msgid="2183471491302242879">"Osvetlitev ozadja zasveti z vsakim klikom. Osvetlitev traja 5 sekund vsakič, ko je aktivirana."</item>
-    <item msgid="4339318499911916123">"Osvetlitev ozadja zasveti z vsakim klikom samo v večernem in nočnem času (od 18.00 do približno 6.00). Osvetlitev traja 5 sekund vsakič, ko je aktivirana."</item>
+    <item msgid="5834948533097349983">"Osvetlitev ozadja nikoli ne zasveti z vsakim pritiskom."</item>
+    <item msgid="2571249757867129366">"Osvetlitev ozadja zasveti z vsakim pritiskom. Osvetlitev traja 5 sekund vsakič, ko je aktivirana."</item>
+    <item msgid="6724077490859797929">"Osvetlitev ozadja zasveti z vsakim pritiskom samo v večernem in nočnem času (od 18.00 do približno 6.00). Osvetlitev traja 5 sekund vsakič, ko je aktivirana."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-sq/arrays.xml b/libraries/BluetoothServices/res/values-sq/arrays.xml
index 89e6c36..6d10e35 100644
--- a/libraries/BluetoothServices/res/values-sq/arrays.xml
+++ b/libraries/BluetoothServices/res/values-sq/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"I planifikuar"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Drita e sfondit nuk do të ndriçojë me çdo klikim."</item>
-    <item msgid="2183471491302242879">"Drita e sfondit do të ndriçojë me çdo klikim. Ndriçimi do të zgjasë për 5 sekonda sa herë që të aktivizohet."</item>
-    <item msgid="4339318499911916123">"Drita e sfondit do të ndriçojë me çdo klikim vetëm gjatë orarit të natës (18:00~6:00). Ndriçimi do të zgjasë për 5 sekonda sa herë që të aktivizohet."</item>
+    <item msgid="5834948533097349983">"Drita e sfondit nuk do të ndriçojë asnjëherë me çdo shtypje."</item>
+    <item msgid="2571249757867129366">"Drita e sfondit do të ndriçojë me çdo shtypje. Ndriçimi do të zgjasë për 5 sekonda sa herë që të aktivizohet."</item>
+    <item msgid="6724077490859797929">"Drita e sfondit do të ndriçojë me çdo shtypje vetëm gjatë orarit të natës (18:00~6:00). Ndriçimi do të zgjasë për 5 sekonda sa herë që të aktivizohet."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-sr/arrays.xml b/libraries/BluetoothServices/res/values-sr/arrays.xml
index c62310f..bbf9857 100644
--- a/libraries/BluetoothServices/res/values-sr/arrays.xml
+++ b/libraries/BluetoothServices/res/values-sr/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Заказано"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Позадинско осветљење се неће укључивати за сваки клик."</item>
-    <item msgid="2183471491302242879">"Позадинско осветљење ће се укључивати за сваки клик. Осветљење ће трајати 5 секунди сваки пут када се активира."</item>
-    <item msgid="4339318499911916123">"Позадинско осветљење ће се укључивати за сваки клик само током ноћи (оквирно од 18:00 до 6:00). Осветљење ће трајати 5 секунди сваки пут када се активира."</item>
+    <item msgid="5834948533097349983">"Позадинско осветљење се неће укључивати за сваки притисак."</item>
+    <item msgid="2571249757867129366">"Позадинско осветљење ће се укључивати за сваки притисак. Осветљење ће трајати 5 секунди сваки пут када се активира."</item>
+    <item msgid="6724077490859797929">"Позадинско осветљење ће се укључивати за сваки притисак само током ноћи (оквирно од 18:00 до 6:00). Осветљење ће трајати 5 секунди сваки пут када се активира."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-sv/arrays.xml b/libraries/BluetoothServices/res/values-sv/arrays.xml
index ecfea87..91f7a8c 100644
--- a/libraries/BluetoothServices/res/values-sv/arrays.xml
+++ b/libraries/BluetoothServices/res/values-sv/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Planerad"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Bakgrundsbelysningen aktiveras aldrig vid klick."</item>
-    <item msgid="2183471491302242879">"Bakgrundsbelysningen aktiveras vid varje klick. Den lyser i fem sekunder varje gång den aktiveras."</item>
-    <item msgid="4339318499911916123">"Bakgrundsbelysningen aktiveras vid varje klick endast på natten (mellan kl. 18.00 och 6.00). Den lyser i fem sekunder varje gång den aktiveras."</item>
+    <item msgid="5834948533097349983">"Bakgrundsbelysningen aktiveras aldrig vid tryckning."</item>
+    <item msgid="2571249757867129366">"Bakgrundsbelysningen aktiveras vid varje tryckning. Den lyser i fem sekunder varje gång den aktiveras."</item>
+    <item msgid="6724077490859797929">"Bakgrundsbelysningen aktiveras vid varje tryckning endast på natten (mellan kl. 18.00 och 6.00). Den lyser i fem sekunder varje gång den aktiveras."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-sw/arrays.xml b/libraries/BluetoothServices/res/values-sw/arrays.xml
index 4cb007e..43774c5 100644
--- a/libraries/BluetoothServices/res/values-sw/arrays.xml
+++ b/libraries/BluetoothServices/res/values-sw/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Umeratibiwa"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Mwangaza wa skrini hautaangaza kila unapobofya."</item>
-    <item msgid="2183471491302242879">"Mwangaza wa skrini utaangaza kila unapobofya. Mwangaza utawaka kwa sekunde 5 kila wakati unapowashwa."</item>
-    <item msgid="4339318499911916123">"Mwangaza wa skrini utaangaza kila unapobofya saa za usiku pekee (saa 12 jioni hadi 12 asubuhi). Mwangaza utawaka kwa sekunde 5 kila wakati unapowashwa."</item>
+    <item msgid="5834948533097349983">"Mwangaza wa skrini hautawaka kila mara utakapobonyeza."</item>
+    <item msgid="2571249757867129366">"Mwangaza wa skrini utawaka kila mara utakapobonyeza. Mwangaza utawaka kwa sekunde 5 kila mara utakapowashwa."</item>
+    <item msgid="6724077490859797929">"Mwangaza wa skrini utawaka kila mara utakapobonyeza usiku pekee (saa 12 jioni hadi 12 asubuhi). Mwangaza utawaka kwa sekunde 5 kila mara utakapowashwa."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ta/arrays.xml b/libraries/BluetoothServices/res/values-ta/arrays.xml
index 1d816ed..be5d900 100644
--- a/libraries/BluetoothServices/res/values-ta/arrays.xml
+++ b/libraries/BluetoothServices/res/values-ta/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"திட்டமிடப்பட்டது"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"பேக்லைட் ஒவ்வொரு கிளிக்கின்போதும் ஒளிராது."</item>
-    <item msgid="2183471491302242879">"பேக்லைட் ஒவ்வொரு கிளிக்கின்போதும் ஒளிரும். வெளிச்சம் ஒவ்வொருமுறை செயல்படுத்தப்படும்போதும் அது 5 வினாடிகள் நீடிக்கும்."</item>
-    <item msgid="4339318499911916123">"இரவுநேரத்தில் (மாலை 6 மணி~காலை 6 மணி) மட்டும் பேக்லைட் ஒவ்வொரு கிளிக்கின்போதும் ஒளிரும். வெளிச்சம் ஒவ்வொருமுறை செயல்படுத்தப்படும்போதும் அது 5 வினாடிகள் நீடிக்கும்."</item>
+    <item msgid="5834948533097349983">"ஒவ்வொருமுறை அழுத்தும்போதும் பேக்லைட் ஒளிராது."</item>
+    <item msgid="2571249757867129366">"ஒவ்வொருமுறை அழுத்தும்போதும் பேக்லைட் ஒளிரும். ஒவ்வொருமுறை செயல்படுத்தப்படும்போதும் 5 வினாடிகள் ஒளிரும்."</item>
+    <item msgid="6724077490859797929">"இரவுநேரத்தில் (மாலை 6 மணி முதல் காலை 6 மணி வரை) மட்டும் ஒவ்வொருமுறை அழுத்தும்போதும் பேக்லைட் ஒளிரும். ஒவ்வொருமுறை செயல்படுத்தப்படும்போதும் 5 வினாடிகள் ஒளிரும்."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-te/arrays.xml b/libraries/BluetoothServices/res/values-te/arrays.xml
index 2c82acf..1982d07 100644
--- a/libraries/BluetoothServices/res/values-te/arrays.xml
+++ b/libraries/BluetoothServices/res/values-te/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"షెడ్యూల్ అయింది"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"క్లిక్ చేసిన ప్రతిసారి బ్యాక్‌లైట్ వెలగదు."</item>
-    <item msgid="2183471491302242879">"క్లిక్ చేసిన ప్రతిసారి బ్యాక్‌లైట్ వెలుగుతుంది. యాక్టివేట్ అయినప్పుడల్లా బ్యాక్‌లైట్ 5 సెకన్ల పాటు వెలుగుతూ ఉంటుంది."</item>
-    <item msgid="4339318499911916123">"రాత్రి సమయాలలో(6pm~6am) మాత్రమే క్లిక్ చేసినప్పుడల్లా బ్యాక్‌లైట్ వెలుగుతుంది. యాక్టివేట్ అయినప్పుడల్లా బ్యాక్‌లైట్ 5 సెకన్ల పాటు వెలుగుతూ ఉంటుంది."</item>
+    <item msgid="5834948533097349983">"నొక్కినప్పుడల్లా బ్యాక్‌లైట్ వెలగదు."</item>
+    <item msgid="2571249757867129366">"నొక్కినప్పుడల్లా బ్యాక్‌లైట్ వెలుగుతుంది. యాక్టివేట్ అయినప్పుడల్లా బ్యాక్‌లైట్ 5 సెకన్ల పాటు వెలుగుతూ ఉంటుంది."</item>
+    <item msgid="6724077490859797929">"రాత్రి సమయాలలో (6pm~6am) మాత్రమే క్లిక్ నొక్కినప్పుడల్లా బ్యాక్‌లైట్ వెలుగుతుంది. యాక్టివేట్ అయినప్పుడల్లా బ్యాక్‌లైట్ 5 సెకన్ల పాటు వెలుగుతూ ఉంటుంది."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-te/strings.xml b/libraries/BluetoothServices/res/values-te/strings.xml
index 2853d15..8a35126 100644
--- a/libraries/BluetoothServices/res/values-te/strings.xml
+++ b/libraries/BluetoothServices/res/values-te/strings.xml
@@ -41,7 +41,7 @@
     <string name="settings_remote_serial_number_label" msgid="7591347399882767241">"బ్లూటూత్ అడ్రస్‌"</string>
     <string name="settings_bt_battery_low" msgid="3547517382697124858">"దయచేసి బ్యాటరీని రీప్లేస్ చేయండి"</string>
     <string name="settings_bt_battery_low_warning" msgid="721091326401791089">"బ్యాటరీ తక్కువగా ఉంది"</string>
-    <string name="connected_devices_pref_title" msgid="8985364841073196008">"కనెక్ట్ అయిన పరికరాలు"</string>
+    <string name="connected_devices_pref_title" msgid="8985364841073196008">"కనెక్ట్ అయిన డివైజ్‌లు"</string>
     <string name="connected_devices_slice_pref_title" msgid="8637777961277201747">"రిమోట్‌లు &amp; యాక్సెసరీలు"</string>
     <string name="settings_notif_update_title" msgid="4767043003900594863">"మీ రిమోట్‌ను అప్‌డేట్ చేయండి"</string>
     <string name="settings_notif_update_text" msgid="1092279154776177720">"ఇన్‌స్టాల్ చేయడానికి సిద్ధంగా ఉంది"</string>
diff --git a/libraries/BluetoothServices/res/values-th/arrays.xml b/libraries/BluetoothServices/res/values-th/arrays.xml
index 89958ac..45a403c 100644
--- a/libraries/BluetoothServices/res/values-th/arrays.xml
+++ b/libraries/BluetoothServices/res/values-th/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"ตามกำหนดเวลา"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"ไฟแบ็กไลต์จะไม่ติดสว่างแต่ละครั้งที่กดปุ่ม"</item>
-    <item msgid="2183471491302242879">"ไฟแบ็กไลต์จะติดสว่างแต่ละครั้งที่กดปุ่ม โดยจะสว่างอยู่เป็นเวลา 5 วินาทีในแต่ละครั้งที่มีการเปิดใช้งาน"</item>
-    <item msgid="4339318499911916123">"ไฟแบ็กไลต์จะติดสว่างแต่ละครั้งที่กดปุ่มเฉพาะในช่วงเวลากลางคืน (ประมาณ 18:00 - 06:00 น.) โดยจะสว่างอยู่เป็นเวลา 5 วินาทีในแต่ละครั้งที่มีการเปิดใช้งาน"</item>
+    <item msgid="5834948533097349983">"ไฟแบ็กไลต์จะไม่ติดสว่างแต่ละครั้งที่กดปุ่ม"</item>
+    <item msgid="2571249757867129366">"ไฟแบ็กไลต์จะติดสว่างแต่ละครั้งที่กดปุ่ม โดยจะสว่างอยู่เป็นเวลา 5 วินาทีในแต่ละครั้งที่มีการเปิดใช้งาน"</item>
+    <item msgid="6724077490859797929">"ไฟแบ็กไลต์จะติดสว่างแต่ละครั้งที่กดปุ่มเฉพาะในช่วงเวลากลางคืน (ประมาณ 18:00-06:00 น.) โดยจะสว่างอยู่เป็นเวลา 5 วินาทีในแต่ละครั้งที่มีการเปิดใช้งาน"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-tl/arrays.xml b/libraries/BluetoothServices/res/values-tl/arrays.xml
index b8bd5b3..e4199fd 100644
--- a/libraries/BluetoothServices/res/values-tl/arrays.xml
+++ b/libraries/BluetoothServices/res/values-tl/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Nakaiskedyul"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Hindi kailanman iilaw sa bawat pag-click ang backlight."</item>
-    <item msgid="2183471491302242879">"Iilaw sa bawat pag-click ang backlight. Tatagal nang 5 segundo ang ilaw sa tuwing ia-activate ito."</item>
-    <item msgid="4339318499911916123">"Iilaw sa bawat pag-click ang backlight kapag gabi lang (6pm~6am). Tatagal nang 5 segundo ang ilaw sa tuwing ia-activate ito."</item>
+    <item msgid="5834948533097349983">"Hindi kailanman iilaw ang backlight sa bawat pagpindot."</item>
+    <item msgid="2571249757867129366">"Iilaw ang backlight sa bawat pagpindot. Tatagal nang 5 segundo ang pag-ilaw sa tuwing ia-activate ito."</item>
+    <item msgid="6724077490859797929">"Iilaw ang backlight sa bawat pagpindot kapag gabi lang (6pm~6am). Tatagal nang 5 segundo ang pag-ilaw sa tuwing ia-activate ito."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-tr/arrays.xml b/libraries/BluetoothServices/res/values-tr/arrays.xml
index babfc71..6e2b3f8 100644
--- a/libraries/BluetoothServices/res/values-tr/arrays.xml
+++ b/libraries/BluetoothServices/res/values-tr/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Planlandı"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Arka ışık hiçbir zaman düğmeye her basıldığında yanmaz."</item>
-    <item msgid="2183471491302242879">"Arka ışık düğmeye her basıldığında yanar. Işık, her etkinleştirildiğinde 5 saniye boyunca yanar."</item>
-    <item msgid="4339318499911916123">"Arka ışık yalnızca gece saatlerinde (18:00-06:00) düğmeye her basıldığında yanar. Işık, her etkinleştirildiğinde 5 saniye boyunca yanar."</item>
+    <item msgid="5834948533097349983">"Arka ışık düğmeye her basıldığında yanmaz."</item>
+    <item msgid="2571249757867129366">"Arka ışık düğmeye her basıldığında yanar. Işık, her etkinleştirildiğinde 5 saniye boyunca yanar."</item>
+    <item msgid="6724077490859797929">"Arka ışık yalnızca gece saatlerinde (18:00-06:00) düğmeye her basıldığında yanar. Işık, her etkinleştirildiğinde 5 saniye boyunca yanar."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-uk/arrays.xml b/libraries/BluetoothServices/res/values-uk/arrays.xml
index db28964..9305f83 100644
--- a/libraries/BluetoothServices/res/values-uk/arrays.xml
+++ b/libraries/BluetoothServices/res/values-uk/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"За розкладом"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Підсвічування не вмикатиметься після кожного кліку."</item>
-    <item msgid="2183471491302242879">"Підсвічування вмикатиметься після кожного кліку й щоразу триватиме 5 секунд після активації."</item>
-    <item msgid="4339318499911916123">"Підсвічування вмикатиметься після кожного кліку лише ввечері й уночі (18:00~6:00) і щоразу триватиме 5 секунд після активації."</item>
+    <item msgid="5834948533097349983">"Підсвічування не вмикатиметься після кожного натискання."</item>
+    <item msgid="2571249757867129366">"Підсвічування вмикатиметься після кожного натискання й щоразу триватиме 5 секунд після активації."</item>
+    <item msgid="6724077490859797929">"Підсвічування вмикатиметься після кожного натискання лише ввечері й уночі (18:00~6:00) і щоразу триватиме 5 секунд після активації."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-ur/arrays.xml b/libraries/BluetoothServices/res/values-ur/arrays.xml
index ee4db59..225663e 100644
--- a/libraries/BluetoothServices/res/values-ur/arrays.xml
+++ b/libraries/BluetoothServices/res/values-ur/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"شیڈول کردہ"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"ہر بار کلک کرنے پر کبھی بھی بیک لائٹ نہیں جلے گی۔"</item>
-    <item msgid="2183471491302242879">"ہر بار کلک کرنے پر بیک لائٹ جلے گی۔ جب بھی لائٹ کو فعال کیا جائے گا وہ 5 سیکنڈ تک جلے گی۔"</item>
-    <item msgid="4339318499911916123">"بیک لائٹ صرف رات کے اوقات (6pm~6am) کے دوران ہر بار کلک کرنے پر جلے گی۔ جب بھی لائٹ کو فعال کیا جائے گا وہ 5 سیکنڈ تک جلے گی۔"</item>
+    <item msgid="5834948533097349983">"ہر بار دبانے پر بیک لائٹ کبھی نہیں جلے گی۔"</item>
+    <item msgid="2571249757867129366">"ہر بار دبانے پر بیک لائٹ جلے گی۔ ہر بار فعال کیے جانے پر لائٹ 5 سیکنڈ تک جلے گی۔"</item>
+    <item msgid="6724077490859797929">"بیک لائٹ صرف رات کے اوقات (6pm~6am) کے دوران ہر بار دبانے پر جلے گی۔ ہر بار فعال کیے جانے پر لائٹ 5 سیکنڈ تک جلے گی۔"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-uz/arrays.xml b/libraries/BluetoothServices/res/values-uz/arrays.xml
index 0e4cf42..52a80d8 100644
--- a/libraries/BluetoothServices/res/values-uz/arrays.xml
+++ b/libraries/BluetoothServices/res/values-uz/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Rejalashtirilgan"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Orqa chiroq har bir bosishda hech qachon yoritilmaydi."</item>
-    <item msgid="2183471491302242879">"Orqa chiroq har bir bosishda yoritiladi. Yoritish har safar faollashtirilganda 5 soniya davom etadi."</item>
-    <item msgid="4339318499911916123">"Orqa chiroq har bir bosishda faqat tungi soatlarda (18:00~06:00) yonadi. Yoritish har safar faollashtirilganda 5 soniya davom etadi."</item>
+    <item msgid="5834948533097349983">"Orqa chiroq har bosganda aslo yonmaydi."</item>
+    <item msgid="2571249757867129366">"Orqa chiroq har bosganda yonadi. Yoritish har safar faollashtirilganda 5 soniya davom etadi."</item>
+    <item msgid="6724077490859797929">"Orqa chiroq har bosganda faqat tungi soatlarda (18:00~06:00) yonadi. Yoritish har safar faollashtirilganda 5 soniya davom etadi."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-vi/arrays.xml b/libraries/BluetoothServices/res/values-vi/arrays.xml
index 27a3502..0e80c1a 100644
--- a/libraries/BluetoothServices/res/values-vi/arrays.xml
+++ b/libraries/BluetoothServices/res/values-vi/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Theo lịch"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Đèn nền sẽ không sáng sau mỗi lần nhấp."</item>
-    <item msgid="2183471491302242879">"Đèn nền sẽ sáng sau mỗi lần nhấp. Đèn sẽ sáng trong 5 giây sau mỗi lần kích hoạt."</item>
-    <item msgid="4339318499911916123">"Đèn nền sẽ chỉ sáng sau mỗi lần nhấp vào ban đêm (6 giờ chiều đến 6 giờ sáng). Đèn sẽ sáng trong 5 giây sau mỗi lần kích hoạt."</item>
+    <item msgid="5834948533097349983">"Đèn nền sẽ không sáng sau mỗi lần nhấn."</item>
+    <item msgid="2571249757867129366">"Đèn nền sẽ sáng sau mỗi lần nhấn. Đèn sẽ sáng trong 5 giây sau mỗi lần kích hoạt."</item>
+    <item msgid="6724077490859797929">"Đèn nền sẽ chỉ sáng sau mỗi lần nhấn vào ban đêm (6:00 CH – 6:00 SA). Đèn sẽ sáng trong 5 giây sau mỗi lần kích hoạt."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-zh-rCN/arrays.xml b/libraries/BluetoothServices/res/values-zh-rCN/arrays.xml
index d59a808..7f6ba2a 100644
--- a/libraries/BluetoothServices/res/values-zh-rCN/arrays.xml
+++ b/libraries/BluetoothServices/res/values-zh-rCN/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"已排定时间"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"每次点击时，背光都不会亮起。"</item>
-    <item msgid="2183471491302242879">"每次点击时，背光都会亮起。每次激活时，背光将持续亮 5 秒钟。"</item>
-    <item msgid="4339318499911916123">"只有在夜间时段（晚上 6 点到早上 6 点）点击时，背光才会亮起。每次激活时，背光将持续亮 5 秒钟。"</item>
+    <item msgid="5834948533097349983">"每次按下按钮时背光都不会亮起。"</item>
+    <item msgid="2571249757867129366">"每次按下按钮时背光都会亮起。每次被激活时，背光将持续亮 5 秒钟。"</item>
+    <item msgid="6724077490859797929">"只有在夜间时段（晚上 6 点到早上 6 点）按下按钮时，背光才会亮起。每次被激活时，背光将持续亮 5 秒钟。"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-zh-rHK/arrays.xml b/libraries/BluetoothServices/res/values-zh-rHK/arrays.xml
index 0d5b964..70a4c22 100644
--- a/libraries/BluetoothServices/res/values-zh-rHK/arrays.xml
+++ b/libraries/BluetoothServices/res/values-zh-rHK/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"已預定"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"背光不會在每次點擊時亮起。"</item>
-    <item msgid="2183471491302242879">"背光在每次點擊時亮起。每次啟用時，背光會亮起 5 秒。"</item>
-    <item msgid="4339318499911916123">"背光於晚間時段 (下午 6 時至上午 6 時)，才會在每次點擊時亮起。每次啟用時，背光會亮起 5 秒。"</item>
+    <item msgid="5834948533097349983">"背光不會在每次按下時亮起。"</item>
+    <item msgid="2571249757867129366">"背光會在每次按下時亮起。每次啟用時，背光會亮起 5 秒。"</item>
+    <item msgid="6724077490859797929">"背光於晚間時段 (下午 6 時至上午 6 時)，才會在每次按下時亮起。每次啟用時，背光會亮起 5 秒。"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-zh-rTW/arrays.xml b/libraries/BluetoothServices/res/values-zh-rTW/arrays.xml
index 6cc98fc..4b9caf5 100644
--- a/libraries/BluetoothServices/res/values-zh-rTW/arrays.xml
+++ b/libraries/BluetoothServices/res/values-zh-rTW/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"在排定時間內"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"按下按鈕時不會啟動按鈕背光。"</item>
-    <item msgid="2183471491302242879">"按下按鈕時會啟動按鈕背光，且背光會持續 5 秒。"</item>
-    <item msgid="4339318499911916123">"只有在夜間 (下午 6 點至隔天上午 6 點) 按下按鈕時才啟動按鈕背光，且背光會持續 5 秒。"</item>
+    <item msgid="5834948533097349983">"按下按鈕不會讓按鈕背光亮起。"</item>
+    <item msgid="2571249757867129366">"按下按鈕會讓按鈕背光亮起，且背光將持續 5 秒。"</item>
+    <item msgid="6724077490859797929">"只有在夜間 (下午 6 點至隔天上午 6 點) 按下按鈕時，按鈕背光才會亮起，且背光將持續 5 秒。"</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values-zu/arrays.xml b/libraries/BluetoothServices/res/values-zu/arrays.xml
index b640c4c..df2f3ac 100644
--- a/libraries/BluetoothServices/res/values-zu/arrays.xml
+++ b/libraries/BluetoothServices/res/values-zu/arrays.xml
@@ -22,8 +22,8 @@
     <item msgid="1608651425322487768">"Kushejuliwe"</item>
   </string-array>
   <string-array name="backlight_hints">
-    <item msgid="9076173600287388436">"Ukukhanya kwangemuva ngeke kukhanyise ngokuchofoza ngakunye."</item>
-    <item msgid="2183471491302242879">"Ukukhanya kwangemuva kuzokhanyisa ngokuchofoza ngakunye. Ukukhanya kuzothatha imizuzwana emi-5 njalo lapho kukhanyiswa."</item>
-    <item msgid="4339318499911916123">"Ukukhanya kuzokhanya ngokuchofoza ngakunye kuphela phakathi namahora asebusuku(6pm~6am). Ukukhanya kuzothatha imizuzwana emi-5 njalo lapho kukhanyiswa."</item>
+    <item msgid="5834948533097349983">"Ilambu langemuva angeke likhanyise ngokucindezela ngakunye."</item>
+    <item msgid="2571249757867129366">"Ukukhanya kwangemuva kuzokhanyisa ngokucindezela ngakunye. Ukukhanya kuzothatha imizuzwana emi-5 njalo lapho kukhanyiswa."</item>
+    <item msgid="6724077490859797929">"Ukukhanya kuzokhanya ngokucindezela ngakunye kuphela phakathi namahora asebusuku (6pm~6am). Ukukhanya kuzothatha imizuzwana emi-5 njalo lapho kukhanyiswa."</item>
   </string-array>
 </resources>
diff --git a/libraries/BluetoothServices/res/values/arrays.xml b/libraries/BluetoothServices/res/values/arrays.xml
index fe64cbe..c3756a4 100644
--- a/libraries/BluetoothServices/res/values/arrays.xml
+++ b/libraries/BluetoothServices/res/values/arrays.xml
@@ -28,8 +28,8 @@
     </string-array>
 
     <string-array name="backlight_hints">
-        <item>The backlight will never illuminate with each click.</item>
-        <item>The backlight will illuminate with each click. The illumination will last for 5 seconds each time it is activated.</item>
-        <item>The backlight will illuminate with each click only during nighttime hours(6pm~6am). The illumination will last for 5 seconds each time it is activated.</item>
+        <item>The backlight will never illuminate with each press.</item>
+        <item>The backlight will illuminate with each press. The illumination will last for 5 seconds each time it is activated.</item>
+        <item>The backlight will illuminate with each press only during nighttime hours (6pm~6am). The illumination will last for 5 seconds each time it is activated.</item>
     </string-array>
 </resources>
\ No newline at end of file
diff --git a/libraries/BluetoothServices/res/values/config.xml b/libraries/BluetoothServices/res/values/config.xml
index c2ef49a..7a7aff9 100644
--- a/libraries/BluetoothServices/res/values/config.xml
+++ b/libraries/BluetoothServices/res/values/config.xml
@@ -78,6 +78,10 @@
 
   <string name="custom_bluetooth_slice_provider_uri" translatable="false" />
 
+  <!-- Entry in settings menu to manage external speakers. -->
+  <string name="external_speaker_slice_provider_uri" translatable="false" />
+  <string name="external_speaker_category" />
+
   <!--
     Whether the ATV integrates the Find My Remote functionality with the on-device button.
     If it does, the integration should respect the value of
diff --git a/libraries/BluetoothServices/res/values/overlayable.xml b/libraries/BluetoothServices/res/values/overlayable.xml
new file mode 100644
index 0000000..3ff41c7
--- /dev/null
+++ b/libraries/BluetoothServices/res/values/overlayable.xml
@@ -0,0 +1,9 @@
+<?xml version="1.0" encoding="utf-8" ?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android">
+  <overlayable name="RemotesAccessoriesConfig">
+    <policy type="signature">
+      <item type="string" name="external_speaker_slice_provider_uri"/>
+      <item type="string" name="external_speaker_category"/>
+    </policy>
+  </overlayable>
+</resources>
diff --git a/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/BluetoothDevicePreferenceFragment.java b/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/BluetoothDevicePreferenceFragment.java
index d0c8a2d..1640d4f 100644
--- a/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/BluetoothDevicePreferenceFragment.java
+++ b/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/BluetoothDevicePreferenceFragment.java
@@ -59,6 +59,7 @@ public class BluetoothDevicePreferenceFragment extends LeanbackPreferenceFragmen
     static final String KEY_RENAME = "key_rename";
     static final String KEY_CONNECT = "key_connect";
     static final String KEY_DISCONNECT = "key_disconnect";
+    static final String KEY_BLE_INFO = "key_bluetooth_info";
     static final String KEY_FORGET = "key_forget";
     static final String KEY_UPDATE= "key_update";
     private static final String KEY_RECONNECT = "key_reconnect";
diff --git a/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/ConnectedDevicesSliceProvider.java b/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/ConnectedDevicesSliceProvider.java
index 8d423b4..fa563ec 100644
--- a/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/ConnectedDevicesSliceProvider.java
+++ b/libraries/BluetoothServices/src/com/google/android/tv/btservices/settings/ConnectedDevicesSliceProvider.java
@@ -27,6 +27,7 @@ import static com.android.tv.twopanelsettings.slices.SlicesConstants.EXTRA_SLICE
 import static com.google.android.tv.btservices.settings.BluetoothDevicePreferenceFragment.CONT_CANCEL_ARGS;
 import static com.google.android.tv.btservices.settings.BluetoothDevicePreferenceFragment.KEY_CONNECT;
 import static com.google.android.tv.btservices.settings.BluetoothDevicePreferenceFragment.KEY_DISCONNECT;
+import static com.google.android.tv.btservices.settings.BluetoothDevicePreferenceFragment.KEY_BLE_INFO;
 import static com.google.android.tv.btservices.settings.BluetoothDevicePreferenceFragment.KEY_FORGET;
 import static com.google.android.tv.btservices.settings.BluetoothDevicePreferenceFragment.KEY_RENAME;
 import static com.google.android.tv.btservices.settings.BluetoothDevicePreferenceFragment.KEY_UPDATE;
@@ -63,6 +64,7 @@ import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
 import android.content.ServiceConnection;
+import android.content.pm.ProviderInfo;
 import android.content.pm.ResolveInfo;
 import android.net.Uri;
 import android.os.Bundle;
@@ -126,6 +128,8 @@ public class ConnectedDevicesSliceProvider extends SliceProvider implements
     static final String KEY_BACKLIGHT_RADIO_GROUP = "backlight_radio_group";
     static final String KEY_TOGGLE_ACTIVE_AUDIO_OUTPUT = "toggle_active_audio_output";
 
+    private static final String KEY_EXTERNAL_SPEAKER = "external_speaker";
+
     private static final String SCHEME_CONTENT = "content://";
     private final Handler mHandler = new Handler(Looper.getMainLooper());
 
@@ -332,6 +336,7 @@ public class ConnectedDevicesSliceProvider extends SliceProvider implements
         //       of inactiveAccessories and bondedAccessories.
         Set<String> activeOfficialRemotes = new HashSet<>();
         Set<String> inactiveOfficialRemotes = new HashSet<>();
+        boolean hasActiveDevices = false;
 
         // Bucketing all BT devices
         for (BluetoothDevice device : getBluetoothDevices()) {
@@ -372,8 +377,12 @@ public class ConnectedDevicesSliceProvider extends SliceProvider implements
             createAndAddBtDeviceSlicePreferenceFromSet(psb, activeAccessories, addressToDevice);
             createAndAddBtDeviceSlicePreferenceFromSet(psb, inactiveAccessories, addressToDevice);
             createAndAddBtDeviceSlicePreferenceFromSet(psb, bondedAccessories, addressToDevice);
+            hasActiveDevices = true;
         }
 
+        // Add a section for external speakers.
+        updateExternalSpeakerSlice(psb);
+
         // "Official remote" category
         if (activeOfficialRemotes.size() + inactiveOfficialRemotes.size() > 0) {
             psb.addPreferenceCategory(new RowBuilder()
@@ -382,13 +391,17 @@ public class ConnectedDevicesSliceProvider extends SliceProvider implements
             createAndAddBtDeviceSlicePreferenceFromSet(psb, activeOfficialRemotes, addressToDevice);
             createAndAddBtDeviceSlicePreferenceFromSet(
                     psb, inactiveOfficialRemotes, addressToDevice);
+            hasActiveDevices = true;
         }
 
         // Adding the remote buttons settings at the bottom
         updateAxelSlice(psb);
         updateCustomSlice(psb);
-        updateFindMyRemoteSlice(psb);
-        updateBacklight(psb);
+
+        if (hasActiveDevices) {
+            updateFindMyRemoteSlice(psb);
+            updateBacklight(psb);
+        }
     }
 
     private void updateDeviceControlSlice(PreferenceSliceBuilder psb) {
@@ -404,6 +417,29 @@ public class ConnectedDevicesSliceProvider extends SliceProvider implements
         updateCecSettings(psb);
     }
 
+    private void updateExternalSpeakerSlice(PreferenceSliceBuilder psb) {
+        String uri = getString(R.string.external_speaker_slice_provider_uri);
+        if (TextUtils.isEmpty(uri)) {
+            return;
+        }
+
+        ProviderInfo provider =
+                getContext()
+                        .getPackageManager()
+                        .resolveContentProvider(Uri.parse(uri).getAuthority(), 0);
+        if (provider == null) {
+            return;
+        }
+
+        String category = getString(R.string.external_speaker_category);
+        if (TextUtils.isEmpty(category)) {
+            return;
+        }
+
+        psb.addPreferenceCategory(new RowBuilder().setTitle(category).setKey(KEY_EXTERNAL_SPEAKER));
+        psb.addEmbeddedPreference(new RowBuilder().setTargetSliceUri(uri));
+    }
+
     private void updateAxelSlice(PreferenceSliceBuilder psb) {
         if (!ConnectedDevicesPreferenceFragment.isAxelSettingsEnabled(getContext())) {
             return;
@@ -710,6 +746,7 @@ public class ConnectedDevicesSliceProvider extends SliceProvider implements
 
         // Update "bluetooth device info preference".
         RowBuilder infoPref = new RowBuilder()
+                .setKey("KEY_BLE_INFO")
                 .setIcon(IconCompat.createWithResource(context, R.drawable.ic_baseline_info_24dp));
 
         int battery = btDeviceProvider.getBatteryLevel(device);
diff --git a/libraries/BluetoothServices/src/com/google/android/tv/btservices/syncwork/RemoteSyncWorkManager.java b/libraries/BluetoothServices/src/com/google/android/tv/btservices/syncwork/RemoteSyncWorkManager.java
index f8093a4..52e1cb6 100644
--- a/libraries/BluetoothServices/src/com/google/android/tv/btservices/syncwork/RemoteSyncWorkManager.java
+++ b/libraries/BluetoothServices/src/com/google/android/tv/btservices/syncwork/RemoteSyncWorkManager.java
@@ -41,13 +41,16 @@ public class RemoteSyncWorkManager {
         // Typically WorkManager is initialized as part of app start up. It is possible for
         // apps to disable that for customized configuration, so to be safe we should
         // attempt to initialize it here as well.
-        try {
-            WorkManager.initialize(context.getApplicationContext(),
-                    new Configuration.Builder().build());
-        } catch (IllegalStateException ex) {
-            // The call to initialize can fail in normal scenarios when WorkManager is already
-            // initialized.
-        }
+        if (!WorkManager.isInitialized()) {
+            try {
+                WorkManager.initialize(context.getApplicationContext(),
+                        new Configuration.Builder().build());
+            } catch (IllegalStateException ex) {
+                // The call to initialize can fail in normal scenarios when WorkManager is already
+                // initialized.
+                Log.d(TAG, "IllegalStateException:" + ex);
+            }
+         }
         return WorkManager.getInstance(context.getApplicationContext());
     }
 
diff --git a/overlay/TvFrameworkOverlay/res/values-iw/strings.xml b/overlay/TvFrameworkOverlay/res/values-iw/strings.xml
index b5a0203..85c7405 100644
--- a/overlay/TvFrameworkOverlay/res/values-iw/strings.xml
+++ b/overlay/TvFrameworkOverlay/res/values-iw/strings.xml
@@ -16,12 +16,12 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="accessibility_shortcut_multiple_service_warning" msgid="7133244216041378936">"לחצת לחיצה ארוכה למשך שלוש שניות על הלחצן \'הקודם\' ועל לחצן החץ למטה כדי להשתמש ב-<xliff:g id="SERVICE_0">%1$s</xliff:g>.\n\n כדי להפעיל את <xliff:g id="SERVICE_1">%1$s</xliff:g> עכשיו, יש ללחוץ שוב לחיצה ארוכה על הלחצן \'הקודם\' ועל לחצן החץ למטה למשך שלוש שניות. אפשר להשתמש במקש הקיצור בכל שלב כדי להפעיל את <xliff:g id="SERVICE_2">%1$s</xliff:g> או להשבית אותו.\n\n ניתן לשנות את ההעדפות בהגדרות &gt; מערכת &gt; נגישות."</string>
-    <string name="accessibility_shortcut_toogle_warning" msgid="6107141001991769734">"כשקיצור הדרך מופעל, לחיצה על הלחצן \'הקודם\' ועל החץ למטה בו זמנית למשך 3 שניות תפעיל תכונת נגישות.\n\n תכונת הנגישות המוגדרת כרגע:\n <xliff:g id="SERVICE_NAME">%1$s</xliff:g>\n\n ניתן לבחור תכונה אחרת בקטע \'הגדרות\' &gt; \'נגישות\'."</string>
-    <string name="accessibility_shortcut_enabling_service" msgid="955379455142747901">"לחיצה ארוכה התבצעה על הלחצן \'הקודם\' ועל לחצן החץ למטה. <xliff:g id="SERVICE_NAME">%1$s</xliff:g> הופעל."</string>
-    <string name="accessibility_shortcut_disabling_service" msgid="1407311966343470931">"לחיצה ארוכה התבצעה על הלחצן \'הקודם\' ועל לחצן החץ למטה. <xliff:g id="SERVICE_NAME">%1$s</xliff:g> הושבת."</string>
-    <string name="accessibility_shortcut_spoken_feedback" msgid="7263788823743141556">"לחצת לחיצה ארוכה למשך שלוש שניות על הלחצן \'הקודם\' ועל לחצן החץ למטה כדי להשתמש ב-<xliff:g id="SERVICE_0">%1$s</xliff:g>. כדי להפעיל את <xliff:g id="SERVICE_1">%1$s</xliff:g> עכשיו, יש ללחוץ לחיצה ארוכה למשך שלוש שניות על הלחצן \'הקודם\'. אפשר להשתמש במקש הקיצור בכל שלב כדי להפעיל את <xliff:g id="SERVICE_2">%1$s</xliff:g> או להשבית אותו."</string>
-    <string name="accessibility_shortcut_single_service_warning" msgid="7941823324711523679">"לחצת לחיצה ארוכה למשך שלוש שניות על הלחצן \'הקודם\' ועל לחצן החץ למטה כדי להשתמש ב-<xliff:g id="SERVICE_0">%1$s</xliff:g>.\n\n כדי להפעיל את <xliff:g id="SERVICE_1">%1$s</xliff:g> עכשיו, יש ללחוץ שוב לחיצה ארוכה על הלחצן \'הקודם\' ועל לחצן החץ למטה למשך שלוש שניות.\n אפשר להשתמש במקש הקיצור בכל שלב כדי להפעיל את <xliff:g id="SERVICE_2">%1$s</xliff:g> או כדי להשבית אותו.\n\n ניתן לשנות את ההעדפות בהגדרות &gt; מערכת &gt; נגישות."</string>
+    <string name="accessibility_shortcut_multiple_service_warning" msgid="7133244216041378936">"לחצת לחיצה ארוכה למשך שלוש שניות על הכפתור \"הקודם\" ועל כפתור החץ למטה כדי להשתמש ב-<xliff:g id="SERVICE_0">%1$s</xliff:g>.\n\n כדי להפעיל את <xliff:g id="SERVICE_1">%1$s</xliff:g> עכשיו, יש ללחוץ שוב לחיצה ארוכה על הכפתור \"הקודם\" ועל כפתור החץ למטה למשך שלוש שניות. אפשר להשתמש במקש הקיצור בכל שלב כדי להפעיל את <xliff:g id="SERVICE_2">%1$s</xliff:g> או להשבית אותו.\n\n ניתן לשנות את ההעדפות בהגדרות &gt; מערכת &gt; נגישות."</string>
+    <string name="accessibility_shortcut_toogle_warning" msgid="6107141001991769734">"כשקיצור הדרך מופעל, לחיצה על הכפתור \"הקודם\" ועל החץ למטה בו זמנית למשך 3 שניות תפעיל תכונת נגישות.\n\n תכונת הנגישות המוגדרת כרגע:\n <xliff:g id="SERVICE_NAME">%1$s</xliff:g>\n\n ניתן לבחור תכונה אחרת בקטע \"הגדרות\" &gt; \"נגישות\"."</string>
+    <string name="accessibility_shortcut_enabling_service" msgid="955379455142747901">"לחיצה ארוכה התבצעה על הכפתור \"הקודם\" ועל כפתור החץ למטה. <xliff:g id="SERVICE_NAME">%1$s</xliff:g> הופעל."</string>
+    <string name="accessibility_shortcut_disabling_service" msgid="1407311966343470931">"לחיצה ארוכה התבצעה על הכפתור \"הקודם\" ועל כפתור החץ למטה. <xliff:g id="SERVICE_NAME">%1$s</xliff:g> הושבת."</string>
+    <string name="accessibility_shortcut_spoken_feedback" msgid="7263788823743141556">"לחצת לחיצה ארוכה למשך שלוש שניות על הכפתור \"הקודם\" ועל כפתור החץ למטה כדי להשתמש ב-<xliff:g id="SERVICE_0">%1$s</xliff:g>. כדי להפעיל את <xliff:g id="SERVICE_1">%1$s</xliff:g> עכשיו, יש ללחוץ לחיצה ארוכה למשך שלוש שניות על הכפתור \"הקודם\". אפשר להשתמש במקש הקיצור בכל שלב כדי להפעיל את <xliff:g id="SERVICE_2">%1$s</xliff:g> או להשבית אותו."</string>
+    <string name="accessibility_shortcut_single_service_warning" msgid="7941823324711523679">"לחצת לחיצה ארוכה למשך שלוש שניות על הכפתור \"הקודם\" ועל כפתור החץ למטה כדי להשתמש ב-<xliff:g id="SERVICE_0">%1$s</xliff:g>.\n\n כדי להפעיל את <xliff:g id="SERVICE_1">%1$s</xliff:g> עכשיו, יש ללחוץ שוב לחיצה ארוכה על הכפתור \"הקודם\" ועל כפתור החץ למטה למשך שלוש שניות.\n אפשר להשתמש במקש הקיצור בכל שלב כדי להפעיל את <xliff:g id="SERVICE_2">%1$s</xliff:g> או כדי להשבית אותו.\n\n ניתן לשנות את ההעדפות בהגדרות &gt; מערכת &gt; נגישות."</string>
     <string name="disable_accessibility_shortcut" msgid="4559312586447750126">"לא עכשיו"</string>
     <string name="leave_accessibility_shortcut_on" msgid="6807632291651241490">"הפעלה עכשיו"</string>
 </resources>
diff --git a/overlay/TvFrameworkOverlay/res/values-mr/strings.xml b/overlay/TvFrameworkOverlay/res/values-mr/strings.xml
index 6f9cfda..c435f54 100644
--- a/overlay/TvFrameworkOverlay/res/values-mr/strings.xml
+++ b/overlay/TvFrameworkOverlay/res/values-mr/strings.xml
@@ -16,12 +16,12 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="accessibility_shortcut_multiple_service_warning" msgid="7133244216041378936">"तुम्ही <xliff:g id="SERVICE_0">%1$s</xliff:g> वापरण्यासाठी मागे जा आणि खाली जा ही दोन्ही बटण तीन सेकंदांसाठी धरून ठेवली होती.\n\n आता <xliff:g id="SERVICE_1">%1$s</xliff:g> सुरू करण्यासाठी, मागे जा आणि खाली जा ही बटण तीन सेकंद धरून ठेवा. <xliff:g id="SERVICE_2">%1$s</xliff:g> सुरू किंवा बंद करण्यासाठी हा शॉर्टकट कधीही वापरा.\n\n तुम्ही सेटिंग्ज &lt; सिस्टम &gt; अ‍ॅक्सेसिबिलिटी मध्ये तुमची प्राधान्ये अ‍ॅडजस्ट करू शकता.."</string>
+    <string name="accessibility_shortcut_multiple_service_warning" msgid="7133244216041378936">"तुम्ही <xliff:g id="SERVICE_0">%1$s</xliff:g> वापरण्यासाठी बॅक आणि डाउन ही दोन्ही बटणे तीन सेकंदांसाठी धरून ठेवली होती.\n\n आता <xliff:g id="SERVICE_1">%1$s</xliff:g>  सुरू करण्यासाठी, बॅक आणि डाउन ही बटणे तीन सेकंद धरून ठेवा.<xliff:g id="SERVICE_2">%1$s</xliff:g> \n  सुरू किंवा बंद करण्यासाठी हा शॉर्टकट कधीही वापरा.\n तुम्ही तुमची प्राधान्ये सेटिंग्ज &gt; सिस्टीम &gt; अ‍ॅक्सेसिबिलिटी मध्ये तुमची प्राधान्ये अ‍ॅडजस्ट करू शकता."</string>
     <string name="accessibility_shortcut_toogle_warning" msgid="6107141001991769734">"शॉर्टकट सुरू असतो तेव्हा, मागे जा आणि खाली जा ही दोन्ही बटण तीन सेकंदांसाठी प्रेस करून ठेवल्यामुळे अ‍ॅक्सेसिबिलिटी वैशिष्ट्य सुरू होईल.\n\n सध्याचे अ‍ॅक्सेसिबिलिटी वैशिष्ट्य:\n <xliff:g id="SERVICE_NAME">%1$s</xliff:g>\n\n तुम्ही हे वैशिष्ट्य सेटिंग्ज &gt; अ‍ॅक्सेसिबिलिटी मध्ये बदलू शकता."</string>
     <string name="accessibility_shortcut_enabling_service" msgid="955379455142747901">"मागे जा आणि खाली जा ही बटण धरून ठेवा. <xliff:g id="SERVICE_NAME">%1$s</xliff:g> सुरू केले."</string>
     <string name="accessibility_shortcut_disabling_service" msgid="1407311966343470931">"मागे जा आणि खाली जा ही बटण धरून ठेवा. <xliff:g id="SERVICE_NAME">%1$s</xliff:g> बंद केले."</string>
     <string name="accessibility_shortcut_spoken_feedback" msgid="7263788823743141556">"तुम्ही <xliff:g id="SERVICE_0">%1$s</xliff:g> वापरण्यासाठी मागे जा आणि खाली जा ही दोन्ही बटण तीन सेकंदांसाठी धरून ठेवली होती. <xliff:g id="SERVICE_1">%1$s</xliff:g> आता सुरू करण्यासाठी, मागे जा आणि खाली जा बटण तीन सेकंद धरून ठेवा. <xliff:g id="SERVICE_2">%1$s</xliff:g> सुरू किंवा बंद करण्यासाठी हा शॉर्टकट कधीही वापरा."</string>
-    <string name="accessibility_shortcut_single_service_warning" msgid="7941823324711523679">"तुम्ही <xliff:g id="SERVICE_0">%1$s</xliff:g> वापरण्यासाठी मागे जा आणि खाली जा ही दोन्ही बटण तीन सेकंदांसाठी धरून ठेवली होती.\n\n आता <xliff:g id="SERVICE_1">%1$s</xliff:g> सुरू करण्यासाठी, मागे जा आणि खाली जा ही बटण तीन सेकंद धरून ठेवा.\n <xliff:g id="SERVICE_2">%1$s</xliff:g> सुरू किंवा बंद करण्यासाठी हा शॉर्टकट कधीही वापरा.\n\n तुम्ही तुमची प्राधान्ये सेटिंग्ज &lt; सिस्टम &gt; अ‍ॅक्सेसिबिलिटी मध्ये अ‍ॅडजस्ट करू शकता."</string>
+    <string name="accessibility_shortcut_single_service_warning" msgid="7941823324711523679">"तुम्ही <xliff:g id="SERVICE_0">%1$s</xliff:g> वापरण्यासाठी मागे जा आणि खाली जा ही दोन्ही बटणे तीन सेकंदांसाठी धरून ठेवली होती.\n\n आता <xliff:g id="SERVICE_1">%1$s</xliff:g> सुरू किंवा बंद करण्यासाठी हा शॉर्टकट कधीही वापरा.\n <xliff:g id="SERVICE_2">%1$s</xliff:g> सुरू किंवा बंद करण्यासाठी हा शॉर्टकट कधीही वापरा.\n\n तुम्ही सेटिंग्ज &gt; सिस्टीम &gt; अ‍ॅक्सेसिबिलिटी मध्ये तुमची प्राधान्ये अ‍ॅडजस्ट करू शकता."</string>
     <string name="disable_accessibility_shortcut" msgid="4559312586447750126">"आता नको"</string>
     <string name="leave_accessibility_shortcut_on" msgid="6807632291651241490">"आता सुरू करा"</string>
 </resources>
diff --git a/overlay/TvFrameworkOverlay/res/values-nl/strings.xml b/overlay/TvFrameworkOverlay/res/values-nl/strings.xml
index e4c84b8..fbb1afe 100644
--- a/overlay/TvFrameworkOverlay/res/values-nl/strings.xml
+++ b/overlay/TvFrameworkOverlay/res/values-nl/strings.xml
@@ -18,8 +18,8 @@
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
     <string name="accessibility_shortcut_multiple_service_warning" msgid="7133244216041378936">"Je hebt de knoppen voor terug en omlaag 3 seconden ingedrukt gehouden om <xliff:g id="SERVICE_0">%1$s</xliff:g> te gebruiken.\n\n Als je <xliff:g id="SERVICE_1">%1$s</xliff:g> nu wilt aanzetten, houd je de knoppen voor terug en omlaag weer 3 seconden ingedrukt. Gebruik deze sneltoets wanneer je wilt om <xliff:g id="SERVICE_2">%1$s</xliff:g> aan of uit te zetten.\n\n Je kunt je voorkeuren aanpassen via Instellingen &gt; Systeem &gt; Toegankelijkheid."</string>
     <string name="accessibility_shortcut_toogle_warning" msgid="6107141001991769734">"Wanneer de sneltoets aanstaat, kun je een toegankelijkheidsfunctie starten door 3 seconden op de knop Terug en de knop Omlaag te drukken.\n\n Huidige toegankelijkheidsfunctie:\n <xliff:g id="SERVICE_NAME">%1$s</xliff:g>\n\n Je kunt de functie wijzigen via Instellingen &gt; Toegankelijkheid."</string>
-    <string name="accessibility_shortcut_enabling_service" msgid="955379455142747901">"Toetsen voor terug en omlaag ingedrukt gehouden. <xliff:g id="SERVICE_NAME">%1$s</xliff:g> is aangezet."</string>
-    <string name="accessibility_shortcut_disabling_service" msgid="1407311966343470931">"Toetsen voor terug en omlaag ingedrukt gehouden. <xliff:g id="SERVICE_NAME">%1$s</xliff:g> is uitgezet."</string>
+    <string name="accessibility_shortcut_enabling_service" msgid="955379455142747901">"Knoppen voor terug en omlaag ingedrukt gehouden. <xliff:g id="SERVICE_NAME">%1$s</xliff:g> is aangezet."</string>
+    <string name="accessibility_shortcut_disabling_service" msgid="1407311966343470931">"Knoppen voor terug en omlaag ingedrukt gehouden. <xliff:g id="SERVICE_NAME">%1$s</xliff:g> is uitgezet."</string>
     <string name="accessibility_shortcut_spoken_feedback" msgid="7263788823743141556">"Je hebt de knoppen voor terug en omlaag 3 seconden ingedrukt gehouden om <xliff:g id="SERVICE_0">%1$s</xliff:g> te gebruiken. Als je <xliff:g id="SERVICE_1">%1$s</xliff:g> nu wilt aanzetten, houd je de knoppen voor terug en omlaag weer 3 seconden ingedrukt. Gebruik deze sneltoets wanneer je wilt om <xliff:g id="SERVICE_2">%1$s</xliff:g> aan of uit te zetten."</string>
     <string name="accessibility_shortcut_single_service_warning" msgid="7941823324711523679">"Je hebt de knoppen voor terug en omlaag 3 seconden ingedrukt gehouden om <xliff:g id="SERVICE_0">%1$s</xliff:g> te gebruiken.\n\n Als je <xliff:g id="SERVICE_1">%1$s</xliff:g> nu wilt aanzetten, houd je de knoppen voor terug en omlaag weer 3 seconden ingedrukt.\n Gebruik deze sneltoets wanneer je wilt om <xliff:g id="SERVICE_2">%1$s</xliff:g> aan of uit te zetten.\n\n Je kunt je voorkeuren aanpassen via Instellingen &gt; Systeem &gt; Toegankelijkheid."</string>
     <string name="disable_accessibility_shortcut" msgid="4559312586447750126">"Niet nu"</string>
diff --git a/products/atv_emulator_vendor.mk b/products/atv_emulator_vendor.mk
index ea3c8a5..5e549c8 100644
--- a/products/atv_emulator_vendor.mk
+++ b/products/atv_emulator_vendor.mk
@@ -55,7 +55,7 @@ PRODUCT_COPY_FILES += \
     device/generic/goldfish/data/etc/advancedFeatures.ini:advancedFeatures.ini
 
 PRODUCT_COPY_FILES += \
-    device/generic/goldfish/camera/media/media_codecs_google_tv.xml:${TARGET_COPY_OUT_VENDOR}/etc/media_codecs_google_tv.xml \
+    device/generic/goldfish/codecs/media/media_codecs_google_tv.xml:${TARGET_COPY_OUT_VENDOR}/etc/media_codecs_google_tv.xml \
     frameworks/native/data/etc/android.hardware.ethernet.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.ethernet.xml \
     hardware/libhardware_legacy/audio/audio_policy.conf:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy.conf
 
diff --git a/products/atv_lowram_defaults.mk b/products/atv_lowram_defaults.mk
index 522cbf2..13a81c0 100644
--- a/products/atv_lowram_defaults.mk
+++ b/products/atv_lowram_defaults.mk
@@ -56,8 +56,19 @@ ifeq (,$(filter eng, $(TARGET_BUILD_VARIANT)))
   MALLOC_SVELTE := true
 endif
 
+# Enable Madvising of the art, odex and vdex files to MADV_WILLNEED.
+# The size specified here is the size limit of how much of the file
+# (in bytes) is madvised.
+# We madvise 0MB of .art file.
+# For odex and vdex files, we limit madvising to 30MB (down from the default of
+# 100MB) to alleviate pagecache pressure.
+PRODUCT_PROPERTY_OVERRIDES += \
+    dalvik.vm.madvise.vdexfile.size=31457280\
+    dalvik.vm.madvise.odexfile.size=31457280\
+    dalvik.vm.madvise.artfile.size=0
+
 # Overlay for lowram
 PRODUCT_PACKAGES += TvLowRamOverlay
 
 # Disable camera by default
-PRODUCT_SUPPORTS_CAMERA ?= false
+PRODUCT_SUPPORTS_CAMERA ?= false
\ No newline at end of file
diff --git a/products/atv_product.mk b/products/atv_product.mk
index a7bacc5..9078a2d 100644
--- a/products/atv_product.mk
+++ b/products/atv_product.mk
@@ -40,7 +40,7 @@ PRODUCT_COPY_FILES += \
 PRODUCT_PRODUCT_PROPERTIES += \
     tombstoned.max_tombstone_count?=10
 
-# Limit persistent logs to 60MB
+# Limit persistent logs to 10MB
 PRODUCT_PRODUCT_PROPERTIES += \
-    logd.logpersistd.size=30 \
+    logd.logpersistd.size=5 \
     logd.logpersistd.rotate_kbytes=2048
diff --git a/products/atv_system.mk b/products/atv_system.mk
index 3ffafcb..64252c7 100644
--- a/products/atv_system.mk
+++ b/products/atv_system.mk
@@ -122,4 +122,4 @@ PRODUCT_COPY_FILES += \
 
 PRODUCT_PACKAGES += framework-audio_effects.xml
 
-$(call soong_config_set,system_services,without_vibrator,true)
+$(call soong_config_set,system_services,without_hal,vibrator)
```

