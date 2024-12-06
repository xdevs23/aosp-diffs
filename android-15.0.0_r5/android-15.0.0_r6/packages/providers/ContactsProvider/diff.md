```diff
diff --git a/Android.bp b/Android.bp
index 945b32c4..17f5d8e5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -12,11 +12,12 @@ android_app {
         "src/com/android/providers/contacts/EventLogTags.logtags",
     ],
     libs: [
-        "ext"
+        "ext",
     ],
     static_libs: [
         "android-common",
         "com.android.vcard",
+        "contactsprovider_flags_java_lib",
         "guava",
         "android.content.pm.flags-aconfig-java",
     ],
@@ -41,3 +42,15 @@ platform_compat_config {
     name: "contacts-provider-platform-compat-config",
     src: ":ContactsProvider",
 }
+
+aconfig_declarations {
+    name: "contactsprovider_flags",
+    package: "com.android.providers.contacts.flags",
+    container: "system",
+    srcs: ["contactsprovider_flags.aconfig"],
+}
+
+java_aconfig_library {
+    name: "contactsprovider_flags_java_lib",
+    aconfig_declarations: "contactsprovider_flags",
+}
diff --git a/OWNERS b/OWNERS
index 5dff6c52..b244519c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
+aibra@google.com
 omakoto@google.com
 yamasani@google.com
 
diff --git a/contactsprovider_flags.aconfig b/contactsprovider_flags.aconfig
new file mode 100644
index 00000000..7eee666a
--- /dev/null
+++ b/contactsprovider_flags.aconfig
@@ -0,0 +1,27 @@
+package: "com.android.providers.contacts.flags"
+container: "system"
+
+flag {
+    name: "cp2_account_move_flag"
+    namespace: "contacts"
+    description: "Methods for bulk move of contacts between accounts"
+    bug: "330324156"
+}
+flag {
+    name: "cp2_account_move_sync_stub_flag"
+    namespace: "contacts"
+    description: "Methods for writing sync stubs during bulk move of contacts between accounts"
+    bug: "330324156"
+}
+flag {
+    name: "enable_new_default_account_rule_flag"
+    namespace: "contacts"
+    description: "Enable new default account for contacts"
+    bug: "337979000"
+}
+flag {
+    name: "cp2_sync_search_index_flag"
+    namespace: "contacts"
+    description: "Refactor to update search index during account removal and contact aggregation"
+    bug: "363260703"
+}
diff --git a/res/values-af/arrays.xml b/res/values-af/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-af/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-am/arrays.xml b/res/values-am/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-am/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-ar/arrays.xml b/res/values-ar/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-ar/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-as/arrays.xml b/res/values-as/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-as/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-az/arrays.xml b/res/values-az/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-az/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-b+sr+Latn/arrays.xml b/res/values-b+sr+Latn/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-b+sr+Latn/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-be/arrays.xml b/res/values-be/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-be/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-bg/arrays.xml b/res/values-bg/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-bg/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-bn/arrays.xml b/res/values-bn/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-bn/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-bs/arrays.xml b/res/values-bs/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-bs/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-ca/arrays.xml b/res/values-ca/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-ca/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-cs/arrays.xml b/res/values-cs/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-cs/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-da/arrays.xml b/res/values-da/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-da/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-de/arrays.xml b/res/values-de/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-de/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-el/arrays.xml b/res/values-el/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-el/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-en-rAU/arrays.xml b/res/values-en-rAU/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-en-rAU/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-en-rCA/arrays.xml b/res/values-en-rCA/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-en-rCA/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-en-rGB/arrays.xml b/res/values-en-rGB/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-en-rGB/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-en-rIN/arrays.xml b/res/values-en-rIN/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-en-rIN/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-en-rXC/arrays.xml b/res/values-en-rXC/arrays.xml
new file mode 100644
index 00000000..9df5737d
--- /dev/null
+++ b/res/values-en-rXC/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‎‏‎‎‏‏‏‏‏‏‏‏‏‏‎‎‎‏‎‏‏‏‏‎‏‎‎‏‎‎‎‏‎‎‏‎‏‏‎‎‎‏‎‏‎‎‏‎‎‎‏‎‎‎‎‏‏‏‎‎‏‏‎‎‎‎‎‏‎‏‏‏‎‏‎‎com.google‎‏‎‎‏‎"</item>
+  </string-array>
+</resources>
diff --git a/res/values-es-rUS/arrays.xml b/res/values-es-rUS/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-es-rUS/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-es/arrays.xml b/res/values-es/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-es/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-et/arrays.xml b/res/values-et/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-et/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-eu/arrays.xml b/res/values-eu/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-eu/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-fa/arrays.xml b/res/values-fa/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-fa/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-fi/arrays.xml b/res/values-fi/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-fi/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-fr-rCA/arrays.xml b/res/values-fr-rCA/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-fr-rCA/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-fr/arrays.xml b/res/values-fr/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-fr/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-gl/arrays.xml b/res/values-gl/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-gl/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-gu/arrays.xml b/res/values-gu/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-gu/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-hi/arrays.xml b/res/values-hi/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-hi/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-hr/arrays.xml b/res/values-hr/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-hr/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-hu/arrays.xml b/res/values-hu/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-hu/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-hy/arrays.xml b/res/values-hy/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-hy/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-in/arrays.xml b/res/values-in/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-in/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-is/arrays.xml b/res/values-is/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-is/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-it/arrays.xml b/res/values-it/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-it/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-iw/arrays.xml b/res/values-iw/arrays.xml
new file mode 100644
index 00000000..cd38f267
--- /dev/null
+++ b/res/values-iw/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"‎com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-ja/arrays.xml b/res/values-ja/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-ja/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-ka/arrays.xml b/res/values-ka/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-ka/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-kk/arrays.xml b/res/values-kk/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-kk/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-km/arrays.xml b/res/values-km/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-km/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-kn/arrays.xml b/res/values-kn/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-kn/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-ko/arrays.xml b/res/values-ko/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-ko/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-ky/arrays.xml b/res/values-ky/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-ky/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-lo/arrays.xml b/res/values-lo/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-lo/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-lt/arrays.xml b/res/values-lt/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-lt/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-lv/arrays.xml b/res/values-lv/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-lv/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-mk/arrays.xml b/res/values-mk/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-mk/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-ml/arrays.xml b/res/values-ml/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-ml/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-mn/arrays.xml b/res/values-mn/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-mn/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-mr/arrays.xml b/res/values-mr/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-mr/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-ms/arrays.xml b/res/values-ms/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-ms/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-my/arrays.xml b/res/values-my/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-my/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-nb/arrays.xml b/res/values-nb/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-nb/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-ne/arrays.xml b/res/values-ne/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-ne/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-nl/arrays.xml b/res/values-nl/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-nl/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-or/arrays.xml b/res/values-or/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-or/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index eda7b1f6..ab8efb16 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -25,8 +25,8 @@
     <string name="default_directory" msgid="93961630309570294">"ଯୋଗାଯୋଗ"</string>
     <string name="local_invisible_directory" msgid="705244318477396120">"ଅନ୍ଯ"</string>
     <string name="voicemail_from_column" msgid="435732568832121444">"ଏହାଙ୍କଠାରୁ ଭଏସମେଲ୍‌ "</string>
-    <string name="debug_dump_title" msgid="4916885724165570279">"ଯୋଗାଯୋଗ ଡାଟାବେସ୍ କପୀ କରନ୍ତୁ"</string>
-    <string name="debug_dump_database_message" msgid="406438635002392290">"ଆପଣ 1) ଇଣ୍ଟର୍ନଲ ଷ୍ଟୋରେଜରେ ନିଜ ଡାଟାବେସ୍‌ର ଏକ କପୀ ବନାନ୍ତୁ, ଯେଉଁଥିରେ ଯୋଗାଯୋଗ ସମ୍ବନ୍ଧିତ ସମସ୍ତ ତଥ୍ୟ ଏବଂ କଲ୍ ଲଗ୍ ସାମିଲ ରହିବ ଏବଂ 2) ଏହାକୁ ଇମେଲ୍ କରନ୍ତୁ। ମନେରଖନ୍ତୁ, ଡିଭାଇସ୍‌ରୁ ସଫଳତାପୂର୍ବକ ଏହାର କପୀ କରିସାରିବା ପରେ କିମ୍ୱା ଇମେଲ୍ ପ୍ରାପ୍ତ ହୋଇସାରିବା ପରେ, ଏହି କପୀକୁ ଡିଲିଟ୍ କରିଦେବେ।"</string>
+    <string name="debug_dump_title" msgid="4916885724165570279">"କଣ୍ଟାକ୍ଟ ଡାଟାବେସକୁ କପି କରନ୍ତୁ"</string>
+    <string name="debug_dump_database_message" msgid="406438635002392290">"ଆପଣ 1) ଇଣ୍ଟର୍ନଲ ଷ୍ଟୋରେଜରେ ନିଜ ଡାଟାବେସର ଏକ କପି ବନାନ୍ତୁ, ଯେଉଁଥିରେ କଣ୍ଟାକ୍ଟ ସମ୍ବନ୍ଧିତ ସମସ୍ତ ତଥ୍ୟ ଏବଂ କଲ ଲଗ ରହିବ, ଏବଂ 2) ଏହାକୁ ଇମେଲ କରନ୍ତୁ। ମନେରଖନ୍ତୁ, ଡିଭାଇସରୁ ସଫଳତାର ସହ ଏହାକୁ କପି କରିସାରିବା ପରେ କିମ୍ୱା ଇମେଲ ମିଳିବା ପରେ, ଏହି କପିକୁ ଡିଲିଟ କରିଦେବେ।"</string>
     <string name="debug_dump_delete_button" msgid="7832879421132026435">"ବର୍ତ୍ତମାନ ଡିଲିଟ୍ କରନ୍ତୁ"</string>
     <string name="debug_dump_start_button" msgid="2837506913757600001">"ଆରମ୍ଭ କରନ୍ତୁ"</string>
     <string name="debug_dump_email_sender_picker" msgid="3534420908672176460">"ନିଜ ଫାଇଲ ପଠାଇବା ପାଇଁ ଗୋଟିଏ ପ୍ରୋଗ୍ରାମ୍ ବାଛନ୍ତୁ"</string>
diff --git a/res/values-pa/arrays.xml b/res/values-pa/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-pa/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-pl/arrays.xml b/res/values-pl/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-pl/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-pt-rBR/arrays.xml b/res/values-pt-rBR/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-pt-rBR/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-pt-rPT/arrays.xml b/res/values-pt-rPT/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-pt-rPT/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-pt/arrays.xml b/res/values-pt/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-pt/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-ro/arrays.xml b/res/values-ro/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-ro/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-ru/arrays.xml b/res/values-ru/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-ru/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-si/arrays.xml b/res/values-si/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-si/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-sk/arrays.xml b/res/values-sk/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-sk/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-sl/arrays.xml b/res/values-sl/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-sl/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-sq/arrays.xml b/res/values-sq/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-sq/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-sr/arrays.xml b/res/values-sr/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-sr/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-sv/arrays.xml b/res/values-sv/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-sv/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-sw/arrays.xml b/res/values-sw/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-sw/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-ta/arrays.xml b/res/values-ta/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-ta/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-te/arrays.xml b/res/values-te/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-te/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-th/arrays.xml b/res/values-th/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-th/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-tl/arrays.xml b/res/values-tl/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-tl/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-tr/arrays.xml b/res/values-tr/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-tr/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-uk/arrays.xml b/res/values-uk/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-uk/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-ur/arrays.xml b/res/values-ur/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-ur/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-uz/arrays.xml b/res/values-uz/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-uz/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-vi/arrays.xml b/res/values-vi/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-vi/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-zh-rCN/arrays.xml b/res/values-zh-rCN/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-zh-rCN/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-zh-rHK/arrays.xml b/res/values-zh-rHK/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-zh-rHK/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-zh-rTW/arrays.xml b/res/values-zh-rTW/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-zh-rTW/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/res/values-zu/arrays.xml b/res/values-zu/arrays.xml
new file mode 100644
index 00000000..944e2035
--- /dev/null
+++ b/res/values-zu/arrays.xml
@@ -0,0 +1,7 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+  <string-array name="eligible_system_cloud_account_types">
+    <item msgid="7130475166467776698">"com.google"</item>
+  </string-array>
+</resources>
diff --git a/src/com/android/providers/contacts/AccountResolver.java b/src/com/android/providers/contacts/AccountResolver.java
new file mode 100644
index 00000000..5372cf06
--- /dev/null
+++ b/src/com/android/providers/contacts/AccountResolver.java
@@ -0,0 +1,242 @@
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
+package com.android.providers.contacts;
+
+import android.accounts.Account;
+import android.content.ContentValues;
+import android.net.Uri;
+import android.provider.ContactsContract.RawContacts;
+import android.provider.ContactsContract.SimAccount;
+import android.text.TextUtils;
+
+import com.android.providers.contacts.DefaultAccount.AccountCategory;
+
+import java.util.List;
+
+public class AccountResolver {
+    private static final String TAG = "AccountResolver";
+
+    private final ContactsDatabaseHelper mDbHelper;
+    private final DefaultAccountManager mDefaultAccountManager;
+
+    public AccountResolver(ContactsDatabaseHelper dbHelper,
+            DefaultAccountManager defaultAccountManager) {
+        mDbHelper = dbHelper;
+        mDefaultAccountManager = defaultAccountManager;
+    }
+
+    /**
+     * Resolves the account and builds an {@link AccountWithDataSet} based on the data set specified
+     * in the URI or values (if any).
+     * @param uri Current {@link Uri} being operated on.
+     * @param values {@link ContentValues} to read and possibly update.
+     * @param applyDefaultAccount Whether to look up default account during account resolution.
+     */
+    public AccountWithDataSet resolveAccountWithDataSet(Uri uri, ContentValues values,
+            boolean applyDefaultAccount) {
+        final Account[] accounts = resolveAccount(uri, values);
+        final Account account =  applyDefaultAccount
+                ? getAccountWithDefaultAccountApplied(uri, accounts)
+                : getFirstAccountOrNull(accounts);
+
+        AccountWithDataSet accountWithDataSet = null;
+        if (account != null) {
+            String dataSet = ContactsProvider2.getQueryParameter(uri, RawContacts.DATA_SET);
+            if (dataSet == null) {
+                dataSet = values.getAsString(RawContacts.DATA_SET);
+            } else {
+                values.put(RawContacts.DATA_SET, dataSet);
+            }
+            accountWithDataSet = AccountWithDataSet.get(account.name, account.type, dataSet);
+        }
+
+        return accountWithDataSet;
+    }
+
+    /**
+     * Resolves the account to be used, taking into consideration the default account settings.
+     *
+     * @param accounts 1-size array which contains specified account, or empty array if account is
+     *                not specified.
+     * @param uri The URI used for resolving accounts.
+     * @return The resolved account, or null if it's the default device (aka "NULL") account.
+     * @throws IllegalArgumentException If there's an issue with the account resolution due to
+     *  default account incompatible account types.
+     */
+    private Account getAccountWithDefaultAccountApplied(Uri uri, Account[] accounts)
+            throws IllegalArgumentException {
+        if (accounts.length == 0) {
+            DefaultAccount defaultAccount = mDefaultAccountManager.pullDefaultAccount();
+            if (defaultAccount.getAccountCategory() == AccountCategory.UNKNOWN) {
+                String exceptionMessage = mDbHelper.exceptionMessage(
+                        "Must specify ACCOUNT_NAME and ACCOUNT_TYPE",
+                        uri);
+                throw new IllegalArgumentException(exceptionMessage);
+            } else if (defaultAccount.getAccountCategory() == AccountCategory.DEVICE) {
+                return getLocalAccount();
+            } else {
+                return defaultAccount.getCloudAccount();
+            }
+        } else {
+            checkAccountIsWritableInternal(accounts[0]);
+            return accounts[0];
+        }
+    }
+
+    /**
+     * Checks if the specified account is writable.
+     *
+     * <p>This method verifies if contacts can be written to the given account based on the
+     * current default account settings. It throws an {@link IllegalArgumentException} if
+     * the account is not writable.</p>
+     *
+     * @param accountName The name of the account to check.
+     * @param accountType The type of the account to check.
+     *
+     * @throws IllegalArgumentException if either of the following conditions are met:
+     *     <ul>
+     *         <li>Only one of <code>accountName</code> or <code>accountType</code> is
+     *             specified.</li>
+     *         <li>The default account is set to cloud and the specified account is a local
+     *             (device or SIM) account.</li>
+     *     </ul>
+     */
+    public void checkAccountIsWritable(String accountName, String accountType) {
+        if (TextUtils.isEmpty(accountName) ^ TextUtils.isEmpty(accountType)) {
+            throw new IllegalArgumentException(
+                    "Must specify both or neither of ACCOUNT_NAME and ACCOUNT_TYPE");
+        }
+        if (TextUtils.isEmpty(accountName)) {
+            checkAccountIsWritableInternal(/*account=*/null);
+        } else {
+            checkAccountIsWritableInternal(new Account(accountName, accountType));
+        }
+    }
+
+    private void checkAccountIsWritableInternal(Account account)
+            throws IllegalArgumentException {
+        DefaultAccount defaultAccount = mDefaultAccountManager.pullDefaultAccount();
+
+        if (defaultAccount.getAccountCategory() == AccountCategory.CLOUD) {
+            if (isDeviceOrSimAccount(account)) {
+                throw new IllegalArgumentException("Cannot write contacts to local accounts "
+                        + "when default account is set to cloud");
+            }
+        }
+    }
+
+    private static Account getLocalAccount() {
+        if (TextUtils.isEmpty(AccountWithDataSet.LOCAL.getAccountName())) {
+            // AccountWithDataSet.LOCAL's getAccountType() must be null as well, thus we return
+            // the NULL account.
+            return null;
+        } else {
+            // AccountWithDataSet.LOCAL's getAccountType() must not be null as well, thus we return
+            // the customized local account.
+            return new Account(AccountWithDataSet.LOCAL.getAccountName(),
+                    AccountWithDataSet.LOCAL.getAccountType());
+        }
+    }
+
+    /**
+     * Gets the first account from the array, or null if the array is empty.
+     *
+     * @param accounts The array of accounts.
+     * @return The first account, or null if the array is empty.
+     */
+    private Account getFirstAccountOrNull(Account[] accounts) {
+        return accounts.length > 0 ? accounts[0] : null;
+    }
+
+
+    private boolean isDeviceOrSimAccount(Account account) {
+        AccountWithDataSet accountWithDataSet = account == null
+                ? new AccountWithDataSet(null, null, null)
+                : new AccountWithDataSet(account.name, account.type, null);
+
+        List<SimAccount> simAccounts = mDbHelper.getAllSimAccounts();
+        return accountWithDataSet.isLocalAccount() || accountWithDataSet.inSimAccounts(simAccounts);
+    }
+
+    /**
+     * If account is non-null then store it in the values. If the account is
+     * already specified in the values then it must be consistent with the
+     * account, if it is non-null.
+     *
+     * @param uri Current {@link Uri} being operated on.
+     * @param values {@link ContentValues} to read and possibly update.
+     * @return 1-size array which contains account specified by {@link Uri} and
+     *             {@link ContentValues}, or empty array if account is not specified.
+     * @throws IllegalArgumentException when only one of
+     *             {@link RawContacts#ACCOUNT_NAME} or
+     *             {@link RawContacts#ACCOUNT_TYPE} is specified, leaving the
+     *             other undefined.
+     * @throws IllegalArgumentException when {@link RawContacts#ACCOUNT_NAME}
+     *             and {@link RawContacts#ACCOUNT_TYPE} are inconsistent between
+     *             the given {@link Uri} and {@link ContentValues}.
+     */
+    private Account[] resolveAccount(Uri uri, ContentValues values)
+            throws IllegalArgumentException {
+        String accountName = ContactsProvider2.getQueryParameter(uri, RawContacts.ACCOUNT_NAME);
+        String accountType = ContactsProvider2.getQueryParameter(uri, RawContacts.ACCOUNT_TYPE);
+        final boolean partialUri = TextUtils.isEmpty(accountName) ^ TextUtils.isEmpty(accountType);
+
+        if (accountName == null && accountType == null
+                && !values.containsKey(RawContacts.ACCOUNT_NAME)
+                && !values.containsKey(RawContacts.ACCOUNT_TYPE)) {
+            // Account is not specified.
+            return new Account[0];
+        }
+
+        String valueAccountName = values.getAsString(RawContacts.ACCOUNT_NAME);
+        String valueAccountType = values.getAsString(RawContacts.ACCOUNT_TYPE);
+
+        final boolean partialValues = TextUtils.isEmpty(valueAccountName)
+                ^ TextUtils.isEmpty(valueAccountType);
+
+        if (partialUri || partialValues) {
+            // Throw when either account is incomplete.
+            throw new IllegalArgumentException(mDbHelper.exceptionMessage(
+                    "Must specify both or neither of ACCOUNT_NAME and ACCOUNT_TYPE", uri));
+        }
+
+        // Accounts are valid by only checking one parameter, since we've
+        // already ruled out partial accounts.
+        final boolean validUri = !TextUtils.isEmpty(accountName);
+        final boolean validValues = !TextUtils.isEmpty(valueAccountName);
+
+        if (validValues && validUri) {
+            // Check that accounts match when both present
+            final boolean accountMatch = TextUtils.equals(accountName, valueAccountName)
+                    && TextUtils.equals(accountType, valueAccountType);
+            if (!accountMatch) {
+                throw new IllegalArgumentException(mDbHelper.exceptionMessage(
+                        "When both specified, ACCOUNT_NAME and ACCOUNT_TYPE must match", uri));
+            }
+        } else if (validUri) {
+            // Fill values from the URI when not present.
+            values.put(RawContacts.ACCOUNT_NAME, accountName);
+            values.put(RawContacts.ACCOUNT_TYPE, accountType);
+        } else if (validValues) {
+            accountName = valueAccountName;
+            accountType = valueAccountType;
+        } else {
+            return new Account[]{null};
+        }
+
+        return new Account[]{new Account(accountName, accountType)};
+    }
+}
diff --git a/src/com/android/providers/contacts/CallComposerLocationProvider.java b/src/com/android/providers/contacts/CallComposerLocationProvider.java
index 568a1899..49a2a093 100644
--- a/src/com/android/providers/contacts/CallComposerLocationProvider.java
+++ b/src/com/android/providers/contacts/CallComposerLocationProvider.java
@@ -18,7 +18,6 @@ package com.android.providers.contacts;
 
 import static com.android.providers.contacts.util.DbQueryUtils.getEqualityClause;
 
-import android.Manifest;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.content.ContentProvider;
@@ -33,12 +32,13 @@ import android.database.sqlite.SQLiteQueryBuilder;
 import android.net.Uri;
 import android.os.Binder;
 import android.os.Process;
+import android.os.UserHandle;
 import android.provider.CallLog;
 import android.telecom.TelecomManager;
 import android.text.TextUtils;
 import android.util.Log;
 
-
+import com.android.internal.telephony.TelephonyPermissions;
 import com.android.providers.contacts.util.SelectionBuilder;
 
 import java.util.Objects;
@@ -173,7 +173,8 @@ public class CallComposerLocationProvider extends ContentProvider {
 
     private void enforceAccessRestrictions() {
         int uid = Binder.getCallingUid();
-        if (uid == Process.SYSTEM_UID || uid == Process.myUid() || uid == Process.PHONE_UID) {
+        if (TelephonyPermissions.isSystemOrPhone(uid)
+                || UserHandle.isSameApp(uid, Process.myUid())) {
             return;
         }
         String defaultDialerPackageName = getContext().getSystemService(TelecomManager.class)
diff --git a/src/com/android/providers/contacts/ContactMover.java b/src/com/android/providers/contacts/ContactMover.java
new file mode 100644
index 00000000..2ab7e8fe
--- /dev/null
+++ b/src/com/android/providers/contacts/ContactMover.java
@@ -0,0 +1,431 @@
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
+package com.android.providers.contacts;
+
+import static com.android.providers.contacts.flags.Flags.cp2AccountMoveFlag;
+import static com.android.providers.contacts.flags.Flags.cp2AccountMoveSyncStubFlag;
+
+import android.accounts.Account;
+import android.content.ContentUris;
+import android.content.ContentValues;
+import android.database.sqlite.SQLiteDatabase;
+import android.net.Uri;
+import android.provider.ContactsContract.CommonDataKinds;
+import android.provider.ContactsContract.Data;
+import android.provider.ContactsContract.Groups;
+import android.provider.ContactsContract.RawContacts;
+import android.text.TextUtils;
+import android.util.Log;
+import android.util.Pair;
+
+import com.android.providers.contacts.util.NeededForTesting;
+
+import java.util.HashMap;
+import java.util.Map;
+import java.util.Set;
+import java.util.stream.Collectors;
+
+/**
+ * A class to move {@link RawContacts} and {@link Groups} from one account to another.
+ */
+@NeededForTesting
+public class ContactMover {
+    private static final String TAG = "ContactMover";
+    private final ContactsDatabaseHelper mDbHelper;
+    private final ContactsProvider2 mCp2;
+    private final DefaultAccountManager mDefaultAccountManager;
+
+    @NeededForTesting
+    public ContactMover(ContactsProvider2 contactsProvider,
+            ContactsDatabaseHelper contactsDatabaseHelper,
+            DefaultAccountManager defaultAccountManager) {
+        mCp2 = contactsProvider;
+        mDbHelper = contactsDatabaseHelper;
+        mDefaultAccountManager = defaultAccountManager;
+    }
+
+    private void updateRawContactsAccount(
+            AccountWithDataSet destAccount, Set<Long> rawContactIds) {
+        if (rawContactIds.isEmpty()) {
+            return;
+        }
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, destAccount.getAccountName());
+        values.put(RawContacts.ACCOUNT_TYPE, destAccount.getAccountType());
+        values.put(RawContacts.DATA_SET, destAccount.getDataSet());
+        values.putNull(RawContacts.SOURCE_ID);
+        values.putNull(RawContacts.SYNC1);
+        values.putNull(RawContacts.SYNC2);
+        values.putNull(RawContacts.SYNC3);
+        values.putNull(RawContacts.SYNC4);
+
+        // actually update the account columns and break the source ID
+        mCp2.update(
+                RawContacts.CONTENT_URI,
+                values,
+                RawContacts._ID + " IN (" + TextUtils.join(",", rawContactIds) + ")",
+                new String[] {});
+    }
+
+    private void updateGroupAccount(
+            AccountWithDataSet destAccount, Set<Long> groupIds) {
+        if (groupIds.isEmpty()) {
+            return;
+        }
+        ContentValues values = new ContentValues();
+        values.put(Groups.ACCOUNT_NAME, destAccount.getAccountName());
+        values.put(Groups.ACCOUNT_TYPE, destAccount.getAccountType());
+        values.put(Groups.DATA_SET, destAccount.getDataSet());
+        values.putNull(Groups.SOURCE_ID);
+        values.putNull(Groups.SYNC1);
+        values.putNull(Groups.SYNC2);
+        values.putNull(Groups.SYNC3);
+        values.putNull(Groups.SYNC4);
+
+        // actually update the account columns and break the source ID
+        mCp2.update(
+                Groups.CONTENT_URI,
+                values,
+                Groups._ID + " IN (" + TextUtils.join(",", groupIds) + ")",
+                new String[] {});
+    }
+
+    private void updateGroupDataRows(Map<Long, Long> groupIdMap) {
+        // for each group in the groupIdMap, update all Group Membership data rows from key to value
+        for (Map.Entry<Long, Long> groupIds: groupIdMap.entrySet()) {
+            mDbHelper.updateGroupMemberships(groupIds.getKey(), groupIds.getValue());
+        }
+
+    }
+
+    private boolean isAccountTypeMatch(
+            AccountWithDataSet sourceAccount, AccountWithDataSet destAccount) {
+        if (sourceAccount.getAccountType() == null) {
+            return destAccount.getAccountType() == null;
+        }
+
+        return sourceAccount.getAccountType().equals(destAccount.getAccountType());
+    }
+
+    private boolean isDataSetMatch(
+            AccountWithDataSet sourceAccount, AccountWithDataSet destAccount) {
+        if (sourceAccount.getDataSet() == null) {
+            return destAccount.getDataSet() == null;
+        }
+
+        return sourceAccount.getDataSet().equals(destAccount.getDataSet());
+    }
+
+    private void moveNonSystemGroups(AccountWithDataSet sourceAccount,
+            AccountWithDataSet destAccount, boolean insertSyncStubs) {
+        Pair<Set<Long>, Map<Long, Long>> nonSystemGroups = mDbHelper
+                .deDuplicateGroups(sourceAccount, destAccount, /* isSystemGroupQuery= */ false);
+        Set<Long> nonSystemUniqueGroups = nonSystemGroups.first;
+        Map<Long, Long> nonSystemDuplicateGroupMap = nonSystemGroups.second;
+
+        // For non-system groups that are duplicated in source and dest:
+        // 1. update contact data rows (to point do the group in dest)
+        // 2. Set deleted = 1 for dupe groups in source
+        updateGroupDataRows(nonSystemDuplicateGroupMap);
+        for (Map.Entry<Long, Long> groupIds: nonSystemDuplicateGroupMap.entrySet()) {
+            mCp2.deleteGroup(Groups.CONTENT_URI, groupIds.getKey(), false);
+        }
+
+        // For non-system groups that only exist in source:
+        // 1. Write sync stubs for synced groups (if needed)
+        // 2. Update account ids
+        if (!sourceAccount.isLocalAccount() && insertSyncStubs) {
+            mDbHelper.insertGroupSyncStubs(sourceAccount, nonSystemUniqueGroups);
+        }
+        updateGroupAccount(destAccount, nonSystemUniqueGroups);
+    }
+
+    private void moveSystemGroups(
+            AccountWithDataSet sourceAccount, AccountWithDataSet destAccount) {
+        Pair<Set<Long>, Map<Long, Long>> systemGroups = mDbHelper
+                .deDuplicateGroups(sourceAccount, destAccount, /* isSystemGroupQuery= */ true);
+        Set<Long> systemUniqueGroups = systemGroups.first;
+        Map<Long, Long> systemDuplicateGroupMap = systemGroups.second;
+
+        // For system groups in source that have a match in dest:
+        // 1. Update contact data rows (can't delete the existing groups)
+        updateGroupDataRows(systemDuplicateGroupMap);
+
+        // For system groups that only exist in source:
+        // 1. Get content values for the relevant (non-empty) groups
+        // 2. Create a group in destination account (while building an ID map)
+        // 3. Update contact data rows to point at the new group(s)
+        Map<Long, ContentValues> oldIdToNewValues = mDbHelper
+                .getGroupContentValuesForMoveCopy(destAccount, systemUniqueGroups);
+        Map<Long, Long> systemGroupIdMap = new HashMap<>();
+        for (Map.Entry<Long, ContentValues> idToValues: oldIdToNewValues.entrySet()) {
+            Uri newGroupUri = mCp2.insert(Groups.CONTENT_URI, idToValues.getValue());
+            if (newGroupUri != null) {
+                Long newGroupId = ContentUris.parseId(newGroupUri);
+                systemGroupIdMap.put(idToValues.getKey(), newGroupId);
+            }
+        }
+        updateGroupDataRows(systemGroupIdMap);
+
+        // now delete membership data rows for any unique groups we skipped - otherwise the contacts
+        // will be left with data rows pointing to the skipped groups in the source account.
+        if (!oldIdToNewValues.isEmpty()) {
+            systemUniqueGroups.removeAll(oldIdToNewValues.keySet());
+        }
+        mCp2.delete(Data.CONTENT_URI,
+                CommonDataKinds.GroupMembership.GROUP_ROW_ID
+                        + " IN (" + TextUtils.join(",", systemUniqueGroups) + ")"
+                        + " AND " + Data.MIMETYPE + " = ?",
+                new String[] {CommonDataKinds.GroupMembership.CONTENT_ITEM_TYPE}
+        );
+    }
+
+    private void moveGroups(AccountWithDataSet sourceAccount, AccountWithDataSet destAccount,
+            boolean createSyncStubs) {
+        moveNonSystemGroups(sourceAccount, destAccount, createSyncStubs);
+        moveSystemGroups(sourceAccount, destAccount);
+    }
+
+    private Set<AccountWithDataSet> getLocalAccounts() {
+        AccountWithDataSet nullAccount = new AccountWithDataSet(
+                /* accountName= */ null, /* accountType= */ null, /* dataSet= */ null);
+        if (AccountWithDataSet.LOCAL.equals(nullAccount)) {
+            return Set.of(AccountWithDataSet.LOCAL);
+        }
+        return Set.of(
+                AccountWithDataSet.LOCAL,
+                nullAccount);
+    }
+
+    private Set<AccountWithDataSet> getSimAccounts() {
+        return mDbHelper.getAllSimAccounts().stream()
+                .map(simAccount ->
+                        new AccountWithDataSet(
+                                simAccount.getAccountName(), simAccount.getAccountType(), null))
+                .collect(Collectors.toSet());
+    }
+
+    /**
+     * Moves {@link RawContacts} and {@link Groups} from the local account(s) to the Cloud Default
+     * Account (if any).
+     */
+    // Keep it in proguard for testing: once it's used in production code, remove this annotation.
+    @NeededForTesting
+    void moveLocalToCloudDefaultAccount() {
+        if (!cp2AccountMoveFlag()) {
+            Log.w(TAG, "moveLocalToCloudDefaultAccount: flag disabled");
+            return;
+        }
+
+        // Check if there is a cloud default account set
+        // - if not, then we don't need to do anything
+        // - if there is, then that's our destAccount, get the AccountWithDataSet
+        Account account = mDefaultAccountManager.pullDefaultAccount().getCloudAccount();
+        if (account == null) {
+            Log.w(TAG, "moveToDefaultCloudAccount with no default cloud account set");
+            return;
+        }
+        AccountWithDataSet destAccount = new AccountWithDataSet(
+                account.name, account.type, /* dataSet= */ null);
+
+        // Move any contacts from the local account to the destination account
+        moveRawContacts(getLocalAccounts(), destAccount);
+    }
+
+    /**
+     * Moves {@link RawContacts} and {@link Groups} from the SIM account(s) to the Cloud Default
+     * Account (if any).
+     */
+    // Keep it in proguard for testing: once it's used in production code, remove this annotation.
+    @NeededForTesting
+    void moveSimToCloudDefaultAccount() {
+        if (!cp2AccountMoveFlag()) {
+            Log.w(TAG, "moveLocalToCloudDefaultAccount: flag disabled");
+            return;
+        }
+
+        // Check if there is a cloud default account set
+        // - if not, then we don't need to do anything
+        // - if there is, then that's our destAccount, get the AccountWithDataSet
+        Account account = mDefaultAccountManager.pullDefaultAccount().getCloudAccount();
+        if (account == null) {
+            Log.w(TAG, "moveToDefaultCloudAccount with no default cloud account set");
+            return;
+        }
+        AccountWithDataSet destAccount = new AccountWithDataSet(
+                account.name, account.type, /* dataSet= */ null);
+
+        // Move any contacts from the sim accounts to the destination account
+        moveRawContacts(getSimAccounts(), destAccount);
+    }
+
+    /**
+     * Gets the number of {@link RawContacts} in the local account(s) which may be moved using
+     * {@link ContactMover#moveLocalToCloudDefaultAccount} (if any).
+     * @return the number of {@link RawContacts} in the local account(s), or 0 if there is no Cloud
+     * Default Account.
+     */
+    // Keep it in proguard for testing: once it's used in production code, remove this annotation.
+    @NeededForTesting
+    int getNumberLocalContacts() {
+        if (!cp2AccountMoveFlag()) {
+            Log.w(TAG, "getNumberLocalContacts: flag disabled");
+            return 0;
+        }
+
+        // Check if there is a cloud default account set
+        // - if not, then we don't need to do anything, count = 0
+        // - if there is, then do the count
+        Account account = mDefaultAccountManager.pullDefaultAccount().getCloudAccount();
+        if (account == null) {
+            Log.w(TAG, "getNumberLocalContacts with no default cloud account set");
+            return 0;
+        }
+
+        // Count any contacts in the local account(s)
+        return countRawContactsForAccounts(getLocalAccounts());
+    }
+
+    /**
+     * Gets the number of {@link RawContacts} in the SIM account(s) which may be moved using
+     * {@link ContactMover#moveSimToCloudDefaultAccount} (if any).
+     * @return the number of {@link RawContacts} in the SIM account(s), or 0 if there is no Cloud
+     * Default Account.
+     */
+    // Keep it in proguard for testing: once it's used in production code, remove this annotation.
+    @NeededForTesting
+    int getNumberSimContacts() {
+        if (!cp2AccountMoveFlag()) {
+            Log.w(TAG, "getNumberSimContacts: flag disabled");
+            return 0;
+        }
+
+        // Check if there is a cloud default account set
+        // - if not, then we don't need to do anything, count = 0
+        // - if there is, then do the count
+        Account account = mDefaultAccountManager.pullDefaultAccount().getCloudAccount();
+        if (account == null) {
+            Log.w(TAG, "getNumberSimContacts with no default cloud account set");
+            return 0;
+        }
+
+        // Count any contacts in the sim accounts.
+        return countRawContactsForAccounts(getSimAccounts());
+    }
+
+    /**
+     * Moves {@link RawContacts} and {@link Groups} from one account to another.
+     * @param sourceAccounts the source {@link AccountWithDataSet}s to move contacts and groups
+     *                       from.
+     * @param destAccount the destination {@link AccountWithDataSet} to move contacts and groups to.
+     */
+    // Keep it in proguard for testing: once it's used in production code, remove this annotation.
+    @NeededForTesting
+    void moveRawContacts(Set<AccountWithDataSet> sourceAccounts, AccountWithDataSet destAccount) {
+        if (!cp2AccountMoveFlag()) {
+            Log.w(TAG, "moveRawContacts: flag disabled");
+            return;
+        }
+        moveRawContactsForAccounts(
+                sourceAccounts, destAccount, /* insertSyncStubs= */ false);
+    }
+
+    /**
+     * Moves {@link RawContacts} and {@link Groups} from one account to another, while writing sync
+     * stubs in the source account to notify relevant sync adapters in the source account of the
+     * move.
+     * @param sourceAccounts the source {@link AccountWithDataSet}s to move contacts and groups
+     *                       from.
+     * @param destAccount the destination {@link AccountWithDataSet} to move contacts and groups to.
+     */
+    // Keep it in proguard for testing: once it's used in production code, remove this annotation.
+    @NeededForTesting
+    void moveRawContactsWithSyncStubs(Set<AccountWithDataSet> sourceAccounts,
+            AccountWithDataSet destAccount) {
+        if (!cp2AccountMoveFlag() || !cp2AccountMoveSyncStubFlag()) {
+            Log.w(TAG, "moveRawContactsWithSyncStubs: flags disabled");
+            return;
+        }
+        moveRawContactsForAccounts(sourceAccounts, destAccount, /* insertSyncStubs= */ true);
+    }
+
+    private int countRawContactsForAccounts(Set<AccountWithDataSet> sourceAccounts) {
+        return mDbHelper.countRawContactsQuery(sourceAccounts);
+    }
+
+    private void moveRawContactsForAccounts(Set<AccountWithDataSet> sourceAccounts,
+            AccountWithDataSet destAccount, boolean insertSyncStubs) {
+        if (sourceAccounts.contains(destAccount)) {
+            throw new IllegalArgumentException("Source and destination accounts must differ");
+        }
+
+        final SQLiteDatabase db = mDbHelper.getWritableDatabase();
+        db.beginTransaction();
+        try {
+            for (AccountWithDataSet source: sourceAccounts) {
+                moveRawContactsInternal(source, destAccount, insertSyncStubs);
+            }
+
+            db.setTransactionSuccessful();
+        } finally {
+            db.endTransaction();
+        }
+    }
+
+    private void moveRawContactsInternal(AccountWithDataSet sourceAccount,
+            AccountWithDataSet destAccount, boolean insertSyncStubs) {
+        // If we are moving between account types or data sets, delete non-portable data rows
+        // from the source
+        if (!isAccountTypeMatch(sourceAccount, destAccount)
+                || !isDataSetMatch(sourceAccount, destAccount)) {
+            mDbHelper.deleteNonCommonDataRows(sourceAccount);
+        }
+
+        // Move any groups and group memberships from the source to destination account
+        moveGroups(sourceAccount, destAccount, insertSyncStubs);
+
+        // Next, compare raw contacts from source and destination accounts, find the unique
+        // raw contacts from source account;
+        Pair<Set<Long>, Set<Long>> sourceRawContactIds =
+                mDbHelper.deDuplicateRawContacts(sourceAccount, destAccount);
+        Set<Long> nonDuplicates = sourceRawContactIds.first;
+        Set<Long> duplicates = sourceRawContactIds.second;
+
+        if (!sourceAccount.isLocalAccount() && insertSyncStubs) {
+            /*
+                If the source account isn't a device account, and we want to write stub contacts
+                for the move, create them now.
+                This ensures any sync adapters on the source account won't just sync the moved
+                contacts back down (creating duplicates).
+             */
+            mDbHelper.insertRawContactSyncStubs(sourceAccount, nonDuplicates);
+        }
+
+        // move the contacts to the destination account
+        updateRawContactsAccount(destAccount, nonDuplicates);
+
+        // Last, clear the duplicates.
+        // Since these are duplicates, we don't need to do anything else with them
+        for (long rawContactId: duplicates) {
+            mCp2.deleteRawContact(
+                    rawContactId,
+                    mDbHelper.getContactId(rawContactId),
+                    false);
+        }
+    }
+
+}
diff --git a/src/com/android/providers/contacts/ContactsDatabaseHelper.java b/src/com/android/providers/contacts/ContactsDatabaseHelper.java
index 9446462b..eabadd4a 100644
--- a/src/com/android/providers/contacts/ContactsDatabaseHelper.java
+++ b/src/com/android/providers/contacts/ContactsDatabaseHelper.java
@@ -43,7 +43,6 @@ import android.os.Binder;
 import android.os.Bundle;
 import android.os.SystemClock;
 import android.os.UserManager;
-import android.preference.PreferenceManager;
 import android.provider.BaseColumns;
 import android.provider.ContactsContract;
 import android.provider.ContactsContract.AggregationExceptions;
@@ -90,13 +89,12 @@ import android.util.ArrayMap;
 import android.util.ArraySet;
 import android.util.Base64;
 import android.util.Log;
+import android.util.Pair;
 import android.util.Slog;
 
 import com.android.common.content.SyncStateContentProviderHelper;
-import com.android.internal.R;
 import com.android.internal.R.bool;
 import com.android.internal.annotations.VisibleForTesting;
-import com.android.providers.contacts.aggregation.util.CommonNicknameCache;
 import com.android.providers.contacts.database.ContactsTableUtil;
 import com.android.providers.contacts.database.DeletedContactsTableUtil;
 import com.android.providers.contacts.database.MoreDatabaseUtils;
@@ -107,21 +105,22 @@ import com.android.providers.contacts.util.NeededForTesting;
 import com.android.providers.contacts.util.PhoneAccountHandleMigrationUtils;
 import com.android.providers.contacts.util.PropertyUtils;
 
-import com.google.common.base.Strings;
-
 import java.io.PrintWriter;
 import java.security.MessageDigest;
 import java.security.NoSuchAlgorithmException;
 import java.util.ArrayList;
 import java.util.HashMap;
+import java.util.HashSet;
 import java.util.List;
 import java.util.Locale;
 import java.util.Map;
+import java.util.Objects;
 import java.util.Set;
 import java.util.concurrent.Executor;
 import java.util.concurrent.LinkedBlockingQueue;
 import java.util.concurrent.ThreadPoolExecutor;
 import java.util.concurrent.TimeUnit;
+import java.util.stream.Collectors;
 
 /**
  * Database helper for contacts. Designed as a singleton to make sure that all
@@ -952,7 +951,7 @@ public class ContactsDatabaseHelper extends SQLiteOpenHelper {
      */
     private long mDatabaseCreationTime;
 
-    private MessageDigest mMessageDigest;
+    private final MessageDigest mMessageDigest;
     {
         try {
             mMessageDigest = MessageDigest.getInstance("SHA-1");
@@ -4246,12 +4245,24 @@ public class ContactsDatabaseHelper extends SQLiteOpenHelper {
                 new String[]{String.valueOf(simSlot)});
     }
 
+    /**
+     * Clear the previous set default account from Accounts table.
+     */
+    public void clearDefaultAccount() {
+        SQLiteDatabase db = getWritableDatabase();
+
+        ContentValues values = new ContentValues();
+        values.put(AccountsColumns.IS_DEFAULT, 0);
+
+        db.update(Tables.ACCOUNTS, values, null, null);
+    }
+
     /**
      * Set is_default column for the given account name and account type.
      *
      * @param accountName The account name to be set to default.
      * @param accountType The account type to be set to default.
-     * @throws IllegalArgumentException if the account name or type is null.
+     * @throws IllegalArgumentException if one of the account name or type is null, but not both.
      */
     public void setDefaultAccount(String accountName, String accountType) {
         if (TextUtils.isEmpty(accountName) ^ TextUtils.isEmpty(accountType)) {
@@ -4281,9 +4292,11 @@ public class ContactsDatabaseHelper extends SQLiteOpenHelper {
 
     /**
      * Return the default account from Accounts table.
+     *
+     * @return empty array if Default account is not set; 1-element with null if the default account
+     * is set to NULL account; 1-element with non-null account otherwise.
      */
-    public Account getDefaultAccount() {
-        Account defaultAccount = null;
+    public Account[] getDefaultAccountIfAny() {
         try (Cursor c = getReadableDatabase().rawQuery(
                 "SELECT " + AccountsColumns.ACCOUNT_NAME + ","
                 + AccountsColumns.ACCOUNT_TYPE + " FROM " + Tables.ACCOUNTS + " WHERE "
@@ -4291,12 +4304,14 @@ public class ContactsDatabaseHelper extends SQLiteOpenHelper {
             while (c.moveToNext()) {
                 String accountName = c.getString(0);
                 String accountType = c.getString(1);
-                if (!TextUtils.isEmpty(accountName) && !TextUtils.isEmpty(accountType)) {
-                    defaultAccount = new Account(accountName, accountType);
+                if (TextUtils.isEmpty(accountName) || TextUtils.isEmpty(accountType)) {
+                    return new Account[]{null};
+                } else {
+                    return new Account[]{new Account(accountName, accountType)};
                 }
             }
         }
-        return defaultAccount;
+        return new Account[0];
     }
 
     /**
@@ -4395,32 +4410,70 @@ public class ContactsDatabaseHelper extends SQLiteOpenHelper {
      * If {@code optionalContactId} is non-negative, it'll update only for the specified contact.
      */
     private void updateCustomContactVisibility(SQLiteDatabase db, long optionalContactId) {
-        final long groupMembershipMimetypeId = getMimeTypeId(GroupMembership.CONTENT_ITEM_TYPE);
-        String[] selectionArgs = new String[] {String.valueOf(groupMembershipMimetypeId)};
+        // NOTE: This requires late binding of GroupMembership MIME-type
+        final String contactIsVisible = """
+                SELECT
+                MAX((SELECT (CASE WHEN
+                    (CASE
+                        WHEN COUNT(groups._id)=0
+                        THEN ungrouped_visible
+                        ELSE MAX(group_visible)
+                        END)=1 THEN 1 ELSE 0 END)
+                    FROM raw_contacts JOIN accounts ON
+                        (raw_contacts.account_id = accounts._id)
+                        LEFT OUTER JOIN data ON (data.mimetype_id=? AND
+                            data.raw_contact_id = raw_contacts._id)
+                        LEFT OUTER JOIN groups ON (groups._id = data.data1)
+                    WHERE raw_contacts._id = outer_raw_contacts._id))
+                FROM raw_contacts AS outer_raw_contacts
+                WHERE contact_id = contacts._id
+                GROUP BY contact_id
+                """;
 
-        final String contactIdSelect = (optionalContactId < 0) ? "" :
-                (Contacts._ID + "=" + optionalContactId + " AND ");
+        final long groupMembershipMimetypeId = getMimeTypeId(GroupMembership.CONTENT_ITEM_TYPE);
 
         // First delete what needs to be deleted, then insert what needs to be added.
         // Since flash writes are very expensive, this approach is much better than
         // delete-all-insert-all.
-        db.execSQL(
-                "DELETE FROM " + Tables.VISIBLE_CONTACTS +
-                " WHERE " + Contacts._ID + " IN" +
-                    "(SELECT " + Contacts._ID +
-                    " FROM " + Tables.CONTACTS +
-                    " WHERE " + contactIdSelect + "(" + Clauses.CONTACT_IS_VISIBLE + ")=0) ",
-                selectionArgs);
+        if (optionalContactId < 0) {
+            String[] selectionArgs = new String[] {String.valueOf(groupMembershipMimetypeId)};
+            db.execSQL("""
+                    DELETE FROM visible_contacts
+                        WHERE _id IN
+                            (SELECT contacts._id
+                             FROM contacts
+                             WHERE (""" + contactIsVisible + ")=0)",
+                    selectionArgs);
+
+            db.execSQL("""
+                    INSERT INTO visible_contacts
+                        SELECT _id
+                        FROM contacts
+                        WHERE _id NOT IN visible_contacts
+                           AND (""" + contactIsVisible + ")=1 ",
+                    selectionArgs);
+        } else {
+            String[] selectionArgs = new String[] {String.valueOf(optionalContactId),
+                                                    String.valueOf(groupMembershipMimetypeId)};
 
-        db.execSQL(
-                "INSERT INTO " + Tables.VISIBLE_CONTACTS +
-                " SELECT " + Contacts._ID +
-                " FROM " + Tables.CONTACTS +
-                " WHERE " +
-                    contactIdSelect +
-                    Contacts._ID + " NOT IN " + Tables.VISIBLE_CONTACTS +
-                    " AND (" + Clauses.CONTACT_IS_VISIBLE + ")=1 ",
-                selectionArgs);
+            db.execSQL("""
+                    DELETE FROM visible_contacts
+                        WHERE _id IN
+                            (SELECT contacts._id
+                             FROM contacts
+                             WHERE contacts._id = ?
+                                 AND (""" + contactIsVisible + ")=0) ",
+                    selectionArgs);
+
+            db.execSQL("""
+                    INSERT INTO visible_contacts
+                        SELECT _id
+                        FROM contacts
+                        WHERE _id = ? AND
+                            _id NOT IN visible_contacts
+                            AND (""" + contactIsVisible + ")=1 ",
+                    selectionArgs);
+        }
     }
 
     /**
@@ -4722,6 +4775,586 @@ public class ContactsDatabaseHelper extends SQLiteOpenHelper {
         return sb.toString();
     }
 
+    private interface Move {
+        String RAW_CONTACTS_ID_SELECT_FRAGMENT = (
+                "SELECT "
+                        + RawContacts._ID + ", " + RawContacts.DISPLAY_NAME_PRIMARY
+                        + " FROM " + Tables.RAW_CONTACTS
+                        + " WHERE " + RawContactsColumns.ACCOUNT_ID + " = ?"
+                        + " AND " + RawContacts.DELETED + " = 0");
+
+        String DEDUPLICATION_QUERY = "SELECT "
+                + "source." + RawContacts._ID + " AS source_raw_contact_id,"
+                + " dest." + RawContacts._ID + " AS dest_raw_contact_id"
+                + " FROM (" + RAW_CONTACTS_ID_SELECT_FRAGMENT + ") source"
+                + " LEFT OUTER JOIN (" + RAW_CONTACTS_ID_SELECT_FRAGMENT + ") dest" + " ON "
+                + "source." + RawContacts.DISPLAY_NAME_PRIMARY + " = "
+                + "dest." + RawContacts.DISPLAY_NAME_PRIMARY;
+
+        String IS_NONSYSTEM_GROUP_FILTER = "("
+                    + Groups.SYSTEM_ID + " IS NULL"
+                    + " AND " + Groups.GROUP_IS_READ_ONLY + " = 0"
+                + ")";
+
+        String IS_SYSTEM_GROUP_FILTER = "("
+                    + Groups.SYSTEM_ID + " IS NOT NULL"
+                    + " OR " + Groups.GROUP_IS_READ_ONLY + " != 0"
+                + ")";
+
+        String GROUPS_ID_SELECT_FRAGMENT = (
+                "SELECT "
+                    + Groups._ID + ", "
+                    + Groups.TITLE
+                + " FROM " + Tables.GROUPS
+                + " WHERE " + GroupsColumns.ACCOUNT_ID + " = ?"
+                    + " AND " + Groups.DELETED + " = 0");
+    }
+
+    /**
+     * Count the number of {@link RawContacts} associated with the specified accounts.
+     * @param accounts the set of {@link AccountWithDataSet} to consider.
+     * @return the number of {@link RawContacts}.
+     */
+    public int countRawContactsQuery(Set<AccountWithDataSet> accounts) {
+        Set<Long> accountIds = accounts.stream()
+                .map(this::getAccountIdOrNull)
+                .filter(Objects::nonNull)
+                .collect(Collectors.toSet());
+        try (Cursor c = getReadableDatabase().rawQuery("SELECT"
+                + " count(*) FROM " + Tables.RAW_CONTACTS
+                + " WHERE " + RawContactsColumns.ACCOUNT_ID + " IN "
+                + " (" + TextUtils.join(",", accountIds) + ")"
+                + " AND " + RawContacts.DELETED + " = 0",
+                new String[] {}
+        )) {
+            c.moveToFirst();
+            return c.getInt(0);
+        }
+    }
+
+    private Cursor getGroupDeduplicationQuery(
+            long sourceAccountId, long destAccountId, boolean isSystemGroupQuery) {
+        return getReadableDatabase().rawQuery(
+                        "SELECT "
+                            + "source." + Groups._ID + " AS source_group_id,"
+                            + "dest." + Groups._ID + " AS dest_group_id"
+                            + " FROM (" + Move.GROUPS_ID_SELECT_FRAGMENT + " AND "
+                                + (isSystemGroupQuery
+                                ? Move.IS_SYSTEM_GROUP_FILTER
+                                : Move.IS_NONSYSTEM_GROUP_FILTER) + ") source"
+                            + " LEFT OUTER JOIN (" + Move.GROUPS_ID_SELECT_FRAGMENT + ") dest ON "
+                            + "source." + Groups.TITLE + " = "
+                            + "dest." + Groups.TITLE,
+                new String[] {String.valueOf(sourceAccountId), String.valueOf(destAccountId)}
+        );
+    }
+
+    private Cursor getFirstPassDeduplicationQuery(
+            long sourceAccountId, long destAccountId) {
+        return getReadableDatabase().rawQuery(
+                Move.DEDUPLICATION_QUERY, new String[]{
+                        String.valueOf(sourceAccountId), String.valueOf(destAccountId)}
+        );
+    }
+
+    private Cursor getSecondPassDeduplicationQuery(Set<Long> rawContactIds) {
+        return getReadableDatabase().rawQuery("SELECT "
+                + RawContactsColumns.CONCRETE_ID + ", "
+                + RawContactsColumns.CONCRETE_STARRED + ", "
+                + dbForProfile() + " AS " + RawContacts.RAW_CONTACT_IS_USER_PROFILE + ", "
+                + Tables.DATA + "." + Data.IS_SUPER_PRIMARY + ", "
+                + DataColumns.CONCRETE_IS_PRIMARY + ", "
+                + DataColumns.MIMETYPE_ID + ", "
+                + DataColumns.CONCRETE_DATA1 + ", "
+                + DataColumns.CONCRETE_DATA2 + ", "
+                + DataColumns.CONCRETE_DATA3 + ", "
+                + DataColumns.CONCRETE_DATA4 + ", "
+                + DataColumns.CONCRETE_DATA5 + ", "
+                + DataColumns.CONCRETE_DATA6 + ", "
+                + DataColumns.CONCRETE_DATA7 + ", "
+                + DataColumns.CONCRETE_DATA8 + ", "
+                + DataColumns.CONCRETE_DATA9 + ", "
+                + DataColumns.CONCRETE_DATA10 + ", "
+                + DataColumns.CONCRETE_DATA11 + ", "
+                + DataColumns.CONCRETE_DATA12 + ", "
+                + DataColumns.CONCRETE_DATA13 + ", "
+                + DataColumns.CONCRETE_DATA14 + ", "
+                + DataColumns.CONCRETE_DATA15
+                + " FROM " + Tables.RAW_CONTACTS
+                + " LEFT OUTER JOIN " + Tables.DATA
+                + " ON " + RawContactsColumns.CONCRETE_ID + " = "
+                + DataColumns.CONCRETE_RAW_CONTACT_ID
+                + " WHERE " + RawContactsColumns.CONCRETE_ID
+                + " IN (" + TextUtils.join(",", rawContactIds) + ")",
+                new String[]{});
+    }
+
+    /**
+     * Update GroupMembership DataRows from oldGroup to newGroup.
+     * @param oldGroup the old group.
+     * @param newGroup the new group.
+     */
+    public void updateGroupMemberships(Long oldGroup, Long newGroup) {
+        Long groupMembershipMimeType =
+                mCommonMimeTypeIdsCache.get(GroupMembership.CONTENT_ITEM_TYPE);
+        if (groupMembershipMimeType == null) {
+            // if we don't have a mimetype ID for group membership we know we don't have anything
+            // to update.
+            return;
+        }
+
+        try (SQLiteStatement updateGroupMembershipQuery = getWritableDatabase().compileStatement(
+                "UPDATE " + Tables.DATA
+                        + " SET " + GroupMembership.GROUP_ROW_ID + "= ?"
+                        + " WHERE "
+                        + GroupMembership.GROUP_ROW_ID + "= ?"
+                        + " AND " + DataColumns.MIMETYPE_ID + " = ?")) {
+
+            updateGroupMembershipQuery.bindLong(1, newGroup);
+            updateGroupMembershipQuery.bindLong(2, oldGroup);
+            updateGroupMembershipQuery.bindLong(3, groupMembershipMimeType);
+            updateGroupMembershipQuery.execute();
+        }
+    }
+
+    /**
+     * Compares the Groups in source and dest accounts, dividing the Groups in the
+     * source account into two sets - those which are duplicated in the destination account and
+     * those which are not.
+     *
+     * @param sourceAccount the source account
+     * @param destAccount the destination account
+     * @param isSystemGroupQuery true if we should deduplicate system groups, false if we should
+     *                              deduplicate non-system groups
+     * @return Pair of nonDuplicate ID set and the ID mapping (source to desk) for duplicates.
+     */
+    public Pair<Set<Long>, Map<Long, Long>> deDuplicateGroups(
+            AccountWithDataSet sourceAccount, AccountWithDataSet destAccount,
+            boolean isSystemGroupQuery) {
+        /*
+            First get the account ids
+         */
+        final Long sourceAccountId = getAccountIdOrNull(sourceAccount);
+        final Long destAccountId = getAccountIdOrNull(destAccount);
+        // if source account id is null then source account is empty, we are done
+        if (sourceAccountId == null) {
+
+            return Pair.create(Set.of(), Map.of());
+        }
+
+        // if dest account id is null, then dest account is empty, we can be sure everything in
+        // source is unique
+        Set<Long> nonDuplicates = new HashSet<>();
+        if (destAccountId == null) {
+            try (Cursor c = getReadableDatabase().query(
+                    Tables.GROUPS,
+                    new String[] {
+                            Groups._ID,
+                    },
+                    GroupsColumns.ACCOUNT_ID + " = ?"
+                            + " AND " + Groups.DELETED + " = 0"
+                            + " AND " + (isSystemGroupQuery ? Move.IS_SYSTEM_GROUP_FILTER
+                                : Move.IS_NONSYSTEM_GROUP_FILTER),
+                    new String[] {sourceAccountId.toString()},
+                    null, null, null)) {
+                while (c.moveToNext()) {
+                    long rawContactId = c.getLong(0);
+                    nonDuplicates.add(rawContactId);
+                }
+            }
+            return Pair.create(nonDuplicates, Map.of());
+        }
+
+        HashMap<Long, Long> duplicates = new HashMap<>();
+        try (Cursor c = getGroupDeduplicationQuery(sourceAccountId, destAccountId,
+                isSystemGroupQuery)) {
+            while (c.moveToNext()) {
+                long sourceGroupId = c.getLong(0);
+                if (!c.isNull(1)) {
+                    // if name matches, it's a duplicate
+                    long destGroupId = c.getLong(1);
+                    duplicates.put(sourceGroupId, destGroupId);
+                } else {
+                    // add non name matching unique raw contacts to results.
+                    nonDuplicates.add(sourceGroupId);
+                }
+            }
+        }
+
+        return Pair.create(nonDuplicates, duplicates);
+    }
+
+
+
+
+    /**
+     * Compares the raw contacts in source and dest accounts, dividing the raw contacts in the
+     * source account into two sets - those which are duplicated in the destination account and
+     * those which are not.
+     *
+     * @param sourceAccount the source account
+     * @param destAccount the destination account
+     * @return Pair of nonDuplicate ID set and the duplicate ID sets
+     */
+    public Pair<Set<Long>, Set<Long>> deDuplicateRawContacts(
+            AccountWithDataSet sourceAccount,
+            AccountWithDataSet destAccount) {
+        /*
+            First get the account ids
+         */
+        final Long sourceAccountId = getAccountIdOrNull(sourceAccount);
+        final Long destAccountId = getAccountIdOrNull(destAccount);
+        // if source account id is null then source account is empty, we are done
+        if (sourceAccountId == null) {
+
+            return Pair.create(Set.of(), Set.of());
+        }
+
+        // if dest account id is null, it is empty, everything in source is a non-duplicate
+        Set<Long> nonDuplicates = new HashSet<>();
+        if (destAccountId == null) {
+            try (Cursor c = getReadableDatabase().query(
+                    Tables.RAW_CONTACTS,
+                    new String[] {
+                            RawContacts._ID,
+                    },
+                    RawContactsColumns.ACCOUNT_ID + " = ?"
+                    + " AND " + RawContacts.DELETED + " = 0",
+                    new String[] {sourceAccountId.toString()},
+                    null, null, null)) {
+                while (c.moveToNext()) {
+                    long rawContactId = c.getLong(0);
+                    nonDuplicates.add(rawContactId);
+                }
+            }
+            return Pair.create(nonDuplicates, Set.of());
+        }
+
+        /*
+         First discover potential duplicate by comparing names, which should filter out most of the
+         non-duplicate cases.
+        */
+        Set<Long> potentialDupSourceRawContactIds = new ArraySet<>();
+        Set<Long> potentialDupIds = new ArraySet<>();
+
+        try (Cursor c = getFirstPassDeduplicationQuery(sourceAccountId, destAccountId)) {
+            while (c.moveToNext()) {
+                long sourceRawContactIdId = c.getLong(0);
+                if (!c.isNull(1)) {
+                    // if name matches, consider it a potential duplicate
+                    long destRawContactId = c.getLong(1);
+                    potentialDupSourceRawContactIds.add(sourceRawContactIdId);
+                    potentialDupIds.add(sourceRawContactIdId);
+                    potentialDupIds.add(destRawContactId);
+                } else {
+                    // add non name matching unique raw contacts to results.
+                    nonDuplicates.add(sourceRawContactIdId);
+                }
+            }
+        }
+
+        // if there are no potential duplicates at this point, then we are done
+        if (potentialDupIds.isEmpty()) {
+            return Pair.create(nonDuplicates, Set.of());
+        }
+
+        /*
+            Next, hash the potential duplicates.
+        */
+        Map<Long, Set<String>> sourceRawContactIdToHashSet = new HashMap<>();
+        Map<String, Set<Long>> destEntityHashes = new HashMap<>();
+        try (Cursor c = getSecondPassDeduplicationQuery(potentialDupIds)) {
+            while (c.moveToNext()) {
+                long id = c.getLong(0);
+                String hash = hashRawContactEntities(c);
+                if (potentialDupSourceRawContactIds.contains(id)) {
+                    // if it's a source id, we'll want to build a set of hashes that represent it
+                    if (!sourceRawContactIdToHashSet.containsKey(id)) {
+                        Set<String> sourceHashes = new ArraySet<>();
+                        sourceRawContactIdToHashSet.put(id, sourceHashes);
+                    }
+                    sourceRawContactIdToHashSet.get(id).add(hash);
+                } else {
+                    // if it's a destination id, build a set of ids that it maps to
+                    if (!destEntityHashes.containsKey(hash)) {
+                        Set<Long> destIds = new ArraySet<>();
+                        destEntityHashes.put(hash, destIds);
+                    }
+                    destEntityHashes.get(hash).add(id);
+                }
+            }
+        }
+
+        /*
+            Now use the hashes to determine which of the raw contact ids on the source account have
+            exact duplicates in the destination set.
+         */
+        Set<Long> duplicates = new ArraySet<>();
+        // At last, compare the raw entity hash to locate the exact duplicates
+        for (Map.Entry<Long, Set<String>> entry : sourceRawContactIdToHashSet.entrySet()) {
+            Long sourceRawContactId = entry.getKey();
+            Set<String> sourceHashes = entry.getValue();
+            if (hasDuplicateAtDestination(sourceHashes, destEntityHashes)) {
+                // if the source already has an exact match in the dest set, then it's a duplicate
+                duplicates.add(sourceRawContactId);
+            } else {
+                // if there is unique data on the source raw contact, add it to the unique set
+                nonDuplicates.add(sourceRawContactId);
+            }
+        }
+
+        return Pair.create(nonDuplicates, duplicates);
+    }
+
+    private boolean hasDuplicateAtDestination(Set<String> sourceHashes,
+            Map<String, Set<Long>> destHashToIdMap) {
+        // if we have no source hashes then treat it as unique
+        if (sourceHashes == null || sourceHashes.isEmpty()) {
+            // we should always have source hashes at this point so log something
+            Log.e(TAG, "empty source hashes while checking for duplicates during move");
+            return false;
+        }
+
+        Set<Long> potentialDestinationIds = null;
+        for (String sourceHash : sourceHashes) {
+            // if the source hash doesn't have a match in the dest account, we are done
+            if (!destHashToIdMap.containsKey(sourceHash)) {
+                return false;
+            }
+
+            // for all the matches in the destination account, intersect the sets of ids
+            if (potentialDestinationIds == null) {
+                potentialDestinationIds = new ArraySet<>(destHashToIdMap.get(sourceHash));
+            } else {
+                potentialDestinationIds.retainAll(destHashToIdMap.get(sourceHash));
+            }
+
+            // if the set of potential destination ids is ever empty, then we are done (no dupe)
+            if (potentialDestinationIds.isEmpty()) {
+                return false;
+            }
+        }
+
+        return true;
+    }
+
+
+    private String hashRawContactEntities(final Cursor c) {
+        byte[] hashResult;
+        synchronized (mMessageDigest) {
+            mMessageDigest.reset();
+            for (int i = 1; i < c.getColumnCount(); i++) {
+                String data = c.getString(i);
+                if (!TextUtils.isEmpty(data)) {
+                    mMessageDigest.update(data.getBytes());
+                }
+            }
+            hashResult = mMessageDigest.digest();
+        }
+
+        return Base64.encodeToString(hashResult, Base64.DEFAULT);
+    }
+
+    /**
+     * Delete all Data rows where MIMETYPE is not in ContactsContract.CommonDataKinds.
+     * @param account the account to delete data rows from.
+     */
+    public void deleteNonCommonDataRows(AccountWithDataSet account) {
+        final Long accountId = getAccountIdOrNull(account);
+        if (accountId == null) {
+            return;
+        }
+
+        try (SQLiteStatement nonPortableDataDelete = getWritableDatabase().compileStatement(
+                "DELETE FROM " + Tables.DATA
+                        + " WHERE " + DataColumns.MIMETYPE_ID + " NOT IN ("
+                            + TextUtils.join(",", mCommonMimeTypeIdsCache.values()) + ")"
+                        + " AND " + Data.RAW_CONTACT_ID + " IN ("
+                            + "SELECT " + RawContacts._ID + " FROM " + Tables.RAW_CONTACTS
+                            + " WHERE " + RawContactsColumns.ACCOUNT_ID + " = ? )"
+        )) {
+            nonPortableDataDelete.bindLong(1, accountId);
+            nonPortableDataDelete.execute();
+        }
+    }
+
+    private Set<Long> filterEmptyGroups(Set<Long> groupIds) {
+        if (groupIds == null || groupIds.isEmpty()) {
+            return Set.of();
+        }
+        Set<Long> nonEmptyGroupIds = new HashSet<>();
+        try (Cursor c = getReadableDatabase().query(
+                /* distinct= */ true,
+                Tables.DATA,
+                new String[] {
+                        GroupMembership.GROUP_ROW_ID,
+                },
+                GroupMembership.GROUP_ROW_ID + " IN (" + TextUtils.join(",", groupIds) + ")"
+                + " AND " + DataColumns.MIMETYPE_ID + " = "
+                        + mCommonMimeTypeIdsCache.get(GroupMembership.CONTENT_ITEM_TYPE),
+                new String[] {},
+                null, null, null, null)) {
+            while (c.moveToNext()) {
+                nonEmptyGroupIds.add(c.getLong(0));
+            }
+        }
+        return nonEmptyGroupIds;
+    }
+
+    /**
+     * Gets the content values for Groups that will be copied over during a move. Specifically, we
+     * move {@link ContactsContract.Groups#TITLE}, {@link ContactsContract.Groups#NOTES},
+     * {@link ContactsContract.Groups#GROUP_VISIBLE} {@link ContactsContract.Groups#TITLE_RES}, and
+     * {@link ContactsContract.Groups#RES_PACKAGE}.
+     * It will only create ContentValues for Groups that contain Contacts and will skip any with
+     * {@link ContactsContract.Groups#AUTO_ADD} set (as they are likely to simply be all contacts).
+     */
+    public Map<Long, ContentValues> getGroupContentValuesForMoveCopy(AccountWithDataSet account,
+            Set<Long> groupIds) {
+        // we only want move copies for non-empty groups
+        Set<Long> nonEmptyGroupIds = filterEmptyGroups(groupIds);
+        if (nonEmptyGroupIds == null || nonEmptyGroupIds.isEmpty()) {
+            return Map.of();
+        }
+        Map<Long, ContentValues> idToContentValues = new HashMap<>();
+        try (Cursor c = getReadableDatabase().query(
+                Tables.GROUPS,
+                new String[] {
+                        Groups._ID,
+                        Groups.GROUP_VISIBLE,
+                        Groups.NOTES,
+                        GroupsColumns.CONCRETE_PACKAGE_ID,
+                        Groups.TITLE,
+                        Groups.TITLE_RES,
+                },
+                Groups._ID + " IN (" + TextUtils.join(",", nonEmptyGroupIds) + ")"
+                + " AND " + Groups.AUTO_ADD + " = 0",
+                new String[] {},
+                null, null, null)) {
+            while (c.moveToNext()) {
+                Long originalGroupId = c.getLong(0);
+                ContentValues values = new ContentValues();
+                DatabaseUtils.cursorRowToContentValues(c, values);
+                // clear the existing ID from the content values
+                values.putNull(Groups._ID);
+                values.put(Groups.ACCOUNT_NAME, account.getAccountName());
+                values.put(Groups.ACCOUNT_TYPE, account.getAccountType());
+                values.put(Groups.DATA_SET, account.getDataSet());
+                idToContentValues.put(originalGroupId, values);
+            }
+        }
+
+        return idToContentValues;
+    }
+
+    /**
+     * Inserts sync stubs in account, for the groups in groupIds.
+     * The stubs consist of just the {@link ContactsContract.Groups#SOURCE_ID},
+     * {@link ContactsContract.Groups#SYNC1}, {@link ContactsContract.Groups#SYNC2},
+     * {@link ContactsContract.Groups#SYNC3}, and {@link ContactsContract.Groups#SYNC4} columns,
+     * with {@link ContactsContract.Groups#DELETED} and {@link ContactsContract.Groups#DIRTY} = 1.
+     * @param account the account to create the sync stubs in.
+     * @param groupIds the group ids to create sync stubs for.
+     */
+    public void insertGroupSyncStubs(AccountWithDataSet account,
+            Set<Long> groupIds) {
+        if (groupIds == null || groupIds.isEmpty()) {
+            return;
+        }
+        final long accountId = getOrCreateAccountIdInTransaction(account);
+
+        try (SQLiteStatement insertStubs = getWritableDatabase().compileStatement(
+                "INSERT INTO " + Tables.GROUPS
+                        + "("
+                        + Groups.SOURCE_ID + ","
+                        + Groups.SYNC1 + ","
+                        + Groups.SYNC2 + ","
+                        + Groups.SYNC3 + ","
+                        + Groups.SYNC4 + ","
+                        + Groups.DELETED + ","
+                        + Groups.DIRTY + ","
+                        + GroupsColumns.ACCOUNT_ID
+                        + ")"
+                        + " SELECT "
+                        + Groups.SOURCE_ID + ","
+                        + Groups.SYNC1 + ","
+                        + Groups.SYNC2 + ","
+                        + Groups.SYNC3 + ","
+                        + Groups.SYNC4 + ","
+                        /* Groups.DELETED */ + "?,"
+                        /* Groups.DIRTY */ + "?,"
+                        /* GroupsColumns.ACCOUNT_ID */ + "?"
+                        + " FROM " + Tables.GROUPS
+                        + " WHERE "
+                        + Groups._ID + " IN (" + TextUtils.join(",", groupIds) + ")"
+                        + " AND " + Groups.SOURCE_ID + " IS NOT NULL"
+        )) {
+            // Groups.DELETED
+            insertStubs.bindLong(1, 1);
+            // Groups.DIRTY
+            insertStubs.bindLong(2, 1);
+            // GroupsColumns.ACCOUNT_ID
+            insertStubs.bindLong(3, accountId);
+            insertStubs.execute();
+        }
+    }
+
+    /**
+     * Inserts sync stubs in account, for the raw contacts in rawContactIds.
+     * The stubs consist of just the {@link ContactsContract.RawContacts#CONTACT_ID},
+     * {@link ContactsContract.RawContacts#SOURCE_ID}, {@link ContactsContract.RawContacts#SYNC1},
+     * {@link ContactsContract.RawContacts#SYNC2}, {@link ContactsContract.RawContacts#SYNC3}, and
+     * {@link ContactsContract.RawContacts#SYNC4}  columns, with
+     * {@link ContactsContract.RawContacts#DELETED} and
+     * {@link ContactsContract.RawContacts#DIRTY} = 1.
+     * @param account the account to create the sync stubs in.
+     * @param rawContactIds the raw contact ids to create sync stubs for.
+     */
+    public void insertRawContactSyncStubs(AccountWithDataSet account,
+            Set<Long> rawContactIds) {
+        if (rawContactIds == null || rawContactIds.isEmpty()) {
+            return;
+        }
+        final long accountId = getOrCreateAccountIdInTransaction(account);
+
+        try (SQLiteStatement insertStubs = getWritableDatabase().compileStatement(
+                "INSERT INTO " + Tables.RAW_CONTACTS
+                        + "("
+                        + RawContacts.CONTACT_ID + ","
+                        + RawContacts.SOURCE_ID + ","
+                        + RawContacts.SYNC1 + ","
+                        + RawContacts.SYNC2 + ","
+                        + RawContacts.SYNC3 + ","
+                        + RawContacts.SYNC4 + ","
+                        + RawContacts.DELETED + ","
+                        + RawContacts.DIRTY + ","
+                        + RawContactsColumns.ACCOUNT_ID
+                        + ")"
+                        + " SELECT "
+                        + RawContacts.CONTACT_ID + ","
+                        + RawContacts.SOURCE_ID + ","
+                        + RawContacts.SYNC1 + ","
+                        + RawContacts.SYNC2 + ","
+                        + RawContacts.SYNC3 + ","
+                        + RawContacts.SYNC4 + ","
+                        /* RawContacts.DELETED */ + "?,"
+                        /* RawContacts.DIRTY */ + "?,"
+                        /* RawContactsColumns.ACCOUNT_ID */ + "?"
+                        + " FROM " + Tables.RAW_CONTACTS
+                        + " WHERE "
+                        + RawContacts._ID + " IN (" + TextUtils.join(",", rawContactIds) + ")"
+                        + " AND " + RawContacts.SOURCE_ID + " IS NOT NULL"
+        )) {
+            // RawContacts.DELETED
+            insertStubs.bindLong(1, 1);
+            // RawContacts.DIRTY
+            insertStubs.bindLong(2, 1);
+            // RawContactsColumns.ACCOUNT_ID
+            insertStubs.bindLong(3, accountId);
+            insertStubs.execute();
+        }
+    }
+
     public void deleteStatusUpdate(long dataId) {
         final SQLiteStatement statusUpdateDelete = getWritableDatabase().compileStatement(
                     "DELETE FROM " + Tables.STATUS_UPDATES +
diff --git a/src/com/android/providers/contacts/ContactsProvider2.java b/src/com/android/providers/contacts/ContactsProvider2.java
index 8b105738..f15ade66 100644
--- a/src/com/android/providers/contacts/ContactsProvider2.java
+++ b/src/com/android/providers/contacts/ContactsProvider2.java
@@ -20,6 +20,8 @@ import static android.Manifest.permission.INTERACT_ACROSS_USERS;
 import static android.Manifest.permission.INTERACT_ACROSS_USERS_FULL;
 import static android.content.pm.PackageManager.PERMISSION_GRANTED;
 
+import static com.android.providers.contacts.flags.Flags.cp2SyncSearchIndexFlag;
+import static com.android.providers.contacts.flags.Flags.enableNewDefaultAccountRuleFlag;
 import static com.android.providers.contacts.util.PhoneAccountHandleMigrationUtils.TELEPHONY_COMPONENT_NAME;
 
 import android.accounts.Account;
@@ -1488,8 +1490,6 @@ public class ContactsProvider2 extends AbstractContactsProvider
     private boolean mIsPhoneInitialized;
     private boolean mIsPhone;
 
-    private Account mAccount;
-
     private AbstractContactAggregator mContactAggregator;
     private AbstractContactAggregator mProfileAggregator;
 
@@ -1500,6 +1500,9 @@ public class ContactsProvider2 extends AbstractContactsProvider
     private GlobalSearchSupport mGlobalSearchSupport;
     private SearchIndexManager mSearchIndexManager;
 
+    private DefaultAccountManager mDefaultAccountManager;
+    private AccountResolver mAccountResolver;
+
     private int mProviderStatus = STATUS_NORMAL;
     private boolean mProviderStatusUpdateNeeded;
     private volatile CountDownLatch mReadAccessLatch;
@@ -1623,6 +1626,11 @@ public class ContactsProvider2 extends AbstractContactsProvider
 
         mContactDirectoryManager = new ContactDirectoryManager(this);
         mGlobalSearchSupport = new GlobalSearchSupport(this);
+        mDefaultAccountManager = new DefaultAccountManager(getContext(), mContactsHelper);
+        mAccountResolver = new AccountResolver(mContactsHelper, mDefaultAccountManager);
+
+        mDefaultAccountManager = new DefaultAccountManager(getContext(), mContactsHelper);
+        mAccountResolver = new AccountResolver(mContactsHelper, mDefaultAccountManager);
 
         if (mContactsHelper.getPhoneAccountHandleMigrationUtils()
                 .isPhoneAccountMigrationPending()) {
@@ -2576,8 +2584,13 @@ public class ContactsProvider2 extends AbstractContactsProvider
             ContactsPermissions.enforceCallingOrSelfPermission(getContext(), READ_PERMISSION);
             final Bundle response = new Bundle();
 
-            final Account defaultAccount = mDbHelper.get().getDefaultAccount();
-            response.putParcelable(Settings.KEY_DEFAULT_ACCOUNT, defaultAccount);
+            final Account[] defaultAccount = mDbHelper.get().getDefaultAccountIfAny();
+
+            if (defaultAccount.length > 0) {
+                response.putParcelable(Settings.KEY_DEFAULT_ACCOUNT, defaultAccount[0]);
+            } else {
+                response.putParcelable(Settings.KEY_DEFAULT_ACCOUNT, null);
+            }
 
             return response;
         } else if (Settings.SET_DEFAULT_ACCOUNT_METHOD.equals(method)) {
@@ -2975,7 +2988,8 @@ public class ContactsProvider2 extends AbstractContactsProvider
             case RAW_CONTACTS:
             case PROFILE_RAW_CONTACTS: {
                 invalidateFastScrollingIndexCache();
-                id = insertRawContact(uri, values, callerIsSyncAdapter);
+                id = insertRawContact(uri, values, callerIsSyncAdapter,
+                        enableNewDefaultAccountRuleFlag() && match == RAW_CONTACTS);
                 mSyncToNetwork |= !callerIsSyncAdapter;
                 break;
             }
@@ -3006,7 +3020,8 @@ public class ContactsProvider2 extends AbstractContactsProvider
             }
 
             case GROUPS: {
-                id = insertGroup(uri, values, callerIsSyncAdapter);
+                id = insertGroup(uri, values, callerIsSyncAdapter,
+                        enableNewDefaultAccountRuleFlag());
                 mSyncToNetwork |= !callerIsSyncAdapter;
                 break;
             }
@@ -3054,91 +3069,6 @@ public class ContactsProvider2 extends AbstractContactsProvider
         return ContentUris.withAppendedId(uri, id);
     }
 
-    /**
-     * If account is non-null then store it in the values. If the account is
-     * already specified in the values then it must be consistent with the
-     * account, if it is non-null.
-     *
-     * @param uri Current {@link Uri} being operated on.
-     * @param values {@link ContentValues} to read and possibly update.
-     * @throws IllegalArgumentException when only one of
-     *             {@link RawContacts#ACCOUNT_NAME} or
-     *             {@link RawContacts#ACCOUNT_TYPE} is specified, leaving the
-     *             other undefined.
-     * @throws IllegalArgumentException when {@link RawContacts#ACCOUNT_NAME}
-     *             and {@link RawContacts#ACCOUNT_TYPE} are inconsistent between
-     *             the given {@link Uri} and {@link ContentValues}.
-     */
-    private Account resolveAccount(Uri uri, ContentValues values) throws IllegalArgumentException {
-        String accountName = getQueryParameter(uri, RawContacts.ACCOUNT_NAME);
-        String accountType = getQueryParameter(uri, RawContacts.ACCOUNT_TYPE);
-        final boolean partialUri = TextUtils.isEmpty(accountName) ^ TextUtils.isEmpty(accountType);
-
-        String valueAccountName = values.getAsString(RawContacts.ACCOUNT_NAME);
-        String valueAccountType = values.getAsString(RawContacts.ACCOUNT_TYPE);
-        final boolean partialValues = TextUtils.isEmpty(valueAccountName)
-                ^ TextUtils.isEmpty(valueAccountType);
-
-        if (partialUri || partialValues) {
-            // Throw when either account is incomplete.
-            throw new IllegalArgumentException(mDbHelper.get().exceptionMessage(
-                    "Must specify both or neither of ACCOUNT_NAME and ACCOUNT_TYPE", uri));
-        }
-
-        // Accounts are valid by only checking one parameter, since we've
-        // already ruled out partial accounts.
-        final boolean validUri = !TextUtils.isEmpty(accountName);
-        final boolean validValues = !TextUtils.isEmpty(valueAccountName);
-
-        if (validValues && validUri) {
-            // Check that accounts match when both present
-            final boolean accountMatch = TextUtils.equals(accountName, valueAccountName)
-                    && TextUtils.equals(accountType, valueAccountType);
-            if (!accountMatch) {
-                throw new IllegalArgumentException(mDbHelper.get().exceptionMessage(
-                        "When both specified, ACCOUNT_NAME and ACCOUNT_TYPE must match", uri));
-            }
-        } else if (validUri) {
-            // Fill values from the URI when not present.
-            values.put(RawContacts.ACCOUNT_NAME, accountName);
-            values.put(RawContacts.ACCOUNT_TYPE, accountType);
-        } else if (validValues) {
-            accountName = valueAccountName;
-            accountType = valueAccountType;
-        } else {
-            return null;
-        }
-
-        // Use cached Account object when matches, otherwise create
-        if (mAccount == null
-                || !mAccount.name.equals(accountName)
-                || !mAccount.type.equals(accountType)) {
-            mAccount = new Account(accountName, accountType);
-        }
-
-        return mAccount;
-    }
-
-    /**
-     * Resolves the account and builds an {@link AccountWithDataSet} based on the data set specified
-     * in the URI or values (if any).
-     * @param uri Current {@link Uri} being operated on.
-     * @param values {@link ContentValues} to read and possibly update.
-     */
-    private AccountWithDataSet resolveAccountWithDataSet(Uri uri, ContentValues values) {
-        final Account account = resolveAccount(uri, values);
-        AccountWithDataSet accountWithDataSet = null;
-        if (account != null) {
-            String dataSet = getQueryParameter(uri, RawContacts.DATA_SET);
-            if (dataSet == null) {
-                dataSet = values.getAsString(RawContacts.DATA_SET);
-            } else {
-                values.put(RawContacts.DATA_SET, dataSet);
-            }
-            accountWithDataSet = AccountWithDataSet.get(account.name, account.type, dataSet);
-        }
-        return accountWithDataSet;
-    }
 
     /**
      * Inserts an item in the contacts table
@@ -3160,7 +3090,8 @@ public class ContactsProvider2 extends AbstractContactsProvider
      * @return the ID of the newly-created row.
      */
     private long insertRawContact(
-            Uri uri, ContentValues inputValues, boolean callerIsSyncAdapter) {
+            Uri uri, ContentValues inputValues, boolean callerIsSyncAdapter,
+            boolean applyDefaultAccount) {
 
         inputValues = fixUpUsageColumnsForEdit(inputValues);
 
@@ -3169,7 +3100,8 @@ public class ContactsProvider2 extends AbstractContactsProvider
         values.putNull(RawContacts.CONTACT_ID);
 
         // Populate the relevant values before inserting the new entry into the database.
-        final long accountId = replaceAccountInfoByAccountId(uri, values);
+        final long accountId = replaceAccountInfoByAccountId(uri, values,
+                applyDefaultAccount);
         if (flagIsSet(values, RawContacts.DELETED)) {
             values.put(RawContacts.AGGREGATION_MODE, RawContacts.AGGREGATION_MODE_DISABLED);
         }
@@ -3529,12 +3461,14 @@ public class ContactsProvider2 extends AbstractContactsProvider
      *     and false otherwise.
      * @return the ID of the newly-created row.
      */
-    private long insertGroup(Uri uri, ContentValues inputValues, boolean callerIsSyncAdapter) {
+    private long insertGroup(Uri uri, ContentValues inputValues, boolean callerIsSyncAdapter,
+            boolean applyDefaultAccount) {
         // Create a shallow copy.
         final ContentValues values = new ContentValues(inputValues);
 
         // Populate the relevant values before inserting the new entry into the database.
-        final long accountId = replaceAccountInfoByAccountId(uri, values);
+        final long accountId = replaceAccountInfoByAccountId(uri, values,
+                applyDefaultAccount);
         replacePackageNameByPackageId(values);
         if (!callerIsSyncAdapter) {
             values.put(Groups.DIRTY, 1);
@@ -3573,7 +3507,8 @@ public class ContactsProvider2 extends AbstractContactsProvider
     }
 
     private Uri insertSettings(Uri uri, ContentValues values) {
-        final AccountWithDataSet account = resolveAccountWithDataSet(uri, values);
+        final AccountWithDataSet account = mAccountResolver.resolveAccountWithDataSet(uri, values,
+                /*applyDefaultAccount=*/false);
 
         // Note that the following check means the local account settings cannot be created with
         // an insert because resolveAccountWithDataSet returns null for it. However, the settings
@@ -4312,7 +4247,8 @@ public class ContactsProvider2 extends AbstractContactsProvider
         values.put(RawContactsColumns.AGGREGATION_NEEDED, 1);
         values.putNull(RawContacts.CONTACT_ID);
         values.put(RawContacts.DIRTY, 1);
-        return updateRawContact(db, rawContactId, values, callerIsSyncAdapter);
+        return updateRawContact(db, rawContactId, values, callerIsSyncAdapter,
+                /*applyDefaultAccount=*/false);
     }
 
     static int deleteDataUsage(SQLiteDatabase db) {
@@ -4446,7 +4382,8 @@ public class ContactsProvider2 extends AbstractContactsProvider
             case PROFILE_RAW_CONTACTS: {
                 invalidateFastScrollingIndexCache();
                 selection = appendAccountIdToSelection(uri, selection);
-                count = updateRawContacts(values, selection, selectionArgs, callerIsSyncAdapter);
+                count = updateRawContacts(values, selection, selectionArgs, callerIsSyncAdapter,
+                         enableNewDefaultAccountRuleFlag() && match == RAW_CONTACTS);
                 break;
             }
 
@@ -4457,11 +4394,11 @@ public class ContactsProvider2 extends AbstractContactsProvider
                     selectionArgs = insertSelectionArg(selectionArgs, String.valueOf(rawContactId));
                     count = updateRawContacts(values, RawContacts._ID + "=?"
                                     + " AND(" + selection + ")", selectionArgs,
-                            callerIsSyncAdapter);
+                            callerIsSyncAdapter, enableNewDefaultAccountRuleFlag());
                 } else {
                     mSelectionArgs1[0] = String.valueOf(rawContactId);
                     count = updateRawContacts(values, RawContacts._ID + "=?", mSelectionArgs1,
-                            callerIsSyncAdapter);
+                            callerIsSyncAdapter, enableNewDefaultAccountRuleFlag());
                 }
                 break;
             }
@@ -4752,6 +4689,11 @@ public class ContactsProvider2 extends AbstractContactsProvider
                         ? updatedDataSet : c.getString(GroupAccountQuery.DATA_SET);
 
                 if (isAccountChanging) {
+                    if (enableNewDefaultAccountRuleFlag()) {
+                        mAccountResolver.checkAccountIsWritable(updatedAccountName,
+                                updatedAccountType);
+                    }
+
                     final long accountId = dbHelper.getOrCreateAccountIdInTransaction(
                             AccountWithDataSet.get(accountName, accountType, dataSet));
                     updatedValues.put(GroupsColumns.ACCOUNT_ID, accountId);
@@ -4808,7 +4750,7 @@ public class ContactsProvider2 extends AbstractContactsProvider
     }
 
     private int updateRawContacts(ContentValues values, String selection, String[] selectionArgs,
-            boolean callerIsSyncAdapter) {
+            boolean callerIsSyncAdapter, boolean applyDefaultAccount) {
         if (values.containsKey(RawContacts.CONTACT_ID)) {
             throw new IllegalArgumentException(RawContacts.CONTACT_ID + " should not be included " +
                     "in content values. Contact IDs are assigned automatically");
@@ -4827,7 +4769,8 @@ public class ContactsProvider2 extends AbstractContactsProvider
         try {
             while (cursor.moveToNext()) {
                 long rawContactId = cursor.getLong(0);
-                updateRawContact(db, rawContactId, values, callerIsSyncAdapter);
+                updateRawContact(db, rawContactId, values, callerIsSyncAdapter,
+                        applyDefaultAccount);
                 count++;
             }
         } finally {
@@ -4860,7 +4803,7 @@ public class ContactsProvider2 extends AbstractContactsProvider
     }
 
     private int updateRawContact(SQLiteDatabase db, long rawContactId, ContentValues values,
-            boolean callerIsSyncAdapter) {
+            boolean callerIsSyncAdapter, boolean applyDefaultAccount) {
         final String selection = RawContactsColumns.CONCRETE_ID + " = ?";
         mSelectionArgs1[0] = Long.toString(rawContactId);
 
@@ -4916,6 +4859,23 @@ public class ContactsProvider2 extends AbstractContactsProvider
                         isDataSetChanging
                             ? values.getAsString(RawContacts.DATA_SET) : oldDataSet
                         );
+
+                // The checkAccountIsWritable has to be done at the level of attempting to update
+                // each raw contacts, rather than at the beginning of attempting all selected raw
+                // contacts:
+                // since not all of account field (name, type, data_set) are provided in the
+                // ContentValues @param, the destination account of each raw contact can be
+                // partially derived from the their existing account info, and thus can be
+                // different.
+                // Since the UpdateRawContacts (updating all selected raw contacts) are done in
+                // a single transaction, failing checkAccountIsWritable will fail the entire update
+                // operation, which is clean such that no partial updated will be committed to the
+                // DB.
+                if (applyDefaultAccount) {
+                    mAccountResolver.checkAccountIsWritable(newAccountWithDataSet.getAccountName(),
+                            newAccountWithDataSet.getAccountType());
+                }
+
                 accountId = dbHelper.getOrCreateAccountIdInTransaction(newAccountWithDataSet);
 
                 values.put(RawContactsColumns.ACCOUNT_ID, accountId);
@@ -5432,174 +5392,214 @@ public class ContactsProvider2 extends AbstractContactsProvider
                 accountsWithDataSetsToDelete.add(knownAccountWithDataSet);
             }
 
-            if (!accountsWithDataSetsToDelete.isEmpty()) {
-                for (AccountWithDataSet accountWithDataSet : accountsWithDataSetsToDelete) {
-                    final Long accountIdOrNull = dbHelper.getAccountIdOrNull(accountWithDataSet);
-
-                    if (accountIdOrNull != null) {
-                        final String accountId = Long.toString(accountIdOrNull);
-                        final String[] accountIdParams =
-                                new String[] {accountId};
-                        db.execSQL(
-                                "DELETE FROM " + Tables.GROUPS +
-                                " WHERE " + GroupsColumns.ACCOUNT_ID + " = ?",
-                                accountIdParams);
-                        db.execSQL(
-                                "DELETE FROM " + Tables.PRESENCE +
-                                " WHERE " + PresenceColumns.RAW_CONTACT_ID + " IN (" +
-                                        "SELECT " + RawContacts._ID +
-                                        " FROM " + Tables.RAW_CONTACTS +
-                                        " WHERE " + RawContactsColumns.ACCOUNT_ID + " = ?)",
-                                        accountIdParams);
-                        db.execSQL(
-                                "DELETE FROM " + Tables.STREAM_ITEM_PHOTOS +
-                                " WHERE " + StreamItemPhotos.STREAM_ITEM_ID + " IN (" +
-                                        "SELECT " + StreamItems._ID +
-                                        " FROM " + Tables.STREAM_ITEMS +
-                                        " WHERE " + StreamItems.RAW_CONTACT_ID + " IN (" +
-                                                "SELECT " + RawContacts._ID +
-                                                " FROM " + Tables.RAW_CONTACTS +
-                                                " WHERE " + RawContactsColumns.ACCOUNT_ID + "=?))",
-                                                accountIdParams);
-                        db.execSQL(
-                                "DELETE FROM " + Tables.STREAM_ITEMS +
-                                " WHERE " + StreamItems.RAW_CONTACT_ID + " IN (" +
-                                        "SELECT " + RawContacts._ID +
-                                        " FROM " + Tables.RAW_CONTACTS +
-                                        " WHERE " + RawContactsColumns.ACCOUNT_ID + " = ?)",
-                                        accountIdParams);
-
-                        // Delta API is only needed for regular contacts.
-                        if (!inProfileMode()) {
-                            // Contacts are deleted by a trigger on the raw_contacts table.
-                            // But we also need to insert the contact into the delete log.
-                            // This logic is being consolidated into the ContactsTableUtil.
-
-                            // deleteContactIfSingleton() does not work in this case because raw
-                            // contacts will be deleted in a single batch below.  Contacts with
-                            // multiple raw contacts in the same account will be missed.
-
-                            // Find all contacts that do not have raw contacts in other accounts.
-                            // These should be deleted.
-                            Cursor cursor = db.rawQuery(
-                                    "SELECT " + RawContactsColumns.CONCRETE_CONTACT_ID +
+            removeDataOfAccount(systemAccounts, accountsWithDataSetsToDelete, dbHelper, db);
+        } finally {
+            db.endTransaction();
+        }
+        mAccountWritability.clear();
+
+        updateContactsAccountCount(systemAccounts);
+        updateProviderStatus();
+        return true;
+    }
+
+    private void removeDataOfAccount(Account[] systemAccounts,
+            List<AccountWithDataSet> accountsWithDataSetsToDelete, ContactsDatabaseHelper dbHelper,
+            SQLiteDatabase db) {
+        if (!accountsWithDataSetsToDelete.isEmpty()) {
+            for (AccountWithDataSet accountWithDataSet : accountsWithDataSetsToDelete) {
+                final Long accountIdOrNull = dbHelper.getAccountIdOrNull(accountWithDataSet);
+
+                if (accountIdOrNull != null) {
+                    final String accountId = Long.toString(accountIdOrNull);
+                    final String[] accountIdParams =
+                            new String[] {accountId};
+                    db.execSQL(
+                            "DELETE FROM " + Tables.GROUPS +
+                            " WHERE " + GroupsColumns.ACCOUNT_ID + " = ?",
+                            accountIdParams);
+                    db.execSQL(
+                            "DELETE FROM " + Tables.PRESENCE +
+                            " WHERE " + PresenceColumns.RAW_CONTACT_ID + " IN (" +
+                                    "SELECT " + RawContacts._ID +
+                                    " FROM " + Tables.RAW_CONTACTS +
+                                    " WHERE " + RawContactsColumns.ACCOUNT_ID + " = ?)",
+                                    accountIdParams);
+                    db.execSQL(
+                            "DELETE FROM " + Tables.STREAM_ITEM_PHOTOS +
+                            " WHERE " + StreamItemPhotos.STREAM_ITEM_ID + " IN (" +
+                                    "SELECT " + StreamItems._ID +
+                                    " FROM " + Tables.STREAM_ITEMS +
+                                    " WHERE " + StreamItems.RAW_CONTACT_ID + " IN (" +
+                                            "SELECT " + RawContacts._ID +
                                             " FROM " + Tables.RAW_CONTACTS +
-                                            " WHERE " + RawContactsColumns.ACCOUNT_ID + " = ?1" +
-                                            " AND " + RawContactsColumns.CONCRETE_CONTACT_ID +
-                                            " IS NOT NULL" +
-                                            " AND " + RawContactsColumns.CONCRETE_CONTACT_ID +
-                                            " NOT IN (" +
-                                            "    SELECT " + RawContactsColumns.CONCRETE_CONTACT_ID +
-                                            "    FROM " + Tables.RAW_CONTACTS +
-                                            "    WHERE " + RawContactsColumns.ACCOUNT_ID + " != ?1"
-                                            + "  AND " + RawContactsColumns.CONCRETE_CONTACT_ID +
-                                            "    IS NOT NULL"
-                                            + ")", accountIdParams);
-                            try {
-                                while (cursor.moveToNext()) {
-                                    final long contactId = cursor.getLong(0);
-                                    ContactsTableUtil.deleteContact(db, contactId);
+                                            " WHERE " + RawContactsColumns.ACCOUNT_ID + "=?))",
+                                            accountIdParams);
+                    db.execSQL(
+                            "DELETE FROM " + Tables.STREAM_ITEMS +
+                            " WHERE " + StreamItems.RAW_CONTACT_ID + " IN (" +
+                                    "SELECT " + RawContacts._ID +
+                                    " FROM " + Tables.RAW_CONTACTS +
+                                    " WHERE " + RawContactsColumns.ACCOUNT_ID + " = ?)",
+                                    accountIdParams);
+
+                    // Delta API is only needed for regular contacts.
+                    if (!inProfileMode()) {
+                        // Contacts are deleted by a trigger on the raw_contacts table.
+                        // But we also need to insert the contact into the delete log.
+                        // This logic is being consolidated into the ContactsTableUtil.
+
+                        // deleteContactIfSingleton() does not work in this case because raw
+                        // contacts will be deleted in a single batch below.  Contacts with
+                        // multiple raw contacts in the same account will be missed.
+
+                        // Find all contacts that do not have raw contacts in other accounts.
+                        // These should be deleted.
+                        Cursor cursor = db.rawQuery(
+                                "SELECT " + RawContactsColumns.CONCRETE_CONTACT_ID +
+                                        " FROM " + Tables.RAW_CONTACTS +
+                                        " WHERE " + RawContactsColumns.ACCOUNT_ID + " = ?1" +
+                                        " AND " + RawContactsColumns.CONCRETE_CONTACT_ID +
+                                        " IS NOT NULL" +
+                                        " AND " + RawContactsColumns.CONCRETE_CONTACT_ID +
+                                        " NOT IN (" +
+                                        "    SELECT " + RawContactsColumns.CONCRETE_CONTACT_ID +
+                                        "    FROM " + Tables.RAW_CONTACTS +
+                                        "    WHERE " + RawContactsColumns.ACCOUNT_ID + " != ?1"
+                                        + "  AND " + RawContactsColumns.CONCRETE_CONTACT_ID +
+                                        "    IS NOT NULL"
+                                        + ")", accountIdParams);
+                        try {
+                            while (cursor.moveToNext()) {
+                                final long contactId = cursor.getLong(0);
+                                ContactsTableUtil.deleteContact(db, contactId);
+                                if (cp2SyncSearchIndexFlag()) {
+                                    mTransactionContext.get()
+                                            .invalidateSearchIndexForContact(contactId);
                                 }
-                            } finally {
-                                MoreCloseables.closeQuietly(cursor);
                             }
+                        } finally {
+                            MoreCloseables.closeQuietly(cursor);
+                        }
 
-                            // If the contact was not deleted, its last updated timestamp needs to
-                            // be refreshed since one of its raw contacts got removed.
-                            // Find all contacts that will not be deleted (i.e. contacts with
-                            // raw contacts in other accounts)
-                            cursor = db.rawQuery(
-                                    "SELECT DISTINCT " + RawContactsColumns.CONCRETE_CONTACT_ID +
-                                            " FROM " + Tables.RAW_CONTACTS +
-                                            " WHERE " + RawContactsColumns.ACCOUNT_ID + " = ?1" +
-                                            " AND " + RawContactsColumns.CONCRETE_CONTACT_ID +
-                                            " IN (" +
-                                            "    SELECT " + RawContactsColumns.CONCRETE_CONTACT_ID +
-                                            "    FROM " + Tables.RAW_CONTACTS +
-                                            "    WHERE " + RawContactsColumns.ACCOUNT_ID + " != ?1"
-                                            + ")", accountIdParams);
-                            try {
-                                while (cursor.moveToNext()) {
-                                    final long contactId = cursor.getLong(0);
-                                    ContactsTableUtil.updateContactLastUpdateByContactId(
-                                            db, contactId);
+                        // If the contact was not deleted, its last updated timestamp needs to
+                        // be refreshed since one of its raw contacts got removed.
+                        // Find all contacts that will not be deleted (i.e. contacts with
+                        // raw contacts in other accounts)
+                        cursor = db.rawQuery(
+                                "SELECT DISTINCT " + RawContactsColumns.CONCRETE_CONTACT_ID +
+                                        " FROM " + Tables.RAW_CONTACTS +
+                                        " WHERE " + RawContactsColumns.ACCOUNT_ID + " = ?1" +
+                                        " AND " + RawContactsColumns.CONCRETE_CONTACT_ID +
+                                        " IN (" +
+                                        "    SELECT " + RawContactsColumns.CONCRETE_CONTACT_ID +
+                                        "    FROM " + Tables.RAW_CONTACTS +
+                                        "    WHERE " + RawContactsColumns.ACCOUNT_ID + " != ?1"
+                                        + ")", accountIdParams);
+                        try {
+                            while (cursor.moveToNext()) {
+                                final long contactId = cursor.getLong(0);
+                                ContactsTableUtil.updateContactLastUpdateByContactId(
+                                        db, contactId);
+                                if (cp2SyncSearchIndexFlag()) {
+                                    mTransactionContext.get()
+                                            .invalidateSearchIndexForContact(contactId);
                                 }
-                            } finally {
-                                MoreCloseables.closeQuietly(cursor);
                             }
+                        } finally {
+                            MoreCloseables.closeQuietly(cursor);
                         }
-
-                        db.execSQL(
-                                "DELETE FROM " + Tables.RAW_CONTACTS +
-                                " WHERE " + RawContactsColumns.ACCOUNT_ID + " = ?",
-                                accountIdParams);
-                        db.execSQL(
-                                "DELETE FROM " + Tables.ACCOUNTS +
-                                " WHERE " + AccountsColumns._ID + "=?",
-                                accountIdParams);
                     }
-                }
 
-                // Find all aggregated contacts that used to contain the raw contacts
-                // we have just deleted and see if they are still referencing the deleted
-                // names or photos.  If so, fix up those contacts.
-                ArraySet<Long> orphanContactIds = new ArraySet<>();
-                Cursor cursor = db.rawQuery("SELECT " + Contacts._ID +
-                        " FROM " + Tables.CONTACTS +
-                        " WHERE (" + Contacts.NAME_RAW_CONTACT_ID + " NOT NULL AND " +
-                                Contacts.NAME_RAW_CONTACT_ID + " NOT IN " +
-                                        "(SELECT " + RawContacts._ID +
-                                        " FROM " + Tables.RAW_CONTACTS + "))" +
-                        " OR (" + Contacts.PHOTO_ID + " NOT NULL AND " +
-                                Contacts.PHOTO_ID + " NOT IN " +
-                                        "(SELECT " + Data._ID +
-                                        " FROM " + Tables.DATA + "))", null);
-                try {
-                    while (cursor.moveToNext()) {
-                        orphanContactIds.add(cursor.getLong(0));
-                    }
-                } finally {
-                    cursor.close();
+                    db.execSQL(
+                            "DELETE FROM " + Tables.RAW_CONTACTS +
+                            " WHERE " + RawContactsColumns.ACCOUNT_ID + " = ?",
+                            accountIdParams);
+                    db.execSQL(
+                            "DELETE FROM " + Tables.ACCOUNTS +
+                            " WHERE " + AccountsColumns._ID + "=?",
+                            accountIdParams);
+                }
+            }
+
+            // Find all aggregated contacts that used to contain the raw contacts
+            // we have just deleted and see if they are still referencing the deleted
+            // names or photos.  If so, fix up those contacts.
+            ArraySet<Long> orphanContactIds = new ArraySet<>();
+            Cursor cursor = db.rawQuery("SELECT " + Contacts._ID +
+                    " FROM " + Tables.CONTACTS +
+                    " WHERE (" + Contacts.NAME_RAW_CONTACT_ID + " NOT NULL AND " +
+                            Contacts.NAME_RAW_CONTACT_ID + " NOT IN " +
+                                    "(SELECT " + RawContacts._ID +
+                                    " FROM " + Tables.RAW_CONTACTS + "))" +
+                    " OR (" + Contacts.PHOTO_ID + " NOT NULL AND " +
+                            Contacts.PHOTO_ID + " NOT IN " +
+                                    "(SELECT " + Data._ID +
+                                    " FROM " + Tables.DATA + "))", null);
+            try {
+                while (cursor.moveToNext()) {
+                    orphanContactIds.add(cursor.getLong(0));
                 }
+            } finally {
+                cursor.close();
+            }
 
-                for (Long contactId : orphanContactIds) {
-                    mAggregator.get().updateAggregateData(mTransactionContext.get(), contactId);
-                }
-                dbHelper.updateAllVisible();
+            for (Long contactId : orphanContactIds) {
+                mAggregator.get().updateAggregateData(mTransactionContext.get(), contactId);
+            }
+            dbHelper.updateAllVisible();
 
-                // Don't bother updating the search index if we're in profile mode - there is no
-                // search index for the profile DB, and updating it for the contacts DB in this case
-                // makes no sense and risks a deadlock.
-                if (!inProfileMode()) {
-                    // TODO Fix it.  It only updates index for contacts/raw_contacts that the
-                    // current transaction context knows updated, but here in this method we don't
-                    // update that information, so effectively it's no-op.
-                    // We can probably just schedule BACKGROUND_TASK_UPDATE_SEARCH_INDEX.
-                    // (But make sure it's not scheduled yet. We schedule this task in initialize()
-                    // too.)
-                    updateSearchIndexInTransaction();
-                }
+            // Don't bother updating the search index if we're in profile mode - there is no
+            // search index for the profile DB, and updating it for the contacts DB in this case
+            // makes no sense and risks a deadlock.
+            if (!inProfileMode()) {
+                // Will remove the deleted contact ids of the account from the search index and
+                // will update the contacts in the search index which had a raw contact deleted.
+                updateSearchIndexInTransaction();
             }
+        }
 
-            // Second, remove stale rows from Tables.DIRECTORIES
-            removeStaleAccountRows(Tables.DIRECTORIES, Directory.ACCOUNT_NAME,
-                    Directory.ACCOUNT_TYPE, systemAccounts);
+        // Second, remove stale rows from Tables.DIRECTORIES
+        removeStaleAccountRows(Tables.DIRECTORIES, Directory.ACCOUNT_NAME,
+                Directory.ACCOUNT_TYPE, systemAccounts);
 
-            // Third, remaining tasks that must be done in a transaction.
-            // TODO: Should sync state take data set into consideration?
-            dbHelper.getSyncState().onAccountsChanged(db, systemAccounts);
+        // Third, remaining tasks that must be done in a transaction.
+        // TODO: Should sync state take data set into consideration?
+        dbHelper.getSyncState().onAccountsChanged(db, systemAccounts);
 
-            saveAccounts(systemAccounts);
+        saveAccounts(systemAccounts);
 
-            db.setTransactionSuccessful();
+        db.setTransactionSuccessful();
+    }
+
+    @VisibleForTesting
+    void unSyncAccounts(Account[] accountsToUnSync) {
+        List<AccountWithDataSet> accountWithDataSetList =
+                mDbHelper.get().getAllAccountsWithDataSets().stream().filter(
+                        accountWithDataSet -> accountWithDataSet.inSystemAccounts(
+                                accountsToUnSync)).toList();
+        Account[] accounts = AccountManager.get(getContext()).getAccounts();
+        switchToContactMode();
+        final ContactsDatabaseHelper dbHelper = mDbHelper.get();
+        final SQLiteDatabase db = dbHelper.getWritableDatabase();
+        db.beginTransaction();
+        try {
+            removeDataOfAccount(accounts, accountWithDataSetList, dbHelper,
+                    dbHelper.getWritableDatabase());
         } finally {
             db.endTransaction();
         }
-        mAccountWritability.clear();
-
-        updateContactsAccountCount(systemAccounts);
-        updateProviderStatus();
-        return true;
+        switchToProfileMode();
+        db.beginTransaction();
+        try {
+            removeDataOfAccount(accounts, accountWithDataSetList, dbHelper,
+                    dbHelper.getWritableDatabase());
+        } finally {
+            db.endTransaction();
+        }
+        switchToContactMode();
+        updateContactsAccountCount(accounts);
+        updateDirectoriesInBackground(true);
     }
 
     private void updateContactsAccountCount(Account[] accounts) {
@@ -10290,8 +10290,10 @@ public class ContactsProvider2 extends AbstractContactsProvider
      * @param values The {@link ContentValues} object to operate on.
      * @return The corresponding account ID.
      */
-    private long replaceAccountInfoByAccountId(Uri uri, ContentValues values) {
-        final AccountWithDataSet account = resolveAccountWithDataSet(uri, values);
+    private long replaceAccountInfoByAccountId(Uri uri, ContentValues values,
+            boolean applyDefaultAccount) {
+        final AccountWithDataSet account = mAccountResolver.resolveAccountWithDataSet(uri, values,
+                applyDefaultAccount);
         final long id = mDbHelper.get().getOrCreateAccountIdInTransaction(account);
         values.put(RawContactsColumns.ACCOUNT_ID, id);
 
@@ -10450,4 +10452,10 @@ public class ContactsProvider2 extends AbstractContactsProvider
     public ProfileProvider getProfileProviderForTest() {
         return mProfileProvider;
     }
+
+    /** Should be only used in tests. */
+    @NeededForTesting
+    void setSearchIndexMaxUpdateFilterContacts(int maxUpdateFilterContacts) {
+        mSearchIndexManager.setMaxUpdateFilterContacts(maxUpdateFilterContacts);
+    }
 }
diff --git a/src/com/android/providers/contacts/DefaultAccount.java b/src/com/android/providers/contacts/DefaultAccount.java
new file mode 100644
index 00000000..a8b41641
--- /dev/null
+++ b/src/com/android/providers/contacts/DefaultAccount.java
@@ -0,0 +1,141 @@
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
+package com.android.providers.contacts;
+
+import android.accounts.Account;
+
+/**
+ * Represents a default account with a category (UNKNOWN, DEVICE, or CLOUD)
+ * and an optional associated Android Account object.
+ */
+public class DefaultAccount {
+    /**
+     * The possible categories for a DefaultAccount.
+     */
+    public enum AccountCategory {
+        /**
+         * The account category is unknown. This is usually a temporary state.
+         */
+        UNKNOWN,
+
+        /**
+         * The account is a device-only account and not synced to the cloud.
+         */
+        DEVICE,
+
+        /**
+         * The account is synced to the cloud.
+         */
+        CLOUD
+    }
+
+
+    public static final DefaultAccount UNKNOWN_DEFAULT_ACCOUNT = new DefaultAccount(
+            AccountCategory.UNKNOWN, null);
+    public static final DefaultAccount DEVICE_DEFAULT_ACCOUNT = new DefaultAccount(
+            AccountCategory.DEVICE, null);
+
+    /**
+     * Create a DefaultAccount object which points to the cloud.
+     * @param cloudAccount The cloud account that is being set as the default account.
+     * @return The DefaultAccount object.
+     */
+    public static DefaultAccount ofCloud(Account cloudAccount) {
+        return new DefaultAccount(AccountCategory.CLOUD, cloudAccount);
+    }
+
+    private final AccountCategory mAccountCategory;
+    private final Account mCloudAccount;
+
+    /**
+     * Constructs a DefaultAccount object.
+     *
+     * @param accountCategory The category of the default account.
+     * @param cloudAccount    The account when mAccountCategory is CLOUD (null for
+     *                        DEVICE/UNKNOWN).
+     * @throws IllegalArgumentException If cloudAccount is null when accountCategory is
+     *                                  CLOUD,
+     *                                  or if cloudAccount is not null when accountCategory is not
+     *                                  CLOUD.
+     */
+    public DefaultAccount(AccountCategory accountCategory, Account cloudAccount) {
+        this.mAccountCategory = accountCategory;
+
+        // Validate cloudAccount based on accountCategory
+        if (accountCategory == AccountCategory.CLOUD && cloudAccount == null) {
+            throw new IllegalArgumentException(
+                    "Cloud account cannot be null when category is CLOUD");
+        } else if (accountCategory != AccountCategory.CLOUD && cloudAccount != null) {
+            throw new IllegalArgumentException(
+                    "Cloud account should be null when category is not CLOUD");
+        }
+
+        this.mCloudAccount = cloudAccount;
+    }
+
+    /**
+     * Gets the category of the account.
+     *
+     * @return The current category (UNKNOWN, DEVICE, or CLOUD).
+     */
+    public AccountCategory getAccountCategory() {
+        return mAccountCategory;
+    }
+
+    /**
+     * Gets the associated cloud account, if available.
+     *
+     * @return The Android Account object, or null if the category is not CLOUD.
+     */
+    public Account getCloudAccount() {
+        return mCloudAccount;
+    }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) return true; // Same object
+        if (o == null || getClass() != o.getClass()) return false; // Null or different class
+
+        DefaultAccount that = (DefaultAccount) o;
+
+        // Compare account categories first for efficiency
+        if (mAccountCategory != that.mAccountCategory) return false;
+
+        // If categories match, compare cloud accounts depending on category
+        if (mAccountCategory == AccountCategory.CLOUD) {
+            return mCloudAccount.equals(that.mCloudAccount); // Use Account's equals
+        } else {
+            return true; // Categories match and cloud account is irrelevant
+        }
+    }
+
+    @Override
+    public int hashCode() {
+        int result = mAccountCategory.hashCode();
+        if (mAccountCategory == AccountCategory.CLOUD) {
+            result = 31 * result + mCloudAccount.hashCode(); // Use Account's hashCode
+        }
+        return result;
+    }
+
+    @Override
+    public String toString() {
+        return String.format("{mAccountCategory: %s, mCloudAccount: %s}",
+                mAccountCategory, mCloudAccount);
+    }
+
+}
diff --git a/src/com/android/providers/contacts/DefaultAccountManager.java b/src/com/android/providers/contacts/DefaultAccountManager.java
new file mode 100644
index 00000000..c42aac17
--- /dev/null
+++ b/src/com/android/providers/contacts/DefaultAccountManager.java
@@ -0,0 +1,178 @@
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
+package com.android.providers.contacts;
+
+import android.accounts.Account;
+import android.accounts.AccountManager;
+import android.content.Context;
+import android.content.res.Resources;
+import android.util.Log;
+
+import com.android.internal.R;
+import com.android.providers.contacts.util.NeededForTesting;
+
+import java.util.Arrays;
+import java.util.HashSet;
+import java.util.Set;
+
+/**
+ * A utility class to provide methods to load and set the default account.
+ */
+@NeededForTesting
+public class DefaultAccountManager {
+    private static final String TAG = "DefaultAccountManager";
+
+    private static HashSet<String> sEligibleSystemCloudAccountTypes = null;
+
+    private final Context mContext;
+    private final ContactsDatabaseHelper mDbHelper;
+    private final SyncSettingsHelper mSyncSettingsHelper;
+    private final AccountManager mAccountManager;
+
+    DefaultAccountManager(Context context, ContactsDatabaseHelper dbHelper) {
+        this(context, dbHelper, new SyncSettingsHelper(), AccountManager.get(context));
+    }
+
+    // Keep it in proguard for testing: once it's used in production code, remove this annotation.
+    @NeededForTesting
+    DefaultAccountManager(Context context, ContactsDatabaseHelper dbHelper,
+            SyncSettingsHelper syncSettingsHelper, AccountManager accountManager) {
+        mContext = context;
+        mDbHelper = dbHelper;
+        mSyncSettingsHelper = syncSettingsHelper;
+        mAccountManager = accountManager;
+    }
+
+    private static synchronized Set<String> getEligibleSystemAccountTypes(Context context) {
+        if (sEligibleSystemCloudAccountTypes == null) {
+            sEligibleSystemCloudAccountTypes = new HashSet<>();
+
+            Resources resources = Resources.getSystem();
+            String[] accountTypesArray =
+                    resources.getStringArray(R.array.config_rawContactsEligibleDefaultAccountTypes);
+
+            sEligibleSystemCloudAccountTypes.addAll(Arrays.asList(accountTypesArray));
+        }
+        return sEligibleSystemCloudAccountTypes;
+    }
+
+    @NeededForTesting
+    static synchronized void setEligibleSystemCloudAccountTypesForTesting(String[] accountTypes) {
+        sEligibleSystemCloudAccountTypes = new HashSet<>(Arrays.asList(accountTypes));
+    }
+
+    /**
+     * Try to push an account as the default account.
+     *
+     * @param defaultAccount account to be set as the default account.
+     * @return true if the default account is successfully updated.
+     */
+    @NeededForTesting
+    public boolean tryPushDefaultAccount(DefaultAccount defaultAccount) {
+        if (!isValidDefaultAccount(defaultAccount)) {
+            Log.w(TAG, "Attempt to push an invalid default account.");
+            return false;
+        }
+
+        DefaultAccount previousDefaultAccount = pullDefaultAccount();
+
+        if (defaultAccount.equals(previousDefaultAccount)) {
+            Log.w(TAG, "Account has already been set as default before");
+            return false;
+        }
+
+        directlySetDefaultAccountInDb(defaultAccount);
+        return true;
+    }
+
+    private boolean isValidDefaultAccount(DefaultAccount defaultAccount) {
+        if (defaultAccount.getAccountCategory() == DefaultAccount.AccountCategory.CLOUD) {
+            return defaultAccount.getCloudAccount() != null
+                    && isSystemCloudAccount(defaultAccount.getCloudAccount())
+                    && !mSyncSettingsHelper.isSyncOff(defaultAccount.getCloudAccount());
+        }
+        return defaultAccount.getCloudAccount() == null;
+    }
+
+    /**
+     * Pull the default account from the DB.
+     */
+    @NeededForTesting
+    public DefaultAccount pullDefaultAccount() {
+        DefaultAccount defaultAccount = getDefaultAccountFromDb();
+
+        if (isValidDefaultAccount(defaultAccount)) {
+            return defaultAccount;
+        } else {
+            Log.w(TAG, "Default account stored in the DB is no longer valid.");
+            directlySetDefaultAccountInDb(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+            return DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT;
+        }
+    }
+
+    private void directlySetDefaultAccountInDb(DefaultAccount defaultAccount) {
+        switch (defaultAccount.getAccountCategory()) {
+            case UNKNOWN: {
+                mDbHelper.clearDefaultAccount();
+                break;
+            }
+            case DEVICE: {
+                mDbHelper.setDefaultAccount(AccountWithDataSet.LOCAL.getAccountName(),
+                        AccountWithDataSet.LOCAL.getAccountType());
+                break;
+            }
+            case CLOUD:
+                mDbHelper.setDefaultAccount(defaultAccount.getCloudAccount().name,
+                        defaultAccount.getCloudAccount().type);
+                break;
+            default:
+                Log.e(TAG, "Incorrect default account category");
+                break;
+        }
+    }
+
+    private boolean isSystemCloudAccount(Account account) {
+        if (account == null || !getEligibleSystemAccountTypes(mContext).contains(account.type)) {
+            return false;
+        }
+
+        Account[] accountsInThisType = mAccountManager.getAccountsByType(account.type);
+        for (Account currentAccount : accountsInThisType) {
+            if (currentAccount.equals(account)) {
+                return true;
+            }
+        }
+        return false;
+    }
+
+    private DefaultAccount getDefaultAccountFromDb() {
+        Account[] defaultAccountFromDb = mDbHelper.getDefaultAccountIfAny();
+        if (defaultAccountFromDb.length == 0) {
+            return DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT;
+        }
+
+        if (defaultAccountFromDb[0] == null) {
+            return DefaultAccount.DEVICE_DEFAULT_ACCOUNT;
+        }
+
+        if (defaultAccountFromDb[0].name.equals(AccountWithDataSet.LOCAL.getAccountName())
+                && defaultAccountFromDb[0].type.equals(AccountWithDataSet.LOCAL.getAccountType())) {
+            return DefaultAccount.DEVICE_DEFAULT_ACCOUNT;
+        }
+
+        return DefaultAccount.ofCloud(defaultAccountFromDb[0]);
+    }
+}
diff --git a/src/com/android/providers/contacts/SearchIndexManager.java b/src/com/android/providers/contacts/SearchIndexManager.java
index aeaa0e7d..38a91f1a 100644
--- a/src/com/android/providers/contacts/SearchIndexManager.java
+++ b/src/com/android/providers/contacts/SearchIndexManager.java
@@ -15,6 +15,8 @@
  */
 package com.android.providers.contacts;
 
+import static com.android.providers.contacts.flags.Flags.cp2SyncSearchIndexFlag;
+
 import android.content.ContentValues;
 import android.database.Cursor;
 import android.database.sqlite.SQLiteDatabase;
@@ -52,6 +54,7 @@ public class SearchIndexManager {
 
     private static final boolean VERBOSE_LOGGING = Log.isLoggable(TAG, Log.VERBOSE);
 
+    public static final int MAX_UPDATE_FILTER_CONTACTS = 5000;
     private static final int MAX_STRING_BUILDER_SIZE = 1024 * 10;
 
     public static final String PROPERTY_SEARCH_INDEX_VERSION = "search_index";
@@ -246,6 +249,7 @@ public class SearchIndexManager {
     private IndexBuilder mIndexBuilder = new IndexBuilder();
     private ContentValues mValues = new ContentValues();
     private String[] mSelectionArgs1 = new String[1];
+    private int mMaxUpdateFilterContacts = MAX_UPDATE_FILTER_CONTACTS;
 
     public SearchIndexManager(ContactsProvider2 contactsProvider) {
         this.mContactsProvider = contactsProvider;
@@ -296,44 +300,70 @@ public class SearchIndexManager {
             Log.v(TAG, "Updating search index for " + contactIds.size() +
                     " contacts / " + rawContactIds.size() + " raw contacts");
         }
+
+        final long contactsCount = contactIds.size() + rawContactIds.size();
+
         StringBuilder sb = new StringBuilder();
-        sb.append("(");
-        if (!contactIds.isEmpty()) {
-            // Select all raw contacts that belong to all contacts in contactIds
-            sb.append(RawContacts.CONTACT_ID + " IN (");
-            sb.append(TextUtils.join(",", contactIds));
-            sb.append(')');
-        }
-        if (!rawContactIds.isEmpty()) {
+        if (!cp2SyncSearchIndexFlag() || contactsCount <= mMaxUpdateFilterContacts) {
+            sb.append("(");
             if (!contactIds.isEmpty()) {
-                sb.append(" OR ");
+                // Select all raw contacts that belong to all contacts in contactIds
+                sb.append(RawContacts.CONTACT_ID + " IN (");
+                sb.append(TextUtils.join(",", contactIds));
+                sb.append(')');
             }
-            // Select all raw contacts that belong to the same contact as all raw contacts
-            // in rawContactIds. For every raw contact in rawContactIds that we are updating
-            // the index for, we need to rebuild the search index for all raw contacts belonging
-            // to the same contact, because we can only update the search index on a per-contact
-            // basis.
-            sb.append(RawContacts.CONTACT_ID + " IN " +
-                    "(SELECT " + RawContacts.CONTACT_ID + " FROM " + Tables.RAW_CONTACTS +
-                    " WHERE " + RawContactsColumns.CONCRETE_ID + " IN (");
-            sb.append(TextUtils.join(",", rawContactIds));
-            sb.append("))");
+            if (!rawContactIds.isEmpty()) {
+                if (!contactIds.isEmpty()) {
+                    sb.append(" OR ");
+                }
+                // Select all raw contacts that belong to the same contact as all raw contacts
+                // in rawContactIds. For every raw contact in rawContactIds that we are updating
+                // the index for, we need to rebuild the search index for all raw contacts belonging
+                // to the same contact, because we can only update the search index on a per-contact
+                // basis.
+                sb.append(RawContacts.CONTACT_ID + " IN "
+                        + "(SELECT " + RawContacts.CONTACT_ID + " FROM " + Tables.RAW_CONTACTS
+                        + " WHERE " + RawContactsColumns.CONCRETE_ID + " IN (");
+                sb.append(TextUtils.join(",", rawContactIds));
+                sb.append("))");
+            }
+            sb.append(")");
         }
 
-        sb.append(")");
-
-        // The selection to select raw_contacts.
-        final String rawContactsSelection = sb.toString();
+        // The selection to select raw_contacts. If the selection string is empty
+        // the entire search index table will be rebuilt.
+        String rawContactsSelection = sb.toString();
 
         // Remove affected search_index rows.
         final SQLiteDatabase db = mDbHelper.getWritableDatabase();
-        final int deleted = db.delete(Tables.SEARCH_INDEX,
-                ROW_ID_KEY + " IN (SELECT " +
-                    RawContacts.CONTACT_ID +
-                    " FROM " + Tables.RAW_CONTACTS +
-                    " WHERE " + rawContactsSelection +
-                    ")"
-                , null);
+        if (cp2SyncSearchIndexFlag()) {
+            // If the amount of contacts which need to be re-synced in the search index
+            // surpasses the limit, then simply clear the entire search index table and
+            // and rebuild it.
+            String whereClause = null;
+            if (contactsCount <= mMaxUpdateFilterContacts) {
+                // Only remove the provided contacts
+                whereClause =
+                    "rowid IN ("
+                        + TextUtils.join(",", contactIds)
+                    + """
+                    ) OR rowid IN (
+                        SELECT contact_id
+                        FROM raw_contacts
+                        WHERE raw_contacts._id IN ("""
+                            + TextUtils.join(",", rawContactIds)
+                    + "))";
+            }
+            db.delete(Tables.SEARCH_INDEX, whereClause, null);
+        } else {
+            db.delete(Tables.SEARCH_INDEX,
+                    ROW_ID_KEY + " IN (SELECT "
+                        + RawContacts.CONTACT_ID
+                        + " FROM " + Tables.RAW_CONTACTS
+                        + " WHERE " + rawContactsSelection
+                        + ")",
+                    null);
+        }
 
         // Then rebuild index for them.
         final int count = buildAndInsertIndex(db, rawContactsSelection);
@@ -404,6 +434,7 @@ public class SearchIndexManager {
         mValues.put(ROW_ID_KEY, contactId);
         db.insert(Tables.SEARCH_INDEX, null, mValues);
     }
+
     private int getSearchIndexVersion() {
         return Integer.parseInt(mDbHelper.getProperty(PROPERTY_SEARCH_INDEX_VERSION, "0"));
     }
@@ -412,6 +443,11 @@ public class SearchIndexManager {
         mDbHelper.setProperty(PROPERTY_SEARCH_INDEX_VERSION, String.valueOf(version));
     }
 
+    @VisibleForTesting
+    void setMaxUpdateFilterContacts(int maxUpdateFilterContacts) {
+        mMaxUpdateFilterContacts = maxUpdateFilterContacts;
+    }
+
     /**
      * Token separator that matches SQLite's "simple" tokenizer.
      * - Unicode codepoints >= 128: Everything
diff --git a/src/com/android/providers/contacts/SyncSettingsHelper.java b/src/com/android/providers/contacts/SyncSettingsHelper.java
new file mode 100644
index 00000000..1e950c41
--- /dev/null
+++ b/src/com/android/providers/contacts/SyncSettingsHelper.java
@@ -0,0 +1,70 @@
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
+package com.android.providers.contacts;
+
+import android.accounts.Account;
+
+import com.android.providers.contacts.util.NeededForTesting;
+
+import java.util.HashMap;
+import java.util.Map;
+
+@NeededForTesting
+public class SyncSettingsHelper {
+    @NeededForTesting
+    public enum SyncState { ON, OFF }
+
+    // TODO: Currently the sync state are stored in memory, which will be hooked up with the real
+    // sync settings.
+    private final Map<Account, SyncState> mSyncStates;
+
+    public SyncSettingsHelper() {
+        mSyncStates = new HashMap<>();
+    }
+
+    /**
+     * Turns on sync for the given account.
+     *
+     * @param account The account for which sync should be turned on.
+     */
+    @NeededForTesting
+    public void turnOnSync(Account account) {
+        mSyncStates.put(account, SyncState.ON);
+    }
+
+    /**
+     * Turns off sync for the given account.
+     *
+     * @param account The account for which sync should be turned off.
+     */
+    @NeededForTesting
+    public void turnOffSync(Account account) {
+        mSyncStates.put(account, SyncState.OFF);
+    }
+
+    /**
+     * Checks if sync is turned off for the given account.
+     *
+     * @param account The account to check.
+     * @return false if sync is off, true otherwise.
+     */
+    @NeededForTesting
+    public boolean isSyncOff(Account account) {
+        return mSyncStates.get(account) == SyncState.OFF;
+    }
+}
+
diff --git a/src/com/android/providers/contacts/aggregation/ContactAggregator2.java b/src/com/android/providers/contacts/aggregation/ContactAggregator2.java
index cb649cad..0accfb0e 100644
--- a/src/com/android/providers/contacts/aggregation/ContactAggregator2.java
+++ b/src/com/android/providers/contacts/aggregation/ContactAggregator2.java
@@ -16,9 +16,11 @@
 
 package com.android.providers.contacts.aggregation;
 
+import static com.android.providers.contacts.flags.Flags.cp2SyncSearchIndexFlag;
 import static com.android.providers.contacts.aggregation.util.RawContactMatcher.SCORE_THRESHOLD_PRIMARY;
 import static com.android.providers.contacts.aggregation.util.RawContactMatcher.SCORE_THRESHOLD_SECONDARY;
 import static com.android.providers.contacts.aggregation.util.RawContactMatcher.SCORE_THRESHOLD_SUGGEST;
+
 import android.database.Cursor;
 import android.database.sqlite.SQLiteDatabase;
 import android.provider.ContactsContract.AggregationExceptions;
@@ -33,6 +35,7 @@ import android.provider.ContactsContract.RawContacts;
 import android.text.TextUtils;
 import android.util.ArraySet;
 import android.util.Log;
+
 import com.android.providers.contacts.ContactsDatabaseHelper;
 import com.android.providers.contacts.ContactsDatabaseHelper.DataColumns;
 import com.android.providers.contacts.ContactsDatabaseHelper.NameLookupColumns;
@@ -44,12 +47,12 @@ import com.android.providers.contacts.ContactsProvider2;
 import com.android.providers.contacts.NameSplitter;
 import com.android.providers.contacts.PhotoPriorityResolver;
 import com.android.providers.contacts.TransactionContext;
-import com.android.providers.contacts.aggregation.util.CommonNicknameCache;
 import com.android.providers.contacts.aggregation.util.ContactAggregatorHelper;
 import com.android.providers.contacts.aggregation.util.MatchScore;
 import com.android.providers.contacts.aggregation.util.RawContactMatcher;
 import com.android.providers.contacts.aggregation.util.RawContactMatchingCandidates;
 import com.android.providers.contacts.database.ContactsTableUtil;
+
 import com.google.android.collect.Sets;
 import com.google.common.collect.HashMultimap;
 import com.google.common.collect.Multimap;
@@ -379,9 +382,16 @@ public class ContactAggregator2 extends AbstractContactAggregator {
 
                 if (currentRcCount == 0) {
                     // Delete a contact if it doesn't contain anything
+                    if (VERBOSE_LOGGING) {
+                        Log.v(TAG, "Deleting contact id: " + cid);
+                    }
                     ContactsTableUtil.deleteContact(db, cid);
                     mAggregatedPresenceDelete.bindLong(1, cid);
                     mAggregatedPresenceDelete.execute();
+                    if (cp2SyncSearchIndexFlag()) {
+                        // Make sure we remove the obsolete contact id from search index
+                        txContext.invalidateSearchIndexForContact(cid);
+                    }
                 } else {
                     updateAggregateData(txContext, cid);
                 }
diff --git a/test_common/Android.bp b/test_common/Android.bp
index 1ec6b9a9..1c9e4bf7 100644
--- a/test_common/Android.bp
+++ b/test_common/Android.bp
@@ -21,7 +21,7 @@ java_library {
     name: "ContactsProviderTestUtils",
     srcs: ["src/**/*.java"],
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "androidx.test.rules",
         "mockito-target-minus-junit4",
     ],
diff --git a/tests/Android.bp b/tests/Android.bp
index 83ef12be..96a0cc1b 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -12,11 +12,12 @@ android_test {
         "mockito-target-minus-junit4",
         "flag-junit",
         "android.content.pm.flags-aconfig-java",
+        "contactsprovider_flags_java_lib",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
     ],
 
     // Only compile source java files in this apk.
@@ -29,3 +30,42 @@ android_test {
         enabled: false,
     },
 }
+
+// Tests with all launch-able flags enabled by default.
+// All flags' value will be true unless overridden in the individual tests.
+test_module_config {
+    name: "ContactsProviderTestsWithAllFlagEnabled",
+    base: "ContactsProviderTests",
+    test_suites: ["device-tests"],
+
+    options: [
+        {
+            name: "feature-flags:flag-value",
+            value: "contacts/com.android.providers.contacts.flags.cp2_account_move_flag=true",
+        },
+        {
+            name: "feature-flags:flag-value",
+            value: "contacts/com.android.providers.contacts.flags.enable_new_default_account_rule_flag=true",
+        },
+
+    ],
+}
+
+// Tests with all launch-able flags disabled by default.
+// All flags' value will be false unless overridden in the individual tests.
+test_module_config {
+    name: "ContactsProviderTestsWithAllFlagDisabled",
+    base: "ContactsProviderTests",
+    test_suites: ["device-tests"],
+
+    options: [
+        {
+            name: "feature-flags:flag-value",
+            value: "contacts/com.android.providers.contacts.flags.cp2_account_move_flag=false",
+        },
+        {
+            name: "feature-flags:flag-value",
+            value: "contacts/com.android.providers.contacts.flags.enable_new_default_account_rule_flag=false",
+        },
+    ],
+}
diff --git a/tests/AndroidTest.xml b/tests/AndroidTest.xml
index 967614cc..7c6e2b91 100644
--- a/tests/AndroidTest.xml
+++ b/tests/AndroidTest.xml
@@ -17,6 +17,7 @@
     <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
         <option name="test-file-name" value="ContactsProviderTests.apk" />
     </target_preparer>
+    <target_preparer class="com.android.tradefed.targetprep.FeatureFlagTargetPreparer" />
 
     <option name="test-suite-tag" value="apct" />
     <option name="test-tag" value="ContactsProviderTests" />
diff --git a/tests/src/com/android/providers/contacts/AccountResolverTest.java b/tests/src/com/android/providers/contacts/AccountResolverTest.java
new file mode 100644
index 00000000..c0f82f3a
--- /dev/null
+++ b/tests/src/com/android/providers/contacts/AccountResolverTest.java
@@ -0,0 +1,717 @@
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
+package com.android.providers.contacts;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertThrows;
+import static org.mockito.Mockito.when;
+
+import android.accounts.Account;
+import android.content.ContentValues;
+import android.net.Uri;
+import android.provider.ContactsContract.RawContacts;
+
+import androidx.test.filters.SmallTest;
+
+import com.android.providers.contacts.DefaultAccount.AccountCategory;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.Mock;
+import org.mockito.MockitoAnnotations;
+
+@SmallTest
+@RunWith(JUnit4.class)
+public class AccountResolverTest {
+    @Mock
+    private ContactsDatabaseHelper mDbHelper;
+    @Mock
+    private DefaultAccountManager mDefaultAccountManager;
+
+    private AccountResolver mAccountResolver;
+
+    @Before
+    public void setUp() {
+        MockitoAnnotations.initMocks(this);
+        mAccountResolver = new AccountResolver(mDbHelper, mDefaultAccountManager);
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_ignoreDefaultAccount_accountAndDataSetInUri() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "test_account")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "com.google")
+                .appendQueryParameter(RawContacts.DATA_SET, "test_data_set")
+                .build();
+        ContentValues values = new ContentValues();
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertEquals("test_account", result.getAccountName());
+        assertEquals("com.google", result.getAccountType());
+        assertEquals("test_data_set", result.getDataSet());
+        assertEquals("test_data_set", values.getAsString(RawContacts.DATA_SET));
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_defaultAccountIsUnknown_accountAndDataSetInUri() {
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "test_account")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "com.google")
+                .appendQueryParameter(RawContacts.DATA_SET, "test_data_set")
+                .build();
+        ContentValues values = new ContentValues();
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/true);
+
+        assertEquals("test_account", result.getAccountName());
+        assertEquals("com.google", result.getAccountType());
+        assertEquals("test_data_set", result.getDataSet());
+        assertEquals("test_data_set", values.getAsString(RawContacts.DATA_SET));
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_ignoreDefaultAccount_accountInUriDataSetInValues() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "test_account")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "com.google")
+                .build();
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.DATA_SET, "test_data_set");
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertEquals("test_account", result.getAccountName());
+        assertEquals("com.google", result.getAccountType());
+        assertEquals("test_data_set", result.getDataSet());
+        assertEquals("test_data_set", values.getAsString(RawContacts.DATA_SET));
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_applyDefaultAccount_accountInUriDataSetInValues() {
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(new DefaultAccount(
+                AccountCategory.CLOUD, new Account("randomaccount1@gmail.com", "com.google")));
+
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "test_account")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "com.google")
+                .build();
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.DATA_SET, "test_data_set");
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertEquals("test_account", result.getAccountName());
+        assertEquals("com.google", result.getAccountType());
+        assertEquals("test_data_set", result.getDataSet());
+        assertEquals("test_data_set", values.getAsString(RawContacts.DATA_SET));
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_ignoreDefaultAccount_noAccount() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
+        ContentValues values = new ContentValues();
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertNull(result);
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_defaultAccountIsUnknown_noAccount() {
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
+        ContentValues values = new ContentValues();
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertNull(result);
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_defaultAccountIsDevice_noAccount() {
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
+        ContentValues values = new ContentValues();
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertNull(result);
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_defaultAccountIsCloud_noAccount() {
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(new DefaultAccount(
+                AccountCategory.CLOUD, new Account("randomaccount1@gmail.com", "com.google")));
+
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
+        ContentValues values = new ContentValues();
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertNull(result);
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_accountInValuesOnly() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts"); // No account in URI
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "test_account");
+        values.put(RawContacts.ACCOUNT_TYPE, "com.google");
+        values.put(RawContacts.DATA_SET, "test_data_set");
+
+        AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertEquals("test_account", result1.getAccountName());
+        assertEquals("com.google", result1.getAccountType());
+        assertEquals("test_data_set", result1.getDataSet());
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+
+        AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/true);
+
+        assertEquals("test_account", result2.getAccountName());
+        assertEquals("com.google", result2.getAccountType());
+        assertEquals("test_data_set", result2.getDataSet());
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_invalidAccountInUri() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "invalid_account")
+                .build(); // Missing ACCOUNT_TYPE
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "test_account");
+        values.put(RawContacts.ACCOUNT_TYPE, "com.google");
+        values.put(RawContacts.DATA_SET, "test_data_set");
+
+        when(mDbHelper.exceptionMessage(
+                "Must specify both or neither of ACCOUNT_NAME and ACCOUNT_TYPE", uri))
+                .thenReturn("Test Exception Message");
+
+        // Expecting an exception due to the invalid account in the URI
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values,
+                    /*applyDefaultAccount=*/false);
+        });
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+        // Expecting an exception due to the invalid account in the URI
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values,
+                    /*applyDefaultAccount=*/true);
+        });
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_invalidAccountInValues() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "test_account")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "com.google")
+                .build();
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "invalid_account"); // Invalid account
+        values.put(RawContacts.DATA_SET, "test_data_set");
+
+        when(mDbHelper.exceptionMessage(
+                "Must specify both or neither of ACCOUNT_NAME and ACCOUNT_TYPE", uri))
+                .thenReturn("Test Exception Message");
+
+        // Expecting an exception due to the invalid account in the values
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+        });
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+        // Expecting an exception due to the invalid account in the URI
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+        });
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_matchingAccounts() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "test_account")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "com.google")
+                .build();
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "test_account");
+        values.put(RawContacts.ACCOUNT_TYPE, "com.google");
+        values.put(RawContacts.DATA_SET, "test_data_set");
+
+        AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertEquals("test_account", result1.getAccountName());
+        assertEquals("com.google", result1.getAccountType());
+        assertEquals("test_data_set", result1.getDataSet());
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+
+        AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertEquals("test_account", result2.getAccountName());
+        assertEquals("com.google", result2.getAccountType());
+        assertEquals("test_data_set", result2.getDataSet());
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_invalidAccountsBoth() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "invalid_account_uri")
+                .build(); // Missing ACCOUNT_TYPE
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "invalid_account_values");
+        values.put(RawContacts.DATA_SET, "test_data_set");
+
+        when(mDbHelper.exceptionMessage(
+                "Must specify both or neither of ACCOUNT_NAME and ACCOUNT_TYPE", uri))
+                .thenReturn("Test Exception Message");
+
+        // Expecting an exception due to the invalid account in the URI
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+        });
+
+        // Expecting an exception due to the invalid account in the URI, regardless of what is the
+        // default account
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+        });
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+        });
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, new Account(
+                        "test_account", "com.google"
+                )));
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+        });
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_partialAccountInUri() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "test_account")
+                .build();
+        ContentValues values = new ContentValues();
+
+        when(mDbHelper.exceptionMessage(
+                "Must specify both or neither of ACCOUNT_NAME and ACCOUNT_TYPE", uri))
+                .thenReturn("Test Exception Message");
+
+        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+        });
+        assertEquals("Test Exception Message", exception.getMessage());
+
+        // Expecting an exception due to the partial account in uri, regardless of what is the
+        // default account
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+        });
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+        });
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, new Account(
+                        "test_account", "com.google"
+                )));
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+        });
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_partialAccountInValues() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "test_account");
+
+        when(mDbHelper.exceptionMessage(
+                "Must specify both or neither of ACCOUNT_NAME and ACCOUNT_TYPE", uri))
+                .thenReturn("Test Exception Message");
+
+        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+        });
+        assertEquals("Test Exception Message", exception.getMessage());
+
+        // Expecting an exception due to the partial account in uri, regardless of what is the
+        // default account
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+        exception = assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+        });
+        assertEquals("Test Exception Message", exception.getMessage());
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+        exception = assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+        });
+        assertEquals("Test Exception Message", exception.getMessage());
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, new Account(
+                        "test_account", "com.google"
+                )));
+        exception = assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+        });
+        assertEquals("Test Exception Message", exception.getMessage());
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_mismatchedAccounts() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "test_account_uri")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "com.google_uri")
+                .build();
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "test_account_values");
+        values.put(RawContacts.ACCOUNT_TYPE, "com.google_values");
+
+        when(mDbHelper.exceptionMessage(
+                "When both specified, ACCOUNT_NAME and ACCOUNT_TYPE must match", uri))
+                .thenReturn("Test Exception Message");
+
+        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+        });
+        assertEquals("Test Exception Message", exception.getMessage());
+
+        // Expecting an exception due to the uri and content value's account info mismatching,
+        // regardless of what is the default account
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+        exception = assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+        });
+        assertEquals("Test Exception Message", exception.getMessage());
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, new Account(
+                        "test_account", "com.google"
+                )));
+        exception = assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/false);
+        });
+        assertEquals("Test Exception Message", exception.getMessage());
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_ignoreDefaultAccount_emptyAccountInUri() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "")
+                .build();
+        ContentValues values = new ContentValues();
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertNull(result); // Expect null result as account is effectively absent
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_defaultAccountIsDeviceOrUnknown_emptyAccountInUri() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "")
+                .build();
+        ContentValues values = new ContentValues();
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+        AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/true);
+        assertNull(result1); // Expect null result as account is effectively absent
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+        AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/true);
+        assertNull(result2); // Expect null result as account is effectively absent
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_defaultAccountIsCloud_emptyAccountInUri() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "")
+                .build();
+        ContentValues values = new ContentValues();
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                new DefaultAccount(AccountCategory.CLOUD,
+                        new Account("test_user2", "com.google")));
+
+        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+        });
+        assertEquals("Cannot write contacts to local accounts when default account is set to cloud",
+                exception.getMessage());
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_ignoreDefaultAccount_emptyAccountInValues() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "");
+        values.put(RawContacts.ACCOUNT_TYPE, "");
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertNull(result); // Expect null result as account is effectively absent
+    }
+
+
+    @Test
+    public void testResolveAccountWithDataSet_defaultAccountDeviceOrUnknown_emptyAccountInValues() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "");
+        values.put(RawContacts.ACCOUNT_TYPE, "");
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+        AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/true);
+        assertNull(result1); // Expect null result as account is effectively absent
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+        AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/true);
+        assertNull(result2); // Expect null result as account is effectively absent
+    }
+
+
+    @Test
+    public void testResolveAccountWithDataSet_defaultAccountIsCloud_emptyAccountInValues() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts");
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "");
+        values.put(RawContacts.ACCOUNT_TYPE, "");
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                new DefaultAccount(AccountCategory.CLOUD,
+                        new Account("test_user2", "com.google")));
+
+        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+        });
+        assertEquals("Cannot write contacts to local accounts when default account is set to cloud",
+                exception.getMessage());
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_ignoreDefaultAccount_emptyAccountInUriAndValues() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "")
+                .build();
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "");
+        values.put(RawContacts.ACCOUNT_TYPE, "");
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertNull(result); // Expect null result as account is effectively absent
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_defaultDeviceOrUnknown_emptyAccountInUriAndValues() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "")
+                .build();
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "");
+        values.put(RawContacts.ACCOUNT_TYPE, "");
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+        AccountWithDataSet result1 = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/true);
+        assertNull(result1); // Expect null result as account is effectively absent
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+        AccountWithDataSet result2 = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/true);
+        assertNull(result2); // Expect null result as account is effectively absent
+    }
+
+    @Test
+    public void testResolveAccountWithDataSet_defaultAccountIsCloud_emptyAccountInUriAndValues() {
+        Uri uri = Uri.parse("content://com.android.contacts/raw_contacts")
+                .buildUpon()
+                .appendQueryParameter(RawContacts.ACCOUNT_NAME, "")
+                .appendQueryParameter(RawContacts.ACCOUNT_TYPE, "")
+                .build();
+        ContentValues values = new ContentValues();
+        values.put(RawContacts.ACCOUNT_NAME, "");
+        values.put(RawContacts.ACCOUNT_TYPE, "");
+
+        AccountWithDataSet result = mAccountResolver.resolveAccountWithDataSet(
+                uri, values, /*applyDefaultAccount=*/false);
+
+        assertNull(result); // Expect null result as account is effectively absent
+
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                new DefaultAccount(AccountCategory.CLOUD,
+                        new Account("test_user2", "com.google")));
+
+        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.resolveAccountWithDataSet(uri, values, /*applyDefaultAccount=*/true);
+        });
+        assertEquals("Cannot write contacts to local accounts when default account is set to cloud",
+                exception.getMessage());
+    }
+
+
+    @Test
+    public void testCheckAccountIsWritable_bothAccountNameAndTypeAreNullOrEmpty_NoException() {
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+
+        mAccountResolver.checkAccountIsWritable("", "");
+        mAccountResolver.checkAccountIsWritable(null, "");
+        mAccountResolver.checkAccountIsWritable("", null);
+        mAccountResolver.checkAccountIsWritable(null, null);
+        // No exception expected
+    }
+
+    @Test
+    public void testCheckAccountIsWritable_eitherAccountNameOrTypeEmpty_ThrowsException() {
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.checkAccountIsWritable("accountName", "");
+        });
+
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.checkAccountIsWritable("accountName", null);
+        });
+
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.checkAccountIsWritable("", "accountType");
+        });
+        assertThrows(IllegalArgumentException.class, () -> {
+            mAccountResolver.checkAccountIsWritable(null, "accountType");
+        });
+    }
+
+    @Test
+    public void testCheckAccountIsWritable_defaultAccountIsCloud() {
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                new DefaultAccount(AccountCategory.CLOUD,
+                        new Account("test_user1", "com.google")));
+
+        mAccountResolver.checkAccountIsWritable("test_user1", "com.google");
+        mAccountResolver.checkAccountIsWritable("test_user2", "com.google");
+        mAccountResolver.checkAccountIsWritable("test_user3", "com.whatsapp");
+        assertThrows(IllegalArgumentException.class, () ->
+                mAccountResolver.checkAccountIsWritable("", ""));
+        assertThrows(IllegalArgumentException.class, () ->
+                mAccountResolver.checkAccountIsWritable(null, null));
+        // No exception expected
+    }
+
+    @Test
+    public void testCheckAccountIsWritable_defaultAccountIsDevice() {
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT);
+
+        mAccountResolver.checkAccountIsWritable("test_user1", "com.google");
+        mAccountResolver.checkAccountIsWritable("test_user2", "com.google");
+        mAccountResolver.checkAccountIsWritable("test_user3", "com.whatsapp");
+        mAccountResolver.checkAccountIsWritable("", "");
+        mAccountResolver.checkAccountIsWritable(null, null);
+        // No exception expected
+    }
+
+
+    @Test
+    public void testCheckAccountIsWritable_defaultAccountIsUnknown() {
+        when(mDefaultAccountManager.pullDefaultAccount()).thenReturn(
+                DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT);
+
+        mAccountResolver.checkAccountIsWritable("test_user1", "com.google");
+        mAccountResolver.checkAccountIsWritable("test_user2", "com.google");
+        mAccountResolver.checkAccountIsWritable("test_user3", "com.whatsapp");
+        mAccountResolver.checkAccountIsWritable("", "");
+        mAccountResolver.checkAccountIsWritable(null, null);
+        // No exception expected
+    }
+}
diff --git a/tests/src/com/android/providers/contacts/ContactsActor.java b/tests/src/com/android/providers/contacts/ContactsActor.java
index 0d7d9b3b..9e5c69a5 100644
--- a/tests/src/com/android/providers/contacts/ContactsActor.java
+++ b/tests/src/com/android/providers/contacts/ContactsActor.java
@@ -17,6 +17,7 @@
 package com.android.providers.contacts;
 
 import static android.content.pm.UserProperties.SHOW_IN_LAUNCHER_WITH_PARENT;
+
 import static com.android.providers.contacts.ContactsActor.MockUserManager.CLONE_PROFILE_USER;
 import static com.android.providers.contacts.ContactsActor.MockUserManager.PRIMARY_USER;
 
@@ -386,7 +387,11 @@ public class ContactsActor {
             @Override
             public File getFilesDir() {
                 // TODO: Need to figure out something more graceful than this.
-                return new File("/data/data/com.android.providers.contacts.tests/files");
+                // The returned file path must take into account the user under
+                // which the test is running given that in HSUM the test doesn't
+                // run under the system user.
+                return new File("/data/user/" + UserHandle.myUserId()
+                        + "/com.android.providers.contacts.tests/files");
             }
 
             @Override
diff --git a/tests/src/com/android/providers/contacts/ContactsDatabaseHelperTest.java b/tests/src/com/android/providers/contacts/ContactsDatabaseHelperTest.java
index 40c3b8ac..9901fdb2 100644
--- a/tests/src/com/android/providers/contacts/ContactsDatabaseHelperTest.java
+++ b/tests/src/com/android/providers/contacts/ContactsDatabaseHelperTest.java
@@ -512,39 +512,56 @@ public class ContactsDatabaseHelperTest extends BaseContactsProvider2Test {
     }
 
     public void testGetAndSetDefaultAccount() {
-        Account account = mDbHelper.getDefaultAccount();
-        assertNull(account);
+        // Test: Initially, no default account exists
+        Account[] accounts = mDbHelper.getDefaultAccountIfAny();
+        assertEquals(0, accounts.length); // Check for empty array
 
+        // Test: Setting and getting valid default account
         mDbHelper.setDefaultAccount("a", "b");
-        account = mDbHelper.getDefaultAccount();
-        assertEquals("a", account.name);
-        assertEquals("b", account.type);
+        accounts = mDbHelper.getDefaultAccountIfAny();
+        assertEquals(1, accounts.length);
+        assertEquals("a", accounts[0].name);
+        assertEquals("b", accounts[0].type);
 
         mDbHelper.setDefaultAccount("c", "d");
-        account = mDbHelper.getDefaultAccount();
-        assertEquals("c", account.name);
-        assertEquals("d", account.type);
+        accounts = mDbHelper.getDefaultAccountIfAny();
+        assertEquals(1, accounts.length);
+        assertEquals("c", accounts[0].name);
+        assertEquals("d", accounts[0].type);
 
+        // Test: set the default account to NULL.
         mDbHelper.setDefaultAccount(null, null);
-        account = mDbHelper.getDefaultAccount();
-        assertNull(account);
+        accounts = mDbHelper.getDefaultAccountIfAny();
+        assertEquals(1, accounts.length);
+        assertNull(accounts[0]);
 
-        // Invalid account (not-null account name and null account type) throws exception.
+        // Test: Invalid account (non-null name, null type)
         try {
             mDbHelper.setDefaultAccount("name", null);
             fail("Setting default account to an invalid account should fail.");
         } catch (IllegalArgumentException e) {
-            // expected.
+            // Expected exception
         }
-        account = mDbHelper.getDefaultAccount();
-        assertNull(account);
+        accounts = mDbHelper.getDefaultAccountIfAny();
+        assertEquals(1, accounts.length);
+        assertNull(accounts[0]);
 
-        // Update default account to an existing account
+        // Test: Update default account to an existing account
         mDbHelper.setDefaultAccount("a", "b");
-        account = mDbHelper.getDefaultAccount();
-        assertEquals("a", account.name);
-        assertEquals("b", account.type);
+        accounts = mDbHelper.getDefaultAccountIfAny();
+        assertEquals(1, accounts.length);
+        assertEquals("a", accounts[0].name);
+        assertEquals("b", accounts[0].type);
 
+        // Test: Unset the default account.
+        ContentValues values = new ContentValues();
+        values.put(ContactsDatabaseHelper.AccountsColumns.IS_DEFAULT, 0);
+        mDb.update(Tables.ACCOUNTS, values, null, null);
+
+        accounts = mDbHelper.getDefaultAccountIfAny();
+        assertEquals(0, accounts.length); // Check for empty array
+
+        // Test: Verify total accounts in the database (including added defaults)
         try (Cursor cursor = mDbHelper.getReadableDatabase().query(Tables.ACCOUNTS, new String[]{
                 ContactsDatabaseHelper.AccountsColumns.ACCOUNT_NAME,
                 ContactsDatabaseHelper.AccountsColumns.ACCOUNT_TYPE
@@ -552,4 +569,72 @@ public class ContactsDatabaseHelperTest extends BaseContactsProvider2Test {
             assertEquals(3, cursor.getCount());
         }
     }
+
+    void createRawContact(AccountWithDataSet account) {
+        createRawContact(account, /* deleted= */ false);
+    }
+
+    void createRawContact(AccountWithDataSet account, boolean deleted) {
+        // Create an account.
+        final long accountId = mDbHelper.getOrCreateAccountIdInTransaction(account);
+        // Create a raw contact.
+        ContentValues rawContactValues = new ContentValues();
+        rawContactValues.put(ContactsDatabaseHelper.RawContactsColumns.ACCOUNT_ID, accountId);
+        if (deleted) {
+            rawContactValues.put(RawContactsColumns.CONCRETE_DELETED, 1);
+        }
+        mDb.insert(Tables.RAW_CONTACTS, null, rawContactValues);
+    }
+
+    public void testCountRawContactsForAccount() {
+        createRawContact(
+                new AccountWithDataSet("testName", "testType", /* dataSet= */ null));
+
+        int count = mDbHelper.countRawContactsQuery(Set.of(
+                new AccountWithDataSet("testName", "testType", /* dataSet= */ null)
+        ));
+
+        assertEquals(1, count);
+    }
+
+    public void testCountRawContactsForAccountsNullAccount() {
+        createRawContact(new AccountWithDataSet(null, null, null));
+        createRawContact(new AccountWithDataSet(null, null, null));
+
+        int count = mDbHelper.countRawContactsQuery(Set.of(
+                new AccountWithDataSet(null, null, null)
+        ));
+
+        assertEquals(2, count);
+    }
+
+    public void testCountRawContactsDoesNotIncludeDeletedContacts() {
+        createRawContact(new AccountWithDataSet(null, null, null));
+        createRawContact(new AccountWithDataSet(null, null, null),
+                /* deleted= */ true
+        );
+
+        int count = mDbHelper.countRawContactsQuery(Set.of(
+                new AccountWithDataSet(null, null, null)
+        ));
+
+        assertEquals(1, count);
+    }
+
+    public void testCountRawContactsForAccountsEmptyLocalAccount() {
+        int count = mDbHelper.countRawContactsQuery(Set.of(AccountWithDataSet.LOCAL));
+
+        assertEquals(0, count);
+    }
+
+    public void testCountRawContactsForUnrelatedAccount() {
+        createRawContact(
+                new AccountWithDataSet("testName", "testType", /* dataSet= */ null));
+
+        int count = mDbHelper.countRawContactsQuery(Set.of(
+                new AccountWithDataSet(null, null, null)
+        ));
+
+        assertEquals(0, count);
+    }
 }
diff --git a/tests/src/com/android/providers/contacts/ContactsProvider2Test.java b/tests/src/com/android/providers/contacts/ContactsProvider2Test.java
index d8d7ed31..8696c59a 100644
--- a/tests/src/com/android/providers/contacts/ContactsProvider2Test.java
+++ b/tests/src/com/android/providers/contacts/ContactsProvider2Test.java
@@ -41,6 +41,9 @@ import android.database.sqlite.SQLiteDatabase;
 import android.net.Uri;
 import android.os.AsyncTask;
 import android.os.Bundle;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
 import android.provider.ContactsContract;
 import android.provider.ContactsContract.AggregationExceptions;
 import android.provider.ContactsContract.CommonDataKinds.Callable;
@@ -83,7 +86,8 @@ import android.test.MoreAsserts;
 import android.text.TextUtils;
 import android.util.ArraySet;
 
-import androidx.test.filters.LargeTest;
+import androidx.test.annotation.UiThreadTest;
+import androidx.test.runner.AndroidJUnit4;
 
 import com.android.internal.util.ArrayUtils;
 import com.android.providers.contacts.ContactsActor.AlteringUserContext;
@@ -96,6 +100,7 @@ import com.android.providers.contacts.ContactsDatabaseHelper.DbProperties;
 import com.android.providers.contacts.ContactsDatabaseHelper.PresenceColumns;
 import com.android.providers.contacts.ContactsDatabaseHelper.RawContactsColumns;
 import com.android.providers.contacts.ContactsDatabaseHelper.Tables;
+import com.android.providers.contacts.flags.Flags;
 import com.android.providers.contacts.tests.R;
 import com.android.providers.contacts.testutil.CommonDatabaseUtils;
 import com.android.providers.contacts.testutil.ContactUtil;
@@ -111,6 +116,12 @@ import com.android.providers.contacts.util.UserUtils;
 import com.google.android.collect.Lists;
 import com.google.android.collect.Sets;
 
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
 import java.io.FileInputStream;
 import java.io.IOException;
 import java.io.OutputStream;
@@ -131,7 +142,8 @@ import java.util.Set;
            com.android.providers.contacts.tests/android.test.InstrumentationTestRunner
  * </code>
  */
-@LargeTest
+@RunWith(AndroidJUnit4.class)
+@UiThreadTest
 public class ContactsProvider2Test extends BaseContactsProvider2Test {
 
     private static final String TAG = ContactsProvider2Test.class.getSimpleName();
@@ -147,6 +159,9 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     static final String TEST_PHONE_ACCOUNT_HANDLE_ICC_ID2 = "T5E5S5T5I5C5C5I5D";
     static final String TEST_COMPONENT_NAME = "foo/bar";
 
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+
     private int mOldMinMatch1;
     private int mOldMinMatch2;
 
@@ -155,8 +170,9 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     private ContactsDatabaseHelper mDbHelper;
     private BroadcastReceiver mBroadcastReceiver;
 
+    @Before
     @Override
-    protected void setUp() throws Exception {
+    public void setUp() throws Exception {
         super.setUp();
         mContactsProvider2 = (ContactsProvider2) getProvider();
         mDbHelper = mContactsProvider2.getThreadActiveDatabaseHelperForTest();
@@ -165,10 +181,12 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         mOldMinMatch2 = mDbHelper.getMinMatchForTest();
         PhoneNumberUtils.setMinMatchForTest(MIN_MATCH);
         mDbHelper.setMinMatchForTest(MIN_MATCH);
+        assertNotNull(mDbHelper);
     }
 
+    @After
     @Override
-    protected void tearDown() throws Exception {
+    public void tearDown() throws Exception {
         final ContactsProvider2 cp = (ContactsProvider2) getProvider();
         //final ContactsDatabaseHelper dbHelper = cp.getThreadActiveDatabaseHelperForTest();
         PhoneNumberUtils.setMinMatchForTest(mOldMinMatch1);
@@ -243,6 +261,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         return contactsDatabaseHelper;
     }
 
+    @Test
     public void testPhoneAccountHandleMigrationSimEvent() throws IOException {
         ContactsDatabaseHelper originalContactsDatabaseHelper
                 = mContactsProvider2.getContactsDatabaseHelperForTest();
@@ -302,6 +321,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         mContactsProvider2.setContactsDatabaseHelperForTest(originalContactsDatabaseHelper);
     }
 
+    @Test
     public void testPhoneAccountHandleMigrationInitiation() throws IOException {
         ContactsDatabaseHelper originalContactsDatabaseHelper
                 = mContactsProvider2.getContactsDatabaseHelperForTest();
@@ -357,6 +377,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         mContactsProvider2.setContactsDatabaseHelperForTest(originalContactsDatabaseHelper);
     }
 
+    @Test
     public void testPhoneAccountHandleMigrationPendingStatus() {
         // Mock ContactsDatabaseHelper
         ContactsDatabaseHelper contactsDatabaseHelper = getMockContactsDatabaseHelper(
@@ -374,6 +395,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertTrue(phoneAccountHandleMigrationUtils.isPhoneAccountMigrationPending());
     }
 
+    @Test
     public void testConvertEnterpriseUriWithEnterpriseDirectoryToLocalUri() {
         String phoneNumber = "886";
         String directory = String.valueOf(Directory.ENTERPRISE_DEFAULT);
@@ -391,6 +413,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertUriEquals(expectedUri, localUri);
     }
 
+    @Test
     public void testConvertEnterpriseUriWithPersonalDirectoryToLocalUri() {
         String phoneNumber = "886";
         String directory = String.valueOf(Directory.DEFAULT);
@@ -408,6 +431,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertUriEquals(expectedUri, localUri);
     }
 
+    @Test
     public void testConvertEnterpriseUriWithoutDirectoryToLocalUri() {
         String phoneNumber = "886";
         boolean isSip = true;
@@ -421,6 +445,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertUriEquals(expectedUri, localUri);
     }
 
+    @Test
     public void testContactsProjection() {
         assertProjection(Contacts.CONTENT_URI, new String[]{
                 Contacts._ID,
@@ -462,6 +487,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testContactsStrequentProjection() {
         assertProjection(Contacts.CONTENT_STREQUENT_URI, new String[]{
                 Contacts._ID,
@@ -505,6 +531,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testContactsStrequentPhoneOnlyProjection() {
         assertProjection(Contacts.CONTENT_STREQUENT_URI.buildUpon()
                     .appendQueryParameter(ContactsContract.STREQUENT_PHONE_ONLY, "true").build(),
@@ -555,6 +582,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testContactsWithSnippetProjection() {
         assertProjection(Contacts.CONTENT_FILTER_URI.buildUpon().appendPath("nothing").build(),
             new String[]{
@@ -598,6 +626,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testRawContactsProjection() {
         assertProjection(RawContacts.CONTENT_URI, new String[]{
                 RawContacts._ID,
@@ -638,6 +667,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testDataProjection() {
         assertProjection(Data.CONTENT_URI, new String[]{
                 Data._ID,
@@ -728,6 +758,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testDistinctDataProjection() {
         assertProjection(Phone.CONTENT_FILTER_URI.buildUpon().appendPath("123").build(),
             new String[]{
@@ -809,6 +840,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testEntityProjection() {
         assertProjection(
             Uri.withAppendedPath(ContentUris.withAppendedId(Contacts.CONTENT_URI, 0),
@@ -907,6 +939,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testRawEntityProjection() {
         assertProjection(RawContactsEntity.CONTENT_URI, new String[]{
                 RawContacts.Entity.DATA_ID,
@@ -958,6 +991,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testPhoneLookupProjection() {
         assertProjection(PhoneLookup.CONTENT_FILTER_URI.buildUpon().appendPath("123").build(),
             new String[]{
@@ -993,6 +1027,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testPhoneLookupEnterpriseProjection() {
         assertProjection(PhoneLookup.ENTERPRISE_CONTENT_FILTER_URI
                         .buildUpon().appendPath("123").build(),
@@ -1029,6 +1064,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 });
     }
 
+    @Test
     public void testSipPhoneLookupProjection() {
         assertContainProjection(PhoneLookup.CONTENT_FILTER_URI.buildUpon().appendPath("123")
                         .appendQueryParameter(PhoneLookup.QUERY_PARAMETER_SIP_ADDRESS, "1")
@@ -1058,6 +1094,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 });
     }
 
+    @Test
     public void testSipPhoneLookupEnterpriseProjection() {
         assertContainProjection(PhoneLookup.ENTERPRISE_CONTENT_FILTER_URI
                         .buildUpon()
@@ -1089,6 +1126,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 });
     }
 
+    @Test
     public void testGroupsProjection() {
         assertProjection(Groups.CONTENT_URI, new String[]{
                 Groups._ID,
@@ -1117,6 +1155,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testGroupsSummaryProjection() {
         assertProjection(Groups.CONTENT_SUMMARY_URI, new String[]{
                 Groups._ID,
@@ -1148,6 +1187,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testAggregateExceptionProjection() {
         assertProjection(AggregationExceptions.CONTENT_URI, new String[]{
                 AggregationExceptionColumns._ID,
@@ -1157,6 +1197,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testSettingsProjection() {
         assertProjection(Settings.CONTENT_URI, new String[]{
                 Settings.ACCOUNT_NAME,
@@ -1170,6 +1211,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testStatusUpdatesProjection() {
         assertProjection(StatusUpdates.CONTENT_URI, new String[]{
                 PresenceColumns.RAW_CONTACT_ID,
@@ -1188,6 +1230,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testDirectoryProjection() {
         assertProjection(Directory.CONTENT_URI, new String[]{
                 Directory._ID,
@@ -1203,6 +1246,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testProviderStatusProjection() {
         assertProjection(ProviderStatus.CONTENT_URI, new String[]{
                 ProviderStatus.STATUS,
@@ -1210,6 +1254,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         });
     }
 
+    @Test
     public void testRawContactsInsert() {
         ContentValues values = new ContentValues();
 
@@ -1241,6 +1286,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNetworkNotified(true);
     }
 
+    @Test
     public void testDataDirectoryWithLookupUri() {
         ContentValues values = new ContentValues();
 
@@ -1286,6 +1332,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         cursor.close();
     }
 
+    @Test
     public void testContactEntitiesWithIdBasedUri() {
         ContentValues values = new ContentValues();
         Account account1 = new Account("act1", "actype1");
@@ -1308,6 +1355,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEntityRows(entityUri, contactId, rawContactId1, rawContactId2);
     }
 
+    @Test
     public void testContactEntitiesWithLookupUri() {
         ContentValues values = new ContentValues();
         Account account1 = new Account("act1", "actype1");
@@ -1404,6 +1452,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         cursor.close();
     }
 
+    @Test
     public void testDataInsert() {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver, "John", "Doe");
 
@@ -1432,6 +1481,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNetworkNotified(true);
     }
 
+    @Test
     public void testDataInsertAndUpdateHashId() {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver, "John", "Doe");
 
@@ -1489,6 +1539,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(dataUri, Data.HASH_ID, null);
     }
 
+    @Test
     public void testDataInsertAndUpdateHashId_Photo() {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver, "John", "Doe");
 
@@ -1513,6 +1564,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(dataUri, Data.HASH_ID, hashId);
     }
 
+    @Test
     public void testDataInsertPhoneNumberTooLongIsTrimmed() {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver, "John", "Doe");
 
@@ -1539,6 +1591,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertSelection(dataUri, expected, Data._ID, dataId);
     }
 
+    @Test
     public void testRawContactDataQuery() {
         Account account1 = new Account("a", "b");
         Account account2 = new Account("c", "d");
@@ -1553,6 +1606,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(uri2, Data._ID, ContentUris.parseId(dataUri2)) ;
     }
 
+    @Test
     public void testPhonesQuery() {
 
         ContentValues values = new ContentValues();
@@ -1589,6 +1643,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(ContentUris.withAppendedId(Phone.CONTENT_URI, phoneId), values);
     }
 
+    @Test
     public void testPhonesWithMergedContacts() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver);
         insertPhoneNumber(rawContactId1, "123456789", true);
@@ -1628,6 +1683,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(dedupeUri, values1);
     }
 
+    @Test
     public void testPhonesNormalizedNumber() {
         final long rawContactId = RawContactUtil.createRawContact(mResolver);
 
@@ -1730,6 +1786,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 );
     }
 
+    @Test
     public void testPhonesFilterQuery() {
         testPhonesFilterQueryInter(Phone.CONTENT_FILTER_URI);
     }
@@ -1839,6 +1896,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(filterUri6, new ContentValues[] {values1, values2, values3} );
     }
 
+    @Test
     public void testPhonesFilterSearchParams() {
         final long rid1 = RawContactUtil.createRawContactWithName(mResolver, "Dad", null);
         insertPhoneNumber(rid1, "123-456-7890");
@@ -1874,6 +1932,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         );
     }
 
+    @Test
     public void testPhoneLookup() {
         ContentValues values = new ContentValues();
         values.put(RawContacts.CUSTOM_RINGTONE, "d");
@@ -1913,6 +1972,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(0, getCount(lookupUri2, null, null));
     }
 
+    @Test
     public void testSipPhoneLookup() {
         ContentValues values = new ContentValues();
 
@@ -1942,6 +2002,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(0, getCount(lookupUri2, null, null));
     }
 
+    @Test
     public void testPhoneLookupStarUseCases() {
         // Create two raw contacts with numbers "*123" and "12 3". This is a real life example
         // from b/13195334.
@@ -1975,6 +2036,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(lookupUri, null, null, new ContentValues[] {values});
     }
 
+    @Test
     public void testPhoneLookupReturnsNothingRatherThanStar() {
         // Create Emergency raw contact with "*123456789" number.
         final ContentValues values = new ContentValues();
@@ -1989,6 +2051,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(0, getCount(lookupUri, null, null));
     }
 
+    @Test
     public void testPhoneLookupReturnsNothingRatherThanMissStar() {
         // Create Voice Mail raw contact with "123456789" number.
         final ContentValues values = new ContentValues();
@@ -2003,6 +2066,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(0, getCount(lookupUri, null, null));
     }
 
+    @Test
     public void testPhoneLookupStarNoFallbackMatch() {
         final ContentValues values = new ContentValues();
         final Uri rawContactUri = mResolver.insert(RawContacts.CONTENT_URI, values);
@@ -2018,6 +2082,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(0, getCount(lookupUri, null, null));
     }
 
+    @Test
     public void testPhoneLookupStarNotBreakFallbackMatching() {
         // Create a raw contact with a phone number starting with "011"
         Uri rawContactUri = mResolver.insert(RawContacts.CONTENT_URI, new ContentValues());
@@ -2043,6 +2108,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(lookupUri1, null, null, new ContentValues[]{values});
     }
 
+    @Test
     public void testPhoneLookupExplicitProjection() {
         final ContentValues values = new ContentValues();
         final Uri rawContactUri = mResolver.insert(RawContacts.CONTENT_URI, values);
@@ -2067,6 +2133,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         mResolver.query(lookupUri, projection, null, null, null);
     }
 
+    @Test
     public void testPhoneLookupUseCases() {
         ContentValues values = new ContentValues();
         Uri rawContactUri;
@@ -2146,6 +2213,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(0, getCount(lookupUri2, null, null));
     }
 
+    @Test
     public void testIntlPhoneLookupUseCases() {
         // Checks the logic that relies on phone_number_compare_loose(Gingerbread) as a fallback
         //for phone number lookups.
@@ -2183,6 +2251,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 PhoneLookup.CONTENT_FILTER_URI, "049102395"), null, null));
     }
 
+    @Test
     public void testPhoneLookupB5252190() {
         // Test cases from b/5252190
         String storedNumber = "796010101";
@@ -2210,6 +2279,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 PhoneLookup.CONTENT_FILTER_URI, "4 879 601 0101"), null, null));
     }
 
+    @Test
     public void testPhoneLookupUseStrictPhoneNumberCompare() {
         // Test lookup cases when mUseStrictPhoneNumberComparison is true
         final ContactsProvider2 cp = (ContactsProvider2) getProvider();
@@ -2270,6 +2340,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     /**
      * Test for enterprise caller-id, but with no corp profile.
      */
+    @Test
     public void testPhoneLookupEnterprise_noCorpProfile() throws Exception {
 
         Uri uri1 = Uri.withAppendedPath(PhoneLookup.ENTERPRISE_CONTENT_FILTER_URI, "408-111-1111");
@@ -2298,6 +2369,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     /**
      * Test for enterprise caller-id.  Corp profile exists, but it returns a null cursor.
      */
+    @Test
     public void testPhoneLookupEnterprise_withCorpProfile_nullResult() throws Exception {
         setUpNullCorpProvider();
 
@@ -2362,6 +2434,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
      * Note: in this test, we add one more provider instance for the authority
      * "10@com.android.contacts" and use it as the corp cp2.
      */
+    @Test
     public void testQueryMergedDataPhones() throws Exception {
         mActor.addPermissions("android.permission.INTERACT_ACROSS_USERS");
 
@@ -2442,6 +2515,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
      * Note: in this test, we add one more provider instance for the authority
      * "10@com.android.contacts" and use it as the corp cp2.
      */
+    @Test
     public void testQueryMergedDataPhones_nullCorp() throws Exception {
         mActor.addPermissions("android.permission.INTERACT_ACROSS_USERS");
 
@@ -2479,6 +2553,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
      * Note: in this test, we add one more provider instance for the authority
      * "10@com.android.contacts" and use it as the corp cp2.
      */
+    @Test
     public void testPhoneLookupEnterprise_withCorpProfile() throws Exception {
         final SynchronousContactsProvider2 corpCp2 = setUpCorpProvider();
 
@@ -2569,6 +2644,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testQueryRawContactEntitiesCorp_noCorpProfile() {
         mActor.addPermissions("android.permission.INTERACT_ACROSS_USERS");
 
@@ -2582,6 +2658,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(0, getCount(RawContactsEntity.CORP_CONTENT_URI));
     }
 
+    @Test
     public void testQueryRawContactEntitiesCorp_withCorpProfile() throws Exception {
         mActor.addPermissions("android.permission.INTERACT_ACROSS_USERS");
 
@@ -2625,6 +2702,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         c.close();
     }
 
+    @Test
     public void testRewriteCorpDirectories() {
         // 6 columns
         final MatrixCursor c = new MatrixCursor(new String[] {
@@ -2665,6 +2743,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals("aname", rewritten.getString(column++));
     }
 
+    @Test
     public void testPhoneUpdate() {
         ContentValues values = new ContentValues();
         Uri rawContactUri = mResolver.insert(RawContacts.CONTENT_URI, values);
@@ -2703,6 +2782,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     }
 
     /** Tests if {@link Callable#CONTENT_URI} returns both phones and sip addresses. */
+    @Test
     public void testCallablesQuery() {
         long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, "Meghan", "Knox");
         long phoneId1 = ContentUris.parseId(insertPhoneNumber(rawContactId1, "18004664411"));
@@ -2735,10 +2815,12 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(Callable.CONTENT_URI, new ContentValues[] { values1, values2 });
     }
 
+    @Test
     public void testCallablesFilterQuery() {
         testPhonesFilterQueryInter(Callable.CONTENT_FILTER_URI);
     }
 
+    @Test
     public void testEmailsQuery() {
         ContentValues values = new ContentValues();
         values.put(RawContacts.CUSTOM_RINGTONE, "d");
@@ -2797,6 +2879,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(dedupeUri, values);
     }
 
+    @Test
     public void testEmailsLookupQuery() {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver, "Hot", "Tamale");
         insertEmail(rawContactId, "tamale@acme.com");
@@ -2817,6 +2900,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(0, getCount(filterUri3, null, null));
     }
 
+    @Test
     public void testEmailsFilterQuery() {
         long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, "Hot", "Tamale",
                 TestUtil.ACCOUNT_1);
@@ -2852,6 +2936,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     /**
      * Tests if ContactsProvider2 returns addresses according to registration order.
      */
+    @Test
     public void testEmailFilterDefaultSortOrder() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver);
         insertEmail(rawContactId1, "address1@email.com");
@@ -2871,6 +2956,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     /**
      * Tests if ContactsProvider2 returns primary addresses before the other addresses.
      */
+    @Test
     public void testEmailFilterPrimaryAddress() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver);
         insertEmail(rawContactId1, "address1@email.com");
@@ -2888,6 +2974,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
      * Tests if ContactsProvider2 has email address associated with a primary account before the
      * other address.
      */
+    @Test
     public void testEmailFilterPrimaryAccount() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver, TestUtil.ACCOUNT_1);
         insertEmail(rawContactId1, "account1@email.com");
@@ -2925,6 +3012,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     /**
      * Test emails with the same domain as primary account are ordered first.
      */
+    @Test
     public void testEmailFilterSameDomainAccountOrder() {
         final Account account = new Account("tester@email.com", "not_used");
         final long rawContactId = RawContactUtil.createRawContact(mResolver, account);
@@ -2944,6 +3032,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     /**
      * Test "default" emails are sorted above emails used last.
      */
+    @Test
     public void testEmailFilterSuperPrimaryOverUsageSort() {
         final long rawContactId = RawContactUtil.createRawContact(mResolver, TestUtil.ACCOUNT_1);
         final Uri emailUri1 = insertEmail(rawContactId, "account1@testemail.com");
@@ -2964,6 +3053,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValuesOrderly(filterUri, v3, v1, v2);
     }
 
+    @Test
     public void testEmailFilterUsageOverPrimarySort() {
         final long rawContactId = RawContactUtil.createRawContact(mResolver, TestUtil.ACCOUNT_1);
         final Uri emailUri1 = insertEmail(rawContactId, "account1@testemail.com");
@@ -2985,6 +3075,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     }
 
     /** Tests {@link DataUsageFeedback} correctly promotes a data row instead of a raw contact. */
+    @Test
     public void testEmailFilterSortOrderWithFeedback() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver);
         String address1 = "address1@email.com";
@@ -3037,6 +3128,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValuesOrderly(filterUri3, new ContentValues[] { v1, v2, v3 });
     }
 
+    @Test
     public void testAddQueryParametersFromUri() {
         final ContactsProvider2 provider = (ContactsProvider2) getProvider();
         final Uri originalUri = Phone.CONTENT_FILTER_URI.buildUpon()
@@ -3059,6 +3151,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 .appendQueryParameter(ContactsContract.DIRECTORY_PARAM_KEY, directory).build();
     }
 
+    @Test
     public void testTestInvalidDirectory() throws Exception {
         final ContactsProvider2 provider = (ContactsProvider2) getProvider();
         assertTrue(provider.isDirectoryParamValid(Contacts.CONTENT_FILTER_URI));
@@ -3068,6 +3161,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertFalse(provider.isDirectoryParamValid(buildContactsFilterUriWithDirectory("abc")));
     }
 
+    @Test
     public void testQueryCorpContactsProvider() throws Exception {
         final ContactsProvider2 provider = (ContactsProvider2) getProvider();
         final MockUserManager um = mActor.mockUserManager;
@@ -3113,6 +3207,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testPostalsQuery() {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver, "Alice", "Nextore");
         Uri dataUri = insertPostalAddress(rawContactId, "1600 Amphiteatre Ave, Mountain View");
@@ -3158,6 +3253,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(dedupeUri, values);
     }
 
+    @Test
     public void testDataContentUriInvisibleQuery() {
         final ContentValues values = new ContentValues();
         final long contactId = createContact(values, "John", "Doe",
@@ -3173,6 +3269,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(0, getCount(uri, null, null));
     }
 
+    @Test
     public void testInDefaultDirectoryData() {
         final ContentValues values = new ContentValues();
         final long contactId = createContact(values, "John", "Doe",
@@ -3195,6 +3292,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 getCount(Email.CONTENT_URI, query.toString(), new String[]{"goog411@acme.com"}));
     }
 
+    @Test
     public void testContactablesQuery() {
         final long rawContactId = RawContactUtil.createRawContactWithName(mResolver, "Hot",
                 "Tamale");
@@ -3242,6 +3340,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(filterUri7, cv1, cv2);
     }
 
+    @Test
     public void testContactablesMultipleQuery() {
 
         final long rawContactId = RawContactUtil.createRawContactWithName(mResolver, "Hot",
@@ -3336,6 +3435,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     }
 
 
+    @Test
     public void testQueryContactData() {
         ContentValues values = new ContentValues();
         long contactId = createContact(values, "John", "Doe",
@@ -3347,6 +3447,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(contactUri, values);
     }
 
+    @Test
     public void testQueryContactWithStatusUpdate() {
         ContentValues values = new ContentValues();
         long contactId = createContact(values, "John", "Doe",
@@ -3361,6 +3462,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValuesWithProjection(contactUri, values);
     }
 
+    @Test
     public void testQueryContactFilterByName() {
         ContentValues values = new ContentValues();
         long rawContactId = createRawContact(values, "18004664411",
@@ -3401,6 +3503,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertContactFilterNoResult("goolish");
     }
 
+    @Test
     public void testQueryContactFilterByEmailAddress() {
         ContentValues values = new ContentValues();
         long rawContactId = createRawContact(values, "18004664411",
@@ -3428,6 +3531,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertContactFilterNoResult("goolish");
     }
 
+    @Test
     public void testQueryContactFilterByPhoneNumber() {
         ContentValues values = new ContentValues();
         long rawContactId = createRawContact(values, "18004664411",
@@ -3458,6 +3562,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
      * Checks ContactsProvider2 works well with strequent Uris. The provider should return starred
      * contacts.
      */
+    @Test
     public void testQueryContactStrequent() {
         ContentValues values1 = new ContentValues();
         final String email1 = "a@acme.com";
@@ -3513,6 +3618,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValuesOrderly(phoneOnlyStrequentUri, new ContentValues[] { });
     }
 
+    @Test
     public void testQueryContactStrequentFrequentOrder() {
         // Prepare test data
         final long rid1 = RawContactUtil.createRawContact(mResolver);
@@ -3622,6 +3728,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
      * Checks ContactsProvider2 works well with frequent Uri. The provider should return frequently
      * contacted person ordered by number of times contacted.
      */
+    @Test
     public void testQueryContactFrequent() {
         ContentValues values1 = new ContentValues();
         final String email1 = "a@acme.com";
@@ -3681,6 +3788,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 );
     }
 
+    @Test
     public void testQueryContactFrequentExcludingInvisible() {
         ContentValues values1 = new ContentValues();
         final String email1 = "a@acme.com";
@@ -3705,6 +3813,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
 
     }
 
+    @Test
     public void testQueryDataUsageStat() {
         // Now all data usage stats are zero as of Q.
 
@@ -3762,6 +3871,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertDataUsageZero(dataUriWithUsageTypeCall, "a@acme.com");
     }
 
+    @Test
     public void testQueryContactGroup() {
         long groupId = createGroup(null, "testGroup", "Test Group");
 
@@ -3824,6 +3934,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testQueryProfileWithoutPermission() {
         createBasicProfileContact(new ContentValues());
 
@@ -3845,6 +3956,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                         .appendPath("entities").build(), null, null, null, Contacts._ID);
     }
 
+    @Test
     public void testQueryProfileByContactIdWithoutReadPermission() {
         long profileRawContactId = createBasicProfileContact(new ContentValues());
         long profileContactId = queryContactId(profileRawContactId);
@@ -3856,6 +3968,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 null, null, null, Contacts._ID);
     }
 
+    @Test
     public void testQueryProfileByRawContactIdWithoutReadPermission() {
         long profileRawContactId = createBasicProfileContact(new ContentValues());
 
@@ -3865,6 +3978,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                         profileRawContactId), null, null, null, RawContacts._ID);
     }
 
+    @Test
     public void testQueryProfileRawContactWithoutReadPermission() {
         long profileRawContactId = createBasicProfileContact(new ContentValues());
 
@@ -3888,6 +4002,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                         .appendPath("entity").build(), null, null, null, null);
     }
 
+    @Test
     public void testQueryProfileDataByDataIdWithoutReadPermission() {
         createBasicProfileContact(new ContentValues());
         Cursor c = mResolver.query(Profile.CONTENT_URI.buildUpon().appendPath("data").build(),
@@ -3903,6 +4018,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 null, null, null, null);
     }
 
+    @Test
     public void testQueryProfileDataWithoutReadPermission() {
         createBasicProfileContact(new ContentValues());
 
@@ -3912,6 +4028,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 null, null, null, null);
     }
 
+    @Test
     public void testInsertProfileWithoutWritePermission() {
         // Creating a non-profile contact should be fine.
         createBasicNonProfileContact(new ContentValues());
@@ -3923,6 +4040,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testInsertProfileDataWithoutWritePermission() {
         long profileRawContactId = createBasicProfileContact(new ContentValues());
 
@@ -3933,6 +4051,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testUpdateDataDoesNotRequireProfilePermission() {
         // Create a non-profile contact.
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver, "Domo", "Arigato");
@@ -3952,6 +4071,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(ContentUris.withAppendedId(Data.CONTENT_URI, dataId), values);
     }
 
+    @Test
     public void testQueryContactThenProfile() {
         ContentValues profileValues = new ContentValues();
         long profileRawContactId = createBasicProfileContact(profileValues);
@@ -3969,6 +4089,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(Profile.CONTENT_URI, profileValues);
     }
 
+    @Test
     public void testQueryContactExcludeProfile() {
         // Create a profile contact (it should not be returned by the general contact URI).
         createBasicProfileContact(new ContentValues());
@@ -3980,6 +4101,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(Contacts.CONTENT_URI, new ContentValues[] {nonProfileValues});
     }
 
+    @Test
     public void testQueryProfile() {
         ContentValues profileValues = new ContentValues();
         createBasicProfileContact(profileValues);
@@ -4013,6 +4135,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         return new ContentValues[]{photoRow, phoneRow, emailRow, nameRow};
     }
 
+    @Test
     public void testQueryProfileData() {
         createBasicProfileContact(new ContentValues());
 
@@ -4020,6 +4143,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 getExpectedProfileDataValues());
     }
 
+    @Test
     public void testQueryProfileEntities() {
         createBasicProfileContact(new ContentValues());
 
@@ -4027,6 +4151,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 getExpectedProfileDataValues());
     }
 
+    @Test
     public void testQueryRawProfile() {
         ContentValues profileValues = new ContentValues();
         createBasicProfileContact(profileValues);
@@ -4037,6 +4162,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(Profile.CONTENT_RAW_CONTACTS_URI, profileValues);
     }
 
+    @Test
     public void testQueryRawProfileById() {
         ContentValues profileValues = new ContentValues();
         long profileRawContactId = createBasicProfileContact(profileValues);
@@ -4048,6 +4174,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 Profile.CONTENT_RAW_CONTACTS_URI, profileRawContactId), profileValues);
     }
 
+    @Test
     public void testQueryRawProfileData() {
         long profileRawContactId = createBasicProfileContact(new ContentValues());
 
@@ -4056,6 +4183,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 .appendPath("data").build(), getExpectedProfileDataValues());
     }
 
+    @Test
     public void testQueryRawProfileEntity() {
         long profileRawContactId = createBasicProfileContact(new ContentValues());
 
@@ -4064,6 +4192,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 .appendPath("entity").build(), getExpectedProfileDataValues());
     }
 
+    @Test
     public void testQueryDataForProfile() {
         createBasicProfileContact(new ContentValues());
 
@@ -4071,6 +4200,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 getExpectedProfileDataValues());
     }
 
+    @Test
     public void testUpdateProfileRawContact() {
         createBasicProfileContact(new ContentValues());
         ContentValues updatedValues = new ContentValues();
@@ -4082,6 +4212,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(Profile.CONTENT_RAW_CONTACTS_URI, updatedValues);
     }
 
+    @Test
     public void testInsertProfileWithDataSetTriggersAccountCreation() {
         // Check that we have no profile raw contacts.
         assertStoredValues(Profile.CONTENT_RAW_CONTACTS_URI, new ContentValues[]{});
@@ -4100,6 +4231,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(Profile.CONTENT_RAW_CONTACTS_URI, values);
     }
 
+    @Test
     public void testLoadProfilePhoto() throws IOException {
         long rawContactId = createBasicProfileContact(new ContentValues());
         insertPhoto(rawContactId, R.drawable.earth_normal);
@@ -4108,6 +4240,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 Contacts.openContactPhotoInputStream(mResolver, Profile.CONTENT_URI, false));
     }
 
+    @Test
     public void testLoadProfileDisplayPhoto() throws IOException {
         long rawContactId = createBasicProfileContact(new ContentValues());
         insertPhoto(rawContactId, R.drawable.earth_normal);
@@ -4116,6 +4249,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 Contacts.openContactPhotoInputStream(mResolver, Profile.CONTENT_URI, true));
     }
 
+    @Test
     public void testPhonesWithStatusUpdate() {
 
         ContentValues values = new ContentValues();
@@ -4168,6 +4302,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         c.close();
     }
 
+    @Test
     public void testGroupQuery() {
         Account account1 = new Account("a", "b");
         Account account2 = new Account("c", "d");
@@ -4181,6 +4316,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(uri2, Groups._ID + "=" + groupId2, null, Groups._ID, groupId2) ;
     }
 
+    @Test
     public void testGroupInsert() {
         ContentValues values = new ContentValues();
 
@@ -4207,6 +4343,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(rowUri, values);
     }
 
+    @Test
     public void testGroupCreationAfterMembershipInsert() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver, mAccount);
         Uri groupMembershipUri = insertGroupMembership(rawContactId1, "gsid1");
@@ -4216,6 +4353,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 rawContactId1, groupId, "gsid1");
     }
 
+    @Test
     public void testGroupReuseAfterMembershipInsert() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver, mAccount);
         long groupId1 = createGroup(mAccount, "gsid1", "title1");
@@ -4226,6 +4364,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 rawContactId1, groupId1, "gsid1");
     }
 
+    @Test
     public void testGroupInsertFailureOnGroupIdConflict() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver, mAccount);
         long groupId1 = createGroup(mAccount, "gsid1", "title1");
@@ -4243,6 +4382,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testGroupDelete_byAccountSelection() {
         final Account account1 = new Account("accountName1", "accountType1");
         final Account account2 = new Account("accountName2", "accountType2");
@@ -4271,6 +4411,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(Groups.CONTENT_URI, new ContentValues[] { v1, v2, v3 });
     }
 
+    @Test
     public void testGroupDelete_byAccountParam() {
         final Account account1 = new Account("accountName1", "accountType1");
         final Account account2 = new Account("accountName2", "accountType2");
@@ -4302,6 +4443,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(Groups.CONTENT_URI, new ContentValues[] { v1, v2, v3 });
     }
 
+    @Test
     public void testGroupSummaryQuery() {
         final Account account1 = new Account("accountName1", "accountType1");
         final Account account2 = new Account("accountName2", "accountType2");
@@ -4424,6 +4566,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValuesWithProjection(uri, new ContentValues[] { v1, v2, v3, v4 });
     }
 
+    @Test
     public void testSettingsQuery() {
         Account account1 = new Account("a", "b");
         Account account2 = new Account("c", "d");
@@ -4449,6 +4592,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(uri3, Settings.UNGROUPED_VISIBLE, "0");
     }
 
+    @Test
     public void testSettingsInsertionPreventsDuplicates() {
         Account account1 = new Account("a", "b");
         AccountWithDataSet account2 = new AccountWithDataSet("c", "d", "plus");
@@ -4468,6 +4612,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 new String[] {"c", "d", "plus"}, Settings.SHOULD_SYNC, "0");
     }
 
+    @Test
     public void testSettingsDeletion() {
         Account account = new Account("a", "b");
         Uri settingUri = createSettings(account, "0", "1");
@@ -4490,6 +4635,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertRowCount(0, Settings.CONTENT_URI, null, null);
     }
 
+    @Test
     public void testSettingsUpdate() {
         Account account1 = new Account("a", "b");
         Account account2 = new Account("c", "d");
@@ -4561,6 +4707,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 ));
     }
 
+    @Test
     public void testSettingsLocalAccount() {
         AccountWithDataSet localAccount = AccountWithDataSet.LOCAL;
 
@@ -4598,6 +4745,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertRowCount(1, Settings.CONTENT_URI, null, null);
     }
 
+    @Test
     public void testDisplayNameParsingWhenPartsUnspecified() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues values = new ContentValues();
@@ -4607,6 +4755,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStructuredName(rawContactId, "Mr.", "John", "Kevin", "von Smith", "Jr.");
     }
 
+    @Test
     public void testDisplayNameParsingWhenPartsAreNull() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues values = new ContentValues();
@@ -4617,6 +4766,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStructuredName(rawContactId, "Mr.", "John", "Kevin", "von Smith", "Jr.");
     }
 
+    @Test
     public void testDisplayNameParsingWhenPartsSpecified() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues values = new ContentValues();
@@ -4627,6 +4777,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStructuredName(rawContactId, null, null, null, "Johnson", null);
     }
 
+    @Test
     public void testContactWithoutPhoneticName() {
         ContactLocaleUtils.setLocaleForTest(Locale.ENGLISH);
         final long rawContactId = RawContactUtil.createRawContact(mResolver, null);
@@ -4672,6 +4823,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(dataUri, values);
     }
 
+    @Test
     public void testContactWithChineseName() {
         if (!hasChineseCollator()) {
             return;
@@ -4718,6 +4870,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(dataUri, values);
     }
 
+    @Test
     public void testJapaneseNameContactInEnglishLocale() {
         // Need Japanese locale data for transliteration
         if (!hasJapaneseCollator()) {
@@ -4739,6 +4892,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertContactFilterNoResult("kong");
     }
 
+    @Test
     public void testContactWithJapaneseName() {
         if (!hasJapaneseCollator()) {
             return;
@@ -4790,6 +4944,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertContactFilterNoResult("kong");
     }
 
+    @Test
     public void testDisplayNameUpdate() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver);
         insertEmail(rawContactId1, "potato@acme.com", true);
@@ -4808,6 +4963,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNetworkNotified(true);
     }
 
+    @Test
     public void testDisplayNameFromData() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -4844,6 +5000,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(uri, Contacts.DISPLAY_NAME, "James P. Sullivan");
     }
 
+    @Test
     public void testDisplayNameFromOrganizationWithoutPhoneticName() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -4873,6 +5030,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(uri, values);
     }
 
+    @Test
     public void testDisplayNameFromOrganizationWithJapanesePhoneticName() {
         if (!hasJapaneseCollator()) {
             return;
@@ -4901,6 +5059,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(uri, values);
     }
 
+    @Test
     public void testDisplayNameFromOrganizationWithChineseName() {
         if (!hasChineseCollator()) {
             return;
@@ -4929,6 +5088,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(uri, values);
     }
 
+    @Test
     public void testLookupByOrganization() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -4982,6 +5142,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(0, getCount(filterUri, null, null));
     }
 
+    @Test
     public void testSearchSnippetOrganization() throws Exception {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -5014,6 +5175,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertContainsValues(filterUri, values);
     }
 
+    @Test
     public void testSearchSnippetEmail() throws Exception {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -5030,6 +5192,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(filterUri, values);
     }
 
+    @Test
     public void testCountPhoneNumberDigits() {
         assertEquals(10, ContactsProvider2.countPhoneNumberDigits("86 (0) 5-55-12-34"));
         assertEquals(10, ContactsProvider2.countPhoneNumberDigits("860 555-1234"));
@@ -5043,6 +5206,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(0, ContactsProvider2.countPhoneNumberDigits("+441234098foo"));
     }
 
+    @Test
     public void testSearchSnippetPhone() throws Exception {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -5088,6 +5252,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         return values;
     }
 
+    @Test
     public void testSearchSnippetNickname() throws Exception {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -5103,6 +5268,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(filterUri, values);
     }
 
+    @Test
     public void testSearchSnippetEmptyForNameInDisplayName() throws Exception {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -5115,6 +5281,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertContainsValues(buildFilterUri("john", true), snippet);
     }
 
+    @Test
     public void testSearchSnippetEmptyForNicknameInDisplayName() throws Exception {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -5126,6 +5293,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertContainsValues(buildFilterUri("cave", true), snippet);
     }
 
+    @Test
     public void testSearchSnippetEmptyForCompanyInDisplayName() throws Exception {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -5141,6 +5309,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertContainsValues(buildFilterUri("aperture", true), snippet);
     }
 
+    @Test
     public void testSearchSnippetEmptyForPhoneInDisplayName() throws Exception {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -5152,6 +5321,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertContainsValues(buildFilterUri("860", true), snippet);
     }
 
+    @Test
     public void testSearchSnippetEmptyForEmailInDisplayName() throws Exception {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -5164,6 +5334,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertContainsValues(buildFilterUri("cave", true), snippet);
     }
 
+    @Test
     public void testDisplayNameUpdateFromStructuredNameUpdate() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         Uri nameUri = DataUtil.insertStructuredName(mResolver, rawContactId, "Slinky", "Dog");
@@ -5190,6 +5361,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(uri, Contacts.DISPLAY_NAME, "Dog");
     }
 
+    @Test
     public void testInsertDataWithContentProviderOperations() throws Exception {
         ContentProviderOperation cpo1 = ContentProviderOperation.newInsert(RawContacts.CONTENT_URI)
                 .withValues(new ContentValues())
@@ -5207,6 +5379,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(uri, Contacts.DISPLAY_NAME, "John Doe");
     }
 
+    @Test
     public void testSendToVoicemailDefault() {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -5218,6 +5391,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         c.close();
     }
 
+    @Test
     public void testSetSendToVoicemailAndRingtone() {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         Uri rawContactUri = ContentUris.withAppendedId(RawContacts.CONTENT_URI, rawContactId);
@@ -5238,6 +5412,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertMetadataDirty(rawContactUri, false);
     }
 
+    @Test
     public void testSendToVoicemailAndRingtoneAfterAggregation() {
         long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, "a", "b");
         long contactId1 = queryContactId(rawContactId1);
@@ -5255,6 +5430,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertSendToVoicemailAndRingtone(contactId1, true, "foo,bar"); // Either foo or bar
     }
 
+    @Test
     public void testDoNotSendToVoicemailAfterAggregation() {
         long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, "e", "f");
         long contactId1 = queryContactId(rawContactId1);
@@ -5272,6 +5448,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertSendToVoicemailAndRingtone(queryContactId(rawContactId1), false, null);
     }
 
+    @Test
     public void testSetSendToVoicemailAndRingtonePreservedAfterJoinAndSplit() {
         long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, "i", "j");
         long contactId1 = queryContactId(rawContactId1);
@@ -5293,6 +5470,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertSendToVoicemailAndRingtone(queryContactId(rawContactId2), false, "bar");
     }
 
+    @Test
     public void testMarkMetadataDirtyAfterAggregation() {
         long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, "i", "j");
         long rawContactId2 = RawContactUtil.createRawContactWithName(mResolver, "k", "l");
@@ -5314,6 +5492,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNetworkNotified(false);
     }
 
+    @Test
     public void testStatusUpdateInsert() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         Uri imUri = insertImHandle(rawContactId, Im.PROTOCOL_AIM, null, "aim");
@@ -5367,6 +5546,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(contactUri, values);
     }
 
+    @Test
     public void testStatusUpdateInferAttribution() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         Uri imUri = insertImHandle(rawContactId, Im.PROTOCOL_AIM, null, "aim");
@@ -5388,6 +5568,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(resultUri, values);
     }
 
+    @Test
     public void testStatusUpdateMatchingImOrEmail() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         insertImHandle(rawContactId, Im.PROTOCOL_AIM, null, "aim");
@@ -5432,6 +5613,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValuesWithProjection(contactUri, values);
     }
 
+    @Test
     public void testStatusUpdateUpdateAndDelete() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         insertImHandle(rawContactId, Im.PROTOCOL_AIM, null, "aim");
@@ -5507,6 +5689,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValuesWithProjection(contactUri, values);
     }
 
+    @Test
     public void testStatusUpdateUpdateToNull() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         insertImHandle(rawContactId, Im.PROTOCOL_AIM, null, "aim");
@@ -5535,6 +5718,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValuesWithProjection(contactUri, values);
     }
 
+    @Test
     public void testStatusUpdateWithTimestamp() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         insertImHandle(rawContactId, Im.PROTOCOL_AIM, null, "aim");
@@ -5568,6 +5752,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
 
     // Stream item query test cases.
 
+    @Test
     public void testQueryStreamItemsByRawContactId() {
         long rawContactId = RawContactUtil.createRawContact(mResolver, mAccount);
         ContentValues values = buildGenericStreamItemValues();
@@ -5579,6 +5764,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 values);
     }
 
+    @Test
     public void testQueryStreamItemsByContactId() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -5591,6 +5777,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 values);
     }
 
+    @Test
     public void testQueryStreamItemsByLookupKey() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -5604,6 +5791,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 values);
     }
 
+    @Test
     public void testQueryStreamItemsByLookupKeyAndContactId() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -5619,6 +5807,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 values);
     }
 
+    @Test
     public void testQueryStreamItems() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues values = buildGenericStreamItemValues();
@@ -5626,6 +5815,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(StreamItems.CONTENT_URI, values);
     }
 
+    @Test
     public void testQueryStreamItemsWithSelection() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues firstValues = buildGenericStreamItemValues();
@@ -5644,6 +5834,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 new String[]{"Goodbye world"}, secondValues);
     }
 
+    @Test
     public void testQueryStreamItemById() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues firstValues = buildGenericStreamItemValues();
@@ -5666,6 +5857,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
 
     // Stream item photo insertion + query test cases.
 
+    @Test
     public void testQueryStreamItemPhotoWithSelection() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues values = buildGenericStreamItemValues();
@@ -5683,6 +5875,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 new String[]{"1"}, photo1Values);
     }
 
+    @Test
     public void testQueryStreamItemPhotoByStreamItemId() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
 
@@ -5714,6 +5907,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 StreamItems.StreamItemPhotos.CONTENT_DIRECTORY), photo2Values);
     }
 
+    @Test
     public void testQueryStreamItemPhotoByStreamItemPhotoId() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
 
@@ -5760,6 +5954,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
 
     // Stream item insertion test cases.
 
+    @Test
     public void testInsertStreamItemInProfileRequiresWriteProfileAccess() {
         long profileRawContactId = createBasicProfileContact(new ContentValues());
 
@@ -5768,6 +5963,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         insertStreamItem(profileRawContactId, values, null);
     }
 
+    @Test
     public void testInsertStreamItemWithContentValues() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues values = buildGenericStreamItemValues();
@@ -5778,6 +5974,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 RawContacts.StreamItems.CONTENT_DIRECTORY), values);
     }
 
+    @Test
     public void testInsertStreamItemOverLimit() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues values = buildGenericStreamItemValues();
@@ -5812,6 +6009,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(1, streamItemIds.size());
     }
 
+    @Test
     public void testInsertStreamItemOlderThanOldestInLimit() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues values = buildGenericStreamItemValues();
@@ -5835,6 +6033,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
 
     // Stream item photo insertion test cases.
 
+    @Test
     public void testInsertStreamItemsAndPhotosInBatch() throws Exception {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues streamItemValues = buildGenericStreamItemValues();
@@ -5889,6 +6088,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
 
     // Stream item update test cases.
 
+    @Test
     public void testUpdateStreamItemById() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues values = buildGenericStreamItemValues();
@@ -5902,6 +6102,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 RawContacts.StreamItems.CONTENT_DIRECTORY), values);
     }
 
+    @Test
     public void testUpdateStreamItemWithContentValues() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues values = buildGenericStreamItemValues();
@@ -5917,6 +6118,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
 
     // Stream item photo update test cases.
 
+    @Test
     public void testUpdateStreamItemPhotoById() throws IOException {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues values = buildGenericStreamItemValues();
@@ -5945,6 +6147,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 mResolver.openInputStream(Uri.parse(displayPhotoUri)));
     }
 
+    @Test
     public void testUpdateStreamItemPhotoWithContentValues() throws IOException {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues values = buildGenericStreamItemValues();
@@ -5974,6 +6177,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
 
     // Stream item deletion test cases.
 
+    @Test
     public void testDeleteStreamItemById() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues firstValues = buildGenericStreamItemValues();
@@ -5994,6 +6198,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 RawContacts.StreamItems.CONTENT_DIRECTORY), secondValues);
     }
 
+    @Test
     public void testDeleteStreamItemWithSelection() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         ContentValues firstValues = buildGenericStreamItemValues();
@@ -6015,6 +6220,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
 
     // Stream item photo deletion test cases.
 
+    @Test
     public void testDeleteStreamItemPhotoById() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long streamItemId = ContentUris.parseId(
@@ -6039,6 +6245,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testDeleteStreamItemPhotoWithSelection() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long streamItemId = ContentUris.parseId(
@@ -6056,6 +6263,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(photoUri, firstPhotoValues);
     }
 
+    @Test
     public void testDeleteStreamItemsWhenRawContactDeleted() {
         long rawContactId = RawContactUtil.createRawContact(mResolver, mAccount);
         Uri streamItemUri = insertStreamItem(rawContactId,
@@ -6072,6 +6280,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(streamItemPhotoUri, emptyValues);
     }
 
+    @Test
     public void testQueryStreamItemLimit() {
         ContentValues values = new ContentValues();
         values.put(StreamItems.MAX_ITEMS, 5);
@@ -6081,6 +6290,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     // Tests for inserting or updating stream items as a side-effect of making status updates
     // (forward-compatibility of status updates into the new social stream API).
 
+    @Test
     public void testStreamItemInsertedOnStatusUpdate() {
 
         // This method of creating a raw contact automatically inserts a status update with
@@ -6100,6 +6310,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 expectedValues);
     }
 
+    @Test
     public void testStreamItemInsertedOnStatusUpdate_HtmlQuoting() {
 
         // This method of creating a raw contact automatically inserts a status update with
@@ -6122,6 +6333,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 expectedValues);
     }
 
+    @Test
     public void testStreamItemUpdatedOnSecondStatusUpdate() {
 
         // This method of creating a raw contact automatically inserts a status update with
@@ -6161,6 +6373,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         return values;
     }
 
+    @Test
     public void testSingleStatusUpdateRowPerContact() {
         int protocol1 = Im.PROTOCOL_GOOGLE_TALK;
         String handle1 = "test@gmail.com";
@@ -6226,6 +6439,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         c.close();
     }
 
+    @Test
     public void testContactVisibilityUpdateOnMembershipChange() {
         long rawContactId = RawContactUtil.createRawContact(mResolver, mAccount);
         assertVisibility(rawContactId, "0");
@@ -6254,6 +6468,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 null, Contacts.IN_VISIBLE_GROUP, expectedValue);
     }
 
+    @Test
     public void testSupplyingBothValuesAndParameters() throws Exception {
         Account account = new Account("account 1", "type%/:1");
         Uri uri = ContactsContract.Groups.CONTENT_URI.buildUpon()
@@ -6286,6 +6501,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testContentEntityIterator() {
         // create multiple contacts and check that the selected ones are returned
         long id;
@@ -6375,6 +6591,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         iterator.close();
     }
 
+    @Test
     public void testDataCreateUpdateDeleteByMimeType() throws Exception {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
 
@@ -6442,6 +6659,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNetworkNotified(true);
     }
 
+    @Test
     public void testRawContactQuery() {
         Account account1 = new Account("a", "b");
         Account account2 = new Account("c", "d");
@@ -6461,6 +6679,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(rowUri2, RawContacts._ID, rawContactId2) ;
     }
 
+    @Test
     public void testRawContactDeletion() {
         long rawContactId = RawContactUtil.createRawContact(mResolver, mAccount);
         Uri uri = ContentUris.withAppendedId(RawContacts.CONTENT_URI, rawContactId);
@@ -6492,6 +6711,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNetworkNotified(false);
     }
 
+    @Test
     public void testRawContactDeletionKeepingAggregateContact() {
         long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, mAccount);
         long rawContactId2 = RawContactUtil.createRawContactWithName(mResolver, mAccount);
@@ -6507,6 +6727,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(1, getCount(Contacts.CONTENT_URI, Contacts._ID + "=" + contactId, null));
     }
 
+    @Test
     public void testRawContactDeletion_byAccountParam() {
         long rawContactId = RawContactUtil.createRawContact(mResolver, mAccount);
         Uri uri = ContentUris.withAppendedId(RawContacts.CONTENT_URI, rawContactId);
@@ -6543,6 +6764,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(uri, RawContacts.DELETED, "1");
     }
 
+    @Test
     public void testRawContactDeletion_byAccountSelection() {
         long rawContactId = RawContactUtil.createRawContact(mResolver, mAccount);
         Uri uri = ContentUris.withAppendedId(RawContacts.CONTENT_URI, rawContactId);
@@ -6568,6 +6790,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
      * Test for {@link ContactsProvider2#stringToAccounts} and
      * {@link ContactsProvider2#accountsToString}.
      */
+    @Test
     public void testAccountsToString() {
         final Set<Account> EXPECTED_0 = Sets.newHashSet();
         final Set<Account> EXPECTED_1 = Sets.newHashSet(TestUtil.ACCOUNT_1);
@@ -6614,6 +6837,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
      * Test for {@link ContactsProvider2#haveAccountsChanged} and
      * {@link ContactsProvider2#saveAccounts}.
      */
+    @Test
     public void testHaveAccountsChanged() {
         final ContactsProvider2 cp = (ContactsProvider2) getProvider();
 
@@ -6661,6 +6885,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertTrue(cp.haveAccountsChanged(ACCOUNTS_1));
     }
 
+    @Test
     public void testAccountsUpdated() {
         // This is to ensure we do not delete contacts with null, null (account name, type)
         // accidentally.
@@ -6695,6 +6920,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 + rawContactId2, null));
     }
 
+    @Test
     public void testAccountDeletion() {
         Account readOnlyAccount = new Account("act", READ_ONLY_ACCOUNT_TYPE);
         ContactsProvider2 cp = (ContactsProvider2) getProvider();
@@ -6738,6 +6964,119 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 Contacts.PHOTO_ID, ContentUris.parseId(photoUri1));
     }
 
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_CP2_SYNC_SEARCH_INDEX_FLAG)
+    public void testSearchIndexUpdatedOnAccountDeletion() {
+        ContactsProvider2 cp = (ContactsProvider2) getProvider();
+        SQLiteDatabase db = cp.getDatabaseHelper().getReadableDatabase();
+        mActor.setAccounts(new Account[]{mAccount});
+        cp.onAccountsUpdated(new Account[]{mAccount});
+
+        long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, "John", "Wick",
+                mAccount);
+
+        // Assert the contact is in the search index
+        assertStoredValue(buildFilterUri("wick", false), SearchSnippets.SNIPPET, null);
+        assertEquals(1, DatabaseUtils.longForQuery(db, "SELECT COUNT(*) FROM search_index", null));
+
+        // Remove the account
+        mActor.setAccounts(new Account[]{});
+        cp.onAccountsUpdated(new Account[]{});
+
+        // Assert the contact is no longer searchable
+        assertRowCount(0, buildFilterUri("wick", false), null, null);
+
+        // Assert the contact is no longer in the search index table
+        assertEquals(0, DatabaseUtils.longForQuery(db, "SELECT COUNT(*) FROM search_index", null));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_CP2_SYNC_SEARCH_INDEX_FLAG)
+    public void testSearchIndexUpdatedOnAccountDeletion_withMultipleAccounts() {
+        Account readOnlyAccount = new Account("act", READ_ONLY_ACCOUNT_TYPE);
+        ContactsProvider2 cp = (ContactsProvider2) getProvider();
+        SQLiteDatabase db = cp.getDatabaseHelper().getReadableDatabase();
+        mActor.setAccounts(new Account[]{readOnlyAccount, mAccount});
+        cp.onAccountsUpdated(new Account[]{readOnlyAccount, mAccount});
+
+        long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, "John", "Wick",
+                readOnlyAccount);
+        long rawContactId2 = RawContactUtil.createRawContactWithName(mResolver, "john", "wick",
+                mAccount);
+        insertEmail(rawContactId2, "person@movie.com", true);
+
+        assertAggregated(rawContactId1, rawContactId2);
+
+        // Assert the contact is searchable by name and email
+        assertStoredValue(buildFilterUri("wick", false), SearchSnippets.SNIPPET, null);
+        assertStoredValue(buildFilterUri("movie", false), SearchSnippets.SNIPPET,
+                "person@[movie].com");
+        // Since contacts are aggregated only 1 entry should be present in search index
+        assertEquals(1, DatabaseUtils.longForQuery(db, "SELECT COUNT(*) FROM search_index", null));
+
+        // Remove the writable account
+        mActor.setAccounts(new Account[]{readOnlyAccount});
+        cp.onAccountsUpdated(new Account[]{readOnlyAccount});
+
+        // Assert the contact is searchable by name but not by email
+        assertStoredValue(buildFilterUri("wick", false), SearchSnippets.SNIPPET, null);
+        assertRowCount(0, buildFilterUri("movie", false), null, null);
+
+        // Assert the contact is still in the search index table
+        assertEquals(1, DatabaseUtils.longForQuery(db, "SELECT count(*) FROM search_index", null));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_CP2_SYNC_SEARCH_INDEX_FLAG)
+    public void testSearchIndexUpdatedOnAccountDeletion_withMaxStaleContacts() {
+        Account readOnlyAccount = new Account("act", READ_ONLY_ACCOUNT_TYPE);
+        ContactsProvider2 cp = (ContactsProvider2) getProvider();
+        SQLiteDatabase db = cp.getDatabaseHelper().getReadableDatabase();
+        mActor.setAccounts(new Account[]{readOnlyAccount, mAccount});
+        cp.onAccountsUpdated(new Account[]{readOnlyAccount, mAccount});
+
+        // The maximum amount of stale contacts before rebuilding search index completely
+        cp.setSearchIndexMaxUpdateFilterContacts(5);
+
+        // Add more contacts than the max amount of stale contacts, such that we trigger a
+        // rebuild of the search index during the account removal process
+        for (int i = 0; i < 10; i++) {
+            String firstName = "first" + i;
+            String lastName = "last" + i;
+            long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, firstName,
+                    lastName, readOnlyAccount);
+            long rawContactId2 = RawContactUtil.createRawContactWithName(mResolver, firstName,
+                    lastName, mAccount);
+            insertEmail(rawContactId2, "person@corp" + i + ".com", true);
+
+            assertAggregated(rawContactId1, rawContactId2);
+
+            // Assert the contact is searchable by name and email
+            assertStoredValue(buildFilterUri(firstName, false), SearchSnippets.SNIPPET, null);
+            assertStoredValue(buildFilterUri("corp" + i, false), SearchSnippets.SNIPPET,
+                    "person@[corp" + i + "].com");
+            // Since contacts are aggregated only 1 entry should be present in search index
+            assertEquals(i + 1,
+                    DatabaseUtils.longForQuery(db, "SELECT COUNT(*) FROM search_index", null));
+        }
+
+        // Remove the writable account
+        mActor.setAccounts(new Account[]{readOnlyAccount});
+        cp.onAccountsUpdated(new Account[]{readOnlyAccount});
+
+        for (int i = 0; i < 10; i++) {
+            String firstName = "first" + i;
+            String lastName = "last" + i;
+            // Assert the contact is searchable by name but not by email
+            assertStoredValue(buildFilterUri(firstName, false), SearchSnippets.SNIPPET, null);
+            assertRowCount(0, buildFilterUri("corp" + i, false), null, null);
+        }
+
+        // Assert all of the contacts are still in the search index table
+        assertEquals(10, DatabaseUtils.longForQuery(db, "SELECT count(*) FROM search_index", null));
+    }
+
+    @Test
     public void testStreamItemsCleanedUpOnAccountRemoval() {
         Account doomedAccount = new Account("doom", "doom");
         Account safeAccount = mAccount;
@@ -6780,6 +7119,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(safeStreamItemPhotoUri, StreamItemPhotos._ID, safeStreamItemPhotoId);
     }
 
+    @Test
     public void testContactDeletion() {
         long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, "John", "Doe",
                 TestUtil.ACCOUNT_1);
@@ -6796,6 +7136,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 RawContacts.DELETED, "1");
     }
 
+    @Test
     public void testMarkAsDirtyParameter() {
         long rawContactId = RawContactUtil.createRawContact(mResolver, mAccount);
         Uri rawContactUri = ContentUris.withAppendedId(RawContacts.CONTENT_URI, rawContactId);
@@ -6812,6 +7153,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNetworkNotified(false);
     }
 
+    @Test
     public void testDirtyWhenRawContactInsert() {
         // When inserting a rawcontact.
         long rawContactId = RawContactUtil.createRawContact(mResolver, mAccount);
@@ -6821,6 +7163,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNetworkNotified(true);
     }
 
+    @Test
     public void testRawContactDirtyAndVersion() {
         final long rawContactId = RawContactUtil.createRawContact(mResolver, mAccount);
         Uri uri = ContentUris.withAppendedId(ContactsContract.RawContacts.CONTENT_URI, rawContactId);
@@ -6861,6 +7204,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(version, getVersion(uri));
     }
 
+    @Test
     public void testRawContactClearDirty() {
         final long rawContactId = RawContactUtil.createRawContact(mResolver, mAccount);
         Uri uri = ContentUris.withAppendedId(ContactsContract.RawContacts.CONTENT_URI,
@@ -6876,6 +7220,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(version, getVersion(uri));
     }
 
+    @Test
     public void testRawContactDeletionSetsDirty() {
         final long rawContactId = RawContactUtil.createRawContact(mResolver, mAccount);
         Uri uri = ContentUris.withAppendedId(ContactsContract.RawContacts.CONTENT_URI,
@@ -6892,6 +7237,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(version, getVersion(uri));
     }
 
+    @Test
     public void testNotifyMetadataChangeForRawContactInsertBySyncAdapter() {
         Uri uri = RawContacts.CONTENT_URI.buildUpon()
                 .appendQueryParameter(RawContacts.ACCOUNT_NAME, mAccount.name)
@@ -6904,6 +7250,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertMetadataDirty(rawContactUri, false);
     }
 
+    @Test
     public void testMarkAsMetadataDirtyForRawContactMetadataChange() {
         long rawContactId = RawContactUtil.createRawContact(mResolver, mAccount);
         long contactId = queryContactId(rawContactId);
@@ -6934,6 +7281,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertMetadataDirty(rawContactUri, false);
     }
 
+    @Test
     public void testMarkAsMetadataDirtyForRawContactBackupIdChange() {
         long rawContactId = RawContactUtil.createRawContact(mResolver, mAccount);
         Uri rawContactUri = ContentUris.withAppendedId(RawContacts.CONTENT_URI, rawContactId);
@@ -6952,6 +7300,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertMetadataDirty(rawContactUri, false);
     }
 
+    @Test
     public void testMarkAsMetadataDirtyForAggregationExceptionChange() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver, new Account("a", "a"));
         long rawContactId2 = RawContactUtil.createRawContact(mResolver, new Account("b", "b"));
@@ -6965,6 +7314,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 false);
     }
 
+    @Test
     public void testMarkAsMetadataNotDirtyForUsageStatsChange() {
         final long rid1 = RawContactUtil.createRawContactWithName(mResolver, "contact", "a");
         final long did1a = ContentUris.parseId(insertEmail(rid1, "email_1_a@email.com"));
@@ -6974,6 +7324,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertMetadataDirty(ContentUris.withAppendedId(RawContacts.CONTENT_URI, rid1), false);
     }
 
+    @Test
     public void testMarkAsMetadataDirtyForDataPrimarySettingInsert() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver, new Account("a", "a"));
         Uri mailUri11 = insertEmail(rawContactId1, "test1@domain1.com", true, true);
@@ -6984,6 +7335,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 false);
     }
 
+    @Test
     public void testMarkAsMetadataDirtyForDataPrimarySettingUpdate() {
         long rawContactId = RawContactUtil.createRawContact(mResolver, new Account("a", "a"));
         Uri mailUri1 = insertEmail(rawContactId, "test1@domain1.com");
@@ -6999,6 +7351,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 false);
     }
 
+    @Test
     public void testMarkAsMetadataDirtyForDataDelete() {
         long rawContactId = RawContactUtil.createRawContact(mResolver, new Account("a", "a"));
         Uri mailUri1 = insertEmail(rawContactId, "test1@domain1.com", true, true);
@@ -7009,6 +7362,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 false);
     }
 
+    @Test
     public void testDeleteContactWithoutName() {
         Uri rawContactUri = mResolver.insert(RawContacts.CONTENT_URI, new ContentValues());
         long rawContactId = ContentUris.parseId(rawContactUri);
@@ -7023,6 +7377,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(1, numDeleted);
     }
 
+    @Test
     public void testDeleteContactWithoutAnyData() {
         Uri rawContactUri = mResolver.insert(RawContacts.CONTENT_URI, new ContentValues());
         long rawContactId = ContentUris.parseId(rawContactUri);
@@ -7035,6 +7390,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(1, numDeleted);
     }
 
+    @Test
     public void testDeleteContactWithEscapedUri() {
         ContentValues values = new ContentValues();
         values.put(RawContacts.SOURCE_ID, "!@#$%^&*()_+=-/.,<>?;'\":[]}{\\|`~");
@@ -7047,6 +7403,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(1, mResolver.delete(lookupUri, null, null));
     }
 
+    @Test
     public void testDeleteContactComposedOfSingleLocalRawContact() {
         // Create a raw contact in the local (null) account
         long rawContactId = RawContactUtil.createRawContact(mResolver, null);
@@ -7068,6 +7425,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         c2.close();
     }
 
+    @Test
     public void testDeleteContactComposedOfTwoLocalRawContacts() {
         // Create a raw contact in the local (null) account
         long rawContactId1 = RawContactUtil.createRawContact(mResolver, null);
@@ -7104,6 +7462,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         c3.close();
     }
 
+    @Test
     public void testDeleteContactComposedOfSomeLocalRawContacts() {
         // Create a raw contact in the local (null) account
         long rawContactId1 = RawContactUtil.createRawContact(mResolver, null);
@@ -7139,6 +7498,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         c3.close();
     }
 
+    @Test
     public void testQueryContactWithEscapedUri() {
         ContentValues values = new ContentValues();
         values.put(RawContacts.SOURCE_ID, "!@#$%^&*()_+=-/.,<>?;'\":[]}{\\|`~");
@@ -7153,6 +7513,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         c.close();
     }
 
+    @Test
     public void testGetPhotoUri() {
         ContentValues values = new ContentValues();
         Uri rawContactUri = mResolver.insert(RawContacts.CONTENT_URI, values);
@@ -7169,6 +7530,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 Contacts.PHOTO_URI, photoUri);
     }
 
+    @Test
     public void testGetPhotoViaLookupUri() throws IOException {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -7196,6 +7558,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 thumbnail, mResolver.openInputStream(photoLookupUriWithoutId));
     }
 
+    @Test
     public void testInputStreamForPhoto() throws Exception {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -7219,6 +7582,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 mResolver.openInputStream(photoUri));
     }
 
+    @Test
     public void testSuperPrimaryPhoto() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver, new Account("a", "a"));
         Uri photoUri1 = insertPhoto(rawContactId1, R.drawable.earth_normal);
@@ -7258,6 +7622,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(contactUri, Contacts.PHOTO_ID, photoId1);
     }
 
+    @Test
     public void testUpdatePhoto() {
         ContentValues values = new ContentValues();
         Uri rawContactUri = mResolver.insert(RawContacts.CONTENT_URI, values);
@@ -7285,6 +7650,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(photoId, twigId);
     }
 
+    @Test
     public void testUpdateRawContactDataPhoto() {
         // setup a contact with a null photo
         ContentValues values = new ContentValues();
@@ -7320,6 +7686,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         storedPhoto.close();
     }
 
+    @Test
     public void testOpenDisplayPhotoForContactId() throws IOException {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -7332,6 +7699,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 mResolver.openInputStream(photoUri));
     }
 
+    @Test
     public void testOpenDisplayPhotoForContactLookupKey() throws IOException {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -7345,6 +7713,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 mResolver.openInputStream(photoUri));
     }
 
+    @Test
     public void testOpenDisplayPhotoForContactLookupKeyAndId() throws IOException {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -7359,6 +7728,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 mResolver.openInputStream(photoUri));
     }
 
+    @Test
     public void testOpenDisplayPhotoForRawContactId() throws IOException {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         insertPhoto(rawContactId, R.drawable.earth_normal);
@@ -7370,6 +7740,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 mResolver.openInputStream(photoUri));
     }
 
+    @Test
     public void testOpenDisplayPhotoByPhotoUri() throws IOException {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -7384,6 +7755,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 mResolver.openInputStream(Uri.parse(photoUri)));
     }
 
+    @Test
     public void testPhotoUriForDisplayPhoto() {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -7407,6 +7779,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 photoUri);
     }
 
+    @Test
     public void testPhotoUriForThumbnailPhoto() throws IOException {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -7436,6 +7809,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 mResolver.openInputStream(Uri.parse(photoUri)));
     }
 
+    @Test
     public void testWriteNewPhotoToAssetFile() throws Exception {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -7476,6 +7850,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 mResolver.openInputStream(Uri.parse(thumbnailUri)));
     }
 
+    @Test
     public void testWriteUpdatedPhotoToAssetFile() throws Exception {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -7533,6 +7908,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, (Object[])null).get();
     }
 
+    @Test
     public void testPhotoDimensionLimits() {
         ContentValues values = new ContentValues();
         values.put(DisplayPhoto.DISPLAY_MAX_DIM, 256);
@@ -7540,6 +7916,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValues(DisplayPhoto.CONTENT_MAX_DIMENSIONS_URI, values);
     }
 
+    @Test
     public void testPhotoStoreCleanup() throws IOException {
         SynchronousContactsProvider2 provider = (SynchronousContactsProvider2) mActor.provider;
         PhotoStore photoStore = provider.getPhotoStore();
@@ -7634,6 +8011,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 new ContentValues[0]);
     }
 
+    @Test
     public void testPhotoStoreCleanupForProfile() {
         SynchronousContactsProvider2 provider = (SynchronousContactsProvider2) mActor.provider;
         PhotoStore profilePhotoStore = provider.getProfilePhotoStore();
@@ -7688,6 +8066,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
 
     }
 
+    @Test
     public void testCleanupDanglingContacts_noDanglingContacts() throws Exception {
         SynchronousContactsProvider2 provider = (SynchronousContactsProvider2) mActor.provider;
         RawContactUtil.createRawContactWithName(mResolver, "A", "B");
@@ -7703,6 +8082,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(2, rawContactCursor.getCount());
     }
 
+    @Test
     public void testCleanupDanglingContacts_singleDanglingContacts() throws Exception {
         SynchronousContactsProvider2 provider = (SynchronousContactsProvider2) mActor.provider;
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver, "A", "B");
@@ -7717,6 +8097,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(0, mResolver.query(Contacts.CONTENT_URI, null, null, null, null).getCount());
     }
 
+    @Test
     public void testCleanupDanglingContacts_multipleDanglingContacts() throws Exception {
         SynchronousContactsProvider2 provider = (SynchronousContactsProvider2) mActor.provider;
         long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, "A", "B");
@@ -7737,6 +8118,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(1, mResolver.query(Contacts.CONTENT_URI, null, null, null, null).getCount());
     }
 
+    @Test
     public void testOverwritePhotoWithThumbnail() throws IOException {
         long rawContactId = RawContactUtil.createRawContactWithName(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -7765,6 +8147,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 mResolver.openInputStream(Uri.parse(photoUri)));
     }
 
+    @Test
     public void testUpdateRawContactSetStarred() {
         long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver);
         Uri rawContactUri1 = ContentUris.withAppendedId(RawContacts.CONTENT_URI, rawContactId1);
@@ -7814,6 +8197,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNetworkNotified(true);
     }
 
+    @Test
     public void testUpdateContactOptionsSetStarred() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         long contactId = queryContactId(rawContactId);
@@ -7827,6 +8211,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNetworkNotified(true);
     }
 
+    @Test
     public void testSetAndClearSuperPrimaryEmail() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver, new Account("a", "a"));
         Uri mailUri11 = insertEmail(rawContactId1, "test1@domain1.com");
@@ -7967,22 +8352,27 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(mailUri2, Data.IS_SUPER_PRIMARY, withSuperPrimary ? 1 : 0);
     }
 
+    @Test
     public void testNewPrimaryInInsert() {
         testChangingPrimary(false, false);
     }
 
+    @Test
     public void testNewPrimaryInInsertWithSuperPrimary() {
         testChangingPrimary(false, true);
     }
 
+    @Test
     public void testNewPrimaryInUpdate() {
         testChangingPrimary(true, false);
     }
 
+    @Test
     public void testNewPrimaryInUpdateWithSuperPrimary() {
         testChangingPrimary(true, true);
     }
 
+    @Test
     public void testContactSortOrder() {
         assertEquals(ContactsColumns.PHONEBOOK_BUCKET_PRIMARY + ", "
                      + Contacts.SORT_KEY_PRIMARY,
@@ -8000,6 +8390,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                                                              + suffix));
     }
 
+    @Test
     public void testContactCounts() {
         Uri uri = Contacts.CONTENT_URI.buildUpon()
                 .appendQueryParameter(Contacts.EXTRA_ADDRESS_BOOK_INDEX, "true").build();
@@ -8044,6 +8435,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         MoreAsserts.assertEquals(expected, actual);
     }
 
+    @Test
     public void testReadBooleanQueryParameter() {
         assertBooleanUriParameter("foo:bar", "bool", true, true);
         assertBooleanUriParameter("foo:bar", "bool", false, false);
@@ -8064,6 +8456,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 Uri.parse(uriString), parameter, defaultValue));
     }
 
+    @Test
     public void testGetQueryParameter() {
         assertQueryParameter("foo:bar", "param", null);
         assertQueryParameter("foo:bar?param", "param", null);
@@ -8088,6 +8481,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertQueryParameter("foo:bar?ppp=val&", "p", null);
     }
 
+    @Test
     public void testMissingAccountTypeParameter() {
         // Try querying for RawContacts only using ACCOUNT_NAME
         final Uri queryUri = RawContacts.CONTENT_URI.buildUpon().appendQueryParameter(
@@ -8100,6 +8494,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testInsertInconsistentAccountType() {
         // Try inserting RawContact with inconsistent Accounts
         final Account red = new Account("red", "red");
@@ -8119,10 +8514,12 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testProviderStatusNoContactsNoAccounts() throws Exception {
         assertProviderStatus(ProviderStatus.STATUS_EMPTY);
     }
 
+    @Test
     public void testProviderStatusOnlyLocalContacts() throws Exception {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         assertProviderStatus(ProviderStatus.STATUS_NORMAL);
@@ -8131,6 +8528,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertProviderStatus(ProviderStatus.STATUS_EMPTY);
     }
 
+    @Test
     public void testProviderStatusWithAccounts() throws Exception {
         assertProviderStatus(ProviderStatus.STATUS_EMPTY);
         mActor.setAccounts(new Account[]{TestUtil.ACCOUNT_1});
@@ -8150,6 +8548,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         cursor.close();
     }
 
+    @Test
     public void testProperties() throws Exception {
         ContactsProvider2 provider = (ContactsProvider2)getProvider();
         ContactsDatabaseHelper helper = (ContactsDatabaseHelper)provider.getDatabaseHelper();
@@ -8164,6 +8563,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals("default", helper.getProperty("existent1", "default"));
     }
 
+    @Test
     public void testQueryMultiVCard() {
         // No need to create any contacts here, because the query for multiple vcards
         // does not go into the database at all
@@ -8180,6 +8580,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         cursor.close();
     }
 
+    @Test
     public void testQueryFileSingleVCard() {
         final VCardTestUriCreator contacts = createVCardTestContacts();
 
@@ -8204,6 +8605,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testQueryFileProfileVCard() {
         createBasicProfileContact(new ContentValues());
         Cursor cursor = mResolver.query(Profile.CONTENT_VCARD_URI, null, null, null, null);
@@ -8215,6 +8617,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         cursor.close();
     }
 
+    @Test
     public void testOpenAssetFileMultiVCard() throws IOException {
         final VCardTestUriCreator contacts = createVCardTestContacts();
 
@@ -8230,6 +8633,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertTrue(data.contains("N:Doh;Jane;;;"));
     }
 
+    @Test
     public void testOpenAssetFileSingleVCard() throws IOException {
         final VCardTestUriCreator contacts = createVCardTestContacts();
 
@@ -8259,6 +8663,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testAutoGroupMembership() {
         long g1 = createGroup(mAccount, "g1", "t1", 0, true /* autoAdd */, false /* favorite */);
         long g2 = createGroup(mAccount, "g2", "t2", 0, false /* autoAdd */, false /* favorite */);
@@ -8289,6 +8694,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testNoAutoAddMembershipAfterGroupCreation() {
         long r1 = RawContactUtil.createRawContact(mResolver, mAccount);
         long r2 = RawContactUtil.createRawContact(mResolver, mAccount);
@@ -8313,6 +8719,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     // the starred contacts should be added to group
     // favorites group removed
     // no change to starred status
+    @Test
     public void testFavoritesMembershipAfterGroupCreation() {
         long r1 = RawContactUtil.createRawContact(mResolver, mAccount, RawContacts.STARRED, "1");
         long r2 = RawContactUtil.createRawContact(mResolver, mAccount);
@@ -8385,6 +8792,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertFalse(queryRawContactIsStarred(r7));
     }
 
+    @Test
     public void testFavoritesGroupMembershipChangeAfterStarChange() {
         long g1 = createGroup(mAccount, "g1", "t1", 0, false /* autoAdd */, true /* favorite */);
         long g2 = createGroup(mAccount, "g2", "t2", 0, false /* autoAdd */, false/* favorite */);
@@ -8460,6 +8868,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNoRowsAndClose(queryGroupMemberships(mAccountTwo));
     }
 
+    @Test
     public void testStarChangedAfterGroupMembershipChange() {
         long g1 = createGroup(mAccount, "g1", "t1", 0, false /* autoAdd */, true /* favorite */);
         long g2 = createGroup(mAccount, "g2", "t2", 0, false /* autoAdd */, false/* favorite */);
@@ -8530,6 +8939,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNoRowsAndClose(queryGroupMemberships(mAccountTwo));
     }
 
+    @Test
     public void testReadOnlyRawContact() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         Uri rawContactUri = ContentUris.withAppendedId(RawContacts.CONTENT_URI, rawContactId);
@@ -8546,6 +8956,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(rawContactUri, RawContacts.CUSTOM_RINGTONE, "third");
     }
 
+    @Test
     public void testReadOnlyDataRow() {
         long rawContactId = RawContactUtil.createRawContact(mResolver);
         Uri emailUri = insertEmail(rawContactId, "email");
@@ -8564,6 +8975,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(emailUri, Email.ADDRESS, "changed");
     }
 
+    @Test
     public void testContactWithReadOnlyRawContact() {
         long rawContactId1 = RawContactUtil.createRawContact(mResolver);
         Uri rawContactUri1 = ContentUris.withAppendedId(RawContacts.CONTENT_URI, rawContactId1);
@@ -8586,6 +8998,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertStoredValue(rawContactUri2, RawContacts.CUSTOM_RINGTONE, "second");
     }
 
+    @Test
     public void testNameParsingQuery() {
         Uri uri = ContactsContract.AUTHORITY_URI.buildUpon().appendPath("complete_name")
                 .appendQueryParameter(StructuredName.DISPLAY_NAME, "Mr. John Q. Doe Jr.").build();
@@ -8603,6 +9016,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         cursor.close();
     }
 
+    @Test
     public void testNameConcatenationQuery() {
         Uri uri = ContactsContract.AUTHORITY_URI.buildUpon().appendPath("complete_name")
                 .appendQueryParameter(StructuredName.PREFIX, "Mr")
@@ -8625,6 +9039,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         cursor.close();
     }
 
+    @Test
     public void testBuildSingleRowResult() {
         checkBuildSingleRowResult(
                 new String[] {"b"},
@@ -8672,6 +9087,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testDataUsageFeedbackAndDelete() {
 
         sMockClock.install();
@@ -8813,6 +9229,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     /*******************************************************
      * Delta api tests.
      */
+    @Test
     public void testContactDelete_hasDeleteLog() {
         sMockClock.install();
         long start = sMockClock.currentTimeMillis();
@@ -8823,6 +9240,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         RawContactUtil.delete(mResolver, ids.mRawContactId, true);
     }
 
+    @Test
     public void testContactDelete_marksRawContactsForDeletion() {
         DatabaseAsserts.ContactIdPair ids = assertContactCreateDelete(mAccount);
 
@@ -8837,6 +9255,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         RawContactUtil.delete(mResolver, ids.mRawContactId, true);
     }
 
+    @Test
     public void testContactDelete_checkRawContactContactId() {
         DatabaseAsserts.ContactIdPair ids = assertContactCreateDelete(mAccount);
 
@@ -8849,6 +9268,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         RawContactUtil.delete(mResolver, ids.mRawContactId, true);
     }
 
+    @Test
     public void testContactUpdate_metadataChange() {
         DatabaseAsserts.ContactIdPair ids = DatabaseAsserts.assertAndCreateContact(mResolver);
         Uri rawContactUri = ContentUris.withAppendedId(RawContacts.CONTENT_URI, ids.mRawContactId);
@@ -8864,6 +9284,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNetworkNotified(false);
     }
 
+    @Test
     public void testContactUpdate_updatesContactUpdatedTimestamp() {
         sMockClock.install();
         DatabaseAsserts.ContactIdPair ids = DatabaseAsserts.assertAndCreateContact(mResolver);
@@ -8884,6 +9305,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     }
 
     // This implicitly tests the Contact create case.
+    @Test
     public void testRawContactCreate_updatesContactUpdatedTimestamp() {
         long startTime = System.currentTimeMillis();
 
@@ -8896,6 +9318,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         RawContactUtil.delete(mResolver, rawContactId, true);
     }
 
+    @Test
     public void testRawContactUpdate_updatesContactUpdatedTimestamp() {
         DatabaseAsserts.ContactIdPair ids = DatabaseAsserts.assertAndCreateContact(mResolver);
 
@@ -8912,6 +9335,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         RawContactUtil.delete(mResolver, ids.mRawContactId, true);
     }
 
+    @Test
     public void testRawContactPsuedoDelete_hasDeleteLogForContact() {
         DatabaseAsserts.ContactIdPair ids = DatabaseAsserts.assertAndCreateContact(mResolver);
 
@@ -8925,6 +9349,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         RawContactUtil.delete(mResolver, ids.mRawContactId, true);
     }
 
+    @Test
     public void testRawContactDelete_hasDeleteLogForContact() {
         DatabaseAsserts.ContactIdPair ids = DatabaseAsserts.assertAndCreateContact(mResolver);
 
@@ -8945,6 +9370,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         return ContactUtil.queryContactLastUpdatedTimestamp(mResolver, contactId);
     }
 
+    @Test
     public void testDataInsert_updatesContactLastUpdatedTimestamp() {
         sMockClock.install();
         DatabaseAsserts.ContactIdPair ids = DatabaseAsserts.assertAndCreateContact(mResolver);
@@ -8960,6 +9386,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         RawContactUtil.delete(mResolver, ids.mRawContactId, true);
     }
 
+    @Test
     public void testDataDelete_updatesContactLastUpdatedTimestamp() {
         sMockClock.install();
         DatabaseAsserts.ContactIdPair ids = DatabaseAsserts.assertAndCreateContact(mResolver);
@@ -8978,6 +9405,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         RawContactUtil.delete(mResolver, ids.mRawContactId, true);
     }
 
+    @Test
     public void testDataUpdate_updatesContactLastUpdatedTimestamp() {
         sMockClock.install();
         DatabaseAsserts.ContactIdPair ids = DatabaseAsserts.assertAndCreateContact(mResolver);
@@ -9003,6 +9431,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         return ContentUris.parseId(uri);
     }
 
+    @Test
     public void testDeletedContactsDelete_isUnsupported() {
         final Uri URI = ContactsContract.DeletedContacts.CONTENT_URI;
         DatabaseAsserts.assertDeleteIsUnsupported(mResolver, URI);
@@ -9011,12 +9440,14 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         DatabaseAsserts.assertDeleteIsUnsupported(mResolver, uri);
     }
 
+    @Test
     public void testDeletedContactsInsert_isUnsupported() {
         final Uri URI = ContactsContract.DeletedContacts.CONTENT_URI;
         DatabaseAsserts.assertInsertIsUnsupported(mResolver, URI);
     }
 
 
+    @Test
     public void testQueryDeletedContactsByContactId() {
         DatabaseAsserts.ContactIdPair ids = assertContactCreateDelete();
 
@@ -9024,6 +9455,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 DeletedContactUtil.queryDeletedTimestampForContactId(mResolver, ids.mContactId));
     }
 
+    @Test
     public void testQueryDeletedContactsAll() {
         final int numDeletes = 10;
 
@@ -9040,6 +9472,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertEquals(numDeletes, endCount - startCount);
     }
 
+    @Test
     public void testQueryDeletedContactsSinceTimestamp() {
         sMockClock.install();
 
@@ -9110,6 +9543,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
     /*******************************************************
      * Pinning support tests
      */
+    @Test
     public void testPinnedPositionsUpdate() {
         final DatabaseAsserts.ContactIdPair i1 = DatabaseAsserts.assertAndCreateContact(mResolver);
         final DatabaseAsserts.ContactIdPair i2 = DatabaseAsserts.assertAndCreateContact(mResolver);
@@ -9181,6 +9615,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         );
     }
 
+    @Test
     public void testPinnedPositionsAfterJoinAndSplit() {
         final DatabaseAsserts.ContactIdPair i1 = DatabaseAsserts.assertAndCreateContactWithName(
                 mResolver, "A", "Smith");
@@ -9308,6 +9743,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         );
     }
 
+    @Test
     public void testDefaultAccountSet_throwException() {
         mActor.setAccounts(new Account[]{mAccount});
         try {
@@ -9349,6 +9785,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         }
     }
 
+    @Test
     public void testDefaultAccountSetAndQuery() {
         Bundle response = mResolver.call(ContactsContract.AUTHORITY_URI,
                 Settings.QUERY_DEFAULT_ACCOUNT_METHOD, null, null);
@@ -9381,6 +9818,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertNull(account);
     }
 
+    @Test
     public void testPinnedPositionsDemoteIllegalArguments() {
         try {
             mResolver.call(ContactsContract.AUTHORITY_URI, PinnedPositions.UNDEMOTE_METHOD,
@@ -9408,6 +9846,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
                 null);
     }
 
+    @Test
     public void testPinnedPositionsAfterDemoteAndUndemote() {
         final DatabaseAsserts.ContactIdPair i1 = DatabaseAsserts.assertAndCreateContact(mResolver);
         final DatabaseAsserts.ContactIdPair i2 = DatabaseAsserts.assertAndCreateContact(mResolver);
@@ -9458,6 +9897,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
      * Verifies that any existing pinned contacts have their pinned positions incremented by one
      * after the upgrade step
      */
+    @Test
     public void testPinnedPositionsUpgradeTo906_PinnedContactsIncrementedByOne() {
         final DatabaseAsserts.ContactIdPair i1 = DatabaseAsserts.assertAndCreateContact(mResolver);
         final DatabaseAsserts.ContactIdPair i2 = DatabaseAsserts.assertAndCreateContact(mResolver);
@@ -9484,6 +9924,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
      * Verifies that any unpinned contacts (or those with pinned position Integer.MAX_VALUE - 1)
      * have their pinned positions correctly set to 0 after the upgrade step.
      */
+    @Test
     public void testPinnedPositionsUpgradeTo906_UnpinnedValueCorrectlyUpdated() {
         final DatabaseAsserts.ContactIdPair i1 = DatabaseAsserts.assertAndCreateContact(mResolver);
         final DatabaseAsserts.ContactIdPair i2 = DatabaseAsserts.assertAndCreateContact(mResolver);
@@ -9508,6 +9949,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
      * Tests the functionality of the
      * {@link ContactsContract.PinnedPositions#pin(ContentResolver, long, int)} API.
      */
+    @Test
     public void testPinnedPositions_ContactsContractPinnedPositionsPin() {
         final DatabaseAsserts.ContactIdPair i1 = DatabaseAsserts.assertAndCreateContact(mResolver);
 
@@ -9540,6 +9982,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
      * End pinning support tests
      ******************************************************/
 
+    @Test
     public void testAuthorization_authorize() throws Exception {
         // Setup
         ContentValues values = new ContentValues();
@@ -9558,6 +10001,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertTrue(cp.isValidPreAuthorizedUri(authorizedUri));
     }
 
+    @Test
     public void testAuthorization_unauthorized() throws Exception {
         // Setup
         ContentValues values = new ContentValues();
@@ -9570,6 +10014,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertFalse(cp.isValidPreAuthorizedUri(contactUri));
     }
 
+    @Test
     public void testAuthorization_invalidAuthorization() throws Exception {
         // Setup
         ContentValues values = new ContentValues();
@@ -9586,6 +10031,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertFalse(cp.isValidPreAuthorizedUri(almostAuthorizedUri));
     }
 
+    @Test
     public void testAuthorization_expired() throws Exception {
         // Setup
         ContentValues values = new ContentValues();
@@ -9603,6 +10049,7 @@ public class ContactsProvider2Test extends BaseContactsProvider2Test {
         assertFalse(cp.isValidPreAuthorizedUri(authorizedUri));
     }
 
+    @Test
     public void testAuthorization_contactUpgrade() throws Exception {
         ContactsDatabaseHelper helper =
                 ((ContactsDatabaseHelper) ((ContactsProvider2) getProvider()).getDatabaseHelper());
diff --git a/tests/src/com/android/providers/contacts/DefaultAccountManagerTest.java b/tests/src/com/android/providers/contacts/DefaultAccountManagerTest.java
new file mode 100644
index 00000000..bb9a1b17
--- /dev/null
+++ b/tests/src/com/android/providers/contacts/DefaultAccountManagerTest.java
@@ -0,0 +1,265 @@
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
+package com.android.providers.contacts;
+
+import static org.mockito.Mockito.argThat;
+
+import android.accounts.Account;
+import android.accounts.AccountManager;
+
+import androidx.test.filters.SmallTest;
+
+import org.mockito.Mockito;
+
+import java.util.ArrayList;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+
+@SmallTest
+public class DefaultAccountManagerTest extends BaseContactsProvider2Test {
+    private static final String TAG = "DefaultAccountManagerTest";
+    private static final Account SYSTEM_CLOUD_ACCOUNT_1 = new Account("user1@gmail.com",
+            "com.google");
+    private static final Account NON_SYSTEM_CLOUD_ACCOUNT_1 = new Account("user2@whatsapp.com",
+            "com.whatsapp");
+
+    private ContactsDatabaseHelper mDbHelper;
+    private DefaultAccountManager mDefaultAccountManager;
+    private SyncSettingsHelper mSyncSettingsHelper;
+    private AccountManager mMockAccountManager;
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+
+        mDbHelper = getContactsProvider().getDatabaseHelper();
+        mSyncSettingsHelper = new SyncSettingsHelper();
+        mMockAccountManager = Mockito.mock(AccountManager.class);
+        mDefaultAccountManager = new DefaultAccountManager(getContactsProvider().getContext(),
+                mDbHelper, mSyncSettingsHelper, mMockAccountManager); // Inject mockAccountManager
+
+        setAccounts(new Account[0]);
+        DefaultAccountManager.setEligibleSystemCloudAccountTypesForTesting(
+                new String[]{SYSTEM_CLOUD_ACCOUNT_1.type});
+    }
+
+    private void setAccounts(Account[] accounts) {
+        Mockito.when(mMockAccountManager.getAccounts()).thenReturn(accounts);
+
+        // Construsts a map between the account type and account list, so that we could mock
+        // mMockAccountManager.getAccountsByType below.
+        Map<String, List<Account>> accountTypeMap = new HashMap<>();
+        for (Account account : accounts) {
+            if (accountTypeMap.containsKey(account.type)) {
+                accountTypeMap.get(account.type).add(account);
+            } else {
+                List<Account> accountList = new ArrayList<>();
+                accountList.add(account);
+                accountTypeMap.put(account.type, accountList);
+            }
+        }
+
+        // By default: getAccountsByType returns empty account list unless there is a match in
+        // in accountTypeMap.
+        Mockito.when(mMockAccountManager.getAccountsByType(
+                argThat(str -> !accountTypeMap.containsKey(str)))).thenReturn(new Account[0]);
+
+        for (Map.Entry<String, List<Account>> entry : accountTypeMap.entrySet()) {
+            String accountType = entry.getKey();
+            Mockito.when(mMockAccountManager.getAccountsByType(accountType)).thenReturn(
+                    entry.getValue().toArray(new Account[0]));
+        }
+    }
+
+    public void testPushDca_noCloudAccountsSignedIn() {
+        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+
+        // Push the DCA which is device account, which should succeed.
+        assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT));
+        assertEquals(DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+
+        // Push the DCA which is not signed in, expect failure.
+        assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
+        assertEquals(DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+    }
+
+    public void testPushDeviceAccountAsDca_cloudSyncIsOff() {
+        setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+
+        // The initial DCA should be unknown, regardless of the cloud account existence and their
+        // sync status.
+        mSyncSettingsHelper.turnOffSync(SYSTEM_CLOUD_ACCOUNT_1);
+        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+
+        // Try to set the DCA as DEVICE account, which should succeed
+        assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT));
+        assertEquals(DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+
+        // Try to set the DCA as the system cloud account which sync is currently off, should fail.
+        assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
+        assertEquals(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+        assertTrue(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+    }
+
+    public void testPushCustomizedDeviceAccountAsDca_cloudSyncIsOff() {
+        setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+        mSyncSettingsHelper.turnOffSync(SYSTEM_CLOUD_ACCOUNT_1);
+
+        // No cloud account remains sync on, and thus DCA reverts to the DEVICE.
+        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+
+        // Try to set DCA to be device account, which should succeed.
+        assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT));
+        assertEquals(DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+
+        // Try to set DCA to be a system cloud account which sync is off, should fail.
+        assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
+        assertEquals(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+        // Sync state should still remains off.
+        assertTrue(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+    }
+
+    public void testPushDca_dcaWasUnknown_tryPushDeviceAndThenCloudAccount() {
+        setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+        mSyncSettingsHelper.turnOnSync(SYSTEM_CLOUD_ACCOUNT_1);
+
+        // 1 system cloud account with sync on. DCA was set to cloud before, and thus it's in
+        // a UNKNOWN state.
+        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+
+        // Try to set the DCA to be local, which should succeed. In addition, it should turn
+        // all system cloud account's sync off.
+        assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT));
+        assertEquals(DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+        // Sync setting should remain to be on.
+        assertFalse(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+
+        // Try to set the DCA to be system cloud account, which should succeed.
+        assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
+        assertEquals(
+                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.pullDefaultAccount());
+        // Sync setting should remain to be on.
+        assertFalse(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+    }
+
+    public void testPushDca_dcaWasCloud() {
+        setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+        mSyncSettingsHelper.turnOnSync(SYSTEM_CLOUD_ACCOUNT_1);
+
+        // DCA was a system cloud initially.
+        mDbHelper.setDefaultAccount(SYSTEM_CLOUD_ACCOUNT_1.name, SYSTEM_CLOUD_ACCOUNT_1.type);
+        assertEquals(
+                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.pullDefaultAccount());
+
+        // Try to set DCA to a device (null) account, which should succeed, and it shouldn't
+        // change the cloud account's sync status.
+        assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT));
+        assertEquals(
+                DefaultAccount.DEVICE_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+        assertFalse(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+
+        // Try to set DCA to the same system cloud account again, which should succeed
+        assertTrue(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.ofCloud(SYSTEM_CLOUD_ACCOUNT_1)));
+        assertEquals(
+                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.pullDefaultAccount());
+        assertFalse(mSyncSettingsHelper.isSyncOff(SYSTEM_CLOUD_ACCOUNT_1));
+    }
+
+    public void testPushDca_dcaWasUnknown_tryPushAccountNotSignedIn() {
+        setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+
+        // Try to set the DCA to be an account not signed in, which should fail.
+        assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.ofCloud(new Account("unknown1@gmail.com", "com.google"))));
+        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+    }
+
+    public void testPushDca_dcaWasUnknown_tryPushNonSystemCloudAccount() {
+        setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1, NON_SYSTEM_CLOUD_ACCOUNT_1});
+        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+
+        // Try to set the DCA to be an account which is not a system cloud account, which should
+        // fail.
+        assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.ofCloud(NON_SYSTEM_CLOUD_ACCOUNT_1)));
+        assertEquals(DefaultAccount.UNKNOWN_DEFAULT_ACCOUNT,
+                mDefaultAccountManager.pullDefaultAccount());
+    }
+
+    public void testPushDca_dcaWasCloud_tryPushAccountNotSignedIn() {
+        setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1});
+        mDbHelper.setDefaultAccount(SYSTEM_CLOUD_ACCOUNT_1.name, SYSTEM_CLOUD_ACCOUNT_1.type);
+        assertEquals(
+                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.pullDefaultAccount());
+
+        // Try to set the DCA to be an account not signed in, which should fail.
+        assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.ofCloud(new Account("unknown1@gmail.com", "com.google"))));
+        assertEquals(
+                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.pullDefaultAccount());
+    }
+
+    public void testPushDca_dcaWasCloud_tryPushNonSystemCloudAccount() {
+        setAccounts(new Account[]{SYSTEM_CLOUD_ACCOUNT_1, NON_SYSTEM_CLOUD_ACCOUNT_1});
+        mDbHelper.setDefaultAccount(SYSTEM_CLOUD_ACCOUNT_1.name, SYSTEM_CLOUD_ACCOUNT_1.type);
+        assertEquals(
+                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.pullDefaultAccount());
+
+        // Try to set the DCA to be an account which is not a system cloud account, which should
+        // fail.
+        assertFalse(mDefaultAccountManager.tryPushDefaultAccount(
+                DefaultAccount.ofCloud(NON_SYSTEM_CLOUD_ACCOUNT_1)));
+        assertEquals(
+                new DefaultAccount(DefaultAccount.AccountCategory.CLOUD, SYSTEM_CLOUD_ACCOUNT_1),
+                mDefaultAccountManager.pullDefaultAccount());
+    }
+}
diff --git a/tests/src/com/android/providers/contacts/MoveRawContactsTest.java b/tests/src/com/android/providers/contacts/MoveRawContactsTest.java
new file mode 100644
index 00000000..f4ce0dce
--- /dev/null
+++ b/tests/src/com/android/providers/contacts/MoveRawContactsTest.java
@@ -0,0 +1,1151 @@
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
+package com.android.providers.contacts;
+
+import static android.provider.ContactsContract.SimAccount.SDN_EF_TYPE;
+
+import static org.mockito.ArgumentMatchers.argThat;
+
+import android.accounts.Account;
+import android.accounts.AccountManager;
+import android.content.ContentResolver;
+import android.content.ContentValues;
+import android.database.Cursor;
+import android.database.sqlite.SQLiteDatabase;
+import android.platform.test.annotations.EnableFlags;
+import android.platform.test.flag.junit.SetFlagsRule;
+import android.provider.ContactsContract.CommonDataKinds.GroupMembership;
+import android.provider.ContactsContract.CommonDataKinds.StructuredName;
+import android.provider.ContactsContract.Data;
+import android.provider.ContactsContract.Groups;
+import android.provider.ContactsContract.RawContacts;
+
+import androidx.test.filters.MediumTest;
+
+import com.android.providers.contacts.flags.Flags;
+import com.android.providers.contacts.testutil.DataUtil;
+import com.android.providers.contacts.testutil.RawContactUtil;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.ClassRule;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.Mockito;
+
+import java.util.ArrayList;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.Set;
+
+/**
+ * Unit tests for {@link ContactsProvider2} Move API.
+ *
+ * Run the test like this:
+ * <code>
+   adb shell am instrument -e class com.android.providers.contacts.MoveRawContactsTest -w \
+           com.android.providers.contacts.tests/android.test.InstrumentationTestRunner
+ * </code>
+ */
+@MediumTest
+@RunWith(JUnit4.class)
+public class MoveRawContactsTest extends BaseContactsProvider2Test {
+    @ClassRule public static final SetFlagsRule.ClassRule mClassRule = new SetFlagsRule.ClassRule();
+
+    @Rule public final SetFlagsRule mSetFlagsRule = mClassRule.createSetFlagsRule();
+
+    static final Account SOURCE_ACCOUNT = new Account("sourceName", "sourceType");
+    static final Account DEST_ACCOUNT = new Account("destName", "destType");
+    static final Account DEST_ACCOUNT_WITH_SOURCE_TYPE = new Account("destName", "sourceType");
+    static final Account DEST_CLOUD_ACCOUNT = new Account("destName", "com.google");
+    static final Account SIM_ACCOUNT = new Account("simName", "simType");
+
+    static final String SOURCE_ID = "uniqueSourceId";
+
+    static final String NON_PORTABLE_MIMETYPE = "test/mimetype";
+
+    static final String RES_PACKAGE = "testpackage";
+
+    ContactsProvider2 mCp;
+    AccountWithDataSet mSource;
+    AccountWithDataSet mDest;
+    AccountWithDataSet mCloudDest;
+    AccountWithDataSet mSimAcct;
+    ContactMover mMover;
+    DefaultAccountManager mDefaultAccountManager;
+    AccountManager mMockAccountManager;
+
+    @Before
+    @Override
+    public void setUp() throws Exception {
+        super.setUp();
+
+        mCp = (ContactsProvider2) getProvider();
+        mMockAccountManager = Mockito.mock(AccountManager.class);
+        mDefaultAccountManager = new DefaultAccountManager(mCp.getContext(),
+                mCp.getDatabaseHelper(), new SyncSettingsHelper(), mMockAccountManager);
+        mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_ACCOUNT});
+        mSource = AccountWithDataSet.get(SOURCE_ACCOUNT.name, SOURCE_ACCOUNT.type, null);
+        mDest = AccountWithDataSet.get(DEST_ACCOUNT.name, DEST_ACCOUNT.type, null);
+        mCloudDest = AccountWithDataSet.get(
+                DEST_CLOUD_ACCOUNT.name, DEST_CLOUD_ACCOUNT.type, null);
+        DefaultAccountManager.setEligibleSystemCloudAccountTypesForTesting(new String[]{
+                DEST_CLOUD_ACCOUNT.type,
+        });
+
+        mMover = new ContactMover(mCp, mCp.getDatabaseHelper(), mDefaultAccountManager);
+        mSimAcct = createSimAccount(SIM_ACCOUNT);
+    }
+
+    @After
+    @Override
+    public void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    private AccountWithDataSet createSimAccount(Account account) {
+        AccountWithDataSet accountWithDataSet =
+                new AccountWithDataSet(account.name, account.type, null);
+        final SQLiteDatabase db = mCp.getDatabaseHelper().getWritableDatabase();
+        db.beginTransaction();
+        try {
+            mCp.getDatabaseHelper()
+                    .createSimAccountIdInTransaction(accountWithDataSet, 1, SDN_EF_TYPE);
+            db.setTransactionSuccessful();
+        } finally {
+            db.endTransaction();
+        }
+        return accountWithDataSet;
+    }
+
+    private void setDefaultAccountManagerAccounts(Account[] accounts) {
+        Mockito.when(mMockAccountManager.getAccounts()).thenReturn(accounts);
+
+        // Constructs a map between the account type and account list, so that we could mock
+        // mMockAccountManager.getAccountsByType below.
+        Map<String, List<Account>> accountTypeMap = new HashMap<>();
+        for (Account account : accounts) {
+            if (accountTypeMap.containsKey(account.type)) {
+                accountTypeMap.get(account.type).add(account);
+            } else {
+                List<Account> accountList = new ArrayList<>();
+                accountList.add(account);
+                accountTypeMap.put(account.type, accountList);
+            }
+        }
+
+        // By default: getAccountsByType returns empty account list unless there is a match in
+        // in accountTypeMap.
+        Mockito.when(mMockAccountManager.getAccountsByType(
+                argThat(str -> !accountTypeMap.containsKey(str)))).thenReturn(new Account[0]);
+
+        for (Map.Entry<String, List<Account>> entry : accountTypeMap.entrySet()) {
+            String accountType = entry.getKey();
+            Mockito.when(mMockAccountManager.getAccountsByType(accountType)).thenReturn(
+                    entry.getValue().toArray(new Account[0]));
+        }
+    }
+
+    private void assertMovedContactIsDeleted(long rawContactId,
+            AccountWithDataSet account) {
+        ContentValues contentValues = new ContentValues();
+        contentValues.put(RawContacts._ID, rawContactId);
+        contentValues.put(RawContacts.DELETED, 1);
+        contentValues.put(RawContacts.ACCOUNT_NAME, account.getAccountName());
+        contentValues.put(RawContacts.ACCOUNT_TYPE, account.getAccountType());
+        assertStoredValues(RawContacts.CONTENT_URI,
+                RawContacts._ID + " = ?",
+                new String[]{String.valueOf(rawContactId)},
+                contentValues);
+    }
+
+    private void assertMovedRawContact(long rawContactId, AccountWithDataSet account,
+            boolean isStarred) {
+        ContentValues contentValues = new ContentValues();
+        contentValues.put(RawContacts._ID, rawContactId);
+        contentValues.put(RawContacts.DELETED, 0);
+        contentValues.put(RawContacts.STARRED, isStarred ? 1 : 0);
+        contentValues.putNull(RawContacts.SOURCE_ID);
+        contentValues.put(RawContacts.ACCOUNT_NAME, account.getAccountName());
+        contentValues.put(RawContacts.ACCOUNT_TYPE, account.getAccountType());
+        contentValues.put(RawContacts.DIRTY, 1);
+        assertStoredValues(RawContacts.CONTENT_URI,
+                RawContacts._ID + " = ?",
+                new String[]{String.valueOf(rawContactId)},
+                contentValues);
+    }
+
+    private void assertMoveStubExists(long rawContactId, String sourceId,
+            AccountWithDataSet account) {
+        assertEquals(1, getCount(RawContacts.CONTENT_URI,
+                RawContacts._ID + " <> ? and " + RawContacts.SOURCE_ID + " = ? and "
+                        + RawContacts.DELETED + " = 1 and " + RawContacts.ACCOUNT_NAME + " = ? and "
+                        + RawContacts.ACCOUNT_TYPE + " = ? and " + RawContacts.DIRTY + " = 1",
+                new String[] {
+                        Long.toString(rawContactId),
+                        sourceId,
+                        account.getAccountName(),
+                        account.getAccountType()
+                }));
+    }
+
+    private void assertMoveStubDoesNotExist(long rawContactId, AccountWithDataSet account) {
+        assertEquals(0, getCount(RawContacts.CONTENT_URI,
+                RawContacts._ID + " <> ? and "
+                        + RawContacts.DELETED + " = 1 and " + RawContacts.ACCOUNT_NAME + " = ? and "
+                        + RawContacts.ACCOUNT_TYPE + " = ?",
+                new String[] {
+                        Long.toString(rawContactId),
+                        account.getAccountName(),
+                        account.getAccountType()
+                }));
+    }
+
+    private long createStarredRawContactForMove(String firstName, String lastName, String sourceId,
+            Account account) {
+        long rawContactId = RawContactUtil.createRawContactWithName(
+                mResolver, firstName, lastName, account);
+        ContentValues rawContactValues = new ContentValues();
+        rawContactValues.put(RawContacts.SOURCE_ID, sourceId);
+        rawContactValues.put(RawContacts.STARRED, 1);
+
+        if (account == null) {
+            rawContactValues.putNull(RawContacts.ACCOUNT_NAME);
+            rawContactValues.putNull(RawContacts.ACCOUNT_TYPE);
+        } else {
+            rawContactValues.put(RawContacts.ACCOUNT_NAME, account.name);
+            rawContactValues.put(RawContacts.ACCOUNT_TYPE, account.type);
+        }
+
+        RawContactUtil.update(mResolver, rawContactId, rawContactValues);
+        return rawContactId;
+    }
+
+    private void insertNonPortableData(
+            ContentResolver resolver, long rawContactId, String data1) {
+        ContentValues values = new ContentValues();
+        values.put(Data.DATA1, data1);
+        values.put(Data.MIMETYPE, NON_PORTABLE_MIMETYPE);
+        values.put(Data.RAW_CONTACT_ID, rawContactId);
+        resolver.insert(Data.CONTENT_URI, values);
+    }
+
+    private void assertData(long rawContactId, String mimetype, String data1, int expectedCount) {
+        assertEquals(expectedCount, getCount(Data.CONTENT_URI,
+                Data.RAW_CONTACT_ID + " == ? AND "
+                        + Data.MIMETYPE + " = ? AND "
+                        + Data.DATA1 + " = ?",
+                new String[] {
+                        Long.toString(rawContactId),
+                        mimetype,
+                        data1
+                }));
+    }
+
+    private void assertDataExists(long rawContactId, String mimetype, String data1) {
+        assertData(rawContactId, mimetype, data1, 1);
+    }
+
+    private void assertDataDoesNotExist(long rawContactId, String mimetype, String data1) {
+        assertData(rawContactId, mimetype, data1, 0);
+    }
+
+    private Long createGroupWithMembers(AccountWithDataSet account,
+            String title, String titleRes, List<Long> memberIds) {
+        ContentValues values = new ContentValues();
+        values.put(Groups.TITLE, title);
+        values.put(Groups.TITLE_RES, titleRes);
+        values.put(Groups.RES_PACKAGE, RES_PACKAGE);
+        values.put(Groups.ACCOUNT_NAME, account.getAccountName());
+        values.put(Groups.ACCOUNT_TYPE, account.getAccountType());
+        values.put(Groups.DATA_SET, account.getDataSet());
+        mResolver.insert(Groups.CONTENT_URI, values);
+        Long groupId = getGroupWithName(account, title, titleRes);
+
+        for (Long rawContactId: memberIds) {
+            values = new ContentValues();
+            values.put(GroupMembership.GROUP_ROW_ID, groupId);
+            values.put(GroupMembership.RAW_CONTACT_ID, rawContactId);
+            values.put(Data.MIMETYPE, GroupMembership.CONTENT_ITEM_TYPE);
+            mResolver.insert(Data.CONTENT_URI, values);
+        }
+        return groupId;
+    }
+
+    private void promoteToSystemGroup(Long groupId, String systemId, boolean isReadOnly) {
+        ContentValues values = new ContentValues();
+        values.put(Groups.SYSTEM_ID, systemId);
+        values.put(Groups.GROUP_IS_READ_ONLY, isReadOnly ? 1 : 0);
+        mResolver.update(Groups.CONTENT_URI, values,
+                Groups._ID + " = ?",
+                new String[]{
+                        groupId.toString()
+                });
+    }
+
+    private void setGroupSourceId(Long groupId, String sourceId) {
+        ContentValues values = new ContentValues();
+        values.put(Groups.SOURCE_ID, sourceId);
+        mResolver.update(Groups.CONTENT_URI, values,
+                Groups._ID + " = ?",
+                new String[]{
+                        groupId.toString()
+                });
+    }
+
+    private void assertInGroup(Long rawContactId, Long groupId) {
+        assertEquals(1, getCount(Data.CONTENT_URI,
+                GroupMembership.GROUP_ROW_ID + " == ? AND "
+                        + Data.MIMETYPE + " = ? AND "
+                        + GroupMembership.RAW_CONTACT_ID + " = ?",
+                new String[] {
+                        Long.toString(groupId),
+                        GroupMembership.CONTENT_ITEM_TYPE,
+                        Long.toString(rawContactId)
+                }));
+    }
+
+    private void assertGroupState(Long groupId, AccountWithDataSet account, Set<Long> members,
+            boolean isDeleted) {
+        ContentValues contentValues = new ContentValues();
+        contentValues.put(Groups._ID, groupId);
+        contentValues.put(Groups.DELETED, isDeleted ? 1 : 0);
+        contentValues.put(Groups.ACCOUNT_NAME, account.getAccountName());
+        contentValues.put(Groups.ACCOUNT_TYPE, account.getAccountType());
+        contentValues.put(Groups.RES_PACKAGE, RES_PACKAGE);
+        contentValues.put(Groups.DIRTY, 1);
+        assertStoredValues(Groups.CONTENT_URI,
+                Groups._ID + " = ?",
+                new String[]{String.valueOf(groupId)},
+                contentValues);
+
+        assertEquals(members.size(), getCount(Data.CONTENT_URI,
+                GroupMembership.GROUP_ROW_ID + " == ? AND "
+                        + Data.MIMETYPE + " = ?",
+                new String[] {
+                        Long.toString(groupId),
+                        GroupMembership.CONTENT_ITEM_TYPE
+                }));
+
+        for (Long member: members) {
+            assertInGroup(member, groupId);
+        }
+    }
+
+    private void assertGroup(Long groupId, AccountWithDataSet account, Set<Long> members) {
+        assertGroupState(groupId, account, members, /* isDeleted= */ false);
+    }
+
+    private void assertGroupDeleted(Long groupId, AccountWithDataSet account) {
+        assertGroupState(groupId, account, Set.of(), /* isDeleted= */ true);
+    }
+
+    private void assertGroupMoveStubExists(long groupId, String sourceId,
+            AccountWithDataSet account) {
+        assertEquals(1, getCount(Groups.CONTENT_URI,
+                Groups._ID + " <> ? and " + Groups.SOURCE_ID + " = ? and "
+                        + Groups.DELETED + " = 1 and " + Groups.ACCOUNT_NAME + " = ? and "
+                        + Groups.ACCOUNT_TYPE + " = ? and " + Groups.DIRTY + " = 1",
+                new String[] {
+                        Long.toString(groupId),
+                        sourceId,
+                        account.getAccountName(),
+                        account.getAccountType()
+                }));
+    }
+
+    private Long getGroupWithName(AccountWithDataSet account, String title, String titleRes) {
+        try (Cursor c = mResolver.query(Groups.CONTENT_URI,
+                new String[] { Groups._ID, },
+                Groups.ACCOUNT_NAME + " = ? AND "
+                        + Groups.ACCOUNT_TYPE + " = ? AND "
+                        + Groups.TITLE + " = ? AND "
+                        + Groups.TITLE_RES + " = ?",
+                new String[] {
+                        account.getAccountName(),
+                        account.getAccountType(),
+                        title,
+                        titleRes
+                },
+                null)) {
+            assertNotNull(c);
+            c.moveToFirst();
+            return c.getLong(0);
+        }
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testMoveDuplicateRawContacts() {
+        // create a duplicate pair of contacts
+        long sourceDupeRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long destDupeRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                DEST_ACCOUNT);
+
+        // trigger the move
+        mMover.moveRawContacts(Set.of(mSource), mDest);
+
+        // verify the duplicate raw contact in dest has been deleted in place
+        assertMovedContactIsDeleted(sourceDupeRawContactId, mSource);
+
+        // verify the duplicate destination contact is unaffected
+        assertMovedRawContact(destDupeRawContactId, mDest, false);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testMoveUniqueRawContactsWithDataRows() {
+        // create a duplicate pair of contacts
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long destRawContactId1 = RawContactUtil.createRawContactWithName(mResolver, DEST_ACCOUNT);
+        long destRawContactId2 = RawContactUtil.createRawContactWithName(mResolver, DEST_ACCOUNT);
+        // create a combination of data rows
+        DataUtil.insertStructuredName(mResolver, sourceRawContactId, "firstA", "lastA");
+        DataUtil.insertStructuredName(mResolver, sourceRawContactId, "firstB", "lastB");
+        DataUtil.insertStructuredName(mResolver, destRawContactId1, "firstA", "lastA");
+        DataUtil.insertStructuredName(mResolver, destRawContactId2, "firstB", "lastB");
+
+        // trigger the move
+        mMover.moveRawContacts(Set.of(mSource), mDest);
+
+        // Verify no stub was written since no source ID existed
+        assertMoveStubDoesNotExist(sourceRawContactId, mSource);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(sourceRawContactId, mDest, false);
+
+        // verify the original near duplicate contact remains unchanged
+        assertMovedRawContact(destRawContactId1, mDest, false);
+        assertMovedRawContact(destRawContactId2, mDest, false);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    public void testMoveUniqueRawContacts() {
+        // create a near duplicate in the destination account
+        long destContactId = RawContactUtil.createRawContactWithName(
+                mResolver, "Foo", "Bar", DEST_ACCOUNT);
+
+        // create a near duplicate, unique contact in the source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar", SOURCE_ID, SOURCE_ACCOUNT);
+
+        // trigger the move
+        mMover.moveRawContactsWithSyncStubs(Set.of(mSource), mDest);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(uniqueContactId, mDest, true);
+
+        // verify a stub has been written for the unique raw contact in the source account
+        assertMoveStubExists(uniqueContactId, SOURCE_ID, mSource);
+
+        // verify the original near duplicate contact remains unchanged (still not starred)
+        assertMovedRawContact(destContactId, mDest, false);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testMoveUniqueRawContactsStubDisabled() {
+        // create a near duplicate in the destination account
+        long destContactId = RawContactUtil.createRawContactWithName(
+                mResolver, "Foo", "Bar", DEST_ACCOUNT);
+
+        // create a near duplicate, unique contact in the source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar", SOURCE_ID, SOURCE_ACCOUNT);
+
+        // trigger the move
+        mMover.moveRawContacts(Set.of(mSource), mDest);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(uniqueContactId, mDest, true);
+
+        // verify a stub has been written for the unique raw contact in the source account
+        assertMoveStubDoesNotExist(uniqueContactId, mSource);
+
+        // verify no stub was created (since we've disabled stub creation)
+        assertMovedRawContact(destContactId, mDest, false);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    public void testMoveUniqueRawContactsFromNullAccount() {
+        mActor.setAccounts(new Account[]{DEST_ACCOUNT});
+        AccountWithDataSet source =
+                AccountWithDataSet.get(null, null, null);
+
+        // create a near duplicate in the destination account
+        long destContactId = RawContactUtil.createRawContactWithName(
+                mResolver, "Foo", "Bar", DEST_ACCOUNT);
+
+        // create a near duplicate, unique contact in the source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar", SOURCE_ID, /* account= */ null);
+
+        // trigger the move
+        mMover.moveRawContactsWithSyncStubs(Set.of(source), mDest);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(uniqueContactId, mDest, true);
+
+        // verify we didn't write a stub since null accounts don't need them (they're not synced)
+        assertEquals(0, getCount(RawContacts.CONTENT_URI,
+                RawContacts._ID + " <> ? and " + RawContacts.SOURCE_ID + " = ? and "
+                        + RawContacts.DELETED + " = 1 and " + RawContacts.ACCOUNT_NAME + " IS NULL"
+                        + " and " + RawContacts.ACCOUNT_TYPE + " IS NULL",
+                new String[] {
+                        Long.toString(uniqueContactId),
+                        SOURCE_ID
+                }));
+
+        // verify the original near duplicate contact remains unchanged
+        assertMovedRawContact(destContactId, mDest, false);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    public void testMoveUniqueRawContactsFromNullAccountToEmptyDestination() {
+        mActor.setAccounts(new Account[]{DEST_ACCOUNT});
+        AccountWithDataSet source =
+                AccountWithDataSet.get(null, null, null);
+
+        // create a unique contact in the source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar", SOURCE_ID, /* account= */ null);
+
+        // trigger the move
+        mMover.moveRawContactsWithSyncStubs(Set.of(source), mDest);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(uniqueContactId, mDest, true);
+
+        // verify we didn't write a stub since null accounts don't need them (they're not synced)
+        assertEquals(0, getCount(RawContacts.CONTENT_URI,
+                RawContacts._ID + " <> ? and " + RawContacts.SOURCE_ID + " = ? and "
+                        + RawContacts.DELETED + " = 1 and " + RawContacts.ACCOUNT_NAME + " IS NULL"
+                        + " and " + RawContacts.ACCOUNT_TYPE + " IS NULL",
+                new String[] {
+                        Long.toString(uniqueContactId),
+                        SOURCE_ID
+                }));
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    public void testMoveUniqueRawContactsToNullAccount() {
+        mActor.setAccounts(new Account[]{SOURCE_ACCOUNT});
+        AccountWithDataSet dest =
+                AccountWithDataSet.get(null, null, null);
+
+        // create a unique contact in the source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar", SOURCE_ID, SOURCE_ACCOUNT);
+
+        // trigger the move
+        mMover.moveRawContactsWithSyncStubs(Set.of(mSource), dest);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(uniqueContactId, dest, true);
+
+        // verify a stub has been written for the unique raw contact in the source account
+        assertMoveStubExists(uniqueContactId, SOURCE_ID, mSource);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testMoveUniqueRawContactsToNullAccountStubDisabled() {
+        mActor.setAccounts(new Account[]{SOURCE_ACCOUNT});
+        AccountWithDataSet dest =
+                AccountWithDataSet.get(null, null, null);
+
+        // create a unique contact in the source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar", SOURCE_ID, SOURCE_ACCOUNT);
+
+        // trigger the move
+        mMover.moveRawContacts(Set.of(mSource), dest);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(uniqueContactId, dest, true);
+
+        // verify no stub was created (since stub creation is disabled)
+        assertMoveStubDoesNotExist(uniqueContactId, mSource);
+    }
+
+    /**
+     * Move a contact between source and dest where both account have different account types.
+     * The contact is unique because of a non-portable data row, because the account types don't
+     * match, the non-portable data row will be deleted before matching the contacts and the contact
+     * will be deleted as a duplicate.
+     */
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    public void testMoveUniqueRawContactWithNonPortableDataRows() {
+        // create a duplicate pair of contacts
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long destRawContactId = RawContactUtil.createRawContactWithName(mResolver, DEST_ACCOUNT);
+        // create a combination of data rows
+        DataUtil.insertStructuredName(mResolver, sourceRawContactId, "firstA", "lastA");
+        insertNonPortableData(mResolver, sourceRawContactId, "foo");
+        DataUtil.insertStructuredName(mResolver, destRawContactId, "firstA", "lastA");
+
+        // trigger the move
+        mMover.moveRawContactsWithSyncStubs(Set.of(mSource), mDest);
+
+        // Verify no stub was written since no source ID existed
+        assertMoveStubDoesNotExist(sourceRawContactId, mSource);
+
+        // verify the unique raw contact has been deleted as a duplicate
+        assertMovedContactIsDeleted(sourceRawContactId, mSource);
+        assertDataDoesNotExist(sourceRawContactId, NON_PORTABLE_MIMETYPE, "foo");
+        assertDataDoesNotExist(
+                sourceRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
+
+
+        // verify the original near duplicate contact remains unchanged
+        assertMovedRawContact(destRawContactId, mDest, false);
+        // the non portable data should still not exist on the destination account
+        assertDataDoesNotExist(destRawContactId, NON_PORTABLE_MIMETYPE, "foo");
+        // the existing data row in the destination account should be unaffected
+        assertDataExists(destRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
+    }
+
+    /**
+     * Moves a contact between source and dest where both accounts have the same account type.
+    *  The contact is unique because of a non-portable data row. Because the account types match,
+    *  the non-portable data row will be considered while matching the contacts and the contact will
+    *  be treated as unique.
+     */
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    public void testMoveUniqueRawContactsWithNonPortableDataRowsAccountTypesMatch() {
+        mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_ACCOUNT_WITH_SOURCE_TYPE});
+        AccountWithDataSet dest =
+                AccountWithDataSet.get(DEST_ACCOUNT_WITH_SOURCE_TYPE.name,
+                        DEST_ACCOUNT_WITH_SOURCE_TYPE.type, null);
+
+        // create a duplicate pair of contacts
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long destRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                DEST_ACCOUNT_WITH_SOURCE_TYPE);
+        // create a combination of data rows
+        DataUtil.insertStructuredName(mResolver, sourceRawContactId, "firstA", "lastA");
+        insertNonPortableData(mResolver, sourceRawContactId, "foo");
+        DataUtil.insertStructuredName(mResolver, destRawContactId, "firstA", "lastA");
+
+        // trigger the move
+        mMover.moveRawContactsWithSyncStubs(Set.of(mSource), dest);
+
+        // Verify no stub was written since no source ID existed
+        assertMoveStubDoesNotExist(sourceRawContactId, mSource);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(sourceRawContactId, dest, false);
+        // all data rows should have moved with the source
+        assertDataExists(sourceRawContactId, NON_PORTABLE_MIMETYPE, "foo");
+        assertDataExists(sourceRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
+
+        // verify the original near duplicate contact remains unchanged
+        assertMovedRawContact(destRawContactId, dest, false);
+        // the non portable data should still not exist on the destination account
+        assertDataDoesNotExist(destRawContactId, NON_PORTABLE_MIMETYPE, "foo");
+        // the existing data row in the destination account should be unaffected
+        assertDataExists(destRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
+    }
+
+    /**
+     * Moves a contact between source and dest where both accounts have the same account type.
+     * The contact is unique because of a non-portable data row. Because the account types match,
+     * the non-portable data row will be considered while matching the contacts and the contact will
+     * be treated as a duplicate.
+     */
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testMoveDuplicateRawContactsWithNonPortableDataRowsAccountTypesMatch() {
+        mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_ACCOUNT_WITH_SOURCE_TYPE});
+        AccountWithDataSet dest =
+                AccountWithDataSet.get(DEST_ACCOUNT_WITH_SOURCE_TYPE.name,
+                        DEST_ACCOUNT_WITH_SOURCE_TYPE.type, null);
+
+        // create a duplicate pair of contacts
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long destRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                DEST_ACCOUNT_WITH_SOURCE_TYPE);
+        // create a combination of data rows
+        DataUtil.insertStructuredName(mResolver, sourceRawContactId, "firstA", "lastA");
+        insertNonPortableData(mResolver, sourceRawContactId, "foo");
+        DataUtil.insertStructuredName(mResolver, destRawContactId, "firstA", "lastA");
+        insertNonPortableData(mResolver, destRawContactId, "foo");
+
+        // trigger the move
+        mMover.moveRawContacts(Set.of(mSource), dest);
+
+        // verify the duplicate contact has been deleted
+        assertMovedContactIsDeleted(sourceRawContactId, mSource);
+        assertDataDoesNotExist(sourceRawContactId, NON_PORTABLE_MIMETYPE, "foo");
+        assertDataDoesNotExist(
+                sourceRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
+
+        // verify the original near duplicate contact remains unchanged
+        assertMovedRawContact(destRawContactId, dest, false);
+        assertDataExists(destRawContactId, NON_PORTABLE_MIMETYPE, "foo");
+        assertDataExists(destRawContactId, StructuredName.CONTENT_ITEM_TYPE, "firstA lastA");
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    public void testMoveDuplicateNonSystemGroup() {
+        // create a duplicate pair of contacts
+        long sourceDupeRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long destDupeRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                DEST_ACCOUNT);
+        long sourceGroup = createGroupWithMembers(mSource, "groupTitle",
+                "groupTitleRes", List.of(sourceDupeRawContactId));
+        setGroupSourceId(sourceGroup, SOURCE_ID);
+        long destGroup = createGroupWithMembers(mDest, "groupTitle",
+                "groupTitleRes", List.of(destDupeRawContactId));
+
+        // trigger the move
+        mMover.moveRawContactsWithSyncStubs(Set.of(mSource), mDest);
+
+        // verify the duplicate raw contact in dest has been deleted in place instead of creating
+        // a stub (because this is a duplicate non-system group, we delete in-place even if there's
+        // a source ID)
+        assertMovedContactIsDeleted(sourceDupeRawContactId, mSource);
+
+        // since sourceGroup was a duplicate of destGroup, it was deleted in place
+        assertGroupDeleted(sourceGroup, mSource);
+
+        // verify the duplicate destination contact is unaffected
+        assertMovedRawContact(destDupeRawContactId, mDest, false);
+        assertGroup(destGroup, mDest, Set.of(destDupeRawContactId));
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    public void testMoveUniqueNonSystemGroup() {
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long sourceGroup = createGroupWithMembers(mSource, "groupTitle",
+                "groupTitleRes", List.of(sourceRawContactId));
+
+
+        // trigger the move
+        mMover.moveRawContactsWithSyncStubs(Set.of(mSource), mDest);
+
+        // verify group and contact have been moved from the source account to the dest account
+        assertMovedRawContact(sourceRawContactId, mDest, false);
+        assertGroup(sourceGroup, mDest, Set.of(sourceRawContactId));
+
+        // check that the only group in source got moved and no stub was written
+        assertEquals(0, getCount(Groups.CONTENT_URI,
+                Groups.ACCOUNT_NAME + " = ? AND "
+                        + Groups.ACCOUNT_TYPE + " = ?",
+                new String[] {
+                        mSource.getAccountName(),
+                        mSource.getAccountType()
+                }));
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    public void testMoveUniqueNonSystemGroupWithSourceId() {
+        // create a duplicate pair of contacts
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long sourceGroup = createGroupWithMembers(mSource, "groupTitle",
+                "groupTitleRes", List.of(sourceRawContactId));
+        setGroupSourceId(sourceGroup, SOURCE_ID);
+
+
+        // trigger the move
+        mMover.moveRawContactsWithSyncStubs(Set.of(mSource), mDest);
+
+        // verify group and contact have been moved from the source account to the dest account
+        assertMovedRawContact(sourceRawContactId, mDest, false);
+        assertGroup(sourceGroup, mDest, Set.of(sourceRawContactId));
+
+        // verify we created a move stub (since this was a unique non-system group with a source ID)
+        assertGroupMoveStubExists(sourceGroup, SOURCE_ID, mSource);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testMoveUniqueNonSystemGroupWithSourceIdStubsDisabled() {
+        // create a duplicate pair of contacts
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long sourceGroup = createGroupWithMembers(mSource, "groupTitle",
+                "groupTitleRes", List.of(sourceRawContactId));
+        setGroupSourceId(sourceGroup, SOURCE_ID);
+
+
+        // trigger the move
+        mMover.moveRawContacts(Set.of(mSource), mDest);
+
+        // verify group and contact have been moved from the source account to the dest account
+        assertMovedRawContact(sourceRawContactId, mDest, false);
+        assertGroup(sourceGroup, mDest, Set.of(sourceRawContactId));
+
+        // check that the only group in source got moved and no stub was written (because we
+        // disabled stub creation)
+        assertEquals(0, getCount(Groups.CONTENT_URI,
+                Groups.ACCOUNT_NAME + " = ? AND "
+                        + Groups.ACCOUNT_TYPE + " = ?",
+                new String[] {
+                        mSource.getAccountName(),
+                        mSource.getAccountType()
+                }));
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG, Flags.FLAG_CP2_ACCOUNT_MOVE_SYNC_STUB_FLAG})
+    public void testMoveUniqueRawContactsWithGroups() {
+        // create a duplicate pair of contacts
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long destRawContactId1 = RawContactUtil.createRawContactWithName(mResolver, DEST_ACCOUNT);
+        long destRawContactId2 = RawContactUtil.createRawContactWithName(mResolver, DEST_ACCOUNT);
+        // create a combination of data rows
+        long sourceGroup1 = createGroupWithMembers(
+                mSource, "group1Title", "group1TitleRes",
+                List.of(sourceRawContactId));
+        long sourceGroup2 = createGroupWithMembers(
+                mSource, "group2Title", "group2TitleRes",
+                List.of(sourceRawContactId));
+        promoteToSystemGroup(sourceGroup2, null, true);
+        long destGroup1 = createGroupWithMembers(
+                mDest, "group1Title", "group1TitleRes",
+                List.of(destRawContactId1));
+        long destGroup2 = createGroupWithMembers(
+                mDest, "group2Title", "group2TitleRes",
+                List.of(destRawContactId2));
+
+        // trigger the move
+        mMover.moveRawContactsWithSyncStubs(Set.of(mSource), mDest);
+
+        // Verify no stub was written since no source ID existed
+        assertMoveStubDoesNotExist(sourceRawContactId, mSource);
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(sourceRawContactId, mDest, false);
+
+        // check the source contact got moved into the new group
+        assertGroup(destGroup1, mDest, Set.of(sourceRawContactId, destRawContactId1));
+        assertGroup(destGroup2, mDest, Set.of(sourceRawContactId, destRawContactId2));
+        assertGroupDeleted(sourceGroup1, mSource);
+        assertGroup(sourceGroup2, mSource, Set.of());
+
+        // verify the original near duplicate contact remains unchanged
+        assertMovedRawContact(destRawContactId1, mDest, false);
+        assertMovedRawContact(destRawContactId2, mDest, false);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testMoveDuplicateSystemGroup() {
+        // create a duplicate pair of contacts
+        long sourceDupeRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long destDupeRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                DEST_ACCOUNT);
+        long sourceGroup = createGroupWithMembers(mSource, "groupTitle",
+                "groupTitleRes", List.of(sourceDupeRawContactId));
+        promoteToSystemGroup(sourceGroup, null, true);
+        setGroupSourceId(sourceGroup, SOURCE_ID);
+        long destGroup = createGroupWithMembers(mDest, "groupTitle",
+                "groupTitleRes", List.of(destDupeRawContactId));
+
+        // trigger the move
+        mMover.moveRawContacts(Set.of(mSource), mDest);
+
+        // verify the duplicate raw contact in dest has been deleted in place
+        assertMovedContactIsDeleted(sourceDupeRawContactId, mSource);
+
+        // Source group is a system group so it shouldn't get deleted
+        assertGroup(sourceGroup, mSource, Set.of());
+
+        // verify the duplicate destination contact is unaffected
+        assertMovedRawContact(destDupeRawContactId, mDest, false);
+
+        // The destination contact is the only one in destGroup since the source and destination
+        // contacts were true duplicates
+        assertGroup(destGroup, mDest, Set.of(destDupeRawContactId));
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testMoveUniqueSystemGroup() {
+        // create a duplicate pair of contacts
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long sourceGroup = createGroupWithMembers(mSource, "groupTitle",
+                "groupTitleRes", List.of(sourceRawContactId));
+        promoteToSystemGroup(sourceGroup, null, true);
+        setGroupSourceId(sourceGroup, SOURCE_ID);
+
+        // trigger the move
+        mMover.moveRawContacts(Set.of(mSource), mDest);
+
+        // verify the duplicate raw contact in dest has been deleted in place
+        assertMovedRawContact(sourceRawContactId, mDest, false);
+
+        // since sourceGroup is a system group, it cannot be deleted
+        assertGroup(sourceGroup, mSource, Set.of());
+
+        // verify that a copied group exists in dest now
+        long newGroup = getGroupWithName(mDest, "groupTitle", "groupTitleRes");
+        assertGroup(newGroup, mDest, Set.of(sourceRawContactId));
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testDoNotMoveEmptyUniqueSystemGroup() {
+        // create a duplicate pair of contacts
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long sourceGroup = createGroupWithMembers(mSource, "groupTitle",
+                "groupTitleRes", List.of());
+        promoteToSystemGroup(sourceGroup, null, true);
+
+        // trigger the move
+        mMover.moveRawContacts(Set.of(mSource), mDest);
+
+        // since sourceGroup is a system group, it cannot be deleted
+        assertGroup(sourceGroup, mSource, Set.of());
+
+        // verify the duplicate raw contact in dest has been deleted in place
+        assertMovedRawContact(sourceRawContactId, mDest, false);
+
+        // check that we did not create a copy of the empty group in dest
+        assertEquals(0, getCount(Groups.CONTENT_URI,
+                Groups.ACCOUNT_NAME + " = ? AND "
+                        + Groups.ACCOUNT_TYPE + " = ? AND "
+                        + Groups.TITLE + " = ? AND "
+                        + Groups.TITLE_RES + " = ?",
+                new String[] {
+                        mDest.getAccountName(),
+                        mDest.getAccountType(),
+                        "groupTitle",
+                        "groupTitleRes"
+                }));
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testDoNotMoveAutoAddSystemGroup() {
+        // create a duplicate pair of contacts
+        long sourceRawContactId = RawContactUtil.createRawContactWithName(mResolver,
+                SOURCE_ACCOUNT);
+        long sourceGroup = createGroupWithMembers(mSource, "groupTitle",
+                "groupTitleRes", List.of(sourceRawContactId));
+        promoteToSystemGroup(sourceGroup, null, true);
+        ContentValues values = new ContentValues();
+        values.put(Groups.AUTO_ADD, 1);
+        mResolver.update(Groups.CONTENT_URI, values,
+                Groups._ID + " = ?",
+                new String[]{
+                        Long.toString(sourceGroup)
+                });
+
+        // trigger the move
+        mMover.moveRawContacts(Set.of(mSource), mDest);
+
+        // since sourceGroup is a system group, it cannot be deleted
+        assertGroup(sourceGroup, mSource, Set.of());
+
+        // verify the duplicate raw contact in dest has been deleted in place
+        assertMovedRawContact(sourceRawContactId, mDest, false);
+
+        // check that we did not create a copy of the AUTO_ADD group in dest
+        assertEquals(0, getCount(Groups.CONTENT_URI,
+                Groups.ACCOUNT_NAME + " = ? AND "
+                        + Groups.ACCOUNT_TYPE + " = ? AND "
+                        + Groups.TITLE + " = ? AND "
+                        + Groups.TITLE_RES + " = ?",
+                new String[] {
+                        mDest.getAccountName(),
+                        mDest.getAccountType(),
+                        "groupTitle",
+                        "groupTitleRes"
+                }));
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testMoveLocalToDefaultCloudAccount() {
+        mActor.setAccounts(new Account[]{DEST_CLOUD_ACCOUNT});
+        setDefaultAccountManagerAccounts(new Account[]{
+                DEST_CLOUD_ACCOUNT,
+        });
+        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccount.ofCloud(DEST_CLOUD_ACCOUNT));
+
+        // create a unique contact in the (null/local) source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar",  /* sourceId= */ null, /* account= */ null);
+
+        // trigger the move
+        mMover.moveLocalToCloudDefaultAccount();
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(uniqueContactId, mCloudDest, true);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testMoveToDefaultNonCloudAccount() {
+        mActor.setAccounts(new Account[]{DEST_ACCOUNT});
+        AccountWithDataSet source =
+                AccountWithDataSet.get(null, null, null);
+        setDefaultAccountManagerAccounts(new Account[]{
+                DEST_ACCOUNT,
+        });
+        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccount.ofCloud(DEST_ACCOUNT));
+
+        // create a unique contact in the (null/local) source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar", /* sourceId= */ null, /* account= */ null);
+
+        // trigger the move
+        mMover.moveLocalToCloudDefaultAccount();
+
+        // verify the unique raw contact has *not* been moved
+        assertMovedRawContact(uniqueContactId, source, true);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testMoveFromNonLocalAccount() {
+        mActor.setAccounts(new Account[]{SOURCE_ACCOUNT, DEST_CLOUD_ACCOUNT});
+        setDefaultAccountManagerAccounts(new Account[]{
+                SOURCE_ACCOUNT,
+                DEST_ACCOUNT,
+        });
+        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccount.ofCloud(DEST_ACCOUNT));
+
+        // create a unique contact in the source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar", /* sourceId= */ null, SOURCE_ACCOUNT);
+
+        // trigger the move
+        mMover.moveLocalToCloudDefaultAccount();
+
+        // verify the unique raw contact has *not* been moved
+        assertMovedRawContact(uniqueContactId, mSource, true);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testMoveSimToDefaultCloudAccount() {
+        mActor.setAccounts(new Account[]{SIM_ACCOUNT, DEST_CLOUD_ACCOUNT});
+
+        setDefaultAccountManagerAccounts(new Account[]{
+                SIM_ACCOUNT,
+                DEST_CLOUD_ACCOUNT,
+        });
+        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccount.ofCloud(DEST_CLOUD_ACCOUNT));
+
+        // create a unique contact in the (null/local) source account
+        long uniqueContactId = createStarredRawContactForMove(
+                "Foo", "Bar",  /* sourceId= */ null, /* account= */ SIM_ACCOUNT);
+
+        // trigger the move
+        mMover.moveSimToCloudDefaultAccount();
+
+        // verify the unique raw contact has been moved from the old -> new account
+        assertMovedRawContact(uniqueContactId, mCloudDest, true);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testGetNumberContactsWithSimContacts() {
+        mActor.setAccounts(new Account[]{SIM_ACCOUNT, DEST_CLOUD_ACCOUNT});
+
+        setDefaultAccountManagerAccounts(new Account[]{
+                SIM_ACCOUNT,
+                DEST_CLOUD_ACCOUNT,
+        });
+        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccount.ofCloud(DEST_CLOUD_ACCOUNT));
+
+        // create a unique contact in a sim account
+        createStarredRawContactForMove(
+                "Foo", "Bar",  /* sourceId= */ null, /* account= */ SIM_ACCOUNT);
+        // create a unique contact in a non-sim account
+        createStarredRawContactForMove(
+                "Bar", "Baz",  /* sourceId= */ null, /* account= */ DEST_CLOUD_ACCOUNT);
+
+        // get the counts
+        int localCount = mMover.getNumberLocalContacts();
+        int simCount = mMover.getNumberSimContacts();
+
+        // only contact is in the sim count
+        assertEquals(1, simCount);
+        assertEquals(0, localCount);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testGetNumberContactsWithLocalContacts() {
+        mActor.setAccounts(new Account[]{DEST_CLOUD_ACCOUNT});
+        setDefaultAccountManagerAccounts(new Account[]{
+                DEST_CLOUD_ACCOUNT,
+        });
+        mDefaultAccountManager.tryPushDefaultAccount(DefaultAccount.ofCloud(DEST_CLOUD_ACCOUNT));
+
+        // create a unique contact in the (null/local) source account
+        createStarredRawContactForMove(
+                "Foo", "Bar",  /* sourceId= */ null, /* account= */ null);
+
+        // trigger the move
+        int localCount = mMover.getNumberLocalContacts();
+        int simCount = mMover.getNumberSimContacts();
+
+        // only contact is in the local count
+        assertEquals(1, localCount);
+        assertEquals(0, simCount);
+    }
+
+    @Test
+    @EnableFlags({Flags.FLAG_CP2_ACCOUNT_MOVE_FLAG})
+    public void testGetNumberContactsWithoutCloudAccount() {
+        mActor.setAccounts(new Account[]{SIM_ACCOUNT});
+
+        setDefaultAccountManagerAccounts(new Account[]{SIM_ACCOUNT});
+        // create a unique contact in the sim and local source accounts
+        createStarredRawContactForMove(
+                "Foo", "Bar",  /* sourceId= */ null, /* account= */ SIM_ACCOUNT);
+        createStarredRawContactForMove(
+                "Bar", "Baz",  /* sourceId= */ null, /* account= */ null);
+
+        // trigger the move
+        int localCount = mMover.getNumberLocalContacts();
+        int simCount = mMover.getNumberSimContacts();
+
+        // no movable contacts without a Cloud Default Account
+        assertEquals(0, localCount);
+        assertEquals(0, simCount);
+    }
+}
diff --git a/tests/src/com/android/providers/contacts/UnSyncAccountsTest.java b/tests/src/com/android/providers/contacts/UnSyncAccountsTest.java
new file mode 100644
index 00000000..9d0a6b97
--- /dev/null
+++ b/tests/src/com/android/providers/contacts/UnSyncAccountsTest.java
@@ -0,0 +1,176 @@
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
+package com.android.providers.contacts;
+
+import android.accounts.Account;
+import android.content.ContentUris;
+import android.content.ContentValues;
+import android.net.Uri;
+import android.platform.test.flag.junit.SetFlagsRule;
+import android.provider.ContactsContract;
+import android.provider.ContactsContract.RawContacts;
+import android.provider.ContactsContract.StreamItemPhotos;
+import android.provider.ContactsContract.StreamItems;
+
+import androidx.test.filters.MediumTest;
+
+import com.android.providers.contacts.tests.R;
+import com.android.providers.contacts.testutil.RawContactUtil;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.ClassRule;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+
+/**
+ * Unit tests for {@link ContactsProvider2} UnSync API.
+ *
+ * Run the test like this:
+ * <code>
+ * adb shell am instrument -e class com.android.providers.contacts.UnSyncAccountsTest -w \
+ * com.android.providers.contacts.tests/android.test.InstrumentationTestRunner
+ * </code>
+ */
+@MediumTest
+@RunWith(JUnit4.class)
+public class UnSyncAccountsTest extends BaseContactsProvider2Test {
+    @ClassRule
+    public static final SetFlagsRule.ClassRule mClassRule = new SetFlagsRule.ClassRule();
+
+    @Rule
+    public final SetFlagsRule mSetFlagsRule = mClassRule.createSetFlagsRule();
+
+    @Before
+    @Override
+    public void setUp() throws Exception {
+        super.setUp();
+    }
+
+    @After
+    @Override
+    public void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    @Test
+    public void testAccountUnSynced() {
+        Account readOnlyAccount = new Account("act", READ_ONLY_ACCOUNT_TYPE);
+        ContactsProvider2 cp = (ContactsProvider2) getProvider();
+        mActor.setAccounts(new Account[]{readOnlyAccount, mAccount});
+        cp.onAccountsUpdated(new Account[]{readOnlyAccount, mAccount});
+
+        long rawContactId1 = RawContactUtil.createRawContactWithName(mResolver, "John", "Doe",
+                readOnlyAccount);
+        Uri photoUri1 = insertPhoto(rawContactId1);
+        long rawContactId2 = RawContactUtil.createRawContactWithName(mResolver, "john", "doe",
+                mAccount);
+        Uri photoUri2 = insertPhoto(rawContactId2);
+        storeValue(photoUri2, ContactsContract.CommonDataKinds.Photo.IS_SUPER_PRIMARY, "1");
+
+        assertAggregated(rawContactId1, rawContactId2);
+
+        long contactId = queryContactId(rawContactId1);
+
+        // The display name should come from the writable account
+        assertStoredValue(Uri.withAppendedPath(
+                        ContentUris.withAppendedId(ContactsContract.Contacts.CONTENT_URI,
+                                contactId),
+                        ContactsContract.Contacts.Data.CONTENT_DIRECTORY),
+                ContactsContract.Contacts.DISPLAY_NAME, "john doe");
+
+        // The photo should be the one we marked as super-primary
+        assertStoredValue(ContactsContract.Contacts.CONTENT_URI, contactId,
+                ContactsContract.Contacts.PHOTO_ID, ContentUris.parseId(photoUri2));
+
+        mActor.setAccounts(new Account[]{readOnlyAccount, mAccount});
+        // Un Sync account.
+        cp.unSyncAccounts(new Account[]{mAccount});
+
+        // The display name should come from the remaining account
+        assertStoredValue(Uri.withAppendedPath(
+                        ContentUris.withAppendedId(ContactsContract.Contacts.CONTENT_URI,
+                                contactId),
+                        ContactsContract.Contacts.Data.CONTENT_DIRECTORY),
+                ContactsContract.Contacts.DISPLAY_NAME, "John Doe");
+
+        // The photo should be the remaining one
+        assertStoredValue(ContactsContract.Contacts.CONTENT_URI, contactId,
+                ContactsContract.Contacts.PHOTO_ID, ContentUris.parseId(photoUri1));
+    }
+
+    @Test
+    public void testStreamItemsCleanedUpOnAccountUnSynced() {
+        Account doomedAccount = new Account("doom", "doom");
+        Account safeAccount = mAccount;
+        ContactsProvider2 cp = (ContactsProvider2) getProvider();
+        mActor.setAccounts(new Account[]{doomedAccount, safeAccount});
+        cp.onAccountsUpdated(new Account[]{doomedAccount, safeAccount});
+
+        // Create a doomed raw contact, stream item, and photo.
+        long doomedRawContactId = RawContactUtil.createRawContactWithName(mResolver, doomedAccount);
+        Uri doomedStreamItemUri =
+                insertStreamItem(doomedRawContactId, buildGenericStreamItemValues(), doomedAccount);
+        long doomedStreamItemId = ContentUris.parseId(doomedStreamItemUri);
+        Uri doomedStreamItemPhotoUri = insertStreamItemPhoto(
+                doomedStreamItemId, buildGenericStreamItemPhotoValues(0), doomedAccount);
+
+        // Create a safe raw contact, stream item, and photo.
+        long safeRawContactId = RawContactUtil.createRawContactWithName(mResolver, safeAccount);
+        Uri safeStreamItemUri =
+                insertStreamItem(safeRawContactId, buildGenericStreamItemValues(), safeAccount);
+        long safeStreamItemId = ContentUris.parseId(safeStreamItemUri);
+        Uri safeStreamItemPhotoUri = insertStreamItemPhoto(
+                safeStreamItemId, buildGenericStreamItemPhotoValues(0), safeAccount);
+        long safeStreamItemPhotoId = ContentUris.parseId(safeStreamItemPhotoUri);
+
+        // UnSync the doomed account.
+        cp.unSyncAccounts(new Account[]{doomedAccount});
+
+        // Check that the doomed stuff has all been nuked.
+        ContentValues[] noValues = new ContentValues[0];
+        assertStoredValues(ContentUris.withAppendedId(RawContacts.CONTENT_URI, doomedRawContactId),
+                noValues);
+        assertStoredValues(doomedStreamItemUri, noValues);
+        assertStoredValues(doomedStreamItemPhotoUri, noValues);
+
+        // Check that the safe stuff lives on.
+        assertStoredValue(RawContacts.CONTENT_URI, safeRawContactId, RawContacts._ID,
+                safeRawContactId);
+        assertStoredValue(safeStreamItemUri, StreamItems._ID, safeStreamItemId);
+        assertStoredValue(safeStreamItemPhotoUri, StreamItemPhotos._ID, safeStreamItemPhotoId);
+    }
+
+    private ContentValues buildGenericStreamItemValues() {
+        ContentValues values = new ContentValues();
+        values.put(StreamItems.TEXT, "Hello world");
+        values.put(StreamItems.TIMESTAMP, System.currentTimeMillis());
+        values.put(StreamItems.COMMENTS, "Reshared by 123 others");
+        return values;
+    }
+
+    private ContentValues buildGenericStreamItemPhotoValues(int sortIndex) {
+        ContentValues values = new ContentValues();
+        values.put(StreamItemPhotos.SORT_INDEX, sortIndex);
+        values.put(StreamItemPhotos.PHOTO,
+                loadPhotoFromResource(R.drawable.earth_normal, PhotoSize.ORIGINAL));
+        return values;
+    }
+}
```

