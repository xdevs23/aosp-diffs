```diff
diff --git a/.gitignore b/.gitignore
index 7b74e6c..b2c6023 100644
--- a/.gitignore
+++ b/.gitignore
@@ -1,19 +1,18 @@
 *.iml
 .gradle
 /local.properties
-/.idea/caches
-/.idea/libraries
-/.idea/modules.xml
-/.idea/workspace.xml
-/.idea/navEditor.xml
-/.idea/assetWizardSettings.xml
+**/.idea/**
+!**/.idea/codeStyleSettings.xml
+!**/.idea/copyright
+!**/.idea/codeStyles
+!.idea/codeStyles/Project.xml
+!.idea/codeStyles/codeStyleConfig.xml
+!.idea/copyright/AOSP.xml
+!.idea/copyright/profiles_settings.xml
+!.idea/inspectionProfiles/Project_Default.xml
 .DS_Store
 **/build
 /captures
 .externalNativeBuild
 .cxx
 local.properties
-.idea/deploymentTargetDropDown.xml
-.idea/gradle.xml
-.idea/deploymentTargetSelector.xml
-.idea/androidTestResultsUserPreferences.xml
\ No newline at end of file
diff --git a/.idea/.gitignore b/.idea/.gitignore
deleted file mode 100644
index 26d3352..0000000
--- a/.idea/.gitignore
+++ /dev/null
@@ -1,3 +0,0 @@
-# Default ignored files
-/shelf/
-/workspace.xml
diff --git a/.idea/.name b/.idea/.name
deleted file mode 100644
index e3b6108..0000000
--- a/.idea/.name
+++ /dev/null
@@ -1 +0,0 @@
-Jetpack Camera
\ No newline at end of file
diff --git a/.idea/androidTestResultsUserPreferences.xml b/.idea/androidTestResultsUserPreferences.xml
deleted file mode 100644
index c64c910..0000000
--- a/.idea/androidTestResultsUserPreferences.xml
+++ /dev/null
@@ -1,23 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<project version="4">
-  <component name="AndroidTestResultsUserPreferences">
-    <option name="androidTestResultsTableState">
-      <map>
-        <entry key="811462001">
-          <value>
-            <AndroidTestResultsTableState>
-              <option name="preferredColumnWidths">
-                <map>
-                  <entry key="Duration" value="90" />
-                  <entry key="Pixel_7_Pro_API_34" value="120" />
-                  <entry key="Pixel_C_API_34" value="120" />
-                  <entry key="Tests" value="360" />
-                </map>
-              </option>
-            </AndroidTestResultsTableState>
-          </value>
-        </entry>
-      </map>
-    </option>
-  </component>
-</project>
\ No newline at end of file
diff --git a/.idea/compiler.xml b/.idea/compiler.xml
deleted file mode 100644
index b589d56..0000000
--- a/.idea/compiler.xml
+++ /dev/null
@@ -1,6 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<project version="4">
-  <component name="CompilerConfiguration">
-    <bytecodeTargetLevel target="17" />
-  </component>
-</project>
\ No newline at end of file
diff --git a/.idea/deploymentTargetSelector.xml b/.idea/deploymentTargetSelector.xml
deleted file mode 100644
index b268ef3..0000000
--- a/.idea/deploymentTargetSelector.xml
+++ /dev/null
@@ -1,10 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<project version="4">
-  <component name="deploymentTargetSelector">
-    <selectionStates>
-      <SelectionState runConfigName="app">
-        <option name="selectionMode" value="DROPDOWN" />
-      </SelectionState>
-    </selectionStates>
-  </component>
-</project>
\ No newline at end of file
diff --git a/.idea/gradle.xml b/.idea/gradle.xml
deleted file mode 100644
index ce85930..0000000
--- a/.idea/gradle.xml
+++ /dev/null
@@ -1,29 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<project version="4">
-  <component name="GradleMigrationSettings" migrationVersion="1" />
-  <component name="GradleSettings">
-    <option name="linkedExternalProjectsSettings">
-      <GradleProjectSettings>
-        <option name="externalProjectPath" value="$PROJECT_DIR$" />
-        <option name="gradleJvm" value="jbr-17" />
-        <option name="modules">
-          <set>
-            <option value="$PROJECT_DIR$" />
-            <option value="$PROJECT_DIR$/app" />
-            <option value="$PROJECT_DIR$/benchmark" />
-            <option value="$PROJECT_DIR$/core" />
-            <option value="$PROJECT_DIR$/core/camera" />
-            <option value="$PROJECT_DIR$/core/common" />
-            <option value="$PROJECT_DIR$/data" />
-            <option value="$PROJECT_DIR$/data/settings" />
-            <option value="$PROJECT_DIR$/feature" />
-            <option value="$PROJECT_DIR$/feature/permissions" />
-            <option value="$PROJECT_DIR$/feature/preview" />
-            <option value="$PROJECT_DIR$/feature/settings" />
-          </set>
-        </option>
-        <option name="resolveExternalAnnotations" value="false" />
-      </GradleProjectSettings>
-    </option>
-  </component>
-</project>
\ No newline at end of file
diff --git a/.idea/inspectionProfiles/Project_Default.xml b/.idea/inspectionProfiles/Project_Default.xml
deleted file mode 100644
index 44ca2d9..0000000
--- a/.idea/inspectionProfiles/Project_Default.xml
+++ /dev/null
@@ -1,41 +0,0 @@
-<component name="InspectionProjectProfileManager">
-  <profile version="1.0">
-    <option name="myName" value="Project Default" />
-    <inspection_tool class="PreviewAnnotationInFunctionWithParameters" enabled="true" level="ERROR" enabled_by_default="true">
-      <option name="composableFile" value="true" />
-      <option name="previewFile" value="true" />
-    </inspection_tool>
-    <inspection_tool class="PreviewApiLevelMustBeValid" enabled="true" level="ERROR" enabled_by_default="true">
-      <option name="composableFile" value="true" />
-      <option name="previewFile" value="true" />
-    </inspection_tool>
-    <inspection_tool class="PreviewDimensionRespectsLimit" enabled="true" level="WARNING" enabled_by_default="true">
-      <option name="composableFile" value="true" />
-      <option name="previewFile" value="true" />
-    </inspection_tool>
-    <inspection_tool class="PreviewFontScaleMustBeGreaterThanZero" enabled="true" level="ERROR" enabled_by_default="true">
-      <option name="composableFile" value="true" />
-      <option name="previewFile" value="true" />
-    </inspection_tool>
-    <inspection_tool class="PreviewMultipleParameterProviders" enabled="true" level="ERROR" enabled_by_default="true">
-      <option name="composableFile" value="true" />
-      <option name="previewFile" value="true" />
-    </inspection_tool>
-    <inspection_tool class="PreviewMustBeTopLevelFunction" enabled="true" level="ERROR" enabled_by_default="true">
-      <option name="composableFile" value="true" />
-      <option name="previewFile" value="true" />
-    </inspection_tool>
-    <inspection_tool class="PreviewNeedsComposableAnnotation" enabled="true" level="ERROR" enabled_by_default="true">
-      <option name="composableFile" value="true" />
-      <option name="previewFile" value="true" />
-    </inspection_tool>
-    <inspection_tool class="PreviewNotSupportedInUnitTestFiles" enabled="true" level="ERROR" enabled_by_default="true">
-      <option name="composableFile" value="true" />
-      <option name="previewFile" value="true" />
-    </inspection_tool>
-    <inspection_tool class="PreviewPickerAnnotation" enabled="true" level="ERROR" enabled_by_default="true">
-      <option name="composableFile" value="true" />
-      <option name="previewFile" value="true" />
-    </inspection_tool>
-  </profile>
-</component>
\ No newline at end of file
diff --git a/.idea/kotlinc.xml b/.idea/kotlinc.xml
deleted file mode 100644
index 8d81632..0000000
--- a/.idea/kotlinc.xml
+++ /dev/null
@@ -1,6 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<project version="4">
-  <component name="KotlinJpsPluginSettings">
-    <option name="version" value="1.9.22" />
-  </component>
-</project>
\ No newline at end of file
diff --git a/.idea/migrations.xml b/.idea/migrations.xml
deleted file mode 100644
index f8051a6..0000000
--- a/.idea/migrations.xml
+++ /dev/null
@@ -1,10 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<project version="4">
-  <component name="ProjectMigrations">
-    <option name="MigrateToGradleLocalJavaHome">
-      <set>
-        <option value="$PROJECT_DIR$" />
-      </set>
-    </option>
-  </component>
-</project>
\ No newline at end of file
diff --git a/.idea/misc.xml b/.idea/misc.xml
deleted file mode 100644
index 0ff99b3..0000000
--- a/.idea/misc.xml
+++ /dev/null
@@ -1,61 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<project version="4">
-  <component name="ExternalStorageConfigurationManager" enabled="true" />
-  <component name="NullableNotNullManager">
-    <option name="myDefaultNullable" value="androidx.annotation.Nullable" />
-    <option name="myDefaultNotNull" value="androidx.annotation.NonNull" />
-    <option name="myNullables">
-      <value>
-        <list size="18">
-          <item index="0" class="java.lang.String" itemvalue="com.android.annotations.Nullable" />
-          <item index="1" class="java.lang.String" itemvalue="org.jspecify.nullness.Nullable" />
-          <item index="2" class="java.lang.String" itemvalue="androidx.annotation.RecentlyNullable" />
-          <item index="3" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.compatqual.NullableDecl" />
-          <item index="4" class="java.lang.String" itemvalue="org.jetbrains.annotations.Nullable" />
-          <item index="5" class="java.lang.String" itemvalue="androidx.annotation.Nullable" />
-          <item index="6" class="java.lang.String" itemvalue="org.eclipse.jdt.annotation.Nullable" />
-          <item index="7" class="java.lang.String" itemvalue="edu.umd.cs.findbugs.annotations.Nullable" />
-          <item index="8" class="java.lang.String" itemvalue="android.support.annotation.Nullable" />
-          <item index="9" class="java.lang.String" itemvalue="javax.annotation.CheckForNull" />
-          <item index="10" class="java.lang.String" itemvalue="javax.annotation.Nullable" />
-          <item index="11" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.qual.Nullable" />
-          <item index="12" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.compatqual.NullableType" />
-          <item index="13" class="java.lang.String" itemvalue="android.annotation.Nullable" />
-          <item index="14" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.compatqual.NullableDecl" />
-          <item index="15" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.compatqual.NullableType" />
-          <item index="16" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.qual.Nullable" />
-          <item index="17" class="java.lang.String" itemvalue="jakarta.annotation.Nullable" />
-        </list>
-      </value>
-    </option>
-    <option name="myNotNulls">
-      <value>
-        <list size="17">
-          <item index="0" class="java.lang.String" itemvalue="androidx.annotation.RecentlyNonNull" />
-          <item index="1" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.qual.NonNull" />
-          <item index="2" class="java.lang.String" itemvalue="org.jspecify.nullness.NonNull" />
-          <item index="3" class="java.lang.String" itemvalue="com.android.annotations.NonNull" />
-          <item index="4" class="java.lang.String" itemvalue="androidx.annotation.NonNull" />
-          <item index="5" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.compatqual.NonNullType" />
-          <item index="6" class="java.lang.String" itemvalue="edu.umd.cs.findbugs.annotations.NonNull" />
-          <item index="7" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.compatqual.NonNullDecl" />
-          <item index="8" class="java.lang.String" itemvalue="android.support.annotation.NonNull" />
-          <item index="9" class="java.lang.String" itemvalue="org.jetbrains.annotations.NotNull" />
-          <item index="10" class="java.lang.String" itemvalue="javax.annotation.Nonnull" />
-          <item index="11" class="java.lang.String" itemvalue="org.eclipse.jdt.annotation.NonNull" />
-          <item index="12" class="java.lang.String" itemvalue="android.annotation.NonNull" />
-          <item index="13" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.compatqual.NonNullDecl" />
-          <item index="14" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.compatqual.NonNullType" />
-          <item index="15" class="java.lang.String" itemvalue="org.checkerframework.checker.nullness.qual.NonNull" />
-          <item index="16" class="java.lang.String" itemvalue="jakarta.annotation.Nonnull" />
-        </list>
-      </value>
-    </option>
-  </component>
-  <component name="ProjectRootManager" version="2" languageLevel="JDK_17" default="true" project-jdk-name="Android Studio default JDK" project-jdk-type="JavaSDK">
-    <output url="file://$PROJECT_DIR$/build/classes" />
-  </component>
-  <component name="ProjectType">
-    <option name="id" value="Android" />
-  </component>
-</project>
\ No newline at end of file
diff --git a/.idea/other.xml b/.idea/other.xml
new file mode 100644
index 0000000..94c96f6
--- /dev/null
+++ b/.idea/other.xml
@@ -0,0 +1,318 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<project version="4">
+  <component name="direct_access_persist.xml">
+    <option name="deviceSelectionList">
+      <list>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="27" />
+          <option name="brand" value="DOCOMO" />
+          <option name="codename" value="F01L" />
+          <option name="id" value="F01L" />
+          <option name="manufacturer" value="FUJITSU" />
+          <option name="name" value="F-01L" />
+          <option name="screenDensity" value="360" />
+          <option name="screenX" value="720" />
+          <option name="screenY" value="1280" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="28" />
+          <option name="brand" value="DOCOMO" />
+          <option name="codename" value="SH-01L" />
+          <option name="id" value="SH-01L" />
+          <option name="manufacturer" value="SHARP" />
+          <option name="name" value="AQUOS sense2 SH-01L" />
+          <option name="screenDensity" value="480" />
+          <option name="screenX" value="1080" />
+          <option name="screenY" value="2160" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="31" />
+          <option name="brand" value="samsung" />
+          <option name="codename" value="a51" />
+          <option name="id" value="a51" />
+          <option name="manufacturer" value="Samsung" />
+          <option name="name" value="Galaxy A51" />
+          <option name="screenDensity" value="420" />
+          <option name="screenX" value="1080" />
+          <option name="screenY" value="2400" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="34" />
+          <option name="brand" value="google" />
+          <option name="codename" value="akita" />
+          <option name="id" value="akita" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel 8a" />
+          <option name="screenDensity" value="420" />
+          <option name="screenX" value="1080" />
+          <option name="screenY" value="2400" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="33" />
+          <option name="brand" value="samsung" />
+          <option name="codename" value="b0q" />
+          <option name="id" value="b0q" />
+          <option name="manufacturer" value="Samsung" />
+          <option name="name" value="Galaxy S22 Ultra" />
+          <option name="screenDensity" value="600" />
+          <option name="screenX" value="1440" />
+          <option name="screenY" value="3088" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="32" />
+          <option name="brand" value="google" />
+          <option name="codename" value="bluejay" />
+          <option name="id" value="bluejay" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel 6a" />
+          <option name="screenDensity" value="420" />
+          <option name="screenX" value="1080" />
+          <option name="screenY" value="2400" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="34" />
+          <option name="brand" value="google" />
+          <option name="codename" value="caiman" />
+          <option name="id" value="caiman" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel 9 Pro" />
+          <option name="screenDensity" value="360" />
+          <option name="screenX" value="960" />
+          <option name="screenY" value="2142" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="34" />
+          <option name="brand" value="google" />
+          <option name="codename" value="comet" />
+          <option name="id" value="comet" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel 9 Pro Fold" />
+          <option name="screenDensity" value="390" />
+          <option name="screenX" value="2076" />
+          <option name="screenY" value="2152" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="29" />
+          <option name="brand" value="samsung" />
+          <option name="codename" value="crownqlteue" />
+          <option name="id" value="crownqlteue" />
+          <option name="manufacturer" value="Samsung" />
+          <option name="name" value="Galaxy Note9" />
+          <option name="screenDensity" value="420" />
+          <option name="screenX" value="2220" />
+          <option name="screenY" value="1080" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="34" />
+          <option name="brand" value="samsung" />
+          <option name="codename" value="dm3q" />
+          <option name="id" value="dm3q" />
+          <option name="manufacturer" value="Samsung" />
+          <option name="name" value="Galaxy S23 Ultra" />
+          <option name="screenDensity" value="600" />
+          <option name="screenX" value="1440" />
+          <option name="screenY" value="3088" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="34" />
+          <option name="brand" value="samsung" />
+          <option name="codename" value="e1q" />
+          <option name="id" value="e1q" />
+          <option name="manufacturer" value="Samsung" />
+          <option name="name" value="Galaxy S24" />
+          <option name="screenDensity" value="480" />
+          <option name="screenX" value="1080" />
+          <option name="screenY" value="2340" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="33" />
+          <option name="brand" value="google" />
+          <option name="codename" value="felix" />
+          <option name="id" value="felix" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel Fold" />
+          <option name="screenDensity" value="420" />
+          <option name="screenX" value="2208" />
+          <option name="screenY" value="1840" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="34" />
+          <option name="brand" value="google" />
+          <option name="codename" value="felix" />
+          <option name="id" value="felix" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel Fold" />
+          <option name="screenDensity" value="420" />
+          <option name="screenX" value="2208" />
+          <option name="screenY" value="1840" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="33" />
+          <option name="brand" value="google" />
+          <option name="codename" value="felix_camera" />
+          <option name="id" value="felix_camera" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel Fold (Camera-enabled)" />
+          <option name="screenDensity" value="420" />
+          <option name="screenX" value="2208" />
+          <option name="screenY" value="1840" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="33" />
+          <option name="brand" value="samsung" />
+          <option name="codename" value="gts8uwifi" />
+          <option name="id" value="gts8uwifi" />
+          <option name="manufacturer" value="Samsung" />
+          <option name="name" value="Galaxy Tab S8 Ultra" />
+          <option name="screenDensity" value="320" />
+          <option name="screenX" value="1848" />
+          <option name="screenY" value="2960" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="34" />
+          <option name="brand" value="google" />
+          <option name="codename" value="husky" />
+          <option name="id" value="husky" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel 8 Pro" />
+          <option name="screenDensity" value="390" />
+          <option name="screenX" value="1008" />
+          <option name="screenY" value="2244" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="30" />
+          <option name="brand" value="motorola" />
+          <option name="codename" value="java" />
+          <option name="id" value="java" />
+          <option name="manufacturer" value="Motorola" />
+          <option name="name" value="G20" />
+          <option name="screenDensity" value="280" />
+          <option name="screenX" value="720" />
+          <option name="screenY" value="1600" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="34" />
+          <option name="brand" value="google" />
+          <option name="codename" value="komodo" />
+          <option name="id" value="komodo" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel 9 Pro XL" />
+          <option name="screenDensity" value="360" />
+          <option name="screenX" value="1008" />
+          <option name="screenY" value="2244" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="33" />
+          <option name="brand" value="google" />
+          <option name="codename" value="lynx" />
+          <option name="id" value="lynx" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel 7a" />
+          <option name="screenDensity" value="420" />
+          <option name="screenX" value="1080" />
+          <option name="screenY" value="2400" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="31" />
+          <option name="brand" value="google" />
+          <option name="codename" value="oriole" />
+          <option name="id" value="oriole" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel 6" />
+          <option name="screenDensity" value="420" />
+          <option name="screenX" value="1080" />
+          <option name="screenY" value="2400" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="33" />
+          <option name="brand" value="google" />
+          <option name="codename" value="panther" />
+          <option name="id" value="panther" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel 7" />
+          <option name="screenDensity" value="420" />
+          <option name="screenX" value="1080" />
+          <option name="screenY" value="2400" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="34" />
+          <option name="brand" value="samsung" />
+          <option name="codename" value="q5q" />
+          <option name="id" value="q5q" />
+          <option name="manufacturer" value="Samsung" />
+          <option name="name" value="Galaxy Z Fold5" />
+          <option name="screenDensity" value="420" />
+          <option name="screenX" value="1812" />
+          <option name="screenY" value="2176" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="30" />
+          <option name="brand" value="google" />
+          <option name="codename" value="r11" />
+          <option name="id" value="r11" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel Watch" />
+          <option name="screenDensity" value="320" />
+          <option name="screenX" value="384" />
+          <option name="screenY" value="384" />
+          <option name="type" value="WEAR_OS" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="30" />
+          <option name="brand" value="google" />
+          <option name="codename" value="redfin" />
+          <option name="id" value="redfin" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel 5" />
+          <option name="screenDensity" value="440" />
+          <option name="screenX" value="1080" />
+          <option name="screenY" value="2340" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="34" />
+          <option name="brand" value="google" />
+          <option name="codename" value="shiba" />
+          <option name="id" value="shiba" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel 8" />
+          <option name="screenDensity" value="420" />
+          <option name="screenX" value="1080" />
+          <option name="screenY" value="2400" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="33" />
+          <option name="brand" value="google" />
+          <option name="codename" value="tangorpro" />
+          <option name="id" value="tangorpro" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel Tablet" />
+          <option name="screenDensity" value="320" />
+          <option name="screenX" value="1600" />
+          <option name="screenY" value="2560" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="34" />
+          <option name="brand" value="google" />
+          <option name="codename" value="tokay" />
+          <option name="id" value="tokay" />
+          <option name="manufacturer" value="Google" />
+          <option name="name" value="Pixel 9" />
+          <option name="screenDensity" value="420" />
+          <option name="screenX" value="1080" />
+          <option name="screenY" value="2424" />
+        </PersistentDeviceSelectionData>
+        <PersistentDeviceSelectionData>
+          <option name="api" value="29" />
+          <option name="brand" value="samsung" />
+          <option name="codename" value="x1q" />
+          <option name="id" value="x1q" />
+          <option name="manufacturer" value="Samsung" />
+          <option name="name" value="Galaxy S20" />
+          <option name="screenDensity" value="480" />
+          <option name="screenX" value="1440" />
+          <option name="screenY" value="3200" />
+        </PersistentDeviceSelectionData>
+      </list>
+    </option>
+  </component>
+</project>
\ No newline at end of file
diff --git a/.idea/vcs.xml b/.idea/vcs.xml
deleted file mode 100644
index df496fd..0000000
--- a/.idea/vcs.xml
+++ /dev/null
@@ -1,40 +0,0 @@
-<?xml version="1.0" encoding="UTF-8"?>
-<project version="4">
-  <component name="IssueNavigationConfiguration">
-    <option name="links">
-      <list>
-        <IssueNavigationLink>
-          <option name="issueRegexp" value="\bb/(\d+)(#\w+)?\b" />
-          <option name="linkRegexp" value="https://buganizer.corp.google.com/issues/$1$2" />
-        </IssueNavigationLink>
-        <IssueNavigationLink>
-          <option name="issueRegexp" value="\b(?:BUG=|FIXED=)(\d+)\b" />
-          <option name="linkRegexp" value="https://buganizer.corp.google.com/issues/$1" />
-        </IssueNavigationLink>
-        <IssueNavigationLink>
-          <option name="issueRegexp" value="\b(?:cl/|cr/|OCL=|DIFFBASE=|ROLLBACK_OF=)(\d+)\b" />
-          <option name="linkRegexp" value="https://critique.corp.google.com/$1" />
-        </IssueNavigationLink>
-        <IssueNavigationLink>
-          <option name="issueRegexp" value="\bomg/(\d+)\b" />
-          <option name="linkRegexp" value="https://omg.corp.google.com/$1" />
-        </IssueNavigationLink>
-        <IssueNavigationLink>
-          <option name="issueRegexp" value="\b(?:go/|goto/)([^,.&lt;&gt;()&quot;\s]+(?:[.,][^,.&lt;&gt;()&quot;\s]+)*)" />
-          <option name="linkRegexp" value="https://goto.google.com/$1" />
-        </IssueNavigationLink>
-        <IssueNavigationLink>
-          <option name="issueRegexp" value="\bcs/([^\s]+[\w$])" />
-          <option name="linkRegexp" value="https://cs.corp.google.com/search/?q=$1" />
-        </IssueNavigationLink>
-        <IssueNavigationLink>
-          <option name="issueRegexp" value="(LINT\.IfChange)|(LINT\.ThenChange)" />
-          <option name="linkRegexp" value="https://goto.google.com/ifthisthenthatlint" />
-        </IssueNavigationLink>
-      </list>
-    </option>
-  </component>
-  <component name="VcsDirectoryMappings">
-    <mapping directory="$PROJECT_DIR$" vcs="Git" />
-  </component>
-</project>
\ No newline at end of file
diff --git a/Android.bp b/Android.bp
index 19d87ff..c0cb361 100644
--- a/Android.bp
+++ b/Android.bp
@@ -2,7 +2,7 @@ package {
     default_applicable_licenses: [
         "Android-Apache-2.0",
     ],
-    default_team: "trendy_team_camerax",
+    default_team: "trendy_team_android_camera_innovation_team",
 }
 
 subdirs = [
diff --git a/OWNERS b/OWNERS
index 6a44f69..b596c36 100644
--- a/OWNERS
+++ b/OWNERS
@@ -5,3 +5,4 @@ trevormcguire@google.com
 yasith@google.com
 davidjia@google.com
 kcrevecoeur@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
index 48f9df4..dfb9b5d 100644
--- a/README.md
+++ b/README.md
@@ -30,11 +30,595 @@ These tests can be run on a connected device via Android Studio, or can be teste
 Emulator using built-in Gradle Managed Device tasks. Currently, we include Pixel 2 (API 28) and
 Pixel 8 (API 34) emulators which can be used to run instrumentation tests with:
 
-`$ ./gradlew pixel2Api28DebugAndroidTest` and
-`$ ./gradlew pixel8Api34DebugAndroidTest`
+`$ ./gradlew pixel2Api28StableDebugAndroidTest` and
+`$ ./gradlew pixel8Api34StableDebugAndroidTest`
 
+# Features ✨🧰✨
 
-## Source Code Headers
+This section provides a detailed overview of the camera app's features, highlighting its 
+capabilities and functionalities. Each feature is described with its purpose, usage, and any
+relevant considerations to help you understand and utilize the app effectively.
+
+- [Standard Camera Features](#standard-camera-features)
+    * [Viewfinder](#viewfinder)
+    * [Aspect Ratio](#aspect-ratio)
+    * [Image Capture](#image-capture)
+    * [Tap to Focus](#tap-to-focus)
+    * [Flip Camera](#flip-camera)
+    * [Zoom](#zoom)
+    * [Scene Illumination / Flash](#scene-illumination---flash)
+- [Video Features](#video-features)
+    * [Video Capture](#video-capture)
+    * [Pause / Resume](#pause---resume)
+    * [Video Duration Limit](#video-duration-limit)
+    * [Video Quality](#video-quality)
+    * [Audio / Amplitude Visualization](#audio---amplitude-visualization)
+    * [Frame Rate](#frame-rate)
+    * [Video Stabilization](#video-stabilization)
+    * [Flip Camera While Recording](#flip-camera-while-recording)
+- [Advanced Camera Features](#advanced-camera-features)
+    * [Screen Flash](#screen-flash)
+    * [Dual Concurrent Camera](#dual-concurrent-camera)
+    * [HDR (High Dynamic Range)](#hdr--high-dynamic-range-)
+    * [LLB (Low Light Boost)](#llb--low-light-boost-)
+    * [Single / Multi-stream Mode](#single---multi-stream-mode)
+- [Special Application Features](#special-application-features)
+    * [Debug Mode](#debug-mode)
+    * [Intent Capture Modes](#intent-capture-modes)
+    * [Dark Mode](#dark-mode)
+
+## Standard Camera Features
+
+This section outlines the essential features of the camera app that enable you to capture photos and
+videos with ease. It covers fundamental aspects of camera operation, providing a solid starting
+point for utilizing the app's capabilities.
+
+### Viewfinder
+
+The viewfinder provides a real-time preview of the camera's sensor output, accurately displaying the
+scene with correct scaling and orientation. It functions as a "What You See Is What You Get" (
+WYSIWYG) display, showing only the pixels that will be captured in the final image or video, when
+hardware and processing capabilities allow (see limitations). This ensures that the displayed
+preview precisely reflects the captured content, allowing for accurate composition and framing.
+
+#### How to Enable / Use
+
+* This is a core function of the camera app. When the camera app is opened, the viewfinder is
+  active.
+
+#### Constraints / Limitations
+
+* The viewfinder's quality is limited by the screen's resolution and brightness. JCA is built on
+  CameraX, which will limit the viewfinder resolution to 1080p as a tradeoff of performance and
+  quality.
+* Due to the computational demands of high-quality video stabilization, the viewfinder may not be
+  strictly WYSIWYG when the video stabilization mode is set to “High Quality”, as the stabilization
+  algorithm applied to the recorded video stream might not be able to be replicated in real-time for
+  the viewfinder preview.
+
+---
+
+### Aspect Ratio
+
+Sets the proportions of the preview and the captured image or video.
+
+#### How to Enable / Use
+
+1. Open the camera app settings and select Set Aspect Ratio
+2. Or open the quick dropdown in the preview screen and look for the aspect ratio icon
+3. Select/toggle among the desired aspect ratios (e.g., 16:9, 4:3, 1:1).
+
+---
+
+### Image Capture
+
+Captures a still image from the camera. When the capture button is pressed, the camera captures a
+still image that accurately represents the scene currently displayed in the viewfinder. The captured
+image will incorporate any applicable image processing settings, such as Ultra HDR, based on the
+user's selected mode.
+
+#### How to Enable / Use
+
+1. Open the camera app.
+2. Tap the shutter button (white circle).
+3. The resulting image is saved to the device's media store, or, when the app is launched via the
+   `ACTION_IMAGE_CAPTURE` or `INTENT_ACTION_STILL_IMAGE_CAMERA` intents, to the URI(s) provided.
+
+#### Constraints / Limitations
+
+* The ability to capture an image may be limited by available device storage.
+* Image capture is disabled when the app is launched with the `ACTION_VIDEO_CAPTURE` intent.
+* Image capture is also disabled in concurrent camera mode and when HDR is enabled and the device
+  does not support Ultra HDR image capture.
+
+---
+
+### Tap to Focus
+
+Allows the user to manually select the focus point of the camera.
+
+#### How to Enable / Use
+
+1. Open the camera app.
+2. Tap on the desired area of the viewfinder.
+3. The camera will adjust the focus to the tapped area.
+
+#### Constraints / Limitations
+
+* May struggle in low-light conditions.
+* Can be affected by movement of the subject or camera.
+* Some devices may have limitations on how close or far the focus can be adjusted.
+
+---
+
+### Flip Camera
+
+This feature allows users to instantly switch between the device's primary front-facing and
+rear-facing cameras.
+
+#### How to Enable / Use
+
+There are several ways to flip camera lenses:
+
+1. Open the camera app.
+2. Tap the flip camera button.
+
+Alternatively,
+
+1. Open the camera app.
+2. Double tap on the viewfinder.
+
+Alternatively,
+
+1. Open the camera app.
+2. Open quick settings by tapping the downward facing arrow at the top of the screen.
+3. Tap the flip camera button which is displaying the currently visible camera.
+
+#### Constraints / Limitations
+
+* If the device does not have a front or a rear camera, the flip camera button will be disabled.
+
+---
+
+### Zoom
+
+This feature enables users to digitally or optically zoom in and out on the scene. On devices
+equipped with Camera2's `LOGICAL_MULTI_CAMERA` capability, the zoom functionality may automatically
+transition between available lenses, such as the main, telephoto, and wide-angle lenses, to provide
+seamless zoom transitions across the device's optical range.
+
+#### How to Enable / Use
+
+1. Open the camera app.
+2. Use pinch-to-zoom gestures. Text indicating the current magnification factor will appear above
+   the capture button. If the device supports the `LOGICAL_MULTI_CAMERA` capability, switching
+   between lenses will occur automatically as zoom increases or decreases.
+
+#### Constraints / Limitations
+
+* Digital zoom may reduce image quality.
+* In Dual Concurrent Camera mode, only the primary lens’ zoom can be changed. The secondary lens
+  will not react to pinch-to-zoom gestures.
+
+---
+
+### Scene Illumination / Flash
+
+This feature provides various options for illuminating the scene during capture of images and video,
+including:
+
+* **On:** Activates the device's built-in flash for a burst of light during image capture, and
+  constant illumination during video capture.
+* **Auto:** Automatically determines the need for illumination based on ambient light conditions for
+  image capture.
+* **Low-Light Boost:** Utilizes Camera2's `ON_LOW_LIGHT_BOOST_BRIGHTNESS_PRIORITY` auto-exposure (
+  AE) mode to enhance brightness in low-light conditions, if the device supports it.
+* **Off:** Disables all scene illumination.
+
+#### How to Enable / Use
+
+1. Open the camera app.
+2. Tap the flash icon to toggle between scene illumination modes (on, off, auto, LLB).
+3. Take a photo or video.
+
+Alternatively,
+
+1. Open the camera app.
+2. Open quick settings by tapping the downward facing arrow at the top of the screen.
+3. Tap the flash icon to toggle between scene illumination modes.
+4. Take a photo or video.
+
+#### Constraints / Limitations
+
+* Auto mode relies solely on ambient scene lighting for image capture and behaves as "On" for video
+  capture.
+* Dedicated front-facing flash units, if present, are not utilized; front-facing cameras exclusively
+  use screen flash for illumination.
+* Low-light boost may not be applied to image capture when the app is in multi-stream mode. To
+  guarantee low-light boost application in both image and video capture, utilize single-stream mode.
+
+## Video Features
+
+This section explores the camera app's comprehensive video recording capabilities, providing tools
+and settings to enhance your video capture experience. It covers various aspects of video
+functionality, from basic recording to advanced controls and customization.
+
+### Video Capture
+
+Records video that, in most cases (see limitations), represents the scene visible in the viewfinder.
+When HDR mode is enabled, the captured video can record 10-bit HDR content.
+
+#### How to Enable / Use
+
+1. Open the camera app.
+2. Press and hold the shutter button (white circle) until video recording starts, indicated by a
+   filled red circle in the shutter button and an incrementing duration timer above the shutter
+   button.
+3. Release the shutter button to finish recording. The resulting video is saved to the device's
+   media store, or, when the app is launched via the `ACTION_VIDEO_CAPTURE` intent, to the URI
+   provided.
+
+#### Constraints / Limitations
+
+* May be limited by device storage.
+* Due to the computational demands of high-quality video stabilization, the viewfinder may not be
+  strictly WYSIWYG when the video stabilization mode is set to “High Quality”. The stabilization
+  algorithm applied to the recorded video stream might not be able to be replicated in real-time for
+  the viewfinder preview.
+* Video capture is disabled when the app is launched with the `ACTION_IMAGE_CAPTURE` or
+  `INTENT_ACTION_STILL_IMAGE_CAMERA` intents.
+* Video capture is also disabled when HDR is enabled and the device does not support 10-bit HDR
+  video capture.
+
+---
+
+### Pause / Resume
+
+Temporarily stops and restarts video recording.
+
+#### How to Enable / Use
+
+1. While recording video, tap the pause button.
+2. Tap the resume button to continue recording.
+
+#### Constraints / Limitations
+
+* May not be available on all devices or in all recording modes.
+
+---
+
+### Video Duration Limit
+
+Sets a maximum length for video recordings.
+
+#### How to Enable / Use
+
+1. Open the camera app settings.
+2. Select Set Maximum Video Duration
+3. Choose the desired duration limit.
+
+---
+
+### Video Quality
+
+Sets the resolution and compression level of video recordings.
+
+#### How to Enable / Use
+
+1. Open the camera app settings.
+2. Select Set Video Quality.
+3. Choose the desired video quality (e.g., 720p, 1080p, 4K).
+
+#### Constraints / Limitations
+
+* Available quality settings depend on camera hardware.
+* Ultra High Definition may only be available under video/image-only mode
+
+---
+
+### Audio / Amplitude Visualization
+
+Controls the audio recording level and processing.
+
+#### How to Enable / Use
+
+1. Start video recording by holding down the capture button
+2. Audio visualization appears to the right of the button while recording
+
+---
+
+### Frame Rate
+
+Sets the number of frames recorded per second in a video.
+
+#### How to Enable / Use
+
+1. Open the camera app settings.
+2. Select Set Frame Rate
+3. Select the desired frame rate (e.g., 30fps, 60fps).
+
+#### Constraints / Limitations
+
+* Available frame rates depend on camera hardware.
+
+---
+
+### Video Stabilization
+
+This feature offers multiple stabilization modes to enhance video smoothness and clarity. The
+following stabilization modes are offered as options by JCA
+
+* **Auto:** Automatically enables stabilization based on the device's capabilities and current
+  recording settings.
+* **On:** Activates stabilization for both the preview and recorded video streams, providing a
+  smooth viewing experience during capture and playback.
+* **High Quality:** Applies a high-quality stabilization algorithm to the recorded video stream,
+  potentially resulting in superior stabilization. However, the preview stream may not be stabilized
+  in real-time due to computational limitations.
+* **Optical:** Utilizes the device's optical image stabilization (OIS) hardware to stabilize all
+  streams.
+* **Off:** Disables all stabilization features.
+
+#### How to Enable / Use
+
+1. Open the camera app settings from the settings icon in the upper left corner.
+2. Click the “Set Video Stabilization” setting if it is selectable. If it is not selectable, the
+   current lens does not support any video stabilization.
+3. Choose the desired stabilization mode and press “close”. The stabilization mode will be applied
+   when returning to the camera viewfinder. This selected stabilization mode will be persisted if
+   the app is closed, and will be applied the next time the app is opened.
+
+#### Constraints / Limitations
+
+* Some stabilization modes, such as “On” and “High Quality”, may crop the video and/or viewfinder
+  slightly.
+* Each lens may support different stabilization modes. Supported stabilization modes will be
+  selectable in settings, and unsupported stabilization modes will not be selectable. Swapping the
+  default lens in settings may change the available stabilization modes.
+* Some stabilization modes may not support every frame rate. To ensure best support for most
+  stabilization modes, select “Auto” frame rate.
+* If a stabilization mode is selected, and the camera switches settings via quick settings or by
+  flipping cameras, the stabilization may be disabled temporarily. This is indicated by a greyed out
+  stabilization icon at the top of the viewfinder screen. When settings and/or lens allow the
+  stabilization mode, it will be re-enabled.
+
+---
+
+### Flip Camera While Recording
+
+Switches between front and rear cameras during video recording.
+
+#### How to Enable / Use
+
+1. While recording video, tap the flip camera button.
+
+#### Constraints / Limitations
+
+* Uses Persistent Recording API which is experimental, and may not always function as expected
+* May be buggy with pause/resume. This is being addressed.
+* Does not work with concurrent cameras, stabilization, or single stream.
+
+## Advanced Camera Features
+
+This section delves into the advanced capabilities of the camera app, unlocking a new level of
+control and creativity for experienced users. It explores features that extend beyond basic camera
+operation, offering specialized functionalities and enhanced capture modes.
+
+### Screen Flash
+
+During image capture with a front-facing camera, this feature illuminates the subject by displaying
+a solid, bright overlay on the device's screen and maximizing screen brightness.
+
+#### How to Enable / Use
+
+1. Open the camera app.
+2. Ensure a front-facing camera is selected by tapping on the “flip camera” button.
+3. Tap the flash icon to toggle between scene illumination mode. Screen flash will be selected if
+   the “On” or “Auto” flash mode is selected.
+4. Take a photo.
+
+See the “Scene Illumination / Flash” feature for other methods of enabling screen flash.
+
+#### Constraints / Limitations
+
+* Screen flash will only be used for front-facing cameras.
+* Screen flash is currently limited to image capture only. There will be no additional illumination
+  for video capture.
+* In "Auto" mode, screen flash behaves equivalently to the "On" mode, regardless of ambient scene
+  lighting.
+
+---
+
+### Dual Concurrent Camera
+
+This feature enables simultaneous video capture from both the front and rear-facing cameras. It is
+built upon the CameraX concurrent camera APIs and is only available on devices that support the
+`PackageManager.FEATURE_CAMERA_CONCURRENT` feature. The interface displays two video streams: a "
+primary" stream and a "secondary" stream. The primary stream occupies the majority of the
+viewfinder, providing the main view, while the secondary stream is presented in a picture-in-picture
+format. The "Flip Camera" feature will swap the roles of the primary and secondary camera streams,
+effectively switching which camera provides the main view.
+
+#### How to Enable / Use
+
+1. Open the camera app.
+2. Open quick settings by tapping the downward facing arrow at the top of the screen.
+3. Tap the concurrent camera mode button to select the concurrent camera mode. It will display
+   “DUAL” underneath the button when Dual Concurrent Camera mode is enabled, and “SINGLE” for normal
+   single-camera operation.
+4. Both streams will be visible in the viewfinder. You may optionally record a video of what is
+   visible in the viewfinder. Both streams will be composited in the recorded video.
+
+#### Constraints / Limitations
+
+* Image capture is not supported in dual concurrent camera mode; only video capture is available.
+* Single-stream and multi-stream modes are unavailable; both camera streams are composited into a
+  single output stream.
+* HDR mode is not supported in dual concurrent camera mode.
+* Zoom and tap-to-focus functionality are limited to the primary camera stream. Tapping on the
+  secondary stream will interact with the corresponding area of the primary stream that is occluded
+  by the secondary stream's view.
+* Because two cameras are being used concurrently in Dual Concurrent Camera mode, additional power
+  and thermal load should be expected.
+
+---
+
+### HDR (High Dynamic Range)
+
+This multifaceted feature enhances the camera's ability to capture and display a wider range of
+colors and brightness levels. It comprises three key components:
+
+* **10-bit HDR Video Capture:** Record videos with enhanced color and dynamic range. This
+  functionality is built upon CameraX's `DynamicRange` APIs, including the associated APIs within
+  the `VideoCapture` class. 10-bit HDR allows for over a billion color possibilities, resulting in
+  smoother gradients and more realistic color reproduction. High Dynamic Range (HDR) captures a
+  wider range of light and dark tones, preserving detail in both highlights and shadows.
+* **Ultra HDR Image Capture:** Capture images with expanded dynamic range by embedding a gain map
+  within the standard JPEG file. This functionality is dependent on
+  `ImageCapture.OUTPUT_FORMAT_JPEG_ULTRA_HDR` being an available output format on the device. This
+  gain map stores supplemental luminance data, enabling compatible displays to render a wider range
+  of brightness levels. On non-HDR displays, the image is rendered as a standard SDR JPEG, ensuring
+  backward compatibility.
+* **HDR Viewfinder Preview:** When 10-bit HDR video mode is activated, the device's display
+  dynamically switches to HDR rendering for real-time preview, provided the current display supports
+  the `ActivityInfo.COLOR_MODE_HDR` color mode. This enables accurate monitoring of captured HDR
+  video content during recording, leveraging the display's extended dynamic range capabilities.
+
+#### How to Enable / Use
+
+1. Open the camera app.
+2. Open quick settings by tapping the downward facing arrow at the top of the screen.
+3. Tap the “HDR” button to select HDR mode, if it is enabled. Tapping again will toggle back to SDR
+   mode.
+4. Exit quick settings by tapping the upward facing arrow at the top of the screen.
+5. Toggle between 10-bit HDR video mode and Ultra HDR image capture mode using the toggle switch in
+   the lower right corner. If only one of these modes is available on the device, this switch will
+   be disabled, and tapping it will display a reason for why it is disabled.
+6. Take a photo or video as normal, depending on which mode is selected.
+
+#### Constraints / Limitations
+
+* Not every device supports HDR mode. Some devices may support only 10-bit HDR video or Ultra HDR,
+  but not both.
+* HDR mode supports either image capture or video capture, but not both simultaneously. Users must
+  select their desired capture mode using the mode selector switch.
+* HDR mode is not supported when using the dual concurrent camera feature.
+* Different lenses on the device may have varying HDR capabilities. Some lenses may support HDR
+  capture, while others may only support SDR capture.
+* In HDR mode, single-stream mode is exclusively used for video capture. Image capture is disabled
+  when single-stream mode is enabled.
+* The viewfinder utilizes HDR rendering during 10-bit HDR video capture. However, HDR rendering may
+  not be used in Ultra HDR image capture mode.
+* During HDR preview, standard dynamic range (SDR) assets, such as the app's user interface, may
+  appear dimmed.
+
+---
+
+### LLB (Low Light Boost)
+
+Enhances the brightness of the camera's preview and recorded videos. If the device supports it, this
+feature utilizes Camera2's `ON_LOW_LIGHT_BOOST_BRIGHTNESS_PRIORITY` auto-exposure (AE) mode to
+improve brightness in low-light conditions.
+
+#### How to Enable / Use
+
+1. Tap the flash icon to cycle through flash modes.
+2. The crescent moon icon indicates that LLB is enabled.
+3. LLB has two states:
+    1. Outlined Crescent Moon: LLB is inactive (the scene isn't dark enough).
+    2. Filled Crescent Moon: LLB is active (the scene is dark enough, and brightness is enhanced).
+4. To disable LLB, switch to a different flash mode.
+
+#### Constraints / Limitations
+
+* A reduced frame rate can introduce some motion blur.
+* It only works on Preview and Video Capture in multi-stream mode.
+* Images captured in single-stream mode will still be brightened.
+* Not all devices support Low Light Boost. Only lenses with `ON_LOW_LIGHT_BOOST_BRIGHTNESS_PRIORITY`
+  as an available `CONTROL_AE_AVAILABLE_MODES` support LLB.
+* LLB will override the frame rate setting.
+
+---
+
+### Single / Multi-stream Mode
+
+This setting controls whether the camera uses a single stream or multiple streams for preview,
+video, and image capture.
+
+* **Multi-stream mode:** Uses separate streams for preview, video recording, and still image
+  capture. The output of each stream may appear slightly different. In general, this mode can be
+  more efficient and have higher performance than single-stream mode.
+* **Single-stream mode:** Uses a single stream for all functions. In this mode, the preview
+  accurately reflects what will be captured in videos or images. This is a common mode that is used
+  in apps that want to apply effects to the camera stream and have them appear in captured images
+  and videos.
+
+#### How to Enable / Use
+
+1. Open quick settings by tapping the downward facing arrow at the top of the screen.
+2. Tap the single or multi stream button. This will toggle between single stream or multi stream
+   modes.
+
+#### Constraints / Limitations
+
+* Ultra HDR cannot be enabled in single stream mode.
+* Multi or single stream selectors are not available when using Dual Concurrent Cameras.
+
+## Special Application Features
+
+This section explores features that provide extended functionality and customization within the
+camera app, going beyond core image and video capture capabilities. These features cater to specific
+user preferences and developer needs.
+
+### Debug Mode
+
+Provides advanced camera information and controls for developers.
+
+#### How to Enable / Use
+
+1. Launch the app with extra KEY_DEBUG_MODE set to true
+2. Access the debug mode UI through the purple “Debug” button in the preview screen
+
+#### Constraints / Limitations
+
+* Intended for developers and may cause instability.
+
+---
+
+### Intent Capture Modes
+
+Launch the app into modes with specialized user flow. Also allows configuring content values for
+media to be captured
+
+#### How to Enable / Use
+
+1. In the launching intent for JCA, set intent action to ACTION_IMAGE_CAPTURE, ACTION_VIDEO_CAPTURE,
+   or INTENT_ACTION_STILL_IMAGE_CAMERA for single image capture, single video capture, or multiple
+   image capture mode.
+2. Configure content values and insert the url into the intent at MediaStore.EXTRA_OUTPUT
+3. Launch JCA
+
+---
+
+### Dark Mode
+
+This feature allows users to customize the app's appearance by selecting between three modes:
+
+* **On:** Enables dark mode, displaying UI elements with a darker color scheme.
+* **Off:** Enables light mode, displaying UI elements with a lighter color scheme.
+* **System:** Adopts the system-wide dark mode setting, dynamically adjusting the app's appearance
+  based on the user's device preferences.
+
+The appearance of UI elements will differ depending on the selected mode. This setting only affects
+the user interface and does not impact the captured images or videos.
+
+#### How to Enable / Use
+
+1. Open the camera app settings from the settings icon in the upper left corner.
+2. Tap the “Set Dark Mode” setting under “App Settings”.
+3. Select the desired mode.
+
+# Source Code Headers
 
 Every file containing source code must include copyright and license
 information. This includes any JS/CSS files that you might be serving out to
diff --git a/TEST_MAPPING b/TEST_MAPPING
index bdf0596..f140f95 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,5 +1,5 @@
 {
-  "postsubmit": [
+  "presubmit": [
     {
       "name": "jetpack-camera-app-tests"
     },
diff --git a/app/build.gradle.kts b/app/build.gradle.kts
index 8686bda..db70317 100644
--- a/app/build.gradle.kts
+++ b/app/build.gradle.kts
@@ -23,7 +23,6 @@ plugins {
 
 android {
     compileSdk = libs.versions.compileSdk.get().toInt()
-    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     namespace = "com.google.jetpackcamera"
 
@@ -34,8 +33,10 @@ android {
         versionCode = 1
         versionName = "0.1.0"
         testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
+        testInstrumentationRunnerArguments["clearPackageData"] = "true"
     }
 
+
     buildTypes {
         getByName("debug") {
             signingConfig = signingConfigs.getByName("debug")
@@ -57,11 +58,6 @@ android {
             dimension = "flavor"
             isDefault = true
         }
-
-        create("preview") {
-            dimension = "flavor"
-            targetSdkPreview = libs.versions.targetSdkPreview.get()
-        }
     }
 
     compileOptions {
@@ -83,8 +79,11 @@ android {
             excludes += "/META-INF/{AL2.0,LGPL2.1}"
         }
     }
+
     @Suppress("UnstableApiUsage")
     testOptions {
+        execution = "ANDROIDX_TEST_ORCHESTRATOR"
+
         managedDevices {
             localDevices {
                 create("pixel2Api28") {
@@ -108,6 +107,7 @@ android {
 dependencies {
     implementation(libs.androidx.tracing)
     implementation(project(":core:common"))
+    implementation(project(":feature:postcapture"))
     // Compose
     val composeBom = platform(libs.compose.bom)
     implementation(composeBom)
@@ -138,6 +138,8 @@ dependencies {
     androidTestImplementation(libs.androidx.rules)
     androidTestImplementation(libs.androidx.uiautomator)
     androidTestImplementation(libs.truth)
+    androidTestUtil(libs.androidx.orchestrator)
+
 
     implementation(libs.androidx.core.ktx)
     implementation(libs.androidx.lifecycle.runtime.compose)
@@ -166,7 +168,6 @@ dependencies {
 
     // benchmark
     implementation(libs.androidx.profileinstaller)
-
 }
 
 // Allow references to generated code
diff --git a/app/src/androidTest/Android.bp b/app/src/androidTest/Android.bp
index cbc1bb2..3cf8445 100644
--- a/app/src/androidTest/Android.bp
+++ b/app/src/androidTest/Android.bp
@@ -6,11 +6,14 @@ package {
 
 android_test {
     name: "jetpack-camera-app-tests",
-    team: "trendy_team_camerax",
+    team: "trendy_team_android_camera_innovation_team",
     srcs: [
         "java/**/*.kt",
     ],
-
+    // Test orchestrator not available
+    exclude_srcs: [
+        "java/com/google/jetpackcamera/PermissionsTest.kt",
+    ],
     static_libs: [
         "androidx.test.runner",
         "androidx.test.uiautomator_uiautomator",
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/BackgroundDeviceTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/BackgroundDeviceTest.kt
index 747650f..f333805 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/BackgroundDeviceTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/BackgroundDeviceTest.kt
@@ -28,14 +28,14 @@ import androidx.test.uiautomator.UiDevice
 import androidx.test.uiautomator.Until
 import com.google.common.truth.Truth.assertThat
 import com.google.common.truth.TruthJUnit.assume
-import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_CAPTURE_MODE_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_DROP_DOWN
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLIP_CAMERA_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_RATIO_1_1_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_RATIO_BUTTON
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_STREAM_CONFIG_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
-import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
 import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.TEST_REQUIRED_PERMISSIONS
 import com.google.jetpackcamera.utils.runScenarioTest
 import org.junit.Before
 import org.junit.Rule
@@ -46,7 +46,7 @@ import org.junit.runner.RunWith
 class BackgroundDeviceTest {
     @get:Rule
     val permissionsRule: GrantPermissionRule =
-        GrantPermissionRule.grant(*(APP_REQUIRED_PERMISSIONS).toTypedArray())
+        GrantPermissionRule.grant(*(TEST_REQUIRED_PERMISSIONS).toTypedArray())
 
     @get:Rule
     val composeTestRule = createEmptyComposeRule()
@@ -157,7 +157,7 @@ class BackgroundDeviceTest {
             .performClick()
 
         // Click the flip camera button
-        composeTestRule.onNodeWithTag(QUICK_SETTINGS_CAPTURE_MODE_BUTTON)
+        composeTestRule.onNodeWithTag(QUICK_SETTINGS_STREAM_CONFIG_BUTTON)
             .assertExists()
             .performClick()
 
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/ConcurrentCameraTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/ConcurrentCameraTest.kt
new file mode 100644
index 0000000..b9b2695
--- /dev/null
+++ b/app/src/androidTest/java/com/google/jetpackcamera/ConcurrentCameraTest.kt
@@ -0,0 +1,368 @@
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
+import android.app.Activity
+import android.net.Uri
+import android.provider.MediaStore
+import androidx.compose.ui.semantics.SemanticsNode
+import androidx.compose.ui.semantics.SemanticsProperties
+import androidx.compose.ui.test.SemanticsNodeInteraction
+import androidx.compose.ui.test.SemanticsNodeInteractionsProvider
+import androidx.compose.ui.test.assert
+import androidx.compose.ui.test.assertIsDisplayed
+import androidx.compose.ui.test.isDisplayed
+import androidx.compose.ui.test.isEnabled
+import androidx.compose.ui.test.isNotEnabled
+import androidx.compose.ui.test.junit4.createEmptyComposeRule
+import androidx.compose.ui.test.onNodeWithTag
+import androidx.compose.ui.test.performClick
+import androidx.test.core.app.ActivityScenario
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.rule.GrantPermissionRule
+import com.google.common.truth.Truth.assertThat
+import com.google.jetpackcamera.MainActivity
+import com.google.jetpackcamera.feature.preview.R
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_DROP_DOWN
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLIP_CAMERA_BUTTON
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_HDR_BUTTON
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_RATIO_1_1_BUTTON
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_RATIO_BUTTON
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_STREAM_CONFIG_BUTTON
+import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
+import com.google.jetpackcamera.feature.preview.ui.CAPTURE_MODE_TOGGLE_BUTTON
+import com.google.jetpackcamera.feature.preview.ui.FLIP_CAMERA_BUTTON
+import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA_TAG
+import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_SUCCESS_TAG
+import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
+import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.TEST_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.utils.VIDEO_CAPTURE_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.assume
+import com.google.jetpackcamera.utils.getResString
+import com.google.jetpackcamera.utils.longClickForVideoRecording
+import com.google.jetpackcamera.utils.runMediaStoreAutoDeleteScenarioTest
+import com.google.jetpackcamera.utils.runScenarioTest
+import com.google.jetpackcamera.utils.stateDescriptionMatches
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+@RunWith(AndroidJUnit4::class)
+class ConcurrentCameraTest {
+    @get:Rule
+    val permissionsRule: GrantPermissionRule =
+        GrantPermissionRule.grant(*(TEST_REQUIRED_PERMISSIONS).toTypedArray())
+
+    @get:Rule
+    val composeTestRule = createEmptyComposeRule()
+
+    @Test
+    fun concurrentCameraMode_canBeEnabled() = runConcurrentCameraScenarioTest<MainActivity> {
+        val concurrentCameraModes = mutableListOf<ConcurrentCameraMode>()
+        with(composeTestRule) {
+            onNodeWithTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+                .assertExists().apply {
+                    // Check the original mode
+                    fetchSemanticsNode().let { node ->
+                        concurrentCameraModes.add(node.fetchConcurrentCameraMode())
+                    }
+                }
+                // Enable concurrent camera
+                .performClick().apply {
+                    // Check the mode has changed
+                    fetchSemanticsNode().let { node ->
+                        concurrentCameraModes.add(node.fetchConcurrentCameraMode())
+                    }
+                }
+
+            // Exit quick settings
+            onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
+                .assertExists()
+                .performClick()
+
+            // Assert that the flip camera button is visible
+            onNodeWithTag(FLIP_CAMERA_BUTTON)
+                .assertIsDisplayed()
+        }
+
+        assertThat(concurrentCameraModes).containsExactly(
+            ConcurrentCameraMode.OFF,
+            ConcurrentCameraMode.DUAL
+        ).inOrder()
+    }
+
+    @Test
+    fun concurrentCameraMode_whenEnabled_canBeDisabled() =
+        runConcurrentCameraScenarioTest<MainActivity> {
+            val concurrentCameraModes = mutableListOf<ConcurrentCameraMode>()
+            with(composeTestRule) {
+                onNodeWithTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+                    .assertExists().apply {
+                        // Check the original mode
+                        fetchSemanticsNode().let { node ->
+                            concurrentCameraModes.add(node.fetchConcurrentCameraMode())
+                        }
+                    }
+                    // Enable concurrent camera
+                    .performClick().apply {
+                        // Check the mode has changed
+                        fetchSemanticsNode().let { node ->
+                            concurrentCameraModes.add(node.fetchConcurrentCameraMode())
+                        }
+                    }
+
+                // Exit quick settings
+                onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
+                    .assertExists()
+                    .performClick()
+
+                // Assert that the flip camera button is visible
+                onNodeWithTag(FLIP_CAMERA_BUTTON)
+                    .assertIsDisplayed()
+
+                // Enter quick settings
+                onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
+                    .assertExists()
+                    .performClick()
+
+                onNodeWithTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+                    .assertExists()
+                    // Disable concurrent camera
+                    .performClick().apply {
+                        // Check the mode is back to OFF
+                        fetchSemanticsNode().let { node ->
+                            concurrentCameraModes.add(node.fetchConcurrentCameraMode())
+                        }
+                    }
+
+                // Exit quick settings
+                onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
+                    .assertExists()
+                    .performClick()
+
+                // Assert that the flip camera button is visible
+                onNodeWithTag(FLIP_CAMERA_BUTTON)
+                    .assertIsDisplayed()
+            }
+
+            assertThat(concurrentCameraModes).containsExactly(
+                ConcurrentCameraMode.OFF,
+                ConcurrentCameraMode.DUAL,
+                ConcurrentCameraMode.OFF
+            ).inOrder()
+        }
+
+    @Test
+    fun concurrentCameraMode_whenEnabled_canFlipCamera() =
+        runConcurrentCameraScenarioTest<MainActivity> {
+            with(composeTestRule) {
+                // Check device has multiple cameras
+                onNodeWithTag(QUICK_SETTINGS_FLIP_CAMERA_BUTTON)
+                    .assertExists()
+                    .assume(isEnabled()) {
+                        "Device does not have multiple cameras."
+                    }
+
+                onNodeWithTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+                    .assertExists()
+                    .assertConcurrentCameraMode(ConcurrentCameraMode.OFF)
+                    // Enable concurrent camera
+                    .performClick()
+                    .assertConcurrentCameraMode(ConcurrentCameraMode.DUAL)
+
+                onNodeWithTag(QUICK_SETTINGS_FLIP_CAMERA_BUTTON)
+                    .assertExists()
+                    .performClick()
+
+                // Exit quick settings
+                onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
+                    .assertExists()
+                    .performClick()
+
+                // Assert that the flip camera button is visible
+                onNodeWithTag(FLIP_CAMERA_BUTTON)
+                    .assertIsDisplayed()
+            }
+        }
+
+    @Test
+    fun concurrentCameraMode_whenEnabled_canSwitchAspectRatio() =
+        runConcurrentCameraScenarioTest<MainActivity> {
+            with(composeTestRule) {
+                onNodeWithTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+                    .assertExists()
+                    .assertConcurrentCameraMode(ConcurrentCameraMode.OFF)
+                    // Enable concurrent camera
+                    .performClick()
+                    .assertConcurrentCameraMode(ConcurrentCameraMode.DUAL)
+
+                // Click the ratio button
+                composeTestRule.onNodeWithTag(QUICK_SETTINGS_RATIO_BUTTON)
+                    .assertExists()
+                    .performClick()
+
+                // Click the 1:1 ratio button
+                composeTestRule.onNodeWithTag(QUICK_SETTINGS_RATIO_1_1_BUTTON)
+                    .assertExists()
+                    .performClick()
+
+                // Exit quick settings
+                onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
+                    .assertExists()
+                    .performClick()
+
+                // Assert that the flip camera button is visible
+                onNodeWithTag(FLIP_CAMERA_BUTTON)
+                    .assertIsDisplayed()
+            }
+        }
+
+    @Test
+    fun concurrentCameraMode_whenEnabled_disablesOtherSettings() =
+        runConcurrentCameraScenarioTest<MainActivity> {
+            with(composeTestRule) {
+                onNodeWithTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+                    .assertExists()
+                    .assertConcurrentCameraMode(ConcurrentCameraMode.OFF)
+                    // Enable concurrent camera
+                    .performClick()
+                    .assertConcurrentCameraMode(ConcurrentCameraMode.DUAL)
+
+                // Assert the capture mode button is disabled
+                onNodeWithTag(QUICK_SETTINGS_STREAM_CONFIG_BUTTON)
+                    .assertExists()
+                    .assert(isNotEnabled())
+
+                // Assert the HDR button is disabled
+                onNodeWithTag(QUICK_SETTINGS_HDR_BUTTON)
+                    .assertExists()
+                    .assert(isNotEnabled())
+
+                // Exit quick settings
+                onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
+                    .assertExists()
+                    .performClick()
+
+                onNodeWithTag(CAPTURE_MODE_TOGGLE_BUTTON)
+                    .assertExists()
+                    .assert(
+                        stateDescriptionMatches(
+                            getResString(R.string.capture_mode_video_recording_content_description)
+                        )
+                    ).performClick()
+
+                waitUntil {
+                    onNodeWithTag(IMAGE_CAPTURE_UNSUPPORTED_CONCURRENT_CAMERA_TAG).isDisplayed()
+                }
+            }
+        }
+
+    @Test
+    fun concurrentCameraMode_canRecordVideo() = runConcurrentCameraScenarioTest<MainActivity>(
+        mediaUriForSavedFiles = MediaStore.Video.Media.EXTERNAL_CONTENT_URI
+    ) {
+        with(composeTestRule) {
+            onNodeWithTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+                .assertExists()
+                .assertConcurrentCameraMode(ConcurrentCameraMode.OFF)
+                // Enable concurrent camera
+                .performClick()
+                .assertConcurrentCameraMode(ConcurrentCameraMode.DUAL)
+
+            // Exit quick settings
+            onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
+                .assertExists()
+                .performClick()
+
+            longClickForVideoRecording()
+
+            waitUntil(timeoutMillis = VIDEO_CAPTURE_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(VIDEO_CAPTURE_SUCCESS_TAG).isDisplayed()
+            }
+        }
+    }
+
+    // Ensures the app has launched and checks that the device supports concurrent camera before
+    // running the test.
+    // This test will start with quick settings visible
+    private inline fun <reified T : Activity> runConcurrentCameraScenarioTest(
+        mediaUriForSavedFiles: Uri? = null,
+        expectedMediaFiles: Int = 1,
+        crossinline block: ActivityScenario<T>.() -> Unit
+    ) {
+        val wrappedBlock: ActivityScenario<T>.() -> Unit = {
+            // Wait for the capture button to be displayed
+            composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+            }
+
+            // ///////////////////////////////////////////////////
+            // Check that the device supports concurrent camera //
+            // ///////////////////////////////////////////////////
+            // Navigate to quick settings
+            composeTestRule.onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
+                .assertExists()
+                .performClick()
+
+            // Check that the concurrent camera button is enabled
+            composeTestRule.onNodeWithTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON)
+                .assertExists()
+                .assume(isEnabled()) {
+                    "Device does not support concurrent camera."
+                }
+
+            // ///////////////////////////////////////////////////
+            //               Run the actual test                //
+            // ///////////////////////////////////////////////////
+            block()
+        }
+
+        if (mediaUriForSavedFiles != null) {
+            runMediaStoreAutoDeleteScenarioTest(
+                mediaUri = mediaUriForSavedFiles,
+                expectedNumFiles = expectedMediaFiles,
+                block = wrappedBlock
+            )
+        } else {
+            runScenarioTest(wrappedBlock)
+        }
+    }
+
+    context(SemanticsNodeInteractionsProvider)
+    private fun SemanticsNode.fetchConcurrentCameraMode(): ConcurrentCameraMode {
+        config[SemanticsProperties.ContentDescription].any { description ->
+            when (description) {
+                getResString(R.string.quick_settings_concurrent_camera_off_description) ->
+                    return ConcurrentCameraMode.OFF
+
+                getResString(R.string.quick_settings_concurrent_camera_dual_description) ->
+                    return ConcurrentCameraMode.DUAL
+
+                else -> false
+            }
+        }
+        throw AssertionError("Unable to determine concurrent camera mode from quick settings")
+    }
+
+    context(SemanticsNodeInteractionsProvider)
+    private fun SemanticsNodeInteraction.assertConcurrentCameraMode(
+        mode: ConcurrentCameraMode
+    ): SemanticsNodeInteraction {
+        assertThat(fetchSemanticsNode().fetchConcurrentCameraMode())
+            .isEqualTo(mode)
+        return this
+    }
+}
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/FlashDeviceTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/FlashDeviceTest.kt
index 0e57a00..b840cae 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/FlashDeviceTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/FlashDeviceTest.kt
@@ -16,6 +16,7 @@
 package com.google.jetpackcamera
 
 import android.os.Build
+import android.provider.MediaStore
 import androidx.compose.ui.test.isDisplayed
 import androidx.compose.ui.test.isEnabled
 import androidx.compose.ui.test.junit4.createEmptyComposeRule
@@ -27,21 +28,24 @@ import androidx.test.rule.GrantPermissionRule
 import androidx.test.uiautomator.UiDevice
 import com.google.common.truth.Truth.assertThat
 import com.google.common.truth.TruthJUnit.assume
-import com.google.jetpackcamera.feature.preview.R
-import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_DROP_DOWN
-import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLASH_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.FLIP_CAMERA_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_SUCCESS_TAG
 import com.google.jetpackcamera.feature.preview.ui.SCREEN_FLASH_OVERLAY
+import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_SUCCESS_TAG
+import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
 import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
 import com.google.jetpackcamera.utils.IMAGE_CAPTURE_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.SCREEN_FLASH_OVERLAY_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.TEST_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.utils.VIDEO_CAPTURE_TIMEOUT_MILLIS
 import com.google.jetpackcamera.utils.assume
 import com.google.jetpackcamera.utils.getCurrentLensFacing
-import com.google.jetpackcamera.utils.onNodeWithContentDescription
+import com.google.jetpackcamera.utils.longClickForVideoRecording
+import com.google.jetpackcamera.utils.runMediaStoreAutoDeleteScenarioTest
 import com.google.jetpackcamera.utils.runScenarioTest
+import com.google.jetpackcamera.utils.setFlashMode
 import org.junit.Before
 import org.junit.Rule
 import org.junit.Test
@@ -52,7 +56,7 @@ internal class FlashDeviceTest {
 
     @get:Rule
     val permissionsRule: GrantPermissionRule =
-        GrantPermissionRule.grant(*(APP_REQUIRED_PERMISSIONS).toTypedArray())
+        GrantPermissionRule.grant(*(TEST_REQUIRED_PERMISSIONS).toTypedArray())
 
     @get:Rule
     val composeTestRule = createEmptyComposeRule()
@@ -71,21 +75,7 @@ internal class FlashDeviceTest {
             composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
         }
 
-        // Navigate to quick settings
-        composeTestRule.onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
-            .assertExists()
-            .performClick()
-
-        // Click the flash button to switch to ON
-        composeTestRule.onNodeWithTag(QUICK_SETTINGS_FLASH_BUTTON)
-            .assertExists()
-            .performClick()
-
-        composeTestRule.onNodeWithTag(QUICK_SETTINGS_FLASH_BUTTON)
-            .assertExists()
-        composeTestRule.onNodeWithContentDescription(
-            R.string.quick_settings_flash_on_description
-        )
+        composeTestRule.setFlashMode(FlashMode.ON)
     }
 
     @Test
@@ -95,20 +85,7 @@ internal class FlashDeviceTest {
             composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
         }
 
-        // Navigate to quick settings
-        composeTestRule.onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
-            .assertExists()
-            .performClick()
-
-        // Click the flash button twice to switch to AUTO
-        composeTestRule.onNodeWithTag(QUICK_SETTINGS_FLASH_BUTTON)
-            .assertExists()
-            .performClick()
-            .performClick()
-
-        composeTestRule.onNodeWithContentDescription(
-            R.string.quick_settings_flash_auto_description
-        )
+        composeTestRule.setFlashMode(FlashMode.AUTO)
     }
 
     @Test
@@ -118,25 +95,17 @@ internal class FlashDeviceTest {
             composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
         }
 
-        composeTestRule.onNodeWithContentDescription(
-            R.string.quick_settings_flash_off_description
-        )
-
-        // Navigate to quick settings
-        composeTestRule.onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
-            .assertExists()
-            .performClick()
+        composeTestRule.setFlashMode(FlashMode.OFF)
+    }
 
-        // Click the flash button three times to switch to OFF
-        composeTestRule.onNodeWithTag(QUICK_SETTINGS_FLASH_BUTTON)
-            .assertExists()
-            .performClick()
-            .performClick()
-            .performClick()
+    @Test
+    fun set_flash_low_light_boost() = runScenarioTest<MainActivity> {
+        // Wait for the capture button to be displayed
+        composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+            composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+        }
 
-        composeTestRule.onNodeWithContentDescription(
-            R.string.quick_settings_flash_off_description
-        )
+        composeTestRule.setFlashMode(FlashMode.LOW_LIGHT_BOOST)
     }
 
     private fun assumeHalStableOnImageCapture() {
@@ -146,7 +115,10 @@ internal class FlashDeviceTest {
     }
 
     @Test
-    fun set_flash_and_capture_successfully() = runScenarioTest<MainActivity> {
+    fun set_flash_and_capture_successfully() = runMediaStoreAutoDeleteScenarioTest<MainActivity>(
+        mediaUri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
+        filePrefix = "JCA"
+    ) {
         // Skip test on unstable devices
         assumeHalStableOnImageCapture()
 
@@ -163,20 +135,7 @@ internal class FlashDeviceTest {
             }.performClick()
         }
 
-        // Navigate to quick settings
-        composeTestRule.onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
-            .assertExists()
-            .performClick()
-
-        // Click the flash button to switch to ON
-        composeTestRule.onNodeWithTag(QUICK_SETTINGS_FLASH_BUTTON)
-            .assertExists()
-            .performClick()
-
-        // Exit quick settings
-        composeTestRule.onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
-            .assertExists()
-            .performClick()
+        composeTestRule.setFlashMode(FlashMode.ON)
 
         composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
             .assertExists()
@@ -189,7 +148,10 @@ internal class FlashDeviceTest {
 
     @Test
     fun set_screen_flash_and_capture_with_screen_change_overlay_shown() =
-        runScenarioTest<MainActivity> {
+        runMediaStoreAutoDeleteScenarioTest<MainActivity>(
+            mediaUri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
+            filePrefix = "JCA"
+        ) {
             // Wait for the capture button to be displayed
             composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
                 composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
@@ -203,28 +165,52 @@ internal class FlashDeviceTest {
                 }.performClick()
             }
 
-            // Navigate to quick settings
-            composeTestRule.onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
-                .assertExists()
-                .performClick()
-
-            // Click the flash button to switch to ON
-            composeTestRule.onNodeWithTag(QUICK_SETTINGS_FLASH_BUTTON)
-                .assertExists()
-                .performClick()
-
-            // Exit quick settings
-            composeTestRule.onNodeWithTag(QUICK_SETTINGS_DROP_DOWN)
-                .assertExists()
-                .performClick()
+            composeTestRule.setFlashMode(FlashMode.ON)
 
             // Perform a capture to enable screen flash
             composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
                 .assertExists()
                 .performClick()
 
-            composeTestRule.waitUntil(timeoutMillis = IMAGE_CAPTURE_TIMEOUT_MILLIS) {
+            composeTestRule.waitUntil(timeoutMillis = SCREEN_FLASH_OVERLAY_TIMEOUT_MILLIS) {
                 composeTestRule.onNodeWithTag(SCREEN_FLASH_OVERLAY).isDisplayed()
             }
+
+            composeTestRule.waitUntil(timeoutMillis = IMAGE_CAPTURE_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(IMAGE_CAPTURE_SUCCESS_TAG).isDisplayed()
+            }
+        }
+
+    @Test
+    fun set_flash_and_capture_rear_video_successfully() =
+        set_flash_and_capture_video_successfully(LensFacing.BACK)
+
+    @Test
+    fun set_flash_and_capture_front_video_successfully() =
+        set_flash_and_capture_video_successfully(LensFacing.FRONT)
+
+    private fun set_flash_and_capture_video_successfully(targetLensFacing: LensFacing) =
+        runMediaStoreAutoDeleteScenarioTest<MainActivity>(
+            mediaUri = MediaStore.Video.Media.EXTERNAL_CONTENT_URI
+        ) {
+            // Wait for the capture button to be displayed
+            composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+            }
+
+            // Ensure camera has the target lens facing camera and flip to it
+            val lensFacing = composeTestRule.getCurrentLensFacing()
+            if (lensFacing != targetLensFacing) {
+                composeTestRule.onNodeWithTag(FLIP_CAMERA_BUTTON).assume(isEnabled()) {
+                    "Device does not have a $targetLensFacing camera to flip to."
+                }.performClick()
+            }
+
+            composeTestRule.setFlashMode(FlashMode.ON)
+
+            composeTestRule.longClickForVideoRecording()
+            composeTestRule.waitUntil(timeoutMillis = VIDEO_CAPTURE_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(VIDEO_CAPTURE_SUCCESS_TAG).isDisplayed()
+            }
         }
 }
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/ImageCaptureDeviceTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/ImageCaptureDeviceTest.kt
index 7edae9a..d6a4498 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/ImageCaptureDeviceTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/ImageCaptureDeviceTest.kt
@@ -19,7 +19,9 @@ import android.app.Activity
 import android.net.Uri
 import android.os.Environment
 import android.provider.MediaStore
+import androidx.compose.ui.test.ComposeTimeoutException
 import androidx.compose.ui.test.isDisplayed
+import androidx.compose.ui.test.isNotDisplayed
 import androidx.compose.ui.test.junit4.createEmptyComposeRule
 import androidx.compose.ui.test.longClick
 import androidx.compose.ui.test.onNodeWithTag
@@ -34,17 +36,21 @@ import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_FAILURE_TAG
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_SUCCESS_TAG
 import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
-import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
 import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
 import com.google.jetpackcamera.utils.IMAGE_CAPTURE_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.IMAGE_PREFIX
+import com.google.jetpackcamera.utils.MESSAGE_DISAPPEAR_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.TEST_REQUIRED_PERMISSIONS
 import com.google.jetpackcamera.utils.VIDEO_CAPTURE_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.VIDEO_PREFIX
 import com.google.jetpackcamera.utils.deleteFilesInDirAfterTimestamp
-import com.google.jetpackcamera.utils.doesImageFileExist
-import com.google.jetpackcamera.utils.getIntent
+import com.google.jetpackcamera.utils.doesFileExist
+import com.google.jetpackcamera.utils.doesMediaExist
+import com.google.jetpackcamera.utils.getMultipleImageCaptureIntent
+import com.google.jetpackcamera.utils.getSingleImageCaptureIntent
 import com.google.jetpackcamera.utils.getTestUri
-import com.google.jetpackcamera.utils.runScenarioTest
+import com.google.jetpackcamera.utils.runMediaStoreAutoDeleteScenarioTest
 import com.google.jetpackcamera.utils.runScenarioTestForResult
-import java.io.File
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
@@ -55,7 +61,7 @@ internal class ImageCaptureDeviceTest {
 
     @get:Rule
     val permissionsRule: GrantPermissionRule =
-        GrantPermissionRule.grant(*(APP_REQUIRED_PERMISSIONS).toTypedArray())
+        GrantPermissionRule.grant(*(TEST_REQUIRED_PERMISSIONS).toTypedArray())
 
     @get:Rule
     val composeTestRule = createEmptyComposeRule()
@@ -64,8 +70,10 @@ internal class ImageCaptureDeviceTest {
     private val uiDevice = UiDevice.getInstance(instrumentation)
 
     @Test
-    fun image_capture() = runScenarioTest<MainActivity> {
-        val timeStamp = System.currentTimeMillis()
+    fun image_capture() = runMediaStoreAutoDeleteScenarioTest<MainActivity>(
+        mediaUri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
+        filePrefix = "JCA"
+    ) {
         // Wait for the capture button to be displayed
         composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
             composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
@@ -77,8 +85,6 @@ internal class ImageCaptureDeviceTest {
         composeTestRule.waitUntil(timeoutMillis = IMAGE_CAPTURE_TIMEOUT_MILLIS) {
             composeTestRule.onNodeWithTag(IMAGE_CAPTURE_SUCCESS_TAG).isDisplayed()
         }
-        Truth.assertThat(File(DIR_PATH).lastModified() > timeStamp).isTrue()
-        deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
     }
 
     @Test
@@ -87,7 +93,7 @@ internal class ImageCaptureDeviceTest {
         val uri = getTestUri(DIR_PATH, timeStamp, "jpg")
         val result =
             runScenarioTestForResult<MainActivity>(
-                getIntent(uri, MediaStore.ACTION_IMAGE_CAPTURE)
+                getSingleImageCaptureIntent(uri, MediaStore.ACTION_IMAGE_CAPTURE)
             ) {
                 // Wait for the capture button to be displayed
                 composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
@@ -98,8 +104,12 @@ internal class ImageCaptureDeviceTest {
                     .assertExists()
                     .performClick()
             }
-        Truth.assertThat(result?.resultCode).isEqualTo(Activity.RESULT_OK)
-        Truth.assertThat(doesImageFileExist(uri, "image")).isTrue()
+
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_OK)
+
+        Truth.assertThat(
+            doesMediaExist(uri, IMAGE_PREFIX)
+        ).isTrue()
         deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
     }
 
@@ -108,7 +118,7 @@ internal class ImageCaptureDeviceTest {
         val uri = Uri.parse("asdfasdf")
         val result =
             runScenarioTestForResult<MainActivity>(
-                getIntent(uri, MediaStore.ACTION_IMAGE_CAPTURE)
+                getSingleImageCaptureIntent(uri, MediaStore.ACTION_IMAGE_CAPTURE)
             ) {
                 // Wait for the capture button to be displayed
                 composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
@@ -118,13 +128,14 @@ internal class ImageCaptureDeviceTest {
                 composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
                     .assertExists()
                     .performClick()
+
                 composeTestRule.waitUntil(timeoutMillis = IMAGE_CAPTURE_TIMEOUT_MILLIS) {
                     composeTestRule.onNodeWithTag(IMAGE_CAPTURE_FAILURE_TAG).isDisplayed()
                 }
                 uiDevice.pressBack()
             }
-        Truth.assertThat(result?.resultCode).isEqualTo(Activity.RESULT_CANCELED)
-        Truth.assertThat(doesImageFileExist(uri, "image")).isFalse()
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_CANCELED)
+        Truth.assertThat(doesFileExist(uri)).isFalse()
     }
 
     @Test
@@ -133,7 +144,7 @@ internal class ImageCaptureDeviceTest {
         val uri = getTestUri(DIR_PATH, timeStamp, "mp4")
         val result =
             runScenarioTestForResult<MainActivity>(
-                getIntent(uri, MediaStore.ACTION_IMAGE_CAPTURE)
+                getSingleImageCaptureIntent(uri, MediaStore.ACTION_IMAGE_CAPTURE)
             ) {
                 // Wait for the capture button to be displayed
                 composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
@@ -142,15 +153,147 @@ internal class ImageCaptureDeviceTest {
 
                 composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
                     .assertExists()
-                    .performTouchInput { longClick() }
-                composeTestRule.waitUntil(timeoutMillis = VIDEO_CAPTURE_TIMEOUT_MILLIS) {
-                    composeTestRule.onNodeWithTag(VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG)
-                        .isDisplayed()
+                    .performTouchInput { longClick(durationMillis = 3_000) }
+
+                try {
+                    composeTestRule.waitUntil(timeoutMillis = VIDEO_CAPTURE_TIMEOUT_MILLIS) {
+                        // image_only capture UI does not display the video unsupported snackbar
+                        composeTestRule.onNodeWithTag(VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG)
+                            .isDisplayed()
+                    }
+                    throw AssertionError(
+                        "$VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG should not be present"
+                    )
+                } catch (e: ComposeTimeoutException) { /*do nothing. we want to time out */ }
+
+                uiDevice.pressBack()
+            }
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_CANCELED)
+        Truth.assertThat(doesMediaExist(uri, VIDEO_PREFIX)).isFalse()
+    }
+
+    @Test
+    fun multipleImageCaptureExternal_returnsResultOk() {
+        val timeStamp = System.currentTimeMillis()
+        val uriStrings = arrayListOf<String>()
+        for (i in 1..3) {
+            val uri = getTestUri(DIR_PATH, timeStamp + i.toLong(), "jpg")
+            uriStrings.add(uri.toString())
+        }
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getMultipleImageCaptureIntent(
+                    uriStrings,
+                    MediaStore.INTENT_ACTION_STILL_IMAGE_CAMERA
+                )
+            ) {
+                // Wait for the capture button to be displayed
+                composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+                }
+                repeat(2) {
+                    clickCaptureAndWaitUntilMessageDisappears(
+                        IMAGE_CAPTURE_TIMEOUT_MILLIS,
+                        IMAGE_CAPTURE_SUCCESS_TAG
+                    )
+                }
+                clickCapture()
+            }
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_OK)
+        for (string in uriStrings) {
+            Truth.assertThat(
+                doesMediaExist(Uri.parse(string), IMAGE_PREFIX)
+            ).isTrue()
+        }
+        deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
+    }
+
+    @Test
+    fun multipleImageCaptureExternal_withNullUriList_returnsResultOk() {
+        val timeStamp = System.currentTimeMillis()
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getMultipleImageCaptureIntent(null, MediaStore.INTENT_ACTION_STILL_IMAGE_CAMERA)
+            ) {
+                // Wait for the capture button to be displayed
+                composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+                }
+                repeat(2) {
+                    clickCaptureAndWaitUntilMessageDisappears(
+                        IMAGE_CAPTURE_TIMEOUT_MILLIS,
+                        IMAGE_CAPTURE_SUCCESS_TAG
+                    )
                 }
                 uiDevice.pressBack()
             }
-        Truth.assertThat(result?.resultCode).isEqualTo(Activity.RESULT_CANCELED)
-        Truth.assertThat(doesImageFileExist(uri, "video")).isFalse()
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_OK)
+        Truth.assertThat(result.resultData.getStringArrayListExtra(MediaStore.EXTRA_OUTPUT)?.size)
+            .isEqualTo(2)
+        deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
+    }
+
+    @Test
+    fun multipleImageCaptureExternal_withNullUriList_returnsResultCancel() {
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getMultipleImageCaptureIntent(null, MediaStore.INTENT_ACTION_STILL_IMAGE_CAMERA)
+            ) {
+                // Wait for the capture button to be displayed
+                composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+                }
+                uiDevice.pressBack()
+            }
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_CANCELED)
+    }
+
+    @Test
+    fun multipleImageCaptureExternal_withIllegalUri_returnsResultOk() {
+        val timeStamp = System.currentTimeMillis()
+        val uriStrings = arrayListOf<String>()
+        uriStrings.add("illegal_uri")
+        uriStrings.add(getTestUri(DIR_PATH, timeStamp, "jpg").toString())
+        val result =
+            runScenarioTestForResult<MainActivity>(
+                getMultipleImageCaptureIntent(
+                    uriStrings,
+                    MediaStore.INTENT_ACTION_STILL_IMAGE_CAMERA
+                )
+            ) {
+                // Wait for the capture button to be displayed
+                composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+                }
+                clickCaptureAndWaitUntilMessageDisappears(
+                    IMAGE_CAPTURE_TIMEOUT_MILLIS,
+                    IMAGE_CAPTURE_FAILURE_TAG
+                )
+                clickCapture()
+            }
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_OK)
+        Truth.assertThat(
+            doesMediaExist(Uri.parse(uriStrings[1]), IMAGE_PREFIX)
+        ).isTrue()
+        deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
+    }
+
+    private fun clickCaptureAndWaitUntilMessageDisappears(msgTimeOut: Long, msgTag: String) {
+        clickCapture()
+        composeTestRule.waitUntil(timeoutMillis = msgTimeOut) {
+            composeTestRule.onNodeWithTag(msgTag).isDisplayed()
+        }
+        composeTestRule.waitUntil(
+            timeoutMillis = MESSAGE_DISAPPEAR_TIMEOUT_MILLIS
+        ) {
+            composeTestRule.onNodeWithTag(msgTag).isNotDisplayed()
+        }
+    }
+
+    private fun clickCapture() {
+        composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
+            .assertExists()
+            .performClick()
     }
 
     companion object {
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/NavigationTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/NavigationTest.kt
index b3e82ab..f85f244 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/NavigationTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/NavigationTest.kt
@@ -32,8 +32,8 @@ import com.google.jetpackcamera.feature.preview.ui.FLIP_CAMERA_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.SETTINGS_BUTTON
 import com.google.jetpackcamera.settings.R
 import com.google.jetpackcamera.settings.ui.BACK_BUTTON
-import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
 import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.TEST_REQUIRED_PERMISSIONS
 import com.google.jetpackcamera.utils.assume
 import com.google.jetpackcamera.utils.onNodeWithText
 import com.google.jetpackcamera.utils.runScenarioTest
@@ -45,7 +45,7 @@ import org.junit.runner.RunWith
 class NavigationTest {
     @get:Rule
     val permissionsRule: GrantPermissionRule =
-        GrantPermissionRule.grant(*(APP_REQUIRED_PERMISSIONS).toTypedArray())
+        GrantPermissionRule.grant(*(TEST_REQUIRED_PERMISSIONS).toTypedArray())
 
     @get:Rule
     val composeTestRule = createEmptyComposeRule()
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/PermissionsTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/PermissionsTest.kt
new file mode 100644
index 0000000..10c993a
--- /dev/null
+++ b/app/src/androidTest/java/com/google/jetpackcamera/PermissionsTest.kt
@@ -0,0 +1,207 @@
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
+package com.google.jetpackcamera
+
+import androidx.compose.ui.test.isDisplayed
+import androidx.compose.ui.test.isNotDisplayed
+import androidx.compose.ui.test.junit4.createEmptyComposeRule
+import androidx.compose.ui.test.onNodeWithTag
+import androidx.compose.ui.test.performClick
+import androidx.test.ext.junit.runners.AndroidJUnit4
+import androidx.test.filters.SdkSuppress
+import androidx.test.platform.app.InstrumentationRegistry
+import androidx.test.uiautomator.UiDevice
+import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
+import com.google.jetpackcamera.permissions.ui.CAMERA_PERMISSION_BUTTON
+import com.google.jetpackcamera.permissions.ui.RECORD_AUDIO_PERMISSION_BUTTON
+import com.google.jetpackcamera.permissions.ui.REQUEST_PERMISSION_BUTTON
+import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.IndividualTestGrantPermissionRule
+import com.google.jetpackcamera.utils.askEveryTimeDialog
+import com.google.jetpackcamera.utils.denyPermissionDialog
+import com.google.jetpackcamera.utils.grantPermissionDialog
+import com.google.jetpackcamera.utils.onNodeWithText
+import com.google.jetpackcamera.utils.runScenarioTest
+import org.junit.Rule
+import org.junit.Test
+import org.junit.runner.RunWith
+
+const val CAMERA_PERMISSION = "android.permission.CAMERA"
+
+@RunWith(AndroidJUnit4::class)
+class PermissionsTest {
+    @get:Rule
+    val composeTestRule = createEmptyComposeRule()
+
+    @get:Rule
+    val allPermissionsRule = IndividualTestGrantPermissionRule(
+        permissions = APP_REQUIRED_PERMISSIONS.toTypedArray(),
+        targetTestNames = arrayOf(
+            "allPermissions_alreadyGranted_screenNotShown"
+        )
+    )
+
+    @get:Rule
+    val cameraPermissionRule = IndividualTestGrantPermissionRule(
+        permissions = arrayOf(CAMERA_PERMISSION),
+        targetTestNames = arrayOf(
+            "recordAudioPermission_granted_closesPage",
+            "recordAudioPermission_denied_closesPage"
+        )
+    )
+
+    private val instrumentation = InstrumentationRegistry.getInstrumentation()
+    private val uiDevice = UiDevice.getInstance(instrumentation)
+
+    @Test
+    fun allPermissions_alreadyGranted_screenNotShown() {
+        runScenarioTest<MainActivity> {
+            composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
+            }
+        }
+    }
+
+    @Test
+    fun cameraPermission_granted_closesPage() = runScenarioTest<MainActivity> {
+        // Wait for the camera permission screen to be displayed
+        composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+            composeTestRule.onNodeWithTag(CAMERA_PERMISSION_BUTTON).isDisplayed()
+        }
+
+        // Click button to request permission
+        composeTestRule.onNodeWithTag(REQUEST_PERMISSION_BUTTON)
+            .assertExists()
+            .performClick()
+
+        uiDevice.waitForIdle()
+        // grant permission
+        uiDevice.grantPermissionDialog()
+
+        // Assert we're no longer on camera permission screen
+        composeTestRule.onNodeWithTag(CAMERA_PERMISSION_BUTTON).assertDoesNotExist()
+    }
+
+    @SdkSuppress(minSdkVersion = 30)
+    @Test
+    fun cameraPermission_askEveryTime_closesPage() {
+        uiDevice.waitForIdle()
+        runScenarioTest<MainActivity> {
+            // Wait for the camera permission screen to be displayed
+            composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(CAMERA_PERMISSION_BUTTON).isDisplayed()
+            }
+
+            // Click button to request permission
+            composeTestRule.onNodeWithTag(REQUEST_PERMISSION_BUTTON)
+                .assertExists()
+                .performClick()
+
+            // set permission to ask every time
+            uiDevice.askEveryTimeDialog()
+
+            // Assert we're no longer on camera permission screen
+            composeTestRule.onNodeWithTag(CAMERA_PERMISSION_BUTTON).assertDoesNotExist()
+        }
+    }
+
+    @Test
+    fun cameraPermission_declined_staysOnScreen() {
+        // required permissions should persist on screen
+        // Wait for the permission screen to be displayed
+        runScenarioTest<MainActivity> {
+            composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(CAMERA_PERMISSION_BUTTON).isDisplayed()
+            }
+
+            // Click button to request permission
+            composeTestRule.onNodeWithTag(REQUEST_PERMISSION_BUTTON)
+                .assertExists()
+                .performClick()
+
+            // deny permission
+            uiDevice.denyPermissionDialog()
+
+            uiDevice.waitForIdle()
+
+            // Assert we're still on camera permission screen
+            composeTestRule.onNodeWithTag(CAMERA_PERMISSION_BUTTON).isDisplayed()
+
+            // text changed after permission denied
+            composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithText(
+                    com.google.jetpackcamera.permissions.R.string
+                        .camera_permission_declined_rationale
+                )
+                    .isDisplayed()
+            }
+            // request permissions button should now say to navigate to settings
+            composeTestRule.onNodeWithText(
+                com.google.jetpackcamera.permissions
+                    .R.string.navigate_to_settings
+            ).assertExists()
+        }
+    }
+
+    @Test
+    fun recordAudioPermission_granted_closesPage() {
+        // optional permissions should close the screen after declining
+        runScenarioTest<MainActivity> {
+            composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(RECORD_AUDIO_PERMISSION_BUTTON).isDisplayed()
+            }
+
+            // Click button to request permission
+            composeTestRule.onNodeWithTag(REQUEST_PERMISSION_BUTTON)
+                .assertExists()
+                .performClick()
+
+            // grant permission
+            uiDevice.grantPermissionDialog()
+            uiDevice.waitForIdle()
+
+            // Assert we're on a different page
+            composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(RECORD_AUDIO_PERMISSION_BUTTON).isNotDisplayed()
+            }
+        }
+    }
+
+    @Test
+    fun recordAudioPermission_denied_closesPage() {
+        // optional permissions should close the screen after declining
+        runScenarioTest<MainActivity> {
+            composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(RECORD_AUDIO_PERMISSION_BUTTON).isDisplayed()
+            }
+
+            // Click button to request permission
+            composeTestRule.onNodeWithTag(REQUEST_PERMISSION_BUTTON)
+                .assertExists()
+                .performClick()
+
+            // deny permission
+            uiDevice.denyPermissionDialog()
+            uiDevice.waitForIdle()
+
+            // Assert we're on a different page
+            composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
+                composeTestRule.onNodeWithTag(RECORD_AUDIO_PERMISSION_BUTTON).isNotDisplayed()
+            }
+        }
+    }
+}
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/SwitchCameraTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/SwitchCameraTest.kt
index 5d732a9..320f3ef 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/SwitchCameraTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/SwitchCameraTest.kt
@@ -32,7 +32,8 @@ import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_
 import com.google.jetpackcamera.feature.preview.ui.FLIP_CAMERA_BUTTON
 import com.google.jetpackcamera.feature.preview.ui.PREVIEW_DISPLAY
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
+import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.TEST_REQUIRED_PERMISSIONS
 import com.google.jetpackcamera.utils.assume
 import com.google.jetpackcamera.utils.getCurrentLensFacing
 import com.google.jetpackcamera.utils.runScenarioTest
@@ -44,7 +45,7 @@ import org.junit.runner.RunWith
 class SwitchCameraTest {
     @get:Rule
     val permissionsRule: GrantPermissionRule =
-        GrantPermissionRule.grant(*(APP_REQUIRED_PERMISSIONS).toTypedArray())
+        GrantPermissionRule.grant(*(TEST_REQUIRED_PERMISSIONS).toTypedArray())
 
     @get:Rule
     val composeTestRule = createEmptyComposeRule()
@@ -140,7 +141,7 @@ inline fun runFlipCameraTest(
     crossinline block: ActivityScenario<MainActivity>.() -> Unit
 ) = runScenarioTest {
     // Wait for the preview display to be visible
-    composeTestRule.waitUntil {
+    composeTestRule.waitUntil(APP_START_TIMEOUT_MILLIS) {
         composeTestRule.onNodeWithTag(PREVIEW_DISPLAY).isDisplayed()
     }
 
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/VideoAudioTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/VideoAudioTest.kt
index 0cfbd73..3af4d12 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/VideoAudioTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/VideoAudioTest.kt
@@ -30,8 +30,8 @@ import androidx.test.uiautomator.Until
 import com.google.common.truth.Truth.assertThat
 import com.google.jetpackcamera.feature.preview.ui.AMPLITUDE_HOT_TAG
 import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
-import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
 import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.TEST_REQUIRED_PERMISSIONS
 import com.google.jetpackcamera.utils.runScenarioTest
 import org.junit.Before
 import org.junit.Rule
@@ -43,7 +43,7 @@ import org.junit.runner.RunWith
 class VideoAudioTest {
     @get:Rule
     val permissionsRule: GrantPermissionRule =
-        GrantPermissionRule.grant(*(APP_REQUIRED_PERMISSIONS).toTypedArray())
+        GrantPermissionRule.grant(*(TEST_REQUIRED_PERMISSIONS).toTypedArray())
 
     @get:Rule
     val composeTestRule = createEmptyComposeRule()
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/VideoRecordingDeviceTest.kt b/app/src/androidTest/java/com/google/jetpackcamera/VideoRecordingDeviceTest.kt
index 545b406..c4ff473 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/VideoRecordingDeviceTest.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/VideoRecordingDeviceTest.kt
@@ -19,33 +19,31 @@ import android.app.Activity
 import android.net.Uri
 import android.os.Environment
 import android.provider.MediaStore
-import androidx.compose.ui.test.ComposeTimeoutException
 import androidx.compose.ui.test.isDisplayed
 import androidx.compose.ui.test.junit4.createEmptyComposeRule
 import androidx.compose.ui.test.onNodeWithTag
 import androidx.compose.ui.test.performClick
-import androidx.compose.ui.test.performTouchInput
 import androidx.test.ext.junit.runners.AndroidJUnit4
 import androidx.test.platform.app.InstrumentationRegistry
 import androidx.test.rule.GrantPermissionRule
 import androidx.test.uiautomator.UiDevice
 import com.google.common.truth.Truth
 import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
-import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
 import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_FAILURE_TAG
 import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_SUCCESS_TAG
-import com.google.jetpackcamera.utils.APP_REQUIRED_PERMISSIONS
 import com.google.jetpackcamera.utils.APP_START_TIMEOUT_MILLIS
-import com.google.jetpackcamera.utils.IMAGE_CAPTURE_TIMEOUT_MILLIS
+import com.google.jetpackcamera.utils.IMAGE_PREFIX
+import com.google.jetpackcamera.utils.TEST_REQUIRED_PERMISSIONS
 import com.google.jetpackcamera.utils.VIDEO_CAPTURE_TIMEOUT_MILLIS
-import com.google.jetpackcamera.utils.VIDEO_DURATION_MILLIS
+import com.google.jetpackcamera.utils.VIDEO_PREFIX
 import com.google.jetpackcamera.utils.deleteFilesInDirAfterTimestamp
-import com.google.jetpackcamera.utils.doesImageFileExist
-import com.google.jetpackcamera.utils.getIntent
+import com.google.jetpackcamera.utils.doesMediaExist
+import com.google.jetpackcamera.utils.getSingleImageCaptureIntent
 import com.google.jetpackcamera.utils.getTestUri
-import com.google.jetpackcamera.utils.runScenarioTest
+import com.google.jetpackcamera.utils.longClickForVideoRecording
+import com.google.jetpackcamera.utils.runMediaStoreAutoDeleteScenarioTest
 import com.google.jetpackcamera.utils.runScenarioTestForResult
-import java.io.File
+import com.google.jetpackcamera.utils.tapStartLockedVideoRecording
 import org.junit.Rule
 import org.junit.Test
 import org.junit.runner.RunWith
@@ -54,7 +52,7 @@ import org.junit.runner.RunWith
 internal class VideoRecordingDeviceTest {
     @get:Rule
     val permissionsRule: GrantPermissionRule =
-        GrantPermissionRule.grant(*(APP_REQUIRED_PERMISSIONS).toTypedArray())
+        GrantPermissionRule.grant(*(TEST_REQUIRED_PERMISSIONS).toTypedArray())
 
     @get:Rule
     val composeTestRule = createEmptyComposeRule()
@@ -63,109 +61,83 @@ internal class VideoRecordingDeviceTest {
     private val uiDevice = UiDevice.getInstance(instrumentation)
 
     @Test
-    fun video_capture() = runScenarioTest<MainActivity> {
+    fun pressed_video_capture(): Unit = runMediaStoreAutoDeleteScenarioTest<MainActivity>(
+        mediaUri = MediaStore.Video.Media.EXTERNAL_CONTENT_URI
+    ) {
         val timeStamp = System.currentTimeMillis()
         // Wait for the capture button to be displayed
         composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
             composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
         }
-        longClickForVideoRecording()
+        composeTestRule.longClickForVideoRecording()
         composeTestRule.waitUntil(timeoutMillis = VIDEO_CAPTURE_TIMEOUT_MILLIS) {
             composeTestRule.onNodeWithTag(VIDEO_CAPTURE_SUCCESS_TAG).isDisplayed()
         }
-        Truth.assertThat(File(DIR_PATH).lastModified() > timeStamp).isTrue()
         deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
     }
 
     @Test
-    fun video_capture_external_intent() {
+    fun pressed_video_capture_external_intent() {
         val timeStamp = System.currentTimeMillis()
         val uri = getTestUri(DIR_PATH, timeStamp, "mp4")
         val result =
             runScenarioTestForResult<MainActivity>(
-                getIntent(uri, MediaStore.ACTION_VIDEO_CAPTURE)
+                getSingleImageCaptureIntent(uri, MediaStore.ACTION_VIDEO_CAPTURE)
             ) {
                 // Wait for the capture button to be displayed
                 composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
                     composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
                 }
-                longClickForVideoRecording()
+                composeTestRule.longClickForVideoRecording()
             }
-        Truth.assertThat(result?.resultCode).isEqualTo(Activity.RESULT_OK)
-        Truth.assertThat(doesImageFileExist(uri, "video")).isTrue()
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_OK)
+        Truth.assertThat(doesMediaExist(uri, VIDEO_PREFIX)).isTrue()
         deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
     }
 
     @Test
-    fun video_capture_external_illegal_uri() {
-        val uri = Uri.parse("asdfasdf")
+    fun tap_video_capture_external_intent() {
+        val timeStamp = System.currentTimeMillis()
+        val uri = getTestUri(DIR_PATH, timeStamp, "mp4")
         val result =
             runScenarioTestForResult<MainActivity>(
-                getIntent(uri, MediaStore.ACTION_VIDEO_CAPTURE)
+                getSingleImageCaptureIntent(uri, MediaStore.ACTION_VIDEO_CAPTURE)
             ) {
                 // Wait for the capture button to be displayed
                 composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
                     composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
                 }
-                longClickForVideoRecording()
-                composeTestRule.waitUntil(timeoutMillis = VIDEO_CAPTURE_TIMEOUT_MILLIS) {
-                    composeTestRule.onNodeWithTag(VIDEO_CAPTURE_FAILURE_TAG).isDisplayed()
-                }
-                uiDevice.pressBack()
+                // start recording
+                composeTestRule.tapStartLockedVideoRecording()
+
+                // stop recording
+                composeTestRule.onNodeWithTag(CAPTURE_BUTTON).assertExists().performClick()
             }
-        Truth.assertThat(result?.resultCode).isEqualTo(Activity.RESULT_CANCELED)
-        Truth.assertThat(doesImageFileExist(uri, "video")).isFalse()
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_OK)
+        Truth.assertThat(doesMediaExist(uri, IMAGE_PREFIX)).isFalse()
+        Truth.assertThat(doesMediaExist(uri, VIDEO_PREFIX)).isTrue()
+        deleteFilesInDirAfterTimestamp(DIR_PATH, instrumentation, timeStamp)
     }
 
     @Test
-    fun image_capture_during_video_capture_external() {
-        val timeStamp = System.currentTimeMillis()
-        val uri = getTestUri(ImageCaptureDeviceTest.DIR_PATH, timeStamp, "mp4")
+    fun video_capture_external_illegal_uri() {
+        val uri = Uri.parse("asdfasdf")
         val result =
             runScenarioTestForResult<MainActivity>(
-                getIntent(uri, MediaStore.ACTION_VIDEO_CAPTURE)
+                getSingleImageCaptureIntent(uri, MediaStore.ACTION_VIDEO_CAPTURE)
             ) {
                 // Wait for the capture button to be displayed
                 composeTestRule.waitUntil(timeoutMillis = APP_START_TIMEOUT_MILLIS) {
                     composeTestRule.onNodeWithTag(CAPTURE_BUTTON).isDisplayed()
                 }
-
-                composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
-                    .assertExists()
-                    .performClick()
-                composeTestRule.waitUntil(timeoutMillis = IMAGE_CAPTURE_TIMEOUT_MILLIS) {
-                    composeTestRule.onNodeWithTag(
-                        IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
-                    ).isDisplayed()
+                composeTestRule.longClickForVideoRecording()
+                composeTestRule.waitUntil(timeoutMillis = VIDEO_CAPTURE_TIMEOUT_MILLIS) {
+                    composeTestRule.onNodeWithTag(VIDEO_CAPTURE_FAILURE_TAG).isDisplayed()
                 }
                 uiDevice.pressBack()
             }
-        Truth.assertThat(result?.resultCode).isEqualTo(Activity.RESULT_CANCELED)
-        Truth.assertThat(doesImageFileExist(uri, "image")).isFalse()
-    }
-
-    private fun longClickForVideoRecording() {
-        composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
-            .assertExists()
-            .performTouchInput {
-                down(center)
-            }
-        idleForVideoDuration()
-        composeTestRule.onNodeWithTag(CAPTURE_BUTTON)
-            .assertExists()
-            .performTouchInput {
-                up()
-            }
-    }
-
-    private fun idleForVideoDuration() {
-        // TODO: replace with a check for the timestamp UI of the video duration
-        try {
-            composeTestRule.waitUntil(timeoutMillis = VIDEO_DURATION_MILLIS) {
-                composeTestRule.onNodeWithTag("dummyTagForLongPress").isDisplayed()
-            }
-        } catch (e: ComposeTimeoutException) {
-        }
+        Truth.assertThat(result.resultCode).isEqualTo(Activity.RESULT_CANCELED)
+        Truth.assertThat(doesMediaExist(uri, VIDEO_PREFIX)).isFalse()
     }
 
     companion object {
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/utils/AppTestUtil.kt b/app/src/androidTest/java/com/google/jetpackcamera/utils/AppTestUtil.kt
index 0d1e8d6..55033f7 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/utils/AppTestUtil.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/utils/AppTestUtil.kt
@@ -15,12 +15,125 @@
  */
 package com.google.jetpackcamera.utils
 
+import android.app.Instrumentation
+import android.database.ContentObserver
+import android.database.Cursor
+import android.net.Uri
 import android.os.Build
+import android.provider.BaseColumns
+import android.provider.MediaStore
+import kotlinx.coroutines.channels.awaitClose
+import kotlinx.coroutines.flow.Flow
+import kotlinx.coroutines.flow.callbackFlow
+import kotlinx.coroutines.flow.transform
 
-val APP_REQUIRED_PERMISSIONS: List<String> = buildList {
+internal val APP_REQUIRED_PERMISSIONS: List<String> = buildList {
     add(android.Manifest.permission.CAMERA)
     add(android.Manifest.permission.RECORD_AUDIO)
     if (Build.VERSION.SDK_INT <= 28) {
         add(android.Manifest.permission.WRITE_EXTERNAL_STORAGE)
+        add(android.Manifest.permission.READ_EXTERNAL_STORAGE)
+    }
+}
+
+val TEST_REQUIRED_PERMISSIONS: List<String> = buildList {
+    addAll(APP_REQUIRED_PERMISSIONS)
+    if (Build.VERSION.SDK_INT >= 33) {
+        add(android.Manifest.permission.READ_MEDIA_IMAGES)
+        add(android.Manifest.permission.READ_MEDIA_VIDEO)
+    }
+}
+
+fun mediaStoreInsertedFlow(
+    mediaUri: Uri,
+    instrumentation: Instrumentation,
+    filePrefix: String = ""
+): Flow<Pair<String, Uri>> = with(instrumentation.targetContext.contentResolver) {
+    // Creates a map of the display names and corresponding URIs for all files contained within
+    // the URI argument. If the URI is a single file, the map will contain a single file.
+    // On API 29+, this will also only return files that are not "pending". Pending files
+    // have not yet been fully written.
+    fun queryWrittenFiles(uri: Uri): Map<String, Uri> {
+        return buildMap {
+            query(
+                uri,
+                buildList {
+                    add(BaseColumns._ID)
+                    add(MediaStore.MediaColumns.DISPLAY_NAME)
+                    if (Build.VERSION.SDK_INT >= 29) {
+                        add(MediaStore.MediaColumns.IS_PENDING)
+                    }
+                }.toTypedArray(),
+                null,
+                null,
+                null
+            )?.use { cursor: Cursor ->
+                cursor.moveToFirst()
+                val idCol = cursor.getColumnIndex(BaseColumns._ID)
+                val displayNameCol = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME)
+
+                while (!cursor.isAfterLast) {
+                    val id = cursor.getLong(idCol)
+                    val displayName = cursor.getString(displayNameCol)
+                    val isPending = if (Build.VERSION.SDK_INT >= 29) {
+                        cursor.getInt(cursor.getColumnIndex(MediaStore.MediaColumns.IS_PENDING))
+                    } else {
+                        // On devices pre-API 29, we don't have an is_pending column, so never
+                        // say that the file is pending
+                        0
+                    }
+                    if (isPending == 0 &&
+                        (filePrefix.isEmpty() || displayName.startsWith(filePrefix))
+                    ) {
+                        // Construct URI for a single file
+                        val outputUri = if (uri.lastPathSegment?.equals("$id") == false) {
+                            uri.buildUpon().appendPath("$id").build()
+                        } else {
+                            uri
+                        }
+                        put(displayName, outputUri)
+                    }
+                    cursor.moveToNext()
+                }
+            }
+        }
+    }
+
+    // Get the full list of initially written files. We'll append files to this as we
+    // publish them.
+    val existingFiles = queryWrittenFiles(mediaUri).toMutableMap()
+    return callbackFlow {
+        val observer = object : ContentObserver(null) {
+            override fun onChange(selfChange: Boolean) {
+                onChange(selfChange, null)
+            }
+
+            override fun onChange(selfChange: Boolean, uri: Uri?) {
+                onChange(selfChange, uri, 0)
+            }
+
+            override fun onChange(selfChange: Boolean, uri: Uri?, flags: Int) {
+                onChange(selfChange, uri?.let { setOf(it) } ?: emptySet(), flags)
+            }
+
+            override fun onChange(selfChange: Boolean, uris: Collection<Uri>, flags: Int) {
+                uris.forEach { uri ->
+                    queryWrittenFiles(uri).forEach {
+                        trySend(it)
+                    }
+                }
+            }
+        }
+
+        registerContentObserver(mediaUri, true, observer)
+
+        awaitClose {
+            unregisterContentObserver(observer)
+        }
+    }.transform {
+        if (!existingFiles.containsKey(it.key)) {
+            existingFiles[it.key] = it.value
+            emit(it.toPair())
+        }
     }
 }
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/utils/ComposeTestRuleExt.kt b/app/src/androidTest/java/com/google/jetpackcamera/utils/ComposeTestRuleExt.kt
index e3be80e..7561b1e 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/utils/ComposeTestRuleExt.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/utils/ComposeTestRuleExt.kt
@@ -17,13 +17,27 @@ package com.google.jetpackcamera.utils
 
 import android.content.Context
 import androidx.annotation.StringRes
+import androidx.compose.ui.semantics.SemanticsProperties
+import androidx.compose.ui.test.ComposeTimeoutException
 import androidx.compose.ui.test.SemanticsMatcher
 import androidx.compose.ui.test.SemanticsNodeInteraction
 import androidx.compose.ui.test.SemanticsNodeInteractionsProvider
+import androidx.compose.ui.test.isDisplayed
+import androidx.compose.ui.test.isEnabled
+import androidx.compose.ui.test.junit4.ComposeTestRule
 import androidx.compose.ui.test.onNodeWithContentDescription
+import androidx.compose.ui.test.onNodeWithTag
 import androidx.compose.ui.test.onNodeWithText
+import androidx.compose.ui.test.performClick
+import androidx.compose.ui.test.performTouchInput
 import androidx.compose.ui.test.printToString
 import androidx.test.core.app.ApplicationProvider
+import com.google.jetpackcamera.feature.preview.R
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLASH_BUTTON
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLIP_CAMERA_BUTTON
+import com.google.jetpackcamera.feature.preview.ui.CAPTURE_BUTTON
+import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.LensFacing
 import org.junit.AssumptionViolatedException
 
 /**
@@ -49,9 +63,8 @@ fun SemanticsNodeInteractionsProvider.onNodeWithContentDescription(
 /**
  * Fetch a string resources from a [SemanticsNodeInteractionsProvider] context.
  */
-fun SemanticsNodeInteractionsProvider.getResString(@StringRes strRes: Int): String {
-    return ApplicationProvider.getApplicationContext<Context>().getString(strRes)
-}
+fun SemanticsNodeInteractionsProvider.getResString(@StringRes strRes: Int): String =
+    ApplicationProvider.getApplicationContext<Context>().getString(strRes)
 
 /**
  * Assumes that the provided [matcher] is satisfied for this node.
@@ -84,6 +97,124 @@ fun SemanticsNodeInteraction.assume(
     return this
 }
 
+fun ComposeTestRule.longClickForVideoRecording() {
+    onNodeWithTag(CAPTURE_BUTTON)
+        .assertExists()
+        .performTouchInput {
+            down(center)
+        }
+    idleForVideoDuration()
+    onNodeWithTag(CAPTURE_BUTTON)
+        .assertExists()
+        .performTouchInput {
+            up()
+        }
+}
+
+fun ComposeTestRule.tapStartLockedVideoRecording() {
+    onNodeWithTag(CAPTURE_BUTTON)
+        .assertExists()
+        .performClick()
+    idleForVideoDuration()
+}
+
+private fun ComposeTestRule.idleForVideoDuration() {
+    // TODO: replace with a check for the timestamp UI of the video duration
+    try {
+        waitUntil(timeoutMillis = VIDEO_DURATION_MILLIS) {
+            onNodeWithTag("dummyTagForLongPress").isDisplayed()
+        }
+    } catch (e: ComposeTimeoutException) {
+    }
+}
+
+fun ComposeTestRule.getCurrentLensFacing(): LensFacing = visitQuickSettings {
+    onNodeWithTag(QUICK_SETTINGS_FLIP_CAMERA_BUTTON).fetchSemanticsNode(
+        "Flip camera button is not visible when expected."
+    ).let { node ->
+        node.config[SemanticsProperties.ContentDescription].any { description ->
+            when (description) {
+                getResString(R.string.quick_settings_front_camera_description) ->
+                    return@let LensFacing.FRONT
+                getResString(R.string.quick_settings_back_camera_description) ->
+                    return@let LensFacing.BACK
+                else -> false
+            }
+        }
+        throw AssertionError("Unable to determine lens facing from quick settings")
+    }
+}
+
+fun ComposeTestRule.getCurrentFlashMode(): FlashMode = visitQuickSettings {
+    onNodeWithTag(QUICK_SETTINGS_FLASH_BUTTON).fetchSemanticsNode(
+        "Flash button is not visible when expected."
+    ).let { node ->
+        node.config[SemanticsProperties.ContentDescription].any { description ->
+            when (description) {
+                getResString(R.string.quick_settings_flash_off_description) ->
+                    return@let FlashMode.OFF
+                getResString(R.string.quick_settings_flash_on_description) ->
+                    return@let FlashMode.ON
+                getResString(R.string.quick_settings_flash_auto_description) ->
+                    return@let FlashMode.AUTO
+                getResString(R.string.quick_settings_flash_llb_description) ->
+                    return@let FlashMode.LOW_LIGHT_BOOST
+                else -> false
+            }
+        }
+        throw AssertionError("Unable to determine flash mode from quick settings")
+    }
+}
+
+// Navigates to quick settings if not already there and perform action from provided block.
+// This will return from quick settings if not already there, or remain on quick settings if there.
+inline fun <T> ComposeTestRule.visitQuickSettings(crossinline block: ComposeTestRule.() -> T): T {
+    var needReturnFromQuickSettings = false
+    onNodeWithContentDescription(R.string.quick_settings_dropdown_closed_description).apply {
+        if (isDisplayed()) {
+            performClick()
+            needReturnFromQuickSettings = true
+        }
+    }
+
+    onNodeWithContentDescription(R.string.quick_settings_dropdown_open_description).assertExists(
+        "Quick settings can only be entered from PreviewScreen or QuickSettings screen"
+    )
+
+    try {
+        return block()
+    } finally {
+        if (needReturnFromQuickSettings) {
+            onNodeWithContentDescription(R.string.quick_settings_dropdown_open_description)
+                .assertExists()
+                .performClick()
+        }
+    }
+}
+
+fun ComposeTestRule.setFlashMode(flashMode: FlashMode) {
+    visitQuickSettings {
+        // Click the flash button to switch to ON
+        onNodeWithTag(QUICK_SETTINGS_FLASH_BUTTON)
+            .assertExists()
+            .assume(isEnabled()) {
+                "Current lens does not support any flash modes"
+            }.apply {
+                val initialFlashMode = getCurrentFlashMode()
+                var currentFlashMode = initialFlashMode
+                while (currentFlashMode != flashMode) {
+                    performClick()
+                    currentFlashMode = getCurrentFlashMode()
+                    if (currentFlashMode == initialFlashMode) {
+                        throw AssumptionViolatedException(
+                            "Current lens does not support $flashMode"
+                        )
+                    }
+                }
+            }
+    }
+}
+
 internal fun buildGeneralErrorMessage(
     errorMessage: String,
     nodeInteraction: SemanticsNodeInteraction
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/utils/MetaDataRetrieverExt.kt b/app/src/androidTest/java/com/google/jetpackcamera/utils/MetaDataRetrieverExt.kt
new file mode 100644
index 0000000..2d43e64
--- /dev/null
+++ b/app/src/androidTest/java/com/google/jetpackcamera/utils/MetaDataRetrieverExt.kt
@@ -0,0 +1,61 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.google.jetpackcamera.utils
+
+import android.media.MediaMetadataRetriever
+import android.media.MediaMetadataRetriever.METADATA_KEY_DURATION
+import android.media.MediaMetadataRetriever.METADATA_KEY_HAS_AUDIO
+import android.media.MediaMetadataRetriever.METADATA_KEY_HAS_VIDEO
+import android.media.MediaMetadataRetriever.METADATA_KEY_MIMETYPE
+import android.media.MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT
+import android.media.MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH
+import android.util.Rational
+import android.util.Size
+
+inline fun <R> MediaMetadataRetriever.useAndRelease(
+    crossinline block: (MediaMetadataRetriever) -> R
+): R? {
+    try {
+        return block(this)
+    } finally {
+        release()
+    }
+}
+
+fun MediaMetadataRetriever.hasAudio(): Boolean = extractMetadata(METADATA_KEY_HAS_AUDIO) == "yes"
+
+fun MediaMetadataRetriever.hasVideo(): Boolean = extractMetadata(METADATA_KEY_HAS_VIDEO) == "yes"
+
+fun MediaMetadataRetriever.getDurationMs(): Long =
+    checkNotNull(extractMetadata(METADATA_KEY_DURATION)?.toLong()) {
+        "duration unavailable"
+    }
+
+fun MediaMetadataRetriever.getWidth(): Int =
+    checkNotNull(extractMetadata(METADATA_KEY_VIDEO_WIDTH)?.toInt()) {
+        "width unavailable"
+    }
+
+fun MediaMetadataRetriever.getHeight(): Int =
+    checkNotNull(extractMetadata(METADATA_KEY_VIDEO_HEIGHT)?.toInt()) {
+        "height information unavailable"
+    }
+
+fun MediaMetadataRetriever.getResolution(): Size = Size(getWidth(), getHeight())
+
+fun MediaMetadataRetriever.getAspectRatio(): Rational = Rational(getWidth(), getHeight())
+
+fun MediaMetadataRetriever.getMimeType(): String = extractMetadata(METADATA_KEY_MIMETYPE)!!
diff --git a/app/src/androidTest/java/com/google/jetpackcamera/utils/UiTestUtil.kt b/app/src/androidTest/java/com/google/jetpackcamera/utils/UiTestUtil.kt
index 782ede2..c403f2c 100644
--- a/app/src/androidTest/java/com/google/jetpackcamera/utils/UiTestUtil.kt
+++ b/app/src/androidTest/java/com/google/jetpackcamera/utils/UiTestUtil.kt
@@ -19,25 +19,118 @@ import android.app.Activity
 import android.app.Instrumentation
 import android.content.ComponentName
 import android.content.Intent
+import android.graphics.BitmapFactory
+import android.media.MediaMetadataRetriever
 import android.net.Uri
+import android.os.Build
 import android.provider.MediaStore
+import android.util.Log
 import androidx.compose.ui.semantics.SemanticsProperties
-import androidx.compose.ui.test.isDisplayed
-import androidx.compose.ui.test.junit4.ComposeTestRule
-import androidx.compose.ui.test.onNodeWithTag
-import androidx.compose.ui.test.performClick
+import androidx.compose.ui.test.SemanticsMatcher
+import androidx.lifecycle.Lifecycle
 import androidx.test.core.app.ActivityScenario
-import com.google.jetpackcamera.MainActivity
-import com.google.jetpackcamera.feature.preview.R
-import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLIP_CAMERA_BUTTON
-import com.google.jetpackcamera.settings.model.LensFacing
+import androidx.test.platform.app.InstrumentationRegistry
+import androidx.test.rule.GrantPermissionRule
+import androidx.test.uiautomator.By
+import androidx.test.uiautomator.UiDevice
+import androidx.test.uiautomator.UiObject2
+import androidx.test.uiautomator.Until
+import com.google.common.truth.Truth.assertWithMessage
 import java.io.File
 import java.net.URLConnection
+import java.util.concurrent.TimeoutException
+import kotlin.coroutines.CoroutineContext
+import kotlin.time.Duration
+import kotlin.time.Duration.Companion.seconds
+import kotlinx.coroutines.Dispatchers
+import kotlinx.coroutines.NonCancellable
+import kotlinx.coroutines.cancelAndJoin
+import kotlinx.coroutines.delay
+import kotlinx.coroutines.flow.take
+import kotlinx.coroutines.launch
+import kotlinx.coroutines.runBlocking
+import kotlinx.coroutines.withContext
+import kotlinx.coroutines.withTimeoutOrNull
+import org.junit.Assert.fail
+import org.junit.rules.TestRule
+import org.junit.runner.Description
+import org.junit.runners.model.Statement
 
 const val APP_START_TIMEOUT_MILLIS = 10_000L
+const val SCREEN_FLASH_OVERLAY_TIMEOUT_MILLIS = 5_000L
 const val IMAGE_CAPTURE_TIMEOUT_MILLIS = 5_000L
 const val VIDEO_CAPTURE_TIMEOUT_MILLIS = 5_000L
-const val VIDEO_DURATION_MILLIS = 2_000L
+const val VIDEO_DURATION_MILLIS = 3_000L
+const val MESSAGE_DISAPPEAR_TIMEOUT_MILLIS = 15_000L
+const val VIDEO_PREFIX = "video"
+const val IMAGE_PREFIX = "image"
+const val COMPONENT_PACKAGE_NAME = "com.google.jetpackcamera"
+const val COMPONENT_CLASS = "com.google.jetpackcamera.MainActivity"
+private const val TAG = "UiTestUtil"
+
+inline fun <reified T : Activity> runMediaStoreAutoDeleteScenarioTest(
+    mediaUri: Uri,
+    filePrefix: String = "",
+    expectedNumFiles: Int = 1,
+    fileWaitTimeoutMs: Duration = 10.seconds,
+    fileObserverContext: CoroutineContext = Dispatchers.IO,
+    crossinline block: ActivityScenario<T>.() -> Unit
+) = runBlocking {
+    val debugTag = "MediaStoreAutoDelete"
+    val instrumentation = InstrumentationRegistry.getInstrumentation()
+    val insertedMediaStoreEntries = mutableMapOf<String, Uri>()
+    val observeFilesJob = launch(fileObserverContext) {
+        mediaStoreInsertedFlow(
+            mediaUri = mediaUri,
+            instrumentation = instrumentation,
+            filePrefix = filePrefix
+        ).take(expectedNumFiles)
+            .collect {
+                Log.d(debugTag, "Discovered new media store file: ${it.first}")
+                insertedMediaStoreEntries[it.first] = it.second
+            }
+    }
+
+    var succeeded = false
+    try {
+        runScenarioTest(block = block)
+        succeeded = true
+    } finally {
+        withContext(NonCancellable) {
+            if (!succeeded ||
+                withTimeoutOrNull(fileWaitTimeoutMs) {
+                    // Wait for normal completion with timeout
+                    observeFilesJob.join()
+                } == null
+            ) {
+                // If the test didn't succeed, or we've timed out waiting for files,
+                // cancel file observer and ensure job is complete
+                observeFilesJob.cancelAndJoin()
+            }
+
+            val detectedNumFiles = insertedMediaStoreEntries.size
+            // Delete all inserted files that we know about at this point
+            insertedMediaStoreEntries.forEach {
+                Log.d(debugTag, "Deleting media store file: $it")
+                val deletedRows = instrumentation.targetContext.contentResolver.delete(
+                    it.value,
+                    null,
+                    null
+                )
+                if (deletedRows > 0) {
+                    Log.d(debugTag, "Deleted $deletedRows files")
+                } else {
+                    Log.e(debugTag, "Failed to delete ${it.key}")
+                }
+            }
+
+            if (succeeded) {
+                assertWithMessage("Expected number of saved files does not match detected number")
+                    .that(detectedNumFiles).isEqualTo(expectedNumFiles)
+            }
+        }
+    }
+}
 
 inline fun <reified T : Activity> runScenarioTest(
     crossinline block: ActivityScenario<T>.() -> Unit
@@ -50,61 +143,36 @@ inline fun <reified T : Activity> runScenarioTest(
 inline fun <reified T : Activity> runScenarioTestForResult(
     intent: Intent,
     crossinline block: ActivityScenario<T>.() -> Unit
-): Instrumentation.ActivityResult? {
+): Instrumentation.ActivityResult {
     ActivityScenario.launchActivityForResult<T>(intent).use { scenario ->
         scenario.apply(block)
-        return scenario.result
+        return runBlocking { scenario.pollResult() }
     }
 }
 
-context(ActivityScenario<MainActivity>)
-fun ComposeTestRule.getCurrentLensFacing(): LensFacing {
-    var needReturnFromQuickSettings = false
-    onNodeWithContentDescription(R.string.quick_settings_dropdown_closed_description).apply {
-        if (isDisplayed()) {
-            performClick()
-            needReturnFromQuickSettings = true
-        }
+// Workaround for https://github.com/android/android-test/issues/676
+suspend inline fun <reified T : Activity> ActivityScenario<T>.pollResult(
+    // Choose timeout to match
+    // https://github.com/android/android-test/blob/67fa7cb12b9a14dc790b75947f4241c3063e80dc/runner/monitor/java/androidx/test/internal/platform/app/ActivityLifecycleTimeout.java#L22
+    timeout: Duration = 45.seconds
+): Instrumentation.ActivityResult = withTimeoutOrNull(timeout) {
+    // Poll for the state to be destroyed before we return the result
+    while (state != Lifecycle.State.DESTROYED) {
+        delay(100)
     }
-
-    onNodeWithContentDescription(R.string.quick_settings_dropdown_open_description).assertExists(
-        "LensFacing can only be retrieved from PreviewScreen or QuickSettings screen"
+    checkNotNull(result)
+} ?: run {
+    throw TimeoutException(
+        "Timed out while waiting for activity result. Waited $timeout."
     )
-
-    try {
-        return onNodeWithTag(QUICK_SETTINGS_FLIP_CAMERA_BUTTON).fetchSemanticsNode(
-            "Flip camera button is not visible when expected."
-        ).let { node ->
-            node.config[SemanticsProperties.ContentDescription].any { description ->
-                when (description) {
-                    getResString(R.string.quick_settings_front_camera_description) ->
-                        return@let LensFacing.FRONT
-
-                    getResString(R.string.quick_settings_back_camera_description) ->
-                        return@let LensFacing.BACK
-
-                    else -> false
-                }
-            }
-            throw AssertionError("Unable to determine lens facing from quick settings")
-        }
-    } finally {
-        if (needReturnFromQuickSettings) {
-            onNodeWithContentDescription(R.string.quick_settings_dropdown_open_description)
-                .assertExists()
-                .performClick()
-        }
-    }
 }
 
-fun getTestUri(directoryPath: String, timeStamp: Long, suffix: String): Uri {
-    return Uri.fromFile(
-        File(
-            directoryPath,
-            "$timeStamp.$suffix"
-        )
+fun getTestUri(directoryPath: String, timeStamp: Long, suffix: String): Uri = Uri.fromFile(
+    File(
+        directoryPath,
+        "$timeStamp.$suffix"
     )
-}
+)
 
 fun deleteFilesInDirAfterTimestamp(
     directoryPath: String,
@@ -112,13 +180,13 @@ fun deleteFilesInDirAfterTimestamp(
     timeStamp: Long
 ): Boolean {
     var hasDeletedFile = false
-    for (file in File(directoryPath).listFiles()) {
+    for (file in File(directoryPath).listFiles() ?: emptyArray()) {
         if (file.lastModified() >= timeStamp) {
             file.delete()
             if (file.exists()) {
-                file.getCanonicalFile().delete()
+                file.canonicalFile.delete()
                 if (file.exists()) {
-                    instrumentation.targetContext.applicationContext.deleteFile(file.getName())
+                    instrumentation.targetContext.applicationContext.deleteFile(file.name)
                 }
             }
             hasDeletedFile = true
@@ -127,23 +195,170 @@ fun deleteFilesInDirAfterTimestamp(
     return hasDeletedFile
 }
 
-fun doesImageFileExist(uri: Uri, prefix: String): Boolean {
-    val file = File(uri.path)
-    if (file.exists()) {
-        val mimeType = URLConnection.guessContentTypeFromName(uri.path)
-        return mimeType != null && mimeType.startsWith(prefix)
+fun doesFileExist(uri: Uri): Boolean = uri.path?.let { File(it) }?.exists() == true
+
+fun doesMediaExist(uri: Uri, prefix: String): Boolean {
+    require(prefix == IMAGE_PREFIX || prefix == VIDEO_PREFIX) { "Uknown prefix: $prefix" }
+    return if (prefix == IMAGE_PREFIX) {
+        doesImageExist(uri)
+    } else {
+        doesVideoExist(uri, prefix)
     }
-    return false
 }
 
-fun getIntent(uri: Uri, action: String): Intent {
+private fun doesImageExist(uri: Uri): Boolean {
+    val bitmap = uri.path?.let { path -> BitmapFactory.decodeFile(path) }
+    val mimeType = URLConnection.guessContentTypeFromName(uri.path)
+    return mimeType != null && mimeType.startsWith(IMAGE_PREFIX) && bitmap != null
+}
+
+private fun doesVideoExist(
+    uri: Uri,
+    prefix: String,
+    checkAudio: Boolean = false,
+    durationMs: Long? = null
+): Boolean {
+    require(prefix == VIDEO_PREFIX) {
+        "doesVideoExist() only works for videos. Can't handle prefix: $prefix"
+    }
+
+    if (!doesFileExist(uri)) {
+        return false
+    }
+    return MediaMetadataRetriever().useAndRelease {
+        it.setDataSource(uri.path)
+
+        it.getMimeType().startsWith(prefix) &&
+            it.hasVideo() &&
+            (!checkAudio || it.hasAudio()) &&
+            (durationMs == null || it.getDurationMs() == durationMs)
+    } == true
+}
+
+fun getSingleImageCaptureIntent(uri: Uri, action: String): Intent {
     val intent = Intent(action)
     intent.setComponent(
         ComponentName(
-            "com.google.jetpackcamera",
-            "com.google.jetpackcamera.MainActivity"
+            COMPONENT_PACKAGE_NAME,
+            COMPONENT_CLASS
         )
     )
     intent.putExtra(MediaStore.EXTRA_OUTPUT, uri)
     return intent
 }
+
+fun getMultipleImageCaptureIntent(uriStrings: ArrayList<String>?, action: String): Intent {
+    val intent = Intent(action)
+    intent.setComponent(
+        ComponentName(
+            COMPONENT_PACKAGE_NAME,
+            COMPONENT_CLASS
+        )
+    )
+    intent.putStringArrayListExtra(MediaStore.EXTRA_OUTPUT, uriStrings)
+    return intent
+}
+
+fun stateDescriptionMatches(expected: String?) = SemanticsMatcher("stateDescription is $expected") {
+    SemanticsProperties.StateDescription in it.config &&
+        (it.config[SemanticsProperties.StateDescription] == expected)
+}
+
+/**
+ * Rule to specify test methods that will have permissions granted prior to running
+ *
+ * @param permissions the permissions to be granted
+ * @param targetTestNames the names of the tests that this rule will apply to
+ */
+class IndividualTestGrantPermissionRule(
+    private val permissions: Array<String>,
+    private val targetTestNames: Array<String>
+) : TestRule {
+    private lateinit var wrappedRule: GrantPermissionRule
+
+    override fun apply(base: Statement, description: Description): Statement {
+        for (targetName in targetTestNames) {
+            if (description.methodName == targetName) {
+                wrappedRule = GrantPermissionRule.grant(*permissions)
+                return wrappedRule.apply(base, description)
+            }
+        }
+        // If no match, return the base statement without granting permissions
+        return base
+    }
+}
+
+// functions for interacting with system permission dialog
+fun UiDevice.askEveryTimeDialog() {
+    if (Build.VERSION.SDK_INT >= 30) {
+        Log.d(TAG, "Searching for Allow Once Button...")
+
+        val askPermission = this.findObjectById(
+            resId = "com.android.permissioncontroller:id/permission_allow_one_time_button"
+        )
+
+        Log.d(TAG, "Clicking Allow Once Button")
+
+        askPermission?.click()
+    }
+}
+
+/**
+ *  Clicks ALLOW option on an open permission dialog
+ */
+fun UiDevice.grantPermissionDialog() {
+    if (Build.VERSION.SDK_INT >= 23) {
+        Log.d(TAG, "Searching for Allow Button...")
+
+        val allowPermission = this.findObjectById(
+            resId = when {
+                Build.VERSION.SDK_INT <= 29 ->
+                    "com.android.packageinstaller:id/permission_allow_button"
+                else ->
+                    "com.android.permissioncontroller:id/permission_allow_foreground_only_button"
+            }
+        )
+        Log.d(TAG, "Clicking Allow Button")
+
+        allowPermission?.click()
+    }
+}
+
+/**
+ * Clicks the DENY option on an open permission dialog
+ */
+fun UiDevice.denyPermissionDialog() {
+    if (Build.VERSION.SDK_INT >= 23) {
+        Log.d(TAG, "Searching for Deny Button...")
+        val denyPermission = this.findObjectById(
+            resId = when {
+                Build.VERSION.SDK_INT <= 29 ->
+                    "com.android.packageinstaller:id/permission_deny_button"
+                else -> "com.android.permissioncontroller:id/permission_deny_button"
+            }
+        )
+        Log.d(TAG, "Clicking Deny Button")
+
+        denyPermission?.click()
+    }
+}
+
+/**
+ * Finds a system button by its resource ID.
+ * fails if not found
+ */
+private fun UiDevice.findObjectById(
+    resId: String,
+    timeout: Long = 10000,
+    shouldFailIfNotFound: Boolean = true
+): UiObject2? {
+    val selector = By.res(resId)
+    return if (!this.wait(Until.hasObject(selector), timeout)) {
+        if (shouldFailIfNotFound) {
+            fail("Could not find object with RESOURCE ID: $resId")
+        }
+        null
+    } else {
+        this.findObject(selector)
+    }
+}
diff --git a/app/src/main/Android.bp b/app/src/main/Android.bp
index 88fec06..fd0a9ce 100644
--- a/app/src/main/Android.bp
+++ b/app/src/main/Android.bp
@@ -22,6 +22,7 @@ java_defaults {
         "jetpack-camera-app_feature_permissions",
         "jetpack-camera-app_feature_preview",
         "jetpack-camera-app_feature_settings",
+        "jetpack-camera-app_feature_postcapture",
     ],
     srcs: [
         "java/**/*.kt",
diff --git a/app/src/main/AndroidManifest.xml b/app/src/main/AndroidManifest.xml
index b86f484..c25f37c 100644
--- a/app/src/main/AndroidManifest.xml
+++ b/app/src/main/AndroidManifest.xml
@@ -15,8 +15,7 @@
   ~ limitations under the License.
   -->
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
-  xmlns:tools="http://schemas.android.com/tools"
-  package="com.google.jetpackcamera">
+    xmlns:tools="http://schemas.android.com/tools" package="com.google.jetpackcamera">
 
     <uses-feature
         android:name="android.hardware.camera"
@@ -33,6 +32,15 @@
     <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"
         android:maxSdkVersion="28"
         tools:ignore="ScopedStorage" />
+    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"
+        android:maxSdkVersion="28"
+        tools:ignore="ScopedStorage" />
+    <uses-permission android:name="android.permission.READ_MEDIA_VIDEO"
+        android:minSdkVersion="33"
+        tools:ignore="SelectedPhotoAccess" />
+    <uses-permission android:name="android.permission.READ_MEDIA_IMAGES"
+        android:minSdkVersion="33"
+        tools:ignore="SelectedPhotoAccess" />
 
 
     <application
@@ -45,8 +53,8 @@
         android:roundIcon="@mipmap/ic_launcher_round"
         android:supportsRtl="true"
         android:theme="@style/Theme.JetpackCamera"
+        android:requestLegacyExternalStorage="true"
         tools:targetApi="33">
-
         <profileable android:shell="true"/>
         <activity
             android:name=".MainActivity"
@@ -61,5 +69,4 @@
             </intent-filter>
         </activity>
     </application>
-
-</manifest>
+</manifest>
\ No newline at end of file
diff --git a/app/src/main/java/com/google/jetpackcamera/MainActivity.kt b/app/src/main/java/com/google/jetpackcamera/MainActivity.kt
index 04dfaf9..803c4d9 100644
--- a/app/src/main/java/com/google/jetpackcamera/MainActivity.kt
+++ b/app/src/main/java/com/google/jetpackcamera/MainActivity.kt
@@ -18,7 +18,6 @@ package com.google.jetpackcamera
 import android.app.Activity
 import android.content.Intent
 import android.content.pm.ActivityInfo
-import android.hardware.Camera
 import android.net.Uri
 import android.os.Build
 import android.os.Bundle
@@ -168,7 +167,8 @@ class MainActivity : Hilt_MainActivity() {
     private fun getStandardMode(): PreviewMode.StandardMode {
         return PreviewMode.StandardMode { event ->
             if (event is PreviewViewModel.ImageCaptureEvent.ImageSaved) {
-                val intent = Intent(Camera.ACTION_NEW_PICTURE)
+                @Suppress("DEPRECATION")
+                val intent = Intent(android.hardware.Camera.ACTION_NEW_PICTURE)
                 intent.setData(event.savedUri)
                 sendBroadcast(intent)
             }
@@ -183,6 +183,19 @@ class MainActivity : Hilt_MainActivity() {
         ) ?: intent?.clipData?.getItemAt(0)?.uri
     }
 
+    private fun getMultipleExternalCaptureUri(): List<Uri>? {
+        val stringUris = intent.getStringArrayListExtra(MediaStore.EXTRA_OUTPUT)
+        if (stringUris.isNullOrEmpty()) {
+            return null
+        } else {
+            val result = mutableListOf<Uri>()
+            for (string in stringUris) {
+                result.add(Uri.parse(string))
+            }
+            return result
+        }
+    }
+
     private fun getPreviewMode(): PreviewMode {
         return intent?.action?.let { action ->
             when (action) {
@@ -210,6 +223,34 @@ class MainActivity : Hilt_MainActivity() {
                         }
                     }
 
+                MediaStore.INTENT_ACTION_STILL_IMAGE_CAMERA -> {
+                    val uriList: List<Uri>? = getMultipleExternalCaptureUri()
+                    val pictureTakenUriList: ArrayList<String?> = arrayListOf()
+                    PreviewMode.ExternalMultipleImageCaptureMode(
+                        uriList
+                    ) { event: PreviewViewModel.ImageCaptureEvent, uriIndex: Int ->
+                        Log.d(TAG, "onMultipleImageCapture, event: $event")
+                        if (uriList == null) {
+                            when (event) {
+                                is PreviewViewModel.ImageCaptureEvent.ImageSaved ->
+                                    pictureTakenUriList.add(event.savedUri.toString())
+                                is PreviewViewModel.ImageCaptureEvent.ImageCaptureError ->
+                                    pictureTakenUriList.add(event.exception.toString())
+                            }
+                            val resultIntent = Intent()
+                            resultIntent.putStringArrayListExtra(
+                                MediaStore.EXTRA_OUTPUT,
+                                pictureTakenUriList
+                            )
+                            setResult(RESULT_OK, resultIntent)
+                        } else if (uriIndex == uriList.size - 1) {
+                            setResult(RESULT_OK, Intent())
+                            Log.d(TAG, "onMultipleImageCapture, finish()")
+                            finish()
+                        }
+                    }
+                }
+
                 else -> {
                     Log.w(TAG, "Ignoring external intent with unknown action.")
                     getStandardMode()
diff --git a/app/src/main/java/com/google/jetpackcamera/ui/JcaApp.kt b/app/src/main/java/com/google/jetpackcamera/ui/JcaApp.kt
index 1e16d5b..e66f510 100644
--- a/app/src/main/java/com/google/jetpackcamera/ui/JcaApp.kt
+++ b/app/src/main/java/com/google/jetpackcamera/ui/JcaApp.kt
@@ -16,23 +16,34 @@
 package com.google.jetpackcamera.ui
 
 import android.Manifest
+import android.net.Uri
+import androidx.compose.animation.AnimatedContentTransitionScope
+import androidx.compose.animation.core.EaseIn
+import androidx.compose.animation.core.EaseOut
+import androidx.compose.animation.core.LinearEasing
+import androidx.compose.animation.core.tween
+import androidx.compose.animation.fadeIn
 import androidx.compose.runtime.Composable
 import androidx.compose.runtime.LaunchedEffect
 import androidx.compose.ui.Modifier
 import androidx.navigation.NavHostController
+import androidx.navigation.NavType
 import androidx.navigation.compose.NavHost
 import androidx.navigation.compose.composable
 import androidx.navigation.compose.rememberNavController
+import androidx.navigation.navArgument
 import com.google.accompanist.permissions.ExperimentalPermissionsApi
 import com.google.accompanist.permissions.isGranted
 import com.google.accompanist.permissions.rememberMultiplePermissionsState
 import com.google.jetpackcamera.BuildConfig
+import com.google.jetpackcamera.feature.postcapture.PostCaptureScreen
 import com.google.jetpackcamera.feature.preview.PreviewMode
 import com.google.jetpackcamera.feature.preview.PreviewScreen
 import com.google.jetpackcamera.permissions.PermissionsScreen
 import com.google.jetpackcamera.settings.SettingsScreen
 import com.google.jetpackcamera.settings.VersionInfoHolder
 import com.google.jetpackcamera.ui.Routes.PERMISSIONS_ROUTE
+import com.google.jetpackcamera.ui.Routes.POST_CAPTURE_ROUTE
 import com.google.jetpackcamera.ui.Routes.PREVIEW_ROUTE
 import com.google.jetpackcamera.ui.Routes.SETTINGS_ROUTE
 
@@ -75,17 +86,19 @@ private fun JetpackCameraNavHost(
         composable(PERMISSIONS_ROUTE) {
             PermissionsScreen(
                 shouldRequestAudioPermission = previewMode is PreviewMode.StandardMode,
-                onNavigateToPreview = {
+                onAllPermissionsGranted = {
+                    // Pop off the permissions screen
                     navController.navigate(PREVIEW_ROUTE) {
-                        // cannot navigate back to permissions after leaving
-                        popUpTo(0)
+                        popUpTo(PERMISSIONS_ROUTE) {
+                            inclusive = true
+                        }
                     }
                 },
                 openAppSettings = onOpenAppSettings
             )
         }
 
-        composable(PREVIEW_ROUTE) {
+        composable(route = PREVIEW_ROUTE, enterTransition = { fadeIn() }) {
             val permissionStates = rememberMultiplePermissionsState(
                 permissions = listOf(
                     Manifest.permission.CAMERA,
@@ -95,21 +108,44 @@ private fun JetpackCameraNavHost(
             // Automatically navigate to permissions screen when camera permission revoked
             LaunchedEffect(key1 = permissionStates.permissions[0].status) {
                 if (!permissionStates.permissions[0].status.isGranted) {
+                    // Pop off the preview screen
                     navController.navigate(PERMISSIONS_ROUTE) {
-                        // cannot navigate back to preview
-                        popUpTo(0)
+                        popUpTo(PREVIEW_ROUTE) {
+                            inclusive = true
+                        }
                     }
                 }
             }
             PreviewScreen(
                 onNavigateToSettings = { navController.navigate(SETTINGS_ROUTE) },
+                onNavigateToPostCapture = { imageUri ->
+                    navController.navigate(
+                        "$POST_CAPTURE_ROUTE?imageUri=${Uri.encode(imageUri.toString())}"
+                    )
+                },
                 onRequestWindowColorMode = onRequestWindowColorMode,
                 onFirstFrameCaptureCompleted = onFirstFrameCaptureCompleted,
                 previewMode = previewMode,
                 isDebugMode = isDebugMode
             )
         }
-        composable(SETTINGS_ROUTE) {
+        composable(
+            route = SETTINGS_ROUTE,
+            enterTransition = {
+                fadeIn(
+                    animationSpec = tween(easing = LinearEasing)
+                ) + slideIntoContainer(
+                    animationSpec = tween(easing = EaseIn),
+                    towards = AnimatedContentTransitionScope.SlideDirection.Start
+                )
+            },
+            exitTransition = {
+                slideOutOfContainer(
+                    animationSpec = tween(easing = EaseOut),
+                    towards = AnimatedContentTransitionScope.SlideDirection.End
+                )
+            }
+        ) {
             SettingsScreen(
                 versionInfo = VersionInfoHolder(
                     versionName = BuildConfig.VERSION_NAME,
@@ -118,5 +154,28 @@ private fun JetpackCameraNavHost(
                 onNavigateBack = { navController.popBackStack() }
             )
         }
+
+        composable(
+            "$POST_CAPTURE_ROUTE?imageUri={imageUri}",
+            arguments = listOf(
+                navArgument("imageUri") {
+                    type = NavType.StringType
+                    defaultValue = ""
+                }
+            )
+        ) { backStackEntry ->
+            val imageUriString = backStackEntry.arguments?.getString("imageUri")
+
+            val imageUri = if (!imageUriString.isNullOrEmpty()) {
+                Uri.parse(
+                    imageUriString
+                )
+            } else {
+                null
+            }
+            PostCaptureScreen(
+                imageUri = imageUri
+            )
+        }
     }
 }
diff --git a/app/src/main/java/com/google/jetpackcamera/ui/Routes.kt b/app/src/main/java/com/google/jetpackcamera/ui/Routes.kt
index 1373bcc..f5c858a 100644
--- a/app/src/main/java/com/google/jetpackcamera/ui/Routes.kt
+++ b/app/src/main/java/com/google/jetpackcamera/ui/Routes.kt
@@ -19,4 +19,5 @@ object Routes {
     const val PREVIEW_ROUTE = "preview"
     const val SETTINGS_ROUTE = "settings"
     const val PERMISSIONS_ROUTE = "permissions"
+    const val POST_CAPTURE_ROUTE = "postCapture"
 }
diff --git a/benchmark/build.gradle.kts b/benchmark/build.gradle.kts
index a923cc4..0c949e1 100644
--- a/benchmark/build.gradle.kts
+++ b/benchmark/build.gradle.kts
@@ -22,7 +22,6 @@ plugins {
 android {
     namespace = "com.google.jetpackcamera.benchmark"
     compileSdk = libs.versions.compileSdk.get().toInt()
-    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     compileOptions {
         sourceCompatibility = JavaVersion.VERSION_1_8
@@ -61,11 +60,6 @@ android {
         create("stable") {
             dimension = "flavor"
         }
-
-        create("preview") {
-            dimension = "flavor"
-            targetSdkPreview = libs.versions.targetSdkPreview.get()
-        }
     }
 
     targetProjectPath = ":app"
diff --git a/copy.bara.sky b/copy.bara.sky
new file mode 100644
index 0000000..a4b062d
--- /dev/null
+++ b/copy.bara.sky
@@ -0,0 +1,122 @@
+"""Copybara config to merge Jetpack Camera App code from upstream-main to main."""
+
+core.workflow(
+  name = "jetpack_camera_app_copy_upstream_to_main",
+  origin = git.origin(
+    url = "https://android.googlesource.com/platform/external/jetpack-camera-app",
+    ref = "upstream-main"
+  ),
+  destination = git.gerrit_destination(
+    url = "https://android.googlesource.com/platform/external/jetpack-camera-app",
+    fetch = "main",
+    reviewers = [
+        "davidjia@google.com",
+        "trevormcguire@google.com",
+        "kcrevecoeur@google.com",
+        "yasith@google.com"
+    ]
+  ),
+  origin_files = glob(
+    include = ["**"],
+    exclude = [
+      "OWNERS",
+      "**/OWNERS",
+    ],
+  ),
+  destination_files = glob(
+    include = ["**"],
+    exclude = [
+      "copy.bara.sky",
+      "METADATA",
+      "MODULE_LICENSE_APACHE2",
+      "OWNERS",
+      "Android.bp",
+      "**/Android.bp",
+      "**/androidTest/AndroidManifest.xml",
+      "**/test/AndroidManifest.xml",
+      "**/AndroidTest.xml",
+      "TEST_MAPPING",
+      "app/src/main/java/com/google/jetpackcamera/BuildConfig.kt"
+    ],
+  ),
+  authoring = authoring.pass_thru(
+        "JCA Team <mdb.jca-core-team@google.com>"
+    ),
+  mode = "SQUASH",
+  transformations = [
+    core.replace(
+        before = 'xmlns:tools="http://schemas.android.com/tools"',
+        after = 'xmlns:tools="http://schemas.android.com/tools" package="com.google.jetpackcamera"',
+        paths = glob(["app/src/main/AndroidManifest.xml"])
+    ),
+    core.replace(
+        before = 'android:name=".JetpackCameraApplication"',
+        after = 'android:name="JetpackCameraApplication"',
+        paths = glob(["app/src/main/AndroidManifest.xml"])
+    ),
+    core.replace(
+        before = 'xmlns:tools="http://schemas.android.com/tools"',
+        after = 'xmlns:tools="http://schemas.android.com/tools" package="com.google.jetpackcamera.core.camera"',
+        paths = glob(["core/camera/src/main/AndroidManifest.xml"])
+    ),
+    core.replace(
+        before = '<manifest>',
+        after = '<manifest package="com.google.jetpackcamera.core.common">',
+        paths = glob(["core/common/src/main/AndroidManifest.xml"])
+    ),
+    core.replace(
+        before = '<manifest>',
+        after = '<manifest package="com.google.jetpackcamera.data.settings">',
+        paths = glob(["data/settings/src/main/AndroidManifest.xml"])
+    ),
+    core.replace(
+        before = '<manifest>',
+        after = '<manifest package="com.google.jetpackcamera.feature.preview">',
+        paths = glob(["feature/preview/src/main/AndroidManifest.xml"])
+    ),
+    core.replace(
+        before = 'xmlns:android="http://schemas.android.com/apk/res/android"',
+        after = 'xmlns:android="http://schemas.android.com/apk/res/android" package="com.google.jetpackcamera.permissions"',
+        paths = glob(["feature/permissions/src/main/AndroidManifest.xml"])
+    ),
+    core.replace(
+        before = 'xmlns:android="http://schemas.android.com/apk/res/android"',
+        after = 'xmlns:android="http://schemas.android.com/apk/res/android" package="com.google.jetpackcamera.settings"',
+        paths = glob(["feature/settings/src/main/AndroidManifest.xml"])
+    ),
+    core.replace(
+        before = '@HiltAndroidApp',
+        after = '@HiltAndroidApp(Application::class)',
+    ),
+    core.replace(
+        before = 'class JetpackCameraApplication : Application()',
+        after = 'class JetpackCameraApplication : Hilt_JetpackCameraApplication()',
+    ),
+    core.replace(
+        before = '@AndroidEntryPoint',
+        after = '@AndroidEntryPoint(ComponentActivity::class)',
+    ),
+    core.replace(
+        before = 'class MainActivity : ComponentActivity() {',
+        after = 'class MainActivity : Hilt_MainActivity() {',
+    )],
+)
+
+service.migration(
+        migration_name = "jetpack_camera_app_copy_upstream_to_main",
+        owner_mdb = "jca-core-team",
+        contact_email = "mdb.jca-core-team@google.com",
+        notifications = service.notifications(
+            on_error = [
+                service.email(address = "trevormcguire@google.com"),
+                service.email(address = "davidjia@google.com"),
+                service.email(address = "kcrevecoeur@google.com"),
+                service.email(address = "yasith@google.com"),
+            ],
+        ),
+        state = "ACTIVE",
+        flags = {
+            "--ignore-noop": [],
+        },
+        triggering = "EVENT_BASED",
+    )
diff --git a/core/camera/Android.bp b/core/camera/Android.bp
index b5a8c62..ddd01b9 100644
--- a/core/camera/Android.bp
+++ b/core/camera/Android.bp
@@ -18,7 +18,7 @@ android_library {
         "jetpack-camera-app_data_settings",
         "jetpack-camera-app_core_common",
     ],
-    sdk_version: "34",
+    sdk_version: "35",
     min_sdk_version: "21",
     manifest: "src/main/AndroidManifest.xml",
     kotlincflags: [
diff --git a/core/camera/build.gradle.kts b/core/camera/build.gradle.kts
index cc471c3..3b07796 100644
--- a/core/camera/build.gradle.kts
+++ b/core/camera/build.gradle.kts
@@ -24,7 +24,6 @@ plugins {
 android {
     namespace = "com.google.jetpackcamera.core.camera"
     compileSdk = libs.versions.compileSdk.get().toInt()
-    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     defaultConfig {
         minSdk = libs.versions.minSdk.get().toInt()
@@ -70,10 +69,22 @@ android {
             dimension = "flavor"
             isDefault = true
         }
+    }
 
-        create("preview") {
-            dimension = "flavor"
-            targetSdkPreview = libs.versions.targetSdkPreview.get()
+    @Suppress("UnstableApiUsage")
+    testOptions {
+        managedDevices {
+            localDevices {
+                create("pixel2Api28") {
+                    device = "Pixel 2"
+                    apiLevel = 28
+                }
+                create("pixel8Api34") {
+                    device = "Pixel 8"
+                    apiLevel = 34
+                    systemImageSource = "aosp_atd"
+                }
+            }
         }
     }
 
@@ -98,8 +109,8 @@ dependencies {
     testImplementation(libs.mockito.core)
     androidTestImplementation(libs.androidx.junit)
     androidTestImplementation(libs.androidx.espresso.core)
+    androidTestImplementation(libs.androidx.rules)
     androidTestImplementation(libs.kotlinx.coroutines.test)
-    androidTestImplementation(libs.rules)
     androidTestImplementation(libs.truth)
 
     // Futures
diff --git a/core/camera/src/androidTest/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCaseTest.kt b/core/camera/src/androidTest/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCaseTest.kt
index 5cd9d75..02335de 100644
--- a/core/camera/src/androidTest/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCaseTest.kt
+++ b/core/camera/src/androidTest/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCaseTest.kt
@@ -26,7 +26,6 @@ import androidx.test.filters.LargeTest
 import androidx.test.platform.app.InstrumentationRegistry
 import androidx.test.rule.GrantPermissionRule
 import com.google.jetpackcamera.core.camera.CameraUseCase.OnVideoRecordEvent.OnVideoRecordError
-import com.google.jetpackcamera.core.camera.CameraUseCase.OnVideoRecordEvent.OnVideoRecordStatus
 import com.google.jetpackcamera.core.camera.CameraUseCase.OnVideoRecordEvent.OnVideoRecorded
 import com.google.jetpackcamera.core.camera.utils.APP_REQUIRED_PERMISSIONS
 import com.google.jetpackcamera.settings.ConstraintsRepository
@@ -35,8 +34,11 @@ import com.google.jetpackcamera.settings.SettableConstraintsRepositoryImpl
 import com.google.jetpackcamera.settings.model.CameraAppSettings
 import com.google.jetpackcamera.settings.model.DEFAULT_CAMERA_APP_SETTINGS
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.Illuminant
 import com.google.jetpackcamera.settings.model.LensFacing
 import java.io.File
+import kotlin.time.DurationUnit
+import kotlin.time.toDuration
 import kotlinx.coroutines.CompletableDeferred
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.Dispatchers
@@ -46,8 +48,10 @@ import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.flow.first
 import kotlinx.coroutines.flow.map
 import kotlinx.coroutines.flow.produceIn
+import kotlinx.coroutines.flow.transform
 import kotlinx.coroutines.launch
 import kotlinx.coroutines.runBlocking
+import kotlinx.coroutines.withTimeout
 import kotlinx.coroutines.withTimeoutOrNull
 import org.junit.After
 import org.junit.Assert.fail
@@ -62,9 +66,9 @@ import org.junit.runner.RunWith
 class CameraXCameraUseCaseTest {
 
     companion object {
-        private const val STATUS_VERIFY_COUNT = 5
         private const val GENERAL_TIMEOUT_MS = 3_000L
-        private const val STATUS_VERIFY_TIMEOUT_MS = 10_000L
+        private const val RECORDING_TIMEOUT_MS = 10_000L
+        private const val RECORDING_START_DURATION_MS = 500L
     }
 
     @get:Rule
@@ -95,16 +99,20 @@ class CameraXCameraUseCaseTest {
         cameraUseCase.runCameraOnMain()
 
         // Act.
-        val recordEvent = cameraUseCase.startRecordingAndGetEvents()
-
-        // Assert.
-        recordEvent.onRecordStatus.await(STATUS_VERIFY_TIMEOUT_MS)
+        val recordingComplete = CompletableDeferred<Unit>()
+        cameraUseCase.startRecording {
+            when (it) {
+                is OnVideoRecorded -> {
+                    recordingComplete.complete(Unit)
+                }
+                is OnVideoRecordError -> recordingComplete.completeExceptionally(it.error)
+            }
+        }
 
-        // Act.
         cameraUseCase.stopVideoRecording()
 
         // Assert.
-        recordEvent.onRecorded.await()
+        recordingComplete.await()
     }
 
     @Test
@@ -127,20 +135,27 @@ class CameraXCameraUseCaseTest {
         torchEnabled.awaitValue(false)
 
         // Act: Start recording with FlashMode.ON
+        val recordingComplete = CompletableDeferred<Unit>()
         cameraUseCase.setFlashMode(FlashMode.ON)
-        val recordEvent = cameraUseCase.startRecordingAndGetEvents()
+        cameraUseCase.startRecording {
+            when (it) {
+                is OnVideoRecorded -> {
+                    recordingComplete.complete(Unit)
+                }
+                is OnVideoRecordError -> recordingComplete.completeExceptionally(it.error)
+            }
+        }
 
         // Assert: Torch enabled transitions to true.
         torchEnabled.awaitValue(true)
 
-        // Act: Ensure enough data is received and stop recording.
-        recordEvent.onRecordStatus.await(STATUS_VERIFY_TIMEOUT_MS)
         cameraUseCase.stopVideoRecording()
 
         // Assert: Torch enabled transitions to false.
         torchEnabled.awaitValue(false)
 
         // Clean-up.
+        recordingComplete.await()
         torchEnabled.cancel()
     }
 
@@ -148,20 +163,15 @@ class CameraXCameraUseCaseTest {
         appSettings: CameraAppSettings = DEFAULT_CAMERA_APP_SETTINGS,
         constraintsRepository: SettableConstraintsRepository = SettableConstraintsRepositoryImpl()
     ) = CameraXCameraUseCase(
-        application,
-        useCaseScope,
-        Dispatchers.Default,
-        constraintsRepository
+        application = application,
+        defaultDispatcher = Dispatchers.Default,
+        iODispatcher = Dispatchers.IO,
+        constraintsRepository = constraintsRepository
     ).apply {
-        initialize(appSettings, CameraUseCase.UseCaseMode.STANDARD)
+        initialize(appSettings) {}
         providePreviewSurface()
     }
 
-    private data class RecordEvents(
-        val onRecorded: CompletableDeferred<Unit>,
-        val onRecordStatus: CompletableDeferred<Unit>
-    )
-
     private suspend fun CompletableDeferred<*>.await(timeoutMs: Long = GENERAL_TIMEOUT_MS) =
         withTimeoutOrNull(timeoutMs) {
             await()
@@ -177,31 +187,38 @@ class CameraXCameraUseCaseTest {
         }
     } ?: fail("Timeout while waiting for expected value: $expectedValue")
 
-    private suspend fun CameraXCameraUseCase.startRecordingAndGetEvents(
-        statusVerifyCount: Int = STATUS_VERIFY_COUNT
-    ): RecordEvents {
-        val onRecorded = CompletableDeferred<Unit>()
-        val onRecordStatus = CompletableDeferred<Unit>()
-        var statusCount = 0
-        startVideoRecording(null, false) {
-            when (it) {
-                is OnVideoRecorded -> {
-                    val videoUri = it.savedUri
-                    if (videoUri != Uri.EMPTY) {
-                        videosToDelete.add(videoUri)
-                    }
-                    onRecorded.complete(Unit)
+    private suspend fun CameraXCameraUseCase.startRecording(
+        onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
+    ) {
+        // Start recording
+        startVideoRecording(
+            videoCaptureUri = null,
+            shouldUseUri = false
+        ) { event ->
+            // Track files that need to be deleted
+            if (event is OnVideoRecorded) {
+                val videoUri = event.savedUri
+                if (videoUri != Uri.EMPTY) {
+                    videosToDelete.add(videoUri)
                 }
-                is OnVideoRecordError -> onRecorded.complete(Unit)
-                is OnVideoRecordStatus -> {
-                    statusCount++
-                    if (statusCount == statusVerifyCount) {
-                        onRecordStatus.complete(Unit)
-                    }
+            }
+
+            // Forward event to provided callback
+            onVideoRecord(event)
+        }
+
+        // Wait for recording duration to reach start duration to consider it started
+        withTimeout(RECORDING_TIMEOUT_MS) {
+            getCurrentCameraState().transform { cameraState ->
+                (cameraState.videoRecordingState as? VideoRecordingState.Active)?.let {
+                    emit(
+                        it.elapsedTimeNanos.toDuration(DurationUnit.NANOSECONDS).inWholeMilliseconds
+                    )
                 }
+            }.first { elapsedTimeMs ->
+                elapsedTimeMs >= RECORDING_START_DURATION_MS
             }
         }
-        return RecordEvents(onRecorded, onRecordStatus)
     }
 
     private fun CameraXCameraUseCase.providePreviewSurface() {
@@ -218,13 +235,14 @@ class CameraXCameraUseCaseTest {
         }
     }
 
-    private suspend fun CameraXCameraUseCase.runCameraOnMain() {
+    private fun CameraXCameraUseCase.runCameraOnMain() {
         useCaseScope.launch(Dispatchers.Main) { runCamera() }
         instrumentation.waitForIdleSync()
     }
 
     private suspend fun ConstraintsRepository.hasFlashUnit(lensFacing: LensFacing): Boolean =
-        systemConstraints.first()!!.perLensConstraints[lensFacing]!!.hasFlashUnit
+        Illuminant.FLASH_UNIT in
+            systemConstraints.first()!!.perLensConstraints[lensFacing]!!.supportedIlluminants
 
     private fun deleteVideos() {
         for (uri in videosToDelete) {
diff --git a/core/camera/src/main/AndroidManifest.xml b/core/camera/src/main/AndroidManifest.xml
index 150f8d8..d4de569 100644
--- a/core/camera/src/main/AndroidManifest.xml
+++ b/core/camera/src/main/AndroidManifest.xml
@@ -1,6 +1,6 @@
 <?xml version="1.0" encoding="utf-8"?>
 <!--
-  ~ Copyright (C) 2024 The Android Open Source Project
+  ~ Copyright (C) 2023 The Android Open Source Project
   ~
   ~ Licensed under the Apache License, Version 2.0 (the "License");
   ~ you may not use this file except in compliance with the License.
@@ -15,11 +15,10 @@
   ~ limitations under the License.
   -->
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    xmlns:tools="http://schemas.android.com/tools"
-    package="com.google.jetpackcamera.core.camera">
+    xmlns:tools="http://schemas.android.com/tools" package="com.google.jetpackcamera.core.camera">
     <uses-permission android:name="android.permission.CAMERA" />
     <uses-permission android:name="android.permission.RECORD_AUDIO" />
     <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"
         android:maxSdkVersion="28"
         tools:ignore="ScopedStorage" />
-</manifest>
+</manifest>
\ No newline at end of file
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraExt.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraExt.kt
index 8af0d9e..fc415fb 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraExt.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraExt.kt
@@ -15,8 +15,8 @@
  */
 package com.google.jetpackcamera.core.camera
 
-import android.annotation.SuppressLint
 import android.hardware.camera2.CameraCharacteristics
+import android.hardware.camera2.CameraMetadata
 import androidx.annotation.OptIn
 import androidx.camera.camera2.interop.Camera2CameraInfo
 import androidx.camera.camera2.interop.ExperimentalCamera2Interop
@@ -27,11 +27,18 @@ import androidx.camera.core.ImageCapture
 import androidx.camera.core.Preview
 import androidx.camera.core.UseCase
 import androidx.camera.core.UseCaseGroup
+import androidx.camera.video.Quality
 import androidx.camera.video.Recorder
 import androidx.camera.video.VideoCapture
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
+import com.google.jetpackcamera.settings.model.VideoQuality
+import com.google.jetpackcamera.settings.model.VideoQuality.FHD
+import com.google.jetpackcamera.settings.model.VideoQuality.HD
+import com.google.jetpackcamera.settings.model.VideoQuality.SD
+import com.google.jetpackcamera.settings.model.VideoQuality.UHD
+import com.google.jetpackcamera.settings.model.VideoQuality.UNSPECIFIED
 
 val CameraInfo.appLensFacing: LensFacing
     get() = when (this.lensFacing) {
@@ -64,15 +71,6 @@ fun LensFacing.toCameraSelector(): CameraSelector = when (this) {
     LensFacing.BACK -> CameraSelector.DEFAULT_BACK_CAMERA
 }
 
-@SuppressLint("RestrictedApi")
-fun CameraSelector.toAppLensFacing(): LensFacing = when (this.lensFacing) {
-    CameraSelector.LENS_FACING_FRONT -> LensFacing.FRONT
-    CameraSelector.LENS_FACING_BACK -> LensFacing.BACK
-    else -> throw IllegalArgumentException(
-        "Unknown CameraSelector -> LensFacing mapping. [CameraSelector: $this]"
-    )
-}
-
 val CameraInfo.sensorLandscapeRatio: Float
     @OptIn(ExperimentalCamera2Interop::class)
     get() = Camera2CameraInfo.from(this)
@@ -94,6 +92,26 @@ fun Int.toAppImageFormat(): ImageOutputFormat? {
     }
 }
 
+fun VideoQuality.toQuality(): Quality? {
+    return when (this) {
+        SD -> Quality.SD
+        HD -> Quality.HD
+        FHD -> Quality.FHD
+        UHD -> Quality.UHD
+        UNSPECIFIED -> null
+    }
+}
+
+fun Quality.toVideoQuality(): VideoQuality {
+    return when (this) {
+        Quality.SD -> SD
+        Quality.HD -> HD
+        Quality.FHD -> FHD
+        Quality.UHD -> UHD
+        else -> UNSPECIFIED
+    }
+}
+
 /**
  * Checks if preview stabilization is supported by the device.
  *
@@ -108,6 +126,23 @@ val CameraInfo.isPreviewStabilizationSupported: Boolean
 val CameraInfo.isVideoStabilizationSupported: Boolean
     get() = Recorder.getVideoCapabilities(this).isStabilizationSupported
 
+/** Checks if optical image stabilization (OIS) is supported by the device. */
+val CameraInfo.isOpticalStabilizationSupported: Boolean
+    @OptIn(ExperimentalCamera2Interop::class)
+    get() = Camera2CameraInfo.from(this)
+        .getCameraCharacteristic(CameraCharacteristics.LENS_INFO_AVAILABLE_OPTICAL_STABILIZATION)
+        ?.contains(
+            CameraMetadata.LENS_OPTICAL_STABILIZATION_MODE_ON
+        ) ?: false
+
+val CameraInfo.isLowLightBoostSupported: Boolean
+    @OptIn(ExperimentalCamera2Interop::class)
+    get() = Camera2CameraInfo.from(this)
+        .getCameraCharacteristic(CameraCharacteristics.CONTROL_AE_AVAILABLE_MODES)
+        ?.contains(
+            CameraMetadata.CONTROL_AE_MODE_ON_LOW_LIGHT_BOOST_BRIGHTNESS_PRIORITY
+        ) ?: false
+
 fun CameraInfo.filterSupportedFixedFrameRates(desired: Set<Int>): Set<Int> {
     return buildSet {
         this@filterSupportedFixedFrameRates.supportedFrameRateRanges.forEach { e ->
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt
index b2b446e..08103b6 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSession.kt
@@ -19,7 +19,9 @@ import android.Manifest
 import android.content.ContentValues
 import android.content.Context
 import android.content.pm.PackageManager
+import android.graphics.Rect
 import android.hardware.camera2.CameraCaptureSession
+import android.hardware.camera2.CameraMetadata
 import android.hardware.camera2.CaptureRequest
 import android.hardware.camera2.CaptureResult
 import android.hardware.camera2.TotalCaptureResult
@@ -29,15 +31,17 @@ import android.os.SystemClock
 import android.provider.MediaStore
 import android.util.Log
 import android.util.Range
+import android.util.Size
 import androidx.annotation.OptIn
+import androidx.camera.camera2.interop.Camera2CameraControl
 import androidx.camera.camera2.interop.Camera2CameraInfo
 import androidx.camera.camera2.interop.Camera2Interop
+import androidx.camera.camera2.interop.CaptureRequestOptions
 import androidx.camera.camera2.interop.ExperimentalCamera2Interop
 import androidx.camera.core.Camera
 import androidx.camera.core.CameraControl
 import androidx.camera.core.CameraEffect
 import androidx.camera.core.CameraInfo
-import androidx.camera.core.CameraSelector
 import androidx.camera.core.FocusMeteringAction
 import androidx.camera.core.ImageCapture
 import androidx.camera.core.Preview
@@ -47,14 +51,18 @@ import androidx.camera.core.UseCaseGroup
 import androidx.camera.core.ViewPort
 import androidx.camera.core.resolutionselector.AspectRatioStrategy
 import androidx.camera.core.resolutionselector.ResolutionSelector
+import androidx.camera.video.FallbackStrategy
+import androidx.camera.video.FileDescriptorOutputOptions
 import androidx.camera.video.FileOutputOptions
 import androidx.camera.video.MediaStoreOutputOptions
+import androidx.camera.video.PendingRecording
+import androidx.camera.video.QualitySelector
 import androidx.camera.video.Recorder
 import androidx.camera.video.Recording
 import androidx.camera.video.VideoCapture
 import androidx.camera.video.VideoRecordEvent
+import androidx.camera.video.VideoRecordEvent.Finalize.ERROR_DURATION_LIMIT_REACHED
 import androidx.camera.video.VideoRecordEvent.Finalize.ERROR_NONE
-import androidx.concurrent.futures.await
 import androidx.core.content.ContextCompat
 import androidx.core.content.ContextCompat.checkSelfPermission
 import androidx.lifecycle.asFlow
@@ -66,99 +74,160 @@ import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.LowLightBoostState
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.StreamConfig
+import com.google.jetpackcamera.settings.model.VideoQuality
+import com.google.jetpackcamera.settings.model.VideoQuality.FHD
+import com.google.jetpackcamera.settings.model.VideoQuality.HD
+import com.google.jetpackcamera.settings.model.VideoQuality.SD
+import com.google.jetpackcamera.settings.model.VideoQuality.UHD
 import java.io.File
 import java.util.Date
 import java.util.concurrent.Executor
 import kotlin.coroutines.ContinuationInterceptor
 import kotlin.math.abs
+import kotlin.time.Duration.Companion.milliseconds
 import kotlinx.atomicfu.atomic
 import kotlinx.coroutines.CoroutineDispatcher
-import kotlinx.coroutines.CoroutineStart
-import kotlinx.coroutines.Job
 import kotlinx.coroutines.asExecutor
+import kotlinx.coroutines.channels.Channel
 import kotlinx.coroutines.coroutineScope
 import kotlinx.coroutines.currentCoroutineContext
 import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.collectLatest
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.flow.first
 import kotlinx.coroutines.flow.map
-import kotlinx.coroutines.flow.onCompletion
 import kotlinx.coroutines.flow.update
 import kotlinx.coroutines.launch
 
 private const val TAG = "CameraSession"
+private val QUALITY_RANGE_MAP = mapOf(
+    UHD to Range.create(2160, 4319),
+    FHD to Range.create(1080, 1439),
+    HD to Range.create(720, 1079),
+    SD to Range.create(241, 719)
+)
 
 context(CameraSessionContext)
 internal suspend fun runSingleCameraSession(
     sessionSettings: PerpetualSessionSettings.SingleCamera,
-    useCaseMode: CameraUseCase.UseCaseMode,
     // TODO(tm): ImageCapture should go through an event channel like VideoCapture
     onImageCaptureCreated: (ImageCapture) -> Unit = {}
 ) = coroutineScope {
-    val lensFacing = sessionSettings.cameraInfo.appLensFacing
-    Log.d(TAG, "Starting new single camera session for $lensFacing")
-
-    val initialTransientSettings = transientSettings
-        .filterNotNull()
-        .first()
-
-    val useCaseGroup = createUseCaseGroup(
-        cameraInfo = sessionSettings.cameraInfo,
-        initialTransientSettings = initialTransientSettings,
-        stabilizePreviewMode = sessionSettings.stabilizePreviewMode,
-        stabilizeVideoMode = sessionSettings.stabilizeVideoMode,
-        aspectRatio = sessionSettings.aspectRatio,
-        targetFrameRate = sessionSettings.targetFrameRate,
-        dynamicRange = sessionSettings.dynamicRange,
-        imageFormat = sessionSettings.imageFormat,
-        useCaseMode = useCaseMode,
-        effect = when (sessionSettings.captureMode) {
-            CaptureMode.SINGLE_STREAM -> SingleSurfaceForcingEffect(this@coroutineScope)
-            CaptureMode.MULTI_STREAM -> null
-        }
-    ).apply {
-        getImageCapture()?.let(onImageCaptureCreated)
+    Log.d(TAG, "Starting new single camera session")
+
+    val initialCameraSelector = transientSettings.filterNotNull().first()
+        .primaryLensFacing.toCameraSelector()
+
+    val videoCaptureUseCase = when (sessionSettings.captureMode) {
+        CaptureMode.STANDARD, CaptureMode.VIDEO_ONLY ->
+            createVideoUseCase(
+                cameraProvider.getCameraInfo(initialCameraSelector),
+                sessionSettings.aspectRatio,
+                sessionSettings.targetFrameRate,
+                sessionSettings.stabilizationMode,
+                sessionSettings.dynamicRange,
+                sessionSettings.videoQuality,
+                backgroundDispatcher
+            )
+        else -> {
+            null
+        }
     }
 
-    cameraProvider.runWith(sessionSettings.cameraInfo.cameraSelector, useCaseGroup) { camera ->
-        Log.d(TAG, "Camera session started")
+    launch {
+        processVideoControlEvents(
+            videoCaptureUseCase,
+            captureTypeSuffix = when (sessionSettings.streamConfig) {
+                StreamConfig.MULTI_STREAM -> "MultiStream"
+                StreamConfig.SINGLE_STREAM -> "SingleStream"
+            }
+        )
+    }
 
-        launch {
-            processFocusMeteringEvents(camera.cameraControl)
+    transientSettings.filterNotNull().distinctUntilChanged { old, new ->
+        old.primaryLensFacing == new.primaryLensFacing
+    }.collectLatest { currentTransientSettings ->
+        cameraProvider.unbindAll()
+        val currentCameraSelector = currentTransientSettings.primaryLensFacing.toCameraSelector()
+        val useCaseGroup = createUseCaseGroup(
+            cameraInfo = cameraProvider.getCameraInfo(currentCameraSelector),
+            videoCaptureUseCase = videoCaptureUseCase,
+            initialTransientSettings = currentTransientSettings,
+            stabilizationMode = sessionSettings.stabilizationMode,
+            aspectRatio = sessionSettings.aspectRatio,
+            dynamicRange = sessionSettings.dynamicRange,
+            imageFormat = sessionSettings.imageFormat,
+            captureMode = sessionSettings.captureMode,
+            effect = when (sessionSettings.streamConfig) {
+                StreamConfig.SINGLE_STREAM -> SingleSurfaceForcingEffect(this@coroutineScope)
+                StreamConfig.MULTI_STREAM -> null
+            }
+        ).apply {
+            getImageCapture()?.let(onImageCaptureCreated)
         }
 
-        launch {
-            processVideoControlEvents(
-                camera,
-                useCaseGroup.getVideoCapture(),
-                captureTypeSuffix = when (sessionSettings.captureMode) {
-                    CaptureMode.MULTI_STREAM -> "MultiStream"
-                    CaptureMode.SINGLE_STREAM -> "SingleStream"
+        cameraProvider.runWith(
+            currentCameraSelector,
+            useCaseGroup
+        ) { camera ->
+            Log.d(TAG, "Camera session started")
+
+            launch {
+                processFocusMeteringEvents(camera.cameraControl)
+            }
+
+            launch {
+                camera.cameraInfo.torchState.asFlow().collectLatest { torchState ->
+                    currentCameraState.update { old ->
+                        old.copy(torchEnabled = torchState == TorchState.ON)
+                    }
                 }
-            )
-        }
+            }
 
-        launch {
-            camera.cameraInfo.torchState.asFlow().collectLatest { torchState ->
-                currentCameraState.update { old ->
-                    old.copy(torchEnabled = torchState == TorchState.ON)
+            if (videoCaptureUseCase != null) {
+                val videoQuality = getVideoQualityFromResolution(
+                    videoCaptureUseCase.resolutionInfo?.resolution
+                )
+                if (videoQuality != sessionSettings.videoQuality) {
+                    Log.e(
+                        TAG,
+                        "Failed to select video quality: $sessionSettings.videoQuality. " +
+                            "Fallback: $videoQuality"
+                    )
+                }
+                launch {
+                    currentCameraState.update { old ->
+                        old.copy(
+                            videoQualityInfo = VideoQualityInfo(
+                                videoQuality,
+                                getWidthFromCropRect(videoCaptureUseCase.resolutionInfo?.cropRect),
+                                getHeightFromCropRect(videoCaptureUseCase.resolutionInfo?.cropRect)
+                            )
+                        )
+                    }
                 }
             }
-        }
 
-        applyDeviceRotation(initialTransientSettings.deviceRotation, useCaseGroup)
-        processTransientSettingEvents(
-            camera,
-            useCaseGroup,
-            initialTransientSettings,
-            transientSettings
-        )
+            applyDeviceRotation(currentTransientSettings.deviceRotation, useCaseGroup)
+            setZoomScale(camera, 1f)
+            processTransientSettingEvents(
+                camera,
+                useCaseGroup,
+                currentTransientSettings,
+                transientSettings
+            )
+        }
     }
 }
 
 context(CameraSessionContext)
+@OptIn(ExperimentalCamera2Interop::class)
 internal suspend fun processTransientSettingEvents(
     camera: Camera,
     useCaseGroup: UseCaseGroup,
@@ -166,22 +235,41 @@ internal suspend fun processTransientSettingEvents(
     transientSettings: StateFlow<TransientSessionSettings?>
 ) {
     var prevTransientSettings = initialTransientSettings
-    transientSettings.filterNotNull().collectLatest { newTransientSettings ->
-        // Apply camera control settings
-        if (prevTransientSettings.zoomScale != newTransientSettings.zoomScale) {
-            camera.cameraInfo.zoomState.value?.let { zoomState ->
-                val finalScale =
-                    (zoomState.zoomRatio * newTransientSettings.zoomScale).coerceIn(
-                        zoomState.minZoomRatio,
-                        zoomState.maxZoomRatio
-                    )
-                camera.cameraControl.setZoomRatio(finalScale)
-                currentCameraState.update { old ->
-                    old.copy(zoomScale = finalScale)
-                }
-            }
+    val isFrontFacing = camera.cameraInfo.appLensFacing == LensFacing.FRONT
+    var torchOn = false
+    fun setTorch(newTorchOn: Boolean) {
+        if (newTorchOn != torchOn) {
+            camera.cameraControl.enableTorch(newTorchOn)
+            torchOn = newTorchOn
         }
+    }
+    combine(
+        transientSettings.filterNotNull(),
+        currentCameraState.asStateFlow()
+    ) { newTransientSettings, cameraState ->
+        return@combine Pair(newTransientSettings, cameraState)
+    }.collectLatest {
+        val newTransientSettings = it.first
+        val cameraState = it.second
 
+        // Apply camera zoom
+        if (prevTransientSettings.zoomScale != newTransientSettings.zoomScale
+        ) {
+            setZoomScale(camera, newTransientSettings.zoomScale)
+        }
+
+        // todo(): How should we handle torch on Auto FlashMode?
+        // enable torch only while recording is in progress
+        if ((cameraState.videoRecordingState !is VideoRecordingState.Inactive) &&
+            newTransientSettings.flashMode == FlashMode.ON &&
+            !isFrontFacing
+        ) {
+            setTorch(true)
+        } else {
+            setTorch(false)
+        }
+
+        // apply camera torch mode to image capture
         useCaseGroup.getImageCapture()?.let { imageCapture ->
             if (prevTransientSettings.flashMode != newTransientSettings.flashMode) {
                 setFlashModeInternal(
@@ -192,6 +280,28 @@ internal suspend fun processTransientSettingEvents(
             }
         }
 
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM &&
+            prevTransientSettings.flashMode != newTransientSettings.flashMode
+        ) {
+            when (newTransientSettings.flashMode) {
+                FlashMode.LOW_LIGHT_BOOST -> {
+                    val captureRequestOptions = CaptureRequestOptions.Builder()
+                        .setCaptureRequestOption(
+                            CaptureRequest.CONTROL_AE_MODE,
+                            CameraMetadata.CONTROL_AE_MODE_ON_LOW_LIGHT_BOOST_BRIGHTNESS_PRIORITY
+                        )
+                        .build()
+
+                    Camera2CameraControl.from(camera.cameraControl)
+                        .addCaptureRequestOptions(captureRequestOptions)
+                }
+                else -> {
+                    Camera2CameraControl.from(camera.cameraControl)
+                        .setCaptureRequestOptions(CaptureRequestOptions.Builder().build())
+                }
+            }
+        }
+
         if (prevTransientSettings.deviceRotation
             != newTransientSettings.deviceRotation
         ) {
@@ -208,6 +318,24 @@ internal suspend fun processTransientSettingEvents(
     }
 }
 
+context(CameraSessionContext)
+internal fun setZoomScale(camera: Camera, zoomScaleRelative: Float) {
+    camera.cameraInfo.zoomState.value?.let { zoomState ->
+        transientSettings.value?.let { transientSettings ->
+            val finalScale =
+                (zoomScale.value * zoomScaleRelative).coerceIn(
+                    zoomState.minZoomRatio,
+                    zoomState.maxZoomRatio
+                )
+            camera.cameraControl.setZoomRatio(finalScale)
+            zoomScale.update { finalScale }
+            currentCameraState.update { old ->
+                old.copy(zoomScale = finalScale)
+            }
+        }
+    }
+}
+
 internal fun applyDeviceRotation(deviceRotation: DeviceRotation, useCaseGroup: UseCaseGroup) {
     val targetRotation = deviceRotation.toUiSurfaceRotation()
     useCaseGroup.useCases.forEach {
@@ -235,38 +363,25 @@ context(CameraSessionContext)
 internal fun createUseCaseGroup(
     cameraInfo: CameraInfo,
     initialTransientSettings: TransientSessionSettings,
-    stabilizePreviewMode: Stabilization,
-    stabilizeVideoMode: Stabilization,
+    stabilizationMode: StabilizationMode,
     aspectRatio: AspectRatio,
-    targetFrameRate: Int,
+    videoCaptureUseCase: VideoCapture<Recorder>?,
     dynamicRange: DynamicRange,
     imageFormat: ImageOutputFormat,
-    useCaseMode: CameraUseCase.UseCaseMode,
+    captureMode: CaptureMode,
     effect: CameraEffect? = null
 ): UseCaseGroup {
     val previewUseCase =
         createPreviewUseCase(
             cameraInfo,
             aspectRatio,
-            stabilizePreviewMode
+            stabilizationMode
         )
-    val imageCaptureUseCase = if (useCaseMode != CameraUseCase.UseCaseMode.VIDEO_ONLY) {
+    val imageCaptureUseCase = if (captureMode != CaptureMode.VIDEO_ONLY) {
         createImageUseCase(cameraInfo, aspectRatio, dynamicRange, imageFormat)
     } else {
         null
     }
-    val videoCaptureUseCase = if (useCaseMode != CameraUseCase.UseCaseMode.IMAGE_ONLY) {
-        createVideoUseCase(
-            cameraInfo,
-            aspectRatio,
-            targetFrameRate,
-            stabilizeVideoMode,
-            dynamicRange,
-            backgroundDispatcher
-        )
-    } else {
-        null
-    }
 
     imageCaptureUseCase?.let {
         setFlashModeInternal(
@@ -308,6 +423,27 @@ internal fun createUseCaseGroup(
     }.build()
 }
 
+private fun getVideoQualityFromResolution(resolution: Size?): VideoQuality =
+    resolution?.let { res ->
+        QUALITY_RANGE_MAP.firstNotNullOfOrNull {
+            if (it.value.contains(res.height)) it.key else null
+        }
+    } ?: VideoQuality.UNSPECIFIED
+
+private fun getWidthFromCropRect(cropRect: Rect?): Int {
+    if (cropRect == null) {
+        return 0
+    }
+    return abs(cropRect.top - cropRect.bottom)
+}
+
+private fun getHeightFromCropRect(cropRect: Rect?): Int {
+    if (cropRect == null) {
+        return 0
+    }
+    return abs(cropRect.left - cropRect.right)
+}
+
 private fun createImageUseCase(
     cameraInfo: CameraInfo,
     aspectRatio: AspectRatio,
@@ -325,12 +461,13 @@ private fun createImageUseCase(
     return builder.build()
 }
 
-private fun createVideoUseCase(
+internal fun createVideoUseCase(
     cameraInfo: CameraInfo,
     aspectRatio: AspectRatio,
     targetFrameRate: Int,
-    stabilizeVideoMode: Stabilization,
+    stabilizationMode: StabilizationMode,
     dynamicRange: DynamicRange,
+    videoQuality: VideoQuality,
     backgroundDispatcher: CoroutineDispatcher
 ): VideoCapture<Recorder> {
     val sensorLandscapeRatio = cameraInfo.sensorLandscapeRatio
@@ -338,10 +475,22 @@ private fun createVideoUseCase(
         .setAspectRatio(
             getAspectRatioForUseCase(sensorLandscapeRatio, aspectRatio)
         )
-        .setExecutor(backgroundDispatcher.asExecutor()).build()
+        .setExecutor(backgroundDispatcher.asExecutor())
+        .apply {
+            videoQuality.toQuality()?.let { quality ->
+                // No fallback strategy is used. The app will crash if the quality is unsupported
+                setQualitySelector(
+                    QualitySelector.from(
+                        quality,
+                        FallbackStrategy.lowerQualityOrHigherThan(quality)
+                    )
+                )
+            }
+        }.build()
+
     return VideoCapture.Builder(recorder).apply {
         // set video stabilization
-        if (stabilizeVideoMode == Stabilization.ON) {
+        if (stabilizationMode == StabilizationMode.HIGH_QUALITY) {
             setVideoStabilizationEnabled(true)
         }
         // set target fps
@@ -353,8 +502,8 @@ private fun createVideoUseCase(
     }.build()
 }
 
-private fun getAspectRatioForUseCase(sensorLandscapeRatio: Float, aspectRatio: AspectRatio): Int {
-    return when (aspectRatio) {
+private fun getAspectRatioForUseCase(sensorLandscapeRatio: Float, aspectRatio: AspectRatio): Int =
+    when (aspectRatio) {
         AspectRatio.THREE_FOUR -> androidx.camera.core.AspectRatio.RATIO_4_3
         AspectRatio.NINE_SIXTEEN -> androidx.camera.core.AspectRatio.RATIO_16_9
         else -> {
@@ -369,19 +518,25 @@ private fun getAspectRatioForUseCase(sensorLandscapeRatio: Float, aspectRatio: A
             }
         }
     }
-}
 
 context(CameraSessionContext)
 private fun createPreviewUseCase(
     cameraInfo: CameraInfo,
     aspectRatio: AspectRatio,
-    stabilizePreviewMode: Stabilization
+    stabilizationMode: StabilizationMode
 ): Preview = Preview.Builder().apply {
     updateCameraStateWithCaptureResults(targetCameraInfo = cameraInfo)
 
     // set preview stabilization
-    if (stabilizePreviewMode == Stabilization.ON) {
-        setPreviewStabilizationEnabled(true)
+    when (stabilizationMode) {
+        StabilizationMode.ON -> setPreviewStabilizationEnabled(true)
+        StabilizationMode.OPTICAL -> setOpticalStabilizationModeEnabled(true)
+        StabilizationMode.OFF -> setOpticalStabilizationModeEnabled(false)
+        StabilizationMode.HIGH_QUALITY -> {} // No-op. Handled by VideoCapture use case.
+        else -> throw UnsupportedOperationException(
+            "Unexpected stabilization mode: $stabilizationMode. Stabilization mode should always " +
+                "an explicit mode, such as ON, OPTICAL, OFF or HIGH_QUALITY"
+        )
     }
 
     setResolutionSelector(
@@ -394,6 +549,20 @@ private fun createPreviewUseCase(
         }
     }
 
+@OptIn(ExperimentalCamera2Interop::class)
+private fun Preview.Builder.setOpticalStabilizationModeEnabled(enabled: Boolean): Preview.Builder {
+    Camera2Interop.Extender(this)
+        .setCaptureRequestOption(
+            CaptureRequest.LENS_OPTICAL_STABILIZATION_MODE,
+            if (enabled) {
+                CaptureRequest.LENS_OPTICAL_STABILIZATION_MODE_ON
+            } else {
+                CaptureRequest.LENS_OPTICAL_STABILIZATION_MODE_OFF
+            }
+        )
+    return this
+}
+
 private fun getResolutionSelector(
     sensorLandscapeRatio: Float,
     aspectRatio: AspectRatio
@@ -463,37 +632,56 @@ private fun setFlashModeInternal(
         } else {
             ImageCapture.FLASH_MODE_AUTO // 0
         }
+
+        FlashMode.LOW_LIGHT_BOOST -> ImageCapture.FLASH_MODE_OFF // 2
     }
     Log.d(TAG, "Set flash mode to: ${imageCapture.flashMode}")
 }
 
-private suspend fun startVideoRecordingInternal(
-    initialMuted: Boolean,
+private fun getPendingRecording(
+    context: Context,
     videoCaptureUseCase: VideoCapture<Recorder>,
+    maxDurationMillis: Long,
     captureTypeSuffix: String,
-    context: Context,
     videoCaptureUri: Uri?,
     shouldUseUri: Boolean,
     onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
-): Recording {
-    Log.d(TAG, "recordVideo")
-    // todo(b/336886716): default setting to enable or disable audio when permission is granted
+): PendingRecording? {
+    Log.d(TAG, "getPendingRecording")
 
-    // ok. there is a difference between MUTING and ENABLING audio
-    // audio must be enabled in order to be muted
-    // if the video recording isnt started with audio enabled, you will not be able to unmute it
-    // the toggle should only affect whether or not the audio is muted.
-    // the permission will determine whether or not the audio is enabled.
-    val audioEnabled = checkSelfPermission(
-        context,
-        Manifest.permission.RECORD_AUDIO
-    ) == PackageManager.PERMISSION_GRANTED
-
-    val pendingRecord = if (shouldUseUri) {
-        val fileOutputOptions = FileOutputOptions.Builder(
-            File(videoCaptureUri!!.path!!)
-        ).build()
-        videoCaptureUseCase.output.prepareRecording(context, fileOutputOptions)
+    return if (shouldUseUri) {
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
+            try {
+                videoCaptureUseCase.output.prepareRecording(
+                    context,
+                    FileDescriptorOutputOptions.Builder(
+                        context.applicationContext.contentResolver.openFileDescriptor(
+                            videoCaptureUri!!,
+                            "rw"
+                        )!!
+                    ).build()
+                )
+            } catch (e: Exception) {
+                onVideoRecord(
+                    CameraUseCase.OnVideoRecordEvent.OnVideoRecordError(e)
+                )
+                null
+            }
+        } else {
+            if (videoCaptureUri?.scheme == "file") {
+                val fileOutputOptions = FileOutputOptions.Builder(
+                    File(videoCaptureUri.path!!)
+                ).build()
+                videoCaptureUseCase.output.prepareRecording(context, fileOutputOptions)
+            } else {
+                onVideoRecord(
+                    CameraUseCase.OnVideoRecordEvent.OnVideoRecordError(
+                        RuntimeException("Uri scheme not supported.")
+                    )
+                )
+                null
+            }
+        }
     } else {
         val name = "JCA-recording-${Date()}-$captureTypeSuffix.mp4"
         val contentValues =
@@ -505,15 +693,46 @@ private suspend fun startVideoRecordingInternal(
                 context.contentResolver,
                 MediaStore.Video.Media.EXTERNAL_CONTENT_URI
             )
+                .setDurationLimitMillis(maxDurationMillis)
                 .setContentValues(contentValues)
                 .build()
         videoCaptureUseCase.output.prepareRecording(context, mediaStoreOutput)
     }
+}
+
+context(CameraSessionContext)
+private suspend fun startVideoRecordingInternal(
+    isInitialAudioEnabled: Boolean,
+    context: Context,
+    pendingRecord: PendingRecording,
+    maxDurationMillis: Long,
+    onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
+): Recording {
+    Log.d(TAG, "recordVideo")
+    // todo(b/336886716): default setting to enable or disable audio when permission is granted
+    // set the camerastate to starting
+    currentCameraState.update { old ->
+        old.copy(videoRecordingState = VideoRecordingState.Starting)
+    }
+
+    // ok. there is a difference between MUTING and ENABLING audio
+    // audio must be enabled in order to be muted
+    // if the video recording isn't started with audio enabled, you will not be able to un-mute it
+    // the toggle should only affect whether or not the audio is muted.
+    // the permission will determine whether or not the audio is enabled.
+    val isAudioGranted = checkSelfPermission(
+        context,
+        Manifest.permission.RECORD_AUDIO
+    ) == PackageManager.PERMISSION_GRANTED
+
     pendingRecord.apply {
-        if (audioEnabled) {
-            withAudioEnabled()
+        if (isAudioGranted) {
+            Log.d(TAG, "INITIAL AUDIO $isInitialAudioEnabled")
+            withAudioEnabled(isInitialAudioEnabled)
         }
     }
+        .asPersistentRecording()
+
     val callbackExecutor: Executor =
         (
             currentCoroutineContext()[ContinuationInterceptor] as?
@@ -522,91 +741,198 @@ private suspend fun startVideoRecordingInternal(
     return pendingRecord.start(callbackExecutor) { onVideoRecordEvent ->
         Log.d(TAG, onVideoRecordEvent.toString())
         when (onVideoRecordEvent) {
+            is VideoRecordEvent.Start -> {
+                currentCameraState.update { old ->
+                    old.copy(
+                        videoRecordingState = VideoRecordingState.Active.Recording(
+                            audioAmplitude = onVideoRecordEvent.recordingStats.audioStats
+                                .audioAmplitude,
+                            maxDurationMillis = maxDurationMillis,
+                            elapsedTimeNanos = onVideoRecordEvent.recordingStats
+                                .recordedDurationNanos
+                        )
+                    )
+                }
+            }
+
+            is VideoRecordEvent.Pause -> {
+                currentCameraState.update { old ->
+                    old.copy(
+                        videoRecordingState = VideoRecordingState.Active.Paused(
+                            audioAmplitude = onVideoRecordEvent.recordingStats.audioStats
+                                .audioAmplitude,
+                            maxDurationMillis = maxDurationMillis,
+                            elapsedTimeNanos = onVideoRecordEvent.recordingStats
+                                .recordedDurationNanos
+                        )
+                    )
+                }
+            }
+
+            is VideoRecordEvent.Resume -> {
+                currentCameraState.update { old ->
+                    old.copy(
+                        videoRecordingState = VideoRecordingState.Active.Recording(
+                            audioAmplitude = onVideoRecordEvent.recordingStats.audioStats
+                                .audioAmplitude,
+                            maxDurationMillis = maxDurationMillis,
+                            elapsedTimeNanos = onVideoRecordEvent.recordingStats
+                                .recordedDurationNanos
+                        )
+                    )
+                }
+            }
+
+            is VideoRecordEvent.Status -> {
+                currentCameraState.update { old ->
+                    // don't want to change state from paused to recording if status changes while paused
+                    if (old.videoRecordingState is VideoRecordingState.Active.Paused) {
+                        old.copy(
+                            videoRecordingState = VideoRecordingState.Active.Paused(
+                                audioAmplitude = onVideoRecordEvent.recordingStats.audioStats
+                                    .audioAmplitude,
+                                maxDurationMillis = maxDurationMillis,
+                                elapsedTimeNanos = onVideoRecordEvent.recordingStats
+                                    .recordedDurationNanos
+                            )
+                        )
+                    } else {
+                        old.copy(
+                            videoRecordingState = VideoRecordingState.Active.Recording(
+                                audioAmplitude = onVideoRecordEvent.recordingStats.audioStats
+                                    .audioAmplitude,
+                                maxDurationMillis = maxDurationMillis,
+                                elapsedTimeNanos = onVideoRecordEvent.recordingStats
+                                    .recordedDurationNanos
+                            )
+                        )
+                    }
+                }
+            }
+
             is VideoRecordEvent.Finalize -> {
                 when (onVideoRecordEvent.error) {
-                    ERROR_NONE ->
+                    ERROR_NONE -> {
+                        // update recording state to inactive with the final values of the recording.
+                        currentCameraState.update { old ->
+                            old.copy(
+                                videoRecordingState = VideoRecordingState.Inactive(
+                                    finalElapsedTimeNanos = onVideoRecordEvent.recordingStats
+                                        .recordedDurationNanos
+                                )
+                            )
+                        }
                         onVideoRecord(
                             CameraUseCase.OnVideoRecordEvent.OnVideoRecorded(
                                 onVideoRecordEvent.outputResults.outputUri
                             )
                         )
+                    }
+
+                    ERROR_DURATION_LIMIT_REACHED -> {
+                        currentCameraState.update { old ->
+                            old.copy(
+                                videoRecordingState = VideoRecordingState.Inactive(
+                                    finalElapsedTimeNanos = maxDurationMillis.milliseconds
+                                        .inWholeNanoseconds
+                                )
+                            )
+                        }
 
-                    else ->
+                        onVideoRecord(
+                            CameraUseCase.OnVideoRecordEvent.OnVideoRecorded(
+                                onVideoRecordEvent.outputResults.outputUri
+                            )
+                        )
+                    }
+
+                    else -> {
                         onVideoRecord(
                             CameraUseCase.OnVideoRecordEvent.OnVideoRecordError(
-                                onVideoRecordEvent.cause
+                                RuntimeException(
+                                    "Recording finished with error: ${onVideoRecordEvent.error}",
+                                    onVideoRecordEvent.cause
+                                )
                             )
                         )
+                        currentCameraState.update { old ->
+                            old.copy(
+                                videoRecordingState = VideoRecordingState.Inactive(
+                                    finalElapsedTimeNanos = onVideoRecordEvent.recordingStats
+                                        .recordedDurationNanos
+                                )
+                            )
+                        }
+                    }
                 }
             }
-
-            is VideoRecordEvent.Status -> {
-                onVideoRecord(
-                    CameraUseCase.OnVideoRecordEvent.OnVideoRecordStatus(
-                        onVideoRecordEvent.recordingStats.audioStats
-                            .audioAmplitude
-                    )
-                )
-            }
         }
     }.apply {
-        mute(initialMuted)
+        mute(!isInitialAudioEnabled)
     }
 }
 
+context(CameraSessionContext)
 private suspend fun runVideoRecording(
-    camera: Camera,
     videoCapture: VideoCapture<Recorder>,
     captureTypeSuffix: String,
     context: Context,
+    maxDurationMillis: Long,
     transientSettings: StateFlow<TransientSessionSettings?>,
     videoCaptureUri: Uri?,
+    videoControlEvents: Channel<VideoCaptureControlEvent>,
     shouldUseUri: Boolean,
     onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
-) {
+) = coroutineScope {
     var currentSettings = transientSettings.filterNotNull().first()
 
-    startVideoRecordingInternal(
-        initialMuted = currentSettings.audioMuted,
+    getPendingRecording(
+        context,
         videoCapture,
+        maxDurationMillis,
         captureTypeSuffix,
-        context,
         videoCaptureUri,
         shouldUseUri,
         onVideoRecord
-    ).use { recording ->
-
-        fun TransientSessionSettings.isFlashModeOn() = flashMode == FlashMode.ON
-        val isFrontCameraSelector =
-            camera.cameraInfo.cameraSelector == CameraSelector.DEFAULT_FRONT_CAMERA
+    )?.let {
+        startVideoRecordingInternal(
+            isInitialAudioEnabled = currentSettings.isAudioEnabled,
+            context = context,
+            pendingRecord = it,
+            maxDurationMillis = maxDurationMillis,
+            onVideoRecord = onVideoRecord
+        ).use { recording ->
+            val recordingSettingsUpdater = launch {
+                fun TransientSessionSettings.isFlashModeOn() = flashMode == FlashMode.ON
 
-        if (currentSettings.isFlashModeOn()) {
-            if (!isFrontCameraSelector) {
-                camera.cameraControl.enableTorch(true).await()
-            } else {
-                Log.d(TAG, "Unable to enable torch for front camera.")
+                transientSettings.filterNotNull()
+                    .collectLatest { newTransientSettings ->
+                        if (currentSettings.isAudioEnabled != newTransientSettings.isAudioEnabled) {
+                            recording.mute(newTransientSettings.isAudioEnabled)
+                        }
+                        if (currentSettings.isFlashModeOn() !=
+                            newTransientSettings.isFlashModeOn()
+                        ) {
+                            currentSettings = newTransientSettings
+                        }
+                    }
             }
-        }
 
-        transientSettings.filterNotNull()
-            .onCompletion {
-                // Could do some fancier tracking of whether the torch was enabled before
-                // calling this.
-                camera.cameraControl.enableTorch(false)
-            }
-            .collectLatest { newTransientSettings ->
-                if (currentSettings.audioMuted != newTransientSettings.audioMuted) {
-                    recording.mute(newTransientSettings.audioMuted)
-                }
-                if (currentSettings.isFlashModeOn() != newTransientSettings.isFlashModeOn()) {
-                    if (!isFrontCameraSelector) {
-                        camera.cameraControl.enableTorch(newTransientSettings.isFlashModeOn())
-                    } else {
-                        Log.d(TAG, "Unable to update torch for front camera.")
+            for (event in videoControlEvents) {
+                when (event) {
+                    is VideoCaptureControlEvent.StartRecordingEvent ->
+                        throw IllegalStateException("A recording is already in progress")
+
+                    VideoCaptureControlEvent.StopRecordingEvent -> {
+                        recordingSettingsUpdater.cancel()
+                        break
                     }
+
+                    VideoCaptureControlEvent.PauseRecordingEvent -> recording.pause()
+                    VideoCaptureControlEvent.ResumeRecordingEvent -> recording.resume()
                 }
-                currentSettings = newTransientSettings
             }
+        }
     }
 }
 
@@ -637,12 +963,9 @@ internal suspend fun processFocusMeteringEvents(cameraControl: CameraControl) {
 
 context(CameraSessionContext)
 internal suspend fun processVideoControlEvents(
-    camera: Camera,
     videoCapture: VideoCapture<Recorder>?,
     captureTypeSuffix: String
 ) = coroutineScope {
-    var recordingJob: Job? = null
-
     for (event in videoCaptureControlEvents) {
         when (event) {
             is VideoCaptureControlEvent.StartRecordingEvent -> {
@@ -651,25 +974,20 @@ internal suspend fun processVideoControlEvents(
                         "Attempted video recording with null videoCapture"
                     )
                 }
-
-                recordingJob = launch(start = CoroutineStart.UNDISPATCHED) {
-                    runVideoRecording(
-                        camera,
-                        videoCapture,
-                        captureTypeSuffix,
-                        context,
-                        transientSettings,
-                        event.videoCaptureUri,
-                        event.shouldUseUri,
-                        event.onVideoRecord
-                    )
-                }
+                runVideoRecording(
+                    videoCapture,
+                    captureTypeSuffix,
+                    context,
+                    event.maxVideoDuration,
+                    transientSettings,
+                    event.videoCaptureUri,
+                    videoCaptureControlEvents,
+                    event.shouldUseUri,
+                    event.onVideoRecord
+                )
             }
 
-            VideoCaptureControlEvent.StopRecordingEvent -> {
-                recordingJob?.cancel()
-                recordingJob = null
-            }
+            else -> {}
         }
     }
 }
@@ -692,6 +1010,23 @@ private fun Preview.Builder.updateCameraStateWithCaptureResults(
                 result: TotalCaptureResult
             ) {
                 super.onCaptureCompleted(session, request, result)
+
+                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
+                    val nativeBoostState = result.get(CaptureResult.CONTROL_LOW_LIGHT_BOOST_STATE)
+                    val boostState = when (nativeBoostState) {
+                        CameraMetadata.CONTROL_LOW_LIGHT_BOOST_STATE_ACTIVE ->
+                            LowLightBoostState.ACTIVE
+                        else -> LowLightBoostState.INACTIVE
+                    }
+                    currentCameraState.update { old ->
+                        if (old.lowLightBoostState != boostState) {
+                            old.copy(lowLightBoostState = boostState)
+                        } else {
+                            old
+                        }
+                    }
+                }
+
                 val logicalCameraId = session.device.id
                 if (logicalCameraId != targetCameraLogicalId) return
                 try {
@@ -704,7 +1039,9 @@ private fun Preview.Builder.updateCameraStateWithCaptureResults(
                         if (old.debugInfo.logicalCameraId != logicalCameraId ||
                             old.debugInfo.physicalCameraId != physicalCameraId
                         ) {
-                            old.copy(debugInfo = DebugInfo(logicalCameraId, physicalCameraId))
+                            old.copy(
+                                debugInfo = DebugInfo(logicalCameraId, physicalCameraId)
+                            )
                         } else {
                             old
                         }
@@ -717,6 +1054,8 @@ private fun Preview.Builder.updateCameraStateWithCaptureResults(
                         }
                         isFirstFrameTimestampUpdated.value = true
                     }
+                    // Publish stabilization state
+                    publishStabilizationMode(result)
                 } catch (_: Exception) {
                 }
             }
@@ -724,3 +1063,31 @@ private fun Preview.Builder.updateCameraStateWithCaptureResults(
     )
     return this
 }
+
+context(CameraSessionContext)
+private fun publishStabilizationMode(result: TotalCaptureResult) {
+    val nativeVideoStabilizationMode = result.get(CaptureResult.CONTROL_VIDEO_STABILIZATION_MODE)
+    val stabilizationMode = when (nativeVideoStabilizationMode) {
+        CaptureResult.CONTROL_VIDEO_STABILIZATION_MODE_PREVIEW_STABILIZATION ->
+            StabilizationMode.ON
+
+        CaptureResult.CONTROL_VIDEO_STABILIZATION_MODE_ON -> StabilizationMode.HIGH_QUALITY
+        else -> {
+            result.get(CaptureResult.LENS_OPTICAL_STABILIZATION_MODE)?.let {
+                if (it == CaptureResult.LENS_OPTICAL_STABILIZATION_MODE_ON) {
+                    StabilizationMode.OPTICAL
+                } else {
+                    StabilizationMode.OFF
+                }
+            } ?: StabilizationMode.OFF
+        }
+    }
+
+    currentCameraState.update { old ->
+        if (old.stabilizationMode != stabilizationMode) {
+            old.copy(stabilizationMode = stabilizationMode)
+        } else {
+            old
+        }
+    }
+}
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionContext.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionContext.kt
index 1425bbb..e28d49a 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionContext.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionContext.kt
@@ -39,5 +39,6 @@ internal data class CameraSessionContext(
     val videoCaptureControlEvents: Channel<VideoCaptureControlEvent>,
     val currentCameraState: MutableStateFlow<CameraState>,
     val surfaceRequests: MutableStateFlow<SurfaceRequest?>,
-    val transientSettings: StateFlow<TransientSessionSettings?>
+    val transientSettings: StateFlow<TransientSessionSettings?>,
+    var zoomScale: MutableStateFlow<Float>
 )
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionSettings.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionSettings.kt
index b96c6a3..2a9fa4d 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionSettings.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraSessionSettings.kt
@@ -22,7 +22,10 @@ import com.google.jetpackcamera.settings.model.DeviceRotation
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.LensFacing
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.StreamConfig
+import com.google.jetpackcamera.settings.model.VideoQuality
 
 /**
  * Camera settings that persist as long as a camera is running.
@@ -32,23 +35,30 @@ import com.google.jetpackcamera.settings.model.Stabilization
  */
 internal sealed interface PerpetualSessionSettings {
     val aspectRatio: AspectRatio
+    val captureMode: CaptureMode
 
     data class SingleCamera(
-        val cameraInfo: CameraInfo,
         override val aspectRatio: AspectRatio,
-        val captureMode: CaptureMode,
+        override val captureMode: CaptureMode,
+        val streamConfig: StreamConfig,
         val targetFrameRate: Int,
-        val stabilizePreviewMode: Stabilization,
-        val stabilizeVideoMode: Stabilization,
+        val stabilizationMode: StabilizationMode,
         val dynamicRange: DynamicRange,
+        val videoQuality: VideoQuality,
         val imageFormat: ImageOutputFormat
     ) : PerpetualSessionSettings
 
+    /**
+     * @property captureMode is always [CaptureMode.VIDEO_ONLY] in Concurrent Camera mode.
+     * Concurrent Camera currently only supports video capture
+     */
     data class ConcurrentCamera(
         val primaryCameraInfo: CameraInfo,
         val secondaryCameraInfo: CameraInfo,
         override val aspectRatio: AspectRatio
-    ) : PerpetualSessionSettings
+    ) : PerpetualSessionSettings {
+        override val captureMode: CaptureMode = CaptureMode.VIDEO_ONLY
+    }
 }
 
 /**
@@ -59,8 +69,9 @@ internal sealed interface PerpetualSessionSettings {
  * The use cases typically will not need to be re-bound.
  */
 internal data class TransientSessionSettings(
-    val audioMuted: Boolean,
+    val isAudioEnabled: Boolean,
     val deviceRotation: DeviceRotation,
     val flashMode: FlashMode,
-    val zoomScale: Float
+    val zoomScale: Float,
+    val primaryLensFacing: LensFacing
 )
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraUseCase.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraUseCase.kt
index 02477d8..881953c 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraUseCase.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraUseCase.kt
@@ -28,8 +28,10 @@ import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.LowLightBoost
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.LowLightBoostState
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.StreamConfig
+import com.google.jetpackcamera.settings.model.VideoQuality
 import kotlinx.coroutines.channels.ReceiveChannel
 import kotlinx.coroutines.flow.StateFlow
 
@@ -44,8 +46,8 @@ interface CameraUseCase {
      */
     suspend fun initialize(
         cameraAppSettings: CameraAppSettings,
-        useCaseMode: UseCaseMode,
-        isDebugMode: Boolean = false
+        isDebugMode: Boolean = false,
+        cameraPropertiesJSONCallback: (result: String) -> Unit
     )
 
     /**
@@ -78,7 +80,11 @@ interface CameraUseCase {
         onVideoRecord: (OnVideoRecordEvent) -> Unit
     )
 
-    fun stopVideoRecording()
+    suspend fun pauseVideoRecording()
+
+    suspend fun resumeVideoRecording()
+
+    suspend fun stopVideoRecording()
 
     fun setZoomScale(scale: Float)
 
@@ -96,11 +102,13 @@ interface CameraUseCase {
 
     suspend fun setAspectRatio(aspectRatio: AspectRatio)
 
+    suspend fun setVideoQuality(videoQuality: VideoQuality)
+
     suspend fun setLensFacing(lensFacing: LensFacing)
 
     suspend fun tapToFocus(x: Float, y: Float)
 
-    suspend fun setCaptureMode(captureMode: CaptureMode)
+    suspend fun setStreamConfig(streamConfig: StreamConfig)
 
     suspend fun setDynamicRange(dynamicRange: DynamicRange)
 
@@ -108,18 +116,18 @@ interface CameraUseCase {
 
     suspend fun setConcurrentCameraMode(concurrentCameraMode: ConcurrentCameraMode)
 
-    suspend fun setLowLightBoost(lowLightBoost: LowLightBoost)
-
     suspend fun setImageFormat(imageFormat: ImageOutputFormat)
 
-    suspend fun setAudioMuted(isAudioMuted: Boolean)
-
-    suspend fun setVideoCaptureStabilization(videoCaptureStabilization: Stabilization)
+    suspend fun setAudioEnabled(isAudioEnabled: Boolean)
 
-    suspend fun setPreviewStabilization(previewStabilization: Stabilization)
+    suspend fun setStabilizationMode(stabilizationMode: StabilizationMode)
 
     suspend fun setTargetFrameRate(targetFrameRate: Int)
 
+    suspend fun setMaxVideoDuration(durationInMillis: Long)
+
+    suspend fun setCaptureMode(captureMode: CaptureMode)
+
     /**
      * Represents the events required for screen flash.
      */
@@ -133,26 +141,60 @@ interface CameraUseCase {
     /**
      * Represents the events for video recording.
      */
+
     sealed interface OnVideoRecordEvent {
         data class OnVideoRecorded(val savedUri: Uri) : OnVideoRecordEvent
 
-        data class OnVideoRecordStatus(val audioAmplitude: Double) : OnVideoRecordEvent
-
-        data class OnVideoRecordError(val error: Throwable?) : OnVideoRecordEvent
+        data class OnVideoRecordError(val error: Throwable) : OnVideoRecordEvent
     }
+}
+
+sealed interface VideoRecordingState {
+
+    /**
+     * [PendingRecording][androidx.camera.video.PendingRecording] has not yet started but is about to.
+     * This state may be used as a signal to start processes just before the recording actually starts.
+     */
+    data object Starting : VideoRecordingState
 
-    enum class UseCaseMode {
-        STANDARD,
-        IMAGE_ONLY,
-        VIDEO_ONLY
+    /**
+     * Camera is not currently recording a video
+     */
+    data class Inactive(val finalElapsedTimeNanos: Long = 0) : VideoRecordingState
+
+    /**
+     * Camera is currently active; paused, stopping, or recording a video
+     */
+    sealed interface Active : VideoRecordingState {
+        val maxDurationMillis: Long
+        val audioAmplitude: Double
+        val elapsedTimeNanos: Long
+
+        data class Recording(
+            override val maxDurationMillis: Long,
+            override val audioAmplitude: Double,
+            override val elapsedTimeNanos: Long
+        ) : Active
+
+        data class Paused(
+            override val maxDurationMillis: Long,
+            override val audioAmplitude: Double,
+            override val elapsedTimeNanos: Long
+        ) : Active
     }
 }
 
 data class CameraState(
+    val videoRecordingState: VideoRecordingState = VideoRecordingState.Inactive(),
     val zoomScale: Float = 1f,
     val sessionFirstFrameTimestamp: Long = 0L,
     val torchEnabled: Boolean = false,
-    val debugInfo: DebugInfo = DebugInfo(null, null)
+    val stabilizationMode: StabilizationMode = StabilizationMode.OFF,
+    val lowLightBoostState: LowLightBoostState = LowLightBoostState.INACTIVE,
+    val debugInfo: DebugInfo = DebugInfo(null, null),
+    val videoQualityInfo: VideoQualityInfo = VideoQualityInfo(VideoQuality.UNSPECIFIED, 0, 0)
 )
 
 data class DebugInfo(val logicalCameraId: String?, val physicalCameraId: String?)
+
+data class VideoQualityInfo(val quality: VideoQuality, val width: Int, val height: Int)
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCase.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCase.kt
index 2f7f99a..3bff09c 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCase.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/CameraXCameraUseCase.kt
@@ -21,11 +21,9 @@ import android.content.ContentValues
 import android.net.Uri
 import android.os.Build
 import android.os.Environment
-import android.os.Environment.DIRECTORY_DOCUMENTS
 import android.provider.MediaStore
 import android.util.Log
 import androidx.camera.core.CameraInfo
-import androidx.camera.core.CameraSelector
 import androidx.camera.core.DynamicRange as CXDynamicRange
 import androidx.camera.core.ImageCapture
 import androidx.camera.core.ImageCapture.OutputFileOptions
@@ -43,17 +41,21 @@ import com.google.jetpackcamera.settings.SettableConstraintsRepository
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CameraAppSettings
 import com.google.jetpackcamera.settings.model.CameraConstraints
+import com.google.jetpackcamera.settings.model.CameraConstraints.Companion.FPS_15
+import com.google.jetpackcamera.settings.model.CameraConstraints.Companion.FPS_60
 import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
 import com.google.jetpackcamera.settings.model.DeviceRotation
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.Illuminant
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.LowLightBoost
-import com.google.jetpackcamera.settings.model.Stabilization
-import com.google.jetpackcamera.settings.model.SupportedStabilizationMode
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.StreamConfig
 import com.google.jetpackcamera.settings.model.SystemConstraints
+import com.google.jetpackcamera.settings.model.VideoQuality
+import com.google.jetpackcamera.settings.model.forCurrentLens
 import dagger.hilt.android.scopes.ViewModelScoped
 import java.io.File
 import java.io.FileNotFoundException
@@ -61,10 +63,8 @@ import java.text.SimpleDateFormat
 import java.util.Calendar
 import java.util.Locale
 import javax.inject.Inject
-import kotlin.properties.Delegates
 import kotlinx.coroutines.CoroutineDispatcher
 import kotlinx.coroutines.channels.Channel
-import kotlinx.coroutines.channels.trySendBlocking
 import kotlinx.coroutines.coroutineScope
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.StateFlow
@@ -82,6 +82,8 @@ const val TARGET_FPS_15 = 15
 const val TARGET_FPS_30 = 30
 const val TARGET_FPS_60 = 60
 
+const val UNLIMITED_VIDEO_DURATION = 0L
+
 /**
  * CameraX based implementation for [CameraUseCase]
  */
@@ -99,7 +101,6 @@ constructor(
     private var imageCaptureUseCase: ImageCapture? = null
 
     private lateinit var systemConstraints: SystemConstraints
-    private var useCaseMode by Delegates.notNull<CameraUseCase.UseCaseMode>()
 
     private val screenFlashEvents: Channel<CameraUseCase.ScreenFlashEvent> =
         Channel(capacity = Channel.UNLIMITED)
@@ -110,18 +111,18 @@ constructor(
     private val currentSettings = MutableStateFlow<CameraAppSettings?>(null)
 
     // Could be improved by setting initial value only when camera is initialized
-    private val _currentCameraState = MutableStateFlow(CameraState())
+    private var _currentCameraState = MutableStateFlow(CameraState())
     override fun getCurrentCameraState(): StateFlow<CameraState> = _currentCameraState.asStateFlow()
 
     private val _surfaceRequest = MutableStateFlow<SurfaceRequest?>(null)
+
     override fun getSurfaceRequest(): StateFlow<SurfaceRequest?> = _surfaceRequest.asStateFlow()
 
     override suspend fun initialize(
         cameraAppSettings: CameraAppSettings,
-        useCaseMode: CameraUseCase.UseCaseMode,
-        isDebugMode: Boolean
+        isDebugMode: Boolean,
+        cameraPropertiesJSONCallback: (result: String) -> Unit
     ) {
-        this.useCaseMode = useCaseMode
         cameraProvider = ProcessCameraProvider.awaitInstance(application)
 
         // updates values for available cameras
@@ -137,7 +138,7 @@ constructor(
         systemConstraints = SystemConstraints(
             availableLenses = availableCameraLenses,
             concurrentCamerasSupported = cameraProvider.availableConcurrentCameraInfos.any {
-                it.map { cameraInfo -> cameraInfo.cameraSelector.toAppLensFacing() }
+                it.map { cameraInfo -> cameraInfo.appLensFacing }
                     .toSet() == setOf(LensFacing.FRONT, LensFacing.BACK)
             },
             perLensConstraints = buildMap {
@@ -145,25 +146,85 @@ constructor(
                 for (lensFacing in availableCameraLenses) {
                     val selector = lensFacing.toCameraSelector()
                     selector.filter(availableCameraInfos).firstOrNull()?.let { camInfo ->
+                        val videoCapabilities = Recorder.getVideoCapabilities(camInfo)
                         val supportedDynamicRanges =
-                            Recorder.getVideoCapabilities(camInfo).supportedDynamicRanges
+                            videoCapabilities.supportedDynamicRanges
                                 .mapNotNull(CXDynamicRange::toSupportedAppDynamicRange)
                                 .toSet()
+                        val supportedVideoQualitiesMap =
+                            buildMap {
+                                for (dynamicRange in supportedDynamicRanges) {
+                                    val supportedVideoQualities =
+                                        videoCapabilities.getSupportedQualities(
+                                            dynamicRange.toCXDynamicRange()
+                                        ).map { it.toVideoQuality() }
+                                    put(dynamicRange, supportedVideoQualities)
+                                }
+                            }
 
                         val supportedStabilizationModes = buildSet {
                             if (camInfo.isPreviewStabilizationSupported) {
-                                add(SupportedStabilizationMode.ON)
+                                add(StabilizationMode.ON)
+                                add(StabilizationMode.AUTO)
                             }
 
                             if (camInfo.isVideoStabilizationSupported) {
-                                add(SupportedStabilizationMode.HIGH_QUALITY)
+                                add(StabilizationMode.HIGH_QUALITY)
+                            }
+
+                            if (camInfo.isOpticalStabilizationSupported) {
+                                add(StabilizationMode.OPTICAL)
+                                add(StabilizationMode.AUTO)
+                            }
+
+                            add(StabilizationMode.OFF)
+                        }
+
+                        val unsupportedStabilizationFpsMap = buildMap {
+                            for (stabilizationMode in supportedStabilizationModes) {
+                                when (stabilizationMode) {
+                                    StabilizationMode.ON -> setOf(FPS_15, FPS_60)
+                                    StabilizationMode.HIGH_QUALITY -> setOf(FPS_60)
+                                    StabilizationMode.OPTICAL -> emptySet()
+                                    else -> null
+                                }?.let { put(stabilizationMode, it) }
                             }
                         }
 
                         val supportedFixedFrameRates =
                             camInfo.filterSupportedFixedFrameRates(FIXED_FRAME_RATES)
                         val supportedImageFormats = camInfo.supportedImageFormats
-                        val hasFlashUnit = camInfo.hasFlashUnit()
+                        val supportedIlluminants = buildSet {
+                            if (camInfo.hasFlashUnit()) {
+                                add(Illuminant.FLASH_UNIT)
+                            }
+
+                            if (lensFacing == LensFacing.FRONT) {
+                                add(Illuminant.SCREEN)
+                            }
+
+                            if (camInfo.isLowLightBoostSupported) {
+                                add(Illuminant.LOW_LIGHT_BOOST)
+                            }
+                        }
+
+                        val supportedFlashModes = buildSet {
+                            add(FlashMode.OFF)
+                            if ((
+                                    setOf(
+                                        Illuminant.FLASH_UNIT,
+                                        Illuminant.SCREEN
+                                    ) intersect supportedIlluminants
+                                    ).isNotEmpty()
+                            ) {
+                                add(FlashMode.ON)
+                                add(FlashMode.AUTO)
+                            }
+
+                            if (Illuminant.LOW_LIGHT_BOOST in supportedIlluminants) {
+                                add(FlashMode.LOW_LIGHT_BOOST)
+                            }
+                        }
 
                         put(
                             lensFacing,
@@ -175,10 +236,13 @@ constructor(
                                     // Only JPEG is supported in single-stream mode, since
                                     // single-stream mode uses CameraEffect, which does not support
                                     // Ultra HDR now.
-                                    Pair(CaptureMode.SINGLE_STREAM, setOf(ImageOutputFormat.JPEG)),
-                                    Pair(CaptureMode.MULTI_STREAM, supportedImageFormats)
+                                    Pair(StreamConfig.SINGLE_STREAM, setOf(ImageOutputFormat.JPEG)),
+                                    Pair(StreamConfig.MULTI_STREAM, supportedImageFormats)
                                 ),
-                                hasFlashUnit = hasFlashUnit
+                                supportedVideoQualitiesMap = supportedVideoQualitiesMap,
+                                supportedIlluminants = supportedIlluminants,
+                                supportedFlashModes = supportedFlashModes,
+                                unsupportedStabilizationFpsMap = unsupportedStabilizationFpsMap
                             )
                         )
                     }
@@ -191,21 +255,27 @@ constructor(
         currentSettings.value =
             cameraAppSettings
                 .tryApplyDynamicRangeConstraints()
-                .tryApplyAspectRatioForExternalCapture(this.useCaseMode)
+                .tryApplyAspectRatioForExternalCapture(cameraAppSettings.captureMode)
                 .tryApplyImageFormatConstraints()
                 .tryApplyFrameRateConstraints()
                 .tryApplyStabilizationConstraints()
                 .tryApplyConcurrentCameraModeConstraints()
+                .tryApplyFlashModeConstraints()
+                .tryApplyVideoQualityConstraints()
+                .tryApplyCaptureModeConstraints()
         if (isDebugMode && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
             withContext(iODispatcher) {
-                val cameraProperties =
+                val cameraPropertiesJSON =
                     getAllCamerasPropertiesJSONArray(cameraProvider.availableCameraInfos).toString()
+                val fileDir = File(application.getExternalFilesDir(null), "Debug")
+                fileDir.mkdirs()
                 val file = File(
-                    Environment.getExternalStoragePublicDirectory(DIRECTORY_DOCUMENTS),
+                    fileDir,
                     "JCACameraProperties.json"
                 )
-                writeFileExternalStorage(file, cameraProperties)
-                Log.d(TAG, "JCACameraProperties written to ${file.path}. \n$cameraProperties")
+                writeFileExternalStorage(file, cameraPropertiesJSON)
+                cameraPropertiesJSONCallback.invoke(cameraPropertiesJSON)
+                Log.d(TAG, "JCACameraProperties written to ${file.path}. \n$cameraPropertiesJSON")
             }
         }
     }
@@ -214,34 +284,46 @@ constructor(
         Log.d(TAG, "runCamera")
 
         val transientSettings = MutableStateFlow<TransientSessionSettings?>(null)
+        val cameraSessionZoomScale = MutableStateFlow(1f)
+        var prevCameraSessionLensFacing: LensFacing? = null
         currentSettings
             .filterNotNull()
             .map { currentCameraSettings ->
                 transientSettings.value = TransientSessionSettings(
-                    audioMuted = currentCameraSettings.audioMuted,
+                    isAudioEnabled = currentCameraSettings.audioEnabled,
                     deviceRotation = currentCameraSettings.deviceRotation,
                     flashMode = currentCameraSettings.flashMode,
+                    primaryLensFacing = currentCameraSettings.cameraLensFacing,
                     zoomScale = currentCameraSettings.zoomScale
                 )
 
                 when (currentCameraSettings.concurrentCameraMode) {
                     ConcurrentCameraMode.OFF -> {
-                        val cameraSelector = when (currentCameraSettings.cameraLensFacing) {
-                            LensFacing.FRONT -> CameraSelector.DEFAULT_FRONT_CAMERA
-                            LensFacing.BACK -> CameraSelector.DEFAULT_BACK_CAMERA
+                        val cameraConstraints = checkNotNull(
+                            systemConstraints.forCurrentLens(currentCameraSettings)
+                        ) {
+                            "Could not retrieve constraints for ${currentCameraSettings.cameraLensFacing}"
                         }
 
+                        val resolvedStabilizationMode = resolveStabilizationMode(
+                            requestedStabilizationMode = currentCameraSettings.stabilizationMode,
+                            targetFrameRate = currentCameraSettings.targetFrameRate,
+                            cameraConstraints = cameraConstraints,
+                            concurrentCameraMode = currentCameraSettings.concurrentCameraMode
+                        )
+
                         PerpetualSessionSettings.SingleCamera(
-                            cameraInfo = cameraProvider.getCameraInfo(cameraSelector),
                             aspectRatio = currentCameraSettings.aspectRatio,
                             captureMode = currentCameraSettings.captureMode,
+                            streamConfig = currentCameraSettings.streamConfig,
                             targetFrameRate = currentCameraSettings.targetFrameRate,
-                            stabilizePreviewMode = currentCameraSettings.previewStabilization,
-                            stabilizeVideoMode = currentCameraSettings.videoCaptureStabilization,
+                            stabilizationMode = resolvedStabilizationMode,
                             dynamicRange = currentCameraSettings.dynamicRange,
+                            videoQuality = currentCameraSettings.videoQuality,
                             imageFormat = currentCameraSettings.imageFormat
                         )
                     }
+
                     ConcurrentCameraMode.DUAL -> {
                         val primaryFacing = currentCameraSettings.cameraLensFacing
                         val secondaryFacing = primaryFacing.flip()
@@ -270,6 +352,10 @@ constructor(
                 }
             }.distinctUntilChanged()
             .collectLatest { sessionSettings ->
+                if (transientSettings.value?.primaryLensFacing != prevCameraSessionLensFacing) {
+                    cameraSessionZoomScale.update { 1f }
+                }
+                prevCameraSessionLensFacing = transientSettings.value?.primaryLensFacing
                 coroutineScope {
                     with(
                         CameraSessionContext(
@@ -281,22 +367,21 @@ constructor(
                             videoCaptureControlEvents = videoCaptureControlEvents,
                             currentCameraState = _currentCameraState,
                             surfaceRequests = _surfaceRequest,
-                            transientSettings = transientSettings
+                            transientSettings = transientSettings,
+                            zoomScale = cameraSessionZoomScale
                         )
                     ) {
                         try {
                             when (sessionSettings) {
                                 is PerpetualSessionSettings.SingleCamera -> runSingleCameraSession(
-                                    sessionSettings,
-                                    useCaseMode = useCaseMode
+                                    sessionSettings
                                 ) { imageCapture ->
                                     imageCaptureUseCase = imageCapture
                                 }
 
                                 is PerpetualSessionSettings.ConcurrentCamera ->
                                     runConcurrentCameraSession(
-                                        sessionSettings,
-                                        useCaseMode = CameraUseCase.UseCaseMode.VIDEO_ONLY
+                                        sessionSettings
                                     )
                             }
                         } finally {
@@ -310,6 +395,38 @@ constructor(
             }
     }
 
+    private fun resolveStabilizationMode(
+        requestedStabilizationMode: StabilizationMode,
+        targetFrameRate: Int,
+        cameraConstraints: CameraConstraints,
+        concurrentCameraMode: ConcurrentCameraMode
+    ): StabilizationMode = if (concurrentCameraMode == ConcurrentCameraMode.DUAL) {
+        StabilizationMode.OFF
+    } else {
+        with(cameraConstraints) {
+            // Convert AUTO stabilization mode to the first supported stabilization mode
+            val stabilizationMode = if (requestedStabilizationMode == StabilizationMode.AUTO) {
+                // Choose between ON, OPTICAL, or OFF, depending on support, in that order
+                sequenceOf(StabilizationMode.ON, StabilizationMode.OPTICAL, StabilizationMode.OFF)
+                    .first {
+                        it in supportedStabilizationModes &&
+                            targetFrameRate !in it.unsupportedFpsSet
+                    }
+            } else {
+                requestedStabilizationMode
+            }
+
+            // Check that the stabilization mode can be supported, otherwise return OFF
+            if (stabilizationMode in supportedStabilizationModes &&
+                targetFrameRate !in stabilizationMode.unsupportedFpsSet
+            ) {
+                stabilizationMode
+            } else {
+                StabilizationMode.OFF
+            }
+        }
+    }
+
     override suspend fun takePicture(onCaptureStarted: (() -> Unit)) {
         if (imageCaptureUseCase == null) {
             throw RuntimeException("Attempted take picture with null imageCapture use case")
@@ -418,13 +535,23 @@ constructor(
             VideoCaptureControlEvent.StartRecordingEvent(
                 videoCaptureUri,
                 shouldUseUri,
+                currentSettings.value?.maxVideoDurationMillis
+                    ?: UNLIMITED_VIDEO_DURATION,
                 onVideoRecord
             )
         )
     }
 
-    override fun stopVideoRecording() {
-        videoCaptureControlEvents.trySendBlocking(VideoCaptureControlEvent.StopRecordingEvent)
+    override suspend fun pauseVideoRecording() {
+        videoCaptureControlEvents.send(VideoCaptureControlEvent.PauseRecordingEvent)
+    }
+
+    override suspend fun resumeVideoRecording() {
+        videoCaptureControlEvents.send(VideoCaptureControlEvent.ResumeRecordingEvent)
+    }
+
+    override suspend fun stopVideoRecording() {
+        videoCaptureControlEvents.send(VideoCaptureControlEvent.StopRecordingEvent)
     }
 
     override fun setZoomScale(scale: Float) {
@@ -440,14 +567,82 @@ constructor(
                 old?.copy(cameraLensFacing = lensFacing)
                     ?.tryApplyDynamicRangeConstraints()
                     ?.tryApplyImageFormatConstraints()
+                    ?.tryApplyFlashModeConstraints()
+                    ?.tryApplyCaptureModeConstraints()
             } else {
                 old
             }
         }
     }
 
-    private fun CameraAppSettings.tryApplyDynamicRangeConstraints(): CameraAppSettings {
-        return systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
+    /**
+     * Applies an appropriate Capture Mode for given settings, if necessary
+     *
+     * Should be applied whenever
+     * [tryApplyImageFormatConstraints],
+     * [tryApplyDynamicRangeConstraints],
+     * or [tryApplyConcurrentCameraModeConstraints] would be called
+     *
+     * @param defaultCaptureMode if multiple capture modes are supported by the device, this capture
+     * mode will be applied. If left null, it will not change the current capture mode.
+     */
+    private fun CameraAppSettings.tryApplyCaptureModeConstraints(
+        defaultCaptureMode: CaptureMode? = null
+    ): CameraAppSettings {
+        Log.d(TAG, "applying capture mode constraints")
+        systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
+            val newCaptureMode =
+                // concurrent currently only supports VIDEO_ONLY
+                if (concurrentCameraMode == ConcurrentCameraMode.DUAL) {
+                    CaptureMode.VIDEO_ONLY
+                } else if (imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR) {
+                    CaptureMode.IMAGE_ONLY
+                } else if (dynamicRange == DynamicRange.HLG10) {
+                    CaptureMode.VIDEO_ONLY
+                }
+                // TODO(kc): the two elif statements above should be DELETED and the block below
+                //  should be used when a dedicated capture mode button is available
+
+                /*
+                 // if hdr is enabled, select an appropriate capture mode
+                 else if (dynamicRange == DynamicRange.HLG10 ||
+                    imageFormat == ImageOutputFormat.JPEG_ULTRA_HDR
+                ) {
+                    if (constraints.supportedDynamicRanges.contains(DynamicRange.HLG10)) {
+                        if (constraints.supportedImageFormatsMap[streamConfig]
+                                ?.contains(ImageOutputFormat.JPEG_ULTRA_HDR) == true
+                        ) {
+                            // if both image/video HDR is supported, only change if STANDARD is the current capture mode.
+                            // image and video capture use cases cannot be simultaneously bound while HDR is enabled
+                            if (this.captureMode != CaptureMode.STANDARD) {
+                                this.captureMode
+                            } else {
+                                CaptureMode.VIDEO_ONLY
+                            }
+                        } else {
+                            // if only video is supported, change to video only
+                            CaptureMode.VIDEO_ONLY
+                        }
+                    } else {
+                        // if only image is supported, change to image only
+                        CaptureMode.IMAGE_ONLY
+                    }
+                }
+                 */
+                else {
+                    // if no dynamic range value is set, its OK to return the current value
+                    defaultCaptureMode ?: return this
+                }
+            Log.d(TAG, "new capture mode $newCaptureMode")
+            return this@tryApplyCaptureModeConstraints.copy(
+                captureMode = newCaptureMode
+            )
+        }
+            ?: return this
+    }
+
+    private fun CameraAppSettings.tryApplyDynamicRangeConstraints(): CameraAppSettings =
+        systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
             with(constraints.supportedDynamicRanges) {
                 val newDynamicRange = if (contains(dynamicRange)) {
                     dynamicRange
@@ -460,24 +655,20 @@ constructor(
                 )
             }
         } ?: this
-    }
 
     private fun CameraAppSettings.tryApplyAspectRatioForExternalCapture(
-        useCaseMode: CameraUseCase.UseCaseMode
-    ): CameraAppSettings {
-        return when (useCaseMode) {
-            CameraUseCase.UseCaseMode.STANDARD -> this
-            CameraUseCase.UseCaseMode.IMAGE_ONLY ->
-                this.copy(aspectRatio = AspectRatio.THREE_FOUR)
-
-            CameraUseCase.UseCaseMode.VIDEO_ONLY ->
-                this.copy(aspectRatio = AspectRatio.NINE_SIXTEEN)
-        }
+        captureMode: CaptureMode
+    ): CameraAppSettings = when (captureMode) {
+        CaptureMode.STANDARD -> this
+        CaptureMode.IMAGE_ONLY ->
+            this.copy(aspectRatio = AspectRatio.THREE_FOUR)
+        CaptureMode.VIDEO_ONLY ->
+            this.copy(aspectRatio = AspectRatio.NINE_SIXTEEN)
     }
 
-    private fun CameraAppSettings.tryApplyImageFormatConstraints(): CameraAppSettings {
-        return systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
-            with(constraints.supportedImageFormatsMap[captureMode]) {
+    private fun CameraAppSettings.tryApplyImageFormatConstraints(): CameraAppSettings =
+        systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
+            with(constraints.supportedImageFormatsMap[streamConfig]) {
                 val newImageFormat = if (this != null && contains(imageFormat)) {
                     imageFormat
                 } else {
@@ -489,10 +680,9 @@ constructor(
                 )
             }
         } ?: this
-    }
 
-    private fun CameraAppSettings.tryApplyFrameRateConstraints(): CameraAppSettings {
-        return systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
+    private fun CameraAppSettings.tryApplyFrameRateConstraints(): CameraAppSettings =
+        systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
             with(constraints.supportedFixedFrameRates) {
                 val newTargetFrameRate = if (contains(targetFrameRate)) {
                     targetFrameRate
@@ -505,34 +695,24 @@ constructor(
                 )
             }
         } ?: this
-    }
 
-    private fun CameraAppSettings.tryApplyStabilizationConstraints(): CameraAppSettings {
-        return systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
-            with(constraints.supportedStabilizationModes) {
-                val newVideoStabilization = if (contains(SupportedStabilizationMode.HIGH_QUALITY) &&
-                    (targetFrameRate != TARGET_FPS_60)
-                ) {
-                    // unlike shouldVideoBeStabilized, doesn't check value of previewStabilization
-                    videoCaptureStabilization
-                } else {
-                    Stabilization.UNDEFINED
-                }
-                val newPreviewStabilization = if (contains(SupportedStabilizationMode.ON) &&
-                    (targetFrameRate in setOf(TARGET_FPS_AUTO, TARGET_FPS_30))
+    private fun CameraAppSettings.tryApplyStabilizationConstraints(): CameraAppSettings =
+        systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
+            with(constraints) {
+                val newStabilizationMode = if (stabilizationMode != StabilizationMode.AUTO &&
+                    stabilizationMode in constraints.supportedStabilizationModes &&
+                    targetFrameRate !in stabilizationMode.unsupportedFpsSet
                 ) {
-                    previewStabilization
+                    stabilizationMode
                 } else {
-                    Stabilization.UNDEFINED
+                    StabilizationMode.AUTO
                 }
 
                 this@tryApplyStabilizationConstraints.copy(
-                    previewStabilization = newPreviewStabilization,
-                    videoCaptureStabilization = newVideoStabilization
+                    stabilizationMode = newStabilizationMode
                 )
             }
         } ?: this
-    }
 
     private fun CameraAppSettings.tryApplyConcurrentCameraModeConstraints(): CameraAppSettings =
         when (concurrentCameraMode) {
@@ -541,16 +721,48 @@ constructor(
                 if (systemConstraints.concurrentCamerasSupported) {
                     copy(
                         targetFrameRate = TARGET_FPS_AUTO,
-                        previewStabilization = Stabilization.OFF,
-                        videoCaptureStabilization = Stabilization.OFF,
                         dynamicRange = DynamicRange.SDR,
-                        captureMode = CaptureMode.MULTI_STREAM
+                        streamConfig = StreamConfig.MULTI_STREAM
                     )
                 } else {
                     copy(concurrentCameraMode = ConcurrentCameraMode.OFF)
                 }
         }
 
+    private fun CameraAppSettings.tryApplyVideoQualityConstraints(): CameraAppSettings =
+        systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
+            with(constraints.supportedVideoQualitiesMap) {
+                val newVideoQuality = get(dynamicRange).let {
+                    if (it == null) {
+                        VideoQuality.UNSPECIFIED
+                    } else if (it.contains(videoQuality)) {
+                        videoQuality
+                    } else {
+                        VideoQuality.UNSPECIFIED
+                    }
+                }
+
+                this@tryApplyVideoQualityConstraints.copy(
+                    videoQuality = newVideoQuality
+                )
+            }
+        } ?: this
+
+    private fun CameraAppSettings.tryApplyFlashModeConstraints(): CameraAppSettings =
+        systemConstraints.perLensConstraints[cameraLensFacing]?.let { constraints ->
+            with(constraints.supportedFlashModes) {
+                val newFlashMode = if (contains(flashMode)) {
+                    flashMode
+                } else {
+                    FlashMode.OFF
+                }
+
+                this@tryApplyFlashModeConstraints.copy(
+                    flashMode = newFlashMode
+                )
+            }
+        } ?: this
+
     override suspend fun tapToFocus(x: Float, y: Float) {
         focusMeteringEvents.send(CameraEvent.FocusMeteringEvent(x, y))
     }
@@ -574,11 +786,19 @@ constructor(
         }
     }
 
-    override suspend fun setCaptureMode(captureMode: CaptureMode) {
+    override suspend fun setVideoQuality(videoQuality: VideoQuality) {
         currentSettings.update { old ->
-            old?.copy(captureMode = captureMode)
+            old?.copy(videoQuality = videoQuality)
+                ?.tryApplyVideoQualityConstraints()
+        }
+    }
+
+    override suspend fun setStreamConfig(streamConfig: StreamConfig) {
+        currentSettings.update { old ->
+            old?.copy(streamConfig = streamConfig)
                 ?.tryApplyImageFormatConstraints()
                 ?.tryApplyConcurrentCameraModeConstraints()
+                ?.tryApplyVideoQualityConstraints()
         }
     }
 
@@ -586,6 +806,7 @@ constructor(
         currentSettings.update { old ->
             old?.copy(dynamicRange = dynamicRange)
                 ?.tryApplyConcurrentCameraModeConstraints()
+                ?.tryApplyCaptureModeConstraints(CaptureMode.STANDARD)
         }
     }
 
@@ -599,30 +820,28 @@ constructor(
         currentSettings.update { old ->
             old?.copy(concurrentCameraMode = concurrentCameraMode)
                 ?.tryApplyConcurrentCameraModeConstraints()
+                ?.tryApplyCaptureModeConstraints(CaptureMode.STANDARD)
         }
     }
 
     override suspend fun setImageFormat(imageFormat: ImageOutputFormat) {
         currentSettings.update { old ->
             old?.copy(imageFormat = imageFormat)
+                ?.tryApplyCaptureModeConstraints(CaptureMode.STANDARD)
         }
     }
 
-    override suspend fun setPreviewStabilization(previewStabilization: Stabilization) {
+    override suspend fun setMaxVideoDuration(durationInMillis: Long) {
         currentSettings.update { old ->
             old?.copy(
-                previewStabilization = previewStabilization
-            )?.tryApplyStabilizationConstraints()
-                ?.tryApplyConcurrentCameraModeConstraints()
+                maxVideoDurationMillis = durationInMillis
+            )
         }
     }
 
-    override suspend fun setVideoCaptureStabilization(videoCaptureStabilization: Stabilization) {
+    override suspend fun setStabilizationMode(stabilizationMode: StabilizationMode) {
         currentSettings.update { old ->
-            old?.copy(
-                videoCaptureStabilization = videoCaptureStabilization
-            )?.tryApplyStabilizationConstraints()
-                ?.tryApplyConcurrentCameraModeConstraints()
+            old?.copy(stabilizationMode = stabilizationMode)
         }
     }
 
@@ -633,15 +852,15 @@ constructor(
         }
     }
 
-    override suspend fun setLowLightBoost(lowLightBoost: LowLightBoost) {
+    override suspend fun setAudioEnabled(isAudioEnabled: Boolean) {
         currentSettings.update { old ->
-            old?.copy(lowLightBoost = lowLightBoost)
+            old?.copy(audioEnabled = isAudioEnabled)
         }
     }
 
-    override suspend fun setAudioMuted(isAudioMuted: Boolean) {
+    override suspend fun setCaptureMode(captureMode: CaptureMode) {
         currentSettings.update { old ->
-            old?.copy(audioMuted = isAudioMuted)
+            old?.copy(captureMode = captureMode)
         }
     }
 
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/ConcurrentCameraSession.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/ConcurrentCameraSession.kt
index 1ea84a1..61b4d11 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/ConcurrentCameraSession.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/ConcurrentCameraSession.kt
@@ -20,9 +20,11 @@ import android.util.Log
 import androidx.camera.core.CompositionSettings
 import androidx.camera.core.TorchState
 import androidx.lifecycle.asFlow
+import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.VideoQuality
 import kotlinx.coroutines.coroutineScope
 import kotlinx.coroutines.flow.collectLatest
 import kotlinx.coroutines.flow.filterNotNull
@@ -35,8 +37,7 @@ private const val TAG = "ConcurrentCameraSession"
 context(CameraSessionContext)
 @SuppressLint("RestrictedApi")
 internal suspend fun runConcurrentCameraSession(
-    sessionSettings: PerpetualSessionSettings.ConcurrentCamera,
-    useCaseMode: CameraUseCase.UseCaseMode
+    sessionSettings: PerpetualSessionSettings.ConcurrentCamera
 ) = coroutineScope {
     val primaryLensFacing = sessionSettings.primaryCameraInfo.appLensFacing
     val secondaryLensFacing = sessionSettings.secondaryCameraInfo.appLensFacing
@@ -50,16 +51,31 @@ internal suspend fun runConcurrentCameraSession(
         .filterNotNull()
         .first()
 
+    val videoCapture = if (sessionSettings.captureMode != CaptureMode.IMAGE_ONLY) {
+        createVideoUseCase(
+            cameraProvider.getCameraInfo(
+                initialTransientSettings.primaryLensFacing.toCameraSelector()
+            ),
+            sessionSettings.aspectRatio,
+            TARGET_FPS_AUTO,
+            StabilizationMode.OFF,
+            DynamicRange.SDR,
+            VideoQuality.UNSPECIFIED,
+            backgroundDispatcher
+        )
+    } else {
+        null
+    }
+
     val useCaseGroup = createUseCaseGroup(
         cameraInfo = sessionSettings.primaryCameraInfo,
         initialTransientSettings = initialTransientSettings,
-        stabilizePreviewMode = Stabilization.OFF,
-        stabilizeVideoMode = Stabilization.OFF,
+        stabilizationMode = StabilizationMode.OFF,
         aspectRatio = sessionSettings.aspectRatio,
-        targetFrameRate = TARGET_FPS_AUTO,
         dynamicRange = DynamicRange.SDR,
         imageFormat = ImageOutputFormat.JPEG,
-        useCaseMode = useCaseMode
+        captureMode = sessionSettings.captureMode,
+        videoCaptureUseCase = videoCapture
     )
 
     val cameraConfigs = listOf(
@@ -93,7 +109,6 @@ internal suspend fun runConcurrentCameraSession(
 
         launch {
             processVideoControlEvents(
-                primaryCamera,
                 useCaseGroup.getVideoCapture(),
                 captureTypeSuffix = "DualCam"
             )
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/VideoCaptureControlEvent.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/VideoCaptureControlEvent.kt
index 822c5cd..1132d8e 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/VideoCaptureControlEvent.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/VideoCaptureControlEvent.kt
@@ -30,9 +30,20 @@ sealed interface VideoCaptureControlEvent {
     class StartRecordingEvent(
         val videoCaptureUri: Uri?,
         val shouldUseUri: Boolean,
+        val maxVideoDuration: Long,
         val onVideoRecord: (CameraUseCase.OnVideoRecordEvent) -> Unit
     ) : VideoCaptureControlEvent
 
+    /**
+     * Pauses a video recording.
+     */
+    data object PauseRecordingEvent : VideoCaptureControlEvent
+
+    /**
+     * Resumes a paused video recording.
+     */
+    data object ResumeRecordingEvent : VideoCaptureControlEvent
+
     /**
      * Stops video recording.
      */
diff --git a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCase.kt b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCase.kt
index f865a63..ddd5174 100644
--- a/core/camera/src/main/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCase.kt
+++ b/core/camera/src/main/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCase.kt
@@ -31,8 +31,9 @@ import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.LowLightBoost
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.StreamConfig
+import com.google.jetpackcamera.settings.model.VideoQuality
 import kotlinx.coroutines.channels.Channel
 import kotlinx.coroutines.channels.Channel.Factory.UNLIMITED
 import kotlinx.coroutines.flow.MutableStateFlow
@@ -42,9 +43,8 @@ import kotlinx.coroutines.flow.collectLatest
 import kotlinx.coroutines.flow.onCompletion
 import kotlinx.coroutines.flow.update
 
-class FakeCameraUseCase(
-    defaultCameraSettings: CameraAppSettings = CameraAppSettings()
-) : CameraUseCase {
+class FakeCameraUseCase(defaultCameraSettings: CameraAppSettings = CameraAppSettings()) :
+    CameraUseCase {
     private val availableLenses = listOf(LensFacing.FRONT, LensFacing.BACK)
     private var initialized = false
     private var useCasesBinded = false
@@ -53,6 +53,7 @@ class FakeCameraUseCase(
     var numPicturesTaken = 0
 
     var recordingInProgress = false
+    var isRecordingPaused = false
 
     var isLensFacingFront = false
 
@@ -63,8 +64,8 @@ class FakeCameraUseCase(
 
     override suspend fun initialize(
         cameraAppSettings: CameraAppSettings,
-        useCaseMode: CameraUseCase.UseCaseMode,
-        isDebugMode: Boolean
+        isDebugMode: Boolean,
+        cameraPropertiesJSONCallback: (result: String) -> Unit
     ) {
         initialized = true
     }
@@ -92,10 +93,6 @@ class FakeCameraUseCase(
                 isScreenFlash =
                     isLensFacingFront &&
                     (it.flashMode == FlashMode.AUTO || it.flashMode == FlashMode.ON)
-
-                _currentCameraState.update { old ->
-                    old.copy(zoomScale = it.zoomScale)
-                }
             }
     }
 
@@ -140,7 +137,15 @@ class FakeCameraUseCase(
         recordingInProgress = true
     }
 
-    override fun stopVideoRecording() {
+    override suspend fun pauseVideoRecording() {
+        isRecordingPaused = true
+    }
+
+    override suspend fun resumeVideoRecording() {
+        isRecordingPaused = false
+    }
+
+    override suspend fun stopVideoRecording() {
         recordingInProgress = false
     }
 
@@ -174,6 +179,12 @@ class FakeCameraUseCase(
         }
     }
 
+    override suspend fun setVideoQuality(videoQuality: VideoQuality) {
+        currentSettings.update { old ->
+            old.copy(videoQuality = videoQuality)
+        }
+    }
+
     override suspend fun setLensFacing(lensFacing: LensFacing) {
         currentSettings.update { old ->
             old.copy(cameraLensFacing = lensFacing)
@@ -184,9 +195,9 @@ class FakeCameraUseCase(
         TODO("Not yet implemented")
     }
 
-    override suspend fun setCaptureMode(captureMode: CaptureMode) {
+    override suspend fun setStreamConfig(streamConfig: StreamConfig) {
         currentSettings.update { old ->
-            old.copy(captureMode = captureMode)
+            old.copy(streamConfig = streamConfig)
         }
     }
 
@@ -214,33 +225,33 @@ class FakeCameraUseCase(
         }
     }
 
-    override suspend fun setLowLightBoost(lowLightBoost: LowLightBoost) {
+    override suspend fun setAudioEnabled(isAudioEnabled: Boolean) {
         currentSettings.update { old ->
-            old.copy(lowLightBoost = lowLightBoost)
+            old.copy(audioEnabled = isAudioEnabled)
         }
     }
 
-    override suspend fun setAudioMuted(isAudioMuted: Boolean) {
+    override suspend fun setStabilizationMode(stabilizationMode: StabilizationMode) {
         currentSettings.update { old ->
-            old.copy(audioMuted = isAudioMuted)
+            old.copy(stabilizationMode = stabilizationMode)
         }
     }
 
-    override suspend fun setVideoCaptureStabilization(videoCaptureStabilization: Stabilization) {
+    override suspend fun setTargetFrameRate(targetFrameRate: Int) {
         currentSettings.update { old ->
-            old.copy(videoCaptureStabilization = videoCaptureStabilization)
+            old.copy(targetFrameRate = targetFrameRate)
         }
     }
 
-    override suspend fun setPreviewStabilization(previewStabilization: Stabilization) {
+    override suspend fun setMaxVideoDuration(durationInMillis: Long) {
         currentSettings.update { old ->
-            old.copy(previewStabilization = previewStabilization)
+            old.copy(maxVideoDurationMillis = durationInMillis)
         }
     }
 
-    override suspend fun setTargetFrameRate(targetFrameRate: Int) {
+    override suspend fun setCaptureMode(captureMode: CaptureMode) {
         currentSettings.update { old ->
-            old.copy(targetFrameRate = targetFrameRate)
+            old.copy(captureMode = captureMode)
         }
     }
 }
diff --git a/core/camera/src/test/Android.bp b/core/camera/src/test/Android.bp
index b969779..b748431 100644
--- a/core/camera/src/test/Android.bp
+++ b/core/camera/src/test/Android.bp
@@ -4,7 +4,7 @@ package {
 
 java_test {
     name: "jetpack-camera-app_core_camera-tests",
-    team: "trendy_team_camerax",
+    team: "trendy_team_android_camera_innovation_team",
     srcs: ["java/**/*.kt"],
     static_libs: [
         "androidx.test.runner",
diff --git a/core/camera/src/test/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCaseTest.kt b/core/camera/src/test/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCaseTest.kt
index 00cedf3..09f9d2f 100644
--- a/core/camera/src/test/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCaseTest.kt
+++ b/core/camera/src/test/java/com/google/jetpackcamera/core/camera/test/FakeCameraUseCaseTest.kt
@@ -56,9 +56,8 @@ class FakeCameraUseCaseTest {
     @Test
     fun canInitialize() = runTest(testDispatcher) {
         cameraUseCase.initialize(
-            cameraAppSettings = DEFAULT_CAMERA_APP_SETTINGS,
-            useCaseMode = CameraUseCase.UseCaseMode.STANDARD
-        )
+            cameraAppSettings = DEFAULT_CAMERA_APP_SETTINGS
+        ) {}
     }
 
     @Test
@@ -150,9 +149,8 @@ class FakeCameraUseCaseTest {
     private fun TestScope.initAndRunCamera() {
         backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
             cameraUseCase.initialize(
-                cameraAppSettings = DEFAULT_CAMERA_APP_SETTINGS,
-                useCaseMode = CameraUseCase.UseCaseMode.STANDARD
-            )
+                cameraAppSettings = DEFAULT_CAMERA_APP_SETTINGS
+            ) {}
             cameraUseCase.runCamera()
         }
     }
diff --git a/core/common/build.gradle.kts b/core/common/build.gradle.kts
index 2a81639..185217b 100644
--- a/core/common/build.gradle.kts
+++ b/core/common/build.gradle.kts
@@ -24,7 +24,6 @@ plugins {
 android {
     namespace = "com.google.jetpackcamera.core.common"
     compileSdk = libs.versions.compileSdk.get().toInt()
-    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     defaultConfig {
         minSdk = libs.versions.minSdk.get().toInt()
@@ -53,11 +52,6 @@ android {
             dimension = "flavor"
             isDefault = true
         }
-
-        create("preview") {
-            dimension = "flavor"
-            targetSdkPreview = libs.versions.targetSdkPreview.get()
-        }
     }
 
     compileOptions {
@@ -73,7 +67,6 @@ dependencies {
 
     implementation(libs.androidx.core.ktx)
     implementation(libs.androidx.appcompat)
-    implementation(libs.android.material)
     implementation(libs.kotlinx.atomicfu)
     implementation(libs.androidx.tracing)
 
diff --git a/core/common/src/main/AndroidManifest.xml b/core/common/src/main/AndroidManifest.xml
index 1609b38..180435b 100644
--- a/core/common/src/main/AndroidManifest.xml
+++ b/core/common/src/main/AndroidManifest.xml
@@ -16,4 +16,4 @@
   -->
 <manifest package="com.google.jetpackcamera.core.common">
 
-</manifest>
+</manifest>
\ No newline at end of file
diff --git a/core/common/src/main/java/com/google/jetpackcamera/core/common/MediaStoreUtils.kt b/core/common/src/main/java/com/google/jetpackcamera/core/common/MediaStoreUtils.kt
new file mode 100644
index 0000000..f760452
--- /dev/null
+++ b/core/common/src/main/java/com/google/jetpackcamera/core/common/MediaStoreUtils.kt
@@ -0,0 +1,100 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.google.jetpackcamera.core.common
+
+import android.content.ContentUris
+import android.content.Context
+import android.graphics.Bitmap
+import android.graphics.ImageDecoder
+import android.graphics.Matrix
+import android.net.Uri
+import android.provider.MediaStore
+import java.io.File
+import java.io.FileNotFoundException
+
+/**
+ * Retrieves the URI for the most recently added image whose filename starts with "JCA".
+ *
+ * @param context The application context.
+ * @return The content URI of the matching image, or null if none is found.
+ */
+fun getLastImageUri(context: Context): Uri? {
+    val projection = arrayOf(
+        MediaStore.Images.Media._ID,
+        MediaStore.Images.Media.DATE_ADDED
+    )
+
+    // Filter by filenames starting with "JCA"
+    val selection = "${MediaStore.Images.Media.DISPLAY_NAME} LIKE ?"
+    val selectionArgs = arrayOf("JCA%")
+
+    // Sort the results so that the most recently added image appears first.
+    val sortOrder = "${MediaStore.Images.Media.DATE_ADDED} DESC"
+
+    // Perform the query on the MediaStore.
+    context.contentResolver.query(
+        MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
+        projection,
+        selection,
+        selectionArgs,
+        sortOrder
+    )?.use { cursor ->
+        if (cursor.moveToFirst()) {
+            val idColumn = cursor.getColumnIndexOrThrow(MediaStore.Images.Media._ID)
+            val id = cursor.getLong(idColumn)
+
+            return ContentUris.withAppendedId(
+                MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
+                id
+            )
+        }
+    }
+    return null
+}
+
+/**
+ * Loads a Bitmap from a given URI and rotates it by the specified degrees.
+ *
+ * @param context The application context.
+ * @param uri The URI of the image to load.
+ * @param degrees The number of degrees to rotate the image by.
+ */
+fun loadAndRotateBitmap(context: Context, uri: Uri?, degrees: Float): Bitmap? {
+    uri ?: return null
+
+    if (uri.scheme == "file") {
+        val file = File(uri.path ?: "")
+        if (!file.exists()) {
+            return null
+        }
+    }
+
+    return try {
+        val bitmap = if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.P) {
+            MediaStore.Images.Media.getBitmap(context.contentResolver, uri)
+        } else {
+            val imageDecoderSource = ImageDecoder.createSource(context.contentResolver, uri)
+            ImageDecoder.decodeBitmap(imageDecoderSource)
+        }
+
+        bitmap?.let {
+            val matrix = Matrix().apply { postRotate(degrees) }
+            Bitmap.createBitmap(it, 0, 0, it.width, it.height, matrix, true)
+        }
+    } catch (e: FileNotFoundException) {
+        null
+    }
+}
diff --git a/data/settings/build.gradle.kts b/data/settings/build.gradle.kts
index e0edd40..08849be 100644
--- a/data/settings/build.gradle.kts
+++ b/data/settings/build.gradle.kts
@@ -25,7 +25,6 @@ plugins {
 android {
     namespace = "com.google.jetpackcamera.data.settings"
     compileSdk = libs.versions.compileSdk.get().toInt()
-    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     defaultConfig {
         minSdk = libs.versions.minSdk.get().toInt()
@@ -42,11 +41,6 @@ android {
             dimension = "flavor"
             isDefault = true
         }
-
-        create("preview") {
-            dimension = "flavor"
-            targetSdkPreview = libs.versions.targetSdkPreview.get()
-        }
     }
 
     compileOptions {
@@ -101,7 +95,7 @@ protobuf {
     }
 
     generateProtoTasks {
-        all().forEach {task ->
+        all().forEach { task ->
             task.builtins {
                 create("java") {
                     option("lite")
diff --git a/data/settings/src/androidTest/java/com/google/jetpackcamera/settings/DataStoreModuleTest.kt b/data/settings/src/androidTest/java/com/google/jetpackcamera/settings/DataStoreModuleTest.kt
index f8862b8..a6093dc 100644
--- a/data/settings/src/androidTest/java/com/google/jetpackcamera/settings/DataStoreModuleTest.kt
+++ b/data/settings/src/androidTest/java/com/google/jetpackcamera/settings/DataStoreModuleTest.kt
@@ -46,7 +46,7 @@ class DataStoreModuleTest {
     fun dataStoreModule_read_can_handle_corrupted_file() = runTest {
         // should handle exception and replace file information
         val dataStore: DataStore<JcaSettings> = FakeDataStoreModule.provideDataStore(
-            scope = this,
+            scope = this.backgroundScope,
             serializer = FakeJcaSettingsSerializer(failReadWithCorruptionException = true),
             file = testFile
         )
diff --git a/data/settings/src/main/AndroidManifest.xml b/data/settings/src/main/AndroidManifest.xml
index da78212..78846e7 100644
--- a/data/settings/src/main/AndroidManifest.xml
+++ b/data/settings/src/main/AndroidManifest.xml
@@ -16,4 +16,4 @@
   -->
 <manifest package="com.google.jetpackcamera.data.settings">
 
-</manifest>
+</manifest>
\ No newline at end of file
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/JcaSettingsSerializer.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/JcaSettingsSerializer.kt
index 1a07af2..489ac01 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/JcaSettingsSerializer.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/JcaSettingsSerializer.kt
@@ -20,7 +20,11 @@ import androidx.datastore.core.Serializer
 import com.google.protobuf.InvalidProtocolBufferException
 import java.io.InputStream
 import java.io.OutputStream
-
+/**
+ * This constant is `0L` because the `DURATION_UNLIMITED`
+ * constant in the `OutputOptions` API [documentation](https://developer.android.com/reference/androidx/camera/video/OutputOptions#DURATION_UNLIMITED()) is `0`.
+ */
+const val UNLIMITED_VIDEO_DURATION = 0L
 object JcaSettingsSerializer : Serializer<JcaSettings> {
 
     override val defaultValue: JcaSettings = JcaSettings.newBuilder()
@@ -28,11 +32,13 @@ object JcaSettingsSerializer : Serializer<JcaSettings> {
         .setDefaultLensFacing(LensFacing.LENS_FACING_BACK)
         .setFlashModeStatus(FlashMode.FLASH_MODE_OFF)
         .setAspectRatioStatus(AspectRatio.ASPECT_RATIO_NINE_SIXTEEN)
-        .setCaptureModeStatus(CaptureMode.CAPTURE_MODE_MULTI_STREAM)
-        .setStabilizePreview(PreviewStabilization.PREVIEW_STABILIZATION_UNDEFINED)
-        .setStabilizeVideo(VideoStabilization.VIDEO_STABILIZATION_UNDEFINED)
+        .setStreamConfigStatus(StreamConfig.STREAM_CONFIG_MULTI_STREAM)
+        .setStabilizationMode(StabilizationMode.STABILIZATION_MODE_AUTO)
         .setDynamicRangeStatus(DynamicRange.DYNAMIC_RANGE_UNSPECIFIED)
         .setImageFormatStatus(ImageOutputFormat.IMAGE_OUTPUT_FORMAT_JPEG)
+        .setMaxVideoDurationMillis(UNLIMITED_VIDEO_DURATION)
+        .setVideoQuality(VideoQuality.VIDEO_QUALITY_UNSPECIFIED)
+        .setAudioEnabledStatus(true)
         .build()
 
     override suspend fun readFrom(input: InputStream): JcaSettings {
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/LocalSettingsRepository.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/LocalSettingsRepository.kt
index fb10dc2..39fafe3 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/LocalSettingsRepository.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/LocalSettingsRepository.kt
@@ -17,14 +17,12 @@ package com.google.jetpackcamera.settings
 
 import androidx.datastore.core.DataStore
 import com.google.jetpackcamera.settings.AspectRatio as AspectRatioProto
-import com.google.jetpackcamera.settings.CaptureMode as CaptureModeProto
 import com.google.jetpackcamera.settings.DarkMode as DarkModeProto
 import com.google.jetpackcamera.settings.FlashMode as FlashModeProto
-import com.google.jetpackcamera.settings.PreviewStabilization as PreviewStabilizationProto
-import com.google.jetpackcamera.settings.VideoStabilization as VideoStabilizationProto
+import com.google.jetpackcamera.settings.StabilizationMode as StabilizationModeProto
+import com.google.jetpackcamera.settings.StreamConfig as StreamConfigProto
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CameraAppSettings
-import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.DynamicRange.Companion.toProto
@@ -33,20 +31,19 @@ import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.ImageOutputFormat.Companion.toProto
 import com.google.jetpackcamera.settings.model.LensFacing
 import com.google.jetpackcamera.settings.model.LensFacing.Companion.toProto
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.StreamConfig
+import com.google.jetpackcamera.settings.model.VideoQuality
+import com.google.jetpackcamera.settings.model.VideoQuality.Companion.toProto
 import javax.inject.Inject
 import kotlinx.coroutines.flow.first
 import kotlinx.coroutines.flow.map
 
-const val TARGET_FPS_15 = 15
-const val TARGET_FPS_60 = 60
-
 /**
  * Implementation of [SettingsRepository] with locally stored settings.
  */
-class LocalSettingsRepository @Inject constructor(
-    private val jcaSettings: DataStore<JcaSettings>
-) : SettingsRepository {
+class LocalSettingsRepository @Inject constructor(private val jcaSettings: DataStore<JcaSettings>) :
+    SettingsRepository {
 
     override val defaultCameraAppSettings = jcaSettings.data
         .map {
@@ -62,19 +59,22 @@ class LocalSettingsRepository @Inject constructor(
                     FlashModeProto.FLASH_MODE_AUTO -> FlashMode.AUTO
                     FlashModeProto.FLASH_MODE_ON -> FlashMode.ON
                     FlashModeProto.FLASH_MODE_OFF -> FlashMode.OFF
+                    FlashModeProto.FLASH_MODE_LOW_LIGHT_BOOST -> FlashMode.LOW_LIGHT_BOOST
                     else -> FlashMode.OFF
                 },
                 aspectRatio = AspectRatio.fromProto(it.aspectRatioStatus),
-                previewStabilization = Stabilization.fromProto(it.stabilizePreview),
-                videoCaptureStabilization = Stabilization.fromProto(it.stabilizeVideo),
+                stabilizationMode = StabilizationMode.fromProto(it.stabilizationMode),
                 targetFrameRate = it.targetFrameRate,
-                captureMode = when (it.captureModeStatus) {
-                    CaptureModeProto.CAPTURE_MODE_SINGLE_STREAM -> CaptureMode.SINGLE_STREAM
-                    CaptureModeProto.CAPTURE_MODE_MULTI_STREAM -> CaptureMode.MULTI_STREAM
-                    else -> CaptureMode.MULTI_STREAM
+                streamConfig = when (it.streamConfigStatus) {
+                    StreamConfigProto.STREAM_CONFIG_SINGLE_STREAM -> StreamConfig.SINGLE_STREAM
+                    StreamConfigProto.STREAM_CONFIG_MULTI_STREAM -> StreamConfig.MULTI_STREAM
+                    else -> StreamConfig.MULTI_STREAM
                 },
                 dynamicRange = DynamicRange.fromProto(it.dynamicRangeStatus),
-                imageFormat = ImageOutputFormat.fromProto(it.imageFormatStatus)
+                imageFormat = ImageOutputFormat.fromProto(it.imageFormatStatus),
+                maxVideoDurationMillis = it.maxVideoDurationMillis,
+                videoQuality = VideoQuality.fromProto(it.videoQuality),
+                audioEnabled = it.audioEnabledStatus
             )
         }
 
@@ -107,6 +107,7 @@ class LocalSettingsRepository @Inject constructor(
             FlashMode.AUTO -> FlashModeProto.FLASH_MODE_AUTO
             FlashMode.ON -> FlashModeProto.FLASH_MODE_ON
             FlashMode.OFF -> FlashModeProto.FLASH_MODE_OFF
+            FlashMode.LOW_LIGHT_BOOST -> FlashModeProto.FLASH_MODE_LOW_LIGHT_BOOST
         }
         jcaSettings.updateData { currentSettings ->
             currentSettings.toBuilder()
@@ -136,56 +137,68 @@ class LocalSettingsRepository @Inject constructor(
         }
     }
 
-    override suspend fun updateCaptureMode(captureMode: CaptureMode) {
-        val newStatus = when (captureMode) {
-            CaptureMode.MULTI_STREAM -> CaptureModeProto.CAPTURE_MODE_MULTI_STREAM
-            CaptureMode.SINGLE_STREAM -> CaptureModeProto.CAPTURE_MODE_SINGLE_STREAM
+    override suspend fun updateStreamConfig(streamConfig: StreamConfig) {
+        val newStatus = when (streamConfig) {
+            StreamConfig.MULTI_STREAM -> StreamConfigProto.STREAM_CONFIG_MULTI_STREAM
+            StreamConfig.SINGLE_STREAM -> StreamConfigProto.STREAM_CONFIG_SINGLE_STREAM
         }
         jcaSettings.updateData { currentSettings ->
             currentSettings.toBuilder()
-                .setCaptureModeStatus(newStatus)
+                .setStreamConfigStatus(newStatus)
                 .build()
         }
     }
 
-    override suspend fun updatePreviewStabilization(stabilization: Stabilization) {
-        val newStatus = when (stabilization) {
-            Stabilization.ON -> PreviewStabilizationProto.PREVIEW_STABILIZATION_ON
-            Stabilization.OFF -> PreviewStabilizationProto.PREVIEW_STABILIZATION_OFF
-            else -> PreviewStabilizationProto.PREVIEW_STABILIZATION_UNDEFINED
+    override suspend fun updateStabilizationMode(stabilizationMode: StabilizationMode) {
+        val newStatus = when (stabilizationMode) {
+            StabilizationMode.OFF -> StabilizationModeProto.STABILIZATION_MODE_OFF
+            StabilizationMode.AUTO -> StabilizationModeProto.STABILIZATION_MODE_AUTO
+            StabilizationMode.ON -> StabilizationModeProto.STABILIZATION_MODE_ON
+            StabilizationMode.HIGH_QUALITY -> StabilizationModeProto.STABILIZATION_MODE_HIGH_QUALITY
+            StabilizationMode.OPTICAL -> StabilizationModeProto.STABILIZATION_MODE_OPTICAL
         }
         jcaSettings.updateData { currentSettings ->
             currentSettings.toBuilder()
-                .setStabilizePreview(newStatus)
+                .setStabilizationMode(newStatus)
                 .build()
         }
     }
 
-    override suspend fun updateVideoStabilization(stabilization: Stabilization) {
-        val newStatus = when (stabilization) {
-            Stabilization.ON -> VideoStabilizationProto.VIDEO_STABILIZATION_ON
-            Stabilization.OFF -> VideoStabilizationProto.VIDEO_STABILIZATION_OFF
-            else -> VideoStabilizationProto.VIDEO_STABILIZATION_UNDEFINED
+    override suspend fun updateDynamicRange(dynamicRange: DynamicRange) {
+        jcaSettings.updateData { currentSettings ->
+            currentSettings.toBuilder()
+                .setDynamicRangeStatus(dynamicRange.toProto())
+                .build()
         }
+    }
+
+    override suspend fun updateImageFormat(imageFormat: ImageOutputFormat) {
         jcaSettings.updateData { currentSettings ->
             currentSettings.toBuilder()
-                .setStabilizeVideo(newStatus)
+                .setImageFormatStatus(imageFormat.toProto())
+                .build()
+        }
+    }
+    override suspend fun updateMaxVideoDuration(durationMillis: Long) {
+        jcaSettings.updateData { currentSettings ->
+            currentSettings.toBuilder()
+                .setMaxVideoDurationMillis(durationMillis)
                 .build()
         }
     }
 
-    override suspend fun updateDynamicRange(dynamicRange: DynamicRange) {
+    override suspend fun updateVideoQuality(videoQuality: VideoQuality) {
         jcaSettings.updateData { currentSettings ->
             currentSettings.toBuilder()
-                .setDynamicRangeStatus(dynamicRange.toProto())
+                .setVideoQuality(videoQuality.toProto())
                 .build()
         }
     }
 
-    override suspend fun updateImageFormat(imageFormat: ImageOutputFormat) {
+    override suspend fun updateAudioEnabled(isAudioEnabled: Boolean) {
         jcaSettings.updateData { currentSettings ->
             currentSettings.toBuilder()
-                .setImageFormatStatus(imageFormat.toProto())
+                .setAudioEnabledStatus(isAudioEnabled)
                 .build()
         }
     }
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/SettingsRepository.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/SettingsRepository.kt
index 2631d7f..2401968 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/SettingsRepository.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/SettingsRepository.kt
@@ -17,13 +17,14 @@ package com.google.jetpackcamera.settings
 
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CameraAppSettings
-import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.StreamConfig
+import com.google.jetpackcamera.settings.model.VideoQuality
 import kotlinx.coroutines.flow.Flow
 
 /**
@@ -43,15 +44,19 @@ interface SettingsRepository {
 
     suspend fun updateAspectRatio(aspectRatio: AspectRatio)
 
-    suspend fun updateCaptureMode(captureMode: CaptureMode)
+    suspend fun updateStreamConfig(streamConfig: StreamConfig)
 
-    suspend fun updatePreviewStabilization(stabilization: Stabilization)
-
-    suspend fun updateVideoStabilization(stabilization: Stabilization)
+    suspend fun updateStabilizationMode(stabilizationMode: StabilizationMode)
 
     suspend fun updateDynamicRange(dynamicRange: DynamicRange)
 
     suspend fun updateTargetFrameRate(targetFrameRate: Int)
 
     suspend fun updateImageFormat(imageFormat: ImageOutputFormat)
+
+    suspend fun updateMaxVideoDuration(durationMillis: Long)
+
+    suspend fun updateVideoQuality(videoQuality: VideoQuality)
+
+    suspend fun updateAudioEnabled(isAudioEnabled: Boolean)
 }
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraAppSettings.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraAppSettings.kt
index 1daa078..494ed5b 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraAppSettings.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CameraAppSettings.kt
@@ -14,33 +14,35 @@
  * limitations under the License.
  */
 package com.google.jetpackcamera.settings.model
+
 const val TARGET_FPS_AUTO = 0
+const val UNLIMITED_VIDEO_DURATION = 0L
+val DEFAULT_HDR_DYNAMIC_RANGE = DynamicRange.HLG10
+val DEFAULT_HDR_IMAGE_OUTPUT = ImageOutputFormat.JPEG_ULTRA_HDR
 
 /**
  * Data layer representation for settings.
  */
 data class CameraAppSettings(
+    val captureMode: CaptureMode = CaptureMode.STANDARD,
     val cameraLensFacing: LensFacing = LensFacing.BACK,
     val darkMode: DarkMode = DarkMode.SYSTEM,
     val flashMode: FlashMode = FlashMode.OFF,
-    val captureMode: CaptureMode = CaptureMode.MULTI_STREAM,
+    val streamConfig: StreamConfig = StreamConfig.MULTI_STREAM,
     val aspectRatio: AspectRatio = AspectRatio.NINE_SIXTEEN,
-    val previewStabilization: Stabilization = Stabilization.UNDEFINED,
-    val videoCaptureStabilization: Stabilization = Stabilization.UNDEFINED,
+    val stabilizationMode: StabilizationMode = StabilizationMode.AUTO,
     val dynamicRange: DynamicRange = DynamicRange.SDR,
-    val defaultHdrDynamicRange: DynamicRange = DynamicRange.HLG10,
-    val defaultHdrImageOutputFormat: ImageOutputFormat = ImageOutputFormat.JPEG_ULTRA_HDR,
-    val lowLightBoost: LowLightBoost = LowLightBoost.DISABLED,
+    val videoQuality: VideoQuality = VideoQuality.UNSPECIFIED,
     val zoomScale: Float = 1f,
     val targetFrameRate: Int = TARGET_FPS_AUTO,
     val imageFormat: ImageOutputFormat = ImageOutputFormat.JPEG,
-    val audioMuted: Boolean = false,
+    val audioEnabled: Boolean = true,
     val deviceRotation: DeviceRotation = DeviceRotation.Natural,
-    val concurrentCameraMode: ConcurrentCameraMode = ConcurrentCameraMode.OFF
+    val concurrentCameraMode: ConcurrentCameraMode = ConcurrentCameraMode.OFF,
+    val maxVideoDurationMillis: Long = UNLIMITED_VIDEO_DURATION
 )
 
-fun SystemConstraints.forCurrentLens(cameraAppSettings: CameraAppSettings): CameraConstraints? {
-    return perLensConstraints[cameraAppSettings.cameraLensFacing]
-}
+fun SystemConstraints.forCurrentLens(cameraAppSettings: CameraAppSettings): CameraConstraints? =
+    perLensConstraints[cameraAppSettings.cameraLensFacing]
 
 val DEFAULT_CAMERA_APP_SETTINGS = CameraAppSettings()
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CaptureMode.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CaptureMode.kt
index 1931d9f..ada8b5e 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CaptureMode.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/CaptureMode.kt
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -15,7 +15,35 @@
  */
 package com.google.jetpackcamera.settings.model
 
+/**
+ * Class representing the app's configuration to capture an image
+ */
 enum class CaptureMode {
-    MULTI_STREAM,
-    SINGLE_STREAM
+
+    /**
+     * Both Image and Video use cases will be bound.
+     *
+     * Tap the Capture Button to take an image.
+     *
+     * Hold the Capture button to start recording, and release to complete the recording.
+     */
+    STANDARD,
+
+    /**
+     * Video use case will be bound. Image use case will not be bound.
+     *
+     * Tap the Capture Button to start recording.
+     * Hold the Capture button to start recording; releasing will not stop the recording.
+     *
+     * Tap the capture button again after recording has started to complete the recording.
+     */
+    VIDEO_ONLY,
+
+    /**
+     * Image use case will be bound. Video use case will not be bound.
+     *
+     * Tap the Capture Button to capture an Image.
+     * Holding the Capture Button will do nothing. Subsequent release of the Capture button will also do nothing.
+     */
+    IMAGE_ONLY
 }
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Constraints.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Constraints.kt
index 8b75351..fd23758 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Constraints.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Constraints.kt
@@ -16,18 +16,35 @@
 package com.google.jetpackcamera.settings.model
 
 data class SystemConstraints(
-    val availableLenses: List<LensFacing>,
-    val concurrentCamerasSupported: Boolean,
-    val perLensConstraints: Map<LensFacing, CameraConstraints>
+    val availableLenses: List<LensFacing> = emptyList(),
+    val concurrentCamerasSupported: Boolean = false,
+    val perLensConstraints: Map<LensFacing, CameraConstraints> = emptyMap()
 )
 
+inline fun <reified T> SystemConstraints.forDevice(
+    crossinline constraintSelector: (CameraConstraints) -> Iterable<T>
+) = perLensConstraints.values.asSequence().flatMap { constraintSelector(it) }.toSet()
+
 data class CameraConstraints(
-    val supportedStabilizationModes: Set<SupportedStabilizationMode>,
+    val supportedStabilizationModes: Set<StabilizationMode>,
     val supportedFixedFrameRates: Set<Int>,
     val supportedDynamicRanges: Set<DynamicRange>,
-    val supportedImageFormatsMap: Map<CaptureMode, Set<ImageOutputFormat>>,
-    val hasFlashUnit: Boolean
-)
+    val supportedVideoQualitiesMap: Map<DynamicRange, List<VideoQuality>>,
+    val supportedImageFormatsMap: Map<StreamConfig, Set<ImageOutputFormat>>,
+    val supportedIlluminants: Set<Illuminant>,
+    val supportedFlashModes: Set<FlashMode>,
+    val unsupportedStabilizationFpsMap: Map<StabilizationMode, Set<Int>>
+) {
+    val StabilizationMode.unsupportedFpsSet
+        get() = unsupportedStabilizationFpsMap[this] ?: emptySet()
+
+    companion object {
+        const val FPS_AUTO = 0
+        const val FPS_15 = 15
+        const val FPS_30 = 30
+        const val FPS_60 = 60
+    }
+}
 
 /**
  * Useful set of constraints for testing
@@ -42,13 +59,16 @@ val TYPICAL_SYSTEM_CONSTRAINTS =
                     lensFacing,
                     CameraConstraints(
                         supportedFixedFrameRates = setOf(15, 30),
-                        supportedStabilizationModes = emptySet(),
+                        supportedStabilizationModes = setOf(StabilizationMode.OFF),
                         supportedDynamicRanges = setOf(DynamicRange.SDR),
                         supportedImageFormatsMap = mapOf(
-                            Pair(CaptureMode.SINGLE_STREAM, setOf(ImageOutputFormat.JPEG)),
-                            Pair(CaptureMode.MULTI_STREAM, setOf(ImageOutputFormat.JPEG))
+                            Pair(StreamConfig.SINGLE_STREAM, setOf(ImageOutputFormat.JPEG)),
+                            Pair(StreamConfig.MULTI_STREAM, setOf(ImageOutputFormat.JPEG))
                         ),
-                        hasFlashUnit = lensFacing == LensFacing.BACK
+                        supportedVideoQualitiesMap = emptyMap(),
+                        supportedIlluminants = setOf(Illuminant.FLASH_UNIT),
+                        supportedFlashModes = setOf(FlashMode.OFF, FlashMode.ON, FlashMode.AUTO),
+                        unsupportedStabilizationFpsMap = emptyMap()
                     )
                 )
             }
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/FlashMode.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/FlashMode.kt
index 2778740..1f2daf4 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/FlashMode.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/FlashMode.kt
@@ -18,5 +18,6 @@ package com.google.jetpackcamera.settings.model
 enum class FlashMode {
     OFF,
     ON,
-    AUTO
+    AUTO,
+    LOW_LIGHT_BOOST
 }
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Illuminant.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Illuminant.kt
new file mode 100644
index 0000000..a9c320b
--- /dev/null
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Illuminant.kt
@@ -0,0 +1,22 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package com.google.jetpackcamera.settings.model
+
+enum class Illuminant {
+    FLASH_UNIT,
+    SCREEN,
+    LOW_LIGHT_BOOST
+}
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/SupportedStabilizationMode.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/LowLightBoostState.kt
similarity index 72%
rename from data/settings/src/main/java/com/google/jetpackcamera/settings/model/SupportedStabilizationMode.kt
rename to data/settings/src/main/java/com/google/jetpackcamera/settings/model/LowLightBoostState.kt
index c71ca5c..5ff6d93 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/SupportedStabilizationMode.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/LowLightBoostState.kt
@@ -15,11 +15,17 @@
  */
 package com.google.jetpackcamera.settings.model
 
-/** Enum class representing the device's supported video stabilization configurations. */
-enum class SupportedStabilizationMode {
-    /** Device supports Preview stabilization. */
-    ON,
+/**
+ * Enum describing the state of Low Light Boost state.
+ */
+enum class LowLightBoostState {
+    /**
+     * Low Light Boost is turned on, and active
+     */
+    ACTIVE,
 
-    /** Device supports Video stabilization.*/
-    HIGH_QUALITY
+    /**
+     * Low Light Boost is turned on, but inactive
+     */
+    INACTIVE
 }
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Stabilization.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Stabilization.kt
deleted file mode 100644
index e97dfc5..0000000
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/Stabilization.kt
+++ /dev/null
@@ -1,48 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.google.jetpackcamera.settings.model
-
-import com.google.jetpackcamera.settings.PreviewStabilization as PreviewStabilizationProto
-import com.google.jetpackcamera.settings.VideoStabilization as VideoStabilizationProto
-
-enum class Stabilization {
-    UNDEFINED,
-    OFF,
-    ON;
-
-    companion object {
-        /** returns the Stabilization enum equivalent of a provided [PreviewStabilizationProto]. */
-        fun fromProto(stabilizationProto: PreviewStabilizationProto): Stabilization {
-            return when (stabilizationProto) {
-                PreviewStabilizationProto.PREVIEW_STABILIZATION_UNDEFINED -> UNDEFINED
-                PreviewStabilizationProto.PREVIEW_STABILIZATION_OFF -> OFF
-                PreviewStabilizationProto.PREVIEW_STABILIZATION_ON -> ON
-                else -> UNDEFINED
-            }
-        }
-
-        /** returns the Stabilization enum equivalent of a provided [VideoStabilizationProto]. */
-
-        fun fromProto(stabilizationProto: VideoStabilizationProto): Stabilization {
-            return when (stabilizationProto) {
-                VideoStabilizationProto.VIDEO_STABILIZATION_UNDEFINED -> UNDEFINED
-                VideoStabilizationProto.VIDEO_STABILIZATION_OFF -> OFF
-                VideoStabilizationProto.VIDEO_STABILIZATION_ON -> ON
-                else -> UNDEFINED
-            }
-        }
-    }
-}
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/StabilizationMode.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/StabilizationMode.kt
new file mode 100644
index 0000000..c66275c
--- /dev/null
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/StabilizationMode.kt
@@ -0,0 +1,57 @@
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
+package com.google.jetpackcamera.settings.model
+
+import com.google.jetpackcamera.settings.StabilizationMode as StabilizationModeProto
+
+/** Enum class representing the device's supported stabilization configurations. */
+enum class StabilizationMode {
+    /** Stabilization off */
+    OFF,
+
+    /**
+     * Device-chosen stabilization mode
+     *
+     * This will choose [ON] if the device and settings support it, otherwise it will be [OFF].
+     */
+    AUTO,
+
+    /** Preview stabilization. */
+    ON,
+
+    /** Video stabilization.*/
+    HIGH_QUALITY,
+
+    /** Optical Stabilization (OIS) */
+    OPTICAL;
+
+    companion object {
+        /** returns the AspectRatio enum equivalent of a provided AspectRatioProto */
+        fun fromProto(stabilizationModeProto: StabilizationModeProto): StabilizationMode =
+            when (stabilizationModeProto) {
+                StabilizationModeProto.STABILIZATION_MODE_OFF -> OFF
+                StabilizationModeProto.STABILIZATION_MODE_ON -> ON
+                StabilizationModeProto.STABILIZATION_MODE_HIGH_QUALITY -> HIGH_QUALITY
+                StabilizationModeProto.STABILIZATION_MODE_OPTICAL -> OPTICAL
+
+                // Default to AUTO
+                StabilizationModeProto.STABILIZATION_MODE_UNDEFINED,
+                StabilizationModeProto.UNRECOGNIZED,
+                StabilizationModeProto.STABILIZATION_MODE_AUTO
+                -> AUTO
+            }
+    }
+}
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/LowLightBoost.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/StreamConfig.kt
similarity index 84%
rename from data/settings/src/main/java/com/google/jetpackcamera/settings/model/LowLightBoost.kt
rename to data/settings/src/main/java/com/google/jetpackcamera/settings/model/StreamConfig.kt
index 8fd7221..73b45ac 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/LowLightBoost.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/StreamConfig.kt
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2023 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -15,7 +15,7 @@
  */
 package com.google.jetpackcamera.settings.model
 
-enum class LowLightBoost {
-    DISABLED,
-    ENABLED
+enum class StreamConfig {
+    MULTI_STREAM,
+    SINGLE_STREAM
 }
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/model/VideoQuality.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/VideoQuality.kt
new file mode 100644
index 0000000..0daeada
--- /dev/null
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/model/VideoQuality.kt
@@ -0,0 +1,51 @@
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
+package com.google.jetpackcamera.settings.model
+
+import com.google.jetpackcamera.settings.VideoQuality as VideoQualityProto
+
+enum class VideoQuality {
+    UNSPECIFIED,
+    SD,
+    HD,
+    FHD,
+    UHD;
+
+    companion object {
+        /** returns the VideoQuality enum equivalent of a provided VideoQualityProto */
+        fun fromProto(videoQualityProto: VideoQualityProto): VideoQuality {
+            return when (videoQualityProto) {
+                VideoQualityProto.VIDEO_QUALITY_SD -> SD
+                VideoQualityProto.VIDEO_QUALITY_HD -> HD
+                VideoQualityProto.VIDEO_QUALITY_FHD -> FHD
+                VideoQualityProto.VIDEO_QUALITY_UHD -> UHD
+                VideoQualityProto.VIDEO_QUALITY_UNSPECIFIED,
+                VideoQualityProto.UNRECOGNIZED
+                -> UNSPECIFIED
+            }
+        }
+
+        fun VideoQuality.toProto(): com.google.jetpackcamera.settings.VideoQuality {
+            return when (this) {
+                UNSPECIFIED -> VideoQualityProto.VIDEO_QUALITY_UNSPECIFIED
+                SD -> VideoQualityProto.VIDEO_QUALITY_SD
+                HD -> VideoQualityProto.VIDEO_QUALITY_HD
+                FHD -> VideoQualityProto.VIDEO_QUALITY_FHD
+                UHD -> VideoQualityProto.VIDEO_QUALITY_UHD
+            }
+        }
+    }
+}
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/test/FakeJcaSettingsSerializer.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/test/FakeJcaSettingsSerializer.kt
index d207a99..3402665 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/test/FakeJcaSettingsSerializer.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/test/FakeJcaSettingsSerializer.kt
@@ -18,32 +18,35 @@ package com.google.jetpackcamera.settings.test
 import androidx.datastore.core.CorruptionException
 import androidx.datastore.core.Serializer
 import com.google.jetpackcamera.settings.AspectRatio
-import com.google.jetpackcamera.settings.CaptureMode
 import com.google.jetpackcamera.settings.DarkMode
 import com.google.jetpackcamera.settings.DynamicRange
 import com.google.jetpackcamera.settings.FlashMode
+import com.google.jetpackcamera.settings.ImageOutputFormat
 import com.google.jetpackcamera.settings.JcaSettings
 import com.google.jetpackcamera.settings.LensFacing
-import com.google.jetpackcamera.settings.PreviewStabilization
-import com.google.jetpackcamera.settings.VideoStabilization
+import com.google.jetpackcamera.settings.StabilizationMode
+import com.google.jetpackcamera.settings.StreamConfig
+import com.google.jetpackcamera.settings.UNLIMITED_VIDEO_DURATION
+import com.google.jetpackcamera.settings.VideoQuality
 import com.google.protobuf.InvalidProtocolBufferException
 import java.io.IOException
 import java.io.InputStream
 import java.io.OutputStream
 
-class FakeJcaSettingsSerializer(
-    var failReadWithCorruptionException: Boolean = false
-) : Serializer<JcaSettings> {
+class FakeJcaSettingsSerializer(var failReadWithCorruptionException: Boolean = false) :
+    Serializer<JcaSettings> {
 
     override val defaultValue: JcaSettings = JcaSettings.newBuilder()
         .setDarkModeStatus(DarkMode.DARK_MODE_SYSTEM)
         .setDefaultLensFacing(LensFacing.LENS_FACING_BACK)
         .setFlashModeStatus(FlashMode.FLASH_MODE_OFF)
         .setAspectRatioStatus(AspectRatio.ASPECT_RATIO_NINE_SIXTEEN)
-        .setCaptureModeStatus(CaptureMode.CAPTURE_MODE_MULTI_STREAM)
-        .setStabilizePreview(PreviewStabilization.PREVIEW_STABILIZATION_UNDEFINED)
-        .setStabilizeVideo(VideoStabilization.VIDEO_STABILIZATION_UNDEFINED)
+        .setStreamConfigStatus(StreamConfig.STREAM_CONFIG_MULTI_STREAM)
+        .setStabilizationMode(StabilizationMode.STABILIZATION_MODE_AUTO)
         .setDynamicRangeStatus(DynamicRange.DYNAMIC_RANGE_SDR)
+        .setVideoQuality(VideoQuality.VIDEO_QUALITY_UNSPECIFIED)
+        .setImageFormatStatus(ImageOutputFormat.IMAGE_OUTPUT_FORMAT_JPEG)
+        .setMaxVideoDurationMillis(UNLIMITED_VIDEO_DURATION)
         .build()
 
     override suspend fun readFrom(input: InputStream): JcaSettings {
diff --git a/data/settings/src/main/java/com/google/jetpackcamera/settings/test/FakeSettingsRepository.kt b/data/settings/src/main/java/com/google/jetpackcamera/settings/test/FakeSettingsRepository.kt
index fce599f..1ec2e3a 100644
--- a/data/settings/src/main/java/com/google/jetpackcamera/settings/test/FakeSettingsRepository.kt
+++ b/data/settings/src/main/java/com/google/jetpackcamera/settings/test/FakeSettingsRepository.kt
@@ -18,14 +18,15 @@ package com.google.jetpackcamera.settings.test
 import com.google.jetpackcamera.settings.SettingsRepository
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CameraAppSettings
-import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.DEFAULT_CAMERA_APP_SETTINGS
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.StreamConfig
+import com.google.jetpackcamera.settings.model.VideoQuality
 import kotlinx.coroutines.flow.Flow
 import kotlinx.coroutines.flow.first
 import kotlinx.coroutines.flow.flow
@@ -50,19 +51,14 @@ object FakeSettingsRepository : SettingsRepository {
         currentCameraSettings = currentCameraSettings.copy(flashMode = flashMode)
     }
 
-    override suspend fun updateCaptureMode(captureMode: CaptureMode) {
+    override suspend fun updateStreamConfig(streamConfig: StreamConfig) {
         currentCameraSettings =
-            currentCameraSettings.copy(captureMode = captureMode)
+            currentCameraSettings.copy(streamConfig = streamConfig)
     }
 
-    override suspend fun updatePreviewStabilization(stabilization: Stabilization) {
+    override suspend fun updateStabilizationMode(stabilizationMode: StabilizationMode) {
         currentCameraSettings =
-            currentCameraSettings.copy(previewStabilization = stabilization)
-    }
-
-    override suspend fun updateVideoStabilization(stabilization: Stabilization) {
-        currentCameraSettings =
-            currentCameraSettings.copy(videoCaptureStabilization = stabilization)
+            currentCameraSettings.copy(stabilizationMode = stabilizationMode)
     }
 
     override suspend fun updateDynamicRange(dynamicRange: DynamicRange) {
@@ -83,4 +79,17 @@ object FakeSettingsRepository : SettingsRepository {
     override suspend fun updateImageFormat(imageFormat: ImageOutputFormat) {
         currentCameraSettings = currentCameraSettings.copy(imageFormat = imageFormat)
     }
+
+    override suspend fun updateMaxVideoDuration(durationMillis: Long) {
+        currentCameraSettings = currentCameraSettings.copy(maxVideoDurationMillis = durationMillis)
+    }
+
+    override suspend fun updateVideoQuality(videoQuality: VideoQuality) {
+        currentCameraSettings = currentCameraSettings.copy(videoQuality = videoQuality)
+    }
+
+    override suspend fun updateAudioEnabled(isAudioEnabled: Boolean) {
+        currentCameraSettings =
+            currentCameraSettings.copy(audioEnabled = isAudioEnabled)
+    }
 }
diff --git a/data/settings/src/main/proto/com/google/jetpackcamera/settings/capture_mode.proto b/data/settings/src/main/proto/com/google/jetpackcamera/settings/capture_mode.proto
index f74868f..2e3ceb9 100644
--- a/data/settings/src/main/proto/com/google/jetpackcamera/settings/capture_mode.proto
+++ b/data/settings/src/main/proto/com/google/jetpackcamera/settings/capture_mode.proto
@@ -19,8 +19,8 @@ syntax = "proto3";
 option java_package = "com.google.jetpackcamera.settings";
 option java_multiple_files = true;
 
-enum CaptureMode {
-  CAPTURE_MODE_UNDEFINED = 0;
-  CAPTURE_MODE_MULTI_STREAM = 1;
-  CAPTURE_MODE_SINGLE_STREAM = 2;
+enum StreamConfig {
+  STREAM_CONFIG_UNDEFINED = 0;
+  STREAM_CONFIG_MULTI_STREAM = 1;
+  STREAM_CONFIG_SINGLE_STREAM = 2;
 }
\ No newline at end of file
diff --git a/data/settings/src/main/proto/com/google/jetpackcamera/settings/flash_mode.proto b/data/settings/src/main/proto/com/google/jetpackcamera/settings/flash_mode.proto
index 8096b2b..a315e48 100644
--- a/data/settings/src/main/proto/com/google/jetpackcamera/settings/flash_mode.proto
+++ b/data/settings/src/main/proto/com/google/jetpackcamera/settings/flash_mode.proto
@@ -23,4 +23,5 @@ enum FlashMode{
   FLASH_MODE_AUTO = 0;
   FLASH_MODE_ON = 1;
   FLASH_MODE_OFF = 2;
+  FLASH_MODE_LOW_LIGHT_BOOST = 3;
 }
\ No newline at end of file
diff --git a/data/settings/src/main/proto/com/google/jetpackcamera/settings/jca_settings.proto b/data/settings/src/main/proto/com/google/jetpackcamera/settings/jca_settings.proto
index 03aeb6d..d75b989 100644
--- a/data/settings/src/main/proto/com/google/jetpackcamera/settings/jca_settings.proto
+++ b/data/settings/src/main/proto/com/google/jetpackcamera/settings/jca_settings.proto
@@ -23,8 +23,8 @@ import "com/google/jetpackcamera/settings/dynamic_range.proto";
 import "com/google/jetpackcamera/settings/flash_mode.proto";
 import "com/google/jetpackcamera/settings/image_output_format.proto";
 import "com/google/jetpackcamera/settings/lens_facing.proto";
-import "com/google/jetpackcamera/settings/preview_stabilization.proto";
-import "com/google/jetpackcamera/settings/video_stabilization.proto";
+import "com/google/jetpackcamera/settings/stabilization_mode.proto";
+import "com/google/jetpackcamera/settings/video_quality.proto";
 
 
 option java_package = "com.google.jetpackcamera.settings";
@@ -36,11 +36,13 @@ message JcaSettings {
   FlashMode flash_mode_status = 2;
   int32 target_frame_rate = 3;
   AspectRatio aspect_ratio_status = 4;
-  CaptureMode capture_mode_status = 5;
-  PreviewStabilization stabilize_preview = 6;
-  VideoStabilization stabilize_video = 7;
+  StreamConfig stream_config_status = 5;
+  StabilizationMode stabilization_mode = 6;
   DynamicRange dynamic_range_status = 8;
   ImageOutputFormat image_format_status = 10;
+  uint64 max_video_duration_millis = 11;
+  VideoQuality video_quality = 12;
+  bool audio_enabled_status = 13;
 
   // Non-camera app settings
   DarkMode dark_mode_status = 9;
diff --git a/data/settings/src/main/proto/com/google/jetpackcamera/settings/video_stabilization.proto b/data/settings/src/main/proto/com/google/jetpackcamera/settings/stabilization_mode.proto
similarity index 76%
rename from data/settings/src/main/proto/com/google/jetpackcamera/settings/video_stabilization.proto
rename to data/settings/src/main/proto/com/google/jetpackcamera/settings/stabilization_mode.proto
index 5063b66..a340e0e 100644
--- a/data/settings/src/main/proto/com/google/jetpackcamera/settings/video_stabilization.proto
+++ b/data/settings/src/main/proto/com/google/jetpackcamera/settings/stabilization_mode.proto
@@ -19,8 +19,11 @@ syntax = "proto3";
 option java_package = "com.google.jetpackcamera.settings";
 option java_multiple_files = true;
 
-enum VideoStabilization {
-  VIDEO_STABILIZATION_UNDEFINED = 0;
-  VIDEO_STABILIZATION_OFF = 1;
-  VIDEO_STABILIZATION_ON = 2;
+enum StabilizationMode {
+  STABILIZATION_MODE_UNDEFINED = 0;
+  STABILIZATION_MODE_AUTO = 1;
+  STABILIZATION_MODE_OFF = 2;
+  STABILIZATION_MODE_ON = 3;
+  STABILIZATION_MODE_HIGH_QUALITY = 4;
+  STABILIZATION_MODE_OPTICAL = 5;
 }
\ No newline at end of file
diff --git a/data/settings/src/main/proto/com/google/jetpackcamera/settings/preview_stabilization.proto b/data/settings/src/main/proto/com/google/jetpackcamera/settings/video_quality.proto
similarity index 82%
rename from data/settings/src/main/proto/com/google/jetpackcamera/settings/preview_stabilization.proto
rename to data/settings/src/main/proto/com/google/jetpackcamera/settings/video_quality.proto
index 5d8172d..c10a73f 100644
--- a/data/settings/src/main/proto/com/google/jetpackcamera/settings/preview_stabilization.proto
+++ b/data/settings/src/main/proto/com/google/jetpackcamera/settings/video_quality.proto
@@ -19,8 +19,10 @@ syntax = "proto3";
 option java_package = "com.google.jetpackcamera.settings";
 option java_multiple_files = true;
 
-enum PreviewStabilization {
-  PREVIEW_STABILIZATION_UNDEFINED = 0;
-  PREVIEW_STABILIZATION_OFF = 1;
-  PREVIEW_STABILIZATION_ON = 2;
+enum VideoQuality {
+  VIDEO_QUALITY_UNSPECIFIED = 0;
+  VIDEO_QUALITY_SD = 1;
+  VIDEO_QUALITY_HD = 2;
+  VIDEO_QUALITY_FHD = 3;
+  VIDEO_QUALITY_UHD = 4;
 }
\ No newline at end of file
diff --git a/feature/permissions/build.gradle.kts b/feature/permissions/build.gradle.kts
index 66fadf3..d935b2c 100644
--- a/feature/permissions/build.gradle.kts
+++ b/feature/permissions/build.gradle.kts
@@ -24,7 +24,6 @@ plugins {
 android {
     namespace = "com.google.jetpackcamera.permissions"
     compileSdk = libs.versions.compileSdk.get().toInt()
-    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     defaultConfig {
         minSdk = libs.versions.minSdk.get().toInt()
@@ -81,7 +80,6 @@ dependencies {
 
     implementation(libs.androidx.core.ktx)
     implementation(libs.androidx.appcompat)
-    implementation(libs.android.material)
     testImplementation(libs.junit)
     androidTestImplementation(libs.androidx.junit)
     androidTestImplementation(libs.androidx.espresso.core)
diff --git a/feature/permissions/src/main/AndroidManifest.xml b/feature/permissions/src/main/AndroidManifest.xml
index 926ca9b..52de678 100644
--- a/feature/permissions/src/main/AndroidManifest.xml
+++ b/feature/permissions/src/main/AndroidManifest.xml
@@ -14,7 +14,6 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
-<manifest package="com.google.jetpackcamera.permissions">
-
-</manifest>
+<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.google.jetpackcamera.permissions">
 
+</manifest>
\ No newline at end of file
diff --git a/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsEnums.kt b/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsEnums.kt
index 57fd0b1..941d660 100644
--- a/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsEnums.kt
+++ b/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsEnums.kt
@@ -25,6 +25,8 @@ import androidx.compose.ui.graphics.painter.Painter
 import androidx.compose.ui.graphics.vector.ImageVector
 import androidx.compose.ui.graphics.vector.rememberVectorPainter
 import androidx.compose.ui.res.painterResource
+import com.google.jetpackcamera.permissions.ui.CAMERA_PERMISSION_BUTTON
+import com.google.jetpackcamera.permissions.ui.RECORD_AUDIO_PERMISSION_BUTTON
 
 const val CAMERA_PERMISSION = "android.permission.CAMERA"
 const val AUDIO_RECORD_PERMISSION = "android.permission.RECORD_AUDIO"
@@ -55,6 +57,8 @@ sealed interface PermissionInfoProvider {
 
     fun isOptional(): Boolean
 
+    fun getTestTag(): String
+
     @DrawableRes
     fun getDrawableResId(): Int?
 
@@ -84,6 +88,8 @@ enum class PermissionEnum : PermissionInfoProvider {
 
         override fun isOptional(): Boolean = false
 
+        override fun getTestTag(): String = CAMERA_PERMISSION_BUTTON
+
         override fun getDrawableResId(): Int? = null
 
         override fun getImageVector(): ImageVector = Icons.Outlined.CameraAlt
@@ -105,6 +111,8 @@ enum class PermissionEnum : PermissionInfoProvider {
 
         override fun isOptional(): Boolean = true
 
+        override fun getTestTag(): String = RECORD_AUDIO_PERMISSION_BUTTON
+
         override fun getDrawableResId(): Int? = null
 
         override fun getImageVector(): ImageVector = Icons.Outlined.Mic
diff --git a/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsScreen.kt b/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsScreen.kt
index ad67fda..b694727 100644
--- a/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsScreen.kt
+++ b/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/PermissionsScreen.kt
@@ -20,6 +20,7 @@ import android.util.Log
 import androidx.activity.compose.rememberLauncherForActivityResult
 import androidx.activity.result.contract.ActivityResultContracts
 import androidx.compose.runtime.Composable
+import androidx.compose.runtime.LaunchedEffect
 import androidx.compose.runtime.collectAsState
 import androidx.compose.runtime.getValue
 import androidx.compose.ui.Modifier
@@ -36,7 +37,7 @@ private const val TAG = "PermissionsScreen"
 @Composable
 fun PermissionsScreen(
     shouldRequestAudioPermission: Boolean,
-    onNavigateToPreview: () -> Unit,
+    onAllPermissionsGranted: () -> Unit,
     openAppSettings: () -> Unit
 ) {
     val permissionStates = rememberMultiplePermissionsState(
@@ -53,7 +54,7 @@ fun PermissionsScreen(
     )
     PermissionsScreen(
         permissionStates = permissionStates,
-        onNavigateToPreview = onNavigateToPreview,
+        onAllPermissionsGranted = onAllPermissionsGranted,
         openAppSettings = openAppSettings
     )
 }
@@ -67,7 +68,7 @@ fun PermissionsScreen(
 @Composable
 fun PermissionsScreen(
     modifier: Modifier = Modifier,
-    onNavigateToPreview: () -> Unit,
+    onAllPermissionsGranted: () -> Unit,
     openAppSettings: () -> Unit,
     permissionStates: MultiplePermissionsState,
     viewModel: PermissionsViewModel = hiltViewModel<
@@ -77,6 +78,12 @@ fun PermissionsScreen(
 ) {
     Log.d(TAG, "PermissionsScreen")
     val permissionsUiState: PermissionsUiState by viewModel.permissionsUiState.collectAsState()
+    LaunchedEffect(permissionsUiState) {
+        if (permissionsUiState is PermissionsUiState.AllPermissionsGranted) {
+            onAllPermissionsGranted()
+        }
+    }
+
     if (permissionsUiState is PermissionsUiState.PermissionsNeeded) {
         val permissionEnum =
             (permissionsUiState as PermissionsUiState.PermissionsNeeded).currentPermission
@@ -111,7 +118,5 @@ fun PermissionsScreen(
             onRequestPermission = { permissionLauncher.launch(permissionEnum.getPermission()) },
             onOpenAppSettings = openAppSettings
         )
-    } else {
-        onNavigateToPreview()
     }
 }
diff --git a/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/ui/PermissionsScreenComponents.kt b/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/ui/PermissionsScreenComponents.kt
index d376b33..b889726 100644
--- a/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/ui/PermissionsScreenComponents.kt
+++ b/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/ui/PermissionsScreenComponents.kt
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2024 The Android Open Source Project
+ * Copyright (C) 2023 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -38,6 +38,7 @@ import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
 import androidx.compose.ui.graphics.Color
 import androidx.compose.ui.graphics.vector.ImageVector
+import androidx.compose.ui.platform.testTag
 import androidx.compose.ui.res.stringResource
 import androidx.compose.ui.text.font.FontWeight
 import androidx.compose.ui.text.style.TextAlign
@@ -67,6 +68,7 @@ fun PermissionTemplate(
 ) {
     PermissionTemplate(
         modifier = modifier,
+        testTag = permissionEnum.getTestTag(),
         onRequestPermission = {
             if (permissionState.status.shouldShowRationale) {
                 onOpenAppSettings()
@@ -101,6 +103,7 @@ fun PermissionTemplate(
 @Composable
 fun PermissionTemplate(
     modifier: Modifier = Modifier,
+    testTag: String,
     onRequestPermission: () -> Unit,
     onSkipPermission: (() -> Unit)? = null,
     imageVector: ImageVector,
@@ -117,7 +120,8 @@ fun PermissionTemplate(
         PermissionImage(
             modifier = Modifier
                 .height(IntrinsicSize.Min)
-                .align(Alignment.CenterHorizontally),
+                .align(Alignment.CenterHorizontally)
+                .testTag(testTag),
             imageVector = imageVector,
             accessibilityText = iconAccessibilityText
         )
@@ -133,6 +137,7 @@ fun PermissionTemplate(
             // permission button section
             PermissionButtonSection(
                 modifier = Modifier
+                    .testTag(REQUEST_PERMISSION_BUTTON)
                     .fillMaxWidth()
                     .align(Alignment.CenterHorizontally)
                     .height(IntrinsicSize.Min),
@@ -153,6 +158,7 @@ Permission UI Previews
 private fun Preview_Camera_Permission_Page() {
     PermissionTemplate(
         onRequestPermission = { /*TODO*/ },
+        testTag = "",
         imageVector = PermissionEnum.CAMERA.getImageVector()!!,
         iconAccessibilityText = "",
         title = stringResource(id = PermissionEnum.CAMERA.getPermissionTitleResId()),
@@ -166,6 +172,7 @@ private fun Preview_Camera_Permission_Page() {
 private fun Preview_Audio_Permission_Page() {
     PermissionTemplate(
         onRequestPermission = { /*TODO*/ },
+        testTag = "",
         imageVector = PermissionEnum.RECORD_AUDIO.getImageVector()!!,
         iconAccessibilityText = "",
         title = stringResource(id = PermissionEnum.RECORD_AUDIO.getPermissionTitleResId()),
@@ -303,4 +310,3 @@ fun PermissionBodyText(modifier: Modifier = Modifier, text: String, color: Color
         textAlign = TextAlign.Center
     )
 }
-
diff --git a/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/ui/TestTags.kt b/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/ui/TestTags.kt
new file mode 100644
index 0000000..f09e503
--- /dev/null
+++ b/feature/permissions/src/main/java/com/google/jetpackcamera/permissions/ui/TestTags.kt
@@ -0,0 +1,20 @@
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
+package com.google.jetpackcamera.permissions.ui
+
+const val REQUEST_PERMISSION_BUTTON = "RequestPermissionButton"
+const val CAMERA_PERMISSION_BUTTON = "CameraPermissionButton"
+const val RECORD_AUDIO_PERMISSION_BUTTON = "RecordAudioPermissionButton"
diff --git a/feature/postcapture/.gitignore b/feature/postcapture/.gitignore
new file mode 100644
index 0000000..42afabf
--- /dev/null
+++ b/feature/postcapture/.gitignore
@@ -0,0 +1 @@
+/build
\ No newline at end of file
diff --git a/feature/postcapture/Android.bp b/feature/postcapture/Android.bp
new file mode 100644
index 0000000..7f49e84
--- /dev/null
+++ b/feature/postcapture/Android.bp
@@ -0,0 +1,25 @@
+package {
+    default_applicable_licenses: [
+        "Android-Apache-2.0",
+    ],
+}
+
+android_library {
+    name: "jetpack-camera-app_feature_postcapture",
+    srcs: ["src/main/**/*.kt"],
+    static_libs: [
+        "androidx.compose.runtime_runtime",
+        "androidx.compose.material3_material3",
+        "androidx.compose.material_material-icons-extended",
+        "androidx.compose.ui_ui-tooling-preview",
+        "androidx.hilt_hilt-navigation-compose",
+        "androidx.compose.ui_ui-tooling",
+        "kotlin-reflect",
+        "kotlinx_coroutines_guava",
+        "jetpack-camera-app_core_common",
+
+    ],
+    sdk_version: "34",
+    min_sdk_version: "21",
+    manifest: "src/main/AndroidManifest.xml",
+}
diff --git a/feature/postcapture/build.gradle.kts b/feature/postcapture/build.gradle.kts
new file mode 100644
index 0000000..f421334
--- /dev/null
+++ b/feature/postcapture/build.gradle.kts
@@ -0,0 +1,133 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+plugins {
+    alias(libs.plugins.android.library)
+    alias(libs.plugins.kotlin.android)
+}
+
+android {
+    namespace = "com.google.jetpackcamera.feature.postcapture"
+    compileSdk = 35
+
+    defaultConfig {
+        minSdk = libs.versions.minSdk.get().toInt()
+        testOptions.targetSdk = libs.versions.targetSdk.get().toInt()
+        lint.targetSdk = libs.versions.targetSdk.get().toInt()
+
+        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
+    }
+
+
+    flavorDimensions += "flavor"
+    productFlavors {
+        create("stable") {
+            dimension = "flavor"
+            isDefault = true
+        }
+    }
+
+    compileOptions {
+        sourceCompatibility = JavaVersion.VERSION_17
+        targetCompatibility = JavaVersion.VERSION_17
+    }
+    kotlin {
+        jvmToolchain(17)
+    }
+    buildFeatures {
+        buildConfig = true
+        compose = true
+    }
+    composeOptions {
+        kotlinCompilerExtensionVersion = libs.versions.composeCompiler.get()
+    }
+
+    @Suppress("UnstableApiUsage")
+    testOptions {
+        unitTests {
+            isReturnDefaultValues = true
+            isIncludeAndroidResources = true
+        }
+        managedDevices {
+            localDevices {
+                create("pixel2Api28") {
+                    device = "Pixel 2"
+                    apiLevel = 28
+                }
+                create("pixel8Api34") {
+                    device = "Pixel 8"
+                    apiLevel = 34
+                    systemImageSource = "aosp_atd"
+                }
+            }
+        }
+    }
+
+    kotlinOptions {
+        freeCompilerArgs += "-Xcontext-receivers"
+    }
+}
+
+dependencies {
+
+    // Reflect
+    implementation(libs.kotlin.reflect)
+    // Compose
+    val composeBom = platform(libs.compose.bom)
+    implementation(composeBom)
+    androidTestImplementation(composeBom)
+
+    // Compose - Material Design 3
+    implementation(libs.compose.material3)
+    implementation(libs.compose.material.icons.extended)
+
+    // Compose - Android Studio Preview support
+    implementation(libs.compose.ui.tooling.preview)
+    debugImplementation(libs.compose.ui.tooling)
+
+    // Compose - Integration with ViewModels with Navigation and Hilt
+    implementation(libs.hilt.navigation.compose)
+
+    // Compose - Lifecycle utilities
+    implementation(libs.androidx.lifecycle.viewmodel.compose)
+    implementation(libs.androidx.lifecycle.runtime.compose)
+
+    // Compose - Testing
+    androidTestImplementation(libs.compose.junit)
+    debugImplementation(libs.compose.test.manifest)
+    // noinspection TestManifestGradleConfiguration: required for release build unit tests
+    testImplementation(libs.compose.test.manifest)
+    testImplementation(libs.compose.junit)
+
+    // Testing
+    testImplementation(libs.junit)
+    testImplementation(libs.truth)
+    testImplementation(libs.mockito.core)
+    testImplementation(libs.kotlinx.coroutines.test)
+    testImplementation(libs.robolectric)
+    debugImplementation(libs.androidx.test.monitor)
+    implementation(libs.androidx.junit)
+    androidTestImplementation(libs.androidx.junit)
+    androidTestImplementation(libs.androidx.espresso.core)
+
+    // Futures
+    implementation(libs.futures.ktx)
+
+    implementation(libs.kotlinx.atomicfu)
+
+    // Project dependencies
+    implementation(project(":core:common"))
+    testImplementation(project(":core:common"))
+}
\ No newline at end of file
diff --git a/feature/postcapture/proguard-rules.pro b/feature/postcapture/proguard-rules.pro
new file mode 100644
index 0000000..481bb43
--- /dev/null
+++ b/feature/postcapture/proguard-rules.pro
@@ -0,0 +1,21 @@
+# Add project specific ProGuard rules here.
+# You can control the set of applied configuration files using the
+# proguardFiles setting in build.gradle.
+#
+# For more details, see
+#   http://developer.android.com/guide/developing/tools/proguard.html
+
+# If your project uses WebView with JS, uncomment the following
+# and specify the fully qualified class name to the JavaScript interface
+# class:
+#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
+#   public *;
+#}
+
+# Uncomment this to preserve the line number information for
+# debugging stack traces.
+#-keepattributes SourceFile,LineNumberTable
+
+# If you keep the line number information, uncomment this to
+# hide the original source file name.
+#-renamesourcefileattribute SourceFile
\ No newline at end of file
diff --git a/feature/postcapture/src/main/AndroidManifest.xml b/feature/postcapture/src/main/AndroidManifest.xml
new file mode 100644
index 0000000..664f138
--- /dev/null
+++ b/feature/postcapture/src/main/AndroidManifest.xml
@@ -0,0 +1,19 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.google.jetpackcamera.postcapture">
+
+</manifest>
\ No newline at end of file
diff --git a/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureScreen.kt b/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureScreen.kt
new file mode 100644
index 0000000..854f64f
--- /dev/null
+++ b/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureScreen.kt
@@ -0,0 +1,161 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.google.jetpackcamera.feature.postcapture
+
+import android.content.Context
+import android.content.Intent
+import android.net.Uri
+import androidx.compose.foundation.Canvas
+import androidx.compose.foundation.layout.Arrangement
+import androidx.compose.foundation.layout.Box
+import androidx.compose.foundation.layout.Row
+import androidx.compose.foundation.layout.Spacer
+import androidx.compose.foundation.layout.fillMaxSize
+import androidx.compose.foundation.layout.fillMaxWidth
+import androidx.compose.foundation.layout.padding
+import androidx.compose.foundation.layout.size
+import androidx.compose.foundation.shape.CircleShape
+import androidx.compose.material.icons.Icons
+import androidx.compose.material.icons.filled.Delete
+import androidx.compose.material.icons.filled.Share
+import androidx.compose.material3.Icon
+import androidx.compose.material3.IconButton
+import androidx.compose.material3.IconButtonDefaults
+import androidx.compose.material3.MaterialTheme
+import androidx.compose.material3.Text
+import androidx.compose.runtime.Composable
+import androidx.compose.runtime.LaunchedEffect
+import androidx.compose.runtime.collectAsState
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.remember
+import androidx.compose.ui.Alignment
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.draw.shadow
+import androidx.compose.ui.geometry.Size
+import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
+import androidx.compose.ui.graphics.nativeCanvas
+import androidx.compose.ui.platform.LocalContext
+import androidx.compose.ui.unit.dp
+import androidx.hilt.navigation.compose.hiltViewModel
+import com.google.jetpackcamera.core.common.loadAndRotateBitmap
+
+@Composable
+fun PostCaptureScreen(viewModel: PostCaptureViewModel = hiltViewModel(), imageUri: Uri?) {
+    val uiState: PostCaptureUiState by viewModel.uiState.collectAsState()
+    val context = LocalContext.current
+
+    LaunchedEffect(imageUri) {
+        viewModel.setLastCapturedImageUri(imageUri)
+    }
+
+    Box(modifier = Modifier.fillMaxSize()) {
+        uiState.imageUri?.let { uri ->
+            val bitmap = remember(uri) {
+                // TODO(yasith): Get the image rotation from the image
+                loadAndRotateBitmap(context, uri, 270f)
+            }
+
+            if (bitmap != null) {
+                Canvas(modifier = Modifier.fillMaxSize()) {
+                    drawIntoCanvas { canvas ->
+                        val scale = maxOf(
+                            size.width / bitmap.width,
+                            size.height / bitmap.height
+                        )
+                        val imageSize = Size(bitmap.width * scale, bitmap.height * scale)
+                        canvas.nativeCanvas.drawBitmap(
+                            bitmap,
+                            null,
+                            android.graphics.RectF(
+                                0f,
+                                0f,
+                                imageSize.width,
+                                imageSize.height
+                            ),
+                            null
+                        )
+                    }
+                }
+            }
+        } ?: Text(
+            text = "No Image Captured",
+            modifier = Modifier.align(Alignment.Center)
+        )
+
+        Row(
+            modifier = Modifier
+                .fillMaxWidth()
+                .align(Alignment.BottomCenter)
+                .padding(16.dp),
+            horizontalArrangement = Arrangement.SpaceAround
+        ) {
+            // Delete Image Button
+            IconButton(
+                onClick = { viewModel.deleteImage(context.contentResolver) },
+                modifier = Modifier
+                    .size(56.dp)
+                    .shadow(10.dp, CircleShape),
+                colors = IconButtonDefaults.iconButtonColors(
+                    containerColor = MaterialTheme.colorScheme.surface
+                )
+            ) {
+                Icon(
+                    imageVector = Icons.Default.Delete,
+                    contentDescription = "Delete",
+                    tint = MaterialTheme.colorScheme.onSurface
+                )
+            }
+
+            Spacer(modifier = Modifier.weight(1f))
+
+            // Share Image Button
+            IconButton(
+                onClick = {
+                    imageUri?.let {
+                        shareImage(context, it)
+                    }
+                },
+                modifier = Modifier
+                    .size(56.dp)
+                    .shadow(10.dp, CircleShape),
+                colors = IconButtonDefaults.iconButtonColors(
+                    containerColor = MaterialTheme.colorScheme.surface
+                )
+            ) {
+                Icon(
+                    imageVector = Icons.Default.Share,
+                    contentDescription = "Share",
+                    tint = MaterialTheme.colorScheme.onSurface
+                )
+            }
+        }
+    }
+}
+
+/**
+ * Starts an intent to share an image
+ *
+ * @param context The application context
+ * @param imagePath The path to the image to share
+ */
+private fun shareImage(context: Context, uri: Uri) {
+    val intent = Intent(Intent.ACTION_SEND).apply {
+        type = "image/jpeg"
+        putExtra(Intent.EXTRA_STREAM, uri)
+    }
+    intent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
+    context.startActivity(Intent.createChooser(intent, "Share Image"))
+}
diff --git a/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureViewModel.kt b/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureViewModel.kt
new file mode 100644
index 0000000..a9ed0b8
--- /dev/null
+++ b/feature/postcapture/src/main/java/com/google/jetpackcamera/feature/postcapture/PostCaptureViewModel.kt
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.google.jetpackcamera.feature.postcapture
+
+import android.content.ContentResolver
+import android.net.Uri
+import androidx.lifecycle.ViewModel
+import dagger.hilt.android.lifecycle.HiltViewModel
+import kotlinx.coroutines.flow.MutableStateFlow
+import kotlinx.coroutines.flow.StateFlow
+import kotlinx.coroutines.flow.update
+
+@HiltViewModel
+class PostCaptureViewModel : ViewModel() {
+
+    private val _uiState = MutableStateFlow(PostCaptureUiState())
+    val uiState: StateFlow<PostCaptureUiState> = _uiState
+
+    fun setLastCapturedImageUri(imageUri: Uri?) {
+        _uiState.update { it.copy(imageUri = imageUri, isImageDeleted = false) }
+    }
+
+    fun deleteImage(contentResolver: ContentResolver) {
+        contentResolver.delete(uiState.value.imageUri!!, null, null)
+        _uiState.update { it.copy(imageUri = null, isImageDeleted = true) }
+    }
+}
+
+data class PostCaptureUiState(
+    val imageUri: Uri? = null,
+    val isImageDeleted: Boolean = false
+)
diff --git a/feature/preview/Android.bp b/feature/preview/Android.bp
index a3d8366..cbc642a 100644
--- a/feature/preview/Android.bp
+++ b/feature/preview/Android.bp
@@ -23,12 +23,12 @@ android_library {
         "kotlinx_coroutines_guava",
         "androidx.datastore_datastore",
         "libprotobuf-java-lite",
+        "androidx.camera_camera-compose",
         "androidx.camera_camera-core",
         "androidx.camera_camera-viewfinder",
         "jetpack-camera-app_data_settings",
         "jetpack-camera-app_core_camera",
         "jetpack-camera-app_core_common",
-        "androidx.camera_camera-viewfinder-compose",
         "androidx.compose.ui_ui-tooling",
 
     ],
diff --git a/feature/preview/build.gradle.kts b/feature/preview/build.gradle.kts
index 5ba5f3a..abe853b 100644
--- a/feature/preview/build.gradle.kts
+++ b/feature/preview/build.gradle.kts
@@ -24,7 +24,6 @@ plugins {
 android {
     namespace = "com.google.jetpackcamera.feature.preview"
     compileSdk = libs.versions.compileSdk.get().toInt()
-    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     defaultConfig {
         minSdk = libs.versions.minSdk.get().toInt()
@@ -40,11 +39,6 @@ android {
             dimension = "flavor"
             isDefault = true
         }
-
-        create("preview") {
-            dimension = "flavor"
-            targetSdkPreview = libs.versions.targetSdkPreview.get()
-        }
     }
 
     compileOptions {
@@ -134,7 +128,7 @@ dependencies {
 
     // CameraX
     implementation(libs.camera.core)
-    implementation(libs.camera.viewfinder.compose)
+    implementation(libs.camera.compose)
 
     // Hilt
     implementation(libs.dagger.hilt.android)
diff --git a/feature/preview/src/androidTest/Android.bp b/feature/preview/src/androidTest/Android.bp
index 83e62dc..53b1026 100644
--- a/feature/preview/src/androidTest/Android.bp
+++ b/feature/preview/src/androidTest/Android.bp
@@ -4,7 +4,7 @@ package {
 
 android_test {
     name: "jetpack-camera-app_feature_preview-tests",
-    team: "trendy_team_camerax",
+    team: "trendy_team_android_camera_innovation_team",
     srcs: ["java/**/*.kt"],
     static_libs: [
         "androidx.test.runner",
diff --git a/feature/preview/src/main/AndroidManifest.xml b/feature/preview/src/main/AndroidManifest.xml
index 1fb3b89..35e5a53 100644
--- a/feature/preview/src/main/AndroidManifest.xml
+++ b/feature/preview/src/main/AndroidManifest.xml
@@ -16,4 +16,4 @@
   -->
 <manifest package="com.google.jetpackcamera.feature.preview">
 
-</manifest>
+</manifest>
\ No newline at end of file
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewMode.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewMode.kt
index dc3f8e7..1f5d12c 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewMode.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewMode.kt
@@ -30,7 +30,7 @@ sealed interface PreviewMode {
     ) : PreviewMode
 
     /**
-     * Under this mode, the app is launched by an external intent to capture an image.
+     * Under this mode, the app is launched by an external intent to capture one image.
      */
     data class ExternalImageCaptureMode(
         val imageCaptureUri: Uri?,
@@ -44,4 +44,12 @@ sealed interface PreviewMode {
         val videoCaptureUri: Uri?,
         val onVideoCapture: (PreviewViewModel.VideoCaptureEvent) -> Unit
     ) : PreviewMode
+
+    /**
+     * Under this mode, the app is launched by an external intent to capture multiple images.
+     */
+    data class ExternalMultipleImageCaptureMode(
+        val imageCaptureUris: List<Uri>?,
+        val onImageCapture: (PreviewViewModel.ImageCaptureEvent, Int) -> Unit
+    ) : PreviewMode
 }
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewScreen.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewScreen.kt
index 55583a2..11140fa 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewScreen.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewScreen.kt
@@ -38,6 +38,7 @@ import androidx.compose.runtime.LaunchedEffect
 import androidx.compose.runtime.collectAsState
 import androidx.compose.runtime.getValue
 import androidx.compose.runtime.remember
+import androidx.compose.runtime.rememberUpdatedState
 import androidx.compose.runtime.snapshotFlow
 import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
@@ -50,13 +51,17 @@ import androidx.compose.ui.unit.dp
 import androidx.hilt.navigation.compose.hiltViewModel
 import androidx.lifecycle.compose.LifecycleStartEffect
 import androidx.tracing.Trace
+import com.google.jetpackcamera.core.camera.VideoRecordingState
+import com.google.jetpackcamera.core.common.getLastImageUri
 import com.google.jetpackcamera.feature.preview.quicksettings.QuickSettingsScreenOverlay
 import com.google.jetpackcamera.feature.preview.ui.CameraControlsOverlay
 import com.google.jetpackcamera.feature.preview.ui.PreviewDisplay
 import com.google.jetpackcamera.feature.preview.ui.ScreenFlashScreen
 import com.google.jetpackcamera.feature.preview.ui.TestableSnackbar
 import com.google.jetpackcamera.feature.preview.ui.TestableToast
+import com.google.jetpackcamera.feature.preview.ui.ZoomLevelDisplayState
 import com.google.jetpackcamera.feature.preview.ui.debouncedOrientationFlow
+import com.google.jetpackcamera.feature.preview.ui.debug.DebugOverlayComponent
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
@@ -65,7 +70,7 @@ import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.LowLightBoost
+import com.google.jetpackcamera.settings.model.StreamConfig
 import com.google.jetpackcamera.settings.model.TYPICAL_SYSTEM_CONSTRAINTS
 import kotlinx.coroutines.flow.transformWhile
 
@@ -77,6 +82,7 @@ private const val TAG = "PreviewScreen"
 @Composable
 fun PreviewScreen(
     onNavigateToSettings: () -> Unit,
+    onNavigateToPostCapture: (uri: Uri?) -> Unit,
     previewMode: PreviewMode,
     isDebugMode: Boolean,
     modifier: Modifier = Modifier,
@@ -140,22 +146,33 @@ fun PreviewScreen(
                 onChangeZoomScale = viewModel::setZoomScale,
                 onChangeFlash = viewModel::setFlash,
                 onChangeAspectRatio = viewModel::setAspectRatio,
-                onChangeCaptureMode = viewModel::setCaptureMode,
+                onSetStreamConfig = viewModel::setStreamConfig,
                 onChangeDynamicRange = viewModel::setDynamicRange,
                 onChangeConcurrentCameraMode = viewModel::setConcurrentCameraMode,
-                onLowLightBoost = viewModel::setLowLightBoost,
                 onChangeImageFormat = viewModel::setImageFormat,
                 onToggleWhenDisabled = viewModel::showSnackBarForDisabledHdrToggle,
                 onToggleQuickSettings = viewModel::toggleQuickSettings,
-                onMuteAudio = viewModel::setAudioMuted,
-                onCaptureImage = viewModel::captureImage,
+                onToggleDebugOverlay = viewModel::toggleDebugOverlay,
+                onSetPause = viewModel::setPaused,
+                onSetAudioEnabled = viewModel::setAudioEnabled,
                 onCaptureImageWithUri = viewModel::captureImageWithUri,
                 onStartVideoRecording = viewModel::startVideoRecording,
                 onStopVideoRecording = viewModel::stopVideoRecording,
+                onLockVideoRecording = viewModel::setLockedRecording,
                 onToastShown = viewModel::onToastShown,
                 onRequestWindowColorMode = onRequestWindowColorMode,
-                onSnackBarResult = viewModel::onSnackBarResult
+                onSnackBarResult = viewModel::onSnackBarResult,
+                isDebugMode = isDebugMode,
+                onImageWellClick = { uri -> onNavigateToPostCapture(uri) }
             )
+
+            // TODO(yasith): Remove and use ImageRepository after implementing
+            LaunchedEffect(Unit) {
+                val lastCapturedImageUri = getLastImageUri(context)
+                lastCapturedImageUri?.let { uri ->
+                    viewModel.updateLastCapturedImageUri(uri)
+                }
+            }
         }
     }
 }
@@ -174,20 +191,20 @@ private fun ContentScreen(
     onChangeZoomScale: (Float) -> Unit = {},
     onChangeFlash: (FlashMode) -> Unit = {},
     onChangeAspectRatio: (AspectRatio) -> Unit = {},
-    onChangeCaptureMode: (CaptureMode) -> Unit = {},
+    onSetStreamConfig: (StreamConfig) -> Unit = {},
     onChangeDynamicRange: (DynamicRange) -> Unit = {},
     onChangeConcurrentCameraMode: (ConcurrentCameraMode) -> Unit = {},
-    onLowLightBoost: (LowLightBoost) -> Unit = {},
     onChangeImageFormat: (ImageOutputFormat) -> Unit = {},
     onToggleWhenDisabled: (CaptureModeToggleUiState.DisabledReason) -> Unit = {},
     onToggleQuickSettings: () -> Unit = {},
-    onMuteAudio: (Boolean) -> Unit = {},
-    onCaptureImage: () -> Unit = {},
+    onToggleDebugOverlay: () -> Unit = {},
+    onSetPause: (Boolean) -> Unit = {},
+    onSetAudioEnabled: (Boolean) -> Unit = {},
     onCaptureImageWithUri: (
         ContentResolver,
         Uri?,
         Boolean,
-        (PreviewViewModel.ImageCaptureEvent) -> Unit
+        (PreviewViewModel.ImageCaptureEvent, Int) -> Unit
     ) -> Unit = { _, _, _, _ -> },
     onStartVideoRecording: (
         Uri?,
@@ -195,30 +212,29 @@ private fun ContentScreen(
         (PreviewViewModel.VideoCaptureEvent) -> Unit
     ) -> Unit = { _, _, _ -> },
     onStopVideoRecording: () -> Unit = {},
+    onLockVideoRecording: (Boolean) -> Unit = {},
     onToastShown: () -> Unit = {},
     onRequestWindowColorMode: (Int) -> Unit = {},
-    onSnackBarResult: (String) -> Unit = {}
+    onSnackBarResult: (String) -> Unit = {},
+    isDebugMode: Boolean = false,
+    onImageWellClick: (uri: Uri?) -> Unit = {}
 ) {
     val snackbarHostState = remember { SnackbarHostState() }
     Scaffold(
         snackbarHost = { SnackbarHost(hostState = snackbarHostState) }
     ) {
-        val lensFacing = remember(previewUiState) {
+        val lensFacing by rememberUpdatedState(
             previewUiState.currentCameraSettings.cameraLensFacing
-        }
+        )
 
-        val onFlipCamera = remember(lensFacing) {
-            {
-                onSetLensFacing(lensFacing.flip())
-            }
-        }
+        val onFlipCamera = { onSetLensFacing(lensFacing.flip()) }
 
-        val isMuted = remember(previewUiState) {
-            previewUiState.currentCameraSettings.audioMuted
+        val isAudioEnabled = remember(previewUiState) {
+            previewUiState.currentCameraSettings.audioEnabled
         }
-        val onToggleMuteAudio = remember(isMuted) {
+        val onToggleAudio = remember(isAudioEnabled) {
             {
-                onMuteAudio(!isMuted)
+                onSetAudioEnabled(!isAudioEnabled)
             }
         }
 
@@ -243,11 +259,10 @@ private fun ContentScreen(
                 onLensFaceClick = onSetLensFacing,
                 onFlashModeClick = onChangeFlash,
                 onAspectRatioClick = onChangeAspectRatio,
-                onCaptureModeClick = onChangeCaptureMode,
+                onStreamConfigClick = onSetStreamConfig,
                 onDynamicRangeClick = onChangeDynamicRange,
                 onImageOutputFormatClick = onChangeImageFormat,
-                onConcurrentCameraModeClick = onChangeConcurrentCameraMode,
-                onLowLightBoostClick = onLowLightBoost
+                onConcurrentCameraModeClick = onChangeConcurrentCameraMode
             )
             // relative-grid style overlay on top of preview display
             CameraControlsOverlay(
@@ -255,15 +270,26 @@ private fun ContentScreen(
                 onNavigateToSettings = onNavigateToSettings,
                 onFlipCamera = onFlipCamera,
                 onChangeFlash = onChangeFlash,
-                onMuteAudio = onToggleMuteAudio,
+                onToggleAudio = onToggleAudio,
                 onToggleQuickSettings = onToggleQuickSettings,
+                onToggleDebugOverlay = onToggleDebugOverlay,
                 onChangeImageFormat = onChangeImageFormat,
                 onToggleWhenDisabled = onToggleWhenDisabled,
-                onCaptureImage = onCaptureImage,
+                onSetPause = onSetPause,
                 onCaptureImageWithUri = onCaptureImageWithUri,
                 onStartVideoRecording = onStartVideoRecording,
-                onStopVideoRecording = onStopVideoRecording
+                onStopVideoRecording = onStopVideoRecording,
+                zoomLevelDisplayState = remember { ZoomLevelDisplayState(isDebugMode) },
+                onImageWellClick = onImageWellClick,
+                onLockVideoRecording = onLockVideoRecording
+            )
+
+            DebugOverlayComponent(
+                toggleIsOpen = onToggleDebugOverlay,
+                previewUiState = previewUiState,
+                onChangeZoomScale = onChangeZoomScale
             )
+
             // displays toast when there is a message to show
             if (previewUiState.toastMessageToShow != null) {
                 TestableToast(
@@ -322,11 +348,23 @@ private fun ContentScreenPreview() {
 
 @Preview
 @Composable
-private fun ContentScreen_WhileRecording() {
+private fun ContentScreen_Standard_Idle() {
+    MaterialTheme(colorScheme = darkColorScheme()) {
+        ContentScreen(
+            previewUiState = FAKE_PREVIEW_UI_STATE_READY.copy(),
+            screenFlashUiState = ScreenFlash.ScreenFlashUiState(),
+            surfaceRequest = null
+        )
+    }
+}
+
+@Preview
+@Composable
+private fun ContentScreen_ImageOnly_Idle() {
     MaterialTheme(colorScheme = darkColorScheme()) {
         ContentScreen(
             previewUiState = FAKE_PREVIEW_UI_STATE_READY.copy(
-                videoRecordingState = VideoRecordingState.ACTIVE
+                captureButtonUiState = CaptureButtonUiState.Enabled.Idle(CaptureMode.IMAGE_ONLY)
             ),
             screenFlashUiState = ScreenFlash.ScreenFlashUiState(),
             surfaceRequest = null
@@ -334,9 +372,60 @@ private fun ContentScreen_WhileRecording() {
     }
 }
 
+@Preview
+@Composable
+private fun ContentScreen_VideoOnly_Idle() {
+    MaterialTheme(colorScheme = darkColorScheme()) {
+        ContentScreen(
+            previewUiState = FAKE_PREVIEW_UI_STATE_READY.copy(
+                captureButtonUiState = CaptureButtonUiState.Enabled.Idle(CaptureMode.VIDEO_ONLY)
+            ),
+            screenFlashUiState = ScreenFlash.ScreenFlashUiState(),
+            surfaceRequest = null
+        )
+    }
+}
+
+@Preview
+@Composable
+private fun ContentScreen_Standard_Recording() {
+    MaterialTheme(colorScheme = darkColorScheme()) {
+        ContentScreen(
+            previewUiState = FAKE_PREVIEW_UI_STATE_PRESSED_RECORDING,
+            screenFlashUiState = ScreenFlash.ScreenFlashUiState(),
+            surfaceRequest = null
+        )
+    }
+}
+
+@Preview
+@Composable
+private fun ContentScreen_Locked_Recording() {
+    MaterialTheme(colorScheme = darkColorScheme()) {
+        ContentScreen(
+            previewUiState = FAKE_PREVIEW_UI_STATE_LOCKED_RECORDING,
+            screenFlashUiState = ScreenFlash.ScreenFlashUiState(),
+            surfaceRequest = null
+        )
+    }
+}
+
 private val FAKE_PREVIEW_UI_STATE_READY = PreviewUiState.Ready(
     currentCameraSettings = DEFAULT_CAMERA_APP_SETTINGS,
+    videoRecordingState = VideoRecordingState.Inactive(),
     systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
     previewMode = PreviewMode.StandardMode {},
     captureModeToggleUiState = CaptureModeToggleUiState.Invisible
 )
+
+private val FAKE_PREVIEW_UI_STATE_PRESSED_RECORDING = FAKE_PREVIEW_UI_STATE_READY.copy(
+    videoRecordingState = VideoRecordingState.Active.Recording(0, 0.0, 0),
+    captureButtonUiState = CaptureButtonUiState.Enabled.Recording.PressedRecording,
+    audioUiState = AudioUiState.Enabled.On(1.0)
+)
+
+private val FAKE_PREVIEW_UI_STATE_LOCKED_RECORDING = FAKE_PREVIEW_UI_STATE_READY.copy(
+    videoRecordingState = VideoRecordingState.Active.Recording(0, 0.0, 0),
+    captureButtonUiState = CaptureButtonUiState.Enabled.Recording.LockedRecording,
+    audioUiState = AudioUiState.Enabled.On(1.0)
+)
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewUiState.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewUiState.kt
index 5152bbe..9b097e6 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewUiState.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewUiState.kt
@@ -15,10 +15,17 @@
  */
 package com.google.jetpackcamera.feature.preview
 
+import android.util.Size
+import com.google.jetpackcamera.core.camera.VideoRecordingState
+import com.google.jetpackcamera.feature.preview.ui.ImageWellUiState
 import com.google.jetpackcamera.feature.preview.ui.SnackbarData
 import com.google.jetpackcamera.feature.preview.ui.ToastMessage
 import com.google.jetpackcamera.settings.model.CameraAppSettings
+import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.FlashMode
+import com.google.jetpackcamera.settings.model.StabilizationMode
 import com.google.jetpackcamera.settings.model.SystemConstraints
+import com.google.jetpackcamera.settings.model.VideoQuality
 
 /**
  * Defines the current state of the [PreviewScreen].
@@ -28,38 +35,149 @@ sealed interface PreviewUiState {
 
     data class Ready(
         // "quick" settings
-        val currentCameraSettings: CameraAppSettings,
-        val systemConstraints: SystemConstraints,
+        val currentCameraSettings: CameraAppSettings = CameraAppSettings(),
+        val systemConstraints: SystemConstraints = SystemConstraints(),
         val zoomScale: Float = 1f,
-        val videoRecordingState: VideoRecordingState = VideoRecordingState.INACTIVE,
+        val videoRecordingState: VideoRecordingState = VideoRecordingState.Inactive(),
         val quickSettingsIsOpen: Boolean = false,
-        val audioAmplitude: Double = 0.0,
-        val audioMuted: Boolean = false,
 
         // todo: remove after implementing post capture screen
         val toastMessageToShow: ToastMessage? = null,
         val snackBarToShow: SnackbarData? = null,
         val lastBlinkTimeStamp: Long = 0,
-        val previewMode: PreviewMode,
-        val captureModeToggleUiState: CaptureModeToggleUiState,
+        val previewMode: PreviewMode = PreviewMode.StandardMode {},
+        val captureModeToggleUiState: CaptureModeToggleUiState = CaptureModeToggleUiState.Invisible,
         val sessionFirstFrameTimestamp: Long = 0L,
         val currentPhysicalCameraId: String? = null,
         val currentLogicalCameraId: String? = null,
-        val isDebugMode: Boolean = false
+        val debugUiState: DebugUiState = DebugUiState(),
+        val stabilizationUiState: StabilizationUiState = StabilizationUiState.Disabled,
+        val flashModeUiState: FlashModeUiState = FlashModeUiState.Unavailable,
+        val videoQuality: VideoQuality = VideoQuality.UNSPECIFIED,
+        val audioUiState: AudioUiState = AudioUiState.Disabled,
+        val elapsedTimeUiState: ElapsedTimeUiState = ElapsedTimeUiState.Unavailable,
+        val captureButtonUiState: CaptureButtonUiState = CaptureButtonUiState.Unavailable,
+        val imageWellUiState: ImageWellUiState = ImageWellUiState.NoPreviousCapture
     ) : PreviewUiState
 }
 
-/**
- * Defines the current state of Video Recording
- */
-enum class VideoRecordingState {
-    /**
-     * Camera is not currently recording a video
-     */
-    INACTIVE,
-
-    /**
-     * Camera is currently recording a video
-     */
-    ACTIVE
+data class DebugUiState(
+    val cameraPropertiesJSON: String = "",
+    val videoResolution: Size? = null,
+    val isDebugMode: Boolean = false,
+    val isDebugOverlayOpen: Boolean = false
+)
+val DEFAULT_CAPTURE_BUTTON_STATE = CaptureButtonUiState.Enabled.Idle(CaptureMode.STANDARD)
+
+sealed interface CaptureButtonUiState {
+    data object Unavailable : CaptureButtonUiState
+    sealed interface Enabled : CaptureButtonUiState {
+        data class Idle(val captureMode: CaptureMode) : Enabled
+
+        sealed interface Recording : Enabled {
+            data object PressedRecording : Recording
+            data object LockedRecording : Recording
+        }
+    }
+}
+sealed interface ElapsedTimeUiState {
+    data object Unavailable : ElapsedTimeUiState
+
+    data class Enabled(val elapsedTimeNanos: Long) : ElapsedTimeUiState
+}
+
+sealed interface AudioUiState {
+    val amplitude: Double
+
+    sealed interface Enabled : AudioUiState {
+        data class On(override val amplitude: Double) : Enabled
+        data object Mute : Enabled {
+            override val amplitude = 0.0
+        }
+    }
+
+    // todo give a disabledreason when audio permission is not granted
+    data object Disabled : AudioUiState {
+        override val amplitude = 0.0
+    }
+}
+
+sealed interface StabilizationUiState {
+    data object Disabled : StabilizationUiState
+
+    sealed interface Enabled : StabilizationUiState {
+        val stabilizationMode: StabilizationMode
+        val active: Boolean
+    }
+
+    data class Specific(
+        override val stabilizationMode: StabilizationMode,
+        override val active: Boolean = true
+    ) : Enabled {
+        init {
+            require(stabilizationMode != StabilizationMode.AUTO) {
+                "Specific StabilizationUiState cannot have AUTO stabilization mode."
+            }
+        }
+    }
+
+    data class Auto(override val stabilizationMode: StabilizationMode) : Enabled {
+        override val active = true
+    }
+}
+
+sealed class FlashModeUiState {
+    data object Unavailable : FlashModeUiState()
+
+    data class Available(
+        val selectedFlashMode: FlashMode,
+        val availableFlashModes: List<FlashMode>,
+        val isActive: Boolean
+    ) : FlashModeUiState() {
+        init {
+            check(selectedFlashMode in availableFlashModes) {
+                "Selected flash mode of $selectedFlashMode not in available modes: " +
+                    "$availableFlashModes"
+            }
+        }
+    }
+
+    companion object {
+        private val ORDERED_UI_SUPPORTED_FLASH_MODES = listOf(
+            FlashMode.OFF,
+            FlashMode.ON,
+            FlashMode.AUTO,
+            FlashMode.LOW_LIGHT_BOOST
+        )
+
+        /**
+         * Creates a FlashModeUiState from a selected flash mode and a set of supported flash modes
+         * that may not include flash modes supported by the UI.
+         */
+        fun createFrom(
+            selectedFlashMode: FlashMode,
+            supportedFlashModes: Set<FlashMode>
+        ): FlashModeUiState {
+            // Ensure we at least support one flash mode
+            check(supportedFlashModes.isNotEmpty()) {
+                "No flash modes supported. Should at least support OFF."
+            }
+
+            // Convert available flash modes to list we support in the UI in our desired order
+            val availableModes = ORDERED_UI_SUPPORTED_FLASH_MODES.filter {
+                it in supportedFlashModes
+            }
+
+            return if (availableModes.isEmpty() || availableModes == listOf(FlashMode.OFF)) {
+                // If we only support OFF, then return "Unavailable".
+                Unavailable
+            } else {
+                Available(
+                    selectedFlashMode = selectedFlashMode,
+                    availableFlashModes = availableModes,
+                    isActive = false
+                )
+            }
+        }
+    }
 }
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewViewModel.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewViewModel.kt
index fef3aa1..12deedf 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewViewModel.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/PreviewViewModel.kt
@@ -19,16 +19,20 @@ import android.content.ContentResolver
 import android.net.Uri
 import android.os.SystemClock
 import android.util.Log
+import android.util.Size
 import androidx.camera.core.SurfaceRequest
 import androidx.lifecycle.ViewModel
 import androidx.lifecycle.viewModelScope
 import androidx.tracing.Trace
 import androidx.tracing.traceAsync
+import com.google.jetpackcamera.core.camera.CameraState
 import com.google.jetpackcamera.core.camera.CameraUseCase
+import com.google.jetpackcamera.core.camera.VideoRecordingState
 import com.google.jetpackcamera.core.common.traceFirstFramePreview
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_FAILURE_TAG
 import com.google.jetpackcamera.feature.preview.ui.IMAGE_CAPTURE_SUCCESS_TAG
+import com.google.jetpackcamera.feature.preview.ui.ImageWellUiState
 import com.google.jetpackcamera.feature.preview.ui.SnackbarData
 import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_EXTERNAL_UNSUPPORTED_TAG
 import com.google.jetpackcamera.feature.preview.ui.VIDEO_CAPTURE_FAILURE_TAG
@@ -45,9 +49,11 @@ import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.LowLightBoost
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.LowLightBoostState
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.StreamConfig
 import com.google.jetpackcamera.settings.model.SystemConstraints
+import com.google.jetpackcamera.settings.model.VideoQuality
 import com.google.jetpackcamera.settings.model.forCurrentLens
 import dagger.assisted.Assisted
 import dagger.assisted.AssistedFactory
@@ -66,6 +72,7 @@ import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.StateFlow
 import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.distinctUntilChanged
 import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.flow.first
 import kotlinx.coroutines.flow.transform
@@ -89,6 +96,7 @@ class PreviewViewModel @AssistedInject constructor(
 ) : ViewModel() {
     private val _previewUiState: MutableStateFlow<PreviewUiState> =
         MutableStateFlow(PreviewUiState.NotReady)
+    private val lockedRecordingState: MutableStateFlow<Boolean> = MutableStateFlow(false)
 
     val previewUiState: StateFlow<PreviewUiState> =
         _previewUiState.asStateFlow()
@@ -99,6 +107,10 @@ class PreviewViewModel @AssistedInject constructor(
 
     private var recordingJob: Job? = null
 
+    private var externalUriIndex: Int = 0
+
+    private var cameraPropertiesJSON = ""
+
     val screenFlash = ScreenFlash(cameraUseCase, viewModelScope)
 
     private val snackBarCount = atomic(0)
@@ -108,10 +120,22 @@ class PreviewViewModel @AssistedInject constructor(
     // used to ensure we don't start the camera before initialization is complete.
     private var initializationDeferred: Deferred<Unit> = viewModelScope.async {
         cameraUseCase.initialize(
-            cameraAppSettings = settingsRepository.defaultCameraAppSettings.first(),
-            previewMode.toUseCaseMode(),
-            isDebugMode
-        )
+            cameraAppSettings = settingsRepository.defaultCameraAppSettings.first()
+                .applyPreviewMode(previewMode),
+            isDebugMode = isDebugMode
+        ) { cameraPropertiesJSON = it }
+    }
+
+    /**
+     * updates the capture mode based on the preview mode
+     */
+    private fun CameraAppSettings.applyPreviewMode(previewMode: PreviewMode): CameraAppSettings {
+        val captureMode = previewMode.toCaptureMode()
+        return if (captureMode == this.captureMode) {
+            this
+        } else {
+            this.copy(captureMode = captureMode)
+        }
     }
 
     init {
@@ -131,50 +155,205 @@ class PreviewViewModel @AssistedInject constructor(
             combine(
                 cameraUseCase.getCurrentSettings().filterNotNull(),
                 constraintsRepository.systemConstraints.filterNotNull(),
-                cameraUseCase.getCurrentCameraState()
-            ) { cameraAppSettings, systemConstraints, cameraState ->
+                cameraUseCase.getCurrentCameraState(),
+                lockedRecordingState.filterNotNull().distinctUntilChanged()
+            ) { cameraAppSettings, systemConstraints, cameraState, lockedState ->
+
+                var flashModeUiState: FlashModeUiState
                 _previewUiState.update { old ->
                     when (old) {
-                        is PreviewUiState.Ready ->
-                            old.copy(
-                                currentCameraSettings = cameraAppSettings,
-                                systemConstraints = systemConstraints,
-                                zoomScale = cameraState.zoomScale,
-                                sessionFirstFrameTimestamp = cameraState.sessionFirstFrameTimestamp,
-                                captureModeToggleUiState = getCaptureToggleUiState(
-                                    systemConstraints,
-                                    cameraAppSettings
-                                ),
-                                isDebugMode = isDebugMode,
-                                currentLogicalCameraId = cameraState.debugInfo.logicalCameraId,
-                                currentPhysicalCameraId = cameraState.debugInfo.physicalCameraId
+                        is PreviewUiState.NotReady -> {
+                            // Generate initial FlashModeUiState
+                            val supportedFlashModes =
+                                systemConstraints.forCurrentLens(cameraAppSettings)
+                                    ?.supportedFlashModes
+                                    ?: setOf(FlashMode.OFF)
+                            flashModeUiState = FlashModeUiState.createFrom(
+                                selectedFlashMode = cameraAppSettings.flashMode,
+                                supportedFlashModes = supportedFlashModes
                             )
+                            // This is the first PreviewUiState.Ready. Create the initial
+                            // PreviewUiState.Ready from defaults and initialize it below.
+                            PreviewUiState.Ready()
+                        }
+
+                        is PreviewUiState.Ready -> {
+                            val previousCameraSettings = old.currentCameraSettings
+                            val previousConstraints = old.systemConstraints
 
-                        is PreviewUiState.NotReady ->
-                            PreviewUiState.Ready(
+                            flashModeUiState = old.flashModeUiState.updateFrom(
                                 currentCameraSettings = cameraAppSettings,
-                                systemConstraints = systemConstraints,
-                                zoomScale = cameraState.zoomScale,
-                                sessionFirstFrameTimestamp = cameraState.sessionFirstFrameTimestamp,
-                                previewMode = previewMode,
-                                captureModeToggleUiState = getCaptureToggleUiState(
-                                    systemConstraints,
-                                    cameraAppSettings
-                                ),
-                                isDebugMode = isDebugMode,
-                                currentLogicalCameraId = cameraState.debugInfo.logicalCameraId,
-                                currentPhysicalCameraId = cameraState.debugInfo.physicalCameraId
+                                previousCameraSettings = previousCameraSettings,
+                                currentConstraints = systemConstraints,
+                                previousConstraints = previousConstraints,
+                                cameraState = cameraState
                             )
-                    }
+
+                            // We have a previous `PreviewUiState.Ready`, return it here and
+                            // update it below.
+                            old
+                        }
+                    }.copy(
+                        // Update or initialize PreviewUiState.Ready
+                        previewMode = previewMode,
+                        currentCameraSettings = cameraAppSettings.applyPreviewMode(previewMode),
+                        systemConstraints = systemConstraints,
+                        zoomScale = cameraState.zoomScale,
+                        videoRecordingState = cameraState.videoRecordingState,
+                        sessionFirstFrameTimestamp = cameraState.sessionFirstFrameTimestamp,
+                        captureModeToggleUiState = getCaptureToggleUiState(
+                            systemConstraints,
+                            cameraAppSettings
+                        ),
+                        currentLogicalCameraId = cameraState.debugInfo.logicalCameraId,
+                        currentPhysicalCameraId = cameraState.debugInfo.physicalCameraId,
+                        debugUiState = DebugUiState(
+                            cameraPropertiesJSON = cameraPropertiesJSON,
+                            videoResolution = Size(
+                                cameraState.videoQualityInfo.width,
+                                cameraState.videoQualityInfo.height
+                            ),
+                            isDebugMode = isDebugMode
+                        ),
+                        stabilizationUiState = stabilizationUiStateFrom(
+                            cameraAppSettings,
+                            cameraState
+                        ),
+                        flashModeUiState = flashModeUiState,
+                        videoQuality = cameraState.videoQualityInfo.quality,
+                        audioUiState = getAudioUiState(
+                            cameraAppSettings.audioEnabled,
+                            cameraState.videoRecordingState
+                        ),
+                        elapsedTimeUiState = getElapsedTimeUiState(cameraState.videoRecordingState),
+                        captureButtonUiState = getCaptureButtonUiState(
+                            cameraAppSettings,
+                            cameraState,
+                            lockedState
+                        )
+                    )
                 }
             }.collect {}
         }
     }
 
-    private fun PreviewMode.toUseCaseMode() = when (this) {
-        is PreviewMode.ExternalImageCaptureMode -> CameraUseCase.UseCaseMode.IMAGE_ONLY
-        is PreviewMode.ExternalVideoCaptureMode -> CameraUseCase.UseCaseMode.VIDEO_ONLY
-        is PreviewMode.StandardMode -> CameraUseCase.UseCaseMode.STANDARD
+    fun updateLastCapturedImageUri(uri: Uri) {
+        viewModelScope.launch {
+            _previewUiState.update { old ->
+                (old as PreviewUiState.Ready)
+                    .copy(imageWellUiState = ImageWellUiState.LastCapture(uri))
+            }
+        }
+    }
+
+    private fun getElapsedTimeUiState(
+        videoRecordingState: VideoRecordingState
+    ): ElapsedTimeUiState = when (videoRecordingState) {
+        is VideoRecordingState.Active ->
+            ElapsedTimeUiState.Enabled(videoRecordingState.elapsedTimeNanos)
+
+        is VideoRecordingState.Inactive ->
+            ElapsedTimeUiState.Enabled(videoRecordingState.finalElapsedTimeNanos)
+
+        VideoRecordingState.Starting -> ElapsedTimeUiState.Enabled(0L)
+    }
+
+    /**
+     * Updates the FlashModeUiState based on the changes in flash mode or constraints
+     */
+    private fun FlashModeUiState.updateFrom(
+        currentCameraSettings: CameraAppSettings,
+        previousCameraSettings: CameraAppSettings,
+        currentConstraints: SystemConstraints,
+        previousConstraints: SystemConstraints,
+        cameraState: CameraState
+    ): FlashModeUiState {
+        val currentFlashMode = currentCameraSettings.flashMode
+        val currentSupportedFlashModes =
+            currentConstraints.forCurrentLens(currentCameraSettings)?.supportedFlashModes
+        return when (this) {
+            is FlashModeUiState.Unavailable -> {
+                // When previous state was "Unavailable", we'll try to create a new FlashModeUiState
+                FlashModeUiState.createFrom(
+                    selectedFlashMode = currentFlashMode,
+                    supportedFlashModes = currentSupportedFlashModes ?: setOf(FlashMode.OFF)
+                )
+            }
+
+            is FlashModeUiState.Available -> {
+                val previousFlashMode = previousCameraSettings.flashMode
+                val previousSupportedFlashModes =
+                    previousConstraints.forCurrentLens(previousCameraSettings)?.supportedFlashModes
+                if (previousSupportedFlashModes != currentSupportedFlashModes) {
+                    // Supported flash modes have changed, generate a new FlashModeUiState
+                    FlashModeUiState.createFrom(
+                        selectedFlashMode = currentFlashMode,
+                        supportedFlashModes = currentSupportedFlashModes ?: setOf(FlashMode.OFF)
+                    )
+                } else if (previousFlashMode != currentFlashMode) {
+                    // Only the selected flash mode has changed, just update the flash mode
+                    copy(selectedFlashMode = currentFlashMode)
+                } else {
+                    if (currentFlashMode == FlashMode.LOW_LIGHT_BOOST) {
+                        copy(
+                            isActive = cameraState.lowLightBoostState == LowLightBoostState.ACTIVE
+                        )
+                    } else {
+                        // Nothing has changed
+                        this
+                    }
+                }
+            }
+        }
+    }
+
+    private fun getAudioUiState(
+        isAudioEnabled: Boolean,
+        videoRecordingState: VideoRecordingState
+    ): AudioUiState = if (isAudioEnabled) {
+        if (videoRecordingState is VideoRecordingState.Active) {
+            AudioUiState.Enabled.On(videoRecordingState.audioAmplitude)
+        } else {
+            AudioUiState.Enabled.On(0.0)
+        }
+    } else {
+        AudioUiState.Enabled.Mute
+    }
+
+    private fun stabilizationUiStateFrom(
+        cameraAppSettings: CameraAppSettings,
+        cameraState: CameraState
+    ): StabilizationUiState {
+        val expectedMode = cameraAppSettings.stabilizationMode
+        val actualMode = cameraState.stabilizationMode
+        check(actualMode != StabilizationMode.AUTO) {
+            "CameraState should never resolve to AUTO stabilization mode"
+        }
+        return when (expectedMode) {
+            StabilizationMode.OFF -> StabilizationUiState.Disabled
+            StabilizationMode.AUTO -> {
+                if (actualMode !in setOf(StabilizationMode.ON, StabilizationMode.OPTICAL)) {
+                    StabilizationUiState.Disabled
+                } else {
+                    StabilizationUiState.Auto(actualMode)
+                }
+            }
+
+            StabilizationMode.ON,
+            StabilizationMode.HIGH_QUALITY,
+            StabilizationMode.OPTICAL ->
+                StabilizationUiState.Specific(
+                    stabilizationMode = expectedMode,
+                    active = expectedMode == actualMode
+                )
+        }
+    }
+
+    private fun PreviewMode.toCaptureMode() = when (this) {
+        is PreviewMode.ExternalImageCaptureMode -> CaptureMode.IMAGE_ONLY
+        is PreviewMode.ExternalMultipleImageCaptureMode -> CaptureMode.IMAGE_ONLY
+        is PreviewMode.ExternalVideoCaptureMode -> CaptureMode.VIDEO_ONLY
+        is PreviewMode.StandardMode -> CaptureMode.STANDARD
     }
 
     /**
@@ -206,34 +385,62 @@ class PreviewViewModel @AssistedInject constructor(
                     cameraUseCase.setFlashMode(entry.value as FlashMode)
                 }
 
-                CameraAppSettings::captureMode -> {
-                    cameraUseCase.setCaptureMode(entry.value as CaptureMode)
+                CameraAppSettings::streamConfig -> {
+                    cameraUseCase.setStreamConfig(entry.value as StreamConfig)
                 }
 
                 CameraAppSettings::aspectRatio -> {
                     cameraUseCase.setAspectRatio(entry.value as AspectRatio)
                 }
 
-                CameraAppSettings::previewStabilization -> {
-                    cameraUseCase.setPreviewStabilization(entry.value as Stabilization)
-                }
-
-                CameraAppSettings::videoCaptureStabilization -> {
-                    cameraUseCase.setVideoCaptureStabilization(
-                        entry.value as Stabilization
-                    )
+                CameraAppSettings::stabilizationMode -> {
+                    cameraUseCase.setStabilizationMode(entry.value as StabilizationMode)
                 }
 
                 CameraAppSettings::targetFrameRate -> {
                     cameraUseCase.setTargetFrameRate(entry.value as Int)
                 }
 
+                CameraAppSettings::maxVideoDurationMillis -> {
+                    cameraUseCase.setMaxVideoDuration(entry.value as Long)
+                }
+
+                CameraAppSettings::videoQuality -> {
+                    cameraUseCase.setVideoQuality(entry.value as VideoQuality)
+                }
+
+                CameraAppSettings::audioEnabled -> {
+                    cameraUseCase.setAudioEnabled(entry.value as Boolean)
+                }
+
                 CameraAppSettings::darkMode -> {}
 
                 else -> TODO("Unhandled CameraAppSetting $entry")
             }
         }
     }
+    fun getCaptureButtonUiState(
+        cameraAppSettings: CameraAppSettings,
+        cameraState: CameraState,
+        lockedState: Boolean
+    ): CaptureButtonUiState = when (cameraState.videoRecordingState) {
+        // if not currently recording, check capturemode to determine idle capture button UI
+        is VideoRecordingState.Inactive ->
+            CaptureButtonUiState
+                .Enabled.Idle(captureMode = cameraAppSettings.captureMode)
+
+        // display different capture button UI depending on if recording is pressed or locked
+        is VideoRecordingState.Active.Recording, is VideoRecordingState.Active.Paused ->
+            if (lockedState) {
+                CaptureButtonUiState.Enabled.Recording.LockedRecording
+            } else {
+                CaptureButtonUiState.Enabled.Recording.PressedRecording
+            }
+
+        VideoRecordingState.Starting ->
+            CaptureButtonUiState
+                .Enabled.Idle(captureMode = cameraAppSettings.captureMode)
+    }
 
     private fun getCaptureToggleUiState(
         systemConstraints: SystemConstraints,
@@ -246,7 +453,7 @@ class PreviewViewModel @AssistedInject constructor(
             it.supportedDynamicRanges.size > 1
         } ?: false
         val hdrImageFormatSupported =
-            cameraConstraints?.supportedImageFormatsMap?.get(cameraAppSettings.captureMode)?.let {
+            cameraConstraints?.supportedImageFormatsMap?.get(cameraAppSettings.streamConfig)?.let {
                 it.size > 1
             } ?: false
         val isShown = previewMode is PreviewMode.ExternalImageCaptureMode ||
@@ -280,7 +487,7 @@ class PreviewViewModel @AssistedInject constructor(
                         hdrImageFormatSupported,
                         systemConstraints,
                         cameraAppSettings.cameraLensFacing,
-                        cameraAppSettings.captureMode,
+                        cameraAppSettings.streamConfig,
                         cameraAppSettings.concurrentCameraMode
                     )
                 )
@@ -296,7 +503,7 @@ class PreviewViewModel @AssistedInject constructor(
         hdrImageFormatSupported: Boolean,
         systemConstraints: SystemConstraints,
         currentLensFacing: LensFacing,
-        currentCaptureMode: CaptureMode,
+        currentStreamConfig: StreamConfig,
         concurrentCameraMode: ConcurrentCameraMode
     ): CaptureModeToggleUiState.DisabledReason {
         when (captureModeToggleUiState) {
@@ -316,14 +523,14 @@ class PreviewViewModel @AssistedInject constructor(
                     if (systemConstraints
                             .perLensConstraints[currentLensFacing]
                             ?.supportedImageFormatsMap
-                            ?.anySupportsUltraHdr { it != currentCaptureMode } == true
+                            ?.anySupportsUltraHdr { it != currentStreamConfig } == true
                     ) {
-                        return when (currentCaptureMode) {
-                            CaptureMode.MULTI_STREAM ->
+                        return when (currentStreamConfig) {
+                            StreamConfig.MULTI_STREAM ->
                                 CaptureModeToggleUiState.DisabledReason
                                     .HDR_IMAGE_UNSUPPORTED_ON_MULTI_STREAM
 
-                            CaptureMode.SINGLE_STREAM ->
+                            StreamConfig.SINGLE_STREAM ->
                                 CaptureModeToggleUiState.DisabledReason
                                     .HDR_IMAGE_UNSUPPORTED_ON_SINGLE_STREAM
                         }
@@ -365,14 +572,14 @@ class PreviewViewModel @AssistedInject constructor(
         lensFilter(it.key) && it.value.supportedDynamicRanges.size > 1
     } != null
 
-    private fun Map<CaptureMode, Set<ImageOutputFormat>>.anySupportsUltraHdr(
-        captureModeFilter: (CaptureMode) -> Boolean
+    private fun Map<StreamConfig, Set<ImageOutputFormat>>.anySupportsUltraHdr(
+        captureModeFilter: (StreamConfig) -> Boolean
     ): Boolean = asSequence().firstOrNull {
         captureModeFilter(it.key) && it.value.contains(ImageOutputFormat.JPEG_ULTRA_HDR)
     } != null
 
     private fun SystemConstraints.anySupportsUltraHdr(
-        captureModeFilter: (CaptureMode) -> Boolean = { true },
+        captureModeFilter: (StreamConfig) -> Boolean = { true },
         lensFilter: (LensFacing) -> Boolean
     ): Boolean = perLensConstraints.asSequence().firstOrNull { lensConstraints ->
         lensFilter(lensConstraints.key) &&
@@ -431,9 +638,9 @@ class PreviewViewModel @AssistedInject constructor(
         }
     }
 
-    fun setCaptureMode(captureMode: CaptureMode) {
+    fun setStreamConfig(streamConfig: StreamConfig) {
         viewModelScope.launch {
-            cameraUseCase.setCaptureMode(captureMode)
+            cameraUseCase.setStreamConfig(streamConfig)
         }
     }
 
@@ -445,20 +652,27 @@ class PreviewViewModel @AssistedInject constructor(
         }
     }
 
-    fun setAudioMuted(shouldMuteAudio: Boolean) {
+    fun setAudioEnabled(shouldEnableAudio: Boolean) {
         viewModelScope.launch {
-            cameraUseCase.setAudioMuted(shouldMuteAudio)
+            cameraUseCase.setAudioEnabled(shouldEnableAudio)
         }
 
         Log.d(
             TAG,
-            "Toggle Audio ${
-                (previewUiState.value as PreviewUiState.Ready)
-                    .currentCameraSettings.audioMuted
-            }"
+            "Toggle Audio: $shouldEnableAudio"
         )
     }
 
+    fun setPaused(shouldBePaused: Boolean) {
+        viewModelScope.launch {
+            if (shouldBePaused) {
+                cameraUseCase.pauseVideoRecording()
+            } else {
+                cameraUseCase.resumeVideoRecording()
+            }
+        }
+    }
+
     private fun showExternalVideoCaptureUnsupportedToast() {
         viewModelScope.launch {
             _previewUiState.update { old ->
@@ -474,35 +688,11 @@ class PreviewViewModel @AssistedInject constructor(
         }
     }
 
-    fun captureImage() {
-        if (previewUiState.value is PreviewUiState.Ready &&
-            (previewUiState.value as PreviewUiState.Ready).previewMode is
-                PreviewMode.ExternalVideoCaptureMode
-        ) {
-            showExternalVideoCaptureUnsupportedToast()
-            return
-        }
-        Log.d(TAG, "captureImage")
-        viewModelScope.launch {
-            captureImageInternal(
-                doTakePicture = {
-                    cameraUseCase.takePicture {
-                        _previewUiState.update { old ->
-                            (old as? PreviewUiState.Ready)?.copy(
-                                lastBlinkTimeStamp = System.currentTimeMillis()
-                            ) ?: old
-                        }
-                    }
-                }
-            )
-        }
-    }
-
     fun captureImageWithUri(
         contentResolver: ContentResolver,
         imageCaptureUri: Uri?,
         ignoreUri: Boolean = false,
-        onImageCapture: (ImageCaptureEvent) -> Unit
+        onImageCapture: (ImageCaptureEvent, Int) -> Unit
     ) {
         if (previewUiState.value is PreviewUiState.Ready &&
             (previewUiState.value as PreviewUiState.Ready).previewMode is
@@ -532,6 +722,18 @@ class PreviewViewModel @AssistedInject constructor(
         }
         Log.d(TAG, "captureImageWithUri")
         viewModelScope.launch {
+            val (uriIndex: Int, finalImageUri: Uri?) =
+                (
+                    (previewUiState.value as? PreviewUiState.Ready)?.previewMode as?
+                        PreviewMode.ExternalMultipleImageCaptureMode
+                    )?.let {
+                    val uri = if (ignoreUri || it.imageCaptureUris.isNullOrEmpty()) {
+                        null
+                    } else {
+                        it.imageCaptureUris[externalUriIndex]
+                    }
+                    Pair(externalUriIndex, uri)
+                } ?: Pair(-1, imageCaptureUri)
             captureImageInternal(
                 doTakePicture = {
                     cameraUseCase.takePicture({
@@ -540,13 +742,31 @@ class PreviewViewModel @AssistedInject constructor(
                                 lastBlinkTimeStamp = System.currentTimeMillis()
                             ) ?: old
                         }
-                    }, contentResolver, imageCaptureUri, ignoreUri).savedUri
+                    }, contentResolver, finalImageUri, ignoreUri).savedUri
+                },
+                onSuccess = { savedUri ->
+                    savedUri?.let {
+                        updateLastCapturedImageUri(it)
+                    }
+                    onImageCapture(ImageCaptureEvent.ImageSaved(savedUri), uriIndex)
                 },
-                onSuccess = { savedUri -> onImageCapture(ImageCaptureEvent.ImageSaved(savedUri)) },
                 onFailure = { exception ->
-                    onImageCapture(ImageCaptureEvent.ImageCaptureError(exception))
+                    onImageCapture(ImageCaptureEvent.ImageCaptureError(exception), uriIndex)
                 }
             )
+            incrementExternalMultipleImageCaptureModeUriIndexIfNeeded()
+        }
+    }
+
+    private fun incrementExternalMultipleImageCaptureModeUriIndexIfNeeded() {
+        (
+            (previewUiState.value as? PreviewUiState.Ready)
+                ?.previewMode as? PreviewMode.ExternalMultipleImageCaptureMode
+            )?.let {
+            if (!it.imageCaptureUris.isNullOrEmpty()) {
+                externalUriIndex++
+                Log.d(TAG, "Uri index for multiple image capture at $externalUriIndex")
+            }
         }
     }
 
@@ -635,7 +855,6 @@ class PreviewViewModel @AssistedInject constructor(
             val cookie = "Video-${videoCaptureStartedCount.incrementAndGet()}"
             try {
                 cameraUseCase.startVideoRecording(videoCaptureUri, shouldUseUri) {
-                    var audioAmplitude = 0.0
                     var snackbarToShow: SnackbarData? = null
                     when (it) {
                         is CameraUseCase.OnVideoRecordEvent.OnVideoRecorded -> {
@@ -659,26 +878,16 @@ class PreviewViewModel @AssistedInject constructor(
                                 testTag = VIDEO_CAPTURE_FAILURE_TAG
                             )
                         }
-
-                        is CameraUseCase.OnVideoRecordEvent.OnVideoRecordStatus -> {
-                            audioAmplitude = it.audioAmplitude
-                        }
                     }
 
                     viewModelScope.launch {
                         _previewUiState.update { old ->
                             (old as? PreviewUiState.Ready)?.copy(
-                                snackBarToShow = snackbarToShow,
-                                audioAmplitude = audioAmplitude
+                                snackBarToShow = snackbarToShow
                             ) ?: old
                         }
                     }
                 }
-                _previewUiState.update { old ->
-                    (old as? PreviewUiState.Ready)?.copy(
-                        videoRecordingState = VideoRecordingState.ACTIVE
-                    ) ?: old
-                }
                 Log.d(TAG, "cameraUseCase.startRecording success")
             } catch (exception: IllegalStateException) {
                 Log.d(TAG, "cameraUseCase.startVideoRecording error", exception)
@@ -689,14 +898,21 @@ class PreviewViewModel @AssistedInject constructor(
     fun stopVideoRecording() {
         Log.d(TAG, "stopVideoRecording")
         viewModelScope.launch {
-            _previewUiState.update { old ->
-                (old as? PreviewUiState.Ready)?.copy(
-                    videoRecordingState = VideoRecordingState.INACTIVE
-                ) ?: old
+            cameraUseCase.stopVideoRecording()
+            recordingJob?.cancel()
+        }
+        setLockedRecording(false)
+    }
+
+    /**
+     "Locks" the video recording such that the user no longer needs to keep their finger pressed on the capture button
+     */
+    fun setLockedRecording(isLocked: Boolean) {
+        viewModelScope.launch {
+            lockedRecordingState.update {
+                isLocked
             }
         }
-        cameraUseCase.stopVideoRecording()
-        recordingJob?.cancel()
     }
 
     fun setZoomScale(scale: Float) {
@@ -715,12 +931,6 @@ class PreviewViewModel @AssistedInject constructor(
         }
     }
 
-    fun setLowLightBoost(lowLightBoost: LowLightBoost) {
-        viewModelScope.launch {
-            cameraUseCase.setLowLightBoost(lowLightBoost)
-        }
-    }
-
     fun setImageFormat(imageFormat: ImageOutputFormat) {
         viewModelScope.launch {
             cameraUseCase.setImageFormat(imageFormat)
@@ -738,6 +948,21 @@ class PreviewViewModel @AssistedInject constructor(
         }
     }
 
+    fun toggleDebugOverlay() {
+        viewModelScope.launch {
+            _previewUiState.update { old ->
+                (old as? PreviewUiState.Ready)?.copy(
+                    debugUiState = DebugUiState(
+                        old.debugUiState.cameraPropertiesJSON,
+                        old.debugUiState.videoResolution,
+                        old.debugUiState.isDebugMode,
+                        !old.debugUiState.isDebugOverlayOpen
+                    )
+                ) ?: old
+            }
+        }
+    }
+
     fun tapToFocus(x: Float, y: Float) {
         Log.d(TAG, "tapToFocus")
         viewModelScope.launch {
@@ -787,22 +1012,14 @@ class PreviewViewModel @AssistedInject constructor(
     }
 
     sealed interface ImageCaptureEvent {
-        data class ImageSaved(
-            val savedUri: Uri? = null
-        ) : ImageCaptureEvent
+        data class ImageSaved(val savedUri: Uri? = null) : ImageCaptureEvent
 
-        data class ImageCaptureError(
-            val exception: Exception
-        ) : ImageCaptureEvent
+        data class ImageCaptureError(val exception: Exception) : ImageCaptureEvent
     }
 
     sealed interface VideoCaptureEvent {
-        data class VideoSaved(
-            val savedUri: Uri
-        ) : VideoCaptureEvent
+        data class VideoSaved(val savedUri: Uri) : VideoCaptureEvent
 
-        data class VideoCaptureError(
-            val error: Throwable?
-        ) : VideoCaptureEvent
+        data class VideoCaptureError(val error: Throwable?) : VideoCaptureEvent
     }
 }
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsEnums.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsEnums.kt
index 2ee1e78..0b8115e 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsEnums.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsEnums.kt
@@ -96,6 +96,18 @@ enum class CameraFlashMode : QuickSettingsEnum {
         override fun getImageVector() = Icons.Filled.FlashOn
         override fun getTextResId() = R.string.quick_settings_flash_on
         override fun getDescriptionResId() = R.string.quick_settings_flash_on_description
+    },
+    LOW_LIGHT_BOOST_INACTIVE {
+        override fun getDrawableResId() = null
+        override fun getImageVector() = Icons.Outlined.Nightlight
+        override fun getTextResId() = R.string.quick_settings_flash_llb
+        override fun getDescriptionResId() = R.string.quick_settings_flash_llb_description
+    },
+    LOW_LIGHT_BOOST_ACTIVE {
+        override fun getDrawableResId() = null
+        override fun getImageVector() = Icons.Filled.Nightlight
+        override fun getTextResId() = R.string.quick_settings_flash_llb
+        override fun getDescriptionResId() = R.string.quick_settings_flash_llb_description
     }
 }
 
@@ -120,7 +132,7 @@ enum class CameraAspectRatio : QuickSettingsEnum {
     }
 }
 
-enum class CameraCaptureMode : QuickSettingsEnum {
+enum class CameraStreamConfig : QuickSettingsEnum {
     MULTI_STREAM {
         override fun getDrawableResId() = R.drawable.multi_stream_icon
         override fun getImageVector() = null // this icon is not available
@@ -150,25 +162,6 @@ enum class CameraDynamicRange : QuickSettingsEnum {
     }
 }
 
-enum class CameraLowLightBoost : QuickSettingsEnum {
-
-    ENABLED {
-        override fun getDrawableResId() = null
-        override fun getImageVector() = Icons.Filled.Nightlight
-        override fun getTextResId() = R.string.quick_settings_lowlightboost_enabled
-        override fun getDescriptionResId() =
-            R.string.quick_settings_lowlightboost_enabled_description
-    },
-
-    DISABLED {
-        override fun getDrawableResId() = null
-        override fun getImageVector() = Icons.Outlined.Nightlight
-        override fun getTextResId() = R.string.quick_settings_lowlightboost_disabled
-        override fun getDescriptionResId() =
-            R.string.quick_settings_lowlightboost_disabled_description
-    }
-}
-
 enum class CameraConcurrentCameraMode : QuickSettingsEnum {
     OFF {
         override fun getDrawableResId() = R.drawable.picture_in_picture_off_icon
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsScreen.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsScreen.kt
index 7dbb474..93a55f8 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsScreen.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/QuickSettingsScreen.kt
@@ -16,11 +16,14 @@
 package com.google.jetpackcamera.feature.preview.quicksettings
 
 import androidx.activity.compose.BackHandler
-import androidx.compose.animation.animateColorAsState
-import androidx.compose.animation.core.animateFloatAsState
-import androidx.compose.animation.core.tween
+import androidx.compose.animation.AnimatedVisibility
+import androidx.compose.animation.fadeIn
+import androidx.compose.animation.fadeOut
+import androidx.compose.animation.slideInVertically
+import androidx.compose.animation.slideOutVertically
 import androidx.compose.foundation.background
 import androidx.compose.foundation.clickable
+import androidx.compose.foundation.interaction.MutableInteractionSource
 import androidx.compose.foundation.layout.Arrangement
 import androidx.compose.foundation.layout.Column
 import androidx.compose.foundation.layout.fillMaxSize
@@ -33,39 +36,42 @@ import androidx.compose.runtime.remember
 import androidx.compose.runtime.setValue
 import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
-import androidx.compose.ui.draw.alpha
 import androidx.compose.ui.graphics.Color
 import androidx.compose.ui.platform.testTag
 import androidx.compose.ui.res.dimensionResource
 import androidx.compose.ui.tooling.preview.Preview
+import com.google.jetpackcamera.core.camera.VideoRecordingState
 import com.google.jetpackcamera.feature.preview.CaptureModeToggleUiState
+import com.google.jetpackcamera.feature.preview.DEFAULT_CAPTURE_BUTTON_STATE
+import com.google.jetpackcamera.feature.preview.FlashModeUiState
 import com.google.jetpackcamera.feature.preview.PreviewMode
 import com.google.jetpackcamera.feature.preview.PreviewUiState
 import com.google.jetpackcamera.feature.preview.R
-import com.google.jetpackcamera.feature.preview.quicksettings.ui.ExpandedQuickSetRatio
-import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_CAPTURE_MODE_BUTTON
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.FocusedQuickSetRatio
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLASH_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_FLIP_CAMERA_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_HDR_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_RATIO_BUTTON
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QUICK_SETTINGS_STREAM_CONFIG_BUTTON
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickFlipCamera
-import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetCaptureMode
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetConcurrentCamera
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetFlash
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetHdr
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetRatio
+import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSetStreamConfig
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSettingsGrid
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CameraAppSettings
 import com.google.jetpackcamera.settings.model.CameraConstraints
-import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
+import com.google.jetpackcamera.settings.model.DEFAULT_HDR_DYNAMIC_RANGE
+import com.google.jetpackcamera.settings.model.DEFAULT_HDR_IMAGE_OUTPUT
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.LowLightBoost
+import com.google.jetpackcamera.settings.model.StreamConfig
 import com.google.jetpackcamera.settings.model.TYPICAL_SYSTEM_CONSTRAINTS
 import com.google.jetpackcamera.settings.model.forCurrentLens
 
@@ -80,98 +86,97 @@ fun QuickSettingsScreenOverlay(
     onLensFaceClick: (lensFace: LensFacing) -> Unit,
     onFlashModeClick: (flashMode: FlashMode) -> Unit,
     onAspectRatioClick: (aspectRation: AspectRatio) -> Unit,
-    onCaptureModeClick: (captureMode: CaptureMode) -> Unit,
+    onStreamConfigClick: (streamConfig: StreamConfig) -> Unit,
     onDynamicRangeClick: (dynamicRange: DynamicRange) -> Unit,
     onImageOutputFormatClick: (imageOutputFormat: ImageOutputFormat) -> Unit,
     onConcurrentCameraModeClick: (concurrentCameraMode: ConcurrentCameraMode) -> Unit,
-    onLowLightBoostClick: (lowLightBoost: LowLightBoost) -> Unit,
     modifier: Modifier = Modifier,
     isOpen: Boolean = false
 ) {
-    var shouldShowQuickSetting by remember {
-        mutableStateOf(IsExpandedQuickSetting.NONE)
+    var focusedQuickSetting by remember {
+        mutableStateOf(FocusedQuickSetting.NONE)
     }
 
-    val backgroundColor =
-        animateColorAsState(
-            targetValue = Color.Black.copy(alpha = if (isOpen) 0.7f else 0f),
-            label = "backgroundColorAnimation"
-        )
-
-    val contentAlpha =
-        animateFloatAsState(
-            targetValue = if (isOpen) 1f else 0f,
-            label = "contentAlphaAnimation",
-            animationSpec = tween()
-        )
-
-    if (isOpen) {
+    AnimatedVisibility(
+        visible = isOpen,
+        enter = slideInVertically(initialOffsetY = { -it / 8 }) + fadeIn(),
+        exit = slideOutVertically(targetOffsetY = { -it / 16 }) + fadeOut()
+    ) {
         val onBack = {
-            when (shouldShowQuickSetting) {
-                IsExpandedQuickSetting.NONE -> toggleIsOpen()
-                else -> shouldShowQuickSetting = IsExpandedQuickSetting.NONE
+            when (focusedQuickSetting) {
+                FocusedQuickSetting.NONE -> toggleIsOpen()
+                else -> focusedQuickSetting = FocusedQuickSetting.NONE
             }
         }
+        // close out of focused quick setting
+        if (!isOpen) {
+            focusedQuickSetting = FocusedQuickSetting.NONE
+        }
+
         BackHandler(onBack = onBack)
         Column(
             modifier =
             modifier
                 .fillMaxSize()
-                .background(color = backgroundColor.value)
-                .alpha(alpha = contentAlpha.value)
-                .clickable(onClick = onBack),
+                .background(color = Color.Black.copy(alpha = 0.7f))
+                .clickable(
+                    onClick = onBack,
+                    indication = null,
+                    interactionSource = remember {
+                        MutableInteractionSource()
+                    }
+                ),
             verticalArrangement = Arrangement.Center,
             horizontalAlignment = Alignment.CenterHorizontally
         ) {
             ExpandedQuickSettingsUi(
                 previewUiState = previewUiState,
                 currentCameraSettings = currentCameraSettings,
-                shouldShowQuickSetting = shouldShowQuickSetting,
-                setVisibleQuickSetting = { enum: IsExpandedQuickSetting ->
-                    shouldShowQuickSetting = enum
+                focusedQuickSetting = focusedQuickSetting,
+                setFocusedQuickSetting = { enum: FocusedQuickSetting ->
+                    focusedQuickSetting = enum
                 },
                 onLensFaceClick = onLensFaceClick,
                 onFlashModeClick = onFlashModeClick,
                 onAspectRatioClick = onAspectRatioClick,
-                onCaptureModeClick = onCaptureModeClick,
+                onStreamConfigClick = onStreamConfigClick,
                 onDynamicRangeClick = onDynamicRangeClick,
                 onImageOutputFormatClick = onImageOutputFormatClick,
-                onConcurrentCameraModeClick = onConcurrentCameraModeClick,
-                onLowLightBoostClick = onLowLightBoostClick
+                onConcurrentCameraModeClick = onConcurrentCameraModeClick
             )
         }
-    } else {
-        shouldShowQuickSetting = IsExpandedQuickSetting.NONE
     }
 }
 
-// enum representing which individual quick setting is currently expanded
-private enum class IsExpandedQuickSetting {
+// enum representing which individual quick setting is currently focused
+private enum class FocusedQuickSetting {
     NONE,
     ASPECT_RATIO
 }
 
+// todo: Add UI states for Quick Settings buttons
+
 /**
- * The UI component for quick settings when it is expanded.
+ * The UI component for quick settings when it is focused.
  */
 @Composable
 private fun ExpandedQuickSettingsUi(
+    modifier: Modifier = Modifier,
     previewUiState: PreviewUiState.Ready,
     currentCameraSettings: CameraAppSettings,
     onLensFaceClick: (newLensFace: LensFacing) -> Unit,
     onFlashModeClick: (flashMode: FlashMode) -> Unit,
     onAspectRatioClick: (aspectRation: AspectRatio) -> Unit,
-    onCaptureModeClick: (captureMode: CaptureMode) -> Unit,
-    shouldShowQuickSetting: IsExpandedQuickSetting,
-    setVisibleQuickSetting: (IsExpandedQuickSetting) -> Unit,
+    onStreamConfigClick: (streamConfig: StreamConfig) -> Unit,
+    focusedQuickSetting: FocusedQuickSetting,
+    setFocusedQuickSetting: (FocusedQuickSetting) -> Unit,
     onDynamicRangeClick: (dynamicRange: DynamicRange) -> Unit,
     onImageOutputFormatClick: (imageOutputFormat: ImageOutputFormat) -> Unit,
-    onConcurrentCameraModeClick: (concurrentCameraMode: ConcurrentCameraMode) -> Unit,
-    onLowLightBoostClick: (lowLightBoost: LowLightBoost) -> Unit
+    onConcurrentCameraModeClick: (concurrentCameraMode: ConcurrentCameraMode) -> Unit
 ) {
     Column(
         modifier =
-        Modifier
+        modifier
             .padding(
                 horizontal = dimensionResource(
                     id = R.dimen.quick_settings_ui_horizontal_padding
@@ -180,113 +185,121 @@ private fun ExpandedQuickSettingsUi(
     ) {
         // if no setting is chosen, display the grid of settings
         // to change the order of display just move these lines of code above or below each other
-        when (shouldShowQuickSetting) {
-            IsExpandedQuickSetting.NONE -> {
-                val displayedQuickSettings: List<@Composable () -> Unit> =
-                    buildList {
-                        add {
-                            QuickSetFlash(
-                                modifier = Modifier.testTag(QUICK_SETTINGS_FLASH_BUTTON),
-                                onClick = { f: FlashMode -> onFlashModeClick(f) },
-                                currentFlashMode = currentCameraSettings.flashMode
-                            )
-                        }
-
-                        add {
-                            QuickFlipCamera(
-                                modifier = Modifier.testTag(QUICK_SETTINGS_FLIP_CAMERA_BUTTON),
-                                setLensFacing = { l: LensFacing -> onLensFaceClick(l) },
-                                currentLensFacing = currentCameraSettings.cameraLensFacing
-                            )
-                        }
+        AnimatedVisibility(visible = focusedQuickSetting == FocusedQuickSetting.NONE) {
+            val displayedQuickSettings: List<@Composable () -> Unit> =
+                buildList {
+                    add {
+                        QuickSetFlash(
+                            modifier = Modifier.testTag(QUICK_SETTINGS_FLASH_BUTTON),
+                            onClick = { f: FlashMode -> onFlashModeClick(f) },
+                            flashModeUiState = previewUiState.flashModeUiState
+                        )
+                    }
 
-                        add {
-                            QuickSetRatio(
-                                modifier = Modifier.testTag(QUICK_SETTINGS_RATIO_BUTTON),
-                                onClick = {
-                                    setVisibleQuickSetting(
-                                        IsExpandedQuickSetting.ASPECT_RATIO
-                                    )
-                                },
-                                ratio = currentCameraSettings.aspectRatio,
-                                currentRatio = currentCameraSettings.aspectRatio
-                            )
-                        }
+                    add {
+                        QuickFlipCamera(
+                            modifier = Modifier.testTag(QUICK_SETTINGS_FLIP_CAMERA_BUTTON),
+                            setLensFacing = { l: LensFacing -> onLensFaceClick(l) },
+                            currentLensFacing = currentCameraSettings.cameraLensFacing
+                        )
+                    }
 
-                        add {
-                            QuickSetCaptureMode(
-                                modifier = Modifier.testTag(QUICK_SETTINGS_CAPTURE_MODE_BUTTON),
-                                setCaptureMode = { c: CaptureMode -> onCaptureModeClick(c) },
-                                currentCaptureMode = currentCameraSettings.captureMode,
-                                enabled = currentCameraSettings.concurrentCameraMode ==
-                                    ConcurrentCameraMode.OFF
-                            )
-                        }
+                    add {
+                        QuickSetRatio(
+                            modifier = Modifier.testTag(QUICK_SETTINGS_RATIO_BUTTON),
+                            onClick = {
+                                setFocusedQuickSetting(
+                                    FocusedQuickSetting.ASPECT_RATIO
+                                )
+                            },
+                            ratio = currentCameraSettings.aspectRatio,
+                            currentRatio = currentCameraSettings.aspectRatio
+                        )
+                    }
 
-                        val cameraConstraints = previewUiState.systemConstraints.forCurrentLens(
-                            currentCameraSettings
+                    add {
+                        QuickSetStreamConfig(
+                            modifier = Modifier.testTag(
+                                QUICK_SETTINGS_STREAM_CONFIG_BUTTON
+                            ),
+                            setStreamConfig = { c: StreamConfig -> onStreamConfigClick(c) },
+                            currentStreamConfig = currentCameraSettings.streamConfig,
+                            enabled = !(
+                                currentCameraSettings.concurrentCameraMode ==
+                                    ConcurrentCameraMode.DUAL ||
+                                    currentCameraSettings.imageFormat ==
+                                    ImageOutputFormat.JPEG_ULTRA_HDR
+                                )
                         )
-                        add {
-                            fun CameraConstraints.hdrDynamicRangeSupported(): Boolean =
-                                this.supportedDynamicRanges.size > 1
+                    }
 
-                            fun CameraConstraints.hdrImageFormatSupported(): Boolean =
-                                supportedImageFormatsMap[currentCameraSettings.captureMode]
-                                    ?.let { it.size > 1 } ?: false
+                    val cameraConstraints = previewUiState.systemConstraints.forCurrentLens(
+                        currentCameraSettings
+                    )
+                    add {
+                        fun CameraConstraints.hdrDynamicRangeSupported(): Boolean =
+                            this.supportedDynamicRanges.size > 1
 
-                            // TODO(tm): Move this to PreviewUiState
-                            fun shouldEnable(): Boolean = when {
-                                currentCameraSettings.concurrentCameraMode !=
-                                    ConcurrentCameraMode.OFF -> false
-                                else -> (
-                                    cameraConstraints?.hdrDynamicRangeSupported() == true &&
-                                        previewUiState.previewMode is PreviewMode.StandardMode
-                                    ) ||
-                                    cameraConstraints?.hdrImageFormatSupported() == true
-                            }
+                        fun CameraConstraints.hdrImageFormatSupported(): Boolean =
+                            supportedImageFormatsMap[currentCameraSettings.streamConfig]
+                                ?.let { it.size > 1 } == true
 
-                            QuickSetHdr(
-                                modifier = Modifier.testTag(QUICK_SETTINGS_HDR_BUTTON),
-                                onClick = { d: DynamicRange, i: ImageOutputFormat ->
-                                    onDynamicRangeClick(d)
-                                    onImageOutputFormatClick(i)
-                                },
-                                selectedDynamicRange = currentCameraSettings.dynamicRange,
-                                selectedImageOutputFormat = currentCameraSettings.imageFormat,
-                                hdrDynamicRange = currentCameraSettings.defaultHdrDynamicRange,
-                                hdrImageFormat = currentCameraSettings.defaultHdrImageOutputFormat,
-                                hdrDynamicRangeSupported =
-                                cameraConstraints?.hdrDynamicRangeSupported() ?: false,
-                                previewMode = previewUiState.previewMode,
-                                enabled = shouldEnable()
-                            )
+                        // TODO(tm): Move this to PreviewUiState
+                        fun shouldEnable(): Boolean = when {
+                            currentCameraSettings.concurrentCameraMode !=
+                                ConcurrentCameraMode.OFF -> false
+                            else -> (
+                                cameraConstraints?.hdrDynamicRangeSupported() == true &&
+                                    previewUiState.previewMode is PreviewMode.StandardMode
+                                ) ||
+                                cameraConstraints?.hdrImageFormatSupported() == true
                         }
 
-                        add {
-                            QuickSetConcurrentCamera(
-                                modifier =
-                                Modifier.testTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON),
-                                setConcurrentCameraMode = { c: ConcurrentCameraMode ->
-                                    onConcurrentCameraModeClick(c)
-                                },
-                                currentConcurrentCameraMode =
-                                currentCameraSettings.concurrentCameraMode,
-                                enabled =
-                                previewUiState.systemConstraints.concurrentCamerasSupported &&
-                                    previewUiState.previewMode
-                                        !is PreviewMode.ExternalImageCaptureMode
-                            )
-                        }
+                        QuickSetHdr(
+                            modifier = Modifier.testTag(QUICK_SETTINGS_HDR_BUTTON),
+                            onClick = { d: DynamicRange, i: ImageOutputFormat ->
+                                onDynamicRangeClick(d)
+                                onImageOutputFormatClick(i)
+                            },
+                            selectedDynamicRange = currentCameraSettings.dynamicRange,
+                            selectedImageOutputFormat = currentCameraSettings.imageFormat,
+                            hdrDynamicRangeSupported =
+                            cameraConstraints?.hdrDynamicRangeSupported() == true,
+                            previewMode = previewUiState.previewMode,
+                            enabled = shouldEnable()
+                        )
                     }
-                QuickSettingsGrid(quickSettingsButtons = displayedQuickSettings)
-            }
-            // if a setting that can be expanded is selected, show it
-            IsExpandedQuickSetting.ASPECT_RATIO -> {
-                ExpandedQuickSetRatio(
-                    setRatio = onAspectRatioClick,
-                    currentRatio = currentCameraSettings.aspectRatio
-                )
-            }
+
+                    add {
+                        QuickSetConcurrentCamera(
+                            modifier =
+                            Modifier.testTag(QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON),
+                            setConcurrentCameraMode = { c: ConcurrentCameraMode ->
+                                onConcurrentCameraModeClick(c)
+                            },
+                            currentConcurrentCameraMode =
+                            currentCameraSettings.concurrentCameraMode,
+                            enabled =
+                            previewUiState.systemConstraints.concurrentCamerasSupported &&
+                                previewUiState.previewMode
+                                    !is PreviewMode.ExternalImageCaptureMode &&
+                                (
+                                    currentCameraSettings.dynamicRange !=
+                                        DEFAULT_HDR_DYNAMIC_RANGE &&
+                                        currentCameraSettings.imageFormat !=
+                                        DEFAULT_HDR_IMAGE_OUTPUT
+                                    )
+                        )
+                    }
+                }
+            QuickSettingsGrid(quickSettingsButtons = displayedQuickSettings)
+        }
+        // if a setting that can be focused is selected, show it
+        AnimatedVisibility(visible = focusedQuickSetting == FocusedQuickSetting.ASPECT_RATIO) {
+            FocusedQuickSetRatio(
+                setRatio = onAspectRatioClick,
+                currentRatio = currentCameraSettings.aspectRatio
+            )
         }
     }
 }
@@ -300,19 +313,25 @@ fun ExpandedQuickSettingsUiPreview() {
                 currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
+                videoRecordingState = VideoRecordingState.Inactive(),
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                flashModeUiState = FlashModeUiState.Available(
+                    selectedFlashMode = FlashMode.OFF,
+                    availableFlashModes = listOf(FlashMode.OFF, FlashMode.ON),
+                    isActive = false
+                ),
+                captureButtonUiState = DEFAULT_CAPTURE_BUTTON_STATE
             ),
             currentCameraSettings = CameraAppSettings(),
             onLensFaceClick = { },
             onFlashModeClick = { },
-            shouldShowQuickSetting = IsExpandedQuickSetting.NONE,
-            setVisibleQuickSetting = { },
+            focusedQuickSetting = FocusedQuickSetting.NONE,
+            setFocusedQuickSetting = { },
             onAspectRatioClick = { },
-            onCaptureModeClick = { },
+            onStreamConfigClick = { },
             onDynamicRangeClick = { },
             onImageOutputFormatClick = { },
-            onConcurrentCameraModeClick = { },
-            onLowLightBoostClick = { }
+            onConcurrentCameraModeClick = { }
         )
     }
 }
@@ -323,32 +342,32 @@ fun ExpandedQuickSettingsUiPreview_WithHdr() {
     MaterialTheme {
         ExpandedQuickSettingsUi(
             previewUiState = PreviewUiState.Ready(
-                currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                videoRecordingState = VideoRecordingState.Inactive(),
+                captureButtonUiState = DEFAULT_CAPTURE_BUTTON_STATE
             ),
             currentCameraSettings = CameraAppSettings(dynamicRange = DynamicRange.HLG10),
             onLensFaceClick = { },
             onFlashModeClick = { },
-            shouldShowQuickSetting = IsExpandedQuickSetting.NONE,
-            setVisibleQuickSetting = { },
+            focusedQuickSetting = FocusedQuickSetting.NONE,
+            setFocusedQuickSetting = { },
             onAspectRatioClick = { },
-            onCaptureModeClick = { },
+            onStreamConfigClick = { },
             onDynamicRangeClick = { },
             onImageOutputFormatClick = { },
-            onConcurrentCameraModeClick = { },
-            onLowLightBoostClick = { }
+            onConcurrentCameraModeClick = { }
         )
     }
 }
 
 private val TYPICAL_SYSTEM_CONSTRAINTS_WITH_HDR =
     TYPICAL_SYSTEM_CONSTRAINTS.copy(
-        perLensConstraints = TYPICAL_SYSTEM_CONSTRAINTS.perLensConstraints.entries.associate {
-                (lensFacing, constraints) ->
-            lensFacing to constraints.copy(
-                supportedDynamicRanges = setOf(DynamicRange.SDR, DynamicRange.HLG10)
-            )
-        }
+        perLensConstraints = TYPICAL_SYSTEM_CONSTRAINTS
+            .perLensConstraints.entries.associate { (lensFacing, constraints) ->
+                lensFacing to constraints.copy(
+                    supportedDynamicRanges = setOf(DynamicRange.SDR, DynamicRange.HLG10)
+                )
+            }
     )
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/QuickSettingsComponents.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/QuickSettingsComponents.kt
index 66e2bc7..e991057 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/QuickSettingsComponents.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/QuickSettingsComponents.kt
@@ -15,7 +15,11 @@
  */
 package com.google.jetpackcamera.feature.preview.quicksettings.ui
 
+import androidx.compose.animation.core.Spring
+import androidx.compose.animation.core.animateFloatAsState
+import androidx.compose.animation.core.spring
 import androidx.compose.foundation.clickable
+import androidx.compose.foundation.interaction.MutableInteractionSource
 import androidx.compose.foundation.layout.Arrangement
 import androidx.compose.foundation.layout.Column
 import androidx.compose.foundation.layout.Row
@@ -32,8 +36,13 @@ import androidx.compose.material3.LocalContentColor
 import androidx.compose.material3.Text
 import androidx.compose.runtime.Composable
 import androidx.compose.runtime.CompositionLocalProvider
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.remember
+import androidx.compose.runtime.setValue
 import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
+import androidx.compose.ui.draw.rotate
 import androidx.compose.ui.draw.scale
 import androidx.compose.ui.graphics.Color
 import androidx.compose.ui.graphics.painter.Painter
@@ -41,34 +50,33 @@ import androidx.compose.ui.platform.LocalConfiguration
 import androidx.compose.ui.platform.testTag
 import androidx.compose.ui.res.dimensionResource
 import androidx.compose.ui.res.stringResource
-import androidx.compose.ui.semantics.contentDescription
-import androidx.compose.ui.semantics.semantics
 import androidx.compose.ui.text.style.TextAlign
 import androidx.compose.ui.unit.dp
+import com.google.jetpackcamera.feature.preview.FlashModeUiState
 import com.google.jetpackcamera.feature.preview.PreviewMode
 import com.google.jetpackcamera.feature.preview.R
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraAspectRatio
-import com.google.jetpackcamera.feature.preview.quicksettings.CameraCaptureMode
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraConcurrentCameraMode
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraDynamicRange
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraFlashMode
 import com.google.jetpackcamera.feature.preview.quicksettings.CameraLensFace
-import com.google.jetpackcamera.feature.preview.quicksettings.CameraLowLightBoost
+import com.google.jetpackcamera.feature.preview.quicksettings.CameraStreamConfig
 import com.google.jetpackcamera.feature.preview.quicksettings.QuickSettingsEnum
 import com.google.jetpackcamera.settings.model.AspectRatio
-import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.ConcurrentCameraMode
+import com.google.jetpackcamera.settings.model.DEFAULT_HDR_DYNAMIC_RANGE
+import com.google.jetpackcamera.settings.model.DEFAULT_HDR_IMAGE_OUTPUT
 import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.LowLightBoost
+import com.google.jetpackcamera.settings.model.StreamConfig
 import kotlin.math.min
 
 // completed components ready to go into preview screen
 
 @Composable
-fun ExpandedQuickSetRatio(
+fun FocusedQuickSetRatio(
     setRatio: (aspectRatio: AspectRatio) -> Unit,
     currentRatio: AspectRatio,
     modifier: Modifier = Modifier
@@ -112,15 +120,13 @@ fun QuickSetHdr(
     onClick: (dynamicRange: DynamicRange, imageOutputFormat: ImageOutputFormat) -> Unit,
     selectedDynamicRange: DynamicRange,
     selectedImageOutputFormat: ImageOutputFormat,
-    hdrDynamicRange: DynamicRange,
-    hdrImageFormat: ImageOutputFormat,
     hdrDynamicRangeSupported: Boolean,
     previewMode: PreviewMode,
     enabled: Boolean
 ) {
     val enum =
-        if (selectedDynamicRange == hdrDynamicRange ||
-            selectedImageOutputFormat == hdrImageFormat
+        if (selectedDynamicRange == DEFAULT_HDR_DYNAMIC_RANGE ||
+            selectedImageOutputFormat == DEFAULT_HDR_IMAGE_OUTPUT
         ) {
             CameraDynamicRange.HDR
         } else {
@@ -133,7 +139,7 @@ fun QuickSetHdr(
         onClick = {
             val newDynamicRange =
                 if (selectedDynamicRange == DynamicRange.SDR && hdrDynamicRangeSupported) {
-                    hdrDynamicRange
+                    DEFAULT_HDR_DYNAMIC_RANGE
                 } else {
                     DynamicRange.SDR
                 }
@@ -141,7 +147,7 @@ fun QuickSetHdr(
                 if (!hdrDynamicRangeSupported ||
                     previewMode is PreviewMode.ExternalImageCaptureMode
                 ) {
-                    hdrImageFormat
+                    DEFAULT_HDR_IMAGE_OUTPUT
                 } else {
                     ImageOutputFormat.JPEG
                 }
@@ -152,30 +158,6 @@ fun QuickSetHdr(
     )
 }
 
-@Composable
-fun QuickSetLowLightBoost(
-    modifier: Modifier = Modifier,
-    onClick: (lowLightBoost: LowLightBoost) -> Unit,
-    selectedLowLightBoost: LowLightBoost
-) {
-    val enum = when (selectedLowLightBoost) {
-        LowLightBoost.DISABLED -> CameraLowLightBoost.DISABLED
-        LowLightBoost.ENABLED -> CameraLowLightBoost.ENABLED
-    }
-
-    QuickSettingUiItem(
-        modifier = modifier,
-        enum = enum,
-        onClick = {
-            when (selectedLowLightBoost) {
-                LowLightBoost.DISABLED -> onClick(LowLightBoost.ENABLED)
-                LowLightBoost.ENABLED -> onClick(LowLightBoost.DISABLED)
-            }
-        },
-        isHighLighted = false
-    )
-}
-
 @Composable
 fun QuickSetRatio(
     onClick: () -> Unit,
@@ -201,32 +183,30 @@ fun QuickSetRatio(
 
 @Composable
 fun QuickSetFlash(
+    modifier: Modifier = Modifier,
     onClick: (FlashMode) -> Unit,
-    currentFlashMode: FlashMode,
-    modifier: Modifier = Modifier
+    flashModeUiState: FlashModeUiState
 ) {
-    val enum = when (currentFlashMode) {
-        FlashMode.OFF -> CameraFlashMode.OFF
-        FlashMode.AUTO -> CameraFlashMode.AUTO
-        FlashMode.ON -> CameraFlashMode.ON
+    when (flashModeUiState) {
+        is FlashModeUiState.Unavailable ->
+            QuickSettingUiItem(
+                modifier = modifier,
+                enum = CameraFlashMode.OFF,
+                enabled = false,
+                onClick = {}
+            )
+        is FlashModeUiState.Available ->
+            QuickSettingUiItem(
+                modifier = modifier,
+                enum = flashModeUiState.selectedFlashMode.toCameraFlashMode(
+                    flashModeUiState.isActive
+                ),
+                isHighLighted = flashModeUiState.selectedFlashMode == FlashMode.ON,
+                onClick = {
+                    onClick(flashModeUiState.getNextFlashMode())
+                }
+            )
     }
-    QuickSettingUiItem(
-        modifier = modifier
-            .semantics {
-                contentDescription =
-                    when (enum) {
-                        CameraFlashMode.OFF -> "QUICK SETTINGS FLASH IS OFF"
-                        CameraFlashMode.AUTO -> "QUICK SETTINGS FLASH IS AUTO"
-                        CameraFlashMode.ON -> "QUICK SETTINGS FLASH IS ON"
-                    }
-            },
-        enum = enum,
-        isHighLighted = currentFlashMode == FlashMode.ON,
-        onClick =
-        {
-            onClick(currentFlashMode.getNextFlashMode())
-        }
-    )
 }
 
 @Composable
@@ -248,24 +228,24 @@ fun QuickFlipCamera(
 }
 
 @Composable
-fun QuickSetCaptureMode(
-    setCaptureMode: (CaptureMode) -> Unit,
-    currentCaptureMode: CaptureMode,
+fun QuickSetStreamConfig(
+    setStreamConfig: (StreamConfig) -> Unit,
+    currentStreamConfig: StreamConfig,
     modifier: Modifier = Modifier,
     enabled: Boolean = true
 ) {
-    val enum: CameraCaptureMode =
-        when (currentCaptureMode) {
-            CaptureMode.MULTI_STREAM -> CameraCaptureMode.MULTI_STREAM
-            CaptureMode.SINGLE_STREAM -> CameraCaptureMode.SINGLE_STREAM
+    val enum: CameraStreamConfig =
+        when (currentStreamConfig) {
+            StreamConfig.MULTI_STREAM -> CameraStreamConfig.MULTI_STREAM
+            StreamConfig.SINGLE_STREAM -> CameraStreamConfig.SINGLE_STREAM
         }
     QuickSettingUiItem(
         modifier = modifier,
         enum = enum,
         onClick = {
-            when (currentCaptureMode) {
-                CaptureMode.MULTI_STREAM -> setCaptureMode(CaptureMode.SINGLE_STREAM)
-                CaptureMode.SINGLE_STREAM -> setCaptureMode(CaptureMode.MULTI_STREAM)
+            when (currentStreamConfig) {
+                StreamConfig.MULTI_STREAM -> setStreamConfig(StreamConfig.SINGLE_STREAM)
+                StreamConfig.SINGLE_STREAM -> setStreamConfig(StreamConfig.MULTI_STREAM)
             }
         },
         enabled = enabled
@@ -306,10 +286,14 @@ fun ToggleQuickSettingsButton(
     isOpen: Boolean,
     modifier: Modifier = Modifier
 ) {
+    val rotationAngle by animateFloatAsState(
+        targetValue = if (isOpen) -180f else 0f,
+        animationSpec = spring(stiffness = Spring.StiffnessLow) // Adjust duration as needed
+    )
     Row(
         horizontalArrangement = Arrangement.Center,
         verticalAlignment = Alignment.CenterVertically,
-        modifier = modifier
+        modifier = modifier.rotate(rotationAngle)
     ) {
         // dropdown icon
         Icon(
@@ -322,10 +306,12 @@ fun ToggleQuickSettingsButton(
             modifier = Modifier
                 .testTag(QUICK_SETTINGS_DROP_DOWN)
                 .size(72.dp)
-                .clickable {
-                    toggleDropDown()
-                }
-                .scale(1f, if (isOpen) -1f else 1f)
+                .clickable(
+                    interactionSource = remember { MutableInteractionSource() },
+                    // removes the greyish background animation that appears when clicking on a clickable
+                    indication = null,
+                    onClick = toggleDropDown
+                )
         )
     }
 }
@@ -364,12 +350,33 @@ fun QuickSettingUiItem(
     isHighLighted: Boolean = false,
     enabled: Boolean = true
 ) {
+    val iconSize = dimensionResource(id = R.dimen.quick_settings_ui_item_icon_size)
+
+    var buttonClicked by remember { mutableStateOf(false) }
+    val animatedScale by animateFloatAsState(
+        targetValue = if (buttonClicked) 1.1f else 1f, // Scale up to 110%
+        animationSpec = spring(
+            dampingRatio = Spring.DampingRatioLowBouncy,
+            stiffness = Spring.StiffnessMedium
+        ),
+        finishedListener = {
+            buttonClicked = false // Reset the trigger
+        }
+    )
     Column(
         modifier =
         modifier
             .wrapContentSize()
             .padding(dimensionResource(id = R.dimen.quick_settings_ui_item_padding))
-            .clickable(onClick = onClick, enabled = enabled),
+            .clickable(
+                enabled = enabled,
+                onClick = {
+                    buttonClicked = true
+                    onClick()
+                },
+                indication = null,
+                interactionSource = null
+            ),
         verticalArrangement = Arrangement.Center,
         horizontalAlignment = Alignment.CenterHorizontally
     ) {
@@ -383,9 +390,7 @@ fun QuickSettingUiItem(
             Icon(
                 painter = painter,
                 contentDescription = accessibilityText,
-                modifier = Modifier.size(
-                    dimensionResource(id = R.dimen.quick_settings_ui_item_icon_size)
-                )
+                modifier = Modifier.size(iconSize).scale(animatedScale)
             )
 
             Text(text = text, textAlign = TextAlign.Center)
@@ -468,46 +473,80 @@ fun QuickSettingsGrid(
  * The top bar indicators for quick settings items.
  */
 @Composable
-fun Indicator(enum: QuickSettingsEnum, onClick: () -> Unit, modifier: Modifier = Modifier) {
-    Icon(
-        painter = enum.getPainter(),
-        contentDescription = stringResource(id = enum.getDescriptionResId()),
-        modifier = modifier
-            .size(dimensionResource(id = R.dimen.quick_settings_indicator_size))
-            .clickable { onClick() }
-    )
+fun TopBarSettingIndicator(
+    enum: QuickSettingsEnum,
+    modifier: Modifier = Modifier,
+    enabled: Boolean = true,
+    onClick: () -> Unit = {}
+) {
+    val contentColor = Color.White.let {
+        if (!enabled) it.copy(alpha = 0.38f) else it
+    }
+    CompositionLocalProvider(LocalContentColor provides contentColor) {
+        Icon(
+            painter = enum.getPainter(),
+            contentDescription = stringResource(id = enum.getDescriptionResId()),
+            modifier = modifier
+                .size(dimensionResource(id = R.dimen.quick_settings_indicator_size))
+                .clickable(
+                    interactionSource = remember { MutableInteractionSource() },
+                    indication = null,
+                    onClick = onClick,
+                    enabled = enabled
+                )
+        )
+    }
 }
 
 @Composable
-fun FlashModeIndicator(currentFlashMode: FlashMode, onClick: (flashMode: FlashMode) -> Unit) {
-    val enum = when (currentFlashMode) {
-        FlashMode.OFF -> CameraFlashMode.OFF
-        FlashMode.AUTO -> CameraFlashMode.AUTO
-        FlashMode.ON -> CameraFlashMode.ON
+fun FlashModeIndicator(
+    flashModeUiState: FlashModeUiState,
+    onClick: (flashMode: FlashMode) -> Unit
+) {
+    when (flashModeUiState) {
+        is FlashModeUiState.Unavailable ->
+            TopBarSettingIndicator(
+                enum = CameraFlashMode.OFF,
+                enabled = false
+            )
+        is FlashModeUiState.Available ->
+            TopBarSettingIndicator(
+                enum = flashModeUiState.selectedFlashMode.toCameraFlashMode(
+                    flashModeUiState.isActive
+                ),
+                onClick = {
+                    onClick(flashModeUiState.getNextFlashMode())
+                }
+            )
     }
-    Indicator(
-        enum = enum,
-        onClick = {
-            onClick(currentFlashMode.getNextFlashMode())
-        }
-    )
 }
 
 @Composable
 fun QuickSettingsIndicators(
-    currentFlashMode: FlashMode,
-    onFlashModeClick: (flashMode: FlashMode) -> Unit,
-    modifier: Modifier = Modifier
+    modifier: Modifier = Modifier,
+    flashModeUiState: FlashModeUiState,
+    onFlashModeClick: (flashMode: FlashMode) -> Unit
 ) {
-    Row(modifier) {
-        FlashModeIndicator(currentFlashMode, onFlashModeClick)
+    Row(modifier = modifier) {
+        FlashModeIndicator(
+            flashModeUiState,
+            onFlashModeClick
+        )
     }
 }
 
-fun FlashMode.getNextFlashMode(): FlashMode {
-    return when (this) {
-        FlashMode.OFF -> FlashMode.ON
-        FlashMode.ON -> FlashMode.AUTO
-        FlashMode.AUTO -> FlashMode.OFF
+private fun FlashModeUiState.Available.getNextFlashMode(): FlashMode = availableFlashModes.run {
+    get((indexOf(selectedFlashMode) + 1) % size)
+}
+
+private fun FlashMode.toCameraFlashMode(isActive: Boolean) = when (this) {
+    FlashMode.OFF -> CameraFlashMode.OFF
+    FlashMode.AUTO -> CameraFlashMode.AUTO
+    FlashMode.ON -> CameraFlashMode.ON
+    FlashMode.LOW_LIGHT_BOOST -> {
+        when (isActive) {
+            true -> CameraFlashMode.LOW_LIGHT_BOOST_ACTIVE
+            false -> CameraFlashMode.LOW_LIGHT_BOOST_INACTIVE
+        }
     }
 }
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/TestTags.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/TestTags.kt
index 5a226e6..1c73fa1 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/TestTags.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/quicksettings/ui/TestTags.kt
@@ -15,12 +15,21 @@
  */
 package com.google.jetpackcamera.feature.preview.quicksettings.ui
 
-const val QUICK_SETTINGS_CAPTURE_MODE_BUTTON = "QuickSettingsCaptureModeButton"
+// ////////////////////////////////
+//
+// !!!HEY YOU!!!
+// MODIFICATIONS TO EXISTING TEST TAGS WILL BREAK EXISTING EXTERNAL
+// AUTOMATED TESTS THAT SEARCH FOR THESE TAGS.
+//
+// PLEASE UPDATE YOUR TESTS ACCORDINGLY!
+//
+// ////////////////////////////////
+
+const val QUICK_SETTINGS_STREAM_CONFIG_BUTTON = "QuickSettingsStreamConfigButton"
 const val QUICK_SETTINGS_CONCURRENT_CAMERA_MODE_BUTTON = "QuickSettingsConcurrentCameraModeButton"
 const val QUICK_SETTINGS_DROP_DOWN = "QuickSettingsDropDown"
 const val QUICK_SETTINGS_HDR_BUTTON = "QuickSettingsHdrButton"
 const val QUICK_SETTINGS_FLASH_BUTTON = "QuickSettingsFlashButton"
-const val QUICK_SETTINGS_LOW_LIGHT_BOOST_BUTTON = "QuickSettingsLowLightBoostButton"
 const val QUICK_SETTINGS_FLIP_CAMERA_BUTTON = "QuickSettingsFlipCameraButton"
 const val QUICK_SETTINGS_RATIO_3_4_BUTTON = "QuickSettingsRatio3:4Button"
 const val QUICK_SETTINGS_RATIO_9_16_BUTTON = "QuickSettingsRatio9:16Button"
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraControlsOverlay.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraControlsOverlay.kt
index 9563db9..021a25c 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraControlsOverlay.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraControlsOverlay.kt
@@ -15,9 +15,12 @@
  */
 package com.google.jetpackcamera.feature.preview.ui
 
-import android.annotation.SuppressLint
 import android.content.ContentResolver
 import android.net.Uri
+import androidx.compose.animation.AnimatedVisibility
+import androidx.compose.animation.core.tween
+import androidx.compose.animation.fadeIn
+import androidx.compose.animation.fadeOut
 import androidx.compose.foundation.layout.Arrangement
 import androidx.compose.foundation.layout.Box
 import androidx.compose.foundation.layout.Column
@@ -27,6 +30,7 @@ import androidx.compose.foundation.layout.fillMaxSize
 import androidx.compose.foundation.layout.fillMaxWidth
 import androidx.compose.foundation.layout.height
 import androidx.compose.foundation.layout.padding
+import androidx.compose.foundation.layout.safeDrawingPadding
 import androidx.compose.material.icons.Icons
 import androidx.compose.material.icons.filled.CameraAlt
 import androidx.compose.material.icons.filled.Videocam
@@ -47,35 +51,44 @@ import androidx.compose.ui.graphics.Color
 import androidx.compose.ui.graphics.vector.rememberVectorPainter
 import androidx.compose.ui.platform.LocalContext
 import androidx.compose.ui.platform.testTag
+import androidx.compose.ui.res.stringResource
 import androidx.compose.ui.tooling.preview.Preview
 import androidx.compose.ui.unit.dp
 import androidx.compose.ui.unit.sp
-import androidx.core.util.Preconditions
+import com.google.jetpackcamera.core.camera.VideoRecordingState
+import com.google.jetpackcamera.feature.preview.CaptureButtonUiState
 import com.google.jetpackcamera.feature.preview.CaptureModeToggleUiState
+import com.google.jetpackcamera.feature.preview.DEFAULT_CAPTURE_BUTTON_STATE
+import com.google.jetpackcamera.feature.preview.ElapsedTimeUiState
+import com.google.jetpackcamera.feature.preview.FlashModeUiState
 import com.google.jetpackcamera.feature.preview.MultipleEventsCutter
 import com.google.jetpackcamera.feature.preview.PreviewMode
 import com.google.jetpackcamera.feature.preview.PreviewUiState
 import com.google.jetpackcamera.feature.preview.PreviewViewModel
-import com.google.jetpackcamera.feature.preview.VideoRecordingState
+import com.google.jetpackcamera.feature.preview.R
+import com.google.jetpackcamera.feature.preview.StabilizationUiState
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.QuickSettingsIndicators
 import com.google.jetpackcamera.feature.preview.quicksettings.ui.ToggleQuickSettingsButton
-import com.google.jetpackcamera.settings.model.CameraAppSettings
+import com.google.jetpackcamera.feature.preview.ui.debug.DebugOverlayToggleButton
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.ImageOutputFormat
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.StabilizationMode
 import com.google.jetpackcamera.settings.model.SystemConstraints
 import com.google.jetpackcamera.settings.model.TYPICAL_SYSTEM_CONSTRAINTS
+import com.google.jetpackcamera.settings.model.VideoQuality
 import kotlinx.coroutines.delay
 
-class ZoomLevelDisplayState(showInitially: Boolean = false) {
-    private var _showZoomLevel = mutableStateOf(showInitially)
+class ZoomLevelDisplayState(private val alwaysDisplay: Boolean = false) {
+    private var _showZoomLevel = mutableStateOf(alwaysDisplay)
     val showZoomLevel: Boolean get() = _showZoomLevel.value
 
     suspend fun showZoomLevel() {
-        _showZoomLevel.value = true
-        delay(3000)
-        _showZoomLevel.value = false
+        if (!alwaysDisplay) {
+            _showZoomLevel.value = true
+            delay(3000)
+            _showZoomLevel.value = false
+        }
     }
 }
 
@@ -90,20 +103,23 @@ fun CameraControlsOverlay(
     onChangeImageFormat: (ImageOutputFormat) -> Unit = {},
     onToggleWhenDisabled: (CaptureModeToggleUiState.DisabledReason) -> Unit = {},
     onToggleQuickSettings: () -> Unit = {},
-    onMuteAudio: () -> Unit = {},
-    onCaptureImage: () -> Unit = {},
+    onToggleDebugOverlay: () -> Unit = {},
+    onToggleAudio: () -> Unit = {},
+    onSetPause: (Boolean) -> Unit = {},
     onCaptureImageWithUri: (
         ContentResolver,
         Uri?,
         Boolean,
-        (PreviewViewModel.ImageCaptureEvent) -> Unit
+        (PreviewViewModel.ImageCaptureEvent, Int) -> Unit
     ) -> Unit = { _, _, _, _ -> },
     onStartVideoRecording: (
         Uri?,
         Boolean,
         (PreviewViewModel.VideoCaptureEvent) -> Unit
     ) -> Unit = { _, _, _ -> },
-    onStopVideoRecording: () -> Unit = {}
+    onStopVideoRecording: () -> Unit = {},
+    onImageWellClick: (uri: Uri?) -> Unit = {},
+    onLockVideoRecording: (Boolean) -> Unit
 ) {
     // Show the current zoom level for a short period of time, only when the level changes.
     var firstRun by remember { mutableStateOf(true) }
@@ -116,43 +132,53 @@ fun CameraControlsOverlay(
     }
 
     CompositionLocalProvider(LocalContentColor provides Color.White) {
-        Box(modifier.fillMaxSize()) {
-            if (previewUiState.videoRecordingState == VideoRecordingState.INACTIVE) {
+        Box(
+            modifier
+                .safeDrawingPadding()
+                .fillMaxSize()
+        ) {
+            if (previewUiState.videoRecordingState is VideoRecordingState.Inactive) {
                 ControlsTop(
                     modifier = Modifier
                         .fillMaxWidth()
                         .align(Alignment.TopCenter),
                     isQuickSettingsOpen = previewUiState.quickSettingsIsOpen,
-                    currentCameraSettings = previewUiState.currentCameraSettings,
+                    isDebugMode = previewUiState.debugUiState.isDebugMode,
                     onNavigateToSettings = onNavigateToSettings,
                     onChangeFlash = onChangeFlash,
-                    onToggleQuickSettings = onToggleQuickSettings
+                    onToggleQuickSettings = onToggleQuickSettings,
+                    onToggleDebugOverlay = onToggleDebugOverlay,
+                    stabilizationUiState = previewUiState.stabilizationUiState,
+                    videoQuality = previewUiState.videoQuality,
+                    flashModeUiState = previewUiState.flashModeUiState
                 )
             }
 
             ControlsBottom(
                 modifier = Modifier
+                    // padding to avoid snackbar
+                    .padding(bottom = 60.dp)
                     .fillMaxWidth()
                     .align(Alignment.BottomCenter),
                 previewUiState = previewUiState,
-                audioAmplitude = previewUiState.audioAmplitude,
                 zoomLevel = previewUiState.zoomScale,
                 physicalCameraId = previewUiState.currentPhysicalCameraId,
                 logicalCameraId = previewUiState.currentLogicalCameraId,
                 showZoomLevel = zoomLevelDisplayState.showZoomLevel,
                 isQuickSettingsOpen = previewUiState.quickSettingsIsOpen,
-                currentCameraSettings = previewUiState.currentCameraSettings,
                 systemConstraints = previewUiState.systemConstraints,
                 videoRecordingState = previewUiState.videoRecordingState,
                 onFlipCamera = onFlipCamera,
-                onCaptureImage = onCaptureImage,
                 onCaptureImageWithUri = onCaptureImageWithUri,
                 onToggleQuickSettings = onToggleQuickSettings,
-                onToggleAudioMuted = onMuteAudio,
+                onToggleAudio = onToggleAudio,
+                onSetPause = onSetPause,
                 onChangeImageFormat = onChangeImageFormat,
                 onToggleWhenDisabled = onToggleWhenDisabled,
                 onStartVideoRecording = onStartVideoRecording,
-                onStopVideoRecording = onStopVideoRecording
+                onStopVideoRecording = onStopVideoRecording,
+                onImageWellClick = onImageWellClick,
+                onLockVideoRecording = onLockVideoRecording
             )
         }
     }
@@ -161,44 +187,70 @@ fun CameraControlsOverlay(
 @Composable
 private fun ControlsTop(
     isQuickSettingsOpen: Boolean,
-    currentCameraSettings: CameraAppSettings,
     modifier: Modifier = Modifier,
+    isDebugMode: Boolean = false,
     onNavigateToSettings: () -> Unit = {},
     onChangeFlash: (FlashMode) -> Unit = {},
-    onToggleQuickSettings: () -> Unit = {}
+    onToggleQuickSettings: () -> Unit = {},
+    onToggleDebugOverlay: () -> Unit = {},
+    stabilizationUiState: StabilizationUiState = StabilizationUiState.Disabled,
+    videoQuality: VideoQuality = VideoQuality.UNSPECIFIED,
+    flashModeUiState: FlashModeUiState = FlashModeUiState.Unavailable
 ) {
-    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
-        Row(Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) {
-            // button to open default settings page
-            SettingsNavButton(
-                modifier = Modifier
-                    .padding(12.dp)
-                    .testTag(SETTINGS_BUTTON),
-                onNavigateToSettings = onNavigateToSettings
-            )
-            if (!isQuickSettingsOpen) {
-                QuickSettingsIndicators(
-                    currentFlashMode = currentCameraSettings.flashMode,
-                    onFlashModeClick = onChangeFlash
+    Column(modifier) {
+        Row(modifier, verticalAlignment = Alignment.CenterVertically) {
+            Row(Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) {
+                // button to open default settings page
+                SettingsNavButton(
+                    modifier = Modifier
+                        .padding(12.dp)
+                        .testTag(SETTINGS_BUTTON),
+                    onNavigateToSettings = onNavigateToSettings
                 )
+                AnimatedVisibility(
+                    visible = !isQuickSettingsOpen,
+                    enter = fadeIn(),
+                    exit = fadeOut()
+                ) {
+                    QuickSettingsIndicators(
+                        flashModeUiState = flashModeUiState,
+                        onFlashModeClick = onChangeFlash
+                    )
+                }
             }
-        }
-
-        // quick settings button
-        ToggleQuickSettingsButton(onToggleQuickSettings, isQuickSettingsOpen)
 
-        Row(
-            Modifier.weight(1f),
-            verticalAlignment = Alignment.CenterVertically,
-            horizontalArrangement = Arrangement.SpaceEvenly
-        ) {
-            StabilizationIcon(
-                videoStabilization = currentCameraSettings.videoCaptureStabilization,
-                previewStabilization = currentCameraSettings.previewStabilization
-            )
-            LowLightBoostIcon(
-                lowLightBoost = currentCameraSettings.lowLightBoost
+            // quick settings button
+            ToggleQuickSettingsButton(
+                toggleDropDown = onToggleQuickSettings,
+                isOpen = isQuickSettingsOpen
             )
+
+            Row(
+                Modifier.weight(1f),
+                verticalAlignment = Alignment.CenterVertically,
+                horizontalArrangement = Arrangement.SpaceEvenly
+            ) {
+                var visibleStabilizationUiState: StabilizationUiState by remember {
+                    mutableStateOf(StabilizationUiState.Disabled)
+                }
+                if (stabilizationUiState is StabilizationUiState.Enabled) {
+                    // Only save StabilizationUiState.Set so exit transition can happen properly
+                    visibleStabilizationUiState = stabilizationUiState
+                }
+                AnimatedVisibility(
+                    visible = stabilizationUiState is StabilizationUiState.Enabled,
+                    enter = fadeIn(),
+                    exit = fadeOut()
+                ) {
+                    (visibleStabilizationUiState as? StabilizationUiState.Enabled)?.let {
+                        StabilizationIcon(stabilizationUiState = it)
+                    }
+                }
+                VideoQualityIcon(videoQuality, Modifier.testTag(VIDEO_QUALITY_TAG))
+            }
+        }
+        if (isDebugMode) {
+            DebugOverlayToggleButton(toggleIsOpen = onToggleDebugOverlay)
         }
     }
 }
@@ -206,26 +258,24 @@ private fun ControlsTop(
 @Composable
 private fun ControlsBottom(
     modifier: Modifier = Modifier,
-    audioAmplitude: Double,
     previewUiState: PreviewUiState.Ready,
     physicalCameraId: String? = null,
     logicalCameraId: String? = null,
     zoomLevel: Float,
     showZoomLevel: Boolean,
     isQuickSettingsOpen: Boolean,
-    currentCameraSettings: CameraAppSettings,
     systemConstraints: SystemConstraints,
     videoRecordingState: VideoRecordingState,
     onFlipCamera: () -> Unit = {},
-    onCaptureImage: () -> Unit = {},
     onCaptureImageWithUri: (
         ContentResolver,
         Uri?,
         Boolean,
-        (PreviewViewModel.ImageCaptureEvent) -> Unit
+        (PreviewViewModel.ImageCaptureEvent, Int) -> Unit
     ) -> Unit = { _, _, _, _ -> },
     onToggleQuickSettings: () -> Unit = {},
-    onToggleAudioMuted: () -> Unit = {},
+    onToggleAudio: () -> Unit = {},
+    onSetPause: (Boolean) -> Unit = {},
     onChangeImageFormat: (ImageOutputFormat) -> Unit = {},
     onToggleWhenDisabled: (CaptureModeToggleUiState.DisabledReason) -> Unit = {},
     onStartVideoRecording: (
@@ -233,9 +283,14 @@ private fun ControlsBottom(
         Boolean,
         (PreviewViewModel.VideoCaptureEvent) -> Unit
     ) -> Unit = { _, _, _ -> },
-    onStopVideoRecording: () -> Unit = {}
+    onStopVideoRecording: () -> Unit = {},
+    onImageWellClick: (uri: Uri?) -> Unit = {},
+    onLockVideoRecording: (Boolean) -> Unit = {}
 ) {
-    Column(modifier = modifier, horizontalAlignment = Alignment.CenterHorizontally) {
+    Column(
+        modifier = modifier,
+        horizontalAlignment = Alignment.CenterHorizontally
+    ) {
         CompositionLocalProvider(
             LocalTextStyle provides LocalTextStyle.current.copy(fontSize = 20.sp)
         ) {
@@ -243,57 +298,107 @@ private fun ControlsBottom(
                 if (showZoomLevel) {
                     ZoomScaleText(zoomLevel)
                 }
-                if (previewUiState.isDebugMode) {
+                if (previewUiState.debugUiState.isDebugMode) {
                     CurrentCameraIdText(physicalCameraId, logicalCameraId)
                 }
+                if (previewUiState.elapsedTimeUiState is ElapsedTimeUiState.Enabled) {
+                    AnimatedVisibility(
+                        visible = (
+                            previewUiState.videoRecordingState is
+                                VideoRecordingState.Active
+                            ),
+                        enter = fadeIn(),
+                        exit = fadeOut(animationSpec = tween(delayMillis = 1_500))
+                    ) {
+                        ElapsedTimeText(
+                            modifier = Modifier.testTag(ELAPSED_TIME_TAG),
+                            elapsedTimeUiState = previewUiState.elapsedTimeUiState
+                        )
+                    }
+                }
             }
         }
 
-        Row(
-            Modifier
-                .fillMaxWidth()
-                .height(IntrinsicSize.Max),
-            verticalAlignment = Alignment.CenterVertically
-        ) {
-            Row(Modifier.weight(1f), horizontalArrangement = Arrangement.SpaceEvenly) {
-                if (!isQuickSettingsOpen && videoRecordingState == VideoRecordingState.INACTIVE) {
-                    FlipCameraButton(
-                        modifier = Modifier.testTag(FLIP_CAMERA_BUTTON),
-                        onClick = onFlipCamera,
-                        // enable only when phone has front and rear camera
-                        enabledCondition = systemConstraints.availableLenses.size > 1
+        Column {
+            if (!isQuickSettingsOpen &&
+                previewUiState.captureModeToggleUiState
+                    is CaptureModeToggleUiState.Visible
+            ) {
+                // TODO(yasith): Align to end of ImageWell based on alignment lines
+                Box(
+                    Modifier.align(Alignment.End).padding(end = 12.dp)
+                ) {
+                    CaptureModeToggleButton(
+                        uiState = previewUiState.captureModeToggleUiState,
+                        onChangeImageFormat = onChangeImageFormat,
+                        onToggleWhenDisabled = onToggleWhenDisabled,
+                        modifier = Modifier.testTag(CAPTURE_MODE_TOGGLE_BUTTON)
                     )
                 }
             }
-            CaptureButton(
-                previewUiState = previewUiState,
-                isQuickSettingsOpen = isQuickSettingsOpen,
-                videoRecordingState = videoRecordingState,
-                onCaptureImage = onCaptureImage,
-                onCaptureImageWithUri = onCaptureImageWithUri,
-                onToggleQuickSettings = onToggleQuickSettings,
-                onStartVideoRecording = onStartVideoRecording,
-                onStopVideoRecording = onStopVideoRecording
-            )
-            Row(Modifier.weight(1f), horizontalArrangement = Arrangement.SpaceEvenly) {
-                if (videoRecordingState == VideoRecordingState.ACTIVE) {
-                    AmplitudeVisualizer(
-                        modifier = Modifier
-                            .weight(1f)
-                            .fillMaxSize(),
-                        onToggleMute = onToggleAudioMuted,
-                        size = 75,
-                        audioAmplitude = audioAmplitude
-                    )
-                } else {
-                    if (!isQuickSettingsOpen &&
-                        previewUiState.captureModeToggleUiState is CaptureModeToggleUiState.Visible
+
+            Row(
+                Modifier
+                    .fillMaxWidth()
+                    .height(IntrinsicSize.Max),
+                verticalAlignment = Alignment.CenterVertically
+            ) {
+                // Row that holds flip camera, capture button, and audio
+                Row(Modifier.weight(1f), horizontalArrangement = Arrangement.SpaceEvenly) {
+                    // animation fades in/out this component based on quick settings
+                    AnimatedVisibility(
+                        visible = !isQuickSettingsOpen,
+                        enter = fadeIn(),
+                        exit = fadeOut()
                     ) {
-                        CaptureModeToggleButton(
-                            uiState = previewUiState.captureModeToggleUiState,
-                            onChangeImageFormat = onChangeImageFormat,
-                            onToggleWhenDisabled = onToggleWhenDisabled
+                        if (videoRecordingState is VideoRecordingState.Inactive) {
+                            FlipCameraButton(
+                                modifier = Modifier.testTag(FLIP_CAMERA_BUTTON),
+                                onClick = onFlipCamera,
+                                lensFacing = previewUiState.currentCameraSettings.cameraLensFacing,
+                                // enable only when phone has front and rear camera
+                                enabledCondition = systemConstraints.availableLenses.size > 1
+                            )
+                        } else if (videoRecordingState is VideoRecordingState.Active
+                        ) {
+                            PauseResumeToggleButton(
+                                onSetPause = onSetPause,
+                                currentRecordingState = videoRecordingState
+                            )
+                        }
+                    }
+                }
+                CaptureButton(
+                    captureButtonUiState = previewUiState.captureButtonUiState,
+                    previewMode = previewUiState.previewMode,
+                    isQuickSettingsOpen = isQuickSettingsOpen,
+                    onCaptureImageWithUri = onCaptureImageWithUri,
+                    onToggleQuickSettings = onToggleQuickSettings,
+                    onStartVideoRecording = onStartVideoRecording,
+                    onStopVideoRecording = onStopVideoRecording,
+                    onLockVideoRecording = onLockVideoRecording
+                )
+                Row(Modifier.weight(1f), horizontalArrangement = Arrangement.SpaceEvenly) {
+                    if (videoRecordingState is VideoRecordingState.Active) {
+                        AmplitudeVisualizer(
+                            modifier = Modifier
+                                .weight(1f)
+                                .fillMaxSize(),
+                            onToggleAudio = onToggleAudio,
+                            audioUiState = previewUiState.audioUiState
                         )
+                    } else {
+                        Column {
+                            if (!isQuickSettingsOpen &&
+                                previewUiState.previewMode is PreviewMode.StandardMode
+                            ) {
+                                ImageWell(
+                                    modifier = Modifier.weight(1f),
+                                    imageWellUiState = previewUiState.imageWellUiState,
+                                    onClick = onImageWellClick
+                                )
+                            }
+                        }
                     }
                 }
             }
@@ -303,56 +408,73 @@ private fun ControlsBottom(
 
 @Composable
 private fun CaptureButton(
-    previewUiState: PreviewUiState.Ready,
-    isQuickSettingsOpen: Boolean,
-    videoRecordingState: VideoRecordingState,
     modifier: Modifier = Modifier,
-    onCaptureImage: () -> Unit = {},
+    captureButtonUiState: CaptureButtonUiState,
+    isQuickSettingsOpen: Boolean,
+    previewMode: PreviewMode,
+    onToggleQuickSettings: () -> Unit = {},
     onCaptureImageWithUri: (
         ContentResolver,
         Uri?,
         Boolean,
-        (PreviewViewModel.ImageCaptureEvent) -> Unit
+        (PreviewViewModel.ImageCaptureEvent, Int) -> Unit
     ) -> Unit = { _, _, _, _ -> },
-    onToggleQuickSettings: () -> Unit = {},
     onStartVideoRecording: (
         Uri?,
         Boolean,
         (PreviewViewModel.VideoCaptureEvent) -> Unit
     ) -> Unit = { _, _, _ -> },
-    onStopVideoRecording: () -> Unit = {}
+    onStopVideoRecording: () -> Unit = {},
+    onLockVideoRecording: (Boolean) -> Unit = {}
 ) {
     val multipleEventsCutter = remember { MultipleEventsCutter() }
     val context = LocalContext.current
+
     CaptureButton(
         modifier = modifier.testTag(CAPTURE_BUTTON),
-        onClick = {
-            multipleEventsCutter.processEvent {
-                when (previewUiState.previewMode) {
-                    is PreviewMode.StandardMode -> {
-                        onCaptureImageWithUri(
-                            context.contentResolver,
-                            null,
-                            true,
-                            previewUiState.previewMode.onImageCapture
-                        )
-                    }
+        onCaptureImage = {
+            if (captureButtonUiState is CaptureButtonUiState.Enabled) {
+                multipleEventsCutter.processEvent {
+                    when (previewMode) {
+                        is PreviewMode.StandardMode -> {
+                            onCaptureImageWithUri(
+                                context.contentResolver,
+                                null,
+                                true
+                            ) { event: PreviewViewModel.ImageCaptureEvent, _: Int ->
+                                previewMode.onImageCapture(event)
+                            }
+                        }
 
-                    is PreviewMode.ExternalImageCaptureMode -> {
-                        onCaptureImageWithUri(
-                            context.contentResolver,
-                            previewUiState.previewMode.imageCaptureUri,
-                            false,
-                            previewUiState.previewMode.onImageCapture
-                        )
-                    }
+                        is PreviewMode.ExternalImageCaptureMode -> {
+                            onCaptureImageWithUri(
+                                context.contentResolver,
+                                previewMode.imageCaptureUri,
+                                false
+                            ) { event: PreviewViewModel.ImageCaptureEvent, _: Int ->
+                                previewMode.onImageCapture(event)
+                            }
+                        }
 
-                    else -> {
-                        onCaptureImageWithUri(
-                            context.contentResolver,
-                            null,
-                            false
-                        ) {}
+                        is PreviewMode.ExternalMultipleImageCaptureMode -> {
+                            val ignoreUri =
+                                previewMode.imageCaptureUris.isNullOrEmpty()
+                            onCaptureImageWithUri(
+                                context.contentResolver,
+                                null,
+                                previewMode.imageCaptureUris.isNullOrEmpty() ||
+                                    ignoreUri,
+                                previewMode.onImageCapture
+                            )
+                        }
+
+                        else -> {
+                            onCaptureImageWithUri(
+                                context.contentResolver,
+                                null,
+                                false
+                            ) { _: PreviewViewModel.ImageCaptureEvent, _: Int -> }
+                        }
                     }
                 }
             }
@@ -360,41 +482,44 @@ private fun CaptureButton(
                 onToggleQuickSettings()
             }
         },
-        onLongPress = {
-            when (previewUiState.previewMode) {
-                is PreviewMode.StandardMode -> {
-                    onStartVideoRecording(null, false) {}
-                }
+        onStartVideoRecording = {
+            if (captureButtonUiState is CaptureButtonUiState.Enabled) {
+                when (previewMode) {
+                    is PreviewMode.StandardMode -> {
+                        onStartVideoRecording(null, false) {}
+                    }
 
-                is PreviewMode.ExternalVideoCaptureMode -> {
-                    onStartVideoRecording(
-                        previewUiState.previewMode.videoCaptureUri,
-                        true,
-                        previewUiState.previewMode.onVideoCapture
-                    )
-                }
+                    is PreviewMode.ExternalVideoCaptureMode -> {
+                        onStartVideoRecording(
+                            previewMode.videoCaptureUri,
+                            true,
+                            previewMode.onVideoCapture
+                        )
+                    }
 
-                else -> {
-                    onStartVideoRecording(null, false) {}
+                    else -> {
+                        onStartVideoRecording(null, false) {}
+                    }
+                }
+                if (isQuickSettingsOpen) {
+                    onToggleQuickSettings()
                 }
-            }
-            if (isQuickSettingsOpen) {
-                onToggleQuickSettings()
             }
         },
-        onRelease = {
+        onStopVideoRecording = {
             onStopVideoRecording()
         },
-        videoRecordingState = videoRecordingState
+        captureButtonUiState = captureButtonUiState,
+        onLockVideoRecording = onLockVideoRecording
     )
 }
 
-@SuppressLint("RestrictedApi")
 @Composable
 private fun CaptureModeToggleButton(
     uiState: CaptureModeToggleUiState.Visible,
     onChangeImageFormat: (ImageOutputFormat) -> Unit,
-    onToggleWhenDisabled: (CaptureModeToggleUiState.DisabledReason) -> Unit
+    onToggleWhenDisabled: (CaptureModeToggleUiState.DisabledReason) -> Unit,
+    modifier: Modifier = Modifier
 ) {
     // Captures hdr image (left) when output format is UltraHdr, else captures hdr video (right).
     val initialState =
@@ -426,10 +551,15 @@ private fun CaptureModeToggleButton(
             onChangeImageFormat(imageFormat)
         },
         onToggleWhenDisabled = {
-            Preconditions.checkArgument(uiState is CaptureModeToggleUiState.Disabled)
-            onToggleWhenDisabled((uiState as CaptureModeToggleUiState.Disabled).disabledReason)
+            check(uiState is CaptureModeToggleUiState.Disabled)
+            onToggleWhenDisabled(uiState.disabledReason)
         },
-        enabled = uiState is CaptureModeToggleUiState.Enabled
+        enabled = uiState is CaptureModeToggleUiState.Enabled,
+        leftIconDescription =
+        stringResource(id = R.string.capture_mode_image_capture_content_description),
+        rightIconDescription =
+        stringResource(id = R.string.capture_mode_video_recording_content_description),
+        modifier = modifier
     )
 }
 
@@ -438,8 +568,7 @@ private fun CaptureModeToggleButton(
 private fun Preview_ControlsTop_QuickSettingsOpen() {
     CompositionLocalProvider(LocalContentColor provides Color.White) {
         ControlsTop(
-            isQuickSettingsOpen = true,
-            currentCameraSettings = CameraAppSettings()
+            isQuickSettingsOpen = true
         )
     }
 }
@@ -449,8 +578,7 @@ private fun Preview_ControlsTop_QuickSettingsOpen() {
 private fun Preview_ControlsTop_QuickSettingsClosed() {
     CompositionLocalProvider(LocalContentColor provides Color.White) {
         ControlsTop(
-            isQuickSettingsOpen = false,
-            currentCameraSettings = CameraAppSettings()
+            isQuickSettingsOpen = false
         )
     }
 }
@@ -461,7 +589,11 @@ private fun Preview_ControlsTop_FlashModeOn() {
     CompositionLocalProvider(LocalContentColor provides Color.White) {
         ControlsTop(
             isQuickSettingsOpen = false,
-            currentCameraSettings = CameraAppSettings(flashMode = FlashMode.ON)
+            flashModeUiState = FlashModeUiState.Available(
+                selectedFlashMode = FlashMode.ON,
+                availableFlashModes = listOf(FlashMode.OFF, FlashMode.ON),
+                isActive = false
+            )
         )
     }
 }
@@ -472,7 +604,11 @@ private fun Preview_ControlsTop_FlashModeAuto() {
     CompositionLocalProvider(LocalContentColor provides Color.White) {
         ControlsTop(
             isQuickSettingsOpen = false,
-            currentCameraSettings = CameraAppSettings(flashMode = FlashMode.AUTO)
+            flashModeUiState = FlashModeUiState.Available(
+                selectedFlashMode = FlashMode.AUTO,
+                availableFlashModes = listOf(FlashMode.OFF, FlashMode.ON, FlashMode.AUTO),
+                isActive = false
+            )
         )
     }
 }
@@ -483,9 +619,21 @@ private fun Preview_ControlsTop_WithStabilization() {
     CompositionLocalProvider(LocalContentColor provides Color.White) {
         ControlsTop(
             isQuickSettingsOpen = false,
-            currentCameraSettings = CameraAppSettings(
-                videoCaptureStabilization = Stabilization.ON,
-                previewStabilization = Stabilization.ON
+            stabilizationUiState = StabilizationUiState.Specific(
+                stabilizationMode = StabilizationMode.ON
+            )
+        )
+    }
+}
+
+@Preview(backgroundColor = 0xFF000000, showBackground = true)
+@Composable
+private fun Preview_ControlsTop_WithStabilizationAuto() {
+    CompositionLocalProvider(LocalContentColor provides Color.White) {
+        ControlsTop(
+            isQuickSettingsOpen = false,
+            stabilizationUiState = StabilizationUiState.Auto(
+                stabilizationMode = StabilizationMode.OPTICAL
             )
         )
     }
@@ -497,18 +645,17 @@ private fun Preview_ControlsBottom() {
     CompositionLocalProvider(LocalContentColor provides Color.White) {
         ControlsBottom(
             previewUiState = PreviewUiState.Ready(
-                currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                videoRecordingState = VideoRecordingState.Inactive(),
+                captureButtonUiState = DEFAULT_CAPTURE_BUTTON_STATE
             ),
             zoomLevel = 1.3f,
             showZoomLevel = true,
             isQuickSettingsOpen = false,
-            currentCameraSettings = CameraAppSettings(),
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
-            videoRecordingState = VideoRecordingState.INACTIVE,
-            audioAmplitude = 0.0
+            videoRecordingState = VideoRecordingState.Inactive()
         )
     }
 }
@@ -519,18 +666,17 @@ private fun Preview_ControlsBottom_NoZoomLevel() {
     CompositionLocalProvider(LocalContentColor provides Color.White) {
         ControlsBottom(
             previewUiState = PreviewUiState.Ready(
-                currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                videoRecordingState = VideoRecordingState.Inactive(),
+                captureButtonUiState = DEFAULT_CAPTURE_BUTTON_STATE
             ),
             zoomLevel = 1.3f,
             showZoomLevel = false,
             isQuickSettingsOpen = false,
-            currentCameraSettings = CameraAppSettings(),
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
-            videoRecordingState = VideoRecordingState.INACTIVE,
-            audioAmplitude = 0.0
+            videoRecordingState = VideoRecordingState.Inactive()
         )
     }
 }
@@ -541,18 +687,17 @@ private fun Preview_ControlsBottom_QuickSettingsOpen() {
     CompositionLocalProvider(LocalContentColor provides Color.White) {
         ControlsBottom(
             previewUiState = PreviewUiState.Ready(
-                currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                videoRecordingState = VideoRecordingState.Inactive(),
+                captureButtonUiState = DEFAULT_CAPTURE_BUTTON_STATE
             ),
             zoomLevel = 1.3f,
             showZoomLevel = true,
             isQuickSettingsOpen = true,
-            currentCameraSettings = CameraAppSettings(),
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
-            videoRecordingState = VideoRecordingState.INACTIVE,
-            audioAmplitude = 0.0
+            videoRecordingState = VideoRecordingState.Inactive()
         )
     }
 }
@@ -563,15 +708,15 @@ private fun Preview_ControlsBottom_NoFlippableCamera() {
     CompositionLocalProvider(LocalContentColor provides Color.White) {
         ControlsBottom(
             previewUiState = PreviewUiState.Ready(
-                currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                videoRecordingState = VideoRecordingState.Inactive(),
+                captureButtonUiState = DEFAULT_CAPTURE_BUTTON_STATE
             ),
             zoomLevel = 1.3f,
             showZoomLevel = true,
             isQuickSettingsOpen = false,
-            currentCameraSettings = CameraAppSettings(),
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS.copy(
                 availableLenses = listOf(LensFacing.FRONT),
                 perLensConstraints = mapOf(
@@ -579,8 +724,7 @@ private fun Preview_ControlsBottom_NoFlippableCamera() {
                         TYPICAL_SYSTEM_CONSTRAINTS.perLensConstraints[LensFacing.FRONT]!!
                 )
             ),
-            videoRecordingState = VideoRecordingState.INACTIVE,
-            audioAmplitude = 0.0
+            videoRecordingState = VideoRecordingState.Inactive()
         )
     }
 }
@@ -591,18 +735,17 @@ private fun Preview_ControlsBottom_Recording() {
     CompositionLocalProvider(LocalContentColor provides Color.White) {
         ControlsBottom(
             previewUiState = PreviewUiState.Ready(
-                currentCameraSettings = CameraAppSettings(),
                 systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
                 previewMode = PreviewMode.StandardMode {},
-                captureModeToggleUiState = CaptureModeToggleUiState.Invisible
+                captureModeToggleUiState = CaptureModeToggleUiState.Invisible,
+                videoRecordingState = VideoRecordingState.Active.Recording(0L, .9, 1_000_000_000),
+                captureButtonUiState = DEFAULT_CAPTURE_BUTTON_STATE
             ),
             zoomLevel = 1.3f,
             showZoomLevel = true,
             isQuickSettingsOpen = false,
-            currentCameraSettings = CameraAppSettings(),
             systemConstraints = TYPICAL_SYSTEM_CONSTRAINTS,
-            videoRecordingState = VideoRecordingState.ACTIVE,
-            audioAmplitude = 0.9
+            videoRecordingState = VideoRecordingState.Active.Recording(0L, .9, 1_000_000_000)
         )
     }
 }
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraXViewfinder.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraXViewfinder.kt
deleted file mode 100644
index 2cf49ad..0000000
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/CameraXViewfinder.kt
+++ /dev/null
@@ -1,187 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.google.jetpackcamera.feature.preview.ui
-
-import android.content.pm.ActivityInfo
-import android.os.Build
-import android.util.Log
-import androidx.camera.core.DynamicRange
-import androidx.camera.core.Preview
-import androidx.camera.core.SurfaceRequest
-import androidx.camera.core.SurfaceRequest.TransformationInfo as CXTransformationInfo
-import androidx.camera.viewfinder.compose.MutableCoordinateTransformer
-import androidx.camera.viewfinder.compose.Viewfinder
-import androidx.camera.viewfinder.surface.ImplementationMode
-import androidx.camera.viewfinder.surface.TransformationInfo
-import androidx.camera.viewfinder.surface.ViewfinderSurfaceRequest
-import androidx.compose.foundation.gestures.detectTapGestures
-import androidx.compose.foundation.layout.fillMaxSize
-import androidx.compose.runtime.Composable
-import androidx.compose.runtime.LaunchedEffect
-import androidx.compose.runtime.getValue
-import androidx.compose.runtime.produceState
-import androidx.compose.runtime.rememberUpdatedState
-import androidx.compose.runtime.snapshotFlow
-import androidx.compose.ui.Modifier
-import androidx.compose.ui.input.pointer.pointerInput
-import kotlinx.coroutines.CoroutineStart
-import kotlinx.coroutines.Runnable
-import kotlinx.coroutines.flow.MutableStateFlow
-import kotlinx.coroutines.flow.collect
-import kotlinx.coroutines.flow.collectLatest
-import kotlinx.coroutines.flow.combine
-import kotlinx.coroutines.flow.distinctUntilChanged
-import kotlinx.coroutines.flow.filterNotNull
-import kotlinx.coroutines.flow.map
-import kotlinx.coroutines.flow.onCompletion
-import kotlinx.coroutines.flow.onEach
-import kotlinx.coroutines.flow.takeWhile
-import kotlinx.coroutines.launch
-
-private const val TAG = "CameraXViewfinder"
-
-/**
- * A composable viewfinder that adapts CameraX's [Preview.SurfaceProvider] to [Viewfinder]
- *
- * This adapter code will eventually be upstreamed to CameraX, but for now can be copied
- * in its entirety to connect CameraX to [Viewfinder].
- *
- * @param[modifier] the modifier to be applied to the layout
- * @param[surfaceRequest] a [SurfaceRequest] from [Preview.SurfaceProvider].
- * @param[implementationMode] the implementation mode, either [ImplementationMode.EXTERNAL] or
- * [ImplementationMode.EMBEDDED].
- */
-@Composable
-fun CameraXViewfinder(
-    surfaceRequest: SurfaceRequest,
-    modifier: Modifier = Modifier,
-    implementationMode: ImplementationMode = ImplementationMode.EXTERNAL,
-    onRequestWindowColorMode: (Int) -> Unit = {},
-    onTap: (x: Float, y: Float) -> Unit = { _, _ -> }
-) {
-    val currentImplementationMode by rememberUpdatedState(implementationMode)
-    val currentOnRequestWindowColorMode by rememberUpdatedState(onRequestWindowColorMode)
-
-    val viewfinderArgs by produceState<ViewfinderArgs?>(initialValue = null, surfaceRequest) {
-        val viewfinderSurfaceRequest = ViewfinderSurfaceRequest.Builder(surfaceRequest.resolution)
-            .build()
-
-        surfaceRequest.addRequestCancellationListener(Runnable::run) {
-            viewfinderSurfaceRequest.markSurfaceSafeToRelease()
-        }
-
-        // Launch undispatched so we always reach the try/finally in this coroutine
-        launch(start = CoroutineStart.UNDISPATCHED) {
-            try {
-                val surface = viewfinderSurfaceRequest.getSurface()
-                surfaceRequest.provideSurface(surface, Runnable::run) {
-                    viewfinderSurfaceRequest.markSurfaceSafeToRelease()
-                }
-            } finally {
-                // If we haven't provided the surface, such as if we're cancelled
-                // while suspending on getSurface(), this call will succeed. Otherwise
-                // it will be a no-op.
-                surfaceRequest.willNotProvideSurface()
-            }
-        }
-
-        val transformationInfos = MutableStateFlow<CXTransformationInfo?>(null)
-        surfaceRequest.setTransformationInfoListener(Runnable::run) {
-            transformationInfos.value = it
-        }
-
-        // The ImplementationMode that will be used for all TransformationInfo updates.
-        // This is locked in once we have updated ViewfinderArgs and won't change until
-        // this produceState block is cancelled and restarted
-        var snapshotImplementationMode: ImplementationMode? = null
-
-        snapshotFlow { currentImplementationMode }
-            .combine(transformationInfos.filterNotNull()) { implMode, transformInfo ->
-                Pair(implMode, transformInfo)
-            }.takeWhile { (implMode, _) ->
-                val shouldAbort =
-                    snapshotImplementationMode != null && implMode != snapshotImplementationMode
-                if (shouldAbort) {
-                    // Abort flow and invalidate SurfaceRequest so a new one will be sent
-                    surfaceRequest.invalidate()
-                }
-                !shouldAbort
-            }.collectLatest { (implMode, transformInfo) ->
-                // We'll only ever get here with a single non-null implMode,
-                // so setting it every time is ok
-                snapshotImplementationMode = implMode
-                value = ViewfinderArgs(
-                    viewfinderSurfaceRequest,
-                    isSourceHdr = surfaceRequest.dynamicRange.encoding != DynamicRange.ENCODING_SDR,
-                    implMode,
-                    TransformationInfo(
-                        sourceRotation = transformInfo.rotationDegrees,
-                        cropRectLeft = transformInfo.cropRect.left,
-                        cropRectTop = transformInfo.cropRect.top,
-                        cropRectRight = transformInfo.cropRect.right,
-                        cropRectBottom = transformInfo.cropRect.bottom,
-                        shouldMirror = transformInfo.isMirroring
-                    )
-                )
-            }
-    }
-
-    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
-        LaunchedEffect(Unit) {
-            snapshotFlow { viewfinderArgs }
-                .filterNotNull()
-                .map { args ->
-                    if (args.isSourceHdr &&
-                        args.implementationMode == ImplementationMode.EXTERNAL
-                    ) {
-                        ActivityInfo.COLOR_MODE_HDR
-                    } else {
-                        ActivityInfo.COLOR_MODE_DEFAULT
-                    }
-                }.distinctUntilChanged()
-                .onEach { currentOnRequestWindowColorMode(it) }
-                .onCompletion { currentOnRequestWindowColorMode(ActivityInfo.COLOR_MODE_DEFAULT) }
-                .collect()
-        }
-    }
-
-    val coordinateTransformer = MutableCoordinateTransformer()
-
-    viewfinderArgs?.let { args ->
-        Viewfinder(
-            surfaceRequest = args.viewfinderSurfaceRequest,
-            implementationMode = args.implementationMode,
-            transformationInfo = args.transformationInfo,
-            modifier = modifier.fillMaxSize().pointerInput(Unit) {
-                detectTapGestures {
-                    with(coordinateTransformer) {
-                        val tapOffset = it.transform()
-                        Log.d(TAG, "onTap: $tapOffset")
-                        onTap(tapOffset.x, tapOffset.y)
-                    }
-                }
-            },
-            coordinateTransformer = coordinateTransformer
-        )
-    }
-}
-
-private data class ViewfinderArgs(
-    val viewfinderSurfaceRequest: ViewfinderSurfaceRequest,
-    val isSourceHdr: Boolean,
-    val implementationMode: ImplementationMode,
-    val transformationInfo: TransformationInfo
-)
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/ImageWell.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/ImageWell.kt
new file mode 100644
index 0000000..504fec2
--- /dev/null
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/ImageWell.kt
@@ -0,0 +1,109 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.google.jetpackcamera.feature.preview.ui
+
+import android.graphics.RectF
+import android.net.Uri
+import androidx.compose.animation.AnimatedContent
+import androidx.compose.foundation.Canvas
+import androidx.compose.foundation.border
+import androidx.compose.foundation.clickable
+import androidx.compose.foundation.layout.Box
+import androidx.compose.foundation.layout.padding
+import androidx.compose.foundation.layout.size
+import androidx.compose.foundation.shape.RoundedCornerShape
+import androidx.compose.runtime.Composable
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.draw.clip
+import androidx.compose.ui.graphics.Color
+import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
+import androidx.compose.ui.graphics.nativeCanvas
+import androidx.compose.ui.platform.LocalContext
+import androidx.compose.ui.unit.dp
+import com.google.jetpackcamera.core.common.loadAndRotateBitmap
+import kotlin.math.min
+
+@Composable
+fun ImageWell(
+    modifier: Modifier = Modifier,
+    imageWellUiState: ImageWellUiState = ImageWellUiState.NoPreviousCapture,
+    onClick: (uri: Uri?) -> Unit
+) {
+    val context = LocalContext.current
+
+    when (imageWellUiState) {
+        is ImageWellUiState.LastCapture -> {
+            val bitmap = loadAndRotateBitmap(context, imageWellUiState.uri, 270f)
+
+            bitmap?.let {
+                Box(
+                    modifier = modifier
+                        .size(120.dp)
+                        .padding(18.dp)
+                        .border(2.dp, Color.White, RoundedCornerShape(16.dp))
+                        .clip(RoundedCornerShape(16.dp))
+                        .clickable(onClick = { onClick(imageWellUiState.uri) })
+                ) {
+                    AnimatedContent(
+                        targetState = bitmap
+                    ) { targetBitmap ->
+                        Canvas(
+                            modifier = Modifier
+                                .size(110.dp)
+                        ) {
+                            drawIntoCanvas { canvas ->
+                                val canvasSize = min(size.width, size.height)
+
+                                val scale = canvasSize / min(
+                                    targetBitmap.width,
+                                    targetBitmap.height
+                                )
+
+                                val imageWidth = targetBitmap.width * scale
+                                val imageHeight = targetBitmap.height * scale
+
+                                val offsetX = (canvasSize - imageWidth) / 2f
+                                val offsetY = (canvasSize - imageHeight) / 2f
+
+                                canvas.nativeCanvas.drawBitmap(
+                                    targetBitmap,
+                                    null,
+                                    RectF(
+                                        offsetX,
+                                        offsetY,
+                                        offsetX + imageWidth,
+                                        offsetY + imageHeight
+                                    ),
+                                    null
+                                )
+                            }
+                        }
+                    }
+                }
+            }
+        }
+
+        is ImageWellUiState.NoPreviousCapture -> {
+        }
+    }
+}
+
+// TODO(yasith): Add support for Video
+sealed interface ImageWellUiState {
+    data object NoPreviousCapture : ImageWellUiState
+
+    data class LastCapture(val uri: Uri) : ImageWellUiState
+}
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/PreviewScreenComponents.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/PreviewScreenComponents.kt
index 25a0f28..407e3c2 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/PreviewScreenComponents.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/PreviewScreenComponents.kt
@@ -15,16 +15,30 @@
  */
 package com.google.jetpackcamera.feature.preview.ui
 
+import android.content.pm.ActivityInfo
 import android.content.res.Configuration
 import android.os.Build
 import android.util.Log
 import android.widget.Toast
+import androidx.camera.compose.CameraXViewfinder
+import androidx.camera.core.DynamicRange as CXDynamicRange
 import androidx.camera.core.SurfaceRequest
-import androidx.camera.viewfinder.surface.ImplementationMode
+import androidx.camera.viewfinder.compose.MutableCoordinateTransformer
+import androidx.camera.viewfinder.core.ImplementationMode
+import androidx.compose.animation.AnimatedVisibility
+import androidx.compose.animation.animateColorAsState
+import androidx.compose.animation.core.Animatable
 import androidx.compose.animation.core.EaseOutExpo
+import androidx.compose.animation.core.FastOutSlowInEasing
 import androidx.compose.animation.core.LinearEasing
+import androidx.compose.animation.core.Spring
+import androidx.compose.animation.core.animateDpAsState
 import androidx.compose.animation.core.animateFloatAsState
+import androidx.compose.animation.core.spring
 import androidx.compose.animation.core.tween
+import androidx.compose.animation.fadeIn
+import androidx.compose.animation.fadeOut
+import androidx.compose.animation.scaleIn
 import androidx.compose.foundation.Canvas
 import androidx.compose.foundation.background
 import androidx.compose.foundation.border
@@ -51,12 +65,12 @@ import androidx.compose.material.icons.filled.CameraAlt
 import androidx.compose.material.icons.filled.FlipCameraAndroid
 import androidx.compose.material.icons.filled.Mic
 import androidx.compose.material.icons.filled.MicOff
-import androidx.compose.material.icons.filled.Nightlight
+import androidx.compose.material.icons.filled.Pause
+import androidx.compose.material.icons.filled.PlayArrow
 import androidx.compose.material.icons.filled.Settings
 import androidx.compose.material.icons.filled.VideoStable
 import androidx.compose.material.icons.filled.Videocam
 import androidx.compose.material.icons.outlined.CameraAlt
-import androidx.compose.material.icons.outlined.Nightlight
 import androidx.compose.material.icons.outlined.Videocam
 import androidx.compose.material3.Icon
 import androidx.compose.material3.IconButton
@@ -68,17 +82,24 @@ import androidx.compose.material3.SuggestionChip
 import androidx.compose.material3.Surface
 import androidx.compose.material3.Text
 import androidx.compose.runtime.Composable
+import androidx.compose.runtime.CompositionLocalProvider
 import androidx.compose.runtime.LaunchedEffect
 import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableFloatStateOf
 import androidx.compose.runtime.mutableStateOf
 import androidx.compose.runtime.remember
-import androidx.compose.runtime.rememberCoroutineScope
 import androidx.compose.runtime.rememberUpdatedState
 import androidx.compose.runtime.setValue
+import androidx.compose.runtime.snapshotFlow
 import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
 import androidx.compose.ui.draw.alpha
 import androidx.compose.ui.draw.clip
+import androidx.compose.ui.draw.rotate
+import androidx.compose.ui.draw.scale
+import androidx.compose.ui.geometry.CornerRadius
+import androidx.compose.ui.geometry.Offset
+import androidx.compose.ui.geometry.Size
 import androidx.compose.ui.graphics.Color
 import androidx.compose.ui.graphics.painter.Painter
 import androidx.compose.ui.graphics.vector.rememberVectorPainter
@@ -86,44 +107,147 @@ import androidx.compose.ui.input.pointer.pointerInput
 import androidx.compose.ui.layout.layout
 import androidx.compose.ui.platform.LocalContext
 import androidx.compose.ui.platform.testTag
+import androidx.compose.ui.res.painterResource
 import androidx.compose.ui.res.stringResource
+import androidx.compose.ui.semantics.Role
+import androidx.compose.ui.semantics.semantics
+import androidx.compose.ui.semantics.stateDescription
+import androidx.compose.ui.text.style.TextAlign
 import androidx.compose.ui.tooling.preview.Preview
 import androidx.compose.ui.unit.Dp
 import androidx.compose.ui.unit.dp
+import com.google.jetpackcamera.core.camera.VideoRecordingState
+import com.google.jetpackcamera.feature.preview.AudioUiState
+import com.google.jetpackcamera.feature.preview.CaptureButtonUiState
+import com.google.jetpackcamera.feature.preview.ElapsedTimeUiState
 import com.google.jetpackcamera.feature.preview.PreviewUiState
 import com.google.jetpackcamera.feature.preview.R
-import com.google.jetpackcamera.feature.preview.VideoRecordingState
+import com.google.jetpackcamera.feature.preview.StabilizationUiState
 import com.google.jetpackcamera.feature.preview.ui.theme.PreviewPreviewTheme
 import com.google.jetpackcamera.settings.model.AspectRatio
-import com.google.jetpackcamera.settings.model.LowLightBoost
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.LensFacing
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.VideoQuality
+import kotlin.time.Duration.Companion.nanoseconds
 import kotlinx.coroutines.delay
-import kotlinx.coroutines.launch
+import kotlinx.coroutines.flow.combine
+import kotlinx.coroutines.flow.distinctUntilChanged
+import kotlinx.coroutines.flow.map
+import kotlinx.coroutines.flow.onCompletion
 
 private const val TAG = "PreviewScreen"
 private const val BLINK_TIME = 100L
 
+@Composable
+fun ElapsedTimeText(modifier: Modifier = Modifier, elapsedTimeUiState: ElapsedTimeUiState.Enabled) {
+    Text(
+        modifier = modifier,
+        text = elapsedTimeUiState.elapsedTimeNanos.nanoseconds
+            .toComponents { minutes, seconds, _ -> "%02d:%02d".format(minutes, seconds) },
+        textAlign = TextAlign.Center
+    )
+}
+
+@Composable
+fun PauseResumeToggleButton(
+    modifier: Modifier = Modifier,
+    onSetPause: (Boolean) -> Unit,
+    size: Float = 55f,
+    currentRecordingState: VideoRecordingState.Active
+) {
+    var buttonClicked by remember { mutableStateOf(false) }
+    // animation value for the toggle icon itself
+    val animatedToggleScale by animateFloatAsState(
+        targetValue = if (buttonClicked) 1.1f else 1f, // Scale up to 110%
+        animationSpec = spring(
+            dampingRatio = Spring.DampingRatioLowBouncy,
+            stiffness = Spring.StiffnessMedium
+        ),
+        finishedListener = {
+            buttonClicked = false // Reset the trigger
+        }
+    )
+    Box(
+        modifier = modifier
+    ) {
+        Box(
+            modifier = Modifier
+                .clickable(
+                    onClick = {
+                        buttonClicked = true
+                        onSetPause(currentRecordingState !is VideoRecordingState.Active.Paused)
+                    },
+                    indication = null,
+                    interactionSource = null
+                )
+                .size(size = size.dp)
+                .scale(scale = animatedToggleScale)
+                .clip(CircleShape)
+                .background(Color.White),
+            contentAlignment = Alignment.Center
+        ) {
+            // icon
+            Icon(
+                modifier = Modifier
+                    .align(Alignment.Center)
+                    .size((0.75 * size).dp),
+                tint = Color.Red,
+                imageVector = when (currentRecordingState) {
+                    is VideoRecordingState.Active.Recording -> Icons.Filled.Pause
+                    is VideoRecordingState.Active.Paused -> Icons.Filled.PlayArrow
+                },
+                contentDescription = "pause resume toggle"
+            )
+        }
+    }
+}
+
 @Composable
 fun AmplitudeVisualizer(
     modifier: Modifier = Modifier,
-    size: Int = 100,
-    audioAmplitude: Double,
-    onToggleMute: () -> Unit
+    size: Float = 75f,
+    audioUiState: AudioUiState,
+    onToggleAudio: () -> Unit
 ) {
+    val currentUiState = rememberUpdatedState(audioUiState)
+    var buttonClicked by remember { mutableStateOf(false) }
+    // animation value for the toggle icon itself
+    val animatedToggleScale by animateFloatAsState(
+        targetValue = if (buttonClicked) 1.1f else 1f, // Scale up to 110%
+        animationSpec = spring(
+            dampingRatio = Spring.DampingRatioLowBouncy,
+            stiffness = Spring.StiffnessMedium
+        ),
+        finishedListener = {
+            buttonClicked = false // Reset the trigger
+        }
+    )
+
     // Tweak the multiplier to amplitude to adjust the visualizer sensitivity
-    val animatedScaling by animateFloatAsState(
-        targetValue = EaseOutExpo.transform(1 + (1.75f * audioAmplitude.toFloat())),
+    val animatedAudioScale by animateFloatAsState(
+        targetValue = EaseOutExpo.transform(1 + (1.75f * currentUiState.value.amplitude.toFloat())),
         label = "AudioAnimation"
     )
-    Box(modifier = modifier.clickable { onToggleMute() }) {
-        // animated circle
+    Box(
+        modifier = modifier.clickable(
+            onClick = {
+                buttonClicked = true
+                onToggleAudio()
+            },
+            interactionSource = null,
+            // removes the greyish background animation that appears when clicking
+            indication = null
+        )
+    ) {
+        // animated audio circle
         Canvas(
             modifier = Modifier
                 .align(Alignment.Center),
             onDraw = {
                 drawCircle(
                     // tweak the multiplier to size to adjust the maximum size of the visualizer
-                    radius = (size * animatedScaling).coerceIn(size.toFloat(), size * 1.65f),
+                    radius = (size * animatedAudioScale).coerceIn(size, size * 1.65f),
                     alpha = .5f,
                     color = Color.White
                 )
@@ -136,7 +260,7 @@ fun AmplitudeVisualizer(
                 .align(Alignment.Center),
             onDraw = {
                 drawCircle(
-                    radius = (size.toFloat()),
+                    radius = (size * animatedToggleScale),
                     color = Color.White
                 )
             }
@@ -146,15 +270,16 @@ fun AmplitudeVisualizer(
             modifier = Modifier
                 .align(Alignment.Center)
                 .size((0.5 * size).dp)
+                .scale(animatedToggleScale)
                 .apply {
-                    if (audioAmplitude != 0.0) {
+                    if (currentUiState.value is AudioUiState.Enabled.On) {
                         testTag(AMPLITUDE_HOT_TAG)
                     } else {
                         testTag(AMPLITUDE_NONE_TAG)
                     }
                 },
             tint = Color.Black,
-            imageVector = if (audioAmplitude != 0.0) {
+            imageVector = if (currentUiState.value is AudioUiState.Enabled.On) {
                 Icons.Filled.Mic
             } else {
                 Icons.Filled.MicOff
@@ -243,6 +368,50 @@ fun TestableSnackbar(
     }
 }
 
+@Composable
+fun DetectWindowColorModeChanges(
+    surfaceRequest: SurfaceRequest,
+    implementationMode: ImplementationMode,
+    onRequestWindowColorMode: (Int) -> Unit
+) {
+    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
+        val currentSurfaceRequest: SurfaceRequest by rememberUpdatedState(surfaceRequest)
+        val currentImplementationMode: ImplementationMode by rememberUpdatedState(
+            implementationMode
+        )
+        val currentOnRequestWindowColorMode: (Int) -> Unit by rememberUpdatedState(
+            onRequestWindowColorMode
+        )
+
+        LaunchedEffect(Unit) {
+            val colorModeSnapshotFlow =
+                snapshotFlow { Pair(currentSurfaceRequest.dynamicRange, currentImplementationMode) }
+                    .map { (dynamicRange, implMode) ->
+                        val isSourceHdr = dynamicRange.encoding != CXDynamicRange.ENCODING_SDR
+                        val destSupportsHdr = implMode == ImplementationMode.EXTERNAL
+                        if (isSourceHdr && destSupportsHdr) {
+                            ActivityInfo.COLOR_MODE_HDR
+                        } else {
+                            ActivityInfo.COLOR_MODE_DEFAULT
+                        }
+                    }.distinctUntilChanged()
+
+            val callbackSnapshotFlow = snapshotFlow { currentOnRequestWindowColorMode }
+
+            // Combine both flows so that we call the callback every time it changes or the
+            // window color mode changes.
+            // We'll also reset to default when this LaunchedEffect is disposed
+            combine(colorModeSnapshotFlow, callbackSnapshotFlow) { colorMode, callback ->
+                Pair(colorMode, callback)
+            }.onCompletion {
+                currentOnRequestWindowColorMode(ActivityInfo.COLOR_MODE_DEFAULT)
+            }.collect { (colorMode, callback) ->
+                callback(colorMode)
+            }
+        }
+    }
+}
+
 /**
  * this is the preview surface display. This view implements gestures tap to focus, pinch to zoom,
  * and double-tap to flip camera
@@ -264,24 +433,12 @@ fun PreviewDisplay(
         }
     )
 
-    val currentOnFlipCamera by rememberUpdatedState(onFlipCamera)
-
     surfaceRequest?.let {
         BoxWithConstraints(
-            Modifier
+            modifier
                 .testTag(PREVIEW_DISPLAY)
                 .fillMaxSize()
-                .background(Color.Black)
-                .pointerInput(Unit) {
-                    detectTapGestures(
-                        onDoubleTap = { offset ->
-                            // double tap to flip camera
-                            Log.d(TAG, "onDoubleTap $offset")
-                            currentOnFlipCamera()
-                        }
-                    )
-                },
-
+                .background(Color.Black),
             contentAlignment = Alignment.Center
         ) {
             val maxAspectRatio: Float = maxWidth / maxHeight
@@ -316,15 +473,44 @@ fun PreviewDisplay(
                     .alpha(imageAlpha)
                     .clip(RoundedCornerShape(16.dp))
             ) {
+                val implementationMode = when {
+                    Build.VERSION.SDK_INT > 24 -> ImplementationMode.EXTERNAL
+                    else -> ImplementationMode.EMBEDDED
+                }
+
+                DetectWindowColorModeChanges(
+                    surfaceRequest = surfaceRequest,
+                    implementationMode = implementationMode,
+                    onRequestWindowColorMode = onRequestWindowColorMode
+                )
+
+                val coordinateTransformer = remember { MutableCoordinateTransformer() }
                 CameraXViewfinder(
-                    modifier = Modifier.fillMaxSize(),
+                    modifier = Modifier
+                        .fillMaxSize()
+                        .pointerInput(Unit) {
+                            detectTapGestures(
+                                onDoubleTap = { offset ->
+                                    // double tap to flip camera
+                                    Log.d(TAG, "onDoubleTap $offset")
+                                    onFlipCamera()
+                                },
+                                onTap = {
+                                    with(coordinateTransformer) {
+                                        val surfaceCoords = it.transform()
+                                        Log.d(
+                                            "TAG",
+                                            "onTapToFocus: " +
+                                                "input{$it} -> surface{$surfaceCoords}"
+                                        )
+                                        onTapToFocus(surfaceCoords.x, surfaceCoords.y)
+                                    }
+                                }
+                            )
+                        },
                     surfaceRequest = it,
-                    implementationMode = when {
-                        Build.VERSION.SDK_INT > 24 -> ImplementationMode.EXTERNAL
-                        else -> ImplementationMode.EMBEDDED
-                    },
-                    onRequestWindowColorMode = onRequestWindowColorMode,
-                    onTap = { x, y -> onTapToFocus(x, y) }
+                    implementationMode = implementationMode,
+                    coordinateTransformer = coordinateTransformer
                 )
             }
         }
@@ -333,44 +519,118 @@ fun PreviewDisplay(
 
 @Composable
 fun StabilizationIcon(
-    videoStabilization: Stabilization,
-    previewStabilization: Stabilization,
+    stabilizationUiState: StabilizationUiState.Enabled,
     modifier: Modifier = Modifier
 ) {
-    if (videoStabilization == Stabilization.ON || previewStabilization == Stabilization.ON) {
-        val descriptionText = if (videoStabilization == Stabilization.ON) {
-            stringResource(id = R.string.stabilization_icon_description_preview_and_video)
-        } else {
-            // previewStabilization will not be on for high quality
-            stringResource(id = R.string.stabilization_icon_description_video_only)
+    val contentColor = Color.White.let {
+        if (!stabilizationUiState.active) it.copy(alpha = 0.38f) else it
+    }
+    CompositionLocalProvider(LocalContentColor provides contentColor) {
+        if (stabilizationUiState.stabilizationMode != StabilizationMode.OFF) {
+            Icon(
+                painter = when (stabilizationUiState) {
+                    is StabilizationUiState.Specific ->
+                        when (stabilizationUiState.stabilizationMode) {
+                            StabilizationMode.AUTO ->
+                                throw IllegalStateException(
+                                    "AUTO is not a specific StabilizationUiState."
+                                )
+
+                            StabilizationMode.HIGH_QUALITY ->
+                                painterResource(R.drawable.video_stable_hq_filled_icon)
+
+                            StabilizationMode.OPTICAL ->
+                                painterResource(R.drawable.video_stable_ois_filled_icon)
+
+                            StabilizationMode.ON ->
+                                rememberVectorPainter(Icons.Filled.VideoStable)
+
+                            else ->
+                                TODO(
+                                    "Cannot retrieve icon for unimplemented stabilization mode:" +
+                                        "${stabilizationUiState.stabilizationMode}"
+                                )
+                        }
+
+                    is StabilizationUiState.Auto -> {
+                        when (stabilizationUiState.stabilizationMode) {
+                            StabilizationMode.ON ->
+                                painterResource(R.drawable.video_stable_auto_filled_icon)
+
+                            StabilizationMode.OPTICAL ->
+                                painterResource(R.drawable.video_stable_ois_auto_filled_icon)
+
+                            else ->
+                                TODO(
+                                    "Auto stabilization not yet implemented for " +
+                                        "${stabilizationUiState.stabilizationMode}, " +
+                                        "unable to retrieve icon."
+                                )
+                        }
+                    }
+                },
+                contentDescription = when (stabilizationUiState.stabilizationMode) {
+                    StabilizationMode.AUTO ->
+                        stringResource(R.string.stabilization_icon_description_auto)
+
+                    StabilizationMode.ON ->
+                        stringResource(R.string.stabilization_icon_description_preview_and_video)
+
+                    StabilizationMode.HIGH_QUALITY ->
+                        stringResource(R.string.stabilization_icon_description_video_only)
+
+                    StabilizationMode.OPTICAL ->
+                        stringResource(R.string.stabilization_icon_description_optical)
+
+                    else -> null
+                },
+                modifier = modifier
+            )
         }
-        Icon(
-            imageVector = Icons.Filled.VideoStable,
-            contentDescription = descriptionText,
-            modifier = modifier
-        )
     }
 }
 
-/**
- * LowLightBoostIcon has 3 states
- * - disabled: hidden
- * - enabled and inactive: outline
- * - enabled and active: filled
- */
 @Composable
-fun LowLightBoostIcon(lowLightBoost: LowLightBoost, modifier: Modifier = Modifier) {
-    when (lowLightBoost) {
-        LowLightBoost.ENABLED -> {
+fun VideoQualityIcon(videoQuality: VideoQuality, modifier: Modifier = Modifier) {
+    CompositionLocalProvider(LocalContentColor provides Color.White) {
+        if (videoQuality != VideoQuality.UNSPECIFIED) {
             Icon(
-                imageVector = Icons.Outlined.Nightlight,
-                contentDescription =
-                stringResource(id = R.string.quick_settings_lowlightboost_enabled),
-                modifier = modifier.alpha(0.5f)
+                painter = when (videoQuality) {
+                    VideoQuality.SD ->
+                        painterResource(R.drawable.video_resolution_sd_icon)
+
+                    VideoQuality.HD ->
+                        painterResource(R.drawable.video_resolution_hd_icon)
+
+                    VideoQuality.FHD ->
+                        painterResource(R.drawable.video_resolution_fhd_icon)
+
+                    VideoQuality.UHD ->
+                        painterResource(R.drawable.video_resolution_uhd_icon)
+
+                    else ->
+                        throw IllegalStateException(
+                            "Illegal video quality state"
+                        )
+                },
+                contentDescription = when (videoQuality) {
+                    VideoQuality.SD ->
+                        stringResource(R.string.video_quality_description_sd)
+
+                    VideoQuality.HD ->
+                        stringResource(R.string.video_quality_description_hd)
+
+                    VideoQuality.FHD ->
+                        stringResource(R.string.video_quality_description_fhd)
+
+                    VideoQuality.UHD ->
+                        stringResource(R.string.video_quality_description_uhd)
+
+                    else -> null
+                },
+                modifier = modifier
             )
         }
-        LowLightBoost.DISABLED -> {
-        }
     }
 }
 
@@ -391,9 +651,32 @@ fun TestingButton(onClick: () -> Unit, text: String, modifier: Modifier = Modifi
 @Composable
 fun FlipCameraButton(
     enabledCondition: Boolean,
+    lensFacing: LensFacing,
     onClick: () -> Unit,
     modifier: Modifier = Modifier
 ) {
+    var rotation by remember { mutableFloatStateOf(0f) }
+    val animatedRotation = remember { Animatable(0f) }
+    var initialLaunch by remember { mutableStateOf(false) }
+
+    // spin animate whenever lensfacing changes
+    LaunchedEffect(lensFacing) {
+        if (initialLaunch) {
+            // full 360
+            rotation -= 180f
+            animatedRotation.animateTo(
+                targetValue = rotation,
+                animationSpec = spring(
+                    dampingRatio = Spring.DampingRatioMediumBouncy,
+                    stiffness = Spring.StiffnessVeryLow
+                )
+            )
+        }
+        // dont rotate on the initial launch
+        else {
+            initialLaunch = true
+        }
+    }
     IconButton(
         modifier = modifier.size(40.dp),
         onClick = onClick,
@@ -402,7 +685,9 @@ fun FlipCameraButton(
         Icon(
             imageVector = Icons.Filled.FlipCameraAndroid,
             contentDescription = stringResource(id = R.string.flip_camera_content_description),
-            modifier = Modifier.size(72.dp)
+            modifier = Modifier
+                .size(72.dp)
+                .rotate(animatedRotation.value)
         )
     }
 }
@@ -458,50 +743,163 @@ fun CurrentCameraIdText(physicalCameraId: String?, logicalCameraId: String?) {
 
 @Composable
 fun CaptureButton(
-    onClick: () -> Unit,
-    onLongPress: () -> Unit,
-    onRelease: () -> Unit,
-    videoRecordingState: VideoRecordingState,
-    modifier: Modifier = Modifier
+    modifier: Modifier = Modifier,
+    onCaptureImage: () -> Unit,
+    onStartVideoRecording: () -> Unit,
+    onStopVideoRecording: () -> Unit,
+    onLockVideoRecording: (Boolean) -> Unit,
+    captureButtonUiState: CaptureButtonUiState,
+    captureButtonSize: Float = 80f
 ) {
+    val currentUiState = rememberUpdatedState(captureButtonUiState)
     var isPressedDown by remember {
         mutableStateOf(false)
     }
+    var isLongPressing by remember {
+        mutableStateOf(false)
+    }
+
     val currentColor = LocalContentColor.current
     Box(
+        contentAlignment = Alignment.Center,
         modifier = modifier
             .pointerInput(Unit) {
                 detectTapGestures(
                     onLongPress = {
-                        onLongPress()
+                        isLongPressing = true
+                        val uiState = currentUiState.value
+                        if (uiState is CaptureButtonUiState.Enabled.Idle) {
+                            when (uiState.captureMode) {
+                                CaptureMode.STANDARD,
+                                CaptureMode.VIDEO_ONLY -> {
+                                    onStartVideoRecording()
+                                }
+
+                                CaptureMode.IMAGE_ONLY -> {}
+                            }
+                        }
                     },
-                    // TODO: @kimblebee - stopVideoRecording is being called every time the capture
-                    // button is pressed -- regardless of tap or long press
                     onPress = {
                         isPressedDown = true
                         awaitRelease()
                         isPressedDown = false
-                        onRelease()
+                        isLongPressing = false
+                        val uiState = currentUiState.value
+                        when (uiState) {
+                            // stop recording after button is lifted
+                            is CaptureButtonUiState.Enabled.Recording.PressedRecording -> {
+                                onStopVideoRecording()
+                            }
+
+                            is CaptureButtonUiState.Enabled.Idle,
+                            CaptureButtonUiState.Unavailable -> {
+                            }
+
+                            CaptureButtonUiState.Enabled.Recording.LockedRecording -> {}
+                        }
                     },
-                    onTap = { onClick() }
+                    onTap = {
+                        val uiState = currentUiState.value
+                        when (uiState) {
+                            is CaptureButtonUiState.Enabled.Idle -> {
+                                if (!isLongPressing) {
+                                    when (uiState.captureMode) {
+                                        CaptureMode.STANDARD,
+                                        CaptureMode.IMAGE_ONLY -> onCaptureImage()
+
+                                        CaptureMode.VIDEO_ONLY -> {
+                                            onLockVideoRecording(true)
+                                            onStartVideoRecording()
+                                        }
+                                    }
+                                }
+                            }
+                            // stop if locked recording
+                            CaptureButtonUiState.Enabled.Recording.LockedRecording -> {
+                                onStopVideoRecording()
+                            }
+
+                            CaptureButtonUiState.Unavailable,
+                            CaptureButtonUiState.Enabled.Recording.PressedRecording -> {
+                            }
+                        }
+                    }
                 )
             }
-            .size(120.dp)
-            .padding(18.dp)
-            .border(4.dp, currentColor, CircleShape)
+            .size(captureButtonSize.dp)
+            .border(4.dp, currentColor, CircleShape) // border is the white ring
     ) {
-        Canvas(modifier = Modifier.size(110.dp), onDraw = {
-            drawCircle(
-                color =
-                when (videoRecordingState) {
-                    VideoRecordingState.INACTIVE -> {
-                        if (isPressedDown) currentColor else Color.Transparent
-                    }
+        // now we draw center circle
+        val centerShapeSize by animateDpAsState(
+            targetValue = when (val uiState = currentUiState.value) {
+                // inner circle fills white ring when locked
+                CaptureButtonUiState.Enabled.Recording.LockedRecording -> captureButtonSize.dp
+                // larger circle while recording, but not max size
+                CaptureButtonUiState.Enabled.Recording.PressedRecording ->
+                    (captureButtonSize * .7f).dp
 
-                    VideoRecordingState.ACTIVE -> Color.Red
+                CaptureButtonUiState.Unavailable -> 0.dp
+                is CaptureButtonUiState.Enabled.Idle -> when (uiState.captureMode) {
+                    // no inner circle will be visible on STANDARD
+                    CaptureMode.STANDARD -> 0.dp
+                    // large white circle will be visible on IMAGE_ONLY
+                    CaptureMode.IMAGE_ONLY -> (captureButtonSize * .7f).dp
+                    // small red circle will be visible on VIDEO_ONLY
+                    CaptureMode.VIDEO_ONLY -> (captureButtonSize * .35f).dp
                 }
-            )
-        })
+            },
+            animationSpec = tween(durationMillis = 500, easing = FastOutSlowInEasing)
+        )
+
+        // used to fade between red/white in the center of the capture button
+        val animatedColor by animateColorAsState(
+            targetValue = when (val uiState = currentUiState.value) {
+                is CaptureButtonUiState.Enabled.Idle -> when (uiState.captureMode) {
+                    CaptureMode.STANDARD -> Color.White
+                    CaptureMode.IMAGE_ONLY -> Color.White
+                    CaptureMode.VIDEO_ONLY -> Color.Red
+                }
+
+                is CaptureButtonUiState.Enabled.Recording -> Color.Red
+                is CaptureButtonUiState.Unavailable -> Color.Transparent
+            },
+            animationSpec = tween(durationMillis = 500)
+        )
+        // inner circle
+        Box(
+            contentAlignment = Alignment.Center,
+            modifier = Modifier
+                .size(centerShapeSize)
+                .clip(CircleShape)
+                .alpha(
+                    if (isPressedDown &&
+                        currentUiState.value ==
+                        CaptureButtonUiState.Enabled.Idle(CaptureMode.IMAGE_ONLY)
+                    ) {
+                        .5f // transparency to indicate click ONLY on IMAGE_ONLY
+                    } else {
+                        1f // solid alpha the rest of the time
+                    }
+                )
+                .background(animatedColor)
+        ) {}
+        // central "square" stop icon
+        AnimatedVisibility(
+            visible = currentUiState.value is
+                CaptureButtonUiState.Enabled.Recording.LockedRecording,
+            enter = scaleIn(initialScale = .5f) + fadeIn(),
+            exit = fadeOut()
+        ) {
+            val smallBoxSize = (captureButtonSize / 5f).dp
+            Canvas(modifier = Modifier) {
+                drawRoundRect(
+                    color = Color.White,
+                    topLeft = Offset(-smallBoxSize.toPx() / 2f, -smallBoxSize.toPx() / 2f),
+                    size = Size(smallBoxSize.toPx(), smallBoxSize.toPx()),
+                    cornerRadius = CornerRadius(smallBoxSize.toPx() * .15f)
+                )
+            }
+        }
     }
 }
 
@@ -514,9 +912,7 @@ enum class ToggleState {
 fun ToggleButton(
     leftIcon: Painter,
     rightIcon: Painter,
-    modifier: Modifier = Modifier
-        .width(64.dp)
-        .height(32.dp),
+    modifier: Modifier = Modifier,
     initialState: ToggleState = ToggleState.Left,
     onToggleStateChanged: (newState: ToggleState) -> Unit = {},
     onToggleWhenDisabled: () -> Unit = {},
@@ -539,26 +935,33 @@ fun ToggleButton(
         },
         label = "togglePosition"
     )
-    val scope = rememberCoroutineScope()
 
     Surface(
         modifier = modifier
             .clip(shape = RoundedCornerShape(50))
             .then(
-                Modifier.clickable {
-                    scope.launch {
-                        if (enabled) {
-                            toggleState = when (toggleState) {
-                                ToggleState.Left -> ToggleState.Right
-                                ToggleState.Right -> ToggleState.Left
-                            }
-                            onToggleStateChanged(toggleState)
-                        } else {
-                            onToggleWhenDisabled()
+                Modifier.clickable(
+                    role = Role.Switch
+                ) {
+                    if (enabled) {
+                        toggleState = when (toggleState) {
+                            ToggleState.Left -> ToggleState.Right
+                            ToggleState.Right -> ToggleState.Left
                         }
+                        onToggleStateChanged(toggleState)
+                    } else {
+                        onToggleWhenDisabled()
                     }
                 }
-            ),
+            )
+            .semantics {
+                stateDescription = when (toggleState) {
+                    ToggleState.Left -> leftIconDescription
+                    ToggleState.Right -> rightIconDescription
+                }
+            }
+            .width(64.dp)
+            .height(32.dp),
         color = backgroundColor
     ) {
         Box {
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/TestTags.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/TestTags.kt
index 077a971..58ab943 100644
--- a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/TestTags.kt
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/TestTags.kt
@@ -15,7 +15,18 @@
  */
 package com.google.jetpackcamera.feature.preview.ui
 
+// ////////////////////////////////
+//
+// !!!HEY YOU!!!
+// MODIFICATIONS TO EXISTING TEST TAGS WILL BREAK EXISTING EXTERNAL
+// AUTOMATED TESTS THAT SEARCH FOR THESE TAGS.
+//
+// PLEASE UPDATE YOUR TESTS ACCORDINGLY!
+//
+// ////////////////////////////////
+
 const val CAPTURE_BUTTON = "CaptureButton"
+const val CAPTURE_MODE_TOGGLE_BUTTON = "CaptureModeToggleButton"
 const val FLIP_CAMERA_BUTTON = "FlipCameraButton"
 const val IMAGE_CAPTURE_SUCCESS_TAG = "ImageCaptureSuccessTag"
 const val IMAGE_CAPTURE_FAILURE_TAG = "ImageCaptureFailureTag"
@@ -39,3 +50,12 @@ const val HDR_VIDEO_UNSUPPORTED_ON_LENS_TAG = "HdrVideoUnsupportedOnDeviceTag"
 const val ZOOM_RATIO_TAG = "ZoomRatioTag"
 const val LOGICAL_CAMERA_ID_TAG = "LogicalCameraIdTag"
 const val PHYSICAL_CAMERA_ID_TAG = "PhysicalCameraIdTag"
+const val ELAPSED_TIME_TAG = "ElapsedTimeTag"
+const val VIDEO_QUALITY_TAG = "VideoQualityTag"
+const val DEBUG_OVERLAY_BUTTON = "DebugOverlayButton"
+const val DEBUG_OVERLAY_SHOW_CAMERA_PROPERTIES_BUTTON = "DebugOverlayShowCameraPropertiesButton"
+const val DEBUG_OVERLAY_SET_ZOOM_RATIO_BUTTON = "DebugOverlaySetZoomRatioButton"
+const val DEBUG_OVERLAY_CAMERA_PROPERTIES_TAG = "DebugOverlayCameraPropertiesTag"
+const val DEBUG_OVERLAY_SET_ZOOM_RATIO_TEXT_FIELD = "DebugOverlaySetZoomRatioTextField"
+const val DEBUG_OVERLAY_SET_ZOOM_RATIO_SET_BUTTON = "DebugOverlaySetZoomRatioSetButton"
+const val DEBUG_OVERLAY_VIDEO_RESOLUTION_TAG = "DebugOverlayVideoResolutionTag"
diff --git a/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/debug/DebugOverlayComponents.kt b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/debug/DebugOverlayComponents.kt
new file mode 100644
index 0000000..47ed19a
--- /dev/null
+++ b/feature/preview/src/main/java/com/google/jetpackcamera/feature/preview/ui/debug/DebugOverlayComponents.kt
@@ -0,0 +1,231 @@
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
+package com.google.jetpackcamera.feature.preview.ui.debug
+
+import android.util.Log
+import androidx.activity.compose.BackHandler
+import androidx.compose.animation.animateColorAsState
+import androidx.compose.animation.core.animateFloatAsState
+import androidx.compose.animation.core.tween
+import androidx.compose.foundation.background
+import androidx.compose.foundation.clickable
+import androidx.compose.foundation.layout.Arrangement
+import androidx.compose.foundation.layout.Box
+import androidx.compose.foundation.layout.Column
+import androidx.compose.foundation.layout.Row
+import androidx.compose.foundation.layout.fillMaxSize
+import androidx.compose.foundation.rememberScrollState
+import androidx.compose.foundation.text.KeyboardOptions
+import androidx.compose.foundation.verticalScroll
+import androidx.compose.material3.Text
+import androidx.compose.material3.TextButton
+import androidx.compose.material3.TextField
+import androidx.compose.runtime.Composable
+import androidx.compose.runtime.getValue
+import androidx.compose.runtime.mutableStateOf
+import androidx.compose.runtime.remember
+import androidx.compose.runtime.setValue
+import androidx.compose.ui.Alignment
+import androidx.compose.ui.Modifier
+import androidx.compose.ui.draw.alpha
+import androidx.compose.ui.graphics.Color
+import androidx.compose.ui.platform.testTag
+import androidx.compose.ui.text.input.KeyboardType
+import androidx.compose.ui.unit.sp
+import com.google.jetpackcamera.feature.preview.PreviewUiState
+import com.google.jetpackcamera.feature.preview.ui.DEBUG_OVERLAY_BUTTON
+import com.google.jetpackcamera.feature.preview.ui.DEBUG_OVERLAY_CAMERA_PROPERTIES_TAG
+import com.google.jetpackcamera.feature.preview.ui.DEBUG_OVERLAY_SET_ZOOM_RATIO_BUTTON
+import com.google.jetpackcamera.feature.preview.ui.DEBUG_OVERLAY_SET_ZOOM_RATIO_SET_BUTTON
+import com.google.jetpackcamera.feature.preview.ui.DEBUG_OVERLAY_SET_ZOOM_RATIO_TEXT_FIELD
+import com.google.jetpackcamera.feature.preview.ui.DEBUG_OVERLAY_SHOW_CAMERA_PROPERTIES_BUTTON
+import com.google.jetpackcamera.feature.preview.ui.DEBUG_OVERLAY_VIDEO_RESOLUTION_TAG
+import kotlin.math.abs
+
+private const val TAG = "DebugOverlayComponents"
+
+@Composable
+fun DebugOverlayToggleButton(modifier: Modifier = Modifier, toggleIsOpen: () -> Unit) {
+    TextButton(modifier = modifier.testTag(DEBUG_OVERLAY_BUTTON), onClick = { toggleIsOpen() }) {
+        Text(text = "Debug")
+    }
+}
+
+@Composable
+fun DebugOverlayComponent(
+    modifier: Modifier = Modifier,
+    onChangeZoomScale: (Float) -> Unit,
+    toggleIsOpen: () -> Unit,
+    previewUiState: PreviewUiState.Ready
+) {
+    val isOpen = previewUiState.debugUiState.isDebugMode &&
+        previewUiState.debugUiState.isDebugOverlayOpen
+    val backgroundColor =
+        animateColorAsState(
+            targetValue = Color.Black.copy(alpha = if (isOpen) 0.7f else 0f),
+            label = "backgroundColorAnimation"
+        )
+
+    val contentAlpha =
+        animateFloatAsState(
+            targetValue = if (isOpen) 1f else 0f,
+            label = "contentAlphaAnimation",
+            animationSpec = tween()
+        )
+
+    val zoomRatioDialog = remember { mutableStateOf(false) }
+    val cameraPropertiesJSONDialog = remember { mutableStateOf(false) }
+
+    if (isOpen) {
+        BackHandler(onBack = { toggleIsOpen() })
+
+        Box(
+            modifier = modifier
+                .fillMaxSize()
+                .background(color = backgroundColor.value)
+                .alpha(alpha = contentAlpha.value)
+                .clickable(onClick = { toggleIsOpen() })
+        ) {
+            // Buttons
+            Column(
+                modifier = Modifier.fillMaxSize(),
+                verticalArrangement = Arrangement.Center,
+                horizontalAlignment = Alignment.CenterHorizontally
+            ) {
+                TextButton(
+                    modifier = Modifier.testTag(
+                        DEBUG_OVERLAY_SHOW_CAMERA_PROPERTIES_BUTTON
+                    ),
+                    onClick = {
+                        cameraPropertiesJSONDialog.value = true
+                    }
+                ) {
+                    Text(text = "Show Camera Properties JSON")
+                }
+
+                Row {
+                    Text("Video resolution: ")
+                    val videoResText = if (previewUiState.debugUiState.videoResolution == null) {
+                        "null"
+                    } else {
+                        val size = previewUiState.debugUiState.videoResolution
+                        abs(size.height).toString() + "x" + abs(size.width).toString()
+                    }
+                    Text(
+                        modifier = Modifier.testTag(
+                            DEBUG_OVERLAY_VIDEO_RESOLUTION_TAG
+                        ),
+                        text = videoResText
+                    )
+                }
+
+                TextButton(
+                    modifier = Modifier.testTag(
+                        DEBUG_OVERLAY_SET_ZOOM_RATIO_BUTTON
+                    ),
+                    onClick = {
+                        zoomRatioDialog.value = true
+                    }
+                ) {
+                    Text(text = "Set Zoom Ratio")
+                }
+            }
+
+            // Openable contents
+            // Show Camera properties
+            if (cameraPropertiesJSONDialog.value) {
+                CameraPropertiesJSONComponent(previewUiState) {
+                    cameraPropertiesJSONDialog.value = false
+                }
+            }
+
+            // Set zoom ratio
+            if (zoomRatioDialog.value) {
+                SetZoomRatioComponent(previewUiState, onChangeZoomScale) {
+                    zoomRatioDialog.value = false
+                }
+            }
+        }
+    }
+}
+
+@Composable
+private fun CameraPropertiesJSONComponent(
+    previewUiState: PreviewUiState.Ready,
+    onClose: () -> Unit
+) {
+    BackHandler(onBack = { onClose() })
+    val scrollState = rememberScrollState()
+    Column(
+        modifier = Modifier
+            .fillMaxSize()
+            .verticalScroll(state = scrollState)
+            .background(color = Color.Black)
+    ) {
+        Text(
+            modifier = Modifier.testTag(DEBUG_OVERLAY_CAMERA_PROPERTIES_TAG),
+            text = previewUiState.debugUiState.cameraPropertiesJSON,
+            fontSize = 10.sp
+        )
+    }
+}
+
+@Composable
+private fun SetZoomRatioComponent(
+    previewUiState: PreviewUiState.Ready,
+    onChangeZoomScale: (Float) -> Unit,
+    onClose: () -> Unit
+) {
+    var zoomRatioText = remember { mutableStateOf("") }
+    BackHandler(onBack = { onClose() })
+    val scrollState = rememberScrollState()
+    Column(
+        modifier = Modifier
+            .fillMaxSize()
+            .verticalScroll(state = scrollState)
+            .background(color = Color.Black)
+    ) {
+        Text(text = "Enter and confirm zoom ratio (Absolute not relative)")
+        TextField(
+            modifier = Modifier.testTag(DEBUG_OVERLAY_SET_ZOOM_RATIO_TEXT_FIELD),
+            value = zoomRatioText.value,
+            onValueChange = { zoomRatioText.value = it },
+            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
+        )
+        TextButton(
+            modifier = Modifier.testTag(
+                DEBUG_OVERLAY_SET_ZOOM_RATIO_SET_BUTTON
+            ),
+            onClick = {
+                try {
+                    val relativeRatio = if (zoomRatioText.value.isEmpty()) {
+                        1f
+                    } else {
+                        zoomRatioText.value.toFloat()
+                    }
+                    val currentRatio = previewUiState.zoomScale
+                    val absoluteRatio = relativeRatio / currentRatio
+                    onChangeZoomScale(absoluteRatio)
+                } catch (e: NumberFormatException) {
+                    Log.d(TAG, "Zoom ratio should be a float")
+                }
+                onClose()
+            }
+        ) {
+            Text(text = "Set")
+        }
+    }
+}
diff --git a/feature/preview/src/main/res/drawable/video_resolution_fhd_icon.xml b/feature/preview/src/main/res/drawable/video_resolution_fhd_icon.xml
new file mode 100644
index 0000000..3aed271
--- /dev/null
+++ b/feature/preview/src/main/res/drawable/video_resolution_fhd_icon.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<vector xmlns:android="http://schemas.android.com/apk/res/android" xmlns:aapt="http://schemas.android.com/aapt"
+    android:viewportWidth="960"
+    android:viewportHeight="960"
+    android:width="24dp"
+    android:height="24dp">
+    <group
+        android:translateX="-0"
+        android:translateY="960">
+        <path
+            android:pathData="M380 -360h60v-80h60v80h60v-240h-60v100h-60v-100h-60v240Zm220 0h140q17 0 28.5 -11.5T780 -400v-160q0 -17 -11.5 -28.5T740 -600H600v240Zm60 -60v-120h60v120h-60Zm-480 60h60v-80h80v-60h-80v-40h100v-60H180v240Zm-60 200q-33 0 -56.5 -23.5T40 -240v-480q0 -33 23.5 -56.5T120 -800h720q33 0 56.5 23.5T920 -720v480q0 33 -23.5 56.5T840 -160H120Zm0 -80h720v-480H120v480Zm0 0v-480 480Z"
+            android:fillColor="@android:color/white" />
+    </group>
+</vector>
\ No newline at end of file
diff --git a/feature/preview/src/main/res/drawable/video_resolution_hd_icon.xml b/feature/preview/src/main/res/drawable/video_resolution_hd_icon.xml
new file mode 100644
index 0000000..0fbf23d
--- /dev/null
+++ b/feature/preview/src/main/res/drawable/video_resolution_hd_icon.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<vector xmlns:android="http://schemas.android.com/apk/res/android" xmlns:aapt="http://schemas.android.com/aapt"
+    android:viewportWidth="960"
+    android:viewportHeight="960"
+    android:width="24dp"
+    android:height="24dp">
+    <group
+        android:translateX="-0"
+        android:translateY="960">
+        <path
+            android:pathData="M240 -360h60v-80h80v80h60v-240h-60v100h-80v-100h-60v240Zm280 0h160q17 0 28.5 -11.5T720 -400v-160q0 -17 -11.5 -28.5T680 -600H520v240Zm60 -60v-120h80v120h-80ZM160 -160q-33 0 -56.5 -23.5T80 -240v-480q0 -33 23.5 -56.5T160 -800h640q33 0 56.5 23.5T880 -720v480q0 33 -23.5 56.5T800 -160H160Zm0 -80h640v-480H160v480Zm0 0v-480 480Z"
+            android:fillColor="@android:color/white" />
+    </group>
+</vector>
\ No newline at end of file
diff --git a/feature/preview/src/main/res/drawable/video_resolution_sd_icon.xml b/feature/preview/src/main/res/drawable/video_resolution_sd_icon.xml
new file mode 100644
index 0000000..31e1c23
--- /dev/null
+++ b/feature/preview/src/main/res/drawable/video_resolution_sd_icon.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="960"
+    android:viewportHeight="960">
+  <path
+      android:pathData="M520,600L680,600C691.33,600 700.83,596.17 708.5,588.5C716.17,580.83 720,571.33 720,560L720,400C720,388.67 716.17,379.17 708.5,371.5C700.83,363.83 691.33,360 680,360L520,360L520,600ZM580,540L580,420L660,420L660,540L580,540ZM160,800C138,800 119.17,792.17 103.5,776.5C87.83,760.83 80,742 80,720L80,240C80,218 87.83,199.17 103.5,183.5C119.17,167.83 138,160 160,160L800,160C822,160 840.83,167.83 856.5,183.5C872.17,199.17 880,218 880,240L880,720C880,742 872.17,760.83 856.5,776.5C840.83,792.17 822,800 800,800L160,800ZM160,720L800,720L800,240L160,240L160,720ZM160,720L160,240L160,720Z"
+      android:fillColor="@android:color/white"/>
+  <path
+      android:pathData="M269.82,603.7L409.82,603.7C421.15,603.7 430.65,599.87 438.32,592.2C445.99,584.54 449.82,575.04 449.82,563.7L449.82,503.7C449.82,492.37 445.99,482.87 438.32,475.2C430.65,467.54 421.15,463.7 409.82,463.7L329.82,463.7L329.82,423.7L449.82,423.7L449.82,363.7L309.82,363.7C298.49,363.7 288.99,367.54 281.32,375.2C273.65,382.87 269.82,392.37 269.82,403.7L269.82,463.7C269.82,475.04 273.65,484.54 281.32,492.2C288.99,499.87 298.49,503.7 309.82,503.7L389.82,503.7L389.82,543.7L269.82,543.7L269.82,603.7Z"
+      android:fillColor="@android:color/white"/>
+</vector>
diff --git a/feature/preview/src/main/res/drawable/video_resolution_uhd_icon.xml b/feature/preview/src/main/res/drawable/video_resolution_uhd_icon.xml
new file mode 100644
index 0000000..d725f61
--- /dev/null
+++ b/feature/preview/src/main/res/drawable/video_resolution_uhd_icon.xml
@@ -0,0 +1,28 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="960"
+    android:viewportHeight="960">
+  <path
+      android:pathData="M380,600L440,600L440,520L500,520L500,600L560,600L560,360L500,360L500,460L440,460L440,360L380,360L380,600ZM600,600L740,600C751.33,600 760.83,596.17 768.5,588.5C776.17,580.83 780,571.33 780,560L780,400C780,388.67 776.17,379.17 768.5,371.5C760.83,363.83 751.33,360 740,360L600,360L600,600ZM660,540L660,420L720,420L720,540L660,540ZM120,800C98,800 79.17,792.17 63.5,776.5C47.83,760.83 40,742 40,720L40,240C40,218 47.83,199.17 63.5,183.5C79.17,167.83 98,160 120,160L840,160C862,160 880.83,167.83 896.5,183.5C912.17,199.17 920,218 920,240L920,720C920,742 912.17,760.83 896.5,776.5C880.83,792.17 862,800 840,800L120,800ZM120,720L840,720L840,240L120,240L120,720ZM120,720L120,240L120,720Z"
+      android:fillColor="@android:color/white"/>
+  <path
+      android:pathData="M160.43,601.57L220.43,601.57L220.45,601.8L280.58,601.99L280.43,601.57L340.43,601.57L340.43,361.57L280.43,361.57L280.58,536.78L222.94,537.1L220.43,361.57L160.43,361.57L160.43,601.57Z"
+      android:fillColor="@android:color/white"/>
+</vector>
diff --git a/feature/preview/src/main/res/drawable/video_stable_auto_filled_icon.xml b/feature/preview/src/main/res/drawable/video_stable_auto_filled_icon.xml
new file mode 100644
index 0000000..fb4ae38
--- /dev/null
+++ b/feature/preview/src/main/res/drawable/video_stable_auto_filled_icon.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="960"
+    android:viewportHeight="960"
+    android:tint="#000000">
+  <path
+      android:fillColor="@android:color/white"
+      android:pathData="M633,352.02 L753.75,12h75.5L950,352.02h-71.69l-26.43,-75.56L731.13,276.45l-26.38,75.56ZM748.1,225.49h86.81L791.5,87.57ZM879.61,719.96c0,44.02 -35.98,80.04 -79.96,80.04h-639.69C115.98,800 80,763.98 80,719.96v-480.24c0,-44.02 35.98,-80.04 79.96,-80.04h352.42a283.8,283.8 0,0 0,-0.88 22.32c0,19.78 2.05,39.09 5.95,57.72L287.1,239.72l254.22,68.16c40.37,80.08 118.06,138.13 210.21,151.29l-69.83,260.78h117.94v-258.07c27.86,-0.8 54.71,-5.66 79.96,-14.03ZM672.51,719.96L184.75,589.1l93.15,-349.37L159.96,239.72v480.24Z"/>
+</vector>
diff --git a/feature/preview/src/main/res/drawable/video_stable_hq_filled_icon.xml b/feature/preview/src/main/res/drawable/video_stable_hq_filled_icon.xml
new file mode 100644
index 0000000..e09ed63
--- /dev/null
+++ b/feature/preview/src/main/res/drawable/video_stable_hq_filled_icon.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="960"
+    android:viewportHeight="960"
+    android:tint="#000000">
+  <path
+      android:fillColor="@android:color/white"
+      android:pathData="M278,240L160,240v480h180v80L160,800c-44,0 -80,-36 -80,-80v-480c0,-44 36,-80 80,-80h640c44,0 80,36 80,80v260h-59.52v-0.2L800,499.8L800,240L287.2,240l488.4,130.8 -34.58,128.99L660.48,499.79a47.13,47.13 0,0 0,-4.44 0.2L340,500v130.8L184.8,589.2ZM750,800h-30c-11.33,0 -20.83,-3.83 -28.5,-11.5 -7.67,-7.67 -11.5,-17.17 -11.5,-28.5v-160c0,-11.33 3.83,-20.83 11.5,-28.5 7.67,-7.67 17.17,-11.5 28.5,-11.5h120c11.33,0 20.83,3.83 28.5,11.5 7.67,7.67 11.5,17.17 11.5,28.5v160c0,11.33 -3.83,20.83 -11.5,28.5 -7.67,7.67 -17.17,11.5 -28.5,11.5h-30v60h-60ZM400,560h60v100h80v-100h60v240h-60v-80h-80v80h-60ZM820,740v-120h-80v120Z"/>
+</vector>
diff --git a/feature/preview/src/main/res/drawable/video_stable_ois_auto_filled_icon.xml b/feature/preview/src/main/res/drawable/video_stable_ois_auto_filled_icon.xml
new file mode 100644
index 0000000..e9a17a7
--- /dev/null
+++ b/feature/preview/src/main/res/drawable/video_stable_ois_auto_filled_icon.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="960"
+    android:viewportHeight="960"
+    android:tint="#000000">
+  <path
+      android:fillColor="@android:color/white"
+      android:pathData="M633,352.02 L753.75,12h75.5L950,352.02h-71.69l-26.43,-75.56L731.13,276.45l-26.38,75.56ZM748.1,225.49h86.81L791.5,87.57ZM880,500h-80v-38.12c27.88,-0.83 54.74,-5.74 80,-14.15ZM287.2,240l254.22,68.08c40.45,80.08 118.23,138.08 210.47,151.14L740.96,500L400,500c-11.32,0 -20.84,3.84 -28.48,11.52C363.84,519.16 360,528.68 360,540v96.16L184.8,589.2 278,240L160,240v480h200v80L160,800c-44,0 -80,-36 -80,-80v-480c0,-44 36,-80 80,-80h352.35a284.18,284.18 0,0 0,-0.85 22.01c0,19.88 2.07,39.28 6.01,57.99ZM431.52,788.48C423.84,780.84 420,771.32 420,760v-160c0,-11.32 3.84,-20.84 11.52,-28.52C439.16,563.84 448.68,560 460,560h80c11.32,0 20.84,3.84 28.52,11.48 7.64,7.68 11.48,17.2 11.48,28.52v160c0,11.32 -3.84,20.84 -11.48,28.48 -7.68,7.68 -17.2,11.52 -28.52,11.52h-80c-11.32,0 -20.84,-3.84 -28.48,-11.52ZM520,740v-120h-40v120ZM720,740h100v-36h-60c-11.32,0 -20.84,-4.52 -28.48,-13.52 -7.68,-9 -11.52,-19.16 -11.52,-30.48v-60c0,-11.32 3.84,-20.84 11.52,-28.52C739.16,563.84 748.68,560 760,560h120v60L780,620v34h60c11.32,0 20.84,4.84 28.52,14.48 7.64,9.68 11.48,20.2 11.48,31.52v60c0,11.32 -3.84,20.84 -11.48,28.48 -7.68,7.68 -17.2,11.52 -28.52,11.52L720,800ZM620,560h60v240h-60Z"/>
+</vector>
diff --git a/feature/preview/src/main/res/drawable/video_stable_ois_filled_icon.xml b/feature/preview/src/main/res/drawable/video_stable_ois_filled_icon.xml
new file mode 100644
index 0000000..9eb0f7c
--- /dev/null
+++ b/feature/preview/src/main/res/drawable/video_stable_ois_filled_icon.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2024 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="24dp"
+    android:height="24dp"
+    android:viewportWidth="960"
+    android:viewportHeight="960"
+    android:tint="#000000">
+  <path
+      android:fillColor="@android:color/white"
+      android:pathData="M880,240v260h-80v-260L287.2,240l488.4,130.8L740.96,500L400,500c-11.32,0 -20.84,3.84 -28.48,11.52C363.84,519.16 360,528.68 360,540v96.16L184.8,589.2 278,240L160,240v480h200v80L160,800c-44,0 -80,-36 -80,-80v-480c0,-44 36,-80 80,-80h640c44,0 80,36 80,80ZM431.52,788.48C423.84,780.84 420,771.32 420,760v-160c0,-11.32 3.84,-20.84 11.52,-28.52C439.16,563.84 448.68,560 460,560h80c11.32,0 20.84,3.84 28.52,11.48 7.64,7.68 11.48,17.2 11.48,28.52v160c0,11.32 -3.84,20.84 -11.48,28.48 -7.68,7.68 -17.2,11.52 -28.52,11.52h-80c-11.32,0 -20.84,-3.84 -28.48,-11.52ZM520,740v-120h-40v120h40ZM720,740h100v-36h-60c-11.32,0 -20.84,-4.52 -28.48,-13.52 -7.68,-9 -11.52,-19.16 -11.52,-30.48v-60c0,-11.32 3.84,-20.84 11.52,-28.52C739.16,563.84 748.68,560 760,560h120v60L780,620v34h60c11.32,0 20.84,4.84 28.52,14.48 7.64,9.68 11.48,20.2 11.48,31.52v60c0,11.32 -3.84,20.84 -11.48,28.48 -7.68,7.68 -17.2,11.52 -28.52,11.52L720,800v-60ZM620,560h60v240h-60v-240Z"/>
+</vector>
diff --git a/feature/preview/src/main/res/values/strings.xml b/feature/preview/src/main/res/values/strings.xml
index 77d80e0..d88a2e0 100644
--- a/feature/preview/src/main/res/values/strings.xml
+++ b/feature/preview/src/main/res/values/strings.xml
@@ -16,6 +16,10 @@
   -->
 <resources>
     <string name="camera_not_ready">Camera Loading…</string>
+
+    <string name="capture_mode_image_capture_content_description">Image capture mode</string>
+    <string name="capture_mode_video_recording_content_description">Video recording mode</string>
+
     <string name="settings_content_description">Settings</string>
     <string name="flip_camera_content_description">Flip Camera</string>
 
@@ -33,8 +37,14 @@
     <string name="toast_video_capture_external_unsupported">Video not supported while app is in image-only capture mode</string>
     <string name="toast_image_capture_external_unsupported">Image capture not supported while app is in video-only capture mode</string>
     <string name="toast_image_capture_unsupported_concurrent_camera">Image capture not supported in dual camera mode</string>
+    <string name="stabilization_icon_description_auto">Stabilization is on</string>
     <string name="stabilization_icon_description_preview_and_video">Preview is Stabilized</string>
     <string name="stabilization_icon_description_video_only">Only Video is Stabilized</string>
+    <string name="stabilization_icon_description_optical">Optical stabilization is Enabled</string>
+    <string name="video_quality_description_sd">Video quality is SD</string>
+    <string name="video_quality_description_hd">Video quality is HD</string>
+    <string name="video_quality_description_fhd">Video quality is FHD</string>
+    <string name="video_quality_description_uhd">Video quality is UHD</string>
     <string name="toast_hdr_photo_unsupported_on_device">Ultra HDR photos not supported on this device</string>
     <string name="toast_hdr_photo_unsupported_on_lens">Ultra HDR photos not supported by current lens</string>
     <string name="toast_hdr_photo_unsupported_on_lens_single_stream">Single-stream mode does not support UltraHDR photo capture for current lens</string>
@@ -64,9 +74,11 @@
     <string name="quick_settings_flash_off">OFF</string>
     <string name="quick_settings_flash_auto">AUTO</string>
     <string name="quick_settings_flash_on">ON</string>
+    <string name="quick_settings_flash_llb">LLB</string>
     <string name="quick_settings_flash_off_description">Flash off</string>
     <string name="quick_settings_flash_auto_description">Auto flash</string>
     <string name="quick_settings_flash_on_description">Flash on</string>
+    <string name="quick_settings_flash_llb_description">Low Light Boost on</string>
 
     <string name="quick_settings_capture_mode_single">Single Stream</string>
     <string name="quick_settings_capture_mode_multi">Multi Stream</string>
diff --git a/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/PreviewViewModelTest.kt b/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/PreviewViewModelTest.kt
index 2d40334..a652896 100644
--- a/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/PreviewViewModelTest.kt
+++ b/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/PreviewViewModelTest.kt
@@ -32,9 +32,12 @@ import kotlinx.coroutines.test.runTest
 import kotlinx.coroutines.test.setMain
 import org.junit.Before
 import org.junit.Test
+import org.junit.runner.RunWith
 import org.mockito.Mockito.mock
+import org.robolectric.RobolectricTestRunner
 
 @OptIn(ExperimentalCoroutinesApi::class)
+@RunWith(RobolectricTestRunner::class)
 class PreviewViewModelTest {
 
     private val cameraUseCase = FakeCameraUseCase()
@@ -70,19 +73,11 @@ class PreviewViewModelTest {
         assertThat(cameraUseCase.previewStarted).isTrue()
     }
 
-    @Test
-    fun captureImage() = runTest(StandardTestDispatcher()) {
-        previewViewModel.startCameraUntilRunning()
-        previewViewModel.captureImage()
-        advanceUntilIdle()
-        assertThat(cameraUseCase.numPicturesTaken).isEqualTo(1)
-    }
-
     @Test
     fun captureImageWithUri() = runTest(StandardTestDispatcher()) {
         val contentResolver: ContentResolver = mock()
         previewViewModel.startCameraUntilRunning()
-        previewViewModel.captureImageWithUri(contentResolver, null) {}
+        previewViewModel.captureImageWithUri(contentResolver, null) { _, _ -> }
         advanceUntilIdle()
         assertThat(cameraUseCase.numPicturesTaken).isEqualTo(1)
     }
@@ -101,6 +96,7 @@ class PreviewViewModelTest {
         previewViewModel.startVideoRecording(null, false) {}
         advanceUntilIdle()
         previewViewModel.stopVideoRecording()
+        advanceUntilIdle()
         assertThat(cameraUseCase.recordingInProgress).isFalse()
     }
 
@@ -139,11 +135,10 @@ class PreviewViewModelTest {
     }
 }
 
-private fun assertIsReady(previewUiState: PreviewUiState): PreviewUiState.Ready {
-    return when (previewUiState) {
+private fun assertIsReady(previewUiState: PreviewUiState): PreviewUiState.Ready =
+    when (previewUiState) {
         is PreviewUiState.Ready -> previewUiState
         else -> throw AssertionError(
             "PreviewUiState expected to be Ready, but was ${previewUiState::class}"
         )
     }
-}
diff --git a/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/ScreenFlashTest.kt b/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/ScreenFlashTest.kt
index 536e90e..30c17f9 100644
--- a/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/ScreenFlashTest.kt
+++ b/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/ScreenFlashTest.kt
@@ -34,9 +34,12 @@ import kotlinx.coroutines.test.runTest
 import org.junit.Before
 import org.junit.Rule
 import org.junit.Test
+import org.junit.runner.RunWith
 import org.mockito.Mockito
+import org.robolectric.RobolectricTestRunner
 
 @OptIn(ExperimentalCoroutinesApi::class)
+@RunWith(RobolectricTestRunner::class)
 class ScreenFlashTest {
     private val testScope = TestScope()
     private val testDispatcher = StandardTestDispatcher(testScope.testScheduler)
@@ -111,9 +114,8 @@ class ScreenFlashTest {
     private fun runCameraTest(testBody: suspend TestScope.() -> Unit) = runTest(testDispatcher) {
         backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
             cameraUseCase.initialize(
-                DEFAULT_CAMERA_APP_SETTINGS,
-                CameraUseCase.UseCaseMode.STANDARD
-            )
+                DEFAULT_CAMERA_APP_SETTINGS
+            ) {}
             cameraUseCase.runCamera()
         }
 
diff --git a/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/ui/ScreenFlashComponentsKtTest.kt b/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/ui/ScreenFlashComponentsKtTest.kt
deleted file mode 100644
index c90bde2..0000000
--- a/feature/preview/src/test/java/com/google/jetpackcamera/feature/preview/ui/ScreenFlashComponentsKtTest.kt
+++ /dev/null
@@ -1,133 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-package com.google.jetpackcamera.feature.preview.ui
-
-import androidx.compose.runtime.MutableState
-import androidx.compose.runtime.mutableStateOf
-import androidx.compose.ui.graphics.Color
-import androidx.compose.ui.graphics.toArgb
-import androidx.compose.ui.test.assertHeightIsAtLeast
-import androidx.compose.ui.test.assertWidthIsAtLeast
-import androidx.compose.ui.test.getBoundsInRoot
-import androidx.compose.ui.test.hasTestTag
-import androidx.compose.ui.test.junit4.createComposeRule
-import androidx.compose.ui.test.onRoot
-import androidx.compose.ui.unit.height
-import androidx.compose.ui.unit.width
-import com.google.jetpackcamera.feature.preview.ScreenFlash
-import com.google.jetpackcamera.feature.preview.rules.MainDispatcherRule
-import com.google.jetpackcamera.feature.preview.workaround.captureToImage
-import kotlinx.coroutines.ExperimentalCoroutinesApi
-import kotlinx.coroutines.test.StandardTestDispatcher
-import kotlinx.coroutines.test.TestScope
-import kotlinx.coroutines.test.advanceUntilIdle
-import kotlinx.coroutines.test.runTest
-import org.junit.Assert.assertEquals
-import org.junit.Before
-import org.junit.Rule
-import org.junit.Test
-import org.junit.runner.RunWith
-import org.robolectric.RobolectricTestRunner
-import org.robolectric.annotation.Config
-import org.robolectric.annotation.GraphicsMode
-import org.robolectric.shadows.ShadowPixelCopy
-
-// TODO: After device tests are added to github workflow, remove the tests here since they are
-//  duplicated in androidTest and fits there better
-@OptIn(ExperimentalCoroutinesApi::class)
-@RunWith(RobolectricTestRunner::class)
-class ScreenFlashComponentsKtTest {
-    private val testScope = TestScope()
-    private val testDispatcher = StandardTestDispatcher(testScope.testScheduler)
-
-    @get:Rule
-    val mainDispatcherRule = MainDispatcherRule(testDispatcher)
-
-    @get:Rule
-    val composeTestRule = createComposeRule()
-
-    private val screenFlashUiState: MutableState<ScreenFlash.ScreenFlashUiState> =
-        mutableStateOf(ScreenFlash.ScreenFlashUiState())
-
-    @Before
-    fun setUp() {
-        composeTestRule.setContent {
-            ScreenFlashScreen(
-                screenFlashUiState = screenFlashUiState.value,
-                onInitialBrightnessCalculated = {}
-            )
-        }
-    }
-
-    @Test
-    fun screenFlashOverlay_doesNotExistByDefault() = runTest {
-        advanceUntilIdle()
-        composeTestRule.onNode(hasTestTag("ScreenFlashOverlay")).assertDoesNotExist()
-    }
-
-    @Test
-    fun screenFlashOverlay_existsAfterStateIsEnabled() = runTest {
-        screenFlashUiState.value = ScreenFlash.ScreenFlashUiState(enabled = true)
-
-        advanceUntilIdle()
-        composeTestRule.onNode(hasTestTag("ScreenFlashOverlay")).assertExists()
-    }
-
-    @Test
-    fun screenFlashOverlay_doesNotExistWhenDisabledAfterEnabled() = runTest {
-        screenFlashUiState.value = ScreenFlash.ScreenFlashUiState(enabled = true)
-        screenFlashUiState.value = ScreenFlash.ScreenFlashUiState(enabled = false)
-
-        advanceUntilIdle()
-        composeTestRule.onNode(hasTestTag("ScreenFlashOverlay")).assertDoesNotExist()
-    }
-
-    @Test
-    fun screenFlashOverlay_sizeFillsMaxSize() = runTest {
-        screenFlashUiState.value = ScreenFlash.ScreenFlashUiState(enabled = true)
-
-        advanceUntilIdle()
-        val rootBounds = composeTestRule.onRoot().getBoundsInRoot()
-        composeTestRule.onNode(hasTestTag("ScreenFlashOverlay"))
-            .assertWidthIsAtLeast(rootBounds.width)
-        composeTestRule.onNode(hasTestTag("ScreenFlashOverlay"))
-            .assertHeightIsAtLeast(rootBounds.height)
-    }
-
-    @Test
-    @GraphicsMode(GraphicsMode.Mode.NATIVE)
-    @Config(shadows = [ShadowPixelCopy::class])
-    fun screenFlashOverlay_fullWhiteWhenEnabled() = runTest {
-        screenFlashUiState.value = ScreenFlash.ScreenFlashUiState(enabled = true)
-
-        advanceUntilIdle()
-        val overlayScreenShot =
-            composeTestRule.onNode(hasTestTag("ScreenFlashOverlay")).captureToImage()
-
-        // check a few pixels near center instead of whole image to save time
-        val overlayPixels = IntArray(4)
-        overlayScreenShot.readPixels(
-            overlayPixels,
-            overlayScreenShot.width / 2,
-            overlayScreenShot.height / 2,
-            2,
-            2
-        )
-        overlayPixels.forEach {
-            assertEquals(Color.White.toArgb(), it)
-        }
-    }
-}
diff --git a/feature/settings/Android.bp b/feature/settings/Android.bp
index 2e21fb8..9150900 100644
--- a/feature/settings/Android.bp
+++ b/feature/settings/Android.bp
@@ -11,6 +11,7 @@ android_library {
         "src/main/res",
     ],
     static_libs: [
+    "accompanist-permissions",
         "androidx.compose.material3_material3",
 	"androidx.compose.material_material-icons-core",
 	"androidx.compose.runtime_runtime",
diff --git a/feature/settings/build.gradle.kts b/feature/settings/build.gradle.kts
index 0be4f1b..1d227a3 100644
--- a/feature/settings/build.gradle.kts
+++ b/feature/settings/build.gradle.kts
@@ -24,7 +24,6 @@ plugins {
 android {
     namespace = "com.google.jetpackcamera.settings"
     compileSdk = libs.versions.compileSdk.get().toInt()
-    compileSdkPreview = libs.versions.compileSdkPreview.get()
 
     defaultConfig {
         minSdk = libs.versions.minSdk.get().toInt()
@@ -40,11 +39,6 @@ android {
             dimension = "flavor"
             isDefault = true
         }
-
-        create("preview") {
-            dimension = "flavor"
-            targetSdkPreview = libs.versions.targetSdkPreview.get()
-        }
     }
 
     compileOptions {
@@ -81,6 +75,7 @@ android {
 }
 
 dependencies {
+    implementation(libs.androidx.rules)
     // Compose
     val composeBom = platform(libs.compose.bom)
     implementation(composeBom)
@@ -109,6 +104,9 @@ dependencies {
 
     implementation(libs.androidx.core.ktx)
 
+    // Accompanist - Permissions
+    implementation(libs.accompanist.permissions)
+
     // Futures
     implementation(libs.futures.ktx)
 
diff --git a/feature/settings/src/androidTest/Android.bp b/feature/settings/src/androidTest/Android.bp
index 0ced4cc..8670e27 100644
--- a/feature/settings/src/androidTest/Android.bp
+++ b/feature/settings/src/androidTest/Android.bp
@@ -4,7 +4,7 @@ package {
 
 android_test {
     name: "jetpack-camera-app_feature_settings-tests",
-    team: "trendy_team_camerax",
+    team: "trendy_team_android_camera_innovation_team",
     srcs: ["java/**/*.kt"],
     static_libs: [
         "androidx.test.runner",
diff --git a/feature/settings/src/androidTest/java/com/google/jetpackcamera/settings/CameraAppSettingsViewModelTest.kt b/feature/settings/src/androidTest/java/com/google/jetpackcamera/settings/CameraAppSettingsViewModelTest.kt
index dbbc72b..fd15cf3 100644
--- a/feature/settings/src/androidTest/java/com/google/jetpackcamera/settings/CameraAppSettingsViewModelTest.kt
+++ b/feature/settings/src/androidTest/java/com/google/jetpackcamera/settings/CameraAppSettingsViewModelTest.kt
@@ -63,7 +63,10 @@ internal class CameraAppSettingsViewModelTest {
         val constraintsRepository = SettableConstraintsRepositoryImpl().apply {
             updateSystemConstraints(TYPICAL_SYSTEM_CONSTRAINTS)
         }
-        settingsViewModel = SettingsViewModel(settingsRepository, constraintsRepository)
+        settingsViewModel = SettingsViewModel(
+            settingsRepository,
+            constraintsRepository
+        )
         advanceUntilIdle()
     }
 
@@ -79,6 +82,9 @@ internal class CameraAppSettingsViewModelTest {
 
     @Test
     fun getSettingsUiState() = runTest(StandardTestDispatcher()) {
+        settingsViewModel.setGrantedPermissions(
+            mutableSetOf(android.Manifest.permission.RECORD_AUDIO)
+        )
         val uiState = settingsViewModel.settingsUiState.first {
             it is SettingsUiState.Enabled
         }
@@ -88,6 +94,52 @@ internal class CameraAppSettingsViewModelTest {
         )
     }
 
+    @Test
+    fun setMute_permission_granted() = runTest(StandardTestDispatcher()) {
+        // permission must be granted or the setting will be disabled
+        // Wait for first Enabled state
+        settingsViewModel.setGrantedPermissions(
+            mutableSetOf(android.Manifest.permission.RECORD_AUDIO)
+        )
+        val initialState = settingsViewModel.settingsUiState.first {
+            it is SettingsUiState.Enabled
+        }
+
+        val initialAudioState = assertIsEnabled(initialState).audioUiState
+        // assert that muteUiState is Enabled
+        assertThat(initialAudioState).isInstanceOf(AudioUiState.Enabled.On::class.java)
+
+        val nextAudioUiState = AudioUiState.Enabled.Mute()
+        settingsViewModel.setVideoAudio(false)
+
+        advanceUntilIdle()
+
+        assertIsEnabled(settingsViewModel.settingsUiState.value).also {
+            assertThat(it.audioUiState).isEqualTo(nextAudioUiState)
+        }
+    }
+
+    @Test
+    fun setMute_permission_not_granted() = runTest(StandardTestDispatcher()) {
+        // Wait for first Enabled state
+        val initialState = settingsViewModel.settingsUiState.first {
+            it is SettingsUiState.Enabled
+        }
+
+        val initialAudioState = assertIsEnabled(initialState).audioUiState
+        // assert that muteUiState is disabled
+        assertThat(initialAudioState).isNotInstanceOf(AudioUiState.Enabled::class.java)
+
+        settingsViewModel.setVideoAudio(false)
+
+        advanceUntilIdle()
+
+        // ensure still disabled
+        assertIsEnabled(settingsViewModel.settingsUiState.value).also {
+            assertThat(it.audioUiState).isNotInstanceOf(AudioUiState.Enabled::class.java)
+        }
+    }
+
     @Test
     fun setDefaultToFrontCamera() = runTest(StandardTestDispatcher()) {
         // Wait for first Enabled state
@@ -138,11 +190,10 @@ internal class CameraAppSettingsViewModelTest {
     }
 }
 
-private fun assertIsEnabled(settingsUiState: SettingsUiState): SettingsUiState.Enabled {
-    return when (settingsUiState) {
+private fun assertIsEnabled(settingsUiState: SettingsUiState): SettingsUiState.Enabled =
+    when (settingsUiState) {
         is SettingsUiState.Enabled -> settingsUiState
         else -> throw AssertionError(
             "SettingsUiState expected to be Enabled, but was ${settingsUiState::class}"
         )
     }
-}
diff --git a/feature/settings/src/main/AndroidManifest.xml b/feature/settings/src/main/AndroidManifest.xml
index cfecf54..f09c2b9 100644
--- a/feature/settings/src/main/AndroidManifest.xml
+++ b/feature/settings/src/main/AndroidManifest.xml
@@ -14,6 +14,10 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License.
   -->
-<manifest package="com.google.jetpackcamera.settings">
+<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.google.jetpackcamera.settings">
+    <!--
+    permission needed for test
+    -->
+    <uses-permission android:name="android.permission.RECORD_AUDIO" />
 
-</manifest>
+</manifest>
\ No newline at end of file
diff --git a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsScreen.kt b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsScreen.kt
index a3ab00e..6680cfc 100644
--- a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsScreen.kt
+++ b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsScreen.kt
@@ -15,40 +15,55 @@
  */
 package com.google.jetpackcamera.settings
 
+import android.Manifest
 import android.content.res.Configuration
 import androidx.compose.foundation.background
 import androidx.compose.foundation.layout.Column
+import androidx.compose.foundation.layout.padding
 import androidx.compose.foundation.rememberScrollState
 import androidx.compose.foundation.verticalScroll
+import androidx.compose.material3.ExperimentalMaterial3Api
 import androidx.compose.material3.MaterialTheme
+import androidx.compose.material3.Scaffold
+import androidx.compose.material3.TopAppBarDefaults
+import androidx.compose.material3.rememberTopAppBarState
 import androidx.compose.runtime.Composable
 import androidx.compose.runtime.collectAsState
 import androidx.compose.runtime.getValue
 import androidx.compose.ui.Modifier
+import androidx.compose.ui.input.nestedscroll.nestedScroll
 import androidx.compose.ui.res.stringResource
 import androidx.compose.ui.tooling.preview.Preview
 import androidx.hilt.navigation.compose.hiltViewModel
+import com.google.accompanist.permissions.ExperimentalPermissionsApi
+import com.google.accompanist.permissions.rememberMultiplePermissionsState
 import com.google.jetpackcamera.settings.model.AspectRatio
-import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.StreamConfig
+import com.google.jetpackcamera.settings.model.VideoQuality
 import com.google.jetpackcamera.settings.ui.AspectRatioSetting
-import com.google.jetpackcamera.settings.ui.CaptureModeSetting
 import com.google.jetpackcamera.settings.ui.DarkModeSetting
 import com.google.jetpackcamera.settings.ui.DefaultCameraFacing
 import com.google.jetpackcamera.settings.ui.FlashModeSetting
+import com.google.jetpackcamera.settings.ui.MaxVideoDurationSetting
+import com.google.jetpackcamera.settings.ui.RecordingAudioSetting
 import com.google.jetpackcamera.settings.ui.SectionHeader
 import com.google.jetpackcamera.settings.ui.SettingsPageHeader
 import com.google.jetpackcamera.settings.ui.StabilizationSetting
+import com.google.jetpackcamera.settings.ui.StreamConfigSetting
 import com.google.jetpackcamera.settings.ui.TargetFpsSetting
 import com.google.jetpackcamera.settings.ui.VersionInfo
+import com.google.jetpackcamera.settings.ui.VideoQualitySetting
 import com.google.jetpackcamera.settings.ui.theme.SettingsPreviewTheme
 
 /**
  * Screen used for the Settings feature.
  */
+
+@OptIn(ExperimentalPermissionsApi::class)
 @Composable
 fun SettingsScreen(
     versionInfo: VersionInfoHolder,
@@ -65,13 +80,25 @@ fun SettingsScreen(
         setFlashMode = viewModel::setFlashMode,
         setTargetFrameRate = viewModel::setTargetFrameRate,
         setAspectRatio = viewModel::setAspectRatio,
-        setCaptureMode = viewModel::setCaptureMode,
-        setVideoStabilization = viewModel::setVideoStabilization,
-        setPreviewStabilization = viewModel::setPreviewStabilization,
-        setDarkMode = viewModel::setDarkMode
+        setCaptureMode = viewModel::setStreamConfig,
+        setAudio = viewModel::setVideoAudio,
+        setStabilizationMode = viewModel::setStabilizationMode,
+        setMaxVideoDuration = viewModel::setMaxVideoDuration,
+        setDarkMode = viewModel::setDarkMode,
+        setVideoQuality = viewModel::setVideoQuality
+    )
+    val permissionStates = rememberMultiplePermissionsState(
+        permissions =
+        listOf(
+            Manifest.permission.CAMERA,
+            Manifest.permission.RECORD_AUDIO
+        )
     )
+
+    viewModel.setGrantedPermissions(permissionStates)
 }
 
+@OptIn(ExperimentalMaterial3Api::class)
 @Composable
 private fun SettingsScreen(
     uiState: SettingsUiState,
@@ -81,34 +108,50 @@ private fun SettingsScreen(
     setFlashMode: (FlashMode) -> Unit = {},
     setTargetFrameRate: (Int) -> Unit = {},
     setAspectRatio: (AspectRatio) -> Unit = {},
-    setCaptureMode: (CaptureMode) -> Unit = {},
-    setVideoStabilization: (Stabilization) -> Unit = {},
-    setPreviewStabilization: (Stabilization) -> Unit = {},
-    setDarkMode: (DarkMode) -> Unit = {}
+    setCaptureMode: (StreamConfig) -> Unit = {},
+    setStabilizationMode: (StabilizationMode) -> Unit = {},
+    setAudio: (Boolean) -> Unit = {},
+    setMaxVideoDuration: (Long) -> Unit = {},
+    setDarkMode: (DarkMode) -> Unit = {},
+    setVideoQuality: (VideoQuality) -> Unit = {}
 ) {
-    Column(
-        modifier = Modifier
-            .verticalScroll(rememberScrollState())
-            .background(color = MaterialTheme.colorScheme.background)
-    ) {
-        SettingsPageHeader(
-            title = stringResource(id = R.string.settings_title),
-            navBack = onNavigateBack
-        )
-        if (uiState is SettingsUiState.Enabled) {
-            SettingsList(
-                uiState = uiState,
-                versionInfo = versionInfo,
-                setDefaultLensFacing = setDefaultLensFacing,
-                setFlashMode = setFlashMode,
-                setTargetFrameRate = setTargetFrameRate,
-                setAspectRatio = setAspectRatio,
-                setCaptureMode = setCaptureMode,
-                setVideoStabilization = setVideoStabilization,
-                setPreviewStabilization = setPreviewStabilization,
-                setDarkMode = setDarkMode
+    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(
+        rememberTopAppBarState()
+    )
+
+    Scaffold(
+        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
+        topBar = {
+            SettingsPageHeader(
+                title = stringResource(id = R.string.settings_title),
+                navBack = onNavigateBack,
+                scrollBehavior = scrollBehavior
             )
         }
+    ) { innerPadding ->
+        Column(
+            modifier = Modifier
+                .padding(innerPadding)
+                .verticalScroll(rememberScrollState())
+                .background(color = MaterialTheme.colorScheme.background)
+        ) {
+            if (uiState is SettingsUiState.Enabled) {
+                SettingsList(
+                    uiState = uiState,
+                    versionInfo = versionInfo,
+                    setDefaultLensFacing = setDefaultLensFacing,
+                    setFlashMode = setFlashMode,
+                    setTargetFrameRate = setTargetFrameRate,
+                    setAspectRatio = setAspectRatio,
+                    setCaptureMode = setCaptureMode,
+                    setStabilizationMode = setStabilizationMode,
+                    setAudio = setAudio,
+                    setMaxVideoDuration = setMaxVideoDuration,
+                    setDarkMode = setDarkMode,
+                    setVideoQuality = setVideoQuality
+                )
+            }
+        }
     }
 }
 
@@ -120,9 +163,11 @@ fun SettingsList(
     setFlashMode: (FlashMode) -> Unit = {},
     setTargetFrameRate: (Int) -> Unit = {},
     setAspectRatio: (AspectRatio) -> Unit = {},
-    setCaptureMode: (CaptureMode) -> Unit = {},
-    setVideoStabilization: (Stabilization) -> Unit = {},
-    setPreviewStabilization: (Stabilization) -> Unit = {},
+    setCaptureMode: (StreamConfig) -> Unit = {},
+    setAudio: (Boolean) -> Unit = {},
+    setStabilizationMode: (StabilizationMode) -> Unit = {},
+    setVideoQuality: (VideoQuality) -> Unit = {},
+    setMaxVideoDuration: (Long) -> Unit = {},
     setDarkMode: (DarkMode) -> Unit = {}
 ) {
     SectionHeader(title = stringResource(id = R.string.section_title_camera_settings))
@@ -147,15 +192,31 @@ fun SettingsList(
         setAspectRatio = setAspectRatio
     )
 
-    CaptureModeSetting(
-        captureModeUiState = uiState.captureModeUiState,
-        setCaptureMode = setCaptureMode
+    StreamConfigSetting(
+        streamConfigUiState = uiState.streamConfigUiState,
+        setStreamConfig = setCaptureMode
+    )
+
+    SectionHeader(title = stringResource(R.string.section_title_recording_settings))
+
+    RecordingAudioSetting(
+        audioUiState = uiState.audioUiState,
+        setDefaultAudio = setAudio
+    )
+
+    MaxVideoDurationSetting(
+        maxVideoDurationUiState = uiState.maxVideoDurationUiState,
+        setMaxDuration = setMaxVideoDuration
     )
 
     StabilizationSetting(
         stabilizationUiState = uiState.stabilizationUiState,
-        setVideoStabilization = setVideoStabilization,
-        setPreviewStabilization = setPreviewStabilization
+        setStabilizationMode = setStabilizationMode
+    )
+
+    VideoQualitySetting(
+        videQualityUiState = uiState.videoQualityUiState,
+        setVideoQuality = setVideoQuality
     )
 
     SectionHeader(title = stringResource(id = R.string.section_title_app_settings))
@@ -175,10 +236,7 @@ fun SettingsList(
 
 // will allow you to open stabilization popup or give disabled rationale
 
-data class VersionInfoHolder(
-    val versionName: String,
-    val buildType: String
-)
+data class VersionInfoHolder(val versionName: String, val buildType: String)
 
 @Preview(name = "Light Mode")
 @Preview(name = "Dark Mode", uiMode = Configuration.UI_MODE_NIGHT_YES)
diff --git a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsUiState.kt b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsUiState.kt
index 7f882c3..92b8aca 100644
--- a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsUiState.kt
+++ b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsUiState.kt
@@ -18,16 +18,26 @@ package com.google.jetpackcamera.settings
 import com.google.jetpackcamera.settings.DisabledRationale.DeviceUnsupportedRationale
 import com.google.jetpackcamera.settings.DisabledRationale.LensUnsupportedRationale
 import com.google.jetpackcamera.settings.model.AspectRatio
-import com.google.jetpackcamera.settings.model.CaptureMode
 import com.google.jetpackcamera.settings.model.DEFAULT_CAMERA_APP_SETTINGS
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.StreamConfig
+import com.google.jetpackcamera.settings.model.VideoQuality
 import com.google.jetpackcamera.settings.ui.DEVICE_UNSUPPORTED_TAG
 import com.google.jetpackcamera.settings.ui.FPS_UNSUPPORTED_TAG
 import com.google.jetpackcamera.settings.ui.LENS_UNSUPPORTED_TAG
+import com.google.jetpackcamera.settings.ui.PERMISSION_RECORD_AUDIO_NOT_GRANTED_TAG
 import com.google.jetpackcamera.settings.ui.STABILIZATION_UNSUPPORTED_TAG
+import com.google.jetpackcamera.settings.ui.VIDEO_QUALITY_UNSUPPORTED_TAG
+
+// seconds duration in millis
+const val UNLIMITED_VIDEO_DURATION = 0L
+const val FIVE_SECONDS_DURATION = 5_000L
+const val TEN_SECONDS_DURATION = 10_000L
+const val THIRTY_SECONDS_DURATION = 30_000L
+const val SIXTY_SECONDS_DURATION = 60_000L
 
 /**
  * Defines the current state of the [SettingsScreen].
@@ -36,12 +46,15 @@ sealed interface SettingsUiState {
     data object Disabled : SettingsUiState
     data class Enabled(
         val aspectRatioUiState: AspectRatioUiState,
-        val captureModeUiState: CaptureModeUiState,
+        val streamConfigUiState: StreamConfigUiState,
         val darkModeUiState: DarkModeUiState,
         val flashUiState: FlashUiState,
         val fpsUiState: FpsUiState,
         val lensFlipUiState: FlipLensUiState,
-        val stabilizationUiState: StabilizationUiState
+        val stabilizationUiState: StabilizationUiState,
+        val maxVideoDurationUiState: MaxVideoDurationUiState.Enabled,
+        val videoQualityUiState: VideoQualityUiState,
+        val audioUiState: AudioUiState
     ) : SettingsUiState
 }
 
@@ -58,6 +71,13 @@ sealed interface DisabledRationale {
     val reasonTextResId: Int
     val testTag: String
 
+    data class PermissionRecordAudioNotGrantedRationale(
+        override val affectedSettingNameResId: Int
+    ) : DisabledRationale {
+        override val reasonTextResId: Int = R.string.permission_record_audio_unsupported
+        override val testTag = PERMISSION_RECORD_AUDIO_NOT_GRANTED_TAG
+    }
+
     /**
      * Text will be [affectedSettingNameResId] is [R.string.device_unsupported]
      */
@@ -81,6 +101,14 @@ sealed interface DisabledRationale {
         override val testTag = STABILIZATION_UNSUPPORTED_TAG
     }
 
+    data class VideoQualityUnsupportedRationale(
+        override val affectedSettingNameResId: Int,
+        val currentDynamicRange: Int = R.string.video_quality_rationale_suffix_default
+    ) : DisabledRationale {
+        override val reasonTextResId = R.string.video_quality_unsupported
+        override val testTag = VIDEO_QUALITY_UNSUPPORTED_TAG
+    }
+
     sealed interface LensUnsupportedRationale : DisabledRationale {
         data class FrontLensUnsupportedRationale(override val affectedSettingNameResId: Int) :
             LensUnsupportedRationale {
@@ -99,19 +127,21 @@ sealed interface DisabledRationale {
 fun getLensUnsupportedRationale(
     lensFacing: LensFacing,
     affectedSettingNameResId: Int
-): LensUnsupportedRationale {
-    return when (lensFacing) {
-        LensFacing.BACK -> LensUnsupportedRationale.RearLensUnsupportedRationale(
-            affectedSettingNameResId
-        )
+): LensUnsupportedRationale = when (lensFacing) {
+    LensFacing.BACK -> LensUnsupportedRationale.RearLensUnsupportedRationale(
+        affectedSettingNameResId
+    )
 
-        LensFacing.FRONT -> LensUnsupportedRationale.FrontLensUnsupportedRationale(
-            affectedSettingNameResId
-        )
-    }
+    LensFacing.FRONT -> LensUnsupportedRationale.FrontLensUnsupportedRationale(
+        affectedSettingNameResId
+    )
 }
 
-/* Settings that currently have constraints **/
+// ////////////////////////////////////////////////////////////
+//
+// Settings that currently depend on constraints
+//
+// ////////////////////////////////////////////////////////////
 
 sealed interface FpsUiState {
     data class Enabled(
@@ -131,9 +161,7 @@ sealed interface FpsUiState {
 sealed interface FlipLensUiState {
     val currentLensFacing: LensFacing
 
-    data class Enabled(
-        override val currentLensFacing: LensFacing
-    ) : FlipLensUiState
+    data class Enabled(override val currentLensFacing: LensFacing) : FlipLensUiState
 
     data class Disabled(
         override val currentLensFacing: LensFacing,
@@ -143,10 +171,11 @@ sealed interface FlipLensUiState {
 
 sealed interface StabilizationUiState {
     data class Enabled(
-        val currentPreviewStabilization: Stabilization,
-        val currentVideoStabilization: Stabilization,
+        val currentStabilizationMode: StabilizationMode,
+        val stabilizationAutoState: SingleSelectableState,
         val stabilizationOnState: SingleSelectableState,
         val stabilizationHighQualityState: SingleSelectableState,
+        val stabilizationOpticalState: SingleSelectableState,
         // Contains text like "Selected stabilization mode only supported by rear lens"
         val additionalContext: String = ""
     ) : StabilizationUiState
@@ -155,35 +184,76 @@ sealed interface StabilizationUiState {
     data class Disabled(val disabledRationale: DisabledRationale) : StabilizationUiState
 }
 
-/* Settings that don't currently depend on constraints */
+sealed interface AudioUiState {
+
+    sealed interface Enabled : AudioUiState {
+        val additionalContext: String
+
+        data class On(override val additionalContext: String = "") : Enabled
+        data class Mute(override val additionalContext: String = "") : Enabled
+    }
+
+    data class Disabled(val disabledRationale: DisabledRationale) : AudioUiState
+}
 
-// this could be constrained w/ a check to see if a torch is available?
 sealed interface FlashUiState {
     data class Enabled(
         val currentFlashMode: FlashMode,
+        val onSelectableState: SingleSelectableState,
+        val autoSelectableState: SingleSelectableState,
+        val lowLightSelectableState: SingleSelectableState,
         val additionalContext: String = ""
     ) : FlashUiState
+
+    data class Disabled(val disabledRationale: DisabledRationale) : FlashUiState
 }
 
+// ////////////////////////////////////////////////////////////
+//
+// Settings that DON'T currently depend on constraints
+//
+// ////////////////////////////////////////////////////////////
+
 sealed interface AspectRatioUiState {
-    data class Enabled(
-        val currentAspectRatio: AspectRatio,
-        val additionalContext: String = ""
-    ) : AspectRatioUiState
+    data class Enabled(val currentAspectRatio: AspectRatio, val additionalContext: String = "") :
+        AspectRatioUiState
 }
 
-sealed interface CaptureModeUiState {
-    data class Enabled(
-        val currentCaptureMode: CaptureMode,
-        val additionalContext: String = ""
-    ) : CaptureModeUiState
+sealed interface StreamConfigUiState {
+    data class Enabled(val currentStreamConfig: StreamConfig, val additionalContext: String = "") :
+        StreamConfigUiState
 }
 
 sealed interface DarkModeUiState {
+    data class Enabled(val currentDarkMode: DarkMode, val additionalContext: String = "") :
+        DarkModeUiState
+}
+
+sealed interface MaxVideoDurationUiState {
+    data class Enabled(val currentMaxDurationMillis: Long, val additionalContext: String = "") :
+        MaxVideoDurationUiState
+}
+
+sealed interface VideoQualityUiState {
     data class Enabled(
-        val currentDarkMode: DarkMode,
-        val additionalContext: String = ""
-    ) : DarkModeUiState
+        val currentVideoQuality: VideoQuality,
+        val videoQualityAutoState: SingleSelectableState,
+        val videoQualitySDState: SingleSelectableState,
+        val videoQualityHDState: SingleSelectableState,
+        val videoQualityFHDState: SingleSelectableState,
+        val videoQualityUHDState: SingleSelectableState
+    ) : VideoQualityUiState {
+        fun getSelectableState(videoQuality: VideoQuality): SingleSelectableState =
+            when (videoQuality) {
+                VideoQuality.UNSPECIFIED -> this.videoQualityAutoState
+                VideoQuality.SD -> this.videoQualitySDState
+                VideoQuality.HD -> this.videoQualityHDState
+                VideoQuality.FHD -> this.videoQualityFHDState
+                VideoQuality.UHD -> this.videoQualityUHDState
+            }
+    }
+
+    data class Disabled(val disabledRationale: DisabledRationale) : VideoQualityUiState
 }
 
 /**
@@ -192,10 +262,22 @@ sealed interface DarkModeUiState {
  */
 val TYPICAL_SETTINGS_UISTATE = SettingsUiState.Enabled(
     aspectRatioUiState = AspectRatioUiState.Enabled(DEFAULT_CAMERA_APP_SETTINGS.aspectRatio),
-    captureModeUiState = CaptureModeUiState.Enabled(DEFAULT_CAMERA_APP_SETTINGS.captureMode),
+    streamConfigUiState = StreamConfigUiState.Enabled(DEFAULT_CAMERA_APP_SETTINGS.streamConfig),
     darkModeUiState = DarkModeUiState.Enabled(DEFAULT_CAMERA_APP_SETTINGS.darkMode),
+    audioUiState = if (DEFAULT_CAMERA_APP_SETTINGS.audioEnabled) {
+        AudioUiState.Enabled.On()
+    } else {
+        AudioUiState.Enabled.Mute()
+    },
     flashUiState =
-    FlashUiState.Enabled(currentFlashMode = DEFAULT_CAMERA_APP_SETTINGS.flashMode),
+    FlashUiState.Enabled(
+        currentFlashMode = DEFAULT_CAMERA_APP_SETTINGS.flashMode,
+        autoSelectableState = SingleSelectableState.Selectable,
+        onSelectableState = SingleSelectableState.Selectable,
+        lowLightSelectableState = SingleSelectableState.Disabled(
+            DeviceUnsupportedRationale(R.string.flash_llb_rationale_prefix)
+        )
+    ),
     fpsUiState = FpsUiState.Enabled(
         currentSelection = DEFAULT_CAMERA_APP_SETTINGS.targetFrameRate,
         fpsAutoState = SingleSelectableState.Selectable,
@@ -206,8 +288,12 @@ val TYPICAL_SETTINGS_UISTATE = SettingsUiState.Enabled(
         )
     ),
     lensFlipUiState = FlipLensUiState.Enabled(DEFAULT_CAMERA_APP_SETTINGS.cameraLensFacing),
+    maxVideoDurationUiState = MaxVideoDurationUiState.Enabled(UNLIMITED_VIDEO_DURATION),
     stabilizationUiState =
     StabilizationUiState.Disabled(
         DeviceUnsupportedRationale(R.string.stabilization_rationale_prefix)
+    ),
+    videoQualityUiState = VideoQualityUiState.Disabled(
+        DisabledRationale.VideoQualityUnsupportedRationale(R.string.video_quality_rationale_prefix)
     )
 )
diff --git a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsViewModel.kt b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsViewModel.kt
index 43e7a50..02fbdd8 100644
--- a/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsViewModel.kt
+++ b/feature/settings/src/main/java/com/google/jetpackcamera/settings/SettingsViewModel.kt
@@ -15,32 +15,42 @@
  */
 package com.google.jetpackcamera.settings
 
+import android.Manifest
 import android.util.Log
 import androidx.lifecycle.ViewModel
 import androidx.lifecycle.viewModelScope
+import com.google.accompanist.permissions.ExperimentalPermissionsApi
+import com.google.accompanist.permissions.MultiplePermissionsState
+import com.google.accompanist.permissions.isGranted
 import com.google.jetpackcamera.settings.DisabledRationale.DeviceUnsupportedRationale
 import com.google.jetpackcamera.settings.DisabledRationale.FpsUnsupportedRationale
 import com.google.jetpackcamera.settings.DisabledRationale.StabilizationUnsupportedRationale
 import com.google.jetpackcamera.settings.model.AspectRatio
 import com.google.jetpackcamera.settings.model.CameraAppSettings
-import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.CameraConstraints
+import com.google.jetpackcamera.settings.model.CameraConstraints.Companion.FPS_15
+import com.google.jetpackcamera.settings.model.CameraConstraints.Companion.FPS_30
+import com.google.jetpackcamera.settings.model.CameraConstraints.Companion.FPS_60
+import com.google.jetpackcamera.settings.model.CameraConstraints.Companion.FPS_AUTO
 import com.google.jetpackcamera.settings.model.DarkMode
+import com.google.jetpackcamera.settings.model.DynamicRange
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.Stabilization
-import com.google.jetpackcamera.settings.model.SupportedStabilizationMode
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.StreamConfig
 import com.google.jetpackcamera.settings.model.SystemConstraints
-import com.google.jetpackcamera.settings.ui.FPS_15
-import com.google.jetpackcamera.settings.ui.FPS_30
-import com.google.jetpackcamera.settings.ui.FPS_60
-import com.google.jetpackcamera.settings.ui.FPS_AUTO
+import com.google.jetpackcamera.settings.model.VideoQuality
+import com.google.jetpackcamera.settings.model.forCurrentLens
+import com.google.jetpackcamera.settings.model.forDevice
 import dagger.hilt.android.lifecycle.HiltViewModel
 import javax.inject.Inject
+import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.SharingStarted
 import kotlinx.coroutines.flow.StateFlow
 import kotlinx.coroutines.flow.combine
 import kotlinx.coroutines.flow.filterNotNull
 import kotlinx.coroutines.flow.stateIn
+import kotlinx.coroutines.flow.update
 import kotlinx.coroutines.launch
 
 private const val TAG = "SettingsViewModel"
@@ -54,21 +64,31 @@ class SettingsViewModel @Inject constructor(
     private val settingsRepository: SettingsRepository,
     constraintsRepository: ConstraintsRepository
 ) : ViewModel() {
+    private var grantedPermissions = MutableStateFlow<Set<String>>(emptySet())
 
     val settingsUiState: StateFlow<SettingsUiState> =
         combine(
             settingsRepository.defaultCameraAppSettings,
-            constraintsRepository.systemConstraints.filterNotNull()
-        ) { updatedSettings, constraints ->
+            constraintsRepository.systemConstraints.filterNotNull(),
+            grantedPermissions
+        ) { updatedSettings, constraints, grantedPerms ->
+            updatedSettings.videoQuality
             SettingsUiState.Enabled(
                 aspectRatioUiState = AspectRatioUiState.Enabled(updatedSettings.aspectRatio),
-                captureModeUiState = CaptureModeUiState.Enabled(updatedSettings.captureMode),
+                streamConfigUiState = StreamConfigUiState.Enabled(updatedSettings.streamConfig),
+                maxVideoDurationUiState = MaxVideoDurationUiState.Enabled(
+                    updatedSettings.maxVideoDurationMillis
+                ),
+                flashUiState = getFlashUiState(updatedSettings, constraints),
                 darkModeUiState = DarkModeUiState.Enabled(updatedSettings.darkMode),
-                flashUiState = FlashUiState.Enabled(updatedSettings.flashMode),
+                audioUiState = getAudioUiState(
+                    updatedSettings.audioEnabled,
+                    grantedPerms.contains(Manifest.permission.RECORD_AUDIO)
+                ),
                 fpsUiState = getFpsUiState(constraints, updatedSettings),
                 lensFlipUiState = getLensFlipUiState(constraints, updatedSettings),
-                stabilizationUiState = getStabilizationUiState(constraints, updatedSettings)
-
+                stabilizationUiState = getStabilizationUiState(constraints, updatedSettings),
+                videoQualityUiState = getVideoQualityUiState(constraints, updatedSettings)
             )
         }.stateIn(
             scope = viewModelScope,
@@ -76,115 +96,246 @@ class SettingsViewModel @Inject constructor(
             initialValue = SettingsUiState.Disabled
         )
 
-    private fun getStabilizationUiState(
-        systemConstraints: SystemConstraints,
-        cameraAppSettings: CameraAppSettings
-    ): StabilizationUiState {
-        val deviceStabilizations: Set<SupportedStabilizationMode> =
-            systemConstraints
-                .perLensConstraints[cameraAppSettings.cameraLensFacing]
-                ?.supportedStabilizationModes
-                ?: emptySet()
-
-        // if no lens supports
-        if (deviceStabilizations.isEmpty()) {
-            return StabilizationUiState.Disabled(
-                DeviceUnsupportedRationale(
-                    R.string.stabilization_rationale_prefix
+// ////////////////////////////////////////////////////////////
+//
+// Get UiStates for components
+//
+// ////////////////////////////////////////////////////////////
+
+    private fun getFlashUiState(
+        cameraAppSettings: CameraAppSettings,
+        constraints: SystemConstraints
+    ): FlashUiState {
+        val currentSupportedFlashModes =
+            constraints.forCurrentLens(cameraAppSettings)?.supportedFlashModes ?: emptySet()
+
+        check(currentSupportedFlashModes.isNotEmpty()) {
+            "No flash modes supported. Should at least support OFF."
+        }
+        val deviceSupportedFlashModes: Set<FlashMode> = constraints.forDevice(
+            CameraConstraints::supportedFlashModes
+        )
+        // disable entire setting when:git status
+        //  device only supports off... device unsupported rationale
+        //  lens only supports off... lens unsupported rationale
+        if (deviceSupportedFlashModes == setOf(FlashMode.OFF)) {
+            return FlashUiState.Disabled(
+                DeviceUnsupportedRationale(R.string.flash_rationale_prefix)
+            )
+        } else if (deviceSupportedFlashModes == setOf(FlashMode.OFF)) {
+            return FlashUiState.Disabled(
+                getLensUnsupportedRationale(
+                    cameraAppSettings.cameraLensFacing,
+                    R.string.flash_rationale_prefix
                 )
             )
         }
 
-        // if a lens supports but it isn't the current
-        if (systemConstraints.perLensConstraints[cameraAppSettings.cameraLensFacing]
-                ?.supportedStabilizationModes?.isEmpty() == true
-        ) {
-            return StabilizationUiState.Disabled(
+        // if options besides off are available for this lens...
+        val onSelectableState = if (currentSupportedFlashModes.contains(FlashMode.ON)) {
+            SingleSelectableState.Selectable
+        } else if (deviceSupportedFlashModes.contains(FlashMode.ON)) {
+            SingleSelectableState.Disabled(
                 getLensUnsupportedRationale(
                     cameraAppSettings.cameraLensFacing,
-                    R.string.stabilization_rationale_prefix
+                    affectedSettingNameResId = R.string.flash_on_rationale_prefix
                 )
             )
+        } else {
+            SingleSelectableState.Disabled(
+                DeviceUnsupportedRationale(R.string.flash_on_rationale_prefix)
+            )
         }
 
-        // if fps is too high for any stabilization
-        if (cameraAppSettings.targetFrameRate >= TARGET_FPS_60) {
-            return StabilizationUiState.Disabled(
-                FpsUnsupportedRationale(
-                    R.string.stabilization_rationale_prefix,
-                    FPS_60
+        val autoSelectableState = if (currentSupportedFlashModes.contains(FlashMode.AUTO)) {
+            SingleSelectableState.Selectable
+        } else if (deviceSupportedFlashModes.contains(FlashMode.AUTO)) {
+            SingleSelectableState.Disabled(
+                getLensUnsupportedRationale(
+                    cameraAppSettings.cameraLensFacing,
+                    affectedSettingNameResId = R.string.flash_auto_rationale_prefix
                 )
             )
+        } else {
+            SingleSelectableState.Disabled(
+                DeviceUnsupportedRationale(R.string.flash_auto_rationale_prefix)
+            )
         }
 
-        return StabilizationUiState.Enabled(
-            currentPreviewStabilization = cameraAppSettings.previewStabilization,
-            currentVideoStabilization = cameraAppSettings.videoCaptureStabilization,
-            stabilizationOnState = getPreviewStabilizationState(
-                currentFrameRate = cameraAppSettings.targetFrameRate,
-                defaultLensFacing = cameraAppSettings.cameraLensFacing,
-                deviceStabilizations = deviceStabilizations,
-                currentLensStabilizations = systemConstraints
-                    .perLensConstraints[cameraAppSettings.cameraLensFacing]
-                    ?.supportedStabilizationModes
-            ),
-            stabilizationHighQualityState =
-            getVideoStabilizationState(
-                currentFrameRate = cameraAppSettings.targetFrameRate,
-                deviceStabilizations = deviceStabilizations,
-                defaultLensFacing = cameraAppSettings.cameraLensFacing,
-                currentLensStabilizations = systemConstraints
-                    .perLensConstraints[cameraAppSettings.cameraLensFacing]
-                    ?.supportedStabilizationModes
-            )
+        // check if llb constraints:
+        // llb must be supported by device
+        val llbSelectableState =
+            if (!currentSupportedFlashModes.contains(FlashMode.LOW_LIGHT_BOOST)) {
+                SingleSelectableState.Disabled(
+                    DeviceUnsupportedRationale(R.string.flash_llb_rationale_prefix)
+                )
+            } // llb unsupported above 30fps
+            else if (cameraAppSettings.targetFrameRate > FPS_30) {
+                SingleSelectableState.Disabled(
+                    FpsUnsupportedRationale(
+                        R.string.flash_llb_rationale_prefix,
+                        cameraAppSettings.targetFrameRate
+                    )
+                )
+            } else {
+                SingleSelectableState.Selectable
+            }
+
+        return FlashUiState.Enabled(
+            currentFlashMode = cameraAppSettings.flashMode,
+            onSelectableState = onSelectableState,
+            autoSelectableState = autoSelectableState,
+            lowLightSelectableState = llbSelectableState
         )
     }
 
-    private fun getPreviewStabilizationState(
-        currentFrameRate: Int,
-        defaultLensFacing: LensFacing,
-        deviceStabilizations: Set<SupportedStabilizationMode>,
-        currentLensStabilizations: Set<SupportedStabilizationMode>?
-    ): SingleSelectableState {
-        // if unsupported by device
-        if (!deviceStabilizations.contains(SupportedStabilizationMode.ON)) {
-            return SingleSelectableState.Disabled(
-                disabledRationale =
-                DeviceUnsupportedRationale(R.string.stabilization_rationale_prefix)
+    private fun getAudioUiState(isAudioEnabled: Boolean, permissionGranted: Boolean): AudioUiState =
+        if (permissionGranted) {
+            if (isAudioEnabled) {
+                AudioUiState.Enabled.On()
+            } else {
+                AudioUiState.Enabled.Mute()
+            }
+        } else {
+            AudioUiState.Disabled(
+                DisabledRationale
+                    .PermissionRecordAudioNotGrantedRationale(
+                        R.string.mute_audio_rationale_prefix
+                    )
             )
         }
 
-        // if unsupported by by current lens
-        if (currentLensStabilizations?.contains(SupportedStabilizationMode.ON) == false) {
-            return SingleSelectableState.Disabled(
-                getLensUnsupportedRationale(
-                    defaultLensFacing,
+    @OptIn(ExperimentalPermissionsApi::class)
+    fun setGrantedPermissions(multiplePermissionsState: MultiplePermissionsState) {
+        val permissions = mutableSetOf<String>()
+        for (permissionState in multiplePermissionsState.permissions) {
+            if (permissionState.status.isGranted) {
+                permissions.add(permissionState.permission)
+            }
+        }
+        grantedPermissions.update {
+            permissions
+        }
+    }
+
+    fun setGrantedPermissions(permissions: MutableSet<String>) {
+        grantedPermissions.update { permissions }
+    }
+
+    private fun getStabilizationUiState(
+        systemConstraints: SystemConstraints,
+        cameraAppSettings: CameraAppSettings
+    ): StabilizationUiState {
+        val deviceStabilizations: Set<StabilizationMode> =
+            systemConstraints
+                .perLensConstraints.values
+                .asSequence()
+                .flatMap { it.supportedStabilizationModes }
+                .toSet()
+
+        fun supportsStabilization(stabilizationModes: Collection<StabilizationMode>): Boolean =
+            stabilizationModes.isNotEmpty() &&
+                stabilizationModes.toSet() != setOf(StabilizationMode.OFF)
+
+        // if no lens supports stabilization
+        if (!supportsStabilization(deviceStabilizations)) {
+            return StabilizationUiState.Disabled(
+                DeviceUnsupportedRationale(
                     R.string.stabilization_rationale_prefix
                 )
             )
         }
 
-        // if fps is unsupported by preview stabilization
-        if (currentFrameRate == TARGET_FPS_60 || currentFrameRate == TARGET_FPS_15) {
-            return SingleSelectableState.Disabled(
-                FpsUnsupportedRationale(
-                    R.string.stabilization_rationale_prefix,
-                    currentFrameRate
+        // if a lens supports any stabilization but it isn't the current
+        val currentLensConstraints = checkNotNull(
+            systemConstraints.forCurrentLens(cameraAppSettings)
+        ) {
+            "Lens constraints for ${cameraAppSettings.cameraLensFacing} not available."
+        }
+
+        with(currentLensConstraints) {
+            supportedStabilizationModes.let {
+                if (!supportsStabilization(it)) {
+                    return StabilizationUiState.Disabled(
+                        getLensUnsupportedRationale(
+                            cameraAppSettings.cameraLensFacing,
+                            R.string.stabilization_rationale_prefix
+                        )
+                    )
+                }
+            }
+
+            // if fps is too high for any stabilization
+            val maxCommonUnsupportedFps = currentLensConstraints.unsupportedStabilizationFpsMap
+                .asSequence()
+                .filter {
+                    it.key != StabilizationMode.AUTO &&
+                        it.key != StabilizationMode.OFF &&
+                        it.key in currentLensConstraints.supportedStabilizationModes
+                }
+                .map { it.value }
+                .reduceOrNull { acc, additionalUnsupported -> additionalUnsupported intersect acc }
+                ?.maxOrNull()
+
+            if (maxCommonUnsupportedFps != null &&
+                maxCommonUnsupportedFps <= cameraAppSettings.targetFrameRate
+            ) {
+                return StabilizationUiState.Disabled(
+                    FpsUnsupportedRationale(
+                        R.string.stabilization_rationale_prefix,
+                        maxCommonUnsupportedFps
+                    )
+                )
+            }
+
+            return StabilizationUiState.Enabled(
+                currentStabilizationMode = cameraAppSettings.stabilizationMode,
+                stabilizationAutoState = getSingleStabilizationState(
+                    stabilizationMode = StabilizationMode.AUTO,
+                    currentFrameRate = cameraAppSettings.targetFrameRate,
+                    defaultLensFacing = cameraAppSettings.cameraLensFacing,
+                    deviceStabilizations = deviceStabilizations,
+                    currentLensStabilizations = supportedStabilizationModes,
+                    unsupportedFrameRates = StabilizationMode.AUTO.unsupportedFpsSet
+                ),
+                stabilizationOnState = getSingleStabilizationState(
+                    stabilizationMode = StabilizationMode.ON,
+                    currentFrameRate = cameraAppSettings.targetFrameRate,
+                    defaultLensFacing = cameraAppSettings.cameraLensFacing,
+                    deviceStabilizations = deviceStabilizations,
+                    currentLensStabilizations = supportedStabilizationModes,
+                    unsupportedFrameRates = StabilizationMode.ON.unsupportedFpsSet
+                ),
+                stabilizationHighQualityState = getSingleStabilizationState(
+                    stabilizationMode = StabilizationMode.HIGH_QUALITY,
+                    currentFrameRate = cameraAppSettings.targetFrameRate,
+                    defaultLensFacing = cameraAppSettings.cameraLensFacing,
+                    deviceStabilizations = deviceStabilizations,
+                    currentLensStabilizations = supportedStabilizationModes,
+                    unsupportedFrameRates = StabilizationMode.HIGH_QUALITY.unsupportedFpsSet
+                ),
+                stabilizationOpticalState = getSingleStabilizationState(
+                    stabilizationMode = StabilizationMode.OPTICAL,
+                    currentFrameRate = cameraAppSettings.targetFrameRate,
+                    defaultLensFacing = cameraAppSettings.cameraLensFacing,
+                    deviceStabilizations = deviceStabilizations,
+                    currentLensStabilizations = supportedStabilizationModes,
+                    unsupportedFrameRates = StabilizationMode.OPTICAL.unsupportedFpsSet
                 )
             )
         }
-
-        return SingleSelectableState.Selectable
     }
 
-    private fun getVideoStabilizationState(
+    private fun getSingleStabilizationState(
+        stabilizationMode: StabilizationMode,
         currentFrameRate: Int,
         defaultLensFacing: LensFacing,
-        deviceStabilizations: Set<SupportedStabilizationMode>,
-        currentLensStabilizations: Set<SupportedStabilizationMode>?
+        deviceStabilizations: Set<StabilizationMode>,
+        currentLensStabilizations: Set<StabilizationMode>?,
+        unsupportedFrameRates: Set<Int>
     ): SingleSelectableState {
         // if unsupported by device
-        if (!deviceStabilizations.contains(SupportedStabilizationMode.ON)) {
+        if (!deviceStabilizations.contains(stabilizationMode)) {
             return SingleSelectableState.Disabled(
                 disabledRationale =
                 DeviceUnsupportedRationale(R.string.stabilization_rationale_prefix)
@@ -192,7 +343,7 @@ class SettingsViewModel @Inject constructor(
         }
 
         // if unsupported by by current lens
-        if (currentLensStabilizations?.contains(SupportedStabilizationMode.HIGH_QUALITY) == false) {
+        if (currentLensStabilizations?.contains(stabilizationMode) == false) {
             return SingleSelectableState.Disabled(
                 getLensUnsupportedRationale(
                     defaultLensFacing,
@@ -200,8 +351,9 @@ class SettingsViewModel @Inject constructor(
                 )
             )
         }
+
         // if fps is unsupported by preview stabilization
-        if (currentFrameRate == TARGET_FPS_60) {
+        if (currentFrameRate in unsupportedFrameRates) {
             return SingleSelectableState.Disabled(
                 FpsUnsupportedRationale(
                     R.string.stabilization_rationale_prefix,
@@ -213,6 +365,59 @@ class SettingsViewModel @Inject constructor(
         return SingleSelectableState.Selectable
     }
 
+    private fun getVideoQualityUiState(
+        systemConstraints: SystemConstraints,
+        cameraAppSettings: CameraAppSettings
+    ): VideoQualityUiState {
+        val cameraConstraints = systemConstraints.forCurrentLens(cameraAppSettings)
+        val supportedVideoQualities: List<VideoQuality> =
+            cameraConstraints?.supportedVideoQualitiesMap?.get(
+                cameraAppSettings.dynamicRange
+            ) ?: listOf(VideoQuality.UNSPECIFIED)
+
+        return if (supportedVideoQualities != listOf(VideoQuality.UNSPECIFIED)) {
+            VideoQualityUiState.Enabled(
+                currentVideoQuality = cameraAppSettings.videoQuality,
+                videoQualityAutoState = SingleSelectableState.Selectable,
+                videoQualitySDState = getSingleVideoQualityState(
+                    VideoQuality.SD,
+                    supportedVideoQualities
+                ),
+                videoQualityHDState = getSingleVideoQualityState(
+                    VideoQuality.HD,
+                    supportedVideoQualities
+                ),
+                videoQualityFHDState = getSingleVideoQualityState(
+                    VideoQuality.FHD,
+                    supportedVideoQualities
+                ),
+                videoQualityUHDState = getSingleVideoQualityState(
+                    VideoQuality.UHD,
+                    supportedVideoQualities
+                )
+            )
+        } else {
+            VideoQualityUiState.Disabled(
+                DisabledRationale.VideoQualityUnsupportedRationale(
+                    R.string.video_quality_rationale_prefix
+                )
+            )
+        }
+    }
+
+    private fun getSingleVideoQualityState(
+        videoQuality: VideoQuality,
+        supportedVideQualities: List<VideoQuality>
+    ): SingleSelectableState = if (supportedVideQualities.contains(videoQuality)) {
+        SingleSelectableState.Selectable
+    } else {
+        SingleSelectableState.Disabled(
+            DisabledRationale.VideoQualityUnsupportedRationale(
+                R.string.video_quality_rationale_prefix
+            )
+        )
+    }
+
     /**
      * Enables or disables default camera switch based on:
      * - number of cameras available
@@ -267,38 +472,37 @@ class SettingsViewModel @Inject constructor(
             )
         }
 
-        // if preview stabilization is currently on and the other lens won't support it
-        if (currentSettings.previewStabilization == Stabilization.ON) {
-            if (!newLensConstraints.supportedStabilizationModes.contains(
-                    SupportedStabilizationMode.ON
-                )
-            ) {
-                return FlipLensUiState.Disabled(
-                    currentLensFacing = currentSettings.cameraLensFacing,
-                    disabledRationale = StabilizationUnsupportedRationale(
-                        when (currentSettings.cameraLensFacing) {
-                            LensFacing.BACK -> R.string.front_lens_rationale_prefix
-                            LensFacing.FRONT -> R.string.rear_lens_rationale_prefix
-                        }
-                    )
+        // If a non-AUTO stabilization is currently on and the other lens won't support it
+        if (currentSettings.stabilizationMode != StabilizationMode.AUTO &&
+            currentSettings.stabilizationMode !in newLensConstraints.supportedStabilizationModes
+        ) {
+            return FlipLensUiState.Disabled(
+                currentLensFacing = currentSettings.cameraLensFacing,
+                disabledRationale = StabilizationUnsupportedRationale(
+                    when (currentSettings.cameraLensFacing) {
+                        LensFacing.BACK -> R.string.front_lens_rationale_prefix
+                        LensFacing.FRONT -> R.string.rear_lens_rationale_prefix
+                    }
                 )
-            }
+            )
         }
-        // if video stabilization is currently on and the other lens won't support it
-        if (currentSettings.videoCaptureStabilization == Stabilization.ON) {
-            if (!newLensConstraints.supportedStabilizationModes
-                    .contains(SupportedStabilizationMode.HIGH_QUALITY)
-            ) {
-                return FlipLensUiState.Disabled(
-                    currentLensFacing = currentSettings.cameraLensFacing,
-                    disabledRationale = StabilizationUnsupportedRationale(
-                        when (currentSettings.cameraLensFacing) {
-                            LensFacing.BACK -> R.string.front_lens_rationale_prefix
-                            LensFacing.FRONT -> R.string.rear_lens_rationale_prefix
-                        }
-                    )
+
+        // if other lens doesnt support the video quality
+        if (currentSettings.videoQuality != VideoQuality.UNSPECIFIED &&
+            newLensConstraints.supportedVideoQualitiesMap[DynamicRange.SDR]?.contains(
+                currentSettings.videoQuality
+            ) != true
+        ) {
+            return FlipLensUiState.Disabled(
+                currentLensFacing = currentSettings.cameraLensFacing,
+                disabledRationale = DisabledRationale.VideoQualityUnsupportedRationale(
+                    when (currentSettings.cameraLensFacing) {
+                        LensFacing.BACK -> R.string.front_lens_rationale_prefix
+                        LensFacing.FRONT -> R.string.rear_lens_rationale_prefix
+                    },
+                    R.string.video_quality_rationale_suffix_sdr
                 )
-            }
+            )
         }
 
         return FlipLensUiState.Enabled(currentLensFacing = currentSettings.cameraLensFacing)
@@ -310,32 +514,41 @@ class SettingsViewModel @Inject constructor(
     ): FpsUiState {
         val optionConstraintRationale: MutableMap<Int, SingleSelectableState> = mutableMapOf()
 
-        val currentLensFrameRates: Set<Int> = systemConstraints
-            .perLensConstraints[cameraAppSettings.cameraLensFacing]
-            ?.supportedFixedFrameRates ?: emptySet()
+        val deviceSupportedFrameRates = systemConstraints.perLensConstraints
+            .asSequence()
+            .flatMap { it.value.supportedFixedFrameRates }
+            .toSet()
 
         // if device supports no fixed frame rates, disable
-        if (currentLensFrameRates.isEmpty()) {
+        if (deviceSupportedFrameRates.isEmpty()) {
             return FpsUiState.Disabled(
                 DeviceUnsupportedRationale(R.string.no_fixed_fps_rationale_prefix)
             )
         }
 
-        // provide selectable states for each of the fps options
-        fpsOptions.forEach { fpsOption ->
-            val fpsUiState = isFpsOptionEnabled(
-                fpsOption,
-                cameraAppSettings.cameraLensFacing,
-                currentLensFrameRates,
-                systemConstraints.perLensConstraints[cameraAppSettings.cameraLensFacing]
-                    ?.supportedFixedFrameRates ?: emptySet(),
-                cameraAppSettings.previewStabilization,
-                cameraAppSettings.videoCaptureStabilization
-            )
-            if (fpsUiState is SingleSelectableState.Disabled) {
-                Log.d(TAG, "fps option $fpsOption disabled. ${fpsUiState.disabledRationale::class}")
+        val currentLensConstraints = checkNotNull(
+            systemConstraints.forCurrentLens(cameraAppSettings)
+        ) {
+            "Lens constraints for ${cameraAppSettings.cameraLensFacing} not available."
+        }
+
+        with(currentLensConstraints) {
+            // provide selectable states for each of the fps options
+            fpsOptions.forEach { fpsOption ->
+                val fpsUiState = isFpsOptionEnabled(
+                    fpsOption = fpsOption,
+                    defaultLensFacing = cameraAppSettings.cameraLensFacing,
+                    deviceSupportedFrameRates = deviceSupportedFrameRates,
+                    stabilizationMode = cameraAppSettings.stabilizationMode
+                )
+                if (fpsUiState is SingleSelectableState.Disabled) {
+                    Log.d(
+                        TAG,
+                        "fps option $fpsOption disabled. ${fpsUiState.disabledRationale::class}"
+                    )
+                }
+                optionConstraintRationale[fpsOption] = fpsUiState
             }
-            optionConstraintRationale[fpsOption] = fpsUiState
         }
         return FpsUiState.Enabled(
             currentSelection = cameraAppSettings.targetFrameRate,
@@ -349,22 +562,20 @@ class SettingsViewModel @Inject constructor(
     /**
      * Auxiliary function to determine if an FPS option should be disabled or not
      */
-    private fun isFpsOptionEnabled(
+    private fun CameraConstraints.isFpsOptionEnabled(
         fpsOption: Int,
         defaultLensFacing: LensFacing,
-        deviceFrameRates: Set<Int>,
-        lensFrameRates: Set<Int>,
-        previewStabilization: Stabilization,
-        videoStabilization: Stabilization
+        deviceSupportedFrameRates: Set<Int>,
+        stabilizationMode: StabilizationMode
     ): SingleSelectableState {
-        // if device doesnt support the fps option, disable
-        if (!deviceFrameRates.contains(fpsOption)) {
+        // if device doesn't support the fps option, disable
+        if (!deviceSupportedFrameRates.contains(fpsOption)) {
             return SingleSelectableState.Disabled(
                 disabledRationale = DeviceUnsupportedRationale(R.string.fps_rationale_prefix)
             )
         }
-        // if the current lens doesnt support the fps, disable
-        if (!lensFrameRates.contains(fpsOption)) {
+        // if the current lens doesn't support the fps, disable
+        if (!supportedFixedFrameRates.contains(fpsOption)) {
             Log.d(TAG, "FPS disabled for current lens")
 
             return SingleSelectableState.Disabled(
@@ -373,12 +584,7 @@ class SettingsViewModel @Inject constructor(
         }
 
         // if stabilization is on and the option is incompatible, disable
-        if ((
-                previewStabilization == Stabilization.ON &&
-                    (fpsOption == FPS_15 || fpsOption == FPS_60)
-                ) ||
-            (videoStabilization == Stabilization.ON && fpsOption == FPS_60)
-        ) {
+        if (fpsOption in stabilizationMode.unsupportedFpsSet) {
             return SingleSelectableState.Disabled(
                 StabilizationUnsupportedRationale(R.string.fps_rationale_prefix)
             )
@@ -387,6 +593,12 @@ class SettingsViewModel @Inject constructor(
         return SingleSelectableState.Selectable
     }
 
+// ////////////////////////////////////////////////////////////
+//
+// Settings Repository functions
+//
+// ////////////////////////////////////////////////////////////
+
     fun setDefaultLensFacing(lensFacing: LensFacing) {
         viewModelScope.launch {
             settingsRepository.updateDefaultLensFacing(lensFacing)
@@ -422,24 +634,38 @@ class SettingsViewModel @Inject constructor(
         }
     }
 
-    fun setCaptureMode(captureMode: CaptureMode) {
+    fun setStreamConfig(streamConfig: StreamConfig) {
+        viewModelScope.launch {
+            settingsRepository.updateStreamConfig(streamConfig)
+            Log.d(TAG, "set default capture mode: $streamConfig")
+        }
+    }
+
+    fun setStabilizationMode(stabilizationMode: StabilizationMode) {
+        viewModelScope.launch {
+            settingsRepository.updateStabilizationMode(stabilizationMode)
+            Log.d(TAG, "set stabilization mode: $stabilizationMode")
+        }
+    }
+
+    fun setMaxVideoDuration(durationMillis: Long) {
         viewModelScope.launch {
-            settingsRepository.updateCaptureMode(captureMode)
-            Log.d(TAG, "set default capture mode: $captureMode")
+            settingsRepository.updateMaxVideoDuration(durationMillis)
+            Log.d(TAG, "set video duration: $durationMillis ms")
         }
     }
 
-    fun setPreviewStabilization(stabilization: Stabilization) {
+    fun setVideoQuality(videoQuality: VideoQuality) {
         viewModelScope.launch {
-            settingsRepository.updatePreviewStabilization(stabilization)
-            Log.d(TAG, "set preview stabilization: $stabilization")
+            settingsRepository.updateVideoQuality(videoQuality)
+            Log.d(TAG, "set video quality: $videoQuality ms")
         }
     }
 
-    fun setVideoStabilization(stabilization: Stabilization) {
+    fun setVideoAudio(isAudioEnabled: Boolean) {
         viewModelScope.launch {
-            settingsRepository.updateVideoStabilization(stabilization)
-            Log.d(TAG, "set video stabilization: $stabilization")
+            settingsRepository.updateAudioEnabled(isAudioEnabled)
+            Log.d(TAG, "recording audio muted: $isAudioEnabled")
         }
     }
 }
diff --git a/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/SettingsComponents.kt b/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/SettingsComponents.kt
index e8c02fb..3c176de 100644
--- a/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/SettingsComponents.kt
+++ b/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/SettingsComponents.kt
@@ -21,9 +21,11 @@ import androidx.compose.foundation.layout.Column
 import androidx.compose.foundation.layout.Row
 import androidx.compose.foundation.layout.fillMaxWidth
 import androidx.compose.foundation.layout.padding
+import androidx.compose.foundation.rememberScrollState
 import androidx.compose.foundation.selection.selectable
 import androidx.compose.foundation.selection.selectableGroup
 import androidx.compose.foundation.selection.toggleable
+import androidx.compose.foundation.verticalScroll
 import androidx.compose.material.icons.Icons
 import androidx.compose.material.icons.automirrored.filled.ArrowBack
 import androidx.compose.material3.AlertDialog
@@ -37,12 +39,15 @@ import androidx.compose.material3.RadioButton
 import androidx.compose.material3.Switch
 import androidx.compose.material3.Text
 import androidx.compose.material3.TopAppBar
+import androidx.compose.material3.TopAppBarScrollBehavior
 import androidx.compose.runtime.Composable
+import androidx.compose.runtime.MutableState
 import androidx.compose.runtime.ReadOnlyComposable
 import androidx.compose.runtime.mutableStateOf
 import androidx.compose.runtime.remember
 import androidx.compose.ui.Alignment
 import androidx.compose.ui.Modifier
+import androidx.compose.ui.graphics.Color
 import androidx.compose.ui.platform.testTag
 import androidx.compose.ui.res.stringResource
 import androidx.compose.ui.semantics.Role
@@ -53,28 +58,36 @@ import androidx.compose.ui.tooling.preview.Preview
 import androidx.compose.ui.unit.dp
 import androidx.compose.ui.unit.sp
 import com.google.jetpackcamera.settings.AspectRatioUiState
-import com.google.jetpackcamera.settings.CaptureModeUiState
+import com.google.jetpackcamera.settings.AudioUiState
 import com.google.jetpackcamera.settings.DarkModeUiState
 import com.google.jetpackcamera.settings.DisabledRationale
+import com.google.jetpackcamera.settings.FIVE_SECONDS_DURATION
 import com.google.jetpackcamera.settings.FlashUiState
 import com.google.jetpackcamera.settings.FlipLensUiState
 import com.google.jetpackcamera.settings.FpsUiState
+import com.google.jetpackcamera.settings.MaxVideoDurationUiState
 import com.google.jetpackcamera.settings.R
+import com.google.jetpackcamera.settings.SIXTY_SECONDS_DURATION
 import com.google.jetpackcamera.settings.SingleSelectableState
 import com.google.jetpackcamera.settings.StabilizationUiState
+import com.google.jetpackcamera.settings.StreamConfigUiState
+import com.google.jetpackcamera.settings.TEN_SECONDS_DURATION
+import com.google.jetpackcamera.settings.THIRTY_SECONDS_DURATION
+import com.google.jetpackcamera.settings.UNLIMITED_VIDEO_DURATION
+import com.google.jetpackcamera.settings.VideoQualityUiState
 import com.google.jetpackcamera.settings.model.AspectRatio
-import com.google.jetpackcamera.settings.model.CaptureMode
+import com.google.jetpackcamera.settings.model.CameraConstraints.Companion.FPS_15
+import com.google.jetpackcamera.settings.model.CameraConstraints.Companion.FPS_30
+import com.google.jetpackcamera.settings.model.CameraConstraints.Companion.FPS_60
+import com.google.jetpackcamera.settings.model.CameraConstraints.Companion.FPS_AUTO
 import com.google.jetpackcamera.settings.model.DarkMode
 import com.google.jetpackcamera.settings.model.FlashMode
 import com.google.jetpackcamera.settings.model.LensFacing
-import com.google.jetpackcamera.settings.model.Stabilization
+import com.google.jetpackcamera.settings.model.StabilizationMode
+import com.google.jetpackcamera.settings.model.StreamConfig
+import com.google.jetpackcamera.settings.model.VideoQuality
 import com.google.jetpackcamera.settings.ui.theme.SettingsPreviewTheme
 
-const val FPS_AUTO = 0
-const val FPS_15 = 15
-const val FPS_30 = 30
-const val FPS_60 = 60
-
 /**
  * MAJOR SETTING UI COMPONENTS
  * these are ready to be popped into the ui
@@ -82,7 +95,12 @@ const val FPS_60 = 60
 
 @OptIn(ExperimentalMaterial3Api::class)
 @Composable
-fun SettingsPageHeader(title: String, navBack: () -> Unit, modifier: Modifier = Modifier) {
+fun SettingsPageHeader(
+    title: String,
+    navBack: () -> Unit,
+    modifier: Modifier = Modifier,
+    scrollBehavior: TopAppBarScrollBehavior? = null
+) {
     TopAppBar(
         modifier = modifier,
         title = {
@@ -98,7 +116,8 @@ fun SettingsPageHeader(title: String, navBack: () -> Unit, modifier: Modifier =
                     stringResource(id = R.string.nav_back_accessibility)
                 )
             }
-        }
+        },
+        scrollBehavior = scrollBehavior
     )
 }
 
@@ -113,37 +132,6 @@ fun SectionHeader(title: String, modifier: Modifier = Modifier) {
     )
 }
 
-@Composable
-fun DefaultCameraFacing(
-    modifier: Modifier = Modifier,
-    lensUiState: FlipLensUiState,
-    setDefaultLensFacing: (LensFacing) -> Unit
-) {
-    SwitchSettingUI(
-        modifier = modifier.apply {
-            if (lensUiState is FlipLensUiState.Disabled) {
-                testTag(lensUiState.disabledRationale.testTag)
-            }
-        },
-        title = stringResource(id = R.string.default_facing_camera_title),
-        description = when (lensUiState) {
-            is FlipLensUiState.Disabled -> {
-                disabledRationaleString(disabledRationale = lensUiState.disabledRationale)
-            }
-
-            is FlipLensUiState.Enabled -> {
-                null
-            }
-        },
-        leadingIcon = null,
-        onSwitchChanged = { on ->
-            setDefaultLensFacing(if (on) LensFacing.FRONT else LensFacing.BACK)
-        },
-        settingValue = lensUiState.currentLensFacing == LensFacing.FRONT,
-        enabled = lensUiState is FlipLensUiState.Enabled
-    )
-}
-
 @Composable
 fun DarkModeSetting(
     darkModeUiState: DarkModeUiState,
@@ -151,7 +139,7 @@ fun DarkModeSetting(
     modifier: Modifier = Modifier
 ) {
     BasicPopupSetting(
-        modifier = modifier,
+        modifier = modifier.testTag(BTN_OPEN_DIALOG_SETTING_DARK_MODE_TAG),
         title = stringResource(id = R.string.dark_mode_title),
         leadingIcon = null,
         enabled = true,
@@ -167,18 +155,21 @@ fun DarkModeSetting(
         popupContents = {
             Column(Modifier.selectableGroup()) {
                 SingleChoiceSelector(
+                    modifier = modifier.testTag(BTN_DIALOG_DARK_MODE_OPTION_ON_TAG),
                     text = stringResource(id = R.string.dark_mode_selector_dark),
                     selected = darkModeUiState.currentDarkMode == DarkMode.DARK,
                     enabled = true,
                     onClick = { setDarkMode(DarkMode.DARK) }
                 )
                 SingleChoiceSelector(
+                    modifier = modifier.testTag(BTN_DIALOG_DARK_MODE_OPTION_OFF_TAG),
                     text = stringResource(id = R.string.dark_mode_selector_light),
                     selected = darkModeUiState.currentDarkMode == DarkMode.LIGHT,
                     enabled = true,
                     onClick = { setDarkMode(DarkMode.LIGHT) }
                 )
                 SingleChoiceSelector(
+                    modifier = modifier.testTag(BTN_DIALOG_DARK_MODE_OPTION_SYSTEM_TAG),
                     text = stringResource(id = R.string.dark_mode_selector_system),
                     selected = darkModeUiState.currentDarkMode == DarkMode.SYSTEM,
                     enabled = true,
@@ -189,6 +180,37 @@ fun DarkModeSetting(
     )
 }
 
+@Composable
+fun DefaultCameraFacing(
+    modifier: Modifier = Modifier,
+    lensUiState: FlipLensUiState,
+    setDefaultLensFacing: (LensFacing) -> Unit
+) {
+    SwitchSettingUI(
+        modifier = modifier.apply {
+            if (lensUiState is FlipLensUiState.Disabled) {
+                testTag(lensUiState.disabledRationale.testTag)
+            }
+        },
+        title = stringResource(id = R.string.default_facing_camera_title),
+        description = when (lensUiState) {
+            is FlipLensUiState.Disabled -> {
+                disabledRationaleString(disabledRationale = lensUiState.disabledRationale)
+            }
+
+            is FlipLensUiState.Enabled -> {
+                null
+            }
+        },
+        leadingIcon = null,
+        onSwitchChanged = { on ->
+            setDefaultLensFacing(if (on) LensFacing.FRONT else LensFacing.BACK)
+        },
+        settingValue = lensUiState.currentLensFacing == LensFacing.FRONT,
+        enabled = lensUiState is FlipLensUiState.Enabled
+    )
+}
+
 @Composable
 fun FlashModeSetting(
     flashUiState: FlashUiState,
@@ -196,40 +218,63 @@ fun FlashModeSetting(
     modifier: Modifier = Modifier
 ) {
     BasicPopupSetting(
-        modifier = modifier,
+        modifier = modifier.testTag(BTN_OPEN_DIALOG_SETTING_FLASH_TAG),
         title = stringResource(id = R.string.flash_mode_title),
         leadingIcon = null,
-        enabled = true,
+        enabled = flashUiState is FlashUiState.Enabled,
         description =
-        if (flashUiState is FlashUiState.Enabled) {
-            when (flashUiState.currentFlashMode) {
+        when (flashUiState) {
+            is FlashUiState.Enabled -> when (flashUiState.currentFlashMode) {
                 FlashMode.AUTO -> stringResource(id = R.string.flash_mode_description_auto)
                 FlashMode.ON -> stringResource(id = R.string.flash_mode_description_on)
                 FlashMode.OFF -> stringResource(id = R.string.flash_mode_description_off)
+                FlashMode.LOW_LIGHT_BOOST -> stringResource(
+                    id = R.string.flash_mode_description_llb
+                )
             }
-        } else {
-            TODO("flash mode currently has no disabled criteria")
+            is FlashUiState.Disabled -> stringResource(
+                flashUiState.disabledRationale.reasonTextResId,
+                stringResource(flashUiState.disabledRationale.affectedSettingNameResId)
+            )
         },
         popupContents = {
-            Column(Modifier.selectableGroup()) {
-                SingleChoiceSelector(
-                    text = stringResource(id = R.string.flash_mode_selector_auto),
-                    selected = flashUiState.currentFlashMode == FlashMode.AUTO,
-                    enabled = true,
-                    onClick = { setFlashMode(FlashMode.AUTO) }
-                )
-                SingleChoiceSelector(
-                    text = stringResource(id = R.string.flash_mode_selector_on),
-                    selected = flashUiState.currentFlashMode == FlashMode.ON,
-                    enabled = true,
-                    onClick = { setFlashMode(FlashMode.ON) }
-                )
-                SingleChoiceSelector(
-                    text = stringResource(id = R.string.flash_mode_selector_off),
-                    selected = flashUiState.currentFlashMode == FlashMode.OFF,
-                    enabled = true,
-                    onClick = { setFlashMode(FlashMode.OFF) }
-                )
+            if (flashUiState is FlashUiState.Enabled) {
+                Column(Modifier.selectableGroup()) {
+                    SingleChoiceSelector(
+                        modifier = Modifier.testTag(BTN_DIALOG_FLASH_OPTION_AUTO_TAG),
+                        text = stringResource(id = R.string.flash_mode_selector_auto),
+                        selected = flashUiState.currentFlashMode == FlashMode.AUTO,
+                        enabled = flashUiState.autoSelectableState is
+                            SingleSelectableState.Selectable,
+                        onClick = { setFlashMode(FlashMode.AUTO) }
+                    )
+
+                    SingleChoiceSelector(
+                        modifier = Modifier.testTag(BTN_DIALOG_FLASH_OPTION_ON_TAG),
+                        text = stringResource(id = R.string.flash_mode_selector_on),
+                        selected = flashUiState.currentFlashMode == FlashMode.ON,
+                        enabled = flashUiState.onSelectableState is
+                            SingleSelectableState.Selectable,
+                        onClick = { setFlashMode(FlashMode.ON) }
+                    )
+
+                    SingleChoiceSelector(
+                        modifier = Modifier.testTag(BTN_DIALOG_FLASH_OPTION_LLB_TAG),
+                        text = stringResource(id = R.string.flash_mode_selector_llb),
+                        selected = flashUiState.currentFlashMode == FlashMode.LOW_LIGHT_BOOST,
+                        enabled = flashUiState.lowLightSelectableState is
+                            SingleSelectableState.Selectable,
+                        onClick = { setFlashMode(FlashMode.LOW_LIGHT_BOOST) }
+                    )
+
+                    SingleChoiceSelector(
+                        modifier = Modifier.testTag(BTN_DIALOG_FLASH_OPTION_OFF_TAG),
+                        text = stringResource(id = R.string.flash_mode_selector_off),
+                        selected = flashUiState.currentFlashMode == FlashMode.OFF,
+                        enabled = true,
+                        onClick = { setFlashMode(FlashMode.OFF) }
+                    )
+                }
             }
         }
     )
@@ -242,7 +287,7 @@ fun AspectRatioSetting(
     modifier: Modifier = Modifier
 ) {
     BasicPopupSetting(
-        modifier = modifier,
+        modifier = modifier.testTag(BTN_OPEN_DIALOG_SETTING_ASPECT_RATIO_TAG),
         title = stringResource(id = R.string.aspect_ratio_title),
         leadingIcon = null,
         description =
@@ -262,18 +307,21 @@ fun AspectRatioSetting(
         popupContents = {
             Column(Modifier.selectableGroup()) {
                 SingleChoiceSelector(
+                    modifier = Modifier.testTag(BTN_DIALOG_ASPECT_RATIO_OPTION_9_16_TAG),
                     text = stringResource(id = R.string.aspect_ratio_selector_9_16),
                     selected = aspectRatioUiState.currentAspectRatio == AspectRatio.NINE_SIXTEEN,
                     enabled = true,
                     onClick = { setAspectRatio(AspectRatio.NINE_SIXTEEN) }
                 )
                 SingleChoiceSelector(
+                    modifier = Modifier.testTag(BTN_DIALOG_ASPECT_RATIO_OPTION_3_4_TAG),
                     text = stringResource(id = R.string.aspect_ratio_selector_3_4),
                     selected = aspectRatioUiState.currentAspectRatio == AspectRatio.THREE_FOUR,
                     enabled = true,
                     onClick = { setAspectRatio(AspectRatio.THREE_FOUR) }
                 )
                 SingleChoiceSelector(
+                    modifier = Modifier.testTag(BTN_DIALOG_ASPECT_RATIO_OPTION_1_1_TAG),
                     text = stringResource(id = R.string.aspect_ratio_selector_1_1),
                     selected = aspectRatioUiState.currentAspectRatio == AspectRatio.ONE_ONE,
                     enabled = true,
@@ -285,49 +333,122 @@ fun AspectRatioSetting(
 }
 
 @Composable
-fun CaptureModeSetting(
-    captureModeUiState: CaptureModeUiState,
-    setCaptureMode: (CaptureMode) -> Unit,
+fun StreamConfigSetting(
+    streamConfigUiState: StreamConfigUiState,
+    setStreamConfig: (StreamConfig) -> Unit,
     modifier: Modifier = Modifier
 ) {
     BasicPopupSetting(
-        modifier = modifier,
-        title = stringResource(R.string.capture_mode_title),
+        modifier = modifier.testTag(BTN_OPEN_DIALOG_SETTING_STREAM_CONFIG_TAG),
+        title = stringResource(R.string.stream_config_title),
         leadingIcon = null,
         enabled = true,
         description =
-        if (captureModeUiState is CaptureModeUiState.Enabled) {
-            when (captureModeUiState.currentCaptureMode) {
-                CaptureMode.MULTI_STREAM -> stringResource(
-                    id = R.string.capture_mode_description_multi_stream
+        if (streamConfigUiState is StreamConfigUiState.Enabled) {
+            when (streamConfigUiState.currentStreamConfig) {
+                StreamConfig.MULTI_STREAM -> stringResource(
+                    id = R.string.stream_config_description_multi_stream
                 )
 
-                CaptureMode.SINGLE_STREAM -> stringResource(
-                    id = R.string.capture_mode_description_single_stream
+                StreamConfig.SINGLE_STREAM -> stringResource(
+                    id = R.string.stream_config_description_single_stream
                 )
             }
         } else {
-            TODO("capture mode currently has no disabled criteria")
+            TODO("stream config currently has no disabled criteria")
         },
         popupContents = {
             Column(Modifier.selectableGroup()) {
                 SingleChoiceSelector(
-                    text = stringResource(id = R.string.capture_mode_selector_multi_stream),
-                    selected = captureModeUiState.currentCaptureMode == CaptureMode.MULTI_STREAM,
+                    modifier = Modifier.testTag(
+                        BTN_DIALOG_STREAM_CONFIG_OPTION_MULTI_STREAM_CAPTURE_TAG
+                    ),
+                    text = stringResource(id = R.string.stream_config_selector_multi_stream),
+                    selected = streamConfigUiState.currentStreamConfig == StreamConfig.MULTI_STREAM,
                     enabled = true,
-                    onClick = { setCaptureMode(CaptureMode.MULTI_STREAM) }
+                    onClick = { setStreamConfig(StreamConfig.MULTI_STREAM) }
                 )
                 SingleChoiceSelector(
-                    text = stringResource(id = R.string.capture_mode_description_single_stream),
-                    selected = captureModeUiState.currentCaptureMode == CaptureMode.SINGLE_STREAM,
+                    modifier = Modifier.testTag(BTN_DIALOG_STREAM_CONFIG_OPTION_SINGLE_STREAM_TAG),
+                    text = stringResource(id = R.string.stream_config_description_single_stream),
+                    selected = streamConfigUiState.currentStreamConfig ==
+                        StreamConfig.SINGLE_STREAM,
                     enabled = true,
-                    onClick = { setCaptureMode(CaptureMode.SINGLE_STREAM) }
+                    onClick = { setStreamConfig(StreamConfig.SINGLE_STREAM) }
                 )
             }
         }
     )
 }
 
+private fun getMaxVideoDurationTestTag(videoDuration: Long): String = when (videoDuration) {
+    UNLIMITED_VIDEO_DURATION -> BTN_DIALOG_VIDEO_DURATION_OPTION_UNLIMITED_TAG
+    FIVE_SECONDS_DURATION -> BTN_DIALOG_VIDEO_DURATION_OPTION_1S_TAG
+    TEN_SECONDS_DURATION -> BTN_DIALOG_VIDEO_DURATION_OPTION_10S_TAG
+    THIRTY_SECONDS_DURATION -> BTN_DIALOG_VIDEO_DURATION_OPTION_30S_TAG
+    SIXTY_SECONDS_DURATION -> BTN_DIALOG_VIDEO_DURATION_OPTION_60S_TAG
+    else -> BTN_DIALOG_VIDEO_DURATION_OPTION_UNLIMITED_TAG
+}
+
+@Composable
+fun MaxVideoDurationSetting(
+    maxVideoDurationUiState: MaxVideoDurationUiState.Enabled,
+    setMaxDuration: (Long) -> Unit,
+    modifier: Modifier = Modifier
+) {
+    BasicPopupSetting(
+        modifier = modifier.testTag(BTN_OPEN_DIALOG_SETTING_VIDEO_DURATION_TAG),
+        enabled = true,
+        title = stringResource(R.string.duration_title),
+        leadingIcon = null,
+        description = when (val maxDuration = maxVideoDurationUiState.currentMaxDurationMillis) {
+            UNLIMITED_VIDEO_DURATION -> stringResource(R.string.duration_description_none)
+            else -> stringResource(R.string.duration_description_seconds, (maxDuration / 1000))
+        },
+        popupContents = {
+            Column(Modifier.selectableGroup()) {
+                SingleChoiceSelector(
+                    modifier = modifier.testTag(
+                        getMaxVideoDurationTestTag(
+                            UNLIMITED_VIDEO_DURATION
+                        )
+                    ),
+                    enabled = true,
+                    text = stringResource(R.string.duration_description_none),
+                    selected = maxVideoDurationUiState.currentMaxDurationMillis
+                        == UNLIMITED_VIDEO_DURATION,
+                    onClick = { setMaxDuration(UNLIMITED_VIDEO_DURATION) }
+                )
+                listOf(
+                    FIVE_SECONDS_DURATION,
+                    TEN_SECONDS_DURATION,
+                    THIRTY_SECONDS_DURATION,
+                    SIXTY_SECONDS_DURATION
+                ).forEach { maxDuration ->
+                    SingleChoiceSelector(
+                        modifier = Modifier.testTag(getMaxVideoDurationTestTag(maxDuration)),
+                        enabled = true,
+                        text = stringResource(
+                            R.string.duration_description_seconds,
+                            (maxDuration / 1000)
+                        ),
+                        selected = maxVideoDurationUiState.currentMaxDurationMillis == maxDuration,
+                        onClick = { setMaxDuration(maxDuration) }
+                    )
+                }
+            }
+        }
+    )
+}
+
+private fun getTargetFpsTestTag(fpsOption: Int): String = when (fpsOption) {
+    FPS_15 -> BTN_DIALOG_FPS_OPTION_15_TAG
+    FPS_30 -> BTN_DIALOG_FPS_OPTION_30_TAG
+    FPS_60 -> BTN_DIALOG_FPS_OPTION_60_TAG
+    FPS_AUTO -> BTN_DIALOG_FPS_OPTION_AUTO_TAG
+    else -> BTN_DIALOG_FPS_OPTION_AUTO_TAG
+}
+
 @Composable
 fun TargetFpsSetting(
     fpsUiState: FpsUiState,
@@ -335,11 +456,14 @@ fun TargetFpsSetting(
     modifier: Modifier = Modifier
 ) {
     BasicPopupSetting(
-        modifier = modifier.apply {
-            if (fpsUiState is FpsUiState.Disabled) {
-                testTag(fpsUiState.disabledRationale.testTag)
-            }
-        },
+        modifier = modifier
+            .apply {
+                if (fpsUiState is FpsUiState.Disabled) {
+                    testTag(fpsUiState.disabledRationale.testTag)
+                } else {
+                    testTag(BTN_OPEN_DIALOG_SETTING_FPS_TAG)
+                }
+            },
         title = stringResource(id = R.string.fps_title),
         enabled = fpsUiState is FpsUiState.Enabled,
         leadingIcon = null,
@@ -359,6 +483,7 @@ fun TargetFpsSetting(
             if (fpsUiState is FpsUiState.Enabled) {
                 Column(Modifier.selectableGroup()) {
                     Text(
+                        modifier = Modifier.testTag(getTargetFpsTestTag(FPS_AUTO)),
                         text = stringResource(id = R.string.fps_stabilization_disclaimer),
                         fontStyle = FontStyle.Italic,
                         color = MaterialTheme.colorScheme.onPrimaryContainer
@@ -372,6 +497,7 @@ fun TargetFpsSetting(
                     )
                     listOf(FPS_15, FPS_30, FPS_60).forEach { fpsOption ->
                         SingleChoiceSelector(
+                            modifier = Modifier.testTag(getTargetFpsTestTag(fpsOption)),
                             text = "%d".format(fpsOption),
                             selected = fpsUiState.currentSelection == fpsOption,
                             onClick = { setTargetFps(fpsOption) },
@@ -404,21 +530,38 @@ fun TargetFpsSetting(
  * High Quality - preview is unspecified and video is ON.
  * Off - Every other configuration.
  */
-private fun getStabilizationStringRes(
-    previewStabilization: Stabilization,
-    videoStabilization: Stabilization
-): Int {
-    return if (previewStabilization == Stabilization.ON &&
-        videoStabilization != Stabilization.OFF
-    ) {
-        R.string.stabilization_description_on
-    } else if (previewStabilization == Stabilization.UNDEFINED &&
-        videoStabilization == Stabilization.ON
-    ) {
-        R.string.stabilization_description_high_quality
-    } else {
-        R.string.stabilization_description_off
+private fun getStabilizationStringRes(stabilizationMode: StabilizationMode): Int =
+    when (stabilizationMode) {
+        StabilizationMode.OFF -> R.string.stabilization_description_off
+        StabilizationMode.AUTO -> R.string.stabilization_description_auto
+        StabilizationMode.ON -> R.string.stabilization_description_on
+        StabilizationMode.HIGH_QUALITY -> R.string.stabilization_description_high_quality
+        StabilizationMode.OPTICAL -> R.string.stabilization_description_optical
     }
+
+private fun getVideoQualityStringRes(videoQuality: VideoQuality): Int = when (videoQuality) {
+    VideoQuality.UNSPECIFIED -> R.string.video_quality_value_auto
+    VideoQuality.SD -> R.string.video_quality_value_sd
+    VideoQuality.HD -> R.string.video_quality_value_hd
+    VideoQuality.FHD -> R.string.video_quality_value_fhd
+    VideoQuality.UHD -> R.string.video_quality_value_uhd
+}
+
+private fun getVideoQualitySecondaryStringRes(videoQuality: VideoQuality): Int =
+    when (videoQuality) {
+        VideoQuality.UNSPECIFIED -> R.string.video_quality_value_auto_info
+        VideoQuality.SD -> R.string.video_quality_value_sd_info
+        VideoQuality.HD -> R.string.video_quality_value_hd_info
+        VideoQuality.FHD -> R.string.video_quality_value_fhd_info
+        VideoQuality.UHD -> R.string.video_quality_value_uhd_info
+    }
+
+private fun getVideoQualityOptionTestTag(quality: VideoQuality): String = when (quality) {
+    VideoQuality.UNSPECIFIED -> BTN_DIALOG_VIDEO_QUALITY_OPTION_UNSPECIFIED_TAG
+    VideoQuality.SD -> BTN_DIALOG_VIDEO_QUALITY_OPTION_SD_TAG
+    VideoQuality.HD -> BTN_DIALOG_VIDEO_QUALITY_OPTION_HD_TAG
+    VideoQuality.FHD -> BTN_DIALOG_VIDEO_QUALITY_OPTION_FHD_TAG
+    VideoQuality.UHD -> BTN_DIALOG_VIDEO_QUALITY_OPTION_UHD_TAG
 }
 
 /**
@@ -433,8 +576,7 @@ private fun getStabilizationStringRes(
 @Composable
 fun StabilizationSetting(
     stabilizationUiState: StabilizationUiState,
-    setVideoStabilization: (Stabilization) -> Unit,
-    setPreviewStabilization: (Stabilization) -> Unit,
+    setStabilizationMode: (StabilizationMode) -> Unit,
     modifier: Modifier = Modifier
 ) {
     // entire setting disabled when no available fps or target fps = 60
@@ -445,7 +587,7 @@ fun StabilizationSetting(
                 is StabilizationUiState.Disabled ->
                     testTag(stabilizationUiState.disabledRationale.testTag)
 
-                else -> {}
+                else -> testTag(BTN_OPEN_DIALOG_SETTING_VIDEO_STABILIZATION_TAG)
             }
         },
         title = stringResource(R.string.video_stabilization_title),
@@ -454,10 +596,7 @@ fun StabilizationSetting(
         description = when (stabilizationUiState) {
             is StabilizationUiState.Enabled ->
                 stringResource(
-                    id = getStabilizationStringRes(
-                        previewStabilization = stabilizationUiState.currentPreviewStabilization,
-                        videoStabilization = stabilizationUiState.currentVideoStabilization
-                    )
+                    id = getStabilizationStringRes(stabilizationUiState.currentStabilizationMode)
                 )
 
             is StabilizationUiState.Disabled -> {
@@ -479,6 +618,32 @@ fun StabilizationSetting(
                 // TODO(b/328223562): device always resolves to 30fps when using preview stabilization
                 when (stabilizationUiState) {
                     is StabilizationUiState.Enabled -> {
+                        SingleChoiceSelector(
+                            modifier = Modifier.apply {
+                                if (stabilizationUiState.stabilizationAutoState
+                                        is SingleSelectableState.Disabled
+                                ) {
+                                    testTag(
+                                        stabilizationUiState.stabilizationAutoState
+                                            .disabledRationale.testTag
+                                    )
+                                } else {
+                                    testTag(BTN_DIALOG_VIDEO_STABILIZATION_OPTION_AUTO_TAG)
+                                }
+                            },
+                            text = stringResource(id = R.string.stabilization_selector_auto),
+                            secondaryText = stringResource(
+                                id = R.string.stabilization_selector_auto_info
+                            ),
+                            enabled = stabilizationUiState.stabilizationAutoState is
+                                SingleSelectableState.Selectable,
+                            selected = stabilizationUiState.currentStabilizationMode
+                                == StabilizationMode.AUTO,
+                            onClick = {
+                                setStabilizationMode(StabilizationMode.AUTO)
+                            }
+                        )
+
                         SingleChoiceSelector(
                             modifier = Modifier.apply {
                                 if (stabilizationUiState.stabilizationOnState
@@ -488,6 +653,8 @@ fun StabilizationSetting(
                                         stabilizationUiState.stabilizationOnState
                                             .disabledRationale.testTag
                                     )
+                                } else {
+                                    testTag(BTN_DIALOG_VIDEO_STABILIZATION_OPTION_ON_TAG)
                                 }
                             },
                             text = stringResource(id = R.string.stabilization_selector_on),
@@ -496,17 +663,10 @@ fun StabilizationSetting(
                             ),
                             enabled = stabilizationUiState.stabilizationOnState is
                                 SingleSelectableState.Selectable,
-                            selected = (
-                                stabilizationUiState.currentPreviewStabilization
-                                    == Stabilization.ON
-                                ) &&
-                                (
-                                    stabilizationUiState.currentVideoStabilization
-                                        != Stabilization.OFF
-                                    ),
+                            selected = stabilizationUiState.currentStabilizationMode
+                                == StabilizationMode.ON,
                             onClick = {
-                                setVideoStabilization(Stabilization.UNDEFINED)
-                                setPreviewStabilization(Stabilization.ON)
+                                setStabilizationMode(StabilizationMode.ON)
                             }
                         )
 
@@ -521,6 +681,8 @@ fun StabilizationSetting(
                                         stabilizationUiState.stabilizationHighQualityState
                                             .disabledRationale.testTag
                                     )
+                                } else {
+                                    testTag(BTN_DIALOG_VIDEO_STABILIZATION_OPTION_HIGH_QUALITY_TAG)
                                 }
                             },
                             text = stringResource(
@@ -532,34 +694,53 @@ fun StabilizationSetting(
                             enabled = stabilizationUiState.stabilizationHighQualityState
                                 == SingleSelectableState.Selectable,
 
-                            selected = (
-                                stabilizationUiState.currentPreviewStabilization
-                                    == Stabilization.UNDEFINED
-                                ) &&
-                                (
-                                    stabilizationUiState.currentVideoStabilization
-                                        == Stabilization.ON
-                                    ),
+                            selected = stabilizationUiState.currentStabilizationMode
+                                == StabilizationMode.HIGH_QUALITY,
+                            onClick = {
+                                setStabilizationMode(StabilizationMode.HIGH_QUALITY)
+                            }
+                        )
+
+                        // optical selector
+                        SingleChoiceSelector(
+                            modifier = Modifier.apply {
+                                if (stabilizationUiState.stabilizationOpticalState
+                                        is SingleSelectableState.Disabled
+                                ) {
+                                    testTag(
+                                        stabilizationUiState.stabilizationOpticalState
+                                            .disabledRationale.testTag
+                                    )
+                                } else {
+                                    testTag(BTN_DIALOG_VIDEO_STABILIZATION_OPTION_OPTICAL_TAG)
+                                }
+                            },
+                            text = stringResource(
+                                id = R.string.stabilization_selector_optical
+                            ),
+                            secondaryText = stringResource(
+                                id = R.string.stabilization_selector_optical_info
+                            ),
+                            enabled = stabilizationUiState.stabilizationOpticalState
+                                == SingleSelectableState.Selectable,
+
+                            selected = stabilizationUiState.currentStabilizationMode
+                                == StabilizationMode.OPTICAL,
                             onClick = {
-                                setVideoStabilization(Stabilization.ON)
-                                setPreviewStabilization(Stabilization.UNDEFINED)
+                                setStabilizationMode(StabilizationMode.OPTICAL)
                             }
                         )
 
                         // off selector
                         SingleChoiceSelector(
+                            modifier = Modifier.testTag(
+                                BTN_DIALOG_VIDEO_STABILIZATION_OPTION_OFF_TAG
+                            ),
                             text = stringResource(id = R.string.stabilization_selector_off),
-                            selected = (
-                                stabilizationUiState.currentPreviewStabilization
-                                    != Stabilization.ON
-                                ) &&
-                                (
-                                    stabilizationUiState.currentVideoStabilization
-                                        != Stabilization.ON
-                                    ),
+                            selected = stabilizationUiState.currentStabilizationMode
+                                == StabilizationMode.OFF,
                             onClick = {
-                                setVideoStabilization(Stabilization.OFF)
-                                setPreviewStabilization(Stabilization.OFF)
+                                setStabilizationMode(StabilizationMode.OFF)
                             },
                             enabled = true
                         )
@@ -572,6 +753,100 @@ fun StabilizationSetting(
     )
 }
 
+@Composable
+fun VideoQualitySetting(
+    videQualityUiState: VideoQualityUiState,
+    setVideoQuality: (VideoQuality) -> Unit,
+    modifier: Modifier = Modifier
+) {
+    BasicPopupSetting(
+        modifier = modifier.testTag(BTN_OPEN_DIALOG_SETTING_VIDEO_QUALITY_TAG),
+        title = stringResource(R.string.video_quality_title),
+        leadingIcon = null,
+        enabled = videQualityUiState is VideoQualityUiState.Enabled,
+        description = when (videQualityUiState) {
+            is VideoQualityUiState.Enabled ->
+                stringResource(getVideoQualityStringRes(videQualityUiState.currentVideoQuality))
+
+            is VideoQualityUiState.Disabled -> {
+                disabledRationaleString(
+                    disabledRationale = videQualityUiState.disabledRationale
+                )
+            }
+        },
+        popupContents = {
+            Column(
+                Modifier
+                    .selectableGroup()
+                    .verticalScroll(rememberScrollState())
+            ) {
+                SingleChoiceSelector(
+                    modifier = Modifier.testTag(
+                        getVideoQualityOptionTestTag(VideoQuality.UNSPECIFIED)
+                    ),
+                    text = stringResource(getVideoQualityStringRes(VideoQuality.UNSPECIFIED)),
+                    secondaryText = stringResource(
+                        getVideoQualitySecondaryStringRes(
+                            VideoQuality.UNSPECIFIED
+                        )
+                    ),
+                    selected = (videQualityUiState as VideoQualityUiState.Enabled)
+                        .currentVideoQuality == VideoQuality.UNSPECIFIED,
+                    enabled = videQualityUiState.videoQualityAutoState is
+                        SingleSelectableState.Selectable,
+                    onClick = { setVideoQuality(VideoQuality.UNSPECIFIED) }
+                )
+                listOf(VideoQuality.SD, VideoQuality.HD, VideoQuality.FHD, VideoQuality.UHD)
+                    .forEach { videoQuality ->
+                        SingleChoiceSelector(
+                            modifier = Modifier.testTag(getVideoQualityOptionTestTag(videoQuality)),
+                            text = stringResource(getVideoQualityStringRes(videoQuality)),
+                            secondaryText = stringResource(
+                                getVideoQualitySecondaryStringRes(
+                                    videoQuality
+                                )
+                            ),
+                            selected = videQualityUiState.currentVideoQuality == videoQuality,
+                            enabled = videQualityUiState.getSelectableState(videoQuality) is
+                                SingleSelectableState.Selectable,
+                            onClick = { setVideoQuality(videoQuality) }
+                        )
+                    }
+            }
+        }
+    )
+}
+
+@Composable
+fun RecordingAudioSetting(
+    modifier: Modifier = Modifier,
+    audioUiState: AudioUiState,
+    setDefaultAudio: (Boolean) -> Unit
+) {
+    SwitchSettingUI(
+        modifier = modifier.testTag(BTN_SWITCH_SETTING_ENABLE_AUDIO_TAG),
+        title = stringResource(id = R.string.audio_title),
+        description = when (audioUiState) {
+            is AudioUiState.Enabled.On -> {
+                stringResource(R.string.audio_selector_on)
+            }
+            is AudioUiState.Enabled.Mute -> {
+                stringResource(R.string.audio_selector_off)
+            }
+            is AudioUiState.Disabled -> {
+                disabledRationaleString(disabledRationale = audioUiState.disabledRationale)
+            }
+        },
+        leadingIcon = null,
+        onSwitchChanged = { on -> setDefaultAudio(on) },
+        settingValue = when (audioUiState) {
+            is AudioUiState.Enabled.On -> true
+            is AudioUiState.Disabled, is AudioUiState.Enabled.Mute -> false
+        },
+        enabled = audioUiState is AudioUiState.Enabled
+    )
+}
+
 @Composable
 fun VersionInfo(versionName: String, modifier: Modifier = Modifier, buildType: String = "") {
     SettingUI(
@@ -586,7 +861,7 @@ fun VersionInfo(versionName: String, modifier: Modifier = Modifier, buildType: S
             } else {
                 ""
             }
-        Text(text = versionString)
+        Text(text = versionString, modifier = Modifier.testTag(TEXT_SETTING_APP_VERSION_TAG))
     }
 }
 
@@ -605,9 +880,9 @@ fun BasicPopupSetting(
     leadingIcon: @Composable (() -> Unit)?,
     popupContents: @Composable () -> Unit,
     modifier: Modifier = Modifier,
-    enabled: Boolean
+    enabled: Boolean,
+    popupStatus: MutableState<Boolean> = remember { mutableStateOf(false) }
 ) {
-    val popupStatus = remember { mutableStateOf(false) }
     SettingUI(
         modifier = modifier.clickable(enabled = enabled) { popupStatus.value = true },
         title = title,
@@ -626,7 +901,12 @@ fun BasicPopupSetting(
                 )
             },
             title = { Text(text = title) },
-            text = popupContents
+            text = {
+                MaterialTheme(
+                    colorScheme = MaterialTheme.colorScheme.copy(surface = Color.Transparent),
+                    content = popupContents
+                )
+            }
         )
     }
 }
@@ -648,12 +928,14 @@ fun SwitchSettingUI(
     modifier: Modifier = Modifier
 ) {
     SettingUI(
-        modifier = modifier.toggleable(
-            enabled = enabled,
-            role = Role.Switch,
-            value = settingValue,
-            onValueChange = { value -> onSwitchChanged(value) }
-        ),
+        modifier = modifier
+            .toggleable(
+                enabled = enabled,
+                role = Role.Switch,
+                value = settingValue,
+                onValueChange = { value -> onSwitchChanged(value) }
+            )
+            .testTag(BTN_SWITCH_SETTING_LENS_FACING_TAG),
         enabled = enabled,
         title = title,
         description = description,
@@ -749,8 +1031,8 @@ fun SingleChoiceSelector(
 
 @Composable
 @ReadOnlyComposable
-fun disabledRationaleString(disabledRationale: DisabledRationale): String {
-    return when (disabledRationale) {
+fun disabledRationaleString(disabledRationale: DisabledRationale): String =
+    when (disabledRationale) {
         is DisabledRationale.DeviceUnsupportedRationale -> stringResource(
 
             disabledRationale.reasonTextResId,
@@ -772,8 +1054,17 @@ fun disabledRationaleString(disabledRationale: DisabledRationale): String {
             disabledRationale.reasonTextResId,
             stringResource(disabledRationale.affectedSettingNameResId)
         )
+
+        is DisabledRationale.VideoQualityUnsupportedRationale -> stringResource(
+            disabledRationale.reasonTextResId,
+            stringResource(disabledRationale.affectedSettingNameResId)
+        )
+
+        is DisabledRationale.PermissionRecordAudioNotGrantedRationale -> stringResource(
+            disabledRationale.reasonTextResId,
+            stringResource(disabledRationale.affectedSettingNameResId)
+        )
     }
-}
 
 @Preview(name = "Light Mode")
 @Preview(name = "Dark Mode", uiMode = Configuration.UI_MODE_NIGHT_YES)
@@ -783,3 +1074,39 @@ private fun Preview_VersionInfo() {
         VersionInfo(versionName = "0.1.0", buildType = "debug")
     }
 }
+
+@Preview(name = "Light Mode")
+@Preview(name = "Dark Mode", uiMode = Configuration.UI_MODE_NIGHT_YES)
+@Composable
+private fun Preview_Popup() {
+    SettingsPreviewTheme {
+        BasicPopupSetting(
+            title = "Test Popup",
+            description = "Test Description",
+            leadingIcon = null,
+            popupContents = {
+                Column(Modifier.selectableGroup()) {
+                    Text(
+                        text = "Test sub-text",
+                        fontStyle = FontStyle.Italic,
+                        color = MaterialTheme.colorScheme.onPrimaryContainer
+                    )
+                    SingleChoiceSelector(
+                        text = "Option 1",
+                        selected = true,
+                        enabled = true,
+                        onClick = { }
+                    )
+                    SingleChoiceSelector(
+                        text = "Option 2",
+                        selected = false,
+                        enabled = true,
+                        onClick = { }
+                    )
+                }
+            },
+            enabled = true,
+            popupStatus = remember { mutableStateOf(true) }
+        )
+    }
+}
diff --git a/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/TestTags.kt b/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/TestTags.kt
index 8253fc1..20e4c9b 100644
--- a/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/TestTags.kt
+++ b/feature/settings/src/main/java/com/google/jetpackcamera/settings/ui/TestTags.kt
@@ -15,6 +15,16 @@
  */
 package com.google.jetpackcamera.settings.ui
 
+// ////////////////////////////////
+//
+// !!!HEY YOU!!!
+// MODIFICATIONS TO EXISTING TEST TAGS WILL BREAK EXISTING EXTERNAL
+// AUTOMATED TESTS THAT SEARCH FOR THESE TAGS.
+//
+// PLEASE UPDATE YOUR TESTS ACCORDINGLY!
+//
+// ////////////////////////////////
+
 const val BACK_BUTTON = "BackButton"
 
 // unsupported rationale tags
@@ -22,3 +32,75 @@ const val DEVICE_UNSUPPORTED_TAG = "DeviceUnsupportedTag"
 const val STABILIZATION_UNSUPPORTED_TAG = "StabilizationUnsupportedTag"
 const val LENS_UNSUPPORTED_TAG = "LensUnsupportedTag"
 const val FPS_UNSUPPORTED_TAG = "FpsUnsupportedTag"
+const val VIDEO_QUALITY_UNSUPPORTED_TAG = "VideoQualityUnsupportedTag"
+const val PERMISSION_RECORD_AUDIO_NOT_GRANTED_TAG = "PermissionRecordAudioNotGrantedTag"
+
+// Settings w/ no dialog
+const val BTN_SWITCH_SETTING_LENS_FACING_TAG = "btn_switch_setting_lens_facing_tag"
+const val BTN_SWITCH_SETTING_ENABLE_AUDIO_TAG = "btn_switch_setting_enable_audio_tag"
+const val TEXT_SETTING_APP_VERSION_TAG = "text_setting_app_version_tag"
+
+// Flash Mode
+const val BTN_OPEN_DIALOG_SETTING_FLASH_TAG = "btn_open_dialog_setting_flash_tag"
+const val BTN_DIALOG_FLASH_OPTION_AUTO_TAG = "btn_dialog_flash_option_auto_tag"
+const val BTN_DIALOG_FLASH_OPTION_ON_TAG = "btn_dialog_flash_option_on_tag"
+const val BTN_DIALOG_FLASH_OPTION_OFF_TAG = "btn_dialog_flash_option_off_tag"
+const val BTN_DIALOG_FLASH_OPTION_LLB_TAG = "btn_dialog_flash_option_llb_tag"
+
+// Frame Rate
+const val BTN_OPEN_DIALOG_SETTING_FPS_TAG = "btn_open_dialog_setting_fps_tag"
+const val BTN_DIALOG_FPS_OPTION_AUTO_TAG = "btn_dialog_fps_option_auto_tag"
+const val BTN_DIALOG_FPS_OPTION_15_TAG = "btn_dialog_fps_option_15_tag"
+const val BTN_DIALOG_FPS_OPTION_30_TAG = "btn_dialog_fps_option_30_tag"
+const val BTN_DIALOG_FPS_OPTION_60_TAG = "btn_dialog_fps_option_60_tag"
+
+// Aspect Ratio
+const val BTN_OPEN_DIALOG_SETTING_ASPECT_RATIO_TAG = "btn_open_dialog_setting_aspect_ratio_tag"
+const val BTN_DIALOG_ASPECT_RATIO_OPTION_9_16_TAG = "btn_dialog_aspect_ratio_option_9_16_tag"
+const val BTN_DIALOG_ASPECT_RATIO_OPTION_3_4_TAG = "btn_dialog_aspect_ratio_option_3_4_tag"
+const val BTN_DIALOG_ASPECT_RATIO_OPTION_1_1_TAG = "btn_dialog_aspect_ratio_option_1_1_tag"
+
+// Stream Configuration
+const val BTN_OPEN_DIALOG_SETTING_STREAM_CONFIG_TAG = "btn_open_dialog_setting_stream_config_tag"
+const val BTN_DIALOG_STREAM_CONFIG_OPTION_SINGLE_STREAM_TAG =
+    "btn_dialog_stream_config_option_single_stream_tag"
+const val BTN_DIALOG_STREAM_CONFIG_OPTION_MULTI_STREAM_CAPTURE_TAG =
+    "btn_dialog_stream_config_option_multi_stream_capture_tag"
+
+// Max Video Duration
+const val BTN_OPEN_DIALOG_SETTING_VIDEO_DURATION_TAG = "btn_open_dialog_setting_video_duration_tag"
+const val BTN_DIALOG_VIDEO_DURATION_OPTION_UNLIMITED_TAG =
+    "btn_dialog_video_duration_option_unlimited_tag"
+const val BTN_DIALOG_VIDEO_DURATION_OPTION_1S_TAG = "btn_dialog_video_duration_option_1s_tag"
+const val BTN_DIALOG_VIDEO_DURATION_OPTION_10S_TAG = "btn_dialog_video_duration_option_10s_tag"
+const val BTN_DIALOG_VIDEO_DURATION_OPTION_30S_TAG = "btn_dialog_video_duration_option_30s_tag"
+const val BTN_DIALOG_VIDEO_DURATION_OPTION_60S_TAG = "btn_dialog_video_duration_option_60s_tag"
+
+// Video Stabilization
+const val BTN_OPEN_DIALOG_SETTING_VIDEO_STABILIZATION_TAG =
+    "btn_open_dialog_setting_video_stabilization_tag"
+const val BTN_DIALOG_VIDEO_STABILIZATION_OPTION_AUTO_TAG =
+    "btn_dialog_video_stabilization_option_auto_tag"
+const val BTN_DIALOG_VIDEO_STABILIZATION_OPTION_ON_TAG =
+    "btn_dialog_video_stabilization_option_on_tag"
+const val BTN_DIALOG_VIDEO_STABILIZATION_OPTION_OFF_TAG =
+    "btn_dialog_video_stabilization_option_off_tag"
+const val BTN_DIALOG_VIDEO_STABILIZATION_OPTION_HIGH_QUALITY_TAG =
+    "btn_dialog_video_stabilization_option_high_quality_tag"
+const val BTN_DIALOG_VIDEO_STABILIZATION_OPTION_OPTICAL_TAG =
+    "btn_dialog_video_stabilization_option_optical_tag"
+
+// Video Quality
+const val BTN_OPEN_DIALOG_SETTING_VIDEO_QUALITY_TAG = "btn_open_dialog_setting_video_quality_tag"
+const val BTN_DIALOG_VIDEO_QUALITY_OPTION_UNSPECIFIED_TAG =
+    "btn_dialog_video_quality_option_unspecified_tag"
+const val BTN_DIALOG_VIDEO_QUALITY_OPTION_SD_TAG = "btn_dialog_video_quality_option_sd_tag"
+const val BTN_DIALOG_VIDEO_QUALITY_OPTION_HD_TAG = "btn_dialog_video_quality_option_hd_tag"
+const val BTN_DIALOG_VIDEO_QUALITY_OPTION_FHD_TAG = "btn_dialog_video_quality_option_fhd_tag"
+const val BTN_DIALOG_VIDEO_QUALITY_OPTION_UHD_TAG = "btn_dialog_video_quality_option_uhd_tag"
+
+// Dark Mode
+const val BTN_OPEN_DIALOG_SETTING_DARK_MODE_TAG = "btn_open_dialog_setting_dark_mode_tag"
+const val BTN_DIALOG_DARK_MODE_OPTION_ON_TAG = "btn_dialog_dark_mode_option_on_tag"
+const val BTN_DIALOG_DARK_MODE_OPTION_OFF_TAG = "btn_dialog_dark_mode_option_off_tag"
+const val BTN_DIALOG_DARK_MODE_OPTION_SYSTEM_TAG = "btn_dialog_dark_mode_option_system_tag"
diff --git a/feature/settings/src/main/res/values/strings.xml b/feature/settings/src/main/res/values/strings.xml
index e41f4fd..2b4ef5e 100644
--- a/feature/settings/src/main/res/values/strings.xml
+++ b/feature/settings/src/main/res/values/strings.xml
@@ -22,6 +22,8 @@
     <string name="nav_back_accessibility">Button to navigate back out of settings</string>
 
     <string name="section_title_camera_settings">Default Camera Settings</string>
+    <string name="section_title_recording_settings">Default Recording Settings</string>
+
     <string name="section_title_app_settings">App Settings</string>
     <string name="section_title_software_info">Software Information</string>
 
@@ -46,19 +48,30 @@
     <string name="flash_mode_selector_auto">Auto</string>
     <string name="flash_mode_selector_on">On</string>
     <string name="flash_mode_selector_off">Off</string>
+    <string name="flash_mode_selector_llb">Low Light Boost</string>
 
     <string name="flash_mode_description_auto">Flash is set to Auto</string>
     <string name="flash_mode_description_on">Flash is On</string>
     <string name="flash_mode_description_off">Flash is Off</string>
+    <string name="flash_mode_description_llb">Using Low Light Boost</string>
+
+    <!-- Audio setting strings -->
+    <string name="audio_title">Enable Audio</string>
+
+    <string name="audio_selector_on">Recordings will start with audio enabled</string>
+    <string name="audio_selector_off">Recordings will start muted</string>
 
-    <!-- Capture mode setting strings -->
-    <string name="capture_mode_title">Set Capture Mode</string>
+    <string name="audio_description_on">Recordings will start with audio enabled</string>
+    <string name="audio_description_off">Recordings will start muted</string>
 
-    <string name="capture_mode_selector_multi_stream">Multi Stream Capture</string>
-    <string name="capture_mode_selector_single_stream">Single Stream Capture</string>
+    <!-- Stream Config mode setting strings -->
+    <string name="stream_config_title">Set Stream Configuration</string>
 
-    <string name="capture_mode_description_multi_stream">Multi Stream</string>
-    <string name="capture_mode_description_single_stream">Single Stream</string>
+    <string name="stream_config_selector_multi_stream">Multi Stream Capture</string>
+    <string name="stream_config_selector_single_stream">Single Stream Capture</string>
+
+    <string name="stream_config_description_multi_stream">Multi Stream</string>
+    <string name="stream_config_description_single_stream">Single Stream</string>
 
     <!-- Aspect Ratio setting strings -->
     <string name="aspect_ratio_title">Set Aspect Ratio</string>
@@ -74,15 +87,21 @@
     <!-- Stabilization setting strings -->
     <string name="video_stabilization_title">Set Video Stabilization</string>
 
+    <string name="stabilization_selector_auto">Auto</string>
     <string name="stabilization_selector_on">On</string>
     <string name="stabilization_selector_high_quality">High Quality</string>
+    <string name="stabilization_selector_optical">Optical</string>
     <string name="stabilization_selector_off">Off</string>
 
-    <string name="stabilization_selector_on_info">Both preview and video streams will be stabilized</string>
-    <string name="stabilization_selector_high_quality_info">Video stream will be stabilized, but preview might not be. This mode ensures highest-quality video stream.</string>
+    <string name="stabilization_selector_auto_info">Stabilization automatically turned on when device configuration supports it.</string>
+    <string name="stabilization_selector_on_info">Both preview and video streams stabilized.</string>
+    <string name="stabilization_selector_high_quality_info">Video stream stabilized, but preview might not be. Ensures highest-quality recordings.</string>
+    <string name="stabilization_selector_optical_info">All streams are stabilized by OIS hardware only.</string>
 
     <string name="stabilization_description_on">Stabilization On</string>
+    <string name="stabilization_description_optical">Stabilization Optical</string>
     <string name="stabilization_description_high_quality">Stabilization High Quality</string>
+    <string name="stabilization_description_auto">Stabilization Auto</string>
     <string name="stabilization_description_off">Stabilization Off</string>
     <string name="stabilization_description_unsupported_device">Stabilization unsupported by device</string>
     <string name="stabilization_description_unsupported_fps">Stabilization unsupported due to frame rate</string>
@@ -94,32 +113,63 @@
     <string name="fps_description_auto">Auto Frame Rate</string>
     <string name="fps_description">%d fps</string>
 
-
     <string name="fps_selector_auto">Auto</string>
     <string name="fps_selector_value">%d</string>
 
     <string name="fps_stabilization_disclaimer">*Available stabilization modes may change due to selected frame rate.</string>
-    <string name="lens_stabilization_disclaimer">*Some devices may not support stabilization on both lens.</string>
+    <string name="lens_stabilization_disclaimer">*Some devices may not support stabilization on both lenses.</string>
+
+    <!-- video limit strings -->
+    <string name="duration_title">Set Maximum Video Duration</string>
+    <string name="duration_description_none">Unlimited duration</string>
+    <string name="duration_description_seconds">%d seconds</string>
+
+    <!-- video quality strings -->
+    <string name="video_quality_title">Set Video Quality</string>
+    <string name="video_quality_value_auto">Auto</string>
+    <string name="video_quality_value_sd">SD</string>
+    <string name="video_quality_value_hd">HD</string>
+    <string name="video_quality_value_fhd">FHD</string>
+    <string name="video_quality_value_uhd">UHD</string>
+
+    <string name="video_quality_value_auto_info">Video quality automatically selected by the device.</string>
+    <string name="video_quality_value_sd_info">Standard Definition (SD) 480p video quality.</string>
+    <string name="video_quality_value_hd_info">High Definition (HD) video quality.</string>
+    <string name="video_quality_value_fhd_info">Full High Definition (FHD) 1080p video quality.</string>
+    <string name="video_quality_value_uhd_info">Ultra High Definition (UHD) 2160p video quality.</string>
+
 
     <!-- disabled rationale strings-->
+
     <string name="device_unsupported">%1$s is unsupported by the device</string>
     <string name="fps_unsupported"> %1$s is unsupported at %2$d fps</string>
-    <string name="stabilization_unsupported">%$1s is unsupported by the current stabilization</string>
-    <string name="current_lens_unsupported">%$s is unsupported by the current lens</string>
-    <string name="rear_lens_unsupported">%$s is unsupported by the rear lens</string>
-    <string name="front_lens_unsupported">%$s is unsupported by the front lens</string>
+    <string name="stabilization_unsupported">%1$s is unsupported by the current stabilization</string>
+    <string name="current_lens_unsupported">%1$s is unsupported by the current lens</string>
+    <string name="rear_lens_unsupported">%1$s is unsupported by the rear lens</string>
+    <string name="front_lens_unsupported">%1$s is unsupported by the front lens</string>
+    <string name="video_quality_unsupported">%1$s is unsupported by the current video quality</string>
+    <string name="permission_record_audio_unsupported">%1$s requires permission to record audio</string>
 
 
     <!-- Rationale prefixes -->
     <string name="stabilization_rationale_prefix">Stabilization</string>
     <string name="lens_rationale_prefix">Lens flip</string>
     <string name="fps_rationale_prefix">Fps</string>
+    <string name="flash_rationale_prefix">Flash</string>
+    <string name="flash_on_rationale_prefix">Flash On</string>
+    <string name="flash_auto_rationale_prefix">Flash Auto</string>
+    <string name="flash_llb_rationale_prefix">Low Light Boost</string>
+
+    <string name="video_quality_rationale_prefix">Video quality</string>
+    <string name="video_quality_rationale_suffix_default">the current dynamic range</string>
+    <string name="video_quality_rationale_suffix_sdr">SDR</string>
 
     <string name="front_lens_rationale_prefix">Front lens</string>
     <string name="rear_lens_rationale_prefix">Rear lens</string>
     <string name="no_fixed_fps_rationale_prefix">Fixed frame rate</string>
 
+    <string name="mute_audio_rationale_prefix">Mute</string>
 
     <!-- Version info strings -->
     <string name="version_info_title">Version</string>
-</resources>
\ No newline at end of file
+</resources>
diff --git a/gradle/libs.versions.toml b/gradle/libs.versions.toml
index 36ea132..97ecfb2 100644
--- a/gradle/libs.versions.toml
+++ b/gradle/libs.versions.toml
@@ -1,57 +1,52 @@
 [versions]
 # Used directly in build.gradle.kts files
-compileSdk = "34"
-compileSdkPreview = "VanillaIceCream"
+compileSdk = "35"
+orchestrator = "1.4.2"
 minSdk = "21"
-targetSdk = "34"
-targetSdkPreview = "VanillaIceCream"
-composeCompiler = "1.5.10"
+targetSdk = "35"
+composeCompiler = "1.5.14"
 
 # Used below in dependency definitions
 # Compose and Accompanist versions are linked
 # See https://github.com/google/accompanist?tab=readme-ov-file#compose-versions
-composeBom = "2024.04.00"
-accompanist = "0.34.0"
+composeBom = "2024.11.00"
+accompanist = "0.36.0"
 # kotlinPlugin and composeCompiler are linked
 # See https://developer.android.com/jetpack/androidx/releases/compose-kotlin
-kotlinPlugin = "1.9.22"
-androidGradlePlugin = "8.4.2"
+kotlinPlugin = "1.9.24"
+androidGradlePlugin = "8.7.3"
 protobufPlugin = "0.9.4"
 
-androidxActivityCompose = "1.8.2"
-androidxAppCompat = "1.6.1"
-androidxBenchmark = "1.2.3"
-androidxCamera = "1.4.0-SNAPSHOT"
-androidxCameraViewfinder = "1.0.0-SNAPSHOT"
-androidxConcurrentFutures = "1.1.0"
-androidxCoreKtx = "1.12.0"
-androidxDatastore = "1.0.0"
-androidxGraphicsCore = "1.0.0-beta01"
+androidxActivityCompose = "1.9.3"
+androidxAppCompat = "1.7.0"
+androidxBenchmark = "1.3.3"
+androidxCamera = "1.5.0-SNAPSHOT"
+androidxConcurrentFutures = "1.2.0"
+androidxCoreKtx = "1.15.0"
+androidxDatastore = "1.1.1"
+androidxGraphicsCore = "1.0.2"
 androidxHiltNavigationCompose = "1.2.0"
-androidxLifecycle = "2.7.0"
-androidxNavigationCompose = "2.7.7"
-androidxProfileinstaller = "1.3.1"
-androidxTestEspresso = "3.5.1"
-androidxTestJunit = "1.1.5"
-androidxTestMonitor = "1.6.1"
-androidxTestRules = "1.5.0"
+androidxLifecycle = "2.8.7"
+androidxNavigationCompose = "2.8.4"
+androidxProfileinstaller = "1.4.1"
+androidxTestEspresso = "3.6.1"
+androidxTestJunit = "1.2.1"
+androidxTestMonitor = "1.7.2"
+androidxTestRules = "1.6.1"
 androidxTestUiautomator = "2.3.0"
 androidxTracing = "1.2.0"
 cmake = "3.22.1"
 kotlinxAtomicfu = "0.23.2"
-kotlinxCoroutines = "1.8.0"
-hilt = "2.51"
+kotlinxCoroutines = "1.9.0"
+hilt = "2.52"
 junit = "4.13.2"
-material = "1.11.0"
 mockitoCore = "5.6.0"
 protobuf = "3.25.2"
-robolectric = "4.11.1"
+robolectric = "4.14"
 truth = "1.4.2"
-rules = "1.6.1"
 
 [libraries]
 accompanist-permissions = { module = "com.google.accompanist:accompanist-permissions", version.ref = "accompanist" }
-android-material = { module = "com.google.android.material:material", version.ref = "material" }
 androidx-activity-compose = { module = "androidx.activity:activity-compose", version.ref = "androidxActivityCompose" }
 androidx-appcompat = { module = "androidx.appcompat:appcompat", version.ref = "androidxAppCompat" }
 androidx-benchmark-macro-junit4 = { module = "androidx.benchmark:benchmark-macro-junit4", version.ref = "androidxBenchmark" }
@@ -64,6 +59,7 @@ androidx-lifecycle-livedata = { module = "androidx.lifecycle:lifecycle-livedata-
 androidx-lifecycle-viewmodel-compose = { module = "androidx.lifecycle:lifecycle-viewmodel-compose", version.ref = "androidxLifecycle" }
 androidx-lifecycle-runtime-compose = { module = "androidx.lifecycle:lifecycle-runtime-compose", version.ref = "androidxLifecycle" }
 androidx-navigation-compose = { module = "androidx.navigation:navigation-compose", version.ref = "androidxNavigationCompose" }
+androidx-orchestrator = { module = "androidx.test:orchestrator", version.ref = "orchestrator" }
 androidx-profileinstaller = { module = "androidx.profileinstaller:profileinstaller", version.ref = "androidxProfileinstaller" }
 androidx-rules = { module = "androidx.test:rules", version.ref = "androidxTestRules" }
 androidx-test-monitor = { module = "androidx.test:monitor", version.ref = "androidxTestMonitor" }
@@ -73,7 +69,7 @@ camera-camera2 = { module = "androidx.camera:camera-camera2", version.ref = "and
 camera-core = { module = "androidx.camera:camera-core", version.ref = "androidxCamera" }
 camera-lifecycle = { module = "androidx.camera:camera-lifecycle", version.ref = "androidxCamera" }
 camera-video = { module = "androidx.camera:camera-video", version.ref = "androidxCamera" }
-camera-viewfinder-compose = { module = "androidx.camera:camera-viewfinder-compose", version.ref = "androidxCameraViewfinder" }
+camera-compose = { module = "androidx.camera:camera-compose", version.ref = "androidxCamera" }
 compose-bom = { module = "androidx.compose:compose-bom", version.ref = "composeBom" }
 compose-junit = { module = "androidx.compose.ui:ui-test-junit4" }
 compose-material3 = { module = "androidx.compose.material3:material3" }
@@ -95,7 +91,6 @@ mockito-core = { module = "org.mockito:mockito-core", version.ref = "mockitoCore
 protobuf-kotlin-lite = { module = "com.google.protobuf:protobuf-kotlin-lite", version.ref = "protobuf" }
 robolectric = { module = "org.robolectric:robolectric", version.ref = "robolectric" }
 truth = { module = "com.google.truth:truth", version.ref = "truth" }
-rules = { group = "androidx.test", name = "rules", version.ref = "rules" }
 
 [plugins]
 android-application = { id = "com.android.application", version.ref = "androidGradlePlugin" }
diff --git a/gradle/wrapper/gradle-wrapper.properties b/gradle/wrapper/gradle-wrapper.properties
index 84d16f4..2518d85 100644
--- a/gradle/wrapper/gradle-wrapper.properties
+++ b/gradle/wrapper/gradle-wrapper.properties
@@ -1,6 +1,6 @@
 #Tue Mar 12 23:44:57 PDT 2024
 distributionBase=GRADLE_USER_HOME
 distributionPath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-8.6-bin.zip
+distributionUrl=https\://services.gradle.org/distributions/gradle-8.9-bin.zip
 zipStoreBase=GRADLE_USER_HOME
 zipStorePath=wrapper/dists
diff --git a/settings.gradle.kts b/settings.gradle.kts
index 7c7842f..96740cf 100644
--- a/settings.gradle.kts
+++ b/settings.gradle.kts
@@ -26,7 +26,7 @@ dependencyResolutionManagement {
     repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
     repositories {
         maven {
-            setUrl("https://androidx.dev/snapshots/builds/12167802/artifacts/repository")
+            setUrl("https://androidx.dev/snapshots/builds/12696077/artifacts/repository")
         }
         google()
         mavenCentral()
@@ -41,3 +41,4 @@ include(":data:settings")
 include(":core:common")
 include(":benchmark")
 include(":feature:permissions")
+include(":feature:postcapture")
```

