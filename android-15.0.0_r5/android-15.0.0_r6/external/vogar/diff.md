```diff
diff --git a/bin/vogar b/bin/vogar
index 5f6717e..c1f6b27 100755
--- a/bin/vogar
+++ b/bin/vogar
@@ -3,13 +3,15 @@
 vogar_jar=`dirname $0`/../build/vogar.jar
 if [ ! -f "${vogar_jar}" ]; then
     echo "vogar: info: couldn't find prebuilt ${vogar_jar}; building ..."
-    
+
     if [ -n "${ANDROID_BUILD_TOP}" ]; then
         # We're in an Android build tree, so pull the latest sdk from there.
         # <= ICS uses 'prebuilt', >= JB uses 'prebuilts'.
         android_sdks_dir=`echo ${ANDROID_BUILD_TOP}/prebuilt*/sdk/`
         latest_android_sdk=`ls -1 ${android_sdks_dir} | sort -n | tail -1`
         android_platform_dir=${android_sdks_dir}${latest_android_sdk}
+        export JAVA_HOME=${ANDROID_BUILD_TOP}/prebuilts/jdk/jdk21/linux-x86
+        export PATH=${JAVA_HOME}/bin:${PATH}
     else
         # See if there's an Android SDK on the path.
         adb_path=`which adb`
@@ -20,13 +22,14 @@ if [ ! -f "${vogar_jar}" ]; then
             android_platform_dir=${android_platforms_dir}/${latest_android_platform}
         fi
     fi
-    
+
     if [ ! -d "${android_platform_dir}" ]; then
         echo "vogar: error: couldn't find an SDK on the path, and don't appear to be in an Android build tree"
         exit 1
     fi
-    
+
     ( cd `dirname $0`/.. ; ant -Dandroid.platform.dir=${android_platform_dir} jar ) || exit 1
 fi
 
+set_lunch_paths # include platform prebuilt java, javac, etc in $PATH.
 exec java -jar ${vogar_jar} "$@"
diff --git a/bin/vogar-android b/bin/vogar-android
index 4b82b37..d95cc6f 100755
--- a/bin/vogar-android
+++ b/bin/vogar-android
@@ -17,5 +17,9 @@ if [ -z "$ANDROID_HOST_OUT" ] ; then
   ANDROID_HOST_OUT=${OUT_DIR:-$ANDROID_BUILD_TOP/out}/host/linux-x86
 fi
 
+export JAVA_HOME=${ANDROID_BUILD_TOP}/prebuilts/jdk/jdk21/linux-x86
+export PATH=${JAVA_HOME}/bin:${PATH}
 vogar_jar=${ANDROID_HOST_OUT}/framework/vogar.jar
+
+echo "vogar-android java binary location:"  `which java` 1>&2
 exec java -classpath ${vogar_jar} vogar.Vogar "$@"
```

