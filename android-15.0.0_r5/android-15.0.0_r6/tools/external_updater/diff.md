```diff
diff --git a/README.md b/README.md
index fe1811a..9d0fb68 100644
--- a/README.md
+++ b/README.md
@@ -61,10 +61,12 @@ external/kotlinc, or external/python/cpython3.
 
 ## Configure
 
-To use this tool, a METADATA file must present at the root of the 
-repository. The full definition can be found
-[here](https://android.googlesource.com/platform/tools/external_updater/+/refs/heads/main/metadata.proto).
-Or see example [here](https://android.googlesource.com/platform/external/ImageMagick/+/refs/heads/main/METADATA)
+To use this tool, a METADATA file must present at the root of the
+repository. The full definition can be found in
+[metadata.proto](https://android.googlesource.com/platform/tools/external_updater/+/refs/heads/main/metadata.proto).
+Or
+[external/toybox/METADATA](https://android.googlesource.com/platform/external/toybox/+/refs/heads/main/METADATA)
+is a concrete example.
 
 The most important part in the file is a list of urls.
 `external_updater` will go through all urls and uses the first
@@ -133,7 +135,7 @@ If there are multiple archives in one GitHub release, the one most
 
 After upgrade, files not present in the new tarball will be removed. But we
 explicitly keep files famous in Android tree.
-See [here](https://android.googlesource.com/platform/tools/external_updater/+/refs/heads/main/update_package.sh).
+See [update_package.sh](https://android.googlesource.com/platform/tools/external_updater/+/refs/heads/main/update_package.sh).
 
 If more files need to be reserved, a post_update.sh can be created to copy
 these files over.
@@ -142,12 +144,12 @@ See [example](https://android.googlesource.com/platform/external/kotlinc/+/refs/
 #### Local patches
 
 Local patches can be kept as patches/*.diff. They will be applied after
-upgrade. [example](https://cs.android.com/android/platform/superproject/+/main:external/jsmn/patches/header.diff)
+upgrade. [example](https://cs.android.com/android/platform/superproject/main/+/main:external/jsmn/patches/header.diff)
 
 ## Email notification
 
-There is some support to automatically check updates for all external 
-libraries every hour, send email and change. Currently this is done by 
+There is some support to automatically check updates for all external
+libraries every hour, send email and change. Currently this is done by
 running the following script on a desktop machine.
 
 ```shell
diff --git a/external_updater.py b/external_updater.py
index b4b532d..6e8a304 100644
--- a/external_updater.py
+++ b/external_updater.py
@@ -95,7 +95,7 @@ def commit_message_generator(project_name: str, version: str, path: str, bug: in
     body = textwrap.dedent(f"""
     This project was upgraded with external_updater.
     Usage: tools/external_updater/updater.sh update external/{path}
-    For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md\n\n""")
+    For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md\n\n""")
     if bug is None:
         footer = "Test: TreeHugger"
     else:
diff --git a/fileutils.py b/fileutils.py
index 0432d5a..0ff8b05 100644
--- a/fileutils.py
+++ b/fileutils.py
@@ -223,7 +223,7 @@ def write_metadata(proj_path: Path, metadata: metadata_pb2.MetaData, keep_date:
     usage_hint = textwrap.dedent(f"""\
     # This project was upgraded with external_updater.
     # Usage: tools/external_updater/updater.sh update external/{rel_proj_path}
-    # For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+    # For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
     """)
     text_metadata = usage_hint + text_format.MessageToString(metadata)
diff --git a/regen_bp.sh b/regen_bp.sh
index 8c8276e..4b5ab5f 100755
--- a/regen_bp.sh
+++ b/regen_bp.sh
@@ -35,12 +35,12 @@ function main() {
   # Save Cargo.lock if it existed before this update.
   [ ! -f Cargo.lock ] || mv Cargo.lock Cargo.lock.saved
   if [[ "$CARGO_EMBARGO" = 'true' ]]; then
-    echo "Updating Android.bp: cargo_embargo generate cargo_embargo.json"
+    echo "Updating Android.bp or rules.mk: cargo_embargo generate cargo_embargo.json"
     cargo_embargo generate cargo_embargo.json
   fi
-  if [ -f rules.mk ]; then
-    echo "Updating rules.mk: $SANDBOX $SANDBOX_FLAGS $SANDBOX_RULESMK_FLAGS -- $C2R_SCRIPT_FLAGS"
-    $SANDBOX $SANDBOX_FLAGS $SANDBOX_RULESMK_FLAGS -- $C2R_SCRIPT_FLAGS
+  if [[ "$C2R" = 'true' ]]; then
+    echo "Updating rules.mk: cargo2rulesmk.py $C2R_SCRIPT_FLAGS"
+    cargo2rulesmk.py $C2R_SCRIPT_FLAGS
   fi
   copy_cargo_out_files $*
   rm -rf target.tmp cargo.metadata cargo.out Cargo.lock
@@ -60,22 +60,27 @@ function check_files() {
     EXTERNAL_DIR="$2"  # e.g. rust/crates/bytes
   fi
   [ -f "$SANDBOX" ] || abort "ERROR: cannot find $SANDBOX"
-  LINE1=`head -1 Android.bp || abort "ERROR: cannot find Android.bp"`
-  if [[ "$LINE1" =~ ^.*cargo_embargo.*$ ]]; then
-    CARGO_EMBARGO='true'
-  else
-    echo 'Android.bp header does not contain "cargo_embargo"; skip regen_bp'
-    exit 0
+  if [ -f Android.bp ]; then
+    LINE1=`head -1 Android.bp`
+    if [[ "$LINE1" =~ ^.*cargo_embargo.*$ ]]; then
+      CARGO_EMBARGO='true'
+    fi
   fi
   [ -f Cargo.toml ] || abort "ERROR: cannot find ./Cargo.toml."
 
   if [ -f rules.mk ]; then
     LINE1=`head -1 rules.mk`
-    if [[ ! "$LINE1" =~ ^.*cargo2rulesmk.py.*$ ]]; then
-      echo 'rules.mk header does not contain "cargo2rulesmk.py"; skip regen_bp'
-      exit 0
+    if [[ "$LINE1" =~ ^.*cargo_embargo.*$ ]]; then
+      CARGO_EMBARGO='true'
+    elif [[ "$LINE1" =~ ^.*cargo2rulesmk.py.*$ ]]; then
+      C2R='true'
+      C2R_SCRIPT_FLAGS=`echo "$LINE1" | sed -e 's:^.*cargo2rulesmk.py ::;s:\.$::'`
     fi
-    C2R_SCRIPT_FLAGS=`echo "$LINE1" | sed -e 's:^.*cargo2rulesmk.py ::;s:\.$::'`
+  fi
+
+  if [ ! "$CARGO_EMBARGO" = 'true' ] && [ ! "$C2R" = 'true']; then
+    echo 'No need to run cargo_embargo or cargo2rules.mk.py; skip regen_bp'
+    exit 0
   fi
 }
 
diff --git a/update_package.sh b/update_package.sh
index d5bec8a..794f912 100644
--- a/update_package.sh
+++ b/update_package.sh
@@ -18,6 +18,7 @@
 # invoke directly.
 
 set -e
+shopt -s globstar
 
 tmp_dir=$1
 external_dir=$2
@@ -36,7 +37,6 @@ function CopyIfPresent() {
 }
 
 echo "Copying preserved files..."
-CopyIfPresent "Android.bp"
 CopyIfPresent "Android.mk"
 CopyIfPresent "CleanSpec.mk"
 CopyIfPresent "LICENSE"
@@ -52,6 +52,11 @@ fi
 if compgen -G "$external_dir/cargo_embargo*"; then
     cp -a -f --update=none $external_dir/cargo_embargo* .
 fi
+if compgen -G "$external_dir/**/*.bp"; then
+    pushd "$external_dir"
+    cp -a -f --update=none --parents **/*.bp "$tmp_dir"
+    popd
+fi
 CopyIfPresent "patches"
 CopyIfPresent "post_update.sh"
 CopyIfPresent "OWNERS"
@@ -87,12 +92,6 @@ then
   /bin/bash `dirname $0`/regen_bp.sh $root_dir $external_dir
 fi
 
-if [ -f $tmp_dir/post_update.sh ]
-then
-  echo "Running post update script"
-  $tmp_dir/post_update.sh $tmp_dir $external_dir
-fi
-
 echo "Swapping old and new..."
 second_tmp_dir=`mktemp -d`
 mv $external_dir $second_tmp_dir
diff --git a/updater_utils.py b/updater_utils.py
index cae917d..5f2829e 100644
--- a/updater_utils.py
+++ b/updater_utils.py
@@ -73,6 +73,7 @@ def run_post_update(source_dir: Path, target_dir: Path) -> None:
     """
     post_update_path = os.path.join(source_dir, 'post_update.sh')
     if os.path.isfile(post_update_path):
+        print("Running post update script")
         cmd: Sequence[str | Path] = ['bash', post_update_path, source_dir, target_dir]
         print(f'Running {post_update_path}')
         subprocess.check_call(cmd)
```

