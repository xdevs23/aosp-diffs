```diff
diff --git a/net/test/bpf.py b/net/test/bpf.py
index 80acda7..65b0749 100755
--- a/net/test/bpf.py
+++ b/net/test/bpf.py
@@ -210,7 +210,6 @@ BpfInsn = cstruct.Struct("bpf_insn", "=BBhi", "code dst_src_reg off imm")
 # pylint: enable=invalid-name
 
 libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
-HAVE_EBPF_5_4 = net_test.LINUX_VERSION >= (5, 4, 0)
 
 # set memlock resource 1 GiB
 resource.setrlimit(resource.RLIMIT_MEMLOCK, (1073741824, 1073741824))
diff --git a/tools/coverage_howto.md b/tools/coverage_howto.md
new file mode 100644
index 0000000..80829aa
--- /dev/null
+++ b/tools/coverage_howto.md
@@ -0,0 +1,98 @@
+HOW TO COLLECT KERNEL CODE COVERAGE FROM A TRADEFED TEST RUN
+============================================================
+
+
+## Build and use a kernel with GCOV profile enabled
+Build your kernel with the [`--gcov`](https://android.googlesource.com/kernel/build/+/refs/heads/main/kleaf/docs/gcov.md) option to enable
+GCOV profiling from the kernel. This will also trigger the build to save the required *.gcno files needed to viewing the collected count data.
+
+For example to build a Cuttlefish (CF) kernel with GCOV profiling enabled run:
+```
+$ bazel run --gcov //common-modules/virtual-device:virtual_device_x86_64_dist
+```
+
+## Run your test(s) using tradefed.sh with kernel coverage collection enabled
+'tradefed.sh' can be used to run a number of different types of tests. Adding the appropriate coverage flags
+to the tradefed call will trigger tradefed to take care of mounting debugfs, reseting the gcov counts prior
+to test run, and the collection of gcov data files from debugfs after test completion.
+
+These coverage arguments are:
+```
+--coverage --coverage-toolchain GCOV_KERNEL --auto-collect GCOV_KERNEL_COVERAGE
+```
+
+The following is a full example call running just the `kselftest_net_socket` test in the
+selftests test suite that exists under the 'bazel-bin/common/testcases' directory. The artifact
+output has been redirected to 'tf-logs' for easier reference needed in the next step.
+```
+$ prebuilts/tradefed/filegroups/tradefed/tradefed.sh run commandAndExit \
+    template/local_min --template:map test=suite/test_mapping_suite     \
+    --include-filter 'selftests kselftest_net_socket' --tests-dir=bazel-bin/common/testcases/  \
+    --primary-abi-only --log-file-path tf-logs                          \
+    --coverage --coverage-toolchain GCOV_KERNEL                         \
+    --auto-collect GCOV_KERNEL_COVERAGE
+```
+
+## Create an lcov tracefile out of the gcov tar artifact from test run
+The previously mentioned tradefed run will produce a tar file artifact in the
+tradefed log folder with a name similar to <test>_kernel_coverage_*.tar.gz.
+This tar file is an archive of all the gcov data files collected into debugfs/
+from the profiled device. In order to make it easier to work with this data,
+it needs to be converted to a single lcov tracefile.
+
+The script 'create-tracefile.py' facilitates this generation by handling the
+required unpacking, file path corrections and ultimate 'lcov' call.
+
+An example where we generate a tracefile only including results from net/socket.c.
+(If no source files are specified as included, then all source file data is used):
+```
+$ ./kernel/tests/tools/create-tracefile.py -t tf-logs/ --include net/socket.c
+```
+
+This will create a local tracefile named 'cov.info'.
+
+
+## Visualizing Results
+With the created tracefile there a number of different ways to view coverage data from it.
+Check out 'man lcov' for more options.
+### 1. Text Options
+#### 1.1 Summary
+```
+$ lcov --summary --rc lcov_branch_coverage=1 cov.info
+Reading tracefile cov.info_fix
+Summary coverage rate:
+  lines......: 6.0% (81646 of 1370811 lines)
+  functions..: 9.6% (10285 of 107304 functions)
+  branches...: 3.7% (28639 of 765538 branches)
+```
+#### 1.2 List
+```
+$ lcov --list --rc lcov_branch_coverage=1 cov.info
+Reading tracefile cov.info_fix
+                                               |Lines      |Functions|Branches
+Filename                                       |Rate    Num|Rate  Num|Rate   Num
+================================================================================
+[/usr/local/google/home/joefradley/dev/common-android-mainline-2/common/]
+arch/x86/crypto/aesni-intel_glue.c             |23.9%   623|22.2%  36|15.0%  240
+arch/x86/crypto/blake2s-glue.c                 |50.0%    28|50.0%   2|16.7%   30
+arch/x86/crypto/chacha_glue.c                  | 0.0%   157| 0.0%  10| 0.0%   80
+<truncated>
+virt/lib/irqbypass.c                           | 0.0%   137| 0.0%   6| 0.0%   88
+================================================================================
+                                         Total:| 6.0% 1369k| 9.6%  0M| 3.7% 764k
+```
+### 2. HTML
+The `lcov` tool `genhtml` is used to generate html. To create html with the default settings:
+
+```
+$ genhtml --branch-coverage -o html cov.info
+```
+
+The page can be viewed at `html\index.html`.
+
+Options of interest:
+ * `--frame`: Creates a left hand macro view in a source file view.
+ * `--missed`: Helpful if you want to sort by what source is missing the most as opposed to the default coverage percentages.
+
+
+
diff --git a/tools/create-tracefile.py b/tools/create-tracefile.py
new file mode 100755
index 0000000..c91d510
--- /dev/null
+++ b/tools/create-tracefile.py
@@ -0,0 +1,580 @@
+#!/usr/bin/python3
+# SPDX-License-Identifier: GPL-2.0
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""This utility generates a single lcov tracefile from a gcov tar file."""
+
+import argparse
+import collections
+import fnmatch
+import glob
+import json
+import logging
+import os
+import pathlib
+import re
+import shutil
+import sys
+import tarfile
+
+
+LCOV = "lcov"
+
+# Relative to the root of the source tree.
+OUTPUT_COV_DIR = os.path.join("out", "coverage")
+
+BUILD_CONFIG_CONSTANTS_PATH = os.path.join("common", "build.config.constants")
+
+PREBUILT_CLANG_DIR = os.path.join("prebuilts", "clang", "host", "linux-x86")
+
+PREBUILT_LLVM_COV_PATH_FORMAT = os.path.join(
+    PREBUILT_CLANG_DIR, "clang-%s", "bin", "llvm-cov"
+)
+
+PREBUILT_STABLE_LLVM_COV_PATH = os.path.join(
+    PREBUILT_CLANG_DIR, "llvm-binutils-stable", "llvm-cov"
+)
+
+EXCLUDED_FILES = [
+    "*/security/selinux/av_permissions.h",
+    "*/security/selinux/flask.h",
+]
+
+
+def create_llvm_gcov_sh(
+    llvm_cov_filename: str,
+    llvm_gcov_sh_filename: str,
+) -> None:
+  """Create a shell script that is compatible with gcov.
+
+  Args:
+    llvm_cov_filename: The absolute path to llvm-cov.
+    llvm_gcov_sh_filename: The path to the script to be created.
+  """
+  file_path = pathlib.Path(llvm_gcov_sh_filename)
+  file_path.parent.mkdir(parents=True, exist_ok=True)
+  file_path.write_text(f'#!/bin/bash\nexec {llvm_cov_filename} gcov "$@"')
+  os.chmod(llvm_gcov_sh_filename, 0o755)
+
+
+def generate_lcov_tracefile(
+    gcov_dir: str,
+    kernel_source: str,
+    gcov_filename: str,
+    tracefile_filename: str,
+    included_files: [],
+) -> None:
+  """Call lcov to create tracefile based on gcov data files.
+
+  Args:
+    gcov_dir: Directory that contains the extracted gcov data files as retrieved
+      from debugfs.
+    kernel_source: Directory containing the kernel source same as what was used
+      to build system under test.
+    gcov_filename: The absolute path to gcov or a compatible script.
+    tracefile_filename: The name of tracefile to create.
+    included_files: List of source file pattern to include in tracefile. Can be
+      empty in which case include allo source.
+  """
+  exclude_args = " ".join([f'--exclude "{f}"' for f in EXCLUDED_FILES])
+  include_args = (
+      " ".join([f'--include "{f[0]}"' for f in included_files])
+      if included_files is not None
+      else ""
+  )
+
+  logging.info("Running lcov on %s", gcov_dir)
+  lcov_cmd = (
+      f"{LCOV} -q "
+      "--ignore-errors=source "
+      "--rc branch_coverage=1 "
+      f"-b {kernel_source} "
+      f"-d {gcov_dir} "
+      f"--gcov-tool {gcov_filename} "
+      f"{exclude_args} "
+      f"{include_args} "
+      "--ignore-errors gcov,gcov,unused,unused "
+      "--capture "
+      f"-o {tracefile_filename} "
+  )
+  os.system(lcov_cmd)
+
+
+def update_symlink_from_mapping(filepath: str, prefix_mappings: {}) -> bool:
+  """Update symbolic link based on prefix mappings.
+
+  It will attempt to update the given symbolic link based on the prefix
+  mappings. For every "from" prefix that matches replace with the new "to"
+  value. If the resulting path doesn't exist, try the next.
+
+  Args:
+    filepath: Path of symbolic link to update.
+    prefix_mappings: A multimap where the key is the "from" prefix to match, and
+      the value is an array of "to" values to attempt to replace with.
+
+  Returns:
+    True or false depending on the whether symbolic link was successfully
+      updated to a new path that exists.
+  """
+
+  link_target = os.readlink(filepath)
+  for old_prefix, new_prefix_list in prefix_mappings.items():
+    for new_prefix in new_prefix_list:
+      if link_target.startswith(old_prefix):
+        new_target = os.path.abspath(
+            link_target.replace(old_prefix, new_prefix)
+        )
+        if not os.path.exists(new_target):
+          continue
+        os.unlink(filepath)  # Remove the old symbolic link
+        os.symlink(new_target, filepath)  # Create the updated link
+        return True
+
+  return False
+
+
+def correct_symlinks_in_directory(directory: str, prefix_mappings: {}) -> None:
+  """Recursively traverses a directory, updating symbolic links.
+
+  Replaces 'old_prefix' in the link destination with 'new_prefix'.
+
+  Args:
+    directory: The root directory to traverse.
+    prefix_mappings: Dictionary where the keys are the old prefixes and the
+      values are the new prefixes
+  """
+
+  logging.info("Fixing up symbolic links in %s", directory)
+
+  for root, _, files in os.walk(directory):
+    for filename in files:
+      filepath = os.path.join(root, filename)
+      if os.path.islink(filepath):
+        if not update_symlink_from_mapping(filepath, prefix_mappings):
+          logging.error(
+              "Unable to update link at %s with any prefix mappings: %s",
+              filepath,
+              prefix_mappings,
+          )
+          sys.exit(-1)
+
+
+def find_most_recent_tarfile(path: str, pattern: str = "*.tar.gz") -> str:
+  """Attempts to find a valid tar file given the location.
+
+  If location is a directory finds the most recent tarfile or if location is a
+  a valid tar file returns, if neither of these return None.
+
+  Args:
+    path (str): The path to either a tarfile or a directory.
+    pattern (str, optional): Glob pattern for matching tarfiles. Defaults to
+      "*.tar.gz".
+
+  Returns:
+      str: The path to the most recent tarfile found, or the original path
+           if it was a valid tarfile. None if no matching tarfiles are found.
+  """
+
+  if os.path.isfile(path):
+    if tarfile.is_tarfile(path):
+      return path  # Path is a valid tarfile
+    return None  # Path is a file but not a tar file
+
+  if os.path.isdir(path):
+    results = []
+    for root, _, files in os.walk(path):
+      for file in files:
+        if fnmatch.fnmatch(file, pattern):
+          full_path = os.path.join(root, file)
+          results.append((full_path, os.path.getmtime(full_path)))
+
+    if results:
+      return max(results, key=lambda item: item[1])[
+          0
+      ]  # Return path of the most recent one
+    else:
+      return None  # No tarfiles found in the directory
+
+  return None  # Path is neither a tarfile nor a directory
+
+
+def make_absolute(path: str, base_dir: str) -> str:
+  if os.path.isabs(path):
+    return path
+
+  return os.path.join(base_dir, path)
+
+
+def append_slash(path: str) -> str:
+  if path is not None and path[-1] != "/":
+    path += "/"
+  return path
+
+
+def update_multimap_from_json(
+    json_file: str, base_dir: str, result_multimap: collections.defaultdict
+) -> None:
+  """Reads 'to' and 'from' fields from a JSON file and updates a multimap.
+
+  'from' refers to a bazel sandbox directory.
+  'to' refers to the output directory of gcno files.
+  The multimap is implemented as a dictionary of lists allowing multiple 'to'
+  values for each 'from' key.
+
+  Sample input:
+  [
+    {
+      "from": "/sandbox/1/execroot/_main/out/android-mainline/common",
+      "to": "bazel-out/k8-fastbuild/bin/common/kernel_x86_64/kernel_x86_64_gcno"
+    },
+    {
+      "from": "/sandbox/2/execroot/_main/out/android-mainline/common",
+      "to": "bazel-out/k8-fastbuild/bin/common-modules/virtual-device/virtual_device_x86_64/virtual_device_x86_64_gcno"
+    }
+  ]
+
+  Args:
+    json_file: The path to the JSON file.
+    base_dir: Used if either of the 'to' or 'from' paths are relative to make
+      them absolute by prepending this base_dir value.
+    result_multimap: A multimap that is updated with every 'to' and 'from'
+      found.
+
+  Returns:
+    The updated dictionary.
+  """
+  with open(json_file, "r") as file:
+    data = json.load(file)
+
+  for item in data:
+    to_value = append_slash(item.get("to"))
+    from_value = append_slash(item.get("from"))
+    if to_value and from_value:
+      to_value = make_absolute(to_value, base_dir)
+      from_value = make_absolute(from_value, base_dir)
+      result_multimap[from_value].append(to_value)
+
+
+def read_gcno_mapping_files(
+    search_dir_pattern: str,
+    base_dir: str,
+    result_multimap: collections.defaultdict
+) -> None:
+  """Search a directory for gcno_mapping."""
+  found = False
+  pattern = os.path.join(search_dir_pattern, "gcno_mapping.*.json")
+  for filepath in glob.iglob(pattern, recursive=False):
+    found = True
+    logging.info("Reading %s", filepath)
+    update_multimap_from_json(filepath, base_dir, result_multimap)
+
+  if not found:
+    logging.error("No gcno_mapping in %s", search_dir_pattern)
+
+
+def read_gcno_dir(
+    gcno_dir: str, result_multimap: collections.defaultdict
+) -> None:
+  """Read a directory containing gcno_mapping and gcno files."""
+  multimap = collections.defaultdict(list)
+  read_gcno_mapping_files(gcno_dir, gcno_dir, multimap)
+
+  to_value = append_slash(os.path.abspath(gcno_dir))
+  for from_value in multimap:
+    result_multimap[from_value].append(to_value)
+
+
+def get_testname_from_filename(file_path: str) -> str:
+  filename = os.path.basename(file_path)
+  if "_kernel_coverage" in filename:
+    tmp = filename[: filename.find("_kernel_coverage")]
+    testname = tmp[: tmp.rfind("_")]
+  else:
+    testname = filename[: filename.rfind("_")]
+  return testname
+
+
+def unpack_gcov_tar(file_path: str, output_dir: str) -> str:
+  """Unpack the tar file into the specified directory.
+
+  Args:
+    file_path: The path of the tar file to be unpacked.
+    output_dir: The root directory where the unpacked folder will reside.
+
+  Returns:
+    The path of extracted data.
+  """
+
+  testname = get_testname_from_filename(file_path)
+  logging.info(
+      "Unpacking %s for test %s...", os.path.basename(file_path), testname
+  )
+
+  test_dest_dir = os.path.join(output_dir, testname)
+  if os.path.exists(test_dest_dir):
+    shutil.rmtree(test_dest_dir)
+  os.makedirs(test_dest_dir)
+  shutil.unpack_archive(file_path, test_dest_dir, "tar")
+  return test_dest_dir
+
+
+def get_parent_path(path: str, levels_up: int) -> str:
+  """Goes up a specified number of levels from a given path.
+
+  Args:
+    path: The path to find desired ancestor.
+    levels_up: The number of levels up to go.
+
+  Returns:
+    The desired ancestor of the given path.
+  """
+  p = pathlib.Path(path)
+  for _ in range(levels_up):
+    p = p.parent
+  return str(p)
+
+
+def get_kernel_repo_dir() -> str:
+  # Assume this script is in a kernel source tree:
+  # kernel_repo/kernel/tests/tools/<this_script>
+  return get_parent_path(os.path.abspath(__file__), 4)
+
+
+def load_kernel_clang_version(repo_dir: str) -> str:
+  """Load CLANG_VERSION from build.config.constants."""
+  config_path = os.path.join(repo_dir, BUILD_CONFIG_CONSTANTS_PATH)
+  if not os.path.isfile(config_path):
+    return ""
+  clang_version = ""
+  with open(config_path, "r") as config_file:
+    for line in config_file:
+      match = re.fullmatch(r"\s*CLANG_VERSION=(\S*)\s*", line)
+      if match:
+        clang_version = match.group(1)
+  return clang_version
+
+
+class Config:
+  """The input and output paths of this script."""
+
+  def __init__(self, repo_dir: str, llvm_cov_path: str, tmp_dir: str):
+    """Each argument can be empty."""
+    self._repo_dir = os.path.abspath(repo_dir) if repo_dir else None
+    self._llvm_cov_path = (
+        os.path.abspath(llvm_cov_path) if llvm_cov_path else None
+    )
+    self._tmp_dir = os.path.abspath(tmp_dir) if tmp_dir else None
+    self._repo_out_dir = None
+
+  @property
+  def repo_dir(self) -> str:
+    if not self._repo_dir:
+      self._repo_dir = get_kernel_repo_dir()
+    return self._repo_dir
+
+  def _get_repo_path(self, rel_path: str) -> str:
+    repo_path = os.path.join(self.repo_dir, rel_path)
+    if not os.path.exists(repo_path):
+      logging.error(
+          "%s does not exist. If this script is not in the source directory,"
+          " specify --repo-dir. If you do not have full kernel source,"
+          " specify --llvm-cov, --gcno-dir, and --tmp-dir.",
+          repo_path,
+      )
+      sys.exit(-1)
+    return repo_path
+
+  @property
+  def llvm_cov_path(self) -> str:
+    if not self._llvm_cov_path:
+      # Load the clang version in kernel repo,
+      # or use the stable version in platform repo.
+      clang_version = load_kernel_clang_version(self.repo_dir)
+      self._llvm_cov_path = self._get_repo_path(
+          PREBUILT_LLVM_COV_PATH_FORMAT % clang_version if clang_version else
+          PREBUILT_STABLE_LLVM_COV_PATH
+      )
+    return self._llvm_cov_path
+
+  @property
+  def repo_out_dir(self) -> str:
+    if not self._repo_out_dir:
+      self._repo_out_dir = self._get_repo_path("out")
+    return self._repo_out_dir
+
+  @property
+  def tmp_dir(self) -> str:
+    if not self._tmp_dir:
+      # Temporary directory does not have to exist.
+      self._tmp_dir = os.path.join(self.repo_dir, OUTPUT_COV_DIR)
+    return self._tmp_dir
+
+  @property
+  def llvm_gcov_sh_path(self) -> str:
+    return os.path.join(self.tmp_dir, "tmp", "llvm-gcov.sh")
+
+
+def main() -> None:
+  arg_parser = argparse.ArgumentParser(
+      description="Generate lcov tracefiles from gcov file dumps"
+  )
+
+  arg_parser.add_argument(
+      "-t",
+      dest="tar_location",
+      required=True,
+      help=(
+          "Either a path to a gcov tar file or a directory that contains gcov"
+          " tar file(s). The gcov tar file is expected to be created from"
+          " Tradefed. If a directory is used, will search the entire directory"
+          " for files matching *_kernel_coverage*.tar.gz and select the most"
+          " recent one."
+      ),
+  )
+  arg_parser.add_argument(
+      "-o",
+      dest="out_file",
+      required=False,
+      help="Name of output tracefile generated. Default: cov.info",
+      default="cov.info",
+  )
+  arg_parser.add_argument(
+      "--include",
+      action="append",
+      nargs=1,
+      required=False,
+      help=(
+          "File pattern of source file(s) to include in generated tracefile."
+          " Multiple patterns can be specified by using multiple --include"
+          " command line switches. If no includes are specified all source is"
+          " included."
+      ),
+  )
+  arg_parser.add_argument(
+      "--repo-dir",
+      required=False,
+      help="Root directory of kernel source"
+  )
+  arg_parser.add_argument(
+      "--dist-dir",
+      dest="dist_dirs",
+      action="append",
+      default=[],
+      required=False,
+      help="Dist directory containing gcno mapping files"
+  )
+  arg_parser.add_argument(
+      "--gcno-dir",
+      dest="gcno_dirs",
+      action="append",
+      default=[],
+      required=False,
+      help="Path to an extracted .gcno.tar.gz"
+  )
+  arg_parser.add_argument(
+      "--llvm-cov",
+      required=False,
+      help=(
+          "Path to llvm-cov. Default: "
+          + os.path.join("<repo_dir>", PREBUILT_LLVM_COV_PATH_FORMAT % "*")
+          + " or " + os.path.join("<repo_dir>", PREBUILT_STABLE_LLVM_COV_PATH)
+      )
+  )
+  arg_parser.add_argument(
+      "--tmp-dir",
+      required=False,
+      help=(
+          "Path to the directory where the temporary files are created."
+          " Default: " + os.path.join("<repo_dir>", OUTPUT_COV_DIR)
+      )
+  )
+  arg_parser.add_argument(
+      "--verbose",
+      action="store_true",
+      default=False,
+      help="Enable verbose logging",
+  )
+
+  args = arg_parser.parse_args()
+
+  if args.verbose:
+    logging.basicConfig(level=logging.DEBUG)
+  else:
+    logging.basicConfig(level=logging.WARNING)
+
+  if shutil.which(LCOV) is None:
+    logging.error(
+        "%s is not found and is required for this script. Please install from:",
+        LCOV,
+    )
+    logging.critical("       https://github.com/linux-test-project/lcov")
+    sys.exit(-1)
+
+  if args.repo_dir and not os.path.isdir(args.repo_dir):
+    logging.error("%s is not a directory.", args.repo_dir)
+    sys.exit(-1)
+
+  if args.llvm_cov and not os.path.isfile(args.llvm_cov):
+    logging.error("%s is not a file.", args.llvm_cov)
+    sys.exit(-1)
+
+  for gcno_dir in args.gcno_dirs + args.dist_dirs:
+    if not os.path.isdir(gcno_dir):
+      logging.error("%s is not a directory.", gcno_dir)
+      sys.exit(-1)
+
+  config = Config(args.repo_dir, args.llvm_cov, args.tmp_dir)
+
+  gcno_mappings = collections.defaultdict(list)
+  if not args.gcno_dirs and not args.dist_dirs:
+    dist_dir_pattern = os.path.join(config.repo_out_dir, "**", "dist")
+    read_gcno_mapping_files(dist_dir_pattern, config.repo_dir, gcno_mappings)
+
+  for dist_dir in args.dist_dirs:
+    read_gcno_mapping_files(dist_dir, config.repo_dir, gcno_mappings)
+
+  for gcno_dir in args.gcno_dirs:
+    read_gcno_dir(gcno_dir, gcno_mappings)
+
+  if not gcno_mappings:
+    # read_gcno_mapping_files prints the error messages
+    sys.exit(-1)
+
+  tar_file = find_most_recent_tarfile(
+      args.tar_location, pattern="*kernel_coverage_*.tar.gz"
+  )
+  if tar_file is None:
+    logging.error("Unable to find a gcov tar under %s", args.tar_location)
+    sys.exit(-1)
+
+  gcov_dir = unpack_gcov_tar(tar_file, config.tmp_dir)
+  correct_symlinks_in_directory(gcov_dir, gcno_mappings)
+
+  create_llvm_gcov_sh(
+      config.llvm_cov_path,
+      config.llvm_gcov_sh_path,
+  )
+
+  generate_lcov_tracefile(
+      gcov_dir,
+      config.repo_dir,
+      config.llvm_gcov_sh_path,
+      args.out_file,
+      args.include,
+  )
+
+
+if __name__ == "__main__":
+  main()
diff --git a/tools/flash_device.sh b/tools/flash_device.sh
index ba50c13..52b7d68 100755
--- a/tools/flash_device.sh
+++ b/tools/flash_device.sh
@@ -13,8 +13,9 @@ FETCH_SCRIPT="kernel/tests/tools/fetch_artifact.sh"
 DOWNLOAD_PATH="/tmp/downloaded_images"
 KERNEL_TF_PREBUILT=prebuilts/tradefed/filegroups/tradefed/tradefed.sh
 PLATFORM_TF_PREBUILT=tools/tradefederation/prebuilts/filegroups/tradefed/tradefed.sh
-JDK_PATH=prebuilts/jdk/jdk11/linux-x86
+KERNEL_JDK_PATH=prebuilts/jdk/jdk11/linux-x86
 PLATFORM_JDK_PATH=prebuilts/jdk/jdk21/linux-x86
+LOCAL_JDK_PATH=/usr/local/buildtools/java/jdk11
 LOG_DIR=$PWD/out/test_logs/$(date +%Y%m%d_%H%M%S)
 # Color constants
 BOLD="$(tput bold)"
@@ -33,6 +34,14 @@ EXTRA_OPTIONS=()
 LOCAL_REPO=
 DEVICE_VARIANT="userdebug"
 
+BOARD=
+ABI=
+PRODUCT=
+BUILD_TYPE=
+DEVICE_KERNEL_STRING=
+DEVICE_KERNEL_VERSION=
+SYSTEM_DLKM_INFO=
+
 function print_help() {
     echo "Usage: $0 [OPTIONS]"
     echo ""
@@ -40,30 +49,37 @@ function print_help() {
     echo ""
     echo "Available options:"
     echo "  -s <serial_number>, --serial=<serial_number>"
-    echo "                        The serial number for device to be flashed with."
-    echo "  --skip-build          Skip the image build step. Will build by default if in repo."
-    echo "  --gcov                Build gcov enabled kernel"
-    echo "  --debug               Build debug enabled kernel"
-    echo "  --kasan               Build kasan enabled kernel"
+    echo "                        [Mandatory] The serial number for device to be flashed with."
+    echo "  --skip-build          [Optional] Skip the image build step. Will build by default if in repo."
+    echo "  --gcov                [Optional] Build gcov enabled kernel"
+    echo "  --debug               [Optional] Build debug enabled kernel"
+    echo "  --kasan               [Optional] Build kasan enabled kernel"
     echo "  -pb <platform_build>, --platform-build=<platform_build>"
-    echo "                        The platform build path. Can be a local path or a remote build"
+    echo "                        [Optional] The platform build path. Can be a local path or a remote build"
     echo "                        as ab://<branch>/<build_target>/<build_id>."
-    echo "                        If not specified, it could use the platform build in the local"
-    echo "                        repo."
+    echo "                        If not specified and the script is running from a platform repo,"
+    echo "                        it will use the platform build in the local repo."
+    echo "                        If string 'None' is set, no platform build will be flashed,"
     echo "  -sb <system_build>, --system-build=<system_build>"
-    echo "                        The system build path for GSI testing. Can be a local path or"
+    echo "                        [Optional] The system build path for GSI testing. Can be a local path or"
     echo "                        remote build as ab://<branch>/<build_target>/<build_id>."
     echo "                        If not specified, no system build will be used."
     echo "  -kb <kernel_build>, --kernel-build=<kernel_build>"
-    echo "                        The kernel build path. Can be a local path or a remote build"
+    echo "                        [Optional] The kernel build path. Can be a local path or a remote build"
     echo "                        as ab://<branch>/<build_target>/<build_id>."
-    echo "                        If not specified, it could use the kernel in the local repo."
-    echo "  -vkb <vendor-kernel_build>, --vendor-kernel-build=<kernel_build>"
-    echo "                        The vendor kernel build path. Can be a local path or a remote build"
+    echo "                        If not specified and the script is running from an Android common kernel repo,"
+    echo "                        it will use the kernel in the local repo."
+    echo "  -vkb <vendor_kernel_build>, --vendor-kernel-build=<vendor_kernel_build>"
+    echo "                        [Optional] The vendor kernel build path. Can be a local path or a remote build"
     echo "                        as ab://<branch>/<build_target>/<build_id>."
-    echo "                        If not specified, it could use the kernel in the local repo."
+    echo "                        If not specified, and the script is running from a vendor kernel repo, "
+    echo "                        it will use the kernel in the local repo."
+    echo "  -vkbt <vendor_kernel_build_target>, --vendor-kernel-build-target=<vendor_kernel_build_target>"
+    echo "                        [Optional] The vendor kernel build target to be used to build vendor kernel."
+    echo "                        If not specified, and the script is running from a vendor kernel repo, "
+    echo "                        it will try to find a local build target in the local repo."
     echo "  --device-variant=<device_variant>"
-    echo "                        Device variant such as userdebug, user, or eng."
+    echo "                        [Optional] Device variant such as userdebug, user, or eng."
     echo "                        If not specified, will be userdebug by default."
     echo "  -h, --help            Display this help message and exit"
     echo ""
@@ -155,6 +171,19 @@ function parse_arg() {
                 VENDOR_KERNEL_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
                 shift
                 ;;
+            -vkbt)
+                shift
+                if test $# -gt 0; then
+                    VENDOR_KERNEL_BUILD_TARGET=$1
+                else
+                    print_error "vendor kernel build target is not specified"
+                fi
+                shift
+                ;;
+            --vendor-kernel-build-target=*)
+                VENDOR_KERNEL_BUILD_TARGET=$(echo $1 | sed -e "s/^[^=]*=//g")
+                shift
+                ;;
             --device-variant=*)
                 DEVICE_VARIANT=$(echo $1 | sed -e "s/^[^=]*=//g")
                 shift
@@ -239,8 +268,9 @@ function set_platform_repo () {
 }
 
 function find_repo () {
-    manifest_output=$(grep -e "superproject" -e "gs-pixel" -e "private/google-modules/soc/gs" \
-    -e "kernel/common" -e "common-modules/virtual-device" .repo/manifests/default.xml)
+    manifest_output=$(grep -e "superproject" -e "gs-pixel" -e "kernel/private/devices/google/common" \
+     -e "private/google-modules/soc/gs" -e "kernel/common" -e "common-modules/virtual-device" \
+     .repo/manifests/default.xml)
     case "$manifest_output" in
         *platform/superproject*)
             PLATFORM_REPO_ROOT="$PWD"
@@ -249,30 +279,31 @@ function find_repo () {
             print_info "PLATFORM_REPO_ROOT=$PLATFORM_REPO_ROOT, PLATFORM_VERSION=$PLATFORM_VERSION" "$LINENO"
             if [ -z "$PLATFORM_BUILD" ]; then
                 PLATFORM_BUILD="$PLATFORM_REPO_ROOT"
+            elif [[ "$PLATFORM_BUILD" == "None" ]]; then
+                PLATFORM_BUILD=
             fi
             ;;
-        *kernel/superproject*)
-            if [[ "$manifest_output" == *private/google-modules/soc/gs* ]]; then
-                VENDOR_KERNEL_REPO_ROOT="$PWD"
-                VENDOR_KERNEL_VERSION=$(grep -e "default revision" .repo/manifests/default.xml | \
-                grep -oP 'revision="\K[^"]*')
-                print_info "VENDOR_KERNEL_REPO_ROOT=$VENDOR_KERNEL_REPO_ROOT" "$LINENO"
-                print_info "VENDOR_KERNEL_VERSION=$VENDOR_KERNEL_VERSION" "$LINENO"
-                if [ -z "$VENDOR_KERNEL_BUILD" ]; then
-                    VENDOR_KERNEL_BUILD="$VENDOR_KERNEL_REPO_ROOT"
-                fi
-            elif [[ "$manifest_output" == *common-modules/virtual-device* ]]; then
-                KERNEL_REPO_ROOT="$PWD"
-                KERNEL_VERSION=$(grep -e "kernel/superproject" \
-                .repo/manifests/default.xml | grep -oP 'revision="common-\K[^"]*')
-                print_info "KERNEL_REPO_ROOT=$KERNEL_REPO_ROOT, KERNEL_VERSION=$KERNEL_VERSION" "$LINENO"
-                if [ -z "$KERNEL_BUILD" ]; then
-                    KERNEL_BUILD="$KERNEL_REPO_ROOT"
-                fi
+        *kernel/private/devices/google/common*|*private/google-modules/soc/gs*)
+            VENDOR_KERNEL_REPO_ROOT="$PWD"
+            VENDOR_KERNEL_VERSION=$(grep -e "default revision" .repo/manifests/default.xml | \
+            grep -oP 'revision="\K[^"]*')
+            print_info "VENDOR_KERNEL_REPO_ROOT=$VENDOR_KERNEL_REPO_ROOT" "$LINENO"
+            print_info "VENDOR_KERNEL_VERSION=$VENDOR_KERNEL_VERSION" "$LINENO"
+            if [ -z "$VENDOR_KERNEL_BUILD" ]; then
+                VENDOR_KERNEL_BUILD="$VENDOR_KERNEL_REPO_ROOT"
+            fi
+            ;;
+        *common-modules/virtual-device*)
+            KERNEL_REPO_ROOT="$PWD"
+            KERNEL_VERSION=$(grep -e "kernel/superproject" \
+            .repo/manifests/default.xml | grep -oP 'revision="common-\K[^"]*')
+            print_info "KERNEL_REPO_ROOT=$KERNEL_REPO_ROOT, KERNEL_VERSION=$KERNEL_VERSION" "$LINENO"
+            if [ -z "$KERNEL_BUILD" ]; then
+                KERNEL_BUILD="$KERNEL_REPO_ROOT"
             fi
             ;;
         *)
-            print_warn "Unexpected manifest output. Could not determine repository type." "$LINENO"
+            print_warn "Unknown manifest output. Could not determine repository type." "$LINENO"
             ;;
     esac
 }
@@ -298,36 +329,6 @@ function build_platform () {
     fi
 }
 
-function build_slider () {
-    if [[ "$SKIP_BUILD" = true ]]; then
-        print_warn "--skip-build is set. Do not rebuild slider" "$LINENO"
-        return
-    fi
-    local build_cmd=
-    if [ -f "build_slider.sh" ]; then
-        build_cmd="./build_slider.sh"
-    else
-        build_cmd="tools/bazel run --config=fast"
-        build_cmd+=" //private/google-modules/soc/gs:slider_dist"
-    fi
-    if [ "$GCOV" = true ]; then
-        build_cmd+=" --gcov"
-    fi
-    if [ "$DEBUG" = true ]; then
-        build_cmd+=" --debug"
-    fi
-    if [ "$KASAN" = true ]; then
-        build_cmd+=" --kasan"
-    fi
-    eval "$build_cmd"
-    exit_code=$?
-    if [ $exit_code -eq 0 ]; then
-        print_info "Build kernel succeeded" "$LINENO"
-    else
-        print_error "Build kernel failed with exit code $exit_code" "$LINENO"
-    fi
-}
-
 function build_ack () {
     if [[ "$SKIP_BUILD" = true ]]; then
         print_warn "--skip-build is set. Do not rebuild kernel" "$LINENO"
@@ -357,8 +358,14 @@ function build_ack () {
 function download_platform_build() {
     print_info "Downloading $1 to $PWD" "$LINENO"
     local build_info="$1"
-    local file_patterns=("*$PRODUCT-img-*.zip" "bootloader.img" "radio.img" "vendor_ramdisk.img" "misc_info.txt" "otatools.zip")
+    local file_patterns=("*$PRODUCT-img-*.zip" "bootloader.img" "radio.img" "misc_info.txt" "otatools.zip")
+    if [[ "$1" == *"user/"* ]]; then
+        file_patterns+=("vendor_ramdisk-debug.img")
+    else
+        file_patterns+=("vendor_ramdisk.img")
+    fi
 
+    echo "Downloading ${file_patterns[@]} from $build_info"
     for pattern in "${file_patterns[@]}"; do
         download_file_name="$build_info/$pattern"
         eval "$FETCH_SCRIPT $download_file_name"
@@ -368,6 +375,9 @@ function download_platform_build() {
         else
             print_error "Download $download_file_name failed" "$LINENO"
         fi
+        if [[ "$pattern" == "vendor_ramdisk-debug.img" ]]; then
+            cp vendor_ramdisk-debug.img vendor_ramdisk.img
+        fi
     done
     echo ""
 }
@@ -377,6 +387,7 @@ function download_gki_build() {
     local build_info="$1"
     local file_patterns=("Image.lz4" "boot-lz4.img" "system_dlkm_staging_archive.tar.gz" "system_dlkm.flatten.ext4.img" "system_dlkm.flatten.erofs.img")
 
+    echo "Downloading ${file_patterns[@]} from $build_info"
     for pattern in "${file_patterns[@]}"; do
         download_file_name="$build_info/$pattern"
         eval "$FETCH_SCRIPT $download_file_name"
@@ -397,16 +408,18 @@ function download_vendor_kernel_build() {
     "initramfs.img" "vendor_dlkm.img" "boot.img" "vendor_dlkm.modules.blocklist" "vendor_dlkm.modules.load" )
 
     if [[ "$VENDOR_KERNEL_VERSION" == *"6.6" ]]; then
-        file_patterns+="*vendor_dev_nodes_fragment.img"
+        file_patterns+=("*vendor_dev_nodes_fragment.img")
     fi
 
     case "$PRODUCT" in
         oriole | raven | bluejay)
-            file_patterns+=("gs101-a0.dtb" "gs101-b0.dtb")
+            file_patterns+=( "gs101-a0.dtb" "gs101-b0.dtb")
             ;;
         *)
             ;;
     esac
+
+    echo "Downloading ${file_patterns[@]} from $build_info"
     for pattern in "${file_patterns[@]}"; do
         download_file_name="$build_info/$pattern"
         eval "$FETCH_SCRIPT $download_file_name"
@@ -467,6 +480,7 @@ function flash_gki_build() {
     tf_cli="$TRADEFED \
     run commandAndExit template/local_min --log-level-display VERBOSE \
     --log-file-path=$LOG_DIR -s $SERIAL_NUMBER --disable-verity \
+    --template:map test=example/reboot --num-of-reboots 1 \
     --template:map preparers=template/preparers/gki-device-flash-preparer \
     --extra-file gki_boot.img=$kernel_dir/$boot_image_name"
 
@@ -483,9 +497,9 @@ function flash_vendor_kernel_build() {
     if [ -z "$TRADEFED" ]; then
         find_tradefed_bin
     fi
-    local tf_cli="$TRADEFED \
-    run commandAndExit template/local_min --log-level-display VERBOSE \
+    local tf_cli="$TRADEFED run commandAndExit template/local_min --log-level-display VERBOSE \
     --log-file-path=$LOG_DIR -s $SERIAL_NUMBER --disable-verity \
+    --template:map test=example/reboot --num-of-reboots 1 \
     --template:map preparers=template/preparers/gki-device-flash-preparer"
 
     if [ -d "$DOWNLOAD_PATH/tf_vendor_kernel_dir" ]; then
@@ -509,15 +523,38 @@ function flash_vendor_kernel_build() {
     eval $tf_cli
 }
 
+# Function to check and wait for an ADB device
+function wait_for_adb_device() {
+  local serial_number="$1"  # Optional serial number
+  local timeout_seconds="${2:-300}"  # Timeout in seconds (default 5 minutes)
+
+  local start_time=$(date +%s)
+  local end_time=$((start_time + timeout_seconds))
+
+  while (( $(date +%s) < end_time )); do
+    devices=$(adb devices | grep "$SERIAL_NUMBER" | wc -l)
+
+    if (( devices > 0 )); then
+      print_info "Device $SERIAL_NUMBER is connected with adb" "$LINENO"
+      return 0  # Success
+    fi
+    print_info "Waiting for device $SERIAL_NUMBER in adb devies" "$LINENO"
+    sleep 1
+  done
+
+  print_error "Timeout waiting for $SERIAL_NUMBER in adb devices" "$LINENO"
+}
+
 function flash_platform_build() {
     if [[ "$PLATFORM_BUILD" == ab://* ]] && [ -x "$FLASH_CLI" ]; then
-        local flash_cmd="$FLASH_CLI --nointeractive --force_flash_partitions --disable_verity --skip_build_compatibility_check -w -s $SERIAL_NUMBER "
+        local flash_cmd="$FLASH_CLI --nointeractive --force_flash_partitions --disable_verity -w -s $SERIAL_NUMBER "
         IFS='/' read -ra array <<< "$PLATFORM_BUILD"
         if [ ! -z "${array[3]}" ]; then
-            if [[ "${array[3]}" == *userdebug ]]; then
-                flash_cmd+=" -t userdebug"
-            elif [[ "${array[3]}" == *user ]]; then
-                flash_cmd+=" -t user"
+            local _build_type="${array[3]#*-}"
+            if [[ "$_build_type" == *userdebug ]]; then
+                flash_cmd+=" -t $_build_type"
+            elif [[ "$_build_type" == *user ]]; then
+                flash_cmd+=" -t $_build_type --force_debuggable"
             fi
         fi
         if [ ! -z "${array[4]}" ] && [[ "${array[4]}" != latest* ]]; then
@@ -532,6 +569,7 @@ function flash_platform_build() {
         exit_code=$?
         if [ $exit_code -eq 0 ]; then
             echo "Flash platform succeeded"
+            wait_for_adb_device
             return
         else
             echo "Flash platform build failed with exit code $exit_code"
@@ -547,7 +585,7 @@ function flash_platform_build() {
             if [[ "$PLATFORM_VERSION" == aosp-* ]]; then
                 set_platform_repo "aosp_$PRODUCT"
             else
-                set_platform_repo "PRODUCT"
+                set_platform_repo "$PRODUCT"
             fi
         fi
         eval "vendor/google/tools/flashall  --nointeractive -w -s $SERIAL_NUMBER"
@@ -579,12 +617,13 @@ function flash_platform_build() {
             flash_cmd="${ANDROID_HOST_OUT}/bin/local_flashstation"
         fi
 
-        flash_cmd+=" --nointeractive --force_flash_partitions --skip_build_compatibility_check --disable_verity --disable_verification  -w -s $SERIAL_NUMBER"
+        flash_cmd+=" --nointeractive --force_flash_partitions --disable_verity --disable_verification  -w -s $SERIAL_NUMBER"
         print_info "Flash device with: $flash_cmd" "$LINENO"
         eval "$flash_cmd"
         exit_code=$?
         if [ $exit_code -eq 0 ]; then
             echo "Flash platform succeeded"
+            wait_for_adb_device
             return
         else
             echo "Flash platform build failed with exit code $exit_code"
@@ -740,15 +779,15 @@ function gki_build_only_operation {
     IFS='-' read -ra array <<< "$KERNEL_VERSION"
     case "$KERNEL_VERSION" in
         android-mainline | android15-6.6* | android14-6.1* | android14-5.15* )
-            if [[ "$KERNEL_VERSION" == "$DEVICE_KERNEL_VERSION"* ]] && [ ! -z "$SYSTEM_DLKM_VERSION" ]; then
+            if [[ "$KERNEL_VERSION" == "$DEVICE_KERNEL_VERSION"* ]] && [ ! -z "$SYSTEM_DLKM_INFO" ]; then
                 print_info "Device $SERIAL_NUMBER is with $KERNEL_VERSION kernel. Flash GKI directly" "$LINENO"
-                flash_gki
-            elif [ -z "$SYSTEM_DLKM_VERSION" ]; then
+                flash_gki_build
+            elif [ -z "$SYSTEM_DLKM_INFO" ]; then
                 print_warn "Device $SERIAL_NUMBER is $PRODUCT that doesn't have system_dlkm partition. Can't flash GKI directly. \
 Please add vendor kernel build for example by flag -vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
                 print_error "Can not flash GKI to SERIAL_NUMBER without -vkb <vendor_kernel_build> been specified." "$LINENO"
             elif [[ "$KERNEL_VERSION" != "$DEVICE_KERNEL_VERSION"* ]]; then
-                print_warn "Device $SERIAL_NUMBER is $PRODUCT comes with $DEVICE_KERNEL_STRING kernel. Can't flash GKI directly. \
+                print_warn "Device $PRODUCT $SERIAL_NUMBER comes with $DEVICE_KERNEL_STRING kernel. Can't flash GKI directly. \
 Please add a platform build with $KERNEL_VERSION kernel or add vendor kernel build for example by flag \
 -vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
                 print_error "Cannot flash $KERNEL_VERSION GKI to device directly $SERIAL_NUMBER." "$LINENO"
@@ -757,7 +796,7 @@ Please add a platform build with $KERNEL_VERSION kernel or add vendor kernel bui
         android13-5.15* | android13-5.10* | android12-5.10* | android12-5.4* )
             if [[ "$KERNEL_VERSION" == "$EVICE_KERNEL_VERSION"* ]]; then
                 print_info "Device $SERIAL_NUMBER is with android13-5.15 kernel. Flash GKI directly." "$LINENO"
-                flash_gki
+                flash_gki_build
             else
                 print_warn "Device $SERIAL_NUMBER is $PRODUCT comes with $DEVICE_KERNEL_STRING kernel. Can't flash GKI directly. \
 Please add a platform build with $KERNEL_VERSION kernel or add vendor kernel build for example by flag \
@@ -771,34 +810,43 @@ Please add a platform build with $KERNEL_VERSION kernel or add vendor kernel bui
     esac
 }
 
-function extract_kernel_version() {
+function extract_device_kernel_version() {
     local kernel_string="$1"
     # Check if the string contains '-android'
     if [[ "$kernel_string" == *"-mainline"* ]]; then
-        kernel_version="android-mainline"
+        DEVICE_KERNEL_VERSION="android-mainline"
     elif [[ "$kernel_string" == *"-android"* ]]; then
         # Extract the substring between the first hyphen and the second hyphen
-        local kernel_version=$(echo "$kernel_string" | cut -d '-' -f 2-)
-        kernel_version=$(echo "$kernel_version" | cut -d '-' -f 1)
+        DEVICE_KERNEL_VERSION=$(echo "$kernel_string" | awk -F '-' '{print $2"-"$1}' | cut -d '.' -f -2)
     else
        print_warn "Can not parse $kernel_string into kernel version" "$LINENO"
     fi
-    print_info "Device kernel version is $kernel_version" "$LINENO"
+    print_info "Device kernel version is $DEVICE_KERNEL_VERSION" "$LINENO"
 }
 
 function get_device_info {
-    BOARD=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.board)
-    ABI=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.cpu.abi)
-    PRODUCT=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.product)
-    BUILD_TYPE=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.type)
-    DEVICE_KERNEL_STRING=$(adb -s "$SERIAL_NUMBER" shell uname -r)
-    DEVICE_KERNEL_VERSION=$(extract_kernel_version "$DEVICE_KERNEL_STRING")
-    SYSTEM_DLKM_VERSION=$(adb -s "$SERIAL_NUMBER" shell getprop ro.system_dlkm.build.version.release)
-    if [ -z "$PRODUCT" ]; then
+    adb_count=$(adb devices | grep "$SERIAL_NUMBER" | wc -l)
+    if (( adb_count > 0 )); then
+        BOARD=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.board)
+        ABI=$(adb -s "$SERIAL_NUMBER" shell getprop ro.product.cpu.abi)
+        PRODUCT=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.product)
+        BUILD_TYPE=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.type)
+        DEVICE_KERNEL_STRING=$(adb -s "$SERIAL_NUMBER" shell uname -r)
+        extract_device_kernel_version "$DEVICE_KERNEL_STRING"
+        SYSTEM_DLKM_INFO=$(adb -s "$SERIAL_NUMBER" shell getprop dev.mnt.blk.system_dlkm)
+        print_info "device info: BOARD=$BOARD, ABI=$ABI, PRODUCT=$PRODUCT, BUILD_TYPE=$BUILD_TYPE" "$LINENO"
+        print_info "device info: SYSTEM_DLKM_INFO=$SYSTEM_DLKM_INFO, DEVICE_KERNEL_STRING=$DEVICE_KERNEL_STRING" "$LINENO"
+        return 0
+    fi
+    fastboot_count=$(fastboot devices | grep "$SERIAL_NUMBER" | wc -l)
+    if (( fastboot_count > 0 )); then
         # try get product by fastboot command
         local output=$(fastboot -s "$SERIAL_NUMBER" getvar product 2>&1)
         PRODUCT=$(echo "$output" | grep -oP '^product:\s*\K.*' | cut -d' ' -f1)
+        print_info "$SERIAL_NUMBER is in fastboot with device info: PRODUCT=$PRODUCT" "$LINENO"
+        return 0
     fi
+    print_error "$SERIAL_NUMBER is not connected with adb or fastboot"
 }
 
 function find_tradefed_bin {
@@ -806,15 +854,42 @@ function find_tradefed_bin {
     if [ -f "${ANDROID_HOST_OUT}/bin/tradefed.sh" ] ; then
         TRADEFED="${ANDROID_HOST_OUT}/bin/tradefed.sh"
         print_info "Use the tradefed from the local built path $TRADEFED" "$LINENO"
+        return
     elif [ -f "$PLATFORM_TF_PREBUILT" ]; then
-        TRADEFED="JAVA_HOME=$PLATFORM_JDK_PATH PATH=$PLATFORM_JDK_PATH/bin:$PATH $PLATFORM_TF_PREBUILT"
+        TF_BIN="$PLATFORM_TF_PREBUILT"
         print_info "Local Tradefed is not built yet. Use the prebuilt from $PLATFORM_TF_PREBUILT" "$LINENO"
     elif [ -f "$KERNEL_TF_PREBUILT" ]; then
-        TRADEFED="JAVA_HOME=$JDK_PATH PATH=$JDK_PATH/bin:$PATH $KERNEL_TF_PREBUILT"
+        TF_BIN="$KERNEL_TF_PREBUILT"
+    elif [ -f "/tmp/tradefed/tradefed.sh" ]; then
+        TF_BIN=/tmp/tradefed/tradefed.sh
     # No Tradefed found
     else
-        print_error "Can not find Tradefed binary. Please use flag -tf to specify the binary path." "$LINENO" "$LINENO"
+        mkdir -p "/tmp/tradefed"
+        cd /tmp/tradefed
+        eval "$FETCH_SCRIPT ab://tradefed/tradefed/latest/google-tradefed.zip"
+        exit_code=$?
+        if [ $exit_code -eq 0 ]; then
+            print_info "Download tradefed succeeded" "$LINENO"
+        else
+            print_error "Download tradefed failed" "$LINENO"
+        fi
+        echo ""
+        eval "unzip -oq google-tradefed.zip"
+        TF_BIN=/tmp/tradefed/tradefed.sh
+        cd "$REPO_ROOT_PATH"
+    fi
+    if [ -d "${ANDROID_JAVA_HOME}" ] ; then
+        JDK_PATH="${ANDROID_JAVA_HOME}"
+    elif [ -d "$PLATFORM_JDK_PATH" ] ; then
+        JDK_PATH="$PLATFORM_JDK_PATH"
+    elif [ -d "$KERNEL_JDK_PATH" ] ; then
+        JDK_PATH="$KERNEL_JDK_PATH"
+    elif [ -d "$LOCAL_JDK_PATH" ] ; then
+        JDK_PATH="$LOCAL_JDK_PATH"
+    else
+        print_error "Can't find JAVA JDK path" "$LINENO"
     fi
+    TRADEFED="JAVA_HOME=$JDK_PATH PATH=$JDK_PATH/bin:$PATH $TF_BIN"
 }
 
 adb_checker
@@ -861,12 +936,12 @@ if [ ! -z "$PLATFORM_BUILD" ] && [[ "$PLATFORM_BUILD" != ab://* ]] && [ -d "$PLA
         if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
             find_repo
         fi
-        if [ "$SKIP_BUILD" = false ]; then
+        if [ "$SKIP_BUILD" = false ] && [[ "$PLATFORM_BUILD" != "ab://"* ]] && [[ ! -z "$PLATFORM_BUILD" ]]; then
             if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != *"$PRODUCT" ]]; then
                 if [[ "$PLATFORM_VERSION" == aosp-* ]]; then
                     set_platform_repo "aosp_$PRODUCT"
                 else
-                    set_platform_repo "PRODUCT"
+                    set_platform_repo "$PRODUCT"
                 fi
             elif [[ "${TARGET_PRODUCT}" == *"$PRODUCT" ]]; then
                 echo "TARGET_PRODUCT=${TARGET_PRODUCT}, ANDROID_PRODUCT_OUT=${ANDROID_PRODUCT_OUT}"
@@ -914,14 +989,14 @@ if [[ "$KERNEL_BUILD" == ab://* ]]; then
     KERNEL_VERSION=$(echo "${array[2]}" | sed "s/aosp_kernel-common-//g")
     IFS='-' read -ra array <<< "$KERNEL_VERSION"
     KERNEL_VERSION="${array[0]}-${array[1]}"
-    print_info "$KERNEL_BUILD is KERNEL_VERSION $KERNEL_VERSION"
+    print_info "$KERNEL_BUILD is KERNEL_VERSION $KERNEL_VERSION" "$LINENO"
     if [[ "$KERNEL_VERSION" != "$DEVICE_KERNEL_VERSION"* ]] && [ -z "$PLATFORM_BUILD" ] && [ -z "$VENDOR_KERNEL_BUILD" ]; then
-        print_warn "Device $SERIAL_NUMBER is $PRODUCT comes with $DEVICE_KERNEL_STRING kernel. Can't flash GKI directly. \
-Please add a platform build with $KERNEL_VERSION kernel or add vendor kernel build for example by flag \
--vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
-        print_error "Cannot flash $KERNEL_VERSION GKI to device directly $SERIAL_NUMBER." "$LINENO"
+        print_warn "Device $PRODUCT $SERIAL_NUMBER comes with $DEVICE_KERNEL_STRING $DEVICE_KERNEL_VERSION kernel. \
+Can't flash $KERNEL_VERSION GKI directly. Please use a platform build with the $KERNEL_VERSION kernel \
+or use a vendor kernel build by flag -vkb, for example -vkb -vkb ab://kernel-${array[0]}-gs-pixel-${array[1]}/<kernel_target>/latest" "$LINENO"
+        print_error "Cannot flash $KERNEL_VERSION GKI to device $SERIAL_NUMBER directly." "$LINENO"
     fi
-    print_info "Download kernel build $KERNEL_BUILD"
+    print_info "Download kernel build $KERNEL_BUILD" "$LINENO"
     if [ -d "$DOWNLOAD_PATH/gki_dir" ]; then
         rm -rf "$DOWNLOAD_PATH/gki_dir"
     fi
@@ -972,15 +1047,40 @@ elif [ ! -z "$VENDOR_KERNEL_BUILD" ] && [ -d "$VENDOR_KERNEL_BUILD" ]; then
         if [[ "$PWD" != "$REPO_ROOT_PATH" ]]; then
             find_repo
         fi
-        if [ "$SKIP_BUILD" = false ] ; then
-            if [ ! -f "private/google-modules/soc/gs/BUILD.bazel" ]; then
+        if [ -z "$VENDOR_KERNEL_BUILD_TARGET" ]; then
+            kernel_build_target_count=$(ls build_*.sh | wc -w)
+            if (( kernel_build_target_count == 1 )); then
+                VENDOR_KERNEL_BUILD_TARGET=$(echo $(ls build_*.sh) | sed 's/build_\(.*\)\.sh/\1/')
+            elif (( kernel_build_target_count > 1 )); then
+                print_warn "There are multiple build_*.sh scripts in $PWD, Can't decide vendor kernel build target" "$LINENO"
+                print_error "Please use -vkbt <value> or --vendor-kernel-build-target=<value> to specify a kernel build target" "$LINENO"
+            else
                 # TODO: Add build support to android12 and earlier kernels
-                print_error "bazel build is not supported in $PWD" "$LINENO"
+                print_error "There is no build_*.sh script in $PWD" "$LINENO"
+            fi
+        fi
+        if [ "$SKIP_BUILD" = false ] ; then
+            build_cmd="./build_$VENDOR_KERNEL_BUILD_TARGET.sh"
+            if [ "$GCOV" = true ]; then
+                build_cmd+=" --gcov"
+            fi
+            if [ "$DEBUG" = true ]; then
+                build_cmd+=" --debug"
+            fi
+            if [ "$KASAN" = true ]; then
+                build_cmd+=" --kasan"
+            fi
+            print_info "Build vendor kernel with $build_cmd"
+            eval "$build_cmd"
+            exit_code=$?
+            if [ $exit_code -eq 0 ]; then
+                print_info "Build vendor kernel succeeded"
             else
-                build_slider
+                print_error "Build vendor kernel failed with exit code $exit_code"
+                exit 1
             fi
         fi
-        VENDOR_KERNEL_BUILD="$PWD/out/slider/dist"
+        VENDOR_KERNEL_BUILD="$PWD/out/$VENDOR_KERNEL_BUILD_TARGET/dist"
     fi
 fi
 
@@ -1014,4 +1114,4 @@ else  # Platform build provided
         mixing_build
         flash_platform_build
     fi
-fi
\ No newline at end of file
+fi
diff --git a/tools/launch_cvd.sh b/tools/launch_cvd.sh
index afb893d..d1be8c0 100755
--- a/tools/launch_cvd.sh
+++ b/tools/launch_cvd.sh
@@ -8,12 +8,12 @@ ACLOUD_PREBUILT="prebuilts/asuite/acloud/linux-x86/acloud"
 OPT_SKIP_PRERUNCHECK='--skip-pre-run-check'
 PRODUCT='aosp_cf_x86_64_phone'
 # Color constants
-BOLD="$(tput bold)"
+#BOLD="$(tput bold)" # Unused
 END="$(tput sgr0)"
 GREEN="$(tput setaf 2)"
 RED="$(tput setaf 198)"
 YELLOW="$(tput setaf 3)"
-BLUE="$(tput setaf 34)"
+# BLUE="$(tput setaf 34)" # Unused
 
 SKIP_BUILD=false
 GCOV=false
@@ -84,7 +84,7 @@ function parse_arg() {
                 shift
                 ;;
             --platform-build=*)
-                PLATFORM_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
+                PLATFORM_BUILD=$(echo "$1" | sed -e "s/^[^=]*=//g")
                 shift
                 ;;
             -sb)
@@ -97,7 +97,7 @@ function parse_arg() {
                 shift
                 ;;
             --system-build=*)
-                SYSTEM_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
+                SYSTEM_BUILD=$(echo "$1" | sed -e "s/^[^=]*=//g")
                 shift
                 ;;
             -kb)
@@ -110,19 +110,19 @@ function parse_arg() {
                 shift
                 ;;
             --kernel-build=*)
-                KERNEL_BUILD=$(echo $1 | sed -e "s/^[^=]*=//g")
+                KERNEL_BUILD=$(echo "$1" | sed -e "s/^[^=]*=//g")
                 shift
                 ;;
             --acloud-arg=*)
-                EXTRA_OPTIONS+=($(echo $1 | sed -e "s/^[^=]*=//g")) # Use array append syntax
+                EXTRA_OPTIONS+=("$(echo "$1" | sed -e "s/^[^=]*=//g")") # Use array append syntax
                 shift
                 ;;
             --acloud-bin=*)
-                ACLOUD_BIN=$(echo $1 | sed -e "s/^[^=]*=//g")
+                ACLOUD_BIN=$(echo "$1" | sed -e "s/^[^=]*=//g")
                 shift
                 ;;
             --cf-product=*)
-                PRODUCT=$(echo $1 | sed -e "s/^[^=]*=//g")
+                PRODUCT=$(echo "$1" | sed -e "s/^[^=]*=//g")
                 shift
                 ;;
             --gcov)
@@ -139,7 +139,6 @@ function parse_arg() {
                 ;;
             *)
                 print_error "Unsupported flag: $1" >&2
-                shift
                 ;;
         esac
     done
@@ -155,7 +154,7 @@ function go_to_repo_root() {
     current_dir="$1"
     while [ ! -d ".repo" ] && [ "$current_dir" != "/" ]; do
         current_dir=$(dirname "$current_dir")  # Go up one directory
-        cd "$current_dir"
+        cd "$current_dir" || print_error "Failed to cd to $current_dir"
     done
 }
 
@@ -169,7 +168,7 @@ function print_warn() {
 
 function print_error() {
     echo -e "[$MY_NAME]: ${RED}$1${END}"
-    cd $OLD_PWD
+    cd "$OLD_PWD" || echo "Failed to cd to $OLD_PWD"
     exit 1
 }
 
@@ -206,7 +205,7 @@ function find_repo () {
                 print_info "CF_KERNEL_REPO_ROOT=$CF_KERNEL_REPO_ROOT, \
                 CF_KERNEL_VERSION=$CF_KERNEL_VERSION"
                 if [ -z "$KERNEL_BUILD" ]; then
-                    KERNEL_BUILD="$CF_KERNEL_REPO_ROOT"
+                    KERNEL_BUILD="$CF_KERNEL_REPO_ROOT/out/virtual_device_x86_64/dist"
                 fi
             fi
             ;;
@@ -219,7 +218,7 @@ function find_repo () {
 function rebuild_platform () {
     build_cmd="m -j12"
     print_warn "Flag --skip-build is not set. Rebuilt images at $PWD with: $build_cmd"
-    eval $build_cmd
+    eval "$build_cmd"
     exit_code=$?
     if [ $exit_code -eq 0 ]; then
         if [ -f "${ANDROID_PRODUCT_OUT}/system.img" ]; then
@@ -235,7 +234,7 @@ function rebuild_platform () {
 
 adb_checker
 
-LOCAL_REPO=
+# LOCAL_REPO= $ Unused
 
 OLD_PWD=$PWD
 MY_NAME=$0
@@ -245,36 +244,36 @@ parse_arg "$@"
 FULL_COMMAND_PATH=$(dirname "$PWD/$0")
 REPO_LIST_OUT=$(repo list 2>&1)
 if [[ "$REPO_LIST_OUT" == "error"* ]]; then
-    print_error "Current path $PWD is not in an Android repo. Change path to repo root."
+    echo -e "[$MY_NAME]: ${RED}Current path $PWD is not in an Android repo. Change path to repo root.${END}"
     go_to_repo_root "$FULL_COMMAND_PATH"
     print_info "Changed path to $PWD"
 else
     go_to_repo_root "$PWD"
 fi
 
-REPO_ROOT_PATH="$PWD"
+# REPO_ROOT_PATH="$PWD" # unused
 
 find_repo
 
-if [ "$SKIP_BUILD" = false ] && [ ! -z "$PLATFORM_BUILD" ] && [[ "$PLATFORM_BUILD" != ab://* ]] \
+if [ "$SKIP_BUILD" = false ] && [ -n "$PLATFORM_BUILD" ] && [[ "$PLATFORM_BUILD" != ab://* ]] \
 && [ -d "$PLATFORM_BUILD" ]; then
     # Check if PLATFORM_BUILD is an Android platform repo, if yes rebuild
-    cd "$PLATFORM_BUILD"
+    cd "$PLATFORM_BUILD" || print_error "Failed to cd to $PLATFORM_BUILD"
     PLATFORM_REPO_LIST_OUT=$(repo list 2>&1)
     if [[ "$PLATFORM_REPO_LIST_OUT" != "error"* ]]; then
         go_to_repo_root "$PWD"
         if [ -z "${TARGET_PRODUCT}" ] || [[ "${TARGET_PRODUCT}" != "$PRODUCT" ]]; then
-            set_platform_repo $PRODUCT
+            set_platform_repo "$PRODUCT"
             rebuild_platform
             PLATFORM_BUILD=${ANDROID_PRODUCT_OUT}
         fi
     fi
 fi
 
-if [ "$SKIP_BUILD" = false ] && [ ! -z "$SYSTEM_BUILD" ] && [[ "$SYSTEM_BUILD" != ab://* ]] \
+if [ "$SKIP_BUILD" = false ] && [ -n "$SYSTEM_BUILD" ] && [[ "$SYSTEM_BUILD" != ab://* ]] \
 && [ -d "$SYSTEM_BUILD" ]; then
     # Get GSI build
-    cd "$SYSTEM_BUILD"
+    cd "$SYSTEM_BUILD" || print_error "Failed to cd to $SYSTEM_BUILD"
     SYSTEM_REPO_LIST_OUT=$(repo list 2>&1)
     if [[ "$SYSTEM_REPO_LIST_OUT" != "error"* ]]; then
         go_to_repo_root "$PWD"
@@ -286,18 +285,20 @@ if [ "$SKIP_BUILD" = false ] && [ ! -z "$SYSTEM_BUILD" ] && [[ "$SYSTEM_BUILD" !
     fi
 fi
 
-if [ "$SKIP_BUILD" = false ] && [ ! -z "$KERNEL_BUILD" ] && [[ "$KERNEL_BUILD" != ab://* ]] \
+if [ "$SKIP_BUILD" = false ] && [ -n "$KERNEL_BUILD" ] && [[ "$KERNEL_BUILD" != ab://* ]] \
 && [ -d "$KERNEL_BUILD" ]; then
     # Check if kernel repo is provided, if yes rebuild
-    cd "$KERNEL_BUILD"
+    cd "$KERNEL_BUILD" || print_error "Failed to cd to $KERNEL_BUILD"
     KERNEL_REPO_LIST_OUT=$(repo list 2>&1)
     if [[ "$KERNEL_REPO_LIST_OUT" != "error"* ]]; then
         go_to_repo_root "$PWD"
         if [ ! -f "common-modules/virtual-device/BUILD.bazel" ]; then
-            # TODO: Add build support to android12 and earlier kernels
+            # TODO(b/365590299): Add build support to android12 and earlier kernels
             print_error "bazel build common-modules/virtual-device is not supported in this kernel tree"
         fi
-        KERNEL_VERSION=$(grep -e "common-modules/virtual-device" .repo/manifests/default.xml | grep -oP 'revision="\K[^"]*')
+
+        # KERNEL_VERSION=$(grep -e "common-modules/virtual-device" .repo/manifests/default.xml | grep -oP 'revision="\K[^"]*') # unused
+
         # Build a new kernel
         build_cmd="tools/bazel run --config=fast"
         if [ "$GCOV" = true ]; then
@@ -311,7 +312,7 @@ if [ "$SKIP_BUILD" = false ] && [ ! -z "$KERNEL_BUILD" ] && [[ "$KERNEL_BUILD" !
         fi
         build_cmd+=" //common-modules/virtual-device:virtual_device_x86_64_dist"
         print_warn "Flag --skip-build is not set. Rebuild the kernel with: $build_cmd."
-        eval $build_cmd
+        eval "$build_cmd"
         exit_code=$?
         if [ $exit_code -eq 0 ]; then
             print_info "$build_cmd succeeded"
@@ -324,7 +325,7 @@ fi
 
 
 if [ -z "$ACLOUD_BIN" ] || ! [ -x "$ACLOUD_BIN" ]; then
-    local output=$(which acloud 2>&1)
+    output=$(which acloud 2>&1)
     if [ -z "$output" ]; then
         print_info "Use acloud binary from $ACLOUD_PREBUILT"
         ACLOUD_BIN="$ACLOUD_PREBUILT"
@@ -352,11 +353,11 @@ elif [[ "$PLATFORM_BUILD" == ab://* ]]; then
     acloud_cli+=" --branch ${array[2]}"
 
     # Check if array[3] exists before using it
-    if [ ${#array[@]} -ge 3 ] && [ ! -z "${array[3]}" ]; then
+    if [ ${#array[@]} -ge 3 ] && [ -n "${array[3]}" ]; then
         acloud_cli+=" --build-target ${array[3]}"
 
         # Check if array[4] exists and is not 'latest' before using it
-        if [ ${#array[@]} -ge 4 ] && [ ! -z "${array[4]}" ] && [ "${array[4]}" != 'latest' ]; then
+        if [ ${#array[@]} -ge 4 ] && [ -n "${array[4]}" ] && [ "${array[4]}" != 'latest' ]; then
             acloud_cli+=" --build-id ${array[4]}"
         fi
     fi
@@ -371,11 +372,11 @@ elif [[ "$KERNEL_BUILD" == ab://* ]]; then
     acloud_cli+=" --kernel-branch ${array[2]}"
 
     # Check if array[3] exists before using it
-    if [ ${#array[@]} -ge 3 ] && [ ! -z "${array[3]}" ]; then
+    if [ ${#array[@]} -ge 3 ] && [ -n "${array[3]}" ]; then
         acloud_cli+=" --kernel-build-target ${array[3]}"
 
         # Check if array[4] exists and is not 'latest' before using it
-        if [ ${#array[@]} -ge 4 ] && [ ! -z "${array[4]}" ] && [ "${array[4]}" != 'latest' ]; then
+        if [ ${#array[@]} -ge 4 ] && [ -n "${array[4]}" ] && [ "${array[4]}" != 'latest' ]; then
             acloud_cli+=" --kernel-build-id ${array[4]}"
         fi
     fi
@@ -390,11 +391,11 @@ elif [[ "$SYSTEM_BUILD" == ab://* ]]; then
     acloud_cli+=" --system-branch ${array[2]}"
 
      # Check if array[3] exists before using it
-    if [ ${#array[@]} -ge 3 ] && [ ! -z "${array[3]}" ]; then
+    if [ ${#array[@]} -ge 3 ] && [ -n "${array[3]}" ]; then
         acloud_cli+=" --system-build-target ${array[3]}"
 
         # Check if array[4] exists and is not 'latest' before using it
-        if [ ${#array[@]} -ge 4 ] && [ ! -z "${array[4]}" ] && [ "${array[4]}" != 'latest' ]; then
+        if [ ${#array[@]} -ge 4 ] && [ -n "${array[4]}" ] && [ "${array[4]}" != 'latest' ]; then
             acloud_cli+=" --system-build-id ${array[4]}"
         fi
     fi
@@ -402,6 +403,6 @@ else
     acloud_cli+=" --local-system-image $SYSTEM_BUILD"
 fi
 
-acloud_cli+=" ${EXTRA_OPTIONS[@]}"
+acloud_cli+=" ${EXTRA_OPTIONS[*]}"
 print_info "Launch CVD with command: $acloud_cli"
 eval "$acloud_cli"
diff --git a/tools/run_test_only.sh b/tools/run_test_only.sh
index 0c2d568..65442f7 100755
--- a/tools/run_test_only.sh
+++ b/tools/run_test_only.sh
@@ -12,8 +12,10 @@ PLATFORM_JDK_PATH=prebuilts/jdk/jdk21/linux-x86
 DEFAULT_LOG_DIR=$PWD/out/test_logs/$(date +%Y%m%d_%H%M%S)
 DOWNLOAD_PATH="/tmp/downloaded_tests"
 GCOV=false
+CREATE_TRACEFILE_SCRIPT="kernel/tests/tools/create-tracefile.py"
 FETCH_SCRIPT="kernel/tests/tools/fetch_artifact.sh"
 TRADEFED=
+TRADEFED_GCOV_OPTIONS=" --coverage --coverage-toolchain GCOV_KERNEL --auto-collect GCOV_KERNEL_COVERAGE"
 TEST_ARGS=()
 TEST_DIR=
 TEST_NAMES=()
@@ -40,15 +42,27 @@ function go_to_repo_root() {
 }
 
 function print_info() {
-    echo "[$MY_NAME]: ${GREEN}$1${END}"
+    local log_prompt=$MY_NAME
+    if [ ! -z "$2" ]; then
+        log_prompt+=" line $2"
+    fi
+    echo "[$log_prompt]: ${GREEN}$1${END}"
 }
 
 function print_warn() {
-    echo "[$MY_NAME]: ${YELLOW}$1${END}"
+    local log_prompt=$MY_NAME
+    if [ ! -z "$2" ]; then
+        log_prompt+=" line $2"
+    fi
+    echo "[$log_prompt]: ${ORANGE}$1${END}"
 }
 
 function print_error() {
-    echo -e "[$MY_NAME]: ${RED}$1${END}"
+    local log_prompt=$MY_NAME
+    if [ ! -z "$2" ]; then
+        log_prompt+=" line $2"
+    fi
+    echo -e "[$log_prompt]: ${RED}$1${END}"
     cd $OLD_PWD
     exit 1
 }
@@ -67,15 +81,14 @@ function print_help() {
     echo "                        as ab://<branch>/<build_target>/<build_id>/<file_name>."
     echo "                        If not specified, it will use the tests in the local"
     echo "                        repo."
-    echo "  -tl <test_log_dir>, --test_log=<test_log_dir>"
+    echo "  -tl <test_log_dir>, --test-log=<test_log_dir>"
     echo "                        The test log dir. Use default out/test_logs if not specified."
-    echo "  -ta <extra_arg>, --extra-arg=<extra_arg>"
+    echo "  -ta <test_arg>, --test-arg=<test_arg>"
     echo "                        Additional tradefed command arg. Can be repeated."
     echo "  -t <test_name>, --test=<test_name>  The test name. Can be repeated."
     echo "                        If test is not specified, no tests will be run."
     echo "  -tf <tradefed_binary_path>, --tradefed-bin=<tradefed_binary_path>"
     echo "                        The alternative tradefed binary to run test with."
-    echo "  --skip-build          Skip the platform build step. Will build by default if in repo."
     echo "  --gcov                Collect coverage data from the test result"
     echo "  -h, --help            Display this help message and exit"
     echo ""
@@ -111,8 +124,19 @@ function run_test_in_platform_repo () {
        [[ "${TARGET_PRODUCT}" == *"x86"* && "${PRODUCT}" != *"x86"* ]]; then
        set_platform_repo
     fi
-    eval atest " ${TEST_NAMES[@]}" -s "$SERIAL_NUMBER"
+    atest_cli="atest ${TEST_NAMES[*]} -s $SERIAL_NUMBER --"
+    if $GCOV; then
+        atest_cli+="$TRADEFED_GCOV_OPTIONS"
+    fi
+    eval "$atest_cli" "${TEST_ARGS[*]}"
     exit_code=$?
+
+    if $GCOV; then
+        atest_log_dir="/tmp/atest_result_$USER/LATEST"
+        create_tracefile_cli="$CREATE_TRACEFILE_SCRIPT -t $atest_log_dir/log -o $atest_log_dir/cov.info"
+        print_info "Skip creating tracefile. If you have full kernel source, run the following command:"
+        print_info "$create_tracefile_cli"
+    fi
     cd $OLD_PWD
     exit $exit_code
 }
@@ -187,7 +211,7 @@ while test $# -gt 0; do
             shift
             ;;
         --test*)
-            TEST_NAMES+=$1
+            TEST_NAMES+=$(echo $1 | sed -e "s/^[^=]*=//g")
             shift
             ;;
         -tf)
@@ -214,20 +238,20 @@ done
 
 # Ensure SERIAL_NUMBER is provided
 if [ -z "$SERIAL_NUMBER" ]; then
-    print_error "Device serial is not provided with flag -s <serial_number>."
+    print_error "Device serial is not provided with flag -s <serial_number>." "$LINENO"
 fi
 
 # Ensure TEST_NAMES is provided
 if [ -z "$TEST_NAMES" ]; then
-    print_error "No test is specified with flag -t <test_name>."
+    print_error "No test is specified with flag -t <test_name>." "$LINENO"
 fi
 
 FULL_COMMAND_PATH=$(dirname "$PWD/$0")
 REPO_LIST_OUT=$(repo list 2>&1)
 if [[ "$REPO_LIST_OUT" == "error"* ]]; then
-    print_warn "Current path $PWD is not in an Android repo. Change path to repo root."
+    print_warn "Current path $PWD is not in an Android repo. Change path to repo root." "$LINENO"
     go_to_repo_root "$FULL_COMMAND_PATH"
-    print_info "Changed path to $PWD"
+    print_info "Changed path to $PWD" "$LINENO"
 else
     go_to_repo_root "$PWD"
 fi
@@ -248,10 +272,10 @@ PRODUCT=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.product)
 BUILD_TYPE=$(adb -s "$SERIAL_NUMBER" shell getprop ro.build.type)
 
 if [ -z "$TEST_DIR" ]; then
-    print_warn "Flag -td <test_dir> is not provided. Will use the default test directory"
-    if [[ "$REPO_LIST_OUT" == *"vendor/google/tools"* ]]; then
+    print_warn "Flag -td <test_dir> is not provided. Will use the default test directory" "$LINENO"
+    if [[ "$REPO_LIST_OUT" == *"build/make"* ]]; then
         # In the platform repo
-        print_info "Run test with atest"
+        print_info "Run test with atest" "$LINENO"
         run_test_in_platform_repo
     elif [[ "$BOARD" == "cutf"* ]] && [[ "$REPO_LIST_OUT" == *"common-modules/virtual-device"* ]]; then
         # In the android kernel repo
@@ -260,14 +284,14 @@ if [ -z "$TEST_DIR" ]; then
         elif [[ "$ABI" == "x86_64"* ]]; then
             TEST_DIR="$REPO_ROOT_PATH/out/virtual_device_x86_64/dist/tests.zip"
         else
-            print_error "No test builds for $ABI Cuttlefish in $REPO_ROOT_PATH"
+            print_error "No test builds for $ABI Cuttlefish in $REPO_ROOT_PATH" "$LINENO"
         fi
     elif [[ "$BOARD" == "raven"* || "$BOARD" == "oriole"* ]] && [[ "$REPO_LIST_OUT" == *"private/google-modules/display"* ]]; then
         TEST_DIR="$REPO_ROOT_PATH/out/slider/dist/tests.zip"
     elif [[ "$ABI" == "arm64"* ]] && [[ "$REPO_LIST_OUT" == *"kernel/common"* ]]; then
         TEST_DIR="$REPO_ROOT_PATH/out/kernel_aarch64/dist/tests.zip"
     else
-        print_error "No test builds for $ABI $BOARD in $REPO_ROOT_PATH"
+        print_error "No test builds for $ABI $BOARD in $REPO_ROOT_PATH" "$LINENO"
     fi
 fi
 
@@ -282,21 +306,21 @@ if [[ "$TEST_DIR" == ab://* ]]; then
     if [ -d "$DOWNLOAD_PATH" ]; then
         rm -rf "$DOWNLOAD_PATH"
     fi
-    mkdir -p "$DOWNLOAD_PATH" || $(print_error "Fail to create directory $DOWNLOAD_PATH")
-    cd $DOWNLOAD_PATH || $(print_error "Fail to go to $DOWNLOAD_PATH")
+    mkdir -p "$DOWNLOAD_PATH" || $(print_error "Fail to create directory $DOWNLOAD_PATH" "$LINENO")
+    cd $DOWNLOAD_PATH || $(print_error "Fail to go to $DOWNLOAD_PATH" "$LINENO")
     file_name=${TEST_DIR##*/}
     eval "$FETCH_SCRIPT $TEST_DIR"
     exit_code=$?
     if [ $exit_code -eq 0 ]; then
-        print_info "$TEST_DIR is downloaded succeeded"
+        print_info "$TEST_DIR is downloaded succeeded" "$LINENO"
     else
-        print_error "Failed to download $TEST_DIR"
+        print_error "Failed to download $TEST_DIR" "$LINENO"
     fi
 
     file_name=$(ls $file_name)
     # Check if the download was successful
     if [ ! -f "${file_name}" ]; then
-        print_error "Failed to download ${file_name}"
+        print_error "Failed to download ${file_name}" "$LINENO"
     fi
     TEST_DIR="$DOWNLOAD_PATH/$file_name"
 elif [ ! -z "$TEST_DIR" ]; then
@@ -305,15 +329,15 @@ elif [ ! -z "$TEST_DIR" ]; then
     elif [ -f "$TEST_DIR" ]; then
         test_file_path=$(dirname "$TEST_DIR")
     else
-        print_error "$TEST_DIR is neither a directory or file"
+        print_error "$TEST_DIR is neither a directory or file"  "$LINENO"
     fi
-    cd "$test_file_path" || $(print_error "Failed to go to $test_file_path")
+    cd "$test_file_path" || $(print_error "Failed to go to $test_file_path" "$LINENO")
     TEST_REPO_LIST_OUT=$(repo list 2>&1)
     if [[ "$TEST_REPO_LIST_OUT" == "error"* ]]; then
-        print_info "Test path $test_file_path is not in an Android repo. Will use $TEST_DIR directly."
-    elif [[ "$TEST_REPO_LIST_OUT" == *"vendor/google/tools"* ]]; then
+        print_info "Test path $test_file_path is not in an Android repo. Will use $TEST_DIR directly." "$LINENO"
+    elif [[ "$TEST_REPO_LIST_OUT" == *"build/make"* ]]; then
         # Test_dir is from the platform repo
-        print_info "Test_dir $TEST_DIR is from Android platform repo. Run test with atest"
+        print_info "Test_dir $TEST_DIR is from Android platform repo. Run test with atest" "$LINENO"
         go_to_repo_root "$PWD"
         run_test_in_platform_repo
     fi
@@ -324,9 +348,12 @@ if [[ "$TEST_DIR" == *".zip"* ]]; then
     filename=${TEST_DIR##*/}
     new_test_dir="$REPO_ROOT_PATH/out/tests"
     if [ ! -d "$new_test_dir" ]; then
-        mkdir -p "$new_test_dir" || $(print_error "Failed to make directory $new_test_dir")
+        mkdir -p "$new_test_dir" || $(print_error "Failed to make directory $new_test_dir" "$LINENO")
+    else
+        folder_name="${filenamef%.*}"
+        rm -r "$new_test_dir/$folder_name"
     fi
-    unzip -oq "$TEST_DIR" -d "$new_test_dir" || $(print_error "Failed to unzip $TEST_DIR to $new_test_dir")
+    unzip -oq "$TEST_DIR" -d "$new_test_dir" || $(print_error "Failed to unzip $TEST_DIR to $new_test_dir" "$LINENO")
     case $filename in
         "android-vts.zip" | "android-cts.zip")
         new_test_dir+="/$(echo $filename | sed "s/.zip//g")"
@@ -337,56 +364,71 @@ if [[ "$TEST_DIR" == *".zip"* ]]; then
     TEST_DIR="$new_test_dir" # Update TEST_DIR to the unzipped directory
 fi
 
-print_info "Will run tests with test artifacts in $TEST_DIR"
+print_info "Will run tests with test artifacts in $TEST_DIR" "$LINENO"
 
 if [ -f "${TEST_DIR}/tools/vts-tradefed" ]; then
     TRADEFED="${TEST_DIR}/tools/vts-tradefed"
-    print_info "Will run tests with vts-tradefed from $TRADEFED"
+    print_info "Will run tests with vts-tradefed from $TRADEFED" "$LINENO"
+    print_info "Many VTS tests need WIFI connection, please make sure WIFI is connected before you run the test." "$LINENO"
     tf_cli="$TRADEFED run commandAndExit \
     vts --skip-device-info --log-level-display info --log-file-path=$LOG_DIR \
     $TEST_FILTERS -s $SERIAL_NUMBER"
 elif [ -f "${TEST_DIR}/tools/cts-tradefed" ]; then
     TRADEFED="${TEST_DIR}/tools/cts-tradefed"
-    print_info "Will run tests with cts-tradefed from $TRADEFED"
+    print_info "Will run tests with cts-tradefed from $TRADEFED" "$LINENO"
+    print_info "Many CTS tests need WIFI connection, please make sure WIFI is connected before you run the test." "$LINENO"
     tf_cli="$TRADEFED run commandAndExit cts --skip-device-info \
     --log-level-display info --log-file-path=$LOG_DIR \
     $TEST_FILTERS -s $SERIAL_NUMBER"
 elif [ -f "${ANDROID_HOST_OUT}/bin/tradefed.sh" ] ; then
     TRADEFED="${ANDROID_HOST_OUT}/bin/tradefed.sh"
-    print_info "Use the tradefed from the local built path $TRADEFED"
+    print_info "Use the tradefed from the local built path $TRADEFED" "$LINENO"
     tf_cli="$TRADEFED run commandAndExit template/local_min \
     --log-level-display info --log-file-path=$LOG_DIR \
     --template:map test=suite/test_mapping_suite  --tests-dir=$TEST_DIR\
     $TEST_FILTERS -s $SERIAL_NUMBER"
 elif [ -f "$PLATFORM_TF_PREBUILT" ]; then
     TRADEFED="JAVA_HOME=$PLATFORM_JDK_PATH PATH=$PLATFORM_JDK_PATH/bin:$PATH $PLATFORM_TF_PREBUILT"
-    print_info "Local Tradefed is not built yet. Use the prebuilt from $PLATFORM_TF_PREBUILT"
+    print_info "Local Tradefed is not built yet. Use the prebuilt from $PLATFORM_TF_PREBUILT" "$LINENO"
     tf_cli="$TRADEFED run commandAndExit template/local_min \
     --log-level-display info --log-file-path=$LOG_DIR \
     --template:map test=suite/test_mapping_suite  --tests-dir=$TEST_DIR\
     $TEST_FILTERS -s $SERIAL_NUMBER"
 elif [ -f "$KERNEL_TF_PREBUILT" ]; then
     TRADEFED="JAVA_HOME=$JDK_PATH PATH=$JDK_PATH/bin:$PATH $KERNEL_TF_PREBUILT"
-    print_info "Use the tradefed prebuilt from $KERNEL_TF_PREBUILT"
+    print_info "Use the tradefed prebuilt from $KERNEL_TF_PREBUILT" "$LINENO"
     tf_cli="$TRADEFED run commandAndExit template/local_min \
     --log-level-display info --log-file-path=$LOG_DIR \
     --template:map test=suite/test_mapping_suite  --tests-dir=$TEST_DIR\
     $TEST_FILTERS -s $SERIAL_NUMBER"
 # No Tradefed found
 else
-    print_error "Can not find Tradefed binary. Please use flag -tf to specify the binary path."
+    print_error "Can not find Tradefed binary. Please use flag -tf to specify the binary path." "$LINENO"
 fi
 
 # Construct the TradeFed command
 
 # Add GCOV options if enabled
 if $GCOV; then
-    tf_cli+=" --coverage --coverage-toolchain GCOV_KERNEL --auto-collect GCOV_KERNEL_COVERAGE"
+    tf_cli+=$TRADEFED_GCOV_OPTIONS
 fi
 
 # Evaluate the TradeFed command with extra arguments
-print_info "Run test with: $tf_cli" "${EXTRA_ARGS[*]}"
-eval "$tf_cli" "${EXTRA_ARGS[*]}"
+print_info "Run test with: $tf_cli" "${TEST_ARGS[*]}" "$LINENO"
+eval "$tf_cli" "${TEST_ARGS[*]}"
 exit_code=$?
+
+if $GCOV; then
+    create_tracefile_cli="$CREATE_TRACEFILE_SCRIPT -t $LOG_DIR -o $LOG_DIR/cov.info"
+    if [ -f $KERNEL_TF_PREBUILT ]; then
+        print_info "Create tracefile with $create_tracefile_cli" "$LINENO"
+        $create_tracefile_cli && \
+        print_info "Created tracefile at $LOG_DIR/cov.info" "$LINENO"
+    else
+        print_info "Skip creating tracefile. If you have full kernel source, run the following command:" "$LINENO"
+        print_info "$create_tracefile_cli" "$LINENO"
+    fi
+fi
+
 cd $OLD_PWD
 exit $exit_code
```

