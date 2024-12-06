```diff
diff --git a/Changes.md b/Changes.md
index fc15e601b6..9f2449c2c3 100644
--- a/Changes.md
+++ b/Changes.md
@@ -43,14 +43,9 @@ within a product configuration .mk file, board config .mk file, or buildspec.mk.
 The path set when running builds now makes the `python` executable point to python 3,
 whereas on previous versions it pointed to python 2. If you still have python 2 scripts,
 you can change the shebang line to use `python2` explicitly. This only applies for
-scripts run directly from makefiles, or from soong genrules. This behavior can be
-temporarily overridden by setting the `BUILD_BROKEN_PYTHON_IS_PYTHON2` environment
-variable to `true`. It's only an environment variable and not a product config variable
-because product config sometimes calls python code.
-
-In addition, `python_*` soong modules no longer allow python 2. This can be temporarily
-overridden by setting the `BUILD_BROKEN_USES_SOONG_PYTHON2_MODULES` product configuration
-variable to `true`.
+scripts run directly from makefiles, or from soong genrules.
+
+In addition, `python_*` soong modules no longer allow python 2.
 
 Python 2 is slated for complete removal in V.
 
diff --git a/CleanSpec.mk b/CleanSpec.mk
index f56227955a..8c30883864 100644
--- a/CleanSpec.mk
+++ b/CleanSpec.mk
@@ -791,6 +791,9 @@ $(call add-clean-step, find $(OUT_DIR) -type f -name "*.jar" -print0 | xargs -0
 $(call add-clean-step, rm -f $(PRODUCT_OUT)/dexpreopt_config/dexpreopt.config)
 $(call add-clean-step, rm -f $(PRODUCT_OUT)/dexpreopt_config/dexpreopt_soong.config)
 
+# Clear out Soong .intermediates directory regarding removal of hashed subdir
+$(call add-clean-step, rm -rf $(OUT_DIR)/soong/.intermediates)
+
 # ************************************************
 # NEWER CLEAN STEPS MUST BE AT THE END OF THE LIST
 # ************************************************
diff --git a/ci/Android.bp b/ci/Android.bp
index 104f517ccd..6d4ac35517 100644
--- a/ci/Android.bp
+++ b/ci/Android.bp
@@ -71,11 +71,37 @@ python_test_host {
     },
 }
 
+python_test_host {
+    name: "optimized_targets_test",
+    main: "optimized_targets_test.py",
+    pkg_path: "testdata",
+    srcs: [
+        "optimized_targets_test.py",
+    ],
+    libs: [
+        "build_test_suites",
+        "pyfakefs",
+    ],
+    test_options: {
+        unit_test: true,
+    },
+    data: [
+        ":py3-cmd",
+    ],
+    version: {
+        py3: {
+            embedded_launcher: true,
+        },
+    },
+}
+
 python_library_host {
     name: "build_test_suites",
     srcs: [
         "build_test_suites.py",
         "optimized_targets.py",
+        "test_mapping_module_retriever.py",
+        "build_context.py",
     ],
 }
 
diff --git a/ci/build_context.py b/ci/build_context.py
new file mode 100644
index 0000000000..cc48d53992
--- /dev/null
+++ b/ci/build_context.py
@@ -0,0 +1,64 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Container class for build context with utility functions."""
+
+import re
+
+
+class BuildContext:
+
+  def __init__(self, build_context_dict: dict[str, any]):
+    self.enabled_build_features = set()
+    for opt in build_context_dict.get('enabledBuildFeatures', []):
+      self.enabled_build_features.add(opt.get('name'))
+    self.test_infos = set()
+    for test_info_dict in build_context_dict.get('testContext', dict()).get(
+        'testInfos', []
+    ):
+      self.test_infos.add(self.TestInfo(test_info_dict))
+
+  def build_target_used(self, target: str) -> bool:
+    return any(test.build_target_used(target) for test in self.test_infos)
+
+  class TestInfo:
+
+    _DOWNLOAD_OPTS = {
+        'test-config-only-zip',
+        'test-zip-file-filter',
+        'extra-host-shared-lib-zip',
+        'sandbox-tests-zips',
+        'additional-files-filter',
+        'cts-package-name',
+    }
+
+    def __init__(self, test_info_dict: dict[str, any]):
+      self.is_test_mapping = False
+      self.test_mapping_test_groups = set()
+      self.file_download_options = set()
+      for opt in test_info_dict.get('extraOptions', []):
+        key = opt.get('key')
+        if key == 'test-mapping-test-group':
+          self.is_test_mapping = True
+          self.test_mapping_test_groups.update(opt.get('values', set()))
+
+        if key in self._DOWNLOAD_OPTS:
+          self.file_download_options.update(opt.get('values', set()))
+
+    def build_target_used(self, target: str) -> bool:
+      # For all of a targets' outputs, check if any of the regexes used by tests
+      # to download artifacts would match it. If any of them do then this target
+      # is necessary.
+      regex = r'\b(%s)\b' % re.escape(target)
+      return any(re.search(regex, opt) for opt in self.file_download_options)
diff --git a/ci/build_metadata b/ci/build_metadata
new file mode 100755
index 0000000000..a8eb65dd36
--- /dev/null
+++ b/ci/build_metadata
@@ -0,0 +1,25 @@
+#/bin/bash
+
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+set -ex
+
+export TARGET_PRODUCT=aosp_arm64
+export TARGET_RELEASE=trunk_staging
+export TARGET_BUILD_VARIANT=eng
+
+build/soong/bin/m dist \
+    all_teams
+
diff --git a/ci/build_test_suites.py b/ci/build_test_suites.py
index 6e1f88c36c..b8c4a385e0 100644
--- a/ci/build_test_suites.py
+++ b/ci/build_test_suites.py
@@ -23,11 +23,13 @@ import pathlib
 import subprocess
 import sys
 from typing import Callable
+from build_context import BuildContext
 import optimized_targets
 
 
 REQUIRED_ENV_VARS = frozenset(['TARGET_PRODUCT', 'TARGET_RELEASE', 'TOP'])
 SOONG_UI_EXE_REL_PATH = 'build/soong/soong_ui.bash'
+LOG_PATH = 'logs/build_test_suites.log'
 
 
 class Error(Exception):
@@ -53,7 +55,7 @@ class BuildPlanner:
 
   def __init__(
       self,
-      build_context: dict[str, any],
+      build_context: BuildContext,
       args: argparse.Namespace,
       target_optimizations: dict[str, optimized_targets.OptimizedBuildTarget],
   ):
@@ -63,12 +65,17 @@ class BuildPlanner:
 
   def create_build_plan(self):
 
-    if 'optimized_build' not in self.build_context['enabled_build_features']:
+    if 'optimized_build' not in self.build_context.enabled_build_features:
       return BuildPlan(set(self.args.extra_targets), set())
 
     build_targets = set()
-    packaging_functions = set()
+    packaging_commands_getters = []
     for target in self.args.extra_targets:
+      if self._unused_target_exclusion_enabled(
+          target
+      ) and not self.build_context.build_target_used(target):
+        continue
+
       target_optimizer_getter = self.target_optimizations.get(target, None)
       if not target_optimizer_getter:
         build_targets.add(target)
@@ -78,15 +85,23 @@ class BuildPlanner:
           target, self.build_context, self.args
       )
       build_targets.update(target_optimizer.get_build_targets())
-      packaging_functions.add(target_optimizer.package_outputs)
+      packaging_commands_getters.append(
+          target_optimizer.get_package_outputs_commands
+      )
 
-    return BuildPlan(build_targets, packaging_functions)
+    return BuildPlan(build_targets, packaging_commands_getters)
+
+  def _unused_target_exclusion_enabled(self, target: str) -> bool:
+    return (
+        f'{target}_unused_exclusion'
+        in self.build_context.enabled_build_features
+    )
 
 
 @dataclass(frozen=True)
 class BuildPlan:
   build_targets: set[str]
-  packaging_functions: set[Callable[..., None]]
+  packaging_commands_getters: list[Callable[[], list[list[str]]]]
 
 
 def build_test_suites(argv: list[str]) -> int:
@@ -100,7 +115,7 @@ def build_test_suites(argv: list[str]) -> int:
   """
   args = parse_args(argv)
   check_required_env()
-  build_context = load_build_context()
+  build_context = BuildContext(load_build_context())
   build_planner = BuildPlanner(
       build_context, args, optimized_targets.OPTIMIZED_BUILD_TARGETS
   )
@@ -154,7 +169,7 @@ def load_build_context():
 
 
 def empty_build_context():
-  return {'enabled_build_features': []}
+  return {'enabledBuildFeatures': []}
 
 
 def execute_build_plan(build_plan: BuildPlan):
@@ -168,8 +183,12 @@ def execute_build_plan(build_plan: BuildPlan):
   except subprocess.CalledProcessError as e:
     raise BuildFailureError(e.returncode) from e
 
-  for packaging_function in build_plan.packaging_functions:
-    packaging_function()
+  for packaging_commands_getter in build_plan.packaging_commands_getters:
+    try:
+      for packaging_command in packaging_commands_getter():
+        run_command(packaging_command)
+    except subprocess.CalledProcessError as e:
+      raise BuildFailureError(e.returncode) from e
 
 
 def get_top() -> pathlib.Path:
@@ -181,4 +200,12 @@ def run_command(args: list[str], stdout=None):
 
 
 def main(argv):
+  dist_dir = os.environ.get('DIST_DIR')
+  if dist_dir:
+    log_file = pathlib.Path(dist_dir) / LOG_PATH
+    logging.basicConfig(
+        level=logging.DEBUG,
+        format='%(asctime)s %(levelname)s %(message)s',
+        filename=log_file,
+    )
   sys.exit(build_test_suites(argv))
diff --git a/ci/build_test_suites_test.py b/ci/build_test_suites_test.py
index a9ff3fbf4d..2afaab7711 100644
--- a/ci/build_test_suites_test.py
+++ b/ci/build_test_suites_test.py
@@ -15,6 +15,7 @@
 """Tests for build_test_suites.py"""
 
 import argparse
+import functools
 from importlib import resources
 import json
 import multiprocessing
@@ -31,6 +32,7 @@ import time
 from typing import Callable
 import unittest
 from unittest import mock
+from build_context import BuildContext
 import build_test_suites
 import ci_test_lib
 import optimized_targets
@@ -238,14 +240,21 @@ class BuildPlannerTest(unittest.TestCase):
 
   class TestOptimizedBuildTarget(optimized_targets.OptimizedBuildTarget):
 
-    def __init__(self, output_targets):
+    def __init__(
+        self, target, build_context, args, output_targets, packaging_commands
+    ):
+      super().__init__(target, build_context, args)
       self.output_targets = output_targets
+      self.packaging_commands = packaging_commands
 
-    def get_build_targets(self):
+    def get_build_targets_impl(self):
       return self.output_targets
 
-    def package_outputs(self):
-      return f'packaging {" ".join(self.output_targets)}'
+    def get_package_outputs_commands_impl(self):
+      return self.packaging_commands
+
+    def get_enabled_flag(self):
+      return f'{self.target}_enabled'
 
   def test_build_optimization_off_builds_everything(self):
     build_targets = {'target_1', 'target_2'}
@@ -267,14 +276,15 @@ class BuildPlannerTest(unittest.TestCase):
 
     build_plan = build_planner.create_build_plan()
 
-    self.assertEqual(len(build_plan.packaging_functions), 0)
+    for packaging_command in self.run_packaging_commands(build_plan):
+      self.assertEqual(len(packaging_command), 0)
 
   def test_build_optimization_on_optimizes_target(self):
     build_targets = {'target_1', 'target_2'}
     build_planner = self.create_build_planner(
         build_targets=build_targets,
         build_context=self.create_build_context(
-            enabled_build_features={self.get_target_flag('target_1')}
+            enabled_build_features=[{'name': self.get_target_flag('target_1')}]
         ),
     )
 
@@ -285,20 +295,19 @@ class BuildPlannerTest(unittest.TestCase):
 
   def test_build_optimization_on_packages_target(self):
     build_targets = {'target_1', 'target_2'}
+    optimized_target_name = self.get_optimized_target_name('target_1')
+    packaging_commands = [[f'packaging {optimized_target_name}']]
     build_planner = self.create_build_planner(
         build_targets=build_targets,
         build_context=self.create_build_context(
-            enabled_build_features={self.get_target_flag('target_1')}
+            enabled_build_features=[{'name': self.get_target_flag('target_1')}]
         ),
+        packaging_commands=packaging_commands,
     )
 
     build_plan = build_planner.create_build_plan()
 
-    optimized_target_name = self.get_optimized_target_name('target_1')
-    self.assertIn(
-        f'packaging {optimized_target_name}',
-        self.run_packaging_functions(build_plan),
-    )
+    self.assertIn(packaging_commands, self.run_packaging_commands(build_plan))
 
   def test_individual_build_optimization_off_doesnt_optimize(self):
     build_targets = {'target_1', 'target_2'}
@@ -312,26 +321,94 @@ class BuildPlannerTest(unittest.TestCase):
 
   def test_individual_build_optimization_off_doesnt_package(self):
     build_targets = {'target_1', 'target_2'}
+    packaging_commands = [['packaging command']]
     build_planner = self.create_build_planner(
         build_targets=build_targets,
+        packaging_commands=packaging_commands,
+    )
+
+    build_plan = build_planner.create_build_plan()
+
+    for packaging_command in self.run_packaging_commands(build_plan):
+      self.assertEqual(len(packaging_command), 0)
+
+  def test_target_output_used_target_built(self):
+    build_target = 'test_target'
+    build_planner = self.create_build_planner(
+        build_targets={build_target},
+        build_context=self.create_build_context(
+            test_context=self.get_test_context(build_target),
+            enabled_build_features=[{'name': 'test_target_unused_exclusion'}],
+        ),
     )
 
     build_plan = build_planner.create_build_plan()
 
-    expected_packaging_function_outputs = {None, None}
-    self.assertSetEqual(
-        expected_packaging_function_outputs,
-        self.run_packaging_functions(build_plan),
+    self.assertSetEqual(build_plan.build_targets, {build_target})
+
+  def test_target_regex_used_target_built(self):
+    build_target = 'test_target'
+    test_context = self.get_test_context(build_target)
+    test_context['testInfos'][0]['extraOptions'] = [{
+        'key': 'additional-files-filter',
+        'values': [f'.*{build_target}.*\.zip'],
+    }]
+    build_planner = self.create_build_planner(
+        build_targets={build_target},
+        build_context=self.create_build_context(
+            test_context=test_context,
+            enabled_build_features=[{'name': 'test_target_unused_exclusion'}],
+        ),
     )
 
+    build_plan = build_planner.create_build_plan()
+
+    self.assertSetEqual(build_plan.build_targets, {build_target})
+
+  def test_target_output_not_used_target_not_built(self):
+    build_target = 'test_target'
+    test_context = self.get_test_context(build_target)
+    test_context['testInfos'][0]['extraOptions'] = []
+    build_planner = self.create_build_planner(
+        build_targets={build_target},
+        build_context=self.create_build_context(
+            test_context=test_context,
+            enabled_build_features=[{'name': 'test_target_unused_exclusion'}],
+        ),
+    )
+
+    build_plan = build_planner.create_build_plan()
+
+    self.assertSetEqual(build_plan.build_targets, set())
+
+  def test_target_regex_matching_not_too_broad(self):
+    build_target = 'test_target'
+    test_context = self.get_test_context(build_target)
+    test_context['testInfos'][0]['extraOptions'] = [{
+        'key': 'additional-files-filter',
+        'values': [f'.*a{build_target}.*\.zip'],
+    }]
+    build_planner = self.create_build_planner(
+        build_targets={build_target},
+        build_context=self.create_build_context(
+            test_context=test_context,
+            enabled_build_features=[{'name': 'test_target_unused_exclusion'}],
+        ),
+    )
+
+    build_plan = build_planner.create_build_plan()
+
+    self.assertSetEqual(build_plan.build_targets, set())
+
   def create_build_planner(
       self,
       build_targets: set[str],
-      build_context: dict[str, any] = None,
+      build_context: BuildContext = None,
       args: argparse.Namespace = None,
       target_optimizations: dict[
           str, optimized_targets.OptimizedBuildTarget
       ] = None,
+      packaging_commands: list[list[str]] = [],
   ) -> build_test_suites.BuildPlanner:
     if not build_context:
       build_context = self.create_build_context()
@@ -339,7 +416,9 @@ class BuildPlannerTest(unittest.TestCase):
       args = self.create_args(extra_build_targets=build_targets)
     if not target_optimizations:
       target_optimizations = self.create_target_optimizations(
-          build_context, build_targets
+          build_context,
+          build_targets,
+          packaging_commands,
       )
     return build_test_suites.BuildPlanner(
         build_context, args, target_optimizations
@@ -348,15 +427,17 @@ class BuildPlannerTest(unittest.TestCase):
   def create_build_context(
       self,
       optimized_build_enabled: bool = True,
-      enabled_build_features: set[str] = set(),
+      enabled_build_features: list[dict[str, str]] = [],
       test_context: dict[str, any] = {},
-  ) -> dict[str, any]:
-    build_context = {}
-    build_context['enabled_build_features'] = enabled_build_features
+  ) -> BuildContext:
+    build_context_dict = {}
+    build_context_dict['enabledBuildFeatures'] = enabled_build_features
     if optimized_build_enabled:
-      build_context['enabled_build_features'].add('optimized_build')
-    build_context['test_context'] = test_context
-    return build_context
+      build_context_dict['enabledBuildFeatures'].append(
+          {'name': 'optimized_build'}
+      )
+    build_context_dict['testContext'] = test_context
+    return BuildContext(build_context_dict)
 
   def create_args(
       self, extra_build_targets: set[str] = set()
@@ -366,19 +447,17 @@ class BuildPlannerTest(unittest.TestCase):
     return parser.parse_args(extra_build_targets)
 
   def create_target_optimizations(
-      self, build_context: dict[str, any], build_targets: set[str]
+      self,
+      build_context: BuildContext,
+      build_targets: set[str],
+      packaging_commands: list[list[str]] = [],
   ):
     target_optimizations = dict()
     for target in build_targets:
-      target_optimizations[target] = (
-          lambda target, build_context, args: optimized_targets.get_target_optimizer(
-              target,
-              self.get_target_flag(target),
-              build_context,
-              self.TestOptimizedBuildTarget(
-                  {self.get_optimized_target_name(target)}
-              ),
-          )
+      target_optimizations[target] = functools.partial(
+          self.TestOptimizedBuildTarget,
+          output_targets={self.get_optimized_target_name(target)},
+          packaging_commands=packaging_commands,
       )
 
     return target_optimizations
@@ -389,14 +468,30 @@ class BuildPlannerTest(unittest.TestCase):
   def get_optimized_target_name(self, target: str):
     return f'{target}_optimized'
 
-  def run_packaging_functions(
-      self, build_plan: build_test_suites.BuildPlan
-  ) -> set[str]:
-    output = set()
-    for packaging_function in build_plan.packaging_functions:
-      output.add(packaging_function())
-
-    return output
+  def get_test_context(self, target: str):
+    return {
+        'testInfos': [
+            {
+                'name': 'atp_test',
+                'target': 'test_target',
+                'branch': 'branch',
+                'extraOptions': [{
+                    'key': 'additional-files-filter',
+                    'values': [f'{target}.zip'],
+                }],
+                'command': '/tf/command',
+                'extraBuildTargets': [
+                    'extra_build_target',
+                ],
+            },
+        ],
+    }
+
+  def run_packaging_commands(self, build_plan: build_test_suites.BuildPlan):
+    return [
+        packaging_command_getter()
+        for packaging_command_getter in build_plan.packaging_commands_getters
+    ]
 
 
 def wait_until(
diff --git a/ci/buildbot.py b/ci/buildbot.py
new file mode 100644
index 0000000000..97097be598
--- /dev/null
+++ b/ci/buildbot.py
@@ -0,0 +1,43 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Utilities for interacting with buildbot, with a simulation in a local environment"""
+
+import os
+import sys
+
+# Check that the script is running from the root of the tree. Prevents subtle
+# errors later, and CI always runs from the root of the tree.
+if not os.path.exists("build/make/ci/buildbot.py"):
+    raise Exception("CI script must be run from the root of the tree instead of: "
+                    + os.getcwd())
+
+# Check that we are using the hermetic interpreter
+if "prebuilts/build-tools/" not in sys.executable:
+    raise Exception("CI script must be run using the hermetic interpreter from "
+                    + "prebuilts/build-tools instead of: " + sys.executable)
+
+
+def OutDir():
+    "Get the out directory. Will create it if needed."
+    result = os.environ.get("OUT_DIR", "out")
+    os.makedirs(result, exist_ok=True)
+    return result
+
+def DistDir():
+    "Get the dist directory. Will create it if needed."
+    result = os.environ.get("DIST_DIR", os.path.join(OutDir(), "dist"))
+    os.makedirs(result, exist_ok=True)
+    return result
+
diff --git a/ci/dump_product_config b/ci/dump_product_config
new file mode 100755
index 0000000000..77b51dd281
--- /dev/null
+++ b/ci/dump_product_config
@@ -0,0 +1,353 @@
+#!prebuilts/build-tools/linux-x86/bin/py3-cmd -B
+
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Script to collect all of the make variables from all product config combos.
+
+This script must be run from the root of the source tree.
+
+See GetArgs() below or run dump_product_config for more information.
+"""
+
+import argparse
+import asyncio
+import contextlib
+import csv
+import dataclasses
+import json
+import multiprocessing
+import os
+import subprocess
+import sys
+import time
+from typing import List, Dict, Tuple, Optional
+
+import buildbot
+
+# We have some BIG variables
+csv.field_size_limit(sys.maxsize)
+
+
+class DataclassJSONEncoder(json.JSONEncoder):
+    """JSONEncoder for our custom types."""
+    def default(self, o):
+        if dataclasses.is_dataclass(o):
+            return dataclasses.asdict(o)
+        return super().default(o)
+
+
+def GetProducts():
+    """Get the all of the available TARGET_PRODUCT values."""
+    try:
+        stdout = subprocess.check_output(["build/soong/bin/list_products"], text=True)
+    except subprocess.CalledProcessError:
+        sys.exit(1)
+    return [s.strip() for s in stdout.splitlines() if s.strip()]
+
+
+def GetReleases(product):
+    """For a given product, get the release configs available to it."""
+    if True:
+        # Hard code the list
+        mainline_products = [
+            "module_arm",
+            "module_x86",
+            "module_arm64",
+            "module_riscv64",
+            "module_x86_64",
+            "module_arm64only",
+            "module_x86_64only",
+        ]
+        if product in mainline_products:
+            return ["trunk_staging", "trunk", "mainline"]
+        else:
+            return ["trunk_staging", "trunk", "next"]
+    else:
+        # Get it from the build system
+        try:
+            stdout = subprocess.check_output(["build/soong/bin/list_releases", product], text=True)
+        except subprocess.CalledProcessError:
+            sys.exit(1)
+        return [s.strip() for s in stdout.splitlines() if s.strip()]
+
+
+def GenerateAllLunchTargets():
+    """Generate the full list of lunch targets."""
+    for product in GetProducts():
+        for release in GetReleases(product):
+            for variant in ["user", "userdebug", "eng"]:
+                yield (product, release, variant)
+
+
+async def ParallelExec(parallelism, tasks):
+    '''
+    ParallelExec takes a parallelism number, and an iterator of tasks to run.
+    Then it will run all the tasks, but a maximum of parallelism will be run at
+    any given time. The tasks must be async functions that accept one argument,
+    which will be an integer id of the worker that they're running on.
+    '''
+    tasks = iter(tasks)
+
+    overall_start = time.monotonic()
+    # lists so they can be modified from the inner function
+    total_duration = [0]
+    count = [0]
+    async def dispatch(worker):
+        while True:
+            try:
+                task = next(tasks)
+                item_start = time.monotonic()
+                await task(worker)
+                now = time.monotonic()
+                item_duration = now - item_start
+                count[0] += 1
+                total_duration[0] += item_duration
+                sys.stderr.write(f"Timing: Items processed: {count[0]}, Wall time: {now-overall_start:0.1f} sec, Throughput: {(now-overall_start)/count[0]:0.3f} sec per item, Average duration: {total_duration[0]/count[0]:0.1f} sec\n")
+            except StopIteration:
+                return
+
+    await asyncio.gather(*[dispatch(worker) for worker in range(parallelism)])
+
+
+async def DumpProductConfigs(out, generator, out_dir):
+    """Collects all of the product config data and store it in file."""
+    # Write the outer json list by hand so we can stream it
+    out.write("[")
+    try:
+        first_result = [True] # a list so it can be modified from the inner function
+        def run(lunch):
+            async def curried(worker):
+                sys.stderr.write(f"running: {'-'.join(lunch)}\n")
+                result = await DumpOneProductConfig(lunch, os.path.join(out_dir, f"lunchable_{worker}"))
+                if first_result[0]:
+                    out.write("\n")
+                    first_result[0] = False
+                else:
+                    out.write(",\n")
+                result.dumpToFile(out)
+                sys.stderr.write(f"finished: {'-'.join(lunch)}\n")
+            return curried
+
+        await ParallelExec(multiprocessing.cpu_count(), (run(lunch) for lunch in generator))
+    finally:
+        # Close the json regardless of how we exit
+        out.write("\n]\n")
+
+
+@dataclasses.dataclass(frozen=True)
+class Variable:
+    """A variable name, value and where it was set."""
+    name: str
+    value: str
+    location: str
+
+
+@dataclasses.dataclass(frozen=True)
+class ProductResult:
+    product: str
+    release: str
+    variant: str
+    board_includes: List[str]
+    product_includes: Dict[str, List[str]]
+    product_graph: List[Tuple[str, str]]
+    board_vars: List[Variable]
+    product_vars: List[Variable]
+
+    def dumpToFile(self, f):
+        json.dump(self, f, sort_keys=True, indent=2, cls=DataclassJSONEncoder)
+
+
+@dataclasses.dataclass(frozen=True)
+class ProductError:
+    product: str
+    release: str
+    variant: str
+    error: str
+
+    def dumpToFile(self, f):
+        json.dump(self, f, sort_keys=True, indent=2, cls=DataclassJSONEncoder)
+
+
+def NormalizeInheritGraph(lists):
+    """Flatten the inheritance graph to a simple list for easier querying."""
+    result = set()
+    for item in lists:
+        for i in range(len(item)):
+            result.add((item[i+1] if i < len(item)-1 else "", item[i]))
+    return sorted(list(result))
+
+
+def ParseDump(lunch, filename) -> ProductResult:
+    """Parses the csv and returns a tuple of the data."""
+    def diff(initial, final):
+        return [after for after in final.values() if
+                initial.get(after.name, Variable(after.name, "", "<unset>")).value != after.value]
+    product_initial = {}
+    product_final = {}
+    board_initial = {}
+    board_final = {}
+    inherit_product = [] # The stack of inherit-product calls
+    product_includes = {} # Other files included by each of the properly imported files
+    board_includes = [] # Files included by boardconfig
+    with open(filename) as f:
+        phase = ""
+        for line in csv.reader(f):
+            if line[0] == "phase":
+                phase = line[1]
+            elif line[0] == "val":
+                # TOOD: We should skip these somewhere else.
+                if line[3].startswith("_ALL_RELEASE_FLAGS"):
+                    continue
+                if line[3].startswith("PRODUCTS."):
+                    continue
+                if phase == "PRODUCTS":
+                    if line[2] == "initial":
+                        product_initial[line[3]] = Variable(line[3], line[4], line[5])
+                if phase == "PRODUCT-EXPAND":
+                    if line[2] == "final":
+                        product_final[line[3]] = Variable(line[3], line[4], line[5])
+                if phase == "BOARD":
+                    if line[2] == "initial":
+                        board_initial[line[3]] = Variable(line[3], line[4], line[5])
+                    if line[2] == "final":
+                        board_final[line[3]] = Variable(line[3], line[4], line[5])
+            elif line[0] == "imported":
+                imports = [s.strip() for s in line[1].split()]
+                if imports:
+                    inherit_product.append(imports)
+                    inc = [s.strip() for s in line[2].split()]
+                    for f in inc:
+                        product_includes.setdefault(imports[0], []).append(f)
+            elif line[0] == "board_config_files":
+                board_includes += [s.strip() for s in line[1].split()]
+    return ProductResult(
+        product = lunch[0],
+        release = lunch[1],
+        variant = lunch[2],
+        product_vars = diff(product_initial, product_final),
+        board_vars = diff(board_initial, board_final),
+        product_graph = NormalizeInheritGraph(inherit_product),
+        product_includes = product_includes,
+        board_includes = board_includes
+    )
+
+
+async def DumpOneProductConfig(lunch, out_dir) -> ProductResult | ProductError:
+    """Print a single config's lunch info to stdout."""
+    product, release, variant = lunch
+
+    dumpconfig_file = os.path.join(out_dir, f"{product}-{release}-{variant}.csv")
+
+    # Run get_build_var to bootstrap soong_ui for this target
+    env = dict(os.environ)
+    env["TARGET_PRODUCT"] = product
+    env["TARGET_RELEASE"] = release
+    env["TARGET_BUILD_VARIANT"] = variant
+    env["OUT_DIR"] = out_dir
+    process = await asyncio.create_subprocess_exec(
+        "build/soong/bin/get_build_var",
+        "TARGET_PRODUCT",
+        stdout=subprocess.PIPE,
+        stderr=subprocess.STDOUT,
+        env=env
+    )
+    stdout, _ = await process.communicate()
+    stdout = stdout.decode()
+
+    if process.returncode != 0:
+        return ProductError(
+            product = product,
+            release = release,
+            variant = variant,
+            error = stdout
+        )
+    else:
+        # Run kati to extract the data
+        process = await asyncio.create_subprocess_exec(
+            "prebuilts/build-tools/linux-x86/bin/ckati",
+            "-f",
+            "build/make/core/dumpconfig.mk",
+            f"TARGET_PRODUCT={product}",
+            f"TARGET_RELEASE={release}",
+            f"TARGET_BUILD_VARIANT={variant}",
+            f"DUMPCONFIG_FILE={dumpconfig_file}",
+            stdout=subprocess.PIPE,
+            stderr=subprocess.STDOUT,
+            env=env
+        )
+        stdout, _ = await process.communicate()
+        if process.returncode != 0:
+            stdout = stdout.decode()
+            return ProductError(
+                product = product,
+                release = release,
+                variant = variant,
+                error = stdout
+            )
+        else:
+            # Parse and record the output
+            return ParseDump(lunch, dumpconfig_file)
+
+
+def GetArgs():
+    """Parse command line arguments."""
+    parser = argparse.ArgumentParser(
+            description="Collect all of the make variables from product config.",
+            epilog="NOTE: This script must be run from the root of the source tree.")
+    parser.add_argument("--lunch", nargs="*")
+    parser.add_argument("--dist", action="store_true")
+
+    return parser.parse_args()
+
+
+async def main():
+    args = GetArgs()
+
+    out_dir = buildbot.OutDir()
+
+    if args.dist:
+        cm = open(os.path.join(buildbot.DistDir(), "all_product_config.json"), "w")
+    else:
+        cm = contextlib.nullcontext(sys.stdout)
+
+
+    with cm as out:
+        if args.lunch:
+            lunches = [lunch.split("-") for lunch in args.lunch]
+            fail = False
+            for i in range(len(lunches)):
+                if len(lunches[i]) != 3:
+                    sys.stderr.write(f"Malformed lunch targets: {args.lunch[i]}\n")
+                    fail = True
+            if fail:
+                sys.exit(1)
+            if len(lunches) == 1:
+                result = await DumpOneProductConfig(lunches[0], out_dir)
+                result.dumpToFile(out)
+                out.write("\n")
+            else:
+                await DumpProductConfigs(out, lunches, out_dir)
+        else:
+            # All configs mode. This will exec single config mode in parallel
+            # for each lunch combo. Write output to $DIST_DIR.
+            await DumpProductConfigs(out, GenerateAllLunchTargets(), out_dir)
+
+
+if __name__ == "__main__":
+    asyncio.run(main())
+
+
+# vim: set syntax=python ts=4 sw=4 sts=4:
+
diff --git a/ci/optimized_targets.py b/ci/optimized_targets.py
index 224c8c0221..688bdd8370 100644
--- a/ci/optimized_targets.py
+++ b/ci/optimized_targets.py
@@ -14,6 +14,16 @@
 # limitations under the License.
 
 from abc import ABC
+import argparse
+import functools
+import json
+import logging
+import os
+import pathlib
+import subprocess
+
+from build_context import BuildContext
+import test_mapping_module_retriever
 
 
 class OptimizedBuildTarget(ABC):
@@ -24,15 +34,132 @@ class OptimizedBuildTarget(ABC):
   build.
   """
 
-  def __init__(self, build_context, args):
+  _SOONG_UI_BASH_PATH = 'build/soong/soong_ui.bash'
+  _PREBUILT_SOONG_ZIP_PATH = 'prebuilts/build-tools/linux-x86/bin/soong_zip'
+
+  def __init__(
+      self,
+      target: str,
+      build_context: BuildContext,
+      args: argparse.Namespace,
+  ):
+    self.target = target
     self.build_context = build_context
     self.args = args
 
-  def get_build_targets(self):
-    pass
+  def get_build_targets(self) -> set[str]:
+    features = self.build_context.enabled_build_features
+    if self.get_enabled_flag() in features:
+      self.modules_to_build = self.get_build_targets_impl()
+      return self.modules_to_build
+
+    self.modules_to_build = {self.target}
+    return {self.target}
+
+  def get_package_outputs_commands(self) -> list[list[str]]:
+    features = self.build_context.enabled_build_features
+    if self.get_enabled_flag() in features:
+      return self.get_package_outputs_commands_impl()
+
+    return []
+
+  def get_package_outputs_commands_impl(self) -> list[list[str]]:
+    raise NotImplementedError(
+        'get_package_outputs_commands_impl not implemented in'
+        f' {type(self).__name__}'
+    )
 
-  def package_outputs(self):
-    pass
+  def get_enabled_flag(self):
+    raise NotImplementedError(
+        f'get_enabled_flag not implemented in {type(self).__name__}'
+    )
+
+  def get_build_targets_impl(self) -> set[str]:
+    raise NotImplementedError(
+        f'get_build_targets_impl not implemented in {type(self).__name__}'
+    )
+
+  def _generate_zip_options_for_items(
+      self,
+      prefix: str = '',
+      relative_root: str = '',
+      list_files: list[str] | None = None,
+      files: list[str] | None = None,
+      directories: list[str] | None = None,
+  ) -> list[str]:
+    if not list_files and not files and not directories:
+      raise RuntimeError(
+          f'No items specified to be added to zip! Prefix: {prefix}, Relative'
+          f' root: {relative_root}'
+      )
+    command_segment = []
+    # These are all soong_zip options so consult soong_zip --help for specifics.
+    if prefix:
+      command_segment.append('-P')
+      command_segment.append(prefix)
+    if relative_root:
+      command_segment.append('-C')
+      command_segment.append(relative_root)
+    if list_files:
+      for list_file in list_files:
+        command_segment.append('-l')
+        command_segment.append(list_file)
+    if files:
+      for file in files:
+        command_segment.append('-f')
+        command_segment.append(file)
+    if directories:
+      for directory in directories:
+        command_segment.append('-D')
+        command_segment.append(directory)
+
+    return command_segment
+
+  def _query_soong_vars(
+      self, src_top: pathlib.Path, soong_vars: list[str]
+  ) -> dict[str, str]:
+    process_result = subprocess.run(
+        args=[
+            f'{src_top / self._SOONG_UI_BASH_PATH}',
+            '--dumpvars-mode',
+            f'--abs-vars={" ".join(soong_vars)}',
+        ],
+        env=os.environ,
+        check=False,
+        capture_output=True,
+        text=True,
+    )
+    if not process_result.returncode == 0:
+      logging.error('soong dumpvars command failed! stderr:')
+      logging.error(process_result.stderr)
+      raise RuntimeError('Soong dumpvars failed! See log for stderr.')
+
+    if not process_result.stdout:
+      raise RuntimeError(
+          'Necessary soong variables ' + soong_vars + ' not found.'
+      )
+
+    try:
+      return {
+          line.split('=')[0]: line.split('=')[1].strip("'")
+          for line in process_result.stdout.strip().split('\n')
+      }
+    except IndexError as e:
+      raise RuntimeError(
+          'Error parsing soong dumpvars output! See output here:'
+          f' {process_result.stdout}',
+          e,
+      )
+
+  def _base_zip_command(
+      self, src_top: pathlib.Path, dist_dir: pathlib.Path, name: str
+  ) -> list[str]:
+    return [
+        f'{src_top / self._PREBUILT_SOONG_ZIP_PATH }',
+        '-d',
+        '-o',
+        f'{dist_dir / name}',
+    ]
 
 
 class NullOptimizer(OptimizedBuildTarget):
@@ -48,22 +175,308 @@ class NullOptimizer(OptimizedBuildTarget):
   def get_build_targets(self):
     return {self.target}
 
-  def package_outputs(self):
-    pass
+  def get_package_outputs_commands(self):
+    return []
+
+
+class ChangeInfo:
+
+  def __init__(self, change_info_file_path):
+    try:
+      with open(change_info_file_path) as change_info_file:
+        change_info_contents = json.load(change_info_file)
+    except json.decoder.JSONDecodeError:
+      logging.error(f'Failed to load CHANGE_INFO: {change_info_file_path}')
+      raise
+
+    self._change_info_contents = change_info_contents
+
+  def find_changed_files(self) -> set[str]:
+    changed_files = set()
+
+    for change in self._change_info_contents['changes']:
+      project_path = change.get('projectPath') + '/'
+
+      for revision in change.get('revisions'):
+        for file_info in revision.get('fileInfos'):
+          changed_files.add(project_path + file_info.get('path'))
+
+    return changed_files
+
+
+class GeneralTestsOptimizer(OptimizedBuildTarget):
+  """general-tests optimizer
+
+  This optimizer reads in the list of changed files from the file located in
+  env[CHANGE_INFO] and uses this list alongside the normal TEST MAPPING logic to
+  determine what test mapping modules will run for the given changes. It then
+  builds those modules and packages them in the same way general-tests.zip is
+  normally built.
+  """
+
+  # List of modules that are built alongside general-tests as dependencies.
+  _REQUIRED_MODULES = frozenset([
+      'cts-tradefed',
+      'vts-tradefed',
+      'compatibility-host-util',
+      'general-tests-shared-libs',
+  ])
+
+  def get_build_targets_impl(self) -> set[str]:
+    change_info_file_path = os.environ.get('CHANGE_INFO')
+    if not change_info_file_path:
+      logging.info(
+          'No CHANGE_INFO env var found, general-tests optimization disabled.'
+      )
+      return {'general-tests'}
+
+    test_infos = self.build_context.test_infos
+    test_mapping_test_groups = set()
+    for test_info in test_infos:
+      is_test_mapping = test_info.is_test_mapping
+      current_test_mapping_test_groups = test_info.test_mapping_test_groups
+      uses_general_tests = test_info.build_target_used('general-tests')
+
+      if uses_general_tests and not is_test_mapping:
+        logging.info(
+            'Test uses general-tests.zip but is not test-mapping, general-tests'
+            ' optimization disabled.'
+        )
+        return {'general-tests'}
+
+      if is_test_mapping:
+        test_mapping_test_groups.update(current_test_mapping_test_groups)
+
+    change_info = ChangeInfo(change_info_file_path)
+    changed_files = change_info.find_changed_files()
+
+    test_mappings = test_mapping_module_retriever.GetTestMappings(
+        changed_files, set()
+    )
+
+    modules_to_build = set(self._REQUIRED_MODULES)
+
+    modules_to_build.update(
+        test_mapping_module_retriever.FindAffectedModules(
+            test_mappings, changed_files, test_mapping_test_groups
+        )
+    )
+
+    return modules_to_build
+
+  def get_package_outputs_commands_impl(self):
+    src_top = pathlib.Path(os.environ.get('TOP', os.getcwd()))
+    dist_dir = pathlib.Path(os.environ.get('DIST_DIR'))
+
+    soong_vars = self._query_soong_vars(
+        src_top,
+        [
+            'HOST_OUT_TESTCASES',
+            'TARGET_OUT_TESTCASES',
+            'PRODUCT_OUT',
+            'SOONG_HOST_OUT',
+            'HOST_OUT',
+        ],
+    )
+    host_out_testcases = pathlib.Path(soong_vars.get('HOST_OUT_TESTCASES'))
+    target_out_testcases = pathlib.Path(soong_vars.get('TARGET_OUT_TESTCASES'))
+    product_out = pathlib.Path(soong_vars.get('PRODUCT_OUT'))
+    soong_host_out = pathlib.Path(soong_vars.get('SOONG_HOST_OUT'))
+    host_out = pathlib.Path(soong_vars.get('HOST_OUT'))
+
+    host_paths = []
+    target_paths = []
+    host_config_files = []
+    target_config_files = []
+    for module in self.modules_to_build:
+      # The required modules are handled separately, no need to package.
+      if module in self._REQUIRED_MODULES:
+        continue
+
+      host_path = host_out_testcases / module
+      if os.path.exists(host_path):
+        host_paths.append(host_path)
+        self._collect_config_files(src_top, host_path, host_config_files)
+
+      target_path = target_out_testcases / module
+      if os.path.exists(target_path):
+        target_paths.append(target_path)
+        self._collect_config_files(src_top, target_path, target_config_files)
+
+      if not os.path.exists(host_path) and not os.path.exists(target_path):
+        logging.info(f'No host or target build outputs found for {module}.')
+
+    zip_commands = []
+
+    zip_commands.extend(
+        self._get_zip_test_configs_zips_commands(
+            src_top,
+            dist_dir,
+            host_out,
+            product_out,
+            host_config_files,
+            target_config_files,
+        )
+    )
+
+    zip_command = self._base_zip_command(src_top, dist_dir, 'general-tests.zip')
+
+    # Add host testcases.
+    if host_paths:
+      zip_command.extend(
+          self._generate_zip_options_for_items(
+              prefix='host',
+              relative_root=f'{src_top / soong_host_out}',
+              directories=host_paths,
+          )
+      )
+
+    # Add target testcases.
+    if target_paths:
+      zip_command.extend(
+          self._generate_zip_options_for_items(
+              prefix='target',
+              relative_root=f'{src_top / product_out}',
+              directories=target_paths,
+          )
+      )
+
+    # TODO(lucafarsi): Push this logic into a general-tests-minimal build command
+    # Add necessary tools. These are also hardcoded in general-tests.mk.
+    framework_path = soong_host_out / 'framework'
+
+    zip_command.extend(
+        self._generate_zip_options_for_items(
+            prefix='host/tools',
+            relative_root=str(framework_path),
+            files=[
+                f"{framework_path / 'cts-tradefed.jar'}",
+                f"{framework_path / 'compatibility-host-util.jar'}",
+                f"{framework_path / 'vts-tradefed.jar'}",
+            ],
+        )
+    )
+
+    zip_commands.append(zip_command)
+    return zip_commands
+
+  def _collect_config_files(
+      self,
+      src_top: pathlib.Path,
+      root_dir: pathlib.Path,
+      config_files: list[str],
+  ):
+    for root, dirs, files in os.walk(src_top / root_dir):
+      for file in files:
+        if file.endswith('.config'):
+          config_files.append(root_dir / file)
+
+  def _get_zip_test_configs_zips_commands(
+      self,
+      src_top: pathlib.Path,
+      dist_dir: pathlib.Path,
+      host_out: pathlib.Path,
+      product_out: pathlib.Path,
+      host_config_files: list[str],
+      target_config_files: list[str],
+  ) -> tuple[list[str], list[str]]:
+    """Generate general-tests_configs.zip and general-tests_list.zip.
+
+    general-tests_configs.zip contains all of the .config files that were
+    built and general-tests_list.zip contains a text file which lists
+    all of the .config files that are in general-tests_configs.zip.
+
+    general-tests_configs.zip is organized as follows:
+    /
+      host/
+        testcases/
+          test_1.config
+          test_2.config
+          ...
+      target/
+        testcases/
+          test_1.config
+          test_2.config
+          ...
+
+    So the process is we write out the paths to all the host config files into
+    one
+    file and all the paths to the target config files in another. We also write
+    the paths to all the config files into a third file to use for
+    general-tests_list.zip.
+
+    Args:
+      dist_dir: dist directory.
+      host_out: host out directory.
+      product_out: product out directory.
+      host_config_files: list of all host config files.
+      target_config_files: list of all target config files.
+
+    Returns:
+      The commands to generate general-tests_configs.zip and
+      general-tests_list.zip
+    """
+    with open(
+        f"{host_out / 'host_general-tests_list'}", 'w'
+    ) as host_list_file, open(
+        f"{product_out / 'target_general-tests_list'}", 'w'
+    ) as target_list_file, open(
+        f"{host_out / 'general-tests_list'}", 'w'
+    ) as list_file:
+
+      for config_file in host_config_files:
+        host_list_file.write(f'{config_file}' + '\n')
+        list_file.write('host/' + os.path.relpath(config_file, host_out) + '\n')
+
+      for config_file in target_config_files:
+        target_list_file.write(f'{config_file}' + '\n')
+        list_file.write(
+            'target/' + os.path.relpath(config_file, product_out) + '\n'
+        )
+
+    zip_commands = []
+
+    tests_config_zip_command = self._base_zip_command(
+        src_top, dist_dir, 'general-tests_configs.zip'
+    )
+    tests_config_zip_command.extend(
+        self._generate_zip_options_for_items(
+            prefix='host',
+            relative_root=str(host_out),
+            list_files=[f"{host_out / 'host_general-tests_list'}"],
+        )
+    )
+
+    tests_config_zip_command.extend(
+        self._generate_zip_options_for_items(
+            prefix='target',
+            relative_root=str(product_out),
+            list_files=[f"{product_out / 'target_general-tests_list'}"],
+        ),
+    )
+
+    zip_commands.append(tests_config_zip_command)
+
+    tests_list_zip_command = self._base_zip_command(
+        src_top, dist_dir, 'general-tests_list.zip'
+    )
+    tests_list_zip_command.extend(
+        self._generate_zip_options_for_items(
+            relative_root=str(host_out),
+            files=[f"{host_out / 'general-tests_list'}"],
+        )
+    )
+    zip_commands.append(tests_list_zip_command)
 
+    return zip_commands
 
-def get_target_optimizer(target, enabled_flag, build_context, optimizer):
-  if enabled_flag in build_context['enabled_build_features']:
-    return optimizer
+  def get_enabled_flag(self):
+    return 'general_tests_optimized'
 
-  return NullOptimizer(target)
+  @classmethod
+  def get_optimized_targets(cls) -> dict[str, OptimizedBuildTarget]:
+    return {'general-tests': functools.partial(cls)}
 
 
-# To be written as:
-#    'target': lambda target, build_context, args: get_target_optimizer(
-#        target,
-#        'target_enabled_flag',
-#        build_context,
-#        TargetOptimizer(build_context, args),
-#    )
-OPTIMIZED_BUILD_TARGETS = dict()
+OPTIMIZED_BUILD_TARGETS = {}
+OPTIMIZED_BUILD_TARGETS.update(GeneralTestsOptimizer.get_optimized_targets())
diff --git a/ci/optimized_targets_test.py b/ci/optimized_targets_test.py
new file mode 100644
index 0000000000..0b0c0ec087
--- /dev/null
+++ b/ci/optimized_targets_test.py
@@ -0,0 +1,350 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Tests for optimized_targets.py"""
+
+import json
+import logging
+import os
+import pathlib
+import re
+import subprocess
+import textwrap
+import unittest
+from unittest import mock
+from build_context import BuildContext
+import optimized_targets
+from pyfakefs import fake_filesystem_unittest
+
+
+class GeneralTestsOptimizerTest(fake_filesystem_unittest.TestCase):
+
+  def setUp(self):
+    self.setUpPyfakefs()
+
+    os_environ_patcher = mock.patch.dict('os.environ', {})
+    self.addCleanup(os_environ_patcher.stop)
+    self.mock_os_environ = os_environ_patcher.start()
+
+    self._setup_working_build_env()
+    self._write_change_info_file()
+    test_mapping_dir = pathlib.Path('/project/path/file/path')
+    test_mapping_dir.mkdir(parents=True)
+    self._write_test_mapping_file()
+
+  def _setup_working_build_env(self):
+    self.change_info_file = pathlib.Path('/tmp/change_info')
+    self._write_soong_ui_file()
+    self._host_out_testcases = pathlib.Path('/tmp/top/host_out_testcases')
+    self._host_out_testcases.mkdir(parents=True)
+    self._target_out_testcases = pathlib.Path('/tmp/top/target_out_testcases')
+    self._target_out_testcases.mkdir(parents=True)
+    self._product_out = pathlib.Path('/tmp/top/product_out')
+    self._product_out.mkdir(parents=True)
+    self._soong_host_out = pathlib.Path('/tmp/top/soong_host_out')
+    self._soong_host_out.mkdir(parents=True)
+    self._host_out = pathlib.Path('/tmp/top/host_out')
+    self._host_out.mkdir(parents=True)
+
+    self._dist_dir = pathlib.Path('/tmp/top/out/dist')
+    self._dist_dir.mkdir(parents=True)
+
+    self.mock_os_environ.update({
+        'CHANGE_INFO': str(self.change_info_file),
+        'TOP': '/tmp/top',
+        'DIST_DIR': '/tmp/top/out/dist',
+    })
+
+  def _write_soong_ui_file(self):
+    soong_path = pathlib.Path('/tmp/top/build/soong')
+    soong_path.mkdir(parents=True)
+    with open(os.path.join(soong_path, 'soong_ui.bash'), 'w') as f:
+      f.write("""
+              #/bin/bash
+              echo HOST_OUT_TESTCASES='/tmp/top/host_out_testcases'
+              echo TARGET_OUT_TESTCASES='/tmp/top/target_out_testcases'
+              echo PRODUCT_OUT='/tmp/top/product_out'
+              echo SOONG_HOST_OUT='/tmp/top/soong_host_out'
+              echo HOST_OUT='/tmp/top/host_out'
+              """)
+    os.chmod(os.path.join(soong_path, 'soong_ui.bash'), 0o666)
+
+  def _write_change_info_file(self):
+    change_info_contents = {
+        'changes': [{
+            'projectPath': '/project/path',
+            'revisions': [{
+                'fileInfos': [{
+                    'path': 'file/path/file_name',
+                }],
+            }],
+        }]
+    }
+
+    with open(self.change_info_file, 'w') as f:
+      json.dump(change_info_contents, f)
+
+  def _write_test_mapping_file(self):
+    test_mapping_contents = {
+        'test-mapping-group': [
+            {
+                'name': 'test_mapping_module',
+            },
+        ],
+    }
+
+    with open('/project/path/file/path/TEST_MAPPING', 'w') as f:
+      json.dump(test_mapping_contents, f)
+
+  def test_general_tests_optimized(self):
+    optimizer = self._create_general_tests_optimizer()
+
+    build_targets = optimizer.get_build_targets()
+
+    expected_build_targets = set(
+        optimized_targets.GeneralTestsOptimizer._REQUIRED_MODULES
+    )
+    expected_build_targets.add('test_mapping_module')
+
+    self.assertSetEqual(build_targets, expected_build_targets)
+
+  def test_no_change_info_no_optimization(self):
+    del os.environ['CHANGE_INFO']
+
+    optimizer = self._create_general_tests_optimizer()
+
+    build_targets = optimizer.get_build_targets()
+
+    self.assertSetEqual(build_targets, {'general-tests'})
+
+  def test_mapping_groups_unused_module_not_built(self):
+    test_context = self._create_test_context()
+    test_context['testInfos'][0]['extraOptions'] = [
+        {
+            'key': 'additional-files-filter',
+            'values': ['general-tests.zip'],
+        },
+        {
+            'key': 'test-mapping-test-group',
+            'values': ['unused-test-mapping-group'],
+        },
+    ]
+    optimizer = self._create_general_tests_optimizer(
+        build_context=self._create_build_context(test_context=test_context)
+    )
+
+    build_targets = optimizer.get_build_targets()
+
+    expected_build_targets = set(
+        optimized_targets.GeneralTestsOptimizer._REQUIRED_MODULES
+    )
+    self.assertSetEqual(build_targets, expected_build_targets)
+
+  def test_general_tests_used_by_non_test_mapping_test_no_optimization(self):
+    test_context = self._create_test_context()
+    test_context['testInfos'][0]['extraOptions'] = [{
+        'key': 'additional-files-filter',
+        'values': ['general-tests.zip'],
+    }]
+    optimizer = self._create_general_tests_optimizer(
+        build_context=self._create_build_context(test_context=test_context)
+    )
+
+    build_targets = optimizer.get_build_targets()
+
+    self.assertSetEqual(build_targets, {'general-tests'})
+
+  def test_malformed_change_info_raises(self):
+    with open(self.change_info_file, 'w') as f:
+      f.write('not change info')
+
+    optimizer = self._create_general_tests_optimizer()
+
+    with self.assertRaises(json.decoder.JSONDecodeError):
+      build_targets = optimizer.get_build_targets()
+
+  def test_malformed_test_mapping_raises(self):
+    with open('/project/path/file/path/TEST_MAPPING', 'w') as f:
+      f.write('not test mapping')
+
+    optimizer = self._create_general_tests_optimizer()
+
+    with self.assertRaises(json.decoder.JSONDecodeError):
+      build_targets = optimizer.get_build_targets()
+
+  @mock.patch('subprocess.run')
+  def test_packaging_outputs_success(self, subprocess_run):
+    subprocess_run.return_value = self._get_soong_vars_output()
+    optimizer = self._create_general_tests_optimizer()
+    self._set_up_build_outputs(['test_mapping_module'])
+
+    targets = optimizer.get_build_targets()
+    package_commands = optimizer.get_package_outputs_commands()
+
+    self._verify_soong_zip_commands(package_commands, ['test_mapping_module'])
+
+  @mock.patch('subprocess.run')
+  def test_get_soong_dumpvars_fails_raises(self, subprocess_run):
+    subprocess_run.return_value = self._get_soong_vars_output(return_code=-1)
+    optimizer = self._create_general_tests_optimizer()
+    self._set_up_build_outputs(['test_mapping_module'])
+
+    targets = optimizer.get_build_targets()
+
+    with self.assertRaisesRegex(RuntimeError, 'Soong dumpvars failed!'):
+      package_commands = optimizer.get_package_outputs_commands()
+
+  @mock.patch('subprocess.run')
+  def test_get_soong_dumpvars_bad_output_raises(self, subprocess_run):
+    subprocess_run.return_value = self._get_soong_vars_output(
+        stdout='This output is bad'
+    )
+    optimizer = self._create_general_tests_optimizer()
+    self._set_up_build_outputs(['test_mapping_module'])
+
+    targets = optimizer.get_build_targets()
+
+    with self.assertRaisesRegex(
+        RuntimeError, 'Error parsing soong dumpvars output'
+    ):
+      package_commands = optimizer.get_package_outputs_commands()
+
+  def _create_general_tests_optimizer(self, build_context: BuildContext = None):
+    if not build_context:
+      build_context = self._create_build_context()
+    return optimized_targets.GeneralTestsOptimizer(
+        'general-tests', build_context, None
+    )
+
+  def _create_build_context(
+      self,
+      general_tests_optimized: bool = True,
+      test_context: dict[str, any] = None,
+  ) -> BuildContext:
+    if not test_context:
+      test_context = self._create_test_context()
+    build_context_dict = {}
+    build_context_dict['enabledBuildFeatures'] = [{'name': 'optimized_build'}]
+    if general_tests_optimized:
+      build_context_dict['enabledBuildFeatures'].append(
+          {'name': 'general_tests_optimized'}
+      )
+    build_context_dict['testContext'] = test_context
+    return BuildContext(build_context_dict)
+
+  def _create_test_context(self):
+    return {
+        'testInfos': [
+            {
+                'name': 'atp_test',
+                'target': 'test_target',
+                'branch': 'branch',
+                'extraOptions': [
+                    {
+                        'key': 'additional-files-filter',
+                        'values': ['general-tests.zip'],
+                    },
+                    {
+                        'key': 'test-mapping-test-group',
+                        'values': ['test-mapping-group'],
+                    },
+                ],
+                'command': '/tf/command',
+                'extraBuildTargets': [
+                    'extra_build_target',
+                ],
+            },
+        ],
+    }
+
+  def _get_soong_vars_output(
+      self, return_code: int = 0, stdout: str = ''
+  ) -> subprocess.CompletedProcess:
+    return_value = subprocess.CompletedProcess(args=[], returncode=return_code)
+    if not stdout:
+      stdout = textwrap.dedent(f"""\
+                               HOST_OUT_TESTCASES='{self._host_out_testcases}'
+                               TARGET_OUT_TESTCASES='{self._target_out_testcases}'
+                               PRODUCT_OUT='{self._product_out}'
+                               SOONG_HOST_OUT='{self._soong_host_out}'
+                               HOST_OUT='{self._host_out}'""")
+
+    return_value.stdout = stdout
+    return return_value
+
+  def _set_up_build_outputs(self, targets: list[str]):
+    for target in targets:
+      host_dir = self._host_out_testcases / target
+      host_dir.mkdir()
+      (host_dir / f'{target}.config').touch()
+      (host_dir / f'test_file').touch()
+
+      target_dir = self._target_out_testcases / target
+      target_dir.mkdir()
+      (target_dir / f'{target}.config').touch()
+      (target_dir / f'test_file').touch()
+
+  def _verify_soong_zip_commands(self, commands: list[str], targets: list[str]):
+    """Verify the structure of the zip commands.
+
+    Zip commands have to start with the soong_zip binary path, then are followed
+    by a couple of options and the name of the file being zipped. Depending on
+    which zip we are creating look for a few essential items being added in
+    those zips.
+
+    Args:
+      commands: list of command lists
+      targets: list of targets expected to be in general-tests.zip
+    """
+    for command in commands:
+      self.assertEqual(
+          '/tmp/top/prebuilts/build-tools/linux-x86/bin/soong_zip',
+          command[0],
+      )
+      self.assertEqual('-d', command[1])
+      self.assertEqual('-o', command[2])
+      match (command[3]):
+        case '/tmp/top/out/dist/general-tests_configs.zip':
+          self.assertIn(f'{self._host_out}/host_general-tests_list', command)
+          self.assertIn(
+              f'{self._product_out}/target_general-tests_list', command
+          )
+          return
+        case '/tmp/top/out/dist/general-tests_list.zip':
+          self.assertIn('-f', command)
+          self.assertIn(f'{self._host_out}/general-tests_list', command)
+          return
+        case '/tmp/top/out/dist/general-tests.zip':
+          for target in targets:
+            self.assertIn(f'{self._host_out_testcases}/{target}', command)
+            self.assertIn(f'{self._target_out_testcases}/{target}', command)
+          self.assertIn(
+              f'{self._soong_host_out}/framework/cts-tradefed.jar', command
+          )
+          self.assertIn(
+              f'{self._soong_host_out}/framework/compatibility-host-util.jar',
+              command,
+          )
+          self.assertIn(
+              f'{self._soong_host_out}/framework/vts-tradefed.jar', command
+          )
+          return
+        case _:
+          self.fail(f'malformed command: {command}')
+
+
+if __name__ == '__main__':
+  # Setup logging to be silent so unit tests can pass through TF.
+  logging.disable(logging.ERROR)
+  unittest.main()
diff --git a/ci/test_mapping_module_retriever.py b/ci/test_mapping_module_retriever.py
index d2c13c0e7d..c93cdd5953 100644
--- a/ci/test_mapping_module_retriever.py
+++ b/ci/test_mapping_module_retriever.py
@@ -17,11 +17,13 @@ Simple parsing code to scan test_mapping files and determine which
 modules are needed to build for the given list of changed files.
 TODO(lucafarsi): Deduplicate from artifact_helper.py
 """
+# TODO(lucafarsi): Share this logic with the original logic in
+# test_mapping_test_retriever.py
 
-from typing import Any, Dict, Set, Text
 import json
 import os
 import re
+from typing import Any
 
 # Regex to extra test name from the path of test config file.
 TEST_NAME_REGEX = r'(?:^|.*/)([^/]+)\.config'
@@ -39,7 +41,7 @@ TEST_MAPPING = 'TEST_MAPPING'
 _COMMENTS_RE = re.compile(r'(\"(?:[^\"\\]|\\.)*\"|(?=//))(?://.*)?')
 
 
-def FilterComments(test_mapping_file: Text) -> Text:
+def FilterComments(test_mapping_file: str) -> str:
   """Remove comments in TEST_MAPPING file to valid format.
 
   Only '//' is regarded as comments.
@@ -52,8 +54,8 @@ def FilterComments(test_mapping_file: Text) -> Text:
   """
   return re.sub(_COMMENTS_RE, r'\1', test_mapping_file)
 
-def GetTestMappings(paths: Set[Text],
-                    checked_paths: Set[Text]) -> Dict[Text, Dict[Text, Any]]:
+def GetTestMappings(paths: set[str],
+                    checked_paths: set[str]) -> dict[str, dict[str, Any]]:
   """Get the affected TEST_MAPPING files.
 
   TEST_MAPPING files in source code are packaged into a build artifact
@@ -123,3 +125,68 @@ def GetTestMappings(paths: Set[Text],
       pass
 
   return test_mappings
+
+
+def FindAffectedModules(
+    test_mappings: dict[str, Any],
+    changed_files: set[str],
+    test_mapping_test_groups: set[str],
+) -> set[str]:
+  """Find affected test modules.
+
+  Find the affected set of test modules that would run in a test mapping run based on the given test mappings, changed files, and test mapping test group.
+
+  Args:
+    test_mappings: A set of test mappings returned by GetTestMappings in the following format:
+      {
+        'test_mapping_file_path': {
+          'group_name' : [
+            'name': 'module_name',
+          ],
+        }
+      }
+    changed_files: A set of files changed for the given run.
+    test_mapping_test_groups: A set of test mapping test groups that are being considered for the given run.
+
+  Returns:
+    A set of test module names which would run for a test mapping test run with the given parameters.
+  """
+
+  modules = set()
+
+  for test_mapping in test_mappings.values():
+    for group_name, group in test_mapping.items():
+      # If a module is not in any of the test mapping groups being tested skip
+      # it.
+      if group_name not in test_mapping_test_groups:
+        continue
+
+      for entry in group:
+        module_name = entry.get('name')
+
+        if not module_name:
+          continue
+
+        file_patterns = entry.get('file_patterns')
+        if not file_patterns:
+          modules.add(module_name)
+          continue
+
+        if matches_file_patterns(file_patterns, changed_files):
+          modules.add(module_name)
+
+  return modules
+
+def MatchesFilePatterns(
+    file_patterns: list[set], changed_files: set[str]
+) -> bool:
+  """Checks if any of the changed files match any of the file patterns.
+
+  Args:
+    file_patterns: A list of file patterns to match against.
+    changed_files: A set of files to check against the file patterns.
+
+  Returns:
+    True if any of the changed files match any of the file patterns.
+  """
+  return any(re.search(pattern, "|".join(changed_files)) for pattern in file_patterns)
diff --git a/cogsetup.sh b/cogsetup.sh
index ef1485d5f2..5c64a068e0 100644
--- a/cogsetup.sh
+++ b/cogsetup.sh
@@ -57,7 +57,7 @@ function _setup_cog_env() {
   fi
   function repo {
     if [[ "${PWD}" == /google/cog/* ]]; then
-      echo "\e[01;31mERROR:\e[0mrepo command is disallowed within Cog workspaces."
+      echo -e "\e[01;31mERROR:\e[0mrepo command is disallowed within Cog workspaces."
       return 1
     fi
     ${ORIG_REPO_PATH} "$@"
diff --git a/common/math.mk b/common/math.mk
index ecee474d14..829ceb5e6f 100644
--- a/common/math.mk
+++ b/common/math.mk
@@ -315,8 +315,9 @@ $(call math-expect,(call numbers_greater_or_equal_to,1,0 2 1 3),2 1 3)
 $(call math-expect,(call numbers_greater_or_equal_to,0,0 2 1 3),0 2 1 3)
 $(call math-expect,(call numbers_greater_or_equal_to,1,0 2 1 3 2),2 1 3 2)
 
-_INT_LIMIT_WORDS := $(foreach a,x x,$(foreach b,x x x x x x x x x x x x x x x x,\
-  $(foreach c,x x x x x x x x x x x x x x x x,x x x x x x x x x x x x x x x x)))
+# 10,001 = 10 ** 4 + 1, contains 10,001 x's, so 1 more than 10,000 (future) API level
+_INT_LIMIT_WORDS := x $(foreach a,0 1 2 3 4 5 6 7 8 9,$(foreach b,0 1 2 3 4 5 6 7 8 9,\
+  $(foreach c,0 1 2 3 4 5 6 7 8 9,x x x x x x x x x x)))
 
 define _int_encode
 $(if $(filter $(words x $(_INT_LIMIT_WORDS)),$(words $(wordlist 1,$(1),x $(_INT_LIMIT_WORDS)))),\
diff --git a/core/Makefile b/core/Makefile
index cdb8423a9d..2cdb24f9b0 100644
--- a/core/Makefile
+++ b/core/Makefile
@@ -717,7 +717,7 @@ $(foreach kmd,$(BOARD_KERNEL_MODULE_DIRS), \
   $(eval ALL_DEFAULT_INSTALLED_MODULES += $(call build-vendor-ramdisk-charger-load,$(kmd))) \
   $(eval ALL_DEFAULT_INSTALLED_MODULES += $(call build-vendor-kernel-ramdisk-charger-load,$(kmd))) \
   $(eval ALL_DEFAULT_INSTALLED_MODULES += $(call build-image-kernel-modules-dir,ODM,$(if $(filter true,$(BOARD_USES_ODM_DLKMIMAGE)),$(TARGET_OUT_ODM_DLKM),$(TARGET_OUT_ODM)),odm,modules.load,,$(kmd))) \
-  $(eval ALL_DEFAULT_INSTALLED_MODULES += $(call build-image-kernel-modules-dir,SYSTEM,$(if $(filter true,$(BOARD_USES_SYSTEM_DLKMIMAGE)),$(TARGET_OUT_SYSTEM_DLKM),$(TARGET_OUT_SYSTEM)),system,modules.load,,$(kmd))) \
+  $(eval ALL_DEFAULT_INSTALLED_MODULES += $(call build-image-kernel-modules-dir,SYSTEM,$(if $(filter true,$(BOARD_USES_SYSTEM_DLKMIMAGE)),$(TARGET_OUT_SYSTEM_DLKM),$(TARGET_OUT)),system,modules.load,,$(kmd))) \
   $(if $(filter true,$(BOARD_USES_RECOVERY_AS_BOOT)),\
     $(eval ALL_DEFAULT_INSTALLED_MODULES += $(call build-recovery-as-boot-load,$(kmd))),\
     $(eval ALL_DEFAULT_INSTALLED_MODULES += $(call build-image-kernel-modules-dir,GENERIC_RAMDISK,$(TARGET_RAMDISK_OUT),,modules.load,$(GENERIC_RAMDISK_STRIPPED_MODULE_STAGING_DIR),$(kmd)))))
@@ -1052,6 +1052,35 @@ $(INSTALLED_DTBIMAGE_TARGET) : $(sort $(wildcard $(BOARD_PREBUILT_DTBIMAGE_DIR)/
 endif
 endif
 
+
+# -----------------------------------------------------------------
+# dtbo image
+ifdef BOARD_PREBUILT_DTBOIMAGE
+INSTALLED_DTBOIMAGE_TARGET := $(PRODUCT_OUT)/dtbo.img
+
+ifeq ($(BOARD_AVB_ENABLE),true)
+$(INSTALLED_DTBOIMAGE_TARGET): $(BOARD_PREBUILT_DTBOIMAGE) $(AVBTOOL) $(BOARD_AVB_DTBO_KEY_PATH)
+	cp $(BOARD_PREBUILT_DTBOIMAGE) $@
+	chmod +w $@
+	$(AVBTOOL) add_hash_footer \
+	    --image $@ \
+	    $(call get-partition-size-argument,$(BOARD_DTBOIMG_PARTITION_SIZE)) \
+	    --partition_name dtbo $(INTERNAL_AVB_DTBO_SIGNING_ARGS) \
+	    $(BOARD_AVB_DTBO_ADD_HASH_FOOTER_ARGS)
+
+$(call declare-1p-container,$(INSTALLED_DTBOIMAGE_TARGET),)
+$(call declare-container-license-deps,$(INSTALLED_DTBOIMAGE_TARGET),$(BOARD_PREBUILT_DTBOIMAGE),$(PRODUCT_OUT)/:/)
+
+UNMOUNTED_NOTICE_VENDOR_DEPS+= $(INSTALLED_DTBOIMAGE_TARGET)
+else
+$(INSTALLED_DTBOIMAGE_TARGET): $(BOARD_PREBUILT_DTBOIMAGE)
+	cp $(BOARD_PREBUILT_DTBOIMAGE) $@
+endif
+
+endif # BOARD_PREBUILT_DTBOIMAGE
+
+# -----------------------------------------------------------------
+
 # -----------------------------------------------------------------
 # the ramdisk
 INSTALLED_FILES_OUTSIDE_IMAGES := $(filter-out $(TARGET_RAMDISK_OUT)/%, $(INSTALLED_FILES_OUTSIDE_IMAGES))
@@ -1075,6 +1104,16 @@ $(eval $(call declare-0p-target,$(INSTALLED_FILES_JSON_RAMDISK)))
 
 BUILT_RAMDISK_TARGET := $(PRODUCT_OUT)/ramdisk.img
 
+ifeq ($(BOARD_RAMDISK_USE_LZ4),true)
+# -l enables the legacy format used by the Linux kernel
+COMPRESSION_COMMAND_DEPS := $(LZ4)
+COMPRESSION_COMMAND := $(LZ4) -l -12 --favor-decSpeed
+RAMDISK_EXT := .lz4
+else
+COMPRESSION_COMMAND_DEPS := $(GZIP)
+COMPRESSION_COMMAND := $(GZIP)
+RAMDISK_EXT := .gz
+endif
 
 ifneq ($(BOARD_KERNEL_MODULES_16K),)
 
@@ -1153,6 +1192,33 @@ ramdisk_16k: $(BUILT_RAMDISK_16K_TARGET)
 
 endif
 
+# -----------------------------------------------------------------
+# 16KB dtbo image
+ifdef BOARD_PREBUILT_DTBOIMAGE_16KB
+INSTALLED_DTBOIMAGE_16KB_TARGET := $(PRODUCT_OUT)/dtbo_16k.img
+
+ifeq ($(BOARD_AVB_ENABLE),true)
+$(INSTALLED_DTBOIMAGE_16KB_TARGET): $(BOARD_PREBUILT_DTBOIMAGE_16KB) $(AVBTOOL) $(BOARD_AVB_DTBO_KEY_PATH)
+	cp $(BOARD_PREBUILT_DTBOIMAGE_16KB) $@
+	chmod +w $@
+	$(AVBTOOL) add_hash_footer \
+	    --image $@ \
+	    $(call get-partition-size-argument,$(BOARD_DTBOIMG_PARTITION_SIZE)) \
+	    --partition_name dtbo $(INTERNAL_AVB_DTBO_SIGNING_ARGS) \
+	    $(BOARD_AVB_DTBO_ADD_HASH_FOOTER_ARGS)
+
+$(call declare-1p-container,$(INSTALLED_DTBOIMAGE_16KB_TARGET),)
+$(call declare-container-license-deps,$(INSTALLED_DTBOIMAGE_16KB_TARGET),$(BOARD_PREBUILT_DTBOIMAGE_16KB),$(PRODUCT_OUT)/:/)
+
+UNMOUNTED_NOTICE_VENDOR_DEPS += $(INSTALLED_DTBOIMAGE_16KB_TARGET)
+else
+$(INSTALLED_DTBOIMAGE_16KB_TARGET): $(BOARD_PREBUILT_DTBOIMAGE_16KB)
+	cp $(BOARD_PREBUILT_DTBOIMAGE_16KB) $@
+endif
+
+endif # BOARD_PREBUILT_DTBOIMAGE_16KB
+
+
 ifneq ($(BOARD_KERNEL_PATH_16K),)
 BUILT_KERNEL_16K_TARGET := $(PRODUCT_OUT)/kernel_16k
 
@@ -1175,36 +1241,34 @@ bootimage_16k: $(BUILT_BOOTIMAGE_16K_TARGET)
 .PHONY: bootimage_16k
 
 BUILT_BOOT_OTA_PACKAGE_16K := $(PRODUCT_OUT)/boot_ota_16k.zip
-$(BUILT_BOOT_OTA_PACKAGE_16K): $(OTA_FROM_RAW_IMG) $(BUILT_BOOTIMAGE_16K_TARGET) $(INSTALLED_BOOTIMAGE_TARGET) $(DEFAULT_SYSTEM_DEV_CERTIFICATE).pk8
+$(BUILT_BOOT_OTA_PACKAGE_16K):  $(OTA_FROM_RAW_IMG) \
+                                $(BUILT_BOOTIMAGE_16K_TARGET) \
+                                $(INSTALLED_BOOTIMAGE_TARGET) \
+                                $(DEFAULT_SYSTEM_DEV_CERTIFICATE).pk8 \
+                                $(INSTALLED_DTBOIMAGE_16KB_TARGET) \
+                                $(INSTALLED_DTBOIMAGE_TARGET)
 	$(OTA_FROM_RAW_IMG) --package_key $(DEFAULT_SYSTEM_DEV_CERTIFICATE) \
                       --max_timestamp `cat $(BUILD_DATETIME_FILE)` \
                       --path $(HOST_OUT) \
-                      --partition_name boot \
+                      --partition_name $(if $(and $(INSTALLED_DTBOIMAGE_TARGET),\
+                          $(INSTALLED_DTBOIMAGE_16KB_TARGET)),\
+                        boot$(comma)dtbo,\
+                        boot) \
                       --output $@ \
                       $(if $(BOARD_16K_OTA_USE_INCREMENTAL),\
                         $(INSTALLED_BOOTIMAGE_TARGET):$(BUILT_BOOTIMAGE_16K_TARGET),\
                         $(BUILT_BOOTIMAGE_16K_TARGET)\
-                      )
+                      )\
+                      $(if $(and $(INSTALLED_DTBOIMAGE_TARGET),$(INSTALLED_DTBOIMAGE_16KB_TARGET)),\
+                        $(INSTALLED_DTBOIMAGE_16KB_TARGET))
 
 boototapackage_16k: $(BUILT_BOOT_OTA_PACKAGE_16K)
 .PHONY: boototapackage_16k
 
 endif
 
-
-ifeq ($(BOARD_RAMDISK_USE_LZ4),true)
-# -l enables the legacy format used by the Linux kernel
-COMPRESSION_COMMAND_DEPS := $(LZ4)
-COMPRESSION_COMMAND := $(LZ4) -l -12 --favor-decSpeed
-RAMDISK_EXT := .lz4
-else
-COMPRESSION_COMMAND_DEPS := $(GZIP)
-COMPRESSION_COMMAND := $(GZIP)
-RAMDISK_EXT := .gz
-endif
-
+# The value of RAMDISK_NODE_LIST is defined in system/core/rootdir/Android.bp.
 # This file contains /dev nodes description added to the generic ramdisk
-RAMDISK_NODE_LIST := $(PRODUCT_OUT)/ramdisk_node_list
 
 # We just build this directly to the install location.
 INSTALLED_RAMDISK_TARGET := $(BUILT_RAMDISK_TARGET)
@@ -1375,30 +1439,7 @@ bootimage-nodeps: $(MKBOOTIMG) $(AVBTOOL) $(BOARD_AVB_BOOT_KEY_PATH)
 	@echo "make $@: ignoring dependencies"
 	$(foreach b,$(INSTALLED_BOOTIMAGE_TARGET),$(call build_boot_board_avb_enabled,$(b)))
 
-else ifeq (true,$(PRODUCT_SUPPORTS_VBOOT)) # BOARD_AVB_ENABLE != true
-
-# $1: boot image target
-define build_boot_supports_vboot
-  $(MKBOOTIMG) --kernel $(call bootimage-to-kernel,$(1)) $(INTERNAL_BOOTIMAGE_ARGS) $(INTERNAL_MKBOOTIMG_VERSION_ARGS) $(BOARD_MKBOOTIMG_ARGS) --output $(1).unsigned
-  $(VBOOT_SIGNER) $(FUTILITY) $(1).unsigned $(PRODUCT_VBOOT_SIGNING_KEY).vbpubk $(PRODUCT_VBOOT_SIGNING_KEY).vbprivk $(PRODUCT_VBOOT_SIGNING_SUBKEY).vbprivk $(1).keyblock $(1)
-  $(call assert-max-image-size,$(1),$(call get-bootimage-partition-size,$(1),boot))
-endef
-
-$(INSTALLED_BOOTIMAGE_TARGET): $(MKBOOTIMG) $(INTERNAL_BOOTIMAGE_FILES) $(VBOOT_SIGNER) $(FUTILITY)
-	$(call pretty,"Target boot image: $@")
-	$(call build_boot_supports_vboot,$@)
-
-$(call declare-container-license-metadata,$(INSTALLED_BOOTIMAGE_TARGET),SPDX-license-identifier-GPL-2.0-only SPDX-license-identifier-Apache-2.0,restricted notice,$(BUILD_SYSTEM)/LINUX_KERNEL_COPYING build/soong/licenses/LICENSE,"Boot Image",boot)
-$(call declare-container-license-deps,$(INSTALLED_BOOTIMAGE_TARGET),$(INTERNAL_BOOTIMAGE_FILES),$(PRODUCT_OUT)/:/)
-
-UNMOUNTED_NOTICE_VENDOR_DEPS += $(INSTALLED_BOOTIMAGE_TARGET)
-
-.PHONY: bootimage-nodeps
-bootimage-nodeps: $(MKBOOTIMG) $(VBOOT_SIGNER) $(FUTILITY)
-	@echo "make $@: ignoring dependencies"
-	$(foreach b,$(INSTALLED_BOOTIMAGE_TARGET),$(call build_boot_supports_vboot,$(b)))
-
-else # PRODUCT_SUPPORTS_VBOOT != true
+else # BOARD_AVB_ENABLE != true
 
 # $1: boot image target
 define build_boot_novboot
@@ -1460,16 +1501,26 @@ endif # my_installed_prebuilt_gki_apex not defined
 
 ifneq ($(BOARD_KERNEL_PATH_16K),)
 BUILT_BOOT_OTA_PACKAGE_4K := $(PRODUCT_OUT)/boot_ota_4k.zip
-$(BUILT_BOOT_OTA_PACKAGE_4K): $(OTA_FROM_RAW_IMG) $(INSTALLED_BOOTIMAGE_TARGET) $(BUILT_BOOTIMAGE_16K_TARGET) $(DEFAULT_SYSTEM_DEV_CERTIFICATE).pk8
+$(BUILT_BOOT_OTA_PACKAGE_4K): $(OTA_FROM_RAW_IMG) \
+                              $(INSTALLED_BOOTIMAGE_TARGET) \
+                              $(BUILT_BOOTIMAGE_16K_TARGET) \
+                              $(DEFAULT_SYSTEM_DEV_CERTIFICATE).pk8 \
+                              $(INSTALLED_DTBOIMAGE_TARGET) \
+                              $(INSTALLED_DTBOIMAGE_16KB_TARGET)
 	$(OTA_FROM_RAW_IMG) --package_key $(DEFAULT_SYSTEM_DEV_CERTIFICATE) \
                       --max_timestamp `cat $(BUILD_DATETIME_FILE)` \
                       --path $(HOST_OUT) \
-                      --partition_name boot \
+                      --partition_name $(if $(and $(INSTALLED_DTBOIMAGE_TARGET),\
+                          $(INSTALLED_DTBOIMAGE_16KB_TARGET)),\
+                        boot$(comma)dtbo,\
+                        boot) \
                       --output $@ \
                       $(if $(BOARD_16K_OTA_USE_INCREMENTAL),\
                         $(BUILT_BOOTIMAGE_16K_TARGET):$(INSTALLED_BOOTIMAGE_TARGET),\
                         $(INSTALLED_BOOTIMAGE_TARGET)\
-                      )
+                      )\
+                      $(if $(and $(INSTALLED_DTBOIMAGE_TARGET),$(INSTALLED_DTBOIMAGE_16KB_TARGET)),\
+                        $(INSTALLED_DTBOIMAGE_TARGET))
 
 boototapackage_4k: $(BUILT_BOOT_OTA_PACKAGE_4K)
 .PHONY: boototapackage_4k
@@ -1697,6 +1748,30 @@ endif
 $(call declare-1p-container,$(INSTALLED_VENDOR_BOOTIMAGE_TARGET),)
 $(call declare-container-license-deps,$(INSTALLED_VENDOR_BOOTIMAGE_TARGET),$(INTERNAL_VENDOR_RAMDISK_TARGET) $(INSTALLED_DTB_IMAGE_TARGET) $(INTERNAL_VENDOR_RAMDISK_FRAGMENT_TARGETS) $(INTERNAL_VENDOR_BOOTCONDIG_TARGET),$(PRODUCT_OUT)/:/)
 VENDOR_NOTICE_DEPS += $(INSTALLED_VENDOR_BOOTIMAGE_TARGET)
+
+else # BUILDING_VENDOR_BOOT_IMAGE not defined, use prebuilt image
+
+ifdef BOARD_PREBUILT_VENDOR_BOOTIMAGE
+INTERNAL_PREBUILT_VENDOR_BOOTIMAGE := $(BOARD_PREBUILT_VENDOR_BOOTIMAGE)
+INSTALLED_VENDOR_BOOTIMAGE_TARGET := $(PRODUCT_OUT)/vendor_boot.img
+
+ifeq ($(BOARD_AVB_ENABLE),true)
+$(INSTALLED_VENDOR_BOOTIMAGE_TARGET): $(INTERNAL_PREBUILT_VENDOR_BOOTIMAGE) $(AVBTOOL) $(BOARD_AVB_VENDOR_BOOT_KEY_PATH)
+	cp $(INTERNAL_PREBUILT_VENDOR_BOOTIMAGE) $@
+	chmod +w $@
+	$(AVBTOOL) add_hash_footer \
+	    --image $@ \
+	    $(call get-partition-size-argument,$(BOARD_VENDOR_BOOTIMAGE_PARTITION_SIZE)) \
+	    --partition_name vendor_boot $(INTERNAL_AVB_VENDOR_BOOT_SIGNING_ARGS) \
+	    $(BOARD_AVB_VENDOR_BOOT_ADD_HASH_FOOTER_ARGS)
+else
+$(INSTALLED_VENDOR_BOOTIMAGE_TARGET): $(INTERNAL_PREBUILT_VENDOR_BOOTIMAGE)
+	cp $(INTERNAL_PREBUILT_VENDOR_BOOTIMAGE) $@
+
+endif # BOARD_AVB_ENABLE
+$(call declare-1p-container,$(INSTALLED_VENDOR_BOOTIMAGE_TARGET),)
+$(call declare-container-license-deps,$(INSTALLED_VENDOR_BOOTIMAGE_TARGET),$(INTERNAL_PREBUILT_VENDOR_BOOTIMAGE),$(PRODUCT_OUT)/:/)
+endif # BOARD_PREBUILT_VENDOR_BOOTIMAGE
 endif # BUILDING_VENDOR_BOOT_IMAGE
 
 # -----------------------------------------------------------------
@@ -1889,7 +1964,7 @@ target_system_dlkm_notice_file_xml_gz := $(TARGET_OUT_INTERMEDIATES)/NOTICE_SYST
 installed_system_dlkm_notice_xml_gz := $(TARGET_OUT_SYSTEM_DLKM)/etc/NOTICE.xml.gz
 
 ALL_INSTALLED_NOTICE_FILES := \
-  $(installed_notice_html_or_xml_gz) \
+  $(if $(USE_SOONG_DEFINED_SYSTEM_IMAGE),,$(installed_notice_html_or_xml_gz)) \
   $(installed_vendor_notice_xml_gz) \
   $(installed_product_notice_xml_gz) \
   $(installed_system_ext_notice_xml_gz) \
@@ -1976,7 +2051,9 @@ endif
 
 endif # PRODUCT_NOTICE_SPLIT
 
+ifneq ($(USE_SOONG_DEFINED_SYSTEM_IMAGE),true)
 ALL_DEFAULT_INSTALLED_MODULES += $(installed_notice_html_or_xml_gz)
+endif
 
 need_vendor_notice:=false
 ifeq ($(BUILDING_VENDOR_BOOT_IMAGE),true)
@@ -2233,11 +2310,6 @@ $(if $(PRODUCT_SYSTEM_EXT_VERITY_PARTITION),$(hide) echo "system_ext_verity_bloc
 $(if $(PRODUCT_VENDOR_DLKM_VERITY_PARTITION),$(hide) echo "vendor_dlkm_verity_block_device=$(PRODUCT_VENDOR_DLKM_VERITY_PARTITION)" >> $(1))
 $(if $(PRODUCT_ODM_DLKM_VERITY_PARTITION),$(hide) echo "odm_dlkm_verity_block_device=$(PRODUCT_ODM_DLKM_VERITY_PARTITION)" >> $(1))
 $(if $(PRODUCT_SYSTEM_DLKM_VERITY_PARTITION),$(hide) echo "system_dlkm_verity_block_device=$(PRODUCT_SYSTEM_DLKM_VERITY_PARTITION)" >> $(1))
-$(if $(PRODUCT_SUPPORTS_VBOOT),$(hide) echo "vboot=$(PRODUCT_SUPPORTS_VBOOT)" >> $(1))
-$(if $(PRODUCT_SUPPORTS_VBOOT),$(hide) echo "vboot_key=$(PRODUCT_VBOOT_SIGNING_KEY)" >> $(1))
-$(if $(PRODUCT_SUPPORTS_VBOOT),$(hide) echo "vboot_subkey=$(PRODUCT_VBOOT_SIGNING_SUBKEY)" >> $(1))
-$(if $(PRODUCT_SUPPORTS_VBOOT),$(hide) echo "futility=$(notdir $(FUTILITY))" >> $(1))
-$(if $(PRODUCT_SUPPORTS_VBOOT),$(hide) echo "vboot_signer_cmd=$(VBOOT_SIGNER)" >> $(1))
 $(if $(BOARD_AVB_ENABLE), \
   $(hide) echo "avb_avbtool=$(notdir $(AVBTOOL))" >> $(1)$(newline) \
   $(if $(filter $(2),system), \
@@ -2747,15 +2819,9 @@ $(recovery_ramdisk): $(INTERNAL_RECOVERY_RAMDISK_FILES_TIMESTAMP)
 # $(1): output file
 # $(2): optional kernel file
 define build-recoveryimage-target
-  $(if $(filter true,$(PRODUCT_SUPPORTS_VBOOT)), \
-    $(MKBOOTIMG) $(if $(strip $(2)),--kernel $(strip $(2))) $(INTERNAL_RECOVERYIMAGE_ARGS) \
-                 $(INTERNAL_MKBOOTIMG_VERSION_ARGS) $(BOARD_RECOVERY_MKBOOTIMG_ARGS) \
-                 --output $(1).unsigned, \
-    $(MKBOOTIMG) $(if $(strip $(2)),--kernel $(strip $(2))) $(INTERNAL_RECOVERYIMAGE_ARGS) \
-                 $(INTERNAL_MKBOOTIMG_VERSION_ARGS) \
-                 $(BOARD_RECOVERY_MKBOOTIMG_ARGS) --output $(1))
-  $(if $(filter true,$(PRODUCT_SUPPORTS_VBOOT)), \
-    $(VBOOT_SIGNER) $(FUTILITY) $(1).unsigned $(PRODUCT_VBOOT_SIGNING_KEY).vbpubk $(PRODUCT_VBOOT_SIGNING_KEY).vbprivk $(PRODUCT_VBOOT_SIGNING_SUBKEY).vbprivk $(1).keyblock $(1))
+  $(MKBOOTIMG) $(if $(strip $(2)),--kernel $(strip $(2))) $(INTERNAL_RECOVERYIMAGE_ARGS) \
+               $(INTERNAL_MKBOOTIMG_VERSION_ARGS) \
+               $(BOARD_RECOVERY_MKBOOTIMG_ARGS) --output $(1)
   $(if $(filter true,$(BOARD_USES_RECOVERY_AS_BOOT)), \
     $(call assert-max-image-size,$(1),$(call get-hash-image-max-size,$(call get-bootimage-partition-size,$(1),boot))), \
     $(call assert-max-image-size,$(1),$(call get-hash-image-max-size,$(BOARD_RECOVERYIMAGE_PARTITION_SIZE))))
@@ -2766,9 +2832,6 @@ define build-recoveryimage-target
 endef
 
 recoveryimage-deps := $(MKBOOTIMG) $(recovery_ramdisk) $(recovery_kernel)
-ifeq (true,$(PRODUCT_SUPPORTS_VBOOT))
-  recoveryimage-deps += $(VBOOT_SIGNER)
-endif
 ifeq (true,$(BOARD_AVB_ENABLE))
   recoveryimage-deps += $(AVBTOOL) $(BOARD_AVB_BOOT_KEY_PATH)
 endif
@@ -3355,8 +3418,10 @@ endif  # PRODUCT_FSVERITY_GENERATE_METADATA
 # system image
 
 INSTALLED_FILES_OUTSIDE_IMAGES := $(filter-out $(TARGET_OUT)/%, $(INSTALLED_FILES_OUTSIDE_IMAGES))
+ifdef BUILDING_SYSTEM_IMAGE
 INTERNAL_SYSTEMIMAGE_FILES := $(sort $(filter $(TARGET_OUT)/%, \
     $(ALL_DEFAULT_INSTALLED_MODULES)))
+endif
 
 # Create symlink /system/vendor to /vendor if necessary.
 ifdef BOARD_USES_VENDORIMAGE
@@ -3448,6 +3513,8 @@ $(SYSTEM_LINKER_CONFIG): $(INTERNAL_SYSTEMIMAGE_FILES) $(SYSTEM_LINKER_CONFIG_SO
 		--output $@ --value "$(STUB_LIBRARIES)" --system "$(TARGET_OUT)"
 	$(HOST_OUT_EXECUTABLES)/conv_linker_config append --source $@ --output $@ --key requireLibs \
 		--value "$(foreach lib,$(LLNDK_MOVED_TO_APEX_LIBRARIES), $(lib).so)"
+	$(HOST_OUT_EXECUTABLES)/conv_linker_config append --source $@ --output $@ --key provideLibs \
+		--value "$(foreach lib,$(PRODUCT_EXTRA_STUB_LIBRARIES), $(lib).so)"
 
 $(call declare-1p-target,$(SYSTEM_LINKER_CONFIG),)
 $(call declare-license-deps,$(SYSTEM_LINKER_CONFIG),$(INTERNAL_SYSTEMIMAGE_FILES) $(SYSTEM_LINKER_CONFIG_SOURCE))
@@ -3495,6 +3562,24 @@ define build-systemimage-target
 endef
 
 $(eval $(call write-partition-file-list,$(systemimage_intermediates)/file_list.txt,$(TARGET_OUT),$(FULL_SYSTEMIMAGE_DEPS)))
+
+ifneq ($(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE),)
+file_list_diff := $(HOST_OUT_EXECUTABLES)/file_list_diff$(HOST_EXECUTABLE_SUFFIX)
+system_file_diff_timestamp := $(systemimage_intermediates)/file_diff.timestamp
+
+$(system_file_diff_timestamp): \
+	    $(systemimage_intermediates)/file_list.txt \
+	    $(ALL_MODULES.$(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE).FILESYSTEM_FILELIST) \
+	    $(ALL_MODULES.system_image_diff_allowlist.INSTALLED) \
+	    $(file_list_diff)
+	$(file_list_diff) $(systemimage_intermediates)/file_list.txt \
+	  $(ALL_MODULES.$(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE).FILESYSTEM_FILELIST) \
+	  $(ALL_MODULES.system_image_diff_allowlist.INSTALLED) $(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE)
+	touch $@
+
+$(BUILT_SYSTEMIMAGE): $(system_file_diff_timestamp)
+endif
+
 # Used by soong sandwich to request the staging dir be built
 $(systemimage_intermediates)/staging_dir.stamp: $(filter $(TARGET_OUT)/%,$(FULL_SYSTEMIMAGE_DEPS))
 	touch $@
@@ -3502,8 +3587,19 @@ $(systemimage_intermediates)/staging_dir.stamp: $(filter $(TARGET_OUT)/%,$(FULL_
 ifeq ($(BOARD_AVB_ENABLE),true)
 $(BUILT_SYSTEMIMAGE): $(BOARD_AVB_SYSTEM_KEY_PATH)
 endif
+
+ifeq ($(USE_SOONG_DEFINED_SYSTEM_IMAGE),true)
+ifeq ($(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE),)
+$(error PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE must be set if USE_SOONG_DEFINED_SYSTEM_IMAGE is true)
+endif
+SOONG_DEFINED_SYSTEM_IMAGE_PATH := $(call intermediates-dir-for,ETC,$(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE))/$(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE)
+SOONG_DEFINED_SYSTEM_IMAGE_BASE := $(dir $(ALL_MODULES.$(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE).FILESYSTEM_FILELIST))
+$(BUILT_SYSTEMIMAGE): $(INSTALLED_FILES_FILE) $(systemimage_intermediates)/file_list.txt $(SOONG_DEFINED_SYSTEM_IMAGE_PATH)
+$(eval $(call copy-one-file, $(SOONG_DEFINED_SYSTEM_IMAGE_PATH), $(BUILT_SYSTEMIMAGE)))
+else
 $(BUILT_SYSTEMIMAGE): $(FULL_SYSTEMIMAGE_DEPS) $(INSTALLED_FILES_FILE) $(systemimage_intermediates)/file_list.txt
 	$(call build-systemimage-target,$@)
+endif
 
 $(call declare-1p-container,$(BUILT_SYSTEMIMAGE),system/extras)
 $(call declare-container-license-deps,$(BUILT_SYSTEMIMAGE),$(FULL_SYSTEMIMAGE_DEPS),$(PRODUCT_OUT)/:/)
@@ -3584,10 +3680,10 @@ platform-java:
 # -----------------------------------------------------------------
 # data partition image
 INSTALLED_FILES_OUTSIDE_IMAGES := $(filter-out $(TARGET_OUT_DATA)/%, $(INSTALLED_FILES_OUTSIDE_IMAGES))
+ifdef BUILDING_USERDATA_IMAGE
 INTERNAL_USERDATAIMAGE_FILES := \
     $(filter $(TARGET_OUT_DATA)/%,$(ALL_DEFAULT_INSTALLED_MODULES))
 
-ifdef BUILDING_USERDATA_IMAGE
 userdataimage_intermediates := \
     $(call intermediates-dir-for,PACKAGING,userdata)
 BUILT_USERDATAIMAGE_TARGET := $(PRODUCT_OUT)/userdata.img
@@ -4332,33 +4428,6 @@ INSTALLED_SYSTEM_DLKMIMAGE_TARGET := $(PRODUCT_OUT)/system_dlkm.img
 $(eval $(call copy-one-file,$(BOARD_PREBUILT_SYSTEM_DLKMIMAGE),$(INSTALLED_SYSTEM_DLKMIMAGE_TARGET)))
 endif
 
-# -----------------------------------------------------------------
-# dtbo image
-ifdef BOARD_PREBUILT_DTBOIMAGE
-INSTALLED_DTBOIMAGE_TARGET := $(PRODUCT_OUT)/dtbo.img
-
-ifeq ($(BOARD_AVB_ENABLE),true)
-$(INSTALLED_DTBOIMAGE_TARGET): $(BOARD_PREBUILT_DTBOIMAGE) $(AVBTOOL) $(BOARD_AVB_DTBO_KEY_PATH)
-	cp $(BOARD_PREBUILT_DTBOIMAGE) $@
-	chmod +w $@
-	$(AVBTOOL) add_hash_footer \
-	    --image $@ \
-	    $(call get-partition-size-argument,$(BOARD_DTBOIMG_PARTITION_SIZE)) \
-	    --partition_name dtbo $(INTERNAL_AVB_DTBO_SIGNING_ARGS) \
-	    $(BOARD_AVB_DTBO_ADD_HASH_FOOTER_ARGS)
-
-$(call declare-1p-container,$(INSTALLED_DTBOIMAGE_TARGET),)
-$(call declare-container-license-deps,$(INSTALLED_DTBOIMAGE_TARGET),$(BOARD_PREBUILT_DTBOIMAGE),$(PRODUCT_OUT)/:/)
-
-UNMOUNTED_NOTICE_VENDOR_DEPS+= $(INSTALLED_DTBOIMAGE_TARGET)
-else
-$(INSTALLED_DTBOIMAGE_TARGET): $(BOARD_PREBUILT_DTBOIMAGE)
-	cp $(BOARD_PREBUILT_DTBOIMAGE) $@
-endif
-
-endif # BOARD_PREBUILT_DTBOIMAGE
-
-# -----------------------------------------------------------------
 # Protected VM firmware image
 ifeq ($(BOARD_USES_PVMFWIMAGE),true)
 
@@ -5072,6 +5141,7 @@ apex_dirs := \
   $(TARGET_OUT)/apex/% \
   $(TARGET_OUT_SYSTEM_EXT)/apex/% \
   $(TARGET_OUT_VENDOR)/apex/% \
+  $(TARGET_OUT_ODM)/apex/% \
   $(TARGET_OUT_PRODUCT)/apex/% \
 
 apex_files := $(sort $(filter $(apex_dirs), $(INTERNAL_ALLIMAGES_FILES)))
@@ -5124,6 +5194,7 @@ apex_dirs := \
   $(TARGET_OUT_PRODUCT)/apex/% \
   $(TARGET_OUT_SYSTEM_EXT)/apex/% \
   $(TARGET_OUT_VENDOR)/apex/% \
+  $(TARGET_OUT_ODM)/apex/% \
 
 apex_files := $(sort $(filter $(apex_dirs), $(INTERNAL_ALLIMAGES_FILES)))
 
@@ -5142,6 +5213,7 @@ $(APEX_INFO_FILE): $(HOST_OUT_EXECUTABLES)/apexd_host $(apex_files)
 	   --system_ext_path $(TARGET_OUT_SYSTEM_EXT) \
 	   --product_path $(TARGET_OUT_PRODUCT) \
 	   --vendor_path $(TARGET_OUT_VENDOR) \
+	   --odm_path $(TARGET_OUT_ODM) \
 	   --apex_path $(APEX_OUT)
 
 apex_files :=
@@ -5651,12 +5723,6 @@ INTERNAL_OTATOOLS_MODULES += \
   resize2fs \
   soong_zip \
 
-ifeq (true,$(PRODUCT_SUPPORTS_VBOOT))
-INTERNAL_OTATOOLS_MODULES += \
-  futility-host \
-  vboot_signer
-endif
-
 INTERNAL_OTATOOLS_FILES := \
   $(filter $(HOST_OUT)/%,$(call module-installed-files,$(INTERNAL_OTATOOLS_MODULES)))
 
@@ -5692,10 +5758,6 @@ INTERNAL_OTATOOLS_PACKAGE_FILES += \
   $(sort $(shell find external/avb/test/data -type f -name "testkey_*.pem" -o \
       -name "atx_metadata.bin"))
 endif
-ifeq (true,$(PRODUCT_SUPPORTS_VBOOT))
-INTERNAL_OTATOOLS_PACKAGE_FILES += \
-  $(sort $(shell find external/vboot_reference/tests/devkeys -type f))
-endif
 
 INTERNAL_OTATOOLS_RELEASETOOLS := \
   $(shell find build/make/tools/releasetools -name "*.pyc" -prune -o \
@@ -6076,6 +6138,9 @@ $(BUILT_TARGET_FILES_PACKAGE): zip_root := $(intermediates)/$(name)
 $(BUILT_TARGET_FILES_DIR): zip_root := $(intermediates)/$(name)
 $(BUILT_TARGET_FILES_DIR): intermediates := $(intermediates)
 
+ifneq ($(SOONG_DEFINED_SYSTEM_IMAGE_PATH),)
+  $(BUILT_TARGET_FILES_DIR): $(SOONG_DEFINED_SYSTEM_IMAGE_PATH)
+endif
 
 # $(1): Directory to copy
 # $(2): Location to copy it to
@@ -6132,12 +6197,6 @@ ifeq ($(AB_OTA_UPDATER),true)
     $(BUILT_TARGET_FILES_DIR): $(TARGET_OUT_OEM)/$(OSRELEASED_DIRECTORY)/product_version
     $(BUILT_TARGET_FILES_DIR): $(TARGET_OUT_ETC)/$(OSRELEASED_DIRECTORY)/system_version
   endif
-
-  # Not checking in board_config.mk, since AB_OTA_PARTITIONS may be updated in Android.mk (e.g. to
-  # additionally include radio or bootloader partitions).
-  ifeq ($(AB_OTA_PARTITIONS),)
-    $(error AB_OTA_PARTITIONS must be defined when using AB_OTA_UPDATER)
-  endif
 endif
 
 ifneq ($(AB_OTA_PARTITIONS),)
@@ -6410,8 +6469,11 @@ $(BUILT_TARGET_FILES_DIR): \
 	    $(INSTALLED_RAMDISK_TARGET) \
 	    $(INSTALLED_DTBIMAGE_TARGET) \
 	    $(INSTALLED_2NDBOOTLOADER_TARGET) \
+	    $(INSTALLED_VENDOR_KERNEL_RAMDISK_TARGET) \
 	    $(BUILT_RAMDISK_16K_TARGET) \
 	    $(BUILT_KERNEL_16K_TARGET) \
+	    $(BUILT_BOOTIMAGE_16K_TARGET) \
+	    $(INSTALLED_DTBOIMAGE_16KB_TARGET) \
 	    $(BOARD_PREBUILT_DTBOIMAGE) \
 	    $(BOARD_PREBUILT_RECOVERY_DTBOIMAGE) \
 	    $(BOARD_RECOVERY_ACPIO) \
@@ -6565,8 +6627,13 @@ endif
 endif # INSTALLED_VENDOR_BOOTIMAGE_TARGET
 ifdef BUILDING_SYSTEM_IMAGE
 	@# Contents of the system image
+ifneq ($(SOONG_DEFINED_SYSTEM_IMAGE_PATH),)
+	$(hide) $(call package_files-copy-root, \
+	    $(SOONG_DEFINED_SYSTEM_IMAGE_BASE)/root/system,$(zip_root)/SYSTEM)
+else
 	$(hide) $(call package_files-copy-root, \
 	    $(SYSTEMIMAGE_SOURCE_DIR),$(zip_root)/SYSTEM)
+endif
 else ifdef INSTALLED_BUILD_PROP_TARGET
 	@# Copy the system build.prop even if not building a system image
 	@# because add_img_to_target_files may need it to build other partition
@@ -6708,6 +6775,10 @@ ifeq ($(BREAKPAD_GENERATE_SYMBOLS),true)
 	@# If breakpad symbols have been generated, add them to the zip.
 	$(hide) cp -R $(TARGET_OUT_BREAKPAD) $(zip_root)/BREAKPAD
 endif
+ifdef BOARD_PREBUILT_VENDOR_BOOTIMAGE
+	$(hide) mkdir -p $(zip_root)/IMAGES
+	$(hide) cp $(INSTALLED_VENDOR_BOOTIMAGE_TARGET) $(zip_root)/IMAGES/
+endif
 ifdef BOARD_PREBUILT_VENDORIMAGE
 	$(hide) mkdir -p $(zip_root)/IMAGES
 	$(hide) cp $(INSTALLED_VENDORIMAGE_TARGET) $(zip_root)/IMAGES/
@@ -6756,14 +6827,22 @@ ifdef BOARD_PREBUILT_DTBOIMAGE
 	$(hide) mkdir -p $(zip_root)/PREBUILT_IMAGES
 	$(hide) cp $(INSTALLED_DTBOIMAGE_TARGET) $(zip_root)/PREBUILT_IMAGES/
 endif # BOARD_PREBUILT_DTBOIMAGE
-ifdef BUILT_KERNEL_16K_TARGET
+ifdef BOARD_KERNEL_PATH_16K
 	$(hide) mkdir -p $(zip_root)/PREBUILT_IMAGES
 	$(hide) cp $(BUILT_KERNEL_16K_TARGET) $(zip_root)/PREBUILT_IMAGES/
-endif # BUILT_KERNEL_16K_TARGET
-ifdef BUILT_RAMDISK_16K_TARGET
+endif # BOARD_KERNEL_PATH_16K
+ifdef BOARD_KERNEL_MODULES_16K
 	$(hide) mkdir -p $(zip_root)/PREBUILT_IMAGES
 	$(hide) cp $(BUILT_RAMDISK_16K_TARGET) $(zip_root)/PREBUILT_IMAGES/
-endif # BUILT_RAMDISK_16K_TARGET
+endif # BOARD_KERNEL_MODULES_16K
+ifdef BUILT_BOOTIMAGE_16K_TARGET
+	$(hide) mkdir -p $(zip_root)/IMAGES
+	$(hide) cp $(BUILT_BOOTIMAGE_16K_TARGET) $(zip_root)/IMAGES/
+endif # BUILT_BOOTIMAGE_16K_TARGET
+ifdef INSTALLED_DTBOIMAGE_16KB_TARGET
+	$(hide) mkdir -p $(zip_root)/IMAGES
+	$(hide) cp $(INSTALLED_DTBOIMAGE_16KB_TARGET) $(zip_root)/IMAGES/
+endif # INSTALLED_DTBOIMAGE_16KB_TARGET
 ifeq ($(BOARD_USES_PVMFWIMAGE),true)
 	$(hide) mkdir -p $(zip_root)/PREBUILT_IMAGES
 	$(hide) cp $(INSTALLED_PVMFWIMAGE_TARGET) $(zip_root)/PREBUILT_IMAGES/
@@ -6831,6 +6910,33 @@ ifdef BOARD_KERNEL_PAGESIZE
 	$(hide) echo "$(BOARD_KERNEL_PAGESIZE)" > $(zip_root)/INIT_BOOT/pagesize
 endif # BOARD_KERNEL_PAGESIZE
 endif # BUILDING_INIT_BOOT_IMAGE
+ifdef BOARD_EROFS_COMPRESS_HINTS
+	$(hide) cp $(BOARD_EROFS_COMPRESS_HINTS) $(zip_root)/META/erofs_default_compress_hints.txt
+endif
+ifdef BOARD_SYSTEMIMAGE_EROFS_COMPRESS_HINTS
+	$(hide) cp $(BOARD_SYSTEMIMAGE_EROFS_COMPRESS_HINTS) $(zip_root)/META/system_erofs_compress_hints.txt
+endif
+ifdef BOARD_SYSTEM_EXTIMAGE_EROFS_COMPRESS_HINTS
+	$(hide) cp $(BOARD_SYSTEM_EXTIMAGE_EROFS_COMPRESS_HINTS) $(zip_root)/META/system_ext_erofs_compress_hints.txt
+endif
+ifdef BOARD_PRODUCTIMAGE_EROFS_COMPRESS_HINTS
+	$(hide) cp $(BOARD_PRODUCTIMAGE_EROFS_COMPRESS_HINTS) $(zip_root)/META/product_erofs_compress_hints.txt
+endif
+ifdef BOARD_VENDORIMAGE_EROFS_COMPRESS_HINTS
+	$(hide) cp $(BOARD_VENDORIMAGE_EROFS_COMPRESS_HINTS) $(zip_root)/META/vendor_erofs_compress_hints.txt
+endif
+ifdef BOARD_ODMIMAGE_EROFS_COMPRESS_HINTS
+	$(hide) cp $(BOARD_ODMIMAGE_EROFS_COMPRESS_HINTS) $(zip_root)/META/odm_erofs_compress_hints.txt
+endif
+ifdef BOARD_VENDOR_DLKMIMAGE_EROFS_COMPRESS_HINTS
+	$(hide) cp $(BOARD_VENDOR_DLKMIMAGE_EROFS_COMPRESS_HINTS) $(zip_root)/META/vendor_dlkm_erofs_compress_hints.txt
+endif
+ifdef BOARD_ODM_DLKMIMAGE_EROFS_COMPRESS_HINTS
+	$(hide) cp $(BOARD_ODM_DLKMIMAGE_EROFS_COMPRESS_HINTS) $(zip_root)/META/odm_dlkm_erofs_compress_hints.txt
+endif
+ifdef BOARD_SYSTEM_DLKMIMAGE_EROFS_COMPRESS_HINTS
+	$(hide) cp $(BOARD_SYSTEM_DLKMIMAGE_EROFS_COMPRESS_HINTS) $(zip_root)/META/system_dlkm_erofs_compress_hints.txt
+endif
 ifneq ($(INSTALLED_VENDOR_BOOTIMAGE_TARGET),)
 	$(call fs_config,$(zip_root)/VENDOR_BOOT/RAMDISK,) > $(zip_root)/META/vendor_boot_filesystem_config.txt
 endif
@@ -7807,9 +7913,78 @@ haiku-presubmit: $(SOONG_PRESUBMIT_FUZZ_PACKAGING_ARCH_MODULES) $(ALL_PRESUBMIT_
 $(call dist-for-goals,haiku-presubmit,$(SOONG_PRESUBMIT_FUZZ_PACKAGING_ARCH_MODULES))
 
 # -----------------------------------------------------------------
-# Extract platform fonts used in Layoutlib
+# Extract additional data files used in Layoutlib
 include $(BUILD_SYSTEM)/layoutlib_data.mk
 
+# -----------------------------------------------------------------
+# Desktop pack common variables.
+PACK_IMAGE_SCRIPT := $(HOST_OUT_EXECUTABLES)/pack_image
+IMAGES := $(INSTALLED_BOOTIMAGE_TARGET) \
+	$(INSTALLED_SUPERIMAGE_TARGET) \
+	$(INSTALLED_INIT_BOOT_IMAGE_TARGET) \
+	$(INSTALLED_VENDOR_BOOTIMAGE_TARGET) \
+	$(INSTALLED_VBMETAIMAGE_TARGET) \
+	$(INSTALLED_USERDATAIMAGE_TARGET)
+
+# -----------------------------------------------------------------
+# Desktop pack image hook.
+ifneq (,$(strip $(PACK_DESKTOP_FILESYSTEM_IMAGES)))
+PACK_IMAGE_TARGET := $(PRODUCT_OUT)/android-desktop_image.bin
+
+$(PACK_IMAGE_TARGET): $(IMAGES) $(PACK_IMAGE_SCRIPT)
+	$(PACK_IMAGE_SCRIPT) --out_dir $(PRODUCT_OUT) --noarchive
+
+PACKED_IMAGE_ARCHIVE_TARGET := $(PACK_IMAGE_TARGET).gz
+
+$(PACKED_IMAGE_ARCHIVE_TARGET): $(PACK_IMAGE_TARGET) | $(GZIP)
+	$(GZIP) -fk $(PACK_IMAGE_TARGET)
+
+$(call dist-for-goals,dist_files,$(PACKED_IMAGE_ARCHIVE_TARGET))
+
+.PHONY: pack-image
+pack-image: $(PACK_IMAGE_TARGET)
+
+endif # PACK_DESKTOP_FILESYSTEM_IMAGES
+
+# -----------------------------------------------------------------
+# Desktop pack recovery image hook.
+ifneq (,$(strip $(PACK_DESKTOP_RECOVERY_IMAGE)))
+PACK_RECOVERY_IMAGE_TARGET := $(PRODUCT_OUT)/android-desktop_recovery_image.bin
+
+$(PACK_RECOVERY_IMAGE_TARGET): $(IMAGES) $(PACK_IMAGE_SCRIPT)
+	$(PACK_IMAGE_SCRIPT) --out_dir $(PRODUCT_OUT) --noarchive --recovery
+
+PACKED_RECOVERY_IMAGE_ARCHIVE_TARGET := $(PACK_RECOVERY_IMAGE_TARGET).gz
+
+$(PACKED_RECOVERY_IMAGE_ARCHIVE_TARGET): $(PACK_RECOVERY_IMAGE_TARGET) | $(GZIP)
+	$(GZIP) -fk $(PACK_RECOVERY_IMAGE_TARGET)
+
+$(call dist-for-goals,dist_files,$(PACKED_RECOVERY_IMAGE_ARCHIVE_TARGET))
+
+.PHONY: pack-recovery-image
+pack-recovery-image: $(PACK_RECOVERY_IMAGE_TARGET)
+
+endif # PACK_DESKTOP_RECOVERY_IMAGE
+
+# -----------------------------------------------------------------
+# Desktop pack update image hook.
+ifneq (,$(strip $(PACK_DESKTOP_UPDATE_IMAGE)))
+PACK_UPDATE_IMAGE_TARGET := $(PRODUCT_OUT)/android-desktop_update_image.bin
+
+$(PACK_UPDATE_IMAGE_TARGET): $(IMAGES) $(PACK_IMAGE_SCRIPT)
+	$(PACK_IMAGE_SCRIPT) --out_dir $(PRODUCT_OUT) --noarchive --update
+
+PACKED_UPDATE_IMAGE_ARCHIVE_TARGET := $(PACK_UPDATE_IMAGE_TARGET).gz
+
+$(PACKED_UPDATE_IMAGE_ARCHIVE_TARGET): $(PACK_UPDATE_IMAGE_TARGET) | $(GZIP)
+	$(GZIP) -fk $(PACK_UPDATE_IMAGE_TARGET)
+
+$(call dist-for-goals,dist_files,$(PACKED_UPDATE_IMAGE_ARCHIVE_TARGET))
+
+.PHONY: pack-update-image
+pack-update-image: $(PACK_UPDATE_IMAGE_TARGET)
+
+endif # PACK_DESKTOP_UPDATE_IMAGE
 
 # -----------------------------------------------------------------
 # OS Licensing
diff --git a/core/android_soong_config_vars.mk b/core/android_soong_config_vars.mk
index 9b536f0ad6..7ba186b73b 100644
--- a/core/android_soong_config_vars.mk
+++ b/core/android_soong_config_vars.mk
@@ -27,20 +27,38 @@ $(call add_soong_config_namespace,ANDROID)
 # Add variables to the namespace below:
 
 $(call add_soong_config_var,ANDROID,BOARD_USES_ODMIMAGE)
-$(call add_soong_config_var,ANDROID,BOARD_USES_RECOVERY_AS_BOOT)
+$(call soong_config_set_bool,ANDROID,BOARD_USES_RECOVERY_AS_BOOT,$(BOARD_USES_RECOVERY_AS_BOOT))
+$(call soong_config_set_bool,ANDROID,BOARD_MOVE_GSI_AVB_KEYS_TO_VENDOR_BOOT,$(BOARD_MOVE_GSI_AVB_KEYS_TO_VENDOR_BOOT))
 $(call add_soong_config_var,ANDROID,CHECK_DEV_TYPE_VIOLATIONS)
+$(call add_soong_config_var,ANDROID,PLATFORM_SEPOLICY_VERSION)
 $(call add_soong_config_var,ANDROID,PLATFORM_SEPOLICY_COMPAT_VERSIONS)
 $(call add_soong_config_var,ANDROID,PRODUCT_INSTALL_DEBUG_POLICY_TO_SYSTEM_EXT)
 $(call add_soong_config_var,ANDROID,TARGET_DYNAMIC_64_32_DRMSERVER)
 $(call add_soong_config_var,ANDROID,TARGET_ENABLE_MEDIADRM_64)
 $(call add_soong_config_var,ANDROID,TARGET_DYNAMIC_64_32_MEDIASERVER)
 
+# For Sanitizers
+$(call soong_config_set_bool,ANDROID,ASAN_ENABLED,$(if $(filter address,$(SANITIZE_TARGET)),true,false))
+$(call soong_config_set_bool,ANDROID,HWASAN_ENABLED,$(if $(filter hwaddress,$(SANITIZE_TARGET)),true,false))
+$(call soong_config_set_bool,ANDROID,SANITIZE_TARGET_SYSTEM_ENABLED,$(if $(filter true,$(SANITIZE_TARGET_SYSTEM)),true,false))
+
+# For init.environ.rc
+$(call soong_config_set_bool,ANDROID,GCOV_COVERAGE,$(NATIVE_COVERAGE))
+$(call soong_config_set_bool,ANDROID,CLANG_COVERAGE,$(CLANG_COVERAGE))
+$(call soong_config_set,ANDROID,SCUDO_ALLOCATION_RING_BUFFER_SIZE,$(PRODUCT_SCUDO_ALLOCATION_RING_BUFFER_SIZE))
+
+$(call soong_config_set_bool,ANDROID,EMMA_INSTRUMENT,$(if $(filter true,$(EMMA_INSTRUMENT)),true,false))
+
 # PRODUCT_PRECOMPILED_SEPOLICY defaults to true. Explicitly check if it's "false" or not.
-$(call add_soong_config_var_value,ANDROID,PRODUCT_PRECOMPILED_SEPOLICY,$(if $(filter false,$(PRODUCT_PRECOMPILED_SEPOLICY)),false,true))
+$(call soong_config_set_bool,ANDROID,PRODUCT_PRECOMPILED_SEPOLICY,$(if $(filter false,$(PRODUCT_PRECOMPILED_SEPOLICY)),false,true))
 
+# For art modules
+$(call soong_config_set_bool,art_module,host_prefer_32_bit,$(if $(filter true,$(HOST_PREFER_32_BIT)),true,false))
 ifdef ART_DEBUG_OPT_FLAG
 $(call soong_config_set,art_module,art_debug_opt_flag,$(ART_DEBUG_OPT_FLAG))
 endif
+# The default value of ART_BUILD_HOST_DEBUG is true
+$(call soong_config_set_bool,art_module,art_build_host_debug,$(if $(filter false,$(ART_BUILD_HOST_DEBUG)),false,true))
 
 ifdef TARGET_BOARD_AUTO
   $(call add_soong_config_var_value, ANDROID, target_board_auto, $(TARGET_BOARD_AUTO))
@@ -55,15 +73,13 @@ $(call add_soong_config_var_value,ANDROID,library_linking_strategy,prefer_static
 endif
 endif
 
-# TODO(b/308187800): some internal modules set `prefer` to true on the prebuilt apex module,
-# and set that to false when `ANDROID.module_build_from_source` is true.
-# Set this soong config variable to true for now, and cleanup `prefer` as part of b/308187800
-$(call add_soong_config_var_value,ANDROID,module_build_from_source,true)
-
 # Enable SystemUI optimizations by default unless explicitly set.
 SYSTEMUI_OPTIMIZE_JAVA ?= true
 $(call add_soong_config_var,ANDROID,SYSTEMUI_OPTIMIZE_JAVA)
 
+# Flag for enabling compose for Launcher.
+$(call soong_config_set,ANDROID,release_enable_compose_in_launcher,$(RELEASE_ENABLE_COMPOSE_IN_LAUNCHER))
+
 ifdef PRODUCT_AVF_ENABLED
 $(call add_soong_config_var_value,ANDROID,avf_enabled,$(PRODUCT_AVF_ENABLED))
 endif
@@ -89,6 +105,7 @@ endif
 $(call add_soong_config_var_value,ANDROID,release_avf_allow_preinstalled_apps,$(RELEASE_AVF_ALLOW_PREINSTALLED_APPS))
 $(call add_soong_config_var_value,ANDROID,release_avf_enable_device_assignment,$(RELEASE_AVF_ENABLE_DEVICE_ASSIGNMENT))
 $(call add_soong_config_var_value,ANDROID,release_avf_enable_dice_changes,$(RELEASE_AVF_ENABLE_DICE_CHANGES))
+$(call add_soong_config_var_value,ANDROID,release_avf_enable_early_vm,$(RELEASE_AVF_ENABLE_EARLY_VM))
 $(call add_soong_config_var_value,ANDROID,release_avf_enable_llpvm_changes,$(RELEASE_AVF_ENABLE_LLPVM_CHANGES))
 $(call add_soong_config_var_value,ANDROID,release_avf_enable_multi_tenant_microdroid_vm,$(RELEASE_AVF_ENABLE_MULTI_TENANT_MICRODROID_VM))
 $(call add_soong_config_var_value,ANDROID,release_avf_enable_network,$(RELEASE_AVF_ENABLE_NETWORK))
@@ -158,6 +175,29 @@ endif
 # Required as platform_bootclasspath is using this namespace
 $(call soong_config_set,bootclasspath,release_crashrecovery_module,$(RELEASE_CRASHRECOVERY_MODULE))
 
+# Add uprobestats build flag to soong
+$(call soong_config_set,ANDROID,release_uprobestats_module,$(RELEASE_UPROBESTATS_MODULE))
+# Add uprobestats file move flags to soong, for both platform and module
+ifeq (true,$(RELEASE_UPROBESTATS_FILE_MOVE))
+  $(call soong_config_set,ANDROID,uprobestats_files_in_module,true)
+  $(call soong_config_set,ANDROID,uprobestats_files_in_platform,false)
+else
+  $(call soong_config_set,ANDROID,uprobestats_files_in_module,false)
+  $(call soong_config_set,ANDROID,uprobestats_files_in_platform,true)
+endif
+
 # Enable Profiling module. Also used by platform_bootclasspath.
 $(call soong_config_set,ANDROID,release_package_profiling_module,$(RELEASE_PACKAGE_PROFILING_MODULE))
 $(call soong_config_set,bootclasspath,release_package_profiling_module,$(RELEASE_PACKAGE_PROFILING_MODULE))
+
+# Add perf-setup build flag to soong
+# Note: BOARD_PERFSETUP_SCRIPT location must be under platform_testing/scripts/perf-setup/.
+ifdef BOARD_PERFSETUP_SCRIPT
+  $(call soong_config_set,perf,board_perfsetup_script,$(notdir $(BOARD_PERFSETUP_SCRIPT)))
+endif
+
+# Add target_use_pan_display flag for hardware/libhardware:gralloc.default
+$(call soong_config_set_bool,gralloc,target_use_pan_display,$(if $(filter true,$(TARGET_USE_PAN_DISPLAY)),true,false))
+
+# Add use_camera_v4l2_hal flag for hardware/libhardware/modules/camera/3_4:camera.v4l2
+$(call soong_config_set_bool,camera,use_camera_v4l2_hal,$(if $(filter true,$(USE_CAMERA_V4L2_HAL)),true,false))
diff --git a/core/base_rules.mk b/core/base_rules.mk
index 1592f54fc5..5363e0fbf9 100644
--- a/core/base_rules.mk
+++ b/core/base_rules.mk
@@ -340,7 +340,7 @@ LOCAL_BUILT_MODULE := $(intermediates)/$(my_built_module_stem)
 
 ifneq (,$(LOCAL_SOONG_INSTALLED_MODULE))
   ifneq ($(LOCAL_MODULE_MAKEFILE),$(SOONG_ANDROID_MK))
-    $(call pretty-error, LOCAL_SOONG_INSTALLED_MODULE can only be used from $(SOONG_ANDROID_MK))
+    $(call pretty-error, LOCAL_MODULE_MAKEFILE can only be used from $(SOONG_ANDROID_MK))
   endif
   # Use the install path requested by Soong.
   LOCAL_INSTALLED_MODULE := $(LOCAL_SOONG_INSTALLED_MODULE)
@@ -728,6 +728,14 @@ endif
 
 ifneq (true,$(LOCAL_UNINSTALLABLE_MODULE))
 
+ifeq ($(EXCLUDE_MCTS),true)
+  ifneq (,$(test_config))
+    ifneq (,$(filter mcts-%,$(LOCAL_COMPATIBILITY_SUITE)))
+      LOCAL_COMPATIBILITY_SUITE := $(filter-out cts,$(LOCAL_COMPATIBILITY_SUITE))
+    endif
+  endif
+endif
+
 # If we are building a native test or benchmark and its stem variants are not defined,
 # separate the multiple architectures into subdirectories of the testcase folder.
 arch_dir :=
@@ -768,6 +776,8 @@ $(foreach suite, $(LOCAL_COMPATIBILITY_SUITE), \
   $(eval my_compat_dist_$(suite) := $(patsubst %:$(LOCAL_INSTALLED_MODULE),$(LOCAL_INSTALLED_MODULE):$(LOCAL_INSTALLED_MODULE),\
     $(foreach dir, $(call compatibility_suite_dirs,$(suite),$(arch_dir)), \
       $(LOCAL_BUILT_MODULE):$(dir)/$(my_installed_module_stem)))) \
+  $(eval my_compat_module_arch_dir_$(suite).$(my_register_name) :=) \
+  $(foreach dir,$(call compatibility_suite_dirs,$(suite),$(arch_dir)),$(eval my_compat_module_arch_dir_$(suite).$(my_register_name) += $(dir))) \
   $(eval my_compat_dist_config_$(suite) := ))
 
 ifneq (,$(LOCAL_SOONG_CLASSES_JAR))
@@ -967,6 +977,8 @@ ALL_MODULES.$(my_register_name).BUILT := \
     $(ALL_MODULES.$(my_register_name).BUILT) $(LOCAL_BUILT_MODULE)
 ALL_MODULES.$(my_register_name).SOONG_MODULE_TYPE := \
     $(ALL_MODULES.$(my_register_name).SOONG_MODULE_TYPE) $(LOCAL_SOONG_MODULE_TYPE)
+ALL_MODULES.$(my_register_name).IS_SOONG_MODULE := \
+    $(if $(filter $(LOCAL_MODULE_MAKEFILE),$(SOONG_ANDROID_MK)),true)
 ifndef LOCAL_IS_HOST_MODULE
 ALL_MODULES.$(my_register_name).TARGET_BUILT := \
     $(ALL_MODULES.$(my_register_name).TARGET_BUILT) $(LOCAL_BUILT_MODULE)
@@ -1057,6 +1069,11 @@ ifdef LOCAL_ACONFIG_FILES
       $(ALL_MODULES.$(my_register_name).ACONFIG_FILES) $(LOCAL_ACONFIG_FILES)
 endif
 
+ifdef LOCAL_FILESYSTEM_FILELIST
+  ALL_MODULES.$(my_register_name).FILESYSTEM_FILELIST := \
+      $(ALL_MODULES.$(my_register_name).FILESYSTEM_FILELIST) $(LOCAL_FILESYSTEM_FILELIST)
+endif
+
 ifndef LOCAL_SOONG_MODULE_INFO_JSON
   ALL_MAKE_MODULE_INFO_JSON_MODULES += $(my_register_name)
   ALL_MODULES.$(my_register_name).SHARED_LIBS := \
@@ -1268,6 +1285,8 @@ $(LOCAL_MODULE)-$(h_or_hc_or_t)$(my_32_64_bit_suffix) : $(my_all_targets)
 endif
 endif
 
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=base_rules))
+
 ###########################################################
 # Ensure privileged applications always have LOCAL_PRIVILEGED_MODULE
 ###########################################################
diff --git a/core/binary.mk b/core/binary.mk
index f86b5a464e..1e98bc08fb 100644
--- a/core/binary.mk
+++ b/core/binary.mk
@@ -205,8 +205,6 @@ ifneq ($(LOCAL_SDK_VERSION),)
     my_api_level := $(my_ndk_api)
   endif
 
-  my_ndk_source_root := \
-      $(HISTORICAL_NDK_VERSIONS_ROOT)/$(LOCAL_NDK_VERSION)/sources
   my_built_ndk := $(SOONG_OUT_DIR)/ndk
   my_ndk_triple := $($(LOCAL_2ND_ARCH_VAR_PREFIX)TARGET_NDK_TRIPLE)
   my_ndk_sysroot_include := \
@@ -239,16 +237,18 @@ ifneq ($(LOCAL_SDK_VERSION),)
   endif
 
   ifeq (system,$(LOCAL_NDK_STL_VARIANT))
+    my_ndk_source_root := \
+        $(HISTORICAL_NDK_VERSIONS_ROOT)/$(LOCAL_NDK_VERSION)/sources
     my_ndk_stl_include_path := $(my_ndk_source_root)/cxx-stl/system/include
     my_system_shared_libraries += libstdc++
   else ifneq (,$(filter c++_%, $(LOCAL_NDK_STL_VARIANT)))
-    my_ndk_stl_include_path := \
-      $(my_ndk_source_root)/cxx-stl/llvm-libc++/include
-    my_ndk_stl_include_path += \
-      $(my_ndk_source_root)/cxx-stl/llvm-libc++abi/include
+    my_llvm_dir := $(LLVM_PREBUILTS_BASE)/$(BUILD_OS)-x86/$(LLVM_PREBUILTS_VERSION)
+    my_libcxx_arch_dir := $(my_llvm_dir)/android_libc++/ndk/$($(LOCAL_2ND_ARCH_VAR_PREFIX)PREBUILT_LIBCXX_ARCH_DIR)
 
-    my_libcxx_libdir := \
-      $(my_ndk_source_root)/cxx-stl/llvm-libc++/libs/$(my_cpu_variant)
+    # Include the target-specific __config_site file followed by the generic libc++ headers.
+    my_ndk_stl_include_path := $(my_libcxx_arch_dir)/include/c++/v1
+    my_ndk_stl_include_path += $(my_llvm_dir)/include/c++/v1
+    my_libcxx_libdir := $(my_libcxx_arch_dir)/lib
 
     ifeq (c++_static,$(LOCAL_NDK_STL_VARIANT))
       my_ndk_stl_static_lib := \
@@ -258,14 +258,7 @@ ifneq ($(LOCAL_SDK_VERSION),)
       my_ndk_stl_shared_lib_fullpath := $(my_libcxx_libdir)/libc++_shared.so
     endif
 
-    ifneq ($(my_ndk_api),current)
-      ifeq ($(call math_lt,$(my_ndk_api),21),true)
-        my_ndk_stl_include_path += $(my_ndk_source_root)/android/support/include
-        my_ndk_stl_static_lib += $(my_libcxx_libdir)/libandroid_support.a
-      endif
-    endif
-
-    my_ndk_stl_static_lib += $(my_libcxx_libdir)/libunwind.a
+    my_ndk_stl_static_lib += $($(LOCAL_2ND_ARCH_VAR_PREFIX)TARGET_LIBUNWIND)
     my_ldlibs += -ldl
   else # LOCAL_NDK_STL_VARIANT must be none
     # Do nothing.
@@ -1352,6 +1345,8 @@ my_warn_types := $(my_warn_ndk_types)
 my_allowed_types := $(my_allowed_ndk_types) native:platform native:platform_vndk
 endif
 
+ALL_MODULES.$(my_register_name).WHOLE_STATIC_LIBS := $(my_whole_static_libraries)
+
 my_link_deps := $(addprefix STATIC_LIBRARIES:,$(my_whole_static_libraries) $(my_static_libraries))
 ifneq ($(filter-out STATIC_LIBRARIES HEADER_LIBRARIES,$(LOCAL_MODULE_CLASS)),)
 my_link_deps += $(addprefix SHARED_LIBRARIES:,$(my_shared_libraries))
diff --git a/core/board_config.mk b/core/board_config.mk
index e184601008..5606964950 100644
--- a/core/board_config.mk
+++ b/core/board_config.mk
@@ -237,6 +237,7 @@ else
   .KATI_READONLY := TARGET_DEVICE_DIR
 endif
 
+$(call dump-phase-start,BOARD,,,, build/make/core/board_config.mk)
 ifndef RBC_PRODUCT_CONFIG
 include $(board_config_mk)
 else
@@ -261,6 +262,7 @@ else
 
   include $(OUT_DIR)/rbc/rbc_board_config_results.mk
 endif
+$(call dump-phase-end, build/make/core/board_config.mk)
 
 ifneq (,$(and $(TARGET_ARCH),$(TARGET_ARCH_SUITE)))
   $(error $(board_config_mk) erroneously sets both TARGET_ARCH and TARGET_ARCH_SUITE)
@@ -923,7 +925,9 @@ endif
 ###########################################
 # Ensure consistency among TARGET_RECOVERY_UPDATER_LIBS, AB_OTA_UPDATER, and PRODUCT_OTA_FORCE_NON_AB_PACKAGE.
 TARGET_RECOVERY_UPDATER_LIBS ?=
-AB_OTA_UPDATER ?=
+ifeq ($(AB_OTA_UPDATER),)
+AB_OTA_UPDATER := true
+endif
 .KATI_READONLY := TARGET_RECOVERY_UPDATER_LIBS AB_OTA_UPDATER
 
 # Ensure that if PRODUCT_OTA_FORCE_NON_AB_PACKAGE == true, then AB_OTA_UPDATER must be true
diff --git a/core/build_id.mk b/core/build_id.mk
index 841db4457b..fcc0f3948f 100644
--- a/core/build_id.mk
+++ b/core/build_id.mk
@@ -18,4 +18,4 @@
 # (like "CRB01").  It must be a single word, and is
 # capitalized by convention.
 
-BUILD_ID=AP3A.241105.008
+BUILD_ID=AP4A.241205.013
diff --git a/core/clang/TARGET_arm.mk b/core/clang/TARGET_arm.mk
index f18747a44b..126482f72c 100644
--- a/core/clang/TARGET_arm.mk
+++ b/core/clang/TARGET_arm.mk
@@ -4,7 +4,10 @@ $(clang_2nd_arch_prefix)RS_COMPAT_TRIPLE := armv7-none-linux-gnueabi
 
 $(clang_2nd_arch_prefix)TARGET_LIBPROFILE_RT := $(LLVM_RTLIB_PATH)/libclang_rt.profile-arm-android.a
 $(clang_2nd_arch_prefix)TARGET_LIBCRT_BUILTINS := $(LLVM_RTLIB_PATH)/libclang_rt.builtins-arm-android.a
+$(clang_2nd_arch_prefix)TARGET_LIBUNWIND := $(LLVM_RTLIB_PATH)/arm/libunwind.a
 
 # Address sanitizer clang config
 $(clang_2nd_arch_prefix)ADDRESS_SANITIZER_LINKER := /system/bin/linker_asan
 $(clang_2nd_arch_prefix)ADDRESS_SANITIZER_LINKER_FILE := /system/bin/bootstrap/linker_asan
+
+$(clang_2nd_arch_prefix)PREBUILT_LIBCXX_ARCH_DIR := arm
diff --git a/core/clang/TARGET_arm64.mk b/core/clang/TARGET_arm64.mk
index 42bed0aaed..e7ab6cb500 100644
--- a/core/clang/TARGET_arm64.mk
+++ b/core/clang/TARGET_arm64.mk
@@ -4,7 +4,10 @@ RS_COMPAT_TRIPLE := aarch64-linux-android
 
 TARGET_LIBPROFILE_RT := $(LLVM_RTLIB_PATH)/libclang_rt.profile-aarch64-android.a
 TARGET_LIBCRT_BUILTINS := $(LLVM_RTLIB_PATH)/libclang_rt.builtins-aarch64-android.a
+TARGET_LIBUNWIND := $(LLVM_RTLIB_PATH)/aarch64/libunwind.a
 
 # Address sanitizer clang config
 ADDRESS_SANITIZER_LINKER := /system/bin/linker_asan64
 ADDRESS_SANITIZER_LINKER_FILE := /system/bin/bootstrap/linker_asan64
+
+PREBUILT_LIBCXX_ARCH_DIR := aarch64
diff --git a/core/clang/TARGET_riscv64.mk b/core/clang/TARGET_riscv64.mk
index cfb5c7d0ea..58c9c7bf54 100644
--- a/core/clang/TARGET_riscv64.mk
+++ b/core/clang/TARGET_riscv64.mk
@@ -4,7 +4,10 @@ RS_COMPAT_TRIPLE := riscv64-linux-android
 
 TARGET_LIBPROFILE_RT := $(LLVM_RTLIB_PATH)/libclang_rt.profile-riscv64-android.a
 TARGET_LIBCRT_BUILTINS := $(LLVM_RTLIB_PATH)/libclang_rt.builtins-riscv64-android.a
+TARGET_LIBUNWIND := $(LLVM_RTLIB_PATH)/riscv64/libunwind.a
 
 # Address sanitizer clang config
 ADDRESS_SANITIZER_LINKER := /system/bin/linker_asan64
 ADDRESS_SANITIZER_LINKER_FILE := /system/bin/bootstrap/linker_asan64
+
+PREBUILT_LIBCXX_ARCH_DIR := riscv64
diff --git a/core/clang/TARGET_x86.mk b/core/clang/TARGET_x86.mk
index 5491a05978..1a08c79518 100644
--- a/core/clang/TARGET_x86.mk
+++ b/core/clang/TARGET_x86.mk
@@ -4,7 +4,10 @@ $(clang_2nd_arch_prefix)RS_COMPAT_TRIPLE := i686-linux-android
 
 $(clang_2nd_arch_prefix)TARGET_LIBPROFILE_RT := $(LLVM_RTLIB_PATH)/libclang_rt.profile-i686-android.a
 $(clang_2nd_arch_prefix)TARGET_LIBCRT_BUILTINS := $(LLVM_RTLIB_PATH)/libclang_rt.builtins-i686-android.a
+$(clang_2nd_arch_prefix)TARGET_LIBUNWIND := $(LLVM_RTLIB_PATH)/i386/libunwind.a
 
 # Address sanitizer clang config
 $(clang_2nd_arch_prefix)ADDRESS_SANITIZER_LINKER := /system/bin/linker_asan
 $(clang_2nd_arch_prefix)ADDRESS_SANITIZER_LINKER_FILE := /system/bin/bootstrap/linker_asan
+
+$(clang_2nd_arch_prefix)PREBUILT_LIBCXX_ARCH_DIR := i386
diff --git a/core/clang/TARGET_x86_64.mk b/core/clang/TARGET_x86_64.mk
index 167db72e74..f39b41ebf4 100644
--- a/core/clang/TARGET_x86_64.mk
+++ b/core/clang/TARGET_x86_64.mk
@@ -4,7 +4,10 @@ RS_COMPAT_TRIPLE := x86_64-linux-android
 
 TARGET_LIBPROFILE_RT := $(LLVM_RTLIB_PATH)/libclang_rt.profile-x86_64-android.a
 TARGET_LIBCRT_BUILTINS := $(LLVM_RTLIB_PATH)/libclang_rt.builtins-x86_64-android.a
+TARGET_LIBUNWIND := $(LLVM_RTLIB_PATH)/x86_64/libunwind.a
 
 # Address sanitizer clang config
 ADDRESS_SANITIZER_LINKER := /system/bin/linker_asan64
 ADDRESS_SANITIZER_LINKER_FILE := /system/bin/bootstrap/linker_asan64
+
+PREBUILT_LIBCXX_ARCH_DIR := x86_64
diff --git a/core/clear_vars.mk b/core/clear_vars.mk
index 61926907c3..fed19e6d45 100644
--- a/core/clear_vars.mk
+++ b/core/clear_vars.mk
@@ -87,6 +87,7 @@ LOCAL_EXPORT_STATIC_LIBRARY_HEADERS:=
 LOCAL_EXTRA_FULL_TEST_CONFIGS:=
 LOCAL_EXTRACT_APK:=
 LOCAL_EXTRACT_DPI_APK:=
+LOCAL_FILESYSTEM_FILELIST:=
 LOCAL_FINDBUGS_FLAGS:=
 LOCAL_FORCE_STATIC_EXECUTABLE:=
 LOCAL_FULL_CLASSES_JACOCO_JAR:=
diff --git a/core/combo/arch/arm64/armv9-2a.mk b/core/combo/arch/arm64/armv9-2a.mk
new file mode 100644
index 0000000000..69ffde014b
--- /dev/null
+++ b/core/combo/arch/arm64/armv9-2a.mk
@@ -0,0 +1,18 @@
+#
+# Copyright (C) 2023 The Android Open Source Project
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
+#
+
+# .mk file required to support build for the ARMv9.2-A arch variant.
+# The file just needs to be present, it does not need to contain anything.
diff --git a/core/config.mk b/core/config.mk
index 4bb9a42943..192c8b28c8 100644
--- a/core/config.mk
+++ b/core/config.mk
@@ -173,6 +173,7 @@ $(KATI_obsolete_var BOARD_PREBUILT_PVMFWIMAGE,pvmfw.bin is now built in AOSP and
 $(KATI_obsolete_var BUILDING_PVMFW_IMAGE,BUILDING_PVMFW_IMAGE is no longer used)
 $(KATI_obsolete_var BOARD_BUILD_SYSTEM_ROOT_IMAGE)
 $(KATI_obsolete_var FS_GET_STATS)
+$(KATI_obsolete_var BUILD_BROKEN_USES_SOONG_PYTHON2_MODULES)
 
 # Used to force goals to build.  Only use for conditionally defined goals.
 .PHONY: FORCE
@@ -316,6 +317,19 @@ $(call soong_config_define_internal,$1,$2) \
 $(eval SOONG_CONFIG_$(strip $1)_$(strip $2):=$(strip $3))
 endef
 
+# soong_config_set_bool is the same as soong_config_set, but it will
+# also type the variable as a bool, so that when using select() expressions
+# in blueprint files they can use boolean values instead of strings.
+# It will only accept "true" for its value, any other value will be
+# treated as false.
+# $1 is the namespace. $2 is the variable name. $3 is the variable value.
+# Ex: $(call soong_config_set_bool,acme,COOL_FEATURE,true)
+define soong_config_set_bool
+$(call soong_config_define_internal,$1,$2) \
+$(eval SOONG_CONFIG_$(strip $1)_$(strip $2):=$(filter true,$3))
+$(eval SOONG_CONFIG_TYPE_$(strip $1)_$(strip $2):=bool)
+endef
+
 # soong_config_append appends to the value of the variable in the given Soong
 # config namespace. If the variable does not exist, it will be defined. If the
 # namespace does not  exist, it will be defined.
@@ -350,8 +364,7 @@ endif
 # configs, generally for cross-cutting features.
 
 # Build broken variables that should be treated as booleans
-_build_broken_bool_vars := \
-  BUILD_BROKEN_USES_SOONG_PYTHON2_MODULES \
+_build_broken_bool_vars :=
 
 # Build broken variables that should be treated as lists
 _build_broken_list_vars := \
@@ -718,8 +731,6 @@ APPEND2SIMG := $(HOST_OUT_EXECUTABLES)/append2simg
 VERITY_SIGNER := $(HOST_OUT_EXECUTABLES)/verity_signer
 BUILD_VERITY_METADATA := $(HOST_OUT_EXECUTABLES)/build_verity_metadata
 BUILD_VERITY_TREE := $(HOST_OUT_EXECUTABLES)/build_verity_tree
-FUTILITY := $(HOST_OUT_EXECUTABLES)/futility-host
-VBOOT_SIGNER := $(HOST_OUT_EXECUTABLES)/vboot_signer
 
 DEXDUMP := $(HOST_OUT_EXECUTABLES)/dexdump$(BUILD_EXECUTABLE_SUFFIX)
 PROFMAN := $(HOST_OUT_EXECUTABLES)/profman
@@ -800,6 +811,12 @@ ifeq ($(PRODUCT_FULL_TREBLE),true)
   BOARD_PROPERTY_OVERRIDES_SPLIT_ENABLED ?= true
 endif
 
+ifneq ($(call math_gt_or_eq,$(PRODUCT_SHIPPING_API_LEVEL),36),)
+  ifneq ($(NEED_AIDL_NDK_PLATFORM_BACKEND),)
+    $(error Must not set NEED_AIDL_NDK_PLATFORM_BACKEND, but it is set to: $(NEED_AIDL_NDK_PLATFORM_BACKEND). Support will be removed.)
+  endif
+endif
+
 # Set BOARD_SYSTEMSDK_VERSIONS to the latest SystemSDK version starting from P-launching
 # devices if unset.
 ifndef BOARD_SYSTEMSDK_VERSIONS
@@ -828,9 +845,6 @@ ifdef PRODUCT_SHIPPING_API_LEVEL
   else
     min_systemsdk_version := $(PRODUCT_SHIPPING_API_LEVEL)
   endif
-  ifneq ($(call numbers_less_than,$(min_systemsdk_version),$(BOARD_SYSTEMSDK_VERSIONS)),)
-    $(error BOARD_SYSTEMSDK_VERSIONS ($(BOARD_SYSTEMSDK_VERSIONS)) must all be greater than or equal to BOARD_API_LEVEL, BOARD_SHIPPING_API_LEVEL or PRODUCT_SHIPPING_API_LEVEL ($(min_systemsdk_version)))
-  endif
   ifneq ($(call math_gt_or_eq,$(PRODUCT_SHIPPING_API_LEVEL),29),)
     ifneq ($(BOARD_OTA_FRAMEWORK_VBMETA_VERSION_OVERRIDE),)
       $(error When PRODUCT_SHIPPING_API_LEVEL >= 29, BOARD_OTA_FRAMEWORK_VBMETA_VERSION_OVERRIDE cannot be set)
@@ -1243,17 +1257,52 @@ BUILD_WARNING_BAD_OPTIONAL_USES_LIBS_ALLOWLIST := LegacyCamera Gallery2
 # in the source tree.
 dont_bother_goals := out product-graph
 
+ifeq ($(TARGET_SYSTEM_PROP),)
+TARGET_SYSTEM_PROP := $(wildcard $(TARGET_DEVICE_DIR)/system.prop)
+endif
+
+ifeq ($(TARGET_SYSTEM_EXT_PROP),)
+TARGET_SYSTEM_EXT_PROP := $(wildcard $(TARGET_DEVICE_DIR)/system_ext.prop)
+endif
+
+ifeq ($(TARGET_PRODUCT_PROP),)
+TARGET_PRODUCT_PROP := $(wildcard $(TARGET_DEVICE_DIR)/product.prop)
+endif
+
+ifeq ($(TARGET_ODM_PROP),)
+TARGET_ODM_PROP := $(wildcard $(TARGET_DEVICE_DIR)/odm.prop)
+endif
+
+.KATI_READONLY := \
+    TARGET_SYSTEM_PROP \
+    TARGET_SYSTEM_EXT_PROP \
+    TARGET_PRODUCT_PROP \
+    TARGET_ODM_PROP \
+
 include $(BUILD_SYSTEM)/sysprop_config.mk
 
 # Make ANDROID Soong config variables visible to Android.mk files, for
 # consistency with those defined in BoardConfig.mk files.
 include $(BUILD_SYSTEM)/android_soong_config_vars.mk
 
+# EMMA_INSTRUMENT is set to true when coverage is enabled. Creates a suffix to
+# differeciate the coverage version of ninja files. This will save 5 minutes of
+# build time used to regenerate ninja.
+ifeq (true,$(EMMA_INSTRUMENT))
+COVERAGE_SUFFIX := .coverage
+endif
+
+SOONG_VARIABLES := $(SOONG_OUT_DIR)/soong.$(TARGET_PRODUCT)$(COVERAGE_SUFFIX).variables
+SOONG_EXTRA_VARIABLES := $(SOONG_OUT_DIR)/soong.$(TARGET_PRODUCT)$(COVERAGE_SUFFIX).extra.variables
+
 ifeq ($(CALLED_FROM_SETUP),true)
 include $(BUILD_SYSTEM)/ninja_config.mk
 include $(BUILD_SYSTEM)/soong_config.mk
 endif
 
+SOONG_VARIABLES :=
+SOONG_EXTRA_VARIABLES :=
+
 -include external/ltp/android/ltp_package_list.mk
 DEFAULT_DATA_OUT_MODULES := ltp $(ltp_packages)
 .KATI_READONLY := DEFAULT_DATA_OUT_MODULES
diff --git a/core/copy_headers.mk b/core/copy_headers.mk
index 397ea629a9..2e82db7391 100644
--- a/core/copy_headers.mk
+++ b/core/copy_headers.mk
@@ -50,4 +50,5 @@ $(foreach header,$(LOCAL_COPY_HEADERS), \
 _chFrom :=
 _chTo :=
 
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=COPY_HEADERS))
 endif # LOCAL_COPY_HEADERS
diff --git a/core/definitions.mk b/core/definitions.mk
index 51def29fcb..cd1b36e4c7 100644
--- a/core/definitions.mk
+++ b/core/definitions.mk
@@ -2584,7 +2584,28 @@ define dump-words-to-file
         @$(call emit-line,$(wordlist 98001,98500,$(1)),$(2))
         @$(call emit-line,$(wordlist 98501,99000,$(1)),$(2))
         @$(call emit-line,$(wordlist 99001,99500,$(1)),$(2))
-        @$(if $(wordlist 99501,99502,$(1)),$(error dump-words-to-file: Too many words ($(words $(1)))))
+        @$(call emit-line,$(wordlist 99501,100000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 100001,100500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 100501,101000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 101001,101500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 101501,102000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 102001,102500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 102501,103000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 103001,103500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 103501,104000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 104001,104500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 104501,105000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 105001,105500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 105501,106000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 106001,106500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 106501,107000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 107001,107500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 107501,108000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 108001,108500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 108501,109000,$(1)),$(2))
+        @$(call emit-line,$(wordlist 109001,109500,$(1)),$(2))
+        @$(call emit-line,$(wordlist 109501,110000,$(1)),$(2))
+        @$(if $(wordlist 110001,110002,$(1)),$(error dump-words-to-file: Too many words ($(words $(1)))))
 endef
 # Return jar arguments to compress files in a given directory
 # $(1): directory
@@ -3591,6 +3612,7 @@ $(foreach suite, $(LOCAL_COMPATIBILITY_SUITE), \
     $$(foreach f,$$(my_compat_dist_$(suite)),$$(call word-colon,2,$$(f))) \
     $$(foreach f,$$(my_compat_dist_config_$(suite)),$$(call word-colon,2,$$(f))) \
     $$(my_compat_dist_test_data_$(suite))) \
+  $(eval COMPATIBILITY.$(suite).ARCH_DIRS.$(my_register_name) := $(my_compat_module_arch_dir_$(suite).$(my_register_name))) \
   $(eval COMPATIBILITY.$(suite).API_MAP_FILES += $$(my_compat_api_map_$(suite))) \
   $(eval COMPATIBILITY.$(suite).SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES += $(LOCAL_SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES)) \
   $(eval ALL_COMPATIBILITY_DIST_FILES += $$(my_compat_dist_$(suite))) \
diff --git a/core/dex_preopt.mk b/core/dex_preopt.mk
index 26b8b17a49..906d7f0163 100644
--- a/core/dex_preopt.mk
+++ b/core/dex_preopt.mk
@@ -13,25 +13,6 @@ else
 install-on-system-other = $(filter-out $(PRODUCT_DEXPREOPT_SPEED_APPS) $(PRODUCT_SYSTEM_SERVER_APPS),$(basename $(notdir $(filter $(foreach f,$(SYSTEM_OTHER_ODEX_FILTER),$(TARGET_OUT)/$(f)),$(1)))))
 endif
 
-# We want to install the profile even if we are not using preopt since it is required to generate
-# the image on the device.
-ALL_DEFAULT_INSTALLED_MODULES += $(call copy-many-files,$(DEXPREOPT_IMAGE_PROFILE_BUILT_INSTALLED),$(PRODUCT_OUT))
-
-# Install boot images. Note that there can be multiple.
-my_boot_image_arch := TARGET_ARCH
-my_boot_image_out := $(PRODUCT_OUT)
-my_boot_image_syms := $(TARGET_OUT_UNSTRIPPED)
-DEFAULT_DEX_PREOPT_INSTALLED_IMAGE_MODULE := \
-  $(foreach my_boot_image_name,$(DEXPREOPT_IMAGE_NAMES),$(strip \
-    $(eval include $(BUILD_SYSTEM)/dex_preopt_libart.mk) \
-    $(my_boot_image_module)))
-ifdef TARGET_2ND_ARCH
-  my_boot_image_arch := TARGET_2ND_ARCH
-  2ND_DEFAULT_DEX_PREOPT_INSTALLED_IMAGE_MODULE := \
-    $(foreach my_boot_image_name,$(DEXPREOPT_IMAGE_NAMES),$(strip \
-      $(eval include $(BUILD_SYSTEM)/dex_preopt_libart.mk) \
-      $(my_boot_image_module)))
-endif
 # Install boot images for testing on host. We exclude framework image as it is not part of art manifest.
 my_boot_image_arch := HOST_ARCH
 my_boot_image_out := $(HOST_OUT)
diff --git a/core/dex_preopt_config.mk b/core/dex_preopt_config.mk
index d51de33273..f1e9fb59b7 100644
--- a/core/dex_preopt_config.mk
+++ b/core/dex_preopt_config.mk
@@ -1,4 +1,4 @@
-DEX_PREOPT_CONFIG := $(SOONG_OUT_DIR)/dexpreopt.config
+DEX_PREOPT_CONFIG := $(SOONG_OUT_DIR)/dexpreopt${COVERAGE_SUFFIX}.config
 
 ENABLE_PREOPT := true
 ENABLE_PREOPT_BOOT_IMAGES := true
diff --git a/core/dex_preopt_odex_install.mk b/core/dex_preopt_odex_install.mk
index 08e2da3655..e7086b7e4e 100644
--- a/core/dex_preopt_odex_install.mk
+++ b/core/dex_preopt_odex_install.mk
@@ -504,8 +504,8 @@ ifdef LOCAL_DEX_PREOPT
   _system_other := $(strip $(if $(strip $(BOARD_USES_SYSTEM_OTHER_ODEX)), \
     $(if $(strip $(SANITIZE_LITE)),, \
       $(if $(filter $(_dexname),$(PRODUCT_DEXPREOPT_SPEED_APPS))$(filter $(_dexname),$(PRODUCT_SYSTEM_SERVER_APPS)),, \
-        $(if $(strip $(foreach myfilter,$(SYSTEM_OTHER_ODEX_FILTER),$(filter system/$(myfilter),$(_dexlocation)))), \
-          system_other/)))))
+        $(if $(strip $(foreach myfilter,$(SYSTEM_OTHER_ODEX_FILTER),$(filter system/$(myfilter),$(_dexlocation))$(filter $(myfilter),$(_dexlocation)))), \
+            system_other/)))))
   # _dexdir has a trailing /
   _dexdir := $(_system_other)$(dir $(_dexlocation))
   my_dexpreopt_zip_contents := $(sort \
diff --git a/core/dumpconfig.mk b/core/dumpconfig.mk
index 640fe10f9c..eb4c822dc5 100644
--- a/core/dumpconfig.mk
+++ b/core/dumpconfig.mk
@@ -56,7 +56,7 @@ BUILD_DATETIME_FILE := $(OUT_DIR)/build_date.txt
 
 # Escape quotation marks for CSV, and wraps in quotation marks.
 define escape-for-csv
-"$(subst ","",$1)"
+"$(subst ","",$(subst $(newline), ,$1))"
 endef
 
 # Args:
@@ -68,7 +68,7 @@ endef
 # Args:
 #   $(1): include stack
 define dump-import-done
-$(eval $(file >> $(DUMPCONFIG_FILE),imported,$(strip $(1))))
+$(eval $(file >> $(DUMPCONFIG_FILE),imported,$(strip $(1)),$(filter-out $(1),$(MAKEFILE_LIST))))
 endef
 
 # Args:
diff --git a/core/envsetup.mk b/core/envsetup.mk
index c063f60a15..f82e861abf 100644
--- a/core/envsetup.mk
+++ b/core/envsetup.mk
@@ -417,6 +417,7 @@ HOST_OUT_SDK_ADDON := $(HOST_OUT)/sdk_addon
 HOST_OUT_NATIVE_TESTS := $(HOST_OUT)/nativetest64
 HOST_OUT_COVERAGE := $(HOST_OUT)/coverage
 HOST_OUT_TESTCASES := $(HOST_OUT)/testcases
+HOST_OUT_ETC := $(HOST_OUT)/etc
 .KATI_READONLY := \
   HOST_OUT_EXECUTABLES \
   HOST_OUT_SHARED_LIBRARIES \
@@ -425,7 +426,8 @@ HOST_OUT_TESTCASES := $(HOST_OUT)/testcases
   HOST_OUT_SDK_ADDON \
   HOST_OUT_NATIVE_TESTS \
   HOST_OUT_COVERAGE \
-  HOST_OUT_TESTCASES
+  HOST_OUT_TESTCASES \
+  HOST_OUT_ETC
 
 HOST_CROSS_OUT_EXECUTABLES := $(HOST_CROSS_OUT)/bin
 HOST_CROSS_OUT_SHARED_LIBRARIES := $(HOST_CROSS_OUT)/lib
diff --git a/core/executable_internal.mk b/core/executable_internal.mk
index fecf4f6a28..2a76c9d419 100644
--- a/core/executable_internal.mk
+++ b/core/executable_internal.mk
@@ -110,4 +110,6 @@ $(my_coverage_path)/$(GCNO_ARCHIVE) : $(intermediates)/$(GCNO_ARCHIVE)
 $(LOCAL_BUILT_MODULE): $(my_coverage_path)/$(GCNO_ARCHIVE)
 endif
 
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=EXECUTABLE))
+
 endif  # skip_build_from_source
diff --git a/core/fuzz_test.mk b/core/fuzz_test.mk
index 8a4b8c3d10..1181c661ce 100644
--- a/core/fuzz_test.mk
+++ b/core/fuzz_test.mk
@@ -43,3 +43,5 @@ LOCAL_STRIP_MODULE := keep_symbols
 endif
 
 include $(BUILD_EXECUTABLE)
+
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=FUZZ_TEST))
\ No newline at end of file
diff --git a/core/header_library_internal.mk b/core/header_library_internal.mk
index 35ee1bc032..a21c853562 100644
--- a/core/header_library_internal.mk
+++ b/core/header_library_internal.mk
@@ -19,3 +19,5 @@ endif
 
 $(LOCAL_BUILT_MODULE):
 	$(hide) touch $@
+
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=HEADER_LIBRARY))
\ No newline at end of file
diff --git a/core/host_executable_internal.mk b/core/host_executable_internal.mk
index 2ff9ff217a..7c79a1e4c6 100644
--- a/core/host_executable_internal.mk
+++ b/core/host_executable_internal.mk
@@ -57,4 +57,6 @@ $(LOCAL_BUILT_MODULE): $(my_crtbegin) $(my_crtend) $(my_libcrt_builtins)
 $(LOCAL_BUILT_MODULE): $(all_objects) $(all_libraries) $(CLANG_CXX)
 	$(transform-host-o-to-executable)
 
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=HOST_EXECUTABLE))
+
 endif  # skip_build_from_source
diff --git a/core/host_java_library.mk b/core/host_java_library.mk
index d45da48c84..652eb0ef79 100644
--- a/core/host_java_library.mk
+++ b/core/host_java_library.mk
@@ -124,3 +124,5 @@ $(eval $(call copy-one-file,$(LOCAL_FULL_CLASSES_JACOCO_JAR),$(full_classes_jar)
 ifeq ($(TURBINE_ENABLED),false)
 $(eval $(call copy-one-file,$(LOCAL_FULL_CLASSES_JACOCO_JAR),$(full_classes_header_jar)))
 endif
+
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=HOST_JAVA_LIBRARY))
\ No newline at end of file
diff --git a/core/host_prebuilt.mk b/core/host_prebuilt.mk
index 79f3ffa23f..7dc6704e8b 100644
--- a/core/host_prebuilt.mk
+++ b/core/host_prebuilt.mk
@@ -17,3 +17,5 @@
 $(call record-module-type,HOST_PREBUILT)
 LOCAL_IS_HOST_MODULE := true
 include $(BUILD_MULTI_PREBUILT)
+
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=HOST_PREBUILT))
\ No newline at end of file
diff --git a/core/host_shared_library_internal.mk b/core/host_shared_library_internal.mk
index ae8b798c3c..22a02d45bd 100644
--- a/core/host_shared_library_internal.mk
+++ b/core/host_shared_library_internal.mk
@@ -53,4 +53,6 @@ $(LOCAL_BUILT_MODULE): \
         $(LOCAL_ADDITIONAL_DEPENDENCIES)
 	$(transform-host-o-to-shared-lib)
 
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=HOST_SHARED_LIBRARY))
+
 endif  # skip_build_from_source
diff --git a/core/host_static_library_internal.mk b/core/host_static_library_internal.mk
index 3946aa7bc9..079c45eb98 100644
--- a/core/host_static_library_internal.mk
+++ b/core/host_static_library_internal.mk
@@ -23,3 +23,5 @@ include $(BUILD_SYSTEM)/binary.mk
 $(LOCAL_BUILT_MODULE): $(built_whole_libraries)
 $(LOCAL_BUILT_MODULE): $(all_objects)
 	$(transform-host-o-to-static-lib)
+
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=HOST_STATIC_LIBRARY))
\ No newline at end of file
diff --git a/core/install_jni_libs_internal.mk b/core/install_jni_libs_internal.mk
index 5491247057..4959edd4c3 100644
--- a/core/install_jni_libs_internal.mk
+++ b/core/install_jni_libs_internal.mk
@@ -38,8 +38,9 @@ ifdef my_embed_jni
       $(error LOCAL_SDK_VERSION must be defined with LOCAL_NDK_STL_VARIANT, \
           LOCAL_PACKAGE_NAME=$(LOCAL_PACKAGE_NAME))
     endif
+    my_libcxx_arch := $($(LOCAL_2ND_ARCH_VAR_PREFIX)PREBUILT_LIBCXX_ARCH_DIR)
     my_jni_shared_libraries += \
-        $(HISTORICAL_NDK_VERSIONS_ROOT)/$(LOCAL_NDK_VERSION)/sources/cxx-stl/llvm-libc++/libs/$(TARGET_$(my_2nd_arch_prefix)CPU_ABI)/libc++_shared.so
+        $(LLVM_PREBUILTS_BASE)/$(BUILD_OS)-x86/$(LLVM_PREBUILTS_VERSION)/android_libc++/ndk/$(my_libcxx_arch)/lib/libc++_shared.so
   endif
 
   # Set the abi directory used by the local JNI shared libraries.
diff --git a/core/java_library.mk b/core/java_library.mk
index 3ac03dc085..97ce92c413 100644
--- a/core/java_library.mk
+++ b/core/java_library.mk
@@ -88,3 +88,5 @@ endif  # LOCAL_UNCOMPRESS_DEX
 $(eval $(call copy-one-file,$(common_javalib.jar),$(LOCAL_BUILT_MODULE)))
 
 endif # !LOCAL_IS_STATIC_JAVA_LIBRARY
+
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=JAVA_LIBRARY))
\ No newline at end of file
diff --git a/core/java_prebuilt_internal.mk b/core/java_prebuilt_internal.mk
index 46393acb12..4b6eea7616 100644
--- a/core/java_prebuilt_internal.mk
+++ b/core/java_prebuilt_internal.mk
@@ -172,6 +172,12 @@ framework_res_package_export := \
 endif
 endif
 
+# transitive-res-packages is only populated for Soong modules for now, but needs
+# to exist so that other Make modules can depend on it.  Create an empty file.
+my_transitive_res_packages := $(intermediates.COMMON)/transitive-res-packages
+$(my_transitive_res_packages):
+	touch $@
+
 my_res_package := $(intermediates.COMMON)/package-res.apk
 
 # We needed only very few PRIVATE variables and aapt2.mk input variables. Reset the unnecessary ones.
diff --git a/core/layoutlib_data.mk b/core/layoutlib_data.mk
index e45f7efe16..e420a004de 100644
--- a/core/layoutlib_data.mk
+++ b/core/layoutlib_data.mk
@@ -66,11 +66,19 @@ $(call dist-for-goals,layoutlib,$(LAYOUTLIB_BUILD_PROP)/layoutlib-build.prop:lay
 # Resource files from frameworks/base/core/res/res
 LAYOUTLIB_RES := $(call intermediates-dir-for,PACKAGING,layoutlib-res,HOST,COMMON)
 LAYOUTLIB_RES_FILES := $(shell find frameworks/base/core/res/res -type f -not -path 'frameworks/base/core/res/res/values-m[nc]c*' | sort)
-$(LAYOUTLIB_RES)/layoutlib-res.zip: $(SOONG_ZIP) $(HOST_OUT_EXECUTABLES)/aapt2 $(LAYOUTLIB_RES_FILES)
+EMULATED_OVERLAYS_FILES := $(shell find frameworks/base/packages/overlays/*/res/ | sort)
+DEVICE_OVERLAYS_FILES := $(shell find device/generic/goldfish/phone/overlay/frameworks/base/packages/overlays/*/AndroidOverlay/res/ | sort)
+$(LAYOUTLIB_RES)/layoutlib-res.zip: $(SOONG_ZIP) $(HOST_OUT_EXECUTABLES)/aapt2 $(LAYOUTLIB_RES_FILES) $(EMULATED_OVERLAYS_FILES) $(DEVICE_OVERLAYS_FILES)
 	rm -rf $@
-	echo $(LAYOUTLIB_RES_FILES) > $(LAYOUTLIB_RES)/filelist.txt
-	$(SOONG_ZIP) -C frameworks/base/core/res -l $(LAYOUTLIB_RES)/filelist.txt -o $(LAYOUTLIB_RES)/temp.zip
-	rm -rf $(LAYOUTLIB_RES)/data && unzip -q -d $(LAYOUTLIB_RES)/data $(LAYOUTLIB_RES)/temp.zip
+	echo $(LAYOUTLIB_RES_FILES) > $(LAYOUTLIB_RES)/filelist_res.txt
+	$(SOONG_ZIP) -C frameworks/base/core/res -l $(LAYOUTLIB_RES)/filelist_res.txt -o $(LAYOUTLIB_RES)/temp_res.zip
+	echo $(EMULATED_OVERLAYS_FILES) > $(LAYOUTLIB_RES)/filelist_emulated_overlays.txt
+	$(SOONG_ZIP) -C frameworks/base/packages -l $(LAYOUTLIB_RES)/filelist_emulated_overlays.txt -o $(LAYOUTLIB_RES)/temp_emulated_overlays.zip
+	echo $(DEVICE_OVERLAYS_FILES) > $(LAYOUTLIB_RES)/filelist_device_overlays.txt
+	$(SOONG_ZIP) -C device/generic/goldfish/phone/overlay/frameworks/base/packages -l $(LAYOUTLIB_RES)/filelist_device_overlays.txt -o $(LAYOUTLIB_RES)/temp_device_overlays.zip
+	rm -rf $(LAYOUTLIB_RES)/data && unzip -q -d $(LAYOUTLIB_RES)/data $(LAYOUTLIB_RES)/temp_res.zip
+	unzip -q -d $(LAYOUTLIB_RES)/data $(LAYOUTLIB_RES)/temp_emulated_overlays.zip
+	unzip -q -d $(LAYOUTLIB_RES)/data $(LAYOUTLIB_RES)/temp_device_overlays.zip
 	rm -rf $(LAYOUTLIB_RES)/compiled && mkdir $(LAYOUTLIB_RES)/compiled && $(HOST_OUT_EXECUTABLES)/aapt2 compile $(LAYOUTLIB_RES)/data/res/**/*.9.png -o $(LAYOUTLIB_RES)/compiled
 	printf '<?xml version="1.0" encoding="utf-8"?>\n<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.google.android.layoutlib" />' > $(LAYOUTLIB_RES)/AndroidManifest.xml
 	$(HOST_OUT_EXECUTABLES)/aapt2 link -R $(LAYOUTLIB_RES)/compiled/* -o $(LAYOUTLIB_RES)/compiled.apk --manifest $(LAYOUTLIB_RES)/AndroidManifest.xml
@@ -78,7 +86,7 @@ $(LAYOUTLIB_RES)/layoutlib-res.zip: $(SOONG_ZIP) $(HOST_OUT_EXECUTABLES)/aapt2 $
 	for f in $(LAYOUTLIB_RES)/compiled_apk/res/*; do mv "$$f" "$${f/-v4/}";done
 	for f in $(LAYOUTLIB_RES)/compiled_apk/res/**/*.9.png; do mv "$$f" "$${f/.9.png/.compiled.9.png}";done
 	cp -r $(LAYOUTLIB_RES)/compiled_apk/res $(LAYOUTLIB_RES)/data
-	$(SOONG_ZIP) -C $(LAYOUTLIB_RES)/data -D $(LAYOUTLIB_RES)/data/res -o $@
+	$(SOONG_ZIP) -C $(LAYOUTLIB_RES)/data -D $(LAYOUTLIB_RES)/data/ -o $@
 
 $(call dist-for-goals,layoutlib,$(LAYOUTLIB_RES)/layoutlib-res.zip:layoutlib_native/res.zip)
 
@@ -132,16 +140,26 @@ $(LAYOUTLIB_SBOM)/sbom-metadata.csv:
 	  echo $(_path),,,,,,Y,$f,,, >> $@; \
 	)
 
+	$(foreach f,$(EMULATED_OVERLAYS_FILES), \
+	  $(eval _path := $(subst frameworks/base/packages,data,$f)) \
+	  echo $(_path),,,,,,Y,$f,,, >> $@; \
+	)
+
+	$(foreach f,$(DEVICE_OVERLAYS_FILES), \
+	  $(eval _path := $(subst device/generic/goldfish/phone/overlay/frameworks/base/packages,data,$f)) \
+	  echo $(_path),,,,,,Y,$f,,, >> $@; \
+	)
+
 .PHONY: layoutlib-sbom
 layoutlib-sbom: $(LAYOUTLIB_SBOM)/layoutlib.spdx.json
-$(LAYOUTLIB_SBOM)/layoutlib.spdx.json: $(PRODUCT_OUT)/always_dirty_file.txt $(GEN_SBOM) $(LAYOUTLIB_SBOM)/sbom-metadata.csv $(_layoutlib_font_config_files) $(_layoutlib_fonts_files) $(LAYOUTLIB_BUILD_PROP)/layoutlib-build.prop $(_layoutlib_keyboard_files) $(LAYOUTLIB_RES_FILES)
+$(LAYOUTLIB_SBOM)/layoutlib.spdx.json: $(PRODUCT_OUT)/always_dirty_file.txt $(GEN_SBOM) $(LAYOUTLIB_SBOM)/sbom-metadata.csv $(_layoutlib_font_config_files) $(_layoutlib_fonts_files) $(LAYOUTLIB_BUILD_PROP)/layoutlib-build.prop $(_layoutlib_keyboard_files) $(LAYOUTLIB_RES_FILES) $(EMULATED_OVERLAYS_FILES) $(DEVICE_OVERLAYS_FILES)
 	rm -rf $@
 	$(GEN_SBOM) --output_file $@ --metadata $(LAYOUTLIB_SBOM)/sbom-metadata.csv --build_version $(BUILD_FINGERPRINT_FROM_FILE) --product_mfr "$(PRODUCT_MANUFACTURER)" --module_name "layoutlib" --json
 
 $(call dist-for-goals,layoutlib,$(LAYOUTLIB_SBOM)/layoutlib.spdx.json:layoutlib_native/sbom/layoutlib.spdx.json)
 
 # Generate SBOM of framework_res.jar that is created in release_layoutlib.sh.
-# The generated SBOM contains placeholders for release_layotlib.sh to substitute, and the placeholders include:
+# The generated SBOM contains placeholders for release_layoutlib.sh to substitute, and the placeholders include:
 # document name, document namespace, document creation info, organization and SHA1 value of framework_res.jar.
 GEN_SBOM_FRAMEWORK_RES := $(HOST_OUT_EXECUTABLES)/generate-sbom-framework_res
 .PHONY: layoutlib-framework_res-sbom
diff --git a/core/main.mk b/core/main.mk
index 62fa53d08e..e5f5b9d2c6 100644
--- a/core/main.mk
+++ b/core/main.mk
@@ -31,8 +31,7 @@ endif
 .KATI_READONLY := $(foreach n,$(SOONG_CONFIG_NAMESPACES),SOONG_CONFIG_$(n))
 .KATI_READONLY := $(foreach n,$(SOONG_CONFIG_NAMESPACES),$(foreach k,$(SOONG_CONFIG_$(n)),SOONG_CONFIG_$(n)_$(k)))
 
-include $(SOONG_MAKEVARS_MK)
-
+include $(SOONG_OUT_DIR)/make_vars-$(TARGET_PRODUCT)$(COVERAGE_SUFFIX).mk
 YACC :=$= $(BISON) -d
 
 include $(BUILD_SYSTEM)/clang/config.mk
@@ -276,17 +275,23 @@ FULL_BUILD := true
 # Include all of the makefiles in the system
 #
 
-subdir_makefiles := $(SOONG_OUT_DIR)/installs-$(TARGET_PRODUCT).mk $(SOONG_ANDROID_MK)
+subdir_makefiles := $(SOONG_OUT_DIR)/installs-$(TARGET_PRODUCT)$(COVERAGE_SUFFIX).mk $(SOONG_ANDROID_MK)
+
 # Android.mk files are only used on Linux builds, Mac only supports Android.bp
 ifeq ($(HOST_OS),linux)
   subdir_makefiles += $(file <$(OUT_DIR)/.module_paths/Android.mk.list)
 endif
-subdir_makefiles += $(SOONG_OUT_DIR)/late-$(TARGET_PRODUCT).mk
+
+subdir_makefiles += $(SOONG_OUT_DIR)/late-$(TARGET_PRODUCT)$(COVERAGE_SUFFIX).mk
+
 subdir_makefiles_total := $(words int $(subdir_makefiles) post finish)
 .KATI_READONLY := subdir_makefiles_total
 
 $(foreach mk,$(subdir_makefiles),$(info [$(call inc_and_print,subdir_makefiles_inc)/$(subdir_makefiles_total)] including $(mk) ...)$(eval include $(mk)))
 
+# Build bootloader.img/radio.img, and unpack the partitions.
+include $(BUILD_SYSTEM)/tasks/tools/update_bootloader_radio_image.mk
+
 # For an unbundled image, we can skip blueprint_tools because unbundled image
 # aims to remove a large number framework projects from the manifest, the
 # sources or dependencies for these tools may be missing from the tree.
@@ -295,6 +300,9 @@ droid_targets : blueprint_tools
 checkbuild: blueprint_tests
 endif
 
+# Create necessary directories and symlinks in the root filesystem
+include system/core/rootdir/create_root_structure.mk
+
 endif # dont_bother
 
 ifndef subdir_makefiles_total
@@ -679,20 +687,28 @@ endef
 # Scan all modules in general-tests, device-tests and other selected suites and
 # flatten the shared library dependencies.
 define update-host-shared-libs-deps-for-suites
-$(foreach suite,general-tests device-tests vts tvts art-host-tests host-unit-tests,\
+$(foreach suite,general-tests device-tests vts tvts art-host-tests host-unit-tests camera-hal-tests,\
   $(foreach m,$(COMPATIBILITY.$(suite).MODULES),\
     $(eval my_deps := $(call get-all-shared-libs-deps,$(m)))\
     $(foreach dep,$(my_deps),\
       $(foreach f,$(ALL_MODULES.$(dep).HOST_SHARED_LIBRARY_FILES),\
-        $(if $(filter $(suite),device-tests general-tests art-host-tests host-unit-tests),\
+        $(if $(filter $(suite),device-tests general-tests art-host-tests host-unit-tests camera-hal-tests),\
           $(eval my_testcases := $(HOST_OUT_TESTCASES)),\
           $(eval my_testcases := $$(COMPATIBILITY_TESTCASES_OUT_$(suite))))\
         $(eval target := $(my_testcases)/$(lastword $(subst /, ,$(dir $(f))))/$(notdir $(f)))\
+        $(eval prefix := ../../..)
+        $(if $(strip $(patsubst %x86,,$(COMPATIBILITY.$(suite).ARCH_DIRS.$(m)))), \
+          $(if $(strip $(patsubst %x86_64,,$(COMPATIBILITY.$(suite).ARCH_DIRS.$(m)))),$(eval prefix := ../..),),) \
+        $(eval link_target := $(prefix)/$(lastword $(subst /, ,$(dir $(f))))/$(notdir $(f)))\
+        $(eval symlink := $(COMPATIBILITY.$(suite).ARCH_DIRS.$(m))/shared_libs/$(notdir $(f)))\
+        $(eval COMPATIBILITY.$(suite).SYMLINKS := \
+          $$(COMPATIBILITY.$(suite).SYMLINKS) $(f):$(link_target):$(symlink))\
         $(if $(strip $(ALL_TARGETS.$(target).META_LIC)),,$(call declare-copy-target-license-metadata,$(target),$(f)))\
         $(eval COMPATIBILITY.$(suite).HOST_SHARED_LIBRARY.FILES := \
           $$(COMPATIBILITY.$(suite).HOST_SHARED_LIBRARY.FILES) $(f):$(target))\
         $(eval COMPATIBILITY.$(suite).HOST_SHARED_LIBRARY.FILES := \
-          $(sort $(COMPATIBILITY.$(suite).HOST_SHARED_LIBRARY.FILES)))))))
+          $(sort $(COMPATIBILITY.$(suite).HOST_SHARED_LIBRARY.FILES))))))\
+  $(eval COMPATIBILITY.$(suite).SYMLINKS := $(sort $(COMPATIBILITY.$(suite).SYMLINKS))))
 endef
 
 $(call resolve-shared-libs-depes,TARGET_)
@@ -1850,48 +1866,34 @@ ifndef INSTALLED_RECOVERYIMAGE_TARGET
 filter_out_files += $(PRODUCT_OUT)/recovery/%
 endif
 
+# userdata.img
+ifndef BUILDING_USERDATA_IMAGE
+filter_out_files += $(PRODUCT_OUT)/data/%
+endif
+
 installed_files := $(sort $(filter-out $(filter_out_files),$(filter $(PRODUCT_OUT)/%,$(modules_to_install))))
 else
 installed_files := $(apps_only_installed_files)
 endif  # TARGET_BUILD_APPS
 
-# sbom-metadata.csv contains all raw data collected in Make for generating SBOM in generate-sbom.py.
-# There are multiple columns and each identifies the source of an installed file for a specific case.
-# The columns and their uses are described as below:
-#   installed_file: the file path on device, e.g. /product/app/Browser2/Browser2.apk
-#   module_path: the path of the module that generates the installed file, e.g. packages/apps/Browser2
-#   soong_module_type: Soong module type, e.g. android_app, cc_binary
-#   is_prebuilt_make_module: Y, if the installed file is from a prebuilt Make module, see prebuilt_internal.mk
-#   product_copy_files: the installed file is from variable PRODUCT_COPY_FILES, e.g. device/google/cuttlefish/shared/config/init.product.rc:product/etc/init/init.rc
-#   kernel_module_copy_files: the installed file is from variable KERNEL_MODULE_COPY_FILES, similar to product_copy_files
-#   is_platform_generated: this is an aggregated value including some small cases instead of adding more columns. It is set to Y if any case is Y
-#       is_build_prop: build.prop in each partition, see sysprop.mk.
-#       is_notice_file: NOTICE.xml.gz in each partition, see Makefile.
-#       is_dexpreopt_image_profile: see the usage of DEXPREOPT_IMAGE_PROFILE_BUILT_INSTALLED in Soong and Make
-#       is_product_system_other_avbkey: see INSTALLED_PRODUCT_SYSTEM_OTHER_AVBKEY_TARGET
-#       is_system_other_odex_marker: see INSTALLED_SYSTEM_OTHER_ODEX_MARKER
-#       is_event_log_tags_file: see variable event_log_tags_file in Makefile
-#       is_kernel_modules_blocklist: modules.blocklist created for _dlkm partitions, see macro build-image-kernel-modules-dir in Makefile.
-#       is_fsverity_build_manifest_apk: BuildManifest<part>.apk files for system and system_ext partition, see ALL_FSVERITY_BUILD_MANIFEST_APK in Makefile.
-#       is_linker_config: see SYSTEM_LINKER_CONFIG and vendor_linker_config_file in Makefile.
-#   build_output_path: the path of the built file, used to calculate checksum
-#   static_libraries/whole_static_libraries: list of module name of the static libraries the file links against, e.g. libclang_rt.builtins or libclang_rt.builtins_32
-#       Info of all static libraries of all installed files are collected in variable _all_static_libs that is used to list all the static library files in sbom-metadata.csv.
-#       See the second foreach loop in the rule of sbom-metadata.csv for the detailed info of static libraries collected in _all_static_libs.
-#   is_static_lib: whether the file is a static library
-
 metadata_list := $(OUT_DIR)/.module_paths/METADATA.list
 metadata_files := $(subst $(newline),$(space),$(file <$(metadata_list)))
-$(PRODUCT_OUT)/sbom-metadata.csv:
+
+# Create metadata for compliance support in Soong
+.PHONY: make-compliance-metadata
+make-compliance-metadata: \
+    $(SOONG_OUT_DIR)/compliance-metadata/$(TARGET_PRODUCT)/make-metadata.csv \
+    $(SOONG_OUT_DIR)/compliance-metadata/$(TARGET_PRODUCT)/make-modules.csv
+
+$(SOONG_OUT_DIR)/compliance-metadata/$(TARGET_PRODUCT)/make-metadata.csv:
 	rm -f $@
-	echo 'installed_file,module_path,soong_module_type,is_prebuilt_make_module,product_copy_files,kernel_module_copy_files,is_platform_generated,build_output_path,static_libraries,whole_static_libraries,is_static_lib' >> $@
-	$(eval _all_static_libs :=)
+	echo 'installed_file,module_path,is_soong_module,is_prebuilt_make_module,product_copy_files,kernel_module_copy_files,is_platform_generated,static_libs,whole_static_libs,license_text' >> $@
 	$(foreach f,$(installed_files),\
 	  $(eval _module_name := $(ALL_INSTALLED_FILES.$f)) \
 	  $(eval _path_on_device := $(patsubst $(PRODUCT_OUT)/%,%,$f)) \
 	  $(eval _build_output_path := $(PRODUCT_OUT)/$(_path_on_device)) \
 	  $(eval _module_path := $(strip $(sort $(ALL_MODULES.$(_module_name).PATH)))) \
-	  $(eval _soong_module_type := $(strip $(sort $(ALL_MODULES.$(_module_name).SOONG_MODULE_TYPE)))) \
+	  $(eval _is_soong_module := $(ALL_MODULES.$(_module_name).IS_SOONG_MODULE)) \
 	  $(eval _is_prebuilt_make_module := $(ALL_MODULES.$(_module_name).IS_PREBUILT_MAKE_MODULE)) \
 	  $(eval _product_copy_files := $(sort $(filter %:$(_path_on_device),$(product_copy_files_without_owner)))) \
 	  $(eval _kernel_module_copy_files := $(sort $(filter %$(_path_on_device),$(KERNEL_MODULE_COPY_FILES)))) \
@@ -1908,39 +1910,40 @@ $(PRODUCT_OUT)/sbom-metadata.csv:
 	  $(eval _is_flags_file := $(if $(findstring $f, $(ALL_FLAGS_FILES)),Y)) \
 	  $(eval _is_rootdir_symlink := $(if $(findstring $f, $(ALL_ROOTDIR_SYMLINKS)),Y)) \
 	  $(eval _is_platform_generated := $(_is_build_prop)$(_is_notice_file)$(_is_dexpreopt_image_profile)$(_is_product_system_other_avbkey)$(_is_event_log_tags_file)$(_is_system_other_odex_marker)$(_is_kernel_modules_blocklist)$(_is_fsverity_build_manifest_apk)$(_is_linker_config)$(_is_partition_compat_symlink)$(_is_flags_file)$(_is_rootdir_symlink)) \
-	  $(eval _static_libs := $(ALL_INSTALLED_FILES.$f.STATIC_LIBRARIES)) \
-	  $(eval _whole_static_libs := $(ALL_INSTALLED_FILES.$f.WHOLE_STATIC_LIBRARIES)) \
-	  $(foreach l,$(_static_libs),$(eval _all_static_libs += $l:$(strip $(sort $(ALL_MODULES.$l.PATH))):$(strip $(sort $(ALL_MODULES.$l.SOONG_MODULE_TYPE))):$(ALL_STATIC_LIBRARIES.$l.BUILT_FILE))) \
-	  $(foreach l,$(_whole_static_libs),$(eval _all_static_libs += $l:$(strip $(sort $(ALL_MODULES.$l.PATH))):$(strip $(sort $(ALL_MODULES.$l.SOONG_MODULE_TYPE))):$(ALL_STATIC_LIBRARIES.$l.BUILT_FILE))) \
-	  echo '/$(_path_on_device),$(_module_path),$(_soong_module_type),$(_is_prebuilt_make_module),$(_product_copy_files),$(_kernel_module_copy_files),$(_is_platform_generated),$(_build_output_path),$(_static_libs),$(_whole_static_libs),' >> $@; \
+	  $(eval _static_libs := $(if $(_is_soong_module),,$(ALL_INSTALLED_FILES.$f.STATIC_LIBRARIES))) \
+	  $(eval _whole_static_libs := $(if $(_is_soong_module),,$(ALL_INSTALLED_FILES.$f.WHOLE_STATIC_LIBRARIES))) \
+	  $(eval _license_text := $(if $(filter $(_build_output_path),$(ALL_NON_MODULES)),$(ALL_NON_MODULES.$(_build_output_path).NOTICES))) \
+	  echo '$(_build_output_path),$(_module_path),$(_is_soong_module),$(_is_prebuilt_make_module),$(_product_copy_files),$(_kernel_module_copy_files),$(_is_platform_generated),$(_static_libs),$(_whole_static_libs),$(_license_text)' >> $@; \
 	)
-	$(foreach l,$(sort $(_all_static_libs)), \
-	  $(eval _lib_stem := $(call word-colon,1,$l)) \
-	  $(eval _module_path := $(call word-colon,2,$l)) \
-	  $(eval _soong_module_type := $(call word-colon,3,$l)) \
-	  $(eval _built_file := $(call word-colon,4,$l)) \
-	  $(eval _static_libs := $(ALL_STATIC_LIBRARIES.$l.STATIC_LIBRARIES)) \
-	  $(eval _whole_static_libs := $(ALL_STATIC_LIBRARIES.$l.WHOLE_STATIC_LIBRARIES)) \
-	  $(eval _is_static_lib := Y) \
-	  echo '$(_lib_stem).a,$(_module_path),$(_soong_module_type),,,,,$(_built_file),$(_static_libs),$(_whole_static_libs),$(_is_static_lib)' >> $@; \
+
+$(SOONG_OUT_DIR)/compliance-metadata/$(TARGET_PRODUCT)/make-modules.csv:
+	rm -f $@
+	echo 'name,module_path,module_class,module_type,static_libs,whole_static_libs,built_files,installed_files' >> $@
+	$(foreach m,$(ALL_MODULES), \
+	  $(eval _module_name := $m) \
+	  $(eval _module_path := $(strip $(sort $(ALL_MODULES.$(_module_name).PATH)))) \
+	  $(eval _make_module_class := $(ALL_MODULES.$(_module_name).CLASS)) \
+	  $(eval _make_module_type := $(ALL_MODULES.$(_module_name).MAKE_MODULE_TYPE)) \
+	  $(eval _static_libs := $(strip $(sort $(ALL_MODULES.$(_module_name).STATIC_LIBS)))) \
+	  $(eval _whole_static_libs := $(strip $(sort $(ALL_MODULES.$(_module_name).WHOLE_STATIC_LIBS)))) \
+	  $(eval _built_files := $(strip $(sort $(ALL_MODULES.$(_module_name).BUILT)))) \
+	  $(eval _installed_files := $(strip $(sort $(ALL_MODULES.$(_module_name).INSTALLED)))) \
+	  $(eval _is_soong_module := $(ALL_MODULES.$(_module_name).IS_SOONG_MODULE)) \
+	  $(if $(_is_soong_module),, \
+		echo '$(_module_name),$(_module_path),$(_make_module_class),$(_make_module_type),$(_static_libs),$(_whole_static_libs),$(_built_files),$(_installed_files)' >> $@; \
+	  ) \
 	)
 
-# (TODO: b/272358583 find another way of always rebuilding sbom.spdx)
+$(SOONG_OUT_DIR)/compliance-metadata/$(TARGET_PRODUCT)/installed_files.stamp: $(installed_files)
+	touch $@
+
 # Remove the always_dirty_file.txt whenever the makefile is evaluated
 $(shell rm -f $(PRODUCT_OUT)/always_dirty_file.txt)
 $(PRODUCT_OUT)/always_dirty_file.txt:
 	touch $@
 
 .PHONY: sbom
-ifeq ($(TARGET_BUILD_APPS),)
-sbom: $(PRODUCT_OUT)/sbom.spdx.json
-$(PRODUCT_OUT)/sbom.spdx.json: $(PRODUCT_OUT)/sbom.spdx
-$(PRODUCT_OUT)/sbom.spdx: $(PRODUCT_OUT)/sbom-metadata.csv $(GEN_SBOM) $(installed_files) $(metadata_list) $(metadata_files) $(PRODUCT_OUT)/always_dirty_file.txt
-	rm -rf $@
-	$(GEN_SBOM) --output_file $@ --metadata $(PRODUCT_OUT)/sbom-metadata.csv --build_version $(BUILD_FINGERPRINT_FROM_FILE) --product_mfr "$(PRODUCT_MANUFACTURER)" --json
-
-$(call dist-for-goals,droid,$(PRODUCT_OUT)/sbom.spdx.json:sbom/sbom.spdx.json)
-else
+ifneq ($(TARGET_BUILD_APPS),)
 # Create build rules for generating SBOMs of unbundled APKs and APEXs
 # $1: sbom file
 # $2: sbom fragment file
diff --git a/core/multi_prebuilt.mk b/core/multi_prebuilt.mk
index c97d481f58..415401b3ca 100644
--- a/core/multi_prebuilt.mk
+++ b/core/multi_prebuilt.mk
@@ -132,3 +132,5 @@ prebuilt_java_libraries :=
 prebuilt_static_java_libraries :=
 prebuilt_is_host :=
 prebuilt_module_tags :=
+
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=MULTI_PREBUILT))
\ No newline at end of file
diff --git a/core/native_test.mk b/core/native_test.mk
index 8b49fbde10..c12b211467 100644
--- a/core/native_test.mk
+++ b/core/native_test.mk
@@ -21,3 +21,5 @@ endif
 endif
 
 include $(BUILD_EXECUTABLE)
+
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=NATIVE_TEST))
\ No newline at end of file
diff --git a/core/os_licensing.mk b/core/os_licensing.mk
index 1e1b7df7a9..d15a3d0715 100644
--- a/core/os_licensing.mk
+++ b/core/os_licensing.mk
@@ -17,13 +17,17 @@ $(eval $(call xml-notice-rule,$(target_notice_file_xml_gz),"System image",$(syst
 
 $(eval $(call text-notice-rule,$(target_notice_file_txt),"System image",$(system_notice_file_message),$(SYSTEM_NOTICE_DEPS),$(SYSTEM_NOTICE_DEPS)))
 
+ifneq ($(USE_SOONG_DEFINED_SYSTEM_IMAGE),true)
 $(installed_notice_html_or_xml_gz): $(target_notice_file_xml_gz)
 	$(copy-file-to-target)
 endif
+endif
 
 $(call declare-1p-target,$(target_notice_file_xml_gz))
+ifneq ($(USE_SOONG_DEFINED_SYSTEM_IMAGE),true)
 $(call declare-1p-target,$(installed_notice_html_or_xml_gz))
 endif
+endif
 
 .PHONY: vendorlicense
 vendorlicense: $(call corresponding-license-metadata, $(VENDOR_NOTICE_DEPS)) reportmissinglicenses
diff --git a/core/package_internal.mk b/core/package_internal.mk
index a03a62b7fa..a7eb57218f 100644
--- a/core/package_internal.mk
+++ b/core/package_internal.mk
@@ -731,3 +731,5 @@ ifneq (,$(runtime_resource_overlays_product)$(runtime_resource_overlays_vendor))
     )
   endif
 endif
+
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=PACKAGE))
\ No newline at end of file
diff --git a/core/packaging/flags.mk b/core/packaging/flags.mk
index a96ea8fed3..4693bcd6d8 100644
--- a/core/packaging/flags.mk
+++ b/core/packaging/flags.mk
@@ -18,7 +18,7 @@
 #
 
 # TODO: Should we do all of the images in $(IMAGES_TO_BUILD)?
-_FLAG_PARTITIONS := product system system_ext vendor
+_FLAG_PARTITIONS := product system vendor
 
 
 # -----------------------------------------------------------------
@@ -27,9 +27,28 @@ _FLAG_PARTITIONS := product system system_ext vendor
 # Create a summary file of build flags for each partition
 # $(1): built aconfig flags file (out)
 # $(2): installed aconfig flags file (out)
-# $(3): input aconfig files for the partition (in)
+# $(3): the partition (in)
 define generate-partition-aconfig-flag-file
 $(eval $(strip $(1)): PRIVATE_OUT := $(strip $(1)))
+$(eval $(strip $(1)): PRIVATE_IN := $(strip $(4)))
+$(strip $(1)): $(ACONFIG) $(strip $(4))
+	mkdir -p $$(dir $$(PRIVATE_OUT))
+	$$(if $$(PRIVATE_IN), \
+		$$(ACONFIG) dump --dedup --format protobuf --out $$(PRIVATE_OUT) \
+			--filter container:$(strip $(3)) \
+			$$(addprefix --cache ,$$(PRIVATE_IN)), \
+		echo -n > $$(PRIVATE_OUT) \
+	)
+$(call copy-one-file, $(1), $(2))
+endef
+
+
+# Create a summary file of build flags for each partition
+# $(1): built aconfig flags file (out)
+# $(2): installed aconfig flags file (out)
+# $(3): input aconfig files for the partition (in)
+define generate-global-aconfig-flag-file
+$(eval $(strip $(1)): PRIVATE_OUT := $(strip $(1)))
 $(eval $(strip $(1)): PRIVATE_IN := $(strip $(3)))
 $(strip $(1)): $(ACONFIG) $(strip $(3))
 	mkdir -p $$(dir $$(PRIVATE_OUT))
@@ -41,15 +60,22 @@ $(strip $(1)): $(ACONFIG) $(strip $(3))
 $(call copy-one-file, $(1), $(2))
 endef
 
-
 $(foreach partition, $(_FLAG_PARTITIONS), \
 	$(eval aconfig_flag_summaries_protobuf.$(partition) := $(PRODUCT_OUT)/$(partition)/etc/aconfig_flags.pb) \
 	$(eval $(call generate-partition-aconfig-flag-file, \
-				$(TARGET_OUT_FLAGS)/$(partition)/aconfig_flags.pb, \
-				$(aconfig_flag_summaries_protobuf.$(partition)), \
-				$(sort $(foreach m,$(call register-names-for-partition, $(partition)), \
+			$(TARGET_OUT_FLAGS)/$(partition)/aconfig_flags.pb, \
+			$(aconfig_flag_summaries_protobuf.$(partition)), \
+			$(partition), \
+			$(sort \
+				$(foreach m, $(call register-names-for-partition, $(partition)), \
 					$(ALL_MODULES.$(m).ACONFIG_FILES) \
-				)), \
+				) \
+				$(if $(filter system, $(partition)), \
+					$(foreach m, $(call register-names-for-partition, system_ext), \
+						$(ALL_MODULES.$(m).ACONFIG_FILES) \
+					) \
+				) \
+			) \
 	)) \
 )
 
@@ -61,7 +87,7 @@ required_aconfig_flags_files := \
 
 .PHONY: device_aconfig_declarations
 device_aconfig_declarations: $(PRODUCT_OUT)/device_aconfig_declarations.pb
-$(eval $(call generate-partition-aconfig-flag-file, \
+$(eval $(call generate-global-aconfig-flag-file, \
 			$(TARGET_OUT_FLAGS)/device_aconfig_declarations.pb, \
 			$(PRODUCT_OUT)/device_aconfig_declarations.pb, \
 			$(sort $(required_aconfig_flags_files)) \
@@ -121,9 +147,7 @@ $(foreach partition, $(_FLAG_PARTITIONS), \
 				$(aconfig_storage_package_map.$(partition)), \
 				$(aconfig_storage_flag_map.$(partition)), \
 				$(aconfig_storage_flag_val.$(partition)), \
-				$(sort $(foreach m,$(call register-names-for-partition, $(partition)), \
-					$(ALL_MODULES.$(m).ACONFIG_FILES) \
-				)), \
+				$(aconfig_flag_summaries_protobuf.$(partition)), \
 				$(partition), \
 	)) \
 )
@@ -158,4 +182,3 @@ $(foreach partition, $(_FLAG_PARTITIONS), \
 	$(eval aconfig_storage_flag_map.$(partition):=) \
 	$(eval aconfig_storage_flag_val.$(partition):=) \
 )
-
diff --git a/core/phony_package.mk b/core/phony_package.mk
index 578d629789..c978793e2e 100644
--- a/core/phony_package.mk
+++ b/core/phony_package.mk
@@ -12,3 +12,5 @@ $(LOCAL_BUILT_MODULE): $(LOCAL_ADDITIONAL_DEPENDENCIES)
 	$(hide) echo "Fake: $@"
 	$(hide) mkdir -p $(dir $@)
 	$(hide) touch $@
+
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=PHONY_PACKAGE))
\ No newline at end of file
diff --git a/core/prebuilt_internal.mk b/core/prebuilt_internal.mk
index 94626402c9..d5261f4cfc 100644
--- a/core/prebuilt_internal.mk
+++ b/core/prebuilt_internal.mk
@@ -63,3 +63,5 @@ $(if $(filter-out $(SOONG_ANDROID_MK),$(LOCAL_MODULE_MAKEFILE)), \
 $(built_module) : $(LOCAL_ADDITIONAL_DEPENDENCIES)
 
 my_prebuilt_src_file :=
+
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=PREBUILT))
\ No newline at end of file
diff --git a/core/product.mk b/core/product.mk
index d469c0e737..b07e6e0dc4 100644
--- a/core/product.mk
+++ b/core/product.mk
@@ -26,6 +26,7 @@ _product_single_value_vars += PRODUCT_NAME
 _product_single_value_vars += PRODUCT_MODEL
 _product_single_value_vars += PRODUCT_NAME_FOR_ATTESTATION
 _product_single_value_vars += PRODUCT_MODEL_FOR_ATTESTATION
+_product_single_value_vars += PRODUCT_BASE_OS
 
 # Defines the ELF segment alignment for binaries (executables and shared libraries).
 # The ELF segment alignment has to be a PAGE_SIZE multiple. For example, if
@@ -160,7 +161,6 @@ _product_list_vars += PRODUCT_BOOT_JARS_EXTRA
 # List of jars to be included in the ART boot image for testing.
 _product_list_vars += PRODUCT_TEST_ONLY_ART_BOOT_IMAGE_JARS
 
-_product_single_value_vars += PRODUCT_SUPPORTS_VBOOT
 _product_list_vars += PRODUCT_SYSTEM_SERVER_APPS
 # List of system_server classpath jars on the platform.
 _product_list_vars += PRODUCT_SYSTEM_SERVER_JARS
@@ -496,6 +496,13 @@ _product_single_value_vars += PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG
 # If set, the default value of the versionName of apps will include the build number.
 _product_single_value_vars += PRODUCT_BUILD_APPS_WITH_BUILD_NUMBER
 
+# If set, build would generate system image from Soong-defined module.
+_product_single_value_vars += PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE
+
+# List of stub libraries specific to the product that are already present in the system image and
+# should be included in the system_linker_config.
+_product_list_vars += PRODUCT_EXTRA_STUB_LIBRARIES
+
 .KATI_READONLY := _product_single_value_vars _product_list_vars
 _product_var_list :=$= $(_product_single_value_vars) $(_product_list_vars)
 
diff --git a/core/product_config.mk b/core/product_config.mk
index f939690f98..738d4cff58 100644
--- a/core/product_config.mk
+++ b/core/product_config.mk
@@ -311,6 +311,14 @@ endif
 
 TARGET_DEVICE := $(PRODUCT_DEVICE)
 
+# Allow overriding PLATFORM_BASE_OS when PRODUCT_BASE_OS is defined
+ifdef PRODUCT_BASE_OS
+  PLATFORM_BASE_OS := $(PRODUCT_BASE_OS)
+else
+  PLATFORM_BASE_OS := $(PLATFORM_BASE_OS_ENV_INPUT)
+endif
+.KATI_READONLY := PLATFORM_BASE_OS
+
 # TODO: also keep track of things like "port", "land" in product files.
 
 # Figure out which resoure configuration options to use for this
@@ -405,6 +413,10 @@ else
   TARGET_AAPT_CHARACTERISTICS := $(PRODUCT_CHARACTERISTICS)
 endif
 
+ifndef PRODUCT_SHIPPING_API_LEVEL
+  PRODUCT_SHIPPING_API_LEVEL := 10000
+endif
+
 ifdef PRODUCT_DEFAULT_DEV_CERTIFICATE
   ifneq (1,$(words $(PRODUCT_DEFAULT_DEV_CERTIFICATE)))
     $(error PRODUCT_DEFAULT_DEV_CERTIFICATE='$(PRODUCT_DEFAULT_DEV_CERTIFICATE)', \
@@ -557,11 +569,26 @@ ifdef PRODUCT_ENFORCE_RRO_EXEMPTED_TARGETS
 endif
 
 # This table maps sdk version 35 to vendor api level 202404 and assumes yearly
-# release for the same month.
+# release for the same month. If 10000 API level or more is used, which usually
+# represents 'current' or 'future' API levels, several zeros are added to
+# preserve ordering. Specifically API level 10,000 is converted to 10,000,000
+# which importantly is greater than 202404 = 202,404. This convention will break
+# in 100,000 CE, which is the closest multiple of 10 that doesn't break earlier
+# than 10,000 as an API level breaks.
 define sdk-to-vendor-api-level
-  $(if $(call math_lt_or_eq,$(1),34),$(1),20$(call int_subtract,$(1),11)04)
+$(if $(call math_lt_or_eq,$(1),34),$(1),$(if $(call math_lt,$(1),10000),20$(call int_subtract,$(1),11)04,$(1)000))
 endef
 
+ifneq ($(call sdk-to-vendor-api-level,34),34)
+$(error sdk-to-vendor-api-level is broken for pre-Trunk-Stable SDKs)
+endif
+ifneq ($(call sdk-to-vendor-api-level,35),202404)
+$(error sdk-to-vendor-api-level is broken for post-Trunk-Stable SDKs)
+endif
+ifneq ($(call sdk-to-vendor-api-level,10000),10000000)
+$(error sdk-to-vendor-api-level is broken for current $(call sdk-to-vendor-api-level,10000))
+endif
+
 ifdef PRODUCT_SHIPPING_VENDOR_API_LEVEL
 # Follow the version that is set manually.
   VSR_VENDOR_API_LEVEL := $(PRODUCT_SHIPPING_VENDOR_API_LEVEL)
diff --git a/core/product_config.rbc b/core/product_config.rbc
index 59e2c95903..20344f4f87 100644
--- a/core/product_config.rbc
+++ b/core/product_config.rbc
@@ -382,6 +382,11 @@ def _soong_config_set(g, nsname, var, value):
     _soong_config_namespace(g, nsname)
     g[_soong_config_namespaces_key][nsname][var]=_mkstrip(value)
 
+def _soong_config_set_bool(g, nsname, var, value):
+    """Assigns the value to the variable in the namespace, and marks it as a boolean."""
+    _soong_config_set(g, nsname, var, _filter("true", value))
+    g["SOONG_CONFIG_TYPE_%s_%s" % (nsname, var)] = "bool"
+
 def _soong_config_append(g, nsname, var, value):
     """Appends to the value of the variable in the namespace."""
     _soong_config_namespace(g, nsname)
@@ -861,6 +866,7 @@ rblf = struct(
     soong_config_namespace = _soong_config_namespace,
     soong_config_append = _soong_config_append,
     soong_config_set = _soong_config_set,
+    soong_config_set_bool = _soong_config_set_bool,
     soong_config_get = _soong_config_get,
     abspath = _abspath,
     add_product_dex_preopt_module_config = _add_product_dex_preopt_module_config,
diff --git a/core/ravenwood_test_config_template.xml b/core/ravenwood_test_config_template.xml
index 16a22c0628..2f21baedf7 100644
--- a/core/ravenwood_test_config_template.xml
+++ b/core/ravenwood_test_config_template.xml
@@ -18,10 +18,9 @@
     <option name="test-suite-tag" value="ravenwood" />
     <option name="test-suite-tag" value="ravenwood-tests" />
 
-    <option name="java-folder" value="prebuilts/jdk/jdk17/linux-x86/" />
+    <option name="java-folder" value="prebuilts/jdk/jdk21/linux-x86/" />
     <option name="use-ravenwood-resources" value="true" />
     <option name="exclude-paths" value="java" />
-    <option name="socket-timeout" value="10000" />
     <option name="null-device" value="true" />
 
     {EXTRA_CONFIGS}
diff --git a/core/release_config.mk b/core/release_config.mk
index 2898868682..fe2170ede4 100644
--- a/core/release_config.mk
+++ b/core/release_config.mk
@@ -131,6 +131,9 @@ ifneq (,$(_use_protobuf))
         _args += --guard=false
     endif
     _args += --allow-missing=true
+    ifneq (,$(TARGET_PRODUCT))
+        _args += --product $(TARGET_PRODUCT)
+    endif
     _flags_dir:=$(OUT_DIR)/soong/release-config
     _flags_file:=$(_flags_dir)/release_config-$(TARGET_PRODUCT)-$(TARGET_RELEASE).vars
     # release-config generates $(_flags_varmk)
diff --git a/core/robolectric_test_config_template.xml b/core/robolectric_test_config_template.xml
index 56d2312626..b1d0c2f4fa 100644
--- a/core/robolectric_test_config_template.xml
+++ b/core/robolectric_test_config_template.xml
@@ -18,7 +18,7 @@
     <option name="test-suite-tag" value="robolectric" />
     <option name="test-suite-tag" value="robolectric-tests" />
 
-    <option name="java-folder" value="prebuilts/jdk/jdk17/linux-x86/" />
+    <option name="java-folder" value="prebuilts/jdk/jdk21/linux-x86/" />
     <option name="exclude-paths" value="java" />
     <option name="use-robolectric-resources" value="true" />
 
diff --git a/core/rust_device_test_config_template.xml b/core/rust_device_test_config_template.xml
index bfd2f4761c..aacabcb111 100644
--- a/core/rust_device_test_config_template.xml
+++ b/core/rust_device_test_config_template.xml
@@ -20,11 +20,11 @@
 
     <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
         <option name="cleanup" value="true" />
-        <option name="push" value="{MODULE}->/data/local/tmp/{MODULE}" />
+        <option name="push" value="{MODULE}->{TEST_INSTALL_BASE}/{MODULE}" />
     </target_preparer>
 
     <test class="com.android.tradefed.testtype.rust.RustBinaryTest" >
-        <option name="test-device-path" value="/data/local/tmp" />
+        <option name="test-device-path" value="{TEST_INSTALL_BASE}" />
         <option name="module-name" value="{MODULE}" />
     </test>
 </configuration>
diff --git a/core/shared_library_internal.mk b/core/shared_library_internal.mk
index 2f510d9b30..ae34cb887d 100644
--- a/core/shared_library_internal.mk
+++ b/core/shared_library_internal.mk
@@ -101,4 +101,6 @@ $(my_coverage_path)/$(GCNO_ARCHIVE) : $(intermediates)/$(GCNO_ARCHIVE)
 $(LOCAL_BUILT_MODULE): $(my_coverage_path)/$(GCNO_ARCHIVE)
 endif
 
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=SHARED_LIBRARY))
+
 endif  # skip_build_from_source
diff --git a/core/soong_android_app_set.mk b/core/soong_android_app_set.mk
index ec3d8c85cb..d97980d2ba 100644
--- a/core/soong_android_app_set.mk
+++ b/core/soong_android_app_set.mk
@@ -9,10 +9,6 @@ endif
 LOCAL_BUILT_MODULE_STEM := package.apk
 LOCAL_INSTALLED_MODULE_STEM := $(notdir $(LOCAL_PREBUILT_MODULE_FILE))
 
-# Use the Soong output as the checkbuild target instead of LOCAL_BUILT_MODULE
-# to avoid checkbuilds making an extra copy of every module.
-LOCAL_CHECKED_MODULE := $(LOCAL_PREBUILT_MODULE_FILE)
-
 #######################################
 include $(BUILD_SYSTEM)/base_rules.mk
 #######################################
diff --git a/core/soong_app_prebuilt.mk b/core/soong_app_prebuilt.mk
index 3aa244c77f..df1cf2d369 100644
--- a/core/soong_app_prebuilt.mk
+++ b/core/soong_app_prebuilt.mk
@@ -29,16 +29,6 @@ full_classes_pre_proguard_jar := $(intermediates.COMMON)/classes-pre-proguard.ja
 full_classes_header_jar := $(intermediates.COMMON)/classes-header.jar
 
 
-# Use the Soong output as the checkbuild target instead of LOCAL_BUILT_MODULE
-# to avoid checkbuilds making an extra copy of every module.
-LOCAL_CHECKED_MODULE := $(LOCAL_PREBUILT_MODULE_FILE)
-LOCAL_ADDITIONAL_CHECKED_MODULE += $(LOCAL_SOONG_CLASSES_JAR)
-LOCAL_ADDITIONAL_CHECKED_MODULE += $(LOCAL_SOONG_HEADER_JAR)
-LOCAL_ADDITIONAL_CHECKED_MODULE += $(LOCAL_FULL_MANIFEST_FILE)
-LOCAL_ADDITIONAL_CHECKED_MODULE += $(LOCAL_SOONG_DEXPREOPT_CONFIG)
-LOCAL_ADDITIONAL_CHECKED_MODULE += $(LOCAL_SOONG_RESOURCE_EXPORT_PACKAGE)
-LOCAL_ADDITIONAL_CHECKED_MODULE += $(LOCAL_SOONG_DEX_JAR)
-
 #######################################
 include $(BUILD_SYSTEM)/base_rules.mk
 #######################################
diff --git a/core/soong_cc_rust_prebuilt.mk b/core/soong_cc_rust_prebuilt.mk
index a1c64786ee..da608322f2 100644
--- a/core/soong_cc_rust_prebuilt.mk
+++ b/core/soong_cc_rust_prebuilt.mk
@@ -38,10 +38,6 @@ ifndef LOCAL_UNINSTALLABLE_MODULE
   endif
 endif
 
-# Use the Soong output as the checkbuild target instead of LOCAL_BUILT_MODULE
-# to avoid checkbuilds making an extra copy of every module.
-LOCAL_CHECKED_MODULE := $(LOCAL_PREBUILT_MODULE_FILE)
-
 my_check_same_vndk_variants :=
 same_vndk_variants_stamp :=
 ifeq ($(LOCAL_CHECK_SAME_VNDK_VARIANTS),true)
@@ -61,7 +57,7 @@ ifeq ($(my_check_same_vndk_variants),true)
   # Note that because `checkbuild` doesn't check LOCAL_BUILT_MODULE for soong-built modules adding
   # the timestamp to LOCAL_BUILT_MODULE isn't enough. It is skipped when the vendor variant
   # isn't used at all and it may break in the downstream trees.
-  LOCAL_ADDITIONAL_CHECKED_MODULE := $(same_vndk_variants_stamp)
+  LOCAL_ADDITIONAL_CHECKED_MODULE += $(same_vndk_variants_stamp)
 endif
 
 #######################################
diff --git a/core/soong_config.mk b/core/soong_config.mk
index dd7e4e6bd7..1e6388a5ba 100644
--- a/core/soong_config.mk
+++ b/core/soong_config.mk
@@ -1,6 +1,5 @@
-SOONG_MAKEVARS_MK := $(SOONG_OUT_DIR)/make_vars-$(TARGET_PRODUCT).mk
-SOONG_VARIABLES := $(SOONG_OUT_DIR)/soong.$(TARGET_PRODUCT).variables
-SOONG_ANDROID_MK := $(SOONG_OUT_DIR)/Android-$(TARGET_PRODUCT).mk
+SOONG_MAKEVARS_MK := $(SOONG_OUT_DIR)/make_vars-$(TARGET_PRODUCT)$(COVERAGE_SUFFIX).mk
+SOONG_ANDROID_MK := $(SOONG_OUT_DIR)/Android-$(TARGET_PRODUCT)$(COVERAGE_SUFFIX).mk
 
 include $(BUILD_SYSTEM)/art_config.mk
 include $(BUILD_SYSTEM)/dex_preopt_config.mk
@@ -27,9 +26,10 @@ ifeq ($(WRITE_SOONG_VARIABLES),true)
 $(shell mkdir -p $(dir $(SOONG_VARIABLES)))
 $(call json_start)
 
-$(call add_json_str,  Make_suffix, -$(TARGET_PRODUCT))
+$(call add_json_str,  Make_suffix, -$(TARGET_PRODUCT)$(COVERAGE_SUFFIX))
 
 $(call add_json_str,  BuildId,                           $(BUILD_ID))
+$(call add_json_str,  BuildFingerprintFile,              build_fingerprint.txt)
 $(call add_json_str,  BuildNumberFile,                   build_number.txt)
 $(call add_json_str,  BuildHostnameFile,                 build_hostname.txt)
 $(call add_json_str,  BuildThumbprintFile,               build_thumbprint.txt)
@@ -109,6 +109,8 @@ $(call add_json_str,  AAPTPreferredConfig,               $(PRODUCT_AAPT_PREF_CON
 $(call add_json_list, AAPTPrebuiltDPI,                   $(PRODUCT_AAPT_PREBUILT_DPI))
 
 $(call add_json_str,  DefaultAppCertificate,             $(PRODUCT_DEFAULT_DEV_CERTIFICATE))
+$(call add_json_list, ExtraOtaKeys,                      $(PRODUCT_EXTRA_OTA_KEYS))
+$(call add_json_list, ExtraOtaRecoveryKeys,              $(PRODUCT_EXTRA_RECOVERY_KEYS))
 $(call add_json_str,  MainlineSepolicyDevCertificates,   $(MAINLINE_SEPOLICY_DEV_CERTIFICATES))
 
 $(call add_json_str,  AppsDefaultVersionName,            $(APPS_DEFAULT_VERSION_NAME))
@@ -150,7 +152,6 @@ $(call add_json_list, DeviceKernelHeaders,               $(TARGET_DEVICE_KERNEL_
 $(call add_json_str,  VendorApiLevel,                    $(BOARD_API_LEVEL))
 $(call add_json_list, ExtraVndkVersions,                 $(PRODUCT_EXTRA_VNDK_VERSIONS))
 $(call add_json_list, DeviceSystemSdkVersions,           $(BOARD_SYSTEMSDK_VERSIONS))
-$(call add_json_str,  RecoverySnapshotVersion,           $(RECOVERY_SNAPSHOT_VERSION))
 $(call add_json_list, Platform_systemsdk_versions,       $(PLATFORM_SYSTEMSDK_VERSIONS))
 $(call add_json_bool, Malloc_low_memory,                 $(findstring true,$(MALLOC_SVELTE) $(MALLOC_LOW_MEMORY)))
 $(call add_json_bool, Malloc_zero_contents,              $(call invert_bool,$(filter false,$(MALLOC_ZERO_CONTENTS))))
@@ -165,8 +166,6 @@ $(call add_json_list, ModulesLoadedByPrivilegedModules,  $(PRODUCT_LOADED_BY_PRI
 $(call add_json_list, BootJars,                          $(PRODUCT_BOOT_JARS))
 $(call add_json_list, ApexBootJars,                      $(filter-out $(APEX_BOOT_JARS_EXCLUDED), $(PRODUCT_APEX_BOOT_JARS)))
 
-$(call add_json_bool, VndkSnapshotBuildArtifacts,        $(VNDK_SNAPSHOT_BUILD_ARTIFACTS))
-
 $(call add_json_map,  BuildFlags)
 $(foreach flag,$(_ALL_RELEASE_FLAGS),\
   $(call add_json_str,$(flag),$(_ALL_RELEASE_FLAGS.$(flag).VALUE)))
@@ -176,24 +175,6 @@ $(foreach flag,$(_ALL_RELEASE_FLAGS),\
   $(call add_json_str,$(flag),$(_ALL_RELEASE_FLAGS.$(flag).TYPE)))
 $(call end_json_map)
 
-$(call add_json_bool, DirectedVendorSnapshot,            $(DIRECTED_VENDOR_SNAPSHOT))
-$(call add_json_map,  VendorSnapshotModules)
-$(foreach module,$(VENDOR_SNAPSHOT_MODULES),\
-  $(call add_json_bool,$(module),true))
-$(call end_json_map)
-
-$(call add_json_bool, DirectedRecoverySnapshot,          $(DIRECTED_RECOVERY_SNAPSHOT))
-$(call add_json_map,  RecoverySnapshotModules)
-$(foreach module,$(RECOVERY_SNAPSHOT_MODULES),\
-  $(call add_json_bool,$(module),true))
-$(call end_json_map)
-
-$(call add_json_list, VendorSnapshotDirsIncluded,        $(VENDOR_SNAPSHOT_DIRS_INCLUDED))
-$(call add_json_list, VendorSnapshotDirsExcluded,        $(VENDOR_SNAPSHOT_DIRS_EXCLUDED))
-$(call add_json_list, RecoverySnapshotDirsIncluded,      $(RECOVERY_SNAPSHOT_DIRS_INCLUDED))
-$(call add_json_list, RecoverySnapshotDirsExcluded,      $(RECOVERY_SNAPSHOT_DIRS_EXCLUDED))
-$(call add_json_bool, HostFakeSnapshotEnabled,           $(HOST_FAKE_SNAPSHOT_ENABLE))
-
 $(call add_json_bool, MultitreeUpdateMeta,               $(filter true,$(TARGET_MULTITREE_UPDATE_META)))
 
 $(call add_json_bool, Treble_linker_namespaces,          $(filter true,$(PRODUCT_TREBLE_LINKER_NAMESPACES)))
@@ -225,6 +206,7 @@ $(call add_json_list, BoardSepolicyM4Defs,               $(BOARD_SEPOLICY_M4DEFS
 $(call add_json_str,  BoardSepolicyVers,                 $(BOARD_SEPOLICY_VERS))
 $(call add_json_str,  SystemExtSepolicyPrebuiltApiDir,   $(BOARD_SYSTEM_EXT_PREBUILT_DIR))
 $(call add_json_str,  ProductSepolicyPrebuiltApiDir,     $(BOARD_PRODUCT_PREBUILT_DIR))
+$(call add_json_str,  BoardPlatform,                     $(TARGET_BOARD_PLATFORM))
 
 $(call add_json_str,  PlatformSepolicyVersion,           $(PLATFORM_SEPOLICY_VERSION))
 $(call add_json_list, PlatformSepolicyCompatVersions,    $(PLATFORM_SEPOLICY_COMPAT_VERSIONS))
@@ -254,6 +236,12 @@ $(call add_json_list, ProductPrivateSepolicyDirs,        $(PRODUCT_PRIVATE_SEPOL
 
 $(call add_json_list, TargetFSConfigGen,                 $(TARGET_FS_CONFIG_GEN))
 
+# Although USE_SOONG_DEFINED_SYSTEM_IMAGE determines whether to use the system image specified by
+# PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE, PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE is still used to compare
+# installed files between make and soong, regardless of the USE_SOONG_DEFINED_SYSTEM_IMAGE setting.
+$(call add_json_bool, UseSoongSystemImage,               $(filter true,$(USE_SOONG_DEFINED_SYSTEM_IMAGE)))
+$(call add_json_str,  ProductSoongDefinedSystemImage,    $(PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE))
+
 $(call add_json_map, VendorVars)
 $(foreach namespace,$(sort $(SOONG_CONFIG_NAMESPACES)),\
   $(call add_json_map, $(namespace))\
@@ -262,6 +250,18 @@ $(foreach namespace,$(sort $(SOONG_CONFIG_NAMESPACES)),\
   $(call end_json_map))
 $(call end_json_map)
 
+# Add the types of the variables in VendorVars. Since this is much newer
+# than VendorVars, which has a history of just using string values for everything,
+# variables are assumed to be strings by default. For strings, SOONG_CONFIG_TYPE_*
+# will not be set, and they will not have an entry in the VendorVarTypes map.
+$(call add_json_map, VendorVarTypes)
+$(foreach namespace,$(sort $(SOONG_CONFIG_NAMESPACES)),\
+  $(call add_json_map, $(namespace))\
+  $(foreach key,$(sort $(SOONG_CONFIG_$(namespace))),\
+    $(if $(SOONG_CONFIG_TYPE_$(namespace)_$(key)),$(call add_json_str,$(key),$(subst ",\",$(SOONG_CONFIG_TYPE_$(namespace)_$(key))))))\
+  $(call end_json_map))
+$(call end_json_map)
+
 $(call add_json_bool, EnforceProductPartitionInterface,  $(filter true,$(PRODUCT_ENFORCE_PRODUCT_PARTITION_INTERFACE)))
 $(call add_json_str,  DeviceCurrentApiLevelForVendorModules,  $(BOARD_CURRENT_API_LEVEL_FOR_VENDOR_MODULES))
 
@@ -292,11 +292,11 @@ $(call add_json_bool, BuildBrokenClangCFlags,              $(filter true,$(BUILD
 $(call add_json_bool, GenruleSandboxing,                   $(if $(GENRULE_SANDBOXING),$(filter true,$(GENRULE_SANDBOXING)),$(if $(filter true,$(BUILD_BROKEN_GENRULE_SANDBOXING)),,true)))
 $(call add_json_bool, BuildBrokenEnforceSyspropOwner,      $(filter true,$(BUILD_BROKEN_ENFORCE_SYSPROP_OWNER)))
 $(call add_json_bool, BuildBrokenTrebleSyspropNeverallow,  $(filter true,$(BUILD_BROKEN_TREBLE_SYSPROP_NEVERALLOW)))
-$(call add_json_bool, BuildBrokenUsesSoongPython2Modules,  $(filter true,$(BUILD_BROKEN_USES_SOONG_PYTHON2_MODULES)))
 $(call add_json_bool, BuildBrokenVendorPropertyNamespace,  $(filter true,$(BUILD_BROKEN_VENDOR_PROPERTY_NAMESPACE)))
 $(call add_json_bool, BuildBrokenIncorrectPartitionImages, $(filter true,$(BUILD_BROKEN_INCORRECT_PARTITION_IMAGES)))
 $(call add_json_list, BuildBrokenInputDirModules,          $(BUILD_BROKEN_INPUT_DIR_MODULES))
 $(call add_json_bool, BuildBrokenDontCheckSystemSdk,       $(filter true,$(BUILD_BROKEN_DONT_CHECK_SYSTEMSDK)))
+$(call add_json_bool, BuildBrokenDupSysprop,               $(filter true,$(BUILD_BROKEN_DUP_SYSPROP)))
 
 $(call add_json_list, BuildWarningBadOptionalUsesLibsAllowlist,    $(BUILD_WARNING_BAD_OPTIONAL_USES_LIBS_ALLOWLIST))
 
@@ -346,6 +346,27 @@ $(call add_json_bool, BoardUseVbmetaDigestInFingerprint, $(filter true,$(BOARD_U
 
 $(call add_json_list, OemProperties, $(PRODUCT_OEM_PROPERTIES))
 
+$(call add_json_list, SystemPropFiles, $(TARGET_SYSTEM_PROP))
+$(call add_json_list, SystemExtPropFiles, $(TARGET_SYSTEM_EXT_PROP))
+$(call add_json_list, ProductPropFiles, $(TARGET_PRODUCT_PROP))
+$(call add_json_list, OdmPropFiles, $(TARGET_ODM_PROP))
+
+# Do not set ArtTargetIncludeDebugBuild into any value if PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD is not set,
+# to have the same behavior from runtime_libart.mk.
+ifneq ($(PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD),)
+$(call add_json_bool, ArtTargetIncludeDebugBuild, $(PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD))
+endif
+
+_config_enable_uffd_gc := \
+  $(firstword $(OVERRIDE_ENABLE_UFFD_GC) $(PRODUCT_ENABLE_UFFD_GC) default)
+$(call add_json_str, EnableUffdGc, $(_config_enable_uffd_gc))
+_config_enable_uffd_gc :=
+
+$(call add_json_list, DeviceFrameworkCompatibilityMatrixFile, $(DEVICE_FRAMEWORK_COMPATIBILITY_MATRIX_FILE))
+$(call add_json_list, DeviceProductCompatibilityMatrixFile, $(DEVICE_PRODUCT_COMPATIBILITY_MATRIX_FILE))
+$(call add_json_list, BoardAvbSystemAddHashtreeFooterArgs, $(BOARD_AVB_SYSTEM_ADD_HASHTREE_FOOTER_ARGS))
+$(call add_json_bool, BoardAvbEnable, $(filter true,$(BOARD_AVB_ENABLE)))
+
 $(call json_end)
 
 $(file >$(SOONG_VARIABLES).tmp,$(json_contents))
@@ -356,4 +377,6 @@ $(shell if ! cmp -s $(SOONG_VARIABLES).tmp $(SOONG_VARIABLES); then \
 	  rm $(SOONG_VARIABLES).tmp; \
 	fi)
 
+include $(BUILD_SYSTEM)/soong_extra_config.mk
+
 endif # CONFIGURE_SOONG
diff --git a/core/soong_extra_config.mk b/core/soong_extra_config.mk
new file mode 100644
index 0000000000..00b5c0fd63
--- /dev/null
+++ b/core/soong_extra_config.mk
@@ -0,0 +1,106 @@
+$(call json_start)
+
+$(call add_json_str, DeviceCpuVariantRuntime,           $(TARGET_CPU_VARIANT_RUNTIME))
+$(call add_json_str, DeviceAbiList,                     $(TARGET_CPU_ABI_LIST))
+$(call add_json_str, DeviceAbiList32,                   $(TARGET_CPU_ABI_LIST_32_BIT))
+$(call add_json_str, DeviceAbiList64,                   $(TARGET_CPU_ABI_LIST_64_BIT))
+$(call add_json_str, DeviceSecondaryCpuVariantRuntime,  $(TARGET_2ND_CPU_VARIANT_RUNTIME))
+
+$(call add_json_str, Dex2oatTargetCpuVariantRuntime,         $(DEX2OAT_TARGET_CPU_VARIANT_RUNTIME))
+$(call add_json_str, Dex2oatTargetInstructionSetFeatures,    $(DEX2OAT_TARGET_INSTRUCTION_SET_FEATURES))
+$(call add_json_str, SecondaryDex2oatCpuVariantRuntime,      $($(TARGET_2ND_ARCH_VAR_PREFIX)DEX2OAT_TARGET_CPU_VARIANT_RUNTIME))
+$(call add_json_str, SecondaryDex2oatInstructionSetFeatures, $($(TARGET_2ND_ARCH_VAR_PREFIX)DEX2OAT_TARGET_INSTRUCTION_SET_FEATURES))
+
+$(call add_json_str, BoardPlatform,          $(TARGET_BOARD_PLATFORM))
+$(call add_json_str, BoardShippingApiLevel,  $(BOARD_SHIPPING_API_LEVEL))
+$(call add_json_str, ShippingApiLevel,       $(PRODUCT_SHIPPING_API_LEVEL))
+$(call add_json_str, ShippingVendorApiLevel, $(PRODUCT_SHIPPING_VENDOR_API_LEVEL))
+
+$(call add_json_str, ProductModel,                      $(PRODUCT_MODEL))
+$(call add_json_str, ProductModelForAttestation,        $(PRODUCT_MODEL_FOR_ATTESTATION))
+$(call add_json_str, ProductBrandForAttestation,        $(PRODUCT_BRAND_FOR_ATTESTATION))
+$(call add_json_str, ProductNameForAttestation,         $(PRODUCT_NAME_FOR_ATTESTATION))
+$(call add_json_str, ProductDeviceForAttestation,       $(PRODUCT_DEVICE_FOR_ATTESTATION))
+$(call add_json_str, ProductManufacturerForAttestation, $(PRODUCT_MANUFACTURER_FOR_ATTESTATION))
+
+$(call add_json_str, SystemBrand, $(PRODUCT_SYSTEM_BRAND))
+$(call add_json_str, SystemDevice, $(PRODUCT_SYSTEM_DEVICE))
+$(call add_json_str, SystemManufacturer, $(PRODUCT_SYSTEM_MANUFACTURER))
+$(call add_json_str, SystemModel, $(PRODUCT_SYSTEM_MODEL))
+$(call add_json_str, SystemName, $(PRODUCT_SYSTEM_NAME))
+
+# Collapses ?= and = operators for system property variables. Also removes double quotes to prevent
+# malformed JSON. This change aligns with the existing behavior of sysprop.mk, which passes property
+# variables to the echo command, effectively discarding surrounding double quotes.
+define collapse-prop-pairs
+$(subst ",,$(call collapse-pairs,$(call collapse-pairs,$$($(1)),?=),=))
+endef
+
+$(call add_json_list, PRODUCT_SYSTEM_PROPERTIES,         $(call collapse-prop-pairs,PRODUCT_SYSTEM_PROPERTIES))
+$(call add_json_list, PRODUCT_SYSTEM_DEFAULT_PROPERTIES, $(call collapse-prop-pairs,PRODUCT_SYSTEM_DEFAULT_PROPERTIES))
+$(call add_json_list, PRODUCT_SYSTEM_EXT_PROPERTIES,     $(call collapse-prop-pairs,PRODUCT_SYSTEM_EXT_PROPERTIES))
+$(call add_json_list, PRODUCT_VENDOR_PROPERTIES,         $(call collapse-prop-pairs,PRODUCT_VENDOR_PROPERTIES))
+$(call add_json_list, PRODUCT_PRODUCT_PROPERTIES,        $(call collapse-prop-pairs,PRODUCT_PRODUCT_PROPERTIES))
+$(call add_json_list, PRODUCT_ODM_PROPERTIES,            $(call collapse-prop-pairs,PRODUCT_ODM_PROPERTIES))
+$(call add_json_list, PRODUCT_PROPERTY_OVERRIDES,        $(call collapse-prop-pairs,PRODUCT_PROPERTY_OVERRIDES))
+
+$(call add_json_str, BootloaderBoardName, $(TARGET_BOOTLOADER_BOARD_NAME))
+
+$(call add_json_bool, SdkBuild, $(filter sdk sdk_addon,$(MAKECMDGOALS)))
+
+$(call add_json_str, SystemServerCompilerFilter, $(PRODUCT_SYSTEM_SERVER_COMPILER_FILTER))
+
+$(call add_json_bool, Product16KDeveloperOption, $(filter true,$(PRODUCT_16K_DEVELOPER_OPTION)))
+
+$(call add_json_str, RecoveryDefaultRotation, $(TARGET_RECOVERY_DEFAULT_ROTATION))
+$(call add_json_str, RecoveryOverscanPercent, $(TARGET_RECOVERY_OVERSCAN_PERCENT))
+$(call add_json_str, RecoveryPixelFormat, $(TARGET_RECOVERY_PIXEL_FORMAT))
+
+ifdef AB_OTA_UPDATER
+$(call add_json_bool, AbOtaUpdater, $(filter true,$(AB_OTA_UPDATER)))
+$(call add_json_str, AbOtaPartitions, $(subst $(space),$(comma),$(sort $(AB_OTA_PARTITIONS))))
+endif
+
+ifdef PRODUCT_USE_DYNAMIC_PARTITIONS
+$(call add_json_bool, UseDynamicPartitions, $(filter true,$(PRODUCT_USE_DYNAMIC_PARTITIONS)))
+endif
+
+ifdef PRODUCT_RETROFIT_DYNAMIC_PARTITIONS
+$(call add_json_bool, RetrofitDynamicPartitions, $(filter true,$(PRODUCT_RETROFIT_DYNAMIC_PARTITIONS)))
+endif
+
+$(call add_json_bool, DontUseVabcOta, $(filter true,$(BOARD_DONT_USE_VABC_OTA)))
+
+$(call add_json_bool, FullTreble, $(filter true,$(PRODUCT_FULL_TREBLE)))
+
+$(call add_json_bool, NoBionicPageSizeMacro, $(filter true,$(PRODUCT_NO_BIONIC_PAGE_SIZE_MACRO)))
+
+$(call add_json_bool, PropertySplitEnabled, $(filter true,$(BOARD_PROPERTY_OVERRIDES_SPLIT_ENABLED)))
+
+$(call add_json_str, ScreenDensity, $(TARGET_SCREEN_DENSITY))
+
+$(call add_json_bool, UsesVulkan, $(filter true,$(TARGET_USES_VULKAN)))
+
+$(call add_json_bool, ZygoteForce64, $(filter true,$(ZYGOTE_FORCE_64)))
+
+$(call add_json_str, VendorSecurityPatch,       $(VENDOR_SECURITY_PATCH))
+$(call add_json_str, VendorImageFileSystemType, $(BOARD_VENDORIMAGE_FILE_SYSTEM_TYPE))
+
+$(call add_json_list, BuildVersionTags, $(BUILD_VERSION_TAGS))
+
+$(call add_json_bool, ProductNotDebuggableInUserdebug, $(PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG))
+
+$(call add_json_bool, UsesProductImage, $(filter true,$(BOARD_USES_PRODUCTIMAGE)))
+
+$(call add_json_bool, TargetBoots16K, $(filter true,$(TARGET_BOOTS_16K)))
+
+$(call json_end)
+
+$(shell mkdir -p $(dir $(SOONG_EXTRA_VARIABLES)))
+$(file >$(SOONG_EXTRA_VARIABLES).tmp,$(json_contents))
+
+$(shell if ! cmp -s $(SOONG_EXTRA_VARIABLES).tmp $(SOONG_EXTRA_VARIABLES); then \
+	  mv $(SOONG_EXTRA_VARIABLES).tmp $(SOONG_EXTRA_VARIABLES); \
+	else \
+	  rm $(SOONG_EXTRA_VARIABLES).tmp; \
+	fi)
diff --git a/core/soong_java_prebuilt.mk b/core/soong_java_prebuilt.mk
index 7f85231543..8c3882f364 100644
--- a/core/soong_java_prebuilt.mk
+++ b/core/soong_java_prebuilt.mk
@@ -21,19 +21,6 @@ full_classes_pre_proguard_jar := $(intermediates.COMMON)/classes-pre-proguard.ja
 full_classes_header_jar := $(intermediates.COMMON)/classes-header.jar
 common_javalib.jar := $(intermediates.COMMON)/javalib.jar
 
-ifdef LOCAL_SOONG_AAR
-  LOCAL_ADDITIONAL_CHECKED_MODULE += $(LOCAL_SOONG_AAR)
-endif
-
-# Use the Soong output as the checkbuild target instead of LOCAL_BUILT_MODULE
-# to avoid checkbuilds making an extra copy of every module.
-LOCAL_CHECKED_MODULE := $(LOCAL_PREBUILT_MODULE_FILE)
-LOCAL_ADDITIONAL_CHECKED_MODULE += $(LOCAL_SOONG_HEADER_JAR)
-LOCAL_ADDITIONAL_CHECKED_MODULE += $(LOCAL_FULL_MANIFEST_FILE)
-LOCAL_ADDITIONAL_CHECKED_MODULE += $(LOCAL_SOONG_DEXPREOPT_CONFIG)
-LOCAL_ADDITIONAL_CHECKED_MODULE += $(LOCAL_SOONG_RESOURCE_EXPORT_PACKAGE)
-LOCAL_ADDITIONAL_CHECKED_MODULE += $(LOCAL_SOONG_DEX_JAR)
-
 #######################################
 include $(BUILD_SYSTEM)/base_rules.mk
 #######################################
@@ -115,16 +102,14 @@ ifdef LOCAL_SOONG_DEX_JAR
     boot_jars := $(foreach pair,$(PRODUCT_BOOT_JARS), $(call word-colon,2,$(pair)))
     ifneq ($(filter $(LOCAL_MODULE),$(boot_jars)),) # is_boot_jar
       ifeq (true,$(WITH_DEXPREOPT))
-        # $(DEFAULT_DEX_PREOPT_INSTALLED_IMAGE_MODULE) contains modules that installs
-        # all of bootjars' dexpreopt files (.art, .oat, .vdex, ...)
+        # dex_bootjars singleton installs all of bootjars' dexpreopt files (.art, .oat, .vdex, ...)
+        # This includes both the primary and secondary arches.
         # Add them to the required list so they are installed alongside this module.
-        ALL_MODULES.$(my_register_name).REQUIRED_FROM_TARGET += \
-          $(DEFAULT_DEX_PREOPT_INSTALLED_IMAGE_MODULE) \
-          $(2ND_DEFAULT_DEX_PREOPT_INSTALLED_IMAGE_MODULE)
+        ALL_MODULES.$(my_register_name).REQUIRED_FROM_TARGET += dex_bootjars
         # Copy $(LOCAL_BUILT_MODULE) and its dependencies when installing boot.art
         # so that dependencies of $(LOCAL_BUILT_MODULE) (which may include
         # jacoco-report-classes.jar) are copied for every build.
-        $(foreach m,$(DEFAULT_DEX_PREOPT_INSTALLED_IMAGE_MODULE) $(2ND_DEFAULT_DEX_PREOPT_INSTALLED_IMAGE_MODULE), \
+        $(foreach m,dex_bootjars, \
           $(eval $(call add-dependency,$(firstword $(call module-installed-files,$(m))),$(LOCAL_BUILT_MODULE))) \
         )
       endif
diff --git a/core/static_java_library.mk b/core/static_java_library.mk
index 4a72a1fc31..dd1d8b5280 100644
--- a/core/static_java_library.mk
+++ b/core/static_java_library.mk
@@ -229,3 +229,5 @@ endif  # need_compile_res
 aar_classes_jar :=
 all_res_assets :=
 LOCAL_IS_STATIC_JAVA_LIBRARY :=
+
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=STATIC_JAVA_LIBRARY))
\ No newline at end of file
diff --git a/core/static_library_internal.mk b/core/static_library_internal.mk
index 039246098f..844360e52d 100644
--- a/core/static_library_internal.mk
+++ b/core/static_library_internal.mk
@@ -41,3 +41,5 @@ $(intermediates)/$(GCNO_ARCHIVE) : PRIVATE_ALL_WHOLE_STATIC_LIBRARIES := $(strip
 $(intermediates)/$(GCNO_ARCHIVE) : $(LOCAL_GCNO_FILES) $(built_whole_gcno_libraries)
 	$(package-coverage-files)
 endif
+
+$(if $(my_register_name),$(eval ALL_MODULES.$(my_register_name).MAKE_MODULE_TYPE:=STATIC_LIBRARY))
\ No newline at end of file
diff --git a/core/sysprop.mk b/core/sysprop.mk
index 47d8a41a38..dc6f2c4ac6 100644
--- a/core/sysprop.mk
+++ b/core/sysprop.mk
@@ -33,34 +33,26 @@ define generate-common-build-props
     echo "# from generate-common-build-props" >> $(2);\
     echo "# These properties identify this partition image." >> $(2);\
     echo "####################################" >> $(2);\
-    $(if $(filter system,$(1)),\
-        echo "ro.product.$(1).brand=$(PRODUCT_SYSTEM_BRAND)" >> $(2);\
-        echo "ro.product.$(1).device=$(PRODUCT_SYSTEM_DEVICE)" >> $(2);\
-        echo "ro.product.$(1).manufacturer=$(PRODUCT_SYSTEM_MANUFACTURER)" >> $(2);\
-        echo "ro.product.$(1).model=$(PRODUCT_SYSTEM_MODEL)" >> $(2);\
-        echo "ro.product.$(1).name=$(PRODUCT_SYSTEM_NAME)" >> $(2);\
-      ,\
-        echo "ro.product.$(1).brand=$(PRODUCT_BRAND)" >> $(2);\
-        echo "ro.product.$(1).device=$(TARGET_DEVICE)" >> $(2);\
-        echo "ro.product.$(1).manufacturer=$(PRODUCT_MANUFACTURER)" >> $(2);\
-        echo "ro.product.$(1).model=$(PRODUCT_MODEL)" >> $(2);\
-        echo "ro.product.$(1).name=$(TARGET_PRODUCT)" >> $(2);\
-        if [ -n "$(strip $(PRODUCT_MODEL_FOR_ATTESTATION))" ]; then \
-            echo "ro.product.model_for_attestation=$(PRODUCT_MODEL_FOR_ATTESTATION)" >> $(2);\
-        fi; \
-        if [ -n "$(strip $(PRODUCT_BRAND_FOR_ATTESTATION))" ]; then \
-            echo "ro.product.brand_for_attestation=$(PRODUCT_BRAND_FOR_ATTESTATION)" >> $(2);\
-        fi; \
-        if [ -n "$(strip $(PRODUCT_NAME_FOR_ATTESTATION))" ]; then \
-            echo "ro.product.name_for_attestation=$(PRODUCT_NAME_FOR_ATTESTATION)" >> $(2);\
-        fi; \
-        if [ -n "$(strip $(PRODUCT_DEVICE_FOR_ATTESTATION))" ]; then \
-            echo "ro.product.device_for_attestation=$(PRODUCT_DEVICE_FOR_ATTESTATION)" >> $(2);\
-        fi; \
-        if [ -n "$(strip $(PRODUCT_MANUFACTURER_FOR_ATTESTATION))" ]; then \
-            echo "ro.product.manufacturer_for_attestation=$(PRODUCT_MANUFACTURER_FOR_ATTESTATION)" >> $(2);\
-        fi; \
-    )\
+    echo "ro.product.$(1).brand=$(PRODUCT_BRAND)" >> $(2);\
+    echo "ro.product.$(1).device=$(TARGET_DEVICE)" >> $(2);\
+    echo "ro.product.$(1).manufacturer=$(PRODUCT_MANUFACTURER)" >> $(2);\
+    echo "ro.product.$(1).model=$(PRODUCT_MODEL)" >> $(2);\
+    echo "ro.product.$(1).name=$(TARGET_PRODUCT)" >> $(2);\
+    if [ -n "$(strip $(PRODUCT_MODEL_FOR_ATTESTATION))" ]; then \
+        echo "ro.product.model_for_attestation=$(PRODUCT_MODEL_FOR_ATTESTATION)" >> $(2);\
+    fi; \
+    if [ -n "$(strip $(PRODUCT_BRAND_FOR_ATTESTATION))" ]; then \
+        echo "ro.product.brand_for_attestation=$(PRODUCT_BRAND_FOR_ATTESTATION)" >> $(2);\
+    fi; \
+    if [ -n "$(strip $(PRODUCT_NAME_FOR_ATTESTATION))" ]; then \
+        echo "ro.product.name_for_attestation=$(PRODUCT_NAME_FOR_ATTESTATION)" >> $(2);\
+    fi; \
+    if [ -n "$(strip $(PRODUCT_DEVICE_FOR_ATTESTATION))" ]; then \
+        echo "ro.product.device_for_attestation=$(PRODUCT_DEVICE_FOR_ATTESTATION)" >> $(2);\
+    fi; \
+    if [ -n "$(strip $(PRODUCT_MANUFACTURER_FOR_ATTESTATION))" ]; then \
+        echo "ro.product.manufacturer_for_attestation=$(PRODUCT_MANUFACTURER_FOR_ATTESTATION)" >> $(2);\
+    fi; \
     $(if $(filter true,$(ZYGOTE_FORCE_64)),\
         $(if $(filter vendor,$(1)),\
             echo "ro.$(1).product.cpu.abilist=$(TARGET_CPU_ABI_LIST_64_BIT)" >> $(2);\
@@ -226,50 +218,11 @@ KNOWN_OEM_THUMBPRINT_PROPERTIES:=
 # -----------------------------------------------------------------
 # system/build.prop
 #
-# Note: parts of this file that can't be generated by the build-properties
-# macro are manually created as separate files and then fed into the macro
-
-buildinfo_prop := $(call intermediates-dir-for,ETC,buildinfo.prop)/buildinfo.prop
-
-ifdef TARGET_SYSTEM_PROP
-system_prop_file := $(TARGET_SYSTEM_PROP)
-else
-system_prop_file := $(wildcard $(TARGET_DEVICE_DIR)/system.prop)
-endif
-
-_prop_files_ := \
-  $(buildinfo_prop) \
-  $(system_prop_file)
-
-# Order matters here. When there are duplicates, the last one wins.
-# TODO(b/117892318): don't allow duplicates so that the ordering doesn't matter
-_prop_vars_ := \
-    ADDITIONAL_SYSTEM_PROPERTIES \
-    PRODUCT_SYSTEM_PROPERTIES
-
-# TODO(b/117892318): deprecate this
-_prop_vars_ += \
-    PRODUCT_SYSTEM_DEFAULT_PROPERTIES
-
-ifndef property_overrides_split_enabled
-_prop_vars_ += \
-    ADDITIONAL_VENDOR_PROPERTIES \
-    PRODUCT_VENDOR_PROPERTIES
-endif
+# system/build.prop is built by Soong. See system-build.prop module in
+# build/soong/Android.bp.
 
 INSTALLED_BUILD_PROP_TARGET := $(TARGET_OUT)/build.prop
 
-$(eval $(call build-properties,\
-    system,\
-    $(INSTALLED_BUILD_PROP_TARGET),\
-    $(_prop_files_),\
-    $(_prop_vars_),\
-    $(PRODUCT_SYSTEM_PROPERTY_BLACKLIST),\
-    $(empty),\
-    $(empty)))
-
-$(eval $(call declare-1p-target,$(INSTALLED_BUILD_PROP_TARGET)))
-
 # -----------------------------------------------------------------
 # vendor/build.prop
 #
@@ -313,83 +266,18 @@ $(eval $(call declare-1p-target,$(INSTALLED_VENDOR_BUILD_PROP_TARGET)))
 # -----------------------------------------------------------------
 # product/etc/build.prop
 #
-
-_prop_files_ := $(if $(TARGET_PRODUCT_PROP),\
-    $(TARGET_PRODUCT_PROP),\
-    $(wildcard $(TARGET_DEVICE_DIR)/product.prop))
-
-# Order matters here. When there are duplicates, the last one wins.
-# TODO(b/117892318): don't allow duplicates so that the ordering doesn't matter
-_prop_vars_ := \
-    ADDITIONAL_PRODUCT_PROPERTIES \
-    PRODUCT_PRODUCT_PROPERTIES
+# product/etc/build.prop is built by Soong. See product-build.prop module in
+# build/soong/Android.bp.
 
 INSTALLED_PRODUCT_BUILD_PROP_TARGET := $(TARGET_OUT_PRODUCT)/etc/build.prop
 
-ifdef PRODUCT_OEM_PROPERTIES
-import_oem_prop := $(call intermediates-dir-for,ETC,import_oem_prop)/oem.prop
-
-$(import_oem_prop):
-	$(hide) echo "####################################" >> $@; \
-	        echo "# PRODUCT_OEM_PROPERTIES" >> $@; \
-	        echo "####################################" >> $@;
-	$(hide) $(foreach prop,$(PRODUCT_OEM_PROPERTIES), \
-	    echo "import /oem/oem.prop $(prop)" >> $@;)
-
-_footers_ := $(import_oem_prop)
-else
-_footers_ :=
-endif
-
-# Skip common /product properties generation if device released before R and
-# has no product partition. This is the first part of the check.
-ifeq ($(call math_lt,$(if $(PRODUCT_SHIPPING_API_LEVEL),$(PRODUCT_SHIPPING_API_LEVEL),30),30), true)
-  _skip_common_properties := true
-endif
-
-# The second part of the check - always generate common properties for the
-# devices with product partition regardless of shipping level.
-ifneq ($(BOARD_USES_PRODUCTIMAGE),)
-  _skip_common_properties :=
-endif
-
-$(eval $(call build-properties,\
-    product,\
-    $(INSTALLED_PRODUCT_BUILD_PROP_TARGET),\
-    $(_prop_files_),\
-    $(_prop_vars_),\
-    $(empty),\
-    $(_footers_),\
-    $(_skip_common_properties)))
-
-$(eval $(call declare-1p-target,$(INSTALLED_PRODUCT_BUILD_PROP_TARGET)))
-
-_skip_common_properties :=
-
 # ----------------------------------------------------------------
 # odm/etc/build.prop
 #
-_prop_files_ := $(if $(TARGET_ODM_PROP),\
-    $(TARGET_ODM_PROP),\
-    $(wildcard $(TARGET_DEVICE_DIR)/odm.prop))
-
-# Order matters here. When there are duplicates, the last one wins.
-# TODO(b/117892318): don't allow duplicates so that the ordering doesn't matter
-_prop_vars_ := \
-    ADDITIONAL_ODM_PROPERTIES \
-    PRODUCT_ODM_PROPERTIES
+# odm/etc/build.prop is built by Soong. See odm-build.prop module in
+# build/soong/Android.bp.
 
 INSTALLED_ODM_BUILD_PROP_TARGET := $(TARGET_OUT_ODM)/etc/build.prop
-$(eval $(call build-properties,\
-    odm,\
-    $(INSTALLED_ODM_BUILD_PROP_TARGET),\
-    $(_prop_files_),\
-    $(_prop_vars_),\
-    $(empty),\
-    $(empty),\
-    $(empty)))
-
-$(eval $(call declare-1p-target,$(INSTALLED_ODM_BUILD_PROP_TARGET)))
 
 # ----------------------------------------------------------------
 # vendor_dlkm/etc/build.prop
@@ -442,25 +330,10 @@ $(eval $(call declare-1p-target,$(INSTALLED_SYSTEM_DLKM_BUILD_PROP_TARGET)))
 # -----------------------------------------------------------------
 # system_ext/etc/build.prop
 #
-_prop_files_ := $(if $(TARGET_SYSTEM_EXT_PROP),\
-    $(TARGET_SYSTEM_EXT_PROP),\
-    $(wildcard $(TARGET_DEVICE_DIR)/system_ext.prop))
-
-# Order matters here. When there are duplicates, the last one wins.
-# TODO(b/117892318): don't allow duplicates so that the ordering doesn't matter
-_prop_vars_ := PRODUCT_SYSTEM_EXT_PROPERTIES
+# system_ext/etc/build.prop is built by Soong. See system-build.prop module in
+# build/soong/Android.bp.
 
 INSTALLED_SYSTEM_EXT_BUILD_PROP_TARGET := $(TARGET_OUT_SYSTEM_EXT)/etc/build.prop
-$(eval $(call build-properties,\
-    system_ext,\
-    $(INSTALLED_SYSTEM_EXT_BUILD_PROP_TARGET),\
-    $(_prop_files_),\
-    $(_prop_vars_),\
-    $(empty),\
-    $(empty),\
-    $(empty)))
-
-$(eval $(call declare-1p-target,$(INSTALLED_SYSTEM_EXT_BUILD_PROP_TARGET)))
 
 # ----------------------------------------------------------------
 # ramdisk/boot/etc/build.prop
diff --git a/core/sysprop_config.mk b/core/sysprop_config.mk
index 6e3da721fd..69066117a3 100644
--- a/core/sysprop_config.mk
+++ b/core/sysprop_config.mk
@@ -15,57 +15,9 @@ $(foreach name, $(_additional_prop_var_names),\
 )
 _additional_prop_var_names :=
 
-#
-# -----------------------------------------------------------------
-# Add the product-defined properties to the build properties.
-ifneq ($(BOARD_PROPERTY_OVERRIDES_SPLIT_ENABLED), true)
-  ADDITIONAL_SYSTEM_PROPERTIES += $(PRODUCT_PROPERTY_OVERRIDES)
-else
-  ifndef BOARD_VENDORIMAGE_FILE_SYSTEM_TYPE
-    ADDITIONAL_SYSTEM_PROPERTIES += $(PRODUCT_PROPERTY_OVERRIDES)
-  endif
-endif
-
-ADDITIONAL_SYSTEM_PROPERTIES += ro.treble.enabled=${PRODUCT_FULL_TREBLE}
-
-# Set ro.llndk.api_level to show the maximum vendor API level that the LLNDK in
-# the system partition supports.
-ifdef RELEASE_BOARD_API_LEVEL
-ADDITIONAL_SYSTEM_PROPERTIES += ro.llndk.api_level=$(RELEASE_BOARD_API_LEVEL)
-endif
-
-# Sets ro.actionable_compatible_property.enabled to know on runtime whether the
-# allowed list of actionable compatible properties is enabled or not.
-ADDITIONAL_SYSTEM_PROPERTIES += ro.actionable_compatible_property.enabled=true
-
-# Add the system server compiler filter if they are specified for the product.
-ifneq (,$(PRODUCT_SYSTEM_SERVER_COMPILER_FILTER))
-ADDITIONAL_PRODUCT_PROPERTIES += dalvik.vm.systemservercompilerfilter=$(PRODUCT_SYSTEM_SERVER_COMPILER_FILTER)
-endif
-
-# Add the 16K developer option if it is defined for the product.
-ifeq ($(PRODUCT_16K_DEVELOPER_OPTION),true)
-ADDITIONAL_PRODUCT_PROPERTIES += ro.product.build.16k_page.enabled=true
-else
-ADDITIONAL_PRODUCT_PROPERTIES += ro.product.build.16k_page.enabled=false
-endif
-
-# Enable core platform API violation warnings on userdebug and eng builds.
-ifneq ($(TARGET_BUILD_VARIANT),user)
-ADDITIONAL_SYSTEM_PROPERTIES += persist.debug.dalvik.vm.core_platform_api_policy=just-warn
-endif
-
-# Define ro.sanitize.<name> properties for all global sanitizers.
-ADDITIONAL_SYSTEM_PROPERTIES += $(foreach s,$(SANITIZE_TARGET),ro.sanitize.$(s)=true)
-
-# Sets the default value of ro.postinstall.fstab.prefix to /system.
-# Device board config should override the value to /product when needed by:
-#
-#     PRODUCT_PRODUCT_PROPERTIES += ro.postinstall.fstab.prefix=/product
-#
-# It then uses ${ro.postinstall.fstab.prefix}/etc/fstab.postinstall to
-# mount system_other partition.
-ADDITIONAL_SYSTEM_PROPERTIES += ro.postinstall.fstab.prefix=/system
+$(KATI_obsolete_var ADDITIONAL_SYSTEM_PROPERTIES,Use build/soong/scripts/gen_build_prop.py instead)
+$(KATI_obsolete_var ADDITIONAL_ODM_PROPERTIES,Use build/soong/scripts/gen_build_prop.py instead)
+$(KATI_obsolete_var ADDITIONAL_PRODUCT_PROPERTIES,Use build/soong/scripts/gen_build_prop.py instead)
 
 # Add cpu properties for bionic and ART.
 ADDITIONAL_VENDOR_PROPERTIES += ro.bionic.arch=$(TARGET_ARCH)
@@ -178,118 +130,16 @@ ADDITIONAL_VENDOR_PROPERTIES += \
     ro.build.ab_update=$(AB_OTA_UPDATER)
 endif
 
-ADDITIONAL_PRODUCT_PROPERTIES += ro.build.characteristics=$(TARGET_AAPT_CHARACTERISTICS)
-
 ifeq ($(AB_OTA_UPDATER),true)
-ADDITIONAL_PRODUCT_PROPERTIES += ro.product.ab_ota_partitions=$(subst $(space),$(comma),$(sort $(AB_OTA_PARTITIONS)))
 ADDITIONAL_VENDOR_PROPERTIES += ro.vendor.build.ab_ota_partitions=$(subst $(space),$(comma),$(sort $(AB_OTA_PARTITIONS)))
 endif
 
-# Set this property for VTS to skip large page size tests on unsupported devices.
-ADDITIONAL_PRODUCT_PROPERTIES += \
-    ro.product.cpu.pagesize.max=$(TARGET_MAX_PAGE_SIZE_SUPPORTED)
-
-ifeq ($(PRODUCT_NO_BIONIC_PAGE_SIZE_MACRO),true)
-ADDITIONAL_PRODUCT_PROPERTIES += ro.product.build.no_bionic_page_size_macro=true
-endif
-
 user_variant := $(filter user userdebug,$(TARGET_BUILD_VARIANT))
-enable_target_debugging := true
-enable_dalvik_lock_contention_logging := true
-ifneq (,$(user_variant))
-  # Target is secure in user builds.
-  ADDITIONAL_SYSTEM_PROPERTIES += ro.secure=1
-  ADDITIONAL_SYSTEM_PROPERTIES += security.perf_harden=1
-
-  ifeq ($(user_variant),user)
-    ADDITIONAL_SYSTEM_PROPERTIES += ro.adb.secure=1
-  endif
-
-  ifneq ($(user_variant),userdebug)
-    # Disable debugging in plain user builds.
-    enable_target_debugging :=
-    enable_dalvik_lock_contention_logging :=
-  else
-    # Disable debugging in userdebug builds if PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG
-    # is set.
-    ifneq (,$(strip $(PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG)))
-      enable_target_debugging :=
-    endif
-  endif
-
-  # Disallow mock locations by default for user builds
-  ADDITIONAL_SYSTEM_PROPERTIES += ro.allow.mock.location=0
-
-else # !user_variant
-  # Turn on checkjni for non-user builds.
-  ADDITIONAL_SYSTEM_PROPERTIES += ro.kernel.android.checkjni=1
-  # Set device insecure for non-user builds.
-  ADDITIONAL_SYSTEM_PROPERTIES += ro.secure=0
-  # Allow mock locations by default for non user builds
-  ADDITIONAL_SYSTEM_PROPERTIES += ro.allow.mock.location=1
-endif # !user_variant
-
-ifeq (true,$(strip $(enable_dalvik_lock_contention_logging)))
-  # Enable Dalvik lock contention logging.
-  ADDITIONAL_SYSTEM_PROPERTIES += dalvik.vm.lockprof.threshold=500
-endif # !enable_dalvik_lock_contention_logging
-
-ifeq (true,$(strip $(enable_target_debugging)))
-  # Target is more debuggable and adbd is on by default
-  ADDITIONAL_SYSTEM_PROPERTIES += ro.debuggable=1
-else # !enable_target_debugging
-  # Target is less debuggable and adbd is off by default
-  ADDITIONAL_SYSTEM_PROPERTIES += ro.debuggable=0
-endif # !enable_target_debugging
-
-enable_target_debugging:=
-enable_dalvik_lock_contention_logging:=
-
-ifneq ($(filter sdk sdk_addon,$(MAKECMDGOALS)),)
-_is_sdk_build := true
-endif
-
-ifeq ($(TARGET_BUILD_VARIANT),eng)
-ifneq ($(filter ro.setupwizard.mode=ENABLED, $(call collapse-pairs, $(ADDITIONAL_SYSTEM_PROPERTIES))),)
-  # Don't require the setup wizard on eng builds
-  ADDITIONAL_SYSTEM_PROPERTIES := $(filter-out ro.setupwizard.mode=%,\
-          $(call collapse-pairs, $(ADDITIONAL_SYSTEM_PROPERTIES))) \
-          ro.setupwizard.mode=OPTIONAL
-endif
-ifndef _is_sdk_build
-  # To speedup startup of non-preopted builds, don't verify or compile the boot image.
-  ADDITIONAL_SYSTEM_PROPERTIES += dalvik.vm.image-dex2oat-filter=extract
-endif
-# b/323566535
-ADDITIONAL_SYSTEM_PROPERTIES += init.svc_debug.no_fatal.zygote=true
-endif
-
-ifdef _is_sdk_build
-ADDITIONAL_SYSTEM_PROPERTIES += xmpp.auto-presence=true
-ADDITIONAL_SYSTEM_PROPERTIES += ro.config.nocheckin=yes
-endif
-
-_is_sdk_build :=
-
-ADDITIONAL_SYSTEM_PROPERTIES += net.bt.name=Android
-
-# This property is set by flashing debug boot image, so default to false.
-ADDITIONAL_SYSTEM_PROPERTIES += ro.force.debuggable=0
 
 config_enable_uffd_gc := \
   $(firstword $(OVERRIDE_ENABLE_UFFD_GC) $(PRODUCT_ENABLE_UFFD_GC) default)
 
-# This is a temporary system property that controls the ART module. The plan is
-# to remove it by Aug 2025, at which time Mainline updates of the ART module
-# will ignore it as well.
-# If the value is "default", it will be mangled by post_process_props.py.
-ADDITIONAL_PRODUCT_PROPERTIES += ro.dalvik.vm.enable_uffd_gc=$(config_enable_uffd_gc)
-
-ADDITIONAL_SYSTEM_PROPERTIES := $(strip $(ADDITIONAL_SYSTEM_PROPERTIES))
-ADDITIONAL_PRODUCT_PROPERTIES := $(strip $(ADDITIONAL_PRODUCT_PROPERTIES))
 ADDITIONAL_VENDOR_PROPERTIES := $(strip $(ADDITIONAL_VENDOR_PROPERTIES))
 
 .KATI_READONLY += \
-    ADDITIONAL_SYSTEM_PROPERTIES \
-    ADDITIONAL_PRODUCT_PROPERTIES \
     ADDITIONAL_VENDOR_PROPERTIES
diff --git a/core/tasks/art-host-tests.mk b/core/tasks/art-host-tests.mk
index c95f6e7878..eb54faeffe 100644
--- a/core/tasks/art-host-tests.mk
+++ b/core/tasks/art-host-tests.mk
@@ -47,21 +47,16 @@ $(art_host_tests_zip) : $(COMPATIBILITY.art-host-tests.FILES) $(my_host_shared_l
 	$(hide) for shared_lib in $(PRIVATE_HOST_SHARED_LIBS); do \
 	  echo $$shared_lib >> $(PRIVATE_INTERMEDIATES_DIR)/shared-libs.list; \
 	done
-	grep $(TARGET_OUT_TESTCASES) $(PRIVATE_INTERMEDIATES_DIR)/list > $(PRIVATE_INTERMEDIATES_DIR)/target.list || true
 	$(hide) $(SOONG_ZIP) -d -o $@ -P host -C $(HOST_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/host.list \
-	  -P target -C $(PRODUCT_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/target.list \
 	  -P host/testcases -C $(HOST_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/shared-libs.list \
 	  -sha256
 	grep -e .*\\.config$$ $(PRIVATE_INTERMEDIATES_DIR)/host.list > $(PRIVATE_INTERMEDIATES_DIR)/host-test-configs.list || true
-	grep -e .*\\.config$$ $(PRIVATE_INTERMEDIATES_DIR)/target.list > $(PRIVATE_INTERMEDIATES_DIR)/target-test-configs.list || true
 	$(hide) $(SOONG_ZIP) -d -o $(PRIVATE_art_host_tests_configs_zip) \
-	  -P host -C $(HOST_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/host-test-configs.list \
-	  -P target -C $(PRODUCT_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/target-test-configs.list
+	  -P host -C $(HOST_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/host-test-configs.list
 	grep $(HOST_OUT) $(PRIVATE_INTERMEDIATES_DIR)/shared-libs.list > $(PRIVATE_INTERMEDIATES_DIR)/host-shared-libs.list || true
 	$(hide) $(SOONG_ZIP) -d -o $(PRIVATE_art_host_tests_host_shared_libs_zip) \
 	  -P host -C $(HOST_OUT) -l $(PRIVATE_INTERMEDIATES_DIR)/host-shared-libs.list
 	grep -e .*\\.config$$ $(PRIVATE_INTERMEDIATES_DIR)/host.list | sed s%$(HOST_OUT)%host%g > $(PRIVATE_INTERMEDIATES_DIR)/art-host-tests_list
-	grep -e .*\\.config$$ $(PRIVATE_INTERMEDIATES_DIR)/target.list | sed s%$(PRODUCT_OUT)%target%g >> $(PRIVATE_INTERMEDIATES_DIR)/art-host-tests_list
 	$(hide) $(SOONG_ZIP) -d -o $(PRIVATE_art_host_tests_list_zip) -C $(PRIVATE_INTERMEDIATES_DIR) -f $(PRIVATE_INTERMEDIATES_DIR)/art-host-tests_list
 
 art-host-tests: $(art_host_tests_zip)
diff --git a/core/tasks/cts.mk b/core/tasks/cts.mk
index 2e2ea79035..294cb577e2 100644
--- a/core/tasks/cts.mk
+++ b/core/tasks/cts.mk
@@ -92,8 +92,16 @@ $(verifier-zip): $(SOONG_ANDROID_CTS_VERIFIER_ZIP)
 
 cts_api_coverage_exe := $(HOST_OUT_EXECUTABLES)/cts-api-coverage
 dexdeps_exe := $(HOST_OUT_EXECUTABLES)/dexdeps
+cts_api_map_exe := $(HOST_OUT_EXECUTABLES)/cts-api-map
 
 coverage_out := $(HOST_OUT)/cts-api-coverage
+api_map_out := $(HOST_OUT)/cts-api-map
+
+cts_jar_files := $(api_map_out)/api_map_files.txt
+$(cts_jar_files): PRIVATE_API_MAP_FILES := $(sort $(COMPATIBILITY.cts.API_MAP_FILES))
+$(cts_jar_files):
+	mkdir -p $(dir $@)
+	echo $(PRIVATE_API_MAP_FILES) > $@
 
 api_xml_description := $(TARGET_OUT_COMMON_INTERMEDIATES)/api.xml
 
@@ -116,6 +124,14 @@ cts-combined-xml-coverage-report := $(coverage_out)/combined-coverage.xml
 cts_api_coverage_dependencies := $(cts_api_coverage_exe) $(dexdeps_exe) $(api_xml_description) $(napi_xml_description)
 cts_system_api_coverage_dependencies := $(cts_api_coverage_exe) $(dexdeps_exe) $(system_api_xml_description)
 
+cts-api-xml-api-map-report := $(api_map_out)/api-map.xml
+cts-api-html-api-map-report := $(api_map_out)/api-map.html
+cts-system-api-xml-api-map-report := $(api_map_out)/system-api-map.xml
+cts-system-api-html-api-map-report := $(api_map_out)/system-api-map.html
+
+cts_system_api_map_dependencies := $(cts_api_map_exe) $(system_api_xml_description) $(cts_jar_files)
+cts_api_map_dependencies := $(cts_api_map_exe) $(api_xml_description) $(cts_jar_files)
+
 android_cts_zip := $(HOST_OUT)/cts/android-cts.zip
 cts_verifier_apk := $(call intermediates-dir-for,APPS,CtsVerifier)/package.apk
 
@@ -194,6 +210,48 @@ cts-combined-xml-coverage : $(cts-combined-xml-coverage-report)
 .PHONY: cts-coverage-report-all cts-api-coverage
 cts-coverage-report-all: cts-test-coverage cts-verifier-coverage cts-combined-coverage cts-combined-xml-coverage
 
+$(cts-system-api-xml-api-map-report): PRIVATE_CTS_API_MAP_EXE := $(cts_api_map_exe)
+$(cts-system-api-xml-api-map-report): PRIVATE_API_XML_DESC := $(system_api_xml_description)
+$(cts-system-api-xml-api-map-report): PRIVATE_JAR_FILES := $(cts_jar_files)
+$(cts-system-api-xml-api-map-report) : $(android_cts_zip) $(cts_system_api_map_dependencies) | $(ACP)
+	$(call generate-api-map-report-cts,"CTS System API MAP Report - XML",\
+			$(PRIVATE_JAR_FILES),xml)
+
+$(cts-system-api-html-api-map-report): PRIVATE_CTS_API_MAP_EXE := $(cts_api_map_exe)
+$(cts-system-api-html-api-map-report): PRIVATE_API_XML_DESC := $(system_api_xml_description)
+$(cts-system-api-html-api-map-report): PRIVATE_JAR_FILES := $(cts_jar_files)
+$(cts-system-api-html-api-map-report) : $(android_cts_zip) $(cts_system_api_map_dependencies) | $(ACP)
+	$(call generate-api-map-report-cts,"CTS System API MAP Report - HTML",\
+			$(PRIVATE_JAR_FILES),html)
+
+$(cts-api-xml-api-map-report): PRIVATE_CTS_API_MAP_EXE := $(cts_api_map_exe)
+$(cts-api-xml-api-map-report): PRIVATE_API_XML_DESC := $(api_xml_description)
+$(cts-api-xml-api-map-report): PRIVATE_JAR_FILES := $(cts_jar_files)
+$(cts-api-xml-api-map-report) : $(android_cts_zip) $(cts_api_map_dependencies) | $(ACP)
+	$(call generate-api-map-report-cts,"CTS API MAP Report - XML",\
+			$(PRIVATE_JAR_FILES),xml)
+
+$(cts-api-html-api-map-report): PRIVATE_CTS_API_MAP_EXE := $(cts_api_map_exe)
+$(cts-api-html-api-map-report): PRIVATE_API_XML_DESC := $(api_xml_description)
+$(cts-api-html-api-map-report): PRIVATE_JAR_FILES := $(cts_jar_files)
+$(cts-api-html-api-map-report) : $(android_cts_zip) $(cts_api_map_dependencies) | $(ACP)
+	$(call generate-api-map-report-cts,"CTS API MAP Report - HTML",\
+			$(PRIVATE_JAR_FILES),html)
+
+.PHONY: cts-system-api-xml-api-map
+cts-system-api-xml-api-map : $(cts-system-api-xml-api-map-report)
+
+.PHONY: cts-system-api-html-api-map
+cts-system-api-html-api-map : $(cts-system-api-html-api-map-report)
+
+.PHONY: cts-api-xml-api-map
+cts-api-xml-api-map : $(cts-api-xml-api-map-report)
+
+.PHONY: cts-api-html-api-map
+cts-api-html-api-map : $(cts-api-html-api-map-report)
+
+.PHONY: cts-api-map-all
+
 # Put the test coverage report in the dist dir if "cts-api-coverage" is among the build goals.
 $(call dist-for-goals, cts-api-coverage, $(cts-test-coverage-report):cts-test-coverage-report.html)
 $(call dist-for-goals, cts-api-coverage, $(cts-system-api-coverage-report):cts-system-api-coverage-report.html)
@@ -209,6 +267,17 @@ ALL_TARGETS.$(cts-verifier-coverage-report).META_LIC:=$(module_license_metadata)
 ALL_TARGETS.$(cts-combined-coverage-report).META_LIC:=$(module_license_metadata)
 ALL_TARGETS.$(cts-combined-xml-coverage-report).META_LIC:=$(module_license_metadata)
 
+# Put the test api map report in the dist dir if "cts-api-map-all" is among the build goals.
+$(call dist-for-goals, cts-api-map-all, $(cts-system-api-xml-api-map-report):cts-system-api-xml-api-map-report.xml)
+$(call dist-for-goals, cts-api-map-all, $(cts-system-api-html-api-map-report):cts-system-api-html-api-map-report.html)
+$(call dist-for-goals, cts-api-map-all, $(cts-api-xml-api-map-report):cts-api-xml-api-map-report.xml)
+$(call dist-for-goals, cts-api-map-all, $(cts-api-html-api-map-report):cts-api-html-api-map-report.html)
+
+ALL_TARGETS.$(cts-system-api-xml-api-map-report).META_LIC:=$(module_license_metadata)
+ALL_TARGETS.$(cts-system-api-html-api-map-report).META_LIC:=$(module_license_metadata)
+ALL_TARGETS.$(cts-api-xml-api-map-report).META_LIC:=$(module_license_metadata)
+ALL_TARGETS.$(cts-api-html-api-map-report).META_LIC:=$(module_license_metadata)
+
 # Arguments;
 #  1 - Name of the report printed out on the screen
 #  2 - List of apk files that will be scanned to generate the report
@@ -219,23 +288,42 @@ define generate-coverage-report-cts
 	@ echo $(1): file://$$(cd $(dir $@); pwd)/$(notdir $@)
 endef
 
+# Arguments;
+#  1 - Name of the report printed out on the screen
+#  2 - A file containing list of files that to be analyzed
+#  3 - Format of the report
+define generate-api-map-report-cts
+	$(hide) mkdir -p $(dir $@)
+	$(hide) $(PRIVATE_CTS_API_MAP_EXE) -j 8 -a $(PRIVATE_API_XML_DESC) -i $(2) -f $(3) -o $@
+	@ echo $(1): file://$$(cd $(dir $@); pwd)/$(notdir $@)
+endef
+
 # Reset temp vars
 cts_api_coverage_dependencies :=
 cts_system_api_coverage_dependencies :=
+cts_api_map_dependencies :=
+cts_system_api_map_dependencies :=
 cts-combined-coverage-report :=
 cts-combined-xml-coverage-report :=
 cts-verifier-coverage-report :=
 cts-test-coverage-report :=
 cts-system-api-coverage-report :=
 cts-system-api-xml-coverage-report :=
+cts-api-xml-api-map-report :=
+cts-api-html-api-map-report :=
+cts-system-api-xml-api-map-report :=
+cts-system-api-html-api-map-report :=
 api_xml_description :=
 api_text_description :=
 system_api_xml_description :=
 napi_xml_description :=
 napi_text_description :=
 coverage_out :=
+api_map_out :=
+cts_jar_files :=
 dexdeps_exe :=
 cts_api_coverage_exe :=
+cts_api_map_exe :=
 cts_verifier_apk :=
 android_cts_zip :=
 cts-dir :=
diff --git a/core/tasks/device-tests.mk b/core/tasks/device-tests.mk
index 5850c4ed73..6164c2e94b 100644
--- a/core/tasks/device-tests.mk
+++ b/core/tasks/device-tests.mk
@@ -14,6 +14,7 @@
 
 
 .PHONY: device-tests
+.PHONY: device-tests-host-shared-libs
 
 device-tests-zip := $(PRODUCT_OUT)/device-tests.zip
 # Create an artifact to include a list of test config files in device-tests.
@@ -23,37 +24,45 @@ device-tests-configs-zip := $(PRODUCT_OUT)/device-tests_configs.zip
 my_host_shared_lib_for_device_tests := $(call copy-many-files,$(COMPATIBILITY.device-tests.HOST_SHARED_LIBRARY.FILES))
 device_tests_host_shared_libs_zip := $(PRODUCT_OUT)/device-tests_host-shared-libs.zip
 
-$(device-tests-zip) : .KATI_IMPLICIT_OUTPUTS := $(device-tests-list-zip) $(device-tests-configs-zip) $(device_tests_host_shared_libs_zip)
+$(device-tests-zip) : .KATI_IMPLICIT_OUTPUTS := $(device-tests-list-zip) $(device-tests-configs-zip)
 $(device-tests-zip) : PRIVATE_device_tests_list := $(PRODUCT_OUT)/device-tests_list
 $(device-tests-zip) : PRIVATE_HOST_SHARED_LIBS := $(my_host_shared_lib_for_device_tests)
-$(device-tests-zip) : PRIVATE_device_host_shared_libs_zip := $(device_tests_host_shared_libs_zip)
 $(device-tests-zip) : $(COMPATIBILITY.device-tests.FILES) $(COMPATIBILITY.device-tests.SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES) $(my_host_shared_lib_for_device_tests) $(SOONG_ZIP)
-	rm -f $@-shared-libs.list
 	echo $(sort $(COMPATIBILITY.device-tests.FILES) $(COMPATIBILITY.device-tests.SOONG_INSTALLED_COMPATIBILITY_SUPPORT_FILES)) | tr " " "\n" > $@.list
 	grep $(HOST_OUT_TESTCASES) $@.list > $@-host.list || true
 	grep -e .*\\.config$$ $@-host.list > $@-host-test-configs.list || true
 	$(hide) for shared_lib in $(PRIVATE_HOST_SHARED_LIBS); do \
 	  echo $$shared_lib >> $@-host.list; \
-	  echo $$shared_lib >> $@-shared-libs.list; \
 	done
-	grep $(HOST_OUT_TESTCASES) $@-shared-libs.list > $@-host-shared-libs.list || true
 	grep $(TARGET_OUT_TESTCASES) $@.list > $@-target.list || true
 	grep -e .*\\.config$$ $@-target.list > $@-target-test-configs.list || true
 	$(hide) $(SOONG_ZIP) -d -o $@ -P host -C $(HOST_OUT) -l $@-host.list -P target -C $(PRODUCT_OUT) -l $@-target.list -sha256
 	$(hide) $(SOONG_ZIP) -d -o $(device-tests-configs-zip) \
 	  -P host -C $(HOST_OUT) -l $@-host-test-configs.list \
 	  -P target -C $(PRODUCT_OUT) -l $@-target-test-configs.list
-	$(SOONG_ZIP) -d -o $(PRIVATE_device_host_shared_libs_zip) \
-	  -P host -C $(HOST_OUT) -l $@-host-shared-libs.list
 	rm -f $(PRIVATE_device_tests_list)
 	$(hide) grep -e .*\\.config$$ $@-host.list | sed s%$(HOST_OUT)%host%g > $(PRIVATE_device_tests_list)
 	$(hide) grep -e .*\\.config$$ $@-target.list | sed s%$(PRODUCT_OUT)%target%g >> $(PRIVATE_device_tests_list)
 	$(hide) $(SOONG_ZIP) -d -o $(device-tests-list-zip) -C $(dir $@) -f $(PRIVATE_device_tests_list)
 	rm -f $@.list $@-host.list $@-target.list $@-host-test-configs.list $@-target-test-configs.list \
-	  $@-shared-libs.list $@-host-shared-libs.list $(PRIVATE_device_tests_list)
+		$(PRIVATE_device_tests_list)
+
+$(device_tests_host_shared_libs_zip) : PRIVATE_device_host_shared_libs_zip := $(device_tests_host_shared_libs_zip)
+$(device_tests_host_shared_libs_zip) : PRIVATE_HOST_SHARED_LIBS := $(my_host_shared_lib_for_device_tests)
+$(device_tests_host_shared_libs_zip) : $(my_host_shared_lib_for_device_tests) $(SOONG_ZIP)
+	rm -f $@-shared-libs.list
+	$(hide) for shared_lib in $(PRIVATE_HOST_SHARED_LIBS); do \
+	  echo $$shared_lib >> $@-shared-libs.list; \
+	done
+	grep $(HOST_OUT_TESTCASES) $@-shared-libs.list > $@-host-shared-libs.list || true
+	$(SOONG_ZIP) -d -o $(PRIVATE_device_host_shared_libs_zip) \
+	  -P host -C $(HOST_OUT) -l $@-host-shared-libs.list
 
 device-tests: $(device-tests-zip)
+device-tests-host-shared-libs: $(device_tests_host_shared_libs_zip)
+
 $(call dist-for-goals, device-tests, $(device-tests-zip) $(device-tests-list-zip) $(device-tests-configs-zip) $(device_tests_host_shared_libs_zip))
+$(call dist-for-goals, device-tests-host-shared-libs, $(device_tests_host_shared_libs_zip))
 
 $(call declare-1p-container,$(device-tests-zip),)
 $(call declare-container-license-deps,$(device-tests-zip),$(COMPATIBILITY.device-tests.FILES) $(my_host_shared_lib_for_device_tests),$(PRODUCT_OUT)/:/)
diff --git a/core/tasks/host-unit-tests.mk b/core/tasks/host-unit-tests.mk
index 733a2e258c..4cb23c02eb 100644
--- a/core/tasks/host-unit-tests.mk
+++ b/core/tasks/host-unit-tests.mk
@@ -29,15 +29,28 @@ my_host_shared_lib_for_host_unit_tests := $(foreach f,$(COMPATIBILITY.host-unit-
     $(eval _cmf_src := $(word 1,$(_cmf_tuple))) \
     $(_cmf_src)))
 
+my_symlinks_for_host_unit_tests := $(foreach f,$(COMPATIBILITY.host-unit-tests.SYMLINKS),\
+	$(strip $(eval _cmf_tuple := $(subst :, ,$(f))) \
+	$(eval _cmf_dep := $(word 1,$(_cmf_tuple))) \
+	$(eval _cmf_src := $(word 2,$(_cmf_tuple))) \
+	$(eval _cmf_dest := $(word 3,$(_cmf_tuple))) \
+	$(call symlink-file,$(_cmf_dep),$(_cmf_src),$(_cmf_dest)) \
+	$(_cmf_dest)))
+
 $(host_unit_tests_zip) : PRIVATE_HOST_SHARED_LIBS := $(my_host_shared_lib_for_host_unit_tests)
 
-$(host_unit_tests_zip) : $(COMPATIBILITY.host-unit-tests.FILES) $(my_host_shared_lib_for_host_unit_tests) $(SOONG_ZIP)
+$(host_unit_tests_zip) : PRIVATE_SYMLINKS := $(my_symlinks_for_host_unit_tests)
+
+$(host_unit_tests_zip) : $(COMPATIBILITY.host-unit-tests.FILES) $(my_host_shared_lib_for_host_unit_tests) $(my_symlinks_for_host_unit_tests) $(SOONG_ZIP)
 	echo $(sort $(COMPATIBILITY.host-unit-tests.FILES)) | tr " " "\n" > $@.list
 	grep $(HOST_OUT_TESTCASES) $@.list > $@-host.list || true
 	echo "" >> $@-host-libs.list
 	$(hide) for shared_lib in $(PRIVATE_HOST_SHARED_LIBS); do \
 	  echo $$shared_lib >> $@-host-libs.list; \
 	done
+	$(hide) for symlink in $(PRIVATE_SYMLINKS); do \
+	  echo $$symlink >> $@-host.list; \
+	done
 	grep $(TARGET_OUT_TESTCASES) $@.list > $@-target.list || true
 	$(hide) $(SOONG_ZIP) -d -o $@ -P host -C $(HOST_OUT) -l $@-host.list \
 	  -P target -C $(PRODUCT_OUT) -l $@-target.list \
diff --git a/core/tasks/mcts.mk b/core/tasks/mcts.mk
index 09a41915eb..02e916a38d 100644
--- a/core/tasks/mcts.mk
+++ b/core/tasks/mcts.mk
@@ -15,7 +15,8 @@
 ifneq ($(wildcard test/mts/README.md),)
 
 mcts_test_suites :=
-mcts_test_suites += mcts
+mcts_all_test_suites :=
+mcts_all_test_suites += mcts
 
 $(foreach module, $(mts_modules), $(eval mcts_test_suites += mcts-$(module)))
 
@@ -29,4 +30,14 @@ $(foreach suite, $(mcts_test_suites), \
 	$(eval $(call dist-for-goals, $(suite), $(compatibility_zip))) \
 )
 
+$(foreach suite, $(mcts_all_test_suites), \
+	$(eval test_suite_name := $(suite)) \
+	$(eval test_suite_tradefed := mcts-tradefed) \
+	$(eval test_suite_readme := test/mts/README.md) \
+	$(eval include $(BUILD_SYSTEM)/tasks/tools/compatibility.mk) \
+	$(eval .PHONY: $(suite)) \
+	$(eval $(suite): $(compatibility_zip)) \
+	$(eval $(call dist-for-goals, $(suite), $(compatibility_zip))) \
+)
+
 endif
diff --git a/core/tasks/meta-lic.mk b/core/tasks/meta-lic.mk
index a94a0162ba..620b1e29ae 100644
--- a/core/tasks/meta-lic.mk
+++ b/core/tasks/meta-lic.mk
@@ -83,6 +83,40 @@ $(eval $(call declare-copy-files-license-metadata,device/google/coral,display_19
 $(eval $(call declare-1p-copy-files,device/google/coral,audio_policy_configuration.xml))
 $(eval $(call declare-1p-copy-files,device/google/coral,display_19260504575090817.xml))
 
+# Moved here from device/google/cuttlefish/Android.mk
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,.idc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,default-permissions.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,libnfc-nci.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,fstab.postinstall,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,ueventd.rc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,wpa_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,hals.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,device_state_configuration.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,p2p_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,wpa_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,wpa_supplicant_overlay.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,wpa_supplicant.rc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,init.cutf_cvm.rc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,fstab.cf.f2fs.hctr2,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,fstab.cf.f2fs.cts,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,fstab.cf.ext4.hctr2,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,fstab.cf.ext4.cts,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,init.rc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,audio_policy.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
+
+$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish/shared/config,pci.ids,SPDX-license-identifier-BSD-3-Clause,notice,device/google/cuttlefish/shared/config/LICENSE_BSD,))
+
+$(eval $(call declare-1p-copy-files,device/google/cuttlefish,privapp-permissions-cuttlefish.xml))
+$(eval $(call declare-1p-copy-files,device/google/cuttlefish,media_profiles_V1_0.xml))
+$(eval $(call declare-1p-copy-files,device/google/cuttlefish,media_codecs_performance.xml))
+$(eval $(call declare-1p-copy-files,device/google/cuttlefish,cuttlefish_excluded_hardware.xml))
+$(eval $(call declare-1p-copy-files,device/google/cuttlefish,media_codecs.xml))
+$(eval $(call declare-1p-copy-files,device/google/cuttlefish,media_codecs_google_video.xml))
+$(eval $(call declare-1p-copy-files,device/google/cuttlefish,car_audio_configuration.xml))
+$(eval $(call declare-1p-copy-files,device/google/cuttlefish,audio_policy_configuration.xml))
+$(eval $(call declare-1p-copy-files,device/google/cuttlefish,preinstalled-packages-product-car-cuttlefish.xml))
+$(eval $(call declare-1p-copy-files,hardware/google/camera/devices,.json))
+
 # Moved here from device/google/gs101/Android.mk
 $(eval $(call declare-copy-files-license-metadata,device/google/gs101,default-permissions.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
 $(eval $(call declare-copy-files-license-metadata,device/google/gs101,libnfc-nci.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
@@ -185,3 +219,12 @@ $(eval $(call declare-1p-copy-files,device/generic/goldfish,device_state_configu
 $(eval $(call declare-1p-copy-files,device/generic/goldfish,init.ranchu-core.sh))
 $(eval $(call declare-1p-copy-files,device/generic/goldfish,init.ranchu-net.sh))
 $(eval $(call declare-1p-copy-files,device/generic/goldfish,audio_policy_configuration.xml))
+
+# Moved here from packages/services/Car/Android.mk
+$(eval $(call declare-1p-copy-files,packages/services/Car,))
+
+# Moved here from hardware/libhardware_legacy/Android.mk
+$(eval $(call declare-1p-copy-files,hardware/libhardware_legacy,))
+
+# Moved here from system/core/rootdir/Android.mk
+$(eval $(call declare-1p-copy-files,system/core/rootdir,))
diff --git a/core/tasks/mke2fs-dist.mk b/core/tasks/mke2fs-dist.mk
new file mode 100644
index 0000000000..3540c1f985
--- /dev/null
+++ b/core/tasks/mke2fs-dist.mk
@@ -0,0 +1,22 @@
+# Copyright (C) 2024 Google Inc.
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
+# TODO: After Soong's recovery partition variation can be set to selectable
+#       and the meta_lic file duplication issue is resolved, move it to the
+#       dist section of the corresponding module's Android.bp.
+my_dist_files := $(HOST_OUT_EXECUTABLES)/mke2fs
+my_dist_files += $(HOST_OUT_EXECUTABLES)/make_f2fs
+my_dist_files += $(HOST_OUT_EXECUTABLES)/make_f2fs_casefold
+$(call dist-for-goals,dist_files sdk,$(my_dist_files))
+my_dist_files :=
diff --git a/core/tasks/module-info.mk b/core/tasks/module-info.mk
index 75936685a4..0ca27d8222 100644
--- a/core/tasks/module-info.mk
+++ b/core/tasks/module-info.mk
@@ -13,7 +13,7 @@ define write-optional-json-bool
 $(if $(strip $(2)),'$(COMMA)$(strip $(1)): "$(strip $(2))"')
 endef
 
-SOONG_MODULE_INFO := $(SOONG_OUT_DIR)/module-info-$(TARGET_PRODUCT).json
+SOONG_MODULE_INFO := $(SOONG_OUT_DIR)/module-info-$(TARGET_PRODUCT)${COVERAGE_SUFFIX}.json
 
 $(MODULE_INFO_JSON): PRIVATE_SOONG_MODULE_INFO := $(SOONG_MODULE_INFO)
 $(MODULE_INFO_JSON): PRIVATE_MERGE_JSON_OBJECTS := $(HOST_OUT_EXECUTABLES)/merge_module_info_json
diff --git a/core/tasks/recovery_snapshot.mk b/core/tasks/recovery_snapshot.mk
deleted file mode 100644
index 525273bfc3..0000000000
--- a/core/tasks/recovery_snapshot.mk
+++ /dev/null
@@ -1,34 +0,0 @@
-# Copyright (C) 2020 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-current_makefile := $(lastword $(MAKEFILE_LIST))
-
-# RECOVERY_SNAPSHOT_VERSION must be set to 'current' in order to generate a recovery snapshot.
-ifeq ($(RECOVERY_SNAPSHOT_VERSION),current)
-
-.PHONY: recovery-snapshot
-recovery-snapshot: $(SOONG_RECOVERY_SNAPSHOT_ZIP)
-
-$(call dist-for-goals, recovery-snapshot, $(SOONG_RECOVERY_SNAPSHOT_ZIP))
-
-else # RECOVERY_SNAPSHOT_VERSION is NOT set to 'current'
-
-.PHONY: recovery-snapshot
-recovery-snapshot: PRIVATE_MAKEFILE := $(current_makefile)
-recovery-snapshot:
-	$(call echo-error,$(PRIVATE_MAKEFILE),\
-		"CANNOT generate Recovery snapshot. RECOVERY_SNAPSHOT_VERSION must be set to 'current'.")
-	exit 1
-
-endif # RECOVERY_SNAPSHOT_VERSION
diff --git a/core/tasks/sts-lite.mk b/core/tasks/sts-sdk.mk
similarity index 61%
rename from core/tasks/sts-lite.mk
rename to core/tasks/sts-sdk.mk
index 65c65c3dc6..4abbc29c5e 100644
--- a/core/tasks/sts-lite.mk
+++ b/core/tasks/sts-sdk.mk
@@ -13,26 +13,24 @@
 # limitations under the License.
 
 ifneq ($(wildcard test/sts/README-sts-sdk.md),)
-test_suite_name := sts-lite
+test_suite_name := sts-sdk
 test_suite_tradefed := sts-tradefed
 test_suite_readme := test/sts/README-sts-sdk.md
 sts_sdk_zip := $(HOST_OUT)/$(test_suite_name)/sts-sdk.zip
 
 include $(BUILD_SYSTEM)/tasks/tools/compatibility.mk
 
-sts_sdk_samples := $(call intermediates-dir-for,ETC,sts-sdk-samples.zip)/sts-sdk-samples.zip
+sts_sdk_plugin_skel := $(call intermediates-dir-for,ETC,sts-sdk-plugin-skel.zip)/sts-sdk-plugin-skel.zip
 
-$(sts_sdk_zip): STS_LITE_ZIP := $(compatibility_zip)
-$(sts_sdk_zip): STS_SDK_SAMPLES := $(sts_sdk_samples)
-$(sts_sdk_zip): $(MERGE_ZIPS) $(ZIP2ZIP) $(compatibility_zip) $(sts_sdk_samples)
-	rm -f $@ $(STS_LITE_ZIP)_filtered
-	$(ZIP2ZIP) -i $(STS_LITE_ZIP) -o $(STS_LITE_ZIP)_filtered \
-		-x android-sts-lite/tools/sts-tradefed-tests.jar \
-		'android-sts-lite/tools/*:sts-test/libs/' \
-		'android-sts-lite/testcases/*:sts-test/utils/' \
-		'android-sts-lite/jdk/**/*:sts-test/jdk/'
-	$(MERGE_ZIPS) $@ $(STS_LITE_ZIP)_filtered $(STS_SDK_SAMPLES)
-	rm -f $(STS_LITE_ZIP)_filtered
+$(sts_sdk_zip): STS_SDK_ZIP := $(compatibility_zip)
+$(sts_sdk_zip): STS_SDK_PLUGIN_SKEL := $(sts_sdk_plugin_skel)
+$(sts_sdk_zip): $(MERGE_ZIPS) $(ZIP2ZIP) $(compatibility_zip) $(sts_sdk_plugin_skel)
+	rm -f $@ $(STS_SDK_ZIP)_filtered
+	$(ZIP2ZIP) -i $(STS_SDK_ZIP) -o $(STS_SDK_ZIP)_filtered \
+		-x android-sts-sdk/tools/sts-tradefed-tests.jar \
+		'android-sts-sdk/tools/*:sts-sdk/src/main/resources/sts-tradefed-tools/'
+	$(MERGE_ZIPS) $@ $(STS_SDK_ZIP)_filtered $(STS_SDK_PLUGIN_SKEL)
+	rm -f $(STS_SDK_ZIP)_filtered
 
 .PHONY: sts-sdk
 sts-sdk: $(sts_sdk_zip)
diff --git a/core/tasks/tools/compatibility.mk b/core/tasks/tools/compatibility.mk
index 9189c2d58e..f205cea156 100644
--- a/core/tasks/tools/compatibility.mk
+++ b/core/tasks/tools/compatibility.mk
@@ -27,7 +27,6 @@
 #   compatibility_zip: the path to the output zip file.
 
 special_mts_test_suites :=
-special_mts_test_suites += mcts
 special_mts_test_suites += $(mts_modules)
 ifneq ($(filter $(special_mts_test_suites),$(patsubst mcts-%,%,$(test_suite_name))),)
 	test_suite_subdir := android-mts
diff --git a/core/tasks/tools/update_bootloader_radio_image.mk b/core/tasks/tools/update_bootloader_radio_image.mk
new file mode 100644
index 0000000000..0ebf247213
--- /dev/null
+++ b/core/tasks/tools/update_bootloader_radio_image.mk
@@ -0,0 +1,17 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http:#www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+ifeq ($(USES_DEVICE_GOOGLE_ZUMA),true)
+    -include vendor/google_devices/zuma/prebuilts/misc_bins/update_bootloader_radio_image.mk
+endif
diff --git a/core/tasks/tradefed-tests-list.mk b/core/tasks/tradefed-tests-list.mk
index 61bf13695d..47c360de52 100644
--- a/core/tasks/tradefed-tests-list.mk
+++ b/core/tasks/tradefed-tests-list.mk
@@ -15,6 +15,11 @@
 # List all TradeFed tests from COMPATIBILITY.tradefed_tests_dir
 .PHONY: tradefed-tests-list
 
+COMPATIBILITY.tradefed_tests_dir := \
+  $(COMPATIBILITY.tradefed_tests_dir) \
+  tools/tradefederation/core/res/config \
+  tools/tradefederation/core/javatests/res/config
+
 tradefed_tests :=
 $(foreach dir, $(COMPATIBILITY.tradefed_tests_dir), \
   $(eval tradefed_tests += $(shell find $(dir) -type f -name "*.xml")))
diff --git a/core/tasks/vendor_snapshot.mk b/core/tasks/vendor_snapshot.mk
deleted file mode 100644
index 83c13792a8..0000000000
--- a/core/tasks/vendor_snapshot.mk
+++ /dev/null
@@ -1,46 +0,0 @@
-# Copyright (C) 2020 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-current_makefile := $(lastword $(MAKEFILE_LIST))
-
-# BOARD_VNDK_VERSION must be set to 'current' in order to generate a vendor snapshot.
-ifeq ($(BOARD_VNDK_VERSION),current)
-
-.PHONY: vendor-snapshot
-vendor-snapshot: $(SOONG_VENDOR_SNAPSHOT_ZIP)
-
-$(call dist-for-goals, vendor-snapshot, $(SOONG_VENDOR_SNAPSHOT_ZIP))
-
-.PHONY: vendor-fake-snapshot
-vendor-fake-snapshot: $(SOONG_VENDOR_FAKE_SNAPSHOT_ZIP)
-
-$(call dist-for-goals, vendor-fake-snapshot, $(SOONG_VENDOR_FAKE_SNAPSHOT_ZIP):fake/$(notdir $(SOONG_VENDOR_FAKE_SNAPSHOT_ZIP)))
-
-else # BOARD_VNDK_VERSION is NOT set to 'current'
-
-.PHONY: vendor-snapshot
-vendor-snapshot: PRIVATE_MAKEFILE := $(current_makefile)
-vendor-snapshot:
-	$(call echo-error,$(PRIVATE_MAKEFILE),\
-		"CANNOT generate Vendor snapshot. BOARD_VNDK_VERSION must be set to 'current'.")
-	exit 1
-
-.PHONY: vendor-fake-snapshot
-vendor-fake-snapshot: PRIVATE_MAKEFILE := $(current_makefile)
-vendor-fake-snapshot:
-	$(call echo-error,$(PRIVATE_MAKEFILE),\
-		"CANNOT generate Vendor snapshot. BOARD_VNDK_VERSION must be set to 'current'.")
-	exit 1
-
-endif # BOARD_VNDK_VERSION
diff --git a/core/version_util.mk b/core/version_util.mk
index eb568becc4..0e346347bb 100644
--- a/core/version_util.mk
+++ b/core/version_util.mk
@@ -183,14 +183,17 @@ ifndef PLATFORM_SECURITY_PATCH_TIMESTAMP
 endif
 .KATI_READONLY := PLATFORM_SECURITY_PATCH_TIMESTAMP
 
-ifndef PLATFORM_BASE_OS
-  # Used to indicate the base os applied to the device.
-  # Can be an arbitrary string, but must be a single word.
-  #
-  # If there is no $PLATFORM_BASE_OS set, keep it empty.
-  PLATFORM_BASE_OS :=
-endif
-.KATI_READONLY := PLATFORM_BASE_OS
+# PLATFORM_BASE_OS is used to indicate the base os applied
+# to the device. Can be an arbitrary string, but must be a
+# single word.
+#
+# If there is no $PLATFORM_BASE_OS set, keep it empty.
+#
+# PLATFORM_BASE_OS can either be set via an enviornment
+# variable, or set via the PRODUCT_BASE_OS product variable.
+PLATFORM_BASE_OS_ENV_INPUT := $(PLATFORM_BASE_OS)
+.KATI_READONLY := PLATFORM_BASE_OS_ENV_INPUT
+PLATFORM_BASE_OS :=
 
 ifndef BUILD_ID
   # Used to signify special builds.  E.g., branches and/or releases,
diff --git a/target/board/Android.mk b/target/board/Android.mk
index decc345ded..8133af9a7f 100644
--- a/target/board/Android.mk
+++ b/target/board/Android.mk
@@ -67,7 +67,6 @@ $(GEN): PRIVATE_DEVICE_MANIFEST_FILE := $(DEVICE_MANIFEST_FILE)
 $(GEN): $(DEVICE_MANIFEST_FILE) $(HOST_OUT_EXECUTABLES)/assemble_vintf
 	BOARD_SEPOLICY_VERS=$(BOARD_SEPOLICY_VERS) \
 	PRODUCT_ENFORCE_VINTF_MANIFEST=$(PRODUCT_ENFORCE_VINTF_MANIFEST) \
-	PRODUCT_SHIPPING_API_LEVEL=$(PRODUCT_SHIPPING_API_LEVEL) \
 	$(HOST_OUT_EXECUTABLES)/assemble_vintf -o $@ \
 		-i $(call normalize-path-list,$(PRIVATE_DEVICE_MANIFEST_FILE))
 
@@ -99,7 +98,6 @@ $$(GEN): PRIVATE_SRC_FILES := $$(my_fragment_files)
 $$(GEN): $$(my_fragment_files) $$(HOST_OUT_EXECUTABLES)/assemble_vintf
 	BOARD_SEPOLICY_VERS=$$(BOARD_SEPOLICY_VERS) \
 	PRODUCT_ENFORCE_VINTF_MANIFEST=$$(PRODUCT_ENFORCE_VINTF_MANIFEST) \
-	PRODUCT_SHIPPING_API_LEVEL=$$(PRODUCT_SHIPPING_API_LEVEL) \
 	$$(HOST_OUT_EXECUTABLES)/assemble_vintf -o $$@ \
 		-i $$(call normalize-path-list,$$(PRIVATE_SRC_FILES))
 
diff --git a/target/product/aosp_arm64.mk b/target/product/aosp_arm64.mk
index 783ed3bcc0..7a9325dae3 100644
--- a/target/product/aosp_arm64.mk
+++ b/target/product/aosp_arm64.mk
@@ -58,9 +58,6 @@ $(call inherit-product, $(SRC_TARGET_DIR)/board/generic_arm64/device.mk)
 AB_OTA_UPDATER := true
 AB_OTA_PARTITIONS ?= system
 
-# Set widevine apex signed with dev key
-$(call soong_config_set,widevine,use_devkey,true)
-
 #
 # Special settings for GSI releasing
 #
diff --git a/target/product/aosp_x86_64.mk b/target/product/aosp_x86_64.mk
index e9ca482371..595940d9d1 100644
--- a/target/product/aosp_x86_64.mk
+++ b/target/product/aosp_x86_64.mk
@@ -60,9 +60,6 @@ $(call inherit-product, $(SRC_TARGET_DIR)/board/generic_x86_64/device.mk)
 AB_OTA_UPDATER := true
 AB_OTA_PARTITIONS ?= system
 
-# Set widevine apex signed with dev key
-$(call soong_config_set,widevine,use_devkey,true)
-
 #
 # Special settings for GSI releasing
 #
diff --git a/target/product/vboot.mk b/target/product/app_function_extensions.mk
similarity index 53%
rename from target/product/vboot.mk
rename to target/product/app_function_extensions.mk
index 48a4883b43..a61afdc5ab 100644
--- a/target/product/vboot.mk
+++ b/target/product/app_function_extensions.mk
@@ -1,5 +1,5 @@
 #
-# Copyright (C) 2015 The Android Open Source Project
+# Copyright (C) 2024 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -14,12 +14,9 @@
 # limitations under the License.
 #
 
-# Provides dependencies necessary for verified boot
+# The app function sidecar extensions
 
-PRODUCT_SUPPORTS_VBOOT := true
-
-# The dev key is used to sign boot and recovery images.
-# We expect this file to exist with the suffixes ".vbprivk" and ".vbpupk".
-# TODO: find a proper location for this
-PRODUCT_VBOOT_SIGNING_KEY := external/vboot_reference/tests/devkeys/kernel_data_key
-PRODUCT_VBOOT_SIGNING_SUBKEY := external/vboot_reference/tests/devkeys/kernel_subkey
+# /system_ext packages
+PRODUCT_PACKAGES += \
+    com.google.android.appfunctions.sidecar \
+    appfunctions.sidecar.xml
diff --git a/target/product/base_product.mk b/target/product/base_product.mk
index 0ac220bb16..acfc6534f8 100644
--- a/target/product/base_product.mk
+++ b/target/product/base_product.mk
@@ -25,3 +25,8 @@ PRODUCT_PACKAGES += \
     product_compatibility_matrix.xml \
     product_manifest.xml \
     selinux_policy_product \
+    product-build.prop \
+
+# Packages included only for eng or userdebug builds, previously debug tagged
+PRODUCT_PACKAGES_DEBUG += \
+    adb_keys \
diff --git a/target/product/base_system.mk b/target/product/base_system.mk
index 4f21c3ed63..586d2b896b 100644
--- a/target/product/base_system.mk
+++ b/target/product/base_system.mk
@@ -178,6 +178,7 @@ PRODUCT_PACKAGES += \
     libmedia \
     libmedia_jni \
     libmediandk \
+    libmonkey_jni \
     libmtp \
     libnetd_client \
     libnetlink \
@@ -204,6 +205,7 @@ PRODUCT_PACKAGES += \
     libstdc++ \
     libsysutils \
     libui \
+    libuprobestats_client \
     libusbhost \
     libutils \
     libvintf_jni \
@@ -279,6 +281,7 @@ PRODUCT_PACKAGES += \
     storaged \
     surfaceflinger \
     svc \
+    system-build.prop \
     task_profiles.json \
     tc \
     telecom \
@@ -290,7 +293,6 @@ PRODUCT_PACKAGES += \
     uiautomator \
     uinput \
     uncrypt \
-    uprobestats \
     usbd \
     vdc \
     vintf \
@@ -308,6 +310,17 @@ ifeq ($(RELEASE_CRASHRECOVERY_MODULE),true)
 
 endif
 
+# When we release uprobestats module
+ifeq ($(RELEASE_UPROBESTATS_MODULE),true)
+    PRODUCT_PACKAGES += \
+        com.android.uprobestats \
+
+else
+    PRODUCT_PACKAGES += \
+        uprobestats \
+
+endif
+
 # These packages are not used on Android TV
 ifneq ($(PRODUCT_IS_ATV),true)
   PRODUCT_PACKAGES += \
@@ -344,6 +357,11 @@ ifeq ($(RELEASE_USE_WEBVIEW_BOOTSTRAP_MODULE),true)
         com.android.webview.bootstrap
 endif
 
+ifneq (,$(RELEASE_RANGING_STACK))
+    PRODUCT_PACKAGES += \
+        com.android.ranging
+endif
+
 # VINTF data for system image
 PRODUCT_PACKAGES += \
     system_manifest.xml \
@@ -402,7 +420,6 @@ PRODUCT_HOST_PACKAGES += \
     BugReport \
     adb \
     adevice \
-    art-tools \
     atest \
     bcc \
     bit \
@@ -412,7 +429,7 @@ PRODUCT_HOST_PACKAGES += \
     flags_health_check \
     fsck.erofs \
     icu-data_host_i18n_apex \
-    icu_tzdata.dat_host_tzdata_apex \
+    tzdata_icu_res_files_host_prebuilts \
     idmap2 \
     incident_report \
     ld.mc \
@@ -433,6 +450,21 @@ PRODUCT_HOST_PACKAGES += \
     tz_version_host \
     tz_version_host_tzdata_apex \
 
+# For art-tools, if the dependencies have changed, please sync them to art/Android.bp as well.
+PRODUCT_HOST_PACKAGES += \
+    ahat \
+    dexdump \
+    hprof-conv
+# A subset of the tools are disabled when HOST_PREFER_32_BIT is defined as make reports that
+# they are not supported on host (b/129323791). This is likely due to art_apex disabling host
+# APEX builds when HOST_PREFER_32_BIT is set (b/120617876).
+ifneq ($(HOST_PREFER_32_BIT),true)
+PRODUCT_HOST_PACKAGES += \
+    dexlist \
+    oatdump
+endif
+
+
 PRODUCT_PACKAGES += init.usb.rc init.usb.configfs.rc
 
 PRODUCT_PACKAGES += etc_hosts
@@ -443,9 +475,13 @@ PRODUCT_VENDOR_PROPERTIES += ro.zygote?=zygote32
 PRODUCT_SYSTEM_PROPERTIES += debug.atrace.tags.enableflags=0
 PRODUCT_SYSTEM_PROPERTIES += persist.traced.enable=1
 
+# Include kernel configs.
+PRODUCT_PACKAGES += \
+    approved-ogki-builds.xml \
+    kernel-lifetimes.xml
+
 # Packages included only for eng or userdebug builds, previously debug tagged
 PRODUCT_PACKAGES_DEBUG := \
-    adb_keys \
     adevice_fingerprint \
     arping \
     dmuserd \
@@ -512,4 +548,5 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/build_variables.mk)
 $(call inherit-product,$(SRC_TARGET_DIR)/product/updatable_apex.mk)
 
 $(call soong_config_set, bionic, large_system_property_node, $(RELEASE_LARGE_SYSTEM_PROPERTY_NODE))
+$(call soong_config_set, Aconfig, read_from_new_storage, $(RELEASE_READ_FROM_NEW_STORAGE))
 $(call soong_config_set, SettingsLib, legacy_avatar_picker_app_enabled, $(if $(RELEASE_AVATAR_PICKER_APP),,true))
diff --git a/target/product/base_system_ext.mk b/target/product/base_system_ext.mk
index 92ca227a01..febe5378b5 100644
--- a/target/product/base_system_ext.mk
+++ b/target/product/base_system_ext.mk
@@ -24,6 +24,7 @@ PRODUCT_PACKAGES += \
     SatelliteClient \
     selinux_policy_system_ext \
     system_ext_manifest.xml \
+    system_ext-build.prop \
 
 # Base modules when shipping api level is less than or equal to 34
 PRODUCT_PACKAGES_SHIPPING_API_LEVEL_34 += \
diff --git a/target/product/base_vendor.mk b/target/product/base_vendor.mk
index 1854f9756f..a80e0b31b6 100644
--- a/target/product/base_vendor.mk
+++ b/target/product/base_vendor.mk
@@ -73,6 +73,12 @@ PRODUCT_PACKAGES += \
     passwd_vendor \
     selinux_policy_nonsystem \
     shell_and_utilities_vendor \
+    odm-build.prop \
+
+# libhealthloop BPF filter. This is in base_vendor.mk because libhealthloop must
+# be a static library and because the Android build system ignores 'required'
+# sections for static libraries.
+PRODUCT_PACKAGES += filterPowerSupplyEvents.o
 
 # Base modules when shipping api level is less than or equal to 34
 PRODUCT_PACKAGES_SHIPPING_API_LEVEL_34 += \
@@ -105,3 +111,9 @@ PRODUCT_PACKAGES += \
 PRODUCT_PACKAGES += \
     adb_debug.prop \
     userdebug_plat_sepolicy.cil
+
+# On eng or userdebug builds, build in perf-setup-sh by default.
+ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
+PRODUCT_PACKAGES += \
+    perf-setup-sh
+endif
diff --git a/target/product/build_variables.mk b/target/product/build_variables.mk
index 5fe5333f45..7661e063a7 100644
--- a/target/product/build_variables.mk
+++ b/target/product/build_variables.mk
@@ -17,5 +17,11 @@
 # This file contains the trunk-stable flags that should be exported to all
 # Android targets.
 
+# Control libbinder client caching
+$(call soong_config_set, libbinder, release_libbinder_client_cache, $(RELEASE_LIBBINDER_CLIENT_CACHE))
+
 # Use the configured release of sqlite
 $(call soong_config_set, libsqlite3, release_package_libsqlite3, $(RELEASE_PACKAGE_LIBSQLITE3))
+
+# Use the configured MessageQueue implementation
+$(call soong_config_set, messagequeue, release_package_messagequeue_implementation, $(RELEASE_PACKAGE_MESSAGEQUEUE_IMPLEMENTATION))
diff --git a/target/product/default_art_config.mk b/target/product/default_art_config.mk
index 1a3f2cf0e8..668f054773 100644
--- a/target/product/default_art_config.mk
+++ b/target/product/default_art_config.mk
@@ -76,6 +76,7 @@ PRODUCT_APEX_BOOT_JARS := \
     com.android.mediaprovider:framework-mediaprovider \
     com.android.mediaprovider:framework-pdf \
     com.android.mediaprovider:framework-pdf-v \
+    com.android.mediaprovider:framework-photopicker \
     com.android.ondevicepersonalization:framework-ondevicepersonalization \
     com.android.os.statsd:framework-statsd \
     com.android.permission:framework-permission \
@@ -113,6 +114,12 @@ ifeq ($(RELEASE_PACKAGE_PROFILING_MODULE),true)
 
 endif
 
+ifneq (,$(RELEASE_RANGING_STACK))
+    PRODUCT_APEX_BOOT_JARS += \
+        com.android.uwb:framework-ranging \
+    $(call soong_config_set,bootclasspath,release_ranging_stack,true)
+endif
+
 # List of system_server classpath jars delivered via apex.
 # Keep the list sorted by module names and then library names.
 # Note: For modules available in Q, DO NOT add new entries here.
@@ -168,6 +175,11 @@ ifeq ($(RELEASE_PACKAGE_PROFILING_MODULE),true)
 
 endif
 
+ifneq (,$(RELEASE_RANGING_STACK))
+    PRODUCT_APEX_STANDALONE_SYSTEM_SERVER_JARS += \
+        com.android.uwb:service-ranging
+endif
+
 # Overrides the (apex, jar) pairs above when determining the on-device location. The format is:
 # <old_apex>:<old_jar>:<new_apex>:<new_jar>
 PRODUCT_CONFIGURED_JAR_LOCATION_OVERRIDES := \
diff --git a/target/product/go_defaults.mk b/target/product/go_defaults.mk
index 6ee8fb415b..ccc4f365e7 100644
--- a/target/product/go_defaults.mk
+++ b/target/product/go_defaults.mk
@@ -21,9 +21,6 @@ $(call inherit-product, build/make/target/product/go_defaults_common.mk)
 PRODUCT_RELEASE_CONFIG_MAPS += $(wildcard build/release/gms_mainline_go/required/release_config_map.textproto)
 PRODUCT_RELEASE_CONFIG_MAPS += $(wildcard vendor/google_shared/build/release/gms_mainline_go/required/release_config_map.textproto)
 
-# TODO (b/342265627): Remove v/g/r once all the flags have been moved to v/g_s/b/r
-PRODUCT_RELEASE_CONFIG_MAPS += $(wildcard vendor/google/release/go_devices/release_config_map.mk)
-
 # Add the system properties.
 TARGET_SYSTEM_PROP += \
     build/make/target/board/go_defaults.prop
diff --git a/target/product/go_defaults_common.mk b/target/product/go_defaults_common.mk
index 5218f29c0a..fd4047a65b 100644
--- a/target/product/go_defaults_common.mk
+++ b/target/product/go_defaults_common.mk
@@ -37,9 +37,9 @@ PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD := false
 # leave less information available via JDWP.
 PRODUCT_MINIMIZE_JAVA_DEBUG_INFO := true
 
-# Disable Scudo outside of eng builds to save RAM.
+# Use the low memory allocator outside of eng builds to save RSS.
 ifneq (,$(filter eng, $(TARGET_BUILD_VARIANT)))
-  PRODUCT_DISABLE_SCUDO := true
+  MALLOC_LOW_MEMORY := true
 endif
 
 # Add the system properties.
diff --git a/target/product/gsi_release.mk b/target/product/gsi_release.mk
index da1284e7b8..39428d2cfe 100644
--- a/target/product/gsi_release.mk
+++ b/target/product/gsi_release.mk
@@ -51,9 +51,11 @@ PRODUCT_PACKAGES += \
     init.vndk-nodef.rc \
 
 
-# Overlay the GSI specific SystemUI setting
+# Overlay the GSI specific setting for framework and SystemUI
 ifneq ($(PRODUCT_IS_AUTOMOTIVE),true)
-    PRODUCT_PACKAGES += gsi_overlay_systemui
+    PRODUCT_PACKAGES += \
+        gsi_overlay_framework \
+        gsi_overlay_systemui \
     PRODUCT_COPY_FILES += \
         device/generic/common/overlays/overlay-config.xml:$(TARGET_COPY_OUT_SYSTEM_EXT)/overlay/config/config.xml
 endif
diff --git a/target/product/handheld_system.mk b/target/product/handheld_system.mk
index 743dc03272..2b055c7ed0 100644
--- a/target/product/handheld_system.mk
+++ b/target/product/handheld_system.mk
@@ -33,6 +33,7 @@ $(call inherit-product-if-exists, frameworks/base/data/keyboards/keyboards.mk)
 $(call inherit-product-if-exists, frameworks/webview/chromium/chromium.mk)
 
 PRODUCT_PACKAGES += \
+    android.software.window_magnification.prebuilt.xml \
     BasicDreams \
     BlockedNumberProvider \
     BluetoothMidiService \
@@ -68,13 +69,19 @@ PRODUCT_PACKAGES += \
     SharedStorageBackup \
     SimAppDialog \
     Telecom \
-    TelephonyProvider \
     TeleService \
     Traceur \
     UserDictionaryProvider \
     VpnDialogs \
     vr \
 
+# Choose the correct products based on HSUM status
+ifeq ($(PRODUCT_USE_HSUM),true)
+  PRODUCT_PACKAGES += TelephonyProviderHsum
+else
+  PRODUCT_PACKAGES += TelephonyProvider
+endif
+
 PRODUCT_PACKAGES += $(RELEASE_PACKAGE_VIRTUAL_CAMERA)
 # Set virtual_camera_service_enabled soong config variable based on the
 # RELEASE_PACKAGE_VIRTUAL_CAMERA build. virtual_camera_service_enabled soong config
@@ -89,9 +96,6 @@ PRODUCT_SYSTEM_SERVER_APPS += \
 
 PRODUCT_PACKAGES += framework-audio_effects.xml
 
-PRODUCT_COPY_FILES += \
-    frameworks/native/data/etc/android.software.window_magnification.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.software.window_magnification.xml \
-
 PRODUCT_VENDOR_PROPERTIES += \
     ro.carrier?=unknown \
     ro.config.notification_sound?=OnTheHunt.ogg \
diff --git a/target/product/hsum_common.mk b/target/product/hsum_common.mk
new file mode 100644
index 0000000000..b19bc65c90
--- /dev/null
+++ b/target/product/hsum_common.mk
@@ -0,0 +1,29 @@
+#
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
+#
+
+# Contains common default elements for devices running in Headless System User Mode.
+
+# Should generally be inherited first as using an HSUM configuration can affect downstream choices
+# (such as ensuring that the HSUM-variants of packages are selected).
+
+PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
+    ro.fw.mu.headless_system_user=true
+
+# Variable for elsewhere choosing the appropriate products based on HSUM status.
+PRODUCT_USE_HSUM := true
+
+PRODUCT_PACKAGES += \
+    HsumDefaultConfigOverlay
diff --git a/target/product/large_screen_common.mk b/target/product/large_screen_common.mk
new file mode 100644
index 0000000000..3eb9ff05e5
--- /dev/null
+++ b/target/product/large_screen_common.mk
@@ -0,0 +1,21 @@
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
+#
+
+# Window Extensions
+$(call inherit-product, $(SRC_TARGET_DIR)/product/window_extensions.mk)
+
+# Enable Settings 2-pane optimization for large-screen
+PRODUCT_SYSTEM_PROPERTIES += \
+    persist.settings.large_screen_opt.enabled=true
diff --git a/target/product/media_system.mk b/target/product/media_system.mk
index 503c9b3531..af3857ebc1 100644
--- a/target/product/media_system.mk
+++ b/target/product/media_system.mk
@@ -21,6 +21,7 @@
 $(call inherit-product, $(SRC_TARGET_DIR)/product/base_system.mk)
 
 PRODUCT_PACKAGES += \
+    android.software.webview.prebuilt.xml \
     com.android.future.usb.accessory \
     com.android.mediadrm.signer \
     com.android.media.remotedisplay \
@@ -39,12 +40,9 @@ PRODUCT_PACKAGES += \
 PRODUCT_HOST_PACKAGES += \
     fsck.f2fs \
 
-PRODUCT_COPY_FILES += \
-    frameworks/native/data/etc/android.software.webview.xml:system/etc/permissions/android.software.webview.xml
-
 ifneq (REL,$(PLATFORM_VERSION_CODENAME))
-PRODUCT_COPY_FILES += \
-    frameworks/native/data/etc/android.software.preview_sdk.xml:system/etc/permissions/android.software.preview_sdk.xml
+PRODUCT_PACKAGES += \
+    android.software.preview_sdk.prebuilt.xml
 endif
 
 # The order here is the same order they end up on the classpath, so it matters.
diff --git a/target/product/media_system_ext.mk b/target/product/media_system_ext.mk
index 30dd2e2711..34d8de3f32 100644
--- a/target/product/media_system_ext.mk
+++ b/target/product/media_system_ext.mk
@@ -26,3 +26,8 @@ PRODUCT_PACKAGES += \
 
 # Window Extensions
 $(call inherit-product, $(SRC_TARGET_DIR)/product/window_extensions_base.mk)
+
+# AppFunction Extensions
+ifneq (,$(RELEASE_APPFUNCTION_SIDECAR))
+    $(call inherit-product, $(SRC_TARGET_DIR)/product/app_function_extensions.mk)
+endif
diff --git a/target/product/runtime_libart.mk b/target/product/runtime_libart.mk
index dc78368983..9e8afa85a4 100644
--- a/target/product/runtime_libart.mk
+++ b/target/product/runtime_libart.mk
@@ -178,3 +178,8 @@ PRODUCT_SYSTEM_PROPERTIES += \
 PRODUCT_SYSTEM_PROPERTIES += \
     dalvik.vm.useartservice=true \
     dalvik.vm.enable_pr_dexopt=true
+
+# Copy preopted files from system_b on first boot.
+PRODUCT_SYSTEM_PROPERTIES += ro.cp_system_other_odex=1
+PRODUCT_PACKAGES += \
+  cppreopts.sh
diff --git a/target/product/sdk.mk b/target/product/sdk.mk
index 1a073636ef..3d56a80a91 100644
--- a/target/product/sdk.mk
+++ b/target/product/sdk.mk
@@ -40,3 +40,6 @@ PRODUCT_MODULE_BUILD_FROM_SOURCE := true
 ifeq ($(WITHOUT_CHECK_API),true)
   $(error WITHOUT_CHECK_API cannot be set to true for SDK product builds)
 endif
+
+# Include Wear flag values so that Wear-related APIs are build in sdks.
+PRODUCT_RELEASE_CONFIG_MAPS += $(wildcard vendor/google_shared/wear/release/release_config_map.textproto)
diff --git a/target/product/security/Android.bp b/target/product/security/Android.bp
index 1e26d598da..0d7b35e1c9 100644
--- a/target/product/security/Android.bp
+++ b/target/product/security/Android.bp
@@ -25,3 +25,15 @@ prebuilt_etc {
     sub_dir: "security/fsverity",
     filename_from_src: true,
 }
+
+// otacerts: A keystore with the authorized keys in it, which is used to verify
+// the authenticity of downloaded OTA packages.
+// This module zips files defined in PRODUCT_DEFAULT_DEV_CERTIFICATE and
+// PRODUCT_EXTRA_OTA_KEYS for system or PRODUCT_EXTRA_RECOVERY_KEYS for recovery
+// image
+otacerts_zip {
+    name: "otacerts",
+    recovery_available: true,
+    relative_install_path: "security",
+    filename: "otacerts.zip",
+}
diff --git a/target/product/security/Android.mk b/target/product/security/Android.mk
index 4bd8efc0fe..138e5bbe31 100644
--- a/target/product/security/Android.mk
+++ b/target/product/security/Android.mk
@@ -10,59 +10,8 @@ ifdef PRODUCT_ADB_KEYS
     LOCAL_LICENSE_CONDITIONS := notice
     LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
     LOCAL_MODULE_CLASS := ETC
-    LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)
+    LOCAL_MODULE_PATH := $(TARGET_OUT_PRODUCT_ETC)/security
     LOCAL_PREBUILT_MODULE_FILE := $(PRODUCT_ADB_KEYS)
     include $(BUILD_PREBUILT)
   endif
 endif
-
-
-#######################################
-# otacerts: A keystore with the authorized keys in it, which is used to verify the authenticity of
-# downloaded OTA packages.
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := otacerts
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_MODULE_CLASS := ETC
-LOCAL_MODULE_STEM := otacerts.zip
-LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/security
-include $(BUILD_SYSTEM)/base_rules.mk
-
-extra_ota_keys := $(addsuffix .x509.pem,$(PRODUCT_EXTRA_OTA_KEYS))
-
-$(LOCAL_BUILT_MODULE): PRIVATE_CERT := $(DEFAULT_SYSTEM_DEV_CERTIFICATE).x509.pem
-$(LOCAL_BUILT_MODULE): PRIVATE_EXTRA_OTA_KEYS := $(extra_ota_keys)
-$(LOCAL_BUILT_MODULE): \
-	    $(SOONG_ZIP) \
-	    $(DEFAULT_SYSTEM_DEV_CERTIFICATE).x509.pem \
-	    $(extra_ota_keys)
-	$(SOONG_ZIP) -o $@ -j -symlinks=false \
-	    $(addprefix -f ,$(PRIVATE_CERT) $(PRIVATE_EXTRA_OTA_KEYS))
-
-
-#######################################
-# otacerts for recovery image.
-include $(CLEAR_VARS)
-
-LOCAL_MODULE := otacerts.recovery
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
-LOCAL_LICENSE_CONDITIONS := notice
-LOCAL_NOTICE_FILE := build/soong/licenses/LICENSE
-LOCAL_MODULE_CLASS := ETC
-LOCAL_MODULE_STEM := otacerts.zip
-LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/system/etc/security
-include $(BUILD_SYSTEM)/base_rules.mk
-
-extra_recovery_keys := $(addsuffix .x509.pem,$(PRODUCT_EXTRA_RECOVERY_KEYS))
-
-$(LOCAL_BUILT_MODULE): PRIVATE_CERT := $(DEFAULT_SYSTEM_DEV_CERTIFICATE).x509.pem
-$(LOCAL_BUILT_MODULE): PRIVATE_EXTRA_RECOVERY_KEYS := $(extra_recovery_keys)
-$(LOCAL_BUILT_MODULE): \
-	    $(SOONG_ZIP) \
-	    $(DEFAULT_SYSTEM_DEV_CERTIFICATE).x509.pem \
-	    $(extra_recovery_keys)
-	$(SOONG_ZIP) -o $@ -j -symlinks=false \
-	    $(addprefix -f ,$(PRIVATE_CERT) $(PRIVATE_EXTRA_RECOVERY_KEYS))
diff --git a/target/product/userspace_reboot.mk b/target/product/userspace_reboot.mk
index f235d146e3..51feb0721f 100644
--- a/target/product/userspace_reboot.mk
+++ b/target/product/userspace_reboot.mk
@@ -14,6 +14,4 @@
 # limitations under the License.
 #
 
-# Inherit this when the target supports userspace reboot
-
-PRODUCT_VENDOR_PROPERTIES := init.userspace_reboot.is_supported=true
+# DEPRECATED! Do not inherit this.
diff --git a/target/product/virtual_ab_ota/OWNERS b/target/product/virtual_ab_ota/OWNERS
new file mode 100644
index 0000000000..8eb0686bd6
--- /dev/null
+++ b/target/product/virtual_ab_ota/OWNERS
@@ -0,0 +1,4 @@
+zhangkelvin@google.com
+dvander@google.com
+akailash@google.com
+
diff --git a/target/product/virtual_ab_ota/vabc_features.mk b/target/product/virtual_ab_ota/vabc_features.mk
index 1219763b0d..e2745a1356 100644
--- a/target/product/virtual_ab_ota/vabc_features.mk
+++ b/target/product/virtual_ab_ota/vabc_features.mk
@@ -40,6 +40,7 @@ PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.batch_writes=true
 # ro.virtual_ab.compression.xor.enabled and ro.virtual_ab.io_uring.enabled
 # is also recommended
 #
+# PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.read_ahead_size=16
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.o_direct.enabled=true
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.merge_thread_priority=19
 # PRODUCT_VENDOR_PROPERTIES += ro.virtual_ab.worker_thread_priority=0
diff --git a/teams/Android.bp b/teams/Android.bp
index c56af6bf63..0f5b47529b 100644
--- a/teams/Android.bp
+++ b/teams/Android.bp
@@ -4405,3 +4405,45 @@ team {
     // go/trendy/manage/engineers/4705629185081344
     trendy_team_id: "4705629185081344",
 }
+
+team {
+    name: "trendy_team_android_media_solutions_editing",
+
+    // go/trendy/manage/engineers/5350750192762880
+    trendy_team_id: "5350750192762880",
+}
+
+team {
+    name: "trendy_team_android_media_solutions_playback",
+
+    // go/trendy/manage/engineers/6742515252559872
+    trendy_team_id: "6742515252559872",
+}
+
+team {
+    name: "trendy_team_android_telemetry_client_infra",
+
+    // go/trendy/manage/engineers/5403245077430272
+    trendy_team_id: "5403245077430272",
+}
+
+team {
+    name: "trendy_team_pte_sysui",
+
+    // go/trendy/manage/engineers/5185897463382016
+    trendy_team_id: "5185897463382016",
+}
+
+team {
+    name: "trendy_team_pixel_troubleshooting_app",
+
+    // go/trendy/manage/engineers/5097003746426880
+    trendy_team_id: "5097003746426880",
+}
+
+team {
+    name: "trendy_team_desktop_firmware",
+
+    // go/trendy/manage/engineers/5787938454863872
+    trendy_team_id: "5787938454863872",
+}
diff --git a/tools/aconfig/TEST_MAPPING b/tools/aconfig/TEST_MAPPING
index 448d8cf8af..15e41876cf 100644
--- a/tools/aconfig/TEST_MAPPING
+++ b/tools/aconfig/TEST_MAPPING
@@ -98,6 +98,10 @@
     {
       // aconfig_storage file cpp integration tests
       "name": "aconfig_storage_file.test.cpp"
+    },
+    {
+      // aconfig_storage file java integration tests
+      "name": "aconfig_storage_file.test.java"
     }
   ],
   "postsubmit": [
diff --git a/tools/aconfig/aconfig/src/codegen/cpp.rs b/tools/aconfig/aconfig/src/codegen/cpp.rs
index e743b2fc59..7a9c382bc7 100644
--- a/tools/aconfig/aconfig/src/codegen/cpp.rs
+++ b/tools/aconfig/aconfig/src/codegen/cpp.rs
@@ -45,6 +45,8 @@ where
     let header = package.replace('.', "_");
     let package_macro = header.to_uppercase();
     let cpp_namespace = package.replace('.', "::");
+    ensure!(class_elements.len() > 0);
+    let container = class_elements[0].container.clone();
     ensure!(codegen::is_valid_name_ident(&header));
     let context = Context {
         header: &header,
@@ -56,6 +58,7 @@ where
         readwrite_count,
         is_test_mode: codegen_mode == CodegenMode::Test,
         class_elements,
+        container,
         allow_instrumentation,
     };
 
@@ -100,6 +103,7 @@ pub struct Context<'a> {
     pub readwrite_count: i32,
     pub is_test_mode: bool,
     pub class_elements: Vec<ClassElement>,
+    pub container: String,
     pub allow_instrumentation: bool,
 }
 
@@ -279,39 +283,23 @@ public:
     virtual ~flag_provider_interface() = default;
 
     virtual bool disabled_ro() = 0;
-
-    virtual void disabled_ro(bool val) = 0;
-
     virtual bool disabled_rw() = 0;
-
-    virtual void disabled_rw(bool val) = 0;
-
     virtual bool disabled_rw_exported() = 0;
-
-    virtual void disabled_rw_exported(bool val) = 0;
-
     virtual bool disabled_rw_in_other_namespace() = 0;
-
-    virtual void disabled_rw_in_other_namespace(bool val) = 0;
-
     virtual bool enabled_fixed_ro() = 0;
-
-    virtual void enabled_fixed_ro(bool val) = 0;
-
     virtual bool enabled_fixed_ro_exported() = 0;
-
-    virtual void enabled_fixed_ro_exported(bool val) = 0;
-
     virtual bool enabled_ro() = 0;
-
-    virtual void enabled_ro(bool val) = 0;
-
     virtual bool enabled_ro_exported() = 0;
-
-    virtual void enabled_ro_exported(bool val) = 0;
-
     virtual bool enabled_rw() = 0;
 
+    virtual void disabled_ro(bool val) = 0;
+    virtual void disabled_rw(bool val) = 0;
+    virtual void disabled_rw_exported(bool val) = 0;
+    virtual void disabled_rw_in_other_namespace(bool val) = 0;
+    virtual void enabled_fixed_ro(bool val) = 0;
+    virtual void enabled_fixed_ro_exported(bool val) = 0;
+    virtual void enabled_ro(bool val) = 0;
+    virtual void enabled_ro_exported(bool val) = 0;
     virtual void enabled_rw(bool val) = 0;
 
     virtual void reset_flags() {}
diff --git a/tools/aconfig/aconfig/src/codegen/java.rs b/tools/aconfig/aconfig/src/codegen/java.rs
index 3360ddd68b..1ac58c1b84 100644
--- a/tools/aconfig/aconfig/src/codegen/java.rs
+++ b/tools/aconfig/aconfig/src/codegen/java.rs
@@ -1,18 +1,18 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
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
+* Copyright (C) 2023 The Android Open Source Project
+*
+* Licensed under the Apache License, Version 2.0 (the "License");
+* you may not use this file except in compliance with the License.
+* You may obtain a copy of the License at
+*
+*      http://www.apache.org/licenses/LICENSE-2.0
+*
+* Unless required by applicable law or agreed to in writing, software
+* distributed under the License is distributed on an "AS IS" BASIS,
+* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+* See the License for the specific language governing permissions and
+* limitations under the License.
+*/
 
 use anyhow::Result;
 use serde::Serialize;
@@ -20,22 +20,24 @@ use std::collections::{BTreeMap, BTreeSet};
 use std::path::PathBuf;
 use tinytemplate::TinyTemplate;
 
-use aconfig_protos::{ProtoFlagPermission, ProtoFlagState, ProtoParsedFlag};
-
 use crate::codegen;
 use crate::codegen::CodegenMode;
 use crate::commands::OutputFile;
+use aconfig_protos::{ProtoFlagPermission, ProtoFlagState, ProtoParsedFlag};
+use std::collections::HashMap;
 
 pub fn generate_java_code<I>(
     package: &str,
     parsed_flags_iter: I,
     codegen_mode: CodegenMode,
+    flag_ids: HashMap<String, u16>,
+    allow_instrumentation: bool,
 ) -> Result<Vec<OutputFile>>
 where
     I: Iterator<Item = ProtoParsedFlag>,
 {
     let flag_elements: Vec<FlagElement> =
-        parsed_flags_iter.map(|pf| create_flag_element(package, &pf)).collect();
+        parsed_flags_iter.map(|pf| create_flag_element(package, &pf, flag_ids.clone())).collect();
     let namespace_flags = gen_flags_by_namespace(&flag_elements);
     let properties_set: BTreeSet<String> =
         flag_elements.iter().map(|fe| format_property_name(&fe.device_config_namespace)).collect();
@@ -43,7 +45,7 @@ where
     let library_exported = codegen_mode == CodegenMode::Exported;
     let runtime_lookup_required =
         flag_elements.iter().any(|elem| elem.is_read_write) || library_exported;
-
+    let container = (flag_elements.first().expect("zero template flags").container).to_string();
     let context = Context {
         flag_elements,
         namespace_flags,
@@ -52,6 +54,8 @@ where
         properties_set,
         package_name: package.to_string(),
         library_exported,
+        allow_instrumentation,
+        container,
     };
     let mut template = TinyTemplate::new();
     template.add_template("Flags.java", include_str!("../../templates/Flags.java.template"))?;
@@ -117,6 +121,8 @@ struct Context {
     pub properties_set: BTreeSet<String>,
     pub package_name: String,
     pub library_exported: bool,
+    pub allow_instrumentation: bool,
+    pub container: String,
 }
 
 #[derive(Serialize, Debug)]
@@ -127,23 +133,31 @@ struct NamespaceFlags {
 
 #[derive(Serialize, Clone, Debug)]
 struct FlagElement {
+    pub container: String,
     pub default_value: bool,
     pub device_config_namespace: String,
     pub device_config_flag: String,
     pub flag_name_constant_suffix: String,
+    pub flag_offset: u16,
     pub is_read_write: bool,
     pub method_name: String,
     pub properties: String,
 }
 
-fn create_flag_element(package: &str, pf: &ProtoParsedFlag) -> FlagElement {
+fn create_flag_element(
+    package: &str,
+    pf: &ProtoParsedFlag,
+    flag_offsets: HashMap<String, u16>,
+) -> FlagElement {
     let device_config_flag = codegen::create_device_config_ident(package, pf.name())
         .expect("values checked at flag parse time");
     FlagElement {
+        container: pf.container().to_string(),
         default_value: pf.state() == ProtoFlagState::ENABLED,
         device_config_namespace: pf.namespace().to_string(),
         device_config_flag,
         flag_name_constant_suffix: pf.name().to_ascii_uppercase(),
+        flag_offset: *flag_offsets.get(pf.name()).expect("didnt find package offset :("),
         is_read_write: pf.permission() == ProtoFlagPermission::READ_WRITE,
         method_name: format_java_method_name(pf.name()),
         properties: format_property_name(pf.namespace()),
@@ -179,6 +193,7 @@ fn format_property_name(property_name: &str) -> String {
 #[cfg(test)]
 mod tests {
     use super::*;
+    use crate::commands::assign_flag_ids;
     use std::collections::HashMap;
 
     const EXPECTED_FEATUREFLAGS_COMMON_CONTENT: &str = r#"
@@ -477,70 +492,40 @@ mod tests {
         let mode = CodegenMode::Production;
         let modified_parsed_flags =
             crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
-        let generated_files =
-            generate_java_code(crate::test::TEST_PACKAGE, modified_parsed_flags.into_iter(), mode)
-                .unwrap();
+        let flag_ids =
+            assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let generated_files = generate_java_code(
+            crate::test::TEST_PACKAGE,
+            modified_parsed_flags.into_iter(),
+            mode,
+            flag_ids,
+            false,
+        )
+        .unwrap();
         let expect_flags_content = EXPECTED_FLAG_COMMON_CONTENT.to_string()
             + r#"
             private static FeatureFlags FEATURE_FLAGS = new FeatureFlagsImpl();
         }"#;
 
-        let expect_featureflagsimpl_content = r#"
+        let expected_featureflagsmpl_content_0 = r#"
         package com.android.aconfig.test;
         // TODO(b/303773055): Remove the annotation after access issue is resolved.
         import android.compat.annotation.UnsupportedAppUsage;
         import android.provider.DeviceConfig;
         import android.provider.DeviceConfig.Properties;
+        "#;
+
+        let expected_featureflagsmpl_content_1 = r#"
         /** @hide */
         public final class FeatureFlagsImpl implements FeatureFlags {
-            private static boolean aconfig_test_is_cached = false;
-            private static boolean other_namespace_is_cached = false;
+            private static volatile boolean aconfig_test_is_cached = false;
+            private static volatile boolean other_namespace_is_cached = false;
             private static boolean disabledRw = false;
             private static boolean disabledRwExported = false;
             private static boolean disabledRwInOtherNamespace = false;
             private static boolean enabledRw = true;
-
-
-            private void load_overrides_aconfig_test() {
-                try {
-                    Properties properties = DeviceConfig.getProperties("aconfig_test");
-                    disabledRw =
-                        properties.getBoolean("com.android.aconfig.test.disabled_rw", false);
-                    disabledRwExported =
-                        properties.getBoolean("com.android.aconfig.test.disabled_rw_exported", false);
-                    enabledRw =
-                        properties.getBoolean("com.android.aconfig.test.enabled_rw", true);
-                } catch (NullPointerException e) {
-                    throw new RuntimeException(
-                        "Cannot read value from namespace aconfig_test "
-                        + "from DeviceConfig. It could be that the code using flag "
-                        + "executed before SettingsProvider initialization. Please use "
-                        + "fixed read-only flag by adding is_fixed_read_only: true in "
-                        + "flag declaration.",
-                        e
-                    );
-                }
-                aconfig_test_is_cached = true;
-            }
-
-            private void load_overrides_other_namespace() {
-                try {
-                    Properties properties = DeviceConfig.getProperties("other_namespace");
-                    disabledRwInOtherNamespace =
-                        properties.getBoolean("com.android.aconfig.test.disabled_rw_in_other_namespace", false);
-                } catch (NullPointerException e) {
-                    throw new RuntimeException(
-                        "Cannot read value from namespace other_namespace "
-                        + "from DeviceConfig. It could be that the code using flag "
-                        + "executed before SettingsProvider initialization. Please use "
-                        + "fixed read-only flag by adding is_fixed_read_only: true in "
-                        + "flag declaration.",
-                        e
-                    );
-                }
-                other_namespace_is_cached = true;
-            }
-
+        "#;
+        let expected_featureflagsmpl_content_2 = r#"
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
             @UnsupportedAppUsage
@@ -609,9 +594,230 @@ mod tests {
             }
         }
         "#;
+
+        let expect_featureflagsimpl_content_old = expected_featureflagsmpl_content_0.to_owned()
+            + expected_featureflagsmpl_content_1
+            + r#"
+            private void load_overrides_aconfig_test() {
+                try {
+                    Properties properties = DeviceConfig.getProperties("aconfig_test");
+                    disabledRw =
+                        properties.getBoolean(Flags.FLAG_DISABLED_RW, false);
+                    disabledRwExported =
+                        properties.getBoolean(Flags.FLAG_DISABLED_RW_EXPORTED, false);
+                    enabledRw =
+                        properties.getBoolean(Flags.FLAG_ENABLED_RW, true);
+                } catch (NullPointerException e) {
+                    throw new RuntimeException(
+                        "Cannot read value from namespace aconfig_test "
+                        + "from DeviceConfig. It could be that the code using flag "
+                        + "executed before SettingsProvider initialization. Please use "
+                        + "fixed read-only flag by adding is_fixed_read_only: true in "
+                        + "flag declaration.",
+                        e
+                    );
+                }
+                aconfig_test_is_cached = true;
+            }
+
+            private void load_overrides_other_namespace() {
+                try {
+                    Properties properties = DeviceConfig.getProperties("other_namespace");
+                    disabledRwInOtherNamespace =
+                        properties.getBoolean(Flags.FLAG_DISABLED_RW_IN_OTHER_NAMESPACE, false);
+                } catch (NullPointerException e) {
+                    throw new RuntimeException(
+                        "Cannot read value from namespace other_namespace "
+                        + "from DeviceConfig. It could be that the code using flag "
+                        + "executed before SettingsProvider initialization. Please use "
+                        + "fixed read-only flag by adding is_fixed_read_only: true in "
+                        + "flag declaration.",
+                        e
+                    );
+                }
+                other_namespace_is_cached = true;
+            }"#
+            + expected_featureflagsmpl_content_2;
+
         let mut file_set = HashMap::from([
             ("com/android/aconfig/test/Flags.java", expect_flags_content.as_str()),
-            ("com/android/aconfig/test/FeatureFlagsImpl.java", expect_featureflagsimpl_content),
+            (
+                "com/android/aconfig/test/FeatureFlagsImpl.java",
+                &expect_featureflagsimpl_content_old,
+            ),
+            ("com/android/aconfig/test/FeatureFlags.java", EXPECTED_FEATUREFLAGS_COMMON_CONTENT),
+            (
+                "com/android/aconfig/test/CustomFeatureFlags.java",
+                EXPECTED_CUSTOMFEATUREFLAGS_CONTENT,
+            ),
+            (
+                "com/android/aconfig/test/FakeFeatureFlagsImpl.java",
+                EXPECTED_FAKEFEATUREFLAGSIMPL_CONTENT,
+            ),
+        ]);
+
+        for file in generated_files {
+            let file_path = file.path.to_str().unwrap();
+            assert!(file_set.contains_key(file_path), "Cannot find {}", file_path);
+            assert_eq!(
+                None,
+                crate::test::first_significant_code_diff(
+                    file_set.get(file_path).unwrap(),
+                    &String::from_utf8(file.contents).unwrap()
+                ),
+                "File {} content is not correct",
+                file_path
+            );
+            file_set.remove(file_path);
+        }
+
+        assert!(file_set.is_empty());
+
+        let parsed_flags = crate::test::parse_test_flags();
+        let mode = CodegenMode::Production;
+        let modified_parsed_flags =
+            crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
+        let flag_ids =
+            assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let generated_files = generate_java_code(
+            crate::test::TEST_PACKAGE,
+            modified_parsed_flags.into_iter(),
+            mode,
+            flag_ids,
+            true,
+        )
+        .unwrap();
+
+        let expect_featureflagsimpl_content_new = expected_featureflagsmpl_content_0.to_owned()
+            + r#"
+            import android.aconfig.storage.StorageInternalReader;
+            import android.util.Log;
+            "#
+            + expected_featureflagsmpl_content_1
+            + r#"
+        StorageInternalReader reader;
+        boolean readFromNewStorage;
+
+        boolean useNewStorageValueAndDiscardOld = false;
+
+        private final static String TAG = "AconfigJavaCodegen";
+        private final static String SUCCESS_LOG = "success: %s value matches";
+        private final static String MISMATCH_LOG = "error: %s value mismatch, new storage value is %s, old storage value is %s";
+        private final static String ERROR_LOG = "error: failed to read flag value";
+
+        private void init() {
+            if (reader != null) return;
+            if (DeviceConfig.getBoolean("core_experiments_team_internal", "com.android.providers.settings.storage_test_mission_1", false)) {
+                readFromNewStorage = true;
+                try {
+                    reader = new StorageInternalReader("system", "com.android.aconfig.test");
+                } catch (Exception e) {
+                    reader = null;
+                }
+            }
+
+            useNewStorageValueAndDiscardOld =
+                DeviceConfig.getBoolean("core_experiments_team_internal", "com.android.providers.settings.use_new_storage_value", false);
+        }
+
+        private void load_overrides_aconfig_test() {
+            try {
+                Properties properties = DeviceConfig.getProperties("aconfig_test");
+                disabledRw =
+                    properties.getBoolean(Flags.FLAG_DISABLED_RW, false);
+                disabledRwExported =
+                    properties.getBoolean(Flags.FLAG_DISABLED_RW_EXPORTED, false);
+                enabledRw =
+                    properties.getBoolean(Flags.FLAG_ENABLED_RW, true);
+            } catch (NullPointerException e) {
+                throw new RuntimeException(
+                    "Cannot read value from namespace aconfig_test "
+                    + "from DeviceConfig. It could be that the code using flag "
+                    + "executed before SettingsProvider initialization. Please use "
+                    + "fixed read-only flag by adding is_fixed_read_only: true in "
+                    + "flag declaration.",
+                    e
+                );
+            }
+            aconfig_test_is_cached = true;
+            init();
+            if (readFromNewStorage && reader != null) {
+                boolean val;
+                try {
+                    val = reader.getBooleanFlagValue(1);
+                    if (val != disabledRw) {
+                        Log.w(TAG, String.format(MISMATCH_LOG, "disabledRw", val, disabledRw));
+                    }
+
+                    if (useNewStorageValueAndDiscardOld) {
+                        disabledRw = val;
+                    }
+
+                    val = reader.getBooleanFlagValue(2);
+                    if (val != disabledRwExported) {
+                        Log.w(TAG, String.format(MISMATCH_LOG, "disabledRwExported", val, disabledRwExported));
+                    }
+
+                    if (useNewStorageValueAndDiscardOld) {
+                        disabledRwExported = val;
+                    }
+
+                    val = reader.getBooleanFlagValue(8);
+                    if (val != enabledRw) {
+                        Log.w(TAG, String.format(MISMATCH_LOG, "enabledRw", val, enabledRw));
+                    }
+
+                    if (useNewStorageValueAndDiscardOld) {
+                        enabledRw = val;
+                    }
+
+                } catch (Exception e) {
+                    Log.e(TAG, ERROR_LOG, e);
+                }
+            }
+        }
+
+        private void load_overrides_other_namespace() {
+            try {
+                Properties properties = DeviceConfig.getProperties("other_namespace");
+                disabledRwInOtherNamespace =
+                    properties.getBoolean(Flags.FLAG_DISABLED_RW_IN_OTHER_NAMESPACE, false);
+            } catch (NullPointerException e) {
+                throw new RuntimeException(
+                    "Cannot read value from namespace other_namespace "
+                    + "from DeviceConfig. It could be that the code using flag "
+                    + "executed before SettingsProvider initialization. Please use "
+                    + "fixed read-only flag by adding is_fixed_read_only: true in "
+                    + "flag declaration.",
+                    e
+                );
+            }
+            other_namespace_is_cached = true;
+            init();
+            if (readFromNewStorage && reader != null) {
+                boolean val;
+                try {
+                    val = reader.getBooleanFlagValue(3);
+                    if (val != disabledRwInOtherNamespace) {
+                        Log.w(TAG, String.format(MISMATCH_LOG, "disabledRwInOtherNamespace", val, disabledRwInOtherNamespace));
+                    }
+
+                    if (useNewStorageValueAndDiscardOld) {
+                        disabledRwInOtherNamespace = val;
+                    }
+
+                } catch (Exception e) {
+                    Log.e(TAG, ERROR_LOG, e);
+                }
+            }
+        }"# + expected_featureflagsmpl_content_2;
+
+        let mut file_set = HashMap::from([
+            ("com/android/aconfig/test/Flags.java", expect_flags_content.as_str()),
+            (
+                "com/android/aconfig/test/FeatureFlagsImpl.java",
+                &expect_featureflagsimpl_content_new,
+            ),
             ("com/android/aconfig/test/FeatureFlags.java", EXPECTED_FEATUREFLAGS_COMMON_CONTENT),
             (
                 "com/android/aconfig/test/CustomFeatureFlags.java",
@@ -647,9 +853,16 @@ mod tests {
         let mode = CodegenMode::Exported;
         let modified_parsed_flags =
             crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
-        let generated_files =
-            generate_java_code(crate::test::TEST_PACKAGE, modified_parsed_flags.into_iter(), mode)
-                .unwrap();
+        let flag_ids =
+            assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let generated_files = generate_java_code(
+            crate::test::TEST_PACKAGE,
+            modified_parsed_flags.into_iter(),
+            mode,
+            flag_ids,
+            true,
+        )
+        .unwrap();
 
         let expect_flags_content = r#"
         package com.android.aconfig.test;
@@ -690,7 +903,7 @@ mod tests {
         import android.provider.DeviceConfig.Properties;
         /** @hide */
         public final class FeatureFlagsImpl implements FeatureFlags {
-            private static boolean aconfig_test_is_cached = false;
+            private static volatile boolean aconfig_test_is_cached = false;
             private static boolean disabledRwExported = false;
             private static boolean enabledFixedRoExported = false;
             private static boolean enabledRoExported = false;
@@ -700,11 +913,11 @@ mod tests {
                 try {
                     Properties properties = DeviceConfig.getProperties("aconfig_test");
                     disabledRwExported =
-                        properties.getBoolean("com.android.aconfig.test.disabled_rw_exported", false);
+                        properties.getBoolean(Flags.FLAG_DISABLED_RW_EXPORTED, false);
                     enabledFixedRoExported =
-                        properties.getBoolean("com.android.aconfig.test.enabled_fixed_ro_exported", false);
+                        properties.getBoolean(Flags.FLAG_ENABLED_FIXED_RO_EXPORTED, false);
                     enabledRoExported =
-                        properties.getBoolean("com.android.aconfig.test.enabled_ro_exported", false);
+                        properties.getBoolean(Flags.FLAG_ENABLED_RO_EXPORTED, false);
                 } catch (NullPointerException e) {
                     throw new RuntimeException(
                         "Cannot read value from namespace aconfig_test "
@@ -833,9 +1046,16 @@ mod tests {
         let mode = CodegenMode::Test;
         let modified_parsed_flags =
             crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
-        let generated_files =
-            generate_java_code(crate::test::TEST_PACKAGE, modified_parsed_flags.into_iter(), mode)
-                .unwrap();
+        let flag_ids =
+            assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let generated_files = generate_java_code(
+            crate::test::TEST_PACKAGE,
+            modified_parsed_flags.into_iter(),
+            mode,
+            flag_ids,
+            true,
+        )
+        .unwrap();
 
         let expect_flags_content = EXPECTED_FLAG_COMMON_CONTENT.to_string()
             + r#"
@@ -850,69 +1070,58 @@ mod tests {
         "#;
         let expect_featureflagsimpl_content = r#"
         package com.android.aconfig.test;
-        // TODO(b/303773055): Remove the annotation after access issue is resolved.
-        import android.compat.annotation.UnsupportedAppUsage;
         /** @hide */
         public final class FeatureFlagsImpl implements FeatureFlags {
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
             public boolean disabledRo() {
                 throw new UnsupportedOperationException(
                     "Method is not implemented.");
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
             public boolean disabledRw() {
                 throw new UnsupportedOperationException(
                     "Method is not implemented.");
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
             public boolean disabledRwExported() {
                 throw new UnsupportedOperationException(
                     "Method is not implemented.");
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
             public boolean disabledRwInOtherNamespace() {
                 throw new UnsupportedOperationException(
                     "Method is not implemented.");
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
             public boolean enabledFixedRo() {
                 throw new UnsupportedOperationException(
                     "Method is not implemented.");
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
             public boolean enabledFixedRoExported() {
                 throw new UnsupportedOperationException(
                     "Method is not implemented.");
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
             public boolean enabledRo() {
                 throw new UnsupportedOperationException(
                     "Method is not implemented.");
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
             public boolean enabledRoExported() {
                 throw new UnsupportedOperationException(
                     "Method is not implemented.");
             }
             @Override
             @com.android.aconfig.annotations.AconfigFlagAccessor
-            @UnsupportedAppUsage
             public boolean enabledRw() {
                 throw new UnsupportedOperationException(
                     "Method is not implemented.");
@@ -958,9 +1167,16 @@ mod tests {
         let mode = CodegenMode::ForceReadOnly;
         let modified_parsed_flags =
             crate::commands::modify_parsed_flags_based_on_mode(parsed_flags, mode).unwrap();
-        let generated_files =
-            generate_java_code(crate::test::TEST_PACKAGE, modified_parsed_flags.into_iter(), mode)
-                .unwrap();
+        let flag_ids =
+            assign_flag_ids(crate::test::TEST_PACKAGE, modified_parsed_flags.iter()).unwrap();
+        let generated_files = generate_java_code(
+            crate::test::TEST_PACKAGE,
+            modified_parsed_flags.into_iter(),
+            mode,
+            flag_ids,
+            true,
+        )
+        .unwrap();
         let expect_featureflags_content = r#"
         package com.android.aconfig.test;
         // TODO(b/303773055): Remove the annotation after access issue is resolved.
diff --git a/tools/aconfig/aconfig/src/codegen/rust.rs b/tools/aconfig/aconfig/src/codegen/rust.rs
index 45488b05f2..7bc34d6cfe 100644
--- a/tools/aconfig/aconfig/src/codegen/rust.rs
+++ b/tools/aconfig/aconfig/src/codegen/rust.rs
@@ -113,41 +113,35 @@ mod tests {
 use aconfig_storage_read_api::{Mmap, AconfigStorageError, StorageFileType, PackageReadContext, get_mapped_storage_file, get_boolean_flag_value, get_package_read_context};
 use std::path::Path;
 use std::io::Write;
+use std::sync::LazyLock;
 use log::{log, LevelFilter, Level};
 
-static STORAGE_MIGRATION_MARKER_FILE: &str =
-    "/metadata/aconfig_test_missions/mission_1";
-static MIGRATION_LOG_TAG: &str = "AconfigTestMission1";
-
 /// flag provider
 pub struct FlagProvider;
 
-lazy_static::lazy_static! {
     /// flag value cache for disabled_rw
-    static ref CACHED_disabled_rw: bool = flags_rust::GetServerConfigurableFlag(
+    static CACHED_disabled_rw: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
         "aconfig_flags.aconfig_test",
         "com.android.aconfig.test.disabled_rw",
-        "false") == "true";
+        "false") == "true");
 
     /// flag value cache for disabled_rw_exported
-    static ref CACHED_disabled_rw_exported: bool = flags_rust::GetServerConfigurableFlag(
+    static CACHED_disabled_rw_exported: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
         "aconfig_flags.aconfig_test",
         "com.android.aconfig.test.disabled_rw_exported",
-        "false") == "true";
+        "false") == "true");
 
     /// flag value cache for disabled_rw_in_other_namespace
-    static ref CACHED_disabled_rw_in_other_namespace: bool = flags_rust::GetServerConfigurableFlag(
+    static CACHED_disabled_rw_in_other_namespace: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
         "aconfig_flags.other_namespace",
         "com.android.aconfig.test.disabled_rw_in_other_namespace",
-        "false") == "true";
+        "false") == "true");
 
     /// flag value cache for enabled_rw
-    static ref CACHED_enabled_rw: bool = flags_rust::GetServerConfigurableFlag(
+    static CACHED_enabled_rw: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
         "aconfig_flags.aconfig_test",
         "com.android.aconfig.test.enabled_rw",
-        "true") == "true";
-
-}
+        "true") == "true");
 
 impl FlagProvider {
     /// query flag disabled_ro
@@ -259,223 +253,202 @@ pub fn enabled_rw() -> bool {
 use aconfig_storage_read_api::{Mmap, AconfigStorageError, StorageFileType, PackageReadContext, get_mapped_storage_file, get_boolean_flag_value, get_package_read_context};
 use std::path::Path;
 use std::io::Write;
+use std::sync::LazyLock;
 use log::{log, LevelFilter, Level};
 
-static STORAGE_MIGRATION_MARKER_FILE: &str =
-    "/metadata/aconfig_test_missions/mission_1";
-static MIGRATION_LOG_TAG: &str = "AconfigTestMission1";
-
 /// flag provider
 pub struct FlagProvider;
 
-lazy_static::lazy_static! {
-
-    static ref PACKAGE_OFFSET: Result<Option<u32>, AconfigStorageError> = unsafe {
-        get_mapped_storage_file("system", StorageFileType::PackageMap)
-        .and_then(|package_map| get_package_read_context(&package_map, "com.android.aconfig.test"))
-        .map(|context| context.map(|c| c.boolean_start_index))
-    };
-
-    static ref FLAG_VAL_MAP: Result<Mmap, AconfigStorageError> = unsafe {
-        get_mapped_storage_file("system", StorageFileType::FlagVal)
-    };
-    /// flag value cache for disabled_rw
-
-    static ref CACHED_disabled_rw: bool = {
-        let result = flags_rust::GetServerConfigurableFlag(
+static READ_FROM_NEW_STORAGE: LazyLock<bool> = LazyLock::new(|| unsafe {
+    Path::new("/metadata/aconfig/boot/enable_only_new_storage").exists()
+});
+
+static PACKAGE_OFFSET: LazyLock<Result<Option<u32>, AconfigStorageError>> = LazyLock::new(|| unsafe {
+    get_mapped_storage_file("system", StorageFileType::PackageMap)
+    .and_then(|package_map| get_package_read_context(&package_map, "com.android.aconfig.test"))
+    .map(|context| context.map(|c| c.boolean_start_index))
+});
+
+static FLAG_VAL_MAP: LazyLock<Result<Mmap, AconfigStorageError>> = LazyLock::new(|| unsafe {
+    get_mapped_storage_file("system", StorageFileType::FlagVal)
+});
+
+/// flag value cache for disabled_rw
+static CACHED_disabled_rw: LazyLock<bool> = LazyLock::new(|| {
+    if *READ_FROM_NEW_STORAGE {
+        // This will be called multiple times. Subsequent calls after the first are noops.
+        logger::init(
+            logger::Config::default()
+                .with_tag_on_device("aconfig_rust_codegen")
+                .with_max_level(LevelFilter::Info));
+
+        let flag_value_result = FLAG_VAL_MAP
+            .as_ref()
+            .map_err(|err| format!("failed to get flag val map: {err}"))
+            .and_then(|flag_val_map| {
+                PACKAGE_OFFSET
+                    .as_ref()
+                    .map_err(|err| format!("failed to get package read offset: {err}"))
+                    .and_then(|package_offset| {
+                        match package_offset {
+                            Some(offset) => {
+                                get_boolean_flag_value(&flag_val_map, offset + 1)
+                                    .map_err(|err| format!("failed to get flag: {err}"))
+                            },
+                            None => Err("no context found for package 'com.android.aconfig.test'".to_string())
+                        }
+                    })
+                });
+
+        match flag_value_result {
+            Ok(flag_value) => {
+                 return flag_value;
+            },
+            Err(err) => {
+                log!(Level::Error, "aconfig_rust_codegen: error: {err}");
+                panic!("failed to read flag value: {err}");
+            }
+        }
+    } else {
+        flags_rust::GetServerConfigurableFlag(
             "aconfig_flags.aconfig_test",
             "com.android.aconfig.test.disabled_rw",
-            "false") == "true";
-
-        if Path::new(STORAGE_MIGRATION_MARKER_FILE).exists() {
-            // This will be called multiple times. Subsequent calls after the first are noops.
-            logger::init(
-                logger::Config::default()
-                    .with_tag_on_device(MIGRATION_LOG_TAG)
-                    .with_max_level(LevelFilter::Info));
-
-            let aconfig_storage_result = FLAG_VAL_MAP
-                .as_ref()
-                .map_err(|err| format!("failed to get flag val map: {err}"))
-                .and_then(|flag_val_map| {
-                    PACKAGE_OFFSET
-                        .as_ref()
-                        .map_err(|err| format!("failed to get package read offset: {err}"))
-                        .and_then(|package_offset| {
-                            match package_offset {
-                                Some(offset) => {
-                                    get_boolean_flag_value(&flag_val_map, offset + 1)
-                                        .map_err(|err| format!("failed to get flag: {err}"))
-                                },
-                                None => Err("no context found for package 'com.android.aconfig.test'".to_string())
-                            }
-                        })
-                    });
-
-            match aconfig_storage_result {
-                Ok(storage_result) if storage_result == result => {
-                    log!(Level::Info, "AconfigTestMission1: success! flag 'disabled_rw' contained correct value. Legacy storage was {result}, new storage was {storage_result}");
-                },
-                Ok(storage_result) => {
-                    log!(Level::Error, "AconfigTestMission1: error: mismatch for flag 'disabled_rw'. Legacy storage was {result}, new storage was {storage_result}");
-                },
-                Err(err) => {
-                    log!(Level::Error, "AconfigTestMission1: error: {err}")
-                }
+            "false") == "true"
+    }
+});
+
+/// flag value cache for disabled_rw_exported
+static CACHED_disabled_rw_exported: LazyLock<bool> = LazyLock::new(|| {
+    if *READ_FROM_NEW_STORAGE {
+        // This will be called multiple times. Subsequent calls after the first are noops.
+        logger::init(
+            logger::Config::default()
+                .with_tag_on_device("aconfig_rust_codegen")
+                .with_max_level(LevelFilter::Info));
+
+        let flag_value_result = FLAG_VAL_MAP
+            .as_ref()
+            .map_err(|err| format!("failed to get flag val map: {err}"))
+            .and_then(|flag_val_map| {
+                PACKAGE_OFFSET
+                    .as_ref()
+                    .map_err(|err| format!("failed to get package read offset: {err}"))
+                    .and_then(|package_offset| {
+                        match package_offset {
+                            Some(offset) => {
+                                get_boolean_flag_value(&flag_val_map, offset + 2)
+                                    .map_err(|err| format!("failed to get flag: {err}"))
+                            },
+                            None => Err("no context found for package 'com.android.aconfig.test'".to_string())
+                        }
+                    })
+                });
+
+        match flag_value_result {
+            Ok(flag_value) => {
+                 return flag_value;
+            },
+            Err(err) => {
+                log!(Level::Error, "aconfig_rust_codegen: error: {err}");
+                panic!("failed to read flag value: {err}");
             }
         }
-
-        result
-        };
-
-    /// flag value cache for disabled_rw_exported
-
-    static ref CACHED_disabled_rw_exported: bool = {
-        let result = flags_rust::GetServerConfigurableFlag(
+    } else {
+        flags_rust::GetServerConfigurableFlag(
             "aconfig_flags.aconfig_test",
             "com.android.aconfig.test.disabled_rw_exported",
-            "false") == "true";
-
-        if Path::new(STORAGE_MIGRATION_MARKER_FILE).exists() {
-            // This will be called multiple times. Subsequent calls after the first are noops.
-            logger::init(
-                logger::Config::default()
-                    .with_tag_on_device(MIGRATION_LOG_TAG)
-                    .with_max_level(LevelFilter::Info));
-
-            let aconfig_storage_result = FLAG_VAL_MAP
-                .as_ref()
-                .map_err(|err| format!("failed to get flag val map: {err}"))
-                .and_then(|flag_val_map| {
-                    PACKAGE_OFFSET
-                        .as_ref()
-                        .map_err(|err| format!("failed to get package read offset: {err}"))
-                        .and_then(|package_offset| {
-                            match package_offset {
-                                Some(offset) => {
-                                    get_boolean_flag_value(&flag_val_map, offset + 2)
-                                        .map_err(|err| format!("failed to get flag: {err}"))
-                                },
-                                None => Err("no context found for package 'com.android.aconfig.test'".to_string())
-                            }
-                        })
-                    });
-
-            match aconfig_storage_result {
-                Ok(storage_result) if storage_result == result => {
-                    log!(Level::Info, "AconfigTestMission1: success! flag 'disabled_rw_exported' contained correct value. Legacy storage was {result}, new storage was {storage_result}");
-                },
-                Ok(storage_result) => {
-                    log!(Level::Error, "AconfigTestMission1: error: mismatch for flag 'disabled_rw_exported'. Legacy storage was {result}, new storage was {storage_result}");
-                },
-                Err(err) => {
-                    log!(Level::Error, "AconfigTestMission1: error: {err}")
-                }
+            "false") == "true"
+    }
+});
+
+/// flag value cache for disabled_rw_in_other_namespace
+static CACHED_disabled_rw_in_other_namespace: LazyLock<bool> = LazyLock::new(|| {
+    if *READ_FROM_NEW_STORAGE {
+        // This will be called multiple times. Subsequent calls after the first are noops.
+        logger::init(
+            logger::Config::default()
+                .with_tag_on_device("aconfig_rust_codegen")
+                .with_max_level(LevelFilter::Info));
+
+        let flag_value_result = FLAG_VAL_MAP
+            .as_ref()
+            .map_err(|err| format!("failed to get flag val map: {err}"))
+            .and_then(|flag_val_map| {
+                PACKAGE_OFFSET
+                    .as_ref()
+                    .map_err(|err| format!("failed to get package read offset: {err}"))
+                    .and_then(|package_offset| {
+                        match package_offset {
+                            Some(offset) => {
+                                get_boolean_flag_value(&flag_val_map, offset + 3)
+                                    .map_err(|err| format!("failed to get flag: {err}"))
+                            },
+                            None => Err("no context found for package 'com.android.aconfig.test'".to_string())
+                        }
+                    })
+                });
+
+        match flag_value_result {
+            Ok(flag_value) => {
+                 return flag_value;
+            },
+            Err(err) => {
+                log!(Level::Error, "aconfig_rust_codegen: error: {err}");
+                panic!("failed to read flag value: {err}");
             }
         }
-
-        result
-        };
-
-    /// flag value cache for disabled_rw_in_other_namespace
-
-    static ref CACHED_disabled_rw_in_other_namespace: bool = {
-        let result = flags_rust::GetServerConfigurableFlag(
+    } else {
+        flags_rust::GetServerConfigurableFlag(
             "aconfig_flags.other_namespace",
             "com.android.aconfig.test.disabled_rw_in_other_namespace",
-            "false") == "true";
-
-        if Path::new(STORAGE_MIGRATION_MARKER_FILE).exists() {
-            // This will be called multiple times. Subsequent calls after the first are noops.
-            logger::init(
-                logger::Config::default()
-                    .with_tag_on_device(MIGRATION_LOG_TAG)
-                    .with_max_level(LevelFilter::Info));
-
-            let aconfig_storage_result = FLAG_VAL_MAP
-                .as_ref()
-                .map_err(|err| format!("failed to get flag val map: {err}"))
-                .and_then(|flag_val_map| {
-                    PACKAGE_OFFSET
-                        .as_ref()
-                        .map_err(|err| format!("failed to get package read offset: {err}"))
-                        .and_then(|package_offset| {
-                            match package_offset {
-                                Some(offset) => {
-                                    get_boolean_flag_value(&flag_val_map, offset + 3)
-                                        .map_err(|err| format!("failed to get flag: {err}"))
-                                },
-                                None => Err("no context found for package 'com.android.aconfig.test'".to_string())
-                            }
-                        })
-                    });
-
-            match aconfig_storage_result {
-                Ok(storage_result) if storage_result == result => {
-                    log!(Level::Info, "AconfigTestMission1: success! flag 'disabled_rw_in_other_namespace' contained correct value. Legacy storage was {result}, new storage was {storage_result}");
-                },
-                Ok(storage_result) => {
-                    log!(Level::Error, "AconfigTestMission1: error: mismatch for flag 'disabled_rw_in_other_namespace'. Legacy storage was {result}, new storage was {storage_result}");
-                },
-                Err(err) => {
-                    log!(Level::Error, "AconfigTestMission1: error: {err}")
-                }
+            "false") == "true"
+    }
+});
+
+
+/// flag value cache for enabled_rw
+static CACHED_enabled_rw: LazyLock<bool> = LazyLock::new(|| {
+    if *READ_FROM_NEW_STORAGE {
+        // This will be called multiple times. Subsequent calls after the first are noops.
+        logger::init(
+            logger::Config::default()
+                .with_tag_on_device("aconfig_rust_codegen")
+                .with_max_level(LevelFilter::Info));
+
+        let flag_value_result = FLAG_VAL_MAP
+            .as_ref()
+            .map_err(|err| format!("failed to get flag val map: {err}"))
+            .and_then(|flag_val_map| {
+                PACKAGE_OFFSET
+                    .as_ref()
+                    .map_err(|err| format!("failed to get package read offset: {err}"))
+                    .and_then(|package_offset| {
+                        match package_offset {
+                            Some(offset) => {
+                                get_boolean_flag_value(&flag_val_map, offset + 8)
+                                    .map_err(|err| format!("failed to get flag: {err}"))
+                            },
+                            None => Err("no context found for package 'com.android.aconfig.test'".to_string())
+                        }
+                    })
+                });
+
+        match flag_value_result {
+            Ok(flag_value) => {
+                 return flag_value;
+            },
+            Err(err) => {
+                log!(Level::Error, "aconfig_rust_codegen: error: {err}");
+                panic!("failed to read flag value: {err}");
             }
         }
-
-        result
-        };
-
-    /// flag value cache for enabled_rw
-
-    static ref CACHED_enabled_rw: bool = {
-        let result = flags_rust::GetServerConfigurableFlag(
+    } else {
+        flags_rust::GetServerConfigurableFlag(
             "aconfig_flags.aconfig_test",
             "com.android.aconfig.test.enabled_rw",
-            "true") == "true";
-
-        if Path::new(STORAGE_MIGRATION_MARKER_FILE).exists() {
-            // This will be called multiple times. Subsequent calls after the first are noops.
-            logger::init(
-                logger::Config::default()
-                    .with_tag_on_device(MIGRATION_LOG_TAG)
-                    .with_max_level(LevelFilter::Info));
-
-            let aconfig_storage_result = FLAG_VAL_MAP
-                .as_ref()
-                .map_err(|err| format!("failed to get flag val map: {err}"))
-                .and_then(|flag_val_map| {
-                    PACKAGE_OFFSET
-                        .as_ref()
-                        .map_err(|err| format!("failed to get package read offset: {err}"))
-                        .and_then(|package_offset| {
-                            match package_offset {
-                                Some(offset) => {
-                                    get_boolean_flag_value(&flag_val_map, offset + 8)
-                                        .map_err(|err| format!("failed to get flag: {err}"))
-                                },
-                                None => Err("no context found for package 'com.android.aconfig.test'".to_string())
-                            }
-                        })
-                    });
-
-            match aconfig_storage_result {
-                Ok(storage_result) if storage_result == result => {
-                    log!(Level::Info, "AconfigTestMission1: success! flag 'enabled_rw' contained correct value. Legacy storage was {result}, new storage was {storage_result}");
-                },
-                Ok(storage_result) => {
-                    log!(Level::Error, "AconfigTestMission1: error: mismatch for flag 'enabled_rw'. Legacy storage was {result}, new storage was {storage_result}");
-                },
-                Err(err) => {
-                    log!(Level::Error, "AconfigTestMission1: error: {err}")
-                }
-            }
-        }
-
-        result
-        };
-
-}
+            "true") == "true"
+    }
+});
 
 impl FlagProvider {
 
@@ -535,66 +508,7 @@ pub static PROVIDER: FlagProvider = FlagProvider;
 /// query flag disabled_ro
 #[inline(always)]
 pub fn disabled_ro() -> bool {
-
-
-    let result = false;
-    if !Path::new(STORAGE_MIGRATION_MARKER_FILE).exists() {
-        return result;
-    }
-
-    // This will be called multiple times. Subsequent calls after the first
-    // are noops.
-    logger::init(
-        logger::Config::default()
-            .with_tag_on_device(MIGRATION_LOG_TAG)
-            .with_max_level(LevelFilter::Info),
-    );
-
-    unsafe {
-        let package_map = match get_mapped_storage_file("system", StorageFileType::PackageMap) {
-            Ok(file) => file,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'disabled_ro': {err}");
-                return result;
-            }
-        };
-
-        let package_read_context = match get_package_read_context(&package_map, "com.android.aconfig.test") {
-            Ok(Some(context)) => context,
-            Ok(None) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'disabled_ro': did not get context");
-                return result;
-            },
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'disabled_ro': {err}");
-                return result;
-            }
-        };
-        let flag_val_map = match get_mapped_storage_file("system", StorageFileType::FlagVal) {
-            Ok(val_map) => val_map,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'disabled_ro': {err}");
-                return result;
-            }
-        };
-        let value = match get_boolean_flag_value(&flag_val_map, 0 + package_read_context.boolean_start_index) {
-            Ok(val) => val,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'disabled_ro': {err}");
-                return result;
-            }
-        };
-
-        if result != value {
-            log!(Level::Error, "AconfigTestMission1: error: flag mismatch for 'disabled_ro'. Legacy storage was {result}, new storage was {value}");
-        } else {
-            let default_value = false;
-            log!(Level::Info, "AconfigTestMission1: success! flag 'disabled_ro' contained correct value. Legacy storage was {default_value}, new storage was {value}");
-        }
-    }
-
-    result
-
+   false
 }
 
 /// query flag disabled_rw
@@ -618,261 +532,25 @@ pub fn disabled_rw_in_other_namespace() -> bool {
 /// query flag enabled_fixed_ro
 #[inline(always)]
 pub fn enabled_fixed_ro() -> bool {
-
-
-    let result = true;
-    if !Path::new(STORAGE_MIGRATION_MARKER_FILE).exists() {
-        return result;
-    }
-
-    // This will be called multiple times. Subsequent calls after the first
-    // are noops.
-    logger::init(
-        logger::Config::default()
-            .with_tag_on_device(MIGRATION_LOG_TAG)
-            .with_max_level(LevelFilter::Info),
-    );
-
-    unsafe {
-        let package_map = match get_mapped_storage_file("system", StorageFileType::PackageMap) {
-            Ok(file) => file,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_fixed_ro': {err}");
-                return result;
-            }
-        };
-
-        let package_read_context = match get_package_read_context(&package_map, "com.android.aconfig.test") {
-            Ok(Some(context)) => context,
-            Ok(None) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_fixed_ro': did not get context");
-                return result;
-            },
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_fixed_ro': {err}");
-                return result;
-            }
-        };
-        let flag_val_map = match get_mapped_storage_file("system", StorageFileType::FlagVal) {
-            Ok(val_map) => val_map,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_fixed_ro': {err}");
-                return result;
-            }
-        };
-        let value = match get_boolean_flag_value(&flag_val_map, 4 + package_read_context.boolean_start_index) {
-            Ok(val) => val,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_fixed_ro': {err}");
-                return result;
-            }
-        };
-
-        if result != value {
-            log!(Level::Error, "AconfigTestMission1: error: flag mismatch for 'enabled_fixed_ro'. Legacy storage was {result}, new storage was {value}");
-        } else {
-            let default_value = true;
-            log!(Level::Info, "AconfigTestMission1: success! flag 'enabled_fixed_ro' contained correct value. Legacy storage was {default_value}, new storage was {value}");
-        }
-    }
-
-    result
-
+    true
 }
 
 /// query flag enabled_fixed_ro_exported
 #[inline(always)]
 pub fn enabled_fixed_ro_exported() -> bool {
-
-
-    let result = true;
-    if !Path::new(STORAGE_MIGRATION_MARKER_FILE).exists() {
-        return result;
-    }
-
-    // This will be called multiple times. Subsequent calls after the first
-    // are noops.
-    logger::init(
-        logger::Config::default()
-            .with_tag_on_device(MIGRATION_LOG_TAG)
-            .with_max_level(LevelFilter::Info),
-    );
-
-    unsafe {
-        let package_map = match get_mapped_storage_file("system", StorageFileType::PackageMap) {
-            Ok(file) => file,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_fixed_ro_exported': {err}");
-                return result;
-            }
-        };
-
-        let package_read_context = match get_package_read_context(&package_map, "com.android.aconfig.test") {
-            Ok(Some(context)) => context,
-            Ok(None) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_fixed_ro_exported': did not get context");
-                return result;
-            },
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_fixed_ro_exported': {err}");
-                return result;
-            }
-        };
-        let flag_val_map = match get_mapped_storage_file("system", StorageFileType::FlagVal) {
-            Ok(val_map) => val_map,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_fixed_ro_exported': {err}");
-                return result;
-            }
-        };
-        let value = match get_boolean_flag_value(&flag_val_map, 5 + package_read_context.boolean_start_index) {
-            Ok(val) => val,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_fixed_ro_exported': {err}");
-                return result;
-            }
-        };
-
-        if result != value {
-            log!(Level::Error, "AconfigTestMission1: error: flag mismatch for 'enabled_fixed_ro_exported'. Legacy storage was {result}, new storage was {value}");
-        } else {
-            let default_value = true;
-            log!(Level::Info, "AconfigTestMission1: success! flag 'enabled_fixed_ro_exported' contained correct value. Legacy storage was {default_value}, new storage was {value}");
-        }
-    }
-
-    result
-
+    true
 }
 
 /// query flag enabled_ro
 #[inline(always)]
 pub fn enabled_ro() -> bool {
-
-
-    let result = true;
-    if !Path::new(STORAGE_MIGRATION_MARKER_FILE).exists() {
-        return result;
-    }
-
-    // This will be called multiple times. Subsequent calls after the first
-    // are noops.
-    logger::init(
-        logger::Config::default()
-            .with_tag_on_device(MIGRATION_LOG_TAG)
-            .with_max_level(LevelFilter::Info),
-    );
-
-    unsafe {
-        let package_map = match get_mapped_storage_file("system", StorageFileType::PackageMap) {
-            Ok(file) => file,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_ro': {err}");
-                return result;
-            }
-        };
-
-        let package_read_context = match get_package_read_context(&package_map, "com.android.aconfig.test") {
-            Ok(Some(context)) => context,
-            Ok(None) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_ro': did not get context");
-                return result;
-            },
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_ro': {err}");
-                return result;
-            }
-        };
-        let flag_val_map = match get_mapped_storage_file("system", StorageFileType::FlagVal) {
-            Ok(val_map) => val_map,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_ro': {err}");
-                return result;
-            }
-        };
-        let value = match get_boolean_flag_value(&flag_val_map, 6 + package_read_context.boolean_start_index) {
-            Ok(val) => val,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_ro': {err}");
-                return result;
-            }
-        };
-
-        if result != value {
-            log!(Level::Error, "AconfigTestMission1: error: flag mismatch for 'enabled_ro'. Legacy storage was {result}, new storage was {value}");
-        } else {
-            let default_value = true;
-            log!(Level::Info, "AconfigTestMission1: success! flag 'enabled_ro' contained correct value. Legacy storage was {default_value}, new storage was {value}");
-        }
-    }
-
-    result
-
+    true
 }
 
 /// query flag enabled_ro_exported
 #[inline(always)]
 pub fn enabled_ro_exported() -> bool {
-
-
-    let result = true;
-    if !Path::new(STORAGE_MIGRATION_MARKER_FILE).exists() {
-        return result;
-    }
-
-    // This will be called multiple times. Subsequent calls after the first
-    // are noops.
-    logger::init(
-        logger::Config::default()
-            .with_tag_on_device(MIGRATION_LOG_TAG)
-            .with_max_level(LevelFilter::Info),
-    );
-
-    unsafe {
-        let package_map = match get_mapped_storage_file("system", StorageFileType::PackageMap) {
-            Ok(file) => file,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_ro_exported': {err}");
-                return result;
-            }
-        };
-
-        let package_read_context = match get_package_read_context(&package_map, "com.android.aconfig.test") {
-            Ok(Some(context)) => context,
-            Ok(None) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_ro_exported': did not get context");
-                return result;
-            },
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_ro_exported': {err}");
-                return result;
-            }
-        };
-        let flag_val_map = match get_mapped_storage_file("system", StorageFileType::FlagVal) {
-            Ok(val_map) => val_map,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_ro_exported': {err}");
-                return result;
-            }
-        };
-        let value = match get_boolean_flag_value(&flag_val_map, 7 + package_read_context.boolean_start_index) {
-            Ok(val) => val,
-            Err(err) => {
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag 'enabled_ro_exported': {err}");
-                return result;
-            }
-        };
-
-        if result != value {
-            log!(Level::Error, "AconfigTestMission1: error: flag mismatch for 'enabled_ro_exported'. Legacy storage was {result}, new storage was {value}");
-        } else {
-            let default_value = true;
-            log!(Level::Info, "AconfigTestMission1: success! flag 'enabled_ro_exported' contained correct value. Legacy storage was {default_value}, new storage was {value}");
-        }
-    }
-
-    result
-
+    true
 }
 
 /// query flag enabled_rw
@@ -1144,35 +822,29 @@ pub fn reset_flags() {
 use aconfig_storage_read_api::{Mmap, AconfigStorageError, StorageFileType, PackageReadContext, get_mapped_storage_file, get_boolean_flag_value, get_package_read_context};
 use std::path::Path;
 use std::io::Write;
+use std::sync::LazyLock;
 use log::{log, LevelFilter, Level};
 
-static STORAGE_MIGRATION_MARKER_FILE: &str =
-    "/metadata/aconfig_test_missions/mission_1";
-static MIGRATION_LOG_TAG: &str = "AconfigTestMission1";
-
 /// flag provider
 pub struct FlagProvider;
 
-lazy_static::lazy_static! {
     /// flag value cache for disabled_rw_exported
-    static ref CACHED_disabled_rw_exported: bool = flags_rust::GetServerConfigurableFlag(
+    static CACHED_disabled_rw_exported: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
         "aconfig_flags.aconfig_test",
         "com.android.aconfig.test.disabled_rw_exported",
-        "false") == "true";
+        "false") == "true");
 
     /// flag value cache for enabled_fixed_ro_exported
-    static ref CACHED_enabled_fixed_ro_exported: bool = flags_rust::GetServerConfigurableFlag(
+    static CACHED_enabled_fixed_ro_exported: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
         "aconfig_flags.aconfig_test",
         "com.android.aconfig.test.enabled_fixed_ro_exported",
-        "false") == "true";
+        "false") == "true");
 
     /// flag value cache for enabled_ro_exported
-    static ref CACHED_enabled_ro_exported: bool = flags_rust::GetServerConfigurableFlag(
+    static CACHED_enabled_ro_exported: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
         "aconfig_flags.aconfig_test",
         "com.android.aconfig.test.enabled_ro_exported",
-        "false") == "true";
-
-}
+        "false") == "true");
 
 impl FlagProvider {
     /// query flag disabled_rw_exported
@@ -1218,12 +890,9 @@ pub fn enabled_ro_exported() -> bool {
 use aconfig_storage_read_api::{Mmap, AconfigStorageError, StorageFileType, PackageReadContext, get_mapped_storage_file, get_boolean_flag_value, get_package_read_context};
 use std::path::Path;
 use std::io::Write;
+use std::sync::LazyLock;
 use log::{log, LevelFilter, Level};
 
-static STORAGE_MIGRATION_MARKER_FILE: &str =
-    "/metadata/aconfig_test_missions/mission_1";
-static MIGRATION_LOG_TAG: &str = "AconfigTestMission1";
-
 /// flag provider
 pub struct FlagProvider;
 
diff --git a/tools/aconfig/aconfig/src/commands.rs b/tools/aconfig/aconfig/src/commands.rs
index 68c3f41087..797a893ff1 100644
--- a/tools/aconfig/aconfig/src/commands.rs
+++ b/tools/aconfig/aconfig/src/commands.rs
@@ -17,7 +17,8 @@
 use anyhow::{bail, ensure, Context, Result};
 use itertools::Itertools;
 use protobuf::Message;
-use std::collections::HashMap;
+use std::collections::{BTreeMap, HashMap};
+use std::hash::Hasher;
 use std::io::Read;
 use std::path::PathBuf;
 
@@ -31,6 +32,7 @@ use aconfig_protos::{
     ParsedFlagExt, ProtoFlagMetadata, ProtoFlagPermission, ProtoFlagState, ProtoParsedFlag,
     ProtoParsedFlags, ProtoTracepoint,
 };
+use aconfig_storage_file::sip_hasher13::SipHasher13;
 use aconfig_storage_file::StorageFileType;
 
 pub struct Input {
@@ -77,8 +79,18 @@ pub fn parse_flags(
             .read_to_string(&mut contents)
             .with_context(|| format!("failed to read {}", input.source))?;
 
-        let flag_declarations = aconfig_protos::flag_declarations::try_from_text_proto(&contents)
-            .with_context(|| input.error_context())?;
+        let mut flag_declarations =
+            aconfig_protos::flag_declarations::try_from_text_proto(&contents)
+                .with_context(|| input.error_context())?;
+
+        // system_ext flags should be treated as system flags as we are combining /system_ext
+        // and /system as one container
+        // TODO: remove this logic when we start enforcing that system_ext cannot be set as
+        // container in aconfig declaration files.
+        if flag_declarations.container() == "system_ext" {
+            flag_declarations.set_container(String::from("system"));
+        }
+
         ensure!(
             package == flag_declarations.package(),
             "failed to parse {}: expected package {}, got {}",
@@ -191,15 +203,25 @@ pub fn parse_flags(
     Ok(output)
 }
 
-pub fn create_java_lib(mut input: Input, codegen_mode: CodegenMode) -> Result<Vec<OutputFile>> {
+pub fn create_java_lib(
+    mut input: Input,
+    codegen_mode: CodegenMode,
+    allow_instrumentation: bool,
+) -> Result<Vec<OutputFile>> {
     let parsed_flags = input.try_parse_flags()?;
     let modified_parsed_flags = modify_parsed_flags_based_on_mode(parsed_flags, codegen_mode)?;
     let Some(package) = find_unique_package(&modified_parsed_flags) else {
         bail!("no parsed flags, or the parsed flags use different packages");
     };
     let package = package.to_string();
-    let _flag_ids = assign_flag_ids(&package, modified_parsed_flags.iter())?;
-    generate_java_code(&package, modified_parsed_flags.into_iter(), codegen_mode)
+    let flag_ids = assign_flag_ids(&package, modified_parsed_flags.iter())?;
+    generate_java_code(
+        &package,
+        modified_parsed_flags.into_iter(),
+        codegen_mode,
+        flag_ids,
+        allow_instrumentation,
+    )
 }
 
 pub fn create_cpp_lib(
@@ -400,11 +422,42 @@ where
     Ok(flag_ids)
 }
 
+#[allow(dead_code)] // TODO: b/316357686 - Use fingerprint in codegen to
+                    // protect hardcoded offset reads.
+pub fn compute_flag_offsets_fingerprint(flags_map: &HashMap<String, u16>) -> Result<u64> {
+    let mut hasher = SipHasher13::new();
+
+    // Need to sort to ensure the data is added to the hasher in the same order
+    // each run.
+    let sorted_map: BTreeMap<&String, &u16> = flags_map.iter().collect();
+
+    for (flag, offset) in sorted_map {
+        // See https://docs.rs/siphasher/latest/siphasher/#note for use of write
+        // over write_i16. Similarly, use to_be_bytes rather than to_ne_bytes to
+        // ensure consistency.
+        hasher.write(flag.as_bytes());
+        hasher.write(&offset.to_be_bytes());
+    }
+    Ok(hasher.finish())
+}
+
 #[cfg(test)]
 mod tests {
     use super::*;
     use aconfig_protos::ProtoFlagPurpose;
 
+    #[test]
+    fn test_offset_fingerprint() {
+        let parsed_flags = crate::test::parse_test_flags();
+        let package = find_unique_package(&parsed_flags.parsed_flag).unwrap().to_string();
+        let flag_ids = assign_flag_ids(&package, parsed_flags.parsed_flag.iter()).unwrap();
+        let expected_fingerprint = 10709892481002252132u64;
+
+        let hash_result = compute_flag_offsets_fingerprint(&flag_ids);
+
+        assert_eq!(hash_result.unwrap(), expected_fingerprint);
+    }
+
     #[test]
     fn test_parse_flags() {
         let parsed_flags = crate::test::parse_test_flags(); // calls parse_flags
diff --git a/tools/aconfig/aconfig/src/main.rs b/tools/aconfig/aconfig/src/main.rs
index 519d6ef354..1fb64f9c56 100644
--- a/tools/aconfig/aconfig/src/main.rs
+++ b/tools/aconfig/aconfig/src/main.rs
@@ -72,6 +72,12 @@ fn cli() -> Command {
                         .long("mode")
                         .value_parser(EnumValueParser::<CodegenMode>::new())
                         .default_value("production"),
+                )
+                .arg(
+                    Arg::new("allow-instrumentation")
+                        .long("allow-instrumentation")
+                        .value_parser(clap::value_parser!(bool))
+                        .default_value("false"),
                 ),
         )
         .subcommand(
@@ -243,8 +249,10 @@ fn main() -> Result<()> {
         Some(("create-java-lib", sub_matches)) => {
             let cache = open_single_file(sub_matches, "cache")?;
             let mode = get_required_arg::<CodegenMode>(sub_matches, "mode")?;
-            let generated_files =
-                commands::create_java_lib(cache, *mode).context("failed to create java lib")?;
+            let allow_instrumentation =
+                get_required_arg::<bool>(sub_matches, "allow-instrumentation")?;
+            let generated_files = commands::create_java_lib(cache, *mode, *allow_instrumentation)
+                .context("failed to create java lib")?;
             let dir = PathBuf::from(get_required_arg::<String>(sub_matches, "out")?);
             generated_files
                 .iter()
diff --git a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.java.template b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.java.template
index 6235e6946c..bc01aa4bab 100644
--- a/tools/aconfig/aconfig/templates/FeatureFlagsImpl.java.template
+++ b/tools/aconfig/aconfig/templates/FeatureFlagsImpl.java.template
@@ -1,18 +1,28 @@
 package {package_name};
+{{ -if not is_test_mode }}
 {{ if not library_exported- }}
 // TODO(b/303773055): Remove the annotation after access issue is resolved.
 import android.compat.annotation.UnsupportedAppUsage;
 {{ -endif }}
-{{ -if not is_test_mode }}
+
 {{ -if runtime_lookup_required }}
 import android.provider.DeviceConfig;
 import android.provider.DeviceConfig.Properties;
-{{ endif }}
+
+
+{{ -if not library_exported }}
+{{ -if allow_instrumentation }}
+import android.aconfig.storage.StorageInternalReader;
+import android.util.Log;
+{{ -endif }}
+{{ -endif }}
+
+{{ -endif }}
 /** @hide */
 public final class FeatureFlagsImpl implements FeatureFlags \{
 {{ -if runtime_lookup_required }}
 {{ -for namespace_with_flags in namespace_flags }}
-    private static boolean {namespace_with_flags.namespace}_is_cached = false;
+    private static volatile boolean {namespace_with_flags.namespace}_is_cached = false;
 {{ -endfor- }}
 
 {{ for flag in flag_elements }}
@@ -20,6 +30,35 @@ public final class FeatureFlagsImpl implements FeatureFlags \{
     private static boolean {flag.method_name} = {flag.default_value};
 {{ -endif }}
 {{ -endfor }}
+{{ -if not library_exported }}
+{{ -if allow_instrumentation }}
+    StorageInternalReader reader;
+    boolean readFromNewStorage;
+
+    boolean useNewStorageValueAndDiscardOld = false;
+
+    private final static String TAG = "AconfigJavaCodegen";
+    private final static String SUCCESS_LOG = "success: %s value matches";
+    private final static String MISMATCH_LOG = "error: %s value mismatch, new storage value is %s, old storage value is %s";
+    private final static String ERROR_LOG = "error: failed to read flag value";
+
+    private void init() \{
+        if (reader != null) return;
+        if (DeviceConfig.getBoolean("core_experiments_team_internal", "com.android.providers.settings.storage_test_mission_1", false)) \{
+            readFromNewStorage = true;
+            try \{
+                reader = new StorageInternalReader("{container}", "{package_name}");
+            } catch (Exception e) \{
+                reader = null;
+            }
+        }
+
+        useNewStorageValueAndDiscardOld =
+            DeviceConfig.getBoolean("core_experiments_team_internal", "com.android.providers.settings.use_new_storage_value", false);
+    }
+
+{{ -endif }}
+{{ -endif }}
 {{ for namespace_with_flags in namespace_flags }}
     private void load_overrides_{namespace_with_flags.namespace}() \{
         try \{
@@ -27,7 +66,7 @@ public final class FeatureFlagsImpl implements FeatureFlags \{
 {{ -for flag in namespace_with_flags.flags }}
 {{ -if flag.is_read_write }}
             {flag.method_name} =
-                properties.getBoolean("{flag.device_config_flag}", {flag.default_value});
+                properties.getBoolean(Flags.FLAG_{flag.flag_name_constant_suffix}, {flag.default_value});
 {{ -endif }}
 {{ -endfor }}
         } catch (NullPointerException e) \{
@@ -41,6 +80,32 @@ public final class FeatureFlagsImpl implements FeatureFlags \{
             );
         }
         {namespace_with_flags.namespace}_is_cached = true;
+{{ -if not library_exported }}
+{{ -if allow_instrumentation }}
+        init();
+        if (readFromNewStorage && reader != null) \{
+            boolean val;
+            try \{
+{{ -for flag in namespace_with_flags.flags }}
+{{ -if flag.is_read_write }}
+
+                val = reader.getBooleanFlagValue({flag.flag_offset});
+                if (val != {flag.method_name}) \{
+                    Log.w(TAG, String.format(MISMATCH_LOG, "{flag.method_name}", val, {flag.method_name}));
+                }
+
+                if (useNewStorageValueAndDiscardOld) \{
+                    {flag.method_name} = val;
+                }
+
+{{ -endif }}
+{{ -endfor }}
+            } catch (Exception e) \{
+                    Log.e(TAG, ERROR_LOG, e);
+            }
+        }
+{{ -endif }}
+{{ -endif }}
     }
 {{ endfor- }}
 {{ -endif }}{#- end of runtime_lookup_required #}
@@ -70,7 +135,6 @@ public final class FeatureFlagsImpl implements FeatureFlags \{
     @Override
 {{ -if not library_exported }}
     @com.android.aconfig.annotations.AconfigFlagAccessor
-    @UnsupportedAppUsage
 {{ -endif }}
     public boolean {flag.method_name}() \{
         throw new UnsupportedOperationException(
diff --git a/tools/aconfig/aconfig/templates/cpp_exported_header.template b/tools/aconfig/aconfig/templates/cpp_exported_header.template
index 0f7853e405..4643c9775c 100644
--- a/tools/aconfig/aconfig/templates/cpp_exported_header.template
+++ b/tools/aconfig/aconfig/templates/cpp_exported_header.template
@@ -27,12 +27,13 @@ public:
     {{ -for item in class_elements}}
     virtual bool {item.flag_name}() = 0;
 
+    {{ -endfor }}
+
     {{ -if is_test_mode }}
+    {{ -for item in class_elements}}
     virtual void {item.flag_name}(bool val) = 0;
-    {{ -endif }}
     {{ -endfor }}
 
-    {{ -if is_test_mode }}
     virtual void reset_flags() \{}
     {{ -endif }}
 };
diff --git a/tools/aconfig/aconfig/templates/cpp_source_file.template b/tools/aconfig/aconfig/templates/cpp_source_file.template
index 38dda7df31..852b905f32 100644
--- a/tools/aconfig/aconfig/templates/cpp_source_file.template
+++ b/tools/aconfig/aconfig/templates/cpp_source_file.template
@@ -1,13 +1,13 @@
 #include "{header}.h"
 
 {{ if allow_instrumentation }}
-#include <sys/stat.h>
+{{ if readwrite- }}
+#include <unistd.h>
 #include "aconfig_storage/aconfig_storage_read_api.hpp"
 #include <android/log.h>
-
-#define ALOGI(msg, ...)                                                        \
-  __android_log_print(ANDROID_LOG_INFO, "AconfigTestMission1", (msg), __VA_ARGS__)
-
+#define LOG_TAG "aconfig_cpp_codegen"
+#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
+{{ -endif }}
 {{ endif }}
 
 {{ if readwrite- }}
@@ -66,15 +66,87 @@ namespace {cpp_namespace} \{
     class flag_provider : public flag_provider_interface \{
     public:
 
-        {{ -for item in class_elements }}
+        {{ if allow_instrumentation- }}
+        {{ if readwrite- }}
+        flag_provider()
+            {{ if readwrite- }}
+            : cache_({readwrite_count}, -1)
+            , boolean_start_index_()
+            {{ -else- }}
+            : boolean_start_index_()
+            {{ -endif }}
+            , flag_value_file_(nullptr)
+            , read_from_new_storage_(false) \{
+
+            if (access("/metadata/aconfig/boot/enable_only_new_storage", F_OK) == 0) \{
+               read_from_new_storage_ = true;
+            }
+
+            if (!read_from_new_storage_) \{
+               return;
+            }
+
+            auto package_map_file = aconfig_storage::get_mapped_file(
+                 "{container}",
+                 aconfig_storage::StorageFileType::package_map);
+            if (!package_map_file.ok()) \{
+                ALOGE("error: failed to get package map file: %s", package_map_file.error().c_str());
+            }
+
+            auto context = aconfig_storage::get_package_read_context(
+                **package_map_file, "{package}");
+            if (!context.ok()) \{
+                ALOGE("error: failed to get package read context: %s", context.error().c_str());
+            }
+
+            // cache package boolean flag start index
+            boolean_start_index_ = context->boolean_start_index;
+
+            // unmap package map file and free memory
+            delete *package_map_file;
 
+            auto flag_value_file = aconfig_storage::get_mapped_file(
+                "{container}",
+                aconfig_storage::StorageFileType::flag_val);
+            if (!flag_value_file.ok()) \{
+                ALOGE("error: failed to get flag value file: %s", flag_value_file.error().c_str());
+            }
+
+            // cache flag value file
+            flag_value_file_ = std::unique_ptr<aconfig_storage::MappedStorageFile>(
+                *flag_value_file);
+
+        }
+        {{ -endif }}
+        {{ -endif }}
+
+        {{ -for item in class_elements }}
         virtual bool {item.flag_name}() override \{
             {{ -if item.readwrite }}
             if (cache_[{item.readwrite_idx}] == -1) \{
+            {{ if allow_instrumentation- }}
+                if (read_from_new_storage_) \{
+                    auto value = aconfig_storage::get_boolean_flag_value(
+                        *flag_value_file_,
+                        boolean_start_index_ + {item.flag_offset});
+
+                    if (!value.ok()) \{
+                        ALOGE("error: failed to read flag value: %s", value.error().c_str());
+                    }
+
+                    cache_[{item.readwrite_idx}] = *value;
+                } else \{
+                    cache_[{item.readwrite_idx}] = server_configurable_flags::GetServerConfigurableFlag(
+                        "aconfig_flags.{item.device_config_namespace}",
+                        "{item.device_config_flag}",
+                        "{item.default_value}") == "true";
+                }
+            {{ -else- }}
                 cache_[{item.readwrite_idx}] = server_configurable_flags::GetServerConfigurableFlag(
                     "aconfig_flags.{item.device_config_namespace}",
                     "{item.device_config_flag}",
                     "{item.default_value}") == "true";
+            {{ -endif }}
             }
             return cache_[{item.readwrite_idx}];
             {{ -else }}
@@ -86,12 +158,20 @@ namespace {cpp_namespace} \{
             {{ -endif }}
         }
         {{ -endfor }}
+
     {{ if readwrite- }}
     private:
         std::vector<int8_t> cache_ = std::vector<int8_t>({readwrite_count}, -1);
+    {{ if allow_instrumentation- }}
+        uint32_t boolean_start_index_;
+
+        std::unique_ptr<aconfig_storage::MappedStorageFile> flag_value_file_;
+
+        bool read_from_new_storage_;
+    {{ -endif }}
     {{ -endif }}
-    };
 
+    };
 
 {{ -endif }}
 
@@ -107,62 +187,6 @@ bool {header}_{item.flag_name}() \{
     {{ -if item.readwrite }}
     return {cpp_namespace}::{item.flag_name}();
     {{ -else }}
-    {{ if allow_instrumentation }}
-    auto result =
-        {{ if item.is_fixed_read_only }}
-	    {package_macro}_{item.flag_macro}
-	{{ else }}
-	    {item.default_value}
-	{{ endif }};
-
-    struct stat buffer;
-    if (stat("/metadata/aconfig_test_missions/mission_1", &buffer) != 0) \{
-        return result;
-    }
-
-    auto package_map_file = aconfig_storage::get_mapped_file(
-        "{item.container}",
-        aconfig_storage::StorageFileType::package_map);
-    if (!package_map_file.ok()) \{
-        ALOGI("error: failed to get package map file: %s", package_map_file.error().c_str());
-        return result;
-    }
-
-    auto package_read_context = aconfig_storage::get_package_read_context(
-        **package_map_file, "{package}");
-    if (!package_read_context.ok()) \{
-        ALOGI("error: failed to get package read context: %s", package_map_file.error().c_str());
-        return result;
-    }
-
-    delete *package_map_file;
-
-    auto flag_val_map = aconfig_storage::get_mapped_file(
-        "{item.container}",
-        aconfig_storage::StorageFileType::flag_val);
-    if (!flag_val_map.ok()) \{
-        ALOGI("error: failed to get flag val map: %s", package_map_file.error().c_str());
-        return result;
-    }
-
-    auto value = aconfig_storage::get_boolean_flag_value(
-        **flag_val_map,
-        package_read_context->boolean_start_index + {item.flag_offset});
-    if (!value.ok()) \{
-        ALOGI("error: failed to get flag val: %s", package_map_file.error().c_str());
-        return result;
-    }
-
-    delete *flag_val_map;
-
-    if (*value != result) \{
-        ALOGI("error: new storage value '%d' does not match current value '%d'", *value, result);
-    } else \{
-        ALOGI("success: new storage value was '%d, legacy storage was '%d'", *value, result);
-    }
-
-    return result;
-    {{ else }}
     {{ -if item.is_fixed_read_only }}
     return {package_macro}_{item.flag_macro};
     {{ -else }}
@@ -170,7 +194,6 @@ bool {header}_{item.flag_name}() \{
     {{ -endif }}
     {{ -endif }}
     {{ -endif }}
-    {{ -endif }}
 }
 
 {{ -if is_test_mode }}
@@ -185,5 +208,3 @@ void {header}_reset_flags() \{
      {cpp_namespace}::reset_flags();
 }
 {{ -endif }}
-
-
diff --git a/tools/aconfig/aconfig/templates/rust.template b/tools/aconfig/aconfig/templates/rust.template
index cfd9d6aec8..c2f162fcc8 100644
--- a/tools/aconfig/aconfig/templates/rust.template
+++ b/tools/aconfig/aconfig/templates/rust.template
@@ -2,88 +2,85 @@
 use aconfig_storage_read_api::\{Mmap, AconfigStorageError, StorageFileType, PackageReadContext, get_mapped_storage_file, get_boolean_flag_value, get_package_read_context};
 use std::path::Path;
 use std::io::Write;
+use std::sync::LazyLock;
 use log::\{log, LevelFilter, Level};
 
-static STORAGE_MIGRATION_MARKER_FILE: &str =
-    "/metadata/aconfig_test_missions/mission_1";
-static MIGRATION_LOG_TAG: &str = "AconfigTestMission1";
-
 /// flag provider
 pub struct FlagProvider;
 
 {{ if has_readwrite- }}
-lazy_static::lazy_static! \{
-    {{ if allow_instrumentation }}
-    static ref PACKAGE_OFFSET: Result<Option<u32>, AconfigStorageError> = unsafe \{
-        get_mapped_storage_file("{container}", StorageFileType::PackageMap)
-        .and_then(|package_map| get_package_read_context(&package_map, "{package}"))
-        .map(|context| context.map(|c| c.boolean_start_index))
-    };
-
-    static ref FLAG_VAL_MAP: Result<Mmap, AconfigStorageError> = unsafe \{
-        get_mapped_storage_file("{container}", StorageFileType::FlagVal)
-    };
-    {{ -endif }}
-
+{{ if allow_instrumentation }}
+static READ_FROM_NEW_STORAGE: LazyLock<bool> = LazyLock::new(|| unsafe \{
+    Path::new("/metadata/aconfig/boot/enable_only_new_storage").exists()
+});
+
+static PACKAGE_OFFSET: LazyLock<Result<Option<u32>, AconfigStorageError>> = LazyLock::new(|| unsafe \{
+    get_mapped_storage_file("{container}", StorageFileType::PackageMap)
+    .and_then(|package_map| get_package_read_context(&package_map, "{package}"))
+    .map(|context| context.map(|c| c.boolean_start_index))
+});
+
+static FLAG_VAL_MAP: LazyLock<Result<Mmap, AconfigStorageError>> = LazyLock::new(|| unsafe \{
+    get_mapped_storage_file("{container}", StorageFileType::FlagVal)
+});
+{{ -endif }}
 {{ -for flag in template_flags }}
-    {{ -if flag.readwrite }}
-    /// flag value cache for {flag.name}
-    {{ if allow_instrumentation }}
-    static ref CACHED_{flag.name}: bool = \{
-        let result = flags_rust::GetServerConfigurableFlag(
-            "aconfig_flags.{flag.device_config_namespace}",
-            "{flag.device_config_flag}",
-            "{flag.default_value}") == "true";
-
-        if Path::new(STORAGE_MIGRATION_MARKER_FILE).exists() \{
-            // This will be called multiple times. Subsequent calls after the first are noops.
-            logger::init(
-                logger::Config::default()
-                    .with_tag_on_device(MIGRATION_LOG_TAG)
-                    .with_max_level(LevelFilter::Info));
-
-            let aconfig_storage_result = FLAG_VAL_MAP
-                .as_ref()
-                .map_err(|err| format!("failed to get flag val map: \{err}"))
-                .and_then(|flag_val_map| \{
-                    PACKAGE_OFFSET
-                        .as_ref()
-                        .map_err(|err| format!("failed to get package read offset: \{err}"))
-                        .and_then(|package_offset| \{
-                            match package_offset \{
-                                Some(offset) => \{
-                                    get_boolean_flag_value(&flag_val_map, offset + {flag.flag_offset})
-                                        .map_err(|err| format!("failed to get flag: \{err}"))
-                                },
-                                None => Err("no context found for package '{package}'".to_string())
-                            }
-                        })
-                    });
 
-            match aconfig_storage_result \{
-                Ok(storage_result) if storage_result == result => \{
-                    log!(Level::Info, "AconfigTestMission1: success! flag '{flag.name}' contained correct value. Legacy storage was \{result}, new storage was \{storage_result}");
-                },
-                Ok(storage_result) => \{
-                    log!(Level::Error, "AconfigTestMission1: error: mismatch for flag '{flag.name}'. Legacy storage was \{result}, new storage was \{storage_result}");
-                },
-                Err(err) => \{
-                    log!(Level::Error, "AconfigTestMission1: error: \{err}")
-                }
+{{ -if flag.readwrite }}
+/// flag value cache for {flag.name}
+{{ if allow_instrumentation }}
+static CACHED_{flag.name}: LazyLock<bool> = LazyLock::new(|| \{
+
+    if *READ_FROM_NEW_STORAGE \{
+        // This will be called multiple times. Subsequent calls after the first are noops.
+        logger::init(
+            logger::Config::default()
+                .with_tag_on_device("aconfig_rust_codegen")
+                .with_max_level(LevelFilter::Info));
+
+        let flag_value_result = FLAG_VAL_MAP
+            .as_ref()
+            .map_err(|err| format!("failed to get flag val map: \{err}"))
+            .and_then(|flag_val_map| \{
+                PACKAGE_OFFSET
+                    .as_ref()
+                    .map_err(|err| format!("failed to get package read offset: \{err}"))
+                    .and_then(|package_offset| \{
+                        match package_offset \{
+                            Some(offset) => \{
+                                get_boolean_flag_value(&flag_val_map, offset + {flag.flag_offset})
+                                    .map_err(|err| format!("failed to get flag: \{err}"))
+                            },
+                            None => Err("no context found for package '{package}'".to_string())
+                        }
+                    })
+                });
+
+        match flag_value_result \{
+            Ok(flag_value) => \{
+                return flag_value;
+            },
+            Err(err) => \{
+                log!(Level::Error, "aconfig_rust_codegen: error: \{err}");
+                panic!("failed to read flag value: \{err}");
             }
         }
+    } else \{
+        flags_rust::GetServerConfigurableFlag(
+            "aconfig_flags.{flag.device_config_namespace}",
+            "{flag.device_config_flag}",
+            "{flag.default_value}") == "true"
+    }
 
-        result
-        };
-    {{ else }}
-    static ref CACHED_{flag.name}: bool = flags_rust::GetServerConfigurableFlag(
-        "aconfig_flags.{flag.device_config_namespace}",
-        "{flag.device_config_flag}",
-        "{flag.default_value}") == "true";
-    {{ endif }}
-    {{ -endif }}
+});
+{{ else }}
+static CACHED_{flag.name}: LazyLock<bool> = LazyLock::new(|| flags_rust::GetServerConfigurableFlag(
+    "aconfig_flags.{flag.device_config_namespace}",
+    "{flag.device_config_flag}",
+    "{flag.default_value}") == "true");
+{{ endif }}
+{{ -endif }}
 {{ -endfor }}
-}
 {{ -endif }}
 
 impl FlagProvider \{
@@ -107,73 +104,11 @@ pub static PROVIDER: FlagProvider = FlagProvider;
 {{ for flag in template_flags }}
 /// query flag {flag.name}
 #[inline(always)]
-{{ -if flag.readwrite }}
 pub fn {flag.name}() -> bool \{
+{{ -if flag.readwrite }}
     PROVIDER.{flag.name}()
 {{ -else }}
-pub fn {flag.name}() -> bool \{
-    {{ if not allow_instrumentation }}
     {flag.default_value}
-    {{ else }}
-
-    let result = {flag.default_value};
-    if !Path::new(STORAGE_MIGRATION_MARKER_FILE).exists() \{
-        return result;
-    }
-
-    // This will be called multiple times. Subsequent calls after the first
-    // are noops.
-    logger::init(
-        logger::Config::default()
-            .with_tag_on_device(MIGRATION_LOG_TAG)
-            .with_max_level(LevelFilter::Info),
-    );
-
-    unsafe \{
-        let package_map = match get_mapped_storage_file("{flag.container}", StorageFileType::PackageMap) \{
-            Ok(file) => file,
-            Err(err) => \{
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag '{flag.name}': \{err}");
-                return result;
-            }
-        };
-
-        let package_read_context = match get_package_read_context(&package_map, "{package}") \{
-            Ok(Some(context)) => context,
-            Ok(None) => \{
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag '{flag.name}': did not get context");
-                return result;
-            },
-            Err(err) => \{
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag '{flag.name}': \{err}");
-                return result;
-            }
-        };
-        let flag_val_map = match get_mapped_storage_file("{flag.container}", StorageFileType::FlagVal) \{
-            Ok(val_map) => val_map,
-            Err(err) => \{
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag '{flag.name}': \{err}");
-                return result;
-            }
-        };
-        let value = match get_boolean_flag_value(&flag_val_map, {flag.flag_offset} + package_read_context.boolean_start_index) \{
-            Ok(val) => val,
-            Err(err) => \{
-                log!(Level::Error, "AconfigTestMission1: error: failed to read flag '{flag.name}': \{err}");
-                return result;
-            }
-        };
-
-        if result != value \{
-            log!(Level::Error, "AconfigTestMission1: error: flag mismatch for '{flag.name}'. Legacy storage was \{result}, new storage was \{value}");
-        } else \{
-            let default_value = {flag.default_value};
-            log!(Level::Info, "AconfigTestMission1: success! flag '{flag.name}' contained correct value. Legacy storage was \{default_value}, new storage was \{value}");
-        }
-    }
-
-    result
-    {{ endif }}
 {{ -endif }}
 }
 {{ endfor }}
diff --git a/tools/aconfig/aconfig_device_paths/Android.bp b/tools/aconfig/aconfig_device_paths/Android.bp
index 2c771e09f5..dda7a55903 100644
--- a/tools/aconfig/aconfig_device_paths/Android.bp
+++ b/tools/aconfig/aconfig_device_paths/Android.bp
@@ -39,13 +39,33 @@ rust_library {
 
 genrule {
     name: "libaconfig_java_device_paths_src",
-    srcs: ["src/DevicePathsTemplate.java"],
-    out: ["DevicePaths.java"],
+    srcs: ["src/DeviceProtosTemplate.java"],
+    out: ["DeviceProtos.java"],
     tool_files: ["partition_aconfig_flags_paths.txt"],
-    cmd: "sed -e '/TEMPLATE/{r$(location partition_aconfig_flags_paths.txt)' -e 'd}' $(in) > $(out)"
+    cmd: "sed -e '/TEMPLATE/{r$(location partition_aconfig_flags_paths.txt)' -e 'd}' $(in) > $(out)",
 }
 
 java_library {
     name: "aconfig_device_paths_java",
     srcs: [":libaconfig_java_device_paths_src"],
+    static_libs: [
+        "libaconfig_java_proto_nano",
+    ],
+    sdk_version: "core_platform",
+    apex_available: [
+        "//apex_available:platform",
+    ],
+}
+
+genrule {
+    name: "libaconfig_java_host_device_paths_src",
+    srcs: ["src/HostDeviceProtosTemplate.java"],
+    out: ["HostDeviceProtos.java"],
+    tool_files: ["partition_aconfig_flags_paths.txt"],
+    cmd: "sed -e '/TEMPLATE/{r$(location partition_aconfig_flags_paths.txt)' -e 'd}' $(in) > $(out)",
+}
+
+java_library_host {
+    name: "aconfig_host_device_paths_java",
+    srcs: [":libaconfig_java_host_device_paths_src"],
 }
diff --git a/tools/aconfig/aconfig_device_paths/src/DevicePathsTemplate.java b/tools/aconfig/aconfig_device_paths/src/DeviceProtosTemplate.java
similarity index 60%
rename from tools/aconfig/aconfig_device_paths/src/DevicePathsTemplate.java
rename to tools/aconfig/aconfig_device_paths/src/DeviceProtosTemplate.java
index f27b9bd360..4d4119947f 100644
--- a/tools/aconfig/aconfig_device_paths/src/DevicePathsTemplate.java
+++ b/tools/aconfig/aconfig_device_paths/src/DeviceProtosTemplate.java
@@ -15,7 +15,12 @@
  */
 package android.aconfig;
 
+import android.aconfig.nano.Aconfig.parsed_flag;
+import android.aconfig.nano.Aconfig.parsed_flags;
+
 import java.io.File;
+import java.io.FileInputStream;
+import java.io.IOException;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
@@ -23,20 +28,44 @@ import java.util.List;
 /**
  * @hide
  */
-public class DevicePaths {
-    static final String[] PATHS = {
+public class DeviceProtos {
+	public static final String[] PATHS = {
         TEMPLATE
     };
 
     private static final String APEX_DIR = "/apex";
     private static final String APEX_ACONFIG_PATH_SUFFIX = "/etc/aconfig_flags.pb";
 
+    /**
+     * Returns a list of all on-device aconfig protos.
+     *
+     * May throw an exception if the protos can't be read at the call site. For
+     * example, some of the protos are in the apex/ partition, which is mounted
+     * somewhat late in the boot process.
+     *
+     * @throws IOException if we can't read one of the protos yet
+     * @return a list of all on-device aconfig protos
+     */
+    public static List<parsed_flag> loadAndParseFlagProtos() throws IOException {
+        ArrayList<parsed_flag> result = new ArrayList();
+
+        for (String path : parsedFlagsProtoPaths()) {
+            try (FileInputStream inputStream = new FileInputStream(path)) {
+                parsed_flags parsedFlags = parsed_flags.parseFrom(inputStream.readAllBytes());
+                for (parsed_flag flag : parsedFlags.parsedFlag) {
+                    result.add(flag);
+                }
+            }
+        }
+
+        return result;
+    }
 
     /**
      * Returns the list of all on-device aconfig protos paths.
      * @hide
      */
-    public List<String> parsedFlagsProtoPaths() {
+    public static List<String> parsedFlagsProtoPaths() {
         ArrayList<String> paths = new ArrayList(Arrays.asList(PATHS));
 
         File apexDirectory = new File(APEX_DIR);
diff --git a/tools/aconfig/aconfig_device_paths/src/HostDeviceProtosTemplate.java b/tools/aconfig/aconfig_device_paths/src/HostDeviceProtosTemplate.java
new file mode 100644
index 0000000000..844232b9e1
--- /dev/null
+++ b/tools/aconfig/aconfig_device_paths/src/HostDeviceProtosTemplate.java
@@ -0,0 +1,82 @@
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
+package android.aconfig;
+
+import java.io.File;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Set;
+import java.util.stream.Collectors;
+
+/**
+ * A host lib that can read all aconfig proto file paths on a given device.
+ */
+public class HostDeviceProtos {
+    /**
+     * An interface that executes ADB command and return the result.
+     */
+    public static interface AdbCommandExecutor {
+        /** Executes the ADB command. */
+        String executeAdbCommand(String command);
+    }
+
+    static final String[] PATHS = {
+        TEMPLATE
+    };
+
+    private static final String APEX_DIR = "/apex";
+    private static final String RECURSIVELY_LIST_APEX_DIR_COMMAND = "shell find /apex | grep aconfig_flags";
+    private static final String APEX_ACONFIG_PATH_SUFFIX = "/etc/aconfig_flags.pb";
+
+
+    /**
+     * Returns the list of all on-device aconfig proto paths from host side.
+     */
+    public static List<String> parsedFlagsProtoPaths(AdbCommandExecutor adbCommandExecutor) {
+        ArrayList<String> paths = new ArrayList(Arrays.asList(PATHS));
+
+        String adbCommandOutput = adbCommandExecutor.executeAdbCommand(
+            RECURSIVELY_LIST_APEX_DIR_COMMAND);
+
+        if (adbCommandOutput == null) {
+            return paths;
+        }
+
+        Set<String> allFiles = new HashSet<>(Arrays.asList(adbCommandOutput.split("\n")));
+
+        Set<String> subdirs = allFiles.stream().map(file -> {
+            String[] filePaths = file.split("/");
+            // The first element is "", the second element is "apex".
+            return filePaths.length > 2 ? filePaths[2] : "";
+        }).collect(Collectors.toSet());
+
+        for (String prefix : subdirs) {
+            // For each mainline modules, there are two directories, one <modulepackage>/,
+            // and one <modulepackage>@<versioncode>/. Just read the former.
+            if (prefix.contains("@")) {
+                continue;
+            }
+
+            String protoPath = APEX_DIR + "/" + prefix + APEX_ACONFIG_PATH_SUFFIX;
+            if (allFiles.contains(protoPath)) {
+                paths.add(protoPath);
+            }
+        }
+        return paths;
+    }
+}
diff --git a/tools/aconfig/aconfig_device_paths/src/lib.rs b/tools/aconfig/aconfig_device_paths/src/lib.rs
index 7480b3002c..9ab9cea267 100644
--- a/tools/aconfig/aconfig_device_paths/src/lib.rs
+++ b/tools/aconfig/aconfig_device_paths/src/lib.rs
@@ -30,9 +30,11 @@ fn read_partition_paths() -> Vec<PathBuf> {
         .collect()
 }
 
-/// Determine all paths that contain an aconfig protobuf file.
+/// Determines all paths that contain an aconfig protobuf file,
+/// filtering out nonexistent partition protobuf files.
 pub fn parsed_flags_proto_paths() -> Result<Vec<PathBuf>> {
-    let mut result: Vec<PathBuf> = read_partition_paths();
+    let mut result: Vec<PathBuf> =
+        read_partition_paths().into_iter().filter(|s| s.exists()).collect();
 
     for dir in fs::read_dir("/apex")? {
         let dir = dir?;
diff --git a/tools/aconfig/aconfig_flags/Android.bp b/tools/aconfig/aconfig_flags/Android.bp
new file mode 100644
index 0000000000..e327ced26c
--- /dev/null
+++ b/tools/aconfig/aconfig_flags/Android.bp
@@ -0,0 +1,46 @@
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
+rust_library {
+    name: "libaconfig_flags",
+    crate_name: "aconfig_flags",
+    srcs: [
+        "src/lib.rs",
+    ],
+    rustlibs: [
+        "libaconfig_flags_rust",
+    ],
+    host_supported: true,
+}
+
+aconfig_declarations {
+    name: "aconfig_flags",
+    package: "com.android.aconfig.flags",
+    container: "system",
+    srcs: ["flags.aconfig"],
+}
+
+rust_aconfig_library {
+    name: "libaconfig_flags_rust",
+    crate_name: "aconfig_flags_rust",
+    aconfig_declarations: "aconfig_flags",
+    host_supported: true,
+}
+
+cc_aconfig_library {
+    name: "libaconfig_flags_cc",
+    aconfig_declarations: "aconfig_flags",
+}
diff --git a/tools/aconfig/aconfig_flags/Cargo.toml b/tools/aconfig/aconfig_flags/Cargo.toml
new file mode 100644
index 0000000000..6eb9f14058
--- /dev/null
+++ b/tools/aconfig/aconfig_flags/Cargo.toml
@@ -0,0 +1,10 @@
+[package]
+name = "aconfig_flags"
+version = "0.1.0"
+edition = "2021"
+
+[features]
+default = ["cargo"]
+cargo = []
+
+[dependencies]
\ No newline at end of file
diff --git a/tools/aconfig/aconfig_flags/flags.aconfig b/tools/aconfig/aconfig_flags/flags.aconfig
new file mode 100644
index 0000000000..db8b1b7904
--- /dev/null
+++ b/tools/aconfig/aconfig_flags/flags.aconfig
@@ -0,0 +1,9 @@
+package: "com.android.aconfig.flags"
+container: "system"
+
+flag {
+  name: "enable_only_new_storage"
+  namespace: "core_experiments_team_internal"
+  bug: "312235596"
+  description: "When enabled, aconfig flags are read from the new aconfig storage only."
+}
diff --git a/tools/aconfig/aconfig_flags/src/lib.rs b/tools/aconfig/aconfig_flags/src/lib.rs
new file mode 100644
index 0000000000..a607efb7d4
--- /dev/null
+++ b/tools/aconfig/aconfig_flags/src/lib.rs
@@ -0,0 +1,47 @@
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
+//! `aconfig_flags` is a crate for reading aconfig flags from Rust
+// When building with the Android tool-chain
+//
+//   - the flag functions will read from aconfig_flags_inner
+//   - the feature "cargo" will be disabled
+//
+// When building with cargo
+//
+//   - the flag functions will all return some trivial value, like true
+//   - the feature "cargo" will be enabled
+//
+// This module hides these differences from the rest of aconfig.
+
+/// Module used when building with the Android tool-chain
+#[cfg(not(feature = "cargo"))]
+pub mod auto_generated {
+    /// Returns the value for the enable_only_new_storage flag.
+    pub fn enable_only_new_storage() -> bool {
+        aconfig_flags_rust::enable_only_new_storage()
+    }
+}
+
+/// Module used when building with cargo
+#[cfg(feature = "cargo")]
+pub mod auto_generated {
+    /// Returns a placeholder value for the enable_only_new_storage flag.
+    pub fn enable_only_new_storage() -> bool {
+        // Used only to enable typechecking and testing with cargo
+        true
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/Android.bp b/tools/aconfig/aconfig_storage_file/Android.bp
index e066e31ac1..e875c7be6a 100644
--- a/tools/aconfig/aconfig_storage_file/Android.bp
+++ b/tools/aconfig/aconfig_storage_file/Android.bp
@@ -14,6 +14,7 @@ rust_defaults {
         "libclap",
         "libcxx",
         "libaconfig_storage_protos",
+        "libserde",
     ],
 }
 
@@ -36,7 +37,10 @@ rust_binary_host {
     name: "aconfig-storage",
     defaults: ["aconfig_storage_file.defaults"],
     srcs: ["src/main.rs"],
-    rustlibs: ["libaconfig_storage_file"],
+    rustlibs: [
+        "libaconfig_storage_file",
+        "libserde_json",
+    ],
 }
 
 rust_test_host {
@@ -137,3 +141,29 @@ cc_library {
     min_sdk_version: "29",
     double_loadable: true,
 }
+
+// storage file parse api java library
+java_library {
+    name: "aconfig_storage_file_java",
+    srcs: [
+        "srcs/**/*.java",
+    ],
+    sdk_version: "core_current",
+    min_sdk_version: "29",
+    host_supported: true,
+    apex_available: [
+        "//apex_available:platform",
+        "//apex_available:anyapex",
+    ],
+}
+
+// storage file parse api java library for core library
+java_library {
+    name: "aconfig_storage_file_java_none",
+    srcs: [
+        "srcs/**/*.java",
+    ],
+    sdk_version: "none",
+    system_modules: "core-all-system-modules",
+    host_supported: true,
+}
diff --git a/tools/aconfig/aconfig_storage_file/Cargo.toml b/tools/aconfig/aconfig_storage_file/Cargo.toml
index 192dfad40a..a40557803f 100644
--- a/tools/aconfig/aconfig_storage_file/Cargo.toml
+++ b/tools/aconfig/aconfig_storage_file/Cargo.toml
@@ -14,6 +14,8 @@ tempfile = "3.9.0"
 thiserror = "1.0.56"
 clap = { version = "4.1.8", features = ["derive"] }
 cxx = "1.0"
+serde = { version = "1.0.152", features = ["derive"] }
+serde_json = "1.0.93"
 
 [[bin]]
 name = "aconfig-storage"
diff --git a/tools/aconfig/aconfig_storage_file/src/flag_info.rs b/tools/aconfig/aconfig_storage_file/src/flag_info.rs
index beac38d156..f090396901 100644
--- a/tools/aconfig/aconfig_storage_file/src/flag_info.rs
+++ b/tools/aconfig/aconfig_storage_file/src/flag_info.rs
@@ -20,10 +20,11 @@
 use crate::{read_str_from_bytes, read_u32_from_bytes, read_u8_from_bytes};
 use crate::{AconfigStorageError, StorageFileType};
 use anyhow::anyhow;
+use serde::{Deserialize, Serialize};
 use std::fmt;
 
 /// Flag info header struct
-#[derive(PartialEq)]
+#[derive(PartialEq, Serialize, Deserialize)]
 pub struct FlagInfoHeader {
     pub version: u32,
     pub container: String,
@@ -89,7 +90,7 @@ impl FlagInfoHeader {
 }
 
 /// bit field for flag info
-#[derive(Clone, Debug, PartialEq, Eq)]
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
 pub enum FlagInfoBit {
     HasServerOverride = 1 << 0,
     IsReadWrite = 1 << 1,
@@ -97,7 +98,7 @@ pub enum FlagInfoBit {
 }
 
 /// Flag info node struct
-#[derive(PartialEq, Clone)]
+#[derive(PartialEq, Clone, Serialize, Deserialize)]
 pub struct FlagInfoNode {
     pub attributes: u8,
 }
@@ -138,7 +139,7 @@ impl FlagInfoNode {
 }
 
 /// Flag info list struct
-#[derive(PartialEq)]
+#[derive(PartialEq, Serialize, Deserialize)]
 pub struct FlagInfoList {
     pub header: FlagInfoHeader,
     pub nodes: Vec<FlagInfoNode>,
diff --git a/tools/aconfig/aconfig_storage_file/src/flag_table.rs b/tools/aconfig/aconfig_storage_file/src/flag_table.rs
index 64b90eabfa..0588fe5039 100644
--- a/tools/aconfig/aconfig_storage_file/src/flag_table.rs
+++ b/tools/aconfig/aconfig_storage_file/src/flag_table.rs
@@ -23,10 +23,11 @@ use crate::{
 };
 use crate::{AconfigStorageError, StorageFileType, StoredFlagType};
 use anyhow::anyhow;
+use serde::{Deserialize, Serialize};
 use std::fmt;
 
 /// Flag table header struct
-#[derive(PartialEq)]
+#[derive(PartialEq, Serialize, Deserialize)]
 pub struct FlagTableHeader {
     pub version: u32,
     pub container: String,
@@ -95,7 +96,7 @@ impl FlagTableHeader {
 }
 
 /// Flag table node struct
-#[derive(PartialEq, Clone)]
+#[derive(PartialEq, Clone, Serialize, Deserialize)]
 pub struct FlagTableNode {
     pub package_id: u32,
     pub flag_name: String,
@@ -150,11 +151,11 @@ impl FlagTableNode {
     /// Calculate node bucket index
     pub fn find_bucket_index(package_id: u32, flag_name: &str, num_buckets: u32) -> u32 {
         let full_flag_name = package_id.to_string() + "/" + flag_name;
-        get_bucket_index(&full_flag_name, num_buckets)
+        get_bucket_index(full_flag_name.as_bytes(), num_buckets)
     }
 }
 
-#[derive(PartialEq)]
+#[derive(PartialEq, Serialize, Deserialize)]
 pub struct FlagTable {
     pub header: FlagTableHeader,
     pub buckets: Vec<Option<u32>>,
diff --git a/tools/aconfig/aconfig_storage_file/src/flag_value.rs b/tools/aconfig/aconfig_storage_file/src/flag_value.rs
index 506924b339..b64c10ecdd 100644
--- a/tools/aconfig/aconfig_storage_file/src/flag_value.rs
+++ b/tools/aconfig/aconfig_storage_file/src/flag_value.rs
@@ -20,10 +20,11 @@
 use crate::{read_str_from_bytes, read_u32_from_bytes, read_u8_from_bytes};
 use crate::{AconfigStorageError, StorageFileType};
 use anyhow::anyhow;
+use serde::{Deserialize, Serialize};
 use std::fmt;
 
 /// Flag value header struct
-#[derive(PartialEq)]
+#[derive(PartialEq, Serialize, Deserialize)]
 pub struct FlagValueHeader {
     pub version: u32,
     pub container: String,
@@ -89,7 +90,7 @@ impl FlagValueHeader {
 }
 
 /// Flag value list struct
-#[derive(PartialEq)]
+#[derive(PartialEq, Serialize, Deserialize)]
 pub struct FlagValueList {
     pub header: FlagValueHeader,
     pub booleans: Vec<bool>,
diff --git a/tools/aconfig/aconfig_storage_file/src/lib.rs b/tools/aconfig/aconfig_storage_file/src/lib.rs
index 26e9c1a3be..cf52bc017d 100644
--- a/tools/aconfig/aconfig_storage_file/src/lib.rs
+++ b/tools/aconfig/aconfig_storage_file/src/lib.rs
@@ -37,19 +37,21 @@ pub mod flag_table;
 pub mod flag_value;
 pub mod package_table;
 pub mod protos;
+pub mod sip_hasher13;
 pub mod test_utils;
 
 use anyhow::anyhow;
+use serde::{Deserialize, Serialize};
 use std::cmp::Ordering;
-use std::collections::hash_map::DefaultHasher;
 use std::fs::File;
-use std::hash::{Hash, Hasher};
+use std::hash::Hasher;
 use std::io::Read;
 
 pub use crate::flag_info::{FlagInfoBit, FlagInfoHeader, FlagInfoList, FlagInfoNode};
 pub use crate::flag_table::{FlagTable, FlagTableHeader, FlagTableNode};
 pub use crate::flag_value::{FlagValueHeader, FlagValueList};
 pub use crate::package_table::{PackageTable, PackageTableHeader, PackageTableNode};
+pub use crate::sip_hasher13::SipHasher13;
 
 use crate::AconfigStorageError::{
     BytesParseFail, HashTableSizeLimit, InvalidFlagValueType, InvalidStoredFlagType,
@@ -106,7 +108,7 @@ impl TryFrom<u8> for StorageFileType {
 
 /// Flag type enum as stored by storage file
 /// ONLY APPEND, NEVER REMOVE FOR BACKWARD COMPATIBILITY. THE MAX IS U16.
-#[derive(Clone, Copy, Debug, PartialEq, Eq)]
+#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
 pub enum StoredFlagType {
     ReadWriteBoolean = 0,
     ReadOnlyBoolean = 1,
@@ -211,10 +213,12 @@ pub fn get_table_size(entries: u32) -> Result<u32, AconfigStorageError> {
 }
 
 /// Get the corresponding bucket index given the key and number of buckets
-pub(crate) fn get_bucket_index<T: Hash>(val: &T, num_buckets: u32) -> u32 {
-    let mut s = DefaultHasher::new();
-    val.hash(&mut s);
-    (s.finish() % num_buckets as u64) as u32
+pub(crate) fn get_bucket_index(val: &[u8], num_buckets: u32) -> u32 {
+    let mut s = SipHasher13::new();
+    s.write(val);
+    s.write_u8(0xff);
+    let ret = (s.finish() % num_buckets as u64) as u32;
+    ret
 }
 
 /// Read and parse bytes as u8
diff --git a/tools/aconfig/aconfig_storage_file/src/main.rs b/tools/aconfig/aconfig_storage_file/src/main.rs
index 8b9e38da02..a9cfd19066 100644
--- a/tools/aconfig/aconfig_storage_file/src/main.rs
+++ b/tools/aconfig/aconfig_storage_file/src/main.rs
@@ -20,9 +20,29 @@ use aconfig_storage_file::{
     list_flags, list_flags_with_info, read_file_to_bytes, AconfigStorageError, FlagInfoList,
     FlagTable, FlagValueList, PackageTable, StorageFileType,
 };
-
 use clap::{builder::ArgAction, Arg, Command};
+use serde::Serialize;
+use serde_json;
+use std::fmt;
+use std::fs;
+use std::fs::File;
+use std::io::Write;
 
+/**
+ * Usage Examples
+ *
+ * Print file:
+ * $ aconfig-storage print --file=path/to/flag.map --type=flag_map
+ *
+ * List flags:
+ * $ aconfig-storage list --flag-map=path/to/flag.map \
+ * --flag-val=path/to/flag.val --package-map=path/to/package.map
+ *
+ * Write binary file for testing:
+ * $ aconfig-storage print --file=path/to/flag.map --type=flag_map --format=json > flag_map.json
+ * $ vim flag_map.json // Manually make updates
+ * $ aconfig-storage write-bytes --input-file=flag_map.json --output-file=path/to/flag.map --type=flag_map
+ */
 fn cli() -> Command {
     Command::new("aconfig-storage")
         .subcommand_required(true)
@@ -34,7 +54,8 @@ fn cli() -> Command {
                         .long("type")
                         .required(true)
                         .value_parser(|s: &str| StorageFileType::try_from(s)),
-                ),
+                )
+                .arg(Arg::new("format").long("format").required(false).action(ArgAction::Set)),
         )
         .subcommand(
             Command::new("list")
@@ -50,41 +71,75 @@ fn cli() -> Command {
                     Arg::new("flag-info").long("flag-info").required(false).action(ArgAction::Set),
                 ),
         )
+        .subcommand(
+            Command::new("write-bytes")
+                // Where to write the output bytes. Suggest to use the StorageFileType names (e.g. flag.map).
+                .arg(
+                    Arg::new("output-file")
+                        .long("output-file")
+                        .required(true)
+                        .action(ArgAction::Set),
+                )
+                // Input file should be json.
+                .arg(
+                    Arg::new("input-file").long("input-file").required(true).action(ArgAction::Set),
+                )
+                .arg(
+                    Arg::new("type")
+                        .long("type")
+                        .required(true)
+                        .value_parser(|s: &str| StorageFileType::try_from(s)),
+                ),
+        )
 }
 
 fn print_storage_file(
     file_path: &str,
     file_type: &StorageFileType,
+    as_json: bool,
 ) -> Result<(), AconfigStorageError> {
     let bytes = read_file_to_bytes(file_path)?;
     match file_type {
         StorageFileType::PackageMap => {
             let package_table = PackageTable::from_bytes(&bytes)?;
-            println!("{:?}", package_table);
+            println!("{}", to_print_format(package_table, as_json));
         }
         StorageFileType::FlagMap => {
             let flag_table = FlagTable::from_bytes(&bytes)?;
-            println!("{:?}", flag_table);
+            println!("{}", to_print_format(flag_table, as_json));
         }
         StorageFileType::FlagVal => {
             let flag_value = FlagValueList::from_bytes(&bytes)?;
-            println!("{:?}", flag_value);
+            println!("{}", to_print_format(flag_value, as_json));
         }
         StorageFileType::FlagInfo => {
             let flag_info = FlagInfoList::from_bytes(&bytes)?;
-            println!("{:?}", flag_info);
+            println!("{}", to_print_format(flag_info, as_json));
         }
     }
     Ok(())
 }
 
+fn to_print_format<T>(file_contents: T, as_json: bool) -> String
+where
+    T: Serialize + fmt::Debug,
+{
+    if as_json {
+        serde_json::to_string(&file_contents).unwrap()
+    } else {
+        format!("{:?}", file_contents)
+    }
+}
+
 fn main() -> Result<(), AconfigStorageError> {
     let matches = cli().get_matches();
     match matches.subcommand() {
         Some(("print", sub_matches)) => {
             let file_path = sub_matches.get_one::<String>("file").unwrap();
             let file_type = sub_matches.get_one::<StorageFileType>("type").unwrap();
-            print_storage_file(file_path, file_type)?
+            let format = sub_matches.get_one::<String>("format");
+            let as_json: bool = format == Some(&"json".to_string());
+            print_storage_file(file_path, file_type, as_json)?
         }
         Some(("list", sub_matches)) => {
             let package_map = sub_matches.get_one::<String>("package-map").unwrap();
@@ -96,10 +151,10 @@ fn main() -> Result<(), AconfigStorageError> {
                     let flags = list_flags_with_info(package_map, flag_map, flag_val, info_file)?;
                     for flag in flags.iter() {
                         println!(
-                            "{} {} {} {:?} IsReadWrite: {}, HasServerOverride: {}, HasLocalOverride: {}",
-                            flag.package_name, flag.flag_name, flag.flag_value, flag.value_type,
-                            flag.is_readwrite, flag.has_server_override, flag.has_local_override,
-                        );
+                          "{} {} {} {:?} IsReadWrite: {}, HasServerOverride: {}, HasLocalOverride: {}",
+                          flag.package_name, flag.flag_name, flag.flag_value, flag.value_type,
+                          flag.is_readwrite, flag.has_server_override, flag.has_local_override,
+                      );
                     }
                 }
                 None => {
@@ -113,6 +168,40 @@ fn main() -> Result<(), AconfigStorageError> {
                 }
             }
         }
+        // Converts JSON of the file into raw bytes (as is used on-device).
+        // Intended to generate/easily update these files for testing.
+        Some(("write-bytes", sub_matches)) => {
+            let input_file_path = sub_matches.get_one::<String>("input-file").unwrap();
+            let input_json = fs::read_to_string(input_file_path).unwrap();
+
+            let file_type = sub_matches.get_one::<StorageFileType>("type").unwrap();
+            let output_bytes: Vec<u8>;
+            match file_type {
+                StorageFileType::FlagVal => {
+                    let list: FlagValueList = serde_json::from_str(&input_json).unwrap();
+                    output_bytes = list.into_bytes();
+                }
+                StorageFileType::FlagInfo => {
+                    let list: FlagInfoList = serde_json::from_str(&input_json).unwrap();
+                    output_bytes = list.into_bytes();
+                }
+                StorageFileType::FlagMap => {
+                    let table: FlagTable = serde_json::from_str(&input_json).unwrap();
+                    output_bytes = table.into_bytes();
+                }
+                StorageFileType::PackageMap => {
+                    let table: PackageTable = serde_json::from_str(&input_json).unwrap();
+                    output_bytes = table.into_bytes();
+                }
+            }
+
+            let output_file_path = sub_matches.get_one::<String>("output-file").unwrap();
+            let file = File::create(output_file_path);
+            if file.is_err() {
+                panic!("can't make file");
+            }
+            let _ = file.unwrap().write_all(&output_bytes);
+        }
         _ => unreachable!(),
     }
     Ok(())
diff --git a/tools/aconfig/aconfig_storage_file/src/package_table.rs b/tools/aconfig/aconfig_storage_file/src/package_table.rs
index b734972f33..a5bd9e6446 100644
--- a/tools/aconfig/aconfig_storage_file/src/package_table.rs
+++ b/tools/aconfig/aconfig_storage_file/src/package_table.rs
@@ -20,10 +20,11 @@
 use crate::{get_bucket_index, read_str_from_bytes, read_u32_from_bytes, read_u8_from_bytes};
 use crate::{AconfigStorageError, StorageFileType};
 use anyhow::anyhow;
+use serde::{Deserialize, Serialize};
 use std::fmt;
 
 /// Package table header struct
-#[derive(PartialEq)]
+#[derive(PartialEq, Serialize, Deserialize)]
 pub struct PackageTableHeader {
     pub version: u32,
     pub container: String,
@@ -92,7 +93,7 @@ impl PackageTableHeader {
 }
 
 /// Package table node struct
-#[derive(PartialEq)]
+#[derive(PartialEq, Serialize, Deserialize)]
 pub struct PackageTableNode {
     pub package_name: String,
     pub package_id: u32,
@@ -146,12 +147,12 @@ impl PackageTableNode {
     /// construction side (aconfig binary) and consumption side (flag read lib)
     /// use the same method of hashing
     pub fn find_bucket_index(package: &str, num_buckets: u32) -> u32 {
-        get_bucket_index(&package, num_buckets)
+        get_bucket_index(package.as_bytes(), num_buckets)
     }
 }
 
 /// Package table struct
-#[derive(PartialEq)]
+#[derive(PartialEq, Serialize, Deserialize)]
 pub struct PackageTable {
     pub header: PackageTableHeader,
     pub buckets: Vec<Option<u32>>,
diff --git a/tools/aconfig/aconfig_storage_file/src/sip_hasher13.rs b/tools/aconfig/aconfig_storage_file/src/sip_hasher13.rs
new file mode 100644
index 0000000000..9be3175e18
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/src/sip_hasher13.rs
@@ -0,0 +1,327 @@
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
+
+//! An implementation of SipHash13
+
+use std::cmp;
+use std::mem;
+use std::ptr;
+use std::slice;
+
+use std::hash::Hasher;
+
+/// An implementation of SipHash 2-4.
+///
+#[derive(Debug, Clone, Default)]
+pub struct SipHasher13 {
+    k0: u64,
+    k1: u64,
+    length: usize, // how many bytes we've processed
+    state: State,  // hash State
+    tail: u64,     // unprocessed bytes le
+    ntail: usize,  // how many bytes in tail are valid
+}
+
+#[derive(Debug, Clone, Copy, Default)]
+#[repr(C)]
+struct State {
+    // v0, v2 and v1, v3 show up in pairs in the algorithm,
+    // and simd implementations of SipHash will use vectors
+    // of v02 and v13. By placing them in this order in the struct,
+    // the compiler can pick up on just a few simd optimizations by itself.
+    v0: u64,
+    v2: u64,
+    v1: u64,
+    v3: u64,
+}
+
+macro_rules! compress {
+    ($state:expr) => {{
+        compress!($state.v0, $state.v1, $state.v2, $state.v3)
+    }};
+    ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {{
+        $v0 = $v0.wrapping_add($v1);
+        $v1 = $v1.rotate_left(13);
+        $v1 ^= $v0;
+        $v0 = $v0.rotate_left(32);
+        $v2 = $v2.wrapping_add($v3);
+        $v3 = $v3.rotate_left(16);
+        $v3 ^= $v2;
+        $v0 = $v0.wrapping_add($v3);
+        $v3 = $v3.rotate_left(21);
+        $v3 ^= $v0;
+        $v2 = $v2.wrapping_add($v1);
+        $v1 = $v1.rotate_left(17);
+        $v1 ^= $v2;
+        $v2 = $v2.rotate_left(32);
+    }};
+}
+
+/// Load an integer of the desired type from a byte stream, in LE order. Uses
+/// `copy_nonoverlapping` to let the compiler generate the most efficient way
+/// to load it from a possibly unaligned address.
+///
+/// Unsafe because: unchecked indexing at i..i+size_of(int_ty)
+macro_rules! load_int_le {
+    ($buf:expr, $i:expr, $int_ty:ident) => {{
+        debug_assert!($i + mem::size_of::<$int_ty>() <= $buf.len());
+        let mut data = 0 as $int_ty;
+        ptr::copy_nonoverlapping(
+            $buf.get_unchecked($i),
+            &mut data as *mut _ as *mut u8,
+            mem::size_of::<$int_ty>(),
+        );
+        data.to_le()
+    }};
+}
+
+/// Load an u64 using up to 7 bytes of a byte slice.
+///
+/// Unsafe because: unchecked indexing at start..start+len
+#[inline]
+unsafe fn u8to64_le(buf: &[u8], start: usize, len: usize) -> u64 {
+    debug_assert!(len < 8);
+    let mut i = 0; // current byte index (from LSB) in the output u64
+    let mut out = 0;
+    if i + 3 < len {
+        out = load_int_le!(buf, start + i, u32) as u64;
+        i += 4;
+    }
+    if i + 1 < len {
+        out |= (load_int_le!(buf, start + i, u16) as u64) << (i * 8);
+        i += 2
+    }
+    if i < len {
+        out |= (*buf.get_unchecked(start + i) as u64) << (i * 8);
+        i += 1;
+    }
+    debug_assert_eq!(i, len);
+    out
+}
+
+impl SipHasher13 {
+    /// Creates a new `SipHasher13` with the two initial keys set to 0.
+    #[inline]
+    pub fn new() -> SipHasher13 {
+        SipHasher13::new_with_keys(0, 0)
+    }
+
+    /// Creates a `SipHasher13` that is keyed off the provided keys.
+    #[inline]
+    pub fn new_with_keys(key0: u64, key1: u64) -> SipHasher13 {
+        let mut sip_hasher = SipHasher13 {
+            k0: key0,
+            k1: key1,
+            length: 0,
+            state: State { v0: 0, v1: 0, v2: 0, v3: 0 },
+            tail: 0,
+            ntail: 0,
+        };
+        sip_hasher.reset();
+        sip_hasher
+    }
+
+    #[inline]
+    fn c_rounds(state: &mut State) {
+        compress!(state);
+    }
+
+    #[inline]
+    fn d_rounds(state: &mut State) {
+        compress!(state);
+        compress!(state);
+        compress!(state);
+    }
+
+    #[inline]
+    fn reset(&mut self) {
+        self.length = 0;
+        self.state.v0 = self.k0 ^ 0x736f6d6570736575;
+        self.state.v1 = self.k1 ^ 0x646f72616e646f6d;
+        self.state.v2 = self.k0 ^ 0x6c7967656e657261;
+        self.state.v3 = self.k1 ^ 0x7465646279746573;
+        self.ntail = 0;
+    }
+
+    // Specialized write function that is only valid for buffers with len <= 8.
+    // It's used to force inlining of write_u8 and write_usize, those would normally be inlined
+    // except for composite types (that includes slices and str hashing because of delimiter).
+    // Without this extra push the compiler is very reluctant to inline delimiter writes,
+    // degrading performance substantially for the most common use cases.
+    #[inline]
+    fn short_write(&mut self, msg: &[u8]) {
+        debug_assert!(msg.len() <= 8);
+        let length = msg.len();
+        self.length += length;
+
+        let needed = 8 - self.ntail;
+        let fill = cmp::min(length, needed);
+        if fill == 8 {
+            // safe to call since msg hasn't been loaded
+            self.tail = unsafe { load_int_le!(msg, 0, u64) };
+        } else {
+            // safe to call since msg hasn't been loaded, and fill <= msg.len()
+            self.tail |= unsafe { u8to64_le(msg, 0, fill) } << (8 * self.ntail);
+            if length < needed {
+                self.ntail += length;
+                return;
+            }
+        }
+        self.state.v3 ^= self.tail;
+        Self::c_rounds(&mut self.state);
+        self.state.v0 ^= self.tail;
+
+        // Buffered tail is now flushed, process new input.
+        self.ntail = length - needed;
+        // safe to call since number of `needed` bytes has been loaded
+        // and self.ntail + needed == msg.len()
+        self.tail = unsafe { u8to64_le(msg, needed, self.ntail) };
+    }
+}
+
+impl Hasher for SipHasher13 {
+    // see short_write comment for explanation
+    #[inline]
+    fn write_usize(&mut self, i: usize) {
+        // safe to call, since convert the pointer to u8
+        let bytes = unsafe {
+            slice::from_raw_parts(&i as *const usize as *const u8, mem::size_of::<usize>())
+        };
+        self.short_write(bytes);
+    }
+
+    // see short_write comment for explanation
+    #[inline]
+    fn write_u8(&mut self, i: u8) {
+        self.short_write(&[i]);
+    }
+
+    #[inline]
+    fn write(&mut self, msg: &[u8]) {
+        let length = msg.len();
+        self.length += length;
+
+        let mut needed = 0;
+
+        // loading unprocessed byte from last write
+        if self.ntail != 0 {
+            needed = 8 - self.ntail;
+            // safe to call, since msg hasn't been processed
+            // and cmp::min(length, needed) < 8
+            self.tail |= unsafe { u8to64_le(msg, 0, cmp::min(length, needed)) } << 8 * self.ntail;
+            if length < needed {
+                self.ntail += length;
+                return;
+            } else {
+                self.state.v3 ^= self.tail;
+                Self::c_rounds(&mut self.state);
+                self.state.v0 ^= self.tail;
+                self.ntail = 0;
+            }
+        }
+
+        // Buffered tail is now flushed, process new input.
+        let len = length - needed;
+        let left = len & 0x7;
+
+        let mut i = needed;
+        while i < len - left {
+            // safe to call since if i < len - left, it means msg has at least 1 byte to load
+            let mi = unsafe { load_int_le!(msg, i, u64) };
+
+            self.state.v3 ^= mi;
+            Self::c_rounds(&mut self.state);
+            self.state.v0 ^= mi;
+
+            i += 8;
+        }
+
+        // safe to call since if left == 0, since this call will load nothing
+        // if left > 0, it means there are number of `left` bytes in msg
+        self.tail = unsafe { u8to64_le(msg, i, left) };
+        self.ntail = left;
+    }
+
+    #[inline]
+    fn finish(&self) -> u64 {
+        let mut state = self.state;
+
+        let b: u64 = ((self.length as u64 & 0xff) << 56) | self.tail;
+
+        state.v3 ^= b;
+        Self::c_rounds(&mut state);
+        state.v0 ^= b;
+
+        state.v2 ^= 0xff;
+        Self::d_rounds(&mut state);
+
+        state.v0 ^ state.v1 ^ state.v2 ^ state.v3
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    use std::hash::{Hash, Hasher};
+    use std::string::String;
+
+    #[test]
+    // this test point locks down the value list serialization
+    fn test_sip_hash13_string_hash() {
+        let mut sip_hash13 = SipHasher13::new();
+        let test_str1 = String::from("com.google.android.test");
+        test_str1.hash(&mut sip_hash13);
+        assert_eq!(17898838669067067585, sip_hash13.finish());
+
+        let test_str2 = String::from("adfadfadf adfafadadf 1231241241");
+        test_str2.hash(&mut sip_hash13);
+        assert_eq!(13543518987672889310, sip_hash13.finish());
+    }
+
+    #[test]
+    fn test_sip_hash13_write() {
+        let mut sip_hash13 = SipHasher13::new();
+        let test_str1 = String::from("com.google.android.test");
+        sip_hash13.write(test_str1.as_bytes());
+        sip_hash13.write_u8(0xff);
+        assert_eq!(17898838669067067585, sip_hash13.finish());
+
+        let mut sip_hash132 = SipHasher13::new();
+        let test_str1 = String::from("com.google.android.test");
+        sip_hash132.write(test_str1.as_bytes());
+        assert_eq!(9685440969685209025, sip_hash132.finish());
+        sip_hash132.write(test_str1.as_bytes());
+        assert_eq!(6719694176662736568, sip_hash132.finish());
+
+        let mut sip_hash133 = SipHasher13::new();
+        let test_str2 = String::from("abcdefg");
+        test_str2.hash(&mut sip_hash133);
+        assert_eq!(2492161047327640297, sip_hash133.finish());
+
+        let mut sip_hash134 = SipHasher13::new();
+        let test_str3 = String::from("abcdefgh");
+        test_str3.hash(&mut sip_hash134);
+        assert_eq!(6689927370435554326, sip_hash134.finish());
+    }
+
+    #[test]
+    fn test_sip_hash13_write_short() {
+        let mut sip_hash13 = SipHasher13::new();
+        sip_hash13.write_u8(0x61);
+        assert_eq!(4644417185603328019, sip_hash13.finish());
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/AconfigStorageException.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/AconfigStorageException.java
new file mode 100644
index 0000000000..86a75f2f65
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/AconfigStorageException.java
@@ -0,0 +1,27 @@
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
+package android.aconfig.storage;
+
+public class AconfigStorageException extends RuntimeException {
+    public AconfigStorageException(String msg) {
+        super(msg);
+    }
+
+    public AconfigStorageException(String msg, Throwable cause) {
+        super(msg, cause);
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java
new file mode 100644
index 0000000000..4bea0836f0
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/ByteBufferReader.java
@@ -0,0 +1,58 @@
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
+package android.aconfig.storage;
+
+import java.nio.ByteBuffer;
+import java.nio.ByteOrder;
+import java.nio.charset.StandardCharsets;
+
+public class ByteBufferReader {
+
+    private ByteBuffer mByteBuffer;
+
+    public ByteBufferReader(ByteBuffer byteBuffer) {
+        this.mByteBuffer = byteBuffer;
+        this.mByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
+    }
+
+    public int readByte() {
+        return Byte.toUnsignedInt(mByteBuffer.get());
+    }
+
+    public int readShort() {
+        return Short.toUnsignedInt(mByteBuffer.getShort());
+    }
+
+    public int readInt() {
+        return this.mByteBuffer.getInt();
+    }
+
+    public String readString() {
+        int length = readInt();
+        byte[] bytes = new byte[length];
+        mByteBuffer.get(bytes, 0, length);
+        return new String(bytes, StandardCharsets.UTF_8);
+    }
+
+    public int readByte(int i) {
+        return Byte.toUnsignedInt(mByteBuffer.get(i));
+    }
+
+    public void position(int newPosition) {
+        mByteBuffer.position(newPosition);
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FileType.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FileType.java
new file mode 100644
index 0000000000..b0b1b9b186
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FileType.java
@@ -0,0 +1,45 @@
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
+package android.aconfig.storage;
+
+public enum FileType {
+    PACKAGE_MAP(0),
+    FLAG_MAP(1),
+    FLAG_VAL(2),
+    FLAG_INFO(3);
+
+    public final int type;
+
+    FileType(int type) {
+        this.type = type;
+    }
+
+    public static FileType fromInt(int index) {
+        switch (index) {
+            case 0:
+                return PACKAGE_MAP;
+            case 1:
+                return FLAG_MAP;
+            case 2:
+                return FLAG_VAL;
+            case 3:
+                return FLAG_INFO;
+            default:
+                return null;
+        }
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java
new file mode 100644
index 0000000000..9838a7c780
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagTable.java
@@ -0,0 +1,183 @@
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
+package android.aconfig.storage;
+
+import static java.nio.charset.StandardCharsets.UTF_8;
+
+import java.nio.ByteBuffer;
+import java.util.Objects;
+
+public class FlagTable {
+
+    private Header mHeader;
+    private ByteBufferReader mReader;
+
+    public static FlagTable fromBytes(ByteBuffer bytes) {
+        FlagTable flagTable = new FlagTable();
+        flagTable.mReader = new ByteBufferReader(bytes);
+        flagTable.mHeader = Header.fromBytes(flagTable.mReader);
+
+        return flagTable;
+    }
+
+    public Node get(int packageId, String flagName) {
+        int numBuckets = (mHeader.mNodeOffset - mHeader.mBucketOffset) / 4;
+        int bucketIndex = TableUtils.getBucketIndex(makeKey(packageId, flagName), numBuckets);
+
+        mReader.position(mHeader.mBucketOffset + bucketIndex * 4);
+        int nodeIndex = mReader.readInt();
+
+        while (nodeIndex != -1) {
+            mReader.position(nodeIndex);
+            Node node = Node.fromBytes(mReader);
+            if (Objects.equals(flagName, node.mFlagName) && packageId == node.mPackageId) {
+                return node;
+            }
+            nodeIndex = node.mNextOffset;
+        }
+
+        throw new AconfigStorageException("get cannot find flag: " + flagName);
+    }
+
+    public Header getHeader() {
+        return mHeader;
+    }
+
+    private static byte[] makeKey(int packageId, String flagName) {
+        StringBuilder ret = new StringBuilder();
+        return ret.append(packageId).append('/').append(flagName).toString().getBytes(UTF_8);
+    }
+
+    public static class Header {
+
+        private int mVersion;
+        private String mContainer;
+        private FileType mFileType;
+        private int mFileSize;
+        private int mNumFlags;
+        private int mBucketOffset;
+        private int mNodeOffset;
+
+        public static Header fromBytes(ByteBufferReader reader) {
+            Header header = new Header();
+            header.mVersion = reader.readInt();
+            header.mContainer = reader.readString();
+            header.mFileType = FileType.fromInt(reader.readByte());
+            header.mFileSize = reader.readInt();
+            header.mNumFlags = reader.readInt();
+            header.mBucketOffset = reader.readInt();
+            header.mNodeOffset = reader.readInt();
+
+            if (header.mFileType != FileType.FLAG_MAP) {
+                throw new AconfigStorageException("binary file is not a flag map");
+            }
+
+            return header;
+        }
+
+        public int getVersion() {
+            return mVersion;
+        }
+
+        public String getContainer() {
+            return mContainer;
+        }
+
+        public FileType getFileType() {
+            return mFileType;
+        }
+
+        public int getFileSize() {
+            return mFileSize;
+        }
+
+        public int getNumFlags() {
+            return mNumFlags;
+        }
+
+        public int getBucketOffset() {
+            return mBucketOffset;
+        }
+
+        public int getNodeOffset() {
+            return mNodeOffset;
+        }
+    }
+
+    public static class Node {
+
+        private String mFlagName;
+        private FlagType mFlagType;
+        private int mPackageId;
+        private int mFlagIndex;
+        private int mNextOffset;
+
+        public static Node fromBytes(ByteBufferReader reader) {
+            Node node = new Node();
+            node.mPackageId = reader.readInt();
+            node.mFlagName = reader.readString();
+            node.mFlagType = FlagType.fromInt(reader.readShort());
+            node.mFlagIndex = reader.readShort();
+            node.mNextOffset = reader.readInt();
+            node.mNextOffset = node.mNextOffset == 0 ? -1 : node.mNextOffset;
+            return node;
+        }
+
+        @Override
+        public int hashCode() {
+            return Objects.hash(mFlagName, mFlagType, mPackageId, mFlagIndex, mNextOffset);
+        }
+
+        @Override
+        public boolean equals(Object obj) {
+            if (this == obj) {
+                return true;
+            }
+
+            if (obj == null || !(obj instanceof Node)) {
+                return false;
+            }
+
+            Node other = (Node) obj;
+            return Objects.equals(mFlagName, other.mFlagName)
+                    && Objects.equals(mFlagType, other.mFlagType)
+                    && mPackageId == other.mPackageId
+                    && mFlagIndex == other.mFlagIndex
+                    && mNextOffset == other.mNextOffset;
+        }
+
+        public String getFlagName() {
+            return mFlagName;
+        }
+
+        public FlagType getFlagType() {
+            return mFlagType;
+        }
+
+        public int getPackageId() {
+            return mPackageId;
+        }
+
+        public int getFlagIndex() {
+            return mFlagIndex;
+        }
+
+        public int getNextOffset() {
+            return mNextOffset;
+        }
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagType.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagType.java
new file mode 100644
index 0000000000..385e2d9db9
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagType.java
@@ -0,0 +1,42 @@
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
+package android.aconfig.storage;
+
+public enum FlagType {
+    ReadWriteBoolean (0),
+    ReadOnlyBoolean(1),
+    FixedReadOnlyBoolean(2);
+
+    public final int type;
+
+    FlagType(int type) {
+        this.type = type;
+    }
+
+    public static FlagType fromInt(int index) {
+        switch (index) {
+            case 0:
+                return ReadWriteBoolean;
+            case 1:
+                return ReadOnlyBoolean;
+            case 2:
+                return FixedReadOnlyBoolean;
+            default:
+                return null;
+        }
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagValueList.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagValueList.java
new file mode 100644
index 0000000000..493436d2a2
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/FlagValueList.java
@@ -0,0 +1,94 @@
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
+package android.aconfig.storage;
+
+import java.nio.ByteBuffer;
+
+public class FlagValueList {
+
+    private Header mHeader;
+    private ByteBufferReader mReader;
+
+    public static FlagValueList fromBytes(ByteBuffer bytes) {
+        FlagValueList flagValueList = new FlagValueList();
+        flagValueList.mReader = new ByteBufferReader(bytes);
+        flagValueList.mHeader = Header.fromBytes(flagValueList.mReader);
+        return flagValueList;
+    }
+
+    public boolean getBoolean(int index) {
+        return mReader.readByte(mHeader.mBooleanValueOffset + index) == 1;
+    }
+
+    public Header getHeader() {
+        return mHeader;
+    }
+
+    public int size() {
+        return mHeader.mNumFlags;
+    }
+
+    public static class Header {
+
+        private int mVersion;
+        private String mContainer;
+        private FileType mFileType;
+        private int mFileSize;
+        private int mNumFlags;
+        private int mBooleanValueOffset;
+
+        public static Header fromBytes(ByteBufferReader reader) {
+            Header header = new Header();
+            header.mVersion = reader.readInt();
+            header.mContainer = reader.readString();
+            header.mFileType = FileType.fromInt(reader.readByte());
+            header.mFileSize = reader.readInt();
+            header.mNumFlags = reader.readInt();
+            header.mBooleanValueOffset = reader.readInt();
+
+            if (header.mFileType != FileType.FLAG_VAL) {
+                throw new AconfigStorageException("binary file is not a flag value file");
+            }
+
+            return header;
+        }
+
+        public int getVersion() {
+            return mVersion;
+        }
+
+        public String getContainer() {
+            return mContainer;
+        }
+
+        public FileType getFileType() {
+            return mFileType;
+        }
+
+        public int getFileSize() {
+            return mFileSize;
+        }
+
+        public int getNumFlags() {
+            return mNumFlags;
+        }
+
+        public int getBooleanValueOffset() {
+            return mBooleanValueOffset;
+        }
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java
new file mode 100644
index 0000000000..773b882f4a
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/PackageTable.java
@@ -0,0 +1,172 @@
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
+package android.aconfig.storage;
+
+import static java.nio.charset.StandardCharsets.UTF_8;
+
+import java.nio.ByteBuffer;
+import java.util.Objects;
+
+public class PackageTable {
+
+    private Header mHeader;
+    private ByteBufferReader mReader;
+
+    public static PackageTable fromBytes(ByteBuffer bytes) {
+        PackageTable packageTable = new PackageTable();
+        packageTable.mReader = new ByteBufferReader(bytes);
+        packageTable.mHeader = Header.fromBytes(packageTable.mReader);
+
+        return packageTable;
+    }
+
+    public Node get(String packageName) {
+
+        int numBuckets = (mHeader.mNodeOffset - mHeader.mBucketOffset) / 4;
+        int bucketIndex = TableUtils.getBucketIndex(packageName.getBytes(UTF_8), numBuckets);
+
+        mReader.position(mHeader.mBucketOffset + bucketIndex * 4);
+        int nodeIndex = mReader.readInt();
+
+        while (nodeIndex != -1) {
+            mReader.position(nodeIndex);
+            Node node = Node.fromBytes(mReader);
+            if (Objects.equals(packageName, node.mPackageName)) {
+                return node;
+            }
+            nodeIndex = node.mNextOffset;
+        }
+
+        throw new AconfigStorageException("get cannot find package: " + packageName);
+    }
+
+    public Header getHeader() {
+        return mHeader;
+    }
+
+    public static class Header {
+
+        private int mVersion;
+        private String mContainer;
+        private FileType mFileType;
+        private int mFileSize;
+        private int mNumPackages;
+        private int mBucketOffset;
+        private int mNodeOffset;
+
+        public static Header fromBytes(ByteBufferReader reader) {
+            Header header = new Header();
+            header.mVersion = reader.readInt();
+            header.mContainer = reader.readString();
+            header.mFileType = FileType.fromInt(reader.readByte());
+            header.mFileSize = reader.readInt();
+            header.mNumPackages = reader.readInt();
+            header.mBucketOffset = reader.readInt();
+            header.mNodeOffset = reader.readInt();
+
+            if (header.mFileType != FileType.PACKAGE_MAP) {
+                throw new AconfigStorageException("binary file is not a package map");
+            }
+
+            return header;
+        }
+
+        public int getVersion() {
+            return mVersion;
+        }
+
+        public String getContainer() {
+            return mContainer;
+        }
+
+        public FileType getFileType() {
+            return mFileType;
+        }
+
+        public int getFileSize() {
+            return mFileSize;
+        }
+
+        public int getNumPackages() {
+            return mNumPackages;
+        }
+
+        public int getBucketOffset() {
+            return mBucketOffset;
+        }
+
+        public int getNodeOffset() {
+            return mNodeOffset;
+        }
+    }
+
+    public static class Node {
+
+        private String mPackageName;
+        private int mPackageId;
+        private int mBooleanStartIndex;
+        private int mNextOffset;
+
+        public static Node fromBytes(ByteBufferReader reader) {
+            Node node = new Node();
+            node.mPackageName = reader.readString();
+            node.mPackageId = reader.readInt();
+            node.mBooleanStartIndex = reader.readInt();
+            node.mNextOffset = reader.readInt();
+            node.mNextOffset = node.mNextOffset == 0 ? -1 : node.mNextOffset;
+            return node;
+        }
+
+        @Override
+        public int hashCode() {
+            return Objects.hash(mPackageName, mPackageId, mBooleanStartIndex, mNextOffset);
+        }
+
+        @Override
+        public boolean equals(Object obj) {
+            if (this == obj) {
+                return true;
+            }
+
+            if (obj == null || !(obj instanceof Node)) {
+                return false;
+            }
+
+            Node other = (Node) obj;
+            return Objects.equals(mPackageName, other.mPackageName)
+                    && mPackageId == other.mPackageId
+                    && mBooleanStartIndex == other.mBooleanStartIndex
+                    && mNextOffset == other.mNextOffset;
+        }
+
+        public String getPackageName() {
+            return mPackageName;
+        }
+
+        public int getPackageId() {
+            return mPackageId;
+        }
+
+        public int getBooleanStartIndex() {
+            return mBooleanStartIndex;
+        }
+
+        public int getNextOffset() {
+            return mNextOffset;
+        }
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/SipHasher13.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/SipHasher13.java
new file mode 100644
index 0000000000..64714ee5f8
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/SipHasher13.java
@@ -0,0 +1,115 @@
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
+package android.aconfig.storage;
+
+public class SipHasher13 {
+    static class State {
+        private long v0;
+        private long v2;
+        private long v1;
+        private long v3;
+
+        public State(long k0, long k1) {
+            v0 = k0 ^ 0x736f6d6570736575L;
+            v1 = k1 ^ 0x646f72616e646f6dL;
+            v2 = k0 ^ 0x6c7967656e657261L;
+            v3 = k1 ^ 0x7465646279746573L;
+        }
+
+        public void compress(long m) {
+            v3 ^= m;
+            cRounds();
+            v0 ^= m;
+        }
+
+        public long finish() {
+            v2 ^= 0xff;
+            dRounds();
+            return v0 ^ v1 ^ v2 ^ v3;
+        }
+
+        private void cRounds() {
+            v0 += v1;
+            v1 = Long.rotateLeft(v1, 13);
+            v1 ^= v0;
+            v0 = Long.rotateLeft(v0, 32);
+            v2 += v3;
+            v3 = Long.rotateLeft(v3, 16);
+            v3 ^= v2;
+            v0 += v3;
+            v3 = Long.rotateLeft(v3, 21);
+            v3 ^= v0;
+            v2 += v1;
+            v1 = Long.rotateLeft(v1, 17);
+            v1 ^= v2;
+            v2 = Long.rotateLeft(v2, 32);
+        }
+
+        private void dRounds() {
+            for (int i = 0; i < 3; i++) {
+                v0 += v1;
+                v1 = Long.rotateLeft(v1, 13);
+                v1 ^= v0;
+                v0 = Long.rotateLeft(v0, 32);
+                v2 += v3;
+                v3 = Long.rotateLeft(v3, 16);
+                v3 ^= v2;
+                v0 += v3;
+                v3 = Long.rotateLeft(v3, 21);
+                v3 ^= v0;
+                v2 += v1;
+                v1 = Long.rotateLeft(v1, 17);
+                v1 ^= v2;
+                v2 = Long.rotateLeft(v2, 32);
+            }
+        }
+    }
+
+    public static long hash(byte[] data) {
+        State state = new State(0, 0);
+        int len = data.length;
+        int left = len & 0x7;
+        int index = 0;
+
+        while (index < len - left) {
+            long mi = loadLe(data, index, 8);
+            index += 8;
+            state.compress(mi);
+        }
+
+        // padding the end with 0xff to be consistent with rust
+        long m = (0xffL << (left * 8)) | loadLe(data, index, left);
+        if (left == 0x7) {
+            // compress the m w-2
+            state.compress(m);
+            m = 0L;
+        }
+        // len adds 1 since padded 0xff
+        m |= (((len + 1) & 0xffL) << 56);
+        state.compress(m);
+
+        return state.finish();
+    }
+
+    private static long loadLe(byte[] data, int offset, int size) {
+        long m = 0;
+        for (int i = 0; i < size; i++) {
+            m |= (data[i + offset] & 0xffL) << (i * 8);
+        }
+        return m;
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/TableUtils.java b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/TableUtils.java
new file mode 100644
index 0000000000..81168f538e
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/srcs/android/aconfig/storage/TableUtils.java
@@ -0,0 +1,66 @@
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
+package android.aconfig.storage;
+
+public class TableUtils {
+
+    private static final int[] HASH_PRIMES =
+            new int[] {
+                7,
+                17,
+                29,
+                53,
+                97,
+                193,
+                389,
+                769,
+                1543,
+                3079,
+                6151,
+                12289,
+                24593,
+                49157,
+                98317,
+                196613,
+                393241,
+                786433,
+                1572869,
+                3145739,
+                6291469,
+                12582917,
+                25165843,
+                50331653,
+                100663319,
+                201326611,
+                402653189,
+                805306457,
+                1610612741
+            };
+
+    public static int getTableSize(int numEntries) {
+        for (int i : HASH_PRIMES) {
+            if (i < 2 * numEntries) continue;
+            return i;
+        }
+        throw new AconfigStorageException("Number of items in a hash table exceeds limit");
+    }
+
+    public static int getBucketIndex(byte[] val, int numBuckets) {
+        long hashVal = SipHasher13.hash(val);
+        return (int) Long.remainderUnsigned(hashVal, numBuckets);
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/tests/Android.bp b/tools/aconfig/aconfig_storage_file/tests/Android.bp
index 26b7800877..12e4acad1b 100644
--- a/tools/aconfig/aconfig_storage_file/tests/Android.bp
+++ b/tools/aconfig/aconfig_storage_file/tests/Android.bp
@@ -1,4 +1,3 @@
-
 cc_test {
     name: "aconfig_storage_file.test.cpp",
     team: "trendy_team_android_core_experiments",
@@ -21,3 +20,28 @@ cc_test {
         "general-tests",
     ],
 }
+
+android_test {
+    name: "aconfig_storage_file.test.java",
+    team: "trendy_team_android_core_experiments",
+    srcs: [
+        "srcs/**/*.java",
+    ],
+    static_libs: [
+        "androidx.test.runner",
+        "junit",
+        "aconfig_storage_file_java",
+    ],
+    test_config: "AndroidStorageJaveTest.xml",
+    sdk_version: "test_current",
+    data: [
+        "package.map",
+        "flag.map",
+        "flag.val",
+        "flag.info",
+    ],
+    test_suites: [
+        "general-tests",
+    ],
+    jarjar_rules: "jarjar.txt",
+}
diff --git a/tools/aconfig/aconfig_storage_file/tests/AndroidManifest.xml b/tools/aconfig/aconfig_storage_file/tests/AndroidManifest.xml
new file mode 100644
index 0000000000..5e01879157
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/tests/AndroidManifest.xml
@@ -0,0 +1,27 @@
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
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="android.aconfig.storage.test">
+    <application>
+        <uses-library android:name="android.test.runner" />
+    </application>
+
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+                     android:targetPackage="android.aconfig.storage.test" />
+
+</manifest>
diff --git a/tools/aconfig/aconfig_storage_file/tests/AndroidStorageJaveTest.xml b/tools/aconfig/aconfig_storage_file/tests/AndroidStorageJaveTest.xml
new file mode 100644
index 0000000000..2d52d44c57
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/tests/AndroidStorageJaveTest.xml
@@ -0,0 +1,33 @@
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
+<configuration description="Test aconfig storage java tests">
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true" />
+        <option name="test-file-name" value="aconfig_storage_file.test.java.apk" />
+    </target_preparer>
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.FilePusher">
+        <option name="cleanup" value="true" />
+        <option name="push" value="package.map->/data/local/tmp/aconfig_storage_file_test_java/testdata/package.map" />
+        <option name="push" value="flag.map->/data/local/tmp/aconfig_storage_file_test_java/testdata/flag.map" />
+        <option name="push" value="flag.val->/data/local/tmp/aconfig_storage_file_test_java/testdata/flag.val" />
+        <option name="push" value="flag.info->/data/local/tmp/aconfig_storage_file_test_java/testdata/flag.info" />
+    </target_preparer>
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
+        <option name="package" value="android.aconfig.storage.test" />
+        <option name="runtime-hint" value="1m" />
+    </test>
+</configuration>
\ No newline at end of file
diff --git a/tools/aconfig/aconfig_storage_file/tests/jarjar.txt b/tools/aconfig/aconfig_storage_file/tests/jarjar.txt
new file mode 100644
index 0000000000..a6c17fa476
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/tests/jarjar.txt
@@ -0,0 +1,15 @@
+rule android.aconfig.storage.AconfigStorageException android.aconfig.storage.test.AconfigStorageException
+rule android.aconfig.storage.FlagTable android.aconfig.storage.test.FlagTable
+rule android.aconfig.storage.PackageTable android.aconfig.storage.test.PackageTable
+rule android.aconfig.storage.ByteBufferReader android.aconfig.storage.test.ByteBufferReader
+rule android.aconfig.storage.FlagType android.aconfig.storage.test.FlagType
+rule android.aconfig.storage.SipHasher13 android.aconfig.storage.test.SipHasher13
+rule android.aconfig.storage.FileType android.aconfig.storage.test.FileType
+rule android.aconfig.storage.FlagValueList android.aconfig.storage.test.FlagValueList
+rule android.aconfig.storage.TableUtils android.aconfig.storage.test.TableUtils
+
+
+rule android.aconfig.storage.FlagTable$* android.aconfig.storage.test.FlagTable$@1
+rule android.aconfig.storage.PackageTable$* android.aconfig.storage.test.PackageTable$@1
+rule android.aconfig.storage.FlagValueList$* android.aconfig.storage.test.FlagValueList@1
+rule android.aconfig.storage.SipHasher13$* android.aconfig.storage.test.SipHasher13@1
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/ByteBufferReaderTest.java b/tools/aconfig/aconfig_storage_file/tests/srcs/ByteBufferReaderTest.java
new file mode 100644
index 0000000000..66a8166812
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/ByteBufferReaderTest.java
@@ -0,0 +1,79 @@
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
+package android.aconfig.storage.test;
+
+import static org.junit.Assert.assertEquals;
+
+import android.aconfig.storage.ByteBufferReader;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.nio.ByteBuffer;
+import java.nio.ByteOrder;
+import java.nio.charset.StandardCharsets;
+
+@RunWith(JUnit4.class)
+public class ByteBufferReaderTest {
+
+    @Test
+    public void testReadByte() {
+        ByteBuffer buffer = ByteBuffer.allocate(1);
+        byte expect = 10;
+        buffer.put(expect).rewind();
+
+        ByteBufferReader reader = new ByteBufferReader(buffer);
+        assertEquals(expect, reader.readByte());
+    }
+
+    @Test
+    public void testReadShort() {
+        ByteBuffer buffer = ByteBuffer.allocate(4);
+        buffer.order(ByteOrder.LITTLE_ENDIAN);
+        short expect = Short.MAX_VALUE;
+        buffer.putShort(expect).rewind();
+
+        ByteBufferReader reader = new ByteBufferReader(buffer);
+        assertEquals(expect, reader.readShort());
+    }
+
+    @Test
+    public void testReadInt() {
+        ByteBuffer buffer = ByteBuffer.allocate(4);
+        buffer.order(ByteOrder.LITTLE_ENDIAN);
+        int expect = 10000;
+        buffer.putInt(expect).rewind();
+
+        ByteBufferReader reader = new ByteBufferReader(buffer);
+        assertEquals(expect, reader.readInt());
+    }
+
+    @Test
+    public void testReadString() {
+        String expect = "test read string";
+        byte[] bytes = expect.getBytes(StandardCharsets.UTF_8);
+
+        ByteBuffer buffer = ByteBuffer.allocate(expect.length() * 2 + 4);
+        buffer.order(ByteOrder.LITTLE_ENDIAN);
+        buffer.putInt(expect.length()).put(bytes).rewind();
+
+        ByteBufferReader reader = new ByteBufferReader(buffer);
+
+        assertEquals(expect, reader.readString());
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/FlagTableTest.java b/tools/aconfig/aconfig_storage_file/tests/srcs/FlagTableTest.java
new file mode 100644
index 0000000000..fd40d4c4ef
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/FlagTableTest.java
@@ -0,0 +1,103 @@
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
+package android.aconfig.storage.test;
+
+import static org.junit.Assert.assertEquals;
+
+import android.aconfig.storage.FileType;
+import android.aconfig.storage.FlagTable;
+import android.aconfig.storage.FlagType;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public class FlagTableTest {
+
+    @Test
+    public void testFlagTable_rightHeader() throws Exception {
+        FlagTable flagTable = FlagTable.fromBytes(TestDataUtils.getTestFlagMapByteBuffer());
+        FlagTable.Header header = flagTable.getHeader();
+        assertEquals(1, header.getVersion());
+        assertEquals("mockup", header.getContainer());
+        assertEquals(FileType.FLAG_MAP, header.getFileType());
+        assertEquals(321, header.getFileSize());
+        assertEquals(8, header.getNumFlags());
+        assertEquals(31, header.getBucketOffset());
+        assertEquals(99, header.getNodeOffset());
+    }
+
+    @Test
+    public void testFlagTable_rightNode() throws Exception {
+        FlagTable flagTable = FlagTable.fromBytes(TestDataUtils.getTestFlagMapByteBuffer());
+
+        FlagTable.Node node1 = flagTable.get(0, "enabled_ro");
+        FlagTable.Node node2 = flagTable.get(0, "enabled_rw");
+        FlagTable.Node node3 = flagTable.get(2, "enabled_rw");
+        FlagTable.Node node4 = flagTable.get(1, "disabled_rw");
+        FlagTable.Node node5 = flagTable.get(1, "enabled_fixed_ro");
+        FlagTable.Node node6 = flagTable.get(1, "enabled_ro");
+        FlagTable.Node node7 = flagTable.get(2, "enabled_fixed_ro");
+        FlagTable.Node node8 = flagTable.get(0, "disabled_rw");
+
+        assertEquals("enabled_ro", node1.getFlagName());
+        assertEquals("enabled_rw", node2.getFlagName());
+        assertEquals("enabled_rw", node3.getFlagName());
+        assertEquals("disabled_rw", node4.getFlagName());
+        assertEquals("enabled_fixed_ro", node5.getFlagName());
+        assertEquals("enabled_ro", node6.getFlagName());
+        assertEquals("enabled_fixed_ro", node7.getFlagName());
+        assertEquals("disabled_rw", node8.getFlagName());
+
+        assertEquals(0, node1.getPackageId());
+        assertEquals(0, node2.getPackageId());
+        assertEquals(2, node3.getPackageId());
+        assertEquals(1, node4.getPackageId());
+        assertEquals(1, node5.getPackageId());
+        assertEquals(1, node6.getPackageId());
+        assertEquals(2, node7.getPackageId());
+        assertEquals(0, node8.getPackageId());
+
+        assertEquals(FlagType.ReadOnlyBoolean, node1.getFlagType());
+        assertEquals(FlagType.ReadWriteBoolean, node2.getFlagType());
+        assertEquals(FlagType.ReadWriteBoolean, node3.getFlagType());
+        assertEquals(FlagType.ReadWriteBoolean, node4.getFlagType());
+        assertEquals(FlagType.FixedReadOnlyBoolean, node5.getFlagType());
+        assertEquals(FlagType.ReadOnlyBoolean, node6.getFlagType());
+        assertEquals(FlagType.FixedReadOnlyBoolean, node7.getFlagType());
+        assertEquals(FlagType.ReadWriteBoolean, node8.getFlagType());
+
+        assertEquals(1, node1.getFlagIndex());
+        assertEquals(2, node2.getFlagIndex());
+        assertEquals(1, node3.getFlagIndex());
+        assertEquals(0, node4.getFlagIndex());
+        assertEquals(1, node5.getFlagIndex());
+        assertEquals(2, node6.getFlagIndex());
+        assertEquals(0, node7.getFlagIndex());
+        assertEquals(0, node8.getFlagIndex());
+
+        assertEquals(-1, node1.getNextOffset());
+        assertEquals(151, node2.getNextOffset());
+        assertEquals(-1, node3.getNextOffset());
+        assertEquals(-1, node4.getNextOffset());
+        assertEquals(236, node5.getNextOffset());
+        assertEquals(-1, node6.getNextOffset());
+        assertEquals(-1, node7.getNextOffset());
+        assertEquals(-1, node8.getNextOffset());
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/FlagValueListTest.java b/tools/aconfig/aconfig_storage_file/tests/srcs/FlagValueListTest.java
new file mode 100644
index 0000000000..1b0de630c7
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/FlagValueListTest.java
@@ -0,0 +1,77 @@
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
+package android.aconfig.storage.test;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertTrue;
+
+import android.aconfig.storage.FileType;
+import android.aconfig.storage.FlagTable;
+import android.aconfig.storage.FlagValueList;
+import android.aconfig.storage.PackageTable;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public class FlagValueListTest {
+
+    @Test
+    public void testFlagValueList_rightHeader() throws Exception {
+        FlagValueList flagValueList =
+                FlagValueList.fromBytes(TestDataUtils.getTestFlagValByteBuffer());
+        FlagValueList.Header header = flagValueList.getHeader();
+        assertEquals(1, header.getVersion());
+        assertEquals("mockup", header.getContainer());
+        assertEquals(FileType.FLAG_VAL, header.getFileType());
+        assertEquals(35, header.getFileSize());
+        assertEquals(8, header.getNumFlags());
+        assertEquals(27, header.getBooleanValueOffset());
+    }
+
+    @Test
+    public void testFlagValueList_rightNode() throws Exception {
+        FlagValueList flagValueList =
+                FlagValueList.fromBytes(TestDataUtils.getTestFlagValByteBuffer());
+
+        boolean[] expected = new boolean[] {false, true, true, false, true, true, true, true};
+        assertEquals(expected.length, flagValueList.size());
+
+        for (int i = 0; i < flagValueList.size(); i++) {
+            assertEquals(expected[i], flagValueList.getBoolean(i));
+        }
+    }
+
+    @Test
+    public void testFlagValueList_getValue() throws Exception {
+        PackageTable packageTable =
+                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer());
+        FlagTable flagTable = FlagTable.fromBytes(TestDataUtils.getTestFlagMapByteBuffer());
+
+        FlagValueList flagValueList =
+                FlagValueList.fromBytes(TestDataUtils.getTestFlagValByteBuffer());
+
+        PackageTable.Node pNode = packageTable.get("com.android.aconfig.storage.test_1");
+        FlagTable.Node fNode = flagTable.get(pNode.getPackageId(), "enabled_rw");
+        assertTrue(flagValueList.getBoolean(pNode.getBooleanStartIndex() + fNode.getFlagIndex()));
+
+        pNode = packageTable.get("com.android.aconfig.storage.test_4");
+        fNode = flagTable.get(pNode.getPackageId(), "enabled_fixed_ro");
+        assertTrue(flagValueList.getBoolean(pNode.getBooleanStartIndex() + fNode.getFlagIndex()));
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java b/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java
new file mode 100644
index 0000000000..e7e19d8d51
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/PackageTableTest.java
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
+package android.aconfig.storage.test;
+
+import static org.junit.Assert.assertEquals;
+
+import android.aconfig.storage.FileType;
+import android.aconfig.storage.PackageTable;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public class PackageTableTest {
+
+    @Test
+    public void testPackageTable_rightHeader() throws Exception {
+        PackageTable packageTable =
+                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer());
+        PackageTable.Header header = packageTable.getHeader();
+        assertEquals(1, header.getVersion());
+        assertEquals("mockup", header.getContainer());
+        assertEquals(FileType.PACKAGE_MAP, header.getFileType());
+        assertEquals(209, header.getFileSize());
+        assertEquals(3, header.getNumPackages());
+        assertEquals(31, header.getBucketOffset());
+        assertEquals(59, header.getNodeOffset());
+    }
+
+    @Test
+    public void testPackageTable_rightNode() throws Exception {
+        PackageTable packageTable =
+                PackageTable.fromBytes(TestDataUtils.getTestPackageMapByteBuffer());
+
+        PackageTable.Node node1 = packageTable.get("com.android.aconfig.storage.test_1");
+        PackageTable.Node node2 = packageTable.get("com.android.aconfig.storage.test_2");
+        PackageTable.Node node4 = packageTable.get("com.android.aconfig.storage.test_4");
+
+        assertEquals("com.android.aconfig.storage.test_1", node1.getPackageName());
+        assertEquals("com.android.aconfig.storage.test_2", node2.getPackageName());
+        assertEquals("com.android.aconfig.storage.test_4", node4.getPackageName());
+
+        assertEquals(0, node1.getPackageId());
+        assertEquals(1, node2.getPackageId());
+        assertEquals(2, node4.getPackageId());
+
+        assertEquals(0, node1.getBooleanStartIndex());
+        assertEquals(3, node2.getBooleanStartIndex());
+        assertEquals(6, node4.getBooleanStartIndex());
+
+        assertEquals(159, node1.getNextOffset());
+        assertEquals(-1, node2.getNextOffset());
+        assertEquals(-1, node4.getNextOffset());
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/SipHasher13Test.java b/tools/aconfig/aconfig_storage_file/tests/srcs/SipHasher13Test.java
new file mode 100644
index 0000000000..10620d272b
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/SipHasher13Test.java
@@ -0,0 +1,44 @@
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
+package android.aconfig.storage.test;
+
+import static org.junit.Assert.assertEquals;
+import static java.nio.charset.StandardCharsets.UTF_8;
+
+import android.aconfig.storage.SipHasher13;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public class SipHasher13Test {
+    @Test
+    public void testSipHash_hashString() throws Exception {
+        String testStr = "com.google.android.test";
+        long result = SipHasher13.hash(testStr.getBytes(UTF_8));
+        assertEquals(0xF86572EFF9C4A0C1L, result);
+
+        testStr = "abcdefg";
+        result = SipHasher13.hash(testStr.getBytes(UTF_8));
+        assertEquals(0x2295EF44BD078AE9L, result);
+
+        testStr = "abcdefgh";
+        result = SipHasher13.hash(testStr.getBytes(UTF_8));
+        assertEquals(0x5CD7657FA7F96C16L, result);
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_file/tests/srcs/TestDataUtils.java b/tools/aconfig/aconfig_storage_file/tests/srcs/TestDataUtils.java
new file mode 100644
index 0000000000..f35952d392
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_file/tests/srcs/TestDataUtils.java
@@ -0,0 +1,52 @@
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
+package android.aconfig.storage.test;
+
+import java.io.FileInputStream;
+import java.io.InputStream;
+import java.nio.ByteBuffer;
+
+public final class TestDataUtils {
+    private static final String TEST_PACKAGE_MAP_PATH = "package.map";
+    private static final String TEST_FLAG_MAP_PATH = "flag.map";
+    private static final String TEST_FLAG_VAL_PATH = "flag.val";
+    private static final String TEST_FLAG_INFO_PATH = "flag.info";
+
+    private static final String TESTDATA_PATH =
+            "/data/local/tmp/aconfig_storage_file_test_java/testdata/";
+
+    public static ByteBuffer getTestPackageMapByteBuffer() throws Exception {
+        return readFile(TESTDATA_PATH + TEST_PACKAGE_MAP_PATH);
+    }
+
+    public static ByteBuffer getTestFlagMapByteBuffer() throws Exception {
+        return readFile(TESTDATA_PATH + TEST_FLAG_MAP_PATH);
+    }
+
+    public static ByteBuffer getTestFlagValByteBuffer() throws Exception {
+        return readFile(TESTDATA_PATH + TEST_FLAG_VAL_PATH);
+    }
+
+    public static ByteBuffer getTestFlagInfoByteBuffer() throws Exception {
+        return readFile(TESTDATA_PATH + TEST_FLAG_INFO_PATH);
+    }
+
+    private static ByteBuffer readFile(String fileName) throws Exception {
+        InputStream input = new FileInputStream(fileName);
+        return ByteBuffer.wrap(input.readAllBytes());
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_read_api/Android.bp b/tools/aconfig/aconfig_storage_read_api/Android.bp
index 3b124b15c1..f96b2230d1 100644
--- a/tools/aconfig/aconfig_storage_read_api/Android.bp
+++ b/tools/aconfig/aconfig_storage_read_api/Android.bp
@@ -87,6 +87,9 @@ cc_library {
     generated_sources: ["libcxx_aconfig_storage_read_api_bridge_code"],
     whole_static_libs: ["libaconfig_storage_read_api_cxx_bridge"],
     export_include_dirs: ["include"],
+    static_libs: [
+        "libbase",
+    ],
     host_supported: true,
     vendor_available: true,
     product_available: true,
@@ -104,6 +107,33 @@ cc_library {
     afdo: true,
 }
 
+soong_config_module_type {
+    name: "aconfig_lib_cc_shared_link_defaults",
+    module_type: "cc_defaults",
+    config_namespace: "Aconfig",
+    bool_variables: [
+        "read_from_new_storage",
+    ],
+    properties: [
+        "shared_libs",
+    ],
+}
+
+soong_config_bool_variable {
+    name: "read_from_new_storage",
+}
+
+aconfig_lib_cc_shared_link_defaults {
+    name: "aconfig_lib_cc_shared_link.defaults",
+    soong_config_variables: {
+        read_from_new_storage: {
+            shared_libs: [
+                "libaconfig_storage_read_api_cc",
+            ],
+        },
+    },
+}
+
 cc_defaults {
     name: "aconfig_lib_cc_static_link.defaults",
     shared_libs: [
@@ -117,6 +147,7 @@ rust_ffi_shared {
     crate_name: "aconfig_storage_read_api_rust_jni",
     srcs: ["srcs/lib.rs"],
     rustlibs: [
+        "libaconfig_storage_file",
         "libaconfig_storage_read_api",
         "libanyhow",
         "libjni",
@@ -127,7 +158,9 @@ rust_ffi_shared {
 java_library {
     name: "libaconfig_storage_read_api_java",
     srcs: [
-        "srcs/**/*.java",
+        "srcs/android/aconfig/storage/AconfigStorageReadAPI.java",
+        "srcs/android/aconfig/storage/FlagReadContext.java",
+        "srcs/android/aconfig/storage/PackageReadContext.java",
     ],
     required: ["libaconfig_storage_read_api_rust_jni"],
     min_sdk_version: "UpsideDownCake",
@@ -136,3 +169,41 @@ java_library {
         "//apex_available:platform",
     ],
 }
+
+java_library {
+    name: "aconfig_storage_reader_java",
+    srcs: [
+        "srcs/android/aconfig/storage/StorageInternalReader.java",
+    ],
+    libs: [
+        "unsupportedappusage",
+        "strict_mode_stub",
+    ],
+    static_libs: [
+        "aconfig_storage_file_java",
+    ],
+    sdk_version: "core_current",
+    host_supported: true,
+    min_sdk_version: "29",
+    apex_available: [
+        "//apex_available:platform",
+        "//apex_available:anyapex",
+    ],
+}
+
+java_library {
+    name: "aconfig_storage_reader_java_none",
+    srcs: [
+        "srcs/android/aconfig/storage/StorageInternalReader.java",
+    ],
+    libs: [
+        "unsupportedappusage-sdk-none",
+        "fake_device_config",
+    ],
+    static_libs: [
+        "aconfig_storage_file_java_none",
+    ],
+    sdk_version: "none",
+    system_modules: "core-all-system-modules",
+    host_supported: true,
+}
diff --git a/tools/aconfig/aconfig_storage_read_api/aconfig_storage_read_api.cpp b/tools/aconfig/aconfig_storage_read_api/aconfig_storage_read_api.cpp
index 97ada3a33e..8e0c4e1a12 100644
--- a/tools/aconfig/aconfig_storage_read_api/aconfig_storage_read_api.cpp
+++ b/tools/aconfig/aconfig_storage_read_api/aconfig_storage_read_api.cpp
@@ -1,3 +1,4 @@
+#include <android-base/unique_fd.h>
 #include <sys/mman.h>
 #include <sys/stat.h>
 #include <fcntl.h>
@@ -59,22 +60,22 @@ Result<MappedStorageFile*> get_mapped_file_impl(
 
 /// Map a storage file
 Result<MappedStorageFile*> map_storage_file(std::string const& file) {
-  int fd = open(file.c_str(), O_CLOEXEC | O_NOFOLLOW | O_RDONLY);
-  if (fd == -1) {
+  android::base::unique_fd ufd(open(file.c_str(), O_CLOEXEC | O_NOFOLLOW | O_RDONLY));
+  if (ufd.get() == -1) {
     auto result = Result<MappedStorageFile*>();
     result.errmsg = std::string("failed to open ") + file + ": " + strerror(errno);
     return result;
   };
 
   struct stat fd_stat;
-  if (fstat(fd, &fd_stat) < 0) {
+  if (fstat(ufd.get(), &fd_stat) < 0) {
     auto result = Result<MappedStorageFile*>();
     result.errmsg = std::string("fstat failed: ") + strerror(errno);
     return result;
   }
   size_t file_size = fd_stat.st_size;
 
-  void* const map_result = mmap(nullptr, file_size, PROT_READ, MAP_SHARED, fd, 0);
+  void* const map_result = mmap(nullptr, file_size, PROT_READ, MAP_SHARED, ufd.get(), 0);
   if (map_result == MAP_FAILED) {
     auto result = Result<MappedStorageFile*>();
     result.errmsg = std::string("mmap failed: ") + strerror(errno);
diff --git a/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/AconfigStorageReadAPI.java b/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/AconfigStorageReadAPI.java
index 406ff24dd3..850c2b8146 100644
--- a/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/AconfigStorageReadAPI.java
+++ b/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/AconfigStorageReadAPI.java
@@ -16,18 +16,14 @@
 
 package android.aconfig.storage;
 
+import dalvik.annotation.optimization.FastNative;
+
 import java.io.FileInputStream;
 import java.io.IOException;
 import java.nio.ByteBuffer;
 import java.nio.ByteOrder;
 import java.nio.MappedByteBuffer;
 import java.nio.channels.FileChannel;
-import java.nio.channels.FileChannel.MapMode;
-
-import android.aconfig.storage.PackageReadContext;
-import android.aconfig.storage.FlagReadContext;
-
-import dalvik.annotation.optimization.FastNative;
 
 public class AconfigStorageReadAPI {
 
@@ -50,9 +46,8 @@ public class AconfigStorageReadAPI {
     }
 
     // Map a storage file given container and file type
-    public static MappedByteBuffer getMappedFile(
-        String container,
-        StorageFileType type) throws IOException{
+    public static MappedByteBuffer getMappedFile(String container, StorageFileType type)
+            throws IOException {
         switch (type) {
             case PACKAGE_MAP:
                 return mapStorageFile(STORAGEDIR + "/maps/" + container + ".package.map");
@@ -73,14 +68,14 @@ public class AconfigStorageReadAPI {
     // @throws IOException if the passed in file is not a valid package map file
     @FastNative
     private static native ByteBuffer getPackageReadContextImpl(
-        ByteBuffer mappedFile, String packageName) throws IOException;
+            ByteBuffer mappedFile, String packageName) throws IOException;
 
     // API to get package read context
     // @param mappedFile: memory mapped package map file
     // @param packageName: package name
     // @throws IOException if the passed in file is not a valid package map file
-    static public PackageReadContext getPackageReadContext (
-        ByteBuffer mappedFile, String packageName) throws IOException {
+    public static PackageReadContext getPackageReadContext(
+            ByteBuffer mappedFile, String packageName) throws IOException {
         ByteBuffer buffer = getPackageReadContextImpl(mappedFile, packageName);
         buffer.order(ByteOrder.LITTLE_ENDIAN);
         return new PackageReadContext(buffer.getInt(), buffer.getInt(4));
@@ -94,7 +89,7 @@ public class AconfigStorageReadAPI {
     // @throws IOException if the passed in file is not a valid flag map file
     @FastNative
     private static native ByteBuffer getFlagReadContextImpl(
-        ByteBuffer mappedFile, int packageId, String flagName) throws IOException;
+            ByteBuffer mappedFile, int packageId, String flagName) throws IOException;
 
     // API to get flag read context
     // @param mappedFile: memory mapped flag map file
@@ -103,7 +98,7 @@ public class AconfigStorageReadAPI {
     // @param flagName: flag name
     // @throws IOException if the passed in file is not a valid flag map file
     public static FlagReadContext getFlagReadContext(
-        ByteBuffer mappedFile, int packageId, String flagName) throws IOException {
+            ByteBuffer mappedFile, int packageId, String flagName) throws IOException {
         ByteBuffer buffer = getFlagReadContextImpl(mappedFile, packageId, flagName);
         buffer.order(ByteOrder.LITTLE_ENDIAN);
         return new FlagReadContext(buffer.getInt(), buffer.getInt(4));
@@ -115,8 +110,11 @@ public class AconfigStorageReadAPI {
     // @throws IOException if the passed in file is not a valid flag value file or the
     // flag index went over the file boundary.
     @FastNative
-    public static native boolean getBooleanFlagValue(
-        ByteBuffer mappedFile, int flagIndex) throws IOException;
+    public static native boolean getBooleanFlagValue(ByteBuffer mappedFile, int flagIndex)
+            throws IOException;
+
+    @FastNative
+    public static native long hash(String packageName) throws IOException;
 
     static {
         System.loadLibrary("aconfig_storage_read_api_rust_jni");
diff --git a/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/StorageInternalReader.java b/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/StorageInternalReader.java
new file mode 100644
index 0000000000..29ebee5ab4
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_read_api/srcs/android/aconfig/storage/StorageInternalReader.java
@@ -0,0 +1,97 @@
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
+package android.aconfig.storage;
+
+import android.compat.annotation.UnsupportedAppUsage;
+import android.os.StrictMode;
+
+import java.io.Closeable;
+import java.nio.MappedByteBuffer;
+import java.nio.channels.FileChannel;
+import java.nio.file.Paths;
+import java.nio.file.StandardOpenOption;
+
+/** @hide */
+public class StorageInternalReader {
+
+    private static final String MAP_PATH = "/metadata/aconfig/maps/";
+    private static final String BOOT_PATH = "/metadata/aconfig/boot/";
+
+    private PackageTable mPackageTable;
+    private FlagValueList mFlagValueList;
+
+    private int mPackageBooleanStartOffset;
+
+    @UnsupportedAppUsage
+    public StorageInternalReader(String container, String packageName) {
+        this(packageName, MAP_PATH + container + ".package.map", BOOT_PATH + container + ".val");
+    }
+
+    @UnsupportedAppUsage
+    public StorageInternalReader(String packageName, String packageMapFile, String flagValueFile) {
+        StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskReads();
+        mPackageTable = PackageTable.fromBytes(mapStorageFile(packageMapFile));
+        mFlagValueList = FlagValueList.fromBytes(mapStorageFile(flagValueFile));
+        StrictMode.setThreadPolicy(oldPolicy);
+        mPackageBooleanStartOffset = getPackageBooleanStartOffset(packageName);
+    }
+
+    @UnsupportedAppUsage
+    public boolean getBooleanFlagValue(int index) {
+        index += mPackageBooleanStartOffset;
+        if (index >= mFlagValueList.size()) {
+            throw new AconfigStorageException("Fail to get boolean flag value");
+        }
+        return mFlagValueList.getBoolean(index);
+    }
+
+    private int getPackageBooleanStartOffset(String packageName) {
+        PackageTable.Node pNode = mPackageTable.get(packageName);
+        if (pNode == null) {
+            PackageTable.Header header = mPackageTable.getHeader();
+            throw new AconfigStorageException(
+                    String.format(
+                            "Fail to get package %s from container %s",
+                            packageName, header.getContainer()));
+        }
+        return pNode.getBooleanStartIndex();
+    }
+
+    // Map a storage file given file path
+    private static MappedByteBuffer mapStorageFile(String file) {
+        FileChannel channel = null;
+        try {
+            channel = FileChannel.open(Paths.get(file), StandardOpenOption.READ);
+            return channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());
+        } catch (Exception e) {
+            throw new AconfigStorageException(
+                    String.format("Fail to mmap storage file %s", file), e);
+        } finally {
+            quietlyDispose(channel);
+        }
+    }
+
+    private static void quietlyDispose(Closeable closable) {
+        try {
+            if (closable != null) {
+                closable.close();
+            }
+        } catch (Exception e) {
+            // no need to care, at least as of now
+        }
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_read_api/srcs/lib.rs b/tools/aconfig/aconfig_storage_read_api/srcs/lib.rs
index 304a059c90..f5f12bb1fa 100644
--- a/tools/aconfig/aconfig_storage_read_api/srcs/lib.rs
+++ b/tools/aconfig/aconfig_storage_read_api/srcs/lib.rs
@@ -1,5 +1,6 @@
 //! aconfig storage read api java rust interlop
 
+use aconfig_storage_file::SipHasher13;
 use aconfig_storage_read_api::flag_table_query::find_flag_read_context;
 use aconfig_storage_read_api::flag_value_query::find_boolean_flag_value;
 use aconfig_storage_read_api::package_table_query::find_package_read_context;
@@ -7,8 +8,9 @@ use aconfig_storage_read_api::{FlagReadContext, PackageReadContext};
 
 use anyhow::Result;
 use jni::objects::{JByteBuffer, JClass, JString};
-use jni::sys::{jboolean, jint};
+use jni::sys::{jboolean, jint, jlong};
 use jni::JNIEnv;
+use std::hash::Hasher;
 
 /// Call rust find package read context
 fn get_package_read_context_java(
@@ -158,3 +160,30 @@ pub extern "system" fn Java_android_aconfig_storage_AconfigStorageReadAPI_getBoo
         }
     }
 }
+
+/// Get flag value JNI
+#[no_mangle]
+#[allow(unused)]
+pub extern "system" fn Java_android_aconfig_storage_AconfigStorageReadAPI_hash<'local>(
+    mut env: JNIEnv<'local>,
+    class: JClass<'local>,
+    package_name: JString<'local>,
+) -> jlong {
+    match siphasher13_hash(&mut env, package_name) {
+        Ok(value) => value as jlong,
+        Err(errmsg) => {
+            env.throw(("java/io/IOException", errmsg.to_string())).expect("failed to throw");
+            0i64
+        }
+    }
+}
+
+fn siphasher13_hash(env: &mut JNIEnv, package_name: JString) -> Result<u64> {
+    // SAFETY:
+    // The safety here is ensured as the flag name is guaranteed to be a java string
+    let flag_name: String = unsafe { env.get_string_unchecked(&package_name)?.into() };
+    let mut s = SipHasher13::new();
+    s.write(flag_name.as_bytes());
+    s.write_u8(0xff);
+    Ok(s.finish())
+}
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/java/AconfigStorageReadAPITest.java b/tools/aconfig/aconfig_storage_read_api/tests/java/AconfigStorageReadAPITest.java
index a26b25707d..191741ef51 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/java/AconfigStorageReadAPITest.java
+++ b/tools/aconfig/aconfig_storage_read_api/tests/java/AconfigStorageReadAPITest.java
@@ -16,28 +16,29 @@
 
 package android.aconfig.storage.test;
 
-import java.io.IOException;
-import java.nio.MappedByteBuffer;
-import java.nio.ByteBuffer;
-import java.nio.ByteOrder;
-import java.util.ArrayList;
-import java.util.List;
-import java.util.Random;
-
 import static org.junit.Assert.assertEquals;
-import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
 
+import android.aconfig.DeviceProtos;
+import android.aconfig.nano.Aconfig.parsed_flag;
 import android.aconfig.storage.AconfigStorageReadAPI;
-import android.aconfig.storage.PackageReadContext;
 import android.aconfig.storage.FlagReadContext;
 import android.aconfig.storage.FlagReadContext.StoredFlagType;
+import android.aconfig.storage.PackageReadContext;
+import android.aconfig.storage.SipHasher13;
+import android.aconfig.storage.StorageInternalReader;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.io.IOException;
+import java.nio.MappedByteBuffer;
+import java.util.ArrayList;
+import java.util.List;
 
 @RunWith(JUnit4.class)
-public class AconfigStorageReadAPITest{
+public class AconfigStorageReadAPITest {
 
     private String mStorageDir = "/data/local/tmp/aconfig_java_api_test";
 
@@ -45,26 +46,29 @@ public class AconfigStorageReadAPITest{
     public void testPackageContextQuery() {
         MappedByteBuffer packageMap = null;
         try {
-            packageMap = AconfigStorageReadAPI.mapStorageFile(
-                mStorageDir + "/maps/mockup.package.map");
-        } catch(IOException ex){
+            packageMap =
+                    AconfigStorageReadAPI.mapStorageFile(mStorageDir + "/maps/mockup.package.map");
+        } catch (IOException ex) {
             assertTrue(ex.toString(), false);
         }
         assertTrue(packageMap != null);
 
         try {
-            PackageReadContext context = AconfigStorageReadAPI.getPackageReadContext(
-                packageMap, "com.android.aconfig.storage.test_1");
+            PackageReadContext context =
+                    AconfigStorageReadAPI.getPackageReadContext(
+                            packageMap, "com.android.aconfig.storage.test_1");
             assertEquals(context.mPackageId, 0);
             assertEquals(context.mBooleanStartIndex, 0);
 
-            context = AconfigStorageReadAPI.getPackageReadContext(
-                packageMap, "com.android.aconfig.storage.test_2");
+            context =
+                    AconfigStorageReadAPI.getPackageReadContext(
+                            packageMap, "com.android.aconfig.storage.test_2");
             assertEquals(context.mPackageId, 1);
             assertEquals(context.mBooleanStartIndex, 3);
 
-            context = AconfigStorageReadAPI.getPackageReadContext(
-                packageMap, "com.android.aconfig.storage.test_4");
+            context =
+                    AconfigStorageReadAPI.getPackageReadContext(
+                            packageMap, "com.android.aconfig.storage.test_4");
             assertEquals(context.mPackageId, 2);
             assertEquals(context.mBooleanStartIndex, 6);
         } catch (IOException ex) {
@@ -76,19 +80,19 @@ public class AconfigStorageReadAPITest{
     public void testNonExistPackageContextQuery() {
         MappedByteBuffer packageMap = null;
         try {
-            packageMap = AconfigStorageReadAPI.mapStorageFile(
-                mStorageDir + "/maps/mockup.package.map");
-        } catch(IOException ex){
+            packageMap =
+                    AconfigStorageReadAPI.mapStorageFile(mStorageDir + "/maps/mockup.package.map");
+        } catch (IOException ex) {
             assertTrue(ex.toString(), false);
         }
         assertTrue(packageMap != null);
 
         try {
-            PackageReadContext context = AconfigStorageReadAPI.getPackageReadContext(
-                packageMap, "unknown");
+            PackageReadContext context =
+                    AconfigStorageReadAPI.getPackageReadContext(packageMap, "unknown");
             assertEquals(context.mPackageId, -1);
             assertEquals(context.mBooleanStartIndex, -1);
-        } catch(IOException ex){
+        } catch (IOException ex) {
             assertTrue(ex.toString(), false);
         }
     }
@@ -97,12 +101,11 @@ public class AconfigStorageReadAPITest{
     public void testFlagContextQuery() {
         MappedByteBuffer flagMap = null;
         try {
-            flagMap = AconfigStorageReadAPI.mapStorageFile(
-                mStorageDir + "/maps/mockup.flag.map");
-        } catch(IOException ex){
+            flagMap = AconfigStorageReadAPI.mapStorageFile(mStorageDir + "/maps/mockup.flag.map");
+        } catch (IOException ex) {
             assertTrue(ex.toString(), false);
         }
-        assertTrue(flagMap!= null);
+        assertTrue(flagMap != null);
 
         class Baseline {
             public int mPackageId;
@@ -110,10 +113,8 @@ public class AconfigStorageReadAPITest{
             public StoredFlagType mFlagType;
             public int mFlagIndex;
 
-            public Baseline(int packageId,
-                    String flagName,
-                    StoredFlagType flagType,
-                    int flagIndex) {
+            public Baseline(
+                    int packageId, String flagName, StoredFlagType flagType, int flagIndex) {
                 mPackageId = packageId;
                 mFlagName = flagName;
                 mFlagType = flagType;
@@ -133,8 +134,9 @@ public class AconfigStorageReadAPITest{
 
         try {
             for (Baseline baseline : baselines) {
-                FlagReadContext context = AconfigStorageReadAPI.getFlagReadContext(
-                    flagMap, baseline.mPackageId,  baseline.mFlagName);
+                FlagReadContext context =
+                        AconfigStorageReadAPI.getFlagReadContext(
+                                flagMap, baseline.mPackageId, baseline.mFlagName);
                 assertEquals(context.mFlagType, baseline.mFlagType);
                 assertEquals(context.mFlagIndex, baseline.mFlagIndex);
             }
@@ -147,21 +149,19 @@ public class AconfigStorageReadAPITest{
     public void testNonExistFlagContextQuery() {
         MappedByteBuffer flagMap = null;
         try {
-            flagMap = AconfigStorageReadAPI.mapStorageFile(
-                mStorageDir + "/maps/mockup.flag.map");
-        } catch(IOException ex){
+            flagMap = AconfigStorageReadAPI.mapStorageFile(mStorageDir + "/maps/mockup.flag.map");
+        } catch (IOException ex) {
             assertTrue(ex.toString(), false);
         }
-        assertTrue(flagMap!= null);
+        assertTrue(flagMap != null);
 
         try {
-            FlagReadContext context = AconfigStorageReadAPI.getFlagReadContext(
-                flagMap, 0,  "unknown");
+            FlagReadContext context =
+                    AconfigStorageReadAPI.getFlagReadContext(flagMap, 0, "unknown");
             assertEquals(context.mFlagType, null);
             assertEquals(context.mFlagIndex, -1);
 
-            context = AconfigStorageReadAPI.getFlagReadContext(
-                flagMap, 3,  "enabled_ro");
+            context = AconfigStorageReadAPI.getFlagReadContext(flagMap, 3, "enabled_ro");
             assertEquals(context.mFlagType, null);
             assertEquals(context.mFlagIndex, -1);
         } catch (IOException ex) {
@@ -173,12 +173,11 @@ public class AconfigStorageReadAPITest{
     public void testBooleanFlagValueQuery() {
         MappedByteBuffer flagVal = null;
         try {
-            flagVal = AconfigStorageReadAPI.mapStorageFile(
-                mStorageDir + "/boot/mockup.val");
+            flagVal = AconfigStorageReadAPI.mapStorageFile(mStorageDir + "/boot/mockup.val");
         } catch (IOException ex) {
             assertTrue(ex.toString(), false);
         }
-        assertTrue(flagVal!= null);
+        assertTrue(flagVal != null);
 
         boolean[] baselines = {false, true, true, false, true, true, true, true};
         for (int i = 0; i < 8; ++i) {
@@ -195,12 +194,11 @@ public class AconfigStorageReadAPITest{
     public void testInvalidBooleanFlagValueQuery() {
         MappedByteBuffer flagVal = null;
         try {
-            flagVal = AconfigStorageReadAPI.mapStorageFile(
-                mStorageDir + "/boot/mockup.val");
+            flagVal = AconfigStorageReadAPI.mapStorageFile(mStorageDir + "/boot/mockup.val");
         } catch (IOException ex) {
             assertTrue(ex.toString(), false);
         }
-        assertTrue(flagVal!= null);
+        assertTrue(flagVal != null);
 
         try {
             Boolean value = AconfigStorageReadAPI.getBooleanFlagValue(flagVal, 9);
@@ -210,4 +208,63 @@ public class AconfigStorageReadAPITest{
             assertTrue(ex.toString(), ex.toString().contains(expectedErrmsg));
         }
     }
- }
+
+    @Test
+    public void testRustJavaEqualHash() throws IOException {
+        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
+        for (parsed_flag flag : flags) {
+            String packageName = flag.package_;
+            String flagName = flag.name;
+            long rHash = AconfigStorageReadAPI.hash(packageName);
+            long jHash = SipHasher13.hash(packageName.getBytes());
+            assertEquals(rHash, jHash);
+
+            String fullFlagName = packageName + "/" + flagName;
+            rHash = AconfigStorageReadAPI.hash(fullFlagName);
+            jHash = SipHasher13.hash(fullFlagName.getBytes());
+            assertEquals(rHash, jHash);
+        }
+    }
+
+    @Test
+    public void testRustJavaEqualFlag() throws IOException {
+        List<parsed_flag> flags = DeviceProtos.loadAndParseFlagProtos();
+
+        String mapPath = "/metadata/aconfig/maps/";
+        String flagsPath = "/metadata/aconfig/boot/";
+
+        for (parsed_flag flag : flags) {
+
+            String container = flag.container;
+            String packageName = flag.package_;
+            String flagName = flag.name;
+            String fullFlagName = packageName + "/" + flagName;
+
+            MappedByteBuffer packageMap =
+                    AconfigStorageReadAPI.mapStorageFile(mapPath + container + ".package.map");
+            MappedByteBuffer flagMap =
+                    AconfigStorageReadAPI.mapStorageFile(mapPath + container + ".flag.map");
+            MappedByteBuffer flagValList =
+                    AconfigStorageReadAPI.mapStorageFile(flagsPath + container + ".val");
+
+            PackageReadContext packageContext =
+                    AconfigStorageReadAPI.getPackageReadContext(packageMap, packageName);
+
+            FlagReadContext flagContext =
+                    AconfigStorageReadAPI.getFlagReadContext(
+                            flagMap, packageContext.mPackageId, flagName);
+
+            boolean rVal =
+                    AconfigStorageReadAPI.getBooleanFlagValue(
+                            flagValList,
+                            packageContext.mBooleanStartIndex + flagContext.mFlagIndex);
+
+            StorageInternalReader reader = new StorageInternalReader(container, packageName);
+            boolean jVal = reader.getBooleanFlagValue(flagContext.mFlagIndex);
+
+            long rHash = AconfigStorageReadAPI.hash(packageName);
+            long jHash = SipHasher13.hash(packageName.getBytes());
+            assertEquals(rVal, jVal);
+        }
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/java/Android.bp b/tools/aconfig/aconfig_storage_read_api/tests/java/Android.bp
index d94b2b438c..3d4e9ad218 100644
--- a/tools/aconfig/aconfig_storage_read_api/tests/java/Android.bp
+++ b/tools/aconfig/aconfig_storage_read_api/tests/java/Android.bp
@@ -1,7 +1,10 @@
 android_test {
     name: "aconfig_storage_read_api.test.java",
-    srcs: ["AconfigStorageReadAPITest.java"],
+    srcs: ["./**/*.java"],
     static_libs: [
+        "aconfig_device_paths_java",
+        "aconfig_storage_file_java",
+        "aconfig_storage_reader_java",
         "androidx.test.rules",
         "libaconfig_storage_read_api_java",
         "junit",
diff --git a/tools/aconfig/aconfig_storage_read_api/tests/java/StorageInternalReaderTest.java b/tools/aconfig/aconfig_storage_read_api/tests/java/StorageInternalReaderTest.java
new file mode 100644
index 0000000000..3a1bba0fad
--- /dev/null
+++ b/tools/aconfig/aconfig_storage_read_api/tests/java/StorageInternalReaderTest.java
@@ -0,0 +1,45 @@
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
+package android.aconfig.storage.test;
+
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+
+import android.aconfig.storage.StorageInternalReader;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+@RunWith(JUnit4.class)
+public class StorageInternalReaderTest {
+
+    private String mStorageDir = "/data/local/tmp/aconfig_java_api_test";
+
+    @Test
+    public void testStorageInternalReader_getFlag() {
+
+        String packageMapFile = mStorageDir + "/maps/mockup.package.map";
+        String flagValueFile = mStorageDir + "/boot/mockup.val";
+
+        StorageInternalReader reader =
+                new StorageInternalReader(
+                        "com.android.aconfig.storage.test_1", packageMapFile, flagValueFile);
+        assertFalse(reader.getBooleanFlagValue(0));
+        assertTrue(reader.getBooleanFlagValue(1));
+    }
+}
diff --git a/tools/aconfig/aconfig_storage_write_api/aconfig_storage_write_api.cpp b/tools/aconfig/aconfig_storage_write_api/aconfig_storage_write_api.cpp
index cabc65e40c..7b435746da 100644
--- a/tools/aconfig/aconfig_storage_write_api/aconfig_storage_write_api.cpp
+++ b/tools/aconfig/aconfig_storage_write_api/aconfig_storage_write_api.cpp
@@ -1,6 +1,7 @@
 
 #include <android-base/file.h>
 #include <android-base/logging.h>
+#include <android-base/unique_fd.h>
 
 #include <sys/mman.h>
 #include <sys/stat.h>
@@ -13,8 +14,8 @@
 namespace aconfig_storage {
 
 /// Map a storage file
-android::base::Result<MutableMappedStorageFile*> map_mutable_storage_file(
-    std::string const& file) {
+android::base::Result<MutableMappedStorageFile *> map_mutable_storage_file(
+    std::string const &file) {
   struct stat file_stat;
   if (stat(file.c_str(), &file_stat) < 0) {
     return android::base::ErrnoError() << "stat failed";
@@ -26,13 +27,13 @@ android::base::Result<MutableMappedStorageFile*> map_mutable_storage_file(
 
   size_t file_size = file_stat.st_size;
 
-  const int fd = open(file.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC);
-  if (fd == -1) {
+  android::base::unique_fd ufd(open(file.c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC));
+  if (ufd.get() == -1) {
     return android::base::ErrnoError() << "failed to open " << file;
   };
 
-  void* const map_result =
-      mmap(nullptr, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
+  void *const map_result =
+      mmap(nullptr, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, ufd.get(), 0);
   if (map_result == MAP_FAILED) {
     return android::base::ErrnoError() << "mmap failed";
   }
@@ -46,47 +47,56 @@ android::base::Result<MutableMappedStorageFile*> map_mutable_storage_file(
 
 /// Set boolean flag value
 android::base::Result<void> set_boolean_flag_value(
-    const MutableMappedStorageFile& file,
+    const MutableMappedStorageFile &file,
     uint32_t offset,
     bool value) {
   auto content = rust::Slice<uint8_t>(
-      static_cast<uint8_t*>(file.file_ptr), file.file_size);
+      static_cast<uint8_t *>(file.file_ptr), file.file_size);
   auto update_cxx = update_boolean_flag_value_cxx(content, offset, value);
   if (!update_cxx.update_success) {
     return android::base::Error() << update_cxx.error_message.c_str();
   }
+  if (!msync(static_cast<uint8_t *>(file.file_ptr) + update_cxx.offset, 1, MS_SYNC)) {
+    return android::base::ErrnoError() << "msync failed";
+  }
   return {};
 }
 
 /// Set if flag has server override
 android::base::Result<void> set_flag_has_server_override(
-    const MutableMappedStorageFile& file,
+    const MutableMappedStorageFile &file,
     FlagValueType value_type,
     uint32_t offset,
     bool value) {
   auto content = rust::Slice<uint8_t>(
-      static_cast<uint8_t*>(file.file_ptr), file.file_size);
+      static_cast<uint8_t *>(file.file_ptr), file.file_size);
   auto update_cxx = update_flag_has_server_override_cxx(
       content, static_cast<uint16_t>(value_type), offset, value);
   if (!update_cxx.update_success) {
     return android::base::Error() << update_cxx.error_message.c_str();
   }
+  if (!msync(static_cast<uint8_t *>(file.file_ptr) + update_cxx.offset, 1, MS_SYNC)) {
+    return android::base::ErrnoError() << "msync failed";
+  }
   return {};
 }
 
 /// Set if flag has local override
 android::base::Result<void> set_flag_has_local_override(
-    const MutableMappedStorageFile& file,
+    const MutableMappedStorageFile &file,
     FlagValueType value_type,
     uint32_t offset,
     bool value) {
   auto content = rust::Slice<uint8_t>(
-      static_cast<uint8_t*>(file.file_ptr), file.file_size);
+      static_cast<uint8_t *>(file.file_ptr), file.file_size);
   auto update_cxx = update_flag_has_local_override_cxx(
       content, static_cast<uint16_t>(value_type), offset, value);
   if (!update_cxx.update_success) {
     return android::base::Error() << update_cxx.error_message.c_str();
   }
+  if (!msync(static_cast<uint8_t *>(file.file_ptr) + update_cxx.offset, 1, MS_SYNC)) {
+    return android::base::ErrnoError() << "msync failed";
+  }
   return {};
 }
 
diff --git a/tools/aconfig/aconfig_storage_write_api/src/flag_info_update.rs b/tools/aconfig/aconfig_storage_write_api/src/flag_info_update.rs
index 6f03f128a5..7e6071340c 100644
--- a/tools/aconfig/aconfig_storage_write_api/src/flag_info_update.rs
+++ b/tools/aconfig/aconfig_storage_write_api/src/flag_info_update.rs
@@ -67,13 +67,13 @@ pub fn update_flag_has_server_override(
     flag_type: FlagValueType,
     flag_index: u32,
     value: bool,
-) -> Result<(), AconfigStorageError> {
+) -> Result<usize, AconfigStorageError> {
     let (attribute, head) = get_flag_attribute_and_offset(buf, flag_type, flag_index)?;
     let has_override = (attribute & (FlagInfoBit::HasServerOverride as u8)) != 0;
     if has_override != value {
         buf[head] = (attribute ^ FlagInfoBit::HasServerOverride as u8).to_le_bytes()[0];
     }
-    Ok(())
+    Ok(head)
 }
 
 /// Set if flag has local override
@@ -82,13 +82,13 @@ pub fn update_flag_has_local_override(
     flag_type: FlagValueType,
     flag_index: u32,
     value: bool,
-) -> Result<(), AconfigStorageError> {
+) -> Result<usize, AconfigStorageError> {
     let (attribute, head) = get_flag_attribute_and_offset(buf, flag_type, flag_index)?;
     let has_override = (attribute & (FlagInfoBit::HasLocalOverride as u8)) != 0;
     if has_override != value {
         buf[head] = (attribute ^ FlagInfoBit::HasLocalOverride as u8).to_le_bytes()[0];
     }
-    Ok(())
+    Ok(head)
 }
 
 #[cfg(test)]
diff --git a/tools/aconfig/aconfig_storage_write_api/src/flag_value_update.rs b/tools/aconfig/aconfig_storage_write_api/src/flag_value_update.rs
index 0938715714..dd15c996a6 100644
--- a/tools/aconfig/aconfig_storage_write_api/src/flag_value_update.rs
+++ b/tools/aconfig/aconfig_storage_write_api/src/flag_value_update.rs
@@ -24,7 +24,7 @@ pub fn update_boolean_flag_value(
     buf: &mut [u8],
     flag_index: u32,
     flag_value: bool,
-) -> Result<(), AconfigStorageError> {
+) -> Result<usize, AconfigStorageError> {
     let interpreted_header = FlagValueHeader::from_bytes(buf)?;
     if interpreted_header.version > FILE_VERSION {
         return Err(AconfigStorageError::HigherStorageFileVersion(anyhow!(
@@ -43,7 +43,7 @@ pub fn update_boolean_flag_value(
     }
 
     buf[head] = u8::from(flag_value).to_le_bytes()[0];
-    Ok(())
+    Ok(head)
 }
 
 #[cfg(test)]
diff --git a/tools/aconfig/aconfig_storage_write_api/src/lib.rs b/tools/aconfig/aconfig_storage_write_api/src/lib.rs
index aec28def68..0396a63d4e 100644
--- a/tools/aconfig/aconfig_storage_write_api/src/lib.rs
+++ b/tools/aconfig/aconfig_storage_write_api/src/lib.rs
@@ -194,18 +194,21 @@ mod ffi {
     // Flag value update return for cc interlop
     pub struct BooleanFlagValueUpdateCXX {
         pub update_success: bool,
+        pub offset: usize,
         pub error_message: String,
     }
 
     // Flag has server override update return for cc interlop
     pub struct FlagHasServerOverrideUpdateCXX {
         pub update_success: bool,
+        pub offset: usize,
         pub error_message: String,
     }
 
     // Flag has local override update return for cc interlop
     pub struct FlagHasLocalOverrideUpdateCXX {
         pub update_success: bool,
+        pub offset: usize,
         pub error_message: String,
     }
 
@@ -251,11 +254,14 @@ pub(crate) fn update_boolean_flag_value_cxx(
     value: bool,
 ) -> ffi::BooleanFlagValueUpdateCXX {
     match crate::flag_value_update::update_boolean_flag_value(file, offset, value) {
-        Ok(()) => {
-            ffi::BooleanFlagValueUpdateCXX { update_success: true, error_message: String::from("") }
-        }
+        Ok(head) => ffi::BooleanFlagValueUpdateCXX {
+            update_success: true,
+            offset: head,
+            error_message: String::from(""),
+        },
         Err(errmsg) => ffi::BooleanFlagValueUpdateCXX {
             update_success: false,
+            offset: usize::MAX,
             error_message: format!("{:?}", errmsg),
         },
     }
@@ -272,18 +278,21 @@ pub(crate) fn update_flag_has_server_override_cxx(
             match crate::flag_info_update::update_flag_has_server_override(
                 file, value_type, offset, value,
             ) {
-                Ok(()) => ffi::FlagHasServerOverrideUpdateCXX {
+                Ok(head) => ffi::FlagHasServerOverrideUpdateCXX {
                     update_success: true,
+                    offset: head,
                     error_message: String::from(""),
                 },
                 Err(errmsg) => ffi::FlagHasServerOverrideUpdateCXX {
                     update_success: false,
+                    offset: usize::MAX,
                     error_message: format!("{:?}", errmsg),
                 },
             }
         }
         Err(errmsg) => ffi::FlagHasServerOverrideUpdateCXX {
             update_success: false,
+            offset: usize::MAX,
             error_message: format!("{:?}", errmsg),
         },
     }
@@ -300,18 +309,21 @@ pub(crate) fn update_flag_has_local_override_cxx(
             match crate::flag_info_update::update_flag_has_local_override(
                 file, value_type, offset, value,
             ) {
-                Ok(()) => ffi::FlagHasLocalOverrideUpdateCXX {
+                Ok(head) => ffi::FlagHasLocalOverrideUpdateCXX {
                     update_success: true,
+                    offset: head,
                     error_message: String::from(""),
                 },
                 Err(errmsg) => ffi::FlagHasLocalOverrideUpdateCXX {
                     update_success: false,
+                    offset: usize::MAX,
                     error_message: format!("{:?}", errmsg),
                 },
             }
         }
         Err(errmsg) => ffi::FlagHasLocalOverrideUpdateCXX {
             update_success: false,
+            offset: usize::MAX,
             error_message: format!("{:?}", errmsg),
         },
     }
diff --git a/tools/aconfig/aconfig_storage_write_api/tests/Android.bp b/tools/aconfig/aconfig_storage_write_api/tests/Android.bp
index f6409b7090..5508dacbea 100644
--- a/tools/aconfig/aconfig_storage_write_api/tests/Android.bp
+++ b/tools/aconfig/aconfig_storage_write_api/tests/Android.bp
@@ -38,5 +38,10 @@ cc_test {
         "device-tests",
         "general-tests",
     ],
-    ldflags: ["-Wl,--allow-multiple-definition"],
+    generated_headers: [
+        "cxx-bridge-header",
+        "libcxx_aconfig_storage_read_api_bridge_header",
+    ],
+    generated_sources: ["libcxx_aconfig_storage_read_api_bridge_code"],
+    whole_static_libs: ["libaconfig_storage_read_api_cxx_bridge"],
 }
diff --git a/tools/aconfig/aconfig_storage_write_api/tests/storage_write_api_test.cpp b/tools/aconfig/aconfig_storage_write_api/tests/storage_write_api_test.cpp
index 31183fa01b..133f5a0592 100644
--- a/tools/aconfig/aconfig_storage_write_api/tests/storage_write_api_test.cpp
+++ b/tools/aconfig/aconfig_storage_write_api/tests/storage_write_api_test.cpp
@@ -25,6 +25,9 @@
 #include <android-base/file.h>
 #include <android-base/result.h>
 
+#include "rust/cxx.h"
+#include "aconfig_storage/lib.rs.h"
+
 using namespace android::base;
 
 namespace api = aconfig_storage;
@@ -85,6 +88,23 @@ TEST_F(AconfigStorageTest, test_boolean_flag_value_update) {
     ASSERT_TRUE(value.ok());
     ASSERT_TRUE(*value);
   }
+
+  // load the file on disk and check has been updated
+  std::ifstream file(flag_val, std::ios::binary | std::ios::ate);
+  std::streamsize size = file.tellg();
+  file.seekg(0, std::ios::beg);
+
+  std::vector<uint8_t> buffer(size);
+  file.read(reinterpret_cast<char *>(buffer.data()), size);
+
+  auto content = rust::Slice<const uint8_t>(
+      buffer.data(), mapped_file->file_size);
+
+  for (int offset = 0; offset < 8; ++offset) {
+    auto value_cxx = get_boolean_flag_value_cxx(content, offset);
+    ASSERT_TRUE(value_cxx.query_success);
+    ASSERT_TRUE(value_cxx.flag_value);
+  }
 }
 
 /// Negative test to lock down the error when querying flag value out of range
@@ -112,15 +132,43 @@ TEST_F(AconfigStorageTest, test_flag_has_server_override_update) {
         *mapped_file, api::FlagValueType::Boolean, offset);
     ASSERT_TRUE(attribute.ok());
     ASSERT_TRUE(*attribute & api::FlagInfoBit::HasServerOverride);
+  }
+
+  // load the file on disk and check has been updated
+  std::ifstream file(flag_info, std::ios::binary | std::ios::ate);
+  std::streamsize size = file.tellg();
+  file.seekg(0, std::ios::beg);
 
-    update_result = api::set_flag_has_server_override(
+  std::vector<uint8_t> buffer(size);
+  file.read(reinterpret_cast<char *>(buffer.data()), size);
+
+  auto content = rust::Slice<const uint8_t>(
+      buffer.data(), mapped_file->file_size);
+
+  for (int offset = 0; offset < 8; ++offset) {
+    auto attribute = get_flag_attribute_cxx(content, api::FlagValueType::Boolean, offset);
+    ASSERT_TRUE(attribute.query_success);
+    ASSERT_TRUE(attribute.flag_attribute & api::FlagInfoBit::HasServerOverride);
+  }
+
+  for (int offset = 0; offset < 8; ++offset) {
+    auto update_result = api::set_flag_has_server_override(
         *mapped_file, api::FlagValueType::Boolean, offset, false);
     ASSERT_TRUE(update_result.ok());
-    attribute = api::get_flag_attribute(
+    auto attribute = api::get_flag_attribute(
         *mapped_file, api::FlagValueType::Boolean, offset);
     ASSERT_TRUE(attribute.ok());
     ASSERT_FALSE(*attribute & api::FlagInfoBit::HasServerOverride);
   }
+
+  std::ifstream file2(flag_info, std::ios::binary);
+  buffer.clear();
+  file2.read(reinterpret_cast<char *>(buffer.data()), size);
+  for (int offset = 0; offset < 8; ++offset) {
+    auto attribute = get_flag_attribute_cxx(content, api::FlagValueType::Boolean, offset);
+    ASSERT_TRUE(attribute.query_success);
+    ASSERT_FALSE(attribute.flag_attribute & api::FlagInfoBit::HasServerOverride);
+  }
 }
 
 /// Test to lock down storage flag has local override update api
@@ -137,13 +185,41 @@ TEST_F(AconfigStorageTest, test_flag_has_local_override_update) {
         *mapped_file, api::FlagValueType::Boolean, offset);
     ASSERT_TRUE(attribute.ok());
     ASSERT_TRUE(*attribute & api::FlagInfoBit::HasLocalOverride);
+  }
+
+  // load the file on disk and check has been updated
+  std::ifstream file(flag_info, std::ios::binary | std::ios::ate);
+  std::streamsize size = file.tellg();
+  file.seekg(0, std::ios::beg);
+
+  std::vector<uint8_t> buffer(size);
+  file.read(reinterpret_cast<char *>(buffer.data()), size);
+
+  auto content = rust::Slice<const uint8_t>(
+      buffer.data(), mapped_file->file_size);
+
+  for (int offset = 0; offset < 8; ++offset) {
+    auto attribute = get_flag_attribute_cxx(content, api::FlagValueType::Boolean, offset);
+    ASSERT_TRUE(attribute.query_success);
+    ASSERT_TRUE(attribute.flag_attribute & api::FlagInfoBit::HasLocalOverride);
+  }
 
-    update_result = api::set_flag_has_local_override(
+  for (int offset = 0; offset < 8; ++offset) {
+    auto update_result = api::set_flag_has_local_override(
         *mapped_file, api::FlagValueType::Boolean, offset, false);
     ASSERT_TRUE(update_result.ok());
-    attribute = api::get_flag_attribute(
+    auto attribute = api::get_flag_attribute(
         *mapped_file, api::FlagValueType::Boolean, offset);
     ASSERT_TRUE(attribute.ok());
     ASSERT_FALSE(*attribute & api::FlagInfoBit::HasLocalOverride);
   }
+
+  std::ifstream file2(flag_info, std::ios::binary);
+  buffer.clear();
+  file2.read(reinterpret_cast<char *>(buffer.data()), size);
+  for (int offset = 0; offset < 8; ++offset) {
+    auto attribute = get_flag_attribute_cxx(content, api::FlagValueType::Boolean, offset);
+    ASSERT_TRUE(attribute.query_success);
+    ASSERT_FALSE(attribute.flag_attribute & api::FlagInfoBit::HasLocalOverride);
+  }
 }
diff --git a/tools/aconfig/aflags/Android.bp b/tools/aconfig/aflags/Android.bp
index 2a023792b6..2040cc635b 100644
--- a/tools/aconfig/aflags/Android.bp
+++ b/tools/aconfig/aflags/Android.bp
@@ -10,7 +10,9 @@ rust_defaults {
     srcs: ["src/main.rs"],
     rustlibs: [
         "libaconfig_device_paths",
+        "libaconfig_flags",
         "libaconfig_protos",
+        "libaconfigd_protos",
         "libaconfig_storage_read_api",
         "libaconfig_storage_file",
         "libanyhow",
@@ -23,6 +25,7 @@ rust_defaults {
 
 rust_binary {
     name: "aflags",
+    host_supported: true,
     defaults: ["aflags.defaults"],
 }
 
diff --git a/tools/aconfig/aflags/Cargo.toml b/tools/aconfig/aflags/Cargo.toml
index eeae295316..7efce6dc96 100644
--- a/tools/aconfig/aflags/Cargo.toml
+++ b/tools/aconfig/aflags/Cargo.toml
@@ -9,8 +9,10 @@ paste = "1.0.11"
 protobuf = "3.2.0"
 regex = "1.10.3"
 aconfig_protos = { path = "../aconfig_protos" }
+aconfigd_protos = { version = "0.1.0", path = "../../../../../system/server_configurable_flags/aconfigd"}
 nix = { version = "0.28.0", features = ["user"] }
 aconfig_storage_file = { version = "0.1.0", path = "../aconfig_storage_file" }
 aconfig_storage_read_api = { version = "0.1.0", path = "../aconfig_storage_read_api" }
 clap = {version = "4.5.2" }
 aconfig_device_paths = { version = "0.1.0", path = "../aconfig_device_paths" }
+aconfig_flags = { version = "0.1.0", path = "../aconfig_flags" }
\ No newline at end of file
diff --git a/tools/aconfig/aflags/src/aconfig_storage_source.rs b/tools/aconfig/aflags/src/aconfig_storage_source.rs
index 04140c7fa3..68edf7d3ac 100644
--- a/tools/aconfig/aflags/src/aconfig_storage_source.rs
+++ b/tools/aconfig/aflags/src/aconfig_storage_source.rs
@@ -1,52 +1,141 @@
-use crate::{Flag, FlagPermission, FlagSource, FlagValue, ValuePickedFrom};
-use anyhow::{anyhow, Result};
-
-use std::fs::File;
-use std::io::Read;
+use crate::load_protos;
+use crate::{Flag, FlagSource};
+use crate::{FlagPermission, FlagValue, ValuePickedFrom};
+use aconfigd_protos::{
+    ProtoFlagQueryReturnMessage, ProtoListStorageMessage, ProtoListStorageMessageMsg,
+    ProtoStorageRequestMessage, ProtoStorageRequestMessageMsg, ProtoStorageRequestMessages,
+    ProtoStorageReturnMessage, ProtoStorageReturnMessageMsg, ProtoStorageReturnMessages,
+};
+use anyhow::anyhow;
+use anyhow::Result;
+use protobuf::Message;
+use protobuf::SpecialFields;
+use std::collections::HashMap;
+use std::io::{Read, Write};
+use std::net::Shutdown;
+use std::os::unix::net::UnixStream;
 
 pub struct AconfigStorageSource {}
 
-use aconfig_storage_file::protos::ProtoStorageFiles;
+fn load_flag_to_container() -> Result<HashMap<String, String>> {
+    Ok(load_protos::load()?.into_iter().map(|p| (p.qualified_name(), p.container)).collect())
+}
 
-static STORAGE_INFO_FILE_PATH: &str = "/metadata/aconfig/persistent_storage_file_records.pb";
+fn convert(msg: ProtoFlagQueryReturnMessage, containers: &HashMap<String, String>) -> Result<Flag> {
+    let (value, value_picked_from) = match (
+        &msg.boot_flag_value,
+        msg.default_flag_value,
+        msg.local_flag_value,
+        msg.has_local_override,
+    ) {
+        (_, _, Some(local), Some(has_local)) if has_local => {
+            (FlagValue::try_from(local.as_str())?, ValuePickedFrom::Local)
+        }
+        (Some(boot), Some(default), _, _) => {
+            let value = FlagValue::try_from(boot.as_str())?;
+            if *boot == default {
+                (value, ValuePickedFrom::Default)
+            } else {
+                (value, ValuePickedFrom::Server)
+            }
+        }
+        _ => return Err(anyhow!("missing override")),
+    };
 
-impl FlagSource for AconfigStorageSource {
-    fn list_flags() -> Result<Vec<Flag>> {
-        let mut result = Vec::new();
-
-        let mut file = File::open(STORAGE_INFO_FILE_PATH)?;
-        let mut bytes = Vec::new();
-        file.read_to_end(&mut bytes)?;
-        let storage_file_info: ProtoStorageFiles = protobuf::Message::parse_from_bytes(&bytes)?;
-
-        for file_info in storage_file_info.files {
-            let package_map =
-                file_info.package_map.ok_or(anyhow!("storage file is missing package map"))?;
-            let flag_map = file_info.flag_map.ok_or(anyhow!("storage file is missing flag map"))?;
-            let flag_val = file_info.flag_val.ok_or(anyhow!("storage file is missing flag val"))?;
-            let container =
-                file_info.container.ok_or(anyhow!("storage file is missing container"))?;
-
-            for listed_flag in aconfig_storage_file::list_flags(&package_map, &flag_map, &flag_val)?
-            {
-                result.push(Flag {
-                    name: listed_flag.flag_name,
-                    package: listed_flag.package_name,
-                    value: FlagValue::try_from(listed_flag.flag_value.as_str())?,
-                    container: container.to_string(),
-
-                    // TODO(b/324436145): delete namespace field once DeviceConfig isn't in CLI.
-                    namespace: "-".to_string(),
-
-                    // TODO(b/324436145): Populate with real values once API is available.
-                    staged_value: None,
-                    permission: FlagPermission::ReadOnly,
-                    value_picked_from: ValuePickedFrom::Default,
-                });
+    let staged_value = match (msg.boot_flag_value, msg.server_flag_value, msg.has_server_override) {
+        (Some(boot), Some(server), _) if boot == server => None,
+        (Some(boot), Some(server), Some(has_server)) if boot != server && has_server => {
+            Some(FlagValue::try_from(server.as_str())?)
+        }
+        _ => None,
+    };
+
+    let permission = match msg.is_readwrite {
+        Some(is_readwrite) => {
+            if is_readwrite {
+                FlagPermission::ReadWrite
+            } else {
+                FlagPermission::ReadOnly
             }
         }
+        None => return Err(anyhow!("missing permission")),
+    };
+
+    let name = msg.flag_name.ok_or(anyhow!("missing flag name"))?;
+    let package = msg.package_name.ok_or(anyhow!("missing package name"))?;
+    let qualified_name = format!("{package}.{name}");
+    Ok(Flag {
+        name,
+        package,
+        value,
+        permission,
+        value_picked_from,
+        staged_value,
+        container: containers
+            .get(&qualified_name)
+            .cloned()
+            .unwrap_or_else(|| "<no container>".to_string())
+            .to_string(),
+        // TODO: remove once DeviceConfig is not in the CLI.
+        namespace: "-".to_string(),
+    })
+}
 
-        Ok(result)
+fn read_from_socket() -> Result<Vec<ProtoFlagQueryReturnMessage>> {
+    let messages = ProtoStorageRequestMessages {
+        msgs: vec![ProtoStorageRequestMessage {
+            msg: Some(ProtoStorageRequestMessageMsg::ListStorageMessage(ProtoListStorageMessage {
+                msg: Some(ProtoListStorageMessageMsg::All(true)),
+                special_fields: SpecialFields::new(),
+            })),
+            special_fields: SpecialFields::new(),
+        }],
+        special_fields: SpecialFields::new(),
+    };
+
+    let mut socket = UnixStream::connect("/dev/socket/aconfigd")?;
+
+    let message_buffer = messages.write_to_bytes()?;
+    let mut message_length_buffer: [u8; 4] = [0; 4];
+    let message_size = &message_buffer.len();
+    message_length_buffer[0] = (message_size >> 24) as u8;
+    message_length_buffer[1] = (message_size >> 16) as u8;
+    message_length_buffer[2] = (message_size >> 8) as u8;
+    message_length_buffer[3] = *message_size as u8;
+    socket.write_all(&message_length_buffer)?;
+    socket.write_all(&message_buffer)?;
+    socket.shutdown(Shutdown::Write)?;
+
+    let mut response_length_buffer: [u8; 4] = [0; 4];
+    socket.read_exact(&mut response_length_buffer)?;
+    let response_length = u32::from_be_bytes(response_length_buffer) as usize;
+    let mut response_buffer = vec![0; response_length];
+    socket.read_exact(&mut response_buffer)?;
+
+    let response: ProtoStorageReturnMessages =
+        protobuf::Message::parse_from_bytes(&response_buffer)?;
+
+    match response.msgs.as_slice() {
+        [ProtoStorageReturnMessage {
+            msg: Some(ProtoStorageReturnMessageMsg::ListStorageMessage(list_storage_message)),
+            ..
+        }] => Ok(list_storage_message.flags.clone()),
+        _ => Err(anyhow!("unexpected response from aconfigd")),
+    }
+}
+
+impl FlagSource for AconfigStorageSource {
+    fn list_flags() -> Result<Vec<Flag>> {
+        let containers = load_flag_to_container()?;
+        read_from_socket()
+            .map(|query_messages| {
+                query_messages
+                    .iter()
+                    .map(|message| convert(message.clone(), &containers))
+                    .collect::<Vec<_>>()
+            })?
+            .into_iter()
+            .collect()
     }
 
     fn override_flag(_namespace: &str, _qualified_name: &str, _value: &str) -> Result<()> {
diff --git a/tools/aconfig/aflags/src/main.rs b/tools/aconfig/aflags/src/main.rs
index 05c15bb304..07b7243ab4 100644
--- a/tools/aconfig/aflags/src/main.rs
+++ b/tools/aconfig/aflags/src/main.rs
@@ -50,6 +50,7 @@ impl std::fmt::Display for FlagPermission {
 enum ValuePickedFrom {
     Default,
     Server,
+    Local,
 }
 
 impl std::fmt::Display for ValuePickedFrom {
@@ -60,6 +61,7 @@ impl std::fmt::Display for ValuePickedFrom {
             match &self {
                 Self::Default => "default",
                 Self::Server => "server",
+                Self::Local => "local",
             }
         )
     }
@@ -114,9 +116,10 @@ impl Flag {
     }
 
     fn display_staged_value(&self) -> String {
-        match self.staged_value {
-            Some(v) => format!("(->{})", v),
-            None => "-".to_string(),
+        match (&self.permission, self.staged_value) {
+            (FlagPermission::ReadOnly, _) => "-".to_string(),
+            (FlagPermission::ReadWrite, None) => "-".to_string(),
+            (FlagPermission::ReadWrite, Some(v)) => format!("(->{})", v),
         }
     }
 }
@@ -162,10 +165,6 @@ struct Cli {
 enum Command {
     /// List all aconfig flags on this device.
     List {
-        /// Read from the new flag storage.
-        #[clap(long)]
-        use_new_storage: bool,
-
         /// Optionally filter by container name.
         #[clap(short = 'c', long = "container")]
         container: Option<String>,
@@ -182,6 +181,9 @@ enum Command {
         /// <package>.<flag_name>
         qualified_name: String,
     },
+
+    /// Display which flag storage backs aconfig flags.
+    WhichBacking,
 }
 
 struct PaddingInfo {
@@ -233,8 +235,6 @@ fn format_flag_row(flag: &Flag, info: &PaddingInfo) -> String {
 }
 
 fn set_flag(qualified_name: &str, value: &str) -> Result<()> {
-    ensure!(nix::unistd::Uid::current().is_root(), "must be root to mutate flags");
-
     let flags_binding = DeviceConfigSource::list_flags()?;
     let flag = flags_binding.iter().find(|f| f.qualified_name() == qualified_name).ok_or(
         anyhow!("no aconfig flag '{qualified_name}'. Does the flag have an .aconfig definition?"),
@@ -282,23 +282,39 @@ fn list(source_type: FlagSourceType, container: Option<String>) -> Result<String
     Ok(result)
 }
 
-fn main() {
+fn display_which_backing() -> String {
+    if aconfig_flags::auto_generated::enable_only_new_storage() {
+        "aconfig_storage".to_string()
+    } else {
+        "device_config".to_string()
+    }
+}
+
+fn main() -> Result<()> {
+    ensure!(nix::unistd::Uid::current().is_root(), "must be root");
+
     let cli = Cli::parse();
     let output = match cli.command {
-        Command::List { use_new_storage: true, container } => {
-            list(FlagSourceType::AconfigStorage, container).map(Some)
-        }
-        Command::List { use_new_storage: false, container } => {
-            list(FlagSourceType::DeviceConfig, container).map(Some)
+        Command::List { container } => {
+            if aconfig_flags::auto_generated::enable_only_new_storage() {
+                list(FlagSourceType::AconfigStorage, container)
+                    .map_err(|err| anyhow!("storage may not be enabled: {err}"))
+                    .map(Some)
+            } else {
+                list(FlagSourceType::DeviceConfig, container).map(Some)
+            }
         }
         Command::Enable { qualified_name } => set_flag(&qualified_name, "true").map(|_| None),
         Command::Disable { qualified_name } => set_flag(&qualified_name, "false").map(|_| None),
+        Command::WhichBacking => Ok(Some(display_which_backing())),
     };
     match output {
         Ok(Some(text)) => println!("{text}"),
         Ok(None) => (),
         Err(message) => println!("Error: {message}"),
     }
+
+    Ok(())
 }
 
 #[cfg(test)]
diff --git a/tools/aconfig/fake_device_config/Android.bp b/tools/aconfig/fake_device_config/Android.bp
index 4566bf985a..7704742601 100644
--- a/tools/aconfig/fake_device_config/Android.bp
+++ b/tools/aconfig/fake_device_config/Android.bp
@@ -13,10 +13,24 @@
 // limitations under the License.
 
 java_library {
-	name: "fake_device_config",
-	srcs: ["src/**/*.java"],
-	sdk_version: "none",
-	system_modules: "core-all-system-modules",
-	host_supported: true,
+    name: "fake_device_config",
+    srcs: [
+        "src/android/util/Log.java",
+        "src/android/provider/DeviceConfig.java",
+        "src/android/os/StrictMode.java",
+    ],
+    sdk_version: "none",
+    system_modules: "core-all-system-modules",
+    host_supported: true,
+    is_stubs_module: true,
 }
 
+java_library {
+    name: "strict_mode_stub",
+    srcs: [
+        "src/android/os/StrictMode.java",
+    ],
+    sdk_version: "core_current",
+    host_supported: true,
+    is_stubs_module: true,
+}
diff --git a/tools/aconfig/fake_device_config/src/android/os/StrictMode.java b/tools/aconfig/fake_device_config/src/android/os/StrictMode.java
new file mode 100644
index 0000000000..641625206c
--- /dev/null
+++ b/tools/aconfig/fake_device_config/src/android/os/StrictMode.java
@@ -0,0 +1,29 @@
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
+package android.os;
+
+public class StrictMode {
+    public static ThreadPolicy allowThreadDiskReads() {
+        throw new UnsupportedOperationException("Stub!");
+    }
+
+    public static void setThreadPolicy(final ThreadPolicy policy) {
+        throw new UnsupportedOperationException("Stub!");
+    }
+
+    public static final class ThreadPolicy {}
+}
diff --git a/tools/aconfig/fake_device_config/src/android/util/Log.java b/tools/aconfig/fake_device_config/src/android/util/Log.java
new file mode 100644
index 0000000000..79de68060e
--- /dev/null
+++ b/tools/aconfig/fake_device_config/src/android/util/Log.java
@@ -0,0 +1,19 @@
+package android.util;
+
+public final class Log {
+    public static int i(String tag, String msg) {
+        return 0;
+    }
+
+    public static int w(String tag, String msg) {
+        return 0;
+    }
+
+    public static int e(String tag, String msg) {
+        return 0;
+    }
+
+    public static int e(String tag, String msg, Throwable tr) {
+        return 0;
+    }
+}
diff --git a/tools/check-flagged-apis/src/com/android/checkflaggedapis/Main.kt b/tools/check-flagged-apis/src/com/android/checkflaggedapis/Main.kt
index 1125d393bf..d323c200da 100644
--- a/tools/check-flagged-apis/src/com/android/checkflaggedapis/Main.kt
+++ b/tools/check-flagged-apis/src/com/android/checkflaggedapis/Main.kt
@@ -19,10 +19,10 @@ package com.android.checkflaggedapis
 
 import android.aconfig.Aconfig
 import com.android.tools.metalava.model.BaseItemVisitor
+import com.android.tools.metalava.model.CallableItem
 import com.android.tools.metalava.model.ClassItem
 import com.android.tools.metalava.model.FieldItem
 import com.android.tools.metalava.model.Item
-import com.android.tools.metalava.model.MethodItem
 import com.android.tools.metalava.model.text.ApiFile
 import com.github.ajalt.clikt.core.CliktCommand
 import com.github.ajalt.clikt.core.ProgramResult
@@ -274,15 +274,15 @@ internal fun parseApiSignature(path: String, input: InputStream): Set<Pair<Symbo
           }
         }
 
-        override fun visitMethod(method: MethodItem) {
-          getFlagOrNull(method)?.let { flag ->
-            val methodName = buildString {
-              append(method.name())
+        override fun visitCallable(callable: CallableItem) {
+          getFlagOrNull(callable)?.let { flag ->
+            val callableSignature = buildString {
+              append(callable.name())
               append("(")
-              method.parameters().joinTo(this, separator = "") { it.type().internalName() }
+              callable.parameters().joinTo(this, separator = "") { it.type().internalName() }
               append(")")
             }
-            val symbol = Symbol.createMethod(method.containingClass().qualifiedName(), methodName)
+            val symbol = Symbol.createMethod(callable.containingClass().qualifiedName(), callableSignature)
             output.add(Pair(symbol, flag))
           }
         }
diff --git a/tools/edit_monitor/Android.bp b/tools/edit_monitor/Android.bp
new file mode 100644
index 0000000000..b939633817
--- /dev/null
+++ b/tools/edit_monitor/Android.bp
@@ -0,0 +1,44 @@
+// Copyright 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+// Set of error prone rules to ensure code quality
+// PackageLocation check requires the androidCompatible=false otherwise it does not do anything.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_adte",
+}
+
+python_library_host {
+    name: "edit_monitor_lib",
+    pkg_path: "edit_monitor",
+    srcs: [
+        "daemon_manager.py",
+    ],
+}
+
+python_test_host {
+    name: "daemon_manager_test",
+    main: "daemon_manager_test.py",
+    pkg_path: "edit_monitor",
+    srcs: [
+        "daemon_manager_test.py",
+    ],
+    libs: [
+        "edit_monitor_lib",
+    ],
+    test_options: {
+        unit_test: true,
+    },
+}
diff --git a/tools/edit_monitor/OWNERS b/tools/edit_monitor/OWNERS
new file mode 100644
index 0000000000..8f0f3646dd
--- /dev/null
+++ b/tools/edit_monitor/OWNERS
@@ -0,0 +1 @@
+include platform/tools/asuite:/OWNERS_ADTE_TEAM
\ No newline at end of file
diff --git a/tools/edit_monitor/daemon_manager.py b/tools/edit_monitor/daemon_manager.py
new file mode 100644
index 0000000000..8ec25886dc
--- /dev/null
+++ b/tools/edit_monitor/daemon_manager.py
@@ -0,0 +1,182 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+
+import hashlib
+import logging
+import multiprocessing
+import os
+import pathlib
+import signal
+import subprocess
+import tempfile
+import time
+
+
+DEFAULT_PROCESS_TERMINATION_TIMEOUT_SECONDS = 1
+
+
+def default_daemon_target():
+  """Place holder for the default daemon target."""
+  print("default daemon target")
+
+
+class DaemonManager:
+  """Class to manage and monitor the daemon run as a subprocess."""
+
+  def __init__(
+      self,
+      binary_path: str,
+      daemon_target: callable = default_daemon_target,
+      daemon_args: tuple = (),
+  ):
+    self.binary_path = binary_path
+    self.daemon_target = daemon_target
+    self.daemon_args = daemon_args
+
+    self.pid = os.getpid()
+    self.daemon_process = None
+
+    pid_file_dir = pathlib.Path(tempfile.gettempdir()).joinpath("edit_monitor")
+    pid_file_dir.mkdir(parents=True, exist_ok=True)
+    self.pid_file_path = self._get_pid_file_path(pid_file_dir)
+
+  def start(self):
+    """Writes the pidfile and starts the daemon proces."""
+    try:
+      self._stop_any_existing_instance()
+      self._write_pid_to_pidfile()
+      self._start_daemon_process()
+    except Exception as e:
+      logging.exception("Failed to start daemon manager with error %s", e)
+
+  def stop(self):
+    """Stops the daemon process and removes the pidfile."""
+
+    logging.debug("in daemon manager cleanup.")
+    try:
+      if self.daemon_process and self.daemon_process.is_alive():
+        self._terminate_process(self.daemon_process.pid)
+      self._remove_pidfile()
+    except Exception as e:
+      logging.exception("Failed to stop daemon manager with error %s", e)
+
+  def _stop_any_existing_instance(self):
+    if not self.pid_file_path.exists():
+      logging.debug("No existing instances.")
+      return
+
+    ex_pid = self._read_pid_from_pidfile()
+
+    if ex_pid:
+      logging.info("Found another instance with pid %d.", ex_pid)
+      self._terminate_process(ex_pid)
+      self._remove_pidfile()
+
+  def _read_pid_from_pidfile(self):
+    with open(self.pid_file_path, "r") as f:
+      return int(f.read().strip())
+
+  def _write_pid_to_pidfile(self):
+    """Creates a pidfile and writes the current pid to the file.
+
+    Raise FileExistsError if the pidfile already exists.
+    """
+    try:
+      # Use the 'x' mode to open the file for exclusive creation
+      with open(self.pid_file_path, "x") as f:
+        f.write(f"{self.pid}")
+    except FileExistsError as e:
+      # This could be caused due to race condition that a user is trying
+      # to start two edit monitors at the same time. Or because there is
+      # already an existing edit monitor running and we can not kill it
+      # for some reason.
+      logging.exception("pidfile %s already exists.", self.pid_file_path)
+      raise e
+
+  def _start_daemon_process(self):
+    """Starts a subprocess to run the daemon."""
+    p = multiprocessing.Process(
+        target=self.daemon_target, args=self.daemon_args
+    )
+    p.start()
+
+    logging.info("Start subprocess with PID %d", p.pid)
+    self.daemon_process = p
+
+  def _terminate_process(
+      self, pid: int, timeout: int = DEFAULT_PROCESS_TERMINATION_TIMEOUT_SECONDS
+  ):
+    """Terminates a process with given pid.
+
+    It first sends a SIGTERM to the process to allow it for proper
+    termination with a timeout. If the process is not terminated within
+    the timeout, kills it forcefully.
+    """
+    try:
+      os.kill(pid, signal.SIGTERM)
+      if not self._wait_for_process_terminate(pid, timeout):
+        logging.warning(
+            "Process %d not terminated within timeout, try force kill", pid
+        )
+        os.kill(pid, signal.SIGKILL)
+    except ProcessLookupError:
+      logging.info("Process with PID %d not found (already terminated)", pid)
+
+  def _wait_for_process_terminate(self, pid: int, timeout: int) -> bool:
+    start_time = time.time()
+
+    while time.time() < start_time + timeout:
+      if not self._is_process_alive(pid):
+        return True
+      time.sleep(1)
+
+    logging.error("Process %d not terminated within %d seconds.", pid, timeout)
+    return False
+
+  def _is_process_alive(self, pid: int) -> bool:
+    try:
+      output = subprocess.check_output(
+          ["ps", "-p", str(pid), "-o", "state="], text=True
+      ).strip()
+      state = output.split()[0]
+      return state != "Z"  # Check if the state is not 'Z' (zombie)
+    except subprocess.CalledProcessError:
+      # Process not found (already dead).
+      return False
+    except (FileNotFoundError, OSError, ValueError) as e:
+      logging.warning(
+          "Unable to check the status for process %d with error: %s.", pid, e
+      )
+      return True
+
+  def _remove_pidfile(self):
+    try:
+      os.remove(self.pid_file_path)
+    except FileNotFoundError:
+      logging.info("pid file %s already removed.", self.pid_file_path)
+
+  def _get_pid_file_path(self, pid_file_dir: pathlib.Path) -> pathlib.Path:
+    """Generates the path to store the pidfile.
+
+    The file path should have the format of "/tmp/edit_monitor/xxxx.lock"
+    where xxxx is a hashed value based on the binary path that starts the
+    process.
+    """
+    hash_object = hashlib.sha256()
+    hash_object.update(self.binary_path.encode("utf-8"))
+    pid_file_path = pid_file_dir.joinpath(hash_object.hexdigest() + ".lock")
+    logging.info("pid_file_path: %s", pid_file_path)
+
+    return pid_file_path
diff --git a/tools/edit_monitor/daemon_manager_test.py b/tools/edit_monitor/daemon_manager_test.py
new file mode 100644
index 0000000000..214b0388dc
--- /dev/null
+++ b/tools/edit_monitor/daemon_manager_test.py
@@ -0,0 +1,253 @@
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Unittests for DaemonManager."""
+
+import logging
+import multiprocessing
+import os
+import pathlib
+import signal
+import subprocess
+import sys
+import tempfile
+import time
+import unittest
+from unittest import mock
+from edit_monitor import daemon_manager
+
+TEST_BINARY_FILE = '/path/to/test_binary'
+TEST_PID_FILE_PATH = (
+    '587239c2d1050afdf54512e2d799f3b929f86b43575eb3c7b4bab105dd9bd25e.lock'
+)
+
+
+def simple_daemon(output_file):
+  with open(output_file, 'w') as f:
+    f.write('running daemon target')
+
+
+def long_running_daemon():
+  while True:
+    time.sleep(1)
+
+
+class DaemonManagerTest(unittest.TestCase):
+
+  @classmethod
+  def setUpClass(cls):
+    super().setUpClass()
+    # Configure to print logging to stdout.
+    logging.basicConfig(filename=None, level=logging.DEBUG)
+    console = logging.StreamHandler(sys.stdout)
+    logging.getLogger('').addHandler(console)
+
+  def setUp(self):
+    super().setUp()
+    self.original_tempdir = tempfile.tempdir
+    self.working_dir = tempfile.TemporaryDirectory()
+    # Sets the tempdir under the working dir so any temp files created during
+    # tests will be cleaned.
+    tempfile.tempdir = self.working_dir.name
+
+  def tearDown(self):
+    # Cleans up any child processes left by the tests.
+    self._cleanup_child_processes()
+    self.working_dir.cleanup()
+    # Restores tempdir.
+    tempfile.tempdir = self.original_tempdir
+    super().tearDown()
+
+  def test_start_success_with_no_existing_instance(self):
+    self.assert_run_simple_daemon_success()
+
+  def test_start_success_with_existing_instance_running(self):
+    # Create a long running subprocess
+    p = multiprocessing.Process(target=long_running_daemon)
+    p.start()
+
+    # Create a pidfile with the subprocess pid
+    pid_file_path_dir = pathlib.Path(self.working_dir.name).joinpath(
+        'edit_monitor'
+    )
+    pid_file_path_dir.mkdir(parents=True, exist_ok=True)
+    with open(pid_file_path_dir.joinpath(TEST_PID_FILE_PATH), 'w') as f:
+      f.write(str(p.pid))
+
+    self.assert_run_simple_daemon_success()
+    p.terminate()
+
+  def test_start_success_with_existing_instance_already_dead(self):
+    # Create a pidfile with pid that does not exist.
+    pid_file_path_dir = pathlib.Path(self.working_dir.name).joinpath(
+        'edit_monitor'
+    )
+    pid_file_path_dir.mkdir(parents=True, exist_ok=True)
+    with open(pid_file_path_dir.joinpath(TEST_PID_FILE_PATH), 'w') as f:
+      f.write('123456')
+
+    self.assert_run_simple_daemon_success()
+
+  def test_start_success_with_existing_instance_from_different_binary(self):
+    # First start an instance based on "some_binary_path"
+    existing_dm = daemon_manager.DaemonManager(
+        "some_binary_path",
+        daemon_target=long_running_daemon,
+    )
+    existing_dm.start()
+
+    self.assert_run_simple_daemon_success()
+    existing_dm.stop()
+
+  @mock.patch('os.kill')
+  def test_start_failed_to_kill_existing_instance(self, mock_kill):
+    mock_kill.side_effect = OSError('Unknown OSError')
+    pid_file_path_dir = pathlib.Path(self.working_dir.name).joinpath(
+        'edit_monitor'
+    )
+    pid_file_path_dir.mkdir(parents=True, exist_ok=True)
+    with open(pid_file_path_dir.joinpath(TEST_PID_FILE_PATH), 'w') as f:
+      f.write('123456')
+
+    dm = daemon_manager.DaemonManager(TEST_BINARY_FILE)
+    dm.start()
+
+    # Verify no daemon process is started.
+    self.assertIsNone(dm.daemon_process)
+
+  def test_start_failed_to_write_pidfile(self):
+    pid_file_path_dir = pathlib.Path(self.working_dir.name).joinpath(
+        'edit_monitor'
+    )
+    pid_file_path_dir.mkdir(parents=True, exist_ok=True)
+    # Makes the directory read-only so write pidfile will fail.
+    os.chmod(pid_file_path_dir, 0o555)
+
+    dm = daemon_manager.DaemonManager(TEST_BINARY_FILE)
+    dm.start()
+
+    # Verifies no daemon process is started.
+    self.assertIsNone(dm.daemon_process)
+
+  def test_start_failed_to_start_daemon_process(self):
+    dm = daemon_manager.DaemonManager(
+        TEST_BINARY_FILE, daemon_target='wrong_target', daemon_args=(1)
+    )
+    dm.start()
+
+    # Verifies no daemon process is started.
+    self.assertIsNone(dm.daemon_process)
+
+  def test_stop_success(self):
+    dm = daemon_manager.DaemonManager(
+        TEST_BINARY_FILE, daemon_target=long_running_daemon
+    )
+    dm.start()
+    dm.stop()
+
+    self.assert_no_subprocess_running()
+    self.assertFalse(dm.pid_file_path.exists())
+
+  @mock.patch('os.kill')
+  def test_stop_failed_to_kill_daemon_process(self, mock_kill):
+    mock_kill.side_effect = OSError('Unknown OSError')
+    dm = daemon_manager.DaemonManager(
+        TEST_BINARY_FILE, daemon_target=long_running_daemon
+    )
+    dm.start()
+    dm.stop()
+
+    self.assertTrue(dm.daemon_process.is_alive())
+    self.assertTrue(dm.pid_file_path.exists())
+
+  @mock.patch('os.remove')
+  def test_stop_failed_to_remove_pidfile(self, mock_remove):
+    mock_remove.side_effect = OSError('Unknown OSError')
+
+    dm = daemon_manager.DaemonManager(
+        TEST_BINARY_FILE, daemon_target=long_running_daemon
+    )
+    dm.start()
+    dm.stop()
+
+    self.assert_no_subprocess_running()
+    self.assertTrue(dm.pid_file_path.exists())
+
+  def assert_run_simple_daemon_success(self):
+    damone_output_file = tempfile.NamedTemporaryFile(
+        dir=self.working_dir.name, delete=False
+    )
+    dm = daemon_manager.DaemonManager(
+        TEST_BINARY_FILE,
+        daemon_target=simple_daemon,
+        daemon_args=(damone_output_file.name,),
+    )
+    dm.start()
+    dm.daemon_process.join()
+
+    # Verifies the expected pid file is created.
+    expected_pid_file_path = pathlib.Path(self.working_dir.name).joinpath(
+        'edit_monitor', TEST_PID_FILE_PATH
+    )
+    self.assertTrue(expected_pid_file_path.exists())
+
+    # Verify the daemon process is executed successfully.
+    with open(damone_output_file.name, 'r') as f:
+      contents = f.read()
+      self.assertEqual(contents, 'running daemon target')
+
+  def assert_no_subprocess_running(self):
+    child_pids = self._get_child_processes(os.getpid())
+    for child_pid in child_pids:
+      self.assertFalse(
+          self._is_process_alive(child_pid), f'process {child_pid} still alive'
+      )
+
+  def _get_child_processes(self, parent_pid):
+    try:
+      output = subprocess.check_output(
+          ['ps', '-o', 'pid,ppid', '--no-headers'], text=True
+      )
+
+      child_processes = []
+      for line in output.splitlines():
+        pid, ppid = line.split()
+        if int(ppid) == parent_pid:
+          child_processes.append(int(pid))
+      return child_processes
+    except subprocess.CalledProcessError as e:
+      self.fail(f'failed to get child process, error: {e}')
+
+  def _is_process_alive(self, pid):
+    try:
+      output = subprocess.check_output(
+          ['ps', '-p', str(pid), '-o', 'state='], text=True
+      ).strip()
+      state = output.split()[0]
+      return state != 'Z'  # Check if the state is not 'Z' (zombie)
+    except subprocess.CalledProcessError:
+      return False
+
+  def _cleanup_child_processes(self):
+    child_pids = self._get_child_processes(os.getpid())
+    for child_pid in child_pids:
+      try:
+        os.kill(child_pid, signal.SIGKILL)
+      except ProcessLookupError:
+        # process already terminated
+        pass
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/tools/filelistdiff/Android.bp b/tools/filelistdiff/Android.bp
new file mode 100644
index 0000000000..ab766d6d93
--- /dev/null
+++ b/tools/filelistdiff/Android.bp
@@ -0,0 +1,27 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+python_binary_host {
+    name: "file_list_diff",
+    srcs: ["file_list_diff.py"],
+}
+
+prebuilt_etc_host {
+    name: "system_image_diff_allowlist",
+    src: "allowlist",
+}
\ No newline at end of file
diff --git a/tools/filelistdiff/OWNERS b/tools/filelistdiff/OWNERS
new file mode 100644
index 0000000000..690fb178fc
--- /dev/null
+++ b/tools/filelistdiff/OWNERS
@@ -0,0 +1 @@
+per-file allowlist = justinyun@google.com, jeongik@google.com, kiyoungkim@google.com, inseob@google.com
diff --git a/tools/filelistdiff/allowlist b/tools/filelistdiff/allowlist
new file mode 100644
index 0000000000..120045e3b2
--- /dev/null
+++ b/tools/filelistdiff/allowlist
@@ -0,0 +1,51 @@
+# Known diffs only in the KATI system image
+etc/NOTICE.xml.gz
+framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.odex
+framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.odex.fsv_meta
+framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.vdex
+framework/oat/x86_64/apex@com.android.compos@javalib@service-compos.jar@classes.vdex.fsv_meta
+lib/aaudio-aidl-cpp.so
+lib/android.hardware.biometrics.fingerprint@2.1.so
+lib/android.hardware.radio.config@1.0.so
+lib/android.hardware.radio.deprecated@1.0.so
+lib/android.hardware.radio@1.0.so
+lib/android.hardware.radio@1.1.so
+lib/android.hardware.radio@1.2.so
+lib/android.hardware.radio@1.3.so
+lib/android.hardware.radio@1.4.so
+lib/android.hardware.secure_element@1.0.so
+lib/com.android.media.aaudio-aconfig-cc.so
+lib/heapprofd_client.so
+lib/heapprofd_client_api.so
+lib/libaaudio.so
+lib/libaaudio_internal.so
+lib/libalarm_jni.so
+lib/libamidi.so
+lib/libcups.so
+lib/libjni_deviceAsWebcam.so
+lib/libprintspooler_jni.so
+lib/libvendorsupport.so
+lib/libwfds.so
+lib/libyuv.so
+
+# b/351258461
+adb_keys
+init.environ.rc
+
+# Known diffs only in the Soong system image
+lib/libhidcommand_jni.so
+lib/libuinputcommand_jni.so
+
+# Known diffs in internal source
+bin/uprobestats
+etc/aconfig/flag.map
+etc/aconfig/flag.val
+etc/aconfig/package.map
+etc/bpf/uprobestats/BitmapAllocation.o
+etc/bpf/uprobestats/GenericInstrumentation.o
+etc/bpf/uprobestats/ProcessManagement.o
+etc/init/UprobeStats.rc
+lib/libuprobestats_client.so
+lib64/libuprobestats_client.so
+priv-app/DeviceDiagnostics/DeviceDiagnostics.apk
+
diff --git a/tools/filelistdiff/file_list_diff.py b/tools/filelistdiff/file_list_diff.py
new file mode 100644
index 0000000000..cdc5b2ee41
--- /dev/null
+++ b/tools/filelistdiff/file_list_diff.py
@@ -0,0 +1,66 @@
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
+import argparse
+import sys
+
+COLOR_WARNING = '\033[93m'
+COLOR_ERROR = '\033[91m'
+COLOR_NORMAL = '\033[0m'
+
+def find_unique_items(kati_installed_files, soong_installed_files, allowlist, system_module_name):
+    with open(kati_installed_files, 'r') as kati_list_file, \
+            open(soong_installed_files, 'r') as soong_list_file, \
+            open(allowlist, 'r') as allowlist_file:
+        kati_files = set(kati_list_file.read().split())
+        soong_files = set(soong_list_file.read().split())
+        allowed_files = set(filter(lambda x: len(x), map(lambda x: x.lstrip().split('#',1)[0].rstrip() , allowlist_file.read().split('\n'))))
+
+    def is_unknown_diff(filepath):
+        return not filepath in allowed_files
+
+    unique_in_kati = set(filter(is_unknown_diff, kati_files - soong_files))
+    unique_in_soong = set(filter(is_unknown_diff, soong_files - kati_files))
+
+    if unique_in_kati:
+        print(f'{COLOR_ERROR}Please add following modules into system image module {system_module_name}.{COLOR_NORMAL}')
+        print(f'{COLOR_WARNING}KATI only module(s):{COLOR_NORMAL}')
+        for item in sorted(unique_in_kati):
+            print(item)
+
+    if unique_in_soong:
+        if unique_in_kati:
+            print('')
+
+        print(f'{COLOR_ERROR}Please add following modules into build/make/target/product/base_system.mk.{COLOR_NORMAL}')
+        print(f'{COLOR_WARNING}Soong only module(s):{COLOR_NORMAL}')
+        for item in sorted(unique_in_soong):
+            print(item)
+
+    if unique_in_kati or unique_in_soong:
+        print('')
+        print(f'{COLOR_ERROR}FAILED: System image from KATI and SOONG differs from installed file list.{COLOR_NORMAL}')
+        sys.exit(1)
+
+
+if __name__ == '__main__':
+    parser = argparse.ArgumentParser()
+
+    parser.add_argument('kati_installed_file_list')
+    parser.add_argument('soong_installed_file_list')
+    parser.add_argument('allowlist')
+    parser.add_argument('system_module_name')
+    args = parser.parse_args()
+
+    find_unique_items(args.kati_installed_file_list, args.soong_installed_file_list, args.allowlist, args.system_module_name)
\ No newline at end of file
diff --git a/tools/finalization/build-step-0-and-m.sh b/tools/finalization/build-step-0-and-m.sh
new file mode 100755
index 0000000000..484380045e
--- /dev/null
+++ b/tools/finalization/build-step-0-and-m.sh
@@ -0,0 +1,20 @@
+
+#!/bin/bash
+# Copyright 2024 Google Inc. All rights reserved.
+set -ex
+function help() {
+    echo "Finalize VINTF and build a target for test."
+    echo "usage: $(basename "$0") target [goals...]"
+}
+function finalize_main_step0_and_m() {
+    if [ $# == 0 ] ; then
+        help
+        exit 1
+    fi;
+    local top="$(dirname "$0")"/../../../..
+    source $top/build/make/tools/finalization/build-step-0.sh
+    local m="$top/build/soong/soong_ui.bash --make-mode TARGET_PRODUCT=$1 TARGET_RELEASE=fina_0 TARGET_BUILD_VARIANT=userdebug"
+    # This command tests the release state for AIDL.
+    AIDL_FROZEN_REL=true $m ${@:2}
+}
+finalize_main_step0_and_m $@
diff --git a/tools/finalization/build-step-0.sh b/tools/finalization/build-step-0.sh
index f81b720b2d..8826b35c0f 100755
--- a/tools/finalization/build-step-0.sh
+++ b/tools/finalization/build-step-0.sh
@@ -7,11 +7,26 @@ function finalize_main_step0() {
     local top="$(dirname "$0")"/../../../..
     source $top/build/make/tools/finalization/environment.sh
 
+    local need_vintf_finalize=false
     if [ "$FINAL_STATE" = "unfinalized" ] ; then
-        # VINTF finalization
+        need_vintf_finalize=true
+    else
+        # build-step-0.sh tests the vintf finalization step (step-0) when the
+        # FINAL_BOARD_API_LEVEL is the same as the RELEASE_BOARD_API_LEVEL; and
+        # RELEASE_BOARD_API_LEVEL_FROZEN is not true from the fina_0 configuration.
+        # The FINAL_BOARD_API_LEVEL must be the next vendor API level to be finalized.
+        local board_api_level_vars=$(TARGET_RELEASE=fina_0 $top/build/soong/soong_ui.bash --dumpvars-mode -vars "RELEASE_BOARD_API_LEVEL_FROZEN RELEASE_BOARD_API_LEVEL")
+        local target_board_api_level_vars="RELEASE_BOARD_API_LEVEL_FROZEN=''
+RELEASE_BOARD_API_LEVEL='$FINAL_BOARD_API_LEVEL'"
+        if [ "$board_api_level_vars" = "$target_board_api_level_vars" ] ; then
+            echo The target is a finalization candidate.
+            need_vintf_finalize=true
+        fi;
+    fi;
+
+    if [ "$need_vintf_finalize" = true ] ; then        # VINTF finalization
         source $top/build/make/tools/finalization/finalize-vintf-resources.sh
     fi;
 }
 
 finalize_main_step0
-
diff --git a/tools/finalization/environment.sh b/tools/finalization/environment.sh
index f68a68b650..cf3e61bd99 100755
--- a/tools/finalization/environment.sh
+++ b/tools/finalization/environment.sh
@@ -29,4 +29,8 @@ export BUILD_FROM_SOURCE_STUB=true
 # FINAL versions for VINTF
 # TODO(b/323985297): The version must match with that from the release configuration.
 # Instead of hardcoding the version here, read it from a release configuration.
-export FINAL_BOARD_API_LEVEL='202404'
+export FINAL_BOARD_API_LEVEL='202504'
+export FINAL_CORRESPONDING_VERSION_LETTER='W'
+export FINAL_CORRESPONDING_PLATFORM_VERSION='16'
+export FINAL_NEXT_BOARD_API_LEVEL='202604'
+export FINAL_NEXT_CORRESPONDING_VERSION_LETTER='X'
diff --git a/tools/finalization/finalize-vintf-resources.sh b/tools/finalization/finalize-vintf-resources.sh
index d532b25346..6f1a6f646e 100755
--- a/tools/finalization/finalize-vintf-resources.sh
+++ b/tools/finalization/finalize-vintf-resources.sh
@@ -33,18 +33,18 @@ function finalize_vintf_resources() {
 function create_new_compat_matrix_and_kernel_configs() {
     # The compatibility matrix versions are bumped during vFRC
     # These will change every time we have a new vFRC
-    local CURRENT_COMPATIBILITY_MATRIX_LEVEL='202404'
-    local NEXT_COMPATIBILITY_MATRIX_LEVEL='202504'
+    local CURRENT_COMPATIBILITY_MATRIX_LEVEL="$FINAL_BOARD_API_LEVEL"
+    local NEXT_COMPATIBILITY_MATRIX_LEVEL="$FINAL_NEXT_BOARD_API_LEVEL"
     # The kernel configs need the letter of the Android release
-    local CURRENT_RELEASE_LETTER='v'
-    local NEXT_RELEASE_LETTER='w'
+    local CURRENT_RELEASE_LETTER="$FINAL_CORRESPONDING_VERSION_LETTER"
+    local NEXT_RELEASE_LETTER="$FINAL_NEXT_CORRESPONDING_VERSION_LETTER"
 
 
     # build the targets required before touching the Android.bp/Android.mk files
     local build_cmd="$top/build/soong/soong_ui.bash --make-mode"
     $build_cmd bpmodify
 
-    "$top/prebuilts/build-tools/path/linux-x86/python3" "$top/hardware/interfaces/compatibility_matrices/bump.py" "$CURRENT_COMPATIBILITY_MATRIX_LEVEL" "$NEXT_COMPATIBILITY_MATRIX_LEVEL" "$CURRENT_RELEASE_LETTER" "$NEXT_RELEASE_LETTER"
+    "$top/prebuilts/build-tools/path/linux-x86/python3" "$top/hardware/interfaces/compatibility_matrices/bump.py" "$CURRENT_COMPATIBILITY_MATRIX_LEVEL" "$NEXT_COMPATIBILITY_MATRIX_LEVEL" "$CURRENT_RELEASE_LETTER" "$NEXT_RELEASE_LETTER" "$FINAL_CORRESPONDING_PLATFORM_VERSION"
 
     # Freeze the current framework manifest file. This relies on the
     # aosp_cf_x86_64-trunk_staging build target to get the right manifest
diff --git a/tools/ide_query/OWNERS b/tools/ide_query/OWNERS
new file mode 100644
index 0000000000..914a9a2ee0
--- /dev/null
+++ b/tools/ide_query/OWNERS
@@ -0,0 +1,4 @@
+ialiyev@google.com
+ivankirichenko@google.com
+kadircet@google.com
+michaelmerg@google.com
diff --git a/tools/ide_query/cc_analyzer/Android.bp b/tools/ide_query/cc_analyzer/Android.bp
index 3cbbb0587f..e85d4459c3 100644
--- a/tools/ide_query/cc_analyzer/Android.bp
+++ b/tools/ide_query/cc_analyzer/Android.bp
@@ -58,7 +58,7 @@ cc_library_host_static {
     shared_libs: ["libclang-cpp_host"],
     static_libs: [
         "include_scanner",
-        "ide_query_proto",
+        "cc_analyzer_proto",
     ],
     defaults: ["ide_query_cc_analyzer_defaults"],
 }
@@ -72,7 +72,7 @@ cc_binary_host {
         "libprotobuf-cpp-full",
     ],
     static_libs: [
-        "ide_query_proto",
+        "cc_analyzer_proto",
         "builtin_headers",
         "include_scanner",
         "analyzer",
diff --git a/tools/ide_query/cc_analyzer/analyzer.cc b/tools/ide_query/cc_analyzer/analyzer.cc
index bb7ca0b5bc..4ccec54c73 100644
--- a/tools/ide_query/cc_analyzer/analyzer.cc
+++ b/tools/ide_query/cc_analyzer/analyzer.cc
@@ -20,9 +20,9 @@
 #include <utility>
 #include <vector>
 
+#include "cc_analyzer.pb.h"
 #include "clang/Tooling/CompilationDatabase.h"
 #include "clang/Tooling/JSONCompilationDatabase.h"
-#include "ide_query.pb.h"
 #include "include_scanner.h"
 #include "llvm/ADT/SmallString.h"
 #include "llvm/ADT/StringRef.h"
@@ -48,11 +48,11 @@ llvm::Expected<std::unique_ptr<clang::tooling::CompilationDatabase>> LoadCompDB(
 }
 }  // namespace
 
-::ide_query::DepsResponse GetDeps(::ide_query::RepoState state) {
-  ::ide_query::DepsResponse results;
+::cc_analyzer::DepsResponse GetDeps(::cc_analyzer::RepoState state) {
+  ::cc_analyzer::DepsResponse results;
   auto db = LoadCompDB(state.comp_db_path());
   if (!db) {
-    results.mutable_status()->set_code(::ide_query::Status::FAILURE);
+    results.mutable_status()->set_code(::cc_analyzer::Status::FAILURE);
     results.mutable_status()->set_message(llvm::toString(db.takeError()));
     return results;
   }
@@ -63,7 +63,7 @@ llvm::Expected<std::unique_ptr<clang::tooling::CompilationDatabase>> LoadCompDB(
     llvm::sys::path::append(abs_file, active_file);
     auto cmds = db->get()->getCompileCommands(active_file);
     if (cmds.empty()) {
-      result.mutable_status()->set_code(::ide_query::Status::FAILURE);
+      result.mutable_status()->set_code(::cc_analyzer::Status::FAILURE);
       result.mutable_status()->set_message(
           llvm::Twine("Can't find compile flags for file: ", abs_file).str());
       continue;
@@ -80,11 +80,11 @@ llvm::Expected<std::unique_ptr<clang::tooling::CompilationDatabase>> LoadCompDB(
   return results;
 }
 
-::ide_query::IdeAnalysis GetBuildInputs(::ide_query::RepoState state) {
+::cc_analyzer::IdeAnalysis GetBuildInputs(::cc_analyzer::RepoState state) {
   auto db = LoadCompDB(state.comp_db_path());
-  ::ide_query::IdeAnalysis results;
+  ::cc_analyzer::IdeAnalysis results;
   if (!db) {
-    results.mutable_status()->set_code(::ide_query::Status::FAILURE);
+    results.mutable_status()->set_code(::cc_analyzer::Status::FAILURE);
     results.mutable_status()->set_message(llvm::toString(db.takeError()));
     return results;
   }
@@ -97,7 +97,6 @@ llvm::Expected<std::unique_ptr<clang::tooling::CompilationDatabase>> LoadCompDB(
     genfile_root_abs.push_back('/');
   }
 
-  results.set_build_artifact_root(state.out_dir());
   for (llvm::StringRef active_file : state.active_file_path()) {
     auto& result = *results.add_sources();
     result.set_path(active_file.str());
@@ -106,7 +105,7 @@ llvm::Expected<std::unique_ptr<clang::tooling::CompilationDatabase>> LoadCompDB(
     llvm::sys::path::append(abs_file, active_file);
     auto cmds = db->get()->getCompileCommands(abs_file);
     if (cmds.empty()) {
-      result.mutable_status()->set_code(::ide_query::Status::FAILURE);
+      result.mutable_status()->set_code(::cc_analyzer::Status::FAILURE);
       result.mutable_status()->set_message(
           llvm::Twine("Can't find compile flags for file: ", abs_file).str());
       continue;
@@ -114,7 +113,7 @@ llvm::Expected<std::unique_ptr<clang::tooling::CompilationDatabase>> LoadCompDB(
     const auto& cmd = cmds.front();
     llvm::StringRef working_dir = cmd.Directory;
     if (!working_dir.consume_front(repo_dir)) {
-      result.mutable_status()->set_code(::ide_query::Status::FAILURE);
+      result.mutable_status()->set_code(::cc_analyzer::Status::FAILURE);
       result.mutable_status()->set_message("Command working dir " +
                                            working_dir.str() +
                                            " outside repository " + repo_dir);
@@ -127,7 +126,7 @@ llvm::Expected<std::unique_ptr<clang::tooling::CompilationDatabase>> LoadCompDB(
     auto includes =
         ScanIncludes(cmds.front(), llvm::vfs::createPhysicalFileSystem());
     if (!includes) {
-      result.mutable_status()->set_code(::ide_query::Status::FAILURE);
+      result.mutable_status()->set_code(::cc_analyzer::Status::FAILURE);
       result.mutable_status()->set_message(
           llvm::toString(includes.takeError()));
       continue;
diff --git a/tools/ide_query/cc_analyzer/analyzer.h b/tools/ide_query/cc_analyzer/analyzer.h
index 3133795217..fd1908250b 100644
--- a/tools/ide_query/cc_analyzer/analyzer.h
+++ b/tools/ide_query/cc_analyzer/analyzer.h
@@ -17,17 +17,17 @@
 #ifndef _TOOLS_IDE_QUERY_CC_ANALYZER_ANALYZER_H_
 #define _TOOLS_IDE_QUERY_CC_ANALYZER_ANALYZER_H_
 
-#include "ide_query.pb.h"
+#include "cc_analyzer.pb.h"
 
 namespace tools::ide_query::cc_analyzer {
 
 // Scans the build graph and returns target names from the build graph to
 // generate all the dependencies for the active files.
-::ide_query::DepsResponse GetDeps(::ide_query::RepoState state);
+::cc_analyzer::DepsResponse GetDeps(::cc_analyzer::RepoState state);
 
 // Scans the sources and returns all the source files required for analyzing the
 // active files.
-::ide_query::IdeAnalysis GetBuildInputs(::ide_query::RepoState state);
+::cc_analyzer::IdeAnalysis GetBuildInputs(::cc_analyzer::RepoState state);
 
 }  // namespace tools::ide_query::cc_analyzer
 
diff --git a/tools/ide_query/cc_analyzer/main.cc b/tools/ide_query/cc_analyzer/main.cc
index 8e00c6396a..d86fc8c950 100644
--- a/tools/ide_query/cc_analyzer/main.cc
+++ b/tools/ide_query/cc_analyzer/main.cc
@@ -28,7 +28,7 @@
 
 #include "analyzer.h"
 #include "google/protobuf/message.h"
-#include "ide_query.pb.h"
+#include "cc_analyzer.pb.h"
 #include "llvm/ADT/StringRef.h"
 #include "llvm/Support/CommandLine.h"
 #include "llvm/Support/TargetSelect.h"
@@ -48,9 +48,9 @@ llvm::cl::opt<OpMode> mode{
     llvm::cl::desc("Print the list of headers to insert and remove"),
 };
 
-ide_query::IdeAnalysis ReturnError(llvm::StringRef message) {
-  ide_query::IdeAnalysis result;
-  result.mutable_status()->set_code(ide_query::Status::FAILURE);
+cc_analyzer::IdeAnalysis ReturnError(llvm::StringRef message) {
+  cc_analyzer::IdeAnalysis result;
+  result.mutable_status()->set_code(cc_analyzer::Status::FAILURE);
   result.mutable_status()->set_message(message.str());
   return result;
 }
@@ -61,7 +61,7 @@ int main(int argc, char* argv[]) {
   llvm::InitializeAllTargetInfos();
   llvm::cl::ParseCommandLineOptions(argc, argv);
 
-  ide_query::RepoState state;
+  cc_analyzer::RepoState state;
   if (!state.ParseFromFileDescriptor(STDIN_FILENO)) {
     llvm::errs() << "Failed to parse input!\n";
     return 1;
@@ -70,12 +70,12 @@ int main(int argc, char* argv[]) {
   std::unique_ptr<google::protobuf::Message> result;
   switch (mode) {
     case OpMode::DEPS: {
-      result = std::make_unique<ide_query::DepsResponse>(
+      result = std::make_unique<cc_analyzer::DepsResponse>(
           tools::ide_query::cc_analyzer::GetDeps(std::move(state)));
       break;
     }
     case OpMode::INPUTS: {
-      result = std::make_unique<ide_query::IdeAnalysis>(
+      result = std::make_unique<cc_analyzer::IdeAnalysis>(
           tools::ide_query::cc_analyzer::GetBuildInputs(std::move(state)));
       break;
     }
diff --git a/tools/ide_query/ide_query_proto/Android.bp b/tools/ide_query/cc_analyzer_proto/Android.bp
similarity index 93%
rename from tools/ide_query/ide_query_proto/Android.bp
rename to tools/ide_query/cc_analyzer_proto/Android.bp
index 70f15cd4a0..0ed07b42f1 100644
--- a/tools/ide_query/ide_query_proto/Android.bp
+++ b/tools/ide_query/cc_analyzer_proto/Android.bp
@@ -19,9 +19,9 @@ package {
 }
 
 cc_library_host_static {
-    name: "ide_query_proto",
+    name: "cc_analyzer_proto",
     srcs: [
-        "ide_query.proto",
+        "cc_analyzer.proto",
     ],
     proto: {
         export_proto_headers: true,
diff --git a/tools/ide_query/cc_analyzer_proto/cc_analyzer.pb.go b/tools/ide_query/cc_analyzer_proto/cc_analyzer.pb.go
new file mode 100644
index 0000000000..debe5c0e87
--- /dev/null
+++ b/tools/ide_query/cc_analyzer_proto/cc_analyzer.pb.go
@@ -0,0 +1,789 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+// Code generated by protoc-gen-go. DO NOT EDIT.
+// versions:
+// 	protoc-gen-go v1.30.0
+// 	protoc        v3.21.12
+// source: cc_analyzer.proto
+
+package cc_analyzer_proto
+
+import (
+	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
+	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
+	reflect "reflect"
+	sync "sync"
+)
+
+const (
+	// Verify that this generated code is sufficiently up-to-date.
+	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
+	// Verify that runtime/protoimpl is sufficiently up-to-date.
+	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
+)
+
+type Status_Code int32
+
+const (
+	Status_OK      Status_Code = 0
+	Status_FAILURE Status_Code = 1
+)
+
+// Enum value maps for Status_Code.
+var (
+	Status_Code_name = map[int32]string{
+		0: "OK",
+		1: "FAILURE",
+	}
+	Status_Code_value = map[string]int32{
+		"OK":      0,
+		"FAILURE": 1,
+	}
+)
+
+func (x Status_Code) Enum() *Status_Code {
+	p := new(Status_Code)
+	*p = x
+	return p
+}
+
+func (x Status_Code) String() string {
+	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
+}
+
+func (Status_Code) Descriptor() protoreflect.EnumDescriptor {
+	return file_cc_analyzer_proto_enumTypes[0].Descriptor()
+}
+
+func (Status_Code) Type() protoreflect.EnumType {
+	return &file_cc_analyzer_proto_enumTypes[0]
+}
+
+func (x Status_Code) Number() protoreflect.EnumNumber {
+	return protoreflect.EnumNumber(x)
+}
+
+// Deprecated: Use Status_Code.Descriptor instead.
+func (Status_Code) EnumDescriptor() ([]byte, []int) {
+	return file_cc_analyzer_proto_rawDescGZIP(), []int{0, 0}
+}
+
+// Indicates the success/failure for analysis.
+type Status struct {
+	state         protoimpl.MessageState
+	sizeCache     protoimpl.SizeCache
+	unknownFields protoimpl.UnknownFields
+
+	Code Status_Code `protobuf:"varint,1,opt,name=code,proto3,enum=cc_analyzer.Status_Code" json:"code,omitempty"`
+	// Details about the status, might be displayed to user.
+	Message *string `protobuf:"bytes,2,opt,name=message,proto3,oneof" json:"message,omitempty"`
+}
+
+func (x *Status) Reset() {
+	*x = Status{}
+	if protoimpl.UnsafeEnabled {
+		mi := &file_cc_analyzer_proto_msgTypes[0]
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		ms.StoreMessageInfo(mi)
+	}
+}
+
+func (x *Status) String() string {
+	return protoimpl.X.MessageStringOf(x)
+}
+
+func (*Status) ProtoMessage() {}
+
+func (x *Status) ProtoReflect() protoreflect.Message {
+	mi := &file_cc_analyzer_proto_msgTypes[0]
+	if protoimpl.UnsafeEnabled && x != nil {
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		if ms.LoadMessageInfo() == nil {
+			ms.StoreMessageInfo(mi)
+		}
+		return ms
+	}
+	return mi.MessageOf(x)
+}
+
+// Deprecated: Use Status.ProtoReflect.Descriptor instead.
+func (*Status) Descriptor() ([]byte, []int) {
+	return file_cc_analyzer_proto_rawDescGZIP(), []int{0}
+}
+
+func (x *Status) GetCode() Status_Code {
+	if x != nil {
+		return x.Code
+	}
+	return Status_OK
+}
+
+func (x *Status) GetMessage() string {
+	if x != nil && x.Message != nil {
+		return *x.Message
+	}
+	return ""
+}
+
+// Represents an Android checkout on user's workstation.
+type RepoState struct {
+	state         protoimpl.MessageState
+	sizeCache     protoimpl.SizeCache
+	unknownFields protoimpl.UnknownFields
+
+	// Absolute path for the checkout in the workstation.
+	// e.g. /home/user/work/android/
+	RepoDir string `protobuf:"bytes,1,opt,name=repo_dir,json=repoDir,proto3" json:"repo_dir,omitempty"`
+	// Relative to repo_dir.
+	ActiveFilePath []string `protobuf:"bytes,2,rep,name=active_file_path,json=activeFilePath,proto3" json:"active_file_path,omitempty"`
+	// Repository relative path to output directory in workstation.
+	OutDir string `protobuf:"bytes,3,opt,name=out_dir,json=outDir,proto3" json:"out_dir,omitempty"`
+	// Repository relative path to compile_commands.json in workstation.
+	CompDbPath string `protobuf:"bytes,4,opt,name=comp_db_path,json=compDbPath,proto3" json:"comp_db_path,omitempty"`
+}
+
+func (x *RepoState) Reset() {
+	*x = RepoState{}
+	if protoimpl.UnsafeEnabled {
+		mi := &file_cc_analyzer_proto_msgTypes[1]
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		ms.StoreMessageInfo(mi)
+	}
+}
+
+func (x *RepoState) String() string {
+	return protoimpl.X.MessageStringOf(x)
+}
+
+func (*RepoState) ProtoMessage() {}
+
+func (x *RepoState) ProtoReflect() protoreflect.Message {
+	mi := &file_cc_analyzer_proto_msgTypes[1]
+	if protoimpl.UnsafeEnabled && x != nil {
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		if ms.LoadMessageInfo() == nil {
+			ms.StoreMessageInfo(mi)
+		}
+		return ms
+	}
+	return mi.MessageOf(x)
+}
+
+// Deprecated: Use RepoState.ProtoReflect.Descriptor instead.
+func (*RepoState) Descriptor() ([]byte, []int) {
+	return file_cc_analyzer_proto_rawDescGZIP(), []int{1}
+}
+
+func (x *RepoState) GetRepoDir() string {
+	if x != nil {
+		return x.RepoDir
+	}
+	return ""
+}
+
+func (x *RepoState) GetActiveFilePath() []string {
+	if x != nil {
+		return x.ActiveFilePath
+	}
+	return nil
+}
+
+func (x *RepoState) GetOutDir() string {
+	if x != nil {
+		return x.OutDir
+	}
+	return ""
+}
+
+func (x *RepoState) GetCompDbPath() string {
+	if x != nil {
+		return x.CompDbPath
+	}
+	return ""
+}
+
+// Provides all the targets that are pre-requisities for running language
+// services on active_file_paths.
+type DepsResponse struct {
+	state         protoimpl.MessageState
+	sizeCache     protoimpl.SizeCache
+	unknownFields protoimpl.UnknownFields
+
+	Deps   []*DepsResponse_Deps `protobuf:"bytes,1,rep,name=deps,proto3" json:"deps,omitempty"`
+	Status *Status              `protobuf:"bytes,2,opt,name=status,proto3,oneof" json:"status,omitempty"`
+}
+
+func (x *DepsResponse) Reset() {
+	*x = DepsResponse{}
+	if protoimpl.UnsafeEnabled {
+		mi := &file_cc_analyzer_proto_msgTypes[2]
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		ms.StoreMessageInfo(mi)
+	}
+}
+
+func (x *DepsResponse) String() string {
+	return protoimpl.X.MessageStringOf(x)
+}
+
+func (*DepsResponse) ProtoMessage() {}
+
+func (x *DepsResponse) ProtoReflect() protoreflect.Message {
+	mi := &file_cc_analyzer_proto_msgTypes[2]
+	if protoimpl.UnsafeEnabled && x != nil {
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		if ms.LoadMessageInfo() == nil {
+			ms.StoreMessageInfo(mi)
+		}
+		return ms
+	}
+	return mi.MessageOf(x)
+}
+
+// Deprecated: Use DepsResponse.ProtoReflect.Descriptor instead.
+func (*DepsResponse) Descriptor() ([]byte, []int) {
+	return file_cc_analyzer_proto_rawDescGZIP(), []int{2}
+}
+
+func (x *DepsResponse) GetDeps() []*DepsResponse_Deps {
+	if x != nil {
+		return x.Deps
+	}
+	return nil
+}
+
+func (x *DepsResponse) GetStatus() *Status {
+	if x != nil {
+		return x.Status
+	}
+	return nil
+}
+
+// Returns all the information necessary for providing language services for the
+// active files.
+type GeneratedFile struct {
+	state         protoimpl.MessageState
+	sizeCache     protoimpl.SizeCache
+	unknownFields protoimpl.UnknownFields
+
+	// Path to the file relative to repository root.
+	Path string `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
+	// The text of the generated file, if not provided contents will be read
+	// from the path above in user's workstation.
+	Contents []byte `protobuf:"bytes,2,opt,name=contents,proto3,oneof" json:"contents,omitempty"`
+}
+
+func (x *GeneratedFile) Reset() {
+	*x = GeneratedFile{}
+	if protoimpl.UnsafeEnabled {
+		mi := &file_cc_analyzer_proto_msgTypes[3]
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		ms.StoreMessageInfo(mi)
+	}
+}
+
+func (x *GeneratedFile) String() string {
+	return protoimpl.X.MessageStringOf(x)
+}
+
+func (*GeneratedFile) ProtoMessage() {}
+
+func (x *GeneratedFile) ProtoReflect() protoreflect.Message {
+	mi := &file_cc_analyzer_proto_msgTypes[3]
+	if protoimpl.UnsafeEnabled && x != nil {
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		if ms.LoadMessageInfo() == nil {
+			ms.StoreMessageInfo(mi)
+		}
+		return ms
+	}
+	return mi.MessageOf(x)
+}
+
+// Deprecated: Use GeneratedFile.ProtoReflect.Descriptor instead.
+func (*GeneratedFile) Descriptor() ([]byte, []int) {
+	return file_cc_analyzer_proto_rawDescGZIP(), []int{3}
+}
+
+func (x *GeneratedFile) GetPath() string {
+	if x != nil {
+		return x.Path
+	}
+	return ""
+}
+
+func (x *GeneratedFile) GetContents() []byte {
+	if x != nil {
+		return x.Contents
+	}
+	return nil
+}
+
+type SourceFile struct {
+	state         protoimpl.MessageState
+	sizeCache     protoimpl.SizeCache
+	unknownFields protoimpl.UnknownFields
+
+	// Path to the source file relative to repository root.
+	Path string `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
+	// Working directory used by the build system. All the relative
+	// paths in compiler_arguments should be relative to this path.
+	// Relative to repository root.
+	WorkingDir string `protobuf:"bytes,2,opt,name=working_dir,json=workingDir,proto3" json:"working_dir,omitempty"`
+	// Compiler arguments to compile the source file. If multiple variants
+	// of the module being compiled are possible, the query script will choose
+	// one.
+	CompilerArguments []string `protobuf:"bytes,3,rep,name=compiler_arguments,json=compilerArguments,proto3" json:"compiler_arguments,omitempty"`
+	// Any generated files that are used in compiling the file.
+	Generated []*GeneratedFile `protobuf:"bytes,4,rep,name=generated,proto3" json:"generated,omitempty"`
+	// Paths to all of the sources, like build files, code generators,
+	// proto files etc. that were used during analysis. Used to figure
+	// out when a set of build artifacts are stale and the query tool
+	// must be re-run.
+	// Relative to repository root.
+	Deps []string `protobuf:"bytes,5,rep,name=deps,proto3" json:"deps,omitempty"`
+	// Represents analysis status for this particular file. e.g. not part
+	// of the build graph.
+	Status *Status `protobuf:"bytes,6,opt,name=status,proto3,oneof" json:"status,omitempty"`
+}
+
+func (x *SourceFile) Reset() {
+	*x = SourceFile{}
+	if protoimpl.UnsafeEnabled {
+		mi := &file_cc_analyzer_proto_msgTypes[4]
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		ms.StoreMessageInfo(mi)
+	}
+}
+
+func (x *SourceFile) String() string {
+	return protoimpl.X.MessageStringOf(x)
+}
+
+func (*SourceFile) ProtoMessage() {}
+
+func (x *SourceFile) ProtoReflect() protoreflect.Message {
+	mi := &file_cc_analyzer_proto_msgTypes[4]
+	if protoimpl.UnsafeEnabled && x != nil {
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		if ms.LoadMessageInfo() == nil {
+			ms.StoreMessageInfo(mi)
+		}
+		return ms
+	}
+	return mi.MessageOf(x)
+}
+
+// Deprecated: Use SourceFile.ProtoReflect.Descriptor instead.
+func (*SourceFile) Descriptor() ([]byte, []int) {
+	return file_cc_analyzer_proto_rawDescGZIP(), []int{4}
+}
+
+func (x *SourceFile) GetPath() string {
+	if x != nil {
+		return x.Path
+	}
+	return ""
+}
+
+func (x *SourceFile) GetWorkingDir() string {
+	if x != nil {
+		return x.WorkingDir
+	}
+	return ""
+}
+
+func (x *SourceFile) GetCompilerArguments() []string {
+	if x != nil {
+		return x.CompilerArguments
+	}
+	return nil
+}
+
+func (x *SourceFile) GetGenerated() []*GeneratedFile {
+	if x != nil {
+		return x.Generated
+	}
+	return nil
+}
+
+func (x *SourceFile) GetDeps() []string {
+	if x != nil {
+		return x.Deps
+	}
+	return nil
+}
+
+func (x *SourceFile) GetStatus() *Status {
+	if x != nil {
+		return x.Status
+	}
+	return nil
+}
+
+type IdeAnalysis struct {
+	state         protoimpl.MessageState
+	sizeCache     protoimpl.SizeCache
+	unknownFields protoimpl.UnknownFields
+
+	Sources []*SourceFile `protobuf:"bytes,2,rep,name=sources,proto3" json:"sources,omitempty"`
+	// Status representing overall analysis.
+	// Should fail only when no analysis can be performed.
+	Status *Status `protobuf:"bytes,3,opt,name=status,proto3,oneof" json:"status,omitempty"`
+}
+
+func (x *IdeAnalysis) Reset() {
+	*x = IdeAnalysis{}
+	if protoimpl.UnsafeEnabled {
+		mi := &file_cc_analyzer_proto_msgTypes[5]
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		ms.StoreMessageInfo(mi)
+	}
+}
+
+func (x *IdeAnalysis) String() string {
+	return protoimpl.X.MessageStringOf(x)
+}
+
+func (*IdeAnalysis) ProtoMessage() {}
+
+func (x *IdeAnalysis) ProtoReflect() protoreflect.Message {
+	mi := &file_cc_analyzer_proto_msgTypes[5]
+	if protoimpl.UnsafeEnabled && x != nil {
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		if ms.LoadMessageInfo() == nil {
+			ms.StoreMessageInfo(mi)
+		}
+		return ms
+	}
+	return mi.MessageOf(x)
+}
+
+// Deprecated: Use IdeAnalysis.ProtoReflect.Descriptor instead.
+func (*IdeAnalysis) Descriptor() ([]byte, []int) {
+	return file_cc_analyzer_proto_rawDescGZIP(), []int{5}
+}
+
+func (x *IdeAnalysis) GetSources() []*SourceFile {
+	if x != nil {
+		return x.Sources
+	}
+	return nil
+}
+
+func (x *IdeAnalysis) GetStatus() *Status {
+	if x != nil {
+		return x.Status
+	}
+	return nil
+}
+
+// Build dependencies of a source file for providing language services.
+type DepsResponse_Deps struct {
+	state         protoimpl.MessageState
+	sizeCache     protoimpl.SizeCache
+	unknownFields protoimpl.UnknownFields
+
+	// Relative to repo_dir.
+	SourceFile string `protobuf:"bytes,1,opt,name=source_file,json=sourceFile,proto3" json:"source_file,omitempty"`
+	// Build target to execute for generating dep.
+	BuildTarget []string `protobuf:"bytes,2,rep,name=build_target,json=buildTarget,proto3" json:"build_target,omitempty"`
+	Status      *Status  `protobuf:"bytes,3,opt,name=status,proto3,oneof" json:"status,omitempty"`
+}
+
+func (x *DepsResponse_Deps) Reset() {
+	*x = DepsResponse_Deps{}
+	if protoimpl.UnsafeEnabled {
+		mi := &file_cc_analyzer_proto_msgTypes[6]
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		ms.StoreMessageInfo(mi)
+	}
+}
+
+func (x *DepsResponse_Deps) String() string {
+	return protoimpl.X.MessageStringOf(x)
+}
+
+func (*DepsResponse_Deps) ProtoMessage() {}
+
+func (x *DepsResponse_Deps) ProtoReflect() protoreflect.Message {
+	mi := &file_cc_analyzer_proto_msgTypes[6]
+	if protoimpl.UnsafeEnabled && x != nil {
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		if ms.LoadMessageInfo() == nil {
+			ms.StoreMessageInfo(mi)
+		}
+		return ms
+	}
+	return mi.MessageOf(x)
+}
+
+// Deprecated: Use DepsResponse_Deps.ProtoReflect.Descriptor instead.
+func (*DepsResponse_Deps) Descriptor() ([]byte, []int) {
+	return file_cc_analyzer_proto_rawDescGZIP(), []int{2, 0}
+}
+
+func (x *DepsResponse_Deps) GetSourceFile() string {
+	if x != nil {
+		return x.SourceFile
+	}
+	return ""
+}
+
+func (x *DepsResponse_Deps) GetBuildTarget() []string {
+	if x != nil {
+		return x.BuildTarget
+	}
+	return nil
+}
+
+func (x *DepsResponse_Deps) GetStatus() *Status {
+	if x != nil {
+		return x.Status
+	}
+	return nil
+}
+
+var File_cc_analyzer_proto protoreflect.FileDescriptor
+
+var file_cc_analyzer_proto_rawDesc = []byte{
+	0x0a, 0x11, 0x63, 0x63, 0x5f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72, 0x2e, 0x70, 0x72,
+	0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x63, 0x63, 0x5f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72,
+	0x22, 0x7e, 0x0a, 0x06, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x2c, 0x0a, 0x04, 0x63, 0x6f,
+	0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x18, 0x2e, 0x63, 0x63, 0x5f, 0x61, 0x6e,
+	0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x43, 0x6f,
+	0x64, 0x65, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x1d, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73,
+	0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x07, 0x6d, 0x65, 0x73,
+	0x73, 0x61, 0x67, 0x65, 0x88, 0x01, 0x01, 0x22, 0x1b, 0x0a, 0x04, 0x43, 0x6f, 0x64, 0x65, 0x12,
+	0x06, 0x0a, 0x02, 0x4f, 0x4b, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x46, 0x41, 0x49, 0x4c, 0x55,
+	0x52, 0x45, 0x10, 0x01, 0x42, 0x0a, 0x0a, 0x08, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
+	0x22, 0x8b, 0x01, 0x0a, 0x09, 0x52, 0x65, 0x70, 0x6f, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x19,
+	0x0a, 0x08, 0x72, 0x65, 0x70, 0x6f, 0x5f, 0x64, 0x69, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
+	0x52, 0x07, 0x72, 0x65, 0x70, 0x6f, 0x44, 0x69, 0x72, 0x12, 0x28, 0x0a, 0x10, 0x61, 0x63, 0x74,
+	0x69, 0x76, 0x65, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x70, 0x61, 0x74, 0x68, 0x18, 0x02, 0x20,
+	0x03, 0x28, 0x09, 0x52, 0x0e, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x46, 0x69, 0x6c, 0x65, 0x50,
+	0x61, 0x74, 0x68, 0x12, 0x17, 0x0a, 0x07, 0x6f, 0x75, 0x74, 0x5f, 0x64, 0x69, 0x72, 0x18, 0x03,
+	0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6f, 0x75, 0x74, 0x44, 0x69, 0x72, 0x12, 0x20, 0x0a, 0x0c,
+	0x63, 0x6f, 0x6d, 0x70, 0x5f, 0x64, 0x62, 0x5f, 0x70, 0x61, 0x74, 0x68, 0x18, 0x04, 0x20, 0x01,
+	0x28, 0x09, 0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x70, 0x44, 0x62, 0x50, 0x61, 0x74, 0x68, 0x22, 0x89,
+	0x02, 0x0a, 0x0c, 0x44, 0x65, 0x70, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
+	0x32, 0x0a, 0x04, 0x64, 0x65, 0x70, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1e, 0x2e,
+	0x63, 0x63, 0x5f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72, 0x2e, 0x44, 0x65, 0x70, 0x73,
+	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x44, 0x65, 0x70, 0x73, 0x52, 0x04, 0x64,
+	0x65, 0x70, 0x73, 0x12, 0x30, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x02, 0x20,
+	0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x63, 0x63, 0x5f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65,
+	0x72, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x48, 0x00, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74,
+	0x75, 0x73, 0x88, 0x01, 0x01, 0x1a, 0x87, 0x01, 0x0a, 0x04, 0x44, 0x65, 0x70, 0x73, 0x12, 0x1f,
+	0x0a, 0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x18, 0x01, 0x20,
+	0x01, 0x28, 0x09, 0x52, 0x0a, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x46, 0x69, 0x6c, 0x65, 0x12,
+	0x21, 0x0a, 0x0c, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x5f, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18,
+	0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x54, 0x61, 0x72, 0x67,
+	0x65, 0x74, 0x12, 0x30, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x03, 0x20, 0x01,
+	0x28, 0x0b, 0x32, 0x13, 0x2e, 0x63, 0x63, 0x5f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72,
+	0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x48, 0x00, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,
+	0x73, 0x88, 0x01, 0x01, 0x42, 0x09, 0x0a, 0x07, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x42,
+	0x09, 0x0a, 0x07, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x51, 0x0a, 0x0d, 0x47, 0x65,
+	0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x70,
+	0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68, 0x12,
+	0x1f, 0x0a, 0x08, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28,
+	0x0c, 0x48, 0x00, 0x52, 0x08, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x88, 0x01, 0x01,
+	0x42, 0x0b, 0x0a, 0x09, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x22, 0xfb, 0x01,
+	0x0a, 0x0a, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x12, 0x0a, 0x04,
+	0x70, 0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68,
+	0x12, 0x1f, 0x0a, 0x0b, 0x77, 0x6f, 0x72, 0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x64, 0x69, 0x72, 0x18,
+	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x77, 0x6f, 0x72, 0x6b, 0x69, 0x6e, 0x67, 0x44, 0x69,
+	0x72, 0x12, 0x2d, 0x0a, 0x12, 0x63, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x72, 0x5f, 0x61, 0x72,
+	0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x11, 0x63,
+	0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x72, 0x41, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73,
+	0x12, 0x38, 0x0a, 0x09, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x18, 0x04, 0x20,
+	0x03, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x63, 0x63, 0x5f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65,
+	0x72, 0x2e, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x46, 0x69, 0x6c, 0x65, 0x52,
+	0x09, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x65,
+	0x70, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x04, 0x64, 0x65, 0x70, 0x73, 0x12, 0x30,
+	0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13,
+	0x2e, 0x63, 0x63, 0x5f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72, 0x2e, 0x53, 0x74, 0x61,
+	0x74, 0x75, 0x73, 0x48, 0x00, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x88, 0x01, 0x01,
+	0x42, 0x09, 0x0a, 0x07, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x83, 0x01, 0x0a, 0x0b,
+	0x49, 0x64, 0x65, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x73, 0x69, 0x73, 0x12, 0x31, 0x0a, 0x07, 0x73,
+	0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x63,
+	0x63, 0x5f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72, 0x2e, 0x53, 0x6f, 0x75, 0x72, 0x63,
+	0x65, 0x46, 0x69, 0x6c, 0x65, 0x52, 0x07, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x12, 0x30,
+	0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13,
+	0x2e, 0x63, 0x63, 0x5f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72, 0x2e, 0x53, 0x74, 0x61,
+	0x74, 0x75, 0x73, 0x48, 0x00, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x88, 0x01, 0x01,
+	0x42, 0x09, 0x0a, 0x07, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x4a, 0x04, 0x08, 0x01, 0x10,
+	0x02, 0x42, 0x1d, 0x5a, 0x1b, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2f, 0x63,
+	0x63, 0x5f, 0x61, 0x6e, 0x61, 0x6c, 0x79, 0x7a, 0x65, 0x72, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
+	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
+}
+
+var (
+	file_cc_analyzer_proto_rawDescOnce sync.Once
+	file_cc_analyzer_proto_rawDescData = file_cc_analyzer_proto_rawDesc
+)
+
+func file_cc_analyzer_proto_rawDescGZIP() []byte {
+	file_cc_analyzer_proto_rawDescOnce.Do(func() {
+		file_cc_analyzer_proto_rawDescData = protoimpl.X.CompressGZIP(file_cc_analyzer_proto_rawDescData)
+	})
+	return file_cc_analyzer_proto_rawDescData
+}
+
+var file_cc_analyzer_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
+var file_cc_analyzer_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
+var file_cc_analyzer_proto_goTypes = []interface{}{
+	(Status_Code)(0),          // 0: cc_analyzer.Status.Code
+	(*Status)(nil),            // 1: cc_analyzer.Status
+	(*RepoState)(nil),         // 2: cc_analyzer.RepoState
+	(*DepsResponse)(nil),      // 3: cc_analyzer.DepsResponse
+	(*GeneratedFile)(nil),     // 4: cc_analyzer.GeneratedFile
+	(*SourceFile)(nil),        // 5: cc_analyzer.SourceFile
+	(*IdeAnalysis)(nil),       // 6: cc_analyzer.IdeAnalysis
+	(*DepsResponse_Deps)(nil), // 7: cc_analyzer.DepsResponse.Deps
+}
+var file_cc_analyzer_proto_depIdxs = []int32{
+	0, // 0: cc_analyzer.Status.code:type_name -> cc_analyzer.Status.Code
+	7, // 1: cc_analyzer.DepsResponse.deps:type_name -> cc_analyzer.DepsResponse.Deps
+	1, // 2: cc_analyzer.DepsResponse.status:type_name -> cc_analyzer.Status
+	4, // 3: cc_analyzer.SourceFile.generated:type_name -> cc_analyzer.GeneratedFile
+	1, // 4: cc_analyzer.SourceFile.status:type_name -> cc_analyzer.Status
+	5, // 5: cc_analyzer.IdeAnalysis.sources:type_name -> cc_analyzer.SourceFile
+	1, // 6: cc_analyzer.IdeAnalysis.status:type_name -> cc_analyzer.Status
+	1, // 7: cc_analyzer.DepsResponse.Deps.status:type_name -> cc_analyzer.Status
+	8, // [8:8] is the sub-list for method output_type
+	8, // [8:8] is the sub-list for method input_type
+	8, // [8:8] is the sub-list for extension type_name
+	8, // [8:8] is the sub-list for extension extendee
+	0, // [0:8] is the sub-list for field type_name
+}
+
+func init() { file_cc_analyzer_proto_init() }
+func file_cc_analyzer_proto_init() {
+	if File_cc_analyzer_proto != nil {
+		return
+	}
+	if !protoimpl.UnsafeEnabled {
+		file_cc_analyzer_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
+			switch v := v.(*Status); i {
+			case 0:
+				return &v.state
+			case 1:
+				return &v.sizeCache
+			case 2:
+				return &v.unknownFields
+			default:
+				return nil
+			}
+		}
+		file_cc_analyzer_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
+			switch v := v.(*RepoState); i {
+			case 0:
+				return &v.state
+			case 1:
+				return &v.sizeCache
+			case 2:
+				return &v.unknownFields
+			default:
+				return nil
+			}
+		}
+		file_cc_analyzer_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
+			switch v := v.(*DepsResponse); i {
+			case 0:
+				return &v.state
+			case 1:
+				return &v.sizeCache
+			case 2:
+				return &v.unknownFields
+			default:
+				return nil
+			}
+		}
+		file_cc_analyzer_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
+			switch v := v.(*GeneratedFile); i {
+			case 0:
+				return &v.state
+			case 1:
+				return &v.sizeCache
+			case 2:
+				return &v.unknownFields
+			default:
+				return nil
+			}
+		}
+		file_cc_analyzer_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
+			switch v := v.(*SourceFile); i {
+			case 0:
+				return &v.state
+			case 1:
+				return &v.sizeCache
+			case 2:
+				return &v.unknownFields
+			default:
+				return nil
+			}
+		}
+		file_cc_analyzer_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
+			switch v := v.(*IdeAnalysis); i {
+			case 0:
+				return &v.state
+			case 1:
+				return &v.sizeCache
+			case 2:
+				return &v.unknownFields
+			default:
+				return nil
+			}
+		}
+		file_cc_analyzer_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
+			switch v := v.(*DepsResponse_Deps); i {
+			case 0:
+				return &v.state
+			case 1:
+				return &v.sizeCache
+			case 2:
+				return &v.unknownFields
+			default:
+				return nil
+			}
+		}
+	}
+	file_cc_analyzer_proto_msgTypes[0].OneofWrappers = []interface{}{}
+	file_cc_analyzer_proto_msgTypes[2].OneofWrappers = []interface{}{}
+	file_cc_analyzer_proto_msgTypes[3].OneofWrappers = []interface{}{}
+	file_cc_analyzer_proto_msgTypes[4].OneofWrappers = []interface{}{}
+	file_cc_analyzer_proto_msgTypes[5].OneofWrappers = []interface{}{}
+	file_cc_analyzer_proto_msgTypes[6].OneofWrappers = []interface{}{}
+	type x struct{}
+	out := protoimpl.TypeBuilder{
+		File: protoimpl.DescBuilder{
+			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
+			RawDescriptor: file_cc_analyzer_proto_rawDesc,
+			NumEnums:      1,
+			NumMessages:   7,
+			NumExtensions: 0,
+			NumServices:   0,
+		},
+		GoTypes:           file_cc_analyzer_proto_goTypes,
+		DependencyIndexes: file_cc_analyzer_proto_depIdxs,
+		EnumInfos:         file_cc_analyzer_proto_enumTypes,
+		MessageInfos:      file_cc_analyzer_proto_msgTypes,
+	}.Build()
+	File_cc_analyzer_proto = out.File
+	file_cc_analyzer_proto_rawDesc = nil
+	file_cc_analyzer_proto_goTypes = nil
+	file_cc_analyzer_proto_depIdxs = nil
+}
diff --git a/tools/ide_query/cc_analyzer_proto/cc_analyzer.proto b/tools/ide_query/cc_analyzer_proto/cc_analyzer.proto
new file mode 100644
index 0000000000..094eb49224
--- /dev/null
+++ b/tools/ide_query/cc_analyzer_proto/cc_analyzer.proto
@@ -0,0 +1,109 @@
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
+syntax = "proto3";
+
+package cc_analyzer;
+
+option go_package = "ide_query/cc_analyzer_proto";
+
+// Indicates the success/failure for analysis.
+message Status {
+  enum Code {
+    OK = 0;
+    FAILURE = 1;
+  }
+  Code code = 1;
+  // Details about the status, might be displayed to user.
+  optional string message = 2;
+}
+
+// Represents an Android checkout on user's workstation.
+message RepoState {
+  // Absolute path for the checkout in the workstation.
+  // e.g. /home/user/work/android/
+  string repo_dir = 1;
+  // Relative to repo_dir.
+  repeated string active_file_path = 2;
+  // Repository relative path to output directory in workstation.
+  string out_dir = 3;
+  // Repository relative path to compile_commands.json in workstation.
+  string comp_db_path = 4;
+}
+
+// Provides all the targets that are pre-requisities for running language
+// services on active_file_paths.
+message DepsResponse {
+  // Build dependencies of a source file for providing language services.
+  message Deps {
+    // Relative to repo_dir.
+    string source_file = 1;
+    // Build target to execute for generating dep.
+    repeated string build_target = 2;
+    optional Status status = 3;
+  }
+  repeated Deps deps = 1;
+  optional Status status = 2;
+}
+
+// Returns all the information necessary for providing language services for the
+// active files.
+message GeneratedFile {
+  // Path to the file relative to repository root.
+  string path = 1;
+
+  // The text of the generated file, if not provided contents will be read
+  // from the path above in user's workstation.
+  optional bytes contents = 2;
+}
+
+message SourceFile {
+  // Path to the source file relative to repository root.
+  string path = 1;
+
+  // Working directory used by the build system. All the relative
+  // paths in compiler_arguments should be relative to this path.
+  // Relative to repository root.
+  string working_dir = 2;
+
+  // Compiler arguments to compile the source file. If multiple variants
+  // of the module being compiled are possible, the query script will choose
+  // one.
+  repeated string compiler_arguments = 3;
+
+  // Any generated files that are used in compiling the file.
+  repeated GeneratedFile generated = 4;
+
+  // Paths to all of the sources, like build files, code generators,
+  // proto files etc. that were used during analysis. Used to figure
+  // out when a set of build artifacts are stale and the query tool
+  // must be re-run.
+  // Relative to repository root.
+  repeated string deps = 5;
+
+  // Represents analysis status for this particular file. e.g. not part
+  // of the build graph.
+  optional Status status = 6;
+}
+
+message IdeAnalysis {
+  repeated SourceFile sources = 2;
+
+  // Status representing overall analysis.
+  // Should fail only when no analysis can be performed.
+  optional Status status = 3;
+
+  reserved 1;
+}
diff --git a/tools/ide_query/cc_analyzer_proto/regen.sh b/tools/ide_query/cc_analyzer_proto/regen.sh
new file mode 100755
index 0000000000..ef44f8809c
--- /dev/null
+++ b/tools/ide_query/cc_analyzer_proto/regen.sh
@@ -0,0 +1,3 @@
+#!/bin/bash
+
+aprotoc --go_out=paths=source_relative:. cc_analyzer.proto
diff --git a/tools/ide_query/ide_query.go b/tools/ide_query/ide_query.go
index de84fbe3e4..23c7abd2a0 100644
--- a/tools/ide_query/ide_query.go
+++ b/tools/ide_query/ide_query.go
@@ -33,6 +33,7 @@ import (
 	"strings"
 
 	"google.golang.org/protobuf/proto"
+	apb "ide_query/cc_analyzer_proto"
 	pb "ide_query/ide_query_proto"
 )
 
@@ -42,9 +43,6 @@ type Env struct {
 	RepoDir        string
 	OutDir         string
 	ClangToolsRoot string
-
-	CcFiles   []string
-	JavaFiles []string
 }
 
 // LunchTarget is a parsed Android lunch target.
@@ -83,7 +81,7 @@ func (l *LunchTarget) String() string {
 
 func main() {
 	var env Env
-	env.OutDir = os.Getenv("OUT_DIR")
+	env.OutDir = strings.TrimSuffix(os.Getenv("OUT_DIR"), "/")
 	env.RepoDir = os.Getenv("ANDROID_BUILD_TOP")
 	env.ClangToolsRoot = os.Getenv("PREBUILTS_CLANG_TOOLS_ROOT")
 	flag.Var(&env.LunchTarget, "lunch_target", "The lunch target to query")
@@ -95,12 +93,13 @@ func main() {
 		return
 	}
 
+	var ccFiles, javaFiles []string
 	for _, f := range files {
 		switch {
 		case strings.HasSuffix(f, ".java") || strings.HasSuffix(f, ".kt"):
-			env.JavaFiles = append(env.JavaFiles, f)
+			javaFiles = append(javaFiles, f)
 		case strings.HasSuffix(f, ".cc") || strings.HasSuffix(f, ".cpp") || strings.HasSuffix(f, ".h"):
-			env.CcFiles = append(env.CcFiles, f)
+			ccFiles = append(ccFiles, f)
 		default:
 			log.Printf("File %q is supported - will be skipped.", f)
 		}
@@ -110,28 +109,54 @@ func main() {
 	// TODO(michaelmerg): Figure out if module_bp_java_deps.json and compile_commands.json is outdated.
 	runMake(ctx, env, "nothing")
 
-	javaModules, javaFileToModuleMap, err := loadJavaModules(&env)
+	javaModules, err := loadJavaModules(env)
 	if err != nil {
 		log.Printf("Failed to load java modules: %v", err)
 	}
-	toMake := getJavaTargets(javaFileToModuleMap)
 
-	ccTargets, status := getCCTargets(ctx, &env)
-	if status != nil && status.Code != pb.Status_OK {
-		log.Fatalf("Failed to query cc targets: %v", *status.Message)
+	var targets []string
+	javaTargetsByFile := findJavaModules(javaFiles, javaModules)
+	for _, t := range javaTargetsByFile {
+		targets = append(targets, t)
 	}
-	toMake = append(toMake, ccTargets...)
-	fmt.Fprintf(os.Stderr, "Running make for modules: %v\n", strings.Join(toMake, ", "))
-	if err := runMake(ctx, env, toMake...); err != nil {
-		log.Printf("Building deps failed: %v", err)
+
+	ccTargets, err := getCCTargets(ctx, env, ccFiles)
+	if err != nil {
+		log.Fatalf("Failed to query cc targets: %v", err)
+	}
+	targets = append(targets, ccTargets...)
+	if len(targets) == 0 {
+		fmt.Println("No targets found.")
+		os.Exit(1)
+		return
+	}
+
+	fmt.Fprintf(os.Stderr, "Running make for modules: %v\n", strings.Join(targets, ", "))
+	if err := runMake(ctx, env, targets...); err != nil {
+		log.Printf("Building modules failed: %v", err)
 	}
 
-	res := getJavaInputs(&env, javaModules, javaFileToModuleMap)
-	ccAnalysis := getCCInputs(ctx, &env)
-	proto.Merge(res, ccAnalysis)
+	var analysis pb.IdeAnalysis
+	results, units := getJavaInputs(env, javaTargetsByFile, javaModules)
+	analysis.Results = results
+	analysis.Units = units
+	if err != nil && analysis.Error == nil {
+		analysis.Error = &pb.AnalysisError{
+			ErrorMessage: err.Error(),
+		}
+	}
 
-	res.BuildArtifactRoot = env.OutDir
-	data, err := proto.Marshal(res)
+	results, units, err = getCCInputs(ctx, env, ccFiles)
+	analysis.Results = append(analysis.Results, results...)
+	analysis.Units = append(analysis.Units, units...)
+	if err != nil && analysis.Error == nil {
+		analysis.Error = &pb.AnalysisError{
+			ErrorMessage: err.Error(),
+		}
+	}
+
+	analysis.BuildOutDir = env.OutDir
+	data, err := proto.Marshal(&analysis)
 	if err != nil {
 		log.Fatalf("Failed to marshal result proto: %v", err)
 	}
@@ -141,22 +166,22 @@ func main() {
 		log.Fatalf("Failed to write result proto: %v", err)
 	}
 
-	for _, s := range res.Sources {
-		fmt.Fprintf(os.Stderr, "%s: %v (Deps: %d, Generated: %d)\n", s.GetPath(), s.GetStatus(), len(s.GetDeps()), len(s.GetGenerated()))
+	for _, r := range analysis.Results {
+		fmt.Fprintf(os.Stderr, "%s: %+v\n", r.GetSourceFilePath(), r.GetStatus())
 	}
 }
 
-func repoState(env *Env) *pb.RepoState {
+func repoState(env Env, filePaths []string) *apb.RepoState {
 	const compDbPath = "soong/development/ide/compdb/compile_commands.json"
-	return &pb.RepoState{
+	return &apb.RepoState{
 		RepoDir:        env.RepoDir,
-		ActiveFilePath: env.CcFiles,
+		ActiveFilePath: filePaths,
 		OutDir:         env.OutDir,
 		CompDbPath:     path.Join(env.OutDir, compDbPath),
 	}
 }
 
-func runCCanalyzer(ctx context.Context, env *Env, mode string, in []byte) ([]byte, error) {
+func runCCanalyzer(ctx context.Context, env Env, mode string, in []byte) ([]byte, error) {
 	ccAnalyzerPath := path.Join(env.ClangToolsRoot, "bin/ide_query_cc_analyzer")
 	outBuffer := new(bytes.Buffer)
 
@@ -176,127 +201,205 @@ func runCCanalyzer(ctx context.Context, env *Env, mode string, in []byte) ([]byt
 }
 
 // Execute cc_analyzer and get all the targets that needs to be build for analyzing files.
-func getCCTargets(ctx context.Context, env *Env) ([]string, *pb.Status) {
-	state := repoState(env)
-	bytes, err := proto.Marshal(state)
+func getCCTargets(ctx context.Context, env Env, filePaths []string) ([]string, error) {
+	state, err := proto.Marshal(repoState(env, filePaths))
 	if err != nil {
 		log.Fatalln("Failed to serialize state:", err)
 	}
 
-	resp := new(pb.DepsResponse)
-	result, err := runCCanalyzer(ctx, env, "deps", bytes)
-	if marshal_err := proto.Unmarshal(result, resp); marshal_err != nil {
-		return nil, &pb.Status{
-			Code:    pb.Status_FAILURE,
-			Message: proto.String("Malformed response from cc_analyzer: " + marshal_err.Error()),
-		}
+	resp := new(apb.DepsResponse)
+	result, err := runCCanalyzer(ctx, env, "deps", state)
+	if err != nil {
+		return nil, err
+	}
+
+	if err := proto.Unmarshal(result, resp); err != nil {
+		return nil, fmt.Errorf("malformed response from cc_analyzer: %v", err)
 	}
 
 	var targets []string
-	if resp.Status != nil && resp.Status.Code != pb.Status_OK {
-		return targets, resp.Status
+	if resp.Status != nil && resp.Status.Code != apb.Status_OK {
+		return targets, fmt.Errorf("cc_analyzer failed: %v", resp.Status.Message)
 	}
+
 	for _, deps := range resp.Deps {
 		targets = append(targets, deps.BuildTarget...)
 	}
+	return targets, nil
+}
 
-	status := &pb.Status{Code: pb.Status_OK}
+func getCCInputs(ctx context.Context, env Env, filePaths []string) ([]*pb.AnalysisResult, []*pb.BuildableUnit, error) {
+	state, err := proto.Marshal(repoState(env, filePaths))
 	if err != nil {
-		status = &pb.Status{
-			Code:    pb.Status_FAILURE,
-			Message: proto.String(err.Error()),
-		}
+		log.Fatalln("Failed to serialize state:", err)
 	}
-	return targets, status
-}
 
-func getCCInputs(ctx context.Context, env *Env) *pb.IdeAnalysis {
-	state := repoState(env)
-	bytes, err := proto.Marshal(state)
+	resp := new(apb.IdeAnalysis)
+	result, err := runCCanalyzer(ctx, env, "inputs", state)
 	if err != nil {
-		log.Fatalln("Failed to serialize state:", err)
+		return nil, nil, fmt.Errorf("cc_analyzer failed:", err)
+	}
+	if err := proto.Unmarshal(result, resp); err != nil {
+		return nil, nil, fmt.Errorf("malformed response from cc_analyzer: %v", err)
+	}
+	if resp.Status != nil && resp.Status.Code != apb.Status_OK {
+		return nil, nil, fmt.Errorf("cc_analyzer failed: %v", resp.Status.Message)
 	}
 
-	resp := new(pb.IdeAnalysis)
-	result, err := runCCanalyzer(ctx, env, "inputs", bytes)
-	if marshal_err := proto.Unmarshal(result, resp); marshal_err != nil {
-		resp.Status = &pb.Status{
-			Code:    pb.Status_FAILURE,
-			Message: proto.String("Malformed response from cc_analyzer: " + marshal_err.Error()),
+	var results []*pb.AnalysisResult
+	var units []*pb.BuildableUnit
+	for _, s := range resp.Sources {
+		status := &pb.AnalysisResult_Status{
+			Code: pb.AnalysisResult_Status_CODE_OK,
+		}
+		if s.GetStatus().GetCode() != apb.Status_OK {
+			status.Code = pb.AnalysisResult_Status_CODE_BUILD_FAILED
+			status.StatusMessage = proto.String(s.GetStatus().GetMessage())
+		}
+
+		result := &pb.AnalysisResult{
+			SourceFilePath: s.GetPath(),
+			UnitId:         s.GetPath(),
+			Status:         status,
+		}
+		results = append(results, result)
+
+		var generated []*pb.GeneratedFile
+		for _, f := range s.Generated {
+			generated = append(generated, &pb.GeneratedFile{
+				Path:     f.GetPath(),
+				Contents: f.GetContents(),
+			})
+		}
+		genUnit := &pb.BuildableUnit{
+			Id:              "genfiles_for_" + s.GetPath(),
+			SourceFilePaths: s.GetDeps(),
+			GeneratedFiles:  generated,
 		}
-		return resp
-	}
 
-	if err != nil && (resp.Status == nil || resp.Status.Code == pb.Status_OK) {
-		resp.Status = &pb.Status{
-			Code:    pb.Status_FAILURE,
-			Message: proto.String(err.Error()),
+		unit := &pb.BuildableUnit{
+			Id:                s.GetPath(),
+			Language:          pb.Language_LANGUAGE_CPP,
+			SourceFilePaths:   []string{s.GetPath()},
+			CompilerArguments: s.GetCompilerArguments(),
+			DependencyIds:     []string{genUnit.GetId()},
 		}
+		units = append(units, unit, genUnit)
 	}
-	return resp
+	return results, units, nil
 }
 
-func getJavaTargets(javaFileToModuleMap map[string]*javaModule) []string {
-	var targets []string
-	for _, m := range javaFileToModuleMap {
-		targets = append(targets, m.Name)
+// findJavaModules tries to find the modules that cover the given file paths.
+// If a file is covered by multiple modules, the first module is returned.
+func findJavaModules(paths []string, modules map[string]*javaModule) map[string]string {
+	ret := make(map[string]string)
+	for name, module := range modules {
+		if strings.HasSuffix(name, ".impl") {
+			continue
+		}
+
+		for i, p := range paths {
+			if slices.Contains(module.Srcs, p) {
+				ret[p] = name
+				paths = append(paths[:i], paths[i+1:]...)
+				break
+			}
+		}
+		if len(paths) == 0 {
+			break
+		}
 	}
-	return targets
+	return ret
 }
 
-func getJavaInputs(env *Env, javaModules map[string]*javaModule, javaFileToModuleMap map[string]*javaModule) *pb.IdeAnalysis {
-	var sources []*pb.SourceFile
-	type depsAndGenerated struct {
-		Deps      []string
-		Generated []*pb.GeneratedFile
-	}
-	moduleToDeps := make(map[string]*depsAndGenerated)
-	for _, f := range env.JavaFiles {
-		file := &pb.SourceFile{
-			Path: f,
+func getJavaInputs(env Env, modulesByPath map[string]string, modules map[string]*javaModule) ([]*pb.AnalysisResult, []*pb.BuildableUnit) {
+	var results []*pb.AnalysisResult
+	unitsById := make(map[string]*pb.BuildableUnit)
+	for p, moduleName := range modulesByPath {
+		r := &pb.AnalysisResult{
+			SourceFilePath: p,
 		}
-		sources = append(sources, file)
+		results = append(results, r)
 
-		m := javaFileToModuleMap[f]
+		m := modules[moduleName]
 		if m == nil {
-			file.Status = &pb.Status{
-				Code:    pb.Status_FAILURE,
-				Message: proto.String("File not found in any module."),
+			r.Status = &pb.AnalysisResult_Status{
+				Code:          pb.AnalysisResult_Status_CODE_NOT_FOUND,
+				StatusMessage: proto.String("File not found in any module."),
 			}
 			continue
 		}
 
-		file.Status = &pb.Status{Code: pb.Status_OK}
-		if moduleToDeps[m.Name] != nil {
-			file.Generated = moduleToDeps[m.Name].Generated
-			file.Deps = moduleToDeps[m.Name].Deps
+		r.UnitId = moduleName
+		r.Status = &pb.AnalysisResult_Status{Code: pb.AnalysisResult_Status_CODE_OK}
+		if unitsById[r.UnitId] != nil {
+			// File is covered by an already created unit.
 			continue
 		}
 
-		deps := transitiveDeps(m, javaModules)
-		var generated []*pb.GeneratedFile
-		outPrefix := env.OutDir + "/"
-		for _, d := range deps {
-			if relPath, ok := strings.CutPrefix(d, outPrefix); ok {
-				contents, err := os.ReadFile(d)
-				if err != nil {
-					fmt.Printf("Generated file %q not found - will be skipped.\n", d)
-					continue
-				}
-
-				generated = append(generated, &pb.GeneratedFile{
-					Path:     relPath,
-					Contents: contents,
-				})
+		u := &pb.BuildableUnit{
+			Id:              moduleName,
+			Language:        pb.Language_LANGUAGE_JAVA,
+			SourceFilePaths: m.Srcs,
+		}
+		unitsById[u.Id] = u
+
+		q := list.New()
+		for _, d := range m.Deps {
+			q.PushBack(d)
+		}
+		for q.Len() > 0 {
+			name := q.Remove(q.Front()).(string)
+			mod := modules[name]
+			if mod == nil || unitsById[name] != nil {
+				continue
+			}
+
+			var paths []string
+			paths = append(paths, mod.Srcs...)
+			paths = append(paths, mod.SrcJars...)
+			paths = append(paths, mod.Jars...)
+			unitsById[name] = &pb.BuildableUnit{
+				Id:              name,
+				SourceFilePaths: mod.Srcs,
+				GeneratedFiles:  genFiles(env, paths),
+			}
+
+			for _, d := range mod.Deps {
+				q.PushBack(d)
 			}
 		}
-		moduleToDeps[m.Name] = &depsAndGenerated{deps, generated}
-		file.Generated = generated
-		file.Deps = deps
 	}
-	return &pb.IdeAnalysis{
-		Sources: sources,
+
+	units := make([]*pb.BuildableUnit, 0, len(unitsById))
+	for _, u := range unitsById {
+		units = append(units, u)
+	}
+	return results, units
+}
+
+// genFiles returns the generated files (paths that start with outDir/) for the
+// given paths. Generated files that do not exist are ignored.
+func genFiles(env Env, paths []string) []*pb.GeneratedFile {
+	prefix := env.OutDir + "/"
+	var ret []*pb.GeneratedFile
+	for _, p := range paths {
+		relPath, ok := strings.CutPrefix(p, prefix)
+		if !ok {
+			continue
+		}
+
+		contents, err := os.ReadFile(path.Join(env.RepoDir, p))
+		if err != nil {
+			continue
+		}
+
+		ret = append(ret, &pb.GeneratedFile{
+			Path:     relPath,
+			Contents: contents,
+		})
 	}
+	return ret
 }
 
 // runMake runs Soong build for the given modules.
@@ -308,6 +411,7 @@ func runMake(ctx context.Context, env Env, modules ...string) error {
 		"TARGET_PRODUCT=" + env.LunchTarget.Product,
 		"TARGET_RELEASE=" + env.LunchTarget.Release,
 		"TARGET_BUILD_VARIANT=" + env.LunchTarget.Variant,
+		"TARGET_BUILD_TYPE=release",
 		"-k",
 	}
 	args = append(args, modules...)
@@ -319,7 +423,6 @@ func runMake(ctx context.Context, env Env, modules ...string) error {
 }
 
 type javaModule struct {
-	Name    string
 	Path    []string `json:"path,omitempty"`
 	Deps    []string `json:"dependencies,omitempty"`
 	Srcs    []string `json:"srcs,omitempty"`
@@ -327,66 +430,23 @@ type javaModule struct {
 	SrcJars []string `json:"srcjars,omitempty"`
 }
 
-func loadJavaModules(env *Env) (map[string]*javaModule, map[string]*javaModule, error) {
+func loadJavaModules(env Env) (map[string]*javaModule, error) {
 	javaDepsPath := path.Join(env.RepoDir, env.OutDir, "soong/module_bp_java_deps.json")
 	data, err := os.ReadFile(javaDepsPath)
 	if err != nil {
-		return nil, nil, err
-	}
-
-	var moduleMapping map[string]*javaModule // module name -> module
-	if err = json.Unmarshal(data, &moduleMapping); err != nil {
-		return nil, nil, err
+		return nil, err
 	}
 
-	javaModules := make(map[string]*javaModule)
-	javaFileToModuleMap := make(map[string]*javaModule)
-	for name, module := range moduleMapping {
-		if strings.HasSuffix(name, "-jarjar") || strings.HasSuffix(name, ".impl") {
-			continue
-		}
-		module.Name = name
-		javaModules[name] = module
-		for _, src := range module.Srcs {
-			if !slices.Contains(env.JavaFiles, src) {
-				// We are only interested in active files.
-				continue
-			}
-			if javaFileToModuleMap[src] != nil {
-				// TODO(michaelmerg): Handle the case where a file is covered by multiple modules.
-				log.Printf("File %q found in module %q but is already covered by module %q", src, module.Name, javaFileToModuleMap[src].Name)
-				continue
-			}
-			javaFileToModuleMap[src] = module
-		}
+	var ret map[string]*javaModule // module name -> module
+	if err = json.Unmarshal(data, &ret); err != nil {
+		return nil, err
 	}
-	return javaModules, javaFileToModuleMap, nil
-}
-
-func transitiveDeps(m *javaModule, modules map[string]*javaModule) []string {
-	var ret []string
-	q := list.New()
-	q.PushBack(m.Name)
-	seen := make(map[string]bool) // module names -> true
-	for q.Len() > 0 {
-		name := q.Remove(q.Front()).(string)
-		mod := modules[name]
-		if mod == nil {
-			continue
-		}
 
-		ret = append(ret, mod.Srcs...)
-		ret = append(ret, mod.SrcJars...)
-		ret = append(ret, mod.Jars...)
-		for _, d := range mod.Deps {
-			if seen[d] {
-				continue
-			}
-			seen[d] = true
-			q.PushBack(d)
+	// Add top level java_sdk_library for .impl modules.
+	for name, module := range ret {
+		if striped := strings.TrimSuffix(name, ".impl"); striped != name {
+			ret[striped] = module
 		}
 	}
-	slices.Sort(ret)
-	ret = slices.Compact(ret)
-	return ret
+	return ret, nil
 }
diff --git a/tools/ide_query/ide_query.sh b/tools/ide_query/ide_query.sh
index 2df48d0129..6f9b0c4b8b 100755
--- a/tools/ide_query/ide_query.sh
+++ b/tools/ide_query/ide_query.sh
@@ -32,6 +32,7 @@ case $(uname -s) in
       ;;
 esac
 
+export BUILD_ENV_SEQUENCE_NUMBER=13
 export ANDROID_BUILD_TOP=$TOP
 export OUT_DIR=${OUT_DIR}
 exec "${PREBUILTS_GO_ROOT}/bin/go" "run" "ide_query" "$@"
diff --git a/tools/ide_query/ide_query_proto/ide_query.pb.go b/tools/ide_query/ide_query_proto/ide_query.pb.go
index f3a016d36b..a190223e6c 100644
--- a/tools/ide_query/ide_query_proto/ide_query.pb.go
+++ b/tools/ide_query/ide_query_proto/ide_query.pb.go
@@ -1,6 +1,21 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
 // Code generated by protoc-gen-go. DO NOT EDIT.
 // versions:
-// 	protoc-gen-go v1.25.0-devel
+// 	protoc-gen-go v1.30.0
 // 	protoc        v3.21.12
 // source: ide_query.proto
 
@@ -20,65 +35,121 @@ const (
 	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
 )
 
-type Status_Code int32
+type Language int32
 
 const (
-	Status_OK      Status_Code = 0
-	Status_FAILURE Status_Code = 1
+	Language_LANGUAGE_UNSPECIFIED Language = 0
+	Language_LANGUAGE_JAVA        Language = 1 // also includes Kotlin
+	Language_LANGUAGE_CPP         Language = 2
 )
 
-// Enum value maps for Status_Code.
+// Enum value maps for Language.
 var (
-	Status_Code_name = map[int32]string{
-		0: "OK",
-		1: "FAILURE",
+	Language_name = map[int32]string{
+		0: "LANGUAGE_UNSPECIFIED",
+		1: "LANGUAGE_JAVA",
+		2: "LANGUAGE_CPP",
 	}
-	Status_Code_value = map[string]int32{
-		"OK":      0,
-		"FAILURE": 1,
+	Language_value = map[string]int32{
+		"LANGUAGE_UNSPECIFIED": 0,
+		"LANGUAGE_JAVA":        1,
+		"LANGUAGE_CPP":         2,
 	}
 )
 
-func (x Status_Code) Enum() *Status_Code {
-	p := new(Status_Code)
+func (x Language) Enum() *Language {
+	p := new(Language)
 	*p = x
 	return p
 }
 
-func (x Status_Code) String() string {
+func (x Language) String() string {
 	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
 }
 
-func (Status_Code) Descriptor() protoreflect.EnumDescriptor {
+func (Language) Descriptor() protoreflect.EnumDescriptor {
 	return file_ide_query_proto_enumTypes[0].Descriptor()
 }
 
-func (Status_Code) Type() protoreflect.EnumType {
+func (Language) Type() protoreflect.EnumType {
 	return &file_ide_query_proto_enumTypes[0]
 }
 
-func (x Status_Code) Number() protoreflect.EnumNumber {
+func (x Language) Number() protoreflect.EnumNumber {
 	return protoreflect.EnumNumber(x)
 }
 
-// Deprecated: Use Status_Code.Descriptor instead.
-func (Status_Code) EnumDescriptor() ([]byte, []int) {
-	return file_ide_query_proto_rawDescGZIP(), []int{0, 0}
+// Deprecated: Use Language.Descriptor instead.
+func (Language) EnumDescriptor() ([]byte, []int) {
+	return file_ide_query_proto_rawDescGZIP(), []int{0}
+}
+
+type AnalysisResult_Status_Code int32
+
+const (
+	AnalysisResult_Status_CODE_UNSPECIFIED  AnalysisResult_Status_Code = 0
+	AnalysisResult_Status_CODE_OK           AnalysisResult_Status_Code = 1
+	AnalysisResult_Status_CODE_NOT_FOUND    AnalysisResult_Status_Code = 2 // no target or module found for the source file.
+	AnalysisResult_Status_CODE_BUILD_FAILED AnalysisResult_Status_Code = 3
+)
+
+// Enum value maps for AnalysisResult_Status_Code.
+var (
+	AnalysisResult_Status_Code_name = map[int32]string{
+		0: "CODE_UNSPECIFIED",
+		1: "CODE_OK",
+		2: "CODE_NOT_FOUND",
+		3: "CODE_BUILD_FAILED",
+	}
+	AnalysisResult_Status_Code_value = map[string]int32{
+		"CODE_UNSPECIFIED":  0,
+		"CODE_OK":           1,
+		"CODE_NOT_FOUND":    2,
+		"CODE_BUILD_FAILED": 3,
+	}
+)
+
+func (x AnalysisResult_Status_Code) Enum() *AnalysisResult_Status_Code {
+	p := new(AnalysisResult_Status_Code)
+	*p = x
+	return p
+}
+
+func (x AnalysisResult_Status_Code) String() string {
+	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
+}
+
+func (AnalysisResult_Status_Code) Descriptor() protoreflect.EnumDescriptor {
+	return file_ide_query_proto_enumTypes[1].Descriptor()
+}
+
+func (AnalysisResult_Status_Code) Type() protoreflect.EnumType {
+	return &file_ide_query_proto_enumTypes[1]
+}
+
+func (x AnalysisResult_Status_Code) Number() protoreflect.EnumNumber {
+	return protoreflect.EnumNumber(x)
 }
 
-// Indicates the success/failure for analysis.
-type Status struct {
+// Deprecated: Use AnalysisResult_Status_Code.Descriptor instead.
+func (AnalysisResult_Status_Code) EnumDescriptor() ([]byte, []int) {
+	return file_ide_query_proto_rawDescGZIP(), []int{3, 0, 0}
+}
+
+type GeneratedFile struct {
 	state         protoimpl.MessageState
 	sizeCache     protoimpl.SizeCache
 	unknownFields protoimpl.UnknownFields
 
-	Code Status_Code `protobuf:"varint,1,opt,name=code,proto3,enum=ide_query.Status_Code" json:"code,omitempty"`
-	// Details about the status, might be displayed to user.
-	Message *string `protobuf:"bytes,2,opt,name=message,proto3,oneof" json:"message,omitempty"`
+	// Path to the file relative to build_out_dir.
+	Path string `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
+	// The text of the generated file, if not provided contents will be read
+	// from the path above in user's workstation.
+	Contents []byte `protobuf:"bytes,2,opt,name=contents,proto3,oneof" json:"contents,omitempty"`
 }
 
-func (x *Status) Reset() {
-	*x = Status{}
+func (x *GeneratedFile) Reset() {
+	*x = GeneratedFile{}
 	if protoimpl.UnsafeEnabled {
 		mi := &file_ide_query_proto_msgTypes[0]
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -86,13 +157,13 @@ func (x *Status) Reset() {
 	}
 }
 
-func (x *Status) String() string {
+func (x *GeneratedFile) String() string {
 	return protoimpl.X.MessageStringOf(x)
 }
 
-func (*Status) ProtoMessage() {}
+func (*GeneratedFile) ProtoMessage() {}
 
-func (x *Status) ProtoReflect() protoreflect.Message {
+func (x *GeneratedFile) ProtoReflect() protoreflect.Message {
 	mi := &file_ide_query_proto_msgTypes[0]
 	if protoimpl.UnsafeEnabled && x != nil {
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -104,44 +175,46 @@ func (x *Status) ProtoReflect() protoreflect.Message {
 	return mi.MessageOf(x)
 }
 
-// Deprecated: Use Status.ProtoReflect.Descriptor instead.
-func (*Status) Descriptor() ([]byte, []int) {
+// Deprecated: Use GeneratedFile.ProtoReflect.Descriptor instead.
+func (*GeneratedFile) Descriptor() ([]byte, []int) {
 	return file_ide_query_proto_rawDescGZIP(), []int{0}
 }
 
-func (x *Status) GetCode() Status_Code {
+func (x *GeneratedFile) GetPath() string {
 	if x != nil {
-		return x.Code
+		return x.Path
 	}
-	return Status_OK
+	return ""
 }
 
-func (x *Status) GetMessage() string {
-	if x != nil && x.Message != nil {
-		return *x.Message
+func (x *GeneratedFile) GetContents() []byte {
+	if x != nil {
+		return x.Contents
 	}
-	return ""
+	return nil
 }
 
-// Represents an Android checkout on user's workstation.
-type RepoState struct {
+type IdeAnalysis struct {
 	state         protoimpl.MessageState
 	sizeCache     protoimpl.SizeCache
 	unknownFields protoimpl.UnknownFields
 
-	// Absolute path for the checkout in the workstation.
-	// e.g. /home/user/work/android/
-	RepoDir string `protobuf:"bytes,1,opt,name=repo_dir,json=repoDir,proto3" json:"repo_dir,omitempty"`
-	// Relative to repo_dir.
-	ActiveFilePath []string `protobuf:"bytes,2,rep,name=active_file_path,json=activeFilePath,proto3" json:"active_file_path,omitempty"`
-	// Repository relative path to output directory in workstation.
-	OutDir string `protobuf:"bytes,3,opt,name=out_dir,json=outDir,proto3" json:"out_dir,omitempty"`
-	// Repository relative path to compile_commands.json in workstation.
-	CompDbPath string `protobuf:"bytes,4,opt,name=comp_db_path,json=compDbPath,proto3" json:"comp_db_path,omitempty"`
+	// Directory that contains build outputs generated by the build system.
+	// Relative to repository root.
+	BuildOutDir string `protobuf:"bytes,1,opt,name=build_out_dir,json=buildOutDir,proto3" json:"build_out_dir,omitempty"`
+	// Working directory used by the build system.
+	// Relative to repository root.
+	WorkingDir string `protobuf:"bytes,4,opt,name=working_dir,json=workingDir,proto3" json:"working_dir,omitempty"`
+	// Only set if the whole query failed.
+	Error *AnalysisError `protobuf:"bytes,5,opt,name=error,proto3,oneof" json:"error,omitempty"`
+	// List of results, one per queried file.
+	Results []*AnalysisResult `protobuf:"bytes,6,rep,name=results,proto3" json:"results,omitempty"`
+	// List of buildable units directly or indirectly references by the results.
+	Units []*BuildableUnit `protobuf:"bytes,7,rep,name=units,proto3" json:"units,omitempty"`
 }
 
-func (x *RepoState) Reset() {
-	*x = RepoState{}
+func (x *IdeAnalysis) Reset() {
+	*x = IdeAnalysis{}
 	if protoimpl.UnsafeEnabled {
 		mi := &file_ide_query_proto_msgTypes[1]
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -149,13 +222,13 @@ func (x *RepoState) Reset() {
 	}
 }
 
-func (x *RepoState) String() string {
+func (x *IdeAnalysis) String() string {
 	return protoimpl.X.MessageStringOf(x)
 }
 
-func (*RepoState) ProtoMessage() {}
+func (*IdeAnalysis) ProtoMessage() {}
 
-func (x *RepoState) ProtoReflect() protoreflect.Message {
+func (x *IdeAnalysis) ProtoReflect() protoreflect.Message {
 	mi := &file_ide_query_proto_msgTypes[1]
 	if protoimpl.UnsafeEnabled && x != nil {
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -167,52 +240,57 @@ func (x *RepoState) ProtoReflect() protoreflect.Message {
 	return mi.MessageOf(x)
 }
 
-// Deprecated: Use RepoState.ProtoReflect.Descriptor instead.
-func (*RepoState) Descriptor() ([]byte, []int) {
+// Deprecated: Use IdeAnalysis.ProtoReflect.Descriptor instead.
+func (*IdeAnalysis) Descriptor() ([]byte, []int) {
 	return file_ide_query_proto_rawDescGZIP(), []int{1}
 }
 
-func (x *RepoState) GetRepoDir() string {
+func (x *IdeAnalysis) GetBuildOutDir() string {
 	if x != nil {
-		return x.RepoDir
+		return x.BuildOutDir
 	}
 	return ""
 }
 
-func (x *RepoState) GetActiveFilePath() []string {
+func (x *IdeAnalysis) GetWorkingDir() string {
 	if x != nil {
-		return x.ActiveFilePath
+		return x.WorkingDir
+	}
+	return ""
+}
+
+func (x *IdeAnalysis) GetError() *AnalysisError {
+	if x != nil {
+		return x.Error
 	}
 	return nil
 }
 
-func (x *RepoState) GetOutDir() string {
+func (x *IdeAnalysis) GetResults() []*AnalysisResult {
 	if x != nil {
-		return x.OutDir
+		return x.Results
 	}
-	return ""
+	return nil
 }
 
-func (x *RepoState) GetCompDbPath() string {
+func (x *IdeAnalysis) GetUnits() []*BuildableUnit {
 	if x != nil {
-		return x.CompDbPath
+		return x.Units
 	}
-	return ""
+	return nil
 }
 
-// Provides all the targets that are pre-requisities for running language
-// services on active_file_paths.
-type DepsResponse struct {
+type AnalysisError struct {
 	state         protoimpl.MessageState
 	sizeCache     protoimpl.SizeCache
 	unknownFields protoimpl.UnknownFields
 
-	Deps   []*DepsResponse_Deps `protobuf:"bytes,1,rep,name=deps,proto3" json:"deps,omitempty"`
-	Status *Status              `protobuf:"bytes,2,opt,name=status,proto3,oneof" json:"status,omitempty"`
+	// Human readable error message.
+	ErrorMessage string `protobuf:"bytes,1,opt,name=error_message,json=errorMessage,proto3" json:"error_message,omitempty"`
 }
 
-func (x *DepsResponse) Reset() {
-	*x = DepsResponse{}
+func (x *AnalysisError) Reset() {
+	*x = AnalysisError{}
 	if protoimpl.UnsafeEnabled {
 		mi := &file_ide_query_proto_msgTypes[2]
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -220,13 +298,13 @@ func (x *DepsResponse) Reset() {
 	}
 }
 
-func (x *DepsResponse) String() string {
+func (x *AnalysisError) String() string {
 	return protoimpl.X.MessageStringOf(x)
 }
 
-func (*DepsResponse) ProtoMessage() {}
+func (*AnalysisError) ProtoMessage() {}
 
-func (x *DepsResponse) ProtoReflect() protoreflect.Message {
+func (x *AnalysisError) ProtoReflect() protoreflect.Message {
 	mi := &file_ide_query_proto_msgTypes[2]
 	if protoimpl.UnsafeEnabled && x != nil {
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -238,41 +316,37 @@ func (x *DepsResponse) ProtoReflect() protoreflect.Message {
 	return mi.MessageOf(x)
 }
 
-// Deprecated: Use DepsResponse.ProtoReflect.Descriptor instead.
-func (*DepsResponse) Descriptor() ([]byte, []int) {
+// Deprecated: Use AnalysisError.ProtoReflect.Descriptor instead.
+func (*AnalysisError) Descriptor() ([]byte, []int) {
 	return file_ide_query_proto_rawDescGZIP(), []int{2}
 }
 
-func (x *DepsResponse) GetDeps() []*DepsResponse_Deps {
-	if x != nil {
-		return x.Deps
-	}
-	return nil
-}
-
-func (x *DepsResponse) GetStatus() *Status {
+func (x *AnalysisError) GetErrorMessage() string {
 	if x != nil {
-		return x.Status
+		return x.ErrorMessage
 	}
-	return nil
+	return ""
 }
 
-// Returns all the information necessary for providing language services for the
-// active files.
-type GeneratedFile struct {
+type AnalysisResult struct {
 	state         protoimpl.MessageState
 	sizeCache     protoimpl.SizeCache
 	unknownFields protoimpl.UnknownFields
 
-	// Path to the file relative to IdeAnalysis.build_artifact_root.
-	Path string `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
-	// The text of the generated file, if not provided contents will be read
-	// from the path above in user's workstation.
-	Contents []byte `protobuf:"bytes,2,opt,name=contents,proto3,oneof" json:"contents,omitempty"`
+	// Path to the source file that was queried, relative to repository root.
+	SourceFilePath string `protobuf:"bytes,1,opt,name=source_file_path,json=sourceFilePath,proto3" json:"source_file_path,omitempty"`
+	// Represents status for this result. e.g. not part of the build graph.
+	Status *AnalysisResult_Status `protobuf:"bytes,2,opt,name=status,proto3" json:"status,omitempty"`
+	// ID of buildable unit that contains the source file.
+	// The ide_query script can choose the most relevant unit from multiple
+	// options.
+	UnitId string `protobuf:"bytes,3,opt,name=unit_id,json=unitId,proto3" json:"unit_id,omitempty"`
+	// Invalidation rule to check if the result is still valid.
+	Invalidation *Invalidation `protobuf:"bytes,4,opt,name=invalidation,proto3" json:"invalidation,omitempty"`
 }
 
-func (x *GeneratedFile) Reset() {
-	*x = GeneratedFile{}
+func (x *AnalysisResult) Reset() {
+	*x = AnalysisResult{}
 	if protoimpl.UnsafeEnabled {
 		mi := &file_ide_query_proto_msgTypes[3]
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -280,13 +354,13 @@ func (x *GeneratedFile) Reset() {
 	}
 }
 
-func (x *GeneratedFile) String() string {
+func (x *AnalysisResult) String() string {
 	return protoimpl.X.MessageStringOf(x)
 }
 
-func (*GeneratedFile) ProtoMessage() {}
+func (*AnalysisResult) ProtoMessage() {}
 
-func (x *GeneratedFile) ProtoReflect() protoreflect.Message {
+func (x *AnalysisResult) ProtoReflect() protoreflect.Message {
 	mi := &file_ide_query_proto_msgTypes[3]
 	if protoimpl.UnsafeEnabled && x != nil {
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -298,55 +372,68 @@ func (x *GeneratedFile) ProtoReflect() protoreflect.Message {
 	return mi.MessageOf(x)
 }
 
-// Deprecated: Use GeneratedFile.ProtoReflect.Descriptor instead.
-func (*GeneratedFile) Descriptor() ([]byte, []int) {
+// Deprecated: Use AnalysisResult.ProtoReflect.Descriptor instead.
+func (*AnalysisResult) Descriptor() ([]byte, []int) {
 	return file_ide_query_proto_rawDescGZIP(), []int{3}
 }
 
-func (x *GeneratedFile) GetPath() string {
+func (x *AnalysisResult) GetSourceFilePath() string {
 	if x != nil {
-		return x.Path
+		return x.SourceFilePath
 	}
 	return ""
 }
 
-func (x *GeneratedFile) GetContents() []byte {
+func (x *AnalysisResult) GetStatus() *AnalysisResult_Status {
 	if x != nil {
-		return x.Contents
+		return x.Status
 	}
 	return nil
 }
 
-type SourceFile struct {
+func (x *AnalysisResult) GetUnitId() string {
+	if x != nil {
+		return x.UnitId
+	}
+	return ""
+}
+
+func (x *AnalysisResult) GetInvalidation() *Invalidation {
+	if x != nil {
+		return x.Invalidation
+	}
+	return nil
+}
+
+type BuildableUnit struct {
 	state         protoimpl.MessageState
 	sizeCache     protoimpl.SizeCache
 	unknownFields protoimpl.UnknownFields
 
-	// Path to the source file relative to repository root.
-	Path string `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
-	// Working directory used by the build system. All the relative
-	// paths in compiler_arguments should be relative to this path.
-	// Relative to repository root.
-	WorkingDir string `protobuf:"bytes,2,opt,name=working_dir,json=workingDir,proto3" json:"working_dir,omitempty"`
-	// Compiler arguments to compile the source file. If multiple variants
-	// of the module being compiled are possible, the query script will choose
-	// one.
-	CompilerArguments []string `protobuf:"bytes,3,rep,name=compiler_arguments,json=compilerArguments,proto3" json:"compiler_arguments,omitempty"`
-	// Any generated files that are used in compiling the file.
-	Generated []*GeneratedFile `protobuf:"bytes,4,rep,name=generated,proto3" json:"generated,omitempty"`
-	// Paths to all of the sources, like build files, code generators,
-	// proto files etc. that were used during analysis. Used to figure
-	// out when a set of build artifacts are stale and the query tool
-	// must be re-run.
-	// Relative to repository root.
-	Deps []string `protobuf:"bytes,5,rep,name=deps,proto3" json:"deps,omitempty"`
-	// Represents analysis status for this particular file. e.g. not part
-	// of the build graph.
-	Status *Status `protobuf:"bytes,6,opt,name=status,proto3,oneof" json:"status,omitempty"`
-}
-
-func (x *SourceFile) Reset() {
-	*x = SourceFile{}
+	// Unique identifier of the buildable unit.
+	//
+	// Examples:
+	//   - Java: module or target name, e.g. "framework-bluetooth" or
+	//     "//third_party/hamcrest:hamcrest_java"
+	//   - C++: source file, e.g. "path/to/file.cc"
+	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
+	// Language of the unit.
+	// Required for buildable units directly referenced by the AnalysisResult,
+	// e.g. the unit associated with the compilation stage for the source file.
+	Language Language `protobuf:"varint,2,opt,name=language,proto3,enum=ide_query.Language" json:"language,omitempty"`
+	// Source files that are part of this unit.
+	// Path to the file relative to working_dir.
+	SourceFilePaths []string `protobuf:"bytes,3,rep,name=source_file_paths,json=sourceFilePaths,proto3" json:"source_file_paths,omitempty"`
+	// Compiler arguments to compile the source files.
+	CompilerArguments []string `protobuf:"bytes,4,rep,name=compiler_arguments,json=compilerArguments,proto3" json:"compiler_arguments,omitempty"`
+	// List of generated files produced by this unit.
+	GeneratedFiles []*GeneratedFile `protobuf:"bytes,5,rep,name=generated_files,json=generatedFiles,proto3" json:"generated_files,omitempty"`
+	// List of other BuildableUnits this unit depend on.
+	DependencyIds []string `protobuf:"bytes,6,rep,name=dependency_ids,json=dependencyIds,proto3" json:"dependency_ids,omitempty"`
+}
+
+func (x *BuildableUnit) Reset() {
+	*x = BuildableUnit{}
 	if protoimpl.UnsafeEnabled {
 		mi := &file_ide_query_proto_msgTypes[4]
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -354,13 +441,13 @@ func (x *SourceFile) Reset() {
 	}
 }
 
-func (x *SourceFile) String() string {
+func (x *BuildableUnit) String() string {
 	return protoimpl.X.MessageStringOf(x)
 }
 
-func (*SourceFile) ProtoMessage() {}
+func (*BuildableUnit) ProtoMessage() {}
 
-func (x *SourceFile) ProtoReflect() protoreflect.Message {
+func (x *BuildableUnit) ProtoReflect() protoreflect.Message {
 	mi := &file_ide_query_proto_msgTypes[4]
 	if protoimpl.UnsafeEnabled && x != nil {
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -372,70 +459,71 @@ func (x *SourceFile) ProtoReflect() protoreflect.Message {
 	return mi.MessageOf(x)
 }
 
-// Deprecated: Use SourceFile.ProtoReflect.Descriptor instead.
-func (*SourceFile) Descriptor() ([]byte, []int) {
+// Deprecated: Use BuildableUnit.ProtoReflect.Descriptor instead.
+func (*BuildableUnit) Descriptor() ([]byte, []int) {
 	return file_ide_query_proto_rawDescGZIP(), []int{4}
 }
 
-func (x *SourceFile) GetPath() string {
+func (x *BuildableUnit) GetId() string {
 	if x != nil {
-		return x.Path
+		return x.Id
 	}
 	return ""
 }
 
-func (x *SourceFile) GetWorkingDir() string {
+func (x *BuildableUnit) GetLanguage() Language {
 	if x != nil {
-		return x.WorkingDir
+		return x.Language
 	}
-	return ""
+	return Language_LANGUAGE_UNSPECIFIED
 }
 
-func (x *SourceFile) GetCompilerArguments() []string {
+func (x *BuildableUnit) GetSourceFilePaths() []string {
 	if x != nil {
-		return x.CompilerArguments
+		return x.SourceFilePaths
 	}
 	return nil
 }
 
-func (x *SourceFile) GetGenerated() []*GeneratedFile {
+func (x *BuildableUnit) GetCompilerArguments() []string {
 	if x != nil {
-		return x.Generated
+		return x.CompilerArguments
 	}
 	return nil
 }
 
-func (x *SourceFile) GetDeps() []string {
+func (x *BuildableUnit) GetGeneratedFiles() []*GeneratedFile {
 	if x != nil {
-		return x.Deps
+		return x.GeneratedFiles
 	}
 	return nil
 }
 
-func (x *SourceFile) GetStatus() *Status {
+func (x *BuildableUnit) GetDependencyIds() []string {
 	if x != nil {
-		return x.Status
+		return x.DependencyIds
 	}
 	return nil
 }
 
-type IdeAnalysis struct {
+// Invalidation rule to check if the result is still valid.
+// This should contain files/dirs that are not directly part of the build graph
+// but still affect the result. For example BUILD files, directory to the
+// toolchain or config files etc.
+type Invalidation struct {
 	state         protoimpl.MessageState
 	sizeCache     protoimpl.SizeCache
 	unknownFields protoimpl.UnknownFields
 
-	// Path relative to repository root, containing all the artifacts
-	// generated by the build system. GeneratedFile.path are always
-	// relative to this directory.
-	BuildArtifactRoot string        `protobuf:"bytes,1,opt,name=build_artifact_root,json=buildArtifactRoot,proto3" json:"build_artifact_root,omitempty"`
-	Sources           []*SourceFile `protobuf:"bytes,2,rep,name=sources,proto3" json:"sources,omitempty"`
-	// Status representing overall analysis.
-	// Should fail only when no analysis can be performed.
-	Status *Status `protobuf:"bytes,3,opt,name=status,proto3,oneof" json:"status,omitempty"`
+	// If any of these files change the result may become invalid.
+	// Path to the file relative to repository root.
+	FilePaths []string `protobuf:"bytes,1,rep,name=file_paths,json=filePaths,proto3" json:"file_paths,omitempty"`
+	// If any of these rules match a changed file the result may become invalid.
+	Wildcards []*Invalidation_Wildcard `protobuf:"bytes,4,rep,name=wildcards,proto3" json:"wildcards,omitempty"`
 }
 
-func (x *IdeAnalysis) Reset() {
-	*x = IdeAnalysis{}
+func (x *Invalidation) Reset() {
+	*x = Invalidation{}
 	if protoimpl.UnsafeEnabled {
 		mi := &file_ide_query_proto_msgTypes[5]
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -443,13 +531,13 @@ func (x *IdeAnalysis) Reset() {
 	}
 }
 
-func (x *IdeAnalysis) String() string {
+func (x *Invalidation) String() string {
 	return protoimpl.X.MessageStringOf(x)
 }
 
-func (*IdeAnalysis) ProtoMessage() {}
+func (*Invalidation) ProtoMessage() {}
 
-func (x *IdeAnalysis) ProtoReflect() protoreflect.Message {
+func (x *Invalidation) ProtoReflect() protoreflect.Message {
 	mi := &file_ide_query_proto_msgTypes[5]
 	if protoimpl.UnsafeEnabled && x != nil {
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -461,47 +549,38 @@ func (x *IdeAnalysis) ProtoReflect() protoreflect.Message {
 	return mi.MessageOf(x)
 }
 
-// Deprecated: Use IdeAnalysis.ProtoReflect.Descriptor instead.
-func (*IdeAnalysis) Descriptor() ([]byte, []int) {
+// Deprecated: Use Invalidation.ProtoReflect.Descriptor instead.
+func (*Invalidation) Descriptor() ([]byte, []int) {
 	return file_ide_query_proto_rawDescGZIP(), []int{5}
 }
 
-func (x *IdeAnalysis) GetBuildArtifactRoot() string {
+func (x *Invalidation) GetFilePaths() []string {
 	if x != nil {
-		return x.BuildArtifactRoot
-	}
-	return ""
-}
-
-func (x *IdeAnalysis) GetSources() []*SourceFile {
-	if x != nil {
-		return x.Sources
+		return x.FilePaths
 	}
 	return nil
 }
 
-func (x *IdeAnalysis) GetStatus() *Status {
+func (x *Invalidation) GetWildcards() []*Invalidation_Wildcard {
 	if x != nil {
-		return x.Status
+		return x.Wildcards
 	}
 	return nil
 }
 
-// Build dependencies of a source file for providing language services.
-type DepsResponse_Deps struct {
+// Indicates the success/failure for the query.
+type AnalysisResult_Status struct {
 	state         protoimpl.MessageState
 	sizeCache     protoimpl.SizeCache
 	unknownFields protoimpl.UnknownFields
 
-	// Relative to repo_dir.
-	SourceFile string `protobuf:"bytes,1,opt,name=source_file,json=sourceFile,proto3" json:"source_file,omitempty"`
-	// Build target to execute for generating dep.
-	BuildTarget []string `protobuf:"bytes,2,rep,name=build_target,json=buildTarget,proto3" json:"build_target,omitempty"`
-	Status      *Status  `protobuf:"bytes,3,opt,name=status,proto3,oneof" json:"status,omitempty"`
+	Code AnalysisResult_Status_Code `protobuf:"varint,1,opt,name=code,proto3,enum=ide_query.AnalysisResult_Status_Code" json:"code,omitempty"`
+	// Details about the status, might be displayed to user.
+	StatusMessage *string `protobuf:"bytes,2,opt,name=status_message,json=statusMessage,proto3,oneof" json:"status_message,omitempty"`
 }
 
-func (x *DepsResponse_Deps) Reset() {
-	*x = DepsResponse_Deps{}
+func (x *AnalysisResult_Status) Reset() {
+	*x = AnalysisResult_Status{}
 	if protoimpl.UnsafeEnabled {
 		mi := &file_ide_query_proto_msgTypes[6]
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -509,13 +588,13 @@ func (x *DepsResponse_Deps) Reset() {
 	}
 }
 
-func (x *DepsResponse_Deps) String() string {
+func (x *AnalysisResult_Status) String() string {
 	return protoimpl.X.MessageStringOf(x)
 }
 
-func (*DepsResponse_Deps) ProtoMessage() {}
+func (*AnalysisResult_Status) ProtoMessage() {}
 
-func (x *DepsResponse_Deps) ProtoReflect() protoreflect.Message {
+func (x *AnalysisResult_Status) ProtoReflect() protoreflect.Message {
 	mi := &file_ide_query_proto_msgTypes[6]
 	if protoimpl.UnsafeEnabled && x != nil {
 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
@@ -527,104 +606,190 @@ func (x *DepsResponse_Deps) ProtoReflect() protoreflect.Message {
 	return mi.MessageOf(x)
 }
 
-// Deprecated: Use DepsResponse_Deps.ProtoReflect.Descriptor instead.
-func (*DepsResponse_Deps) Descriptor() ([]byte, []int) {
-	return file_ide_query_proto_rawDescGZIP(), []int{2, 0}
+// Deprecated: Use AnalysisResult_Status.ProtoReflect.Descriptor instead.
+func (*AnalysisResult_Status) Descriptor() ([]byte, []int) {
+	return file_ide_query_proto_rawDescGZIP(), []int{3, 0}
 }
 
-func (x *DepsResponse_Deps) GetSourceFile() string {
+func (x *AnalysisResult_Status) GetCode() AnalysisResult_Status_Code {
 	if x != nil {
-		return x.SourceFile
+		return x.Code
+	}
+	return AnalysisResult_Status_CODE_UNSPECIFIED
+}
+
+func (x *AnalysisResult_Status) GetStatusMessage() string {
+	if x != nil && x.StatusMessage != nil {
+		return *x.StatusMessage
 	}
 	return ""
 }
 
-func (x *DepsResponse_Deps) GetBuildTarget() []string {
-	if x != nil {
-		return x.BuildTarget
+type Invalidation_Wildcard struct {
+	state         protoimpl.MessageState
+	sizeCache     protoimpl.SizeCache
+	unknownFields protoimpl.UnknownFields
+
+	// Prefix of the file path (e.g. "path/to/")
+	Prefix *string `protobuf:"bytes,1,opt,name=prefix,proto3,oneof" json:"prefix,omitempty"`
+	// Suffix of the file path (e.g. "Android.bp")
+	Suffix *string `protobuf:"bytes,2,opt,name=suffix,proto3,oneof" json:"suffix,omitempty"`
+	// If false, the part of the path between the given `prefix` and `suffix`
+	// should not contain directory separators ('/').
+	CanCrossFolder *bool `protobuf:"varint,3,opt,name=can_cross_folder,json=canCrossFolder,proto3,oneof" json:"can_cross_folder,omitempty"`
+}
+
+func (x *Invalidation_Wildcard) Reset() {
+	*x = Invalidation_Wildcard{}
+	if protoimpl.UnsafeEnabled {
+		mi := &file_ide_query_proto_msgTypes[7]
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		ms.StoreMessageInfo(mi)
 	}
-	return nil
 }
 
-func (x *DepsResponse_Deps) GetStatus() *Status {
-	if x != nil {
-		return x.Status
+func (x *Invalidation_Wildcard) String() string {
+	return protoimpl.X.MessageStringOf(x)
+}
+
+func (*Invalidation_Wildcard) ProtoMessage() {}
+
+func (x *Invalidation_Wildcard) ProtoReflect() protoreflect.Message {
+	mi := &file_ide_query_proto_msgTypes[7]
+	if protoimpl.UnsafeEnabled && x != nil {
+		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
+		if ms.LoadMessageInfo() == nil {
+			ms.StoreMessageInfo(mi)
+		}
+		return ms
 	}
-	return nil
+	return mi.MessageOf(x)
+}
+
+// Deprecated: Use Invalidation_Wildcard.ProtoReflect.Descriptor instead.
+func (*Invalidation_Wildcard) Descriptor() ([]byte, []int) {
+	return file_ide_query_proto_rawDescGZIP(), []int{5, 0}
+}
+
+func (x *Invalidation_Wildcard) GetPrefix() string {
+	if x != nil && x.Prefix != nil {
+		return *x.Prefix
+	}
+	return ""
+}
+
+func (x *Invalidation_Wildcard) GetSuffix() string {
+	if x != nil && x.Suffix != nil {
+		return *x.Suffix
+	}
+	return ""
+}
+
+func (x *Invalidation_Wildcard) GetCanCrossFolder() bool {
+	if x != nil && x.CanCrossFolder != nil {
+		return *x.CanCrossFolder
+	}
+	return false
 }
 
 var File_ide_query_proto protoreflect.FileDescriptor
 
 var file_ide_query_proto_rawDesc = []byte{
 	0x0a, 0x0f, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74,
-	0x6f, 0x12, 0x09, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x22, 0x7c, 0x0a, 0x06,
-	0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x2a, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01,
-	0x20, 0x01, 0x28, 0x0e, 0x32, 0x16, 0x2e, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79,
-	0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x43, 0x6f, 0x64, 0x65, 0x52, 0x04, 0x63, 0x6f,
-	0x64, 0x65, 0x12, 0x1d, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20,
-	0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x88, 0x01,
-	0x01, 0x22, 0x1b, 0x0a, 0x04, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x06, 0x0a, 0x02, 0x4f, 0x4b, 0x10,
-	0x00, 0x12, 0x0b, 0x0a, 0x07, 0x46, 0x41, 0x49, 0x4c, 0x55, 0x52, 0x45, 0x10, 0x01, 0x42, 0x0a,
-	0x0a, 0x08, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0x8b, 0x01, 0x0a, 0x09, 0x52,
-	0x65, 0x70, 0x6f, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x72, 0x65, 0x70, 0x6f,
-	0x5f, 0x64, 0x69, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x72, 0x65, 0x70, 0x6f,
-	0x44, 0x69, 0x72, 0x12, 0x28, 0x0a, 0x10, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x66, 0x69,
-	0x6c, 0x65, 0x5f, 0x70, 0x61, 0x74, 0x68, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0e, 0x61,
-	0x63, 0x74, 0x69, 0x76, 0x65, 0x46, 0x69, 0x6c, 0x65, 0x50, 0x61, 0x74, 0x68, 0x12, 0x17, 0x0a,
-	0x07, 0x6f, 0x75, 0x74, 0x5f, 0x64, 0x69, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
-	0x6f, 0x75, 0x74, 0x44, 0x69, 0x72, 0x12, 0x20, 0x0a, 0x0c, 0x63, 0x6f, 0x6d, 0x70, 0x5f, 0x64,
-	0x62, 0x5f, 0x70, 0x61, 0x74, 0x68, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x6f,
-	0x6d, 0x70, 0x44, 0x62, 0x50, 0x61, 0x74, 0x68, 0x22, 0x83, 0x02, 0x0a, 0x0c, 0x44, 0x65, 0x70,
-	0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x30, 0x0a, 0x04, 0x64, 0x65, 0x70,
-	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75,
-	0x65, 0x72, 0x79, 0x2e, 0x44, 0x65, 0x70, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
-	0x2e, 0x44, 0x65, 0x70, 0x73, 0x52, 0x04, 0x64, 0x65, 0x70, 0x73, 0x12, 0x2e, 0x0a, 0x06, 0x73,
-	0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x69, 0x64,
-	0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x48, 0x00,
-	0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x88, 0x01, 0x01, 0x1a, 0x85, 0x01, 0x0a, 0x04,
-	0x44, 0x65, 0x70, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x66,
-	0x69, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x73, 0x6f, 0x75, 0x72, 0x63,
-	0x65, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x5f, 0x74,
-	0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x62, 0x75, 0x69,
-	0x6c, 0x64, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12, 0x2e, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74,
-	0x75, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x69, 0x64, 0x65, 0x5f, 0x71,
-	0x75, 0x65, 0x72, 0x79, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x48, 0x00, 0x52, 0x06, 0x73,
-	0x74, 0x61, 0x74, 0x75, 0x73, 0x88, 0x01, 0x01, 0x42, 0x09, 0x0a, 0x07, 0x5f, 0x73, 0x74, 0x61,
-	0x74, 0x75, 0x73, 0x42, 0x09, 0x0a, 0x07, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x51,
-	0x0a, 0x0d, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x46, 0x69, 0x6c, 0x65, 0x12,
-	0x12, 0x0a, 0x04, 0x70, 0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70,
-	0x61, 0x74, 0x68, 0x12, 0x1f, 0x0a, 0x08, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x18,
-	0x02, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x08, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
-	0x73, 0x88, 0x01, 0x01, 0x42, 0x0b, 0x0a, 0x09, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
-	0x73, 0x22, 0xf7, 0x01, 0x0a, 0x0a, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x46, 0x69, 0x6c, 0x65,
-	0x12, 0x12, 0x0a, 0x04, 0x70, 0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
-	0x70, 0x61, 0x74, 0x68, 0x12, 0x1f, 0x0a, 0x0b, 0x77, 0x6f, 0x72, 0x6b, 0x69, 0x6e, 0x67, 0x5f,
-	0x64, 0x69, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x77, 0x6f, 0x72, 0x6b, 0x69,
-	0x6e, 0x67, 0x44, 0x69, 0x72, 0x12, 0x2d, 0x0a, 0x12, 0x63, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65,
-	0x72, 0x5f, 0x61, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28,
-	0x09, 0x52, 0x11, 0x63, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x72, 0x41, 0x72, 0x67, 0x75, 0x6d,
-	0x65, 0x6e, 0x74, 0x73, 0x12, 0x36, 0x0a, 0x09, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65,
-	0x64, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75,
-	0x65, 0x72, 0x79, 0x2e, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x46, 0x69, 0x6c,
-	0x65, 0x52, 0x09, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x12, 0x12, 0x0a, 0x04,
-	0x64, 0x65, 0x70, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x04, 0x64, 0x65, 0x70, 0x73,
-	0x12, 0x2e, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b,
-	0x32, 0x11, 0x2e, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x53, 0x74, 0x61,
-	0x74, 0x75, 0x73, 0x48, 0x00, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x88, 0x01, 0x01,
-	0x42, 0x09, 0x0a, 0x07, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0xa9, 0x01, 0x0a, 0x0b,
-	0x49, 0x64, 0x65, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x73, 0x69, 0x73, 0x12, 0x2e, 0x0a, 0x13, 0x62,
-	0x75, 0x69, 0x6c, 0x64, 0x5f, 0x61, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x5f, 0x72, 0x6f,
-	0x6f, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x41,
-	0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x52, 0x6f, 0x6f, 0x74, 0x12, 0x2f, 0x0a, 0x07, 0x73,
-	0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x69,
-	0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x46,
-	0x69, 0x6c, 0x65, 0x52, 0x07, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x12, 0x2e, 0x0a, 0x06,
-	0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x69,
-	0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x48,
-	0x00, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x88, 0x01, 0x01, 0x42, 0x09, 0x0a, 0x07,
-	0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x42, 0x1b, 0x5a, 0x19, 0x69, 0x64, 0x65, 0x5f, 0x71,
-	0x75, 0x65, 0x72, 0x79, 0x2f, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x5f, 0x70,
-	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
+	0x6f, 0x12, 0x09, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x22, 0x51, 0x0a, 0x0d,
+	0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x12, 0x0a,
+	0x04, 0x70, 0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x61, 0x74,
+	0x68, 0x12, 0x1f, 0x0a, 0x08, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x02, 0x20,
+	0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x08, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x88,
+	0x01, 0x01, 0x42, 0x0b, 0x0a, 0x09, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x22,
+	0x82, 0x02, 0x0a, 0x0b, 0x49, 0x64, 0x65, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x73, 0x69, 0x73, 0x12,
+	0x22, 0x0a, 0x0d, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x5f, 0x6f, 0x75, 0x74, 0x5f, 0x64, 0x69, 0x72,
+	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x4f, 0x75, 0x74,
+	0x44, 0x69, 0x72, 0x12, 0x1f, 0x0a, 0x0b, 0x77, 0x6f, 0x72, 0x6b, 0x69, 0x6e, 0x67, 0x5f, 0x64,
+	0x69, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x77, 0x6f, 0x72, 0x6b, 0x69, 0x6e,
+	0x67, 0x44, 0x69, 0x72, 0x12, 0x33, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x05, 0x20,
+	0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e,
+	0x41, 0x6e, 0x61, 0x6c, 0x79, 0x73, 0x69, 0x73, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x48, 0x00, 0x52,
+	0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x88, 0x01, 0x01, 0x12, 0x33, 0x0a, 0x07, 0x72, 0x65, 0x73,
+	0x75, 0x6c, 0x74, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x69, 0x64, 0x65,
+	0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x73, 0x69, 0x73, 0x52,
+	0x65, 0x73, 0x75, 0x6c, 0x74, 0x52, 0x07, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x73, 0x12, 0x2e,
+	0x0a, 0x05, 0x75, 0x6e, 0x69, 0x74, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e,
+	0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x61,
+	0x62, 0x6c, 0x65, 0x55, 0x6e, 0x69, 0x74, 0x52, 0x05, 0x75, 0x6e, 0x69, 0x74, 0x73, 0x42, 0x08,
+	0x0a, 0x06, 0x5f, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x4a, 0x04, 0x08, 0x02, 0x10, 0x03, 0x4a, 0x04,
+	0x08, 0x03, 0x10, 0x04, 0x22, 0x34, 0x0a, 0x0d, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x73, 0x69, 0x73,
+	0x45, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x23, 0x0a, 0x0d, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x5f, 0x6d,
+	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x65, 0x72,
+	0x72, 0x6f, 0x72, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0xa5, 0x03, 0x0a, 0x0e, 0x41,
+	0x6e, 0x61, 0x6c, 0x79, 0x73, 0x69, 0x73, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12, 0x28, 0x0a,
+	0x10, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x70, 0x61, 0x74,
+	0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x46,
+	0x69, 0x6c, 0x65, 0x50, 0x61, 0x74, 0x68, 0x12, 0x38, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,
+	0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75,
+	0x65, 0x72, 0x79, 0x2e, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x73, 0x69, 0x73, 0x52, 0x65, 0x73, 0x75,
+	0x6c, 0x74, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,
+	0x73, 0x12, 0x17, 0x0a, 0x07, 0x75, 0x6e, 0x69, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01,
+	0x28, 0x09, 0x52, 0x06, 0x75, 0x6e, 0x69, 0x74, 0x49, 0x64, 0x12, 0x3b, 0x0a, 0x0c, 0x69, 0x6e,
+	0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b,
+	0x32, 0x17, 0x2e, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x49, 0x6e, 0x76,
+	0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0c, 0x69, 0x6e, 0x76, 0x61, 0x6c,
+	0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0xd8, 0x01, 0x0a, 0x06, 0x53, 0x74, 0x61, 0x74,
+	0x75, 0x73, 0x12, 0x39, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e,
+	0x32, 0x25, 0x2e, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x41, 0x6e, 0x61,
+	0x6c, 0x79, 0x73, 0x69, 0x73, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x2e, 0x53, 0x74, 0x61, 0x74,
+	0x75, 0x73, 0x2e, 0x43, 0x6f, 0x64, 0x65, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x2a, 0x0a,
+	0x0e, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18,
+	0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x0d, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x4d,
+	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x88, 0x01, 0x01, 0x22, 0x54, 0x0a, 0x04, 0x43, 0x6f, 0x64,
+	0x65, 0x12, 0x14, 0x0a, 0x10, 0x43, 0x4f, 0x44, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43,
+	0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x43, 0x4f, 0x44, 0x45, 0x5f,
+	0x4f, 0x4b, 0x10, 0x01, 0x12, 0x12, 0x0a, 0x0e, 0x43, 0x4f, 0x44, 0x45, 0x5f, 0x4e, 0x4f, 0x54,
+	0x5f, 0x46, 0x4f, 0x55, 0x4e, 0x44, 0x10, 0x02, 0x12, 0x15, 0x0a, 0x11, 0x43, 0x4f, 0x44, 0x45,
+	0x5f, 0x42, 0x55, 0x49, 0x4c, 0x44, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x45, 0x44, 0x10, 0x03, 0x42,
+	0x11, 0x0a, 0x0f, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61,
+	0x67, 0x65, 0x22, 0x95, 0x02, 0x0a, 0x0d, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x61, 0x62, 0x6c, 0x65,
+	0x55, 0x6e, 0x69, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
+	0x52, 0x02, 0x69, 0x64, 0x12, 0x2f, 0x0a, 0x08, 0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65,
+	0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x13, 0x2e, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65,
+	0x72, 0x79, 0x2e, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x52, 0x08, 0x6c, 0x61, 0x6e,
+	0x67, 0x75, 0x61, 0x67, 0x65, 0x12, 0x2a, 0x0a, 0x11, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f,
+	0x66, 0x69, 0x6c, 0x65, 0x5f, 0x70, 0x61, 0x74, 0x68, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09,
+	0x52, 0x0f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x46, 0x69, 0x6c, 0x65, 0x50, 0x61, 0x74, 0x68,
+	0x73, 0x12, 0x2d, 0x0a, 0x12, 0x63, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x72, 0x5f, 0x61, 0x72,
+	0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x52, 0x11, 0x63,
+	0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x72, 0x41, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73,
+	0x12, 0x41, 0x0a, 0x0f, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x66, 0x69,
+	0x6c, 0x65, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x69, 0x64, 0x65, 0x5f,
+	0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x46,
+	0x69, 0x6c, 0x65, 0x52, 0x0e, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x46, 0x69,
+	0x6c, 0x65, 0x73, 0x12, 0x25, 0x0a, 0x0e, 0x64, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63,
+	0x79, 0x5f, 0x69, 0x64, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0d, 0x64, 0x65, 0x70,
+	0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x79, 0x49, 0x64, 0x73, 0x22, 0x8e, 0x02, 0x0a, 0x0c, 0x49,
+	0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1d, 0x0a, 0x0a, 0x66,
+	0x69, 0x6c, 0x65, 0x5f, 0x70, 0x61, 0x74, 0x68, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52,
+	0x09, 0x66, 0x69, 0x6c, 0x65, 0x50, 0x61, 0x74, 0x68, 0x73, 0x12, 0x3e, 0x0a, 0x09, 0x77, 0x69,
+	0x6c, 0x64, 0x63, 0x61, 0x72, 0x64, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e,
+	0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x2e, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69,
+	0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x57, 0x69, 0x6c, 0x64, 0x63, 0x61, 0x72, 0x64, 0x52,
+	0x09, 0x77, 0x69, 0x6c, 0x64, 0x63, 0x61, 0x72, 0x64, 0x73, 0x1a, 0x9e, 0x01, 0x0a, 0x08, 0x57,
+	0x69, 0x6c, 0x64, 0x63, 0x61, 0x72, 0x64, 0x12, 0x1b, 0x0a, 0x06, 0x70, 0x72, 0x65, 0x66, 0x69,
+	0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x06, 0x70, 0x72, 0x65, 0x66, 0x69,
+	0x78, 0x88, 0x01, 0x01, 0x12, 0x1b, 0x0a, 0x06, 0x73, 0x75, 0x66, 0x66, 0x69, 0x78, 0x18, 0x02,
+	0x20, 0x01, 0x28, 0x09, 0x48, 0x01, 0x52, 0x06, 0x73, 0x75, 0x66, 0x66, 0x69, 0x78, 0x88, 0x01,
+	0x01, 0x12, 0x2d, 0x0a, 0x10, 0x63, 0x61, 0x6e, 0x5f, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x5f, 0x66,
+	0x6f, 0x6c, 0x64, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x48, 0x02, 0x52, 0x0e, 0x63,
+	0x61, 0x6e, 0x43, 0x72, 0x6f, 0x73, 0x73, 0x46, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x88, 0x01, 0x01,
+	0x42, 0x09, 0x0a, 0x07, 0x5f, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x42, 0x09, 0x0a, 0x07, 0x5f,
+	0x73, 0x75, 0x66, 0x66, 0x69, 0x78, 0x42, 0x13, 0x0a, 0x11, 0x5f, 0x63, 0x61, 0x6e, 0x5f, 0x63,
+	0x72, 0x6f, 0x73, 0x73, 0x5f, 0x66, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x2a, 0x49, 0x0a, 0x08, 0x4c,
+	0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x12, 0x18, 0x0a, 0x14, 0x4c, 0x41, 0x4e, 0x47, 0x55,
+	0x41, 0x47, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10,
+	0x00, 0x12, 0x11, 0x0a, 0x0d, 0x4c, 0x41, 0x4e, 0x47, 0x55, 0x41, 0x47, 0x45, 0x5f, 0x4a, 0x41,
+	0x56, 0x41, 0x10, 0x01, 0x12, 0x10, 0x0a, 0x0c, 0x4c, 0x41, 0x4e, 0x47, 0x55, 0x41, 0x47, 0x45,
+	0x5f, 0x43, 0x50, 0x50, 0x10, 0x02, 0x42, 0x1b, 0x5a, 0x19, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75,
+	0x65, 0x72, 0x79, 0x2f, 0x69, 0x64, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x72, 0x79, 0x5f, 0x70, 0x72,
+	0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
 }
 
 var (
@@ -639,32 +804,35 @@ func file_ide_query_proto_rawDescGZIP() []byte {
 	return file_ide_query_proto_rawDescData
 }
 
-var file_ide_query_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
-var file_ide_query_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
+var file_ide_query_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
+var file_ide_query_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
 var file_ide_query_proto_goTypes = []interface{}{
-	(Status_Code)(0),          // 0: ide_query.Status.Code
-	(*Status)(nil),            // 1: ide_query.Status
-	(*RepoState)(nil),         // 2: ide_query.RepoState
-	(*DepsResponse)(nil),      // 3: ide_query.DepsResponse
-	(*GeneratedFile)(nil),     // 4: ide_query.GeneratedFile
-	(*SourceFile)(nil),        // 5: ide_query.SourceFile
-	(*IdeAnalysis)(nil),       // 6: ide_query.IdeAnalysis
-	(*DepsResponse_Deps)(nil), // 7: ide_query.DepsResponse.Deps
+	(Language)(0),                   // 0: ide_query.Language
+	(AnalysisResult_Status_Code)(0), // 1: ide_query.AnalysisResult.Status.Code
+	(*GeneratedFile)(nil),           // 2: ide_query.GeneratedFile
+	(*IdeAnalysis)(nil),             // 3: ide_query.IdeAnalysis
+	(*AnalysisError)(nil),           // 4: ide_query.AnalysisError
+	(*AnalysisResult)(nil),          // 5: ide_query.AnalysisResult
+	(*BuildableUnit)(nil),           // 6: ide_query.BuildableUnit
+	(*Invalidation)(nil),            // 7: ide_query.Invalidation
+	(*AnalysisResult_Status)(nil),   // 8: ide_query.AnalysisResult.Status
+	(*Invalidation_Wildcard)(nil),   // 9: ide_query.Invalidation.Wildcard
 }
 var file_ide_query_proto_depIdxs = []int32{
-	0, // 0: ide_query.Status.code:type_name -> ide_query.Status.Code
-	7, // 1: ide_query.DepsResponse.deps:type_name -> ide_query.DepsResponse.Deps
-	1, // 2: ide_query.DepsResponse.status:type_name -> ide_query.Status
-	4, // 3: ide_query.SourceFile.generated:type_name -> ide_query.GeneratedFile
-	1, // 4: ide_query.SourceFile.status:type_name -> ide_query.Status
-	5, // 5: ide_query.IdeAnalysis.sources:type_name -> ide_query.SourceFile
-	1, // 6: ide_query.IdeAnalysis.status:type_name -> ide_query.Status
-	1, // 7: ide_query.DepsResponse.Deps.status:type_name -> ide_query.Status
-	8, // [8:8] is the sub-list for method output_type
-	8, // [8:8] is the sub-list for method input_type
-	8, // [8:8] is the sub-list for extension type_name
-	8, // [8:8] is the sub-list for extension extendee
-	0, // [0:8] is the sub-list for field type_name
+	4, // 0: ide_query.IdeAnalysis.error:type_name -> ide_query.AnalysisError
+	5, // 1: ide_query.IdeAnalysis.results:type_name -> ide_query.AnalysisResult
+	6, // 2: ide_query.IdeAnalysis.units:type_name -> ide_query.BuildableUnit
+	8, // 3: ide_query.AnalysisResult.status:type_name -> ide_query.AnalysisResult.Status
+	7, // 4: ide_query.AnalysisResult.invalidation:type_name -> ide_query.Invalidation
+	0, // 5: ide_query.BuildableUnit.language:type_name -> ide_query.Language
+	2, // 6: ide_query.BuildableUnit.generated_files:type_name -> ide_query.GeneratedFile
+	9, // 7: ide_query.Invalidation.wildcards:type_name -> ide_query.Invalidation.Wildcard
+	1, // 8: ide_query.AnalysisResult.Status.code:type_name -> ide_query.AnalysisResult.Status.Code
+	9, // [9:9] is the sub-list for method output_type
+	9, // [9:9] is the sub-list for method input_type
+	9, // [9:9] is the sub-list for extension type_name
+	9, // [9:9] is the sub-list for extension extendee
+	0, // [0:9] is the sub-list for field type_name
 }
 
 func init() { file_ide_query_proto_init() }
@@ -674,7 +842,7 @@ func file_ide_query_proto_init() {
 	}
 	if !protoimpl.UnsafeEnabled {
 		file_ide_query_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
-			switch v := v.(*Status); i {
+			switch v := v.(*GeneratedFile); i {
 			case 0:
 				return &v.state
 			case 1:
@@ -686,7 +854,7 @@ func file_ide_query_proto_init() {
 			}
 		}
 		file_ide_query_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
-			switch v := v.(*RepoState); i {
+			switch v := v.(*IdeAnalysis); i {
 			case 0:
 				return &v.state
 			case 1:
@@ -698,7 +866,7 @@ func file_ide_query_proto_init() {
 			}
 		}
 		file_ide_query_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
-			switch v := v.(*DepsResponse); i {
+			switch v := v.(*AnalysisError); i {
 			case 0:
 				return &v.state
 			case 1:
@@ -710,7 +878,7 @@ func file_ide_query_proto_init() {
 			}
 		}
 		file_ide_query_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
-			switch v := v.(*GeneratedFile); i {
+			switch v := v.(*AnalysisResult); i {
 			case 0:
 				return &v.state
 			case 1:
@@ -722,7 +890,7 @@ func file_ide_query_proto_init() {
 			}
 		}
 		file_ide_query_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
-			switch v := v.(*SourceFile); i {
+			switch v := v.(*BuildableUnit); i {
 			case 0:
 				return &v.state
 			case 1:
@@ -734,7 +902,7 @@ func file_ide_query_proto_init() {
 			}
 		}
 		file_ide_query_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
-			switch v := v.(*IdeAnalysis); i {
+			switch v := v.(*Invalidation); i {
 			case 0:
 				return &v.state
 			case 1:
@@ -746,7 +914,19 @@ func file_ide_query_proto_init() {
 			}
 		}
 		file_ide_query_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
-			switch v := v.(*DepsResponse_Deps); i {
+			switch v := v.(*AnalysisResult_Status); i {
+			case 0:
+				return &v.state
+			case 1:
+				return &v.sizeCache
+			case 2:
+				return &v.unknownFields
+			default:
+				return nil
+			}
+		}
+		file_ide_query_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
+			switch v := v.(*Invalidation_Wildcard); i {
 			case 0:
 				return &v.state
 			case 1:
@@ -759,18 +939,16 @@ func file_ide_query_proto_init() {
 		}
 	}
 	file_ide_query_proto_msgTypes[0].OneofWrappers = []interface{}{}
-	file_ide_query_proto_msgTypes[2].OneofWrappers = []interface{}{}
-	file_ide_query_proto_msgTypes[3].OneofWrappers = []interface{}{}
-	file_ide_query_proto_msgTypes[4].OneofWrappers = []interface{}{}
-	file_ide_query_proto_msgTypes[5].OneofWrappers = []interface{}{}
+	file_ide_query_proto_msgTypes[1].OneofWrappers = []interface{}{}
 	file_ide_query_proto_msgTypes[6].OneofWrappers = []interface{}{}
+	file_ide_query_proto_msgTypes[7].OneofWrappers = []interface{}{}
 	type x struct{}
 	out := protoimpl.TypeBuilder{
 		File: protoimpl.DescBuilder{
 			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
 			RawDescriptor: file_ide_query_proto_rawDesc,
-			NumEnums:      1,
-			NumMessages:   7,
+			NumEnums:      2,
+			NumMessages:   8,
 			NumExtensions: 0,
 			NumServices:   0,
 		},
diff --git a/tools/ide_query/ide_query_proto/ide_query.proto b/tools/ide_query/ide_query_proto/ide_query.proto
index 3d7a8e760a..13f349ca80 100644
--- a/tools/ide_query/ide_query_proto/ide_query.proto
+++ b/tools/ide_query/ide_query_proto/ide_query.proto
@@ -16,51 +16,11 @@
 syntax = "proto3";
 
 package ide_query;
-option go_package = "ide_query/ide_query_proto";
-
-// Indicates the success/failure for analysis.
-message Status {
-  enum Code {
-    OK = 0;
-    FAILURE = 1;
-  }
-  Code code = 1;
-  // Details about the status, might be displayed to user.
-  optional string message = 2;
-}
-
-// Represents an Android checkout on user's workstation.
-message RepoState {
-  // Absolute path for the checkout in the workstation.
-  // e.g. /home/user/work/android/
-  string repo_dir = 1;
-  // Relative to repo_dir.
-  repeated string active_file_path = 2;
-  // Repository relative path to output directory in workstation.
-  string out_dir = 3;
-  // Repository relative path to compile_commands.json in workstation.
-  string comp_db_path = 4;
-}
 
-// Provides all the targets that are pre-requisities for running language
-// services on active_file_paths.
-message DepsResponse {
-  // Build dependencies of a source file for providing language services.
-  message Deps {
-    // Relative to repo_dir.
-    string source_file = 1;
-    // Build target to execute for generating dep.
-    repeated string build_target = 2;
-    optional Status status = 3;
-  }
-  repeated Deps deps = 1;
-  optional Status status = 2;
-}
+option go_package = "ide_query/ide_query_proto";
 
-// Returns all the information necessary for providing language services for the
-// active files.
 message GeneratedFile {
-  // Path to the file relative to IdeAnalysis.build_artifact_root.
+  // Path to the file relative to build_out_dir.
   string path = 1;
 
   // The text of the generated file, if not provided contents will be read
@@ -68,44 +28,100 @@ message GeneratedFile {
   optional bytes contents = 2;
 }
 
-message SourceFile {
-  // Path to the source file relative to repository root.
-  string path = 1;
-
-  // Working directory used by the build system. All the relative
-  // paths in compiler_arguments should be relative to this path.
+message IdeAnalysis {
+  // Directory that contains build outputs generated by the build system.
+  // Relative to repository root.
+  string build_out_dir = 1;
+  // Working directory used by the build system.
   // Relative to repository root.
-  string working_dir = 2;
+  string working_dir = 4;
+  // Only set if the whole query failed.
+  optional AnalysisError error = 5;
+  // List of results, one per queried file.
+  repeated AnalysisResult results = 6;
+  // List of buildable units directly or indirectly references by the results.
+  repeated BuildableUnit units = 7;
 
-  // Compiler arguments to compile the source file. If multiple variants
-  // of the module being compiled are possible, the query script will choose
-  // one.
-  repeated string compiler_arguments = 3;
+  reserved 2, 3;
+}
 
-  // Any generated files that are used in compiling the file.
-  repeated GeneratedFile generated = 4;
+message AnalysisError {
+  // Human readable error message.
+  string error_message = 1;
+}
 
-  // Paths to all of the sources, like build files, code generators,
-  // proto files etc. that were used during analysis. Used to figure
-  // out when a set of build artifacts are stale and the query tool
-  // must be re-run.
-  // Relative to repository root.
-  repeated string deps = 5;
+message AnalysisResult {
+  // Path to the source file that was queried, relative to repository root.
+  string source_file_path = 1;
+  // Indicates the success/failure for the query.
+  message Status {
+    enum Code {
+      CODE_UNSPECIFIED = 0;
+      CODE_OK = 1;
+      CODE_NOT_FOUND = 2;  // no target or module found for the source file.
+      CODE_BUILD_FAILED = 3;
+    }
+    Code code = 1;
+    // Details about the status, might be displayed to user.
+    optional string status_message = 2;
+  }
+  // Represents status for this result. e.g. not part of the build graph.
+  Status status = 2;
+  // ID of buildable unit that contains the source file.
+  // The ide_query script can choose the most relevant unit from multiple
+  // options.
+  string unit_id = 3;
+  // Invalidation rule to check if the result is still valid.
+  Invalidation invalidation = 4;
+}
 
-  // Represents analysis status for this particular file. e.g. not part
-  // of the build graph.
-  optional Status status = 6;
+enum Language {
+  LANGUAGE_UNSPECIFIED = 0;
+  LANGUAGE_JAVA = 1;  // also includes Kotlin
+  LANGUAGE_CPP = 2;
 }
 
-message IdeAnalysis {
-  // Path relative to repository root, containing all the artifacts
-  // generated by the build system. GeneratedFile.path are always
-  // relative to this directory.
-  string build_artifact_root = 1;
+message BuildableUnit {
+  // Unique identifier of the buildable unit.
+  //
+  // Examples:
+  //   - Java: module or target name, e.g. "framework-bluetooth" or
+  //   "//third_party/hamcrest:hamcrest_java"
+  //   - C++: source file, e.g. "path/to/file.cc"
+  string id = 1;
+  // Language of the unit.
+  // Required for buildable units directly referenced by the AnalysisResult,
+  // e.g. the unit associated with the compilation stage for the source file.
+  Language language = 2;
+  // Source files that are part of this unit.
+  // Path to the file relative to working_dir.
+  repeated string source_file_paths = 3;
+  // Compiler arguments to compile the source files.
+  repeated string compiler_arguments = 4;
+  // List of generated files produced by this unit.
+  repeated GeneratedFile generated_files = 5;
+  // List of other BuildableUnits this unit depend on.
+  repeated string dependency_ids = 6;
+}
 
-  repeated SourceFile sources = 2;
+// Invalidation rule to check if the result is still valid.
+// This should contain files/dirs that are not directly part of the build graph
+// but still affect the result. For example BUILD files, directory to the
+// toolchain or config files etc.
+message Invalidation {
+  // If any of these files change the result may become invalid.
+  // Path to the file relative to repository root.
+  repeated string file_paths = 1;
 
-  // Status representing overall analysis.
-  // Should fail only when no analysis can be performed.
-  optional Status status = 3;
-}
+  message Wildcard {
+    // Prefix of the file path (e.g. "path/to/")
+    optional string prefix = 1;
+    // Suffix of the file path (e.g. "Android.bp")
+    optional string suffix = 2;
+    // If false, the part of the path between the given `prefix` and `suffix`
+    // should not contain directory separators ('/').
+    optional bool can_cross_folder = 3;
+  }
+  // If any of these rules match a changed file the result may become invalid.
+  repeated Wildcard wildcards = 4;
+}
\ No newline at end of file
diff --git a/tools/ide_query/prober_scripts/cpp/Android.bp b/tools/ide_query/prober_scripts/cpp/Android.bp
new file mode 100644
index 0000000000..5190210924
--- /dev/null
+++ b/tools/ide_query/prober_scripts/cpp/Android.bp
@@ -0,0 +1,31 @@
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_binary {
+    name: "ide_query_proberscript_cc",
+    srcs: [
+        "general.cc",
+        "foo.proto",
+    ],
+    cflags: ["-Wno-unused-parameter"],
+    proto: {
+        type: "lite",
+    },
+}
diff --git a/tools/ide_query/prober_scripts/cpp/foo.proto b/tools/ide_query/prober_scripts/cpp/foo.proto
new file mode 100644
index 0000000000..5a851474e1
--- /dev/null
+++ b/tools/ide_query/prober_scripts/cpp/foo.proto
@@ -0,0 +1,25 @@
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
+syntax = "proto3";
+
+package ide_query.prober_scripts;
+
+message ProtoMsg {
+  // Test proto field.
+  int64 some_field = 1;
+  //                   ^ some_field
+}
diff --git a/tools/ide_query/prober_scripts/cpp/general.cc b/tools/ide_query/prober_scripts/cpp/general.cc
new file mode 100644
index 0000000000..0f0639be5e
--- /dev/null
+++ b/tools/ide_query/prober_scripts/cpp/general.cc
@@ -0,0 +1,119 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include <vector>
+
+#include "foo.pb.h"
+
+using ide_query::prober_scripts::ProtoMsg;
+
+void Foo(int x, double y) {}
+float Foo(float x, float y) { return 0.0f; }
+
+void TestCompletion() {
+  // Test completion on protos and fuzzy matching of completion suggestions.
+
+  ProtoMsg foo;
+
+  // ^
+
+  // step
+  // workspace.waitForReady()
+  // type("f")
+  // completion.trigger()
+  // assert completion.items.filter(label="foo")
+  // delline()
+  // type("foo.sf")
+  // completion.trigger()
+  // assert completion.items.filter(
+  //  label="some_field.*",
+  //  insertText="some_field.*",
+  // )
+  // delline()
+
+  std::vector<int> v;
+
+  // ^
+
+  // step
+  // workspace.waitForReady()
+  // type("v.push")
+  // completion.trigger()
+  // assert completion.items.filter(label="push_back.*")
+  // delline()
+}
+
+void TestNavigation() {
+  std::vector<int> ints;
+  //               |   | ints
+  //      ^
+
+  // step
+  // ; Test navigation to definition on STL types.
+  // workspace.waitForReady()
+  // navigation.trigger()
+  // assert navigation.items.filter(path=".*/vector")
+
+  ints.push_back(0);
+  // ^
+
+  // step
+  // ; Test navigation to definition on local symbols.
+  // workspace.waitForReady()
+  // navigation.trigger()
+  // assert navigation.items.filter(path=".*/general.cc", range=ints)
+
+  ProtoMsg msg;
+  msg.set_some_field(0);
+  //          ^
+
+  // step
+  // ; Test navigation to definition on proto fields. We do not check for a
+  // ; specific target as it can be in generated code.
+  // workspace.waitForReady()
+  // navigation.trigger()
+  // assert navigation.items
+}
+
+void TestParameterInfo() {
+  std::vector<int> v;
+  v.push_back(0);
+  //          ^
+
+  // step
+  // ; Test the signature help for STL functions. We do not check for a specific
+  // ; text as it can be implementation-dependent.
+  // workspace.waitForReady()
+  // paraminfo.trigger()
+  // assert paraminfo.items
+
+  Foo(0, 0.0);
+  //      ^
+
+  // step
+  // ; Test the signature help for the function 'Foo' having two overloads.
+  // workspace.waitForReady()
+  // paraminfo.trigger()
+  // assert paraminfo.items.filter(
+  //  active=true,
+  //  label="Foo\\(int x, double y\\) -> void",
+  //  selection="double y",
+  // )
+  // assert paraminfo.items.filter(
+  //  active=false,
+  //  label="Foo\\(float x, float y\\) -> float",
+  // )
+}
+
+int main() { return 0; }
diff --git a/tools/ide_query/prober_scripts/cpp_suite.textpb b/tools/ide_query/prober_scripts/cpp_suite.textpb
new file mode 100644
index 0000000000..83772699ba
--- /dev/null
+++ b/tools/ide_query/prober_scripts/cpp_suite.textpb
@@ -0,0 +1,5 @@
+tests: {
+  name: "general"
+  scripts: "build/make/tools/ide_query/prober_scripts/cpp/general.cc"
+  scripts: "build/make/tools/ide_query/prober_scripts/cpp/foo.proto"
+}
diff --git a/tools/ide_query/prober_scripts/ide_query.out b/tools/ide_query/prober_scripts/ide_query.out
new file mode 100644
index 0000000000..cd7ce6d258
--- /dev/null
+++ b/tools/ide_query/prober_scripts/ide_query.out
@@ -0,0 +1,239 @@
+
+out–a
+8build/make/tools/ide_query/prober_scripts/cpp/general.cc8prebuilts/clang/host/linux-x86/clang-r522817/bin/clang++-mthumb-Os-fomit-frame-pointer-mllvm-enable-shrink-wrap=false-O2-Wall-Wextra-Winit-self-Wpointer-arith-Wunguarded-availability-Werror=date-time-Werror=int-conversion-Werror=pragma-pack&-Werror=pragma-pack-suspicious-include-Werror=sizeof-array-div-Werror=string-plus-int'-Werror=unreachable-code-loop-increment"-Wno-error=deprecated-declarations-Wno-c99-designator-Wno-gnu-folding-constant"-Wno-inconsistent-missing-override-Wno-error=reorder-init-list-Wno-reorder-init-list-Wno-sign-compare-Wno-unused	-DANDROID-DNDEBUG-UDEBUG(-D__compiler_offsetof=__builtin_offsetof*-D__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__	-faddrsig-fdebug-default-version=5-fcolor-diagnostics-ffp-contract=off-fno-exceptions-fno-strict-aliasing-fmessage-length=0#-fno-relaxed-template-template-args-gsimple-template-names-gz=zstd-no-canonical-prefixes-Wno-error=format"-fdebug-prefix-map=/proc/self/cwd=-ftrivial-auto-var-init=zero-g-ffunction-sections-fdata-sections-fno-short-enums-funwind-tables-fstack-protector-strong-Wa,--noexecstack-D_FORTIFY_SOURCE=2-Wstrict-aliasing=2-Werror=return-type-Werror=non-virtual-dtor-Werror=address-Werror=sequence-point-Werror=format-security-nostdlibinc-fdebug-info-for-profiling-msoft-float-march=armv7-a-mfloat-abi=softfp
+-mfpu=neon/-Ibuild/make/tools/ide_query/prober_scripts/cpp³-Iout/soong/.intermediates/build/make/tools/ide_query/prober_scripts/cpp/ide_query_proberscript_cc/android_arm_armv7-a-neon/gen/proto/build/make/tools/ide_query/prober_scripts/cpp…-Iout/soong/.intermediates/build/make/tools/ide_query/prober_scripts/cpp/ide_query_proberscript_cc/android_arm_armv7-a-neon/gen/proto-D__LIBC_API__=10000-D__LIBM_API__=10000-D__LIBDL_API__=10000-Iexternal/protobuf/srcY-Iprebuilts/clang/host/linux-x86/clang-r522817/android_libc++/platform/arm/include/c++/v1=-Iprebuilts/clang/host/linux-x86/clang-r522817/include/c++/v1 -Ibionic/libc/async_safe/include-Isystem/logging/liblog/include'-Ibionic/libc/system_properties/include<-Isystem/core/property_service/libpropertyinfoparser/include-isystembionic/libc/include-isystembionic/libc/kernel/uapi/asm-arm-isystembionic/libc/kernel/uapi-isystembionic/libc/kernel/android/scsi-isystembionic/libc/kernel/android/uapi-targetarmv7a-linux-androideabi10000-DANDROID_STRICT-fPIE-Werror-Wno-unused-parameter-DGOOGLE_PROTOBUF_NO_RTTI-Wimplicit-fallthrough*-D_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS-Wno-gnu-include-next-fvisibility-inlines-hidden-mllvm-enable-shrink-wrap=false-std=gnu++20	-fno-rtti-Isystem/core/include-Isystem/logging/liblog/include-Isystem/media/audio/include-Ihardware/libhardware/include%-Ihardware/libhardware_legacy/include-Ihardware/ril/include-Iframeworks/native/include"-Iframeworks/native/opengl/include-Iframeworks/av/include-Werror=bool-operation -Werror=format-insufficient-args%-Werror=implicit-int-float-conversion-Werror=int-in-bool-context-Werror=int-to-pointer-cast-Werror=pointer-to-int-cast-Werror=xor-used-as-pow-Wno-void-pointer-to-enum-cast-Wno-void-pointer-to-int-cast-Wno-pointer-to-int-cast-Werror=fortify-source-Wno-unused-variable-Wno-missing-field-initializers-Wno-packed-non-pod-Werror=address-of-temporary+-Werror=incompatible-function-pointer-types-Werror=null-dereference-Werror=return-type"-Wno-tautological-constant-compare$-Wno-tautological-type-limit-compare"-Wno-implicit-int-float-conversion!-Wno-tautological-overlap-compare-Wno-deprecated-copy-Wno-range-loop-construct"-Wno-zero-as-null-pointer-constant)-Wno-deprecated-anon-enum-enum-conversion$-Wno-deprecated-enum-enum-conversion-Wno-pessimizing-move-Wno-non-c-typedef-for-linkage-Wno-align-mismatch"-Wno-error=unused-but-set-variable#-Wno-error=unused-but-set-parameter-Wno-error=deprecated-builtins-Wno-error=deprecated2-Wno-error=single-bit-bitfield-constant-conversion$-Wno-error=enum-constexpr-conversion-Wno-error=invalid-offsetof&-Wno-deprecated-dynamic-exception-spec8build/make/tools/ide_query/prober_scripts/cpp/general.cc"Õ?
+¶soong/.intermediates/build/make/tools/ide_query/prober_scripts/cpp/ide_query_proberscript_cc/android_arm_armv7-a-neon/gen/proto/build/make/tools/ide_query/prober_scripts/cpp/foo.pb.h™>// Generated by the protocol buffer compiler.  DO NOT EDIT!
+// source: build/make/tools/ide_query/prober_scripts/cpp/foo.proto
+
+#ifndef GOOGLE_PROTOBUF_INCLUDED_build_2fmake_2ftools_2fide_5fquery_2fprober_5fscripts_2fcpp_2ffoo_2eproto
+#define GOOGLE_PROTOBUF_INCLUDED_build_2fmake_2ftools_2fide_5fquery_2fprober_5fscripts_2fcpp_2ffoo_2eproto
+
+#include <cstdint>
+#include <limits>
+#include <string>
+
+#include <google/protobuf/port_def.inc>
+#if PROTOBUF_VERSION < 3021000
+#error This file was generated by a newer version of protoc which is
+#error incompatible with your Protocol Buffer headers. Please update
+#error your headers.
+#endif
+#if 3021012 < PROTOBUF_MIN_PROTOC_VERSION
+#error This file was generated by an older version of protoc which is
+#error incompatible with your Protocol Buffer headers. Please
+#error regenerate this file with a newer version of protoc.
+#endif
+
+#include <google/protobuf/port_undef.inc>
+#include <google/protobuf/io/coded_stream.h>
+#include <google/protobuf/arena.h>
+#include <google/protobuf/arenastring.h>
+#include <google/protobuf/generated_message_util.h>
+#include <google/protobuf/metadata_lite.h>
+#include <google/protobuf/message_lite.h>
+#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
+#include <google/protobuf/extension_set.h>  // IWYU pragma: export
+// @@protoc_insertion_point(includes)
+#include <google/protobuf/port_def.inc>
+#define PROTOBUF_INTERNAL_EXPORT_build_2fmake_2ftools_2fide_5fquery_2fprober_5fscripts_2fcpp_2ffoo_2eproto
+PROTOBUF_NAMESPACE_OPEN
+namespace internal {
+class AnyMetadata;
+}  // namespace internal
+PROTOBUF_NAMESPACE_CLOSE
+
+// Internal implementation detail -- do not use these members.
+struct TableStruct_build_2fmake_2ftools_2fide_5fquery_2fprober_5fscripts_2fcpp_2ffoo_2eproto {
+  static const ::uint32_t offsets[];
+};
+namespace ide_query {
+namespace prober_scripts {
+class ProtoMsg;
+struct ProtoMsgDefaultTypeInternal;
+extern ProtoMsgDefaultTypeInternal _ProtoMsg_default_instance_;
+}  // namespace prober_scripts
+}  // namespace ide_query
+PROTOBUF_NAMESPACE_OPEN
+template<> ::ide_query::prober_scripts::ProtoMsg* Arena::CreateMaybeMessage<::ide_query::prober_scripts::ProtoMsg>(Arena*);
+PROTOBUF_NAMESPACE_CLOSE
+namespace ide_query {
+namespace prober_scripts {
+
+// ===================================================================
+
+class ProtoMsg final :
+    public ::PROTOBUF_NAMESPACE_ID::MessageLite /* @@protoc_insertion_point(class_definition:ide_query.prober_scripts.ProtoMsg) */ {
+ public:
+  inline ProtoMsg() : ProtoMsg(nullptr) {}
+  ~ProtoMsg() override;
+  explicit PROTOBUF_CONSTEXPR ProtoMsg(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);
+
+  ProtoMsg(const ProtoMsg& from);
+  ProtoMsg(ProtoMsg&& from) noexcept
+    : ProtoMsg() {
+    *this = ::std::move(from);
+  }
+
+  inline ProtoMsg& operator=(const ProtoMsg& from) {
+    if (this == &from) return *this;
+    CopyFrom(from);
+    return *this;
+  }
+  inline ProtoMsg& operator=(ProtoMsg&& from) noexcept {
+    if (this == &from) return *this;
+    if (GetOwningArena() == from.GetOwningArena()
+  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
+        && GetOwningArena() != nullptr
+  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
+    ) {
+      InternalSwap(&from);
+    } else {
+      CopyFrom(from);
+    }
+    return *this;
+  }
+
+  static const ProtoMsg& default_instance() {
+    return *internal_default_instance();
+  }
+  static inline const ProtoMsg* internal_default_instance() {
+    return reinterpret_cast<const ProtoMsg*>(
+               &_ProtoMsg_default_instance_);
+  }
+  static constexpr int kIndexInFileMessages =
+    0;
+
+  friend void swap(ProtoMsg& a, ProtoMsg& b) {
+    a.Swap(&b);
+  }
+  inline void Swap(ProtoMsg* other) {
+    if (other == this) return;
+  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
+    if (GetOwningArena() != nullptr &&
+        GetOwningArena() == other->GetOwningArena()) {
+   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
+    if (GetOwningArena() == other->GetOwningArena()) {
+  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
+      InternalSwap(other);
+    } else {
+      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
+    }
+  }
+  void UnsafeArenaSwap(ProtoMsg* other) {
+    if (other == this) return;
+    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
+    InternalSwap(other);
+  }
+
+  // implements Message ----------------------------------------------
+
+  ProtoMsg* New(::PROTOBUF_NAMESPACE_ID::Arena* arena) const final {
+    return CreateMaybeMessage<ProtoMsg>(arena);
+  }
+  ProtoMsg* New() const {
+    return New(nullptr);
+  }
+  void CheckTypeAndMergeFrom(const ::PROTOBUF_NAMESPACE_ID::MessageLite& from)  final;
+  void CopyFrom(const ProtoMsg& from);
+  void MergeFrom(const ProtoMsg& from);
+  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
+  bool IsInitialized() const final;
+
+  size_t ByteSizeLong() const final;
+  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
+  ::uint8_t* _InternalSerialize(
+      ::uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
+  int GetCachedSize() const final { return _impl_._cached_size_.Get(); }
+
+  private:
+  void SharedCtor(::PROTOBUF_NAMESPACE_ID::Arena* arena, bool is_message_owned);
+  void SharedDtor();
+  void SetCachedSize(int size) const;
+  void InternalSwap(ProtoMsg* other);
+
+  private:
+  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
+  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
+    return "ide_query.prober_scripts.ProtoMsg";
+  }
+  protected:
+  explicit ProtoMsg(::PROTOBUF_NAMESPACE_ID::Arena* arena,
+                       bool is_message_owned = false);
+  public:
+
+  std::string GetTypeName() const final;
+
+  // nested types ----------------------------------------------------
+
+  // accessors -------------------------------------------------------
+
+  enum : int {
+    kSomeFieldFieldNumber = 1,
+  };
+  // int64 some_field = 1;
+  void clear_some_field();
+  ::int64_t some_field() const;
+  void set_some_field(::int64_t value);
+  private:
+  ::int64_t _internal_some_field() const;
+  void _internal_set_some_field(::int64_t value);
+  public:
+
+  // @@protoc_insertion_point(class_scope:ide_query.prober_scripts.ProtoMsg)
+ private:
+  class _Internal;
+
+  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
+  typedef void InternalArenaConstructable_;
+  typedef void DestructorSkippable_;
+  struct Impl_ {
+    ::int64_t some_field_;
+    mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
+  };
+  union { Impl_ _impl_; };
+  friend struct ::TableStruct_build_2fmake_2ftools_2fide_5fquery_2fprober_5fscripts_2fcpp_2ffoo_2eproto;
+};
+// ===================================================================
+
+
+// ===================================================================
+
+#ifdef __GNUC__
+  #pragma GCC diagnostic push
+  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
+#endif  // __GNUC__
+// ProtoMsg
+
+// int64 some_field = 1;
+inline void ProtoMsg::clear_some_field() {
+  _impl_.some_field_ = ::int64_t{0};
+}
+inline ::int64_t ProtoMsg::_internal_some_field() const {
+  return _impl_.some_field_;
+}
+inline ::int64_t ProtoMsg::some_field() const {
+  // @@protoc_insertion_point(field_get:ide_query.prober_scripts.ProtoMsg.some_field)
+  return _internal_some_field();
+}
+inline void ProtoMsg::_internal_set_some_field(::int64_t value) {
+  
+  _impl_.some_field_ = value;
+}
+inline void ProtoMsg::set_some_field(::int64_t value) {
+  _internal_set_some_field(value);
+  // @@protoc_insertion_point(field_set:ide_query.prober_scripts.ProtoMsg.some_field)
+}
+
+#ifdef __GNUC__
+  #pragma GCC diagnostic pop
+#endif  // __GNUC__
+
+// @@protoc_insertion_point(namespace_scope)
+
+}  // namespace prober_scripts
+}  // namespace ide_query
+
+// @@protoc_insertion_point(global_scope)
+
+#include <google/protobuf/port_undef.inc>
+#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_build_2fmake_2ftools_2fide_5fquery_2fprober_5fscripts_2fcpp_2ffoo_2eproto
diff --git a/tools/ide_query/prober_scripts/jvm/Foo.java b/tools/ide_query/prober_scripts/jvm/Foo.java
new file mode 100644
index 0000000000..a043f72e32
--- /dev/null
+++ b/tools/ide_query/prober_scripts/jvm/Foo.java
@@ -0,0 +1,37 @@
+/*
+ * Copyright 2014 The Android Open Source Project
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
+package jvm;
+
+import java.util.ArrayList;
+import java.util.HashSet;
+
+/** Foo class. */
+public final class Foo {
+
+  void testCompletion() {
+    ArrayList<Integer> list = new ArrayList<>();
+    System.out.println(list);
+
+    // ^
+
+    // step
+    // ; Test completion on the standard types.
+    // type("list.")
+    // completion.trigger()
+    // assert completion.items.filter(label="add.*")
+  }
+}
diff --git a/tools/ide_query/prober_scripts/jvm/suite.textpb b/tools/ide_query/prober_scripts/jvm/suite.textpb
new file mode 100644
index 0000000000..460e08ca31
--- /dev/null
+++ b/tools/ide_query/prober_scripts/jvm/suite.textpb
@@ -0,0 +1,4 @@
+tests: {
+  name: "general"
+  scripts: "build/make/tools/ide_query/prober_scripts/jvm/Foo.java"
+}
diff --git a/tools/ide_query/prober_scripts/regen.sh b/tools/ide_query/prober_scripts/regen.sh
new file mode 100755
index 0000000000..2edfe53ec3
--- /dev/null
+++ b/tools/ide_query/prober_scripts/regen.sh
@@ -0,0 +1,33 @@
+#!/bin/bash -e
+
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
+# This script is used to generate the ide_query.out file.
+#
+# The ide_query.out file is a pre-computed result of running ide_query.sh
+# on a set of files. This allows the prober to run its tests without running
+# ide_query.sh. The prober doesn't check-out the full source code, so it
+# can't run ide_query.sh itself.
+
+cd $(dirname $BASH_SOURCE)
+source $(pwd)/../../../shell_utils.sh
+require_top
+
+files_to_build=(
+  build/make/tools/ide_query/prober_scripts/cpp/general.cc
+)
+
+cd ${TOP}
+build/make/tools/ide_query/ide_query.sh --lunch_target=aosp_arm-trunk_staging-eng ${files_to_build[@]} > build/make/tools/ide_query/prober_scripts/ide_query.out
diff --git a/tools/releasetools/Android.bp b/tools/releasetools/Android.bp
index 9b134f22d4..8c710449f9 100644
--- a/tools/releasetools/Android.bp
+++ b/tools/releasetools/Android.bp
@@ -96,6 +96,7 @@ python_defaults {
     ],
     libs: [
         "apex_manifest",
+        "releasetools_apex_utils",
         "releasetools_common",
     ],
     required: [
@@ -107,7 +108,7 @@ python_defaults {
 python_library_host {
     name: "ota_metadata_proto",
     srcs: [
-       "ota_metadata.proto",
+        "ota_metadata.proto",
     ],
     proto: {
         canonical_path_from_root: false,
@@ -117,7 +118,7 @@ python_library_host {
 cc_library_static {
     name: "ota_metadata_proto_cc",
     srcs: [
-       "ota_metadata.proto",
+        "ota_metadata.proto",
     ],
     host_supported: true,
     recovery_available: true,
@@ -144,7 +145,7 @@ java_library_static {
             static_libs: ["libprotobuf-java-nano"],
         },
     },
-    visibility: ["//frameworks/base:__subpackages__"]
+    visibility: ["//frameworks/base:__subpackages__"],
 }
 
 python_defaults {
@@ -367,6 +368,9 @@ python_binary_host {
     libs: [
         "ota_utils_lib",
     ],
+    required: [
+        "signapk",
+    ],
 }
 
 python_binary_host {
@@ -436,7 +440,7 @@ python_binary_host {
     name: "check_target_files_vintf",
     defaults: [
         "releasetools_binary_defaults",
-        "releasetools_check_target_files_vintf_defaults"
+        "releasetools_check_target_files_vintf_defaults",
     ],
 }
 
@@ -546,13 +550,15 @@ python_binary_host {
     defaults: ["releasetools_binary_defaults"],
     srcs: [
         "sign_target_files_apks.py",
-        "payload_signer.py",
-        "ota_signing_utils.py",
+        "ota_from_raw_img.py",
     ],
     libs: [
         "releasetools_add_img_to_target_files",
         "releasetools_apex_utils",
         "releasetools_common",
+        "ota_metadata_proto",
+        "ota_utils_lib",
+        "update_payload",
     ],
 }
 
@@ -632,7 +638,7 @@ python_defaults {
     data: [
         "testdata/**/*",
         ":com.android.apex.compressed.v1",
-        ":com.android.apex.vendor.foo.with_vintf"
+        ":com.android.apex.vendor.foo.with_vintf",
     ],
     target: {
         darwin: {
diff --git a/tools/releasetools/add_img_to_target_files.py b/tools/releasetools/add_img_to_target_files.py
index b39a82cf45..c25ff2718c 100644
--- a/tools/releasetools/add_img_to_target_files.py
+++ b/tools/releasetools/add_img_to_target_files.py
@@ -464,6 +464,7 @@ def AddDtbo(output_zip):
   dtbo_prebuilt_path = os.path.join(
       OPTIONS.input_tmp, "PREBUILT_IMAGES", "dtbo.img")
   assert os.path.exists(dtbo_prebuilt_path)
+  os.makedirs(os.path.dirname(img.name), exist_ok=True)
   shutil.copy(dtbo_prebuilt_path, img.name)
 
   # AVB-sign the image as needed.
diff --git a/tools/releasetools/apex_utils.py b/tools/releasetools/apex_utils.py
index 3abef3bece..54df955e9f 100644
--- a/tools/releasetools/apex_utils.py
+++ b/tools/releasetools/apex_utils.py
@@ -36,6 +36,8 @@ APEX_PAYLOAD_IMAGE = 'apex_payload.img'
 
 APEX_PUBKEY = 'apex_pubkey'
 
+# Partitions supporting APEXes
+PARTITIONS = ['system', 'system_ext', 'product', 'vendor', 'odm']
 
 class ApexInfoError(Exception):
   """An Exception raised during Apex Information command."""
@@ -550,7 +552,7 @@ def GetApexInfoFromTargetFiles(input_file):
   if not isinstance(input_file, str):
     raise RuntimeError("must pass filepath to target-files zip or directory")
   apex_infos = []
-  for partition in ['system', 'system_ext', 'product', 'vendor']:
+  for partition in PARTITIONS:
     apex_infos.extend(GetApexInfoForPartition(input_file, partition))
   return apex_infos
 
diff --git a/tools/releasetools/check_target_files_vintf.py b/tools/releasetools/check_target_files_vintf.py
index b8dcd8465c..dc123efb46 100755
--- a/tools/releasetools/check_target_files_vintf.py
+++ b/tools/releasetools/check_target_files_vintf.py
@@ -30,6 +30,7 @@ import subprocess
 import sys
 import zipfile
 
+import apex_utils
 import common
 from apex_manifest import ParseApexManifest
 
@@ -229,7 +230,7 @@ def PrepareApexDirectory(inp, dirmap):
   apex_host = os.path.join(OPTIONS.search_path, 'bin', 'apexd_host')
   cmd = [apex_host, '--tool_path', OPTIONS.search_path]
   cmd += ['--apex_path', dirmap['/apex']]
-  for p in ['system', 'system_ext', 'product', 'vendor']:
+  for p in apex_utils.PARTITIONS:
     if '/' + p in dirmap:
       cmd += ['--' + p + '_path', dirmap['/' + p]]
   common.RunAndCheckOutput(cmd)
diff --git a/tools/releasetools/common.py b/tools/releasetools/common.py
index d91a713276..f04dfb703d 100644
--- a/tools/releasetools/common.py
+++ b/tools/releasetools/common.py
@@ -898,7 +898,7 @@ def LoadInfoDict(input_file, repacking=False):
       if key.endswith("selinux_fc"):
         fc_basename = os.path.basename(d[key])
         fc_config = os.path.join(input_file, "META", fc_basename)
-        assert os.path.exists(fc_config)
+        assert os.path.exists(fc_config), "{} does not exist".format(fc_config)
 
         d[key] = fc_config
 
@@ -907,9 +907,10 @@ def LoadInfoDict(input_file, repacking=False):
     d["root_fs_config"] = os.path.join(
         input_file, "META", "root_filesystem_config.txt")
 
+    partitions = ["system", "vendor", "system_ext", "product", "odm",
+                  "vendor_dlkm", "odm_dlkm", "system_dlkm"]
     # Redirect {partition}_base_fs_file for each of the named partitions.
-    for part_name in ["system", "vendor", "system_ext", "product", "odm",
-                      "vendor_dlkm", "odm_dlkm", "system_dlkm"]:
+    for part_name in partitions:
       key_name = part_name + "_base_fs_file"
       if key_name not in d:
         continue
@@ -922,6 +923,25 @@ def LoadInfoDict(input_file, repacking=False):
             "Failed to find %s base fs file: %s", part_name, base_fs_file)
         del d[key_name]
 
+    # Redirecting helper for optional properties like erofs_compress_hints
+    def redirect_file(prop, filename):
+      if prop not in d:
+        return
+      config_file = os.path.join(input_file, "META/" + filename)
+      if os.path.exists(config_file):
+        d[prop] = config_file
+      else:
+        logger.warning(
+            "Failed to find %s fro %s", filename, prop)
+        del d[prop]
+
+    # Redirect erofs_[default_]compress_hints files
+    redirect_file("erofs_default_compress_hints",
+                  "erofs_default_compress_hints.txt")
+    for part in partitions:
+      redirect_file(part + "_erofs_compress_hints",
+                    part + "_erofs_compress_hints.txt")
+
   def makeint(key):
     if key in d:
       d[key] = int(d[key], 0)
@@ -1784,12 +1804,7 @@ def _BuildBootableImage(image_name, sourcedir, fs_config_file,
   if has_ramdisk:
     cmd.extend(["--ramdisk", ramdisk_img.name])
 
-  img_unsigned = None
-  if info_dict.get("vboot"):
-    img_unsigned = tempfile.NamedTemporaryFile()
-    cmd.extend(["--output", img_unsigned.name])
-  else:
-    cmd.extend(["--output", img.name])
+  cmd.extend(["--output", img.name])
 
   if partition_name == "recovery":
     if info_dict.get("include_recovery_dtbo") == "true":
@@ -1801,28 +1816,6 @@ def _BuildBootableImage(image_name, sourcedir, fs_config_file,
 
   RunAndCheckOutput(cmd)
 
-  # Sign the image if vboot is non-empty.
-  if info_dict.get("vboot"):
-    path = "/" + partition_name
-    img_keyblock = tempfile.NamedTemporaryFile()
-    # We have switched from the prebuilt futility binary to using the tool
-    # (futility-host) built from the source. Override the setting in the old
-    # TF.zip.
-    futility = info_dict["futility"]
-    if futility.startswith("prebuilts/"):
-      futility = "futility-host"
-    cmd = [info_dict["vboot_signer_cmd"], futility,
-           img_unsigned.name, info_dict["vboot_key"] + ".vbpubk",
-           info_dict["vboot_key"] + ".vbprivk",
-           info_dict["vboot_subkey"] + ".vbprivk",
-           img_keyblock.name,
-           img.name]
-    RunAndCheckOutput(cmd)
-
-    # Clean up the temp files.
-    img_unsigned.close()
-    img_keyblock.close()
-
   # AVB: if enabled, calculate and add hash to boot.img or recovery.img.
   if info_dict.get("avb_enable") == "true":
     avbtool = info_dict["avb_avbtool"]
@@ -2461,12 +2454,23 @@ def GetMinSdkVersion(apk_name):
         "Failed to obtain minSdkVersion for {}: aapt2 return code {}:\n{}\n{}".format(
             apk_name, proc.returncode, stdoutdata, stderrdata))
 
+  is_split_apk = False
   for line in stdoutdata.split("\n"):
+    # See b/353837347 , split APKs do not have sdk version defined,
+    # so we default to 21 as split APKs are only supported since SDK
+    # 21.
+    if (re.search(r"split=[\"'].*[\"']", line)):
+      is_split_apk = True
     # Due to ag/24161708, looking for lines such as minSdkVersion:'23',minSdkVersion:'M'
     # or sdkVersion:'23', sdkVersion:'M'.
     m = re.match(r'(?:minSdkVersion|sdkVersion):\'([^\']*)\'', line)
     if m:
       return m.group(1)
+  if is_split_apk:
+    logger.info("%s is a split APK, it does not have minimum SDK version"
+                " defined. Defaulting to 21 because split APK isn't supported"
+                " before that.", apk_name)
+    return 21
   raise ExternalError("No minSdkVersion returned by aapt2 for apk: {}".format(apk_name))
 
 
@@ -2815,6 +2819,7 @@ def ParseOptions(argv,
             break
         elif handler(o, a):
           success = True
+          break
       if not success:
         raise ValueError("unknown option \"%s\"" % (o,))
 
@@ -3003,7 +3008,7 @@ def ZipWrite(zip_file, filename, arcname=None, perms=0o644,
     zipfile.ZIP64_LIMIT = saved_zip64_limit
 
 
-def ZipWriteStr(zip_file, zinfo_or_arcname, data, perms=None,
+def ZipWriteStr(zip_file: zipfile.ZipFile, zinfo_or_arcname, data, perms=None,
                 compress_type=None):
   """Wrap zipfile.writestr() function to work around the zip64 limit.
 
@@ -3233,7 +3238,9 @@ class File(object):
     return t
 
   def WriteToDir(self, d):
-    with open(os.path.join(d, self.name), "wb") as fp:
+    output_path = os.path.join(d, self.name)
+    os.makedirs(os.path.dirname(output_path), exist_ok=True)
+    with open(output_path, "wb") as fp:
       fp.write(self.data)
 
   def AddToZip(self, z, compression=None):
diff --git a/tools/releasetools/ota_from_raw_img.py b/tools/releasetools/ota_from_raw_img.py
index c186940c25..3b9374ab13 100644
--- a/tools/releasetools/ota_from_raw_img.py
+++ b/tools/releasetools/ota_from_raw_img.py
@@ -54,7 +54,7 @@ def main(argv):
       prog=argv[0], description="Given a series of .img files, produces a full OTA package that installs thoese images")
   parser.add_argument("images", nargs="+", type=str,
                       help="List of images to generate OTA")
-  parser.add_argument("--partition_names", nargs='+', type=str,
+  parser.add_argument("--partition_names", nargs='?', type=str,
                       help="Partition names to install the images, default to basename of the image(no file name extension)")
   parser.add_argument('--output', type=str,
                       help='Paths to output merged ota', required=True)
@@ -74,18 +74,20 @@ def main(argv):
       old_imgs[i], args.images[i] = img.split(":", maxsplit=1)
 
   if not args.partition_names:
-    args.partition_names = [os.path.os.path.splitext(os.path.basename(path))[
+    args.partition_names = [os.path.splitext(os.path.basename(path))[
         0] for path in args.images]
+  else:
+    args.partition_names = args.partition_names.split(",")
   with tempfile.NamedTemporaryFile() as unsigned_payload, tempfile.NamedTemporaryFile() as dynamic_partition_info_file:
     dynamic_partition_info_file.writelines(
         [b"virtual_ab=true\n", b"super_partition_groups=\n"])
     dynamic_partition_info_file.flush()
     cmd = [ResolveBinaryPath("delta_generator", args.search_path)]
-    cmd.append("--partition_names=" + ",".join(args.partition_names))
+    cmd.append("--partition_names=" + ":".join(args.partition_names))
     cmd.append("--dynamic_partition_info_file=" +
                dynamic_partition_info_file.name)
-    cmd.append("--old_partitions=" + ",".join(old_imgs))
-    cmd.append("--new_partitions=" + ",".join(args.images))
+    cmd.append("--old_partitions=" + ":".join(old_imgs))
+    cmd.append("--new_partitions=" + ":".join(args.images))
     cmd.append("--out_file=" + unsigned_payload.name)
     cmd.append("--is_partial_update")
     if args.max_timestamp:
@@ -103,9 +105,6 @@ def main(argv):
 
     if args.package_key:
       logger.info("Signing payload...")
-      # TODO: remove OPTIONS when no longer used as fallback in payload_signer
-      common.OPTIONS.payload_signer_args = None
-      common.OPTIONS.payload_signer_maximum_signature_size = None
       signer = PayloadSigner(args.package_key, args.private_key_suffix,
                              key_passwords[args.package_key],
                              payload_signer=args.payload_signer,
diff --git a/tools/releasetools/ota_from_target_files.py b/tools/releasetools/ota_from_target_files.py
index 985cd56cb0..6446e1ff59 100755
--- a/tools/releasetools/ota_from_target_files.py
+++ b/tools/releasetools/ota_from_target_files.py
@@ -264,6 +264,10 @@ A/B OTA specific options
 
   --compression_factor
       Specify the maximum block size to be compressed at once during OTA. supported options: 4k, 8k, 16k, 32k, 64k, 128k, 256k
+
+  --full_ota_partitions
+      Specify list of partitions should be updated in full OTA fashion, even if
+      an incremental OTA is about to be generated
 """
 
 from __future__ import print_function
@@ -283,7 +287,7 @@ import common
 import ota_utils
 import payload_signer
 from ota_utils import (VABC_COMPRESSION_PARAM_SUPPORT, FinalizeMetadata, GetPackageMetadata,
-                       PayloadGenerator, SECURITY_PATCH_LEVEL_PROP_NAME, ExtractTargetFiles, CopyTargetFilesDir)
+                       PayloadGenerator, SECURITY_PATCH_LEVEL_PROP_NAME, ExtractTargetFiles, CopyTargetFilesDir, TARGET_FILES_IMAGES_SUBDIR)
 from common import DoesInputFileContain, IsSparseImage
 import target_files_diff
 from non_ab_ota import GenerateNonAbOtaPackage
@@ -337,6 +341,7 @@ OPTIONS.security_patch_level = None
 OPTIONS.max_threads = None
 OPTIONS.vabc_cow_version = None
 OPTIONS.compression_factor = None
+OPTIONS.full_ota_partitions = None
 
 
 POSTINSTALL_CONFIG = 'META/postinstall_config.txt'
@@ -892,6 +897,14 @@ def GenerateAbOtaPackage(target_file, output_file, source_file=None):
 
   if source_file is not None:
     source_file = ExtractTargetFiles(source_file)
+    if OPTIONS.full_ota_partitions:
+      for partition in OPTIONS.full_ota_partitions:
+        for subdir in TARGET_FILES_IMAGES_SUBDIR:
+          image_path = os.path.join(source_file, subdir, partition + ".img")
+          if os.path.exists(image_path):
+            logger.info(
+                "Ignoring source image %s for partition %s because it is configured to use full OTA", image_path, partition)
+            os.remove(image_path)
     assert "ab_partitions" in OPTIONS.source_info_dict, \
         "META/ab_partitions.txt is required for ab_update."
     assert "ab_partitions" in OPTIONS.target_info_dict, \
@@ -1193,7 +1206,7 @@ def GenerateAbOtaPackage(target_file, output_file, source_file=None):
 
 def main(argv):
 
-  def option_handler(o, a):
+  def option_handler(o, a: str):
     if o in ("-i", "--incremental_from"):
       OPTIONS.incremental_source = a
     elif o == "--full_radio":
@@ -1320,6 +1333,9 @@ def main(argv):
       else:
         raise ValueError("Cannot parse value %r for option %r - only "
                          "integers are allowed." % (a, o))
+    elif o == "--full_ota_partitions":
+      OPTIONS.full_ota_partitions = set(
+          a.strip().strip("\"").strip("'").split(","))
     else:
       return False
     return True
@@ -1370,6 +1386,7 @@ def main(argv):
                                  "max_threads=",
                                  "vabc_cow_version=",
                                  "compression_factor=",
+                                 "full_ota_partitions=",
                              ], extra_option_handler=[option_handler, payload_signer.signer_options])
   common.InitLogging()
 
diff --git a/tools/releasetools/sign_target_files_apks.py b/tools/releasetools/sign_target_files_apks.py
index b8f848fb2b..4ad97e0108 100755
--- a/tools/releasetools/sign_target_files_apks.py
+++ b/tools/releasetools/sign_target_files_apks.py
@@ -184,14 +184,17 @@ import re
 import shutil
 import stat
 import sys
+import shlex
 import tempfile
 import zipfile
 from xml.etree import ElementTree
 
 import add_img_to_target_files
+import ota_from_raw_img
 import apex_utils
 import common
 import payload_signer
+import update_payload
 from payload_signer import SignOtaPackage, PAYLOAD_BIN
 
 
@@ -221,6 +224,7 @@ OPTIONS.vendor_otatools = None
 OPTIONS.allow_gsi_debug_sepolicy = False
 OPTIONS.override_apk_keys = None
 OPTIONS.override_apex_keys = None
+OPTIONS.input_tmp = None
 
 
 AVB_FOOTER_ARGS_BY_PARTITION = {
@@ -579,7 +583,104 @@ def IsBuildPropFile(filename):
         filename.endswith("/prop.default")
 
 
-def ProcessTargetFiles(input_tf_zip: zipfile.ZipFile, output_tf_zip, misc_info,
+def GetOtaSigningArgs():
+  args = []
+  if OPTIONS.package_key:
+    args.extend(["--package_key", OPTIONS.package_key])
+  if OPTIONS.payload_signer:
+    args.extend(["--payload_signer=" + OPTIONS.payload_signer])
+  if OPTIONS.payload_signer_args:
+    args.extend(["--payload_signer_args=" + shlex.join(OPTIONS.payload_signer_args)])
+  if OPTIONS.search_path:
+    args.extend(["--search_path", OPTIONS.search_path])
+  if OPTIONS.payload_signer_maximum_signature_size:
+    args.extend(["--payload_signer_maximum_signature_size",
+                OPTIONS.payload_signer_maximum_signature_size])
+  if OPTIONS.private_key_suffix:
+    args.extend(["--private_key_suffix", OPTIONS.private_key_suffix])
+  return args
+
+
+def RegenerateKernelPartitions(input_tf_zip: zipfile.ZipFile, output_tf_zip: zipfile.ZipFile, misc_info):
+  """Re-generate boot and dtbo partitions using new signing configuration"""
+  files_to_unzip = [
+      "PREBUILT_IMAGES/*", "BOOTABLE_IMAGES/*.img", "*/boot_16k.img", "*/dtbo_16k.img"]
+  if OPTIONS.input_tmp is None:
+    OPTIONS.input_tmp = common.UnzipTemp(input_tf_zip.filename, files_to_unzip)
+  else:
+    common.UnzipToDir(input_tf_zip.filename, OPTIONS.input_tmp, files_to_unzip)
+  unzip_dir = OPTIONS.input_tmp
+  os.makedirs(os.path.join(unzip_dir, "IMAGES"), exist_ok=True)
+
+  boot_image = common.GetBootableImage(
+      "IMAGES/boot.img", "boot.img", unzip_dir, "BOOT", misc_info)
+  if boot_image:
+    boot_image.WriteToDir(unzip_dir)
+    boot_image = os.path.join(unzip_dir, boot_image.name)
+    common.ZipWrite(output_tf_zip, boot_image, "IMAGES/boot.img",
+                    compress_type=zipfile.ZIP_STORED)
+  if misc_info.get("has_dtbo") == "true":
+    add_img_to_target_files.AddDtbo(output_tf_zip)
+  return unzip_dir
+
+
+def RegenerateBootOTA(input_tf_zip: zipfile.ZipFile, filename, input_ota):
+  with input_tf_zip.open(filename, "r") as in_fp:
+    payload = update_payload.Payload(in_fp)
+  is_incremental = any([part.HasField('old_partition_info')
+                        for part in payload.manifest.partitions])
+  is_boot_ota = filename.startswith(
+      "VENDOR/boot_otas/") or filename.startswith("SYSTEM/boot_otas/")
+  if not is_boot_ota:
+    return
+  is_4k_boot_ota = filename in [
+      "VENDOR/boot_otas/boot_ota_4k.zip", "SYSTEM/boot_otas/boot_ota_4k.zip"]
+  # Only 4K boot image is re-generated, so if 16K boot ota isn't incremental,
+  # we do not need to re-generate
+  if not is_4k_boot_ota and not is_incremental:
+    return
+
+  timestamp = str(payload.manifest.max_timestamp)
+  partitions = [part.partition_name for part in payload.manifest.partitions]
+  unzip_dir = OPTIONS.input_tmp
+  signed_boot_image = os.path.join(unzip_dir, "IMAGES", "boot.img")
+  if not os.path.exists(signed_boot_image):
+    logger.warn("Need to re-generate boot OTA {} but failed to get signed boot image. 16K dev option will be impacted, after rolling back to 4K user would need to sideload/flash their device to continue receiving OTAs.")
+    return
+  signed_dtbo_image = os.path.join(unzip_dir, "IMAGES", "dtbo.img")
+  if "dtbo" in partitions and not os.path.exists(signed_dtbo_image):
+    raise ValueError(
+        "Boot OTA {} has dtbo partition, but no dtbo image found in target files.".format(filename))
+  if is_incremental:
+    signed_16k_boot_image = os.path.join(
+        unzip_dir, "IMAGES", "boot_16k.img")
+    signed_16k_dtbo_image = os.path.join(
+        unzip_dir, "IMAGES", "dtbo_16k.img")
+    if is_4k_boot_ota:
+      if os.path.exists(signed_16k_boot_image):
+        signed_boot_image = signed_16k_boot_image + ":" + signed_boot_image
+      if os.path.exists(signed_16k_dtbo_image):
+        signed_dtbo_image = signed_16k_dtbo_image + ":" + signed_dtbo_image
+    else:
+      if os.path.exists(signed_16k_boot_image):
+        signed_boot_image += ":" + signed_16k_boot_image
+      if os.path.exists(signed_16k_dtbo_image):
+        signed_dtbo_image += ":" + signed_16k_dtbo_image
+
+  args = ["ota_from_raw_img",
+          "--max_timestamp", timestamp, "--output", input_ota.name]
+  args.extend(GetOtaSigningArgs())
+  if "dtbo" in partitions:
+    args.extend(["--partition_name", "boot,dtbo",
+                signed_boot_image, signed_dtbo_image])
+  else:
+    args.extend(["--partition_name", "boot", signed_boot_image])
+  logger.info(
+      "Re-generating boot OTA {} using cmd {}".format(filename, args))
+  ota_from_raw_img.main(args)
+
+
+def ProcessTargetFiles(input_tf_zip: zipfile.ZipFile, output_tf_zip: zipfile.ZipFile, misc_info,
                        apk_keys, apex_keys, key_passwords,
                        platform_api_level, codename_to_api_level_map,
                        compressed_extension):
@@ -593,6 +694,16 @@ def ProcessTargetFiles(input_tf_zip: zipfile.ZipFile, output_tf_zip, misc_info,
     # Sets this to zero for targets without APK files.
     maxsize = 0
 
+  # Replace the AVB signing keys, if any.
+  ReplaceAvbSigningKeys(misc_info)
+  OPTIONS.info_dict = misc_info
+
+  # Rewrite the props in AVB signing args.
+  if misc_info.get('avb_enable') == 'true':
+    RewriteAvbProps(misc_info)
+
+  RegenerateKernelPartitions(input_tf_zip, output_tf_zip, misc_info)
+
   for info in input_tf_zip.infolist():
     filename = info.filename
     if filename.startswith("IMAGES/"):
@@ -603,10 +714,10 @@ def ProcessTargetFiles(input_tf_zip: zipfile.ZipFile, output_tf_zip, misc_info,
     if filename.startswith("OTA/") and filename.endswith(".img"):
       continue
 
-    data = input_tf_zip.read(filename)
-    out_info = copy.copy(info)
     (is_apk, is_compressed, should_be_skipped) = GetApkFileInfo(
         filename, compressed_extension, OPTIONS.skip_apks_with_path_prefix)
+    data = input_tf_zip.read(filename)
+    out_info = copy.copy(info)
 
     if is_apk and should_be_skipped:
       # Copy skipped APKs verbatim.
@@ -670,9 +781,8 @@ def ProcessTargetFiles(input_tf_zip: zipfile.ZipFile, output_tf_zip, misc_info,
     elif filename.endswith(".zip") and IsEntryOtaPackage(input_tf_zip, filename):
       logger.info("Re-signing OTA package {}".format(filename))
       with tempfile.NamedTemporaryFile() as input_ota, tempfile.NamedTemporaryFile() as output_ota:
-        with input_tf_zip.open(filename, "r") as in_fp:
-          shutil.copyfileobj(in_fp, input_ota)
-          input_ota.flush()
+        RegenerateBootOTA(input_tf_zip, filename, input_ota)
+
         SignOtaPackage(input_ota.name, output_ota.name)
         common.ZipWrite(output_tf_zip, output_ota.name, filename,
                         compress_type=zipfile.ZIP_STORED)
@@ -811,17 +921,18 @@ def ProcessTargetFiles(input_tf_zip: zipfile.ZipFile, output_tf_zip, misc_info,
         common.ZipWrite(output_tf_zip, image.name, filename)
     # A non-APK file; copy it verbatim.
     else:
-      common.ZipWriteStr(output_tf_zip, out_info, data)
+      try:
+        entry = output_tf_zip.getinfo(filename)
+        if output_tf_zip.read(entry) != data:
+          logger.warn(
+              "Output zip contains duplicate entries for %s with different contents", filename)
+        continue
+      except KeyError:
+        common.ZipWriteStr(output_tf_zip, out_info, data)
 
   if OPTIONS.replace_ota_keys:
     ReplaceOtaKeys(input_tf_zip, output_tf_zip, misc_info)
 
-  # Replace the AVB signing keys, if any.
-  ReplaceAvbSigningKeys(misc_info)
-
-  # Rewrite the props in AVB signing args.
-  if misc_info.get('avb_enable') == 'true':
-    RewriteAvbProps(misc_info)
 
   # Write back misc_info with the latest values.
   ReplaceMiscInfoTxt(input_tf_zip, output_tf_zip, misc_info)
@@ -1066,9 +1177,9 @@ def WriteOtacerts(output_zip, filename, keys):
   common.ZipWriteStr(output_zip, filename, temp_file.getvalue())
 
 
-def ReplaceOtaKeys(input_tf_zip, output_tf_zip, misc_info):
+def ReplaceOtaKeys(input_tf_zip: zipfile.ZipFile, output_tf_zip, misc_info):
   try:
-    keylist = input_tf_zip.read("META/otakeys.txt").split()
+    keylist = input_tf_zip.read("META/otakeys.txt").decode().split()
   except KeyError:
     raise common.ExternalError("can't read META/otakeys.txt from input")
 
diff --git a/tools/sbom/Android.bp b/tools/sbom/Android.bp
index 2b2b573234..4f6d3b7863 100644
--- a/tools/sbom/Android.bp
+++ b/tools/sbom/Android.bp
@@ -33,6 +33,31 @@ python_binary_host {
     ],
 }
 
+python_library_host {
+    name: "compliance_metadata",
+    srcs: [
+        "compliance_metadata.py",
+    ],
+}
+
+python_binary_host {
+    name: "gen_sbom",
+    srcs: [
+        "gen_sbom.py",
+    ],
+    version: {
+        py3: {
+            embedded_launcher: true,
+        },
+    },
+    libs: [
+        "compliance_metadata",
+        "metadata_file_proto_py",
+        "libprotobuf-python",
+        "sbom_lib",
+    ],
+}
+
 python_library_host {
     name: "sbom_lib",
     srcs: [
@@ -91,4 +116,18 @@ python_binary_host {
     libs: [
         "sbom_lib",
     ],
-}
\ No newline at end of file
+}
+
+python_binary_host {
+    name: "gen_notice_xml",
+    srcs: [
+        "gen_notice_xml.py",
+    ],
+    version: {
+        py3: {
+            embedded_launcher: true,
+        },
+    },
+    libs: [
+    ],
+}
diff --git a/tools/sbom/compliance_metadata.py b/tools/sbom/compliance_metadata.py
new file mode 100644
index 0000000000..9910217bbe
--- /dev/null
+++ b/tools/sbom/compliance_metadata.py
@@ -0,0 +1,204 @@
+#!/usr/bin/env python3
+#
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
+import sqlite3
+
+class MetadataDb:
+  def __init__(self, db):
+    self.conn = sqlite3.connect(':memory')
+    self.conn.row_factory = sqlite3.Row
+    with sqlite3.connect(db) as c:
+      c.backup(self.conn)
+    self.reorg()
+
+  def reorg(self):
+    # package_license table
+    self.conn.execute("create table package_license as "
+                      "select name as package, pkg_default_applicable_licenses as license "
+                      "from modules "
+                      "where module_type = 'package' ")
+    cursor = self.conn.execute("select package,license from package_license where license like '% %'")
+    multi_licenses_packages = cursor.fetchall()
+    cursor.close()
+    rows = []
+    for p in multi_licenses_packages:
+      licenses = p['license'].strip().split(' ')
+      for lic in licenses:
+        rows.append((p['package'], lic))
+    self.conn.executemany('insert into package_license values (?, ?)', rows)
+    self.conn.commit()
+
+    self.conn.execute("delete from package_license where license like '% %'")
+    self.conn.commit()
+
+    # module_license table
+    self.conn.execute("create table module_license as "
+                      "select distinct name as module, package, licenses as license "
+                      "from modules "
+                      "where licenses != '' ")
+    cursor = self.conn.execute("select module,package,license from module_license where license like '% %'")
+    multi_licenses_modules = cursor.fetchall()
+    cursor.close()
+    rows = []
+    for m in multi_licenses_modules:
+      licenses = m['license'].strip().split(' ')
+      for lic in licenses:
+        rows.append((m['module'], m['package'],lic))
+    self.conn.executemany('insert into module_license values (?, ?, ?)', rows)
+    self.conn.commit()
+
+    self.conn.execute("delete from module_license where license like '% %'")
+    self.conn.commit()
+
+    # module_installed_file table
+    self.conn.execute("create table module_installed_file as "
+                      "select id as module_id, name as module_name, package, installed_files as installed_file "
+                      "from modules "
+                      "where installed_files != '' ")
+    cursor = self.conn.execute("select module_id, module_name, package, installed_file "
+                               "from module_installed_file where installed_file like '% %'")
+    multi_installed_file_modules = cursor.fetchall()
+    cursor.close()
+    rows = []
+    for m in multi_installed_file_modules:
+      installed_files = m['installed_file'].strip().split(' ')
+      for f in installed_files:
+        rows.append((m['module_id'], m['module_name'], m['package'], f))
+    self.conn.executemany('insert into module_installed_file values (?, ?, ?, ?)', rows)
+    self.conn.commit()
+
+    self.conn.execute("delete from module_installed_file where installed_file like '% %'")
+    self.conn.commit()
+
+    # module_built_file table
+    self.conn.execute("create table module_built_file as "
+                      "select id as module_id, name as module_name, package, built_files as built_file "
+                      "from modules "
+                      "where built_files != '' ")
+    cursor = self.conn.execute("select module_id, module_name, package, built_file "
+                               "from module_built_file where built_file like '% %'")
+    multi_built_file_modules = cursor.fetchall()
+    cursor.close()
+    rows = []
+    for m in multi_built_file_modules:
+      built_files = m['installed_file'].strip().split(' ')
+      for f in built_files:
+        rows.append((m['module_id'], m['module_name'], m['package'], f))
+    self.conn.executemany('insert into module_built_file values (?, ?, ?, ?)', rows)
+    self.conn.commit()
+
+    self.conn.execute("delete from module_built_file where built_file like '% %'")
+    self.conn.commit()
+
+
+    # Indexes
+    self.conn.execute('create index idx_modules_id on modules (id)')
+    self.conn.execute('create index idx_modules_name on modules (name)')
+    self.conn.execute('create index idx_package_licnese_package on package_license (package)')
+    self.conn.execute('create index idx_package_licnese_license on package_license (license)')
+    self.conn.execute('create index idx_module_licnese_module on module_license (module)')
+    self.conn.execute('create index idx_module_licnese_license on module_license (license)')
+    self.conn.execute('create index idx_module_installed_file_module_id on module_installed_file (module_id)')
+    self.conn.execute('create index idx_module_installed_file_installed_file on module_installed_file (installed_file)')
+    self.conn.execute('create index idx_module_built_file_module_id on module_built_file (module_id)')
+    self.conn.execute('create index idx_module_built_file_built_file on module_built_file (built_file)')
+    self.conn.commit()
+
+  def dump_debug_db(self, debug_db):
+    with sqlite3.connect(debug_db) as c:
+      self.conn.backup(c)
+
+  def get_installed_files(self):
+    # Get all records from table make_metadata, which contains all installed files and corresponding make modules' metadata
+    cursor = self.conn.execute('select installed_file, module_path, is_prebuilt_make_module, product_copy_files, kernel_module_copy_files, is_platform_generated, license_text from make_metadata')
+    rows = cursor.fetchall()
+    cursor.close()
+    installed_files_metadata = []
+    for row in rows:
+      metadata = dict(zip(row.keys(), row))
+      installed_files_metadata.append(metadata)
+    return installed_files_metadata
+
+  def get_soong_modules(self):
+    # Get all records from table modules, which contains metadata of all soong modules
+    cursor = self.conn.execute('select name, package, package as module_path, module_type as soong_module_type, built_files, installed_files, static_dep_files, whole_static_dep_files from modules')
+    rows = cursor.fetchall()
+    cursor.close()
+    soong_modules = []
+    for row in rows:
+      soong_module = dict(zip(row.keys(), row))
+      soong_modules.append(soong_module)
+    return soong_modules
+
+  def get_package_licenses(self, package):
+    cursor = self.conn.execute('select m.name, m.package, m.lic_license_text as license_text '
+                               'from package_license pl join modules m on pl.license = m.name '
+                               'where pl.package = ?',
+                               ('//' + package,))
+    rows = cursor.fetchall()
+    licenses = {}
+    for r in rows:
+      licenses[r['name']] = r['license_text']
+    return licenses
+
+  def get_module_licenses(self, module_name, package):
+    licenses = {}
+    # If property "licenses" is defined on module
+    cursor = self.conn.execute('select m.name, m.package, m.lic_license_text as license_text '
+                               'from module_license ml join modules m on ml.license = m.name '
+                               'where ml.module = ? and ml.package = ?',
+                               (module_name, package))
+    rows = cursor.fetchall()
+    for r in rows:
+      licenses[r['name']] = r['license_text']
+    if len(licenses) > 0:
+      return licenses
+
+    # Use default package license
+    cursor = self.conn.execute('select m.name, m.package, m.lic_license_text as license_text '
+                               'from package_license pl join modules m on pl.license = m.name '
+                               'where pl.package = ?',
+                               ('//' + package,))
+    rows = cursor.fetchall()
+    for r in rows:
+      licenses[r['name']] = r['license_text']
+    return licenses
+
+  def get_soong_module_of_installed_file(self, installed_file):
+    cursor = self.conn.execute('select name, m.package, m.package as module_path, module_type as soong_module_type, built_files, installed_files, static_dep_files, whole_static_dep_files '
+                               'from modules m join module_installed_file mif on m.id = mif.module_id '
+                               'where mif.installed_file = ?',
+                               (installed_file,))
+    rows = cursor.fetchall()
+    cursor.close()
+    if rows:
+      soong_module = dict(zip(rows[0].keys(), rows[0]))
+      return soong_module
+
+    return None
+
+  def get_soong_module_of_built_file(self, built_file):
+    cursor = self.conn.execute('select name, m.package, m.package as module_path, module_type as soong_module_type, built_files, installed_files, static_dep_files, whole_static_dep_files '
+                               'from modules m join module_built_file mbf on m.id = mbf.module_id '
+                               'where mbf.built_file = ?',
+                               (built_file,))
+    rows = cursor.fetchall()
+    cursor.close()
+    if rows:
+      soong_module = dict(zip(rows[0].keys(), rows[0]))
+      return soong_module
+
+    return None
\ No newline at end of file
diff --git a/tools/sbom/gen_notice_xml.py b/tools/sbom/gen_notice_xml.py
new file mode 100644
index 0000000000..eaa6e5a74d
--- /dev/null
+++ b/tools/sbom/gen_notice_xml.py
@@ -0,0 +1,81 @@
+# !/usr/bin/env python3
+#
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
+"""
+Generate NOTICE.xml.gz of a partition.
+Usage example:
+  gen_notice_xml.py --output_file out/soong/.intermediate/.../NOTICE.xml.gz \
+              --metadata out/soong/compliance-metadata/aosp_cf_x86_64_phone/compliance-metadata.db \
+              --partition system \
+              --product_out out/target/vsoc_x86_64 \
+              --soong_out out/soong
+"""
+
+import argparse
+
+
+FILE_HEADER = '''\
+<?xml version="1.0" encoding="utf-8"?>
+<licenses>
+'''
+FILE_FOOTER = '''\
+</licenses>
+'''
+
+
+def get_args():
+  parser = argparse.ArgumentParser()
+  parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Print more information.')
+  parser.add_argument('-d', '--debug', action='store_true', default=True, help='Debug mode')
+  parser.add_argument('--output_file', required=True, help='The path of the generated NOTICE.xml.gz file.')
+  parser.add_argument('--partition', required=True, help='The name of partition for which the NOTICE.xml.gz is generated.')
+  parser.add_argument('--metadata', required=True, help='The path of compliance metadata DB file.')
+  parser.add_argument('--product_out', required=True, help='The path of PRODUCT_OUT, e.g. out/target/product/vsoc_x86_64.')
+  parser.add_argument('--soong_out', required=True, help='The path of Soong output directory, e.g. out/soong')
+
+  return parser.parse_args()
+
+
+def log(*info):
+  if args.verbose:
+    for i in info:
+      print(i)
+
+
+def new_file_name_tag(file_metadata, package_name):
+  file_path = file_metadata['installed_file'].removeprefix(args.product_out)
+  lib = 'Android'
+  if package_name:
+    lib = package_name
+  return f'<file-name contentId="" lib="{lib}">{file_path}</file-name>\n'
+
+
+def new_file_content_tag():
+  pass
+
+
+def main():
+  global args
+  args = get_args()
+  log('Args:', vars(args))
+
+  with open(args.output_file, 'w', encoding="utf-8") as notice_xml_file:
+    notice_xml_file.write(FILE_HEADER)
+    notice_xml_file.write(FILE_FOOTER)
+
+
+if __name__ == '__main__':
+  main()
diff --git a/tools/sbom/gen_sbom.py b/tools/sbom/gen_sbom.py
new file mode 100644
index 0000000000..9c3a8be9ef
--- /dev/null
+++ b/tools/sbom/gen_sbom.py
@@ -0,0 +1,740 @@
+# !/usr/bin/env python3
+#
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
+"""
+Generate the SBOM of the current target product in SPDX format.
+Usage example:
+  gen_sbom.py --output_file out/soong/sbom/aosp_cf_x86_64_phone/sbom.spdx \
+              --metadata out/soong/metadata/aosp_cf_x86_64_phone/metadata.db \
+              --product_out out/target/vsoc_x86_64
+              --soong_out out/soong
+              --build_version $(cat out/target/product/vsoc_x86_64/build_fingerprint.txt) \
+              --product_mfr=Google
+"""
+
+import argparse
+import compliance_metadata
+import datetime
+import google.protobuf.text_format as text_format
+import hashlib
+import os
+import pathlib
+import queue
+import metadata_file_pb2
+import sbom_data
+import sbom_writers
+
+# Package type
+PKG_SOURCE = 'SOURCE'
+PKG_UPSTREAM = 'UPSTREAM'
+PKG_PREBUILT = 'PREBUILT'
+
+# Security tag
+NVD_CPE23 = 'NVD-CPE2.3:'
+
+# Report
+ISSUE_NO_METADATA = 'No metadata generated in Make for installed files:'
+ISSUE_NO_METADATA_FILE = 'No METADATA file found for installed file:'
+ISSUE_METADATA_FILE_INCOMPLETE = 'METADATA file incomplete:'
+ISSUE_UNKNOWN_SECURITY_TAG_TYPE = 'Unknown security tag type:'
+ISSUE_INSTALLED_FILE_NOT_EXIST = 'Non-existent installed files:'
+ISSUE_NO_MODULE_FOUND_FOR_STATIC_DEP = 'No module found for static dependency files:'
+INFO_METADATA_FOUND_FOR_PACKAGE = 'METADATA file found for packages:'
+
+SOONG_PREBUILT_MODULE_TYPES = [
+    'android_app_import',
+    'android_library_import',
+    'cc_prebuilt_binary',
+    'cc_prebuilt_library',
+    'cc_prebuilt_library_headers',
+    'cc_prebuilt_library_shared',
+    'cc_prebuilt_library_static',
+    'cc_prebuilt_object',
+    'dex_import',
+    'java_import',
+    'java_sdk_library_import',
+    'java_system_modules_import',
+    'libclang_rt_prebuilt_library_static',
+    'libclang_rt_prebuilt_library_shared',
+    'llvm_prebuilt_library_static',
+    'ndk_prebuilt_object',
+    'ndk_prebuilt_shared_stl',
+    'nkd_prebuilt_static_stl',
+    'prebuilt_apex',
+    'prebuilt_bootclasspath_fragment',
+    'prebuilt_dsp',
+    'prebuilt_firmware',
+    'prebuilt_kernel_modules',
+    'prebuilt_rfsa',
+    'prebuilt_root',
+    'rust_prebuilt_dylib',
+    'rust_prebuilt_library',
+    'rust_prebuilt_rlib',
+    'vndk_prebuilt_shared',
+]
+
+THIRD_PARTY_IDENTIFIER_TYPES = [
+    # Types defined in metadata_file.proto
+    'Git',
+    'SVN',
+    'Hg',
+    'Darcs',
+    'VCS',
+    'Archive',
+    'PrebuiltByAlphabet',
+    'LocalSource',
+    'Other',
+    # OSV ecosystems defined at https://ossf.github.io/osv-schema/#affectedpackage-field.
+    'Go',
+    'npm',
+    'OSS-Fuzz',
+    'PyPI',
+    'RubyGems',
+    'crates.io',
+    'Hackage',
+    'GHC',
+    'Packagist',
+    'Maven',
+    'NuGet',
+    'Linux',
+    'Debian',
+    'Alpine',
+    'Hex',
+    'Android',
+    'GitHub Actions',
+    'Pub',
+    'ConanCenter',
+    'Rocky Linux',
+    'AlmaLinux',
+    'Bitnami',
+    'Photon OS',
+    'CRAN',
+    'Bioconductor',
+    'SwiftURL'
+]
+
+
+def get_args():
+  parser = argparse.ArgumentParser()
+  parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Print more information.')
+  parser.add_argument('-d', '--debug', action='store_true', default=False, help='Debug mode')
+  parser.add_argument('--output_file', required=True, help='The generated SBOM file in SPDX format.')
+  parser.add_argument('--metadata', required=True, help='The metadata DB file path.')
+  parser.add_argument('--product_out', required=True, help='The path of PRODUCT_OUT, e.g. out/target/product/vsoc_x86_64.')
+  parser.add_argument('--soong_out', required=True, help='The path of Soong output directory, e.g. out/soong')
+  parser.add_argument('--build_version', required=True, help='The build version.')
+  parser.add_argument('--product_mfr', required=True, help='The product manufacturer.')
+  parser.add_argument('--json', action='store_true', default=False, help='Generated SBOM file in SPDX JSON format')
+
+  return parser.parse_args()
+
+
+def log(*info):
+  if args.verbose:
+    for i in info:
+      print(i)
+
+
+def new_package_id(package_name, type):
+  return f'SPDXRef-{type}-{sbom_data.encode_for_spdxid(package_name)}'
+
+
+def new_file_id(file_path):
+  return f'SPDXRef-{sbom_data.encode_for_spdxid(file_path)}'
+
+
+def new_license_id(license_name):
+  return f'LicenseRef-{sbom_data.encode_for_spdxid(license_name)}'
+
+
+def checksum(file_path):
+  h = hashlib.sha1()
+  if os.path.islink(file_path):
+    h.update(os.readlink(file_path).encode('utf-8'))
+  else:
+    with open(file_path, 'rb') as f:
+      h.update(f.read())
+  return f'SHA1: {h.hexdigest()}'
+
+
+def is_soong_prebuilt_module(file_metadata):
+  return (file_metadata['soong_module_type'] and
+          file_metadata['soong_module_type'] in SOONG_PREBUILT_MODULE_TYPES)
+
+
+def is_source_package(file_metadata):
+  module_path = file_metadata['module_path']
+  return module_path.startswith('external/') and not is_prebuilt_package(file_metadata)
+
+
+def is_prebuilt_package(file_metadata):
+  module_path = file_metadata['module_path']
+  if module_path:
+    return (module_path.startswith('prebuilts/') or
+            is_soong_prebuilt_module(file_metadata) or
+            file_metadata['is_prebuilt_make_module'])
+
+  kernel_module_copy_files = file_metadata['kernel_module_copy_files']
+  if kernel_module_copy_files and not kernel_module_copy_files.startswith('ANDROID-GEN:'):
+    return True
+
+  return False
+
+
+def get_source_package_info(file_metadata, metadata_file_path):
+  """Return source package info exists in its METADATA file, currently including name, security tag
+  and external SBOM reference.
+
+  See go/android-spdx and go/android-sbom-gen for more details.
+  """
+  if not metadata_file_path:
+    return file_metadata['module_path'], []
+
+  metadata_proto = metadata_file_protos[metadata_file_path]
+  external_refs = []
+  for tag in metadata_proto.third_party.security.tag:
+    if tag.lower().startswith((NVD_CPE23 + 'cpe:2.3:').lower()):
+      external_refs.append(
+          sbom_data.PackageExternalRef(category=sbom_data.PackageExternalRefCategory.SECURITY,
+                                       type=sbom_data.PackageExternalRefType.cpe23Type,
+                                       locator=tag.removeprefix(NVD_CPE23)))
+    elif tag.lower().startswith((NVD_CPE23 + 'cpe:/').lower()):
+      external_refs.append(
+          sbom_data.PackageExternalRef(category=sbom_data.PackageExternalRefCategory.SECURITY,
+                                       type=sbom_data.PackageExternalRefType.cpe22Type,
+                                       locator=tag.removeprefix(NVD_CPE23)))
+
+  if metadata_proto.name:
+    return metadata_proto.name, external_refs
+  else:
+    return os.path.basename(metadata_file_path), external_refs  # return the directory name only as package name
+
+
+def get_prebuilt_package_name(file_metadata, metadata_file_path):
+  """Return name of a prebuilt package, which can be from the METADATA file, metadata file path,
+  module path or kernel module's source path if the installed file is a kernel module.
+
+  See go/android-spdx and go/android-sbom-gen for more details.
+  """
+  name = None
+  if metadata_file_path:
+    metadata_proto = metadata_file_protos[metadata_file_path]
+    if metadata_proto.name:
+      name = metadata_proto.name
+    else:
+      name = metadata_file_path
+  elif file_metadata['module_path']:
+    name = file_metadata['module_path']
+  elif file_metadata['kernel_module_copy_files']:
+    src_path = file_metadata['kernel_module_copy_files'].split(':')[0]
+    name = os.path.dirname(src_path)
+
+  return name.removeprefix('prebuilts/').replace('/', '-')
+
+
+def get_metadata_file_path(file_metadata):
+  """Search for METADATA file of a package and return its path."""
+  metadata_path = ''
+  if file_metadata['module_path']:
+    metadata_path = file_metadata['module_path']
+  elif file_metadata['kernel_module_copy_files']:
+    metadata_path = os.path.dirname(file_metadata['kernel_module_copy_files'].split(':')[0])
+
+  while metadata_path and not os.path.exists(metadata_path + '/METADATA'):
+    metadata_path = os.path.dirname(metadata_path)
+
+  return metadata_path
+
+
+def get_package_version(metadata_file_path):
+  """Return a package's version in its METADATA file."""
+  if not metadata_file_path:
+    return None
+  metadata_proto = metadata_file_protos[metadata_file_path]
+  return metadata_proto.third_party.version
+
+
+def get_package_homepage(metadata_file_path):
+  """Return a package's homepage URL in its METADATA file."""
+  if not metadata_file_path:
+    return None
+  metadata_proto = metadata_file_protos[metadata_file_path]
+  if metadata_proto.third_party.homepage:
+    return metadata_proto.third_party.homepage
+  for url in metadata_proto.third_party.url:
+    if url.type == metadata_file_pb2.URL.Type.HOMEPAGE:
+      return url.value
+
+  return None
+
+
+def get_package_download_location(metadata_file_path):
+  """Return a package's code repository URL in its METADATA file."""
+  if not metadata_file_path:
+    return None
+  metadata_proto = metadata_file_protos[metadata_file_path]
+  if metadata_proto.third_party.url:
+    urls = sorted(metadata_proto.third_party.url, key=lambda url: url.type)
+    if urls[0].type != metadata_file_pb2.URL.Type.HOMEPAGE:
+      return urls[0].value
+    elif len(urls) > 1:
+      return urls[1].value
+
+  return None
+
+
+def get_license_text(license_files):
+  license_text = ''
+  for license_file in license_files:
+    if args.debug:
+      license_text += '#### Content from ' + license_file + '\n'
+    else:
+      license_text += pathlib.Path(license_file).read_text(errors='replace') + '\n\n'
+  return license_text
+
+
+def get_sbom_fragments(installed_file_metadata, metadata_file_path):
+  """Return SPDX fragment of source/prebuilt packages, which usually contains a SOURCE/PREBUILT
+  package, a UPSTREAM package and an external SBOM document reference if sbom_ref defined in its
+  METADATA file.
+
+  See go/android-spdx and go/android-sbom-gen for more details.
+  """
+  external_doc_ref = None
+  packages = []
+  relationships = []
+  licenses = []
+
+  # Info from METADATA file
+  homepage = get_package_homepage(metadata_file_path)
+  version = get_package_version(metadata_file_path)
+  download_location = get_package_download_location(metadata_file_path)
+
+  lics = db.get_package_licenses(installed_file_metadata['module_path'])
+  if not lics:
+    lics = db.get_package_licenses(metadata_file_path)
+
+  if lics:
+    for license_name, license_files in lics.items():
+      if not license_files:
+        continue
+      license_id = new_license_id(license_name)
+      if license_name not in licenses_text:
+        licenses_text[license_name] = get_license_text(license_files.split(' '))
+      licenses.append(sbom_data.License(id=license_id, name=license_name, text=licenses_text[license_name]))
+
+  if is_source_package(installed_file_metadata):
+    # Source fork packages
+    name, external_refs = get_source_package_info(installed_file_metadata, metadata_file_path)
+    source_package_id = new_package_id(name, PKG_SOURCE)
+    source_package = sbom_data.Package(id=source_package_id, name=name, version=args.build_version,
+                                       download_location=sbom_data.VALUE_NONE,
+                                       supplier='Organization: ' + args.product_mfr,
+                                       external_refs=external_refs)
+
+    upstream_package_id = new_package_id(name, PKG_UPSTREAM)
+    upstream_package = sbom_data.Package(id=upstream_package_id, name=name, version=version,
+                                         supplier=(
+                                               'Organization: ' + homepage) if homepage else sbom_data.VALUE_NOASSERTION,
+                                         download_location=download_location)
+    packages += [source_package, upstream_package]
+    relationships.append(sbom_data.Relationship(id1=source_package_id,
+                                                relationship=sbom_data.RelationshipType.VARIANT_OF,
+                                                id2=upstream_package_id))
+
+    for license in licenses:
+      source_package.declared_license_ids.append(license.id)
+      upstream_package.declared_license_ids.append(license.id)
+
+  elif is_prebuilt_package(installed_file_metadata):
+    # Prebuilt fork packages
+    name = get_prebuilt_package_name(installed_file_metadata, metadata_file_path)
+    prebuilt_package_id = new_package_id(name, PKG_PREBUILT)
+    prebuilt_package = sbom_data.Package(id=prebuilt_package_id,
+                                         name=name,
+                                         download_location=sbom_data.VALUE_NONE,
+                                         version=version if version else args.build_version,
+                                         supplier='Organization: ' + args.product_mfr)
+
+    upstream_package_id = new_package_id(name, PKG_UPSTREAM)
+    upstream_package = sbom_data.Package(id=upstream_package_id, name=name, version=version,
+                                         supplier=(
+                                               'Organization: ' + homepage) if homepage else sbom_data.VALUE_NOASSERTION,
+                                         download_location=download_location)
+    packages += [prebuilt_package, upstream_package]
+    relationships.append(sbom_data.Relationship(id1=prebuilt_package_id,
+                                                relationship=sbom_data.RelationshipType.VARIANT_OF,
+                                                id2=upstream_package_id))
+    for license in licenses:
+      prebuilt_package.declared_license_ids.append(license.id)
+      upstream_package.declared_license_ids.append(license.id)
+
+  if metadata_file_path:
+    metadata_proto = metadata_file_protos[metadata_file_path]
+    if metadata_proto.third_party.WhichOneof('sbom') == 'sbom_ref':
+      sbom_url = metadata_proto.third_party.sbom_ref.url
+      sbom_checksum = metadata_proto.third_party.sbom_ref.checksum
+      upstream_element_id = metadata_proto.third_party.sbom_ref.element_id
+      if sbom_url and sbom_checksum and upstream_element_id:
+        doc_ref_id = f'DocumentRef-{PKG_UPSTREAM}-{sbom_data.encode_for_spdxid(name)}'
+        external_doc_ref = sbom_data.DocumentExternalReference(id=doc_ref_id,
+                                                               uri=sbom_url,
+                                                               checksum=sbom_checksum)
+        relationships.append(
+            sbom_data.Relationship(id1=upstream_package_id,
+                                   relationship=sbom_data.RelationshipType.VARIANT_OF,
+                                   id2=doc_ref_id + ':' + upstream_element_id))
+
+  return external_doc_ref, packages, relationships, licenses
+
+
+def save_report(report_file_path, report):
+  with open(report_file_path, 'w', encoding='utf-8') as report_file:
+    for type, issues in report.items():
+      report_file.write(type + '\n')
+      for issue in issues:
+        report_file.write('\t' + issue + '\n')
+      report_file.write('\n')
+
+
+# Validate the metadata generated by Make for installed files and report if there is no metadata.
+def installed_file_has_metadata(installed_file_metadata, report):
+  installed_file = installed_file_metadata['installed_file']
+  module_path = installed_file_metadata['module_path']
+  product_copy_files = installed_file_metadata['product_copy_files']
+  kernel_module_copy_files = installed_file_metadata['kernel_module_copy_files']
+  is_platform_generated = installed_file_metadata['is_platform_generated']
+
+  if (not module_path and
+      not product_copy_files and
+      not kernel_module_copy_files and
+      not is_platform_generated and
+      not installed_file.endswith('.fsv_meta')):
+    report[ISSUE_NO_METADATA].append(installed_file)
+    return False
+
+  return True
+
+
+# Validate identifiers in a package's METADATA.
+# 1) Only known identifier type is allowed
+# 2) Only one identifier's primary_source can be true
+def validate_package_metadata(metadata_file_path, package_metadata):
+  primary_source_found = False
+  for identifier in package_metadata.third_party.identifier:
+    if identifier.type not in THIRD_PARTY_IDENTIFIER_TYPES:
+      sys.exit(f'Unknown value of third_party.identifier.type in {metadata_file_path}/METADATA: {identifier.type}.')
+    if primary_source_found and identifier.primary_source:
+      sys.exit(
+          f'Field "primary_source" is set to true in multiple third_party.identifier in {metadata_file_path}/METADATA.')
+    primary_source_found = identifier.primary_source
+
+
+def report_metadata_file(metadata_file_path, installed_file_metadata, report):
+  if metadata_file_path:
+    report[INFO_METADATA_FOUND_FOR_PACKAGE].append(
+        'installed_file: {}, module_path: {}, METADATA file: {}'.format(
+            installed_file_metadata['installed_file'],
+            installed_file_metadata['module_path'],
+            metadata_file_path + '/METADATA'))
+
+    package_metadata = metadata_file_pb2.Metadata()
+    with open(metadata_file_path + '/METADATA', 'rt') as f:
+      text_format.Parse(f.read(), package_metadata)
+
+    validate_package_metadata(metadata_file_path, package_metadata)
+
+    if not metadata_file_path in metadata_file_protos:
+      metadata_file_protos[metadata_file_path] = package_metadata
+      if not package_metadata.name:
+        report[ISSUE_METADATA_FILE_INCOMPLETE].append(f'{metadata_file_path}/METADATA does not has "name"')
+
+      if not package_metadata.third_party.version:
+        report[ISSUE_METADATA_FILE_INCOMPLETE].append(
+            f'{metadata_file_path}/METADATA does not has "third_party.version"')
+
+      for tag in package_metadata.third_party.security.tag:
+        if not tag.startswith(NVD_CPE23):
+          report[ISSUE_UNKNOWN_SECURITY_TAG_TYPE].append(
+              f'Unknown security tag type: {tag} in {metadata_file_path}/METADATA')
+  else:
+    report[ISSUE_NO_METADATA_FILE].append(
+        "installed_file: {}, module_path: {}".format(
+            installed_file_metadata['installed_file'], installed_file_metadata['module_path']))
+
+
+# If a file is from a source fork or prebuilt fork package, add its package information to SBOM
+def add_package_of_file(file_id, file_metadata, doc, report):
+  metadata_file_path = get_metadata_file_path(file_metadata)
+  report_metadata_file(metadata_file_path, file_metadata, report)
+
+  external_doc_ref, pkgs, rels, licenses = get_sbom_fragments(file_metadata, metadata_file_path)
+  if len(pkgs) > 0:
+    if external_doc_ref:
+      doc.add_external_ref(external_doc_ref)
+    for p in pkgs:
+      doc.add_package(p)
+    for rel in rels:
+      doc.add_relationship(rel)
+    fork_package_id = pkgs[0].id  # The first package should be the source/prebuilt fork package
+    doc.add_relationship(sbom_data.Relationship(id1=file_id,
+                                                relationship=sbom_data.RelationshipType.GENERATED_FROM,
+                                                id2=fork_package_id))
+    for license in licenses:
+      doc.add_license(license)
+
+
+# Add STATIC_LINK relationship for static dependencies of a file
+def add_static_deps_of_file(file_id, file_metadata, doc):
+  if not file_metadata['static_dep_files'] and not file_metadata['whole_static_dep_files']:
+    return
+  static_dep_files = []
+  if file_metadata['static_dep_files']:
+    static_dep_files += file_metadata['static_dep_files'].split(' ')
+  if file_metadata['whole_static_dep_files']:
+    static_dep_files += file_metadata['whole_static_dep_files'].split(' ')
+
+  for dep_file in static_dep_files:
+    # Static libs are not shipped on devices, so names are derived from .intermediates paths.
+    doc.add_relationship(sbom_data.Relationship(id1=file_id,
+                                                relationship=sbom_data.RelationshipType.STATIC_LINK,
+                                                id2=new_file_id(
+                                                  dep_file.removeprefix(args.soong_out + '/.intermediates/'))))
+
+
+def add_licenses_of_file(file_id, file_metadata, doc):
+  lics = db.get_module_licenses(file_metadata.get('name', ''), file_metadata['module_path'])
+  if lics:
+    file = next(f for f in doc.files if file_id == f.id)
+    for license_name, license_files in lics.items():
+      if not license_files:
+        continue
+      license_id = new_license_id(license_name)
+      file.concluded_license_ids.append(license_id)
+      if license_name not in licenses_text:
+        license_text = get_license_text(license_files.split(' '))
+        licenses_text[license_name] = license_text
+
+      doc.add_license(sbom_data.License(id=license_id, name=license_name, text=licenses_text[license_name]))
+
+
+def get_all_transitive_static_dep_files_of_installed_files(installed_files_metadata, db, report):
+  # Find all transitive static dep files of all installed files
+  q = queue.Queue()
+  for installed_file_metadata in installed_files_metadata:
+    if installed_file_metadata['static_dep_files']:
+      for f in installed_file_metadata['static_dep_files'].split(' '):
+        q.put(f)
+    if installed_file_metadata['whole_static_dep_files']:
+      for f in installed_file_metadata['whole_static_dep_files'].split(' '):
+        q.put(f)
+
+  all_static_dep_files = {}
+  while not q.empty():
+    dep_file = q.get()
+    if dep_file in all_static_dep_files:
+      # It has been processed
+      continue
+
+    all_static_dep_files[dep_file] = True
+    soong_module = db.get_soong_module_of_built_file(dep_file)
+    if not soong_module:
+      # This should not happen, add to report[ISSUE_NO_MODULE_FOUND_FOR_STATIC_DEP]
+      report[ISSUE_NO_MODULE_FOUND_FOR_STATIC_DEP].append(f)
+      continue
+
+    if soong_module['static_dep_files']:
+      for f in soong_module['static_dep_files'].split(' '):
+        if f not in all_static_dep_files:
+          q.put(f)
+    if soong_module['whole_static_dep_files']:
+      for f in soong_module['whole_static_dep_files'].split(' '):
+        if f not in all_static_dep_files:
+          q.put(f)
+
+  return sorted(all_static_dep_files.keys())
+
+
+def main():
+  global args
+  args = get_args()
+  log('Args:', vars(args))
+
+  global db
+  db = compliance_metadata.MetadataDb(args.metadata)
+  if args.debug:
+    db.dump_debug_db(os.path.dirname(args.output_file) + '/compliance-metadata-debug.db')
+
+  global metadata_file_protos
+  metadata_file_protos = {}
+  global licenses_text
+  licenses_text = {}
+
+  product_package_id = sbom_data.SPDXID_PRODUCT
+  product_package_name = sbom_data.PACKAGE_NAME_PRODUCT
+  product_package = sbom_data.Package(id=product_package_id,
+                                      name=product_package_name,
+                                      download_location=sbom_data.VALUE_NONE,
+                                      version=args.build_version,
+                                      supplier='Organization: ' + args.product_mfr,
+                                      files_analyzed=True)
+  doc_name = args.build_version
+  doc = sbom_data.Document(name=doc_name,
+                           namespace=f'https://www.google.com/sbom/spdx/android/{doc_name}',
+                           creators=['Organization: ' + args.product_mfr],
+                           describes=product_package_id)
+
+  doc.packages.append(product_package)
+  doc.packages.append(sbom_data.Package(id=sbom_data.SPDXID_PLATFORM,
+                                        name=sbom_data.PACKAGE_NAME_PLATFORM,
+                                        download_location=sbom_data.VALUE_NONE,
+                                        version=args.build_version,
+                                        supplier='Organization: ' + args.product_mfr,
+                                        declared_license_ids=[sbom_data.SPDXID_LICENSE_APACHE]))
+
+  # Report on some issues and information
+  report = {
+      ISSUE_NO_METADATA: [],
+      ISSUE_NO_METADATA_FILE: [],
+      ISSUE_METADATA_FILE_INCOMPLETE: [],
+      ISSUE_UNKNOWN_SECURITY_TAG_TYPE: [],
+      ISSUE_INSTALLED_FILE_NOT_EXIST: [],
+      ISSUE_NO_MODULE_FOUND_FOR_STATIC_DEP: [],
+      INFO_METADATA_FOUND_FOR_PACKAGE: [],
+  }
+
+  # Get installed files and corresponding make modules' metadata if an installed file is from a make module.
+  installed_files_metadata = db.get_installed_files()
+
+  # Find which Soong module an installed file is from and merge metadata from Make and Soong
+  for installed_file_metadata in installed_files_metadata:
+    soong_module = db.get_soong_module_of_installed_file(installed_file_metadata['installed_file'])
+    if soong_module:
+      # Merge soong metadata to make metadata
+      installed_file_metadata.update(soong_module)
+    else:
+      # For make modules soong_module_type should be empty
+      installed_file_metadata['soong_module_type'] = ''
+      installed_file_metadata['static_dep_files'] = ''
+      installed_file_metadata['whole_static_dep_files'] = ''
+
+  # Scan the metadata and create the corresponding package and file records in SPDX
+  for installed_file_metadata in installed_files_metadata:
+    installed_file = installed_file_metadata['installed_file']
+    module_path = installed_file_metadata['module_path']
+    product_copy_files = installed_file_metadata['product_copy_files']
+    kernel_module_copy_files = installed_file_metadata['kernel_module_copy_files']
+    build_output_path = installed_file
+    installed_file = installed_file.removeprefix(args.product_out)
+
+    if not installed_file_has_metadata(installed_file_metadata, report):
+      continue
+    if not (os.path.islink(build_output_path) or os.path.isfile(build_output_path)):
+      report[ISSUE_INSTALLED_FILE_NOT_EXIST].append(installed_file)
+      continue
+
+    file_id = new_file_id(installed_file)
+    sha1 = checksum(build_output_path)
+    f = sbom_data.File(id=file_id, name=installed_file, checksum=sha1)
+    doc.files.append(f)
+    product_package.file_ids.append(file_id)
+
+    if is_source_package(installed_file_metadata) or is_prebuilt_package(installed_file_metadata):
+      add_package_of_file(file_id, installed_file_metadata, doc, report)
+
+    elif module_path or installed_file_metadata['is_platform_generated']:
+      # File from PLATFORM package
+      doc.add_relationship(sbom_data.Relationship(id1=file_id,
+                                                  relationship=sbom_data.RelationshipType.GENERATED_FROM,
+                                                  id2=sbom_data.SPDXID_PLATFORM))
+      if installed_file_metadata['is_platform_generated']:
+        f.concluded_license_ids = [sbom_data.SPDXID_LICENSE_APACHE]
+
+    elif product_copy_files:
+      # Format of product_copy_files: <source path>:<dest path>
+      src_path = product_copy_files.split(':')[0]
+      # So far product_copy_files are copied from directory system, kernel, hardware, frameworks and device,
+      # so process them as files from PLATFORM package
+      doc.add_relationship(sbom_data.Relationship(id1=file_id,
+                                                  relationship=sbom_data.RelationshipType.GENERATED_FROM,
+                                                  id2=sbom_data.SPDXID_PLATFORM))
+      if installed_file_metadata['license_text']:
+        if installed_file_metadata['license_text'] == 'build/soong/licenses/LICENSE':
+          f.concluded_license_ids = [sbom_data.SPDXID_LICENSE_APACHE]
+
+    elif installed_file.endswith('.fsv_meta'):
+      doc.add_relationship(sbom_data.Relationship(id1=file_id,
+                                                  relationship=sbom_data.RelationshipType.GENERATED_FROM,
+                                                  id2=sbom_data.SPDXID_PLATFORM))
+      f.concluded_license_ids = [sbom_data.SPDXID_LICENSE_APACHE]
+
+    elif kernel_module_copy_files.startswith('ANDROID-GEN'):
+      # For the four files generated for _dlkm, _ramdisk partitions
+      doc.add_relationship(sbom_data.Relationship(id1=file_id,
+                                                  relationship=sbom_data.RelationshipType.GENERATED_FROM,
+                                                  id2=sbom_data.SPDXID_PLATFORM))
+
+    # Process static dependencies of the installed file
+    add_static_deps_of_file(file_id, installed_file_metadata, doc)
+
+    # Add licenses of the installed file
+    add_licenses_of_file(file_id, installed_file_metadata, doc)
+
+  # Add all static library files to SBOM
+  for dep_file in get_all_transitive_static_dep_files_of_installed_files(installed_files_metadata, db, report):
+    filepath = dep_file.removeprefix(args.soong_out + '/.intermediates/')
+    file_id = new_file_id(filepath)
+    # SHA1 of empty string. Sometimes .a files might not be built.
+    sha1 = 'SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709'
+    if os.path.islink(dep_file) or os.path.isfile(dep_file):
+      sha1 = checksum(dep_file)
+    doc.files.append(sbom_data.File(id=file_id,
+                                    name=filepath,
+                                    checksum=sha1))
+    file_metadata = {
+        'installed_file': dep_file,
+        'is_prebuilt_make_module': False
+    }
+    file_metadata.update(db.get_soong_module_of_built_file(dep_file))
+    add_package_of_file(file_id, file_metadata, doc, report)
+
+    # Add relationships for static deps of static libraries
+    add_static_deps_of_file(file_id, file_metadata, doc)
+
+    # Add licenses of the static lib
+    add_licenses_of_file(file_id, file_metadata, doc)
+
+  # Save SBOM records to output file
+  doc.generate_packages_verification_code()
+  doc.created = datetime.datetime.now(tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
+  prefix = args.output_file
+  if prefix.endswith('.spdx'):
+    prefix = prefix.removesuffix('.spdx')
+  elif prefix.endswith('.spdx.json'):
+    prefix = prefix.removesuffix('.spdx.json')
+
+  output_file = prefix + '.spdx'
+  with open(output_file, 'w', encoding="utf-8") as file:
+    sbom_writers.TagValueWriter.write(doc, file)
+  if args.json:
+    with open(prefix + '.spdx.json', 'w', encoding="utf-8") as file:
+      sbom_writers.JSONWriter.write(doc, file)
+
+  save_report(prefix + '-gen-report.txt', report)
+
+
+if __name__ == '__main__':
+  main()
diff --git a/tools/sbom/generate-sbom-framework_res.py b/tools/sbom/generate-sbom-framework_res.py
index d0d232d635..27f3d2ebc1 100644
--- a/tools/sbom/generate-sbom-framework_res.py
+++ b/tools/sbom/generate-sbom-framework_res.py
@@ -80,7 +80,8 @@ def main():
 
   resource_file_spdxids = []
   for file in layoutlib_sbom[sbom_writers.PropNames.FILES]:
-    if file[sbom_writers.PropNames.FILE_NAME].startswith('data/res/'):
+    file_path = file[sbom_writers.PropNames.FILE_NAME]
+    if file_path.startswith('data/res/') or file_path.startswith('data/overlays/'):
       resource_file_spdxids.append(file[sbom_writers.PropNames.SPDXID])
 
   doc.relationships = [
diff --git a/tools/sbom/sbom_data.py b/tools/sbom/sbom_data.py
index b5ac8a59c3..fc5c704cf1 100644
--- a/tools/sbom/sbom_data.py
+++ b/tools/sbom/sbom_data.py
@@ -30,6 +30,7 @@ import hashlib
 SPDXID_DOC = 'SPDXRef-DOCUMENT'
 SPDXID_PRODUCT = 'SPDXRef-PRODUCT'
 SPDXID_PLATFORM = 'SPDXRef-PLATFORM'
+SPDXID_LICENSE_APACHE = 'LicenseRef-Android-Apache-2.0'
 
 PACKAGE_NAME_PRODUCT = 'PRODUCT'
 PACKAGE_NAME_PLATFORM = 'PLATFORM'
@@ -50,7 +51,7 @@ class PackageExternalRefType:
   cpe23Type = 'cpe23Type'
 
 
-@dataclass
+@dataclass(frozen=True)
 class PackageExternalRef:
   category: PackageExternalRefCategory
   type: PackageExternalRefType
@@ -68,6 +69,7 @@ class Package:
   verification_code: str = None
   file_ids: List[str] = field(default_factory=list)
   external_refs: List[PackageExternalRef] = field(default_factory=list)
+  declared_license_ids: List[str] = field(default_factory=list)
 
 
 @dataclass
@@ -75,6 +77,7 @@ class File:
   id: str
   name: str
   checksum: str
+  concluded_license_ids: List[str] = field(default_factory=list)
 
 
 class RelationshipType:
@@ -85,20 +88,27 @@ class RelationshipType:
   STATIC_LINK = 'STATIC_LINK'
 
 
-@dataclass
+@dataclass(frozen=True)
 class Relationship:
   id1: str
   relationship: RelationshipType
   id2: str
 
 
-@dataclass
+@dataclass(frozen=True)
 class DocumentExternalReference:
   id: str
   uri: str
   checksum: str
 
 
+@dataclass(frozen=True)
+class License:
+  id: str
+  text: str
+  name: str
+
+
 @dataclass
 class Document:
   name: str
@@ -111,20 +121,30 @@ class Document:
   packages: List[Package] = field(default_factory=list)
   files: List[File] = field(default_factory=list)
   relationships: List[Relationship] = field(default_factory=list)
+  licenses: List[License] = field(default_factory=list)
 
   def add_external_ref(self, external_ref):
     if not any(external_ref.uri == ref.uri for ref in self.external_refs):
       self.external_refs.append(external_ref)
 
   def add_package(self, package):
-    if not any(package.id == p.id for p in self.packages):
+    p = next((p for p in self.packages if package.id == p.id), None)
+    if not p:
       self.packages.append(package)
+    else:
+      for license_id in package.declared_license_ids:
+        if license_id not in p.declared_license_ids:
+          p.declared_license_ids.append(license_id)
 
   def add_relationship(self, rel):
     if not any(rel.id1 == r.id1 and rel.id2 == r.id2 and rel.relationship == r.relationship
                for r in self.relationships):
       self.relationships.append(rel)
 
+  def add_license(self, license):
+    if not any(license.id == l.id for l in self.licenses):
+      self.licenses.append(license)
+
   def generate_packages_verification_code(self):
     for package in self.packages:
       if not package.file_ids:
diff --git a/tools/sbom/sbom_data_test.py b/tools/sbom/sbom_data_test.py
index 69bc9d2d29..9d987c4dfb 100644
--- a/tools/sbom/sbom_data_test.py
+++ b/tools/sbom/sbom_data_test.py
@@ -23,6 +23,7 @@ SUPPLIER_GOOGLE = 'Organization: Google'
 SUPPLIER_UPSTREAM = 'Organization: upstream'
 
 SPDXID_PREBUILT_PACKAGE1 = 'SPDXRef-PREBUILT-package1'
+SPDXID_PREBUILT_PACKAGE2 = 'SPDXRef-PREBUILT-package2'
 SPDXID_SOURCE_PACKAGE1 = 'SPDXRef-SOURCE-package1'
 SPDXID_UPSTREAM_PACKAGE1 = 'SPDXRef-UPSTREAM-package1'
 
@@ -31,6 +32,9 @@ SPDXID_FILE2 = 'SPDXRef-file2'
 SPDXID_FILE3 = 'SPDXRef-file3'
 SPDXID_FILE4 = 'SPDXRef-file4'
 
+SPDXID_LICENSE1 = "SPDXRef-License-1"
+SPDXID_LICENSE2 = "SPDXRef-License-2"
+
 
 class SBOMDataTest(unittest.TestCase):
 
@@ -134,6 +138,47 @@ class SBOMDataTest(unittest.TestCase):
     self.sbom_doc.generate_packages_verification_code()
     self.assertEqual(expected_package_verification_code, self.sbom_doc.packages[0].verification_code)
 
+  def test_add_package_(self):
+    self.sbom_doc.add_package(sbom_data.Package(id=SPDXID_PREBUILT_PACKAGE2,
+                                                name='Prebuilt package2',
+                                                download_location=sbom_data.VALUE_NONE,
+                                                supplier=SUPPLIER_GOOGLE,
+                                                version=BUILD_FINGER_PRINT,
+                                                ))
+    p = next((p for p in self.sbom_doc.packages if p.id == SPDXID_PREBUILT_PACKAGE2), None)
+    self.assertNotEqual(p, None)
+    self.assertEqual(p.declared_license_ids, [])
+
+    # Add same package with license 1
+    self.sbom_doc.add_package(sbom_data.Package(id=SPDXID_PREBUILT_PACKAGE2,
+                                                name='Prebuilt package2',
+                                                download_location=sbom_data.VALUE_NONE,
+                                                supplier=SUPPLIER_GOOGLE,
+                                                version=BUILD_FINGER_PRINT,
+                                                declared_license_ids=[SPDXID_LICENSE1]
+                                                ))
+    self.assertEqual(p.declared_license_ids, [SPDXID_LICENSE1])
+
+    # Add same package with license 2
+    self.sbom_doc.add_package(sbom_data.Package(id=SPDXID_PREBUILT_PACKAGE2,
+                                                name='Prebuilt package2',
+                                                download_location=sbom_data.VALUE_NONE,
+                                                supplier=SUPPLIER_GOOGLE,
+                                                version=BUILD_FINGER_PRINT,
+                                                declared_license_ids=[SPDXID_LICENSE2]
+                                                ))
+    self.assertEqual(p.declared_license_ids, [SPDXID_LICENSE1, SPDXID_LICENSE2])
+
+    # Add same package with license 2 again
+    self.sbom_doc.add_package(sbom_data.Package(id=SPDXID_PREBUILT_PACKAGE2,
+                                                name='Prebuilt package2',
+                                                download_location=sbom_data.VALUE_NONE,
+                                                supplier=SUPPLIER_GOOGLE,
+                                                version=BUILD_FINGER_PRINT,
+                                                declared_license_ids=[SPDXID_LICENSE2]
+                                                ))
+    self.assertEqual(p.declared_license_ids, [SPDXID_LICENSE1, SPDXID_LICENSE2])
+
 
 if __name__ == '__main__':
   unittest.main(verbosity=2)
diff --git a/tools/sbom/sbom_writers.py b/tools/sbom/sbom_writers.py
index 1cb864db75..26b3c57f34 100644
--- a/tools/sbom/sbom_writers.py
+++ b/tools/sbom/sbom_writers.py
@@ -64,6 +64,11 @@ class Tags:
   # Relationship
   RELATIONSHIP = 'Relationship'
 
+  # License
+  LICENSE_ID = 'LicenseID'
+  LICENSE_NAME = 'LicenseName'
+  LICENSE_EXTRACTED_TEXT = 'ExtractedText'
+
 
 class TagValueWriter:
   @staticmethod
@@ -99,6 +104,12 @@ class TagValueWriter:
       tagvalues.append(f'{Tags.PACKAGE_VERSION}: {package.version}')
     if package.supplier:
       tagvalues.append(f'{Tags.PACKAGE_SUPPLIER}: {package.supplier}')
+
+    license = sbom_data.VALUE_NOASSERTION
+    if package.declared_license_ids:
+      license = ' OR '.join(package.declared_license_ids)
+    tagvalues.append(f'{Tags.PACKAGE_LICENSE_DECLARED}: {license}')
+
     if package.verification_code:
       tagvalues.append(f'{Tags.PACKAGE_VERIFICATION_CODE}: {package.verification_code}')
     if package.external_refs:
@@ -155,8 +166,12 @@ class TagValueWriter:
       f'{Tags.FILE_NAME}: {file.name}',
       f'{Tags.SPDXID}: {file.id}',
       f'{Tags.FILE_CHECKSUM}: {file.checksum}',
-      '',
     ]
+    license = sbom_data.VALUE_NOASSERTION
+    if file.concluded_license_ids:
+      license = ' OR '.join(file.concluded_license_ids)
+    tagvalues.append(f'{Tags.FILE_LICENSE_CONCLUDED}: {license}')
+    tagvalues.append('')
 
     return tagvalues
 
@@ -193,6 +208,22 @@ class TagValueWriter:
     tagvalues.append('')
     return tagvalues
 
+  @staticmethod
+  def marshal_license(license):
+    tagvalues = []
+    tagvalues.append(f'{Tags.LICENSE_ID}: {license.id}')
+    tagvalues.append(f'{Tags.LICENSE_NAME}: {license.name}')
+    tagvalues.append(f'{Tags.LICENSE_EXTRACTED_TEXT}: <text>{license.text}</text>')
+    return tagvalues
+
+  @staticmethod
+  def marshal_licenses(sbom_doc):
+    tagvalues = []
+    for license in sbom_doc.licenses:
+      tagvalues += TagValueWriter.marshal_license(license)
+      tagvalues.append('')
+    return tagvalues
+
   @staticmethod
   def write(sbom_doc, file, fragment=False):
     content = []
@@ -202,6 +233,7 @@ class TagValueWriter:
     tagvalues, marshaled_relationships = TagValueWriter.marshal_packages(sbom_doc, fragment)
     content += tagvalues
     content += TagValueWriter.marshal_relationships(sbom_doc, marshaled_relationships)
+    content += TagValueWriter.marshal_licenses(sbom_doc)
     file.write('\n'.join(content))
 
 
@@ -236,11 +268,13 @@ class PropNames:
   PACKAGE_EXTERNAL_REF_TYPE = 'referenceType'
   PACKAGE_EXTERNAL_REF_LOCATOR = 'referenceLocator'
   PACKAGE_HAS_FILES = 'hasFiles'
+  PACKAGE_LICENSE_DECLARED = 'licenseDeclared'
 
   # File
   FILES = 'files'
   FILE_NAME = 'fileName'
   FILE_CHECKSUMS = 'checksums'
+  FILE_LICENSE_CONCLUDED = 'licenseConcluded'
 
   # Relationship
   RELATIONSHIPS = 'relationships'
@@ -248,6 +282,12 @@ class PropNames:
   REL_RELATED_ELEMENT_ID = 'relatedSpdxElement'
   REL_TYPE = 'relationshipType'
 
+  # License
+  LICENSES = 'hasExtractedLicensingInfos'
+  LICENSE_ID = 'licenseId'
+  LICENSE_NAME = 'name'
+  LICENSE_EXTRACTED_TEXT = 'extractedText'
+
 
 class JSONWriter:
   @staticmethod
@@ -294,6 +334,9 @@ class JSONWriter:
         package[PropNames.PACKAGE_VERSION] = p.version
       if p.supplier:
         package[PropNames.PACKAGE_SUPPLIER] = p.supplier
+      package[PropNames.PACKAGE_LICENSE_DECLARED] = sbom_data.VALUE_NOASSERTION
+      if p.declared_license_ids:
+        package[PropNames.PACKAGE_LICENSE_DECLARED] = ' OR '.join(p.declared_license_ids)
       if p.verification_code:
         package[PropNames.PACKAGE_VERIFICATION_CODE] = {
           PropNames.PACKAGE_VERIFICATION_CODE_VALUE: p.verification_code
@@ -329,6 +372,9 @@ class JSONWriter:
         PropNames.ALGORITHM: checksum[0],
         PropNames.CHECKSUM_VALUE: checksum[1],
       }]
+      file[PropNames.FILE_LICENSE_CONCLUDED] = sbom_data.VALUE_NOASSERTION
+      if f.concluded_license_ids:
+        file[PropNames.FILE_LICENSE_CONCLUDED] = ' OR '.join(f.concluded_license_ids)
       files.append(file)
     return {PropNames.FILES: files}
 
@@ -346,6 +392,17 @@ class JSONWriter:
 
     return {PropNames.RELATIONSHIPS: relationships}
 
+  @staticmethod
+  def marshal_licenses(sbom_doc):
+    licenses = []
+    for l in sbom_doc.licenses:
+      licenses.append({
+          PropNames.LICENSE_ID: l.id,
+          PropNames.LICENSE_NAME: l.name,
+          PropNames.LICENSE_EXTRACTED_TEXT: f'<text>{l.text}</text>'
+      })
+    return {PropNames.LICENSES: licenses}
+
   @staticmethod
   def write(sbom_doc, file):
     doc = {}
@@ -353,4 +410,5 @@ class JSONWriter:
     doc.update(JSONWriter.marshal_packages(sbom_doc))
     doc.update(JSONWriter.marshal_files(sbom_doc))
     doc.update(JSONWriter.marshal_relationships(sbom_doc))
+    doc.update(JSONWriter.marshal_licenses(sbom_doc))
     file.write(json.dumps(doc, indent=4))
diff --git a/tools/sbom/sbom_writers_test.py b/tools/sbom/sbom_writers_test.py
index cf85e014b7..f9f5230630 100644
--- a/tools/sbom/sbom_writers_test.py
+++ b/tools/sbom/sbom_writers_test.py
@@ -33,6 +33,14 @@ SPDXID_FILE2 = 'SPDXRef-file2'
 SPDXID_FILE3 = 'SPDXRef-file3'
 SPDXID_FILE4 = 'SPDXRef-file4'
 
+SPDXID_LICENSE_1 = 'LicenseRef-Android-License-1'
+SPDXID_LICENSE_2 = 'LicenseRef-Android-License-2'
+SPDXID_LICENSE_3 = 'LicenseRef-Android-License-3'
+
+LICENSE_APACHE_TEXT = "LICENSE_APACHE"
+LICENSE1_TEXT = 'LICENSE 1'
+LICENSE2_TEXT = 'LICENSE 2'
+LICENSE3_TEXT = 'LICENSE 3'
 
 class SBOMWritersTest(unittest.TestCase):
 
@@ -63,6 +71,7 @@ class SBOMWritersTest(unittest.TestCase):
                         download_location=sbom_data.VALUE_NONE,
                         supplier=SUPPLIER_GOOGLE,
                         version=BUILD_FINGER_PRINT,
+                        declared_license_ids=[sbom_data.SPDXID_LICENSE_APACHE]
                         ))
 
     self.sbom_doc.add_package(
@@ -71,6 +80,7 @@ class SBOMWritersTest(unittest.TestCase):
                         download_location=sbom_data.VALUE_NONE,
                         supplier=SUPPLIER_GOOGLE,
                         version=BUILD_FINGER_PRINT,
+                        declared_license_ids=[SPDXID_LICENSE_1],
                         ))
 
     self.sbom_doc.add_package(
@@ -79,6 +89,7 @@ class SBOMWritersTest(unittest.TestCase):
                         download_location=sbom_data.VALUE_NONE,
                         supplier=SUPPLIER_GOOGLE,
                         version=BUILD_FINGER_PRINT,
+                        declared_license_ids=[SPDXID_LICENSE_2, SPDXID_LICENSE_3],
                         external_refs=[sbom_data.PackageExternalRef(
                           category=sbom_data.PackageExternalRefCategory.SECURITY,
                           type=sbom_data.PackageExternalRefType.cpe22Type,
@@ -90,6 +101,7 @@ class SBOMWritersTest(unittest.TestCase):
                         name='Upstream package1',
                         supplier=SUPPLIER_UPSTREAM,
                         version='1.1',
+                        declared_license_ids=[SPDXID_LICENSE_2, SPDXID_LICENSE_3],
                         ))
 
     self.sbom_doc.add_relationship(sbom_data.Relationship(id1=SPDXID_SOURCE_PACKAGE1,
@@ -97,11 +109,11 @@ class SBOMWritersTest(unittest.TestCase):
                                                           id2=SPDXID_UPSTREAM_PACKAGE1))
 
     self.sbom_doc.files.append(
-      sbom_data.File(id=SPDXID_FILE1, name='/bin/file1', checksum='SHA1: 11111'))
+      sbom_data.File(id=SPDXID_FILE1, name='/bin/file1', checksum='SHA1: 11111', concluded_license_ids=[sbom_data.SPDXID_LICENSE_APACHE]))
     self.sbom_doc.files.append(
-      sbom_data.File(id=SPDXID_FILE2, name='/bin/file2', checksum='SHA1: 22222'))
+      sbom_data.File(id=SPDXID_FILE2, name='/bin/file2', checksum='SHA1: 22222', concluded_license_ids=[SPDXID_LICENSE_1]))
     self.sbom_doc.files.append(
-      sbom_data.File(id=SPDXID_FILE3, name='/bin/file3', checksum='SHA1: 33333'))
+      sbom_data.File(id=SPDXID_FILE3, name='/bin/file3', checksum='SHA1: 33333', concluded_license_ids=[SPDXID_LICENSE_2, SPDXID_LICENSE_3]))
     self.sbom_doc.files.append(
       sbom_data.File(id=SPDXID_FILE4, name='file4.a', checksum='SHA1: 44444'))
 
@@ -120,6 +132,11 @@ class SBOMWritersTest(unittest.TestCase):
                                                           id2=SPDXID_FILE4
                                                           ))
 
+    self.sbom_doc.add_license(sbom_data.License(sbom_data.SPDXID_LICENSE_APACHE, LICENSE_APACHE_TEXT, "License-Apache"))
+    self.sbom_doc.add_license(sbom_data.License(SPDXID_LICENSE_1, LICENSE1_TEXT, "License-1"))
+    self.sbom_doc.add_license(sbom_data.License(SPDXID_LICENSE_2, LICENSE2_TEXT, "License-2"))
+    self.sbom_doc.add_license(sbom_data.License(SPDXID_LICENSE_3, LICENSE3_TEXT, "License-3"))
+
     # SBOM fragment of a APK
     self.unbundled_sbom_doc = sbom_data.Document(name='test doc',
                                                  namespace='http://www.google.com/sbom/spdx/android',
diff --git a/tools/sbom/testdata/expected_json_sbom.spdx.json b/tools/sbom/testdata/expected_json_sbom.spdx.json
index 53936c5c9d..a877810566 100644
--- a/tools/sbom/testdata/expected_json_sbom.spdx.json
+++ b/tools/sbom/testdata/expected_json_sbom.spdx.json
@@ -31,6 +31,7 @@
             "filesAnalyzed": true,
             "versionInfo": "build_finger_print",
             "supplier": "Organization: Google",
+            "licenseDeclared": "NOASSERTION",
             "packageVerificationCode": {
                 "packageVerificationCodeValue": "123456"
             },
@@ -46,7 +47,8 @@
             "downloadLocation": "NONE",
             "filesAnalyzed": false,
             "versionInfo": "build_finger_print",
-            "supplier": "Organization: Google"
+            "supplier": "Organization: Google",
+            "licenseDeclared": "LicenseRef-Android-Apache-2.0"
         },
         {
             "name": "Prebuilt package1",
@@ -54,7 +56,8 @@
             "downloadLocation": "NONE",
             "filesAnalyzed": false,
             "versionInfo": "build_finger_print",
-            "supplier": "Organization: Google"
+            "supplier": "Organization: Google",
+            "licenseDeclared": "LicenseRef-Android-License-1"
         },
         {
             "name": "Source package1",
@@ -63,6 +66,7 @@
             "filesAnalyzed": false,
             "versionInfo": "build_finger_print",
             "supplier": "Organization: Google",
+            "licenseDeclared": "LicenseRef-Android-License-2 OR LicenseRef-Android-License-3",
             "externalRefs": [
                 {
                     "referenceCategory": "SECURITY",
@@ -77,7 +81,8 @@
             "downloadLocation": "NOASSERTION",
             "filesAnalyzed": false,
             "versionInfo": "1.1",
-            "supplier": "Organization: upstream"
+            "supplier": "Organization: upstream",
+            "licenseDeclared": "LicenseRef-Android-License-2 OR LicenseRef-Android-License-3"
         }
     ],
     "files": [
@@ -89,7 +94,8 @@
                     "algorithm": "SHA1",
                     "checksumValue": "11111"
                 }
-            ]
+            ],
+            "licenseConcluded": "LicenseRef-Android-Apache-2.0"
         },
         {
             "fileName": "/bin/file2",
@@ -99,7 +105,8 @@
                     "algorithm": "SHA1",
                     "checksumValue": "22222"
                 }
-            ]
+            ],
+            "licenseConcluded": "LicenseRef-Android-License-1"
         },
         {
             "fileName": "/bin/file3",
@@ -109,7 +116,8 @@
                     "algorithm": "SHA1",
                     "checksumValue": "33333"
                 }
-            ]
+            ],
+            "licenseConcluded": "LicenseRef-Android-License-2 OR LicenseRef-Android-License-3"
         },
         {
             "fileName": "file4.a",
@@ -119,7 +127,8 @@
                     "algorithm": "SHA1",
                     "checksumValue": "44444"
                 }
-            ]
+            ],
+            "licenseConcluded": "NOASSERTION"
         }
     ],
     "relationships": [
@@ -148,5 +157,27 @@
             "relatedSpdxElement": "SPDXRef-UPSTREAM-package1",
             "relationshipType": "VARIANT_OF"
         }
+    ],
+    "hasExtractedLicensingInfos": [
+        {
+            "licenseId": "LicenseRef-Android-Apache-2.0",
+            "name": "License-Apache",
+            "extractedText": "<text>LICENSE_APACHE</text>"
+        },
+        {
+            "licenseId": "LicenseRef-Android-License-1",
+            "name": "License-1",
+            "extractedText": "<text>LICENSE 1</text>"
+        },
+        {
+            "licenseId": "LicenseRef-Android-License-2",
+            "name": "License-2",
+            "extractedText": "<text>LICENSE 2</text>"
+        },
+        {
+            "licenseId": "LicenseRef-Android-License-3",
+            "name": "License-3",
+            "extractedText": "<text>LICENSE 3</text>"
+        }
     ]
 }
\ No newline at end of file
diff --git a/tools/sbom/testdata/expected_tagvalue_sbom.spdx b/tools/sbom/testdata/expected_tagvalue_sbom.spdx
index e6fd17e9c3..1c54410070 100644
--- a/tools/sbom/testdata/expected_tagvalue_sbom.spdx
+++ b/tools/sbom/testdata/expected_tagvalue_sbom.spdx
@@ -10,6 +10,7 @@ ExternalDocumentRef: DocumentRef-external_doc_ref external_doc_uri SHA1: 1234567
 FileName: file4.a
 SPDXID: SPDXRef-file4
 FileChecksum: SHA1: 44444
+LicenseConcluded: NOASSERTION
 
 PackageName: PRODUCT
 SPDXID: SPDXRef-PRODUCT
@@ -17,6 +18,7 @@ PackageDownloadLocation: NONE
 FilesAnalyzed: true
 PackageVersion: build_finger_print
 PackageSupplier: Organization: Google
+PackageLicenseDeclared: NOASSERTION
 PackageVerificationCode: 123456
 
 Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-PRODUCT
@@ -24,14 +26,17 @@ Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-PRODUCT
 FileName: /bin/file1
 SPDXID: SPDXRef-file1
 FileChecksum: SHA1: 11111
+LicenseConcluded: LicenseRef-Android-Apache-2.0
 
 FileName: /bin/file2
 SPDXID: SPDXRef-file2
 FileChecksum: SHA1: 22222
+LicenseConcluded: LicenseRef-Android-License-1
 
 FileName: /bin/file3
 SPDXID: SPDXRef-file3
 FileChecksum: SHA1: 33333
+LicenseConcluded: LicenseRef-Android-License-2 OR LicenseRef-Android-License-3
 
 PackageName: PLATFORM
 SPDXID: SPDXRef-PLATFORM
@@ -39,6 +44,7 @@ PackageDownloadLocation: NONE
 FilesAnalyzed: false
 PackageVersion: build_finger_print
 PackageSupplier: Organization: Google
+PackageLicenseDeclared: LicenseRef-Android-Apache-2.0
 
 PackageName: Prebuilt package1
 SPDXID: SPDXRef-PREBUILT-package1
@@ -46,6 +52,7 @@ PackageDownloadLocation: NONE
 FilesAnalyzed: false
 PackageVersion: build_finger_print
 PackageSupplier: Organization: Google
+PackageLicenseDeclared: LicenseRef-Android-License-1
 
 PackageName: Source package1
 SPDXID: SPDXRef-SOURCE-package1
@@ -53,6 +60,7 @@ PackageDownloadLocation: NONE
 FilesAnalyzed: false
 PackageVersion: build_finger_print
 PackageSupplier: Organization: Google
+PackageLicenseDeclared: LicenseRef-Android-License-2 OR LicenseRef-Android-License-3
 ExternalRef: SECURITY cpe22Type cpe:/a:jsoncpp_project:jsoncpp:1.9.4
 
 PackageName: Upstream package1
@@ -61,6 +69,7 @@ PackageDownloadLocation: NOASSERTION
 FilesAnalyzed: false
 PackageVersion: 1.1
 PackageSupplier: Organization: upstream
+PackageLicenseDeclared: LicenseRef-Android-License-2 OR LicenseRef-Android-License-3
 
 Relationship: SPDXRef-SOURCE-package1 VARIANT_OF SPDXRef-UPSTREAM-package1
 
@@ -68,3 +77,19 @@ Relationship: SPDXRef-file1 GENERATED_FROM SPDXRef-PLATFORM
 Relationship: SPDXRef-file2 GENERATED_FROM SPDXRef-PREBUILT-package1
 Relationship: SPDXRef-file3 GENERATED_FROM SPDXRef-SOURCE-package1
 Relationship: SPDXRef-file1 STATIC_LINK SPDXRef-file4
+
+LicenseID: LicenseRef-Android-Apache-2.0
+LicenseName: License-Apache
+ExtractedText: <text>LICENSE_APACHE</text>
+
+LicenseID: LicenseRef-Android-License-1
+LicenseName: License-1
+ExtractedText: <text>LICENSE 1</text>
+
+LicenseID: LicenseRef-Android-License-2
+LicenseName: License-2
+ExtractedText: <text>LICENSE 2</text>
+
+LicenseID: LicenseRef-Android-License-3
+LicenseName: License-3
+ExtractedText: <text>LICENSE 3</text>
diff --git a/tools/sbom/testdata/expected_tagvalue_sbom_doc_describes_file.spdx b/tools/sbom/testdata/expected_tagvalue_sbom_doc_describes_file.spdx
index 428d7e3ddb..36afc8bcbe 100644
--- a/tools/sbom/testdata/expected_tagvalue_sbom_doc_describes_file.spdx
+++ b/tools/sbom/testdata/expected_tagvalue_sbom_doc_describes_file.spdx
@@ -10,6 +10,7 @@ ExternalDocumentRef: DocumentRef-external_doc_ref external_doc_uri SHA1: 1234567
 FileName: file4.a
 SPDXID: SPDXRef-file4
 FileChecksum: SHA1: 44444
+LicenseConcluded: NOASSERTION
 
 Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-file4
 
@@ -19,19 +20,23 @@ PackageDownloadLocation: NONE
 FilesAnalyzed: true
 PackageVersion: build_finger_print
 PackageSupplier: Organization: Google
+PackageLicenseDeclared: NOASSERTION
 PackageVerificationCode: 123456
 
 FileName: /bin/file1
 SPDXID: SPDXRef-file1
 FileChecksum: SHA1: 11111
+LicenseConcluded: LicenseRef-Android-Apache-2.0
 
 FileName: /bin/file2
 SPDXID: SPDXRef-file2
 FileChecksum: SHA1: 22222
+LicenseConcluded: LicenseRef-Android-License-1
 
 FileName: /bin/file3
 SPDXID: SPDXRef-file3
 FileChecksum: SHA1: 33333
+LicenseConcluded: LicenseRef-Android-License-2 OR LicenseRef-Android-License-3
 
 PackageName: PLATFORM
 SPDXID: SPDXRef-PLATFORM
@@ -39,6 +44,7 @@ PackageDownloadLocation: NONE
 FilesAnalyzed: false
 PackageVersion: build_finger_print
 PackageSupplier: Organization: Google
+PackageLicenseDeclared: LicenseRef-Android-Apache-2.0
 
 PackageName: Prebuilt package1
 SPDXID: SPDXRef-PREBUILT-package1
@@ -46,6 +52,7 @@ PackageDownloadLocation: NONE
 FilesAnalyzed: false
 PackageVersion: build_finger_print
 PackageSupplier: Organization: Google
+PackageLicenseDeclared: LicenseRef-Android-License-1
 
 PackageName: Source package1
 SPDXID: SPDXRef-SOURCE-package1
@@ -53,6 +60,7 @@ PackageDownloadLocation: NONE
 FilesAnalyzed: false
 PackageVersion: build_finger_print
 PackageSupplier: Organization: Google
+PackageLicenseDeclared: LicenseRef-Android-License-2 OR LicenseRef-Android-License-3
 ExternalRef: SECURITY cpe22Type cpe:/a:jsoncpp_project:jsoncpp:1.9.4
 
 PackageName: Upstream package1
@@ -61,6 +69,7 @@ PackageDownloadLocation: NOASSERTION
 FilesAnalyzed: false
 PackageVersion: 1.1
 PackageSupplier: Organization: upstream
+PackageLicenseDeclared: LicenseRef-Android-License-2 OR LicenseRef-Android-License-3
 
 Relationship: SPDXRef-SOURCE-package1 VARIANT_OF SPDXRef-UPSTREAM-package1
 
@@ -68,3 +77,19 @@ Relationship: SPDXRef-file1 GENERATED_FROM SPDXRef-PLATFORM
 Relationship: SPDXRef-file2 GENERATED_FROM SPDXRef-PREBUILT-package1
 Relationship: SPDXRef-file3 GENERATED_FROM SPDXRef-SOURCE-package1
 Relationship: SPDXRef-file1 STATIC_LINK SPDXRef-file4
+
+LicenseID: LicenseRef-Android-Apache-2.0
+LicenseName: License-Apache
+ExtractedText: <text>LICENSE_APACHE</text>
+
+LicenseID: LicenseRef-Android-License-1
+LicenseName: License-1
+ExtractedText: <text>LICENSE 1</text>
+
+LicenseID: LicenseRef-Android-License-2
+LicenseName: License-2
+ExtractedText: <text>LICENSE 2</text>
+
+LicenseID: LicenseRef-Android-License-3
+LicenseName: License-3
+ExtractedText: <text>LICENSE 3</text>
diff --git a/tools/sbom/testdata/expected_tagvalue_sbom_unbundled.spdx b/tools/sbom/testdata/expected_tagvalue_sbom_unbundled.spdx
index a00c291ad7..4b14a4b2ad 100644
--- a/tools/sbom/testdata/expected_tagvalue_sbom_unbundled.spdx
+++ b/tools/sbom/testdata/expected_tagvalue_sbom_unbundled.spdx
@@ -1,6 +1,7 @@
 FileName: /bin/file1.apk
 SPDXID: SPDXRef-file1
 FileChecksum: SHA1: 11111
+LicenseConcluded: NOASSERTION
 
 PackageName: Unbundled apk package
 SPDXID: SPDXRef-SOURCE-package1
@@ -8,5 +9,6 @@ PackageDownloadLocation: NONE
 FilesAnalyzed: false
 PackageVersion: build_finger_print
 PackageSupplier: Organization: Google
+PackageLicenseDeclared: NOASSERTION
 
 Relationship: SPDXRef-file1 GENERATED_FROM SPDXRef-SOURCE-package1
diff --git a/tools/tool_event_logger/proto/tool_event.proto b/tools/tool_event_logger/proto/tool_event.proto
index 61e28a25e7..ef71eac49e 100644
--- a/tools/tool_event_logger/proto/tool_event.proto
+++ b/tools/tool_event_logger/proto/tool_event.proto
@@ -27,6 +27,8 @@ message ToolEvent {
   string source_root = 3;
   // Name of the tool used.
   string tool_tag = 6;
+  // Name of the host workstation.
+  string host_name = 7;
 
   oneof event {
     InvocationStarted invocation_started = 4;
diff --git a/tools/tool_event_logger/tool_event_logger.py b/tools/tool_event_logger/tool_event_logger.py
index 65a9696011..b249d91c56 100644
--- a/tools/tool_event_logger/tool_event_logger.py
+++ b/tools/tool_event_logger/tool_event_logger.py
@@ -38,6 +38,7 @@ class ToolEventLogger:
       tool_tag: str,
       invocation_id: str,
       user_name: str,
+      host_name: str,
       source_root: str,
       platform_version: str,
       python_version: str,
@@ -46,6 +47,7 @@ class ToolEventLogger:
     self.tool_tag = tool_tag
     self.invocation_id = invocation_id
     self.user_name = user_name
+    self.host_name = host_name
     self.source_root = source_root
     self.platform_version = platform_version
     self.python_version = python_version
@@ -57,6 +59,7 @@ class ToolEventLogger:
         tool_tag=tool_tag,
         invocation_id=str(uuid.uuid4()),
         user_name=getpass.getuser(),
+        host_name=platform.node(),
         source_root=os.environ.get('ANDROID_BUILD_TOP', ''),
         platform_version=platform.platform(),
         python_version=platform.python_version(),
@@ -110,6 +113,7 @@ class ToolEventLogger:
         tool_tag=self.tool_tag,
         invocation_id=self.invocation_id,
         user_name=self.user_name,
+        host_name=self.host_name,
         source_root=self.source_root,
     )
 
diff --git a/tools/tool_event_logger/tool_event_logger_test.py b/tools/tool_event_logger/tool_event_logger_test.py
index 34b6c357cc..788812aadd 100644
--- a/tools/tool_event_logger/tool_event_logger_test.py
+++ b/tools/tool_event_logger/tool_event_logger_test.py
@@ -25,6 +25,7 @@ from tool_event_logger import tool_event_logger
 
 TEST_INVOCATION_ID = 'test_invocation_id'
 TEST_USER_NAME = 'test_user'
+TEST_HOST_NAME = 'test_host_name'
 TEST_TOOL_TAG = 'test_tool'
 TEST_SOURCE_ROOT = 'test_source_root'
 TEST_PLATFORM_VERSION = 'test_platform_version'
@@ -41,6 +42,7 @@ class ToolEventLoggerTest(unittest.TestCase):
         TEST_TOOL_TAG,
         TEST_INVOCATION_ID,
         TEST_USER_NAME,
+        TEST_HOST_NAME,
         TEST_SOURCE_ROOT,
         TEST_PLATFORM_VERSION,
         TEST_PYTHON_VERSION,
@@ -65,6 +67,7 @@ class ToolEventLoggerTest(unittest.TestCase):
     log_event = tool_event_pb2.ToolEvent.FromString(sent_event.source_extension)
     self.assertEqual(log_event.invocation_id, TEST_INVOCATION_ID)
     self.assertEqual(log_event.user_name, TEST_USER_NAME)
+    self.assertEqual(log_event.host_name, TEST_HOST_NAME)
     self.assertEqual(log_event.tool_tag, TEST_TOOL_TAG)
     self.assertEqual(log_event.source_root, TEST_SOURCE_ROOT)
 
```

