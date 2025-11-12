```diff
diff --git a/OWNERS b/OWNERS
index 4cc9976..41d1acf 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,10 +1,9 @@
 # keep-sorted start
+gcontreras@google.com
 lovisolo@google.com
 rrangel@google.com
-saklein@google.com
-tbain@google.com
 vapier@google.com
-zland@google.com
+xcl@google.com
 # keep-sorted end
 
 samccone@google.com #{LAST_RESORT_SUGGESTION}
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 4cedfd1..85b9d65 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -13,6 +13,7 @@ check_aosp_license_unittest = ./tools/check_aosp_license_unittest.py
 
 [Builtin Hooks]
 aosp_license = true
+black = true
 commit_msg_bug_field = true
 commit_msg_changeid_field = true
 commit_msg_test_field = true
diff --git a/README.md b/README.md
index ec3c22e..26bd812 100644
--- a/README.md
+++ b/README.md
@@ -181,6 +181,8 @@ canned hooks already included geared towards AOSP style guidelines.
 * `aosp_license`: Check if all new-added file have valid AOSP license headers.
 * `android_test_mapping_format`: Validate TEST_MAPPING files in Android source
   code. Refer to go/test-mapping for more details.
+* `black`: Run Python files (.py) through `black`.  Settings can be stored in
+  `pyproject.toml` in the root of the project.
 * `bpfmt`: Run Blueprint files (.bp) through `bpfmt`.
 * `checkpatch`: Run commits through the Linux kernel's `checkpatch.pl` script.
 * `clang_format`: Run git-clang-format against the commit. The default style is
@@ -280,6 +282,7 @@ distros/versions.  The following tools are recognized:
 * `aidl-format`: used for the `aidl_format` builtin hook.
 * `android-test-mapping-format`: used for the `android_test_mapping_format`
   builtin hook.
+* `black`: used for the `black` builtin hook.
 * `bpfmt`: used for the `bpfmt` builtin hook.
 * `clang-format`: used for the `clang_format` builtin hook.
 * `cpplint`: used for the `cpplint` builtin hook.
diff --git a/pre-upload.py b/pre-upload.py
index c852c29..a51707c 100755
--- a/pre-upload.py
+++ b/pre-upload.py
@@ -31,7 +31,7 @@ from typing import List, Optional
 # Assert some minimum Python versions as we don't test or support any others.
 # See README.md for what version we may require.
 if sys.version_info < (3, 6):
-    print('repohooks: error: Python-3.6+ is required', file=sys.stderr)
+    print("repohooks: error: Python-3.6+ is required", file=sys.stderr)
     sys.exit(1)
 
 
@@ -53,19 +53,19 @@ import rh.utils
 
 
 # Repohooks homepage.
-REPOHOOKS_URL = 'https://android.googlesource.com/platform/tools/repohooks/'
+REPOHOOKS_URL = "https://android.googlesource.com/platform/tools/repohooks/"
 
 
 class Output(object):
     """Class for reporting hook status."""
 
     COLOR = rh.terminal.Color()
-    COMMIT = COLOR.color(COLOR.CYAN, 'COMMIT')
-    RUNNING = COLOR.color(COLOR.YELLOW, 'RUNNING')
-    PASSED = COLOR.color(COLOR.GREEN, 'PASSED')
-    FAILED = COLOR.color(COLOR.RED, 'FAILED')
-    WARNING = COLOR.color(COLOR.YELLOW, 'WARNING')
-    FIXUP = COLOR.color(COLOR.MAGENTA, 'FIXUP')
+    COMMIT = COLOR.color(COLOR.CYAN, "COMMIT")
+    RUNNING = COLOR.color(COLOR.YELLOW, "RUNNING")
+    PASSED = COLOR.color(COLOR.GREEN, "PASSED")
+    FAILED = COLOR.color(COLOR.RED, "FAILED")
+    WARNING = COLOR.color(COLOR.YELLOW, "WARNING")
+    FIXUP = COLOR.color(COLOR.MAGENTA, "FIXUP")
 
     # How long a hook is allowed to run before we warn that it is "too slow".
     _SLOW_HOOK_DURATION = datetime.timedelta(seconds=30)
@@ -85,7 +85,7 @@ class Output(object):
         self.start_time = datetime.datetime.now()
         self.hook_start_time = None
         # Cache number of invisible characters in our banner.
-        self._banner_esc_chars = len(self.COLOR.color(self.COLOR.YELLOW, ''))
+        self._banner_esc_chars = len(self.COLOR.color(self.COLOR.YELLOW, ""))
 
     def set_num_commits(self, num_commits: int) -> None:
         """Keep track of how many commits we'll be running.
@@ -105,9 +105,9 @@ class Output(object):
           commit_summary: commit summary.
         """
         status_line = (
-            f'[{self.COMMIT} '
-            f'{self.commit_index}/{self.num_commits} '
-            f'{commit[0:12]}] {commit_summary}'
+            f"[{self.COMMIT} "
+            f"{self.commit_index}/{self.num_commits} "
+            f"{commit[0:12]}] {commit_summary}"
         )
         rh.terminal.print_status_line(status_line, print_newline=True)
         self.commit_index += 1
@@ -119,15 +119,15 @@ class Output(object):
 
     def hook_banner(self):
         """Display the banner for current set of hooks."""
-        pending = ', '.join(x.name for x in self.hooks)
+        pending = ", ".join(x.name for x in self.hooks)
         status_line = (
-            f'[{self.RUNNING} '
-            f'{self.num_hooks - len(self.hooks)}/{self.num_hooks}] '
-            f'{pending}'
+            f"[{self.RUNNING} "
+            f"{self.num_hooks - len(self.hooks)}/{self.num_hooks}] "
+            f"{pending}"
         )
         if self._banner_esc_chars and sys.stderr.isatty():
             cols = os.get_terminal_size(sys.stderr.fileno()).columns
-            status_line = status_line[0:cols + self._banner_esc_chars]
+            status_line = status_line[0 : cols + self._banner_esc_chars]
         rh.terminal.print_status_line(status_line)
 
     def hook_finish(self, hook, duration):
@@ -137,9 +137,10 @@ class Output(object):
             d = rh.utils.timedelta_str(duration)
             self.hook_warning(
                 hook,
-                f'This hook took {d} to finish which is fairly slow for '
-                'developers.\nPlease consider moving the check to the '
-                'server/CI system instead.')
+                f"This hook took {d} to finish which is fairly slow for "
+                "developers.\nPlease consider moving the check to the "
+                "server/CI system instead.",
+            )
 
         # Show any hooks still pending.
         if self.hooks:
@@ -152,7 +153,7 @@ class Output(object):
           hook: The hook that generated the output.
           error: error string.
         """
-        self.error(f'{hook.name} hook', error)
+        self.error(f"{hook.name} hook", error)
 
     def hook_warning(self, hook, warning):
         """Print a warning for a single hook.
@@ -161,7 +162,7 @@ class Output(object):
           hook: The hook that generated the output.
           warning: warning string.
         """
-        status_line = f'[{self.WARNING}] {hook.name}'
+        status_line = f"[{self.WARNING}] {hook.name}"
         rh.terminal.print_status_line(status_line, print_newline=True)
         print(warning, file=sys.stderr)
 
@@ -172,7 +173,7 @@ class Output(object):
           header: A unique identifier for the source of this error.
           error: error string.
         """
-        status_line = f'[{self.FAILED}] {header}'
+        status_line = f"[{self.FAILED}] {header}"
         rh.terminal.print_status_line(status_line, print_newline=True)
         print(error, file=sys.stderr)
         self.success = False
@@ -186,20 +187,21 @@ class Output(object):
         for result in (x for x in hook_results if x.fixup_cmd):
             cmd = result.fixup_cmd + list(result.files)
             for line in (
-                f'[{self.FIXUP}] {result.hook} has automated fixups available',
-                f'  cd {rh.shell.quote(project_results.workdir)} && \\',
-                f'    {rh.shell.cmd_to_str(cmd)}',
+                f"[{self.FIXUP}] {result.hook} has automated fixups available",
+                f"  cd {rh.shell.quote(project_results.workdir)} && \\",
+                f"    {rh.shell.cmd_to_str(cmd)}",
             ):
                 rh.terminal.print_status_line(line, print_newline=True)
 
     def finish(self):
         """Print summary for all the hooks."""
         header = self.PASSED if self.success else self.FAILED
-        status = 'passed' if self.success else 'failed'
+        status = "passed" if self.success else "failed"
         d = rh.utils.timedelta_str(datetime.datetime.now() - self.start_time)
         rh.terminal.print_status_line(
-            f'[{header}] repohooks for {self.project_name} {status} in {d}',
-            print_newline=True)
+            f"[{header}] repohooks for {self.project_name} {status} in {d}",
+            print_newline=True,
+        )
 
 
 def _process_hook_results(results):
@@ -220,15 +222,15 @@ def _process_hook_results(results):
     has_error = False
     has_warning = False
 
-    error_ret = ''
-    warning_ret = ''
+    error_ret = ""
+    warning_ret = ""
     for result in results:
         if result or result.is_warning():
-            ret = ''
+            ret = ""
             if result.files:
-                ret += f'  FILES: {rh.shell.cmd_to_str(result.files)}\n'
+                ret += f"  FILES: {rh.shell.cmd_to_str(result.files)}\n"
             lines = result.error.splitlines()
-            ret += '\n'.join(f'    {x}' for x in lines)
+            ret += "\n".join(f"    {x}" for x in lines)
             if result.is_warning():
                 has_warning = True
                 warning_ret += ret
@@ -236,8 +238,10 @@ def _process_hook_results(results):
                 has_error = True
                 error_ret += ret
 
-    return (error_ret if has_error else None,
-            warning_ret if has_warning else None)
+    return (
+        error_ret if has_error else None,
+        warning_ret if has_warning else None,
+    )
 
 
 def _get_project_config(from_git=False):
@@ -253,14 +257,14 @@ def _get_project_config(from_git=False):
     else:
         global_paths = (
             # Load the global config found in the manifest repo.
-            (os.path.join(rh.git.find_repo_root(), '.repo', 'manifests')),
+            (os.path.join(rh.git.find_repo_root(), ".repo", "manifests")),
             # Load the global config found in the root of the repo checkout.
             rh.git.find_repo_root(),
         )
 
     paths = (
         # Load the config for this git repo.
-        '.',
+        ".",
     )
     return rh.config.PreUploadSettings(paths=paths, global_paths=global_paths)
 
@@ -270,65 +274,75 @@ def _attempt_fixes(projects_results: List[rh.results.ProjectResults]) -> None:
     # Filter out any result that has a fixup.
     fixups = []
     for project_results in projects_results:
-        fixups.extend((project_results.workdir, x)
-                      for x in project_results.fixups)
+        fixups.extend(
+            (project_results.workdir, x) for x in project_results.fixups
+        )
     if not fixups:
         return
 
     if len(fixups) > 1:
-        banner = f'Multiple fixups ({len(fixups)}) are available.'
+        banner = f"Multiple fixups ({len(fixups)}) are available."
     else:
-        banner = 'Automated fixups are available.'
+        banner = "Automated fixups are available."
     print(Output.COLOR.color(Output.COLOR.MAGENTA, banner), file=sys.stderr)
 
     # If there's more than one fixup available, ask if they want to blindly run
     # them all, or prompt for them one-by-one.
-    mode = 'some'
+    mode = "some"
     if len(fixups) > 1:
         while True:
             response = rh.terminal.str_prompt(
-                'What would you like to do',
-                ('Run (A)ll', 'Run (S)ome', '(D)ry-run', '(N)othing [default]'))
+                "What would you like to do",
+                ("Run (A)ll", "Run (S)ome", "(D)ry-run", "(N)othing [default]"),
+            )
             if not response:
-                print('', file=sys.stderr)
+                print("", file=sys.stderr)
                 return
-            if response.startswith('a') or response.startswith('y'):
-                mode = 'all'
+            if response.startswith("a") or response.startswith("y"):
+                mode = "all"
                 break
-            elif response.startswith('s'):
-                mode = 'some'
+            elif response.startswith("s"):
+                mode = "some"
                 break
-            elif response.startswith('d'):
-                mode = 'dry-run'
+            elif response.startswith("d"):
+                mode = "dry-run"
                 break
-            elif response.startswith('n'):
-                print('', file=sys.stderr)
+            elif response.startswith("n"):
+                print("", file=sys.stderr)
                 return
 
     # Walk all the fixups and run them one-by-one.
     for workdir, result in fixups:
-        if mode == 'some':
+        if mode == "some":
             if not rh.terminal.boolean_prompt(
-                f'Run {result.hook} fixup for {result.commit}'
+                f"Run {result.hook} fixup for {result.commit}"
             ):
                 continue
 
         cmd = tuple(result.fixup_cmd) + tuple(result.files)
         print(
-            f'\n[{Output.RUNNING}] cd {rh.shell.quote(workdir)} && '
-            f'{rh.shell.cmd_to_str(cmd)}', file=sys.stderr)
-        if mode == 'dry-run':
+            f"\n[{Output.RUNNING}] cd {rh.shell.quote(workdir)} && "
+            f"{rh.shell.cmd_to_str(cmd)}",
+            file=sys.stderr,
+        )
+        if mode == "dry-run":
             continue
 
         cmd_result = rh.utils.run(cmd, cwd=workdir, check=False)
         if cmd_result.returncode:
-            print(f'[{Output.WARNING}] command exited {cmd_result.returncode}',
-                  file=sys.stderr)
+            print(
+                f"[{Output.WARNING}] command exited {cmd_result.returncode}",
+                file=sys.stderr,
+            )
         else:
-            print(f'[{Output.PASSED}] great success', file=sys.stderr)
+            print(f"[{Output.PASSED}] great success", file=sys.stderr)
+
+    print(
+        f"\n[{Output.FIXUP}] Please amend & rebase your tree before "
+        "attempting to upload again.\n",
+        file=sys.stderr,
+    )
 
-    print(f'\n[{Output.FIXUP}] Please amend & rebase your tree before '
-          'attempting to upload again.\n', file=sys.stderr)
 
 def _run_project_hooks_in_cwd(
     project_name: str,
@@ -359,7 +373,7 @@ def _run_project_hooks_in_cwd(
     try:
         config = _get_project_config(from_git)
     except rh.config.ValidationError as e:
-        output.error('Loading config files', str(e))
+        output.error("Loading config files", str(e))
         return ret._replace(internal_failure=True)
 
     builtin_hooks = list(config.callable_builtin_hooks())
@@ -374,8 +388,10 @@ def _run_project_hooks_in_cwd(
         remote = rh.git.get_upstream_remote()
         upstream_branch = rh.git.get_upstream_branch()
     except rh.utils.CalledProcessError as e:
-        output.error('Upstream remote/tracking branch lookup',
-                     f'{e}\nDid you run repo start?  Is your HEAD detached?')
+        output.error(
+            "Upstream remote/tracking branch lookup",
+            f"{e}\nDid you run repo start?  Is your HEAD detached?",
+        )
         return ret._replace(internal_failure=True)
 
     project = rh.Project(name=project_name, dir=proj_dir)
@@ -388,17 +404,20 @@ def _run_project_hooks_in_cwd(
     if not builtin_hooks and not custom_hooks:
         return ret
 
-    os.environ.update({
-        'REPO_LREV': rh.git.get_commit_for_ref(upstream_branch),
-        'REPO_PATH': rel_proj_dir,
-        'REPO_PROJECT': project_name,
-        'REPO_REMOTE': remote,
-        'REPO_RREV': rh.git.get_remote_revision(upstream_branch, remote),
-    })
+    os.environ.update(
+        {
+            "REPO_LREV": rh.git.get_commit_for_ref(upstream_branch),
+            "REPO_PATH": rel_proj_dir,
+            "REPO_PROJECT": project_name,
+            "REPO_REMOTE": remote,
+            "REPO_RREV": rh.git.get_remote_revision(upstream_branch, remote),
+        }
+    )
 
     if not commit_list:
         commit_list = rh.git.get_commits(
-            ignore_merged_commits=config.ignore_merged_commits)
+            ignore_merged_commits=config.ignore_merged_commits
+        )
     output.set_num_commits(len(commit_list))
 
     def _run_hook(hook, project, commit, desc, diff):
@@ -412,23 +431,33 @@ def _run_project_hooks_in_cwd(
     with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
         for commit in commit_list:
             # Mix in some settings for our hooks.
-            os.environ['PREUPLOAD_COMMIT'] = commit
+            os.environ["PREUPLOAD_COMMIT"] = commit
             diff = rh.git.get_affected_files(commit)
             desc = rh.git.get_commit_desc(commit)
-            os.environ['PREUPLOAD_COMMIT_MESSAGE'] = desc
+            os.environ["PREUPLOAD_COMMIT_MESSAGE"] = desc
 
-            commit_summary = desc.split('\n', 1)[0]
-            output.commit_start(builtin_hooks + custom_hooks, commit, commit_summary)
+            commit_summary = desc.split("\n", 1)[0]
+            output.commit_start(
+                builtin_hooks + custom_hooks, commit, commit_summary
+            )
 
             def run_hooks(hooks):
                 futures = (
-                    executor.submit(_run_hook, hook, project, commit, desc, diff)
+                    executor.submit(
+                        _run_hook, hook, project, commit, desc, diff
+                    )
                     for hook in hooks
                 )
                 future_results = (
                     x.result() for x in concurrent.futures.as_completed(futures)
                 )
-                for hook, hook_results, error, warning, duration in future_results:
+                for (
+                    hook,
+                    hook_results,
+                    error,
+                    warning,
+                    duration,
+                ) in future_results:
                     ret.add_results(hook_results)
                     if error is not None or warning is not None:
                         if warning is not None:
@@ -470,18 +499,22 @@ def _run_project_hooks(
     output = Output(project_name)
 
     if proj_dir is None:
-        cmd = ['repo', 'forall', project_name, '-c', 'pwd']
+        cmd = ["repo", "forall", project_name, "-c", "pwd"]
         result = rh.utils.run(cmd, capture_output=True)
         proj_dirs = result.stdout.split()
         if not proj_dirs:
-            print(f'{project_name} cannot be found.', file=sys.stderr)
-            print('Please specify a valid project.', file=sys.stderr)
+            print(f"{project_name} cannot be found.", file=sys.stderr)
+            print("Please specify a valid project.", file=sys.stderr)
             return False
         if len(proj_dirs) > 1:
-            print(f'{project_name} is associated with multiple directories.',
-                  file=sys.stderr)
-            print('Please specify a directory to help disambiguate.',
-                  file=sys.stderr)
+            print(
+                f"{project_name} is associated with multiple directories.",
+                file=sys.stderr,
+            )
+            print(
+                "Please specify a directory to help disambiguate.",
+                file=sys.stderr,
+            )
             return False
         proj_dir = proj_dirs[0]
 
@@ -490,8 +523,13 @@ def _run_project_hooks(
         # Hooks assume they are run from the root of the project.
         os.chdir(proj_dir)
         return _run_project_hooks_in_cwd(
-            project_name, proj_dir, output, jobs=jobs, from_git=from_git,
-            commit_list=commit_list)
+            project_name,
+            proj_dir,
+            output,
+            jobs=jobs,
+            from_git=from_git,
+            commit_list=commit_list,
+        )
     finally:
         output.finish()
         os.chdir(pwd)
@@ -533,7 +571,7 @@ def _run_projects_hooks(
             # If a repo had failures, add a blank line to help break up the
             # output.  If there were no failures, then the output should be
             # very minimal, so we don't add it then.
-            print('', file=sys.stderr)
+            print("", file=sys.stderr)
 
     _attempt_fixes(results)
     return not any(results)
@@ -559,10 +597,12 @@ def main(project_list, worktree_list=None, **_kwargs):
         worktree_list = [None] * len(project_list)
     if not _run_projects_hooks(project_list, worktree_list):
         color = rh.terminal.Color()
-        print(color.color(color.RED, 'FATAL') +
-              ': Preupload failed due to above error(s).\n'
-              f'For more info, see: {REPOHOOKS_URL}',
-              file=sys.stderr)
+        print(
+            color.color(color.RED, "FATAL")
+            + ": Preupload failed due to above error(s).\n"
+            f"For more info, see: {REPOHOOKS_URL}",
+            file=sys.stderr,
+        )
         sys.exit(1)
 
 
@@ -574,20 +614,29 @@ def _identify_project(path, from_git=False):
       a blank string upon failure.
     """
     if from_git:
-        cmd = ['git', 'rev-parse', '--show-toplevel']
+        cmd = ["git", "rev-parse", "--show-toplevel"]
         project_path = rh.utils.run(cmd, capture_output=True).stdout.strip()
-        cmd = ['git', 'rev-parse', '--show-superproject-working-tree']
+        cmd = ["git", "rev-parse", "--show-superproject-working-tree"]
         superproject_path = rh.utils.run(
-            cmd, capture_output=True).stdout.strip()
-        module_path = project_path[len(superproject_path) + 1:]
-        cmd = ['git', 'config', '-f', '.gitmodules',
-               '--name-only', '--get-regexp', r'^submodule\..*\.path$',
-               f"^{module_path}$"]
-        module_name = rh.utils.run(cmd, cwd=superproject_path,
-                                   capture_output=True).stdout.strip()
-        return module_name[len('submodule.'):-len(".path")]
+            cmd, capture_output=True
+        ).stdout.strip()
+        module_path = project_path[len(superproject_path) + 1 :]
+        cmd = [
+            "git",
+            "config",
+            "-f",
+            ".gitmodules",
+            "--name-only",
+            "--get-regexp",
+            r"^submodule\..*\.path$",
+            f"^{module_path}$",
+        ]
+        module_name = rh.utils.run(
+            cmd, cwd=superproject_path, capture_output=True
+        ).stdout.strip()
+        return module_name[len("submodule.") : -len(".path")]
     else:
-        cmd = ['repo', 'forall', '.', '-c', 'echo ${REPO_PROJECT}']
+        cmd = ["repo", "forall", ".", "-c", "echo ${REPO_PROJECT}"]
         return rh.utils.run(cmd, capture_output=True, cwd=path).stdout.strip()
 
 
@@ -604,37 +653,49 @@ def direct_main(argv):
       BadInvocation: On some types of invocation errors.
     """
     parser = argparse.ArgumentParser(description=__doc__)
-    parser.add_argument('--git', action='store_true',
-                        help='This hook is called from git instead of repo')
-    parser.add_argument('--dir', default=None,
-                        help='The directory that the project lives in.  If not '
-                        'specified, use the git project root based on the cwd.')
-    parser.add_argument('--project', default=None,
-                        help='The project repo path; this can affect how the '
-                        'hooks get run, since some hooks are project-specific.'
-                        'If not specified, `repo` will be used to figure this '
-                        'out based on the dir.')
-    parser.add_argument('-j', '--jobs', type=int,
-                        help='Run up to this many hooks in parallel. Setting '
-                        'to 1 forces serial execution, and the default '
-                        'automatically chooses an appropriate number for the '
-                        'current system.')
-    parser.add_argument('commits', nargs='*',
-                        help='Check specific commits')
+    parser.add_argument(
+        "--git",
+        action="store_true",
+        help="This hook is called from git instead of repo",
+    )
+    parser.add_argument(
+        "--dir",
+        default=None,
+        help="The directory that the project lives in.  If not "
+        "specified, use the git project root based on the cwd.",
+    )
+    parser.add_argument(
+        "--project",
+        default=None,
+        help="The project repo path; this can affect how the "
+        "hooks get run, since some hooks are project-specific."
+        "If not specified, `repo` will be used to figure this "
+        "out based on the dir.",
+    )
+    parser.add_argument(
+        "-j",
+        "--jobs",
+        type=int,
+        help="Run up to this many hooks in parallel. Setting "
+        "to 1 forces serial execution, and the default "
+        "automatically chooses an appropriate number for the "
+        "current system.",
+    )
+    parser.add_argument("commits", nargs="*", help="Check specific commits")
     opts = parser.parse_args(argv)
 
     # Check/normalize git dir; if unspecified, we'll use the root of the git
     # project from CWD.
     if opts.dir is None:
-        cmd = ['git', 'rev-parse', '--git-dir']
+        cmd = ["git", "rev-parse", "--git-dir"]
         git_dir = rh.utils.run(cmd, capture_output=True).stdout.strip()
         if not git_dir:
-            parser.error('The current directory is not part of a git project.')
+            parser.error("The current directory is not part of a git project.")
         opts.dir = os.path.dirname(os.path.abspath(git_dir))
     elif not os.path.isdir(opts.dir):
-        parser.error(f'Invalid dir: {opts.dir}')
+        parser.error(f"Invalid dir: {opts.dir}")
     elif not rh.git.is_git_repository(opts.dir):
-        parser.error(f'Not a git repository: {opts.dir}')
+        parser.error(f"Not a git repository: {opts.dir}")
 
     # Identify the project if it wasn't specified; this _requires_ the repo
     # tool to be installed and for the project to be part of a repo checkout.
@@ -644,14 +705,19 @@ def direct_main(argv):
             parser.error(f"Couldn't identify the project of {opts.dir}")
 
     try:
-        if _run_projects_hooks([opts.project], [opts.dir], jobs=opts.jobs,
-                               from_git=opts.git, commit_list=opts.commits):
+        if _run_projects_hooks(
+            [opts.project],
+            [opts.dir],
+            jobs=opts.jobs,
+            from_git=opts.git,
+            commit_list=opts.commits,
+        ):
             return 0
     except KeyboardInterrupt:
-        print('Aborting execution early due to user interrupt', file=sys.stderr)
+        print("Aborting execution early due to user interrupt", file=sys.stderr)
         return 128 + signal.SIGINT
     return 1
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     sys.exit(direct_main(sys.argv[1:]))
diff --git a/pyproject.toml b/pyproject.toml
new file mode 100644
index 0000000..2a923fc
--- /dev/null
+++ b/pyproject.toml
@@ -0,0 +1,24 @@
+# Copyright 2025 The Android Open Source Project
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
+[tool.black]
+line-length = 80
+target-version = ['py36']
+exclude = 'tools/cpplint\.py$'
+
+[tool.pytest.ini_options]
+python_files = "*_unittest.py"
+markers = """
+    skip_cq: Skip tests in the CQ. Should be rarely used!
+"""
diff --git a/rh/config.py b/rh/config.py
index 3671a3f..04e1d69 100644
--- a/rh/config.py
+++ b/rh/config.py
@@ -21,7 +21,7 @@ import os
 import shlex
 import sys
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -79,12 +79,12 @@ class RawConfigParser(configparser.RawConfigParser):
 class PreUploadConfig(object):
     """A single (abstract) config used for `repo upload` hooks."""
 
-    CUSTOM_HOOKS_SECTION = 'Hook Scripts'
-    BUILTIN_HOOKS_SECTION = 'Builtin Hooks'
-    BUILTIN_HOOKS_OPTIONS_SECTION = 'Builtin Hooks Options'
-    BUILTIN_HOOKS_EXCLUDE_SECTION = 'Builtin Hooks Exclude Paths'
-    TOOL_PATHS_SECTION = 'Tool Paths'
-    OPTIONS_SECTION = 'Options'
+    CUSTOM_HOOKS_SECTION = "Hook Scripts"
+    BUILTIN_HOOKS_SECTION = "Builtin Hooks"
+    BUILTIN_HOOKS_OPTIONS_SECTION = "Builtin Hooks Options"
+    BUILTIN_HOOKS_EXCLUDE_SECTION = "Builtin Hooks Exclude Paths"
+    TOOL_PATHS_SECTION = "Tool Paths"
+    OPTIONS_SECTION = "Options"
     VALID_SECTIONS = {
         CUSTOM_HOOKS_SECTION,
         BUILTIN_HOOKS_SECTION,
@@ -94,7 +94,7 @@ class PreUploadConfig(object):
         OPTIONS_SECTION,
     }
 
-    OPTION_IGNORE_MERGED_COMMITS = 'ignore_merged_commits'
+    OPTION_IGNORE_MERGED_COMMITS = "ignore_merged_commits"
     VALID_OPTIONS = {OPTION_IGNORE_MERGED_COMMITS}
 
     def __init__(self, config=None, source=None):
@@ -117,24 +117,34 @@ class PreUploadConfig(object):
 
     def custom_hook(self, hook):
         """The command to execute for |hook|."""
-        return shlex.split(self.config.get(
-            self.CUSTOM_HOOKS_SECTION, hook, fallback=''))
+        return shlex.split(
+            self.config.get(self.CUSTOM_HOOKS_SECTION, hook, fallback="")
+        )
 
     @property
     def builtin_hooks(self):
         """List of all enabled builtin hooks (their keys/names)."""
-        return [k for k, v in self.config.items(self.BUILTIN_HOOKS_SECTION, ())
-                if rh.shell.boolean_shell_value(v, None)]
+        return [
+            k
+            for k, v in self.config.items(self.BUILTIN_HOOKS_SECTION, ())
+            if rh.shell.boolean_shell_value(v, None)
+        ]
 
     def builtin_hook_option(self, hook):
         """The options to pass to |hook|."""
-        return shlex.split(self.config.get(
-            self.BUILTIN_HOOKS_OPTIONS_SECTION, hook, fallback=''))
+        return shlex.split(
+            self.config.get(
+                self.BUILTIN_HOOKS_OPTIONS_SECTION, hook, fallback=""
+            )
+        )
 
     def builtin_hook_exclude_paths(self, hook):
         """List of paths for which |hook| should not be executed."""
-        return shlex.split(self.config.get(
-            self.BUILTIN_HOOKS_EXCLUDE_SECTION, hook, fallback=''))
+        return shlex.split(
+            self.config.get(
+                self.BUILTIN_HOOKS_EXCLUDE_SECTION, hook, fallback=""
+            )
+        )
 
     @property
     def tool_paths(self):
@@ -145,9 +155,9 @@ class PreUploadConfig(object):
         """Yield a CallableHook for each hook to be executed."""
         scope = rh.hooks.ExclusionScope([])
         for hook in self.custom_hooks:
-            options = rh.hooks.HookOptions(hook,
-                                           self.custom_hook(hook),
-                                           self.tool_paths)
+            options = rh.hooks.HookOptions(
+                hook, self.custom_hook(hook), self.tool_paths
+            )
             func = functools.partial(rh.hooks.check_custom, options=options)
             yield rh.hooks.CallableHook(hook, func, scope)
 
@@ -155,22 +165,28 @@ class PreUploadConfig(object):
         """Yield a CallableHook for each hook to be executed."""
         scope = rh.hooks.ExclusionScope([])
         for hook in self.builtin_hooks:
-            options = rh.hooks.HookOptions(hook,
-                                           self.builtin_hook_option(hook),
-                                           self.tool_paths)
-            func = functools.partial(rh.hooks.BUILTIN_HOOKS[hook],
-                                     options=options)
+            options = rh.hooks.HookOptions(
+                hook, self.builtin_hook_option(hook), self.tool_paths
+            )
+            func = functools.partial(
+                rh.hooks.BUILTIN_HOOKS[hook], options=options
+            )
             scope = rh.hooks.ExclusionScope(
-                self.builtin_hook_exclude_paths(hook))
+                self.builtin_hook_exclude_paths(hook)
+            )
             yield rh.hooks.CallableHook(hook, func, scope)
 
     @property
     def ignore_merged_commits(self):
         """Whether to skip hooks for merged commits."""
         return rh.shell.boolean_shell_value(
-            self.config.get(self.OPTIONS_SECTION,
-                            self.OPTION_IGNORE_MERGED_COMMITS, fallback=None),
-            False)
+            self.config.get(
+                self.OPTIONS_SECTION,
+                self.OPTION_IGNORE_MERGED_COMMITS,
+                fallback=None,
+            ),
+            False,
+        )
 
     def update(self, preupload_config):
         """Merge settings from |preupload_config| into ourself."""
@@ -184,13 +200,15 @@ class PreUploadConfig(object):
         bad_sections = set(config.sections()) - self.VALID_SECTIONS
         if bad_sections:
             raise ValidationError(
-                f'{self.source}: unknown sections: {bad_sections}')
+                f"{self.source}: unknown sections: {bad_sections}"
+            )
 
         # Reject blank custom hooks.
         for hook in self.custom_hooks:
             if not config.get(self.CUSTOM_HOOKS_SECTION, hook):
                 raise ValidationError(
-                    f'{self.source}: custom hook "{hook}" cannot be blank')
+                    f'{self.source}: custom hook "{hook}" cannot be blank'
+                )
 
         # Reject unknown builtin hooks.
         valid_builtin_hooks = set(rh.hooks.BUILTIN_HOOKS.keys())
@@ -199,17 +217,21 @@ class PreUploadConfig(object):
             bad_hooks = hooks - valid_builtin_hooks
             if bad_hooks:
                 raise ValidationError(
-                    f'{self.source}: unknown builtin hooks: {bad_hooks}')
+                    f"{self.source}: unknown builtin hooks: {bad_hooks}"
+                )
         elif config.has_section(self.BUILTIN_HOOKS_OPTIONS_SECTION):
-            raise ValidationError('Builtin hook options specified, but missing '
-                                  'builtin hook settings')
+            raise ValidationError(
+                "Builtin hook options specified, but missing "
+                "builtin hook settings"
+            )
 
         if config.has_section(self.BUILTIN_HOOKS_OPTIONS_SECTION):
             hooks = set(config.options(self.BUILTIN_HOOKS_OPTIONS_SECTION))
             bad_hooks = hooks - valid_builtin_hooks
             if bad_hooks:
                 raise ValidationError(
-                    f'{self.source}: unknown builtin hook options: {bad_hooks}')
+                    f"{self.source}: unknown builtin hook options: {bad_hooks}"
+                )
 
         # Verify hooks are valid shell strings.
         for hook in self.custom_hooks:
@@ -236,7 +258,8 @@ class PreUploadConfig(object):
             bad_tools = tools - valid_tools
             if bad_tools:
                 raise ValidationError(
-                    f'{self.source}: unknown tools: {bad_tools}')
+                    f"{self.source}: unknown tools: {bad_tools}"
+                )
 
         # Reject unknown options.
         if config.has_section(self.OPTIONS_SECTION):
@@ -244,7 +267,8 @@ class PreUploadConfig(object):
             bad_options = options - self.VALID_OPTIONS
             if bad_options:
                 raise ValidationError(
-                    f'{self.source}: unknown options: {bad_options}')
+                    f"{self.source}: unknown options: {bad_options}"
+                )
 
 
 class PreUploadFile(PreUploadConfig):
@@ -256,6 +280,7 @@ class PreUploadFile(PreUploadConfig):
     Attributes:
       path: The path of the file.
     """
+
     FILENAME = None
 
     def __init__(self, path):
@@ -270,7 +295,7 @@ class PreUploadFile(PreUploadConfig):
         try:
             self.config.read(path)
         except configparser.ParsingError as e:
-            raise ValidationError(f'{path}: {e}') from e
+            raise ValidationError(f"{path}: {e}") from e
 
         self._validate()
 
@@ -292,7 +317,8 @@ class PreUploadFile(PreUploadConfig):
 
 class LocalPreUploadFile(PreUploadFile):
     """A single config file for a project (PREUPLOAD.cfg)."""
-    FILENAME = 'PREUPLOAD.cfg'
+
+    FILENAME = "PREUPLOAD.cfg"
 
     def _validate(self):
         super()._validate()
@@ -300,13 +326,15 @@ class LocalPreUploadFile(PreUploadFile):
         # Reject Exclude Paths section for local config.
         if self.config.has_section(self.BUILTIN_HOOKS_EXCLUDE_SECTION):
             raise ValidationError(
-                f'{self.path}: [{self.BUILTIN_HOOKS_EXCLUDE_SECTION}] is not '
-                'valid in local files')
+                f"{self.path}: [{self.BUILTIN_HOOKS_EXCLUDE_SECTION}] is not "
+                "valid in local files"
+            )
 
 
 class GlobalPreUploadFile(PreUploadFile):
     """A single config file for a repo (GLOBAL-PREUPLOAD.cfg)."""
-    FILENAME = 'GLOBAL-PREUPLOAD.cfg'
+
+    FILENAME = "GLOBAL-PREUPLOAD.cfg"
 
 
 class PreUploadSettings(PreUploadConfig):
@@ -316,7 +344,7 @@ class PreUploadSettings(PreUploadConfig):
     settings for a particular project.
     """
 
-    def __init__(self, paths=('',), global_paths=()):
+    def __init__(self, paths=("",), global_paths=()):
         """Initialize.
 
         All the config files found will be merged together in order.
@@ -329,12 +357,12 @@ class PreUploadSettings(PreUploadConfig):
 
         self.paths = []
         for config in itertools.chain(
-                GlobalPreUploadFile.from_paths(global_paths),
-                LocalPreUploadFile.from_paths(paths)):
+            GlobalPreUploadFile.from_paths(global_paths),
+            LocalPreUploadFile.from_paths(paths),
+        ):
             self.paths.append(config.path)
             self.update(config)
 
-
         # We validated configs in isolation, now do one final pass altogether.
-        self.source = '{' + '|'.join(self.paths) + '}'
+        self.source = "{" + "|".join(self.paths) + "}"
         self._validate()
diff --git a/rh/config_test.py b/rh/config_test.py
index df3afb6..b63a657 100755
--- a/rh/config_test.py
+++ b/rh/config_test.py
@@ -32,25 +32,26 @@ def assertEqual(msg, exp, actual):
 
 def assertEnv(var, value):
     """Assert |var| is set in the environment as |value|."""
-    assert var in os.environ, f'${var} missing in environment'
-    assertEqual(f'env[{var}]', value, os.environ[var])
+    assert var in os.environ, f"${var} missing in environment"
+    assertEqual(f"env[{var}]", value, os.environ[var])
 
 
 def check_commit_id(commit):
     """Check |commit| looks like a git commit id."""
     assert len(commit) == 40, f'commit "{commit}" must be 40 chars'
-    assert re.match(r'^[a-f0-9]+$', commit), \
-        f'commit "{commit}" must be all hex'
+    assert re.match(
+        r"^[a-f0-9]+$", commit
+    ), f'commit "{commit}" must be all hex'
 
 
 def check_commit_msg(msg):
     """Check the ${PREUPLOAD_COMMIT_MESSAGE} setting."""
-    assert len(msg) > 1, f'commit message must be at least 2 bytes: {msg}'
+    assert len(msg) > 1, f"commit message must be at least 2 bytes: {msg}"
 
 
 def check_repo_root(root):
     """Check the ${REPO_ROOT} setting."""
-    assertEqual('REPO_ROOT', REPO_ROOT, root)
+    assertEqual("REPO_ROOT", REPO_ROOT, root)
 
 
 def check_files(files):
@@ -60,27 +61,26 @@ def check_files(files):
 
 def check_env():
     """Verify all exported env vars look sane."""
-    assertEnv('REPO_PROJECT', 'platform/tools/repohooks')
-    assertEnv('REPO_PATH', 'tools/repohooks')
-    assertEnv('REPO_REMOTE', 'aosp')
-    check_commit_id(os.environ['REPO_LREV'])
-    print(os.environ['REPO_RREV'])
-    check_commit_id(os.environ['PREUPLOAD_COMMIT'])
+    assertEnv("REPO_PROJECT", "platform/tools/repohooks")
+    assertEnv("REPO_PATH", "tools/repohooks")
+    assertEnv("REPO_REMOTE", "aosp")
+    check_commit_id(os.environ["REPO_LREV"])
+    print(os.environ["REPO_RREV"])
+    check_commit_id(os.environ["PREUPLOAD_COMMIT"])
 
 
 def get_parser():
     """Return a command line parser."""
     parser = argparse.ArgumentParser(description=__doc__)
-    parser.add_argument('--check-env', action='store_true',
-                        help='Check all exported env vars.')
-    parser.add_argument('--commit-id',
-                        help='${PREUPLOAD_COMMIT} setting.')
-    parser.add_argument('--commit-msg',
-                        help='${PREUPLOAD_COMMIT_MESSAGE} setting.')
-    parser.add_argument('--repo-root',
-                        help='${REPO_ROOT} setting.')
-    parser.add_argument('files', nargs='+',
-                        help='${PREUPLOAD_FILES} paths.')
+    parser.add_argument(
+        "--check-env", action="store_true", help="Check all exported env vars."
+    )
+    parser.add_argument("--commit-id", help="${PREUPLOAD_COMMIT} setting.")
+    parser.add_argument(
+        "--commit-msg", help="${PREUPLOAD_COMMIT_MESSAGE} setting."
+    )
+    parser.add_argument("--repo-root", help="${REPO_ROOT} setting.")
+    parser.add_argument("files", nargs="+", help="${PREUPLOAD_FILES} paths.")
     return parser
 
 
@@ -100,11 +100,11 @@ def main(argv):
             check_repo_root(opts.repo_root)
         check_files(opts.files)
     except AssertionError as e:
-        print(f'error: {e}', file=sys.stderr)
+        print(f"error: {e}", file=sys.stderr)
         return 1
 
     return 0
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     sys.exit(main(sys.argv[1:]))
diff --git a/rh/config_unittest.py b/rh/config_unittest.py
index 475dc22..b645320 100755
--- a/rh/config_unittest.py
+++ b/rh/config_unittest.py
@@ -21,7 +21,7 @@ import sys
 import tempfile
 import unittest
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -50,26 +50,28 @@ class FileTestCase(unittest.TestCase):
     def tearDown(self):
         shutil.rmtree(self.tempdir)
 
-    def _write_config(self, data, filename='temp.cfg'):
+    def _write_config(self, data, filename="temp.cfg"):
         """Helper to write out a config file for testing.
 
         Returns:
           Path to the file where the configuration was written.
         """
         path = os.path.join(self.tempdir, filename)
-        with open(path, 'w', encoding='utf-8') as fp:
+        with open(path, "w", encoding="utf-8") as fp:
             fp.write(data)
         return path
 
     def _write_local_config(self, data):
         """Helper to write out a local config file for testing."""
         return self._write_config(
-            data, filename=rh.config.LocalPreUploadFile.FILENAME)
+            data, filename=rh.config.LocalPreUploadFile.FILENAME
+        )
 
     def _write_global_config(self, data):
         """Helper to write out a global config file for testing."""
         return self._write_config(
-            data, filename=rh.config.GlobalPreUploadFile.FILENAME)
+            data, filename=rh.config.GlobalPreUploadFile.FILENAME
+        )
 
 
 class PreUploadFileTests(FileTestCase):
@@ -77,12 +79,13 @@ class PreUploadFileTests(FileTestCase):
 
     def testEmpty(self):
         """Instantiating an empty config file should be fine."""
-        path = self._write_config('')
+        path = self._write_config("")
         rh.config.PreUploadFile(path)
 
     def testValid(self):
         """Verify a fully valid file works."""
-        path = self._write_config("""# This be a comment me matey.
+        path = self._write_config(
+            """# This be a comment me matey.
 [Hook Scripts]
 name = script --with "some args"
 
@@ -94,40 +97,48 @@ cpplint = --some 'more args'
 
 [Options]
 ignore_merged_commits = true
-""")
+"""
+        )
         rh.config.PreUploadFile(path)
 
     def testUnknownSection(self):
         """Reject unknown sections."""
-        path = self._write_config('[BOOGA]')
-        self.assertRaises(rh.config.ValidationError, rh.config.PreUploadFile,
-                          path)
+        path = self._write_config("[BOOGA]")
+        self.assertRaises(
+            rh.config.ValidationError, rh.config.PreUploadFile, path
+        )
 
     def testUnknownBuiltin(self):
         """Reject unknown builtin hooks."""
-        path = self._write_config('[Builtin Hooks]\nbooga = borg!')
-        self.assertRaises(rh.config.ValidationError, rh.config.PreUploadFile,
-                          path)
+        path = self._write_config("[Builtin Hooks]\nbooga = borg!")
+        self.assertRaises(
+            rh.config.ValidationError, rh.config.PreUploadFile, path
+        )
 
     def testEmptyCustomHook(self):
         """Reject empty custom hooks."""
-        path = self._write_config('[Hook Scripts]\nbooga = \t \n')
-        self.assertRaises(rh.config.ValidationError, rh.config.PreUploadFile,
-                          path)
+        path = self._write_config("[Hook Scripts]\nbooga = \t \n")
+        self.assertRaises(
+            rh.config.ValidationError, rh.config.PreUploadFile, path
+        )
 
     def testInvalidIni(self):
         """Reject invalid ini files."""
-        path = self._write_config('[Hook Scripts]\n =')
-        self.assertRaises(rh.config.ValidationError, rh.config.PreUploadFile,
-                          path)
+        path = self._write_config("[Hook Scripts]\n =")
+        self.assertRaises(
+            rh.config.ValidationError, rh.config.PreUploadFile, path
+        )
 
     def testInvalidString(self):
         """Catch invalid string quoting."""
-        path = self._write_config("""[Hook Scripts]
+        path = self._write_config(
+            """[Hook Scripts]
 name = script --'bad-quotes
-""")
-        self.assertRaises(rh.config.ValidationError, rh.config.PreUploadFile,
-                          path)
+"""
+        )
+        self.assertRaises(
+            rh.config.ValidationError, rh.config.PreUploadFile, path
+        )
 
 
 class LocalPreUploadFileTests(FileTestCase):
@@ -135,12 +146,14 @@ class LocalPreUploadFileTests(FileTestCase):
 
     def testInvalidSectionConfig(self):
         """Reject local config that uses invalid sections."""
-        path = self._write_config("""[Builtin Hooks Exclude Paths]
+        path = self._write_config(
+            """[Builtin Hooks Exclude Paths]
 cpplint = external/ 'test directory' ^vendor/(?!google/)
-""")
-        self.assertRaises(rh.config.ValidationError,
-                          rh.config.LocalPreUploadFile,
-                          path)
+"""
+        )
+        self.assertRaises(
+            rh.config.ValidationError, rh.config.LocalPreUploadFile, path
+        )
 
 
 class PreUploadSettingsTests(FileTestCase):
@@ -148,25 +161,34 @@ class PreUploadSettingsTests(FileTestCase):
 
     def testGlobalConfigs(self):
         """Verify global configs stack properly."""
-        self._write_global_config("""[Builtin Hooks]
+        self._write_global_config(
+            """[Builtin Hooks]
 commit_msg_bug_field = true
 commit_msg_changeid_field = true
-commit_msg_test_field = false""")
-        self._write_local_config("""[Builtin Hooks]
+commit_msg_test_field = false"""
+        )
+        self._write_local_config(
+            """[Builtin Hooks]
 commit_msg_bug_field = false
-commit_msg_test_field = true""")
-        config = rh.config.PreUploadSettings(paths=(self.tempdir,),
-                                             global_paths=(self.tempdir,))
-        self.assertEqual(config.builtin_hooks,
-                         ['commit_msg_changeid_field', 'commit_msg_test_field'])
+commit_msg_test_field = true"""
+        )
+        config = rh.config.PreUploadSettings(
+            paths=(self.tempdir,), global_paths=(self.tempdir,)
+        )
+        self.assertEqual(
+            config.builtin_hooks,
+            ["commit_msg_changeid_field", "commit_msg_test_field"],
+        )
 
     def testGlobalExcludeScope(self):
         """Verify exclude scope is valid for global config."""
-        self._write_global_config("""[Builtin Hooks Exclude Paths]
+        self._write_global_config(
+            """[Builtin Hooks Exclude Paths]
 cpplint = external/ 'test directory' ^vendor/(?!google/)
-""")
+"""
+        )
         rh.config.PreUploadSettings(global_paths=(self.tempdir,))
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     unittest.main()
diff --git a/rh/git.py b/rh/git.py
index 5496164..1b3143d 100644
--- a/rh/git.py
+++ b/rh/git.py
@@ -18,7 +18,7 @@ import os
 import re
 import sys
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -30,12 +30,12 @@ import rh.utils
 def get_upstream_remote():
     """Returns the current upstream remote name."""
     # First get the current branch name.
-    cmd = ['git', 'rev-parse', '--abbrev-ref', 'HEAD']
+    cmd = ["git", "rev-parse", "--abbrev-ref", "HEAD"]
     result = rh.utils.run(cmd, capture_output=True)
     branch = result.stdout.strip()
 
     # Then get the remote associated with this branch.
-    cmd = ['git', 'config', f'branch.{branch}.remote']
+    cmd = ["git", "config", f"branch.{branch}.remote"]
     result = rh.utils.run(cmd, capture_output=True)
     return result.stdout.strip()
 
@@ -46,46 +46,46 @@ def get_upstream_branch():
     Raises:
       Error if there is no tracking branch
     """
-    cmd = ['git', 'symbolic-ref', 'HEAD']
+    cmd = ["git", "symbolic-ref", "HEAD"]
     result = rh.utils.run(cmd, capture_output=True)
-    current_branch = result.stdout.strip().replace('refs/heads/', '')
+    current_branch = result.stdout.strip().replace("refs/heads/", "")
     if not current_branch:
-        raise ValueError('Need to be on a tracking branch')
+        raise ValueError("Need to be on a tracking branch")
 
-    cfg_option = 'branch.' + current_branch + '.'
-    cmd = ['git', 'config', cfg_option + 'merge']
+    cfg_option = "branch." + current_branch + "."
+    cmd = ["git", "config", cfg_option + "merge"]
     result = rh.utils.run(cmd, capture_output=True)
     full_upstream = result.stdout.strip()
     # If remote is not fully qualified, add an implicit namespace.
-    if '/' not in full_upstream:
-        full_upstream = f'refs/heads/{full_upstream}'
-    cmd = ['git', 'config', cfg_option + 'remote']
+    if "/" not in full_upstream:
+        full_upstream = f"refs/heads/{full_upstream}"
+    cmd = ["git", "config", cfg_option + "remote"]
     result = rh.utils.run(cmd, capture_output=True)
     remote = result.stdout.strip()
     if not remote or not full_upstream:
-        raise ValueError('Need to be on a tracking branch')
+        raise ValueError("Need to be on a tracking branch")
 
-    return full_upstream.replace('heads', 'remotes/' + remote)
+    return full_upstream.replace("heads", "remotes/" + remote)
 
 
 def get_commit_for_ref(ref):
     """Returns the latest commit for this ref."""
-    cmd = ['git', 'rev-parse', ref]
+    cmd = ["git", "rev-parse", ref]
     result = rh.utils.run(cmd, capture_output=True)
     return result.stdout.strip()
 
 
 def get_remote_revision(ref, remote):
     """Returns the remote revision for this ref."""
-    prefix = f'refs/remotes/{remote}/'
+    prefix = f"refs/remotes/{remote}/"
     if ref.startswith(prefix):
-        return ref[len(prefix):]
+        return ref[len(prefix) :]
     return ref
 
 
 def get_patch(commit):
     """Returns the patch for this commit."""
-    cmd = ['git', 'format-patch', '--stdout', '-1', commit]
+    cmd = ["git", "format-patch", "--stdout", "-1", commit]
     return rh.utils.run(cmd, capture_output=True).stdout
 
 
@@ -99,7 +99,7 @@ def get_file_content(commit, path):
     a full file, you should check that first.  One way to detect is that the
     content will not have any newlines.
     """
-    cmd = ['git', 'show', f'{commit}:{path}']
+    cmd = ["git", "show", f"{commit}:{path}"]
     return rh.utils.run(cmd, capture_output=True).stdout
 
 
@@ -107,9 +107,18 @@ class RawDiffEntry(object):
     """Representation of a line from raw formatted git diff output."""
 
     # pylint: disable=redefined-builtin
-    def __init__(self, src_mode=0, dst_mode=0, src_sha=None, dst_sha=None,
-                 status=None, score=None, src_file=None, dst_file=None,
-                 file=None):
+    def __init__(
+        self,
+        src_mode=0,
+        dst_mode=0,
+        src_sha=None,
+        dst_sha=None,
+        status=None,
+        score=None,
+        src_file=None,
+        dst_file=None,
+        file=None,
+    ):
         self.src_mode = src_mode
         self.dst_mode = dst_mode
         self.src_sha = src_sha
@@ -123,10 +132,11 @@ class RawDiffEntry(object):
 
 # This regular expression pulls apart a line of raw formatted git diff output.
 DIFF_RE = re.compile(
-    r':(?P<src_mode>[0-7]*) (?P<dst_mode>[0-7]*) '
-    r'(?P<src_sha>[0-9a-f]*)(\.)* (?P<dst_sha>[0-9a-f]*)(\.)* '
-    r'(?P<status>[ACDMRTUX])(?P<score>[0-9]+)?\t'
-    r'(?P<src_file>[^\t]+)\t?(?P<dst_file>[^\t]+)?')
+    r":(?P<src_mode>[0-7]*) (?P<dst_mode>[0-7]*) "
+    r"(?P<src_sha>[0-9a-f]*)(\.)* (?P<dst_sha>[0-9a-f]*)(\.)* "
+    r"(?P<status>[ACDMRTUX])(?P<score>[0-9]+)?\t"
+    r"(?P<src_file>[^\t]+)\t?(?P<dst_file>[^\t]+)?"
+)
 
 
 def raw_diff(path, target):
@@ -141,18 +151,19 @@ def raw_diff(path, target):
     """
     entries = []
 
-    cmd = ['git', 'diff', '--no-ext-diff', '-M', '--raw', target]
+    cmd = ["git", "diff", "--no-ext-diff", "-M", "--raw", target]
     diff = rh.utils.run(cmd, cwd=path, capture_output=True).stdout
     diff_lines = diff.strip().splitlines()
     for line in diff_lines:
         match = DIFF_RE.match(line)
         if not match:
-            raise ValueError(f'Failed to parse diff output: {line}')
+            raise ValueError(f"Failed to parse diff output: {line}")
         rawdiff = RawDiffEntry(**match.groupdict())
         rawdiff.src_mode = int(rawdiff.src_mode)
         rawdiff.dst_mode = int(rawdiff.dst_mode)
-        rawdiff.file = (rawdiff.dst_file
-                        if rawdiff.dst_file else rawdiff.src_file)
+        rawdiff.file = (
+            rawdiff.dst_file if rawdiff.dst_file else rawdiff.src_file
+        )
         entries.append(rawdiff)
 
     return entries
@@ -164,20 +175,20 @@ def get_affected_files(commit):
     Returns:
       A list of modified/added (and perhaps deleted) files
     """
-    return raw_diff(os.getcwd(), f'{commit}^-')
+    return raw_diff(os.getcwd(), f"{commit}^-")
 
 
 def get_commits(ignore_merged_commits=False):
     """Returns a list of commits for this review."""
-    cmd = ['git', 'rev-list', f'{get_upstream_branch()}..']
+    cmd = ["git", "rev-list", f"{get_upstream_branch()}.."]
     if ignore_merged_commits:
-        cmd.append('--first-parent')
+        cmd.append("--first-parent")
     return rh.utils.run(cmd, capture_output=True).stdout.split()
 
 
 def get_commit_desc(commit):
     """Returns the full commit message of a commit."""
-    cmd = ['git', 'diff-tree', '-s', '--always', '--format=%B', commit]
+    cmd = ["git", "diff-tree", "-s", "--always", "--format=%B", commit]
     return rh.utils.run(cmd, capture_output=True).stdout
 
 
@@ -196,24 +207,27 @@ def find_repo_root(path=None, outer=False):
     # If we are working on a superproject instead of a repo client, use the
     # result from git directly.  For regular repo client, this would return
     # empty string.
-    cmd = ['git', 'rev-parse', '--show-superproject-working-tree']
-    git_worktree_path = rh.utils.run(cmd, cwd=path, capture_output=True).stdout.strip()
+    cmd = ["git", "rev-parse", "--show-superproject-working-tree"]
+    git_worktree_path = rh.utils.run(
+        cmd, cwd=path, capture_output=True
+    ).stdout.strip()
     if git_worktree_path:
         return git_worktree_path
 
-    while not os.path.exists(os.path.join(path, '.repo')):
+    while not os.path.exists(os.path.join(path, ".repo")):
         path = os.path.dirname(path)
-        if path == '/':
-            raise ValueError(f'Could not locate .repo in {orig_path}')
+        if path == "/":
+            raise ValueError(f"Could not locate .repo in {orig_path}")
 
     root = path
-    if not outer and os.path.isdir(os.path.join(root, '.repo', 'submanifests')):
+    if not outer and os.path.isdir(os.path.join(root, ".repo", "submanifests")):
         # If there are submanifests, walk backward from path until we find the
         # corresponding submanifest root.
         abs_orig_path = os.path.abspath(orig_path)
         parts = os.path.relpath(abs_orig_path, root).split(os.path.sep)
         while parts and not os.path.isdir(
-            os.path.join(root, '.repo', 'submanifests', *parts, 'manifests')):
+            os.path.join(root, ".repo", "submanifests", *parts, "manifests")
+        ):
             parts.pop()
         path = os.path.join(root, *parts)
 
@@ -222,6 +236,6 @@ def find_repo_root(path=None, outer=False):
 
 def is_git_repository(path):
     """Returns True if the path is a valid git repository."""
-    cmd = ['git', 'rev-parse', '--resolve-git-dir', os.path.join(path, '.git')]
+    cmd = ["git", "rev-parse", "--resolve-git-dir", os.path.join(path, ".git")]
     result = rh.utils.run(cmd, capture_output=True, check=False)
     return result.returncode == 0
diff --git a/rh/hooks.py b/rh/hooks.py
index 6bdf344..8f128b0 100644
--- a/rh/hooks.py
+++ b/rh/hooks.py
@@ -22,7 +22,7 @@ import re
 import sys
 from typing import Callable, NamedTuple
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -67,23 +67,26 @@ class Placeholders(object):
 
         ret = []
         for arg in args:
-            if arg.endswith('${PREUPLOAD_FILES_PREFIXED}'):
-                if arg == '${PREUPLOAD_FILES_PREFIXED}':
-                    assert len(ret) > 1, ('PREUPLOAD_FILES_PREFIXED cannot be '
-                                          'the 1st or 2nd argument')
+            if arg.endswith("${PREUPLOAD_FILES_PREFIXED}"):
+                if arg == "${PREUPLOAD_FILES_PREFIXED}":
+                    assert len(ret) > 1, (
+                        "PREUPLOAD_FILES_PREFIXED cannot be "
+                        "the 1st or 2nd argument"
+                    )
                     prev_arg = ret[-1]
                     ret = ret[0:-1]
-                    for file in self.get('PREUPLOAD_FILES'):
+                    for file in self.get("PREUPLOAD_FILES"):
                         ret.append(prev_arg)
                         ret.append(file)
                 else:
-                    prefix = arg[0:-len('${PREUPLOAD_FILES_PREFIXED}')]
+                    prefix = arg[0 : -len("${PREUPLOAD_FILES_PREFIXED}")]
                     ret.extend(
-                        prefix + file for file in self.get('PREUPLOAD_FILES'))
+                        prefix + file for file in self.get("PREUPLOAD_FILES")
+                    )
             else:
                 # First scan for exact matches
                 for key, val in replacements.items():
-                    var = '${' + key + '}'
+                    var = "${" + key + "}"
                     if arg == var:
                         if isinstance(val, str):
                             ret.append(val)
@@ -97,46 +100,50 @@ class Placeholders(object):
                         val = self.get(m.group(1))
                         if isinstance(val, str):
                             return val
-                        return ' '.join(val)
-                    ret.append(re.sub(r'\$\{(' + '|'.join(all_vars) + r')\}',
-                                      replace, arg))
+                        return " ".join(val)
+
+                    ret.append(
+                        re.sub(
+                            r"\$\{(" + "|".join(all_vars) + r")\}", replace, arg
+                        )
+                    )
         return ret
 
     @classmethod
     def vars(cls):
         """Yield all replacement variable names."""
         for key in dir(cls):
-            if key.startswith('var_'):
+            if key.startswith("var_"):
                 yield key[4:]
 
     def get(self, var):
         """Helper function to get the replacement |var| value."""
-        return getattr(self, f'var_{var}')
+        return getattr(self, f"var_{var}")
 
     @property
     def var_PREUPLOAD_COMMIT_MESSAGE(self):
         """The git commit message."""
-        return os.environ.get('PREUPLOAD_COMMIT_MESSAGE', '')
+        return os.environ.get("PREUPLOAD_COMMIT_MESSAGE", "")
 
     @property
     def var_PREUPLOAD_COMMIT(self):
         """The git commit sha1."""
-        return os.environ.get('PREUPLOAD_COMMIT', '')
+        return os.environ.get("PREUPLOAD_COMMIT", "")
 
     @property
     def var_PREUPLOAD_FILES(self):
         """List of files modified in this git commit."""
-        return [x.file for x in self.diff if x.status != 'D']
+        return [x.file for x in self.diff if x.status != "D"]
 
     @property
     def var_REPO_PATH(self):
         """The path to the project relative to the root"""
-        return os.environ.get('REPO_PATH', '')
+        return os.environ.get("REPO_PATH", "")
 
     @property
     def var_REPO_PROJECT(self):
         """The name of the project"""
-        return os.environ.get('REPO_PROJECT', '')
+        return os.environ.get("REPO_PROJECT", "")
 
     @property
     def var_REPO_ROOT(self):
@@ -170,7 +177,7 @@ class ExclusionScope(object):
         """
         self._scope = []
         for path in scope:
-            if path.startswith('^'):
+            if path.startswith("^"):
                 self._scope.append(re.compile(path))
             else:
                 self._scope.append(path)
@@ -182,7 +189,7 @@ class ExclusionScope(object):
           proj_dir: The relative path of the project.
         """
         for exclusion_path in self._scope:
-            if hasattr(exclusion_path, 'match'):
+            if hasattr(exclusion_path, "match"):
                 if exclusion_path.match(proj_dir):
                     return True
             elif fnmatch.fnmatch(proj_dir, exclusion_path):
@@ -250,6 +257,7 @@ class HookOptions(object):
 
 class CallableHook(NamedTuple):
     """A callable hook."""
+
     name: str
     hook: Callable
     scope: ExclusionScope
@@ -257,12 +265,12 @@ class CallableHook(NamedTuple):
 
 def _run(cmd, **kwargs):
     """Helper command for checks that tend to gather output."""
-    kwargs.setdefault('combine_stdout_stderr', True)
-    kwargs.setdefault('capture_output', True)
-    kwargs.setdefault('check', False)
+    kwargs.setdefault("combine_stdout_stderr", True)
+    kwargs.setdefault("capture_output", True)
+    kwargs.setdefault("check", False)
     # Make sure hooks run with stdin disconnected to avoid accidentally
     # interactive tools causing pauses.
-    kwargs.setdefault('input', '')
+    kwargs.setdefault("input", "")
     return rh.utils.run(cmd, **kwargs)
 
 
@@ -300,9 +308,11 @@ def _filter_diff(diff, include_list, exclude_list=()):
     """
     filtered = []
     for d in diff:
-        if (d.status != 'D' and
-                _match_regex_list(d.file, include_list) and
-                not _match_regex_list(d.file, exclude_list)):
+        if (
+            d.status != "D"
+            and _match_regex_list(d.file, include_list)
+            and not _match_regex_list(d.file, exclude_list)
+        ):
             # We've got a match!
             filtered.append(d)
     return filtered
@@ -315,22 +325,25 @@ def _get_build_os_name():
       A string in a format usable to get prebuilt tool paths.
     """
     system = platform.system()
-    if 'Darwin' in system or 'Macintosh' in system:
-        return 'darwin-x86'
+    if "Darwin" in system or "Macintosh" in system:
+        return "darwin-x86"
 
     # TODO: Add more values if needed.
-    return 'linux-x86'
+    return "linux-x86"
 
 
 def _check_cmd(hook_name, project, commit, cmd, fixup_cmd=None, **kwargs):
     """Runs |cmd| and returns its result as a HookCommandResult."""
-    return [rh.results.HookCommandResult(hook_name, project, commit,
-                                         _run(cmd, **kwargs),
-                                         fixup_cmd=fixup_cmd)]
+    return [
+        rh.results.HookCommandResult(
+            hook_name, project, commit, _run(cmd, **kwargs), fixup_cmd=fixup_cmd
+        )
+    ]
 
 
 # Where helper programs exist.
-TOOLS_DIR = os.path.realpath(__file__ + '/../../tools')
+TOOLS_DIR = os.path.realpath(__file__ + "/../../tools")
+
 
 def get_helper_path(tool):
     """Return the full path to the helper |tool|."""
@@ -339,110 +352,157 @@ def get_helper_path(tool):
 
 def check_custom(project, commit, _desc, diff, options=None, **kwargs):
     """Run a custom hook."""
-    return _check_cmd(options.name, project, commit, options.args((), diff),
-                      **kwargs)
+    return _check_cmd(
+        options.name, project, commit, options.args((), diff), **kwargs
+    )
 
 
 def check_aosp_license(project, commit, _desc, diff, options=None):
     """Checks that if all new added files has AOSP licenses"""
 
-    exclude_dir_args = [x for x in options.args()
-                        if x.startswith('--exclude-dirs=')]
-    exclude_dirs = [x[len('--exclude-dirs='):].split(',')
-                    for x in exclude_dir_args]
-    exclude_list = [fr'^{x}/.*$' for dir_list in exclude_dirs for x in dir_list]
+    exclude_dir_args = [
+        x for x in options.args() if x.startswith("--exclude-dirs=")
+    ]
+    exclude_dirs = [
+        x[len("--exclude-dirs=") :].split(",") for x in exclude_dir_args
+    ]
+    exclude_list = [rf"^{x}/.*$" for dir_list in exclude_dirs for x in dir_list]
 
     # Filter diff based on extension.
-    extensions = frozenset((
-        # Coding languages and scripts.
-        'c',
-        'cc',
-        'cpp',
-        'h',
-        'java',
-        'kt',
-        'rs',
-        'py',
-        'sh',
-
-        # Build and config files.
-        'bp',
-        'mk',
-        'xml',
-    ))
-    diff = _filter_diff(diff, [r'\.(' + '|'.join(extensions) + r')$'], exclude_list)
+    extensions = frozenset(
+        (
+            # Coding languages and scripts.
+            "c",
+            "cc",
+            "cpp",
+            "h",
+            "java",
+            "kt",
+            "rs",
+            "py",
+            "sh",
+            # Build and config files.
+            "bp",
+            "mk",
+            "xml",
+        )
+    )
+    diff = _filter_diff(
+        diff, [r"\.(" + "|".join(extensions) + r")$"], exclude_list
+    )
 
     # Only check the new-added files.
-    diff = [d for d in diff if d.status == 'A']
+    diff = [d for d in diff if d.status == "A"]
 
     if not diff:
         return None
 
-    cmd = [get_helper_path('check_aosp_license.py'), '--commit-hash', commit]
-    cmd += HookOptions.expand_vars(('${PREUPLOAD_FILES}',), diff)
-    return _check_cmd('aosp_license', project, commit, cmd)
+    cmd = [get_helper_path("check_aosp_license.py"), "--commit-hash", commit]
+    cmd += HookOptions.expand_vars(("${PREUPLOAD_FILES}",), diff)
+    return _check_cmd("aosp_license", project, commit, cmd)
+
+
+def check_black(project, commit, _desc, diff, options=None):
+    """Checks that Python files are formatted with black."""
+    filtered = _filter_diff(diff, [r"\.py$"])
+    if not filtered:
+        return None
+
+    tool = options.tool_path("black")
+    tool_options = options.args((), filtered)
+    cmd = [tool, "--check"] + tool_options
+    fixup_cmd = [tool] + tool_options + ["--"]
+
+    ret = []
+    for d in filtered:
+        data = rh.git.get_file_content(commit, d.file)
+        result = _run(cmd, input=data)
+        if result.stdout:
+            ret.append(
+                rh.results.HookResult(
+                    "black",
+                    project,
+                    commit,
+                    error=result.stdout,
+                    files=(d.file,),
+                    fixup_cmd=fixup_cmd,
+                )
+            )
+    return ret
 
 
 def check_bpfmt(project, commit, _desc, diff, options=None):
     """Checks that Blueprint files are formatted with bpfmt."""
-    filtered = _filter_diff(diff, [r'\.bp$'])
+    filtered = _filter_diff(diff, [r"\.bp$"])
     if not filtered:
         return None
 
-    bpfmt = options.tool_path('bpfmt')
+    bpfmt = options.tool_path("bpfmt")
     bpfmt_options = options.args((), filtered)
-    cmd = [bpfmt, '-d'] + bpfmt_options
-    fixup_cmd = [bpfmt, '-w']
-    if '-s' in bpfmt_options:
-        fixup_cmd.append('-s')
-    fixup_cmd.append('--')
+    cmd = [bpfmt, "-d"] + bpfmt_options
+    fixup_cmd = [bpfmt, "-w"]
+    if "-s" in bpfmt_options:
+        fixup_cmd.append("-s")
+    fixup_cmd.append("--")
 
     ret = []
     for d in filtered:
         data = rh.git.get_file_content(commit, d.file)
         result = _run(cmd, input=data)
         if result.stdout:
-            ret.append(rh.results.HookResult(
-                'bpfmt', project, commit,
-                error=result.stdout,
-                files=(d.file,),
-                fixup_cmd=fixup_cmd))
+            ret.append(
+                rh.results.HookResult(
+                    "bpfmt",
+                    project,
+                    commit,
+                    error=result.stdout,
+                    files=(d.file,),
+                    fixup_cmd=fixup_cmd,
+                )
+            )
     return ret
 
 
 def check_checkpatch(project, commit, _desc, diff, options=None):
     """Run |diff| through the kernel's checkpatch.pl tool."""
-    tool = get_helper_path('checkpatch.pl')
-    cmd = ([tool, '-', '--root', project.dir] +
-           options.args(('--ignore=GERRIT_CHANGE_ID',), diff))
-    return _check_cmd('checkpatch.pl', project, commit, cmd,
-                      input=rh.git.get_patch(commit))
+    tool = get_helper_path("checkpatch.pl")
+    cmd = [tool, "-", "--root", project.dir] + options.args(
+        ("--ignore=GERRIT_CHANGE_ID",), diff
+    )
+    return _check_cmd(
+        "checkpatch.pl", project, commit, cmd, input=rh.git.get_patch(commit)
+    )
 
 
 def check_clang_format(project, commit, _desc, diff, options=None):
     """Run git clang-format on the commit."""
-    tool = get_helper_path('clang-format.py')
-    clang_format = options.tool_path('clang-format')
-    git_clang_format = options.tool_path('git-clang-format')
-    tool_args = (['--clang-format', clang_format, '--git-clang-format',
-                  git_clang_format] +
-                 options.args(('--style', 'file', '--commit', commit), diff))
+    tool = get_helper_path("clang-format.py")
+    clang_format = options.tool_path("clang-format")
+    git_clang_format = options.tool_path("git-clang-format")
+    tool_args = [
+        "--clang-format",
+        clang_format,
+        "--git-clang-format",
+        git_clang_format,
+    ] + options.args(("--style", "file", "--commit", commit), diff)
     cmd = [tool] + tool_args
-    fixup_cmd = [tool, '--fix'] + tool_args
-    return _check_cmd('clang-format', project, commit, cmd,
-                      fixup_cmd=fixup_cmd)
+    fixup_cmd = [tool, "--fix"] + tool_args
+    return _check_cmd("clang-format", project, commit, cmd, fixup_cmd=fixup_cmd)
 
 
 def check_google_java_format(project, commit, _desc, _diff, options=None):
     """Run google-java-format on the commit."""
-    include_dir_args = [x for x in options.args()
-                        if x.startswith('--include-dirs=')]
-    include_dirs = [x[len('--include-dirs='):].split(',')
-                    for x in include_dir_args]
-    patterns = [fr'^{x}/.*\.java$' for dir_list in include_dirs
-                for x in dir_list]
+    include_dir_args = [
+        x for x in options.args() if x.startswith("--include-dirs=")
+    ]
+    include_dirs = [
+        x[len("--include-dirs=") :].split(",") for x in include_dir_args
+    ]
+    patterns = [
+        rf"^{x}/.*\.java$" for dir_list in include_dirs for x in dir_list
+    ]
     if not patterns:
-        patterns = [r'\.java$']
+        patterns = [r"\.java$"]
 
     filtered = _filter_diff(_diff, patterns)
 
@@ -451,32 +511,47 @@ def check_google_java_format(project, commit, _desc, _diff, options=None):
 
     args = [x for x in options.args() if x not in include_dir_args]
 
-    tool = get_helper_path('google-java-format.py')
-    google_java_format = options.tool_path('google-java-format')
-    google_java_format_diff = options.tool_path('google-java-format-diff')
-    tool_args = ['--google-java-format', google_java_format,
-                 '--google-java-format-diff', google_java_format_diff,
-                 '--commit', commit] + args
-    cmd = [tool] + tool_args + HookOptions.expand_vars(
-                   ('${PREUPLOAD_FILES}',), filtered)
-    fixup_cmd = [tool, '--fix'] + tool_args
-    return [rh.results.HookCommandResult('google-java-format', project, commit,
-                                         _run(cmd),
-                                         files=[x.file for x in filtered],
-                                         fixup_cmd=fixup_cmd)]
+    tool = get_helper_path("google-java-format.py")
+    google_java_format = options.tool_path("google-java-format")
+    google_java_format_diff = options.tool_path("google-java-format-diff")
+    tool_args = [
+        "--google-java-format",
+        google_java_format,
+        "--google-java-format-diff",
+        google_java_format_diff,
+        "--commit",
+        commit,
+    ] + args
+    cmd = (
+        [tool]
+        + tool_args
+        + HookOptions.expand_vars(("${PREUPLOAD_FILES}",), filtered)
+    )
+    fixup_cmd = [tool, "--fix"] + tool_args
+    return [
+        rh.results.HookCommandResult(
+            "google-java-format",
+            project,
+            commit,
+            _run(cmd),
+            files=[x.file for x in filtered],
+            fixup_cmd=fixup_cmd,
+        )
+    ]
 
 
 def check_ktfmt(project, commit, _desc, diff, options=None):
     """Checks that kotlin files are formatted with ktfmt."""
 
-    include_dir_args = [x for x in options.args()
-                        if x.startswith('--include-dirs=')]
-    include_dirs = [x[len('--include-dirs='):].split(',')
-                    for x in include_dir_args]
-    patterns = [fr'^{x}/.*\.kt$' for dir_list in include_dirs
-                for x in dir_list]
+    include_dir_args = [
+        x for x in options.args() if x.startswith("--include-dirs=")
+    ]
+    include_dirs = [
+        x[len("--include-dirs=") :].split(",") for x in include_dir_args
+    ]
+    patterns = [rf"^{x}/.*\.kt$" for dir_list in include_dirs for x in dir_list]
     if not patterns:
-        patterns = [r'\.kt$']
+        patterns = [r"\.kt$"]
 
     filtered = _filter_diff(diff, patterns)
 
@@ -485,26 +560,36 @@ def check_ktfmt(project, commit, _desc, diff, options=None):
 
     args = [x for x in options.args() if x not in include_dir_args]
 
-    ktfmt = options.tool_path('ktfmt')
-    cmd = [ktfmt, '--dry-run'] + args + HookOptions.expand_vars(
-        ('${PREUPLOAD_FILES}',), filtered)
+    ktfmt = options.tool_path("ktfmt")
+    cmd = (
+        [ktfmt, "--dry-run"]
+        + args
+        + HookOptions.expand_vars(("${PREUPLOAD_FILES}",), filtered)
+    )
     result = _run(cmd)
     if result.stdout:
         fixup_cmd = [ktfmt] + args
-        return [rh.results.HookResult(
-            'ktfmt', project, commit, error='Formatting errors detected',
-            files=[x.file for x in filtered], fixup_cmd=fixup_cmd)]
+        return [
+            rh.results.HookResult(
+                "ktfmt",
+                project,
+                commit,
+                error="Formatting errors detected",
+                files=[x.file for x in filtered],
+                fixup_cmd=fixup_cmd,
+            )
+        ]
     return None
 
 
 def check_commit_msg_bug_field(project, commit, desc, _diff, options=None):
     """Check the commit message for a 'Bug:' or 'Fix:' line."""
-    field = 'Bug'
-    regex = r'^(Bug|Fix): (None|[0-9]+(, [0-9]+)*)$'
+    field = "Bug"
+    regex = r"^(Bug|Fix): (None|[0-9]+(, [0-9]+)*)$"
     check_re = re.compile(regex)
 
     if options.args():
-        raise ValueError(f'commit msg {field} check takes no options')
+        raise ValueError(f"commit msg {field} check takes no options")
 
     found = []
     for line in desc.splitlines():
@@ -514,23 +599,26 @@ def check_commit_msg_bug_field(project, commit, desc, _diff, options=None):
     if not found:
         error = (
             f'Commit message is missing a "{field}:" line.  It must match the\n'
-            f'following case-sensitive regex:\n\n    {regex}'
+            f"following case-sensitive regex:\n\n    {regex}"
         )
     else:
         return None
 
-    return [rh.results.HookResult(f'commit msg: "{field}:" check',
-                                  project, commit, error=error)]
+    return [
+        rh.results.HookResult(
+            f'commit msg: "{field}:" check', project, commit, error=error
+        )
+    ]
 
 
 def check_commit_msg_changeid_field(project, commit, desc, _diff, options=None):
     """Check the commit message for a 'Change-Id:' line."""
-    field = 'Change-Id'
-    regex = fr'^{field}: I[a-f0-9]+$'
+    field = "Change-Id"
+    regex = rf"^{field}: I[a-f0-9]+$"
     check_re = re.compile(regex)
 
     if options.args():
-        raise ValueError(f'commit msg {field} check takes no options')
+        raise ValueError(f"commit msg {field} check takes no options")
 
     found = []
     for line in desc.splitlines():
@@ -540,16 +628,21 @@ def check_commit_msg_changeid_field(project, commit, desc, _diff, options=None):
     if not found:
         error = (
             f'Commit message is missing a "{field}:" line.  It must match the\n'
-            f'following case-sensitive regex:\n\n    {regex}'
+            f"following case-sensitive regex:\n\n    {regex}"
         )
     elif len(found) > 1:
-        error = (f'Commit message has too many "{field}:" lines.  There can be '
-                 'only one.')
+        error = (
+            f'Commit message has too many "{field}:" lines.  There can be '
+            "only one."
+        )
     else:
         return None
 
-    return [rh.results.HookResult(f'commit msg: "{field}:" check',
-                                  project, commit, error=error)]
+    return [
+        rh.results.HookResult(
+            f'commit msg: "{field}:" check', project, commit, error=error
+        )
+    ]
 
 
 PREBUILT_APK_MSG = """Commit message is missing required prebuilt APK
@@ -574,25 +667,28 @@ For more information, see go/platform-prebuilt and go/android-prebuilt.
 """
 
 
-def check_commit_msg_prebuilt_apk_fields(project, commit, desc, diff,
-                                         options=None):
+def check_commit_msg_prebuilt_apk_fields(
+    project, commit, desc, diff, options=None
+):
     """Check that prebuilt APK commits contain the required lines."""
 
     if options.args():
-        raise ValueError('prebuilt apk check takes no options')
+        raise ValueError("prebuilt apk check takes no options")
 
-    filtered = _filter_diff(diff, [r'\.apk$'])
+    filtered = _filter_diff(diff, [r"\.apk$"])
     if not filtered:
         return None
 
     regexes = [
-        r'^package: .*$',
-        r'^sdkVersion:.*$',
-        r'^targetSdkVersion:.*$',
-        r'^Built here:.*$',
-        (r'^This build IS( NOT)? suitable for'
-         r'( preview|( preview or)? public) release'
-         r'( but IS NOT suitable for public release)?\.$')
+        r"^package: .*$",
+        r"^sdkVersion:.*$",
+        r"^targetSdkVersion:.*$",
+        r"^Built here:.*$",
+        (
+            r"^This build IS( NOT)? suitable for"
+            r"( preview|( preview or)? public) release"
+            r"( but IS NOT suitable for public release)?\.$"
+        ),
     ]
 
     missing = []
@@ -601,12 +697,15 @@ def check_commit_msg_prebuilt_apk_fields(project, commit, desc, diff,
             missing.append(regex)
 
     if missing:
-        error = PREBUILT_APK_MSG % '\n    '.join(missing)
+        error = PREBUILT_APK_MSG % "\n    ".join(missing)
     else:
         return None
 
-    return [rh.results.HookResult('commit msg: "prebuilt apk:" check',
-                                  project, commit, error=error)]
+    return [
+        rh.results.HookResult(
+            'commit msg: "prebuilt apk:" check', project, commit, error=error
+        )
+    ]
 
 
 TEST_MSG = """Commit message is missing a "Test:" line.  It must match the
@@ -640,12 +739,12 @@ high-quality Test: descriptions.
 
 def check_commit_msg_test_field(project, commit, desc, _diff, options=None):
     """Check the commit message for a 'Test:' line."""
-    field = 'Test'
-    regex = fr'^{field}: .*$'
+    field = "Test"
+    regex = rf"^{field}: .*$"
     check_re = re.compile(regex)
 
     if options.args():
-        raise ValueError(f'commit msg {field} check takes no options')
+        raise ValueError(f"commit msg {field} check takes no options")
 
     found = []
     for line in desc.splitlines():
@@ -657,8 +756,11 @@ def check_commit_msg_test_field(project, commit, desc, _diff, options=None):
     else:
         return None
 
-    return [rh.results.HookResult(f'commit msg: "{field}:" check',
-                                  project, commit, error=error)]
+    return [
+        rh.results.HookResult(
+            f'commit msg: "{field}:" check', project, commit, error=error
+        )
+    ]
 
 
 RELNOTE_MISSPELL_MSG = """Commit message contains something that looks
@@ -705,8 +807,10 @@ in edge cases."
 Relnote: Added a new API to handle strings like \"foo\"
 """
 
-def check_commit_msg_relnote_field_format(project, commit, desc, _diff,
-                                          options=None):
+
+def check_commit_msg_relnote_field_format(
+    project, commit, desc, _diff, options=None
+):
     """Check the commit for one correctly formatted 'Relnote:' line.
 
     Checks the commit message for two things:
@@ -716,59 +820,74 @@ def check_commit_msg_relnote_field_format(project, commit, desc, _diff,
     (3) Checks that release notes that contain non-starting or non-ending
     quotes are escaped with a backslash.
     """
-    field = 'Relnote'
-    regex_relnote = fr'^{field}:.*$'
+    field = "Relnote"
+    regex_relnote = rf"^{field}:.*$"
     check_re_relnote = re.compile(regex_relnote, re.IGNORECASE)
 
     if options.args():
-        raise ValueError(f'commit msg {field} check takes no options')
+        raise ValueError(f"commit msg {field} check takes no options")
 
     # Check 1: Check for possible misspellings of the `Relnote:` field.
 
     # Regex for misspelled fields.
     possible_field_misspells = {
-        'Relnotes', 'ReleaseNote',
-        'Rel-note', 'Rel note',
-        'rel-notes', 'releasenotes',
-        'release-note', 'release-notes',
+        "Relnotes",
+        "ReleaseNote",
+        "Rel-note",
+        "Rel note",
+        "rel-notes",
+        "releasenotes",
+        "release-note",
+        "release-notes",
     }
-    re_possible_field_misspells = '|'.join(possible_field_misspells)
-    regex_field_misspells = fr'^({re_possible_field_misspells}): .*$'
+    re_possible_field_misspells = "|".join(possible_field_misspells)
+    regex_field_misspells = rf"^({re_possible_field_misspells}): .*$"
     check_re_field_misspells = re.compile(regex_field_misspells, re.IGNORECASE)
 
     ret = []
     for line in desc.splitlines():
         if check_re_field_misspells.match(line):
-            error = RELNOTE_MISSPELL_MSG % (regex_relnote, )
+            error = RELNOTE_MISSPELL_MSG % (regex_relnote,)
             ret.append(
                 rh.results.HookResult(
                     f'commit msg: "{field}:" tag spelling error',
-                    project, commit, error=error))
+                    project,
+                    commit,
+                    error=error,
+                )
+            )
 
     # Check 2: Check that multiline Relnotes are quoted.
 
-    check_re_empty_string = re.compile(r'^$')
+    check_re_empty_string = re.compile(r"^$")
 
     # Regex to find other fields that could be used.
-    regex_other_fields = r'^[a-zA-Z0-9-]+:'
+    regex_other_fields = r"^[a-zA-Z0-9-]+:"
     check_re_other_fields = re.compile(regex_other_fields)
 
     desc_lines = desc.splitlines()
     for i, cur_line in enumerate(desc_lines):
         # Look for a Relnote tag that is before the last line and
         # lacking any quotes.
-        if (check_re_relnote.match(cur_line) and
-                i < len(desc_lines) - 1 and
-                '"' not in cur_line):
+        if (
+            check_re_relnote.match(cur_line)
+            and i < len(desc_lines) - 1
+            and '"' not in cur_line
+        ):
             next_line = desc_lines[i + 1]
             # Check that the next line does not contain any other field
             # and it's not an empty string.
-            if (not check_re_other_fields.findall(next_line) and
-                    not check_re_empty_string.match(next_line)):
+            if not check_re_other_fields.findall(
+                next_line
+            ) and not check_re_empty_string.match(next_line):
                 ret.append(
                     rh.results.HookResult(
                         f'commit msg: "{field}:" tag missing quotes',
-                        project, commit, error=RELNOTE_MISSING_QUOTES_MSG))
+                        project,
+                        commit,
+                        error=RELNOTE_MISSING_QUOTES_MSG,
+                    )
+                )
                 break
 
     # Check 3: Check that multiline Relnotes contain matching quotes.
@@ -802,7 +921,11 @@ def check_commit_msg_relnote_field_format(project, commit, desc, _diff,
         ret.append(
             rh.results.HookResult(
                 f'commit msg: "{field}:" tag missing closing quote',
-                project, commit, error=RELNOTE_MISSING_QUOTES_MSG))
+                project,
+                commit,
+                error=RELNOTE_MISSING_QUOTES_MSG,
+            )
+        )
 
     # Check 4: Check that non-starting or non-ending quotes are escaped with a
     # backslash.
@@ -820,8 +943,9 @@ def check_commit_msg_relnote_field_format(project, commit, desc, _diff,
             if '"""' in cur_line:
                 break
         if line_needs_checking:
-            stripped_line = re.sub(fr'^{field}:', '', cur_line,
-                                   flags=re.IGNORECASE).strip()
+            stripped_line = re.sub(
+                rf"^{field}:", "", cur_line, flags=re.IGNORECASE
+            ).strip()
             for i, character in enumerate(stripped_line):
                 if i == 0:
                     # Case 1: Valid quote at the beginning of the
@@ -834,17 +958,24 @@ def check_commit_msg_relnote_field_format(project, commit, desc, _diff,
                         uses_invalid_quotes = True
                         break
                 # Case 3: Check all other cases.
-                if (character == '"'
-                        and 0 < i < len(stripped_line) - 1
-                        and stripped_line[i-1] != '"'
-                        and stripped_line[i-1] != "\\"):
+                if (
+                    character == '"'
+                    and 0 < i < len(stripped_line) - 1
+                    and stripped_line[i - 1] != '"'
+                    and stripped_line[i - 1] != "\\"
+                ):
                     uses_invalid_quotes = True
                     break
 
     if uses_invalid_quotes:
-        ret.append(rh.results.HookResult(
-            f'commit msg: "{field}:" tag using unescaped quotes',
-            project, commit, error=RELNOTE_INVALID_QUOTES_MSG))
+        ret.append(
+            rh.results.HookResult(
+                f'commit msg: "{field}:" tag using unescaped quotes',
+                project,
+                commit,
+                error=RELNOTE_INVALID_QUOTES_MSG,
+            )
+        )
     return ret
 
 
@@ -870,19 +1001,20 @@ Relnote: N/A
 Check the git history for more examples.
 """
 
-def check_commit_msg_relnote_for_current_txt(project, commit, desc, diff,
-                                             options=None):
+
+def check_commit_msg_relnote_for_current_txt(
+    project, commit, desc, diff, options=None
+):
     """Check changes to current.txt contain the 'Relnote:' stanza."""
-    field = 'Relnote'
-    regex = fr'^{field}: .+$'
+    field = "Relnote"
+    regex = rf"^{field}: .+$"
     check_re = re.compile(regex, re.IGNORECASE)
 
     if options.args():
-        raise ValueError(f'commit msg {field} check takes no options')
+        raise ValueError(f"commit msg {field} check takes no options")
 
     filtered = _filter_diff(
-        diff,
-        [r'(^|/)(public_plus_experimental_current|current)\.txt$']
+        diff, [r"(^|/)(public_plus_experimental_current|current)\.txt$"]
     )
     # If the commit does not contain a change to *current.txt, then this repo
     # hook check no longer applies.
@@ -899,50 +1031,60 @@ def check_commit_msg_relnote_for_current_txt(project, commit, desc, diff,
     else:
         return None
 
-    return [rh.results.HookResult(f'commit msg: "{field}:" check',
-                                  project, commit, error=error)]
+    return [
+        rh.results.HookResult(
+            f'commit msg: "{field}:" check', project, commit, error=error
+        )
+    ]
 
 
 def check_cpplint(project, commit, _desc, diff, options=None):
     """Run cpplint."""
     # This list matches what cpplint expects.  We could run on more (like .cxx),
     # but cpplint would just ignore them.
-    filtered = _filter_diff(diff, [r'\.(cc|h|cpp|cu|cuh)$'])
+    filtered = _filter_diff(diff, [r"\.(cc|h|cpp|cu|cuh)$"])
     if not filtered:
         return None
 
-    cpplint = options.tool_path('cpplint')
-    cmd = [cpplint] + options.args(('${PREUPLOAD_FILES}',), filtered)
-    return _check_cmd('cpplint', project, commit, cmd)
+    cpplint = options.tool_path("cpplint")
+    cmd = [cpplint] + options.args(("${PREUPLOAD_FILES}",), filtered)
+    return _check_cmd("cpplint", project, commit, cmd)
 
 
 def check_gofmt(project, commit, _desc, diff, options=None):
     """Checks that Go files are formatted with gofmt."""
-    filtered = _filter_diff(diff, [r'\.go$'])
+    filtered = _filter_diff(diff, [r"\.go$"])
     if not filtered:
         return None
 
-    gofmt = options.tool_path('gofmt')
-    cmd = [gofmt, '-l'] + options.args()
-    fixup_cmd = [gofmt, '-w'] + options.args()
+    gofmt = options.tool_path("gofmt")
+    cmd = [gofmt, "-l"] + options.args()
+    fixup_cmd = [gofmt, "-w"] + options.args()
 
     ret = []
     for d in filtered:
         data = rh.git.get_file_content(commit, d.file)
         result = _run(cmd, input=data)
         if result.stdout:
-            ret.append(rh.results.HookResult(
-                'gofmt', project, commit, error=result.stdout,
-                files=(d.file,), fixup_cmd=fixup_cmd))
+            ret.append(
+                rh.results.HookResult(
+                    "gofmt",
+                    project,
+                    commit,
+                    error=result.stdout,
+                    files=(d.file,),
+                    fixup_cmd=fixup_cmd,
+                )
+            )
     return ret
 
 
 def check_json(project, commit, _desc, diff, options=None):
     """Verify json files are valid."""
     if options.args():
-        raise ValueError('json check takes no options')
+        raise ValueError("json check takes no options")
 
-    filtered = _filter_diff(diff, [r'\.json$'])
+    filtered = _filter_diff(diff, [r"\.json$"])
     if not filtered:
         return None
 
@@ -952,27 +1094,34 @@ def check_json(project, commit, _desc, diff, options=None):
         try:
             json.loads(data)
         except ValueError as e:
-            ret.append(rh.results.HookResult(
-                'json', project, commit, error=str(e),
-                files=(d.file,)))
+            ret.append(
+                rh.results.HookResult(
+                    "json", project, commit, error=str(e), files=(d.file,)
+                )
+            )
     return ret
 
 
 def _check_pylint(project, commit, _desc, diff, extra_args=None, options=None):
     """Run pylint."""
-    filtered = _filter_diff(diff, [r'\.py$'])
+    filtered = _filter_diff(diff, [r"\.py$"])
     if not filtered:
         return None
 
     if extra_args is None:
         extra_args = []
 
-    pylint = options.tool_path('pylint')
-    cmd = [
-        get_helper_path('pylint.py'),
-        '--executable-path', pylint,
-    ] + extra_args + options.args(('${PREUPLOAD_FILES}',), filtered)
-    return _check_cmd('pylint', project, commit, cmd)
+    pylint = options.tool_path("pylint")
+    cmd = (
+        [
+            get_helper_path("pylint.py"),
+            "--executable-path",
+            pylint,
+        ]
+        + extra_args
+        + options.args(("${PREUPLOAD_FILES}",), filtered)
+    )
+    return _check_cmd("pylint", project, commit, cmd)
 
 
 def check_pylint2(project, commit, desc, diff, options=None):
@@ -982,11 +1131,18 @@ def check_pylint2(project, commit, desc, diff, options=None):
     breaking in older branches with old configs that still have it.
     """
     del desc, diff, options
-    return [rh.results.HookResult(
-        'pylint2', project, commit,
-        ('The pylint2 check is no longer supported.  '
-         'Please delete from PREUPLOAD.cfg.'),
-        warning=True)]
+    return [
+        rh.results.HookResult(
+            "pylint2",
+            project,
+            commit,
+            (
+                "The pylint2 check is no longer supported.  "
+                "Please delete from PREUPLOAD.cfg."
+            ),
+            warning=True,
+        )
+    ]
 
 
 def check_pylint3(project, commit, desc, diff, options=None):
@@ -996,11 +1152,11 @@ def check_pylint3(project, commit, desc, diff, options=None):
 
 def check_rustfmt(project, commit, _desc, diff, options=None):
     """Run "rustfmt --check" on diffed rust files"""
-    filtered = _filter_diff(diff, [r'\.rs$'])
+    filtered = _filter_diff(diff, [r"\.rs$"])
     if not filtered:
         return None
 
-    rustfmt = options.tool_path('rustfmt')
+    rustfmt = options.tool_path("rustfmt")
     cmd = [rustfmt] + options.args((), filtered)
     ret = []
     for d in filtered:
@@ -1009,142 +1165,173 @@ def check_rustfmt(project, commit, _desc, diff, options=None):
         # If the parsing failed, stdout will contain enough details on the
         # location of the error.
         if result.returncode:
-            ret.append(rh.results.HookResult(
-                'rustfmt', project, commit, error=result.stdout,
-                files=(d.file,)))
+            ret.append(
+                rh.results.HookResult(
+                    "rustfmt",
+                    project,
+                    commit,
+                    error=result.stdout,
+                    files=(d.file,),
+                )
+            )
             continue
         # TODO(b/164111102): rustfmt stable does not support --check on stdin.
         # If no error is reported, compare stdin with stdout.
         if data != result.stdout:
-            ret.append(rh.results.HookResult(
-                'rustfmt', project, commit, error='Files not formatted',
-                files=(d.file,), fixup_cmd=cmd))
+            ret.append(
+                rh.results.HookResult(
+                    "rustfmt",
+                    project,
+                    commit,
+                    error="Files not formatted",
+                    files=(d.file,),
+                    fixup_cmd=cmd,
+                )
+            )
     return ret
 
 
 def check_xmllint(project, commit, _desc, diff, options=None):
     """Run xmllint."""
     # XXX: Should we drop most of these and probe for <?xml> tags?
-    extensions = frozenset((
-        'dbus-xml',  # Generated DBUS interface.
-        'dia',       # File format for Dia.
-        'dtd',       # Document Type Definition.
-        'fml',       # Fuzzy markup language.
-        'form',      # Forms created by IntelliJ GUI Designer.
-        'fxml',      # JavaFX user interfaces.
-        'glade',     # Glade user interface design.
-        'grd',       # GRIT translation files.
-        'iml',       # Android build modules?
-        'kml',       # Keyhole Markup Language.
-        'mxml',      # Macromedia user interface markup language.
-        'nib',       # OS X Cocoa Interface Builder.
-        'plist',     # Property list (for OS X).
-        'pom',       # Project Object Model (for Apache Maven).
-        'rng',       # RELAX NG schemas.
-        'sgml',      # Standard Generalized Markup Language.
-        'svg',       # Scalable Vector Graphics.
-        'uml',       # Unified Modeling Language.
-        'vcproj',    # Microsoft Visual Studio project.
-        'vcxproj',   # Microsoft Visual Studio project.
-        'wxs',       # WiX Transform File.
-        'xhtml',     # XML HTML.
-        'xib',       # OS X Cocoa Interface Builder.
-        'xlb',       # Android locale bundle.
-        'xml',       # Extensible Markup Language.
-        'xsd',       # XML Schema Definition.
-        'xsl',       # Extensible Stylesheet Language.
-    ))
-
-    filtered = _filter_diff(diff, [r'\.(' + '|'.join(extensions) + r')$'])
+    extensions = frozenset(
+        (
+            "dbus-xml",  # Generated DBUS interface.
+            "dia",  # File format for Dia.
+            "dtd",  # Document Type Definition.
+            "fml",  # Fuzzy markup language.
+            "form",  # Forms created by IntelliJ GUI Designer.
+            "fxml",  # JavaFX user interfaces.
+            "glade",  # Glade user interface design.
+            "grd",  # GRIT translation files.
+            "iml",  # Android build modules?
+            "kml",  # Keyhole Markup Language.
+            "mxml",  # Macromedia user interface markup language.
+            "nib",  # OS X Cocoa Interface Builder.
+            "plist",  # Property list (for OS X).
+            "pom",  # Project Object Model (for Apache Maven).
+            "rng",  # RELAX NG schemas.
+            "sgml",  # Standard Generalized Markup Language.
+            "svg",  # Scalable Vector Graphics.
+            "uml",  # Unified Modeling Language.
+            "vcproj",  # Microsoft Visual Studio project.
+            "vcxproj",  # Microsoft Visual Studio project.
+            "wxs",  # WiX Transform File.
+            "xhtml",  # XML HTML.
+            "xib",  # OS X Cocoa Interface Builder.
+            "xlb",  # Android locale bundle.
+            "xml",  # Extensible Markup Language.
+            "xsd",  # XML Schema Definition.
+            "xsl",  # Extensible Stylesheet Language.
+        )
+    )
+
+    filtered = _filter_diff(diff, [r"\.(" + "|".join(extensions) + r")$"])
     if not filtered:
         return None
 
     # TODO: Figure out how to integrate schema validation.
     # XXX: Should we use python's XML libs instead?
-    cmd = ['xmllint'] + options.args(('${PREUPLOAD_FILES}',), filtered)
+    cmd = ["xmllint"] + options.args(("${PREUPLOAD_FILES}",), filtered)
 
-    return _check_cmd('xmllint', project, commit, cmd)
+    return _check_cmd("xmllint", project, commit, cmd)
 
 
 def check_android_test_mapping(project, commit, _desc, diff, options=None):
     """Verify Android TEST_MAPPING files are valid."""
     if options.args():
-        raise ValueError('Android TEST_MAPPING check takes no options')
-    filtered = _filter_diff(diff, [r'(^|.*/)TEST_MAPPING$'])
+        raise ValueError("Android TEST_MAPPING check takes no options")
+    filtered = _filter_diff(diff, [r"(^|.*/)TEST_MAPPING$"])
     if not filtered:
         return None
 
-    testmapping_format = options.tool_path('android-test-mapping-format')
-    testmapping_args = ['--commit', commit]
-    cmd = [testmapping_format] + options.args(
-        (project.dir, '${PREUPLOAD_FILES}'), filtered) + testmapping_args
-    return _check_cmd('android-test-mapping-format', project, commit, cmd)
+    testmapping_format = options.tool_path("android-test-mapping-format")
+    testmapping_args = ["--commit", commit]
+    cmd = (
+        [testmapping_format]
+        + options.args((project.dir, "${PREUPLOAD_FILES}"), filtered)
+        + testmapping_args
+    )
+    return _check_cmd("android-test-mapping-format", project, commit, cmd)
 
 
 def check_aidl_format(project, commit, _desc, diff, options=None):
     """Checks that AIDL files are formatted with aidl-format."""
     # All *.aidl files except for those under aidl_api directory.
-    filtered = _filter_diff(diff, [r'\.aidl$'], [r'(^|/)aidl_api/'])
+    filtered = _filter_diff(diff, [r"\.aidl$"], [r"(^|/)aidl_api/"])
     if not filtered:
         return None
-    aidl_format = options.tool_path('aidl-format')
-    clang_format = options.tool_path('clang-format')
-    diff_cmd = [aidl_format, '-d', '--clang-format-path', clang_format] + \
-            options.args((), filtered)
+    aidl_format = options.tool_path("aidl-format")
+    clang_format = options.tool_path("clang-format")
+    diff_cmd = [
+        aidl_format,
+        "-d",
+        "--clang-format-path",
+        clang_format,
+    ] + options.args((), filtered)
     ret = []
     for d in filtered:
         data = rh.git.get_file_content(commit, d.file)
         result = _run(diff_cmd, input=data)
         if result.stdout:
-            fixup_cmd = [aidl_format, '-w', '--clang-format-path', clang_format]
-            ret.append(rh.results.HookResult(
-                'aidl-format', project, commit, error=result.stdout,
-                files=(d.file,), fixup_cmd=fixup_cmd))
+            fixup_cmd = [aidl_format, "-w", "--clang-format-path", clang_format]
+            ret.append(
+                rh.results.HookResult(
+                    "aidl-format",
+                    project,
+                    commit,
+                    error=result.stdout,
+                    files=(d.file,),
+                    fixup_cmd=fixup_cmd,
+                )
+            )
     return ret
 
 
 # Hooks that projects can opt into.
 # Note: Make sure to keep the top level README.md up to date when adding more!
 BUILTIN_HOOKS = {
-    'aidl_format': check_aidl_format,
-    'android_test_mapping_format': check_android_test_mapping,
-    'aosp_license': check_aosp_license,
-    'bpfmt': check_bpfmt,
-    'checkpatch': check_checkpatch,
-    'clang_format': check_clang_format,
-    'commit_msg_bug_field': check_commit_msg_bug_field,
-    'commit_msg_changeid_field': check_commit_msg_changeid_field,
-    'commit_msg_prebuilt_apk_fields': check_commit_msg_prebuilt_apk_fields,
-    'commit_msg_relnote_field_format': check_commit_msg_relnote_field_format,
-    'commit_msg_relnote_for_current_txt':
-        check_commit_msg_relnote_for_current_txt,
-    'commit_msg_test_field': check_commit_msg_test_field,
-    'cpplint': check_cpplint,
-    'gofmt': check_gofmt,
-    'google_java_format': check_google_java_format,
-    'jsonlint': check_json,
-    'ktfmt': check_ktfmt,
-    'pylint': check_pylint3,
-    'pylint2': check_pylint2,
-    'pylint3': check_pylint3,
-    'rustfmt': check_rustfmt,
-    'xmllint': check_xmllint,
+    "aidl_format": check_aidl_format,
+    "android_test_mapping_format": check_android_test_mapping,
+    "aosp_license": check_aosp_license,
+    "black": check_black,
+    "bpfmt": check_bpfmt,
+    "checkpatch": check_checkpatch,
+    "clang_format": check_clang_format,
+    "commit_msg_bug_field": check_commit_msg_bug_field,
+    "commit_msg_changeid_field": check_commit_msg_changeid_field,
+    "commit_msg_prebuilt_apk_fields": check_commit_msg_prebuilt_apk_fields,
+    "commit_msg_relnote_field_format": check_commit_msg_relnote_field_format,
+    "commit_msg_relnote_for_current_txt": check_commit_msg_relnote_for_current_txt,
+    "commit_msg_test_field": check_commit_msg_test_field,
+    "cpplint": check_cpplint,
+    "gofmt": check_gofmt,
+    "google_java_format": check_google_java_format,
+    "jsonlint": check_json,
+    "ktfmt": check_ktfmt,
+    "pylint": check_pylint3,
+    "pylint2": check_pylint2,
+    "pylint3": check_pylint3,
+    "rustfmt": check_rustfmt,
+    "xmllint": check_xmllint,
 }
 
 # Additional tools that the hooks can call with their default values.
 # Note: Make sure to keep the top level README.md up to date when adding more!
 TOOL_PATHS = {
-    'aidl-format': 'aidl-format',
-    'android-test-mapping-format':
-        os.path.join(TOOLS_DIR, 'android_test_mapping_format.py'),
-    'bpfmt': 'bpfmt',
-    'clang-format': 'clang-format',
-    'cpplint': os.path.join(TOOLS_DIR, 'cpplint.py'),
-    'git-clang-format': 'git-clang-format',
-    'gofmt': 'gofmt',
-    'google-java-format': 'google-java-format',
-    'google-java-format-diff': 'google-java-format-diff.py',
-    'ktfmt': 'ktfmt',
-    'pylint': 'pylint',
-    'rustfmt': 'rustfmt',
+    "aidl-format": "aidl-format",
+    "android-test-mapping-format": os.path.join(
+        TOOLS_DIR, "android_test_mapping_format.py"
+    ),
+    "black": "black",
+    "bpfmt": "bpfmt",
+    "clang-format": "clang-format",
+    "cpplint": os.path.join(TOOLS_DIR, "cpplint.py"),
+    "git-clang-format": "git-clang-format",
+    "gofmt": "gofmt",
+    "google-java-format": "google-java-format",
+    "google-java-format-diff": "google-java-format-diff.py",
+    "ktfmt": "ktfmt",
+    "pylint": "pylint",
+    "rustfmt": "rustfmt",
 }
diff --git a/rh/hooks_unittest.py b/rh/hooks_unittest.py
index bed3745..77a1880 100755
--- a/rh/hooks_unittest.py
+++ b/rh/hooks_unittest.py
@@ -20,7 +20,9 @@ import sys
 import unittest
 from unittest import mock
 
-_path = os.path.realpath(__file__ + '/../..')
+import pytest
+
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -35,7 +37,7 @@ import rh.hooks
 
 # pylint: disable=unused-argument
 def mock_find_repo_root(path=None, outer=False):
-    return '/ ${BUILD_OS}' if outer else '/ ${BUILD_OS}/sub'
+    return "/ ${BUILD_OS}" if outer else "/ ${BUILD_OS}/sub"
 
 
 class HooksDocsTests(unittest.TestCase):
@@ -46,47 +48,60 @@ class HooksDocsTests(unittest.TestCase):
     """
 
     def setUp(self):
-        self.readme = os.path.join(os.path.dirname(os.path.dirname(
-            os.path.realpath(__file__))), 'README.md')
+        self.readme = os.path.join(
+            os.path.dirname(os.path.dirname(os.path.realpath(__file__))),
+            "README.md",
+        )
 
     def _grab_section(self, section):
         """Extract the |section| text out of the readme."""
         ret = []
         in_section = False
-        with open(self.readme, encoding='utf-8') as fp:
+        with open(self.readme, encoding="utf-8") as fp:
             for line in fp:
                 if not in_section:
                     # Look for the section like "## [Tool Paths]".
-                    if (line.startswith('#') and
-                            line.lstrip('#').strip() == section):
+                    if (
+                        line.startswith("#")
+                        and line.lstrip("#").strip() == section
+                    ):
                         in_section = True
                 else:
                     # Once we hit the next section (higher or lower), break.
-                    if line[0] == '#':
+                    if line[0] == "#":
                         break
                     ret.append(line)
-        return ''.join(ret)
+        return "".join(ret)
 
     def testBuiltinHooks(self):
         """Verify builtin hooks are documented."""
-        data = self._grab_section('[Builtin Hooks]')
+        data = self._grab_section("[Builtin Hooks]")
         for hook in rh.hooks.BUILTIN_HOOKS:
-            self.assertIn(f'* `{hook}`:', data,
-                          msg=f'README.md missing docs for hook "{hook}"')
+            self.assertIn(
+                f"* `{hook}`:",
+                data,
+                msg=f'README.md missing docs for hook "{hook}"',
+            )
 
     def testToolPaths(self):
         """Verify tools are documented."""
-        data = self._grab_section('[Tool Paths]')
+        data = self._grab_section("[Tool Paths]")
         for tool in rh.hooks.TOOL_PATHS:
-            self.assertIn(f'* `{tool}`:', data,
-                          msg=f'README.md missing docs for tool "{tool}"')
+            self.assertIn(
+                f"* `{tool}`:",
+                data,
+                msg=f'README.md missing docs for tool "{tool}"',
+            )
 
     def testPlaceholders(self):
         """Verify placeholder replacement vars are documented."""
-        data = self._grab_section('Placeholders')
+        data = self._grab_section("Placeholders")
         for var in rh.hooks.Placeholders.vars():
-            self.assertIn('* `${' + var + '}`:', data,
-                          msg=f'README.md missing docs for var "{var}"')
+            self.assertIn(
+                "* `${" + var + "}`:",
+                data,
+                msg=f'README.md missing docs for var "{var}"',
+            )
 
 
 class PlaceholderTests(unittest.TestCase):
@@ -94,13 +109,18 @@ class PlaceholderTests(unittest.TestCase):
 
     def setUp(self):
         self._saved_environ = os.environ.copy()
-        os.environ.update({
-            'PREUPLOAD_COMMIT_MESSAGE': 'commit message',
-            'PREUPLOAD_COMMIT': '5c4c293174bb61f0f39035a71acd9084abfa743d',
-        })
+        os.environ.update(
+            {
+                "PREUPLOAD_COMMIT_MESSAGE": "commit message",
+                "PREUPLOAD_COMMIT": "5c4c293174bb61f0f39035a71acd9084abfa743d",
+            }
+        )
         self.replacer = rh.hooks.Placeholders(
-            [rh.git.RawDiffEntry(file=x)
-             for x in ['path1/file1', 'path2/file2']])
+            [
+                rh.git.RawDiffEntry(file=x)
+                for x in ["path1/file1", "path2/file2"]
+            ]
+        )
 
     def tearDown(self):
         os.environ.clear()
@@ -110,104 +130,116 @@ class PlaceholderTests(unittest.TestCase):
         """Light test for the vars inspection generator."""
         ret = list(self.replacer.vars())
         self.assertGreater(len(ret), 4)
-        self.assertIn('PREUPLOAD_COMMIT', ret)
+        self.assertIn("PREUPLOAD_COMMIT", ret)
 
-    @mock.patch.object(rh.git, 'find_repo_root',
-                       side_effect=mock_find_repo_root)
+    @mock.patch.object(
+        rh.git, "find_repo_root", side_effect=mock_find_repo_root
+    )
     def testExpandVars(self, _m):
         """Verify the replacement actually works."""
         input_args = [
             # Verify ${REPO_ROOT} is updated, but not REPO_ROOT.
             # We also make sure that things in ${REPO_ROOT} are not double
             # expanded (which is why the return includes ${BUILD_OS}).
-            '${REPO_ROOT}/some/prog/REPO_ROOT/ok',
+            "${REPO_ROOT}/some/prog/REPO_ROOT/ok",
             # Verify that ${REPO_OUTER_ROOT} is expanded.
-            '${REPO_OUTER_ROOT}/some/prog/REPO_OUTER_ROOT/ok',
+            "${REPO_OUTER_ROOT}/some/prog/REPO_OUTER_ROOT/ok",
             # Verify lists are merged rather than inserted.
-            '${PREUPLOAD_FILES}',
+            "${PREUPLOAD_FILES}",
             # Verify each file is preceded with '--file=' prefix.
-            '--file=${PREUPLOAD_FILES_PREFIXED}',
+            "--file=${PREUPLOAD_FILES_PREFIXED}",
             # Verify each file is preceded with '--file' argument.
-            '--file',
-            '${PREUPLOAD_FILES_PREFIXED}',
+            "--file",
+            "${PREUPLOAD_FILES_PREFIXED}",
             # Verify values with whitespace don't expand into multiple args.
-            '${PREUPLOAD_COMMIT_MESSAGE}',
+            "${PREUPLOAD_COMMIT_MESSAGE}",
             # Verify multiple values get replaced.
-            '${PREUPLOAD_COMMIT}^${PREUPLOAD_COMMIT_MESSAGE}',
+            "${PREUPLOAD_COMMIT}^${PREUPLOAD_COMMIT_MESSAGE}",
             # Unknown vars should be left alone.
-            '${THIS_VAR_IS_GOOD}',
+            "${THIS_VAR_IS_GOOD}",
         ]
         output_args = self.replacer.expand_vars(input_args)
         exp_args = [
-            '/ ${BUILD_OS}/sub/some/prog/REPO_ROOT/ok',
-            '/ ${BUILD_OS}/some/prog/REPO_OUTER_ROOT/ok',
-            'path1/file1',
-            'path2/file2',
-            '--file=path1/file1',
-            '--file=path2/file2',
-            '--file',
-            'path1/file1',
-            '--file',
-            'path2/file2',
-            'commit message',
-            '5c4c293174bb61f0f39035a71acd9084abfa743d^commit message',
-            '${THIS_VAR_IS_GOOD}',
+            "/ ${BUILD_OS}/sub/some/prog/REPO_ROOT/ok",
+            "/ ${BUILD_OS}/some/prog/REPO_OUTER_ROOT/ok",
+            "path1/file1",
+            "path2/file2",
+            "--file=path1/file1",
+            "--file=path2/file2",
+            "--file",
+            "path1/file1",
+            "--file",
+            "path2/file2",
+            "commit message",
+            "5c4c293174bb61f0f39035a71acd9084abfa743d^commit message",
+            "${THIS_VAR_IS_GOOD}",
         ]
         self.assertEqual(output_args, exp_args)
 
     def testTheTester(self):
         """Make sure we have a test for every variable."""
         for var in self.replacer.vars():
-            self.assertIn(f'test{var}', dir(self),
-                          msg=f'Missing unittest for variable {var}')
+            self.assertIn(
+                f"test{var}",
+                dir(self),
+                msg=f"Missing unittest for variable {var}",
+            )
 
     def testPREUPLOAD_COMMIT_MESSAGE(self):
         """Verify handling of PREUPLOAD_COMMIT_MESSAGE."""
-        self.assertEqual(self.replacer.get('PREUPLOAD_COMMIT_MESSAGE'),
-                         'commit message')
+        self.assertEqual(
+            self.replacer.get("PREUPLOAD_COMMIT_MESSAGE"), "commit message"
+        )
 
     def testPREUPLOAD_COMMIT(self):
         """Verify handling of PREUPLOAD_COMMIT."""
-        self.assertEqual(self.replacer.get('PREUPLOAD_COMMIT'),
-                         '5c4c293174bb61f0f39035a71acd9084abfa743d')
+        self.assertEqual(
+            self.replacer.get("PREUPLOAD_COMMIT"),
+            "5c4c293174bb61f0f39035a71acd9084abfa743d",
+        )
 
     def testPREUPLOAD_FILES(self):
         """Verify handling of PREUPLOAD_FILES."""
-        self.assertEqual(self.replacer.get('PREUPLOAD_FILES'),
-                         ['path1/file1', 'path2/file2'])
+        self.assertEqual(
+            self.replacer.get("PREUPLOAD_FILES"), ["path1/file1", "path2/file2"]
+        )
 
-    @mock.patch.object(rh.git, 'find_repo_root')
+    @mock.patch.object(rh.git, "find_repo_root")
     def testREPO_OUTER_ROOT(self, m):
         """Verify handling of REPO_OUTER_ROOT."""
         m.side_effect = mock_find_repo_root
-        self.assertEqual(self.replacer.get('REPO_OUTER_ROOT'),
-                         mock_find_repo_root(path=None, outer=True))
+        self.assertEqual(
+            self.replacer.get("REPO_OUTER_ROOT"),
+            mock_find_repo_root(path=None, outer=True),
+        )
 
-    @mock.patch.object(rh.git, 'find_repo_root')
+    @mock.patch.object(rh.git, "find_repo_root")
     def testREPO_ROOT(self, m):
         """Verify handling of REPO_ROOT."""
         m.side_effect = mock_find_repo_root
-        self.assertEqual(self.replacer.get('REPO_ROOT'),
-                         mock_find_repo_root(path=None, outer=False))
+        self.assertEqual(
+            self.replacer.get("REPO_ROOT"),
+            mock_find_repo_root(path=None, outer=False),
+        )
 
     def testREPO_PATH(self):
         """Verify handling of REPO_PATH."""
-        os.environ['REPO_PATH'] = ''
-        self.assertEqual(self.replacer.get('REPO_PATH'), '')
-        os.environ['REPO_PATH'] = 'foo/bar'
-        self.assertEqual(self.replacer.get('REPO_PATH'), 'foo/bar')
+        os.environ["REPO_PATH"] = ""
+        self.assertEqual(self.replacer.get("REPO_PATH"), "")
+        os.environ["REPO_PATH"] = "foo/bar"
+        self.assertEqual(self.replacer.get("REPO_PATH"), "foo/bar")
 
     def testREPO_PROJECT(self):
         """Verify handling of REPO_PROJECT."""
-        os.environ['REPO_PROJECT'] = ''
-        self.assertEqual(self.replacer.get('REPO_PROJECT'), '')
-        os.environ['REPO_PROJECT'] = 'platform/foo/bar'
-        self.assertEqual(self.replacer.get('REPO_PROJECT'), 'platform/foo/bar')
+        os.environ["REPO_PROJECT"] = ""
+        self.assertEqual(self.replacer.get("REPO_PROJECT"), "")
+        os.environ["REPO_PROJECT"] = "platform/foo/bar"
+        self.assertEqual(self.replacer.get("REPO_PROJECT"), "platform/foo/bar")
 
-    @mock.patch.object(rh.hooks, '_get_build_os_name', return_value='vapier os')
+    @mock.patch.object(rh.hooks, "_get_build_os_name", return_value="vapier os")
     def testBUILD_OS(self, m):
         """Verify handling of BUILD_OS."""
-        self.assertEqual(self.replacer.get('BUILD_OS'), m.return_value)
+        self.assertEqual(self.replacer.get("BUILD_OS"), m.return_value)
 
 
 class ExclusionScopeTests(unittest.TestCase):
@@ -216,62 +248,68 @@ class ExclusionScopeTests(unittest.TestCase):
     def testEmpty(self):
         """Verify the in operator for an empty scope."""
         scope = rh.hooks.ExclusionScope([])
-        self.assertNotIn('external/*', scope)
+        self.assertNotIn("external/*", scope)
 
     def testGlob(self):
         """Verify the in operator for a scope using wildcards."""
-        scope = rh.hooks.ExclusionScope(['vendor/*', 'external/*'])
-        self.assertIn('external/tools', scope)
+        scope = rh.hooks.ExclusionScope(["vendor/*", "external/*"])
+        self.assertIn("external/tools", scope)
 
     def testRegex(self):
         """Verify the in operator for a scope using regular expressions."""
-        scope = rh.hooks.ExclusionScope(['^vendor/(?!google)',
-                                         'external/*'])
-        self.assertIn('vendor/', scope)
-        self.assertNotIn('vendor/google/', scope)
-        self.assertIn('vendor/other/', scope)
+        scope = rh.hooks.ExclusionScope(["^vendor/(?!google)", "external/*"])
+        self.assertIn("vendor/", scope)
+        self.assertNotIn("vendor/google/", scope)
+        self.assertIn("vendor/other/", scope)
 
 
 class HookOptionsTests(unittest.TestCase):
     """Verify behavior of HookOptions object."""
 
-    @mock.patch.object(rh.hooks, '_get_build_os_name', return_value='vapier os')
+    @pytest.mark.skip_cq("TODO: Relies on .repo dir")
+    @mock.patch.object(rh.hooks, "_get_build_os_name", return_value="vapier os")
     def testExpandVars(self, m):
         """Verify expand_vars behavior."""
         # Simple pass through.
-        args = ['who', 'goes', 'there ?']
+        args = ["who", "goes", "there ?"]
         self.assertEqual(args, rh.hooks.HookOptions.expand_vars(args))
 
         # At least one replacement.  Most real testing is in PlaceholderTests.
-        args = ['who', 'goes', 'there ?', '${BUILD_OS} is great']
-        exp_args = ['who', 'goes', 'there ?', f'{m.return_value} is great']
+        args = ["who", "goes", "there ?", "${BUILD_OS} is great"]
+        exp_args = ["who", "goes", "there ?", f"{m.return_value} is great"]
         self.assertEqual(exp_args, rh.hooks.HookOptions.expand_vars(args))
 
+    @pytest.mark.skip_cq("TODO: Relies on .repo dir")
     def testArgs(self):
         """Verify args behavior."""
         # Verify initial args to __init__ has higher precedent.
-        args = ['start', 'args']
-        options = rh.hooks.HookOptions('hook name', args, {})
+        args = ["start", "args"]
+        options = rh.hooks.HookOptions("hook name", args, {})
         self.assertEqual(options.args(), args)
-        self.assertEqual(options.args(default_args=['moo']), args)
+        self.assertEqual(options.args(default_args=["moo"]), args)
 
         # Verify we fall back to default_args.
-        args = ['default', 'args']
-        options = rh.hooks.HookOptions('hook name', [], {})
+        args = ["default", "args"]
+        options = rh.hooks.HookOptions("hook name", [], {})
         self.assertEqual(options.args(), [])
         self.assertEqual(options.args(default_args=args), args)
 
+    @pytest.mark.skip_cq("TODO: Relies on .repo dir")
     def testToolPath(self):
         """Verify tool_path behavior."""
-        options = rh.hooks.HookOptions('hook name', [], {
-            'cpplint': 'my cpplint',
-        })
+        options = rh.hooks.HookOptions(
+            "hook name",
+            [],
+            {
+                "cpplint": "my cpplint",
+            },
+        )
         # Check a builtin (and not overridden) tool.
-        self.assertEqual(options.tool_path('pylint'), 'pylint')
+        self.assertEqual(options.tool_path("pylint"), "pylint")
         # Check an overridden tool.
-        self.assertEqual(options.tool_path('cpplint'), 'my cpplint')
+        self.assertEqual(options.tool_path("cpplint"), "my cpplint")
         # Check an unknown tool fails.
-        self.assertRaises(AssertionError, options.tool_path, 'extra_tool')
+        self.assertRaises(AssertionError, options.tool_path, "extra_tool")
 
 
 class UtilsTests(unittest.TestCase):
@@ -281,7 +319,7 @@ class UtilsTests(unittest.TestCase):
         """Check _run behavior."""
         # Most testing is done against the utils.RunCommand already.
         # pylint: disable=protected-access
-        ret = rh.hooks._run(['true'])
+        ret = rh.hooks._run(["true"])
         self.assertEqual(ret.returncode, 0)
 
     def testBuildOs(self):
@@ -290,14 +328,14 @@ class UtilsTests(unittest.TestCase):
         # pylint: disable=protected-access
         ret = rh.hooks._get_build_os_name()
         self.assertTrue(isinstance(ret, str))
-        self.assertNotEqual(ret, '')
+        self.assertNotEqual(ret, "")
 
     def testGetHelperPath(self):
         """Check get_helper_path behavior."""
         # Just verify it doesn't crash.  It's a dirt simple func.
-        ret = rh.hooks.get_helper_path('booga')
+        ret = rh.hooks.get_helper_path("booga")
         self.assertTrue(isinstance(ret, str))
-        self.assertNotEqual(ret, '')
+        self.assertNotEqual(ret, "")
 
     def testSortedToolPaths(self):
         """Check TOOL_PATHS is sorted."""
@@ -312,17 +350,18 @@ class UtilsTests(unittest.TestCase):
         # order which Python 3.7+ has codified.
         # https://docs.python.org/3.7/library/stdtypes.html#dict
         self.assertEqual(
-            list(rh.hooks.BUILTIN_HOOKS), sorted(rh.hooks.BUILTIN_HOOKS))
+            list(rh.hooks.BUILTIN_HOOKS), sorted(rh.hooks.BUILTIN_HOOKS)
+        )
 
 
-@mock.patch.object(rh.utils, 'run')
-@mock.patch.object(rh.hooks, '_check_cmd', return_value=['check_cmd'])
+@mock.patch.object(rh.utils, "run")
+@mock.patch.object(rh.hooks, "_check_cmd", return_value=["check_cmd"])
 class BuiltinHooksTests(unittest.TestCase):
     """Verify the builtin hooks."""
 
     def setUp(self):
-        self.project = rh.Project(name='project-name', dir='/.../repo/dir')
-        self.options = rh.hooks.HookOptions('hook name', [], {})
+        self.project = rh.Project(name="project-name", dir="/.../repo/dir")
+        self.options = rh.hooks.HookOptions("hook name", [], {})
 
     def _test_commit_messages(self, func, accept, msgs, files=None):
         """Helper for testing commit message hooks.
@@ -338,13 +377,15 @@ class BuiltinHooksTests(unittest.TestCase):
         else:
             diff = []
         for desc in msgs:
-            ret = func(self.project, 'commit', desc, diff, options=self.options)
+            ret = func(self.project, "commit", desc, diff, options=self.options)
             if accept:
                 self.assertFalse(
-                    bool(ret), msg='Should have accepted: {{{' + desc + '}}}')
+                    bool(ret), msg="Should have accepted: {{{" + desc + "}}}"
+                )
             else:
                 self.assertTrue(
-                    bool(ret), msg='Should have rejected: {{{' + desc + '}}}')
+                    bool(ret), msg="Should have rejected: {{{" + desc + "}}}"
+                )
 
     def _test_file_filter(self, mock_check, func, files):
         """Helper for testing hooks that filter by files and run external tools.
@@ -355,78 +396,109 @@ class BuiltinHooksTests(unittest.TestCase):
           files: A list of files that we'd check.
         """
         # First call should do nothing as there are no files to check.
-        ret = func(self.project, 'commit', 'desc', (), options=self.options)
+        ret = func(self.project, "commit", "desc", (), options=self.options)
         self.assertIsNone(ret)
         self.assertFalse(mock_check.called)
 
         # Second call should include some checks.
         diff = [rh.git.RawDiffEntry(file=x) for x in files]
-        ret = func(self.project, 'commit', 'desc', diff, options=self.options)
+        ret = func(self.project, "commit", "desc", diff, options=self.options)
         self.assertEqual(ret, mock_check.return_value)
 
     def testTheTester(self, _mock_check, _mock_run):
         """Make sure we have a test for every hook."""
         for hook in rh.hooks.BUILTIN_HOOKS:
-            self.assertIn(f'test_{hook}', dir(self),
-                          msg=f'Missing unittest for builtin hook {hook}')
+            self.assertIn(
+                f"test_{hook}",
+                dir(self),
+                msg=f"Missing unittest for builtin hook {hook}",
+            )
 
     def test_aosp_license(self, mock_check, _mock_run):
         """Verify the aosp_license builtin hook."""
         # First call should do nothing as there are no files to check.
         diff = [
-            rh.git.RawDiffEntry(file='d.bp', status='D'),
-            rh.git.RawDiffEntry(file='m.bp', status='M'),
-            rh.git.RawDiffEntry(file='non-interested', status='A'),
+            rh.git.RawDiffEntry(file="d.bp", status="D"),
+            rh.git.RawDiffEntry(file="m.bp", status="M"),
+            rh.git.RawDiffEntry(file="non-interested", status="A"),
         ]
         ret = rh.hooks.check_aosp_license(
-            self.project, 'commit', 'desc', diff, options=self.options)
+            self.project, "commit", "desc", diff, options=self.options
+        )
         self.assertIsNone(ret)
         self.assertFalse(mock_check.called)
 
         # Second call will have some results.
         diff = [
-            rh.git.RawDiffEntry(file='a.bp', status='A'),
+            rh.git.RawDiffEntry(file="a.bp", status="A"),
         ]
         ret = rh.hooks.check_aosp_license(
-            self.project, 'commit', 'desc', diff, options=self.options)
+            self.project, "commit", "desc", diff, options=self.options
+        )
         self.assertIsNotNone(ret)
 
         # No result since all paths are excluded.
         diff = [
-            rh.git.RawDiffEntry(file='a/a.bp', status='A'),
-            rh.git.RawDiffEntry(file='b/a.bp', status='A'),
-            rh.git.RawDiffEntry(file='c/d/a.bp', status='A'),
+            rh.git.RawDiffEntry(file="a/a.bp", status="A"),
+            rh.git.RawDiffEntry(file="b/a.bp", status="A"),
+            rh.git.RawDiffEntry(file="c/d/a.bp", status="A"),
         ]
         ret = rh.hooks.check_aosp_license(
-            self.project, 'commit', 'desc', diff,
-            options=rh.hooks.HookOptions('hook name',
-                ['--exclude-dirs=a,b', '--exclude-dirs=c/d'], {})
+            self.project,
+            "commit",
+            "desc",
+            diff,
+            options=rh.hooks.HookOptions(
+                "hook name", ["--exclude-dirs=a,b", "--exclude-dirs=c/d"], {}
+            ),
         )
         self.assertIsNone(ret)
 
         # Make sure that `--exclude-dir` doesn't match the path in the middle.
         diff = [
-            rh.git.RawDiffEntry(file='a/b/c.bp', status='A'),
+            rh.git.RawDiffEntry(file="a/b/c.bp", status="A"),
         ]
         ret = rh.hooks.check_aosp_license(
-            self.project, 'commit', 'desc', diff,
-            options=rh.hooks.HookOptions('hook name', ['--exclude-dirs=b'], {})
+            self.project,
+            "commit",
+            "desc",
+            diff,
+            options=rh.hooks.HookOptions("hook name", ["--exclude-dirs=b"], {}),
         )
         self.assertIsNotNone(ret)
 
+    def test_black(self, mock_check, _mock_run):
+        """Verify the black builtin hook."""
+        # First call should do nothing as there are no files to check.
+        ret = rh.hooks.check_black(
+            self.project, "commit", "desc", (), options=self.options
+        )
+        self.assertIsNone(ret)
+        self.assertFalse(mock_check.called)
+
+        # Second call will have some results.
+        diff = [rh.git.RawDiffEntry(file="main.py")]
+        ret = rh.hooks.check_black(
+            self.project, "commit", "desc", diff, options=self.options
+        )
+        self.assertIsNotNone(ret)
+        for result in ret:
+            self.assertIsNotNone(result.fixup_cmd)
 
     def test_bpfmt(self, mock_check, _mock_run):
         """Verify the bpfmt builtin hook."""
         # First call should do nothing as there are no files to check.
         ret = rh.hooks.check_bpfmt(
-            self.project, 'commit', 'desc', (), options=self.options)
+            self.project, "commit", "desc", (), options=self.options
+        )
         self.assertIsNone(ret)
         self.assertFalse(mock_check.called)
 
         # Second call will have some results.
-        diff = [rh.git.RawDiffEntry(file='Android.bp')]
+        diff = [rh.git.RawDiffEntry(file="Android.bp")]
         ret = rh.hooks.check_bpfmt(
-            self.project, 'commit', 'desc', diff, options=self.options)
+            self.project, "commit", "desc", diff, options=self.options
+        )
         self.assertIsNotNone(ret)
         for result in ret:
             self.assertIsNotNone(result.fixup_cmd)
@@ -434,74 +506,97 @@ class BuiltinHooksTests(unittest.TestCase):
     def test_checkpatch(self, mock_check, _mock_run):
         """Verify the checkpatch builtin hook."""
         ret = rh.hooks.check_checkpatch(
-            self.project, 'commit', 'desc', (), options=self.options)
+            self.project, "commit", "desc", (), options=self.options
+        )
         self.assertEqual(ret, mock_check.return_value)
 
     def test_clang_format(self, mock_check, _mock_run):
         """Verify the clang_format builtin hook."""
         ret = rh.hooks.check_clang_format(
-            self.project, 'commit', 'desc', (), options=self.options)
+            self.project, "commit", "desc", (), options=self.options
+        )
         self.assertEqual(ret, mock_check.return_value)
 
     def test_google_java_format(self, mock_check, _mock_run):
         """Verify the google_java_format builtin hook."""
         # First call should do nothing as there are no files to check.
         ret = rh.hooks.check_google_java_format(
-            self.project, 'commit', 'desc', (), options=self.options)
+            self.project, "commit", "desc", (), options=self.options
+        )
         self.assertIsNone(ret)
         self.assertFalse(mock_check.called)
         # Check that .java files are included by default.
-        diff = [rh.git.RawDiffEntry(file='foo.java'),
-                rh.git.RawDiffEntry(file='bar.kt'),
-                rh.git.RawDiffEntry(file='baz/blah.java')]
+        diff = [
+            rh.git.RawDiffEntry(file="foo.java"),
+            rh.git.RawDiffEntry(file="bar.kt"),
+            rh.git.RawDiffEntry(file="baz/blah.java"),
+        ]
         ret = rh.hooks.check_google_java_format(
-            self.project, 'commit', 'desc', diff, options=self.options)
-        self.assertListEqual(ret[0].files, ['foo.java', 'baz/blah.java'])
-        diff = [rh.git.RawDiffEntry(file='foo/f1.java'),
-                rh.git.RawDiffEntry(file='bar/f2.java'),
-                rh.git.RawDiffEntry(file='baz/f2.java')]
+            self.project, "commit", "desc", diff, options=self.options
+        )
+        self.assertListEqual(ret[0].files, ["foo.java", "baz/blah.java"])
+        diff = [
+            rh.git.RawDiffEntry(file="foo/f1.java"),
+            rh.git.RawDiffEntry(file="bar/f2.java"),
+            rh.git.RawDiffEntry(file="baz/f2.java"),
+        ]
         ret = rh.hooks.check_google_java_format(
-            self.project, 'commit', 'desc', diff,
-            options=rh.hooks.HookOptions('hook name',
-            ['--include-dirs=foo,baz'], {}))
-        self.assertListEqual(ret[0].files, ['foo/f1.java', 'baz/f2.java'])
+            self.project,
+            "commit",
+            "desc",
+            diff,
+            options=rh.hooks.HookOptions(
+                "hook name", ["--include-dirs=foo,baz"], {}
+            ),
+        )
+        self.assertListEqual(ret[0].files, ["foo/f1.java", "baz/f2.java"])
 
     def test_commit_msg_bug_field(self, _mock_check, _mock_run):
         """Verify the commit_msg_bug_field builtin hook."""
         # Check some good messages.
         self._test_commit_messages(
-            rh.hooks.check_commit_msg_bug_field, True, (
-                'subj\n\nBug: 1234\n',
-                'subj\n\nBug: 1234\nChange-Id: blah\n',
-                'subj\n\nFix: 1234\n',
-            ))
+            rh.hooks.check_commit_msg_bug_field,
+            True,
+            (
+                "subj\n\nBug: 1234\n",
+                "subj\n\nBug: 1234\nChange-Id: blah\n",
+                "subj\n\nFix: 1234\n",
+            ),
+        )
 
         # Check some bad messages.
         self._test_commit_messages(
-            rh.hooks.check_commit_msg_bug_field, False, (
-                'subj',
-                'subj\n\nBUG=1234\n',
-                'subj\n\nBUG: 1234\n',
-                'subj\n\nBug: N/A\n',
-                'subj\n\nBug:\n',
-                'subj\n\nFIX=1234\n',
-            ))
+            rh.hooks.check_commit_msg_bug_field,
+            False,
+            (
+                "subj",
+                "subj\n\nBUG=1234\n",
+                "subj\n\nBUG: 1234\n",
+                "subj\n\nBug: N/A\n",
+                "subj\n\nBug:\n",
+                "subj\n\nFIX=1234\n",
+            ),
+        )
 
     def test_commit_msg_changeid_field(self, _mock_check, _mock_run):
         """Verify the commit_msg_changeid_field builtin hook."""
         # Check some good messages.
         self._test_commit_messages(
-            rh.hooks.check_commit_msg_changeid_field, True, (
-                'subj\n\nChange-Id: I1234\n',
-            ))
+            rh.hooks.check_commit_msg_changeid_field,
+            True,
+            ("subj\n\nChange-Id: I1234\n",),
+        )
 
         # Check some bad messages.
         self._test_commit_messages(
-            rh.hooks.check_commit_msg_changeid_field, False, (
-                'subj',
-                'subj\n\nChange-Id: 1234\n',
-                'subj\n\nChange-ID: I1234\n',
-            ))
+            rh.hooks.check_commit_msg_changeid_field,
+            False,
+            (
+                "subj",
+                "subj\n\nChange-Id: 1234\n",
+                "subj\n\nChange-ID: I1234\n",
+            ),
+        )
 
     def test_commit_msg_prebuilt_apk_fields(self, _mock_check, _mock_run):
         """Verify the check_commit_msg_prebuilt_apk_fields builtin hook."""
@@ -509,10 +604,11 @@ class BuiltinHooksTests(unittest.TestCase):
         self._test_commit_messages(
             rh.hooks.check_commit_msg_prebuilt_apk_fields,
             True,
-            (
-                'subj\nTest: test case\nBug: bug id\n',
-            ),
-            ['foo.cpp', 'bar.py',]
+            ("subj\nTest: test case\nBug: bug id\n",),
+            [
+                "foo.cpp",
+                "bar.py",
+            ],
         )
 
         # Commits with APKs and all the required messages should pass.
@@ -520,41 +616,53 @@ class BuiltinHooksTests(unittest.TestCase):
             rh.hooks.check_commit_msg_prebuilt_apk_fields,
             True,
             (
-                ('Test App\n\nbar.apk\npackage: name=\'com.foo.bar\'\n'
-                 'versionCode=\'1001\'\nversionName=\'1.0.1001-A\'\n'
-                 'platformBuildVersionName=\'\'\ncompileSdkVersion=\'28\'\n'
-                 'compileSdkVersionCodename=\'9\'\nsdkVersion:\'16\'\n'
-                 'targetSdkVersion:\'28\'\n\nBuilt here:\n'
-                 'http://foo.bar.com/builder\n\n'
-                 'This build IS suitable for public release.\n\n'
-                 'Bug: 123\nTest: test\nChange-Id: XXXXXXX\n'),
-                ('Test App\n\nBuilt here:\nhttp://foo.bar.com/builder\n\n'
-                 'This build IS NOT suitable for public release.\n\n'
-                 'bar.apk\npackage: name=\'com.foo.bar\'\n'
-                 'versionCode=\'1001\'\nversionName=\'1.0.1001-A\'\n'
-                 'platformBuildVersionName=\'\'\ncompileSdkVersion=\'28\'\n'
-                 'compileSdkVersionCodename=\'9\'\nsdkVersion:\'16\'\n'
-                 'targetSdkVersion:\'28\'\n\nBug: 123\nTest: test\n'
-                 'Change-Id: XXXXXXX\n'),
-                ('Test App\n\nbar.apk\npackage: name=\'com.foo.bar\'\n'
-                 'versionCode=\'1001\'\nversionName=\'1.0.1001-A\'\n'
-                 'platformBuildVersionName=\'\'\ncompileSdkVersion=\'28\'\n'
-                 'compileSdkVersionCodename=\'9\'\nsdkVersion:\'16\'\n'
-                 'targetSdkVersion:\'28\'\n\nBuilt here:\n'
-                 'http://foo.bar.com/builder\n\n'
-                 'This build IS suitable for preview release but IS NOT '
-                 'suitable for public release.\n\n'
-                 'Bug: 123\nTest: test\nChange-Id: XXXXXXX\n'),
-                ('Test App\n\nbar.apk\npackage: name=\'com.foo.bar\'\n'
-                 'versionCode=\'1001\'\nversionName=\'1.0.1001-A\'\n'
-                 'platformBuildVersionName=\'\'\ncompileSdkVersion=\'28\'\n'
-                 'compileSdkVersionCodename=\'9\'\nsdkVersion:\'16\'\n'
-                 'targetSdkVersion:\'28\'\n\nBuilt here:\n'
-                 'http://foo.bar.com/builder\n\n'
-                 'This build IS NOT suitable for preview or public release.\n\n'
-                 'Bug: 123\nTest: test\nChange-Id: XXXXXXX\n'),
+                (
+                    "Test App\n\nbar.apk\npackage: name='com.foo.bar'\n"
+                    "versionCode='1001'\nversionName='1.0.1001-A'\n"
+                    "platformBuildVersionName=''\ncompileSdkVersion='28'\n"
+                    "compileSdkVersionCodename='9'\nsdkVersion:'16'\n"
+                    "targetSdkVersion:'28'\n\nBuilt here:\n"
+                    "http://foo.bar.com/builder\n\n"
+                    "This build IS suitable for public release.\n\n"
+                    "Bug: 123\nTest: test\nChange-Id: XXXXXXX\n"
+                ),
+                (
+                    "Test App\n\nBuilt here:\nhttp://foo.bar.com/builder\n\n"
+                    "This build IS NOT suitable for public release.\n\n"
+                    "bar.apk\npackage: name='com.foo.bar'\n"
+                    "versionCode='1001'\nversionName='1.0.1001-A'\n"
+                    "platformBuildVersionName=''\ncompileSdkVersion='28'\n"
+                    "compileSdkVersionCodename='9'\nsdkVersion:'16'\n"
+                    "targetSdkVersion:'28'\n\nBug: 123\nTest: test\n"
+                    "Change-Id: XXXXXXX\n"
+                ),
+                (
+                    "Test App\n\nbar.apk\npackage: name='com.foo.bar'\n"
+                    "versionCode='1001'\nversionName='1.0.1001-A'\n"
+                    "platformBuildVersionName=''\ncompileSdkVersion='28'\n"
+                    "compileSdkVersionCodename='9'\nsdkVersion:'16'\n"
+                    "targetSdkVersion:'28'\n\nBuilt here:\n"
+                    "http://foo.bar.com/builder\n\n"
+                    "This build IS suitable for preview release but IS NOT "
+                    "suitable for public release.\n\n"
+                    "Bug: 123\nTest: test\nChange-Id: XXXXXXX\n"
+                ),
+                (
+                    "Test App\n\nbar.apk\npackage: name='com.foo.bar'\n"
+                    "versionCode='1001'\nversionName='1.0.1001-A'\n"
+                    "platformBuildVersionName=''\ncompileSdkVersion='28'\n"
+                    "compileSdkVersionCodename='9'\nsdkVersion:'16'\n"
+                    "targetSdkVersion:'28'\n\nBuilt here:\n"
+                    "http://foo.bar.com/builder\n\n"
+                    "This build IS NOT suitable for preview or public "
+                    "release.\n\n"
+                    "Bug: 123\nTest: test\nChange-Id: XXXXXXX\n"
+                ),
             ),
-            ['foo.apk', 'bar.py',]
+            [
+                "foo.apk",
+                "bar.py",
+            ],
         )
 
         # Commits with APKs and without all the required messages should fail.
@@ -562,68 +670,85 @@ class BuiltinHooksTests(unittest.TestCase):
             rh.hooks.check_commit_msg_prebuilt_apk_fields,
             False,
             (
-                'subj\nTest: test case\nBug: bug id\n',
+                "subj\nTest: test case\nBug: bug id\n",
                 # Missing 'package'.
-                ('Test App\n\nbar.apk\n'
-                 'versionCode=\'1001\'\nversionName=\'1.0.1001-A\'\n'
-                 'platformBuildVersionName=\'\'\ncompileSdkVersion=\'28\'\n'
-                 'compileSdkVersionCodename=\'9\'\nsdkVersion:\'16\'\n'
-                 'targetSdkVersion:\'28\'\n\nBuilt here:\n'
-                 'http://foo.bar.com/builder\n\n'
-                 'This build IS suitable for public release.\n\n'
-                 'Bug: 123\nTest: test\nChange-Id: XXXXXXX\n'),
+                (
+                    "Test App\n\nbar.apk\n"
+                    "versionCode='1001'\nversionName='1.0.1001-A'\n"
+                    "platformBuildVersionName=''\ncompileSdkVersion='28'\n"
+                    "compileSdkVersionCodename='9'\nsdkVersion:'16'\n"
+                    "targetSdkVersion:'28'\n\nBuilt here:\n"
+                    "http://foo.bar.com/builder\n\n"
+                    "This build IS suitable for public release.\n\n"
+                    "Bug: 123\nTest: test\nChange-Id: XXXXXXX\n"
+                ),
                 # Missing 'sdkVersion'.
-                ('Test App\n\nbar.apk\npackage: name=\'com.foo.bar\'\n'
-                 'versionCode=\'1001\'\nversionName=\'1.0.1001-A\'\n'
-                 'platformBuildVersionName=\'\'\ncompileSdkVersion=\'28\'\n'
-                 'compileSdkVersionCodename=\'9\'\n'
-                 'targetSdkVersion:\'28\'\n\nBuilt here:\n'
-                 'http://foo.bar.com/builder\n\n'
-                 'This build IS suitable for public release.\n\n'
-                 'Bug: 123\nTest: test\nChange-Id: XXXXXXX\n'),
+                (
+                    "Test App\n\nbar.apk\npackage: name='com.foo.bar'\n"
+                    "versionCode='1001'\nversionName='1.0.1001-A'\n"
+                    "platformBuildVersionName=''\ncompileSdkVersion='28'\n"
+                    "compileSdkVersionCodename='9'\n"
+                    "targetSdkVersion:'28'\n\nBuilt here:\n"
+                    "http://foo.bar.com/builder\n\n"
+                    "This build IS suitable for public release.\n\n"
+                    "Bug: 123\nTest: test\nChange-Id: XXXXXXX\n"
+                ),
                 # Missing 'targetSdkVersion'.
-                ('Test App\n\nbar.apk\npackage: name=\'com.foo.bar\'\n'
-                 'versionCode=\'1001\'\nversionName=\'1.0.1001-A\'\n'
-                 'platformBuildVersionName=\'\'\ncompileSdkVersion=\'28\'\n'
-                 'compileSdkVersionCodename=\'9\'\nsdkVersion:\'16\'\n'
-                 'Built here:\nhttp://foo.bar.com/builder\n\n'
-                 'This build IS suitable for public release.\n\n'
-                 'Bug: 123\nTest: test\nChange-Id: XXXXXXX\n'),
+                (
+                    "Test App\n\nbar.apk\npackage: name='com.foo.bar'\n"
+                    "versionCode='1001'\nversionName='1.0.1001-A'\n"
+                    "platformBuildVersionName=''\ncompileSdkVersion='28'\n"
+                    "compileSdkVersionCodename='9'\nsdkVersion:'16'\n"
+                    "Built here:\nhttp://foo.bar.com/builder\n\n"
+                    "This build IS suitable for public release.\n\n"
+                    "Bug: 123\nTest: test\nChange-Id: XXXXXXX\n"
+                ),
                 # Missing build location.
-                ('Test App\n\nbar.apk\npackage: name=\'com.foo.bar\'\n'
-                 'versionCode=\'1001\'\nversionName=\'1.0.1001-A\'\n'
-                 'platformBuildVersionName=\'\'\ncompileSdkVersion=\'28\'\n'
-                 'compileSdkVersionCodename=\'9\'\nsdkVersion:\'16\'\n'
-                 'targetSdkVersion:\'28\'\n\n'
-                 'This build IS suitable for public release.\n\n'
-                 'Bug: 123\nTest: test\nChange-Id: XXXXXXX\n'),
+                (
+                    "Test App\n\nbar.apk\npackage: name='com.foo.bar'\n"
+                    "versionCode='1001'\nversionName='1.0.1001-A'\n"
+                    "platformBuildVersionName=''\ncompileSdkVersion='28'\n"
+                    "compileSdkVersionCodename='9'\nsdkVersion:'16'\n"
+                    "targetSdkVersion:'28'\n\n"
+                    "This build IS suitable for public release.\n\n"
+                    "Bug: 123\nTest: test\nChange-Id: XXXXXXX\n"
+                ),
                 # Missing public release indication.
-                ('Test App\n\nbar.apk\npackage: name=\'com.foo.bar\'\n'
-                 'versionCode=\'1001\'\nversionName=\'1.0.1001-A\'\n'
-                 'platformBuildVersionName=\'\'\ncompileSdkVersion=\'28\'\n'
-                 'compileSdkVersionCodename=\'9\'\nsdkVersion:\'16\'\n'
-                 'targetSdkVersion:\'28\'\n\nBuilt here:\n'
-                 'http://foo.bar.com/builder\n\n'
-                 'Bug: 123\nTest: test\nChange-Id: XXXXXXX\n'),
+                (
+                    "Test App\n\nbar.apk\npackage: name='com.foo.bar'\n"
+                    "versionCode='1001'\nversionName='1.0.1001-A'\n"
+                    "platformBuildVersionName=''\ncompileSdkVersion='28'\n"
+                    "compileSdkVersionCodename='9'\nsdkVersion:'16'\n"
+                    "targetSdkVersion:'28'\n\nBuilt here:\n"
+                    "http://foo.bar.com/builder\n\n"
+                    "Bug: 123\nTest: test\nChange-Id: XXXXXXX\n"
+                ),
             ),
-            ['foo.apk', 'bar.py',]
+            [
+                "foo.apk",
+                "bar.py",
+            ],
         )
 
     def test_commit_msg_test_field(self, _mock_check, _mock_run):
         """Verify the commit_msg_test_field builtin hook."""
         # Check some good messages.
         self._test_commit_messages(
-            rh.hooks.check_commit_msg_test_field, True, (
-                'subj\n\nTest: i did done dood it\n',
-            ))
+            rh.hooks.check_commit_msg_test_field,
+            True,
+            ("subj\n\nTest: i did done dood it\n",),
+        )
 
         # Check some bad messages.
         self._test_commit_messages(
-            rh.hooks.check_commit_msg_test_field, False, (
-                'subj',
-                'subj\n\nTEST=1234\n',
-                'subj\n\nTEST: I1234\n',
-            ))
+            rh.hooks.check_commit_msg_test_field,
+            False,
+            (
+                "subj",
+                "subj\n\nTEST=1234\n",
+                "subj\n\nTEST: I1234\n",
+            ),
+        )
 
     def test_commit_msg_relnote_field_format(self, _mock_check, _mock_run):
         """Verify the commit_msg_relnote_field_format builtin hook."""
@@ -632,151 +757,211 @@ class BuiltinHooksTests(unittest.TestCase):
             rh.hooks.check_commit_msg_relnote_field_format,
             True,
             (
-                'subj',
-                'subj\n\nTest: i did done dood it\nBug: 1234',
-                'subj\n\nMore content\n\nTest: i did done dood it\nBug: 1234',
-                'subj\n\nRelnote: This is a release note\nBug: 1234',
-                'subj\n\nRelnote:This is a release note\nBug: 1234',
-                'subj\n\nRelnote: This is a release note.\nBug: 1234',
+                "subj",
+                "subj\n\nTest: i did done dood it\nBug: 1234",
+                "subj\n\nMore content\n\nTest: i did done dood it\nBug: 1234",
+                "subj\n\nRelnote: This is a release note\nBug: 1234",
+                "subj\n\nRelnote:This is a release note\nBug: 1234",
+                "subj\n\nRelnote: This is a release note.\nBug: 1234",
                 'subj\n\nRelnote: "This is a release note."\nBug: 1234',
                 'subj\n\nRelnote: "This is a \\"release note\\"."\n\nBug: 1234',
-                'subj\n\nRelnote: This is a release note.\nChange-Id: 1234',
-                'subj\n\nRelnote: This is a release note.\n\nChange-Id: 1234',
-                ('subj\n\nRelnote: "This is a release note."\n\n'
-                 'Change-Id: 1234'),
-                ('subj\n\nRelnote: This is a release note.\n\n'
-                 'It has more info, but it is not part of the release note'
-                 '\nChange-Id: 1234'),
-                ('subj\n\nRelnote: "This is a release note.\n'
-                 'It contains a correct second line."'),
-                ('subj\n\nRelnote:"This is a release note.\n'
-                 'It contains a correct second line."'),
-                ('subj\n\nRelnote: "This is a release note.\n'
-                 'It contains a correct second line.\n'
-                 'And even a third line."\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: "This is a release note.\n'
-                 'It contains a correct second line.\n'
-                 '\\"Quotes\\" are even used on the third line."\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: This is release note 1.\n'
-                 'Relnote: This is release note 2.\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: This is release note 1.\n'
-                 'Relnote: "This is release note 2, and it\n'
-                 'contains a correctly formatted third line."\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: "This is release note 1 with\n'
-                 'a correctly formatted second line."\n\n'
-                 'Relnote: "This is release note 2, and it\n'
-                 'contains a correctly formatted second line."\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: "This is a release note with\n'
-                 'a correctly formatted second line."\n\n'
-                 'Bug: 1234'
-                 'Here is some extra "quoted" content.'),
-                ('subj\n\nRelnote: """This is a release note.\n\n'
-                 'This relnote contains an empty line.\n'
-                 'Then a non-empty line.\n\n'
-                 'And another empty line."""\n\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: """This is a release note.\n\n'
-                 'This relnote contains an empty line.\n'
-                 'Then an acceptable "quoted" line.\n\n'
-                 'And another empty line."""\n\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: """This is a release note."""\n\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: """This is a release note.\n'
-                 'It has a second line."""\n\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: """This is a release note.\n'
-                 'It has a second line, but does not end here.\n'
-                 '"""\n\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: """This is a release note.\n'
-                 '"It" has a second line, but does not end here.\n'
-                 '"""\n\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: "This is a release note.\n'
-                 'It has a second line, but does not end here.\n'
-                 '"\n\n'
-                 'Bug: 1234'),
-            ))
+                "subj\n\nRelnote: This is a release note.\nChange-Id: 1234",
+                "subj\n\nRelnote: This is a release note.\n\nChange-Id: 1234",
+                (
+                    'subj\n\nRelnote: "This is a release note."\n\n'
+                    "Change-Id: 1234"
+                ),
+                (
+                    "subj\n\nRelnote: This is a release note.\n\n"
+                    "It has more info, but it is not part of the release note"
+                    "\nChange-Id: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: "This is a release note.\n'
+                    'It contains a correct second line."'
+                ),
+                (
+                    'subj\n\nRelnote:"This is a release note.\n'
+                    'It contains a correct second line."'
+                ),
+                (
+                    'subj\n\nRelnote: "This is a release note.\n'
+                    "It contains a correct second line.\n"
+                    'And even a third line."\n'
+                    "Bug: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: "This is a release note.\n'
+                    "It contains a correct second line.\n"
+                    '\\"Quotes\\" are even used on the third line."\n'
+                    "Bug: 1234"
+                ),
+                (
+                    "subj\n\nRelnote: This is release note 1.\n"
+                    "Relnote: This is release note 2.\n"
+                    "Bug: 1234"
+                ),
+                (
+                    "subj\n\nRelnote: This is release note 1.\n"
+                    'Relnote: "This is release note 2, and it\n'
+                    'contains a correctly formatted third line."\n'
+                    "Bug: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: "This is release note 1 with\n'
+                    'a correctly formatted second line."\n\n'
+                    'Relnote: "This is release note 2, and it\n'
+                    'contains a correctly formatted second line."\n'
+                    "Bug: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: "This is a release note with\n'
+                    'a correctly formatted second line."\n\n'
+                    "Bug: 1234"
+                    'Here is some extra "quoted" content.'
+                ),
+                (
+                    'subj\n\nRelnote: """This is a release note.\n\n'
+                    "This relnote contains an empty line.\n"
+                    "Then a non-empty line.\n\n"
+                    'And another empty line."""\n\n'
+                    "Bug: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: """This is a release note.\n\n'
+                    "This relnote contains an empty line.\n"
+                    'Then an acceptable "quoted" line.\n\n'
+                    'And another empty line."""\n\n'
+                    "Bug: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: """This is a release note."""\n\n'
+                    "Bug: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: """This is a release note.\n'
+                    'It has a second line."""\n\n'
+                    "Bug: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: """This is a release note.\n'
+                    "It has a second line, but does not end here.\n"
+                    '"""\n\n'
+                    "Bug: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: """This is a release note.\n'
+                    '"It" has a second line, but does not end here.\n'
+                    '"""\n\n'
+                    "Bug: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: "This is a release note.\n'
+                    "It has a second line, but does not end here.\n"
+                    '"\n\n'
+                    "Bug: 1234"
+                ),
+            ),
+        )
 
         # Check some bad messages.
         self._test_commit_messages(
             rh.hooks.check_commit_msg_relnote_field_format,
             False,
             (
-                'subj\n\nReleaseNote: This is a release note.\n',
-                'subj\n\nRelnotes: This is a release note.\n',
-                'subj\n\nRel-note: This is a release note.\n',
-                'subj\n\nrelnoTes: This is a release note.\n',
-                'subj\n\nrel-Note: This is a release note.\n',
+                "subj\n\nReleaseNote: This is a release note.\n",
+                "subj\n\nRelnotes: This is a release note.\n",
+                "subj\n\nRel-note: This is a release note.\n",
+                "subj\n\nrelnoTes: This is a release note.\n",
+                "subj\n\nrel-Note: This is a release note.\n",
                 'subj\n\nRelnote: "This is a "release note"."\nBug: 1234',
                 'subj\n\nRelnote: This is a "release note".\nBug: 1234',
-                ('subj\n\nRelnote: This is a release note.\n'
-                 'It contains an incorrect second line.'),
-                ('subj\n\nRelnote: "This is a release note.\n'
-                 'It contains multiple lines.\n'
-                 'But it does not provide an ending quote.\n'),
-                ('subj\n\nRelnote: "This is a release note.\n'
-                 'It contains multiple lines but no closing quote.\n'
-                 'Test: my test "hello world"\n'),
-                ('subj\n\nRelnote: This is release note 1.\n'
-                 'Relnote: "This is release note 2, and it\n'
-                 'contains an incorrectly formatted third line.\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: This is release note 1 with\n'
-                 'an incorrectly formatted second line.\n\n'
-                 'Relnote: "This is release note 2, and it\n'
-                 'contains a correctly formatted second line."\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: "This is release note 1 with\n'
-                 'a correctly formatted second line."\n\n'
-                 'Relnote: This is release note 2, and it\n'
-                 'contains an incorrectly formatted second line.\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: "This is a release note.\n'
-                 'It contains a correct second line.\n'
-                 'But incorrect "quotes" on the third line."\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: """This is a release note.\n'
-                 'It has a second line, but no closing triple quote.\n\n'
-                 'Bug: 1234'),
-                ('subj\n\nRelnote: "This is a release note.\n'
-                 '"It" has a second line, but does not end here.\n'
-                 '"\n\n'
-                 'Bug: 1234'),
-            ))
+                (
+                    "subj\n\nRelnote: This is a release note.\n"
+                    "It contains an incorrect second line."
+                ),
+                (
+                    'subj\n\nRelnote: "This is a release note.\n'
+                    "It contains multiple lines.\n"
+                    "But it does not provide an ending quote.\n"
+                ),
+                (
+                    'subj\n\nRelnote: "This is a release note.\n'
+                    "It contains multiple lines but no closing quote.\n"
+                    'Test: my test "hello world"\n'
+                ),
+                (
+                    "subj\n\nRelnote: This is release note 1.\n"
+                    'Relnote: "This is release note 2, and it\n'
+                    "contains an incorrectly formatted third line.\n"
+                    "Bug: 1234"
+                ),
+                (
+                    "subj\n\nRelnote: This is release note 1 with\n"
+                    "an incorrectly formatted second line.\n\n"
+                    'Relnote: "This is release note 2, and it\n'
+                    'contains a correctly formatted second line."\n'
+                    "Bug: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: "This is release note 1 with\n'
+                    'a correctly formatted second line."\n\n'
+                    "Relnote: This is release note 2, and it\n"
+                    "contains an incorrectly formatted second line.\n"
+                    "Bug: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: "This is a release note.\n'
+                    "It contains a correct second line.\n"
+                    'But incorrect "quotes" on the third line."\n'
+                    "Bug: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: """This is a release note.\n'
+                    "It has a second line, but no closing triple quote.\n\n"
+                    "Bug: 1234"
+                ),
+                (
+                    'subj\n\nRelnote: "This is a release note.\n'
+                    '"It" has a second line, but does not end here.\n'
+                    '"\n\n'
+                    "Bug: 1234"
+                ),
+            ),
+        )
 
     def test_commit_msg_relnote_for_current_txt(self, _mock_check, _mock_run):
         """Verify the commit_msg_relnote_for_current_txt builtin hook."""
-        diff_without_current_txt = ['bar/foo.txt',
-                                    'foo.cpp',
-                                    'foo.java',
-                                    'foo_current.java',
-                                    'foo_current.txt',
-                                    'baz/current.java',
-                                    'baz/foo_current.txt']
-        diff_with_current_txt = diff_without_current_txt + ['current.txt']
-        diff_with_subdir_current_txt = \
-            diff_without_current_txt + ['foo/current.txt']
-        diff_with_experimental_current_txt = \
-            diff_without_current_txt + ['public_plus_experimental_current.txt']
+        diff_without_current_txt = [
+            "bar/foo.txt",
+            "foo.cpp",
+            "foo.java",
+            "foo_current.java",
+            "foo_current.txt",
+            "baz/current.java",
+            "baz/foo_current.txt",
+        ]
+        diff_with_current_txt = diff_without_current_txt + ["current.txt"]
+        diff_with_subdir_current_txt = diff_without_current_txt + [
+            "foo/current.txt"
+        ]
+        diff_with_experimental_current_txt = diff_without_current_txt + [
+            "public_plus_experimental_current.txt"
+        ]
         # Check some good messages.
         self._test_commit_messages(
             rh.hooks.check_commit_msg_relnote_for_current_txt,
             True,
             (
-                'subj\n\nRelnote: This is a release note\n',
-                'subj\n\nRelnote: This is a release note.\n\nChange-Id: 1234',
-                ('subj\n\nRelnote: This is release note 1 with\n'
-                 'an incorrectly formatted second line.\n\n'
-                 'Relnote: "This is release note 2, and it\n'
-                 'contains a correctly formatted second line."\n'
-                 'Bug: 1234'),
+                "subj\n\nRelnote: This is a release note\n",
+                "subj\n\nRelnote: This is a release note.\n\nChange-Id: 1234",
+                (
+                    "subj\n\nRelnote: This is release note 1 with\n"
+                    "an incorrectly formatted second line.\n\n"
+                    'Relnote: "This is release note 2, and it\n'
+                    'contains a correctly formatted second line."\n'
+                    "Bug: 1234"
+                ),
             ),
             files=diff_with_current_txt,
         )
@@ -785,13 +970,15 @@ class BuiltinHooksTests(unittest.TestCase):
             rh.hooks.check_commit_msg_relnote_for_current_txt,
             True,
             (
-                'subj\n\nRelnote: This is a release note\n',
-                'subj\n\nRelnote: This is a release note.\n\nChange-Id: 1234',
-                ('subj\n\nRelnote: This is release note 1 with\n'
-                 'an incorrectly formatted second line.\n\n'
-                 'Relnote: "This is release note 2, and it\n'
-                 'contains a correctly formatted second line."\n'
-                 'Bug: 1234'),
+                "subj\n\nRelnote: This is a release note\n",
+                "subj\n\nRelnote: This is a release note.\n\nChange-Id: 1234",
+                (
+                    "subj\n\nRelnote: This is release note 1 with\n"
+                    "an incorrectly formatted second line.\n\n"
+                    'Relnote: "This is release note 2, and it\n'
+                    'contains a correctly formatted second line."\n'
+                    "Bug: 1234"
+                ),
             ),
             files=diff_with_experimental_current_txt,
         )
@@ -800,13 +987,15 @@ class BuiltinHooksTests(unittest.TestCase):
             rh.hooks.check_commit_msg_relnote_for_current_txt,
             True,
             (
-                'subj\n\nRelnote: This is a release note\n',
-                'subj\n\nRelnote: This is a release note.\n\nChange-Id: 1234',
-                ('subj\n\nRelnote: This is release note 1 with\n'
-                 'an incorrectly formatted second line.\n\n'
-                 'Relnote: "This is release note 2, and it\n'
-                 'contains a correctly formatted second line."\n'
-                 'Bug: 1234'),
+                "subj\n\nRelnote: This is a release note\n",
+                "subj\n\nRelnote: This is a release note.\n\nChange-Id: 1234",
+                (
+                    "subj\n\nRelnote: This is release note 1 with\n"
+                    "an incorrectly formatted second line.\n\n"
+                    'Relnote: "This is release note 2, and it\n'
+                    'contains a correctly formatted second line."\n'
+                    "Bug: 1234"
+                ),
             ),
             files=diff_with_subdir_current_txt,
         )
@@ -815,15 +1004,17 @@ class BuiltinHooksTests(unittest.TestCase):
             rh.hooks.check_commit_msg_relnote_for_current_txt,
             True,
             (
-                'subj',
-                'subj\nBug: 12345\nChange-Id: 1234',
-                'subj\n\nRelnote: This is a release note\n',
-                'subj\n\nRelnote: This is a release note.\n\nChange-Id: 1234',
-                ('subj\n\nRelnote: This is release note 1 with\n'
-                 'an incorrectly formatted second line.\n\n'
-                 'Relnote: "This is release note 2, and it\n'
-                 'contains a correctly formatted second line."\n'
-                 'Bug: 1234'),
+                "subj",
+                "subj\nBug: 12345\nChange-Id: 1234",
+                "subj\n\nRelnote: This is a release note\n",
+                "subj\n\nRelnote: This is a release note.\n\nChange-Id: 1234",
+                (
+                    "subj\n\nRelnote: This is release note 1 with\n"
+                    "an incorrectly formatted second line.\n\n"
+                    'Relnote: "This is release note 2, and it\n'
+                    'contains a correctly formatted second line."\n'
+                    "Bug: 1234"
+                ),
             ),
             files=diff_without_current_txt,
         )
@@ -831,57 +1022,52 @@ class BuiltinHooksTests(unittest.TestCase):
         self._test_commit_messages(
             rh.hooks.check_commit_msg_relnote_for_current_txt,
             False,
-            (
-                'subj'
-                'subj\nBug: 12345\nChange-Id: 1234',
-            ),
+            ("subjsubj\nBug: 12345\nChange-Id: 1234",),
             files=diff_with_current_txt,
         )
         # Check some bad messages.
         self._test_commit_messages(
             rh.hooks.check_commit_msg_relnote_for_current_txt,
             False,
-            (
-                'subj'
-                'subj\nBug: 12345\nChange-Id: 1234',
-            ),
+            ("subjsubj\nBug: 12345\nChange-Id: 1234",),
             files=diff_with_experimental_current_txt,
         )
         # Check some bad messages.
         self._test_commit_messages(
             rh.hooks.check_commit_msg_relnote_for_current_txt,
             False,
-            (
-                'subj'
-                'subj\nBug: 12345\nChange-Id: 1234',
-            ),
+            ("subjsubj\nBug: 12345\nChange-Id: 1234",),
             files=diff_with_subdir_current_txt,
         )
 
     def test_cpplint(self, mock_check, _mock_run):
         """Verify the cpplint builtin hook."""
-        self._test_file_filter(mock_check, rh.hooks.check_cpplint,
-                               ('foo.cpp', 'foo.cxx'))
+        self._test_file_filter(
+            mock_check, rh.hooks.check_cpplint, ("foo.cpp", "foo.cxx")
+        )
 
     def test_gofmt(self, mock_check, _mock_run):
         """Verify the gofmt builtin hook."""
         # First call should do nothing as there are no files to check.
         ret = rh.hooks.check_gofmt(
-            self.project, 'commit', 'desc', (), options=self.options)
+            self.project, "commit", "desc", (), options=self.options
+        )
         self.assertIsNone(ret)
         self.assertFalse(mock_check.called)
 
         # Second call will have some results.
-        diff = [rh.git.RawDiffEntry(file='foo.go')]
+        diff = [rh.git.RawDiffEntry(file="foo.go")]
         ret = rh.hooks.check_gofmt(
-            self.project, 'commit', 'desc', diff, options=self.options)
+            self.project, "commit", "desc", diff, options=self.options
+        )
         self.assertIsNotNone(ret)
 
     def test_jsonlint(self, mock_check, _mock_run):
         """Verify the jsonlint builtin hook."""
         # First call should do nothing as there are no files to check.
         ret = rh.hooks.check_json(
-            self.project, 'commit', 'desc', (), options=self.options)
+            self.project, "commit", "desc", (), options=self.options
+        )
         self.assertIsNone(ret)
         self.assertFalse(mock_check.called)
 
@@ -891,87 +1077,103 @@ class BuiltinHooksTests(unittest.TestCase):
         """Verify the ktfmt builtin hook."""
         # First call should do nothing as there are no files to check.
         ret = rh.hooks.check_ktfmt(
-            self.project, 'commit', 'desc', (), options=self.options)
+            self.project, "commit", "desc", (), options=self.options
+        )
         self.assertIsNone(ret)
         self.assertFalse(mock_check.called)
         # Check that .kt files are included by default.
-        diff = [rh.git.RawDiffEntry(file='foo.kt'),
-                rh.git.RawDiffEntry(file='bar.java'),
-                rh.git.RawDiffEntry(file='baz/blah.kt')]
+        diff = [
+            rh.git.RawDiffEntry(file="foo.kt"),
+            rh.git.RawDiffEntry(file="bar.java"),
+            rh.git.RawDiffEntry(file="baz/blah.kt"),
+        ]
+        ret = rh.hooks.check_ktfmt(
+            self.project, "commit", "desc", diff, options=self.options
+        )
+        self.assertListEqual(ret[0].files, ["foo.kt", "baz/blah.kt"])
+        diff = [
+            rh.git.RawDiffEntry(file="foo/f1.kt"),
+            rh.git.RawDiffEntry(file="bar/f2.kt"),
+            rh.git.RawDiffEntry(file="baz/f2.kt"),
+        ]
         ret = rh.hooks.check_ktfmt(
-            self.project, 'commit', 'desc', diff, options=self.options)
-        self.assertListEqual(ret[0].files, ['foo.kt', 'baz/blah.kt'])
-        diff = [rh.git.RawDiffEntry(file='foo/f1.kt'),
-                rh.git.RawDiffEntry(file='bar/f2.kt'),
-                rh.git.RawDiffEntry(file='baz/f2.kt')]
-        ret = rh.hooks.check_ktfmt(self.project, 'commit', 'desc', diff,
-                                   options=rh.hooks.HookOptions('hook name', [
-                                       '--include-dirs=foo,baz'], {}))
-        self.assertListEqual(ret[0].files, ['foo/f1.kt', 'baz/f2.kt'])
+            self.project,
+            "commit",
+            "desc",
+            diff,
+            options=rh.hooks.HookOptions(
+                "hook name", ["--include-dirs=foo,baz"], {}
+            ),
+        )
+        self.assertListEqual(ret[0].files, ["foo/f1.kt", "baz/f2.kt"])
 
     def test_pylint(self, mock_check, _mock_run):
         """Verify the pylint builtin hook."""
-        self._test_file_filter(mock_check, rh.hooks.check_pylint3,
-                               ('foo.py',))
+        self._test_file_filter(mock_check, rh.hooks.check_pylint3, ("foo.py",))
 
     def test_pylint2(self, mock_check, _mock_run):
         """Verify the pylint2 builtin hook."""
         ret = rh.hooks.check_pylint2(
-            self.project, 'commit', 'desc', (), options=self.options)
+            self.project, "commit", "desc", (), options=self.options
+        )
         self.assertEqual(len(ret), 1)
         self.assertTrue(ret[0].is_warning())
 
     def test_pylint3(self, mock_check, _mock_run):
         """Verify the pylint3 builtin hook."""
-        self._test_file_filter(mock_check, rh.hooks.check_pylint3,
-                               ('foo.py',))
+        self._test_file_filter(mock_check, rh.hooks.check_pylint3, ("foo.py",))
 
     def test_rustfmt(self, mock_check, _mock_run):
         # First call should do nothing as there are no files to check.
         ret = rh.hooks.check_rustfmt(
-            self.project, 'commit', 'desc', (), options=self.options)
+            self.project, "commit", "desc", (), options=self.options
+        )
         self.assertEqual(ret, None)
         self.assertFalse(mock_check.called)
 
         # Second call will have some results.
-        diff = [rh.git.RawDiffEntry(file='lib.rs')]
+        diff = [rh.git.RawDiffEntry(file="lib.rs")]
         ret = rh.hooks.check_rustfmt(
-            self.project, 'commit', 'desc', diff, options=self.options)
+            self.project, "commit", "desc", diff, options=self.options
+        )
         self.assertNotEqual(ret, None)
 
     def test_xmllint(self, mock_check, _mock_run):
         """Verify the xmllint builtin hook."""
-        self._test_file_filter(mock_check, rh.hooks.check_xmllint,
-                               ('foo.xml',))
+        self._test_file_filter(mock_check, rh.hooks.check_xmllint, ("foo.xml",))
 
     def test_android_test_mapping_format(self, mock_check, _mock_run):
         """Verify the android_test_mapping_format builtin hook."""
         # First call should do nothing as there are no files to check.
         ret = rh.hooks.check_android_test_mapping(
-            self.project, 'commit', 'desc', (), options=self.options)
+            self.project, "commit", "desc", (), options=self.options
+        )
         self.assertIsNone(ret)
         self.assertFalse(mock_check.called)
 
         # Second call will have some results.
-        diff = [rh.git.RawDiffEntry(file='TEST_MAPPING')]
+        diff = [rh.git.RawDiffEntry(file="TEST_MAPPING")]
         ret = rh.hooks.check_android_test_mapping(
-            self.project, 'commit', 'desc', diff, options=self.options)
+            self.project, "commit", "desc", diff, options=self.options
+        )
         self.assertIsNotNone(ret)
 
     def test_aidl_format(self, mock_check, _mock_run):
         """Verify the aidl_format builtin hook."""
         # First call should do nothing as there are no files to check.
         ret = rh.hooks.check_aidl_format(
-            self.project, 'commit', 'desc', (), options=self.options)
+            self.project, "commit", "desc", (), options=self.options
+        )
         self.assertIsNone(ret)
         self.assertFalse(mock_check.called)
 
         # Second call will have some results.
-        diff = [rh.git.RawDiffEntry(file='IFoo.go')]
+        diff = [rh.git.RawDiffEntry(file="IFoo.go")]
         ret = rh.hooks.check_gofmt(
-            self.project, 'commit', 'desc', diff, options=self.options)
+            self.project, "commit", "desc", diff, options=self.options
+        )
         self.assertIsNotNone(ret)
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     unittest.main()
diff --git a/rh/results.py b/rh/results.py
index 236387e..4a7143b 100644
--- a/rh/results.py
+++ b/rh/results.py
@@ -18,7 +18,7 @@ import os
 import sys
 from typing import List, NamedTuple, Optional
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -71,11 +71,16 @@ class HookResult(object):
 class HookCommandResult(HookResult):
     """A single hook result based on a CompletedProcess."""
 
-    def __init__(self, hook, project, commit, result, files=(),
-                 fixup_cmd=None):
-        HookResult.__init__(self, hook, project, commit,
-                            result.stderr if result.stderr else result.stdout,
-                            files=files, fixup_cmd=fixup_cmd)
+    def __init__(self, hook, project, commit, result, files=(), fixup_cmd=None):
+        HookResult.__init__(
+            self,
+            hook,
+            project,
+            commit,
+            result.stderr if result.stderr else result.stdout,
+            files=files,
+            fixup_cmd=fixup_cmd,
+        )
         self.result = result
 
     def __bool__(self):
diff --git a/rh/results_unittest.py b/rh/results_unittest.py
index 93d909e..a02e77a 100755
--- a/rh/results_unittest.py
+++ b/rh/results_unittest.py
@@ -19,7 +19,7 @@ import os
 import sys
 import unittest
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -43,12 +43,12 @@ class HookResultTests(unittest.TestCase):
     def test_error_warning(self):
         """Check error & warning handling."""
         # No errors.
-        result = rh.results.HookResult('hook', 'project', 'HEAD', False)
+        result = rh.results.HookResult("hook", "project", "HEAD", False)
         self.assertFalse(result)
         self.assertFalse(result.is_warning())
 
         # An error.
-        result = rh.results.HookResult('hook', 'project', 'HEAD', True)
+        result = rh.results.HookResult("hook", "project", "HEAD", True)
         self.assertTrue(result)
         self.assertFalse(result.is_warning())
 
@@ -60,19 +60,22 @@ class HookCommandResultTests(unittest.TestCase):
         """Check error & warning handling."""
         # No errors.
         result = rh.results.HookCommandResult(
-            'hook', 'project', 'HEAD', COMPLETED_PROCESS_PASS)
+            "hook", "project", "HEAD", COMPLETED_PROCESS_PASS
+        )
         self.assertFalse(result)
         self.assertFalse(result.is_warning())
 
         # An error.
         result = rh.results.HookCommandResult(
-            'hook', 'project', 'HEAD', COMPLETED_PROCESS_FAIL)
+            "hook", "project", "HEAD", COMPLETED_PROCESS_FAIL
+        )
         self.assertTrue(result)
         self.assertFalse(result.is_warning())
 
         # A warning.
         result = rh.results.HookCommandResult(
-            'hook', 'project', 'HEAD', COMPLETED_PROCESS_WARN)
+            "hook", "project", "HEAD", COMPLETED_PROCESS_WARN
+        )
         self.assertFalse(result)
         self.assertTrue(result.is_warning())
 
@@ -83,23 +86,28 @@ class ProjectResultsTests(unittest.TestCase):
     def test_error_warning(self):
         """Check error & warning handling."""
         # No errors.
-        result = rh.results.ProjectResults('project', 'workdir')
+        result = rh.results.ProjectResults("project", "workdir")
         self.assertFalse(result)
 
         # Warnings are not errors.
-        result.add_results([
-            rh.results.HookResult('hook', 'project', 'HEAD', False),
-            rh.results.HookCommandResult(
-                'hook', 'project', 'HEAD', COMPLETED_PROCESS_WARN),
-        ])
+        result.add_results(
+            [
+                rh.results.HookResult("hook", "project", "HEAD", False),
+                rh.results.HookCommandResult(
+                    "hook", "project", "HEAD", COMPLETED_PROCESS_WARN
+                ),
+            ]
+        )
         self.assertFalse(result)
 
         # Errors are errors.
-        result.add_results([
-            rh.results.HookResult('hook', 'project', 'HEAD', True),
-        ])
+        result.add_results(
+            [
+                rh.results.HookResult("hook", "project", "HEAD", True),
+            ]
+        )
         self.assertTrue(result)
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     unittest.main()
diff --git a/rh/shell.py b/rh/shell.py
index bc66f37..6ea8fc1 100644
--- a/rh/shell.py
+++ b/rh/shell.py
@@ -18,7 +18,7 @@ import os
 import pathlib
 import sys
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -33,10 +33,10 @@ del _path
 # See the bash man page as well as the POSIX shell documentation for more info:
 #   http://www.gnu.org/software/bash/manual/bashref.html
 #   http://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html
-_SHELL_QUOTABLE_CHARS = frozenset('[|&;()<> \t!{}[]=*?~$"\'\\#^')
+_SHELL_QUOTABLE_CHARS = frozenset("[|&;()<> \t!{}[]=*?~$\"'\\#^")
 # The chars that, when used inside of double quotes, need escaping.
 # Order here matters as we need to escape backslashes first.
-_SHELL_ESCAPE_CHARS = r'\"`$'
+_SHELL_ESCAPE_CHARS = r"\"`$"
 
 
 def quote(s):
@@ -68,7 +68,7 @@ def quote(s):
     """
     # If callers pass down bad types, don't blow up.
     if isinstance(s, bytes):
-        s = s.encode('utf-8')
+        s = s.encode("utf-8")
     elif isinstance(s, pathlib.PurePath):
         return str(s)
     elif not isinstance(s, str):
@@ -89,7 +89,7 @@ def quote(s):
     # used inside of double quotes.
     for c in _SHELL_ESCAPE_CHARS:
         if c in s:
-            s = s.replace(c, fr'\{c}')
+            s = s.replace(c, rf"\{c}")
     return f'"{s}"'
 
 
@@ -106,7 +106,7 @@ def unquote(s):
       The unescaped version of the string.
     """
     if not s:
-        return ''
+        return ""
 
     if s[0] == "'":
         return s[1:-1]
@@ -115,11 +115,11 @@ def unquote(s):
         return s
 
     s = s[1:-1]
-    output = ''
+    output = ""
     i = 0
     while i < len(s) - 1:
         # Skip the backslash when it makes sense.
-        if s[i] == '\\' and s[i + 1] in _SHELL_ESCAPE_CHARS:
+        if s[i] == "\\" and s[i + 1] in _SHELL_ESCAPE_CHARS:
             i += 1
         output += s[i]
         i += 1
@@ -148,7 +148,7 @@ def cmd_to_str(cmd):
       String representing full command.
     """
     # Use str before repr to translate unicode strings to regular strings.
-    return ' '.join(quote(arg) for arg in cmd)
+    return " ".join(quote(arg) for arg in cmd)
 
 
 def boolean_shell_value(sval, default):
@@ -158,9 +158,9 @@ def boolean_shell_value(sval, default):
 
     if isinstance(sval, str):
         s = sval.lower()
-        if s in ('yes', 'y', '1', 'true'):
+        if s in ("yes", "y", "1", "true"):
             return True
-        if s in ('no', 'n', '0', 'false'):
+        if s in ("no", "n", "0", "false"):
             return False
 
-    raise ValueError(f'Could not decode as a boolean value: {sval!r}')
+    raise ValueError(f"Could not decode as a boolean value: {sval!r}")
diff --git a/rh/shell_unittest.py b/rh/shell_unittest.py
index fec8710..4d0bbf1 100755
--- a/rh/shell_unittest.py
+++ b/rh/shell_unittest.py
@@ -21,7 +21,7 @@ from pathlib import Path
 import sys
 import unittest
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -40,9 +40,11 @@ class DiffTestCase(unittest.TestCase):
 
     def _assertEqual(self, func, test_input, test_output, result):
         """Like assertEqual but with built in diff support."""
-        diff = '\n'.join(list(self.differ.compare([test_output], [result])))
-        msg = (f'Expected {func} to translate {test_input!r} to '
-               f'{test_output!r}, but got {result!r}\n{diff}')
+        diff = "\n".join(list(self.differ.compare([test_output], [result])))
+        msg = (
+            f"Expected {func} to translate {test_input!r} to "
+            f"{test_output!r}, but got {result!r}\n{diff}"
+        )
         self.assertEqual(test_output, result, msg)
 
     def _testData(self, functor, tests, check_type=True):
@@ -65,15 +67,15 @@ class ShellQuoteTest(DiffTestCase):
         """Basic ShellQuote tests."""
         # Dict of expected output strings to input lists.
         tests_quote = {
-            "''": '',
-            'a': 'a',
-            "'a b c'": 'a b c',
-            "'a\tb'": 'a\tb',
-            "'/a$file'": '/a$file',
-            "'/a#file'": '/a#file',
+            "''": "",
+            "a": "a",
+            "'a b c'": "a b c",
+            "'a\tb'": "a\tb",
+            "'/a$file'": "/a$file",
+            "'/a#file'": "/a#file",
             """'b"c'""": 'b"c',
-            "'a@()b'": 'a@()b',
-            'j%k': 'j%k',
+            "'a@()b'": "a@()b",
+            "j%k": "j%k",
             r'''"s'a\$va\\rs"''': r"s'a$va\rs",
             r'''"\\'\\\""''': r'''\'\"''',
             r'''"'\\\$"''': r"""'\$""",
@@ -82,7 +84,7 @@ class ShellQuoteTest(DiffTestCase):
         # Expected input output specific to ShellUnquote.  This string cannot
         # be produced by ShellQuote but is still a valid bash escaped string.
         tests_unquote = {
-            r'''\$''': r'''"\\$"''',
+            r"""\$""": r'''"\\$"''',
         }
 
         def aux(s):
@@ -97,13 +99,13 @@ class ShellQuoteTest(DiffTestCase):
 
     def testPathlib(self):
         """Verify pathlib is handled."""
-        self.assertEqual(rh.shell.quote(Path('/')), '/')
+        self.assertEqual(rh.shell.quote(Path("/")), "/")
 
     def testBadInputs(self):
         """Verify bad inputs do not crash."""
         for arg, exp in (
-            (1234, '1234'),
-            (Exception('hi'), "Exception('hi')"),
+            (1234, "1234"),
+            (Exception("hi"), "Exception('hi')"),
         ):
             self.assertEqual(rh.shell.quote(arg), exp)
 
@@ -114,12 +116,11 @@ class CmdToStrTest(DiffTestCase):
     def testCmdToStr(self):
         # Dict of expected output strings to input lists.
         tests = {
-            r"a b": ['a', 'b'],
-            r"'a b' c": ['a b', 'c'],
-            r'''a "b'c"''': ['a', "b'c"],
-            r'''a "/'\$b" 'a b c' "xy'z"''':
-                ['a', "/'$b", 'a b c', "xy'z"],
-            '': [],
+            r"a b": ["a", "b"],
+            r"'a b' c": ["a b", "c"],
+            r'''a "b'c"''': ["a", "b'c"],
+            r'''a "/'\$b" 'a b c' "xy'z"''': ["a", "/'$b", "a b c", "xy'z"],
+            "": [],
         }
         self._testData(rh.shell.cmd_to_str, tests)
 
@@ -133,17 +134,37 @@ class BooleanShellTest(unittest.TestCase):
             self.assertTrue(rh.shell.boolean_shell_value(v, True))
             self.assertFalse(rh.shell.boolean_shell_value(v, False))
 
-        for v in (1234, '', 'akldjsf', '"'):
+        for v in (1234, "", "akldjsf", '"'):
             self.assertRaises(ValueError, rh.shell.boolean_shell_value, v, True)
 
-        for v in ('yes', 'YES', 'YeS', 'y', 'Y', '1', 'true', 'True', 'TRUE',):
+        for v in (
+            "yes",
+            "YES",
+            "YeS",
+            "y",
+            "Y",
+            "1",
+            "true",
+            "True",
+            "TRUE",
+        ):
             self.assertTrue(rh.shell.boolean_shell_value(v, True))
             self.assertTrue(rh.shell.boolean_shell_value(v, False))
 
-        for v in ('no', 'NO', 'nO', 'n', 'N', '0', 'false', 'False', 'FALSE',):
+        for v in (
+            "no",
+            "NO",
+            "nO",
+            "n",
+            "N",
+            "0",
+            "false",
+            "False",
+            "FALSE",
+        ):
             self.assertFalse(rh.shell.boolean_shell_value(v, True))
             self.assertFalse(rh.shell.boolean_shell_value(v, False))
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     unittest.main()
diff --git a/rh/signals.py b/rh/signals.py
index c8a8d81..75ec87c 100644
--- a/rh/signals.py
+++ b/rh/signals.py
@@ -18,7 +18,7 @@ import os
 import signal
 import sys
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
diff --git a/rh/terminal.py b/rh/terminal.py
index a6f31d9..1ef3425 100644
--- a/rh/terminal.py
+++ b/rh/terminal.py
@@ -21,7 +21,7 @@ import os
 import sys
 from typing import List, Optional
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -33,7 +33,7 @@ import rh.shell
 # This will erase all content in the current line after the cursor.  This is
 # useful for partial updates & progress messages as the terminal can display
 # it better.
-CSI_ERASE_LINE_AFTER = '\x1b[K'
+CSI_ERASE_LINE_AFTER = "\x1b[K"
 
 
 class Color(object):
@@ -41,9 +41,9 @@ class Color(object):
 
     BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)
     BOLD = -1
-    COLOR_START = '\033[1;%dm'
-    BOLD_START = '\033[1m'
-    RESET = '\033[m'
+    COLOR_START = "\033[1;%dm"
+    BOLD_START = "\033[1m"
+    RESET = "\033[m"
 
     def __init__(self, enabled=None):
         """Create a new Color object, optionally disabling color output.
@@ -66,7 +66,7 @@ class Color(object):
         """
         if self.enabled:
             return self.COLOR_START % (color + 30)
-        return ''
+        return ""
 
     def stop(self):
         """Returns a stop color code.
@@ -77,7 +77,7 @@ class Color(object):
         """
         if self.enabled:
             return self.RESET
-        return ''
+        return ""
 
     def color(self, color, text):
         """Returns text with conditionally added color escape sequences.
@@ -102,9 +102,10 @@ class Color(object):
     def enabled(self):
         """See if the colorization is enabled."""
         if self._enabled is None:
-            if 'NOCOLOR' in os.environ:
+            if "NOCOLOR" in os.environ:
                 self._enabled = not rh.shell.boolean_shell_value(
-                    os.environ['NOCOLOR'], False)
+                    os.environ["NOCOLOR"], False
+                )
             else:
                 self._enabled = sys.stderr.isatty()
         return self._enabled
@@ -118,11 +119,11 @@ def print_status_line(line, print_newline=False):
       print_newline: Print a newline at the end, if sys.stderr is a TTY.
     """
     if sys.stderr.isatty():
-        output = '\r' + line + CSI_ERASE_LINE_AFTER
+        output = "\r" + line + CSI_ERASE_LINE_AFTER
         if print_newline:
-            output += '\n'
+            output += "\n"
     else:
-        output = line + '\n'
+        output = line + "\n"
 
     sys.stderr.write(output)
     sys.stderr.flush()
@@ -156,8 +157,13 @@ def str_prompt(
         raise
 
 
-def boolean_prompt(prompt='Do you want to continue?', default=True,
-                   true_value='yes', false_value='no', prolog=None):
+def boolean_prompt(
+    prompt="Do you want to continue?",
+    default=True,
+    true_value="yes",
+    false_value="no",
+    prolog=None,
+):
     """Helper function for processing boolean choice prompts.
 
     Args:
@@ -174,7 +180,8 @@ def boolean_prompt(prompt='Do you want to continue?', default=True,
     true_text, false_text = true_value, false_value
     if true_value == false_value:
         raise ValueError(
-            f'true_value and false_value must differ: got {true_value!r}')
+            f"true_value and false_value must differ: got {true_value!r}"
+        )
 
     if default:
         true_text = true_text[0].upper() + true_text[1:]
@@ -182,8 +189,8 @@ def boolean_prompt(prompt='Do you want to continue?', default=True,
         false_text = false_text[0].upper() + false_text[1:]
 
     if prolog:
-        prompt = f'\n{prolog}\n{prompt}'
-    prompt = '\n' + prompt
+        prompt = f"\n{prolog}\n{prompt}"
+    prompt = "\n" + prompt
 
     while True:
         response = str_prompt(prompt, choices=(true_text, false_text))
diff --git a/rh/terminal_unittest.py b/rh/terminal_unittest.py
index b76b907..9f67bba 100755
--- a/rh/terminal_unittest.py
+++ b/rh/terminal_unittest.py
@@ -21,7 +21,7 @@ import os
 import sys
 import unittest
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -36,7 +36,7 @@ class ColorTests(unittest.TestCase):
     """Verify behavior of Color class."""
 
     def setUp(self):
-        os.environ.pop('NOCOLOR', None)
+        os.environ.pop("NOCOLOR", None)
 
     def test_enabled_auto_tty(self):
         """Test automatic enable behavior based on tty."""
@@ -53,11 +53,11 @@ class ColorTests(unittest.TestCase):
         """Test automatic enable behavior based on $NOCOLOR."""
         stderr = io.StringIO()
         with contextlib.redirect_stderr(stderr):
-            os.environ['NOCOLOR'] = 'yes'
+            os.environ["NOCOLOR"] = "yes"
             c = rh.terminal.Color()
             self.assertFalse(c.enabled)
 
-            os.environ['NOCOLOR'] = 'no'
+            os.environ["NOCOLOR"] = "no"
             c = rh.terminal.Color()
             self.assertTrue(c.enabled)
 
@@ -66,14 +66,14 @@ class ColorTests(unittest.TestCase):
         stderr = io.StringIO()
         with contextlib.redirect_stderr(stderr):
             stderr.isatty = lambda: True
-            os.environ['NOCOLOR'] = 'no'
+            os.environ["NOCOLOR"] = "no"
             c = rh.terminal.Color()
             self.assertTrue(c.enabled)
             c = rh.terminal.Color(False)
             self.assertFalse(c.enabled)
 
             stderr.isatty = lambda: False
-            os.environ['NOCOLOR'] = 'yes'
+            os.environ["NOCOLOR"] = "yes"
             c = rh.terminal.Color()
             self.assertFalse(c.enabled)
             c = rh.terminal.Color(True)
@@ -82,17 +82,18 @@ class ColorTests(unittest.TestCase):
     def test_output_disabled(self):
         """Test output when coloring is disabled."""
         c = rh.terminal.Color(False)
-        self.assertEqual(c.start(rh.terminal.Color.BLACK), '')
-        self.assertEqual(c.color(rh.terminal.Color.BLACK, 'foo'), 'foo')
-        self.assertEqual(c.stop(), '')
+        self.assertEqual(c.start(rh.terminal.Color.BLACK), "")
+        self.assertEqual(c.color(rh.terminal.Color.BLACK, "foo"), "foo")
+        self.assertEqual(c.stop(), "")
 
     def test_output_enabled(self):
         """Test output when coloring is enabled."""
         c = rh.terminal.Color(True)
-        self.assertEqual(c.start(rh.terminal.Color.BLACK), '\x1b[1;30m')
-        self.assertEqual(c.color(rh.terminal.Color.BLACK, 'foo'),
-                         '\x1b[1;30mfoo\x1b[m')
-        self.assertEqual(c.stop(), '\x1b[m')
+        self.assertEqual(c.start(rh.terminal.Color.BLACK), "\x1b[1;30m")
+        self.assertEqual(
+            c.color(rh.terminal.Color.BLACK, "foo"), "\x1b[1;30mfoo\x1b[m"
+        )
+        self.assertEqual(c.stop(), "\x1b[m")
 
 
 class PrintStatusLine(unittest.TestCase):
@@ -103,18 +104,18 @@ class PrintStatusLine(unittest.TestCase):
         stderr = io.StringIO()
         stderr.isatty = lambda: True
         with contextlib.redirect_stderr(stderr):
-            rh.terminal.print_status_line('foo')
-            rh.terminal.print_status_line('bar', print_newline=True)
+            rh.terminal.print_status_line("foo")
+            rh.terminal.print_status_line("bar", print_newline=True)
         csi = rh.terminal.CSI_ERASE_LINE_AFTER
-        self.assertEqual(stderr.getvalue(), f'\rfoo{csi}\rbar{csi}\n')
+        self.assertEqual(stderr.getvalue(), f"\rfoo{csi}\rbar{csi}\n")
 
     def test_no_terminal(self):
         """Check tty-less behavior."""
         stderr = io.StringIO()
         with contextlib.redirect_stderr(stderr):
-            rh.terminal.print_status_line('foo')
-            rh.terminal.print_status_line('bar', print_newline=True)
-        self.assertEqual(stderr.getvalue(), 'foo\nbar\n')
+            rh.terminal.print_status_line("foo")
+            rh.terminal.print_status_line("bar", print_newline=True)
+        self.assertEqual(stderr.getvalue(), "foo\nbar\n")
 
 
 @contextlib.contextmanager
@@ -146,20 +147,21 @@ class StringPromptTests(unittest.TestCase):
         stdout = io.StringIO()
         with redirect_stdin(self.stdin), contextlib.redirect_stdout(stdout):
             # Test EOF behavior.
-            self.assertIsNone(rh.terminal.str_prompt('foo', ('a', 'b')))
+            self.assertIsNone(rh.terminal.str_prompt("foo", ("a", "b")))
 
             # Test enter behavior.
-            self.set_stdin('\n')
-            self.assertEqual(rh.terminal.str_prompt('foo', ('a', 'b')), '')
+            self.set_stdin("\n")
+            self.assertEqual(rh.terminal.str_prompt("foo", ("a", "b")), "")
 
             # Lowercase inputs.
-            self.set_stdin('Ok')
-            self.assertEqual(rh.terminal.str_prompt('foo', ('a', 'b')), 'ok')
+            self.set_stdin("Ok")
+            self.assertEqual(rh.terminal.str_prompt("foo", ("a", "b")), "ok")
 
             # Don't lowercase inputs.
-            self.set_stdin('Ok')
+            self.set_stdin("Ok")
             self.assertEqual(
-                rh.terminal.str_prompt('foo', ('a', 'b'), lower=False), 'Ok')
+                rh.terminal.str_prompt("foo", ("a", "b"), lower=False), "Ok"
+            )
 
 
 class BooleanPromptTests(unittest.TestCase):
@@ -180,20 +182,20 @@ class BooleanPromptTests(unittest.TestCase):
         stdout = io.StringIO()
         with redirect_stdin(self.stdin), contextlib.redirect_stdout(stdout):
             # Default values.  Will loop to EOF when it doesn't match anything.
-            for v in ('', '\n', 'oops'):
+            for v in ("", "\n", "oops"):
                 self.set_stdin(v)
                 self.assertTrue(rh.terminal.boolean_prompt())
 
             # False values.
-            for v in ('n', 'N', 'no', 'NO'):
+            for v in ("n", "N", "no", "NO"):
                 self.set_stdin(v)
                 self.assertFalse(rh.terminal.boolean_prompt())
 
             # True values.
-            for v in ('y', 'Y', 'ye', 'yes', 'YES'):
+            for v in ("y", "Y", "ye", "yes", "YES"):
                 self.set_stdin(v)
                 self.assertTrue(rh.terminal.boolean_prompt())
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     unittest.main()
diff --git a/rh/utils.py b/rh/utils.py
index d4001d6..0a599f3 100644
--- a/rh/utils.py
+++ b/rh/utils.py
@@ -23,7 +23,7 @@ import sys
 import tempfile
 import time
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -42,11 +42,11 @@ def timedelta_str(delta):
     total = delta.total_seconds()
     hours, rem = divmod(total, 3600)
     mins, secs = divmod(rem, 60)
-    ret = f'{int(secs)}.{delta.microseconds // 1000:03}s'
+    ret = f"{int(secs)}.{delta.microseconds // 1000:03}s"
     if mins:
-        ret = f'{int(mins)}m{ret}'
+        ret = f"{int(mins)}m{ret}"
     if hours:
-        ret = f'{int(hours)}h{ret}'
+        ret = f"{int(hours)}h{ret}"
     return ret
 
 
@@ -58,7 +58,8 @@ class CompletedProcess(subprocess.CompletedProcess):
 
     def __init__(self, args=None, returncode=None, stdout=None, stderr=None):
         super().__init__(
-            args=args, returncode=returncode, stdout=stdout, stderr=stderr)
+            args=args, returncode=returncode, stdout=stdout, stderr=stderr
+        )
 
     @property
     def cmd(self):
@@ -106,7 +107,7 @@ class CalledProcessError(subprocess.CalledProcessError):
     @property
     def cmdstr(self):
         """Return self.cmd as a well shell-quoted string for debugging."""
-        return '' if self.cmd is None else rh.shell.cmd_to_str(self.cmd)
+        return "" if self.cmd is None else rh.shell.cmd_to_str(self.cmd)
 
     def stringify(self, stdout=True, stderr=True):
         """Custom method for controlling what is included in stringifying this.
@@ -119,7 +120,7 @@ class CalledProcessError(subprocess.CalledProcessError):
           A summary string for this result.
         """
         items = [
-            f'return code: {self.returncode}; command: {self.cmdstr}',
+            f"return code: {self.returncode}; command: {self.cmdstr}",
         ]
         if stderr and self.stderr:
             items.append(self.stderr)
@@ -127,7 +128,7 @@ class CalledProcessError(subprocess.CalledProcessError):
             items.append(self.stdout)
         if self.msg:
             items.append(self.msg)
-        return '\n'.join(items)
+        return "\n".join(items)
 
     def __str__(self):
         return self.stringify()
@@ -141,8 +142,9 @@ class TerminateCalledProcessError(CalledProcessError):
     """
 
 
-def _kill_child_process(proc, int_timeout, kill_timeout, cmd, original_handler,
-                        signum, frame):
+def _kill_child_process(
+    proc, int_timeout, kill_timeout, cmd, original_handler, signum, frame
+):
     """Used as a signal handler by RunCommand.
 
     This is internal to Runcommand.  No other code should use this.
@@ -173,8 +175,10 @@ def _kill_child_process(proc, int_timeout, kill_timeout, cmd, original_handler,
                 # Still doesn't want to die.  Too bad, so sad, time to die.
                 proc.kill()
         except EnvironmentError as e:
-            print(f'Ignoring unhandled exception in _kill_child_process: {e}',
-                  file=sys.stderr)
+            print(
+                f"Ignoring unhandled exception in _kill_child_process: {e}",
+                file=sys.stderr,
+            )
 
         # Ensure our child process has been reaped, but don't wait forever.
         proc.wait_lock_breaker(timeout=60)
@@ -182,7 +186,8 @@ def _kill_child_process(proc, int_timeout, kill_timeout, cmd, original_handler,
     if not rh.signals.relay_signal(original_handler, signum, frame):
         # Mock up our own, matching exit code for signaling.
         raise TerminateCalledProcessError(
-            signum << 8, cmd, msg=f'Received signal {signum}')
+            signum << 8, cmd, msg=f"Received signal {signum}"
+        )
 
 
 class _Popen(subprocess.Popen):
@@ -226,7 +231,7 @@ class _Popen(subprocess.Popen):
         Workaround https://bugs.python.org/issue25960.
         """
         # If the lock doesn't exist, or is not locked, call the func directly.
-        lock = getattr(self, '_waitpid_lock', None)
+        lock = getattr(self, "_waitpid_lock", None)
         if lock is not None and lock.locked():
             try:
                 lock.release()
@@ -248,9 +253,21 @@ class _Popen(subprocess.Popen):
 
 # We use the keyword arg |input| which trips up pylint checks.
 # pylint: disable=redefined-builtin
-def run(cmd, redirect_stdout=False, redirect_stderr=False, cwd=None, input=None,
-        shell=False, env=None, extra_env=None, combine_stdout_stderr=False,
-        check=True, int_timeout=1, kill_timeout=1, capture_output=False):
+def run(
+    cmd,
+    redirect_stdout=False,
+    redirect_stderr=False,
+    cwd=None,
+    input=None,
+    shell=False,
+    env=None,
+    extra_env=None,
+    combine_stdout_stderr=False,
+    check=True,
+    int_timeout=1,
+    kill_timeout=1,
+    capture_output=False,
+):
     """Runs a command.
 
     Args:
@@ -307,7 +324,7 @@ def run(cmd, redirect_stdout=False, redirect_stderr=False, cwd=None, input=None,
             # issue in this particular case since our usage gurantees deletion,
             # and since this is primarily triggered during hard cgroups
             # shutdown.
-            return tempfile.TemporaryFile(dir='/tmp', buffering=0)
+            return tempfile.TemporaryFile(dir="/tmp", buffering=0)
 
     # Modify defaults based on parameters.
     # Note that tempfiles must be unbuffered else attempts to read
@@ -334,18 +351,18 @@ def run(cmd, redirect_stdout=False, redirect_stderr=False, cwd=None, input=None,
     # Otherwise we assume it's a file object that can be read from directly.
     if isinstance(input, str):
         stdin = subprocess.PIPE
-        input = input.encode('utf-8')
+        input = input.encode("utf-8")
     elif input is not None:
         stdin = input
         input = None
 
     if isinstance(cmd, str):
         if not shell:
-            raise Exception('Cannot run a string command without a shell')
-        cmd = ['/bin/bash', '-c', cmd]
+            raise Exception("Cannot run a string command without a shell")
+        cmd = ["/bin/bash", "-c", cmd]
         shell = False
     elif shell:
-        raise Exception('Cannot run an array command with a shell')
+        raise Exception("Cannot run an array command with a shell")
 
     # If we are using enter_chroot we need to use enterchroot pass env through
     # to the final command.
@@ -355,20 +372,33 @@ def run(cmd, redirect_stdout=False, redirect_stderr=False, cwd=None, input=None,
     def ensure_text(s):
         """Make sure |s| is a string if it's bytes."""
         if isinstance(s, bytes):
-            s = s.decode('utf-8', 'replace')
+            s = s.decode("utf-8", "replace")
         return s
 
     result.args = cmd
 
     proc = None
     try:
-        proc = _Popen(cmd, cwd=cwd, stdin=stdin, stdout=popen_stdout,
-                      stderr=popen_stderr, shell=False, env=env,
-                      close_fds=True)
+        proc = _Popen(
+            cmd,
+            cwd=cwd,
+            stdin=stdin,
+            stdout=popen_stdout,
+            stderr=popen_stderr,
+            shell=False,
+            env=env,
+            close_fds=True,
+        )
 
         old_sigint = signal.getsignal(signal.SIGINT)
-        handler = functools.partial(_kill_child_process, proc, int_timeout,
-                                    kill_timeout, cmd, old_sigint)
+        handler = functools.partial(
+            _kill_child_process,
+            proc,
+            int_timeout,
+            kill_timeout,
+            cmd,
+            old_sigint,
+        )
         # We have to ignore ValueError in case we're run from a thread.
         try:
             signal.signal(signal.SIGINT, handler)
@@ -376,8 +406,14 @@ def run(cmd, redirect_stdout=False, redirect_stderr=False, cwd=None, input=None,
             old_sigint = None
 
         old_sigterm = signal.getsignal(signal.SIGTERM)
-        handler = functools.partial(_kill_child_process, proc, int_timeout,
-                                    kill_timeout, cmd, old_sigterm)
+        handler = functools.partial(
+            _kill_child_process,
+            proc,
+            int_timeout,
+            kill_timeout,
+            cmd,
+            old_sigterm,
+        )
         try:
             signal.signal(signal.SIGTERM, handler)
         except ValueError:
@@ -408,13 +444,16 @@ def run(cmd, redirect_stdout=False, redirect_stderr=False, cwd=None, input=None,
         result.returncode = proc.returncode
 
         if check and proc.returncode:
-            msg = f'cwd={cwd}'
+            msg = f"cwd={cwd}"
             if extra_env:
-                msg += f', extra env={extra_env}'
+                msg += f", extra env={extra_env}"
             raise CalledProcessError(
-                result.returncode, result.cmd, msg=msg,
+                result.returncode,
+                result.cmd,
+                msg=msg,
                 stdout=ensure_text(result.stdout),
-                stderr=ensure_text(result.stderr))
+                stderr=ensure_text(result.stderr),
+            )
     except OSError as e:
         # Avoid leaking tempfiles.
         if popen_stdout is not None and not isinstance(popen_stdout, int):
@@ -424,7 +463,7 @@ def run(cmd, redirect_stdout=False, redirect_stderr=False, cwd=None, input=None,
 
         estr = str(e)
         if e.errno == errno.EACCES:
-            estr += '; does the program need `chmod a+x`?'
+            estr += "; does the program need `chmod a+x`?"
         if not check:
             result = CompletedProcess(args=cmd, returncode=255)
             if combine_stdout_stderr:
@@ -433,20 +472,26 @@ def run(cmd, redirect_stdout=False, redirect_stderr=False, cwd=None, input=None,
                 result.stderr = estr
         else:
             raise CalledProcessError(
-                result.returncode, result.cmd, msg=estr,
+                result.returncode,
+                result.cmd,
+                msg=estr,
                 stdout=ensure_text(result.stdout),
-                stderr=ensure_text(result.stderr)) from e
+                stderr=ensure_text(result.stderr),
+            ) from e
     finally:
         if proc is not None:
             # Ensure the process is dead.
             # Some pylint3 versions are confused here.
             # pylint: disable=too-many-function-args
-            _kill_child_process(proc, int_timeout, kill_timeout, cmd, None,
-                                None, None)
+            _kill_child_process(
+                proc, int_timeout, kill_timeout, cmd, None, None, None
+            )
 
     # Make sure output is returned as a string rather than bytes.
     result.stdout = ensure_text(result.stdout)
     result.stderr = ensure_text(result.stderr)
 
     return result
+
+
 # pylint: enable=redefined-builtin
diff --git a/rh/utils_unittest.py b/rh/utils_unittest.py
index bf720a7..5b977cd 100755
--- a/rh/utils_unittest.py
+++ b/rh/utils_unittest.py
@@ -21,7 +21,7 @@ from pathlib import Path
 import sys
 import unittest
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -39,27 +39,27 @@ class TimeDeltaStrTests(unittest.TestCase):
     def test_same(self):
         """Check timedelta of 0 seconds."""
         delta = datetime.timedelta(0)
-        self.assertEqual('0.000s', rh.utils.timedelta_str(delta))
+        self.assertEqual("0.000s", rh.utils.timedelta_str(delta))
 
     def test_millisecondss(self):
         """Check timedelta of milliseconds."""
         delta = datetime.timedelta(seconds=0.123456)
-        self.assertEqual('0.123s', rh.utils.timedelta_str(delta))
+        self.assertEqual("0.123s", rh.utils.timedelta_str(delta))
 
     def test_seconds(self):
         """Check timedelta of seconds."""
         delta = datetime.timedelta(seconds=12.3)
-        self.assertEqual('12.300s', rh.utils.timedelta_str(delta))
+        self.assertEqual("12.300s", rh.utils.timedelta_str(delta))
 
     def test_minutes(self):
         """Check timedelta of minutes."""
         delta = datetime.timedelta(seconds=72.3)
-        self.assertEqual('1m12.300s', rh.utils.timedelta_str(delta))
+        self.assertEqual("1m12.300s", rh.utils.timedelta_str(delta))
 
     def test_hours(self):
         """Check timedelta of hours."""
         delta = datetime.timedelta(seconds=4000.3)
-        self.assertEqual('1h6m40.300s', rh.utils.timedelta_str(delta))
+        self.assertEqual("1h6m40.300s", rh.utils.timedelta_str(delta))
 
 
 class CompletedProcessTests(unittest.TestCase):
@@ -68,28 +68,28 @@ class CompletedProcessTests(unittest.TestCase):
     def test_empty_cmdstr(self):
         """Check cmdstr with an empty command."""
         result = rh.utils.CompletedProcess(args=[])
-        self.assertEqual('', result.cmdstr)
+        self.assertEqual("", result.cmdstr)
 
     def test_basic_cmdstr(self):
         """Check cmdstr with a basic command command."""
-        result = rh.utils.CompletedProcess(args=['ls', 'a b'])
+        result = rh.utils.CompletedProcess(args=["ls", "a b"])
         self.assertEqual("ls 'a b'", result.cmdstr)
 
     def test_str(self):
         """Check str() handling."""
         # We don't enforce much, just that it doesn't crash.
         result = rh.utils.CompletedProcess()
-        self.assertNotEqual('', str(result))
+        self.assertNotEqual("", str(result))
         result = rh.utils.CompletedProcess(args=[])
-        self.assertNotEqual('', str(result))
+        self.assertNotEqual("", str(result))
 
     def test_repr(self):
         """Check repr() handling."""
         # We don't enforce much, just that it doesn't crash.
         result = rh.utils.CompletedProcess()
-        self.assertNotEqual('', repr(result))
+        self.assertNotEqual("", repr(result))
         result = rh.utils.CompletedProcess(args=[])
-        self.assertNotEqual('', repr(result))
+        self.assertNotEqual("", repr(result))
 
 
 class CalledProcessErrorTests(unittest.TestCase):
@@ -97,41 +97,42 @@ class CalledProcessErrorTests(unittest.TestCase):
 
     def test_basic(self):
         """Basic test we can create a normal instance."""
-        rh.utils.CalledProcessError(0, ['mycmd'])
+        rh.utils.CalledProcessError(0, ["mycmd"])
 
     def test_stringify(self):
         """Check stringify() handling."""
         # We don't assert much so we leave flexibility in changing format.
-        err = rh.utils.CalledProcessError(0, ['mycmd'])
-        self.assertIn('mycmd', err.stringify())
+        err = rh.utils.CalledProcessError(0, ["mycmd"])
+        self.assertIn("mycmd", err.stringify())
 
     def test_str(self):
         """Check str() handling."""
         # We don't assert much so we leave flexibility in changing format.
-        err = rh.utils.CalledProcessError(0, ['mycmd'])
-        self.assertIn('mycmd', str(err))
+        err = rh.utils.CalledProcessError(0, ["mycmd"])
+        self.assertIn("mycmd", str(err))
 
     def test_repr(self):
         """Check repr() handling."""
         # We don't assert much so we leave flexibility in changing format.
-        err = rh.utils.CalledProcessError(0, ['mycmd'])
-        self.assertNotEqual('', repr(err))
+        err = rh.utils.CalledProcessError(0, ["mycmd"])
+        self.assertNotEqual("", repr(err))
 
     def test_output(self):
         """Make sure .output is removed and .stdout works."""
         e = rh.utils.CalledProcessError(
-            0, ['true'], stdout='STDOUT', stderr='STDERR')
+            0, ["true"], stdout="STDOUT", stderr="STDERR"
+        )
         with self.assertRaises(AttributeError):
             assert e.output is None
-        assert e.stdout == 'STDOUT'
-        assert e.stderr == 'STDERR'
+        assert e.stdout == "STDOUT"
+        assert e.stderr == "STDERR"
 
-        e.stdout = 'STDout'
-        e.stderr = 'STDerr'
+        e.stdout = "STDout"
+        e.stderr = "STDerr"
         with self.assertRaises(AttributeError):
             assert e.output is None
-        assert e.stdout == 'STDout'
-        assert e.stderr == 'STDerr'
+        assert e.stdout == "STDout"
+        assert e.stderr == "STDerr"
 
 
 class RunCommandTests(unittest.TestCase):
@@ -139,96 +140,100 @@ class RunCommandTests(unittest.TestCase):
 
     def test_basic(self):
         """Simple basic test."""
-        ret = rh.utils.run(['true'])
-        self.assertEqual('true', ret.cmdstr)
+        ret = rh.utils.run(["true"])
+        self.assertEqual("true", ret.cmdstr)
         self.assertIsNone(ret.stdout)
         self.assertIsNone(ret.stderr)
 
     def test_stdout_capture(self):
         """Verify output capturing works."""
-        ret = rh.utils.run(['echo', 'hi'], redirect_stdout=True)
-        self.assertEqual('hi\n', ret.stdout)
+        ret = rh.utils.run(["echo", "hi"], redirect_stdout=True)
+        self.assertEqual("hi\n", ret.stdout)
         self.assertIsNone(ret.stderr)
 
     def test_stderr_capture(self):
         """Verify stderr capturing works."""
-        ret = rh.utils.run(['sh', '-c', 'echo hi >&2'], redirect_stderr=True)
+        ret = rh.utils.run(["sh", "-c", "echo hi >&2"], redirect_stderr=True)
         self.assertIsNone(ret.stdout)
-        self.assertEqual('hi\n', ret.stderr)
+        self.assertEqual("hi\n", ret.stderr)
 
     def test_stdout_utf8(self):
         """Verify reading UTF-8 data works."""
-        ret = rh.utils.run(['printf', r'\xc3\x9f'], redirect_stdout=True)
-        self.assertEqual('ß', ret.stdout)
+        ret = rh.utils.run(["printf", r"\xc3\x9f"], redirect_stdout=True)
+        self.assertEqual("ß", ret.stdout)
         self.assertIsNone(ret.stderr)
 
     def test_stdin_utf8(self):
         """Verify writing UTF-8 data works."""
-        ret = rh.utils.run(['cat'], redirect_stdout=True, input='ß')
-        self.assertEqual('ß', ret.stdout)
+        ret = rh.utils.run(["cat"], redirect_stdout=True, input="ß")
+        self.assertEqual("ß", ret.stdout)
         self.assertIsNone(ret.stderr)
 
     def test_check_false(self):
         """Verify handling of check=False."""
-        ret = rh.utils.run(['false'], check=False)
+        ret = rh.utils.run(["false"], check=False)
         self.assertNotEqual(0, ret.returncode)
-        self.assertIn('false', str(ret))
+        self.assertIn("false", str(ret))
 
-        ret = rh.utils.run(['true'], check=False)
+        ret = rh.utils.run(["true"], check=False)
         self.assertEqual(0, ret.returncode)
-        self.assertIn('true', str(ret))
+        self.assertIn("true", str(ret))
 
     def test_check_true(self):
         """Verify handling of check=True."""
         with self.assertRaises(rh.utils.CalledProcessError) as e:
-            rh.utils.run(['false'], check=True)
+            rh.utils.run(["false"], check=True)
         err = e.exception
         self.assertNotEqual(0, err.returncode)
-        self.assertIn('false', str(err))
+        self.assertIn("false", str(err))
 
-        ret = rh.utils.run(['true'], check=True)
+        ret = rh.utils.run(["true"], check=True)
         self.assertEqual(0, ret.returncode)
-        self.assertIn('true', str(ret))
+        self.assertIn("true", str(ret))
 
     def test_check_false_output(self):
         """Verify handling of output capturing w/check=False."""
         with self.assertRaises(rh.utils.CalledProcessError) as e:
-            rh.utils.run(['sh', '-c', 'echo out; echo err >&2; false'],
-                         check=True, capture_output=True)
+            rh.utils.run(
+                ["sh", "-c", "echo out; echo err >&2; false"],
+                check=True,
+                capture_output=True,
+            )
         err = e.exception
         self.assertNotEqual(0, err.returncode)
-        self.assertIn('false', str(err))
+        self.assertIn("false", str(err))
 
     def test_check_true_missing_prog_output(self):
         """Verify handling of output capturing w/missing progs."""
         with self.assertRaises(rh.utils.CalledProcessError) as e:
-            rh.utils.run(['./!~a/b/c/d/'], check=True, capture_output=True)
+            rh.utils.run(["./!~a/b/c/d/"], check=True, capture_output=True)
         err = e.exception
         self.assertNotEqual(0, err.returncode)
-        self.assertIn('a/b/c/d', str(err))
+        self.assertIn("a/b/c/d", str(err))
 
     def test_check_false_missing_prog_output(self):
         """Verify handling of output capturing w/missing progs."""
-        ret = rh.utils.run(['./!~a/b/c/d/'], check=False, capture_output=True)
+        ret = rh.utils.run(["./!~a/b/c/d/"], check=False, capture_output=True)
         self.assertNotEqual(0, ret.returncode)
-        self.assertIn('a/b/c/d', str(ret))
+        self.assertIn("a/b/c/d", str(ret))
 
     def test_check_false_missing_prog_combined_output(self):
         """Verify handling of combined output capturing w/missing progs."""
         with self.assertRaises(rh.utils.CalledProcessError) as e:
-            rh.utils.run(['./!~a/b/c/d/'], check=True,
-                         combine_stdout_stderr=True)
+            rh.utils.run(
+                ["./!~a/b/c/d/"], check=True, combine_stdout_stderr=True
+            )
         err = e.exception
         self.assertNotEqual(0, err.returncode)
-        self.assertIn('a/b/c/d', str(err))
+        self.assertIn("a/b/c/d", str(err))
 
     def test_pathlib(self):
         """Verify pathlib arguments work."""
-        result = rh.utils.run(['true', Path('/')])
+        result = rh.utils.run(["true", Path("/")])
         # Verify stringify behavior.
         str(result)
-        self.assertEqual(result.cmdstr, 'true /')
+        self.assertEqual(result.cmdstr, "true /")
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     unittest.main()
diff --git a/run_tests b/run_tests
new file mode 100755
index 0000000..605116e
--- /dev/null
+++ b/run_tests
@@ -0,0 +1,72 @@
+#!/usr/bin/env python3
+# Copyright 2019 The Android Open Source Project
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
+"""Wrapper to run analyzers & tests with the right settings."""
+
+import functools
+import os
+from pathlib import Path
+import subprocess
+import sys
+from typing import List
+
+import pytest
+
+
+ROOT_DIR = Path(__file__).resolve().parent
+
+
+@functools.lru_cache()
+def is_ci() -> bool:
+    """Whether we're running in our CI system."""
+    return os.getenv("LUCI_CQ") == "yes"
+
+
+def run_pytest(argv: List[str]) -> int:
+    """Returns the exit code from pytest."""
+    if is_ci():
+        argv = ["-m", "not skip_cq"] + argv
+
+    return pytest.main(argv)
+
+
+def run_black() -> int:
+    """Returns the exit code from black."""
+    # Black by default only matches .py files.  We have to list standalone
+    # scripts manually.
+    extra_programs = [
+        "run_tests",
+    ]
+    return subprocess.run(
+        [sys.executable, "-m", "black", "--verbose", "--check", ROOT_DIR]
+        + extra_programs,
+        check=False,
+        cwd=ROOT_DIR,
+    ).returncode
+
+
+def main(argv):
+    """The main entry."""
+    checks = (
+        functools.partial(run_pytest, argv),
+        run_black,
+    )
+    # Run all the tests all the time to get full feedback.  Don't exit on the
+    # first error as that makes it more difficult to iterate in the CQ.
+    return 1 if sum(c() for c in checks) else 0
+
+
+if __name__ == "__main__":
+    sys.exit(main(sys.argv[1:]))
diff --git a/run_tests.vpython3 b/run_tests.vpython3
new file mode 100644
index 0000000..878e36a
--- /dev/null
+++ b/run_tests.vpython3
@@ -0,0 +1,101 @@
+# This is a vpython "spec" file.
+#
+# Read more about `vpython` and how to modify this file here:
+#   https://chromium.googlesource.com/infra/infra/+/main/doc/users/vpython.md
+# List of available wheels:
+#   https://chromium.googlesource.com/infra/infra/+/main/infra/tools/dockerbuild/wheels.md
+
+python_version: "3.11"
+
+wheel: <
+  name: "infra/python/wheels/pytest-py3"
+  version: "version:8.3.4"
+>
+
+# Required by pytest==8.3.4
+wheel: <
+  name: "infra/python/wheels/py-py2_py3"
+  version: "version:1.11.0"
+>
+
+# Required by pytest==8.3.4
+wheel: <
+  name: "infra/python/wheels/iniconfig-py3"
+  version: "version:1.1.1"
+>
+
+# Required by pytest==8.3.4
+wheel: <
+  name: "infra/python/wheels/packaging-py3"
+  version: "version:23.0"
+>
+
+# Required by pytest==8.3.4
+wheel: <
+  name: "infra/python/wheels/pluggy-py3"
+  version: "version:1.5.0"
+>
+
+# Required by pytest==8.3.4
+wheel: <
+  name: "infra/python/wheels/toml-py3"
+  version: "version:0.10.1"
+>
+
+# Required by pytest==8.3.4
+wheel: <
+  name: "infra/python/wheels/pyparsing-py3"
+  version: "version:3.0.7"
+>
+
+# Required by pytest==8.3.4
+wheel: <
+  name: "infra/python/wheels/attrs-py2_py3"
+  version: "version:21.4.0"
+>
+
+wheel: <
+  name: "infra/python/wheels/black-py3"
+  version: "version:25.1.0"
+>
+
+# Required by black==25.1.0
+wheel: <
+  name: "infra/python/wheels/mypy-extensions-py3"
+  version: "version:0.4.3"
+>
+
+# Required by black==25.1.0
+wheel: <
+  name: "infra/python/wheels/tomli-py3"
+  version: "version:2.0.1"
+>
+
+# Required by black==25.1.0
+wheel: <
+  name: "infra/python/wheels/platformdirs-py3"
+  version: "version:2.5.2"
+>
+
+# Required by black==25.1.0
+wheel: <
+  name: "infra/python/wheels/pathspec-py3"
+  version: "version:0.9.0"
+>
+
+# Required by black==25.1.0
+wheel: <
+  name: "infra/python/wheels/typing-extensions-py3"
+  version: "version:4.3.0"
+>
+
+# Required by black==25.1.0
+wheel: <
+  name: "infra/python/wheels/click-py3"
+  version: "version:8.0.3"
+>
+
+wheel: <
+  name: "infra/python/wheels/isort-py3"
+  version: "version:5.10.1"
+>
diff --git a/tools/android_test_mapping_format.py b/tools/android_test_mapping_format.py
index 7780859..d09e52b 100755
--- a/tools/android_test_mapping_format.py
+++ b/tools/android_test_mapping_format.py
@@ -29,7 +29,7 @@ import re
 import sys
 from typing import Any, Dict
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -39,21 +39,21 @@ del _path
 # pylint: disable=wrong-import-position
 import rh.git
 
-_IMPORTS = 'imports'
-_NAME = 'name'
-_OPTIONS = 'options'
-_PATH = 'path'
-_HOST = 'host'
-_PREFERRED_TARGETS = 'preferred_targets'
-_FILE_PATTERNS = 'file_patterns'
-_INVALID_IMPORT_CONFIG = 'Invalid import config in TEST_MAPPING file'
-_INVALID_TEST_CONFIG = 'Invalid test config in TEST_MAPPING file'
+_IMPORTS = "imports"
+_NAME = "name"
+_OPTIONS = "options"
+_PATH = "path"
+_HOST = "host"
+_PREFERRED_TARGETS = "preferred_targets"
+_FILE_PATTERNS = "file_patterns"
+_INVALID_IMPORT_CONFIG = "Invalid import config in TEST_MAPPING file"
+_INVALID_TEST_CONFIG = "Invalid test config in TEST_MAPPING file"
 _TEST_MAPPING_URL = (
-    'https://source.android.com/compatibility/tests/development/'
-    'test-mapping')
+    "https://source.android.com/compatibility/tests/development/test-mapping"
+)
 
 # Pattern used to identify line-level '//'-format comment in TEST_MAPPING file.
-_COMMENTS_RE = re.compile(r'^\s*//')
+_COMMENTS_RE = re.compile(r"^\s*//")
 
 
 class Error(Exception):
@@ -73,8 +73,9 @@ def _filter_comments(json_data: str) -> str:
     Returns:
         Valid json string without comments.
     """
-    return ''.join(
-        '\n' if _COMMENTS_RE.match(x) else x for x in json_data.splitlines())
+    return "".join(
+        "\n" if _COMMENTS_RE.match(x) else x for x in json_data.splitlines()
+    )
 
 
 def _validate_import(entry: Dict[str, Any], test_mapping_file: str):
@@ -89,12 +90,14 @@ def _validate_import(entry: Dict[str, Any], test_mapping_file: str):
     """
     if len(entry) != 1:
         raise InvalidTestMappingError(
-            f'{_INVALID_IMPORT_CONFIG} {test_mapping_file}. Each import can '
-            f'only have one `path` setting. Failed entry: {entry}')
+            f"{_INVALID_IMPORT_CONFIG} {test_mapping_file}. Each import can "
+            f"only have one `path` setting. Failed entry: {entry}"
+        )
     if _PATH not in entry:
         raise InvalidTestMappingError(
-            f'{_INVALID_IMPORT_CONFIG} {test_mapping_file}. Import can '
-            f'only have one `path` setting. Failed entry: {entry}')
+            f"{_INVALID_IMPORT_CONFIG} {test_mapping_file}. Import can "
+            f"only have one `path` setting. Failed entry: {entry}"
+        )
 
 
 def _validate_test(test: Dict[str, Any], test_mapping_file: str) -> bool:
@@ -109,36 +112,41 @@ def _validate_test(test: Dict[str, Any], test_mapping_file: str) -> bool:
     """
     if _NAME not in test:
         raise InvalidTestMappingError(
-
-            f'{_INVALID_TEST_CONFIG} {test_mapping_file}. Test config must '
-            f'have a `name` setting. Failed test config: {test}')
+            f"{_INVALID_TEST_CONFIG} {test_mapping_file}. Test config must "
+            f"have a `name` setting. Failed test config: {test}"
+        )
 
     if not isinstance(test.get(_HOST, False), bool):
         raise InvalidTestMappingError(
-            f'{_INVALID_TEST_CONFIG} {test_mapping_file}. `host` setting in '
-            f'test config can only have boolean value of `true` or `false`. '
-            f'Failed test config: {test}')
+            f"{_INVALID_TEST_CONFIG} {test_mapping_file}. `host` setting in "
+            f"test config can only have boolean value of `true` or `false`. "
+            f"Failed test config: {test}"
+        )
 
     for key in (_PREFERRED_TARGETS, _FILE_PATTERNS):
         value = test.get(key, [])
-        if (not isinstance(value, list) or
-            any(not isinstance(t, str) for t in value)):
+        if not isinstance(value, list) or any(
+            not isinstance(t, str) for t in value
+        ):
             raise InvalidTestMappingError(
-                f'{_INVALID_TEST_CONFIG} {test_mapping_file}. `{key}` setting '
-                f'in test config can only be a list of strings. '
-                f'Failed test config: {test}')
+                f"{_INVALID_TEST_CONFIG} {test_mapping_file}. `{key}` setting "
+                f"in test config can only be a list of strings. "
+                f"Failed test config: {test}"
+            )
 
     for option in test.get(_OPTIONS, []):
         if not isinstance(option, dict):
             raise InvalidTestMappingError(
-                f'{_INVALID_TEST_CONFIG} {test_mapping_file}. Option setting '
-                f'in test config can only be a dictionary of key-val setting. '
-                f'Failed entry: {option}')
+                f"{_INVALID_TEST_CONFIG} {test_mapping_file}. Option setting "
+                f"in test config can only be a dictionary of key-val setting. "
+                f"Failed entry: {option}"
+            )
         if len(option) != 1:
             raise InvalidTestMappingError(
-                f'{_INVALID_TEST_CONFIG} {test_mapping_file}. Each option '
-                f'setting can only have one key-val setting. '
-                f'Failed entry: {option}')
+                f"{_INVALID_TEST_CONFIG} {test_mapping_file}. Each option "
+                f"setting can only have one key-val setting. "
+                f"Failed entry: {option}"
+            )
 
 
 def process_file(test_mapping_file: str):
@@ -148,10 +156,11 @@ def process_file(test_mapping_file: str):
     except ValueError as exception:
         # The file is not a valid JSON file.
         print(
-            f'Invalid JSON data in TEST_MAPPING file '
-            f'Failed to parse JSON data: {test_mapping_file}, '
-            f'error: {exception}',
-            file=sys.stderr)
+            f"Invalid JSON data in TEST_MAPPING file "
+            f"Failed to parse JSON data: {test_mapping_file}, "
+            f"error: {exception}",
+            file=sys.stderr,
+        )
         raise
 
     for group, value in test_mapping_data.items():
@@ -168,10 +177,11 @@ def process_file(test_mapping_file: str):
 def get_parser():
     """Returns a command line parser."""
     parser = argparse.ArgumentParser(description=__doc__)
-    parser.add_argument('--commit', type=str,
-                        help='Specify the commit to validate.')
-    parser.add_argument('project_dir')
-    parser.add_argument('files', nargs='+')
+    parser.add_argument(
+        "--commit", type=str, help="Specify the commit to validate."
+    )
+    parser.add_argument("project_dir")
+    parser.add_argument("files", nargs="+")
     return parser
 
 
@@ -184,15 +194,19 @@ def main(argv):
             if opts.commit:
                 json_data = rh.git.get_file_content(opts.commit, filename)
             else:
-                with open(os.path.join(opts.project_dir, filename),
-                          encoding='utf-8') as file:
+                with open(
+                    os.path.join(opts.project_dir, filename), encoding="utf-8"
+                ) as file:
                     json_data = file.read()
             process_file(json_data)
     except:
-        print(f'Visit {_TEST_MAPPING_URL} for details about the format of '
-              'TEST_MAPPING file.', file=sys.stderr)
+        print(
+            f"Visit {_TEST_MAPPING_URL} for details about the format of "
+            "TEST_MAPPING file.",
+            file=sys.stderr,
+        )
         raise
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     sys.exit(main(sys.argv[1:]))
diff --git a/tools/android_test_mapping_format_unittest.py b/tools/android_test_mapping_format_unittest.py
index cf3c3ca..c06a535 100755
--- a/tools/android_test_mapping_format_unittest.py
+++ b/tools/android_test_mapping_format_unittest.py
@@ -190,121 +190,132 @@ class AndroidTestMappingFormatTests(unittest.TestCase):
 
     def setUp(self):
         self.tempdir = tempfile.mkdtemp()
-        self.test_mapping_file = os.path.join(self.tempdir, 'TEST_MAPPING')
+        self.test_mapping_file = os.path.join(self.tempdir, "TEST_MAPPING")
 
     def tearDown(self):
         shutil.rmtree(self.tempdir)
 
     def test_valid_test_mapping(self):
-        """Verify that the check doesn't raise any error for valid test mapping.
-        """
-        with open(self.test_mapping_file, 'w', encoding='utf-8') as file:
+        """Verify that the check doesn't raise errors for valid test mapping."""
+        with open(self.test_mapping_file, "w", encoding="utf-8") as file:
             file.write(_VALID_TEST_MAPPING)
-        with open(self.test_mapping_file, 'r', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "r", encoding="utf-8") as file:
             android_test_mapping_format.process_file(file.read())
 
     def test_invalid_test_mapping_bad_json(self):
         """Verify that TEST_MAPPING file with bad json can be detected."""
-        with open(self.test_mapping_file, 'w', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "w", encoding="utf-8") as file:
             file.write(_BAD_JSON)
-        with open(self.test_mapping_file, 'r', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "r", encoding="utf-8") as file:
             self.assertRaises(
-                ValueError, android_test_mapping_format.process_file,
-                file.read())
+                ValueError,
+                android_test_mapping_format.process_file,
+                file.read(),
+            )
 
     def test_invalid_test_mapping_wrong_test_key(self):
         """Verify that test config using wrong key can be detected."""
-        with open(self.test_mapping_file, 'w', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "w", encoding="utf-8") as file:
             file.write(_BAD_TEST_WRONG_KEY)
-        with open(self.test_mapping_file, 'r', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "r", encoding="utf-8") as file:
             self.assertRaises(
                 android_test_mapping_format.InvalidTestMappingError,
                 android_test_mapping_format.process_file,
-                file.read())
+                file.read(),
+            )
 
     def test_invalid_test_mapping_wrong_test_value(self):
         """Verify that test config using wrong host value can be detected."""
-        with open(self.test_mapping_file, 'w', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "w", encoding="utf-8") as file:
             file.write(_BAD_TEST_WRONG_HOST_VALUE)
-        with open(self.test_mapping_file, 'r', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "r", encoding="utf-8") as file:
             self.assertRaises(
                 android_test_mapping_format.InvalidTestMappingError,
                 android_test_mapping_format.process_file,
-                file.read())
+                file.read(),
+            )
 
     def test_invalid_test_mapping_wrong_preferred_targets_value(self):
         """Verify invalid preferred_targets are rejected."""
-        with open(self.test_mapping_file, 'w', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "w", encoding="utf-8") as file:
             file.write(_BAD_TEST_WRONG_PREFERRED_TARGETS_VALUE_NONE_LIST)
-        with open(self.test_mapping_file, 'r', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "r", encoding="utf-8") as file:
             self.assertRaises(
                 android_test_mapping_format.InvalidTestMappingError,
                 android_test_mapping_format.process_file,
-                file.read())
-        with open(self.test_mapping_file, 'w', encoding='utf-8') as file:
+                file.read(),
+            )
+        with open(self.test_mapping_file, "w", encoding="utf-8") as file:
             file.write(_BAD_TEST_WRONG_PREFERRED_TARGETS_VALUE_WRONG_TYPE)
-        with open(self.test_mapping_file, 'r', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "r", encoding="utf-8") as file:
             self.assertRaises(
                 android_test_mapping_format.InvalidTestMappingError,
                 android_test_mapping_format.process_file,
-                file.read())
+                file.read(),
+            )
 
     def test_invalid_test_mapping_wrong_test_option(self):
         """Verify that test config using wrong option can be detected."""
-        with open(self.test_mapping_file, 'w', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "w", encoding="utf-8") as file:
             file.write(_BAD_TEST_WRONG_OPTION)
-        with open(self.test_mapping_file, 'r', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "r", encoding="utf-8") as file:
             self.assertRaises(
                 android_test_mapping_format.InvalidTestMappingError,
                 android_test_mapping_format.process_file,
-                file.read())
+                file.read(),
+            )
 
     def test_invalid_test_mapping_wrong_import_key(self):
         """Verify that import setting using wrong key can be detected."""
-        with open(self.test_mapping_file, 'w', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "w", encoding="utf-8") as file:
             file.write(_BAD_IMPORT_WRONG_KEY)
-        with open(self.test_mapping_file, 'r', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "r", encoding="utf-8") as file:
             self.assertRaises(
                 android_test_mapping_format.InvalidTestMappingError,
                 android_test_mapping_format.process_file,
-                file.read())
+                file.read(),
+            )
 
     def test_invalid_test_mapping_wrong_import_value(self):
         """Verify that import setting using wrong value can be detected."""
-        with open(self.test_mapping_file, 'w', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "w", encoding="utf-8") as file:
             file.write(_BAD_IMPORT_WRONG_IMPORT_VALUE)
-        with open(self.test_mapping_file, 'r', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "r", encoding="utf-8") as file:
             self.assertRaises(
                 android_test_mapping_format.InvalidTestMappingError,
                 android_test_mapping_format.process_file,
-                file.read())
+                file.read(),
+            )
 
     def test_invalid_test_mapping_file_patterns_value(self):
         """Verify that file_patterns using wrong value can be detected."""
-        with open(self.test_mapping_file, 'w', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "w", encoding="utf-8") as file:
             file.write(_BAD_FILE_PATTERNS)
-        with open(self.test_mapping_file, 'r', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "r", encoding="utf-8") as file:
             self.assertRaises(
                 android_test_mapping_format.InvalidTestMappingError,
                 android_test_mapping_format.process_file,
-                file.read())
+                file.read(),
+            )
 
     def test_valid_test_mapping_file_with_supported_comments(self):
         """Verify that '//'-format comment can be filtered."""
-        with open(self.test_mapping_file, 'w', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "w", encoding="utf-8") as file:
             file.write(_TEST_MAPPING_WITH_SUPPORTED_COMMENTS)
-        with open(self.test_mapping_file, 'r', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "r", encoding="utf-8") as file:
             android_test_mapping_format.process_file(file.read())
 
     def test_valid_test_mapping_file_with_non_supported_comments(self):
         """Verify that non-supported comment can be detected."""
-        with open(self.test_mapping_file, 'w', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "w", encoding="utf-8") as file:
             file.write(_TEST_MAPPING_WITH_NON_SUPPORTED_COMMENTS)
-        with open(self.test_mapping_file, 'r', encoding='utf-8') as file:
+        with open(self.test_mapping_file, "r", encoding="utf-8") as file:
             self.assertRaises(
-                ValueError, android_test_mapping_format.process_file,
-                file.read())
+                ValueError,
+                android_test_mapping_format.process_file,
+                file.read(),
+            )
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     unittest.main()
diff --git a/tools/check_aosp_license.py b/tools/check_aosp_license.py
index ffeed21..d00bde4 100755
--- a/tools/check_aosp_license.py
+++ b/tools/check_aosp_license.py
@@ -1,5 +1,4 @@
 #!/usr/bin/env python3
-#
 # Copyright (C) 2024 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
@@ -22,7 +21,7 @@ import re
 import sys
 from typing import List
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -58,7 +57,7 @@ AOSP_LICENSE_HEADER = (
 LICENSE_RE = re.compile(AOSP_LICENSE_HEADER, re.MULTILINE)
 
 
-AOSP_LICENSE_SUBSTR = 'Licensed under the Apache License'
+AOSP_LICENSE_SUBSTR = "Licensed under the Apache License"
 
 
 def check_license(contents: str) -> bool:
@@ -70,17 +69,17 @@ def get_parser() -> argparse.ArgumentParser:
     """Returns a command line parser."""
     parser = argparse.ArgumentParser(description=__doc__)
     parser.add_argument(
-        'files',
-        nargs='+',
-        help='The file paths to check.',
+        "files",
+        nargs="+",
+        help="The file paths to check.",
     )
     parser.add_argument(
-        '--commit-hash',
-        '-c',
-        help='The commit hash to check.',
+        "--commit-hash",
+        "-c",
+        help="The commit hash to check.",
         # TODO(b/370907797): Read the contents on the file system by default
         # instead.
-        default='HEAD',
+        default="HEAD",
     )
     return parser
 
@@ -97,12 +96,12 @@ def main(argv: List[str]) -> int:
         contents = rh.git.get_file_content(commit_hash, file_path)
         if not check_license(contents):
             if AOSP_LICENSE_SUBSTR in contents:
-                print(f'{file_path}: Malformed AOSP license', file=sys.stderr)
+                print(f"{file_path}: Malformed AOSP license", file=sys.stderr)
             else:
-                print(f'{file_path}: Missing AOSP license', file=sys.stderr)
+                print(f"{file_path}: Missing AOSP license", file=sys.stderr)
             all_passed = False
     return 0 if all_passed else 1
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     sys.exit(main(sys.argv[1:]))
diff --git a/tools/check_aosp_license_unittest.py b/tools/check_aosp_license_unittest.py
index bcd98f8..fc35dc3 100755
--- a/tools/check_aosp_license_unittest.py
+++ b/tools/check_aosp_license_unittest.py
@@ -1,5 +1,4 @@
 #!/usr/bin/env python3
-#
 # Copyright (C) 2024 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
@@ -155,5 +154,5 @@ limitations under the License.
         self.assertFalse(check_aosp_license.check_license(invalid_header))
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     unittest.main()
diff --git a/tools/clang-format.py b/tools/clang-format.py
index 1d5f1ac..1854419 100755
--- a/tools/clang-format.py
+++ b/tools/clang-format.py
@@ -19,7 +19,7 @@ import argparse
 import os
 import sys
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -33,34 +33,60 @@ import rh.utils
 
 # Since we're asking git-clang-format to print a diff, all modified filenames
 # that have formatting errors are printed with this prefix.
-DIFF_MARKER_PREFIX = '+++ b/'
+DIFF_MARKER_PREFIX = "+++ b/"
 
 
 def get_parser():
     """Return a command line parser."""
     parser = argparse.ArgumentParser(description=__doc__)
-    parser.add_argument('--clang-format', default='clang-format',
-                        help='The path of the clang-format executable.')
-    parser.add_argument('--git-clang-format', default='git-clang-format',
-                        help='The path of the git-clang-format executable.')
-    parser.add_argument('--style', metavar='STYLE', type=str,
-                        help='The style that clang-format will use.')
-    parser.add_argument('--extensions', metavar='EXTENSIONS', type=str,
-                        help='Comma-separated list of file extensions to '
-                             'format.')
-    parser.add_argument('--fix', action='store_true',
-                        help='Fix any formatting errors automatically.')
+    parser.add_argument(
+        "--clang-format",
+        default="clang-format",
+        help="The path of the clang-format executable.",
+    )
+    parser.add_argument(
+        "--git-clang-format",
+        default="git-clang-format",
+        help="The path of the git-clang-format executable.",
+    )
+    parser.add_argument(
+        "--style",
+        metavar="STYLE",
+        type=str,
+        help="The style that clang-format will use.",
+    )
+    parser.add_argument(
+        "--extensions",
+        metavar="EXTENSIONS",
+        type=str,
+        help="Comma-separated list of file extensions to format.",
+    )
+    parser.add_argument(
+        "--fix",
+        action="store_true",
+        help="Fix any formatting errors automatically.",
+    )
 
     scope = parser.add_mutually_exclusive_group(required=True)
-    scope.add_argument('--commit', type=str, default='HEAD',
-                       help='Specify the commit to validate.')
-    scope.add_argument('--working-tree', action='store_true',
-                       help='Validates the files that have changed from '
-                            'HEAD in the working directory.')
-
-    parser.add_argument('files', type=str, nargs='*',
-                        help='If specified, only consider differences in '
-                             'these files.')
+    scope.add_argument(
+        "--commit",
+        type=str,
+        default="HEAD",
+        help="Specify the commit to validate.",
+    )
+    scope.add_argument(
+        "--working-tree",
+        action="store_true",
+        help="Validates the files that have changed from "
+        "HEAD in the working directory.",
+    )
+
+    parser.add_argument(
+        "files",
+        type=str,
+        nargs="*",
+        help="If specified, only consider differences in these files.",
+    )
     return parser
 
 
@@ -69,14 +95,14 @@ def main(argv):
     parser = get_parser()
     opts = parser.parse_args(argv)
 
-    cmd = [opts.git_clang_format, '--binary', opts.clang_format, '--diff']
+    cmd = [opts.git_clang_format, "--binary", opts.clang_format, "--diff"]
     if opts.style:
-        cmd.extend(['--style', opts.style])
+        cmd.extend(["--style", opts.style])
     if opts.extensions:
-        cmd.extend(['--extensions', opts.extensions])
+        cmd.extend(["--extensions", opts.extensions])
     if not opts.working_tree:
-        cmd.extend([f'{opts.commit}^', opts.commit])
-    cmd.extend(['--'] + opts.files)
+        cmd.extend([f"{opts.commit}^", opts.commit])
+    cmd.extend(["--"] + opts.files)
 
     # Fail gracefully if clang-format itself aborts/fails.
     result = rh.utils.run(cmd, capture_output=True, check=False)
@@ -85,32 +111,44 @@ def main(argv):
     # it exited 1 and produce useful format diffs to stdout.  If it exited 0,
     # then assume all is well and we'll attempt to parse its output below.
     ret_code = None
-    if (result.returncode > 1 or result.stderr or
-        (result.stdout and result.returncode)):
+    if (
+        result.returncode > 1
+        or result.stderr
+        or (result.stdout and result.returncode)
+    ):
         # Apply fix if the flag is set and clang-format shows it is fixible.
         if opts.fix and result.stdout and result.returncode:
-            result = rh.utils.run(['git', 'apply'], input=result.stdout,
-                                   check=False)
+            result = rh.utils.run(
+                ["git", "apply"], input=result.stdout, check=False
+            )
             ret_code = result.returncode
             if ret_code:
-                print('Error: Unable to automatically fix things.\n'
-                      '  Make sure your checkout is clean first.\n'
-                      '  If you have multiple commits, you might have to '
-                      'manually rebase your tree first.',
-                      file=sys.stderr)
+                print(
+                    "Error: Unable to automatically fix things.\n"
+                    "  Make sure your checkout is clean first.\n"
+                    "  If you have multiple commits, you might have to "
+                    "manually rebase your tree first.",
+                    file=sys.stderr,
+                )
 
         else:  # Regular clang-format aborts/fails.
-            print(f'clang-format failed:\ncmd: {result.cmdstr}\n'
-                  f'stdout:\n{result.stdout}\n', file=sys.stderr)
+            print(
+                f"clang-format failed:\ncmd: {result.cmdstr}\n"
+                f"stdout:\n{result.stdout}\n",
+                file=sys.stderr,
+            )
             if result.returncode > 1 or result.stderr:
-                print('\nPlease report this to the clang team.\n',
-                      f'stderr:\n{result.stderr}', file=sys.stderr)
+                print(
+                    "\nPlease report this to the clang team.\n",
+                    f"stderr:\n{result.stderr}",
+                    file=sys.stderr,
+                )
             ret_code = 1
 
         return ret_code
 
     stdout = result.stdout
-    if stdout.rstrip('\n') == 'no modified files to format':
+    if stdout.rstrip("\n") == "no modified files to format":
         # This is always printed when only files that clang-format does not
         # understand were modified.
         return 0
@@ -118,28 +156,32 @@ def main(argv):
     diff_filenames = []
     for line in stdout.splitlines():
         if line.startswith(DIFF_MARKER_PREFIX):
-            diff_filenames.append(line[len(DIFF_MARKER_PREFIX):].rstrip())
+            diff_filenames.append(line[len(DIFF_MARKER_PREFIX) :].rstrip())
 
     if diff_filenames:
         if opts.fix:
-            result = rh.utils.run(['git', 'apply'], input=stdout, check=False)
+            result = rh.utils.run(["git", "apply"], input=stdout, check=False)
             if result.returncode:
-                print('Error: Unable to automatically fix things.\n'
-                      '  Make sure your checkout is clean first.\n'
-                      '  If you have multiple commits, you might have to '
-                      'manually rebase your tree first.',
-                      file=sys.stderr)
+                print(
+                    "Error: Unable to automatically fix things.\n"
+                    "  Make sure your checkout is clean first.\n"
+                    "  If you have multiple commits, you might have to "
+                    "manually rebase your tree first.",
+                    file=sys.stderr,
+                )
                 return result.returncode
         else:
-            print('The following files have formatting errors:')
+            print("The following files have formatting errors:")
             for filename in diff_filenames:
-                print(f'\t{filename}')
-            print('You can try to fix this by running:\n'
-                  f'{sys.argv[0]} --fix {rh.shell.cmd_to_str(argv)}')
+                print(f"\t{filename}")
+            print(
+                "You can try to fix this by running:\n"
+                f"{sys.argv[0]} --fix {rh.shell.cmd_to_str(argv)}"
+            )
             return 1
 
     return 0
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     sys.exit(main(sys.argv[1:]))
diff --git a/tools/clang-format_unittest.py b/tools/clang-format_unittest.py
index 8dfb5cf..eac0e34 100755
--- a/tools/clang-format_unittest.py
+++ b/tools/clang-format_unittest.py
@@ -31,25 +31,26 @@ sys.path.insert(0, str(DIR.parent))
 import rh.utils
 
 
-CLANG_FORMAT = DIR / 'clang-format.py'
+CLANG_FORMAT = DIR / "clang-format.py"
 
 
 @contextlib.contextmanager
 def git_clang_format(data: str):
     """Create a fake git-clang-format script."""
-    with tempfile.TemporaryDirectory(prefix='repohooks-tests') as tempdir:
+    with tempfile.TemporaryDirectory(prefix="repohooks-tests") as tempdir:
         tempdir = Path(tempdir)
-        script = tempdir / 'git-clang-format-fake.sh'
-        script.write_text(f'#!/bin/sh\n{data}', encoding='utf-8')
+        script = tempdir / "git-clang-format-fake.sh"
+        script.write_text(f"#!/bin/sh\n{data}", encoding="utf-8")
         script.chmod(0o755)
         yield script
 
 
 def run_clang_format(script, args, **kwargs):
     """Helper to run clang-format.py with fake git-clang-format script."""
-    kwargs.setdefault('capture_output', True)
+    kwargs.setdefault("capture_output", True)
     return rh.utils.run(
-        [CLANG_FORMAT, '--git-clang-format', script] + args, **kwargs)
+        [CLANG_FORMAT, "--git-clang-format", script] + args, **kwargs
+    )
 
 
 class GitClangFormatExit(unittest.TestCase):
@@ -57,52 +58,53 @@ class GitClangFormatExit(unittest.TestCase):
 
     def test_diff_exit_0_no_output(self):
         """Test exit 0 w/no output."""
-        with git_clang_format('exit 0') as script:
-            result = run_clang_format(script, ['--working-tree'])
-            self.assertEqual(result.stdout, '')
+        with git_clang_format("exit 0") as script:
+            result = run_clang_format(script, ["--working-tree"])
+            self.assertEqual(result.stdout, "")
 
     def test_diff_exit_0_stderr(self):
         """Test exit 0 w/stderr output."""
-        with git_clang_format('echo bad >&2; exit 0') as script:
+        with git_clang_format("echo bad >&2; exit 0") as script:
             with self.assertRaises(rh.utils.CalledProcessError) as e:
-                run_clang_format(script, ['--working-tree'])
-            self.assertIn('clang-format failed', e.exception.stderr)
+                run_clang_format(script, ["--working-tree"])
+            self.assertIn("clang-format failed", e.exception.stderr)
 
     def test_diff_exit_1_no_output(self):
         """Test exit 1 w/no output."""
-        with git_clang_format('exit 1') as script:
-            result = run_clang_format(script, ['--working-tree'])
-            self.assertEqual(result.stdout, '')
+        with git_clang_format("exit 1") as script:
+            result = run_clang_format(script, ["--working-tree"])
+            self.assertEqual(result.stdout, "")
 
     def test_diff_exit_1_output(self):
         """Test exit 1 with output."""
-        with git_clang_format('echo bad; exit 1') as script:
+        with git_clang_format("echo bad; exit 1") as script:
             with self.assertRaises(rh.utils.CalledProcessError) as e:
-                run_clang_format(script, ['--working-tree'])
-            self.assertIn('clang-format failed', e.exception.stderr)
+                run_clang_format(script, ["--working-tree"])
+            self.assertIn("clang-format failed", e.exception.stderr)
 
     def test_diff_exit_1_stderr(self):
         """Test exit 1 w/stderr."""
-        with git_clang_format('echo bad >&2; exit 1') as script:
+        with git_clang_format("echo bad >&2; exit 1") as script:
             with self.assertRaises(rh.utils.CalledProcessError) as e:
-                run_clang_format(script, ['--working-tree'])
-            self.assertIn('clang-format failed', e.exception.stderr)
+                run_clang_format(script, ["--working-tree"])
+            self.assertIn("clang-format failed", e.exception.stderr)
 
     def test_diff_exit_2(self):
         """Test exit 2."""
-        with git_clang_format('exit 2') as script:
+        with git_clang_format("exit 2") as script:
             with self.assertRaises(rh.utils.CalledProcessError) as e:
-                run_clang_format(script, ['--working-tree'])
-            self.assertIn('clang-format failed', e.exception.stderr)
+                run_clang_format(script, ["--working-tree"])
+            self.assertIn("clang-format failed", e.exception.stderr)
 
     def test_fix_exit_1_output(self):
         """Test fix with incorrect patch syntax."""
-        with git_clang_format('echo bad patch; exit 1') as script:
+        with git_clang_format("echo bad patch; exit 1") as script:
             with self.assertRaises(rh.utils.CalledProcessError) as e:
-                run_clang_format(script, ['--working-tree', '--fix'])
-            self.assertIn('Error: Unable to automatically fix things',
-                          e.exception.stderr)
+                run_clang_format(script, ["--working-tree", "--fix"])
+            self.assertIn(
+                "Error: Unable to automatically fix things", e.exception.stderr
+            )
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     unittest.main()
diff --git a/tools/google-java-format.py b/tools/google-java-format.py
index ebb9475..519fac6 100755
--- a/tools/google-java-format.py
+++ b/tools/google-java-format.py
@@ -20,7 +20,7 @@ import os
 import shutil
 import sys
 
-_path = os.path.realpath(__file__ + '/../..')
+_path = os.path.realpath(__file__ + "/../..")
 if sys.path[0] != _path:
     sys.path.insert(0, _path)
 del _path
@@ -35,20 +35,37 @@ import rh.utils
 def get_parser():
     """Return a command line parser."""
     parser = argparse.ArgumentParser(description=__doc__)
-    parser.add_argument('--google-java-format', default='google-java-format',
-                        help='The path of the google-java-format executable.')
-    parser.add_argument('--google-java-format-diff',
-                        default='google-java-format-diff.py',
-                        help='The path of the google-java-format-diff script.')
-    parser.add_argument('--fix', action='store_true',
-                        help='Fix any formatting errors automatically.')
-    parser.add_argument('--commit', type=str, default='HEAD',
-                        help='Specify the commit to validate.')
-    parser.add_argument('--skip-sorting-imports', action='store_true',
-                        help='If true, imports will not be sorted.')
-    parser.add_argument('files', nargs='*',
-                        help='If specified, only consider differences in '
-                             'these files.')
+    parser.add_argument(
+        "--google-java-format",
+        default="google-java-format",
+        help="The path of the google-java-format executable.",
+    )
+    parser.add_argument(
+        "--google-java-format-diff",
+        default="google-java-format-diff.py",
+        help="The path of the google-java-format-diff script.",
+    )
+    parser.add_argument(
+        "--fix",
+        action="store_true",
+        help="Fix any formatting errors automatically.",
+    )
+    parser.add_argument(
+        "--commit",
+        type=str,
+        default="HEAD",
+        help="Specify the commit to validate.",
+    )
+    parser.add_argument(
+        "--skip-sorting-imports",
+        action="store_true",
+        help="If true, imports will not be sorted.",
+    )
+    parser.add_argument(
+        "files",
+        nargs="*",
+        help="If specified, only consider differences in these files.",
+    )
     return parser
 
 
@@ -60,31 +77,31 @@ def main(argv):
     format_path = shutil.which(opts.google_java_format)
     if not format_path:
         print(
-            f'Unable to find google-java-format at: {opts.google_java_format}',
-            file=sys.stderr
+            f"Unable to find google-java-format at: {opts.google_java_format}",
+            file=sys.stderr,
         )
         return 1
 
     # TODO: Delegate to the tool once this issue is resolved:
     # https://github.com/google/google-java-format/issues/107
-    diff_cmd = ['git', 'diff', '--no-ext-diff', '-U0', f'{opts.commit}^!']
-    diff_cmd.extend(['--'] + opts.files)
+    diff_cmd = ["git", "diff", "--no-ext-diff", "-U0", f"{opts.commit}^!"]
+    diff_cmd.extend(["--"] + opts.files)
     diff = rh.utils.run(diff_cmd, capture_output=True).stdout
 
-    cmd = [opts.google_java_format_diff, '-p1', '--aosp', '-b', format_path]
+    cmd = [opts.google_java_format_diff, "-p1", "--aosp", "-b", format_path]
     if opts.fix:
-        cmd.extend(['-i'])
+        cmd.extend(["-i"])
     if opts.skip_sorting_imports:
-        cmd.extend(['--skip-sorting-imports'])
+        cmd.extend(["--skip-sorting-imports"])
 
     stdout = rh.utils.run(cmd, input=diff, capture_output=True).stdout
     if stdout:
-        print('One or more files in your commit have Java formatting errors.')
-        print(f'You can run: {sys.argv[0]} --fix {rh.shell.cmd_to_str(argv)}')
+        print("One or more files in your commit have Java formatting errors.")
+        print(f"You can run: {sys.argv[0]} --fix {rh.shell.cmd_to_str(argv)}")
         return 1
 
     return 0
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     sys.exit(main(sys.argv[1:]))
diff --git a/tools/pylint.py b/tools/pylint.py
index 8b27da8..92b0dd3 100755
--- a/tools/pylint.py
+++ b/tools/pylint.py
@@ -25,17 +25,24 @@ from typing import Dict, List, Optional, Set
 
 # This script is run by repohooks users.
 # See README.md for what version we may require.
-assert (sys.version_info.major, sys.version_info.minor) >= (3, 6), (
-    f'Python 3.6 or newer is required; found {sys.version}')
+assert (sys.version_info.major, sys.version_info.minor) >= (
+    3,
+    6,
+), f"Python 3.6 or newer is required; found {sys.version}"
 
 
 DEFAULT_PYLINTRC_PATH = os.path.join(
-    os.path.dirname(os.path.realpath(__file__)), 'pylintrc')
+    os.path.dirname(os.path.realpath(__file__)), "pylintrc"
+)
 
 
-def run_lint(pylint: str, unknown: Optional[List[str]],
-             files: Optional[List[str]], init_hook: str,
-             pylintrc: Optional[str] = None) -> bool:
+def run_lint(
+    pylint: str,
+    unknown: Optional[List[str]],
+    files: Optional[List[str]],
+    init_hook: str,
+    pylintrc: Optional[str] = None,
+) -> bool:
     """Run lint command.
 
     Upon error the stdout from pylint will be dumped to stdout and
@@ -48,37 +55,41 @@ def run_lint(pylint: str, unknown: Optional[List[str]],
         return True
 
     if pylintrc:
-        cmd += ['--rcfile', pylintrc]
+        cmd += ["--rcfile", pylintrc]
 
     files.sort()
     cmd += unknown + files
 
     if init_hook:
-        cmd += ['--init-hook', init_hook]
+        cmd += ["--init-hook", init_hook]
 
     try:
-        result = subprocess.run(cmd, stdout=subprocess.PIPE, text=True,
-                                check=False)
+        result = subprocess.run(
+            cmd, stdout=subprocess.PIPE, text=True, check=False
+        )
     except OSError as e:
         if e.errno == errno.ENOENT:
-            print(f'{__file__}: unable to run `{cmd[0]}`: {e}',
-                  file=sys.stderr)
-            print(f'{__file__}: Try installing pylint: sudo apt-get install '
-                  f'{os.path.basename(cmd[0])}', file=sys.stderr)
+            print(f"{__file__}: unable to run `{cmd[0]}`: {e}", file=sys.stderr)
+            print(
+                f"{__file__}: Try installing pylint: sudo apt-get install "
+                f"{os.path.basename(cmd[0])}",
+                file=sys.stderr,
+            )
             return False
 
         raise
 
     if result.returncode:
-        print(f'{__file__}: Using pylintrc: {pylintrc}')
+        print(f"{__file__}: Using pylintrc: {pylintrc}")
         print(result.stdout)
         return False
 
     return True
 
 
-def find_parent_dirs_with_pylintrc(leafdir: str,
-                                   pylintrc_map: Dict[str, Set[str]]) -> None:
+def find_parent_dirs_with_pylintrc(
+    leafdir: str, pylintrc_map: Dict[str, Set[str]]
+) -> None:
     """Find all dirs containing a pylintrc between root dir and leafdir."""
 
     # Find all pylintrc files, store the path. The path must end with '/'
@@ -89,15 +100,17 @@ def find_parent_dirs_with_pylintrc(leafdir: str,
     key = os.path.abspath(leafdir) + os.sep
 
     if not key.startswith(rootdir):
-        sys.exit(f'{__file__}: The search directory {key} is outside the '
-                 f'repo dir {rootdir}')
+        sys.exit(
+            f"{__file__}: The search directory {key} is outside the "
+            f"repo dir {rootdir}"
+        )
 
     while rootdir != key:
         # This subdirectory has already been handled, skip it.
         if key in pylintrc_map:
             break
 
-        if os.path.exists(os.path.join(key, 'pylintrc')):
+        if os.path.exists(os.path.join(key, "pylintrc")):
             pylintrc_map.setdefault(key, set())
             break
 
@@ -106,7 +119,7 @@ def find_parent_dirs_with_pylintrc(leafdir: str,
 
 
 def map_pyfiles_to_pylintrc(files: List[str]) -> Dict[str, Set[str]]:
-    """ Map all python files to a pylintrc file.
+    """Map all python files to a pylintrc file.
 
     Generate dictionary with pylintrc-file dirnames (including trailing /)
     as key containing sets with corresponding python files.
@@ -115,15 +128,15 @@ def map_pyfiles_to_pylintrc(files: List[str]) -> Dict[str, Set[str]]:
     pylintrc_map = {}
     # We assume pylint is running in the top directory of the project,
     # so load the pylintrc file from there if it is available.
-    pylintrc = os.path.abspath('pylintrc')
+    pylintrc = os.path.abspath("pylintrc")
     if not os.path.exists(pylintrc):
         pylintrc = DEFAULT_PYLINTRC_PATH
         # If we pass a non-existent rcfile to pylint, it'll happily ignore
         # it.
-        assert os.path.exists(pylintrc), f'Could not find {pylintrc}'
+        assert os.path.exists(pylintrc), f"Could not find {pylintrc}"
     # Always add top directory, either there is a pylintrc or fallback to
     # default.
-    key = os.path.abspath('.') + os.sep
+    key = os.path.abspath(".") + os.sep
     pylintrc_map[key] = set()
 
     search_dirs = {os.path.dirname(x) for x in files}
@@ -142,7 +155,7 @@ def map_pyfiles_to_pylintrc(files: List[str]) -> Dict[str, Set[str]]:
                 pylintrc_map[rc_dir].add(f)
                 break
         else:
-            sys.exit(f'{__file__}: Failed to map file {f} to a pylintrc file.')
+            sys.exit(f"{__file__}: Failed to map file {f} to a pylintrc file.")
 
     return pylintrc_map
 
@@ -150,14 +163,19 @@ def map_pyfiles_to_pylintrc(files: List[str]) -> Dict[str, Set[str]]:
 def get_parser():
     """Return a command line parser."""
     parser = argparse.ArgumentParser(description=__doc__)
-    parser.add_argument('--init-hook', help='Init hook commands to run.')
-    parser.add_argument('--executable-path', default='pylint',
-                        help='The path of the pylint executable.')
-    parser.add_argument('--no-rcfile', dest='use_default_conf',
-                        help='Specify to use the executable\'s default '
-                        'configuration.',
-                        action='store_true')
-    parser.add_argument('files', nargs='+')
+    parser.add_argument("--init-hook", help="Init hook commands to run.")
+    parser.add_argument(
+        "--executable-path",
+        default="pylint",
+        help="The path of the pylint executable.",
+    )
+    parser.add_argument(
+        "--no-rcfile",
+        dest="use_default_conf",
+        help="Specify to use the executable's default configuration.",
+        action="store_true",
+    )
+    parser.add_argument("files", nargs="+")
     return parser
 
 
@@ -172,15 +190,17 @@ def main(argv):
         pylintrc_map = map_pyfiles_to_pylintrc(opts.files)
         first = True
         for rc_dir, files in sorted(pylintrc_map.items()):
-            pylintrc = os.path.join(rc_dir, 'pylintrc')
+            pylintrc = os.path.join(rc_dir, "pylintrc")
             if first:
                 first = False
-                assert os.path.abspath(rc_dir) == os.path.abspath('.'), (
-                    f'{__file__}: pylintrc in top dir not first in list')
+                assert os.path.abspath(rc_dir) == os.path.abspath(
+                    "."
+                ), f"{__file__}: pylintrc in top dir not first in list"
                 if not os.path.exists(pylintrc):
                     pylintrc = DEFAULT_PYLINTRC_PATH
-            if not run_lint(pylint, unknown, sorted(files),
-                            opts.init_hook, pylintrc):
+            if not run_lint(
+                pylint, unknown, sorted(files), opts.init_hook, pylintrc
+            ):
                 ret = 1
     # Not using rc files, pylint default behaviour.
     elif not run_lint(pylint, unknown, sorted(opts.files), opts.init_hook):
@@ -189,5 +209,5 @@ def main(argv):
     return ret
 
 
-if __name__ == '__main__':
+if __name__ == "__main__":
     sys.exit(main(sys.argv[1:]))
```

